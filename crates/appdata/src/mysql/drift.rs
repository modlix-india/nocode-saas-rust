//! `MySQLDrift`: what a live table has that its definition does not, and the reverse.
//! Reporting and repairing are separate, and an unapproved repair runs only the half that
//! cannot lose anything.

use super::column::MySqlColumn;
use super::table_planner::{diff, Kind, SchemaChange};
use crate::value::{non_empty, Document, Value};

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub db: String,
    pub table: String,
    pub table_exists: bool,
    pub columns: Vec<SchemaChange>,
    pub index_statements: Vec<String>,
    pub foreign_key_statements: Vec<String>,
}

fn is_drop(statement: &str) -> bool {
    let s = statement.to_uppercase();
    s.starts_with("DROP INDEX") || s.contains("DROP FOREIGN KEY") || s.contains("DROP COLUMN")
}

impl Report {
    pub fn clean(&self) -> bool {
        self.table_exists && self.columns.is_empty() && self.index_statements.is_empty() && self.foreign_key_statements.is_empty()
    }

    pub fn dangerous(&self) -> Vec<&SchemaChange> {
        self.columns.iter().filter(|c| c.needs_data_check()).collect()
    }

    pub fn drops(&self) -> Vec<String> {
        self.index_statements
            .iter()
            .chain(self.foreign_key_statements.iter())
            .filter(|s| is_drop(s))
            .cloned()
            .collect()
    }

    pub fn needs_approval(&self) -> bool {
        !self.dangerous().is_empty() || !self.drops().is_empty() || !self.table_exists
    }

    pub fn summary(&self) -> String {
        if self.clean() {
            return format!("{}.{}: in sync", self.db, self.table);
        }
        if !self.table_exists {
            return format!("{}.{}: table is MISSING", self.db, self.table);
        }
        format!(
            "{}.{}: {} column change(s) ({} needing approval), {} index statement(s), {} key statement(s)",
            self.db,
            self.table,
            self.columns.len(),
            self.dangerous().len(),
            self.index_statements.len(),
            self.foreign_key_statements.len()
        )
    }

    /// The JSON the services' ObjectMapper writes for the record: the components, then the
    /// `@JsonProperty` methods in the order Jackson finds them, empty ones left out.
    pub fn to_value(&self) -> Value {
        let mut d = Document::new();
        d.insert("db".into(), Value::from(self.db.as_str()));
        d.insert("table".into(), Value::from(self.table.as_str()));
        d.insert("tableExists".into(), Value::Bool(self.table_exists));
        d.insert("columns".into(), Value::Array(self.columns.iter().map(change_value).collect()));
        d.insert("indexStatements".into(), strings(&self.index_statements));
        d.insert("foreignKeyStatements".into(), strings(&self.foreign_key_statements));
        d.insert("dangerous".into(), Value::Array(self.dangerous().into_iter().map(change_value).collect()));
        d.insert("drops".into(), strings(&self.drops()));
        d.insert("needsApproval".into(), Value::Bool(self.needs_approval()));
        d.insert("summary".into(), Value::from(self.summary()));
        d.insert("clean".into(), Value::Bool(self.clean()));
        Value::Object(non_empty(d))
    }
}

fn strings(list: &[String]) -> Value {
    Value::Array(list.iter().map(|s| Value::from(s.as_str())).collect())
}

fn opt(s: &Option<String>) -> Value {
    s.as_ref().map(|v| Value::from(v.as_str())).unwrap_or(Value::Null)
}

pub fn change_value(c: &SchemaChange) -> Value {
    let mut d = Document::new();
    d.insert(
        "kind".into(),
        Value::from(match c.kind {
            Kind::Widening => "WIDENING",
            Kind::Narrowing => "NARROWING",
            Kind::Destructive => "DESTRUCTIVE",
        }),
    );
    d.insert("column".into(), Value::from(c.column.as_str()));
    d.insert("from".into(), opt(&c.from));
    d.insert("to".into(), opt(&c.to));
    d.insert("reason".into(), Value::from(c.reason.as_str()));
    d.insert("collation".into(), opt(&c.collation));
    Value::Object(non_empty(d))
}

/// What a repair did on one tenant; `withheld` is what an approval would have added.
#[derive(Debug, Clone, PartialEq)]
pub struct DriftRepair {
    pub db: String,
    pub table_missing: bool,
    pub applied: Vec<String>,
    pub withheld: Vec<String>,
    pub failed: Vec<String>,
}

impl DriftRepair {
    pub fn complete(&self) -> bool {
        !self.table_missing && self.failed.is_empty() && self.withheld.is_empty()
    }

    pub fn to_value(&self) -> Value {
        let mut d = Document::new();
        d.insert("db".into(), Value::from(self.db.as_str()));
        d.insert("tableMissing".into(), Value::Bool(self.table_missing));
        d.insert("applied".into(), strings(&self.applied));
        d.insert("withheld".into(), strings(&self.withheld));
        d.insert("failed".into(), strings(&self.failed));
        d.insert("complete".into(), Value::Bool(self.complete()));
        Value::Object(non_empty(d))
    }
}

/// A report from what was inspected and what the definition wants.
pub fn of(
    db: &str,
    table: &str,
    table_exists: bool,
    existing: &[MySqlColumn],
    desired: &[MySqlColumn],
    index_statements: Vec<String>,
    foreign_key_statements: Vec<String>,
) -> Report {
    if !table_exists {
        return Report {
            db: db.into(),
            table: table.into(),
            table_exists: false,
            columns: Vec::new(),
            index_statements: Vec::new(),
            foreign_key_statements: Vec::new(),
        };
    }
    Report {
        db: db.into(),
        table: table.into(),
        table_exists: true,
        columns: diff(existing, desired),
        index_statements,
        foreign_key_statements,
    }
}

/// The statements an approved repair would run that this one will not.
pub fn withheld_statements(report: &Report, approved: bool) -> Vec<String> {
    if approved {
        return Vec::new();
    }
    let full = repair_statements(report, true);
    let safe = repair_statements(report, false);
    full.into_iter().filter(|s| !safe.contains(s)).collect()
}

/// The DDL that would bring the table back: drops (keys before indexes), then columns,
/// then additions (indexes before keys).
pub fn repair_statements(report: &Report, approved: bool) -> Vec<String> {
    if report.clean() {
        return Vec::new();
    }
    let mut out = Vec::new();
    if approved {
        out.extend(report.foreign_key_statements.iter().filter(|s| is_drop(s)).cloned());
        out.extend(report.index_statements.iter().filter(|s| is_drop(s)).cloned());
    }
    for change in &report.columns {
        if change.needs_data_check() && !approved {
            continue;
        }
        out.push(column_ddl(&report.db, &report.table, change));
    }
    out.extend(report.index_statements.iter().filter(|s| !is_drop(s)).cloned());
    out.extend(report.foreign_key_statements.iter().filter(|s| !is_drop(s)).cloned());
    out
}

fn column_ddl(db: &str, table: &str, change: &SchemaChange) -> String {
    let target = format!("`{db}`.`{table}`");
    if change.kind == Kind::Destructive && change.to.is_none() {
        return format!("ALTER TABLE {target} DROP COLUMN `{}`", change.column);
    }
    let to = change.to.as_deref().unwrap_or("null");
    if change.from.is_none() {
        return format!("ALTER TABLE {target} ADD COLUMN `{}` {to}{}", change.column, change.collate_clause());
    }
    format!("ALTER TABLE {target} MODIFY COLUMN `{}` {to}{}", change.column, change.collate_clause())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn col(n: &str, t: &str) -> MySqlColumn {
        MySqlColumn::new(n, t, true).unwrap()
    }

    fn report(existing: Vec<MySqlColumn>, desired: Vec<MySqlColumn>, idx: Vec<&str>, fks: Vec<&str>) -> Report {
        of(
            "T_app",
            "thing",
            true,
            &existing,
            &desired,
            idx.into_iter().map(str::to_string).collect(),
            fks.into_iter().map(str::to_string).collect(),
        )
    }

    #[test]
    fn clean_and_missing() {
        let same = vec![col("_id", "VARCHAR(40)"), col("title", "VARCHAR(100)")];
        let r = report(same.clone(), same, vec![], vec![]);
        assert!(r.clean() && !r.needs_approval());
        assert!(repair_statements(&r, false).is_empty() && repair_statements(&r, true).is_empty());
        assert!(r.summary().contains("in sync"));
        let r = of("T_app", "thing", false, &[], &[col("_id", "VARCHAR(40)")], vec![], vec![]);
        assert!(!r.clean() && r.needs_approval() && r.summary().contains("MISSING"));
    }

    #[test]
    fn approval_gate() {
        let id = || vec![col("_id", "VARCHAR(40)")];
        let r = report(
            id(),
            id(),
            vec!["CREATE INDEX `rel_x` ON `T_app`.`thing` (`x`)"],
            vec!["ALTER TABLE `T_app`.`thing` ADD CONSTRAINT `fk_x` FOREIGN KEY (`x`) REFERENCES `o` (`_id`)"],
        );
        assert!(!r.needs_approval());
        assert_eq!(repair_statements(&r, false).len(), 2);

        let r = report(
            id(),
            id(),
            vec!["DROP INDEX `stale` ON `T_app`.`thing`", "CREATE INDEX `rel_x` ON `T_app`.`thing` (`x`)"],
            vec!["ALTER TABLE `T_app`.`thing` DROP FOREIGN KEY `fk_old`"],
        );
        assert!(r.needs_approval());
        assert_eq!(r.drops().len(), 2);
        let unapproved = repair_statements(&r, false);
        assert_eq!(unapproved.len(), 1);
        assert!(unapproved[0].starts_with("CREATE INDEX"));
        assert_eq!(repair_statements(&r, true).len(), 3);
        assert_eq!(withheld_statements(&r, false).len(), 2);

        let r = report(vec![col("_id", "VARCHAR(40)"), col("gone", "VARCHAR(100)")], id(), vec![], vec![]);
        assert!(!r.clean() && r.needs_approval() && !r.dangerous().is_empty());
        assert!(repair_statements(&r, false).is_empty());
        let approved = repair_statements(&r, true);
        assert_eq!(approved.len(), 1);
        assert!(approved[0].contains("DROP COLUMN `gone`"));

        let r = report(id(), vec![col("_id", "VARCHAR(40)"), col("title", "VARCHAR(100)")], vec![], vec![]);
        let unapproved = repair_statements(&r, false);
        assert_eq!(unapproved.len(), 1);
        assert!(unapproved[0].contains("ADD COLUMN `title`"));
    }

    #[test]
    fn plan_order() {
        let id = || vec![col("_id", "VARCHAR(40)")];
        let r = report(
            id(),
            id(),
            vec!["DROP INDEX `rel_x` ON `T_app`.`thing`"],
            vec!["ALTER TABLE `T_app`.`thing` DROP FOREIGN KEY `fk_x`"],
        );
        let plan = repair_statements(&r, true);
        assert!(plan[0].contains("DROP FOREIGN KEY") && plan[1].starts_with("DROP INDEX"));

        let with_owner = || vec![col("_id", "VARCHAR(40)"), col("owner", "CHAR(26)")];
        let r = report(
            id(),
            with_owner(),
            vec!["CREATE INDEX `rel_owner` ON `T_app`.`thing` (`owner`)"],
            vec!["ALTER TABLE `T_app`.`thing` ADD CONSTRAINT `fk_owner` FOREIGN KEY (`owner`) REFERENCES `o` (`_id`)"],
        );
        let plan = repair_statements(&r, false);
        assert_eq!(plan.len(), 3);
        assert!(plan[0].contains("ADD COLUMN `owner`") && plan[1].starts_with("CREATE INDEX") && plan[2].contains("ADD CONSTRAINT"));

        let r = report(
            id(),
            with_owner(),
            vec!["DROP INDEX `stale` ON `T_app`.`thing`", "CREATE INDEX `rel_owner` ON `T_app`.`thing` (`owner`)"],
            vec![
                "ALTER TABLE `T_app`.`thing` DROP FOREIGN KEY `fk_old`",
                "ALTER TABLE `T_app`.`thing` ADD CONSTRAINT `fk_owner` FOREIGN KEY (`owner`) REFERENCES `o` (`_id`)",
            ],
        );
        let plan = repair_statements(&r, true);
        assert_eq!(plan.len(), 5);
        assert!(plan[0].contains("DROP FOREIGN KEY"));
        assert!(plan[1].starts_with("DROP INDEX"));
        assert!(plan[2].contains("ADD COLUMN `owner`"));
        assert!(plan[3].starts_with("CREATE INDEX"));
        assert!(plan[4].contains("ADD CONSTRAINT"));
    }
}
