//! `MySQLMigrationPlanner`, `MigrationStep` and `MySQLConvertibility`: classified schema
//! changes turned into an ordered, re-runnable plan. Every executable step carries a
//! precondition (MySQL 8 has no ADD COLUMN IF NOT EXISTS) and every lossy one a counting
//! query that must return zero first.

use serde::{Deserialize, Serialize};

use super::filter_builder::FilterError;
use super::table_planner::{Kind, SchemaChange};

/// Suffix of the column added during EXPAND, before CONTRACT renames it into place.
pub const NEW_SUFFIX: &str = "__v";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Phase {
    Preflight,
    Expand,
    Backfill,
    Verify,
    Snapshot,
    Contract,
}

impl Phase {
    pub fn name(&self) -> &'static str {
        match self {
            Phase::Preflight => "PREFLIGHT",
            Phase::Expand => "EXPAND",
            Phase::Backfill => "BACKFILL",
            Phase::Verify => "VERIFY",
            Phase::Snapshot => "SNAPSHOT",
            Phase::Contract => "CONTRACT",
        }
    }
}

/// One statement of a plan, with the question that decides whether it may run.
/// Serialised as Jackson serialises the Java record, `destructive` included, so a plan
/// written by either side replays on the other.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MigrationStep {
    pub phase: Phase,
    pub sql: Option<String>,
    pub precondition: Option<String>,
    pub data_check: Option<String>,
    pub describes: Option<SchemaChange>,
    #[serde(default)]
    pub destructive: bool,
}

impl MigrationStep {
    pub fn new(
        phase: Phase,
        sql: Option<String>,
        precondition: Option<String>,
        data_check: Option<String>,
        describes: &SchemaChange,
    ) -> MigrationStep {
        MigrationStep {
            phase,
            sql,
            precondition,
            data_check,
            describes: Some(describes.clone()),
            destructive: phase == Phase::Contract,
        }
    }

    pub fn is_destructive(&self) -> bool {
        self.phase == Phase::Contract
    }
}

pub fn plan(db: &str, table: &str, to_version: i32, changes: &[SchemaChange]) -> Result<Vec<MigrationStep>, FilterError> {
    let mut steps = Vec::new();
    if changes.is_empty() {
        return Ok(steps);
    }

    let any_destructive = changes.iter().any(|c| matches!(c.kind, Kind::Destructive | Kind::Narrowing));
    if any_destructive {
        steps.push(snapshot(db, table, to_version));
    }

    for c in changes {
        match c.kind {
            Kind::Widening => steps.extend(widening(db, table, c)),
            Kind::Narrowing => steps.extend(narrowing(db, table, to_version, c)?),
            Kind::Destructive => steps.extend(destructive(db, table, c)),
        }
    }

    Ok(steps)
}

fn snapshot(db: &str, table: &str, to_version: i32) -> MigrationStep {
    let bak = format!("{table}__bak_{to_version}");
    MigrationStep {
        phase: Phase::Snapshot,
        sql: Some(format!("CREATE TABLE `{db}`.`{bak}` AS SELECT * FROM `{db}`.`{table}`")),
        precondition: Some(table_absent(db, &bak)),
        data_check: None,
        describes: None,
        destructive: false,
    }
}

fn to_type(c: &SchemaChange) -> &str {
    c.to.as_deref().unwrap_or("null")
}

fn widening(db: &str, table: &str, c: &SchemaChange) -> Vec<MigrationStep> {
    if c.from.is_none() {
        return vec![MigrationStep::new(
            Phase::Expand,
            Some(format!(
                "ALTER TABLE `{db}`.`{table}` ADD COLUMN `{}` {}{} NULL",
                c.column,
                to_type(c),
                c.collate_clause()
            )),
            Some(column_absent(db, table, &c.column)),
            None,
            c,
        )];
    }
    vec![MigrationStep::new(
        Phase::Expand,
        Some(format!(
            "ALTER TABLE `{db}`.`{table}` MODIFY COLUMN `{}` {}{}",
            c.column,
            to_type(c),
            c.collate_clause()
        )),
        Some(column_present(db, table, &c.column)),
        None,
        c,
    )]
}

fn narrowing(db: &str, table: &str, to_version: i32, c: &SchemaChange) -> Result<Vec<MigrationStep>, FilterError> {
    if c.from.is_none() {
        return Ok(vec![
            MigrationStep::new(Phase::Preflight, None, None, Some(format!("SELECT COUNT(*) FROM `{db}`.`{table}`")), c),
            MigrationStep::new(
                Phase::Expand,
                Some(format!(
                    "ALTER TABLE `{db}`.`{table}` ADD COLUMN `{}` {}{} NOT NULL",
                    c.column,
                    to_type(c),
                    c.collate_clause()
                )),
                Some(column_absent(db, table, &c.column)),
                None,
                c,
            ),
        ]);
    }

    let tmp = format!("{}{NEW_SUFFIX}{to_version}", c.column);
    let q = format!("`{db}`.`{table}`");
    let convertible = predicate(&c.column, c.to.as_deref())?;

    Ok(vec![
        MigrationStep::new(Phase::Preflight, None, None, Some(preflight(db, table, &c.column, c.to.as_deref())?), c),
        MigrationStep::new(
            Phase::Expand,
            Some(format!("ALTER TABLE {q} ADD COLUMN `{tmp}` {}{} NULL", to_type(c), c.collate_clause())),
            Some(column_absent(db, table, &tmp)),
            None,
            c,
        ),
        MigrationStep::new(
            Phase::Backfill,
            Some(format!(
                "UPDATE {q} SET `{tmp}` = `{}` WHERE `{}` IS NOT NULL AND ({convertible})",
                c.column, c.column
            )),
            Some(column_present(db, table, &tmp)),
            None,
            c,
        ),
        MigrationStep::new(
            Phase::Verify,
            None,
            None,
            Some(format!("SELECT COUNT(*) FROM {q} WHERE `{}` IS NOT NULL AND `{tmp}` IS NULL", c.column)),
            c,
        ),
        MigrationStep::new(
            Phase::Contract,
            Some(format!("ALTER TABLE {q} DROP COLUMN `{}`", c.column)),
            Some(column_present(db, table, &c.column)),
            None,
            c,
        ),
        MigrationStep::new(
            Phase::Contract,
            Some(format!(
                "ALTER TABLE {q} CHANGE COLUMN `{tmp}` `{}` {}{}",
                c.column,
                to_type(c),
                c.collate_clause()
            )),
            Some(column_present(db, table, &tmp)),
            None,
            c,
        ),
    ])
}

fn destructive(db: &str, table: &str, c: &SchemaChange) -> Vec<MigrationStep> {
    vec![MigrationStep::new(
        Phase::Contract,
        Some(format!("ALTER TABLE `{db}`.`{table}` DROP COLUMN `{}`", c.column)),
        Some(column_present(db, table, &c.column)),
        Some(format!("SELECT COUNT(*) FROM `{db}`.`{table}` WHERE `{}` IS NOT NULL", c.column)),
        c,
    )]
}

pub fn column_absent(db: &str, table: &str, column: &str) -> String {
    format!(
        "SELECT COUNT(*) = 0 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = '{db}' AND TABLE_NAME = '{table}' AND COLUMN_NAME = '{column}'"
    )
}

pub fn column_present(db: &str, table: &str, column: &str) -> String {
    format!(
        "SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = '{db}' AND TABLE_NAME = '{table}' AND COLUMN_NAME = '{column}'"
    )
}

pub fn table_absent(db: &str, table: &str) -> String {
    format!("SELECT COUNT(*) = 0 FROM information_schema.TABLES WHERE TABLE_SCHEMA = '{db}' AND TABLE_NAME = '{table}'")
}

// ------------------------------------------------------------------ convertibility

const DECIMAL_RE: &str = r"^[+-]?([0-9]+(\\.[0-9]*)?|\\.[0-9]+)([eE][+-]?[0-9]+)?$";
const INTEGER_RE: &str = "^[+-]?[0-9]+$";
const DATE_RE: &str = "^[0-9]{4}-[0-9]{2}-[0-9]{2}";

fn paren_number(t: &str, prefix: &str) -> Option<String> {
    let inner = t.strip_prefix(prefix)?.strip_suffix(')')?;
    if !inner.is_empty() && inner.bytes().all(|b| b.is_ascii_digit()) {
        Some(inner.to_string())
    } else {
        None
    }
}

/// SQL that is true for a value convertible to `target`, or an error when no safe
/// predicate is known.
pub fn predicate(column: &str, target: Option<&str>) -> Result<String, FilterError> {
    let col = format!("`{column}`");
    let t = target.map(|t| t.trim().to_uppercase()).unwrap_or_default();

    let known = match t.as_str() {
        "TEXT" | "LONGTEXT" | "MEDIUMTEXT" => Some("1 = 1".to_string()),
        "INT" | "BIGINT" | "SMALLINT" => Some(format!("{col} REGEXP '{INTEGER_RE}'")),
        "TINYINT(1)" => Some(format!("{col} REGEXP '^[01]$'")),
        "DOUBLE" | "FLOAT" => Some(format!("{col} REGEXP '{DECIMAL_RE}'")),
        "DATE" | "DATETIME" | "DATETIME(3)" | "TIMESTAMP" => Some(format!("{col} REGEXP '{DATE_RE}'")),
        "JSON" => Some(format!("JSON_VALID({col})")),
        _ => None,
    };
    if let Some(k) = known {
        return Ok(k);
    }

    if let Some(n) = paren_number(&t, "VARCHAR(") {
        return Ok(format!("CHAR_LENGTH({col}) <= {n}"));
    }
    if let Some(n) = paren_number(&t, "CHAR(") {
        return Ok(format!("CHAR_LENGTH({col}) <= {n}"));
    }
    if t.starts_with("DECIMAL") {
        return Ok(format!("{col} REGEXP '{DECIMAL_RE}'"));
    }

    Err(FilterError::Unsupported(format!(
        "no safe convertibility check is known for target type {}, so this change cannot be migrated automatically",
        target.unwrap_or("null")
    )))
}

/// Counts the rows that would NOT survive the change.
pub fn preflight(db: &str, table: &str, column: &str, target: Option<&str>) -> Result<String, FilterError> {
    Ok(format!(
        "SELECT COUNT(*) FROM `{db}`.`{table}` WHERE `{column}` IS NOT NULL AND NOT ({})",
        predicate(column, target)?
    ))
}

/// `MigrationPlanCodec.write`.
pub fn write_plan(plan: &[MigrationStep]) -> String {
    serde_json::to_string(plan).unwrap_or_else(|_| "[]".into())
}

/// `MigrationPlanCodec.read`: empty for a missing or unreadable plan.
pub fn read_plan(json: Option<&str>) -> Vec<MigrationStep> {
    match json {
        Some(j) if !j.trim().is_empty() => serde_json::from_str(j).unwrap_or_default(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DB: &str = "LZCLA_leadzump";
    const T: &str = "sales";

    fn p(changes: Vec<SchemaChange>) -> Vec<MigrationStep> {
        plan(DB, T, 7, &changes).unwrap()
    }

    fn widen(c: &str, from: Option<&str>, to: &str) -> SchemaChange {
        SchemaChange::new(Kind::Widening, c, from, Some(to), "test")
    }

    fn narrow(c: &str, from: Option<&str>, to: &str) -> SchemaChange {
        SchemaChange::new(Kind::Narrowing, c, from, Some(to), "test")
    }

    fn drop(c: &str, from: &str) -> SchemaChange {
        SchemaChange::new(Kind::Destructive, c, Some(from), None, "test")
    }

    fn phases(steps: &[MigrationStep]) -> Vec<Phase> {
        steps.iter().map(|s| s.phase).collect()
    }

    #[test]
    fn widening_steps() {
        let s = p(vec![widen("region", None, "VARCHAR(40)")]);
        assert_eq!(s.len(), 1);
        assert!(s[0].sql.as_ref().unwrap().contains("ADD COLUMN `region` VARCHAR(40) NULL"));
        assert!(s[0].data_check.is_none());
        let s = p(vec![widen("code", Some("VARCHAR(10)"), "VARCHAR(50)")]);
        assert!(s[0].sql.as_ref().unwrap().contains("MODIFY COLUMN `code` VARCHAR(50)"));
        assert!(!phases(&p(vec![widen("a", None, "INT"), widen("b", None, "INT")])).contains(&Phase::Snapshot));
    }

    #[test]
    fn narrowing_steps() {
        let s = p(vec![narrow("amount", Some("VARCHAR(40)"), "DOUBLE")]);
        assert_eq!(
            phases(&s),
            vec![Phase::Snapshot, Phase::Preflight, Phase::Expand, Phase::Backfill, Phase::Verify, Phase::Contract, Phase::Contract]
        );
        let verify = phases(&s).iter().position(|p| *p == Phase::Verify).unwrap();
        let drop_at = s.iter().rposition(|x| x.sql.as_ref().is_some_and(|q| q.contains("DROP COLUMN `amount`"))).unwrap();
        assert!(verify < drop_at);
        let pre = s.iter().find(|x| x.phase == Phase::Preflight).unwrap();
        let check = pre.data_check.as_ref().unwrap();
        assert!(check.contains("`amount` IS NOT NULL") && !check.contains("amount__v"), "{check}");
        let back = s.iter().find(|x| x.phase == Phase::Backfill).unwrap();
        assert!(back.sql.as_ref().unwrap().contains("REGEXP") && back.sql.as_ref().unwrap().starts_with("UPDATE "));
        assert!(s.iter().any(|x| x.sql.as_ref().is_some_and(|q| q.contains("amount__v7"))));
        let s = p(vec![narrow("code", None, "VARCHAR(10)")]);
        assert_eq!(phases(&s), vec![Phase::Snapshot, Phase::Preflight, Phase::Expand]);
        assert!(s[1].data_check.as_ref().unwrap().contains("SELECT COUNT(*)"));
    }

    #[test]
    fn destructive_steps() {
        let s = p(vec![drop("legacy", "VARCHAR(10)")]);
        assert_eq!(s[0].phase, Phase::Snapshot);
        assert!(s[0].sql.as_ref().unwrap().contains("sales__bak_7"));
        let d = s.iter().find(|x| x.phase == Phase::Contract).unwrap();
        assert!(d.data_check.as_ref().unwrap().contains("`legacy` IS NOT NULL"));
        assert!(d.is_destructive());
        let snaps = p(vec![drop("a", "INT"), drop("b", "INT"), narrow("c", Some("VARCHAR(9)"), "INT")])
            .iter()
            .filter(|x| x.phase == Phase::Snapshot)
            .count();
        assert_eq!(snaps, 1);
    }

    #[test]
    fn reruns() {
        for s in p(vec![widen("a", None, "INT"), narrow("amount", Some("VARCHAR(40)"), "DOUBLE"), drop("old", "INT")]) {
            if s.sql.is_none() {
                continue;
            }
            let pre = s.precondition.as_ref().unwrap();
            assert!(pre.contains("information_schema"), "{pre}");
        }
        assert!(p(vec![widen("region", None, "VARCHAR(40)")])[0].precondition.as_ref().unwrap().contains("= 0"));
        assert!(!p(vec![widen("code", Some("VARCHAR(10)"), "VARCHAR(50)")])[0].precondition.as_ref().unwrap().contains("= 0"));
        let snap = &p(vec![drop("a", "INT")])[0];
        assert!(snap.precondition.as_ref().unwrap().contains("information_schema.TABLES"));
        assert!(snap.precondition.as_ref().unwrap().contains("= 0"));
        assert!(plan(DB, T, 1, &[]).unwrap().is_empty());
    }

    #[test]
    fn ordering() {
        let s = p(vec![widen("fresh", None, "INT"), drop("legacy", "INT"), narrow("amt", Some("VARCHAR(9)"), "INT")]);
        assert_eq!(s[0].phase, Phase::Snapshot);
        let s = p(vec![narrow("amt", Some("VARCHAR(9)"), "INT")]);
        let mut verify: isize = -1;
        for (i, x) in s.iter().enumerate() {
            if matches!(x.phase, Phase::Verify | Phase::Preflight) {
                verify = i as isize;
            }
            if x.phase == Phase::Contract {
                assert!(verify >= 0 && verify < i as isize);
            }
        }
    }

    #[test]
    fn plans_round_trip_with_the_java_codec() {
        let java = r#"[{"phase":"EXPAND","sql":"ALTER TABLE `SYSTEM_loopzump`.`t` ADD COLUMN `cycleMs` BIGINT NULL","precondition":"SELECT COUNT(*) = 0 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'SYSTEM_loopzump' AND TABLE_NAME = 't' AND COLUMN_NAME = 'cycleMs'","dataCheck":null,"describes":{"kind":"WIDENING","column":"cycleMs","from":null,"to":"BIGINT","reason":"new nullable column","collation":null},"destructive":false}]"#;
        let plan = read_plan(Some(java));
        assert_eq!(plan.len(), 1);
        assert_eq!(write_plan(&plan), java);
        assert!(read_plan(Some("not json")).is_empty());
        assert!(read_plan(None).is_empty());
    }

    #[test]
    fn convertibility() {
        assert_eq!(predicate("a", Some("TEXT")).unwrap(), "1 = 1");
        assert_eq!(predicate("a", Some("varchar(20)")).unwrap(), "CHAR_LENGTH(`a`) <= 20");
        assert!(predicate("a", Some("DOUBLE")).unwrap().contains("REGEXP"));
        assert_eq!(predicate("a", Some("JSON")).unwrap(), "JSON_VALID(`a`)");
        assert!(predicate("a", Some("BLOB")).is_err());
    }
}
