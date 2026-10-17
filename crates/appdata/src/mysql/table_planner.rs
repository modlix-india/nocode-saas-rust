//! `MySQLTablePlanner` and `SchemaChange`: the DDL for a storage table, and how dangerous
//! each difference between two versions of it is.

use indexmap::IndexMap;
use sha2::{Digest, Sha256};

use super::column::MySqlColumn;
use super::type_mapper::{ID_COLUMN, ID_TYPE};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Kind {
    /// Safe against any existing data.
    Widening,
    /// May fail or lose data depending on what is stored: data check, expand-contract.
    Narrowing,
    /// Loses a column outright.
    Destructive,
}

/// One column-level difference between the definition and the table.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SchemaChange {
    pub kind: Kind,
    pub column: String,
    pub from: Option<String>,
    pub to: Option<String>,
    pub reason: String,
    #[serde(default)]
    pub collation: Option<String>,
}

impl SchemaChange {
    pub fn new(kind: Kind, column: &str, from: Option<&str>, to: Option<&str>, reason: &str) -> SchemaChange {
        SchemaChange {
            kind,
            column: column.into(),
            from: from.map(str::to_string),
            to: to.map(str::to_string),
            reason: reason.into(),
            collation: None,
        }
    }

    pub fn collate_clause(&self) -> String {
        self.collation.as_ref().map(|c| format!(" COLLATE {c}")).unwrap_or_default()
    }

    pub fn needs_data_check(&self) -> bool {
        self.kind != Kind::Widening
    }
}

/// A short, stable fingerprint of the shape a table is supposed to have: the migration's
/// identity in the journal, so it has to be byte-for-byte the one Java computes.
pub fn shape_of(desired: &[MySqlColumn]) -> String {
    let mut sorted: Vec<&MySqlColumn> = desired.iter().collect();
    sorted.sort_by(|a, b| java_compare(a.name(), b.name()));
    let mut sb = String::new();
    for c in sorted {
        sb.push_str(c.name());
        sb.push(' ');
        sb.push_str(&c.column_type.to_uppercase());
        sb.push_str(if c.nullable { " NULL" } else { " NOT NULL" });
        if let Some(col) = &c.collation {
            sb.push_str(" COLLATE ");
            sb.push_str(&col.to_uppercase());
        }
        sb.push('\n');
    }
    let digest = Sha256::digest(sb.as_bytes());
    hex::encode(&digest[..16])
}

/// `String.compareTo`: by UTF-16 code units.
fn java_compare(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

pub fn create_table(table: &str, columns: &[MySqlColumn]) -> String {
    let mut sb = format!("CREATE TABLE IF NOT EXISTS `{table}` (\n  `{ID_COLUMN}` {ID_TYPE} NOT NULL");
    for c in columns {
        sb.push_str(",\n  ");
        sb.push_str(&c.ddl());
    }
    sb.push_str(&format!(",\n  PRIMARY KEY (`{ID_COLUMN}`)\n)"));
    sb
}

/// What turns `existing` into `desired`: additions, then alterations, then drops.
pub fn diff(existing: &[MySqlColumn], desired: &[MySqlColumn]) -> Vec<SchemaChange> {
    let before: IndexMap<&str, &MySqlColumn> = existing.iter().map(|c| (c.name(), c)).collect();
    let after: IndexMap<&str, &MySqlColumn> = desired.iter().map(|c| (c.name(), c)).collect();

    let mut adds = Vec::new();
    let mut alters = Vec::new();
    let mut drops = Vec::new();

    for d in desired {
        match before.get(d.name()) {
            None => {
                let (kind, reason) = if d.nullable {
                    (Kind::Widening, "new nullable column")
                } else {
                    (Kind::Narrowing, "new NOT NULL column; existing rows have no value for it")
                };
                adds.push(SchemaChange {
                    kind,
                    column: d.name().into(),
                    from: None,
                    to: Some(d.column_type.clone()),
                    reason: reason.into(),
                    collation: d.collation.clone(),
                });
            }
            Some(e) => {
                if let Some(c) = compare(e, d) {
                    alters.push(c);
                }
            }
        }
    }

    for e in existing {
        if !after.contains_key(e.name()) {
            drops.push(SchemaChange::new(
                Kind::Destructive,
                e.name(),
                Some(&e.column_type),
                None,
                "column removed from the schema",
            ));
        }
    }

    adds.extend(alters);
    adds.extend(drops);
    adds
}

fn compare(before: &MySqlColumn, after: &MySqlColumn) -> Option<SchemaChange> {
    let type_changed = !before.column_type.eq_ignore_ascii_case(&after.column_type);
    let tightened = before.nullable && !after.nullable;
    let loosened = !before.nullable && after.nullable;
    let collation_changed = match &after.collation {
        Some(a) => before.collation.as_ref().is_none_or(|b| !a.eq_ignore_ascii_case(b)),
        None => false,
    };

    if !type_changed && !tightened && !loosened && !collation_changed {
        return None;
    }

    let change = |kind: Kind, reason: String| SchemaChange {
        kind,
        column: after.name().into(),
        from: Some(before.column_type.clone()),
        to: Some(after.column_type.clone()),
        reason,
        collation: after.collation.clone(),
    };

    if type_changed && !is_safe_widening(&before.column_type, &after.column_type) {
        return Some(change(Kind::Narrowing, "type change that existing values may not satisfy".into()));
    }

    if tightened {
        return Some(change(Kind::Narrowing, "now NOT NULL; existing rows may hold null".into()));
    }

    let reason = if type_changed {
        "widening type change".to_string()
    } else if collation_changed {
        format!("collation change to {}", after.collation.clone().unwrap_or_default())
    } else {
        "now nullable".to_string()
    };

    Some(change(Kind::Widening, reason))
}

fn varchar_length(t: &str) -> Option<u64> {
    let upper = t.to_uppercase();
    let inner = upper.strip_prefix("VARCHAR(")?.strip_suffix(')')?;
    if inner.is_empty() || !inner.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    inner.parse().ok()
}

const INT_WIDTHS: [&str; 3] = ["TINYINT(1)", "INT", "BIGINT"];

fn index_of_type(t: &str) -> Option<usize> {
    INT_WIDTHS.iter().position(|w| w.eq_ignore_ascii_case(t))
}

/// True only for conversions where no stored value can fail.
pub fn is_safe_widening(from: &str, to: &str) -> bool {
    if from.eq_ignore_ascii_case(to) {
        return true;
    }
    if let (Some(f), Some(t)) = (varchar_length(from), varchar_length(to)) {
        return t >= f;
    }
    if varchar_length(from).is_some() && to.eq_ignore_ascii_case("TEXT") {
        return true;
    }
    if let (Some(fi), Some(ti)) = (index_of_type(from), index_of_type(to)) {
        return ti >= fi;
    }
    if index_of_type(from).is_some() && to.eq_ignore_ascii_case("DOUBLE") {
        return true;
    }
    from.eq_ignore_ascii_case("FLOAT") && to.eq_ignore_ascii_case("DOUBLE")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn col(n: &str, t: &str) -> MySqlColumn {
        MySqlColumn::new(n, t, true).unwrap()
    }

    fn not_null(n: &str, t: &str) -> MySqlColumn {
        MySqlColumn::new(n, t, false).unwrap()
    }

    fn one(before: Vec<MySqlColumn>, after: Vec<MySqlColumn>) -> SchemaChange {
        let cs = diff(&before, &after);
        assert_eq!(cs.len(), 1, "{cs:?}");
        cs.into_iter().next().unwrap()
    }

    #[test]
    fn create_table_shape() {
        let ddl = create_table("sales", &[col("region", "VARCHAR(40)")]);
        assert!(ddl.contains("`_id` CHAR(26) NOT NULL") && ddl.contains("PRIMARY KEY (`_id`)"), "{ddl}");
        assert!(create_table("t", &[]).starts_with("CREATE TABLE IF NOT EXISTS"));
        let ddl = create_table("t", &[col("a", "INT"), not_null("b", "VARCHAR(10)")]);
        assert!(ddl.contains("`a` INT NULL") && ddl.contains("`b` VARCHAR(10) NOT NULL"), "{ddl}");
        assert_eq!(
            create_table("t", &[col("a", "INT")]),
            "CREATE TABLE IF NOT EXISTS `t` (\n  `_id` CHAR(26) NOT NULL,\n  `a` INT NULL,\n  PRIMARY KEY (`_id`)\n)"
        );
    }

    #[test]
    fn widening() {
        assert_eq!(one(vec![], vec![col("a", "INT")]).kind, Kind::Widening);
        assert_eq!(one(vec![col("a", "VARCHAR(10)")], vec![col("a", "VARCHAR(50)")]).kind, Kind::Widening);
        assert_eq!(one(vec![col("a", "VARCHAR(10)")], vec![col("a", "TEXT")]).kind, Kind::Widening);
        assert_eq!(one(vec![col("a", "INT")], vec![col("a", "BIGINT")]).kind, Kind::Widening);
        assert_eq!(one(vec![not_null("a", "INT")], vec![col("a", "INT")]).kind, Kind::Widening);
        assert!(!one(vec![], vec![col("a", "INT")]).needs_data_check());
    }

    #[test]
    fn narrowing() {
        let c = one(vec![col("amount", "VARCHAR(40)")], vec![col("amount", "DOUBLE")]);
        assert_eq!(c.kind, Kind::Narrowing);
        assert!(c.needs_data_check());
        assert_eq!(one(vec![col("a", "VARCHAR(50)")], vec![col("a", "VARCHAR(10)")]).kind, Kind::Narrowing);
        assert_eq!(one(vec![col("a", "BIGINT")], vec![col("a", "INT")]).kind, Kind::Narrowing);
        assert_eq!(one(vec![col("a", "TEXT")], vec![col("a", "VARCHAR(10)")]).kind, Kind::Narrowing);
        let c = one(vec![col("a", "INT")], vec![not_null("a", "INT")]);
        assert_eq!(c.kind, Kind::Narrowing);
        assert!(c.reason.contains("null"));
        assert_eq!(one(vec![], vec![not_null("a", "INT")]).kind, Kind::Narrowing);
        assert_eq!(one(vec![col("a", "JSON")], vec![col("a", "DATETIME(3)")]).kind, Kind::Narrowing);
        let c = one(vec![col("a", "INT")], vec![]);
        assert_eq!(c.kind, Kind::Destructive);
        assert!(c.needs_data_check());
    }

    #[test]
    fn ordering() {
        let cs = diff(&[col("old", "INT")], &[col("new", "INT")]);
        assert_eq!(cs.len(), 2);
        assert_eq!(cs[0].column, "new");
        assert_eq!(cs[1].kind, Kind::Destructive);
        let same = vec![col("a", "INT"), not_null("b", "VARCHAR(5)")];
        assert!(diff(&same, &same).is_empty());
        assert!(diff(&[col("a", "int")], &[col("a", "INT")]).is_empty());
    }

    #[test]
    fn shape_keys() {
        let name = col("name", "VARCHAR(60)");
        let age = col("age", "INT");
        assert_eq!(shape_of(&[name.clone(), age.clone()]), shape_of(&[age.clone(), name.clone()]));
        assert_ne!(shape_of(&[name.clone()]), shape_of(&[col("name", "VARCHAR(120)")]));
        assert_ne!(shape_of(&[name.clone()]), shape_of(&[not_null("name", "VARCHAR(60)")]));
        assert_ne!(shape_of(&[name.clone()]), shape_of(&[name.clone(), age]));
        assert_ne!(shape_of(&[name.clone()]), shape_of(&[col("title", "VARCHAR(60)")]));
        assert_eq!(shape_of(&[name.clone()]), shape_of(&[col("name", "varchar(60)")]));
        let noted = MySqlColumn::with_note("name", "VARCHAR(60)", true, Some("declare maxLength".into())).unwrap();
        assert_eq!(shape_of(&[name.clone()]), shape_of(&[noted]));
        assert_eq!(shape_of(&[]).len(), 32);
        assert_ne!(shape_of(&[]), shape_of(&[name]));
    }
}
