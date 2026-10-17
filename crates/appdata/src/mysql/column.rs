//! `MySQLColumn` and `MySQLColumnDefinitions`: one column of a storage table, and the
//! rendering and checking of an author's declared column type.

use crate::field_names;
use crate::model::{Arity, MySqlColumnDefinition, MySqlColumnType};

/// A column name that would not be safe in DDL. The one gate every path goes through.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("not a usable column name: {0}")]
pub struct InvalidColumnName(pub String);

/// One column of a storage table.
///
/// `type` is rendered to match what `information_schema.COLUMN_TYPE` reports (so a diff
/// can compare the two as text); the collation is carried apart because MySQL does not
/// report it in COLUMN_TYPE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MySqlColumn {
    name: String,
    pub column_type: String,
    pub nullable: bool,
    pub note: Option<String>,
    pub collation: Option<String>,
}

impl MySqlColumn {
    pub fn new(name: &str, column_type: &str, nullable: bool) -> Result<MySqlColumn, InvalidColumnName> {
        Self::full(name, column_type, nullable, None, None)
    }

    pub fn with_note(
        name: &str,
        column_type: &str,
        nullable: bool,
        note: Option<String>,
    ) -> Result<MySqlColumn, InvalidColumnName> {
        Self::full(name, column_type, nullable, note, None)
    }

    pub fn full(
        name: &str,
        column_type: &str,
        nullable: bool,
        note: Option<String>,
        collation: Option<String>,
    ) -> Result<MySqlColumn, InvalidColumnName> {
        if !field_names::valid(name) {
            return Err(InvalidColumnName(name.to_string()));
        }
        Ok(MySqlColumn { name: name.to_string(), column_type: column_type.to_string(), nullable, note, collation })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn with_collation(mut self, collation: Option<String>) -> MySqlColumn {
        self.collation = collation;
        self
    }

    /// The fragment this column contributes to a CREATE TABLE or ADD COLUMN.
    pub fn ddl(&self) -> String {
        format!(
            "`{}` {}{}{}",
            self.name,
            self.column_type,
            self.collation.as_ref().map(|c| format!(" COLLATE {c}")).unwrap_or_default(),
            if self.nullable { " NULL" } else { " NOT NULL" }
        )
    }
}

const MAX_FIXED_LENGTH: i32 = 255;
const MAX_SCALE: i32 = 30;

fn collation_ok(c: &str) -> bool {
    !c.is_empty() && c.len() <= 64 && c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// The declared column type, as MySQL will report it back. Requires a type.
pub fn render_type(def: &MySqlColumnDefinition) -> String {
    let Some(t) = def.column_type else { return String::new() };
    let mut s = t.name().to_string();
    match t.arity() {
        Arity::Length => s.push_str(&format!("({})", def.length.unwrap_or(0))),
        Arity::PrecisionScale => {
            s.push_str(&format!("({},{})", def.precision.unwrap_or(0), def.scale.unwrap_or(0)))
        }
        Arity::FractionalSeconds => {
            if let Some(p) = def.precision.filter(|p| *p > 0) {
                s.push_str(&format!("({p})"));
            }
        }
        Arity::None => {}
    }
    if def.unsigned == Some(true) && t.numeric() {
        s.push_str(" UNSIGNED");
    }
    s
}

/// The collation to apply, or none; only ever a value that is an identifier.
pub fn collation(def: &MySqlColumnDefinition) -> Option<String> {
    def.collation.as_ref().filter(|c| !c.trim().is_empty() && collation_ok(c)).cloned()
}

/// Everything wrong with this definition, in words an author can act on.
pub fn problems(field: &str, def: Option<&MySqlColumnDefinition>, require_type: bool) -> Vec<String> {
    let mut out = Vec::new();
    let Some(def) = def else { return out };

    let Some(t) = def.column_type else {
        if require_type {
            out.push(format!("{field}: mysql.type is required when a mysql column definition is given"));
        }
        return out;
    };
    let tn = t.name();

    match t.arity() {
        Arity::Length => {
            if def.scale.is_some() {
                out.push(format!("{field}: {tn} takes no scale"));
            }
            match def.length {
                None => out.push(format!("{field}: {tn} needs a length, because MySQL defaults it invisibly")),
                Some(len) => {
                    let max = if t == MySqlColumnType::Char || t == MySqlColumnType::Binary {
                        MAX_FIXED_LENGTH
                    } else {
                        MySqlColumnType::MAX_VARCHAR
                    };
                    if len < 1 || len > max {
                        out.push(format!("{field}: {tn} length must be between 1 and {max}, not {len}"));
                    }
                }
            }
        }
        Arity::PrecisionScale => {
            if def.length.is_some() {
                out.push(format!("{field}: {tn} takes no length"));
            }
            match (def.precision, def.scale) {
                (Some(p), Some(s)) => {
                    if p < 1 || p > MySqlColumnType::MAX_PRECISION {
                        out.push(format!(
                            "{field}: precision must be between 1 and {}, not {p}",
                            MySqlColumnType::MAX_PRECISION
                        ));
                    }
                    if !(0..=MAX_SCALE).contains(&s) {
                        out.push(format!("{field}: scale must be between 0 and {MAX_SCALE}, not {s}"));
                    }
                    if p >= 1 && s >= 0 && s > p {
                        out.push(format!("{field}: scale {s} cannot exceed precision {p}"));
                    }
                }
                _ => out.push(format!(
                    "{field}: {tn} needs both a precision and a scale, because MySQL defaults them to (10,0) invisibly and would drop every fractional digit"
                )),
            }
        }
        Arity::FractionalSeconds => {
            if def.length.is_some() {
                out.push(format!("{field}: {tn} takes no length"));
            }
            if def.scale.is_some() {
                out.push(format!("{field}: {tn} takes no scale"));
            }
            if let Some(p) = def.precision {
                if p < 0 || p > MySqlColumnType::MAX_FRACTIONAL_SECONDS {
                    out.push(format!(
                        "{field}: {tn} fractional seconds must be between 0 and {}, not {p}",
                        MySqlColumnType::MAX_FRACTIONAL_SECONDS
                    ));
                }
            }
        }
        Arity::None => {
            if def.length.is_some() {
                out.push(format!("{field}: {tn} takes no length"));
            }
            if def.precision.is_some() {
                out.push(format!("{field}: {tn} takes no precision"));
            }
            if def.scale.is_some() {
                out.push(format!("{field}: {tn} takes no scale"));
            }
        }
    }

    if def.unsigned == Some(true) && !t.numeric() {
        out.push(format!("{field}: unsigned means nothing for {tn}"));
    }

    if let Some(c) = def.collation.as_ref().filter(|c| !c.trim().is_empty()) {
        if !t.textual() {
            out.push(format!("{field}: a collation applies only to a text column, and {tn} is not one"));
        } else if !collation_ok(c) {
            out.push(format!("{field}: {c} is not a collation name"));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn def(t: MySqlColumnType) -> MySqlColumnDefinition {
        MySqlColumnDefinition { column_type: Some(t), ..Default::default() }
    }

    #[test]
    fn rendering() {
        let mut d = def(MySqlColumnType::Decimal);
        d.precision = Some(10);
        d.scale = Some(2);
        assert_eq!(render_type(&d), "DECIMAL(10,2)");
        d.unsigned = Some(true);
        assert_eq!(render_type(&d), "DECIMAL(10,2) UNSIGNED");
        let mut v = def(MySqlColumnType::Varchar);
        v.length = Some(20);
        v.unsigned = Some(true);
        assert_eq!(render_type(&v), "VARCHAR(20)");
        assert_eq!(render_type(&def(MySqlColumnType::Datetime)), "DATETIME");
        let mut dt = def(MySqlColumnType::Datetime);
        dt.precision = Some(0);
        assert_eq!(render_type(&dt), "DATETIME");
        dt.precision = Some(6);
        assert_eq!(render_type(&dt), "DATETIME(6)");
        assert_eq!(render_type(&def(MySqlColumnType::Json)), "JSON");
        assert_eq!(render_type(&def(MySqlColumnType::Bigint)), "BIGINT");
        let mut c = def(MySqlColumnType::Varchar);
        c.length = Some(30);
        c.collation = Some("utf8mb4_bin".into());
        assert_eq!(render_type(&c), "VARCHAR(30)");
        assert_eq!(collation(&c).as_deref(), Some("utf8mb4_bin"));
    }

    #[test]
    fn refusals() {
        let p = problems("price", Some(&def(MySqlColumnType::Decimal)), true);
        assert_eq!(p.len(), 1);
        assert!(p[0].contains("precision and a scale"));
        assert!(problems("name", Some(&def(MySqlColumnType::Varchar)), true).iter().any(|p| p.contains("needs a length")));
        let mut d = def(MySqlColumnType::Decimal);
        d.precision = Some(4);
        d.scale = Some(6);
        assert!(problems("rate", Some(&d), true).iter().any(|p| p.contains("cannot exceed precision")));
        let mut ch = def(MySqlColumnType::Char);
        ch.length = Some(300);
        assert!(problems("code", Some(&ch), true).iter().any(|p| p.contains("between 1 and 255")));
        let mut vc = def(MySqlColumnType::Varchar);
        vc.length = Some(300);
        assert!(problems("blurb", Some(&vc), true).is_empty());
        let mut j = def(MySqlColumnType::Json);
        j.length = Some(10);
        assert!(problems("flag", Some(&j), true).iter().any(|p| p.contains("takes no length")));
        let mut b = def(MySqlColumnType::Bigint);
        b.collation = Some("utf8mb4_bin".into());
        assert!(problems("n", Some(&b), true).iter().any(|p| p.contains("only to a text column")));
        let mut x = def(MySqlColumnType::Varchar);
        x.length = Some(10);
        x.collation = Some("utf8mb4_bin, DROP COLUMN secret".into());
        assert!(!problems("x", Some(&x), true).is_empty());
        assert!(collation(&x).is_none());
        assert!(problems("x", None, true).is_empty());
        assert!(problems("x", Some(&MySqlColumnDefinition::default()), true)
            .iter()
            .any(|p| p.contains("mysql.type is required")));
    }

    #[test]
    fn hostile_names_are_refused_at_the_column() {
        assert!(MySqlColumn::new("a` INT, ADD COLUMN `pwned", "INT", true).is_err());
        assert_eq!(MySqlColumn::new("f", "INT", true).unwrap().ddl(), "`f` INT NULL");
    }
}
