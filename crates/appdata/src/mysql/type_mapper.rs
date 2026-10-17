//! `MySQLTypeMapper`: a storage's KIRun schema turned into MySQL columns.
//!
//! Pure, and the start of every DDL decision the backend makes.

use std::collections::BTreeMap;

use indexmap::IndexSet;

use super::column::{collation, render_type, InvalidColumnName, MySqlColumn};
use crate::model::{ColumnDefinitions, MySqlColumnDefinition, Schema, SchemaType, StringFormat};
use crate::value::Value;

pub const ID_COLUMN: &str = "_id";
pub const ID_TYPE: &str = "CHAR(26)";
pub const JSON_TYPE: &str = "JSON";
pub const DEFAULT_DECIMAL: &str = "DECIMAL(19,4)";

const MAX_VARCHAR: i32 = 4000;
const DEFAULT_VARCHAR: i32 = 255;
const EMAIL_LENGTH: i32 = 320;

pub type Columns = Result<Vec<MySqlColumn>, InvalidColumnName>;

/// Every column for a storage, ordered by field name, the id excluded.
pub fn columns(schema: Option<&Schema>, defs: Option<&ColumnDefinitions>) -> Columns {
    let mut out = Vec::new();
    let Some(schema) = schema else { return Ok(out) };
    let Some(props) = &schema.properties else { return Ok(out) };
    if props.is_empty() {
        return Ok(out);
    }

    let required: Vec<&String> = schema.required.as_ref().map(|r| r.iter().collect()).unwrap_or_default();
    let sorted: BTreeMap<&String, &Schema> = props.iter().collect();

    for (name, field) in sorted {
        if name == ID_COLUMN {
            continue;
        }
        let nullable = !required.contains(&name);
        out.push(column(name, Some(field), nullable, declared(defs, name))?);
    }
    Ok(out)
}

fn declared<'a>(defs: Option<&'a ColumnDefinitions>, field: &str) -> Option<&'a MySqlColumnDefinition> {
    defs?.get(field)?.mysql.as_ref().filter(|m| m.column_type.is_some())
}

/// The column for one field, a declared physical shape taking precedence.
pub fn column(
    name: &str,
    field: Option<&Schema>,
    nullable: bool,
    declared: Option<&MySqlColumnDefinition>,
) -> Result<MySqlColumn, InvalidColumnName> {
    if let Some(d) = declared.filter(|d| d.column_type.is_some()) {
        return MySqlColumn::full(name, &render_type(d), nullable, None, collation(d));
    }

    let Some(field) = field else { return json(name, nullable, "no schema for this field") };

    if let Some(r) = field.reference.as_ref().filter(|r| !r.trim().is_empty()) {
        return json(
            name,
            nullable,
            &format!("unresolved reference {r}, so the shape is not known at publish time"),
        );
    }

    let types = field.allowed_types();
    if types.is_empty() {
        return untyped(name, field, nullable);
    }

    let real: Vec<SchemaType> = types.iter().copied().filter(|t| *t != SchemaType::Null).collect();

    if real.len() > 1 {
        let names: Vec<&str> = real.iter().map(SchemaType::name).collect();
        return json(
            name,
            nullable,
            &format!("declares several types [{}], so it cannot be a typed column", names.join(", ")),
        );
    }

    let Some(t) = real.first() else { return json(name, nullable, "declares only NULL") };

    match t {
        SchemaType::String => string_column(name, field, nullable),
        SchemaType::Integer => MySqlColumn::new(name, "INT", nullable),
        SchemaType::Long => MySqlColumn::new(name, "BIGINT", nullable),
        SchemaType::Float => MySqlColumn::new(name, "FLOAT", nullable),
        SchemaType::Double => MySqlColumn::new(name, "DOUBLE", nullable),
        SchemaType::Boolean => MySqlColumn::new(name, "TINYINT(1)", nullable),
        SchemaType::Object => json(name, nullable, &nested(field)),
        SchemaType::Array => json(name, nullable, "an array, stored whole as JSON"),
        SchemaType::Null => json(name, nullable, "declares only NULL"),
    }
}

fn nested(field: &Schema) -> String {
    let count = field.properties.as_ref().map(|p| p.len()).unwrap_or(0);
    if count == 0 {
        "an object with no declared properties, stored whole as JSON".into()
    } else {
        format!(
            "a nested object ({count} field(s)), stored whole as JSON: readable and filterable by path, but not joinable or indexable. Lift a field to the top level to join on it."
        )
    }
}

fn untyped(name: &str, field: &Schema, nullable: bool) -> Result<MySqlColumn, InvalidColumnName> {
    if field.properties.as_ref().is_some_and(|p| !p.is_empty()) {
        return json(
            name,
            nullable,
            &format!("no declared type but it has properties, so it is treated as {}", nested(field)),
        );
    }
    if field.items.is_some() {
        return json(name, nullable, "no declared type but it has items, so it is treated as an array");
    }
    json(name, nullable, "no declared type, stored as JSON. Declare a type to get a real column.")
}

fn json(name: &str, nullable: bool, note: &str) -> Result<MySqlColumn, InvalidColumnName> {
    MySqlColumn::with_note(name, JSON_TYPE, nullable, Some(note.to_string()))
}

fn string_column(name: &str, field: &Schema, nullable: bool) -> Result<MySqlColumn, InvalidColumnName> {
    match field.format {
        Some(StringFormat::DateTime) => return MySqlColumn::new(name, "DATETIME(3)", nullable),
        Some(StringFormat::Date) => return MySqlColumn::new(name, "DATE", nullable),
        Some(StringFormat::Time) => return MySqlColumn::new(name, "TIME(3)", nullable),
        Some(StringFormat::Id) => return MySqlColumn::new(name, ID_TYPE, nullable),
        Some(StringFormat::Decimal) => {
            return MySqlColumn::with_note(
                name,
                DEFAULT_DECIMAL,
                nullable,
                Some(format!(
                    "stored as {DEFAULT_DECIMAL}, the conventional shape for money. Declare maxLength for more total digits; the scale is not yet configurable."
                )),
            )
        }
        _ => {}
    }

    let max = field.max_length.or_else(|| implied_length(field));

    let Some(max) = max else {
        return MySqlColumn::with_note(
            name,
            "TEXT",
            nullable,
            Some(
                "no maxLength, so this becomes TEXT and cannot be indexed, joined on, or given a default. Declare maxLength to get a VARCHAR."
                    .into(),
            ),
        );
    };

    if max <= 0 {
        return MySqlColumn::with_note(
            name,
            &format!("VARCHAR({DEFAULT_VARCHAR})"),
            nullable,
            Some(format!("maxLength {max} is not usable, defaulted to {DEFAULT_VARCHAR}")),
        );
    }

    if max > MAX_VARCHAR {
        return MySqlColumn::with_note(
            name,
            "TEXT",
            nullable,
            Some(format!("maxLength {max} exceeds {MAX_VARCHAR}, so TEXT is used")),
        );
    }

    MySqlColumn::new(name, &format!("VARCHAR({max})"), nullable)
}

fn implied_length(field: &Schema) -> Option<i32> {
    if let Some(enums) = field.enums.as_ref().filter(|e| !e.is_empty()) {
        let mut longest = 1;
        for e in enums {
            match e {
                // Java's String.length(): UTF-16 units.
                Value::String(s) => longest = longest.max(s.encode_utf16().count() as i32),
                _ => return None,
            }
        }
        return Some(longest);
    }
    if field.format == Some(StringFormat::Email) {
        return Some(EMAIL_LENGTH);
    }
    None
}

pub fn is_json(column_type: &str) -> bool {
    column_type.eq_ignore_ascii_case(JSON_TYPE)
}

pub fn is_decimal(column_type: &str) -> bool {
    column_type.to_uppercase().starts_with("DECIMAL")
}

pub fn is_integral(column_type: &str) -> bool {
    let t = column_type.to_uppercase();
    ["TINYINT", "SMALLINT", "MEDIUMINT", "INT", "BIGINT", "BIT", "BOOL"].iter().any(|p| t.starts_with(p))
}

pub fn is_temporal(column_type: &str) -> bool {
    let t = column_type.to_uppercase();
    t.starts_with("DATETIME") || t.starts_with("TIMESTAMP") || t.starts_with("TIME") || t == "DATE"
}

fn names_where(cols: &[MySqlColumn], pred: impl Fn(&str) -> bool) -> IndexSet<String> {
    cols.iter().filter(|c| pred(&c.column_type)).map(|c| c.name().to_string()).collect()
}

/// Columns the schema calls a STRING but that are stored as a real date or time.
pub fn date_string_columns(schema: Option<&Schema>, defs: Option<&ColumnDefinitions>) -> Result<IndexSet<String>, InvalidColumnName> {
    Ok(names_where(&columns(schema, defs)?, is_temporal))
}

pub fn json_columns(schema: Option<&Schema>, defs: Option<&ColumnDefinitions>) -> Result<IndexSet<String>, InvalidColumnName> {
    Ok(names_where(&columns(schema, defs)?, is_json))
}

pub fn decimal_columns(schema: Option<&Schema>, defs: Option<&ColumnDefinitions>) -> Result<IndexSet<String>, InvalidColumnName> {
    Ok(names_where(&columns(schema, defs)?, is_decimal))
}

/// The columns whose field the schema declares BOOLEAN, stored as an integer.
pub fn boolean_columns(schema: Option<&Schema>, defs: Option<&ColumnDefinitions>) -> Result<IndexSet<String>, InvalidColumnName> {
    let mut out = IndexSet::new();
    let Some(s) = schema else { return Ok(out) };
    let Some(props) = &s.properties else { return Ok(out) };
    for c in columns(schema, defs)? {
        if is_boolean_field(props.get(c.name())) && is_integral(&c.column_type) {
            out.insert(c.name().to_string());
        }
    }
    Ok(out)
}

/// BOOLEAN, alone or with NULL, and nothing else.
pub fn is_boolean_field(field: Option<&Schema>) -> bool {
    let Some(f) = field else { return false };
    let real: Vec<SchemaType> = f.allowed_types().into_iter().filter(|t| *t != SchemaType::Null).collect();
    real.len() == 1 && real[0] == SchemaType::Boolean
}

#[cfg(test)]
mod tests {
    use super::*;
    use indexmap::IndexMap;

    fn obj(props: Vec<(&str, Schema)>) -> Schema {
        Schema {
            types: Some(vec![SchemaType::Object]),
            properties: Some(props.into_iter().map(|(k, v)| (k.to_string(), v)).collect::<IndexMap<_, _>>()),
            ..Default::default()
        }
    }

    fn of(t: SchemaType) -> Schema {
        Schema { types: Some(vec![t]), ..Default::default() }
    }

    fn string() -> Schema {
        of(SchemaType::String)
    }

    fn only(field: Schema) -> MySqlColumn {
        let cols = columns(Some(&obj(vec![("f", field)])), None).unwrap();
        assert_eq!(cols.len(), 1);
        cols.into_iter().next().unwrap()
    }

    #[test]
    fn scalars() {
        assert_eq!(only(of(SchemaType::Integer)).column_type, "INT");
        assert_eq!(only(of(SchemaType::Long)).column_type, "BIGINT");
        assert_eq!(only(of(SchemaType::Float)).column_type, "FLOAT");
        assert_eq!(only(of(SchemaType::Double)).column_type, "DOUBLE");
        assert_eq!(only(of(SchemaType::Boolean)).column_type, "TINYINT(1)");
        let c = only(of(SchemaType::Object));
        assert_eq!(c.column_type, "JSON");
        assert!(c.note.is_some());
    }

    #[test]
    fn strings() {
        let c = only(Schema { max_length: Some(120), ..string() });
        assert_eq!(c.column_type, "VARCHAR(120)");
        assert!(c.note.is_none());
        let c = only(string());
        assert_eq!(c.column_type, "TEXT");
        assert!(c.note.as_ref().unwrap().contains("maxLength"));
        let c = only(Schema { max_length: Some(100000), ..string() });
        assert_eq!(c.column_type, "TEXT");
        assert!(c.note.is_some());
        let c = only(Schema { max_length: Some(0), ..string() });
        assert_eq!(c.column_type, "VARCHAR(255)");
        assert!(c.note.is_some());
        let c = only(Schema { enums: Some(vec!["OPEN".into(), "IN_PROGRESS".into()]), ..string() });
        assert_eq!(c.column_type, "VARCHAR(11)");
        assert!(c.note.is_none());
        let c = only(Schema { max_length: Some(40), enums: Some(vec!["OPEN".into()]), ..string() });
        assert_eq!(c.column_type, "VARCHAR(40)");
        let c = only(Schema { enums: Some(vec!["OPEN".into(), Value::Int(3)]), ..string() });
        assert_eq!(c.column_type, "TEXT");
        let c = only(string().with_format(StringFormat::Email));
        assert_eq!(c.column_type, "VARCHAR(320)");
        assert!(c.note.is_none());
    }

    #[test]
    fn dates() {
        assert_eq!(only(string().with_format(StringFormat::DateTime)).column_type, "DATETIME(3)");
        assert_eq!(only(string().with_format(StringFormat::Date)).column_type, "DATE");
        assert_eq!(only(string().with_format(StringFormat::Time)).column_type, "TIME(3)");
        assert_eq!(
            only(Schema { max_length: Some(40), ..string().with_format(StringFormat::DateTime) }).column_type,
            "DATETIME(3)"
        );
        assert_eq!(
            only(Schema { max_length: Some(80), ..string().with_format(StringFormat::Email) }).column_type,
            "VARCHAR(80)"
        );
    }

    #[test]
    fn nullability_and_edges() {
        let mut s = obj(vec![("a", of(SchemaType::Integer)), ("b", of(SchemaType::Integer))]);
        s.required = Some(vec!["a".into()]);
        let cols = columns(Some(&s), None).unwrap();
        assert!(cols[0].ddl().ends_with("NOT NULL"));
        assert!(cols[1].ddl().ends_with("NULL") && !cols[1].ddl().ends_with("NOT NULL"));

        let cols = columns(Some(&obj(vec![("_id", string()), ("name", string())])), None).unwrap();
        assert_eq!(cols.len(), 1);
        assert_eq!(cols[0].name(), "name");

        let cols = columns(
            Some(&obj(vec![
                ("zebra", of(SchemaType::Integer)),
                ("apple", of(SchemaType::Integer)),
                ("mango", of(SchemaType::Integer)),
            ])),
            None,
        )
        .unwrap();
        let names: Vec<&str> = cols.iter().map(|c| c.name()).collect();
        assert_eq!(names, vec!["apple", "mango", "zebra"]);

        let c = only(Schema { types: Some(vec![SchemaType::String, SchemaType::Integer]), ..Default::default() });
        assert_eq!(c.column_type, "JSON");
        assert!(c.note.as_ref().unwrap().contains("several types"));
        let c = only(Schema {
            types: Some(vec![SchemaType::String, SchemaType::Null]),
            max_length: Some(50),
            ..Default::default()
        });
        assert_eq!(c.column_type, "VARCHAR(50)");

        assert!(columns(None, None).unwrap().is_empty());
        assert!(columns(Some(&Schema::default()), None).unwrap().is_empty());
        assert!(columns(Some(&obj(vec![])), None).unwrap().is_empty());
        assert_eq!(only(of(SchemaType::Integer)).ddl(), "`f` INT NULL");
    }

    #[test]
    fn hostile_names_fail_the_mapping() {
        let s = obj(vec![("a` INT, ADD COLUMN `pwned", of(SchemaType::Integer))]);
        assert!(columns(Some(&s), None).is_err());
    }
}
