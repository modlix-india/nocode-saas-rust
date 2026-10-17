//! `MySQLColumnNames`: the edge between a storage's field names and the columns they are
//! stored in. For every storage whose fields are already identifiers, each function here
//! is the identity.

use indexmap::IndexMap;

use crate::field_names;
use crate::model::{ColumnDefinitions, Schema};
use crate::value::Document;

/// The resolved schema as MySQL sees it: properties keyed by column, and the column to
/// field map for the ones that differ.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PhysicalSchema {
    pub schema: Schema,
    pub field_by_column: IndexMap<String, String>,
}

impl PhysicalSchema {
    pub fn schema(&self) -> Option<&Schema> {
        Some(&self.schema)
    }

    pub fn field_names(&self) -> &IndexMap<String, String> {
        &self.field_by_column
    }

    /// A row from the table, keyed the way the caller declared it.
    pub fn to_fields(&self, row: Document) -> Document {
        to_fields(row, &self.field_by_column)
    }
}

/// `MySQLColumnNames.physical`.
pub fn physical(resolved: Schema) -> PhysicalSchema {
    let Some(props) = &resolved.properties else {
        return PhysicalSchema { schema: resolved, field_by_column: IndexMap::new() };
    };

    let mut field_by_column = IndexMap::new();
    for field in props.keys() {
        let col = field_names::column(field);
        if &col != field {
            field_by_column.insert(col, field.clone());
        }
    }
    if field_by_column.is_empty() {
        return PhysicalSchema { schema: resolved, field_by_column };
    }

    let mut out = resolved.clone();
    out.properties = Some(props.iter().map(|(k, v)| (field_names::column(k), v.clone())).collect());
    out.required = resolved.required.as_ref().map(|r| r.iter().map(|f| field_names::column(f)).collect());
    PhysicalSchema { schema: out, field_by_column }
}

/// The column a name in a query reads. A dotted name is left exactly as it is.
pub fn column(name: &str) -> String {
    if name.contains('.') {
        name.to_string()
    } else {
        field_names::column(name)
    }
}

/// A caller's row, keyed the way the table is.
pub fn to_columns(data: &Document) -> Document {
    data.iter().map(|(k, v)| (field_names::column(k), v.clone())).collect()
}

pub fn to_fields(row: Document, field_by_column: &IndexMap<String, String>) -> Document {
    if field_by_column.is_empty() {
        return row;
    }
    row.into_iter()
        .map(|(k, v)| (field_by_column.get(&k).cloned().unwrap_or(k), v))
        .collect()
}

/// Column definitions are written against field names and read against columns.
pub fn column_definitions(defs: Option<&ColumnDefinitions>) -> Option<ColumnDefinitions> {
    let defs = defs?;
    if defs.keys().all(|k| field_names::column(k) == *k) {
        return Some(defs.clone());
    }
    Some(defs.iter().map(|(k, v)| (field_names::column(k), v.clone())).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SchemaType;
    use crate::mysql::{table_planner, type_mapper};
    use crate::value::Value;

    fn hdfc() -> Schema {
        let mut props = IndexMap::new();
        for n in ["IFSC Code", "Virtual Account ", "paymentId"] {
            props.insert(n.to_string(), Schema::of_string(n));
        }
        Schema {
            types: Some(vec![SchemaType::Object]),
            properties: Some(props),
            required: Some(vec!["IFSC Code".into()]),
            ..Default::default()
        }
    }

    #[test]
    fn ddl_is_built_from_columns() {
        let p = physical(hdfc());
        let keys: Vec<&String> = p.schema.properties.as_ref().unwrap().keys().collect();
        assert_eq!(keys, vec!["IFSC_Code", "Virtual_Account_", "paymentId"]);
        assert_eq!(p.schema.required, Some(vec!["IFSC_Code".to_string()]));
        let ddl = table_planner::create_table("t", &type_mapper::columns(p.schema(), None).unwrap());
        assert!(ddl.contains("`IFSC_Code` "), "{ddl}");
        assert!(ddl.contains("`Virtual_Account_` "), "{ddl}");
        assert!(ddl.contains("NOT NULL"), "{ddl}");
    }

    #[test]
    fn rows_round_trip() {
        let p = physical(hdfc());
        let mut row = Document::new();
        row.insert("IFSC Code".into(), Value::from("HDFC0000001"));
        row.insert("Virtual Account ".into(), Value::from("VA1"));
        row.insert("paymentId".into(), Value::from("p1"));
        let mut stored = to_columns(&row);
        let keys: Vec<&String> = stored.keys().collect();
        assert_eq!(keys, vec!["IFSC_Code", "Virtual_Account_", "paymentId"]);
        stored.insert("_id".into(), Value::from("01J"));
        let out = p.to_fields(stored);
        assert_eq!(out.get("IFSC Code"), Some(&Value::from("HDFC0000001")));
        assert_eq!(out.get("Virtual Account "), Some(&Value::from("VA1")));
        assert_eq!(out.get("_id"), Some(&Value::from("01J")));
    }

    #[test]
    fn identifiers_are_untouched() {
        let mut props = IndexMap::new();
        props.insert("amount".to_string(), Schema { types: Some(vec![SchemaType::Double]), ..Default::default() });
        let plain = Schema { properties: Some(props), ..Default::default() };
        let p = physical(plain.clone());
        assert_eq!(p.schema, plain);
        assert!(p.field_by_column.is_empty());
        let mut defs = ColumnDefinitions::new();
        defs.insert("IFSC Code".into(), Default::default());
        assert!(column_definitions(Some(&defs)).unwrap().contains_key("IFSC_Code"));
    }
}
