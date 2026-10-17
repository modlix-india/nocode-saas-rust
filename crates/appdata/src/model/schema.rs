//! The part of a KIRun `Schema` the engines read: types, properties, required, format,
//! maxLength, enums, items and ref.
//!
//! Read the way KIRun's Gson adapters read it. `type` is a name or a list of names, upper
//! cased, with JSON Schema's `number` read as DOUBLE.

use indexmap::IndexMap;

use crate::value::{Document, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SchemaType {
    Integer,
    Long,
    Float,
    Double,
    String,
    Object,
    Array,
    Boolean,
    Null,
}

impl SchemaType {
    pub fn name(&self) -> &'static str {
        match self {
            SchemaType::Integer => "INTEGER",
            SchemaType::Long => "LONG",
            SchemaType::Float => "FLOAT",
            SchemaType::Double => "DOUBLE",
            SchemaType::String => "STRING",
            SchemaType::Object => "OBJECT",
            SchemaType::Array => "ARRAY",
            SchemaType::Boolean => "BOOLEAN",
            SchemaType::Null => "NULL",
        }
    }

    fn from_json_name(s: &str) -> Option<SchemaType> {
        let upper = s.to_uppercase();
        Some(match upper.as_str() {
            "INTEGER" => SchemaType::Integer,
            "LONG" => SchemaType::Long,
            "FLOAT" => SchemaType::Float,
            "DOUBLE" | "NUMBER" => SchemaType::Double,
            "STRING" => SchemaType::String,
            "OBJECT" => SchemaType::Object,
            "ARRAY" => SchemaType::Array,
            "BOOLEAN" => SchemaType::Boolean,
            "NULL" => SchemaType::Null,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringFormat {
    DateTime,
    Time,
    Date,
    Email,
    Regex,
    Decimal,
    Id,
}

impl StringFormat {
    fn from_name(s: &str) -> Option<StringFormat> {
        Some(match s {
            "DATETIME" => StringFormat::DateTime,
            "TIME" => StringFormat::Time,
            "DATE" => StringFormat::Date,
            "EMAIL" => StringFormat::Email,
            "REGEX" => StringFormat::Regex,
            "DECIMAL" => StringFormat::Decimal,
            "ID" => StringFormat::Id,
            _ => return None,
        })
    }
}

/// `ArraySchemaType`: one schema for every item, or a tuple.
#[derive(Debug, Clone, PartialEq)]
pub enum Items {
    Single(Box<Schema>),
    Tuple(Vec<Schema>),
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Schema {
    pub namespace: Option<String>,
    pub name: Option<String>,
    /// `None` when the schema declares no type. A list in declaration order, de-duplicated.
    pub types: Option<Vec<SchemaType>>,
    pub properties: Option<IndexMap<String, Schema>>,
    pub required: Option<Vec<String>>,
    pub format: Option<StringFormat>,
    pub max_length: Option<i32>,
    pub enums: Option<Vec<Value>>,
    pub items: Option<Items>,
    pub reference: Option<String>,
    pub defs: Option<IndexMap<String, Schema>>,
}

impl Schema {
    pub fn of_string(name: &str) -> Schema {
        Schema { name: Some(name.into()), types: Some(vec![SchemaType::String]), ..Default::default() }
    }

    pub fn of_array(name: &str, items: Schema) -> Schema {
        Schema {
            name: Some(name.into()),
            types: Some(vec![SchemaType::Array]),
            items: Some(Items::Single(Box::new(items))),
            ..Default::default()
        }
    }

    pub fn with_format(mut self, f: StringFormat) -> Schema {
        self.format = Some(f);
        self
    }

    /// The allowed types, empty when none are declared.
    pub fn allowed_types(&self) -> Vec<SchemaType> {
        self.types.clone().unwrap_or_default()
    }

    pub fn has_type(&self, t: SchemaType) -> bool {
        self.types.as_ref().is_some_and(|ts| ts.contains(&t))
    }

    /// Gson's read of a schema document. Unknown keys are ignored, as Gson ignores them.
    pub fn from_value(v: &Value) -> Option<Schema> {
        let Value::Object(o) = v else { return None };
        Some(Self::from_document(o))
    }

    pub fn from_document(o: &Document) -> Schema {
        let s = |k: &str| match o.get(k) {
            Some(Value::String(s)) => Some(s.clone()),
            _ => None,
        };

        let types = match o.get("type") {
            Some(Value::String(t)) => SchemaType::from_json_name(t).map(|t| vec![t]),
            Some(Value::Array(a)) => {
                let mut out = Vec::new();
                for t in a {
                    if let Some(t) = t.as_str().and_then(SchemaType::from_json_name) {
                        if !out.contains(&t) {
                            out.push(t);
                        }
                    }
                }
                Some(out)
            }
            _ => None,
        };

        let properties = match o.get("properties") {
            Some(Value::Object(p)) => Some(
                p.iter()
                    .filter_map(|(k, v)| Schema::from_value(v).map(|s| (k.clone(), s)))
                    .collect(),
            ),
            _ => None,
        };

        let defs = match o.get("$defs") {
            Some(Value::Object(p)) => Some(
                p.iter()
                    .filter_map(|(k, v)| Schema::from_value(v).map(|s| (k.clone(), s)))
                    .collect(),
            ),
            _ => None,
        };

        let items = match o.get("items") {
            Some(Value::Object(i)) => {
                // KIRun's ArraySchemaType adapter reads either a schema or
                // {"singleSchema": ...} / {"tupleSchema": [...]}.
                if let Some(single) = i.get("singleSchema").and_then(Schema::from_value) {
                    Some(Items::Single(Box::new(single)))
                } else if let Some(Value::Array(t)) = i.get("tupleSchema") {
                    Some(Items::Tuple(t.iter().filter_map(Schema::from_value).collect()))
                } else {
                    Some(Items::Single(Box::new(Schema::from_document(i))))
                }
            }
            Some(Value::Array(t)) => Some(Items::Tuple(t.iter().filter_map(Schema::from_value).collect())),
            _ => None,
        };

        let max_length = match o.get("maxLength") {
            Some(Value::Int(i)) => Some(*i as i32),
            Some(Value::Double(d)) => Some(*d as i32),
            _ => None,
        };

        Schema {
            namespace: s("namespace"),
            name: s("name"),
            types,
            properties,
            required: match o.get("required") {
                Some(Value::Array(a)) => Some(a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()),
                _ => None,
            },
            format: s("format").and_then(|f| StringFormat::from_name(&f)),
            max_length,
            enums: match o.get("enums") {
                Some(Value::Array(a)) => Some(a.clone()),
                _ => None,
            },
            items,
            reference: s("ref"),
            defs,
        }
    }
}
