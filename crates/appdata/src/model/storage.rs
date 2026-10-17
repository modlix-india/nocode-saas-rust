//! `com.fincity.saas.commons.core.document.Storage` and what hangs off it: relations,
//! indexes and per-backend column definitions.
//!
//! The engines receive the storage already resolved (the override chain merged) by the
//! caller; nothing here merges.

use indexmap::IndexMap;

use super::query::Direction;
use crate::value::{Document, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelationType {
    ToOne,
    ToMany,
}

impl RelationType {
    pub fn name(&self) -> &'static str {
        match self {
            RelationType::ToOne => "TO_ONE",
            RelationType::ToMany => "TO_MANY",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelationConstraint {
    Cascade,
    Restrict,
    Nothing,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StorageRelation {
    pub unique_relation_id: Option<String>,
    pub storage_name: Option<String>,
    pub relation_type: Option<RelationType>,
    pub field_name: Option<String>,
    pub delete_constraint: Option<RelationConstraint>,
    pub update_constraint: Option<RelationConstraint>,
}

impl Default for StorageRelation {
    fn default() -> Self {
        StorageRelation {
            unique_relation_id: None,
            storage_name: None,
            relation_type: None,
            field_name: None,
            delete_constraint: Some(RelationConstraint::Nothing),
            update_constraint: Some(RelationConstraint::Nothing),
        }
    }
}

impl StorageRelation {
    pub fn to_one(storage: &str) -> StorageRelation {
        StorageRelation {
            storage_name: Some(storage.into()),
            relation_type: Some(RelationType::ToOne),
            ..Default::default()
        }
    }

    pub fn to_many(storage: &str) -> StorageRelation {
        StorageRelation {
            storage_name: Some(storage.into()),
            relation_type: Some(RelationType::ToMany),
            ..Default::default()
        }
    }

    pub fn with_delete(mut self, c: RelationConstraint) -> StorageRelation {
        self.delete_constraint = Some(c);
        self
    }

    pub fn with_field_name(mut self, f: &str) -> StorageRelation {
        self.field_name = Some(f.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct StorageIndexField {
    pub field_name: Option<String>,
    pub direction: Option<Direction>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct StorageIndex {
    pub fields: Vec<StorageIndexField>,
    pub unique: bool,
}

impl StorageIndex {
    pub fn of(fields: &[(&str, Direction)], unique: bool) -> StorageIndex {
        StorageIndex {
            fields: fields
                .iter()
                .map(|(f, d)| StorageIndexField { field_name: Some(f.to_string()), direction: Some(*d) })
                .collect(),
            unique,
        }
    }
}

/// `MongoBsonType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MongoBsonType {
    Decimal128,
    Long,
    Int,
    Double,
    Date,
    Boolean,
    String,
}

impl MongoBsonType {
    fn from_name(s: &str) -> Option<MongoBsonType> {
        Some(match s {
            "DECIMAL128" => MongoBsonType::Decimal128,
            "LONG" => MongoBsonType::Long,
            "INT" => MongoBsonType::Int,
            "DOUBLE" => MongoBsonType::Double,
            "DATE" => MongoBsonType::Date,
            "BOOLEAN" => MongoBsonType::Boolean,
            "STRING" => MongoBsonType::String,
            _ => return None,
        })
    }
}

/// `MySQLColumnType` and the shape of its arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MySqlColumnType {
    Tinyint,
    Smallint,
    Mediumint,
    Int,
    Bigint,
    Decimal,
    Float,
    Double,
    Char,
    Varchar,
    Tinytext,
    Text,
    Mediumtext,
    Longtext,
    Binary,
    Varbinary,
    Tinyblob,
    Blob,
    Mediumblob,
    Longblob,
    Date,
    Datetime,
    Time,
    Timestamp,
    Year,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arity {
    None,
    Length,
    PrecisionScale,
    FractionalSeconds,
}

impl MySqlColumnType {
    pub const MAX_VARCHAR: i32 = 16000;
    pub const MAX_PRECISION: i32 = 65;
    pub const MAX_FRACTIONAL_SECONDS: i32 = 6;

    const ALL: [MySqlColumnType; 26] = [
        MySqlColumnType::Tinyint,
        MySqlColumnType::Smallint,
        MySqlColumnType::Mediumint,
        MySqlColumnType::Int,
        MySqlColumnType::Bigint,
        MySqlColumnType::Decimal,
        MySqlColumnType::Float,
        MySqlColumnType::Double,
        MySqlColumnType::Char,
        MySqlColumnType::Varchar,
        MySqlColumnType::Tinytext,
        MySqlColumnType::Text,
        MySqlColumnType::Mediumtext,
        MySqlColumnType::Longtext,
        MySqlColumnType::Binary,
        MySqlColumnType::Varbinary,
        MySqlColumnType::Tinyblob,
        MySqlColumnType::Blob,
        MySqlColumnType::Mediumblob,
        MySqlColumnType::Longblob,
        MySqlColumnType::Date,
        MySqlColumnType::Datetime,
        MySqlColumnType::Time,
        MySqlColumnType::Timestamp,
        MySqlColumnType::Year,
        MySqlColumnType::Json,
    ];

    pub fn name(&self) -> &'static str {
        match self {
            MySqlColumnType::Tinyint => "TINYINT",
            MySqlColumnType::Smallint => "SMALLINT",
            MySqlColumnType::Mediumint => "MEDIUMINT",
            MySqlColumnType::Int => "INT",
            MySqlColumnType::Bigint => "BIGINT",
            MySqlColumnType::Decimal => "DECIMAL",
            MySqlColumnType::Float => "FLOAT",
            MySqlColumnType::Double => "DOUBLE",
            MySqlColumnType::Char => "CHAR",
            MySqlColumnType::Varchar => "VARCHAR",
            MySqlColumnType::Tinytext => "TINYTEXT",
            MySqlColumnType::Text => "TEXT",
            MySqlColumnType::Mediumtext => "MEDIUMTEXT",
            MySqlColumnType::Longtext => "LONGTEXT",
            MySqlColumnType::Binary => "BINARY",
            MySqlColumnType::Varbinary => "VARBINARY",
            MySqlColumnType::Tinyblob => "TINYBLOB",
            MySqlColumnType::Blob => "BLOB",
            MySqlColumnType::Mediumblob => "MEDIUMBLOB",
            MySqlColumnType::Longblob => "LONGBLOB",
            MySqlColumnType::Date => "DATE",
            MySqlColumnType::Datetime => "DATETIME",
            MySqlColumnType::Time => "TIME",
            MySqlColumnType::Timestamp => "TIMESTAMP",
            MySqlColumnType::Year => "YEAR",
            MySqlColumnType::Json => "JSON",
        }
    }

    pub fn from_name(s: &str) -> Option<MySqlColumnType> {
        Self::ALL.into_iter().find(|t| t.name() == s)
    }

    pub fn arity(&self) -> Arity {
        match self {
            MySqlColumnType::Decimal => Arity::PrecisionScale,
            MySqlColumnType::Char
            | MySqlColumnType::Varchar
            | MySqlColumnType::Binary
            | MySqlColumnType::Varbinary => Arity::Length,
            MySqlColumnType::Datetime | MySqlColumnType::Time | MySqlColumnType::Timestamp => {
                Arity::FractionalSeconds
            }
            _ => Arity::None,
        }
    }

    pub fn numeric(&self) -> bool {
        matches!(
            self,
            MySqlColumnType::Tinyint
                | MySqlColumnType::Smallint
                | MySqlColumnType::Mediumint
                | MySqlColumnType::Int
                | MySqlColumnType::Bigint
                | MySqlColumnType::Decimal
                | MySqlColumnType::Float
                | MySqlColumnType::Double
        )
    }

    pub fn textual(&self) -> bool {
        matches!(
            self,
            MySqlColumnType::Char
                | MySqlColumnType::Varchar
                | MySqlColumnType::Tinytext
                | MySqlColumnType::Text
                | MySqlColumnType::Mediumtext
                | MySqlColumnType::Longtext
        )
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct MySqlColumnDefinition {
    pub column_type: Option<MySqlColumnType>,
    pub length: Option<i32>,
    pub precision: Option<i32>,
    pub scale: Option<i32>,
    pub unsigned: Option<bool>,
    pub collation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct MongoColumnDefinition {
    pub bson_type: Option<MongoBsonType>,
}

/// `StorageColumnDefinition`: how one field is physically stored, per backend.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct StorageColumnDefinition {
    pub mysql: Option<MySqlColumnDefinition>,
    pub mongo: Option<MongoColumnDefinition>,
}

impl StorageColumnDefinition {
    pub fn mysql(def: MySqlColumnDefinition) -> StorageColumnDefinition {
        StorageColumnDefinition { mysql: Some(def), mongo: None }
    }

    pub fn mongo(t: MongoBsonType) -> StorageColumnDefinition {
        StorageColumnDefinition { mysql: None, mongo: Some(MongoColumnDefinition { bson_type: Some(t) }) }
    }
}

pub type ColumnDefinitions = IndexMap<String, StorageColumnDefinition>;

/// The storage definition, as the engines read it.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Storage {
    pub id: Option<String>,
    pub name: String,
    pub app_code: String,
    pub client_code: String,
    pub base_client_code: Option<String>,
    pub version: i32,
    /// The storage's KIRun schema, as stored.
    pub schema: Option<Value>,
    pub unique_name: String,
    pub is_audited: Option<bool>,
    pub is_versioned: Option<bool>,
    pub is_app_level: Option<bool>,
    pub only_thru_kirun: Option<bool>,
    pub create_auth: Option<String>,
    pub read_auth: Option<String>,
    pub update_auth: Option<String>,
    pub delete_auth: Option<String>,
    pub relations: Option<IndexMap<String, StorageRelation>>,
    pub generate_events: Option<bool>,
    pub triggers: Option<IndexMap<String, Vec<String>>>,
    pub version_retention_days: Option<i32>,
    pub version_retention_count: Option<i32>,
    pub column_definitions: Option<ColumnDefinitions>,
    pub indexes: Option<IndexMap<String, StorageIndex>>,
    pub text_index_fields: Option<Vec<String>>,
}

impl Storage {
    pub fn audited(&self) -> bool {
        self.is_audited == Some(true)
    }

    pub fn versioned(&self) -> bool {
        self.is_versioned == Some(true)
    }

    pub fn app_level(&self) -> bool {
        self.is_app_level == Some(true)
    }

    /// A storage writes version rows when it asked for auditing, versioning, or both.
    pub fn keeps_history(&self) -> bool {
        self.audited() || self.versioned()
    }

    pub fn relation(&self, field: &str) -> Option<&StorageRelation> {
        self.relations.as_ref().and_then(|r| r.get(field))
    }

    pub fn has_relations(&self) -> bool {
        self.relations.as_ref().is_some_and(|r| !r.is_empty())
    }

    pub fn relation_keys(&self) -> Vec<String> {
        self.relations.as_ref().map(|r| r.keys().cloned().collect()).unwrap_or_default()
    }

    /// From the stored document (or its JSON), as Spring Data / Jackson reads it.
    pub fn from_value(v: &Value) -> Result<Storage, String> {
        let Value::Object(o) = v else { return Err("a storage must be an object".into()) };
        let s = |k: &str| match o.get(k) {
            Some(Value::String(s)) => Some(s.clone()),
            _ => None,
        };
        let b = |k: &str| match o.get(k) {
            Some(Value::Bool(b)) => Some(*b),
            _ => None,
        };
        let i = |k: &str| match o.get(k) {
            Some(Value::Int(i)) => Some(*i as i32),
            Some(Value::Double(d)) => Some(*d as i32),
            _ => None,
        };

        let relations = match o.get("relations") {
            Some(Value::Object(r)) => {
                let mut out = IndexMap::new();
                for (k, v) in r {
                    if let Value::Object(rel) = v {
                        out.insert(k.clone(), relation_from(rel));
                    }
                }
                Some(out)
            }
            _ => None,
        };

        let triggers = match o.get("triggers") {
            Some(Value::Object(t)) => Some(
                t.iter()
                    .map(|(k, v)| {
                        let list = match v {
                            Value::Array(a) => a.iter().map(Value::java_string).collect(),
                            _ => Vec::new(),
                        };
                        (k.clone(), list)
                    })
                    .collect(),
            ),
            _ => None,
        };

        let indexes = match o.get("indexes") {
            Some(Value::Object(ix)) => {
                let mut out = IndexMap::new();
                for (k, v) in ix {
                    if let Value::Object(index) = v {
                        out.insert(k.clone(), index_from(index));
                    }
                }
                Some(out)
            }
            _ => None,
        };

        let column_definitions = match o.get("columnDefinitions") {
            Some(Value::Object(defs)) => {
                let mut out = IndexMap::new();
                for (k, v) in defs {
                    if let Value::Object(def) = v {
                        out.insert(k.clone(), column_definition_from(def));
                    }
                }
                Some(out)
            }
            _ => None,
        };

        let text_index_fields = match o.get("textIndexFields") {
            Some(Value::Array(a)) => Some(a.iter().map(Value::java_string).collect()),
            _ => None,
        };

        let id = match o.get("_id").or(o.get("id")) {
            Some(Value::String(s)) => Some(s.clone()),
            _ => None,
        };

        Ok(Storage {
            id,
            name: s("name").unwrap_or_default(),
            app_code: s("appCode").unwrap_or_default(),
            client_code: s("clientCode").unwrap_or_default(),
            base_client_code: s("baseClientCode"),
            version: i("version").unwrap_or(1),
            schema: o.get("schema").cloned().filter(|v| !v.is_null()),
            unique_name: s("uniqueName").unwrap_or_default(),
            is_audited: b("isAudited"),
            is_versioned: b("isVersioned"),
            is_app_level: b("isAppLevel"),
            only_thru_kirun: b("onlyThruKIRun"),
            create_auth: s("createAuth"),
            read_auth: s("readAuth"),
            update_auth: s("updateAuth"),
            delete_auth: s("deleteAuth"),
            relations,
            generate_events: b("generateEvents"),
            triggers,
            version_retention_days: i("versionRetentionDays"),
            version_retention_count: i("versionRetentionCount"),
            column_definitions,
            indexes,
            text_index_fields,
        })
    }
}

fn relation_from(o: &Document) -> StorageRelation {
    let s = |k: &str| match o.get(k) {
        Some(Value::String(s)) => Some(s.clone()),
        _ => None,
    };
    let constraint = |k: &str| match o.get(k) {
        None => Some(RelationConstraint::Nothing),
        Some(Value::String(s)) => match s.as_str() {
            "CASCADE" => Some(RelationConstraint::Cascade),
            "RESTRICT" => Some(RelationConstraint::Restrict),
            "NOTHING" => Some(RelationConstraint::Nothing),
            _ => None,
        },
        _ => None,
    };
    StorageRelation {
        unique_relation_id: s("uniqueRelationId"),
        storage_name: s("storageName"),
        relation_type: match s("relationType").as_deref() {
            Some("TO_ONE") => Some(RelationType::ToOne),
            Some("TO_MANY") => Some(RelationType::ToMany),
            _ => None,
        },
        field_name: s("fieldName"),
        delete_constraint: constraint("deleteConstraint"),
        update_constraint: constraint("updateConstraint"),
    }
}

fn index_from(o: &Document) -> StorageIndex {
    let fields = match o.get("fields") {
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|f| f.as_object())
            .map(|f| StorageIndexField {
                field_name: f.get("fieldName").and_then(Value::as_str).map(str::to_string),
                direction: match f.get("direction").and_then(Value::as_str) {
                    Some("DESC") => Some(Direction::Desc),
                    Some("ASC") | None => Some(Direction::Asc),
                    _ => Some(Direction::Asc),
                },
            })
            .collect(),
        _ => Vec::new(),
    };
    StorageIndex { fields, unique: matches!(o.get("unique"), Some(Value::Bool(true))) }
}

fn column_definition_from(o: &Document) -> StorageColumnDefinition {
    let mysql = o.get("mysql").and_then(Value::as_object).map(|m| {
        let int = |k: &str| match m.get(k) {
            Some(Value::Int(i)) => Some(*i as i32),
            Some(Value::Double(d)) => Some(*d as i32),
            _ => None,
        };
        MySqlColumnDefinition {
            column_type: m.get("type").and_then(Value::as_str).and_then(MySqlColumnType::from_name),
            length: int("length"),
            precision: int("precision"),
            scale: int("scale"),
            unsigned: match m.get("unsigned") {
                Some(Value::Bool(b)) => Some(*b),
                _ => None,
            },
            collation: m.get("collation").and_then(Value::as_str).map(str::to_string),
        }
    });
    let mongo = o.get("mongo").and_then(Value::as_object).map(|m| MongoColumnDefinition {
        bson_type: m.get("bsonType").and_then(Value::as_str).and_then(MongoBsonType::from_name),
    });
    StorageColumnDefinition { mysql, mongo }
}

/// `DataObject`: what a create or an update hands the engine.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DataObject {
    pub message: Option<String>,
    pub data: Option<Document>,
}

impl DataObject {
    pub fn of(data: Document) -> DataObject {
        DataObject { message: None, data: Some(data) }
    }

    pub fn with_message(mut self, m: &str) -> DataObject {
        self.message = Some(m.into());
        self
    }
}

/// `DraftCopyFilter.Follow`.
#[derive(Debug, Clone, PartialEq)]
pub struct Follow {
    pub field: String,
    pub storage: String,
    pub ref_field: Option<String>,
}

impl Follow {
    pub fn ref_field_or_default(&self) -> String {
        match &self.ref_field {
            Some(f) if !f.trim().is_empty() => f.clone(),
            _ => "_id".into(),
        }
    }
}

/// `DraftCopyFilter`: which live rows a filtered draft copy takes.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DraftCopyFilter {
    pub condition: Option<super::condition::Condition>,
    pub follow: Option<Vec<Follow>>,
}

impl DraftCopyFilter {
    pub fn has_follow(&self) -> bool {
        self.follow.as_ref().is_some_and(|f| !f.is_empty())
    }
}
