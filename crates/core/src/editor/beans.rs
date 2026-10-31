//! The classes nested in core's documents (`StorageRelation`, `StorageIndex`, the column
//! definitions, `EventActionTask`, `EventSchedule`, `NotificationTemplate`), read the way
//! Jackson reads a request body into them and kept the way Spring Data stores them.
//!
//! The read path keeps these as plain maps, which is enough to read what is stored. A write
//! has to do what the Java classes do on the way in: drop the keys the class does not have,
//! fill the field defaults (`deleteConstraint: NOTHING`, `unique: false`, `direction: ASC`),
//! refuse a value Jackson cannot convert (an unknown enum constant, an object where a string
//! goes), and store only the fields that are not null.

use overridable::{JMap, JValue};

/// A field's Java type.
#[derive(Debug, Clone, Copy)]
pub enum T {
    /// `String`: a scalar is converted to its text.
    Str,
    /// `Integer`.
    Int,
    /// `Boolean`.
    Bool,
    /// An enum: one of the constants.
    Enum(&'static [&'static str]),
    /// `Map<String, Object>` (or `Object`): taken as it is.
    Any,
    /// `Map<String, X>`.
    MapOf(&'static T),
    /// `Map<SomeEnum, X>`: the keys must be constants.
    EnumMapOf(&'static [&'static str], &'static T),
    /// `List<X>`.
    ListOf(&'static T),
    /// A nested class.
    Bean(&'static Bean),
}

/// One field: its name, type and initial value (`= NOTHING`, a primitive's zero).
#[derive(Debug)]
pub struct F {
    pub name: &'static str,
    pub t: T,
    pub default: Option<Default>,
}

#[derive(Debug, Clone, Copy)]
pub enum Default {
    Str(&'static str),
    Bool(bool),
}

impl Default {
    fn value(self) -> JValue {
        match self {
            Default::Str(s) => JValue::Str(s.into()),
            Default::Bool(b) => JValue::Bool(b),
        }
    }
}

/// A class, its fields in declaration order (the order Spring Data writes them in).
#[derive(Debug)]
pub struct Bean {
    pub name: &'static str,
    pub fields: &'static [F],
}

const fn f(name: &'static str, t: T) -> F {
    F { name, t, default: None }
}

const fn fd(name: &'static str, t: T, default: Default) -> F {
    F { name, t, default: Some(default) }
}

pub const RELATION_TYPES: &[&str] = &["TO_ONE", "TO_MANY"];
pub const RELATION_CONSTRAINTS: &[&str] = &["CASCADE", "RESTRICT", "NOTHING"];
pub const TRIGGER_TYPES: &[&str] = &[
    "BEFORE_CREATE",
    "AFTER_CREATE",
    "BEFORE_UPDATE",
    "AFTER_UPDATE",
    "BEFORE_DELETE",
    "AFTER_DELETE",
    "BEFORE_UPDATE_STORAGE",
    "AFTER_UPDATE_STORAGE",
    "BEFORE_DELETE_STORAGE",
    "AFTER_DELETE_STORAGE",
];
pub const DIRECTIONS: &[&str] = &["ASC", "DESC"];
pub const MYSQL_TYPES: &[&str] = &[
    "TINYINT", "SMALLINT", "MEDIUMINT", "INT", "BIGINT", "DECIMAL", "FLOAT", "DOUBLE", "CHAR", "VARCHAR", "TINYTEXT", "TEXT",
    "MEDIUMTEXT", "LONGTEXT", "BINARY", "VARBINARY", "TINYBLOB", "BLOB", "MEDIUMBLOB", "LONGBLOB", "DATE", "DATETIME", "TIME",
    "TIMESTAMP", "YEAR", "JSON",
];
pub const BSON_TYPES: &[&str] = &["DECIMAL128", "LONG", "INT", "DOUBLE", "DATE", "BOOLEAN", "STRING"];
pub const TASK_TYPES: &[&str] = &["SEND_EMAIL", "CALL_CORE_FUNCTION"];
pub const NOTIFICATION_TYPES: &[&str] =
    &["ALERT", "INFO", "WARNING", "ERROR", "SUCCESS", "REMINDER", "SYSTEM", "PROMOTIONAL", "UPDATE", "SECURITY"];
pub const CONNECTION_TYPES: &[&str] = &["APP_DATA", "MAIL", "REST_API", "NOTIFICATION", "TEXT", "CALL", "AI", "PUSH"];
pub const CONNECTION_SUB_TYPES: &[&str] = &[
    "MONGO", "MYSQL", "OFFICE365", "SENDGRID", "WHATSAPP", "REST_API_OAUTH2", "REST_API_BASIC", "REST_API_AUTH", "SMTP", "EXOTEL",
    "OPENAI", "GEMINI", "CLAUDE", "GROK", "DEEP_SEEK",
];

/// `StorageRelation`.
pub const STORAGE_RELATION: Bean = Bean {
    name: "StorageRelation",
    fields: &[
        f("uniqueRelationId", T::Str),
        f("storageName", T::Str),
        f("relationType", T::Enum(RELATION_TYPES)),
        f("fieldName", T::Str),
        fd("deleteConstraint", T::Enum(RELATION_CONSTRAINTS), Default::Str("NOTHING")),
        fd("updateConstraint", T::Enum(RELATION_CONSTRAINTS), Default::Str("NOTHING")),
    ],
};

/// `Storage.StorageIndexField`.
pub const STORAGE_INDEX_FIELD: Bean = Bean {
    name: "StorageIndexField",
    fields: &[f("fieldName", T::Str), fd("direction", T::Enum(DIRECTIONS), Default::Str("ASC"))],
};

/// `Storage.StorageIndex`.
pub const STORAGE_INDEX: Bean = Bean {
    name: "StorageIndex",
    fields: &[f("fields", T::ListOf(&T::Bean(&STORAGE_INDEX_FIELD))), fd("unique", T::Bool, Default::Bool(false))],
};

/// `StorageColumnDefinition.MySQL`.
pub const MYSQL_COLUMN: Bean = Bean {
    name: "MySQL",
    fields: &[
        f("type", T::Enum(MYSQL_TYPES)),
        f("length", T::Int),
        f("precision", T::Int),
        f("scale", T::Int),
        f("unsigned", T::Bool),
        f("collation", T::Str),
    ],
};

/// `StorageColumnDefinition.Mongo`.
pub const MONGO_COLUMN: Bean = Bean { name: "Mongo", fields: &[f("bsonType", T::Enum(BSON_TYPES))] };

/// `StorageColumnDefinition`.
pub const COLUMN_DEFINITION: Bean =
    Bean { name: "StorageColumnDefinition", fields: &[f("mysql", T::Bean(&MYSQL_COLUMN)), f("mongo", T::Bean(&MONGO_COLUMN))] };

/// `EventActionTask`.
pub const EVENT_ACTION_TASK: Bean = Bean {
    name: "EventActionTask",
    fields: &[f("key", T::Str), f("order", T::Int), f("type", T::Enum(TASK_TYPES)), f("parameters", T::Any)],
};

/// `EventSchedule`.
pub const EVENT_SCHEDULE: Bean = Bean {
    name: "EventSchedule",
    fields: &[f("cron", T::Str), f("timezone", T::Str), f("perClient", T::Bool), f("enabled", T::Bool), f("spread", T::Bool)],
};

/// `Notification.NotificationTemplate`.
pub const NOTIFICATION_TEMPLATE: Bean = Bean {
    name: "NotificationTemplate",
    fields: &[f("templateParts", T::MapOf(&T::MapOf(&T::Str))), f("resources", T::MapOf(&T::Str))],
};

pub const WORKFLOW_TRIGGER_TYPES: &[&str] = &["MANUAL", "EVENT", "ON_SCHEDULE"];

/// `TriggerWorkflowStep` (its own fields, then `WorkflowStep`'s).
pub const TRIGGER_STEP: Bean = Bean {
    name: "TriggerWorkflowStep",
    fields: &[
        f("triggerType", T::Enum(WORKFLOW_TRIGGER_TYPES)),
        f("eventName", T::Str),
        f("cronString", T::Str),
        f("children", T::MapOf(&T::Bool)),
        f("comment", T::Str),
        f("description", T::Str),
        f("position", T::Any),
        f("stepName", T::Str),
    ],
};

/// Why Jackson refused a value (Spring answers it as an unreadable body).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unreadable(pub String);

type R = Result<JValue, Unreadable>;

fn refuse(what: &str, v: &JValue) -> Unreadable {
    Unreadable(format!("Cannot deserialize value of type `{what}` from {}", kind_name(v)))
}

fn kind_name(v: &JValue) -> &'static str {
    match v {
        JValue::Object(_) => "Object value",
        JValue::Array(_) => "Array value",
        JValue::Str(_) => "String value",
        JValue::Bool(_) => "Boolean value",
        JValue::Null => "null",
        _ => "Number value",
    }
}

/// Jackson reading `v` as `t`. Absent and null are null.
pub fn read(t: T, v: &JValue) -> R {
    if v.is_null() {
        return Ok(JValue::Null);
    }
    match t {
        T::Any => Ok(v.clone()),
        T::Str => match v {
            JValue::Object(_) | JValue::Array(_) => Err(refuse("java.lang.String", v)),
            JValue::Str(_) => Ok(v.clone()),
            other => Ok(JValue::Str(other.java_to_string())),
        },
        T::Int => match v {
            JValue::Int(i) => Ok(JValue::Int(*i as i32 as i64)),
            JValue::Float(x) => Ok(JValue::Int(*x as i32 as i64)),
            JValue::Str(s) if s.trim().is_empty() => Ok(JValue::Null),
            JValue::Str(s) => s.trim().parse::<i32>().map(|i| JValue::Int(i as i64)).map_err(|_| refuse("java.lang.Integer", v)),
            _ => Err(refuse("java.lang.Integer", v)),
        },
        T::Bool => match v {
            JValue::Bool(_) => Ok(v.clone()),
            JValue::Str(s) if s == "true" => Ok(JValue::Bool(true)),
            JValue::Str(s) if s == "false" => Ok(JValue::Bool(false)),
            JValue::Str(s) if s.trim().is_empty() => Ok(JValue::Null),
            JValue::Int(i) => Ok(JValue::Bool(*i != 0)),
            _ => Err(refuse("java.lang.Boolean", v)),
        },
        T::Enum(constants) => match v {
            JValue::Str(s) if s.is_empty() => Ok(JValue::Null),
            JValue::Str(s) if constants.contains(&s.as_str()) => Ok(v.clone()),
            JValue::Int(i) if *i >= 0 && (*i as usize) < constants.len() => Ok(JValue::Str(constants[*i as usize].into())),
            _ => Err(Unreadable(format!("Cannot deserialize value of type enum from {}: not one of the values accepted", kind_name(v)))),
        },
        T::MapOf(inner) => match v {
            JValue::Object(m) => {
                let mut out = JMap::new();
                for (k, x) in m {
                    out.insert(k.clone(), read(*inner, x)?);
                }
                Ok(JValue::Object(out))
            }
            _ => Err(refuse("java.util.Map", v)),
        },
        T::EnumMapOf(keys, inner) => match v {
            JValue::Object(m) => {
                let mut out = JMap::new();
                for (k, x) in m {
                    if !keys.contains(&k.as_str()) {
                        return Err(Unreadable(format!("Cannot deserialize Map key of type enum from String \"{k}\"")));
                    }
                    out.insert(k.clone(), read(*inner, x)?);
                }
                Ok(JValue::Object(out))
            }
            _ => Err(refuse("java.util.Map", v)),
        },
        T::ListOf(inner) => match v {
            JValue::Array(a) => Ok(JValue::Array(a.iter().map(|x| read(*inner, x)).collect::<Result<_, _>>()?)),
            _ => Err(refuse("java.util.ArrayList", v)),
        },
        T::Bean(bean) => match v {
            JValue::Object(m) => {
                let mut out = JMap::new();
                for fld in bean.fields {
                    let x = match m.get(fld.name) {
                        Some(x) => read(fld.t, x)?,
                        None => fld.default.map(Default::value).unwrap_or_default(),
                    };
                    out.insert(fld.name.to_string(), x);
                }
                Ok(JValue::Object(out))
            }
            _ => Err(refuse(bean.name, v)),
        },
    }
}

/// What Spring Data writes for a value of `t`: a class's null fields are left out (a map or a
/// list keeps its null entries, as the converter writes them).
pub fn stored(t: T, v: &JValue) -> JValue {
    match (t, v) {
        (T::Bean(bean), JValue::Object(m)) => {
            let mut out = JMap::new();
            for fld in bean.fields {
                if let Some(x) = m.get(fld.name).filter(|x| !x.is_null()) {
                    out.insert(fld.name.to_string(), stored(fld.t, x));
                }
            }
            JValue::Object(out)
        }
        (T::MapOf(inner) | T::EnumMapOf(_, inner), JValue::Object(m)) => {
            JValue::Object(m.iter().map(|(k, x)| (k.clone(), if x.is_null() { JValue::Null } else { stored(*inner, x) })).collect())
        }
        (T::ListOf(inner), JValue::Array(a)) => JValue::Array(a.iter().map(|x| if x.is_null() { JValue::Null } else { stored(*inner, x) }).collect()),
        _ => v.clone(),
    }
}

/// [`read`] then [`stored`] on one field of `entity`.
pub fn normalize(entity: &mut JMap, field: &str, t: T) -> Result<(), Unreadable> {
    let Some(v) = entity.get(field) else { return Ok(()) };
    let r = read(t, v)?;
    let s = if r.is_null() { JValue::Null } else { stored(t, &r) };
    entity.insert(field.to_string(), s);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use overridable::json::parse;

    fn j(s: &str) -> JValue {
        parse(s.as_bytes()).unwrap()
    }

    #[test]
    fn a_relation_gets_its_defaults_and_loses_unknown_keys() {
        let t = T::MapOf(&T::Bean(&STORAGE_RELATION));
        let r = read(t, &j(r#"{"owner":{"storageName":"users","relationType":"TO_ONE","junk":1}}"#)).unwrap();
        let s = stored(t, &r);
        assert_eq!(
            s,
            j(r#"{"owner":{"storageName":"users","relationType":"TO_ONE","deleteConstraint":"NOTHING","updateConstraint":"NOTHING"}}"#)
        );
        assert!(read(t, &j(r#"{"owner":{"relationType":"MANY"}}"#)).is_err());
        assert!(read(t, &j(r#"{"owner":3}"#)).is_err());
        assert!(read(t, &j(r#"[]"#)).is_err());
        assert_eq!(read(t, &JValue::Null).unwrap(), JValue::Null);
    }

    #[test]
    fn indexes_columns_triggers_and_scalars() {
        let idx = T::MapOf(&T::Bean(&STORAGE_INDEX));
        let s = stored(idx, &read(idx, &j(r#"{"i":{"fields":[{"fieldName":"a"},{"fieldName":"b","direction":"DESC"}]}}"#)).unwrap());
        assert_eq!(s, j(r#"{"i":{"fields":[{"fieldName":"a","direction":"ASC"},{"fieldName":"b","direction":"DESC"}],"unique":false}}"#));
        assert!(read(idx, &j(r#"{"i":{"fields":{}}}"#)).is_err());
        let cd = T::MapOf(&T::Bean(&COLUMN_DEFINITION));
        let s = stored(cd, &read(cd, &j(r#"{"p":{"mysql":{"type":"DECIMAL","precision":"19","scale":4.0}}}"#)).unwrap());
        assert_eq!(s, j(r#"{"p":{"mysql":{"type":"DECIMAL","precision":19,"scale":4}}}"#));
        let tr = T::EnumMapOf(TRIGGER_TYPES, &T::ListOf(&T::Str));
        assert_eq!(read(tr, &j(r#"{"AFTER_CREATE":["A.b",3]}"#)).unwrap(), j(r#"{"AFTER_CREATE":["A.b","3"]}"#));
        assert!(read(tr, &j(r#"{"WHENEVER":[]}"#)).is_err());
        assert_eq!(read(T::Str, &j("12")).unwrap(), JValue::Str("12".into()));
        assert!(read(T::Str, &j("{}")).is_err());
        assert!(read(T::Int, &j(r#""x""#)).is_err());
        assert_eq!(read(T::Int, &j(r#""""#)).unwrap(), JValue::Null);
        assert_eq!(read(T::Bool, &j(r#""true""#)).unwrap(), JValue::Bool(true));
        assert_eq!(read(T::Bool, &j("0")).unwrap(), JValue::Bool(false));
        assert_eq!(read(T::Bool, &j(r#""""#)).unwrap(), JValue::Null);
        assert!(read(T::Bool, &j("[]")).is_err());
        assert_eq!(read(T::Enum(TASK_TYPES), &j("1")).unwrap(), JValue::Str("CALL_CORE_FUNCTION".into()));
        assert_eq!(read(T::Enum(TASK_TYPES), &j(r#""""#)).unwrap(), JValue::Null);
        assert!(read(T::ListOf(&T::Str), &j(r#""a""#)).is_err());
        assert!(read(T::EnumMapOf(TRIGGER_TYPES, &T::Any), &j("1")).is_err());
        assert!(read(T::Bean(&EVENT_SCHEDULE), &j("true")).is_err());
        let mut e = JMap::new();
        e.insert("schedule".into(), j(r#"{"cron":"0 * * * *","enabled":null,"x":1}"#));
        normalize(&mut e, "schedule", T::Bean(&EVENT_SCHEDULE)).unwrap();
        assert_eq!(e["schedule"], j(r#"{"cron":"0 * * * *"}"#));
        normalize(&mut e, "absent", T::Any).unwrap();
        assert!(!e.contains_key("absent"));
        assert_eq!(stored(T::ListOf(&T::Str), &j(r#"["a",null]"#)), j(r#"["a",null]"#));
        assert_eq!(stored(T::MapOf(&T::Str), &j(r#"{"a":null}"#)), j(r#"{"a":null}"#));
    }
}
