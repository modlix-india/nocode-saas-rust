//! `com.fincity.saas.commons.core.document.Connection`, as far as app data reads it.

use crate::value::{Document, Value};

/// `ConnectionSubType`. Only MONGO and MYSQL are app-data backends; the rest belong to
/// other connection types and select no engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionSubType {
    Mongo,
    MySql,
    Other(String),
}

impl ConnectionSubType {
    pub fn from_name(s: &str) -> ConnectionSubType {
        match s {
            "MONGO" => ConnectionSubType::Mongo,
            "MYSQL" => ConnectionSubType::MySql,
            other => ConnectionSubType::Other(other.to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Connection {
    pub id: String,
    pub name: Option<String>,
    pub app_code: Option<String>,
    pub client_code: Option<String>,
    pub connection_type: Option<String>,
    pub connection_sub_type: Option<ConnectionSubType>,
    pub connection_details: Option<Document>,
}

impl Connection {
    pub fn detail(&self, key: &str) -> Option<&Value> {
        self.connection_details.as_ref().and_then(|d| d.get(key))
    }

    /// From the stored document (or its JSON).
    pub fn from_value(v: &Value) -> Result<Connection, String> {
        let Value::Object(o) = v else { return Err("a connection must be an object".into()) };
        let s = |k: &str| match o.get(k) {
            Some(Value::String(s)) => Some(s.clone()),
            _ => None,
        };
        Ok(Connection {
            id: s("_id").or_else(|| s("id")).unwrap_or_default(),
            name: s("name"),
            app_code: s("appCode"),
            client_code: s("clientCode"),
            connection_type: s("connectionType"),
            connection_sub_type: s("connectionSubType").map(|t| ConnectionSubType::from_name(&t)),
            connection_details: o.get("connectionDetails").and_then(Value::as_object).cloned(),
        })
    }
}
