//! `CoreSchemaRepository`: the two schemas of `Security.Context` that
//! `GetAuthentication` / `GetUser` refer to.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use kirun::json::schema::r#type::{SchemaType, TypeUtil};
use kirun::json::schema::string::StringFormat;
use kirun::json::schema::Schema;
use kirun::Map;
use serde_json::Value;

use super::{filter_names, FoundSchema, SchemaSource};
use crate::error::CoreError;
use crate::java_model::gson_schema;

pub const SECURITY_CONTEXT: &str = "Security.Context";
pub const CONTEXT_USER: &str = "ContextUser";
pub const CONTEXT_AUTHENTICATION: &str = "ContextAuthentication";

fn props(entries: Vec<(&str, Schema)>) -> Map<Schema> {
    entries.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
}

fn context_user() -> Schema {
    Schema::new()
        .set_namespace(SECURITY_CONTEXT)
        .set_name(CONTEXT_USER)
        .set_type(TypeUtil::of(&[SchemaType::Object]))
        .set_properties(props(vec![
            ("id", Schema::of_long("id")),
            ("createdBy", Schema::of_long("createdBy")),
            ("updatedBy", Schema::of_long("updatedBy")),
            ("createdAt", Schema::of_string("createdAt").set_format(StringFormat::DateTime)),
            ("updatedAt", Schema::of_string("updatedAt").set_format(StringFormat::DateTime)),
            ("clientId", Schema::of_long("clientId")),
            ("userName", Schema::of_string("userName")),
            ("emailId", Schema::of_string("emailId").set_format(StringFormat::Email)),
            ("phoneNumber", Schema::of_string("phoneNumber")),
            ("firstName", Schema::of_string("firstName")),
            ("lastName", Schema::of_string("lastName")),
            ("middleName", Schema::of_string("middleName")),
            ("localeCode", Schema::of_string("localeCode")),
            ("accountNonExpired", Schema::of_boolean("accountNonExpired")),
            ("accountNonLocked", Schema::of_boolean("accountNonLocked")),
            ("credentialsNonExpired", Schema::of_boolean("credentialsNonExpired")),
            ("noFailedAttempt", Schema::of_integer("noFailedAttempt")),
            ("statusCode", Schema::of_string("statusCode")),
            ("stringAuthorities", Schema::of_array("stringAuthorities", vec![Schema::of_string("authority")])),
        ]))
}

fn context_authentication() -> Schema {
    Schema::new()
        .set_namespace(SECURITY_CONTEXT)
        .set_name(CONTEXT_AUTHENTICATION)
        .set_type(TypeUtil::of(&[SchemaType::Object]))
        .set_properties(props(vec![
            ("user", Schema::of_ref(&format!("{SECURITY_CONTEXT}.{CONTEXT_USER}"))),
            ("isAuthenticated", Schema::of_boolean("isAuthenticated")),
            ("loggedInFromClientId", Schema::of_long("loggedInFromClientId")),
            ("loggedInFromClientCode", Schema::of_string("loggedInFromClientCode")),
            ("clientTypeCode", Schema::of_string("clientTypeCode")),
            ("clientCode", Schema::of_string("clientCode")),
            ("urlClientCode", Schema::of_string("urlClientCode")),
            ("urlAppCode", Schema::of_string("urlAppCode")),
        ]))
}

pub struct CoreSchemas {
    map: HashMap<String, Arc<FoundSchema>>,
    names: Vec<String>,
}

impl CoreSchemas {
    pub fn new() -> Self {
        let mut map = HashMap::new();
        let mut names = Vec::new();
        for s in [context_user(), context_authentication()] {
            let full = s.get_full_name();
            let json = gson_schema(&s.to_json()).unwrap_or(Value::Null);
            names.push(full.clone());
            map.insert(full, Arc::new(FoundSchema { schema: Arc::new(s), json }));
        }
        Self { map, names }
    }
}

impl Default for CoreSchemas {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SchemaSource for CoreSchemas {
    async fn find(&self, namespace: Option<&str>, name: &str) -> Result<Option<Arc<FoundSchema>>, CoreError> {
        Ok(self.map.get(&format!("{}.{name}", namespace.unwrap_or("null"))).cloned())
    }

    async fn filter(&self, name: &str) -> Result<Vec<String>, CoreError> {
        Ok(filter_names(&self.names, name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn security_context_schemas() {
        let core = CoreSchemas::default();
        let user = core.find(Some(SECURITY_CONTEXT), CONTEXT_USER).await.unwrap().unwrap();
        assert_eq!(user.json["properties"]["createdAt"]["format"], json!("DATETIME"));
        assert_eq!(user.json["properties"]["emailId"]["format"], json!("EMAIL"));
        assert_eq!(user.json["properties"]["stringAuthorities"]["items"]["type"], json!("STRING"));
        let auth = core.find(Some(SECURITY_CONTEXT), CONTEXT_AUTHENTICATION).await.unwrap().unwrap();
        assert_eq!(auth.json["properties"]["user"]["ref"], json!("Security.Context.ContextUser"));
        assert!(core.find(None, CONTEXT_USER).await.unwrap().is_none());
        assert_eq!(core.filter("context").await.unwrap().len(), 2);
        assert_eq!(core.filter("user").await.unwrap(), ["Security.Context.ContextUser"]);
    }
}
