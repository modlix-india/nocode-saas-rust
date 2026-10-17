//! Read-only lookups of the definitions the engines are handed, straight from the core
//! Mongo database: a storage, an app's appData connection, an app's schemas.
//!
//! These do NOT merge the override chain (a client's delta over its base); the overridable
//! read path does that and is the caller's to supply in production. They are exact for a
//! definition that has no base, which is every SYSTEM-owned one, and that is what the
//! parity tool and the live tests use.

use std::sync::Arc;

use async_trait::async_trait;
use mongodb::bson::{doc, Bson, Document as BsonDocument};
use mongodb::Database;

use crate::engine::{SchemaRepositories, StorageResolver};
use crate::model::{Connection, Schema, Storage};
use crate::schema_refs::SchemaRepository;
use crate::value::{Document, Value};

/// A definition document as plain JSON values: ids as hex, dates as epoch millis.
pub fn plain(d: &BsonDocument) -> Document {
    d.iter().map(|(k, v)| (k.clone(), plain_value(v))).collect()
}

fn plain_value(b: &Bson) -> Value {
    match b {
        Bson::ObjectId(o) => Value::String(o.to_hex()),
        Bson::DateTime(dt) => Value::Int(dt.timestamp_millis()),
        Bson::Document(d) => Value::Object(plain(d)),
        Bson::Array(a) => Value::Array(a.iter().map(plain_value).collect()),
        other => crate::mongo::bson_util::to_value(other),
    }
}

#[derive(Clone)]
pub struct MongoDefinitions {
    pub core: Database,
}

impl MongoDefinitions {
    pub fn new(core: Database) -> MongoDefinitions {
        MongoDefinitions { core }
    }

    pub async fn storage(&self, name: &str, app_code: &str, client_code: &str) -> anyhow::Result<Option<Storage>> {
        let found = self
            .core
            .collection::<BsonDocument>("storage")
            .find_one(doc! { "name": name, "appCode": app_code, "clientCode": client_code })
            .await?;
        Ok(match found {
            None => None,
            Some(d) => Some(Storage::from_value(&Value::Object(plain(&d))).map_err(anyhow::Error::msg)?),
        })
    }

    /// The app's "appData" APP_DATA connection for exactly this client.
    pub async fn app_data_connection(&self, app_code: &str, client_code: &str) -> anyhow::Result<Option<Connection>> {
        let found = self
            .core
            .collection::<BsonDocument>("connection")
            .find_one(doc! {
                "name": crate::selection::CONNECTION_NAME,
                "appCode": app_code,
                "clientCode": client_code,
                "connectionType": crate::selection::CONNECTION_TYPE,
            })
            .await?;
        Ok(match found {
            None => None,
            Some(d) => Some(Connection::from_value(&Value::Object(plain(&d))).map_err(anyhow::Error::msg)?),
        })
    }

    pub async fn schema(&self, full_name: &str, app_code: &str, client_code: &str) -> anyhow::Result<Option<Schema>> {
        let coll = self.core.collection::<BsonDocument>("schema");
        for client in [client_code, "SYSTEM"] {
            if let Some(d) = coll.find_one(doc! { "name": full_name, "appCode": app_code, "clientCode": client }).await? {
                let def = plain(&d).get("definition").cloned().unwrap_or(Value::Null);
                return Ok(Schema::from_value(&def));
            }
        }
        Ok(None)
    }
}

#[async_trait]
impl StorageResolver for MongoDefinitions {
    async fn read_for_tenant(&self, name: &str, app_code: &str, client_code: &str, _draft: bool)
        -> anyhow::Result<Option<Storage>> {
        match self.storage(name, app_code, client_code).await? {
            Some(s) => Ok(Some(s)),
            None => self.storage(name, app_code, "SYSTEM").await,
        }
    }
}

/// An app's schemas, looked up by full name.
pub struct AppSchemas {
    defs: MongoDefinitions,
    app_code: String,
    client_code: String,
}

#[async_trait]
impl SchemaRepository for AppSchemas {
    async fn find(&self, namespace: &str, name: &str) -> anyhow::Result<Option<Schema>> {
        self.defs.schema(&format!("{namespace}.{name}"), &self.app_code, &self.client_code).await
    }
}

impl SchemaRepositories for MongoDefinitions {
    fn for_app(&self, app_code: &str, client_code: &str) -> Arc<dyn SchemaRepository> {
        Arc::new(AppSchemas { defs: self.clone(), app_code: app_code.into(), client_code: client_code.into() })
    }
}
