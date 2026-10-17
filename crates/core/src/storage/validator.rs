//! `StorageWriteValidator`: a row is checked against its storage's schema on the way in, by
//! KIRun's schema validator, with KIRun's, core's and the storage's app's schemas to resolve
//! references. Relation fields are lifted out first (they hold ids, not values the schema
//! describes) and put back after, in `HashMap` order, at the end of the row.

use std::sync::Arc;

use appdata::engine::WriteValidator;
use appdata::model::{Schema as DataSchema, Storage};
use appdata::value::Document;
use appdata::{AppDataError, AppDataResult};
use async_trait::async_trait;
use kirun::json::schema::validator::schema_validator::SchemaValidator;
use kirun::json::schema::Schema;
use kirun::repository::Repository;

use super::defs::StorageDefs;
use super::values::{gson_object, hash_map_order, storage_document};
use crate::java_model::gson_schema;
use crate::repos::{Hybrid, SchemaRepo, SchemaSource};

pub struct KirunWriteValidator {
    pub kirun_schemas: Arc<dyn SchemaSource>,
    pub defs: Arc<StorageDefs>,
}

/// `gson.fromJson(gson.toJsonTree(storage.getSchema()), Schema.class)`.
pub fn kirun_schema(storage: &Storage) -> Result<Option<Schema>, String> {
    let Some(raw) = &storage.schema else { return Ok(None) };
    let Some(json) = gson_schema(&raw.to_json()) else { return Ok(None) };
    Schema::from_value(&json).map_err(|e| e.to_string())
}

#[async_trait]
impl WriteValidator for KirunWriteValidator {
    async fn validate(&self, data: &Document, storage: &Storage, _schema: Option<&DataSchema>) -> AppDataResult<Document> {
        let internal = |m: String| AppDataError::Internal(anyhow::anyhow!(m));
        let mut job = gson_object(data).map_err(|e| internal(e.text()))?;

        let mut relations = Document::new();
        for key in storage.relation_keys() {
            if let Some(v) = job.shift_remove(&key) {
                relations.insert(key, super::values::storage_value(&v));
            }
        }

        let schema = kirun_schema(storage).map_err(internal)?;
        let app = self
            .defs
            .schema_sources(&storage.app_code, &storage.client_code)
            .source()
            .await
            .map_err(|e| internal(e.text()))?;
        let repo: Arc<dyn SchemaSource> = Arc::new(Hybrid::new(vec![self.kirun_schemas.clone(), app]));
        let repo = SchemaRepo(repo);
        let validated = SchemaValidator::validate(
            None,
            schema.as_ref(),
            Some(&repo as &dyn Repository<Schema>),
            serde_json::Value::Object(job),
        )
        .await
        .map_err(|e| internal(e.to_string()))?;

        let serde_json::Value::Object(validated) = validated else {
            return Err(internal("Not a JSON Object: the validated row".into()));
        };
        let mut out = storage_document(&validated);
        for (k, v) in hash_map_order(relations) {
            out.insert(k, v);
        }
        Ok(out)
    }
}
