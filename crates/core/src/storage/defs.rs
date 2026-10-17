//! The definitions the policy layer reads: `StorageService` (`read`, `readForTenant`,
//! `storagesReferencing`, `storageNames`), `ConnectionService` (`read` with a type,
//! `allAppData`), `EventDefinitionService.read`, and the schema repository the engines resolve
//! a storage's references with (`CoreSchemaService.getSchemaRepository`, core's own schemas
//! first).

use std::sync::Arc;

use appdata::engine::{SchemaRepositories, StorageResolver};
use appdata::model::{Connection, Schema as DataSchema, Storage};
use appdata::schema_refs::SchemaRepository;
use appdata::value::{Document, Value};
use async_trait::async_trait;
use axum::http::StatusCode;
use indexmap::IndexMap;
use mongodb::bson::{doc, Bson, Document as BsonDocument};
use overridable::{DocType, JMap, JValue};
use platform::cache::LocalCaches;

use crate::context;
use crate::docs::{ConnectionDoc, EventDefinitionDoc, StorageDoc};
use crate::error::CoreError;
use crate::repos::app::{app_schema_repository, Definitions};
use crate::repos::SchemaSource;

/// What the policy layer reads of the definitions; [`StorageDefs`] reads them from the
/// overridable store.
#[async_trait]
pub trait Catalog: Send + Sync {
    /// `StorageService.read(name, appCode, clientCode)`.
    async fn storage(&self, name: &str, app_code: &str, client_code: &str) -> Result<Option<Storage>, CoreError>;
    /// `ConnectionService.read(name, appCode, clientCode, type)`.
    async fn connection(&self, name: &str, app_code: &str, client_code: &str, connection_type: &str)
        -> Result<Option<Connection>, CoreError>;
    /// `ConnectionService.read(name, appCode, clientCode)`.
    async fn raw_connection(&self, name: &str, app_code: &str, client_code: &str) -> Result<Option<Connection>, CoreError>;
    /// `ConnectionService.allAppData(subType, appCode)`.
    async fn all_app_data(&self, sub_type: &str, app_code: &str) -> Result<Vec<Connection>, CoreError>;
    /// `StorageService.storagesReferencing`.
    async fn storages_referencing(&self, app_code: &str, storage_name: &str) -> Result<Vec<String>, CoreError>;
    /// `StorageService.storageNames`.
    async fn storage_names(&self, app_code: &str) -> Result<Vec<String>, CoreError>;
    /// `EventDefinitionService.read`.
    async fn event_definition(&self, name: &str, app_code: &str, client_code: &str) -> Result<Option<JMap>, CoreError>;
    /// The schemas besides KIRun's a storage of the app resolves against: core's, the app's.
    async fn schema_source(&self, app_code: &str, client_code: &str) -> Result<Arc<dyn SchemaSource>, CoreError>;
}

#[async_trait]
impl Catalog for StorageDefs {
    async fn storage(&self, name: &str, app_code: &str, client_code: &str) -> Result<Option<Storage>, CoreError> {
        StorageDefs::storage(self, name, app_code, client_code).await
    }
    async fn connection(&self, name: &str, app_code: &str, client_code: &str, connection_type: &str)
        -> Result<Option<Connection>, CoreError> {
        StorageDefs::connection(self, name, app_code, client_code, connection_type).await
    }
    async fn raw_connection(&self, name: &str, app_code: &str, client_code: &str) -> Result<Option<Connection>, CoreError> {
        StorageDefs::raw_connection(self, name, app_code, client_code).await
    }
    async fn all_app_data(&self, sub_type: &str, app_code: &str) -> Result<Vec<Connection>, CoreError> {
        StorageDefs::all_app_data(self, sub_type, app_code).await
    }
    async fn storages_referencing(&self, app_code: &str, storage_name: &str) -> Result<Vec<String>, CoreError> {
        StorageDefs::storages_referencing(self, app_code, storage_name).await
    }
    async fn storage_names(&self, app_code: &str) -> Result<Vec<String>, CoreError> {
        StorageDefs::storage_names(self, app_code).await
    }
    async fn event_definition(&self, name: &str, app_code: &str, client_code: &str) -> Result<Option<JMap>, CoreError> {
        StorageDefs::event_definition(self, name, app_code, client_code).await
    }
    async fn schema_source(&self, app_code: &str, client_code: &str) -> Result<Arc<dyn SchemaSource>, CoreError> {
        self.schema_sources(app_code, client_code).source().await
    }
}

/// `StorageService.CACHE_NAME_STORAGE_REFERENCES`, evicted whole by every storage save.
pub const CACHE_STORAGE_REFERENCES: &str = "storageReferences";

pub type ReferenceIndex = Arc<IndexMap<String, Vec<String>>>;

pub struct StorageDefs {
    defs: Arc<Definitions>,
    core_schemas: Arc<dyn SchemaSource>,
    references: Arc<LocalCaches<String, ReferenceIndex>>,
}

/// An overridable document's map as an engine value.
pub fn jvalue(v: &JValue) -> Value {
    match v {
        JValue::Null => Value::Null,
        JValue::Bool(b) => Value::Bool(*b),
        JValue::Int(i) => Value::Int(*i),
        JValue::Float(f) => Value::Double(*f),
        JValue::Str(s) => Value::String(s.clone()),
        JValue::Array(a) => Value::Array(a.iter().map(jvalue).collect()),
        JValue::Object(o) => Value::Object(jmap(o)),
    }
}

pub fn jmap(m: &JMap) -> Document {
    m.iter().map(|(k, v)| (k.clone(), jvalue(v))).collect()
}

fn storage_of(entity: &JMap) -> Result<Storage, CoreError> {
    Storage::from_value(&Value::Object(jmap(entity))).map_err(CoreError::unknown)
}

impl StorageDefs {
    pub fn new(
        defs: Arc<Definitions>,
        core_schemas: Arc<dyn SchemaSource>,
        references: Arc<LocalCaches<String, ReferenceIndex>>,
    ) -> Self {
        Self { defs, core_schemas, references }
    }

    pub fn definitions(&self) -> &Arc<Definitions> {
        &self.defs
    }

    /// `AbstractOverridableDataService.read(name, appCode, clientCode)`: resolved for the
    /// caller's url client code, on the request's surface, for the client `servedClientCode`
    /// picks (a signed-in tenant's own on a shared host, Java commit e2b7d48aa).
    async fn read(&self, dt: &dyn DocType, name: &str, app_code: &str, client_code: &str) -> Result<Option<JMap>, CoreError> {
        let auth = context::authentication();
        let url_client = auth.url_client_code().map(str::to_string).unwrap_or_else(|| client_code.to_string());
        let store = self.defs.store();
        let served = store.served_client_code(Some(&auth.ca), app_code, client_code).await;
        let r = store.read(dt, name, app_code, &url_client, &served, context::is_draft()).await?;
        Ok(r.map(|r| r.entity.clone()))
    }

    /// `StorageService.read(name, appCode, clientCode)`.
    pub async fn storage(&self, name: &str, app_code: &str, client_code: &str) -> Result<Option<Storage>, CoreError> {
        match self.read(&StorageDoc, name, app_code, client_code).await? {
            Some(e) => Ok(Some(storage_of(&e)?)),
            None => Ok(None),
        }
    }

    /// `StorageService.readForTenant`: `readInternal(name, appCode, clientCode)`, the client
    /// as its own url client, on the surface given.
    pub async fn storage_for_tenant(&self, name: &str, app_code: &str, client_code: &str, draft: bool)
        -> Result<Option<Storage>, CoreError> {
        let r = self.defs.store().read(&StorageDoc, name, app_code, client_code, client_code, draft).await?;
        match r {
            Some(r) => Ok(Some(storage_of(&r.entity)?)),
            None => Ok(None),
        }
    }

    /// `ConnectionService.read(name, appCode, clientCode, type)`: of that type, the client's
    /// own or app-level, and an `onlyThruKIRun` one only inside a KIRun run (outside one Java's
    /// `ContextView.get` throws).
    pub async fn connection(&self, name: &str, app_code: &str, client_code: &str, connection_type: &str)
        -> Result<Option<Connection>, CoreError> {
        let Some(e) = self.read(&ConnectionDoc, name, app_code, client_code).await? else {
            return Ok(None);
        };
        let s = |k: &str| match e.get(k) {
            Some(JValue::Str(s)) => Some(s.as_str()),
            _ => None,
        };
        let b = |k: &str| matches!(e.get(k), Some(JValue::Bool(true)));
        if s("connectionType") != Some(connection_type) {
            return Ok(None);
        }
        if s("clientCode") != Some(client_code) && !b("isAppLevel") {
            return Ok(None);
        }
        if b("onlyThruKIRun") && !context::in_kirun() {
            return Err(CoreError::unknown("Context does not contain key: KIRun Runtime"));
        }
        Connection::from_value(&Value::Object(jmap(&e))).map(Some).map_err(CoreError::unknown)
    }

    /// `connectionService.read(name, appCode, clientCode)`: the resolved document, whatever
    /// its type or client (`downloadTemplate` reads it this way).
    pub async fn raw_connection(&self, name: &str, app_code: &str, client_code: &str) -> Result<Option<Connection>, CoreError> {
        match self.read(&ConnectionDoc, name, app_code, client_code).await? {
            Some(e) => Connection::from_value(&Value::Object(jmap(&e))).map(Some).map_err(CoreError::unknown),
            None => Ok(None),
        }
    }

    /// `ConnectionService.allAppData(subType, appCode)`: the app's APP_DATA connections of a
    /// backend, one per distinct set of connection details, as stored.
    pub async fn all_app_data(&self, sub_type: &str, app_code: &str) -> Result<Vec<Connection>, CoreError> {
        if app_code.trim().is_empty() {
            return Ok(Vec::new());
        }
        let docs = self
            .defs
            .store()
            .find_docs(
                "connection",
                doc! {"$and": [{"connectionType": "APP_DATA"}, {"connectionSubType": sub_type}, {"appCode": app_code}]},
            )
            .await?;
        let mut seen = Vec::new();
        let mut out = Vec::new();
        for d in docs {
            let plain = appdata::lookup::plain(&d);
            let key = plain.get("connectionDetails").map(Value::to_java_json).unwrap_or_default();
            if seen.contains(&key) {
                continue;
            }
            seen.push(key);
            out.push(Connection::from_value(&Value::Object(plain)).map_err(CoreError::unknown)?);
        }
        Ok(out)
    }

    /// `StorageService.storagesReferencing`: the storages whose relations point at this one,
    /// from every client's documents of the app.
    pub async fn storages_referencing(&self, app_code: &str, storage_name: &str) -> Result<Vec<String>, CoreError> {
        if app_code.trim().is_empty() || storage_name.trim().is_empty() {
            return Ok(Vec::new());
        }
        let store = self.defs.store().clone();
        let app = app_code.to_string();
        let index = self
            .references
            .get_or_load(CACHE_STORAGE_REFERENCES, app_code.to_string(), || async move {
                let docs = store.find_docs("storage", doc! {"appCode": &app}).await?;
                Ok::<_, anyhow::Error>(Some(Arc::new(reference_index(&docs))))
            })
            .await?
            .unwrap_or_default();
        Ok(index.get(storage_name).cloned().unwrap_or_default())
    }

    /// `StorageService.storageNames`: every storage name of the app, sorted.
    pub async fn storage_names(&self, app_code: &str) -> Result<Vec<String>, CoreError> {
        if app_code.trim().is_empty() {
            return Ok(Vec::new());
        }
        let values = self
            .defs
            .store()
            .db()
            .collection::<BsonDocument>("storage")
            .distinct("name", doc! {"appCode": app_code})
            .await
            .map_err(anyhow::Error::from)?;
        let mut names: Vec<String> = values.into_iter().filter_map(|b| b.as_str().map(str::to_string)).collect();
        names.sort_by(|a, b| java_compare(a, b));
        Ok(names)
    }

    /// `EventDefinitionService.read(name, appCode, clientCode)`.
    pub async fn event_definition(&self, name: &str, app_code: &str, client_code: &str) -> Result<Option<JMap>, CoreError> {
        self.read(&EventDefinitionDoc, name, app_code, client_code).await
    }

    /// `TemplateService.read(name, appCode, clientCode)`.
    pub async fn template(&self, name: &str, app_code: &str, client_code: &str) -> Result<Option<JMap>, CoreError> {
        self.read(&crate::docs::TemplateDoc, name, app_code, client_code).await
    }

    /// The schemas a storage's `$ref`s and its rows are checked against, besides KIRun's: core's
    /// own, then the app's (and its dependencies').
    pub fn schema_sources(&self, app_code: &str, client_code: &str) -> AppSchemaSources {
        AppSchemaSources {
            defs: self.defs.clone(),
            core: self.core_schemas.clone(),
            app_code: app_code.to_string(),
            client_code: client_code.to_string(),
            surface: None,
        }
    }
}

/// `String.compareTo`: UTF-16 code units.
fn java_compare(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// `StorageService.referenceIndex`: relation target -> the storages pointing at it, in the
/// order the documents and their relations come.
fn reference_index(docs: &[BsonDocument]) -> IndexMap<String, Vec<String>> {
    let mut index: IndexMap<String, Vec<String>> = IndexMap::new();
    for d in docs {
        let Ok(relations) = d.get_document("relations") else { continue };
        let Ok(name) = d.get_str("name") else { continue };
        for (_, rel) in relations {
            let Bson::Document(rel) = rel else { continue };
            let Ok(target) = rel.get_str("storageName") else { continue };
            if target.trim().is_empty() {
                continue;
            }
            let names = index.entry(target.to_string()).or_default();
            if !names.iter().any(|n| n == name) {
                names.push(name.to_string());
            }
        }
    }
    index
}

/// core's and one app's schemas, for the engines and the write validator.
#[derive(Clone)]
pub struct AppSchemaSources {
    defs: Arc<Definitions>,
    core: Arc<dyn SchemaSource>,
    app_code: String,
    client_code: String,
    /// A named surface the app's schemas are read on; `None` follows the request's.
    surface: Option<bool>,
}

impl AppSchemaSources {
    /// The same schemas as one surface sees them: on the draft surface a client's own schema
    /// drafts, which is how a schema draft reaches that client's draft tables.
    pub fn on_surface(mut self, draft: bool) -> Self {
        self.surface = Some(draft);
        self
    }

    /// The schema JSON (Gson's shape) under `namespace.name`.
    pub async fn find_json(&self, namespace: &str, name: &str) -> Result<Option<serde_json::Value>, CoreError> {
        match self.surface {
            Some(draft) => context::with_surface(draft, self.find_json_here(namespace, name)).await,
            None => self.find_json_here(namespace, name).await,
        }
    }

    async fn find_json_here(&self, namespace: &str, name: &str) -> Result<Option<serde_json::Value>, CoreError> {
        if let Some(f) = self.core.find(Some(namespace), name).await? {
            return Ok(Some(f.json.clone()));
        }
        let app = app_schema_repository(&self.defs, &self.app_code, &self.client_code).await?;
        Ok(app.find(Some(namespace), name).await?.map(|f| f.json.clone()))
    }

    /// As a source the kirun validator can use: core's, then the app's.
    pub async fn source(&self) -> Result<Arc<dyn SchemaSource>, CoreError> {
        let app = app_schema_repository(&self.defs, &self.app_code, &self.client_code).await?;
        Ok(Arc::new(crate::repos::Hybrid::new(vec![self.core.clone(), app])))
    }
}

#[async_trait]
impl SchemaRepository for AppSchemaSources {
    async fn find(&self, namespace: &str, name: &str) -> anyhow::Result<Option<DataSchema>> {
        let json = self.find_json(namespace, name).await.map_err(|e| anyhow::anyhow!(e.text()))?;
        Ok(json.and_then(|j| DataSchema::from_value(&Value::from_json(&j))))
    }
}

#[async_trait]
impl StorageResolver for StorageDefs {
    async fn read_for_tenant(&self, name: &str, app_code: &str, client_code: &str, draft: bool)
        -> anyhow::Result<Option<Storage>> {
        self.storage_for_tenant(name, app_code, client_code, draft).await.map_err(anyhow::Error::new)
    }
}

impl SchemaRepositories for StorageDefs {
    fn for_app(&self, app_code: &str, client_code: &str) -> Arc<dyn SchemaRepository> {
        Arc::new(self.schema_sources(app_code, client_code))
    }

    /// `getSchemaRepository` under the draft flag the engine names, not the request's: a
    /// table built for the draft surface reads the client's schema drafts.
    fn for_surface(&self, app_code: &str, client_code: &str, draft: bool) -> Arc<dyn SchemaRepository> {
        Arc::new(self.schema_sources(app_code, client_code).on_surface(draft))
    }
}

/// A refusal `appStorages` drops: a storage this client does not resolve (404) or may not use
/// (403), raised as a `GenericException`.
pub fn not_found_or_forbidden(e: &CoreError) -> bool {
    matches!(e.status(), StatusCode::NOT_FOUND | StatusCode::FORBIDDEN)
        && matches!(e, CoreError::Message { .. } | CoreError::ObjectNotFound { .. })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_index_lists_each_referencing_storage_once() {
        let docs = vec![
            doc! {"name": "blogs", "relations": {"category": {"storageName": "cats"}, "alt": {"storageName": "cats"}}},
            doc! {"name": "posts", "relations": {"cat": {"storageName": "cats"}, "x": {"storageName": ""}, "y": 1}},
            doc! {"name": "plain"},
            doc! {"relations": {"a": {"storageName": "cats"}}},
        ];
        let ix = reference_index(&docs);
        assert_eq!(ix.len(), 1);
        assert_eq!(ix["cats"], ["blogs", "posts"]);
    }

    /// A client's schema draft shapes what the draft surface resolves (the draft tables) and
    /// not what the live one does.
    #[tokio::test]
    async fn a_schema_draft_reaches_the_draft_surface_only() {
        use overridable::backend::{FakeDirectory, MemBackend};
        use overridable::write::draft::DraftStore;
        use overridable::write::persist::to_document;

        let mem = Arc::new(MemBackend::new());
        let dir = Arc::new(FakeDirectory::new());
        dir.chain(&["SYSTEM"]);
        let cache = platform::cache::CacheService::new("cmn", "evictionChannel", None).unwrap();
        let store = overridable::Store::with_parts(mem.clone(), dir, &cache).unwrap();
        let security = platform::security::SecurityClient::new(platform::upstream::Upstream::fixed(&["http://127.0.0.1:1"]), 0).unwrap();
        let deps: Arc<LocalCaches<String, Arc<Vec<String>>>> = cache.family();
        deps.insert("appDepList", "app".to_string(), Arc::new(Vec::new())).await;
        let definitions = Arc::new(Definitions::new(store, security, deps, std::time::Duration::from_secs(5)));
        let defs = Arc::new(StorageDefs::new(definitions, crate::state::Builtins::core_schemas(), cache.family()));

        let schema = |props: serde_json::Value| -> JMap {
            let v = serde_json::json!({"name": "App.Thing", "appCode": "app", "clientCode": "SYSTEM", "version": 1,
                "definition": {"namespace": "App", "name": "Thing", "type": "OBJECT", "properties": props}});
            match overridable::json::parse(v.to_string().as_bytes()).unwrap() {
                JValue::Object(m) => m,
                _ => unreachable!(),
            }
        };
        let live = schema(serde_json::json!({"a": {"type": "STRING"}}));
        let id = mem.put_raw("schema", to_document(&crate::docs::SCHEMA, &live, None, &[]));
        let id = overridable::bson_conv::to_java_string(&id).java_to_string();
        let mut drafted = schema(serde_json::json!({"a": {"type": "STRING"}, "b": {"type": "INTEGER"}}));
        drafted.insert("id".into(), JValue::Str(id.clone()));
        DraftStore::new(mem.clone())
            .upsert("SCHEMA", "app", "App.Thing", "SYSTEM", &id, to_document(&crate::docs::SCHEMA, &drafted, None, &[]), 1, None)
            .await
            .unwrap();

        let storage = Storage::from_value(&Value::from_json(&serde_json::json!({
            "name": "things", "appCode": "app", "clientCode": "SYSTEM", "schema": {"ref": "App.Thing"}})))
        .unwrap();
        let hooks = appdata::engine::Hooks { schemas: Some(defs), ..Default::default() };
        let keys = |s: Option<DataSchema>| -> Vec<String> {
            s.and_then(|s| s.properties).map(|p| p.keys().cloned().collect()).unwrap_or_default()
        };
        assert_eq!(keys(hooks.resolved_schema_on(&storage, false).await), ["a"], "live tables keep the live schema");
        assert_eq!(keys(hooks.resolved_schema_on(&storage, true).await), ["a", "b"], "draft tables take the client's schema draft");
        // A request on the live surface still builds a draft table from the draft.
        let on_draft = crate::context::with_surface(false, hooks.resolved_schema_on(&storage, true)).await;
        assert_eq!(keys(on_draft), ["a", "b"]);
    }

    #[test]
    fn java_string_order() {
        let mut v = vec!["b".to_string(), "B".into(), "a".into(), "\u{ff21}".into(), "\u{1F600}".into()];
        v.sort_by(|a, b| java_compare(a, b));
        assert_eq!(v, ["B", "a", "b", "\u{1F600}", "\u{ff21}"]);
    }

    #[test]
    fn jvalues_become_engine_values() {
        let mut m = JMap::new();
        m.insert("a".into(), JValue::Array(vec![JValue::Null, JValue::Bool(true), JValue::Int(1), JValue::Float(1.5)]));
        m.insert("b".into(), JValue::Str("x".into()));
        let d = jmap(&m);
        assert_eq!(
            d["a"],
            Value::Array(vec![Value::Null, Value::Bool(true), Value::Int(1), Value::Double(1.5)])
        );
        assert_eq!(d["b"], Value::from("x"));
    }
}
