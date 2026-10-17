//! What `StorageService` and `CoreSchemaService` add to the overridable write path:
//!
//! - a storage's `uniqueName` (its table or collection), given once at create and shared by
//!   a client's override;
//! - `validate`: the schema readable and an object, the field names storable, the column
//!   definitions sound, the relations pointing at storages that exist;
//! - the definition triggers (`BEFORE_UPDATE_STORAGE` ... `AFTER_DELETE_STORAGE`);
//! - the tables following the definition: a MySQL app's tenant tables reconciled on every
//!   change of a storage or of a schema a storage stands on, a deleted storage's draft data
//!   dropped, a client's schema override given its own copy of the storages standing on it.
//!
//! The rebuilds never fail the save that caused them; they log, as Java's do.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use axum::http::StatusCode;
use dashmap::DashMap;
use indexmap::{IndexMap, IndexSet};
use mongodb::bson::doc;
use overridable::backend::Find;
use overridable::pojo::{decode_bson, map_field, str_field};
use overridable::write::schema_refs;
use overridable::write::{Commons, OverridableService};
use overridable::{JMap, JValue};
use platform::error::{AppError, AppResult};
use platform::security::ContextAuthentication;

use crate::docs::{SCHEMA, STORAGE};
use crate::editor::kinds::{self, CoreKind};
use crate::repos::{Hybrid, SchemaSource};
use crate::storage::defs::Catalog;

pub const INDEX_CREATION: &str = "_index_creation";
pub const TABLE_CREATION: &str = "_table_creation";
pub const STORAGE_SCHEMA: &str = "_storage_schema";
pub const STORAGE_SCHEMA_RESOLVED: &str = "_storage_schema_resolved";
pub const STORAGE_REFERENCES: &str = "storageReferences";

/// `UniqueUtil.base36UUID`: the first eight characters of a random UUID's text, read as a
/// big-endian `long`, in base 36.
pub fn base36_uuid() -> String {
    let u = uuid::Uuid::new_v4().to_string();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&u.as_bytes()[..8]);
    let mut n = i64::from_be_bytes(bytes) as i128;
    let neg = n < 0;
    if neg {
        n = -n;
    }
    let digits = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut out = Vec::new();
    loop {
        out.push(digits[(n % 36) as usize]);
        n /= 36;
        if n == 0 {
            break;
        }
    }
    if neg {
        out.push(b'-');
    }
    out.reverse();
    String::from_utf8(out).unwrap_or_default()
}

/// `UniqueUtil.uniqueName(maxLength, parts...)`: the parts' letters, digits and underscores,
/// lower-cased, each followed by `_`, cut near `maxLength - 15`, then a random suffix.
pub fn unique_name(max_length: i32, parts: &[Option<&str>]) -> String {
    let mut sb = String::new();
    let mut i: i32 = 0;
    let max = max_length - 15;
    for part in parts {
        if i > max {
            break;
        }
        let Some(s) = part else { continue };
        for c in s.chars() {
            if i > max {
                break;
            }
            for l in c.to_lowercase() {
                if l.is_ascii_lowercase() || l == '_' || l.is_ascii_digit() {
                    sb.push(l);
                    i += 1;
                }
            }
        }
        sb.push('_');
    }
    sb.push_str(&base36_uuid());
    sb
}

fn blank(v: Option<&JValue>) -> bool {
    match v {
        None | Some(JValue::Null) => true,
        Some(x) => x.java_to_string().trim().is_empty(),
    }
}

/// The data side the storage hooks reach: a MySQL app's tables, the draft surface's data.
#[async_trait]
pub trait DataStores: Send + Sync {
    /// `AppDataService.reconcileStorageDdl`: every MySQL server the app uses.
    async fn reconcile(&self, app_code: &str, storage: &JMap, applied_by: &str);
    /// `AppDataService.dropDraftStorageData`.
    async fn drop_draft_storage(&self, app_code: &str, client_code: &str, storage: &JMap) -> Result<bool, String>;
    /// `AppDataService.dropDraftData`: an app's whole draft database for one client.
    async fn drop_draft_data(&self, app_code: &str, client_code: &str) -> Result<bool, String>;
    /// `AppDataService.estimatedRowCount`.
    async fn estimated_row_count(&self, app_code: &str, client_code: &str) -> i64;
}

/// Runs a definition trigger (a core function) as the caller.
#[async_trait]
pub trait Triggers: Send + Sync {
    async fn run(&self, namespace: &str, name: &str, app_code: &str, client_code: &str, args: kirun::Map<serde_json::Value>) -> AppResult<()>;
}

/// What the storage and schema hooks share.
pub struct StorageOps {
    pub catalog: Arc<dyn Catalog>,
    pub kirun_schemas: Arc<dyn SchemaSource>,
    pub core_schemas: Arc<dyn SchemaSource>,
    pub data: Arc<dyn DataStores>,
    pub triggers: Arc<dyn Triggers>,
    pub storages: OnceLock<OverridableService<CoreKind>>,
    /// The stored storage an update started from, for its `AFTER_UPDATE_STORAGE` triggers.
    before_update: DashMap<String, JMap>,
}

impl StorageOps {
    pub fn new(catalog: Arc<dyn Catalog>, kirun_schemas: Arc<dyn SchemaSource>, core_schemas: Arc<dyn SchemaSource>, data: Arc<dyn DataStores>, triggers: Arc<dyn Triggers>) -> Self {
        Self { catalog, kirun_schemas, core_schemas, data, triggers, storages: OnceLock::new(), before_update: DashMap::new() }
    }

    fn storages(&self) -> AppResult<&OverridableService<CoreKind>> {
        self.storages.get().ok_or_else(|| AppError::Internal(anyhow::anyhow!("the storage service is not wired")))
    }

    // ── create ─────────────────────────────────────────────────

    fn new_unique_name(e: &JMap) -> String {
        unique_name(32, &[str_field(e, "appCode"), str_field(e, "clientCode"), str_field(e, "name")])
    }

    /// `StorageService.create` up to `super.create`: the table name (the base's for a client
    /// override), the app-level rule, `validate`.
    pub async fn before_create(&self, cx: &Commons, ca: &ContextAuthentication, e: &mut JMap) -> AppResult<()> {
        if e.get("baseClientCode").is_some_and(|b| !b.is_null()) {
            let merged = self.storages()?.merged_sources(e).await?;
            let inherited = merged.as_ref().and_then(|m| str_field(m, "uniqueName")).filter(|u| !u.trim().is_empty()).map(str::to_string);
            let name = inherited.unwrap_or_else(|| Self::new_unique_name(e));
            e.insert("uniqueName".into(), JValue::Str(name));
            if merged.as_ref().is_some_and(|m| m.get("isAppLevel") == Some(&JValue::Bool(true))) {
                let (app, client) = (str_field(e, "appCode").unwrap_or(""), str_field(e, "clientCode").unwrap_or(""));
                if !cx.directory().has_write_access(app, client).await.map_err(AppError::Internal)? {
                    return Err(cx.error(StatusCode::FORBIDDEN, kinds::STORAGE_IS_APP_LEVEL, &[]));
                }
            }
        } else {
            e.insert("uniqueName".into(), JValue::Str(Self::new_unique_name(e)));
        }
        self.validate(cx, ca, e).await
    }

    pub async fn after_create(&self, cx: &Commons, created: &JMap) {
        let u = str_field(created, "uniqueName").unwrap_or("null");
        cx.evict_all(&format!("{u}{INDEX_CREATION}")).await;
    }

    // ── validate ───────────────────────────────────────────────

    /// The schema the storage declares, references followed: `None` when it declares none.
    async fn declared_schema(&self, cx: &Commons, e: &JMap) -> AppResult<Option<appdata::model::Schema>> {
        let Some(raw) = e.get("schema").filter(|v| !v.is_null()) else { return Ok(None) };
        let json = crate::storage::defs::jvalue(raw).to_json();
        if let Some(m) = unknown_schema_type(&json) {
            return Err(cx.error(StatusCode::BAD_REQUEST, kinds::INVALID_STORAGE_SCHEMA, &[&m]));
        }
        let Some(gson) = crate::java_model::gson_schema(&json) else { return Ok(None) };
        let parsed = kirun::json::schema::Schema::from_value(&gson).map_err(|err| cx.error(StatusCode::BAD_REQUEST, kinds::INVALID_STORAGE_SCHEMA, &[&err.to_string()]))?;
        let Some(schema) = parsed else { return Ok(None) };
        let schema = match schema.get_ref().map(str::to_string) {
            None => schema,
            Some(r) => {
                let (app, client) = (str_field(e, "appCode").unwrap_or(""), str_field(e, "clientCode").unwrap_or(""));
                let app_source = self.catalog.schema_source(app, client).await.map_err(|err| AppError::Internal(anyhow::anyhow!(err.text())))?;
                let repo = crate::repos::SchemaRepo(Arc::new(Hybrid::new(vec![self.kirun_schemas.clone(), self.core_schemas.clone(), app_source])));
                kirun::json::schema::schema_util::SchemaUtil::get_schema_from_ref(&schema, Some(&repo as &dyn kirun::repository::Repository<kirun::json::schema::Schema>), Some(&r))
                    .await
                    .map_err(|err| AppError::Internal(anyhow::anyhow!(err.to_string())))?
                    .unwrap_or(schema)
            }
        };
        Ok(appdata::model::Schema::from_value(&appdata::Value::from_json(&schema.to_json())))
    }

    /// `StorageService.validate`. Gives each new relation its `uniqueRelationId`.
    pub async fn validate(&self, cx: &Commons, ca: &ContextAuthentication, e: &mut JMap) -> AppResult<()> {
        if blank(e.get("uniqueName")) {
            return Err(cx.error(StatusCode::INTERNAL_SERVER_ERROR, overridable::write::messages::NAME_MISSING, &["uniqueName"]));
        }
        let schema = self.declared_schema(cx, e).await?;
        if let Some(s) = &schema {
            if let Some(types) = &s.types {
                if types.len() != 1 || types[0] != appdata::model::SchemaType::Object {
                    return Err(cx.error(StatusCode::BAD_REQUEST, kinds::STORAGE_SCHEMA_ALWAYS_OBJECT, &[]));
                }
            }
        }
        let relation_keys: Vec<String> = map_field(e, "relations").map(|r| r.keys().cloned().collect()).unwrap_or_default();
        let names = appdata::field_names::problems(schema.as_ref(), &relation_keys);
        if !names.is_empty() {
            return Err(cx.error(StatusCode::BAD_REQUEST, kinds::INVALID_COLUMN_DEFINITION, &[&names.join("; ")]));
        }
        let columns = column_problems(map_field(e, "columnDefinitions"), schema.as_ref(), &relation_keys);
        if !columns.is_empty() {
            return Err(cx.error(StatusCode::BAD_REQUEST, kinds::INVALID_COLUMN_DEFINITION, &[&columns.join("; ")]));
        }
        let Some(relations) = map_field(e, "relations").filter(|r| !r.is_empty()).cloned() else { return Ok(()) };
        let declared = schema.as_ref().and_then(|s| s.properties.as_ref());
        let (app, client, name) = (
            str_field(e, "appCode").map(str::to_string),
            str_field(e, "clientCode").map(str::to_string),
            str_field(e, "name").map(str::to_string),
        );
        let mut updated = relations.clone();
        for (field, relation) in &relations {
            if declared.is_some_and(|d| d.contains_key(field)) {
                return Err(cx.error(StatusCode::BAD_REQUEST, kinds::STORAGE_SCHEMA_FIELD_ALREADY_EXISTS, &[field]));
            }
            let Some(r) = relation.as_object() else { continue };
            if r.get("uniqueRelationId").is_some_and(|v| !v.is_null()) {
                continue;
            }
            let mut r = r.clone();
            let id = unique_name(32, &[app.as_deref(), client.as_deref(), name.as_deref(), Some(field)]);
            r.insert("uniqueRelationId".into(), JValue::Str(id));
            // `StorageRelation` is written in its declaration order.
            updated.insert(field.clone(), JValue::Object(reorder_relation(r)));
        }
        e.insert("relations".into(), JValue::Object(updated));
        let storages = self.storages()?;
        for relation in relations.values() {
            let target = relation.as_object().and_then(|r| str_field(r, "storageName")).map(str::to_string);
            let found = match &target {
                Some(t) => storages.read_resolved(ca, t, app.as_deref().unwrap_or(""), client.as_deref().unwrap_or(""), false).await?,
                None => None,
            };
            if found.is_none() {
                let t = target.unwrap_or_else(|| "null".into());
                return Err(cx.error(StatusCode::BAD_REQUEST, kinds::NO_STORAGE_FOUND_WITH_NAME, &[&t]));
            }
        }
        Ok(())
    }

    // ── update ─────────────────────────────────────────────────

    /// `StorageService.update` up to `super.update`: the body validated, the stored storage
    /// read (a 404 for an unknown id), its `BEFORE_UPDATE_STORAGE` triggers run.
    pub async fn before_update(&self, cx: &Commons, ca: &ContextAuthentication, e: &mut JMap) -> AppResult<()> {
        self.validate(cx, ca, e).await?;
        let id = str_field(e, "id").unwrap_or("").to_string();
        let existing = self.storages()?.read(ca, &id).await?;
        let mut args = kirun::Map::new();
        args.insert("existing".into(), gson_of(&existing));
        args.insert("creating".into(), gson_of(e));
        self.run_triggers(&existing, "BEFORE_UPDATE_STORAGE", str_field(e, "appCode"), str_field(e, "clientCode"), args).await?;
        self.before_update.insert(id, existing);
        Ok(())
    }

    /// `StorageService.updatableEntity`: the fields an update may change, then `validate`.
    pub async fn updatable_fill(&self, cx: &Commons, ca: &ContextAuthentication, existing: &mut JMap, incoming: &JMap) -> AppResult<()> {
        for f in [
            "schema",
            "isAudited",
            "isVersioned",
            "isAppLevel",
            "createAuth",
            "readAuth",
            "updateAuth",
            "deleteAuth",
            "generateEvents",
            "triggers",
            "relations",
            "fieldDefinitionMap",
            "columnDefinitions",
            "versionRetentionDays",
            "versionRetentionCount",
            "onlyThruKIRun",
            "indexes",
            "textIndexFields",
        ] {
            existing.insert(f.to_string(), incoming.get(f).cloned().unwrap_or_default());
        }
        self.validate(cx, ca, existing).await
    }

    /// The end of `StorageService.update`: `AFTER_UPDATE_STORAGE` triggers, the index and
    /// table creation caches.
    pub async fn after_update(&self, cx: &Commons, request: &JMap, saved: &JMap) -> AppResult<()> {
        let id = str_field(saved, "id").or(str_field(request, "id")).unwrap_or("").to_string();
        if let Some((_, existing)) = self.before_update.remove(&id) {
            let mut args = kirun::Map::new();
            args.insert("existing".into(), gson_of(&existing));
            args.insert("created".into(), gson_of(saved));
            self.run_triggers(&existing, "AFTER_UPDATE_STORAGE", str_field(request, "appCode"), str_field(request, "clientCode"), args).await?;
        }
        let u = str_field(saved, "uniqueName").unwrap_or("null");
        cx.evict_all(&format!("{u}{INDEX_CREATION}")).await;
        cx.evict_all(&format!("{u}{TABLE_CREATION}")).await;
        Ok(())
    }

    // ── delete ─────────────────────────────────────────────────

    pub async fn before_delete(&self, stored: &JMap) -> AppResult<()> {
        let mut args = kirun::Map::new();
        args.insert("storage".into(), gson_of(stored));
        self.run_triggers(stored, "BEFORE_DELETE_STORAGE", str_field(stored, "appCode"), str_field(stored, "clientCode"), args).await
    }

    /// The end of `StorageService.delete`: `AFTER_DELETE_STORAGE` triggers, the schema caches,
    /// and the draft data (unless a client override shares its base's table).
    pub async fn after_delete(&self, cx: &Commons, deleted: &JMap, result: bool) -> AppResult<bool> {
        let mut args = kirun::Map::new();
        args.insert("storage".into(), gson_of(deleted));
        self.run_triggers(deleted, "AFTER_DELETE_STORAGE", str_field(deleted, "appCode"), str_field(deleted, "clientCode"), args).await?;
        self.evict_schema_caches(cx, str_field(deleted, "uniqueName").unwrap_or("null")).await;
        if !self.shares_base_table(deleted).await {
            let (app, client) = (str_field(deleted, "appCode").unwrap_or(""), str_field(deleted, "clientCode").unwrap_or(""));
            if let Err(e) = self.data.drop_draft_storage(app, client, deleted).await {
                tracing::error!(storage = str_field(deleted, "uniqueName"), client, app, error = %e, "Could not drop the draft collection");
            }
        }
        Ok(result)
    }

    /// True for a client override whose table is its base's.
    async fn shares_base_table(&self, storage: &JMap) -> bool {
        let Some(base) = str_field(storage, "baseClientCode").filter(|b| !b.trim().is_empty()) else { return false };
        let (name, app) = (str_field(storage, "name").unwrap_or(""), str_field(storage, "appCode").unwrap_or(""));
        match self.read_for_tenant(name, app, base).await {
            Some(b) => str_field(&b, "uniqueName") == str_field(storage, "uniqueName"),
            None => false,
        }
    }

    // ── triggers ───────────────────────────────────────────────

    async fn run_triggers(&self, storage: &JMap, kind: &str, app: Option<&str>, client: Option<&str>, args: kirun::Map<serde_json::Value>) -> AppResult<()> {
        let list: Vec<String> = map_field(storage, "triggers")
            .and_then(|t| t.get(kind))
            .and_then(|l| match l {
                JValue::Array(a) => Some(a.iter().map(JValue::java_to_string).collect()),
                _ => None,
            })
            .unwrap_or_default();
        for trigger in list {
            let Some(dot) = trigger.rfind('.') else {
                return Err(AppError::Internal(anyhow::anyhow!("StringIndexOutOfBoundsException: begin 0, end -1, length {}", trigger.len())));
            };
            self.triggers.run(&trigger[..dot], &trigger[dot + 1..], app.unwrap_or(""), client.unwrap_or(""), args.clone()).await?;
        }
        Ok(())
    }

    // ── tables follow the definitions ──────────────────────────

    async fn evict_schema_caches(&self, cx: &Commons, unique_name: &str) {
        cx.evict_all(&format!("{unique_name}{STORAGE_SCHEMA}")).await;
        cx.evict_all(&format!("{unique_name}{STORAGE_SCHEMA_RESOLVED}")).await;
    }

    /// `readForTenant`: the storage merged as that client, live, no access check.
    async fn read_for_tenant(&self, name: &str, app: &str, client: &str) -> Option<JMap> {
        let storages = self.storages().ok()?;
        let cx = storages.commons();
        match cx.store.read(storages.kind(), name, app, client, client, false).await {
            Ok(r) => r.map(|r| r.entity.clone()),
            Err(e) => {
                tracing::warn!(name, app, client, error = %e, "storage read for a tenant failed");
                None
            }
        }
    }

    /// `StorageService.evictRecursively` / `evictDraft` after the base: the reference index,
    /// then the storage's tables and its forks' tables rebuilt.
    pub async fn after_evict(&self, cx: &Commons, app: &str, client: &str, name: &str) {
        cx.evict_all(STORAGE_REFERENCES).await;
        self.rebuild_tables(cx, app, client, name).await;
    }

    async fn rebuild_tables(&self, cx: &Commons, app: &str, client: &str, name: &str) {
        let Some(storage) = self.read_for_tenant(name, app, client).await else { return };
        let unique = str_field(&storage, "uniqueName").unwrap_or("null").to_string();
        self.evict_schema_caches(cx, &unique).await;
        self.data.reconcile(app, &storage, &applied_by()).await;
        let mut names = IndexSet::new();
        names.insert(name.to_string());
        let mut except = IndexSet::new();
        except.insert(unique);
        for fork in self.forks_with_own_table(cx, app, &names, &except).await {
            self.evict_schema_caches(cx, str_field(&fork, "uniqueName").unwrap_or("null")).await;
            self.data.reconcile(app, &fork, &applied_by()).await;
        }
    }

    async fn app_docs(&self, cx: &Commons, collection: &str, filter: mongodb::bson::Document, pojo: &overridable::pojo::Pojo) -> Vec<JMap> {
        match cx.backend().find(collection, Find::new(filter)).await {
            Ok(docs) => docs.iter().map(|d| decode_bson(pojo, d)).collect(),
            Err(e) => {
                tracing::error!(collection, error = %e, "could not read the app's documents");
                Vec::new()
            }
        }
    }

    /// Derived documents of these storages with a table of their own.
    async fn forks_with_own_table(&self, cx: &Commons, app: &str, names: &IndexSet<String>, except: &IndexSet<String>) -> Vec<JMap> {
        if names.is_empty() {
            return Vec::new();
        }
        let list: Vec<&String> = names.iter().collect();
        let docs = self.app_docs(cx, "storage", doc! {"appCode": app, "name": {"$in": list}}, &STORAGE).await;
        docs.into_iter()
            .filter(|s| {
                !blank(s.get("baseClientCode")) && !blank(s.get("uniqueName")) && !except.contains(str_field(s, "uniqueName").unwrap_or(""))
            })
            .collect()
    }

    /// `AbstractSchemaService.referencingClosure`: every schema of the app that changes when
    /// this one does, itself included.
    async fn referencing_closure(&self, cx: &Commons, app: &str, schema_name: &str) -> IndexSet<String> {
        if app.trim().is_empty() || schema_name.trim().is_empty() {
            return IndexSet::new();
        }
        let docs = self.app_docs(cx, "schema", doc! {"appCode": app}, &SCHEMA).await;
        let mut refs = HashMap::new();
        for d in &docs {
            if let Some(n) = str_field(d, "name") {
                refs.insert(n.to_string(), schema_refs::collect(d.get("definition")));
            }
        }
        schema_refs::referencing_closure(&refs, schema_name)
    }

    /// Storages whose definition mentions any of these schemas, every client's document.
    async fn storages_using(&self, cx: &Commons, app: &str, schemas: &IndexSet<String>) -> Vec<JMap> {
        if schemas.is_empty() {
            return Vec::new();
        }
        self.app_docs(cx, "storage", doc! {"appCode": app}, &STORAGE)
            .await
            .into_iter()
            .filter(|s| schema_refs::collect(s.get("schema")).iter().any(|r| schemas.contains(r)))
            .collect()
    }

    /// `StorageService.ensureClientOverrides`: a client that saved its own version of a
    /// schema gets its own (empty) document of every storage standing on it.
    pub async fn ensure_client_overrides(&self, cx: &Commons, ca: Option<&ContextAuthentication>, app: &str, client: &str, schema_name: &str) {
        let Some(ca) = ca else { return };
        let Ok(storages) = self.storages() else { return };
        let closure = self.referencing_closure(cx, app, schema_name).await;
        let mut seen = IndexSet::new();
        for s in self.storages_using(cx, app, &closure).await {
            if str_field(&s, "clientCode") == Some(client) {
                continue;
            }
            let Some(name) = str_field(&s, "name").map(str::to_string) else { continue };
            if !seen.insert(name.clone()) {
                continue;
            }
            let Some(resolved) = self.read_for_tenant(&name, app, client).await else { continue };
            if str_field(&resolved, "clientCode") == Some(client) {
                continue;
            }
            let copy = client_copy(&resolved, client);
            if let Err(e) = storages.create(ca, copy).await {
                tracing::error!(client, storage = name, app, schema = schema_name, error = %e, "Could not create the storage override");
            }
        }
    }

    /// `StorageService.reconcileForSchemaChange`: every storage standing on the schema (and
    /// on the schemas that stand on it), and their forks with tables of their own, rebuilt.
    pub async fn reconcile_for_schema_change(&self, cx: &Commons, app: &str, schema_name: &str) {
        let closure = self.referencing_closure(cx, app, schema_name).await;
        let using = self.storages_using(cx, app, &closure).await;
        let names: IndexSet<String> = using.iter().filter_map(|s| str_field(s, "name").map(str::to_string)).collect();
        let tables: IndexSet<String> = using.iter().filter_map(|s| str_field(s, "uniqueName").filter(|u| !u.trim().is_empty()).map(str::to_string)).collect();
        let forks = if using.is_empty() { Vec::new() } else { self.forks_with_own_table(cx, app, &names, &tables).await };
        for s in using.iter().chain(forks.iter()) {
            self.evict_schema_caches(cx, str_field(s, "uniqueName").unwrap_or("null")).await;
            self.data.reconcile(app, s, &applied_by()).await;
        }
    }

    /// `getTransportDependencies`: the storages the relations point at.
    pub fn transport_dependencies(e: &JMap) -> Vec<String> {
        let mut out = IndexSet::new();
        for r in map_field(e, "relations").map(|r| r.values().collect::<Vec<_>>()).unwrap_or_default() {
            if let Some(n) = r.as_object().and_then(|o| str_field(o, "storageName")).filter(|n| !n.trim().is_empty()) {
                out.insert(n.to_string());
            }
        }
        out.into_iter().collect()
    }

    /// `stripTransportDependencies`: a copy without relations, `None` when it has none.
    pub fn strip_transport_dependencies(e: &JMap) -> Option<JMap> {
        if map_field(e, "relations").is_none_or(|r| r.is_empty()) {
            return None;
        }
        let mut c = e.clone();
        c.insert("relations".into(), JValue::Null);
        Some(c)
    }
}

const SCHEMA_TYPES: [&str; 9] = ["INTEGER", "LONG", "FLOAT", "DOUBLE", "STRING", "OBJECT", "ARRAY", "BOOLEAN", "NULL"];

/// `Type.SchemaTypeAdapter.read`: the first `type` (in the order Gson reads the schema) that is
/// no `SchemaType` (`NUMBER` is read as `DOUBLE`, any case), as `SchemaType.valueOf` words it.
pub fn unknown_schema_type(schema: &serde_json::Value) -> Option<String> {
    use serde_json::Value;
    let check = |t: &str| -> Option<String> {
        let up = t.to_uppercase();
        let up = if up == "NUMBER" { "DOUBLE".to_string() } else { up };
        (!SCHEMA_TYPES.contains(&up.as_str())).then(|| format!("No enum constant com.fincity.nocode.kirun.engine.json.schema.type.SchemaType.{up}"))
    };
    let o = schema.as_object()?;
    for (k, v) in o {
        let found = match (k.as_str(), v) {
            ("type", Value::String(t)) => check(t),
            ("type", Value::Array(a)) => a.iter().filter_map(Value::as_str).find_map(check),
            ("properties" | "patternProperties" | "$defs", Value::Object(m)) => m.values().find_map(unknown_schema_type),
            ("anyOf" | "allOf" | "oneOf", Value::Array(a)) => a.iter().find_map(unknown_schema_type),
            ("items", Value::Array(a)) => a.iter().find_map(unknown_schema_type),
            ("not" | "contains" | "items" | "additionalProperties" | "additionalItems", Value::Object(_)) => unknown_schema_type(v),
            _ => None,
        };
        if found.is_some() {
            return found;
        }
    }
    None
}

/// The signed-in user's name for the migration journal (`system` without one).
fn applied_by() -> String {
    crate::editor::caller::current()
        .and_then(|ca| ca.user.user_name.clone())
        .unwrap_or_else(|| "system".into())
}

/// `clientCopy`: the resolved definition re-homed at the client.
fn client_copy(resolved: &JMap, client: &str) -> JMap {
    let mut c = resolved.clone();
    c.insert("baseClientCode".into(), resolved.get("clientCode").cloned().unwrap_or_default());
    c.insert("clientCode".into(), JValue::Str(client.into()));
    c.insert("published".into(), JValue::Null);
    c.insert("version".into(), JValue::Int(1));
    c.insert("id".into(), JValue::Null);
    c
}

fn reorder_relation(r: JMap) -> JMap {
    let mut out = JMap::new();
    for f in crate::editor::beans::STORAGE_RELATION.fields {
        if let Some(v) = r.get(f.name).filter(|v| !v.is_null()) {
            out.insert(f.name.to_string(), v.clone());
        }
    }
    out
}

/// `gson.toJsonTree(storage)`: the document's fields, nulls left out.
pub fn gson_of(e: &JMap) -> serde_json::Value {
    fn conv(v: &JValue) -> Option<serde_json::Value> {
        Some(match v {
            JValue::Null => return None,
            JValue::Object(m) => serde_json::Value::Object(m.iter().filter_map(|(k, x)| conv(x).map(|y| (k.clone(), y))).collect()),
            JValue::Array(a) => serde_json::Value::Array(a.iter().map(|x| conv(x).unwrap_or(serde_json::Value::Null)).collect()),
            other => serde_json::to_value(other).unwrap_or(serde_json::Value::Null),
        })
    }
    conv(&JValue::Object(e.clone())).unwrap_or(serde_json::Value::Null)
}

/// `StorageColumnDefinitionValidator.problems`.
pub fn column_problems(definitions: Option<&JMap>, schema: Option<&appdata::model::Schema>, relation_fields: &[String]) -> Vec<String> {
    use appdata::model::{MongoBsonType as B, MySqlColumnType as M, SchemaType as S};
    let mut out = Vec::new();
    let Some(defs) = definitions.filter(|d| !d.is_empty()) else { return out };
    let empty = IndexMap::new();
    let props = schema.and_then(|s| s.properties.as_ref()).unwrap_or(&empty);
    let fields_known = !props.is_empty() || !relation_fields.is_empty();
    let parsed = appdata::model::Storage::from_value(&crate::storage::defs::jvalue(&JValue::Object({
        let mut m = JMap::new();
        m.insert("columnDefinitions".into(), JValue::Object(defs.clone()));
        m
    })))
    .ok()
    .and_then(|s| s.column_definitions)
    .unwrap_or_default();
    let set = |t: &[S]| format!("[{}]", t.iter().map(|x| x.name()).collect::<Vec<_>>().join(", "));
    for (field, raw) in defs {
        if raw.is_null() {
            continue;
        }
        if fields_known && !props.contains_key(field) && !relation_fields.contains(field) {
            out.push(format!("{field}: no such field in this storage"));
            continue;
        }
        let types: Vec<S> = props.get(field).map(|p| p.allowed_types()).unwrap_or_default();
        let def = parsed.get(field).cloned().unwrap_or_default();
        out.extend(appdata::mysql::column::problems(field, def.mysql.as_ref(), fields_known));
        if let Some(t) = def.mysql.as_ref().and_then(|m| m.column_type) {
            let temporal = matches!(t, M::Date | M::Datetime | M::Time | M::Timestamp);
            if (temporal || t == M::Decimal) && !types.is_empty() && !types.contains(&S::String) {
                out.push(format!(
                    "{field}: {} is read back as text, so the schema has to declare this field a STRING. It declares {}, which would pass validation on the way in and fail it on the way out.",
                    t.name(),
                    set(&types)
                ));
            }
        }
        if let Some(mongo) = &def.mongo {
            match mongo.bson_type {
                None => {
                    if fields_known {
                        out.push(format!("{field}: mongo.bsonType is required when a mongo column definition is given"));
                    }
                }
                Some(_) if types.is_empty() => {}
                Some(b) => {
                    let name = match b {
                        B::Decimal128 => "DECIMAL128",
                        B::Long => "LONG",
                        B::Int => "INT",
                        B::Double => "DOUBLE",
                        B::Date => "DATE",
                        B::Boolean => "BOOLEAN",
                        B::String => "STRING",
                    };
                    match b {
                        B::Decimal128 | B::Date if !types.contains(&S::String) => out.push(format!(
                            "{field}: {name} is read back as text, so the schema has to declare this field a STRING. It declares {}.",
                            set(&types)
                        )),
                        B::Long | B::Int | B::Double if ![S::Integer, S::Long, S::Float, S::Double].iter().any(|n| types.contains(n)) => out.push(format!(
                            "{field}: {name} is read back as a number, so the schema has to declare this field a number. It declares {}.",
                            set(&types)
                        )),
                        B::Boolean if !types.contains(&S::Boolean) => {
                            out.push(format!("{field}: BOOLEAN needs the schema to declare this field a BOOLEAN, not {}", set(&types)))
                        }
                        B::String if !types.contains(&S::String) => {
                            out.push(format!("{field}: STRING needs the schema to declare this field a STRING, not {}", set(&types)))
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_names_are_java_shaped() {
        let n = unique_name(32, &[Some("MyApp"), Some("SYSTEM"), Some("Sales Deals!")]);
        // Java stops once 18 letters are in: "salesdeals" is cut to "salesde".
        assert!(n.starts_with("myapp_system_salesde_"), "{n}");
        let suffix = &n["myapp_system_salesde_".len()..];
        assert!(!suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
        // A missing part is skipped without its underscore; the parts stop near the limit.
        assert!(unique_name(32, &[Some("a"), None, Some("b")]).starts_with("a_b_"));
        let long = unique_name(32, &[Some("abcdefghijklmnopqrstuvwxyz"), Some("x")]);
        assert!(long.starts_with("abcdefghijklmnopqr_"), "{long}");
        assert_ne!(base36_uuid(), base36_uuid());
    }

    fn schema(s: &str) -> appdata::model::Schema {
        appdata::model::Schema::from_value(&appdata::Value::from_json(&serde_json::from_str(s).unwrap())).unwrap()
    }

    fn defs(s: &str) -> JMap {
        match overridable::json::parse(s.as_bytes()).unwrap() {
            JValue::Object(m) => m,
            _ => panic!(),
        }
    }

    #[test]
    fn column_definitions_are_checked_against_the_schema() {
        let sch = schema(r#"{"type":"OBJECT","properties":{"price":{"type":"INTEGER"},"name":{"type":"STRING"},"ok":{"type":"STRING"}}}"#);
        let p = column_problems(Some(&defs(r#"{"price":{"mysql":{"type":"DECIMAL","precision":10,"scale":2}}}"#)), Some(&sch), &[]);
        assert_eq!(p.len(), 1);
        assert!(p[0].starts_with("price: DECIMAL is read back as text"), "{p:?}");
        let p = column_problems(Some(&defs(r#"{"nope":{"mysql":{"type":"INT"}}}"#)), Some(&sch), &[]);
        assert_eq!(p, vec!["nope: no such field in this storage".to_string()]);
        let p = column_problems(Some(&defs(r#"{"price":{"mongo":{}},"name":{"mongo":{"bsonType":"LONG"}},"ok":{"mongo":{"bsonType":"BOOLEAN"}}}"#)), Some(&sch), &[]);
        assert_eq!(p.len(), 3, "{p:?}");
        let p = column_problems(Some(&defs(r#"{"price":{"mongo":{"bsonType":"DATE"}},"name":{"mongo":{"bsonType":"STRING"}}}"#)), Some(&sch), &[]);
        assert_eq!(p.len(), 1, "{p:?}");
        let p = column_problems(Some(&defs(r#"{"price":{"mongo":{"bsonType":"STRING"}},"ok":{"mongo":{"bsonType":"DECIMAL128"}}}"#)), Some(&sch), &[]);
        assert_eq!(p.len(), 1, "{p:?}");
        // A delta with no schema of its own: the field check is skipped.
        assert!(column_problems(Some(&defs(r#"{"anything":{"mongo":{}}}"#)), None, &[]).is_empty());
        assert!(column_problems(None, Some(&sch), &[]).is_empty());
        assert!(column_problems(Some(&defs(r#"{"owner":{"mysql":{"type":"VARCHAR","length":10}},"x":null}"#)), Some(&sch), &["owner".into()]).is_empty());
    }

    /// `StorageColumnDefinitionValidatorTest`.
    #[test]
    fn column_definitions_checked_against_the_schema_as_java_checks_them() {
        let order = schema(
            r#"{"type":"OBJECT","properties":{"price":{"type":"STRING","format":"DECIMAL"},"quantity":{"type":"INTEGER"},
                "placedAt":{"type":"STRING","format":"DATETIME"}}}"#,
        );
        let empty = schema("{}");
        let check = |field: &str, def: &str| column_problems(Some(&defs(&format!(r#"{{"{field}":{def}}}"#))), Some(&order), &[]);
        let any = |p: Vec<String>, needle: &str| p.iter().any(|x| x.contains(needle));
        // theMotivatingCase
        assert!(check("price", r#"{"mysql":{"type":"DECIMAL","precision":10,"scale":2}}"#).is_empty());
        // deltaWithoutSchema
        assert!(column_problems(Some(&defs(r#"{"price":{"mysql":{"type":"DECIMAL","precision":10,"scale":2}}}"#)), Some(&empty), &[]).is_empty());
        // deltaStillChecksTheDefinition
        assert!(any(column_problems(Some(&defs(r#"{"price":{"mysql":{"type":"DECIMAL"}}}"#)), Some(&empty), &[]), "precision and a scale"));
        // deltaMayOmitTheType
        assert!(column_problems(Some(&defs(r#"{"title":{"mysql":{"length":200}}}"#)), Some(&empty), &[]).is_empty());
        // wholeDefinitionNeedsAType
        assert!(any(check("price", r#"{"mysql":{"length":200}}"#), "mysql.type is required"));
        // unknownField
        assert!(any(check("prcie", r#"{"mysql":{"type":"DECIMAL","precision":10,"scale":2}}"#), "no such field"));
        // relationField
        let p = column_problems(Some(&defs(r#"{"customer":{"mysql":{"type":"CHAR","length":26}}}"#)), Some(&order), &["customer".into()]);
        assert!(p.is_empty(), "{p:?}");
        // decimalNeedsAStringField, temporalNeedsAStringField
        assert!(any(check("quantity", r#"{"mysql":{"type":"DECIMAL","precision":10,"scale":2}}"#), "read back as text"));
        assert!(any(check("quantity", r#"{"mysql":{"type":"DATETIME"}}"#), "read back as text"));
        // mongoDecimalNeedsAString
        assert!(check("price", r#"{"mongo":{"bsonType":"DECIMAL128"}}"#).is_empty());
        assert!(any(check("quantity", r#"{"mongo":{"bsonType":"DECIMAL128"}}"#), "read back as text"));
        // mongoLongNeedsANumber
        assert!(check("quantity", r#"{"mongo":{"bsonType":"LONG"}}"#).is_empty());
        assert!(any(check("price", r#"{"mongo":{"bsonType":"LONG"}}"#), "read back as a number"));
        // bsonTypeRequired
        assert!(any(check("price", r#"{"mongo":{}}"#), "mongo.bsonType is required"));
        // bothHalves
        let p = check("price", r#"{"mysql":{"type":"DECIMAL"},"mongo":{"bsonType":"BOOLEAN"}}"#);
        assert!(p.len() >= 2, "{p:?}");
        // empty
        assert!(column_problems(None, Some(&order), &[]).is_empty());
        assert!(column_problems(Some(&JMap::new()), Some(&order), &[]).is_empty());
    }

    #[test]
    fn unknown_schema_types_are_named() {
        let j = |s: &str| serde_json::from_str::<serde_json::Value>(s).unwrap();
        assert_eq!(unknown_schema_type(&j(r#"{"type":"OBJECT","properties":{"a":{"type":"number"},"b":{"type":["STRING","nope"]}}}"#)).as_deref(), Some("No enum constant com.fincity.nocode.kirun.engine.json.schema.type.SchemaType.NOPE"));
        assert!(unknown_schema_type(&j(r#"{"type":"OBJECT","items":[{"type":"STRING"}],"anyOf":[{"type":"LONG"}],"not":{"type":"NULL"}}"#)).is_none());
        assert!(unknown_schema_type(&j(r#"{"items":{"type":"X"}}"#)).is_some());
        assert!(unknown_schema_type(&j(r#"{"anyOf":[{"type":"X"}]}"#)).is_some());
        assert!(unknown_schema_type(&j(r#"{"$defs":{"a":{"type":"X"}}}"#)).is_some());
        assert!(unknown_schema_type(&j("[]")).is_none());
    }

    #[test]
    fn transport_dependencies_and_their_strip() {
        let e = defs(r#"{"relations":{"a":{"storageName":"users"},"b":{"storageName":"users"},"c":{"storageName":" "}}}"#);
        assert_eq!(StorageOps::transport_dependencies(&e), vec!["users".to_string()]);
        let s = StorageOps::strip_transport_dependencies(&e).unwrap();
        assert_eq!(s["relations"], JValue::Null);
        assert!(StorageOps::strip_transport_dependencies(&defs(r#"{"relations":{}}"#)).is_none());
        let c = client_copy(&defs(r#"{"id":"x","clientCode":"SYSTEM","version":4,"published":true}"#), "FIN");
        assert_eq!((c["baseClientCode"].clone(), c["clientCode"].clone(), c["version"].clone()), (JValue::from("SYSTEM"), JValue::from("FIN"), JValue::Int(1)));
        assert_eq!(gson_of(&defs(r#"{"a":null,"b":{"c":null,"d":[1,null]}}"#)), serde_json::json!({"b":{"d":[1,null]}}));
        assert_eq!(reorder_relation(defs(r#"{"updateConstraint":"NOTHING","storageName":"s","uniqueRelationId":"u"}"#)).keys().cloned().collect::<Vec<_>>(), vec!["uniqueRelationId", "storageName", "updateConstraint"]);
    }
}
