//! core-editor in process, on the in-memory store (`MemBackend`, `FakeDirectory`), with the
//! data side, the triggers and the schedule view's reads faked: the core kinds' hooks (name
//! rules, the storage table name, `validate`, the definition triggers, the table rebuilds, a
//! schema's storage overrides, the connection reads, the nested classes read as Jackson does)
//! and the controllers' own routes.
//!
//! Java tests ported here: the save half of `StorageOverrideChainIntegrationTest` (its
//! `MissingBaseLevel` cases and 7a1766ef6's read-only client included),
//! `StorageValidationIntegrationTest`, `CoreDraftableIntegrationTest`, the deletion half of
//! `DraftDataNamespaceIntegrationTest` (against a fake data side; `editor_local_stack` runs
//! it on the local Mongo), and the routes `PublishRouteRegistrationTest` names.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::Router;
use mongodb::bson::Document;
use overridable::backend::{FakeDirectory, MemBackend};
use overridable::json::{parse, to_compact};
use overridable::pojo::{str_field, Pojo};
use overridable::write::persist::to_document;
use overridable::write::router::CallerSource;
use overridable::{JMap, JValue, Store};
use parking_lot::Mutex;
use platform::cache::{CacheService, LocalCaches};
use platform::error::{AppError, AppResult};
use platform::security::{ContextAuthentication, ContextUser};
use tower::ServiceExt;

use super::billing::BillingSecurity;
use super::caller::{EditorCallers, Resolver};
use super::routes::{router, with_layers, CoreEditor};
use super::schedules::ScheduleSources;
use super::storage::{DataStores, Triggers};
use super::{state, Parts};
use crate::context::RequestContext;
use crate::docs::{EVENT_DEFINITION, SCHEMA, STORAGE};
use crate::error::CoreError;
use crate::repos::{FoundSchema, SchemaSource};
use crate::storage::defs::Catalog;

const SYSTEM: &str = "SYSTEM";
const APP: &str = "testapp";
const MID: &str = "LZCLA";

// ── fakes ───────────────────────────────────────────────────────────

fn all_for(object: &str) -> Vec<String> {
    ["CREATE", "READ", "UPDATE", "DELETE"].iter().map(|m| format!("Authorities.{object}_{m}")).collect()
}

fn everything() -> Vec<String> {
    ["Function", "Schema", "Storage", "Connection", "Template", "Notification", "EventDefinition", "EventAction", "Workflow", "Action", "Application", "Transport"]
        .iter()
        .flat_map(|o| all_for(o))
        .collect()
}

fn auth_for(client: &str, authorities: &[String]) -> ContextAuthentication {
    ContextAuthentication {
        user: ContextUser { id: 7, client_id: 1, user_name: Some(format!("test-{client}")), string_authorities: authorities.to_vec() },
        authenticated: true,
        logged_in_from_client_id: 1,
        logged_in_from_client_code: Some(client.to_string()),
        client_type_code: Some(if client == SYSTEM { "SYS" } else { "BUS" }.to_string()),
        client_code: Some(client.to_string()),
        client_level_type: None,
        access_token: Some("test-token".into()),
        url_client_code: Some(client.to_string()),
        url_app_code: Some(APP.to_string()),
    }
}

fn anonymous() -> ContextAuthentication {
    ContextAuthentication { client_code: Some(SYSTEM.into()), ..Default::default() }
}

/// `x-test-client` signs in as that client with `x-test-auth` (every authority by default);
/// `x-test-fail` is security refusing the token.
struct HeaderCallers;

#[async_trait]
impl CallerSource for HeaderCallers {
    async fn caller(&self, h: &HeaderMap) -> AppResult<ContextAuthentication> {
        let get = |n: &str| h.get(n).and_then(|v| v.to_str().ok()).map(str::to_string);
        if get("x-test-fail").is_some() {
            return Err(AppError::new(StatusCode::UNAUTHORIZED, "Unknown token"));
        }
        let Some(client) = get("x-test-client") else { return Ok(anonymous()) };
        let auths = match get("x-test-auth") {
            Some(a) => a.split(',').filter(|s| !s.is_empty()).map(str::to_string).collect(),
            None => everything(),
        };
        Ok(auth_for(&client, &auths))
    }
}

struct HeaderResolver;

#[async_trait]
impl Resolver for HeaderResolver {
    async fn caller(&self, h: &HeaderMap) -> AppResult<ContextAuthentication> {
        HeaderCallers.caller(h).await
    }
    async fn request_context(&self, _h: &HeaderMap) -> Option<Arc<RequestContext>> {
        Some(Arc::new(RequestContext::default()))
    }
}

struct NoSchemas;

#[async_trait]
impl SchemaSource for NoSchemas {
    async fn find(&self, _namespace: Option<&str>, _name: &str) -> Result<Option<Arc<FoundSchema>>, CoreError> {
        Ok(None)
    }
    async fn filter(&self, _name: &str) -> Result<Vec<String>, CoreError> {
        Ok(Vec::new())
    }
}

#[derive(Default)]
struct FakeCatalog {
    app_data: Mutex<Option<appdata::model::Connection>>,
}

#[async_trait]
impl Catalog for FakeCatalog {
    async fn storage(&self, _: &str, _: &str, _: &str) -> Result<Option<appdata::model::Storage>, CoreError> {
        Ok(None)
    }
    async fn connection(&self, _: &str, _: &str, _: &str, _: &str) -> Result<Option<appdata::model::Connection>, CoreError> {
        Ok(self.app_data.lock().clone())
    }
    async fn raw_connection(&self, _: &str, _: &str, _: &str) -> Result<Option<appdata::model::Connection>, CoreError> {
        Ok(None)
    }
    async fn all_app_data(&self, _: &str, _: &str) -> Result<Vec<appdata::model::Connection>, CoreError> {
        Ok(self.app_data.lock().clone().into_iter().collect())
    }
    async fn storages_referencing(&self, _: &str, _: &str) -> Result<Vec<String>, CoreError> {
        Ok(Vec::new())
    }
    async fn storage_names(&self, _: &str) -> Result<Vec<String>, CoreError> {
        Ok(Vec::new())
    }
    async fn event_definition(&self, _: &str, _: &str, _: &str) -> Result<Option<JMap>, CoreError> {
        Ok(None)
    }
    async fn schema_source(&self, _: &str, _: &str) -> Result<Arc<dyn SchemaSource>, CoreError> {
        Ok(Arc::new(NoSchemas))
    }
}

/// The data side: what it was asked to do.
#[derive(Default)]
struct FakeData {
    calls: Mutex<Vec<String>>,
    /// The databases the app-data servers hold, with their rows.
    tenants: Mutex<Vec<(String, i64)>>,
}

impl FakeData {
    fn calls(&self) -> Vec<String> {
        self.calls.lock().clone()
    }
    fn clear(&self) {
        self.calls.lock().clear();
    }
}

#[async_trait]
impl DataStores for FakeData {
    async fn reconcile(&self, app: &str, storage: &JMap, _by: &str) {
        self.calls.lock().push(format!("reconcile {app} {} {}", str_field(storage, "clientCode").unwrap_or(""), str_field(storage, "uniqueName").unwrap_or("")));
    }
    async fn drop_draft_storage(&self, app: &str, client: &str, storage: &JMap) -> Result<bool, String> {
        self.calls.lock().push(format!("drop draft {app} {client} {}", str_field(storage, "uniqueName").unwrap_or("")));
        Ok(true)
    }
    async fn drop_draft_data(&self, app: &str, client: &str) -> Result<bool, String> {
        self.calls.lock().push(format!("drop draft data {app} {client}"));
        Ok(true)
    }
    async fn estimated_row_count(&self, _: &str, _: &str) -> i64 {
        3
    }
    async fn tenant_databases(&self) -> (Vec<super::purge::TenantDb>, Vec<String>) {
        let dbs = self
            .tenants
            .lock()
            .iter()
            .map(|(name, _)| super::purge::TenantDb { backend: super::purge::TenantBackend::Mongo, server: "default".into(), conn: None, name: name.clone() })
            .collect();
        (dbs, Vec::new())
    }
    async fn tenant_rows(&self, db: &super::purge::TenantDb) -> Result<i64, String> {
        Ok(self.tenants.lock().iter().find(|(n, _)| *n == db.name).map(|(_, r)| *r).unwrap_or(0))
    }
    async fn drop_tenant_database(&self, db: &super::purge::TenantDb) -> Result<bool, String> {
        self.calls.lock().push(format!("drop database {}", db.name));
        self.tenants.lock().retain(|(n, _)| *n != db.name);
        Ok(true)
    }
}

/// The core MySQL schema: `core_tokens` has a CLIENT_CODE, `core_things` a CLIENT_CODE and an
/// APP_CODE; rows are (table, client, app).
#[derive(Default)]
struct FakeRows {
    rows: Mutex<Vec<(&'static str, String, String)>>,
}

impl FakeRows {
    fn matching(&self, table: &str, column: &str, value: &str) -> usize {
        self.rows.lock().iter().filter(|r| Self::hit(r, table, column, value)).count()
    }
    fn hit(r: &(&'static str, String, String), table: &str, column: &str, value: &str) -> bool {
        r.0 == table && if column == "CLIENT_CODE" { r.1 == value } else { r.2 == value }
    }
}

#[async_trait]
impl super::purge::RowStore for FakeRows {
    async fn schema(&self) -> anyhow::Result<String> {
        Ok("core".into())
    }
    async fn tables_with(&self, column: &str) -> anyhow::Result<Vec<String>> {
        Ok(if column == "CLIENT_CODE" { vec!["core_things".into(), "core_tokens".into()] } else { vec!["core_things".into()] })
    }
    async fn count(&self, table: &str, column: &str, value: &str) -> anyhow::Result<u64> {
        Ok(self.matching(table, column, value) as u64)
    }
    async fn delete(&self, table: &str, column: &str, value: &str) -> anyhow::Result<u64> {
        let n = self.matching(table, column, value);
        self.rows.lock().retain(|r| !Self::hit(r, table, column, value));
        Ok(n as u64)
    }
}

/// The collections the purge's document store lists (the in-memory store has no listing).
const PURGE_COLLECTIONS: [&str; 5] = ["function", "storage", "version", "connection", "system.views"];

#[derive(Default)]
struct FakeTriggers {
    calls: Mutex<Vec<(String, Vec<String>)>>,
    fail: Mutex<bool>,
}

#[async_trait]
impl Triggers for FakeTriggers {
    async fn run(&self, namespace: &str, name: &str, _app: &str, _client: &str, args: kirun::Map<serde_json::Value>) -> AppResult<()> {
        self.calls.lock().push((format!("{namespace}.{name}"), args.keys().cloned().collect()));
        if *self.fail.lock() {
            return Err(AppError::new(StatusCode::BAD_REQUEST, "trigger refused"));
        }
        Ok(())
    }
}

struct FakeSchedules;

#[async_trait]
impl ScheduleSources for FakeSchedules {
    async fn copies(&self, _app: &str, _name: &str) -> Vec<JMap> {
        vec![
            obj(r#"{"id":"e1","name":"nightly","clientCode":"SYSTEM","schedule":{"cron":"0 9 * * *","perClient":true}}"#),
            obj(r#"{"id":"e2","name":"nightly","clientCode":"FIN","baseClientCode":"SYSTEM","schedule":{"enabled":false}}"#),
        ]
    }
    async fn writers(&self, _app: &str) -> Vec<String> {
        vec!["SYSTEM".into(), "ACME".into()]
    }
    async fn visible_among(&self, own: &str, _app: &str, candidates: &[String]) -> Result<Vec<String>, AppError> {
        let mut out: Vec<String> = candidates.to_vec();
        if !out.iter().any(|c| c == own) {
            out.push(own.into());
        }
        Ok(out)
    }
    async fn latest_runs(&self, _app: &str, _name: &str, clients: &[String]) -> HashMap<String, crate::event_runs::EventRun> {
        clients
            .iter()
            .filter(|c| c.as_str() == "SYSTEM")
            .map(|c| (c.clone(), crate::event_runs::EventRun { client_code: Some(c.clone()), duration_ms: Some(1500), ..Default::default() }))
            .collect()
    }
    async fn effective_schedule(&self, _app: &str, _name: &str, client: &str) -> Option<crate::scheduler::EventSchedule> {
        let cron = Some("0 9 * * *".to_string());
        match client {
            "FIN" => Some(crate::scheduler::EventSchedule { cron, enabled: Some(false), per_client: Some(true), ..Default::default() }),
            "BAD" => Some(crate::scheduler::EventSchedule { cron: Some("nonsense".into()), ..Default::default() }),
            "NONE" => None,
            _ => Some(crate::scheduler::EventSchedule { cron, per_client: Some(true), ..Default::default() }),
        }
    }
    async fn draft(&self, _ca: &ContextAuthentication, copy_id: &str) -> Option<(i64, Option<crate::scheduler::EventSchedule>)> {
        (copy_id == "e1").then(|| (2, Some(crate::scheduler::EventSchedule { cron: Some("0 10 * * *".into()), ..Default::default() })))
    }
    async fn client_name(&self, client: &str) -> Option<String> {
        (client == "SYSTEM").then(|| "System".into())
    }
}

#[derive(Default)]
struct FakeBilling {
    charges: Mutex<Vec<String>>,
}

#[async_trait]
impl BillingSecurity for FakeBilling {
    async fn instructions(&self, _action: &str) -> anyhow::Result<serde_json::Value> {
        Ok(serde_json::json!([{"configClientId": 1, "appId": 2, "billedClientId": 3, "appCode": APP, "billedClientCode": SYSTEM}]))
    }
    async fn charge(&self, body: String) -> anyhow::Result<serde_json::Value> {
        self.charges.lock().push(body);
        Ok(serde_json::Value::Bool(true))
    }
}

// ── the harness ─────────────────────────────────────────────────────

struct Env {
    mem: Arc<MemBackend>,
    dir: Arc<FakeDirectory>,
    cache: CacheService,
    st: Arc<CoreEditor>,
    router: Router,
    data: Arc<FakeData>,
    triggers: Arc<FakeTriggers>,
    catalog: Arc<FakeCatalog>,
    billing: Arc<FakeBilling>,
    rows: Arc<FakeRows>,
    probe: Arc<LocalCaches<String, u32>>,
}

struct Answer {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Answer {
    fn json(&self) -> JValue {
        parse(&self.body).unwrap_or(JValue::Null)
    }
    fn obj(&self) -> JMap {
        self.json().as_object().cloned().unwrap_or_default()
    }
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
    fn message(&self) -> String {
        str_field(&self.obj(), "message").unwrap_or("").to_string()
    }
    /// Java's text: a coded error's `debugMessage` after its bundle key, else `message`.
    fn java(&self) -> String {
        let o = self.obj();
        match str_field(&o, "code") {
            Some(_) => {
                let d = str_field(&o, "debugMessage").unwrap_or("");
                match d.strip_prefix('[').and_then(|r| r.split_once("] ")) {
                    Some((_, t)) => t.to_string(),
                    None => d.to_string(),
                }
            }
            None => self.message(),
        }
    }
    fn code(&self) -> String {
        str_field(&self.obj(), "code").unwrap_or("").to_string()
    }
    fn id(&self) -> String {
        str_field(&self.obj(), "id").unwrap_or_else(|| panic!("no id in {}", self.text())).to_string()
    }
}

fn obj(s: &str) -> JMap {
    match parse(s.as_bytes()).unwrap() {
        JValue::Object(m) => m,
        other => panic!("not an object: {other:?}"),
    }
}

fn s(v: &str) -> JValue {
    JValue::Str(v.into())
}

fn path<'a>(m: &'a JMap, keys: &[&str]) -> Option<&'a JValue> {
    let mut cur = m.get(keys[0])?;
    for k in &keys[1..] {
        cur = cur.as_object()?.get(*k)?;
    }
    Some(cur)
}

fn env() -> Env {
    env_with(true)
}

/// The editor with `[connections] block_private_targets` as given.
fn env_with(block_private_targets: bool) -> Env {
    let mem = Arc::new(MemBackend::new());
    let dir = Arc::new(FakeDirectory::new());
    dir.chain(&[SYSTEM]);
    let cache = CacheService::new("cmn", "evictionChannel", None).unwrap();
    let store = Store::with_parts(mem.clone(), dir.clone(), &cache).unwrap();
    let data = Arc::new(FakeData::default());
    let triggers = Arc::new(FakeTriggers::default());
    let catalog = Arc::new(FakeCatalog::default());
    let billing = Arc::new(FakeBilling::default());
    let rows = Arc::new(FakeRows::default());
    let parts = Parts {
        catalog: catalog.clone(),
        kirun_schemas: crate::state::Builtins::kirun_schemas(),
        core_schemas: crate::state::Builtins::core_schemas(),
        data: data.clone(),
        triggers: triggers.clone(),
        schedules: Arc::new(|_, _| Arc::new(FakeSchedules) as Arc<dyn ScheduleSources>),
        billing: billing.clone(),
        redis: None,
        eviction_channel: "evictionChannel".into(),
        block_private_targets,
        purge_docs: Some(Arc::new(super::purge::BackendDocs {
            name: "core".into(),
            backend: mem.clone(),
            collections: PURGE_COLLECTIONS.iter().map(|c| c.to_string()).collect(),
        })),
        purge_rows: Some(rows.clone()),
    };
    let callers: Arc<dyn CallerSource> = Arc::new(EditorCallers { inner: Arc::new(HeaderCallers) });
    let st = state(store, cache.clone(), callers, parts);
    let router = with_layers(router(st.clone()), Arc::new(HeaderResolver));
    let probe = cache.family();
    Env { mem, dir, cache, st, router, data, triggers, catalog, billing, rows, probe }
}

impl Env {
    async fn send(&self, method: &str, uri: &str, client: Option<&str>, headers: &[(&str, &str)], body: &str) -> Answer {
        let mut req = Request::builder().method(method).uri(uri).header("content-type", "application/json");
        if let Some(c) = client {
            req = req.header("x-test-client", c);
        }
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let resp = self.router.clone().oneshot(req.body(Body::from(body.to_string())).unwrap()).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec();
        Answer { status, headers, body }
    }

    async fn call(&self, method: &str, uri: &str, body: &str) -> Answer {
        self.send(method, uri, Some(SYSTEM), &[], body).await
    }

    async fn as_client(&self, client: &str, method: &str, uri: &str, body: &str) -> Answer {
        self.send(method, uri, Some(client), &[], body).await
    }

    async fn warm(&self, cache_name: &str) {
        self.probe.insert(cache_name, "k".to_string(), 1).await;
    }

    async fn is_warm(&self, cache_name: &str) -> bool {
        self.probe.get(cache_name, &"k".to_string()).await.is_some()
    }

    fn insert_raw(&self, pojo: &Pojo, collection: &str, json: &str) -> String {
        let m = obj(json);
        let id = self.mem.put_raw(collection, to_document(pojo, &m, None, &[]));
        overridable::bson_conv::to_java_string(&id).java_to_string()
    }

    fn raw(&self, collection: &str, id: &str) -> Document {
        self.mem
            .all(collection)
            .into_iter()
            .find(|d| overridable::bson_conv::to_java_string(d.get("_id").unwrap()).java_to_string() == id)
            .expect("stored document")
    }

    /// `storedStorage(client, base, schema)`: a storage as Java's fixtures insert it.
    fn stored_storage(&self, client: &str, base: Option<&str>, extra: &str) -> String {
        let base = base.map(|b| format!(r#","baseClientCode":"{b}""#)).unwrap_or_default();
        self.insert_raw(
            &STORAGE,
            "storage",
            &format!(r#"{{"name":"testStorage","appCode":"{APP}","clientCode":"{client}","version":1,"uniqueName":"testapp_{}_teststorage"{base}{extra}}}"#, client.to_lowercase()),
        )
    }
}

fn to_body(m: &JMap) -> String {
    to_compact(&JValue::Object(m.clone()))
}

// ── functions and schemas ───────────────────────────────────────────

#[tokio::test]
async fn function_and_schema_names_come_from_their_definitions() {
    let e = env();
    for base in ["functions", "schemas"] {
        let no_def = e.call("POST", &format!("/api/core/{base}"), r#"{"appCode":"testapp","clientCode":"SYSTEM"}"#).await;
        assert_eq!(no_def.status, StatusCode::INTERNAL_SERVER_ERROR, "{base}");
        let no_ns = e.call("POST", &format!("/api/core/{base}"), r#"{"appCode":"testapp","clientCode":"SYSTEM","definition":{"name":"f"}}"#).await;
        assert_eq!((no_ns.status, no_ns.java()), (StatusCode::BAD_REQUEST, "Namespace or name missing".into()));
        assert!(!no_ns.code().is_empty(), "coded: {}", no_ns.text());
        let made = e.call("POST", &format!("/api/core/{base}"), r#"{"appCode":"testapp","clientCode":"SYSTEM","definition":{"namespace":"Ns","name":"f"}}"#).await;
        assert_eq!(made.status, StatusCode::OK, "{base}: {}", made.text());
        assert_eq!(str_field(&made.obj(), "name"), Some("Ns.f"));
        let mut renamed = made.obj();
        renamed.insert("definition".into(), JValue::Object(obj(r#"{"namespace":"Ns","name":"g"}"#)));
        let r = e.call("PUT", &format!("/api/core/{base}/{}", made.id()), &to_body(&renamed)).await;
        assert_eq!((r.status, r.java()), (StatusCode::BAD_REQUEST, "Namespace or name cannot be changed".into()), "{base}");
        let mut nameless = made.obj();
        nameless.insert("definition".into(), JValue::Object(obj(r#"{"name":"f"}"#)));
        let r = e.call("PUT", &format!("/api/core/{base}/{}", made.id()), &to_body(&nameless)).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{base}");
        let mut same = made.obj();
        same.insert("definition".into(), JValue::Object(obj(r#"{"namespace":"Ns","name":"f","steps":{}}"#)));
        let r = e.call("PUT", &format!("/api/core/{base}/{}", made.id()), &to_body(&same)).await;
        assert_eq!(r.status, StatusCode::OK, "{base}: {}", r.text());
        assert_eq!(r.obj().get("version"), Some(&JValue::Int(2)));
        let stale = e.call("PUT", &format!("/api/core/{base}/{}", made.id()), &to_body(&same)).await;
        assert_eq!((stale.status, stale.java()), (StatusCode::PRECONDITION_FAILED, "Please reload to get the new version before making changes.".into()));
        assert_eq!(e.call("DELETE", &format!("/api/core/{base}/{}", made.id()), "").await.text(), "true");
    }
}

#[tokio::test]
async fn a_derived_schema_updates_without_restating_its_name() {
    let e = env();
    e.dir.chain(&[SYSTEM, MID]);
    e.call("POST", "/api/core/schemas", r#"{"appCode":"testapp","clientCode":"SYSTEM","definition":{"namespace":"Ns","name":"s","type":"OBJECT"}}"#).await;
    let d = e.as_client(MID, "POST", "/api/core/schemas", r#"{"appCode":"testapp","clientCode":"LZCLA","baseClientCode":"SYSTEM","definition":{"namespace":"Ns","name":"s","type":"OBJECT"}}"#).await;
    assert_eq!(d.status, StatusCode::OK, "{}", d.text());
    let mut body = d.obj();
    body.insert("definition".into(), JValue::Object(obj(r#"{"description":"mine"}"#)));
    let r = e.as_client(MID, "PUT", &format!("/api/core/schemas/{}", d.id()), &to_body(&body)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
}

/// `AbstractFunctionServiceUpdateTest`: a client's function copy updates (and so publishes its
/// draft) without restating the name its difference leaves out; a rename is still refused, and
/// a base function must name both parts.
#[tokio::test]
async fn a_derived_function_updates_without_restating_its_name() {
    let e = env();
    e.dir.chain(&[SYSTEM, MID]);
    let base = e.call("POST", "/api/core/functions", r#"{"appCode":"testapp","clientCode":"SYSTEM","definition":{"namespace":"ZzOvr","name":"zzOvrFn","steps":{}}}"#).await;
    assert_eq!(base.status, StatusCode::OK, "{}", base.text());
    let d = e
        .as_client(MID, "POST", "/api/core/functions", r#"{"appCode":"testapp","clientCode":"LZCLA","baseClientCode":"SYSTEM","definition":{"namespace":"ZzOvr","name":"zzOvrFn","steps":{}}}"#)
        .await;
    assert_eq!(d.status, StatusCode::OK, "{}", d.text());
    let mut body = d.obj();
    body.insert("definition".into(), JValue::Object(obj(r#"{"steps":{"a":{"statementName":"a","namespace":"System","name":"Print"}}}"#)));
    let r = e.as_client(MID, "PUT", &format!("/api/core/functions/{}", d.id()), &to_body(&body)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let mut body = r.obj();
    body.insert("definition".into(), JValue::Object(obj(r#"{"name":"other"}"#)));
    let r = e.as_client(MID, "PUT", &format!("/api/core/functions/{}", d.id()), &to_body(&body)).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "a rename is refused: {}", r.text());
    let mut root = base.obj();
    root.insert("definition".into(), JValue::Object(obj(r#"{"name":"zzOvrFn"}"#)));
    let r = e.call("PUT", &format!("/api/core/functions/{}", base.id()), &to_body(&root)).await;
    assert_eq!((r.status, r.java()), (StatusCode::BAD_REQUEST, "Namespace or name missing".to_string()));
}

// ── storages: the table name and validate ───────────────────────────

const OBJECT_SCHEMA: &str = r#"{"type":"OBJECT","properties":{"title":{"type":"STRING"}}}"#;

fn storage_body(name: &str, extra: &str) -> String {
    format!(r#"{{"name":"{name}","appCode":"testapp","clientCode":"SYSTEM","schema":{OBJECT_SCHEMA}{extra}}}"#)
}

#[tokio::test]
async fn a_new_storage_gets_a_table_name_of_its_own() {
    let e = env();
    e.warm("x").await;
    let r = e.call("POST", "/api/core/storages", &storage_body("freshStorage", "")).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let u = str_field(&r.obj(), "uniqueName").unwrap().to_string();
    // Java's uniqueName stops near 18 letters: "freshstorage" is cut to "fresh".
    assert!(u.starts_with("testapp_system_fresh_"), "{u}");
}

#[tokio::test]
async fn storage_validation_at_save() {
    let e = env();
    let schema_with = |t: &str| format!(r#"{{"name":"probe{t}","appCode":"testapp","clientCode":"SYSTEM","schema":{{"type":"OBJECT","properties":{{"price":{{"type":"{t}"}}}}}}}}"#);
    // StorageValidationIntegrationTest.
    let bad = e.call("POST", "/api/core/storages", &schema_with("NOTATYPE")).await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST, "{}", bad.text());
    assert!(bad.java().starts_with("The storage schema is not valid."), "{}", bad.text());
    assert!(bad.java().contains("NOTATYPE"), "{}", bad.text());
    assert_eq!(bad.code(), "CORE.INVALID_STORAGE_SCHEMA");
    assert!(bad.message().starts_with("The storage's schema is not valid: "), "{}", bad.message());
    assert_eq!(e.call("POST", "/api/core/storages", &schema_with("NUMBER")).await.status, StatusCode::OK, "NUMBER is KIRun's alias of DOUBLE");
    assert_eq!(e.call("POST", "/api/core/storages", &schema_with("STRING")).await.status, StatusCode::OK);

    let not_object = e.call("POST", "/api/core/storages", r#"{"name":"p2","appCode":"testapp","clientCode":"SYSTEM","schema":{"type":"STRING"}}"#).await;
    assert_eq!((not_object.status, not_object.java()), (StatusCode::BAD_REQUEST, "Storage schema should always be of type Object".into()));
    assert_eq!(not_object.code(), "CORE.STORAGE_SCHEMA_ALWAYS_OBJECT");
    let bad_name = e.call("POST", "/api/core/storages", r#"{"name":"p3","appCode":"testapp","clientCode":"SYSTEM","schema":{"type":"OBJECT","properties":{"bad.name":{"type":"STRING"}}}}"#).await;
    assert_eq!(bad_name.status, StatusCode::BAD_REQUEST);
    assert!(bad_name.java().starts_with("Invalid column definition."), "{}", bad_name.text());
    assert_eq!(bad_name.code(), "CORE.INVALID_COLUMN_DEFINITION");
    let bad_column = e.call("POST", "/api/core/storages", &storage_body("p4", r#","columnDefinitions":{"nope":{"mysql":{"type":"INT"}}}"#)).await;
    assert_eq!(bad_column.java(), "Invalid column definition. nope: no such field in this storage");
    let collision = e.call("POST", "/api/core/storages", &storage_body("p5", r#","relations":{"title":{"storageName":"x"}}"#)).await;
    assert_eq!((collision.status, collision.java()), (StatusCode::BAD_REQUEST, "Storage schema field title already exists".into()));
    assert_eq!(collision.message(), "The field title appears twice in the storage's schema.");
    let missing = e.call("POST", "/api/core/storages", &storage_body("p6", r#","relations":{"owner":{"storageName":"users"}}"#)).await;
    assert_eq!((missing.java(), missing.code()), ("No storage found with name users".into(), "CORE.NO_STORAGE_FOUND_WITH_NAME".into()));
    let unreadable = e.call("POST", "/api/core/storages", &storage_body("p7", r#","relations":{"owner":{"relationType":"SIDEWAYS"}}"#)).await;
    assert_eq!(unreadable.status, StatusCode::BAD_REQUEST, "an unknown enum constant is an unreadable body");
    // Spring's refusal, answered by the definition library (coded once it codes them).
    assert!(unreadable.message().starts_with("Please try again. A server error") || unreadable.code().starts_with("COMMON."), "{}", unreadable.text());

    e.call("POST", "/api/core/storages", &storage_body("users", "")).await;
    let related = e.call("POST", "/api/core/storages", &storage_body("p8", r#","relations":{"owner":{"storageName":"users","relationType":"TO_ONE","junk":1}}"#)).await;
    assert_eq!(related.status, StatusCode::OK, "{}", related.text());
    let rel = path(&related.obj(), &["relations", "owner"]).and_then(JValue::as_object).unwrap().clone();
    assert!(str_field(&rel, "uniqueRelationId").is_some_and(|u| u.starts_with("testapp_system_p8_own_")));
    assert_eq!(rel.get("deleteConstraint"), Some(&s("NOTHING")));
    assert!(!rel.contains_key("junk"));
    assert_eq!(
        rel.keys().cloned().collect::<Vec<_>>(),
        vec!["uniqueRelationId", "storageName", "relationType", "deleteConstraint", "updateConstraint"]
    );
}

// ── StorageOverrideChainIntegrationTest: creating a client override ──

#[tokio::test]
async fn a_client_override_keeps_the_base_table_and_stores_no_name() {
    let e = env();
    e.dir.chain(&[SYSTEM, MID]);
    let base = e.stored_storage(SYSTEM, None, r#","schema":{"type":["OBJECT"]}"#);
    let created = e
        .as_client(MID, "POST", "/api/core/storages", r#"{"name":"testStorage","appCode":"testapp","clientCode":"LZCLA","baseClientCode":"SYSTEM","version":1,"schema":{"type":["OBJECT"]}}"#)
        .await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text());
    let read = e.as_client(MID, "GET", &format!("/api/core/storages/{}", created.id()), "").await;
    assert_eq!(str_field(&read.obj(), "uniqueName"), Some("testapp_system_teststorage"));
    assert!(e.raw("storage", &created.id()).get("uniqueName").is_none(), "the stored delta must not carry the base's name");
    assert_ne!(base, created.id());
}

#[tokio::test]
async fn an_app_level_storage_is_overridden_only_with_write_access() {
    let e = env();
    e.dir.chain(&[SYSTEM, MID]);
    e.stored_storage(SYSTEM, None, r#","schema":{"type":["OBJECT"]},"isAppLevel":true"#);
    e.dir.set(|a| a.write_access = false);
    let r = e
        .as_client(MID, "POST", "/api/core/storages", r#"{"name":"testStorage","appCode":"testapp","clientCode":"LZCLA","baseClientCode":"SYSTEM","version":1}"#)
        .await;
    assert_eq!((r.status, r.java(), r.code()), (StatusCode::FORBIDDEN, "Cannot change a storage which is app level.".into(), "CORE.STORAGE_IS_APP_LEVEL".into()));
}

/// `overrideForReadOnlyClientRefused` (Java commit 7a1766ef6): a manager cannot create an
/// override for a client without write access to the app.
#[tokio::test]
async fn no_override_may_be_created_for_a_client_without_write_access_to_the_app() {
    let e = env();
    e.dir.chain(&[SYSTEM, MID]);
    e.stored_storage(SYSTEM, None, r#","schema":{"type":["OBJECT"]}"#);
    e.dir.set(|a| {
        a.write_by.insert((APP.into(), MID.into()), false);
    });
    let body = format!(r#"{{"name":"testStorage","appCode":"{APP}","clientCode":"{MID}","baseClientCode":"{SYSTEM}","version":1,"schema":{{"type":["OBJECT"]}}}}"#);
    let r = e.call("POST", "/api/core/storages", &body).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.text());
    assert!(e.mem.all("storage").iter().all(|d| d.get_str("clientCode") != Ok(MID)), "nothing stored for the read-only client");
    // With write access on both sides the same create goes through.
    e.dir.set(|a| a.write_by.clear());
    assert_eq!(e.call("POST", "/api/core/storages", &body).await.status, StatusCode::OK);
}

// ── StorageOverrideChainIntegrationTest: a base client that holds no copy ──

const LEAF: &str = "LEAFCL";

#[tokio::test]
async fn a_copy_diffs_against_the_next_level_that_has_one_and_follows_it() {
    let e = env();
    e.dir.chain(&[SYSTEM, MID, LEAF]);
    e.dir.hierarchy(LEAF, &[LEAF, MID, SYSTEM]);
    e.dir.hierarchy(MID, &[MID, SYSTEM]);
    let base = e.stored_storage(SYSTEM, None, r#","schema":{"type":["OBJECT"],"fromRoot":"r"}"#);
    let created = e
        .as_client(
            LEAF,
            "POST",
            "/api/core/storages",
            &format!(r#"{{"name":"testStorage","appCode":"{APP}","clientCode":"{LEAF}","baseClientCode":"{MID}","version":1,"schema":{{"type":["OBJECT"],"fromRoot":"r","fromLeaf":"l"}}}}"#),
        )
        .await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text());
    let stored = e.raw("storage", &created.id());
    assert_eq!(stored.get_str("baseClientCode").ok(), Some(MID));
    assert_eq!(stored.get_document("schema").unwrap(), &mongodb::bson::doc! {"fromLeaf": "l"}, "only the leaf's own change is stored");
    assert_eq!(str_field(&created.obj(), "uniqueName"), Some("testapp_system_teststorage"), "and it shares the base's table");

    let mut root = e.raw("storage", &base);
    root.get_document_mut("schema").unwrap().insert("laterFromRoot", "r2");
    e.mem.put_raw("storage", root);
    let read = read_as(&e, LEAF, &created.id()).await;
    assert_eq!(path(&read, &["schema", "fromLeaf"]), Some(&s("l")));
    assert_eq!(path(&read, &["schema", "laterFromRoot"]), Some(&s("r2")), "a later change from SYSTEM reaches the leaf");
}

#[tokio::test]
async fn the_base_client_is_the_manager_or_the_app_owner_and_none_for_the_owner() {
    let e = env();
    e.dir.hierarchy(LEAF, &[LEAF, MID, SYSTEM]);
    e.dir.hierarchy(MID, &[MID, SYSTEM]);
    let of = |app: &'static str, client: &'static str| {
        let svc = e.st.storages.clone();
        async move { svc.base_client_code_of(app, client).await.unwrap() }
    };
    assert_eq!(of(APP, LEAF).await.as_deref(), Some(MID));
    assert_eq!(of(APP, MID).await.as_deref(), Some(SYSTEM));
    assert_eq!(of(APP, SYSTEM).await, None);

    // An app owned by MID: a client managed by SYSTEM directly stands on MID.
    e.dir.set(|a| {
        a.apps.insert(
            "midapp".into(),
            Some(overridable::backend::ExplicitApp { app_access_type: Some("ANY".into()), client_code: Some(MID.into()), explicit_owner_client_code: None }),
        );
    });
    e.dir.hierarchy("OTHER", &["OTHER", SYSTEM]);
    assert_eq!(of("midapp", "OTHER").await.as_deref(), Some(MID));
    assert_eq!(of("midapp", LEAF).await.as_deref(), Some(MID));
    assert_eq!(of("midapp", MID).await, None);
    // An unknown app has no base client.
    e.dir.set(|a| {
        a.apps.insert("nosuchapp".into(), None);
    });
    assert_eq!(of("nosuchapp", LEAF).await, None);
}

// ── StorageOverrideChainIntegrationTest: saving a derived storage ───

async fn read_as(e: &Env, client: &str, id: &str) -> JMap {
    let r = e.as_client(client, "GET", &format!("/api/core/storages/{id}"), "").await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    r.obj()
}

async fn update_as(e: &Env, client: &str, body: &JMap) -> Answer {
    let id = str_field(body, "id").unwrap().to_string();
    e.as_client(client, "PUT", &format!("/api/core/storages/{id}"), &to_body(body)).await
}

#[tokio::test]
async fn a_client_overriding_something_other_than_the_schema_can_still_save() {
    let e = env();
    e.dir.chain(&[SYSTEM, MID]);
    e.stored_storage(SYSTEM, None, r#","schema":{"title":"t"},"textIndexFields":["title"]"#);
    let mid = e.stored_storage(MID, Some(SYSTEM), r#","indexes":{"byTitle":{"fields":[{"fieldName":"title","direction":"ASC"}],"unique":false}}"#);
    let mut read = read_as(&e, MID, &mid).await;
    read.insert("indexes".into(), JValue::Object(obj(r#"{"byTitleTwo":{"fields":[{"fieldName":"title"}]}}"#)));
    let saved = update_as(&e, MID, &read).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text());
    assert!(path(&saved.obj(), &["indexes", "byTitleTwo"]).is_some());
}

#[tokio::test]
async fn a_derived_clients_own_column_definition_survives_the_save() {
    let e = env();
    e.dir.chain(&[SYSTEM, MID]);
    e.stored_storage(SYSTEM, None, r#","schema":{"title":"t"},"columnDefinitions":{"title":{"mysql":{"type":"DECIMAL","precision":19,"scale":4}}}"#);
    let mid = e.stored_storage(MID, Some(SYSTEM), "");
    let mut read = read_as(&e, MID, &mid).await;
    read.insert("columnDefinitions".into(), JValue::Object(obj(r#"{"title":{"mysql":{"type":"DECIMAL","precision":10,"scale":2}}}"#)));
    let r = update_as(&e, MID, &read).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let after = read_as(&e, MID, &mid).await;
    assert_eq!(path(&after, &["columnDefinitions", "title", "mysql", "precision"]), Some(&JValue::Int(10)));
}

#[tokio::test]
async fn the_retention_numbers_survive_an_update_and_can_be_cleared() {
    let e = env();
    let base = e.stored_storage(SYSTEM, None, r#","schema":{"title":"t"}"#);
    let mut read = read_as(&e, SYSTEM, &base).await;
    read.insert("versionRetentionDays".into(), JValue::Int(7));
    read.insert("versionRetentionCount".into(), JValue::Int(4));
    assert_eq!(update_as(&e, SYSTEM, &read).await.status, StatusCode::OK);
    let mut after = read_as(&e, SYSTEM, &base).await;
    assert_eq!((after.get("versionRetentionDays"), after.get("versionRetentionCount")), (Some(&JValue::Int(7)), Some(&JValue::Int(4))));
    after.insert("versionRetentionDays".into(), JValue::Null);
    assert_eq!(update_as(&e, SYSTEM, &after).await.status, StatusCode::OK);
    assert!(read_as(&e, SYSTEM, &base).await.get("versionRetentionDays").is_none_or(JValue::is_null), "clearing must reach the document");
}

#[tokio::test]
async fn a_derived_storage_with_relations_can_be_saved() {
    let e = env();
    e.dir.chain(&[SYSTEM, MID]);
    e.insert_raw(&STORAGE, "storage", r#"{"name":"categories","appCode":"testapp","clientCode":"SYSTEM","version":1,"uniqueName":"testapp_system_categories","schema":{"label":"l"}}"#);
    e.stored_storage(SYSTEM, None, r#","schema":{"title":"t"}"#);
    let mid = e.stored_storage(MID, Some(SYSTEM), r#","relations":{"category":{"storageName":"categories","relationType":"TO_ONE","fieldName":"_id","deleteConstraint":"NOTHING"}}"#);
    let mut read = read_as(&e, MID, &mid).await;
    if let Some(JValue::Object(r)) = read.get_mut("relations") {
        if let Some(JValue::Object(c)) = r.get_mut("category") {
            c.insert("deleteConstraint".into(), s("RESTRICT"));
        }
    }
    let saved = update_as(&e, MID, &read).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text());
}

#[tokio::test]
async fn a_base_storage_without_an_object_type_is_still_refused() {
    let e = env();
    let base = e.stored_storage(SYSTEM, None, r#","schema":{"type":"STRING"}"#);
    let mut read = read_as(&e, SYSTEM, &base).await;
    read.insert("schema".into(), JValue::Object(obj(r#"{"type":"STRING"}"#)));
    assert_eq!(update_as(&e, SYSTEM, &read).await.status, StatusCode::BAD_REQUEST);
    let unknown = e.call("PUT", "/api/core/storages/000000000000000000000000", &storage_body("x", r#","uniqueName":"u","id":"000000000000000000000000""#)).await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND, "an update reads the storage first: {}", unknown.text());
}

// ── storages: triggers, caches, tables ──────────────────────────────

#[tokio::test]
async fn storage_writes_run_their_triggers_and_rebuild_their_tables() {
    let e = env();
    let made = e
        .call("POST", "/api/core/storages", &storage_body("trig", r#","triggers":{"BEFORE_UPDATE_STORAGE":["Ns.before"],"AFTER_UPDATE_STORAGE":["Ns.after"],"BEFORE_DELETE_STORAGE":["Ns.beforeDel"],"AFTER_DELETE_STORAGE":["Ns.afterDel"]}"#))
        .await;
    assert_eq!(made.status, StatusCode::OK, "{}", made.text());
    let unique = str_field(&made.obj(), "uniqueName").unwrap().to_string();
    assert!(e.data.calls().iter().any(|c| c.starts_with("reconcile testapp SYSTEM")), "{:?}", e.data.calls());
    e.data.clear();

    for c in [format!("{unique}_index_creation"), format!("{unique}_table_creation"), "storageReferences".into(), format!("{unique}_storage_schema")] {
        e.warm(&c).await;
    }
    let mut body = made.obj();
    body.insert("isAudited".into(), JValue::Bool(true));
    let r = e.call("PUT", &format!("/api/core/storages/{}", made.id()), &to_body(&body)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let calls = e.triggers.calls.lock().clone();
    assert_eq!(calls[0], ("Ns.before".to_string(), vec!["existing".to_string(), "creating".to_string()]));
    assert_eq!(calls[1], ("Ns.after".to_string(), vec!["existing".to_string(), "created".to_string()]));
    for c in [format!("{unique}_index_creation"), format!("{unique}_table_creation"), "storageReferences".into(), format!("{unique}_storage_schema")] {
        assert!(!e.is_warm(&c).await, "{c}");
    }
    assert_eq!(e.data.calls(), vec![format!("reconcile testapp SYSTEM {unique}")]);

    *e.triggers.fail.lock() = true;
    let mut again = r.obj();
    again.insert("isAudited".into(), JValue::Bool(false));
    let refused = e.call("PUT", &format!("/api/core/storages/{}", made.id()), &to_body(&again)).await;
    assert_eq!((refused.status, refused.message()), (StatusCode::BAD_REQUEST, "trigger refused".into()));
    *e.triggers.fail.lock() = false;

    e.data.clear();
    let d = e.call("DELETE", &format!("/api/core/storages/{}", made.id()), "").await;
    assert_eq!(d.text(), "true");
    let calls = e.triggers.calls.lock().clone();
    assert!(calls.iter().any(|c| c.0 == "Ns.beforeDel") && calls.iter().any(|c| c.0 == "Ns.afterDel"));
    assert!(e.data.calls().contains(&format!("drop draft testapp SYSTEM {unique}")), "{:?}", e.data.calls());
}

#[tokio::test]
async fn a_trigger_without_a_namespace_fails_the_write() {
    let e = env();
    let made = e.call("POST", "/api/core/storages", &storage_body("trig2", r#","triggers":{"BEFORE_DELETE_STORAGE":["nodot"]}"#)).await;
    let d = e.call("DELETE", &format!("/api/core/storages/{}", made.id()), "").await;
    assert_eq!(d.status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn deleting_a_client_override_that_shares_its_base_table_keeps_the_draft_data() {
    let e = env();
    e.dir.chain(&[SYSTEM, MID]);
    e.stored_storage(SYSTEM, None, r#","schema":{"type":["OBJECT"]}"#);
    let o = e
        .as_client(MID, "POST", "/api/core/storages", r#"{"name":"testStorage","appCode":"testapp","clientCode":"LZCLA","baseClientCode":"SYSTEM","version":1}"#)
        .await;
    assert_eq!(o.status, StatusCode::OK, "{}", o.text());
    e.data.clear();
    let d = e.as_client(MID, "DELETE", &format!("/api/core/storages/{}", o.id()), "").await;
    assert_eq!(d.text(), "true");
    assert!(!e.data.calls().iter().any(|c| c.starts_with("drop draft")), "{:?}", e.data.calls());
}

#[tokio::test]
async fn a_schema_save_rebuilds_the_storages_on_it_and_gives_a_client_its_own_copy() {
    let e = env();
    e.dir.chain(&[SYSTEM, MID]);
    e.insert_raw(&SCHEMA, "schema", r#"{"name":"App.Order","appCode":"testapp","clientCode":"SYSTEM","version":1,"definition":{"namespace":"App","name":"Order","type":"OBJECT"}}"#);
    e.insert_raw(&SCHEMA, "schema", r#"{"name":"App.Wrap","appCode":"testapp","clientCode":"SYSTEM","version":1,"definition":{"namespace":"App","name":"Wrap","properties":{"o":{"ref":"App.Order"}}}}"#);
    e.stored_storage(SYSTEM, None, r#","schema":{"ref":"App.Wrap"}"#);
    // The schema is overridden by the client: the client gets its own storage document.
    let r = e
        .as_client(MID, "POST", "/api/core/schemas", r#"{"appCode":"testapp","clientCode":"LZCLA","baseClientCode":"SYSTEM","definition":{"namespace":"App","name":"Order","type":"OBJECT","description":"mine"}}"#)
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let copies: Vec<JMap> = e.mem.all("storage").iter().map(|d| overridable::pojo::decode_bson(&STORAGE, d)).collect();
    assert!(copies.iter().any(|c| str_field(c, "clientCode") == Some(MID) && str_field(c, "baseClientCode") == Some(SYSTEM)), "{copies:?}");
    assert!(e.data.calls().iter().any(|c| c == "reconcile testapp SYSTEM testapp_system_teststorage"), "{:?}", e.data.calls());

    e.data.clear();
    let id = str_field(&r.obj(), "id").unwrap().to_string();
    let d = e.as_client(MID, "DELETE", &format!("/api/core/schemas/{id}"), "").await;
    assert_eq!(d.text(), "true");
    assert!(e.data.calls().iter().any(|c| c.starts_with("reconcile testapp")), "a deleted schema rebuilds too: {:?}", e.data.calls());
}

// ── connections ─────────────────────────────────────────────────────

#[tokio::test]
async fn connection_reads_hide_what_the_caller_may_not_see() {
    let e = env();
    e.dir.chain(&[SYSTEM, MID]);
    let c = e
        .call("POST", "/api/core/connections", r#"{"name":"mail","appCode":"testapp","clientCode":"SYSTEM","connectionType":"MAIL","connectionSubType":"SMTP","connectionDetails":{"user":"u","password":"p","nested":{"apiKey":"k","keep":1}}}"#)
        .await;
    assert_eq!(c.status, StatusCode::OK, "{}", c.text());
    let id = c.id();
    let full = e.call("GET", &format!("/api/core/connections/{id}"), "").await.obj();
    assert_eq!(path(&full, &["connectionDetails", "password"]), Some(&s(SECRET_MASK)), "masked even for a caller who may update it");
    assert_eq!(path(&full, &["connectionDetails", "user"]), Some(&s("u")));
    let reader = all_for("Connection").into_iter().filter(|a| a.ends_with("_READ")).collect::<Vec<_>>().join(",");
    let r = e.send("GET", &format!("/api/core/connections/{id}"), Some(SYSTEM), &[("x-test-auth", &reader)], "").await.obj();
    assert!(path(&r, &["connectionDetails", "password"]).is_none());
    assert!(path(&r, &["connectionDetails", "nested", "apiKey"]).is_none());
    assert_eq!(path(&r, &["connectionDetails", "nested", "keep"]), Some(&JValue::Int(1)));
    let other = e.as_client(MID, "GET", &format!("/api/core/connections/{id}"), "").await.obj();
    assert!(other.get("connectionDetails").is_none(), "another client sees no details");

    let inside = e
        .call("POST", "/api/core/connections", r#"{"name":"rest","appCode":"testapp","clientCode":"SYSTEM","connectionType":"REST_API","connectionDetails":{"url":"http://127.0.0.1:8080/x"}}"#)
        .await;
    assert_eq!(inside.status, StatusCode::BAD_REQUEST, "{}", inside.text());
    let bad_type = e.call("POST", "/api/core/connections", r#"{"name":"x","appCode":"testapp","clientCode":"SYSTEM","connectionType":"NOPE"}"#).await;
    assert_eq!(bad_type.status, StatusCode::BAD_REQUEST);
    let mut body = full.clone();
    body.insert("connectionDetails".into(), JValue::Object(obj(r#"{"host":"localhost"}"#)));
    let r = e.call("PUT", &format!("/api/core/connections/{id}"), &to_body(&body)).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "an update is checked too: {}", r.text());
}

const LOCAL_SMTP: &str = r#"{"name":"mail","appCode":"testapp","clientCode":"SYSTEM","connectionType":"MAIL","connectionSubType":"SMTP","connectionDetails":{"mailProps":{"mail.smtp.host":"localhost","mail.smtp.port":"16040"}}}"#;

#[tokio::test]
async fn a_private_smtp_host_is_refused_while_the_guard_is_on() {
    let e = env();
    let r = e.call("POST", "/api/core/connections", LOCAL_SMTP).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", r.text());
    assert!(r.text().contains("CORE.CONNECTION_TARGET_REFUSED"), "{}", r.text());
    let on = env_with(true).call("POST", "/api/core/connections", LOCAL_SMTP).await;
    assert_eq!(on.status, StatusCode::BAD_REQUEST, "the default is the guard on");
}

#[tokio::test]
async fn a_private_smtp_host_can_be_saved_with_the_guard_off() {
    let e = env_with(false);
    let c = e.call("POST", "/api/core/connections", LOCAL_SMTP).await;
    assert_eq!(c.status, StatusCode::OK, "{}", c.text());
    let mut body = c.obj();
    body.insert("connectionDetails".into(), JValue::Object(obj(r#"{"mailProps":{"mail.smtp.host":"127.0.0.1","mail.smtp.port":"16040"}}"#)));
    let u = e.call("PUT", &format!("/api/core/connections/{}", c.id()), &to_body(&body)).await;
    assert_eq!(u.status, StatusCode::OK, "{}", u.text());
    assert_eq!(path(&u.obj(), &["connectionDetails", "mailProps", "mail.smtp.host"]), Some(&s("127.0.0.1")));
    // The other save rules stay.
    let file = e
        .call("POST", "/api/core/connections", r#"{"name":"f","appCode":"testapp","clientCode":"SYSTEM","connectionType":"REST_API","connectionDetails":{"baseUrl":"file:///etc/passwd"}}"#)
        .await;
    assert_eq!(file.status, StatusCode::BAD_REQUEST, "{}", file.text());
}

#[tokio::test]
async fn a_connection_keeps_its_consent_auth() {
    let e = env();
    let plain = e.call("POST", "/api/core/connections", r#"{"name":"plain","appCode":"testapp","clientCode":"SYSTEM","connectionType":"REST_API","connectionDetails":{"baseUrl":"https://api.example.com"}}"#).await;
    assert_eq!(plain.status, StatusCode::OK, "{}", plain.text());
    assert!(plain.obj().get("consentAuth").is_none(), "absent stays absent: {}", plain.text());

    let gate = "Authorities.ADZUMPTWO.ROLE_Account_MANAGE or Authorities.ROLE_Owner";
    let c = e
        .call(
            "POST",
            "/api/core/connections",
            &format!(r#"{{"name":"oa","appCode":"testapp","clientCode":"SYSTEM","connectionType":"REST_API","connectionSubType":"REST_API_OAUTH2","consentAuth":"{gate}","connectionDetails":{{"grantType":"AUTHORIZATION_CODE"}}}}"#),
        )
        .await;
    assert_eq!(c.status, StatusCode::OK, "{}", c.text());
    assert_eq!(c.obj().get("consentAuth"), Some(&s(gate)));
    let read = e.call("GET", &format!("/api/core/connections/{}", c.id()), "").await.obj();
    assert_eq!(read.get("consentAuth"), Some(&s(gate)));

    let mut body = read.clone();
    body.insert("consentAuth".into(), s("Authorities.ROLE_Owner"));
    let u = e.call("PUT", &format!("/api/core/connections/{}", c.id()), &to_body(&body)).await;
    assert_eq!(u.status, StatusCode::OK, "{}", u.text());
    assert_eq!(u.obj().get("consentAuth"), Some(&s("Authorities.ROLE_Owner")), "an update changes it");
    let mut body = u.obj();
    body.shift_remove("consentAuth");
    let cleared = e.call("PUT", &format!("/api/core/connections/{}", c.id()), &to_body(&body)).await;
    assert!(cleared.obj().get("consentAuth").is_none(), "an update without it clears it: {}", cleared.text());
}

const SECRET_MASK: &str = connections::connection::SECRET_MASK;

/// The stored connection's detail at `keys`, as text.
fn stored_detail(e: &Env, id: &str, keys: &[&str]) -> Option<String> {
    let raw = overridable::bson_conv::doc_to_j(&e.raw("connection", id));
    let mut all = vec!["connectionDetails"];
    all.extend_from_slice(keys);
    path(&raw, &all).and_then(JValue::as_str).map(str::to_string)
}

#[tokio::test]
async fn connection_secrets_never_leave_and_a_masked_save_keeps_them() {
    let e = env_with(false);
    let c = e
        .call(
            "POST",
            "/api/core/connections",
            r#"{"name":"mail","appCode":"testapp","clientCode":"SYSTEM","connectionType":"MAIL","connectionSubType":"SMTP",
               "connectionDetails":{"userName":"u","password":"fake-pw","mailProps":{"mail.smtp.host":"smtp.example.com","mail.password":"fake-mail-pw"}}}"#,
        )
        .await;
    assert_eq!(c.status, StatusCode::OK, "{}", c.text());
    assert!(!c.text().contains("fake-"), "the create's answer: {}", c.text());
    let id = c.id();

    // Every read: by id, the eager list, the draft view.
    let read = e.call("GET", &format!("/api/core/connections/{id}"), "").await;
    assert!(!read.text().contains("fake-"), "{}", read.text());
    let read = read.obj();
    assert_eq!(path(&read, &["connectionDetails", "password"]), Some(&s(SECRET_MASK)));
    assert_eq!(path(&read, &["connectionDetails", "mailProps", "mail.password"]), Some(&s(SECRET_MASK)));
    assert_eq!(path(&read, &["connectionDetails", "mailProps", "mail.smtp.host"]), Some(&s("smtp.example.com")));
    let list = e.call("GET", "/api/core/connections?appCode=testapp&eager=true", "").await;
    assert_eq!(list.status, StatusCode::OK, "{}", list.text());
    assert!(list.text().contains(SECRET_MASK) && !list.text().contains("fake-"), "{}", list.text());

    // Saved back as read, with another field edited: the stored secrets stay.
    let mut body = read.clone();
    body.insert("connectionDetails".into(), JValue::Object(obj(
        r#"{"userName":"v","password":"********","mailProps":{"mail.smtp.host":"smtp2.example.com","mail.password":""}}"#,
    )));
    let u = e.call("PUT", &format!("/api/core/connections/{id}"), &to_body(&body)).await;
    assert_eq!(u.status, StatusCode::OK, "{}", u.text());
    assert!(!u.text().contains("fake-"), "{}", u.text());
    assert_eq!(stored_detail(&e, &id, &["password"]).as_deref(), Some("fake-pw"));
    assert_eq!(stored_detail(&e, &id, &["mailProps", "mail.password"]).as_deref(), Some("fake-mail-pw"));
    assert_eq!(stored_detail(&e, &id, &["userName"]).as_deref(), Some("v"));
    assert_eq!(stored_detail(&e, &id, &["mailProps", "mail.smtp.host"]).as_deref(), Some("smtp2.example.com"));

    // A new value replaces; a secret the body leaves out stays.
    let mut body = u.obj();
    body.insert("connectionDetails".into(), JValue::Object(obj(r#"{"userName":"v","password":"fake-new-pw","mailProps":{"mail.smtp.host":"smtp2.example.com"}}"#)));
    let u = e.call("PUT", &format!("/api/core/connections/{id}"), &to_body(&body)).await;
    assert_eq!(u.status, StatusCode::OK, "{}", u.text());
    assert_eq!(stored_detail(&e, &id, &["password"]).as_deref(), Some("fake-new-pw"));
    assert_eq!(stored_detail(&e, &id, &["mailProps", "mail.password"]).as_deref(), Some("fake-mail-pw"));

    // A draft of the masked read keeps the real secrets in the draft row, answers them masked,
    // and publishes without losing them.
    let mut draft = u.obj();
    draft.insert("connectionDetails".into(), JValue::Object(obj(r#"{"userName":"drafted","password":"********","mailProps":{"mail.smtp.host":"smtp2.example.com","mail.password":"********"}}"#)));
    let d = e.call("PUT", &format!("/api/core/connections/{id}?draft=true"), &to_body(&draft)).await;
    assert_eq!(d.status, StatusCode::OK, "{}", d.text());
    assert!(!d.text().contains("fake-"), "{}", d.text());
    let row = e.mem.all("draft").into_iter().find(|r| r.get_str("objectId") == Ok(id.as_str())).expect("draft row");
    let content = overridable::bson_conv::doc_to_j(row.get_document("content").unwrap());
    assert_eq!(path(&content, &["connectionDetails", "password"]), Some(&s("fake-new-pw")), "the draft runs with the real secret");
    assert_eq!(path(&content, &["connectionDetails", "mailProps", "mail.password"]), Some(&s("fake-mail-pw")));
    let drafted = e.call("GET", &format!("/api/core/connections/{id}?draft=true"), "").await;
    assert!(!drafted.text().contains("fake-") && drafted.text().contains("drafted"), "{}", drafted.text());
    let p = e.call("POST", &format!("/api/core/connections/{id}/publish"), "").await;
    assert_eq!(p.status, StatusCode::OK, "{}", p.text());
    assert!(!p.text().contains("fake-"), "{}", p.text());
    assert_eq!(stored_detail(&e, &id, &["password"]).as_deref(), Some("fake-new-pw"));
    assert_eq!(stored_detail(&e, &id, &["userName"]).as_deref(), Some("drafted"));

    // The history keeps the real values for the draft merge, and answers them masked.
    assert!(e.mem.all("version").iter().any(|v| format!("{v}").contains("fake-new-pw")));
    let history = e.call("POST", &format!("/api/core/versions/{id}/query"), "{}").await;
    assert_eq!(history.status, StatusCode::OK, "{}", history.text());
    assert!(history.text().contains(SECRET_MASK) && !history.text().contains("fake-"), "{}", history.text());
    let one = path(&history.obj(), &["content"]).and_then(|c| match c {
        JValue::Array(a) => a.first().and_then(JValue::as_object).and_then(|v| str_field(v, "id")).map(str::to_string),
        _ => None,
    });
    let v = e.call("GET", &format!("/api/core/versions/{}", one.expect("a version row")), "").await;
    assert!(v.text().contains(SECRET_MASK) && !v.text().contains("fake-"), "{}", v.text());
    let guess = r#"{"condition":{"field":"object.connectionDetails.password","operator":"EQUALS","value":"fake-new-pw"}}"#;
    let guessed = e.call("POST", &format!("/api/core/versions/{id}/query"), guess).await;
    assert_eq!(path(&guessed.obj(), &["totalElements"]), Some(&JValue::Int(0)), "{}", guessed.text());

    // No list filter or sort on the details.
    let guessed = e.call("GET", "/api/core/connections?appCode=testapp&connectionDetails.password=fake-new-pw", "").await;
    assert_eq!(path(&guessed.obj(), &["totalElements"]), Some(&JValue::Int(0)), "{}", guessed.text());
    let sorted = e.call("GET", "/api/core/connections?appCode=testapp&sort=connectionDetails.password", "").await;
    assert_eq!(path(&sorted.obj(), &["totalElements"]), Some(&JValue::Int(0)), "{}", sorted.text());
    let named = e.call("GET", "/api/core/connections?appCode=testapp&name=mail", "").await;
    assert_eq!(path(&named.obj(), &["totalElements"]), Some(&JValue::Int(1)), "{}", named.text());

    // A new connection never stores the mask as a secret.
    let copy = e
        .call(
            "POST",
            "/api/core/connections",
            r#"{"name":"copy","appCode":"testapp","clientCode":"SYSTEM","connectionType":"MAIL","connectionSubType":"SMTP",
               "connectionDetails":{"userName":"u","password":"********","mailProps":{"mail.smtp.host":"smtp.example.com"}}}"#,
        )
        .await;
    assert_eq!(copy.status, StatusCode::OK, "{}", copy.text());
    assert_eq!(stored_detail(&e, &copy.id(), &["password"]), None);
    assert_eq!(stored_detail(&e, &copy.id(), &["userName"]).as_deref(), Some("u"));
}

// ── the other kinds ─────────────────────────────────────────────────

#[tokio::test]
async fn the_other_kinds_read_their_classes_as_java_does() {
    let e = env();
    let n = e.call("POST", "/api/core/notifications", r#"{"name":"n","appCode":"testapp","clientCode":"SYSTEM","channelTemplates":{"email":{"templateParts":{"en":{"s":"x"}},"x":1}}}"#).await;
    assert_eq!(n.status, StatusCode::OK, "{}", n.text());
    assert_eq!(n.obj().get("notificationType"), Some(&s("INFO")));
    assert_eq!(path(&n.obj(), &["channelTemplates", "email"]).and_then(JValue::as_object).map(|m| m.len()), Some(1));
    let internal = e.send("GET", "/api/core/notifications/internal/n?appCode=testapp&clientCode=SYSTEM&urlClientCode=SYSTEM", None, &[], "").await;
    assert_eq!(str_field(&internal.obj(), "name"), Some("n"));
    let none = e.send("GET", "/api/core/notifications/internal/zz?appCode=testapp&clientCode=SYSTEM&urlClientCode=SYSTEM", None, &[], "").await;
    assert_eq!((none.status, none.body.len()), (StatusCode::OK, 0));
    assert_eq!(e.send("GET", "/api/core/notifications/internal/n?appCode=testapp", None, &[], "").await.status, StatusCode::BAD_REQUEST);
    let mut nb = n.obj();
    nb.insert("channelEnabled".into(), JValue::Object(obj(r#"{"email":false}"#)));
    let r = e.call("PUT", &format!("/api/core/notifications/{}", n.id()), &to_body(&nb)).await;
    assert_eq!(path(&r.obj(), &["channelEnabled", "email"]), Some(&JValue::Bool(false)), "channelEnabled is copied on update");

    let w = e.call("POST", "/api/core/workflows", r#"{"name":"w","appCode":"testapp","clientCode":"SYSTEM"}"#).await;
    assert_eq!((w.status, w.java(), w.code()), (StatusCode::INTERNAL_SERVER_ERROR, "Workflow trigger is missing".into(), "CORE.WORKFLOW_TRIGGER_MISSING".into()));
    let w = e.call("POST", "/api/core/workflows", r#"{"name":"w","appCode":"testapp","clientCode":"SYSTEM","trigger":{"triggerType":"EVENT"},"steps":{"a":{"stepName":"a"}}}"#).await;
    assert_eq!(w.status, StatusCode::INTERNAL_SERVER_ERROR, "an abstract step class cannot be read");
    assert_eq!(w.code(), "COMMON.INTERNAL_ERROR", "{}", w.text());
    assert!(w.java().starts_with("Cannot construct instance of `com.fincity.saas.commons.core.model.WorkflowStep`"), "{}", w.text());
    let w = e.call("POST", "/api/core/workflows", r#"{"name":"w","appCode":"testapp","clientCode":"SYSTEM","trigger":{"triggerType":"EVENT","junk":1}}"#).await;
    assert_eq!(w.status, StatusCode::OK, "{}", w.text());
    assert_eq!(w.obj().get("trigger"), Some(&JValue::Object(obj(r#"{"triggerType":"EVENT","stepType":"TRIGGER"}"#))), "the step type is a getter Jackson writes");
    let mut wb = w.obj();
    wb.insert("startAuth".into(), s("Authorities.X"));
    wb.insert("trigger".into(), JValue::Object(obj(r#"{"triggerType":"ON_SCHEDULE"}"#)));
    let r = e.call("PUT", &format!("/api/core/workflows/{}", w.id()), &to_body(&wb)).await;
    assert_eq!((r.status, r.obj().get("startAuth")), (StatusCode::OK, Some(&s("Authorities.X"))), "{}", r.text());
    wb = r.obj();
    wb.insert("trigger".into(), JValue::Null);
    assert_eq!(e.call("PUT", &format!("/api/core/workflows/{}", w.id()), &to_body(&wb)).await.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(e.call("DELETE", &format!("/api/core/workflows/{}", w.id()), "").await.text(), "true");

    let a = e.call("POST", "/api/core/workflow/actions", r#"{"name":"a","appCode":"testapp","clientCode":"SYSTEM","functionNamespace":"N","functionName":"f","properties":{"p":"1"}}"#).await;
    let mut ab = a.obj();
    ab.insert("properties".into(), JValue::Object(obj(r#"{"p":"2"}"#)));
    let r = e.call("PUT", &format!("/api/core/workflow/actions/{}", a.id()), &to_body(&ab)).await;
    assert_eq!(path(&r.obj(), &["properties", "p"]), Some(&s("2")), "properties are copied on update");

    let ea = e.call("POST", "/api/core/eventActions", r#"{"name":"Ev","appCode":"testapp","clientCode":"SYSTEM","tasks":{"t":{"key":"t","type":"SEND_EMAIL","order":"2"}}}"#).await;
    assert_eq!(path(&ea.obj(), &["tasks", "t", "order"]), Some(&JValue::Int(2)));
    let ed = e.call("POST", "/api/core/eventDefinitions", r#"{"name":"Ev","appCode":"testapp","clientCode":"SYSTEM","schedule":{"cron":"0 * * * *","perClient":"true","x":1}}"#).await;
    assert_eq!(path(&ed.obj(), &["schedule"]), Some(&JValue::Object(obj(r#"{"cron":"0 * * * *","perClient":true}"#))));
    let t = e.call("POST", "/api/core/templates", r#"{"name":"t","appCode":"testapp","clientCode":"SYSTEM","templateParts":{"en":{"body":"B"}}}"#).await;
    let mut tb = t.obj();
    tb.insert("toExpression".into(), s("x"));
    let r = e.call("PUT", &format!("/api/core/templates/{}", t.id()), &to_body(&tb)).await;
    assert_eq!(r.obj().get("toExpression"), Some(&s("x")));
}

// ── CoreDraftableIntegrationTest ────────────────────────────────────

#[tokio::test]
async fn core_objects_are_draftable_and_publish_all() {
    let e = env();
    let stored = e.stored_storage(SYSTEM, None, r#","schema":{"type":"OBJECT","properties":{"title":{"type":"STRING"}}}"#);
    let mut draft = read_as(&e, SYSTEM, &stored).await;
    draft.insert("schema".into(), JValue::Object(obj(r#"{"type":"OBJECT","properties":{"title":{"type":"STRING"},"draftedField":{"type":"STRING"}}}"#)));
    let d = e.call("PUT", &format!("/api/core/storages/{stored}?draft=true"), &to_body(&draft)).await;
    assert_eq!(d.status, StatusCode::OK, "{}", d.text());
    assert_eq!(e.mem.all("draft").len(), 1);
    assert_eq!(e.mem.all("draft")[0].get_str("objectType"), Ok("STORAGE"));
    let live = read_as(&e, SYSTEM, &stored).await;
    assert!(path(&live, &["schema", "properties", "draftedField"]).is_none(), "the draft leaked into the live definition");
    let drafted = e.call("GET", &format!("/api/core/storages/{stored}?draft=true"), "").await.obj();
    assert!(path(&drafted, &["schema", "properties", "draftedField"]).is_some());

    let pending = e.call("GET", "/api/core/publish/app/testapp/pending?clientCode=SYSTEM", "").await.obj();
    assert_eq!(pending.keys().cloned().collect::<Vec<_>>(), vec!["STORAGE"]);
    let all = e.call("POST", "/api/core/publish/app/testapp?clientCode=SYSTEM", "").await.obj();
    assert_eq!((all.get("attempted"), all.get("published")), (Some(&JValue::Int(1)), Some(&JValue::Int(1))), "{all:?}");
    assert!(e.mem.all("draft").is_empty());
    let live = read_as(&e, SYSTEM, &stored).await;
    assert!(path(&live, &["schema", "properties", "draftedField"]).is_some(), "publish did not promote the draft");
}

#[tokio::test]
async fn every_draftable_core_kind_is_published_and_the_lists_are_javas() {
    let e = env();
    let names = |l: Vec<Arc<dyn overridable::write::AnyService>>| l.iter().map(|s| s.object_name().to_string()).collect::<Vec<_>>();
    assert_eq!(
        names(e.st.publish_services()),
        vec!["Storage", "Connection", "Template", "Notification", "EventDefinition", "EventAction", "Action", "Workflow", "Function", "Schema", "Filler"]
    );
    assert_eq!(
        names(e.st.deletion_services()),
        vec!["Action", "Template", "Storage", "Function", "Schema", "EventAction", "EventDefinition", "Filler", "Connection", "Transport", "Workflow"]
    );
}

// ── the commons routes ──────────────────────────────────────────────

#[tokio::test]
async fn transport_versions_and_the_app_wipe() {
    let e = env();
    let types = e.call("GET", "/api/core/transports/transportTypes", "").await;
    assert_eq!(types.json(), JValue::Array(["Schema", "Storage", "Function", "Template", "EventDefinition", "EventAction", "Filler"].iter().map(|t| s(t)).collect()));
    let f = e.call("POST", "/api/core/functions", r#"{"appCode":"testapp","clientCode":"SYSTEM","definition":{"namespace":"Ns","name":"f"}}"#).await;
    let v = e.call("POST", &format!("/api/core/versions/{}/query", f.id()), "{}").await;
    assert_eq!(v.obj()["content"].clone().as_object().is_none(), true);
    assert!(v.text().contains("\"objectType\" : \"FUNCTION\""), "{}", v.text());
    let json = e.call("POST", "/api/core/transports/internal/makeTransport", r#"{"appCode":"testapp","clientCode":"SYSTEM","fileType":"JSON"}"#).await;
    assert_eq!(json.status, StatusCode::OK, "{}", json.text());
    assert!(json.text().contains("\"objectType\" : \"Function\""));

    let fwd = [("x-forwarded-host", "localhost"), ("x-forwarded-port", "8080"), ("clientCode", SYSTEM), ("appCode", APP)];
    let none = e.send("DELETE", "/api/core?deleteAppCode=testapp", Some(SYSTEM), &[], "").await;
    assert_eq!(none.status, StatusCode::BAD_REQUEST, "the forwarded headers are required");
    let wiped = e.send("DELETE", "/api/core?deleteAppCode=testapp", Some(SYSTEM), &fwd, "").await;
    assert_eq!((wiped.status, wiped.text()), (StatusCode::OK, "true".to_string()));
    assert!(e.mem.all("function").is_empty());
    assert!(e.data.calls().contains(&"drop draft data testapp SYSTEM".to_string()), "{:?}", e.data.calls());
    e.data.clear();
    e.dir.set(|a| a.delete_access = false);
    let refused = e.send("DELETE", "/api/core?deleteAppCode=testapp", Some(SYSTEM), &fwd, "").await;
    assert_eq!(refused.status, StatusCode::OK);
    assert!(e.data.calls().is_empty(), "no access, no draft data dropped");
}

#[tokio::test]
async fn the_index_lists_every_type_in_order() {
    let e = env();
    e.call("POST", "/api/core/functions", r#"{"appCode":"testapp","clientCode":"SYSTEM","definition":{"namespace":"Ns","name":"f"}}"#).await;
    let idx = e.call("GET", "/api/core/index?appCode=testapp", "").await.obj();
    assert_eq!(
        idx.keys().cloned().collect::<Vec<_>>(),
        vec!["appCode", "clientCode", "storages", "schemas", "functions", "templates", "connections", "eventDefinitions", "eventActions", "notifications", "workflows", "actions"]
    );
    assert_eq!(idx["clientCode"], s(SYSTEM));
    let row = match &idx["functions"] {
        JValue::Array(a) => a[0].as_object().unwrap().clone(),
        _ => panic!(),
    };
    assert_eq!(row.get("name"), Some(&s("Ns.f")));
    assert_eq!(row.keys().cloned().collect::<Vec<_>>(), vec!["clientCode", "name", "id", "title", "version"], "a HashMap's order");
    let internal = e.call("GET", "/api/core/index/internal/testapp?forClientCode=SYSTEM", "").await.obj();
    assert_eq!(internal["clientCode"], s(SYSTEM));
    assert_eq!(e.call("GET", "/api/core/index", "").await.status, StatusCode::BAD_REQUEST);
}

// ── the controllers' own routes ─────────────────────────────────────

#[tokio::test]
async fn schedule_routes() {
    let e = env();
    let read = "Authorities.EventDefinition_READ";
    let anon = e.send("POST", "/api/core/eventDefinitions/schedule/toCron", None, &[], "{}").await;
    assert_eq!((anon.status, anon.code()), (StatusCode::UNAUTHORIZED, "COMMON.SIGN_IN_REQUIRED".into()));
    let denied = e.send("POST", "/api/core/eventDefinitions/schedule/toCron", Some(SYSTEM), &[("x-test-auth", "Authorities.X")], "{}").await;
    assert_eq!((denied.status, denied.code()), (StatusCode::FORBIDDEN, "COMMON.PERMISSION_REQUIRED".to_string()));
    assert_eq!(denied.java(), "Access Denied: needs Authorities.EventDefinition_READ");
    let ok = e
        .send("POST", "/api/core/eventDefinitions/schedule/toCron?timezone=Asia/Kolkata", Some(SYSTEM), &[("x-test-auth", read)], r#"{"frequency":"weekly","hour":9,"minute":0,"days":[1]}"#)
        .await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.text());
    assert_eq!(ok.obj().get("cron"), Some(&s("30 3 * * 1")));
    assert_eq!(e.send("POST", "/api/core/eventDefinitions/schedule/toCron", Some(SYSTEM), &[("x-test-auth", read)], "[]").await.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        e.send("POST", "/api/core/eventDefinitions/schedule/toCron", Some(SYSTEM), &[("x-test-auth", read)], r#"{"frequency":"yearly"}"#).await.status,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    let from = e.send("POST", "/api/core/eventDefinitions/schedule/fromCron", Some(SYSTEM), &[("x-test-auth", read)], r#"{"cron":"30 3 * * 1","cronZone":"UTC"}"#).await;
    assert_eq!(path(&from.obj(), &["model", "frequency"]), Some(&s("weekly")));
    assert_eq!(e.send("POST", "/api/core/eventDefinitions/schedule/fromCron", Some(SYSTEM), &[("x-test-auth", read)], r#"{"cron":{}}"#).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(e.send("POST", "/api/core/eventDefinitions/schedule/fromCron", Some(SYSTEM), &[("x-test-auth", read)], "1").await.status, StatusCode::BAD_REQUEST);
    let zones = e.call("GET", "/api/core/eventDefinitions/schedule/zones", "").await;
    assert!(matches!(zones.json(), JValue::Array(a) if a.len() > 300));
    assert_eq!(e.send("GET", "/api/core/eventDefinitions/schedule/zones", None, &[], "").await.status, StatusCode::UNAUTHORIZED, "zones need a signed-in caller");

    let page = e.send("GET", "/api/core/eventDefinitions/schedules?appCode=testapp&name=nightly&timezone=UTC&size=500", Some(SYSTEM), &[("x-test-auth", read)], "").await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.text());
    let rows = match page.obj()["content"].clone() {
        JValue::Array(a) => a,
        _ => panic!(),
    };
    let clients: Vec<String> = rows.iter().map(|r| str_field(r.as_object().unwrap(), "clientCode").unwrap().to_string()).collect();
    assert_eq!(clients, vec!["SYSTEM", "FIN", "ACME"], "holders first, the caller's own client first among them");
    let sys = rows[0].as_object().unwrap();
    assert_eq!((sys.get("state"), sys.get("clientName"), sys.get("owner")), (Some(&s("RUNS")), Some(&s("System")), Some(&JValue::Bool(true))));
    assert_eq!(sys.get("draftVersion"), Some(&JValue::Int(2)));
    assert!(sys.get("lastRun").is_some());
    let fin = rows[1].as_object().unwrap();
    assert_eq!(fin.get("state"), Some(&s("PAUSED")));
    let acme = rows[2].as_object().unwrap();
    assert_eq!(acme.get("state"), Some(&s("RUNS")), "per client, and the client may write");
    assert_eq!(page.obj()["size"], JValue::Int(100), "the page size is capped");
    let one = e.send("GET", "/api/core/eventDefinitions/schedules?appCode=testapp&name=nightly&clientCode=FIN", Some(SYSTEM), &[("x-test-auth", read)], "").await;
    assert_eq!(one.obj()["totalElements"], JValue::Int(1));
    assert_eq!(e.send("GET", "/api/core/eventDefinitions/schedules?appCode=testapp", Some(SYSTEM), &[("x-test-auth", read)], "").await.status, StatusCode::BAD_REQUEST);
    assert_eq!(e.send("GET", "/api/core/eventDefinitions/schedules?appCode=testapp&name=x&page=q", Some(SYSTEM), &[("x-test-auth", read)], "").await.status, StatusCode::BAD_REQUEST);
    assert_eq!(e.send("GET", "/api/core/eventDefinitions/schedules?appCode=testapp&name=x", None, &[], "").await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn template_previews_cache_and_billing() {
    let e = env();
    let p = e
        .send("POST", "/api/core/templates/preview", Some(SYSTEM), &[], r#"{"template":{"templateParts":{"en":{"subject":"Hi ${name}","body":"<p>${who}</p>"}},"sampleData":{"name":"Ann"}}}"#)
        .await;
    assert_eq!(p.status, StatusCode::OK, "{}", p.text());
    assert_eq!(p.obj().get("subject"), Some(&s("Hi Ann")));
    assert_eq!(p.obj().get("body"), Some(&s("<p></p>")));
    assert_eq!(e.send("POST", "/api/core/templates/preview", Some(SYSTEM), &[], r#"{"template":3}"#).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(e.send("POST", "/api/core/templates/preview", Some(SYSTEM), &[], r#"{"language":[]}"#).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(e.send("POST", "/api/core/templates/preview", Some(SYSTEM), &[], r#"{"data":"x"}"#).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(e.send("POST", "/api/core/templates/preview", Some(SYSTEM), &[], "x").await.status, StatusCode::BAD_REQUEST);
    assert_eq!(e.send("POST", "/api/core/templates/preview", Some(SYSTEM), &[], "null").await.text().split_whitespace().collect::<String>(), "{}");
    assert_eq!(e.send("POST", "/api/core/templates/preview", Some(SYSTEM), &[], r#"{"template":{"templateParts":{"en":{"a":"${"}}},"language":5}"#).await.status, StatusCode::INTERNAL_SERVER_ERROR);
    let pdf = e.send("POST", "/api/core/templates/preview/pdf", Some(SYSTEM), &[], r#"{"template":{"templateParts":{"en":{"body":"<p>Hello</p>"}}}}"#).await;
    assert_eq!(pdf.headers["content-type"], "application/pdf");
    assert!(pdf.body.starts_with(b"%PDF"));
    assert_eq!(e.send("POST", "/api/core/templates/preview/pdf", Some(SYSTEM), &[], r#"{"template":{"templateParts":{"en":{"body":"${"}}}}"#).await.status, StatusCode::INTERNAL_SERVER_ERROR);

    let fam: Arc<LocalCaches<String, u32>> = e.cache.family();
    fam.insert("FunctionCache_testapp_x", "k".into(), 1).await;
    let names = e.call("GET", "/api/core/internal/cache", "").await;
    assert!(names.text().contains("FunctionCache_testapp_x"));
    assert!(e.call("GET", "/api/core/internal/cache/stats", "").await.text().contains("hitRate"));
    assert_eq!(e.call("DELETE", "/api/core/internal/cache/FunctionCache_testapp_x", "").await.text(), "true");
    assert!(fam.get("FunctionCache_testapp_x", &"k".to_string()).await.is_none());
    let all = e.call("DELETE", "/api/core/internal/cache", "").await;
    assert_eq!((all.status, all.body.len()), (StatusCode::OK, 0), "no Redis: nothing to drop, an empty Mono");

    assert_eq!(e.send("POST", "/api/core/internal/billing/meter", None, &[], "").await.text(), "true");
    assert_eq!(e.send("POST", "/api/core/internal/billing/reconcile?date=2026-10-14", None, &[], "").await.text(), "true");
    assert_eq!(e.send("POST", "/api/core/internal/billing/reconcile?date=nope", None, &[], "").await.status, StatusCode::INTERNAL_SERVER_ERROR);
    let charges = e.billing.charges.lock().clone();
    assert_eq!(charges.len(), 2);
    assert!(charges[1].contains("\"quantity\":3"));

    let anon = e.send("GET", "/api/core/index?appCode=testapp", None, &[], "").await;
    assert_eq!((anon.status, anon.code()), (StatusCode::UNAUTHORIZED, "COMMON.SIGN_IN_REQUIRED".into()), "an anonymous caller only reaches the permitted paths");
    let page = e.call("GET", "/api/core/functions?appCode=testapp", "").await.obj();
    assert_eq!(page.keys().take(3).cloned().collect::<Vec<_>>(), vec!["pageable", "totalPages", "totalElements"], "core's Page order");
    let refused = e.send("GET", "/api/core/index?appCode=testapp", None, &[("x-test-fail", "1")], "").await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED, "a refused token is refused before any route");
    let _ = (&e.catalog, &EVENT_DEFINITION);
}

// ── unmapped paths and methods ──────────────────────────────────────

#[tokio::test]
async fn unmapped_paths_refuse_an_anonymous_caller_first() {
    let mut e = env();
    // As `Service::run` serves it: merged with the health routes, whose default fallback must
    // not replace the editor's.
    e.router = e.router.clone().merge(Router::new().route("/readyz", axum::routing::get(|| async { "ok" })));
    for path in ["/api/core/index/nothing", "/api/core/nonexistent", "/api/core/internal/nothing", "/api/core/storages/a/b/c"] {
        let anon = e.send("GET", path, None, &[], "").await;
        assert_eq!((anon.status, anon.code()), (StatusCode::UNAUTHORIZED, "COMMON.SIGN_IN_REQUIRED".into()), "{path}");
        assert!(anon.headers.get("www-authenticate").is_none());
        let signed = e.call("GET", path, "").await;
        assert_eq!(signed.status, StatusCode::NOT_FOUND, "{path}");
        let b = signed.obj();
        assert_eq!(str_field(&b, "debugMessage"), Some("404 NOT_FOUND"));
        assert_eq!(str_field(&b, "code"), Some("COMMON.NOT_FOUND"));
        assert_eq!(signed.headers.get("x-frame-options").map(|v| v.to_str().unwrap()), Some("DENY"));
    }
    // A permitted path the editor does not map: past the filter chain to the dispatcher.
    let permitted = e.send("GET", "/api/core/index/internal/a/b", None, &[], "").await;
    assert_eq!(permitted.status, StatusCode::NOT_FOUND);
    // A mapped path, a method it does not take.
    let anon = e.send("PUT", "/api/core/index", None, &[], "").await;
    assert_eq!(anon.status, StatusCode::UNAUTHORIZED);
    let signed = e.call("PUT", "/api/core/index", "").await;
    assert_eq!(signed.status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(str_field(&signed.obj(), "debugMessage"), Some("405 METHOD_NOT_ALLOWED \"Request method 'PUT' is not supported.\""));
    assert!(signed.headers.get("allow").is_none(), "Spring lists no methods");
    let permitted = e.send("PUT", "/api/core/index/internal/testapp", None, &[], "").await;
    assert_eq!(permitted.status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(e.send("GET", "/readyz", None, &[], "").await.status, StatusCode::OK, "the health routes stay outside");
}

// ── EventScheduleViewServiceTest ────────────────────────────────────

mod schedule_view {
    use std::collections::HashMap;

    use async_trait::async_trait;
    use chrono::{TimeZone, Utc};
    use overridable::{JMap, JValue};
    use platform::error::AppError;
    use platform::security::ContextAuthentication;

    use super::super::schedules::{client_schedules, from_cron_preview, to_cron, ScheduleModel, ScheduleSources};
    use super::{auth_for, everything, path, SYSTEM};
    use crate::scheduler::EventSchedule;

    const APP: &str = "leadzumptwo";
    const EVENT: &str = "LZ_WA_OUTBOX";

    #[derive(Default)]
    struct View {
        copies: Vec<JMap>,
        writers: Vec<String>,
        visible: Vec<String>,
        effective: HashMap<String, Option<EventSchedule>>,
        any_effective: Option<EventSchedule>,
        drafts: HashMap<String, (i64, Option<EventSchedule>)>,
    }

    #[async_trait]
    impl ScheduleSources for View {
        async fn copies(&self, _app: &str, _name: &str) -> Vec<JMap> {
            self.copies.clone()
        }
        async fn writers(&self, _app: &str) -> Vec<String> {
            self.writers.clone()
        }
        async fn visible_among(&self, _own: &str, _app: &str, _candidates: &[String]) -> Result<Vec<String>, AppError> {
            Ok(self.visible.clone())
        }
        async fn latest_runs(&self, _app: &str, _name: &str, _clients: &[String]) -> HashMap<String, crate::event_runs::EventRun> {
            HashMap::new()
        }
        async fn effective_schedule(&self, _app: &str, _name: &str, client: &str) -> Option<EventSchedule> {
            match self.effective.get(client) {
                Some(s) => s.clone(),
                None => self.any_effective.clone(),
            }
        }
        async fn draft(&self, _ca: &ContextAuthentication, copy_id: &str) -> Option<(i64, Option<EventSchedule>)> {
            self.drafts.get(copy_id).cloned()
        }
        async fn client_name(&self, client: &str) -> Option<String> {
            Some(format!("Client {client}"))
        }
    }

    fn copy(id: &str, client: &str, base: Option<&str>, schedule: Option<EventSchedule>) -> JMap {
        let mut m = JMap::new();
        m.insert("id".into(), JValue::Str(id.into()));
        m.insert("clientCode".into(), JValue::Str(client.into()));
        if let Some(b) = base {
            m.insert("baseClientCode".into(), JValue::Str(b.into()));
        }
        m.insert("appCode".into(), JValue::Str(APP.into()));
        m.insert("name".into(), JValue::Str(EVENT.into()));
        if let Some(s) = schedule {
            m.insert("schedule".into(), s.to_j());
        }
        m
    }

    fn sched(cron: Option<&str>, zone: Option<&str>, per_client: Option<bool>, enabled: Option<bool>) -> EventSchedule {
        EventSchedule { cron: cron.map(str::to_string), timezone: zone.map(str::to_string), per_client, enabled, spread: None }
    }

    fn strings(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    async fn rows(v: &View, zone: &str, client: Option<&str>, page: i64, size: i64) -> JValue {
        let now = Utc.with_ymd_and_hms(2026, 10, 15, 12, 0, 0).unwrap();
        client_schedules(v, &auth_for(SYSTEM, &everything()), APP, EVENT, Some(zone), client, page, size, now).await.unwrap()
    }

    fn content(page: &JValue) -> Vec<JMap> {
        match page.as_object().and_then(|p| p.get("content")) {
            Some(JValue::Array(a)) => a.iter().filter_map(|r| r.as_object().cloned()).collect(),
            _ => Vec::new(),
        }
    }

    fn field<'a>(r: &'a JMap, k: &str) -> Option<&'a str> {
        r.get(k).and_then(JValue::as_str)
    }

    #[tokio::test]
    async fn per_client_schedule_shows_each_clients_own_state() {
        let base = sched(Some("0 * * * * ?"), Some("UTC"), Some(true), Some(false));
        let v = View {
            copies: vec![copy("b", SYSTEM, None, Some(base.clone())), copy("f", "FIN", Some(SYSTEM), Some(sched(None, None, None, Some(true))))],
            writers: strings(&[SYSTEM, "FIN", "FIN2", "OTHER"]),
            visible: strings(&["FIN2", "FIN", SYSTEM]),
            effective: HashMap::from([
                (SYSTEM.to_string(), Some(base.clone())),
                ("FIN".to_string(), Some(EventSchedule { enabled: Some(true), ..base.clone() })),
                ("FIN2".to_string(), Some(base.clone())),
            ]),
            ..Default::default()
        };
        let rs = content(&rows(&v, "Asia/Kolkata", None, 0, 20).await);
        // Owner first, then the caller (here the same), then by code.
        assert_eq!(rs.iter().map(|r| field(r, "clientCode").unwrap()).collect::<Vec<_>>(), vec![SYSTEM, "FIN", "FIN2"]);
        assert_eq!((rs[0].get("owner"), field(&rs[0], "state")), (Some(&JValue::Bool(true)), Some("PAUSED")));
        let fin = &rs[1];
        assert_eq!(fin.get("owner"), Some(&JValue::Bool(false)));
        assert_eq!((field(fin, "copyId"), field(fin, "baseId")), (Some("f"), Some("b")));
        assert_eq!(path(fin, &["ownSchedule", "enabled"]), Some(&JValue::Bool(true)));
        assert_eq!(field(fin, "state"), Some("RUNS"));
        assert!(matches!(fin.get("nextRuns"), Some(JValue::Array(a)) if a.len() == 3));
        assert_eq!(field(fin, "description"), Some("Every minute"));
        assert_eq!(field(fin, "clientName"), Some("Client FIN"));
        assert_eq!((field(&rs[2], "copyId"), field(&rs[2], "state")), (None, Some("PAUSED")));
    }

    #[tokio::test]
    async fn not_per_client_runs_only_for_clients_whose_copy_sets_a_schedule() {
        let base = sched(Some("0 9 * * *"), Some("UTC"), Some(false), None);
        let v = View {
            copies: vec![copy("b", SYSTEM, None, Some(base.clone())), copy("f", "FIN", Some(SYSTEM), None)],
            writers: strings(&["FIN2"]),
            visible: strings(&[SYSTEM, "FIN", "FIN2"]),
            any_effective: Some(base),
            ..Default::default()
        };
        let rs = content(&rows(&v, "UTC", None, 0, 20).await);
        // FIN has a copy, but it stores no schedule: the scheduler does not count it.
        assert_eq!(rs.iter().map(|r| field(r, "state").unwrap()).collect::<Vec<_>>(), vec!["RUNS", "NOT_RUNNING", "NOT_RUNNING"]);
    }

    #[tokio::test]
    async fn per_client_without_write_access_does_not_run() {
        let base = sched(Some("0 9 * * *"), None, Some(true), None);
        let v = View {
            copies: vec![copy("b", SYSTEM, None, Some(base.clone())), copy("x", "GONE", Some(SYSTEM), Some(sched(Some("0 10 * * *"), None, None, None)))],
            writers: strings(&[SYSTEM]),
            visible: strings(&[SYSTEM, "GONE"]),
            any_effective: Some(base),
            ..Default::default()
        };
        let rs = content(&rows(&v, "UTC", None, 0, 20).await);
        assert_eq!(field(&rs[1], "state"), Some("NOT_RUNNING"));
    }

    #[tokio::test]
    async fn an_unreadable_cron_or_no_cron_says_so() {
        let bad = sched(Some("61 * * * *"), None, None, None);
        let v = View {
            copies: vec![copy("b", SYSTEM, None, Some(bad.clone()))],
            visible: strings(&[SYSTEM, "FIN"]),
            effective: HashMap::from([(SYSTEM.to_string(), Some(bad)), ("FIN".to_string(), None)]),
            ..Default::default()
        };
        let rs = content(&rows(&v, "UTC", None, 0, 20).await);
        assert_eq!((field(&rs[0], "state"), field(&rs[1], "state")), (Some("INVALID"), Some("NOT_SCHEDULED")));
    }

    #[tokio::test]
    async fn a_pending_draft_is_reported() {
        let base = sched(Some("0 9 * * *"), None, Some(true), None);
        let v = View {
            copies: vec![copy("b", SYSTEM, None, Some(base.clone())), copy("f", "FIN", Some(SYSTEM), Some(sched(None, None, None, Some(true))))],
            writers: strings(&[SYSTEM, "FIN"]),
            visible: strings(&["FIN"]),
            any_effective: Some(base.clone()),
            drafts: HashMap::from([("f".to_string(), (4, Some(EventSchedule { enabled: Some(false), ..base })))]),
            ..Default::default()
        };
        let rs = content(&rows(&v, "UTC", None, 0, 20).await);
        assert_eq!(rs[0].get("draftVersion"), Some(&JValue::Int(4)));
        assert_eq!(path(&rs[0], &["draftSchedule", "enabled"]), Some(&JValue::Bool(false)));
    }

    #[tokio::test]
    async fn only_the_requested_page_is_built_and_a_client_can_be_picked() {
        let base = sched(Some("0 9 * * *"), None, Some(true), None);
        let v = View {
            copies: vec![copy("b", SYSTEM, None, Some(base.clone()))],
            writers: strings(&["A1", "A2", "A3", "A4"]),
            visible: strings(&["A4", "A3", SYSTEM, "A2", "A1"]),
            any_effective: Some(base),
            ..Default::default()
        };
        let page = rows(&v, "UTC", None, 1, 2).await;
        assert_eq!(page.as_object().unwrap().get("totalElements"), Some(&JValue::Int(5)));
        // SYSTEM (has a copy), then A1..A4 by code: page 1 of size 2 is A2, A3.
        assert_eq!(content(&page).iter().map(|r| field(r, "clientCode").unwrap().to_string()).collect::<Vec<_>>(), strings(&["A2", "A3"]));
        let picked = rows(&v, "UTC", Some("A4"), 0, 20).await;
        assert_eq!(content(&picked).iter().map(|r| field(r, "clientCode").unwrap().to_string()).collect::<Vec<_>>(), strings(&["A4"]));
    }

    #[test]
    fn the_builder_round_trips_through_the_service() {
        let now = Utc.with_ymd_and_hms(2026, 10, 15, 12, 0, 0).unwrap();
        let weekdays = ScheduleModel {
            frequency: Some("weekly".into()),
            hour: Some(9),
            minute: Some(0),
            days: Some(vec![1, 2, 3, 4, 5]),
            every: Some(5),
            day_of_month: Some("1".into()),
            cron: Some(String::new()),
            ..Default::default()
        };
        let p = to_cron(weekdays, Some("Asia/Kolkata"), now).unwrap();
        assert_eq!((p.cron.as_str(), p.timezone.as_str(), p.valid), ("30 3 * * 1,2,3,4,5", "UTC", true));
        assert_eq!(p.next_runs.len(), 3);
        assert_eq!(p.description, "Weekdays at 09:00 (Asia/Kolkata)");
        let p = from_cron_preview(Some("61 * * * *"), None, Some("UTC"), now).unwrap();
        assert!(!p.valid);
        assert!(p.error.as_deref().unwrap_or_default().starts_with("The scheduler cannot read this cron"), "{:?}", p.error);
    }
}

// ── the admin purge ─────────────────────────────────────────────────

mod purge_routes {
    use super::*;
    use mongodb::bson::doc;

    const PURGERS: &str = "Authorities.Client_DELETE,Authorities.Application_DELETE";

    impl Env {
        async fn purge(&self, client: Option<&str>, auth: &str, uri: &str) -> Answer {
            self.send("DELETE", uri, client, &[("x-test-auth", auth)], "").await
        }
    }

    /// Two clients' documents of two apps, their tenant databases, a few service databases,
    /// and core rows.
    fn seeded() -> Env {
        let e = env();
        for (coll, d) in [
            ("function", doc! {"name": "f1", "appCode": "zapp", "clientCode": "ZZ1"}),
            ("function", doc! {"name": "f2", "appCode": "zapp2", "clientCode": "ZZ1"}),
            ("function", doc! {"name": "f3", "appCode": "zapp", "clientCode": "ZZ10"}),
            ("function", doc! {"name": "f4", "appCode": "other", "clientCode": "ZZ10"}),
            ("storage", doc! {"name": "s1", "uniqueName": "u_s1", "appCode": "zapp", "clientCode": "SYSTEM"}),
            ("version", doc! {"objectName": "f1", "objectAppCode": "zapp", "clientCode": "ZZ1"}),
            ("version", doc! {"objectName": "f4", "objectAppCode": "other", "clientCode": "ZZ10"}),
            ("connection", doc! {"name": "c", "appCode": "zapp2", "clientCode": "ZZ1"}),
        ] {
            e.mem.put_raw(coll, d);
        }
        *e.data.tenants.lock() = [
            ("ZZ1_zapp", 4),
            ("ZZ1_zapp_draft", 1),
            ("ZZ1_zapp2", 2),
            ("ZZ10_zapp", 7),
            ("ZZ10_other_draft", 3),
            ("core", 100),
            ("entity_processor", 50),
            ("ZZ1", 1),
        ]
        .iter()
        .map(|(n, r)| (n.to_string(), *r))
        .collect();
        *e.rows.rows.lock() = vec![
            ("core_tokens", "ZZ1".into(), String::new()),
            ("core_tokens", "ZZ10".into(), String::new()),
            ("core_things", "ZZ1".into(), "zapp".into()),
            ("core_things", "ZZ10".into(), "zapp".into()),
            ("core_things", "ZZ10".into(), "other".into()),
        ];
        e
    }

    fn names(e: &Env, coll: &str) -> Vec<String> {
        let mut v: Vec<String> = e
            .mem
            .all(coll)
            .iter()
            .filter_map(|d| d.get_str("name").or_else(|_| d.get_str("objectName")).ok().map(str::to_string))
            .collect();
        v.sort();
        v
    }

    /// The report as compact JSON (the editor writes it pretty, as Jackson).
    fn compact(a: &Answer) -> String {
        to_compact(&JValue::Object(a.obj()))
    }

    fn tenants(e: &Env) -> Vec<String> {
        e.data.tenants.lock().iter().map(|(n, _)| n.clone()).collect()
    }

    #[tokio::test]
    async fn only_a_system_caller_with_the_authority_may_purge() {
        let e = seeded();
        let a = e.purge(None, PURGERS, "/api/core/purge/client/ZZ1").await;
        assert_eq!(a.status, StatusCode::UNAUTHORIZED, "{}", a.text());
        let a = e.purge(Some(SYSTEM), "Authorities.Application_DELETE", "/api/core/purge/client/ZZ1").await;
        assert_eq!(a.status, StatusCode::FORBIDDEN, "{}", a.text());
        let a = e.purge(Some(SYSTEM), "Authorities.Client_DELETE", "/api/core/purge/app/zapp").await;
        assert_eq!(a.status, StatusCode::FORBIDDEN, "{}", a.text());
        let a = e.purge(Some(MID), PURGERS, "/api/core/purge/client/ZZ1?dryRun=false").await;
        assert_eq!(a.status, StatusCode::FORBIDDEN, "{}", a.text());
        assert!(a.text().contains("SYSTEM client only"), "{}", a.text());
        let a = e.purge(Some(MID), PURGERS, "/api/core/purge/app/zapp?dryRun=false").await;
        assert_eq!(a.status, StatusCode::FORBIDDEN, "{}", a.text());
        assert_eq!(names(&e, "function").len(), 4, "a refused purge deleted documents");
        assert_eq!(tenants(&e).len(), 8, "a refused purge dropped databases");
    }

    #[tokio::test]
    async fn bad_codes_and_system_are_refused() {
        let e = seeded();
        for uri in [
            "/api/core/purge/client/SYSTEM",
            "/api/core/purge/client/system",
            "/api/core/purge/client/ZZ_1",
            "/api/core/purge/client/ZZ-1",
            "/api/core/purge/app/z-app",
            "/api/core/purge/app/_",
        ] {
            let a = e.purge(Some(SYSTEM), PURGERS, &format!("{uri}?dryRun=false")).await;
            assert_eq!(a.status, StatusCode::BAD_REQUEST, "{uri}: {}", a.text());
        }
        assert_eq!(names(&e, "function").len(), 4);
    }

    #[tokio::test]
    async fn a_client_purge_is_a_dry_run_unless_asked() {
        let e = seeded();
        for uri in ["/api/core/purge/client/ZZ1", "/api/core/purge/client/ZZ1?dryRun=true", "/api/core/purge/client/ZZ1?dryRun=yes"] {
            let a = e.purge(Some(SYSTEM), PURGERS, uri).await;
            assert_eq!(a.status, StatusCode::OK, "{}", a.text());
            assert_eq!(
                compact(&a),
                r#"{"dryRun":true,"mongo":{"ZZ1_zapp.*":4,"ZZ1_zapp2.*":2,"ZZ1_zapp_draft.*":1,"core.connection":1,"core.function":2,"core.version":1},"mysql":{"core.core_things":1,"core.core_tokens":1},"dropped":["ZZ1_zapp","ZZ1_zapp_draft","ZZ1_zapp2"],"errors":[]}"#
            );
        }
        assert_eq!(names(&e, "function").len(), 4, "a dry run deleted documents");
        assert_eq!(tenants(&e).len(), 8, "a dry run dropped databases");
        assert_eq!(e.rows.rows.lock().len(), 5, "a dry run deleted rows");
        assert!(e.data.calls().is_empty());
    }

    #[tokio::test]
    async fn a_client_purge_deletes_the_clients_traces_only() {
        let e = seeded();
        let cached = e.st.functions.cache_name("zapp", "f1", false);
        let other = e.st.functions.cache_name("zapp2", "f2", true);
        let table = appdata::engine::storage_cache_names("u_s1")[0].clone();
        for c in [&cached, &other, &table] {
            e.warm(c).await;
        }
        let a = e.purge(Some(SYSTEM), PURGERS, "/api/core/purge/client/ZZ1?dryRun=false").await;
        assert_eq!(a.status, StatusCode::OK, "{}", a.text());
        assert_eq!(
            compact(&a),
            r#"{"dryRun":false,"mongo":{"ZZ1_zapp.*":4,"ZZ1_zapp2.*":2,"ZZ1_zapp_draft.*":1,"core.connection":1,"core.function":2,"core.version":1},"mysql":{"core.core_things":1,"core.core_tokens":1},"dropped":["ZZ1_zapp","ZZ1_zapp_draft","ZZ1_zapp2"],"errors":[]}"#
        );
        assert_eq!(names(&e, "function"), ["f3", "f4"]);
        assert_eq!(names(&e, "version"), ["f4"]);
        assert_eq!(names(&e, "storage"), ["s1"], "another client's storage of the app stays");
        assert!(names(&e, "connection").is_empty());
        assert_eq!(tenants(&e), ["ZZ10_zapp", "ZZ10_other_draft", "core", "entity_processor", "ZZ1"]);
        assert_eq!(e.data.calls(), ["drop database ZZ1_zapp", "drop database ZZ1_zapp_draft", "drop database ZZ1_zapp2"]);
        assert!(e.rows.rows.lock().iter().all(|r| r.1 == "ZZ10"));
        for c in [&cached, &other, &table] {
            assert!(!e.is_warm(c).await, "{c} outlived the purge");
        }
    }

    #[tokio::test]
    async fn an_app_purge_reaches_every_client() {
        let e = seeded();
        let a = e.purge(Some(SYSTEM), PURGERS, "/api/core/purge/app/zapp?dryRun=false").await;
        assert_eq!(a.status, StatusCode::OK, "{}", a.text());
        assert_eq!(
            compact(&a),
            r#"{"dryRun":false,"mongo":{"ZZ10_zapp.*":7,"ZZ1_zapp.*":4,"ZZ1_zapp_draft.*":1,"core.function":2,"core.storage":1,"core.version":1},"mysql":{"core.core_things":2},"dropped":["ZZ1_zapp","ZZ1_zapp_draft","ZZ10_zapp"],"errors":[]}"#
        );
        assert_eq!(names(&e, "function"), ["f2", "f4"]);
        assert_eq!(names(&e, "version"), ["f4"]);
        assert!(names(&e, "storage").is_empty());
        assert_eq!(tenants(&e), ["ZZ1_zapp2", "ZZ10_other_draft", "core", "entity_processor", "ZZ1"]);
        assert_eq!(e.rows.rows.lock().len(), 3);
    }

    #[tokio::test]
    async fn failures_are_reported_and_the_rest_goes_on() {
        let e = seeded();
        e.mem.fail("version", true);
        let a = e.purge(Some(SYSTEM), PURGERS, "/api/core/purge/client/ZZ1?dryRun=false").await;
        assert_eq!(a.status, StatusCode::OK, "{}", a.text());
        let errors = a.obj().get("errors").cloned().unwrap();
        assert!(to_compact(&errors).contains("core.version"), "{}", a.text());
        assert_eq!(names(&e, "function"), ["f3", "f4"]);
    }
}
