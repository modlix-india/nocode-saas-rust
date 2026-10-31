//! ui-editor in process, on the in-memory store (`MemBackend`, `FakeDirectory`): the ui kinds'
//! hooks (name rules, URI path validation, the OUI / SSR / index / style / theme / URI pattern
//! evictions), the controllers' own routes (application index, mobile apps, page components
//! and events, function steps) and the commons routes mounted for the ui kinds.
//!
//! Java tests ported here: `PageComponentPatchAuthorizationIntegrationTest`,
//! `PageClientPatchIntegrationTest` (nocode-saas commits 3cf6ebc54 and 7a1766ef6),
//! `SharedHostServedClientIntegrationTest` (e2b7d48aa, the engine reads),
//! `ObjectIndexIntegrationTest`, `CreateTimestampIntegrationTest`, and the
//! `ApplicationService.readProperties` cases of `DraftSaveEvictionIntegrationTest`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::routing::get;
use axum::{Json, Router};
use overridable::backend::{FakeDirectory, MemBackend};
use overridable::json::{parse, to_compact};
use overridable::pojo::{str_field, Pojo};
use overridable::write::persist::to_document;
use overridable::write::router::CallerSource;
use overridable::{JMap, JValue, Store};
use platform::cache::{CacheService, LocalCaches};
use platform::error::AppResult;
use platform::security::{ContextAuthentication, ContextUser, SecurityClient};
use platform::upstream::Upstream;
use tower::ServiceExt;
use ui::docs::{APPLICATION, FUNCTION, PAGE};
use ui::editor::config::EditorConfig;
use ui::engine::Engine;
use ui::state::{AppState, Caller, Inner};

const SYSTEM: &str = "SYSTEM";
const APP: &str = "testapp";

// ── The harness ─────────────────────────────────────────────────────

fn all_for(object: &str) -> Vec<String> {
    ["CREATE", "READ", "UPDATE", "DELETE"].iter().map(|m| format!("Authorities.{object}_{m}")).collect()
}

/// Every authority the editor's routes ask for.
fn everything() -> Vec<String> {
    let mut a: Vec<String> = ["Application", "Page", "Style", "Theme", "Function", "Schema", "Transport"]
        .iter()
        .flat_map(|o| all_for(o))
        .collect();
    a.push("Authorities.ROLE_MobileApp_CREATE".into());
    a
}

/// `authFor(clientCode, authorities...)`, a SYSTEM client being of type SYS.
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

/// `x-test-client` is a signed-in caller of that client with `x-test-auth`'s authorities
/// (every one by default); no header is the anonymous caller.
struct Callers;

#[async_trait]
impl CallerSource for Callers {
    async fn caller(&self, h: &HeaderMap) -> AppResult<ContextAuthentication> {
        let get = |n: &str| h.get(n).and_then(|v| v.to_str().ok()).map(str::to_string);
        let Some(client) = get("x-test-client") else { return Ok(anonymous()) };
        let auths = match get("x-test-auth") {
            Some(a) => a.split(',').filter(|s| !s.is_empty()).map(str::to_string).collect(),
            None => everything(),
        };
        Ok(auth_for(&client, &auths))
    }
}

struct Env {
    mem: Arc<MemBackend>,
    dir: Arc<FakeDirectory>,
    cache: CacheService,
    store: Store,
    router: Router,
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
    fn message(&self) -> String {
        str_field(&self.obj(), "message").unwrap_or("").to_string()
    }
    /// The code and Java's text (`debugMessage` without its `[key] `).
    fn coded(&self) -> (String, String) {
        let o = self.obj();
        let d = str_field(&o, "debugMessage").unwrap_or("");
        let java = d.strip_prefix('[').and_then(|r| r.split_once("] ")).map(|(_, t)| t).unwrap_or(d);
        (str_field(&o, "code").unwrap_or("").to_string(), java.to_string())
    }
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
    fn id(&self) -> String {
        str_field(&self.obj(), "id").expect("an id").to_string()
    }
}

fn env() -> Env {
    env_with(EditorConfig::default())
}

fn env_with(cfg: EditorConfig) -> Env {
    let mem = Arc::new(MemBackend::new());
    let dir = Arc::new(FakeDirectory::new());
    dir.chain(&[SYSTEM]);
    let cache = CacheService::new("cmn", "evictionChannel", None).unwrap();
    let store = Store::with_parts(mem.clone(), dir.clone(), &cache).unwrap();
    let mut st = ui::editor::state(store.clone(), cache.clone(), Arc::new(Callers), &cfg, reqwest::Client::new());
    // A small key keeps keystore generation quick in a debug build.
    Arc::get_mut(&mut st).unwrap().mobile.key_bits = 512;
    let router = ui::editor::routes::router(st.clone());
    let probe = cache.family();
    Env { mem, dir, cache, store, router, probe }
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

    async fn warm(&self, cache_name: &str, key: &str) {
        self.probe.insert(cache_name, key.to_string(), 1).await;
    }

    async fn is_warm(&self, cache_name: &str, key: &str) -> bool {
        self.probe.get(cache_name, &key.to_string()).await.is_some()
    }

    /// Warms each cache under the key `k`, to see whether a write clears it.
    async fn warm_all(&self, names: &[String]) {
        for n in names {
            self.warm(n, "k").await;
        }
    }

    async fn cold(&self, names: &[String]) -> Vec<String> {
        let mut out = Vec::new();
        for n in names {
            if !self.is_warm(n, "k").await {
                out.push(n.clone());
            }
        }
        out
    }

    /// `insertRaw`: the stored form, as Spring Data writes it.
    fn insert_raw(&self, pojo: &Pojo, collection: &str, json: &str) -> String {
        let m = obj(json);
        let id = self.mem.put_raw(collection, to_document(pojo, &m, None, &[]));
        overridable::bson_conv::to_java_string(&id).java_to_string()
    }

    fn raw(&self, pojo: &Pojo, collection: &str, id: &str) -> JMap {
        let d = self
            .mem
            .all(collection)
            .into_iter()
            .find(|d| overridable::bson_conv::to_java_string(d.get("_id").unwrap()).java_to_string() == id)
            .expect("stored document");
        overridable::pojo::decode_bson(pojo, &d)
    }

    fn engine_state(&self) -> AppState {
        let security = SecurityClient::new(Upstream::fixed(&["http://127.0.0.1:9"]), 0).unwrap();
        AppState::new(Inner {
            store: self.store.clone(),
            security,
            properties: self.cache.family(),
            fillers: self.cache.family(),
            app_status: self.cache.family(),
            app_dependencies: self.cache.family(),
            cache: self.cache.clone(),
            config: ui::config::UiConfig::default(),
        })
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

fn arr(v: &JValue) -> Option<&Vec<JValue>> {
    match v {
        JValue::Array(a) => Some(a),
        _ => None,
    }
}

fn names(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

/// The UI classes' three per-app caches, and the per-kind OUI ones.
fn oui(app: &str) -> Vec<String> {
    names(&[&format!("applicationOUICache-{app}"), &format!("pageOUICache-{app}"), &format!("styleOUICache-{app}"), &format!("themeOUICache-{app}")])
}

fn app_caches(app: &str) -> Vec<String> {
    names(&[
        &format!("ApplicationCache_{app}_indexNewCache_{app}"),
        &format!("ApplicationCache_{app}_manifestCache_{app}"),
        &format!("ApplicationCache_{app}_cacheProperties_{app}"),
        &format!("ApplicationCache_{app}_cacheProperties_{app}_DRAFT"),
    ])
}

// ── Applications ────────────────────────────────────────────────────

#[tokio::test]
async fn an_application_name_must_be_its_app_code_in_letters() {
    let e = env();
    for body in [
        r#"{"name":"other","appCode":"testapp","clientCode":"SYSTEM"}"#,
        r#"{"name":"test1","appCode":"test1","clientCode":"SYSTEM"}"#,
        r#"{"appCode":"testapp","clientCode":"SYSTEM"}"#,
        r#"{"name":"testapp","clientCode":"SYSTEM"}"#,
    ] {
        let r = e.call("POST", "/api/ui/applications", body).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(r.coded(), ("UI.APP_NAME_MISMATCH".into(), "Application name should match with appCode and should not contain any special characters ".into()));
        assert_eq!(r.message(), "The app's name must be the same as its app code, and use letters only.");
    }
    let r = e.call("POST", "/api/ui/applications", r#"{"name":"testapp","appCode":"testapp","clientCode":"SYSTEM","properties":{"title":"T"}}"#).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(str_field(&r.obj(), "name"), Some("testapp"));
}

#[tokio::test]
async fn application_writes_clear_the_index_manifest_properties_and_oui_caches() {
    let e = env();
    let watched: Vec<String> = app_caches(APP).into_iter().chain(oui(APP)[..2].to_vec()).collect();
    e.warm_all(&watched).await;
    let created = e.call("POST", "/api/ui/applications", r#"{"name":"testapp","appCode":"testapp","clientCode":"SYSTEM","properties":{"title":"T"}}"#).await;
    assert_eq!(created.status, StatusCode::OK);
    assert_eq!(e.cold(&watched).await, watched, "create clears them too (Java's create clears none)");

    // An update whose body names another app: Java keys the OUI caches on the body's app; the
    // stored app's are cleared as well.
    let other: Vec<String> = oui("otherapp")[..2].to_vec();
    e.warm_all(&watched).await;
    e.warm_all(&other).await;
    let mut body = created.obj();
    body.insert("appCode".into(), s("otherapp"));
    body.insert("properties".into(), JValue::Object(obj(r#"{"title":"U"}"#)));
    let id = created.id();
    let updated = e.call("PUT", &format!("/api/ui/applications/{id}"), &to_compact(&JValue::Object(body))).await;
    assert_eq!(updated.status, StatusCode::OK, "{}", updated.text());
    assert_eq!(str_field(&updated.obj(), "appCode"), Some(APP), "identity comes from the stored row");
    assert_eq!(e.cold(&watched).await, watched);
    assert_eq!(e.cold(&other).await, other);

    e.warm_all(&watched).await;
    let deleted = e.call("DELETE", &format!("/api/ui/applications/{id}"), "").await;
    assert_eq!((deleted.status, deleted.text()), (StatusCode::OK, "true".to_string()));
    assert_eq!(e.cold(&watched).await, watched);
}

#[tokio::test]
async fn deleting_an_app_wipes_every_kind_and_clears_the_app_caches() {
    let e = env();
    e.call("POST", "/api/ui/applications", r#"{"name":"testapp","appCode":"testapp","clientCode":"SYSTEM"}"#).await;
    e.call("POST", "/api/ui/pages", r#"{"name":"home","appCode":"testapp","clientCode":"SYSTEM"}"#).await;
    e.call("POST", "/api/ui/styles", r#"{"name":"st","appCode":"testapp","clientCode":"SYSTEM","styleString":"a{}"}"#).await;
    let watched = app_caches(APP);
    e.warm_all(&watched).await;
    let fwd = [("x-forwarded-host", "localhost"), ("x-forwarded-port", "8080"), ("clientCode", SYSTEM), ("appCode", APP)];
    let r = e.send("DELETE", "/api/ui?deleteAppCode=testapp", Some(SYSTEM), &fwd, "").await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    for c in ["application", "page", "style"] {
        assert_eq!(e.mem.all(c).len(), 0, "{c}");
    }
    assert_eq!(e.cold(&watched).await, watched);
}

// ── Pages, styles, themes ───────────────────────────────────────────

#[tokio::test]
async fn a_page_update_counts_every_component_and_event_edit_and_clears_the_oui_caches() {
    let e = env();
    let created = e
        .call(
            "POST",
            "/api/ui/pages",
            r#"{"name":"home","appCode":"testapp","clientCode":"SYSTEM","rootComponent":"a",
                "componentDefinition":{"a":{"key":"a","name":"a","type":"Grid"},"b":{"key":"b","name":"b","type":"Text"}},
                "eventFunctions":{"onLoad":{"name":"onLoad"}}}"#,
        )
        .await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text());
    let watched = oui(APP)[..2].to_vec();
    e.warm_all(&watched).await;
    e.warm_all(&oui(APP)[2..]).await;
    let id = created.id();
    let mut body = created.obj();
    body.insert("componentVersions".into(), JValue::Object(obj(r#"{"a":4}"#)));
    let updated = e.call("PUT", &format!("/api/ui/pages/{id}"), &to_compact(&JValue::Object(body))).await;
    assert_eq!(updated.status, StatusCode::OK, "{}", updated.text());
    let u = updated.obj();
    assert_eq!(path(&u, &["componentVersions", "a"]), Some(&JValue::Int(1)), "the stored versions count, not the body's");
    assert_eq!(path(&u, &["componentVersions", "b"]), Some(&JValue::Int(1)));
    assert_eq!(path(&u, &["eventFunctionVersions", "onLoad"]), Some(&JValue::Int(1)));
    assert_eq!(e.cold(&watched).await, watched);
    assert!(e.cold(&oui(APP)[2..]).await.is_empty(), "a page write leaves the style and theme caches");

    let again = e.call("PUT", &format!("/api/ui/pages/{id}"), &to_compact(&JValue::Object(u.clone()))).await;
    assert_eq!(path(&again.obj(), &["componentVersions", "a"]), Some(&JValue::Int(2)));
}

#[tokio::test]
async fn style_and_theme_writes_clear_their_own_caches_and_deletes_answer_the_ssr_publish() {
    let e = env();
    let style = e.call("POST", "/api/ui/styles", r#"{"name":"st","appCode":"testapp","clientCode":"SYSTEM","styleString":"a{}"}"#).await;
    assert_eq!(style.status, StatusCode::OK);
    let all = oui(APP);
    e.warm_all(&all).await;
    let mut body = style.obj();
    body.insert("styleString".into(), s("b{}"));
    let r = e.call("PUT", &format!("/api/ui/styles/{}", style.id()), &to_compact(&JValue::Object(body))).await;
    assert_eq!(str_field(&r.obj(), "styleString"), Some("b{}"));
    assert_eq!(e.cold(&all).await, all[..3].to_vec(), "a style write leaves the theme cache");

    let theme = e.call("POST", "/api/ui/themes", r#"{"name":"th","appCode":"testapp","clientCode":"SYSTEM","variables":{"x":{"a":"1"}}}"#).await;
    assert_eq!(theme.status, StatusCode::OK, "{}", theme.text());
    e.warm_all(&all).await;
    let mut body = theme.obj();
    body.insert("variables".into(), JValue::Object(obj(r#"{"x":{"a":"2"}}"#)));
    let r = e.call("PUT", &format!("/api/ui/themes/{}", theme.id()), &to_compact(&JValue::Object(body))).await;
    assert_eq!(path(&r.obj(), &["variables", "x", "a"]), Some(&s("2")));
    assert_eq!(e.cold(&all).await, all);

    // Every client's cached copy goes on delete (Java clears only the deleting client's key).
    e.warm("ThemeCache_testapp_th", "OTHER").await;
    e.warm_all(&all).await;
    let d = e.call("DELETE", &format!("/api/ui/themes/{}", theme.id()), "").await;
    assert_eq!((d.status, d.text()), (StatusCode::OK, "false".to_string()), "the SSR publish's answer: no Redis here");
    assert!(!e.is_warm("ThemeCache_testapp_th", "OTHER").await);
    assert_eq!(e.cold(&all).await, all);
}

// ── Functions and schemas ───────────────────────────────────────────

#[tokio::test]
async fn function_and_schema_names_come_from_their_definitions() {
    let e = env();
    for base in ["functions", "schemas"] {
        let no_def = e.call("POST", &format!("/api/ui/{base}"), r#"{"appCode":"testapp","clientCode":"SYSTEM"}"#).await;
        assert_eq!(no_def.status, StatusCode::INTERNAL_SERVER_ERROR, "{base}: a null definition");
        let no_ns = e.call("POST", &format!("/api/ui/{base}"), r#"{"appCode":"testapp","clientCode":"SYSTEM","definition":{"name":"f"}}"#).await;
        assert_eq!((no_ns.status, no_ns.coded()), (StatusCode::BAD_REQUEST, ("DEF.NAME_MISSING".into(), "Namespace or name missing".into())), "{base}");
        let made = e
            .call("POST", &format!("/api/ui/{base}"), r#"{"name":"ignored","appCode":"testapp","clientCode":"SYSTEM","definition":{"namespace":"Ns","name":"f"}}"#)
            .await;
        assert_eq!(made.status, StatusCode::OK, "{base}: {}", made.text());
        assert_eq!(str_field(&made.obj(), "name"), Some("Ns.f"));
        let mut renamed = made.obj();
        renamed.insert("definition".into(), JValue::Object(obj(r#"{"namespace":"Ns","name":"g"}"#)));
        let r = e.call("PUT", &format!("/api/ui/{base}/{}", made.id()), &to_compact(&JValue::Object(renamed))).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{base}: {}", r.text());
        let mut nameless = made.obj();
        nameless.insert("definition".into(), JValue::Object(obj(r#"{"name":"g"}"#)));
        let r = e.call("PUT", &format!("/api/ui/{base}/{}", made.id()), &to_compact(&JValue::Object(nameless))).await;
        assert_eq!((r.status, r.coded()), (StatusCode::BAD_REQUEST, ("DEF.NAME_MISSING".into(), "Namespace or name missing".into())), "{base}");
        let mut same = made.obj();
        same.insert("definition".into(), JValue::Object(obj(r#"{"namespace":"Ns","name":"f","steps":{}}"#)));
        let r = e.call("PUT", &format!("/api/ui/{base}/{}", made.id()), &to_compact(&JValue::Object(same))).await;
        assert_eq!(r.status, StatusCode::OK, "{base}: {}", r.text());
        let d = e.call("DELETE", &format!("/api/ui/{base}/{}", made.id()), "").await;
        assert_eq!(d.text(), "true");
    }
    let r = e.call("PUT", "/api/ui/functions/nope", r#"{"definition":{"namespace":"Ns","name":"f"}}"#).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
}

#[test]
fn a_derived_schema_keeps_the_name_parts_its_delta_leaves_out() {
    use ui::editor::kinds::updated_schema_name;
    let derived = obj(r#"{"name":"Ns.s","baseClientCode":"SYSTEM"}"#);
    let root = obj(r#"{"name":"Ns.s"}"#);
    assert_eq!(updated_schema_name(&obj(r#"{"definition":{"namespace":"A","name":"b"}}"#), &root).as_deref(), Some("A.b"));
    assert_eq!(updated_schema_name(&obj(r#"{"definition":{}}"#), &root), None, "a root needs both parts");
    assert_eq!(updated_schema_name(&obj(r#"{"definition":{}}"#), &derived).as_deref(), Some("Ns.s"));
    assert_eq!(updated_schema_name(&obj(r#"{"definition":{"name":"t"}}"#), &derived).as_deref(), Some("Ns.t"));
    assert_eq!(updated_schema_name(&obj(r#"{}"#), &derived).as_deref(), Some("Ns.s"));
    assert_eq!(updated_schema_name(&obj(r#"{}"#), &obj(r#"{"name":"plain","baseClientCode":"S"}"#)), None);
    assert_eq!(updated_schema_name(&obj(r#"{}"#), &obj(r#"{"name":".x","baseClientCode":"S"}"#)), None);
    assert_eq!(updated_schema_name(&obj(r#"{}"#), &obj(r#"{"name":"x.","baseClientCode":"S"}"#)), None);
    assert_eq!(updated_schema_name(&obj(r#"{}"#), &obj(r#"{"baseClientCode":"S"}"#)), None);
}

/// The commons `AbstractFunctionServiceUpdateTest` (Java commit 3cf6ebc54).
#[test]
fn a_derived_function_copy_takes_the_name_its_delta_leaves_out() {
    use ui::editor::kinds::updated_function_name;
    let stored = |base: Option<&str>| {
        let base = base.map(|b| format!(r#","baseClientCode":"{b}""#)).unwrap_or_default();
        obj(&format!(r#"{{"name":"ZzOvr.zzOvrFn","definition":{{}}{base}}}"#))
    };
    let derived = stored(Some(SYSTEM));
    assert_eq!(updated_function_name(&obj(r#"{"definition":{"steps":{}}}"#), &derived).as_deref(), Some("ZzOvr.zzOvrFn"));
    assert_eq!(updated_function_name(&obj(r#"{"definition":{"name":"other"}}"#), &derived).as_deref(), Some("ZzOvr.other"), "a rename is still reported");
    let base = stored(None);
    assert_eq!(updated_function_name(&obj(r#"{"definition":{"name":"zzOvrFn"}}"#), &base), None, "a base function must carry both");
    assert_eq!(updated_function_name(&obj(r#"{"definition":{"name":"zzOvrFn","namespace":"ZzOvr"}}"#), &base).as_deref(), Some("ZzOvr.zzOvrFn"));
}

#[tokio::test]
async fn a_derived_schema_updates_without_restating_its_name() {
    let e = env();
    e.dir.chain(&[SYSTEM, "CLIA"]);
    let base = e.call("POST", "/api/ui/schemas", r#"{"appCode":"testapp","clientCode":"SYSTEM","definition":{"namespace":"Ns","name":"s","type":"OBJECT"}}"#).await;
    assert_eq!(base.status, StatusCode::OK, "{}", base.text());
    let derived = e.as_client("CLIA", "POST", "/api/ui/schemas", r#"{"appCode":"testapp","clientCode":"CLIA","baseClientCode":"SYSTEM","definition":{"namespace":"Ns","name":"s","type":"OBJECT"}}"#).await;
    assert_eq!(derived.status, StatusCode::OK, "{}", derived.text());
    let mut body = derived.obj();
    body.insert("definition".into(), JValue::Object(obj(r#"{"type":"STRING"}"#)));
    let r = e.as_client("CLIA", "PUT", &format!("/api/ui/schemas/{}", derived.id()), &to_compact(&JValue::Object(body))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
}

/// `AbstractFunctionServiceUpdateTest`, through the routes.
#[tokio::test]
async fn a_derived_function_updates_without_restating_its_name() {
    let e = env();
    e.dir.chain(&[SYSTEM, "CLIA"]);
    let base = e.call("POST", "/api/ui/functions", r#"{"appCode":"testapp","clientCode":"SYSTEM","definition":{"namespace":"ZzOvr","name":"zzOvrFn","steps":{}}}"#).await;
    assert_eq!(base.status, StatusCode::OK, "{}", base.text());
    let derived = e
        .as_client("CLIA", "POST", "/api/ui/functions", r#"{"appCode":"testapp","clientCode":"CLIA","baseClientCode":"SYSTEM","definition":{"namespace":"ZzOvr","name":"zzOvrFn","steps":{}}}"#)
        .await;
    assert_eq!(derived.status, StatusCode::OK, "{}", derived.text());
    let mut body = derived.obj();
    body.insert("definition".into(), JValue::Object(obj(r#"{"steps":{"a":{"statementName":"a","namespace":"System","name":"Print"}}}"#)));
    let r = e.as_client("CLIA", "PUT", &format!("/api/ui/functions/{}", derived.id()), &to_compact(&JValue::Object(body))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let mut body = r.obj();
    body.insert("definition".into(), JValue::Object(obj(r#"{"name":"other"}"#)));
    let r = e.as_client("CLIA", "PUT", &format!("/api/ui/functions/{}", derived.id()), &to_compact(&JValue::Object(body))).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "a rename is refused: {}", r.text());
}

// ── URI paths ───────────────────────────────────────────────────────

const KIRUN_GET: &str = r#"{"GET":{"uriType":"KIRUN_FUNCTION","kiRunFxDefinition":{"name":"f","namespace":"Ns"},"redirectionDefinition":{"targetUrl":"x"}}}"#;

#[tokio::test]
async fn uri_paths_are_named_validated_and_clear_the_pattern_cache() {
    let e = env();
    let post = |body: String| {
        let e = &e;
        async move { e.call("POST", "/api/ui/uripaths", &body).await }
    };
    let missing = post(r#"{"appCode":"testapp","clientCode":"SYSTEM"}"#.into()).await;
    assert_eq!((missing.status, missing.coded()), (StatusCode::BAD_REQUEST, ("UI.URI_PATH_STRING_NULL".into(), "Path string missing".into())));
    let short = post(format!(r#"{{"appCode":"testapp","clientCode":"SYSTEM","pathString":"/api/x","pathDefinitions":{KIRUN_GET}}}"#)).await;
    assert_eq!(short.status, StatusCode::BAD_REQUEST, "the generated name /<shortCode> does not match /api/x");
    assert!(short.coded().1.starts_with("Pattern: "), "{:?}", short.coded());
    assert_eq!(short.coded().0, "UI.URI_PATTERN_PATH_MISMATCH");
    let short_ok = post(format!(r#"{{"appCode":"testapp","clientCode":"SYSTEM","shortCode":"abc","pathString":"/abc","pathDefinitions":{KIRUN_GET}}}"#)).await;
    assert_eq!(short_ok.status, StatusCode::OK, "{}", short_ok.text());
    assert_eq!(str_field(&short_ok.obj(), "name"), Some("/abc"));
    let bad_type = post(r#"{"name":"/api/y","appCode":"testapp","clientCode":"SYSTEM","pathString":"/api/y","pathDefinitions":{"GET":{}}}"#.into()).await;
    assert_eq!((bad_type.status, bad_type.coded()), (StatusCode::BAD_REQUEST, ("UI.URI_INVALID_TYPE".into(), "Selected Invalid UriPath for given definitions.".into())));
    let bad_method = post(format!(r#"{{"name":"/api/y","appCode":"testapp","clientCode":"SYSTEM","pathString":"/api/y","pathDefinitions":{}}}"#, KIRUN_GET.replace("GET", "HEAD"))).await;
    assert_eq!(bad_method.coded(), ("UI.URI_INVALID_METHOD".into(), "Invalid method: Only GET, POST, PUT, PATCH and DELETE are supported.".into()));
    let no_defs = post(r#"{"name":"/api/y","appCode":"testapp","clientCode":"SYSTEM","pathString":"/api/y"}"#.into()).await;
    assert_eq!(no_defs.status, StatusCode::INTERNAL_SERVER_ERROR);

    e.warm("URIPatternCache", "testapp-SYSTEM").await;
    let made = post(format!(r#"{{"name":"/api/x/{{id}}","appCode":"testapp","clientCode":"SYSTEM","pathString":"/api/x/1","pathDefinitions":{KIRUN_GET}}}"#)).await;
    assert_eq!(made.status, StatusCode::OK, "{}", made.text());
    let m = made.obj();
    assert!(path(&m, &["pathDefinitions", "GET", "redirectionDefinition"]).is_none_or(JValue::is_null), "a function route drops its redirection");
    assert!(!e.is_warm("URIPatternCache", "testapp-SYSTEM").await);

    let redirect = post(r#"{"name":"/go","appCode":"testapp","clientCode":"SYSTEM","pathString":"/go","pathDefinitions":{"GET":{"uriType":"REDIRECTION","kiRunFxDefinition":{"name":"f"}}}}"#.into()).await;
    assert_eq!(redirect.status, StatusCode::OK, "{}", redirect.text());
    assert!(path(&redirect.obj(), &["pathDefinitions", "GET", "kiRunFxDefinition"]).is_none_or(JValue::is_null));

    let history = e.call("POST", &format!("/api/ui/versions/{}/query", made.id()), "{}").await;
    assert_eq!(arr(&history.obj()["content"]).map(Vec::len), Some(1), "a URI path's history is read with the application's authority");

    e.warm("URIPatternCache", "testapp-SYSTEM").await;
    let mut body = m.clone();
    body.insert("pathString".into(), s("/nope/1"));
    let r = e.call("PUT", &format!("/api/ui/uripaths/{}", made.id()), &to_compact(&JValue::Object(body))).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "an update is validated too");
    let mut body = m.clone();
    body.insert("pathString".into(), s("/api/x/2"));
    let r = e.call("PUT", &format!("/api/ui/uripaths/{}", made.id()), &to_compact(&JValue::Object(body))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(str_field(&r.obj(), "pathString"), Some("/api/x/2"));
    assert!(!e.is_warm("URIPatternCache", "testapp-SYSTEM").await);
    // The webhook flag (Rust only): kept on create, set by an update, a boolean or nothing.
    assert!(m.get("webhook").is_none_or(JValue::is_null));
    let mut body = r.obj();
    body.insert("webhook".into(), JValue::Bool(true));
    let r = e.call("PUT", &format!("/api/ui/uripaths/{}", made.id()), &to_compact(&JValue::Object(body))).await;
    assert_eq!(r.obj().get("webhook"), Some(&JValue::Bool(true)), "{}", r.text());
    let mut body = r.obj();
    body.insert("webhook".into(), s("yes"));
    let r = e.call("PUT", &format!("/api/ui/uripaths/{}", made.id()), &to_compact(&JValue::Object(body))).await;
    assert!(r.obj().get("webhook").is_none_or(JValue::is_null), "not a boolean: not a webhook");
    let hook = post(format!(r#"{{"name":"/api/hook","appCode":"testapp","clientCode":"SYSTEM","pathString":"/api/hook","webhook":true,"pathDefinitions":{KIRUN_GET}}}"#)).await;
    assert_eq!(hook.obj().get("webhook"), Some(&JValue::Bool(true)), "{}", hook.text());

    e.warm("URIPatternCache", "testapp-SYSTEM").await;
    let d = e.call("DELETE", &format!("/api/ui/uripaths/{}", made.id()), "").await;
    assert_eq!(d.text(), "true");
    assert!(!e.is_warm("URIPatternCache", "testapp-SYSTEM").await);
}

#[tokio::test]
async fn uri_paths_ask_for_the_application_authorities() {
    let e = env();
    let only_page = all_for("Page").join(",");
    let r = e
        .send("POST", "/api/ui/uripaths", Some(SYSTEM), &[("x-test-auth", &only_page)], &format!(r#"{{"name":"/a","appCode":"testapp","clientCode":"SYSTEM","pathString":"/a","pathDefinitions":{KIRUN_GET}}}"#))
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.text());
    let app_auth = all_for("Application").join(",");
    let r = e
        .send("POST", "/api/ui/uripaths", Some(SYSTEM), &[("x-test-auth", &app_auth)], &format!(r#"{{"name":"/a","appCode":"testapp","clientCode":"SYSTEM","pathString":"/a","pathDefinitions":{KIRUN_GET}}}"#))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
}

// ── Fillers ─────────────────────────────────────────────────────────

#[tokio::test]
async fn a_filler_delete_clears_every_clients_copy() {
    let e = env();
    let f = e.call("POST", "/api/ui/filler", r#"{"name":"testapp","appCode":"testapp","clientCode":"SYSTEM","values":{"a":1}}"#).await;
    assert_eq!(f.status, StatusCode::OK, "{}", f.text());
    e.warm("UIFillerCache_testapp_testapp", "OTHER").await;
    e.warm("UIFillerCache_testapp_testapp_DRAFT", "OTHER").await;
    let d = e.call("DELETE", &format!("/api/ui/filler/{}", f.id()), "").await;
    assert_eq!(d.status, StatusCode::OK, "{}", d.text());
    assert!(!e.is_warm("UIFillerCache_testapp_testapp", "OTHER").await);
    assert!(!e.is_warm("UIFillerCache_testapp_testapp_DRAFT", "OTHER").await);
}

// ── Drafts and publish evict the same caches ────────────────────────

#[tokio::test]
async fn a_draft_save_and_its_publish_clear_the_oui_caches() {
    let e = env();
    let p = e.call("POST", "/api/ui/pages", r#"{"name":"home","appCode":"testapp","clientCode":"SYSTEM","properties":{"title":"a"}}"#).await;
    let id = p.id();
    let watched = oui(APP)[..2].to_vec();
    e.warm_all(&watched).await;
    let mut body = p.obj();
    body.insert("properties".into(), JValue::Object(obj(r#"{"title":"b"}"#)));
    let d = e.call("PUT", &format!("/api/ui/pages/{id}?draft=true"), &to_compact(&JValue::Object(body))).await;
    assert_eq!(d.status, StatusCode::OK, "{}", d.text());
    assert_eq!(e.cold(&watched).await, watched);
    e.warm_all(&watched).await;
    let r = e.call("POST", &format!("/api/ui/pages/{id}/publish?message=go"), "").await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(e.cold(&watched).await, watched);
    let read = e.call("GET", &format!("/api/ui/pages/{id}"), "").await;
    assert_eq!(path(&read.obj(), &["properties", "title"]), Some(&s("b")));

    let u = e.call("POST", "/api/ui/uripaths", &format!(r#"{{"name":"/p","appCode":"testapp","clientCode":"SYSTEM","pathString":"/p","pathDefinitions":{KIRUN_GET}}}"#)).await;
    e.warm("URIPatternCache", "testapp-SYSTEM").await;
    let d = e.call("PUT", &format!("/api/ui/uripaths/{}?draft=true", u.id()), &u.text()).await;
    assert_eq!(d.status, StatusCode::OK, "{}", d.text());
    assert!(!e.is_warm("URIPatternCache", "testapp-SYSTEM").await);

    let a = e.call("POST", "/api/ui/applications", r#"{"name":"testapp","appCode":"testapp","clientCode":"SYSTEM"}"#).await;
    let watched = app_caches(APP);
    e.warm_all(&watched).await;
    let d = e.call("PUT", &format!("/api/ui/applications/{}?draft=true", a.id()), &a.text()).await;
    assert_eq!(d.status, StatusCode::OK, "{}", d.text());
    assert_eq!(e.cold(&watched).await, watched);
}

// ── DraftSaveEvictionIntegrationTest: ApplicationService.readProperties ──

async fn properties_title(e: &Env, state: &AppState, draft: bool) -> Option<JValue> {
    let caller = Caller { ca: auth_for(SYSTEM, &all_for("Application")), client_code: Some(SYSTEM.into()), app_code: Some(APP.into()), draft };
    let _ = e;
    Engine::new(state, &caller).read_properties(APP, SYSTEM).await.unwrap().get("title").cloned()
}

async fn draft_the_app(e: &Env, id: &str, title: &str) {
    let body = format!(r#"{{"id":"{id}","name":"testapp","appCode":"testapp","clientCode":"SYSTEM","version":1,"properties":{{"title":"{title}"}}}}"#);
    let r = e.call("PUT", &format!("/api/ui/applications/{id}?draft=true"), &body).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
}

fn stored_app(e: &Env, title: &str) -> String {
    e.insert_raw(&APPLICATION, "application", &format!(r#"{{"name":"testapp","appCode":"testapp","clientCode":"SYSTEM","version":1,"properties":{{"title":"{title}"}}}}"#))
}

#[tokio::test]
async fn read_properties_serves_a_draft_saved_after_the_surface_was_read() {
    let e = env();
    let state = e.engine_state();
    let id = stored_app(&e, "liveTitle");
    assert_eq!(properties_title(&e, &state, true).await, Some(s("liveTitle")));
    draft_the_app(&e, &id, "draftTitle").await;
    assert_eq!(properties_title(&e, &state, true).await, Some(s("draftTitle")), "the save evicted no draft cache");
    assert_eq!(properties_title(&e, &state, false).await, Some(s("liveTitle")), "the draft leaked onto the live surface");
}

#[tokio::test]
async fn read_properties_sees_a_second_save_over_an_existing_draft() {
    let e = env();
    let state = e.engine_state();
    let id = stored_app(&e, "liveTitle");
    draft_the_app(&e, &id, "first").await;
    assert_eq!(properties_title(&e, &state, true).await, Some(s("first")));
    draft_the_app(&e, &id, "second").await;
    assert_eq!(properties_title(&e, &state, true).await, Some(s("second")), "the draft surface froze on the first draft");
}

#[tokio::test]
async fn read_properties_sees_a_discarded_draft_go() {
    let e = env();
    let state = e.engine_state();
    let id = stored_app(&e, "liveTitle");
    draft_the_app(&e, &id, "draftTitle").await;
    assert_eq!(properties_title(&e, &state, true).await, Some(s("draftTitle")));
    let r = e.call("DELETE", &format!("/api/ui/applications/{id}/draft"), "").await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(properties_title(&e, &state, true).await, Some(s("liveTitle")), "the discarded draft was still served");
}

// ── CreateTimestampIntegrationTest ──────────────────────────────────

#[tokio::test]
async fn a_created_page_is_stamped_updated_at_its_creation() {
    let e = env();
    let r = e.call("POST", "/api/ui/pages", r#"{"name":"timestampPage","appCode":"testapp","clientCode":"SYSTEM"}"#).await;
    let c = r.obj();
    assert!(c.get("createdAt").is_some_and(|v| !v.is_null()));
    assert_eq!(c.get("createdAt"), c.get("updatedAt"), "one instant, not two now() calls");
    assert!(c.get("updatedBy").is_none_or(JValue::is_null));
}

#[tokio::test]
async fn a_create_carrying_another_environments_update_stamps_drops_them() {
    let e = env();
    let r = e
        .call(
            "POST",
            "/api/ui/pages",
            r#"{"name":"timestampPageFromTransport","appCode":"testapp","clientCode":"SYSTEM","updatedAt":"2020-01-01T00:00:00","updatedBy":"someone-on-another-environment"}"#,
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let c = r.obj();
    assert_eq!(c.get("createdAt"), c.get("updatedAt"));
    assert!(c.get("updatedBy").is_none_or(JValue::is_null));
    assert_ne!(c.get("updatedAt"), Some(&s("2020-01-01T00:00:00")));
}

// ── ObjectIndexIntegrationTest ──────────────────────────────────────

const MID: &str = "LZCLA";
const OUTSIDER: &str = "OTHERCL";

fn stored_page(e: &Env, name: &str, client: &str, base: Option<&str>, app: &str) -> String {
    let base = base.map(|b| format!(r#","baseClientCode":"{b}""#)).unwrap_or_default();
    e.insert_raw(&PAGE, "page", &format!(r#"{{"name":"{name}","appCode":"{app}","clientCode":"{client}","version":1{base}}}"#))
}

async fn index_as(e: &Env, client: &str, query: &str) -> JMap {
    let auth = all_for("Page").join(",");
    let r = e.send("GET", &format!("/api/ui/applications/{APP}/index{query}"), Some(client), &[("x-test-auth", &auth)], "").await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    r.obj()
}

fn pages_of(index: &JMap) -> Vec<JMap> {
    arr(&index["pages"]).unwrap().iter().map(|v| v.as_object().unwrap().clone()).collect()
}

fn named<'a>(rows: &'a [JMap], name: &str) -> Vec<&'a JMap> {
    rows.iter().filter(|r| str_field(r, "name") == Some(name)).collect()
}

#[tokio::test]
async fn index_lists_an_overridden_name_once_as_the_clients_copy() {
    let e = env();
    e.dir.chain(&[SYSTEM, MID]);
    stored_page(&e, "sharedPage", SYSTEM, None, APP);
    let over = stored_page(&e, "sharedPage", MID, Some(SYSTEM), APP);
    stored_page(&e, "baseOnlyPage", SYSTEM, None, APP);
    let pages = pages_of(&index_as(&e, MID, "?slim=true").await);
    assert_eq!(named(&pages, "sharedPage").len(), 1, "the base and the override are one object");
    assert_eq!(pages.len(), 2);
    let shared = named(&pages, "sharedPage")[0];
    assert_eq!(str_field(shared, "clientCode"), Some(MID));
    assert_eq!(str_field(shared, "id"), Some(over.as_str()));
    assert_eq!(named(&pages, "baseOnlyPage").len(), 1);
}

#[tokio::test]
async fn index_serves_the_base_copy_to_a_client_without_an_override() {
    let e = env();
    e.dir.chain(&[SYSTEM, MID]);
    let base = stored_page(&e, "sharedPage", SYSTEM, None, APP);
    let pages = pages_of(&index_as(&e, MID, "?slim=true").await);
    assert_eq!(pages.len(), 1);
    assert_eq!(str_field(&pages[0], "id"), Some(base.as_str()));
    assert_eq!(str_field(&pages[0], "clientCode"), Some(SYSTEM));
}

#[tokio::test]
async fn index_leaves_out_clients_outside_the_chain() {
    let e = env();
    e.dir.chain(&[SYSTEM, MID]);
    stored_page(&e, "sharedPage", SYSTEM, None, APP);
    stored_page(&e, "foreignPage", OUTSIDER, Some(SYSTEM), APP);
    let pages = pages_of(&index_as(&e, MID, "?slim=true").await);
    assert_eq!(pages.len(), 1, "only the chain's objects belong in the tree");
    assert!(named(&pages, "foreignPage").is_empty());
}

#[tokio::test]
async fn index_leaves_out_other_apps() {
    let e = env();
    stored_page(&e, "minePage", SYSTEM, None, APP);
    stored_page(&e, "theirsPage", SYSTEM, None, "otherapp");
    let pages = pages_of(&index_as(&e, SYSTEM, "?slim=true").await);
    assert_eq!(pages.len(), 1);
    assert_eq!(str_field(&pages[0], "name"), Some("minePage"));
}

#[tokio::test]
async fn index_names_the_client_it_resolved() {
    let e = env();
    e.dir.chain(&[SYSTEM, MID]);
    stored_page(&e, "sharedPage", SYSTEM, None, APP);
    let index = index_as(&e, MID, "?slim=true").await;
    assert_eq!(index.get("appCode"), Some(&s(APP)));
    assert_eq!(index.get("clientCode"), Some(&s(MID)));
}

#[tokio::test]
async fn index_keys_every_object_type() {
    let e = env();
    stored_page(&e, "minePage", SYSTEM, None, APP);
    let index = index_as(&e, SYSTEM, "?slim=true").await;
    for k in ["applications", "pages", "functions", "schemas", "themes", "styles", "uripaths"] {
        assert!(index.contains_key(k), "{k}");
    }
    assert_eq!(
        index.keys().cloned().collect::<Vec<_>>(),
        names(&["themes", "pages", "functions", "clientCode", "uripaths", "schemas", "styles", "appCode", "applications"]),
        "a HashMap's order"
    );
}

#[tokio::test]
async fn the_full_index_carries_each_pages_versions_and_the_internal_one_takes_a_client() {
    let e = env();
    let p = e
        .call("POST", "/api/ui/pages", r#"{"name":"home","appCode":"testapp","clientCode":"SYSTEM","componentDefinition":{"a":{"key":"a"}}}"#)
        .await;
    e.call("PUT", &format!("/api/ui/pages/{}", p.id()), &p.text()).await;
    let full = e.call("GET", "/api/ui/applications/testapp/index", "").await;
    let row = pages_of(&full.obj()).remove(0);
    assert_eq!(path(&row, &["componentVersions", "a"]), Some(&JValue::Int(1)));
    assert_eq!(row.keys().cloned().collect::<Vec<_>>(), names(&["eventFunctionVersions", "componentVersions", "clientCode", "name", "id", "title", "version"]));
    let slim = e.call("GET", "/api/ui/applications/testapp/index?slim=true", "").await;
    assert!(!pages_of(&slim.obj())[0].contains_key("componentVersions"));
    assert_eq!(e.call("GET", "/api/ui/applications/testapp/index?slim=maybe", "").await.status, StatusCode::BAD_REQUEST);
    let internal = e.call("GET", "/api/ui/applications/internal/index/testapp?forClientCode=SYSTEM", "").await;
    assert_eq!(internal.obj().get("clientCode"), Some(&s(SYSTEM)));
    assert_eq!(pages_of(&internal.obj()).len(), 1);
}

// ── Page components and events ──────────────────────────────────────

const COMPONENTS: &str = r#"{"name":"home","appCode":"testapp","clientCode":"SYSTEM","rootComponent":"root",
    "componentDefinition":{
        "root":{"key":"root","name":"root","type":"Grid","children":{"a":true,"b":false,"zz":true}},
        "a":{"key":"a","name":"a","type":"Grid","children":{"c":true}},
        "b":{"key":"b","name":"b","type":"Text"},
        "c":{"key":"c","name":"c","type":"Button","properties":{"label":{"value":"Go"}}}},
    "eventFunctions":{"onLoad":{"name":"onLoad","steps":{}}}}"#;

#[tokio::test]
async fn components_are_read_with_their_children_to_a_depth() {
    let e = env();
    let p = e.call("POST", "/api/ui/pages", COMPONENTS).await;
    let id = p.id();
    let keys = |d: &str| {
        let e = &e;
        let id = id.clone();
        let d = d.to_string();
        async move { e.call("GET", &format!("/api/ui/pages/{id}/components?{d}"), "").await.obj().keys().cloned().collect::<Vec<_>>() }
    };
    assert_eq!(keys("keys=root").await, names(&["root"]));
    assert_eq!(keys("keys=root&depth=1").await, names(&["root", "a"]));
    assert_eq!(keys("keys=root&depth=2").await, names(&["root", "a", "c"]));
    assert_eq!(keys("keys=c,b,nope").await, names(&["c", "b"]));
    assert_eq!(keys("keys=c&keys=a&depth=1").await, names(&["c", "a"]));
    let r = e.call("GET", &format!("/api/ui/pages/{id}/components"), "").await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    // Spring's refusal, named; Spring's text as the debug message, as Java's ControllerAdvice writes it.
    let o = r.obj();
    assert_eq!(r.message(), "The request is missing the keys parameter.");
    assert_eq!(o.get("code"), Some(&s("COMMON.PARAM_MISSING")));
    assert_eq!(o.get("debugMessage"), Some(&s("400 BAD_REQUEST \"Required query parameter 'keys' is not present.\"")));
    let r = e.call("GET", &format!("/api/ui/pages/{id}/components?keys=a&depth=x"), "").await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let c = e.call("GET", &format!("/api/ui/pages/{id}/components?keys=c"), "").await.obj();
    assert_eq!(path(&c, &["c", "properties", "label", "value"]), Some(&s("Go")));
    assert_eq!(e.call("GET", "/api/ui/pages/nope/components?keys=a", "").await.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_component_patch_replaces_its_fields_counts_the_edit_and_clears_the_page_caches() {
    let e = env();
    let p = e.call("POST", "/api/ui/pages", COMPONENTS).await;
    let id = p.id();
    let patch = |key: &str, body: &str| {
        let e = &e;
        let uri = format!("/api/ui/pages/{id}/components/{key}");
        let body = body.to_string();
        async move { e.call("PATCH", &uri, &body).await }
    };
    let missing = patch("nope", r#"{"componentData":{"properties":{}}}"#).await;
    assert_eq!((missing.status, missing.coded()), (StatusCode::NOT_FOUND, ("DEF.OBJECT_NOT_FOUND".into(), "Component with id nope not found".into())));
    assert_eq!(missing.message(), "We couldn't find the component with id nope.");
    let no_data = patch("c", r#"{"message":"m"}"#).await;
    assert_eq!(no_data.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(patch("c", "[]").await.status, StatusCode::BAD_REQUEST);
    assert_eq!(patch("c", r#"{"componentData":3}"#).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(patch("c", r#"{"expectedComponentVersion":"x"}"#).await.status, StatusCode::BAD_REQUEST);

    let watched = oui(APP)[..2].to_vec();
    e.warm_all(&watched).await;
    let ok = patch("c", r#"{"componentData":{"properties":{"label":{"value":"Stop"}},"type":"Ignored","displayOrder":3},"message":"edit"}"#).await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.text());
    let o = ok.obj();
    assert_eq!(path(&o, &["componentDefinition", "c", "properties", "label", "value"]), Some(&s("Stop")));
    assert_eq!(path(&o, &["componentDefinition", "c", "type"]), Some(&s("Button")), "only the patchable fields");
    assert_eq!(path(&o, &["componentDefinition", "c", "displayOrder"]), Some(&JValue::Int(3)));
    assert_eq!(path(&o, &["componentVersions", "c"]), Some(&JValue::Int(2)), "an unseen component counts from 1");
    assert_eq!(o.get("version"), Some(&JValue::Int(2)));
    assert_eq!(o.get("message"), Some(&s("edit")));
    assert_eq!(e.cold(&watched).await, watched, "the page caches go too (Java's patch leaves them)");

    let stale = patch("c", r#"{"componentData":{},"expectedComponentVersion":1}"#).await;
    assert_eq!(
        (stale.status, stale.coded()),
        (StatusCode::PRECONDITION_FAILED, ("DEF.VERSION_MISMATCH".into(), "Please reload to get the new version before making changes".into()))
    );
    let fresh = patch("c", r#"{"componentData":{},"expectedComponentVersion":2}"#).await;
    assert_eq!(fresh.status, StatusCode::OK, "{}", fresh.text());
    let read = e.call("GET", &format!("/api/ui/pages/{id}"), "").await.obj();
    assert_eq!(path(&read, &["componentVersions", "c"]), Some(&JValue::Int(3)));

    let refused = e.send("PATCH", &format!("/api/ui/pages/{id}/components/c"), Some(SYSTEM), &[("x-test-auth", "Authorities.Page_READ")], r#"{"componentData":{}}"#).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(patch("c", r#"{"componentData":{}}"#).await.status, StatusCode::OK);
    let unknown = e.call("PATCH", "/api/ui/pages/000000000000000000000000/components/c", r#"{"componentData":{}}"#).await;
    assert_eq!(unknown.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn event_functions_are_read_and_replaced_one_at_a_time() {
    let e = env();
    let p = e.call("POST", "/api/ui/pages", COMPONENTS).await;
    let id = p.id();
    let ev = e.call("GET", &format!("/api/ui/pages/{id}/events/onLoad"), "").await;
    assert_eq!(str_field(&ev.obj(), "name"), Some("onLoad"));
    let none = e.call("GET", &format!("/api/ui/pages/{id}/events/nope"), "").await;
    assert_eq!((none.status, none.body.len()), (StatusCode::NOT_FOUND, 0));
    assert!(none.headers.get("content-type").is_none());

    let put = e.call("PUT", &format!("/api/ui/pages/{id}/events/onClick"), r#"{"definition":{"name":"onClick","steps":{"s":{}}},"message":7}"#).await;
    assert_eq!(put.status, StatusCode::OK, "{}", put.text());
    let o = put.obj();
    assert_eq!(path(&o, &["eventFunctions", "onClick", "name"]), Some(&s("onClick")));
    assert_eq!(path(&o, &["eventFunctionVersions", "onClick"]), Some(&JValue::Int(2)));
    assert_eq!(o.get("message"), Some(&s("7")));
    let events = path(&o, &["eventFunctions"]).and_then(JValue::as_object).unwrap();
    assert_eq!(events.keys().cloned().collect::<Vec<_>>(), names(&["onLoad", "onClick"]), "a stored map keeps its order, the new key last");
    let stale = e.call("PUT", &format!("/api/ui/pages/{id}/events/onClick"), r#"{"definition":{},"expectedEventVersion":1}"#).await;
    assert_eq!(stale.status, StatusCode::PRECONDITION_FAILED);
    let cleared = e.call("PUT", &format!("/api/ui/pages/{id}/events/onClick"), r#"{"expectedEventVersion":2}"#).await;
    assert_eq!(cleared.status, StatusCode::OK, "{}", cleared.text());
    assert_eq!(path(&cleared.obj(), &["eventFunctions", "onClick"]), Some(&JValue::Null), "a null definition is kept as a null entry");
    assert_eq!(e.call("PUT", &format!("/api/ui/pages/{id}/events/x"), r#"{"message":{}}"#).await.status, StatusCode::BAD_REQUEST);
}

// ── PageComponentPatchAuthorizationIntegrationTest ──────────────────

const BASE: &str = "LZBASE";
const DERIVED: &str = "LZDERIV";
const COMP_KEY: &str = "btnSubmit";

fn patch_page(e: &Env, client: &str, base: Option<&str>, label: Option<&str>) -> String {
    let base = base.map(|b| format!(r#","baseClientCode":"{b}""#)).unwrap_or_default();
    let comps = label
        .map(|l| format!(r#","componentDefinition":{{"{COMP_KEY}":{{"key":"{COMP_KEY}","name":"{COMP_KEY}","type":"Button","properties":{{"label":"{l}"}}}}}}"#))
        .unwrap_or_default();
    e.insert_raw(&PAGE, "page", &format!(r#"{{"name":"testPage","appCode":"testapp","clientCode":"{client}","version":1,"rootComponent":"rootComp"{base}{comps}}}"#))
}

async fn patch_label(e: &Env, id: &str, client: &str, label: &str) -> Answer {
    let auth = all_for("Page").join(",");
    let body = format!(r#"{{"componentData":{{"properties":{{"label":"{label}"}}}},"expectedComponentVersion":0,"message":"m"}}"#);
    e.send("PATCH", &format!("/api/ui/pages/{id}/components/{COMP_KEY}"), Some(client), &[("x-test-auth", &auth)], &body).await
}

fn label_of(page: &JMap) -> Option<JValue> {
    path(page, &["componentDefinition", COMP_KEY, "properties", "label"]).cloned()
}

#[tokio::test]
async fn a_derived_client_patching_its_bases_page_is_refused_and_the_page_untouched() {
    let e = env();
    e.dir.isolate_tenants();
    e.dir.set(|a| a.write_access = false);
    e.dir.chain(&[BASE, DERIVED]);
    let base = patch_page(&e, BASE, None, Some("Base label"));
    let r = patch_label(&e, &base, DERIVED, "hijacked").await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "a read-level check gated a write: {}", r.text());
    assert_eq!(label_of(&e.raw(&PAGE, "page", &base)), Some(s("Base label")));
}

#[tokio::test]
async fn a_patch_finds_a_component_only_the_base_has() {
    let e = env();
    e.dir.chain(&[BASE, DERIVED]);
    patch_page(&e, BASE, None, Some("Base label"));
    let derived = patch_page(&e, DERIVED, Some(BASE), None);
    let r = patch_label(&e, &derived, DERIVED, "Derived label").await;
    assert_eq!(r.status, StatusCode::OK, "patching an inherited component 404d: {}", r.text());
}

#[tokio::test]
async fn a_patch_keeps_the_derived_row_a_delta() {
    let e = env();
    e.dir.chain(&[BASE, DERIVED]);
    let base = patch_page(&e, BASE, None, Some("Base label"));
    let derived = patch_page(&e, DERIVED, Some(BASE), None);
    assert_eq!(patch_label(&e, &derived, DERIVED, "Derived label").await.status, StatusCode::OK);
    let stored = e.raw(&PAGE, "page", &derived);
    assert_eq!(str_field(&stored, "baseClientCode"), Some(BASE), "the derived row lost its base");
    assert!(stored.get("rootComponent").is_none_or(JValue::is_null), "the merged page was written over the delta");
    assert_eq!(label_of(&stored), Some(s("Derived label")));
    assert_eq!(label_of(&e.raw(&PAGE, "page", &base)), Some(s("Base label")), "patching the derived page wrote into the base");
}

#[tokio::test]
async fn a_patched_derived_page_keeps_inheriting() {
    let e = env();
    e.dir.chain(&[BASE, DERIVED]);
    let base = patch_page(&e, BASE, None, Some("Base label"));
    let derived = patch_page(&e, DERIVED, Some(BASE), None);
    assert_eq!(patch_label(&e, &derived, DERIVED, "Derived label").await.status, StatusCode::OK);

    // The base changes something the derived client never touched (written as the Java test
    // does, straight to the row, then the definition caches cleared as its save would).
    let mut row = e.raw(&PAGE, "page", &base);
    row.insert("rootComponent".into(), s("newRootFromBase"));
    let d = to_document(&PAGE, &row, None, &[]);
    use overridable::backend::Backend;
    e.mem.replace("page", overridable::write::persist::id_bson(&base), d).await.unwrap();
    e.cache.clear_local();

    let auth = all_for("Page").join(",");
    let merged = e.send("GET", &format!("/api/ui/pages/{derived}"), Some(DERIVED), &[("x-test-auth", &auth)], "").await.obj();
    assert_eq!(merged.get("rootComponent"), Some(&s("newRootFromBase")), "the derived row froze a snapshot of the base");
    assert_eq!(label_of(&merged), Some(s("Derived label")), "the derived client's own edit was lost");
}

// ── PageClientPatchIntegrationTest ──────────────────────────────────
// Component-level page changes made FOR a client: the id names the page, `clientCode` names
// whose copy changes. SYSTEM owns the app, CP_MID is managed by SYSTEM, LEAF by CP_MID.

const CP_MID: &str = "LZMID";
const LEAF: &str = "LZLEAF";
const CP_PAGE: &str = "clientPatchPage";

fn client_patch_env() -> Env {
    let e = env();
    e.dir.chain(&[SYSTEM, CP_MID, LEAF]);
    e.dir.hierarchy(CP_MID, &[CP_MID, SYSTEM]);
    e.dir.hierarchy(LEAF, &[LEAF, CP_MID, SYSTEM]);
    e
}

/// SYSTEM's page: a root grid holding a text and a button.
fn system_page(e: &Env) -> String {
    e.insert_raw(
        &PAGE,
        "page",
        &format!(
            r#"{{"name":"{CP_PAGE}","appCode":"{APP}","clientCode":"{SYSTEM}","version":1,"rootComponent":"root","componentDefinition":{{
                "root":{{"key":"root","name":"root","type":"Grid","children":{{"txt":true,"btn":true}}}},
                "txt":{{"key":"txt","name":"txt","type":"Text","properties":{{"text":"Hello"}}}},
                "btn":{{"key":"btn","name":"btn","type":"Button","properties":{{"label":"Submit"}}}}}}}}"#
        ),
    )
}

fn stored_for(e: &Env, client: &str) -> Vec<JMap> {
    e.mem
        .all("page")
        .iter()
        .map(|d| overridable::pojo::decode_bson(&PAGE, d))
        .filter(|p| str_field(p, "name") == Some(CP_PAGE) && str_field(p, "clientCode") == Some(client))
        .collect()
}

fn btn_label(page: &JMap) -> Option<JValue> {
    path(page, &["componentDefinition", "btn", "properties", "label"]).cloned()
}

fn component_keys(page: &JMap) -> Vec<String> {
    let mut k: Vec<String> = page.get("componentDefinition").and_then(JValue::as_object).map(|m| m.keys().cloned().collect()).unwrap_or_default();
    k.sort();
    k
}

async fn patch_for(e: &Env, caller: &str, id: &str, key: &str, data: &str, query: &str) -> Answer {
    let body = format!(r#"{{"componentData":{data},"expectedComponentVersion":0,"message":"m"}}"#);
    e.as_client(caller, "PATCH", &format!("/api/ui/pages/{id}/components/{key}{query}"), &body).await
}

fn label_data(label: &str) -> String {
    format!(r#"{{"properties":{{"label":"{label}"}}}}"#)
}

#[tokio::test]
async fn no_target_changes_the_page_with_that_id() {
    let e = client_patch_env();
    let base = system_page(&e);
    assert_eq!(patch_for(&e, SYSTEM, &base, "btn", &label_data("Go"), "").await.status, StatusCode::OK);
    assert_eq!(btn_label(&stored_for(&e, SYSTEM)[0]), Some(s("Go")));
    assert!(stored_for(&e, CP_MID).is_empty());
}

#[tokio::test]
async fn a_target_with_no_copy_gets_one_on_its_base_holding_only_the_change() {
    let e = client_patch_env();
    let base = system_page(&e);
    let r = patch_for(&e, SYSTEM, &base, "btn", &label_data("Go MID"), &format!("?clientCode={CP_MID}")).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(btn_label(&r.obj()), Some(s("Go MID")));
    assert_eq!(btn_label(&stored_for(&e, SYSTEM)[0]), Some(s("Submit")), "the owner's page is untouched");
    let mid = &stored_for(&e, CP_MID)[0];
    assert_eq!(str_field(mid, "baseClientCode"), Some(SYSTEM));
    assert_eq!(component_keys(mid), vec!["btn"], "only the changed component is stored");
}

#[tokio::test]
async fn a_target_with_its_own_copy_has_that_copy_changed() {
    let e = client_patch_env();
    let base = system_page(&e);
    let q = format!("?clientCode={CP_MID}");
    assert_eq!(patch_for(&e, SYSTEM, &base, "btn", &label_data("one"), &q).await.status, StatusCode::OK);
    let again = patch_for(&e, SYSTEM, &base, "txt", r#"{"properties":{"text":"Hi MID"}}"#, &q).await;
    assert_eq!(again.status, StatusCode::OK, "{}", again.text());
    assert_eq!(stored_for(&e, CP_MID).len(), 1);
    let again = again.obj();
    assert_eq!(btn_label(&again), Some(s("one")));
    assert_eq!(path(&again, &["componentDefinition", "txt", "properties", "text"]), Some(&s("Hi MID")));
}

#[tokio::test]
async fn a_base_level_with_no_copy_is_stored_as_a_difference_and_followed() {
    let e = client_patch_env();
    let base = system_page(&e);
    let r = patch_for(&e, SYSTEM, &base, "btn", &label_data("Go LEAF"), &format!("?clientCode={LEAF}")).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let leaf = stored_for(&e, LEAF)[0].clone();
    assert_eq!(str_field(&leaf, "baseClientCode"), Some(CP_MID));
    assert_eq!(component_keys(&leaf), vec!["btn"]);
    assert_eq!(patch_for(&e, SYSTEM, &base, "txt", r#"{"properties":{"text":"Hello 2"}}"#, "").await.status, StatusCode::OK);
    let merged = e.as_client(LEAF, "GET", &format!("/api/ui/pages/{}", str_field(&leaf, "id").unwrap()), "").await.obj();
    assert_eq!(path(&merged, &["componentDefinition", "txt", "properties", "text"]), Some(&s("Hello 2")));
    assert_eq!(btn_label(&merged), Some(s("Go LEAF")));
}

#[tokio::test]
async fn standalone_the_targets_copy_has_no_base_and_holds_the_whole_page() {
    let e = client_patch_env();
    let base = system_page(&e);
    let r = patch_for(&e, SYSTEM, &base, "btn", &label_data("Own"), &format!("?clientCode={CP_MID}&standalone=true")).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let mid = &stored_for(&e, CP_MID)[0];
    assert!(mid.get("baseClientCode").is_none_or(JValue::is_null));
    assert_eq!(component_keys(mid), vec!["btn", "root", "txt"]);
}

#[tokio::test]
async fn remove_for_a_target_takes_it_from_the_targets_page_only() {
    let e = client_patch_env();
    let base = system_page(&e);
    let r = e.call("DELETE", &format!("/api/ui/pages/{base}/components/txt?message=m&clientCode={CP_MID}"), "").await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let page = r.obj();
    assert!(path(&page, &["componentDefinition", "txt"]).is_none());
    assert!(path(&page, &["componentDefinition", "root", "children", "txt"]).is_none());
    let sys = &stored_for(&e, SYSTEM)[0];
    assert!(path(sys, &["componentDefinition", "txt"]).is_some(), "the owner keeps it");
    assert!(path(sys, &["componentDefinition", "root", "children", "txt"]).is_some());
    // The root and a missing key are refused.
    let root = e.call("DELETE", &format!("/api/ui/pages/{base}/components/root"), "").await;
    assert_eq!((root.status, root.coded()), (StatusCode::BAD_REQUEST, ("UI.ROOT_COMPONENT_NOT_REMOVABLE".into(), "Cannot update this object".into())));
    assert_eq!(e.call("DELETE", &format!("/api/ui/pages/{base}/components/nope"), "").await.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn remove_takes_the_subtree_and_counts_the_parents_edit() {
    let e = client_patch_env();
    let base = system_page(&e);
    let add = |key: &str, parent: &str| {
        format!(r#"{{"componentKey":"{key}","componentData":{{"type":"Grid","name":"{key}"}},"parentKey":"{parent}","message":"m"}}"#)
    };
    assert_eq!(e.call("POST", &format!("/api/ui/pages/{base}/components"), &add("box", "root")).await.status, StatusCode::OK);
    assert_eq!(e.call("POST", &format!("/api/ui/pages/{base}/components"), &add("inner", "box")).await.status, StatusCode::OK);
    let r = e.call("DELETE", &format!("/api/ui/pages/{base}/components/box"), "").await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let page = r.obj();
    assert_eq!(component_keys(&page), vec!["btn", "root", "txt"]);
    assert!(path(&page, &["componentVersions", "box"]).is_none() && path(&page, &["componentVersions", "inner"]).is_none());
    assert_eq!(path(&page, &["componentVersions", "root"]), Some(&JValue::Int(3)), "one add and one remove under root");
    assert!(page.get("message").is_none_or(JValue::is_null), "no message parameter, no message");
}

#[tokio::test]
async fn add_for_a_target_puts_it_on_the_targets_page_only() {
    let e = client_patch_env();
    let base = system_page(&e);
    let body = r#"{"componentKey":"extra","componentData":{"type":"Text","name":"extra","properties":{"text":"only MID"}},"parentKey":"root","message":"m"}"#;
    let r = e.call("POST", &format!("/api/ui/pages/{base}/components?clientCode={CP_MID}"), body).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let page = r.obj();
    assert_eq!(path(&page, &["componentDefinition", "extra", "key"]), Some(&s("extra")));
    assert_eq!(path(&page, &["componentDefinition", "root", "children", "extra"]), Some(&JValue::Bool(true)));
    assert!(path(&stored_for(&e, SYSTEM)[0], &["componentDefinition", "extra"]).is_none());
    // A key the page has, and a parent it has not.
    let dup = r#"{"componentKey":"btn","componentData":{"type":"Text"},"parentKey":"root"}"#;
    assert_eq!(e.call("POST", &format!("/api/ui/pages/{base}/components"), dup).await.status, StatusCode::CONFLICT);
    let orphan = r#"{"componentKey":"x","componentData":{"type":"Text"},"parentKey":"nope"}"#;
    assert_eq!(e.call("POST", &format!("/api/ui/pages/{base}/components"), orphan).await.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn an_event_function_for_a_target_is_stored_in_the_targets_copy() {
    let e = client_patch_env();
    let base = system_page(&e);
    let body = r#"{"definition":{"name":"onSubmit","steps":{}},"expectedEventVersion":0,"message":"m"}"#;
    let r = e.call("PUT", &format!("/api/ui/pages/{base}/events/onSubmit?clientCode={CP_MID}"), body).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert!(path(&r.obj(), &["eventFunctions", "onSubmit"]).is_some());
    assert!(path(&stored_for(&e, SYSTEM)[0], &["eventFunctions", "onSubmit"]).is_none());
    assert!(path(&stored_for(&e, CP_MID)[0], &["eventFunctions", "onSubmit"]).is_some());
}

#[tokio::test]
async fn a_caller_that_does_not_manage_the_target_is_refused_and_nothing_written() {
    let e = client_patch_env();
    let base = system_page(&e);
    e.dir.isolate_tenants();
    let r = patch_for(&e, "OTHER", &base, "btn", &label_data("x"), &format!("?clientCode={LEAF}")).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.text());
    assert!(stored_for(&e, LEAF).is_empty());
    assert_eq!(btn_label(&stored_for(&e, SYSTEM)[0]), Some(s("Submit")));
    // An unknown page id, for a target: Java's empty result, a 403.
    let r = patch_for(&e, SYSTEM, "000000000000000000000000", "btn", &label_data("x"), &format!("?clientCode={CP_MID}")).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_draft_for_a_target_is_an_unpublished_copy_then_that_copys_draft() {
    let e = client_patch_env();
    let base = system_page(&e);
    let q = format!("?clientCode={CP_MID}&draft=true");
    let first = patch_for(&e, SYSTEM, &base, "btn", &label_data("Draft MID"), &q).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.text());
    assert_eq!(btn_label(&first.obj()), Some(s("Draft MID")));
    let mid = &stored_for(&e, CP_MID)[0];
    assert_eq!(mid.get("published"), Some(&JValue::Bool(false)), "never published: hidden from the live surface");
    assert_eq!(str_field(mid, "baseClientCode"), Some(SYSTEM));
    assert_eq!(btn_label(&stored_for(&e, SYSTEM)[0]), Some(s("Submit")));
    let second = patch_for(&e, SYSTEM, &base, "txt", r#"{"properties":{"text":"Draft text"}}"#, &q).await;
    assert_eq!(second.status, StatusCode::OK, "{}", second.text());
    assert_eq!(path(&second.obj(), &["componentDefinition", "txt", "properties", "text"]), Some(&s("Draft text")));
    assert_eq!(stored_for(&e, CP_MID).len(), 1);
    // The unpublished copy is real unpublished work: it publishes like any draft.
    let mid_id = str_field(mid, "id").unwrap().to_string();
    let p = e.call("POST", &format!("/api/ui/pages/{mid_id}/publish?message=publish%20MID"), "").await;
    assert_eq!(p.status, StatusCode::OK, "{}", p.text());
    let live = &stored_for(&e, CP_MID)[0];
    assert_eq!(live.get("published"), Some(&JValue::Bool(true)));
    let merged = e.as_client(CP_MID, "GET", &format!("/api/ui/pages/{mid_id}"), "").await.obj();
    assert_eq!(btn_label(&merged), Some(s("Draft MID")));
    assert_eq!(path(&merged, &["componentDefinition", "txt", "properties", "text"]), Some(&s("Draft text")));
}

// ── A client's page draft published over a SYSTEM page that moved (Rust only) ──
// QA-0637 (NAGEN5): the client's draft held the whole merged page, and its publish stored every
// change SYSTEM shipped while the draft was open as the client's override: old styles, and
// deletions of the components SYSTEM added. Only the client's own edits may be stored.

fn color_style(color: &str) -> String {
    format!(r#"{{"styleProperties":{{"s1":{{"resolutions":{{"ALL":{{"color":{{"value":"{color}"}}}}}}}}}}}}"#)
}

fn txt_color(page: &JMap) -> Option<JValue> {
    path(page, &["componentDefinition", "txt", "styleProperties", "s1", "resolutions", "ALL", "color", "value"]).cloned()
}

/// SYSTEM's page with a styled text, and CP_MID's published copy overriding the button label.
async fn system_and_client_copy(e: &Env) -> (String, String) {
    let base = system_page(e);
    assert_eq!(patch_for(e, SYSTEM, &base, "txt", &color_style("red"), "").await.status, StatusCode::OK);
    assert_eq!(patch_for(e, SYSTEM, &base, "btn", &label_data("Client label"), &format!("?clientCode={CP_MID}")).await.status, StatusCode::OK);
    let mid = str_field(&stored_for(e, CP_MID)[0], "id").unwrap().to_string();
    (base, mid)
}

/// The client's editor: reads its draft view, changes it, saves it as the whole page.
async fn client_draft(e: &Env, mid: &str, change: impl FnOnce(&mut JMap)) {
    let r = e.as_client(CP_MID, "GET", &format!("/api/ui/pages/{mid}?draft=true"), "").await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let mut page = r.obj();
    change(&mut page);
    let r = e.as_client(CP_MID, "PUT", &format!("/api/ui/pages/{mid}?draft=true"), &to_compact(&JValue::Object(page))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
}

/// SYSTEM ships after the client's draft started: a style change and a new component.
async fn system_ships(e: &Env, base: &str) {
    assert_eq!(patch_for(e, SYSTEM, base, "txt", &color_style("blue"), "").await.status, StatusCode::OK);
    let add = r#"{"componentKey":"extra","componentData":{"type":"Text","name":"extra","properties":{"text":"New from SYSTEM"}},"parentKey":"root","message":"m"}"#;
    assert_eq!(e.call("POST", &format!("/api/ui/pages/{base}/components"), add).await.status, StatusCode::OK);
}

async fn publish_as_client(e: &Env, mid: &str) -> JMap {
    let r = e.as_client(CP_MID, "POST", &format!("/api/ui/pages/{mid}/publish"), "").await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    e.as_client(CP_MID, "GET", &format!("/api/ui/pages/{mid}"), "").await.obj()
}

fn comp_mut<'a>(page: &'a mut JMap, key: &str) -> &'a mut JMap {
    page.get_mut("componentDefinition").and_then(|c| c.as_object_mut()).and_then(|c| c.get_mut(key)).and_then(|c| c.as_object_mut()).unwrap()
}

#[tokio::test]
async fn a_client_draft_publish_stores_only_the_clients_edit_and_system_changes_show_through() {
    let e = client_patch_env();
    let (base, mid) = system_and_client_copy(&e).await;
    client_draft(&e, &mid, |p| {
        comp_mut(p, "txt").insert("properties".into(), JValue::Object(obj(r#"{"text":"Client text"}"#)));
    })
    .await;
    system_ships(&e, &base).await;
    let merged = publish_as_client(&e, &mid).await;
    assert_eq!(txt_color(&merged), Some(s("blue")), "SYSTEM's style change shows through");
    assert_eq!(path(&merged, &["componentDefinition", "extra", "properties", "text"]), Some(&s("New from SYSTEM")));
    assert_eq!(path(&merged, &["componentDefinition", "root", "children", "extra"]), Some(&JValue::Bool(true)));
    assert_eq!(path(&merged, &["componentDefinition", "txt", "properties", "text"]), Some(&s("Client text")));
    assert_eq!(btn_label(&merged), Some(s("Client label")), "the client's earlier override survives");
    let stored = &stored_for(&e, CP_MID)[0];
    assert_eq!(component_keys(stored), vec!["btn", "txt"], "no SYSTEM component pinned, none deleted");
    let txt = path(stored, &["componentDefinition", "txt"]).and_then(JValue::as_object).unwrap();
    assert!(map_is_empty(txt.get("styleProperties")), "the old style is not stored: {:?}", txt.get("styleProperties"));
    // A later SYSTEM change still reaches the client.
    assert_eq!(patch_for(&e, SYSTEM, &base, "txt", &color_style("green"), "").await.status, StatusCode::OK);
    let again = e.as_client(CP_MID, "GET", &format!("/api/ui/pages/{mid}"), "").await.obj();
    assert_eq!(txt_color(&again), Some(s("green")));
}

#[tokio::test]
async fn a_client_draft_deleting_a_component_keeps_the_deletion_and_systems_addition() {
    let e = client_patch_env();
    let (base, mid) = system_and_client_copy(&e).await;
    client_draft(&e, &mid, |p| {
        p.get_mut("componentDefinition").and_then(|c| c.as_object_mut()).unwrap().shift_remove("btn");
        comp_mut(p, "root").get_mut("children").and_then(|c| c.as_object_mut()).unwrap().shift_remove("btn");
    })
    .await;
    system_ships(&e, &base).await;
    let merged = publish_as_client(&e, &mid).await;
    assert!(path(&merged, &["componentDefinition", "btn"]).is_none(), "the client's deletion is kept");
    assert!(path(&merged, &["componentDefinition", "root", "children", "btn"]).is_none());
    assert_eq!(path(&merged, &["componentDefinition", "root", "children", "extra"]), Some(&JValue::Bool(true)), "SYSTEM's new child is not deleted");
    assert!(path(&merged, &["componentDefinition", "extra"]).is_some());
    assert_eq!(txt_color(&merged), Some(s("blue")));
}

#[tokio::test]
async fn a_client_draft_changing_what_system_also_changed_wins() {
    let e = client_patch_env();
    let (base, mid) = system_and_client_copy(&e).await;
    client_draft(&e, &mid, |p| {
        let style = obj(&color_style("purple"));
        comp_mut(p, "txt").insert("styleProperties".into(), style["styleProperties"].clone());
    })
    .await;
    system_ships(&e, &base).await;
    let merged = publish_as_client(&e, &mid).await;
    assert_eq!(txt_color(&merged), Some(s("purple")), "the client's own change wins");
    assert!(path(&merged, &["componentDefinition", "extra"]).is_some(), "the rest of SYSTEM's ship shows through");
    let stored = &stored_for(&e, CP_MID)[0];
    assert_eq!(component_keys(stored), vec!["btn", "txt"]);
    assert!(str_field(stored, "message").unwrap_or("").contains("draft kept over live at componentDefinition.txt.styleProperties"), "{:?}", stored.get("message"));
}

fn map_is_empty(v: Option<&JValue>) -> bool {
    match v {
        None | Some(JValue::Null) => true,
        Some(JValue::Object(m)) => m.is_empty(),
        _ => false,
    }
}

#[tokio::test]
async fn the_seed_is_read_as_the_page_service_reads_it() {
    let e = client_patch_env();
    let id = e.insert_raw(
        &PAGE,
        "page",
        &format!(r#"{{"name":"{CP_PAGE}","appCode":"{APP}","clientCode":"{SYSTEM}","version":1,"permission":"Authorities.Secret_READ","componentDefinition":{{"btn":{{"key":"btn","properties":{{"label":"S"}}}}}}}}"#),
    );
    // A caller without the page's permission, and no forbidden page in the app: refused.
    let auth = all_for("Page").join(",");
    let body = format!(r#"{{"componentData":{},"expectedComponentVersion":0}}"#, label_data("x"));
    let r = e
        .send("PATCH", &format!("/api/ui/pages/{id}/components/btn?clientCode={CP_MID}"), Some(SYSTEM), &[("x-test-auth", &auth)], &body)
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.text());
    assert_eq!(r.coded(), ("UI.PAGE_PERMISSION_REQUIRED".into(), "Permission/Role Authorities.Secret_READ is required to use this operation ".into()));
    assert!(stored_for(&e, CP_MID).is_empty());
    // With the authority, the copy is made.
    let r = e
        .send("PATCH", &format!("/api/ui/pages/{id}/components/btn?clientCode={CP_MID}"), Some(SYSTEM), &[("x-test-auth", &format!("{auth},Authorities.Secret_READ"))], &body)
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    // A bad flag is Spring's type mismatch.
    let r = e.call("PATCH", &format!("/api/ui/pages/{id}/components/btn?draft=maybe"), &body).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_client_with_no_copy_on_its_own_url_is_served_its_managing_clients_customization() {
    let e = client_patch_env();
    let base = system_page(&e);
    assert_eq!(patch_for(&e, SYSTEM, &base, "btn", &label_data("CP_MID label"), &format!("?clientCode={CP_MID}")).await.status, StatusCode::OK);
    // LEAF on its own URL: app inheritance alone is [SYSTEM, LEAF], which skipped CP_MID.
    e.dir.chain(&[SYSTEM, LEAF]);
    let leaf_view = e.store.read(&ui::docs::PageDoc, CP_PAGE, APP, LEAF, LEAF, false).await.unwrap().unwrap();
    assert_eq!(btn_label(&leaf_view.entity), Some(s("CP_MID label")));
}

#[tokio::test]
async fn a_caller_that_cannot_read_the_page_named_by_the_id_is_refused_before_anything_is_looked_up() {
    let e = client_patch_env();
    let base = system_page(&e);
    e.dir.isolate_tenants();
    e.dir.set(|a| a.read_access = false);
    let r = patch_for(&e, "OTHER", &base, "btn", &label_data("x"), "?clientCode=OTHER").await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.text());
    assert!(stored_for(&e, "OTHER").is_empty(), "nothing created for the caller");
    assert_eq!(btn_label(&stored_for(&e, SYSTEM)[0]), Some(s("Submit")));
}

#[tokio::test]
async fn a_draft_on_another_clients_copy_without_update_on_it_is_refused_without_a_fork() {
    let e = client_patch_env();
    let base = system_page(&e);
    // SYSTEM manages everyone; LEAF can read the page (it is in the chain) but manages nobody.
    e.dir.set(|a| {
        a.manages_all = false;
        a.managers.insert(SYSTEM.into());
    });
    assert_eq!(patch_for(&e, SYSTEM, &base, "btn", &label_data("MID own"), &format!("?clientCode={CP_MID}")).await.status, StatusCode::OK);
    let drafts = e.mem.all("draft").len();
    let r = patch_for(&e, LEAF, &base, "btn", &label_data("leaf draft"), &format!("?clientCode={CP_MID}&draft=true")).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.text());
    assert!(stored_for(&e, LEAF).is_empty(), "the draft save's fork-for-caller must not run");
    assert_eq!(e.mem.all("draft").len(), drafts, "no draft row written");
    assert_eq!(btn_label(&stored_for(&e, CP_MID)[0]), Some(s("MID own")));
}

#[tokio::test]
async fn without_write_access_to_the_app_every_write_path_is_refused() {
    let e = client_patch_env();
    let base = system_page(&e);
    assert_eq!(patch_for(&e, SYSTEM, &base, "btn", &label_data("MID own"), &format!("?clientCode={CP_MID}")).await.status, StatusCode::OK);
    // Every Page authority and it manages both targets; only the app write access is gone.
    e.dir.set(|a| a.write_access = false);
    for (target, draft, what) in [(LEAF, false, "create of LEAF's copy"), (CP_MID, false, "live change to MID's own copy"), (CP_MID, true, "draft change to MID's own copy")] {
        let r = patch_for(&e, SYSTEM, &base, "btn", &label_data("x"), &format!("?clientCode={target}&draft={draft}")).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{what}: {}", r.text());
    }
    assert!(stored_for(&e, LEAF).is_empty());
    assert_eq!(btn_label(&stored_for(&e, CP_MID)[0]), Some(s("MID own")));
}

/// Java commit 7a1766ef6: the client being customized needs write access to the app too.
#[tokio::test]
async fn the_client_being_customized_needs_write_access_to_the_app_too() {
    let e = client_patch_env();
    let base = system_page(&e);
    assert_eq!(patch_for(&e, SYSTEM, &base, "btn", &label_data("MID own"), &format!("?clientCode={CP_MID}")).await.status, StatusCode::OK);
    // The caller (SYSTEM) keeps write access; the targets are read-only clients.
    e.dir.set(|a| {
        a.write_by.insert((APP.into(), LEAF.into()), false);
        a.write_by.insert((APP.into(), CP_MID.into()), false);
    });
    let r = patch_for(&e, SYSTEM, &base, "btn", &label_data("x"), &format!("?clientCode={LEAF}")).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "no copy may be created for a read-only client: {}", r.text());
    let r = patch_for(&e, SYSTEM, &base, "btn", &label_data("x"), &format!("?clientCode={CP_MID}")).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "a read-only client's existing copy may not be changed: {}", r.text());
    assert!(stored_for(&e, LEAF).is_empty());
    assert_eq!(btn_label(&stored_for(&e, CP_MID)[0]), Some(s("MID own")));
    // Reading is not customizing: the manager can still read it.
    let mid_id = str_field(&stored_for(&e, CP_MID)[0], "id").unwrap().to_string();
    let read = e.call("GET", &format!("/api/ui/pages/{mid_id}"), "").await;
    assert_eq!(read.status, StatusCode::OK, "{}", read.text());
    assert_eq!(btn_label(&read.obj()), Some(s("MID own")));
}

// ── SharedHostServedClientIntegrationTest ───────────────────────────
// What a signed-in user is served on a shared host (Java commit e2b7d48aa). The browser names
// no client, so the gateway sends the host's (SYSTEM): clientCode = the host, the URL's client =
// the host, the token is the tenant user's. SYSTEM hosts and owns the app, CP_MID is managed by
// SYSTEM, LEAF by CP_MID.

const SH_PAGE: &str = "sharedHostPage";

fn shared_host_page(e: &Env, client: &str, base: Option<&str>, label: &str) {
    let base = base.map(|b| format!(r#","baseClientCode":"{b}""#)).unwrap_or_default();
    e.insert_raw(
        &PAGE,
        "page",
        &format!(
            r#"{{"name":"{SH_PAGE}","appCode":"{APP}","clientCode":"{client}","version":1{base},"rootComponent":"btn","componentDefinition":{{"btn":{{"key":"btn","name":"btn","type":"Button","properties":{{"label":"{label}"}}}}}}}}"#
        ),
    );
}

/// The app inheritance as the platform builds it, `[owner, url client, client]` without
/// repeats, and both pages.
fn shared_host_env() -> Env {
    let e = env();
    e.dir.hierarchy(SYSTEM, &[SYSTEM]);
    e.dir.hierarchy(CP_MID, &[CP_MID, SYSTEM]);
    e.dir.hierarchy(LEAF, &[LEAF, CP_MID, SYSTEM]);
    e.dir.set(|a| {
        a.chains.insert(SYSTEM.into(), vec![SYSTEM.into()]);
        a.chains.insert(CP_MID.into(), vec![SYSTEM.into(), CP_MID.into()]);
        a.chains.insert(LEAF.into(), vec![SYSTEM.into(), LEAF.into()]);
    });
    shared_host_page(&e, SYSTEM, None, "Submit");
    shared_host_page(&e, CP_MID, Some(SYSTEM), "MID label");
    e
}

/// A user of `client` on the host `host`, as `JWTTokenFilter` builds it.
fn host_user(client: &str, host: &str, authenticated: bool) -> Caller {
    let mut ca = auth_for(client, &all_for("Page"));
    ca.url_client_code = Some(host.to_string());
    ca.authenticated = authenticated;
    Caller { ca, client_code: Some(host.to_string()), app_code: Some(APP.into()), draft: false }
}

/// `GET api/ui/page/{name}` as the browser sends it: clientCode is the host.
async fn engine_page(e: &Env, caller: &Caller, host: &str, etag: Option<&str>) -> Answer {
    let state = e.engine_state();
    let resp = Engine::new(&state, caller).page(SH_PAGE, APP, host, etag).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec();
    Answer { status, headers, body }
}

#[tokio::test]
async fn a_tenants_user_on_the_shared_host_gets_the_tenants_own_published_page() {
    let e = shared_host_env();
    assert_eq!(btn_label(&engine_page(&e, &host_user(CP_MID, SYSTEM, true), SYSTEM, None).await.obj()), Some(s("MID label")));
}

#[tokio::test]
async fn anonymous_visitors_and_the_hosts_own_users_still_get_the_hosts_page() {
    let e = shared_host_env();
    assert_eq!(btn_label(&engine_page(&e, &host_user(SYSTEM, SYSTEM, false), SYSTEM, None).await.obj()), Some(s("Submit")));
    assert_eq!(btn_label(&engine_page(&e, &host_user(SYSTEM, SYSTEM, true), SYSTEM, None).await.obj()), Some(s("Submit")));
}

#[tokio::test]
async fn a_tenant_with_no_copy_of_its_own_gets_its_managing_clients() {
    let e = shared_host_env();
    assert_eq!(btn_label(&engine_page(&e, &host_user(LEAF, SYSTEM, true), SYSTEM, None).await.obj()), Some(s("MID label")));
}

#[tokio::test]
async fn a_tenant_without_read_access_to_the_app_is_served_the_hosts_page() {
    let e = shared_host_env();
    e.dir.set(|a| {
        a.read_by.insert((APP.into(), CP_MID.into()), false);
    });
    assert_eq!(btn_label(&engine_page(&e, &host_user(CP_MID, SYSTEM, true), SYSTEM, None).await.obj()), Some(s("Submit")));
}

#[tokio::test]
async fn on_a_clients_own_site_a_user_of_a_client_above_it_still_sees_that_clients_site() {
    let e = shared_host_env();
    assert_eq!(btn_label(&engine_page(&e, &host_user(SYSTEM, CP_MID, true), CP_MID, None).await.obj()), Some(s("MID label")));
}

#[tokio::test]
async fn the_hosts_cached_page_never_answers_for_a_tenant_with_or_without_the_hosts_etag() {
    let e = shared_host_env();
    let host = engine_page(&e, &host_user(SYSTEM, SYSTEM, true), SYSTEM, None).await;
    assert_eq!(btn_label(&host.obj()), Some(s("Submit")));
    let host_etag = host.headers["etag"].to_str().unwrap().to_string();
    // The browser still holds the host's eTag from before the tenant signed in.
    let tenant = engine_page(&e, &host_user(CP_MID, SYSTEM, true), SYSTEM, Some(&host_etag)).await;
    assert_eq!(tenant.status, StatusCode::OK);
    assert_eq!(btn_label(&tenant.obj()), Some(s("MID label")));
    assert_eq!(tenant.headers["vary"], "Authorization, clientCode, appCode");
}

#[tokio::test]
async fn the_application_function_and_theme_reads_follow_the_signed_in_client_too() {
    let e = shared_host_env();
    let app = |client: &str, base: Option<&str>, title: &str| {
        let base = base.map(|b| format!(r#","baseClientCode":"{b}""#)).unwrap_or_default();
        e.insert_raw(&APPLICATION, "application", &format!(r#"{{"name":"{APP}","appCode":"{APP}","clientCode":"{client}","version":1{base},"properties":{{"title":"{title}"}}}}"#));
    };
    app(SYSTEM, None, "host app");
    app(CP_MID, Some(SYSTEM), "MID app");
    let function = |client: &str, base: Option<&str>, label: &str| {
        let base = base.map(|b| format!(r#","baseClientCode":"{b}""#)).unwrap_or_default();
        e.insert_raw(&FUNCTION, "function", &format!(r#"{{"name":"Ns.f","appCode":"{APP}","clientCode":"{client}","version":1{base},"definition":{{"namespace":"Ns","name":"f","label":"{label}"}}}}"#));
    };
    function(SYSTEM, None, "host fn");
    function(CP_MID, Some(SYSTEM), "MID fn");
    let state = e.engine_state();
    let tenant = host_user(CP_MID, SYSTEM, true);
    let engine = Engine::new(&state, &tenant);
    let read = engine.app_read(APP, SYSTEM).await.unwrap().unwrap();
    assert_eq!(path(&read.entity, &["properties", "title"]), Some(&s("MID app")));
    let r = engine.function("Ns", "f", APP, SYSTEM, None).await.unwrap();
    assert_eq!(r.headers()["vary"], "Authorization, clientCode, appCode");
    let body = parse(&axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(path(body.as_object().unwrap(), &["definition", "label"]), Some(&s("MID fn")));
    // The host's own user: the host's.
    let host = host_user(SYSTEM, SYSTEM, true);
    let read = Engine::new(&state, &host).app_read(APP, SYSTEM).await.unwrap().unwrap();
    assert_eq!(path(&read.entity, &["properties", "title"]), Some(&s("host app")));
}

// ── Function steps ──────────────────────────────────────────────────

#[tokio::test]
async fn function_steps_are_read_by_name_and_merged_on_patch() {
    let e = env();
    let f = e
        .call(
            "POST",
            "/api/ui/functions",
            r#"{"appCode":"testapp","clientCode":"SYSTEM","definition":{"namespace":"Ns","name":"f","steps":{"one":{"statementName":"one"},"two":{"statementName":"two"}}}}"#,
        )
        .await;
    assert_eq!(f.status, StatusCode::OK, "{}", f.text());
    let id = f.id();
    let all = e.call("GET", &format!("/api/ui/functions/{id}/steps"), "").await.obj();
    assert_eq!(all.keys().cloned().collect::<Vec<_>>(), names(&["one", "two"]));
    let picked = e.call("GET", &format!("/api/ui/functions/{id}/steps?names=two,nope"), "").await.obj();
    assert_eq!(picked.keys().cloned().collect::<Vec<_>>(), names(&["two"]));

    let r = e.call("PATCH", &format!("/api/ui/functions/{id}/steps"), r#"{"steps":{"three":{"statementName":"three"}},"expectedVersion":1}"#).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let o = r.obj();
    let steps = path(&o, &["definition", "steps"]).and_then(JValue::as_object).unwrap();
    assert_eq!(steps.len(), 3);
    assert_eq!(o.get("message"), Some(&s("Step update")));
    assert_eq!(o.get("version"), Some(&JValue::Int(2)));
    let stale = e.call("PATCH", &format!("/api/ui/functions/{id}/steps"), r#"{"steps":{},"expectedVersion":1}"#).await;
    assert_eq!((stale.status, stale.coded()), (StatusCode::PRECONDITION_FAILED, ("UI.FUNCTION_VERSION_MISMATCH".into(), "Version mismatch".into())));
    for bad in [r#"{"steps":[1]}"#, r#"{"message":3}"#, r#"{"expectedVersion":"2"}"#, r#"{"expectedVersion":null}"#] {
        assert_eq!(e.call("PATCH", &format!("/api/ui/functions/{id}/steps"), bad).await.status, StatusCode::INTERNAL_SERVER_ERROR, "{bad}");
    }
    assert_eq!(e.call("PATCH", &format!("/api/ui/functions/{id}/steps"), "[]").await.status, StatusCode::BAD_REQUEST);
    let r = e.call("PATCH", &format!("/api/ui/functions/{id}/steps"), r#"{"message":null}"#).await;
    assert_eq!((r.status, r.obj().get("message")), (StatusCode::OK, None), "a null message is left out");

    let bare = e.call("POST", "/api/ui/functions", r#"{"appCode":"testapp","clientCode":"SYSTEM","definition":{"namespace":"Ns","name":"g"}}"#).await;
    let none = e.call("GET", &format!("/api/ui/functions/{}/steps", bare.id()), "").await;
    assert_eq!(none.text().split_whitespace().collect::<String>(), "{}");
    let raw = e.raw(&FUNCTION, "function", &id);
    assert_eq!(path(&raw, &["definition", "steps"]).and_then(JValue::as_object).map(|m| m.len()), Some(3));
}

// ── Mobile apps ─────────────────────────────────────────────────────

const MOBILE: &str = "Authorities.ROLE_MobileApp_CREATE";

#[tokio::test]
async fn mobile_routes_want_the_mobile_app_authority() {
    let e = env();
    for (m, uri) in [
        ("GET", "/api/ui/applications/testapp/mobileApps"),
        ("POST", "/api/ui/applications/testapp/mobileApps"),
        ("DELETE", "/api/ui/applications/testapp/mobileApps/x"),
        ("GET", "/api/ui/applications/mobileApps/next"),
        ("POST", "/api/ui/applications/mobileApps/status/x"),
    ] {
        let anon = e.send(m, uri, None, &[], r#"{"details":{}}"#).await;
        assert_eq!((anon.status, anon.coded().0), (StatusCode::UNAUTHORIZED, "COMMON.SIGN_IN_REQUIRED".into()), "{m} {uri}");
        assert!(anon.headers.get("www-authenticate").is_none());
        let denied = e.send(m, uri, Some(SYSTEM), &[("x-test-auth", "Authorities.Application_READ")], r#"{"details":{}}"#).await;
        assert_eq!((denied.status, denied.coded()), (StatusCode::FORBIDDEN, ("COMMON.PERMISSION_REQUIRED".into(), format!("Access Denied: needs {MOBILE}"))), "{m} {uri}");
        assert!(denied.message().starts_with("You can't do this: your account does not have the "), "{}", denied.message());
        assert_eq!(denied.headers["content-type"], "application/json");
    }
}

#[tokio::test]
async fn a_mobile_app_gets_a_keystore_a_start_url_and_a_version_per_save() {
    let mut cfg = EditorConfig::default();
    cfg.editor.app_code_suffix = ".local".into();
    let e = env_with(cfg);
    let as_mobile = |m: &'static str, uri: String, body: &'static str| {
        let e = &e;
        async move { e.send(m, &uri, Some(SYSTEM), &[("x-test-auth", MOBILE)], body).await }
    };
    let bad = as_mobile("POST", "/api/ui/applications/testapp/mobileApps".into(), r#"{"clientCode":"SYSTEM"}"#).await;
    assert_eq!((bad.status, bad.coded()), (StatusCode::BAD_REQUEST, ("UI.MOBILE_APP_BAD_REQUEST".into(), "App Details are wrong with the mobile apps request".into())));
    assert_eq!(as_mobile("POST", "/api/ui/applications/testapp/mobileApps".into(), "x").await.status, StatusCode::BAD_REQUEST);

    let made = as_mobile("POST", "/api/ui/applications/testapp/mobileApps".into(), r#"{"details":{"name":"Shop","android":true}}"#).await;
    assert_eq!(made.status, StatusCode::OK, "{}", made.text());
    let m = made.obj();
    assert_eq!(m.get("status"), Some(&s("PENDING")));
    assert_eq!(m.get("clientCode"), Some(&s(SYSTEM)));
    assert_eq!(m.get("appCode"), Some(&s(APP)));
    assert_eq!(path(&m, &["details", "startURL"]), Some(&s("https://local.modlix.com/testapp/SYSTEM/page/")));
    assert_eq!(m.get("androidAlias"), Some(&s("modlix")));
    assert!(str_field(&m, "androidKeystore").is_some_and(|k| k.len() > 100));
    assert_eq!(m.get("createdBy"), Some(&s("7")));
    let id = made.id();

    let mut body = m.clone();
    body.insert("androidKeystore".into(), s("replaced?"));
    let body = to_compact(&JValue::Object(body));
    let again = e.send("POST", "/api/ui/applications/testapp/mobileApps", Some(SYSTEM), &[("x-test-auth", MOBILE)], &body).await;
    assert_eq!(again.status, StatusCode::OK, "{}", again.text());
    let a = again.obj();
    assert_eq!(path(&a, &["details", "version"]), Some(&JValue::Int(1)));
    assert_eq!(a.get("androidKeystore"), m.get("androidKeystore"), "the keystore is the stored one");

    let unknown = e
        .send("POST", "/api/ui/applications/testapp/mobileApps", Some(SYSTEM), &[("x-test-auth", MOBILE)], r#"{"id":"000000000000000000000000","details":{}}"#)
        .await;
    assert_eq!((unknown.status, unknown.body.len()), (StatusCode::OK, 0));

    let list = as_mobile("GET", "/api/ui/applications/testapp/mobileApps".into(), "").await;
    assert_eq!(arr(&list.json()).map(Vec::len), Some(1));
    let managed = as_mobile("GET", "/api/ui/applications/testapp/mobileApps?clientCode=SYSTEM".into(), "").await;
    assert_eq!(arr(&managed.json()).map(Vec::len), Some(1));
    e.dir.isolate_tenants();
    let foreign = as_mobile("GET", "/api/ui/applications/testapp/mobileApps?clientCode=OTHER".into(), "").await;
    assert_eq!(foreign.status, StatusCode::FORBIDDEN);
    let foreign = e
        .send("POST", "/api/ui/applications/testapp/mobileApps", Some(SYSTEM), &[("x-test-auth", MOBILE)], r#"{"clientCode":"OTHER","details":{}}"#)
        .await;
    assert_eq!(foreign.status, StatusCode::FORBIDDEN);

    // The build machines' side.
    let not_system = e.send("GET", "/api/ui/applications/mobileApps/next", Some("CLIA"), &[("x-test-auth", MOBILE)], "").await;
    assert_eq!((not_system.status, not_system.coded()), (StatusCode::FORBIDDEN, ("UI.INTERNAL_ONLY".into(), "Cannot be used by clients other than SYSTEM Client.".into())));
    let next = as_mobile("GET", "/api/ui/applications/mobileApps/next".into(), "").await;
    assert_eq!(str_field(&next.obj(), "id"), Some(id.as_str()));
    let failed = e
        .send("POST", &format!("/api/ui/applications/mobileApps/status/{id}"), Some(SYSTEM), &[("x-test-auth", MOBILE)], r#"{"status":"SUCCESS","errorMessage":"boom"}"#)
        .await;
    assert_eq!(failed.text(), "true");
    let listed = as_mobile("GET", "/api/ui/applications/testapp/mobileApps".into(), "").await.json();
    let row = arr(&listed).unwrap()[0].as_object().unwrap().clone();
    assert_eq!((row.get("status"), row.get("errorMessage")), (Some(&s("FAILED")), Some(&s("boom"))));
    let none = as_mobile("GET", "/api/ui/applications/mobileApps/next".into(), "").await;
    assert_eq!((none.status, none.body.len()), (StatusCode::NOT_FOUND, 0));
    let ok = e
        .send("POST", &format!("/api/ui/applications/mobileApps/status/{id}"), Some(SYSTEM), &[("x-test-auth", MOBILE)], r#"{"status":"SUCCESS","androidAppURL":"u"}"#)
        .await;
    assert_eq!(ok.text(), "true");
    let listed = as_mobile("GET", "/api/ui/applications/testapp/mobileApps".into(), "").await.json();
    let row = arr(&listed).unwrap()[0].as_object().unwrap().clone();
    assert_eq!((row.get("status"), row.get("androidAppURL")), (Some(&s("SUCCESS")), Some(&s("u"))));
    assert!(row.get("errorMessage").is_none_or(JValue::is_null));
    let unknown = as_mobile("POST", "/api/ui/applications/mobileApps/status/000000000000000000000000".into(), r#"{"status":"SUCCESS"}"#).await;
    assert_eq!((unknown.status, unknown.body.len()), (StatusCode::OK, 0));
    assert_eq!(as_mobile("POST", format!("/api/ui/applications/mobileApps/status/{id}"), r#"{"status":"NOPE"}"#).await.status, StatusCode::BAD_REQUEST);
    let other = e
        .send("POST", &format!("/api/ui/applications/mobileApps/status/{id}"), Some("CLIA"), &[("x-test-auth", MOBILE)], r#"{"status":"SUCCESS"}"#)
        .await;
    assert_eq!(other.status, StatusCode::FORBIDDEN);

    let gone = as_mobile("DELETE", format!("/api/ui/applications/testapp/mobileApps/{id}"), "").await;
    assert_eq!(gone.text(), "true");
    let twice = as_mobile("DELETE", format!("/api/ui/applications/testapp/mobileApps/{id}"), "").await;
    assert_eq!(twice.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn deleting_a_mobile_app_needs_write_access_to_its_app() {
    let e = env();
    let made = e.send("POST", "/api/ui/applications/testapp/mobileApps", Some(SYSTEM), &[("x-test-auth", MOBILE)], r#"{"details":{}}"#).await;
    e.dir.set(|a| a.write_access = false);
    let r = e.send("DELETE", &format!("/api/ui/applications/testapp/mobileApps/{}", made.id()), Some(SYSTEM), &[("x-test-auth", MOBILE)], "").await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
}

// ── App Store Connect ───────────────────────────────────────────────

/// What the fake App Store Connect answers, and what it was asked.
#[derive(Default)]
struct FakeApple {
    bundles: Mutex<HashMap<String, String>>,
    profiles: Mutex<Vec<(String, String)>>,
    calls: Mutex<Vec<String>>,
    refuse_bundle_create: Mutex<bool>,
    refuse_profile: Mutex<Option<String>>,
    /// A capability Apple already has on: 409.
    push_already_on: Mutex<bool>,
    /// Profiles deleted so far: a profile made after a delete is "PROFILE<n>".
    deleted: Mutex<usize>,
}

async fn certificates(State(f): State<Arc<FakeApple>>, h: HeaderMap) -> axum::response::Response {
    use axum::response::IntoResponse;
    f.calls.lock().unwrap().push("certificates".into());
    if !h.get("authorization").and_then(|v| v.to_str().ok()).is_some_and(|a| a.starts_with("Bearer ") && a.matches('.').count() == 2) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    Json(serde_json::json!({"data": [{"id": "C1", "attributes": {"certificateType": "DISTRIBUTION", "displayName": "Team", "expirationDate": "2027-01-01T00:00:00.000+00:00"}}]}))
        .into_response()
}

async fn bundle_ids(State(f): State<Arc<FakeApple>>, Query(q): Query<HashMap<String, String>>) -> Json<serde_json::Value> {
    let id = q.get("filter[identifier]").cloned().unwrap_or_default();
    f.calls.lock().unwrap().push(format!("find {id}"));
    let found = f.bundles.lock().unwrap().get(&id).cloned();
    Json(match found {
        Some(apple) => serde_json::json!({"data": [{"id": apple}]}),
        None => serde_json::json!({"data": []}),
    })
}

async fn create_bundle(State(f): State<Arc<FakeApple>>, Json(b): Json<serde_json::Value>) -> axum::response::Response {
    use axum::response::IntoResponse;
    let id = b["data"]["attributes"]["identifier"].as_str().unwrap_or("").to_string();
    f.calls.lock().unwrap().push(format!("create {id}"));
    if *f.refuse_bundle_create.lock().unwrap() {
        f.bundles.lock().unwrap().insert(id, "B-RACE".into());
        return (StatusCode::CONFLICT, r#"{"errors":[{"code":"ENTITY_ERROR.ATTRIBUTE.INVALID"}]}"#).into_response();
    }
    f.bundles.lock().unwrap().insert(id, "B1".into());
    Json(serde_json::json!({"data": {"id": "B1"}})).into_response()
}

async fn profiles(State(f): State<Arc<FakeApple>>) -> Json<serde_json::Value> {
    f.calls.lock().unwrap().push("profiles".into());
    let rows: Vec<serde_json::Value> = f
        .profiles
        .lock()
        .unwrap()
        .iter()
        .enumerate()
        .map(|(i, (b, c))| serde_json::json!({"id": format!("P{i}"), "attributes": {"profileContent": c}, "relationships": {"bundleId": {"data": {"id": b}}}}))
        .collect();
    Json(serde_json::json!({"data": rows}))
}

async fn create_profile(State(f): State<Arc<FakeApple>>, Json(b): Json<serde_json::Value>) -> axum::response::Response {
    use axum::response::IntoResponse;
    let bundle = b["data"]["relationships"]["bundleId"]["data"]["id"].as_str().unwrap_or("").to_string();
    f.calls.lock().unwrap().push(format!("profile {bundle}"));
    if let Some(err) = f.refuse_profile.lock().unwrap().clone() {
        return (StatusCode::CONFLICT, err).into_response();
    }
    let n = *f.deleted.lock().unwrap();
    let content = if n == 0 { "PROFILE".to_string() } else { format!("PROFILE{n}") };
    f.profiles.lock().unwrap().push((bundle, content.clone()));
    Json(serde_json::json!({"data": {"attributes": {"profileContent": content}}})).into_response()
}

async fn delete_profile(State(f): State<Arc<FakeApple>>, axum::extract::Path(id): axum::extract::Path<String>) -> StatusCode {
    f.calls.lock().unwrap().push(format!("delete {id}"));
    let i: usize = id.trim_start_matches('P').parse().unwrap();
    f.profiles.lock().unwrap().remove(i);
    *f.deleted.lock().unwrap() += 1;
    StatusCode::NO_CONTENT
}

async fn capabilities(State(f): State<Arc<FakeApple>>, Json(b): Json<serde_json::Value>) -> axum::response::Response {
    use axum::response::IntoResponse;
    let bundle = b["data"]["relationships"]["bundleId"]["data"]["id"].as_str().unwrap_or("").to_string();
    let kind = b["data"]["attributes"]["capabilityType"].as_str().unwrap_or("").to_string();
    f.calls.lock().unwrap().push(format!("{kind} {bundle}"));
    if *f.push_already_on.lock().unwrap() {
        return (StatusCode::CONFLICT, r#"{"errors":[{"code":"ENTITY_ERROR"}]}"#).into_response();
    }
    Json(serde_json::json!({"data": {"id": "CAP1"}})).into_response()
}

async fn fake_apple() -> (Arc<FakeApple>, String) {
    let f = Arc::new(FakeApple::default());
    let app = Router::new()
        .route("/v1/certificates", get(certificates))
        .route("/v1/bundleIds", get(bundle_ids).post(create_bundle))
        .route("/v1/profiles", get(profiles).post(create_profile))
        .route("/v1/profiles/{id}", axum::routing::delete(delete_profile))
        .route("/v1/bundleIdCapabilities", axum::routing::post(capabilities))
        .with_state(f.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await });
    (f, format!("http://{addr}"))
}

fn apple_key() -> String {
    use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let b64 = overridable::write::transport::base64_encode(pkcs8.as_ref());
    let pem = format!("-----BEGIN PRIVATE KEY-----\n{b64}\n-----END PRIVATE KEY-----\n");
    overridable::write::transport::base64_encode(pem.as_bytes())
}

fn apple_cfg(url: &str, certificate: &str) -> EditorConfig {
    let mut cfg = EditorConfig::default();
    cfg.editor.apple_api_url = url.into();
    cfg.editor.apple_api_key_id = "KEY".into();
    cfg.editor.apple_api_issuer_id = "ISS".into();
    cfg.editor.apple_api_key_content = apple_key();
    cfg.editor.apple_team_id = "TEAM".into();
    cfg.editor.apple_certificate_id = certificate.into();
    cfg
}

#[tokio::test]
async fn apple_certificates_are_listed_or_refused_with_an_empty_500() {
    let e = env();
    let r = e.call("GET", "/api/ui/applications/apple/certificates", "").await;
    assert_eq!((r.status, r.body.len()), (StatusCode::INTERNAL_SERVER_ERROR, 0));
    assert!(r.headers.get("content-type").is_none());

    let (fake, url) = fake_apple().await;
    let e = env_with(apple_cfg(&url, "C1"));
    let r = e.call("GET", "/api/ui/applications/apple/certificates", "").await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let listed = r.json();
    let row = arr(&listed).unwrap()[0].as_object().unwrap().clone();
    assert_eq!(row.get("id"), Some(&s("C1")));
    assert_eq!(row.get("type"), Some(&s("DISTRIBUTION")));
    assert_eq!(fake.calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn an_ios_app_on_the_platform_account_gets_a_bundle_id_and_a_profile() {
    let (fake, url) = fake_apple().await;
    let e = env_with(apple_cfg(&url, "C1"));
    let ios = r#"{"details":{"name":"Shop App","ios":true,"iosPublishMode":"PLATFORM_ACCOUNT"}}"#;
    let made = e.send("POST", "/api/ui/applications/testapp/mobileApps", Some(SYSTEM), &[("x-test-auth", MOBILE)], ios).await;
    assert_eq!(made.status, StatusCode::OK, "{}", made.text());
    let m = made.obj();
    assert_eq!(m.get("iosBundleId"), Some(&s("com.modlix.apps.system.shopapp")));
    assert_eq!(m.get("iosTeamId"), Some(&s("TEAM")));
    assert_eq!(m.get("iosProvisioningProfile"), Some(&s("PROFILE")));
    assert_eq!(
        *fake.calls.lock().unwrap(),
        names(&["find com.modlix.apps.system.shopapp", "create com.modlix.apps.system.shopapp", "profiles", "profile B1"])
    );

    // A later save keeps them, and counts a version.
    let again = e.send("POST", "/api/ui/applications/testapp/mobileApps", Some(SYSTEM), &[("x-test-auth", MOBILE)], &made.text()).await;
    let a = again.obj();
    assert_eq!(a.get("iosProvisioningProfile"), Some(&s("PROFILE")));
    assert_eq!(path(&a, &["details", "version"]), Some(&JValue::Int(1)));

    // A stored app with a bundle id and no profile gets one.
    let mut no_profile = a.clone();
    no_profile.shift_remove("iosProvisioningProfile");
    let id = str_field(&a, "id").unwrap().to_string();
    let mut row = e.raw(&ui::editor::mobile::MOBILE_APP, "mobileApp", &id);
    row.insert("iosProvisioningProfile".into(), JValue::Null);
    row.insert("details".into(), a["details"].clone());
    use overridable::backend::Backend;
    e.mem
        .replace("mobileApp", overridable::write::persist::id_bson(&id), to_document(&ui::editor::mobile::MOBILE_APP, &row, None, &[]))
        .await
        .unwrap();
    fake.profiles.lock().unwrap().clear();
    let third = e
        .send("POST", "/api/ui/applications/testapp/mobileApps", Some(SYSTEM), &[("x-test-auth", MOBILE)], &to_compact(&JValue::Object(no_profile)))
        .await;
    assert_eq!(third.status, StatusCode::OK, "{}", third.text());
    assert_eq!(third.obj().get("iosProvisioningProfile"), Some(&s("PROFILE")));
}

#[tokio::test]
async fn apple_refusals_are_explained() {
    let (fake, url) = fake_apple().await;
    let e = env_with(apple_cfg(&url, "C1"));
    *fake.refuse_bundle_create.lock().unwrap() = true;
    *fake.refuse_profile.lock().unwrap() = Some(r#"{"errors":[{"detail":"There are no current certificates on this team"}]}"#.into());
    let ios = r#"{"details":{"name":"Shop","ios":true,"iosPublishMode":"PLATFORM_ACCOUNT"}}"#;
    let r = e.send("POST", "/api/ui/applications/testapp/mobileApps", Some(SYSTEM), &[("x-test-auth", MOBILE)], ios).await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(fake.calls.lock().unwrap().iter().any(|c| c == "find com.modlix.apps.system.shop"), "the ENTITY_ERROR fallback looks the bundle up");

    // A profile refused as a duplicate falls back to the existing one.
    *fake.refuse_profile.lock().unwrap() = Some(r#"{"errors":[{"code":"ENTITY_ERROR"}]}"#.into());
    fake.profiles.lock().unwrap().push(("OTHER".into(), "NOT-OURS".into()));
    let r = e.send("POST", "/api/ui/applications/testapp/mobileApps", Some(SYSTEM), &[("x-test-auth", MOBILE)], ios).await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR, "no profile of this bundle exists");
    *fake.refuse_profile.lock().unwrap() = Some("plain failure".into());
    let r = e.send("POST", "/api/ui/applications/testapp/mobileApps", Some(SYSTEM), &[("x-test-auth", MOBILE)], ios).await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);

    // Without a certificate there is no profile, and that is fine.
    let e = env_with(apple_cfg(&url, ""));
    let r = e.send("POST", "/api/ui/applications/testapp/mobileApps", Some(SYSTEM), &[("x-test-auth", MOBILE)], ios).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert!(r.obj().get("iosProvisioningProfile").is_none_or(JValue::is_null));
    assert_eq!(r.obj().get("iosBundleId"), Some(&s("com.modlix.apps.system.shop")));
}

#[tokio::test]
async fn an_ios_app_with_push_gets_the_capability_and_a_new_profile_once() {
    let (fake, url) = fake_apple().await;
    let e = env_with(apple_cfg(&url, "C1"));
    let ios = r#"{"details":{"name":"Shop App","ios":true,"iosPublishMode":"PLATFORM_ACCOUNT","pushNotifications":true}}"#;
    let made = e.send("POST", "/api/ui/applications/testapp/mobileApps", Some(SYSTEM), &[("x-test-auth", MOBILE)], ios).await;
    assert_eq!(made.status, StatusCode::OK, "{}", made.text());
    let m = made.obj();
    assert_eq!(m.get("iosPushReady"), Some(&JValue::Bool(true)));
    assert_eq!(m.get("iosProvisioningProfile"), Some(&s("PROFILE1")), "the profile made after push was turned on");
    assert_eq!(
        *fake.calls.lock().unwrap(),
        names(&[
            "find com.modlix.apps.system.shopapp",
            "create com.modlix.apps.system.shopapp",
            "profiles",
            "profile B1",
            "find com.modlix.apps.system.shopapp",
            "PUSH_NOTIFICATIONS B1",
            "profiles",
            "delete P0",
            "profile B1",
        ])
    );
    assert_eq!(fake.profiles.lock().unwrap().len(), 1, "the profile without push is gone");

    // Later saves leave Apple alone, even when the request forgets the marker.
    fake.calls.lock().unwrap().clear();
    let mut forgot = made.obj();
    forgot.shift_remove("iosPushReady");
    let again = e.send("POST", "/api/ui/applications/testapp/mobileApps", Some(SYSTEM), &[("x-test-auth", MOBILE)], &to_compact(&JValue::Object(forgot))).await;
    assert_eq!(again.status, StatusCode::OK, "{}", again.text());
    assert_eq!(again.obj().get("iosPushReady"), Some(&JValue::Bool(true)));
    assert!(!fake.calls.lock().unwrap().iter().any(|c| c.starts_with("PUSH_NOTIFICATIONS")));

    // A bundle that already has push is fine.
    *fake.push_already_on.lock().unwrap() = true;
    let other = r#"{"details":{"name":"Other","ios":true,"iosPublishMode":"PLATFORM_ACCOUNT","pushNotifications":true}}"#;
    let r = e.send("POST", "/api/ui/applications/testapp/mobileApps", Some(SYSTEM), &[("x-test-auth", MOBILE)], other).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(r.obj().get("iosPushReady"), Some(&JValue::Bool(true)));
}

// ── Firebase (Android push) ─────────────────────────────────────────

#[derive(Default)]
struct FakeFirebase {
    /// package -> Firebase app id
    apps: Mutex<HashMap<String, String>>,
    pending: Mutex<Option<String>>,
    calls: Mutex<Vec<String>>,
}

async fn fb_token(State(f): State<Arc<FakeFirebase>>, body: String) -> Json<serde_json::Value> {
    assert!(body.contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant%2Dtype%3Ajwt%2Dbearer"), "{body}");
    f.calls.lock().unwrap().push("token".into());
    Json(serde_json::json!({"access_token": "AT", "expires_in": 3600}))
}

async fn fb_list(State(f): State<Arc<FakeFirebase>>, h: HeaderMap) -> Json<serde_json::Value> {
    assert_eq!(h.get("authorization").unwrap(), "Bearer AT");
    f.calls.lock().unwrap().push("list".into());
    let apps: Vec<serde_json::Value> = f.apps.lock().unwrap().iter().map(|(p, id)| serde_json::json!({"packageName": p, "appId": id})).collect();
    Json(serde_json::json!({"apps": apps}))
}

async fn fb_create(State(f): State<Arc<FakeFirebase>>, Json(b): Json<serde_json::Value>) -> Json<serde_json::Value> {
    let package = b["packageName"].as_str().unwrap().to_string();
    f.calls.lock().unwrap().push(format!("create {package}"));
    *f.pending.lock().unwrap() = Some(package);
    Json(serde_json::json!({"name": "operations/op1", "done": false}))
}

async fn fb_operation(State(f): State<Arc<FakeFirebase>>) -> Json<serde_json::Value> {
    f.calls.lock().unwrap().push("poll".into());
    let package = f.pending.lock().unwrap().take().unwrap();
    f.apps.lock().unwrap().insert(package, "1:99:android:new".into());
    Json(serde_json::json!({"name": "operations/op1", "done": true, "response": {"appId": "1:99:android:new"}}))
}

async fn fb_config(State(f): State<Arc<FakeFirebase>>, axum::extract::Path((_, app)): axum::extract::Path<(String, String)>) -> Json<serde_json::Value> {
    f.calls.lock().unwrap().push(format!("config {app}"));
    let package = f.apps.lock().unwrap().iter().find(|(_, id)| **id == app).map(|(p, _)| p.clone()).unwrap();
    let gs = serde_json::json!({
        "project_info": {"project_number": "99", "project_id": "modlix-push"},
        "client": [{"client_info": {"mobilesdk_app_id": app, "android_client_info": {"package_name": package}}, "api_key": [{"current_key": "KEY99"}]}]
    });
    Json(serde_json::json!({"configFilename": "google-services.json", "configFileContents": overridable::write::transport::base64_encode(gs.to_string().as_bytes())}))
}

async fn fake_firebase() -> (Arc<FakeFirebase>, String) {
    let f = Arc::new(FakeFirebase::default());
    let app = Router::new()
        .route("/token", axum::routing::post(fb_token))
        .route("/v1beta1/projects/{project}/androidApps", get(fb_list).post(fb_create))
        .route("/v1beta1/operations/{op}", get(fb_operation))
        .route("/v1beta1/projects/{project}/androidApps/{app}/config", get(fb_config))
        .with_state(f.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await });
    (f, format!("http://{addr}"))
}

fn firebase_cfg(url: &str) -> EditorConfig {
    use rsa::pkcs8::EncodePrivateKey;
    let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
    let pem = key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap().to_string();
    let mut cfg = EditorConfig::default();
    cfg.editor.firebase_api_url = url.into();
    cfg.editor.firebase_credentials = serde_json::json!({
        "type": "service_account", "project_id": "modlix-push", "client_email": "push@modlix-push.iam.gserviceaccount.com",
        "private_key": pem, "token_uri": format!("{url}/token")
    })
    .to_string();
    cfg
}

#[tokio::test]
async fn an_android_app_with_push_is_registered_in_the_platform_firebase_project() {
    let (fake, url) = fake_firebase().await;
    let e = env_with(firebase_cfg(&url));
    let android = r#"{"details":{"name":"Shop App","android":true,"pushNotifications":true}}"#;
    let made = e.send("POST", "/api/ui/applications/testapp/mobileApps", Some(SYSTEM), &[("x-test-auth", MOBILE)], android).await;
    assert_eq!(made.status, StatusCode::OK, "{}", made.text());
    let fb = made.obj().get("firebaseAndroid").cloned().unwrap();
    assert_eq!(
        to_compact(&fb),
        r#"{"apiKey":"KEY99","appId":"1:99:android:new","projectId":"modlix-push","messagingSenderId":"99"}"#
    );
    assert_eq!(
        *fake.calls.lock().unwrap(),
        names(&["token", "list", "create com.modlix.nocodemobile.system.shop_app", "poll", "config 1:99:android:new"])
    );

    // Saved again: the values are kept and Firebase is not asked.
    fake.calls.lock().unwrap().clear();
    let mut forgot = made.obj();
    forgot.shift_remove("firebaseAndroid");
    let again = e.send("POST", "/api/ui/applications/testapp/mobileApps", Some(SYSTEM), &[("x-test-auth", MOBILE)], &to_compact(&JValue::Object(forgot))).await;
    assert_eq!(again.obj().get("firebaseAndroid"), Some(&fb));
    assert!(fake.calls.lock().unwrap().is_empty());

    // A tenant's own Firebase values are used as they are.
    let own = r#"{"details":{"name":"Own","android":true,"pushNotifications":true},"firebaseAndroid":{"apiKey":"A","appId":"1:5:android:z","projectId":"tenant-fb","messagingSenderId":"5"}}"#;
    let r = e.send("POST", "/api/ui/applications/testapp/mobileApps", Some(SYSTEM), &[("x-test-auth", MOBILE)], own).await;
    assert_eq!(path(&r.obj(), &["firebaseAndroid", "projectId"]), Some(&s("tenant-fb")));
    assert!(fake.calls.lock().unwrap().is_empty());

    // An app already registered is found, not registered twice; without push nothing is asked.
    let lookup = r#"{"details":{"name":"Shop App","android":true,"pushNotifications":true}}"#;
    let r = e.send("POST", "/api/ui/applications/testapp/mobileApps", Some(SYSTEM), &[("x-test-auth", MOBILE)], lookup).await;
    assert_eq!(path(&r.obj(), &["firebaseAndroid", "appId"]), Some(&s("1:99:android:new")));
    assert_eq!(*fake.calls.lock().unwrap(), names(&["token", "list", "config 1:99:android:new"]));
    fake.calls.lock().unwrap().clear();
    let quiet = e.send("POST", "/api/ui/applications/testapp/mobileApps", Some(SYSTEM), &[("x-test-auth", MOBILE)], r#"{"details":{"name":"Q","android":true}}"#).await;
    assert!(quiet.obj().get("firebaseAndroid").is_none_or(JValue::is_null));
    assert!(fake.calls.lock().unwrap().is_empty());
}

// ── The commons routes on the ui kinds ──────────────────────────────

#[tokio::test]
async fn publish_versions_and_transport_cover_every_ui_kind() {
    let e = env();
    e.call("POST", "/api/ui/applications", r#"{"name":"testapp","appCode":"testapp","clientCode":"SYSTEM"}"#).await;
    let p = e.call("POST", "/api/ui/pages", r#"{"name":"home","appCode":"testapp","clientCode":"SYSTEM"}"#).await;
    let d = e.call("PUT", &format!("/api/ui/pages/{}?draft=true", p.id()), &p.text()).await;
    assert_eq!(d.status, StatusCode::OK, "{}", d.text());
    e.call("POST", "/api/ui/functions", r#"{"appCode":"testapp","clientCode":"SYSTEM","definition":{"namespace":"Ns","name":"f"}}"#).await;
    let pending = e.call("GET", "/api/ui/publish/app/testapp/pending?clientCode=SYSTEM", "").await;
    assert_eq!(pending.status, StatusCode::OK, "{}", pending.text());
    assert!(pending.text().contains("home"), "{}", pending.text());
    let all = e.call("POST", "/api/ui/publish/app/testapp?clientCode=SYSTEM", "").await;
    assert_eq!(all.status, StatusCode::OK, "{}", all.text());

    let versions = e.call("POST", &format!("/api/ui/versions/{}/query", p.id()), "{}").await;
    assert_eq!(versions.status, StatusCode::OK, "{}", versions.text());

    let types = e.call("GET", "/api/ui/transports/transportTypes", "").await;
    assert_eq!(types.json(), JValue::Array(["Application", "Page", "Style", "Theme", "Function", "Schema", "Filler", "URIPath"].iter().map(|t| s(t)).collect()));
    let json = e.call("POST", "/api/ui/transports/internal/makeTransport", r#"{"appCode":"testapp","clientCode":"SYSTEM","fileType":"JSON"}"#).await;
    assert_eq!(json.status, StatusCode::OK, "{}", json.text());
    let fwd = [("x-forwarded-host", "localhost"), ("x-forwarded-port", "8080"), ("clientCode", SYSTEM), ("appCode", APP)];
    let wiped = e.send("DELETE", "/api/ui?deleteAppCode=testapp", Some(SYSTEM), &fwd, "").await;
    assert_eq!(wiped.status, StatusCode::OK, "{}", wiped.text());
    assert!(e.mem.all("page").is_empty());
    let mut req = Request::builder().method("POST").uri("/api/ui/transports/internal/createAndApply?fileName=t.json").header("x-test-client", SYSTEM);
    for (k, v) in fwd {
        req = req.header(k, v);
    }
    let resp = e.router.clone().oneshot(req.body(Body::from(json.body.clone())).unwrap()).await.unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    for c in ["application", "page", "function"] {
        assert_eq!(e.mem.all(c).len(), 1, "{c} came back");
    }
    // An application moved to another app code keeps its name, which the name rule refuses.
    let mut req = Request::builder().method("POST").uri("/api/ui/transports/internal/createAndApply?fileName=t.json&applicationCode=newapp").header("x-test-client", SYSTEM);
    for (k, v) in fwd {
        req = req.header(k, v);
    }
    let resp = e.router.clone().oneshot(req.body(Body::from(json.body.clone())).unwrap()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── Page change sets (`PATCH /api/ui/pages/{id}/changes`) ───────────
// Several components, event functions and fields of a page in one write FOR a client: the
// client's copy holds only what changed, never the whole page.

async fn changes_for(e: &Env, id: &str, body: &str, query: &str) -> Answer {
    e.call("PATCH", &format!("/api/ui/pages/{id}/changes{query}"), body).await
}

#[tokio::test]
async fn a_change_set_for_a_client_stores_only_the_changed_entries() {
    let e = client_patch_env();
    let base = system_page(&e);
    let body = r#"{"components":{"btn":{"key":"btn","name":"btn","type":"Button","properties":{"label":"Go MID"}},"txt":null},
        "eventFunctions":{"onGo":{"name":"onGo","steps":{}}},"fields":{"title":"MID title"},"message":"m"}"#;
    let r = changes_for(&e, &base, body, &format!("?clientCode={CP_MID}")).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let system = &stored_for(&e, SYSTEM)[0];
    assert_eq!(btn_label(system), Some(s("Submit")), "the base page is untouched");
    assert_eq!(component_keys(system), vec!["btn", "root", "txt"]);
    let mid = &stored_for(&e, CP_MID)[0];
    assert_eq!(str_field(mid, "baseClientCode"), Some(SYSTEM));
    assert!(!component_keys(mid).contains(&"root".to_string()), "an unchanged component is not stored: {:?}", component_keys(mid));
    let merged = e.as_client(CP_MID, "GET", &format!("/api/ui/pages/{}", str_field(mid, "id").unwrap()), "").await.obj();
    assert_eq!(btn_label(&merged), Some(s("Go MID")));
    assert_eq!(component_keys(&merged), vec!["btn", "root"], "the removed component is gone from the client's page");
    assert!(path(&merged, &["eventFunctions", "onGo"]).is_some());
    assert_eq!(str_field(&merged, "title"), Some("MID title"));
    // A later SYSTEM change to a component the client never changed still reaches the client.
    assert_eq!(e.call("PATCH", &format!("/api/ui/pages/{base}/components/root"), r#"{"componentData":{"properties":{"gap":"8px"}}}"#).await.status, StatusCode::OK);
    let merged = e.as_client(CP_MID, "GET", &format!("/api/ui/pages/{}", str_field(mid, "id").unwrap()), "").await.obj();
    assert_eq!(path(&merged, &["componentDefinition", "root", "properties", "gap"]), Some(&s("8px")));
}

#[tokio::test]
async fn a_change_set_on_a_clients_draft_checks_and_answers_the_draft_version() {
    let e = client_patch_env();
    let base = system_page(&e);
    let q = format!("?clientCode={CP_MID}&draft=true");
    let one = r#"{"components":{"btn":{"key":"btn","type":"Button","properties":{"label":"Draft MID"}}}}"#;
    let first = changes_for(&e, &base, one, &q).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.text());
    let mid = &stored_for(&e, CP_MID)[0];
    assert_eq!(mid.get("published"), Some(&JValue::Bool(false)));
    let mid_id = str_field(mid, "id").unwrap().to_string();
    let read = e.call("GET", &format!("/api/ui/pages/{mid_id}?draft=true"), "").await;
    let seen: i64 = read.headers["x-draft-version"].to_str().unwrap().parse().unwrap();
    let two = r#"{"components":{"txt":{"key":"txt","type":"Text","properties":{"text":"Draft text"}}}}"#;
    let stale = changes_for(&e, &base, two, &format!("{q}&draftVersion={}", seen + 5)).await;
    assert_eq!(stale.status, StatusCode::PRECONDITION_FAILED, "{}", stale.text());
    let ok = changes_for(&e, &base, two, &format!("{q}&draftVersion={seen}")).await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.text());
    let next: i64 = ok.headers["x-draft-version"].to_str().unwrap().parse().unwrap();
    assert!(next > seen, "{next} after {seen}");
    assert_eq!(btn_label(&ok.obj()), Some(s("Draft MID")));
    assert_eq!(path(&ok.obj(), &["componentDefinition", "txt", "properties", "text"]), Some(&s("Draft text")));
    assert_eq!(btn_label(&stored_for(&e, SYSTEM)[0]), Some(s("Submit")));
}

#[tokio::test]
async fn a_change_set_refuses_identity_fields_stale_entries_and_nothing() {
    let e = client_patch_env();
    let base = system_page(&e);
    let r = changes_for(&e, &base, r#"{"fields":{"clientCode":"X"}}"#, "").await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", r.text());
    let r = changes_for(&e, &base, r#"{"components":{"btn":"x"}}"#, "").await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(changes_for(&e, &base, "{}", "").await.status, StatusCode::BAD_REQUEST);
    // One patch gives the page component versions; a change made from an older one is refused.
    assert_eq!(patch_for(&e, SYSTEM, &base, "btn", &label_data("v2"), "").await.status, StatusCode::OK);
    let stale = r#"{"components":{"btn":{"key":"btn","properties":{"label":"old"}}},"expectedComponentVersions":{"btn":1}}"#;
    assert_eq!(changes_for(&e, &base, stale, "").await.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(btn_label(&stored_for(&e, SYSTEM)[0]), Some(s("v2")));
    let current = r#"{"components":{"btn":{"key":"btn","properties":{"label":"v3"}}},"expectedComponentVersions":{"btn":2}}"#;
    let r = changes_for(&e, &base, current, "").await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(btn_label(&stored_for(&e, SYSTEM)[0]), Some(s("v3")));
}
