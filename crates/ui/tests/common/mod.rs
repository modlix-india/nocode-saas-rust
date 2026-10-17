//! The harness the ui integration tests share, the Rust counterpart of the Java ui's
//! `AbstractIntegrationTest`: a scratch Mongo database per test (dropped at the end), a fake
//! security service on a local port (the Java tests mock the Feign clients), and the ui-engine
//! router driven in process.
//!
//! Gated: tests using it are `#[ignore]` and need `MODLIX__MONGO__URI` (the local stack's,
//! from `config/local.env`); without it they return early.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::{to_bytes, Body};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use mongodb::bson::{doc, oid::ObjectId, Document};
use mongodb::Database;
use overridable::{JMap, JValue};
use platform::cache::CacheService;
use platform::config::MongoConfig;
use platform::security::SecurityClient;
use platform::upstream::Upstream;
use tower::ServiceExt;
use ui::config::UiConfig;
use ui::state::{AppState, Inner};

pub const APP: &str = "testapp";

/// What the fake security service answers.
#[derive(Default)]
pub struct FakeSecurity {
    pub chains: Mutex<HashMap<String, Vec<String>>>,
    pub status: Mutex<HashMap<String, String>>,
    pub deps: Mutex<HashMap<String, Vec<String>>>,
}

fn anonymous() -> serde_json::Value {
    serde_json::json!({"user": {"id": 0, "clientId": 1, "userName": "_Anonymous",
        "stringAuthorities": ["Authorities._Anonymous"]}, "authenticated": false,
        "clientCode": "SYSTEM", "clientTypeCode": "SYS"})
}

/// `Authorization: user <client> <authority,authority>` is a signed-in user 142 of that client;
/// `refuse` and `refuse-silent` are refusals with and without a message; `broken` is a body
/// that is not JSON; anything else (or nothing) is the anonymous user.
async fn context_authentication(h: HeaderMap) -> Response {
    let auth = h.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    if auth == "refuse" {
        return (StatusCode::UNAUTHORIZED, axum::Json(serde_json::json!({"message": "Unknown client information requested"})))
            .into_response();
    }
    if auth == "refuse-silent" {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if auth == "broken" {
        return (StatusCode::OK, "not json").into_response();
    }
    let parts: Vec<&str> = auth.split(' ').collect();
    if parts.len() >= 2 && parts[0] == "user" {
        let authorities: Vec<String> = parts
            .get(2)
            .map(|a| a.split(',').map(str::to_string).collect())
            .unwrap_or_default();
        return axum::Json(serde_json::json!({"user": {"id": 142, "clientId": 1, "userName": "142",
            "stringAuthorities": authorities}, "authenticated": true, "clientCode": parts[1],
            "clientTypeCode": "SYS"}))
        .into_response();
    }
    axum::Json(anonymous()).into_response()
}

async fn inheritance(State(f): State<Arc<FakeSecurity>>, Query(q): Query<HashMap<String, String>>) -> axum::Json<Vec<String>> {
    let client = q.get("clientCode").cloned().unwrap_or_default();
    axum::Json(f.chains.lock().unwrap().get(&client).cloned().unwrap_or_else(|| vec![client]))
}

async fn app_status(State(f): State<Arc<FakeSecurity>>, Path(app): Path<String>) -> String {
    f.status.lock().unwrap().get(&app).cloned().unwrap_or_else(|| "ACTIVE".into())
}

async fn dependencies(State(f): State<Arc<FakeSecurity>>, Query(q): Query<HashMap<String, String>>) -> axum::Json<Vec<String>> {
    let app = q.get("appCode").cloned().unwrap_or_default();
    axum::Json(f.deps.lock().unwrap().get(&app).cloned().unwrap_or_default())
}

/// The fake security's routes.
pub fn security_router(fake: Arc<FakeSecurity>) -> Router {
    Router::new()
        .route("/api/security/internal/securityContextAuthentication", get(context_authentication))
        .route("/api/security/applications/internal/appInheritance", get(inheritance))
        .route("/api/security/applications/internal/appStatus/{app}", get(app_status))
        .route("/api/security/applications/internal/dependencies", get(dependencies))
        .with_state(fake)
}

/// Serves a router on a local port and answers its base URL.
pub async fn serve(app: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await });
    format!("http://{addr}")
}

/// Serves the fake security on a local port and answers its base URL.
pub async fn fake_security(fake: Arc<FakeSecurity>) -> String {
    serve(security_router(fake)).await
}

pub struct Env {
    pub db: Database,
    pub db_name: String,
    pub fake: Arc<FakeSecurity>,
    pub state: AppState,
    pub router: Router,
    pub security_url: String,
}

static SEQ: AtomicUsize = AtomicUsize::new(0);

pub fn mongo_uri() -> Option<String> {
    std::env::var("MODLIX__MONGO__URI").ok()
}

/// A fresh scratch database, the fake security, and the router; `None` when the local Mongo is
/// not configured.
pub async fn env() -> Option<Env> {
    env_with(Router::new()).await
}

/// [`env`], the fake security answering `extra`'s routes too.
pub async fn env_with(extra: Router) -> Option<Env> {
    let Some(uri) = mongo_uri() else {
        eprintln!("MODLIX__MONGO__URI not set: skipped");
        return None;
    };
    let db_name = format!("rusttest_ui_{}_{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst));
    let mongo = MongoConfig { uri, database: db_name.clone(), ..Default::default() };
    let db = platform::db::mongo_database(&mongo).await.expect("mongo");
    let fake = Arc::new(FakeSecurity::default());
    let security_url = serve(security_router(fake.clone()).merge(extra)).await;
    let security = SecurityClient::new(Upstream::fixed(&[&security_url]), 0).unwrap();
    let cache = CacheService::new("cmn", "evictionChannel", None).unwrap();
    let store = overridable::Store::new(db.clone(), security.clone(), &cache);
    let mut config = UiConfig::default();
    config.mongo = mongo;
    let state = AppState::new(Inner {
        store,
        security,
        properties: cache.family(),
        fillers: cache.family(),
        app_status: cache.family(),
        app_dependencies: cache.family(),
        cache,
        config,
    });
    let router = ui::handlers::router(state.clone());
    Some(Env { db, db_name, fake, state, router, security_url })
}

pub struct Answer {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl Answer {
    pub fn json(&self) -> JValue {
        overridable::json::parse(&self.body).unwrap_or_else(|_| panic!("not JSON: {}", self.text()))
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    pub fn header(&self, name: &str) -> Option<String> {
        self.headers.get(name).and_then(|v| v.to_str().ok()).map(str::to_string)
    }

    pub fn etag(&self) -> String {
        self.header("etag").unwrap_or_default()
    }

    pub fn obj(&self) -> JMap {
        match self.json() {
            JValue::Object(m) => m,
            other => panic!("not an object: {}", other.java_to_string()),
        }
    }

    /// A coded error's code and Java's text (`debugMessage` without its `[key] `).
    #[allow(dead_code)]
    pub fn coded(&self) -> (String, String) {
        let o = self.obj();
        let field = |k: &str| o.get(k).map(JValue::java_to_string).unwrap_or_default();
        let d = field("debugMessage");
        let java = d.strip_prefix('[').and_then(|r| r.split_once("] ")).map(|(_, t)| t.to_string()).unwrap_or(d);
        (field("code"), java)
    }
}

/// A request with the gateway's headers.
pub struct Req {
    pub method: &'static str,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

pub fn get_req(path: &str) -> Req {
    Req { method: "GET", path: path.to_string(), headers: vec![("appCode".into(), APP.into()), ("clientCode".into(), "SYSTEM".into())], body: None }
}

impl Req {
    pub fn client(mut self, c: &str) -> Self {
        self.headers.retain(|(k, _)| k != "clientCode");
        self.headers.push(("clientCode".into(), c.into()));
        self
    }

    pub fn app(mut self, a: &str) -> Self {
        self.headers.retain(|(k, _)| k != "appCode");
        self.headers.push(("appCode".into(), a.into()));
        self
    }

    pub fn no_header(mut self, name: &str) -> Self {
        self.headers.retain(|(k, _)| k != name);
        self
    }

    pub fn header(mut self, k: &str, v: &str) -> Self {
        self.headers.push((k.into(), v.into()));
        self
    }

    pub fn user(self, client: &str, authorities: &str) -> Self {
        self.header("Authorization", &format!("user {client} {authorities}"))
    }

    pub fn draft(self) -> Self {
        self.header("x-draft", "true")
    }

    pub fn etag(self, tag: &str) -> Self {
        self.header("If-None-Match", tag)
    }

    pub fn method(mut self, m: &'static str) -> Self {
        self.method = m;
        self
    }

    pub fn body(mut self, b: &str) -> Self {
        self.body = Some(b.as_bytes().to_vec());
        self
    }
}

impl Env {
    pub async fn call(&self, r: Req) -> Answer {
        let mut b = Request::builder().method(r.method).uri(&r.path);
        for (k, v) in &r.headers {
            b = b.header(k, v);
        }
        let req = b.body(r.body.map(Body::from).unwrap_or_else(Body::empty)).unwrap();
        let resp = self.router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec();
        Answer { status, headers, body }
    }

    pub fn chain(&self, client: &str, chain: &[&str]) {
        self.fake.chains.lock().unwrap().insert(client.into(), chain.iter().map(|s| s.to_string()).collect());
    }

    pub fn status(&self, app: &str, status: &str) {
        self.fake.status.lock().unwrap().insert(app.into(), status.into());
    }

    pub fn deps(&self, app: &str, deps: &[&str]) {
        self.fake.deps.lock().unwrap().insert(app.into(), deps.iter().map(|s| s.to_string()).collect());
    }

    pub async fn insert(&self, coll: &str, d: Document) -> String {
        let id = ObjectId::new();
        let mut d = d;
        d.insert("_id", id);
        self.db.collection::<Document>(coll).insert_one(d).await.unwrap();
        id.to_hex()
    }

    pub async fn page(&self, name: &str, permission: Option<&str>, props: Document) -> String {
        let mut d = doc! {"name": name, "appCode": APP, "clientCode": "SYSTEM", "version": 1_i32,
            "properties": props, "rootComponent": "root",
            "componentDefinition": {"root": {"key": "root", "name": "Root", "type": "Grid"}}};
        if let Some(p) = permission {
            d.insert("permission", p);
        }
        self.insert("page", d).await
    }

    /// Clears the caches a Java save would clear (the eviction message's local half).
    pub async fn evict(&self, names: &[&str]) {
        for n in names {
            self.state.inner().cache.evict_all_everywhere(n).await;
        }
    }

    /// The fixture app the Java engine tests use, with every page kind it names.
    pub async fn seed_app(&self) {
        self.insert(
            "application",
            doc! {"name": APP, "appCode": APP, "clientCode": "SYSTEM", "version": 1_i32,
            "permission": "Authorities.Logged_IN",
            "blueprint": {"plan": {"x": 1_i32}},
            "properties": {
                "shellPage": "shell", "loginPage": "login", "notFoundPage": "notfound",
                "forbiddenPage": "forbidden", "consentPage": "consent", "defaultPage": "home",
                "mobileApps": {"a": 1_i32}, "manifest": {"m": 1_i32},
                "themes": {"t1": {"name": "light", "order": 1_i32, "style": "lightstyle"},
                           "t2": {"name": "dark", "order": 2_i32}},
                "styles": {"s1": {"name": "main", "order": 1_i32}}
            }},
        )
        .await;
        for (name, perm) in [
            ("shell", None),
            ("login", None),
            ("notfound", None),
            ("forbidden", None),
            ("consent", None),
            ("home", None),
            ("campaigns", Some("Authorities.Logged_IN")),
            ("secret", Some("Authorities.ROLE_Owner")),
        ] {
            self.page(name, perm, doc! {"title": name}).await;
        }
        self.insert("theme", doc! {"name": "light", "appCode": APP, "clientCode": "SYSTEM", "variables": {"ALL": {"c": "white"}}})
            .await;
        self.insert("theme", doc! {"name": "dark", "appCode": APP, "clientCode": "SYSTEM", "variables": {"ALL": {"c": "black"}}})
            .await;
        self.insert("style", doc! {"name": "main", "appCode": APP, "clientCode": "SYSTEM", "styleString": "body{}"}).await;
        self.insert("style", doc! {"name": "lightstyle", "appCode": APP, "clientCode": "SYSTEM", "styleString": ".l{}"})
            .await;
        self.insert(
            "filler",
            doc! {"name": APP, "appCode": APP, "clientCode": "SYSTEM", "values": {"brand": "Acme"}},
        )
        .await;
    }

    pub async fn done(self) {
        self.db.drop().await.unwrap();
    }
}

pub fn s(v: &str) -> JValue {
    JValue::Str(v.to_string())
}

pub fn prop<'a>(m: &'a JMap, k: &str) -> Option<&'a JValue> {
    m.get("properties").and_then(JValue::as_object).and_then(|p| p.get(k))
}
