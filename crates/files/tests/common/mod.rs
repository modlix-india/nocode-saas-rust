//! What the files integration tests share: an in-process S3 (path style, the four calls the
//! store makes), an in-process security service, a MySQL that refuses every query (for tests
//! that must never reach a database) and, for the gated tests, a scratch MySQL database made
//! from the local `files` schema and dropped again.

#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use files::config::FilesConfig;
use files::dao::{Dao, FileDetail};
use files::paths::Kind;
use files::state::{AppState, Inner};
use files::store::{s3_client, Store};
use files::Unit;
use percent_encoding::percent_decode_str;
use platform::cache::CacheService;
use platform::http::RouteTemplate;
use platform::security::SecurityClient;
use platform::upstream::Upstream;
use serde_json::{json, Value};
use sqlx::mysql::{MySqlConnectOptions, MySqlPool, MySqlPoolOptions};
use sqlx::Executor;
use tower::ServiceExt;

/// Serves `router` on a free local port for the life of the test's runtime.
pub async fn serve(router: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    format!("http://{addr}")
}

// ---------------------------------------------------------------------------------------------
// S3
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct S3Object {
    pub bytes: Vec<u8>,
    pub content_type: Option<String>,
    pub disposition: Option<String>,
}

/// The objects, by `<bucket>/<key>`, and every call made, as `<METHOD> <bucket>/<key>`.
#[derive(Default)]
pub struct S3State {
    pub objects: Mutex<BTreeMap<String, S3Object>>,
    pub log: Mutex<Vec<String>>,
}

/// Listing page size: small, so the store's continuation loop is exercised.
pub const S3_PAGE: usize = 2;

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn s3_error(status: StatusCode, code: &str) -> Response {
    let body = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{code}</Code><Message>{code}</Message></Error>");
    (status, [(header::CONTENT_TYPE, "application/xml")], body).into_response()
}

async fn s3_handler(State(st): State<Arc<S3State>>, req: Request) -> Response {
    let method = req.method().clone();
    let raw_path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let headers = req.headers().clone();
    let body = axum::body::to_bytes(req.into_body(), usize::MAX).await.unwrap_or_default();
    let path = percent_decode_str(raw_path.trim_start_matches('/')).decode_utf8_lossy().into_owned();
    let (bucket, key) = path.split_once('/').unwrap_or((path.as_str(), ""));
    let q: HashMap<String, String> = files::spring::parse_query(Some(&query)).into_iter().collect();
    st.log.lock().unwrap().push(format!("{method} {bucket}/{key}"));

    // A refusal the SDK does not retry, for the failure paths.
    if key.contains("s3fail") || q.get("prefix").is_some_and(|p| p.contains("s3fail")) {
        return s3_error(StatusCode::FORBIDDEN, "AccessDenied");
    }
    let full = format!("{bucket}/{key}");
    match method {
        Method::GET if key.is_empty() => {
            let prefix = q.get("prefix").cloned().unwrap_or_default();
            let start: usize = q.get("continuation-token").and_then(|t| t.parse().ok()).unwrap_or(0);
            let objects = st.objects.lock().unwrap();
            let all: Vec<(String, usize)> = objects
                .iter()
                .filter_map(|(k, o)| {
                    let (b, k) = k.split_once('/')?;
                    (b == bucket && k.starts_with(&prefix)).then(|| (k.to_string(), o.bytes.len()))
                })
                .collect();
            let page: Vec<&(String, usize)> = all.iter().skip(start).take(S3_PAGE).collect();
            let truncated = start + S3_PAGE < all.len();
            let mut xml = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>{}</Name><Prefix>{}</Prefix><KeyCount>{}</KeyCount><MaxKeys>{S3_PAGE}</MaxKeys><IsTruncated>{truncated}</IsTruncated>",
                xml_escape(bucket),
                xml_escape(&prefix),
                page.len()
            );
            if truncated {
                xml.push_str(&format!("<NextContinuationToken>{}</NextContinuationToken>", start + S3_PAGE));
            }
            for (k, size) in page {
                xml.push_str(&format!(
                    "<Contents><Key>{}</Key><LastModified>2026-10-15T00:00:00.000Z</LastModified><ETag>&quot;e&quot;</ETag><Size>{size}</Size><StorageClass>STANDARD</StorageClass></Contents>",
                    xml_escape(k)
                ));
            }
            xml.push_str("</ListBucketResult>");
            (StatusCode::OK, [(header::CONTENT_TYPE, "application/xml")], xml).into_response()
        }
        Method::GET => match st.objects.lock().unwrap().get(&full) {
            None => s3_error(StatusCode::NOT_FOUND, "NoSuchKey"),
            Some(o) => (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, o.content_type.clone().unwrap_or_else(|| "application/octet-stream".into())),
                    (header::ETAG, "\"e\"".to_string()),
                ],
                o.bytes.clone(),
            )
                .into_response(),
        },
        Method::PUT => {
            let text = |h: header::HeaderName| headers.get(h).and_then(|v| v.to_str().ok()).map(str::to_string);
            let obj = S3Object {
                bytes: body.to_vec(),
                content_type: text(header::CONTENT_TYPE),
                disposition: text(header::CONTENT_DISPOSITION),
            };
            st.objects.lock().unwrap().insert(full, obj);
            (StatusCode::OK, [(header::ETAG, "\"e\"")]).into_response()
        }
        Method::DELETE => {
            st.objects.lock().unwrap().remove(&full);
            StatusCode::NO_CONTENT.into_response()
        }
        _ => s3_error(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed"),
    }
}

// ---------------------------------------------------------------------------------------------
// Security
// ---------------------------------------------------------------------------------------------

/// What the fake security service knows. Tokens map to the `ContextAuthentication` it answers.
#[derive(Default)]
pub struct World {
    pub tokens: HashMap<String, Value>,
    /// Client code to id.
    pub clients: HashMap<String, u64>,
    /// Codes `validateClientCode` accepts.
    pub valid: Vec<String>,
    /// (managing code, managed code), direct; management is transitive here.
    pub manages: Vec<(String, String)>,
    /// User id to client id.
    pub users: HashMap<u64, u64>,
    /// App code to the `clientId` security sends for it (a number, a string, or nothing).
    pub apps: HashMap<String, Value>,
    pub hierarchy: HashMap<String, Vec<String>>,
    pub instructions: Value,
}

impl World {
    fn code_of(&self, id: u64) -> Option<String> {
        self.clients.iter().find(|(_, v)| **v == id).map(|(k, _)| k.clone())
    }

    /// `managing` is `client` or manages it, directly or through others.
    pub fn manages(&self, managing: &str, client: &str) -> bool {
        if managing == client {
            return true;
        }
        let mut frontier = vec![managing.to_string()];
        let mut seen = vec![];
        while let Some(m) = frontier.pop() {
            for (a, b) in &self.manages {
                if *a == m && !seen.contains(b) {
                    if b == client {
                        return true;
                    }
                    seen.push(b.clone());
                    frontier.push(b.clone());
                }
            }
        }
        false
    }
}

/// A signed-in caller as security describes one.
pub fn ca(user: u64, client_id: u64, code: &str, system: bool, authorities: &[&str]) -> Value {
    json!({
        "user": {"id": user, "clientId": client_id, "userName": format!("user{user}"), "stringAuthorities": authorities},
        "authenticated": true,
        "loggedInFromClientId": client_id,
        "loggedInFromClientCode": code,
        "clientTypeCode": if system { "SYS" } else { "BUS" },
        "clientCode": code
    })
}

pub const SYS_AUTHORITIES: &[&str] = &[
    "Authorities.Logged_IN",
    "Authorities.STATIC_Files_PATH",
    "Authorities.SECURED_Files_PATH",
    "Authorities.Files_RETENTION",
    "Authorities.Client_UPDATE",
    "Authorities.User_UPDATE",
    "Authorities.ROLE_MobileApp_UPLOADER",
];

pub struct SecState {
    pub world: Mutex<World>,
    /// Every call, as `<path>?<query>`.
    pub calls: Mutex<Vec<String>>,
    /// Bodies posted to the billing charge.
    pub charges: Mutex<Vec<String>>,
}

impl SecState {
    /// SYSTEM (id 1) manages CLIA (10), which manages CHILD (11); STRANGER (99) is nobody's.
    /// Tokens: `sys` (user 142 of SYSTEM, every authority), `clia` (user 500), `child` (user
    /// 600), `anon` (not signed in), `refuse` (security answers 401), `garbage` (unreadable).
    pub fn standard() -> Self {
        let mut w = World::default();
        for (code, id) in [("SYSTEM", 1), ("CLIA", 10), ("CHILD", 11), ("STRANGER", 99)] {
            w.clients.insert(code.into(), id);
            w.valid.push(code.into());
        }
        w.manages.push(("SYSTEM".into(), "CLIA".into()));
        w.manages.push(("SYSTEM".into(), "STRANGER".into()));
        w.manages.push(("CLIA".into(), "CHILD".into()));
        w.users.insert(142, 1);
        w.users.insert(500, 10);
        w.users.insert(600, 11);
        w.tokens.insert("sys".into(), ca(142, 1, "SYSTEM", true, SYS_AUTHORITIES));
        w.tokens.insert(
            "clia".into(),
            ca(500, 10, "CLIA", false, &["Authorities.Logged_IN", "Authorities.STATIC_Files_PATH", "Authorities.SECURED_Files_PATH"]),
        );
        w.tokens.insert("child".into(), ca(600, 11, "CHILD", false, &["Authorities.Logged_IN"]));
        w.tokens.insert("anon".into(), json!({"authenticated": false}));
        w.instructions = json!([]);
        Self { world: Mutex::new(w), calls: Mutex::new(vec![]), charges: Mutex::new(vec![]) }
    }

    pub fn token(&self, name: &str, ca: Value) {
        self.world.lock().unwrap().tokens.insert(name.into(), ca);
    }

    pub fn calls_to(&self, path_part: &str) -> usize {
        self.calls.lock().unwrap().iter().filter(|c| c.contains(path_part)).count()
    }
}

fn ok_json(v: Value) -> Response {
    (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], v.to_string()).into_response()
}

fn ok_empty() -> Response {
    StatusCode::OK.into_response()
}

async fn security_handler(State(st): State<Arc<SecState>>, req: Request) -> Response {
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    st.calls.lock().unwrap().push(format!("{path}?{query}"));
    let q: HashMap<String, String> = files::spring::parse_query(Some(&query)).into_iter().collect();
    let qs = |k: &str| q.get(k).cloned().unwrap_or_default();
    let qn = |k: &str| q.get(k).and_then(|v| v.parse::<u64>().ok());
    let auth = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = axum::body::to_bytes(req.into_body(), usize::MAX).await.unwrap_or_default();
    let w = st.world.lock().unwrap();

    match path.as_str() {
        "/api/security/internal/securityContextAuthentication" => {
            let token = auth.trim_start_matches("basic ").trim().to_string();
            match token.as_str() {
                "refuse" => (StatusCode::UNAUTHORIZED, [(header::CONTENT_TYPE, "application/json")], "{\"message\":\"Token expired\"}").into_response(),
                "garbage" => (StatusCode::OK, "not json").into_response(),
                t => ok_json(w.tokens.get(t).cloned().unwrap_or_else(|| json!({"authenticated": false}))),
            }
        }
        "/api/security/clients/internal/getClientByCode" => match w.clients.get(&qs("clientCode")) {
            Some(id) => ok_json(json!({"id": id, "code": qs("clientCode")})),
            None => ok_empty(),
        },
        "/api/security/clients/internal/isUserClientManageClient" => {
            let user_client = qn("userClientId").unwrap_or(0);
            let target = qn("targetClientId");
            let managed = match (w.code_of(user_client), target.and_then(|t| w.code_of(t))) {
                (Some(m), Some(c)) => w.manages(&m, &c),
                _ => false,
            };
            ok_json(json!(managed))
        }
        "/api/security/clients/internal/validateClientCode" => {
            if w.valid.contains(&qs("clientCode")) {
                ok_json(json!(true))
            } else {
                ok_empty()
            }
        }
        "/api/security/clients/internal/getClientById" => match qn("clientId").and_then(|id| w.code_of(id)) {
            Some(code) => ok_json(json!({"id": qn("clientId"), "code": code})),
            None => ok_empty(),
        },
        "/api/security/clients/internal/clientHierarchyCodes" => {
            let cc = qs("clientCode");
            if cc == "BOOM" {
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            ok_json(json!(w.hierarchy.get(&cc).cloned().unwrap_or_default()))
        }
        "/api/security/clients/internal/doesClientManageClientCode" => {
            ok_json(json!(w.manages(&qs("managingClientCode"), &qs("clientCode"))))
        }
        "/api/security/internal/billing/instructions" => ok_json(w.instructions.clone()),
        "/api/security/internal/billing/charge" => {
            let text = String::from_utf8_lossy(&body).into_owned();
            if text.contains("\"billedClientId\":13") {
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            st.charges.lock().unwrap().push(text);
            ok_json(json!(true))
        }
        p if p.starts_with("/api/security/users/internal/") => {
            let id: u64 = p.rsplit('/').next().and_then(|s| s.parse().ok()).unwrap_or(0);
            match w.users.get(&id) {
                Some(c) => ok_json(json!({"id": id, "clientId": c})),
                None => ok_empty(),
            }
        }
        p if p.starts_with("/api/security/applications/internal/appCode/") => {
            let code = p.rsplit('/').next().unwrap_or("");
            if code == "boom" {
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            match w.apps.get(code) {
                Some(Value::Null) => ok_json(json!({"appCode": code})),
                Some(c) => ok_json(json!({"appCode": code, "clientId": c})),
                None => ok_empty(),
            }
        }
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

// ---------------------------------------------------------------------------------------------
// MySQL
// ---------------------------------------------------------------------------------------------

/// A pool whose every connection attempt fails at once: the server end closes each connection
/// as soon as it is accepted.
pub async fn dead_pool() -> MySqlPool {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((s, _)) = listener.accept().await {
            drop(s);
        }
    });
    MySqlPoolOptions::new()
        .acquire_timeout(Duration::from_secs(2))
        .connect_lazy_with(MySqlConnectOptions::new().host("127.0.0.1").port(port).username("nobody").database("none"))
}

/// The gate of the tests that need the local MySQL.
pub const GATE: &str = "FILES_TEST_MYSQL";

/// The local MySQL as the files units reach it (`MODLIX__DATABASE__*`, from `config/local.toml`),
/// when the gate is set.
pub fn mysql_options() -> Option<MySqlConnectOptions> {
    std::env::var(GATE).ok().filter(|v| !v.is_empty())?;
    let password = std::env::var("MODLIX__DATABASE__PASSWORD").ok()?;
    let env = |k: &str, d: &str| std::env::var(k).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| d.to_string());
    Some(
        MySqlConnectOptions::new()
            .host(&env("MODLIX__DATABASE__HOST", "127.0.0.1"))
            .port(env("MODLIX__DATABASE__PORT", "3306").parse().unwrap_or(3306))
            .username(&env("MODLIX__DATABASE__USERNAME", "root"))
            .password(&password)
            .timezone(Some(String::from("+00:00"))),
    )
}

const TABLES: &[&str] = &[
    "files_file_system",
    "files_access_path",
    "files_secured_access_keys",
    "files_upload_download",
    "files_retention_policy",
];

fn without_auto_increment(ddl: &str) -> String {
    match ddl.find(" AUTO_INCREMENT=") {
        None => ddl.to_string(),
        Some(i) => {
            let rest = &ddl[i + " AUTO_INCREMENT=".len()..];
            let digits = rest.chars().take_while(char::is_ascii_digit).count();
            format!("{}{}", &ddl[..i], &rest[digits..])
        }
    }
}

/// A database of its own, `files_rusttest_<epoch>_<random>`, with the tables of the local
/// `files` schema (their DDL read from it; nothing is written there).
pub struct Scratch {
    pub name: String,
    pub pool: MySqlPool,
    admin: MySqlPool,
}

impl Scratch {
    pub async fn create() -> Option<Self> {
        let opts = mysql_options()?;
        let admin = MySqlPoolOptions::new().max_connections(1).connect_with(opts.clone()).await.expect("the local MySQL");
        let now = chrono::Utc::now().timestamp();
        // Scratch databases of runs that died before dropping theirs.
        let names: Vec<String> = sqlx::query_scalar(
            "SELECT CAST(SCHEMA_NAME AS CHAR) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME LIKE 'files\\_rusttest\\_%'",
        )
        .fetch_all(&admin)
        .await
        .unwrap();
        for n in names {
            if n.split('_').nth(2).and_then(|t| t.parse::<i64>().ok()).is_some_and(|ts| now - ts > 7200) {
                admin.execute(format!("DROP DATABASE IF EXISTS `{n}`").as_str()).await.unwrap();
            }
        }
        let name = format!("files_rusttest_{now}_{:08x}", rand::random::<u32>());
        admin
            .execute(format!("CREATE DATABASE `{name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci").as_str())
            .await
            .unwrap();
        let pool = MySqlPoolOptions::new().max_connections(4).connect_with(opts.database(&name)).await.unwrap();
        for t in TABLES {
            let (_, ddl): (String, String) =
                sqlx::query_as(&format!("SHOW CREATE TABLE `files`.`{t}`")).fetch_one(&admin).await.unwrap();
            pool.execute(without_auto_increment(&ddl).as_str()).await.unwrap();
        }
        Some(Self { name, pool, admin })
    }

    pub async fn drop_db(self) {
        self.pool.close().await;
        self.admin.execute(format!("DROP DATABASE IF EXISTS `{}`", self.name).as_str()).await.unwrap();
        self.admin.close().await;
    }
}

/// How many scratch databases a test binary holds at once. The local MySQL allows 151
/// connections and the local stack already holds about a hundred.
const MAX_SCRATCH: usize = 3;
static SCRATCH_IN_USE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

struct ScratchPermit;

impl ScratchPermit {
    async fn acquire() -> Self {
        use std::sync::atomic::Ordering;
        while SCRATCH_IN_USE
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| (n < MAX_SCRATCH).then_some(n + 1))
            .is_err()
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Self
    }
}

impl Drop for ScratchPermit {
    fn drop(&mut self) {
        SCRATCH_IN_USE.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Runs `checks` on a scratch database and drops it afterwards, whether the checks pass or not.
/// Without the gate the test is a no-op that says so.
pub async fn with_scratch<F, Fut>(checks: F)
where
    F: FnOnce(MySqlPool) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    if mysql_options().is_none() {
        eprintln!("skipped: set {GATE}=1 and MODLIX__DATABASE__PASSWORD (eval \"$(tools/local-env.py)\")");
        return;
    }
    let _permit = ScratchPermit::acquire().await;
    let Some(db) = Scratch::create().await else {
        eprintln!("skipped: set {GATE}=1 and MODLIX__DATABASE__PASSWORD (eval \"$(tools/local-env.py)\")");
        return;
    };
    let outcome = tokio::spawn(checks(db.pool.clone())).await;
    db.drop_db().await;
    if let Err(e) = outcome {
        if e.is_panic() {
            std::panic::resume_unwind(e.into_panic());
        }
        panic!("{e}");
    }
}

// ---------------------------------------------------------------------------------------------
// The service under test
// ---------------------------------------------------------------------------------------------

pub struct Resp {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
    pub route: Option<&'static str>,
}

impl Resp {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|e| panic!("not JSON ({e}): {}", self.text()))
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// Java's text for an error body: its `message`, or for a coded error (`code`) the
    /// `debugMessage` without its `[key] ` (the plain text is [`Resp::plain`]).
    pub fn message(&self) -> String {
        let v = self.json();
        if v.get("code").is_none() {
            return v["message"].as_str().unwrap_or("").to_string();
        }
        let d = v["debugMessage"].as_str().unwrap_or("");
        d.strip_prefix('[').and_then(|r| r.split_once("] ")).map(|(_, t)| t).unwrap_or(d).to_string()
    }

    /// A coded error's code.
    #[allow(dead_code)]
    pub fn code(&self) -> String {
        self.json()["code"].as_str().unwrap_or("").to_string()
    }

    /// A coded error's plain text.
    #[allow(dead_code)]
    pub fn plain(&self) -> String {
        self.json()["message"].as_str().unwrap_or("").to_string()
    }
}

pub enum FormPart<'a> {
    Text(&'a str, &'a str),
    File(&'a str, &'a str, &'a str, Vec<u8>),
}

pub const BOUNDARY: &str = "----filesTestBoundary7MA4YWxkTrZu0gW";

/// A `multipart/form-data` body.
pub fn multipart(parts: &[FormPart]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts {
        out.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
        match p {
            FormPart::Text(name, value) => {
                out.extend_from_slice(format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n").as_bytes());
            }
            FormPart::File(name, file_name, content_type, bytes) => {
                out.extend_from_slice(
                    format!("Content-Disposition: form-data; name=\"{name}\"; filename=\"{file_name}\"\r\nContent-Type: {content_type}\r\n\r\n")
                        .as_bytes(),
                );
                out.extend_from_slice(bytes);
                out.extend_from_slice(b"\r\n");
            }
        }
    }
    out.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
    out
}

/// A `w` x `h` PNG of one colour.
pub fn png(w: u32, h: u32) -> Vec<u8> {
    let img = image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(w, h, image::Rgba([200, 10, 10, 255])));
    let mut out = std::io::Cursor::new(Vec::new());
    img.write_to(&mut out, image::ImageFormat::Png).unwrap();
    out.into_inner()
}

pub fn bucket(kind: Kind) -> &'static str {
    match kind {
        Kind::Static => "test-static",
        Kind::Secured => "test-secured",
    }
}

pub struct Harness {
    pub unit: Unit,
    pub state: AppState,
    pub s3: Arc<S3State>,
    pub s3_url: String,
    pub sec: Arc<SecState>,
    pub sec_url: String,
    pub dir: PathBuf,
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Harness {
    /// With a database that refuses every query.
    pub async fn new(unit: Unit) -> Self {
        Self::with_pool(unit, dead_pool().await).await
    }

    pub async fn with_pool(unit: Unit, pool: MySqlPool) -> Self {
        let s3 = Arc::new(S3State::default());
        let s3_url = serve(Router::new().fallback(s3_handler).with_state(s3.clone())).await;
        let sec = Arc::new(SecState::standard());
        let sec_url = serve(Router::new().fallback(security_handler).with_state(sec.clone())).await;

        let dir = std::env::temp_dir().join(format!("files-it-{:016x}", rand::random::<u64>()));
        let work_dir = dir.join("work");
        std::fs::create_dir_all(&work_dir).unwrap();
        let mut config = FilesConfig::default();
        config.storage.endpoint = s3_url.clone();
        config.storage.bucket_prefix = "test".into();
        let client = s3_client(&s3_url, "test-key", "test-secret");
        let cache = CacheService::new("cmn", "evictionChannel", None).unwrap();
        let state = AppState::new(Inner {
            dao: Dao::new(pool),
            static_store: Store::new(client.clone(), "test-static".into(), &dir).unwrap(),
            secured_store: Store::new(client, "test-secured".into(), &dir).unwrap(),
            details: cache.family(),
            exists: cache.family(),
            lists: cache.family(),
            retention_rows: cache.family(),
            hierarchies: cache.family(),
            cache,
            security: SecurityClient::new(Upstream::fixed(&[&sec_url]), 0).unwrap(),
            server_port: 8103,
            config,
            work_dir,
        });
        Self { unit, state, s3, s3_url, sec, sec_url, dir }
    }

    pub fn router(&self) -> Router {
        files::handlers::router(self.unit, self.state.clone())
    }

    pub async fn send(&self, req: axum::http::Request<Body>) -> Resp {
        let resp = self.router().oneshot(req).await.unwrap();
        let route = resp.extensions().get::<RouteTemplate>().map(|r| r.0);
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        Resp { status, headers, body, route }
    }

    pub fn request(method: Method, uri: &str, token: Option<&str>) -> axum::http::request::Builder {
        let b = axum::http::Request::builder().method(method).uri(uri);
        match token {
            Some(t) => b.header(header::AUTHORIZATION, format!("Bearer {t}")),
            None => b,
        }
    }

    pub async fn get(&self, uri: &str, token: Option<&str>) -> Resp {
        self.send(Self::request(Method::GET, uri, token).body(Body::empty()).unwrap()).await
    }

    pub async fn get_with(&self, uri: &str, token: Option<&str>, headers: &[(&str, &str)]) -> Resp {
        let mut b = Self::request(Method::GET, uri, token);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        self.send(b.body(Body::empty()).unwrap()).await
    }

    pub async fn call(&self, method: Method, uri: &str, token: Option<&str>) -> Resp {
        self.send(Self::request(method, uri, token).body(Body::empty()).unwrap()).await
    }

    pub async fn json(&self, method: Method, uri: &str, token: Option<&str>, body: &Value) -> Resp {
        self.send(
            Self::request(method, uri, token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
    }

    pub async fn raw(&self, method: Method, uri: &str, token: Option<&str>, body: impl Into<Body>) -> Resp {
        self.send(Self::request(method, uri, token).body(body.into()).unwrap()).await
    }

    pub async fn form(&self, uri: &str, token: Option<&str>, parts: &[FormPart<'_>]) -> Resp {
        self.send(
            Self::request(Method::POST, uri, token)
                .header(header::CONTENT_TYPE, format!("multipart/form-data; boundary={BOUNDARY}"))
                .body(Body::from(multipart(parts)))
                .unwrap(),
        )
        .await
    }

    /// Puts a row's detail in the `fsGetDetail` cache, as a read would have.
    pub async fn seed_detail(&self, kind: Kind, cc: &str, rest: &str, detail: FileDetail) {
        self.state
            .inner()
            .details
            .insert(&format!("fsGetDetail-{}-{cc}", kind.db_name()), rest.to_string(), detail)
            .await;
    }

    pub fn put_object(&self, kind: Kind, key: &str, bytes: &[u8]) {
        self.s3.objects.lock().unwrap().insert(
            format!("{}/{key}", bucket(kind)),
            S3Object { bytes: bytes.to_vec(), content_type: None, disposition: None },
        );
    }

    pub fn object(&self, kind: Kind, key: &str) -> Option<S3Object> {
        self.s3.objects.lock().unwrap().get(&format!("{}/{key}", bucket(kind))).cloned()
    }

    pub fn s3_calls(&self, prefix: &str) -> usize {
        self.s3.log.lock().unwrap().iter().filter(|l| l.starts_with(prefix)).count()
    }
}

/// A file detail as the DAO would make it.
pub fn file(id: u64, name: &str, size: u64, modified: i64) -> FileDetail {
    FileDetail { id, name: name.into(), is_directory: false, size, created: modified, last_modified: modified }
}

pub fn folder(id: u64, name: &str) -> FileDetail {
    FileDetail { id, name: name.into(), is_directory: true, size: 0, created: 1, last_modified: 1 }
}

/// Waits for `check` to hold, for up to ten seconds.
pub async fn eventually<F, Fut>(what: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    for _ in 0..200 {
        if check().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {what}");
}
