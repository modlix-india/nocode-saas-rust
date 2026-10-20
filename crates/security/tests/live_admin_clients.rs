//! security-admin's clients, apps and hosting routes against the local `security` schema, ported
//! from `ClientControllerTest`, `AppControllerTest`, `ClientUrlControllerTest`,
//! `SSLCertificateControllerTest`, `ClientActivityControllerTest`, the policy service tests,
//! `ClientServiceTest`, `AppServiceTest`, `ClientUrlServiceTest`, `AppRegistrationServiceV2Test`,
//! `AppAccessEventServiceTest` and the lifecycle integration tests (`AppLifecycleIntegrationTest`,
//! `ClientLifecycleIntegrationTest`), with the expected values read from the same schema.
//!
//! Gated: `SECURITY_AUTH_LIVE=1` with `eval "$(tools/local-env.py)"`. Reads are read-only; the write
//! test makes its own scratch app (`zzrustlive...`) with its draft URL, a property, an access
//! row, a dependency, a policy, a client URL, a registration object and an integration, and
//! removes all of them through the routes. Events are logged, not published; no Redis.

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use axum::Router;
use platform::cache::CacheService;
use platform::config::MySqlConfig;
use serde_json::{json, Value};
use sqlx::{MySqlPool, Row};
use tower::ServiceExt;

use security::config::AuthConfig;

struct Live {
    router: Router,
    pool: MySqlPool,
}

async fn live() -> Option<Live> {
    live_with(None).await
}

/// [`live`] with `IFeignFilesService` pointed at `files` (an in-process fake).
async fn live_with(files: Option<&str>) -> Option<Live> {
    let (Ok(_), Ok(password), Ok(key)) =
        (std::env::var("SECURITY_AUTH_LIVE"), std::env::var("MODLIX__DATABASE__PASSWORD"), std::env::var("MODLIX__JWT__KEY"))
    else {
        eprintln!("skipped: SECURITY_AUTH_LIVE / MODLIX__DATABASE__PASSWORD / MODLIX__JWT__KEY not set");
        return None;
    };
    let mut cfg = AuthConfig::default();
    cfg.database = MySqlConfig { database: "security".into(), password, max_connections: 4, ..Default::default() };
    cfg.jwt.key = key;
    cfg.security.app_code_suffix = ".local".into();
    cfg.security.subdomain_endings = ".local.modlix.com, .local.sitezump.ai".into();
    cfg.wallet.publish_events = false;
    cfg.events.publish_events = false;
    let pool = platform::db::mysql_pool(&cfg.database).await.unwrap();
    let cache = CacheService::new("cmn", "evictionChannel", None).unwrap();
    let mut state = security::admin::build(&cfg, pool.clone(), cache, None).unwrap();
    if let Some(f) = files {
        state = std::sync::Arc::new(security::admin::Admin {
            internal: state.internal.clone(),
            events: state.events.clone(),
            files: Some(platform::upstream::Upstream::fixed(&[f])),
            hosting: state.hosting.clone(),
        });
    }
    Some(Live { router: security::admin::router(state), pool })
}

const P: &str = "/api/security";

fn basic(user: u64) -> String {
    use base64::Engine;
    format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{user}:Pass@1234")))
}

/// SYSTEM user 142.
fn sys() -> Vec<(&'static str, String)> {
    vec![("authorization", basic(142)), ("clientcode", "SYSTEM".into()), ("appcode", "appbuilder".into())]
}

/// User 110, an Owner of client FIN.
fn owner() -> Vec<(&'static str, String)> {
    vec![("authorization", basic(110)), ("clientcode", "FIN".into()), ("appcode", "appbuilder".into())]
}

/// User 8 of FIN: signed in, no authority.
fn plain() -> Vec<(&'static str, String)> {
    vec![("authorization", basic(8)), ("clientcode", "FIN".into()), ("appcode", "appbuilder".into())]
}

fn anon() -> Vec<(&'static str, String)> {
    vec![("clientcode", "SYSTEM".into()), ("appcode", "appbuilder".into())]
}

struct Resp {
    status: StatusCode,
    body: String,
    content_type: Option<String>,
    location: Option<String>,
    set_cookie: Option<String>,
}

impl Resp {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }

    /// Java's text for this error: the coded body's `debugMessage`, without its `[key]`.
    fn message(&self) -> String {
        let d = self.json()["debugMessage"].as_str().unwrap_or("").to_string();
        match d.strip_prefix('[').and_then(|r| r.split_once("] ")) {
            Some((_, rest)) => rest.to_string(),
            None => d,
        }
    }
}

impl Live {
    async fn call(&self, method: &str, path: &str, headers: &[(&str, String)], body: Option<Value>) -> Resp {
        let mut b = Request::builder()
            .method(method)
            .uri(format!("{P}{path}"))
            .header("host", "localhost:8001")
            .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 50000))));
        for (k, v) in headers {
            b = b.header(*k, v);
        }
        let req = match body {
            Some(v) => b.header("content-type", "application/json").body(Body::from(v.to_string())).unwrap(),
            None => b.body(Body::empty()).unwrap(),
        };
        self.send(req).await
    }

    /// A body sent with no `Content-Type`.
    async fn call_untyped(&self, method: &str, path: &str, headers: &[(&str, String)], body: &str) -> Resp {
        let mut b = Request::builder()
            .method(method)
            .uri(format!("{P}{path}"))
            .header("host", "localhost:8001")
            .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 50000))));
        for (k, v) in headers {
            b = b.header(*k, v);
        }
        self.send(b.body(Body::from(body.to_string())).unwrap()).await
    }

    async fn send(&self, req: Request<Body>) -> Resp {
        let resp = self.router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let header = |n: &str| resp.headers().get(n).map(|v| v.to_str().unwrap().to_string());
        let (content_type, location, set_cookie) = (header("content-type"), header("location"), header("set-cookie"));
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        Resp { status, body: String::from_utf8_lossy(&bytes).into_owned(), content_type, location, set_cookie }
    }

    async fn ok(&self, method: &str, path: &str, headers: &[(&str, String)], body: Option<Value>) -> Value {
        let r = self.call(method, path, headers, body).await;
        assert_eq!(r.status, StatusCode::OK, "{method} {path}: {}", r.body);
        if r.body.is_empty() {
            Value::Null
        } else {
            r.json()
        }
    }

    async fn status(&self, method: &str, path: &str, headers: &[(&str, String)], body: Option<Value>) -> StatusCode {
        self.call(method, path, headers, body).await.status
    }

    async fn scalar(&self, sql: &str) -> Option<u64> {
        sqlx::query(sql).fetch_optional(&self.pool).await.unwrap().map(|r| r.try_get::<u64, _>(0).unwrap())
    }

    async fn count(&self, sql: &str) -> i64 {
        sqlx::query_scalar::<_, i64>(sql).fetch_one(&self.pool).await.unwrap()
    }
}

fn keys(v: &Value) -> Vec<String> {
    v.as_object().map(|m| m.keys().cloned().collect()).unwrap_or_default()
}

#[tokio::test]
async fn policy_routes() {
    let Some(l) = live().await else { return };
    // The default PIN policy, as Java writes it, and the stored OTP one.
    let pin = l.ok("GET", "/clientPinPolicy/codes/policy", &anon(), None).await;
    let stored_pin = l.count("SELECT COUNT(*) FROM security_client_pin_policy p JOIN security_app a ON a.ID = p.APP_ID WHERE a.APP_CODE = 'appbuilder' AND p.CLIENT_ID = 1").await;
    if stored_pin == 0 {
        assert_eq!(pin, json!({"id": 0, "noFailedAttempts": 3, "length": 4}));
    }
    let otp = l.ok("GET", "/clientOtpPolicy/codes/policy", &anon(), None).await;
    assert!(keys(&otp).ends_with(&["numeric".to_string(), "alphanumeric".to_string()]), "{otp}");
    assert!(otp.get("userLockTime").is_none() && otp.get("clientId").is_none());
    // Missing headers fail where Java builds its tuple; an unknown app answers nothing.
    let mut no_app = anon();
    no_app.retain(|(k, _)| *k != "appcode");
    assert_eq!(l.status("GET", "/clientPinPolicy/codes/policy", &no_app, None).await, StatusCode::INTERNAL_SERVER_ERROR);
    let mut unknown = anon();
    unknown[1].1 = "nope".into();
    let r = l.call("GET", "/clientPinPolicy/codes/policy", &unknown, None).await;
    assert_eq!((r.status, r.body.as_str()), (StatusCode::OK, ""));

    for base in ["clientOtpPolicy", "clientPasswordPolicy", "clientPinPolicy"] {
        let page = l.ok("GET", &format!("/{base}?size=2"), &sys(), None).await;
        assert_eq!(page["size"], 2);
        assert_eq!(l.ok("POST", &format!("/{base}/query"), &sys(), Some(json!({"size": 1}))).await["size"], 1);
        let r = l.call("GET", &format!("/{base}/999999999"), &sys(), None).await;
        assert_eq!(r.status, StatusCode::NOT_FOUND);
        assert!(r.message().ends_with("with id 999999999 not found"));
        assert_eq!(l.status("GET", &format!("/{base}/x"), &sys(), None).await, StatusCode::BAD_REQUEST);
        let denied = l.call("GET", &format!("/{base}/1"), &plain(), None).await;
        assert_eq!((denied.status, denied.json()["code"].as_str(), denied.content_type.as_deref()), (StatusCode::FORBIDDEN, Some("COMMON.PERMISSION_REQUIRED"), Some("application/json")));
        assert_eq!(l.status("GET", &format!("/{base}"), &anon(), None).await, StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn client_and_activity_routes() {
    let Some(l) = live().await else { return };
    let page = l.ok("GET", "/clients?size=2", &sys(), None).await;
    assert_eq!(keys(&page)[..5], ["content", "pageable", "totalPages", "totalElements", "last"]);
    let one = l.ok("GET", "/clients/1", &sys(), None).await;
    assert_eq!((one["code"].as_str(), one["totalUsers"].as_i64()), (Some("SYSTEM"), Some(0)));
    assert_eq!(l.ok("GET", "/clients/28", &owner(), None).await["code"], "FIN");
    let r = l.call("GET", "/clients/1", &owner(), None).await;
    assert_eq!((r.status, r.message().as_str()), (StatusCode::FORBIDDEN, "Permission/Role Client READ is required to use this operation"));
    assert_eq!(l.call("GET", "/clients/999999999", &sys(), None).await.message(), "Client with id 999999999 not found");
    assert_eq!(l.status("GET", "/clients/28", &plain(), None).await, StatusCode::FORBIDDEN);
    let r = l.call("POST", "/clients/noMapping", &sys(), Some(json!({}))).await;
    assert_eq!((r.status, r.body.as_str()), (StatusCode::BAD_REQUEST, ""));
    assert_eq!(l.status("GET", "/clients/makeClientActive?clientId=x", &sys(), None).await, StatusCode::BAD_REQUEST);
    // Activation of a client the caller does not manage is refused before anything changes.
    let r = l.call("GET", "/clients/makeClientInActive?clientId=1", &owner(), None).await;
    assert_eq!((r.status, r.message().as_str()), (StatusCode::FORBIDDEN, "selected client doesn't have access to change status code"));
    let filled = l.ok("POST", "/clients/query?fetchUserCounts=true", &owner(), Some(json!({"size": 5}))).await;
    for c in filled["content"].as_array().unwrap() {
        assert!(c.get("totalUsers").is_some());
    }

    // Client activities.
    let acts = l.ok("GET", "/client-activities/28?size=2", &owner(), None).await;
    assert!(acts["size"] == 2);
    let r = l.call("GET", "/client-activities/1?size=2", &owner(), None).await;
    assert_eq!((r.status, r.message().as_str()), (StatusCode::FORBIDDEN, "Permission/Role Client Activity is required to use this operation"));
    let r = l.call("POST", "/client-activities", &sys(), Some(json!({"activityName": "  "}))).await;
    assert_eq!((r.status, r.message().as_str()), (StatusCode::BAD_REQUEST, "Activity name is required"));
    let q = l.ok("POST", "/client-activities/1/query", &sys(), Some(json!({"size": 1, "sort": [{"property": "id", "direction": "DESC"}]}))).await;
    if let Some(first) = q["content"].as_array().and_then(|c| c.first()) {
        if first.get("createdBy").is_some() {
            assert!(first.get("createdByUser").is_some());
        }
    }
}

#[tokio::test]
async fn app_url_registration_and_ssl_reads() {
    let Some(l) = live().await else { return };
    let app = l.ok("GET", "/applications/2", &sys(), None).await;
    assert_eq!(app["appCode"], "appbuilder");
    assert_eq!(l.ok("GET", "/applications/appCode/appbuilder", &owner(), None).await["id"], 2);
    let r = l.call("GET", "/applications/clients/appbuilder", &sys(), None).await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR, "Java unboxes the missing onlyWriteAccess");
    let access = l.ok("GET", "/applications/clientHasReadAccess?appCodes=appbuilder,nope", &owner(), None).await;
    assert_eq!(access["nope"], false);
    let r = l.call("GET", "/applications/findAnyApps", &sys(), None).await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR, "Page.empty() cannot be written");
    let r = l.call("GET", "/applications/property", &sys(), None).await;
    assert_eq!((r.status, r.message().as_str()), (StatusCode::BAD_REQUEST, "One of App ID or App Code is mandatory"));
    let r = l.call("GET", "/applications/applyAppCodePrefix?appCode=abc", &anon(), None).await;
    assert_eq!((r.status, r.body.as_str()), (StatusCode::OK, "local.abc"));
    assert_eq!(l.call("GET", "/applications/applyAppCodeSuffix?appCode=abc", &anon(), None).await.body, "abc.local");

    let urls = l.ok("GET", "/clienturls/urls?appCode=leadzump&size=2", &sys(), None).await;
    if let Some(first) = urls["content"].as_array().and_then(|c| c.first()) {
        assert!(first.get("clientCode").is_some());
    }
    let r = l.call("GET", "/clienturls/urls?appCode=appbuilder&clientCode=NOPE", &sys(), None).await;
    assert_eq!((r.status, r.message().as_str()), (StatusCode::FORBIDDEN, "User don't have write access to the application."));
    assert_eq!(l.status("GET", "/clienturls/fetchUrls?appCode=", &sys(), None).await, StatusCode::BAD_REQUEST);
    assert_eq!(l.call("GET", "/clienturls/draft?appCode=nope", &sys(), None).await.status, StatusCode::NOT_FOUND);
    assert_eq!(l.status("POST", "/clienturls/draft/token/extend?token=nope", &sys(), None).await, StatusCode::FORBIDDEN);

    assert_eq!(l.status("POST", "/applications/reg/cxapp/nope/query", &sys(), Some(json!({"page": 0, "size": 1}))).await, StatusCode::BAD_REQUEST);
    assert_eq!(l.status("POST", "/applications/reg/cxapp/appAccess/query", &sys(), Some(json!({"size": 1}))).await, StatusCode::INTERNAL_SERVER_ERROR);
    let reg = l.ok("POST", "/applications/reg/cxapp/appAccess/query", &sys(), Some(json!({"page": 0, "size": 2}))).await;
    if let Some(first) = reg["content"].as_array().and_then(|c| c.first()) {
        assert!(first.get("app").is_some() && first.get("client").is_some() && first.get("allowApp").is_some());
    }

    let url: Option<u64> = l.scalar("SELECT URL_ID FROM security_ssl_certificate WHERE CURRENT = 1 ORDER BY ID DESC LIMIT 1").await;
    if let Some(url) = url {
        let certs = l.ok("GET", &format!("/ssl?urlId={url}&size=1"), &sys(), None).await;
        let c = &certs["content"][0];
        assert!(c.get("crtKey").is_none() && c.get("crt").is_some());
        let r = l.call("POST", "/ssl", &sys(), Some(json!({"domainNames": ["x.com"], "urlId": url}))).await;
        assert_eq!(r.status, StatusCode::CONFLICT);
    }
    assert_eq!(l.status("GET", "/ssl", &sys(), None).await, StatusCode::NOT_FOUND);
    assert_eq!(l.status("DELETE", "/ssl/x", &sys(), None).await, StatusCode::INTERNAL_SERVER_ERROR);
    let r = l.call("POST", "/ssl/external", &sys(), Some(json!({"urlId": 1}))).await;
    assert_eq!(r.message(), "Certificate or Key Issue : Key is missing");
    assert_eq!(l.call("GET", "/ssl/token/nope", &anon(), None).await.body, "");
    let r = l.call("POST", "/ssl/internal/renew-certificates", &plain(), None).await;
    assert_eq!((r.status, r.message().as_str()), (StatusCode::INTERNAL_SERVER_ERROR, "Only System users can access the certificates"));
    // This unit has no certificate authority: every expiring certificate fails, nothing changes.
    let before = l.count("SELECT COUNT(*) FROM security_ssl_request").await;
    let renewed = l.ok("POST", "/ssl/internal/renew-certificates", &anon(), None).await;
    assert_eq!(renewed["renewedCount"], 0);
    assert_eq!(l.count("SELECT COUNT(*) FROM security_ssl_request").await, before);

    let r = l.call("GET", "/clients/socialRegister/callback", &anon(), None).await;
    assert_eq!((r.status, r.json()["debugMessage"].as_str()), (StatusCode::INTERNAL_SERVER_ERROR, Some("Invalid state")));
    assert_eq!(l.status("GET", "/clients/socialRegister/evoke?platform=NOPE", &anon(), None).await, StatusCode::BAD_REQUEST);
    let mut unknown_app = anon();
    unknown_app[1].1 = "nope".into();
    let r = l.call("POST", "/clients/register/otp/generate", &unknown_app, Some(json!({"emailId": "zz@example.test"}))).await;
    assert_eq!(r.message(), "Client Registration Error : Feature not supported");
    assert_eq!(l.ok("GET", "/transports/makeTransport?applicationCode=x", &sys(), None).await, Value::Null);
}

/// A scratch app through its whole life, as `AppLifecycleIntegrationTest` does it.
#[tokio::test]
async fn scratch_app_lifecycle() {
    let Some(l) = live().await else { return };
    // Leftovers of a run that stopped half-way.
    for code in sqlx::query_scalar::<_, String>("SELECT APP_CODE FROM security_app WHERE APP_CODE LIKE 'zzrustlive%'").fetch_all(&l.pool).await.unwrap() {
        remove_app(&l, &code).await;
    }
    let suffix: String = security::admin::clients::apps::unique_letters("").chars().take(8).collect();
    let code = format!("zzrustlive{suffix}");
    let r = l.call("POST", "/applications", &sys(), Some(json!({"appCode": "a-1"}))).await;
    assert_eq!((r.status, r.message().as_str()), (StatusCode::BAD_REQUEST, "App Code should not contain any special characters"));
    let app = l.ok("POST", "/applications", &sys(), Some(json!({"appName": "ZZ Rust Live", "appCode": code, "appUsageType": "B2C", "appType": "APP"}))).await;
    let id = app["id"].as_u64().unwrap();
    assert_eq!((app["appAccessType"].as_str(), app["status"].as_str(), app["clientId"].as_u64()), (Some("OWN"), Some("ACTIVE"), Some(1)));
    // Every app is given its draft hostname.
    let draft = l.ok("GET", &format!("/clienturls/draft?appCode={code}"), &sys(), None).await;
    assert!(draft["urlPattern"].as_str().unwrap().ends_with(".local.modlix.com") && draft["urlType"] == "DRAFT");
    let rotated = l.ok("POST", &format!("/clienturls/draft?appCode={code}"), &sys(), None).await;
    assert_eq!(rotated["id"], draft["id"]);
    assert_ne!(rotated["urlPattern"], draft["urlPattern"]);

    let put = l.ok("PUT", &format!("/applications/{id}"), &sys(), Some(json!({"appName": "ZZ 2", "appAccessType": "ANY", "appUsageType": "B2B", "status": "ACTIVE", "appCode": "ignored"}))).await;
    assert_eq!((put["appName"].as_str(), put["appCode"].as_str()), (Some("ZZ 2"), Some(code.as_str())));
    let patched = l.ok("PATCH", &format!("/applications/{id}"), &sys(), Some(json!({"thumbUrl": "t.png"}))).await;
    assert_eq!(patched["thumbUrl"], "t.png");
    let r = l.call("PATCH", &format!("/applications/{id}"), &sys(), Some(json!({"appType": "NOPE"}))).await;
    assert_eq!(r.message(), "appType field cannot be updated, it might not be available or unmodifiable");

    // Properties.
    assert_eq!(l.ok("POST", "/applications/property", &sys(), Some(json!({"appId": id, "clientId": 1, "name": "ZZP", "value": "v"}))).await, json!(true));
    let props = l.ok("GET", &format!("/applications/property?appCode={code}"), &sys(), None).await;
    assert_eq!(props["properties"]["1"]["ZZP"]["value"], "v");
    assert_eq!(props["clients"]["1"]["code"], "SYSTEM");
    assert_eq!(l.ok("DELETE", &format!("/applications/property?clientId=1&appId={id}&name=ZZP"), &sys(), None).await, json!(true));
    assert_eq!(l.ok("GET", &format!("/applications/property?appCode={code}"), &sys(), None).await, json!({}));

    // Access for FIN: added, upgraded, removed; each change raises APP_ACCESS_CHANGED (logged).
    assert_eq!(l.ok("POST", &format!("/applications/{id}/access"), &sys(), Some(json!({"clientId": 28, "writeAccess": false}))).await, json!(true));
    let access = l.scalar(&format!("SELECT ID FROM security_app_access WHERE APP_ID = {id} AND CLIENT_ID = 28")).await.unwrap();
    assert_eq!(l.ok("PATCH", &format!("/applications/{id}/access"), &sys(), Some(json!({"id": access, "writeAccess": true}))).await, json!(true));
    // MySQL reports the matched row, so an unchanged flag still answers true.
    assert_eq!(l.ok("PATCH", &format!("/applications/{id}/access"), &sys(), Some(json!({"id": access, "writeAccess": true}))).await, json!(true));
    let clients = l.ok("GET", &format!("/applications/clients/{code}?onlyWriteAccess=true"), &sys(), None).await;
    assert_eq!(clients["totalElements"], 2);
    assert_eq!(l.ok("GET", &format!("/applications/hasDeleteAccess?deleteAppCode={code}&deleteClientCode=SYSTEM"), &sys(), None).await, json!(false));
    assert_eq!(l.ok("DELETE", &format!("/applications/{id}/access?accessId={access}"), &sys(), None).await, json!(true));
    assert_eq!(l.ok("DELETE", &format!("/applications/{id}/access?accessId={access}"), &sys(), None).await, json!(false));
    let r = l.call("PATCH", &format!("/applications/{id}/access"), &sys(), Some(json!({"id": 999999999, "writeAccess": true}))).await;
    assert_eq!(r.message(), "Application access with id 999999999 not found to update");

    // Dependencies.
    let dep = l.ok("POST", "/applications/dependency", &sys(), Some(json!({"appCode": code, "dependentAppCode": "appbuilder"}))).await;
    assert_eq!((dep["appId"].as_u64(), dep["dependentAppId"].as_u64()), (Some(id), Some(2)));
    let deps = l.ok("GET", &format!("/applications/dependencies?appCode={code}"), &anon(), None).await;
    assert_eq!(deps[0]["dependentAppCode"], "appbuilder");
    let r = l.call("POST", "/applications/dependency", &sys(), Some(json!({"appCode": code, "dependentAppCode": code}))).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(l.ok("DELETE", &format!("/applications/dependency?appCode={code}&dependencyCode=appbuilder"), &sys(), None).await, json!(true));

    // A PIN policy for the app.
    let p = l.ok("POST", "/clientPinPolicy", &sys(), Some(json!({"appId": id, "clientId": 1, "length": 6}))).await;
    let pid = p["id"].as_u64().unwrap();
    assert_eq!((p["length"].as_i64(), p["noFailedAttempts"].as_i64()), (Some(6), Some(3)));
    let r = l.call("POST", "/clientPinPolicy", &sys(), Some(json!({"appId": id, "clientId": 1}))).await;
    assert_eq!((r.status, r.message().as_str()), (StatusCode::FORBIDDEN, "Cannot create client_pin_policy for the selected client"));
    assert_eq!(l.ok("PUT", &format!("/clientPinPolicy/{pid}"), &sys(), Some(json!({"noFailedAttempts": 5}))).await["length"], 4);
    assert_eq!(l.ok("PATCH", &format!("/clientPinPolicy/{pid}"), &sys(), Some(json!({"length": 8}))).await["length"], 8);
    assert_eq!(l.status("DELETE", &format!("/clientPinPolicy/{pid}"), &sys(), None).await, StatusCode::NO_CONTENT);

    // A client URL: trimmed, readable, refused on another app's platform hostname.
    let host = format!("{code}.example.test");
    let u = l.ok("POST", "/clienturls", &sys(), Some(json!({"appCode": code, "urlPattern": format!("https://{host}///")}))).await;
    assert_eq!(u["urlPattern"], format!("https://{host}"));
    let uid = u["id"].as_u64().unwrap();
    assert_eq!(l.ok("GET", &format!("/clienturls/{uid}"), &sys(), None).await["urlType"], "LIVE");
    let r = l.call("POST", "/clienturls", &sys(), Some(json!({"appCode": code, "urlPattern": "appbuilder.local.modlix.com"}))).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert!(r.message().starts_with("appbuilder.local.modlix.com is the platform hostname of the application appbuilder"));
    let r = l.call("GET", &format!("/clienturls/{uid}"), &owner(), None).await;
    assert_eq!(r.message(), format!("Client URL with id {uid} not found"));
    let urls = l.ok("GET", &format!("/clienturls/fetchUrls?appCode={code}&suffix=/x"), &sys(), None).await;
    assert_eq!(urls, json!([format!("https://{host}"), format!("https://{code}.local/x/")]));
    // No certificate authority here: a request answers the credentials error and writes nothing.
    let r = l.call("POST", "/ssl", &sys(), Some(json!({"domainNames": [host], "urlId": uid}))).await;
    assert_eq!(r.message(), "Lets encrypt credentials are not configured properly, it requires login, session and key.");
    assert_eq!(l.count(&format!("SELECT COUNT(*) FROM security_ssl_request WHERE URL_ID = {uid}")).await, 0);
    assert_eq!(l.ok("GET", &format!("/ssl/request?urlId={uid}"), &sys(), None).await, Value::Null);
    assert_eq!(l.status("DELETE", &format!("/clienturls/{uid}"), &sys(), None).await, StatusCode::NO_CONTENT);

    // Draft-edit grants: the same grant again, then pushed forward.
    let t1 = l.ok("POST", &format!("/clienturls/draft/token?appCode={code}"), &sys(), None).await;
    let t2 = l.ok("POST", &format!("/clienturls/draft/token?appCode={code}"), &sys(), None).await;
    assert_eq!(t1["token"], t2["token"]);
    assert_eq!(t1["host"], format!("t-{}.local.modlix.com", t1["token"].as_str().unwrap()));
    let ext = l.ok("POST", &format!("/clienturls/draft/token/extend?token={}", t1["token"].as_str().unwrap()), &sys(), None).await;
    assert_eq!(ext["token"], t1["token"]);
    assert_eq!(l.status("POST", &format!("/clienturls/draft/token/extend?token={}", t1["token"].as_str().unwrap()), &owner(), None).await, StatusCode::FORBIDDEN);

    // A registration object.
    let fa = l
        .ok("POST", &format!("/applications/reg/{code}/fileAccess"), &sys(), Some(json!({"clientType": "BUS", "level": "CLIENT", "resourceType": "STATIC", "accessName": "zz", "path": "/zz"})))
        .await;
    assert_eq!((fa["app"]["appCode"].as_str(), fa["client"]["code"].as_str()), (Some(code.as_str()), Some("SYSTEM")));
    let q = l.ok("POST", &format!("/applications/reg/{code}/fileAccess/query"), &sys(), Some(json!({"page": 0, "size": 5}))).await;
    assert_eq!(q["totalElements"], 1);
    assert_eq!(l.ok("DELETE", &format!("/applications/reg/fileAccess/{}", fa["id"]), &sys(), None).await, json!(true));

    // An integration, evoked for a consent URL, then removed with its states.
    let intg = l
        .ok("POST", "/appRegIntegration", &sys(), Some(json!({"appId": id, "clientId": 1, "platform": "GOOGLE", "intgId": "cid", "intgSecret": "zz", "loginUri": "l", "signupUri": "s"})))
        .await;
    let iid = intg["id"].as_u64().unwrap();
    let mut on_app = anon();
    on_app[1].1 = code.clone();
    on_app.push(("x-forwarded-host", "zz.example.test:443".into()));
    let url = l.call("POST", "/clients/socialRegister/evoke?platform=GOOGLE&appCode=x", &on_app, None).await;
    assert!(url.body.starts_with("https://accounts.google.com/o/oauth2/v2/auth?client_id=cid&redirect_uri=https://zz.example.test/api/security/clients/socialRegister/callback"), "{}", url.body);
    let redirect = l.call("GET", "/clients/socialRegister/evoke?platform=GOOGLE", &on_app, None).await;
    assert_eq!(redirect.status, StatusCode::FOUND);
    assert!(redirect.location.unwrap().contains("state="));
    assert_eq!(l.count(&format!("SELECT COUNT(*) FROM security_app_reg_integration_tokens WHERE INTEGRATION_ID = {iid}")).await, 2);
    // The consent screen cancelled: back to the app, with the error and the recorded parameters.
    let state: String = sqlx::query_scalar(&format!("SELECT STATE FROM security_app_reg_integration_tokens WHERE INTEGRATION_ID = {iid} AND REQUEST_PARAM LIKE '%appCode%'"))
        .fetch_one(&l.pool)
        .await
        .unwrap();
    let cancelled = l.call("GET", &format!("/clients/socialRegister/callback?state={state}"), &anon(), None).await;
    assert_eq!(cancelled.status, StatusCode::BAD_REQUEST, "the recorded appCode has no address: {}", cancelled.body);
    assert_eq!(l.status("DELETE", &format!("/appRegIntegration/{iid}"), &sys(), None).await, StatusCode::NO_CONTENT);
    assert_eq!(l.count(&format!("SELECT COUNT(*) FROM security_app_reg_integration_tokens WHERE INTEGRATION_ID = {iid}")).await, 0);

    // Archived, then deleted with its draft URL.
    assert_eq!(l.status("DELETE", &format!("/applications/{id}"), &sys(), None).await, StatusCode::NO_CONTENT);
    assert_eq!(l.ok("GET", &format!("/applications/{id}"), &sys(), None).await["status"], "ARCHIVED");
    assert_eq!(l.status("DELETE", &format!("/applications/{id}"), &sys(), None).await, StatusCode::NO_CONTENT);
    assert_eq!(l.call("GET", &format!("/applications/{id}"), &sys(), None).await.message(), format!("App with id {id} not found"));
    assert_eq!(l.count(&format!("SELECT COUNT(*) FROM security_client_url WHERE APP_CODE = '{code}'")).await, 0);
}

async fn remove_app(l: &Live, code: &str) {
    let Some(id) = l.scalar(&format!("SELECT ID FROM security_app WHERE APP_CODE = '{code}'")).await else { return };
    for (table, base) in [("security_client_pin_policy", "clientPinPolicy"), ("security_client_otp_policy", "clientOtpPolicy"), ("security_client_password_policy", "clientPasswordPolicy")] {
        for pid in sqlx::query_scalar::<_, u64>(&format!("SELECT ID FROM {table} WHERE APP_ID = {id}")).fetch_all(&l.pool).await.unwrap() {
            l.call("DELETE", &format!("/{base}/{pid}"), &sys(), None).await;
        }
    }
    for iid in sqlx::query_scalar::<_, u64>(&format!("SELECT ID FROM security_app_reg_integration WHERE APP_ID = {id}")).fetch_all(&l.pool).await.unwrap() {
        l.call("DELETE", &format!("/appRegIntegration/{iid}"), &sys(), None).await;
    }
    for rid in sqlx::query_scalar::<_, u64>(&format!("SELECT ID FROM security_app_reg_file_access WHERE APP_ID = {id}")).fetch_all(&l.pool).await.unwrap() {
        l.call("DELETE", &format!("/applications/reg/fileAccess/{rid}"), &sys(), None).await;
    }
    l.call("DELETE", &format!("/applications/everything/{id}?forceDelete=true"), &sys(), None).await;
}

/// Updates of the parity script's scratch client `ZZPRUS` (made once by
/// `tools/parity_security_admin_clients.py`; skipped when it is not there), as
/// `ClientLifecycleIntegrationTest` does them. It ends DELETED, as it started.
#[tokio::test]
async fn scratch_client_lifecycle() {
    let Some(l) = live().await else { return };
    let Some(id) = l.scalar("SELECT ID FROM security_client WHERE CODE = 'ZZPRUS'").await else {
        eprintln!("skipped: no ZZPRUS scratch client");
        return;
    };
    // A second client with the same code: the insert itself is refused.
    let r = l.call("POST", "/clients", &sys(), Some(json!({"code": "ZZPRUS", "name": "ZZ", "typeCode": "BUS", "businessType": "COMMON", "timeZone": "Asia/Kolkata"}))).await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
    // A parent the caller does not manage, and no authority to create at all.
    let r = l.call("POST", "/clients", &owner(), Some(json!({"name": "ZZ", "parentClientId": 1}))).await;
    assert_eq!((r.status, r.message().as_str()), (StatusCode::FORBIDDEN, "Cannot create Client under the selected parent for the selected client"));
    assert_eq!(l.status("POST", "/clients", &plain(), Some(json!({"name": "ZZ"}))).await, StatusCode::FORBIDDEN);

    let revived = l
        .ok("PUT", &format!("/clients/{id}"), &sys(), Some(json!({"code": "ZZPRUS", "name": "ZZ Parity", "typeCode": "INDV", "levelType": "SYSTEM", "businessType": "COMMON", "timeZone": "Asia/Kolkata", "tokenValidityMinutes": 30, "statusCode": "ACTIVE", "website": "  zz.example.test "})))
        .await;
    assert_eq!((revived["statusCode"].as_str(), revived["levelType"].as_str(), revived["typeCode"].as_str()), (Some("ACTIVE"), Some("CLIENT"), Some("BUS")), "level and type stay as stored");
    assert_eq!(revived["website"], "zz.example.test");
    let patched = l.ok("PATCH", &format!("/clients/{id}"), &sys(), Some(json!({"description": "  zz ", "tokenValidityMinutes": null, "id": 1}))).await;
    assert_eq!((patched["description"].as_str(), patched["tokenValidityMinutes"].as_i64(), patched["id"].as_u64()), (Some("zz"), Some(0), Some(id)));
    let r = l.call("PATCH", &format!("/clients/{id}"), &sys(), Some(json!({"statusCode": "NOPE"}))).await;
    assert_eq!(r.message(), "statusCode field cannot be updated, it might not be available or unmodifiable");
    assert_eq!(l.ok("GET", &format!("/clients/makeClientInActive?clientId={id}"), &sys(), None).await, json!(true));
    assert_eq!(l.ok("GET", &format!("/clients/makeClientActive?clientId={id}"), &sys(), None).await, json!(true));
    assert_eq!(l.ok("GET", &format!("/clients/makeClientActive?clientId={id}"), &sys(), None).await, json!(false));
    // Not FIN's client: the owner of FIN may neither read nor change it.
    assert_eq!(l.status("GET", &format!("/clients/{id}"), &owner(), None).await, StatusCode::FORBIDDEN);
    assert_eq!(l.status("PUT", &format!("/clients/{id}"), &owner(), Some(json!({"name": "x"}))).await, StatusCode::FORBIDDEN);
    assert_eq!(l.status("DELETE", &format!("/clients/{id}"), &owner(), None).await, StatusCode::FORBIDDEN);
    assert_eq!(l.status("DELETE", &format!("/clients/{id}"), &sys(), None).await, StatusCode::NO_CONTENT);
    assert_eq!(l.ok("GET", &format!("/clients/{id}"), &sys(), None).await["statusCode"], "DELETED");
    // Two sox rows per patch (update inside update), as Java writes them.
    let logs = l.count(&format!("SELECT COUNT(*) FROM security_sox_log WHERE OBJECT_NAME = 'CLIENT' AND OBJECT_ID = {id} AND ACTION_NAME = 'UPDATE'")).await;
    assert!(logs >= 4, "{logs}");
}

/// Registration end to end on a scratch app (`zzrustreg...`, B2X, owned by SYSTEM, registration
/// without verification), as `ClientRegistrationServiceTest` and the registration integration
/// tests do it: the refusals first, then an individual and a business client with their owners
/// signed in, the business one with its subdomain. The files service is an in-process fake that
/// records the access paths. The two clients and users are marked DELETED through the routes
/// and the app removed with what it holds (access rows, URLs, properties).
#[tokio::test]
async fn scratch_registration() {
    use std::sync::{Arc, Mutex};
    let seen: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let recorded = seen.clone();
    let fake = Router::new().route(
        "/api/files/internal/accesspath",
        axum::routing::post(move |axum::Json(v): axum::Json<Value>| {
            let recorded = recorded.clone();
            async move {
                recorded.lock().unwrap().push(v.clone());
                axum::Json(v)
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let files = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, fake).await.unwrap() });
    let Some(l) = live_with(Some(&files)).await else { return };

    // Leftovers of a run that stopped half-way: its scratch users and clients, then its app.
    let left: Vec<(u64, u64)> = sqlx::query_as(
        "SELECT u.ID, u.CLIENT_ID FROM security_user u JOIN security_client c ON c.ID = u.CLIENT_ID \
         WHERE u.EMAIL_ID LIKE 'zz.reg%@example.com' AND (u.STATUS_CODE <> 'DELETED' OR c.STATUS_CODE <> 'DELETED')",
    )
    .fetch_all(&l.pool)
    .await
    .unwrap();
    for (u, c) in left {
        l.call("DELETE", &format!("/users/{u}"), &sys(), None).await;
        l.call("DELETE", &format!("/clients/{c}"), &sys(), None).await;
    }
    for code in sqlx::query_scalar::<_, String>("SELECT APP_CODE FROM security_app WHERE APP_CODE LIKE 'zzrustreg%'").fetch_all(&l.pool).await.unwrap() {
        remove_app(&l, &code).await;
    }
    let suffix: String = security::admin::clients::apps::unique_letters("").chars().take(8).collect::<String>().to_lowercase();
    let code = format!("zzrustreg{suffix}");
    let app = l.ok("POST", "/applications", &sys(), Some(json!({"appName": "ZZ Rust Reg", "appCode": code, "appUsageType": "B2X", "appType": "APP"}))).await;
    let app_id = app["id"].as_u64().unwrap();
    let on_app = vec![("clientcode", "SYSTEM".to_string()), ("appcode", code.clone()), ("x-forwarded-host", "zz.example.test".to_string()), ("x-forwarded-proto", "https".to_string())];
    let mut signed_in = sys();
    signed_in[2].1 = code.clone();
    let email = format!("zz.reg.{suffix}@example.com");
    let good = "Zz!RegPass12345";
    let indv = json!({"passType": "PASSWORD", "password": good, "emailId": email, "firstName": "ZZ", "lastName": "Reg", "timeZone": "Nowhere/Else"});

    // Refusals, none of which writes anything.
    let r = l.call("POST", "/clients/register", &on_app, Some(json!({}))).await;
    assert_eq!((r.status, r.message().as_str()), (StatusCode::BAD_REQUEST, "Client Registration Error : Type of password for app is required"));
    let r = l.call_untyped("POST", "/clients/register", &on_app, "{}").await;
    assert_eq!(r.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert!(r.json()["debugMessage"].as_str().unwrap().contains("Content type 'application/octet-stream' not supported for bodyType=com.fincity.security.model.ClientRegistrationRequest"));
    let r = l.call("POST", "/clients/register", &on_app, Some(indv.clone())).await;
    assert_eq!((r.status, r.message().as_str()), (StatusCode::BAD_REQUEST, "No registration available for the selected client on this application."));
    assert_eq!(l.ok("POST", "/applications/property", &sys(), Some(json!({"appId": app_id, "clientId": 1, "name": "REGISTRATION_TYPE", "value": "REGISTRATION_TYPE_NO_VERIFICATION"}))).await, json!(true));
    let fa = l
        .ok("POST", &format!("/applications/reg/{code}/fileAccess"), &sys(), Some(json!({"clientType": "INDV", "level": "CLIENT", "resourceType": "STATIC", "accessName": "zzreg", "path": "/zzreg", "writeAccess": true})))
        .await;
    assert!(fa["id"].as_u64().is_some());
    let r = l.call("POST", "/clients/register", &on_app, Some(json!({"passType": "PASSWORD", "password": "weak", "emailId": email}))).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", r.body);
    let biz = |extra: Value| {
        let mut b = json!({"passType": "PASSWORD", "password": good, "emailId": format!("zz.regb.{suffix}@example.com"), "clientName": "ZZ Reg Biz", "businessClient": true});
        b.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        b
    };
    let r = l.call("POST", "/clients/register", &on_app, Some(biz(json!({"subDomain": "zzx", "subDomainSuffix": ".nope.com"})))).await;
    assert_eq!((r.status, r.message().as_str()), (StatusCode::FORBIDDEN, ".nope.com is not a legal subdomain suffix"));
    let r = l.call("POST", "/clients/register", &on_app, Some(biz(json!({"subDomain": code})))).await;
    assert_eq!((r.status, r.message().as_str()), (StatusCode::CONFLICT, "Subdomain already exists"));
    let r = l.call("POST", "/clients/register/otp/verify", &signed_in, Some(indv.clone())).await;
    assert_eq!(r.message(), "Client Registration Error : Logout to register");
    let r = l.call("POST", "/clients/register/otp/verify", &on_app, Some(json!({}))).await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(l.ok("POST", "/clients/register/otp/verify", &on_app, Some(indv.clone())).await, json!(true));
    let r = l.call("POST", "/clients/socialRegister", &on_app, Some(json!({}))).await;
    assert_eq!(r.message(), "Client Registration Error : Social register state cannot be blank for social Login.");
    let r = l.call("POST", "/clients/socialRegister", &on_app, Some(json!({"socialRegisterState": "zz-no-such-state"}))).await;
    assert_eq!((r.status, r.json()["debugMessage"].as_str()), (StatusCode::INTERNAL_SERVER_ERROR, Some("Invalid state")));
    assert_eq!(l.count(&format!("SELECT COUNT(*) FROM security_user WHERE EMAIL_ID = '{email}'")).await, 0);
    assert!(seen.lock().unwrap().is_empty());

    // An individual client: its owner signed in, with a cookie session too.
    let r = l.call("POST", "/clients/register", &on_app, Some(indv.clone())).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let done = r.json();
    let uid = done["userId"].as_u64().unwrap();
    assert_eq!(done["created"], true);
    assert!(done.get("redirectURL").is_none());
    assert_eq!(done["authentication"]["user"]["id"].as_u64(), Some(uid));
    assert!(!done["authentication"]["accessToken"].as_str().unwrap_or("").is_empty());
    assert!(r.set_cookie.as_deref().unwrap_or("").starts_with("Authorization="), "{:?}", r.set_cookie);
    let cid = l.scalar(&format!("SELECT CLIENT_ID FROM security_user WHERE ID = {uid}")).await.unwrap();
    let row = sqlx::query(&format!("SELECT CODE, TYPE_CODE, LEVEL_TYPE, CREATED_BY, TOKEN_VALIDITY_MINUTES, TIME_ZONE, BUSINESS_TYPE FROM security_client WHERE ID = {cid}"))
        .fetch_one(&l.pool)
        .await
        .unwrap();
    let ccode: String = row.try_get("CODE").unwrap();
    assert!(ccode.starts_with("ZZREG"), "{ccode}");
    assert_eq!(row.try_get::<String, _>("TYPE_CODE").unwrap(), "INDV");
    assert_eq!(row.try_get::<String, _>("LEVEL_TYPE").unwrap(), "CLIENT");
    assert_eq!(row.try_get::<Option<u64>, _>("CREATED_BY").unwrap(), Some(0), "an anonymous sign-up is created by user 0");
    assert_eq!(row.try_get::<u32, _>("TOKEN_VALIDITY_MINUTES").unwrap(), 30);
    assert_eq!(row.try_get::<String, _>("TIME_ZONE").unwrap(), "Asia/Kolkata", "an unreadable zone falls back");
    assert_eq!(l.scalar(&format!("SELECT MANAGE_CLIENT_LEVEL_0 FROM security_client_hierarchy WHERE CLIENT_ID = {cid}")).await, Some(1));
    assert_eq!(l.count(&format!("SELECT COUNT(*) FROM security_app_access WHERE APP_ID = {app_id} AND CLIENT_ID = {cid} AND EDIT_ACCESS = 0")).await, 1);
    {
        // Once for the app, once more as one of the apps it also registers on.
        let paths = seen.lock().unwrap().clone();
        assert_eq!(paths.len(), 2, "{paths:?}");
        assert_eq!(paths[0], json!({"clientCode": ccode, "accessName": "zzreg", "writeAccess": true, "path": "/zzreg", "allowSubPathAccess": false, "resourceType": "STATIC"}));
    }
    let r = l.call("POST", "/clients/register", &on_app, Some(indv.clone())).await;
    assert_eq!((r.status, r.message()), (StatusCode::CONFLICT, format!("User {email} already exists. Please try to login / reset your password.")));

    // The events again: nothing to sign in with for OTP; no type at all is Java's NPE.
    let r = l.call("GET", "/clients/register/events", &on_app, Some(json!({"userId": uid, "passType": "OTP"}))).await;
    assert_eq!((r.status, r.body.as_str()), (StatusCode::OK, ""));
    assert_eq!(l.status("GET", "/clients/register/events", &on_app, Some(json!({"userId": uid}))).await, StatusCode::INTERNAL_SERVER_ERROR);
    let r = l.call("GET", "/clients/register/events", &on_app, Some(json!({}))).await;
    assert_eq!((r.status, r.message().as_str()), (StatusCode::NOT_FOUND, "User with id null not found"));

    // Registering the client on the app again needs an owner, and a signed-in caller.
    let r = l.call("POST", &format!("/clients/appRegister?appCode={code}&clientId={cid}&userId={uid}"), &sys(), None).await;
    assert_eq!((r.status, r.message().as_str()), (StatusCode::CONFLICT, "No registration available for the selected client on this application."));
    assert_eq!(l.status("POST", &format!("/clients/appRegister?appCode={code}&clientId={cid}&userId={uid}"), &on_app, None).await, StatusCode::UNAUTHORIZED);
    let r = l.call("POST", "/clients/appRegister?appCode=x", &sys(), None).await;
    assert_eq!(r.json()["debugMessage"], "400 BAD_REQUEST \"Required query parameter 'clientId' is not present.\"");

    // A business client with its subdomain: the URL is made, and the answer points there.
    let sub = format!("zzrsub{suffix}");
    let r = l.call("POST", "/clients/register", &on_app, Some(biz(json!({"subDomain": sub})))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let bdone = r.json();
    let buid = bdone["userId"].as_u64().unwrap();
    assert_eq!(bdone["redirectURL"], format!("{sub}.local.modlix.com"));
    let bcid = l.scalar(&format!("SELECT CLIENT_ID FROM security_user WHERE ID = {buid}")).await.unwrap();
    assert_eq!(l.count(&format!("SELECT COUNT(*) FROM security_client_url WHERE CLIENT_ID = {bcid} AND APP_CODE = '{code}' AND URL_PATTERN = '{sub}.local.modlix.com' AND CREATED_BY = 0")).await, 1);
    let btype: (String, String) = sqlx::query_as(&format!("SELECT TYPE_CODE, BUSINESS_TYPE FROM security_client WHERE ID = {bcid}")).fetch_one(&l.pool).await.unwrap();
    assert_eq!(btype, ("BUS".to_string(), "COMMON".to_string()));
    assert_eq!(seen.lock().unwrap().len(), 2, "no file access for a business client on this app");

    // Removed: the users and clients marked DELETED, the app with its access rows and URLs.
    for u in [uid, buid] {
        assert_eq!(l.status("DELETE", &format!("/users/{u}"), &sys(), None).await, StatusCode::NO_CONTENT);
    }
    for c in [cid, bcid] {
        assert_eq!(l.status("DELETE", &format!("/clients/{c}"), &sys(), None).await, StatusCode::NO_CONTENT);
    }
    remove_app(&l, &code).await;
    assert_eq!(l.scalar(&format!("SELECT ID FROM security_app WHERE APP_CODE = '{code}'")).await, None);
    assert_eq!(l.count(&format!("SELECT COUNT(*) FROM security_client_url WHERE APP_CODE = '{code}'")).await, 0);
}

/// The parity script's read and refusal cases (`tools/parity_security_admin_clients.py`), each
/// with the status Java answers it (the parity runs found Rust's the same), against the local
/// data: `(method, path, user, clientCode, appCode, other headers, body, status)`. Ids that vary
/// with the data are placeholders read here as the script reads them. Writes nothing (the
/// refusals stop before any write); the renewal sweep is only sent as a non-SYSTEM caller.
#[rustfmt::skip]
const SWEEP: &[(&str, &str, Option<u64>, Option<&str>, Option<&str>, &[(&str, &str)], Option<&str>, u16)] = &[
    ("GET", "/clientOtpPolicy?size=3", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("POST", "/clientOtpPolicy/query", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], Some("{\"size\": 2, \"sort\": [{\"property\": \"id\", \"direction\": \"DESC\"}]}"), 200),
    ("GET", "/clientOtpPolicy/{OTP_0}", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/clientOtpPolicy/{OTP_1}", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/clientOtpPolicy/999999", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 404),
    ("GET", "/clientOtpPolicy/x", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 400),
    ("GET", "/clientPasswordPolicy?size=3", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("POST", "/clientPasswordPolicy/query", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], Some("{\"size\": 2, \"sort\": [{\"property\": \"id\", \"direction\": \"DESC\"}]}"), 200),
    ("GET", "/clientPasswordPolicy/{PASSWORD_0}", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/clientPasswordPolicy/{PASSWORD_1}", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/clientPasswordPolicy/999999", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 404),
    ("GET", "/clientPasswordPolicy/x", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 400),
    ("GET", "/clientPinPolicy?size=3", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("POST", "/clientPinPolicy/query", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], Some("{\"size\": 2, \"sort\": [{\"property\": \"id\", \"direction\": \"DESC\"}]}"), 200),
    ("GET", "/clientPinPolicy/{PIN_0}", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/clientPinPolicy/{PIN_1}", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/clientPinPolicy/999999", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 404),
    ("GET", "/clientPinPolicy/x", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 400),
    ("GET", "/client-activities/1?size=2", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("POST", "/client-activities/1/query", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], Some("{\"size\": 2, \"sort\": [{\"property\": \"id\", \"direction\": \"DESC\"}]}"), 200),
    ("GET", "/client-activities/28?size=2", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("POST", "/client-activities/28/query", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], Some("{\"size\": 2, \"sort\": [{\"property\": \"id\", \"direction\": \"DESC\"}]}"), 200),
    ("GET", "/client-activities/4452?size=2", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("POST", "/client-activities/4452/query", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], Some("{\"size\": 2, \"sort\": [{\"property\": \"id\", \"direction\": \"DESC\"}]}"), 200),
    ("POST", "/client-activities", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], Some("{\"activityName\": \" \"}"), 400),
    ("GET", "/clients?size=2&sort=id%2Cdesc", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/clients?size=2&fetchUserCounts=true&fetchOwners=true&fetchApps=true&fetchCreatedByUser=true", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("POST", "/clients/query?fetchManagingClient=true", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], Some("{\"size\": 3, \"condition\": {\"field\": \"typeCode\", \"value\": \"BUS\"}}"), 200),
    ("POST", "/clients/query", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], Some("{\"size\": 3, \"condition\": {\"field\": \"typeCode\", \"value\": \"BUS\"}, \"sort\": [{\"property\": \"updatedAt\", \"direction\": \"DESC\"}, {\"property\": \"id\", \"direction\": \"ASC\"}]}"), 200),
    ("GET", "/clients/1", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/clients/28", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/clients/999999", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 404),
    ("GET", "/clients/x", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 400),
    ("POST", "/clients/noMapping", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], Some("{}"), 400),
    ("GET", "/clients/makeClientActive?clientId=x", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 400),
    ("GET", "/clienturls?size=3", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("POST", "/clienturls/query", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], Some("{\"size\": 2, \"condition\": {\"field\": \"appCode\", \"value\": \"leadzump\"}}"), 200),
    ("GET", "/clienturls/{URL_0}", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/clienturls/{URL_1}", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/clienturls/999999", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 404),
    ("GET", "/clienturls/fetchUrls?appCode=appbuilder&suffix=%2Fx", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/clienturls/urls?appCode=appbuilder&size=3", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/clienturls/draft?appCode=appbuilder", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/applications/appCode/appbuilder", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/applications/clients/appbuilder?onlyWriteAccess=false&size=2", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/applications/findBaseClientCode/appbuilder", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/applications/property?appCode=appbuilder", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/applications/property?appCode=appbuilder&clientId=1", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/applications/dependencies?appCode=appbuilder", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("POST", "/applications/reg/appbuilder/appAccess/query", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], Some("{\"page\": 0, \"size\": 2}"), 200),
    ("POST", "/applications/reg/appbuilder/fileAccess/query", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], Some("{\"page\": 0, \"size\": 2}"), 200),
    ("POST", "/applications/reg/appbuilder/userRole/query", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], Some("{\"page\": 0, \"size\": 2}"), 200),
    ("POST", "/applications/reg/appbuilder/nope/query", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], Some("{\"page\": 0, \"size\": 2}"), 400),
    ("GET", "/clienturls/fetchUrls?appCode=leadzump&suffix=%2Fx", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/clienturls/urls?appCode=leadzump&size=3", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/clienturls/draft?appCode=leadzump", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/applications/appCode/leadzump", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/applications/clients/leadzump?onlyWriteAccess=false&size=2", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/applications/findBaseClientCode/leadzump", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/applications/property?appCode=leadzump", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/applications/property?appCode=leadzump&clientId=1", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/applications/dependencies?appCode=leadzump", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("POST", "/applications/reg/leadzump/appAccess/query", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], Some("{\"page\": 0, \"size\": 2}"), 200),
    ("POST", "/applications/reg/leadzump/fileAccess/query", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], Some("{\"page\": 0, \"size\": 2}"), 200),
    ("POST", "/applications/reg/leadzump/userRole/query", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], Some("{\"page\": 0, \"size\": 2}"), 200),
    ("POST", "/applications/reg/leadzump/nope/query", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], Some("{\"page\": 0, \"size\": 2}"), 400),
    ("GET", "/clienturls/fetchUrls?appCode=nope&suffix=%2Fx", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/clienturls/urls?appCode=nope&size=3", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 403),
    ("GET", "/clienturls/draft?appCode=nope", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 404),
    ("GET", "/applications/appCode/nope", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/applications/clients/nope?onlyWriteAccess=false&size=2", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/applications/findBaseClientCode/nope", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/applications/property?appCode=nope", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/applications/property?appCode=nope&clientId=1", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/applications/dependencies?appCode=nope", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("POST", "/applications/reg/nope/appAccess/query", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], Some("{\"page\": 0, \"size\": 2}"), 200),
    ("POST", "/applications/reg/nope/fileAccess/query", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], Some("{\"page\": 0, \"size\": 2}"), 200),
    ("POST", "/applications/reg/nope/userRole/query", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], Some("{\"page\": 0, \"size\": 2}"), 200),
    ("POST", "/applications/reg/nope/nope/query", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], Some("{\"page\": 0, \"size\": 2}"), 400),
    ("GET", "/clienturls/urls?appCode=appbuilder&clientCode=NOPE", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 403),
    ("GET", "/applications?size=3", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("POST", "/applications/query", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], Some("{\"size\": 3, \"sort\": [{\"property\": \"appCode\"}]}"), 200),
    ("POST", "/applications/accessible/query", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], Some("{\"size\": 3}"), 200),
    ("GET", "/applications/2", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/applications/999999", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 404),
    ("GET", "/applications/clients/appbuilder", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 500),
    ("GET", "/applications/clientHasReadAccess?appCodes=appbuilder,leadzump&appCodes=x", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/applications/clientHasReadAccess?appCodes=appbuilder,%20leadzump,nope", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/applications/findAnyApps?size=2", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 500),
    ("GET", "/applications/hasDeleteAccess?deleteAppCode=appbuilder&deleteClientCode=FIN", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/applications/property", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 400),
    ("POST", "/applications/reg/cxapp/appAccess/query", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], Some("{\"size\": 2}"), 500),
    ("POST", "/applications/reg/cxapp/appAccess/query", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], Some("{\"page\": 0, \"size\": 2, \"clientCode\": \"A\", \"clientId\": 1}"), 400),
    ("GET", "/appRegIntegration?size=2", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("POST", "/appRegIntegration/query", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], Some("{\"size\": 2}"), 200),
    ("GET", "/appRegIntegration/999999", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 404),
    ("GET", "/transports/makeTransport?applicationCode=appbuilder", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("POST", "/transports/createAndApply", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], Some("{}"), 200),
    ("GET", "/ssl?urlId={URL_CERT}&size=2", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/ssl", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 404),
    ("GET", "/ssl?urlId=x", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 500),
    ("POST", "/ssl/query", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], Some("{\"size\": 2, \"condition\": {\"field\": \"urlId\", \"value\": {URL_CERT}}}"), 200),
    ("POST", "/ssl/query", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], Some("{\"size\": 2}"), 500),
    ("GET", "/ssl/request?urlId={URL_CERT}", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/ssl/request?urlId=999999", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 404),
    ("GET", "/ssl/certificate?requestId=999999", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 404),
    ("GET", "/ssl/request/challenge?challengeId=999999", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 404),
    ("DELETE", "/ssl/x", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 500),
    ("DELETE", "/ssl/999999", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 404),
    ("DELETE", "/ssl/request?urlId=999999", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 404),
    ("POST", "/ssl", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], Some("{\"domainNames\": [], \"urlId\": 1}"), 400),
    ("POST", "/ssl", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], Some("{\"urlId\": 1}"), 500),
    ("POST", "/ssl", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], Some("{\"domainNames\": [\"x.com\"], \"urlId\": {URL_CERT}}"), 409),
    ("POST", "/ssl/external", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], Some("{\"urlId\": 1}"), 400),
    ("POST", "/ssl/external", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], Some("{\"urlId\": 1, \"crtKeyUpload\": \"k\", \"crt\": \"garbage\"}"), 400),
    ("GET", "/clientOtpPolicy?size=3", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("POST", "/clientOtpPolicy/query", Some(110), Some("FIN"), Some("appbuilder"), &[], Some("{\"size\": 2, \"sort\": [{\"property\": \"id\", \"direction\": \"DESC\"}]}"), 200),
    ("GET", "/clientOtpPolicy/{OTP_0}", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("GET", "/clientOtpPolicy/{OTP_1}", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("GET", "/clientOtpPolicy/999999", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 404),
    ("GET", "/clientOtpPolicy/x", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 400),
    ("GET", "/clientPasswordPolicy?size=3", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("POST", "/clientPasswordPolicy/query", Some(110), Some("FIN"), Some("appbuilder"), &[], Some("{\"size\": 2, \"sort\": [{\"property\": \"id\", \"direction\": \"DESC\"}]}"), 200),
    ("GET", "/clientPasswordPolicy/{PASSWORD_0}", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("GET", "/clientPasswordPolicy/{PASSWORD_1}", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("GET", "/clientPasswordPolicy/999999", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 404),
    ("GET", "/clientPasswordPolicy/x", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 400),
    ("GET", "/clientPinPolicy?size=3", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("POST", "/clientPinPolicy/query", Some(110), Some("FIN"), Some("appbuilder"), &[], Some("{\"size\": 2, \"sort\": [{\"property\": \"id\", \"direction\": \"DESC\"}]}"), 200),
    ("GET", "/clientPinPolicy/{PIN_0}", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("GET", "/clientPinPolicy/{PIN_1}", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("GET", "/clientPinPolicy/999999", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 404),
    ("GET", "/clientPinPolicy/x", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 400),
    ("GET", "/client-activities/1?size=2", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 403),
    ("POST", "/client-activities/1/query", Some(110), Some("FIN"), Some("appbuilder"), &[], Some("{\"size\": 2, \"sort\": [{\"property\": \"id\", \"direction\": \"DESC\"}]}"), 403),
    ("GET", "/client-activities/28?size=2", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("POST", "/client-activities/28/query", Some(110), Some("FIN"), Some("appbuilder"), &[], Some("{\"size\": 2, \"sort\": [{\"property\": \"id\", \"direction\": \"DESC\"}]}"), 200),
    ("GET", "/client-activities/4452?size=2", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("POST", "/client-activities/4452/query", Some(110), Some("FIN"), Some("appbuilder"), &[], Some("{\"size\": 2, \"sort\": [{\"property\": \"id\", \"direction\": \"DESC\"}]}"), 200),
    ("POST", "/client-activities", Some(110), Some("FIN"), Some("appbuilder"), &[], Some("{\"activityName\": \" \"}"), 400),
    ("GET", "/clients?size=2&sort=id%2Cdesc", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("GET", "/clients?size=2&fetchUserCounts=true&fetchOwners=true&fetchApps=true&fetchCreatedByUser=true", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("POST", "/clients/query?fetchManagingClient=true", Some(110), Some("FIN"), Some("appbuilder"), &[], Some("{\"size\": 3, \"condition\": {\"field\": \"typeCode\", \"value\": \"BUS\"}}"), 200),
    ("POST", "/clients/query", Some(110), Some("FIN"), Some("appbuilder"), &[], Some("{\"size\": 3, \"condition\": {\"field\": \"typeCode\", \"value\": \"BUS\"}, \"sort\": [{\"property\": \"updatedAt\", \"direction\": \"DESC\"}, {\"property\": \"id\", \"direction\": \"ASC\"}]}"), 200),
    ("GET", "/clients/1", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 403),
    ("GET", "/clients/28", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("GET", "/clients/999999", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 404),
    ("GET", "/clients/x", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 400),
    ("POST", "/clients/noMapping", Some(110), Some("FIN"), Some("appbuilder"), &[], Some("{}"), 400),
    ("GET", "/clients/makeClientActive?clientId=x", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 400),
    ("GET", "/clienturls?size=3", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("POST", "/clienturls/query", Some(110), Some("FIN"), Some("appbuilder"), &[], Some("{\"size\": 2, \"condition\": {\"field\": \"appCode\", \"value\": \"leadzump\"}}"), 200),
    ("GET", "/clienturls/{URL_0}", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 404),
    ("GET", "/clienturls/{URL_1}", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 404),
    ("GET", "/clienturls/999999", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 404),
    ("GET", "/clienturls/fetchUrls?appCode=appbuilder&suffix=%2Fx", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("GET", "/clienturls/urls?appCode=appbuilder&size=3", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("GET", "/clienturls/draft?appCode=appbuilder", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 404),
    ("GET", "/applications/appCode/appbuilder", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("GET", "/applications/clients/appbuilder?onlyWriteAccess=false&size=2", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("GET", "/applications/findBaseClientCode/appbuilder", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("GET", "/applications/property?appCode=appbuilder", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("GET", "/applications/property?appCode=appbuilder&clientId=1", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("GET", "/applications/dependencies?appCode=appbuilder", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("POST", "/applications/reg/appbuilder/appAccess/query", Some(110), Some("FIN"), Some("appbuilder"), &[], Some("{\"page\": 0, \"size\": 2}"), 200),
    ("POST", "/applications/reg/appbuilder/fileAccess/query", Some(110), Some("FIN"), Some("appbuilder"), &[], Some("{\"page\": 0, \"size\": 2}"), 200),
    ("POST", "/applications/reg/appbuilder/userRole/query", Some(110), Some("FIN"), Some("appbuilder"), &[], Some("{\"page\": 0, \"size\": 2}"), 200),
    ("POST", "/applications/reg/appbuilder/nope/query", Some(110), Some("FIN"), Some("appbuilder"), &[], Some("{\"page\": 0, \"size\": 2}"), 400),
    ("GET", "/clienturls/fetchUrls?appCode=leadzump&suffix=%2Fx", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("GET", "/clienturls/urls?appCode=leadzump&size=3", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("GET", "/clienturls/draft?appCode=leadzump", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 404),
    ("GET", "/applications/appCode/leadzump", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("GET", "/applications/clients/leadzump?onlyWriteAccess=false&size=2", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("GET", "/applications/findBaseClientCode/leadzump", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("GET", "/applications/property?appCode=leadzump", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("GET", "/applications/property?appCode=leadzump&clientId=1", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("GET", "/applications/dependencies?appCode=leadzump", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("POST", "/applications/reg/leadzump/appAccess/query", Some(110), Some("FIN"), Some("appbuilder"), &[], Some("{\"page\": 0, \"size\": 2}"), 200),
    ("POST", "/applications/reg/leadzump/fileAccess/query", Some(110), Some("FIN"), Some("appbuilder"), &[], Some("{\"page\": 0, \"size\": 2}"), 200),
    ("POST", "/applications/reg/leadzump/userRole/query", Some(110), Some("FIN"), Some("appbuilder"), &[], Some("{\"page\": 0, \"size\": 2}"), 200),
    ("POST", "/applications/reg/leadzump/nope/query", Some(110), Some("FIN"), Some("appbuilder"), &[], Some("{\"page\": 0, \"size\": 2}"), 400),
    ("GET", "/clienturls/fetchUrls?appCode=nope&suffix=%2Fx", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("GET", "/clienturls/urls?appCode=nope&size=3", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 403),
    ("GET", "/clienturls/draft?appCode=nope", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 404),
    ("GET", "/applications/appCode/nope", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("GET", "/applications/clients/nope?onlyWriteAccess=false&size=2", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("GET", "/applications/findBaseClientCode/nope", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("GET", "/applications/property?appCode=nope", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("GET", "/applications/property?appCode=nope&clientId=1", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("GET", "/applications/dependencies?appCode=nope", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("POST", "/applications/reg/nope/appAccess/query", Some(110), Some("FIN"), Some("appbuilder"), &[], Some("{\"page\": 0, \"size\": 2}"), 200),
    ("POST", "/applications/reg/nope/fileAccess/query", Some(110), Some("FIN"), Some("appbuilder"), &[], Some("{\"page\": 0, \"size\": 2}"), 200),
    ("POST", "/applications/reg/nope/userRole/query", Some(110), Some("FIN"), Some("appbuilder"), &[], Some("{\"page\": 0, \"size\": 2}"), 200),
    ("POST", "/applications/reg/nope/nope/query", Some(110), Some("FIN"), Some("appbuilder"), &[], Some("{\"page\": 0, \"size\": 2}"), 400),
    ("GET", "/clienturls/urls?appCode=appbuilder&clientCode=NOPE", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 403),
    ("GET", "/applications?size=3", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("POST", "/applications/query", Some(110), Some("FIN"), Some("appbuilder"), &[], Some("{\"size\": 3, \"sort\": [{\"property\": \"appCode\"}]}"), 200),
    ("POST", "/applications/accessible/query", Some(110), Some("FIN"), Some("appbuilder"), &[], Some("{\"size\": 3}"), 200),
    ("GET", "/applications/2", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("GET", "/applications/999999", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 404),
    ("GET", "/applications/clients/appbuilder", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 500),
    ("GET", "/applications/clientHasReadAccess?appCodes=appbuilder,leadzump&appCodes=x", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("GET", "/applications/clientHasReadAccess?appCodes=appbuilder,%20leadzump,nope", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("GET", "/applications/findAnyApps?size=2", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 500),
    ("GET", "/applications/hasDeleteAccess?deleteAppCode=appbuilder&deleteClientCode=FIN", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("GET", "/applications/property", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 400),
    ("POST", "/applications/reg/cxapp/appAccess/query", Some(110), Some("FIN"), Some("appbuilder"), &[], Some("{\"size\": 2}"), 500),
    ("POST", "/applications/reg/cxapp/appAccess/query", Some(110), Some("FIN"), Some("appbuilder"), &[], Some("{\"page\": 0, \"size\": 2, \"clientCode\": \"A\", \"clientId\": 1}"), 400),
    ("GET", "/appRegIntegration?size=2", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("POST", "/appRegIntegration/query", Some(110), Some("FIN"), Some("appbuilder"), &[], Some("{\"size\": 2}"), 200),
    ("GET", "/appRegIntegration/999999", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 404),
    ("GET", "/transports/makeTransport?applicationCode=appbuilder", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 200),
    ("POST", "/transports/createAndApply", Some(110), Some("FIN"), Some("appbuilder"), &[], Some("{}"), 200),
    ("GET", "/ssl?urlId={URL_CERT}&size=2", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 404),
    ("GET", "/ssl", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 404),
    ("GET", "/ssl?urlId=x", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 500),
    ("POST", "/ssl/query", Some(110), Some("FIN"), Some("appbuilder"), &[], Some("{\"size\": 2, \"condition\": {\"field\": \"urlId\", \"value\": {URL_CERT}}}"), 404),
    ("POST", "/ssl/query", Some(110), Some("FIN"), Some("appbuilder"), &[], Some("{\"size\": 2}"), 500),
    ("GET", "/ssl/request?urlId={URL_CERT}", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 404),
    ("GET", "/ssl/request?urlId=999999", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 404),
    ("GET", "/ssl/certificate?requestId=999999", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 404),
    ("GET", "/ssl/request/challenge?challengeId=999999", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 404),
    ("DELETE", "/ssl/x", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 500),
    ("DELETE", "/ssl/999999", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 404),
    ("DELETE", "/ssl/request?urlId=999999", Some(110), Some("FIN"), Some("appbuilder"), &[], None, 404),
    ("POST", "/ssl", Some(110), Some("FIN"), Some("appbuilder"), &[], Some("{\"domainNames\": [], \"urlId\": 1}"), 400),
    ("POST", "/ssl", Some(110), Some("FIN"), Some("appbuilder"), &[], Some("{\"urlId\": 1}"), 500),
    ("POST", "/ssl", Some(110), Some("FIN"), Some("appbuilder"), &[], Some("{\"domainNames\": [\"x.com\"], \"urlId\": {URL_CERT}}"), 409),
    ("POST", "/ssl/external", Some(110), Some("FIN"), Some("appbuilder"), &[], Some("{\"urlId\": 1}"), 400),
    ("POST", "/ssl/external", Some(110), Some("FIN"), Some("appbuilder"), &[], Some("{\"urlId\": 1, \"crtKeyUpload\": \"k\", \"crt\": \"garbage\"}"), 400),
    ("GET", "/ssl/token/{TOKEN}", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/ssl/token/nope", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/ssl/token/{TOKEN}", None, Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/ssl/token/nope", None, Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("POST", "/ssl/internal/renew-certificates", Some(8), Some("FIN"), Some("appbuilder"), &[], None, 500),
    ("GET", "/applications?size=1", Some(8), Some("FIN"), Some("appbuilder"), &[], None, 403),
    ("GET", "/applications?size=1", None, Some("SYSTEM"), Some("appbuilder"), &[], None, 401),
    ("GET", "/applications/2", Some(8), Some("FIN"), Some("appbuilder"), &[], None, 403),
    ("GET", "/applications/2", None, Some("SYSTEM"), Some("appbuilder"), &[], None, 401),
    ("GET", "/clients?size=1", Some(8), Some("FIN"), Some("appbuilder"), &[], None, 403),
    ("GET", "/clients?size=1", None, Some("SYSTEM"), Some("appbuilder"), &[], None, 401),
    ("GET", "/clients/28", Some(8), Some("FIN"), Some("appbuilder"), &[], None, 403),
    ("GET", "/clients/28", None, Some("SYSTEM"), Some("appbuilder"), &[], None, 401),
    ("GET", "/clienturls?size=1", Some(8), Some("FIN"), Some("appbuilder"), &[], None, 403),
    ("GET", "/clienturls?size=1", None, Some("SYSTEM"), Some("appbuilder"), &[], None, 401),
    ("GET", "/clientPinPolicy/{PIN_0}", Some(8), Some("FIN"), Some("appbuilder"), &[], None, 403),
    ("GET", "/clientPinPolicy/{PIN_0}", None, Some("SYSTEM"), Some("appbuilder"), &[], None, 401),
    ("GET", "/clients/makeClientActive", Some(8), Some("FIN"), Some("appbuilder"), &[], None, 403),
    ("GET", "/clients/makeClientActive", None, Some("SYSTEM"), Some("appbuilder"), &[], None, 401),
    ("GET", "/appRegIntegration?size=1", Some(8), Some("FIN"), Some("appbuilder"), &[], None, 403),
    ("GET", "/appRegIntegration?size=1", None, Some("SYSTEM"), Some("appbuilder"), &[], None, 401),
    ("GET", "/ssl?urlId={URL_CERT}", Some(8), Some("FIN"), Some("appbuilder"), &[], None, 403),
    ("GET", "/ssl?urlId={URL_CERT}", None, Some("SYSTEM"), Some("appbuilder"), &[], None, 401),
    ("POST", "/applications", Some(8), Some("FIN"), Some("appbuilder"), &[], Some("{\"appCode\": \"a-1\"}"), 403),
    ("POST", "/clientOtpPolicy", Some(8), Some("FIN"), Some("appbuilder"), &[], Some("{\"appId\": 999999999}"), 403),
    ("POST", "/clienturls", Some(8), Some("FIN"), Some("appbuilder"), &[], Some("{\"urlPattern\": \"x.example.test\"}"), 403),
    ("POST", "/clients", Some(8), Some("FIN"), Some("appbuilder"), &[], Some("{\"name\": \"x\"}"), 403),
    ("POST", "/appRegIntegration", Some(8), Some("FIN"), Some("appbuilder"), &[], Some("{\"platform\": \"GOOGLE\"}"), 403),
    ("GET", "/clientOtpPolicy/codes/policy", None, Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/clientOtpPolicy/codes/policy", None, Some("SYSTEM"), Some("leadzump"), &[], None, 200),
    ("GET", "/clientOtpPolicy/codes/policy", None, Some("SYSTEM"), Some("nope"), &[], None, 200),
    ("GET", "/clientOtpPolicy/codes/policy", None, Some("SYSTEM"), None, &[], None, 500),
    ("GET", "/clientPasswordPolicy/codes/policy", None, Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/clientPasswordPolicy/codes/policy", None, Some("SYSTEM"), Some("leadzump"), &[], None, 200),
    ("GET", "/clientPasswordPolicy/codes/policy", None, Some("SYSTEM"), Some("nope"), &[], None, 200),
    ("GET", "/clientPasswordPolicy/codes/policy", None, Some("SYSTEM"), None, &[], None, 500),
    ("GET", "/clientPinPolicy/codes/policy", None, Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/clientPinPolicy/codes/policy", None, Some("SYSTEM"), Some("leadzump"), &[], None, 200),
    ("GET", "/clientPinPolicy/codes/policy", None, Some("SYSTEM"), Some("nope"), &[], None, 200),
    ("GET", "/clientPinPolicy/codes/policy", None, Some("SYSTEM"), None, &[], None, 500),
    ("GET", "/applications/applyAppCodeSuffix?appCode=abc", None, Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/applications/applyAppCodePrefix?appCode=abc", None, Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/applications/dependencies?appCode=leadzump", None, Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/clients/socialRegister/callback", None, Some("SYSTEM"), Some("appbuilder"), &[], None, 500),
    ("GET", "/clients/socialRegister/callback?code=x&state=nope", None, Some("SYSTEM"), Some("appbuilder"), &[], None, 500),
    ("GET", "/clients/socialRegister/evoke?platform=GOOGLE", None, Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("POST", "/clients/socialRegister/evoke?platform=META", None, Some("SYSTEM"), Some("appbuilder"), &[], None, 200),
    ("GET", "/clients/socialRegister/evoke?platform=NOPE", None, Some("SYSTEM"), Some("appbuilder"), &[], None, 400),
    ("POST", "/clients/register", None, Some("SYSTEM"), Some("appbuilder"), &[], Some("{}"), 400),
    ("POST", "/clients/register", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], Some("{}"), 400),
    ("POST", "/clients/register", None, Some("SYSTEM"), Some("appbuilder"), &[], Some("{\"passType\": \"NOPE\"}"), 400),
    ("POST", "/clients/register", None, Some("SYSTEM"), Some("appbuilder"), &[], Some("[1]"), 400),
    ("POST", "/clients/register", None, Some("SYSTEM"), Some("appbuilder"), &[], None, 400),
    ("POST", "/clients/register", None, Some("SYSTEM"), Some("appbuilder"), &[], Some("{\"passType\": \"PASSWORD\", \"password\": \"weak\", \"emailId\": \"zz.reg.parity.ybycvjfn@example.com\"}"), 400),
    ("POST", "/clients/register/otp/verify", None, Some("SYSTEM"), Some("appbuilder"), &[], Some("{}"), 500),
    ("POST", "/clients/register/otp/verify", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], Some("{\"emailId\": \"zz.reg.parity.ybycvjfn@example.com\", \"passType\": \"OTP\"}"), 400),
    ("POST", "/clients/register", None, Some("SYSTEM"), Some("appbuilder"), &[], Some("{\"passType\": \"OTP\", \"emailId\": \"zz.reg.parity.ybycvjfn@example.com\", \"firstName\": \"ZZ\"}"), 400),
    ("POST", "/clients/register/otp/verify", None, Some("SYSTEM"), Some("appbuilder"), &[], Some("{\"passType\": \"OTP\", \"emailId\": \"zz.reg.parity.ybycvjfn@example.com\", \"otp\": \"0000\"}"), 400),
    ("POST", "/clients/socialRegister", None, Some("SYSTEM"), Some("appbuilder"), &[], Some("{}"), 400),
    ("POST", "/clients/socialRegister", None, Some("SYSTEM"), Some("appbuilder"), &[], Some("{\"socialRegisterState\": \"zz-no-state-ybycvjfn\"}"), 500),
    ("GET", "/clients/register/events", None, Some("SYSTEM"), Some("appbuilder"), &[], Some("{}"), 404),
    ("GET", "/clients/register/events", None, Some("SYSTEM"), Some("appbuilder"), &[], None, 415),
    ("POST", "/clients/appRegister", None, Some("SYSTEM"), Some("appbuilder"), &[], None, 401),
    ("POST", "/clients/appRegister", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 400),
    ("POST", "/clients/appRegister?appCode=x&clientId=x&userId=1", Some(142), Some("SYSTEM"), Some("appbuilder"), &[], None, 400),
];

#[tokio::test]
async fn read_sweep() {
    let Some(l) = live().await else { return };
    let one = |sql: &str| {
        let pool = l.pool.clone();
        let sql = sql.to_string();
        async move { sqlx::query_scalar::<_, String>(&sql).fetch_optional(&pool).await.unwrap() }
    };
    let mut vars: Vec<(String, String)> = Vec::new();
    if let Some(v) = one("SELECT CAST(URL_ID AS CHAR) FROM security_ssl_certificate WHERE CURRENT = 1 ORDER BY ID DESC LIMIT 1").await {
        vars.push(("{URL_CERT}".into(), v));
    }
    if let Some(v) = one("SELECT TOKEN FROM security_ssl_challenge ORDER BY ID DESC LIMIT 1").await {
        vars.push(("{TOKEN}".into(), v));
    }
    for t in ["otp", "password", "pin"] {
        let ids = sqlx::query_scalar::<_, u64>(&format!("SELECT ID FROM security_client_{t}_policy ORDER BY ID LIMIT 2")).fetch_all(&l.pool).await.unwrap();
        for (i, id) in ids.iter().enumerate() {
            vars.push((format!("{{{}_{i}}}", t.to_uppercase()), id.to_string()));
        }
    }
    let urls = sqlx::query_scalar::<_, u64>("SELECT ID FROM security_client_url WHERE URL_TYPE = 'LIVE' ORDER BY ID DESC LIMIT 2").fetch_all(&l.pool).await.unwrap();
    for (i, id) in urls.iter().enumerate() {
        vars.push((format!("{{URL_{i}}}"), id.to_string()));
    }
    let fill = |s: &str| vars.iter().fold(s.to_string(), |acc, (k, v)| acc.replace(k, v));
    let mut wrong = Vec::new();
    for (method, path, user, client, app, extra, body, status) in SWEEP {
        let mut h: Vec<(&str, String)> = Vec::new();
        if let Some(u) = user {
            h.push(("authorization", basic(*u)));
        }
        if let Some(c) = client {
            h.push(("clientcode", c.to_string()));
        }
        if let Some(a) = app {
            h.push(("appcode", a.to_string()));
        }
        for (k, v) in extra.iter() {
            h.push((k, v.to_string()));
        }
        let body = body.map(|b| serde_json::from_str::<Value>(&fill(b)).unwrap());
        let path = fill(path);
        let r = l.call(method, &path, &h, body).await;
        if r.status.as_u16() != *status {
            wrong.push(format!("{method} {path} as {user:?}: {} (Java {status}): {}", r.status, &r.body[..r.body.len().min(200)]));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
