//! The gateway end to end against in-process upstreams and a fake security service.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::{to_bytes, Body, Bytes};
use axum::extract::{ConnectInfo, Query, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use gateway::config::{GatewayConfig, PoolConfig, RouteConfig};
use platform::config::UpstreamConfig;
use serde_json::{json, Value};
use tower::ServiceExt;

#[derive(Default)]
struct Fake {
    host_calls: AtomicUsize,
    draft_calls: AtomicUsize,
    access_calls: AtomicUsize,
    /// "<appCode>:<clientCode>" pairs whose client owns the app or has access to it.
    access: Mutex<Vec<String>>,
    access_down: Mutex<bool>,
    /// host -> [clientCode, appCode, surface]
    hosts: Mutex<BTreeMap<String, Value>>,
    /// draft answer: [allowed, expiresAt, appCode, clientCode]
    draft: Mutex<Value>,
    security_down: Mutex<bool>,
}

type F = Arc<Fake>;

async fn echo(req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let body = to_bytes(body, usize::MAX).await.unwrap();
    let headers: BTreeMap<String, String> = parts
        .headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let mut resp = Json(json!({
        "method": parts.method.to_string(),
        "path": parts.uri.path(),
        "query": parts.uri.query(),
        "headers": headers,
        "body": String::from_utf8_lossy(&body),
    }))
    .into_response();
    resp.headers_mut().insert("keep-alive", "timeout=5".parse().unwrap());
    resp.headers_mut().insert("x-upstream", "echo".parse().unwrap());
    resp
}

fn fake_app(f: F) -> Router {
    Router::new()
        .route(
            "/api/security/clients/internal/getClientNAppCodeNType",
            get(|State(f): State<F>, Query(q): Query<BTreeMap<String, String>>| async move {
                if *f.security_down.lock().unwrap() {
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
                f.host_calls.fetch_add(1, Ordering::SeqCst);
                let host = q.get("host").cloned().unwrap_or_default();
                if host == "empty.example" {
                    return (StatusCode::OK, "").into_response();
                }
                if host == "short.example" {
                    return Json(json!(["ONLY"])).into_response();
                }
                let v = f.hosts.lock().unwrap().get(&host).cloned().unwrap_or(json!(["SYSTEM", "nothing", "LIVE"]));
                Json(v).into_response()
            }),
        )
        .route(
            "/api/security/clienturls/internal/draft/token/resolve",
            get(|State(f): State<F>, Query(q): Query<BTreeMap<String, String>>| async move {
                f.draft_calls.fetch_add(1, Ordering::SeqCst);
                if *f.security_down.lock().unwrap() {
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
                // Like security: a token grants only its own app and client.
                let answer = f.draft.lock().unwrap().clone();
                let asked_app = q.get("appCode").cloned().unwrap_or_default();
                if !asked_app.is_empty() && answer[2] != json!(asked_app) {
                    return Json(json!([false, "0", "", ""])).into_response();
                }
                Json(answer).into_response()
            }),
        )
        .route(
            "/api/security/applications/internal/hasReadAccess",
            get(|State(f): State<F>, Query(q): Query<BTreeMap<String, String>>| async move {
                f.access_calls.fetch_add(1, Ordering::SeqCst);
                if *f.access_down.lock().unwrap() {
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
                let key = format!("{}:{}", q.get("appCode").cloned().unwrap_or_default(), q.get("clientCode").cloned().unwrap_or_default());
                Json(json!(f.access.lock().unwrap().contains(&key))).into_response()
            }),
        )
        .route("/health", get(|| async { "ok" }))
        .route(
            "/sse",
            get(|| async {
                let mut r = Response::new(Body::from("data: one\n\n"));
                r.headers_mut().insert("content-type", "text/event-stream".parse().unwrap());
                r.headers_mut().insert("content-length", "11".parse().unwrap());
                r
            }),
        )
        .route(
            "/api/slow",
            get(|| async {
                tokio::time::sleep(Duration::from_secs(3)).await;
                "late"
            }),
        )
        .fallback(echo)
        .with_state(f)
}

async fn serve(app: Router) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    base
}

/// Accepts connections and closes them without answering.
async fn closer() -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            if let Ok((s, _)) = l.accept().await {
                drop(s);
            }
        }
    });
    base
}

fn pool(urls: &[&str], health: &str) -> PoolConfig {
    PoolConfig {
        upstreams: UpstreamConfig::Many(urls.iter().map(|s| s.to_string()).collect()),
        health_path: health.into(),
        health_interval_seconds: 3600,
        unhealthy_after: 2,
        ..Default::default()
    }
}

fn route(id: &str, prefix: &str, pool: &str) -> RouteConfig {
    RouteConfig { id: id.into(), prefix: prefix.into(), pool: pool.into(), ..Default::default() }
}

async fn setup() -> (Router, F) {
    let fake: F = Arc::new(Fake::default());
    *fake.draft.lock().unwrap() = json!([false, "0", "", ""]);
    let base = serve(fake_app(fake.clone())).await;
    let dead = "http://127.0.0.1:1";
    let close = closer().await;

    let mut cfg = GatewayConfig::default();
    cfg.security.upstream = UpstreamConfig::One(base.clone());
    cfg.resolution.draft_trust_seconds = 60;
    cfg.pools.insert("echo".into(), pool(&[&base], "/health"));
    cfg.pools.insert("flaky".into(), pool(&[dead, &base], "/health"));
    cfg.pools.insert("dead".into(), pool(&[dead], "/health"));
    cfg.pools.insert("closer".into(), pool(&[&close], "/health"));
    cfg.routes = vec![
        RouteConfig {
            id: "slow".into(),
            prefix: "/api/slow".into(),
            pool: "echo".into(),
            timeout_seconds: Some(1),
            ..Default::default()
        },
        RouteConfig {
            id: "files-read".into(),
            prefix: "/api/files".into(),
            contains: vec!["/api/files/static/file/".into()],
            methods: vec!["GET".into()],
            pool: "flaky".into(),
            ..Default::default()
        },
        route("dead", "/api/dead", "dead"),
        route("closer", "/api/closer", "closer"),
        route("api", "/api", "echo"),
        route("sse", "/sse", "echo"),
    ];
    let (app, _) = gateway::build(&cfg).await.unwrap();
    (app, fake)
}

fn req(method: &str, uri: &str, headers: &[(&str, &str)], body: &str) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri);
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    let mut r = b.body(Body::from(body.to_string())).unwrap();
    let addr: SocketAddr = "[::1]:50000".parse().unwrap();
    r.extensions_mut().insert(ConnectInfo(addr));
    r
}

async fn call(app: &Router, r: Request<Body>) -> (StatusCode, HeaderMap, Bytes) {
    let resp = app.clone().oneshot(r).await.unwrap();
    let (s, h) = (resp.status(), resp.headers().clone());
    (s, h, to_bytes(resp.into_body(), usize::MAX).await.unwrap())
}

fn j(b: &[u8]) -> Value {
    serde_json::from_slice(b).unwrap()
}

#[tokio::test]
async fn forwards_like_spring() {
    let (app, fake) = setup().await;
    fake.hosts.lock().unwrap().insert("leadzump.ai".into(), json!(["FIN", "leadzump", "LIVE"]));
    let (s, h, b) = call(
        &app,
        req(
            "POST",
            "/x/y/api/core/thing/?a=1&b=%20c",
            &[
                ("host", "leadzump.ai"),
                ("x-forwarded-proto", "https"),
                ("x-draft", "true"),
                ("connection", "keep-alive, x-secret"),
                ("x-secret", "s"),
                ("content-type", "application/json"),
            ],
            "{\"k\":1}",
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(h.get("keep-alive").is_none(), "hop-by-hop dropped from the response");
    assert_eq!(h["x-upstream"], "echo");
    let v = j(&b);
    assert_eq!(v["method"], "POST");
    assert_eq!(v["path"], "/api/core/thing");
    assert_eq!(v["query"], "a=1&b=%20c");
    assert_eq!(v["body"], "{\"k\":1}");
    let hd = &v["headers"];
    assert_eq!(hd["clientcode"], "FIN");
    assert_eq!(hd["appcode"], "leadzump");
    assert!(hd.get("x-draft").is_none());
    assert!(hd.get("x-secret").is_none() && hd.get("connection").is_none());
    assert_eq!(hd["x-forwarded-proto"], "https,http");
    assert_eq!(hd["x-forwarded-host"], "leadzump.ai");
    assert_eq!(hd["x-forwarded-port"], "80");
    assert_eq!(hd["x-forwarded-for"], "0:0:0:0:0:0:0:1");
    assert!(hd["host"].as_str().unwrap().starts_with("127.0.0.1:"));

    // The host answer is cached: a second request does not ask security again.
    let before = fake.host_calls.load(Ordering::SeqCst);
    call(&app, req("GET", "/api/x", &[("host", "leadzump.ai"), ("x-forwarded-proto", "https")], "")).await;
    assert_eq!(fake.host_calls.load(Ordering::SeqCst), before);
}

#[tokio::test]
async fn caller_codes_and_url_codes() {
    let (app, _) = setup().await;
    let (_, _, b) = call(&app, req("GET", "/api/x", &[("host", "a.example"), ("clientcode", "MINE"), ("appcode", "myapp")], "")).await;
    let hd = &j(&b)["headers"];
    assert_eq!((hd["clientcode"].as_str(), hd["appcode"].as_str()), (Some("MINE"), Some("myapp")));

    // /<app>/<client>/page/... names the codes; the forwarded path starts at /page/ — routed by
    // the catch-all-less table only when a route covers it, so use the api form after /page/.
    let (_, _, b) = call(&app, req("GET", "/leadzump/FIN2/page/api/x", &[("host", "h.example")], "")).await;
    let hd = &j(&b)["headers"];
    assert_eq!((hd["clientcode"].as_str(), hd["appcode"].as_str()), (Some("FIN2"), Some("leadzump")));
}

fn codes_of(b: &[u8]) -> (String, String) {
    let hd = &j(b)["headers"];
    (hd["appcode"].as_str().unwrap_or("").to_string(), hd["clientcode"].as_str().unwrap_or("").to_string())
}

#[tokio::test]
async fn url_codes_in_front_of_api_count_for_a_real_app_and_client() {
    let (app, fake) = setup().await;
    fake.hosts.lock().unwrap().insert("leadzump.ai".into(), json!(["HOST", "leadzump", "LIVE"]));
    fake.access.lock().unwrap().extend(["leadzump:FIN".to_string(), "leadzump:SYSTEM".to_string()]);
    let get = |path: &str| req("POST", path, &[("host", "leadzump.ai")], "{}");
    let calls = || fake.access_calls.load(Ordering::SeqCst);

    // A tenant with access (and the owner): the URL's codes, the path from /api/ on.
    let (_, _, b) = call(&app, get("/leadzump/FIN/api/webhooks/whatsapp")).await;
    assert_eq!(codes_of(&b), ("leadzump".into(), "FIN".into()));
    assert_eq!(j(&b)["path"], "/api/webhooks/whatsapp");
    let (_, _, b) = call(&app, get("/leadzump/SYSTEM/api/ui/page/home")).await;
    assert_eq!(codes_of(&b), ("leadzump".into(), "SYSTEM".into()), "a /page/ after /api/ changes nothing");
    assert_eq!(j(&b)["path"], "/api/ui/page/home");

    // The answer is cached: the same codes again ask nothing.
    let before = calls();
    call(&app, get("/leadzump/FIN/api/webhooks/whatsapp")).await;
    assert_eq!(calls(), before);

    // Unknown app, unknown client, a client without access, junk: the host decides.
    for path in ["/nosuchapp/FIN/api/x", "/leadzump/NOPE/api/x", "/leadzump/NOACCESS/api/x", "/x/y/api/ui/application"] {
        let (_, _, b) = call(&app, get(path)).await;
        assert_eq!(codes_of(&b), ("leadzump".into(), "HOST".into()), "{path}");
    }
    // A cached `false` is not asked again either.
    let before = calls();
    call(&app, get("/leadzump/NOACCESS/api/x")).await;
    assert_eq!(calls(), before);

    // Nothing to ask about: one segment, blank segments, characters no code has.
    let before = calls();
    for path in ["/assets/api/x", "//api/x", "/leadzump//api/x", "/static.files/FIN/api/x", "/api/x"] {
        let (s, _, b) = call(&app, get(path)).await;
        assert_eq!(s, StatusCode::OK, "{path}");
        assert_eq!(codes_of(&b), ("leadzump".into(), "HOST".into()), "{path}");
    }
    assert_eq!(calls(), before, "no lookup for codes that can not be real");

    // /page/ before /api/: the codes count unchecked, as in Java.
    let before = calls();
    let (_, _, b) = call(&app, get("/other/ANY/page/api/x")).await;
    assert_eq!(codes_of(&b), ("other".into(), "ANY".into()));
    assert_eq!(calls(), before);

    // The caller's own headers still win over the URL's codes.
    let (_, _, b) = call(&app, req("POST", "/leadzump/FIN/api/x", &[("host", "leadzump.ai"), ("clientcode", "MINE")], "{}")).await;
    assert_eq!(codes_of(&b), ("leadzump".into(), "MINE".into()));

    // An internal call that names its codes passes through without any lookup.
    let before = calls();
    let (_, _, b) = call(
        &app,
        req("GET", "/leadzump/OTHER/api/core/internal/x", &[("host", "leadzump.ai"), ("clientcode", "C"), ("appcode", "a")], ""),
    )
    .await;
    assert_eq!(codes_of(&b), ("a".into(), "C".into()));
    assert_eq!(calls(), before);

    // Security failing: the host decides, and the failure is not cached.
    *fake.access_down.lock().unwrap() = true;
    let (s, _, b) = call(&app, get("/leadzump/NEW/api/x")).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(codes_of(&b), ("leadzump".into(), "HOST".into()));
    *fake.access_down.lock().unwrap() = false;
    fake.access.lock().unwrap().push("leadzump:NEW".into());
    let (_, _, b) = call(&app, get("/leadzump/NEW/api/x")).await;
    assert_eq!(codes_of(&b), ("leadzump".into(), "NEW".into()));
}

#[tokio::test]
async fn draft_hosts() {
    let (app, fake) = setup().await;
    let host = "t-0123456789abcdef0123456789abcdef.apps.example";
    let far = (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 3600).to_string();

    *fake.draft.lock().unwrap() = json!([true, far, "leadzump", "FIN"]);
    let (_, _, b) = call(&app, req("GET", "/api/x", &[("host", host)], "")).await;
    let hd = &j(&b)["headers"];
    assert_eq!(hd["x-draft"], "true");
    assert_eq!((hd["clientcode"].as_str(), hd["appcode"].as_str()), (Some("FIN"), Some("leadzump")));
    let calls = fake.draft_calls.load(Ordering::SeqCst);
    call(&app, req("GET", "/api/x", &[("host", host)], "")).await;
    assert_eq!(fake.draft_calls.load(Ordering::SeqCst), calls, "cached within the trust window");

    // Codes in front of /api/ without /page/: draft hosts keep Java's rule and never read them.
    let before = fake.access_calls.load(Ordering::SeqCst);
    let (_, _, b) = call(&app, req("GET", "/other/ELSE/api/x", &[("host", host)], "")).await;
    let hd = &j(&b)["headers"];
    assert_eq!((hd["clientcode"].as_str(), hd["appcode"].as_str()), (Some("FIN"), Some("leadzump")));
    assert_eq!(fake.access_calls.load(Ordering::SeqCst), before);

    // Codes naming another app: served live, not draft.
    let (_, _, b) = call(&app, req("GET", "/api/x", &[("host", host), ("appcode", "other")], "")).await;
    assert!(j(&b)["headers"].get("x-draft").is_none());

    // A denied token, with codes from the URL.
    let host2 = "t-ffffffffffffffffffffffffffffffff.apps.example";
    *fake.draft.lock().unwrap() = json!([false, "0", "", ""]);
    let (_, _, b) = call(&app, req("GET", "/leadzump/FIN/page/api/x", &[("host", host2)], "")).await;
    let hd = &j(&b)["headers"];
    assert!(hd.get("x-draft").is_none());
    assert_eq!(hd["clientcode"], "FIN");

    // Security failing: live, defaults filled.
    *fake.security_down.lock().unwrap() = true;
    let host3 = "t-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.apps.example";
    let (s, _, b) = call(&app, req("GET", "/api/x", &[("host", host3)], "")).await;
    assert_eq!(s, StatusCode::OK);
    let hd = &j(&b)["headers"];
    assert_eq!((hd["clientcode"].as_str(), hd["appcode"].as_str()), (Some("SYSTEM"), Some("nothing")));
}

#[tokio::test]
async fn host_resolution_edge_answers() {
    let (app, fake) = setup().await;
    let (_, _, b) = call(&app, req("GET", "/api/x", &[("host", "empty.example")], "")).await;
    assert_eq!(j(&b)["headers"]["appcode"], "nothing");
    let (_, _, b) = call(&app, req("GET", "/api/x", &[("host", "short.example")], "")).await;
    assert_eq!(j(&b)["headers"]["clientcode"], "SYSTEM");
    fake.hosts.lock().unwrap().insert("d.example".into(), json!(["FIN", "app", "DRAFT"]));
    let (_, _, b) = call(&app, req("GET", "/api/x", &[("host", "d.example")], "")).await;
    assert_eq!(j(&b)["headers"]["x-draft"], "true");

    *fake.security_down.lock().unwrap() = true;
    let (s, _, b) = call(&app, req("GET", "/api/x", &[("host", "new.example")], "")).await;
    assert_eq!(s, StatusCode::BAD_GATEWAY);
    let v = j(&b);
    assert_eq!(v["code"], "GW.HOST_UNRESOLVED");
    assert_eq!(v["message"], "We couldn't tell which app this address belongs to.");
    assert!(v["action"].as_str().unwrap().contains(v["exceptionId"].as_str().unwrap()));
    assert!(v["debugMessage"].as_str().unwrap().starts_with("Unable to resolve the application for the host new.example"));
}

#[tokio::test]
async fn failures_and_retries() {
    let (app, _) = setup().await;
    // No route.
    let (s, _, b) = call(&app, req("GET", "/nowhere", &[("host", "h")], "")).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!((j(&b)["code"].as_str(), j(&b)["message"].as_str()), (Some("GW.NO_ROUTE"), Some("There is nothing at this address.")));
    assert_eq!(j(&b)["debugMessage"], "No route for GET /nowhere");

    // A refused instance is ejected and the GET retried on the next one.
    let (s, _, b) = call(&app, req("GET", "/api/files/static/file/a.png", &[("host", "h")], "")).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(j(&b)["path"], "/api/files/static/file/a.png");

    // Only a dead instance: 503 (no body replay for a POST either).
    let (s, _, b) = call(&app, req("POST", "/api/dead/x", &[("host", "h"), ("content-length", "3")], "abc")).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(j(&b)["code"], "GW.SERVICE_UNAVAILABLE");
    assert_eq!(j(&b)["message"], "The service is not answering right now. Try again in a few seconds.");
    let (s, _, _) = call(&app, req("GET", "/api/dead/x", &[("host", "h")], "")).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);

    // The upstream drops the connection: 502.
    let (s, _, b) = call(&app, req("GET", "/api/closer/x", &[("host", "h")], "")).await;
    assert_eq!(s, StatusCode::BAD_GATEWAY);
    assert_eq!(j(&b)["code"], "GW.SERVICE_FAILED");

    // The route's own timeout: 504.
    let (s, _, b) = call(&app, req("GET", "/api/slow", &[("host", "h")], "")).await;
    assert_eq!(s, StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(j(&b)["code"], "GW.SERVICE_TIMEOUT");
    assert_eq!(j(&b)["message"], "The service took too long to answer.");
}

#[tokio::test]
async fn sse_and_cors_preflight() {
    let (app, _) = setup().await;
    let (s, h, b) = call(&app, req("GET", "/sse", &[("host", "h"), ("accept", "text/event-stream")], "")).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(h["cache-control"], "no-cache, no-store, must-revalidate");
    assert_eq!(h["x-accel-buffering"], "no");
    assert!(h.get("content-length").is_none());
    assert_eq!(&b[..], b"data: one\n\n");

    let (s, h, b) = call(
        &app,
        req("OPTIONS", "/api/x", &[("host", "h"), ("origin", "https://o.example"), ("access-control-request-method", "GET")], ""),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(h.get_all("vary").iter().count(), 3);
    assert!(b.is_empty());
}

#[tokio::test]
async fn bad_config_is_refused() {
    let mut cfg = GatewayConfig::default();
    cfg.security.upstream = UpstreamConfig::One("http://127.0.0.1:1".into());
    cfg.routes = vec![route("x", "/", "missing")];
    assert!(gateway::build(&cfg).await.is_err(), "route naming an unknown pool");

    let mut cfg = GatewayConfig::default();
    cfg.security.upstream = UpstreamConfig::One("http://127.0.0.1:1".into());
    cfg.pools.insert("p".into(), pool(&["http://127.0.0.1:1"], "/h"));
    assert!(gateway::build(&cfg).await.is_err(), "no routes");

    cfg.pools.insert("e".into(), PoolConfig { upstreams: UpstreamConfig::One("lighthouse:X".into()), ..Default::default() });
    cfg.routes = vec![route("x", "/", "p")];
    assert!(gateway::build(&cfg).await.is_err(), "lighthouse pool without lighthouse zones");

    let d = GatewayConfig::default();
    assert_eq!(d.server.port, 8180);
    assert_eq!(d.resolution.draft_trust_seconds, 60);
    assert_eq!(d.proxy.response_timeout_seconds, 3600);
}

#[tokio::test]
async fn the_registry_api_is_not_served() {
    let (app, _fake) = setup().await;
    for path in ["/eureka", "/eureka/apps", "/eureka/apps/GATEWAY", "/eureka/peerreplication/batch"] {
        let (s, _, b) = call(&app, req("GET", path, &[("host", "leadzump.ai")], "")).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(j(&b)["code"], "COMMON.NOT_FOUND", "{path}");
    }
}
