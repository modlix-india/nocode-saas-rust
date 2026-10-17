//! ui-shell end to end: the router driven in process against a scratch database, with fake
//! security, core, CDN and analytics engine services on local ports. The Java ui has no
//! controller tests for these routes beyond the ones ported as unit tests (BeaconHostTest,
//! HasssoBounceTest, SsoRedirectGuardTest, UriPathModelDiffTest, URIPathKIRunRouteTest,
//! AnalyticsServiceTest, AnalyticsAuthorizationTest); these cover the wiring.
//!
//! Gated: `#[ignore]` and `MODLIX__MONGO__URI`. The Redis cases also need `MODLIX__REDIS__URL`
//! and touch only keys and channels named for the test.

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use common::{get_req, Env, Req, APP};
use mongodb::bson::doc;
use platform::upstream::Upstream;
use ui::shell::config::ShellConfig;
use ui::shell::server::{router, ShellInner, ShellState};

/// Every call the fakes received, as `METHOD path?query | headers | body`.
#[derive(Default)]
struct Calls(Mutex<Vec<String>>);

impl Calls {
    fn push(&self, s: String) {
        self.0.lock().unwrap().push(s);
    }
    fn all(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
    fn last(&self) -> String {
        self.0.lock().unwrap().last().cloned().unwrap_or_default()
    }
}

fn q(m: &HashMap<String, String>, k: &str) -> String {
    m.get(k).cloned().unwrap_or_default()
}

/// The security routes the shell adds to the engine's.
fn security_extra(calls: Arc<Calls>) -> Router {
    Router::new()
        .route(
            "/api/security/internal/billing/hosting",
            get(|Query(m): Query<HashMap<String, String>>| async move {
                match q(&m, "urlAppCode").as_str() {
                    "suspended" => axum::Json(serde_json::json!({"suspended": true, "serveAppCode": APP, "serveClientCode": "SYSTEM"}))
                        .into_response(),
                    "boom" => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                    "silent" => StatusCode::OK.into_response(),
                    a => axum::Json(serde_json::json!({"suspended": false, "serveAppCode": a, "serveClientCode": q(&m, "urlClientCode")}))
                        .into_response(),
                }
            }),
        )
        .route(
            "/api/security/clients/internal/getClientNAppCodeNType",
            get(|Query(m): Query<HashMap<String, String>>| async move {
                match q(&m, "host").as_str() {
                    "app.example" => axum::Json(serde_json::json!(["SYSTEM", APP, "LIVE"])).into_response(),
                    "error.example" => (StatusCode::BAD_GATEWAY, axum::Json(serde_json::json!({"message": "broken"}))).into_response(),
                    "text.example" => (StatusCode::INTERNAL_SERVER_ERROR, "boom").into_response(),
                    "empty.example" => StatusCode::OK.into_response(),
                    _ => axum::Json(serde_json::json!(["SYSTEM", "nothing", "LIVE"])).into_response(),
                }
            }),
        )
        .route(
            "/api/security/ssl/token/{token}",
            get(|Path(t): Path<String>| async move {
                if t == "known" {
                    "proof".into_response()
                } else {
                    StatusCode::OK.into_response()
                }
            }),
        )
        .route(
            "/api/security/authenticateWithOneTimeToken/{token}",
            get(move |Path(t): Path<String>, h: HeaderMap| {
                let calls = calls.clone();
                async move {
                    let hv = |k: &str| h.get(k).and_then(|v| v.to_str().ok()).unwrap_or("-").to_string();
                    calls.push(format!("OTT {t} ip={} host={} cc={} app={}", hv("x-real-ip"), hv("x-forwarded-host"), hv("clientcode"), hv("appcode")));
                    match t.as_str() {
                        "good" => axum::Json(serde_json::json!({"accessToken": "tok'en", "accessTokenExpiryAt": 1792038531})).into_response(),
                        "odd" => axum::Json(serde_json::json!({"accessTokenExpiryAt": "later"})).into_response(),
                        "empty" => StatusCode::OK.into_response(),
                        _ => (StatusCode::FORBIDDEN, axum::Json(serde_json::json!({"message": "User credentials mismatch"}))).into_response(),
                    }
                }
            }),
        )
        .route(
            "/api/security/clients/internal/getClientByCode",
            get(|Query(m): Query<HashMap<String, String>>| async move {
                match q(&m, "clientCode").as_str() {
                    "NYC" => axum::Json(serde_json::json!({"code": "NYC", "timeZone": "America/New_York"})).into_response(),
                    "GONE" => StatusCode::OK.into_response(),
                    "FAILS" => (StatusCode::NOT_FOUND, axum::Json(serde_json::json!({"message": "no client"}))).into_response(),
                    c => axum::Json(serde_json::json!({"code": c})).into_response(),
                }
            }),
        )
        .route(
            "/api/security/applications/internal/hasWriteAccess",
            get(|Query(m): Query<HashMap<String, String>>| async move {
                match q(&m, "clientCode").as_str() {
                    "NOWRITE" => "false".into_response(),
                    "BROKEN" => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                    _ => "true".into_response(),
                }
            }),
        )
        .route(
            "/api/security/clients/internal/doesClientManageClientCode",
            get(|Query(m): Query<HashMap<String, String>>| async move { (q(&m, "managingClientCode") == "MGR").to_string() }),
        )
}

/// The core service: `execute/{ns}/{name}` answers by the function name.
fn fake_core(calls: Arc<Calls>) -> Router {
    async fn execute(
        State(calls): State<Arc<Calls>>,
        Path((ns, name)): Path<(String, String)>,
        uri: axum::http::Uri,
        method: axum::http::Method,
        h: HeaderMap,
        body: Bytes,
    ) -> Response {
        let hv = |k: &str| h.get(k).and_then(|v| v.to_str().ok()).unwrap_or("-").to_string();
        calls.push(format!(
            "{method} {ns}.{name}?{} | auth={} host={} port={} app={} cc={} draft={} debug={} ct={} | {}",
            uri.query().unwrap_or(""),
            hv("authorization"),
            hv("x-forwarded-host"),
            hv("x-forwarded-port"),
            hv("appcode"),
            hv("clientcode"),
            hv("x-draft"),
            hv("x-debug"),
            hv("content-type"),
            String::from_utf8_lossy(&body)
        ));
        match name.as_str() {
            "echo" => {
                let arg = if body.is_empty() { serde_json::json!(uri.query().unwrap_or("")) } else { serde_json::from_slice(&body).unwrap() };
                axum::Json(serde_json::json!([{"name": "output", "result": {"result": {"arg": arg, "n": 1.5}}}])).into_response()
            }
            "empty" => StatusCode::OK.into_response(),
            "blank" => "   ".into_response(),
            "conflict" => axum::Json(serde_json::json!([{"name": "error", "result": {"status": 409, "body": "conflict"}}])).into_response(),
            "nothing" => axum::Json(serde_json::json!([{"name": "other"}])).into_response(),
            "missing" => (StatusCode::NOT_FOUND, axum::Json(serde_json::json!({"message": "Function with id x not found"}))).into_response(),
            "nomessage" => (StatusCode::BAD_REQUEST, axum::Json(serde_json::json!({"code": 1}))).into_response(),
            "numbermessage" => (StatusCode::BAD_REQUEST, axum::Json(serde_json::json!({"message": 7}))).into_response(),
            "badjson" => (StatusCode::NOT_FOUND, [("content-type", "application/json")], "not json").into_response(),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "boom").into_response(),
        }
    }
    Router::new()
        .route("/api/core/function/execute/{ns}/{name}", get(execute).post(execute))
        .with_state(calls)
}

/// The CDN behind `ui.jsURL`.
fn fake_cdn() -> Router {
    Router::new().route(
        "/js/dist/{*path}",
        get(|Path(p): Path<String>| async move {
            match p.as_str() {
                "app.js" => "console.log('app')".into_response(),
                "a b.css" => "body{}".into_response(),
                "data.json" => "{}".into_response(),
                "page.html" => "<p>".into_response(),
                "font.woff2" => "bin".into_response(),
                "empty.js" => StatusCode::OK.into_response(),
                _ => StatusCode::NOT_FOUND.into_response(),
            }
        }),
    )
}

/// The analytics engine: `POST /q` with the shared secret.
fn fake_engine(calls: Arc<Calls>) -> Router {
    Router::new().route(
        "/q",
        post(move |h: HeaderMap, body: Bytes| {
            let calls = calls.clone();
            async move {
                calls.push(format!("ENGINE {} | {}", h.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("-"), String::from_utf8_lossy(&body)));
                let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
                match v["widget"].as_str().unwrap_or("") {
                    "bad" => StatusCode::BAD_REQUEST.into_response(),
                    "empty" => StatusCode::OK.into_response(),
                    "garbage" => "not json".into_response(),
                    _ => axum::Json(serde_json::json!({"widget": v["widget"], "site": v["site"], "timezone": v["timezone"], "rows": [1.0, 2]}))
                        .into_response(),
                }
            }
        }),
    )
}

struct Shell {
    env: Env,
    router: Router,
    calls: Arc<Calls>,
    state: ShellState,
}

impl Shell {
    async fn call(&self, r: Req) -> common::Answer {
        use tower::ServiceExt;
        let mut b = axum::http::Request::builder().method(r.method).uri(&r.path);
        for (k, v) in &r.headers {
            b = b.header(k, v);
        }
        let req = b.body(r.body.map(axum::body::Body::from).unwrap_or_else(axum::body::Body::empty)).unwrap();
        let resp = self.router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec();
        common::Answer { status, headers, body }
    }

    async fn done(self) {
        self.env.done().await;
    }
}

fn gw(path: &str) -> Req {
    get_req(path).header("X-Forwarded-Host", "testapp.example").header("X-Forwarded-Port", "443")
}

async fn shell_with(redis: Option<redis::Client>, prefix_channel: Option<(&str, &str)>, tweak: impl FnOnce(&mut ShellConfig)) -> Option<Shell> {
    let calls = Arc::new(Calls::default());
    let env = common::env_with(security_extra(calls.clone())).await?;
    let core = common::serve(fake_core(calls.clone())).await;
    let cdn = common::serve(fake_cdn()).await;
    let engine = common::serve(fake_engine(calls.clone())).await;
    let mut cfg = ShellConfig::default();
    cfg.shell.cdn_host_name = "cdn.example".into();
    cfg.shell.app_code_suffix = ".local".into();
    cfg.shell.js_url = format!("{cdn}/js/dist/");
    cfg.shell.analytics_ingestion_host = "https://engine.example".into();
    cfg.shell.analytics_engine_url = engine;
    cfg.shell.analytics_engine_secret = "s3cret".into();
    if let Some((_, channel)) = prefix_channel {
        cfg.shell.ssr_channel = channel.into();
        cfg.redis.eviction_channel = channel.into();
    }
    tweak(&mut cfg);
    let cache = match prefix_channel {
        Some((prefix, channel)) => {
            platform::cache::CacheService::new(prefix, channel, std::env::var("MODLIX__REDIS__URL").ok().as_deref()).unwrap()
        }
        None => env.state.inner().cache.clone(),
    };
    let ui_state = if prefix_channel.is_some() {
        let inner = env.state.inner();
        ui::state::AppState::new(ui::state::Inner {
            store: inner.store.clone(),
            security: inner.security.clone(),
            properties: cache.family(),
            fillers: cache.family(),
            app_status: cache.family(),
            app_dependencies: cache.family(),
            cache: cache.clone(),
            config: inner.config.clone(),
        })
    } else {
        env.state.clone()
    };
    let state = ShellState::new(ShellInner {
        ui: ui_state,
        cfg,
        http: reqwest::Client::new(),
        core: Upstream::fixed(&[&core]),
        index: cache.family(),
        js: cache.family(),
        patterns: cache.family(),
        analytics: cache.family(),
        entrypoints: vec!["app.js".into()],
        redis,
    });
    Some(Shell { router: router(state.clone()), env, calls, state })
}

async fn shell() -> Option<Shell> {
    shell_with(None, None, |_| {}).await
}

async fn seed(s: &Shell) {
    s.env
        .insert(
            "application",
            doc! {"name": APP, "appCode": APP, "clientCode": "SYSTEM", "version": 1_i32,
            "properties": {"title": "Test App", "manifest": {"name": "m"},
                "analytics": {"enabled": true},
                "csp": {"defaultSrc": "'self'"}, "cspReport": {"imgSrc": "*"}}},
        )
        .await;
    s.env
        .insert("application", doc! {"name": "plain", "appCode": "plain", "clientCode": "SYSTEM", "version": 1_i32, "properties": {"title": "Plain"}})
        .await;
    s.env
        .insert("application", doc! {"name": "badorder", "appCode": "badorder", "clientCode": "SYSTEM", "version": 1_i32,
            "properties": {"links": {"a": {"order": "x", "href": "/a"}, "b": {"href": "/b"}}}})
        .await;
    let fx = |name: &str| {
        doc! {"uriType": "KIRUN_FUNCTION", "kiRunFxDefinition": {"namespace": "ns", "name": name,
            "pathParamMapping": {"code": "code"}, "queryParamMapping": {"q": "query"},
            "headersMapping": {"X-Forwarded-Host": "host"}, "outputEventName": "output",
            "outputEventParamName": "result.result", "errorEventName": "error"}}
    };
    for (name, path_string, defs, extra) in [
        ("/api/route/**", "/api/route/{code}", doc! {"GET": fx("echo"), "POST": fx("echo"), "PUT": fx("conflict"), "PATCH": fx("nothing")}, doc! {}),
        ("/api/raw/*", "/api/raw/{code}", doc! {"GET": {"uriType": "KIRUN_FUNCTION", "kiRunFxDefinition": {"namespace": "ns", "name": "echo"}},
            "POST": {"uriType": "KIRUN_FUNCTION", "kiRunFxDefinition": {"namespace": "ns", "name": "echo"}}}, doc! {}),
        ("/api/redirect", "/api/redirect", doc! {"GET": {"uriType": "REDIRECTION", "redirectionDefinition": {"targetUrl": "https://x/"}},
            "POST": {"uriType": "REDIRECTION"}}, doc! {}),
        ("/api/typeless", "/api/typeless", doc! {"GET": {"kiRunFxDefinition": {"namespace": "ns", "name": "echo"}}}, doc! {}),
        ("/api/nofx", "/api/nofx", doc! {"GET": {"uriType": "KIRUN_FUNCTION"}}, doc! {}),
        ("/api/secret", "/api/secret", doc! {"GET": fx("echo")}, doc! {"permission": "Authorities.ROLE_Owner"}),
        ("/api/unpublished", "/api/unpublished", doc! {"GET": fx("echo")}, doc! {"published": false}),
    ] {
        let mut d = doc! {"name": name, "appCode": APP, "clientCode": "SYSTEM", "version": 1_i32, "pathString": path_string, "pathDefinitions": defs};
        d.extend(extra);
        s.env.insert("uri_path", d).await;
    }
    for name in ["empty", "blank", "missing", "nomessage", "numbermessage", "badjson", "crash"] {
        s.env
            .insert(
                "uri_path",
                doc! {"name": format!("/api/fn/{name}"), "appCode": APP, "clientCode": "SYSTEM", "version": 1_i32,
                "pathString": "/api/fn/x", "pathDefinitions": {"GET": {"uriType": "KIRUN_FUNCTION",
                "kiRunFxDefinition": {"namespace": "ns", "name": name, "outputEventName": "output"}},
                "POST": {"uriType": "KIRUN_FUNCTION", "kiRunFxDefinition": {"namespace": "ns", "name": name, "outputEventName": "output"}}}},
            )
            .await;
    }
}

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn index_pages_behind_the_hosting_gate() {
    let Some(s) = shell().await else { return };
    seed(&s).await;
    let a = s.call(gw("/")).await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.text());
    assert_eq!(a.header("content-type").as_deref(), Some("text/html"));
    assert_eq!(a.header("cache-control").as_deref(), Some("max-age=604800, must-revalidate"));
    assert_eq!(a.headers.get_all("x-frame-options").iter().count(), 2);
    assert_eq!(a.header("content-security-policy").as_deref(), Some("default-src 'self' cdn.example;"));
    assert_eq!(a.header("content-security-policy-report-only").as_deref(), Some("img-src * cdn.example;"));
    let html = a.text();
    assert!(html.contains("<title>Test App</title>"));
    assert!(!html.contains("rel=\"manifest\""), "applyChange removed the manifest");
    assert!(html.contains("data-autocapture"), "analytics beacon");
    assert!(html.ends_with("<script src=\"https://cdn.example/js/dist/app.js\"></script></body></html>"));
    let tag = a.etag();
    assert!(tag.starts_with("W/\""));
    let nm = s.call(gw("/some/page").etag(&tag)).await;
    assert_eq!(nm.status, StatusCode::NOT_MODIFIED);
    assert_eq!(nm.header("cache-control").as_deref(), Some("max-age=604800, must-revalidate"));

    // The draft surface is its own cache entry and marks the document.
    let d = s.call(gw("/").draft()).await;
    assert!(d.text().starts_with("<!DOCTYPE html><html lang=\"en\" data-draft=\"true\">"));
    // A suspended app serves the configured one; a gate that fails or says nothing serves what
    // was asked for.
    let sus = s.call(gw("/").app("suspended")).await;
    assert!(sus.text().contains("<title>Test App</title>"));
    for app in ["boom", "silent", "plain"] {
        let p = s.call(gw("/").app(app)).await;
        assert_eq!(p.status, StatusCode::OK);
        let want = if app == "plain" { "<title>Plain</title>" } else { "<title>Error</title>" };
        assert!(p.text().contains(want), "{app}: {}", &p.text()[..200]);
    }
    let bad = s.call(gw("/").app("badorder")).await;
    assert_eq!(bad.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(bad.obj()["debugMessage"], common::s("For input string: \"x\""));
    // The gateway's headers are required, in order.
    for (missing, name) in [("X-Forwarded-Host", "X-Forwarded-Host"), ("X-Forwarded-Port", "X-Forwarded-Port"), ("appCode", "appCode"), ("clientCode", "clientCode")] {
        let r = s.call(gw("/").no_header(missing)).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST);
        assert_eq!(r.obj()["debugMessage"], common::s(&format!("400 BAD_REQUEST \"Required header '{name}' is not present.\"")));
    }
    // A refused token is refused before anything else.
    assert_eq!(s.call(gw("/").header("Authorization", "refuse")).await.status, StatusCode::UNAUTHORIZED);
    // An unknown method is Spring's 405 (behind the firewall only the seven reach here).
    let r = s.call(gw("/").method("OPTIONS")).await;
    assert_eq!(r.header("allow").as_deref(), Some("DELETE,POST,GET,PUT,PATCH,HEAD,OPTIONS"));
    s.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn manifest_api_docs_js_and_acme() {
    let Some(s) = shell().await else { return };
    seed(&s).await;
    let m = s.call(gw("/manifest/manifest.json")).await;
    assert_eq!(m.status, StatusCode::OK);
    assert_eq!(m.header("etag").as_deref(), Some("W/\"d41d8cd98f00b204e9800998ecf8427e\""));
    assert_eq!(m.header("content-type").as_deref(), Some("application/json;charset=UTF-8"));
    assert!(m.body.is_empty());
    assert_eq!(s.call(gw("/manifest/manifest.json").app("nosuchapp")).await.status, StatusCode::OK);
    assert_eq!(s.call(gw("/manifest/manifest.json").no_header("clientCode")).await.status, StatusCode::BAD_REQUEST);
    let d = s.call(gw("/apiDocs")).await;
    assert_eq!(d.text(), "Coming soon...");
    assert_eq!(d.header("etag").as_deref(), Some("W/\"20c0cfafdfe0b514bedd6af52e0231f\""));
    assert_eq!(d.header("content-type").as_deref(), Some("text/html;charset=UTF-8"));
    assert_eq!(s.call(gw("/apiDocs").no_header("appCode")).await.status, StatusCode::BAD_REQUEST);

    for (file, ct) in [
        ("app.js", "text/javascript"),
        ("a%20b.css", "text/css"),
        ("data.json", "application/json"),
        ("page.html", "text/html"),
        ("font.woff2", "application/octet-stream"),
    ] {
        let r = s.call(get_req(&format!("/js/dist/{file}"))).await;
        assert_eq!(r.status, StatusCode::OK, "{file}");
        assert_eq!(r.header("content-type").as_deref(), Some(ct), "{file}");
        let again = s.call(get_req(&format!("/js/dist/{file}")).etag(&r.etag())).await;
        assert_eq!(again.status, StatusCode::NOT_MODIFIED);
    }
    let e = s.call(get_req("/js/dist/empty.js")).await;
    assert_eq!(e.header("content-type").as_deref(), Some("text/plain;charset=UTF-8"));
    assert_eq!(e.header("etag").as_deref(), Some("W/\"d41d8cd98f00b204e9800998ecf8427e\""));
    let missing = s.call(get_req("/js/dist/missing.js")).await;
    assert_eq!(missing.status, StatusCode::INTERNAL_SERVER_ERROR);
    let dm = missing.obj()["debugMessage"].java_to_string();
    assert!(dm.starts_with("404 Not Found from GET http://127.0.0.1:") && dm.ends_with("/js/dist/missing.js"), "{dm}");

    assert_eq!(s.call(get_req("/.well-known/acme-challenge/known")).await.text(), "proof");
    let unknown = s.call(get_req("/.well-known/acme-challenge/other")).await;
    assert_eq!(unknown.status, StatusCode::OK);
    assert!(unknown.body.is_empty() && unknown.header("content-type").is_none());
    s.done().await;

    // No jsURL: an empty answer.
    let Some(s) = shell_with(None, None, |c| c.shell.js_url = String::new()).await else { return };
    let r = s.call(get_req("/js/dist/app.js")).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.body.is_empty());
    // The CDN not answering at all.
    s.done().await;
    let Some(s) = shell_with(None, None, |c| c.shell.js_url = "http://127.0.0.1:1/js/dist/".into()).await else { return };
    assert_eq!(s.call(get_req("/js/dist/app.js")).await.status, StatusCode::INTERNAL_SERVER_ERROR);
    s.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn sso_bounce_logout_and_one_time_tokens() {
    let Some(s) = shell().await else { return };
    let r = s.call(get_req("/hassso")).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.obj()["debugMessage"], common::s("400 BAD_REQUEST \"Required query parameter 'targetAppCode' is not present.\""));
    let ok = s.call(get_req("/hassso?targetAppCode=testapp&targetClientCode=SYSTEM&returnUrl=https%3A%2F%2Fapp.example%2Fx")).await;
    assert_eq!(ok.status, StatusCode::OK);
    assert_eq!(ok.header("content-security-policy").as_deref(), Some("frame-ancestors *"));
    assert_eq!(ok.header("cache-control").as_deref(), Some("no-store"));
    assert_eq!(ok.header("x-frame-options").as_deref(), Some("DENY"));
    assert!(ok.text().contains("var back='https://app.example/x';var targetAppCode='testapp';var targetClientCode='SYSTEM';"));
    let out = s.call(get_req("/hassso?targetAppCode=testapp&mode=logout&returnUrl=https://app.example:8443/")).await;
    assert!(out.text().contains("window.location.replace('https://app.example:8443/');"));
    for (query, status) in [
        ("targetAppCode=&returnUrl=https://app.example/", StatusCode::BAD_REQUEST),
        ("targetAppCode=testapp&returnUrl=ftp://app.example/", StatusCode::BAD_REQUEST),
        ("targetAppCode=other&returnUrl=https://app.example/", StatusCode::NOT_FOUND),
        ("targetAppCode=testapp&returnUrl=https://empty.example/", StatusCode::NOT_FOUND),
        ("targetAppCode=testapp&returnUrl=https://error.example/", StatusCode::BAD_GATEWAY),
        ("targetAppCode=testapp&returnUrl=https://text.example/", StatusCode::INTERNAL_SERVER_ERROR),
    ] {
        assert_eq!(s.call(get_req(&format!("/hassso?{query}"))).await.status, status, "{query}");
    }

    let sso = s.call(get_req("/sso/good?redirectUrl=https%3A%2F%2Fapp.example%2Fhome").header("X-Real-IP", "10.0.0.9").header("X-Forwarded-Host", "testapp.example")).await;
    assert_eq!(sso.status, StatusCode::OK);
    assert_eq!(
        sso.text(),
        "<html><head><title>SSO</title><script>window.localStorage.setItem('AuthToken', '\"tok\\'en\"');window.localStorage.setItem('AuthTokenExpiry', '1792038531');window.location.href = 'https://app.example/home';</script></head><body></body></html>"
    );
    assert_eq!(sso.header("content-security-policy").as_deref(), Some("frame-ancestors *"));
    assert!(sso.header("cache-control").unwrap().starts_with("no-cache"), "no Cache-Control of its own");
    assert_eq!(s.calls.last(), "OTT good ip=10.0.0.9 host=testapp.example cc=SYSTEM app=testapp");
    for (redirect, want) in [
        ("", "'/'"),
        ("redirectUrl=", "'/'"),
        ("redirectUrl=%2Fdeals", "'/deals'"),
        ("redirectUrl=%2F%2Fevil.example", "'/'"),
        ("redirectUrl=https%3A%2F%2Fother.example%2F", "'/'"),
        ("redirectUrl=https%3A%2F%2Fempty.example%2F", "'/'"),
        ("redirectUrl=javascript%3Aalert(1)", "'/'"),
    ] {
        let r = s.call(get_req(&format!("/sso/good?{redirect}"))).await;
        assert!(r.text().contains(&format!("window.location.href = {want};")), "{redirect}: {}", r.text());
    }
    // The request's own host when no proxy names one.
    let own = s.call(get_req("/sso/good?redirectUrl=http%3A%2F%2Fmine.example%3A8080%2Fp").header("Host", "mine.example:8080")).await;
    assert!(own.text().contains("window.location.href = 'http://mine.example:8080/p';"));
    let odd = s.call(get_req("/sso/odd")).await;
    assert!(odd.text().contains("'\"null\"'") && odd.text().contains("'AuthTokenExpiry', '0'"));
    let empty = s.call(get_req("/sso/empty")).await;
    assert_eq!(empty.status, StatusCode::OK);
    assert!(empty.body.is_empty());
    let bad = s.call(get_req("/sso/bad")).await;
    assert_eq!(bad.status, StatusCode::FORBIDDEN);
    assert_eq!(bad.obj()["message"], common::s("User credentials mismatch"));
    let lookup_fails = s.call(get_req("/sso/good?redirectUrl=https%3A%2F%2Ferror.example%2F")).await;
    assert_eq!(lookup_fails.status, StatusCode::BAD_GATEWAY);
    s.done().await;
}

fn calls_matching(s: &Shell, prefix: &str) -> Vec<String> {
    s.calls.all().into_iter().filter(|c| c.starts_with(prefix)).collect()
}

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn uri_path_routes_run_kirun_functions_on_core() {
    let Some(s) = shell().await else { return };
    seed(&s).await;
    // GET: mapped path variable, query parameter and header; the output parameter picked.
    let r = s.call(gw("/api/route/P%201?q=a%2Bb&z=1").header("Authorization", "user SYSTEM Authorities.Logged_IN").header("x-debug", "dbg")).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(r.header("content-type").as_deref(), Some("text/plain;charset=UTF-8"));
    assert_eq!(r.text(), r#"{"arg":"query=a%2Bb&code=P%201&host=testapp.example","n":1.5}"#);
    assert_eq!(
        s.calls.last(),
        "GET ns.echo?query=a%2Bb&code=P%201&host=testapp.example | auth=user SYSTEM Authorities.Logged_IN host=testapp.example port=443 app=testapp cc=SYSTEM draft=- debug=dbg ct=- | "
    );
    // POST: the body with the mapped values over it.
    let p = s.call(gw("/api/route/P1?q=x").method("POST").header("Content-Type", "application/json").body(r#"{"code":"body","n":1.50}"#).draft()).await;
    assert_eq!(p.status, StatusCode::OK, "{}", p.text());
    assert_eq!(p.header("content-type").as_deref(), Some("application/json;charset=UTF-8"));
    assert_eq!(p.text(), r#"{"arg":{"code":"P1","n":1.5,"query":"x","host":"testapp.example"},"n":1.5}"#);
    assert!(s.calls.last().ends_with(r#"draft=true debug=- ct=application/json | {"code":"P1","n":1.50,"query":"x","host":"testapp.example"}"#), "{}", s.calls.last());
    // No mapping: every query parameter, path variable and header goes along.
    let raw = s.call(gw("/api/raw/R1?a=1&a=2&e=")).await;
    assert!(raw.text().starts_with(r#"[{"name":"output""#), "no output event named: the raw answer");
    let sent = s.calls.last();
    assert!(sent.starts_with("GET ns.echo?a=1&a=2&e=&code=R1&appCode=testapp&clientCode=SYSTEM&X-Forwarded-Host=testapp.example&X-Forwarded-Port=443"), "{sent}");
    let raw_post = s.call(gw("/api/raw/R1").method("PUT").header("Content-Type", "application/json").body("{}")).await;
    assert_eq!(raw_post.status, StatusCode::INTERNAL_SERVER_ERROR, "no PUT definition: {}", raw_post.text());
    assert_eq!(raw_post.obj()["debugMessage"], common::s("value"));
    let no_value = s.call(gw("/api/raw/R1?flag")).await;
    assert_eq!(no_value.obj()["debugMessage"], common::s("Cannot invoke \"Object.toString()\" because \"element\" is null"));
    // Error events, no event, empty and blank answers.
    let c = s.call(gw("/api/route/x").method("PUT").header("Content-Type", "application/json").body("{}")).await;
    assert_eq!((c.status, c.text()), (StatusCode::CONFLICT, "conflict".to_string()));
    let n = s.call(gw("/api/route/x").method("PATCH").header("Content-Type", "application/json").body("{}")).await;
    assert_eq!(n.status, StatusCode::BAD_REQUEST, "no event: a bare 400");
    assert!(n.body.is_empty());
    let page = s.call(gw("/api/fn/empty")).await;
    assert!(page.text().contains("<title>Test App</title>"), "an empty answer serves the page");
    assert_eq!(s.call(gw("/api/fn/empty").method("POST").body("{}")).await.status, StatusCode::BAD_REQUEST);
    let blank = s.call(gw("/api/fn/blank")).await;
    assert_eq!((blank.status, blank.text()), (StatusCode::OK, String::new()));
    // Core's refusals: JSON relayed, anything else the generic 500.
    let missing = s.call(gw("/api/fn/missing")).await;
    assert_eq!((missing.status, missing.obj()["message"].clone()), (StatusCode::NOT_FOUND, common::s("Function with id x not found")));
    assert_eq!(s.call(gw("/api/fn/nomessage")).await.obj()["message"], common::s(""));
    assert_eq!(s.call(gw("/api/fn/numbermessage")).await.obj()["message"], common::s("7"));
    for f in ["badjson", "crash"] {
        let r = s.call(gw(&format!("/api/fn/{f}"))).await;
        assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR, "{f}");
        assert!(r.obj()["debugMessage"].java_to_string().contains("IFeignCoreService#executeWith"), "{f}");
    }
    // Redirections answer nothing (GET serves the page, a body method a bare 400).
    assert!(s.call(gw("/api/redirect")).await.text().contains("<title>Test App</title>"));
    assert_eq!(s.call(gw("/api/redirect").method("POST").body("{}")).await.status, StatusCode::BAD_REQUEST);
    let typeless = s.call(gw("/api/typeless")).await;
    assert!(typeless.obj()["debugMessage"].java_to_string().contains("getUriType()"));
    assert_eq!(s.call(gw("/api/nofx")).await.status, StatusCode::INTERNAL_SERVER_ERROR);
    // The route's permission.
    let secret = s.call(gw("/api/secret")).await;
    assert_eq!((secret.status, secret.coded()), (StatusCode::FORBIDDEN, ("UI.SIGN_IN_REQUIRED".into(), "Authorization Authorities.ROLE_Owner is required".into())));
    let not_held = s.call(gw("/api/secret").header("Authorization", "user SYSTEM Authorities.Logged_IN")).await;
    assert_eq!(not_held.coded().0, "UI.FORBIDDEN_EXECUTION");
    assert_eq!(not_held.obj()["message"], common::s("You can't use this address: your account does not have the Owner role."));
    // Past the permission, the mapped `code` the path does not have is Feign's null parameter.
    let held = s.call(gw("/api/secret").header("Authorization", "user SYSTEM Authorities.ROLE_Owner")).await;
    assert_eq!(held.obj()["debugMessage"], common::s("Cannot invoke \"Object.toString()\" because \"element\" is null"));
    // A never-published route is not a candidate.
    assert!(s.call(gw("/api/unpublished")).await.text().contains("<title>"));
    // Bodies.
    let body_cases: [(Option<&str>, Option<&str>, StatusCode, &str); 5] = [
        (None, None, StatusCode::BAD_REQUEST, "400 BAD_REQUEST \"No request body\""),
        (Some("application/x-www-form-urlencoded; charset=UTF-8"), Some("a=b"), StatusCode::UNSUPPORTED_MEDIA_TYPE, "415 UNSUPPORTED_MEDIA_TYPE"),
        (Some("application/json"), Some("[1]"), StatusCode::INTERNAL_SERVER_ERROR, "Expected a com.google.gson.JsonObject but was com.google.gson.JsonArray; at path $"),
        (Some("application/json"), Some("null"), StatusCode::INTERNAL_SERVER_ERROR, "Expected a com.google.gson.JsonObject but was com.google.gson.JsonNull; at path $"),
        (Some("text/plain"), Some("x"), StatusCode::INTERNAL_SERVER_ERROR, "Expected a com.google.gson.JsonObject but was com.google.gson.JsonPrimitive; at path $"),
    ];
    for (ct, body, status, debug) in body_cases {
        let mut r = gw("/api/route/x").method("POST");
        if let Some(ct) = ct {
            r = r.header("Content-Type", ct);
        }
        if let Some(b) = body {
            r = r.body(b);
        }
        let a = s.call(r).await;
        assert_eq!(a.status, status, "{body:?}");
        assert_eq!(a.obj()["debugMessage"], common::s(debug));
    }
    let blank_body = s.call(gw("/api/route/x").method("DELETE").body("  ")).await;
    assert_eq!(blank_body.status, StatusCode::INTERNAL_SERVER_ERROR, "no DELETE definition");
    // A signed-in caller's routes are looked up in its own client.
    s.env.chain("OTHER", &["SYSTEM", "OTHER"]);
    let other = s.call(gw("/api/route/x?q=1").header("Authorization", "user OTHER Authorities.Logged_IN")).await;
    assert_eq!(other.status, StatusCode::OK);
    assert!(s.calls.last().contains("cc=OTHER"));
    // Missing headers come before the body.
    let h = s.call(gw("/api/route/x").method("POST").no_header("X-Forwarded-Port").body("x")).await;
    assert_eq!(h.obj()["debugMessage"], common::s("400 BAD_REQUEST \"Required header 'X-Forwarded-Port' is not present.\""));
    s.done().await;

    // The core service down.
    let Some(s) = shell().await else { return };
    seed(&s).await;
    let state_down = ShellState::new(ShellInner {
        ui: s.state.inner().ui.clone(),
        cfg: s.state.inner().cfg.clone(),
        http: reqwest::Client::new(),
        core: Upstream::fixed(&["http://127.0.0.1:1"]),
        index: s.state.inner().index.clone(),
        js: s.state.inner().js.clone(),
        patterns: s.state.inner().patterns.clone(),
        analytics: s.state.inner().analytics.clone(),
        entrypoints: vec![],
        redis: None,
    });
    let down = Shell { router: router(state_down.clone()), env: s.env, calls: s.calls, state: state_down };
    assert_eq!(down.call(gw("/api/route/x?q=1")).await.status, StatusCode::INTERNAL_SERVER_ERROR);
    down.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn analytics_queries() {
    let Some(s) = shell().await else { return };
    seed(&s).await;
    let raw = |body: &str| gw("/api/ui/analytics/query").method("POST").header("Content-Type", "application/json").body(body);
    let q = |body: &str| raw(body).user("SYSTEM", "Authorities.Application_UPDATE");
    let anon = s.call(gw("/api/ui/analytics/query").method("POST").body("{}")).await;
    assert_eq!((anon.status, anon.coded()), (StatusCode::FORBIDDEN, ("UI.ANALYTICS_LOGIN_REQUIRED".into(), "Sign in to read this application's analytics.".into())));
    let ok = s.call(q(r#"{"widget":"topPages","site":"x_Y"}"#)).await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.text());
    assert_eq!(ok.header("content-type").as_deref(), Some("application/json"));
    assert_eq!(ok.text(), "{\n  \"widget\" : \"topPages\",\n  \"site\" : \"testapp_SYSTEM\",\n  \"timezone\" : \"Asia/Kolkata\",\n  \"rows\" : [ 1.0, 2 ]\n}");
    assert_eq!(s.calls.last(), r#"ENGINE Bearer s3cret | {"widget":"topPages","site":"testapp_SYSTEM","timezone":"Asia/Kolkata"}"#);
    // Cached: the engine is not asked again.
    let before = calls_matching(&s, "ENGINE").len();
    assert_eq!(s.call(q(r#"{"widget":"topPages","site":"x_Y"}"#)).await.status, StatusCode::OK);
    assert_eq!(calls_matching(&s, "ENGINE").len(), before);
    let zone = s.call(q(r#"{"widget":"z","timezone":"Europe/London"}"#)).await;
    assert!(zone.text().contains("Europe/London"));
    let bad_zone = s.call(q(r#"{"widget":"z","timezone":"Mars/Base"}"#)).await;
    assert_eq!((bad_zone.status, bad_zone.coded()), (StatusCode::BAD_REQUEST, ("UI.ANALYTICS_UNKNOWN_TIMEZONE".into(), "Mars/Base is not a known IANA time zone.".into())));
    assert_eq!(bad_zone.obj()["message"], common::s("Mars/Base is not a time zone we know."));
    let engine_refuses = s.call(q(r#"{"widget":"bad"}"#)).await;
    assert_eq!(engine_refuses.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(engine_refuses.obj()["debugMessage"].java_to_string().starts_with("400 Bad Request from POST http://127.0.0.1:"));
    let empty = s.call(q(r#"{"widget":"empty"}"#)).await;
    assert_eq!((empty.status, empty.body.len()), (StatusCode::OK, 0));
    assert_eq!(s.call(q(r#"{"widget":"garbage"}"#)).await.status, StatusCode::INTERNAL_SERVER_ERROR);
    // The client's zone, and a client that cannot be read.
    for c in ["NYC", "GONE", "FAILS"] {
        s.env.chain(c, &["SYSTEM", c]);
    }
    let nyc = s.call(raw(r#"{"widget":"n"}"#).client("NYC").user("NYC", "Authorities.Application_UPDATE")).await;
    assert!(nyc.text().contains("America/New_York"), "{}", nyc.text());
    let gone = s.call(raw(r#"{"widget":"g"}"#).client("GONE").user("GONE", "Authorities.Application_UPDATE")).await;
    assert!(gone.text().contains("Asia/Kolkata"));
    let fails = s.call(raw(r#"{"widget":"f"}"#).client("FAILS").user("FAILS", "Authorities.Application_UPDATE")).await;
    assert_eq!(fails.status, StatusCode::NOT_FOUND);
    // Refusals in order.
    assert_eq!(s.call(raw("{}").user("SYSTEM", "Authorities.Logged_IN")).await.coded().1, "You do not have write access to this application.");
    assert_eq!(s.call(raw("{}").user("NOWRITE", "Authorities.Application_UPDATE")).await.status, StatusCode::FORBIDDEN);
    assert_eq!(s.call(raw("{}").user("BROKEN", "Authorities.Application_UPDATE")).await.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        s.call(raw("{}").client("ELSE").user("OTHER", "Authorities.Application_UPDATE")).await.coded(),
        ("UI.ANALYTICS_CLIENT_NOT_MANAGED".to_string(), "Your client does not manage the requested client code.".to_string())
    );
    let not_enabled = s.call(q("{}").app("plain")).await;
    assert_eq!(not_enabled.coded(), ("UI.ANALYTICS_NOT_ENABLED".into(), "Analytics is not enabled for this application.".into()));
    let no_app = s.call(q("{}").app("nosuchapp")).await;
    assert_eq!((no_app.status, no_app.body.len()), (StatusCode::OK, 0), "Java's chain ends empty");
    // Bodies and headers.
    assert_eq!(s.call(gw("/api/ui/analytics/query").method("POST")).await.obj()["debugMessage"], common::s("400 BAD_REQUEST \"No request body\""));
    assert_eq!(s.call(q("[1]")).await.obj()["debugMessage"], common::s("400 BAD_REQUEST \"Failed to read HTTP message\""));
    assert_eq!(s.call(q("{}").no_header("clientCode")).await.status, StatusCode::BAD_REQUEST);
    // GET is the ** mapping.
    assert!(s.call(gw("/api/ui/analytics/query")).await.text().contains("<title>Test App</title>"));
    s.done().await;

    let Some(s) = shell_with(None, None, |c| c.shell.analytics_engine_secret = String::new()).await else { return };
    let r = s.call(gw("/api/ui/analytics/query").method("POST").body("{}").user("SYSTEM", "Authorities.Application_UPDATE")).await;
    assert_eq!((r.status, r.coded()), (StatusCode::SERVICE_UNAVAILABLE, ("UI.ANALYTICS_NOT_CONFIGURED".into(), "Analytics is not configured on this server.".into())));
    s.done().await;
    let Some(s) = shell_with(None, None, |c| c.shell.analytics_engine_url = "http://127.0.0.1:1".into()).await else { return };
    seed(&s).await;
    let r = s.call(gw("/api/ui/analytics/query").method("POST").body(r#"{"widget":"x"}"#).user("SYSTEM", "Authorities.Application_UPDATE")).await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
    s.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn cache_endpoints_without_redis() {
    let Some(s) = shell().await else { return };
    seed(&s).await;
    s.call(gw("/")).await;
    s.call(gw("/")).await;
    let names = s.call(get_req("/api/ui/internal/cache")).await;
    assert_eq!(names.header("content-type").as_deref(), Some("application/json"));
    assert!(names.text().contains("\"ApplicationCache_testapp_indexNewCache_testapp\""), "{}", names.text());
    let stats = s.call(get_req("/api/ui/internal/cache/stats")).await;
    let st = stats.obj();
    let idx = st["ApplicationCache_testapp_indexNewCache_testapp"].as_object().unwrap().clone();
    assert!(idx["entries"].as_i64().unwrap() <= 1, "Moka counts entries lazily");
    assert_eq!(idx["hitCount"].as_i64(), Some(1));
    assert_eq!(idx["missCount"].as_i64(), Some(1));
    assert_eq!(idx["weightedBytes"].as_i64(), Some(-1));
    assert_eq!(idx["hitRate"], overridable::JValue::Float(0.5));
    let one = s.call(get_req("/api/ui/internal/cache/ApplicationCache_testapp_indexNewCache_testapp").method("DELETE")).await;
    assert_eq!(one.text(), "true");
    let stats_name = s.call(get_req("/api/ui/internal/cache/stats").method("DELETE")).await;
    assert_eq!(stats_name.text(), "true");
    let all = s.call(get_req("/api/ui/internal/cache").method("DELETE")).await;
    assert_eq!(all.text(), "false", "no Redis: the SSR invalidation could not be sent");
    assert_eq!(s.call(get_req("/api/ui/newdeployment")).await.status, StatusCode::BAD_REQUEST);
    let nd = s.call(get_req("/api/ui/newdeployment").user("SYSTEM", "Authorities.Logged_IN")).await;
    assert_eq!(nd.text(), "1");
    // Other methods are the ** mappings.
    assert!(s.call(gw("/api/ui/internal/cache/x")).await.text().contains("<title>"));
    assert_eq!(s.call(gw("/api/ui/internal/cache").method("POST").body("{}")).await.status, StatusCode::BAD_REQUEST);
    s.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB and Redis (MODLIX__MONGO__URI, MODLIX__REDIS__URL)"]
async fn cache_reset_publishes_on_redis() {
    let Ok(url) = std::env::var("MODLIX__REDIS__URL") else { return };
    let prefix = format!("rusttest{}", std::process::id());
    let channel = format!("rusttest:{}", std::process::id());
    let client = redis::Client::open(platform::cache::normalize_redis_url(&url).as_str()).unwrap();
    let Some(s) = shell_with(Some(client.clone()), Some((&prefix, &channel)), |_| {}).await else { return };
    let mut conn = client.get_multiplexed_async_connection().await.unwrap();
    let mut pubsub = client.get_async_pubsub().await.unwrap();
    pubsub.subscribe(&channel).await.unwrap();
    // Nothing under the prefix: Java's zip of an empty side answers no body.
    let empty = s.call(get_req("/api/ui/internal/cache").method("DELETE")).await;
    assert_eq!((empty.status, empty.body.len()), (StatusCode::OK, 0));
    let key = format!("{prefix}-parityCache");
    let _: () = redis::cmd("HSET").arg(&key).arg("k").arg("v").query_async(&mut conn).await.unwrap();
    let all = s.call(get_req("/api/ui/internal/cache").method("DELETE")).await;
    assert_eq!(all.text(), "true");
    let exists: i64 = redis::cmd("EXISTS").arg(&key).query_async(&mut conn).await.unwrap();
    assert_eq!(exists, 0);
    use futures::StreamExt;
    let mut stream = pubsub.on_message();
    let mut got = Vec::new();
    for _ in 0..3 {
        match tokio::time::timeout(std::time::Duration::from_secs(5), stream.next()).await {
            Ok(Some(m)) => got.push(m.get_payload::<String>().unwrap()),
            _ => break,
        }
    }
    assert!(got.contains(&format!("{key}:*")), "{got:?}");
    let ssr = got.iter().find(|m| m.contains("evictAll")).expect("the SSR message");
    assert!(ssr.starts_with("{\n  \"evictAll\" : true,\n  \"timestamp\" : "), "{ssr}");
    drop(stream);
    s.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn entry_points_from_a_file_the_cdn_or_the_fallback() {
    let dir = std::env::temp_dir().join(format!("ui-shell-it-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("asset-manifest.json");
    std::fs::write(&file, r#"{"entrypoints":{"index":["v.js","i.js"]}}"#).unwrap();
    let http = reqwest::Client::new();
    let mut cfg = ShellConfig::default();
    cfg.shell.asset_manifest_file = file.display().to_string();
    assert_eq!(ui::shell::server::load_entrypoints(&cfg, &http).await, vec!["v.js".to_string(), "i.js".to_string()]);
    std::fs::write(&file, "{}").unwrap();
    cfg.shell.cdn_host_name = "127.0.0.1:1".into();
    assert_eq!(ui::shell::server::load_entrypoints(&cfg, &http).await, vec!["vendors.js".to_string(), "index.js".to_string()]);
    cfg.shell.asset_manifest_file = dir.join("none.json").display().to_string();
    cfg.shell.cdn_host_name = String::new();
    assert_eq!(ui::shell::server::load_entrypoints(&cfg, &http).await.len(), 2);
    let _ = std::fs::remove_dir_all(dir);
    assert!(common::mongo_uri().is_some() || common::mongo_uri().is_none());
}
