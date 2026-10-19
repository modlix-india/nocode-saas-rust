//! Responses as the Java ui writes them: `ResponseEntityUtils` for the engine routes, and the
//! headers Spring Security adds with the ui's configuration (its defaults: `X-Frame-Options:
//! DENY` unless the controller set one, `Referrer-Policy: no-referrer`, and the no-cache trio
//! when the controller set no `Cache-Control`).

use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use overridable::json::{to_jackson_pretty, JValue};
use overridable::write::controller::spring_code;
use platform::error::{AppError, Coded};

/// How long the browser may keep an engine response.
#[derive(Clone, Copy, Debug)]
pub enum Caching {
    /// `makeRevalidateResponseEntity`: `no-cache` (application, page).
    Revalidate,
    /// `makeResponseEntity`: `max-age=<n>, must-revalidate` (style, theme, function).
    MaxAge(u32),
    /// `makeDraftResponseEntity`: `no-store`.
    Draft,
}

impl Caching {
    pub fn header(self) -> String {
        match self {
            Caching::Revalidate => "no-cache".into(),
            Caching::MaxAge(n) => format!("max-age={n}, must-revalidate"),
            Caching::Draft => "no-store".into(),
        }
    }

    pub fn pick(draft: bool, live: Caching) -> Caching {
        if draft {
            Caching::Draft
        } else {
            live
        }
    }
}

/// Marks a response whose frame options the engine set itself.
#[derive(Clone, Copy)]
struct EngineHeaders;

/// `ResponseEntityUtils.VARY` (Java commit e2b7d48aa): what a body depends on besides the URL.
/// A signed-in user is served their own client's copies, so one URL answers differently per
/// login; the login is the `Authorization` header, never a cookie.
pub const ENTITY_VARY: &str = "Authorization, clientCode, appCode";

/// Marks a response that carries `ResponseEntityUtils`' own `Vary`. WebFlux writes a
/// `ResponseEntity`'s headers over the response's with `putAll`, so this one value replaces the
/// three the CORS filter put there before the handler ran.
#[derive(Clone, Copy)]
struct EntityVary;

fn entity_vary(resp: &mut Response) {
    resp.headers_mut().insert(header::VARY, HeaderValue::from_static(ENTITY_VARY));
    resp.extensions_mut().insert(EntityVary);
}

/// Marks a response whose `Content-Security-Policy` the controller set (an app's own policy on
/// the index page, `frame-ancestors *` on the SSO pages).
#[derive(Clone, Copy)]
pub struct OwnCsp;

/// What an engine route answers with.
pub enum EngineBody {
    Json(JValue),
    Css(String),
}

/// `ResponseEntityUtils.build`: a 304 when the client's tag and the object's id contain one
/// another (a substring test, kept from Java), else a 200 with `ETag: W/<id>`.
pub fn build(unique_id: &str, etag: Option<&str>, caching: Caching, body: impl FnOnce() -> EngineBody) -> Response {
    let cc = caching.header();
    if let Some(e) = etag {
        if e.contains(unique_id) || unique_id.contains(e) {
            return not_modified(&cc);
        }
    }
    let (content_type, bytes) = match body() {
        EngineBody::Json(v) => ("application/json", to_jackson_pretty(&v).into_bytes()),
        EngineBody::Css(s) => ("text/css;charset=UTF-8", s.into_bytes()),
    };
    let mut resp = Response::new(Body::from(bytes));
    let h = resp.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&format!("W/{unique_id}")) {
        h.insert(header::ETAG, v);
    }
    if let Ok(v) = HeaderValue::from_str(&cc) {
        h.insert(header::CACHE_CONTROL, v);
    }
    // Set twice in Java, under two spellings of one name: two values.
    h.append("x-frame-options", HeaderValue::from_static("SAMEORIGIN"));
    h.append("x-frame-options", HeaderValue::from_static("SAMEORIGIN"));
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    resp.extensions_mut().insert(EngineHeaders);
    entity_vary(&mut resp);
    resp
}

/// `build`'s 304: `Cache-Control` and `Vary` on it too, so a browser updates its stored entry.
fn not_modified(cache_control: &str) -> Response {
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::NOT_MODIFIED;
    if let Ok(v) = HeaderValue::from_str(cache_control) {
        resp.headers_mut().insert(header::CACHE_CONTROL, v);
    }
    entity_vary(&mut resp);
    resp
}

/// `ResponseEntityUtils.makeResponseEntity` for a text body (the index page, the JS proxy, the
/// manifest): the 304 test, `ETag`, `Cache-Control`, the doubled frame option, the content
/// type when the controller names one, and the object's own headers.
pub fn build_text(
    unique_id: &str,
    etag: Option<&str>,
    caching: Caching,
    content_type: Option<&str>,
    headers: &[(String, String)],
    body: impl FnOnce() -> String,
) -> Response {
    let cc = caching.header();
    if let Some(e) = etag {
        if e.contains(unique_id) || unique_id.contains(e) {
            return not_modified(&cc);
        }
    }
    let mut resp = Response::new(Body::from(body()));
    let h = resp.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&format!("W/{unique_id}")) {
        h.insert(header::ETAG, v);
    }
    if let Ok(v) = HeaderValue::from_str(&cc) {
        h.insert(header::CACHE_CONTROL, v);
    }
    h.append("x-frame-options", HeaderValue::from_static("SAMEORIGIN"));
    h.append("x-frame-options", HeaderValue::from_static("SAMEORIGIN"));
    if let Some(ct) = content_type.and_then(|c| HeaderValue::from_str(c).ok()) {
        h.insert(header::CONTENT_TYPE, ct);
    }
    let mut own_csp = false;
    for (k, v) in headers {
        if let (Ok(name), Ok(value)) = (axum::http::HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(v)) {
            own_csp |= name == header::CONTENT_SECURITY_POLICY;
            h.append(name, value);
        }
    }
    resp.extensions_mut().insert(EngineHeaders);
    entity_vary(&mut resp);
    if own_csp {
        resp.extensions_mut().insert(OwnCsp);
    }
    resp
}

/// `ResponseEntity.ok(body)` for a JSON body.
pub fn json_ok(v: &JValue) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        to_jackson_pretty(v),
    )
        .into_response()
}

/// `ResponseEntity.notFound().build()`.
pub fn not_found() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

/// An empty `Mono<ResponseEntity>`: WebFlux answers 200 with no body.
pub fn empty_ok() -> Response {
    StatusCode::OK.into_response()
}

/// The Java `ControllerAdvice` body for an exception that is not a `GenericException`, coded:
/// a Spring refusal (`400 BAD_REQUEST "..."`) names what was wrong, anything else on our side
/// is `COMMON.INTERNAL_ERROR`; `debug` (Spring's or the cause's text) stays the debug message.
pub fn unknown_error(status: StatusCode, debug: &str) -> Response {
    let code = match spring_reason(debug) {
        Some(reason) => spring_code(status, reason),
        None if status.is_server_error() => Coded::new("COMMON.INTERNAL_ERROR"),
        None => spring_code(status, debug),
    };
    platform::error::coded_response(&code.status(status).debug(debug))
}

/// The quoted reason of Spring's `400 BAD_REQUEST "reason"`.
fn spring_reason(debug: &str) -> Option<&str> {
    let (status, rest) = debug.split_once(' ')?;
    if status.len() != 3 || !status.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let start = rest.find('"')?;
    rest[start + 1..].strip_suffix('"')
}

/// An error as the ui units answer it: coded (`overridable::write::controller::error_response`:
/// a Spring refusal names what was wrong, an unexpected failure is `COMMON.INTERNAL_ERROR`).
pub fn error_response(e: AppError) -> Response {
    overridable::write::controller::error_response(e)
}

/// A plain (non-CORS) `OPTIONS` on any ui path, as Spring answers it: the Java ui's
/// `UniversalController` maps `**` for GET and for POST/PUT/PATCH/DELETE, so every path has a
/// handler for every method and Spring replies with what is allowed. CORS preflights never get
/// here: the CORS layer answers them first.
pub async fn options_like_spring(req: Request, next: Next) -> Response {
    if req.method() != axum::http::Method::OPTIONS {
        return next.run(req).await;
    }
    let mut r = StatusCode::OK.into_response();
    let h = r.headers_mut();
    h.insert(header::ALLOW, HeaderValue::from_static("DELETE,POST,GET,PUT,PATCH,HEAD,OPTIONS"));
    h.insert("accept-patch", HeaderValue::from_static(""));
    r
}

/// Spring Security's `StrictServerWebExchangeFirewall`, which runs before anything else: a
/// method outside the usual seven, an encoded slash, backslash, percent, period, semicolon,
/// NUL, CR or LF in the path, a `//`, a `.` or `..` segment, or a line or paragraph separator
/// once decoded is a bare 400.
pub async fn spring_firewall(req: Request, next: Next) -> Response {
    if firewall_rejects(req.method(), req.uri().path()) {
        let mut r = StatusCode::BAD_REQUEST.into_response();
        r.headers_mut().insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
        return r;
    }
    next.run(req).await
}

pub fn firewall_rejects(method: &axum::http::Method, raw_path: &str) -> bool {
    use axum::http::Method;
    if ![Method::GET, Method::HEAD, Method::POST, Method::PUT, Method::PATCH, Method::DELETE, Method::OPTIONS].contains(method) {
        return true;
    }
    const ENCODED: [&str; 20] = [
        "%2F", "%2f", "%25", "%5C", "%5c", "\\", "%00", "\0", ";", "%3B", "%3b", "%2E", "%2e", "//", "%0A", "%0a", "%0D",
        "%0d", "\n", "\r",
    ];
    if ENCODED.iter().any(|t| raw_path.contains(t)) {
        return true;
    }
    if raw_path.split('/').any(|seg| seg == "." || seg == "..") {
        return true;
    }
    let decoded = percent_encoding::percent_decode_str(raw_path).decode_utf8_lossy();
    decoded.contains('\u{2028}') || decoded.contains('\u{2029}')
}

/// The firewall's check on query parameter names (read on every request, so a control
/// character in a name is a 400, after the security headers are on).
pub async fn query_names_allowed(req: Request, next: Next) -> Response {
    let bad = req.uri().query().is_some_and(|q| {
        q.split('&').any(|kv| {
            let name = kv.split('=').next().unwrap_or("").replace('+', " ");
            percent_encoding::percent_decode_str(&name).decode_utf8_lossy().chars().any(char::is_control)
        })
    });
    if bad {
        let mut r = StatusCode::BAD_REQUEST.into_response();
        r.headers_mut().insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
        return r;
    }
    next.run(req).await
}

/// The ui's `CorsWebFilter`, inside its security chain: the platform's CORS answer, which
/// then gets the security headers like every other response, without
/// `Access-Control-Max-Age` (the ui's `CorsConfiguration` sets none).
pub async fn cors_like_spring(req: Request, next: Next) -> Response {
    let mut r = platform::http::spring_cors(req, next).await;
    r.headers_mut().remove(header::ACCESS_CONTROL_MAX_AGE);
    // A `ResponseEntity`'s `Vary` replaces the filter's (WebFlux's `putAll`).
    if r.extensions().get::<EntityVary>().is_some() {
        r.headers_mut().insert(header::VARY, HeaderValue::from_static(ENTITY_VARY));
    }
    r
}

/// A route that answers `OPTIONS` itself: the layers answer it before the handler runs, and
/// axum then adds no `Allow` of its own (it does for a method the route does not have).
pub fn options_too<S: Clone + Send + Sync + 'static>(mr: axum::routing::MethodRouter<S>) -> axum::routing::MethodRouter<S> {
    mr.options(|| async { StatusCode::OK })
}

/// The Java ui's filter chain around a router's handlers, outermost first: the firewall, the
/// security headers, CORS, the query parameter names, and the plain `OPTIONS` answer.
pub fn with_ui_layers<S: Clone + Send + Sync + 'static>(r: axum::Router<S>) -> axum::Router<S> {
    use axum::middleware::from_fn;
    r.layer(from_fn(options_like_spring))
        .layer(from_fn(query_names_allowed))
        .layer(from_fn(cors_like_spring))
        .layer(from_fn(ui_security_headers))
        .layer(from_fn(spring_firewall))
}

/// Spring Security's response headers for the ui (`ISecurityConfiguration` without the frame
/// options it sets for other services), replacing the ones platform responses carry.
pub async fn ui_security_headers(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let engine = resp.extensions().get::<EngineHeaders>().is_some();
    let own_csp = resp.extensions().get::<OwnCsp>().is_some();
    let status = resp.status();
    let h: &mut HeaderMap = resp.headers_mut();
    if !own_csp {
        h.remove("content-security-policy");
    }
    // Java's ISecurityConfiguration answers a 401 with a bare status (HttpStatusServerEntryPoint).
    h.remove(header::WWW_AUTHENTICATE);
    if !engine {
        h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    }
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    h.insert("x-xss-protection", HeaderValue::from_static("0"));
    h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    if status != StatusCode::NOT_MODIFIED && !h.contains_key(header::CACHE_CONTROL) {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache, no-store, max-age=0, must-revalidate"));
        h.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
        h.insert(header::EXPIRES, HeaderValue::from_static("0"));
    }
    resp
}

#[cfg(test)]
mod tests {
    //! The Java ui `ResponseEntityUtilsTest`, and the header filter.
    use super::*;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    fn body() -> EngineBody {
        EngineBody::Json(JValue::Str("body".into()))
    }

    #[test]
    fn revalidate_ok() {
        let r = build("abc123", None, Caching::Revalidate, body);
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(r.headers()["etag"], "W/abc123");
        assert_eq!(r.headers()["cache-control"], "no-cache");
        assert_eq!(r.headers().get_all("x-frame-options").iter().count(), 2);
        assert_eq!(r.headers()["content-type"], "application/json");
    }

    #[test]
    fn revalidate_not_modified() {
        let r = build("abc123", Some("W/abc123"), Caching::Revalidate, body);
        assert_eq!(r.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(r.headers()["cache-control"], "no-cache");
        assert!(r.headers().get("etag").is_none());
    }

    /// `SharedHostServedClientIntegrationTest.hostCacheNeverAnswersForTenant`'s header: one URL
    /// answers per login, so every engine and shell answer says what it varies on.
    #[test]
    fn every_answer_varies_on_the_login_and_the_codes() {
        let vary = |r: &Response| r.headers().get_all("vary").iter().map(|v| v.to_str().unwrap().to_string()).collect::<Vec<_>>();
        assert_eq!(vary(&build("abc123", None, Caching::Revalidate, body)), [ENTITY_VARY]);
        assert_eq!(vary(&build("abc123", Some("W/abc123"), Caching::Revalidate, body)), [ENTITY_VARY]);
        assert_eq!(vary(&build_text("u", None, Caching::MaxAge(5), None, &[], String::new)), [ENTITY_VARY]);
        assert_eq!(vary(&build_text("u", Some("u"), Caching::MaxAge(5), None, &[], String::new)), [ENTITY_VARY]);
    }

    /// WebFlux writes the entity's headers with `putAll`: its `Vary` replaces the three the CORS
    /// filter wrote before the handler; an answer without one keeps the filter's.
    #[tokio::test]
    async fn an_entity_vary_replaces_the_cors_ones() {
        let app = with_ui_layers(
            Router::new()
                .route("/entity", get(|| async { build("u", None, Caching::Revalidate, || EngineBody::Css(String::new())) }))
                .route("/plain", get(|| async { "x" })),
        );
        let vary = |uri: &'static str| {
            let app = app.clone();
            async move {
                let r = app.oneshot(axum::http::Request::builder().uri(uri).header("origin", "https://elsewhere.example").body(Body::empty()).unwrap()).await.unwrap();
                r.headers().get_all("vary").iter().map(|v| v.to_str().unwrap().to_string()).collect::<Vec<_>>()
            }
        };
        assert_eq!(vary("/entity").await, [ENTITY_VARY]);
        assert_eq!(vary("/plain").await, ["Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers"]);
    }

    #[test]
    fn revalidate_changed() {
        let r = build("abc123", Some("W/zzz999"), Caching::Revalidate, body);
        assert_eq!(r.status(), StatusCode::OK);
    }

    #[test]
    fn lifetime_unchanged() {
        let r = build("abc123", None, Caching::MaxAge(604_800), body);
        assert_eq!(r.headers()["cache-control"], "max-age=604800, must-revalidate");
        let nm = build("abc123", Some("W/abc123"), Caching::MaxAge(604_800), body);
        assert_eq!(nm.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(nm.headers()["cache-control"], "max-age=604800, must-revalidate");
    }

    #[test]
    fn draft_no_store() {
        let r = build("abc123", None, Caching::pick(true, Caching::Revalidate), body);
        assert_eq!(r.headers()["cache-control"], "no-store");
        assert_eq!(Caching::pick(false, Caching::Revalidate).header(), "no-cache");
    }

    #[test]
    fn content_type() {
        let r = build("abc123", None, Caching::MaxAge(10), || EngineBody::Css("a{}".into()));
        assert_eq!(r.headers()["content-type"], "text/css;charset=UTF-8");
    }

    #[test]
    fn substring_rule_both_ways_and_the_empty_tag() {
        assert_eq!(build("abc", Some("xxabcxx"), Caching::Revalidate, body).status(), StatusCode::NOT_MODIFIED);
        assert_eq!(build("xxabcxx", Some("abc"), Caching::Revalidate, body).status(), StatusCode::NOT_MODIFIED);
        assert_eq!(build("abc", Some(""), Caching::Revalidate, body).status(), StatusCode::NOT_MODIFIED);
    }

    #[test]
    fn plain_responses() {
        assert_eq!(json_ok(&JValue::Bool(true)).status(), StatusCode::OK);
        assert_eq!(not_found().status(), StatusCode::NOT_FOUND);
        assert_eq!(empty_ok().status(), StatusCode::OK);
        let e = unknown_error(StatusCode::BAD_REQUEST, "why");
        assert_eq!(e.status(), StatusCode::BAD_REQUEST);
    }

    async fn coded(r: Response) -> (StatusCode, serde_json::Value) {
        let status = r.status();
        (status, serde_json::from_slice(&axum::body::to_bytes(r.into_body(), 100_000).await.unwrap()).unwrap())
    }

    #[tokio::test]
    async fn unknown_errors_are_coded() {
        let (s, v) = coded(unknown_error(StatusCode::BAD_REQUEST, "400 BAD_REQUEST \"Required header 'appCode' is not present.\"")).await;
        assert_eq!((s, v["code"].as_str(), v["params"]["field"].as_str()), (StatusCode::BAD_REQUEST, Some("COMMON.HEADER_MISSING"), Some("appCode")));
        assert_eq!(v["debugMessage"], "400 BAD_REQUEST \"Required header 'appCode' is not present.\"");
        let (_, v) = coded(unknown_error(StatusCode::BAD_REQUEST, "400 BAD_REQUEST \"No request body\"")).await;
        assert_eq!(v["code"], "COMMON.BODY_MISSING");
        let (_, v) = coded(unknown_error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "415 UNSUPPORTED_MEDIA_TYPE")).await;
        assert_eq!(v["code"], "COMMON.BODY_NOT_JSON");
        let (s, v) = coded(unknown_error(StatusCode::INTERNAL_SERVER_ERROR, "[401 ] during a call to security")).await;
        assert_eq!((s, v["code"].as_str()), (StatusCode::INTERNAL_SERVER_ERROR, Some("COMMON.INTERNAL_ERROR")));
        assert!(v["message"].as_str().unwrap().contains(v["exceptionId"].as_str().unwrap()));
        assert_eq!(spring_reason("4xx BAD \"x\""), None);
        let (s, v) = coded(error_response(AppError::Internal(anyhow::anyhow!("boom")))).await;
        assert_eq!((s, v["code"].as_str(), v["debugMessage"].as_str()), (StatusCode::INTERNAL_SERVER_ERROR, Some("COMMON.INTERNAL_ERROR"), Some("boom")));
    }

    #[tokio::test]
    async fn options_answers_like_spring_on_any_path() {
        let app = Router::new()
            .route("/engine", get(|| async { "x" }))
            .layer(axum::middleware::from_fn(options_like_spring))
            .layer(axum::middleware::from_fn(ui_security_headers));
        for path in ["/engine", "/anything/else"] {
            let r = app
                .clone()
                .oneshot(axum::http::Request::builder().method("OPTIONS").uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(r.status(), StatusCode::OK);
            assert_eq!(r.headers()["allow"], "DELETE,POST,GET,PUT,PATCH,HEAD,OPTIONS");
            assert_eq!(r.headers()["accept-patch"], "");
            assert_eq!(r.headers()["x-frame-options"], "DENY");
            assert_eq!(r.headers()["cache-control"], "no-cache, no-store, max-age=0, must-revalidate");
        }
        let r = app.oneshot(axum::http::Request::get("/engine").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(r.status(), StatusCode::OK);
    }

    #[test]
    fn the_firewall_like_spring() {
        use axum::http::Method;
        // Recorded from spring-security-web 6.4.2 StrictServerWebExchangeFirewall.
        for p in [
            "/a%2Fb", "/a%2fb", "/x%252F", "/a%25", "/a%5Cb", "/a%00b", "/a;b", "/a%3Bb", "/a%3bb", "/a/%2e%2e/b", "/a/%2E/b",
            "/a//b", "/a/%0a", "/a/%0D", "/a/%E2%80%A8", "/a/%E2%80%A9", "/a/./b", "/a/../b", "/a/..", "/a/.", "/.", "/..",
        ] {
            assert!(firewall_rejects(&Method::GET, p), "{p}");
        }
        for p in ["/a/b.", "/a/.b", "/a/..b", "/api/x/%E2%82%AC", "/a%20b", "/a+b", "/", "/hello/x/y/C/B", "/a%7Cb"] {
            assert!(!firewall_rejects(&Method::GET, p), "{p}");
        }
        for m in ["TRACE", "CONNECT", "FOO"] {
            assert!(firewall_rejects(&Method::from_bytes(m.as_bytes()).unwrap(), "/x"), "{m}");
        }
        for m in [Method::GET, Method::HEAD, Method::POST, Method::PUT, Method::PATCH, Method::DELETE, Method::OPTIONS] {
            assert!(!firewall_rejects(&m, "/x"));
        }
    }

    #[tokio::test]
    async fn the_ui_filter_chain() {
        let app = with_ui_layers(Router::new().route("/x", options_too(get(|| async { "x" }))));
        let call = |method: &'static str, uri: &'static str, headers: Vec<(&'static str, &'static str)>| {
            let app = app.clone();
            async move {
                let mut b = axum::http::Request::builder().method(method).uri(uri);
                for (k, v) in headers {
                    b = b.header(k, v);
                }
                app.oneshot(b.body(Body::empty()).unwrap()).await.unwrap()
            }
        };
        let r = call("GET", "/a%2Fb", vec![]).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        assert!(r.headers().get("x-frame-options").is_none(), "the firewall answers before the headers are written");
        assert!(r.headers().get("vary").is_none());
        let r = call("GET", "/x?a%0a=1", vec![]).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        assert_eq!(r.headers()["x-frame-options"], "DENY");
        assert_eq!(r.headers().get_all("vary").iter().count(), 3);
        assert_eq!(call("GET", "/x?a=%0a&b", vec![]).await.status(), StatusCode::OK);
        let r = call("OPTIONS", "/x", vec![("origin", "https://elsewhere.example"), ("access-control-request-method", "POST")]).await;
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(r.headers()["access-control-allow-origin"], "*");
        assert_eq!(r.headers()["access-control-allow-methods"], "POST");
        assert!(r.headers().get("access-control-max-age").is_none());
        assert_eq!(r.headers()["x-frame-options"], "DENY");
        assert!(r.headers().get("allow").is_none(), "a preflight is CORS's answer, not the OPTIONS one");
        let r = call("OPTIONS", "/x", vec![]).await;
        assert_eq!(r.headers()["allow"], "DELETE,POST,GET,PUT,PATCH,HEAD,OPTIONS");
    }

    #[tokio::test]
    async fn text_bodies_keep_their_own_headers() {
        let csp = vec![("Content-Security-Policy".to_string(), "default-src 'self'".to_string())];
        let r = build_text("\"u1\"", None, Caching::MaxAge(10), Some("text/html"), &csp, || "<p>".into());
        assert_eq!(r.headers()["etag"], "W/\"u1\"");
        assert_eq!(r.headers()["content-type"], "text/html");
        assert_eq!(r.headers()["cache-control"], "max-age=10, must-revalidate");
        let nm = build_text("\"u1\"", Some("W/\"u1\""), Caching::MaxAge(10), None, &[], String::new);
        assert_eq!(nm.status(), StatusCode::NOT_MODIFIED);
        let plain = build_text("x", None, Caching::Revalidate, None, &[("bad name".into(), "v".into())], || "b".into());
        assert!(plain.headers().get("content-type").is_none());
        let app = Router::new()
            .route("/own", get(move || { let csp = csp.clone(); async move { build_text("u", None, Caching::Revalidate, None, &csp, String::new) } }))
            .route(
                "/beacon",
                get(|| async {
                    let mut r = (StatusCode::OK, [(header::CONTENT_SECURITY_POLICY, "frame-ancestors *")]).into_response();
                    r.extensions_mut().insert(OwnCsp);
                    r
                }),
            )
            .route("/other", get(|| async { ([(header::CONTENT_SECURITY_POLICY, "frame-ancestors 'self'")], "x") }))
            .layer(axum::middleware::from_fn(ui_security_headers));
        let call = |path: &'static str| {
            let app = app.clone();
            async move { app.oneshot(axum::http::Request::get(path).body(Body::empty()).unwrap()).await.unwrap() }
        };
        let r = call("/own").await;
        assert_eq!(r.headers()["content-security-policy"], "default-src 'self'");
        assert_eq!(r.headers()["x-frame-options"], "SAMEORIGIN");
        let r = call("/beacon").await;
        assert_eq!(r.headers()["content-security-policy"], "frame-ancestors *");
        assert_eq!(r.headers()["x-frame-options"], "DENY");
        assert!(call("/other").await.headers().get("content-security-policy").is_none());
    }

    #[tokio::test]
    async fn spring_security_headers_for_the_ui() {
        let app = Router::new()
            .route("/engine", get(|| async { build("u", None, Caching::Revalidate, body) }))
            .route("/nm", get(|| async { build("u", Some("u"), Caching::Revalidate, body) }))
            .route("/err", get(|| async { platform::error::AppError::new(StatusCode::FORBIDDEN, "no").into_response() }))
            .route(
                "/401",
                get(|| async { (StatusCode::UNAUTHORIZED, [(header::WWW_AUTHENTICATE, "Basic realm=\"Realm\"")]).into_response() }),
            )
            .layer(axum::middleware::from_fn(ui_security_headers));
        let call = |path: &'static str| {
            let app = app.clone();
            async move {
                app.oneshot(axum::http::Request::get(path).body(Body::empty()).unwrap()).await.unwrap()
            }
        };
        let r = call("/engine").await;
        assert_eq!(r.headers().get_all("x-frame-options").iter().count(), 2);
        assert_eq!(r.headers()["x-frame-options"], "SAMEORIGIN");
        assert_eq!(r.headers()["referrer-policy"], "no-referrer");
        assert!(r.headers().get("pragma").is_none());
        let r = call("/nm").await;
        assert_eq!(r.headers()["x-frame-options"], "DENY");
        assert!(r.headers().get("pragma").is_none(), "no trio on a 304");
        let r = call("/err").await;
        assert_eq!(r.headers()["x-frame-options"], "DENY");
        assert!(r.headers().get("content-security-policy").is_none());
        assert_eq!(r.headers()["cache-control"], "no-cache, no-store, max-age=0, must-revalidate");
        assert_eq!(r.headers()["expires"], "0");
        let r = call("/401").await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        assert!(r.headers().get("www-authenticate").is_none(), "a 401 is a bare status (nocode-saas aca9929dd)");
    }
}
