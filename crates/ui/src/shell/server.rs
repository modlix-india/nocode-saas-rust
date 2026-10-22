//! The ui-shell routes: `UniversalController` (the index page behind the hosting gate, the
//! manifest, `/js/dist/**`, `/apiDocs`, the URI path routes, ACME, `/hassso`, `/sso/{token}`),
//! `AnalyticsController` and `UICacheController`.
//!
//! Every request first asks security who the caller is, as the Java `JWTTokenFilter` does for
//! every path, so a refused token is refused here too before anything else runs.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::body::to_bytes;
use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, MethodFilter, MethodRouter};
use axum::Router;
use overridable::json::{to_jackson_pretty, JValue};
use overridable::pojo::{map_field, str_field};
use overridable::{JMap, Resolved};
use percent_encoding::percent_decode_str;
use platform::cache::LocalCaches;
use platform::error::AppError;
use platform::http::with_route;
use platform::security::SecurityRefused;
use platform::upstream::Upstream;

use crate::engine::Engine;
use crate::respond::{build_text, unknown_error, with_ui_layers, Caching, OwnCsp};
use crate::shell::analytics::{self, check_authorized, engine_request, resolve_time_zone};
use crate::shell::config::ShellConfig;
use crate::shell::gson::{self, G};
use crate::shell::index::{index_html, IndexPage, CACHE_NAME_INDEX};
use crate::shell::javautil::{absolute_http_uri, client_facing_host, decide_redirect_without_lookup, js_string, md5_unique_id};
use crate::shell::uripath::{self, answer, first_match, get_params, query_string, RouteAnswer, RouteRequest, UriPathDoc};
use crate::shell::{ipfilter, webhook};
use crate::state::{AppState, Caller};

/// A file served from `ui.jsURL`, as `JSService` caches it.
#[derive(Debug, Clone)]
pub struct JsFile {
    pub body: String,
    pub unique_id: String,
    /// `Content-Type` from the file's extension; none for the empty answer.
    pub content_type: Option<&'static str>,
}

#[derive(Clone)]
pub struct ShellState {
    inner: Arc<ShellInner>,
}

pub struct ShellInner {
    /// The engine's state: definitions, security, caches.
    pub ui: AppState,
    pub cfg: ShellConfig,
    pub http: reqwest::Client,
    pub core: Upstream,
    /// `ApplicationCache_<app>_indexNewCache_<app>`, per client and surface.
    pub index: Arc<LocalCaches<String, Arc<IndexPage>>>,
    /// One cache per file path, key `jsObject`.
    pub js: Arc<LocalCaches<String, Arc<JsFile>>>,
    /// `URIPatternCache`, key `<app>-<client>`.
    pub patterns: Arc<LocalCaches<String, Arc<Vec<String>>>>,
    /// `analyticsQueryCache`, key the SHA-256 of the engine request.
    pub analytics: Arc<LocalCaches<String, Arc<Option<JValue>>>>,
    /// The page's webpack entry points, read once at start.
    pub entrypoints: Vec<String>,
    /// For the SSR invalidation channel and the `KEYS` walk of `evictAllCaches`.
    pub redis: Option<redis::Client>,
}

impl ShellState {
    pub fn new(inner: ShellInner) -> Self {
        Self { inner: Arc::new(inner) }
    }

    pub fn inner(&self) -> &ShellInner {
        &self.inner
    }
}

/// A response that ends the request early.
pub struct Fail(pub Response);

impl From<AppError> for Fail {
    fn from(e: AppError) -> Self {
        Fail(crate::respond::error_response(e))
    }
}

type R = Result<Response, Fail>;

fn unknown(status: StatusCode, debug: &str) -> Fail {
    Fail(unknown_error(status, debug))
}

/// A Feign call's failure as `ControllerAdvice` answers it: security's own status and message
/// when it sent a JSON error, otherwise the generic 500.
fn relay(e: anyhow::Error) -> Fail {
    match platform::security::refusal_error(&e) {
        // Security's coded error as it came, else its message.
        Some(AppError::Empty(_)) => {
            let status = e.downcast_ref::<SecurityRefused>().map(|r| r.0).unwrap_or(500);
            unknown(StatusCode::INTERNAL_SERVER_ERROR, &format!("[{status}] during a call to security"))
        }
        Some(refusal) => refusal.into(),
        None => unknown(StatusCode::INTERNAL_SERVER_ERROR, &format!("{e:#}")),
    }
}

fn finish(r: R, route: &'static str) -> Response {
    with_route(r.unwrap_or_else(|f| f.0), route)
}

fn header<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

/// `@RequestHeader(name)`: required.
fn required<'a>(h: &'a HeaderMap, name: &str) -> Result<&'a str, Fail> {
    header(h, name).ok_or_else(|| {
        unknown(StatusCode::BAD_REQUEST, &format!("400 BAD_REQUEST \"Required header '{name}' is not present.\""))
    })
}

/// `URLDecoder.decode`: `+` is a space.
fn url_decode(s: &str) -> String {
    percent_decode_str(&s.replace('+', " ")).decode_utf8_lossy().to_string()
}

/// `request.getQueryParams()`: `([^&=]+)(=?)([^&]+)?` over the raw query, decoded.
pub fn query_params(raw: Option<&str>) -> Vec<(String, Option<String>)> {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| regex::Regex::new("([^&=]+)(=?)([^&]+)?").expect("query pattern"));
    let Some(q) = raw else { return Vec::new() };
    re.captures_iter(q)
        .map(|c| {
            let name = url_decode(&c[1]);
            let value = match c.get(3) {
                Some(v) => Some(url_decode(v.as_str())),
                None if !c[2].is_empty() => Some(String::new()),
                None => None,
            };
            (name, value)
        })
        .collect()
}

/// `@RequestParam` with a default: missing or empty takes the default.
fn param(q: &[(String, Option<String>)], name: &str) -> Option<String> {
    q.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone().unwrap_or_default())
}

/// Header names as a Java service behind the gateway sees them: the ones the proxies and the
/// gateway set keep their spelling; the rest arrive lower case (HTTP/2 clients send them so).
pub fn java_header_name(lower: &str) -> String {
    const KNOWN: [&str; 14] = [
        "appCode",
        "clientCode",
        "X-Forwarded-Host",
        "X-Forwarded-Port",
        "X-Forwarded-For",
        "X-Forwarded-Proto",
        "X-Forwarded-Prefix",
        "X-Real-IP",
        "X-appCode",
        "X-clientCode",
        "X-Full-URL",
        "Host",
        "Authorization",
        "Content-Type",
    ];
    KNOWN
        .iter()
        .find(|k| k.eq_ignore_ascii_case(lower))
        .map(|k| k.to_string())
        .unwrap_or_else(|| lower.to_string())
}

fn route_request(method: &Method, uri: &Uri, h: &HeaderMap) -> RouteRequest {
    RouteRequest {
        method: method.as_str().to_string(),
        path: percent_decode_str(uri.path()).decode_utf8_lossy().to_string(),
        query: query_params(uri.query()),
        headers: h
            .iter()
            .filter_map(|(k, v)| Some((java_header_name(k.as_str()), v.to_str().ok()?.to_string())))
            .collect(),
    }
}

async fn caller(st: &ShellState, h: &HeaderMap) -> Result<Caller, Fail> {
    Ok(st.inner.ui.caller(h).await?)
}

fn cache_age(st: &ShellState) -> u32 {
    st.inner.cfg.ui.resource_cache_age
}

/// Every method a path does not map goes to the `**` handlers, as Spring's `**` mappings take
/// them; naming them all keeps axum from answering 405 (or adding `Allow`) on its own.
fn with_rest(mr: MethodRouter<ShellState>, have: &[Method]) -> MethodRouter<ShellState> {
    let mut mr = mr;
    for (m, f) in [
        (Method::GET, MethodFilter::GET),
        (Method::POST, MethodFilter::POST),
        (Method::PUT, MethodFilter::PUT),
        (Method::PATCH, MethodFilter::PATCH),
        (Method::DELETE, MethodFilter::DELETE),
        (Method::OPTIONS, MethodFilter::OPTIONS),
    ] {
        if !have.contains(&m) {
            mr = mr.on(f, universal);
        }
    }
    mr
}

pub fn router(state: ShellState) -> Router {
    let g = [Method::GET];
    let r = Router::new()
        .route("/js/dist/{*path}", with_rest(get(js_dist), &g))
        .route("/manifest/manifest.json", with_rest(get(manifest), &g))
        .route("/apiDocs", with_rest(get(api_docs), &g))
        .route("/.well-known/acme-challenge/{token}", with_rest(get(acme), &g))
        .route("/hassso", with_rest(get(hassso), &g))
        .route("/sso/{token}", with_rest(get(sso), &g))
        .route("/api/ui/analytics/query", with_rest(post(analytics_query), &[Method::POST]))
        .route("/api/ui/internal/cache", with_rest(get(cache_names).delete(cache_reset_all), &[Method::GET, Method::DELETE]))
        .route(
            "/api/ui/internal/cache/stats",
            with_rest(
                get(cache_stats).delete(|st: State<ShellState>, h: HeaderMap| cache_reset_named(st, Path("stats".to_string()), h)),
                &[Method::GET, Method::DELETE],
            ),
        )
        .route("/api/ui/internal/cache/{cache_name}", with_rest(delete(cache_reset_named), &[Method::DELETE]))
        .route("/api/ui/newdeployment", with_rest(get(new_deployment), &g))
        .fallback(universal);
    with_ui_layers(r).with_state(state)
}

// ---------------------------------------------------------------- UniversalController

/// `GET **` and `POST|PUT|PATCH|DELETE **`.
async fn universal(State(st): State<ShellState>, req: Request) -> Response {
    let method = req.method().clone();
    let r = if method == Method::GET || method == Method::HEAD {
        universal_get(&st, req).await
    } else if [Method::POST, Method::PUT, Method::PATCH, Method::DELETE].contains(&method) {
        universal_body(&st, req).await
    } else {
        Err(unknown(
            StatusCode::METHOD_NOT_ALLOWED,
            &format!("405 METHOD_NOT_ALLOWED \"Request method '{method}' is not supported.\""),
        ))
    };
    finish(r, "**")
}

struct Gateway<'a> {
    forwarded_host: &'a str,
    forwarded_port: &'a str,
    app: &'a str,
    client: &'a str,
}

/// The four headers both `**` methods require, in their order.
fn gateway_headers(h: &HeaderMap) -> Result<Gateway<'_>, Fail> {
    Ok(Gateway {
        forwarded_host: required(h, "X-Forwarded-Host")?,
        forwarded_port: required(h, "X-Forwarded-Port")?,
        app: required(h, "appCode")?,
        client: required(h, "clientCode")?,
    })
}

async fn universal_get(st: &ShellState, req: Request) -> R {
    let (parts, _) = req.into_parts();
    let h = &parts.headers;
    let api = parts.uri.path().contains("/api/");
    let (caller, refused) = route_caller(st, h, api).await?;
    let g = gateway_headers(h)?;
    let etag = header(h, "if-none-match");
    if api {
        let rr = route_request(&parts.method, &parts.uri, h);
        let route_cc = route_client(&caller, &g);
        let found = admit(find_route(st, &caller, &rr, g.app, &route_cc).await?, refused)?;
        if let Some(doc) = found {
            let input = RouteInput { body: None, raw: &[], peer: peer(&parts.extensions) };
            if let Some(resp) = run_route(st, &caller, &rr, h, &doc, input, g.app, &route_cc, &g).await? {
                return Ok(resp);
            }
        }
    }
    index_page(st, &caller, g.app, g.client, etag).await
}

async fn universal_body(st: &ShellState, req: Request) -> R {
    let (parts, body) = req.into_parts();
    let h = &parts.headers;
    let (caller, refused) = route_caller(st, h, true).await?;
    let g = gateway_headers(h)?;
    let bytes = to_bytes(body, webhook::BODY_LIMIT)
        .await
        .map_err(|e| unknown(StatusCode::BAD_REQUEST, &format!("400 BAD_REQUEST \"{e}\"")))?;
    let route_cc = route_client(&caller, &g);
    let rr = route_request(&parts.method, &parts.uri, h);
    let found = admit(find_route(st, &caller, &rr, g.app, &route_cc).await?, refused)?;
    let content_type = header(h, "content-type").unwrap_or("");
    let json = if found.as_deref().is_some_and(|d| webhook::is_webhook(&d.entity)) {
        // A provider's body that does not read still reaches the function, as rawBody.
        webhook::parse_body(content_type, &bytes).await.unwrap_or_else(|_| G::Obj(Vec::new()))
    } else {
        if bytes.is_empty() {
            return Err(unknown(StatusCode::BAD_REQUEST, "400 BAD_REQUEST \"No request body\""));
        }
        webhook::parse_body(content_type, &bytes).await.map_err(|(status, m)| unknown(status, &m))?
    };
    let Some(doc) = found else { return Ok(StatusCode::BAD_REQUEST.into_response()) };
    let input = RouteInput { body: Some(&json), raw: &bytes, peer: peer(&parts.extensions) };
    match run_route(st, &caller, &rr, h, &doc, input, g.app, &route_cc, &g).await? {
        Some(resp) => Ok(resp),
        None => Ok(StatusCode::BAD_REQUEST.into_response()),
    }
}

/// The client whose routes the request looks up: a signed-in caller's own, else the URL's.
fn route_client(caller: &Caller, g: &Gateway<'_>) -> String {
    if caller.authenticated() {
        caller.ca.client_code().to_string()
    } else {
        g.client.to_string()
    }
}

/// The caller, and the refusal of a credential security turned down: a request that may reach a
/// route is then looked at as an anonymous one, since a webhook provider may send an
/// `Authorization` of its own (its function checks it); any other route still answers with the
/// refusal ([`admit`]).
async fn route_caller(st: &ShellState, h: &HeaderMap, routes: bool) -> Result<(Caller, Option<Fail>), Fail> {
    match st.inner.ui.caller(h).await {
        Ok(c) => Ok((c, None)),
        Err(e) if routes && h.contains_key(header::AUTHORIZATION) => {
            let mut anonymous = h.clone();
            anonymous.remove(header::AUTHORIZATION);
            match st.inner.ui.caller(&anonymous).await {
                Ok(c) => Ok((c, Some(e.into()))),
                Err(_) => Err(e.into()),
            }
        }
        Err(e) => Err(e.into()),
    }
}

/// A route found for a caller whose credential was refused goes on only when it is a webhook.
fn admit(found: Option<Arc<Resolved>>, refused: Option<Fail>) -> Result<Option<Arc<Resolved>>, Fail> {
    match refused {
        Some(f) if !found.as_deref().is_some_and(|d| webhook::is_webhook(&d.entity)) => Err(f),
        _ => Ok(found),
    }
}

/// The hosting gate, then the index page of the app and client it chooses.
async fn index_page(st: &ShellState, caller: &Caller, app: &str, client: &str, etag: Option<&str>) -> R {
    let (serve_app, serve_client) = match st.inner.ui.inner().security.billing_hosting(app, client).await {
        Ok(Some(d)) => (
            d.get("serveAppCode").and_then(serde_json::Value::as_str).unwrap_or(app).to_string(),
            d.get("serveClientCode").and_then(serde_json::Value::as_str).unwrap_or(client).to_string(),
        ),
        _ => (app.to_string(), client.to_string()),
    };
    let page = index_of(st, caller, &serve_app, &serve_client).await?;
    Ok(build_text(
        &page.unique_id,
        etag,
        Caching::MaxAge(cache_age(st)),
        Some("text/html"),
        &page.headers,
        || page.html.clone(),
    ))
}

/// `IndexHTMLService.getIndexHTML`, cached per client and surface.
pub async fn index_of(st: &ShellState, caller: &Caller, app: &str, client: &str) -> Result<Arc<IndexPage>, Fail> {
    let cache = format!("ApplicationCache_{app}_{CACHE_NAME_INDEX}_{app}");
    let key = format!("{client}{}", if caller.draft { "-draft" } else { "" });
    let page = st
        .inner
        .index
        .get_or_load(&cache, key, || async {
            let read = Engine::new(&st.inner.ui, caller).app_read(app, client).await?;
            let page = index_html(
                read.as_ref().map(|r| &r.entity),
                app,
                client,
                caller.draft,
                &st.inner.cfg.shell,
                &st.inner.entrypoints,
            )
            .map_err(|e| unknown(StatusCode::INTERNAL_SERVER_ERROR, &e.0))?;
            Ok::<_, Fail>(Some(Arc::new(page)))
        })
        .await?;
    page.ok_or_else(|| unknown(StatusCode::INTERNAL_SERVER_ERROR, "no index page"))
}

/// `findAllNamesByAppCodeAndClientCode`, cached even when empty.
async fn patterns(st: &ShellState, app: &str, client: &str) -> Result<Arc<Vec<String>>, Fail> {
    let v = st
        .inner
        .patterns
        .get_or_load("URIPatternCache", format!("{app}-{client}"), || async {
            let docs = st
                .inner
                .ui
                .store()
                .find_docs("uri_path", uripath::names_filter(app, client))
                .await
                .map_err(|e| unknown(StatusCode::INTERNAL_SERVER_ERROR, &format!("{e:#}")))?;
            let names = docs.iter().filter_map(|d| d.get_str("name").ok().map(str::to_string)).collect();
            Ok::<_, Fail>(Some(Arc::new(names)))
        })
        .await?;
    Ok(v.unwrap_or_default())
}

/// The route the request names: the first pattern, in the client's inheritance order, that
/// matches the path, read for the client (a client with no copy of its own is served the one it
/// inherits).
async fn find_route(st: &ShellState, caller: &Caller, req: &RouteRequest, app: &str, client: &str) -> Result<Option<Arc<Resolved>>, Fail> {
    let order = st.inner.ui.store().inheritance_order(app, client, client).await.map_err(relay)?;
    let mut matched = None;
    for cc in order.iter() {
        let names = patterns(st, app, cc).await?;
        if let Some(p) = first_match(names.iter(), &req.path) {
            matched = Some(p.clone());
            break;
        }
    }
    let Some(name) = matched else { return Ok(None) };
    Ok(Engine::new(&st.inner.ui, caller).read_def(&UriPathDoc, &name, app, client).await?)
}

/// What a route gets of the request body: the parsed arguments and the bytes as they came; and
/// the connection's peer, the caller's address of last resort (`ipfilter::caller_ip`).
struct RouteInput<'a> {
    body: Option<&'a G>,
    raw: &'a [u8],
    peer: Option<IpAddr>,
}

fn peer(ext: &axum::http::Extensions) -> Option<IpAddr> {
    ext.get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip())
}

/// `URIPathService.getResponse` on the route found: `None` when it answers nothing (a GET then
/// serves the page).
#[allow(clippy::too_many_arguments)]
async fn run_route(
    st: &ShellState,
    caller: &Caller,
    req: &RouteRequest,
    h: &HeaderMap,
    doc: &Resolved,
    input: RouteInput<'_>,
    app: &str,
    client: &str,
    g: &Gateway<'_>,
) -> Result<Option<Response>, Fail> {
    let uri_path = &doc.entity;
    let is_webhook = webhook::is_webhook(uri_path);
    if !is_webhook {
        uripath::access_check(uri_path, caller.authorities(), caller.authenticated())?;
    }
    let Some(def) = map_field(uri_path, "pathDefinitions").and_then(|m| m.get(&req.method)).and_then(JValue::as_object) else {
        return Err(unknown(StatusCode::INTERNAL_SERVER_ERROR, "value"));
    };
    // The definition's whitelist and blacklist (Rust only), for every kind of route.
    let route_name = str_field(uri_path, "name").unwrap_or("");
    ipfilter::check(def, route_name, &req.method, ipfilter::caller_ip(h, input.peer))?;
    match str_field(def, "uriType") {
        Some("KIRUN_FUNCTION") => {}
        Some(_) => return Ok(None),
        None => {
            return Err(unknown(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Cannot invoke \"com.fincity.saas.ui.enums.URIType.ordinal()\" because the return value of \"com.fincity.saas.ui.model.PathDefinition.getUriType()\" is null",
            ))
        }
    }
    let Some(fx) = map_field(def, "kiRunFxDefinition") else {
        return Err(unknown(StatusCode::INTERNAL_SERVER_ERROR, "Cannot invoke a method because \"kiRunFxDef\" is null"));
    };
    let path_string = str_field(uri_path, "pathString");
    let fx_app = str_field(uri_path, "appCode").unwrap_or(app);
    let body_method = ["POST", "PUT", "PATCH", "DELETE"].contains(&req.method.as_str());
    if req.method != "GET" && !body_method {
        return Ok(None);
    }
    let mut call = CoreCall {
        route: CoreRoute::Execute,
        namespace: str_field(fx, "namespace").unwrap_or("null"),
        name: str_field(fx, "name").unwrap_or("null"),
        authorization: header(h, "authorization"),
        forwarded_host: g.forwarded_host,
        forwarded_port: g.forwarded_port,
        app_code: fx_app,
        client_code: client,
        debug: header(h, "x-debug"),
        draft: caller.draft,
    };
    let content_type = if req.method == "GET" { "text/plain;charset=UTF-8" } else { "application/json;charset=UTF-8" };
    let text = if is_webhook {
        // The URL's client, whoever calls: the function runs as that client's webhook user.
        call.route = CoreRoute::Webhook;
        call.authorization = None;
        call.client_code = g.client;
        let raw = webhook::raw_request(input.raw, h, &req.query);
        let args = webhook::webhook_arguments(input.body, raw);
        let json = gson::to_string(&uripath::with_mapped_params(Some(&args), req, path_string, fx));
        let text = execute_function(st, &call, None, Some(json)).await?;
        if let Some(resp) = webhook::reply(text.as_deref(), fx)? {
            return Ok(Some(resp));
        }
        text
    } else if req.method == "GET" {
        let q = query_string(&get_params(req, path_string, fx)).map_err(|m| unknown(StatusCode::INTERNAL_SERVER_ERROR, &m))?;
        execute_function(st, &call, Some(&q), None).await?
    } else {
        let json = gson::to_string(&uripath::with_mapped_params(input.body, req, path_string, fx));
        execute_function(st, &call, None, Some(json)).await?
    };
    match answer(text.as_deref(), fx) {
        Ok(None) => Ok(None),
        Ok(Some(RouteAnswer::Body(status, b))) => Ok(Some(uripath::text_response(status, b, content_type))),
        Ok(Some(RouteAnswer::Error(status, m))) | Err(RouteAnswer::Error(status, m)) => Err(AppError::new(status, m).into()),
        Ok(Some(RouteAnswer::Fault(m))) | Err(RouteAnswer::Fault(m)) => Err(unknown(StatusCode::INTERNAL_SERVER_ERROR, &m)),
        Err(RouteAnswer::Body(status, b)) => Ok(Some(uripath::text_response(status, b, content_type))),
    }
}

/// Which core route runs a route's function.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CoreRoute {
    /// The open `execute` route, as the caller.
    Execute,
    /// The internal webhook route: as the client's webhook user.
    Webhook,
}

struct CoreCall<'a> {
    route: CoreRoute,
    namespace: &'a str,
    name: &'a str,
    authorization: Option<&'a str>,
    forwarded_host: &'a str,
    forwarded_port: &'a str,
    app_code: &'a str,
    client_code: &'a str,
    debug: Option<&'a str>,
    draft: bool,
}

/// A value placed in a URL path, as Feign expands a `@PathVariable`.
fn path_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `IFeignCoreService.executeWith` (or the webhook route): the function's output text, `None`
/// for an empty body.
async fn execute_function(st: &ShellState, c: &CoreCall<'_>, query: Option<&str>, json: Option<String>) -> Result<Option<String>, Fail> {
    let base = st.inner.core.base().await.map_err(|e| unknown(StatusCode::INTERNAL_SERVER_ERROR, &format!("{e:#}")))?;
    let (route, feign) = match c.route {
        CoreRoute::Execute => ("execute", "executeWith"),
        CoreRoute::Webhook => ("internal/webhook", "webhook"),
    };
    let mut url = format!("{base}/api/core/function/{route}/{}/{}", path_segment(c.namespace), path_segment(c.name));
    if let Some(q) = query.filter(|q| !q.is_empty()) {
        url.push('?');
        url.push_str(q);
    }
    let method = if json.is_some() { "POST" } else { "GET" };
    let mut rb = match json {
        Some(body) => st.inner.http.post(&url).header(header::CONTENT_TYPE, "application/json").body(body),
        None => st.inner.http.get(&url),
    };
    let mut trace = HeaderMap::new();
    platform::telemetry::inject_trace_headers(&mut trace);
    rb = rb
        .headers(trace)
        .timeout(Duration::from_secs(st.inner.cfg.core.timeout_seconds))
        .header("X-Forwarded-Host", c.forwarded_host)
        .header("X-Forwarded-Port", c.forwarded_port)
        .header("appCode", c.app_code)
        .header("clientCode", c.client_code);
    if let Some(a) = c.authorization {
        rb = rb.header(header::AUTHORIZATION, a);
    }
    if let Some(d) = c.debug {
        rb = rb.header("x-debug", d);
    }
    if c.draft {
        rb = rb.header("x-draft", "true");
    }
    let resp = rb.send().await.map_err(|e| unknown(StatusCode::INTERNAL_SERVER_ERROR, &format!("{e}")))?;
    let status = resp.status();
    let content_type = resp.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).map(str::to_string);
    let bytes = resp.bytes().await.map_err(|e| unknown(StatusCode::INTERNAL_SERVER_ERROR, &format!("{e}")))?;
    if !status.is_success() {
        let detail = format!(
            "[{} {}] during [{method}] to [{url}] [IFeignCoreService#{feign}]: [{}]",
            status.as_u16(),
            status.canonical_reason().unwrap_or(""),
            String::from_utf8_lossy(&bytes)
        );
        if content_type.as_deref() == Some("application/json") {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                let message = match v.get("message") {
                    None | Some(serde_json::Value::Null) => String::new(),
                    Some(serde_json::Value::String(s)) => s.clone(),
                    Some(other) => other.to_string(),
                };
                return Err(AppError::new(status, message).into());
            }
        }
        return Err(unknown(StatusCode::INTERNAL_SERVER_ERROR, &detail));
    }
    if bytes.is_empty() {
        return Ok(None);
    }
    Ok(Some(String::from_utf8_lossy(&bytes).to_string()))
}

/// `GET /js/dist/**`: the file from `ui.jsURL`, cached per path.
async fn js_dist(State(st): State<ShellState>, uri: Uri, h: HeaderMap) -> Response {
    let r = async {
        caller(&st, &h).await?;
        let decoded = percent_decode_str(uri.path()).decode_utf8_lossy().to_string();
        let file_path = decoded.find("/js/dist/").map(|i| decoded[i + 9..].to_string()).unwrap_or_default();
        let f = js_file(&st, &file_path).await?;
        let headers: Vec<(String, String)> =
            f.content_type.map(|c| vec![("Content-Type".to_string(), c.to_string())]).unwrap_or_default();
        let mut resp = build_text(&f.unique_id, header(&h, "if-none-match"), Caching::MaxAge(cache_age(&st)), None, &headers, || f.body.clone());
        if f.content_type.is_none() && resp.status() == StatusCode::OK {
            resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain;charset=UTF-8"));
        }
        Ok(resp)
    }
    .await;
    finish(r, "/js/dist/**")
}

fn mime_type(path: &str) -> &'static str {
    if path.ends_with(".js") {
        "text/javascript"
    } else if path.ends_with(".css") {
        "text/css"
    } else if path.ends_with(".html") {
        "text/html"
    } else if path.ends_with(".json") {
        "application/json"
    } else {
        "application/octet-stream"
    }
}

/// A path appended to a base URL the way `WebClient`'s URI template encodes it: characters a
/// path may hold stay, the rest (`%` included) are escaped.
fn template_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@/".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `JSService.getJSResource`.
pub async fn js_file(st: &ShellState, file_path: &str) -> Result<Arc<JsFile>, Fail> {
    let js_url = st.inner.cfg.shell.js_url.as_str();
    let empty = || Arc::new(JsFile { body: String::new(), unique_id: md5_unique_id(""), content_type: None });
    if js_url.trim().is_empty() {
        return Ok(empty());
    }
    let v = st
        .inner
        .js
        .get_or_load(file_path, "jsObject".to_string(), || async {
            let url = format!("{js_url}{}", template_path(file_path));
            let resp = st
                .inner
                .http
                .get(&url)
                .send()
                .await
                .map_err(|e| unknown(StatusCode::INTERNAL_SERVER_ERROR, &format!("{e}")))?;
            let status = resp.status();
            if !status.is_success() {
                let reason = uripath::reason_phrase(status.as_u16()).or(status.canonical_reason()).unwrap_or("");
                return Err(unknown(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("{} {reason} from GET {url}", status.as_u16()),
                ));
            }
            let bytes = resp.bytes().await.map_err(|e| unknown(StatusCode::INTERNAL_SERVER_ERROR, &format!("{e}")))?;
            if bytes.is_empty() {
                return Ok::<_, Fail>(None);
            }
            let body = String::from_utf8_lossy(&bytes).to_string();
            let unique_id = md5_unique_id(&body);
            Ok(Some(Arc::new(JsFile { body, unique_id, content_type: Some(mime_type(file_path)) })))
        })
        .await?;
    Ok(v.unwrap_or_else(empty))
}

/// `GET /manifest/manifest.json`: the app's `manifest` property, which `applyChange` has
/// already removed, so in practice always empty.
async fn manifest(State(st): State<ShellState>, h: HeaderMap) -> Response {
    let r = async {
        let caller = caller(&st, &h).await?;
        let app = required(&h, "appCode")?;
        let client = required(&h, "clientCode")?;
        let read = Engine::new(&st.inner.ui, &caller).app_read(app, client).await?;
        let body = read
            .as_ref()
            .and_then(|r| map_field(&r.entity, "properties"))
            .and_then(|p| p.get("manifest"))
            .filter(|m| !m.is_null())
            .map(to_jackson_pretty)
            .unwrap_or_default();
        Ok(build_text(
            &md5_unique_id(&body),
            header(&h, "if-none-match"),
            Caching::MaxAge(cache_age(&st)),
            Some("application/json;charset=UTF-8"),
            &[],
            || body.clone(),
        ))
    }
    .await;
    finish(r, "/manifest/manifest.json")
}

/// `GET /apiDocs`.
async fn api_docs(State(st): State<ShellState>, h: HeaderMap) -> Response {
    let r = async {
        caller(&st, &h).await?;
        required(&h, "appCode")?;
        required(&h, "clientCode")?;
        let body = "Coming soon...";
        Ok(build_text(
            &md5_unique_id(body),
            header(&h, "if-none-match"),
            Caching::MaxAge(cache_age(&st)),
            Some("text/html;charset=UTF-8"),
            &[],
            || body.to_string(),
        ))
    }
    .await;
    finish(r, "/apiDocs")
}

/// `GET /.well-known/acme-challenge/{token}`.
async fn acme(State(st): State<ShellState>, Path(token): Path<String>, h: HeaderMap) -> Response {
    let r = async {
        caller(&st, &h).await?;
        let answer = st.inner.ui.inner().security.ssl_token(&token).await.map_err(relay)?;
        Ok(match answer {
            Some(text) => uripath::text_response(StatusCode::OK, text, "text/plain;charset=UTF-8"),
            None => StatusCode::OK.into_response(),
        })
    }
    .await;
    finish(r, "/.well-known/acme-challenge/{token}")
}

const SSO_START: &str = "<html><head><title>SSO</title><script>";
const SSO_END: &str = "</script></head><body></body></html>";

fn beacon_response(html: String, no_store: bool) -> Response {
    let mut r = (StatusCode::OK, html).into_response();
    let h = r.headers_mut();
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("frame-ancestors *"));
    if no_store {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html;charset=UTF-8"));
    r.extensions_mut().insert(OwnCsp);
    r
}

fn logout_script(return_url: &str) -> String {
    format!(
        "try{{localStorage.removeItem('AuthToken');localStorage.removeItem('AuthTokenExpiry');}}catch(e){{}}window.location.replace({});",
        js_string(Some(return_url))
    )
}

fn bounce_script(return_url: &str, target_app: &str, target_client: &str) -> String {
    format!(
        "var back={};var targetAppCode={};var targetClientCode={};\
function leave(k,v){{var u=new URL(back);u.searchParams.set(k,v);window.location.replace(u.toString());}}\
function forget(){{try{{localStorage.removeItem('AuthToken');localStorage.removeItem('AuthTokenExpiry');}}catch(e){{}}}}\
var lsToken=localStorage.getItem('AuthToken');\
var lsExpiry=parseInt(localStorage.getItem('AuthTokenExpiry')||'0',10)*1000;\
if(!lsToken||lsExpiry<Date.now()){{leave('sso','none');}}\
else{{\
var bearer;try{{bearer=JSON.parse(lsToken);}}catch(e){{bearer=lsToken;}}\
fetch('/api/security/makeOneTimeToken',{{method:'POST',credentials:'omit',headers:{{'Content-Type':'application/json','Authorization':bearer,'appCode':'authzump','clientCode':'SYSTEM'}},\
body:JSON.stringify({{targetAppCode:targetAppCode,targetClientCode:targetClientCode,authMode:'COOKIE'}})}})\
.then(function(r){{if(!r.ok){{if(r.status===401||r.status===403){{forget();}}return null;}}return r.json();}})\
.then(function(d){{if(d&&d.token){{leave('ott',d.token);}}else{{leave('sso','none');}}}})\
.catch(function(){{leave('sso','none');}});\
}}",
        js_string(Some(return_url)),
        js_string(Some(target_app)),
        js_string(Some(target_client)),
    )
}

/// `getClientNAppCodeNType` on a URI's scheme, host and port: the app code the host belongs to.
async fn host_app(st: &ShellState, scheme: &str, host: &str, port: i32) -> Result<Option<String>, Fail> {
    let port = if port < 0 { String::new() } else { port.to_string() };
    let t = st.inner.ui.inner().security.client_n_app_code_n_type(scheme, host, &port).await.map_err(relay)?;
    Ok(t.map(|(_, app, _)| app))
}

/// `GET /hassso`: the cross-app SSO beacon (and its logout).
async fn hassso(State(st): State<ShellState>, uri: Uri, h: HeaderMap) -> Response {
    let r = async {
        caller(&st, &h).await?;
        let q = query_params(uri.query());
        let Some(target_app) = q.iter().find(|(k, _)| k == "targetAppCode").map(|(_, v)| v.clone().unwrap_or_default()) else {
            return Err(unknown(
                StatusCode::BAD_REQUEST,
                "400 BAD_REQUEST \"Required query parameter 'targetAppCode' is not present.\"",
            ));
        };
        let target_client = param(&q, "targetClientCode").unwrap_or_default();
        let return_url = param(&q, "returnUrl").unwrap_or_default();
        let mode = param(&q, "mode").unwrap_or_default();
        let Some(u) = absolute_http_uri(Some(&return_url)).filter(|_| !target_app.trim().is_empty()) else {
            return Ok(StatusCode::BAD_REQUEST.into_response());
        };
        if host_app(&st, &u.scheme, &u.host, u.port).await?.as_deref() != Some(target_app.as_str()) {
            return Ok(StatusCode::NOT_FOUND.into_response());
        }
        let script = if mode == "logout" { logout_script(&return_url) } else { bounce_script(&return_url, &target_app, &target_client) };
        Ok(beacon_response(format!("{SSO_START}{script}{SSO_END}"), true))
    }
    .await;
    finish(r, "/hassso")
}

/// `InetAddress.getHostAddress()`: IPv6 written out in full.
fn java_host_address(addr: &SocketAddr) -> String {
    match addr.ip() {
        std::net::IpAddr::V4(v4) => v4.to_string(),
        std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => v6.segments().iter().map(|s| format!("{s:x}")).collect::<Vec<_>>().join(":"),
        },
    }
}

/// `GET /sso/{token}`: signs the visitor in with a one-time token and sends them on.
async fn sso(State(st): State<ShellState>, Path(token): Path<String>, req: Request) -> Response {
    let (parts, _) = req.into_parts();
    let r = async {
        let h = &parts.headers;
        caller(&st, h).await?;
        let q = query_params(parts.uri.query());
        let redirect_url = param(&q, "redirectUrl").filter(|s| !s.is_empty()).unwrap_or_else(|| "/".to_string());
        let forwarded_host = header(h, "x-forwarded-host");
        let addr = match header(h, "x-real-ip") {
            Some(ip) => ip.to_string(),
            None => parts.extensions.get::<ConnectInfo<SocketAddr>>().map(|c| java_host_address(&c.0)).unwrap_or_default(),
        };
        let request_host = header(h, "host").map(|v| v.rsplit_once(':').map(|(a, _)| a).unwrap_or(v)).unwrap_or("");
        let safe = match decide_redirect_without_lookup(Some(&redirect_url), &client_facing_host(forwarded_host, request_host)) {
            Some(s) => s,
            None => match absolute_http_uri(Some(&redirect_url)) {
                Some(u) => match host_app(&st, &u.scheme, &u.host, u.port).await? {
                    Some(app) if !app.trim().is_empty() && app != "nothing" => redirect_url.clone(),
                    _ => "/".to_string(),
                },
                None => "/".to_string(),
            },
        };
        let ca = st
            .inner
            .ui
            .inner()
            .security
            .authenticate_with_one_time_token(&token, forwarded_host, header(h, "clientcode"), header(h, "appcode"), &addr)
            .await
            .map_err(relay)?;
        let Some(ca) = ca else { return Ok(StatusCode::OK.into_response()) };
        let access_token = ca.get("accessToken").and_then(serde_json::Value::as_str).unwrap_or("null");
        let expiry = match ca.get("accessTokenExpiryAt") {
            Some(serde_json::Value::Number(n)) => n.as_i64().unwrap_or(0).to_string(),
            _ => "0".to_string(),
        };
        let script = format!(
            "window.localStorage.setItem('AuthToken', {});window.localStorage.setItem('AuthTokenExpiry', '{expiry}');window.location.href = {};",
            js_string(Some(&format!("\"{access_token}\""))),
            js_string(Some(&safe)),
        );
        Ok(beacon_response(format!("{SSO_START}{script}{SSO_END}"), false))
    }
    .await;
    finish(r, "/sso/{token}")
}

// ---------------------------------------------------------------- AnalyticsController

/// `POST /api/ui/analytics/query`.
async fn analytics_query(State(st): State<ShellState>, req: Request) -> Response {
    let r = async {
        let (parts, body) = req.into_parts();
        let h = &parts.headers;
        let caller = caller(&st, h).await?;
        let app = required(h, "appCode")?;
        let client = required(h, "clientCode")?;
        let bytes = to_bytes(body, 16 * 1024 * 1024)
            .await
            .map_err(|_| unknown(StatusCode::BAD_REQUEST, "400 BAD_REQUEST \"Failed to read HTTP message\""))?;
        if bytes.is_empty() {
            return Err(unknown(StatusCode::BAD_REQUEST, "400 BAD_REQUEST \"No request body\""));
        }
        let body: JMap = match overridable::json::parse(&bytes) {
            Ok(JValue::Object(m)) => m,
            _ => return Err(unknown(StatusCode::BAD_REQUEST, "400 BAD_REQUEST \"Failed to read HTTP message\"")),
        };
        let cfg = &st.inner.cfg.shell;
        let configured = !cfg.analytics_engine_url.trim().is_empty() && !cfg.analytics_engine_secret.trim().is_empty();
        let security = &st.inner.ui.inner().security;
        check_authorized(configured, app, client, &caller.ca, security).await.map_err(|e| match e {
            AppError::Internal(e) => relay(e),
            other => other.into(),
        })?;
        let Some(read) = Engine::new(&st.inner.ui, &caller).app_read(app, client).await? else {
            // An app that does not exist: Java's chain ends empty and answers 200 with no body.
            return Ok(StatusCode::OK.into_response());
        };
        if !analytics::analytics_enabled(&read.entity) {
            return Err(crate::catalogue::error(StatusCode::FORBIDDEN, analytics::NOT_ENABLED, &[]).into());
        }
        let zone = match analytics::requested_zone(&body) {
            Some(_) => resolve_time_zone(&body, None)?,
            None => {
                let record = security.client_by_code(client).await.map_err(relay)?;
                resolve_time_zone(&body, record.as_ref())?
            }
        };
        let request = engine_request(&body, app, client, &zone);
        let key = analytics::cache_key(&request);
        let answer = st
            .inner
            .analytics
            .get_or_load(analytics::CACHE_NAME_ANALYTICS_QUERY, key, || async {
                let url = format!("{}/q", cfg.analytics_engine_url.trim_end_matches('/'));
                let resp = st
                    .inner
                    .http
                    .post(&url)
                    .header(header::AUTHORIZATION, format!("Bearer {}", cfg.analytics_engine_secret))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(overridable::json::to_compact(&JValue::Object(request.clone())))
                    .send()
                    .await
                    .map_err(|e| unknown(StatusCode::INTERNAL_SERVER_ERROR, &format!("{e}")))?;
                let status = resp.status();
                if !status.is_success() {
                    let reason = uripath::reason_phrase(status.as_u16()).or(status.canonical_reason()).unwrap_or("");
                    return Err(unknown(StatusCode::INTERNAL_SERVER_ERROR, &format!("{} {reason} from POST {url}", status.as_u16())));
                }
                let bytes = resp.bytes().await.map_err(|e| unknown(StatusCode::INTERNAL_SERVER_ERROR, &format!("{e}")))?;
                if bytes.is_empty() {
                    return Ok::<_, Fail>(None);
                }
                let v = overridable::json::parse(&bytes).map_err(|e| unknown(StatusCode::INTERNAL_SERVER_ERROR, &format!("{e}")))?;
                Ok(Some(Arc::new(Some(v))))
            })
            .await?;
        Ok(match answer.and_then(|a| (*a).clone()) {
            Some(v) => crate::respond::json_ok(&v),
            None => StatusCode::OK.into_response(),
        })
    }
    .await;
    finish(r, "/api/ui/analytics/query")
}

// ---------------------------------------------------------------- UICacheController

/// `GET /api/ui/internal/cache`: the names of the caches this instance holds.
async fn cache_names(State(st): State<ShellState>, h: HeaderMap) -> Response {
    let r = async {
        caller(&st, &h).await?;
        let names = st.inner.ui.inner().cache.local_cache_names();
        Ok(crate::respond::json_ok(&JValue::Array(names.into_iter().map(|(n, _)| JValue::Str(n)).collect())))
    }
    .await;
    finish(r, "/api/ui/internal/cache")
}

/// `GET /api/ui/internal/cache/stats`.
async fn cache_stats(State(st): State<ShellState>, h: HeaderMap) -> Response {
    let r = async {
        caller(&st, &h).await?;
        let mut out = JMap::new();
        for (name, s) in st.inner.ui.inner().cache.local_cache_stats() {
            let requests = s.hits + s.misses;
            let mut one = JMap::new();
            one.insert("entries".into(), JValue::Int(s.entries as i64));
            // No weigher: Caffeine reports -1 then.
            one.insert("weightedBytes".into(), JValue::Int(-1));
            one.insert("hitCount".into(), JValue::Int(s.hits as i64));
            one.insert("missCount".into(), JValue::Int(s.misses as i64));
            let rate = if requests == 0 { 1.0 } else { s.hits as f64 / requests as f64 };
            one.insert("hitRate".into(), JValue::Float(rate));
            one.insert("evictionCount".into(), JValue::Int(s.evictions as i64));
            out.insert(name, JValue::Object(one));
        }
        Ok(crate::respond::json_ok(&JValue::Object(out)))
    }
    .await;
    finish(r, "/api/ui/internal/cache/stats")
}

/// `DELETE /api/ui/internal/cache/{cacheName}`.
async fn cache_reset_named(State(st): State<ShellState>, Path(name): Path<String>, h: HeaderMap) -> Response {
    let r = async {
        caller(&st, &h).await?;
        st.inner.ui.inner().cache.evict_all_everywhere(&name).await;
        Ok(crate::respond::json_ok(&JValue::Bool(true)))
    }
    .await;
    finish(r, "/api/ui/internal/cache/{cacheName}")
}

/// `CacheService.evictAllCaches`: every `<prefix>-*` hash in Redis is announced and dropped
/// (each instance drops its copies when it hears); `None` when there was nothing to drop.
async fn evict_all_caches(st: &ShellState) -> Option<bool> {
    let cache = &st.inner.ui.inner().cache;
    // The Rust copies are local only and may hold caches Redis has never seen.
    cache.clear_local();
    let Some(client) = &st.inner.redis else { return Some(true) };
    let mut conn = match client.get_multiplexed_async_connection().await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "redis unavailable for evictAllCaches");
            return Some(false);
        }
    };
    let keys: Vec<String> = match redis::cmd("KEYS").arg(format!("{}-*", cache.prefix())).query_async(&mut conn).await {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!(error = %e, "KEYS failed");
            return Some(false);
        }
    };
    if keys.is_empty() {
        return None;
    }
    for k in keys {
        let channel = &st.inner.cfg.redis.eviction_channel;
        let published: redis::RedisResult<i64> = redis::cmd("PUBLISH").arg(channel).arg(format!("{k}:*")).query_async(&mut conn).await;
        let deleted: redis::RedisResult<i64> = redis::cmd("DEL").arg(&k).query_async(&mut conn).await;
        if let Err(e) = published.and(deleted) {
            tracing::warn!(cache = k, error = %e, "eviction not propagated");
        }
    }
    Some(true)
}

pub use crate::ssr::ssr_message;

/// `SSRCacheEvictionService.publishInvalidation`: `false` without Redis or when it fails.
pub async fn ssr_publish(st: &ShellState, message: &str) -> bool {
    let Some(client) = &st.inner.redis else {
        tracing::warn!("SSR cache eviction skipped: Redis pub/sub not configured");
        return false;
    };
    let r: redis::RedisResult<i64> = match client.get_multiplexed_async_connection().await {
        Ok(mut c) => redis::cmd("PUBLISH").arg(&st.inner.cfg.shell.ssr_channel).arg(message).query_async(&mut c).await,
        Err(e) => Err(e),
    };
    match r {
        Ok(n) => {
            tracing::info!(subscribers = n, "SSR cache invalidation published");
            true
        }
        Err(e) => {
            tracing::error!(error = %e, "SSR cache eviction failed");
            false
        }
    }
}

/// `DELETE /api/ui/internal/cache`.
async fn cache_reset_all(State(st): State<ShellState>, h: HeaderMap) -> Response {
    let r = async {
        caller(&st, &h).await?;
        let all = evict_all_caches(&st).await;
        let message = ssr_message(None, None, None, true, chrono::Utc::now().timestamp_millis());
        let ssr = ssr_publish(&st, &message).await;
        Ok(match all {
            // `Mono.zip` with an empty side is empty: 200 and no body.
            None => StatusCode::OK.into_response(),
            Some(a) => crate::respond::json_ok(&JValue::Bool(a && ssr)),
        })
    }
    .await;
    finish(r, "/api/ui/internal/cache")
}

/// `GET /api/ui/newdeployment`: drops the JS and index caches (by the names Java uses, which
/// name no cache any more), for a signed-in caller.
async fn new_deployment(State(st): State<ShellState>, h: HeaderMap) -> Response {
    let r = async {
        let caller = caller(&st, &h).await?;
        if !caller.authenticated() {
            return Ok(StatusCode::BAD_REQUEST.into_response());
        }
        let cache = &st.inner.ui.inner().cache;
        for name in ["jsCache", "jsMapCache", CACHE_NAME_INDEX] {
            cache.evict_all_everywhere(name).await;
        }
        Ok(crate::respond::json_ok(&JValue::Int(1)))
    }
    .await;
    finish(r, "/api/ui/newdeployment")
}

/// Reads the webpack entry points: a local manifest file, then the CDN's, then the legacy
/// bundles.
pub async fn load_entrypoints(cfg: &ShellConfig, http: &reqwest::Client) -> Vec<String> {
    let file = cfg.shell.asset_manifest_file.trim();
    if !file.is_empty() {
        match std::fs::read(file) {
            Ok(b) => {
                if let Some(e) = crate::shell::index::entrypoints_of(&b) {
                    tracing::info!(source = "file", scripts = e.len(), "asset manifest loaded");
                    return e;
                }
            }
            Err(e) => tracing::warn!(error = %e, "asset manifest file unreadable"),
        }
    }
    let cdn = cfg.shell.cdn_host_name.trim();
    if !cdn.is_empty() {
        let url = format!("https://{cdn}/js/dist/asset-manifest.json");
        match http.get(&url).timeout(Duration::from_secs(30)).send().await {
            Ok(r) if r.status().is_success() => {
                if let Ok(b) = r.bytes().await {
                    if let Some(e) = crate::shell::index::entrypoints_of(&b) {
                        tracing::info!(source = "CDN", scripts = e.len(), "asset manifest loaded");
                        return e;
                    }
                }
            }
            Ok(r) => tracing::warn!(status = %r.status(), url, "asset manifest not loaded"),
            Err(e) => tracing::warn!(error = %e, url, "asset manifest not loaded"),
        }
    }
    tracing::info!("using the legacy bundles (vendors.js, index.js)");
    crate::shell::index::fallback_entrypoints()
}
