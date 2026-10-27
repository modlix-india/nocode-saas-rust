//! `NotificationController` behind commons2's servlet security, as the Java service answers.
//!
//! | Route | Answer |
//! |---|---|
//! | `GET /api/notification/notifications` | a page of the caller's in-app notifications (marked read, unless `markRead=false`) |
//! | `GET /api/notification/subscribe?appCode=` | the SSE stream (`init`, then `notification` events and keepalives) |
//! | `GET /api/notification/new` | the caller's unread count |
//! | `POST /api/notification/read?appCode=` | marks the caller's `{"ids": [...]}` or `{"all": true}` read (Rust only) |
//! | `GET /api/notification/preference?appCode=[&userId=]` | a preference map |
//! | `POST /api/notification/preference?appCode=[&userId=]` | stores a preference map |
//!
//! Around them, what Spring does: CORS for any origin (preflights answered before security),
//! the caller from security on every request, a 403 for anyone not signed in (OPTIONS
//! excepted), and `Allow` answers to OPTIONS. Errors are coded (`crate::errors`): the 403 asks
//! to sign in, and a request Spring cannot bind, an unsupported method and an unmapped path
//! answer the 4xx that names the problem where Java's `ControllerAdvice` answered its catch-all
//! 500 (DIFFERENCES.md, N14).

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::Router;
use connections::java::json::jackson_pretty;
use platform::error::{input, Coded};
use platform::http::{spring_security_headers, with_route};
use platform::messages::CallerHint;
use platform::security::{CallerContext, ContextAuthentication, SecurityClient, SecurityRefused};
use serde_json::{Map, Value};

use crate::calls::to_failure;
use crate::errors::{internal_error, Failure};
use crate::inapp::InAppService;
use crate::preference::PreferenceService;
use crate::spring::{big_integer, Pageable, Params};
use crate::sse::{key, Hub};

pub struct AppState {
    pub security: SecurityClient,
    pub inapp: InAppService,
    pub prefs: PreferenceService,
    pub hub: Arc<Hub>,
    pub server_port: u16,
}

pub type Shared = Arc<AppState>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route {
    Notifications,
    Subscribe,
    New,
    Read,
    Preference,
}

impl Route {
    fn of(path: &str) -> Option<Self> {
        match path {
            "/api/notification/notifications" => Some(Self::Notifications),
            "/api/notification/subscribe" => Some(Self::Subscribe),
            "/api/notification/new" => Some(Self::New),
            "/api/notification/read" => Some(Self::Read),
            "/api/notification/preference" => Some(Self::Preference),
            _ => None,
        }
    }

    fn template(self) -> &'static str {
        match self {
            Self::Notifications => "/api/notification/notifications",
            Self::Subscribe => "/api/notification/subscribe",
            Self::New => "/api/notification/new",
            Self::Read => "/api/notification/read",
            Self::Preference => "/api/notification/preference",
        }
    }

    /// The `Allow` header Spring's OPTIONS handler writes.
    fn allow(self) -> &'static str {
        match self {
            Self::Preference => "GET,HEAD,POST,OPTIONS",
            Self::Read => "POST,OPTIONS",
            _ => "GET,HEAD,OPTIONS",
        }
    }

    fn accepts(self, m: &Method) -> bool {
        match self {
            Self::Read => *m == Method::POST,
            Self::Preference => *m == Method::GET || *m == Method::HEAD || *m == Method::POST,
            _ => *m == Method::GET || *m == Method::HEAD,
        }
    }
}

pub fn router(state: Shared) -> Router {
    platform::http::set_header_style(platform::http::HeaderStyle::Files);
    Router::new().fallback(dispatch).with_state(state).layer(middleware::from_fn(servlet_cors))
}

type Res<T> = Result<T, Failure>;

/// An unmapped path (Java: `NoResourceFoundException`, the catch-all 500).
fn not_found(path: &str) -> Failure {
    Coded::new("COMMON.NOT_FOUND").debug(format!("No static resource {}.", path.trim_start_matches('/'))).into()
}

/// Spring Security's 403 for a caller who is not signed in (this servlet chain has no 401),
/// now with a body asking to sign in, or saying "signed out" when a credential was refused.
fn sign_in_first(debug: String) -> Response {
    Failure::from(Coded::unauthenticated().status(StatusCode::FORBIDDEN).debug(debug)).into_response()
}

fn empty(status: StatusCode) -> Response {
    let mut h = HeaderMap::new();
    spring_security_headers(&mut h, true);
    h.insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
    (status, h).into_response()
}

fn json_body(v: &Value) -> Response {
    let mut h = HeaderMap::new();
    spring_security_headers(&mut h, true);
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    (StatusCode::OK, h, jackson_pretty(v)).into_response()
}

async fn dispatch(State(st): State<Shared>, req: Request) -> Response {
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    let route = Route::of(&path);
    let template = route.map(Route::template).unwrap_or("unmatched");

    // `.requestMatchers(HttpMethod.OPTIONS).permitAll()`: Spring MVC answers OPTIONS itself.
    if method == Method::OPTIONS {
        let resp = match route {
            Some(r) => {
                let mut resp = empty(StatusCode::OK);
                resp.headers_mut().insert(header::ALLOW, HeaderValue::from_static(r.allow()));
                resp.headers_mut().insert("accept-patch", HeaderValue::from_static(""));
                resp
            }
            None => not_found(&path).into_response(),
        };
        return with_route(resp, template);
    }

    let ca = match signed_in(&st, req.headers()).await {
        Ok(ca) => ca,
        Err(resp) => return with_route(resp, template),
    };

    let resp = match route {
        None => Err(not_found(&path)),
        Some(r) if !r.accepts(&method) => Err(Coded::new("COMMON.METHOD_NOT_ALLOWED")
            .param("method", &method)
            .debug(format!("Request method '{method}' is not supported"))
            .into()),
        Some(r) => handle(&st, r, &ca, req).await,
    };
    with_route(resp.unwrap_or_else(IntoResponse::into_response), template)
}

/// `JWTTokenFilter` then `.anyRequest().authenticated()`: the caller from security; anyone not
/// signed in (or a token security turns down) gets Spring Security's 403.
async fn signed_in(st: &AppState, h: &HeaderMap) -> Result<ContextAuthentication, Response> {
    let caller = CallerContext::from_headers(h, st.server_port);
    match st.security.context_authentication(&caller).await {
        Ok(ca) if ca.authenticated => Ok(ca),
        Ok(_) => Err(sign_in_first("Not signed in: Spring Security's 403".into())),
        Err(e) if e.downcast_ref::<SecurityRefused>().is_some() => {
            // The platform client notes the caller only when security answers.
            platform::messages::note_caller(CallerHint { credential_sent: !caller.token.trim().is_empty(), ..Default::default() });
            Err(sign_in_first(format!("security refused the credential: {e:#}")))
        }
        Err(e) => Err(internal_error(e).into_response()),
    }
}

fn header_str(h: &HeaderMap, name: &str) -> Option<String> {
    let all: Vec<&str> = h.get_all(name).iter().filter_map(|v| v.to_str().ok()).collect();
    (!all.is_empty()).then(|| all.join(","))
}

/// A required `@RequestParam String`.
fn required(p: &Params, name: &str) -> Res<String> {
    p.string(name).ok_or_else(|| {
        input::param_missing(name)
            .debug(format!("Required request parameter '{name}' for method parameter type String is not present"))
            .into()
    })
}

/// `@RequestParam(required = false) BigInteger userId`.
fn user_id(p: &Params) -> Res<Option<i128>> {
    big_integer(p.first("userId")).map_err(|why| input::param_invalid("userId", Some("a whole number")).debug(why).into())
}

async fn handle(st: &AppState, r: Route, ca: &ContextAuthentication, req: Request) -> Res<Response> {
    let params = Params::from_query(req.uri().query());
    let debug = header_str(req.headers(), "x-debug");
    let uid = ca.user.id;
    match (r, req.method() == Method::POST) {
        (Route::Notifications, _) => {
            // StringUtil.safeValueOf(paramAppCode, headerAppCode).
            let app = params.string("appCode").or_else(|| header_str(req.headers(), "appcode"));
            let pageable = Pageable::from_params(&params);
            let mark_read = !params.string("markRead").is_some_and(|v| v.eq_ignore_ascii_case("false"));
            let page = st
                .inapp
                .read(app.as_deref(), params.string("type").as_deref(), params.string("category").as_deref(), &pageable, uid, mark_read)
                .await
                .map_err(internal_error)?;
            Ok(json_body(&page))
        }
        (Route::Read, _) => {
            let app = params.string("appCode").or_else(|| header_str(req.headers(), "appcode"));
            let body = read_body(req).await?.unwrap_or_default();
            let ids = read_ids(&body)?;
            let n = st.inapp.mark_read(app.as_deref(), ids.as_deref(), uid).await.map_err(internal_error)?;
            Ok(json_body(&serde_json::json!({"read": n})))
        }
        (Route::New, _) => {
            let app = params.string("appCode").or_else(|| header_str(req.headers(), "appcode"));
            let n = st.inapp.check_for_new(app.as_deref(), params.string("type").as_deref(), uid).await.map_err(internal_error)?;
            Ok(json_body(&Value::from(n)))
        }
        (Route::Subscribe, _) => subscribe(st, &params, req.headers(), uid),
        (Route::Preference, false) => {
            let app = required(&params, "appCode")?;
            let user_id = user_id(&params)?;
            let pref = st.prefs.get(ca, &app, user_id, debug.as_deref()).await.map_err(to_failure)?;
            Ok(json_body(&Value::Object(pref)))
        }
        (Route::Preference, true) => {
            let app = required(&params, "appCode")?;
            let user_id = user_id(&params)?;
            let body = read_body(req).await?;
            match st.prefs.set(ca, &app, user_id, body, debug.as_deref()).await.map_err(to_failure)? {
                Some(m) => Ok(json_body(&Value::Object(m))),
                None => Ok(empty(StatusCode::OK)),
            }
        }
    }
}

/// `POST /read`'s body: `{"all": true}` is every unread row (`None`); otherwise `ids`, a list
/// of whole numbers (strings of digits accepted).
fn read_ids(body: &Map<String, Value>) -> Res<Option<Vec<u64>>> {
    if body.get("all").and_then(Value::as_bool) == Some(true) {
        return Ok(None);
    }
    let bad = || -> Failure { input::param_invalid("ids", Some("a list of notification ids")).debug("ids must be whole numbers").into() };
    let Some(Value::Array(list)) = body.get("ids") else {
        return Err(input::param_missing("ids").debug("give ids, or all: true").into());
    };
    list.iter()
        .map(|v| match v {
            Value::Number(n) => n.as_u64().ok_or_else(bad),
            Value::String(s) => s.trim().parse::<u64>().map_err(|_| bad()),
            _ => Err(bad()),
        })
        .collect::<Res<Vec<u64>>>()
        .map(Some)
}

/// `@RequestBody(required = false) Map<String, Object>`: no body (or JSON `null`) is no value;
/// a body that is not JSON, not an object, or not declared as JSON is a binding error, said by
/// the code that names it.
async fn read_body(req: Request) -> Res<Option<Map<String, Value>>> {
    let content_type = req.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).map(str::to_string);
    let bytes = to_bytes(req.into_body(), 16 * 1024 * 1024).await.map_err(|e| {
        let detail = format!("{e:#}");
        let code = if detail.contains("length limit") { "COMMON.PAYLOAD_TOO_LARGE" } else { "COMMON.BODY_UNREADABLE" };
        Failure::from(Coded::new(code).debug(detail))
    })?;
    let is_json = content_type.as_deref().is_some_and(|ct| {
        let mime = ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
        mime == "application/json" || mime.ends_with("+json")
    });
    if bytes.is_empty() {
        return Ok(None);
    }
    if !is_json {
        let detail = format!("Content-Type '{}' is not supported", content_type.as_deref().unwrap_or("application/octet-stream"));
        return Err(Coded::new("COMMON.BODY_NOT_JSON").status(StatusCode::UNSUPPORTED_MEDIA_TYPE).debug(detail).into());
    }
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(Value::Null) => Ok(None),
        Ok(Value::Object(m)) => Ok(Some(m)),
        Ok(_) => Err(Coded::new("COMMON.BODY_INVALID")
            .param("expected", "an object")
            .debug("JSON parse error: Cannot deserialize value of type `java.util.LinkedHashMap`")
            .into()),
        Err(e) => Err(input::body_unreadable(None).debug(format!("JSON parse error: {e}")).into()),
    }
}

/// `subscribe`: registers the stream under `"<userId>-<appCode>"` and answers with its headers.
fn subscribe(st: &AppState, params: &Params, h: &HeaderMap, user_id: u64) -> Res<Response> {
    // `produces = text/event-stream`: a request that accepts no event stream finds no handler.
    if let Some(accept) = h.get(header::ACCEPT).and_then(|v| v.to_str().ok()) {
        let ok = accept.split(',').any(|a| {
            let m = a.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
            m.is_empty() || m == "*/*" || m == "text/*" || m == "text/event-stream"
        });
        if !ok {
            return Err(Coded::new("NOTIF.STREAM_NOT_ACCEPTABLE").debug(format!("No acceptable representation for Accept: {accept}")).into());
        }
    }
    let app = required(params, "appCode")?;
    let stream = st.hub.subscribe(key(user_id, &app));
    let mut resp = Response::new(Body::from_stream(stream));
    let hs = resp.headers_mut();
    spring_security_headers(hs, false);
    hs.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/event-stream;charset=UTF-8"));
    hs.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    hs.insert(header::CONNECTION, HeaderValue::from_static("keep-alive"));
    hs.insert("x-accel-buffering", HeaderValue::from_static("no"));
    Ok(resp)
}

/// The port a URL's scheme implies when it names none.
fn default_port(scheme: &str) -> u16 {
    if scheme.eq_ignore_ascii_case("https") {
        443
    } else {
        80
    }
}

/// `CorsUtils.isCorsRequest` on Tomcat: an `Origin` whose scheme, host or port differs from the
/// request's own (`http`, and the `Host` header's name and port).
fn is_cross_origin(origin: &str, host_header: &str) -> bool {
    let (scheme, rest) = origin.split_once("://").unwrap_or(("", origin));
    let authority = rest.split('/').next().unwrap_or("");
    let (o_host, o_port) = match authority.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => (h, p.parse().unwrap_or(0)),
        _ => (authority, default_port(scheme)),
    };
    let (h_host, h_port) = match host_header.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => (h, p.parse().unwrap_or(0)),
        _ => (host_header, 80),
    };
    !(scheme == "http" && o_host == h_host && o_port == h_port)
}

/// Spring Security's servlet `CorsFilter` with `corsConfigurationSource()` (any origin, header
/// and method, no max age): preflights answered before anything else, the `Vary` trio on every
/// answer, `Access-Control-Allow-Origin: *` on cross-origin ones.
pub async fn servlet_cors(req: Request, next: Next) -> Response {
    let origin = req.headers().get(header::ORIGIN).and_then(|v| v.to_str().ok()).map(str::to_string);
    let host = req.headers().get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let cross = origin.as_deref().is_some_and(|o| is_cross_origin(o, &host));
    let preflight = cross && req.method() == Method::OPTIONS && req.headers().contains_key(header::ACCESS_CONTROL_REQUEST_METHOD);

    let mut resp = if preflight {
        let mut r = empty(StatusCode::OK);
        if let Some(m) = req.headers().get(header::ACCESS_CONTROL_REQUEST_METHOD) {
            r.headers_mut().insert(header::ACCESS_CONTROL_ALLOW_METHODS, m.clone());
        }
        if let Some(rh) = req.headers().get(header::ACCESS_CONTROL_REQUEST_HEADERS).and_then(|v| v.to_str().ok()) {
            let list: Vec<&str> = rh.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
            if let Ok(v) = HeaderValue::from_str(&list.join(", ")) {
                r.headers_mut().insert(header::ACCESS_CONTROL_ALLOW_HEADERS, v);
            }
        }
        r
    } else {
        next.run(req).await
    };
    let h = resp.headers_mut();
    for v in ["Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers"] {
        h.append(header::VARY, HeaderValue::from_static(v));
    }
    if cross {
        h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_and_methods() {
        assert_eq!(Route::of("/api/notification/new"), Some(Route::New));
        assert_eq!(Route::of("/api/notification/new/"), None, "no trailing slash match");
        assert_eq!(Route::of("/api/notification/notifications"), Some(Route::Notifications));
        assert_eq!(Route::of("/api/notification/subscribe"), Some(Route::Subscribe));
        assert_eq!(Route::of("/api/notification/preference"), Some(Route::Preference));
        assert!(Route::Preference.accepts(&Method::POST) && !Route::New.accepts(&Method::POST));
        assert!(Route::New.accepts(&Method::HEAD) && !Route::New.accepts(&Method::DELETE));
        assert_eq!(Route::Preference.allow(), "GET,HEAD,POST,OPTIONS");
        assert_eq!(Route::Subscribe.allow(), "GET,HEAD,OPTIONS");
        for r in [Route::Notifications, Route::Subscribe, Route::New, Route::Preference] {
            assert!(r.template().starts_with("/api/notification/"));
        }
    }

    #[test]
    fn cross_origin_as_tomcat_sees_it() {
        assert!(!is_cross_origin("http://localhost:8007", "localhost:8007"));
        assert!(!is_cross_origin("http://app.local", "app.local"));
        assert!(is_cross_origin("https://app.local", "app.local"), "scheme differs");
        assert!(is_cross_origin("http://x.com", "localhost:8007"));
        assert!(is_cross_origin("http://app.local:81", "app.local"));
        assert!(!is_cross_origin("http://app.local:80", "app.local"));
        assert!(is_cross_origin("null", "app.local"));
        assert_eq!(default_port("HTTPS"), 443);
    }
}
