//! `ApplicationController` + `ApplicationService`: the routes and the calls they make to
//! security, core and ui on the caller's behalf.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use base64::Engine;
use platform::error::{format_message, input, AppError, Coded};
use platform::http::{spring_security_headers, with_route};
use platform::messages::CallerHint;
use platform::security::{CallerContext, ContextAuthentication, SecurityClient, SecurityRefused};
use platform::upstream::Upstream;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::errors::{internal, is_coded_body, Failure, Res};
use crate::index;
use crate::transport::{self, json_app_code_changes, rewrite_modl};

/// Java's `forbidden_create` and `multi_transport_error` texts, for `debugMessage`.
const FORBIDDEN_CREATE: &str = "Cannot create $ for the selected client";
const MULTI_TRANSPORT_ERROR: &str = "Error while creating/updating application";

pub struct AppState {
    pub security: SecurityClient,
    pub security_up: Upstream,
    pub core_up: Upstream,
    pub ui_up: Upstream,
    /// files-manage, for the purge only; `None` (no `[files]` configured) refuses the purge.
    pub files_up: Option<Upstream>,
    pub http: reqwest::Client,
    pub port: u16,
}

pub type Shared = Arc<AppState>;

pub fn router(state: Shared) -> Router {
    Router::new()
        .route("/api/multi/application/{app_code}/index", get(object_index))
        .route("/api/multi/application/{app_code}/search", get(search_objects))
        .route("/api/multi/application/transport", get(transport_export))
        .route("/api/multi/application", post(create_application))
        .route("/api/multi/application/update", post(update_application))
        .route("/api/multi/application/{app_code_or_id}", delete(delete_application))
        .route("/api/multi/purge/client/{code}", delete(purge_client))
        .route("/api/multi/purge/application/{code}", delete(purge_application))
        .with_state(state)
}

/// The headers every route requires, and the caller's own `Authorization` / debug / draft
/// markers and languages, which travel on every call made on the caller's behalf (so an error a
/// service answers is already in the caller's language when multi passes it on).
#[derive(Clone)]
struct Fwd {
    authorization: Option<String>,
    host: String,
    port: String,
    client_code: String,
    app_code: String,
    debug: Option<String>,
    draft: bool,
    accept_language: Option<String>,
}

fn header(h: &HeaderMap, name: &str) -> Option<String> {
    h.get(name).and_then(|v| v.to_str().ok()).map(str::to_string)
}

impl Fwd {
    fn from(h: &HeaderMap) -> Res<Self> {
        let need = |n: &str| {
            header(h, n).ok_or_else(|| {
                Failure::from(platform::error::input::header_missing(n).debug(format!("Required header '{n}' is not present.")))
            })
        };
        Ok(Self {
            authorization: header(h, "authorization"),
            host: need("X-Forwarded-Host")?,
            port: need("X-Forwarded-Port")?,
            client_code: need("clientCode")?,
            app_code: need("appCode")?,
            debug: header(h, "x-debug"),
            draft: header(h, "x-draft").is_some_and(|v| v.eq_ignore_ascii_case("true")),
            accept_language: header(h, "accept-language"),
        })
    }

    /// The same headers with the caller's token as security reported it (`ca.getAccessToken()`).
    fn with_token(&self, token: Option<&str>) -> Self {
        Self { authorization: token.map(str::to_string), ..self.clone() }
    }

    fn apply(&self, mut rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let mut h = HeaderMap::new();
        platform::telemetry::inject_trace_headers(&mut h);
        rb = rb
            .headers(h)
            .header("X-Forwarded-Host", &self.host)
            .header("X-Forwarded-Port", &self.port)
            .header("clientCode", &self.client_code)
            .header("appCode", &self.app_code);
        if let Some(a) = &self.authorization {
            rb = rb.header(header::AUTHORIZATION, a);
        }
        if let Some(d) = &self.debug {
            rb = rb.header("x-debug", d);
        }
        if self.draft {
            rb = rb.header("x-draft", "true");
        }
        if let Some(l) = &self.accept_language {
            rb = rb.header(header::ACCEPT_LANGUAGE, l);
        }
        rb
    }
}

/// `anyRequest().authenticated()` of the reactive services: a caller who is not signed in gets
/// a 401 asking to sign in ("You're signed out" when the token or password sent was refused),
/// with no `WWW-Authenticate` challenge (ISecurityConfiguration, 2026-10-15: a browser answers
/// that challenge with its own sign-in dialog).
async fn authenticate(state: &AppState, h: &HeaderMap) -> Res<ContextAuthentication> {
    let caller = CallerContext::from_headers(h, state.port);
    let ca = match state.security.context_authentication(&caller).await {
        Ok(ca) => ca,
        Err(e) if e.downcast_ref::<SecurityRefused>().is_some() => {
            // The platform client notes the caller only when security answers; a refusal is
            // noted here so the message says "signed out" for a credential that was sent.
            platform::messages::note_caller(CallerHint { credential_sent: !caller.token.trim().is_empty(), ..Default::default() });
            return Err(Coded::unauthenticated().debug(format!("security refused the credential: {e:#}")).into());
        }
        Err(e) => return Err(call_failed("security", "securityContextAuthentication", e)),
    };
    if !ca.authenticated {
        return Err(Coded::unauthenticated().debug("Not signed in").into());
    }
    Ok(ca)
}

/// Every response carries Spring Security's headers. Java adds them only when it finishes the
/// response itself (errors, and bodies over 20 KB as Jackson pretty-prints them), which for the
/// index is most signed-in calls; here they are always there.
fn finish(r: Res<Response>, route: &'static str) -> Response {
    let mut resp = r.unwrap_or_else(IntoResponse::into_response);
    let h = resp.headers_mut();
    let no_cache = !h.contains_key(header::CACHE_CONTROL);
    spring_security_headers(h, no_cache);
    with_route(resp, route)
}

/// The service a call goes to, as people read it ("security", "core", "UI").
fn service_of(what: &str) -> &str {
    match what.split_whitespace().next().unwrap_or("") {
        "ui" => "UI",
        other => other,
    }
}

/// A call that never got an answer: the service is not reachable (503), did not answer in
/// time (504), or the request could not even be built (a fault of ours).
fn call_failed(service: &str, what: &str, e: anyhow::Error) -> Failure {
    let unreachable = e.chain().filter_map(|c| c.downcast_ref::<reqwest::Error>()).find(|r| !r.is_builder() && !r.is_decode());
    match unreachable {
        Some(r) => {
            let coded = Coded::new("MULTI.SERVICE_UNAVAILABLE").param("service", service).debug(format!("{what}: {e:#}"));
            if r.is_timeout() {
                coded.status(StatusCode::GATEWAY_TIMEOUT).into()
            } else {
                coded.into()
            }
        }
        None => internal(format!("{what}: {e:#}")),
    }
}

/// A downstream answered with an error. A coded body (a Rust unit's) is passed on as it came; a
/// Java body's `message` is relayed with the status, as Java's `ControllerAdvice` does
/// (`handleFeignException`); an empty or unreadable body is said plainly by its status.
async fn downstream_error(resp: reqwest::Response, what: &str) -> Failure {
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let body = resp.bytes().await.unwrap_or_default();
    let parsed = serde_json::from_slice::<Value>(&body).ok();
    if let Some(v) = parsed.as_ref().filter(|v| is_coded_body(v)) {
        tracing::warn!(call = what, %status, code = v["code"].as_str().unwrap_or(""), exception_id = %v["exceptionId"], "downstream refused, passed on");
        return Failure::Relayed { status, body };
    }
    if let Some(message) = parsed.as_ref().and_then(|v| v.get("message")).and_then(Value::as_str) {
        tracing::warn!(call = what, %status, message, "downstream refused");
        return AppError::new(status, message).into();
    }
    let detail = format!("{what} answered {status}");
    tracing::warn!(call = what, %status, "downstream refused without a readable body");
    let coded = match status {
        StatusCode::UNAUTHORIZED => Coded::new("COMMON.SIGNED_OUT"),
        StatusCode::FORBIDDEN => Coded::new("COMMON.FORBIDDEN"),
        _ => Coded::new("MULTI.SERVICE_FAILED").param("service", service_of(what)),
    };
    coded.status(status).debug(detail).into()
}

async fn send(rb: reqwest::RequestBuilder, what: &str) -> Res<reqwest::Response> {
    let resp = platform::meter::send_to_service(rb).await.map_err(|e| call_failed(service_of(what), what, e.into()))?;
    if !resp.status().is_success() {
        return Err(downstream_error(resp, what).await);
    }
    Ok(resp)
}

/// Where a service is (a 503 when none is registered).
async fn base(up: &Upstream, service: &str) -> Res<String> {
    base_for(up, service, "").await
}

/// Where a service answers `path`: security's internal routes run in security-internal
/// (`[security] internal_upstream`), the rest in security-admin.
async fn base_for(up: &Upstream, service: &str, path: &str) -> Res<String> {
    up.base_for(path).await.map_err(|e| Coded::new("MULTI.SERVICE_UNAVAILABLE").param("service", service).debug(format!("{service}: {e:#}")).into())
}

/// Feign maps an empty body to an empty Mono.
async fn json_or_empty(resp: reqwest::Response) -> Res<Option<Value>> {
    let bytes = resp.bytes().await.map_err(internal)?;
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(None);
    }
    serde_json::from_slice(&bytes).map(Some).map_err(internal)
}

/// The bytes of a successful answer.
async fn bytes_of(resp: reqwest::Response) -> Res<axum::body::Bytes> {
    resp.bytes().await.map_err(internal)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IndexQuery {
    client_code: Option<String>,
    q: Option<String>,
    #[serde(rename = "type")]
    types: Option<String>,
}

type PathArg = Result<Path<String>, PathRejection>;
type QueryArg<T> = Result<Query<T>, QueryRejection>;
type BodyArg = Result<Option<Json<Definition>>, JsonRejection>;

async fn object_index(State(s): State<Shared>, app_code: PathArg, q: QueryArg<IndexQuery>, h: HeaderMap) -> Response {
    finish(index_impl(&s, app_code, q, false, &h).await, "/api/multi/application/{appCode}/index")
}

async fn search_objects(State(s): State<Shared>, app_code: PathArg, q: QueryArg<IndexQuery>, h: HeaderMap) -> Response {
    finish(index_impl(&s, app_code, q, true, &h).await, "/api/multi/application/{appCode}/search")
}

/// The caller first (an anonymous caller learns nothing else), then the headers, then the
/// request's own values: a value that does not read is a 400 naming it.
async fn index_impl(s: &AppState, app_code: PathArg, q: QueryArg<IndexQuery>, search: bool, h: &HeaderMap) -> Res<Response> {
    authenticate(s, h).await?;
    let fwd = Fwd::from(h)?;
    let Path(app_code) = app_code.map_err(AppError::from)?;
    let Query(q) = q.map_err(AppError::from)?;
    let app_code = app_code.as_str();
    let query = if search { q.q.clone() } else { None };

    let half = |up: &Upstream, path: String| {
        let (up, http, fwd, client) = (up.clone(), s.http.clone(), fwd.clone(), q.client_code.clone());
        async move {
            let result: anyhow::Result<Map<String, Value>> = async {
                let base = up.base().await?;
                let mut rb = http.get(format!("{base}{path}"));
                if let Some(c) = &client {
                    rb = rb.query(&[("forClientCode", c)]);
                }
                let resp = platform::meter::send_to_service(fwd.apply(rb)).await?.error_for_status()?;
                let v: Value = resp.json().await?;
                Ok(v.as_object().cloned().unwrap_or_default())
            }
            .await;
            result
        }
    };
    let (ui, core) = tokio::join!(
        half(&s.ui_up, format!("/api/ui/applications/internal/index/{app_code}")),
        half(&s.core_up, format!("/api/core/index/internal/{app_code}")),
    );
    let degrade = |service: &str, r: anyhow::Result<Map<String, Value>>| {
        r.unwrap_or_else(|e| {
            tracing::error!(service, app_code, error = %e, "object index: service did not answer");
            Map::new()
        })
    };
    let ui = degrade("ui", ui);
    let core = degrade("core", core);

    let types = index::parse_types(q.types.as_deref());
    let body = index::build(app_code, q.client_code.as_deref(), &ui, &core, query.as_deref(), &types);
    Ok(Json(body).into_response())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransportQuery {
    app_code: Option<String>,
    client_code: Option<String>,
}

async fn transport_export(State(s): State<Shared>, q: QueryArg<TransportQuery>, h: HeaderMap) -> Response {
    finish(transport_impl(&s, q, &h).await, "/api/multi/application/transport")
}

async fn transport_impl(s: &AppState, q: QueryArg<TransportQuery>, h: &HeaderMap) -> Res<Response> {
    let ca = authenticate(s, h).await?;
    let fwd = Fwd::from(h)?;
    let Query(q) = q.map_err(AppError::from)?;
    let app_code = q.app_code.ok_or_else(|| input::param_missing("appCode").debug("Required parameter 'appCode' is not present."))?;

    if !ca.is_system_client() {
        let access = s.security.has_write_access(&app_code, ca.client_code()).await.map_err(|e| call_failed("security", "hasWriteAccess", e))?;
        if !access {
            let java = format_message(FORBIDDEN_CREATE, &["transport"]);
            return Err(Coded::new("MULTI.TRANSPORT_EXPORT_FORBIDDEN").debug(format!("[forbidden_create] {java} (appCode={app_code})")).into());
        }
    }
    let as_caller = fwd.with_token(ca.access_token.as_deref());
    let client_code = q.client_code.unwrap_or_else(|| ca.client_code().to_string());

    let sec_base = base(&s.security_up, "security").await?;
    let security = send(
        as_caller.apply(s.http.get(format!("{sec_base}/api/security/transports/makeTransport")).query(&[("applicationCode", &app_code)])),
        "security makeTransport",
    )
    .await?;
    let security = json_or_empty(security).await?;

    let body = json!({"appCode": app_code, "clientCode": client_code});
    let core_base = base(&s.core_up, "core").await?;
    let core = bytes_of(
        send(as_caller.apply(s.http.post(format!("{core_base}/api/core/transports/internal/makeTransport")).json(&body)), "core makeTransport")
            .await?,
    )
    .await?;
    let ui_base = base(&s.ui_up, "UI").await?;
    let ui = bytes_of(
        send(as_caller.apply(s.http.post(format!("{ui_base}/api/ui/transports/internal/makeTransport")).json(&body)), "ui makeTransport").await?,
    )
    .await?;

    let security_bytes = match &security {
        None => b"{}".to_vec(),
        Some(v) => serde_json::to_vec(v).map_err(internal)?,
    };
    let zip = transport::export_zip(&security_bytes, &core, &ui).map_err(|e| internal(format!("writing the transport zip: {e:#}")))?;

    let mut resp = Response::new(Body::from(zip));
    let rh = resp.headers_mut();
    rh.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/zip"));
    if let Ok(v) = HeaderValue::from_str(&format!("inline; filename={app_code}_{}.modl", fwd.client_code)) {
        rh.insert(header::CONTENT_DISPOSITION, v);
    }
    Ok(resp)
}

/// `MultiApp` / `MultiAppUpdate`.
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct Definition {
    app_id: Option<Value>,
    app_code: Option<String>,
    app_name: Option<String>,
    client_id: Option<Value>,
    app_access_type: Option<String>,
    app_type: Option<String>,
    is_base_update: Option<bool>,
    transport_definition: Option<Map<String, Value>>,
    encoded_modl: Option<String>,
    #[serde(rename = "transportDefinitionURL")]
    transport_definition_url: Option<String>,
}

impl Definition {
    fn has_definition(&self) -> bool {
        self.transport_definition_url.as_deref().is_some_and(|u| !u.trim().is_empty())
            || self.transport_definition.as_ref().is_some_and(|d| !d.is_empty())
            || self.encoded_modl.as_deref().is_some_and(|m| !m.trim().is_empty())
    }
}

/// Security's `App` as multi's `App` DTO writes it: its fields in declaration order with nulls
/// left out (the services' Jackson is `NON_NULL` for objects), and `template` (from the
/// `isTemplate` getter) last.
fn app_json(v: &Value) -> Value {
    let mut out = Map::new();
    for k in [
        "id",
        "clientId",
        "appName",
        "appCode",
        "appType",
        "appAccessType",
        "clientCode",
        "explicitClientId",
        "explicitOwnerClientCode",
        "status",
    ] {
        if let Some(val) = v.get(k).filter(|x| !x.is_null()) {
            out.insert(k.to_string(), val.clone());
        }
    }
    let template = v.get("template").or_else(|| v.get("isTemplate")).cloned().unwrap_or(json!(false));
    out.insert("template".into(), template);
    Value::Object(out)
}

async fn create_application(State(s): State<Shared>, h: HeaderMap, body: BodyArg) -> Response {
    finish(create_impl(&s, &h, body).await, "/api/multi/application")
}

/// The body as `MultiApp` / `MultiAppUpdate`: none, one that is not JSON, or one whose values
/// do not fit is a 400 naming what is wrong (axum's reader names the field); a body that is
/// not declared as JSON is Spring's 415.
fn parse_def(body: BodyArg) -> Res<Definition> {
    let body = body.map_err(|r| {
        let unsupported = matches!(r, JsonRejection::MissingJsonContentType(_));
        match AppError::from(r) {
            AppError::Coded(c) if unsupported => AppError::from(c.status(StatusCode::UNSUPPORTED_MEDIA_TYPE)),
            e => e,
        }
    })?;
    match body {
        Some(Json(def)) => Ok(def),
        None => Err(input::body_missing().debug("Required request body is missing").into()),
    }
}

async fn create_impl(s: &AppState, h: &HeaderMap, body: BodyArg) -> Res<Response> {
    let ca = authenticate(s, h).await?;
    let fwd = Fwd::from(h)?;
    let def = parse_def(body)?;
    if !ca.has_authority("Authorities.Application_CREATE") {
        let java = format_message(FORBIDDEN_CREATE, &["Application"]);
        return Err(Coded::new("MULTI.APP_CREATE_FORBIDDEN").debug(format!("[forbidden_create] {java} (needs Authorities.Application_CREATE)")).into());
    }
    let as_caller = fwd.with_token(ca.access_token.as_deref());
    let sec_base = base(&s.security_up, "security").await?;

    if let Some(id) = def.app_id.as_ref().filter(|v| !v.is_null()) {
        let id = id.as_str().map(str::to_string).unwrap_or_else(|| id.to_string());
        let resp = send(as_caller.apply(s.http.get(format!("{sec_base}/api/security/applications/{id}"))), "security getAppById").await?;
        let app = json_or_empty(resp).await?.unwrap_or(Value::Null);
        return Ok(Json(app_json(&app)).into_response());
    }

    let access = match def.app_access_type.as_deref() {
        None | Some("") | Some("OWN") => "OWN".to_string(),
        Some(other) if other.trim().is_empty() => "OWN".to_string(),
        Some(other) => other.to_string(),
    };
    let sec_app = json!({
        "appCode": def.app_code,
        "appName": def.app_name,
        "appType": def.app_type,
        "appAccessType": access,
        "clientId": ca.user.client_id,
    });
    let resp = send(
        // Feign's `/api/security/applications/` reaches security without the trailing slash;
        // security answers 404 with it.
        as_caller.apply(s.http.post(format!("{sec_base}/api/security/applications")).json(&sec_app)),
        "security createApp",
    )
    .await?;
    let new_app = json_or_empty(resp).await?.unwrap_or(Value::Null);
    let new_code = new_app.get("appCode").and_then(Value::as_str).unwrap_or("").to_string();
    add_definition(s, &as_caller, &new_code, Some(true), &def).await?;
    Ok(Json(app_json(&new_app)).into_response())
}

async fn update_application(State(s): State<Shared>, h: HeaderMap, body: BodyArg) -> Response {
    finish(update_impl(&s, &h, body).await, "/api/multi/application/update")
}

async fn update_impl(s: &AppState, h: &HeaderMap, body: BodyArg) -> Res<Response> {
    let ca = authenticate(s, h).await?;
    let fwd = Fwd::from(h)?;
    let def = parse_def(body)?;
    let as_caller = fwd.with_token(ca.access_token.as_deref());
    let app_code = def.app_code.clone().unwrap_or_default();
    let done = add_definition(s, &as_caller, &app_code, def.is_base_update, &def).await?;
    Ok(Json(json!(done)).into_response())
}

/// The definition behind `transportDefinitionURL`: an address that cannot be reached, answers
/// an error or sends more than 50 MB (Java's codec limit) is the caller's to fix, a 400.
async fn download_definition(s: &AppState, url: &str) -> Res<Vec<u8>> {
    let failed = |status: Option<StatusCode>, detail: String| {
        let c = Coded::new("MULTI.DEFINITION_URL_FAILED").debug(format!("transport definition URL {url}: {detail}"));
        Failure::from(match status {
            Some(st) => c.param("status", st.as_u16()),
            None => c,
        })
    };
    // A caller's address: timed under one fixed target, never by its host or path.
    let resp = platform::meter::send("definition-url", s.http.get(url)).await.map_err(|e| failed(None, e.to_string()))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(failed(Some(StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY)), format!("answered {status}")));
    }
    let b = resp.bytes().await.map_err(|e| failed(None, e.to_string()))?;
    if b.len() > 50 * 1024 * 1024 {
        return Err(Coded::new("MULTI.DEFINITION_TOO_LARGE").debug(format!("transport definition URL {url}: {} bytes", b.len())).into());
    }
    Ok(b.to_vec())
}

/// A definition that is neither JSON nor a readable `.modl` zip.
fn unreadable(detail: impl std::fmt::Display) -> Failure {
    Coded::new("MULTI.DEFINITION_UNREADABLE").debug(format!("[multi_transport_error] {MULTI_TRANSPORT_ERROR} ({detail})")).into()
}

/// `addDefinition` / the body of `updateApplication`: fetch or decode the definition, find the
/// client it applies as, and apply the security, core and ui parts in that order.
async fn add_definition(s: &AppState, fwd: &Fwd, app_code: &str, is_base: Option<bool>, def: &Definition) -> Res<bool> {
    if !def.has_definition() {
        return Ok(false);
    }
    let bytes: Vec<u8> = if let Some(url) = def.transport_definition_url.as_deref().filter(|u| !u.trim().is_empty()) {
        download_definition(s, url).await?
    } else if let Some(m) = def.encoded_modl.as_deref().filter(|m| !m.trim().is_empty()) {
        // Java base64-ENCODES the already encoded upload here, so this path never worked there.
        base64::engine::general_purpose::STANDARD.decode(m.trim()).map_err(|e| {
            Failure::from(Coded::new("MULTI.ENCODED_MODL_INVALID").debug(format!("[multi_transport_error] {MULTI_TRANSPORT_ERROR} (encodedModl: {e})")))
        })?
    } else {
        serde_json::to_vec(&def.transport_definition).map_err(internal)?
    };

    let sec_base = base(&s.security_up, "security").await?;
    let resp = send(
        fwd.apply(s.http.get(format!("{sec_base}/api/security/applications/findBaseClientCode/{app_code}"))),
        "security findBaseClientCode",
    )
    .await?;
    // An empty answer (an app the caller's own client owns) leaves the client code null, as in
    // Java; the receiving services then use the caller's client.
    let cc: Option<String> = json_or_empty(resp)
        .await?
        .and_then(|v| v.get(0).and_then(Value::as_str).map(str::to_string));
    let cc = cc.as_deref();

    let (security, core, ui, json_mode) = if transport::is_json(&bytes) {
        let mut definition: Map<String, Value> = serde_json::from_slice(&bytes).map_err(|e| unreadable(format!("JSON: {e}")))?;
        let security = json_app_code_changes(definition.remove("security"), app_code, cc);
        let core = json_app_code_changes(definition.remove("core"), app_code, cc);
        let ui = json_app_code_changes(definition.remove("ui"), app_code, cc);
        let enc = |v: Option<Value>| serde_json::to_vec(&v.unwrap_or(Value::Null)).unwrap_or_default();
        (security, enc(core), enc(ui), true)
    } else {
        let parts = transport::read_modl(&bytes).map_err(|e| unreadable(format!("{e:#}")))?;
        let security = json_app_code_changes(parts.security, app_code, cc);
        let core = rewrite_modl(&parts.core, app_code, cc).map_err(|e| unreadable(format!("core.cmodl: {e:#}")))?;
        let ui = rewrite_modl(&parts.ui, app_code, cc).map_err(|e| unreadable(format!("ui.umodl: {e:#}")))?;
        (security, core, ui, false)
    };

    send(
        fwd.apply(s.http.post(format!("{sec_base}/api/security/transports/createAndApply")).json(&security.unwrap_or(Value::Null))),
        "security createAndApply",
    )
    .await?;

    let mut params: Vec<(&str, String)> = vec![
        ("isJson", json_mode.to_string()),
        ("applicationCode", app_code.to_string()),
    ];
    if let Some(b) = is_base {
        params.push(("isForBaseApp", b.to_string()));
    }
    let core_base = base(&s.core_up, "core").await?;
    let mut core_params = params.clone();
    core_params.push(("fileName", if json_mode { "core.json" } else { "core.cmodl" }.into()));
    send(
        fwd.apply(s.http.post(format!("{core_base}/api/core/transports/internal/createAndApply")).query(&core_params).body(core)),
        "core createAndApply",
    )
    .await?;
    let ui_base = base(&s.ui_up, "UI").await?;
    let mut ui_params = params;
    ui_params.push(("fileName", if json_mode { "ui.json" } else { "ui.umodl" }.into()));
    send(
        fwd.apply(s.http.post(format!("{ui_base}/api/ui/transports/internal/createAndApply")).query(&ui_params).body(ui)),
        "ui createAndApply",
    )
    .await?;
    Ok(true)
}

async fn delete_application(State(s): State<Shared>, app_code_or_id: PathArg, h: HeaderMap) -> Response {
    finish(delete_impl(&s, app_code_or_id, &h).await, "/api/multi/application/{appCodeOrId}")
}

async fn delete_impl(s: &AppState, app_code_or_id: PathArg, h: &HeaderMap) -> Res<Response> {
    let ca = authenticate(s, h).await?;
    let fwd = Fwd::from(h)?;
    let Path(app_code_or_id) = app_code_or_id.map_err(AppError::from)?;
    let app_code_or_id = app_code_or_id.as_str();
    let as_caller = fwd.with_token(ca.access_token.as_deref());
    let sec_base = base(&s.security_up, "security").await?;

    let app = if app_code_or_id.parse::<u64>().is_ok() {
        let resp = send(
            as_caller.apply(s.http.get(format!("{sec_base}/api/security/applications/{app_code_or_id}"))),
            "security getAppById",
        )
        .await?;
        json_or_empty(resp).await?
    } else {
        let path = format!("/api/security/applications/internal/appCode/{app_code_or_id}");
        let internal_base = base_for(&s.security_up, "security", &path).await?;
        let resp = send(
            s.http.get(format!("{internal_base}{path}")),
            "security getAppByCode",
        )
        .await?;
        json_or_empty(resp).await?
    };
    let Some(app) = app else { return Ok(Json(json!(false)).into_response()) };
    let id = app.get("id").map(|v| v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string())).unwrap_or_default();
    let code = app.get("appCode").and_then(Value::as_str).unwrap_or("").to_string();

    if app.get("status").and_then(Value::as_str) == Some("ACTIVE") {
        let resp = send(as_caller.apply(s.http.delete(format!("{sec_base}/api/security/applications/{id}"))), "security deleteByAppId").await?;
        let done = json_or_empty(resp).await?.and_then(|v| v.as_bool()).unwrap_or(false);
        return Ok(Json(json!(done)).into_response());
    }

    let flag = |v: Option<Value>| v.and_then(|v| v.as_bool()).unwrap_or(false);
    let ui_base = base(&s.ui_up, "UI").await?;
    let x = flag(json_or_empty(send(as_caller.apply(s.http.delete(format!("{ui_base}/api/ui")).query(&[("deleteAppCode", &code)])), "ui deleteAll").await?).await?);
    let core_base = base(&s.core_up, "core").await?;
    let y = flag(json_or_empty(send(as_caller.apply(s.http.delete(format!("{core_base}/api/core")).query(&[("deleteAppCode", &code)])), "core deleteAll").await?).await?);
    let z = flag(json_or_empty(send(as_caller.apply(s.http.delete(format!("{sec_base}/api/security/applications/everything/{id}"))), "security deleteEverything").await?).await?);
    Ok(Json(json!(x && y && z)).into_response())
}

// ── Clean-slate purges (no Java counterpart) ──────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PurgeQuery {
    dry_run: Option<bool>,
}

/// `DELETE /api/multi/purge/client/{code}?dryRun=`: the client, its users and every row, definition
/// and tenant database it has, in security, core and ui. A dry run unless `dryRun=false`.
async fn purge_client(State(s): State<Shared>, code: PathArg, q: QueryArg<PurgeQuery>, h: HeaderMap) -> Response {
    finish(purge_impl(&s, Purge::Client, code, q, &h).await, "/api/multi/purge/client/{code}")
}

/// `DELETE /api/multi/purge/application/{code}?dryRun=`: the app and everything of it, for every
/// client. A dry run unless `dryRun=false`.
async fn purge_application(State(s): State<Shared>, code: PathArg, q: QueryArg<PurgeQuery>, h: HeaderMap) -> Response {
    finish(purge_impl(&s, Purge::App, code, q, &h).await, "/api/multi/purge/application/{code}")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Purge {
    Client,
    App,
}

impl Purge {
    /// Each service's purge route for `code`: security's, core's, ui's, files'.
    fn paths(self, code: &str) -> (String, String, String, String) {
        let (sec, other) = match self {
            Purge::Client => ("clients", "client"),
            Purge::App => ("applications", "app"),
        };
        (
            format!("/api/security/{sec}/purge/{code}"),
            format!("/api/core/purge/{other}/{code}"),
            format!("/api/ui/purge/{other}/{code}"),
            format!("/api/files/purge/{other}/{code}"),
        )
    }
}

/// A code goes into three URLs as it is: letters, digits and `_` only.
fn purge_code_ok(code: &str) -> bool {
    !code.is_empty() && code.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Security answers first, always as a dry run, so a purge it refuses (a client that still owns
/// apps, manages clients or has billing rows; an app others depend on) never reaches core or ui.
/// Then core (definitions and tenant databases), ui (definitions), files (the stored files and
/// their rows) and last security (the rows: files asks security who manages the client, so it
/// runs while the client is still there), each with the caller's `dryRun`. The reports come back
/// side by side. Without a `[files]` upstream the purge is refused, not run without files.
async fn purge_impl(s: &AppState, kind: Purge, code: PathArg, q: QueryArg<PurgeQuery>, h: &HeaderMap) -> Res<Response> {
    let ca = authenticate(s, h).await?;
    let fwd = Fwd::from(h)?;
    let Path(code) = code.map_err(AppError::from)?;
    let Query(q) = q.map_err(AppError::from)?;
    if !purge_code_ok(&code) {
        return Err(Failure::from(input::param_invalid("code", Some("letters, digits and _"))));
    }
    let dry_run = q.dry_run != Some(false);
    let as_caller = fwd.with_token(ca.access_token.as_deref());
    let (sec_path, core_path, ui_path, files_path) = kind.paths(&code);
    let Some(files_up) = &s.files_up else {
        return Err(Coded::new("MULTI.SERVICE_UNAVAILABLE").param("service", "files").debug("multi has no [files] upstream configured").into());
    };
    let sec_base = base_for(&s.security_up, "security", &sec_path).await?;
    let call = |base: &str, path: &str, dry: bool| {
        as_caller.apply(s.http.delete(format!("{base}{path}")).query(&[("dryRun", if dry { "true" } else { "false" })]))
    };

    let check = json_or_empty(send(call(&sec_base, &sec_path, true), "security purge check").await?).await?;
    let core_base = base_for(&s.core_up, "core", &core_path).await?;
    let core = json_or_empty(send(call(&core_base, &core_path, dry_run), "core purge").await?).await?;
    let ui_base = base_for(&s.ui_up, "UI", &ui_path).await?;
    let ui = json_or_empty(send(call(&ui_base, &ui_path, dry_run), "ui purge").await?).await?;
    let files_base = base_for(files_up, "files", &files_path).await?;
    let files = json_or_empty(send(call(&files_base, &files_path, dry_run), "files purge").await?).await?;
    let security = if dry_run {
        check
    } else {
        json_or_empty(send(call(&sec_base, &sec_path, false), "security purge").await?).await?
    };
    Ok(Json(json!({"dryRun": dry_run, "security": security, "core": core, "ui": ui, "files": files})).into_response())
}

#[cfg(test)]
mod purge_tests {
    use super::*;

    #[test]
    fn purge_paths_per_service() {
        assert_eq!(
            Purge::Client.paths("ABC1"),
            (
                "/api/security/clients/purge/ABC1".into(),
                "/api/core/purge/client/ABC1".into(),
                "/api/ui/purge/client/ABC1".into(),
                "/api/files/purge/client/ABC1".into()
            )
        );
        assert_eq!(
            Purge::App.paths("my_app"),
            (
                "/api/security/applications/purge/my_app".into(),
                "/api/core/purge/app/my_app".into(),
                "/api/ui/purge/app/my_app".into(),
                "/api/files/purge/app/my_app".into()
            )
        );
    }

    #[test]
    fn purge_codes_cannot_carry_a_path() {
        assert!(purge_code_ok("ABC1"));
        assert!(purge_code_ok("my_app"));
        for bad in ["", "a/b", "a?x=1", "..", "a b", "a%2F"] {
            assert!(!purge_code_ok(bad), "{bad}");
        }
    }
}
