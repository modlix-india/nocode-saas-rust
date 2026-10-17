//! core-exec's routes: `FunctionExecutionController` and the `repositoryFind` /
//! `repositoryFilter` routes of `FunctionController` and `SchemaController`. All of them are
//! open (`CoreConfiguration` lists them as unauthenticated), but the caller is still asked of
//! security, as `JWTTokenFilter` does for every request.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, RawQuery, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use platform::http::with_route;
use platform::security::CallerContext;
use serde_json::Value;

use crate::context::{self, RequestContext};
use crate::error::{security_headers_layer, CoreError};
use crate::exec::{self, Arguments};
use crate::gson::{to_gson, to_jackson_pretty};
use crate::java_model::jackson_schema;
use crate::repos::app::{app_function_repository, app_schema_repository};
use crate::repos::{signature_json, FunctionSource, Hybrid, SchemaSource};
use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    crate::unmapped::without_allow_header(routes(state))
}

fn routes(state: AppState) -> Router {
    Router::new()
        .route("/api/core/function/execute/{namespace}/{name}", get(execute_get).post(execute_post))
        .route("/api/core/function/execute/{full_name}", get(execute_full_get).post(execute_full_post))
        .route("/api/core/functions/repositoryFind", get(functions_find))
        .route("/api/core/functions/repositoryFilter", get(functions_filter))
        .route("/api/core/schemas/repositoryFind", get(schemas_find))
        .route("/api/core/schemas/repositoryFilter", get(schemas_filter))
        .merge(crate::data_routes::router())
        .merge(crate::connection_routes::router())
        .merge(crate::event_routes::router())
        // Unmapped paths and methods: Spring Security's verdict first (`crate::unmapped`).
        .method_not_allowed_fallback(crate::unmapped::exec_method_not_allowed)
        .fallback(crate::unmapped::exec_not_found)
        .layer(middleware::from_fn(security_headers_layer))
        .with_state(state)
}

fn header(h: &HeaderMap, name: &str) -> Option<String> {
    h.get(name).and_then(|v| v.to_str().ok()).map(str::to_string)
}

/// The caller, as `JWTTokenFilter` makes it, in a request context.
pub(crate) async fn request_context(st: &AppState, h: &HeaderMap) -> Result<Arc<RequestContext>, CoreError> {
    let caller = CallerContext::from_headers(h, st.inner().config.server.port);
    let auth = st.inner().auth.authenticate(&caller).await?;
    Ok(Arc::new(RequestContext {
        auth: Arc::new(auth),
        app_code: caller.app_code.clone(),
        client_code: caller.client_code.clone(),
        forwarded_host: header(h, "x-forwarded-host").unwrap_or_default(),
        forwarded_port: header(h, "x-forwarded-port").unwrap_or_default(),
        draft: h
            .get("x-draft")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("true")),
        debug: caller.debug.clone(),
        raised: Default::default(),
    }))
}

fn json_response(body: String) -> Response {
    let mut resp = (StatusCode::OK, body).into_response();
    resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    resp
}

/// `ResponseEntity.ok()` of an empty `Mono`: 200, no body.
fn empty_ok() -> Response {
    let mut resp = StatusCode::OK.into_response();
    resp.headers_mut().insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
    resp
}

pub(crate) fn finish(r: Result<Response, CoreError>, route: &'static str) -> Response {
    with_route(r.unwrap_or_else(IntoResponse::into_response), route)
}

/// The four `@RequestHeader`s the execute routes require, in the order Spring resolves them.
fn required_headers(h: &HeaderMap) -> Result<(String, String), CoreError> {
    for name in ["X-Forwarded-Host", "X-Forwarded-Port", "appCode", "clientCode"] {
        if h.get(name).is_none() {
            return Err(crate::error::spring::header_missing(name));
        }
    }
    Ok((header(h, "appCode").unwrap_or_default(), header(h, "clientCode").unwrap_or_default()))
}

/// What the request carries for the arguments.
enum Input {
    Query(Option<String>),
    Body(Bytes),
}

/// The order Spring takes things in: the security filter, the `@RequestHeader`s, the
/// `@RequestBody` (an absent body is refused), then the method (name split, body parse).
async fn run_execute(st: AppState, h: HeaderMap, path: Result<(String, String), String>, input: Input) -> Result<Response, CoreError> {
    let ctx = request_context(&st, &h).await?;
    let (app_code, client_code) = required_headers(&h)?;
    if let Input::Body(b) = &input {
        if b.is_empty() {
            return Err(crate::error::spring::body("No request body"));
        }
    }
    let (namespace, name) = match path {
        Ok(p) => p,
        Err(full) => exec::split_name(&full)?,
    };
    let arguments = match input {
        Input::Query(q) => Arguments::Query(exec::parse_query(q.as_deref())),
        Input::Body(b) => body_arguments(&b)?,
    };
    context::with_request(ctx, async move {
        exec::execute(&st, Some(&namespace), &name, &app_code, &client_code, arguments).await
    })
    .await
    .map(json_response)
}

/// `gson.fromJson(body, JsonObject.class)`; a blank body is `{}`.
fn body_arguments(body: &Bytes) -> Result<Arguments, CoreError> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(Arguments::Body(kirun::Map::new()));
    }
    match serde_json::from_slice::<Value>(body) {
        Ok(Value::Object(m)) => Ok(Arguments::Body(m.into_iter().collect())),
        Ok(other) => Err(CoreError::unknown(format!(
            "Expected a com.google.gson.JsonObject but was {}",
            match other {
                Value::Array(_) => "com.google.gson.JsonArray",
                Value::Null => "com.google.gson.JsonNull",
                _ => "com.google.gson.JsonPrimitive",
            }
        ))),
        Err(e) => Err(CoreError::unknown(format!("com.google.gson.stream.MalformedJsonException: {e}"))),
    }
}

const EXECUTE: &str = "/api/core/function/execute/{namespace}/{name}";
const EXECUTE_FULL: &str = "/api/core/function/execute/{name}";

async fn execute_get(
    State(st): State<AppState>,
    Path((namespace, name)): Path<(String, String)>,
    RawQuery(q): RawQuery,
    h: HeaderMap,
) -> Response {
    finish(run_execute(st, h, Ok((namespace, name)), Input::Query(q)).await, EXECUTE)
}

async fn execute_post(
    State(st): State<AppState>,
    Path((namespace, name)): Path<(String, String)>,
    h: HeaderMap,
    body: Bytes,
) -> Response {
    finish(run_execute(st, h, Ok((namespace, name)), Input::Body(body)).await, EXECUTE)
}

async fn execute_full_get(
    State(st): State<AppState>,
    Path(full): Path<String>,
    RawQuery(q): RawQuery,
    h: HeaderMap,
) -> Response {
    finish(run_execute(st, h, Err(full), Input::Query(q)).await, EXECUTE_FULL)
}

async fn execute_full_post(State(st): State<AppState>, Path(full): Path<String>, h: HeaderMap, body: Bytes) -> Response {
    finish(run_execute(st, h, Err(full), Input::Body(body)).await, EXECUTE_FULL)
}

/// The query parameters of the repository routes.
struct RepoQuery {
    app_code: Option<String>,
    client_code: Option<String>,
    include_kirun: bool,
    namespace: Option<String>,
    name: Option<String>,
    filter: Option<String>,
}

fn repo_query(raw: Option<&str>) -> Result<RepoQuery, CoreError> {
    let q = exec::parse_query(raw);
    let first = |k: &str| q.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    // Spring's boolean conversion.
    let include_kirun = match first("includeKIRunRepos").map(|v| v.trim().to_ascii_lowercase()) {
        None => false,
        Some(v) if v.is_empty() => false,
        Some(v) if matches!(v.as_str(), "true" | "on" | "yes" | "1") => true,
        Some(v) if matches!(v.as_str(), "false" | "off" | "no" | "0") => false,
        Some(v) => {
            return Err(crate::error::spring::type_mismatch(Some("includeKIRunRepos"), Some("true or false"), Some(&format!("Invalid boolean value [{v}]"))))
        }
    };
    Ok(RepoQuery {
        app_code: first("appCode"),
        client_code: first("clientCode"),
        include_kirun,
        namespace: first("namespace"),
        name: first("name"),
        filter: first("filter"),
    })
}

/// `SecurityContextUtil.resolveAppAndClientCode`: the parameters when both are given,
/// otherwise the caller's url app code and own client code fill the gaps.
fn resolve_codes(q: &RepoQuery) -> (String, String) {
    let given = |v: &Option<String>| v.clone().filter(|s| !s.trim().is_empty());
    let auth = context::authentication();
    let app = given(&q.app_code).or_else(|| auth.url_app_code().map(str::to_string)).unwrap_or_default();
    let client = given(&q.client_code).or_else(|| auth.client_code().map(str::to_string)).unwrap_or_default();
    (app, client)
}

async fn function_repository(st: &AppState, q: &RepoQuery) -> Result<Arc<dyn FunctionSource>, CoreError> {
    let (app, client) = resolve_codes(q);
    let s = st.inner();
    let app_repo = app_function_repository(&s.definitions, &app, &client).await?;
    let remote = s.remote.repositories(&app, &client).await?;
    let mut sources: Vec<Arc<dyn FunctionSource>> = Vec::new();
    if q.include_kirun {
        sources.push(s.kirun_functions.clone());
    }
    // `CoreServices.Platform.*` are listed only for the platform app (Java has none to list);
    // execution resolves them everywhere, so elsewhere their guard answers 403.
    sources.push(crate::functions::platform::listed(s.core_functions.clone(), &app));
    sources.push(app_repo);
    if let Some(r) = remote {
        sources.push(r.functions);
    }
    Ok(Arc::new(Hybrid::new(sources)))
}

async fn schema_repository(st: &AppState, q: &RepoQuery) -> Result<Arc<dyn SchemaSource>, CoreError> {
    let (app, client) = resolve_codes(q);
    let s = st.inner();
    let app_repo = app_schema_repository(&s.definitions, &app, &client).await?;
    let remote = s.remote.repositories(&app, &client).await?;
    let mut sources: Vec<Arc<dyn SchemaSource>> = Vec::new();
    if q.include_kirun {
        sources.push(s.kirun_schemas.clone());
    }
    sources.push(s.core_schemas.clone());
    sources.push(app_repo);
    if let Some(r) = remote {
        sources.push(r.schemas);
    }
    Ok(Arc::new(Hybrid::new(sources)))
}

async fn in_request<F, Fut>(st: AppState, h: HeaderMap, raw: Option<String>, f: F) -> Result<Response, CoreError>
where
    F: FnOnce(AppState, RepoQuery) -> Fut,
    Fut: std::future::Future<Output = Result<Response, CoreError>>,
{
    let ctx = request_context(&st, &h).await?;
    let q = repo_query(raw.as_deref())?;
    context::with_request(ctx, f(st, q)).await
}

/// A `List<String>` as Jackson (`INDENT_OUTPUT`) writes it.
fn jackson_list(names: Vec<String>) -> Response {
    json_response(to_jackson_pretty(&Value::Array(names.into_iter().map(Value::String).collect())))
}

async fn functions_find(State(st): State<AppState>, RawQuery(raw): RawQuery, h: HeaderMap) -> Response {
    let r = in_request(st, h, raw, |st, q| async move {
        let repo = function_repository(&st, &q).await?;
        let Some(name) = q.name.as_deref() else {
            return Ok(empty_ok());
        };
        Ok(match repo.find(q.namespace.as_deref(), name).await? {
            Some(f) => json_response(to_gson(&serde_json::json!({ "definition": signature_json(f.as_ref()) }))),
            None => empty_ok(),
        })
    })
    .await;
    finish(r, "/api/core/functions/repositoryFind")
}

async fn functions_filter(State(st): State<AppState>, RawQuery(raw): RawQuery, h: HeaderMap) -> Response {
    let r = in_request(st, h, raw, |st, q| async move {
        let repo = function_repository(&st, &q).await?;
        Ok(jackson_list(repo.filter(q.filter.as_deref().unwrap_or("")).await?))
    })
    .await;
    finish(r, "/api/core/functions/repositoryFilter")
}

async fn schemas_find(State(st): State<AppState>, RawQuery(raw): RawQuery, h: HeaderMap) -> Response {
    let r = in_request(st, h, raw, |st, q| async move {
        let repo = schema_repository(&st, &q).await?;
        let Some(name) = q.name.as_deref() else {
            return Ok(empty_ok());
        };
        Ok(match repo.find(q.namespace.as_deref(), name).await? {
            Some(s) => json_response(to_jackson_pretty(&jackson_schema(&s.json))),
            None => empty_ok(),
        })
    })
    .await;
    finish(r, "/api/core/schemas/repositoryFind")
}

async fn schemas_filter(State(st): State<AppState>, RawQuery(raw): RawQuery, h: HeaderMap) -> Response {
    let r = in_request(st, h, raw, |st, q| async move {
        let repo = schema_repository(&st, &q).await?;
        Ok(jackson_list(repo.filter(q.filter.as_deref().unwrap_or("")).await?))
    })
    .await;
    finish(r, "/api/core/schemas/repositoryFilter")
}
