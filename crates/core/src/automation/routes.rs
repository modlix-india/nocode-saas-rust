//! core-exec's automation routes (Rust only): a client's runs, stopping one, and a test run.
//!
//! - `GET  /api/core/eventRuns/automations?appCode=&automation=&subject=&status=&page=&size=`
//! - `GET  /api/core/eventRuns/automations/{id}`
//! - `POST /api/core/eventRuns/automations/{id}/cancel`
//! - `POST /api/core/eventRuns/automations/test` with `{ automation: {...}, trigger: {...} }`
//!
//! They sit under `/api/core/eventRuns` because every gateway already sends that prefix to
//! core-exec; anything else under `/api/core/automations` goes to core-editor.
//!
//! Reading needs `Authorities.Automation_READ`; stopping and testing `Automation_UPDATE`. A
//! caller sees its own client's runs; the SYSTEM client may name another with `clientCode`.
//!
//! A test run starts the automation as given (saved or not), as the client's event runner, with
//! every wait cut to a minute at most. Its steps read and write the data the body's `data` names:
//! `"live"` (the app's real records, so a test can run on a real deal) or `"draft"` (the draft
//! app's copy). Without `data`, the surface the request came from: the live app tests on live
//! data, a draft host on draft data. A live test's steps really act (messages go out); only the
//! built-in notification is kept to the tester. It answers once the run first stops or parks, so
//! the editor can draw how far it got.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, RawQuery, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde_json::{json, Value};

use super::engine::{Engine, RunStore, Timers};
use super::runtime::{run_json, MongoRuns};
use crate::context::{self, RequestContext};
use crate::data_routes::query_params;
use crate::error::CoreError;
use crate::handlers::{finish, request_context};
use crate::state::AppState;

pub const AUTOMATION_READ: &str = "Authorities.Automation_READ";
pub const AUTOMATION_UPDATE: &str = "Authorities.Automation_UPDATE";
const MAX_PAGE_SIZE: i64 = 200;
const LIST: &str = "/api/core/eventRuns/automations";
const TEST: &str = "/api/core/eventRuns/automations/test";

/// What the routes run on; set once by core-exec.
#[derive(Clone)]
pub struct Services {
    pub engine: Arc<Engine>,
    pub runs: Arc<MongoRuns>,
    pub timers: Arc<dyn Timers>,
    pub clients: Arc<dyn crate::events::ClientLookup>,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route(LIST, get(list))
        .route("/api/core/eventRuns/automations/{id}", get(read))
        .route("/api/core/eventRuns/automations/{id}/cancel", post(cancel))
        .route(TEST, post(test))
}

fn json_response(v: &Value) -> Response {
    let mut resp = (StatusCode::OK, serde_json::to_string_pretty(v).unwrap_or_default()).into_response();
    resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    resp
}

fn coded(status: StatusCode, message: &str) -> Response {
    let mut resp = (status, json!({ "message": message }).to_string()).into_response();
    resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    resp
}

fn services(st: &AppState) -> Result<&Services, Response> {
    st.inner().automations.get().ok_or_else(|| coded(StatusCode::SERVICE_UNAVAILABLE, "Automations are not available here."))
}

/// The caller, refused unless signed in and holding `authority`.
async fn caller(st: &AppState, h: &HeaderMap, authority: &str) -> Result<Arc<RequestContext>, Result<Response, CoreError>> {
    let ctx = request_context(st, h).await.map_err(Err)?;
    if !ctx.auth.is_authenticated() {
        return Err(Ok(crate::unmapped::unauthorized()));
    }
    if !ctx.auth.ca.has_authority(authority) {
        return Err(Ok(crate::unmapped::access_denied(&[authority])));
    }
    Ok(ctx)
}

/// The client whose runs are read: the caller's own, or one the SYSTEM client names.
fn client_of(ctx: &RequestContext, asked: Option<&str>) -> Result<String, Response> {
    let own = ctx.auth.ca.client_code().to_string();
    match asked.map(str::trim).filter(|c| !c.is_empty()) {
        Some(c) if c != own && !ctx.auth.ca.is_system_client() => Err(coded(StatusCode::FORBIDDEN, "You can only see your own runs.")),
        Some(c) => Ok(c.to_string()),
        None => Ok(own),
    }
}

fn param<'a>(q: &'a [(String, Option<String>)], name: &str) -> Option<&'a str> {
    q.iter().find(|(k, _)| k == name).and_then(|(_, v)| v.as_deref()).filter(|v| !v.trim().is_empty())
}

async fn list(State(st): State<AppState>, RawQuery(raw): RawQuery, h: HeaderMap) -> Response {
    const R: &str = LIST;
    let r = async {
        let ctx = match caller(&st, &h, AUTOMATION_READ).await {
            Ok(c) => c,
            Err(r) => return r,
        };
        let s = match services(&st) {
            Ok(s) => s,
            Err(r) => return Ok(r),
        };
        let q = query_params(raw.as_deref());
        let Some(app) = param(&q, "appCode").map(str::to_string).or_else(|| ctx.app_code.clone()) else {
            return Ok(coded(StatusCode::BAD_REQUEST, "Say which app's runs to list (appCode)."));
        };
        let client = match client_of(&ctx, param(&q, "clientCode")) {
            Ok(c) => c,
            Err(r) => return Ok(r),
        };
        let page = param(&q, "page").and_then(|p| p.parse::<u64>().ok()).unwrap_or(0);
        let size = param(&q, "size").and_then(|p| p.parse::<i64>().ok()).unwrap_or(20).clamp(1, MAX_PAGE_SIZE);
        let (runs, total) = s.runs.list(&app, &client, param(&q, "automation"), param(&q, "subject"), param(&q, "status"), page, size).await?;
        Ok(json_response(&json!({
            "content": runs.iter().map(run_json).collect::<Vec<_>>(),
            "page": page, "size": size, "totalElements": total,
        })))
    }
    .await;
    finish(r, R)
}

/// The run, when the caller may see it.
async fn owned_run(s: &Services, ctx: &RequestContext, id: &str) -> Result<Result<super::engine::Run, Response>, CoreError> {
    let Some(run) = s.runs.get(id).await? else { return Ok(Err(coded(StatusCode::NOT_FOUND, "No such run."))) };
    if run.client_code != ctx.auth.ca.client_code() && !ctx.auth.ca.is_system_client() {
        return Ok(Err(coded(StatusCode::NOT_FOUND, "No such run.")));
    }
    Ok(Ok(run))
}

async fn read(State(st): State<AppState>, Path(id): Path<String>, h: HeaderMap) -> Response {
    const R: &str = "/api/core/eventRuns/automations/{id}";
    let r = async {
        let ctx = match caller(&st, &h, AUTOMATION_READ).await {
            Ok(c) => c,
            Err(r) => return r,
        };
        let s = match services(&st) {
            Ok(s) => s,
            Err(r) => return Ok(r),
        };
        Ok(match owned_run(s, &ctx, &id).await? {
            Ok(run) => json_response(&run_json(&run)),
            Err(r) => r,
        })
    }
    .await;
    finish(r, R)
}

async fn cancel(State(st): State<AppState>, Path(id): Path<String>, h: HeaderMap) -> Response {
    const R: &str = "/api/core/eventRuns/automations/{id}/cancel";
    let r = async {
        let ctx = match caller(&st, &h, AUTOMATION_UPDATE).await {
            Ok(c) => c,
            Err(r) => return r,
        };
        let s = match services(&st) {
            Ok(s) => s,
            Err(r) => return Ok(r),
        };
        let run = match owned_run(s, &ctx, &id).await? {
            Ok(run) => run,
            Err(r) => return Ok(r),
        };
        if run.status.finished() {
            return Ok(coded(StatusCode::CONFLICT, "This run has already finished."));
        }
        let by = ctx.auth.user_id().to_string();
        Ok(match s.engine.cancel(&id, &format!("Stopped by user {by}.")).await? {
            Some(run) => json_response(&run_json(&run)),
            None => coded(StatusCode::CONFLICT, "The run moved on while it was being stopped; try again."),
        })
    }
    .await;
    finish(r, R)
}

async fn test(State(st): State<AppState>, h: HeaderMap, body: Bytes) -> Response {
    const R: &str = TEST;
    let r = async {
        let ctx = match caller(&st, &h, AUTOMATION_UPDATE).await {
            Ok(c) => c,
            Err(r) => return r,
        };
        let s = match services(&st) {
            Ok(s) => s,
            Err(r) => return Ok(r),
        };
        let Ok(Value::Object(b)) = serde_json::from_slice::<Value>(&body) else {
            return Ok(coded(StatusCode::BAD_REQUEST, "Send { automation, trigger }."));
        };
        let Some(Value::Object(automation)) = b.get("automation") else {
            return Ok(coded(StatusCode::BAD_REQUEST, "Send the automation to test."));
        };
        let trigger = b.get("trigger").cloned().unwrap_or_else(|| json!({}));
        let draft = match b.get("data").and_then(Value::as_str).map(str::trim) {
            None | Some("") => ctx.draft,
            Some(d) if d.eq_ignore_ascii_case("live") => false,
            Some(d) if d.eq_ignore_ascii_case("draft") => true,
            Some(_) => return Ok(coded(StatusCode::BAD_REQUEST, "Say \"live\" or \"draft\" for the data a test runs on.")),
        };
        let Some(app) = automation.get("appCode").and_then(Value::as_str).map(str::to_string).or_else(|| ctx.app_code.clone()) else {
            return Ok(coded(StatusCode::BAD_REQUEST, "Say which app the automation is in."));
        };
        let jdoc = match overridable::json::parse(&serde_json::to_vec(automation).unwrap_or_default()) {
            Ok(overridable::JValue::Object(m)) => m,
            _ => return Ok(coded(StatusCode::BAD_REQUEST, "The automation could not be read.")),
        };
        let report = super::check::check(&jdoc);
        if !report.ok() {
            let mut resp = json_response(&json!({ "check": serde_json::to_value(report.to_json()).unwrap_or(Value::Null) }));
            *resp.status_mut() = StatusCode::UNPROCESSABLE_ENTITY;
            return Ok(resp);
        }
        // The automation's own client: the caller's, or any client for the SYSTEM client
        // (testing a tenant's automation from the builder account).
        let own = ctx.auth.ca.client_code().to_string();
        let client = match automation.get("clientCode").and_then(Value::as_str).map(str::trim).filter(|c| !c.is_empty()) {
            Some(c) if c == own || ctx.auth.ca.is_system_client() => c.to_string(),
            Some(_) => return Ok(coded(StatusCode::FORBIDDEN, "You can only test your own automations.")),
            None => own,
        };
        let runner = event_runner(s, &app, &client, draft).await?;
        let engine = s.engine.clone();
        let auto = Value::Object(automation.clone());
        let user = ctx.auth.user_id();
        let run = context::with_request(runner, async move { engine.start_test(&app, &client, draft, &auto, &trigger, user).await }).await?;
        Ok(match run {
            Some(run) => json_response(&run_json(&run)),
            None => coded(StatusCode::OK, "The trigger's filter does not hold for this record, so the automation would not start."),
        })
    }
    .await;
    finish(r, R)
}

/// The client's event runner on the surface a test runs on: what a test run's actions run as.
async fn event_runner(s: &Services, app: &str, client: &str, draft: bool) -> Result<Arc<RequestContext>, CoreError> {
    let found = s.clients.client_by_code(client).await?;
    let Some(found) = found else { return Err(CoreError::unknown(format!("The client '{client}' could not be found"))) };
    let auth = crate::events::anonymous_authentication(Some(app), Some(client), &found)?;
    Ok(Arc::new(RequestContext {
        auth: Arc::new(auth),
        app_code: Some(app.to_string()),
        client_code: Some(client.to_string()),
        draft,
        ..Default::default()
    }))
}
