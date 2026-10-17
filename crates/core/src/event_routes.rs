//! `EventRunController` (`/api/core/eventRuns`) and `CoreInternalEventController`
//! (`/api/core/events/internal`).
//!
//! - `GET /api/core/eventRuns` and `GET /api/core/eventRuns/{id}` need a signed-in caller (a bare
//!   401 otherwise, as core's filter chain answers); the service's
//!   `@PreAuthorize("hasAuthority('Authorities.EventAction_READ')")` refuses a caller without
//!   the authority the way Spring Security's `HttpStatusServerAccessDeniedHandler` does: 403,
//!   `text/plain`, `Access Denied`.
//! - `POST /api/core/eventRuns/internal/cleanupOlderThan` and
//!   `POST /api/core/events/internal/raise` are open (internal paths).
//!
//! Request parameters are resolved in the controller's order, with WebFlux's conversions: a
//! missing required one or one that does not convert is a 400 before the service runs.

use axum::body::Bytes;
use axum::extract::{Path, RawQuery, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use chrono::NaiveDateTime;
use connections::mq::EventMessage;
use overridable::write::spring::{Pageable, Params, Sort};
use serde_json::{Map, Value};

use crate::context;
use crate::data_routes::query_params;
use crate::error::CoreError;
use crate::event_runs::{ReadPageRequest, RunStatus, TriggerType, EVENT_ACTION_READ};
use crate::handlers::{finish, request_context};
use crate::integrations::{caller, Mq};
use crate::scheduler::java_blank;
use crate::state::AppState;

/// `EventRunController.MAX_PAGE_SIZE`.
pub const MAX_PAGE_SIZE: i64 = 200;

/// Raised by the worker's files-ttl-cleanup job. data: `{resourceType, paths}`.
pub const FILES_EXPIRED: &str = "FILES_EXPIRED";

/// The only events a platform service may raise through `/api/core/events/internal/raise`.
pub const RAISABLE_EVENTS: [&str; 1] = [FILES_EXPIRED];

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/core/eventRuns", get(read_page))
        .route("/api/core/eventRuns/{id}", get(read))
        .route("/api/core/eventRuns/internal/cleanupOlderThan", post(cleanup_older_than))
        .route("/api/core/events/internal/raise", post(raise_route))
}

// ------------------------------------------------------------------ request parameters

/// `@RequestParam` over the query string as WebFlux reads it.
struct Query(Vec<(String, Option<String>)>);

fn type_mismatch() -> CoreError {
    crate::error::spring::type_mismatch(None, None, None)
}

fn missing(name: &str) -> CoreError {
    crate::error::spring::param_missing(name)
}

impl Query {
    fn values(&self, name: &str) -> Vec<Option<&str>> {
        self.0.iter().filter(|(k, _)| k == name).map(|(_, v)| v.as_deref()).collect()
    }

    /// A `String` parameter: one value as it is, several joined with commas (Spring's
    /// collection to string conversion); a name without a value is absent.
    fn string(&self, name: &str) -> Option<String> {
        let values = self.values(name);
        match values.len() {
            0 => None,
            1 => values[0].map(str::to_string),
            _ => Some(values.iter().map(|v| v.unwrap_or("null")).collect::<Vec<_>>().join(",")),
        }
    }

    /// Any other parameter: the first value.
    fn first(&self, name: &str) -> Option<&str> {
        self.values(name).into_iter().next().flatten()
    }

    /// `boolean` with a default: `StringToBooleanConverter`.
    fn boolean(&self, name: &str, default: bool) -> Result<bool, CoreError> {
        let Some(v) = self.first(name).filter(|v| !v.is_empty()) else { return Ok(default) };
        match v.trim().to_lowercase().as_str() {
            "" => Ok(default),
            "true" | "on" | "yes" | "1" => Ok(true),
            "false" | "off" | "no" | "0" => Ok(false),
            _ => Err(type_mismatch()),
        }
    }

    /// An enum: `StringToEnumConverterFactory` (`Enum.valueOf(source.trim())`).
    fn enumerated<T>(&self, name: &str, parse: fn(&str) -> Option<T>) -> Result<Option<T>, CoreError> {
        match self.first(name).filter(|v| !v.is_empty()) {
            None => Ok(None),
            Some(v) => parse(v.trim()).map(Some).ok_or_else(type_mismatch),
        }
    }

    /// `Long`: `NumberUtils.parseNumber`.
    fn long(&self, name: &str) -> Result<Option<i64>, CoreError> {
        match self.first(name).filter(|v| !v.is_empty()) {
            None => Ok(None),
            Some(v) => parse_java_long(v).map(Some).ok_or_else(type_mismatch),
        }
    }

    /// `int` with a default (an empty value takes the default too).
    fn int(&self, name: &str, default: i32) -> Result<i32, CoreError> {
        match self.first(name).filter(|v| !v.is_empty()) {
            None => Ok(default),
            Some(v) => parse_java_long(v).and_then(|n| i32::try_from(n).ok()).ok_or_else(type_mismatch),
        }
    }
}

/// `NumberUtils.parseNumber(text, Long.class)`: white space anywhere dropped, then
/// `Long.decode` for a hexadecimal number (`0x`, `0X`, `#`), `Long.valueOf` otherwise.
fn parse_java_long(text: &str) -> Option<i64> {
    let t: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let (negative, body) = match t.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, t.strip_prefix('+').unwrap_or(&t)),
    };
    let hex = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")).or_else(|| body.strip_prefix('#'));
    let (digits, radix) = match hex {
        Some(h) if t.strip_prefix('+').is_none() => (h, 16),
        _ => (body, 10),
    };
    if digits.is_empty() || digits.starts_with(['+', '-']) {
        return None;
    }
    let magnitude = i128::from_str_radix(digits, radix).ok()?;
    i64::try_from(if negative { -magnitude } else { magnitude }).ok()
}

/// `LocalDateTime.ofEpochSecond(epochSeconds, 0, UTC)`.
fn time(epoch_seconds: i64) -> Result<NaiveDateTime, CoreError> {
    chrono::DateTime::from_timestamp(epoch_seconds, 0).map(|t| t.naive_utc()).ok_or_else(|| {
        CoreError::unknown(format!(
            "Invalid value for EpochDay (valid values -365243219162 - 365241780471): {}",
            epoch_seconds.div_euclid(86_400)
        ))
    })
}

/// `PageRequest.of(page, min(200, max(1, size)))` over the `Pageable` Spring resolves; the
/// sort is dropped.
fn pageable(raw: Option<&str>) -> Pageable {
    let p = Pageable::from_params(&Params::from_query(raw));
    Pageable::of(p.page, p.size.clamp(1, MAX_PAGE_SIZE), Sort::unsorted())
}

/// `ULong.valueOf(String)`: a decimal in `0..2^64` (an optional sign).
fn ulong(s: &str) -> Option<u64> {
    let (negative, digits) = match s.strip_prefix('-') {
        Some(d) => (true, d),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if negative {
        return digits.bytes().all(|b| b == b'0').then_some(0);
    }
    let significant = digits.trim_start_matches('0');
    if significant.is_empty() {
        return Some(0);
    }
    significant.parse().ok()
}

// ------------------------------------------------------------------ responses

fn json(body: String) -> Response {
    let mut resp = (StatusCode::OK, body).into_response();
    resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    resp
}

/// A status with no body (`ResponseEntity.notFound().build()`, the 401 entry point).
fn bare(status: StatusCode) -> Response {
    let mut resp = status.into_response();
    resp.headers_mut().insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
    resp
}

/// `HttpStatusServerAccessDeniedHandler(FORBIDDEN)` for the service's `@PreAuthorize`.
fn access_denied() -> Response {
    crate::unmapped::access_denied(&[EVENT_ACTION_READ])
}

// ------------------------------------------------------------------ EventRunController

/// `GET /api/core/eventRuns?appCode=&clientCode=&allClients=&eventName=&status=&triggerType=&
/// from=&to=&timezone=&page=&size=`: runs of the app, newest first. `from` / `to` are epoch
/// seconds.
async fn read_page(State(st): State<AppState>, RawQuery(raw): RawQuery, h: HeaderMap) -> Response {
    let r = async {
        let ctx = request_context(&st, &h).await?;
        if !ctx.auth.is_authenticated() {
            return Ok(crate::unmapped::unauthorized());
        }
        let q = Query(query_params(raw.as_deref()));
        let app_code = q.string("appCode").ok_or_else(|| missing("appCode"))?;
        let client_code = q.string("clientCode");
        let all_clients = q.boolean("allClients", false)?;
        let event_name = q.string("eventName");
        let status = q.enumerated("status", RunStatus::parse)?;
        let trigger_type = q.enumerated("triggerType", TriggerType::parse)?;
        let from = q.long("from")?;
        let to = q.long("to")?;
        let zone = q.string("timezone");
        let pageable = pageable(raw.as_deref());
        let from = from.map(time).transpose()?;
        let to = to.map(time).transpose()?;
        if !ctx.auth.ca.has_authority(EVENT_ACTION_READ) {
            return Ok(access_denied());
        }
        let req = ReadPageRequest { app_code, client_code, all_clients, event_name, status, trigger_type, from, to, pageable, zone };
        let service = st.inner().event_runs.clone();
        let auth = ctx.auth.clone();
        let page = context::with_request(ctx, async move { service.read_page(&auth, &req).await }).await?;
        Ok(json(page.to_jackson_text()))
    }
    .await;
    finish(r, "/api/core/eventRuns")
}

/// `GET /api/core/eventRuns/{id}`: one run; 404 with no body for an id that is not one.
async fn read(State(st): State<AppState>, Path(id): Path<String>, h: HeaderMap) -> Response {
    let r = async {
        let ctx = request_context(&st, &h).await?;
        if !ctx.auth.is_authenticated() {
            return Ok(crate::unmapped::unauthorized());
        }
        let Some(id) = ulong(&id) else { return Ok(bare(StatusCode::NOT_FOUND)) };
        if !ctx.auth.ca.has_authority(EVENT_ACTION_READ) {
            return Ok(access_denied());
        }
        let service = st.inner().event_runs.clone();
        let auth = ctx.auth.clone();
        let run = context::with_request(ctx, async move { service.read(&auth, id).await }).await?;
        Ok(json(run.to_jackson_text()))
    }
    .await;
    finish(r, "/api/core/eventRuns/{id}")
}

/// `POST /api/core/eventRuns/internal/cleanupOlderThan?retentionDays=90&successRetentionDays=7&
/// staleAfterHours=6&limit=50000`: the retention sweep the worker drives.
async fn cleanup_older_than(State(st): State<AppState>, RawQuery(raw): RawQuery, h: HeaderMap) -> Response {
    let r = async {
        let ctx = request_context(&st, &h).await?;
        let q = Query(query_params(raw.as_deref()));
        let retention = q.int("retentionDays", 90)?;
        let success_retention = q.int("successRetentionDays", 7)?;
        let stale = q.int("staleAfterHours", 6)?;
        let limit = q.int("limit", 50_000)?;
        let service = st.inner().event_runs.clone();
        let done = context::with_request(ctx, async move { service.cleanup_older_than(retention, success_retention, stale, limit).await })
            .await?;
        Ok(json(done.to_jackson_text()))
    }
    .await;
    finish(r, "/api/core/eventRuns/internal/cleanupOlderThan")
}

// ------------------------------------------------------------------ CoreInternalEventController

/// `CoreInternalEventController.RaiseRequest`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RaiseRequest {
    pub event_name: Option<String>,
    pub app_code: Option<String>,
    pub client_code: Option<String>,
    pub data: Option<Map<String, Value>>,
}

fn bad_body(what: &str) -> CoreError {
    crate::error::spring::body(what)
}

impl RaiseRequest {
    /// The `@RequestBody` as Jackson reads the record: a missing body (or `null`) is "No request
    /// body", anything that is not the record "Failed to read HTTP message". Scalars read into
    /// the text fields as their text; unknown properties are ignored.
    pub fn from_body(body: &[u8]) -> Result<Self, CoreError> {
        if body.iter().all(u8::is_ascii_whitespace) {
            return Err(bad_body("No request body"));
        }
        let unreadable = || bad_body("Failed to read HTTP message");
        let v: Value = serde_json::from_slice(body).map_err(|_| unreadable())?;
        let o = match v {
            Value::Null => return Err(bad_body("No request body")),
            Value::Object(o) => o,
            _ => return Err(unreadable()),
        };
        let text = |name: &str| -> Result<Option<String>, CoreError> {
            match o.get(name) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::String(s)) => Ok(Some(s.clone())),
                Some(Value::Number(n)) => Ok(Some(n.to_string())),
                Some(Value::Bool(b)) => Ok(Some(b.to_string())),
                Some(_) => Err(unreadable()),
            }
        };
        let data = match o.get("data") {
            None | Some(Value::Null) => None,
            Some(Value::Object(d)) => Some(d.clone()),
            Some(_) => return Err(unreadable()),
        };
        Ok(Self { event_name: text("eventName")?, app_code: text("appCode")?, client_code: text("clientCode")?, data })
    }
}

/// `CoreInternalEventController.raise`: 400 with `false` when a field is missing or the event
/// may not be raised here; otherwise whether it was handed to the queue. Raised with no
/// authentication, so the consumer runs its EventAction as the client's event runner.
pub async fn raise(mq: &Mq, request: Option<&RaiseRequest>) -> Result<(StatusCode, bool), CoreError> {
    let blank = |s: &Option<String>| s.as_deref().is_none_or(java_blank);
    let Some(r) = request.filter(|r| {
        !blank(&r.event_name)
            && !blank(&r.app_code)
            && !blank(&r.client_code)
            && r.event_name.as_deref().is_some_and(|e| RAISABLE_EVENTS.contains(&e))
    }) else {
        return Ok((StatusCode::BAD_REQUEST, false));
    };
    let event = EventMessage {
        event_name: r.event_name.clone(),
        app_code: r.app_code.clone(),
        client_code: r.client_code.clone(),
        data: Some(r.data.clone().unwrap_or_default()),
        authentication: None,
        ..Default::default()
    };
    let sent = mq.create_event(&caller(), event).await?;
    Ok((StatusCode::OK, sent))
}

/// `POST /api/core/events/internal/raise` with `{eventName, appCode, clientCode, data}`.
async fn raise_route(State(st): State<AppState>, h: HeaderMap, body: Bytes) -> Response {
    let r = async {
        let ctx = request_context(&st, &h).await?;
        let request = RaiseRequest::from_body(&body)?;
        let mq = st.inner().integrations.mq.clone();
        let (status, sent) = context::with_request(ctx, async move { raise(&mq, Some(&request)).await }).await?;
        let mut resp = json(sent.to_string());
        *resp.status_mut() = status;
        Ok(resp)
    }
    .await;
    finish(r, "/api/core/events/internal/raise")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_convert_as_spring_converts_them() {
        assert_eq!(parse_java_long(" 12 "), Some(12));
        assert_eq!(parse_java_long("1 2"), Some(12));
        assert_eq!(parse_java_long("+7"), Some(7));
        assert_eq!(parse_java_long("-0x10"), Some(-16));
        assert_eq!(parse_java_long("#ff"), Some(255));
        assert_eq!(parse_java_long("+0x10"), None);
        assert_eq!(parse_java_long("9223372036854775808"), None);
        assert_eq!(parse_java_long("-9223372036854775808"), Some(i64::MIN));
        assert_eq!(parse_java_long("abc"), None);
        assert_eq!(parse_java_long("--1"), None);
        assert_eq!(ulong("18446744073709551615"), Some(u64::MAX));
        assert_eq!(ulong("18446744073709551616"), None);
        assert_eq!(ulong("+5"), Some(5));
        assert_eq!(ulong("-0"), Some(0));
        assert_eq!(ulong("-1"), None);
        assert_eq!(ulong(" 5"), None);
        assert_eq!(ulong("007"), Some(7));
        assert!(time(i64::MAX).unwrap_err().text().starts_with("Invalid value for EpochDay"));
        assert_eq!(time(86_400).unwrap().to_string(), "1970-01-02 00:00:00");
    }

    #[test]
    fn parameters_resolve_in_webflux_s_way() {
        let q = Query(query_params(Some("a=x&a=y&b&c=&t=%20Yes%20&n=4&e=+FAILED+&bad=maybe&big=99999999999")));
        assert_eq!(q.string("a").as_deref(), Some("x,y"));
        assert_eq!(q.string("b"), None);
        assert_eq!(q.string("c").as_deref(), Some(""));
        assert!(q.boolean("t", false).unwrap());
        assert!(!q.boolean("c", false).unwrap());
        assert!(q.boolean("missing", true).unwrap());
        assert_eq!(q.boolean("bad", false).unwrap_err().text(), "400 BAD_REQUEST \"Type mismatch.\"");
        assert_eq!(q.enumerated("e", RunStatus::parse).unwrap(), Some(RunStatus::Failed));
        assert_eq!(q.enumerated("c", RunStatus::parse).unwrap(), None);
        assert!(q.enumerated("bad", RunStatus::parse).is_err());
        assert_eq!(q.long("n").unwrap(), Some(4));
        assert_eq!(q.int("c", 90).unwrap(), 90);
        assert_eq!(q.int("n", 90).unwrap(), 4);
        assert!(q.int("big", 1).is_err());
        assert_eq!(missing("appCode").text(), "400 BAD_REQUEST \"Required query parameter 'appCode' is not present.\"");
        let p = pageable(Some("page=3&size=5000&sort=name,desc"));
        assert_eq!((p.page, p.size, p.sort.0.len()), (3, 200, 0));
        assert_eq!(pageable(Some("size=0")).size, 20);
        assert_eq!(pageable(None).size, 20);
    }

    #[test]
    fn raise_bodies_read_as_jackson_reads_them() {
        assert_eq!(RaiseRequest::from_body(b"").unwrap_err().text(), "400 BAD_REQUEST \"No request body\"");
        assert_eq!(RaiseRequest::from_body(b"null").unwrap_err().text(), "400 BAD_REQUEST \"No request body\"");
        assert_eq!(RaiseRequest::from_body(b"{").unwrap_err().text(), "400 BAD_REQUEST \"Failed to read HTTP message\"");
        assert!(RaiseRequest::from_body(b"[]").is_err());
        assert!(RaiseRequest::from_body(br#"{"data": [1]}"#).is_err());
        assert!(RaiseRequest::from_body(br#"{"eventName": {}}"#).is_err());
        let r = RaiseRequest::from_body(br#"{"eventName": "FILES_EXPIRED", "appCode": 7, "clientCode": true, "other": 1}"#).unwrap();
        assert_eq!(
            (r.event_name.as_deref(), r.app_code.as_deref(), r.client_code.as_deref(), r.data),
            (Some("FILES_EXPIRED"), Some("7"), Some("true"), None)
        );
    }
}
