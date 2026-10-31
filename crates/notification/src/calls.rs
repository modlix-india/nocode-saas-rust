//! The Feign clients notification uses: `IFeignCoreService` (the two definition reads) and the
//! four `IFeignSecurityService` methods (recipients, client by code, user, the management check).
//!
//! Feign's rules are kept: a 2xx with an empty body is `null`; any other status is a
//! `FeignException` carrying the status and the body (which the HTTP edge relays the way
//! `ControllerAdvice.handleFeignException` does); a body that cannot be read is a decode error.
//! Each call carries the `x-debug` tag of the request or message it serves (the module's Feign
//! interceptor) and the current trace.

use std::time::Duration;

use anyhow::{Context, Result};
use axum::http::{HeaderMap, StatusCode};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use platform::error::AppError;
use platform::upstream::Upstream;
use serde_json::Value;

use crate::errors::{internal_error, is_coded_body, Failure};
use crate::model::UsersListRequest;

/// What Feign leaves unencoded in a query value or a path segment (RFC 3986 unreserved).
const UNRESERVED: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'.').remove(b'_').remove(b'~');

fn enc(s: &str) -> String {
    utf8_percent_encode(s, UNRESERVED).to_string()
}

/// `FeignException`: another service answered with a non-2xx status.
#[derive(Debug, Clone)]
pub struct FeignError {
    pub method: &'static str,
    pub url: String,
    pub status: u16,
    pub content_type: Option<String>,
    pub body: bytes::Bytes,
}

impl std::fmt::Display for FeignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] during [{}] to [{}]: [{}]",
            self.status,
            self.method,
            self.url,
            String::from_utf8_lossy(&self.body[..self.body.len().min(400)])
        )
    }
}

impl std::error::Error for FeignError {}

impl FeignError {
    /// `ControllerAdvice.handleFeignExceptionInternal`: a JSON answer (content type exactly
    /// `application/json`) is relayed with its status and `message`; anything else is the
    /// catch-all 500. A coded answer (a Rust unit's) is passed on as it came, so the caller
    /// reads the text that service wrote.
    pub fn relay(&self) -> Option<Failure> {
        if self.content_type.as_deref() != Some("application/json") || self.body.is_empty() {
            return None;
        }
        let v: Value = serde_json::from_slice(&self.body).ok()?;
        let status = StatusCode::from_u16(self.status).ok()?;
        if is_coded_body(&v) {
            return Some(Failure::Relayed { status, body: self.body.clone() });
        }
        let message = match v.get("message") {
            None | Some(Value::Null) => String::new(),
            Some(Value::String(s)) => s.clone(),
            Some(other) => other.to_string(),
        };
        Some(AppError::new(status, message).into())
    }
}

/// An `anyhow` error from these calls at the HTTP edge: a relayed Feign answer, one of the
/// service's own errors, or a 500.
pub fn to_failure(e: anyhow::Error) -> Failure {
    if let Some(f) = e.downcast_ref::<FeignError>().and_then(FeignError::relay) {
        return f;
    }
    match e.downcast::<AppError>() {
        Ok(a) => a.into(),
        Err(e) => internal_error(e),
    }
}

/// One Feign-style HTTP client over an upstream.
#[derive(Clone)]
pub struct Feign {
    upstream: Upstream,
    http: reqwest::Client,
}

impl Feign {
    pub fn new(upstream: Upstream, timeout: Duration) -> Result<Self> {
        Ok(Self { upstream, http: reqwest::Client::builder().timeout(timeout).build()? })
    }

    fn headers(debug: Option<&str>, extra: &[(&'static str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        platform::telemetry::inject_trace_headers(&mut h);
        if let Some(d) = debug.and_then(|d| d.parse().ok()) {
            h.insert("x-debug", d);
        }
        for (k, v) in extra {
            if let Ok(v) = v.parse() {
                h.insert(*k, v);
            }
        }
        h
    }

    /// The query string Feign writes: unset values left out, values percent-encoded.
    fn query(params: &[(&str, Option<String>)]) -> String {
        let q: Vec<String> = params
            .iter()
            .filter_map(|(k, v)| v.as_ref().map(|v| format!("{k}={}", enc(v))))
            .collect();
        if q.is_empty() {
            String::new()
        } else {
            format!("?{}", q.join("&"))
        }
    }

    async fn send(&self, method: &'static str, path_and_query: &str, body: Option<Value>, headers: HeaderMap) -> Result<Option<Value>> {
        let url = format!("{}{}", self.upstream.base_for(path_and_query).await?, path_and_query);
        let rb = match method {
            "POST" => self.http.post(&url),
            _ => self.http.get(&url),
        };
        let rb = rb.headers(headers);
        let rb = match body {
            Some(b) => rb.header("content-type", "application/json").body(b.to_string()),
            None => rb,
        };
        let resp = platform::meter::send_to_service(rb).await.with_context(|| format!("{method} {url}"))?;
        let status = resp.status().as_u16();
        let content_type = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).map(str::to_string);
        let bytes = resp.bytes().await?;
        if !(200..300).contains(&status) {
            return Err(FeignError { method, url, status, content_type, body: bytes }.into());
        }
        if bytes.is_empty() {
            return Ok(None);
        }
        let v: Value = serde_json::from_slice(&bytes).with_context(|| format!("Error while extracting response from {url}"))?;
        Ok((!v.is_null()).then_some(v))
    }
}

/// The definition lookups' arguments (`@PathVariable name`, `appCode`, `clientCode`,
/// `urlClientCode` and the draft marker).
#[derive(Debug, Clone, Copy, Default)]
pub struct DefinitionRead<'a> {
    pub name: Option<&'a str>,
    pub app_code: Option<&'a str>,
    pub client_code: Option<&'a str>,
    pub url_client_code: Option<&'a str>,
    /// `"true"` on the draft surface; `None` sends no `x-draft` header at all.
    pub draft: Option<&'a str>,
    pub debug: Option<&'a str>,
}

/// `IFeignCoreService`.
#[derive(Clone)]
pub struct CoreClient {
    feign: Feign,
    connections: Feign,
}

impl CoreClient {
    pub fn new(upstream: Upstream, timeout: Duration) -> Result<Self> {
        Self::with_connections(upstream.clone(), upstream, timeout)
    }

    /// The notification read from `upstream`, the connection read from `connections`.
    pub fn with_connections(upstream: Upstream, connections: Upstream, timeout: Duration) -> Result<Self> {
        Ok(Self { feign: Feign::new(upstream, timeout)?, connections: Feign::new(connections, timeout)? })
    }

    async fn read(&self, feign: &Feign, prefix: &str, r: DefinitionRead<'_>) -> Result<Option<Value>> {
        let path = format!(
            "{prefix}{}{}",
            enc(r.name.unwrap_or("")),
            Feign::query(&[
                ("appCode", r.app_code.map(str::to_string)),
                ("clientCode", r.client_code.map(str::to_string)),
                ("urlClientCode", r.url_client_code.map(str::to_string)),
            ])
        );
        let extra: Vec<(&'static str, &str)> = r.draft.map(|d| vec![("x-draft", d)]).unwrap_or_default();
        feign.send("GET", &path, None, Feign::headers(r.debug, &extra)).await
    }

    /// `getNotificationConnection`.
    pub async fn notification_connection(&self, r: DefinitionRead<'_>) -> Result<Option<Value>> {
        self.read(&self.connections, "/api/core/connections/internal/notification/", r).await
    }

    /// `getNotification`.
    pub async fn notification(&self, r: DefinitionRead<'_>) -> Result<Option<Value>> {
        self.read(&self.feign, "/api/core/notifications/internal/", r).await
    }

    /// How many notifications of the app reach the screen (an `inapp` or `push` channel), any
    /// client: `GET /api/core/notifications/internal/app/{appCode}` (Rust only).
    pub async fn app_notification_count(&self, app_code: &str) -> Result<i64> {
        let path = format!("/api/core/notifications/internal/app/{}", enc(app_code));
        let v = self.feign.send("GET", &path, None, Feign::headers(None, &[])).await?;
        Ok(v.as_ref().and_then(|v| v.get("count")).and_then(Value::as_i64).unwrap_or(0))
    }
}

/// The `IFeignSecurityService` methods notification calls. None of them carries a draft
/// marker: recipients and users always come from the real directory.
#[derive(Clone)]
pub struct DirectoryClient {
    feign: Feign,
}

impl DirectoryClient {
    pub fn new(upstream: Upstream, timeout: Duration) -> Result<Self> {
        Ok(Self { feign: Feign::new(upstream, timeout)? })
    }

    /// `getUsersForNotification`: `POST /api/security/users/internal/notification`.
    pub async fn users_for_notification(&self, req: &UsersListRequest, debug: Option<&str>) -> Result<Option<Value>> {
        self.feign
            .send("POST", "/api/security/users/internal/notification", Some(req.to_json()), Feign::headers(debug, &[]))
            .await
    }

    /// `getClientByCode`.
    pub async fn client_by_code(&self, client_code: Option<&str>, debug: Option<&str>) -> Result<Option<Value>> {
        let q = Feign::query(&[("clientCode", client_code.map(str::to_string))]);
        self.feign
            .send("GET", &format!("/api/security/clients/internal/getClientByCode{q}"), None, Feign::headers(debug, &[]))
            .await
    }

    /// `getUserInternal(id, null)`.
    pub async fn user_internal(&self, id: &str, debug: Option<&str>) -> Result<Option<Value>> {
        self.feign
            .send("GET", &format!("/api/security/users/internal/{}", enc(id)), None, Feign::headers(debug, &[]))
            .await
    }

    /// `isUserClientManageClient(appCode, userId, userClientId, targetClientId)`.
    pub async fn is_user_client_manage_client(
        &self,
        app_code: Option<&str>,
        user_id: &str,
        user_client_id: Option<String>,
        target_client_id: Option<String>,
        debug: Option<&str>,
    ) -> Result<Option<Value>> {
        let q = Feign::query(&[
            ("appCode", app_code.map(str::to_string)),
            ("userId", Some(user_id.to_string())),
            ("userClientId", user_client_id),
            ("targetClientId", target_client_id),
        ]);
        self.feign
            .send("GET", &format!("/api/security/clients/internal/isUserClientManageClient{q}"), None, Feign::headers(debug, &[]))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feign_relay_rules() {
        let e = |ct: Option<&str>, body: &str, status: u16| FeignError {
            method: "GET",
            url: "http://security/x".into(),
            status,
            content_type: ct.map(str::to_string),
            body: bytes::Bytes::from(body.to_string()),
        };
        let own = |f: Failure| match f {
            Failure::Own(a) => a,
            other => panic!("{other:?}"),
        };
        let relayed = own(e(Some("application/json"), r#"{"message":"Please try again. A server error - id"}"#, 400).relay().unwrap());
        assert_eq!(relayed.status(), StatusCode::BAD_REQUEST);
        assert_eq!(relayed.to_string(), "400 Bad Request: Please try again. A server error - id");
        assert_eq!(own(e(Some("application/json"), "{}", 404).relay().unwrap()).to_string(), "404 Not Found: ");
        assert_eq!(own(e(Some("application/json"), r#"{"message":5}"#, 409).relay().unwrap()).to_string(), "409 Conflict: 5");
        // A Rust unit's coded answer is passed on as it came.
        let coded = r#"{"exceptionId":"e","code":"SEC.OBJECT_NOT_FOUND","message":"We couldn't find the user."}"#;
        match e(Some("application/json"), coded, 404).relay().unwrap() {
            Failure::Relayed { status, body } => assert_eq!((status, body.as_ref()), (StatusCode::NOT_FOUND, coded.as_bytes())),
            other => panic!("{other:?}"),
        }
        assert!(e(Some("application/json;charset=UTF-8"), "{}", 400).relay().is_none());
        assert!(e(None, "{}", 400).relay().is_none());
        assert!(e(Some("application/json"), "", 400).relay().is_none());
        assert!(e(Some("application/json"), "nope", 400).relay().is_none());
        assert!(e(Some("application/json"), "{}", 99).relay().is_none());
        assert!(e(None, "x", 500).to_string().contains("[500] during [GET]"));

        let relayed = to_failure(e(Some("application/json"), r#"{"message":"m"}"#, 403).into());
        assert_eq!(relayed.status(), StatusCode::FORBIDDEN);
        assert_eq!(to_failure(anyhow::anyhow!("x")).status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(to_failure(e(None, "x", 500).into()).status(), StatusCode::INTERNAL_SERVER_ERROR, "a non-JSON answer is the 500");
        let kept = to_failure(AppError::new(StatusCode::FORBIDDEN, "no").into());
        assert_eq!(kept.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn feign_query_and_path_encoding() {
        assert_eq!(Feign::query(&[("a", None)]), "");
        assert_eq!(Feign::query(&[("a", Some("x y/z".into())), ("b", None), ("c", Some("é".into()))]), "?a=x%20y%2Fz&c=%C3%A9");
        assert_eq!(enc("a.b-c_d~e f"), "a.b-c_d~e%20f");
        let h = Feign::headers(Some("dbg"), &[("x-draft", "true")]);
        assert_eq!(h["x-debug"], "dbg");
        assert_eq!(h["x-draft"], "true");
        assert!(Feign::headers(None, &[]).get("x-debug").is_none());
    }
}
