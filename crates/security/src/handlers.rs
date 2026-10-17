//! The routes of `AuthenticationController`.
//!
//! Every request first gets the caller's context, as Spring Security's `JWTTokenFilter` does on
//! every path (so an unknown `clientCode` or a blocked user fails even the open endpoints).
//! Then the paths the Java configuration does not open refuse an unauthenticated caller with a
//! bare 401.
//!
//! | Route | Open to anonymous |
//! |---|---|
//! | `POST authenticate`, `authenticate/social`, `authenticate/otp/generate` | yes |
//! | `GET verifyToken`, `authenticateWithOneTimeToken/{token}` | yes |
//! | `GET internal/securityContextAuthentication`, `POST internal/tokens/cleanup` | yes |
//! | `GET revoke`, `refreshToken`, `securityContextAuthentication` | no |
//! | `POST makeOneTimeToken`, `internal/makeOneTimeToken`, `user/access` | no |

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::to_bytes;
use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use platform::http::with_route;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer};
use serde_json::Value;

use crate::errors::{AuthError, AuthResult};
use crate::jackson::{empty, json};
use crate::model::ContextAuth;
use crate::request::RequestInfo;
use crate::service::Auth;
use crate::signin::{AuthRequest, Minted};
use crate::tokens::{AppAccessRequest, OneTimeTokenRequest};

pub type AppState = Arc<Auth>;

const MAX_BODY: usize = 1024 * 1024;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/security/authenticate", post(authenticate))
        .route("/api/security/authenticate/social", post(authenticate_social))
        .route("/api/security/authenticate/otp/generate", post(generate_otp))
        .route("/api/security/revoke", get(revoke))
        .route("/api/security/refreshToken", get(refresh_token))
        .route("/api/security/verifyToken", get(verify_token))
        .route("/api/security/makeOneTimeToken", post(make_one_time_token))
        .route("/api/security/internal/makeOneTimeToken", post(make_one_time_token_internal))
        .route("/api/security/authenticateWithOneTimeToken/{token}", get(authenticate_with_one_time_token))
        .route("/api/security/internal/securityContextAuthentication", get(context_internal))
        .route("/api/security/securityContextAuthentication", get(context_external))
        .route("/api/security/user/access", post(user_access))
        .route("/api/security/internal/tokens/cleanup", post(cleanup_tokens))
        .method_not_allowed_fallback(crate::web::method_not_allowed)
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

/// The headers Spring Security's default writers put on every security response.
pub async fn security_headers(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    if !h.contains_key(header::CACHE_CONTROL) {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache, no-store, max-age=0, must-revalidate"));
        h.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
        h.insert(header::EXPIRES, HeaderValue::from_static("0"));
    }
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    // A route that sets its own (Java's applyAppCode answers SAMEORIGIN) keeps it.
    if !h.contains_key("x-frame-options") {
        h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    }
    h.insert("x-xss-protection", HeaderValue::from_static("0"));
    h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    h.remove("content-security-policy");
    resp
}

/// A request's parts as the services read them, and its body.
pub(crate) async fn split(req: Request) -> AuthResult<(RequestInfo, Vec<u8>)> {
    let remote = req.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| c.0);
    let (parts, body) = req.into_parts();
    let bytes = to_bytes(body, MAX_BODY)
        .await
        .map_err(|e| AuthError::Unknown { status: StatusCode::PAYLOAD_TOO_LARGE, cause: e.to_string() })?;
    Ok((RequestInfo::new(parts.headers, remote), bytes.to_vec()))
}

/// `@RequestBody`: a missing or unreadable body is a 400.
pub(crate) fn body<T: DeserializeOwned>(bytes: &[u8]) -> AuthResult<T> {
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Err(crate::web::no_body());
    }
    serde_json::from_slice(bytes).map_err(|e| {
        tracing::debug!(error = %e, "unreadable request body");
        AuthError::input(StatusCode::BAD_REQUEST, "400 BAD_REQUEST \"Failed to read HTTP message\"", platform::error::input::body_unreadable(Some(&e)))
    })
}

/// Jackson's lenient `boolean`: JSON booleans, `"true"`/`"false"`, and null as false.
pub fn de_bool<'de, D: Deserializer<'de>>(d: D) -> Result<bool, D::Error> {
    match Value::deserialize(d)? {
        Value::Bool(b) => Ok(b),
        Value::Null => Ok(false),
        Value::String(s) if s.eq_ignore_ascii_case("true") => Ok(true),
        Value::String(s) if s.eq_ignore_ascii_case("false") || s.is_empty() => Ok(false),
        Value::Number(n) => Ok(n.as_i64().unwrap_or(0) != 0),
        other => Err(serde::de::Error::custom(format!("Cannot deserialize boolean from {other}"))),
    }
}

/// A `ULong` from a number or a numeric string.
pub fn de_opt_u64<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
    match Value::deserialize(d)? {
        Value::Null => Ok(None),
        Value::Number(n) => n.as_u64().map(Some).ok_or_else(|| serde::de::Error::custom("not an unsigned number")),
        Value::String(s) if s.trim().is_empty() => Ok(None),
        Value::String(s) => s.trim().parse().map(Some).map_err(serde::de::Error::custom),
        other => Err(serde::de::Error::custom(format!("Cannot deserialize ULong from {other}"))),
    }
}

pub(crate) fn respond(route: &'static str, r: AuthResult<Response>) -> Response {
    with_route(r.unwrap_or_else(IntoResponse::into_response), route)
}

fn minted(m: Minted, as_context: bool) -> Response {
    let body = if as_context { m.response.to_context_auth().to_json() } else { m.response.to_json() };
    let mut resp = json(&body);
    if let Some(c) = m.cookie {
        if let Ok(v) = HeaderValue::from_str(&c) {
            resp.headers_mut().insert(header::SET_COOKIE, v);
        }
    }
    resp
}

/// The caller's context, then the authenticated-only rule where it applies. The request's
/// message scope learns who is calling (their language; whether a credential was refused).
pub(crate) async fn caller(auth: &Auth, info: &RequestInfo, protected: bool) -> AuthResult<ContextAuth> {
    let ca = auth.context(info).await?;
    // The user's client (for an anonymous caller, the site's): its locale comes after the user's.
    let client_locale = match ca.user.client_id {
        Some(id) => auth.dir.client(id).await.ok().flatten().and_then(|c| c.locale_code.clone()),
        None => None,
    };
    platform::messages::note_caller(platform::messages::CallerHint {
        locale: ca.user.locale_code.clone().filter(|_| ca.authenticated),
        client_locale,
        client_code: ca.client_code.clone(),
        authenticated: ca.authenticated,
        credential_sent: !info.basic_or_bearer().1.trim().is_empty(),
    });
    if protected && !ca.authenticated {
        return Err(AuthError::Unauthenticated);
    }
    Ok(ca)
}

async fn authenticate(State(auth): State<AppState>, req: Request) -> Response {
    respond("/api/security/authenticate", async {
        let (info, bytes) = split(req).await?;
        let ca = caller(&auth, &info, false).await?;
        let b: AuthRequest = body(&bytes)?;
        Ok(minted(auth.authenticate(&b, &info, ca.user.id()).await?, false))
    }
    .await)
}

async fn authenticate_social(State(auth): State<AppState>, req: Request) -> Response {
    respond("/api/security/authenticate/social", async {
        let (info, bytes) = split(req).await?;
        let ca = caller(&auth, &info, false).await?;
        let b: AuthRequest = body(&bytes)?;
        Ok(minted(auth.authenticate_social(&b, &info, ca.user.id()).await?, false))
    }
    .await)
}

async fn generate_otp(State(auth): State<AppState>, req: Request) -> Response {
    respond("/api/security/authenticate/otp/generate", async {
        let (info, bytes) = split(req).await?;
        caller(&auth, &info, false).await?;
        let b: AuthRequest = body(&bytes)?;
        Ok(json(&Value::Bool(auth.generate_otp(&b, &info).await?)))
    }
    .await)
}

/// Spring's `boolean` request parameter conversion.
fn bool_param(q: &HashMap<String, String>, name: &str) -> AuthResult<bool> {
    match q.get(name).map(|s| s.trim().to_ascii_lowercase()) {
        None => Ok(false),
        Some(v) => match v.as_str() {
            "" | "false" | "off" | "no" | "0" => Ok(false),
            "true" | "on" | "yes" | "1" => Ok(true),
            _ => Err(AuthError::input(
                StatusCode::BAD_REQUEST,
                format!("Invalid boolean value [{v}]"),
                platform::error::input::param_invalid(name, Some("true or false")),
            )),
        },
    }
}

fn query(req: &Request) -> HashMap<String, String> {
    req.uri()
        .query()
        .map(|q| {
            q.split('&')
                .filter_map(|p| {
                    let (k, v) = p.split_once('=').unwrap_or((p, ""));
                    Some((percent_decode(k), percent_decode(v)))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn percent_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(&s.replace('+', " ")).decode_utf8_lossy().into_owned()
}

async fn revoke(State(auth): State<AppState>, req: Request) -> Response {
    respond("/api/security/revoke", async {
        let q = query(&req);
        let (info, _) = split(req).await?;
        let ca = caller(&auth, &info, true).await?;
        let sso = bool_param(&q, "ssoLogout")?;
        auth.revoke(sso, &info, &ca).await?;
        Ok(empty(StatusCode::OK))
    }
    .await)
}

async fn refresh_token(State(auth): State<AppState>, req: Request) -> Response {
    respond("/api/security/refreshToken", async {
        let (info, _) = split(req).await?;
        let ca = caller(&auth, &info, true).await?;
        Ok(match auth.refresh_token(&info, &ca).await? {
            Some(m) => minted(m, false),
            None => empty(StatusCode::OK),
        })
    }
    .await)
}

async fn verify_token(State(auth): State<AppState>, req: Request) -> Response {
    respond("/api/security/verifyToken", async {
        let (info, _) = split(req).await?;
        let ca = caller(&auth, &info, false).await?;
        Ok(match auth.verify_token(&info, &ca).await? {
            Some(r) => json(&r.to_json()),
            None => empty(StatusCode::UNAUTHORIZED),
        })
    }
    .await)
}

async fn make_one_time_token(State(auth): State<AppState>, req: Request) -> Response {
    respond("/api/security/makeOneTimeToken", async {
        let (info, bytes) = split(req).await?;
        let ca = caller(&auth, &info, true).await?;
        let b: OneTimeTokenRequest = body(&bytes)?;
        Ok(json(&auth.make_one_time_token(&b, &info, &ca, false).await?))
    }
    .await)
}

async fn make_one_time_token_internal(State(auth): State<AppState>, req: Request) -> Response {
    respond("/api/security/internal/makeOneTimeToken", async {
        let (info, bytes) = split(req).await?;
        let ca = caller(&auth, &info, true).await?;
        let b: OneTimeTokenRequest = body(&bytes)?;
        Ok(json(&auth.make_one_time_token(&b, &info, &ca, true).await?))
    }
    .await)
}

async fn authenticate_with_one_time_token(State(auth): State<AppState>, Path(token): Path<String>, req: Request) -> Response {
    respond("/api/security/authenticateWithOneTimeToken/{pathToken}", async {
        let (info, _) = split(req).await?;
        let ca = caller(&auth, &info, false).await?;
        Ok(minted(auth.redeem_one_time_token(&token, &info, ca.user.id()).await?, true))
    }
    .await)
}

async fn context_internal(State(auth): State<AppState>, req: Request) -> Response {
    respond("/api/security/internal/securityContextAuthentication", async {
        let (info, _) = split(req).await?;
        Ok(json(&caller(&auth, &info, false).await?.to_json()))
    }
    .await)
}

async fn context_external(State(auth): State<AppState>, req: Request) -> Response {
    respond("/api/security/securityContextAuthentication", async {
        let (info, _) = split(req).await?;
        Ok(json(&caller(&auth, &info, true).await?.to_json()))
    }
    .await)
}

async fn user_access(State(auth): State<AppState>, req: Request) -> Response {
    respond("/api/security/user/access", async {
        let (info, bytes) = split(req).await?;
        let ca = caller(&auth, &info, true).await?;
        let b: AppAccessRequest = body(&bytes)?;
        Ok(json(&auth.user_app_access(&b, &info, &ca).await?))
    }
    .await)
}

async fn cleanup_tokens(State(auth): State<AppState>, req: Request) -> Response {
    respond("/api/security/internal/tokens/cleanup", async {
        let q = query(&req);
        let (info, _) = split(req).await?;
        caller(&auth, &info, false).await?;
        let days = match q.get("unusedDays").filter(|d| !d.trim().is_empty()) {
            None => 90,
            Some(d) => d
                .trim()
                .parse::<i32>()
                .map_err(|e| {
                    AuthError::input(StatusCode::BAD_REQUEST, e.to_string(), platform::error::input::param_invalid("unusedDays", Some("a whole number")))
                })? as i64,
        };
        Ok(json(&auth.cleanup_tokens(days).await?))
    }
    .await)
}
