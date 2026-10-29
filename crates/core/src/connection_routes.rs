//! `ConnectionController`'s own routes under `/api/core/connections` (the OAuth2 consent flow
//! and the internal reads the other services make), over `crates/connections`' controller
//! functions.
//!
//! `oauth/evoke`, `oauth/callback` and `internal/**` are open (`CoreConfiguration`);
//! `oauth/revoke` and `oauth/status` need a signed-in caller (a bare 401 otherwise).

use axum::extract::{Path, RawQuery, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use connections::connection::ConnectionType;
use connections::controller::{self, CallbackOutcome};
use overridable::json::to_jackson_pretty;
use overridable::pojo::to_jackson;
use overridable::{JMap, JValue};

use crate::context;
use crate::docs::CONNECTION;
use crate::error::CoreError;
use crate::handlers::{finish, request_context};
use crate::integrations::{caller, core_error};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/core/connections/oauth/evoke", post(evoke))
        .route("/api/core/connections/oauth/callback", get(callback))
        .route("/api/core/connections/oauth/revoke", get(revoke))
        .route("/api/core/connections/oauth/status", get(status))
        .route("/api/core/connections/internal/oauth2/token/{connection_name}", get(oauth2_token))
        .route("/api/core/connections/internal/notification/{name}", get(notification))
        .route("/api/core/connections/internal/{name}", get(internal))
}

fn params(q: Option<&str>) -> Vec<(String, String)> {
    crate::exec::parse_query(q)
}

fn param(p: &[(String, String)], name: &str) -> Option<String> {
    p.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone())
}

/// A `@RequestParam` Spring requires.
fn required(p: &[(String, String)], name: &str) -> Result<String, CoreError> {
    param(p, name).ok_or_else(|| crate::error::spring::param_missing(name))
}

fn header_value(h: &HeaderMap, name: &str) -> Option<String> {
    h.get(name).and_then(|v| v.to_str().ok()).map(str::to_string)
}

fn text(body: String) -> Response {
    let mut resp = (StatusCode::OK, body).into_response();
    resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain;charset=UTF-8"));
    resp
}

fn json(body: String) -> Response {
    let mut resp = (StatusCode::OK, body).into_response();
    resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    resp
}

fn empty_ok() -> Response {
    let mut resp = StatusCode::OK.into_response();
    resp.headers_mut().insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
    resp
}

/// Runs `f` inside the caller's request context.
async fn in_request<F, Fut>(st: &AppState, h: &HeaderMap, authenticated: bool, f: F) -> Result<Response, CoreError>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<Response, CoreError>>,
{
    let ctx = request_context(st, h).await?;
    if authenticated && !ctx.auth.is_authenticated() {
        return Ok(crate::unmapped::unauthorized());
    }
    context::with_request(ctx, f()).await
}

/// `POST /oauth/evoke?connectionName=`: the consent URL as text, or nothing.
async fn evoke(State(st): State<AppState>, RawQuery(q): RawQuery, h: HeaderMap) -> Response {
    let r = in_request(&st.clone(), &h.clone(), false, || async move {
        let name = required(&params(q.as_deref()), "connectionName")?;
        let host = header_value(&h, "x-forwarded-host");
        let i = &st.inner().integrations;
        match controller::evoke_oauth(&i.connections, &caller(), &name, host.as_deref()).await.map_err(core_error)? {
            Some(url) => Ok(text(url)),
            None => Ok(empty_ok()),
        }
    })
    .await;
    finish(r, "/api/core/connections/oauth/evoke")
}

/// `GET /oauth/callback?code=&state=`: back to the connection's page.
async fn callback(State(st): State<AppState>, RawQuery(q): RawQuery, h: HeaderMap) -> Response {
    let r = in_request(&st.clone(), &h.clone(), false, || async move {
        let p = params(q.as_deref());
        let host = header_value(&h, "x-forwarded-host");
        let i = &st.inner().integrations;
        let outcome = controller::oauth_callback(&i.connections, &caller(), param(&p, "code").as_deref(), param(&p, "state").as_deref(), host.as_deref())
            .await
            .map_err(core_error)?;
        Ok(match outcome {
            CallbackOutcome::Redirect(to) => {
                let mut resp = StatusCode::FOUND.into_response();
                if let Ok(v) = HeaderValue::from_str(&to) {
                    resp.headers_mut().insert(header::LOCATION, v);
                }
                resp
            }
            CallbackOutcome::FoundWithoutLocation => StatusCode::FOUND.into_response(),
            CallbackOutcome::Empty => empty_ok(),
        })
    })
    .await;
    finish(r, "/api/core/connections/oauth/callback")
}

/// `GET /oauth/revoke?connectionName=`: `true` once the caller's token is revoked.
async fn revoke(State(st): State<AppState>, RawQuery(q): RawQuery, h: HeaderMap) -> Response {
    let r = in_request(&st.clone(), &h, true, || async move {
        let name = required(&params(q.as_deref()), "connectionName")?;
        let i = &st.inner().integrations;
        let done = controller::revoke_token(&i.connections, &caller(), &name).await.map_err(core_error)?;
        Ok(json(done.to_string()))
    })
    .await;
    finish(r, "/api/core/connections/oauth/revoke")
}

/// The answer of `oauth/status`: whether the caller's business has a stored sign-in for the
/// connection, when it was made (UTC, ISO 8601) and by which user. Never the token.
fn sign_in_json(s: Option<&controller::SignIn>) -> String {
    let at = s.and_then(|s| s.connected_at).map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string());
    serde_json::json!({
        "hasToken": s.is_some(),
        "connectedAt": at,
        "connectedBy": s.and_then(|s| s.user_id),
    })
    .to_string()
}

/// `GET /oauth/status?connectionName=` (Rust only): the caller's stored sign-in for the
/// connection, for the caller's own client and URL app (the tokens `oauth/revoke` would drop).
async fn status(State(st): State<AppState>, RawQuery(q): RawQuery, h: HeaderMap) -> Response {
    let r = in_request(&st.clone(), &h, true, || async move {
        let name = required(&params(q.as_deref()), "connectionName")?;
        let i = &st.inner().integrations;
        let s = controller::sign_in_status(&i.connections, &caller(), &name).await.map_err(core_error)?;
        Ok(json(sign_in_json(s.as_ref())))
    })
    .await;
    finish(r, "/api/core/connections/oauth/status")
}

/// `GET /internal/oauth2/token/{connectionName}` with the `appCode` and `clientCode` headers.
async fn oauth2_token(State(st): State<AppState>, Path(connection_name): Path<String>, h: HeaderMap) -> Response {
    let r = in_request(&st.clone(), &h.clone(), false, || async move {
        let i = &st.inner().integrations;
        let app = header_value(&h, "appCode");
        let client = header_value(&h, "clientCode");
        match controller::oauth2_token(&i.connections, &caller(), &connection_name, app.as_deref(), client.as_deref())
            .await
            .map_err(core_error)?
        {
            Some(token) => Ok(text(token)),
            None => Ok(empty_ok()),
        }
    })
    .await;
    finish(r, "/api/core/connections/internal/oauth2/token/{connectionName}")
}

fn connection_type(doc: &JMap) -> Option<&str> {
    match doc.get("connectionType") {
        Some(JValue::Str(s)) => Some(s.as_str()),
        _ => None,
    }
}

fn written(doc: &JMap) -> JValue {
    JValue::Object(to_jackson(&CONNECTION, doc))
}

/// `GET /internal/notification/{name}?appCode=&clientCode=&urlClientCode=`.
async fn notification(State(st): State<AppState>, Path(name): Path<String>, RawQuery(q): RawQuery, h: HeaderMap) -> Response {
    let r = in_request(&st.clone(), &h, false, || async move {
        let p = params(q.as_deref());
        let app = required(&p, "appCode")?;
        let client = required(&p, "clientCode")?;
        let url_client = required(&p, "urlClientCode")?;
        let docs = &st.inner().integrations.connection_docs;
        let Some(n) = docs.read_jmap(&name, &app, &url_client, &client).await?.filter(|d| connection_type(d) == Some("NOTIFICATION")) else {
            return Ok(empty_ok());
        };
        let Some(details) = n.get("connectionDetails").and_then(JValue::as_object).filter(|d| !d.is_empty()) else {
            return Ok(empty_ok());
        };
        let in_app = details.contains_key("inapp");
        let mail_name = details.get("mail").filter(|v| !v.is_null()).map(JValue::java_to_string).filter(|m| !m.is_empty());
        let mut out = JMap::new();
        out.insert("inApp".into(), JValue::Bool(in_app));
        if let Some(mail_name) = mail_name {
            if let Some(m) = docs.read_jmap(&mail_name, &app, &url_client, &client).await?.filter(|d| connection_type(d) == Some("MAIL")) {
                out.insert("mail".into(), written(&m));
            }
        }
        Ok(json(to_jackson_pretty(&JValue::Object(out))))
    })
    .await;
    finish(r, "/api/core/connections/internal/notification/{name}")
}

/// `GET /internal/{name}?appCode=&clientCode=&urlClientCode=&connectionType=`: the whole
/// document as core's Jackson writes it.
async fn internal(State(st): State<AppState>, Path(name): Path<String>, RawQuery(q): RawQuery, h: HeaderMap) -> Response {
    let r = in_request(&st.clone(), &h, false, || async move {
        let p = params(q.as_deref());
        let app = required(&p, "appCode")?;
        let client = required(&p, "clientCode")?;
        let url_client = required(&p, "urlClientCode")?;
        let wanted = required(&p, "connectionType")?;
        let Some(t) = ConnectionType::value_of(&wanted) else {
            return Err(core_error(
                controller::internal_connection(&st.inner().integrations.connections, &name, &app, &client, &url_client, &wanted)
                    .await
                    .err()
                    .unwrap_or_else(|| connections::error::ConnError::other("unknown connection type")),
            ));
        };
        let docs = &st.inner().integrations.connection_docs;
        match docs.read_jmap(&name, &app, &url_client, &client).await?.filter(|d| connection_type(d) == Some(t.name())) {
            Some(doc) => Ok(json(to_jackson_pretty(&written(&doc)))),
            None => Ok(empty_ok()),
        }
    })
    .await;
    finish(r, "/api/core/connections/internal/{name}")
}
