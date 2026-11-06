//! `CoreServices.REST.OAuth2TokenInfo` (Rust only, LZT-2270): what the provider says about the
//! stored access token of an authorization-code OAuth2 connection, without the token ever
//! reaching KIRun.
//!
//! Meta's Embedded Signup hands back only an authorization code; the WhatsApp Business Accounts
//! the customer shared are named only by `GET /debug_token?input_token=<their token>` (in
//! `data.granular_scopes[].target_ids`), asked with the app's own token (`client_id|client_secret`).
//! KIRun cannot make that call: the tenant token is only ever put in `Authorization` by the
//! OAuth2 call, and the app secret is masked everywhere. The Java message service had this as
//! `WhatsappDebugTokenService`; this is its general form.
//!
//! The endpoint comes from the connection, never from the step: `connectionDetails.tokenInfo.url`
//! (optional `inputTokenParam`, default `input_token`), and when there is no `tokenInfo` a
//! connection whose token endpoint is on `graph.facebook.com` uses Meta's `debug_token`. Either
//! way its host must be the token endpoint's host and the scheme https, so the app's credentials
//! only ever go where the token exchange already sends them. The app token goes in
//! `Authorization`, the tenant token in the one query parameter Meta needs. Neither is ever in
//! what the step gets back: failures carry a fixed text or the provider's own error body, never
//! the request URL, and keys named like credentials are dropped from the answer.

use http::StatusCode;
use serde_json::{Map, Value};

use super::call::{Event, EVENT_ERROR, EVENT_OUTPUT};
use super::http::OutboundRequest;
use super::{oauth2, spring_uri};
use crate::connection::{self, is_secret_key, Connection, ConnectionSubType, ConnectionType, GRANT_AUTHORIZATION_CODE};
use crate::context::Caller;
use crate::error::{ConnError, ConnResult};
use crate::{java, outbound, Connections};

pub const FUNCTION_NAME: &str = "OAuth2TokenInfo";

const TOKEN_INFO: &str = "tokenInfo";
const DEFAULT_INPUT_PARAM: &str = "input_token";
const META_GRAPH_HOST: &str = "graph.facebook.com";
const META_DEBUG_TOKEN: &str = "https://graph.facebook.com/debug_token";
/// The answer is small (scopes and ids); anything bigger is not a token description.
const BODY_LIMIT: usize = 256 * 1024;

/// Where to ask about the token, and the query parameter that carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfoEndpoint {
    pub url: String,
    pub input_param: String,
}

fn bad(message: impl Into<String>) -> ConnError {
    ConnError::coded(StatusCode::BAD_REQUEST, "CORE.CONNECTION_TOKEN_INFO_UNAVAILABLE", message)
}

fn host_of(url: &str) -> Option<(String, String)> {
    let parsed = reqwest::Url::parse(java::trim(url)).ok()?;
    let host = parsed.host_str()?.to_ascii_lowercase();
    Some((parsed.scheme().to_ascii_lowercase(), host))
}

/// The token-info endpoint of a connection's details: `tokenInfo`, or Meta's `debug_token` when
/// the token endpoint is Meta's Graph host. Refused unless it is https on the token endpoint's
/// host.
pub fn endpoint(details: &Map<String, Value>) -> ConnResult<InfoEndpoint> {
    let token_url = details
        .get("tokenDetails")
        .and_then(Value::as_object)
        .and_then(|t| t.get("url"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let Some((_, token_host)) = host_of(token_url) else {
        return Err(bad("The connection has no token endpoint (tokenDetails.url)"));
    };
    let configured = details.get(TOKEN_INFO).and_then(Value::as_object);
    let (url, input_param) = match configured {
        Some(info) => {
            let url = info.get("url").and_then(Value::as_str).unwrap_or("").trim().to_string();
            let param = info
                .get("inputTokenParam")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .unwrap_or(DEFAULT_INPUT_PARAM)
                .to_string();
            (url, param)
        }
        None if token_host == META_GRAPH_HOST => (META_DEBUG_TOKEN.to_string(), DEFAULT_INPUT_PARAM.to_string()),
        None => return Err(bad("The connection does not say where to ask about its token (tokenInfo.url)")),
    };
    match host_of(&url) {
        Some((scheme, host)) if scheme == "https" && host == token_host => Ok(InfoEndpoint { url, input_param }),
        _ => Err(bad("tokenInfo.url must be an https address on the same host as the token endpoint")),
    }
}

/// The app's own token, `client_id|client_secret`, from `tokenDetails.queryParams` (where the
/// stored connections keep them; Java's `WhatsappDebugTokenService` read the same two).
pub fn app_token(details: &Map<String, Value>) -> ConnResult<String> {
    let query = details.get("tokenDetails").and_then(Value::as_object).and_then(|t| t.get("queryParams")).and_then(Value::as_object);
    let find = |k: &str| query.and_then(|q| q.get(k)).filter(|v| !java::safe_is_blank(Some(v))).map(java::to_java_string);
    match (find("client_id"), find("client_secret")) {
        (Some(id), Some(secret)) => Ok(format!("{id}|{secret}")),
        _ => Err(bad("The connection has no client_id and client_secret in tokenDetails.queryParams")),
    }
}

/// `value` with every key named like a credential removed, at any depth.
pub fn without_secrets(value: Value) -> Value {
    match value {
        Value::Object(m) => Value::Object(m.into_iter().filter(|(k, _)| !is_secret_key(k)).map(|(k, v)| (k, without_secrets(v))).collect()),
        Value::Array(a) => Value::Array(a.into_iter().map(without_secrets).collect()),
        other => other,
    }
}

fn event_map(data: Value, status: i32) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("data".into(), data);
    m.insert("statusCode".into(), Value::from(status));
    m
}

/// `error` then `output`, as a failed `CallRequest` raises them, so a step can branch on either.
pub fn failure_events(data: Value, status: i32) -> Vec<Event> {
    vec![
        Event { name: EVENT_ERROR, result: event_map(data, status) },
        Event { name: EVENT_OUTPUT, result: event_map(Value::Object(Map::new()), status) },
    ]
}

fn failed(e: &ConnError) -> Vec<Event> {
    failure_events(Value::String(e.message().to_string()), e.status().as_u16() as i32)
}

/// Runs the step. `Ok(None)` when there is no security context (Java's empty Mono).
pub async fn token_info(
    svc: &Connections,
    caller: &Caller,
    app_code: Option<&str>,
    client_code: Option<&str>,
    connection_name: &str,
) -> ConnResult<Option<Vec<Event>>> {
    if !caller.present {
        return Ok(None);
    }
    let (app, client) = caller.resolve_app_and_client(app_code, client_code);
    let (Some(app), Some(client)) = (app, client) else {
        return Ok(Some(failure_events(Value::String("Connection Not found".into()), 500)));
    };
    let Some(conn) = connection::read(svc.store.as_ref(), caller, connection_name, &app, &client, ConnectionType::RestApi).await? else {
        return Ok(Some(failure_events(Value::String("Connection Not found".into()), 500)));
    };
    match ask(svc, caller, &client, &conn).await {
        Ok(events) => Ok(Some(events)),
        Err(e) => Ok(Some(failed(&e))),
    }
}

async fn ask(svc: &Connections, caller: &Caller, client: &str, conn: &Connection) -> ConnResult<Vec<Event>> {
    if conn.connection_sub_type != Some(ConnectionSubType::RestApiOAuth2) || conn.detail_str("grantType") != Some(GRANT_AUTHORIZATION_CODE) {
        return Err(bad("Only an OAuth2 connection with the authorization code grant has a stored token to ask about"));
    }
    let details = conn.details().cloned().unwrap_or_default();
    let target = endpoint(&details)?;
    let app_token = app_token(&details)?;

    // The same token a REST call through this connection would send, for the same client.
    let token_client = super::token_client(svc, caller, client).await?;
    let token_app = oauth2::token_app_code(Some(conn), Some(caller));
    let token = oauth2::access_token(svc, caller, token_app.as_deref(), token_client.as_deref(), conn)
        .await?
        .filter(|t| !java::is_blank(t))
        .ok_or_else(|| bad("This connection has no token yet: connect it first"))?;

    let uri = spring_uri::build_to_uri(&target.url, &[(target.input_param.clone(), token)])
        .map_err(|_| bad("tokenInfo.url is not a valid address"))?;
    if svc.config.block_private_targets {
        outbound::guard_target(&uri).await.map_err(|_| bad("tokenInfo.url is not an address this server may call"))?;
    }
    let request = OutboundRequest {
        method: "GET".into(),
        uri,
        headers: vec![("Authorization".into(), format!("Bearer {app_token}")), ("Accept".into(), "application/json".into())],
        body: None,
    };
    // Never pass the transport's message on: it can carry the request URL, which holds the token.
    let unreachable = || ConnError::other("The token information endpoint could not be reached");
    let response = svc.http.send(request).await.map_err(|_| unreachable())?;
    let status = response.status as i32;
    let bytes = response.read_body(BODY_LIMIT).await.map_err(|_| unreachable())?;
    let data = match serde_json::from_slice::<Value>(&bytes) {
        Ok(v) => without_secrets(v),
        Err(_) if bytes.is_empty() => Value::Null,
        Err(_) => Value::String("The token information endpoint did not answer with JSON".into()),
    };
    if status >= 400 {
        return Ok(failure_events(data, status));
    }
    Ok(vec![Event { name: EVENT_OUTPUT, result: event_map(data, status) }])
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn details(v: Value) -> Map<String, Value> {
        v.as_object().cloned().unwrap()
    }

    #[test]
    fn meta_connections_default_to_debug_token() {
        let d = details(json!({"tokenDetails": {"url": "https://graph.facebook.com/oauth/access_token"}}));
        assert_eq!(endpoint(&d).unwrap(), InfoEndpoint { url: META_DEBUG_TOKEN.into(), input_param: "input_token".into() });
    }

    #[test]
    fn other_providers_need_token_info() {
        let d = details(json!({"tokenDetails": {"url": "https://login.example.com/token"}}));
        assert!(endpoint(&d).is_err());
        let d = details(json!({"tokenDetails": {"url": "https://login.example.com/token"},
            "tokenInfo": {"url": "https://login.example.com/introspect", "inputTokenParam": "token"}}));
        assert_eq!(endpoint(&d).unwrap(), InfoEndpoint { url: "https://login.example.com/introspect".into(), input_param: "token".into() });
    }

    #[test]
    fn token_info_must_stay_on_the_token_host_over_https() {
        for url in ["https://evil.example.com/debug_token", "http://graph.facebook.com/debug_token", "not a url", ""] {
            let d = details(json!({"tokenDetails": {"url": "https://graph.facebook.com/oauth/access_token"}, "tokenInfo": {"url": url}}));
            assert!(endpoint(&d).is_err(), "{url}");
        }
        let d = details(json!({"tokenInfo": {"url": "https://graph.facebook.com/debug_token"}}));
        assert!(endpoint(&d).is_err(), "no token endpoint");
    }

    #[test]
    fn app_token_needs_both_halves() {
        let d = details(json!({"tokenDetails": {"queryParams": {"client_id": "11", "client_secret": "s"}}}));
        assert_eq!(app_token(&d).unwrap(), "11|s");
        let d = details(json!({"tokenDetails": {"queryParams": {"client_id": "11", "client_secret": ""}}}));
        assert!(app_token(&d).is_err());
        assert!(app_token(&Map::new()).is_err());
    }

    #[test]
    fn credentials_never_come_back() {
        let v = json!({"data": {"app_id": "1", "access_token": "x", "nested": [{"client_secret": "y", "scope": "s", "target_ids": ["5"]}],
            "granular_scopes": [{"scope": "whatsapp_business_management", "target_ids": ["541561272379332"]}]}});
        assert_eq!(
            without_secrets(v),
            json!({"data": {"app_id": "1", "nested": [{"scope": "s", "target_ids": ["5"]}],
                "granular_scopes": [{"scope": "whatsapp_business_management", "target_ids": ["541561272379332"]}]}})
        );
    }

    #[test]
    fn failures_raise_error_then_output() {
        let e = failure_events(Value::String("m".into()), 400);
        assert_eq!(e.iter().map(|e| e.name).collect::<Vec<_>>(), vec![EVENT_ERROR, EVENT_OUTPUT]);
        assert_eq!(e[0].result["statusCode"], json!(400));
    }
}
