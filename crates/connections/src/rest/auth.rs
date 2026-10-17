//! `RestAuthService`: a token made by a KIRun function the connection names
//! (`authTokenFunctionNamespace.authTokenFunctionName`, whose first event must carry
//! `accessToken` and `expiresIn`), cached in `RestAuthToken`, then the basic call with
//! `Authorization: <headerPrefix> <token>`.

use async_trait::async_trait;
use chrono::Duration as ChronoDuration;
use http::StatusCode;
use serde_json::{Map, Value};

use super::basic;
use super::{RestRequest, RestResponse};
use crate::connection::Connection;
use crate::context::Caller;
use crate::error::{messages, ConnError, ConnResult};
use crate::java::{self, json};
use crate::tokens::{CoreToken, TokenType};
use crate::Connections;

pub const CACHE_NAME: &str = "RestAuthToken";

const AUTH_TOKEN_FUNCTION_NAME: &str = "authTokenFunctionName";
const AUTH_TOKEN_FUNCTION_NAMESPACE: &str = "authTokenFunctionNamespace";
const ERROR_EVENT: &str = "errorOutput";
const AUTH_TOKEN: &str = "accessToken";
const EXPIRES_IN: &str = "expiresIn";

/// One event a function raised: its name and its result map.
#[derive(Debug, Clone, PartialEq)]
pub struct EventResult {
    pub name: String,
    pub result: Map<String, Value>,
}

/// `coreFunctionService.execute(namespace, name, appCode, clientCode, null, null)`, provided by
/// the core crate. `Ok(None)` is an execution that produced no output; otherwise every event
/// the function raised, in order (`FunctionOutput.allResults()`).
#[async_trait]
pub trait AuthTokenFunction: Send + Sync {
    async fn execute(
        &self,
        namespace: Option<&str>,
        name: &str,
        app_code: Option<&str>,
        client_code: Option<&str>,
    ) -> ConnResult<Option<Vec<EventResult>>>;
}

/// `getCacheKeys(connection)`: client, app and name, a null part left out.
pub fn cache_key(conn: &Connection) -> String {
    [conn.client_code.as_deref(), Some(":"), conn.app_code.as_deref(), Some(":"), conn.name.as_deref()]
        .iter()
        .flatten()
        .copied()
        .collect()
}

fn token_error(conn: &Connection, reason: &str) -> ConnError {
    ConnError::msg(StatusCode::BAD_REQUEST, messages::NOT_ABLE_TO_CREATE_TOKEN, &[conn.name(), reason])
}

/// `RestAuthService.call`.
pub async fn call(
    svc: &Connections,
    _caller: &Caller,
    conn: &Connection,
    mut request: RestRequest,
    file_download: bool,
) -> ConnResult<Option<RestResponse>> {
    let token = access_token(svc, conn).await?;
    let prefix = conn.detail("headerPrefix").filter(|v| !v.is_null()).map(java::to_java_string);
    let authorization = match prefix {
        Some(p) => format!("{p} {token}"),
        None => token,
    };
    request.add_header("Authorization", &authorization);
    basic::call(svc, conn, request, file_download).await
}

/// `getAccessToken(connection)`: the cached or stored token while it is unexpired, otherwise
/// a new one from the auth-token function. Never empty: no token is an error.
pub async fn access_token(svc: &Connections, conn: &Connection) -> ConnResult<String> {
    let existing = svc
        .auth_cache
        .get_or_load(CACHE_NAME, cache_key(conn), || async {
            match (conn.client_code.as_deref(), conn.app_code.as_deref()) {
                (Some(c), Some(a)) => svc.tokens.active_access_token_tuple(c, a, conn.name()).await,
                _ => Ok(None),
            }
        })
        .await?;
    if let Some((token, Some(expires_at))) = existing {
        if expires_at > svc.clock.now() {
            if let Some(t) = token {
                return Ok(t);
            }
        }
    }
    let created = create_new_access_token(svc, conn).await?;
    match created.token {
        Some(t) => Ok(t),
        None => Err(token_error(conn, "no access token could be resolved or created")),
    }
}

async fn create_new_access_token(svc: &Connections, conn: &Connection) -> ConnResult<CoreToken> {
    let output = execute_connection_function(svc, conn).await?;
    svc.cache.evict_everywhere(CACHE_NAME, &cache_key(conn)).await;
    if output.name == ERROR_EVENT {
        return Err(token_error(conn, &event_result_to_string(&output)));
    }
    create_core_token(svc, &output, conn).await
}

/// `EventResult.toString()` (Lombok): `EventResult(name=..., result={k=v, ...})`, the values as
/// their JSON text.
fn event_result_to_string(e: &EventResult) -> String {
    let result = e.result.iter().map(|(k, v)| format!("{k}={}", json::gson_element(v))).collect::<Vec<_>>().join(", ");
    format!("EventResult(name={}, result={{{result}}})", e.name)
}

async fn execute_connection_function(svc: &Connections, conn: &Connection) -> ConnResult<EventResult> {
    if conn.details().is_none() {
        return Err(token_error(conn, "connection has no connection details"));
    }
    let name = conn.detail_str(AUTH_TOKEN_FUNCTION_NAME);
    let namespace = conn.detail_str(AUTH_TOKEN_FUNCTION_NAMESPACE);
    let Some(name) = name.filter(|n| !java::is_blank(n)) else {
        return Err(token_error(conn, &format!("{AUTH_TOKEN_FUNCTION_NAME} is not configured")));
    };
    let full = format!("{}.{name}", namespace.unwrap_or("null"));
    match svc
        .auth_functions
        .execute(namespace, name, conn.app_code.as_deref(), conn.client_code.as_deref())
        .await?
    {
        None => Err(token_error(conn, &format!("{full} produced no output"))),
        Some(events) => events.into_iter().next().ok_or_else(|| token_error(conn, &format!("{full} raised no events"))),
    }
}

async fn create_core_token(svc: &Connections, output: &EventResult, conn: &Connection) -> ConnResult<CoreToken> {
    let token = output.result.get(AUTH_TOKEN).filter(|v| !v.is_null());
    let expires_in = output.result.get(EXPIRES_IN).filter(|v| !v.is_null());
    let Some(token) = token else {
        return Err(token_error(conn, &format!("auth token function returned no '{AUTH_TOKEN}'")));
    };
    let Some(expires_in) = expires_in else {
        return Err(token_error(conn, &format!("auth token function returned no '{EXPIRES_IN}'")));
    };
    let token = as_string(token)?;
    let expires_in = as_long(expires_in)?;
    if java::is_blank(&token) {
        return Err(token_error(conn, &format!("auth token function returned a blank '{AUTH_TOKEN}'")));
    }
    svc.tokens
        .create(&CoreToken {
            client_code: conn.client_code.clone(),
            app_code: conn.app_code.clone(),
            connection_name: conn.name.clone(),
            token_type: Some(TokenType::Access),
            token: Some(token),
            is_revoked: Some(false),
            expires_at: Some(svc.clock.now() + ChronoDuration::seconds(expires_in)),
            ..Default::default()
        })
        .await
}

/// `JsonElement.getAsString()`.
fn as_string(v: &Value) -> ConnResult<String> {
    match v {
        Value::String(s) => Ok(s.clone()),
        Value::Bool(b) => Ok(b.to_string()),
        Value::Number(_) => Ok(json::gson_element(v)),
        Value::Array(a) if a.len() == 1 => as_string(&a[0]),
        Value::Object(_) => Err(ConnError::other("JsonObject")),
        _ => Err(ConnError::other("JsonArray")),
    }
}

/// `JsonElement.getAsLong()`: a number (a decimal truncates), or a string that parses.
fn as_long(v: &Value) -> ConnResult<i64> {
    match v {
        Value::Number(n) => Ok(n.as_i64().unwrap_or_else(|| n.as_f64().unwrap_or(0.0) as i64)),
        Value::String(s) => s.parse::<i64>().map_err(|_| ConnError::other(format!("For input string: \"{s}\""))),
        Value::Array(a) if a.len() == 1 => as_long(&a[0]),
        _ => Err(ConnError::other("JsonObject")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cache_key_and_event_text() {
        let c = Connection::from_json(json!({"name": "ZohoRestSign", "appCode": "sign", "clientCode": "SYSTEM"})).unwrap();
        assert_eq!(cache_key(&c), "SYSTEM:sign:ZohoRestSign");
        let e = EventResult { name: "errorOutput".into(), result: json!({"error": "bad"}).as_object().unwrap().clone() };
        assert_eq!(event_result_to_string(&e), "EventResult(name=errorOutput, result={error=\"bad\"})");
        assert_eq!(as_long(&json!("3600")).unwrap(), 3600);
        assert_eq!(as_long(&json!(3600.9)).unwrap(), 3600);
    }
}
