//! `OAuth2RestService`: the access token of an OAuth2 connection (cached in `RestOAuthToken`,
//! refreshed with the refresh token for the authorization-code grant, fetched anew for the
//! client-credentials grant), the consent flow (evoke, callback, revoke), and the call itself
//! with the token in `Authorization`.

use chrono::{Duration as ChronoDuration, NaiveDateTime};
use http::StatusCode;
use serde_json::{Map, Value};

use base64::Engine;

use super::http::{retrieve_json_with, JsonTarget};
use super::{basic, body};
use super::spring_uri;
use super::{RestRequest, RestResponse};
use crate::connection::{self, Connection, ConnectionType, GRANT_AUTHORIZATION_CODE};
use crate::context::{AuthorityCheck, Caller};
use crate::error::{messages, ConnError, ConnResult};
use crate::java;
use crate::tokens::{CoreToken, TokenType};
use crate::{outbound, Connections};

pub const CACHE_NAME: &str = "RestOAuthToken";
pub const CONSENT_CALLBACK_URI: &str = "/api/core/connections/oauth/callback";

const AUTH_GRANT_TYPE: &str = "grantType";
const AUTH_HEADER_PREFIX: &str = "authHeaderPrefix";
const HEADERS: &str = "headers";
const TOKEN_KEY: &str = "tokenKey";
const REFRESH_TOKEN_KEY: &str = "refreshTokenKey";
const TOKEN_EXPIRES_AT_KEY: &str = "expireAtKey";
const REFRESH_TOKEN_EXPIRES_AT_KEY: &str = "refreshExpireAtKey";
const IS_LIFETIME_TOKEN: &str = "isLifeTimeToken";

/// `getCacheKeys(connectionName, clientCode, appCode)`, joined as `makeKey` joins them (a null
/// part is left out).
pub fn cache_key(connection_name: Option<&str>, client_code: Option<&str>, app_code: Option<&str>) -> String {
    [connection_name, Some(":"), client_code, Some(":"), app_code].iter().flatten().copied().collect()
}

/// The app whose tokens a call uses: the app owning the connection, or the caller's URL app
/// when the connection has none. The client stays the caller's own.
pub fn token_app_code(conn: Option<&Connection>, caller: Option<&Caller>) -> Option<String> {
    if let Some(app) = conn.and_then(|c| c.app_code.as_deref()).filter(|a| !java::is_blank(a)) {
        return Some(app.to_string());
    }
    caller.and_then(|c| c.url_app_code.clone())
}

fn npe(what: &str) -> ConnError {
    ConnError::other(format!("Cannot invoke \"{what}\" because the value is null"))
}

fn details_map<'a>(conn: &'a Connection, key: &str) -> Option<&'a Map<String, Value>> {
    conn.detail(key).and_then(Value::as_object)
}

/// `OAuth2RestService.call`: a token, then the basic call with `Authorization` (and the
/// connection's `headers`) added to the request's headers.
pub async fn call(
    svc: &Connections,
    caller: &Caller,
    conn: &Connection,
    mut request: RestRequest,
    file_download: bool,
) -> ConnResult<Option<RestResponse>> {
    if !caller.present {
        return Err(npe("com.fincity.saas.commons.security.jwt.ContextAuthentication.getClientCode()"));
    }
    let app = token_app_code(Some(conn), Some(caller));
    let token = access_token(svc, caller, app.as_deref(), caller.client_code.as_deref(), conn).await?;

    let prefix = conn.detail(AUTH_HEADER_PREFIX).filter(|v| !v.is_null()).map(java::to_java_string);
    let token_text = token.unwrap_or_else(|| "null".into());
    let authorization = match prefix {
        Some(p) => format!("{p} {token_text}"),
        None => token_text,
    };
    request.add_header("Authorization", &authorization);
    if let Some(extra) = details_map(conn, HEADERS) {
        for (k, v) in extra {
            match v {
                Value::Null => {}
                Value::String(s) => request.add_header(k, s),
                other => {
                    return Err(ConnError::other(format!(
                        "class {} cannot be cast to class java.lang.String",
                        if other.is_number() { "java.lang.Integer" } else { "java.lang.Object" }
                    )))
                }
            }
        }
    }
    basic::call(svc, conn, request, file_download).await
}

/// `getAccessToken(appCode, clientCode, connection)`: the cached or stored access token while
/// it is valid; otherwise a refresh (authorization code) or a new client-credentials token.
pub async fn access_token(
    svc: &Connections,
    caller: &Caller,
    app_code: Option<&str>,
    client_code: Option<&str>,
    conn: &Connection,
) -> ConnResult<Option<String>> {
    let is_authorization_code = conn.detail_str(AUTH_GRANT_TYPE) == Some(GRANT_AUTHORIZATION_CODE);
    let key = cache_key(conn.name.as_deref(), client_code, app_code);
    let existing = svc
        .oauth_cache
        .get_or_load(CACHE_NAME, key, || async {
            match (client_code, app_code) {
                (Some(c), Some(a)) => svc.tokens.active_token(c, a, conn.name(), TokenType::Access).await,
                // `CLIENT_CODE = null` matches nothing.
                _ => Ok(None),
            }
        })
        .await?;

    match existing {
        Some(token) => {
            if token.expires_at.is_none_or(|e| e > svc.clock.now()) {
                return Ok(token.token);
            }
            if is_authorization_code {
                return refresh_access_token(svc, conn, client_code, app_code).await.map(Some);
            }
            svc.cache
                .evict_everywhere(CACHE_NAME, &cache_key(conn.name.as_deref(), token.client_code.as_deref(), token.app_code.as_deref()))
                .await;
            create_client_credentials_token(svc, caller, conn).await
        }
        None => {
            if is_authorization_code {
                return refresh_access_token(svc, conn, client_code, app_code).await.map(Some);
            }
            create_client_credentials_token(svc, caller, conn).await
        }
    }
}

/// `calculateExpiryTime`: none for a lifetime token or when the response has no expiry,
/// otherwise now plus the seconds the response gives.
pub fn calculate_expiry(
    details: &Map<String, Value>,
    token_response: &Map<String, Value>,
    token_type: TokenType,
    now: NaiveDateTime,
) -> ConnResult<Option<NaiveDateTime>> {
    let lifetime = details.get(IS_LIFETIME_TOKEN) == Some(&Value::Bool(true));
    let key_name = if token_type == TokenType::Access { TOKEN_EXPIRES_AT_KEY } else { REFRESH_TOKEN_EXPIRES_AT_KEY };
    let expires_value = details.get(key_name).and_then(Value::as_str).and_then(|k| token_response.get(k));
    if lifetime || java::safe_is_blank(expires_value) {
        return Ok(None);
    }
    let text = java::to_java_string(expires_value.unwrap_or(&Value::Null));
    let seconds: i64 = text.parse().map_err(|_| ConnError::other(format!("For input string: \"{text}\"")))?;
    Ok(Some(now + ChronoDuration::seconds(seconds)))
}

/// `tokenResponse.get(key).toString()`.
fn response_value(response: &Map<String, Value>, details: &Map<String, Value>, key_detail: &str) -> ConnResult<String> {
    let key = details.get(key_detail).and_then(Value::as_str);
    match key.and_then(|k| response.get(k)).filter(|v| !v.is_null()) {
        Some(v) => Ok(java::to_java_string(v)),
        None => Err(npe("Object.toString()")),
    }
}

fn is_lifetime_detail(details: &Map<String, Value>) -> Option<bool> {
    details.get(IS_LIFETIME_TOKEN).and_then(Value::as_bool)
}

/// The query parameters of a `tokenDetails` / `updateToken` / `consentDetails` block, with
/// `null` values left out, as `value.toString()`.
fn query_params(block: &Map<String, Value>) -> Vec<(String, String)> {
    block
        .get("queryParams")
        .and_then(Value::as_object)
        .map(|q| q.iter().filter(|(_, v)| !v.is_null()).map(|(k, v)| (k.clone(), java::to_java_string(v))).collect())
        .unwrap_or_default()
}

/// A token endpoint stored in the connection: Java fetches it without the call-time guard;
/// here it is guarded like every other outbound call (see DIFFERENCES.md).
async fn fetch_token(svc: &Connections, method: &str, uri: &str, target: JsonTarget) -> ConnResult<Option<Value>> {
    fetch_token_with(svc, method, uri, TokenRequest::default(), target).await
}

async fn fetch_token_with(svc: &Connections, method: &str, uri: &str, request: TokenRequest, target: JsonTarget) -> ConnResult<Option<Value>> {
    if svc.config.block_private_targets {
        outbound::guard_target(uri).await?;
    }
    retrieve_json_with(&svc.http, method, uri, request.headers, request.body, target).await
}

/// The headers and body of a client-credentials token request (Rust only; Java sends neither).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TokenRequest {
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

/// `tokenDetails.clientAuthentication: "basic"`: the client's id and secret in
/// `Authorization: Basic` (RFC 6749 2.3.1, each form-encoded first). They are read from
/// `tokenDetails` (`clientId`, `clientSecret`), then the connection details, then the
/// `client_id` / `client_secret` query parameters where the stored connections keep them.
fn basic_client_authentication(details: &Map<String, Value>, token_details: &Map<String, Value>) -> ConnResult<String> {
    let query = token_details.get("queryParams").and_then(Value::as_object);
    let find = |camel: &str, snake: &str| -> Option<String> {
        [token_details.get(camel), details.get(camel), query.and_then(|q| q.get(snake))]
            .into_iter()
            .flatten()
            .find(|v| !java::safe_is_blank(Some(v)))
            .map(java::to_java_string)
    };
    let (Some(id), Some(secret)) = (find("clientId", "client_id"), find("clientSecret", "client_secret")) else {
        return Err(ConnError::coded(
            StatusCode::BAD_REQUEST,
            "CORE.CONNECTION_CLIENT_CREDENTIALS_MISSING",
            "Basic client authentication needs clientId and clientSecret in the connection's tokenDetails",
        ));
    };
    let pair = format!("{}:{}", spring_uri::url_encode_form(&id), spring_uri::url_encode_form(&secret));
    Ok(format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(pair)))
}

/// What the client-credentials request carries besides its query parameters: an optional
/// `tokenDetails.body` (an object, form-encoded unless `bodyType` is `json`) and optional Basic
/// client authentication (`clientAuthentication: "basic"`).
pub fn token_request(details: &Map<String, Value>, token_details: &Map<String, Value>) -> ConnResult<TokenRequest> {
    let mut request = TokenRequest::default();
    match token_details.get("body") {
        None | Some(Value::Null) => {}
        Some(Value::Object(b)) => {
            let json_body = token_details.get("bodyType").and_then(Value::as_str).is_some_and(|t| t.eq_ignore_ascii_case("json"));
            let payload = Value::Object(b.clone());
            if json_body {
                request.headers.push(("Content-Type".into(), "application/json".into()));
                request.body = Some(serde_json::to_vec(&payload).unwrap_or_default());
            } else {
                request.headers.push(("Content-Type".into(), "application/x-www-form-urlencoded".into()));
                request.body = Some(body::form_body(&payload));
            }
        }
        Some(_) => {
            return Err(ConnError::coded(
                StatusCode::BAD_REQUEST,
                "CORE.CONNECTION_TOKEN_BODY_INVALID",
                "The connection's tokenDetails.body must be an object of the values to send",
            ))
        }
    }
    match token_details.get("clientAuthentication").and_then(Value::as_str) {
        Some(a) if a.eq_ignore_ascii_case("basic") => {
            request.headers.push(("Authorization".into(), basic_client_authentication(details, token_details)?));
        }
        _ => {}
    }
    if !request.headers.is_empty() {
        request.headers.push(("Accept".into(), "application/json".into()));
    }
    Ok(request)
}

/// `refreshAccessToken`: revoke the access tokens, take the active refresh token, ask the
/// `updateToken` endpoint for a new access token, store it and drop the cached one.
pub async fn refresh_access_token(
    svc: &Connections,
    conn: &Connection,
    client_code: Option<&str>,
    app_code: Option<&str>,
) -> ConnResult<String> {
    let denied = || ConnError::coded(StatusCode::BAD_REQUEST, "CORE.INTEGRATION_TOKEN_EXPIRED", "Access denied: Integration token unavailable or expired");
    let (Some(client), Some(app)) = (client_code, app_code) else { return Err(denied()) };
    let details = conn.details().cloned().unwrap_or_default();

    svc.tokens.revoke(client, app, conn.name(), Some(TokenType::Access)).await?;
    let Some(refresh) = svc.tokens.active_token(client, app, conn.name(), TokenType::Refresh).await? else {
        return Err(denied());
    };

    let update = details.get("updateToken").and_then(Value::as_object).ok_or_else(|| npe("java.util.Map.getOrDefault(Object, Object)"))?;
    let url = update.get("url").and_then(Value::as_str).unwrap_or("");
    let mut params = vec![("refresh_token".to_string(), refresh.token.clone().unwrap_or_else(|| "null".into()))];
    params.extend(query_params(update));
    let uri = spring_uri::build_to_uri(url, &params)?;
    let method = update.get("methodType").and_then(Value::as_str).unwrap_or("POST");
    let method = if method == "POST" { "POST" } else { "GET" };
    let Some(Value::Object(response)) = fetch_token(svc, method, &uri, JsonTarget::Map).await? else {
        return Err(denied());
    };

    let now = svc.clock.now();
    let created = svc
        .tokens
        .create(&CoreToken {
            client_code: refresh.client_code.clone(),
            app_code: refresh.app_code.clone(),
            state: refresh.state.clone(),
            connection_name: refresh.connection_name.clone(),
            user_id: refresh.user_id,
            token_type: Some(TokenType::Access),
            token: Some(response_value(&response, &details, TOKEN_KEY)?),
            expires_at: calculate_expiry(&details, &response, TokenType::Access, now)?,
            is_lifetime_token: is_lifetime_detail(&details),
            token_metadata: Some(response),
            ..Default::default()
        })
        .await?;
    svc.cache.evict_everywhere(CACHE_NAME, &cache_key(conn.name.as_deref(), Some(client), Some(app))).await;
    created.token.ok_or_else(denied)
}

/// `createClientCredentialsToken`: POST to `tokenDetails.url` with its query parameters and
/// store the token the response names. The row carries the connection's client and app.
/// The request may also carry a body and Basic client authentication ([`token_request`]); a
/// connection with neither must have `queryParams`, as in Java.
pub async fn create_client_credentials_token(svc: &Connections, caller: &Caller, conn: &Connection) -> ConnResult<Option<String>> {
    if !caller.present {
        return Ok(None);
    }
    let details = conn.details().cloned().unwrap_or_default();
    let token_details = details.get("tokenDetails").and_then(Value::as_object).ok_or_else(|| npe("java.util.Map.get(Object)"))?;
    let url = token_details.get("url").and_then(Value::as_str).unwrap_or("");
    let request = token_request(&details, token_details)?;
    if request.headers.is_empty() && !token_details.get("queryParams").is_some_and(Value::is_object) {
        return Err(npe("java.util.Map.forEach(java.util.function.BiConsumer)"));
    }
    let uri = spring_uri::build_to_uri(url, &query_params(token_details))?;
    let Some(response) = fetch_token_with(svc, "POST", &uri, request, JsonTarget::JsonNode).await? else { return Ok(None) };
    let response = response.as_object().cloned().unwrap_or_default();

    let as_text = |key_detail: &str| -> ConnResult<String> {
        let key = details.get(key_detail).and_then(Value::as_str);
        match key.and_then(|k| response.get(k)) {
            None => Err(npe("com.fasterxml.jackson.databind.JsonNode.asText()")),
            Some(Value::String(s)) => Ok(s.clone()),
            Some(Value::Null) => Ok("null".into()),
            Some(Value::Object(_)) | Some(Value::Array(_)) => Ok(String::new()),
            Some(v) => Ok(java::to_java_string(v)),
        }
    };
    let token = as_text(TOKEN_KEY)?;
    let expires_text = as_text(TOKEN_EXPIRES_AT_KEY)?;
    let seconds: i64 = expires_text.parse().map_err(|_| ConnError::other(format!("For input string: \"{expires_text}\"")))?;

    let created = svc
        .tokens
        .create(&CoreToken {
            client_code: conn.client_code.clone(),
            app_code: conn.app_code.clone(),
            user_id: caller.user_id,
            connection_name: conn.name.clone(),
            token_type: Some(TokenType::Access),
            token: Some(token),
            expires_at: Some(svc.clock.now() + ChronoDuration::seconds(seconds)),
            ..Default::default()
        })
        .await?;
    Ok(created.token)
}

/// `getAccessToken(appCode, clientCode, connectionName)`: the internal token route. The
/// connection is read without access checks.
pub async fn access_token_for(
    svc: &Connections,
    caller: &Caller,
    app_code: Option<&str>,
    client_code: Option<&str>,
    connection_name: &str,
) -> ConnResult<Option<String>> {
    let (Some(app), Some(client)) = (app_code, client_code) else { return Ok(None) };
    let Some(conn) = connection::read_internal_connection(svc.store.as_ref(), connection_name, app, client, ConnectionType::RestApi).await?
    else {
        return Ok(None);
    };
    access_token(svc, caller, Some(app), Some(client), &conn).await
}

/// Whether the caller may change the business's token for the connection: its `consentAuth`
/// is absent or blank (as before the field existed), or the caller's authorities satisfy it.
fn satisfies_consent_auth(check: &dyn AuthorityCheck, caller: &Caller, conn: &Connection) -> bool {
    match conn.consent_auth.as_deref().filter(|e| !java::is_blank(e)) {
        None => true,
        Some(expression) => check.has_authority(Some(expression), &caller.authorities),
    }
}

/// Rust only: the connection's `consentAuth` gate on starting a consent, which replaces the
/// business's token for the connection. Absent or blank lets every caller through, as before
/// the field existed; otherwise the caller's authorities must satisfy the expression, or the
/// consent is refused (403) before a state row or a URL is made. The callback is not gated:
/// it only completes a consent this check already let start.
pub fn check_consent_auth(check: &dyn AuthorityCheck, caller: &Caller, conn: &Connection) -> ConnResult<()> {
    if satisfies_consent_auth(check, caller, conn) {
        return Ok(());
    }
    Err(ConnError::coded(
        StatusCode::FORBIDDEN,
        "CORE.CONNECTION_CONSENT_FORBIDDEN",
        format!("Consent for the connection {} is not allowed: the caller does not satisfy its consentAuth", conn.name()),
    )
    .param("connection", conn.name()))
}

/// `evokeConsentAuth`: the provider's consent URL for an authorization-code connection, with
/// a new state row to match the callback against. `None` when the connection is not visible;
/// refused when the caller does not satisfy its `consentAuth` ([`check_consent_auth`]).
pub async fn evoke_consent(
    svc: &Connections,
    caller: &Caller,
    connection_name: &str,
    forwarded_host: Option<&str>,
) -> ConnResult<Option<String>> {
    let callback = format!("https://{}{CONSENT_CALLBACK_URI}", forwarded_host.unwrap_or("null"));
    if !caller.present {
        return Ok(None);
    }
    let (Some(app), Some(url_client)) = (caller.url_app_code.as_deref(), caller.url_client_code.as_deref()) else {
        return Ok(None);
    };
    let Some(conn) = connection::read(svc.store.as_ref(), caller, connection_name, app, url_client, ConnectionType::RestApi).await? else {
        return Ok(None);
    };
    check_consent_auth(svc.authority_check.as_ref(), caller, &conn)?;
    if conn.detail_str(AUTH_GRANT_TYPE) != Some(GRANT_AUTHORIZATION_CODE) {
        return Err(ConnError::coded(StatusCode::BAD_REQUEST, "CORE.CONNECTION_GRANT_TYPE_INVALID", "Invalid Connection Grant Type."));
    }

    let empty = Map::new();
    let consent = details_map(&conn, "consentDetails").unwrap_or(&empty);
    let auth_base = consent.get("url").and_then(Value::as_str).unwrap_or("");
    if auth_base.is_empty() {
        return Err(ConnError::coded(StatusCode::BAD_REQUEST, "CORE.AUTHORIZATION_URL_MISSING", "Authorization URL is required"));
    }

    let state = uuid::Uuid::new_v4().to_string();
    svc.tokens
        .create(&CoreToken {
            client_code: caller.client_code.clone(),
            app_code: caller.url_app_code.clone(),
            connection_name: conn.name.clone(),
            token_type: Some(TokenType::Access),
            state: Some(state.clone()),
            user_id: caller.user_id,
            ..Default::default()
        })
        .await?;

    let mut params = query_params(consent);
    params.push(("redirect_uri".into(), callback));
    params.push(("state".into(), state));
    spring_uri::build_to_uri(auth_base, &params).map(Some)
}

/// What the callback route answers: a redirect, or nothing at all (status 200, no body).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallbackOutcome {
    /// 302 with this `Location`.
    Redirect(String),
    /// 302 without a `Location` (Java sets the status before looking for the state).
    FoundWithoutLocation,
    /// The chain completed empty: 200 with no body.
    Empty,
}

/// `oAuth2Callback`: exchange the code for tokens, store them on the state's row (and a refresh
/// token row), and send the browser back to the connection's `pagePath`.
pub async fn oauth2_callback(
    svc: &Connections,
    caller: &Caller,
    code: Option<&str>,
    state: Option<&str>,
    forwarded_host: Option<&str>,
    request_path: &str,
) -> ConnResult<CallbackOutcome> {
    let base_page = format!("https://{}", forwarded_host.unwrap_or("null"));
    if code.is_none() {
        return invalid_callback(svc, caller, state, &base_page).await;
    }
    let callback_uri = format!("{base_page}{request_path}");

    let Some(core_token) = svc.tokens.by_state(state).await? else { return Ok(CallbackOutcome::Empty) };
    let (Some(t_client), Some(t_app), Some(t_conn)) =
        (core_token.client_code.clone(), core_token.app_code.clone(), core_token.connection_name.clone())
    else {
        return Ok(CallbackOutcome::Empty);
    };
    let Some(conn) = connection::read(svc.store.as_ref(), caller, &t_conn, &t_app, &t_client, ConnectionType::RestApi).await? else {
        return Ok(CallbackOutcome::Empty);
    };
    svc.tokens.revoke(&t_client, &t_app, &t_conn, None).await?;
    svc.cache.evict_everywhere(CACHE_NAME, &cache_key(conn.name.as_deref(), Some(&t_client), Some(&t_app))).await;

    let details = conn.details().cloned().unwrap_or_default();
    let token_details = details.get("tokenDetails").and_then(Value::as_object).ok_or_else(|| npe("java.util.Map.getOrDefault(Object, Object)"))?;
    let token_url = token_details.get("url").and_then(Value::as_str).unwrap_or("");
    let mut params = vec![
        ("code".to_string(), code.unwrap_or_default().to_string()),
        ("redirect_uri".to_string(), callback_uri),
    ];
    params.extend(query_params(token_details));
    let uri = spring_uri::build_to_uri(token_url, &params)?;
    let method = if token_details.get("methodType").and_then(Value::as_str).unwrap_or("GET") == "POST" { "POST" } else { "GET" };
    let Some(Value::Object(response)) = fetch_token(svc, method, &uri, JsonTarget::Map).await? else {
        return Ok(CallbackOutcome::Empty);
    };

    let now = svc.clock.now();
    let mut access = core_token.clone();
    access.token = Some(response_value(&response, &details, TOKEN_KEY)?);
    access.expires_at = calculate_expiry(&details, &response, TokenType::Access, now)?;
    access.is_lifetime_token = is_lifetime_detail(&details);
    access.token_metadata = Some(response.clone());

    let refresh_key = details.get(REFRESH_TOKEN_KEY).and_then(Value::as_str).filter(|k| !java::is_blank(k));
    let refresh = match refresh_key {
        Some(k) if response.contains_key(k) => {
            let expiry = calculate_expiry(&details, &response, TokenType::Refresh, now)?;
            Some(CoreToken {
                client_code: core_token.client_code.clone(),
                app_code: conn.app_code.clone(),
                state: core_token.state.clone(),
                connection_name: conn.name.clone(),
                user_id: core_token.user_id,
                expires_at: expiry,
                is_lifetime_token: Some(expiry.is_none()),
                token_type: Some(TokenType::Refresh),
                token: Some(java::to_java_string(&response[k])),
                token_metadata: Some(response.clone()),
                ..Default::default()
            })
        }
        _ => None,
    };

    // `accessTokenUpdate.zipWith(refreshTokenCreate)`: both run.
    let updated = svc.tokens.update(&access);
    let created = async {
        match &refresh {
            Some(r) => svc.tokens.create(r).await.map(Some),
            None => Ok(None),
        }
    };
    let (updated, created) = tokio::join!(updated, created);
    let updated = updated?;
    created?;
    if updated.is_none() {
        return Ok(CallbackOutcome::Empty);
    }

    let page = format!("{base_page}{}", conn.detail("pagePath").map(java::to_java_string).unwrap_or_else(|| "null".into()));
    let location = spring_uri::build_to_uri_string(&page, &[(conn.name().to_string(), "success".into())])?;
    Ok(CallbackOutcome::Redirect(location))
}

async fn invalid_callback(svc: &Connections, caller: &Caller, state: Option<&str>, base_page: &str) -> ConnResult<CallbackOutcome> {
    let Some(core_token) = svc.tokens.by_state(state).await? else { return Ok(CallbackOutcome::FoundWithoutLocation) };
    let (Some(t_client), Some(t_app), Some(t_conn)) =
        (core_token.client_code.as_deref(), core_token.app_code.as_deref(), core_token.connection_name.as_deref())
    else {
        return Ok(CallbackOutcome::FoundWithoutLocation);
    };
    let Some(conn) = connection::read(svc.store.as_ref(), caller, t_conn, t_app, t_client, ConnectionType::RestApi).await? else {
        return Ok(CallbackOutcome::FoundWithoutLocation);
    };
    let page = format!("{base_page}{}", conn.detail("pagePath").map(java::to_java_string).unwrap_or_else(|| "null".into()));
    let location = spring_uri::build_to_uri_string(&page, &[(conn.name().to_string(), "invalid".into())])?;
    Ok(CallbackOutcome::Redirect(location))
}

/// Rust only: the `consentAuth` gate on revoking, which drops the business's token as a new
/// consent replaces it. Absent or blank lets every caller through, as before; a refusal is 403
/// `CORE.CONNECTION_REVOKE_FORBIDDEN`.
pub fn check_revoke_auth(check: &dyn AuthorityCheck, caller: &Caller, conn: &Connection) -> ConnResult<()> {
    if satisfies_consent_auth(check, caller, conn) {
        return Ok(());
    }
    Err(ConnError::coded(
        StatusCode::FORBIDDEN,
        "CORE.CONNECTION_REVOKE_FORBIDDEN",
        format!("Revoking the token of the connection {} is not allowed: the caller does not satisfy its consentAuth", conn.name()),
    )
    .param("connection", conn.name()))
}

/// The connection whose tokens a revoke drops, for its gate: read as the tokens' client resolves
/// it, without the access or `onlyThruKIRun` checks, so hiding a connection from the caller
/// cannot skip its gate. None found: no gate, as before.
async fn gate_revoke(svc: &Connections, caller: &Caller, connection_name: &str, app: &str, client: &str) -> ConnResult<()> {
    let url_client = caller.url_client_code.as_deref().unwrap_or(client);
    match svc.store.read_internal(connection_name, app, url_client, client).await? {
        Some(conn) => check_revoke_auth(svc.authority_check.as_ref(), caller, &conn),
        None => Ok(()),
    }
}

/// `revokeConnectionToken`: revokes the caller's tokens for the connection. Refused when the
/// caller has no active access token for it, and (Rust only) when the caller does not satisfy
/// the connection's `consentAuth` ([`check_revoke_auth`]), before anything is looked up or
/// revoked.
pub async fn revoke_connection_token(svc: &Connections, caller: &Caller, connection_name: &str) -> ConnResult<bool> {
    let refuse = || ConnError::msg(StatusCode::BAD_REQUEST, messages::CANNOT_DELETE_TOKEN_WITH_CLIENT_CODE, &[connection_name]);
    if !caller.present {
        return Err(refuse());
    }
    let (Some(client), Some(app)) = (caller.client_code.as_deref(), caller.url_app_code.as_deref()) else {
        return Err(refuse());
    };
    gate_revoke(svc, caller, connection_name, app, client).await?;
    let Some(token) = svc.tokens.active_token(client, app, connection_name, TokenType::Access).await? else {
        return Err(refuse());
    };
    svc.tokens.revoke(client, app, connection_name, None).await?;
    svc.cache
        .evict_everywhere(CACHE_NAME, &cache_key(Some(connection_name), token.client_code.as_deref(), token.app_code.as_deref()))
        .await;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn conn(app: Option<&str>) -> Connection {
        let mut c = Connection::default();
        c.app_code = app.map(str::to_string);
        c
    }

    fn caller(url_app: &str) -> Caller {
        Caller { present: true, url_app_code: Some(url_app.into()), ..Default::default() }
    }

    /// OAuth2RestServiceTokenAppTest.
    #[test]
    fn token_app_is_the_connections_app() {
        assert_eq!(token_app_code(Some(&conn(Some("marketingai"))), Some(&caller("leadzumptwo"))).as_deref(), Some("marketingai"));
        assert_eq!(token_app_code(Some(&conn(Some("leadzump"))), Some(&caller("leadzump"))).as_deref(), Some("leadzump"));
        assert_eq!(token_app_code(Some(&conn(None)), Some(&caller("sitezump"))).as_deref(), Some("sitezump"));
        assert_eq!(token_app_code(Some(&conn(Some(" "))), Some(&caller("sitezump"))).as_deref(), Some("sitezump"));
        assert_eq!(token_app_code(None, Some(&caller("sitezump"))).as_deref(), Some("sitezump"));
        assert_eq!(token_app_code(None, None), None);
    }

    #[test]
    fn cache_keys_drop_null_parts() {
        assert_eq!(cache_key(Some("META_API"), Some("SYSTEM"), Some("marketingai")), "META_API:SYSTEM:marketingai");
        assert_eq!(cache_key(Some("c"), Some("S"), None), "c:S:");
    }

    #[test]
    fn expiry() {
        let now = NaiveDateTime::parse_from_str("2026-10-15 10:00:00", "%Y-%m-%d %H:%M:%S").unwrap();
        let d = json!({"expireAtKey": "expires_in", "refreshExpireAtKey": "refresh_expires_in"});
        let d = d.as_object().unwrap();
        let r = json!({"expires_in": 3600, "refresh_expires_in": "7200"});
        let r = r.as_object().unwrap();
        assert_eq!(calculate_expiry(d, r, TokenType::Access, now).unwrap(), Some(now + ChronoDuration::seconds(3600)));
        assert_eq!(calculate_expiry(d, r, TokenType::Refresh, now).unwrap(), Some(now + ChronoDuration::seconds(7200)));
        let lifetime = json!({"expireAtKey": "expires_in", "isLifeTimeToken": true});
        assert_eq!(calculate_expiry(lifetime.as_object().unwrap(), r, TokenType::Access, now).unwrap(), None);
        assert_eq!(calculate_expiry(d, &Map::new(), TokenType::Access, now).unwrap(), None);
        let bad = json!({"expires_in": 1.5});
        assert!(calculate_expiry(d, bad.as_object().unwrap(), TokenType::Access, now).is_err());
    }

    /// Stands in for KIRun's evaluator: an expression is a list of authorities joined by
    /// ` or `, and any one held allows.
    struct AnyOf;

    impl AuthorityCheck for AnyOf {
        fn has_authority(&self, expression: Option<&str>, authorities: &[String]) -> bool {
            expression.unwrap_or("").split(" or ").any(|want| authorities.iter().any(|a| a == want.trim()))
        }
    }

    fn gated(consent_auth: Option<&str>) -> Connection {
        let mut c = Connection { name: Some("META_API".into()), ..Default::default() };
        c.consent_auth = consent_auth.map(str::to_string);
        c
    }

    fn holding(authorities: &[&str]) -> Caller {
        Caller { present: true, authorities: authorities.iter().map(|a| a.to_string()).collect(), ..Default::default() }
    }

    #[test]
    fn no_consent_auth_lets_every_caller_start_a_consent() {
        for c in [gated(None), gated(Some("")), gated(Some("   "))] {
            assert!(check_consent_auth(&AnyOf, &holding(&[]), &c).is_ok());
            assert!(check_consent_auth(&crate::context::NoEvaluator, &Caller::default(), &c).is_ok());
        }
    }

    #[test]
    fn consent_auth_needs_the_callers_authority() {
        let c = gated(Some("Authorities.ADZUMPTWO.ROLE_Account_MANAGE or Authorities.ROLE_Owner"));
        assert!(check_consent_auth(&AnyOf, &holding(&["Authorities.ADZUMPTWO.ROLE_Account_MANAGE"]), &c).is_ok());
        assert!(check_consent_auth(&AnyOf, &holding(&["Authorities.Logged_IN", "Authorities.ROLE_Owner"]), &c).is_ok());

        let e = check_consent_auth(&AnyOf, &holding(&["Authorities.Logged_IN", "Authorities.ADZUMPTWO.ROLE_Report_READ"]), &c).unwrap_err();
        assert_eq!(e.status(), StatusCode::FORBIDDEN);
        assert_eq!(e.code().map(|c| c.code.as_ref()), Some("CORE.CONNECTION_CONSENT_FORBIDDEN"));
        assert_eq!(e.code().unwrap().params, vec![("connection".to_string(), "META_API".to_string())]);
        assert!(e.message().contains("META_API"), "{}", e.message());
        assert!(check_consent_auth(&AnyOf, &Caller::default(), &c).is_err(), "an anonymous caller holds nothing");
    }

    #[test]
    fn revoke_uses_the_same_gate_with_its_own_code() {
        let c = gated(Some("Authorities.ADZUMPTWO.ROLE_Account_MANAGE or Authorities.ROLE_Owner"));
        assert!(check_revoke_auth(&AnyOf, &holding(&["Authorities.ADZUMPTWO.ROLE_Account_MANAGE"]), &c).is_ok());
        assert!(check_revoke_auth(&AnyOf, &holding(&[]), &gated(None)).is_ok());
        assert!(check_revoke_auth(&AnyOf, &holding(&[]), &gated(Some(" "))).is_ok());
        let e = check_revoke_auth(&AnyOf, &holding(&["Authorities.ADZUMPTWO.ROLE_Report_READ"]), &c).unwrap_err();
        assert_eq!(e.status(), StatusCode::FORBIDDEN);
        assert_eq!(e.code().map(|c| c.code.as_ref()), Some("CORE.CONNECTION_REVOKE_FORBIDDEN"));
        assert_eq!(e.code().unwrap().params, vec![("connection".to_string(), "META_API".to_string())]);
        assert!(check_revoke_auth(&crate::context::NoEvaluator, &holding(&["Authorities.ROLE_Owner"]), &c).is_err());
    }

    #[test]
    fn an_unwired_check_keeps_a_gated_consent_shut() {
        let c = gated(Some("Authorities.ROLE_Owner"));
        let e = check_consent_auth(&crate::context::NoEvaluator, &holding(&["Authorities.ROLE_Owner"]), &c).unwrap_err();
        assert_eq!(e.status(), StatusCode::FORBIDDEN);
    }
}
