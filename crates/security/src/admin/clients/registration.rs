//! `ClientController`'s registration routes over `ClientRegistrationService`, and the social
//! sign-up round trip through `AppRegistrationIntegrationService` and its token service.
//!
//! | Route | Who |
//! |---|---|
//! | `POST clients/register/otp/generate` | anyone: an OTP for a registration, when the app verifies |
//! | `GET`/`POST clients/socialRegister/evoke` | anyone: the provider's consent URL (GET redirects to it) |
//! | `GET clients/socialRegister/callback` | anyone: the provider's return, redirected to the app |
//!
//! The provider calls (Google's and Meta's token and profile endpoints) go through [`Providers`];
//! tests point it at an in-process fake.

use async_trait::async_trait;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use serde_json::{json, Map, Value};

use super::common::{err, object_body, reg_error, Kind, SESSION_EXPIRED, UNSUPPORTED_PLATFORM};
use super::entity::{self, col, Col, Entity, Row, CREATED_AT, CREATED_BY, ID, UPDATED_AT, UPDATED_BY};
use super::integrations::{INTEGRATION, PLATFORMS};
use crate::admin::AdminState;
use crate::condition::{ColType, Table};
use crate::errors::{AuthError, AuthResult};
use crate::jackson::json as json_resp;
use crate::model::ContextAuth;
use crate::request::RequestInfo;
use crate::spring::Params;
use crate::web::{self, req_str};
use crate::web_route;

const SOCIAL_CALLBACK_URI: &str = "/api/security/clients/socialRegister/callback";
/// A verified state is spendable this long after the provider's answer.
pub const STATE_VALID_FOR_MINUTES: i64 = 10;

static TOKEN_COLS: [Col; 16] = [
    ID,
    CREATED_AT,
    CREATED_BY,
    UPDATED_AT,
    UPDATED_BY,
    col("integrationId", "INTEGRATION_ID", Kind::U64, true),
    col("authCode", "AUTH_CODE", Kind::Str, false),
    col("state", "STATE", Kind::Str, false),
    col("requestParam", "REQUEST_PARAM", Kind::Json, false),
    col("token", "TOKEN", Kind::Str, false),
    col("refreshToken", "REFRESH_TOKEN", Kind::Str, false),
    col("expiresAt", "EXPIRES_AT", Kind::Ts, false),
    col("username", "USERNAME", Kind::Str, false),
    col("tokenMetadata", "TOKEN_METADATA", Kind::Json, false),
    col("userMetadata", "USER_METADATA", Kind::Json, false),
    entity::extra("_", Kind::Json),
];

/// `AppRegistrationIntegrationToken` over `security_app_reg_integration_tokens`.
pub static TOKEN: Entity = Entity {
    pojo: "AppRegistrationIntegrationToken",
    table: "security_app_reg_integration_tokens",
    cols: &TOKEN_COLS,
    setters: &[],
    aliases: &[],
    filter: Table {
        name: "security_app_reg_integration_tokens",
        columns: &[
            ("ID", ColType::Num),
            ("INTEGRATION_ID", ColType::Num),
            ("AUTH_CODE", ColType::Str),
            ("STATE", ColType::Str),
            ("REQUEST_PARAM", ColType::Str),
            ("TOKEN", ColType::Str),
            ("REFRESH_TOKEN", ColType::Str),
            ("EXPIRES_AT", ColType::Ts),
            ("USERNAME", ColType::Str),
            ("TOKEN_METADATA", ColType::Str),
            ("USER_METADATA", ColType::Str),
            ("CREATED_AT", ColType::Ts),
            ("CREATED_BY", ColType::Num),
            ("UPDATED_BY", ColType::Num),
            ("UPDATED_AT", ColType::Ts),
        ],
    },
    client_column: None,
};

// ---- URLs as Spring builds them ----

/// `java.net.URI`'s multi-argument constructor on a query: what is not a legal URI character is
/// percent-encoded (UTF-8), `%` included; the reserved characters stay as they are.
pub fn quote_query(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let legal = c.is_ascii_alphanumeric() || "_-!.~'()*;/?:@&=+$,".contains(c);
        if legal {
            out.push(c);
        } else {
            let mut buf = [0u8; 4];
            for b in c.encode_utf8(&mut buf).bytes() {
                out.push_str(&format!("%{b:02X}"));
            }
        }
    }
    out
}

/// `UriComponentsBuilder.fromUri(base).queryParam(k, v)...build().toUri()`.
pub fn with_params(base: &str, params: &[(String, String)]) -> String {
    if params.is_empty() {
        return base.to_string();
    }
    let (head, fragment) = match base.split_once('#') {
        Some((h, f)) => (h, Some(f)),
        None => (base, None),
    };
    let mut out = head.to_string();
    let query: Vec<String> = params.iter().map(|(k, v)| format!("{}={}", quote_query(k), quote_query(v))).collect();
    out.push(if head.contains('?') { '&' } else { '?' });
    out.push_str(&query.join("&"));
    if let Some(f) = fragment {
        out.push('#');
        out.push_str(f);
    }
    out
}

/// `firstForwardedHost`: the first `X-Forwarded-Host` value without its port (`null` when none).
pub fn first_forwarded_host(info: &RequestInfo) -> String {
    let Some(raw) = info.header("X-Forwarded-Host").filter(|h| !h.trim().is_empty()) else { return "null".into() };
    let first = raw.split(',').next().unwrap_or("").trim();
    first.split(':').next().unwrap_or("").to_string()
}

// ---- providers ----

/// What a provider answers about the person who consented.
pub type Profile = Map<String, Value>;

/// The provider endpoints (`getGoogleUserToken`, `getMetaUserToken`): a code for an access
/// token, the token for the profile. `Err` is the call's failure message.
#[async_trait]
pub trait Providers: Send + Sync {
    async fn profile(&self, platform: &str, client_id: &str, secret: &str, code: &str, callback: &str) -> Result<Profile, String>;
}

/// The real endpoints, over HTTP.
pub struct HttpProviders {
    pub google_token: String,
    pub google_userinfo: String,
    pub meta_token: String,
    pub meta_me: String,
    http: reqwest::Client,
}

impl HttpProviders {
    pub fn new(google_token: &str, google_userinfo: &str, meta_token: &str, meta_me: &str) -> Self {
        Self {
            google_token: google_token.into(),
            google_userinfo: google_userinfo.into(),
            meta_token: meta_token.into(),
            meta_me: meta_me.into(),
            http: reqwest::Client::new(),
        }
    }

    pub fn real() -> Self {
        Self::new(
            "https://oauth2.googleapis.com/token",
            "https://www.googleapis.com/oauth2/v2/userinfo",
            "https://graph.facebook.com/v20.0/oauth/access_token",
            "https://graph.facebook.com/me",
        )
    }
}

#[async_trait]
impl Providers for HttpProviders {
    async fn profile(&self, platform: &str, client_id: &str, secret: &str, code: &str, callback: &str) -> Result<Profile, String> {
        let token_url = if platform == "GOOGLE" { &self.google_token } else { &self.meta_token };
        let form = [("client_id", client_id), ("client_secret", secret), ("grant_type", "authorization_code"), ("code", code), ("redirect_uri", callback)];
        let resp = self.http.post(token_url).form(&form).send().await.map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("{} from the token endpoint", resp.status()));
        }
        let tok: Map<String, Value> = resp.json().await.map_err(|e| e.to_string())?;
        let access = match tok.get("access_token") {
            Some(Value::String(s)) => s.clone(),
            Some(other) => other.to_string(),
            None => return Err("Cannot invoke \"Object.toString()\" because the return value of \"java.util.Map.get(Object)\" is null".into()),
        };
        let req = if platform == "GOOGLE" {
            self.http.get(&self.google_userinfo).bearer_auth(&access)
        } else {
            self.http.get(&self.meta_me).query(&[("fields", "id,first_name,middle_name,last_name,email,locale"), ("access_token", access.as_str())])
        };
        let resp = req.send().await.map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("{} from the profile endpoint", resp.status()));
        }
        resp.json().await.map_err(|e| e.to_string())
    }
}

// ---- integrations and states ----

/// `getIntegration(platform)`: the integration of the URL's app for the client the caller signed
/// in from.
pub async fn integration(s: &AdminState, ca: &ContextAuth, platform: &str) -> AuthResult<Option<Row>> {
    let Some(app_code) = ca.url_app_code.as_deref() else { return Ok(None) };
    let Some(app) = s.dir().app_by_code(app_code).await? else { return Ok(None) };
    let sql = format!(
        "SELECT {} FROM security_app_reg_integration WHERE (APP_ID = ? AND CLIENT_ID = ? AND PLATFORM = ?) LIMIT 1",
        INTEGRATION.select_list()
    );
    let r = sqlx::query(&sql).bind(app.id).bind(ca.logged_in_from_client_id).bind(platform).fetch_optional(&s.db.pool).await?;
    r.as_ref().map(|r| INTEGRATION.read_row(r)).transpose()
}

/// `verifyIntegrationState(state)`: the token row, or Java's plain `Exception("Invalid state")`.
pub async fn verify_state(s: &AdminState, state: Option<&str>) -> AuthResult<Row> {
    let sql = format!("SELECT {} FROM security_app_reg_integration_tokens WHERE STATE = ? LIMIT 1", TOKEN.select_list());
    let r = sqlx::query(&sql).bind(state).fetch_optional(&s.db.pool).await?;
    match r {
        Some(r) => TOKEN.read_row(&r),
        None => Err(AuthError::internal("Invalid state")),
    }
}

/// `isStateExpired`: ten minutes after the provider's answer (or the mint, without one), in UTC.
pub fn state_expired(token: &Row, now_utc: chrono::NaiveDateTime) -> bool {
    let at = token.get("updatedAt").and_then(Value::as_i64).or_else(|| token.get("createdAt").and_then(Value::as_i64));
    match at {
        None => true,
        Some(t) => t < (now_utc - chrono::Duration::minutes(STATE_VALID_FOR_MINUTES)).and_utc().timestamp(),
    }
}

/// `consumeState(state)`: true for the one caller that cleared it.
pub async fn consume_state(s: &AdminState, state: &str) -> AuthResult<bool> {
    Ok(sqlx::query("UPDATE security_app_reg_integration_tokens SET STATE = NULL WHERE STATE = ?").bind(state).execute(&s.db.pool).await?.rows_affected() == 1)
}

/// The consent URL of a provider for this integration.
pub fn consent_url(platform: &str, client_id: &str, callback: &str, state: &str) -> String {
    let params = |scope: &str, extra: &[(&str, &str)]| -> Vec<(String, String)> {
        let mut p = vec![
            ("client_id".to_string(), client_id.to_string()),
            ("redirect_uri".to_string(), callback.to_string()),
            ("scope".to_string(), scope.to_string()),
            ("response_type".to_string(), "code".to_string()),
            ("state".to_string(), state.to_string()),
        ];
        p.extend(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())));
        p
    };
    if platform == "GOOGLE" {
        with_params("https://accounts.google.com/o/oauth2/v2/auth", &params("email profile openid", &[("prompt", "select_account")]))
    } else {
        with_params("https://www.facebook.com/dialog/oauth", &params("public_profile,email", &[]))
    }
}

/// `evokeRegisterWSocial(platform)`: a new state for the request's parameters, and the consent
/// URL; `None` when the app or the integration is not there.
pub async fn evoke(s: &AdminState, ca: &ContextAuth, platform: &str, params: &Params, host: &str) -> AuthResult<Option<String>> {
    let Some(app_code) = ca.url_app_code.as_deref() else { return Ok(None) };
    if s.dir().app_by_code(app_code).await?.is_none() {
        return Ok(None);
    }
    let Some(intg) = integration(s, ca, platform).await? else { return Ok(None) };
    let state = uuid4();
    let callback = format!("https://{host}{SOCIAL_CALLBACK_URI}");
    let kind = entity::str_of(&intg, "platform").unwrap_or("");
    if kind != "GOOGLE" && kind != "META" {
        return Err(err(StatusCode::BAD_REQUEST, UNSUPPORTED_PLATFORM, &[]));
    }
    let url = consent_url(kind, entity::str_of(&intg, "intgId").unwrap_or(""), &callback, &state);
    // `toSingleValueMap()`: each parameter's first value.
    let mut request_param = Map::new();
    for (k, v) in &params.0 {
        request_param.entry(k.clone()).or_insert_with(|| Value::from(v.clone()));
    }
    let row = json!({"integrationId": intg.get("id"), "state": state, "requestParam": request_param, "createdBy": null});
    entity::insert(&s.db, &TOKEN, row.as_object().unwrap_or(&Row::new())).await?;
    Ok(Some(url))
}

/// A random version 4 UUID in its text form.
fn uuid4() -> String {
    let h = super::urls::random_hex();
    let variant = ['8', '9', 'a', 'b'][(u8::from_str_radix(&h[16..17], 16).unwrap_or(0) % 4) as usize];
    format!("{}-{}-4{}-{}{}-{}", &h[..8], &h[8..12], &h[13..16], variant, &h[17..20], &h[20..32])
}

/// `socialCallbackDestination(token)`: where the browser goes back to, on the app that started.
pub async fn callback_destination(s: &AdminState, ca: &ContextAuth, token: &Row) -> AuthResult<String> {
    let rp = token.get("requestParam").and_then(Value::as_object).cloned().unwrap_or_default();
    let text = |k: &str| rp.get(k).filter(|v| !v.is_null()).map(|v| match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    });
    let Some(app_code) = text("appCode") else { return Err(reg_error("The sign-in did not say which app it started from")) };
    let client_code = text("clientCode");
    let app_root = async {
        let url = s.app_url(ca, Some(&app_code), client_code.as_deref()).await?;
        if url.trim().is_empty() {
            return Err(reg_error(&format!("No address is on record for the app {app_code}")));
        }
        Ok(url)
    };
    let Some(redirect) = text("redirectUrl").filter(|r| !r.trim().is_empty()) else { return Ok(format!("{}/", app_root.await?)) };
    let scheme = redirect.split_once(':').map(|(s, _)| s).filter(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c)));
    match scheme.map(str::to_lowercase) {
        None => {
            let path = if redirect.starts_with('/') { redirect.clone() } else { format!("/{redirect}") };
            Ok(format!("{}{path}", app_root.await?))
        }
        Some(sc) if sc != "http" && sc != "https" => {
            let allowed = client_code.as_ref().is_some_and(|cc| sc == format!("modlix.{cc}.{app_code}").to_lowercase());
            if allowed {
                Ok(redirect)
            } else {
                Ok(format!("{}/", app_root.await?))
            }
        }
        Some(sc) => {
            if apps_own_host(s, &sc, &redirect, &app_code).await? {
                Ok(redirect)
            } else {
                Ok(format!("{}/", app_root.await?))
            }
        }
    }
}

/// `isAppsOwnHost`: the redirect's host resolves (as the gateway resolves hosts) to the app.
async fn apps_own_host(s: &AdminState, scheme: &str, url: &str, app_code: &str) -> AuthResult<bool> {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or("");
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.contains('@') || authority.is_empty() {
        return Ok(false);
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => (h.to_string(), p.to_string()),
        _ => (authority.to_string(), String::new()),
    };
    if host.is_empty() {
        return Ok(false);
    }
    Ok(s.dir().client_pattern(scheme, &host, &port).await?.and_then(|p| p.app_code.clone()).is_some_and(|c| c.eq_ignore_ascii_case(app_code)))
}

/// The request parameters the evoke call recorded, appended to the destination.
fn with_request_params(destination: &str, mut params: Vec<(String, String)>, token: &Row) -> String {
    if let Some(rp) = token.get("requestParam").and_then(Value::as_object) {
        for (k, v) in rp {
            match v {
                Value::Null => {}
                Value::String(s) => params.push((k.clone(), s.clone())),
                other => params.push((k.clone(), other.to_string())),
            }
        }
    }
    with_params(destination, &params)
}

fn found(location: &str) -> Response {
    let mut resp = crate::jackson::empty(StatusCode::FOUND);
    if let Ok(v) = HeaderValue::from_str(location) {
        resp.headers_mut().insert(header::LOCATION, v);
    }
    resp
}

/// `registerWSocialCallback`: the provider's profile recorded on the state, and the browser sent
/// back to the app with it; `None` (an empty 200) when the URL's app is unknown.
pub async fn callback(s: &AdminState, ca: &ContextAuth, params: &Params, providers: &dyn Providers, host: &str) -> AuthResult<Option<Response>> {
    let Some(code) = params.get("code") else {
        let token = verify_state(s, params.get("state")).await?;
        entity::read_by_id(&s.db, &INTEGRATION, entity::u64_of(&token, "integrationId").unwrap_or(0)).await?;
        let destination = callback_destination(s, ca, &token).await?;
        let url = with_request_params(&destination, vec![("error".into(), "access_denied".into())], &token);
        return Ok(Some(found(&url)));
    };
    let Some(app_code) = ca.url_app_code.as_deref() else { return Ok(None) };
    if s.dir().app_by_code(app_code).await?.is_none() {
        return Ok(None);
    }
    let token = verify_state(s, params.get("state")).await?;
    let intg = entity::read_by_id(&s.db, &INTEGRATION, entity::u64_of(&token, "integrationId").unwrap_or(0)).await?;
    let platform = entity::str_of(&intg, "platform").unwrap_or("");
    if platform != "GOOGLE" && platform != "META" {
        return Err(err(StatusCode::BAD_REQUEST, UNSUPPORTED_PLATFORM, &[]));
    }
    let callback = format!("https://{host}{SOCIAL_CALLBACK_URI}");
    let profile = providers
        .profile(platform, entity::str_of(&intg, "intgId").unwrap_or(""), entity::str_of(&intg, "intgSecret").unwrap_or(""), code, &callback)
        .await
        .map_err(AuthError::internal)?;
    let text = |k: &str| -> String {
        match profile.get(k) {
            None => String::new(),
            Some(Value::String(s)) => s.clone(),
            Some(Value::Null) => "null".into(),
            Some(o) => o.to_string(),
        }
    };
    let username = text("email");
    // `update(token)`: only the verified identity is kept.
    let mut stored = entity::read_by_id(&s.db, &TOKEN, entity::u64_of(&token, "id").unwrap_or(0)).await?;
    stored.insert("username".into(), Value::from(username.clone()));
    stored.insert("userMetadata".into(), Value::Object(profile.clone()));
    entity::update(&s.db, &TOKEN, &stored).await?;
    let (first, last) = if platform == "GOOGLE" {
        (text("given_name"), profile.get("family_name").filter(|v| !v.is_null()).map(|_| text("family_name")))
    } else {
        (text("first_name"), Some(text("last_name")))
    };
    let destination = callback_destination(s, ca, &token).await?;
    let mut q = vec![
        ("sessionId".to_string(), entity::str_of(&token, "state").unwrap_or("").to_string()),
        ("userName".to_string(), username.clone()),
        ("emailId".to_string(), username),
        ("firstName".to_string(), first),
    ];
    if let Some(l) = last {
        q.push(("lastName".to_string(), l));
    }
    Ok(Some(found(&with_request_params(&destination, q, &token))))
}

/// `generateOtp` for a registration: only on an app whose registration verifies.
pub async fn generate_otp(s: &AdminState, ca: &ContextAuth, info: &RequestInfo, body: &Map<String, Value>) -> AuthResult<bool> {
    let mut otp = crate::admin::users::otp::OtpBody::read(body)?;
    let Some(client) = info.client_code().as_deref().map(str::to_string) else {
        return Err(AuthError::internal("Cannot invoke \"Object.toString()\" because \"key\" is null"));
    };
    let Some(client) = s.client_by_code(&client).await? else { return Err(reg_error("Feature not supported")) };
    let app = info.app_code();
    let reg = app_prop(s, ca, client.id(), None, app.as_deref(), "REGISTRATION_TYPE").await?;
    if reg != "REGISTRATION_TYPE_VERIFICATION" {
        return Err(reg_error("Feature not supported"));
    }
    otp.purpose = Some(crate::otp::OtpPurpose::Registration);
    s.generate_otp(ca, &otp, info.remote_host(), info.header("x-debug")).await
}

/// `fetchAppProp(clientId, appId, appCode, name)`: the client's value, else the first client's in
/// `HashMap` order, else `""`.
pub async fn app_prop(s: &AdminState, ca: &ContextAuth, client_id: u64, app_id: Option<u64>, app_code: Option<&str>, name: &str) -> AuthResult<String> {
    let props = super::apps::properties(s, ca, Some(client_id), app_id, app_code, Some(name)).await?.unwrap_or_else(|| json!({}));
    let Some(map) = props.as_object().filter(|m| !m.is_empty()) else { return Ok(String::new()) };
    let value = |m: &Value| m.get(name).and_then(|p| p.get("value")).and_then(Value::as_str).map(str::to_string);
    if let Some(own) = map.get(&client_id.to_string()) {
        return Ok(value(own).unwrap_or_default());
    }
    Ok(map.values().next().and_then(value).unwrap_or_default())
}

/// A platform parameter (`SecurityAppRegIntegrationPlatform`): missing is 400, unknown a type
/// mismatch.
fn platform_param(p: &Params) -> AuthResult<String> {
    let v = req_str(p, "platform")?;
    if PLATFORMS.contains(&v) {
        Ok(v.to_string())
    } else {
        Err(web::type_mismatch())
    }
}

pub fn router() -> Router<AdminState> {
    Router::new()
        .route("/api/security/clients/register/otp/generate", post(otp_generate))
        .route("/api/security/clients/socialRegister/evoke", get(evoke_get).post(evoke_post))
        .route("/api/security/clients/socialRegister/callback", get(callback_route))
}

web_route!(otp_generate, AdminState, "/clients/register/otp/generate", false, |s, r, ca| {
    let body = object_body(&r.body)?;
    let m = body.as_object().cloned().unwrap_or_default();
    Ok(json_resp(&Value::Bool(generate_otp(&s, &ca, &r.info, &m).await?)))
});

web_route!(evoke_post, AdminState, "/clients/socialRegister/evoke", false, |s, r, ca| {
    let platform = platform_param(&r.params)?;
    let host = first_forwarded_host(&r.info);
    Ok(match evoke(&s, &ca, &platform, &r.params, &host).await? {
        Some(url) => web::text(&url),
        None => web::nothing(),
    })
});

web_route!(evoke_get, AdminState, "/clients/socialRegister/evoke", false, |s, r, ca| {
    let platform = platform_param(&r.params)?;
    let host = first_forwarded_host(&r.info);
    Ok(match evoke(&s, &ca, &platform, &r.params, &host).await? {
        Some(url) => found(&url),
        None => web::nothing(),
    })
});

web_route!(callback_route, AdminState, "/clients/socialRegister/callback", false, |s, r, ca| {
    let host = first_forwarded_host(&r.info);
    Ok(match callback(&s, &ca, &r.params, &HttpProviders::real(), &host).await? {
        Some(resp) => resp,
        None => web::nothing(),
    })
});

/// The 400 a state that outlived its window answers (`registerWSocial`).
pub fn session_expired() -> AuthError {
    err(StatusCode::BAD_REQUEST, SESSION_EXPIRED, &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_like_uri_components() {
        assert_eq!(quote_query("a b%c/é"), "a%20b%25c/%C3%A9");
        assert_eq!(with_params("https://a.com/x", &[("k".into(), "v w".into())]), "https://a.com/x?k=v%20w");
        assert_eq!(with_params("https://a.com/x?y=1#f", &[("k".into(), "v".into())]), "https://a.com/x?y=1&k=v#f");
        assert_eq!(with_params("https://a.com/", &[]), "https://a.com/");
        let g = consent_url("GOOGLE", "cid", "https://h.com/cb", "st");
        assert_eq!(g, "https://accounts.google.com/o/oauth2/v2/auth?client_id=cid&redirect_uri=https://h.com/cb&scope=email%20profile%20openid&response_type=code&state=st&prompt=select_account");
        assert!(consent_url("META", "c", "cb", "s").starts_with("https://www.facebook.com/dialog/oauth?client_id=c&redirect_uri=cb&scope=public_profile,email"));
        let u = uuid4();
        assert_eq!(u.len(), 36);
        assert_eq!(&u[14..15], "4");
    }

    #[test]
    fn states_expire_after_ten_minutes() {
        let now = chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap().naive_utc();
        let row = |k: &str, t: i64| json!({ k: t }).as_object().cloned().unwrap();
        assert!(!state_expired(&row("updatedAt", 1_800_000_000 - 300), now));
        assert!(state_expired(&row("updatedAt", 1_800_000_000 - 601), now));
        assert!(!state_expired(&row("createdAt", 1_800_000_000), now));
        assert!(state_expired(&Row::new(), now));
        assert_eq!(session_expired().status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn forwarded_hosts_and_params() {
        let mut h = axum::http::HeaderMap::new();
        h.insert("x-forwarded-host", HeaderValue::from_static("a.com:443, b.com"));
        assert_eq!(first_forwarded_host(&RequestInfo::new(h, None)), "a.com");
        assert_eq!(first_forwarded_host(&RequestInfo::new(axum::http::HeaderMap::new(), None)), "null");
        assert_eq!(platform_param(&Params::from_query(Some("platform=GOOGLE"))).unwrap(), "GOOGLE");
        assert!(platform_param(&Params::from_query(Some("platform=x"))).is_err());
        assert!(platform_param(&Params::from_query(None)).is_err());
        let token = json!({"requestParam": {"appCode": "a", "n": null, "x": 1}}).as_object().cloned().unwrap();
        assert_eq!(with_request_params("https://a.com/", vec![("e".into(), "1".into())], &token), "https://a.com/?e=1&appCode=a&x=1");
        assert_eq!(found("https://x").headers()[header::LOCATION], "https://x");
    }

    /// Google's and Meta's endpoints, in process: a code for a token, the token for a profile.
    async fn fake_providers(token_status: u16, token_body: Value, profile_status: u16) -> HttpProviders {
        use axum::routing::{get, post};
        let tb = token_body.clone();
        let app = axum::Router::new()
            .route("/gtoken", post(move || { let tb = tb.clone(); async move { (StatusCode::from_u16(token_status).unwrap(), axum::Json(tb)) } }))
            .route("/mtoken", post(move || { let tb = token_body.clone(); async move { (StatusCode::from_u16(token_status).unwrap(), axum::Json(tb)) } }))
            .route("/guser", get(move |h: axum::http::HeaderMap| async move {
                let auth = h.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                (StatusCode::from_u16(profile_status).unwrap(), axum::Json(json!({"email": "g@x.test", "auth": auth})))
            }))
            .route("/mme", get(move |q: axum::extract::Query<std::collections::HashMap<String, String>>| async move {
                (StatusCode::from_u16(profile_status).unwrap(), axum::Json(json!({"email": "m@x.test", "token": q.get("access_token")})))
            }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        HttpProviders::new(&format!("{base}/gtoken"), &format!("{base}/guser"), &format!("{base}/mtoken"), &format!("{base}/mme"))
    }

    #[tokio::test]
    async fn providers_over_http() {
        let p = fake_providers(200, json!({"access_token": "abc"}), 200).await;
        let g = p.profile("GOOGLE", "cid", "sec", "code", "https://cb").await.unwrap();
        assert_eq!((g["email"].as_str(), g["auth"].as_str()), (Some("g@x.test"), Some("Bearer abc")));
        let m = p.profile("META", "cid", "sec", "code", "https://cb").await.unwrap();
        assert_eq!((m["email"].as_str(), m["token"].as_str()), (Some("m@x.test"), Some("abc")));
        let numeric = fake_providers(200, json!({"access_token": 5}), 200).await;
        assert_eq!(numeric.profile("META", "c", "s", "x", "cb").await.unwrap()["token"], "5");
        let refused = fake_providers(400, json!({}), 200).await;
        assert!(refused.profile("GOOGLE", "c", "s", "x", "cb").await.unwrap_err().contains("token endpoint"));
        let tokenless = fake_providers(200, json!({"x": 1}), 200).await;
        assert!(tokenless.profile("GOOGLE", "c", "s", "x", "cb").await.unwrap_err().contains("is null"));
        let no_profile = fake_providers(200, json!({"access_token": "a"}), 500).await;
        assert!(no_profile.profile("GOOGLE", "c", "s", "x", "cb").await.unwrap_err().contains("profile endpoint"));
        let gone = HttpProviders::new("http://127.0.0.1:9/t", "http://127.0.0.1:9/u", "http://127.0.0.1:9/t", "http://127.0.0.1:9/u");
        assert!(gone.profile("GOOGLE", "c", "s", "x", "cb").await.is_err());
        assert!(HttpProviders::real().google_token.starts_with("https://oauth2.googleapis.com"));
    }
}
