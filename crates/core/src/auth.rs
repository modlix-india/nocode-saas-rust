//! The caller, as `JWTTokenFilter` establishes it in the Java core: security's
//! `securityContextAuthentication` answer for the request's token, with `urlClientCode` and
//! `urlAppCode` taken from the `clientCode` / `appCode` headers.
//!
//! The whole answer is kept, not only the fields the platform's `ContextAuthentication`
//! parses: `CoreServices.SecurityContext.GetAuthentication` hands it to functions, and the
//! entity-processor remote functions forward its `accessToken`.

use std::time::Duration;

use anyhow::{anyhow, Context as _, Result};
use axum::http::{header, HeaderMap, StatusCode};
use overridable::java_map;
use platform::security::{CallerContext, ContextAuthentication};
use platform::upstream::Upstream;
use serde_json::{Map, Value};

use crate::error::CoreError;

#[derive(Debug, Clone, Default)]
pub struct Authentication {
    pub ca: ContextAuthentication,
    /// Security's JSON, as sent.
    pub raw: Map<String, Value>,
}

/// `ContextUser`'s fields in declaration order (Gson writes them in this order). The `bool`
/// marks a primitive `boolean`: always written, `false` when security did not send it.
const USER_FIELDS: &[(&str, bool)] = &[
    ("id", false),
    ("createdBy", false),
    ("updatedBy", false),
    ("createdAt", false),
    ("updatedAt", false),
    ("clientId", false),
    ("userName", false),
    ("emailId", false),
    ("phoneNumber", false),
    ("firstName", false),
    ("lastName", false),
    ("middleName", false),
    ("localeCode", false),
    ("timeZone", false),
    // Ignored by Jackson when security's answer is read (`@JsonIgnore` getters), so always
    // null or false here.
    ("password", false),
    ("passwordHashed", true),
    ("pin", false),
    ("pinHashed", true),
    ("accountNonExpired", true),
    ("accountNonLocked", true),
    ("credentialsNonExpired", true),
    ("noFailedAttempt", false),
    ("noPinFailedAttempt", false),
    ("noOtpResendAttempts", false),
    ("noOtpFailedAttempt", false),
    ("statusCode", false),
    ("lockedUntil", false),
    ("lockedDueTo", false),
    ("stringAuthorities", false),
    ("designationId", false),
];

const IGNORED_ON_READ: &[&str] = &["password", "passwordHashed", "pin", "pinHashed"];

impl Authentication {
    pub fn authorities(&self) -> &[String] {
        &self.ca.user.string_authorities
    }

    pub fn is_authenticated(&self) -> bool {
        self.ca.authenticated
    }

    pub fn access_token(&self) -> Option<&str> {
        self.raw.get("accessToken").and_then(Value::as_str)
    }

    pub fn url_client_code(&self) -> Option<&str> {
        self.ca.url_client_code.as_deref()
    }

    pub fn url_app_code(&self) -> Option<&str> {
        self.ca.url_app_code.as_deref()
    }

    /// `ca.getVerifiedAppCode()`: the app the user signed in to (carried in the token).
    pub fn verified_app_code(&self) -> Option<&str> {
        self.raw.get("verifiedAppCode").and_then(Value::as_str)
    }

    /// `ca.getUser().getId()`.
    pub fn user_id(&self) -> u64 {
        self.ca.user.id
    }

    /// `ca.getClientCode()`: the client the user belongs to.
    pub fn client_code(&self) -> Option<&str> {
        self.ca.client_code.as_deref()
    }

    /// `ContextUser` as Gson writes it once `getAuthorities()` has run (the execute path always
    /// runs it, for the `Authorities.` extractor): `grantedAuthorities` is then the
    /// `HashSet<SimpleGrantedAuthority>` built from `stringAuthorities`, in `HashSet` order.
    pub fn user_json(&self) -> Value {
        let empty = Map::new();
        let user = self.raw.get("user").and_then(Value::as_object).unwrap_or(&empty);
        let mut out = Map::new();
        for (name, primitive) in USER_FIELDS {
            let v = if IGNORED_ON_READ.contains(name) { None } else { user.get(*name).filter(|v| !v.is_null()) };
            match v {
                Some(v) => {
                    out.insert(name.to_string(), v.clone());
                }
                None if *primitive => {
                    out.insert(name.to_string(), Value::Bool(false));
                }
                None => {}
            }
        }
        let auths = self.authorities();
        if !auths.is_empty() {
            out.insert("grantedAuthorities".into(), Value::Array(granted_authorities(auths)));
        }
        Value::Object(out)
    }

    /// `ContextAuthentication` as Gson writes it, without `accessToken` and
    /// `accessTokenExpiryAt` (what `GetAuthentication` removes).
    pub fn authentication_json(&self) -> Value {
        let mut out = Map::new();
        if self.raw.get("user").is_some_and(|u| !u.is_null()) {
            out.insert("user".into(), self.user_json());
        }
        out.insert("isAuthenticated".into(), Value::Bool(self.ca.authenticated));
        for f in ["loggedInFromClientId", "loggedInFromClientCode", "clientTypeCode", "clientLevelType", "clientCode"] {
            if let Some(v) = self.raw.get(f).filter(|v| !v.is_null()) {
                out.insert(f.into(), v.clone());
            }
        }
        if let Some(c) = self.url_client_code() {
            out.insert("urlClientCode".into(), Value::String(c.into()));
        }
        if let Some(a) = self.url_app_code() {
            out.insert("urlAppCode".into(), Value::String(a.into()));
        }
        if let Some(v) = self.raw.get("verifiedAppCode").filter(|v| !v.is_null()) {
            out.insert("verifiedAppCode".into(), v.clone());
        }
        Value::Object(out)
    }
}

/// `stringAuthorities.parallelStream().map(SimpleGrantedAuthority::new).collect(toSet())` in
/// iteration order: a `HashSet` of that size, by `role.hashCode()`. (Within one bucket the
/// parallel collection may order differently; real authority lists rarely share a bucket.)
fn granted_authorities(auths: &[String]) -> Vec<Value> {
    let mut seen = std::collections::HashSet::new();
    let unique: Vec<&String> = auths.iter().filter(|a| seen.insert(a.as_str())).collect();
    let cap = java_map::capacity_by_puts(unique.len());
    let mut keyed: Vec<(usize, &String)> = unique.into_iter().map(|a| (java_map::bucket(a, cap), a)).collect();
    keyed.sort_by_key(|(b, _)| *b);
    keyed
        .into_iter()
        .map(|(_, a)| serde_json::json!({ "role": a }))
        .collect()
}

/// Asks security who is calling, the way `FeignAuthenticationService` does.
#[derive(Clone)]
pub struct AuthClient {
    upstream: Upstream,
    http: reqwest::Client,
}

impl AuthClient {
    pub fn new(upstream: Upstream) -> Result<Self> {
        Ok(Self {
            upstream,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(60))
                // A kept-alive connection left idle is dropped rather than reused: a reused
                // connection the other side stopped serving only fails at the timeout.
                .pool_idle_timeout(Duration::from_secs(20))
                .build()?,
        })
    }

    pub fn upstream(&self) -> &Upstream {
        &self.upstream
    }

    pub fn http(&self) -> &reqwest::Client {
        &self.http
    }

    /// `IFeignSecurityService.contextAuthentication`. A refusal is a Feign error: security's
    /// status and message.
    pub async fn authenticate(&self, caller: &CallerContext) -> Result<Authentication, CoreError> {
        let authorization = if caller.is_basic { format!("basic {}", caller.token) } else { caller.token.clone() };
        let path = "/api/security/internal/securityContextAuthentication";
        let base = self.upstream.base_for(path).await.map_err(CoreError::from)?;
        let mut h = HeaderMap::new();
        platform::telemetry::inject_trace_headers(&mut h);
        let mut rb = self
            .http
            .get(format!("{base}{path}"))
            .headers(h)
            .header("X-Forwarded-Host", &caller.forwarded_host)
            .header("X-Forwarded-Port", &caller.forwarded_port)
            .header("clientCode", caller.client_code.as_deref().unwrap_or(""))
            .header("appCode", caller.app_code.as_deref().unwrap_or(""));
        if !authorization.is_empty() {
            rb = rb.header(header::AUTHORIZATION, &authorization);
        }
        if let Some(d) = &caller.debug {
            rb = rb.header("x-debug", d);
        }
        // Security writes its refusals in the caller's languages; core passes them on.
        if let Some(l) = platform::messages::current_accept_language() {
            rb = rb.header(header::ACCEPT_LANGUAGE, l);
        }
        let credential_sent = !caller.token.trim().is_empty();
        let resp = platform::meter::send_to_service(rb).await.map_err(|e| CoreError::from(anyhow!(e)))?;
        let status = resp.status();
        let bytes = resp.bytes().await.map_err(|e| CoreError::from(anyhow!(e)))?;
        if !status.is_success() {
            platform::messages::note_caller(platform::messages::CallerHint { credential_sent, ..Default::default() });
            return Err(feign_error(status.as_u16(), &bytes));
        }
        let raw: Map<String, Value> = serde_json::from_slice(&bytes)
            .context("securityContextAuthentication body")
            .map_err(CoreError::from)?;
        let mut ca: ContextAuthentication =
            serde_json::from_value(Value::Object(raw.clone())).map_err(|e| CoreError::from(anyhow!(e)))?;
        ca.url_client_code = caller.client_code.clone();
        ca.url_app_code = caller.app_code.clone();
        // What the messages need about the caller: their language, who they are, whether they
        // sent a credential (a refusal then says "signed out" rather than "please sign in").
        let locale = raw.get("user").and_then(|u| u.get("localeCode")).and_then(Value::as_str).map(str::to_string);
        platform::messages::note_caller(platform::messages::CallerHint {
            locale: if ca.authenticated { locale } else { None },
            client_locale: None,
            client_code: ca.client_code.clone(),
            authenticated: ca.authenticated,
            credential_sent,
        });
        Ok(Authentication { ca, raw })
    }
}

/// `ControllerAdvice.handleFeignException`: a JSON error body becomes a `GenericException` with
/// the other service's status and `message`; anything else is an unknown error. A coded body
/// from a Rust unit (security's refusals) is passed on as it came: its code, values, texts and
/// `debugMessage` ([`relayed`]).
pub fn feign_error(status: u16, body: &[u8]) -> CoreError {
    let code = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    match serde_json::from_slice::<Map<String, Value>>(body) {
        Ok(m) => {
            let message = match m.get("message") {
                None | Some(Value::Null) => String::new(),
                Some(Value::String(s)) => s.clone(),
                Some(other) => other.to_string(),
            };
            relayed(code, &Value::Object(m)).unwrap_or_else(|| CoreError::new(code, message))
        }
        Err(_) => CoreError::unknown(format!("[{status}] {}", String::from_utf8_lossy(body))),
    }
}

/// Another Rust unit's coded error, to answer with as it came (`platform::error::Coded::relay`).
/// The text it carries inside core (for KIRun, the event run log) is the other unit's Java text:
/// its `debugMessage` after the bundle key.
pub fn relayed(status: StatusCode, body: &Value) -> Option<CoreError> {
    let c = platform::error::Coded::relay_value(status, body)?;
    let debug = c.debug.clone().unwrap_or_default();
    let java = match debug.strip_prefix('[').and_then(|d| d.split_once("] ")) {
        Some((_, text)) => text.to_string(),
        None => debug,
    };
    Some(CoreError::Message { status, message: java, cause: None, code: Some(Box::new(c)) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{auth, serve};
    use axum::http::HeaderMap;
    use axum::routing::get;
    use axum::Router;
    use serde_json::json;

    #[test]
    fn anonymous_authentication_as_gson_writes_it() {
        // Security's answer for an anonymous caller, and what Java's GetAuthentication sent
        // for it on 2026-10-15.
        let a = auth(
            json!({"user":{"id":0,"createdBy":0,"updatedBy":0,"createdAt":1792027685,"updatedAt":1792027685,
                "clientId":1,"userName":"_Anonymous","emailId":"nothing@nothing","phoneNumber":"+910000000000",
                "firstName":"Anonymous","localeCode":"en","accountNonExpired":true,"accountNonLocked":true,
                "credentialsNonExpired":true,"noFailedAttempt":0,"stringAuthorities":["Authorities._Anonymous"],
                "password":null},
              "authenticated":false,"loggedInFromClientId":1,"loggedInFromClientCode":"SYSTEM",
              "clientTypeCode":"SYS","clientCode":"SYSTEM","accessToken":null,"name":"Anonymous","systemClient":true}),
            Some("SYSTEM"),
            Some("appbuilder"),
        );
        let expected = json!({"user":{"id":0,"createdBy":0,"updatedBy":0,"createdAt":1792027685,"updatedAt":1792027685,
            "clientId":1,"userName":"_Anonymous","emailId":"nothing@nothing","phoneNumber":"+910000000000",
            "firstName":"Anonymous","localeCode":"en","passwordHashed":false,"pinHashed":false,"accountNonExpired":true,
            "accountNonLocked":true,"credentialsNonExpired":true,"noFailedAttempt":0,
            "stringAuthorities":["Authorities._Anonymous"],"grantedAuthorities":[{"role":"Authorities._Anonymous"}]},
            "isAuthenticated":false,"loggedInFromClientId":1,"loggedInFromClientCode":"SYSTEM","clientTypeCode":"SYS",
            "clientCode":"SYSTEM","urlClientCode":"SYSTEM","urlAppCode":"appbuilder"});
        assert_eq!(crate::gson::to_gson(&a.authentication_json()), crate::gson::to_gson(&expected));
        assert!(!a.is_authenticated());
        assert_eq!(a.access_token(), None);
        assert_eq!(a.client_code(), Some("SYSTEM"));
    }

    #[test]
    fn no_user_and_no_header_codes() {
        let a = auth(json!({"authenticated": true, "accessToken": "t", "verifiedAppCode": "x"}), None, None);
        let j = a.authentication_json();
        assert_eq!(j, json!({"isAuthenticated": true, "verifiedAppCode": "x"}));
        assert_eq!(a.user_json(), json!({"passwordHashed": false, "pinHashed": false, "accountNonExpired": false,
            "accountNonLocked": false, "credentialsNonExpired": false}));
        assert_eq!(a.access_token(), Some("t"));
        assert_eq!(a.url_client_code(), None);
        assert_eq!(a.url_app_code(), None);
        // Duplicate authorities are one entry in the set.
        let a = auth(json!({"user": {"stringAuthorities": ["Authorities.A", "Authorities.A"]}}), None, None);
        assert_eq!(a.user_json()["grantedAuthorities"], json!([{"role": "Authorities.A"}]));
    }

    #[test]
    fn granted_authorities_follow_hash_set_order() {
        // The first entries Java sent for user 142 (214 authorities, a 512-bucket HashSet).
        let all: Vec<String> = ["Authorities.ROLE_Style_Manager", "Authorities.Files_RETENTION", "Authorities.Schema_DELETE"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let cap = java_map::capacity_by_puts(214);
        let b: Vec<usize> = all.iter().map(|a| java_map::bucket(a, cap)).collect();
        let mut sorted = b.clone();
        sorted.sort();
        assert_eq!(b, sorted);
    }

    #[test]
    fn feign_errors_carry_the_message() {
        let e = feign_error(401, br#"{"message":"Unknown token","exceptionId":"x"}"#);
        assert_eq!(e.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(e.to_string(), "401 Unauthorized: Unknown token");
        assert_eq!(feign_error(400, br#"{"x":1}"#).text(), "");
        assert_eq!(feign_error(400, br#"{"message":5}"#).text(), "5");
        let e = feign_error(502, b"<html>");
        assert_eq!(e.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(e.text(), "[502] <html>");
    }

    async fn security_stub(h: HeaderMap) -> axum::response::Response {
        use axum::response::IntoResponse;
        let authz = h.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        let debug = h.get("x-debug").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        match authz.as_str() {
            "refuse" => (StatusCode::UNAUTHORIZED, r#"{"message":"Unknown token"}"#).into_response(),
            "garbage" => (StatusCode::OK, "not json").into_response(),
            "basic dXNlcg==" | "" => axum::Json(json!({
                "user": {"id": 1, "stringAuthorities": ["Authorities.X"]},
                "authenticated": !authz.is_empty(), "clientCode": "SYSTEM", "accessToken": authz, "debug": debug,
                "host": h.get("x-forwarded-host").and_then(|v| v.to_str().ok()).unwrap_or(""),
            }))
            .into_response(),
            _ => (StatusCode::OK, "[]").into_response(),
        }
    }

    #[tokio::test]
    async fn asks_security_like_feign() {
        let base = serve(Router::new().route("/api/security/internal/securityContextAuthentication", get(security_stub))).await;
        let client = AuthClient::new(Upstream::fixed(&[&base])).unwrap();
        assert!(client.http().get(&base).build().is_ok());
        assert!(client.upstream().base().await.is_ok());

        let caller = CallerContext {
            is_basic: true,
            token: "dXNlcg==".into(),
            client_code: Some("SYSTEM".into()),
            app_code: Some("appbuilder".into()),
            forwarded_host: "apps.local".into(),
            forwarded_port: "443".into(),
            debug: Some("dbg".into()),
        };
        let a = client.authenticate(&caller).await.unwrap();
        assert!(a.is_authenticated());
        assert_eq!(a.authorities(), ["Authorities.X"]);
        assert_eq!(a.access_token(), Some("basic dXNlcg=="));
        assert_eq!(a.raw["debug"], json!("dbg"));
        assert_eq!(a.raw["host"], json!("apps.local"));
        assert_eq!(a.url_app_code(), Some("appbuilder"));

        let anonymous = client.authenticate(&CallerContext::default()).await.unwrap();
        assert!(!anonymous.is_authenticated());

        let refused = CallerContext { token: "refuse".into(), ..Default::default() };
        let e = client.authenticate(&refused).await.unwrap_err();
        assert_eq!(e.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(e.text(), "Unknown token");

        let garbage = CallerContext { token: "garbage".into(), ..Default::default() };
        assert!(client.authenticate(&garbage).await.is_err());
        let not_an_object = CallerContext { token: "array".into(), ..Default::default() };
        assert!(client.authenticate(&not_an_object).await.is_err());
    }

    #[tokio::test]
    async fn an_unreachable_security_is_an_error() {
        let client = AuthClient::new(Upstream::fixed(&["http://127.0.0.1:1"])).unwrap();
        let e = client.authenticate(&CallerContext::default()).await.unwrap_err();
        assert_eq!(e.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
