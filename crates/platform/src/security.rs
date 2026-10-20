//! Who is calling, asked of the security service the way `commons2-security` asks it.
//!
//! No service verifies a token itself: `JWTTokenFilter` hands the `Authorization` header (or the
//! `Authorization` cookie) to `GET /api/security/internal/securityContextAuthentication`, along
//! with the forwarded host and port and the `clientCode` / `appCode` headers, and uses the
//! `ContextAuthentication` that comes back. Revocation and authorities live in security's
//! database, so this stays a call; what this client adds is that routes which never look at
//! the caller (public static files) do not make it at all.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use axum::http::{header, HeaderMap, StatusCode};
use moka::future::Cache;
use serde::Deserialize;
use serde_json::Value;

use crate::config::SecurityConfig;
use crate::error::{AppError, Coded};
use crate::registry::Registry;
use crate::upstream::Upstream;

pub const CLIENT_TYPE_SYSTEM: &str = "SYS";

/// The path below `/api/security`, without its query.
fn security_path(path: &str) -> &str {
    let path = path.split('?').next().unwrap_or(path);
    path.strip_prefix("/api/security").unwrap_or(path)
}

/// `AuthenticationController`'s paths (security-auth).
pub fn is_auth_route(path: &str) -> bool {
    let p = security_path(path);
    matches!(
        p,
        "/authenticate"
            | "/authenticate/social"
            | "/authenticate/otp/generate"
            | "/internal/makeOneTimeToken"
            | "/internal/securityContextAuthentication"
            | "/internal/tokens/cleanup"
            | "/makeOneTimeToken"
            | "/refreshToken"
            | "/revoke"
            | "/securityContextAuthentication"
            | "/user/access"
            | "/verifyToken"
    ) || p.starts_with("/authenticateWithOneTimeToken/")
}

/// The service-to-service paths security-internal serves: an `internal` segment, outside
/// `AuthenticationController`, less the few routes it leaves to security (the entity-processor
/// ones and the certificate renewal; see crates/security/SPLIT.md).
pub fn is_internal_route(path: &str) -> bool {
    let p = security_path(path);
    let segments: Vec<&str> = p.trim_start_matches('/').split('/').collect();
    if !segments.contains(&"internal") || is_auth_route(path) {
        return false;
    }
    let excluded = matches!(
        p,
        "/ssl/internal/renew-certificates"
            | "/clients/internal/managedClient"
            | "/clients/internal/clients/denorm/delta"
            | "/users/internal/clients"
            | "/users/internal/recordAudience"
            | "/app/profiles/internal"
    ) || matches!(segments.as_slice(), ["designations" | "departments", "internal", ..])
        || matches!(segments.as_slice(), ["users", "internal", _, "processor"])
        || matches!(segments.as_slice(), ["app", "profiles", "internal", id] if *id != "users");
    !excluded
}

/// `[security]` as one upstream: `upstream`, with `AuthenticationController`'s paths sent to
/// `auth_upstream` and security-internal's to `internal_upstream` when they are set. Callers
/// pick with [`Upstream::base_for`].
pub fn security_upstream(cfg: &SecurityConfig, registry: Option<&Registry>) -> Result<Upstream> {
    let mut routes: Vec<(crate::upstream::PathTest, Upstream)> = Vec::new();
    if !cfg.auth_upstream.entries().is_empty() {
        routes.push((is_auth_route, Upstream::from_config(&cfg.auth_upstream, registry)?));
    }
    if !cfg.internal_upstream.entries().is_empty() {
        routes.push((is_internal_route, Upstream::from_config(&cfg.internal_upstream, registry)?));
    }
    Ok(Upstream::from_config(&cfg.upstream, registry)?.with_routes(routes))
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ContextUser {
    #[serde(default, deserialize_with = "de_u64")]
    pub id: u64,
    #[serde(default, deserialize_with = "de_u64")]
    pub client_id: u64,
    #[serde(default)]
    pub user_name: Option<String>,
    #[serde(default)]
    pub string_authorities: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ContextAuthentication {
    #[serde(default)]
    pub user: ContextUser,
    #[serde(default)]
    pub authenticated: bool,
    #[serde(default, deserialize_with = "de_u64")]
    pub logged_in_from_client_id: u64,
    #[serde(default)]
    pub logged_in_from_client_code: Option<String>,
    #[serde(default)]
    pub client_type_code: Option<String>,
    #[serde(default)]
    pub client_code: Option<String>,
    #[serde(default)]
    pub client_level_type: Option<String>,
    /// The caller's token as security sees it; services pass it on when they call other
    /// services on the caller's behalf.
    #[serde(default)]
    pub access_token: Option<String>,
    /// Set from the request headers after the call, as `JWTTokenFilter` does.
    #[serde(skip)]
    pub url_client_code: Option<String>,
    #[serde(skip)]
    pub url_app_code: Option<String>,
}

impl ContextAuthentication {
    pub fn is_system_client(&self) -> bool {
        self.client_type_code.as_deref() == Some(CLIENT_TYPE_SYSTEM)
    }

    pub fn has_authority(&self, authority: &str) -> bool {
        self.user.string_authorities.iter().any(|a| a == authority)
    }

    pub fn client_code(&self) -> &str {
        self.client_code.as_deref().unwrap_or("")
    }
}

/// Security sends ids as JSON numbers, but `BigInteger` fields can arrive as strings.
fn de_u64<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    Ok(match Value::deserialize(d)? {
        Value::Number(n) => n.as_u64().unwrap_or(0),
        Value::String(s) => s.parse().unwrap_or(0),
        _ => 0,
    })
}

/// The caller's credentials and context, read from a request the way `JWTTokenFilter` reads it.
#[derive(Debug, Clone, Default)]
pub struct CallerContext {
    pub is_basic: bool,
    pub token: String,
    pub client_code: Option<String>,
    pub app_code: Option<String>,
    pub forwarded_host: String,
    pub forwarded_port: String,
    pub debug: Option<String>,
}

impl CallerContext {
    pub fn from_headers(h: &HeaderMap, server_port: u16) -> Self {
        let get = |name: &str| {
            h.get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
                .filter(|s| !s.is_empty())
        };

        let mut raw = get(header::AUTHORIZATION.as_str());
        if raw.as_deref().map(str::trim).unwrap_or("").is_empty() {
            raw = cookie(h, "Authorization");
        }
        let (is_basic, token) = match raw {
            None => (false, String::new()),
            Some(t) => {
                let t = t.trim();
                let lower = t.to_ascii_lowercase();
                if lower.starts_with("bearer ") {
                    (false, t[7..].to_string())
                } else if lower.starts_with("basic ") {
                    (true, t[6..].to_string())
                } else {
                    (false, t.to_string())
                }
            }
        };

        let host = get("x-forwarded-host").unwrap_or_else(|| {
            get(header::HOST.as_str())
                .map(|h| h.split(':').next().unwrap_or("").to_string())
                .unwrap_or_default()
        });
        let port = get("x-forwarded-port")
            .map(|p| p.split(',').next().unwrap_or("").trim().to_string())
            .unwrap_or_else(|| server_port.to_string());

        Self {
            is_basic,
            token,
            client_code: get("clientcode"),
            app_code: get("appcode"),
            forwarded_host: host,
            forwarded_port: port,
            debug: get("x-debug"),
        }
    }
}

fn cookie(h: &HeaderMap, name: &str) -> Option<String> {
    h.get_all(header::COOKIE).iter().find_map(|v| {
        v.to_str().ok()?.split(';').find_map(|pair| {
            let (k, v) = pair.trim().split_once('=')?;
            (k == name).then(|| v.to_string())
        })
    })
}

#[derive(Clone)]
pub struct SecurityClient {
    inner: Arc<Inner>,
}

struct Inner {
    /// Security, with its auth and internal routes sent where they run ([`security_upstream`]).
    upstream: Upstream,
    http: reqwest::Client,
    client_id_by_code: Cache<String, u64>,
    /// Optional, off unless `security.authCacheSeconds` is set: a short per-token cache (with the
    /// user's `localeCode`). The Java services meant to have one (`tokenCache`) but read it under
    /// a prefix nothing writes.
    auth_by_token: Option<Cache<String, (ContextAuthentication, Option<String>)>>,
}

/// Tells the request's message scope who is calling, so its errors are written in the user's
/// language and say "signed out" rather than "please sign in" when a credential was refused.
fn note_caller(caller: &CallerContext, ca: &ContextAuthentication, locale: Option<String>) {
    crate::messages::note_caller(crate::messages::CallerHint {
        locale: if ca.authenticated { locale } else { None },
        client_locale: None,
        client_code: ca.client_code.clone(),
        authenticated: ca.authenticated,
        credential_sent: !caller.token.trim().is_empty(),
    });
}

impl SecurityClient {
    pub fn new(upstream: Upstream, auth_cache_seconds: u64) -> Result<Self> {
        Self::with_auth_upstream(upstream, None, auth_cache_seconds)
    }

    /// `[security]` as configured: `upstream` for everything, `auth_upstream` (when set) for the
    /// `AuthenticationController` calls, `internal_upstream` (when set) for the internal ones.
    pub fn from_config(cfg: &SecurityConfig, registry: Option<&Registry>) -> Result<Self> {
        Self::routed(security_upstream(cfg, registry)?, cfg.auth_cache_seconds)
    }

    /// The caller's context and one-time token sign-ins go to `auth_upstream` when given.
    pub fn with_auth_upstream(upstream: Upstream, auth_upstream: Option<Upstream>, auth_cache_seconds: u64) -> Result<Self> {
        let routes = auth_upstream.map(|a| vec![(is_auth_route as crate::upstream::PathTest, a)]).unwrap_or_default();
        Self::routed(upstream.with_routes(routes), auth_cache_seconds)
    }

    /// Over an upstream that already routes by path ([`security_upstream`]).
    pub fn routed(upstream: Upstream, auth_cache_seconds: u64) -> Result<Self> {
        Ok(Self {
            inner: Arc::new(Inner {
                upstream,
                http: reqwest::Client::builder()
                    .timeout(Duration::from_secs(60))
                    .build()?,
                client_id_by_code: Cache::builder()
                    .max_capacity(50_000)
                    .time_to_live(Duration::from_secs(3600))
                    .build(),
                auth_by_token: (auth_cache_seconds > 0).then(|| {
                    Cache::builder()
                        .max_capacity(100_000)
                        .time_to_live(Duration::from_secs(auth_cache_seconds))
                        .build()
                }),
            }),
        })
    }

    /// Sends the request `build` makes for the base URL that serves `path`, with the context
    /// headers; on the next member when the first refuses the connection ([`Upstream::send`]).
    async fn send<F>(&self, path: &str, debug: Option<&str>, build: F) -> Result<reqwest::Response>
    where
        F: Fn(&reqwest::Client, String) -> reqwest::RequestBuilder,
    {
        self.inner
            .upstream
            .send(path, |base| Self::with_context(build(&self.inner.http, format!("{base}{path}")), debug))
            .await
    }

    /// The `x-debug` tag, the current trace and the request's languages (so a refusal security
    /// writes, and a service passes on, reads in the caller's language), on every call to
    /// security.
    fn with_context(rb: reqwest::RequestBuilder, debug: Option<&str>) -> reqwest::RequestBuilder {
        let mut h = HeaderMap::new();
        crate::telemetry::inject_trace_headers(&mut h);
        if let Some(v) = crate::messages::current_accept_language().and_then(|l| header::HeaderValue::from_str(&l).ok()) {
            h.insert(header::ACCEPT_LANGUAGE, v);
        }
        let rb = rb.headers(h);
        match debug {
            Some(d) => rb.header("x-debug", d),
            None => rb,
        }
    }

    pub async fn context_authentication(&self, caller: &CallerContext) -> Result<ContextAuthentication> {
        let authorization = if caller.is_basic {
            format!("basic {}", caller.token)
        } else {
            caller.token.clone()
        };
        let cache_key = format!(
            "{}|{}|{}|{}|{}",
            authorization,
            caller.forwarded_host,
            caller.forwarded_port,
            caller.client_code.as_deref().unwrap_or(""),
            caller.app_code.as_deref().unwrap_or("")
        );
        if let Some(cache) = &self.inner.auth_by_token {
            if !caller.token.is_empty() {
                if let Some((ca, locale)) = cache.get(&cache_key).await {
                    note_caller(caller, &ca, locale);
                    return Ok(ca);
                }
            }
        }

        let path = "/api/security/internal/securityContextAuthentication";
        let resp = self
            .send(path, caller.debug.as_deref(), |http, url| {
                let rb = http
                    .get(url)
                    .header("X-Forwarded-Host", &caller.forwarded_host)
                    .header("X-Forwarded-Port", &caller.forwarded_port)
                    .header("clientCode", caller.client_code.as_deref().unwrap_or(""))
                    .header("appCode", caller.app_code.as_deref().unwrap_or(""));
                if authorization.is_empty() { rb } else { rb.header(header::AUTHORIZATION, &authorization) }
            })
            .await?;
        let status = resp.status();
        if !status.is_success() {
            // The refusal's own message (and, from a Rust security unit, its code) rides along as
            // context, so a service can answer with it the way a Java service relays a Feign
            // error; `downcast_ref::<SecurityRefused>` still finds the status.
            let body = resp.bytes().await.unwrap_or_default();
            let refusal = SecurityRefusal::from_json(status.as_u16(), &body);
            return Err(anyhow::Error::new(SecurityRefused(status.as_u16())).context(refusal));
        }
        let raw: Value = resp.json().await.context("securityContextAuthentication body")?;
        let locale = raw.pointer("/user/localeCode").and_then(Value::as_str).map(str::to_string);
        let mut ca: ContextAuthentication = serde_json::from_value(raw).context("securityContextAuthentication body")?;
        ca.url_client_code = caller.client_code.clone();
        ca.url_app_code = caller.app_code.clone();
        note_caller(caller, &ca, locale.clone());

        if let Some(cache) = &self.inner.auth_by_token {
            if !caller.token.is_empty() && ca.authenticated {
                cache.insert(cache_key, (ca.clone(), locale)).await;
            }
        }
        Ok(ca)
    }

    async fn get_json(&self, path: &str, query: &[(&str, String)]) -> Result<Value> {
        let resp = self.send(path, None, |http, url| http.get(url).query(query)).await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(anyhow!("{path}: {status}"));
        }
        // Feign maps an empty 200 to null.
        let bytes = resp.bytes().await?;
        if bytes.is_empty() {
            return Ok(Value::Null);
        }
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// `FeignAuthenticationService.getClientIdByCode`, cached like the Java `clientByCode`.
    pub async fn client_id_by_code(&self, client_code: &str) -> Result<Option<u64>> {
        if let Some(id) = self.inner.client_id_by_code.get(client_code).await {
            return Ok(Some(id));
        }
        let v = self
            .get_json(
                "/api/security/clients/internal/getClientByCode",
                &[("clientCode", client_code.to_string())],
            )
            .await?;
        let id = match &v["id"] {
            Value::Number(n) => n.as_u64(),
            Value::String(s) => s.parse().ok(),
            _ => None,
        };
        if let Some(id) = id {
            self.inner
                .client_id_by_code
                .insert(client_code.to_string(), id)
                .await;
        }
        Ok(id)
    }

    pub async fn is_user_client_manage_client(
        &self,
        app_code: Option<&str>,
        user_id: u64,
        user_client_id: u64,
        target_client_id: Option<u64>,
    ) -> Result<bool> {
        let mut q = vec![
            ("appCode", app_code.unwrap_or("").to_string()),
            ("userId", user_id.to_string()),
            ("userClientId", user_client_id.to_string()),
        ];
        if let Some(t) = target_client_id {
            q.push(("targetClientId", t.to_string()));
        }
        let v = self
            .get_json("/api/security/clients/internal/isUserClientManageClient", &q)
            .await?;
        Ok(v.as_bool().unwrap_or(false))
    }

    /// `IFeignSecurityService.validClientCode`. Security answers an unknown code with an empty
    /// body, which Feign reads as `null`: that is `None` here.
    pub async fn valid_client_code(&self, client_code: &str) -> Result<Option<bool>> {
        let v = self
            .get_json(
                "/api/security/clients/internal/validateClientCode",
                &[("clientCode", client_code.to_string())],
            )
            .await?;
        Ok(v.as_bool())
    }

    /// `IFeignSecurityService.getClientById`: the client as security sends it, `None` when unknown.
    pub async fn client_by_id(&self, client_id: u64) -> Result<Option<Value>> {
        let v = self
            .get_json(
                "/api/security/clients/internal/getClientById",
                &[("clientId", client_id.to_string())],
            )
            .await?;
        Ok((!v.is_null()).then_some(v))
    }

    /// `IFeignSecurityService.getUserInternal(id, null)`: the user, `None` when unknown.
    pub async fn user_internal(&self, user_id: u64) -> Result<Option<Value>> {
        let v = self
            .get_json(&format!("/api/security/users/internal/{user_id}"), &[])
            .await?;
        Ok((!v.is_null()).then_some(v))
    }

    /// `IFeignSecurityService.getAppByCode`: the app, `None` when unknown.
    pub async fn app_by_code(&self, app_code: &str) -> Result<Option<Value>> {
        let encoded = utf8_percent_encode_path(app_code);
        let v = self
            .get_json(&format!("/api/security/applications/internal/appCode/{encoded}"), &[])
            .await?;
        Ok((!v.is_null()).then_some(v))
    }

    /// `IFeignSecurityService.getClientHierarchyCodes`: the client then its managers, nearest
    /// first; empty for an unknown code.
    pub async fn client_hierarchy_codes(&self, client_code: &str) -> Result<Vec<String>> {
        let v = self
            .get_json(
                "/api/security/clients/internal/clientHierarchyCodes",
                &[("clientCode", client_code.to_string())],
            )
            .await?;
        Ok(match v {
            Value::Array(items) => items
                .into_iter()
                .filter_map(|i| i.as_str().map(str::to_string))
                .collect(),
            _ => Vec::new(),
        })
    }

    /// `IFeignSecurityBillingService.getInstructions`: who to meter for `action`.
    pub async fn billing_instructions(&self, action: &str) -> Result<Value> {
        self.get_json(
            "/api/security/internal/billing/instructions",
            &[("action", action.to_string())],
        )
        .await
    }

    /// `IFeignSecurityBillingService.charge`. `body` is the JSON array of charge requests, written
    /// by the caller so the quantities keep the scale the Java service sends.
    pub async fn billing_charge(&self, body: String) -> Result<Value> {
        let path = "/api/security/internal/billing/charge";
        let resp = self
            .send(path, None, |http, url| {
                http.post(url).header(header::CONTENT_TYPE, "application/json").body(body.clone())
            })
            .await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(anyhow!("billing charge: {status}"));
        }
        let bytes = resp.bytes().await?;
        if bytes.is_empty() {
            return Ok(Value::Null);
        }
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// `applications/internal/hasWriteAccess`: may `client_code` change `app_code`.
    pub async fn has_write_access(&self, app_code: &str, client_code: &str) -> Result<bool> {
        let v = self
            .get_json(
                "/api/security/applications/internal/hasWriteAccess",
                &[("appCode", app_code.to_string()), ("clientCode", client_code.to_string())],
            )
            .await?;
        Ok(v.as_bool().unwrap_or(false))
    }

    /// `clients/internal/activeClientCodes`: the codes among these whose client, and every
    /// client managing it, is active (deleted, inactive and locked clients are left out).
    pub async fn active_client_codes(&self, codes: &[String]) -> Result<Vec<String>> {
        let path = "/api/security/clients/internal/activeClientCodes";
        let body = serde_json::to_string(codes)?;
        let resp = self
            .send(path, None, |http, url| {
                http.post(url).header(header::CONTENT_TYPE, "application/json").body(body.clone())
            })
            .await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(anyhow!("activeClientCodes: {status}"));
        }
        let bytes = resp.bytes().await?;
        if bytes.is_empty() {
            return Ok(Vec::new());
        }
        let v: Value = serde_json::from_slice(&bytes)?;
        Ok(match v {
            Value::Array(items) => items.into_iter().filter_map(|i| i.as_str().map(str::to_string)).collect(),
            _ => Vec::new(),
        })
    }

    pub async fn does_client_manage_client_code(&self, managing: &str, client: &str) -> Result<bool> {
        let v = self
            .get_json(
                "/api/security/clients/internal/doesClientManageClientCode",
                &[
                    ("managingClientCode", managing.to_string()),
                    ("clientCode", client.to_string()),
                ],
            )
            .await?;
        Ok(v.as_bool().unwrap_or(false))
    }
}

/// A value for one URL path segment: everything outside the unreserved set is percent-encoded.
fn utf8_percent_encode_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

impl SecurityClient {
    /// A plain-text answer (`appStatus` is `text/plain`); an empty body is `None`, as Feign
    /// maps it to an empty Mono.
    async fn get_text(&self, path: &str, query: &[(&str, String)]) -> Result<Option<String>> {
        let resp = self.send(path, None, |http, url| http.get(url).query(query)).await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(anyhow!("{path}: {status}"));
        }
        let text = resp.text().await?;
        Ok((!text.is_empty()).then_some(text))
    }

    fn string_list(v: &Value) -> Vec<String> {
        v.as_array()
            .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
            .unwrap_or_default()
    }

    /// `IFeignSecurityService.appInheritance`: the client codes an app resolves through for a
    /// client, root first (`["SYSTEM", "FIN2"]`). Uncached here; callers cache it under the
    /// Java `inheritanceOrder` name.
    pub async fn app_inheritance(&self, app_code: &str, url_client_code: &str, client_code: &str) -> Result<Vec<String>> {
        let v = self
            .get_json(
                "/api/security/applications/internal/appInheritance",
                &[
                    ("appCode", app_code.to_string()),
                    ("urlClientCode", url_client_code.to_string()),
                    ("clientCode", client_code.to_string()),
                ],
            )
            .await?;
        Ok(Self::string_list(&v))
    }

    /// `IFeignSecurityService.getAppStatus`: `ACTIVE`, ..., or `None` for an unknown app.
    pub async fn app_status(&self, app_code: &str) -> Result<Option<String>> {
        self.get_text(
            &format!("/api/security/applications/internal/appStatus/{}", path_segment(app_code)),
            &[],
        )
        .await
    }

    /// `IFeignSecurityService.hasReadAccess`.
    pub async fn has_read_access(&self, app_code: &str, client_code: &str) -> Result<bool> {
        let v = self
            .get_json(
                "/api/security/applications/internal/hasReadAccess",
                &[("appCode", app_code.to_string()), ("clientCode", client_code.to_string())],
            )
            .await?;
        Ok(v.as_bool().unwrap_or(false))
    }

    /// `IFeignSecurityService.getDependencies`: the apps whose functions and schemas an app
    /// can use, in order.
    pub async fn app_dependencies(&self, app_code: &str) -> Result<Vec<String>> {
        let v = self
            .get_json(
                "/api/security/applications/internal/dependencies",
                &[("appCode", app_code.to_string())],
            )
            .await?;
        Ok(Self::string_list(&v))
    }

    /// `IFeignSecurityService.getAppExplicitInfoByCode`: the app's owner and access type
    /// (`appAccessType`, `clientCode`, ...), `Null` for an unknown app.
    pub async fn app_explicit_info(&self, app_code: &str) -> Result<Value> {
        self.get_json(
            &format!("/api/security/applications/internal/explicitInfo/{}", path_segment(app_code)),
            &[],
        )
        .await
    }
}

/// A security answer as received: status, content type and body. Callers that relay
/// security's own errors (as the Java services do for Feign errors) need all three.
#[derive(Debug, Clone)]
pub struct RawAnswer {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: bytes::Bytes,
}

impl RawAnswer {
    /// The error a Java service would raise for this answer: security's own status and message
    /// when it sent a JSON error body, otherwise a plain refusal with the status.
    pub fn into_error(self) -> anyhow::Error {
        let refusal = if self.content_type.as_deref() == Some("application/json") {
            let mut r = SecurityRefusal::from_json(self.status, &self.body);
            if r.message.is_none() && serde_json::from_slice::<Value>(&self.body).is_ok() {
                r.message = Some(String::new());
            }
            r
        } else {
            SecurityRefusal::default()
        };
        anyhow::Error::new(SecurityRefused(self.status)).context(refusal)
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

impl SecurityClient {
    async fn get_raw(&self, path: &str, query: &[(&str, String)], headers: &[(&str, String)]) -> Result<RawAnswer> {
        let resp = self
            .send(path, None, |http, url| {
                headers.iter().fold(http.get(url).query(query), |rb, (k, v)| rb.header(*k, v))
            })
            .await?;
        let status = resp.status().as_u16();
        let content_type = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let body = resp.bytes().await?;
        Ok(RawAnswer { status, content_type, body })
    }

    async fn get_ok(&self, path: &str, query: &[(&str, String)], headers: &[(&str, String)]) -> Result<Option<bytes::Bytes>> {
        Self::ok_body(self.get_raw(path, query, headers).await?)
    }

    fn ok_body(a: RawAnswer) -> Result<Option<bytes::Bytes>> {
        if !a.is_success() {
            return Err(a.into_error());
        }
        Ok((!a.body.is_empty()).then_some(a.body))
    }

    /// `IFeignSecurityBillingService.checkHosting`: which app and client to serve for a URL's
    /// (`{suspended, serveAppCode, serveClientCode}`), `None` when security sends nothing.
    pub async fn billing_hosting(&self, url_app_code: &str, url_client_code: &str) -> Result<Option<Value>> {
        let b = self
            .get_ok(
                "/api/security/internal/billing/hosting",
                &[("urlAppCode", url_app_code.to_string()), ("urlClientCode", url_client_code.to_string())],
                &[],
            )
            .await?;
        Ok(match b {
            Some(b) => Some(serde_json::from_slice(&b)?),
            None => None,
        })
    }

    /// `IFeignSecurityService.getClientNAppCodeNType`: the client code, app code and URL type a
    /// host resolves to (`appCode` is `nothing` for an unknown host).
    pub async fn client_n_app_code_n_type(&self, scheme: &str, host: &str, port: &str) -> Result<Option<(String, String, String)>> {
        let b = self
            .get_ok(
                "/api/security/clients/internal/getClientNAppCodeNType",
                &[("scheme", scheme.to_string()), ("host", host.to_string()), ("port", port.to_string())],
                &[],
            )
            .await?;
        let Some(b) = b else { return Ok(None) };
        let v: Value = serde_json::from_slice(&b)?;
        let part = |i: usize| v.get(i).and_then(Value::as_str).unwrap_or("").to_string();
        Ok(Some((part(0), part(1), part(2))))
    }

    /// `IFeignSecurityService.token`: an ACME HTTP-01 challenge answer, `None` when unknown.
    pub async fn ssl_token(&self, token: &str) -> Result<Option<String>> {
        let b = self
            .get_ok(&format!("/api/security/ssl/token/{}", path_segment(token)), &[], &[])
            .await?;
        Ok(b.map(|b| String::from_utf8_lossy(&b).to_string()))
    }

    /// `IFeignSecurityService.authenticateWithOneTimeToken`: the session a one-time token stands
    /// for. A refusal comes back as security's own status and message.
    pub async fn authenticate_with_one_time_token(
        &self,
        token: &str,
        forwarded_host: Option<&str>,
        client_code: Option<&str>,
        app_code: Option<&str>,
        ip_address: &str,
    ) -> Result<Option<Value>> {
        let mut headers = vec![("X-Real-IP", ip_address.to_string())];
        if let Some(h) = forwarded_host {
            headers.push(("X-Forwarded-Host", h.to_string()));
        }
        if let Some(c) = client_code {
            headers.push(("clientCode", c.to_string()));
        }
        if let Some(a) = app_code {
            headers.push(("appCode", a.to_string()));
        }
        let path = format!("/api/security/authenticateWithOneTimeToken/{}", path_segment(token));
        let b = Self::ok_body(self.get_raw(&path, &[], &headers).await?)?;
        Ok(match b {
            Some(b) => Some(serde_json::from_slice(&b)?),
            None => None,
        })
    }

    /// `IFeignSecurityService.getClientByCode`: the client record (`timeZone` among its fields).
    pub async fn client_by_code(&self, client_code: &str) -> Result<Option<Value>> {
        let b = self
            .get_ok("/api/security/clients/internal/getClientByCode", &[("clientCode", client_code.to_string())], &[])
            .await?;
        Ok(match b {
            Some(b) => Some(serde_json::from_slice(&b)?),
            None => None,
        })
    }

}

/// The caller's token and forwarded request, which the Feign calls made on a caller's behalf
/// (`hasDeleteAccess`, `findBaseClientCodeForOverride`) send as headers.
#[derive(Debug, Clone, Default)]
pub struct OnBehalfOf {
    pub access_token: Option<String>,
    pub forwarded_host: String,
    pub forwarded_port: String,
    pub client_code: String,
    pub app_code: String,
}

impl OnBehalfOf {
    fn headers(&self) -> Vec<(&'static str, String)> {
        let mut h = vec![
            ("X-Forwarded-Host", self.forwarded_host.clone()),
            ("X-Forwarded-Port", self.forwarded_port.clone()),
            ("clientCode", self.client_code.clone()),
            ("appCode", self.app_code.clone()),
        ];
        if let Some(t) = self.access_token.as_deref().filter(|t| !t.is_empty()) {
            h.push(("Authorization", t.to_string()));
        }
        h
    }
}

impl SecurityClient {
    /// `IFeignSecurityService.hasDeleteAccess`: may the caller wipe `delete_app_code` for
    /// `delete_client_code`. An empty answer is `false`, as an empty Mono is.
    pub async fn has_delete_access(&self, caller: &OnBehalfOf, delete_app_code: &str, delete_client_code: &str) -> Result<bool> {
        let b = self
            .get_ok(
                "/api/security/applications/hasDeleteAccess",
                &[
                    ("deleteAppCode", delete_app_code.to_string()),
                    ("deleteClientCode", delete_client_code.to_string()),
                ],
                &caller.headers(),
            )
            .await?;
        Ok(match b {
            Some(b) => serde_json::from_slice::<Value>(&b)?.as_bool().unwrap_or(false),
            None => false,
        })
    }

    /// `IFeignSecurityService.findBaseClientCodeForOverride`: the client an app's objects are
    /// imported under and whether that client owns the app outright (`["SYSTEM", true]`; the
    /// Java `Tuple2` is written as an array). `None` when security sends nothing.
    pub async fn find_base_client_code_for_override(&self, caller: &OnBehalfOf, application_code: &str) -> Result<Option<(String, bool)>> {
        let b = self
            .get_ok(
                &format!("/api/security/applications/findBaseClientCode/{}", path_segment(application_code)),
                &[],
                &caller.headers(),
            )
            .await?;
        let Some(b) = b else { return Ok(None) };
        let v: Value = serde_json::from_slice(&b)?;
        let code = v.get(0).and_then(Value::as_str).map(str::to_string);
        Ok(code.map(|c| (c, v.get(1).and_then(Value::as_bool).unwrap_or(false))))
    }
}

/// A value placed in a URL path, escaped the way Feign expands a `@PathVariable`.
fn path_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Security answered the auth call with a non-2xx status (a bad token is a 401 there).
#[derive(Debug, thiserror::Error)]
#[error("security refused the caller: {0}")]
pub struct SecurityRefused(pub u16);

/// The message security gave with a refusal (`"Unknown client information requested"`), as
/// context on the same error, and the whole coded error when a Rust security unit sent one.
#[derive(Debug, Default, thiserror::Error)]
#[error("security refused the caller: {}", message.as_deref().unwrap_or("(no message)"))]
pub struct SecurityRefusal {
    pub message: Option<String>,
    /// Security's coded error (`code`, values, texts, `debugMessage`), to pass on as it came.
    pub coded: Option<Coded>,
}

impl SecurityRefusal {
    /// What a JSON error body from security says: its `message`, and its code when it has one.
    pub fn from_json(status: u16, body: &[u8]) -> Self {
        let v = serde_json::from_slice::<Value>(body).ok();
        let message = v.as_ref().and_then(|v| v.get("message").and_then(Value::as_str).map(str::to_string));
        let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let coded = v.as_ref().and_then(|v| Coded::relay_value(status, v));
        Self { message, coded }
    }

    /// The error a service answers with for this refusal, as a Java service answers a Feign
    /// error with the other service's status and message: security's coded error as it came
    /// (its code, values, texts and `debugMessage`), else its message, else no body.
    pub fn app_error(&self, status: StatusCode) -> AppError {
        match (&self.coded, &self.message) {
            (Some(c), _) => AppError::from(c.clone().status(status)),
            (None, Some(m)) => AppError::new(status, m.clone()),
            (None, None) => AppError::Empty(status),
        }
    }
}

/// `e` as the error to answer with when it is security refusing a call ([`SecurityRefused`]):
/// security's status with its coded error, message or nothing ([`SecurityRefusal::app_error`]).
/// `None` for any other failure (a transport error, a body that does not parse).
pub fn refusal_error(e: &anyhow::Error) -> Option<AppError> {
    let status = e.downcast_ref::<SecurityRefused>()?.0;
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::UNAUTHORIZED);
    Some(match e.downcast_ref::<SecurityRefusal>() {
        Some(r) => r.app_error(status),
        None => AppError::Empty(status),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn reads_bearer_basic_and_cookie() {
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer abc.def"));
        h.insert("clientcode", HeaderValue::from_static("SYSTEM"));
        h.insert("x-forwarded-port", HeaderValue::from_static("443, 80"));
        let c = CallerContext::from_headers(&h, 8003);
        assert!(!c.is_basic);
        assert_eq!(c.token, "abc.def");
        assert_eq!(c.client_code.as_deref(), Some("SYSTEM"));
        assert_eq!(c.forwarded_port, "443");

        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, HeaderValue::from_static("basic dXNlcjpwdw=="));
        let c = CallerContext::from_headers(&h, 8003);
        assert!(c.is_basic);
        assert_eq!(c.token, "dXNlcjpwdw==");

        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, HeaderValue::from_static("a=1; Authorization=tok; b=2"));
        h.insert(header::HOST, HeaderValue::from_static("apps.local:8080"));
        let c = CallerContext::from_headers(&h, 8003);
        assert_eq!(c.token, "tok");
        assert_eq!(c.forwarded_host, "apps.local");
        assert_eq!(c.forwarded_port, "8003");
    }

    #[test]
    fn refusal_keeps_status_and_message() {
        let e = anyhow::Error::new(SecurityRefused(401)).context(SecurityRefusal { message: Some("no".into()), coded: None });
        assert_eq!(e.downcast_ref::<SecurityRefused>().map(|r| r.0), Some(401));
        assert_eq!(e.downcast_ref::<SecurityRefusal>().and_then(|r| r.message.as_deref()), Some("no"));
        assert!(matches!(refusal_error(&e), Some(AppError::Message { status, .. }) if status == StatusCode::UNAUTHORIZED));
        let bare = anyhow::Error::new(SecurityRefused(403)).context(SecurityRefusal::default());
        assert!(matches!(refusal_error(&bare), Some(AppError::Empty(StatusCode::FORBIDDEN))));
        assert!(matches!(refusal_error(&anyhow::Error::new(SecurityRefused(403))), Some(AppError::Empty(StatusCode::FORBIDDEN))));
        assert!(refusal_error(&anyhow::anyhow!("connection refused")).is_none());
    }

    /// A coded refusal from a Rust security unit is passed on as it came: code, values, texts,
    /// debugMessage, with the status it came with.
    #[test]
    fn coded_refusals_are_relayed() {
        let body = br#"{"exceptionId":"x","message":"This address does not belong to any organisation we know.",
            "stackTrace":"","debugMessage":"[unknown_client] Unknown client information requested","code":"SEC.UNKNOWN_CLIENT",
            "action":"Check the address.","params":{"client":"ZZ"},"locale":"en"}"#;
        let r = SecurityRefusal::from_json(401, body);
        assert_eq!(r.message.as_deref(), Some("This address does not belong to any organisation we know."));
        let c = r.coded.clone().expect("coded");
        assert_eq!((c.code.as_ref(), c.status), ("SEC.UNKNOWN_CLIENT", Some(StatusCode::UNAUTHORIZED)));
        assert_eq!(c.debug.as_deref(), Some("[unknown_client] Unknown client information requested"));
        let AppError::Coded(c) = r.app_error(StatusCode::UNAUTHORIZED) else { panic!("coded") };
        assert!(c.is_relayed());
        assert_eq!(c.params, vec![("client".to_string(), "ZZ".to_string())]);
        let e = anyhow::Error::new(SecurityRefused(401)).context(r);
        assert!(matches!(refusal_error(&e), Some(AppError::Coded(_))));
        // Java's own error body has no code: only its message is relayed.
        let java = SecurityRefusal::from_json(401, br#"{"exceptionId":"x","message":"Unknown token"}"#);
        assert!(java.coded.is_none());
        assert!(matches!(java.app_error(StatusCode::UNAUTHORIZED), AppError::Message { .. }));
        assert!(SecurityRefusal::from_json(500, b"<html>").message.is_none());
    }

    #[test]
    fn parses_security_payload() {
        let body = r#"{"user":{"id":0,"clientId":1,"userName":"_Anonymous",
            "stringAuthorities":["Authorities._Anonymous"],"createdAt":1791891383},
            "loggedInFromClientId":1,"loggedInFromClientCode":"SYSTEM","clientTypeCode":"SYS",
            "clientCode":"SYSTEM","accessTokenExpiryAt":31556889832780799,"authenticated":false,
            "systemClient":true,"name":"Anonymous"}"#;
        let ca: ContextAuthentication = serde_json::from_str(body).unwrap();
        assert!(!ca.authenticated);
        assert!(ca.is_system_client());
        assert_eq!(ca.user.client_id, 1);
        assert!(ca.has_authority("Authorities._Anonymous"));
    }
}
