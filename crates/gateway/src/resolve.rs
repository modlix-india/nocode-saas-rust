//! Which client and app a request is for, and whether it is on the draft surface.
//! A port of `GatewayFilter.resolveCodesAndSurface` and `draftTokenSurface`.
//!
//! The host answer cache is the Java gateway's `gatewayClientAppCodeType`, so security's eviction
//! of it (`cmn-gatewayClientAppCodeType:*` on the eviction channel, when a client URL changes)
//! clears it here too.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use moka::future::Cache;
use platform::cache::LocalCaches;
use platform::upstream::Upstream;
use serde_json::Value;

use crate::path::{codes_from_url, is_draft_token_label};

pub const DEFAULT_CLIENT: &str = "SYSTEM";
pub const DEFAULT_APP: &str = "nothing";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub client_code: String,
    pub app_code: String,
    pub draft: bool,
}

#[derive(Debug, Clone)]
struct DraftAnswer {
    allowed: bool,
    /// Epoch seconds until which this answer may be used.
    trusted_until: i64,
    app_code: String,
    client_code: String,
}

pub struct Resolver {
    security: Upstream,
    http: reqwest::Client,
    hosts: Arc<LocalCaches<String, (String, String, String)>>,
    drafts: Cache<String, DraftAnswer>,
    draft_trust_seconds: i64,
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn s(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

impl Resolver {
    pub fn new(
        security: Upstream,
        hosts: Arc<LocalCaches<String, (String, String, String)>>,
        draft_trust_seconds: u64,
    ) -> Result<Self> {
        Ok(Self {
            security,
            http: reqwest::Client::builder().timeout(Duration::from_secs(10)).build()?,
            hosts,
            drafts: Cache::builder()
                .max_capacity(50_000)
                .time_to_live(Duration::from_secs(draft_trust_seconds.max(1)))
                .build(),
            draft_trust_seconds: draft_trust_seconds as i64,
        })
    }

    /// `scheme`, `host` (no port) and `port` as `getSchemeHostPort` computes them; the codes part
    /// of the path; and the caller's own `clientCode` / `appCode` headers (for draft hosts).
    pub async fn resolve(
        &self,
        scheme: &str,
        host: &str,
        port: &str,
        codes_part: &str,
        header_client: Option<&str>,
        header_app: Option<&str>,
    ) -> Result<Resolved> {
        if !is_draft_token_label(host) {
            if let Some((client_code, app_code)) = codes_from_url(codes_part) {
                return Ok(Resolved { client_code, app_code, draft: false });
            }
            let (client_code, app_code, surface) = self.host_codes(scheme, host, port).await?;
            return Ok(Resolved { client_code, app_code, draft: surface.eq_ignore_ascii_case("DRAFT") });
        }

        let (client, app) = match codes_from_url(codes_part) {
            Some((c, a)) => (c, a),
            None => (
                header_client.unwrap_or("").to_string(),
                header_app.unwrap_or("").to_string(),
            ),
        };
        Ok(self.draft_surface(host, &client, &app).await)
    }

    /// `getClientCodeNType`, cached as Java caches it (`<scheme>:<host>:<port>`).
    async fn host_codes(&self, scheme: &str, host: &str, port: &str) -> Result<(String, String, String)> {
        let key = format!("{scheme}:{host}:{port}");
        let (security, http) = (self.security.clone(), self.http.clone());
        let (scheme, host, port) = (scheme.to_string(), host.to_string(), port.to_string());
        let v = self
            .hosts
            .get_or_load("gatewayClientAppCodeType", key, || async move {
                let path = "/api/security/clients/internal/getClientNAppCodeNType";
                let base = security.base_for(path).await?;
                let resp = http
                    .get(format!("{base}{path}"))
                    .query(&[("scheme", scheme.as_str()), ("host", host.as_str()), ("port", port.as_str())])
                    .send()
                    .await?
                    .error_for_status()?;
                let bytes = resp.bytes().await?;
                if bytes.is_empty() {
                    return Ok::<_, anyhow::Error>(Some((
                        DEFAULT_CLIENT.to_string(),
                        DEFAULT_APP.to_string(),
                        "LIVE".to_string(),
                    )));
                }
                let v: Value = serde_json::from_slice(&bytes).context("getClientNAppCodeNType body")?;
                let arr = v.as_array().cloned().unwrap_or_default();
                if arr.len() < 2 {
                    return Ok(Some((DEFAULT_CLIENT.into(), DEFAULT_APP.into(), "LIVE".into())));
                }
                let surface = arr.get(2).map(s).unwrap_or_else(|| "LIVE".into());
                Ok(Some((s(&arr[0]), s(&arr[1]), surface)))
            })
            .await?;
        Ok(v.unwrap_or_else(|| (DEFAULT_CLIENT.into(), DEFAULT_APP.into(), "LIVE".into())))
    }

    /// `draftTokenSurface`: never an error; anything wrong reads as LIVE.
    async fn draft_surface(&self, host: &str, client_code: &str, app_code: &str) -> Resolved {
        let key = format!("{host}:{app_code}:{client_code}");
        let cached = self.drafts.get(&key).await.filter(|a| a.trusted_until > now());

        let answer = match cached {
            Some(a) => Ok(a),
            None => match self.fetch_draft(host, app_code, client_code).await {
                Ok(a) => {
                    self.drafts.insert(key, a.clone()).await;
                    Ok(a)
                }
                Err(e) => Err(e),
            },
        };

        match answer {
            Ok(a) => {
                let mut app = if app_code.trim().is_empty() { a.app_code.clone() } else { app_code.to_string() };
                let mut client = if client_code.trim().is_empty() { a.client_code.clone() } else { client_code.to_string() };
                if app.trim().is_empty() {
                    app = DEFAULT_APP.into();
                }
                if client.trim().is_empty() {
                    client = DEFAULT_CLIENT.into();
                }
                Resolved { client_code: client, app_code: app, draft: a.allowed }
            }
            Err(e) => {
                tracing::warn!(host, error = %e, "draft token resolution failed, serving live");
                Resolved {
                    client_code: if client_code.trim().is_empty() { DEFAULT_CLIENT.into() } else { client_code.into() },
                    app_code: if app_code.trim().is_empty() { DEFAULT_APP.into() } else { app_code.into() },
                    draft: false,
                }
            }
        }
    }

    async fn fetch_draft(&self, host: &str, app_code: &str, client_code: &str) -> Result<DraftAnswer> {
        let path = "/api/security/clienturls/internal/draft/token/resolve";
        let base = self.security.base_for(path).await?;
        let resp = self
            .http
            .get(format!("{base}{path}"))
            .query(&[("host", host), ("appCode", app_code), ("clientCode", client_code)])
            .send()
            .await?
            .error_for_status()?;
        let bytes = resp.bytes().await?;
        let horizon = now() + self.draft_trust_seconds;
        if bytes.is_empty() {
            return Ok(DraftAnswer { allowed: false, trusted_until: horizon, app_code: String::new(), client_code: String::new() });
        }
        let v: Value = serde_json::from_slice(&bytes)?;
        let arr = v.as_array().cloned().unwrap_or_default();
        let allowed = arr.first().and_then(Value::as_bool).unwrap_or(false);
        let expires: i64 = arr.get(1).map(s).and_then(|x| x.parse().ok()).unwrap_or(0);
        Ok(DraftAnswer {
            allowed,
            // `withTrustWindow`: a denial is trusted for the flat window, a grant until the
            // sooner of its expiry and the window.
            trusted_until: if allowed { expires.min(horizon) } else { horizon },
            app_code: arr.get(2).map(s).unwrap_or_default(),
            client_code: arr.get(3).map(s).unwrap_or_default(),
        })
    }
}

/// `codesMatchResolved`: a blank supplied code is not a mismatch; comparison ignores case.
pub fn codes_match(supplied_app: Option<&str>, app: &str, supplied_client: Option<&str>, client: &str) -> bool {
    let m = |s: Option<&str>, r: &str| s.map(str::trim).filter(|s| !s.is_empty()).is_none_or(|s| s.eq_ignore_ascii_case(r));
    m(supplied_app, app) && m(supplied_client, client)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_rules() {
        assert!(codes_match(None, "leadzump", None, "FIN"));
        assert!(codes_match(Some("LEADZUMP"), "leadzump", Some(""), "FIN"));
        assert!(!codes_match(Some("other"), "leadzump", None, "FIN"));
        assert!(!codes_match(None, "leadzump", Some("SYSTEM"), "FIN"));
    }
}
