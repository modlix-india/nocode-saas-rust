//! `CloudflareCustomHostnameService`: a LIVE client URL's hostname registered (or removed) as a
//! Cloudflare for SaaS custom hostname, validated by TXT record.
//!
//! Configured only with an API token and a zone id; without them (local, dev, stage, and this
//! unit until its configuration carries them) nothing is called and every call answers `false`,
//! exactly as Java does. Failures are logged and answered `false`, never raised.

use serde_json::{json, Value};

/// `https://api.cloudflare.com/client/v4/zones/`.
pub const API_BASE: &str = "https://api.cloudflare.com/client/v4/zones/";

/// `security.cloudflare.ownDomains`' default.
pub const OWN_DOMAINS: &[&str] = &["modlix.com", "sitezump.ai", "authzump.ai", "adzump.ai", "leadzump.ai", "fincity.com"];

#[derive(Clone)]
pub struct CustomHostnames {
    api_token: String,
    zone_id: String,
    own_domains: Vec<String>,
    /// The API's base (`API_BASE`; a local fake in tests).
    base: String,
    http: reqwest::Client,
}

impl CustomHostnames {
    pub fn new(api_token: &str, zone_id: &str, own_domains: &[&str], base: &str) -> Self {
        Self {
            api_token: api_token.to_string(),
            zone_id: zone_id.to_string(),
            own_domains: own_domains.iter().map(|d| d.to_string()).collect(),
            base: base.to_string(),
            http: reqwest::Client::new(),
        }
    }

    /// No token, no zone: the environments that must never touch the shared zone.
    pub fn unconfigured() -> Self {
        Self::new("", "", OWN_DOMAINS, API_BASE)
    }

    /// `isConfigured()`.
    pub fn is_configured(&self) -> bool {
        !self.api_token.trim().is_empty() && !self.zone_id.trim().is_empty()
    }

    /// `isOwnDomain(hostname)`: the apex or anything under one of our domains.
    pub fn is_own_domain(&self, hostname: &str) -> bool {
        if hostname.trim().is_empty() {
            return false;
        }
        let host = hostname.trim().to_lowercase();
        self.own_domains.iter().any(|d| {
            let apex = d.trim().to_lowercase();
            let apex = apex.strip_prefix('.').unwrap_or(&apex).to_string();
            !apex.is_empty() && (host == apex || host.ends_with(&format!(".{apex}")))
        })
    }

    fn url(&self, suffix: &str) -> String {
        format!("{}{}/custom_hostnames{suffix}", self.base, self.zone_id)
    }

    fn skip(&self, hostname: &str) -> bool {
        !self.is_configured() || hostname.trim().is_empty() || self.is_own_domain(hostname)
    }

    /// `addHostname`.
    pub async fn add_hostname(&self, hostname: &str) -> bool {
        if self.skip(hostname) {
            return false;
        }
        let body = json!({"hostname": hostname, "ssl": {"method": "txt", "type": "dv", "settings": {"min_tls_version": "1.2"}}});
        let r = self.http.post(self.url("")).bearer_auth(&self.api_token).json(&body).send().await;
        match read(r).await {
            Some(v) if success(&v) => {
                tracing::info!(hostname, "cloudflare custom hostname created");
                true
            }
            Some(v) => {
                tracing::error!(hostname, errors = %errors(&v), "cloudflare refused a custom hostname");
                false
            }
            None => false,
        }
    }

    /// `removeHostname`: its id looked up first; not registered is not an error.
    pub async fn remove_hostname(&self, hostname: &str) -> bool {
        if self.skip(hostname) {
            return false;
        }
        let Some(id) = self.find_id(hostname).await else { return false };
        let r = self.http.delete(self.url(&format!("/{id}"))).bearer_auth(&self.api_token).send().await;
        match read(r).await {
            Some(v) if success(&v) => {
                tracing::info!(hostname, "cloudflare custom hostname removed");
                true
            }
            Some(v) => {
                tracing::error!(hostname, errors = %errors(&v), "cloudflare refused to remove a custom hostname");
                false
            }
            None => false,
        }
    }

    async fn find_id(&self, hostname: &str) -> Option<String> {
        let r = self.http.get(self.url(&format!("?hostname={hostname}"))).bearer_auth(&self.api_token).send().await;
        let v = read(r).await?;
        if !success(&v) {
            return None;
        }
        let first = v.get("result")?.as_array()?.first()?;
        match first.get("id")? {
            Value::String(s) => Some(s.clone()),
            Value::Null => None,
            other => Some(other.to_string()),
        }
    }
}

async fn read(r: Result<reqwest::Response, reqwest::Error>) -> Option<Value> {
    match r {
        Ok(resp) if resp.status().is_success() => resp.json::<Value>().await.ok(),
        Ok(resp) => {
            tracing::error!(status = %resp.status(), "cloudflare custom hostname call failed");
            None
        }
        Err(e) => {
            tracing::error!(error = %e, "cloudflare custom hostname call failed");
            None
        }
    }
}

fn success(v: &Value) -> bool {
    v.get("success") == Some(&Value::Bool(true))
}

/// The errors array for a log line (never the request, which carries the token).
fn errors(v: &Value) -> String {
    v.get("errors").map(Value::to_string).unwrap_or_else(|| "no detail".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::{Path, Query};
    use axum::routing::{delete, get};
    use axum::{Json, Router};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    /// An in-process stand-in for the Cloudflare API: it records calls and never leaves the host.
    async fn fake(calls: Arc<Mutex<Vec<String>>>, ok: bool) -> String {
        let c1 = calls.clone();
        let c2 = calls.clone();
        let c3 = calls.clone();
        let app = Router::new()
            .route(
                "/zone/custom_hostnames",
                get(move |Query(q): Query<HashMap<String, String>>| {
                    let c = c1.clone();
                    async move {
                        c.lock().unwrap().push(format!("find {}", q.get("hostname").cloned().unwrap_or_default()));
                        Json(json!({"success": true, "result": [{"id": "h1"}]}))
                    }
                })
                .post(move |Json(b): Json<Value>| {
                    let c = c2.clone();
                    async move {
                        c.lock().unwrap().push(format!("add {}", b["hostname"].as_str().unwrap_or("")));
                        Json(json!({"success": ok, "errors": [{"code": 1}]}))
                    }
                }),
            )
            .route(
                "/zone/custom_hostnames/{id}",
                delete(move |Path(id): Path<String>| {
                    let c = c3.clone();
                    async move {
                        c.lock().unwrap().push(format!("delete {id}"));
                        Json(json!({"success": ok}))
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}/")
    }

    #[test]
    fn own_domains_and_configuration() {
        let c = CustomHostnames::unconfigured();
        assert!(!c.is_configured());
        assert!(c.is_own_domain("sitezump.ai") && c.is_own_domain("A.Modlix.com") && !c.is_own_domain("example.com"));
        assert!(!c.is_own_domain(" "));
        // `doesNotOverreach`: a suffix match needs the dot.
        assert!(!c.is_own_domain("notmodlix.com") && !c.is_own_domain("modlix.com.evil.io"));
        // `apexAndWwwAreSeparate`: both are ours.
        assert!(c.is_own_domain("fincity.com") && c.is_own_domain("www.fincity.com"));
        let dotted = CustomHostnames::new("t", "z", &[".x.io", ""], API_BASE);
        assert!(dotted.is_configured() && dotted.is_own_domain("x.io"));
    }

    #[tokio::test]
    async fn calls_the_api_only_when_configured() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let base = fake(calls.clone(), true).await;
        let c = CustomHostnames::new("token", "zone", OWN_DOMAINS, &base);
        assert!(c.add_hostname("shop.example.com").await);
        assert!(c.remove_hostname("shop.example.com").await);
        assert!(!c.add_hostname("app.modlix.com").await, "own domains are never registered");
        assert!(!CustomHostnames::new("", "zone", OWN_DOMAINS, &base).add_hostname("shop.example.com").await);
        assert_eq!(*calls.lock().unwrap(), vec!["add shop.example.com", "find shop.example.com", "delete h1"]);

        let refusing = CustomHostnames::new("token", "zone", OWN_DOMAINS, &fake(calls.clone(), false).await);
        assert!(!refusing.add_hostname("a.example.com").await);
        assert!(!refusing.remove_hostname("a.example.com").await);
        let down = CustomHostnames::new("token", "zone", OWN_DOMAINS, "http://127.0.0.1:9/");
        assert!(!down.add_hostname("a.example.com").await);
        assert!(!down.remove_hostname("a.example.com").await);
        assert_eq!(errors(&json!({})), "no detail");
    }
}
