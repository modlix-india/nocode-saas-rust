//! APNs (iOS): token-based auth over HTTP/2. One `.p8` key serves every app of its Apple team;
//! the topic is the app's bundle id. Apple refuses a provider token renewed more often than every
//! 20 minutes, so each team's is kept for 50.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use parking_lot::Mutex;
use ring::signature::EcdsaKeyPair;
use serde_json::{json, Value};

use super::keys::{es256_pkcs8, jwt_es256};
use super::{Delivery, PushMessage};

const TOKEN_LIFE: Duration = Duration::from_secs(50 * 60);

/// An Apple team's APNs token key.
pub struct ApnsAccount {
    pub team_id: String,
    key_id: String,
    key: EcdsaKeyPair,
}

impl std::fmt::Debug for ApnsAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApnsAccount").field("team_id", &self.team_id).field("key_id", &self.key_id).finish()
    }
}

impl ApnsAccount {
    pub fn new(team_id: &str, key_id: &str, private_key: &str) -> Result<Self> {
        if team_id.trim().is_empty() || key_id.trim().is_empty() {
            return Err(anyhow!("APNs needs teamId and keyId"));
        }
        Ok(Self { team_id: team_id.trim().into(), key_id: key_id.trim().into(), key: es256_pkcs8(private_key)? })
    }
}

/// The APNs payload: the alert, and the same fields the Android data carries.
pub fn payload_json(m: &PushMessage) -> Value {
    let mut v = json!({"aps": {"alert": {"title": m.title, "body": m.body}, "sound": "default"}});
    for (k, val) in m.data() {
        v[k] = json!(val);
    }
    v
}

/// Whether an APNs refusal means the token will never work for this app again.
fn token_gone(status: u16, reason: &str) -> bool {
    status == 410 || matches!(reason, "BadDeviceToken" | "DeviceTokenNotForTopic" | "Unregistered")
}

pub struct Apns {
    client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
    tokens: Mutex<HashMap<String, (String, Instant)>>,
    timeout: Duration,
}

impl Apns {
    pub fn new(timeout: Duration) -> Result<Self> {
        platform::crypto::install();
        let https = hyper_rustls::HttpsConnectorBuilder::new().with_webpki_roots().https_only().enable_http2().build();
        let client = Client::builder(TokioExecutor::new()).http2_only(true).build(https);
        Ok(Self { client, tokens: Mutex::new(HashMap::new()), timeout })
    }

    fn provider_token(&self, a: &ApnsAccount) -> Result<String> {
        let mut tokens = self.tokens.lock();
        if let Some((t, made)) = tokens.get(&a.team_id) {
            if made.elapsed() < TOKEN_LIFE {
                return Ok(t.clone());
            }
        }
        let t = jwt_es256(&a.key, &json!({"alg": "ES256", "kid": a.key_id}), &json!({"iss": a.team_id, "iat": chrono::Utc::now().timestamp()}))?;
        tokens.insert(a.team_id.clone(), (t.clone(), Instant::now()));
        Ok(t)
    }

    pub async fn send(&self, a: &ApnsAccount, device_token: &str, topic: &str, sandbox: bool, m: &PushMessage) -> Delivery {
        match self.try_send(a, device_token, topic, sandbox, m).await {
            Ok(d) => d,
            Err(e) => Delivery::Failed(format!("{e:#}")),
        }
    }

    async fn try_send(&self, a: &ApnsAccount, device_token: &str, topic: &str, sandbox: bool, m: &PushMessage) -> Result<Delivery> {
        if !device_token.chars().all(|c| c.is_ascii_hexdigit()) || device_token.is_empty() {
            return Ok(Delivery::Gone("not an APNs device token".into()));
        }
        let host = if sandbox { "api.sandbox.push.apple.com" } else { "api.push.apple.com" };
        let mut collapse = m.notification_id.clone();
        collapse.truncate(64);
        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri(format!("https://{host}/3/device/{device_token}"))
            .header("authorization", format!("bearer {}", self.provider_token(a)?))
            .header("apns-topic", topic)
            .header("apns-push-type", "alert")
            .header("apns-priority", "10")
            .header("apns-collapse-id", collapse)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(payload_json(m).to_string())))?;
        let started = Instant::now();
        let resp = tokio::time::timeout(self.timeout, self.client.request(req)).await.map_err(|_| anyhow!("APNs timed out"))??;
        let status = resp.status().as_u16();
        let body = tokio::time::timeout(self.timeout, resp.into_body().collect()).await.map_err(|_| anyhow!("APNs body timed out"))??.to_bytes();
        metrics::histogram!("notification_apns_seconds").record(started.elapsed().as_secs_f64());
        if status == 200 {
            return Ok(Delivery::Sent);
        }
        let reason = serde_json::from_slice::<Value>(&body).ok().and_then(|v| v["reason"].as_str().map(str::to_string)).unwrap_or_default();
        if matches!(reason.as_str(), "ExpiredProviderToken" | "InvalidProviderToken") {
            self.tokens.lock().remove(&a.team_id);
        }
        Ok(if token_gone(status, &reason) { Delivery::Gone(format!("{status} {reason}")) } else { Delivery::Failed(format!("{status} {reason}")) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_shape() {
        let m = PushMessage {
            title: "T".into(),
            body: "B".into(),
            image: None,
            url: Some("/page/x".into()),
            notification_id: "9".into(),
            app_code: "app".into(),
        };
        let v = payload_json(&m);
        assert_eq!(v["aps"]["alert"], json!({"title": "T", "body": "B"}));
        assert_eq!(v["url"], "/page/x");
        assert_eq!(v["notificationId"], "9");
    }

    #[test]
    fn which_errors_drop_the_token() {
        assert!(token_gone(410, "Unregistered"));
        assert!(token_gone(400, "BadDeviceToken"));
        assert!(token_gone(400, "DeviceTokenNotForTopic"));
        assert!(!token_gone(403, "InvalidProviderToken"));
        assert!(!token_gone(429, "TooManyRequests"));
        assert!(ApnsAccount::new("", "K", "x").is_err());
    }
}
