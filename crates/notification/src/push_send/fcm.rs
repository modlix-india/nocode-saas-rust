//! FCM HTTP v1 (Android): a message per token, authorised by an OAuth token the service
//! account's RS256 assertion buys from Google, kept until shortly before it expires.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use parking_lot::Mutex;
use ring::signature::RsaKeyPair;
use serde_json::{json, Map, Value};

use super::keys::{jwt_rs256, rs256_pkcs8};
use super::{Delivery, PushMessage};

const SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
const DEFAULT_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";

/// A Firebase project's service account.
pub struct FcmAccount {
    pub project_id: String,
    client_email: String,
    token_uri: String,
    key: RsaKeyPair,
}

impl std::fmt::Debug for FcmAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FcmAccount").field("project_id", &self.project_id).field("client_email", &self.client_email).finish()
    }
}

impl FcmAccount {
    /// From the service account JSON Google hands out, as an object or as its text.
    pub fn from_json(v: &Value) -> Result<Self> {
        let parsed;
        let m = match v {
            Value::Object(m) => m,
            Value::String(s) => {
                parsed = serde_json::from_str::<Map<String, Value>>(s).map_err(|e| anyhow!("FCM credentials are not JSON: {e}"))?;
                &parsed
            }
            _ => return Err(anyhow!("FCM credentials must be the service account JSON")),
        };
        let field = |k: &str| m.get(k).and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string);
        Ok(Self {
            project_id: field("project_id").ok_or_else(|| anyhow!("FCM credentials have no project_id"))?,
            client_email: field("client_email").ok_or_else(|| anyhow!("FCM credentials have no client_email"))?,
            token_uri: field("token_uri").unwrap_or_else(|| DEFAULT_TOKEN_URI.into()),
            key: rs256_pkcs8(&field("private_key").ok_or_else(|| anyhow!("FCM credentials have no private_key"))?)?,
        })
    }
}

/// The FCM v1 message for one token: a notification (shown by Android while the app is in the
/// background) and the same fields as string data (the app reads `url` on a tap).
pub fn message_json(token: &str, m: &PushMessage) -> Value {
    let mut notification = json!({"title": m.title, "body": m.body});
    if let Some(image) = &m.image {
        notification["image"] = json!(image);
    }
    let mut data = Map::new();
    for (k, v) in m.data() {
        data.insert(k.into(), Value::from(v));
    }
    json!({"message": {
        "token": token,
        "notification": notification,
        "data": data,
        "android": {"priority": "high", "notification": {"tag": m.notification_id}},
    }})
}

/// Whether an FCM error means the token will never work again.
fn token_gone(status: u16, body: &str) -> bool {
    if status == 404 || body.contains("UNREGISTERED") {
        return true;
    }
    status == 400 && body.contains("registration token")
}

pub struct Fcm {
    http: reqwest::Client,
    /// Per project: the access token and when to stop using it.
    tokens: Mutex<HashMap<String, (String, Instant)>>,
    send_url: String,
}

impl Fcm {
    pub fn new(timeout: Duration) -> Result<Self> {
        Ok(Self {
            http: reqwest::Client::builder().timeout(timeout).build()?,
            tokens: Mutex::new(HashMap::new()),
            send_url: "https://fcm.googleapis.com/v1/projects/{project}/messages:send".into(),
        })
    }

    async fn access_token(&self, a: &FcmAccount) -> Result<String> {
        if let Some((t, until)) = self.tokens.lock().get(&a.project_id) {
            if Instant::now() < *until {
                return Ok(t.clone());
            }
        }
        let now = chrono::Utc::now().timestamp();
        let assertion = jwt_rs256(
            &a.key,
            &json!({"alg": "RS256", "typ": "JWT"}),
            &json!({"iss": a.client_email, "scope": SCOPE, "aud": a.token_uri, "iat": now, "exp": now + 3600}),
        )?;
        let enc = |s: &str| percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string();
        let form = format!("grant_type={}&assertion={}", enc("urn:ietf:params:oauth:grant-type:jwt-bearer"), enc(&assertion));
        let rb = self.http.post(&a.token_uri).header("Content-Type", "application/x-www-form-urlencoded").body(form);
        let resp = platform::meter::send("google-oauth", rb).await?;
        let status = resp.status();
        let body: Value = resp.json().await.unwrap_or(Value::Null);
        let token = body["access_token"].as_str().filter(|_| status.is_success()).ok_or_else(|| anyhow!("Google refused the FCM service account ({status}): {body}"))?;
        let lifetime = body["expires_in"].as_u64().unwrap_or(3600).saturating_sub(300).max(60);
        self.tokens.lock().insert(a.project_id.clone(), (token.to_string(), Instant::now() + Duration::from_secs(lifetime)));
        Ok(token.to_string())
    }

    pub async fn send(&self, a: &FcmAccount, token: &str, m: &PushMessage) -> Delivery {
        let bearer = match self.access_token(a).await {
            Ok(t) => t,
            Err(e) => return Delivery::Failed(format!("{e:#}")),
        };
        let url = self.send_url.replace("{project}", &a.project_id);
        let rb = self.http.post(url).bearer_auth(bearer).header("Content-Type", "application/json").body(message_json(token, m).to_string());
        match platform::meter::send("fcm", rb).await {
            Ok(r) if r.status().is_success() => Delivery::Sent,
            Ok(r) => {
                let status = r.status().as_u16();
                let body = r.text().await.unwrap_or_default();
                if status == 401 {
                    self.tokens.lock().remove(&a.project_id);
                }
                if token_gone(status, &body) {
                    Delivery::Gone(format!("{status}: {body}"))
                } else {
                    Delivery::Failed(format!("{status}: {body}"))
                }
            }
            Err(e) => Delivery::Failed(format!("{e:#}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg() -> PushMessage {
        PushMessage {
            title: "New lead".into(),
            body: "Ann wants a call".into(),
            image: None,
            url: Some("/page/leads/7".into()),
            notification_id: "n-1".into(),
            app_code: "leadzumptwo".into(),
        }
    }

    #[test]
    fn message_shape() {
        let v = message_json("tok", &msg());
        assert_eq!(v["message"]["token"], "tok");
        assert_eq!(v["message"]["notification"], json!({"title": "New lead", "body": "Ann wants a call"}));
        assert_eq!(v["message"]["data"]["url"], "/page/leads/7");
        assert_eq!(v["message"]["data"]["appCode"], "leadzumptwo");
        assert_eq!(v["message"]["android"]["notification"]["tag"], "n-1");
        let with_image = message_json("tok", &PushMessage { image: Some("https://x/i.png".into()), ..msg() });
        assert_eq!(with_image["message"]["notification"]["image"], "https://x/i.png");
    }

    #[test]
    fn which_errors_drop_the_token() {
        assert!(token_gone(404, ""));
        assert!(token_gone(400, r#"{"error":{"status":"INVALID_ARGUMENT","message":"The registration token is not a valid FCM registration token"}}"#));
        assert!(token_gone(403, r#"{"details":[{"errorCode":"UNREGISTERED"}]}"#));
        assert!(!token_gone(400, r#"{"error":{"message":"Invalid JSON payload"}}"#));
        assert!(!token_gone(503, ""));
    }

    #[test]
    fn credentials_must_be_complete() {
        assert!(FcmAccount::from_json(&json!({"project_id": "p", "client_email": "e"})).unwrap_err().to_string().contains("private_key"));
        assert!(FcmAccount::from_json(&json!("not json")).is_err());
        assert!(FcmAccount::from_json(&json!({"client_email": "e", "private_key": "k"})).unwrap_err().to_string().contains("project_id"));
    }
}
