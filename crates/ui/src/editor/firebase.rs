//! The platform's Firebase project, for Android push (Rust only): a mobile app with push gets
//! its Android package registered there (Firebase Management API), and the values the app
//! starts Firebase with (`firebaseAndroid`: `apiKey`, `appId`, `projectId`,
//! `messagingSenderId`) for the build machine to write into it. A tenant that uses its own
//! Firebase project fills those values itself, and nothing is registered here.

use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ring::rand::SystemRandom;
use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};
use serde_json::{json, Map, Value};

use crate::editor::apple::base64_url;
use crate::editor::config::EditorSection;

const SCOPE: &str = "https://www.googleapis.com/auth/firebase";

/// The values `firebaseAndroid` holds.
pub const ANDROID_KEYS: [&str; 4] = ["apiKey", "appId", "projectId", "messagingSenderId"];

/// The Android package the build machine gives an app (make.py): the client in lower case and
/// the app's name in lower case with spaces as underscores.
pub fn android_package(client: &str, app_name: &str) -> String {
    format!("com.modlix.nocodemobile.{}.{}", client.to_lowercase(), app_name.to_lowercase().replace(' ', "_"))
}

/// The service account `[editor] firebase_credentials` holds.
struct Account {
    client_email: String,
    token_uri: String,
    project_id: String,
    key: RsaKeyPair,
}

fn account(credentials: &str) -> Result<Account> {
    let v: Map<String, Value> = serde_json::from_str(credentials).context("firebase_credentials is not the service account JSON")?;
    let field = |k: &str| v.get(k).and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string);
    let pem = field("private_key").ok_or_else(|| anyhow!("firebase_credentials has no private_key"))?;
    let body: String = pem.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with("-----")).collect();
    let der = STANDARD.decode(body.as_bytes()).context("firebase_credentials private_key is not PEM")?;
    Ok(Account {
        client_email: field("client_email").ok_or_else(|| anyhow!("firebase_credentials has no client_email"))?,
        token_uri: field("token_uri").unwrap_or_else(|| "https://oauth2.googleapis.com/token".into()),
        project_id: field("project_id").ok_or_else(|| anyhow!("firebase_credentials has no project_id"))?,
        key: RsaKeyPair::from_pkcs8(&der).map_err(|e| anyhow!("firebase_credentials private_key: {e}"))?,
    })
}

/// The values of one Android app from its `google-services.json`.
pub fn android_values(google_services: &Value, package: &str) -> Result<Map<String, Value>> {
    let project = &google_services["project_info"];
    let client = google_services["client"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|c| c["client_info"]["android_client_info"]["package_name"].as_str() == Some(package))
        .ok_or_else(|| anyhow!("google-services.json has no client for {package}"))?;
    let text = |v: &Value| v.as_str().filter(|s| !s.is_empty()).map(|s| Value::String(s.to_string()));
    let mut out = Map::new();
    for (k, v) in [
        ("apiKey", text(&client["api_key"][0]["current_key"])),
        ("appId", text(&client["client_info"]["mobilesdk_app_id"])),
        ("projectId", text(&project["project_id"])),
        ("messagingSenderId", text(&project["project_number"])),
    ] {
        out.insert(k.into(), v.ok_or_else(|| anyhow!("google-services.json has no {k} for {package}"))?);
    }
    Ok(out)
}

pub struct Firebase {
    credentials: String,
    api_url: String,
    http: reqwest::Client,
    /// Between looks at a running registration.
    poll: Duration,
}

impl Firebase {
    pub fn new(cfg: &EditorSection, http: reqwest::Client) -> Self {
        Self { credentials: cfg.firebase_credentials.clone(), api_url: cfg.firebase_api_url.trim_end_matches('/').to_string(), http, poll: Duration::from_secs(1) }
    }

    pub fn configured(&self) -> bool {
        !self.credentials.trim().is_empty()
    }

    async fn token(&self, a: &Account) -> Result<String> {
        let now = chrono::Utc::now().timestamp();
        let header = json!({"alg": "RS256", "typ": "JWT"});
        let claims = json!({"iss": a.client_email, "scope": SCOPE, "aud": a.token_uri, "iat": now, "exp": now + 3600});
        let input = format!("{}.{}", base64_url(header.to_string().as_bytes()), base64_url(claims.to_string().as_bytes()));
        let mut sig = vec![0; a.key.public().modulus_len()];
        a.key.sign(&RSA_PKCS1_SHA256, &SystemRandom::new(), input.as_bytes(), &mut sig).map_err(|e| anyhow!("RS256: {e}"))?;
        let assertion = format!("{input}.{}", base64_url(&sig));
        let enc = |s: &str| percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string();
        let form = format!("grant_type={}&assertion={}", enc("urn:ietf:params:oauth:grant-type:jwt-bearer"), enc(&assertion));
        let resp = self.http.post(&a.token_uri).header("Content-Type", "application/x-www-form-urlencoded").body(form).send().await?;
        let status = resp.status();
        let v: Value = resp.json().await.unwrap_or(Value::Null);
        v["access_token"]
            .as_str()
            .filter(|_| status.is_success())
            .map(str::to_string)
            .ok_or_else(|| anyhow!("Google refused the Firebase service account ({status}): {v}"))
    }

    async fn call(&self, token: &str, req: reqwest::RequestBuilder) -> Result<Value> {
        let resp = req.bearer_auth(token).send().await?;
        let status = resp.status();
        let url = resp.url().to_string();
        let body = resp.text().await?;
        if !status.is_success() {
            bail!("Firebase {status} from {url}: {body}");
        }
        Ok(serde_json::from_str(&body).unwrap_or(Value::Null))
    }

    /// The Firebase app id of `package` in the project, if it is registered.
    async fn find_android_app(&self, token: &str, project: &str, package: &str) -> Result<Option<String>> {
        let mut page: Option<String> = None;
        loop {
            let mut req = self.http.get(format!("{}/v1beta1/projects/{project}/androidApps", self.api_url)).query(&[("pageSize", "100")]);
            if let Some(p) = &page {
                req = req.query(&[("pageToken", p)]);
            }
            let v = self.call(token, req).await?;
            if let Some(app) = v["apps"].as_array().into_iter().flatten().find(|a| a["packageName"].as_str() == Some(package)) {
                return Ok(app["appId"].as_str().map(str::to_string));
            }
            match v["nextPageToken"].as_str().filter(|t| !t.is_empty()) {
                Some(t) => page = Some(t.to_string()),
                None => return Ok(None),
            }
        }
    }

    /// Registers `package` and waits for Firebase to finish (it answers a long-running operation).
    async fn create_android_app(&self, token: &str, project: &str, package: &str, display_name: &str) -> Result<String> {
        let url = format!("{}/v1beta1/projects/{project}/androidApps", self.api_url);
        let mut op = self.call(token, self.http.post(url).json(&json!({"packageName": package, "displayName": display_name}))).await?;
        for _ in 0..30 {
            if op["done"].as_bool() == Some(true) {
                if let Some(e) = op.get("error") {
                    bail!("Firebase could not register {package}: {e}");
                }
                return op["response"]["appId"].as_str().map(str::to_string).ok_or_else(|| anyhow!("Firebase registered {package} without an app id"));
            }
            let name = op["name"].as_str().ok_or_else(|| anyhow!("Firebase answered no operation for {package}"))?.to_string();
            tokio::time::sleep(self.poll).await;
            op = self.call(token, self.http.get(format!("{}/v1beta1/{name}", self.api_url))).await?;
        }
        bail!("Firebase is still registering {package}; save the mobile app again in a minute")
    }

    /// `firebaseAndroid` for the app: registered in the platform's project when it is not yet.
    pub async fn android_config(&self, package: &str, display_name: &str) -> Result<Map<String, Value>> {
        let a = account(&self.credentials)?;
        let token = self.token(&a).await?;
        let project = a.project_id.as_str();
        let app_id = match self.find_android_app(&token, project, package).await? {
            Some(id) => id,
            None => self.create_android_app(&token, project, package, display_name).await?,
        };
        let cfg = self.call(&token, self.http.get(format!("{}/v1beta1/projects/{project}/androidApps/{app_id}/config", self.api_url))).await?;
        let file = cfg["configFileContents"].as_str().ok_or_else(|| anyhow!("Firebase sent no google-services.json for {package}"))?;
        let json: Value = serde_json::from_slice(&STANDARD.decode(file.as_bytes()).context("google-services.json is not base64")?)?;
        android_values(&json, package)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_names_as_make_py_builds_them() {
        assert_eq!(android_package("SYSTEM", "Shop App"), "com.modlix.nocodemobile.system.shop_app");
        assert_eq!(android_package("Fin", "lz"), "com.modlix.nocodemobile.fin.lz");
    }

    #[test]
    fn values_from_google_services() {
        let gs = json!({
            "project_info": {"project_number": "123", "project_id": "modlix-push"},
            "client": [
                {"client_info": {"mobilesdk_app_id": "1:123:android:aa", "android_client_info": {"package_name": "other"}}, "api_key": [{"current_key": "K0"}]},
                {"client_info": {"mobilesdk_app_id": "1:123:android:bb", "android_client_info": {"package_name": "com.x"}}, "api_key": [{"current_key": "K1"}]}
            ]
        });
        let v = android_values(&gs, "com.x").unwrap();
        assert_eq!(Value::Object(v), json!({"apiKey": "K1", "appId": "1:123:android:bb", "projectId": "modlix-push", "messagingSenderId": "123"}));
        assert!(android_values(&gs, "com.none").is_err());
        assert!(account("{}").is_err());
    }
}
