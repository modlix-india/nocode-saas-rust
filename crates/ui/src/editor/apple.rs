//! The App Store Connect half of `MobileAppService`: the ES256 token, the certificates list,
//! bundle ids and App Store provisioning profiles, for iOS builds published from the platform's
//! own Apple account.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use overridable::write::transport::base64_decode;
use overridable::{JMap, JValue};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde_json::{json, Value};

use crate::editor::config::EditorSection;

/// Base64 with the URL alphabet and no padding (JWT segments).
pub fn base64_url(bytes: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len() * 4 / 3 + 2);
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        for i in 0..chunk.len() + 1 {
            out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

fn blank(s: &str) -> bool {
    s.trim().is_empty()
}

/// `toLowerCase().replaceAll("[^a-z0-9]", "")`.
pub fn sanitize(s: &str) -> String {
    s.to_lowercase().chars().filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit()).collect()
}

/// The App Store Connect client of one configuration.
pub struct Apple {
    pub cfg: EditorSection,
    pub http: reqwest::Client,
}

impl Apple {
    pub fn new(cfg: EditorSection, http: reqwest::Client) -> Self {
        Self { cfg, http }
    }

    /// `isAppleApiConfiguredForBundleId`: the key, its issuer and the team.
    pub fn configured_for_bundle_id(&self) -> bool {
        let c = &self.cfg;
        !blank(&c.apple_api_key_id) && !blank(&c.apple_api_issuer_id) && !blank(&c.apple_api_key_content) && !blank(&c.apple_team_id)
    }

    /// `generateAppleJWT`: ES256 with the `.p8` key, for 20 minutes.
    pub fn jwt(&self) -> Result<String> {
        let c = &self.cfg;
        if blank(&c.apple_api_key_content) || blank(&c.apple_api_key_id) || blank(&c.apple_api_issuer_id) {
            bail!("Apple API credentials are not configured");
        }
        let pem = String::from_utf8(base64_decode(c.apple_api_key_content.trim()).map_err(|e| anyhow!("{e}"))?)?;
        let body: String = pem
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .chars()
            .filter(|ch| !ch.is_whitespace())
            .collect();
        let der = base64_decode(&body).map_err(|e| anyhow!("{e}"))?;
        let rng = SystemRandom::new();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der, &rng).map_err(|e| anyhow!("{e}"))?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let header = json!({"kid": c.apple_api_key_id, "typ": "JWT", "alg": "ES256"});
        let claims = json!({"iss": c.apple_api_issuer_id, "iat": now, "exp": now + 20 * 60, "aud": "appstoreconnect-v1"});
        let input = format!("{}.{}", base64_url(header.to_string().as_bytes()), base64_url(claims.to_string().as_bytes()));
        let sig = key.sign(&rng, input.as_bytes()).map_err(|e| anyhow!("{e}"))?;
        Ok(format!("{input}.{}", base64_url(sig.as_ref())))
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.cfg.apple_api_url.trim_end_matches('/'))
    }

    /// A GET or POST; `Err` with `on_error`'s text for a refusal.
    async fn call(&self, req: reqwest::RequestBuilder, on_error: impl Fn(u16, &str, String) -> String) -> Result<Value> {
        let jwt = self.jwt()?;
        let resp = req.bearer_auth(jwt).send().await?;
        let status = resp.status();
        let url = resp.url().to_string();
        let body = resp.text().await?;
        if !status.is_success() {
            bail!(on_error(status.as_u16(), &url, body));
        }
        Ok(serde_json::from_str(&body).unwrap_or(Value::Null))
    }

    /// `WebClientResponseException`'s message.
    fn retrieve_error(method: &'static str) -> impl Fn(u16, &str, String) -> String {
        move |status, url, _| {
            let reason = crate::shell::uripath::reason_phrase(status).unwrap_or("");
            format!("{status} {reason} from {method} {url}")
        }
    }

    /// `listCertificates`: id, type, name and expiry of every certificate of the team.
    pub async fn list_certificates(&self) -> Result<Vec<JMap>> {
        let v = self
            .call(self.http.get(self.url("/v1/certificates")), |_, _, body| format!("Apple API error: {body}"))
            .await
            .context("Failed to list certificates")?;
        let text = |v: &Value| match v {
            Value::String(s) => s.clone(),
            Value::Null => String::new(),
            other => other.to_string(),
        };
        let mut out = Vec::new();
        for cert in v.get("data").and_then(Value::as_array).into_iter().flatten() {
            let a = &cert["attributes"];
            let mut m = JMap::new();
            m.insert("id".into(), JValue::Str(text(&cert["id"])));
            m.insert("type".into(), JValue::Str(text(&a["certificateType"])));
            m.insert("displayName".into(), JValue::Str(text(&a["displayName"])));
            m.insert("expirationDate".into(), JValue::Str(text(&a["expirationDate"])));
            out.push(overridable::java_map::by_puts(m));
        }
        Ok(out)
    }

    pub fn bundle_identifier(&self, client: &str, app_name: &str) -> String {
        format!("{}.{}.{}", self.cfg.apple_bundle_id_prefix, sanitize(client), sanitize(app_name))
    }

    /// `getAppleBundleIdByIdentifier`: Apple's id of a bundle id, if it has one.
    async fn bundle_id_by_identifier(&self, identifier: &str) -> Result<Option<(String, String)>> {
        let req = self.http.get(self.url("/v1/bundleIds")).query(&[("filter[identifier]", identifier)]);
        let v = self.call(req, Self::retrieve_error("GET")).await?;
        Ok(v.get("data")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .map(|d| (identifier.to_string(), d["id"].as_str().unwrap_or("").to_string())))
    }

    /// `createAppleBundleId`.
    async fn create_bundle_id(&self, client: &str, app_name: &str) -> Result<(String, String)> {
        let identifier = self.bundle_identifier(client, app_name);
        let body = json!({"data": {"type": "bundleIds", "attributes": {"identifier": identifier, "name": format!("{app_name} - {client}"), "platform": "IOS"}}});
        match self.call(self.http.post(self.url("/v1/bundleIds")).json(&body), Self::retrieve_error("POST")).await {
            Ok(v) => Ok((identifier, v["data"]["id"].as_str().unwrap_or("").to_string())),
            Err(e) if e.to_string().contains("ENTITY_ERROR") => {
                self.bundle_id_by_identifier(&identifier).await?.ok_or_else(|| anyhow!("Bundle ID {identifier} not found"))
            }
            Err(e) => Err(e),
        }
    }

    /// `getOrCreateBundleId`.
    pub async fn get_or_create_bundle_id(&self, client: &str, app_name: &str) -> Result<(String, String)> {
        let identifier = self.bundle_identifier(client, app_name);
        match self.bundle_id_by_identifier(&identifier).await? {
            Some(found) => Ok(found),
            None => self.create_bundle_id(client, app_name).await,
        }
    }

    /// `getExistingProvisioningProfile`: the App Store profile of a bundle id, `""` when there
    /// is none or Apple cannot be asked.
    async fn existing_profile(&self, bundle_apple_id: &str) -> String {
        let req = self
            .http
            .get(self.url("/v1/profiles"))
            .query(&[("filter[profileType]", "IOS_APP_STORE"), ("include", "bundleId")]);
        let Ok(v) = self.call(req, |_, _, body| format!("Apple API error: {body}")).await else { return String::new() };
        v.get("data")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .find(|p| p["relationships"]["bundleId"]["data"]["id"].as_str() == Some(bundle_apple_id))
            .map(|p| p["attributes"]["profileContent"].as_str().unwrap_or("").to_string())
            .unwrap_or_default()
    }

    /// `createNewProvisioningProfile`.
    async fn new_profile(&self, bundle_apple_id: &str, profile_name: &str) -> Result<String> {
        let body = json!({"data": {
            "type": "profiles",
            "attributes": {"name": profile_name, "profileType": "IOS_APP_STORE"},
            "relationships": {
                "bundleId": {"data": {"type": "bundleIds", "id": bundle_apple_id}},
                "certificates": {"data": [{"type": "certificates", "id": self.cfg.apple_certificate_id}]}
            }
        }});
        let r = self.call(self.http.post(self.url("/v1/profiles")).json(&body), |_, _, body| format!("Apple API error: {body}")).await;
        match r {
            Ok(v) => Ok(v["data"]["attributes"]["profileContent"].as_str().unwrap_or("").to_string()),
            Err(e) => {
                let m = e.to_string();
                let lower = m.to_lowercase();
                if lower.contains("certificate") || lower.contains("no current certificates") || lower.contains("certificates on this team") {
                    bail!("Failed to create provisioning profile. Certificate may be invalid, expired, or not compatible with IOS_APP_STORE profiles. Please verify the certificate ID is correct and the certificate is valid for App Store distribution. Error: {m}");
                }
                if lower.contains("entity_error") {
                    let existing = self.existing_profile(bundle_apple_id).await;
                    if !blank(&existing) {
                        return Ok(existing);
                    }
                    bail!("Failed to create or retrieve provisioning profile: {m}");
                }
                bail!("Failed to create provisioning profile: {m}")
            }
        }
    }

    /// `createProvisioningProfile`: the existing profile, or a new one; `""` without a
    /// configured certificate.
    pub async fn provisioning_profile(&self, bundle_apple_id: &str, profile_name: &str) -> Result<String> {
        if blank(&self.cfg.apple_certificate_id) {
            return Ok(String::new());
        }
        let existing = self.existing_profile(bundle_apple_id).await;
        if !blank(&existing) {
            return Ok(existing);
        }
        self.new_profile(bundle_apple_id, profile_name).await
    }

    /// Turns Push Notifications on for the bundle (Rust only); one already on is fine.
    pub async fn enable_push(&self, bundle_apple_id: &str) -> Result<()> {
        let body = json!({"data": {
            "type": "bundleIdCapabilities",
            "attributes": {"capabilityType": "PUSH_NOTIFICATIONS"},
            "relationships": {"bundleId": {"data": {"type": "bundleIds", "id": bundle_apple_id}}}
        }});
        match self.call(self.http.post(self.url("/v1/bundleIdCapabilities")).json(&body), |status, _, body| format!("Apple API error {status}: {body}")).await {
            Ok(_) => Ok(()),
            Err(e) if e.to_string().contains("409") => Ok(()),
            Err(e) => Err(e).context("Failed to turn on Push Notifications for the bundle id"),
        }
    }

    /// A new App Store profile for the bundle, its earlier ones deleted first (Rust only): a
    /// profile made before a capability was turned on does not carry it. `""` without a
    /// configured certificate.
    pub async fn replace_profile(&self, bundle_apple_id: &str, profile_name: &str) -> Result<String> {
        if blank(&self.cfg.apple_certificate_id) {
            return Ok(String::new());
        }
        let req = self.http.get(self.url("/v1/profiles")).query(&[("filter[profileType]", "IOS_APP_STORE"), ("include", "bundleId")]);
        let v = self.call(req, |_, _, body| format!("Apple API error: {body}")).await?;
        let old: Vec<String> = v
            .get("data")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|p| p["relationships"]["bundleId"]["data"]["id"].as_str() == Some(bundle_apple_id))
            .filter_map(|p| p["id"].as_str().map(str::to_string))
            .collect();
        for id in old {
            self.call(self.http.delete(self.url(&format!("/v1/profiles/{id}"))), |_, _, body| format!("Apple API error: {body}"))
                .await
                .context("Failed to delete the old provisioning profile")?;
        }
        self.new_profile(bundle_apple_id, profile_name).await
    }

    /// `setupIosForPlatformAccount`: (bundle id, team id, profile).
    pub async fn setup_ios(&self, client: &str, app_name: &str) -> Result<(String, String, String)> {
        let (identifier, apple_id) = self.get_or_create_bundle_id(client, app_name).await?;
        let profile = self.provisioning_profile(&apple_id, &format!("{app_name} - {client} - App Store")).await?;
        if blank(&profile) && !blank(&self.cfg.apple_certificate_id) {
            bail!("Failed to create or retrieve provisioning profile. Certificate ID is configured but no profile could be obtained.");
        }
        Ok((identifier, self.cfg.apple_team_id.clone(), profile))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_safe_base64_and_names() {
        assert_eq!(base64_url(b""), "");
        assert_eq!(base64_url(b"f"), "Zg");
        assert_eq!(base64_url(b"fo"), "Zm8");
        assert_eq!(base64_url(b"foo"), "Zm9v");
        assert_eq!(base64_url(&[0xfb, 0xff]), "-_8");
        assert_eq!(sanitize("My App-1!"), "myapp1");
        let a = Apple::new(EditorSection::default(), reqwest::Client::new());
        assert_eq!(a.bundle_identifier("CLI.ent", "Shop App"), "com.modlix.apps.client.shopapp");
        assert!(!a.configured_for_bundle_id());
        assert_eq!(a.jwt().unwrap_err().to_string(), "Apple API credentials are not configured");
    }
}
