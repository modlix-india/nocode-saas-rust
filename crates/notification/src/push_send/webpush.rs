//! Web Push: the payload encrypted for the browser's subscription (RFC 8291, `aes128gcm` of
//! RFC 8188 in one record) and posted to its push service with a VAPID token (RFC 8292).

use std::time::Duration;

use anyhow::{anyhow, Result};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::EcdsaKeyPair;
use ring::{aead, agreement, hkdf};
use serde_json::json;

use super::keys::{b64_any, jwt_es256, vapid_pair, vapid_public};
use super::Delivery;

/// The push services browsers subscribe through. A subscription is a URL the browser hands in,
/// so only these hosts are ever posted to (a registered `http://10.0.0.5/...` would otherwise
/// make this service post wherever a user likes).
const PUSH_HOSTS: [&str; 5] = ["fcm.googleapis.com", "android.googleapis.com", "push.services.mozilla.com", "notify.windows.com", "push.apple.com"];

/// Whether `endpoint` is an `https` URL on a known push service.
pub fn allowed_endpoint(endpoint: &str) -> bool {
    let Ok(u) = reqwest::Url::parse(endpoint) else { return false };
    let Some(host) = u.host_str() else { return false };
    u.scheme() == "https" && u.port().is_none() && PUSH_HOSTS.iter().any(|h| host == *h || host.ends_with(&format!(".{h}")))
}

/// `ring::hkdf` output of any length.
struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], n: usize) -> Result<Vec<u8>> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(ikm);
    let info = [info];
    let okm = prk.expand(&info, Len(n)).map_err(|_| anyhow!("HKDF expand"))?;
    let mut out = vec![0; n];
    okm.fill(&mut out).map_err(|_| anyhow!("HKDF fill"))?;
    Ok(out)
}

/// Record size written in the header; one record holds any payload a push service takes (4 KB).
const RECORD_SIZE: u32 = 4096;

/// Everything after the key agreement (RFC 8291 section 3.4): the message body for the
/// browser whose key is `ua_public`, given the shared ECDH secret, this side's ephemeral public
/// key and the salt.
pub fn encrypt_with(ecdh_secret: &[u8], as_public: &[u8], ua_public: &[u8], auth: &[u8], salt: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut key_info = b"WebPush: info\0".to_vec();
    key_info.extend_from_slice(ua_public);
    key_info.extend_from_slice(as_public);
    let ikm = hkdf_sha256(auth, ecdh_secret, &key_info, 32)?;
    let cek = hkdf_sha256(salt, &ikm, b"Content-Encoding: aes128gcm\0", 16)?;
    let nonce = hkdf_sha256(salt, &ikm, b"Content-Encoding: nonce\0", 12)?;

    let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &cek).map_err(|_| anyhow!("AES key"))?);
    let nonce = aead::Nonce::try_assume_unique_for_key(&nonce).map_err(|_| anyhow!("nonce"))?;
    let mut record = plaintext.to_vec();
    // The last (and only) record's padding delimiter, no padding after it.
    record.push(2);
    key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut record).map_err(|_| anyhow!("AES-GCM seal"))?;

    let id_len = u8::try_from(as_public.len()).map_err(|_| anyhow!("key id too long"))?;
    let mut body = Vec::with_capacity(16 + 5 + as_public.len() + record.len());
    body.extend_from_slice(salt);
    body.extend_from_slice(&RECORD_SIZE.to_be_bytes());
    body.push(id_len);
    body.extend_from_slice(as_public);
    body.extend_from_slice(&record);
    Ok(body)
}

/// The body for a subscription (`p256dh` and `auth` as the browser gave them), with a fresh
/// ephemeral key and salt.
pub fn encrypt(p256dh: &str, auth: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    let ua_public = b64_any(p256dh)?;
    let auth = b64_any(auth)?;
    let rng = SystemRandom::new();
    let ephemeral = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).map_err(|_| anyhow!("ECDH key"))?;
    let as_public = ephemeral.compute_public_key().map_err(|_| anyhow!("ECDH public key"))?;
    let peer = agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, &ua_public);
    let secret = agreement::agree_ephemeral(ephemeral, &peer, |s| s.to_vec()).map_err(|_| anyhow!("the subscription's p256dh is not a P-256 key"))?;
    let mut salt = [0u8; 16];
    rng.fill(&mut salt).map_err(|_| anyhow!("salt"))?;
    encrypt_with(&secret, as_public.as_ref(), &ua_public, &auth, &salt, plaintext)
}

/// The platform's VAPID identity and the client that posts.
pub struct WebPush {
    key: EcdsaKeyPair,
    public: String,
    subject: String,
    http: reqwest::Client,
}

impl WebPush {
    pub fn new(public: &str, private: &str, subject: &str, timeout: Duration) -> Result<Self> {
        let key = vapid_pair(public, private)?;
        let public = vapid_public(&key);
        Ok(Self { key, public, subject: subject.to_string(), http: reqwest::Client::builder().timeout(timeout).build()? })
    }

    /// The key browsers subscribe with.
    pub fn public_key(&self) -> &str {
        &self.public
    }

    fn authorization(&self, endpoint: &str) -> Result<String> {
        let aud = reqwest::Url::parse(endpoint)?.origin().ascii_serialization();
        let exp = chrono::Utc::now().timestamp() + 12 * 3600;
        let jwt = jwt_es256(&self.key, &json!({"typ": "JWT", "alg": "ES256"}), &json!({"aud": aud, "exp": exp, "sub": self.subject}))?;
        Ok(format!("vapid t={jwt}, k={}", self.public))
    }

    pub async fn send(&self, endpoint: &str, p256dh: Option<&str>, auth: Option<&str>, payload: &[u8]) -> Delivery {
        if !allowed_endpoint(endpoint) {
            return Delivery::Gone(format!("not a push service: {endpoint}"));
        }
        let (Some(p256dh), Some(auth)) = (p256dh, auth) else { return Delivery::Gone("subscription without keys".into()) };
        let body = match encrypt(p256dh, auth, payload) {
            Ok(b) => b,
            Err(e) => return Delivery::Gone(format!("{e:#}")),
        };
        let authorization = match self.authorization(endpoint) {
            Ok(a) => a,
            Err(e) => return Delivery::Failed(format!("{e:#}")),
        };
        let rb = self
            .http
            .post(endpoint)
            .header("Authorization", authorization)
            .header("Content-Encoding", "aes128gcm")
            .header("Content-Type", "application/octet-stream")
            .header("TTL", "86400")
            .header("Urgency", "high")
            .body(body);
        match platform::meter::send("webpush", rb).await {
            Ok(r) if r.status().is_success() => Delivery::Sent,
            // The subscription expired or the user turned notifications off.
            Ok(r) if matches!(r.status().as_u16(), 404 | 410) => Delivery::Gone(format!("{}", r.status())),
            Ok(r) => {
                let status = r.status();
                Delivery::Failed(format!("{status}: {}", r.text().await.unwrap_or_default()))
            }
            Err(e) => Delivery::Failed(format!("{e:#}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::push_send::keys::b64url;

    /// RFC 8291 appendix A, end to end after the key agreement.
    #[test]
    fn rfc8291_example() {
        let body = encrypt_with(
            &b64_any("kyrL1jIIOHEzg3sM2ZWRHDRB62YACZhhSlknJ672kSs").unwrap(),
            &b64_any("BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8").unwrap(),
            &b64_any("BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4").unwrap(),
            &b64_any("BTBZMqHH6r4Tts7J_aSIgg").unwrap(),
            &b64_any("DGv6ra1nlYgDCS1FRnbzlw").unwrap(),
            b"When I grow up, I want to be a watermelon",
        )
        .unwrap();
        assert_eq!(
            b64url(&body),
            "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN"
        );
    }

    #[test]
    fn fresh_keys_each_time() {
        let ua = "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4";
        let a = encrypt(ua, "BTBZMqHH6r4Tts7J_aSIgg", b"x").unwrap();
        let b = encrypt(ua, "BTBZMqHH6r4Tts7J_aSIgg", b"x").unwrap();
        assert_eq!(a.len(), 16 + 4 + 1 + 65 + 2 + 16);
        assert_ne!(a, b);
        assert!(encrypt("AAAA", "BTBZMqHH6r4Tts7J_aSIgg", b"x").is_err());
    }

    #[test]
    fn only_push_services() {
        assert!(allowed_endpoint("https://fcm.googleapis.com/fcm/send/abc"));
        assert!(allowed_endpoint("https://updates.push.services.mozilla.com/wpush/v2/x"));
        assert!(allowed_endpoint("https://web.push.apple.com/QM"));
        assert!(allowed_endpoint("https://wns2-par02p.notify.windows.com/w/?token=x"));
        assert!(!allowed_endpoint("http://fcm.googleapis.com/fcm/send/abc"), "https only");
        assert!(!allowed_endpoint("https://fcm.googleapis.com:8443/x"), "default port only");
        assert!(!allowed_endpoint("https://evilfcm.googleapis.com.attacker.io/x"));
        assert!(!allowed_endpoint("https://notpush.apple.com.evil/x"));
        assert!(!allowed_endpoint("https://10.0.0.5/x"));
        assert!(!allowed_endpoint("nope"));
    }
}
