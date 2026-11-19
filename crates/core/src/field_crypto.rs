//! Field encryption for app data that must be kept but never shown: `CoreServices.Crypto.EncryptField` and
//! `DecryptField` (`crate::functions::field_crypto`), CXZ-1961 (a buyer's full Aadhaar number).
//!
//! **How it is kept secret.** AES-256-GCM under `[crypto] field_key` (32 bytes, base64; one per environment,
//! never changed once a value has been encrypted with it). The same pattern as the seal certificates
//! (`crate::seal_certs`): a random nonce per value, and the client, the app and a field label are bound in as
//! associated data, so a value copied to another client, another app or another field does not open.
//!
//! **Stored form.** `v1.` + base64url (no padding) of nonce + ciphertext + tag. The prefix names the key
//! generation so a later rotation can tell old values from new ones.
//!
//! **Who may read it.** Decrypting needs a signed-in caller who holds the authority the calling function
//! names (checked here, not by the caller's own code). Encrypting needs no authority: it reveals nothing.
//!
//! **Never logged.** No plaintext, no ciphertext and no key goes into a log line or an error message; an
//! error says what is wrong (no key set up, cannot open, not allowed) and nothing more.
//!
//! No `[crypto] field_key`: both functions answer 503 with a plain message and the rest of the unit works.

use std::sync::OnceLock;

use axum::http::StatusCode;
use base64::Engine as _;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use crate::error::CoreError;

/// `[crypto]` of the core units. `Debug` hides the key.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CryptoConfig {
    /// 32 bytes, base64. Empty: `EncryptField` and `DecryptField` answer 503 on this environment.
    pub field_key: String,
}

impl std::fmt::Debug for CryptoConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoConfig").field("field_key", &if self.field_key.trim().is_empty() { "unset" } else { "set" }).finish()
    }
}

const PREFIX: &str = "v1.";

static KEY: OnceLock<Option<LessSafeKey>> = OnceLock::new();

/// Reads `[crypto]` once at startup. A key that is not base64 or not 32 bytes stops the start (a wrong key
/// must never be mistaken for "no key").
pub fn install(cfg: &CryptoConfig) -> anyhow::Result<()> {
    let key = key_of(&cfg.field_key)?;
    tracing::info!(field_key = key.is_some(), "crypto: [crypto] config");
    let _ = KEY.set(key);
    Ok(())
}

pub fn key_of(b64: &str) -> anyhow::Result<Option<LessSafeKey>> {
    let b64: String = b64.split_whitespace().collect();
    if b64.is_empty() {
        return Ok(None);
    }
    let raw = base64::engine::general_purpose::STANDARD.decode(b64).map_err(|_| anyhow::anyhow!("[crypto] field_key is not base64"))?;
    let unbound = UnboundKey::new(&AES_256_GCM, &raw).map_err(|_| anyhow::anyhow!("[crypto] field_key must be 32 bytes"))?;
    Ok(Some(LessSafeKey::new(unbound)))
}

/// The installed key, or the plain 503 that says what to set.
pub fn installed() -> Result<&'static LessSafeKey, CoreError> {
    KEY.get().and_then(|k| k.as_ref()).ok_or_else(not_set_up)
}

pub fn not_set_up() -> CoreError {
    CoreError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "Field encryption is not set up on this environment: set [crypto] field_key in the core configuration.",
    )
}

fn aad(client: &str, app: &str, field: &str) -> Vec<u8> {
    format!("field-crypto|v1|{client}|{app}|{field}").into_bytes()
}

/// An empty text stays empty (nothing to protect, and "no value" must stay distinguishable).
pub fn encrypt_with(key: &LessSafeKey, client: &str, app: &str, field: &str, plain: &str) -> Result<String, CoreError> {
    if plain.is_empty() {
        return Ok(String::new());
    }
    let mut nonce = [0u8; NONCE_LEN];
    SystemRandom::new().fill(&mut nonce).map_err(|_| CoreError::new(StatusCode::INTERNAL_SERVER_ERROR, "Field encryption failed."))?;
    let mut buf = plain.as_bytes().to_vec();
    key.seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(aad(client, app, field)), &mut buf)
        .map_err(|_| CoreError::new(StatusCode::INTERNAL_SERVER_ERROR, "Field encryption failed."))?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&buf);
    Ok(format!("{PREFIX}{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(out)))
}

pub fn decrypt_with(key: &LessSafeKey, client: &str, app: &str, field: &str, stored: &str) -> Result<String, CoreError> {
    if stored.is_empty() {
        return Ok(String::new());
    }
    let cannot = || CoreError::new(StatusCode::BAD_REQUEST, "This value cannot be decrypted here (another client, app, field or key).");
    let body = stored.strip_prefix(PREFIX).ok_or_else(cannot)?;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(body).map_err(|_| cannot())?;
    if raw.len() <= NONCE_LEN {
        return Err(cannot());
    }
    let (nonce, rest) = raw.split_at(NONCE_LEN);
    let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| cannot())?;
    let mut buf = rest.to_vec();
    let plain = key.open_in_place(nonce, Aad::from(aad(client, app, field)), &mut buf).map_err(|_| cannot())?;
    String::from_utf8(plain.to_vec()).map_err(|_| cannot())
}

/// The caller must be signed in and hold `authority` (a KIRun authority expression, as `HasAuthority`
/// takes). An empty authority is refused: reading a protected value always names who may.
pub fn check_reader(is_authenticated: bool, authorities: &[String], authority: &str) -> Result<(), CoreError> {
    let denied = || CoreError::new(StatusCode::FORBIDDEN, "Not allowed to read this value.");
    if !is_authenticated || authority.trim().is_empty() {
        return Err(denied());
    }
    match crate::authorities::has_authority(Some(authority), authorities) {
        Ok(true) => Ok(()),
        _ => Err(denied()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> LessSafeKey {
        key_of(&base64::engine::general_purpose::STANDARD.encode([byte; 32])).unwrap().unwrap()
    }

    #[test]
    fn a_value_round_trips_and_is_not_readable_in_storage() {
        let k = key(7);
        let enc = encrypt_with(&k, "FIN", "cxzump", "cxParty.aadhaar", "123456789012").unwrap();
        assert!(enc.starts_with("v1."));
        assert!(!enc.contains("123456789012"));
        assert_eq!(decrypt_with(&k, "FIN", "cxzump", "cxParty.aadhaar", &enc).unwrap(), "123456789012");
    }

    #[test]
    fn the_same_value_encrypts_differently_each_time() {
        let k = key(7);
        assert_ne!(encrypt_with(&k, "FIN", "cxzump", "f", "x1").unwrap(), encrypt_with(&k, "FIN", "cxzump", "f", "x1").unwrap());
    }

    #[test]
    fn another_client_app_field_or_key_cannot_open_it() {
        let k = key(7);
        let enc = encrypt_with(&k, "FIN", "cxzump", "cxParty.aadhaar", "123456789012").unwrap();
        for (c, a, f) in [("DISHA1", "cxzump", "cxParty.aadhaar"), ("FIN", "other", "cxParty.aadhaar"), ("FIN", "cxzump", "cxParty.pan")] {
            let e = decrypt_with(&k, c, a, f, &enc).unwrap_err();
            assert_eq!(e.status(), StatusCode::BAD_REQUEST);
            assert!(!e.text().contains("123456789012"));
        }
        assert!(decrypt_with(&key(8), "FIN", "cxzump", "cxParty.aadhaar", &enc).is_err());
    }

    #[test]
    fn a_damaged_or_foreign_text_is_refused_not_guessed() {
        let k = key(7);
        let enc = encrypt_with(&k, "FIN", "cxzump", "f", "secret").unwrap();
        let mut bad = enc.clone();
        bad.push('A');
        assert!(decrypt_with(&k, "FIN", "cxzump", "f", &bad).is_err());
        assert!(decrypt_with(&k, "FIN", "cxzump", "f", "123456789012").is_err());
        assert!(decrypt_with(&k, "FIN", "cxzump", "f", "v1.").is_err());
    }

    #[test]
    fn empty_stays_empty() {
        let k = key(7);
        assert_eq!(encrypt_with(&k, "FIN", "cxzump", "f", "").unwrap(), "");
        assert_eq!(decrypt_with(&k, "FIN", "cxzump", "f", "").unwrap(), "");
    }

    #[test]
    fn a_missing_key_says_what_to_set_and_a_bad_key_is_refused() {
        let e = not_set_up();
        assert_eq!(e.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(e.text().contains("[crypto] field_key"));
        assert!(key_of("").unwrap().is_none());
        assert!(key_of("not base64 !!").is_err());
        assert!(key_of(&base64::engine::general_purpose::STANDARD.encode([1u8; 16])).is_err());
    }

    #[test]
    fn only_a_signed_in_holder_of_the_named_authority_may_read() {
        let admin = vec!["Authorities.ROLE_Owner".to_string(), "Authorities.Logged_IN".to_string()];
        let staff = vec!["Authorities.Logged_IN".to_string()];
        assert!(check_reader(true, &admin, "Authorities.ROLE_Owner").is_ok());
        assert_eq!(check_reader(true, &staff, "Authorities.ROLE_Owner").unwrap_err().status(), StatusCode::FORBIDDEN);
        assert!(check_reader(false, &admin, "Authorities.ROLE_Owner").is_err());
        assert!(check_reader(true, &admin, "").is_err(), "no authority named: refused");
        assert!(check_reader(true, &admin, "  ").is_err());
    }

    #[test]
    fn the_config_never_prints_its_key() {
        let c = CryptoConfig { field_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into() };
        let shown = format!("{c:?}");
        assert!(!shown.contains("AAAA") && shown.contains("set"));
    }
}
