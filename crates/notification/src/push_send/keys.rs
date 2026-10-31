//! The keys and signed tokens push needs: base64url, PEM, and the ES256 (APNs, VAPID) and RS256
//! (Google's OAuth for FCM) JWTs, all on `ring`.

use anyhow::{anyhow, Result};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, RsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING, RSA_PKCS1_SHA256};
use serde_json::Value;

pub fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// base64url or standard base64, padded or not (browsers and key tools write either).
pub fn b64_any(s: &str) -> Result<Vec<u8>> {
    let t: String = s.trim().trim_end_matches('=').chars().map(|c| match c {
        '+' => '-',
        '/' => '_',
        c => c,
    }).collect();
    URL_SAFE_NO_PAD.decode(t.as_bytes()).map_err(|e| anyhow!("not base64: {e}"))
}

/// The DER inside a PEM block. A value that is not PEM is taken as base64 of one (how `.p8`
/// keys are pasted into config), then as the DER itself in base64.
pub fn pem_der(pem: &str) -> Result<Vec<u8>> {
    let text = if pem.contains("-----BEGIN") {
        pem.to_string()
    } else {
        let raw = STANDARD.decode(pem.trim()).map_err(|e| anyhow!("key is neither PEM nor base64: {e}"))?;
        match String::from_utf8(raw.clone()) {
            Ok(t) if t.contains("-----BEGIN") => t,
            _ => return Ok(raw),
        }
    };
    let body: String = text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with("-----")).collect();
    STANDARD.decode(body.as_bytes()).map_err(|e| anyhow!("PEM body is not base64: {e}"))
}

/// An ES256 key from a PKCS#8 PEM (APNs `.p8`).
pub fn es256_pkcs8(pem: &str) -> Result<EcdsaKeyPair> {
    let der = pem_der(pem)?;
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der, &SystemRandom::new()).map_err(|e| anyhow!("not a P-256 PKCS#8 key: {e}"))
}

/// An RS256 key from a PKCS#8 PEM (a Google service account's `private_key`).
pub fn rs256_pkcs8(pem: &str) -> Result<RsaKeyPair> {
    RsaKeyPair::from_pkcs8(&pem_der(pem)?).map_err(|e| anyhow!("not an RSA PKCS#8 key: {e}"))
}

/// A VAPID key pair from its base64url halves (the raw scalar and the uncompressed point).
pub fn vapid_pair(public: &str, private: &str) -> Result<EcdsaKeyPair> {
    let (public, private) = (b64_any(public)?, b64_any(private)?);
    EcdsaKeyPair::from_private_key_and_public_key(&ECDSA_P256_SHA256_FIXED_SIGNING, &private, &public, &SystemRandom::new())
        .map_err(|e| anyhow!("VAPID keys do not make a P-256 pair: {e}"))
}

/// The public key of a VAPID pair, base64url, as `Authorization: vapid k=` and browsers take it.
pub fn vapid_public(key: &EcdsaKeyPair) -> String {
    b64url(key.public_key().as_ref())
}

fn signing_input(header: &Value, claims: &Value) -> String {
    format!("{}.{}", b64url(header.to_string().as_bytes()), b64url(claims.to_string().as_bytes()))
}

pub fn jwt_es256(key: &EcdsaKeyPair, header: &Value, claims: &Value) -> Result<String> {
    let input = signing_input(header, claims);
    let sig = key.sign(&SystemRandom::new(), input.as_bytes()).map_err(|e| anyhow!("ES256 signing failed: {e}"))?;
    Ok(format!("{input}.{}", b64url(sig.as_ref())))
}

pub fn jwt_rs256(key: &RsaKeyPair, header: &Value, claims: &Value) -> Result<String> {
    let input = signing_input(header, claims);
    let mut sig = vec![0; key.public().modulus_len()];
    key.sign(&RSA_PKCS1_SHA256, &SystemRandom::new(), input.as_bytes(), &mut sig).map_err(|e| anyhow!("RS256 signing failed: {e}"))?;
    Ok(format!("{input}.{}", b64url(&sig)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_FIXED};
    use serde_json::json;

    /// RFC 8291 appendix A's application server key pair.
    const PUBLIC: &str = "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8";
    const PRIVATE: &str = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw";

    #[test]
    fn base64_either_alphabet() {
        assert_eq!(b64_any("+/8=").unwrap(), b64_any("-_8").unwrap());
        assert_eq!(b64url(&[0xfb, 0xff]), "-_8");
        assert!(b64_any("!!").is_err());
    }

    #[test]
    fn es256_token_verifies_with_its_public_key() {
        let key = vapid_pair(PUBLIC, PRIVATE).unwrap();
        assert_eq!(vapid_public(&key), PUBLIC);
        let t = jwt_es256(&key, &json!({"typ": "JWT", "alg": "ES256"}), &json!({"aud": "https://push.example", "exp": 1})).unwrap();
        let (input, sig) = t.rsplit_once('.').unwrap();
        let verify = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, b64_any(PUBLIC).unwrap());
        verify.verify(input.as_bytes(), &b64_any(sig).unwrap()).unwrap();
        let claims: Value = serde_json::from_slice(&b64_any(input.split('.').nth(1).unwrap()).unwrap()).unwrap();
        assert_eq!(claims["aud"], "https://push.example");
        assert!(vapid_pair(PUBLIC, "AAAA").is_err());
    }

    #[test]
    fn pem_in_any_wrapping() {
        let der = [1u8, 2, 3, 250];
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n", STANDARD.encode(der));
        assert_eq!(pem_der(&pem).unwrap(), der);
        assert_eq!(pem_der(&STANDARD.encode(pem.as_bytes())).unwrap(), der, "base64 of a PEM");
        assert_eq!(pem_der(&STANDARD.encode(der)).unwrap(), der, "base64 of the DER");
        assert!(es256_pkcs8(&pem).is_err());
        assert!(rs256_pkcs8(&pem).is_err());
    }
}
