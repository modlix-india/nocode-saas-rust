//! `security-admin acme-rollover`: keeps Java's Let's Encrypt account and changes its key.
//!
//! Java's acme4j account (`letsencrypt.login`, the account URL, and `letsencrypt.key`, an RSA key
//! pair in PEM) cannot be used by instant-acme, which signs with P-256 keys only. RFC 8555's key
//! change (section 7.3.5) moves the account itself to a new P-256 key: the same account URL, so
//! the orders Java left pending stay bound to it, and the old key stops working at the authority.
//!
//! The request is the outer JWS, signed RS256 by the old key (`kid` the account URL), carrying
//! the inner JWS, signed ES256 by the new key (`jwk` the new public key), whose payload names the
//! account and the old public key. Afterwards a POST-as-GET of the account with the new key must
//! answer the account as `valid`. What it prints is instant-acme's `AccountCredentials` JSON for
//! `[letsencrypt] credentials`.

use std::io::Write;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use serde_json::{json, Value};
use sha2::Sha256;

use crate::config::LETS_ENCRYPT_DIRECTORY;

/// RFC 8555 6.1: every request names its client (Pebble refuses one without).
const USER_AGENT: &str = concat!("modlix-security/", env!("CARGO_PKG_VERSION"), " acme-rollover");

const USAGE: &str = "Usage: security-admin acme-rollover --account <account url> --key-file <old key pem> [--directory <url>]";

/// The account's old key: an RSA key in PKCS#1 (acme4j's `KeyPairUtils.writeKeyPair`) or PKCS#8
/// PEM. Errors never quote the file.
pub fn rsa_key(pem: &str) -> Result<RsaPrivateKey, String> {
    RsaPrivateKey::from_pkcs1_pem(pem.trim())
        .or_else(|_| RsaPrivateKey::from_pkcs8_pem(pem.trim()))
        .map_err(|_| "the key file is not an RSA private key in PEM".to_string())
}

fn rsa_jwk(key: &RsaPrivateKey) -> Value {
    json!({"e": B64.encode(key.e().to_bytes_be()), "kty": "RSA", "n": B64.encode(key.n().to_bytes_be())})
}

fn ec_jwk(key: &EcdsaKeyPair) -> Value {
    // An uncompressed point: 0x04, x, y.
    let point = key.public_key().as_ref();
    json!({"crv": "P-256", "kty": "EC", "x": B64.encode(&point[1..33]), "y": B64.encode(&point[33..65])})
}

fn b64_json(v: &Value) -> String {
    B64.encode(v.to_string())
}

/// A flattened JWS signed RS256 by `key`.
fn rs256(key: &RsaPrivateKey, protected: &Value, payload: &str) -> Value {
    let protected = b64_json(protected);
    let signer = SigningKey::<Sha256>::new(key.clone());
    let sig = signer.sign(format!("{protected}.{payload}").as_bytes()).to_bytes();
    json!({"protected": protected, "payload": payload, "signature": B64.encode(sig)})
}

/// A flattened JWS signed ES256 by `key`.
fn es256(key: &EcdsaKeyPair, protected: &Value, payload: &str) -> Result<Value, String> {
    let protected = b64_json(protected);
    let sig = key.sign(&SystemRandom::new(), format!("{protected}.{payload}").as_bytes()).map_err(|_| "signing with the new key failed".to_string())?;
    Ok(json!({"protected": protected, "payload": payload, "signature": B64.encode(sig.as_ref())}))
}

/// Talks to one ACME directory, keeping the last nonce.
pub(crate) struct Acme {
    http: reqwest::Client,
    dir: Value,
    nonce: Option<String>,
}

pub(crate) struct Answer {
    pub status: u16,
    /// A new account's URL (the Pebble test makes one, as acme4j did).
    #[cfg_attr(not(test), allow(dead_code))]
    pub location: Option<String>,
    pub body: Value,
}

impl Acme {
    pub(crate) async fn connect(http: reqwest::Client, directory: &str) -> Result<Self, String> {
        let rsp = http.get(directory).header("user-agent", USER_AGENT).send().await.map_err(|e| format!("the directory {directory} cannot be read: {e}"))?;
        if !rsp.status().is_success() {
            return Err(format!("the directory {directory} answered {}", rsp.status()));
        }
        let dir: Value = rsp.json().await.map_err(|_| format!("the directory {directory} is not JSON"))?;
        for k in ["newNonce", "keyChange"] {
            if dir.get(k).and_then(Value::as_str).is_none() {
                return Err(format!("the directory {directory} names no {k}"));
            }
        }
        Ok(Self { http, dir, nonce: None })
    }

    pub(crate) fn url(&self, name: &str) -> String {
        self.dir.get(name).and_then(Value::as_str).unwrap_or_default().to_string()
    }

    async fn nonce(&mut self) -> Result<String, String> {
        if let Some(n) = self.nonce.take() {
            return Ok(n);
        }
        let rsp = self.http.head(self.url("newNonce")).header("user-agent", USER_AGENT).send().await.map_err(|e| format!("no nonce: {e}"))?;
        replay_nonce(&rsp).ok_or_else(|| "the authority sent no nonce".to_string())
    }

    /// POSTs the JWS `sign(nonce)` builds, again with a fresh nonce after a `badNonce` (twice at
    /// most, as the RFC allows).
    pub(crate) async fn post(&mut self, url: &str, sign: impl Fn(&str) -> Result<Value, String>) -> Result<Answer, String> {
        for attempt in 0..3 {
            let nonce = self.nonce().await?;
            let rsp = self
                .http
                .post(url)
                .header("content-type", "application/jose+json")
                .header("user-agent", USER_AGENT)
                .body(sign(&nonce)?.to_string())
                .send()
                .await
                .map_err(|e| format!("{url}: {e}"))?;
            self.nonce = replay_nonce(&rsp);
            let status = rsp.status().as_u16();
            let location = rsp.headers().get("location").and_then(|v| v.to_str().ok()).map(str::to_string);
            let body: Value = rsp.json().await.unwrap_or(Value::Null);
            if status >= 400 && body["type"] == "urn:ietf:params:acme:error:badNonce" && attempt < 2 {
                continue;
            }
            return Ok(Answer { status, location, body });
        }
        unreachable!()
    }
}

fn replay_nonce(rsp: &reqwest::Response) -> Option<String> {
    rsp.headers().get("replay-nonce").and_then(|v| v.to_str().ok()).map(str::to_string)
}

fn problem(a: &Answer) -> String {
    let detail = a.body["detail"].as_str().or_else(|| a.body["type"].as_str()).unwrap_or("no detail");
    format!("{} ({detail})", a.status)
}

fn host(url: &str) -> Option<String> {
    reqwest::Url::parse(url).ok().and_then(|u| u.host_str().map(|h| format!("{h}:{}", u.port_or_known_default().unwrap_or(0))))
}

/// Moves the account at `account` from `old` to a new P-256 key and answers its instant-acme
/// credentials JSON.
pub async fn rollover(http: reqwest::Client, directory: &str, account: &str, old: &RsaPrivateKey) -> Result<String, String> {
    if host(directory).is_none() || host(directory) != host(account) {
        return Err("the account URL is not on the directory's server".into());
    }
    let mut acme = Acme::connect(http, directory).await?;
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).map_err(|_| "no new key".to_string())?;
    let new = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).map_err(|_| "no new key".to_string())?;
    let key_change = acme.url("keyChange");

    let inner = es256(
        &new,
        &json!({"alg": "ES256", "jwk": ec_jwk(&new), "url": key_change}),
        &b64_json(&json!({"account": account, "oldKey": rsa_jwk(old)})),
    )?;
    let inner = b64_json(&inner);
    let changed = acme
        .post(&key_change, |nonce| Ok(rs256(old, &json!({"alg": "RS256", "kid": account, "nonce": nonce, "url": key_change}), &inner)))
        .await?;
    if changed.status != 200 {
        return Err(format!("the key change was refused: {}", problem(&changed)));
    }

    // The account answers to the new key.
    let fetched = acme.post(account, |nonce| es256(&new, &json!({"alg": "ES256", "kid": account, "nonce": nonce, "url": account}), "")).await?;
    if fetched.status != 200 || fetched.body["status"] != "valid" {
        return Err(format!("the key changed, but the account does not answer to the new key: {}", problem(&fetched)));
    }

    let creds = json!({"id": account, "key_pkcs8": B64.encode(pkcs8.as_ref()), "directory": directory});
    let _: instant_acme::AccountCredentials = serde_json::from_value(creds.clone()).map_err(|_| "the credentials do not read back".to_string())?;
    Ok(creds.to_string())
}

/// `security-admin acme-rollover --account <url> --key-file <pem> [--directory <url>]`: the new
/// credentials JSON (a secret) on stdout; 0, 1 when it fails, 2 on bad arguments.
pub async fn rollover_command(args: &[String], out: &mut dyn Write, err: &mut dyn Write, http: reqwest::Client) -> i32 {
    let (mut account, mut key_file, mut directory) = (None, None, LETS_ENCRYPT_DIRECTORY.to_string());
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match (a.as_str(), it.next()) {
            ("--account", Some(v)) => account = Some(v.clone()),
            ("--key-file", Some(v)) => key_file = Some(v.clone()),
            ("--directory", Some(v)) => directory = v.clone(),
            _ => {
                let _ = writeln!(err, "{USAGE}");
                return 2;
            }
        }
    }
    let (Some(account), Some(key_file)) = (account, key_file) else {
        let _ = writeln!(err, "{USAGE}");
        return 2;
    };
    let old = match std::fs::read_to_string(&key_file).map_err(|_| format!("{key_file} cannot be read")).and_then(|pem| rsa_key(&pem)) {
        Ok(k) => k,
        Err(e) => {
            let _ = writeln!(err, "security-admin acme-rollover: {e}");
            return 2;
        }
    };
    match rollover(http, &directory, &account, &old).await {
        Ok(json) => {
            let _ = writeln!(out, "{json}");
            let _ = writeln!(
                err,
                "The account {account} now has a new key; the old one no longer works there. Its credentials are on stdout and hold \
                 the new private key: put them in the private configuration as [letsencrypt] credentials, nowhere else."
            );
            0
        }
        Err(e) => {
            let _ = writeln!(err, "security-admin acme-rollover: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use instant_acme::{Account, Identifier, NewOrder};

    #[test]
    fn keys_and_signatures() {
        let rng = SystemRandom::new();
        let old = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let jwk = rsa_jwk(&old);
        assert_eq!((jwk["kty"].as_str(), jwk["e"].as_str()), (Some("RSA"), Some("AQAB")));
        let jws = rs256(&old, &json!({"alg": "RS256"}), "e30");
        let sig = B64.decode(jws["signature"].as_str().unwrap()).unwrap();
        use rsa::signature::Verifier;
        let vk = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(old.to_public_key());
        let msg = format!("{}.e30", jws["protected"].as_str().unwrap());
        vk.verify(msg.as_bytes(), &rsa::pkcs1v15::Signature::try_from(sig.as_slice()).unwrap()).unwrap();

        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let new = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
        let jwk = ec_jwk(&new);
        assert_eq!(B64.decode(jwk["x"].as_str().unwrap()).unwrap().len(), 32);
        let jws = es256(&new, &json!({"alg": "ES256"}), "").unwrap();
        assert_eq!(B64.decode(jws["signature"].as_str().unwrap()).unwrap().len(), 64);

        // acme4j wrote PKCS#1; PKCS#8 reads too; anything else is refused without quoting it.
        use rsa::pkcs1::EncodeRsaPrivateKey;
        use rsa::pkcs8::EncodePrivateKey;
        let pkcs1 = old.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF).unwrap();
        assert!(rsa_key(&pkcs1).is_ok());
        assert!(rsa_key(&old.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap()).is_ok());
        assert_eq!(rsa_key("-----BEGIN NOTHING-----").unwrap_err(), "the key file is not an RSA private key in PEM");
        assert_eq!(host("https://a.test/dir"), host("https://a.test:443/acct/1"));
        assert_ne!(host("https://a.test/dir"), host("https://b.test/acct/1"));
    }

    #[tokio::test]
    async fn the_command_checks_its_arguments() {
        let http = reqwest::Client::new();
        let run = |args: &[&str]| {
            let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            let http = http.clone();
            async move {
                let (mut out, mut err) = (Vec::new(), Vec::new());
                let code = rollover_command(&args, &mut out, &mut err, http).await;
                (code, String::from_utf8(out).unwrap(), String::from_utf8(err).unwrap())
            }
        };
        assert_eq!(run(&[]).await.0, 2);
        assert_eq!(run(&["--account", "https://a.test/acct/1"]).await.0, 2);
        assert_eq!(run(&["--account"]).await.0, 2);
        let (code, out, err) = run(&["--account", "https://a.test/acct/1", "--key-file", "/nonexistent/zz.pem"]).await;
        assert_eq!((code, out.as_str()), (2, ""));
        assert!(err.contains("cannot be read"), "{err}");
        let dir = std::env::temp_dir().join(format!("zz-rollover-{}.pem", std::process::id()));
        std::fs::write(&dir, "not a key").unwrap();
        let (code, _, err) = run(&["--account", "https://a.test/acct/1", "--key-file", dir.to_str().unwrap()]).await;
        let _ = std::fs::remove_file(&dir);
        assert_eq!(code, 2);
        assert!(!err.contains("not a key"), "never quotes the file");
        let old = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let e = rollover(http.clone(), "https://ca.test/dir", "https://elsewhere.test/acct/1", &old).await.unwrap_err();
        assert_eq!(e, "the account URL is not on the directory's server");
    }

    /// An acme4j-style RSA account on Pebble moved to a new key, then used by instant-acme
    /// (gated like `acme::tests::issues_a_certificate_from_pebble`: `SECURITY_ACME_PEBBLE=1`).
    #[tokio::test]
    async fn rolls_an_rsa_account_over_on_pebble() {
        if std::env::var("SECURITY_ACME_PEBBLE").is_err() {
            eprintln!("skipped: SECURITY_ACME_PEBBLE not set");
            return;
        }
        let directory = std::env::var("SECURITY_ACME_PEBBLE_DIRECTORY").unwrap_or_else(|_| "https://localhost:14000/dir".into());
        let http = reqwest::Client::builder().danger_accept_invalid_certs(true).build().unwrap();

        // The account as Java has it: an RSA key and the account URL.
        let old = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let mut acme = Acme::connect(http.clone(), &directory).await.unwrap();
        let new_account = acme.url("newAccount");
        let payload = b64_json(&json!({"termsOfServiceAgreed": true, "contact": ["mailto:zz-rollover@example.com"]}));
        let made = acme
            .post(&new_account, |nonce| Ok(rs256(&old, &json!({"alg": "RS256", "jwk": rsa_jwk(&old), "nonce": nonce, "url": new_account}), &payload)))
            .await
            .unwrap();
        assert_eq!(made.status, 201, "{}", made.body);
        let account = made.location.unwrap();

        let pem = {
            use rsa::pkcs1::EncodeRsaPrivateKey;
            old.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF).unwrap().to_string()
        };
        let file = std::env::temp_dir().join(format!("zz-rollover-pebble-{}.pem", std::process::id()));
        std::fs::write(&file, pem).unwrap();
        let args: Vec<String> =
            ["--account", &account, "--key-file", file.to_str().unwrap(), "--directory", &directory].iter().map(|s| s.to_string()).collect();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = rollover_command(&args, &mut out, &mut err, http.clone()).await;
        let _ = std::fs::remove_file(&file);
        assert_eq!(code, 0, "{}", String::from_utf8_lossy(&err));
        let creds = super::super::acme::credentials(&String::from_utf8(out).unwrap(), LETS_ENCRYPT_DIRECTORY).unwrap();
        assert_eq!((creds["id"].as_str(), creds["directory"].as_str()), (Some(account.as_str()), Some(directory.as_str())));

        // The old key no longer works for the account.
        let stale = acme.post(&account, |nonce| Ok(rs256(&old, &json!({"alg": "RS256", "kid": account, "nonce": nonce, "url": account}), ""))).await.unwrap();
        assert!(stale.status >= 400, "the old key still works: {}", stale.status);

        // instant-acme runs the same account with the new credentials.
        let acct = Account::builder_with_http(Box::new(super::super::acme::ReqwestHttp(http)))
            .from_credentials(serde_json::from_value(creds).unwrap())
            .await
            .unwrap();
        assert_eq!(acct.id(), account);
        let ids = [Identifier::Dns("zz-rollover.example.test".into())];
        assert!(acct.new_order(&NewOrder::new(&ids)).await.is_ok());
    }
}
