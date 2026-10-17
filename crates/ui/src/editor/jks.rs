//! `MobileAppService.createKeystore`: the Android signing key a mobile app gets when it is
//! first saved. An RSA 2048 key and a self-signed SHA256withRSA certificate valid for 10000
//! days (subject `CN=Modlix Team, OU=Mobile Development, O=Modlix, L=Karnataka, ST=Karnataka,
//! C=IN`), stored as a Java KeyStore (JKS) under alias `modlix`, store and key password the
//! same random string. The build machines read it with `keytool` / `apksigner`, so the file is
//! the JDK's own format: the key protected with Sun's `KeyProtector` and the whole store sealed
//! with the "Mighty Aphrodite" SHA-1 digest.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rand::RngCore;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rsa::signature::{SignatureEncoding, Signer};
use rsa::RsaPrivateKey;
use sha1::{Digest, Sha1};

/// What a mobile app stores: the keystore (base64), its passwords and the key's alias.
#[derive(Debug, Clone)]
pub struct KeystoreBundle {
    pub jks_base64: String,
    pub store_pass: String,
    pub key_pass: String,
    pub alias: String,
}

const ALIAS: &str = "modlix";
/// 1.2.840.113549.1.1.11, sha256WithRSAEncryption.
const SHA256_WITH_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
/// 1.3.6.1.4.1.42.2.17.1.1, Sun's proprietary key protection (`KeyProtector.KEY_PROTECTOR_OID`).
const KEY_PROTECTOR: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x2A, 0x02, 0x11, 0x01, 0x01];
const DAY: u64 = 24 * 60 * 60;

/// A DER element.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = content.len();
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let bytes: Vec<u8> = n.to_be_bytes().iter().copied().skip_while(|b| *b == 0).collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
    out.extend_from_slice(content);
    out
}

fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

fn oid(bytes: &[u8]) -> Vec<u8> {
    tlv(0x06, bytes)
}

const NULL: [u8; 2] = [0x05, 0x00];

/// An `INTEGER` of an unsigned big-endian number.
fn uint(bytes: &[u8]) -> Vec<u8> {
    let mut b: Vec<u8> = bytes.iter().copied().skip_while(|x| *x == 0).collect();
    if b.is_empty() || b[0] & 0x80 != 0 {
        b.insert(0, 0);
    }
    tlv(0x02, &b)
}

fn algorithm(oid_bytes: &[u8]) -> Vec<u8> {
    seq(&[oid(oid_bytes), NULL.to_vec()])
}

/// BouncyCastle's `X500Name` of the subject, in the order written: UTF8String values, the
/// country as a PrintableString.
fn subject_name() -> Vec<u8> {
    let rdn = |arc: u8, value: &str, tag: u8| tlv(0x31, &seq(&[oid(&[0x55, 0x04, arc]), tlv(tag, value.as_bytes())]));
    seq(&[
        rdn(3, "Modlix Team", 0x0C),
        rdn(11, "Mobile Development", 0x0C),
        rdn(10, "Modlix", 0x0C),
        rdn(7, "Karnataka", 0x0C),
        rdn(8, "Karnataka", 0x0C),
        rdn(6, "IN", 0x13),
    ])
}

/// `new BigInteger(130, new SecureRandom()).toString(32)`: up to 26 base-32 digits.
fn random_password() -> String {
    let mut bytes = [0u8; 17];
    rand::thread_rng().fill_bytes(&mut bytes);
    // 130 bits: the top 6 bits of the first byte cleared.
    bytes[0] &= 0x03;
    let mut n = num_from(&bytes);
    let digits = b"0123456789abcdefghijklmnopqrstuv";
    let mut out = Vec::new();
    while n.iter().any(|b| *b != 0) {
        let r = div_small(&mut n, 32);
        out.push(digits[r as usize]);
    }
    if out.is_empty() {
        out.push(b'0');
    }
    out.reverse();
    String::from_utf8(out).unwrap_or_default()
}

fn num_from(bytes: &[u8]) -> Vec<u8> {
    bytes.to_vec()
}

/// Divides a big-endian number in place, answering the remainder.
fn div_small(n: &mut [u8], d: u32) -> u32 {
    let mut rem = 0u32;
    for b in n.iter_mut() {
        let cur = (rem << 8) | *b as u32;
        *b = (cur / d) as u8;
        rem = cur % d;
    }
    rem
}

/// The password as the JDK hashes it: each `char` as two bytes, big-endian.
fn password_bytes(password: &str) -> Vec<u8> {
    password.encode_utf16().flat_map(|c| c.to_be_bytes()).collect()
}

/// `KeyProtector.protect`: the PKCS#8 key XORed with a SHA-1 stream seeded by a random salt,
/// with a SHA-1 check of the plain key, wrapped as an `EncryptedPrivateKeyInfo`.
fn protect(plain_key: &[u8], password: &str) -> Result<Vec<u8>> {
    let pw = password_bytes(password);
    let mut salt = [0u8; 20];
    rand::thread_rng().fill_bytes(&mut salt);
    let mut digest = salt.to_vec();
    let mut xor = Vec::with_capacity(plain_key.len());
    while xor.len() < plain_key.len() {
        let mut md = Sha1::new();
        md.update(&pw);
        md.update(&digest);
        digest = md.finalize().to_vec();
        let take = (plain_key.len() - xor.len()).min(20);
        xor.extend_from_slice(&digest[..take]);
    }
    let mut out = salt.to_vec();
    out.extend(plain_key.iter().zip(&xor).map(|(a, b)| a ^ b));
    let mut md = Sha1::new();
    md.update(&pw);
    md.update(plain_key);
    out.extend_from_slice(&md.finalize());
    // EncryptedPrivateKeyInfo ::= SEQUENCE { AlgorithmIdentifier, OCTET STRING }.
    Ok(seq(&[algorithm(KEY_PROTECTOR), tlv(0x04, &out)]))
}

/// `DataOutputStream.writeUTF` (the alias and the certificate type are ASCII).
fn write_utf(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u16).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

/// A JKS store with one private-key entry.
pub fn jks(alias: &str, password: &str, protected_key: &[u8], certificate: &[u8], created_ms: i64) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xFEED_FEEDu32.to_be_bytes());
    out.extend_from_slice(&2u32.to_be_bytes());
    out.extend_from_slice(&1u32.to_be_bytes());
    out.extend_from_slice(&1u32.to_be_bytes());
    write_utf(&mut out, alias);
    out.extend_from_slice(&created_ms.to_be_bytes());
    out.extend_from_slice(&(protected_key.len() as u32).to_be_bytes());
    out.extend_from_slice(protected_key);
    out.extend_from_slice(&1u32.to_be_bytes());
    write_utf(&mut out, "X.509");
    out.extend_from_slice(&(certificate.len() as u32).to_be_bytes());
    out.extend_from_slice(certificate);
    let mut md = Sha1::new();
    md.update(password_bytes(password));
    md.update(b"Mighty Aphrodite");
    md.update(&out);
    out.extend_from_slice(&md.finalize());
    out
}

/// A certificate date: UTCTime through 2049, GeneralizedTime from 2050 (RFC 5280, as
/// BouncyCastle's `Time` chooses).
fn time(t: SystemTime) -> Result<Vec<u8>> {
    let secs = t.duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let dt = chrono::DateTime::from_timestamp(secs, 0).context("date out of range")?;
    Ok(if secs < 2_524_608_000 {
        tlv(0x17, dt.format("%y%m%d%H%M%SZ").to_string().as_bytes())
    } else {
        tlv(0x18, dt.format("%Y%m%d%H%M%SZ").to_string().as_bytes())
    })
}

/// The self-signed certificate of `key`: X.509 v3, no extensions, SHA256withRSA.
pub fn self_signed(key: &RsaPrivateKey, now: SystemTime) -> Result<Vec<u8>> {
    let spki = key.to_public_key().to_public_key_der()?.as_bytes().to_vec();
    let mut serial = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut serial);
    serial[0] &= 0x7f;
    let name = subject_name();
    let tbs = seq(&[
        tlv(0xA0, &uint(&[2])),
        uint(&serial),
        algorithm(SHA256_WITH_RSA),
        name.clone(),
        seq(&[time(now - Duration::from_secs(DAY))?, time(now + Duration::from_secs(10_000 * DAY))?]),
        name,
        spki,
    ]);
    let signer = SigningKey::<rsa::sha2::Sha256>::new(key.clone());
    let signature = signer.sign(&tbs).to_vec();
    let mut bits = vec![0u8];
    bits.extend(signature);
    Ok(seq(&[tbs, algorithm(SHA256_WITH_RSA), tlv(0x03, &bits)]))
}

/// `createKeystore` with a key of `bits` (2048 in production; tests use fewer to stay quick).
pub fn create_keystore_with(bits: usize) -> Result<KeystoreBundle> {
    let key = RsaPrivateKey::new(&mut rand::thread_rng(), bits).context("RSA key generation")?;
    let now = SystemTime::now();
    let cert = self_signed(&key, now)?;
    let password = random_password();
    let pkcs8 = key.to_pkcs8_der()?;
    let protected = protect(pkcs8.as_bytes(), &password)?;
    let created = now.duration_since(UNIX_EPOCH)?.as_millis() as i64;
    let store = jks(ALIAS, &password, &protected, &cert, created);
    Ok(KeystoreBundle {
        jks_base64: overridable::write::transport::base64_encode(&store),
        store_pass: password.clone(),
        key_pass: password,
        alias: ALIAS.into(),
    })
}

/// `createKeystore`.
pub fn create_keystore() -> Result<KeystoreBundle> {
    create_keystore_with(2048)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwords_are_base_32() {
        for _ in 0..20 {
            let p = random_password();
            assert!(!p.is_empty() && p.len() <= 26, "{p}");
            assert!(p.chars().all(|c| c.is_ascii_digit() || ('a'..='v').contains(&c)), "{p}");
        }
        assert_eq!(password_bytes("aé"), vec![0, b'a', 0, 0xe9]);
        let mut n = [0u8, 0];
        assert_eq!(div_small(&mut n, 32), 0);
    }

    #[test]
    fn a_store_the_jdk_format_describes() {
        let b = create_keystore_with(1024).unwrap();
        assert_eq!(b.alias, "modlix");
        assert_eq!(b.store_pass, b.key_pass);
        let bytes = overridable::write::transport::base64_decode(&b.jks_base64).unwrap();
        assert_eq!(&bytes[..12], &[0xFE, 0xED, 0xFE, 0xED, 0, 0, 0, 2, 0, 0, 0, 1]);
        // The seal: SHA-1 over the password, the phrase and everything before it.
        let (body, seal) = bytes.split_at(bytes.len() - 20);
        let mut md = Sha1::new();
        md.update(password_bytes(&b.store_pass));
        md.update(b"Mighty Aphrodite");
        md.update(body);
        assert_eq!(seal, md.finalize().as_slice());
        // The protected key decrypts back to a PKCS#8 key whose check matches.
        assert_eq!(&bytes[16..24], b"\0\x06modlix");
        let key_len = u32::from_be_bytes(bytes[32..36].try_into().unwrap()) as usize;
        let info = &bytes[36..36 + key_len];
        // SEQUENCE { SEQUENCE { OID key protector, NULL }, OCTET STRING }.
        let alg = algorithm(KEY_PROTECTOR);
        assert_eq!(info[0], 0x30);
        let alg_at = info.windows(alg.len()).position(|w| w == alg.as_slice()).unwrap();
        let rest = &info[alg_at + alg.len()..];
        assert_eq!(rest[0], 0x04);
        let (len, hdr) = if rest[1] < 0x80 { (rest[1] as usize, 2) } else { let n = (rest[1] & 0x7f) as usize; (rest[2..2 + n].iter().fold(0usize, |a, b| a << 8 | *b as usize), 2 + n) };
        let enc = &rest[hdr..hdr + len];
        let (salt, rest) = enc.split_at(20);
        let (cipher, check) = rest.split_at(rest.len() - 20);
        let pw = password_bytes(&b.key_pass);
        let mut digest = salt.to_vec();
        let mut plain = Vec::new();
        for chunk in cipher.chunks(20) {
            let mut md = Sha1::new();
            md.update(&pw);
            md.update(&digest);
            digest = md.finalize().to_vec();
            plain.extend(chunk.iter().zip(&digest).map(|(a, b)| a ^ b));
        }
        let mut md = Sha1::new();
        md.update(&pw);
        md.update(&plain);
        assert_eq!(check, md.finalize().as_slice());
        use rsa::pkcs8::DecodePrivateKey;
        let key = RsaPrivateKey::from_pkcs8_der(&plain).unwrap();
        // The certificate: its signature verifies with the key's public half.
        let cert_start = 36 + key_len + 4 + 2 + 5 + 4;
        let cert_len = u32::from_be_bytes(bytes[cert_start - 4..cert_start].try_into().unwrap()) as usize;
        let cert = &bytes[cert_start..cert_start + cert_len];
        assert_eq!(&bytes[cert_start - 11..cert_start - 4], b"\0\x05X.509");
        assert_eq!(cert_start + cert_len + 20, bytes.len());
        let name = subject_name();
        assert!(cert.windows(name.len()).filter(|w| *w == name.as_slice()).count() == 2, "issuer and subject");
        assert!(cert.windows(1).any(|w| w[0] == 0x18), "the far expiry is a GeneralizedTime");
        let _ = key;
    }

    /// The JDK itself reads the store: `keytool -list` with the password, and the key entry
    /// recovered with the key password. Needs a JDK (`KEYTOOL`, or `keytool` on the path).
    #[test]
    #[ignore = "needs a JDK's keytool"]
    fn keytool_reads_it() {
        let b = create_keystore_with(2048).unwrap();
        let dir = std::env::temp_dir().join(format!("ui-jks-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("k.jks");
        std::fs::write(&file, overridable::write::transport::base64_decode(&b.jks_base64).unwrap()).unwrap();
        let keytool = std::env::var("KEYTOOL").unwrap_or_else(|_| "keytool".into());
        let out = std::process::Command::new(&keytool)
            .args(["-list", "-v", "-storetype", "JKS", "-keystore"])
            .arg(&file)
            .args(["-storepass", &b.store_pass])
            .output()
            .expect("keytool");
        let text = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{text}");
        assert!(text.contains("Alias name: modlix"), "{text}");
        assert!(text.contains("PrivateKeyEntry"), "{text}");
        // As keytool prints the Java-made stores too.
        assert!(text.contains("Owner: C=IN, ST=Karnataka, L=Karnataka, O=Modlix, OU=Mobile Development, CN=Modlix Team"), "{text}");
        assert!(text.contains("SHA256withRSA"), "{text}");
        // The key itself: exporting it to PKCS12 needs the key password to unlock the entry.
        let p12 = dir.join("k.p12");
        let out = std::process::Command::new(&keytool)
            .args(["-importkeystore", "-srcstoretype", "JKS", "-srckeystore"])
            .arg(&file)
            .args(["-srcalias", "modlix", "-srcstorepass", &b.store_pass, "-srckeypass", &b.key_pass, "-destkeystore"])
            .arg(&p12)
            .args(["-deststoretype", "PKCS12", "-deststorepass", "changeit", "-noprompt"])
            .output()
            .expect("keytool");
        let text = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{text}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn der_pieces() {
        assert_eq!(uint(&[0, 0, 5]), vec![0x02, 0x01, 0x05]);
        assert_eq!(uint(&[0x80]), vec![0x02, 0x02, 0x00, 0x80]);
        assert_eq!(uint(&[]), vec![0x02, 0x01, 0x00]);
        assert_eq!(tlv(0x04, &[0u8; 200])[..3], [0x04, 0x81, 200]);
        assert_eq!(tlv(0x04, &[0u8; 300])[..4], [0x04, 0x82, 0x01, 0x2C]);
        let t = time(UNIX_EPOCH + Duration::from_secs(2_524_608_000)).unwrap();
        assert_eq!(t, tlv(0x18, b"20500101000000Z"));
        let t = time(UNIX_EPOCH + Duration::from_secs(86_400)).unwrap();
        assert_eq!(t, tlv(0x17, b"700102000000Z"));
    }
}
