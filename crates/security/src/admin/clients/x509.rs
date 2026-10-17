//! Just enough DER to check an uploaded certificate and key the way
//! `SSLCertificateService.validateCrtAndKey` does: the certificate's expiry, and whether the key
//! is the RSA key of the certificate's public key (Java encrypts with one and decrypts with the
//! other; two RSA keys agree exactly when their modulus and public exponent do).

use base64::Engine;
use chrono::{NaiveDate, NaiveDateTime};

const RSA_OID: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];

/// A PEM block's label and bytes; text without one is taken as DER only when it is not text.
pub fn pem_blocks(text: &str) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("-----BEGIN ") {
        let after = &rest[start + 11..];
        let Some(label_end) = after.find("-----") else { break };
        let label = after[..label_end].to_string();
        let body_start = &after[label_end + 5..];
        let end_marker = format!("-----END {label}-----");
        let Some(end) = body_start.find(&end_marker) else { break };
        let b64: String = body_start[..end].lines().filter(|l| !l.contains(':')).collect::<Vec<_>>().join("").split_whitespace().collect();
        if let Ok(der) = base64::engine::general_purpose::STANDARD.decode(b64) {
            out.push((label, der));
        }
        rest = &body_start[end + end_marker.len()..];
    }
    out
}

/// One TLV: (tag, content, rest).
fn tlv(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = data.split_first()?;
    let (&first, mut rest) = rest.split_first()?;
    let len = if first < 0x80 {
        first as usize
    } else {
        let n = (first & 0x7F) as usize;
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let mut l = 0usize;
        for &b in &rest[..n] {
            l = (l << 8) | b as usize;
        }
        rest = &rest[n..];
        l
    };
    if rest.len() < len {
        return None;
    }
    Some((tag, &rest[..len], &rest[len..]))
}

/// The elements of a SEQUENCE's content.
fn elements(mut content: &[u8]) -> Option<Vec<(u8, &[u8])>> {
    let mut out = Vec::new();
    while !content.is_empty() {
        let (t, c, r) = tlv(content)?;
        out.push((t, c));
        content = r;
    }
    Some(out)
}

/// An INTEGER without its sign-padding zeros.
fn int(c: &[u8]) -> Vec<u8> {
    let mut i = 0;
    while i + 1 < c.len() && c[i] == 0 {
        i += 1;
    }
    c[i..].to_vec()
}

/// A public or private key's algorithm and, for RSA, (modulus, exponent).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyInfo {
    Rsa { n: Vec<u8>, e: Vec<u8> },
    Other,
}

/// What `validateCrtAndKey` reads of a certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertInfo {
    pub not_after: NaiveDateTime,
    pub key: KeyInfo,
}

fn time(tag: u8, c: &[u8]) -> Option<NaiveDateTime> {
    let s = std::str::from_utf8(c).ok()?.trim_end_matches('Z');
    let (year, rest) = match tag {
        0x17 => {
            let yy: i32 = s.get(..2)?.parse().ok()?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, s.get(2..)?)
        }
        0x18 => (s.get(..4)?.parse().ok()?, s.get(4..)?),
        _ => return None,
    };
    let num = |r: std::ops::Range<usize>| -> Option<u32> { rest.get(r)?.parse().ok() };
    NaiveDate::from_ymd_opt(year, num(0..2)?, num(2..4)?)?.and_hms_opt(num(4..6)?, num(6..8)?, num(8..10).unwrap_or(0))
}

fn spki(c: &[u8]) -> Option<KeyInfo> {
    let parts = elements(c)?;
    let (_, alg) = parts.first()?;
    let (_, bits) = parts.get(1)?;
    let alg_parts = elements(alg)?;
    if alg_parts.first()?.1 != RSA_OID {
        return Some(KeyInfo::Other);
    }
    let (_, rsa, _) = tlv(bits.get(1..)?)?;
    let ne = elements(rsa)?;
    Some(KeyInfo::Rsa { n: int(ne.first()?.1), e: int(ne.get(1)?.1) })
}

/// `CertificateFactory.getInstance("X.509").generateCertificate`: `None` when it is not one.
pub fn certificate(text: &str) -> Option<CertInfo> {
    let der = pem_blocks(text).into_iter().find(|(l, _)| l == "CERTIFICATE").map(|(_, d)| d)?;
    let (_, cert, _) = tlv(&der)?;
    let (_, tbs, _) = tlv(cert)?;
    let mut fields = elements(tbs)?;
    if fields.first().map(|f| f.0) == Some(0xA0) {
        fields.remove(0);
    }
    // serial, signature, issuer, validity, subject, subjectPublicKeyInfo
    let validity = elements(fields.get(3)?.1)?;
    let (tag, after) = *validity.get(1)?;
    Some(CertInfo { not_after: time(tag, after)?, key: spki(fields.get(5)?.1)? })
}

/// Why a key could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyProblem {
    /// No PEM object at all (`PEMParser.readObject()` is null).
    Missing,
    /// A PEM object that is not a key bouncy castle converts.
    Unreadable,
}

/// `parsePrivateKey(key)`: PKCS#1 (`RSA PRIVATE KEY`), PKCS#8 (`PRIVATE KEY`) or another key type.
pub fn private_key(text: &str) -> Result<KeyInfo, KeyProblem> {
    let blocks = pem_blocks(text);
    let Some((label, der)) = blocks.first() else { return Err(KeyProblem::Missing) };
    let rsa_private = |der: &[u8]| -> Option<KeyInfo> {
        let (_, c, _) = tlv(der)?;
        let parts = elements(c)?;
        Some(KeyInfo::Rsa { n: int(parts.get(1)?.1), e: int(parts.get(2)?.1) })
    };
    match label.as_str() {
        "RSA PRIVATE KEY" => rsa_private(der).ok_or(KeyProblem::Unreadable),
        "PRIVATE KEY" => {
            let (_, c, _) = tlv(der).ok_or(KeyProblem::Unreadable)?;
            let parts = elements(c).ok_or(KeyProblem::Unreadable)?;
            let alg = elements(parts.get(1).ok_or(KeyProblem::Unreadable)?.1).ok_or(KeyProblem::Unreadable)?;
            if alg.first().map(|a| a.1) != Some(RSA_OID) {
                return Ok(KeyInfo::Other);
            }
            rsa_private(parts.get(2).ok_or(KeyProblem::Unreadable)?.1).ok_or(KeyProblem::Unreadable)
        }
        "EC PRIVATE KEY" | "DSA PRIVATE KEY" => Ok(KeyInfo::Other),
        _ => Err(KeyProblem::Unreadable),
    }
}

/// Whether the key decrypts what the certificate's key encrypts.
pub fn matches(cert: &KeyInfo, key: &KeyInfo) -> bool {
    matches!((cert, key), (KeyInfo::Rsa { n: n1, e: e1 }, KeyInfo::Rsa { n: n2, e: e2 }) if n1 == n2 && e1 == e2)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    fn b64(der: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(der)
    }

    fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
        der(0x30, &parts.concat())
    }

    pub fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if content.len() < 0x80 {
            out.push(content.len() as u8);
        } else if content.len() < 0x100 {
            out.extend([0x81, content.len() as u8]);
        } else {
            out.extend([0x82, (content.len() >> 8) as u8, content.len() as u8]);
        }
        out.extend_from_slice(content);
        out
    }

    /// A certificate-shaped DER: enough for [`certificate`].
    pub fn fake_cert(not_after: &str, n: &[u8], rsa: bool) -> String {
        let alg = seq(&[der(0x06, if rsa { RSA_OID } else { &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01] })]);
        let rsa_key = seq(&[der(0x02, n), der(0x02, &[1, 0, 1])]);
        let mut bits = vec![0u8];
        bits.extend(rsa_key);
        let spki = seq(&[alg.clone(), der(0x03, &bits)]);
        let validity = seq(&[der(0x17, b"250101000000Z"), der(if not_after.len() == 13 { 0x17 } else { 0x18 }, not_after.as_bytes())]);
        let tbs = seq(&[der(0xA0, &der(0x02, &[2])), der(0x02, &[7]), alg.clone(), seq(&[]), validity, seq(&[]), spki]);
        let cert = seq(&[tbs, alg, der(0x03, &[0])]);
        format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", b64(&cert))
    }

    pub fn fake_pkcs1(n: &[u8]) -> String {
        let key = seq(&[der(0x02, &[0]), der(0x02, n), der(0x02, &[1, 0, 1]), der(0x02, &[9])]);
        format!("-----BEGIN RSA PRIVATE KEY-----\n{}\n-----END RSA PRIVATE KEY-----", b64(&key))
    }

    pub fn fake_pkcs8(n: &[u8], rsa: bool) -> String {
        let inner = seq(&[der(0x02, &[0]), der(0x02, n), der(0x02, &[1, 0, 1])]);
        let alg = seq(&[der(0x06, if rsa { RSA_OID } else { &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01] })]);
        let key = seq(&[der(0x02, &[0]), alg, der(0x04, &inner)]);
        format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----", b64(&key))
    }

    #[test]
    fn reads_certificates_and_keys() {
        let n = [0x00, 0xC3, 0x11, 0x22];
        let c = certificate(&fake_cert("491231235959Z", &n, true)).unwrap();
        assert_eq!(c.not_after.to_string(), "2049-12-31 23:59:59");
        assert_eq!(c.key, KeyInfo::Rsa { n: vec![0xC3, 0x11, 0x22], e: vec![1, 0, 1] });
        let g = certificate(&fake_cert("20991231000000Z", &n, true)).unwrap();
        assert_eq!(g.not_after.date().to_string(), "2099-12-31");
        assert_eq!(certificate(&fake_cert("991231000000Z", &n, false)).unwrap().key, KeyInfo::Other);
        assert!(certificate("not a certificate").is_none());
        assert!(certificate("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----").is_none());

        let k1 = private_key(&fake_pkcs1(&n)).unwrap();
        assert!(matches(&c.key, &k1));
        let k8 = private_key(&fake_pkcs8(&n, true)).unwrap();
        assert!(matches(&c.key, &k8));
        assert_eq!(private_key(&fake_pkcs8(&n, false)).unwrap(), KeyInfo::Other);
        assert!(!matches(&c.key, &private_key(&fake_pkcs1(&[0x01, 0x02])).unwrap()));
        assert!(!matches(&KeyInfo::Other, &k1));
        assert_eq!(private_key("garbage"), Err(KeyProblem::Missing));
        assert_eq!(private_key("-----BEGIN FOO-----\nAAAA\n-----END FOO-----"), Err(KeyProblem::Unreadable));
        assert_eq!(private_key("-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----"), Ok(KeyInfo::Other));
        assert_eq!(private_key("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----"), Err(KeyProblem::Unreadable));
        assert!(tlv(&[0x30, 0x85, 1, 1, 1, 1, 1]).is_none());
        assert!(time(0x05, b"x").is_none());
        // A long-form length.
        let long = der(0x04, &[7u8; 300]);
        assert_eq!(tlv(&long).unwrap().1.len(), 300);
    }
}
