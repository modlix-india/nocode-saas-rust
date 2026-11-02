//! Just enough DER to check an uploaded certificate and key the way
//! `SSLCertificateService.validateCrtAndKey` does: the certificate's expiry, and whether the key
//! is the RSA key of the certificate's public key (Java encrypts with one and decrypts with the
//! other; two RSA keys agree exactly when their modulus and public exponent do). An issued
//! certificate's issuer is read here too, in the form `SSLCertificateDAO.create` stored it.

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

/// What `validateCrtAndKey` and `SSLCertificateDAO.create` read of a certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertInfo {
    pub not_after: NaiveDateTime,
    pub key: KeyInfo,
    /// `getIssuerX500Principal().getName(X500Principal.CANONICAL)`, e.g. `cn=r11,o=let's encrypt,c=us`.
    pub issuer: String,
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
    Some(CertInfo { not_after: time(tag, after)?, key: spki(fields.get(5)?.1)?, issuer: canonical_name(fields.get(2)?.1)? })
}

/// The RFC 2253 keywords `X500Principal` writes; any other attribute is written as its OID.
fn keyword(oid: &[u8]) -> Option<&'static str> {
    Some(match oid {
        [0x55, 0x04, 0x03] => "cn",
        [0x55, 0x04, 0x06] => "c",
        [0x55, 0x04, 0x07] => "l",
        [0x55, 0x04, 0x08] => "st",
        [0x55, 0x04, 0x09] => "street",
        [0x55, 0x04, 0x0A] => "o",
        [0x55, 0x04, 0x0B] => "ou",
        [0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x19] => "dc",
        [0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x01] => "uid",
        _ => return None,
    })
}

/// An OBJECT IDENTIFIER's content in dotted form.
fn dotted(oid: &[u8]) -> String {
    let mut arcs = Vec::new();
    let mut v: u64 = 0;
    for &b in oid {
        v = (v << 7) | u64::from(b & 0x7F);
        if b & 0x80 == 0 {
            if arcs.is_empty() {
                let first = (v / 40).min(2);
                arcs.push(first);
                arcs.push(v - first * 40);
            } else {
                arcs.push(v);
            }
            v = 0;
        }
    }
    arcs.iter().map(u64::to_string).collect::<Vec<_>>().join(".")
}

/// A directory string's text; `None` for a type that is not one.
fn directory_string(tag: u8, c: &[u8]) -> Option<String> {
    match tag {
        0x0C | 0x13 | 0x16 => String::from_utf8(c.to_vec()).ok(),
        0x14 => Some(c.iter().map(|&b| b as char).collect()),
        0x1E => char::decode_utf16(c.chunks(2).map(|p| u16::from_be_bytes([p[0], *p.get(1).unwrap_or(&0)]))).collect::<Result<String, _>>().ok(),
        0x1C => c.chunks(4).map(|p| p.try_into().ok().map(u32::from_be_bytes).and_then(char::from_u32)).collect(),
        _ => None,
    }
}

/// One attribute value as `X500Principal`'s canonical form writes it: trimmed, inner white space
/// collapsed, lower case, RFC 2253's special characters escaped; `#` and the DER in hex for an
/// attribute without a keyword or a value that is not a string.
fn canonical_value(oid: &[u8], tag: u8, c: &[u8]) -> String {
    let text = keyword(oid).and_then(|_| directory_string(tag, c));
    let Some(text) = text else {
        let mut der = vec![tag];
        if c.len() < 0x80 {
            der.push(c.len() as u8);
        } else {
            let len = c.len().to_be_bytes();
            let skip = len.iter().take_while(|b| **b == 0).count();
            der.push(0x80 | (len.len() - skip) as u8);
            der.extend_from_slice(&len[skip..]);
        }
        der.extend_from_slice(c);
        return format!("#{}", der.iter().map(|b| format!("{b:02x}")).collect::<String>());
    };
    let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase();
    let mut out = String::with_capacity(collapsed.len());
    for (i, ch) in collapsed.chars().enumerate() {
        if matches!(ch, ',' | '+' | '"' | '\\' | '<' | '>' | ';') || (i == 0 && ch == '#') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// `X500Principal.getName(CANONICAL)` of a Name's content: the RDNs last first, joined by `,`,
/// the attributes of one RDN sorted and joined by `+`.
pub fn canonical_name(name: &[u8]) -> Option<String> {
    let mut rdns = Vec::new();
    for (_, set) in elements(name)?.iter().rev() {
        let mut avas = Vec::new();
        for (_, ava) in elements(set)? {
            let parts = elements(ava)?;
            let (_, oid) = *parts.first()?;
            let (tag, value) = *parts.get(1)?;
            let ty = keyword(oid).map(str::to_string).unwrap_or_else(|| dotted(oid));
            avas.push(format!("{ty}={}", canonical_value(oid, tag, value)));
        }
        avas.sort();
        rdns.push(avas.join("+"));
    }
    Some(rdns.join(","))
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

    fn rdn(oid: &[u8], tag: u8, value: &str) -> Vec<u8> {
        der(0x31, &seq(&[der(0x06, oid), der(tag, value.as_bytes())]))
    }

    #[test]
    fn issuers_in_javas_canonical_form() {
        // Let's Encrypt's intermediates, as their certificates name them (C, O, CN).
        let le = seq(&[rdn(&[0x55, 4, 6], 0x13, "US"), rdn(&[0x55, 4, 10], 0x0C, " Let's  Encrypt "), rdn(&[0x55, 4, 3], 0x13, "R11")]);
        assert_eq!(canonical_name(&tlv(&le).unwrap().1).unwrap(), "cn=r11,o=let's encrypt,c=us");
        let email = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01];
        let odd = seq(&[rdn(&email, 0x16, "a@b"), rdn(&[0x55, 4, 11], 0x0C, "#x,y+z")]);
        assert_eq!(canonical_name(&tlv(&odd).unwrap().1).unwrap(), "ou=\\#x\\,y\\+z,1.2.840.113549.1.9.1=#1603614062");
        // Several attributes in one RDN are sorted; BMP and Teletex strings are text too.
        let bmp: Vec<u8> = "Ab".encode_utf16().flat_map(u16::to_be_bytes).collect();
        let multi = seq(&[der(0x31, &[seq(&[der(0x06, &[0x55, 4, 3]), der(0x1E, &bmp)]), seq(&[der(0x06, &[0x55, 4, 10]), der(0x14, b"Z")])].concat())]);
        assert_eq!(canonical_name(&tlv(&multi).unwrap().1).unwrap(), "cn=ab+o=z");
        assert_eq!(canonical_name(&[]).unwrap(), "");
        assert_eq!(dotted(&[0x55, 4, 3]), "2.5.4.3");
        assert_eq!(certificate(&fake_cert("491231235959Z", &[1], true)).unwrap().issuer, "");
    }
}
