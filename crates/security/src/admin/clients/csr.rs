//! The key pair and CSR of a certificate request (`makeRecord`): what acme4j's
//! `KeyPairUtils.createKeyPair(2048)`, `KeyPairUtils.writeKeyPair` and `CSRBuilder` made.
//!
//! - The key is a new 2048-bit RSA key, written as PKCS#1 PEM (`-----BEGIN RSA PRIVATE KEY-----`),
//!   the form `JcaPEMWriter` wrote for a key pair and every stored row has; the nginx side writes
//!   it to `<host>.key` as it is, so keys made here and by Java are interchangeable.
//! - The CSR (`-----BEGIN CERTIFICATE REQUEST-----`) names the first domain as the subject's CN
//!   and the organization as its O (both UTF8String, as BouncyCastle's X500NameBuilder wrote
//!   them), every domain as a dNSName in a subjectAltName extension request, and is signed
//!   SHA256withRSA. Domains go through `toAce`: trimmed, IDNA ASCII, lower case.

use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
use rsa::pkcs1v15::{Signature, SigningKey};
use rsa::RsaPrivateKey;
use sha2::Sha256;
use x509_cert::builder::{Builder, RequestBuilder};
use x509_cert::der::asn1::{Any, Ia5String, SetOfVec, Utf8StringRef};
use x509_cert::der::oid::ObjectIdentifier;
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::der::EncodePem;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::name::{Name, RdnSequence, RelativeDistinguishedName};

use super::ssl::CertCrypto;

const CN: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
const O: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.10");

/// Real keys and CSRs.
pub struct RsaCsr;

impl CertCrypto for RsaCsr {
    fn key_and_csr(&self, domains: &[String], organization: Option<&str>) -> Option<(String, String)> {
        match key_and_csr(domains, organization) {
            Ok(v) => Some(v),
            Err(e) => {
                tracing::error!(error = %e, "could not make a certificate request's key and CSR");
                None
            }
        }
    }
}

/// `AcmeUtils.toAce`.
pub fn to_ace(domain: &str) -> anyhow::Result<String> {
    let ace = idna::domain_to_ascii(domain.trim()).map_err(|_| anyhow::anyhow!("not a domain name: {domain}"))?;
    Ok(ace.to_lowercase())
}

fn rdn(oid: ObjectIdentifier, value: &str) -> anyhow::Result<RelativeDistinguishedName> {
    let atv = AttributeTypeAndValue { oid, value: Any::encode_from(&Utf8StringRef::new(value)?)? };
    Ok(RelativeDistinguishedName(SetOfVec::try_from(vec![atv])?))
}

/// The key (PKCS#1 PEM) and the CSR (PEM).
pub fn key_and_csr(domains: &[String], organization: Option<&str>) -> anyhow::Result<(String, String)> {
    let names = domains.iter().map(|d| to_ace(d)).collect::<anyhow::Result<Vec<_>>>()?;
    let Some(first) = names.first() else { anyhow::bail!("No domain or IP address was set") };
    let key = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048)?;
    let key_pem = key.to_pkcs1_pem(LineEnding::LF)?.to_string();
    let mut subject = vec![rdn(CN, first)?];
    if let Some(o) = organization {
        subject.push(rdn(O, o)?);
    }
    let signer = SigningKey::<Sha256>::new(key);
    let mut builder = RequestBuilder::new(Name::from(RdnSequence(subject)), &signer)?;
    let san = names.iter().map(|n| Ia5String::new(n).map(GeneralName::DnsName)).collect::<Result<Vec<_>, _>>()?;
    builder.add_extension(&SubjectAltName(san))?;
    let csr = builder.build::<Signature>()?;
    Ok((key_pem, csr.to_pem(LineEnding::LF)?))
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::admin::clients::x509;
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::traits::PublicKeyParts;
    use x509_cert::der::{Decode, DecodePem, Encode, Tagged};
    use x509_cert::request::CertReq;

    /// The SHA256withRSA algorithm identifier.
    const SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
    /// `pkcs-9-at-extensionRequest`.
    const EXTENSION_REQUEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.14");
    const SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");

    #[test]
    fn key_and_csr_as_java_made_them() {
        let domains = vec!["Shop.Example.com ".to_string(), "www.shop.example.com".to_string(), "bücher.example".to_string()];
        let (key, csr) = RsaCsr.key_and_csr(&domains, Some("ZZ Org")).unwrap();
        assert!(key.starts_with("-----BEGIN RSA PRIVATE KEY-----\n") && key.ends_with("-----END RSA PRIVATE KEY-----\n"), "{}", &key[..40]);
        assert!(key.lines().all(|l| l.len() <= 64));
        let private = RsaPrivateKey::from_pkcs1_pem(&key).unwrap();
        assert_eq!(private.size() * 8, 2048);
        // The upload check reads the same key.
        assert!(matches!(x509::private_key(&key), Ok(x509::KeyInfo::Rsa { .. })));

        assert!(csr.starts_with("-----BEGIN CERTIFICATE REQUEST-----\n"));
        let req = CertReq::from_pem(csr.as_bytes()).unwrap();
        assert_eq!(req.algorithm.oid, SHA256_WITH_RSA);
        // RFC 4514 prints the last RDN first: the DER has CN, then O, as CSRBuilder wrote them.
        assert_eq!(req.info.subject.to_string(), "O=ZZ Org,CN=shop.example.com");
        let first = &req.info.subject.0[0].0.as_slice()[0];
        assert_eq!((first.oid, first.value.tag()), (CN, x509_cert::der::Tag::Utf8String));
        let x509::KeyInfo::Rsa { n, .. } = x509::private_key(&key).unwrap() else { panic!("not RSA") };
        assert_eq!(req.info.public_key.subject_public_key.raw_bytes().len(), 270);
        assert_eq!(n, private.n().to_bytes_be());
        let attr = req.info.attributes.iter().find(|a| a.oid == EXTENSION_REQUEST).unwrap();
        let exts: Vec<x509_cert::ext::Extension> = attr.values.iter().next().unwrap().decode_as().unwrap();
        let san_ext = exts.iter().find(|e| e.extn_id == SUBJECT_ALT_NAME).unwrap();
        assert!(!san_ext.critical);
        let san = SubjectAltName::from_der(san_ext.extn_value.as_bytes()).unwrap();
        let names: Vec<String> = san
            .0
            .iter()
            .map(|g| match g {
                GeneralName::DnsName(d) => d.to_string(),
                other => format!("{other:?}"),
            })
            .collect();
        assert_eq!(names, vec!["shop.example.com", "www.shop.example.com", "xn--bcher-kva.example"]);
        // The signature verifies with the request's own key.
        use rsa::pkcs1v15::VerifyingKey;
        use rsa::signature::Verifier;
        let verifying = VerifyingKey::<Sha256>::new(private.to_public_key());
        let sig = Signature::try_from(req.signature.raw_bytes()).unwrap();
        verifying.verify(&req.info.to_der().unwrap(), &sig).unwrap();
    }

    #[test]
    fn without_organization_or_domains() {
        let (_, csr) = key_and_csr(&["a.example".into()], None).unwrap();
        assert_eq!(CertReq::from_pem(csr.as_bytes()).unwrap().info.subject.to_string(), "CN=a.example");
        assert!(RsaCsr.key_and_csr(&[], Some("x")).is_none());
        assert_eq!(to_ace(" A.Example ").unwrap(), "a.example");
    }
}
