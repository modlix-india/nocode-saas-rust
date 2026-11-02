//! `CoreServices.Crypto`: `Signer` and `SignatureValidator` (HMAC; the RSA branch of the Java
//! code has no implementation and is not offered by the signature's `alg` enum). HmacSHA1 is Rust
//! only (some calling and SMS providers sign their webhooks with it; DIFFERENCES.md), and a
//! signature is compared in constant time.

use async_trait::async_trait;
use hmac::{Hmac, Mac};
use kirun::json::schema::Schema;
use kirun::model::{Event, FunctionOutput, FunctionSignature, Parameter};
use kirun::{Map, Value};
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};

use super::{arg, arg_string, output, CoreFunction};
use crate::error::CoreError;
use crate::gson::element_to_string;

const NAMESPACE: &str = "CoreServices.Crypto";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HmacAlgo {
    Hs1,
    Hs256,
    Hs384,
    Hs512,
}

impl HmacAlgo {
    /// `SignatureAlgo.getByJcaName`, for the ones the signature allows.
    pub fn by_jca_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "hmacsha1" => Some(Self::Hs1),
            "hmacsha256" => Some(Self::Hs256),
            "hmacsha384" => Some(Self::Hs384),
            "hmacsha512" => Some(Self::Hs512),
            _ => None,
        }
    }

    fn value(self) -> &'static str {
        match self {
            Self::Hs1 => "HS1",
            Self::Hs256 => "HS256",
            Self::Hs384 => "HS384",
            Self::Hs512 => "HS512",
        }
    }

    /// The digest's size: a shorter key is refused, as Java's `MacSigner` refuses one.
    fn min_key_bits(self) -> usize {
        match self {
            Self::Hs1 => 160,
            Self::Hs256 => 256,
            Self::Hs384 => 384,
            Self::Hs512 => 512,
        }
    }

    /// `new MacSigner(alg, key[, verify])`: `SecretKeySpec` refuses an empty key, then the
    /// key must be at least as long as the digest.
    pub fn check_key(self, key: &[u8], signing: bool) -> Result<(), CoreError> {
        if key.is_empty() {
            return Err(CoreError::unknown("Empty key"));
        }
        let bits = key.len() * 8;
        if bits < self.min_key_bits() {
            let use_ = if signing { "signing" } else { "verification" };
            return Err(CoreError::coded(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "CORE.KEY_TOO_SHORT",
                format!("The {use_} key's size is {bits} bits which is not secure enough for the {} algorithm.", self.value()),
            )
            .param("use", use_)
            .param("bits", bits)
            .param("algorithm", self.value()));
        }
        Ok(())
    }

    pub fn sign(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        fn run<M: Mac + hmac::digest::KeyInit>(key: &[u8], data: &[u8]) -> Vec<u8> {
            match <M as hmac::digest::KeyInit>::new_from_slice(key) {
                Ok(mut m) => {
                    m.update(data);
                    m.finalize().into_bytes().to_vec()
                }
                Err(_) => Vec::new(),
            }
        }
        match self {
            Self::Hs1 => run::<Hmac<Sha1>>(key, data),
            Self::Hs256 => run::<Hmac<Sha256>>(key, data),
            Self::Hs384 => run::<Hmac<Sha384>>(key, data),
            Self::Hs512 => run::<Hmac<Sha512>>(key, data),
        }
    }
}

/// Whether two signatures are the same, in time that does not depend on where they differ (a
/// webhook's signature is checked against what anyone may send).
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(diff) == 0
}

/// The charsets the signature offers, as `String.getBytes(charset)` encodes: an unmappable
/// character becomes `?`, and `UTF-16` writes a big-endian byte order mark.
pub fn encode_charset(s: &str, charset: &str) -> Result<Vec<u8>, CoreError> {
    let units = || s.encode_utf16();
    Ok(match charset.to_ascii_uppercase().as_str() {
        "UTF-8" | "UTF8" => s.as_bytes().to_vec(),
        "US-ASCII" | "ASCII" => s.chars().map(|c| if (c as u32) < 0x80 { c as u8 } else { b'?' }).collect(),
        "ISO-8859-1" | "LATIN1" => s.chars().map(|c| if (c as u32) <= 0xFF { c as u32 as u8 } else { b'?' }).collect(),
        "UTF-16BE" => units().flat_map(u16::to_be_bytes).collect(),
        "UTF-16LE" => units().flat_map(u16::to_le_bytes).collect(),
        "UTF-16" => {
            let mut v = vec![0xFE, 0xFF];
            v.extend(units().flat_map(u16::to_be_bytes));
            v
        }
        other => return Err(CoreError::unknown(other.to_string())),
    })
}

/// `StringEncoder`: `base64` (written without padding) or `Hex` (lower case).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StringEncoder {
    Base64,
    Hex,
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

impl StringEncoder {
    pub fn by_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "base64" => Some(Self::Base64),
            "hex" => Some(Self::Hex),
            _ => None,
        }
    }

    pub fn encode(self, bytes: &[u8]) -> String {
        match self {
            Self::Hex => hex::encode(bytes),
            Self::Base64 => {
                let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
                for chunk in bytes.chunks(3) {
                    let n = chunk.iter().fold(0u32, |acc, b| (acc << 8) | *b as u32) << (8 * (3 - chunk.len()));
                    for i in 0..=chunk.len() {
                        out.push(B64[((n >> (18 - 6 * i)) & 0x3F) as usize] as char);
                    }
                }
                out
            }
        }
    }

    /// `Base64.getDecoder().decode` / `HexFormat.parseHex`, with their error messages.
    pub fn decode(self, s: &str) -> Result<Vec<u8>, CoreError> {
        match self {
            Self::Hex => {
                if s.len() % 2 != 0 {
                    return Err(CoreError::unknown(format!("string length not even: {}", s.chars().count())));
                }
                let b = s.as_bytes();
                let mut out = Vec::with_capacity(b.len() / 2);
                for pair in b.chunks(2) {
                    let digit = |c: u8| -> Result<u8, CoreError> {
                        (c as char).to_digit(16).map(|d| d as u8).ok_or_else(|| {
                            CoreError::unknown(format!("not a hexadecimal digit: \"{}\" = {}", c as char, c))
                        })
                    };
                    out.push(digit(pair[0])? << 4 | digit(pair[1])?);
                }
                Ok(out)
            }
            Self::Base64 => base64_decode(s),
        }
    }
}

fn base64_decode(s: &str) -> Result<Vec<u8>, CoreError> {
    let src = s.as_bytes();
    let mut end = src.len();
    // Padding ends the data; at most two, and only in a final unit.
    while end > 0 && src[end - 1] == b'=' {
        end -= 1;
    }
    let pads = src.len() - end;
    let mut out = Vec::with_capacity(end * 3 / 4);
    let mut bits = 0u32;
    let mut n = 0;
    for &c in &src[..end] {
        let v = match B64.iter().position(|x| *x == c) {
            Some(v) => v as u32,
            None => {
                // `Integer.toString(byte, 16)`: a byte past 0x7F is negative there.
                let b = c as i8 as i32;
                let hex = if b < 0 { format!("-{:x}", -b) } else { format!("{b:x}") };
                return Err(CoreError::unknown(format!("Illegal base64 character {hex}")));
            }
        };
        bits = (bits << 6) | v;
        n += 1;
        if n == 4 {
            out.extend_from_slice(&[(bits >> 16) as u8, (bits >> 8) as u8, bits as u8]);
            bits = 0;
            n = 0;
        }
    }
    match n {
        0 if pads == 0 => {}
        1 => return Err(CoreError::unknown("Last unit does not have enough valid bits")),
        2 if pads == 0 || pads == 2 => out.push((bits >> 4) as u8),
        3 if pads <= 1 => out.extend_from_slice(&[(bits >> 10) as u8, (bits >> 2) as u8]),
        _ => return Err(CoreError::unknown("Input byte array has wrong 4-byte ending unit")),
    }
    Ok(out)
}

/// `AbstractSignatureFunction.toBytes`: a primitive's string value, anything else its JSON.
fn data_bytes(data: &Value, charset: &str) -> Result<Vec<u8>, CoreError> {
    let text = match data {
        Value::String(s) => s.clone(),
        Value::Number(n) => crate::gson::number_to_java_string(n),
        Value::Bool(b) => b.to_string(),
        other => element_to_string(other),
    };
    encode_charset(&text, charset)
}

fn algorithms() -> Schema {
    Schema::of_string("alg").set_enums(vec![
        Value::from("HmacSHA1"),
        Value::from("HmacSHA256"),
        Value::from("HmacSHA384"),
        Value::from("HmacSHA512"),
    ])
}

fn charsets() -> Schema {
    Schema::of_string("charset")
        .set_enums(["US-ASCII", "ISO-8859-1", "UTF-8", "UTF-16BE", "UTF-16LE", "UTF-16"].map(Value::from).to_vec())
        .set_default_value(Value::from("UTF-8"))
}

fn encoders() -> Schema {
    Schema::of_string("signatureEncoder")
        .set_enums(vec![Value::from("base64"), Value::from("Hex")])
        .set_default_value(Value::from("base64"))
}

fn result_event() -> Map<kirun::model::Event> {
    Map::from([Event::output_event_map_entry(Map::from([("result".to_string(), Schema::of_string("result"))]))])
}

struct Common {
    algo: Option<HmacAlgo>,
    charset: String,
    key: Vec<u8>,
    encoder: StringEncoder,
}

fn common(args: &Map<Value>) -> Result<Common, CoreError> {
    let algorithm = arg_string(args, "alg")?;
    let charset = arg_string(args, "charset")?;
    let secret_key = arg_string(args, "secretKey")?;
    let encoder_name = arg_string(args, "signatureEncoder")?;
    let encoder = StringEncoder::by_name(&encoder_name).ok_or_else(|| CoreError::unknown("encoder"))?;
    Ok(Common { algo: HmacAlgo::by_jca_name(&algorithm), key: encode_charset(&secret_key, &charset)?, charset, encoder })
}

pub struct Signer {
    signature: FunctionSignature,
}

impl Signer {
    pub fn new() -> Self {
        Self {
            signature: FunctionSignature::new("Signer")
                .set_namespace(NAMESPACE)
                .set_parameters(Map::from([
                    Parameter::of_entry("alg", algorithms(), false),
                    Parameter::of_entry("charset", charsets(), false),
                    Parameter::of_entry("secretKey", Schema::of_string("secretKey").set_minimum(0.0), false),
                    Parameter::of_entry("data", Schema::of_any_not_null("data"), false),
                    Parameter::of_entry("signatureEncoder", encoders(), false),
                ]))
                .set_events(result_event()),
        }
    }
}

impl Default for Signer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CoreFunction for Signer {
    fn signature(&self) -> &FunctionSignature {
        &self.signature
    }

    async fn internal_execute(&self, args: &Map<Value>) -> Result<FunctionOutput, CoreError> {
        let c = common(args)?;
        let data = arg(args, "data");
        let Some(algo) = c.algo else {
            return Ok(output("result", Value::from("")));
        };
        algo.check_key(&c.key, true)?;
        if data.is_null() {
            return Ok(output("result", Value::from("")));
        }
        let signed = algo.sign(&c.key, &data_bytes(data, &c.charset)?);
        Ok(output("result", Value::String(c.encoder.encode(&signed))))
    }
}

pub struct SignatureValidator {
    signature: FunctionSignature,
}

impl SignatureValidator {
    pub fn new() -> Self {
        Self {
            signature: FunctionSignature::new("SignatureValidator")
                .set_namespace(NAMESPACE)
                .set_parameters(Map::from([
                    Parameter::of_entry("alg", algorithms(), false),
                    Parameter::of_entry("charset", charsets(), false),
                    Parameter::of_entry("secretKey", Schema::of_string("secretKey").set_minimum(0.0), false),
                    Parameter::of_entry("data", Schema::of_any_not_null("data"), false),
                    Parameter::of_entry("signature", Schema::of_string("signature").set_minimum(0.0), false),
                    Parameter::of_entry("signatureEncoder", encoders(), false),
                ]))
                .set_events(result_event()),
        }
    }
}

impl Default for SignatureValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CoreFunction for SignatureValidator {
    fn signature(&self) -> &FunctionSignature {
        &self.signature
    }

    /// The signature says `result`; the output is `isValid`, as in Java.
    async fn internal_execute(&self, args: &Map<Value>) -> Result<FunctionOutput, CoreError> {
        let c = common(args)?;
        let data = arg(args, "data");
        let signature = arg_string(args, "signature")?;
        let Some(algo) = c.algo else {
            return Ok(output("isValid", Value::Bool(false)));
        };
        algo.check_key(&c.key, false)?;
        if data.is_null() {
            return Ok(output("isValid", Value::Bool(false)));
        }
        let given = c.encoder.decode(&signature)?;
        let signed = algo.sign(&c.key, &data_bytes(data, &c.charset)?);
        Ok(output("isValid", Value::Bool(constant_time_eq(&signed, &given))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_without_padding_round_trips() {
        for s in ["", "f", "fo", "foo", "foob", "fooba", "foobar"] {
            let e = StringEncoder::Base64.encode(s.as_bytes());
            assert!(!e.contains('='));
            assert_eq!(StringEncoder::Base64.decode(&e).unwrap(), s.as_bytes());
        }
        assert_eq!(StringEncoder::Base64.encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(StringEncoder::Base64.encode(b"fo"), "Zm8");
        assert_eq!(StringEncoder::Base64.decode("Zm8=").unwrap(), b"fo");
        assert!(StringEncoder::Base64.decode("Z").is_err());
    }

    #[test]
    fn hmac_sha256_known_vector() {
        // RFC 4231 test case 2 key is too short for Java's check; use a 32-byte key.
        let key = b"0123456789abcdef0123456789abcdef";
        let sig = HmacAlgo::Hs256.sign(key, b"hello");
        assert_eq!(sig.len(), 32);
        assert!(HmacAlgo::Hs256.check_key(b"short", true).is_err());
        assert!(HmacAlgo::Hs256.check_key(key, true).is_ok());
        assert_eq!(
            HmacAlgo::Hs256.check_key(b"short", true).unwrap_err().text(),
            "The signing key's size is 40 bits which is not secure enough for the HS256 algorithm."
        );
    }

    #[test]
    fn hmac_sha1_and_the_constant_time_compare() {
        // RFC 2202 test case 7's data with a 20-byte key (case 1's).
        let key = [0x0bu8; 20];
        assert_eq!(hex::encode(HmacAlgo::Hs1.sign(&key, b"Hi There")), "b617318655057264e28bc0b6fb378c8ef146be00");
        assert_eq!(HmacAlgo::by_jca_name("HmacSHA1"), Some(HmacAlgo::Hs1));
        assert!(HmacAlgo::Hs1.check_key(&key, false).is_ok());
        assert_eq!(
            HmacAlgo::Hs1.check_key(&key[..19], false).unwrap_err().text(),
            "The verification key's size is 152 bits which is not secure enough for the HS1 algorithm."
        );
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }

    fn args(pairs: &[(&str, Value)]) -> Map<Value> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
    }

    /// A provider's webhook: an HMAC-SHA256 over the exact body, hex, as Meta's
    /// `X-Hub-Signature-256` carries it; and an HmacSHA1 one in base64.
    #[tokio::test]
    async fn a_webhook_signature_over_the_raw_body() {
        let secret = "0123456789abcdef0123456789abcdef";
        let raw = r#"{"object":"whatsapp_business_account",  "entry":[{"id":"1"}]}"#;
        let expected = hex::encode(HmacAlgo::Hs256.sign(secret.as_bytes(), raw.as_bytes()));
        let common = |alg: &str, enc: &str| {
            vec![
                ("alg", Value::from(alg)),
                ("charset", Value::from("UTF-8")),
                ("secretKey", Value::from(secret)),
                ("data", Value::from(raw)),
                ("signatureEncoder", Value::from(enc)),
            ]
        };
        let mut signed = Signer::new().internal_execute(&args(&common("HmacSHA256", "Hex"))).await.unwrap();
        assert_eq!(signed.next().unwrap().get_result()["result"], Value::from(expected.clone()));
        let check = |sig: &str, alg: &str, enc: &str| {
            let mut a = common(alg, enc);
            a.push(("signature", Value::from(sig)));
            args(&a)
        };
        let valid = |mut out: FunctionOutput| out.next().unwrap().get_result()["isValid"].clone();
        let v = SignatureValidator::new();
        assert_eq!(valid(v.internal_execute(&check(&expected, "HmacSHA256", "Hex")).await.unwrap()), Value::Bool(true));
        let mut tampered = expected.clone();
        tampered.replace_range(0..1, if expected.starts_with('0') { "1" } else { "0" });
        assert_eq!(valid(v.internal_execute(&check(&tampered, "HmacSHA256", "Hex")).await.unwrap()), Value::Bool(false));
        // One space more in the body is another signature.
        let mut spaced = check(&expected, "HmacSHA256", "Hex");
        spaced.insert("data".into(), Value::from(raw.replacen("  ", " ", 1)));
        assert_eq!(valid(v.internal_execute(&spaced).await.unwrap()), Value::Bool(false));
        let sha1 = StringEncoder::Base64.encode(&HmacAlgo::Hs1.sign(secret.as_bytes(), raw.as_bytes()));
        assert_eq!(valid(v.internal_execute(&check(&sha1, "HmacSHA1", "base64")).await.unwrap()), Value::Bool(true));
        assert!(Signer::new().signature().get_parameters()["alg"].get_schema().get_enums().unwrap().contains(&Value::from("HmacSHA1")));
    }

    #[test]
    fn charsets_like_java() {
        assert_eq!(encode_charset("é", "ISO-8859-1").unwrap(), vec![0xE9]);
        assert_eq!(encode_charset("é", "US-ASCII").unwrap(), vec![b'?']);
        assert_eq!(encode_charset("A", "UTF-16").unwrap(), vec![0xFE, 0xFF, 0, 0x41]);
        assert_eq!(encode_charset("A", "UTF-16LE").unwrap(), vec![0x41, 0]);
    }

    #[test]
    fn hex_errors() {
        assert_eq!(StringEncoder::Hex.decode("abc").unwrap_err().text(), "string length not even: 3");
        assert_eq!(StringEncoder::Hex.decode("zz").unwrap_err().text(), "not a hexadecimal digit: \"z\" = 122");
        assert_eq!(StringEncoder::Hex.decode("0aFF").unwrap(), vec![0x0a, 0xff]);
    }
}
