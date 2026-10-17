//! `CoreServices.Hash.HashData`.

use async_trait::async_trait;
use axum::http::StatusCode;
use kirun::json::schema::Schema;
use kirun::model::{Event, FunctionOutput, FunctionSignature, Parameter};
use kirun::{Map, Value};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

use super::{arg, arg_string, output, CoreFunction};
use crate::error::CoreError;
use crate::gson::element_to_string;

pub struct HashData {
    signature: FunctionSignature,
}

impl HashData {
    pub fn new() -> Self {
        let algorithms = ["SHA-256", "SHA-384", "SHA-512", "MD5", "MD2", "MD4", "SHA-1"].map(Value::from).to_vec();
        Self {
            signature: FunctionSignature::new("HashData")
                .set_namespace("CoreServices.Hash")
                .set_parameters(Map::from([
                    Parameter::of_entry("data", Schema::of_any("data"), false),
                    Parameter::of_entry(
                        "algorithm",
                        Schema::of_string("algorithm").set_enums(algorithms).set_default_value(Value::from("SHA-256")),
                        false,
                    ),
                    Parameter::of_entry(
                        "primitiveLevel",
                        Schema::of_boolean("primitiveLevel").set_default_value(Value::Bool(false)),
                        false,
                    ),
                ]))
                .set_events(Map::from([Event::output_event_map_entry(Map::from([(
                    "result".to_string(),
                    Schema::of_string("result"),
                )]))])),
        }
    }
}

impl Default for HashData {
    fn default() -> Self {
        Self::new()
    }
}

/// `MessageDigest.getInstance(alg).digest(bytes)` for the JDK's default providers. MD4 is not
/// registered there, so it fails as Java does.
pub fn digest(algorithm: &str, bytes: &[u8]) -> Result<Vec<u8>, CoreError> {
    if algorithm.trim().is_empty() {
        return Err(CoreError::coded(StatusCode::BAD_REQUEST, "CORE.HASH_ALGORITHM_MISSING", "Algorithm cannot be null or empty"));
    }
    Ok(match algorithm.to_ascii_uppercase().as_str() {
        "SHA-256" | "SHA256" => Sha256::digest(bytes).to_vec(),
        "SHA-384" | "SHA384" => Sha384::digest(bytes).to_vec(),
        "SHA-512" | "SHA512" => Sha512::digest(bytes).to_vec(),
        "SHA-1" | "SHA1" | "SHA" => Sha1::digest(bytes).to_vec(),
        "MD5" => md5::Md5::digest(bytes).to_vec(),
        "MD2" => md2(bytes).to_vec(),
        _ => {
            return Err(CoreError::coded(StatusCode::BAD_REQUEST, "CORE.HASH_ALGORITHM_UNSUPPORTED", format!("Hash algorithm not supported: {algorithm}"))
                .caused_by(format!("{algorithm} MessageDigest not available"))
                .param("algorithm", algorithm))
        }
    })
}

/// `HashUtil.createHash(input, algorithm)` with a `String` input: its UTF-8 bytes, digested,
/// as lower-case hex.
fn hash_text(text: &str, algorithm: &str) -> Result<Value, CoreError> {
    Ok(Value::String(hex::encode(digest(algorithm, text.as_bytes())?)))
}

/// `HashData.processElement`.
fn process(element: &Value, algorithm: &str, primitive_level: bool) -> Result<Value, CoreError> {
    if element.is_null() {
        return hash_text("null", algorithm);
    }
    if !primitive_level {
        return hash_text(&element_to_string(element), algorithm);
    }
    match element {
        // number.toString(), then hashed as that String.
        Value::Number(n) => hash_text(&crate::gson::number_to_java_string(n), algorithm),
        Value::Bool(b) => hash_text(&b.to_string(), algorithm),
        // primitive.toString(): the JSON text, quotes included.
        Value::String(_) => hash_text(&element_to_string(element), algorithm),
        Value::Array(a) => Ok(Value::Array(
            a.iter().map(|e| process(e, algorithm, true)).collect::<Result<_, _>>()?,
        )),
        Value::Object(m) => {
            let mut out = serde_json::Map::new();
            for (k, v) in m {
                let key = match process(&Value::String(k.clone()), algorithm, true)? {
                    Value::String(s) => s,
                    other => other.to_string(),
                };
                out.insert(key, process(v, algorithm, true)?);
            }
            Ok(Value::Object(out))
        }
        Value::Null => hash_text("null", algorithm),
    }
}

#[async_trait]
impl CoreFunction for HashData {
    fn signature(&self) -> &FunctionSignature {
        &self.signature
    }

    async fn internal_execute(&self, args: &Map<Value>) -> Result<FunctionOutput, CoreError> {
        let algorithm = arg_string(args, "algorithm")?;
        let primitive_level = matches!(arg(args, "primitiveLevel"), Value::Bool(true));
        let hash = process(arg(args, "data"), &algorithm, primitive_level)?;
        Ok(output("result", hash))
    }
}

/// MD2 (RFC 1319), which the JDK's SUN provider still offers.
fn md2(input: &[u8]) -> [u8; 16] {
    const S: [u8; 256] = [
        41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6, 19, 98, 167, 5, 243, 192, 199, 115, 140, 152,
        147, 43, 217, 188, 76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24, 138, 23, 229, 18, 190, 78,
        196, 214, 218, 158, 222, 73, 160, 251, 245, 142, 187, 47, 238, 122, 169, 104, 121, 145, 21, 178, 7, 63, 148, 194,
        16, 137, 11, 34, 95, 33, 128, 127, 93, 154, 90, 144, 50, 39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179,
        72, 165, 181, 209, 215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210, 150, 164, 125, 182, 118, 252, 107, 226,
        156, 116, 4, 241, 69, 157, 112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27, 96, 37, 173, 174,
        176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15, 85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197,
        234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65, 129, 77, 82, 106, 220, 55, 200, 108, 193, 171,
        250, 36, 225, 123, 8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109, 233, 203, 213, 254, 59, 0, 29, 57,
        242, 239, 183, 14, 102, 88, 208, 228, 166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237, 31, 26,
        219, 153, 141, 51, 159, 17, 131, 20,
    ];
    let pad = 16 - input.len() % 16;
    let mut msg = input.to_vec();
    msg.extend(std::iter::repeat_n(pad as u8, pad));
    let mut checksum = [0u8; 16];
    let mut l = 0u8;
    for block in msg.chunks(16) {
        for j in 0..16 {
            checksum[j] ^= S[(block[j] ^ l) as usize];
            l = checksum[j];
        }
    }
    msg.extend_from_slice(&checksum);
    let mut x = [0u8; 48];
    for block in msg.chunks(16) {
        for j in 0..16 {
            x[16 + j] = block[j];
            x[32 + j] = x[16 + j] ^ x[j];
        }
        let mut t = 0u8;
        for j in 0..18u8 {
            for k in x.iter_mut() {
                *k ^= S[t as usize];
                t = *k;
            }
            t = t.wrapping_add(j);
        }
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&x[..16]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn md2_rfc_vectors() {
        assert_eq!(hex::encode(md2(b"")), "8350e5a3e24c153df2275c9f80692773");
        assert_eq!(hex::encode(md2(b"abc")), "da853b0d3f88d99b30283a69e6ded6bb");
        assert_eq!(hex::encode(md2(b"message digest")), "ab4f496bfb2a530b219ff33031fe06b0");
    }

    #[test]
    fn strings_are_hashed_with_their_quotes() {
        // HashData hashes `"abc"` (the JsonElement's text), not `abc`.
        let expected = hex::encode(Sha256::digest(b"\"abc\""));
        assert_eq!(process(&json!("abc"), "SHA-256", false).unwrap(), json!(expected));
        assert_eq!(process(&json!("abc"), "SHA-256", true).unwrap(), json!(expected));
    }

    #[test]
    fn primitive_level_hashes_leaves_and_keys() {
        let v = process(&json!({"a": [1, true, null]}), "MD5", true).unwrap();
        let key = hex::encode(md5::Md5::digest(b"\"a\""));
        let arr = v[&key].as_array().unwrap();
        assert_eq!(arr[0], json!(hex::encode(md5::Md5::digest(b"1"))));
        assert_eq!(arr[1], json!(hex::encode(md5::Md5::digest(b"true"))));
        assert_eq!(arr[2], json!(hex::encode(md5::Md5::digest(b"null"))));
    }

    #[test]
    fn md4_is_not_available() {
        let e = digest("MD4", b"x").unwrap_err();
        assert_eq!(e.status(), StatusCode::BAD_REQUEST);
        assert_eq!(e.text(), "Hash algorithm not supported: MD4");
    }
}
