//! The request bodies `BasicRestService` sends: the payload as JSON (`JsonUtil.toMap` through
//! Jackson), as `application/x-www-form-urlencoded` (every value as its JSON text, quotes and
//! all, as Java does), or as `multipart/form-data` (with `data:<type>;name:<file>;base64,...`
//! values turned into file parts).

use base64::Engine;
use serde_json::Value;

use super::media_type::MediaType;
use super::spring_uri::url_encode_form;
use crate::error::ConnError;
use crate::java::{self, json};

/// `JsonUtil.toMap(payload)` written by Jackson: every object rebuilt as a `HashMap`, so keys
/// go out in Java's hash order.
pub fn json_body(payload: &Value) -> Vec<u8> {
    let map = match payload {
        Value::Null => Value::Object(Default::default()),
        other => java::hash_map_order_deep(other.clone()),
    };
    json::jackson(&map).into_bytes()
}

/// `getURLFormDataFromJson` then `FormHttpMessageWriter`: `name=value` pairs, both
/// `URLEncoder`-encoded, the value being the member's JSON text.
pub fn form_body(payload: &Value) -> Vec<u8> {
    let Value::Object(m) = payload else { return Vec::new() };
    let mut out = String::new();
    for (k, v) in m {
        if !out.is_empty() {
            out.push('&');
        }
        out.push_str(&url_encode_form(k));
        out.push('=');
        out.push_str(&url_encode_form(&json::gson_element(v)));
    }
    out.into_bytes()
}

/// One part of a multipart body.
#[derive(Debug, Clone, PartialEq)]
pub enum Part {
    Text { name: String, value: String },
    File { name: String, content_type: String, filename: String, bytes: Vec<u8> },
}

/// `JsonElement.getAsString()`: primitives as their text; anything else fails as Gson does.
fn as_string(v: &Value) -> Result<String, ConnError> {
    match v {
        Value::String(s) => Ok(s.clone()),
        Value::Bool(b) => Ok(b.to_string()),
        Value::Number(_) => Ok(json::gson_element(v)),
        Value::Null => Err(ConnError::other("JsonNull")),
        Value::Object(_) => Err(ConnError::other("JsonObject")),
        Value::Array(a) if a.len() == 1 => as_string(&a[0]),
        Value::Array(_) => Err(ConnError::other("Array must have size 1, but has size ".to_string() + &array_len(v))),
    }
}

fn array_len(v: &Value) -> String {
    v.as_array().map(|a| a.len()).unwrap_or(0).to_string()
}

/// `getFormDataFromJson`: arrays become one part per element.
pub fn multipart_parts(payload: &Value) -> Result<Vec<Part>, ConnError> {
    let Value::Object(m) = payload else { return Ok(Vec::new()) };
    let mut parts = Vec::new();
    for (k, v) in m {
        if let Value::Array(a) = v {
            for y in a {
                parts.push(form_part(k, &as_string(y)?)?);
            }
        } else {
            parts.push(form_part(k, &as_string(v)?)?);
        }
    }
    Ok(parts)
}

fn form_part(key: &str, value: &str) -> Result<Part, ConnError> {
    if value.starts_with("data:") {
        let pieces: Vec<&str> = java_split_semicolon(value);
        if pieces.len() >= 3 && pieces[0].starts_with("data:") && pieces[1].starts_with("name:") && pieces[2].starts_with("base64,") {
            let content_type = &pieces[0]["data:".len()..];
            let filename = &pieces[1]["name:".len()..];
            let b64 = &pieces[2]["base64,".len()..];
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(b64)
                .map_err(|_| ConnError::coded(http::StatusCode::BAD_REQUEST, "CORE.BASE64_INVALID", "Not a base64 encoded string"))?;
            // MediaType.valueOf(type) must parse.
            MediaType::parse(content_type)?;
            return Ok(Part::File { name: key.into(), content_type: content_type.into(), filename: filename.into(), bytes });
        }
    }
    Ok(Part::Text { name: key.into(), value: value.into() })
}

/// `String.split(";")`: trailing empty strings dropped.
fn java_split_semicolon(s: &str) -> Vec<&str> {
    let mut v: Vec<&str> = s.split(';').collect();
    while v.last().is_some_and(|x| x.is_empty()) {
        v.pop();
    }
    v
}

const BOUNDARY_CHARS: &[u8] = b"-_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// `MimeTypeUtils.generateMultipartBoundary`: 30 to 40 random boundary characters.
pub fn boundary() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let len = rng.gen_range(30..41);
    (0..len).map(|_| BOUNDARY_CHARS[rng.gen_range(0..BOUNDARY_CHARS.len())] as char).collect()
}

/// `MultipartHttpMessageWriter`: the body, and the `Content-Type` it writes (the given type's
/// parameters plus `boundary`).
pub fn multipart_body(parts: &[Part], content_type: &MediaType, boundary: &str) -> (Vec<u8>, String) {
    // `new MediaType(type, params)` from a HashMap: the parameters in Java's hash order.
    let mut map: serde_json::Map<String, Value> =
        content_type.params.iter().map(|(k, v)| (k.clone(), Value::String(v.clone()))).collect();
    map.insert("boundary".into(), Value::String(boundary.to_string()));
    let params: Vec<(String, String)> = java::hash_map_order(map)
        .into_iter()
        .map(|(k, v)| (k, v.as_str().unwrap_or_default().to_string()))
        .collect();
    let header = MediaType { type_: content_type.type_.clone(), subtype: content_type.subtype.clone(), params }.to_header();

    let mut out = Vec::new();
    for p in parts {
        out.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        match p {
            Part::Text { name, value } => {
                out.extend_from_slice(format!("Content-Disposition: form-data; name=\"{name}\"\r\n").as_bytes());
                out.extend_from_slice(b"Content-Type: text/plain;charset=UTF-8\r\n");
                out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", value.len()).as_bytes());
                out.extend_from_slice(value.as_bytes());
            }
            Part::File { name, content_type, filename, bytes } => {
                out.extend_from_slice(
                    format!("Content-Type: {content_type}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\n")
                        .as_bytes(),
                );
                out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", bytes.len()).as_bytes());
                out.extend_from_slice(bytes);
            }
        }
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    (out, header)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn json_keys_in_java_hash_order() {
        let body = String::from_utf8(json_body(&json!({"defaultPage": 1, "notFoundPage": 2, "links": null}))).unwrap();
        assert_eq!(body, "{\"defaultPage\":1,\"links\":null,\"notFoundPage\":2}");
        assert_eq!(json_body(&Value::Null), b"{}");
    }

    #[test]
    fn form_values_are_json_text() {
        let body = String::from_utf8(form_body(&json!({"grant_type": "client credentials", "n": 5}))).unwrap();
        assert_eq!(body, "grant_type=%22client+credentials%22&n=5");
    }

    #[test]
    fn multipart_parts_from_payload() {
        let parts = multipart_parts(&json!({"a": "x", "f": "data:text/plain;name:a.txt;base64,aGk=", "l": ["1", 2]})).unwrap();
        assert_eq!(parts.len(), 4);
        assert_eq!(
            parts[1],
            Part::File { name: "f".into(), content_type: "text/plain".into(), filename: "a.txt".into(), bytes: b"hi".to_vec() }
        );
        assert!(multipart_parts(&json!({"o": {}})).is_err());
        let (body, ct) = multipart_body(&parts[..1], &MediaType::parse("multipart/form-data").unwrap(), "B");
        assert_eq!(ct, "multipart/form-data;boundary=B");
        assert_eq!(
            String::from_utf8(body).unwrap(),
            "--B\r\nContent-Disposition: form-data; name=\"a\"\r\nContent-Type: text/plain;charset=UTF-8\r\nContent-Length: 1\r\n\r\nx\r\n--B--\r\n"
        );
    }
}
