//! Request bodies of URI path routes, and the routes marked `webhook: true` (Rust only; see
//! DIFFERENCES.md).
//!
//! A body is read by its content type: JSON (or no type) as Java reads it; a form
//! (`application/x-www-form-urlencoded`) and the text fields of `multipart/form-data` as an object,
//! a repeated name becoming a list; `text/*` and XML as the `body` argument (a text that is a JSON
//! object stays the object, as before).
//!
//! A webhook route is a provider calling an app for one tenant: anyone may call it, so the
//! function verifies the provider's signature itself. Its function runs through core's internal
//! webhook route, as the tenant's anonymous user with `Authorities._Webhook`, and gets the request
//! as it came (`rawBody`, `rawBodyEncoding`, `headers`, `query`) next to the parsed body. Its output
//! event can set the reply (`status`, `contentType`, `headers`, `body`).

use std::convert::Infallible;

use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use bytes::Bytes;
use overridable::pojo::str_field;
use overridable::{JMap, JValue};
use platform::error::AppError;

use crate::shell::gson::{self, G};
use crate::shell::uripath::output_value;

/// The largest body a URI path route reads.
pub const BODY_LIMIT: usize = 64 * 1024 * 1024;

/// The arguments a webhook function gets besides the body's.
pub const RAW_BODY: &str = "rawBody";
pub const RAW_BODY_ENCODING: &str = "rawBodyEncoding";
pub const HEADERS: &str = "headers";
pub const QUERY: &str = "query";

/// The keys of an output that sets the reply.
const REPLY_KEYS: [&str; 4] = ["status", "contentType", "headers", "body"];

/// Headers a reply can not set: the server writes them.
const SERVER_HEADERS: [&str; 3] = ["content-length", "transfer-encoding", "connection"];

/// `webhook: true` on the URI path.
pub fn is_webhook(uri_path: &JMap) -> bool {
    matches!(uri_path.get("webhook"), Some(JValue::Bool(true)))
}

/// How a body is read, by its content type.
#[derive(Debug, PartialEq, Eq)]
pub enum BodyKind {
    /// JSON, and anything that names no other kind (Java's only reading).
    Json,
    Form,
    /// With its boundary, when the type names one.
    Multipart(Option<String>),
    Text,
}

pub fn body_kind(content_type: &str) -> BodyKind {
    let lower = content_type.to_ascii_lowercase();
    let essence = lower.split(';').next().unwrap_or("").trim();
    match essence {
        "application/x-www-form-urlencoded" => BodyKind::Form,
        "multipart/form-data" => BodyKind::Multipart(multer::parse_boundary(content_type).ok()),
        e if e.starts_with("text/") || e == "application/xml" || e.ends_with("+xml") => BodyKind::Text,
        _ => BodyKind::Json,
    }
}

/// A body that can not be read: the status and the debug text (`400 BAD_REQUEST "..."` is
/// Spring's refusal and names its code).
pub type BodyError = (StatusCode, String);

/// The body as the route's arguments: always an object.
pub async fn parse_body(content_type: &str, bytes: &Bytes) -> Result<G, BodyError> {
    match body_kind(content_type) {
        BodyKind::Json => json_body(bytes),
        BodyKind::Form => Ok(pairs_object(form_urlencoded::parse(bytes).map(|(k, v)| (k.into_owned(), v.into_owned())))),
        BodyKind::Multipart(boundary) => multipart_body(boundary, bytes.clone()).await,
        BodyKind::Text => Ok(text_body(bytes)),
    }
}

/// `gson.fromJson(body, JsonObject.class)`; a blank body is `{}`.
fn json_body(bytes: &[u8]) -> Result<G, BodyError> {
    let text = String::from_utf8_lossy(bytes);
    if text.trim().is_empty() {
        return Ok(G::Obj(Vec::new()));
    }
    gson::parse_object(&text).map_err(|m| (StatusCode::INTERNAL_SERVER_ERROR, m))
}

/// A text body: `{"body": text}`, except a JSON object (what a text body could carry before)
/// and a blank one (`{}`).
fn text_body(bytes: &[u8]) -> G {
    let text = String::from_utf8_lossy(bytes);
    if text.trim().is_empty() {
        return G::Obj(Vec::new());
    }
    if text.trim_start().starts_with('{') {
        if let Ok(o) = gson::parse_object(&text) {
            return o;
        }
    }
    G::Obj(vec![("body".to_string(), G::Str(text.into_owned()))])
}

fn unreadable(detail: impl std::fmt::Display) -> BodyError {
    (StatusCode::BAD_REQUEST, format!("400 BAD_REQUEST \"Failed to read HTTP message: {detail}\""))
}

/// The text fields of a multipart body (file parts are left out).
async fn multipart_body(boundary: Option<String>, bytes: Bytes) -> Result<G, BodyError> {
    let Some(boundary) = boundary else { return Err(unreadable("the multipart boundary is missing")) };
    let mut parts = multer::Multipart::new(futures::stream::once(async move { Ok::<_, Infallible>(bytes) }), boundary);
    let mut pairs = Vec::new();
    while let Some(field) = parts.next_field().await.map_err(unreadable)? {
        if field.file_name().is_some() {
            continue;
        }
        let name = field.name().unwrap_or("").to_string();
        let text = field.text().await.map_err(unreadable)?;
        pairs.push((name, text));
    }
    Ok(pairs_object(pairs.into_iter()))
}

/// Name and value pairs as an object, in first-seen order; a repeated name becomes a list.
pub fn pairs_object(pairs: impl Iterator<Item = (String, String)>) -> G {
    let mut out: Vec<(String, G)> = Vec::new();
    for (k, v) in pairs {
        match out.iter_mut().find(|(n, _)| *n == k) {
            Some((_, G::Arr(a))) => a.push(G::Str(v)),
            Some((_, slot)) => {
                let first = std::mem::replace(slot, G::Null);
                *slot = G::Arr(vec![first, G::Str(v)]);
            }
            None => out.push((k, G::Str(v))),
        }
    }
    G::Obj(out)
}

/// The request as it came, for a signature check: the body's exact bytes (UTF-8 text, else
/// base64), every header (lower-case names, repeated ones joined by `, `), every query parameter
/// (a repeated one as a list, one without a value as `""`).
pub fn raw_request(bytes: &[u8], headers: &HeaderMap, query: &[(String, Option<String>)]) -> Vec<(String, G)> {
    let (raw, encoding) = match std::str::from_utf8(bytes) {
        Ok(s) => (s.to_string(), "utf8"),
        Err(_) => (base64::engine::general_purpose::STANDARD.encode(bytes), "base64"),
    };
    let mut hs: Vec<(String, G)> = Vec::new();
    for (name, value) in headers {
        let v = String::from_utf8_lossy(value.as_bytes()).into_owned();
        match hs.iter_mut().find(|(n, _)| n == name.as_str()) {
            Some((_, G::Str(s))) => {
                s.push_str(", ");
                s.push_str(&v);
            }
            _ => hs.push((name.as_str().to_string(), G::Str(v))),
        }
    }
    let query = pairs_object(query.iter().map(|(k, v)| (k.clone(), v.clone().unwrap_or_default())));
    vec![
        (RAW_BODY.to_string(), G::Str(raw)),
        (RAW_BODY_ENCODING.to_string(), G::Str(encoding.to_string())),
        (HEADERS.to_string(), G::Obj(hs)),
        (QUERY.to_string(), query),
    ]
}

/// The body's arguments with the raw request's over them.
pub fn webhook_arguments(body: Option<&G>, raw: Vec<(String, G)>) -> G {
    let mut args = match body {
        Some(b @ G::Obj(_)) => b.clone(),
        _ => G::Obj(Vec::new()),
    };
    for (k, v) in raw {
        args.set(&k, v);
    }
    args
}

/// The reply a webhook function's output event sets, if it sets one: `None` leaves the answer to
/// the route's usual handling (also when the output can not be read: that handling says why).
pub fn reply(text: Option<&str>, def: &JMap) -> Result<Option<Response>, AppError> {
    let Some(text) = text.filter(|t| !t.trim().is_empty()) else { return Ok(None) };
    let Some(output) = str_field(def, "outputEventName").filter(|s| !s.trim().is_empty()) else { return Ok(None) };
    let Ok(events) = gson::parse_array(text) else { return Ok(None) };
    match output_value(&events, output, str_field(def, "outputEventParamName")) {
        Ok(Some(v @ G::Obj(_))) if REPLY_KEYS.iter().any(|k| v.has(k)) => build_reply(&v).map(Some),
        _ => Ok(None),
    }
}

/// A primitive's text; anything else as JSON.
fn text_of(v: &G) -> String {
    match v {
        G::Str(s) => s.clone(),
        other if other.is_primitive() => other.as_string().unwrap_or_default(),
        other => gson::to_string(other),
    }
}

/// The reply's status: 200 when not set, else a whole number from 100 to 599.
fn reply_status(v: Option<&G>) -> Result<StatusCode, AppError> {
    let v = match v {
        None | Some(G::Null) => return Ok(StatusCode::OK),
        Some(v) => v,
    };
    let code = match v {
        G::Num(_) | G::Str(_) => v.as_double().filter(|d| d.fract() == 0.0 && (100.0..=599.0).contains(d)),
        _ => None,
    };
    code.and_then(|c| StatusCode::from_u16(c as u16).ok()).ok_or_else(|| {
        let shown = text_of(v);
        crate::catalogue::literal("UI.WEBHOOK_REPLY_STATUS_INVALID", StatusCode::INTERNAL_SERVER_ERROR, format!("Reply status {shown} is not an HTTP status"))
            .param("status", shown)
            .into()
    })
}

fn build_reply(out: &G) -> Result<Response, AppError> {
    let status = reply_status(out.get("status"))?;
    let (body, default_type) = match out.get("body") {
        None | Some(G::Null) => (String::new(), None),
        Some(G::Str(s)) => (s.clone(), Some("text/plain;charset=UTF-8")),
        Some(other) => (gson::to_string(other), Some("application/json;charset=UTF-8")),
    };
    let mut resp = (status, body).into_response();
    let h = resp.headers_mut();
    h.remove(header::CONTENT_TYPE);
    if let Some(G::Obj(m)) = out.get("headers") {
        for (k, v) in m {
            if matches!(v, G::Null) || SERVER_HEADERS.contains(&k.to_ascii_lowercase().as_str()) {
                continue;
            }
            if let (Ok(name), Ok(value)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(&text_of(v))) {
                h.append(name, value);
            }
        }
    }
    let explicit = out.get("contentType").filter(|c| !matches!(c, G::Null)).and_then(|c| HeaderValue::from_str(&text_of(c)).ok());
    match explicit {
        Some(ct) => {
            h.insert(header::CONTENT_TYPE, ct);
        }
        None => {
            if let (false, Some(d)) = (h.contains_key(header::CONTENT_TYPE), default_type) {
                h.insert(header::CONTENT_TYPE, HeaderValue::from_static(d));
            }
        }
    }
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(pairs: &[(&str, G)]) -> G {
        G::Obj(pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect())
    }

    fn s(v: &str) -> G {
        G::Str(v.into())
    }

    async fn parsed(ct: &str, body: &str) -> Result<G, BodyError> {
        parse_body(ct, &Bytes::from(body.to_string())).await
    }

    #[test]
    fn webhook_flag_and_kinds() {
        let mut m = JMap::new();
        assert!(!is_webhook(&m));
        m.insert("webhook".into(), JValue::Str("true".into()));
        assert!(!is_webhook(&m), "only a boolean true");
        m.insert("webhook".into(), JValue::Bool(true));
        assert!(is_webhook(&m));
        assert_eq!(body_kind(""), BodyKind::Json);
        assert_eq!(body_kind("application/json; charset=UTF-8"), BodyKind::Json);
        assert_eq!(body_kind("Application/X-WWW-Form-Urlencoded; charset=UTF-8"), BodyKind::Form);
        assert_eq!(body_kind("multipart/form-data; boundary=XyZ"), BodyKind::Multipart(Some("XyZ".into())));
        assert_eq!(body_kind("multipart/form-data"), BodyKind::Multipart(None));
        assert_eq!(body_kind("text/plain"), BodyKind::Text);
        assert_eq!(body_kind("text/xml"), BodyKind::Text);
        assert_eq!(body_kind("application/xml"), BodyKind::Text);
        assert_eq!(body_kind("application/soap+xml; charset=utf-8"), BodyKind::Text);
    }

    #[tokio::test]
    async fn bodies_by_content_type() {
        // JSON as before.
        assert_eq!(parsed("application/json", r#"{"a":1.50}"#).await.unwrap(), obj(&[("a", G::Num("1.50".into()))]));
        assert_eq!(parsed("", "  ").await.unwrap(), obj(&[]));
        assert_eq!(parsed("application/json", "[1]").await.unwrap_err().0, StatusCode::INTERNAL_SERVER_ERROR);
        // A form: decoded, a repeated name a list.
        let f = parsed("application/x-www-form-urlencoded", "From=%2B91+98&To=x&tag=a&tag=b&tag=c&flag").await.unwrap();
        assert_eq!(
            f,
            obj(&[
                ("From", s("+91 98")),
                ("To", s("x")),
                ("tag", G::Arr(vec![s("a"), s("b"), s("c")])),
                ("flag", s("")),
            ])
        );
        // Text and XML: the body argument; a JSON object in a text body stays the object.
        assert_eq!(parsed("text/plain", "hello world").await.unwrap(), obj(&[("body", s("hello world"))]));
        assert_eq!(parsed("application/xml", "<a>1</a>").await.unwrap(), obj(&[("body", s("<a>1</a>"))]));
        assert_eq!(parsed("text/plain", r#"{"a":true}"#).await.unwrap(), obj(&[("a", G::Bool(true))]));
        assert_eq!(parsed("text/plain", "{not json").await.unwrap(), obj(&[("body", s("{not json"))]));
        assert_eq!(parsed("text/plain", " ").await.unwrap(), obj(&[]));
    }

    #[tokio::test]
    async fn multipart_text_fields() {
        let body = "--XB\r\nContent-Disposition: form-data; name=\"CallSid\"\r\n\r\nabc 1\r\n\
                    --XB\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\nfile data\r\n\
                    --XB\r\nContent-Disposition: form-data; name=\"tag\"\r\n\r\nx\r\n\
                    --XB\r\nContent-Disposition: form-data; name=\"tag\"\r\n\r\ny\r\n--XB--\r\n";
        let m = parsed("multipart/form-data; boundary=XB", body).await.unwrap();
        assert_eq!(m, obj(&[("CallSid", s("abc 1")), ("tag", G::Arr(vec![s("x"), s("y")]))]));
        let (status, debug) = parsed("multipart/form-data", body).await.unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(debug.starts_with("400 BAD_REQUEST \"Failed to read HTTP message"), "{debug}");
        assert_eq!(parsed("multipart/form-data; boundary=XB", "garbage").await.unwrap_err().0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn the_raw_request() {
        let mut h = HeaderMap::new();
        h.insert("X-Hub-Signature-256", HeaderValue::from_static("sha256=ab"));
        h.append("x-multi", HeaderValue::from_static("1"));
        h.append("x-multi", HeaderValue::from_static("2"));
        let q = vec![("hub.mode".to_string(), Some("subscribe".to_string())), ("k".into(), Some("1".into())), ("k".into(), None)];
        let body = br#"{ "b":1,  "a":2 }"#;
        let raw = raw_request(body, &h, &q);
        let args = webhook_arguments(Some(&obj(&[("a", G::Num("2".into())), ("rawBody", s("from the body"))])), raw);
        assert_eq!(args.get("rawBody"), Some(&s(r#"{ "b":1,  "a":2 }"#)), "the bytes as sent, spaces and order kept");
        assert_eq!(args.get("rawBodyEncoding"), Some(&s("utf8")));
        assert_eq!(args.get("headers").and_then(|h| h.get("x-hub-signature-256")), Some(&s("sha256=ab")));
        assert_eq!(args.get("headers").and_then(|h| h.get("x-multi")), Some(&s("1, 2")));
        assert_eq!(args.get("query"), Some(&obj(&[("hub.mode", s("subscribe")), ("k", G::Arr(vec![s("1"), s("")]))])));
        assert_eq!(args.get("a"), Some(&G::Num("2".into())));
        let binary = raw_request(&[0xff, 0x00, 0x41], &HeaderMap::new(), &[]);
        assert_eq!(binary[0].1, s("/wBB"));
        assert_eq!(binary[1].1, s("base64"));
        assert_eq!(webhook_arguments(Some(&s("x")), vec![]), obj(&[]));
        assert_eq!(webhook_arguments(None, vec![]), obj(&[]));
    }

    fn def(param: Option<&str>) -> JMap {
        let mut m = JMap::new();
        m.insert("outputEventName".into(), JValue::Str("output".into()));
        if let Some(p) = param {
            m.insert("outputEventParamName".into(), JValue::Str(p.into()));
        }
        m
    }

    async fn reply_of(result: &str, param: Option<&str>) -> Option<(StatusCode, Option<String>, Vec<(String, String)>, String)> {
        let text = format!(r#"[{{"name":"output","result":{result}}}]"#);
        let r = reply(Some(&text), &def(param)).unwrap()?;
        let status = r.status();
        let ct = r.headers().get("content-type").map(|v| v.to_str().unwrap().to_string());
        let hs = r.headers().iter().filter(|(k, _)| k.as_str().starts_with("x-")).map(|(k, v)| (k.to_string(), v.to_str().unwrap().to_string())).collect();
        let body = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
        Some((status, ct, hs, String::from_utf8(body.to_vec()).unwrap()))
    }

    #[tokio::test]
    async fn replies_the_function_sets() {
        // A text reply (Meta's hub.challenge).
        let (st, ct, _, body) = reply_of(r#"{"body":"1158201444"}"#, None).await.unwrap();
        assert_eq!((st, ct.as_deref(), body.as_str()), (StatusCode::OK, Some("text/plain;charset=UTF-8"), "1158201444"));
        // JSON, with a status and headers, through the output parameter.
        let (st, ct, hs, body) =
            reply_of(r#"{"reply":{"status":201.0,"headers":{"X-Trace":"t1","x-n":5,"x-null":null,"Content-Length":"9","bad name":"v"},"body":{"select":"agent","n":1.50}}}"#, Some("result.reply"))
                .await
                .unwrap();
        assert_eq!(st, StatusCode::CREATED);
        assert_eq!(ct.as_deref(), Some("application/json;charset=UTF-8"));
        assert_eq!(hs, vec![("x-trace".to_string(), "t1".to_string()), ("x-n".to_string(), "5".to_string())]);
        assert_eq!(body, r#"{"select":"agent","n":1.50}"#);
        // An empty 200, and an explicit content type over a header's.
        let (st, ct, _, body) = reply_of(r#"{"status":"200"}"#, None).await.unwrap();
        assert_eq!((st, ct, body.as_str()), (StatusCode::OK, None, ""));
        let (_, ct, _, _) = reply_of(r#"{"body":"<Response/>","contentType":"application/xml","headers":{"Content-Type":"text/html"}}"#, None).await.unwrap();
        assert_eq!(ct.as_deref(), Some("application/xml"));
        let (_, ct, _, _) = reply_of(r#"{"body":"<p>","headers":{"Content-Type":"text/html"}}"#, None).await.unwrap();
        assert_eq!(ct.as_deref(), Some("text/html"));
        let (st, _, _, _) = reply_of(r#"{"status":null,"body":null}"#, None).await.unwrap();
        assert_eq!(st, StatusCode::OK);
        // Not a reply: the usual answer.
        assert!(reply_of(r#"{"result":{"ok":true}}"#, None).await.is_none());
        assert!(reply_of(r#"{"result":"text"}"#, Some("result")).await.is_none());
        assert!(reply(None, &def(None)).unwrap().is_none());
        assert!(reply(Some("  "), &def(None)).unwrap().is_none());
        assert!(reply(Some(r#"[{"name":"output","result":{"body":"x"}}]"#), &JMap::new()).unwrap().is_none());
        assert!(reply(Some("not json"), &def(None)).unwrap().is_none());
        assert!(reply(Some(r#"[{"name":"output"}]"#), &def(None)).unwrap().is_none());
        // A status that is not one.
        for bad in [r#""abc""#, "99", "600", "200.5", "true", "[200]"] {
            let text = format!(r#"[{{"name":"output","result":{{"status":{bad}}}}}]"#);
            let e = reply(Some(&text), &def(None)).unwrap_err();
            assert!(matches!(&e, AppError::Coded(c) if c.code == "UI.WEBHOOK_REPLY_STATUS_INVALID"), "{bad}");
            assert_eq!(e.status(), StatusCode::INTERNAL_SERVER_ERROR);
        }
    }
}
