//! `BasicRestService`: compose the URL from the connection's `baseUrl` and the request's, guard
//! the target, add the connection's headers (basic auth, `defaultHeaders`), encode the body by
//! content type, call, and read the response by its content type.

use std::time::Duration;

use base64::Engine;
use http::StatusCode;
use serde_json::Value;

use super::body;
use super::http::{OutboundRequest, OutboundResponse};
use super::media_type::{self, MediaType};
use super::spring_uri::{self, WebClientEncodingMode};
use super::{RestData, RestRequest, RestResponse};
use crate::connection::Connection;
use crate::error::{messages, ConnError, ConnResult};
use crate::java::{self, json};
use crate::{outbound, Connections};

/// WebClient's codecs buffer at most 50 MB.
pub const MAX_IN_MEMORY: usize = 50 * 1024 * 1024;

/// Spring `HttpHeaders` (a `LinkedCaseInsensitiveMap<String, List<String>>`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HeaderBag {
    entries: Vec<(String, Vec<String>)>,
}

impl HeaderBag {
    fn position(&self, name: &str) -> Option<usize> {
        self.entries.iter().position(|(k, _)| k.eq_ignore_ascii_case(name))
    }

    /// `set`: replaces the values; a name differing only in case moves to the end with the
    /// new spelling, an identical name keeps its place.
    pub fn set(&mut self, name: &str, value: &str) {
        match self.position(name) {
            Some(i) if self.entries[i].0 == name => self.entries[i].1 = vec![value.to_string()],
            Some(i) => {
                self.entries.remove(i);
                self.entries.push((name.to_string(), vec![value.to_string()]));
            }
            None => self.entries.push((name.to_string(), vec![value.to_string()])),
        }
    }

    /// `add` / `addAll`: appends to the existing entry, keeping its spelling and place.
    pub fn add(&mut self, name: &str, value: &str) {
        match self.position(name) {
            Some(i) => self.entries[i].1.push(value.to_string()),
            None => self.entries.push((name.to_string(), vec![value.to_string()])),
        }
    }

    pub fn first(&self, name: &str) -> Option<&str> {
        self.position(name).and_then(|i| self.entries[i].1.first()).map(String::as_str)
    }

    /// Header lines in order, one per value.
    pub fn lines(&self) -> Vec<(String, String)> {
        self.entries.iter().flat_map(|(k, vs)| vs.iter().map(move |v| (k.clone(), v.clone()))).collect()
    }

    /// `getContentType()`: the first value parsed, `None` when absent or empty.
    pub fn content_type(&self) -> Result<Option<MediaType>, ConnError> {
        match self.first("Content-Type") {
            Some(v) if !v.is_empty() => MediaType::parse(v).map(Some),
            _ => Ok(None),
        }
    }
}

/// The URL, headers and timeout `applyConnectionDetails` derives from the connection.
#[derive(Debug, Clone, PartialEq)]
pub struct Applied {
    pub url: String,
    pub headers: HeaderBag,
    pub timeout: Duration,
}

/// `applyConnectionDetails`. `None` when the connection has no details (Java then refuses
/// with "Connection details missing").
pub fn apply_connection_details(
    conn: &Connection,
    url: &str,
    ignore_default_headers: bool,
    timeout: i32,
) -> ConnResult<Option<Applied>> {
    let mut headers = HeaderBag::default();
    let mut timeout_duration = Duration::from_secs(if timeout < 1 { 300 } else { timeout as u64 });

    let Some(details) = conn.details().filter(|d| !d.is_empty()) else { return Ok(None) };

    // `instanceof Integer`: a whole number in int range (Mongo int32).
    if let Some(con_timeout) = details.get("timeout").and_then(Value::as_i64).filter(|t| i32::try_from(*t).is_ok()) {
        let secs = if timeout < 1 { con_timeout } else { timeout as i64 };
        timeout_duration = Duration::from_secs(secs.max(0) as u64);
    }

    if details.contains_key("userName") && details.contains_key("password") {
        let user = cast_string(details.get("userName"), "userName")?;
        let password = cast_string(details.get("password"), "password")?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}").as_bytes());
        headers.set("Authorization", &format!("Basic {encoded}"));
    }

    if !ignore_default_headers {
        if let Some(Value::Object(default_headers)) = details.get("defaultHeaders") {
            for (k, v) in default_headers {
                if !v.is_null() {
                    headers.set(k, &java::to_java_string(v));
                }
            }
        }
    }

    let mut url = url.to_string();
    if details.contains_key("baseUrl") {
        let base = match details.get("baseUrl") {
            Some(Value::Null) | None => {
                return Err(ConnError::other(
                    "Cannot invoke \"Object.toString()\" because the return value of \"java.util.Map.get(Object)\" is null",
                ))
            }
            Some(v) => java::to_java_string(v),
        };
        let mut base = base;
        if java::trim(&base).ends_with('/') {
            if let Some(i) = base.rfind('/') {
                base.truncate(i);
            }
        }
        if java::trim(&url).starts_with('/') {
            url = url.chars().skip(1).collect();
        }
        url = format!("{base}/{url}");
    }

    Ok(Some(Applied { url, headers, timeout: timeout_duration }))
}

/// `(String) value`: a cast that fails for anything but a string or null.
fn cast_string(v: Option<&Value>, _what: &str) -> ConnResult<String> {
    match v {
        None | Some(Value::Null) => Ok("null".into()),
        Some(Value::String(s)) => Ok(s.clone()),
        Some(other) => {
            let class = java_class_name(other);
            Err(ConnError::other(format!(
                "class {class} cannot be cast to class java.lang.String ({class} and java.lang.String are in module java.base of loader 'bootstrap')"
            )))
        }
    }
}

fn java_class_name(v: &Value) -> &'static str {
    match v {
        Value::Bool(_) => "java.lang.Boolean",
        Value::Number(n) if n.is_f64() => "java.lang.Double",
        Value::Number(_) => "java.lang.Integer",
        Value::Array(_) => "java.util.ArrayList",
        Value::Object(_) => "java.util.LinkedHashMap",
        _ => "java.lang.Object",
    }
}

/// `BasicRestService.call`.
pub async fn call(svc: &Connections, conn: &Connection, request: RestRequest, file_download: bool) -> ConnResult<Option<RestResponse>> {
    let Some(applied) = apply_connection_details(conn, &request.url, request.ignore_default_headers, request.timeout)? else {
        return Err(ConnError::msg_as(StatusCode::BAD_REQUEST, messages::CONNECTION_DETAILS_MISSING, "CORE.CONNECTION_INCOMPLETE", &[conn.name()]));
    };

    // The composed URL is the only place the real target is known.
    if svc.config.block_private_targets {
        if let Err(e) = outbound::guard_target(&applied.url).await {
            tracing::warn!("Outbound call refused: {}", e.message());
            return Err(e);
        }
    }

    let mut headers = applied.headers;
    if let Some(req_headers) = &request.headers {
        for (k, vs) in req_headers {
            for v in vs {
                headers.add(k, v);
            }
        }
    }

    let mode = WebClientEncodingMode::value_of(
        &conn.detail("encodingMode").map(java::to_java_string).unwrap_or_else(|| "TEMPLATE_AND_VALUES".into()),
    )?;

    // WebClient.builder().baseUrl(url) parses the URL before anything else.
    let query: Vec<(String, String)> = request.query_parameters.clone().unwrap_or_default();
    let uri = spring_uri::build_request_uri(&applied.url, mode, &query, &request.path_parameters)?;

    let method = request.method.clone();
    let no_body = request.payload.is_none() && (method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("DELETE"));
    if no_body {
        let out = OutboundRequest { method, uri, headers: headers.lines(), body: None };
        return exchange(svc, out, applied.timeout, file_download).await.map(Some);
    }

    let content_type = headers.content_type()?;

    if let Some(ct) = content_type.as_ref().filter(|ct| ct.is_compatible_with(&media_type::multipart_form_data())) {
        let payload = request.payload.as_ref().ok_or_else(npe_form_payload)?;
        let parts = body::multipart_parts(payload)?;
        let (bytes, header) = body::multipart_body(&parts, ct, &body::boundary());
        headers.set("Content-Type", &header);
        let out = OutboundRequest { method, uri, headers: headers.lines(), body: Some(bytes) };
        return exchange(svc, out, applied.timeout, file_download).await.map(Some);
    }

    if let Some(ct) = content_type.as_ref().filter(|ct| ct.is_compatible_with(&media_type::application_form_urlencoded())) {
        let payload = request.payload.as_ref().ok_or_else(npe_form_payload)?;
        let bytes = body::form_body(payload);
        headers.set("Content-Type", &ct.to_header());
        let out = OutboundRequest { method, uri, headers: headers.lines(), body: Some(bytes) };
        return exchange(svc, out, applied.timeout, file_download).await.map(Some);
    }

    let payload = request.payload.as_ref().ok_or_else(npe_payload)?;
    if !payload.is_null() && !payload.is_object() {
        return Err(ConnError::other(format!("Not a JSON Object: {}", json::gson_element(payload))));
    }

    // From here on any failure is answered, not raised: `onErrorReturn`.
    let url_not_found = || RestResponse::message(StatusCode::BAD_REQUEST, "Url not found with the given connection");
    if !media_type::jackson_can_encode(content_type.as_ref()) {
        return Ok(Some(url_not_found()));
    }
    if content_type.is_none() {
        headers.set("Content-Type", "application/json");
    }
    let out = OutboundRequest { method, uri, headers: headers.lines(), body: Some(body::json_body(payload)) };
    match exchange(svc, out, applied.timeout, file_download).await {
        Ok(r) => Ok(Some(r)),
        Err(_) => Ok(Some(url_not_found())),
    }
}

fn npe_payload() -> ConnError {
    ConnError::other(
        "Cannot invoke \"com.google.gson.JsonElement.isJsonNull()\" because the return value of \"com.fincity.saas.commons.core.dto.RestRequest.getPayload()\" is null",
    )
}

fn npe_form_payload() -> ConnError {
    ConnError::other("Cannot invoke \"com.google.gson.JsonElement.isJsonObject()\" because \"payload\" is null")
}

/// Sends, then reads the response as `handleResponse` does. A failure before the response
/// head arrives is an error; a failure reading the body is a 500 "Error occurred" response.
async fn exchange(svc: &Connections, out: OutboundRequest, timeout: Duration, file_download: bool) -> ConnResult<RestResponse> {
    let response = match tokio::time::timeout(timeout, svc.http.send(out)).await {
        Ok(r) => r?,
        Err(_) => return Ok(error_response(&timeout_message(timeout))),
    };
    handle_response(response, timeout, file_download).await
}

fn timeout_message(timeout: Duration) -> String {
    format!(
        "Did not observe any item or terminal signal within {}ms in 'defaultIfEmpty' (and no fallback has been configured)",
        timeout.as_millis()
    )
}

/// `createErrorResponse`.
fn error_response(message: &str) -> RestResponse {
    RestResponse { data: RestData::Text(format!("Error occurred: {message}")), headers: None, status: 500 }
}

/// `handleResponse`: the status and headers always; the body by content type. An empty body
/// leaves `data` null.
pub async fn handle_response(response: OutboundResponse, timeout: Duration, file_download: bool) -> ConnResult<RestResponse> {
    let headers = response.single_value_map();
    let status = response.status as i32;
    let content_type = match response.first("Content-Type").filter(|v| !v.is_empty()) {
        Some(v) => Some(MediaType::parse(v)?),
        None => None,
    };
    let content_disposition_filename = response.first("Content-Disposition").is_some_and(has_filename);

    let read = tokio::time::timeout(timeout, response.read_body(MAX_IN_MEMORY)).await;
    let bytes = match read {
        Err(_) => return Ok(error_response(&timeout_message(timeout))),
        Ok(Err(e)) => return Ok(error_response(e.message())),
        Ok(Ok(b)) => b,
    };
    let mut out = RestResponse { data: RestData::None, headers: Some(headers), status };
    if bytes.is_empty() {
        return Ok(out);
    }

    let Some(ct) = content_type else {
        out.data = RestData::Text(decode_text(&bytes, None));
        return Ok(out);
    };

    if ct.is_compatible_with(&media_type::application_json()) {
        let text = decode_text(&bytes, ct.charset().as_deref());
        match process_json_response(&text) {
            Ok(data) => out.data = data,
            Err(e) => return Ok(error_response(&e)),
        }
        return Ok(out);
    }

    if file_download || content_disposition_filename || ct.type_ == "application" {
        out.data = RestData::Binary(bytes);
        return Ok(out);
    }

    out.data = RestData::Text(decode_text(&bytes, ct.charset().as_deref()));
    Ok(out)
}

/// `ContentDisposition.parse(..).getFilename() != null`: a `filename` or `filename*`
/// parameter.
fn has_filename(cd: &str) -> bool {
    cd.split(';').skip(1).any(|p| {
        let p = p.trim();
        let name = p.split('=').next().unwrap_or("").trim().to_ascii_lowercase();
        (name == "filename" || name == "filename*") && p.contains('=')
    })
}

/// `bodyToMono(String)`: the charset from the content type, UTF-8 otherwise.
fn decode_text(bytes: &[u8], charset: Option<&str>) -> String {
    match charset.map(|c| c.to_ascii_lowercase()) {
        Some(c) if c == "iso-8859-1" || c == "latin1" || c == "us-ascii" => bytes.iter().map(|b| *b as char).collect(),
        _ => String::from_utf8_lossy(bytes).into_owned(),
    }
}

/// `processJsonResponse`: primitives as they are, objects and arrays read into Java maps and
/// lists (every number a double). A blank body is no data.
pub fn process_json_response(text: &str) -> Result<RestData, String> {
    if java::is_blank(text) {
        return Ok(RestData::None);
    }
    let v: Value = serde_json::from_str(text).map_err(|e| format!("com.google.gson.JsonSyntaxException: {e}"))?;
    Ok(match v {
        Value::Null => RestData::None,
        Value::Object(_) | Value::Array(_) => RestData::Json(json::numbers_as_doubles(v)),
        other => RestData::Json(other),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn conn(details: Value) -> Connection {
        Connection::from_json(json!({"name": "c", "connectionType": "REST_API", "connectionDetails": details})).unwrap()
    }

    #[test]
    fn composes_url_and_headers() {
        let c = conn(json!({
            "baseUrl": "https://api.example.com/v1/",
            "userName": "u", "password": "p",
            "defaultHeaders": {"Content-Type": "application/json", "X-N": 5, "Skip": null},
            "timeout": 30
        }));
        let a = apply_connection_details(&c, "/users", false, 0).unwrap().unwrap();
        assert_eq!(a.url, "https://api.example.com/v1/users");
        assert_eq!(a.timeout, Duration::from_secs(30));
        assert_eq!(
            a.headers.lines(),
            vec![
                ("Authorization".into(), "Basic dTpw".into()),
                ("Content-Type".into(), "application/json".into()),
                ("X-N".into(), "5".into())
            ]
        );
        let a = apply_connection_details(&c, "users", true, 7).unwrap().unwrap();
        assert_eq!(a.timeout, Duration::from_secs(7));
        assert_eq!(a.headers.lines().len(), 1);
        // No baseUrl: the request URL as it is.
        let a = apply_connection_details(&conn(json!({"x": 1})), "https://h.com/a", false, 0).unwrap().unwrap();
        assert_eq!(a.url, "https://h.com/a");
        assert_eq!(a.timeout, Duration::from_secs(300));
        assert!(apply_connection_details(&conn(json!({})), "x", false, 0).unwrap().is_none());
    }

    #[test]
    fn header_bag_is_case_insensitive() {
        let mut h = HeaderBag::default();
        h.set("Authorization", "a");
        h.add("authorization", "b");
        h.set("X", "1");
        h.set("x", "2");
        assert_eq!(h.lines(), vec![("Authorization".into(), "a".into()), ("Authorization".into(), "b".into()), ("x".into(), "2".into())]);
    }

    #[test]
    fn json_responses() {
        assert_eq!(process_json_response("   ").unwrap(), RestData::None);
        assert_eq!(process_json_response("{\"a\":1}").unwrap(), RestData::Json(json!({"a": 1.0})));
        assert_eq!(process_json_response("12").unwrap(), RestData::Json(json!(12)));
        assert!(process_json_response("{oops").is_err());
        assert_eq!(RestData::Binary(vec![1, 255]).to_gson_tree(), json!([1, -1]));
        assert!(has_filename("attachment; filename=\"a.pdf\""));
        assert!(!has_filename("inline"));
    }
}
