//! Errors in the shape the Java services send them, so callers (pages, KIRun functions, Feign
//! clients in other services) read Rust errors exactly like Java ones.
//!
//! Java body (`GenericException.GenericExceptionData`):
//! `{"exceptionId": "...", "message": "...", "stackTrace": "...", "debugMessage": "..."}`.
//!
//! A coded error ([`AppError::Coded`], from the message catalogue in [`crate::messages`]) keeps
//! those four fields and adds four:
//! - `message`: the text in the request's language, what happened and why, in plain words;
//! - `debugMessage`: the technical detail in English (the Java key, ids, the code), for support;
//! - `code`: the stable code (`SEC.APP_ACCESS_FORBIDDEN`), for support, tests and translations;
//! - `action`: what to do next, when there is something to do;
//! - `params`: the values named in the message;
//! - `locale`: the language of `message`.
//!
//! A coded error another Rust unit answered with (a security refusal a service passes on, as the
//! Java services pass on a Feign error) is relayed as it came: its code, values, texts and
//! `debugMessage`, with the status it came with ([`Coded::relay`]).
//!
//! One deliberate difference: `stackTrace` is always empty. The Java services send their full
//! server stack to anyone who triggers an error, including anonymous callers.

use std::borrow::Cow;

use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::http::spring_security_headers;
use crate::java::exception_id;
use crate::messages::{self, Rendered};

pub type AppResult<T> = Result<T, AppError>;

/// Every coded error rendered for a response, by `code` and `status` ([`Coded::render`]).
pub const CODED_ERRORS: &str = "coded_errors_total";

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// A message for the caller, as `GenericException(status, message)`.
    #[error("{status}: {message}")]
    Message { status: StatusCode, message: String },

    /// No body, the way Spring Security refuses (403) or a download reports a missing file (404).
    #[error("{0}")]
    Empty(StatusCode),

    /// Anything unexpected: logged with an id, and the caller gets only the id.
    #[error(transparent)]
    Internal(#[from] anyhow::Error),

    /// A message from the catalogue, by code.
    #[error("{}: {}", .0.resolved_status(), .0.code)]
    Coded(Box<Coded>),
}

impl AppError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self::Message { status, message: message.into() }
    }

    /// `msgService.throwMessage(status, MESSAGE_ID, params...)`.
    pub fn msg(status: StatusCode, template: &str, params: &[&str]) -> Self {
        Self::new(status, format_message(template, params))
    }

    pub fn status(&self) -> StatusCode {
        match self {
            Self::Message { status, .. } => *status,
            Self::Empty(s) => *s,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Coded(c) => c.resolved_status(),
        }
    }

    /// A refused caller who is not signed in: "You're signed out" when the request carried
    /// credentials that were not accepted, "Please sign in" when it carried none. 401.
    pub fn unauthenticated() -> Self {
        Coded::unauthenticated().into()
    }

    /// `@PreAuthorize` refusing a signed-in caller: names the permission(s), any one of which
    /// would do. 403.
    pub fn permission_required(any_of: &[&str]) -> Self {
        Coded::permission_required(any_of).into()
    }

    /// The English text this error stands for, as Java's `getMessage()` would give it (what a
    /// caller that records failures keeps).
    pub fn english_message(&self) -> String {
        match self {
            Self::Message { message, .. } => message.clone(),
            Self::Empty(s) => s.to_string(),
            Self::Internal(e) => e.to_string(),
            Self::Coded(c) => c.english().message,
        }
    }
}

/// A catalogue message: its code, the values it names, and the technical detail for support.
#[derive(Debug, Clone, PartialEq)]
pub struct Coded {
    pub code: Cow<'static, str>,
    /// Named values (`app`, `permission`...), as given: kinds (labels) apply when rendered.
    pub params: Vec<(String, String)>,
    /// The status when it differs from the catalogue's (a Java status kept for parity).
    pub status: Option<StatusCode>,
    /// The English technical detail for `debugMessage`; the code and values when not given.
    pub debug: Option<String>,
    /// The texts another unit already wrote for this code, sent as they came ([`Coded::relay`]).
    pub relayed: Option<Box<RelayedTexts>>,
}

/// What another unit's coded error body said, in the language it chose. The code need not be in
/// this unit's catalogue (a security code relayed by core), so the texts are not rendered again.
#[derive(Debug, Clone, PartialEq)]
pub struct RelayedTexts {
    pub message: String,
    pub action: Option<String>,
    pub locale: String,
}

impl Coded {
    pub fn new(code: impl Into<Cow<'static, str>>) -> Self {
        Self { code: code.into(), params: Vec::new(), status: None, debug: None, relayed: None }
    }

    /// A coded error body another Rust unit answered with (`code`, `message`, `action`,
    /// `params`, `locale`, `debugMessage`), to pass on as it came with `status`: the Java
    /// services pass on another service's error the same way (its status and message), and the
    /// code, values and next step now ride along. `None` for any other body (a Java service's
    /// own, plain text, an empty one).
    pub fn relay(status: StatusCode, body: &[u8]) -> Option<Self> {
        let v: Value = serde_json::from_slice(body).ok()?;
        Self::relay_value(status, &v)
    }

    /// [`Coded::relay`] on a body already parsed.
    pub fn relay_value(status: StatusCode, v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        let text = |k: &str| o.get(k).and_then(Value::as_str).map(str::to_string);
        let code = text("code").filter(|c| !c.trim().is_empty())?;
        let message = text("message").filter(|m| !m.trim().is_empty())?;
        o.get("exceptionId")?;
        let params = match o.get("params") {
            Some(Value::Object(p)) => p
                .iter()
                .map(|(k, v)| (k.clone(), v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string())))
                .collect(),
            _ => Vec::new(),
        };
        let action = text("action").filter(|a| !a.trim().is_empty());
        let locale = text("locale").filter(|l| !l.trim().is_empty()).unwrap_or_else(|| "en".to_string());
        Some(Self {
            code: code.into(),
            params,
            status: Some(status),
            debug: Some(text("debugMessage").unwrap_or_else(|| message.clone())),
            relayed: Some(Box::new(RelayedTexts { message, action, locale })),
        })
    }

    /// Whether this error passes on another unit's texts.
    pub fn is_relayed(&self) -> bool {
        self.relayed.is_some()
    }

    /// Sets a value (replacing one of the same name).
    pub fn param(mut self, name: &str, value: impl ToString) -> Self {
        let value = value.to_string();
        match self.params.iter_mut().find(|(n, _)| n == name) {
            Some(slot) => slot.1 = value,
            None => self.params.push((name.to_string(), value)),
        }
        self
    }

    pub fn status(mut self, status: StatusCode) -> Self {
        self.status = Some(status);
        self
    }

    pub fn debug(mut self, debug: impl Into<String>) -> Self {
        self.debug = Some(debug.into());
        self
    }

    /// The given status, else the catalogue's, else 500.
    pub fn resolved_status(&self) -> StatusCode {
        self.status
            .or_else(|| messages::global().meta(&self.code).and_then(|m| m.status).and_then(|s| StatusCode::from_u16(s).ok()))
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
    }

    /// `debugMessage`: the detail given, else the code and its values.
    pub fn debug_text(&self) -> String {
        match &self.debug {
            Some(d) => d.clone(),
            None => {
                let mut s = self.code.to_string();
                for (k, v) in &self.params {
                    s.push_str(&format!(" {k}={v}"));
                }
                s
            }
        }
    }

    /// The message in English, whatever the request (for logs and Java-style `getMessage`). A
    /// relayed error reads as it came.
    pub fn english(&self) -> Rendered {
        match &self.relayed {
            Some(r) => self.relayed_rendered(r),
            None => messages::global().render(&self.code, &self.params, &["en".to_string()], ""),
        }
    }

    fn relayed_rendered(&self, r: &RelayedTexts) -> Rendered {
        Rendered {
            code: self.code.to_string(),
            message: r.message.clone(),
            action: r.action.clone(),
            params: self.params.iter().filter(|(_, v)| !v.trim().is_empty()).cloned().collect(),
            locale: r.locale.clone(),
        }
    }

    /// See [`AppError::unauthenticated`].
    pub fn unauthenticated() -> Self {
        let code = if messages::current_caller().credential_sent { "COMMON.SIGNED_OUT" } else { "COMMON.SIGN_IN_REQUIRED" };
        Self::new(code).status(StatusCode::UNAUTHORIZED)
    }

    /// See [`AppError::permission_required`].
    pub fn permission_required(any_of: &[&str]) -> Self {
        let mut c = Self::new("COMMON.PERMISSION_REQUIRED");
        if !any_of.is_empty() {
            c = c.param("permission", any_of.join(","));
        }
        c.debug(format!("Access Denied: needs {}", if any_of.is_empty() { "a permission".to_string() } else { any_of.join(" or ") }))
    }

    /// Renders this error for the current request: status, body, and the report later layers
    /// read. Counted in [`CODED_ERRORS`]: every coded answer, whichever unit's handler wrote it,
    /// is rendered here once.
    pub fn render(&self, exception_id: &str) -> (StatusCode, Vec<u8>, ErrorReport) {
        let status = self.resolved_status();
        metrics::counter!(CODED_ERRORS, "code" => self.code.to_string(), "status" => status.as_str().to_string()).increment(1);
        let rendered = match &self.relayed {
            Some(r) => self.relayed_rendered(r),
            None => messages::render(&self.code, &self.params, exception_id),
        };
        let report = ErrorReport {
            code: self.code.to_string(),
            params: self.params.clone(),
            status,
            debug: self.debug_text(),
            exception_id: exception_id.to_string(),
            locale: rendered.locale.clone(),
        };
        let body = coded_body(&report, &rendered);
        (status, body, report)
    }
}

impl From<Coded> for AppError {
    fn from(c: Coded) -> Self {
        Self::Coded(Box::new(c))
    }
}

/// What a coded error response carries for the layers after the handler (the client override
/// pass re-renders the body from it).
#[derive(Debug, Clone, PartialEq)]
pub struct ErrorReport {
    pub code: String,
    pub params: Vec<(String, String)>,
    pub status: StatusCode,
    pub debug: String,
    pub exception_id: String,
    /// The language the body was written in.
    pub locale: String,
}

/// The JSON body of a coded error.
pub fn coded_body(report: &ErrorReport, rendered: &Rendered) -> Vec<u8> {
    let mut m = Map::new();
    m.insert("exceptionId".into(), Value::from(report.exception_id.as_str()));
    m.insert("message".into(), Value::from(rendered.message.as_str()));
    m.insert("stackTrace".into(), Value::from(""));
    m.insert("debugMessage".into(), Value::from(report.debug.as_str()));
    m.insert("code".into(), Value::from(rendered.code.as_str()));
    if let Some(a) = &rendered.action {
        m.insert("action".into(), Value::from(a.as_str()));
    }
    let params: Map<String, Value> = rendered.params.iter().map(|(k, v)| (k.clone(), Value::from(v.as_str()))).collect();
    m.insert("params".into(), Value::Object(params));
    m.insert("locale".into(), Value::from(rendered.locale.as_str()));
    serde_json::to_vec(&Value::Object(m)).unwrap_or_default()
}

/// A coded error as a response with the platform's headers. Server faults are logged with the
/// detail; refusals at debug level.
pub fn coded_response(c: &Coded) -> Response {
    coded_response_logged(c, true)
}

/// [`coded_response`] logged at debug level whatever the status: for answers a service gives on
/// purpose, many times a second, whose cause is already logged once elsewhere (the gateway's open
/// circuit breaker logs its state changes).
pub fn coded_response_quiet(c: &Coded) -> Response {
    coded_response_logged(c, false)
}

fn coded_response_logged(c: &Coded, faults_as_errors: bool) -> Response {
    let id = exception_id();
    let (status, body, report) = c.render(&id);
    if status.is_server_error() && faults_as_errors {
        tracing::error!(exception_id = id, %status, code = %c.code, debug = report.debug, "request failed");
    } else {
        tracing::debug!(exception_id = id, %status, code = %c.code, debug = report.debug, "request refused");
    }
    let mut headers = HeaderMap::new();
    spring_security_headers(&mut headers, true);
    headers.insert(http::header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    let mut resp = (status, headers, body).into_response();
    resp.extensions_mut().insert(report);
    resp
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExceptionData<'a> {
    exception_id: &'a str,
    message: &'a str,
    stack_trace: &'a str,
    debug_message: &'a str,
}

fn json_error(status: StatusCode, id: &str, message: &str) -> Response {
    let body = serde_json::to_vec(&ExceptionData {
        exception_id: id,
        message,
        stack_trace: "",
        debug_message: message,
    })
    .unwrap_or_default();
    let mut headers = HeaderMap::new();
    spring_security_headers(&mut headers, true);
    headers.insert(http::header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    (status, headers, body).into_response()
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            Self::Message { status, message } => {
                let id = exception_id();
                if status.is_server_error() {
                    tracing::error!(exception_id = id, %status, message, "request failed");
                } else {
                    tracing::debug!(exception_id = id, %status, message, "request refused");
                }
                json_error(status, &id, &message)
            }
            Self::Empty(status) => {
                let mut headers = HeaderMap::new();
                spring_security_headers(&mut headers, true);
                headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("0"));
                (status, headers).into_response()
            }
            // A real fault: COMMON.INTERNAL_ERROR with the cause in debugMessage, as security's
            // are (Kiran, 2026-10-17: callers keep seeing the cause, as Java shows it), with any
            // credentials inside a URL masked.
            Self::Internal(e) => coded_response(&Coded::new("COMMON.INTERNAL_ERROR").debug(mask_url_credentials(&format!("{e:#}")))),
            Self::Coded(c) => coded_response(&c),
        }
    }
}

/// `scheme://user:password@host` with the part before `@` replaced by `***`: connection errors
/// can name a URL, and the Redis URL carries its password in the user slot.
pub fn mask_url_credentials(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("://") {
        let start = at + 3;
        out.push_str(&rest[..start]);
        rest = &rest[start..];
        let end = rest.find(|c: char| c == '/' || c == '?' || c == '#' || c.is_whitespace() || c == '"' || c == '\'').unwrap_or(rest.len());
        match rest[..end].rfind('@') {
            Some(cred) => {
                out.push_str("***");
                out.push_str(&rest[cred..end]);
            }
            None => out.push_str(&rest[..end]),
        }
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

/// Bad input, named: what a request that cannot be read answers (400, never a 500).
pub mod input {
    use super::Coded;

    /// No body where one is required.
    pub fn body_missing() -> Coded {
        Coded::new("COMMON.BODY_MISSING")
    }

    /// A body that is not JSON (`None`), or JSON that does not fit: the field is named when the
    /// parser said which one.
    pub fn body_unreadable(e: Option<&serde_json::Error>) -> Coded {
        let Some(e) = e else { return Coded::new("COMMON.BODY_UNREADABLE") };
        let detail = e.to_string();
        if e.is_syntax() || e.is_eof() {
            return Coded::new("COMMON.BODY_UNREADABLE").debug(detail);
        }
        let (field, problem) = split_path(&detail);
        from_problem(field, problem).debug(detail)
    }

    /// A field that is missing.
    pub fn field_missing(field: &str) -> Coded {
        Coded::new("COMMON.FIELD_MISSING").param("field", field)
    }

    /// A field whose value does not fit; `expected` in plain words when known.
    pub fn field_invalid(field: &str, expected: Option<&str>) -> Coded {
        let c = Coded::new("COMMON.FIELD_INVALID").param("field", field);
        match expected {
            Some(x) => c.param("expected", x),
            None => c,
        }
    }

    /// A required query parameter that was not sent.
    pub fn param_missing(name: &str) -> Coded {
        Coded::new("COMMON.PARAM_MISSING").param("field", name)
    }

    /// A required header that was not sent.
    pub fn header_missing(name: &str) -> Coded {
        Coded::new("COMMON.HEADER_MISSING").param("field", name)
    }

    /// A query or path parameter whose value does not convert.
    pub fn param_invalid(name: &str, expected: Option<&str>) -> Coded {
        let c = Coded::new("COMMON.PARAM_INVALID").param("field", name);
        match expected {
            Some(x) => c.param("expected", x),
            None => c,
        }
    }

    /// serde's "expected u64" and friends in plain words.
    pub fn expected_words(serde_expected: &str) -> Option<&'static str> {
        let e = serde_expected.trim();
        let words = if ["u8", "u16", "u32", "u64", "u128", "usize"].iter().any(|t| e.contains(t)) {
            "a whole number, 0 or more"
        } else if ["i8", "i16", "i32", "i64", "i128", "isize", "integer"].iter().any(|t| e.contains(t)) {
            "a whole number"
        } else if e.contains("f32") || e.contains("f64") || e.contains("number") {
            "a number"
        } else if e.contains("bool") {
            "true or false"
        } else if e.contains("string") || e.contains("char") {
            "text"
        } else if e.contains("sequence") || e.contains("array") || e.contains("Vec") {
            "a list"
        } else if e.contains("map") || e.contains("struct") || e.contains("object") {
            "an object"
        } else {
            return None;
        };
        Some(words)
    }

    /// `"user.age: invalid type: ..."` into the path and the problem.
    pub(super) fn split_path(detail: &str) -> (Option<&str>, &str) {
        match detail.split_once(": ") {
            Some((path, rest))
                if !path.contains(' ') && !path.is_empty() && !matches!(path, "invalid type" | "invalid value" | "missing field") =>
            {
                (Some(path), rest)
            }
            _ => (None, detail),
        }
    }

    /// A serde problem (`missing field \`x\``, `invalid type: string "a", expected u64`) as a code.
    pub(super) fn from_problem(path: Option<&str>, problem: &str) -> Coded {
        if let Some(rest) = problem.strip_prefix("missing field `") {
            let name = rest.split('`').next().unwrap_or("");
            let field = match path {
                Some(p) if p != "." => format!("{p}.{name}"),
                _ => name.to_string(),
            };
            return field_missing(&field);
        }
        let expected = problem.split(", expected ").nth(1).map(|e| e.split(" at line").next().unwrap_or(e));
        let expected = expected.and_then(expected_words);
        match path {
            Some(p) if p != "." => field_invalid(p, expected),
            _ => {
                let c = Coded::new("COMMON.BODY_INVALID");
                match expected {
                    Some(x) => c.param("expected", x),
                    None => c,
                }
            }
        }
    }
}

/// axum's `Json` extractor refusing a body: the field named when axum knows it.
impl From<JsonRejection> for AppError {
    fn from(r: JsonRejection) -> Self {
        let detail = r.body_text();
        let coded = match &r {
            JsonRejection::MissingJsonContentType(_) => Coded::new("COMMON.BODY_NOT_JSON"),
            JsonRejection::JsonSyntaxError(_) => input::body_unreadable(None),
            JsonRejection::JsonDataError(_) => {
                let inner = detail.split_once("target type: ").map(|(_, r)| r).unwrap_or(&detail);
                let (path, problem) = input::split_path(inner);
                input::from_problem(path, problem)
            }
            _ => input::body_unreadable(None),
        };
        coded.status(StatusCode::BAD_REQUEST).debug(detail).into()
    }
}

/// axum's `Query` extractor refusing a query string.
impl From<QueryRejection> for AppError {
    fn from(r: QueryRejection) -> Self {
        let detail = r.body_text();
        let inner = detail.split_once("query string: ").map(|(_, r)| r).unwrap_or(&detail);
        let coded = if let Some(rest) = inner.strip_prefix("missing field `") {
            input::param_missing(rest.split('`').next().unwrap_or(""))
        } else {
            match input::split_path(inner) {
                (Some(p), problem) => input::param_invalid(p, problem.split(", expected ").nth(1).and_then(input::expected_words)),
                (None, _) => Coded::new("COMMON.BAD_REQUEST"),
            }
        };
        coded.status(StatusCode::BAD_REQUEST).debug(detail).into()
    }
}

/// axum's `Path` extractor refusing a path segment.
impl From<PathRejection> for AppError {
    fn from(r: PathRejection) -> Self {
        let detail = r.body_text();
        let name = detail.split('`').nth(1).filter(|n| !n.is_empty() && !n.contains(' '));
        let coded = match name {
            Some(n) => input::param_invalid(n, None),
            None => Coded::new("COMMON.BAD_REQUEST"),
        };
        coded.status(StatusCode::BAD_REQUEST).debug(detail).into()
    }
}

/// KIRun `StringFormatter.format`: each `$` takes the next parameter, `\$` is a literal `$`,
/// and `$`s beyond the parameters stay as they are.
pub fn format_message(template: &str, params: &[&str]) -> String {
    if params.is_empty() {
        return template.to_string();
    }
    let mut out = String::with_capacity(template.len() + 16);
    let mut next = 0;
    let mut prev = '\0';
    for c in template.chars() {
        if c == '$' && prev == '\\' {
            out.pop();
            out.push('$');
        } else if c == '$' && next < params.len() {
            out.push_str(params[next]);
            next += 1;
        } else {
            out.push(c);
        }
        prev = c;
    }
    out
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn a_quiet_coded_response_answers_the_same() {
        let c = Coded::new("COMMON.INTERNAL_ERROR").debug("x");
        let (a, b) = (coded_response(&c), coded_response_quiet(&c));
        assert_eq!((a.status(), b.status()), (StatusCode::INTERNAL_SERVER_ERROR, StatusCode::INTERNAL_SERVER_ERROR));
        let (va, vb) = (body(a).await, body(b).await);
        // Each answer has its own error id; everything else is the same.
        assert_eq!((&va["code"], &va["debugMessage"], &va["action"]), (&vb["code"], &vb["debugMessage"], &vb["action"]));
    }

    #[test]
    fn coded_answers_are_counted_by_code_and_status() {
        let ((), text) = crate::meter::capture(|| {
            let c = Coded::new("COMMON.FIELD_MISSING").status(StatusCode::BAD_REQUEST);
            c.render("E1");
            c.render("E2");
            Coded::new("NO.SUCH_CODE").render("E3");
        });
        let count = |code: &str, status: &str| crate::meter::sample(&text, CODED_ERRORS, &[("code", code), ("status", status)]);
        assert_eq!(count("COMMON.FIELD_MISSING", "400"), Some(2.0));
        assert_eq!(count("NO.SUCH_CODE", "500"), Some(1.0));
    }

    #[test]
    fn url_credentials_are_masked() {
        assert_eq!(mask_url_credentials("mysql://root:pw@db:3306/core and mongodb://u:p@m1,m2/x?a=b"), "mysql://***@db:3306/core and mongodb://***@m1,m2/x?a=b");
        assert_eq!(mask_url_credentials("GET http://example.com/a@b failed"), "GET http://example.com/a@b failed");
        assert_eq!(mask_url_credentials("redis://:only@r:6379"), "redis://***@r:6379");
        assert_eq!(mask_url_credentials("no address here: x@y"), "no address here: x@y");
        assert_eq!(mask_url_credentials("\"amqp://g:g@mq:5672\""), "\"amqp://***@mq:5672\"");
    }

    use super::*;
    use axum::body::to_bytes;

    #[test]
    fn statuses() {
        assert_eq!(AppError::new(StatusCode::CONFLICT, "x").status(), StatusCode::CONFLICT);
        assert_eq!(AppError::Empty(StatusCode::NOT_FOUND).status(), StatusCode::NOT_FOUND);
        assert_eq!(AppError::Internal(anyhow::anyhow!("x")).status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(AppError::unauthenticated().status(), StatusCode::UNAUTHORIZED);
        assert_eq!(AppError::permission_required(&["Authorities.Page_UPDATE"]).status(), StatusCode::FORBIDDEN);
        assert_eq!(AppError::from(Coded::new("NO.SUCH_CODE")).status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(AppError::from(Coded::new("COMMON.ERROR").status(StatusCode::IM_A_TEAPOT)).status(), StatusCode::IM_A_TEAPOT);
    }

    #[test]
    fn english_messages() {
        assert_eq!(AppError::new(StatusCode::CONFLICT, "x").english_message(), "x");
        assert_eq!(AppError::Empty(StatusCode::NOT_FOUND).english_message(), "404 Not Found");
        assert_eq!(AppError::Internal(anyhow::anyhow!("boom")).english_message(), "boom");
        assert_eq!(AppError::permission_required(&[]).english_message(), "You don't have permission to do this.");
        let e = AppError::permission_required(&["Authorities.Page_UPDATE"]);
        assert!(e.to_string().starts_with("403 Forbidden: COMMON.PERMISSION_REQUIRED"));
    }

    async fn body(r: Response) -> Value {
        serde_json::from_slice(&to_bytes(r.into_body(), 100_000).await.unwrap()).unwrap()
    }

    #[tokio::test]
    async fn coded_body_shape() {
        let e = AppError::permission_required(&["Authorities.Page_UPDATE", "Authorities.ROLE_Owner"]);
        let r = e.into_response();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        assert_eq!(r.headers()["content-type"], "application/json");
        assert_eq!(r.headers()["x-frame-options"], "DENY");
        let report = r.extensions().get::<ErrorReport>().cloned().unwrap();
        assert_eq!(report.code, "COMMON.PERMISSION_REQUIRED");
        let v = body(r).await;
        assert_eq!(v["code"], "COMMON.PERMISSION_REQUIRED");
        assert_eq!(v["message"], "You can't do this: your account does not have the Edit pages permission or the Owner role.");
        assert_eq!(v["params"]["permission"], "the Edit pages permission or the Owner role");
        assert_eq!(v["locale"], "en");
        assert_eq!(v["stackTrace"], "");
        assert_eq!(v["debugMessage"], "Access Denied: needs Authorities.Page_UPDATE or Authorities.ROLE_Owner");
        assert_eq!(v["exceptionId"], report.exception_id);
        assert_eq!(v["action"], "Ask an owner of your organisation to give you the Edit pages permission or the Owner role.");
        let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
        for k in ["exceptionId", "message", "stackTrace", "debugMessage", "code", "action", "params", "locale"] {
            assert!(keys.iter().any(|x| *x == k), "{k}");
        }
    }

    #[tokio::test]
    async fn internal_error_names_the_id() {
        let r = AppError::from(Coded::new("COMMON.INTERNAL_ERROR").debug("db down")).into_response();
        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let v = body(r).await;
        let id = v["exceptionId"].as_str().unwrap().to_string();
        assert!(v["message"].as_str().unwrap().contains(&id), "{v}");
        assert_eq!(v["debugMessage"], "db down");
        assert!(v.get("action").is_some());
    }

    #[tokio::test]
    async fn unauthenticated_depends_on_credentials() {
        let v = body(AppError::unauthenticated().into_response()).await;
        assert_eq!(v["code"], "COMMON.SIGN_IN_REQUIRED");
        let scope = messages::RequestScope::default();
        let r = messages::scope::with_scope(scope, async {
            messages::note_caller(messages::CallerHint { credential_sent: true, ..Default::default() });
            AppError::unauthenticated().into_response()
        })
        .await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        let v = body(r).await;
        assert_eq!(v["code"], "COMMON.SIGNED_OUT");
        assert_eq!(v["message"], "You're signed out. Please sign in again.");
    }

    /// Another unit's coded error is answered as it came: its code, texts, values, locale and
    /// debugMessage, with the status given (a fresh error id).
    #[tokio::test]
    async fn relayed_errors_keep_their_texts() {
        let body = br#"{"exceptionId":"sec-1","message":"Votre session a expir\u00e9.","stackTrace":"","debugMessage":"[token_expired] Authorization token expired",
            "code":"SEC.TOKEN_EXPIRED","action":"Reconnectez-vous.","params":{"app":"LeadZump","n":3},"locale":"fr"}"#;
        let c = Coded::relay(StatusCode::UNAUTHORIZED, body).expect("a coded body");
        assert!(c.is_relayed());
        assert_eq!(c.english().message, "Votre session a expir\u{e9}.");
        let e = AppError::from(c);
        assert_eq!(e.english_message(), "Votre session a expir\u{e9}.");
        let r = e.into_response();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        let v = body_of(r).await;
        assert_eq!(v["code"], "SEC.TOKEN_EXPIRED");
        assert_eq!(v["message"], "Votre session a expir\u{e9}.");
        assert_eq!(v["action"], "Reconnectez-vous.");
        assert_eq!(v["locale"], "fr");
        assert_eq!(v["params"]["app"], "LeadZump");
        assert_eq!(v["params"]["n"], "3");
        assert_eq!(v["debugMessage"], "[token_expired] Authorization token expired");
        assert_ne!(v["exceptionId"], "sec-1");

        // Bodies that are not coded errors are not relayed.
        for not_coded in [&b"<html>"[..], br#"{"message":"x","exceptionId":"1"}"#, br#"{"code":"X","exceptionId":"1"}"#, br#"{"code":"X","message":"m"}"#, b"[1]"] {
            assert!(Coded::relay(StatusCode::BAD_REQUEST, not_coded).is_none(), "{}", String::from_utf8_lossy(not_coded));
        }
        let c = Coded::relay(StatusCode::FORBIDDEN, br#"{"code":"COMMON.FORBIDDEN","message":"No.","exceptionId":"1","action":" "}"#).unwrap();
        let r = c.render("E");
        assert_eq!((r.0, r.2.locale.as_str(), r.2.debug.as_str()), (StatusCode::FORBIDDEN, "en", "No."));
        assert!(!c.english().action.is_some());
    }

    async fn body_of(r: Response) -> Value {
        serde_json::from_slice(&to_bytes(r.into_body(), 100_000).await.unwrap()).unwrap()
    }

    #[test]
    fn default_debug_text_and_params() {
        let c = Coded::new("X.Y").param("a", 1).param("b", "two").param("a", 3);
        assert_eq!(c.params, vec![("a".to_string(), "3".to_string()), ("b".to_string(), "two".to_string())]);
        assert_eq!(c.debug_text(), "X.Y a=3 b=two");
        assert_eq!(c.english().message, "Your request could not be completed.");
    }

    #[test]
    fn bad_input_names_the_field() {
        #[derive(Debug, serde::Deserialize)]
        #[allow(dead_code)]
        struct B {
            name: String,
            age: u32,
        }
        let e = serde_json::from_str::<B>(r#"{"age": 1}"#).unwrap_err();
        let c = input::body_unreadable(Some(&e));
        assert_eq!((c.code.as_ref(), c.params[0].1.as_str()), ("COMMON.FIELD_MISSING", "name"));
        assert_eq!(c.english().message, "The field name is missing.");
        let e = serde_json::from_str::<B>(r#"{"name": "a", "age": "x"}"#).unwrap_err();
        let c = input::body_unreadable(Some(&e));
        assert_eq!(c.code, "COMMON.BODY_INVALID");
        assert_eq!(c.english().message, "The request body does not have the expected shape: a value should be a whole number, 0 or more.");
        let e = serde_json::from_str::<B>("{").unwrap_err();
        assert_eq!(input::body_unreadable(Some(&e)).code, "COMMON.BODY_UNREADABLE");
        assert_eq!(input::body_unreadable(None).code, "COMMON.BODY_UNREADABLE");
        assert_eq!(input::body_missing().resolved_status(), StatusCode::BAD_REQUEST);
        assert_eq!(input::field_invalid("age", Some("a number")).english().message, "The value of age is not valid: it should be a number.");
        assert_eq!(input::field_invalid("age", None).english().message, "The value of age is not valid.");
        assert_eq!(input::param_missing("appCode").english().message, "The request is missing the appCode parameter.");
        assert_eq!(input::param_invalid("id", Some("a whole number")).english().message, "The value of the id parameter is not valid: it should be a whole number.");
        assert_eq!(input::param_invalid("id", None).resolved_status(), StatusCode::BAD_REQUEST);
        assert_eq!(input::header_missing("appCode").english().message, "The request is missing the appCode header.");

        assert_eq!(input::from_problem(Some("user"), "missing field `age`").params[0].1, "user.age");
        assert_eq!(input::from_problem(Some("user.age"), "invalid type: string \"x\", expected i32 at line 1 column 3").code, "COMMON.FIELD_INVALID");
        assert_eq!(input::split_path("invalid type: x"), (None, "invalid type: x"));
        for (t, w) in [("u64", "a whole number, 0 or more"), ("i32", "a whole number"), ("f64", "a number"), ("a boolean", "true or false"),
            ("a string", "text"), ("a sequence", "a list"), ("struct B", "an object")] {
            assert_eq!(input::expected_words(t), Some(w));
        }
        assert_eq!(input::expected_words("unit"), None);
    }

    #[tokio::test]
    async fn axum_rejections_become_coded_400s() {
        use axum::extract::{FromRequest, FromRequestParts, Path, Query};
        use axum::routing::get;
        use axum::Json;
        use tower::ServiceExt;

        #[derive(Debug, serde::Deserialize)]
        #[allow(dead_code)]
        struct B {
            name: String,
            age: u32,
        }
        let req = |body: &str, ct: Option<&str>| {
            let mut b = axum::http::Request::builder().method("POST").uri("/");
            if let Some(ct) = ct {
                b = b.header("content-type", ct);
            }
            b.body(axum::body::Body::from(body.to_string())).unwrap()
        };
        let code = |e: AppError| match e {
            AppError::Coded(c) => (c.code.to_string(), c.params.clone()),
            other => panic!("{other:?}"),
        };
        let e: AppError = Json::<B>::from_request(req("{}", None), &()).await.unwrap_err().into();
        assert_eq!(code(e).0, "COMMON.BODY_NOT_JSON");
        let e: AppError = Json::<B>::from_request(req("{", Some("application/json")), &()).await.unwrap_err().into();
        assert_eq!(code(e).0, "COMMON.BODY_UNREADABLE");
        let e: AppError = Json::<B>::from_request(req(r#"{"name":"a","age":"x"}"#, Some("application/json")), &()).await.unwrap_err().into();
        assert_eq!(code(e), ("COMMON.FIELD_INVALID".to_string(), vec![("field".into(), "age".into()), ("expected".into(), "a whole number, 0 or more".into())]));
        let e: AppError = Json::<B>::from_request(req(r#"{"age":1}"#, Some("application/json")), &()).await.unwrap_err().into();
        assert_eq!(code(e), ("COMMON.FIELD_MISSING".to_string(), vec![("field".into(), "name".into())]));

        let parts = |uri: &str| axum::http::Request::builder().uri(uri).body(()).unwrap().into_parts().0;
        let mut p = parts("/?age=1");
        let e: AppError = Query::<B>::from_request_parts(&mut p, &()).await.unwrap_err().into();
        assert_eq!(code(e), ("COMMON.PARAM_MISSING".to_string(), vec![("field".into(), "name".into())]));
        let mut p = parts("/?name=a&age=x");
        let e: AppError = Query::<B>::from_request_parts(&mut p, &()).await.unwrap_err().into();
        assert_eq!(code(e).0, "COMMON.PARAM_INVALID");
        let mut p = parts("/?name=a&age=1&age=2");
        let e: AppError = Query::<B>::from_request_parts(&mut p, &()).await.unwrap_err().into();
        assert!(matches!(e, AppError::Coded(_)));

        let app = axum::Router::new().route(
            "/items/{id}",
            get(|r: Result<Path<u32>, PathRejection>| async move {
                match r {
                    Ok(_) => StatusCode::OK.into_response(),
                    Err(e) => AppError::from(e).into_response(),
                }
            }),
        );
        let r = app.oneshot(axum::http::Request::builder().uri("/items/x").body(axum::body::Body::empty()).unwrap()).await.unwrap();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        let v = body(r).await;
        assert!(v["code"] == "COMMON.PARAM_INVALID" || v["code"] == "COMMON.BAD_REQUEST", "{v}");
    }

    #[tokio::test]
    async fn legacy_bodies_are_unchanged() {
        let v = body(AppError::new(StatusCode::CONFLICT, "Taken").into_response()).await;
        assert_eq!(v, serde_json::json!({"exceptionId": v["exceptionId"], "message": "Taken", "stackTrace": "", "debugMessage": "Taken"}));
        let r = AppError::Empty(StatusCode::FORBIDDEN).into_response();
        assert_eq!(r.headers()["content-length"], "0");
        let v = body(AppError::Internal(anyhow::anyhow!("pool timed out").context("reading users")).into_response()).await;
        assert_eq!(v["code"], "COMMON.INTERNAL_ERROR");
        assert!(v["message"].as_str().unwrap().starts_with("Something went wrong on our side."), "{v}");
        assert_eq!(v["debugMessage"], "reading users: pool timed out");
        let v = body(AppError::Internal(anyhow::anyhow!("connect redis://cmn:s3cret@redis:6379/0 failed")).into_response()).await;
        assert_eq!(v["debugMessage"], "connect redis://***@redis:6379/0 failed");
    }

    #[test]
    fn formats_like_kirun() {
        assert_eq!(
            format_message("Permission to $ resource in the path $ is forbidden", &["STATIC", "a/b"]),
            "Permission to STATIC resource in the path a/b is forbidden"
        );
        assert_eq!(format_message("$ and $", &["x"]), "x and $");
        assert_eq!(format_message("cost \\$ $", &["5"]), "cost $ 5");
        assert_eq!(format_message("no params $", &[]), "no params $");
    }
}
