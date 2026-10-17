//! Errors as the Java core service sends them (`ControllerAdvice` over `GenericException`),
//! said in plain words by the message catalogue (`crate::catalogue`, codes `CORE.*` and the
//! shared `COMMON.*`), and the headers every core response carries.
//!
//! Java's body is `{"exceptionId", "message", "stackTrace", "debugMessage"}`:
//! - a `GenericException(status, message)`: `message` and `debugMessage` are the message;
//! - anything else: status 500 (or a `ResponseStatusException`'s), `message` is
//!   `unknown_error_with_id` ("Please try again. A server error - <id>", no trailing space in
//!   core's bundle) and `debugMessage` the exception's own message;
//! - a Feign error from another service: that service's status and `message`.
//!
//! A coded error (every error core raises, see [`CoreError::msg`] and [`CoreError::coded`])
//! keeps Java's status and adds `code`, `action`, `params` and `locale`; `message` is the plain
//! text and `debugMessage` Java's text (`[key] text` for a bundle key, or the cause Java sends
//! there). An unexpected failure answers `COMMON.INTERNAL_ERROR` (or the `COMMON.*` code for
//! Spring's 4xx). A coded refusal from another Rust unit (security) is passed on as it came.
//! The Java text travels inside the error unchanged, so KIRun, the event run log and the
//! parity scripts still read Java's words.
//!
//! `stackTrace` is always empty (Java sends its whole server stack).

use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use platform::error::Coded;
use platform::java::exception_id;
use platform::messages::JavaKey;
use serde::Serialize;

/// core's `messages_en.properties` (every key, with its template).
pub use crate::catalogue::keys as messages;

#[derive(Debug, Clone, thiserror::Error)]
pub enum CoreError {
    /// `GenericException(status, message)`; `cause` is the message of the exception it wraps
    /// (`GenericException(status, message, cause)`), which Java sends as `debugMessage`. `code`
    /// says it plainly (none only for a text that came from elsewhere).
    #[error("{status}: {message}")]
    Message { status: StatusCode, message: String, cause: Option<String>, code: Option<Box<Coded>> },
    /// Any other exception: the caller sees an id, `debugMessage` the exception's message. A
    /// code, when given, says more than "something went wrong" (a function step that failed,
    /// a missing header).
    #[error("{status}: {debug}")]
    Unknown { status: StatusCode, debug: String, code: Option<Box<Coded>> },
    /// `StorageObjectNotFoundException`: a 404 `GenericException` the KIRun storage functions
    /// catch (and nothing else is caught).
    #[error("{status}: {message}")]
    ObjectNotFound { status: StatusCode, message: String, code: Option<Box<Coded>> },
}

pub type CoreResult<T> = Result<T, CoreError>;

/// The `[key] ` a bundle message's `debugMessage` starts with.
fn key_prefix(debug: Option<&str>) -> &str {
    match debug {
        Some(d) if d.starts_with('[') => d.find("] ").map(|i| &d[..i + 2]).unwrap_or(""),
        _ => "",
    }
}

impl CoreError {
    /// `msgService.throwMessage(status, KEY, values...)`: Java's text, and the code standing for
    /// the key with the values named.
    pub fn msg(status: StatusCode, key: JavaKey, params: &[&str]) -> Self {
        crate::catalogue::register();
        let code = key.coded(crate::catalogue::NS, params);
        Self::Message { status, message: key.text(params), cause: None, code: Some(Box::new(code)) }
    }

    /// The key's Java text said by a more specific `code` (one case of the key), its values
    /// named by that code.
    pub fn msg_as(status: StatusCode, key: JavaKey, code: &'static str, params: &[&str]) -> Self {
        crate::catalogue::register();
        Self::Message { status, message: key.text(params), cause: None, code: Some(Box::new(key.coded_as(code, params))) }
    }

    /// `new GenericException(status, literal)`, said plainly by `code`.
    pub fn coded(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        crate::catalogue::register();
        Self::Message { status, message: message.into(), cause: None, code: Some(Box::new(Coded::new(code))) }
    }

    /// A Java text with no code: a message that came from elsewhere and is answered as Java's
    /// shape.
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self::Message { status, message: message.into(), cause: None, code: None }
    }

    pub fn with_cause(status: StatusCode, message: impl Into<String>, cause: impl Into<String>) -> Self {
        Self::Message { status, message: message.into(), cause: Some(cause.into()), code: None }
    }

    /// The exception this one wraps (`GenericException(status, message, cause)`): its message is
    /// what Java sends as `debugMessage`.
    pub fn caused_by(self, cause: impl Into<String>) -> Self {
        match self {
            Self::Message { status, message, code, .. } => Self::Message { status, message, cause: Some(cause.into()), code },
            other => other,
        }
    }

    /// Sets a value of the message (a name Java did not pass, a plainer form of one it did).
    pub fn param(self, name: &str, value: impl ToString) -> Self {
        self.map_code(|c| c.param(name, value))
    }

    /// Takes a value of the message out (a name an anonymous caller must not see).
    pub fn without_param(self, name: &str) -> Self {
        self.map_code(|mut c| {
            c.params.retain(|(n, _)| n != name);
            c
        })
    }

    /// The same Java text said by a more specific code; the values stay.
    pub fn with_code(self, code: &'static str) -> Self {
        crate::catalogue::register();
        let swap = |c: Option<Box<Coded>>| {
            Some(Box::new(match c {
                Some(old) => Coded { code: code.into(), ..*old },
                None => Coded::new(code),
            }))
        };
        match self {
            Self::Message { status, message, cause, code: c } => Self::Message { status, message, cause, code: swap(c) },
            Self::ObjectNotFound { status, message, code: c } => Self::ObjectNotFound { status, message, code: swap(c) },
            Self::Unknown { status, debug, code: c } => Self::Unknown { status, debug, code: swap(c) },
        }
    }

    fn map_code(self, f: impl FnOnce(Coded) -> Coded) -> Self {
        let apply = |c: Option<Box<Coded>>| c.map(|c| Box::new(f(*c)));
        match self {
            Self::Message { status, message, cause, code } => Self::Message { status, message, cause, code: apply(code) },
            Self::ObjectNotFound { status, message, code } => Self::ObjectNotFound { status, message, code: apply(code) },
            Self::Unknown { status, debug, code } => Self::Unknown { status, debug, code: apply(code) },
        }
    }

    /// The code this error answers with, when it has its own.
    pub fn code(&self) -> Option<&Coded> {
        match self {
            Self::Message { code, .. } | Self::ObjectNotFound { code, .. } | Self::Unknown { code, .. } => code.as_deref(),
        }
    }

    /// The text a KIRun error carries for this error while it travels up the runtime: Java's.
    pub fn text(&self) -> String {
        match self {
            Self::Message { message, .. } | Self::ObjectNotFound { message, .. } => message.clone(),
            Self::Unknown { debug, .. } => debug.clone(),
        }
    }

    pub fn is_object_not_found(&self) -> bool {
        matches!(self, Self::ObjectNotFound { .. })
    }

    pub fn unknown(debug: impl Into<String>) -> Self {
        Self::Unknown { status: StatusCode::INTERNAL_SERVER_ERROR, debug: debug.into(), code: None }
    }

    /// An exception with its own status (Spring's `ResponseStatusException`) and the code that
    /// names the problem, when one does.
    pub fn spring(status: StatusCode, debug: impl Into<String>, code: Option<Coded>) -> Self {
        crate::catalogue::register();
        Self::Unknown { status, debug: debug.into(), code: code.map(Box::new) }
    }

    pub fn status(&self) -> StatusCode {
        match self {
            Self::Message { status, .. } | Self::Unknown { status, .. } | Self::ObjectNotFound { status, .. } => *status,
        }
    }

    /// The coded error this answers with: its own code with Java's status and Java's text (or
    /// cause) as `debugMessage`; for an unexpected failure the `COMMON.*` code of its status.
    /// `None` for a Java text that has no code.
    pub fn coded_answer(&self) -> Option<Coded> {
        match self {
            Self::Message { status, message, cause, code: Some(c) } => Some(java_debug(c, *status, cause.as_deref().unwrap_or(message))),
            Self::ObjectNotFound { status, message, code: Some(c) } => Some(java_debug(c, *status, message)),
            Self::Message { code: None, .. } | Self::ObjectNotFound { code: None, .. } => None,
            Self::Unknown { status, debug, code } => {
                let c = match code {
                    Some(c) => (**c).clone(),
                    None => Coded::new(match *status {
                        s if s.is_server_error() => "COMMON.INTERNAL_ERROR",
                        StatusCode::NOT_FOUND => "COMMON.NOT_FOUND",
                        StatusCode::METHOD_NOT_ALLOWED => "COMMON.METHOD_NOT_ALLOWED",
                        StatusCode::PAYLOAD_TOO_LARGE => "COMMON.PAYLOAD_TOO_LARGE",
                        StatusCode::UNSUPPORTED_MEDIA_TYPE => "COMMON.BODY_NOT_JSON",
                        _ => "COMMON.BAD_REQUEST",
                    }),
                };
                let d = c.debug.clone().unwrap_or_else(|| debug.clone());
                Some(c.status(*status).debug(d))
            }
        }
    }
}
/// Spring's refusals of a request it cannot bind, as `ControllerAdvice` answers them (an id in
/// `message`, Spring's text in `debugMessage`), with the `COMMON.*` code that names what was
/// wrong.
pub mod spring {
    use axum::http::StatusCode;
    use platform::error::{input, Coded};

    use super::CoreError;

    /// `@RequestHeader(name)` missing.
    pub fn header_missing(name: &str) -> CoreError {
        CoreError::spring(StatusCode::BAD_REQUEST, format!("400 BAD_REQUEST \"Required header '{name}' is not present.\""), Some(input::header_missing(name)))
    }

    /// `@RequestParam(name)` missing.
    pub fn param_missing(name: &str) -> CoreError {
        CoreError::spring(StatusCode::BAD_REQUEST, format!("400 BAD_REQUEST \"Required query parameter '{name}' is not present.\""), Some(input::param_missing(name)))
    }

    /// A parameter whose value does not convert; `detail` follows Spring's text.
    pub fn type_mismatch(name: Option<&str>, expected: Option<&str>, detail: Option<&str>) -> CoreError {
        let debug = match detail {
            Some(d) => format!("400 BAD_REQUEST \"Type mismatch.\"; {d}"),
            None => "400 BAD_REQUEST \"Type mismatch.\"".to_string(),
        };
        let code = match name {
            Some(n) => input::param_invalid(n, expected),
            None => Coded::new("COMMON.PARAM_INVALID"),
        };
        CoreError::spring(StatusCode::BAD_REQUEST, debug, Some(code))
    }

    /// `@RequestBody` that is missing ("No request body") or cannot be read ("Failed to read
    /// HTTP message").
    pub fn body(what: &str) -> CoreError {
        let code = if what == "No request body" { input::body_missing() } else { input::body_unreadable(None) };
        CoreError::spring(StatusCode::BAD_REQUEST, format!("400 BAD_REQUEST \"{what}\""), Some(code))
    }
}

/// `c` with Java's status, and Java's text (after the bundle key, when there is one) as its
/// `debugMessage`; a relayed error keeps the other unit's.
fn java_debug(c: &Coded, status: StatusCode, java: &str) -> Coded {
    let c = c.clone().status(status);
    if c.is_relayed() {
        return c;
    }
    let prefix = key_prefix(c.debug.as_deref()).to_string();
    c.debug(format!("{prefix}{java}"))
}

impl From<anyhow::Error> for CoreError {
    fn from(e: anyhow::Error) -> Self {
        match e.downcast::<CoreError>() {
            Ok(c) => c,
            Err(e) => Self::unknown(e.to_string()),
        }
    }
}

/// An engine's error as the policy layer lets it through, its code with it. `Empty` only
/// escapes where Java's chain would have completed empty without a refusal; it is answered
/// there, not here.
impl From<appdata::AppDataError> for CoreError {
    fn from(e: appdata::AppDataError) -> Self {
        match e {
            appdata::AppDataError::Message { status, message, kind, code } => match kind {
                appdata::error::ErrorKind::ObjectNotFound => Self::ObjectNotFound { status, message, code },
                appdata::error::ErrorKind::Generic => Self::Message { status, message, cause: None, code },
            },
            appdata::AppDataError::Empty => Self::unknown("the operation produced nothing"),
            appdata::AppDataError::Internal(e) => Self::from(e),
        }
    }
}

impl From<kirun::KIRunError> for CoreError {
    fn from(e: kirun::KIRunError) -> Self {
        Self::unknown(e.to_string())
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExceptionData<'a> {
    exception_id: &'a str,
    message: &'a str,
    stack_trace: &'a str,
    debug_message: &'a str,
}

impl IntoResponse for CoreError {
    fn into_response(self) -> Response {
        if let Some(c) = self.coded_answer() {
            return platform::error::coded_response(&c);
        }
        let id = exception_id();
        let (status, message, debug_text) = match self {
            Self::Message { status, message, cause, .. } => {
                let d = cause.unwrap_or_else(|| message.clone());
                (status, message, d)
            }
            Self::ObjectNotFound { status, message, .. } => (status, message.clone(), message),
            // Always coded (above).
            Self::Unknown { status, debug, .. } => {
                (status, platform::error::format_message(messages::UNKNOWN_ERROR_WITH_ID.template, &[&id]), debug)
            }
        };
        if status.is_server_error() {
            tracing::error!(exception_id = id, %status, debug_message = %debug_text, "request failed");
        } else {
            tracing::debug!(exception_id = id, %status, debug_message = %debug_text, "request refused");
        }
        let body = serde_json::to_vec(&ExceptionData {
            exception_id: &id,
            message: &message,
            stack_trace: "",
            debug_message: &debug_text,
        })
        .unwrap_or_default();
        let mut h = HeaderMap::new();
        h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
        (status, h, body).into_response()
    }
}

/// The headers Spring Security writes on every core response (core's filter chain sets
/// `X-Frame-Options: DENY` and `Referrer-Policy: no-referrer`).
pub fn core_security_headers(h: &mut HeaderMap) {
    let set = |h: &mut HeaderMap, name: header::HeaderName, value: &'static str| {
        h.entry(name).or_insert(HeaderValue::from_static(value));
    };
    set(h, header::CACHE_CONTROL, "no-cache, no-store, max-age=0, must-revalidate");
    set(h, header::PRAGMA, "no-cache");
    set(h, header::EXPIRES, "0");
    set(h, header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    set(h, header::X_FRAME_OPTIONS, "DENY");
    set(h, header::X_XSS_PROTECTION, "0");
    set(h, header::REFERRER_POLICY, "no-referrer");
}

/// The layer that adds [`core_security_headers`] to every response.
pub async fn security_headers_layer(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let mut resp = next.run(req).await;
    core_security_headers(resp.headers_mut());
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_format_like_java() {
        let e = CoreError::msg(StatusCode::NOT_FOUND, messages::OBJECT_NOT_FOUND, &["Function", "Nope.Nothing"]);
        assert_eq!(e.to_string(), "404 Not Found: Function with id Nope.Nothing not found");
        // FORBIDDEN_EXECUTION is thrown without parameters, so the `$` stays.
        let e = CoreError::msg(StatusCode::FORBIDDEN, messages::FORBIDDEN_EXECUTION, &[]);
        assert_eq!(e.to_string(), "403 Forbidden: Authorization $ is required to execute the function");
        assert_eq!(e.code().map(|c| c.code.to_string()).as_deref(), Some("CORE.FORBIDDEN_EXECUTION"));
    }

    async fn body(e: CoreError) -> (StatusCode, serde_json::Value) {
        let r = e.into_response();
        let status = r.status();
        assert_eq!(r.headers()[header::CONTENT_TYPE], "application/json");
        let bytes = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    /// A coded error: Java's status, the plain text, the next step, and Java's text (after the
    /// bundle key) in `debugMessage`.
    #[tokio::test]
    async fn coded_bodies() {
        let (s, b) = body(CoreError::msg_as(StatusCode::NOT_FOUND, messages::OBJECT_NOT_FOUND, "CORE.FUNCTION_NOT_FOUND", &["Function", "A.b"])).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        assert_eq!(b["code"], "CORE.FUNCTION_NOT_FOUND");
        assert_eq!(b["message"], "We couldn't find the function A.b.");
        assert_eq!(b["debugMessage"], "[object_not_found] Function with id A.b not found");
        assert_eq!(b["params"]["function"], "A.b");
        assert_eq!(b["stackTrace"], "");
        assert!(b["action"].as_str().unwrap().contains("namespace"));

        // A literal text, said by its code; the cause is what Java sends as debugMessage.
        let e = CoreError::coded(StatusCode::BAD_REQUEST, "CORE.HASH_ALGORITHM_UNSUPPORTED", "Hash algorithm not supported: MD4")
            .caused_by("MD4 MessageDigest not available")
            .param("algorithm", "MD4");
        assert_eq!(e.text(), "Hash algorithm not supported: MD4");
        let (s, b) = body(e).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(b["message"], "The hash algorithm MD4 is not supported.");
        assert_eq!(b["debugMessage"], "MD4 MessageDigest not available");

        // A key's text with a cause keeps the key in front of the cause.
        let e = CoreError::msg(StatusCode::INTERNAL_SERVER_ERROR, messages::NOT_ABLE_TO_DOWNLOAD_DATA, &[]).caused_by("disk full");
        assert_eq!(body(e).await.1["debugMessage"], "[not_able_to_download_data] disk full");

        // A missing object as the storage functions catch it, coded too.
        let e = CoreError::ObjectNotFound { status: StatusCode::NOT_FOUND, message: "leads with id 1 not found".into(), code: None }.with_code("CORE.ROW_NOT_FOUND");
        assert!(e.is_object_not_found());
        let (_, b) = body(e.param("storage", "leads").param("id", "1")).await;
        assert_eq!((b["code"].as_str(), b["message"].as_str()), (Some("CORE.ROW_NOT_FOUND"), Some("We couldn't find the row 1 in leads.")));
        assert_eq!(b["debugMessage"], "leads with id 1 not found");
    }

    /// Unexpected failures and Spring's refusals answer the `COMMON.*` code of their status, with
    /// Java's "Please try again" text standing behind it and the exception's text in
    /// `debugMessage`.
    #[tokio::test]
    async fn unknown_errors_by_status() {
        let (s, b) = body(CoreError::unknown("t1")).await;
        assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR);
        let id = b["exceptionId"].as_str().unwrap().to_string();
        assert_eq!(b["code"], "COMMON.INTERNAL_ERROR");
        assert!(b["message"].as_str().unwrap().contains(&id));
        assert_eq!(b["debugMessage"], "t1");
        for (status, code) in [
            (StatusCode::BAD_REQUEST, "COMMON.BAD_REQUEST"),
            (StatusCode::NOT_FOUND, "COMMON.NOT_FOUND"),
            (StatusCode::METHOD_NOT_ALLOWED, "COMMON.METHOD_NOT_ALLOWED"),
            (StatusCode::PAYLOAD_TOO_LARGE, "COMMON.PAYLOAD_TOO_LARGE"),
            (StatusCode::UNSUPPORTED_MEDIA_TYPE, "COMMON.BODY_NOT_JSON"),
        ] {
            let (s, b) = body(CoreError::spring(status, "x", None)).await;
            assert_eq!((s, b["code"].as_str()), (status, Some(code)));
        }
        let (_, b) = body(spring::header_missing("appCode")).await;
        assert_eq!(b["code"], "COMMON.HEADER_MISSING");
        assert_eq!(b["debugMessage"], "400 BAD_REQUEST \"Required header 'appCode' is not present.\"");
        let (_, b) = body(spring::param_missing("connectionName")).await;
        assert_eq!((b["code"].as_str(), b["params"]["field"].as_str()), (Some("COMMON.PARAM_MISSING"), Some("connectionName")));
        let (_, b) = body(spring::type_mismatch(Some("draft"), Some("true or false"), Some("Invalid boolean value [x]"))).await;
        assert_eq!(b["code"], "COMMON.PARAM_INVALID");
        assert_eq!(b["debugMessage"], "400 BAD_REQUEST \"Type mismatch.\"; Invalid boolean value [x]");
        let (_, b) = body(spring::type_mismatch(None, None, None)).await;
        assert_eq!((b["code"].as_str(), b["debugMessage"].as_str()), (Some("COMMON.PARAM_INVALID"), Some("400 BAD_REQUEST \"Type mismatch.\"")));
        assert_eq!(body(spring::body("No request body")).await.1["code"], "COMMON.BODY_MISSING");
        assert_eq!(body(spring::body("Failed to read HTTP message")).await.1["code"], "COMMON.BODY_UNREADABLE");
    }

    /// A Java text that came from elsewhere, with no code, keeps Java's shape.
    #[tokio::test]
    async fn uncoded_texts_keep_javas_shape() {
        let (_, b) = body(CoreError::new(StatusCode::CONFLICT, "Taken")).await;
        assert_eq!(b, serde_json::json!({"exceptionId": b["exceptionId"], "message": "Taken", "stackTrace": "", "debugMessage": "Taken"}));
        let (_, b) = body(CoreError::with_cause(StatusCode::BAD_REQUEST, "Bad", "why")).await;
        assert_eq!(b["debugMessage"], "why");
        let (_, b) = body(CoreError::ObjectNotFound { status: StatusCode::NOT_FOUND, message: "gone".into(), code: None }).await;
        assert_eq!(b["debugMessage"], "gone");
        assert!(CoreError::new(StatusCode::CONFLICT, "x").coded_answer().is_none());
        // Builders leave an error without a code alone.
        let e = CoreError::new(StatusCode::CONFLICT, "x").param("a", 1).without_param("a");
        assert!(e.code().is_none());
        assert_eq!(CoreError::unknown("u").caused_by("ignored").text(), "u");
    }

    /// Another unit's coded refusal is answered as it came.
    #[tokio::test]
    async fn relayed_refusals_pass_through() {
        let body_json = serde_json::json!({"exceptionId": "s", "message": "You can't do this: your account does not have the View users permission.",
            "debugMessage": "Access Denied: needs Authorities.User_READ", "code": "COMMON.PERMISSION_REQUIRED",
            "action": "Ask an owner of your organisation to give you the View users permission.", "params": {"permission": "the View users permission"}, "locale": "en"});
        let e = crate::auth::relayed(StatusCode::FORBIDDEN, &body_json).unwrap();
        assert_eq!(e.text(), "Access Denied: needs Authorities.User_READ");
        let (s, b) = body(e).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        assert_eq!(b["code"], "COMMON.PERMISSION_REQUIRED");
        assert_eq!(b["message"], body_json["message"]);
        assert_eq!(b["action"], body_json["action"]);
        assert_eq!(b["debugMessage"], "Access Denied: needs Authorities.User_READ");
        let keyed = serde_json::json!({"exceptionId": "s", "message": "m", "debugMessage": "[unknown_client] Unknown client information requested", "code": "SEC.UNKNOWN_CLIENT"});
        assert_eq!(crate::auth::relayed(StatusCode::UNAUTHORIZED, &keyed).unwrap().text(), "Unknown client information requested");
        assert!(crate::auth::relayed(StatusCode::UNAUTHORIZED, &serde_json::json!({"message": "Unknown token"})).is_none());
    }

    #[test]
    fn codes_change_and_carry() {
        let e = CoreError::msg(StatusCode::FORBIDDEN, messages::FORBIDDEN_READ_STORAGE, &["leads"]);
        assert_eq!(e.code().unwrap().params, vec![("storage".to_string(), "leads".to_string())]);
        let e = e.without_param("storage");
        assert!(e.code().unwrap().params.is_empty());
        let e = CoreError::new(StatusCode::FORBIDDEN, "x").with_code("CORE.STORAGE_ROW_GONE");
        assert_eq!(e.code().unwrap().code, "CORE.STORAGE_ROW_GONE");
        let e = CoreError::unknown("u").with_code("CORE.FUNCTION_FAILED").param("function", "A.b");
        assert_eq!(e.code().unwrap().params[0].1, "A.b");
        let e = CoreError::ObjectNotFound { status: StatusCode::NOT_FOUND, message: "m".into(), code: None }.param("x", 1);
        assert!(e.code().is_none());
        assert_eq!(key_prefix(Some("[k] t")), "[k] ");
        assert_eq!(key_prefix(Some("no key")), "");
        assert_eq!(key_prefix(Some("[unclosed")), "");
        assert_eq!(key_prefix(None), "");
    }

    #[test]
    fn conversions() {
        let e: CoreError = anyhow::Error::new(CoreError::new(StatusCode::FORBIDDEN, "no")).into();
        assert_eq!(e.status(), StatusCode::FORBIDDEN);
        let e: CoreError = anyhow::anyhow!("plain").into();
        assert_eq!(e.text(), "plain");
        let e: CoreError = kirun::KIRunError::runtime("k").into();
        assert_eq!(e.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(e.text(), "k");
        // The engines' errors keep their codes and kinds.
        let e: CoreError = appdata::AppDataError::object_not_found("leads", "7").into();
        assert!(e.is_object_not_found());
        assert_eq!(e.code().unwrap().code, "CORE.ROW_NOT_FOUND");
        let e: CoreError = appdata::AppDataError::invalid_join("no").into();
        assert_eq!((e.status(), e.code().unwrap().code.as_ref()), (StatusCode::BAD_REQUEST, "CORE.INVALID_JOIN"));
        let e: CoreError = appdata::AppDataError::Empty.into();
        assert_eq!(e.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let e: CoreError = appdata::AppDataError::internal("db").into();
        assert_eq!(e.text(), "db");
    }

    #[tokio::test]
    async fn security_headers_on_every_response() {
        use tower::ServiceExt;
        let app = axum::Router::new()
            .route("/", axum::routing::get(|| async { ([(header::CACHE_CONTROL, "max-age=5")], "ok") }))
            .layer(axum::middleware::from_fn(security_headers_layer));
        let r = app.oneshot(axum::http::Request::new(axum::body::Body::empty())).await.unwrap();
        let h = r.headers();
        // A header the handler set is kept.
        assert_eq!(h[header::CACHE_CONTROL], "max-age=5");
        assert_eq!(h[header::X_FRAME_OPTIONS], "DENY");
        assert_eq!(h[header::REFERRER_POLICY], "no-referrer");
        assert_eq!(h[header::PRAGMA], "no-cache");
    }
}
