//! Errors as the security service sends them.
//!
//! Every error answers with the platform's coded body (`platform::error`): Java's status, a
//! `code` from the catalogue (`crate::catalogue`, codes `SEC.*` and the shared `COMMON.*`), the
//! text in the request's language, the next step, and Java's own text in `debugMessage`.
//!
//! What each kind keeps from Java:
//! - A `GenericException` (`authError`, `throwMessage`): its status; its message (the bundle's
//!   template from `messages_en.properties`, formatted with KIRun's `StringFormatter`) is the
//!   parity reference and the `debugMessage`.
//! - Spring Security refusing an unauthenticated caller on a protected path: 401, now with a
//!   body asking to sign in (Java sends none).
//! - `@PreAuthorize` refusing a caller: 403, now JSON naming the permission (Java sends
//!   `text/plain` "Access Denied").
//! - Anything else: 500 (or the `ResponseStatusException`'s status), the cause in
//!   `debugMessage`, as `ControllerAdvice` writes it; a request Spring cannot read is a 400
//!   that names the field or parameter.
//!
//! `stackTrace` is always empty: the Java service sends its server stack to anyone (see
//! DIFFERENCES.md).

use axum::body::Body;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use platform::error::{format_message, Coded};
use platform::java::exception_id;
use platform::messages::render::name_positional;

use crate::model::ContextAuth;

pub const UNKNOWN_ERROR: &str = "unknown_error";
pub const USER_CREDENTIALS_MISMATCHED: &str = "user_credentials_mismatched";
pub const USER_PASSWORD_INVALID_ATTEMPTS: &str = "user_password_invalid_attempts";
pub const USER_ACCOUNT_BLOCKED: &str = "user_account_blocked";
pub const USER_ACCOUNT_BLOCKED_LIMIT: &str = "user_account_blocked_limit";
pub const USER_ACCOUNT_PASS_EXPIRED: &str = "user_account_pass_expired";
pub const TOKEN_EXPIRED: &str = "token_expired";
pub const UNKNOWN_TOKEN: &str = "unknown_token";
pub const UNKNOWN_CLIENT: &str = "unknown_client";
pub const INACTIVE_CLIENT: &str = "inactive_client";
pub const NO_REGISTRATION_AVAILABLE: &str = "no_registration_available";
pub const SOCIAL_LOGIN_FAILED: &str = "social_login_failed";
pub const SESSION_EXPIRED: &str = "session_expired";
pub const ACCESS_REQUEST_REQUIRED: &str = "access_request_required";
pub const FORBIDDEN_PERMISSION: &str = "forbidden_permission";
pub const UNSUPPORTED_AUTH_MODE: &str = "unsupported_auth_mode";
pub const SMS_OTP_ERROR: &str = "sms_otp_error";
pub const OBJECT_NOT_FOUND: &str = "object_not_found";
pub const UNKNOWN_ERROR_WITH_ID: &str = "unknown_error_with_id";
pub const ONLY_SYS_USER_CERTS: &str = "only_sys_user_certs";
pub const MANDATORY_APP_CODE: &str = "mandatory_app_code";

/// The bundle's template for `key` (`crate::messages`). `social_login_failed` and
/// `session_expired` are referenced by the Java code but missing from the bundle, so they read as
/// `unknown_error`, as they do in Java.
fn template(key: &str) -> &'static str {
    crate::messages::template(key)
}

/// `resourceService.getMessage(key, params...)`: Java's English text.
pub fn message(key: &str, params: &[&str]) -> String {
    format_message(template(key), params)
}

#[derive(Debug)]
pub enum AuthError {
    /// `new GenericException(status, message)`: Java's status and text (`message`, the parity
    /// reference; `debugMessage` reads `[key] text`), the bundle key and values it came from, and the code
    /// that says it plainly. `debug` is the cause's message when there is one.
    Generic { status: StatusCode, message: String, debug: Option<String>, key: String, values: Vec<String>, code: Coded },
    /// Spring Security's entry point: an unauthenticated caller on a protected path.
    Unauthenticated,
    /// `@PreAuthorize` refusing a caller: 403. `needed` holds the authorities any one of which
    /// would have done; an anonymous caller (`signed_in` false) is only asked to sign in.
    AccessDenied { needed: Vec<String>, signed_in: bool },
    /// `ControllerAdvice.handleOtherExceptions`: the status (500, or a `ResponseStatusException`'s)
    /// and the cause's message.
    Unknown { status: StatusCode, cause: String },
    /// A request Spring could not read (a missing or unconvertible parameter, an unreadable
    /// body, a wrong method or media type): Java answers it like [`AuthError::Unknown`]; the code
    /// names what was wrong.
    Input { status: StatusCode, cause: String, code: Coded },
}

pub type AuthResult<T> = Result<T, AuthError>;

/// Java prints a missing value as `null`; a message leaves it out instead.
fn named(code: &str, values: &[String]) -> Vec<(String, String)> {
    let refs: Vec<&str> = values.iter().map(|v| if v == "null" { "" } else { v.as_str() }).collect();
    let cat = platform::messages::global();
    name_positional(&cat, code, &refs).into_iter().filter(|(_, v)| !v.trim().is_empty()).collect()
}

impl AuthError {
    /// `authError(key, status, params...)` / `throwMessage`: the code is the one standing for
    /// the key (`crate::catalogue::code_for_key`).
    pub fn msg(status: StatusCode, key: &str, params: &[&str]) -> Self {
        let values: Vec<String> = params.iter().map(|p| p.to_string()).collect();
        let code = crate::catalogue::code_for_key(key);
        let named = named(&code, &values);
        let mut coded = Coded::new(code);
        coded.params = named;
        Self::Generic { status, message: message(key, params), debug: None, key: key.to_string(), values, code: coded }
    }

    /// `new GenericException(status, literalMessage)`, said plainly by `code`.
    pub fn literal(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        crate::catalogue::register();
        Self::Generic { status, message: message.into(), debug: None, key: String::new(), values: Vec::new(), code: Coded::new(code) }
    }

    pub fn internal(cause: impl std::fmt::Display) -> Self {
        Self::Unknown { status: StatusCode::INTERNAL_SERVER_ERROR, cause: cause.to_string() }
    }

    /// A request Spring could not read, with the code that names the problem.
    pub fn input(status: StatusCode, cause: impl Into<String>, code: Coded) -> Self {
        Self::Input { status, cause: cause.into(), code }
    }

    /// `@PreAuthorize("hasAnyAuthority(...)")` refusing `ca`.
    pub fn denied(ca: &ContextAuth, any_of: &[&str]) -> Self {
        Self::AccessDenied { needed: any_of.iter().map(|a| a.to_string()).collect(), signed_in: ca.authenticated }
    }

    /// The same Java text said by a more specific code; the values are named again for it.
    pub fn with_code(self, code: &'static str) -> Self {
        crate::catalogue::register();
        match self {
            Self::Generic { status, message, debug, key, values, code: old } => {
                let mut c = Coded::new(code);
                c.params = named(code, &values);
                c.debug = old.debug;
                Self::Generic { status, message, debug, key, values, code: c }
            }
            Self::Input { status, cause, code: old } => Self::Input { status, cause, code: Coded { code: code.into(), ..old } },
            other => other,
        }
    }

    /// Sets a value of the message (a name where Java passed a code, a field Java did not name).
    pub fn with_param(self, name: &str, value: impl ToString) -> Self {
        match self {
            Self::Generic { status, message, debug, key, values, code } => {
                Self::Generic { status, message, debug, key, values, code: code.param(name, value) }
            }
            Self::Input { status, cause, code } => Self::Input { status, cause, code: code.param(name, value) },
            other => other,
        }
    }

    /// Adds the cause's message (shown in `debugMessage` after Java's text).
    pub fn with_debug(self, cause: impl Into<String>) -> Self {
        match self {
            Self::Generic { status, message, key, values, code, .. } => {
                Self::Generic { status, message, debug: Some(cause.into()), key, values, code }
            }
            other => other,
        }
    }

    pub fn status(&self) -> StatusCode {
        match self {
            Self::Generic { status, .. } | Self::Unknown { status, .. } | Self::Input { status, .. } => *status,
            Self::Unauthenticated => StatusCode::UNAUTHORIZED,
            Self::AccessDenied { .. } => StatusCode::FORBIDDEN,
        }
    }

    pub fn is_client_error(&self) -> bool {
        self.status().is_client_error()
    }

    /// Java's English text for this error (what Java sends as `message`; here `debugMessage`).
    /// Empty for a bare 401.
    pub fn message(&self) -> String {
        match self {
            Self::Generic { message, .. } => message.clone(),
            Self::Unauthenticated => String::new(),
            Self::AccessDenied { .. } => "Access Denied".into(),
            Self::Unknown { .. } | Self::Input { .. } => message(UNKNOWN_ERROR_WITH_ID, &[]),
        }
    }

    /// The catalogue code this error answers with.
    pub fn code(&self) -> String {
        self.coded().code.to_string()
    }

    /// The coded message this error answers with.
    pub fn coded(&self) -> Coded {
        crate::catalogue::register();
        match self {
            Self::Generic { status, message, debug, key, code, .. } => {
                let mut d = if key.is_empty() { message.clone() } else { format!("[{key}] {message}") };
                if let Some(cause) = debug {
                    d.push_str(&format!(" ({cause})"));
                }
                code.clone().status(*status).debug(d)
            }
            Self::Unauthenticated => Coded::unauthenticated().debug("Not signed in: Spring Security's 401"),
            Self::AccessDenied { needed, signed_in: true } => {
                let needed: Vec<&str> = needed.iter().map(String::as_str).collect();
                Coded::permission_required(&needed)
            }
            Self::AccessDenied { needed, signed_in: false } => Coded::new("COMMON.SIGN_IN_REQUIRED")
                .status(StatusCode::FORBIDDEN)
                .debug(format!("Access Denied: anonymous caller, needs {}", needed.join(" or "))),
            Self::Unknown { status, cause } => {
                let code = match *status {
                    s if s.is_server_error() => "COMMON.INTERNAL_ERROR",
                    StatusCode::METHOD_NOT_ALLOWED => "COMMON.METHOD_NOT_ALLOWED",
                    StatusCode::PAYLOAD_TOO_LARGE => "COMMON.PAYLOAD_TOO_LARGE",
                    StatusCode::UNSUPPORTED_MEDIA_TYPE => "COMMON.BODY_NOT_JSON",
                    _ => "COMMON.BAD_REQUEST",
                };
                Coded::new(code).status(*status).debug(cause.clone())
            }
            Self::Input { status, cause, code } => code.clone().status(*status).debug(cause.clone()),
        }
    }
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Generic { status, message, .. } => write!(f, "{status}: {message}"),
            Self::Unauthenticated => write!(f, "401: not authenticated"),
            Self::AccessDenied { .. } => write!(f, "403: Access Denied"),
            Self::Unknown { status, cause } | Self::Input { status, cause, .. } => write!(f, "{status}: {cause}"),
        }
    }
}

impl std::error::Error for AuthError {}

/// A filter Java could not apply (a value that does not convert, a `LIKE` without one): its
/// exception reaches `ControllerAdvice` as a 500.
impl From<crate::condition::Invalid> for AuthError {
    fn from(e: crate::condition::Invalid) -> Self {
        Self::internal(e.0)
    }
}

impl From<sqlx::Error> for AuthError {
    fn from(e: sqlx::Error) -> Self {
        Self::internal(e)
    }
}

impl From<anyhow::Error> for AuthError {
    fn from(e: anyhow::Error) -> Self {
        Self::internal(e)
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let id = exception_id();
        let coded = self.coded();
        let (status, body, report) = coded.render(&id);
        if status.is_server_error() {
            tracing::error!(exception_id = id, %status, code = report.code, debug = report.debug, "request failed");
        } else {
            tracing::debug!(exception_id = id, %status, code = report.code, debug = report.debug, "request refused");
        }
        let mut resp = Response::new(Body::from(body));
        *resp.status_mut() = status;
        resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
        resp.extensions_mut().insert(report);
        resp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use serde_json::Value;

    #[test]
    fn messages_format_like_java() {
        assert_eq!(message(USER_PASSWORD_INVALID_ATTEMPTS, &["Password", "2"]), "Wrong Password, 2 attempt remaining.");
        assert_eq!(message(USER_ACCOUNT_BLOCKED_LIMIT, &["PIN", "15"]), "Wrong PIN limit reached. Try after 15 minutes.");
        assert_eq!(message(SOCIAL_LOGIN_FAILED, &[]), "Internal Server Error (Unknown)");
        assert_eq!(message(SESSION_EXPIRED, &[]), "Internal Server Error (Unknown)");
        assert_eq!(message(FORBIDDEN_PERMISSION, &["SSO target app"]), "Permission/Role SSO target app is required to use this operation");
        assert_eq!(message(OBJECT_NOT_FOUND, &["App", "7"]), "App with id 7 not found");
        assert_eq!(AuthError::internal("x").message(), "Please try again. A server error - $");
    }

    async fn body(r: Response) -> Value {
        serde_json::from_slice(&to_bytes(r.into_body(), 100_000).await.unwrap()).unwrap()
    }

    #[tokio::test]
    async fn bodies() {
        let r = AuthError::msg(StatusCode::FORBIDDEN, USER_CREDENTIALS_MISMATCHED, &[]).into_response();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        assert_eq!(r.headers()["content-type"], "application/json");
        let v = body(r).await;
        assert_eq!(v["code"], "SEC.USER_CREDENTIALS_MISMATCHED");
        assert_eq!(v["message"], "The user name or password is not correct.");
        assert_eq!(v["action"], "Check them and try again, or reset your password if you've forgotten it.");
        assert_eq!(v["debugMessage"], "[user_credentials_mismatched] User credentials mismatch");
        assert_eq!(v["stackTrace"], "");
        assert_eq!(v["locale"], "en");

        let r = AuthError::Unauthenticated.into_response();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        let v = body(r).await;
        assert_eq!(v["code"], "COMMON.SIGN_IN_REQUIRED");
        assert_eq!(v["message"], "Please sign in to continue.");

        let e = AuthError::internal("Empty input string");
        assert!(!e.is_client_error());
        assert_eq!(e.to_string(), "500 Internal Server Error: Empty input string");
        let v = body(e.into_response()).await;
        let id = v["exceptionId"].as_str().unwrap().to_string();
        assert_eq!(v["code"], "COMMON.INTERNAL_ERROR");
        assert_eq!(v["message"], format!("Something went wrong on our side. Error id {id}: give it to support."));
        assert_eq!(v["debugMessage"], "Empty input string");

        let e = AuthError::Unknown { status: StatusCode::BAD_REQUEST, cause: "bad body".into() };
        assert!(e.is_client_error());
        let r = e.into_response();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body(r).await["code"], "COMMON.BAD_REQUEST");
        for (s, code) in [(405, "COMMON.METHOD_NOT_ALLOWED"), (413, "COMMON.PAYLOAD_TOO_LARGE"), (415, "COMMON.BODY_NOT_JSON")] {
            let e = AuthError::Unknown { status: StatusCode::from_u16(s).unwrap(), cause: "x".into() };
            assert_eq!(e.code(), code);
        }
        assert_eq!(AuthError::Unauthenticated.to_string(), "401: not authenticated");
        assert!(AuthError::literal(StatusCode::FORBIDDEN, "SEC.TOKEN_FORBIDDEN", "Forbidden").to_string().contains("Forbidden"));
        let e: AuthError = anyhow::anyhow!("boom").into();
        assert_eq!(e.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let e: AuthError = sqlx::Error::RowNotFound.into();
        assert_eq!(e.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(AuthError::Unauthenticated.message(), "");
    }

    #[tokio::test]
    async fn permission_refusals_name_the_permission_or_ask_to_sign_in() {
        let signed_in = ContextAuth { authenticated: true, ..Default::default() };
        let e = AuthError::denied(&signed_in, &["Authorities.Client_UPDATE"]);
        assert_eq!((e.status(), e.message(), e.to_string()), (StatusCode::FORBIDDEN, "Access Denied".to_string(), "403: Access Denied".to_string()));
        let v = body(e.into_response()).await;
        assert_eq!(v["code"], "COMMON.PERMISSION_REQUIRED");
        assert_eq!(v["message"], "You can't do this: your account does not have the Edit clients permission.");
        assert_eq!(v["debugMessage"], "Access Denied: needs Authorities.Client_UPDATE");

        let r = AuthError::denied(&ContextAuth::default(), &["Authorities.Client_UPDATE"]).into_response();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        let v = body(r).await;
        assert_eq!(v["code"], "COMMON.SIGN_IN_REQUIRED", "an anonymous caller learns nothing about permissions");
        assert_eq!(v["message"], "Please sign in to continue.");
    }

    #[tokio::test]
    async fn codes_values_and_overrides() {
        let e = AuthError::msg(StatusCode::NOT_FOUND, OBJECT_NOT_FOUND, &["ClientUrl", "null"]);
        assert_eq!(e.message(), "ClientUrl with id null not found");
        let v = body(e.into_response()).await;
        assert_eq!(v["message"], "We couldn't find the client address.", "Java's null is left out");
        assert_eq!(v["params"], serde_json::json!({"what": "client address"}));

        let e = AuthError::msg(StatusCode::FORBIDDEN, FORBIDDEN_PERMISSION, &["SSO target app"]).with_code("SEC.SSO_TARGET_APP_FORBIDDEN");
        assert_eq!(e.code(), "SEC.SSO_TARGET_APP_FORBIDDEN");
        assert_eq!(e.message(), "Permission/Role SSO target app is required to use this operation");

        let e = AuthError::msg(StatusCode::BAD_REQUEST, "user_app_request_already_exists", &["leadzump"]).with_param("app", "LeadZump");
        let v = body(e.into_response()).await;
        assert_eq!(v["message"], "You have already asked for access to LeadZump.");
        assert_eq!(v["debugMessage"], "[user_app_request_already_exists] User Access Request for leadzump already exists.");

        let e = AuthError::msg(StatusCode::BAD_REQUEST, "no_such_key", &[]);
        assert_eq!((e.code(), e.message()), ("SEC.UNKNOWN_ERROR".to_string(), "Internal Server Error (Unknown)".to_string()));

        let e = AuthError::msg(StatusCode::UNAUTHORIZED, TOKEN_EXPIRED, &[]).with_debug("bad signature");
        let v = body(e.into_response()).await;
        assert_eq!(v["debugMessage"], "[token_expired] Authorization token expired. Please re-login. (bad signature)");

        let e = AuthError::input(StatusCode::BAD_REQUEST, "400 BAD_REQUEST \"Type mismatch.\"", Coded::new("COMMON.PARAM_INVALID"))
            .with_param("field", "clientId")
            .with_code("COMMON.PARAM_INVALID");
        assert_eq!(e.message(), "Please try again. A server error - $");
        assert_eq!(e.to_string(), "400 Bad Request: 400 BAD_REQUEST \"Type mismatch.\"");
        let v = body(e.into_response()).await;
        assert_eq!(v["message"], "The value of the clientId parameter is not valid.");
        assert_eq!(v["debugMessage"], "400 BAD_REQUEST \"Type mismatch.\"");

        // Builders leave the other kinds alone.
        assert!(matches!(AuthError::Unauthenticated.with_code("X").with_param("a", 1).with_debug("d"), AuthError::Unauthenticated));
    }
}
