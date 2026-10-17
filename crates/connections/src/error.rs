//! Errors as the Java services raise them: a `GenericException` carries a status and a
//! message; anything else is an exception whose `getMessage()` is all a caller ever sees.

use http::StatusCode;
use platform::error::Coded;
use platform::messages::JavaKey;

#[derive(Debug, Clone, thiserror::Error)]
pub enum ConnError {
    /// `GenericException(status, message)`; `code` (core's `CORE.*`) says it plainly.
    #[error("{message}")]
    Generic { status: StatusCode, message: String, code: Option<Box<Coded>> },

    /// Any other exception: a failed connection, a timeout, a parse error. `message` stands in
    /// for Java's `getMessage()`; the texts differ from the JVM's (see DIFFERENCES.md).
    #[error("{message}")]
    Other { message: String },

    /// A `FeignException` from another service: its status (`-1` without a response) and, when
    /// the answer was JSON, the body.
    #[error("{message}")]
    Feign { status: i32, message: String, body: Option<serde_json::Value> },
}

pub type ConnResult<T> = Result<T, ConnError>;

impl ConnError {
    /// A Java text with no code (one that came from elsewhere).
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self::Generic { status, message: message.into(), code: None }
    }

    /// `new GenericException(status, literal)`, said plainly by `code`.
    pub fn coded(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        crate::catalogue::register();
        Self::Generic { status, message: message.into(), code: Some(Box::new(Coded::new(code))) }
    }

    /// `msgService.throwMessage(status, KEY, params...)` with core's `messages_en`: Java's text
    /// and the code standing for the key.
    pub fn msg(status: StatusCode, key: JavaKey, params: &[&str]) -> Self {
        crate::catalogue::register();
        Self::Generic { status, message: key.text(params), code: Some(Box::new(key.coded("CORE", params))) }
    }

    /// The key's Java text said by a more specific `code`, its values named by that code.
    pub fn msg_as(status: StatusCode, key: JavaKey, code: &'static str, params: &[&str]) -> Self {
        crate::catalogue::register();
        Self::Generic { status, message: key.text(params), code: Some(Box::new(key.coded_as(code, params))) }
    }

    /// Sets a value of the message.
    pub fn param(self, name: &str, value: impl ToString) -> Self {
        match self {
            Self::Generic { status, message, code } => Self::Generic { status, message, code: code.map(|c| Box::new(c.param(name, value))) },
            other => other,
        }
    }

    pub fn other(message: impl Into<String>) -> Self {
        Self::Other { message: message.into() }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::Generic { message, .. } | Self::Other { message } | Self::Feign { message, .. } => message,
        }
    }

    /// The code a `GenericException` answers with, when it has one.
    pub fn code(&self) -> Option<&Coded> {
        match self {
            Self::Generic { code, .. } => code.as_deref(),
            _ => None,
        }
    }

    /// The status a `GenericException` carries; 500 for anything else.
    pub fn status(&self) -> StatusCode {
        match self {
            Self::Generic { status, .. } => *status,
            Self::Feign { status, .. } => StatusCode::from_u16(*status as u16).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            Self::Other { .. } => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

/// core's `messages_en.properties`, for the messages this crate raises.
pub mod messages {
    use platform::messages::JavaKey;

    pub const CONNECTION_DETAILS_MISSING: JavaKey = JavaKey::new("connection_details_missing", "Connection details missing $");
    pub const TEMPLATE_DETAILS_MISSING: JavaKey = JavaKey::new("template_details_missing", "Template details missing : $");
    pub const UNABLE_AI_CONNECTION: JavaKey = JavaKey::new("unable_ai_connection", "Unable to connect to AI connection $");
    pub const EMPTY_AI_RESPONSE: JavaKey = JavaKey::new("empty_ai_response", "Empty response received");
    pub const MAIL_SEND_ERROR: JavaKey = JavaKey::new("mail_send_error", "Unable to send the email: $");
    pub const NOT_ABLE_TO_CREATE_TOKEN: JavaKey = JavaKey::new("not_able_to_create_token", "Not able to create a token for the connection $: $");
    pub const CANNOT_DELETE_TOKEN_WITH_CLIENT_CODE: JavaKey = JavaKey::new("cannot_delete_token_with_client_code", "No active token found to revoke for connection $");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coded_errors() {
        let e = ConnError::msg(StatusCode::NOT_FOUND, messages::TEMPLATE_DETAILS_MISSING, &["welcome"]);
        assert_eq!(e.message(), "Template details missing : welcome");
        let c = e.code().unwrap();
        assert_eq!((c.code.as_ref(), c.english().message.as_str()), ("CORE.TEMPLATE_DETAILS_MISSING", "We couldn't find the template welcome."));
        let e = ConnError::msg_as(StatusCode::NOT_FOUND, messages::CONNECTION_DETAILS_MISSING, "CORE.MAIL_CONNECTION_UNSUPPORTED", &["REST"]);
        assert_eq!(e.code().unwrap().params, vec![("provider".to_string(), "REST".to_string())]);
        let e = ConnError::coded(StatusCode::BAD_REQUEST, "CORE.BASE64_INVALID", "Not a base64 encoded string").param("x", 1);
        assert_eq!((e.status(), e.code().unwrap().params.len()), (StatusCode::BAD_REQUEST, 1));
        assert!(ConnError::new(StatusCode::CONFLICT, "m").code().is_none());
        assert!(ConnError::other("x").param("a", 1).code().is_none());
        assert!(ConnError::Feign { status: 403, message: "m".into(), body: None }.code().is_none());
    }
}
