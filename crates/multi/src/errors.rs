//! What a multi route answers when it fails.
//!
//! multi's own errors are coded (`crate::catalogue`, codes `MULTI.*` and the shared `COMMON.*`):
//! Java's status where Java has one, the text in the request's language, the next step, and the
//! technical detail in `debugMessage`. An error a service multi calls answers with its own code
//! (a Rust unit's coded body) is passed on as it came, so the person reads the text that service
//! wrote; a Java service's `message` is relayed with its status, as Java's `ControllerAdvice`
//! does (`handleFeignException`).

use axum::body::{Body, Bytes};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use platform::error::{AppError, Coded};
use serde_json::Value;

/// A failed request.
#[derive(Debug)]
pub enum Failure {
    /// One of multi's own errors.
    Own(AppError),
    /// Another service's coded error, passed on with its status and body.
    Relayed { status: StatusCode, body: Bytes },
}

pub type Res<T> = Result<T, Failure>;

impl From<AppError> for Failure {
    fn from(e: AppError) -> Self {
        Self::Own(e)
    }
}

impl From<Coded> for Failure {
    fn from(c: Coded) -> Self {
        crate::catalogue::register();
        Self::Own(c.into())
    }
}

impl Failure {
    pub fn status(&self) -> StatusCode {
        match self {
            Self::Own(e) => e.status(),
            Self::Relayed { status, .. } => *status,
        }
    }
}

/// Anything unexpected: 500 with the error id, the detail logged and in `debugMessage`.
pub fn internal(detail: impl std::fmt::Display) -> Failure {
    Coded::new("COMMON.INTERNAL_ERROR").debug(detail.to_string()).into()
}

/// A body another Rust unit wrote with a code (`code` and `exceptionId` present).
pub fn is_coded_body(v: &Value) -> bool {
    v.get("code").is_some_and(Value::is_string) && v.get("exceptionId").is_some()
}

impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        crate::catalogue::register();
        match self {
            // The platform writes an unexpected error as Java's "Please try again" text; multi's
            // say it with the code.
            Self::Own(AppError::Internal(e)) => AppError::from(Coded::new("COMMON.INTERNAL_ERROR").debug(format!("{e:#}"))).into_response(),
            Self::Own(e) => e.into_response(),
            Self::Relayed { status, body } => {
                let mut resp = Response::new(Body::from(body));
                *resp.status_mut() = status;
                resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
                resp
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    async fn body(r: Response) -> Value {
        serde_json::from_slice(&to_bytes(r.into_body(), 100_000).await.unwrap()).unwrap()
    }

    #[tokio::test]
    async fn own_relayed_and_internal() {
        let f: Failure = Coded::new("MULTI.TRANSPORT_EXPORT_FORBIDDEN").into();
        assert_eq!(f.status(), StatusCode::FORBIDDEN);
        let v = body(f.into_response()).await;
        assert_eq!(v["code"], "MULTI.TRANSPORT_EXPORT_FORBIDDEN");
        assert_eq!(v["message"], "You can't export this app: your organisation does not have write access to it.");

        let sent = br#"{"exceptionId":"x","code":"SEC.FORBIDDEN_CREATE","message":"No."}"#;
        let f = Failure::Relayed { status: StatusCode::FORBIDDEN, body: Bytes::from_static(sent) };
        assert_eq!(f.status(), StatusCode::FORBIDDEN);
        let r = f.into_response();
        assert_eq!((r.status(), r.headers()["content-type"].to_str().unwrap()), (StatusCode::FORBIDDEN, "application/json"));
        assert_eq!(to_bytes(r.into_body(), 1000).await.unwrap().as_ref(), sent, "passed on byte for byte");

        let f: Failure = AppError::Internal(anyhow::anyhow!("zip broke")).into();
        let v = body(f.into_response()).await;
        assert_eq!(v["code"], "COMMON.INTERNAL_ERROR");
        assert_eq!(v["debugMessage"], "zip broke");
        let v = body(internal("boom").into_response()).await;
        assert_eq!((v["code"].as_str(), v["debugMessage"].as_str()), (Some("COMMON.INTERNAL_ERROR"), Some("boom")));

        let v = body(Failure::from(AppError::new(StatusCode::CONFLICT, "Java text")).into_response()).await;
        assert_eq!(v["message"], "Java text", "a relayed Java message keeps Java's shape");
        assert!(v.get("code").is_none());

        assert!(is_coded_body(&serde_json::json!({"code": "X", "exceptionId": "1"})));
        assert!(!is_coded_body(&serde_json::json!({"message": "Java", "exceptionId": "1"})));
        assert!(!is_coded_body(&serde_json::json!({"code": 5, "exceptionId": "1"})));
    }
}
