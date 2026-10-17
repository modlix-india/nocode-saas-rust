//! What a notification route answers when it fails.
//!
//! The service's own errors are coded (`crate::catalogue`, codes `NOTIF.*` and the shared
//! `COMMON.*`): the text in the request's language, the next step, and the technical detail in
//! `debugMessage`. An error security answers with its own code (a Rust unit's coded body) is
//! passed on as it came; a Java service's `message` is relayed with its status, as commons2's
//! `ControllerAdvice` does (`handleFeignExceptionInternal`).

use axum::body::{Body, Bytes};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use platform::error::{AppError, Coded};
use serde_json::Value;

/// A failed request.
#[derive(Debug)]
pub enum Failure {
    /// One of the service's own errors.
    Own(AppError),
    /// Another service's coded error, passed on with its status and body.
    Relayed { status: StatusCode, body: Bytes },
}

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

/// [`internal`] for an `anyhow` error, with its causes.
pub fn internal_error(e: anyhow::Error) -> Failure {
    internal(format!("{e:#}"))
}

/// A body another Rust unit wrote with a code (`code` and `exceptionId` present).
pub fn is_coded_body(v: &Value) -> bool {
    v.get("code").is_some_and(Value::is_string) && v.get("exceptionId").is_some()
}

impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        crate::catalogue::register();
        match self {
            Self::Own(AppError::Internal(e)) => internal_error(e).into_response(),
            Self::Own(e) => e.into_response(),
            Self::Relayed { status, body } => {
                let mut resp = Response::new(Body::from(body));
                *resp.status_mut() = status;
                resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
                platform::http::spring_security_headers(resp.headers_mut(), true);
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
        let f: Failure = Coded::new("NOTIF.STREAM_NOT_ACCEPTABLE").into();
        assert_eq!(f.status(), StatusCode::NOT_ACCEPTABLE);
        assert_eq!(body(f.into_response()).await["code"], "NOTIF.STREAM_NOT_ACCEPTABLE");

        let sent = br#"{"exceptionId":"x","code":"SEC.OBJECT_NOT_FOUND","message":"No."}"#;
        let f = Failure::Relayed { status: StatusCode::NOT_FOUND, body: Bytes::from_static(sent) };
        assert_eq!(f.status(), StatusCode::NOT_FOUND);
        let r = f.into_response();
        assert_eq!(r.headers()["content-type"], "application/json");
        assert_eq!(to_bytes(r.into_body(), 1000).await.unwrap().as_ref(), sent, "passed on byte for byte");

        let v = body(Failure::from(AppError::Internal(anyhow::anyhow!("db down"))).into_response()).await;
        assert_eq!((v["code"].as_str(), v["debugMessage"].as_str()), (Some("COMMON.INTERNAL_ERROR"), Some("db down")));
        let id = v["exceptionId"].as_str().unwrap();
        assert_eq!(v["message"], format!("Something went wrong on our side. Error id {id}: give it to support."));

        let v = body(Failure::from(AppError::new(StatusCode::BAD_REQUEST, "Java text")).into_response()).await;
        assert_eq!(v["message"], "Java text");
        assert!(is_coded_body(&serde_json::json!({"code": "X", "exceptionId": "1"})));
        assert!(!is_coded_body(&serde_json::json!({"message": "Java"})));
    }
}
