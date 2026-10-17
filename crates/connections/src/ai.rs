//! AI chat: `AIService` (an AI connection by name), `OpenAIService` (one user message to
//! `gpt-4o-mini` through the OpenAI chat completions API), and `CoreServices.AI.Chat`.
//!
//! Java registers a service for `OPENAI` only; a `GEMINI`, `CLAUDE`, `GROK` or `DEEP_SEEK`
//! connection is refused as "Connection details missing <subtype>", and so it is here.

use std::time::Duration;

use http::StatusCode;
use serde_json::{json, Value};

use crate::connection::{self, Connection, ConnectionStore, ConnectionSubType, ConnectionType};
use crate::context::Caller;
use crate::error::{messages, ConnError, ConnResult};
use crate::java::{self, json};
use crate::rest::http::{HttpClient, OutboundRequest};

/// The model `OpenAIService` asks for.
pub const MODEL: &str = "gpt-4o-mini";
/// The OpenAI SDK's default retries (408, 409, 429, 5xx and connection failures).
const MAX_RETRIES: u32 = 2;

/// The request body the OpenAI Java SDK sends for one user message.
pub fn chat_body(prompt: &str) -> Value {
    json!({"messages": [{"content": prompt, "role": "user"}], "model": MODEL})
}

/// The SDK's backoff before retry `n` (0-based): 0.5 s doubling, at most 8 s.
fn backoff(n: u32) -> Duration {
    Duration::from_millis((500u64 << n).min(8000))
}

/// `OpenAIService.chat`: the first choice's message content.
pub async fn openai_chat(http: &HttpClient, base_url: &str, conn: Option<&Connection>, prompt: &str) -> ConnResult<String> {
    let api_key = conn
        .and_then(|c| c.details())
        .filter(|d| !d.is_empty())
        .and_then(|d| d.get("apiKey"))
        .filter(|k| !java::safe_is_blank(Some(k)))
        .map(java::to_java_string);
    let Some(api_key) = api_key else {
        let name = conn.map(|c| c.name().to_string()).unwrap_or_else(|| "Unknown Connection".into());
        return Err(ConnError::msg(StatusCode::INTERNAL_SERVER_ERROR, messages::UNABLE_AI_CONNECTION, &[&name]));
    };
    let url = format!("{}/chat/completions", base_url.trim_end_matches('/'));
    let body = json::jackson(&chat_body(prompt)).into_bytes();
    let mut attempt = 0;
    loop {
        let request = OutboundRequest {
            method: "POST".into(),
            uri: url.clone(),
            headers: vec![
                ("Authorization".into(), format!("Bearer {api_key}")),
                ("Content-Type".into(), "application/json".into()),
                ("Accept".into(), "application/json".into()),
            ],
            body: Some(body.clone()),
        };
        let result = match http.send(request).await {
            Ok(r) => {
                let status = r.status;
                let bytes = r.read_body(16 * 1024 * 1024).await?;
                Ok((status, bytes))
            }
            Err(e) => Err(e),
        };
        let retryable = match &result {
            Err(_) => true,
            Ok((status, _)) => matches!(status, 408 | 409 | 429) || *status >= 500,
        };
        if retryable && attempt < MAX_RETRIES {
            tokio::time::sleep(backoff(attempt)).await;
            attempt += 1;
            continue;
        }
        let (status, bytes) = result?;
        let text = String::from_utf8_lossy(&bytes).into_owned();
        if status >= 400 {
            return Err(ConnError::other(format!("{status}: {text}")));
        }
        let v: Value = serde_json::from_str(&text).map_err(|e| ConnError::other(format!("Unable to read the AI response: {e}")))?;
        let first = v.get("choices").and_then(Value::as_array).and_then(|c| c.first());
        let content = first.and_then(|c| c.get("message")).and_then(|m| m.get("content")).and_then(Value::as_str);
        return match content {
            Some(c) => Ok(c.to_string()),
            None => Err(ConnError::msg(StatusCode::INTERNAL_SERVER_ERROR, messages::EMPTY_AI_RESPONSE, &[])),
        };
    }
}

/// `AIService.chat(appCode, clientCode, connectionName, prompt)`. `None` when the codes cannot
/// be resolved (no security context).
pub async fn chat(
    store: &dyn ConnectionStore,
    http: &HttpClient,
    openai_base_url: &str,
    caller: &Caller,
    app_code: Option<&str>,
    client_code: Option<&str>,
    connection_name: &str,
    prompt: &str,
) -> ConnResult<Option<String>> {
    let (Some(app), Some(client)) = caller.resolve_app_and_client(app_code, client_code) else { return Ok(None) };
    let Some(conn) = connection::read(store, caller, connection_name, &app, &client, ConnectionType::Ai).await? else {
        return Err(ConnError::msg(StatusCode::NOT_FOUND, messages::CONNECTION_DETAILS_MISSING, &[connection_name]));
    };
    if conn.connection_sub_type != Some(ConnectionSubType::OpenAi) {
        let shown = conn.connection_sub_type.map(|s| s.name()).unwrap_or("null");
        return Err(ConnError::msg_as(StatusCode::NOT_FOUND, messages::CONNECTION_DETAILS_MISSING, "CORE.AI_CONNECTION_UNSUPPORTED", &[shown]));
    }
    openai_chat(http, openai_base_url, Some(&conn), prompt).await.map(Some)
}

/// What `CoreServices.AI.Chat` raises: `output {response}`, or `error {error}` followed by
/// `output {response: ""}`.
#[derive(Debug, Clone, PartialEq)]
pub enum ChatOutcome {
    Response(Value),
    Failed(String),
    /// Java's empty result.
    NoOutput,
}

/// `Chat.internalExecute`: `response: false` outside a KIRun runtime; the blank codes from the
/// caller; any failure as the error event.
pub async fn chat_function(
    store: &dyn ConnectionStore,
    http: &HttpClient,
    openai_base_url: &str,
    caller: &Caller,
    app_code: &str,
    client_code: &str,
    connection_name: &str,
    prompt: &str,
) -> ChatOutcome {
    if !caller.in_kirun {
        return ChatOutcome::Response(Value::Bool(false));
    }
    if !caller.present {
        return ChatOutcome::NoOutput;
    }
    let app = if java::trim(app_code).is_empty() { caller.url_app_code.clone() } else { Some(app_code.to_string()) };
    let client = if java::trim(client_code).is_empty() { caller.client_code.clone() } else { Some(client_code.to_string()) };
    match chat(store, http, openai_base_url, caller, app.as_deref(), client.as_deref(), connection_name, prompt).await {
        Ok(Some(r)) => ChatOutcome::Response(Value::String(r)),
        Ok(None) => ChatOutcome::NoOutput,
        Err(e) => ChatOutcome::Failed(e.message().to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_body_and_backoff() {
        assert_eq!(json::jackson(&chat_body("hi")), r#"{"messages":[{"content":"hi","role":"user"}],"model":"gpt-4o-mini"}"#);
        assert_eq!(backoff(0), Duration::from_millis(500));
        assert_eq!(backoff(1), Duration::from_millis(1000));
        assert_eq!(backoff(9), Duration::from_millis(8000));
    }
}
