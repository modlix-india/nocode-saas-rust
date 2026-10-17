//! AI chat against a local stand-in for the OpenAI chat completions API (no provider is
//! called): the request the SDK makes, the answer read back, retries, and the Chat function's
//! events.

use std::sync::Arc;

use async_trait::async_trait;
use connections::ai::{self, ChatOutcome};
use connections::connection::{Connection, ConnectionStore};
use connections::context::Caller;
use connections::error::ConnResult;
use connections::rest::http::HttpClient;
use parking_lot::Mutex;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Answers each request with the next canned `(status, body)`, recording what it got.
async fn fake_openai(answers: Vec<(u16, &'static str)>) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let log = Arc::new(Mutex::new(Vec::new()));
    let l2 = log.clone();
    let answers = Arc::new(Mutex::new(answers.into_iter()));
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else { return };
            let mut data = Vec::new();
            let mut buf = vec![0u8; 65536];
            loop {
                let n = sock.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                data.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&data).to_string();
                if let Some(i) = text.find("\r\n\r\n") {
                    let len: usize = text
                        .lines()
                        .find(|l| l.to_lowercase().starts_with("content-length"))
                        .and_then(|l| l.split(':').nth(1))
                        .and_then(|v| v.trim().parse().ok())
                        .unwrap_or(0);
                    if data.len() >= i + 4 + len {
                        break;
                    }
                }
            }
            l2.lock().push(String::from_utf8_lossy(&data).into_owned());
            let (status, body) = answers.lock().next().unwrap_or((500, "{}"));
            let resp = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
        }
    });
    (format!("http://127.0.0.1:{port}/v1"), log)
}

struct Store(Vec<Connection>);
#[async_trait]
impl ConnectionStore for Store {
    async fn read_internal(&self, name: &str, _: &str, _: &str, _: &str) -> ConnResult<Option<Connection>> {
        Ok(self.0.iter().find(|c| c.name() == name).cloned())
    }
}

fn openai(name: &str, sub: &str, key: &str) -> Connection {
    Connection::from_json(json!({
        "name": name, "clientCode": "SYSTEM", "isAppLevel": true,
        "connectionType": "AI", "connectionSubType": sub, "connectionDetails": {"apiKey": key}
    }))
    .unwrap()
}

fn caller() -> Caller {
    Caller {
        present: true,
        client_code: Some("SYSTEM".into()),
        url_client_code: Some("SYSTEM".into()),
        url_app_code: Some("app".into()),
        in_kirun: true,
        ..Default::default()
    }
}

const ANSWER: &str = r#"{"id":"c1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"Hello there"},"finish_reason":"stop"}]}"#;

#[tokio::test]
async fn chat_sends_one_user_message_to_gpt_4o_mini() {
    let (base, log) = fake_openai(vec![(200, ANSWER)]).await;
    let store = Store(vec![openai("gpt", "OPENAI", "sk-test")]);
    let http = HttpClient { block_private_targets: false };
    let out = ai::chat_function(&store, &http, &base, &caller(), "", "", "gpt", "Say hi").await;
    assert_eq!(out, ChatOutcome::Response(json!("Hello there")));
    let req = log.lock()[0].clone();
    assert!(req.starts_with("POST /v1/chat/completions HTTP/1.1"), "{req}");
    assert!(req.contains("authorization: Bearer sk-test"));
    assert!(req.ends_with(r#"{"messages":[{"content":"Say hi","role":"user"}],"model":"gpt-4o-mini"}"#));
}

#[tokio::test]
async fn retries_like_the_sdk_then_reports_the_error() {
    let (base, log) = fake_openai(vec![(500, "{}"), (429, "{}"), (200, ANSWER)]).await;
    let store = Store(vec![openai("gpt", "OPENAI", "sk-test")]);
    let http = HttpClient { block_private_targets: false };
    let r = ai::chat(&store, &http, &base, &caller(), Some("app"), Some("SYSTEM"), "gpt", "x").await.unwrap();
    assert_eq!(r.as_deref(), Some("Hello there"));
    assert_eq!(log.lock().len(), 3);

    let (base, _) = fake_openai(vec![(401, r#"{"error":"bad key"}"#)]).await;
    let out = ai::chat_function(&store, &http, &base, &caller(), "", "", "gpt", "x").await;
    assert_eq!(out, ChatOutcome::Failed(r#"401: {"error":"bad key"}"#.into()));

    let (base, _) = fake_openai(vec![(200, r#"{"choices":[]}"#)]).await;
    let out = ai::chat_function(&store, &http, &base, &caller(), "", "", "gpt", "x").await;
    assert_eq!(out, ChatOutcome::Failed("Empty response received".into()));
}

#[tokio::test]
async fn refusals() {
    let store = Store(vec![openai("gem", "GEMINI", "k"), openai("nokey", "OPENAI", " ")]);
    let http = HttpClient { block_private_targets: false };
    let c = caller();
    assert_eq!(
        ai::chat_function(&store, &http, "http://127.0.0.1:1", &c, "", "", "gem", "x").await,
        ChatOutcome::Failed("Connection details missing GEMINI".into())
    );
    assert_eq!(
        ai::chat_function(&store, &http, "http://127.0.0.1:1", &c, "", "", "none", "x").await,
        ChatOutcome::Failed("Connection details missing none".into())
    );
    assert_eq!(
        ai::chat_function(&store, &http, "http://127.0.0.1:1", &c, "", "", "nokey", "x").await,
        ChatOutcome::Failed("Unable to connect to AI connection nokey".into())
    );
    let mut outside = caller();
    outside.in_kirun = false;
    assert_eq!(ai::chat_function(&store, &http, "x", &outside, "", "", "gem", "x").await, ChatOutcome::Response(json!(false)));
    let anonymous = Caller { in_kirun: true, ..Default::default() };
    assert_eq!(ai::chat_function(&store, &http, "x", &anonymous, "", "", "gem", "x").await, ChatOutcome::NoOutput);
    assert!(ai::openai_chat(&http, "x", None, "p").await.unwrap_err().message().ends_with("Unknown Connection"));
}
