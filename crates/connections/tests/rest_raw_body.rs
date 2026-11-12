//! `application/octet-stream` with one base64 data URL goes out as the raw body (DIFFERENCES.md
//! #40, LZT-2418): Meta's resumable upload (`POST upload:<session>`, `file_offset: 0`) stores the
//! request body as the file. Any other payload with that type still answers "Url not found".

use std::sync::Arc;

use async_trait::async_trait;
use connections::connection::{Connection, ConnectionStore};
use connections::error::ConnResult;
use connections::rest::auth::{AuthTokenFunction, EventResult};
use connections::rest::{basic, RestRequest};
use connections::tokens::{CoreToken, TokenStore, TokenType};
use connections::{Connections, ConnectionsConfig};
use parking_lot::Mutex;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

struct NoStore;
#[async_trait]
impl ConnectionStore for NoStore {
    async fn read_internal(&self, _: &str, _: &str, _: &str, _: &str) -> ConnResult<Option<Connection>> {
        Ok(None)
    }
}

struct NoTokens;
#[async_trait]
impl TokenStore for NoTokens {
    async fn active_access_token_tuple(&self, _: &str, _: &str, _: &str) -> ConnResult<Option<(Option<String>, Option<chrono::NaiveDateTime>)>> {
        Ok(None)
    }
    async fn active_token(&self, _: &str, _: &str, _: &str, _: TokenType) -> ConnResult<Option<CoreToken>> {
        Ok(None)
    }
    async fn by_state(&self, _: Option<&str>) -> ConnResult<Option<CoreToken>> {
        Ok(None)
    }
    async fn revoke(&self, _: &str, _: &str, _: &str, _: Option<TokenType>) -> ConnResult<bool> {
        Ok(false)
    }
    async fn create(&self, t: &CoreToken) -> ConnResult<CoreToken> {
        Ok(t.clone())
    }
    async fn update(&self, t: &CoreToken) -> ConnResult<Option<CoreToken>> {
        Ok(Some(t.clone()))
    }
}

struct NoFunctions;
#[async_trait]
impl AuthTokenFunction for NoFunctions {
    async fn execute(&self, _: Option<&str>, _: &str, _: Option<&str>, _: Option<&str>) -> ConnResult<Option<Vec<EventResult>>> {
        Ok(None)
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Answers every request with `{"h":"H"}` and records (head, body).
async fn serve(listener: TcpListener, log: Arc<Mutex<Vec<(String, Vec<u8>)>>>) {
    loop {
        let Ok((mut sock, _)) = listener.accept().await else { return };
        let log = log.clone();
        tokio::spawn(async move {
            let mut data = Vec::new();
            let mut buf = [0u8; 65536];
            let head_end = loop {
                if let Some(i) = find(&data, b"\r\n\r\n") {
                    break i;
                }
                let n = sock.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    return;
                }
                data.extend_from_slice(&buf[..n]);
            };
            let head = String::from_utf8_lossy(&data[..head_end]).to_ascii_lowercase();
            let len: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:").map(|v| v.trim().parse().unwrap_or(0)))
                .unwrap_or(0);
            while data.len() < head_end + 4 + len {
                let n = sock.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                data.extend_from_slice(&buf[..n]);
            }
            log.lock().push((head, data[head_end + 4..].to_vec()));
            let body = br#"{"h":"H"}"#;
            let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.write_all(body).await;
        });
    }
}

fn request(payload: Value) -> RestRequest {
    RestRequest {
        url: "/upload:1".into(),
        headers: Some(vec![
            ("Content-Type".into(), vec!["application/octet-stream".into()]),
            ("file_offset".into(), vec!["0".into()]),
        ]),
        path_parameters: Default::default(),
        query_parameters: None,
        timeout: 10,
        method: "POST".into(),
        payload: Some(payload),
        ignore_default_headers: false,
    }
}

#[tokio::test]
async fn octet_stream_sends_the_decoded_file() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let log = Arc::new(Mutex::new(Vec::new()));
    tokio::spawn(serve(listener, log.clone()));
    let svc = Connections::new(
        ConnectionsConfig { block_private_targets: false, ..Default::default() },
        Arc::new(NoStore),
        Arc::new(NoTokens),
        platform::cache::CacheService::new("cmn", "evictionChannel", None).unwrap(),
        Arc::new(NoFunctions),
    );
    let conn = Connection::from_json(json!({"name": "conn", "connectionDetails": {"baseUrl": format!("http://127.0.0.1:{port}")}})).unwrap();

    // "hi\xff" as base64, as FileToBase64 writes it.
    let r = basic::call(&svc, &conn, request(json!({"file": "data:image/jpeg;name:a.jpg;base64,aGn/"})), false)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(r.status, 200);
    {
        let seen = log.lock();
        let (head, body) = seen.last().unwrap();
        assert_eq!(body, b"hi\xff");
        assert!(head.contains("content-type: application/octet-stream"), "{head}");
        assert!(head.contains("file_offset: 0"), "{head}");
        assert!(head.contains("content-length: 3"), "{head}");
    }

    // Anything else with this type is answered without a call, as before.
    let before = log.lock().len();
    let r = basic::call(&svc, &conn, request(json!({"a": "x", "b": "y"})), false).await.unwrap().unwrap();
    assert_eq!(r.status, 400);
    assert_eq!(log.lock().len(), before);

    // Bad base64 is refused.
    let e = basic::call(&svc, &conn, request(json!({"file": "data:image/png;base64,!!"})), false).await.unwrap_err();
    assert_eq!(e.message(), "Not a base64 encoded string");
}
