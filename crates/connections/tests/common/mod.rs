//! Shared fakes for the integration tests: in-memory `core_tokens`, a connection store, an
//! auth-token function, and a tiny HTTP server answering canned responses.

#![allow(dead_code)]

use std::sync::Arc;

use async_trait::async_trait;
use chrono::NaiveDateTime;
use connections::connection::{Connection, ConnectionStore};
use connections::context::Caller;
use connections::error::ConnResult;
use connections::rest::auth::{AuthTokenFunction, EventResult};
use connections::tokens::{CoreToken, JavaClock, TokenStore, TokenType};
use connections::{Connections, ConnectionsConfig};
use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// `core_tokens` in memory, with the DAO's filters.
#[derive(Default)]
pub struct MemTokens {
    pub rows: Mutex<Vec<CoreToken>>,
    pub clock: JavaClock,
}

#[async_trait]
impl TokenStore for MemTokens {
    async fn active_access_token_tuple(&self, c: &str, a: &str, n: &str) -> ConnResult<Option<(Option<String>, Option<NaiveDateTime>)>> {
        let now = self.clock.now();
        Ok(self
            .rows
            .lock()
            .iter()
            .find(|t| {
                t.client_code.as_deref() == Some(c)
                    && t.app_code.as_deref() == Some(a)
                    && t.connection_name.as_deref() == Some(n)
                    && t.is_revoked != Some(true)
                    && t.expires_at.is_some_and(|e| e > now)
            })
            .map(|t| (t.token.clone(), t.expires_at)))
    }
    async fn active_token(&self, c: &str, a: &str, n: &str, ty: TokenType) -> ConnResult<Option<CoreToken>> {
        let now = self.clock.now();
        Ok(self
            .rows
            .lock()
            .iter()
            .find(|t| {
                t.client_code.as_deref() == Some(c)
                    && t.app_code.as_deref() == Some(a)
                    && t.connection_name.as_deref() == Some(n)
                    && t.token_type == Some(ty)
                    && t.token.is_some()
                    && t.is_revoked != Some(true)
                    && match t.expires_at {
                        None => t.is_lifetime_token == Some(true),
                        Some(e) => e > now,
                    }
            })
            .cloned())
    }
    async fn by_state(&self, state: Option<&str>) -> ConnResult<Option<CoreToken>> {
        Ok(self.rows.lock().iter().find(|t| state.is_some() && t.state.as_deref() == state).cloned())
    }
    async fn revoke(&self, c: &str, a: &str, n: &str, ty: Option<TokenType>) -> ConnResult<bool> {
        let mut changed = false;
        for t in self.rows.lock().iter_mut() {
            if t.client_code.as_deref() == Some(c)
                && t.app_code.as_deref() == Some(a)
                && t.connection_name.as_deref() == Some(n)
                && ty.is_none_or(|ty| t.token_type == Some(ty))
                && t.is_revoked != Some(true)
            {
                t.is_revoked = Some(true);
                changed = true;
            }
        }
        Ok(changed)
    }
    async fn create(&self, t: &CoreToken) -> ConnResult<CoreToken> {
        let mut rows = self.rows.lock();
        let mut t = t.clone();
        t.id = Some(rows.len() as u64 + 1);
        t.is_revoked.get_or_insert(false);
        t.is_lifetime_token.get_or_insert(false);
        rows.push(t.clone());
        Ok(t)
    }
    async fn update(&self, t: &CoreToken) -> ConnResult<Option<CoreToken>> {
        let mut rows = self.rows.lock();
        let Some(row) = rows.iter_mut().find(|r| r.id == t.id) else { return Ok(None) };
        let (keep_revoked, keep_lifetime) = (row.is_revoked, row.is_lifetime_token);
        *row = t.clone();
        row.is_revoked = t.is_revoked.or(keep_revoked);
        row.is_lifetime_token = t.is_lifetime_token.or(keep_lifetime);
        Ok(Some(row.clone()))
    }
}

/// Connections by name, whatever the app and client asked for.
pub struct Store(pub Vec<Connection>);

#[async_trait]
impl ConnectionStore for Store {
    async fn read_internal(&self, name: &str, _: &str, _: &str, _: &str) -> ConnResult<Option<Connection>> {
        Ok(self.0.iter().find(|c| c.name() == name).cloned())
    }
}

/// An auth-token function answering with the configured events.
pub struct Functions(pub Mutex<Option<Vec<EventResult>>>, pub Mutex<u32>);

impl Functions {
    pub fn answering(events: Option<Vec<EventResult>>) -> Arc<Self> {
        Arc::new(Functions(Mutex::new(events), Mutex::new(0)))
    }
}

#[async_trait]
impl AuthTokenFunction for Functions {
    async fn execute(&self, _: Option<&str>, _: &str, _: Option<&str>, _: Option<&str>) -> ConnResult<Option<Vec<EventResult>>> {
        *self.1.lock() += 1;
        Ok(self.0.lock().clone())
    }
}

pub fn caller() -> Caller {
    Caller {
        present: true,
        authenticated: true,
        user_id: Some(142),
        user_client_id: Some(1),
        client_code: Some("SYSTEM".into()),
        url_client_code: Some("SYSTEM".into()),
        url_app_code: Some("app".into()),
        in_kirun: true,
        ..Default::default()
    }
}

pub fn service(connections: Vec<Connection>, tokens: Arc<MemTokens>, functions: Arc<Functions>) -> Connections {
    Connections::new(
        ConnectionsConfig { block_private_targets: false, ..Default::default() },
        Arc::new(Store(connections)),
        tokens,
        platform::cache::CacheService::new("cmn", "evictionChannel", None).unwrap(),
        functions,
    )
}

/// A canned HTTP answer.
#[derive(Clone)]
pub struct Canned {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Seconds to wait before answering.
    pub delay_ms: u64,
}

impl Canned {
    pub fn json(status: u16, body: &str) -> Self {
        Canned { status, headers: vec![("Content-Type".into(), "application/json".into())], body: body.as_bytes().to_vec(), delay_ms: 0 }
    }
}

/// Answers every request with the next canned answer (the last repeats), recording requests.
pub async fn server(answers: Vec<Canned>) -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let log = Arc::new(Mutex::new(Vec::new()));
    let l2 = log.clone();
    let answers = Arc::new(Mutex::new((answers, 0usize)));
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else { return };
            let log = l2.clone();
            let answers = answers.clone();
            tokio::spawn(async move {
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
                log.lock().push(String::from_utf8_lossy(&data).into_owned());
                let a = {
                    let mut g = answers.lock();
                    let i = g.1.min(g.0.len() - 1);
                    g.1 += 1;
                    g.0[i].clone()
                };
                if a.delay_ms > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(a.delay_ms)).await;
                }
                let mut out = format!("HTTP/1.1 {} X\r\n", a.status).into_bytes();
                for (k, v) in &a.headers {
                    out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
                }
                out.extend_from_slice(format!("Content-Length: {}\r\nConnection: close\r\n\r\n", a.body.len()).as_bytes());
                out.extend_from_slice(&a.body);
                let _ = sock.write_all(&out).await;
            });
        }
    });
    (port, log)
}
