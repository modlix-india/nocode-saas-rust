//! Test support: a recording HTTP fake (security, core, SendGrid), an SMTP stub, and scratch
//! MySQL schemas for the gated tests. Nothing here reaches a real mail provider, and the only
//! databases written are `RUSTTEST_*` schemas, dropped afterwards.

#![allow(dead_code)]

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use futures::FutureExt;
use parking_lot::Mutex;
use serde_json::{json, Value};
use sqlx::mysql::{MySqlConnectOptions, MySqlPool, MySqlPoolOptions};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

/// A request a fake received.
#[derive(Debug, Clone)]
pub struct Recorded {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: HeaderMap,
    pub body: String,
}

impl Recorded {
    pub fn header(&self, name: &str) -> Option<String> {
        self.headers.get(name).and_then(|v| v.to_str().ok()).map(str::to_string)
    }

    pub fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
}

/// What a fake answers for a method and path prefix.
#[derive(Debug, Clone)]
pub struct Answer {
    pub status: u16,
    pub content_type: Option<&'static str>,
    pub body: String,
}

impl Answer {
    pub fn json(v: Value) -> Self {
        Self { status: 200, content_type: Some("application/json"), body: v.to_string() }
    }

    /// Feign's `null`: a 200 without a body.
    pub fn empty() -> Self {
        Self { status: 200, content_type: None, body: String::new() }
    }

    pub fn error(status: u16, message: &str) -> Self {
        Self {
            status,
            content_type: Some("application/json"),
            body: json!({"exceptionId": "x", "message": message}).to_string(),
        }
    }

    pub fn status(status: u16, body: &str) -> Self {
        Self { status, content_type: Some("text/plain"), body: body.to_string() }
    }
}

#[derive(Default)]
pub struct Fake {
    answers: Mutex<Vec<(String, String, Answer)>>,
    pub calls: Mutex<Vec<Recorded>>,
}

impl Fake {
    /// Starts the fake on a free port; its base URL.
    pub async fn start() -> (Arc<Self>, String) {
        let fake = Arc::new(Self::default());
        let app = Router::new().fallback(Self::serve).with_state(fake.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (fake, base)
    }

    async fn serve(State(f): State<Arc<Fake>>, req: Request) -> Response {
        let method = req.method().to_string();
        let path = req.uri().path().to_string();
        let query = req.uri().query().unwrap_or("").to_string();
        let headers = req.headers().clone();
        let body = String::from_utf8_lossy(&to_bytes(req.into_body(), 1 << 20).await.unwrap_or_default()).into_owned();
        f.calls.lock().push(Recorded { method: method.clone(), path: path.clone(), query, headers, body });
        let answer = f
            .answers
            .lock()
            .iter()
            .rev()
            .find(|(m, p, _)| *m == method && path.starts_with(p.as_str()))
            .map(|(_, _, a)| a.clone());
        let Some(a) = answer else { return StatusCode::NOT_FOUND.into_response() };
        let mut resp = Response::new(Body::from(a.body));
        *resp.status_mut() = StatusCode::from_u16(a.status).unwrap();
        if let Some(ct) = a.content_type {
            resp.headers_mut().insert("content-type", ct.parse().unwrap());
        }
        resp
    }

    /// Answers `method` on paths starting with `prefix` (the latest answer set wins).
    pub fn answer(&self, method: &str, prefix: &str, a: Answer) {
        self.answers.lock().push((method.to_string(), prefix.to_string(), a));
    }

    pub fn calls_to(&self, prefix: &str) -> Vec<Recorded> {
        self.calls.lock().iter().filter(|c| c.path.starts_with(prefix)).cloned().collect()
    }

    pub fn clear(&self) {
        self.calls.lock().clear();
    }
}

pub const AUTH_PATH: &str = "/api/security/internal/securityContextAuthentication";
pub const USERS_PATH: &str = "/api/security/users/internal/notification";
pub const CONN_PATH: &str = "/api/core/connections/internal/notification/";
pub const NOTIF_PATH: &str = "/api/core/notifications/internal/";

/// Security's answer for a signed-in SYSTEM user 142 (or an anonymous caller).
pub fn context(authenticated: bool) -> Value {
    json!({
        "user": {"id": if authenticated { 142 } else { 0 }, "clientId": 1, "userName": if authenticated { "142" } else { "_Anonymous" },
                 "stringAuthorities": ["Authorities.Logged_IN"]},
        "authenticated": authenticated,
        "loggedInFromClientId": 1,
        "loggedInFromClientCode": "SYSTEM",
        "clientTypeCode": "SYS",
        "clientCode": "SYSTEM"
    })
}

/// An SMTP stub: one connection at a time, every command accepted except the RCPT replies
/// given; the DATA of each accepted message is kept.
pub struct StubSmtp {
    pub port: u16,
    pub messages: Arc<Mutex<Vec<String>>>,
    pub recipients: Arc<Mutex<Vec<String>>>,
}

impl StubSmtp {
    pub async fn start(rcpt_replies: Vec<(&'static str, &'static str)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let messages = Arc::new(Mutex::new(Vec::new()));
        let recipients = Arc::new(Mutex::new(Vec::new()));
        let (msgs, rcpts) = (messages.clone(), recipients.clone());
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else { return };
                let (r, mut w) = sock.into_split();
                let mut lines = BufReader::new(r).lines();
                if w.write_all(b"220 stub ready\r\n").await.is_err() {
                    continue;
                }
                while let Ok(Some(line)) = lines.next_line().await {
                    let cmd = line.to_uppercase();
                    let reply = if cmd.starts_with("EHLO") || cmd.starts_with("HELO") {
                        "250-stub\r\n250 AUTH PLAIN LOGIN".to_string()
                    } else if cmd.starts_with("AUTH") {
                        "235 ok".into()
                    } else if cmd.starts_with("RCPT") {
                        let addr = line[line.find('<').unwrap() + 1..line.find('>').unwrap()].to_string();
                        rcpts.lock().push(addr.clone());
                        rcpt_replies.iter().find(|(a, _)| *a == addr).map(|(_, r)| r.to_string()).unwrap_or_else(|| "250 ok".into())
                    } else if cmd.starts_with("DATA") {
                        let _ = w.write_all(b"354 go ahead\r\n").await;
                        let mut msg = String::new();
                        while let Ok(Some(l)) = lines.next_line().await {
                            if l == "." {
                                break;
                            }
                            msg.push_str(&l);
                            msg.push('\n');
                        }
                        msgs.lock().push(msg);
                        "250 queued".into()
                    } else if cmd.starts_with("QUIT") {
                        let _ = w.write_all(b"221 bye\r\n").await;
                        break;
                    } else {
                        "250 ok".into()
                    };
                    if w.write_all(format!("{reply}\r\n").as_bytes()).await.is_err() {
                        break;
                    }
                }
            }
        });
        Self { port, messages, recipients }
    }
}

// ------------------------------------------------------------------------------- local stack

/// The gated tests run with `NOTIFICATION_LOCAL_STACK=1` and the local MySQL password in
/// `MODLIX__DATABASE__PASSWORD` (config/local.env).
pub fn local_stack() -> bool {
    std::env::var("NOTIFICATION_LOCAL_STACK").is_ok_and(|v| v == "1")
}

pub fn mysql_password() -> String {
    std::env::var("MODLIX__DATABASE__PASSWORD").unwrap_or_default()
}

fn options(database: Option<&str>) -> MySqlConnectOptions {
    let o = MySqlConnectOptions::new()
        .host("127.0.0.1")
        .port(3306)
        .username("root")
        .password(&mysql_password())
        .timezone(Some(String::from("+00:00")));
    match database {
        Some(d) => o.database(d),
        None => o,
    }
}

/// The DDL of `notification` after V1-V4, as `SHOW CREATE TABLE` printed it on 2026-10-16.
pub const DDL: [&str; 2] = [
    "CREATE TABLE `notification_inapp` (
  `ID` bigint unsigned NOT NULL AUTO_INCREMENT COMMENT 'Primary key, unique identifier for each notification entry',
  `USER_ID` bigint unsigned NOT NULL COMMENT 'User ID',
  `APP_CODE` char(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'App Code',
  `NOTIFICATION_NAME` varchar(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'Notification name',
  `TITLE` varchar(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'Notification title',
  `MESSAGE` text CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'Notification message',
  `MIME_URL` varchar(1024) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT 'Mime URL',
  `NOTIFICATION_TYPE` varchar(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'Notification type',
  `NOTIFICATION_CATEGORY` varchar(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'Default' COMMENT 'Notification category',
  `URL` text CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci COMMENT 'Notification URL',
  `READ_AT` timestamp NULL DEFAULT NULL COMMENT 'Read at',
  `CREATED_AT` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'Time when this row is created',
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
    "CREATE TABLE `notification_preference` (
  `ID` bigint unsigned NOT NULL AUTO_INCREMENT COMMENT 'Primary key, unique identifier for each notification preference entry',
  `USER_ID` bigint unsigned NOT NULL COMMENT 'User ID',
  `APP_CODE` char(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'App Code',
  `PREFERENCE` json DEFAULT NULL COMMENT 'Preference',
  `CREATED_AT` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'Time when this row is created',
  `UPDATED_AT` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Time when this row is updated',
  `CREATED_BY` bigint unsigned NOT NULL COMMENT 'Created by',
  `UPDATED_BY` bigint unsigned NOT NULL COMMENT 'Updated by',
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
];

/// The local MySQL is shared with the Java services (151 connections): wait while more than
/// 120 are open.
pub async fn wait_for_headroom(p: &MySqlPool) {
    for _ in 0..60 {
        let open: (String, String) = sqlx::query_as("SHOW GLOBAL STATUS LIKE 'Threads_connected'").fetch_one(p).await.unwrap();
        let n: i64 = open.1.parse().unwrap_or(0);
        if n <= 120 {
            return;
        }
        eprintln!("local MySQL: {n} connections open (over 120), waiting");
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    panic!("the local MySQL stayed above 120 connections for five minutes");
}

/// A `RUSTTEST_notif_*` schema with notification's tables, for the life of `f`; dropped after,
/// also when `f` panics.
pub async fn with_scratch<F, Fut>(f: F)
where
    F: FnOnce(MySqlPool, String) -> Fut,
    Fut: Future<Output = ()>,
{
    let admin = MySqlPoolOptions::new().max_connections(1).connect_with(options(None)).await.unwrap();
    wait_for_headroom(&admin).await;
    let name = format!("RUSTTEST_notif_{}", &uuid::Uuid::new_v4().simple().to_string()[..10]);
    assert!(name.starts_with("RUSTTEST_"));
    sqlx::raw_sql(&format!("CREATE DATABASE `{name}` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"))
        .execute(&admin)
        .await
        .unwrap();
    let pool = MySqlPoolOptions::new().max_connections(2).connect_with(options(Some(&name))).await.unwrap();
    for ddl in DDL {
        sqlx::raw_sql(ddl).execute(&pool).await.unwrap();
    }
    let result = std::panic::AssertUnwindSafe(f(pool.clone(), name.clone())).catch_unwind().await;
    pool.close().await;
    sqlx::raw_sql(&format!("DROP DATABASE IF EXISTS `{name}`")).execute(&admin).await.unwrap();
    admin.close().await;
    if let Err(p) = result {
        std::panic::resume_unwind(p);
    }
}
