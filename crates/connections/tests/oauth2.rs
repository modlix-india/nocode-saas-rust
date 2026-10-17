//! OAuth2 connections end to end against local token and API endpoints: which token a call
//! uses, when it refreshes, what it stores, and the consent callback and revoke.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{Duration, NaiveDateTime};
use connections::connection::{Connection, ConnectionStore};
use connections::context::Caller;
use connections::error::ConnResult;
use connections::rest::auth::{AuthTokenFunction, EventResult};
use connections::rest::oauth2::{self, CallbackOutcome};
use connections::rest::{RestData, RestRequest};
use connections::tokens::{CoreToken, JavaClock, TokenStore, TokenType};
use connections::{Connections, ConnectionsConfig};
use parking_lot::Mutex;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// `core_tokens` in memory, with the DAO's filters.
#[derive(Default)]
struct MemTokens {
    rows: Mutex<Vec<CoreToken>>,
    clock: JavaClock,
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
        let keep_revoked = row.is_revoked;
        let keep_lifetime = row.is_lifetime_token;
        *row = t.clone();
        row.is_revoked = t.is_revoked.or(keep_revoked);
        row.is_lifetime_token = t.is_lifetime_token.or(keep_lifetime);
        Ok(Some(row.clone()))
    }
}

struct OneConnection(Connection);
#[async_trait]
impl ConnectionStore for OneConnection {
    async fn read_internal(&self, name: &str, _: &str, _: &str, _: &str) -> ConnResult<Option<Connection>> {
        Ok((self.0.name() == name).then(|| self.0.clone()))
    }
}

struct NoFunctions;
#[async_trait]
impl AuthTokenFunction for NoFunctions {
    async fn execute(&self, _: Option<&str>, _: &str, _: Option<&str>, _: Option<&str>) -> ConnResult<Option<Vec<EventResult>>> {
        Ok(None)
    }
}

/// Answers `/token*` with a token JSON and everything else with the request it got.
async fn server(log: Arc<Mutex<Vec<(String, String, Vec<(String, String)>)>>>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else { return };
            let log = log.clone();
            tokio::spawn(async move {
                let mut data = Vec::new();
                let mut buf = [0u8; 8192];
                while !data.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    data.extend_from_slice(&buf[..n]);
                }
                let head = String::from_utf8_lossy(&data).to_string();
                let mut lines = head.split("\r\n");
                let first: Vec<&str> = lines.next().unwrap().split(' ').collect();
                let headers: Vec<(String, String)> = lines
                    .take_while(|l| !l.is_empty())
                    .filter_map(|l| l.split_once(':').map(|(k, v)| (k.to_string(), v.trim().to_string())))
                    .collect();
                let (method, target) = (first[0].to_string(), first[1].to_string());
                log.lock().push((method.clone(), target.clone(), headers.clone()));
                let body = if target.starts_with("/token") {
                    json!({"access_token": "new-access", "expires_in": 3600, "refresh_token": "new-refresh", "refresh_expires_in": 86400})
                        .to_string()
                } else {
                    json!({"method": method, "target": target}).to_string()
                };
                let out = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(out.as_bytes()).await;
            });
        }
    });
    port
}

fn connection(port: u16, grant: &str) -> Connection {
    Connection::from_json(json!({
        "name": "META_API", "appCode": "marketingai", "clientCode": "SYSTEM",
        "connectionType": "REST_API", "connectionSubType": "REST_API_OAUTH2", "isAppLevel": true,
        "connectionDetails": {
            "baseUrl": format!("http://127.0.0.1:{port}/api"),
            "grantType": grant,
            "authHeaderPrefix": "Bearer",
            "headers": {"developer-token": "dev-1"},
            "tokenKey": "access_token", "expireAtKey": "expires_in",
            "refreshTokenKey": "refresh_token", "refreshExpireAtKey": "refresh_expires_in",
            "consentDetails": {"url": "https://www.facebook.com/v21.0/dialog/oauth", "queryParams": {"client_id": "123", "scope": "ads_read,pages_show_list"}},
            "tokenDetails": {"url": format!("http://127.0.0.1:{port}/token"), "queryParams": {"client_id": "123", "client_secret": "s3"}},
            "updateToken": {"url": format!("http://127.0.0.1:{port}/token/refresh"), "methodType": "POST", "queryParams": {"grant_type": "refresh_token"}},
            "pagePath": "/settings/integrations"
        }
    }))
    .unwrap()
}

fn caller() -> Caller {
    Caller {
        present: true,
        authenticated: true,
        user_id: Some(142),
        client_code: Some("SYSTEM".into()),
        url_client_code: Some("SYSTEM".into()),
        url_app_code: Some("leadzumptwo".into()),
        in_kirun: true,
        ..Default::default()
    }
}

fn setup(conn: Connection) -> (Connections, Arc<MemTokens>) {
    let tokens = Arc::new(MemTokens::default());
    let svc = Connections::new(
        ConnectionsConfig { block_private_targets: false, ..Default::default() },
        Arc::new(OneConnection(conn)),
        tokens.clone(),
        platform::cache::CacheService::new("cmn", "evictionChannel", None).unwrap(),
        Arc::new(NoFunctions),
    );
    (svc, tokens)
}

fn token(ty: TokenType, value: &str, expires_in_secs: Option<i64>, clock: JavaClock) -> CoreToken {
    CoreToken {
        client_code: Some("SYSTEM".into()),
        app_code: Some("marketingai".into()),
        connection_name: Some("META_API".into()),
        token_type: Some(ty),
        token: Some(value.into()),
        expires_at: expires_in_secs.map(|s| clock.now() + Duration::seconds(s)),
        state: Some("st-1".into()),
        user_id: Some(142),
        ..Default::default()
    }
}

fn header<'a>(h: &'a [(String, String)], name: &str) -> Vec<&'a str> {
    h.iter().filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str()).collect()
}

#[tokio::test]
async fn valid_access_token_is_used_as_is_under_the_connections_app() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let port = server(log.clone()).await;
    let (svc, tokens) = setup(connection(port, "AUTHORIZATION_CODE"));
    tokens.create(&token(TokenType::Access, "live-token", Some(600), tokens.clock)).await.unwrap();

    let conn = connection(port, "AUTHORIZATION_CODE");
    let r = oauth2::call(&svc, &caller(), &conn, RestRequest { url: "/me".into(), ..Default::default() }, false)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(r.status, 200);
    let calls = log.lock().clone();
    assert_eq!(calls.len(), 1, "no token endpoint call");
    assert_eq!(calls[0].1, "/api/me");
    assert_eq!(header(&calls[0].2, "authorization"), vec!["Bearer live-token"]);
    assert_eq!(header(&calls[0].2, "developer-token"), vec!["dev-1"]);
}

#[tokio::test]
async fn authorization_code_refreshes_with_the_refresh_token() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let port = server(log.clone()).await;
    let (svc, tokens) = setup(connection(port, "AUTHORIZATION_CODE"));
    tokens.create(&token(TokenType::Access, "old", Some(-10), tokens.clock)).await.unwrap();
    tokens.create(&token(TokenType::Refresh, "the-refresh", None, tokens.clock)).await.unwrap();
    tokens.rows.lock()[1].is_lifetime_token = Some(true);

    let conn = connection(port, "AUTHORIZATION_CODE");
    let r = oauth2::call(&svc, &caller(), &conn, RestRequest { url: "me".into(), ..Default::default() }, false)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(r.data, RestData::Json(json!({"method": "GET", "target": "/api/me"})));

    let calls = log.lock().clone();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].0, "POST");
    assert_eq!(calls[0].1, "/token/refresh?refresh_token=the-refresh&grant_type=refresh_token");
    assert_eq!(header(&calls[1].2, "authorization"), vec!["Bearer new-access"]);

    let rows = tokens.rows.lock().clone();
    assert_eq!(rows[0].is_revoked, Some(true), "old access token revoked");
    let new_access = rows.iter().find(|t| t.token.as_deref() == Some("new-access")).unwrap();
    assert_eq!(new_access.token_type, Some(TokenType::Access));
    assert_eq!(new_access.state.as_deref(), Some("st-1"), "carried over from the refresh row");
    let expires = new_access.expires_at.unwrap();
    let expected = tokens.clock.now() + Duration::seconds(3600);
    assert!((expires - expected).num_seconds().abs() <= 2);
    assert_eq!(new_access.token_metadata.as_ref().unwrap()["refresh_token"], json!("new-refresh"));
}

#[tokio::test]
async fn without_a_refresh_token_access_is_denied() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let port = server(log.clone()).await;
    let (svc, _tokens) = setup(connection(port, "AUTHORIZATION_CODE"));
    let conn = connection(port, "AUTHORIZATION_CODE");
    let e = oauth2::call(&svc, &caller(), &conn, RestRequest { url: "/me".into(), ..Default::default() }, false)
        .await
        .unwrap_err();
    assert_eq!(e.message(), "Access denied: Integration token unavailable or expired");
    assert_eq!(e.status(), http::StatusCode::BAD_REQUEST);
    assert!(log.lock().is_empty());
}

#[tokio::test]
async fn client_credentials_fetches_a_new_token_when_expired() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let port = server(log.clone()).await;
    let (svc, tokens) = setup(connection(port, "CLIENT_CREDENTIALS"));
    let conn = connection(port, "CLIENT_CREDENTIALS");
    let t = oauth2::access_token(&svc, &caller(), Some("marketingai"), Some("SYSTEM"), &conn).await.unwrap();
    assert_eq!(t.as_deref(), Some("new-access"));
    let calls = log.lock().clone();
    assert_eq!(calls[0].0, "POST");
    assert_eq!(calls[0].1, "/token?client_id=123&client_secret=s3");
    let row = tokens.rows.lock()[0].clone();
    assert_eq!((row.client_code.as_deref(), row.app_code.as_deref(), row.user_id), (Some("SYSTEM"), Some("marketingai"), Some(142)));

    // Now valid: served from the cache, no second fetch.
    let t = oauth2::access_token(&svc, &caller(), Some("marketingai"), Some("SYSTEM"), &conn).await.unwrap();
    assert_eq!(t.as_deref(), Some("new-access"));
    assert_eq!(log.lock().len(), 1);
}

#[tokio::test]
async fn consent_callback_and_revoke() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let port = server(log.clone()).await;
    let (svc, tokens) = setup(connection(port, "AUTHORIZATION_CODE"));
    let mut c = caller();
    c.url_app_code = Some("marketingai".into());

    let url = oauth2::evoke_consent(&svc, &c, "META_API", Some("app.example.com")).await.unwrap().unwrap();
    let state = tokens.rows.lock()[0].state.clone().unwrap();
    assert_eq!(
        url,
        format!(
            "https://www.facebook.com/v21.0/dialog/oauth?client_id=123&scope=ads_read,pages_show_list&redirect_uri=https://app.example.com/api/core/connections/oauth/callback&state={state}"
        )
    );

    let out = oauth2::oauth2_callback(&svc, &c, Some("the-code"), Some(&state), Some("app.example.com"), "/api/core/connections/oauth/callback")
        .await
        .unwrap();
    assert_eq!(out, CallbackOutcome::Redirect("https://app.example.com/settings/integrations?META_API=success".into()));
    let calls = log.lock().clone();
    assert_eq!(calls[0].0, "GET", "token exchange defaults to GET");
    assert_eq!(
        calls[0].1,
        "/token?code=the-code&redirect_uri=https://app.example.com/api/core/connections/oauth/callback&client_id=123&client_secret=s3"
    );
    let rows = tokens.rows.lock().clone();
    assert_eq!(rows[0].token.as_deref(), Some("new-access"));
    assert_eq!(rows[0].is_revoked, Some(false), "the state row is written back unrevoked, as Java does");
    assert_eq!(rows[1].token_type, Some(TokenType::Refresh));
    assert_eq!(rows[1].is_lifetime_token, Some(false));

    // A callback without a code goes back to the page as invalid.
    let out = oauth2::oauth2_callback(&svc, &c, None, Some(&state), Some("app.example.com"), "/x").await.unwrap();
    assert_eq!(out, CallbackOutcome::Redirect("https://app.example.com/settings/integrations?META_API=invalid".into()));

    assert!(oauth2::revoke_connection_token(&svc, &c, "META_API").await.unwrap());
    let e = oauth2::revoke_connection_token(&svc, &c, "META_API").await.unwrap_err();
    assert_eq!(e.message(), "No active token found to revoke for connection META_API");
    let _ = Value::Null;
}
