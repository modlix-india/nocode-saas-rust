//! The OAuth2 service's refusals and empty answers, each as Java answers it.

mod common;

use std::sync::Arc;

use chrono::Duration;
use common::{caller, server, service, Canned, Functions, MemTokens};
use connections::connection::Connection;
use connections::rest::oauth2::{self, CallbackOutcome};
use connections::rest::RestRequest;
use connections::tokens::{CoreToken, TokenStore, TokenType};
use connections::{Connections, ConnectionsConfig};
use serde_json::{json, Value};

fn oauth(port: u16, grant: &str, extra: Value) -> Connection {
    let mut d = json!({
        "baseUrl": format!("http://127.0.0.1:{port}/api"),
        "grantType": grant,
        "tokenKey": "access_token", "expireAtKey": "expires_in", "refreshTokenKey": "refresh_token",
        "consentDetails": {"url": "https://auth.example.com/authorize", "queryParams": {"client_id": "1", "skip": null}},
        "tokenDetails": {"url": format!("http://127.0.0.1:{port}/token"), "queryParams": {"client_id": "1"}},
        "updateToken": {"url": format!("http://127.0.0.1:{port}/token"), "methodType": "GET"},
        "pagePath": "/page"
    });
    for (k, v) in extra.as_object().unwrap() {
        if v.is_null() {
            d.as_object_mut().unwrap().remove(k);
        } else {
            d[k] = v.clone();
        }
    }
    Connection::from_json(json!({"name": "oa", "appCode": "app", "clientCode": "SYSTEM", "isAppLevel": true,
        "connectionType": "REST_API", "connectionSubType": "REST_API_OAUTH2", "connectionDetails": d}))
    .unwrap()
}

fn token(tokens: &MemTokens, ty: TokenType, value: &str, secs: Option<i64>) -> CoreToken {
    CoreToken {
        client_code: Some("SYSTEM".into()),
        app_code: Some("app".into()),
        connection_name: Some("oa".into()),
        token_type: Some(ty),
        token: Some(value.into()),
        expires_at: secs.map(|s| tokens.clock.now() + Duration::seconds(s)),
        is_lifetime_token: Some(secs.is_none()),
        state: Some("st".into()),
        ..Default::default()
    }
}

#[tokio::test]
async fn call_headers_and_refusals() {
    let (port, log) = server(vec![Canned::json(200, "{}")]).await;
    let tokens = Arc::new(MemTokens::default());
    tokens.create(&token(&tokens, TokenType::Access, "live", Some(600))).await.unwrap();
    let svc = service(vec![], tokens.clone(), Functions::answering(None));
    let c = caller();
    // No prefix: the token alone. A null extra header is skipped.
    let conn = oauth(port, "AUTHORIZATION_CODE", json!({"headers": {"x-null": null, "x-ok": "1"}}));
    oauth2::call(&svc, &c, &conn, RestRequest { url: "/me".into(), ..Default::default() }, false).await.unwrap();
    let seen = log.lock()[0].to_lowercase();
    assert!(seen.contains("authorization: live") && seen.contains("x-ok: 1") && !seen.contains("x-null"));
    // A non-string extra header fails the cast, as in Java.
    let bad = oauth(port, "AUTHORIZATION_CODE", json!({"headers": {"x-n": 5}}));
    assert!(oauth2::call(&svc, &c, &bad, RestRequest::default(), false).await.unwrap_err().message().contains("cannot be cast"));
    // No security context.
    assert!(oauth2::call(&svc, &Default::default(), &conn, RestRequest::default(), false).await.is_err());
    // No client code: nothing is looked up, and the authorization-code grant has nothing to refresh.
    let mut no_client = caller();
    no_client.client_code = None;
    assert_eq!(
        oauth2::call(&svc, &no_client, &conn, RestRequest::default(), false).await.unwrap_err().message(),
        "Access denied: Integration token unavailable or expired"
    );
}

#[tokio::test]
async fn expired_cached_tokens() {
    let (port, log) = server(vec![Canned::json(200, r#"{"access_token":"fresh","expires_in":60,"refresh_token":"r2"}"#)]).await;
    let tokens = Arc::new(MemTokens::default());
    let svc = service(vec![], tokens.clone(), Functions::answering(None));
    let c = caller();
    // A cached token that expired since: the client-credentials grant fetches a new one.
    let cc = oauth(port, "CLIENT_CREDENTIALS", json!({}));
    tokens.create(&token(&tokens, TokenType::Access, "soon", Some(1))).await.unwrap();
    assert_eq!(oauth2::access_token(&svc, &c, Some("app"), Some("SYSTEM"), &cc).await.unwrap().as_deref(), Some("soon"));
    tokens.rows.lock()[0].expires_at = Some(tokens.clock.now() - Duration::seconds(5));
    // The cache still holds the old row with its old expiry; move it into the past there too.
    let svc2 = service(vec![], tokens.clone(), Functions::answering(None));
    tokens.rows.lock()[0].expires_at = Some(tokens.clock.now() + Duration::seconds(1));
    oauth2::access_token(&svc2, &c, Some("app"), Some("SYSTEM"), &cc).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
    assert_eq!(oauth2::access_token(&svc2, &c, Some("app"), Some("SYSTEM"), &cc).await.unwrap().as_deref(), Some("fresh"));
    // The same for the authorization-code grant: a refresh (the update endpoint, by GET).
    let ac = oauth(port, "AUTHORIZATION_CODE", json!({}));
    let tokens3 = Arc::new(MemTokens::default());
    tokens3.create(&token(&tokens3, TokenType::Access, "soon", Some(1))).await.unwrap();
    tokens3.create(&token(&tokens3, TokenType::Refresh, "r1", None)).await.unwrap();
    let svc3 = service(vec![], tokens3.clone(), Functions::answering(None));
    oauth2::access_token(&svc3, &c, Some("app"), Some("SYSTEM"), &ac).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
    assert_eq!(oauth2::access_token(&svc3, &c, Some("app"), Some("SYSTEM"), &ac).await.unwrap().as_deref(), Some("fresh"));
    assert!(log.lock().iter().any(|r| r.starts_with("GET /token?refresh_token=r1 HTTP/1.1")));
}

#[tokio::test]
async fn token_endpoint_answers_that_fail() {
    let (port, _) = server(vec![Canned::json(200, r#"{"other":1}"#)]).await;
    let svc = service(vec![], Arc::new(MemTokens::default()), Functions::answering(None));
    let c = caller();
    let cc = oauth(port, "CLIENT_CREDENTIALS", json!({}));
    assert!(oauth2::create_client_credentials_token(&svc, &c, &cc).await.unwrap_err().message().contains("asText"));
    let no_params = oauth(port, "CLIENT_CREDENTIALS", json!({"tokenDetails": {"url": "http://127.0.0.1:1/t"}}));
    assert!(oauth2::create_client_credentials_token(&svc, &c, &no_params).await.unwrap_err().message().contains("forEach"));
    assert_eq!(oauth2::create_client_credentials_token(&svc, &Default::default(), &cc).await.unwrap(), None);
    let no_details = oauth(port, "CLIENT_CREDENTIALS", json!({"tokenDetails": null}));
    assert!(oauth2::create_client_credentials_token(&svc, &c, &no_details).await.is_err());

    let (port, _) = server(vec![Canned::json(200, r#"{"access_token":null,"expires_in":{}}"#)]).await;
    let odd = oauth(port, "CLIENT_CREDENTIALS", json!({}));
    assert!(oauth2::create_client_credentials_token(&svc, &c, &odd).await.unwrap_err().message().contains("For input string: \"\""));
    let (port, _) = server(vec![Canned::json(200, r#"{"access_token":[1],"expires_in":"x"}"#)]).await;
    let odd = oauth(port, "CLIENT_CREDENTIALS", json!({}));
    assert!(oauth2::create_client_credentials_token(&svc, &c, &odd).await.is_err());

    // A token endpoint on a private address is refused when private targets are blocked.
    let guarded = Connections::new(
        ConnectionsConfig { block_private_targets: true, ..Default::default() },
        Arc::new(common::Store(vec![])),
        Arc::new(MemTokens::default()),
        platform::cache::CacheService::new("cmn", "evictionChannel", None).unwrap(),
        Functions::answering(None),
    );
    assert!(oauth2::create_client_credentials_token(&guarded, &c, &cc).await.unwrap_err().message().starts_with("Refusing to call"));

    // Refresh: no update block, an empty answer, an answer without the token.
    let tokens = Arc::new(MemTokens::default());
    tokens.create(&token(&tokens, TokenType::Refresh, "r", None)).await.unwrap();
    let svc = service(vec![], tokens.clone(), Functions::answering(None));
    let no_update = oauth(port, "AUTHORIZATION_CODE", json!({"updateToken": null}));
    assert!(oauth2::refresh_access_token(&svc, &no_update, Some("SYSTEM"), Some("app")).await.is_err());
    let (eport, _) = server(vec![Canned::json(200, "")]).await;
    let empty = oauth(eport, "AUTHORIZATION_CODE", json!({}));
    assert_eq!(
        oauth2::refresh_access_token(&svc, &empty, Some("SYSTEM"), Some("app")).await.unwrap_err().message(),
        "Access denied: Integration token unavailable or expired"
    );
    let (wport, _) = server(vec![Canned::json(200, r#"{"x":1}"#)]).await;
    let wrong = oauth(wport, "AUTHORIZATION_CODE", json!({}));
    assert!(oauth2::refresh_access_token(&svc, &wrong, Some("SYSTEM"), Some("app")).await.unwrap_err().message().contains("toString"));
    assert!(oauth2::refresh_access_token(&svc, &wrong, None, Some("app")).await.is_err());
}

#[tokio::test]
async fn consent_and_callback_edges() {
    let (port, _) = server(vec![Canned::json(200, "")]).await;
    let tokens = Arc::new(MemTokens::default());
    let c = caller();
    let mut c2 = caller();
    c2.url_app_code = Some("app".into());
    let svc = service(
        vec![
            oauth(port, "CLIENT_CREDENTIALS", json!({})),
            Connection::from_json(json!({"name": "nourl", "clientCode": "SYSTEM", "connectionType": "REST_API",
                "connectionDetails": {"grantType": "AUTHORIZATION_CODE"}})).unwrap(),
        ],
        tokens.clone(),
        Functions::answering(None),
    );
    assert_eq!(
        oauth2::evoke_consent(&svc, &c2, "oa", Some("h")).await.unwrap_err().message(),
        "Invalid Connection Grant Type."
    );
    assert_eq!(oauth2::evoke_consent(&svc, &c2, "nourl", Some("h")).await.unwrap_err().message(), "Authorization URL is required");
    assert_eq!(oauth2::evoke_consent(&svc, &Default::default(), "oa", None).await.unwrap(), None);
    let mut no_url = caller();
    no_url.url_app_code = None;
    assert_eq!(oauth2::evoke_consent(&svc, &no_url, "oa", None).await.unwrap(), None);

    // Callback: a state row without its codes, a connection that is gone, an empty token answer.
    tokens.create(&CoreToken { state: Some("bare".into()), ..Default::default() }).await.unwrap();
    tokens
        .create(&CoreToken {
            state: Some("gone".into()),
            client_code: Some("SYSTEM".into()),
            app_code: Some("app".into()),
            connection_name: Some("missing".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    tokens
        .create(&CoreToken {
            state: Some("ok".into()),
            client_code: Some("SYSTEM".into()),
            app_code: Some("app".into()),
            connection_name: Some("oa".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    let path = "/api/core/connections/oauth/callback";
    assert_eq!(oauth2::oauth2_callback(&svc, &c, Some("x"), Some("bare"), Some("h"), path).await.unwrap(), CallbackOutcome::Empty);
    assert_eq!(oauth2::oauth2_callback(&svc, &c, Some("x"), Some("gone"), Some("h"), path).await.unwrap(), CallbackOutcome::Empty);
    assert_eq!(oauth2::oauth2_callback(&svc, &c, Some("x"), Some("ok"), Some("h"), path).await.unwrap(), CallbackOutcome::Empty);
    assert_eq!(oauth2::oauth2_callback(&svc, &c, None, Some("bare"), Some("h"), path).await.unwrap(), CallbackOutcome::FoundWithoutLocation);
    assert_eq!(oauth2::oauth2_callback(&svc, &c, None, Some("gone"), Some("h"), path).await.unwrap(), CallbackOutcome::FoundWithoutLocation);
    assert_eq!(
        oauth2::oauth2_callback(&svc, &c, None, Some("ok"), None, path).await.unwrap(),
        CallbackOutcome::Redirect("https://null/page?oa=invalid".into())
    );
    let no_token_details = service(vec![oauth(port, "AUTHORIZATION_CODE", json!({"tokenDetails": null}))], tokens.clone(), Functions::answering(None));
    assert!(oauth2::oauth2_callback(&no_token_details, &c, Some("x"), Some("ok"), Some("h"), path).await.is_err());

    // Revoke without a caller or codes.
    assert!(oauth2::revoke_connection_token(&svc, &Default::default(), "oa").await.is_err());
    let mut nocodes = caller();
    nocodes.client_code = None;
    assert!(oauth2::revoke_connection_token(&svc, &nocodes, "oa").await.is_err());
}

#[tokio::test]
async fn callback_with_a_lifetime_token_and_no_refresh() {
    let (port, _) = server(vec![Canned::json(200, r#"{"access_token":"t","expires_in":60}"#)]).await;
    let tokens = Arc::new(MemTokens::default());
    tokens
        .create(&CoreToken {
            state: Some("s".into()),
            client_code: Some("SYSTEM".into()),
            app_code: Some("app".into()),
            connection_name: Some("oa".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    let conn = oauth(port, "AUTHORIZATION_CODE", json!({"isLifeTimeToken": true, "tokenDetails": {"url": format!("http://127.0.0.1:{port}/token"), "methodType": "POST"}}));
    let svc = service(vec![conn], tokens.clone(), Functions::answering(None));
    let out = oauth2::oauth2_callback(&svc, &caller(), Some("c"), Some("s"), Some("app.example.com"), "/cb").await.unwrap();
    assert_eq!(out, CallbackOutcome::Redirect("https://app.example.com/page?oa=success".into()));
    let rows = tokens.rows.lock().clone();
    assert_eq!(rows.len(), 1, "no refresh token in the answer, no refresh row");
    assert_eq!((rows[0].expires_at, rows[0].is_lifetime_token), (None, Some(true)));
}
