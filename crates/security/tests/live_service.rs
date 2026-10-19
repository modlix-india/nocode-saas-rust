//! The binary's start-up path (`security::run`) on the local stack: configuration, pool,
//! Redis eviction listener, router, then a sign-in, a context, a revoke over HTTP.
//!
//! Gated: `SECURITY_AUTH_LIVE=1` with `eval "$(tools/local-env.py)"` (database password, Redis URL,
//! `MODLIX__JWT__KEY`). Signs in as the SYSTEM user 142 with the local password and revokes the
//! token it got.

use std::time::Duration;

#[tokio::test]
async fn run_serves_sign_in_context_and_revoke() {
    let (Ok(_), Ok(_), Ok(_)) =
        (std::env::var("SECURITY_AUTH_LIVE"), std::env::var("MODLIX__DATABASE__PASSWORD"), std::env::var("MODLIX__JWT__KEY"))
    else {
        eprintln!("skipped: SECURITY_AUTH_LIVE / MODLIX__DATABASE__PASSWORD / MODLIX__JWT__KEY not set");
        return;
    };
    let port = 18101;
    std::env::set_var("CONFIG_FILE", concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/security-auth.toml"));
    std::env::set_var("MODLIX__SERVER__PORT", port.to_string());
    std::env::set_var("MODLIX__SERVER__SHUTDOWN_GRACE_SECONDS", "0");
    let server = tokio::spawn(security::run());
    let base = format!("http://127.0.0.1:{port}");
    let http = reqwest::Client::new();
    let mut ready = false;
    for _ in 0..50 {
        if let Ok(r) = http.get(format!("{base}/readyz")).send().await {
            if r.status().is_success() {
                ready = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(ready, "security-auth did not become ready");

    let headers = [("clientCode", "SYSTEM"), ("appCode", "appbuilder"), ("X-Forwarded-Host", "localhost"), ("X-Forwarded-Port", "8080")];
    let mut rb = http.post(format!("{base}/api/security/authenticate")).json(&serde_json::json!({"userId": 142, "password": "Pass@1234"}));
    for (k, v) in headers {
        rb = rb.header(k, v);
    }
    let v: serde_json::Value = rb.send().await.unwrap().json().await.unwrap();
    let token = v["accessToken"].as_str().expect("signed in").to_string();

    let mut rb = http.get(format!("{base}/api/security/internal/securityContextAuthentication")).bearer_auth(&token);
    for (k, v) in headers {
        rb = rb.header(k, v);
    }
    let ca: serde_json::Value = rb.send().await.unwrap().json().await.unwrap();
    assert_eq!((ca["authenticated"].as_bool(), ca["user"]["id"].as_u64()), (Some(true), Some(142)));

    let mut rb = http.get(format!("{base}/api/security/revoke")).bearer_auth(&token);
    for (k, v) in headers {
        rb = rb.header(k, v);
    }
    assert_eq!(rb.send().await.unwrap().status(), 200);
    server.abort();
}
