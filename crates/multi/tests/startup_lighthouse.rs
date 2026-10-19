//! The startup path with `LIGHTHOUSE_URLS` set: multi's configuration comes from Lighthouse
//! (between its TOML file and its environment) and it registers there once ready, with the
//! version it runs as `configVersion`. A fake Lighthouse stands in for the real one.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post, put};
use axum::Router;
use serde_json::{json, Value};

type Seen = Arc<Mutex<Vec<Value>>>;

#[tokio::test]
async fn configured_and_registered_by_lighthouse() {
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let seen: Seen = Arc::default();
    let doc = json!({
        "server": {"port": port},
        "telemetry": {"log_level": "warn"},
        "security": {"upstream": "http://127.0.0.1:1"},
        "core": {"upstream": "http://127.0.0.1:1"},
        "ui": {"upstream": "http://127.0.0.1:1"},
    });
    let fake = Router::new()
        .route(
            "/v1/units/multi/config",
            get(move || {
                let doc = doc.clone();
                async move {
                    axum::Json(json!({"unit": "multi", "env": "dev", "version": "abcd.ef01", "sha": "s", "live": ["telemetry.log_level"], "config": doc}))
                }
            }),
        )
        .route("/v1/units/multi/version", get(|| async { StatusCode::NOT_MODIFIED }))
        .route(
            "/eureka/apps/{app}",
            post(|State(s): State<Seen>, body: String| async move {
                s.lock().unwrap().push(serde_json::from_str(&body).unwrap());
                StatusCode::NO_CONTENT
            }),
        )
        .route("/eureka/apps/{app}/{id}", put(|| async { StatusCode::OK }).delete(|| async { StatusCode::OK }))
        .route("/eureka/apps/{app}/{id}/status", put(|| async { StatusCode::OK }))
        .with_state(seen.clone());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let lighthouse = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, fake).await.unwrap() });

    std::env::set_var("CONFIG_FILE", "/nonexistent/multi.toml");
    std::env::set_var("LIGHTHOUSE_URLS", &lighthouse);
    std::env::set_var("LIGHTHOUSE_REQUIRED", "true");
    std::env::set_var("MODLIX__EUREKA__REGISTER", "true");
    std::env::set_var("MODLIX__EUREKA__REGISTER_AS", "MULTI");
    std::env::set_var("MODLIX__EUREKA__INSTANCE_IP", "127.0.0.1");

    let task = tokio::spawn(multi::run());
    let mut registered = None;
    for _ in 0..200 {
        if let Some(b) = seen.lock().unwrap().first().cloned() {
            registered = Some(b);
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let body = registered.expect("multi registered in lighthouse");
    let i = &body["instance"];
    assert_eq!(i["app"], "MULTI");
    assert_eq!(i["status"], "UP");
    assert_eq!(i["metadata"]["configVersion"], "abcd.ef01");
    // The port came from Lighthouse's document.
    assert_eq!(i["port"]["$"], port);
    let ready = reqwest::get(format!("http://127.0.0.1:{port}/readyz")).await.unwrap();
    assert!(ready.status().is_success());
    assert_eq!(lighthouse_client::config::running_version().as_deref(), Some("abcd.ef01"));
    task.abort();
}
