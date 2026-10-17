//! `gateway::run` end to end: configuration file, probes, a proxied request.

use std::time::Duration;

#[tokio::test]
async fn runs_from_a_config_file() {
    let backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_base = format!("http://{}", backend.local_addr().unwrap());
    let app = axum::Router::new()
        .route(
            "/api/security/clients/internal/getClientNAppCodeNType",
            axum::routing::get(|| async { axum::Json(serde_json::json!(["SYSTEM", "app", "LIVE"])) }),
        )
        .route("/api/x", axum::routing::get(|| async { "proxied" }))
        .route("/readyz", axum::routing::get(|| async { "ok" }));
    tokio::spawn(async move { axum::serve(backend, app).await.unwrap() });

    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let dir = std::env::temp_dir().join(format!("gw-startup-{port}"));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("gateway-rust.toml");
    std::fs::write(
        &file,
        format!(
            "[server]\nport = {port}\n[telemetry]\nlog_level = \"warn\"\n[security]\nupstream = \"{backend_base}\"\n\
             [pools.b]\nupstreams = [\"{backend_base}\"]\n[[routes]]\nid = \"all\"\nprefix = \"/\"\npool = \"b\"\n"
        ),
    )
    .unwrap();
    std::env::set_var("CONFIG_FILE", &file);

    let task = tokio::spawn(gateway::run());
    let mut up = false;
    for _ in 0..100 {
        if reqwest::get(format!("http://127.0.0.1:{port}/healthz")).await.is_ok() {
            up = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(up);
    let body = reqwest::get(format!("http://127.0.0.1:{port}/api/x")).await.unwrap().text().await.unwrap();
    assert_eq!(body, "proxied");
    let metrics = reqwest::get(format!("http://127.0.0.1:{port}/metrics")).await.unwrap().text().await.unwrap();
    assert!(metrics.contains("http_server_request_duration_seconds"));
    task.abort();
}
