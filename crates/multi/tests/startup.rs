//! The binary's startup path: configuration from the environment, the runner, the probes.

use std::time::Duration;

#[tokio::test]
async fn starts_and_answers_probes() {
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    std::env::set_var("CONFIG_FILE", "/nonexistent/multi.toml");
    std::env::set_var("MODLIX__SERVER__PORT", port.to_string());
    std::env::set_var("MODLIX__SECURITY__UPSTREAM", "http://127.0.0.1:1");
    std::env::set_var("MODLIX__CORE__UPSTREAM", "http://127.0.0.1:1");
    std::env::set_var("MODLIX__UI__UPSTREAM", "http://127.0.0.1:1");
    std::env::set_var("MODLIX__TELEMETRY__LOG_LEVEL", "warn");

    let task = tokio::spawn(multi::run());
    let url = format!("http://127.0.0.1:{port}/healthz");
    let mut ok = false;
    for _ in 0..100 {
        if let Ok(r) = reqwest::get(&url).await {
            ok = r.status().is_success();
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ok, "multi did not come up");
    let ready = reqwest::get(format!("http://127.0.0.1:{port}/readyz")).await.unwrap();
    assert!(ready.status().is_success());
    // Errors are coded from the first request: security is not there, so a 503 that says so.
    let r = reqwest::get(format!("http://127.0.0.1:{port}/api/multi/application/x/index")).await.unwrap();
    assert_eq!(r.status().as_u16(), 503);
    let v: serde_json::Value = r.json().await.unwrap();
    assert_eq!(v["code"], "MULTI.SERVICE_UNAVAILABLE");
    assert_eq!(v["message"], "The security service is not answering right now. Try again in a few seconds.");
    let defaults = multi::config::MultiConfig::default();
    assert_eq!(defaults.server.port, 8110);
    task.abort();
}
