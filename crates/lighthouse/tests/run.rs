//! `lighthouse::run` end to end, as the binary starts it: its own config (defaults and
//! `MODLIX__` environment), `/readyz` once the registry is ready, the Lighthouse API, and a SIGTERM
//! shutdown. One test: telemetry and signal handlers are process-wide.

use std::time::Duration;

#[tokio::test(flavor = "multi_thread")]
async fn runs_until_sigterm() {
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    // Set before the service reads its configuration; this binary has no other test.
    std::env::set_var("MODLIX__SERVER__PORT", port.to_string());
    std::env::set_var("MODLIX__SERVER__SHUTDOWN_GRACE_SECONDS", "0");
    std::env::set_var("MODLIX__TELEMETRY__LOG_FORMAT", "pretty");
    // Itself (skipped) and a peer that is not there: ready after the startup wait.
    let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    std::env::set_var("MODLIX__REGISTRY__PEERS", format!("[\"http://localhost:{port}\", \"http://127.0.0.1:{dead}\"]"));
    std::env::set_var("MODLIX__REGISTRY__STARTUP_WAIT_SECONDS", "1");
    // The config server on the synthetic fixture: /readyz waits for its first snapshot too.
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/oci-config");
    std::env::set_var("MODLIX__CONFIG__SOURCE", format!("dir:{}", fixture.display()));
    std::env::set_var("MODLIX__CONFIG__ENV", "dev");
    let task = tokio::spawn(lighthouse::run());
    let base = format!("http://127.0.0.1:{port}");
    let http = reqwest::Client::new();
    let mut seen = Vec::new();
    for _ in 0..200 {
        if let Ok(r) = http.get(format!("{base}/readyz")).send().await {
            seen.push(r.status().as_u16());
            if r.status() == 200 {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(seen.first(), Some(&503), "warming up first: {seen:?}");
    assert_eq!(seen.last(), Some(&200), "then ready: {seen:?}");
    let r = http.post(format!("{base}/eureka/apps/X")).json(&serde_json::json!({"instance": {"hostName": "h", "ipAddr": "1.1.1.1", "app": "X"}})).send().await.unwrap();
    assert_eq!(r.status(), 204);
    let x = http.get(format!("{base}/eureka/apps")).send().await.unwrap().text().await.unwrap();
    assert!(x.contains("<name>X</name>"));
    let view: serde_json::Value = http.get(format!("{base}/v1/config")).send().await.unwrap().json().await.unwrap();
    assert_eq!((view["enabled"].as_bool(), view["snapshot"]["from"].as_str()), (Some(true), Some("dir")));
    let m = http.get(format!("{base}/metrics")).send().await.unwrap().text().await.unwrap();
    assert!(m.contains("lighthouse_registrations_total"), "{m}");

    std::process::Command::new("kill").args(["-TERM", &std::process::id().to_string()]).status().unwrap();
    tokio::time::timeout(Duration::from_secs(20), task).await.expect("stopped in time").unwrap().unwrap();
}
