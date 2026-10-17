//! ui-shell starts with its configuration: `ui::shell::run()` on a free port, against a
//! scratch database and the fake security service, answering its routes with the Java ui's
//! filter chain around them.
//!
//! Gated: `#[ignore]` and `MODLIX__MONGO__URI`. Its own test binary, because it sets process
//! environment variables and installs the process-wide metrics recorder.

mod common;

use std::time::Duration;

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn shell_starts() {
    let Some(uri) = common::mongo_uri() else { return };
    let fake = std::sync::Arc::new(common::FakeSecurity::default());
    let security = common::fake_security(fake).await;
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let db = format!("rusttest_ui_shell_run_{}", std::process::id());
    let dir = std::env::temp_dir().join(format!("ui-shell-run-it-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("ui-shell.toml");
    std::fs::write(
        &file,
        format!(
            "[server]\nport = {port}\nshutdown_grace_seconds = 0\n[telemetry]\nlog_format = \"pretty\"\nlog_level = \"warn\"\n\
             [security]\nupstream = \"{security}\"\n[core]\nupstream = \"{security}\"\n[mongo]\ndatabase = \"{db}\"\n\
             [ui]\njava_zone_offset = \"+05:30\"\n[shell]\ncdn_host_name = \"\"\n"
        ),
    )
    .unwrap();
    std::env::set_var("CONFIG_FILE", &file);
    std::env::set_var("MODLIX__MONGO__URI", &uri);
    std::env::set_var("MODLIX__REDIS__URL", "");
    let server = tokio::spawn(ui::shell::run());

    let http = reqwest::Client::new();
    let base = format!("http://127.0.0.1:{port}");
    let mut ready = None;
    for _ in 0..100 {
        if let Ok(r) = http.get(format!("{base}/readyz")).send().await {
            ready = Some((r.status(), r.text().await.unwrap_or_default()));
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let (status, body) = ready.expect("ui-shell did not start");
    assert_eq!(status, 200, "{body}");
    let r = http
        .get(format!("{base}/apiDocs"))
        .header("appCode", "testapp")
        .header("clientCode", "SYSTEM")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    // CORS answers inside the router; `ResponseEntityUtils`' own `Vary` then replaces its values,
    // as WebFlux's `putAll` does (Java commit e2b7d48aa).
    assert_eq!(r.headers()["vary"], "Authorization, clientCode, appCode");
    assert_eq!(r.text().await.unwrap(), "Coming soon...");
    let page = http
        .get(format!("{base}/"))
        .header("appCode", "testapp")
        .header("clientCode", "SYSTEM")
        .header("X-Forwarded-Host", "testapp.example")
        .header("X-Forwarded-Port", "443")
        .send()
        .await
        .unwrap();
    let html = page.text().await.unwrap();
    assert!(html.ends_with("<script src=\"/js/dist/vendors.js\"></script><script src=\"/js/dist/index.js\"></script></body></html>"), "{html}");
    let fw = http.get(format!("{base}/a%2Fb")).send().await.unwrap();
    assert_eq!(fw.status(), 400);
    server.abort();

    let mongo = platform::db::mongo_database(&platform::config::MongoConfig { uri, database: db, ..Default::default() })
        .await
        .unwrap();
    mongo.drop().await.unwrap();
    let _ = std::fs::remove_dir_all(dir);
}
