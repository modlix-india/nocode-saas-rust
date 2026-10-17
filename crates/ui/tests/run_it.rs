//! The Java ui's `ContextLoadsTest`: the service starts with its configuration and MongoDB is
//! reachable. Runs `ui::run()` itself on a free port, against a scratch database and the fake
//! security service.
//!
//! Gated: `#[ignore]` and `MODLIX__MONGO__URI`. Its own test binary, because it sets
//! process environment variables and installs the process-wide metrics recorder.

mod common;

use std::time::Duration;

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn context_loads() {
    let Some(uri) = common::mongo_uri() else { return };
    let fake = std::sync::Arc::new(common::FakeSecurity::default());
    let security = common::fake_security(fake).await;
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let db = format!("rusttest_ui_run_{}", std::process::id());
    let dir = std::env::temp_dir().join(format!("ui-engine-run-it-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("ui-engine.toml");
    std::fs::write(
        &file,
        format!(
            "[server]\nport = {port}\nshutdown_grace_seconds = 0\n[telemetry]\nlog_format = \"pretty\"\nlog_level = \"warn\"\n\
             [security]\nupstream = \"{security}\"\n[mongo]\ndatabase = \"{db}\"\n[ui]\njava_zone_offset = \"+05:30\"\n"
        ),
    )
    .unwrap();
    std::env::set_var("CONFIG_FILE", &file);
    std::env::set_var("MODLIX__MONGO__URI", &uri);
    std::env::set_var("MODLIX__REDIS__URL", "");
    let server = tokio::spawn(ui::run());

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
    let (status, body) = ready.expect("ui-engine did not start");
    assert_eq!(status, 200, "{body}");
    assert_eq!(body, r#"{"status":"ok","checks":{"mongo":"ok"}}"#);
    let r = http
        .get(format!("{base}/api/ui/urlDetails"))
        .header("appCode", "testapp")
        .header("clientCode", "SYSTEM")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["vary"], "Origin", "the Spring CORS layer is on");
    server.abort();

    let mongo = platform::db::mongo_database(&platform::config::MongoConfig { uri, database: db, ..Default::default() })
        .await
        .unwrap();
    mongo.drop().await.unwrap();
    let _ = std::fs::remove_dir_all(dir);
    // The zone offset in the file reached the document decoder.
    assert_eq!(overridable::pojo::java_zone_offset_seconds(), 19_800);
}
