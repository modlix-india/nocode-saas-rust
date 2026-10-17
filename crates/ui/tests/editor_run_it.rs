//! ui-editor starts with its configuration: `ui::editor::run()` on a free port, against a
//! scratch database and the fake security service, answering its routes with the Java ui's
//! filter chain around them.
//!
//! Gated: `#[ignore]` and `MODLIX__MONGO__URI`. Its own test binary, because it sets process
//! environment variables and installs the process-wide metrics recorder.

mod common;

use std::time::Duration;

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn editor_starts() {
    let Some(uri) = common::mongo_uri() else { return };
    let fake = std::sync::Arc::new(common::FakeSecurity::default());
    let security = common::fake_security(fake).await;
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let db = format!("rusttest_ui_editor_run_{}", std::process::id());
    let dir = std::env::temp_dir().join(format!("ui-editor-run-it-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("ui-editor.toml");
    std::fs::write(
        &file,
        format!(
            "[server]\nport = {port}\nshutdown_grace_seconds = 0\n[telemetry]\nlog_format = \"pretty\"\nlog_level = \"warn\"\n\
             [security]\nupstream = \"{security}\"\n[mongo]\ndatabase = \"{db}\"\n\
             [ui]\njava_zone_offset = \"+05:30\"\n[editor]\napp_code_suffix = \".local\"\n"
        ),
    )
    .unwrap();
    std::env::set_var("CONFIG_FILE", &file);
    std::env::set_var("MODLIX__MONGO__URI", &uri);
    std::env::set_var("MODLIX__REDIS__URL", "");
    let server = tokio::spawn(ui::editor::run());

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
    let (status, body) = ready.expect("ui-editor did not start");
    assert_eq!(status, 200, "{body}");

    let get = |path: &str| http.get(format!("{base}{path}")).header("appCode", "testapp").header("clientCode", "SYSTEM");
    let types = get("/api/ui/transports/transportTypes").send().await.unwrap();
    assert_eq!(types.status(), 200);
    assert_eq!(types.headers()["vary"], "Origin", "CORS answers inside the router");
    let t: serde_json::Value = types.json().await.unwrap();
    assert_eq!(t, serde_json::json!(["Application", "Page", "Style", "Theme", "Function", "Schema", "Filler", "URIPath"]));

    let anon = get("/api/ui/applications/testapp/mobileApps").send().await.unwrap();
    assert_eq!(anon.status(), 401);
    assert!(anon.headers().get("www-authenticate").is_none());

    let signed_in = get("/api/ui/applications/testapp/mobileApps")
        .header("authorization", "user SYSTEM Authorities.ROLE_MobileApp_CREATE")
        .send()
        .await
        .unwrap();
    assert_eq!(signed_in.status(), 200, "the caller comes from security");
    assert_eq!(signed_in.json::<serde_json::Value>().await.unwrap(), serde_json::json!([]));

    let missing = get("/api/ui/pages/x/components").send().await.unwrap();
    assert_eq!(missing.status(), 400);
    let fw = http.get(format!("{base}/a%2Fb")).send().await.unwrap();
    assert_eq!(fw.status(), 400);
    server.abort();

    let mongo = platform::db::mongo_database(&platform::config::MongoConfig { uri, database: db, ..Default::default() })
        .await
        .unwrap();
    mongo.drop().await.unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
