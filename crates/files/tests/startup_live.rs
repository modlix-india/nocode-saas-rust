//! `files::run` as the binaries call it: configuration from the environment, a real MySQL (a
//! scratch database), the bucket and security as in-process fakes, then the probes and a route.
//! Its own test binary: the runner installs process-wide telemetry once.
//!
//! Gated like `live_mysql`: `FILES_TEST_MYSQL=1` and `MODLIX__DATABASE__PASSWORD`.

mod common;

use std::time::Duration;

use common::*;
use files::Unit;

#[tokio::test]
#[ignore = "needs the local MySQL (FILES_TEST_MYSQL=1, MODLIX__DATABASE__PASSWORD)"]
async fn files_manage_starts_and_serves() {
    with_scratch(|pool| async move {
        let name: String = sqlx::query_scalar("SELECT DATABASE()").fetch_one(&pool).await.unwrap();
        let fakes = Harness::new(Unit::Manage).await;
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        for (k, v) in [
            ("CONFIG_FILE", "/nonexistent/files-manage.toml".to_string()),
            ("MODLIX__SERVER__PORT", port.to_string()),
            ("MODLIX__DATABASE__HOST", "127.0.0.1".to_string()),
            ("MODLIX__DATABASE__DATABASE", name),
            ("MODLIX__STORAGE__ENDPOINT", fakes.s3_url.clone()),
            ("MODLIX__STORAGE__BUCKET_PREFIX", "test".to_string()),
            ("MODLIX__STORAGE__TEMP_DIR", fakes.dir.display().to_string()),
            ("MODLIX__SECURITY__UPSTREAM", fakes.sec_url.clone()),
            // No Redis and no Eureka: nothing outside this test is touched.
            ("MODLIX__REDIS__URL", String::new()),
            ("MODLIX__TELEMETRY__LOG_LEVEL", "warn".to_string()),
        ] {
            std::env::set_var(k, v);
        }
        let task = tokio::spawn(files::run(Unit::Manage));
        let base = format!("http://127.0.0.1:{port}");
        let mut ready = false;
        for _ in 0..200 {
            if let Ok(r) = reqwest::get(format!("{base}/readyz")).await {
                if r.status().is_success() {
                    ready = true;
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(ready, "files-manage did not become ready");
        assert_eq!(files::Unit::Manage.name(), "files-manage");
        assert_eq!(files::Unit::Serve.name(), "files-serve");

        // A read through the whole stack: the row is looked up in the scratch database.
        let r = reqwest::get(format!("{base}/api/files/static/file/SYSTEM/none.txt")).await.unwrap();
        assert_eq!(r.status().as_u16(), 404);
        assert_eq!(r.headers()["x-frame-options"], "SAMEORIGIN");
        // A write, with its row.
        let r = reqwest::Client::new()
            .post(format!("{base}/api/files/internal/static?clientCode=CLIA&fileName=a.txt&filePath=up"))
            .body("hello")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 200);
        assert_eq!(fakes.object(files::paths::Kind::Static, "CLIA/up/a.txt").unwrap().bytes, b"hello");
        let r = reqwest::get(format!("{base}/api/files/static/file/CLIA/up/a.txt")).await.unwrap();
        assert_eq!(r.text().await.unwrap(), "hello");
        task.abort();
        let _ = task.await;
    })
    .await;
}
