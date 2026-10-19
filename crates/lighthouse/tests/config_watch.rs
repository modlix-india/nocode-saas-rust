//! Config changes reaching running units: the client's version watch against a real Lighthouse
//! tells a live change (only live keys) from one that needs the rolling restart, and the
//! Config view compares what each registered instance runs (`configVersion`) with the current
//! version, as `keepup-rust.sh health` does.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use lighthouse_client::config::{Change, ConfigClient};
use serde_json::{json, Value};

fn rewrite(dir: &std::path::Path, file: &str, from: &str, to: &str) {
    let path = dir.join(file);
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains(from), "{file} has no {from}");
    std::fs::write(&path, text.replace(from, to)).unwrap();
}

async fn register_with(base: &str, id: &str, version: Option<&str>) {
    let mut b = body("multi", id, 8110, lighthouse_client::now_millis());
    if let Some(v) = version {
        b["instance"]["metadata"]["configVersion"] = json!(v);
    }
    let r = http().post(format!("{base}/eureka/apps/MULTI")).json(&b).send().await.unwrap();
    assert_eq!(r.status(), 204);
}

async fn states(base: &str) -> Vec<(String, String)> {
    let view: Value = get(format!("{base}/v1/config"), None).await.json().await.unwrap();
    let multi = view["units"].as_array().unwrap().iter().find(|u| u["unit"] == "multi").unwrap().clone();
    let mut out: Vec<(String, String)> = multi["instances"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| (i["id"].as_str().unwrap().to_string(), i["state"].as_str().unwrap().to_string()))
        .collect();
    out.sort();
    out
}

async fn next(rx: &mut tokio::sync::mpsc::UnboundedReceiver<Change>) -> Change {
    tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.unwrap().unwrap()
}

#[tokio::test]
async fn live_changes_and_restarts() {
    let dir = fixture_copy("watch");
    let (l, url) = bind().await;
    let n = TestNode::start(l, config_server(&url, &[], &format!("dir:{}", dir.display()), "dev"));
    let cs = n.node.config.clone().unwrap();
    assert!(eventually(Duration::from_secs(5), || async { cs.served().is_some() }).await);
    wait_ready(&[&n]).await;

    let client = Arc::new(ConfigClient::new(&[format!("{url}/eureka")], Some(UNITS_TOKEN.into())));
    let start = client.fetch("multi").await.unwrap();
    assert_eq!(start.unit, "multi");
    register_with(&url, "h:multi:1", Some(&start.version)).await;
    register_with(&url, "h:multi:2", None).await;
    assert_eq!(states(&url).await, [("h:multi:1".into(), "current".into()), ("h:multi:2".into(), "unmanaged".into())]);

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let watch = lighthouse_client::config::watch_version(client.clone(), "multi", &start.version, Duration::from_millis(20), move |c| {
        let tx = tx.clone();
        async move {
            let _ = tx.send(c);
            true
        }
    });

    // The log level is a live key: applied in place, the instance runs the same restart part.
    rewrite(&dir, "rust/multi.toml", "log_level = \"info\"", "log_level = \"debug\"");
    assert!(cs.poll_once().await);
    let Change::Live(live) = next(&mut rx).await else { panic!("a live change") };
    let doc = client.fetch("multi").await.unwrap();
    assert_eq!(doc.version, live);
    assert_eq!(doc.document["telemetry"]["log_level"], "debug");
    assert_eq!(states(&url).await[0].1, "live");

    // The port is not: the restart applies it, and the instance shows stale until it runs it.
    rewrite(&dir, "rust/multi.toml", "port = 8110", "port = 8120");
    assert!(cs.poll_once().await);
    let Change::Restart(restart) = next(&mut rx).await else { panic!("a restart") };
    assert_eq!(states(&url).await[0].1, "stale");
    register_with(&url, "h:multi:1", Some(&restart)).await;
    assert_eq!(states(&url).await[0].1, "current");

    // A change to another unit leaves multi's version alone.
    rewrite(&dir, "rust/core-exec.toml", "port = 8105", "port = 8125");
    assert!(cs.poll_once().await);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(rx.try_recv().is_err());
    watch.abort();
    std::fs::remove_dir_all(&dir).unwrap();
}
