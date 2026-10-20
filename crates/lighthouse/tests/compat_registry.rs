//! The clients in use today, unchanged, against Lighthouse:
//! - `platform::registry::Lighthouse` (every Rust unit) registers, heartbeats, discovers and
//!   deregisters;
//! - the requests py_eureka_client 0.11.10 sends, replayed byte for byte, and the XML it reads
//!   checked for what its parser requires (`tools/compat_py_client.py` runs the real library).

mod common;

use std::time::Duration;

use common::*;
use platform::config::RegistryConfig;
use platform::registry::Registry;
use tokio::sync::watch;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_platform_registry_client_works_unchanged() {
    let (l, url) = bind().await;
    let lh = TestNode::start(l, config(&url, &[]));
    wait_ready(&[&lh]).await;

    let cfg = RegistryConfig {
        register: true,
        register_as: "files".into(),
        zones: vec![format!("{url}/eureka/")],
        instance_ip: "127.0.0.1".into(),
    };
    let registry = Registry::new(&cfg, 8104).unwrap();
    let id = registry.me().unwrap().instance_id.clone();
    let (tx, rx) = watch::channel(false);
    let lifecycle = registry.spawn_lifecycle(rx);

    // Registers.
    assert!(eventually(Duration::from_secs(3), || async { lh.node.registry.instance("FILES", &id).is_some() }).await);
    let registered = lh.node.registry.instance("FILES", &id).unwrap();
    assert_eq!(registered.lease_info.duration_in_secs, 90, "its own lease, the registry protocol's default");
    assert_eq!(registered.metadata.0["runtime"], "rust");

    // Discovers, through GET /eureka/apps/FILES as JSON.
    assert_eq!(registry.resolve("files").await.unwrap(), "http://127.0.0.1:8104");
    assert_eq!(registry.instances("FILES").await.unwrap(), vec!["http://127.0.0.1:8104"]);
    assert!(registry.resolve("nobody").await.is_err(), "404 for an app without instances");

    // Heartbeats (its first is 30 seconds after registering).
    let first = registered.lease_info.last_renewal_timestamp;
    assert!(
        eventually(Duration::from_secs(40), || async {
            lh.node.registry.instance("FILES", &id).is_some_and(|i| i.lease_info.last_renewal_timestamp > first)
        })
        .await,
        "a heartbeat renewed the lease"
    );

    // Deregisters on shutdown.
    tx.send(true).unwrap();
    lifecycle.await.unwrap();
    assert!(lh.node.registry.instance("FILES", &id).is_none());
}

#[tokio::test]
async fn py_eureka_client_requests_replayed() {
    let (l, url) = bind().await;
    let lh = TestNode::start(l, config(&url, &[]));
    wait_ready(&[&lh]).await;
    let e = format!("{url}/eureka");
    let c = http();

    // py's registration body, as captured from py_eureka_client 0.11.10 (`overriddenstatus`,
    // every lease field 0, empty metadata, string timestamps).
    let reg = include_str!("../../lighthouse-client/tests/goldens/register_py.json");
    let r = c.post(format!("{e}/apps/AI")).header("content-type", "application/json").body(reg).send().await.unwrap();
    assert_eq!(r.status(), 204);
    let dirty = lh.node.registry.instance("AI", "h2:ai:8000").unwrap().last_dirty_timestamp;

    // py's GETs carry no Accept header: XML, with what ElementTree needs.
    for path in ["apps/", "apps/delta", "apps/AI", "apps/AI/h2%3Aai%3A8000"] {
        let r = c.get(format!("{e}/{path}")).send().await.unwrap();
        assert_eq!(r.status(), 200, "{path}");
        assert_eq!(r.headers()["content-type"], "application/xml");
        let x = r.text().await.unwrap();
        assert!(x.contains("<port enabled=\"true\">8000</port>"), "{path}: {x}");
        assert!(x.contains("<dataCenterInfo class=\"com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo\">"));
        assert!(x.contains("<metadata class=\"java.util.Collections$EmptyMap\"/>"));
        assert!(!x.contains("Timestamp></"), "no empty numeric element: {x}");
    }
    let x = c.get(format!("{e}/apps/")).send().await.unwrap().text().await.unwrap();
    assert!(x.starts_with("<applications>\n  <versions__delta>1</versions__delta>\n  <apps__hashcode>UP_1_</apps__hashcode>"));

    // Its heartbeat: status, lastDirtyTimestamp and (sometimes) overriddenstatus, quoted id.
    let hb = format!("{e}/apps/AI/h2%3Aai%3A8000?status=UP&lastDirtyTimestamp={dirty}");
    assert_eq!(c.put(&hb).send().await.unwrap().status(), 200);
    let hb2 = format!("{hb}&overriddenstatus=UNKNOWN");
    assert_eq!(c.put(&hb2).send().await.unwrap().status(), 200);
    // A newer lastDirtyTimestamp than ours: 404, and py registers again.
    let newer = format!("{e}/apps/AI/h2%3Aai%3A8000?status=UP&lastDirtyTimestamp={}", dirty + 1);
    assert_eq!(c.put(&newer).send().await.unwrap().status(), 404);

    // status_update / delete_status_override.
    let su = format!("{e}/apps/AI/h2%3Aai%3A8000/status?value=OUT_OF_SERVICE&lastDirtyTimestamp={dirty}");
    assert_eq!(c.put(&su).send().await.unwrap().status(), 200);
    let x = c.get(format!("{e}/apps/delta")).send().await.unwrap().text().await.unwrap();
    assert!(x.contains("<status>OUT_OF_SERVICE</status>") && x.contains("<actionType>MODIFIED</actionType>"));
    assert!(x.contains("<apps__hashcode>OUT_OF_SERVICE_1_</apps__hashcode>"));
    let dso = format!("{e}/apps/AI/h2%3Aai%3A8000/status?lastDirtyTimestamp={dirty}");
    assert_eq!(c.delete(&dso).send().await.unwrap().status(), 200);
    // UNKNOWN now: the next heartbeat is told to register, which py does.
    assert_eq!(c.put(&hb).send().await.unwrap().status(), 404);
    let r = c.post(format!("{e}/apps/AI")).header("content-type", "application/json").body(reg).send().await.unwrap();
    assert_eq!(r.status(), 204);
    assert_eq!(c.put(&hb).send().await.unwrap().status(), 200);

    // py's stop: register DOWN, then cancel.
    let down = reg.replace("\"status\":\"UP\"", "\"status\":\"DOWN\"");
    let r = c.post(format!("{e}/apps/AI")).header("content-type", "application/json").body(down).send().await.unwrap();
    assert_eq!(r.status(), 204);
    assert!(c.get(format!("{e}/apps/AI")).send().await.unwrap().text().await.unwrap().contains("<status>DOWN</status>"));
    assert_eq!(c.delete(format!("{e}/apps/AI/h2%3Aai%3A8000")).send().await.unwrap().status(), 200);
    assert_eq!(c.get(format!("{e}/apps/AI")).send().await.unwrap().status(), 404);
    let x = c.get(format!("{e}/apps/delta")).send().await.unwrap().text().await.unwrap();
    assert!(x.contains("<actionType>DELETED</actionType>"));
    assert!(x.contains("<apps__hashcode></apps__hashcode>"));
}
