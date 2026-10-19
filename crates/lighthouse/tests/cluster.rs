//! Three peers in one process: what happens on one is seen on the others within a second.

mod common;

use std::time::{Duration, Instant};

use common::*;
use lighthouse_client::wire::Status;

async fn status_on(base: &str, app: &str, id: &str) -> Option<Status> {
    apps(base).await?.application(app)?.instances.iter().find(|i| i.instance_id == id).map(|i| i.status)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn register_heartbeat_status_and_cancel_replicate() {
    let nodes = cluster(3).await;
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    // Started together, every peer is warming up when asked: each serves after its wait.
    wait_ready(&[a, b, c]).await;

    // Register on A: visible on B and C within a second.
    let started = Instant::now();
    assert_eq!(register(&a.url, "files", "f1", 1000).await, 204);
    for n in [b, c] {
        assert!(
            eventually(Duration::from_secs(1), || async { status_on(&n.url, "FILES", "f1").await == Some(Status::Up) }).await,
            "not on {} within a second",
            n.url
        );
    }
    assert!(started.elapsed() < Duration::from_secs(1));

    // A heartbeat through B renews the lease on A and C too.
    let renewed_at = |base: String| async move {
        let apps = apps(&base).await.unwrap();
        apps.application("FILES").unwrap().instances[0].lease_info.last_renewal_timestamp
    };
    let before = renewed_at(a.url.clone()).await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(heartbeat(&b.url, "FILES", "f1", 1000).await, 200);
    for n in [a, c] {
        let url = n.url.clone();
        assert!(eventually(Duration::from_secs(1), || { let u = url.clone(); async move { renewed_at(u).await > before } }).await);
    }

    // OUT_OF_SERVICE through A drains it everywhere.
    let r = http().put(format!("{}/eureka/apps/FILES/f1/status?value=OUT_OF_SERVICE", a.url)).send().await.unwrap();
    assert_eq!(r.status(), 200);
    for n in [b, c] {
        assert!(
            eventually(Duration::from_secs(1), || async { status_on(&n.url, "FILES", "f1").await == Some(Status::OutOfService) })
                .await
        );
    }

    // The dashboard puts it back through B (the override goes, the status is UNKNOWN until its
    // next heartbeat), then takes it out again through C: both replicate.
    let manage = |base: &str, rest: &str| format!("{base}/v1/admin/apps/FILES/f1{rest}");
    assert_eq!(admin("DELETE", manage(&b.url, "/status"), Some(ADMIN_TOKEN)).await, 200);
    for n in [a, c] {
        assert!(eventually(Duration::from_secs(1), || async { status_on(&n.url, "FILES", "f1").await == Some(Status::Unknown) }).await);
    }
    assert_eq!(admin("PUT", manage(&c.url, "/status?value=OUT_OF_SERVICE"), None).await, 401, "not without the token");
    assert_eq!(admin("PUT", manage(&c.url, "/status?value=OUT_OF_SERVICE"), Some(ADMIN_TOKEN)).await, 200);
    for n in [a, b] {
        assert!(
            eventually(Duration::from_secs(1), || async { status_on(&n.url, "FILES", "f1").await == Some(Status::OutOfService) })
                .await
        );
    }
    assert_eq!(register(&a.url, "files", "f2", 1000).await, 204);
    assert!(eventually(Duration::from_secs(1), || async { ids(&b.url).await.len() == 2 }).await);
    assert_eq!(admin("DELETE", format!("{}/v1/admin/apps/FILES/f2", a.url), Some("wrong")).await, 401);
    assert_eq!(admin("DELETE", format!("{}/v1/admin/apps/FILES/f2", a.url), Some(ADMIN_TOKEN)).await, 200);
    for n in [b, c] {
        assert!(eventually(Duration::from_secs(1), || async { ids(&n.url).await == ["f1"] }).await, "removal replicated");
    }

    // Cancel through C: gone everywhere.
    let r = http().delete(format!("{}/eureka/apps/FILES/f1", c.url)).send().await.unwrap();
    assert_eq!(r.status(), 200);
    for n in [a, b] {
        assert!(eventually(Duration::from_secs(1), || async { ids(&n.url).await.is_empty() }).await);
    }

    // Many registrations spread over the three converge on all three.
    for i in 0..30 {
        let via = &nodes[i % 3];
        assert_eq!(register(&via.url, "ui-engine", &format!("u{i}"), 2000 + i as i64).await, 204);
    }
    let all: Vec<String> = {
        let mut v: Vec<String> = (0..30).map(|i| format!("u{i}")).collect();
        v.sort();
        v
    };
    for n in &nodes {
        assert!(eventually(Duration::from_secs(2), || async { ids(&n.url).await == all }).await, "{} did not converge", n.url);
    }

    // The operator view lists the peers and their queues.
    let v = operator(&a.url).await;
    assert_eq!(v["ready"], true);
    assert_eq!(v["instances"], 30);
    let peers = peers_view(&a.url).await;
    assert_eq!(peers.len(), 2, "not itself");
    assert!(peers.iter().all(|p| p["reachable"] == true && p["queued"] == 0 && p["batches"].as_u64().unwrap() > 0));
}
