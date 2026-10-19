//! How peers repair what replication lost: a 404 to a replicated heartbeat sends the whole
//! registration, a 409 hands back the newer copy, and the digest comparison fetches whatever is
//! still missing, without bringing back what was cancelled.

mod common;

use std::time::Duration;

use common::*;
use lighthouse_client::replication::REPLICATION_HEADER;

/// Two peers; `tweak` adjusts A's configuration. B compares digests every `b_digest` seconds.
async fn pair(tweak: impl FnOnce(&mut lighthouse::config::LighthouseConfig), b_digest: u64) -> (TestNode, TestNode) {
    let (la, a_url) = bind().await;
    let (lb, b_url) = bind().await;
    let peers = vec![a_url.clone(), b_url.clone()];
    let mut a_cfg = config(&a_url, &peers);
    a_cfg.registry.startup_wait_seconds = 0;
    tweak(&mut a_cfg);
    let mut b_cfg = config(&b_url, &peers);
    b_cfg.registry.startup_wait_seconds = 0;
    b_cfg.registry.digest_interval_seconds = b_digest;
    let (a, b) = (TestNode::start(la, a_cfg), TestNode::start(lb, b_cfg));
    wait_ready(&[&a, &b]).await;
    (a, b)
}

/// Registers on `base` as a peer would, so it is not replicated any further.
async fn register_quietly(base: &str, app: &str, id: &str, dirty: i64) {
    let r = http()
        .post(format!("{base}/eureka/apps/{app}"))
        .header(REPLICATION_HEADER, "true")
        .json(&body(app, id, 8000, dirty))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_heartbeat_the_peer_does_not_know_sends_the_registration() {
    // A queues one item per peer, and flushes slowly: of two registrations made together, the
    // first is pushed out of the queue and never reaches B.
    let (a, b) = pair(|c| {
        c.registry.replication_queue_limit = 1;
        c.registry.replication_flush_ms = 400;
    }, 60)
    .await;
    assert_eq!(register(&a.url, "files", "lost", 10).await, 204);
    assert_eq!(register(&a.url, "files", "kept", 10).await, 204);
    assert!(eventually(Duration::from_secs(2), || async { ids(&b.url).await == ["kept"] }).await);
    assert_eq!(a.node.peers[0].stats().dropped, 1);

    // The next heartbeat of the lost one: B answers 404, A sends B the whole registration.
    assert_eq!(heartbeat(&a.url, "FILES", "lost", 10).await, 200);
    assert!(eventually(Duration::from_secs(3), || async { ids(&b.url).await == ["kept", "lost"] }).await);
    assert_eq!(a.node.peers[0].stats().healed, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stale_peer_adopts_the_newer_copy_from_a_409() {
    let (a, b) = pair(|_| {}, 60).await;
    assert_eq!(register(&a.url, "files", "x", 10).await, 204);
    assert!(eventually(Duration::from_secs(1), || async { ids(&b.url).await == ["x"] }).await);
    // B alone learns a newer registration (dirty 20, on another port).
    let mut newer = body("files", "x", 9000, 20);
    newer["instance"]["port"]["$"] = 9000.into();
    let r = http().post(format!("{}/eureka/apps/FILES", b.url)).header(REPLICATION_HEADER, "true").json(&newer).send().await.unwrap();
    assert_eq!(r.status(), 204);
    assert_eq!(a.node.registry.instance("FILES", "x").unwrap().last_dirty_timestamp, 10);

    // A heartbeat through A carries A's stale copy to B; B's 409 hands A the newer one.
    assert_eq!(heartbeat(&a.url, "FILES", "x", 10).await, 200);
    assert!(
        eventually(Duration::from_secs(2), || async {
            a.node.registry.instance("FILES", "x").is_some_and(|i| i.last_dirty_timestamp == 20 && i.port.port == 9000)
        })
        .await
    );
    assert_eq!(a.node.peers[0].stats().adopted, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_digest_fetches_what_is_missing_but_not_what_was_cancelled() {
    let (a, b) = pair(|_| {}, 1).await;
    // Only A has these: B finds them in A's digest within a digest interval.
    register_quietly(&a.url, "ui-engine", "only-on-a", 5).await;
    register_quietly(&a.url, "ui-engine", "older-on-b", 7).await;
    register_quietly(&b.url, "ui-engine", "older-on-b", 6).await;
    // Cancelled on B, still on A (the cancel never reached it): B must not take it back.
    register_quietly(&a.url, "ui-engine", "cancelled", 5).await;
    register_quietly(&b.url, "ui-engine", "cancelled", 5).await;
    let r = http().delete(format!("{}/eureka/apps/UI-ENGINE/cancelled", b.url)).header(REPLICATION_HEADER, "true").send().await.unwrap();
    assert_eq!(r.status(), 200);

    assert!(eventually(Duration::from_secs(4), || async { ids(&b.url).await == ["older-on-b", "only-on-a"] }).await);
    assert_eq!(b.node.registry.instance("UI-ENGINE", "older-on-b").unwrap().last_dirty_timestamp, 7, "the newer copy");
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(b.node.registry.instance("UI-ENGINE", "cancelled").is_none(), "the tombstone holds");
    assert!(a.node.registry.instance("UI-ENGINE", "cancelled").is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peers_with_a_token_replicate_and_shrug_off_a_404_cancel() {
    let (la, a_url) = bind().await;
    let (lb, b_url) = bind().await;
    let peers = vec![a_url.clone(), b_url.clone()];
    let start = |l, url: &str| {
        let mut c = config(url, &peers);
        c.registry.peer_token = "between-us".into();
        c.registry.startup_wait_seconds = 2;
        TestNode::start(l, c)
    };
    let (a, b) = (start(la, &a_url), start(lb, &b_url));
    wait_ready(&[&a, &b]).await;
    assert_eq!(register(&a.url, "multi", "m", 1).await, 204);
    assert!(eventually(Duration::from_secs(1), || async { ids(&b.url).await == ["m"] }).await, "the token went along");
    assert_eq!(peers_view(&a.url).await[0]["reachable"], true, "the dashboard's probe carries the token too");

    // A cancel of something the peer never had: it answers 404, and that is the end of it.
    let quiet = http()
        .post(format!("{}/eureka/apps/MULTI", a.url))
        .header(REPLICATION_HEADER, "true")
        .bearer_auth("between-us")
        .json(&body("multi", "only-a", 8000, 1))
        .send()
        .await
        .unwrap();
    assert_eq!(quiet.status(), 204);
    assert_eq!(http().delete(format!("{}/eureka/apps/MULTI/only-a", a.url)).send().await.unwrap().status(), 200);
    assert!(eventually(Duration::from_secs(1), || async { a.node.peers[0].queued() == 0 }).await);
    assert_eq!(ids(&b.url).await, ["m"]);
    assert_eq!(a.node.peers[0].stats().healed, 0);
}
