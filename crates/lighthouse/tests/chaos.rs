//! What goes wrong between peers, and how the registry comes through it.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use common::*;
use lighthouse::registry::Origin;
use lighthouse::Node;
use lighthouse_client::replication::{Action, ReplicationInstance, ReplicationList, ReplicationListResponse, REPLICATION_HEADER};
use lighthouse_client::wire::{InstanceEnvelope, Status};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A peer that reads each request and then drops the connection without answering, the way a
/// process killed in the middle of a batch does. Counts the attempts.
fn aborting_peer(l: TcpListener, attempts: Arc<AtomicUsize>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { continue };
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf).await;
            attempts.fetch_add(1, Ordering::SeqCst);
            drop(s);
        }
    })
}

/// A peer that answers every request 500.
fn failing_peer(l: TcpListener, attempts: Arc<AtomicUsize>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { continue };
            let attempts = attempts.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 65536];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    attempts.fetch_add(1, Ordering::SeqCst);
                    let _ = s.write_all(b"HTTP/1.1 500 Internal Server Error\r\ncontent-length: 0\r\n\r\n").await;
                }
            });
        }
    })
}

/// A peer that takes connections and never answers.
fn silent_peer(l: TcpListener) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            if let Ok((s, _)) = l.accept().await {
                held.push(s);
            }
        }
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_killed_mid_batch_gets_everything_once_back() {
    let (la, a_url) = bind().await;
    let (lb, b_url) = bind().await;
    let peers = vec![a_url.clone(), b_url.clone()];
    let mut cfg = config(&a_url, &peers);
    cfg.registry.startup_wait_seconds = 0;
    // The digest comparison with the broken peer fails too, and is retried.
    cfg.registry.digest_interval_seconds = 1;
    let a = TestNode::start(la, cfg);
    let attempts = Arc::new(AtomicUsize::new(0));
    let fake_b = aborting_peer(lb, attempts.clone());
    wait_ready(&[&a]).await;

    for i in 0..5 {
        assert_eq!(register(&a.url, "core-exec", &format!("c{i}"), 100 + i).await, 204);
    }
    // The startup sync was one attempt; the batch was cut off and retried; the digest too.
    assert!(eventually(Duration::from_secs(3), || async { attempts.load(Ordering::SeqCst) >= 3 }).await, "retried");
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let peer = &a.node.peers[0];
    assert!(
        eventually(Duration::from_secs(1), || async { peer.queued() == 5 }).await,
        "nothing lost: the aborted batch went back in the queue"
    );
    assert!(peer.stats().failures >= 2);

    // B comes back on the same port: it syncs from A, and A's queue drains into it.
    fake_b.abort();
    let b = TestNode::start(rebind(&b_url).await, config(&b_url, &peers));
    wait_ready(&[&b]).await;
    let want: Vec<String> = (0..5).map(|i| format!("c{i}")).collect();
    assert!(eventually(Duration::from_secs(3), || async { ids(&b.url).await == want }).await);
    assert!(eventually(Duration::from_secs(3), || async { peer.queued() == 0 }).await, "the queue drained");
    // And replication carries on as normal.
    assert_eq!(register(&a.url, "core-exec", "c9", 200).await, 204);
    assert!(eventually(Duration::from_secs(1), || async { ids(&b.url).await.contains(&"c9".to_string()) }).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_answering_500s_holds_nothing_up_and_keeps_registrations() {
    let (la, a_url) = bind().await;
    let (lb, b_url) = bind().await;
    let (lc, c_url) = bind().await;
    let peers = vec![a_url.clone(), b_url.clone(), c_url.clone()];
    let mut cfg = config(&a_url, &peers);
    cfg.registry.replication_queue_limit = 6;
    cfg.registry.startup_wait_seconds = 0;
    let a = TestNode::start(la, cfg);
    let attempts = Arc::new(AtomicUsize::new(0));
    let bad_b = failing_peer(lb, attempts.clone());
    let mut c_cfg = config(&c_url, &peers);
    c_cfg.registry.startup_wait_seconds = 0;
    let c = TestNode::start(lc, c_cfg);
    wait_ready(&[&a, &c]).await;

    // Registrations reach C at once although B fails every batch.
    for i in 0..3 {
        assert_eq!(register(&a.url, "multi", &format!("m{i}"), 10).await, 204);
    }
    let want = vec!["m0".to_string(), "m1".to_string(), "m2".to_string()];
    assert!(eventually(Duration::from_secs(1), || async { ids(&c.url).await == want }).await);

    // Heartbeats pile up for B; the full queue drops heartbeats, never the registrations.
    for _ in 0..10 {
        for i in 0..3 {
            assert_eq!(heartbeat(&a.url, "MULTI", &format!("m{i}"), 10).await, 200);
        }
    }
    assert!(eventually(Duration::from_secs(2), || async { attempts.load(Ordering::SeqCst) >= 2 }).await);
    let b_peer = a.node.peers.iter().find(|p| p.url == b_url).unwrap();
    assert!(b_peer.queued() <= 6);
    assert!(eventually(Duration::from_secs(1), || async { b_peer.queued_by_action().get("register") == Some(&3) }).await);
    assert!(eventually(Duration::from_secs(1), || async { b_peer.stats().dropped >= 30 - 3 }).await, "heartbeats went first");
    let views = peers_view(&a.url).await;
    let b_view = views.iter().find(|p| p["url"] == b_url.as_str()).unwrap();
    assert!(b_view["lastError"].as_str().unwrap().contains("500"));
    assert_eq!(b_view["reachable"], false, "it answers 500 to everything");
    let c_view = views.iter().find(|p| p["url"] == c_url.as_str()).unwrap();
    assert_eq!(c_view["reachable"], true);
    assert!(c_view["lastSuccessAgoMs"].as_i64().unwrap() >= 0);

    // B recovers: the kept registrations reach it.
    bad_b.abort();
    let mut b_cfg = config(&b_url, &peers);
    b_cfg.registry.startup_wait_seconds = 0;
    let b = TestNode::start(rebind(&b_url).await, b_cfg);
    assert!(eventually(Duration::from_secs(5), || async { ids(&b.url).await == want }).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restarted_peer_syncs_before_it_serves() {
    let (la, a_url) = bind().await;
    let (lb, b_url) = bind().await;
    let (lq, quiet_url) = bind().await;
    let _quiet = silent_peer(lq);
    let peers = vec![a_url.clone(), b_url.clone()];
    let mut a_cfg = config(&a_url, &peers);
    a_cfg.registry.startup_wait_seconds = 0;
    let a = TestNode::start(la, a_cfg);
    wait_ready(&[&a]).await;
    for i in 0..5 {
        assert_eq!(register(&a.url, "ui-shell", &format!("s{i}"), 50).await, 204);
    }

    // B starts with a peer that never answers listed first, so its sync takes a while.
    let mut b_cfg = config(&b_url, &[quiet_url, a_url.clone(), b_url.clone()]);
    b_cfg.registry.peer_timeout_ms = 600;
    b_cfg.registry.startup_wait_seconds = 10;
    let b = TestNode::start(lb, b_cfg);

    // Warming: discovery answers 503 (with Retry-After), writes are taken.
    let r = http().get(format!("{}/eureka/apps", b.url)).send().await.unwrap();
    assert_eq!(r.status(), 503);
    assert_eq!(r.headers()["retry-after"], "5");
    for path in ["/eureka/apps/delta", "/eureka/apps/UI-SHELL", "/eureka/apps/UI-SHELL/s0"] {
        assert_eq!(http().get(format!("{}{path}", b.url)).send().await.unwrap().status(), 503, "{path}");
    }
    assert_eq!(register(&b.url, "ui-shell", "s-warm", 60).await, 204);
    assert!(!b.node.registry.is_ready());

    // The first 200 already holds everything A had, plus what came in while warming.
    let mut want: Vec<String> = (0..5).map(|i| format!("s{i}")).collect();
    want.push("s-warm".into());
    want.sort();
    let first = loop {
        if let Some(a) = apps(&b.url).await {
            break a;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    let mut got: Vec<String> = first.instances().map(|i| i.instance_id.clone()).collect();
    got.sort();
    assert_eq!(got, want);
    // And A learnt the registration B took while warming.
    assert!(eventually(Duration::from_secs(1), || async { ids(&a.url).await == want }).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tombstone_refuses_a_late_registration() {
    let nodes = cluster(2).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    wait_ready(&[a, b]).await;
    assert_eq!(register(&a.url, "files", "x", 500).await, 204);
    assert!(eventually(Duration::from_secs(1), || async { ids(&b.url).await == ["x"] }).await);
    let late = b.node.registry.instance("FILES", "x").unwrap();
    assert_eq!(http().delete(format!("{}/eureka/apps/FILES/x", a.url)).send().await.unwrap().status(), 200);
    assert!(eventually(Duration::from_secs(1), || async { ids(&b.url).await.is_empty() }).await);

    // A peer's Register that was delayed past the cancel: refused, in a batch...
    let batch = |info: lighthouse_client::wire::InstanceInfo| ReplicationList {
        replication_list: vec![ReplicationInstance {
            app_name: "FILES".into(),
            id: "x".into(),
            last_dirty_timestamp: Some(info.last_dirty_timestamp),
            overridden_status: None,
            status: Some(Status::Up),
            instance_info: Some(info),
            action: Action::Register,
        }],
    };
    let r: ReplicationListResponse = http()
        .post(format!("{}/eureka/peerreplication/batch", b.url))
        .header(REPLICATION_HEADER, "true")
        .json(&batch(late.clone()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r.response_list[0].status_code, 409);
    // ...and as a single replicated call.
    let r = http()
        .post(format!("{}/eureka/apps/FILES", b.url))
        .header(REPLICATION_HEADER, "true")
        .json(&InstanceEnvelope { instance: late.clone() })
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 409);
    assert!(ids(&b.url).await.is_empty(), "the cancelled instance stays cancelled");

    // A newer registration (the instance restarted) is taken.
    let mut newer = late.clone();
    newer.last_dirty_timestamp += 1;
    let r: ReplicationListResponse = http()
        .post(format!("{}/eureka/peerreplication/batch", b.url))
        .json(&batch(newer))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r.response_list[0].status_code, 200);
    assert_eq!(ids(&b.url).await, ["x"]);
}

/// Half the heartbeats stop (a network problem, not the instances): nothing is evicted.
/// Runs on tokio's paused clock with the node's own eviction timer.
#[tokio::test(start_paused = true)]
async fn self_preservation_when_half_the_heartbeats_stop() {
    let node = |preserve: bool| {
        let mut cfg = config("http://127.0.0.1:1", &[]);
        cfg.registry.eviction_interval_ms = 5_000;
        cfg.registry.self_preservation = preserve;
        let n = Node::new(cfg).unwrap();
        n.start();
        n
    };
    let (kept, control) = (node(true), node(false));
    for n in [&kept, &control] {
        for i in 0..10 {
            let info: InstanceEnvelope = serde_json::from_value(body("core-events", &format!("e{i}"), 8000, 1)).unwrap();
            n.registry.register(info.instance, Origin::Client);
        }
    }
    let beat = |n: &Node, upto: usize| {
        for i in 0..upto {
            n.registry.renew("CORE-EVENTS", &format!("e{i}"), Origin::Client, None, None);
        }
    };
    // A healthy minute and more.
    for _ in 0..8 {
        tokio::time::advance(Duration::from_secs(10)).await;
        tokio::task::yield_now().await;
        beat(&kept, 10);
        beat(&control, 10);
    }
    assert!(kept.registry.is_ready());
    assert!(!kept.registry.preservation().active);

    // Half stop for two minutes: their leases (30 s) run out long before.
    for _ in 0..12 {
        tokio::time::advance(Duration::from_secs(10)).await;
        tokio::task::yield_now().await;
        beat(&kept, 5);
        beat(&control, 5);
    }
    let p = kept.registry.preservation();
    assert!(p.active, "{p:?}");
    assert!(p.renewals_last_minute < p.threshold as u64);
    assert_eq!(kept.registry.applications().0.instances().count(), 10, "self-preservation kept them all");
    assert_eq!(control.registry.applications().0.instances().count(), 5, "without it the silent half is gone");
}
