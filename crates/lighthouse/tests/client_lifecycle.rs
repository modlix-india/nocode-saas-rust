//! lighthouse-client against a two-instance Lighthouse: a unit's registration lifecycle on
//! one instance, and the gateway's watch on the other.

mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use common::*;
use lighthouse_client::{registration, Status, WatchConfig, Watcher};
use tokio::sync::watch;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn registration_and_watch_across_peers() {
    let nodes = cluster(2).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    wait_ready(&[a, b]).await;

    let w = Watcher::start(WatchConfig {
        servers: vec![b.url.clone()],
        interval: Duration::from_millis(50),
        ..WatchConfig::default()
    })
    .unwrap();
    let mut seen = w.subscribe();

    let ready = Arc::new(AtomicBool::new(false));
    let r2 = ready.clone();
    // The first server listed is down: the registration falls over to A.
    let reg = registration("files-serve", 8103, "/readyz")
        .servers(["http://127.0.0.1:1", a.url.as_str()])
        .ip("127.0.0.1")
        .lease(Duration::from_millis(100), Duration::from_secs(3))
        .grace(Duration::from_millis(300))
        .ready_poll(Duration::from_millis(20))
        .with_check(move || {
            let ok = r2.load(Ordering::SeqCst);
            async move { ok }
        });
    let id = reg.id().to_string();
    let (tx, rx) = watch::channel(false);
    let task = reg.spawn(rx);

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(a.node.registry.instance("FILES-SERVE", &id).is_none(), "not before it is ready");
    ready.store(true, Ordering::SeqCst);

    // Registered on A, replicated to B, seen by the watch on B.
    tokio::time::timeout(Duration::from_secs(3), seen.wait_for(|apps| apps.up_urls("FILES-SERVE") == ["http://127.0.0.1:8103"]))
        .await
        .expect("the watch saw it UP")
        .unwrap();
    let on_a = a.node.registry.instance("FILES-SERVE", &id).unwrap();
    assert_eq!((on_a.lease_info.renewal_interval_in_secs, on_a.lease_info.duration_in_secs), (1, 3));

    // Unready for three checks: DOWN everywhere; ready again: UP.
    ready.store(false, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(3), seen.wait_for(|apps| apps.up_urls("FILES-SERVE").is_empty() && !apps.is_empty()))
        .await
        .expect("reported DOWN")
        .unwrap();
    assert_eq!(b.node.registry.instance("FILES-SERVE", &id).unwrap().status, Status::Down);
    ready.store(true, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(3), seen.wait_for(|apps| !apps.up_urls("FILES-SERVE").is_empty()))
        .await
        .expect("UP again")
        .unwrap();

    // A forgets it (as after a restart): the next heartbeat registers again.
    a.node.registry.cancel("FILES-SERVE", &id, lighthouse::registry::Origin::Peer);
    assert!(eventually(Duration::from_secs(2), || async { a.node.registry.instance("FILES-SERVE", &id).is_some() }).await);

    // Shutdown: OUT_OF_SERVICE first (the watch sees it drain), then gone after the grace.
    tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(3), seen.wait_for(|apps| {
        apps.application("FILES-SERVE").is_some_and(|a| a.instances.iter().all(|i| i.status == Status::OutOfService))
    }))
    .await
    .expect("drained before leaving")
    .unwrap();
    task.await.unwrap();
    assert!(a.node.registry.instance("FILES-SERVE", &id).is_none(), "deleted");
    assert!(
        eventually(Duration::from_secs(1), || async { b.node.registry.instance("FILES-SERVE", &id).is_none() }).await,
        "the cancel replicated"
    );
    // The watch keeps the last list until the empty registry is confirmed, then empties.
    tokio::time::timeout(Duration::from_secs(3), seen.wait_for(|apps| apps.is_empty())).await.expect("emptied").unwrap();
}
