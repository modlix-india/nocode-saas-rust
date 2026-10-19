//! The eviction timer.
//!
//! Every `eviction_interval_ms` the registry evicts expired leases (see [`Registry::evict`]).
//! Two cases skip a tick: the registry is still warming up (its leases are not trustworthy
//! before the startup sync), and the tick ran more than `late_tick_skip_ms` late, which means the
//! process was stalled and the heartbeats it would have received were probably held up too.

use std::time::Duration;

use crate::registry::Registry;

/// Whether a tick that came `elapsed` after the previous one is too late to act on.
pub fn too_late(elapsed: Duration, interval: Duration, skip_after: Duration) -> bool {
    elapsed.saturating_sub(interval) > skip_after
}

pub async fn run(registry: &Registry, interval: Duration, skip_after: Duration) {
    let mut last = tokio::time::Instant::now();
    loop {
        tokio::time::sleep(interval).await;
        let now = tokio::time::Instant::now();
        let elapsed = now - last;
        last = now;
        if too_late(elapsed, interval, skip_after) {
            tracing::warn!(late_ms = (elapsed - interval).as_millis() as u64, "eviction tick ran late, skipped");
            metrics::counter!("lighthouse_eviction_ticks_skipped_total").increment(1);
            continue;
        }
        if registry.is_ready() {
            registry.evict();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::tests_support::inst;
    use crate::registry::{Origin, Tuning};
    use std::sync::Arc;

    #[test]
    fn lateness() {
        let s = Duration::from_secs;
        assert!(!too_late(s(5), s(5), s(10)));
        assert!(!too_late(s(15), s(5), s(10)));
        assert!(too_late(s(16), s(5), s(10)));
        assert!(!too_late(s(1), s(5), s(10)));
    }

    #[tokio::test(start_paused = true)]
    async fn evicts_on_ticks_but_not_late_ones_or_while_warming() {
        let r = Arc::new(Registry::new(Tuning { self_preservation: false, ..Tuning::default() }, vec![]));
        r.register(inst("A", "i", 1), Origin::Client);
        let r2 = r.clone();
        let task = tokio::spawn(async move { run(&r2, Duration::from_secs(5), Duration::from_secs(10)).await });
        tokio::task::yield_now().await;

        // Warming up: the lease expires but nothing is evicted.
        tokio::time::advance(Duration::from_secs(5)).await;
        for _ in 0..8 {
            tokio::time::advance(Duration::from_secs(5)).await;
            tokio::task::yield_now().await;
        }
        assert!(r.instance("A", "i").is_some());

        // Ready, but the clock jumps 30 seconds in one go: that tick is skipped.
        r.set_ready();
        tokio::time::advance(Duration::from_secs(30)).await;
        tokio::task::yield_now().await;
        assert!(r.instance("A", "i").is_some(), "a stalled process does not evict");

        // The next regular tick evicts.
        tokio::time::advance(Duration::from_secs(5)).await;
        tokio::task::yield_now().await;
        assert!(r.instance("A", "i").is_none());
        task.abort();
    }
}
