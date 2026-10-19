//! The retry budget of a pool: retries after a 5xx stay a small share of its traffic, so a
//! failing service is not hit by a wave of retries on top of the requests that failed.
//!
//! A retry is allowed while the window's retries stay under `budget_percent` of its requests,
//! or, when traffic is light, while this second has seen fewer than `budget_min_per_second`
//! retries and the window fewer than that rate times its length.

use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::config::RetryConfig;
use crate::window::Window;

pub struct RetryBudget {
    pool: String,
    cfg: RetryConfig,
    start: Instant,
    /// Requests, retries.
    window: Mutex<Window>,
}

impl RetryBudget {
    pub fn new(pool: &str, cfg: &RetryConfig) -> Self {
        Self {
            pool: pool.to_string(),
            cfg: cfg.clone(),
            start: Instant::now(),
            window: Mutex::new(Window::new(cfg.budget_window_seconds)),
        }
    }

    pub fn record_request(&self) {
        self.request_at(self.start.elapsed());
    }

    fn request_at(&self, now: Duration) {
        self.window.lock().add(now.as_secs(), 1, 0);
    }

    /// Takes a retry from the budget, or counts the refusal.
    pub fn try_retry(&self) -> bool {
        let ok = self.retry_at(self.start.elapsed());
        if !ok {
            metrics::counter!("gateway_retry_budget_exhausted_total", "pool" => self.pool.clone()).increment(1);
        }
        ok
    }

    fn retry_at(&self, now: Duration) -> bool {
        let second = now.as_secs();
        let mut w = self.window.lock();
        let (requests, retries) = w.sum(second);
        let (_, this_second) = w.at(second);
        let floor = u64::from(self.cfg.budget_min_per_second);
        let share = retries * 100 < requests * u64::from(self.cfg.budget_percent);
        let light = this_second < floor && retries < floor * self.cfg.budget_window_seconds.max(1);
        if share || light {
            w.add(second, 0, 1);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_of_requests_with_a_floor_per_second() {
        let b = RetryBudget::new("p", &RetryConfig::default());
        let s = Duration::from_secs;

        // Light traffic: three retries a second whatever the share.
        b.request_at(s(0));
        assert!((0..3).all(|_| b.retry_at(s(0))));
        assert!(!b.retry_at(s(0)), "a fourth in the same second");
        assert!(b.retry_at(s(1)), "the next second has its own three");

        // Heavy traffic: 20% of the window's requests.
        let b = RetryBudget::new("p", &RetryConfig::default());
        for _ in 0..1000 {
            b.request_at(s(0));
        }
        let allowed = (0..1000).filter(|_| b.retry_at(s(0))).count();
        assert_eq!(allowed, 200);
        // Still spent within the window, back once the requests age out.
        assert!(!b.retry_at(s(9)));
        for _ in 0..10 {
            b.request_at(s(10));
        }
        assert!(b.retry_at(s(10)), "the old retries left the window with their requests");

        // The floor cannot add up past its rate over the window.
        let b = RetryBudget::new("p", &RetryConfig { budget_window_seconds: 2, ..Default::default() });
        assert!((0..3).all(|_| b.retry_at(s(0))));
        assert!((0..3).all(|_| b.retry_at(s(1))));
        assert!(!b.retry_at(s(1)));
        assert!(b.retry_at(s(2)));

        // On the real clock: no floor and no requests leaves nothing to spend.
        let none = RetryBudget::new("p", &RetryConfig { budget_min_per_second: 0, ..Default::default() });
        assert!(!none.try_retry());
        none.record_request();
        assert!(none.try_retry());
    }
}
