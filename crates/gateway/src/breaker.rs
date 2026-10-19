//! A circuit breaker per pool.
//!
//! Closed, it counts each request's final outcome over a short window. When enough requests
//! failed it opens: requests are answered 503 at once, so a failing service gets room to
//! recover instead of a queue. After the open time a few trial requests go through
//! (half-open); if they all succeed it closes, if one fails it opens again for twice as long.
//!
//! `gateway_pool_breaker_state{pool}` is 0 closed, 1 half-open, 2 open.

use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::config::BreakerConfig;
use crate::window::Window;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Closed,
    /// Refusing until this long after the breaker's start.
    Open { until: Duration },
    /// `in_flight` trials are under way and `passed` have succeeded.
    HalfOpen { in_flight: u32, passed: u32 },
}

struct State {
    mode: Mode,
    /// Bumped on every change of mode, so an outcome from before the change is ignored.
    generation: u64,
    window: Window,
    /// How long the next opening lasts: `open_ms`, doubled by every failed trial.
    open_for: Duration,
}

pub struct Breaker {
    pool: String,
    cfg: BreakerConfig,
    start: Instant,
    state: Mutex<State>,
}

/// Leave to send one request. Its outcome goes back through [`Breaker::record`]; a permit
/// dropped without one (the caller went away) just frees its trial slot.
pub struct Permit<'a> {
    breaker: &'a Breaker,
    generation: u64,
    trial: bool,
    done: bool,
}

impl Breaker {
    pub fn new(pool: &str, cfg: &BreakerConfig) -> Self {
        let this = Self {
            pool: pool.to_string(),
            cfg: cfg.clone(),
            start: Instant::now(),
            state: Mutex::new(State {
                mode: Mode::Closed,
                generation: 0,
                window: Window::new(cfg.window_seconds),
                open_for: Duration::from_millis(cfg.open_ms),
            }),
        };
        this.gauge(Mode::Closed);
        this
    }

    fn now(&self) -> Duration {
        self.start.elapsed()
    }

    pub fn mode(&self) -> Mode {
        self.state.lock().mode
    }

    /// A permit for the next request, or how long until the breaker lets trials through.
    pub fn admit(&self) -> Result<Permit<'_>, Duration> {
        self.admit_at(self.now())
    }

    fn admit_at(&self, now: Duration) -> Result<Permit<'_>, Duration> {
        if !self.cfg.enabled {
            return Ok(Permit { breaker: self, generation: 0, trial: false, done: true });
        }
        let mut s = self.state.lock();
        if let Mode::Open { until } = s.mode {
            if now < until {
                return Err(until - now);
            }
            self.set(&mut s, Mode::HalfOpen { in_flight: 0, passed: 0 });
        }
        match s.mode {
            Mode::HalfOpen { in_flight, passed } => {
                if in_flight + passed >= self.cfg.half_open_trials.max(1) {
                    // Trials are under way; the rest wait for their verdict.
                    return Err(Duration::ZERO);
                }
                s.mode = Mode::HalfOpen { in_flight: in_flight + 1, passed };
                Ok(Permit { breaker: self, generation: s.generation, trial: true, done: false })
            }
            _ => Ok(Permit { breaker: self, generation: s.generation, trial: false, done: false }),
        }
    }

    /// The request's final outcome: `false` for a connect failure, a timeout, a broken
    /// connection or a 502/503/504 answer.
    pub fn record(&self, mut permit: Permit<'_>, ok: bool) {
        permit.done = true;
        if !self.cfg.enabled {
            return;
        }
        self.record_at(self.now(), permit.generation, permit.trial, ok);
    }

    fn record_at(&self, now: Duration, generation: u64, trial: bool, ok: bool) {
        let mut s = self.state.lock();
        if generation != s.generation {
            return;
        }
        match s.mode {
            Mode::Closed => {
                let second = now.as_secs();
                s.window.add(second, 1, u64::from(!ok));
                if !ok {
                    let (total, failed) = s.window.sum(second);
                    if total >= u64::from(self.cfg.min_requests)
                        && failed * 100 >= total * u64::from(self.cfg.failure_percent)
                    {
                        tracing::warn!(pool = self.pool, total, failed, "circuit breaker opened");
                        let until = now + s.open_for;
                        self.set(&mut s, Mode::Open { until });
                    }
                }
            }
            Mode::HalfOpen { in_flight, passed } if trial => {
                if ok {
                    let passed = passed + 1;
                    if passed >= self.cfg.half_open_trials.max(1) {
                        tracing::info!(pool = self.pool, "circuit breaker closed after its trial requests");
                        s.open_for = Duration::from_millis(self.cfg.open_ms);
                        self.set(&mut s, Mode::Closed);
                    } else {
                        s.mode = Mode::HalfOpen { in_flight: in_flight.saturating_sub(1), passed };
                    }
                } else {
                    s.open_for = (s.open_for * 2).min(Duration::from_millis(self.cfg.max_open_ms.max(self.cfg.open_ms)));
                    tracing::warn!(pool = self.pool, open_ms = s.open_for.as_millis() as u64, "circuit breaker trial failed, open again");
                    let until = now + s.open_for;
                    self.set(&mut s, Mode::Open { until });
                }
            }
            _ => {}
        }
    }

    /// A trial that never finished frees its slot for another.
    fn release(&self, generation: u64) {
        let mut s = self.state.lock();
        if generation != s.generation {
            return;
        }
        if let Mode::HalfOpen { in_flight, passed } = s.mode {
            s.mode = Mode::HalfOpen { in_flight: in_flight.saturating_sub(1), passed };
        }
    }

    fn set(&self, s: &mut State, mode: Mode) {
        s.mode = mode;
        s.generation += 1;
        s.window.clear();
        self.gauge(mode);
    }

    fn gauge(&self, mode: Mode) {
        let v = match mode {
            Mode::Closed => 0.0,
            Mode::HalfOpen { .. } => 1.0,
            Mode::Open { .. } => 2.0,
        };
        metrics::gauge!("gateway_pool_breaker_state", "pool" => self.pool.clone()).set(v);
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        if !self.done && self.trial {
            self.breaker.release(self.generation);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> BreakerConfig {
        BreakerConfig { open_ms: 1_000, max_open_ms: 3_000, ..Default::default() }
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    /// Admits at `now` and records the outcome at once.
    fn run(b: &Breaker, now: Duration, ok: bool) -> bool {
        match b.admit_at(now) {
            Ok(mut p) => {
                p.done = true;
                b.record_at(now, p.generation, p.trial, ok);
                true
            }
            Err(_) => false,
        }
    }

    #[test]
    fn opens_on_enough_failures_only() {
        let b = Breaker::new("p", &cfg());
        // 19 failures: below the 20 request minimum.
        for _ in 0..19 {
            assert!(run(&b, ms(100), false));
        }
        assert_eq!(b.mode(), Mode::Closed);
        assert!(run(&b, ms(200), false));
        assert_eq!(b.mode(), Mode::Open { until: ms(1_200) });
        assert_eq!(b.admit_at(ms(700)).err(), Some(ms(500)));

        // 50% failures over 20 requests opens; 45% does not.
        let b = Breaker::new("p", &cfg());
        for i in 0..20 {
            run(&b, ms(0), i < 11);
        }
        assert_eq!(b.mode(), Mode::Closed, "9 of 20 failed");
        let b = Breaker::new("p", &cfg());
        for i in 0..20 {
            run(&b, ms(0), i % 2 == 0);
        }
        assert!(matches!(b.mode(), Mode::Open { .. }), "10 of 20 failed");

        // Failures older than the window do not count.
        let b = Breaker::new("p", &cfg());
        for _ in 0..15 {
            run(&b, ms(0), false);
        }
        for _ in 0..10 {
            run(&b, Duration::from_secs(10), false);
        }
        assert_eq!(b.mode(), Mode::Closed);
    }

    #[test]
    fn half_open_trials_close_or_reopen_with_back_off() {
        let b = Breaker::new("p", &cfg());
        for _ in 0..20 {
            run(&b, ms(0), false);
        }
        // Open for 1 s; then three trials at a time.
        let t = ms(1_000);
        let p1 = b.admit_at(t).unwrap();
        let p2 = b.admit_at(t).unwrap();
        let p3 = b.admit_at(t).unwrap();
        assert!(p1.trial && p2.trial && p3.trial);
        assert_eq!(b.admit_at(t).err(), Some(Duration::ZERO), "a fourth waits");
        // A trial that never finishes frees its slot.
        drop(p3);
        let p4 = b.admit_at(t).unwrap();
        b.record(p1, true);
        b.record(p2, true);
        assert_eq!(b.mode(), Mode::HalfOpen { in_flight: 1, passed: 2 });
        b.record(p4, true);
        assert_eq!(b.mode(), Mode::Closed);

        // Open again; a failed trial doubles the open time, up to the maximum.
        for _ in 0..20 {
            run(&b, ms(2_000), false);
        }
        assert_eq!(b.mode(), Mode::Open { until: ms(3_000) });
        assert!(run(&b, ms(3_000), false));
        assert_eq!(b.mode(), Mode::Open { until: ms(5_000) });
        assert!(run(&b, ms(5_000), false));
        assert_eq!(b.mode(), Mode::Open { until: ms(8_000) }, "4 s capped at 3 s");
        // Three passing trials close it, and the next opening is back to 1 s.
        for _ in 0..3 {
            assert!(run(&b, ms(8_000), true));
        }
        assert_eq!(b.mode(), Mode::Closed);
        for _ in 0..20 {
            run(&b, ms(9_000), false);
        }
        assert_eq!(b.mode(), Mode::Open { until: ms(10_000) });
    }

    #[test]
    fn stale_outcomes_and_disabled() {
        let b = Breaker::new("p", &cfg());
        let early = b.admit_at(ms(0)).unwrap();
        for _ in 0..20 {
            run(&b, ms(0), false);
        }
        // A request admitted before the breaker opened finishes while it is open: ignored.
        b.record(early, true);
        assert!(matches!(b.mode(), Mode::Open { .. }));
        // A closed-state permit finishing during half-open is not a trial.
        let b = Breaker::new("p", &cfg());
        let early = b.admit_at(ms(0)).unwrap();
        let gen = early.generation;
        drop(early);
        for _ in 0..20 {
            run(&b, ms(0), false);
        }
        let trial = b.admit_at(ms(1_000)).unwrap();
        b.record_at(ms(1_000), gen, false, false);
        assert_eq!(b.mode(), Mode::HalfOpen { in_flight: 1, passed: 0 });
        b.release(gen);
        b.record(trial, true);

        let off = Breaker::new("p", &BreakerConfig { enabled: false, ..cfg() });
        for _ in 0..100 {
            let p = off.admit().unwrap();
            off.record(p, false);
        }
        assert_eq!(off.mode(), Mode::Closed);
    }
}
