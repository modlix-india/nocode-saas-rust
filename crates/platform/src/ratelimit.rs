//! A per address limit on what callers who are not signed in may run, counted in Redis so every
//! instance of every unit that checks the same bucket shares one budget per address (core-exec's
//! execute routes and ui-shell's URI path routes both count `anon`).
//!
//! Fixed windows of one minute: the key is `<prefix>:rl:<bucket>:<address>:<minute>`
//! ([`crate::cache::window_key`]). An IPv6 caller is counted by its /64 (one household or phone
//! holds a whole /64, so a single address would cost nothing to change); an IPv4 address written
//! as IPv6 is the IPv4 address. A caller whose address cannot be told is counted under
//! `<bucket>-noip`, one budget for all of them.
//!
//! The limiter fails open: with no Redis, or a Redis that errs or does not answer, the request
//! runs and the miss is counted (`outcome="failopen"`). Every decision is counted in
//! [`RATELIMIT_TOTAL`] by `bucket` and `outcome`.
//!
//! `[ratelimit]` of the unit ([`RateLimitConfig`]): `mode` (`enforce`, `report`, `off`),
//! `anonymous_per_minute`, per bucket limits in `[ratelimit.buckets]`, and `exempt_ips`
//! (addresses or CIDR ranges never limited, such as our own monitors).

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};

use crate::cache::CacheService;
use crate::error::Coded;

/// Decisions by `bucket` and `outcome`: `allowed`, `limited` (refused), `reported` (over the
/// limit in `report` mode, let through), `exempt`, `failopen` (no count could be had).
pub const RATELIMIT_TOTAL: &str = "core_ratelimit_total";

/// The refusal's code (core's catalogue, `crates/core/messages/en.toml`), status 429, value
/// `retryAfterSeconds`.
pub const TOO_MANY_REQUESTS: &str = "CORE.TOO_MANY_REQUESTS";

/// The bucket of anonymous server function runs.
pub const ANON: &str = "anon";

/// The window every bucket counts in.
pub const WINDOW_SECS: u64 = 60;

/// How a limit is applied: `enforce` refuses over the limit, `report` logs and counts what it
/// would refuse, `off` does not count at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RateLimitMode {
    Off,
    Report,
    #[default]
    Enforce,
}

/// `[ratelimit]` of the units that run functions for callers who are not signed in (core-exec,
/// ui-shell; core-editor and core-events read it too and never use it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RateLimitConfig {
    pub mode: RateLimitMode,
    /// Runs a minute from one address for a caller who is not signed in.
    pub anonymous_per_minute: u64,
    /// A bucket's own limit a minute (`anon`, `anon-noip`), instead of `anonymous_per_minute`;
    /// `0` leaves the bucket unlimited.
    pub buckets: BTreeMap<String, u64>,
    /// Addresses or CIDR ranges never limited.
    pub exempt_ips: Vec<String>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self { mode: RateLimitMode::Enforce, anonymous_per_minute: 600, buckets: BTreeMap::new(), exempt_ips: Vec::new() }
    }
}

/// Where the counts are kept: Redis ([`CacheService::incr_window_at`]) in the units,
/// [`MemoryCounter`] in tests.
pub trait WindowCounter: Send + Sync {
    /// The count of `key` in the window holding `now_secs`, after adding one; `None` when it
    /// cannot be had.
    fn incr<'a>(&'a self, key: &'a str, window_secs: u64, now_secs: u64) -> BoxFuture<'a, Option<u64>>;
}

impl WindowCounter for CacheService {
    fn incr<'a>(&'a self, key: &'a str, window_secs: u64, now_secs: u64) -> BoxFuture<'a, Option<u64>> {
        Box::pin(self.incr_window_at(key, window_secs, now_secs))
    }
}

/// Counts in this process only. For tests: a unit without Redis fails open instead.
#[derive(Default)]
pub struct MemoryCounter {
    counts: Mutex<HashMap<String, u64>>,
    /// Answer `None`, as a Redis that is down does.
    pub down: std::sync::atomic::AtomicBool,
}

impl WindowCounter for MemoryCounter {
    fn incr<'a>(&'a self, key: &'a str, window_secs: u64, now_secs: u64) -> BoxFuture<'a, Option<u64>> {
        Box::pin(async move {
            if self.down.load(std::sync::atomic::Ordering::Relaxed) {
                return None;
            }
            let full = crate::cache::window_key("mem", key, window_secs, now_secs);
            let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
            let n = counts.entry(full).or_default();
            *n += 1;
            Some(*n)
        })
    }
}

/// What the limiter decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    /// Over the limit in `enforce` mode: refuse, and say when the window turns.
    Limited { retry_after_secs: u64, limit: u64 },
}

/// One address or CIDR range of `exempt_ips`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Net {
    addr: IpAddr,
    prefix: u8,
}

impl Net {
    fn parse(entry: &str) -> Option<Net> {
        let (addr, prefix) = match entry.trim().split_once('/') {
            Some((a, p)) => (a, Some(p.trim().parse::<u8>().ok()?)),
            None => (entry, None),
        };
        let addr = canonical(addr.trim().trim_start_matches('[').trim_end_matches(']').parse().ok()?);
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(max);
        (prefix <= max).then_some(Net { addr, prefix })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(n), IpAddr::V4(i)) => masked(u32::from(n) as u128, 32, self.prefix) == masked(u32::from(i) as u128, 32, self.prefix),
            (IpAddr::V6(n), IpAddr::V6(i)) => masked(u128::from(n), 128, self.prefix) == masked(u128::from(i), 128, self.prefix),
            _ => false,
        }
    }
}

/// The first `prefix` of `width` bits of `v`.
fn masked(v: u128, width: u32, prefix: u8) -> u128 {
    if prefix == 0 {
        return 0;
    }
    v >> (width - prefix as u32)
}

/// An IPv4 address written as IPv6 (`::ffff:10.0.0.1`) is that IPv4 address.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

/// The address as a caller sent it (plain, or IPv6 in brackets), read; `None` when it does not.
pub fn parse_ip(ip: &str) -> Option<IpAddr> {
    let s = ip.trim();
    let s = s.strip_prefix('[').and_then(|r| r.strip_suffix(']')).unwrap_or(s);
    s.parse::<IpAddr>().ok().map(canonical)
}

/// What the address is counted as: an IPv4 address itself, an IPv6 address its /64.
pub fn counted_as(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            let net = std::net::Ipv6Addr::from(u128::from(v6) & !((1u128 << 64) - 1));
            format!("{net}/64")
        }
    }
}

struct Limiter {
    mode: RateLimitMode,
    per_minute: u64,
    buckets: BTreeMap<String, u64>,
    exempt: Vec<Net>,
    counter: Option<Arc<dyn WindowCounter>>,
}

/// The limiter a unit holds: cheap to clone.
#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Limiter>,
}

impl Default for RateLimiter {
    /// Off: never counts, never refuses.
    fn default() -> Self {
        Self::new(&RateLimitConfig { mode: RateLimitMode::Off, ..Default::default() }, None)
    }
}

fn unix_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or_default()
}

impl RateLimiter {
    /// `counter` is where the counts go; `None` lets everything through, counted as `failopen`.
    pub fn new(cfg: &RateLimitConfig, counter: Option<Arc<dyn WindowCounter>>) -> Self {
        let exempt = cfg
            .exempt_ips
            .iter()
            .flat_map(|e| e.split([',', ' ']))
            .filter(|e| !e.trim().is_empty())
            .filter_map(|e| {
                let net = Net::parse(e);
                if net.is_none() {
                    tracing::warn!(entry = e, "[ratelimit] exempt_ips: not an IP address or CIDR range, skipped");
                }
                net
            })
            .collect();
        Self {
            inner: Arc::new(Limiter {
                mode: cfg.mode,
                per_minute: cfg.anonymous_per_minute,
                buckets: cfg.buckets.clone(),
                exempt,
                counter,
            }),
        }
    }

    /// The unit's limiter, counting in its Redis.
    pub fn configured(cfg: &RateLimitConfig, cache: &CacheService) -> Self {
        let limiter = Self::new(cfg, Some(Arc::new(cache.clone())));
        tracing::info!(mode = ?cfg.mode, anonymous_per_minute = cfg.anonymous_per_minute, buckets = ?cfg.buckets, exempt = cfg.exempt_ips.len(), "rate limit for callers not signed in");
        limiter
    }

    pub fn mode(&self) -> RateLimitMode {
        self.inner.mode
    }

    /// The limit a minute of `bucket`; `0` is none.
    pub fn limit(&self, bucket: &str) -> u64 {
        self.inner.buckets.get(bucket).copied().unwrap_or(self.inner.per_minute)
    }

    /// Counts one call from `ip` (as the caller's headers gave it; empty when unknown) in
    /// `bucket`, now.
    pub async fn check(&self, bucket: &str, ip: &str) -> Verdict {
        self.check_at(bucket, ip, unix_secs()).await
    }

    /// [`RateLimiter::check`] at `now_secs` (Unix seconds).
    pub async fn check_at(&self, bucket: &str, ip: &str, now_secs: u64) -> Verdict {
        let l = &self.inner;
        if l.mode == RateLimitMode::Off {
            return Verdict::Allow;
        }
        let parsed = parse_ip(ip);
        let (bucket, who) = match parsed {
            Some(a) => (bucket.to_string(), counted_as(a)),
            None => (format!("{bucket}-noip"), "none".to_string()),
        };
        let count = |outcome: &'static str| {
            metrics::counter!(RATELIMIT_TOTAL, "bucket" => bucket.clone(), "outcome" => outcome).increment(1);
        };
        if parsed.is_some_and(|a| l.exempt.iter().any(|n| n.contains(a))) {
            count("exempt");
            return Verdict::Allow;
        }
        let limit = self.limit(&bucket);
        if limit == 0 {
            count("allowed");
            return Verdict::Allow;
        }
        let key = format!("rl:{bucket}:{who}");
        let Some(n) = (match &l.counter {
            Some(c) => c.incr(&key, WINDOW_SECS, now_secs).await,
            None => None,
        }) else {
            count("failopen");
            return Verdict::Allow;
        };
        if parsed.is_none() && n == 1 {
            tracing::info!(bucket = %bucket, raw = ip, "a caller not signed in whose address is unknown: counted with every such caller");
        }
        if n <= limit {
            count("allowed");
            return Verdict::Allow;
        }
        let retry_after_secs = WINDOW_SECS - now_secs % WINDOW_SECS;
        if n == limit + 1 {
            // Once a window per address.
            tracing::warn!(bucket = %bucket, ip = %who, limit, mode = ?l.mode, retry_after_secs, "rate limit reached for a caller not signed in");
        }
        if l.mode == RateLimitMode::Report {
            count("reported");
            return Verdict::Allow;
        }
        count("limited");
        Verdict::Limited { retry_after_secs, limit }
    }
}

/// The refusal as a coded error: 429 [`TOO_MANY_REQUESTS`] naming `retryAfterSeconds`; the
/// unit's catalogue must hold core's texts. Answer it with [`retry_after`] on the response.
pub fn refusal(retry_after_secs: u64, limit: u64) -> Coded {
    Coded::new(TOO_MANY_REQUESTS)
        .status(http::StatusCode::TOO_MANY_REQUESTS)
        .param("retryAfterSeconds", retry_after_secs)
        .debug(format!("More than {limit} calls a minute from one address without signing in"))
}

/// Adds `Retry-After: <secs>` to a refusal.
pub fn retry_after(resp: &mut axum::response::Response, retry_after_secs: u64) {
    resp.headers_mut().insert(http::header::RETRY_AFTER, http::HeaderValue::from(retry_after_secs));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter(cfg: RateLimitConfig) -> (RateLimiter, Arc<MemoryCounter>) {
        let counter = Arc::new(MemoryCounter::default());
        (RateLimiter::new(&cfg, Some(counter.clone() as Arc<dyn WindowCounter>)), counter)
    }

    fn cfg(per_minute: u64) -> RateLimitConfig {
        RateLimitConfig { anonymous_per_minute: per_minute, ..Default::default() }
    }

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(f)
    }

    #[test]
    fn defaults_enforce_600_a_minute() {
        let c = RateLimitConfig::default();
        assert_eq!((c.mode, c.anonymous_per_minute), (RateLimitMode::Enforce, 600));
        assert!(c.buckets.is_empty() && c.exempt_ips.is_empty());
        let parsed: RateLimitConfig = toml::from_str("mode = \"report\"\nexempt_ips = [\"10.0.0.0/8\"]\n[buckets]\nanon-noip = 50\n").unwrap();
        assert_eq!(parsed.mode, RateLimitMode::Report);
        assert_eq!(parsed.anonymous_per_minute, 600, "unset keys keep their defaults");
        assert_eq!(parsed.buckets.get("anon-noip"), Some(&50));
        let off: RateLimitConfig = toml::from_str("mode = \"off\"").unwrap();
        assert_eq!(off.mode, RateLimitMode::Off);
    }

    #[test]
    fn counts_per_address_and_window() {
        block_on(async {
            let (l, _) = limiter(cfg(3));
            let t = 1_000_000_040; // 20 s into a minute
            for _ in 0..3 {
                assert_eq!(l.check_at(ANON, "1.2.3.4", t).await, Verdict::Allow);
            }
            assert_eq!(l.check_at(ANON, "1.2.3.4", t + 1).await, Verdict::Limited { retry_after_secs: 39, limit: 3 });
            assert_eq!(l.check_at(ANON, "5.6.7.8", t).await, Verdict::Allow, "another address has its own budget");
            assert_eq!(l.check_at("other", "1.2.3.4", t).await, Verdict::Allow, "another bucket has its own budget");
            assert_eq!(l.check_at(ANON, "1.2.3.4", t + 40).await, Verdict::Allow, "the next minute starts again");
        });
    }

    #[test]
    fn one_budget_for_the_same_address_however_written() {
        block_on(async {
            let (l, _) = limiter(cfg(2));
            let t = 1_000_000_000;
            assert_eq!(l.check_at(ANON, "1.2.3.4", t).await, Verdict::Allow);
            assert_eq!(l.check_at(ANON, " ::ffff:1.2.3.4 ", t).await, Verdict::Allow);
            assert!(matches!(l.check_at(ANON, "[::ffff:1.2.3.4]", t).await, Verdict::Limited { .. }));
            // One /64 for IPv6.
            assert_eq!(l.check_at(ANON, "2001:db8:1:2::1", t).await, Verdict::Allow);
            assert_eq!(l.check_at(ANON, "2001:db8:1:2:ffff::9", t).await, Verdict::Allow);
            assert!(matches!(l.check_at(ANON, "2001:db8:1:2::7", t).await, Verdict::Limited { .. }));
            assert_eq!(l.check_at(ANON, "2001:db8:1:3::1", t).await, Verdict::Allow);
        });
        assert_eq!(counted_as("2001:db8:1:2:3:4:5:6".parse().unwrap()), "2001:db8:1:2::/64");
        assert_eq!(counted_as("10.1.2.3".parse().unwrap()), "10.1.2.3");
    }

    #[test]
    fn unknown_addresses_share_the_noip_bucket() {
        let ((), text) = crate::meter::capture(|| {
            block_on(async {
                let mut c = cfg(100);
                c.buckets.insert("anon-noip".into(), 2);
                let (l, _) = limiter(c);
                let t = 1_000_000_000;
                assert_eq!(l.check_at(ANON, "", t).await, Verdict::Allow);
                assert_eq!(l.check_at(ANON, "not-an-ip", t).await, Verdict::Allow);
                assert!(matches!(l.check_at(ANON, "", t).await, Verdict::Limited { limit: 2, .. }));
                assert_eq!(l.check_at(ANON, "9.9.9.9", t).await, Verdict::Allow);
            })
        });
        let n = |bucket: &str, outcome: &str| crate::meter::sample(&text, RATELIMIT_TOTAL, &[("bucket", bucket), ("outcome", outcome)]);
        assert_eq!((n("anon-noip", "allowed"), n("anon-noip", "limited"), n("anon", "allowed")), (Some(2.0), Some(1.0), Some(1.0)), "{text}");
    }

    #[test]
    fn fails_open_without_a_count() {
        let ((), text) = crate::meter::capture(|| {
            block_on(async {
                let (l, counter) = limiter(cfg(1));
                counter.down.store(true, std::sync::atomic::Ordering::Relaxed);
                for _ in 0..5 {
                    assert_eq!(l.check_at(ANON, "1.2.3.4", 1_000_000_000).await, Verdict::Allow);
                }
                let none = RateLimiter::new(&cfg(1), None);
                assert_eq!(none.check_at(ANON, "1.2.3.4", 1_000_000_000).await, Verdict::Allow);
                assert_eq!(none.check_at(ANON, "1.2.3.4", 1_000_000_000).await, Verdict::Allow);
                // A cache service without Redis is the same.
                let cache = CacheService::new("cmn", "evictionChannel", None).unwrap();
                let l = RateLimiter::configured(&cfg(1), &cache);
                assert_eq!(l.check_at(ANON, "1.2.3.4", 1_000_000_000).await, Verdict::Allow);
                assert_eq!(l.check_at(ANON, "1.2.3.4", 1_000_000_000).await, Verdict::Allow);
            })
        });
        assert_eq!(crate::meter::sample(&text, RATELIMIT_TOTAL, &[("bucket", "anon"), ("outcome", "failopen")]), Some(9.0), "{text}");
    }

    #[test]
    fn exempt_addresses_and_ranges_are_never_limited() {
        block_on(async {
            let mut c = cfg(1);
            c.exempt_ips = vec!["203.0.113.7".into(), "10.0.0.0/8, 2001:db8::/32".into(), "junk".into()];
            let (l, _) = limiter(c);
            let t = 1_000_000_000;
            for ip in ["203.0.113.7", "10.200.1.1", "::ffff:10.0.0.1", "2001:db8:ffff::1"] {
                for _ in 0..3 {
                    assert_eq!(l.check_at(ANON, ip, t).await, Verdict::Allow, "{ip}");
                }
            }
            assert_eq!(l.check_at(ANON, "203.0.113.8", t).await, Verdict::Allow);
            assert!(matches!(l.check_at(ANON, "203.0.113.8", t).await, Verdict::Limited { .. }));
        });
    }

    #[test]
    fn report_mode_lets_through_and_off_does_not_count() {
        let ((), text) = crate::meter::capture(|| {
            block_on(async {
                let (l, _) = limiter(RateLimitConfig { mode: RateLimitMode::Report, ..cfg(1) });
                assert_eq!(l.check_at(ANON, "1.2.3.4", 1_000_000_000).await, Verdict::Allow);
                assert_eq!(l.check_at(ANON, "1.2.3.4", 1_000_000_000).await, Verdict::Allow);
                let (off, counter) = limiter(RateLimitConfig { mode: RateLimitMode::Off, ..cfg(1) });
                assert_eq!(off.check_at(ANON, "1.2.3.4", 1_000_000_000).await, Verdict::Allow);
                assert!(counter.counts.lock().unwrap().is_empty());
                assert_eq!(RateLimiter::default().check_at(ANON, "1.2.3.4", 0).await, Verdict::Allow);
            })
        });
        let n = |outcome: &str| crate::meter::sample(&text, RATELIMIT_TOTAL, &[("bucket", "anon"), ("outcome", outcome)]);
        assert_eq!((n("allowed"), n("reported"), n("limited")), (Some(1.0), Some(1.0), None), "{text}");
    }

    #[test]
    fn a_zero_bucket_limit_is_unlimited() {
        block_on(async {
            let mut c = cfg(1);
            c.buckets.insert(ANON.into(), 0);
            let (l, _) = limiter(c);
            for _ in 0..5 {
                assert_eq!(l.check_at(ANON, "1.2.3.4", 1_000_000_000).await, Verdict::Allow);
            }
        });
    }

    #[test]
    fn the_refusal_names_when_to_retry() {
        let c = refusal(17, 600);
        assert_eq!(c.code, TOO_MANY_REQUESTS);
        assert_eq!(c.resolved_status(), http::StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(c.params, vec![("retryAfterSeconds".to_string(), "17".to_string())]);
        let mut resp = axum::response::IntoResponse::into_response(http::StatusCode::TOO_MANY_REQUESTS);
        retry_after(&mut resp, 17);
        assert_eq!(resp.headers()[http::header::RETRY_AFTER], "17");
    }
}
