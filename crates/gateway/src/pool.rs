//! Pools of upstream instances: who they are, which are healthy, and who gets the next request.
//!
//! An instance leaves the rotation when:
//! - its health checks fail `unhealthy_after` times in a row, or a connection to it cannot be
//!   opened: back at its first passing health check;
//! - it gives `outlier.consecutive_5xx` gateway failures in a row (502/503/504, a broken
//!   connection, a timeout): ejected for `base_ejection_ms` times the number of times it has
//!   been ejected, at most `max_ejection_ms`, and back at the first passing health check after
//!   that. At most `max_ejection_percent` of the pool is ejected this way at once.
//!
//! When no instance is left, all of them get traffic anyway (panic mode): a wrong health path
//! or an eager ejection must not black-hole a service that is actually up.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use parking_lot::{Mutex, RwLock};
use platform::registry::Registry;

use crate::breaker::Breaker;
use crate::budget::RetryBudget;
use crate::config::PoolConfig;

/// Empty instance lists from the registry in a row before a pool believes one: a registry that
/// restarted, or lost its peers, answers empty for a while.
const EMPTY_LISTINGS_TO_TRUST: u32 = 3;

#[derive(Debug)]
pub struct Member {
    /// `http://host:port`, no trailing slash.
    pub base: String,
    /// `host:port`, for the forwarded `Host` header.
    pub authority: String,
    healthy: AtomicBool,
    failures: AtomicU32,
    /// Gateway failures in a row (502/503/504, a broken connection, a timeout).
    consecutive_5xx: AtomicU32,
    /// Ejected after a run of gateway failures: out until `ejected_until` and a passing check.
    ejected: AtomicBool,
    /// Milliseconds since the pool started.
    ejected_until: AtomicU64,
    times_ejected: AtomicU32,
}

impl Member {
    fn new(base: &str) -> Self {
        let base = base.trim_end_matches('/').to_string();
        let authority = base
            .split_once("://")
            .map(|(_, rest)| rest)
            .unwrap_or(&base)
            .split('/')
            .next()
            .unwrap_or("")
            .to_string();
        Self {
            base,
            authority,
            healthy: AtomicBool::new(true),
            failures: AtomicU32::new(0),
            consecutive_5xx: AtomicU32::new(0),
            ejected: AtomicBool::new(false),
            ejected_until: AtomicU64::new(0),
            times_ejected: AtomicU32::new(0),
        }
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    pub fn is_ejected(&self) -> bool {
        self.ejected.load(Ordering::Relaxed)
    }

    /// Gets traffic outside panic mode.
    pub fn is_available(&self) -> bool {
        self.is_healthy() && !self.is_ejected()
    }
}

enum Source {
    Static(Vec<String>),
    Registry { registry: Registry, app: String },
}

pub struct Pool {
    pub name: String,
    source: Source,
    members: RwLock<Vec<Arc<Member>>>,
    next: AtomicUsize,
    cfg: PoolConfig,
    start: Instant,
    /// Health checks, regular and at the end of an ejection.
    http: reqwest::Client,
    /// One ejection decision at a time, so the cap holds when several instances fail together.
    ejecting: Mutex<()>,
    empty_listings: AtomicU32,
    pub breaker: Breaker,
    pub budget: RetryBudget,
}

/// Whether an upstream entry is Lighthouse (the registry and config server): its name, an
/// instance name, its ports, or its registry app. No pool may point there (Kiran, 2026-10-19:
/// nothing of Lighthouse is reachable from outside through the gateway).
pub fn is_lighthouse(entry: &str) -> bool {
    let e = entry.trim().to_ascii_lowercase();
    if let Some(app) = platform::upstream::registry_app(&e) {
        return app == "lighthouse";
    }
    let authority = e.split("://").nth(1).unwrap_or(&e).split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().ok()),
        None => (authority, None),
    };
    host == "lighthouse" || host.starts_with("lighthouse-") || matches!(port, Some(8761 | 8762))
}

impl Pool {
    pub fn new(name: &str, cfg: &PoolConfig, registry: Option<&Registry>) -> Result<Arc<Self>> {
        let entries = cfg.upstreams.entries();
        if let Some(bad) = entries.iter().find(|e| is_lighthouse(e)) {
            anyhow::bail!("pool {name} points at Lighthouse ({bad}): the gateway never exposes the registry or its config");
        }
        let source = match entries.as_slice() {
            [one] if platform::upstream::registry_app(one).is_some() => {
                let app = platform::upstream::registry_app(one).unwrap_or_default().to_ascii_uppercase();
                let Some(registry) = registry else {
                    anyhow::bail!("pool {name} uses {one} but [registry] zones are not configured");
                };
                registry.watch(&app);
                Source::Registry { registry: registry.clone(), app }
            }
            [] => anyhow::bail!("pool {name} has no upstreams"),
            list => Source::Static(list.to_vec()),
        };
        let members = match &source {
            Source::Static(list) => list.iter().map(|b| Arc::new(Member::new(b))).collect(),
            Source::Registry { .. } => Vec::new(),
        };
        register_metrics(name);
        Ok(Arc::new(Self {
            name: name.to_string(),
            source,
            members: RwLock::new(members),
            next: AtomicUsize::new(0),
            cfg: cfg.clone(),
            start: Instant::now(),
            http: reqwest::Client::builder().timeout(Duration::from_secs(2)).build()?,
            ejecting: Mutex::new(()),
            empty_listings: AtomicU32::new(0),
            breaker: Breaker::new(name, &cfg.breaker),
            budget: RetryBudget::new(name, &cfg.retry),
        }))
    }

    pub fn config(&self) -> &PoolConfig {
        &self.cfg
    }

    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    /// The next instance, round robin over available ones, skipping `avoid`. When none is
    /// available, the others are tried anyway (panic mode), and `avoid` itself as a last resort.
    pub fn pick(&self, avoid: Option<&str>) -> Option<Arc<Member>> {
        let members = self.members.read();
        if members.is_empty() {
            return None;
        }
        let candidates: Vec<&Arc<Member>> = {
            let available: Vec<&Arc<Member>> = members
                .iter()
                .filter(|m| m.is_available() && Some(m.base.as_str()) != avoid)
                .collect();
            if !available.is_empty() {
                available
            } else {
                let others: Vec<&Arc<Member>> =
                    members.iter().filter(|m| Some(m.base.as_str()) != avoid).collect();
                if others.is_empty() { members.iter().collect() } else { others }
            }
        };
        let i = self.next.fetch_add(1, Ordering::Relaxed);
        Some(candidates[i % candidates.len()].clone())
    }

    /// A connection to this instance failed: out of rotation until a health check passes.
    pub fn eject(&self, member: &Member) {
        member.failures.store(self.cfg.unhealthy_after, Ordering::Relaxed);
        if member.healthy.swap(false, Ordering::Relaxed) {
            metrics::counter!("gateway_pool_ejections_total", "pool" => self.name.clone(), "reason" => "connect").increment(1);
            tracing::warn!(pool = self.name, upstream = member.base, "instance ejected after a connect failure");
        }
    }

    /// The instance answered with something other than a gateway failure.
    pub fn passed(&self, member: &Member) {
        if member.consecutive_5xx.load(Ordering::Relaxed) != 0 {
            member.consecutive_5xx.store(0, Ordering::Relaxed);
        }
    }

    /// The instance answered 502/503/504, broke the connection or timed out.
    pub fn failed(self: &Arc<Self>, member: &Arc<Member>) {
        let threshold = self.cfg.outlier.consecutive_5xx;
        if threshold == 0 {
            return;
        }
        let n = member.consecutive_5xx.fetch_add(1, Ordering::Relaxed) + 1;
        if n >= threshold && !member.is_ejected() {
            self.eject_outlier(member, n);
        }
    }

    fn eject_outlier(self: &Arc<Self>, member: &Arc<Member>, in_a_row: u32) {
        let _one_at_a_time = self.ejecting.lock();
        if member.is_ejected() {
            return;
        }
        let (total, ejected) = {
            let members = self.members.read();
            (members.len(), members.iter().filter(|m| m.is_ejected()).count())
        };
        let cap = total * self.cfg.outlier.max_ejection_percent as usize / 100;
        if ejected + 1 > cap {
            tracing::debug!(pool = self.name, upstream = member.base, ejected, total, "not ejected: the pool is at its ejection cap");
            return;
        }
        let times = member.times_ejected.fetch_add(1, Ordering::Relaxed) + 1;
        let o = &self.cfg.outlier;
        let ms = o.base_ejection_ms.saturating_mul(u64::from(times)).min(o.max_ejection_ms.max(o.base_ejection_ms));
        member.ejected_until.store(self.now_ms() + ms, Ordering::Relaxed);
        member.ejected.store(true, Ordering::Relaxed);
        member.consecutive_5xx.store(0, Ordering::Relaxed);
        metrics::counter!("gateway_pool_ejections_total", "pool" => self.name.clone(), "reason" => "5xx").increment(1);
        self.ejected_gauge();
        tracing::warn!(pool = self.name, upstream = member.base, in_a_row, times, ejection_ms = ms, "instance ejected after gateway failures");

        // Checked again as soon as its time is up, not at the next regular check.
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            let (this, member) = (self.clone(), member.clone());
            rt.spawn(async move {
                tokio::time::sleep(Duration::from_millis(ms)).await;
                this.check_member(&member).await;
            });
        }
    }

    pub fn healthy_count(&self) -> usize {
        self.members.read().iter().filter(|m| m.is_healthy()).count()
    }

    fn ejected_gauge(&self) {
        let n = self.members.read().iter().filter(|m| m.is_ejected()).count();
        metrics::gauge!("gateway_pool_ejected_instances", "pool" => self.name.clone()).set(n as f64);
    }

    /// Takes in a list of base URLs from the registry. `fresh` when it was just fetched: only
    /// fresh answers can empty the pool, and only once seen several times in a row.
    fn apply_listing(&self, bases: Vec<String>, fresh: bool) {
        let mut members = self.members.write();
        if bases.is_empty() && !members.is_empty() {
            let seen = if fresh { self.empty_listings.fetch_add(1, Ordering::Relaxed) + 1 } else { 0 };
            if seen < EMPTY_LISTINGS_TO_TRUST {
                if fresh {
                    tracing::warn!(pool = self.name, seen, "the registry lists no instance, keeping the last list");
                }
                return;
            }
        } else {
            self.empty_listings.store(0, Ordering::Relaxed);
        }
        let current: Vec<String> = members.iter().map(|m| m.base.clone()).collect();
        if current != bases {
            // Keep the state of instances that stay.
            let next: Vec<Arc<Member>> = bases
                .iter()
                .map(|b| {
                    members
                        .iter()
                        .find(|m| &m.base == b)
                        .cloned()
                        .unwrap_or_else(|| Arc::new(Member::new(b)))
                })
                .collect();
            tracing::info!(pool = self.name, instances = ?bases, "pool membership changed");
            *members = next;
        }
    }

    /// Membership from the registry's last answer.
    async fn refresh_members(&self) {
        let Source::Registry { registry, app } = &self.source else { return };
        match registry.instances(app).await {
            Ok(bases) => self.apply_listing(bases, false),
            Err(e) => tracing::warn!(pool = self.name, error = %e, "lighthouse lookup failed, keeping members"),
        }
    }

    /// Asks the registry again now.
    async fn discover(&self) {
        let Source::Registry { registry, app } = &self.source else { return };
        match registry.refresh(app).await {
            Ok(()) => match registry.instances(app).await {
                Ok(bases) => self.apply_listing(bases, true),
                Err(e) => tracing::warn!(pool = self.name, error = %e, "lighthouse lookup failed, keeping members"),
            },
            Err(e) => tracing::warn!(pool = self.name, error = %e, "lighthouse lookup failed, keeping members"),
        }
    }

    async fn check_member(&self, m: &Member) {
        let url = format!("{}{}", m.base, self.cfg.health_path);
        let ok = matches!(self.http.get(&url).send().await, Ok(r) if r.status().is_success());
        if ok {
            m.failures.store(0, Ordering::Relaxed);
            if !m.healthy.swap(true, Ordering::Relaxed) {
                tracing::info!(pool = self.name, upstream = m.base, "instance healthy again");
            }
            if m.is_ejected() && self.now_ms() >= m.ejected_until.load(Ordering::Relaxed) {
                m.consecutive_5xx.store(0, Ordering::Relaxed);
                m.ejected.store(false, Ordering::Relaxed);
                self.ejected_gauge();
                tracing::info!(pool = self.name, upstream = m.base, "instance back after its ejection");
            }
        } else {
            let f = m.failures.fetch_add(1, Ordering::Relaxed) + 1;
            if f >= self.cfg.unhealthy_after && m.healthy.swap(false, Ordering::Relaxed) {
                tracing::warn!(pool = self.name, upstream = m.base, "instance failed its health checks");
            }
        }
    }

    async fn check(&self) {
        self.refresh_members().await;
        let members: Vec<Arc<Member>> = self.members.read().clone();
        for m in members {
            self.check_member(&m).await;
        }
        metrics::gauge!("gateway_pool_healthy_instances", "pool" => self.name.clone())
            .set(self.healthy_count() as f64);
    }

    /// Health checks on the pool's interval and, for a registry pool, the membership refresh,
    /// for the life of the process.
    pub fn spawn_background(self: &Arc<Self>) {
        let this = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(this.cfg.health_interval_seconds.max(1)));
            loop {
                tick.tick().await;
                this.check().await;
            }
        });
        if matches!(self.source, Source::Registry { .. }) {
            let this = self.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_millis(this.cfg.discovery_refresh_ms.max(100)));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    tick.tick().await;
                    this.discover().await;
                }
            });
        }
    }
}

/// Every series of a pool exists from the start, at zero, so dashboards and alerts see it
/// before the first incident.
fn register_metrics(pool: &str) {
    let p = pool.to_string();
    for reason in ["connect", "5xx"] {
        metrics::counter!("gateway_retries_total", "pool" => p.clone(), "reason" => reason).increment(0);
        metrics::counter!("gateway_pool_ejections_total", "pool" => p.clone(), "reason" => reason).increment(0);
    }
    metrics::counter!("gateway_retry_budget_exhausted_total", "pool" => p.clone()).increment(0);
    metrics::counter!("gateway_pool_breaker_rejections_total", "pool" => p.clone()).increment(0);
    metrics::gauge!("gateway_pool_ejected_instances", "pool" => p).set(0.0);
}

#[cfg(test)]
mod tests {
    #[test]
    fn no_pool_may_point_at_lighthouse() {
        for e in ["http://lighthouse:8761", "http://LIGHTHOUSE-1:8761/", "http://lighthouse-2:8761", "http://localhost:8761",
                  "http://127.0.0.1:8762/eureka", "lighthouse:LIGHTHOUSE", "http://u:p@lighthouse:80"] {
            assert!(is_lighthouse(e), "{e}");
            let cfg = PoolConfig { upstreams: UpstreamConfig::One(e.into()), ..Default::default() };
            let err = Pool::new("x", &cfg, None).err().expect("refused").to_string();
            assert!(err.contains("points at Lighthouse"), "{err}");
        }
        for e in ["http://security-auth:8101", "http://lighthouses:80", "http://ai:5001", "lighthouse:SECURITY-AUTH", "http://localhost:87610"] {
            assert!(!is_lighthouse(e), "{e}");
        }
    }

    use super::*;
    use platform::config::UpstreamConfig;

    fn pool(urls: &[&str]) -> Arc<Pool> {
        let cfg = PoolConfig {
            upstreams: UpstreamConfig::Many(urls.iter().map(|s| s.to_string()).collect()),
            ..Default::default()
        };
        Pool::new("p", &cfg, None).unwrap()
    }

    #[test]
    fn round_robin_skips_unhealthy_and_avoided() {
        let p = pool(&["http://a:1", "http://b:2", "http://c:3"]);
        let picks: Vec<String> = (0..3).map(|_| p.pick(None).unwrap().base.clone()).collect();
        assert_eq!(picks, vec!["http://a:1", "http://b:2", "http://c:3"]);

        let b = p.members.read()[1].clone();
        p.eject(&b);
        for _ in 0..6 {
            assert_ne!(p.pick(None).unwrap().base, "http://b:2");
        }
        for _ in 0..6 {
            let m = p.pick(Some("http://a:1")).unwrap();
            assert_eq!(m.base, "http://c:3");
        }
    }

    #[test]
    fn all_down_still_routes() {
        let p = pool(&["http://a:1", "http://b:2"]);
        for m in p.members.read().clone() {
            p.eject(&m);
        }
        assert!(p.pick(None).is_some());
        assert_eq!(p.pick(Some("http://a:1")).unwrap().base, "http://b:2");
    }

    #[tokio::test]
    async fn registry_membership_and_health_transitions() {
        use axum::extract::State;
        use axum::routing::get;
        use std::sync::atomic::AtomicBool;

        // One upstream whose health we flip, and a fake Lighthouse listing it plus a dead one.
        let healthy = Arc::new(AtomicBool::new(true));
        let up = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_port = up.local_addr().unwrap().port();
        let h = healthy.clone();
        let health_app = axum::Router::new()
            .route(
                "/health",
                get(|State(h): State<Arc<AtomicBool>>| async move {
                    if h.load(Ordering::SeqCst) {
                        axum::http::StatusCode::OK
                    } else {
                        axum::http::StatusCode::SERVICE_UNAVAILABLE
                    }
                }),
            )
            .with_state(h);
        tokio::spawn(async move { axum::serve(up, health_app).await.unwrap() });

        let listing = Arc::new(parking_lot::RwLock::new(vec![up_port]));
        let ek = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ek_base = format!("http://{}/eureka/", ek.local_addr().unwrap());
        let l = listing.clone();
        let registry_app = axum::Router::new()
            .route(
                "/eureka/apps/{app}",
                get(|State(l): State<Arc<parking_lot::RwLock<Vec<u16>>>>| async move {
                    let inst: Vec<serde_json::Value> = l
                        .read()
                        .iter()
                        .map(|p| serde_json::json!({"ipAddr": "127.0.0.1", "port": {"$": p}, "status": "UP"}))
                        .collect();
                    axum::Json(serde_json::json!({"application": {"instance": inst}}))
                }),
            )
            .with_state(l);
        tokio::spawn(async move { axum::serve(ek, registry_app).await.unwrap() });

        let registry = Registry::new(
            &platform::config::RegistryConfig { zones: vec![ek_base], ..Default::default() },
            0,
        )
        .unwrap();
        let cfg = PoolConfig {
            upstreams: UpstreamConfig::One("lighthouse:SVC".into()),
            health_path: "/health".into(),
            unhealthy_after: 2,
            ..Default::default()
        };
        let p = Pool::new("svc", &cfg, Some(&registry)).unwrap();
        assert!(p.pick(None).is_none(), "no members before the first refresh");

        p.check().await;
        assert_eq!(p.healthy_count(), 1);
        assert_eq!(p.pick(None).unwrap().base, format!("http://127.0.0.1:{up_port}"));

        healthy.store(false, Ordering::SeqCst);
        p.check().await;
        assert_eq!(p.healthy_count(), 1, "one failure is not enough");
        p.check().await;
        assert_eq!(p.healthy_count(), 0);
        healthy.store(true, Ordering::SeqCst);
        p.check().await;
        assert_eq!(p.healthy_count(), 1, "back after one good check");

        // A second instance appears; the first keeps its state.
        listing.write().push(1);
        registry.refresh("SVC").await.unwrap();
        p.check().await;
        assert_eq!(p.members.read().len(), 2);
        assert_eq!(p.healthy_count(), 2, "a new instance starts healthy, as Lighthouse lists it UP");
        p.check().await;
        assert_eq!(p.healthy_count(), 1, "the dead one is out after its second failed check");

        // Lighthouse unreachable: members kept.
        let lost = Registry::new(
            &platform::config::RegistryConfig { zones: vec!["http://127.0.0.1:1/eureka/".into()], ..Default::default() },
            0,
        )
        .unwrap();
        let p2 = Pool::new("svc2", &cfg, Some(&lost)).unwrap();
        p2.check().await;
        assert!(p2.pick(None).is_none());

        // Without lighthouse configured, an lighthouse pool is refused; an empty static pool too.
        assert!(Pool::new("x", &cfg, None).is_err());
        let empty = PoolConfig { upstreams: UpstreamConfig::Many(vec![]), ..Default::default() };
        assert!(Pool::new("x", &empty, None).is_err());
    }

    #[test]
    fn authority() {
        assert_eq!(Member::new("http://10.0.0.1:8003/").authority, "10.0.0.1:8003");
    }

    /// A health endpoint whose answer the test flips.
    async fn health_server() -> (String, Arc<AtomicBool>) {
        use axum::extract::State;
        let up = Arc::new(AtomicBool::new(true));
        let app = axum::Router::new()
            .route(
                "/health",
                axum::routing::get(|State(up): State<Arc<AtomicBool>>| async move {
                    if up.load(Ordering::SeqCst) {
                        axum::http::StatusCode::OK
                    } else {
                        axum::http::StatusCode::SERVICE_UNAVAILABLE
                    }
                }),
            )
            .with_state(up.clone());
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (base, up)
    }

    fn outlier_pool(urls: &[&str], base_ms: u64, max_ms: u64) -> Arc<Pool> {
        let cfg = PoolConfig {
            upstreams: UpstreamConfig::Many(urls.iter().map(|s| s.to_string()).collect()),
            health_path: "/health".into(),
            outlier: crate::config::OutlierConfig { base_ejection_ms: base_ms, max_ejection_ms: max_ms, ..Default::default() },
            ..Default::default()
        };
        Pool::new("p", &cfg, None).unwrap()
    }

    fn fail(p: &Arc<Pool>, m: &Arc<Member>, n: u32) {
        for _ in 0..n {
            p.failed(m);
        }
    }

    fn left_ms(p: &Pool, m: &Member) -> u64 {
        m.ejected_until.load(Ordering::Relaxed).saturating_sub(p.now_ms())
    }

    #[tokio::test]
    async fn outlier_ejection_grows_and_ends_with_a_passing_check() {
        let (srv, up) = health_server().await;
        let p = outlier_pool(&[&srv, "http://127.0.0.1:1"], 200, 500);
        let m = p.members.read()[0].clone();

        // Four in a row, then a good answer: the run starts over.
        fail(&p, &m, 4);
        p.passed(&m);
        fail(&p, &m, 4);
        assert!(!m.is_ejected());
        p.failed(&m);
        assert!(m.is_ejected());
        assert!((150..=200).contains(&left_ms(&p, &m)));
        for _ in 0..4 {
            assert_ne!(p.pick(None).unwrap().base, srv);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(m.is_ejected(), "still inside its 200 ms");
        // A regular check inside the ejection time does not bring it back.
        p.check().await;
        assert!(m.is_ejected());
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(!m.is_ejected(), "checked as its time ran out, and passed");

        // The second ejection lasts twice as long, the third is capped.
        fail(&p, &m, 5);
        assert!((350..=400).contains(&left_ms(&p, &m)));
        m.ejected_until.store(0, Ordering::Relaxed);
        p.check().await;
        assert!(!m.is_ejected());
        fail(&p, &m, 5);
        assert!((450..=500).contains(&left_ms(&p, &m)), "600 ms capped at 500");

        // A failing check at the end keeps it out until a check passes.
        up.store(false, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert!(m.is_ejected());
        up.store(true, Ordering::SeqCst);
        p.check().await;
        assert!(!m.is_ejected());
    }

    #[tokio::test]
    async fn ejection_cap_and_switch() {
        // Four instances, half may go: the third failing one stays in.
        let p = outlier_pool(&["http://a:1", "http://b:1", "http://c:1", "http://d:1"], 60_000, 60_000);
        let ms: Vec<Arc<Member>> = p.members.read().clone();
        for m in &ms[..3] {
            fail(&p, m, 5);
        }
        assert_eq!(ms.iter().filter(|m| m.is_ejected()).count(), 2);
        assert!(!ms[2].is_ejected());
        fail(&p, &ms[2], 10);
        assert!(!ms[2].is_ejected(), "still at the cap");

        // Everyone out: panic mode routes to them anyway.
        let p = outlier_pool(&["http://a:1", "http://b:1"], 60_000, 60_000);
        let ms: Vec<Arc<Member>> = p.members.read().clone();
        fail(&p, &ms[0], 5);
        p.eject(&ms[1]);
        assert!(ms[0].is_ejected() && !ms[1].is_healthy());
        assert!(p.pick(None).is_some());

        // A pool of one is never ejected this way, and 0 turns ejection off.
        let one = outlier_pool(&["http://a:1"], 60_000, 60_000);
        let m = one.members.read()[0].clone();
        fail(&one, &m, 20);
        assert!(!m.is_ejected());
        let cfg = PoolConfig {
            upstreams: UpstreamConfig::Many(vec!["http://a:1".into(), "http://b:1".into()]),
            outlier: crate::config::OutlierConfig { consecutive_5xx: 0, ..Default::default() },
            ..Default::default()
        };
        let off = Pool::new("off", &cfg, None).unwrap();
        let m = off.members.read()[0].clone();
        fail(&off, &m, 20);
        assert!(!m.is_ejected());
        assert_eq!(off.config().outlier.consecutive_5xx, 0);
    }

    #[test]
    fn ejection_outside_a_runtime_skips_the_return_check() {
        let p = outlier_pool(&["http://a:1", "http://b:1"], 60_000, 60_000);
        let m = p.members.read()[0].clone();
        fail(&p, &m, 5);
        assert!(m.is_ejected());
    }

    #[tokio::test]
    async fn registry_pools_follow_fast_and_distrust_a_lone_empty_list() {
        use axum::extract::State;
        use axum::routing::get;
        type Listing = Arc<parking_lot::RwLock<Vec<u16>>>;
        let listing: Listing = Arc::new(parking_lot::RwLock::new(vec![1001]));
        let app = axum::Router::new()
            .route(
                "/eureka/apps/{app}",
                get(|State(l): State<Listing>| async move {
                    let inst: Vec<serde_json::Value> = l
                        .read()
                        .iter()
                        .map(|p| serde_json::json!({"ipAddr": "127.0.0.1", "port": {"$": p}, "status": "UP"}))
                        .collect();
                    axum::Json(serde_json::json!({"application": {"instance": inst}}))
                }),
            )
            .with_state(listing.clone());
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let zone = format!("http://{}/eureka/", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        let registry = Registry::new(&platform::config::RegistryConfig { zones: vec![zone], ..Default::default() }, 0).unwrap();
        let cfg = PoolConfig {
            upstreams: UpstreamConfig::One("lighthouse:SVC".into()),
            health_interval_seconds: 3600,
            discovery_refresh_ms: 100,
            ..Default::default()
        };
        let p = Pool::new("svc", &cfg, Some(&registry)).unwrap();
        let bases = |p: &Pool| p.members.read().iter().map(|m| m.base.clone()).collect::<Vec<_>>();

        p.discover().await;
        assert_eq!(bases(&p), vec!["http://127.0.0.1:1001"]);
        // Two empty answers are not believed, the third is.
        listing.write().clear();
        p.discover().await;
        p.discover().await;
        p.check().await;
        assert_eq!(bases(&p).len(), 1);
        p.discover().await;
        assert!(bases(&p).is_empty());

        // In the background, a change shows within the refresh interval.
        listing.write().push(1002);
        p.spawn_background();
        let mut seen = false;
        for _ in 0..30 {
            if bases(&p) == vec!["http://127.0.0.1:1002"] {
                seen = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(seen);

        // The registry gone: members kept.
        let gone = Registry::new(
            &platform::config::RegistryConfig { zones: vec!["http://127.0.0.1:1/eureka/".into()], ..Default::default() },
            0,
        )
        .unwrap();
        let p2 = Pool::new("svc2", &cfg, Some(&gone)).unwrap();
        p2.discover().await;
        assert!(bases(&p2).is_empty());
        let s = Pool::new("static", &PoolConfig { upstreams: UpstreamConfig::One("http://a:1".into()), ..Default::default() }, None).unwrap();
        s.discover().await;
        assert_eq!(bases(&s), vec!["http://a:1"]);
    }
}
