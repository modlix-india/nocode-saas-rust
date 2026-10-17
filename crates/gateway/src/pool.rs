//! Pools of upstream instances: who they are, which are healthy, and who gets the next request.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use parking_lot::RwLock;
use platform::eureka::Eureka;

use crate::config::PoolConfig;

#[derive(Debug)]
pub struct Member {
    /// `http://host:port`, no trailing slash.
    pub base: String,
    /// `host:port`, for the forwarded `Host` header.
    pub authority: String,
    healthy: AtomicBool,
    failures: AtomicU32,
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
        Self { base, authority, healthy: AtomicBool::new(true), failures: AtomicU32::new(0) }
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }
}

enum Source {
    Static(Vec<String>),
    Eureka { eureka: Eureka, app: String },
}

pub struct Pool {
    pub name: String,
    source: Source,
    members: RwLock<Vec<Arc<Member>>>,
    next: AtomicUsize,
    cfg: PoolConfig,
}

impl Pool {
    pub fn new(name: &str, cfg: &PoolConfig, eureka: Option<&Eureka>) -> Result<Arc<Self>> {
        let entries = cfg.upstreams.entries();
        let source = match entries.as_slice() {
            [one] if one.starts_with("eureka:") => {
                let app = one["eureka:".len()..].to_ascii_uppercase();
                let Some(eureka) = eureka else {
                    anyhow::bail!("pool {name} uses {one} but [eureka] zones are not configured");
                };
                eureka.watch(&app);
                Source::Eureka { eureka: eureka.clone(), app }
            }
            [] => anyhow::bail!("pool {name} has no upstreams"),
            list => Source::Static(list.to_vec()),
        };
        let members = match &source {
            Source::Static(list) => list.iter().map(|b| Arc::new(Member::new(b))).collect(),
            Source::Eureka { .. } => Vec::new(),
        };
        Ok(Arc::new(Self {
            name: name.to_string(),
            source,
            members: RwLock::new(members),
            next: AtomicUsize::new(0),
            cfg: cfg.clone(),
        }))
    }

    /// The next instance, round robin over healthy ones, skipping `avoid`. When every instance
    /// is marked down, all of them are tried anyway: a wrong health path must not black-hole a
    /// service that is actually up.
    pub fn pick(&self, avoid: Option<&str>) -> Option<Arc<Member>> {
        let members = self.members.read();
        if members.is_empty() {
            return None;
        }
        let candidates: Vec<&Arc<Member>> = {
            let healthy: Vec<&Arc<Member>> = members
                .iter()
                .filter(|m| m.is_healthy() && Some(m.base.as_str()) != avoid)
                .collect();
            if !healthy.is_empty() {
                healthy
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
            tracing::warn!(pool = self.name, upstream = member.base, "instance ejected after a connect failure");
        }
    }

    pub fn healthy_count(&self) -> usize {
        self.members.read().iter().filter(|m| m.is_healthy()).count()
    }

    async fn refresh_members(&self) {
        let Source::Eureka { eureka, app } = &self.source else { return };
        match eureka.instances(app).await {
            Ok(bases) => {
                let mut members = self.members.write();
                let current: Vec<String> = members.iter().map(|m| m.base.clone()).collect();
                if current != bases {
                    // Keep the health state of instances that stay.
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
            Err(e) => tracing::warn!(pool = self.name, error = %e, "eureka lookup failed, keeping members"),
        }
    }

    async fn check(&self, http: &reqwest::Client) {
        self.refresh_members().await;
        let members: Vec<Arc<Member>> = self.members.read().clone();
        for m in members {
            let url = format!("{}{}", m.base, self.cfg.health_path);
            let ok = matches!(http.get(&url).send().await, Ok(r) if r.status().is_success());
            if ok {
                m.failures.store(0, Ordering::Relaxed);
                if !m.healthy.swap(true, Ordering::Relaxed) {
                    tracing::info!(pool = self.name, upstream = m.base, "instance healthy again");
                }
            } else {
                let f = m.failures.fetch_add(1, Ordering::Relaxed) + 1;
                if f >= self.cfg.unhealthy_after && m.healthy.swap(false, Ordering::Relaxed) {
                    tracing::warn!(pool = self.name, upstream = m.base, "instance failed its health checks");
                }
            }
        }
        metrics::gauge!("gateway_pool_healthy_instances", "pool" => self.name.clone())
            .set(self.healthy_count() as f64);
    }

    /// Checks every instance on the pool's interval for the life of the process.
    pub fn spawn_health_checks(self: &Arc<Self>) {
        let this = self.clone();
        tokio::spawn(async move {
            let http = reqwest::Client::builder()
                .timeout(Duration::from_secs(2))
                .build()
                .expect("health check client");
            let mut tick = tokio::time::interval(Duration::from_secs(this.cfg.health_interval_seconds.max(1)));
            loop {
                tick.tick().await;
                this.check(&http).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
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
    async fn eureka_membership_and_health_transitions() {
        use axum::extract::State;
        use axum::routing::get;
        use std::sync::atomic::AtomicBool;

        // One upstream whose health we flip, and a fake Eureka listing it plus a dead one.
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
        let eureka_app = axum::Router::new()
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
        tokio::spawn(async move { axum::serve(ek, eureka_app).await.unwrap() });

        let eureka = Eureka::new(
            &platform::config::EurekaConfig { zones: vec![ek_base], ..Default::default() },
            0,
        )
        .unwrap();
        let cfg = PoolConfig {
            upstreams: UpstreamConfig::One("eureka:SVC".into()),
            health_path: "/health".into(),
            unhealthy_after: 2,
            ..Default::default()
        };
        let p = Pool::new("svc", &cfg, Some(&eureka)).unwrap();
        assert!(p.pick(None).is_none(), "no members before the first refresh");

        let http = reqwest::Client::new();
        p.check(&http).await;
        assert_eq!(p.healthy_count(), 1);
        assert_eq!(p.pick(None).unwrap().base, format!("http://127.0.0.1:{up_port}"));

        healthy.store(false, Ordering::SeqCst);
        p.check(&http).await;
        assert_eq!(p.healthy_count(), 1, "one failure is not enough");
        p.check(&http).await;
        assert_eq!(p.healthy_count(), 0);
        healthy.store(true, Ordering::SeqCst);
        p.check(&http).await;
        assert_eq!(p.healthy_count(), 1, "back after one good check");

        // A second instance appears; the first keeps its state.
        listing.write().push(1);
        eureka.refresh("SVC").await.unwrap();
        p.check(&http).await;
        assert_eq!(p.members.read().len(), 2);
        assert_eq!(p.healthy_count(), 2, "a new instance starts healthy, as Eureka lists it UP");
        p.check(&http).await;
        assert_eq!(p.healthy_count(), 1, "the dead one is out after its second failed check");

        // Eureka unreachable: members kept.
        let lost = Eureka::new(
            &platform::config::EurekaConfig { zones: vec!["http://127.0.0.1:1/eureka/".into()], ..Default::default() },
            0,
        )
        .unwrap();
        let p2 = Pool::new("svc2", &cfg, Some(&lost)).unwrap();
        p2.check(&http).await;
        assert!(p2.pick(None).is_none());

        // Without eureka configured, an eureka pool is refused; an empty static pool too.
        assert!(Pool::new("x", &cfg, None).is_err());
        let empty = PoolConfig { upstreams: UpstreamConfig::Many(vec![]), ..Default::default() };
        assert!(Pool::new("x", &empty, None).is_err());
    }

    #[test]
    fn authority() {
        assert_eq!(Member::new("http://10.0.0.1:8003/").authority, "10.0.0.1:8003");
    }
}
