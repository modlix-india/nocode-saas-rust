//! Where another service is.
//!
//! An [`Upstream`] is either a fixed list of base URLs, used round robin (compose service
//! addresses today, Kubernetes Service names later), or `eureka:<APP>`, which follows the Java
//! registry while Java services are still the ones answering.
//!
//! A fixed list with more than one address is probed every few seconds (a TCP connect: a stopped
//! container refuses it), and addresses that fail are skipped until they answer again. Blue/green
//! deploys keep one colour stopped, so without this half the calls would fail.

use std::net::ToSocketAddrs;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};

use crate::config::UpstreamConfig;
use crate::eureka::Eureka;

/// Accepts the paths a route sends elsewhere.
pub type PathTest = fn(&str) -> bool;

#[derive(Clone)]
pub struct Upstream {
    inner: Arc<Inner>,
    /// Paths sent to another upstream: the first test that accepts a path wins ([`Self::base_for`]).
    routes: Arc<Vec<(PathTest, Upstream)>>,
}

struct Member {
    base: String,
    up: AtomicBool,
}

enum Kind {
    Static(Vec<Member>),
    Eureka { eureka: Eureka, app: String },
}

struct Inner {
    kind: Kind,
    next: AtomicUsize,
}

impl Upstream {
    /// `eureka` is needed only when the configuration names an `eureka:` source.
    pub fn from_config(cfg: &UpstreamConfig, eureka: Option<&Eureka>) -> Result<Self> {
        let entries = cfg.entries();
        if entries.len() == 1 {
            if let Some(app) = entries[0].strip_prefix("eureka:") {
                let Some(eureka) = eureka else {
                    bail!("upstream {} needs [eureka] zones configured", entries[0]);
                };
                eureka.watch(app);
                return Ok(Self::new(Kind::Eureka {
                    eureka: eureka.clone(),
                    app: app.to_ascii_uppercase(),
                }));
            }
        }
        if entries.is_empty() {
            bail!("upstream has no addresses");
        }
        let this = Self::static_list(&entries);
        this.spawn_probes();
        Ok(this)
    }

    pub fn fixed(urls: &[&str]) -> Self {
        let urls: Vec<String> = urls.iter().map(|u| u.to_string()).collect();
        Self::static_list(&urls)
    }

    fn static_list(urls: &[String]) -> Self {
        Self::new(Kind::Static(
            urls.iter()
                .map(|u| Member { base: u.trim_end_matches('/').to_string(), up: AtomicBool::new(true) })
                .collect(),
        ))
    }

    fn new(kind: Kind) -> Self {
        Self { inner: Arc::new(Inner { kind, next: AtomicUsize::new(0) }), routes: Arc::new(Vec::new()) }
    }

    /// This upstream with some paths sent elsewhere (one service split over several units).
    /// [`Self::base`] is unchanged; [`Self::base_for`] picks by path.
    pub fn with_routes(mut self, routes: Vec<(PathTest, Upstream)>) -> Self {
        self.routes = Arc::new(routes);
        self
    }

    /// A base URL for a request to `path` (with or without its query): the first route that
    /// accepts the path, else this upstream's own.
    pub async fn base_for(&self, path: &str) -> Result<String> {
        for (accepts, upstream) in self.routes.iter() {
            if accepts(path) {
                return upstream.base().await;
            }
        }
        self.base().await
    }

    /// A base URL to send the next request to, without a trailing `/`.
    pub async fn base(&self) -> Result<String> {
        match &self.inner.kind {
            Kind::Static(members) => {
                let up: Vec<&Member> = members.iter().filter(|m| m.up.load(Ordering::Relaxed)).collect();
                let pool: Vec<&Member> = if up.is_empty() { members.iter().collect() } else { up };
                let i = self.inner.next.fetch_add(1, Ordering::Relaxed);
                Ok(pool[i % pool.len()].base.clone())
            }
            Kind::Eureka { eureka, app } => eureka.resolve(app).await,
        }
    }

    fn spawn_probes(&self) {
        let Kind::Static(members) = &self.inner.kind else { return };
        if members.len() < 2 {
            return;
        }
        let this = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(5));
            loop {
                tick.tick().await;
                this.probe_once().await;
            }
        });
    }

    async fn probe_once(&self) {
        let Kind::Static(members) = &self.inner.kind else { return };
        for m in members {
            let ok = reachable(&m.base).await;
            if m.up.swap(ok, Ordering::Relaxed) != ok {
                if ok {
                    tracing::info!(upstream = m.base, "upstream reachable again");
                } else {
                    tracing::warn!(upstream = m.base, "upstream unreachable, skipping it");
                }
            }
        }
    }
}

/// Whether a TCP connection to the URL's host and port opens within a second.
async fn reachable(base: &str) -> bool {
    let authority = base.split_once("://").map(|(_, r)| r).unwrap_or(base);
    let authority = authority.split('/').next().unwrap_or(authority).to_string();
    let with_port = if authority.contains(':') { authority } else { format!("{authority}:80") };
    let addrs = tokio::task::spawn_blocking(move || with_port.to_socket_addrs().map(|a| a.collect::<Vec<_>>()))
        .await;
    let Ok(Ok(addrs)) = addrs else { return false };
    let Some(addr) = addrs.into_iter().next() else { return false };
    matches!(
        tokio::time::timeout(Duration::from_secs(1), tokio::net::TcpStream::connect(addr)).await,
        Ok(Ok(_))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn skips_unreachable() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let up = format!("http://127.0.0.1:{port}");
        assert!(reachable(&up).await);
        assert!(!reachable("http://127.0.0.1:1").await);

        let u = Upstream::fixed(&[&up, "http://127.0.0.1:1"]);
        if let Kind::Static(m) = &u.inner.kind {
            m[1].up.store(false, Ordering::Relaxed);
        }
        for _ in 0..4 {
            assert_eq!(u.base().await.unwrap(), up);
        }

        // Probing marks the dead one down and keeps the live one; recovery flips it back.
        let u = Upstream::from_config(&UpstreamConfig::One(format!("{up}, http://127.0.0.1:1")), None).unwrap();
        u.probe_once().await;
        for _ in 0..4 {
            assert_eq!(u.base().await.unwrap(), up);
        }
        if let Kind::Static(m) = &u.inner.kind {
            m[0].up.store(false, Ordering::Relaxed);
        }
        u.probe_once().await;
        assert_eq!(u.base().await.unwrap(), up, "reachable again");

        // All down: every address is still tried.
        let all_down = Upstream::fixed(&["http://127.0.0.1:1", "http://127.0.0.1:2"]);
        if let Kind::Static(m) = &all_down.inner.kind {
            for x in m {
                x.up.store(false, Ordering::Relaxed);
            }
        }
        assert!(all_down.base().await.is_ok());
        assert!(!reachable("http://no-such-host.invalid:80").await);
        assert!(!reachable("no-port-host.invalid").await);
    }

    #[tokio::test]
    async fn routes_pick_by_path() {
        fn admin(p: &str) -> bool {
            p.starts_with("/admin")
        }
        fn never(_: &str) -> bool {
            false
        }
        let u = Upstream::fixed(&["http://main:1"]).with_routes(vec![
            (never, Upstream::fixed(&["http://never:1"])),
            (admin, Upstream::fixed(&["http://admin:1"])),
        ]);
        assert_eq!(u.base_for("/admin/x?y=1").await.unwrap(), "http://admin:1");
        assert_eq!(u.base_for("/other").await.unwrap(), "http://main:1");
        assert_eq!(u.base().await.unwrap(), "http://main:1");
        assert_eq!(u.clone().base_for("/admin").await.unwrap(), "http://admin:1");
    }

    #[tokio::test]
    async fn config_forms_and_eureka_source() {
        assert!(Upstream::from_config(&UpstreamConfig::Many(vec![]), None).is_err());
        assert!(Upstream::from_config(&UpstreamConfig::One("eureka:SECURITY".into()), None).is_err());
        let one = Upstream::from_config(&UpstreamConfig::One("http://a:1/".into()), None).unwrap();
        assert_eq!(one.base().await.unwrap(), "http://a:1");

        let eureka = crate::eureka::Eureka::new(
            &crate::config::EurekaConfig { zones: vec!["http://127.0.0.1:1/eureka/".into()], ..Default::default() },
            0,
        )
        .unwrap();
        let e = Upstream::from_config(&UpstreamConfig::One("eureka:security".into()), Some(&eureka)).unwrap();
        assert!(e.base().await.is_err(), "eureka unreachable");
    }
}
