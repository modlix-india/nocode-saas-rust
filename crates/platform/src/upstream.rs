//! Where another service is.
//!
//! An [`Upstream`] is either a fixed list of base URLs, used round robin (compose service
//! addresses today, Kubernetes Service names later), or `eureka:<APP>`, which follows the Java
//! registry while Java services are still the ones answering.
//!
//! A fixed list with more than one address is probed every few seconds (a TCP connect: a stopped
//! container refuses it), and addresses that fail are skipped until they answer again. Blue/green
//! deploys keep one colour stopped, so without this half the calls would fail.
//!
//! Between two probes, a caller whose connection to an address could not be opened moves on to
//! the next one ([`Upstream::next_base_after`], or [`Upstream::send`] which does it for a
//! reqwest call), so a member that just stopped (a gateway of the pair being redeployed) costs
//! nothing but a refused connect.

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
    /// Probes run for this list: a member marked down comes back when it answers again.
    probed: AtomicBool,
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
        Self {
            inner: Arc::new(Inner { kind, next: AtomicUsize::new(0), probed: AtomicBool::new(false) }),
            routes: Arc::new(Vec::new()),
        }
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
        self.serving(path).base().await
    }

    /// The upstream that takes requests to `path`.
    fn serving(&self, path: &str) -> &Upstream {
        self.routes.iter().find(|(accepts, _)| accepts(path)).map(|(_, u)| u).unwrap_or(self)
    }

    /// Another member to try after a connection to `failed` (a base URL this upstream gave out)
    /// could not be opened: the next one in the list that is up, else the next one at all.
    /// `failed` is skipped from now on until its probe sees it answer again. `None` when there
    /// is no other member: a single address, an `eureka:` source, or a base that is not ours.
    pub fn next_base_after(&self, failed: &str) -> Option<String> {
        let Kind::Static(members) = &self.inner.kind else { return None };
        let at = members.iter().position(|m| m.base == failed)?;
        if self.inner.probed.load(Ordering::Relaxed) && members[at].up.swap(false, Ordering::Relaxed) {
            tracing::warn!(upstream = failed, "upstream refused a connection, skipping it");
        }
        let others = || (1..members.len()).map(|i| &members[(at + i) % members.len()]);
        others()
            .find(|m| m.up.load(Ordering::Relaxed))
            .or_else(|| others().next())
            .map(|m| m.base.clone())
    }

    /// [`Self::next_base_after`] on the upstream that takes requests to `path`.
    pub fn next_base_for(&self, path: &str, failed: &str) -> Option<String> {
        self.serving(path).next_base_after(failed)
    }

    /// Sends the request `build` makes for a base URL, to the member for `path`. When the
    /// connection cannot be opened, sends it once more to the next member: nothing reached the
    /// first one, so this is safe for any method and any body. Each attempt is timed in
    /// `http_client_request_duration_seconds` ([`crate::meter::send_to_service`]).
    pub async fn send<F>(&self, path: &str, build: F) -> Result<reqwest::Response>
    where
        F: Fn(&str) -> reqwest::RequestBuilder,
    {
        let base = self.base_for(path).await?;
        match crate::meter::send_to_service(build(&base)).await {
            Err(e) if e.is_connect() => match self.next_base_for(path, &base) {
                Some(next) => {
                    tracing::warn!(upstream = base, next, error = %e, "connect failed, trying the next member");
                    Ok(crate::meter::send_to_service(build(&next)).await?)
                }
                None => Err(e.into()),
            },
            other => Ok(other?),
        }
    }

    /// Whether this upstream has anywhere to send to: `false` for an empty fixed list (a retired
    /// service left unconfigured).
    pub fn has_addresses(&self) -> bool {
        match &self.inner.kind {
            Kind::Static(members) => !members.is_empty(),
            Kind::Eureka { .. } => true,
        }
    }

    /// A base URL to send the next request to, without a trailing `/`.
    pub async fn base(&self) -> Result<String> {
        match &self.inner.kind {
            Kind::Static(members) => {
                if members.is_empty() {
                    bail!("upstream has no addresses");
                }
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
        self.inner.probed.store(true, Ordering::Relaxed);
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
    async fn next_member_after_a_refused_connection() {
        let u = Upstream::fixed(&["http://a:1", "http://b:2", "http://c:3"]);
        assert_eq!(u.next_base_after("http://a:1").as_deref(), Some("http://b:2"));
        assert_eq!(u.next_base_after("http://c:3").as_deref(), Some("http://a:1"), "wraps around");
        if let Kind::Static(m) = &u.inner.kind {
            m[1].up.store(false, Ordering::Relaxed);
        }
        assert_eq!(u.next_base_after("http://a:1").as_deref(), Some("http://c:3"), "skips one known down");
        if let Kind::Static(m) = &u.inner.kind {
            m[2].up.store(false, Ordering::Relaxed);
        }
        assert_eq!(u.next_base_after("http://a:1").as_deref(), Some("http://b:2"), "all down: the next anyway");
        assert!(u.next_base_after("http://elsewhere:1").is_none());
        assert!(Upstream::fixed(&["http://a:1"]).next_base_after("http://a:1").is_none());
        assert!(Upstream::fixed(&[]).next_base_after("http://a:1").is_none());

        // Unprobed lists never mark a member down (nothing would bring it back); probed ones do.
        let u = Upstream::fixed(&["http://a:1", "http://b:2"]);
        u.next_base_after("http://a:1");
        assert_eq!(u.base().await.unwrap(), "http://a:1");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live = format!("http://{}", listener.local_addr().unwrap());
        let u = Upstream::from_config(&UpstreamConfig::Many(vec!["http://127.0.0.1:1".into(), live.clone()]), None).unwrap();
        assert_eq!(u.next_base_after("http://127.0.0.1:1").as_deref(), Some(live.as_str()));
        for _ in 0..4 {
            assert_eq!(u.base().await.unwrap(), live, "skipped until a probe sees it again");
        }

        // By path, through the routes.
        fn admin(p: &str) -> bool {
            p.starts_with("/admin")
        }
        let routed = Upstream::fixed(&["http://main:1"]).with_routes(vec![(admin, Upstream::fixed(&["http://x:1", "http://y:1"]))]);
        assert_eq!(routed.next_base_for("/admin/z", "http://x:1").as_deref(), Some("http://y:1"));
        assert!(routed.next_base_for("/other", "http://main:1").is_none());
    }

    #[tokio::test]
    async fn send_moves_on_after_a_refused_connection_only() {
        use axum::http::StatusCode;
        let app = axum::Router::new()
            .route("/ok", axum::routing::get(|| async { "ok" }))
            .route("/broken", axum::routing::get(|| async { StatusCode::INTERNAL_SERVER_ERROR }));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        let http = reqwest::Client::new();

        let u = Upstream::fixed(&["http://127.0.0.1:1", &live]);
        for _ in 0..3 {
            let r = u.send("/ok", |b| http.get(format!("{b}/ok"))).await.unwrap();
            assert_eq!(r.text().await.unwrap(), "ok");
        }
        // An answer, even an error, is the answer: not sent again.
        let r = u.send("/broken", |b| http.get(format!("{b}/broken"))).await.unwrap();
        assert_eq!(r.status(), 500);
        // Nowhere else to go: the connect error itself.
        let dead = Upstream::fixed(&["http://127.0.0.1:1"]);
        let e = dead.send("/ok", |b| http.get(format!("{b}/ok"))).await.unwrap_err();
        assert!(e.downcast_ref::<reqwest::Error>().is_some_and(|e| e.is_connect()));
        let both_dead = Upstream::fixed(&["http://127.0.0.1:1", "http://127.0.0.1:2"]);
        assert!(both_dead.send("/ok", |b| http.get(format!("{b}/ok"))).await.is_err());
        assert!(Upstream::fixed(&[]).send("/ok", |b| http.get(format!("{b}/ok"))).await.is_err());
    }

    /// Both attempts are timed: the refused one and the one the next member answered.
    #[test]
    fn each_attempt_is_timed() {
        let ((), text) = crate::meter::capture_async(async {
            let app = axum::Router::new().route("/api/security/x", axum::routing::get(|| async { "ok" }));
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let live = format!("http://{}", l.local_addr().unwrap());
            tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
            let http = reqwest::Client::new();
            let u = Upstream::fixed(&["http://127.0.0.1:1", &live]);
            u.send("/api/security/x", |b| http.get(format!("{b}/api/security/x"))).await.unwrap();
        });
        let count = |status: &str| {
            crate::meter::sample(&text, &format!("{}_count", crate::meter::HTTP_CLIENT_DURATION), &[("target", "security"), ("status", status)])
        };
        assert_eq!((count("connect_error"), count("200")), (Some(1.0), Some(1.0)));
    }

    #[tokio::test]
    async fn no_addresses_is_an_error_not_a_panic() {
        assert!(Upstream::fixed(&[]).base().await.is_err());
        assert!(!Upstream::fixed(&[]).has_addresses());
        assert!(Upstream::fixed(&["http://127.0.0.1:1"]).has_addresses());
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
