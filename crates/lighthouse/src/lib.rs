//! Lighthouse: the registry that replaces the Java Eureka server, run as several instances
//! that replicate to each other the way Eureka peers do.
//!
//! - [`eureka`]: the Eureka API every client in use speaks (XML for py_eureka_client, JSON for
//!   the Rust clients).
//! - [`registry`]: Eureka's registration, status and lease rules, self-preservation, delta.
//! - [`replication`], [`sync`]: batches to the peers, healing, startup sync, digest repair.
//! - [`eviction`]: the eviction timer.
//! - [`allowed`]: source networks and the peer token.
//! - [`dashboard`]: the status page, its JSON views, and managing instances with the admin token.
//! - [`config`]: Lighthouse's own settings, and the config server: oci-config snapshots, the
//!   Spring compat endpoint, the units' documents and the ai and ssr env files.
//!
//! Lighthouse reads its own configuration from its TOML and environment only, and never
//! registers in itself.

pub mod allowed;
pub mod config;
pub mod dashboard;
pub mod eureka;
pub mod eviction;
pub mod registry;
pub mod replication;
pub mod sync;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use axum::middleware;
use axum::Router;
use parking_lot::Mutex;
use platform::app::Service;
use platform::health::Health;
use tokio::task::JoinHandle;

use crate::allowed::Allowed;
use crate::config::auth::Auth;
use crate::config::server::ConfigServer;
use crate::config::LighthouseConfig;
use crate::registry::{Registry, Tuning};
use crate::replication::Peer;
use crate::sync::PeerClient;

pub const NAME: &str = "lighthouse";

/// One Lighthouse instance: the registry, its peers and its background tasks.
pub struct Node {
    pub cfg: LighthouseConfig,
    pub registry: Arc<Registry>,
    pub peers: Vec<Arc<Peer>>,
    allowed: Allowed,
    client: PeerClient,
    /// For the dashboard's peer probes: short, so a dead peer does not hold the page.
    probe: reqwest::Client,
    /// The tokens: the admin token (`ops`), the peer token, the consumers of the config server.
    pub auth: Arc<Auth>,
    /// The config server, when `[config] source` is set.
    pub config: Option<Arc<ConfigServer>>,
    started: tokio::time::Instant,
    started_ms: i64,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

/// The peers other than this instance: `self_url` is skipped, and so is a loopback address on
/// this instance's port, so every instance can share one list.
pub fn peer_urls(cfg: &LighthouseConfig) -> Vec<String> {
    let me = (!cfg.registry.self_url.trim().is_empty()).then(|| lighthouse_client::origin(&cfg.registry.self_url));
    let mut out: Vec<String> = Vec::new();
    for p in cfg.registry.peers.iter().filter(|p| !p.trim().is_empty()) {
        let o = lighthouse_client::origin(p);
        let is_me = me.as_deref() == Some(o.as_str()) || is_loopback_on(&o, cfg.server.port);
        if !is_me && !out.contains(&o) {
            out.push(o);
        }
    }
    out
}

fn is_loopback_on(origin: &str, port: u16) -> bool {
    let Ok(url) = reqwest::Url::parse(origin) else { return false };
    let local = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "0.0.0.0" | "[::1]"));
    local && url.port_or_known_default() == Some(port)
}

impl Node {
    pub fn new(cfg: LighthouseConfig) -> Result<Arc<Self>> {
        let r = &cfg.registry;
        let urls = peer_urls(&cfg);
        if let Some(bad) = urls.iter().find(|u| reqwest::Url::parse(u).is_err()) {
            anyhow::bail!("[registry] peers: {bad:?} is not a URL");
        }
        let peers: Vec<Arc<Peer>> =
            urls.iter().map(|u| Arc::new(Peer::new(u, r.replication_queue_limit, r.replication_batch))).collect();
        let tuning = Tuning {
            renewal_percent_threshold: r.renewal_percent_threshold,
            self_preservation: r.self_preservation,
            delta_retention_ms: (r.delta_retention_seconds * 1000) as i64,
            tombstone_ms: (r.tombstone_seconds * 1000) as i64,
        };
        let registry = Arc::new(Registry::new(tuning, peers.clone()));
        let http = reqwest::Client::builder().timeout(Duration::from_millis(r.peer_timeout_ms.max(1))).build()?;
        let token = Some(r.peer_token.clone()).filter(|t| !t.is_empty());
        dashboard::admin_hash(&cfg.admin_token_sha256)?;
        let auth = Arc::new(Auth::new(&cfg.auth, &cfg.admin_token_sha256, &r.peer_token)?);
        let config = ConfigServer::new(&cfg.config, auth.clone(), urls.clone(), &r.peer_token)?;
        Ok(Arc::new(Self {
            allowed: Allowed::parse(&cfg.allowed.networks)?,
            client: PeerClient { http, token },
            probe: reqwest::Client::builder().timeout(dashboard::PROBE_TIMEOUT).build()?,
            auth,
            config,
            started: tokio::time::Instant::now(),
            started_ms: lighthouse_client::now_millis(),
            cfg,
            registry,
            peers,
            tasks: Mutex::new(Vec::new()),
        }))
    }

    /// Starts the startup sync, the eviction timer, a replication worker per peer, the digest
    /// comparison and, with a config server, the snapshot kept on disk and the source's poll.
    pub fn start(self: &Arc<Self>) {
        let r = &self.cfg.registry;
        let mut tasks = self.tasks.lock();
        if let Some(cs) = &self.config {
            cs.load_kept();
            tasks.push(tokio::spawn(cs.clone().run()));
        }
        let peer_list: Vec<String> = self.peers.iter().map(|p| p.url.clone()).collect();
        for peer in &self.peers {
            tasks.push(tokio::spawn(replication::run(
                peer.clone(),
                self.registry.clone(),
                self.client.http.clone(),
                self.client.token.clone(),
                Duration::from_millis(r.replication_flush_ms.max(1)),
            )));
        }
        let (reg, peers, client) = (self.registry.clone(), peer_list.clone(), self.client.clone());
        let (wait, retry) = (Duration::from_secs(r.startup_wait_seconds), Duration::from_millis(r.sync_retry_ms.max(1)));
        tasks.push(tokio::spawn(async move { sync::startup(&reg, &peers, &client, wait, retry).await }));
        let reg = self.registry.clone();
        let (interval, late) = (Duration::from_millis(r.eviction_interval_ms.max(1)), Duration::from_millis(r.late_tick_skip_ms));
        tasks.push(tokio::spawn(async move { eviction::run(&reg, interval, late).await }));
        if !peer_list.is_empty() {
            let (reg, client) = (self.registry.clone(), self.client.clone());
            let every = Duration::from_secs(r.digest_interval_seconds.max(1));
            tasks.push(tokio::spawn(async move { sync::digest_loop(&reg, &peer_list, &client, every).await }));
        }
    }

    /// Stops the background tasks (the router keeps answering from the registry as it is).
    pub fn stop(&self) {
        for t in self.tasks.lock().drain(..) {
            t.abort();
        }
    }

    /// Whether `app` may register (`[allowed] apps`, empty allows all).
    pub fn app_allowed(&self, app: &str) -> bool {
        self.cfg.allowed.apps.is_empty() || self.cfg.allowed.apps.iter().any(|a| a.eq_ignore_ascii_case(app))
    }

    /// How the dashboard names this instance: its `self_url`, else its host name.
    pub fn instance_name(&self) -> String {
        Some(self.cfg.registry.self_url.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| std::env::var("HOSTNAME").ok().filter(|h| !h.is_empty()))
            .unwrap_or_else(|| format!("lighthouse:{}", self.cfg.server.port))
    }

    /// The registry routes, the config server and the dashboard, behind the network check and
    /// the peer token.
    pub fn router(self: &Arc<Self>) -> Router {
        let config = match &self.config {
            Some(cs) => config::server::routes(cs.clone(), self.registry.clone()),
            None => config::server::disabled_routes(),
        };
        eureka::routes(self.clone())
            .merge(dashboard::routes(self.clone()))
            .merge(config)
            .layer(middleware::from_fn_with_state(Arc::new(self.cfg.registry.peer_token.clone()), allowed::peer_token))
            .layer(middleware::from_fn_with_state(self.allowed.clone(), allowed::networks))
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Runs Lighthouse until SIGTERM. `/readyz` fails until the startup sync is over.
pub async fn run() -> Result<()> {
    let cfg: LighthouseConfig = platform::config::load(NAME)?;
    let telemetry = platform::telemetry::init(NAME, &cfg.telemetry)?;
    if let Some(file) = platform::config::config_file(NAME) {
        tracing::info!(file = %file.display(), "configuration file");
    }
    let node = Node::new(cfg.clone())?;
    tracing::info!(peers = ?node.peers.iter().map(|p| p.url.as_str()).collect::<Vec<_>>(), "lighthouse starting");
    node.start();
    let health = Health::new(telemetry.metrics.clone());
    if let Some(cs) = node.config.clone() {
        health.check("config", move || {
            let ready = cs.served().is_some();
            async move {
                if ready {
                    Ok(())
                } else {
                    anyhow::bail!("no configuration snapshot is loaded yet")
                }
            }
        });
    }
    let n = node.clone();
    health.check("registry", move || {
        let ready = n.registry.is_ready();
        async move {
            if ready {
                Ok(())
            } else {
                anyhow::bail!("warming up: syncing the registry from its peers")
            }
        }
    });
    let service = Service { name: NAME.to_string(), server: cfg.server.clone(), telemetry, health, eureka: None, cors: false };
    let result = service.run(node.router()).await;
    node.stop();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peers_skip_this_instance() {
        let mut cfg = LighthouseConfig::default();
        cfg.registry.self_url = "http://lighthouse-1:8761/eureka/".into();
        cfg.registry.peers = vec![
            "http://lighthouse-1:8761".into(),
            "http://lighthouse-2:8761/eureka/".into(),
            "http://lighthouse-2:8761".into(),
            "http://localhost:8761".into(),
            "http://127.0.0.1:8762".into(),
            "not a url".into(),
            " ".into(),
        ];
        assert_eq!(peer_urls(&cfg), ["http://lighthouse-2:8761", "http://127.0.0.1:8762", "not a url"]);
        assert!(Node::new(cfg.clone()).err().unwrap().to_string().contains("not a URL"));
        cfg.registry.peers.retain(|p| p != "not a url");
        cfg.allowed.apps = vec!["files-serve".into()];
        let node = Node::new(cfg).unwrap();
        assert!(node.app_allowed("FILES-SERVE") && !node.app_allowed("OTHER"));
        let mut bad = LighthouseConfig::default();
        bad.allowed.networks = vec!["nope".into()];
        assert!(Node::new(bad).err().is_some());
        let bad = LighthouseConfig { admin_token_sha256: "abc".into(), ..LighthouseConfig::default() };
        assert!(Node::new(bad).err().is_some());
        let mut named = LighthouseConfig::default();
        assert!(!Node::new(named.clone()).unwrap().instance_name().is_empty());
        named.registry.self_url = "http://lighthouse-1:8761".into();
        assert_eq!(Node::new(named).unwrap().instance_name(), "http://lighthouse-1:8761");
    }
}
