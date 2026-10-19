//! In-process Lighthouse instances for the integration tests: each on its own port, killable
//! like a process (its open connections reset), and restartable on the same port.
#![allow(dead_code)]

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ConnectInfo;
use axum::Router;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use lighthouse::config::LighthouseConfig;
use lighthouse::Node;
use lighthouse_client::wire::{Applications, ApplicationsEnvelope};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::task::{JoinHandle, JoinSet};
use tower::ServiceExt;

pub async fn bind() -> (TcpListener, String) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    (l, url)
}

/// Binds `url`'s port again after its server was killed.
pub async fn rebind(url: &str) -> TcpListener {
    let addr = url.trim_start_matches("http://");
    for _ in 0..200 {
        if let Ok(l) = TcpListener::bind(addr).await {
            return l;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("could not bind {addr} again");
}

pub fn port_of(url: &str) -> u16 {
    url.rsplit(':').next().unwrap().parse().unwrap()
}

/// Serves `router` until the task is aborted; aborting drops every open connection too.
pub fn serve(listener: TcpListener, router: Router) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut conns = JoinSet::new();
        loop {
            let Ok((stream, remote)) = listener.accept().await else { continue };
            let router = router.clone();
            conns.spawn(async move {
                let svc = hyper::service::service_fn(move |mut req: hyper::Request<Incoming>| {
                    req.extensions_mut().insert(ConnectInfo(remote));
                    router.clone().oneshot(req)
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), svc).await;
            });
            while conns.try_join_next().is_some() {}
        }
    })
}

/// The admin token every test instance accepts (`admin_token_sha256` is its hash).
pub const ADMIN_TOKEN: &str = "letmein";

/// A configuration with short timings for tests.
pub fn config(url: &str, peers: &[String]) -> LighthouseConfig {
    let mut c = LighthouseConfig::default();
    c.admin_token_sha256 = lighthouse::dashboard::sha256_hex(ADMIN_TOKEN);
    c.server.port = port_of(url);
    c.registry.self_url = url.to_string();
    c.registry.peers = peers.to_vec();
    c.registry.replication_flush_ms = 20;
    c.registry.eviction_interval_ms = 100;
    c.registry.startup_wait_seconds = 1;
    c.registry.sync_retry_ms = 50;
    c.registry.peer_timeout_ms = 1_000;
    c
}

pub struct TestNode {
    pub node: Arc<Node>,
    pub url: String,
    server: JoinHandle<()>,
}

impl TestNode {
    pub fn start(listener: TcpListener, cfg: LighthouseConfig) -> Self {
        let url = format!("http://{}", listener.local_addr().unwrap());
        let node = Node::new(cfg).unwrap();
        node.start();
        let server = serve(listener, node.router());
        Self { node, url, server }
    }

    /// Like `kill -9`: the listener and every connection go, the background tasks stop.
    pub fn kill(&self) {
        self.server.abort();
        self.node.stop();
    }

    pub fn eureka(&self) -> String {
        format!("{}/eureka", self.url)
    }
}

impl Drop for TestNode {
    fn drop(&mut self) {
        self.kill();
    }
}

/// Starts one node per URL, each with all the others as peers.
pub async fn cluster(n: usize) -> Vec<TestNode> {
    let mut listeners = Vec::new();
    for _ in 0..n {
        listeners.push(bind().await);
    }
    let urls: Vec<String> = listeners.iter().map(|(_, u)| u.clone()).collect();
    listeners.into_iter().map(|(l, u)| TestNode::start(l, config(&u, &urls))).collect()
}

/// Polls `f` every 20 ms until it holds or `within` passes.
pub async fn eventually<F, Fut>(within: Duration, mut f: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + within;
    loop {
        if f().await {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// A client without connection reuse, so a restarted server is reached on a fresh connection.
pub fn http() -> reqwest::Client {
    reqwest::Client::builder().pool_max_idle_per_host(0).timeout(Duration::from_secs(5)).build().unwrap()
}

/// A registration body as the Rust units send it.
pub fn body(app: &str, id: &str, port: u16, dirty: i64) -> Value {
    json!({"instance": {
        "instanceId": id, "hostName": "127.0.0.1", "app": app.to_ascii_uppercase(), "ipAddr": "127.0.0.1",
        "status": "UP", "overriddenStatus": "UNKNOWN",
        "port": {"$": port, "@enabled": "true"}, "securePort": {"$": 443, "@enabled": "false"},
        "countryId": 1,
        "dataCenterInfo": {"@class": "com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo", "name": "MyOwn"},
        "leaseInfo": {"renewalIntervalInSecs": 10, "durationInSecs": 30},
        "metadata": {"management.port": port.to_string(), "runtime": "rust"},
        "vipAddress": app.to_ascii_lowercase(), "secureVipAddress": app.to_ascii_lowercase(),
        "isCoordinatingDiscoveryServer": "false",
        "lastUpdatedTimestamp": dirty.to_string(), "lastDirtyTimestamp": dirty.to_string()
    }})
}

pub async fn register(base: &str, app: &str, id: &str, dirty: i64) -> u16 {
    http()
        .post(format!("{base}/eureka/apps/{}", app.to_ascii_uppercase()))
        .json(&body(app, id, 8000, dirty))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

pub async fn heartbeat(base: &str, app: &str, id: &str, dirty: i64) -> u16 {
    let url = format!("{base}/eureka/apps/{app}/{id}?status=UP&lastDirtyTimestamp={dirty}");
    http().put(url).send().await.unwrap().status().as_u16()
}

/// The registry as JSON, `None` while it does not answer 200.
pub async fn apps(base: &str) -> Option<Applications> {
    let r = http().get(format!("{base}/eureka/apps")).header("accept", "application/json").send().await.ok()?;
    if r.status() != 200 {
        return None;
    }
    Some(r.json::<ApplicationsEnvelope>().await.ok()?.applications)
}

/// The instance ids `base` knows, sorted; empty while it does not answer.
pub async fn ids(base: &str) -> Vec<String> {
    let mut v: Vec<String> = apps(base).await.map(|a| a.instances().map(|i| i.instance_id.clone()).collect()).unwrap_or_default();
    v.sort();
    v
}

pub async fn wait_ready(nodes: &[&TestNode]) {
    for n in nodes {
        assert!(eventually(Duration::from_secs(5), || async { apps(&n.url).await.is_some() }).await, "{} never got ready", n.url);
    }
}

pub async fn operator(base: &str) -> Value {
    http().get(format!("{base}/v1/registry")).send().await.unwrap().json().await.unwrap()
}

/// `/v1/peers`: each peer as the dashboard shows it.
pub async fn peers_view(base: &str) -> Vec<Value> {
    let v: Value = http().get(format!("{base}/v1/peers")).send().await.unwrap().json().await.unwrap();
    v["peers"].as_array().unwrap().clone()
}

/// A dashboard management call, with `token` as the bearer when given.
pub async fn admin(method: &str, url: String, token: Option<&str>) -> u16 {
    let mut req = http().request(method.parse().unwrap(), url);
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    req.send().await.unwrap().status().as_u16()
}

/// The synthetic oci-config every config test reads (never the real one).
pub fn fixture() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/oci-config")
}

/// A copy of the fixture a test may change.
pub fn fixture_copy(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("lighthouse-fixture-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    copy_dir(&fixture(), &dir);
    dir
}

fn copy_dir(from: &std::path::Path, to: &std::path::Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let target = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_dir(&e.path(), &target);
        } else {
            std::fs::copy(e.path(), target).unwrap();
        }
    }
}

/// Tokens of the config tests, by scope: their SHA-256 goes into `[auth]`.
pub const UNITS_TOKEN: &str = "units-token";
pub const AI_TOKEN: &str = "ai-token";
pub const PEER_TOKEN: &str = "peer-token";
/// A `units` token limited to multi's document.
pub const MULTI_TOKEN: &str = "multi-token";

/// A configuration with the config server on `source`, rendering `env`, with a token per scope.
pub fn config_server(url: &str, peers: &[String], source: &str, env: &str) -> LighthouseConfig {
    use lighthouse::config::auth::{Scope, TokenConfig};
    let mut c = config(url, peers);
    c.config.source = source.to_string();
    c.config.env = env.to_string();
    c.registry.peer_token = PEER_TOKEN.to_string();
    c.auth.tokens = vec![
        TokenConfig { name: "units".into(), sha256: lighthouse::dashboard::sha256_hex(UNITS_TOKEN), scopes: vec![Scope::Units], ..Default::default() },
        TokenConfig { name: "ai".into(), sha256: lighthouse::dashboard::sha256_hex(AI_TOKEN), scopes: vec![Scope::Ai], ..Default::default() },
        TokenConfig {
            name: "multi only".into(),
            sha256: lighthouse::dashboard::sha256_hex(MULTI_TOKEN),
            scopes: vec![Scope::Units],
            units: vec!["multi".into()],
        },
    ];
    c
}

/// A GET with an optional bearer token.
pub async fn get(url: String, token: Option<&str>) -> reqwest::Response {
    let mut req = http().get(url);
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    req.send().await.unwrap()
}
