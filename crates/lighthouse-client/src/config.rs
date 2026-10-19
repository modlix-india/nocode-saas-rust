//! A unit's configuration from Lighthouse.
//!
//! - [`ConfigClient::fetch`]: `GET /v1/units/{unit}/config` from the first server that answers:
//!   the unit's document (its rendered TOML with its own secrets), its version and its live
//!   keys. [`fetch_unit_config`] retries across the servers of `LIGHTHOUSE_URLS` for up to 60
//!   seconds; a unit started with `LIGHTHOUSE_REQUIRED` refuses to start without it.
//! - [`watch_version`]: `GET /v1/units/{unit}/version` every 30 seconds with the last version as
//!   the ETag (a 304 when nothing changed), reporting each new version as a live change (only
//!   live keys differ: apply in place) or a restart (wait for the rolling restart).
//!
//! A version is `<restart>.<live>`: the hash of the document without its live keys, then the
//! hash of the live keys.
//!
//! The version a process runs with is kept here too ([`set_running_version`]), for whatever
//! registers it in the registry as `configVersion`.

use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use reqwest::StatusCode;
use serde::Deserialize;
use tokio::task::JoinHandle;

/// A unit's configuration document and its version (the hash units put in their registry
/// metadata as `configVersion`).
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct UnitConfig {
    pub unit: String,
    pub env: String,
    pub version: String,
    /// The oci-config commit it was rendered from.
    pub sha: String,
    /// Prefixes of the document a unit applies in place.
    pub live: Vec<String>,
    #[serde(rename = "config")]
    pub document: serde_json::Value,
}

/// The part of a version a running unit must restart for.
pub fn restart_part(version: &str) -> &str {
    version.split('.').next().unwrap_or(version)
}

static RUNNING: RwLock<Option<String>> = RwLock::new(None);

/// Records the configuration version this process runs with.
pub fn set_running_version(version: &str) {
    *RUNNING.write().unwrap_or_else(|e| e.into_inner()) = Some(version.to_string());
}

/// The configuration version this process runs with, when it came from Lighthouse.
pub fn running_version() -> Option<String> {
    RUNNING.read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Whether `LIGHTHOUSE_REQUIRED` is set (anything but empty, `0` or `false`).
pub fn required() -> bool {
    required_from(std::env::var("LIGHTHOUSE_REQUIRED").ok().as_deref())
}

fn required_from(v: Option<&str>) -> bool {
    v.is_some_and(|v| !matches!(v.trim().to_ascii_lowercase().as_str(), "" | "0" | "false" | "no"))
}

/// A refusal (4xx): asking again, or another server, gives the same answer.
#[derive(Debug)]
struct Refused(String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refused {}

/// Reads unit configuration from one or more Lighthouse servers.
pub struct ConfigClient {
    servers: Vec<String>,
    token: Option<String>,
    http: reqwest::Client,
    current: AtomicUsize,
}

impl ConfigClient {
    /// Servers in any form [`crate::origin`] takes.
    pub fn new<S: AsRef<str>>(servers: &[S], token: Option<String>) -> Self {
        Self {
            servers: servers.iter().map(|s| crate::origin(s.as_ref())).collect(),
            token: token.filter(|t| !t.is_empty()),
            http: reqwest::Client::builder().timeout(Duration::from_secs(10)).build().unwrap_or_default(),
            current: AtomicUsize::new(0),
        }
    }

    /// `LIGHTHOUSE_URLS` (else the local Lighthouse) and `LIGHTHOUSE_TOKEN`.
    pub fn from_env() -> Self {
        Self::new(&crate::servers_from_env(), crate::token_from_env())
    }

    /// Sends `path` to the server that answered last, then the others while one is unreachable
    /// or failing. A 4xx is final: another server would answer the same.
    async fn send(&self, path: &str, etag: Option<&str>) -> Result<reqwest::Response> {
        let n = self.servers.len();
        let start = self.current.load(Ordering::Relaxed);
        let mut errors: Vec<String> = Vec::new();
        for k in 0..n {
            let i = (start + k) % n;
            let mut req = self.http.get(format!("{}{path}", self.servers[i]));
            if let Some(t) = &self.token {
                req = req.bearer_auth(t);
            }
            if let Some(e) = etag {
                req = req.header(reqwest::header::IF_NONE_MATCH, format!("\"{e}\""));
            }
            match req.send().await {
                Ok(r) if r.status().is_server_error() => {
                    let status = r.status();
                    // The body names what is missing, never a value.
                    let body: String = r.text().await.unwrap_or_default().chars().take(400).collect();
                    errors.push(format!("{}{path}: {status} {body}", self.servers[i]));
                }
                Ok(r) if r.status().is_client_error() => {
                    return Err(Refused(format!("{}{path}: {}", self.servers[i], r.status())).into());
                }
                Ok(r) => {
                    self.current.store(i, Ordering::Relaxed);
                    return Ok(r);
                }
                Err(e) => errors.push(format!("{}{path}: {e}", self.servers[i])),
            }
        }
        if errors.is_empty() {
            return Err(anyhow!("no Lighthouse servers configured"));
        }
        Err(anyhow!(errors.join("; ")))
    }

    /// One attempt across the servers.
    pub async fn fetch(&self, unit: &str) -> Result<UnitConfig> {
        let r = self.send(&format!("/v1/units/{unit}/config"), None).await?;
        r.json::<UnitConfig>().await.context("the unit configuration is not readable")
    }

    /// Tries until it works or `within` passes, pausing `pause` between rounds; a refusal (4xx)
    /// ends it at once.
    pub async fn fetch_within(&self, unit: &str, within: Duration, pause: Duration) -> Result<UnitConfig> {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            match self.fetch(unit).await {
                Ok(c) => return Ok(c),
                Err(e) if e.downcast_ref::<Refused>().is_some() || tokio::time::Instant::now() + pause > deadline => {
                    return Err(e.context(format!("no configuration for {unit} from Lighthouse")));
                }
                Err(_) => tokio::time::sleep(pause).await,
            }
        }
    }

    /// The current version, or `None` when it is still `known`.
    pub async fn version(&self, unit: &str, known: Option<&str>) -> Result<Option<String>> {
        let r = self.send(&format!("/v1/units/{unit}/version"), known).await?;
        if r.status() == StatusCode::NOT_MODIFIED {
            return Ok(None);
        }
        Ok(Some(r.text().await?.trim().to_string()))
    }
}

/// The unit's configuration from the servers of `LIGHTHOUSE_URLS`, retried for up to 60 seconds.
pub async fn fetch_unit_config(unit: &str) -> Result<UnitConfig> {
    ConfigClient::from_env().fetch_within(unit, Duration::from_secs(60), Duration::from_secs(2)).await
}

/// A new version, as the watch reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// Only live keys differ from the running version: apply in place.
    Live(String),
    /// Something a restart applies: the rolling restart will.
    Restart(String),
}

/// Polls the unit's version every `every` and hands each new one to `on_change`, classified
/// against the running version. When `on_change` answers false (it could not apply the change)
/// the same version is handed over again at the next poll; a failed poll is retried too.
pub fn watch_version<F, Fut>(client: Arc<ConfigClient>, unit: &str, running: &str, every: Duration, mut on_change: F) -> JoinHandle<()>
where
    F: FnMut(Change) -> Fut + Send + 'static,
    Fut: Future<Output = bool> + Send,
{
    let (unit, running) = (unit.to_string(), running.to_string());
    tokio::spawn(async move {
        let mut known = running.clone();
        let mut tick = tokio::time::interval(every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tick.tick().await;
        loop {
            tick.tick().await;
            match client.version(&unit, Some(&known)).await {
                Ok(Some(v)) if v != known => {
                    let change = if restart_part(&v) == restart_part(&running) { Change::Live(v.clone()) } else { Change::Restart(v.clone()) };
                    if on_change(change).await {
                        known = v;
                    }
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(unit, error = %e, "lighthouse version poll failed"),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU32;

    use axum::extract::{Path, State};
    use axum::http::{HeaderMap, StatusCode as Code};
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::Router;
    use serde_json::json;

    use super::*;

    #[derive(Clone)]
    struct Fake {
        version: Arc<RwLock<String>>,
        failures_left: Arc<AtomicU32>,
        status: Arc<RwLock<u16>>,
    }

    async fn serve(fake: Fake) -> String {
        let app = Router::new()
            .route(
                "/v1/units/{unit}/config",
                get(|State(f): State<Fake>, Path(unit): Path<String>, h: HeaderMap| async move {
                    if f.failures_left.load(Ordering::SeqCst) > 0 {
                        f.failures_left.fetch_sub(1, Ordering::SeqCst);
                        return (Code::SERVICE_UNAVAILABLE, "warming").into_response();
                    }
                    let status = *f.status.read().unwrap();
                    if status != 200 {
                        return (Code::from_u16(status).unwrap(), "{\"missing\":[\"x\"]}").into_response();
                    }
                    assert_eq!(h["authorization"], "Bearer tok");
                    let v = f.version.read().unwrap().clone();
                    axum::Json(json!({"unit": unit, "env": "dev", "version": v, "sha": "abc", "live": ["telemetry.log_level"],
                        "config": {"server": {"port": 1}}}))
                    .into_response()
                }),
            )
            .route(
                "/v1/units/{unit}/version",
                get(|State(f): State<Fake>, h: HeaderMap| async move {
                    let v = f.version.read().unwrap().clone();
                    let etag = h.get("if-none-match").and_then(|x| x.to_str().ok()).unwrap_or("");
                    if etag == format!("\"{v}\"") {
                        Code::NOT_MODIFIED.into_response()
                    } else {
                        v.into_response()
                    }
                }),
            )
            .with_state(fake);
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        url
    }

    fn fake(version: &str) -> Fake {
        Fake { version: Arc::new(RwLock::new(version.into())), failures_left: Arc::default(), status: Arc::new(RwLock::new(200)) }
    }

    #[tokio::test]
    async fn fetches_across_servers_and_retries() {
        let f = fake("aaaa.1111");
        f.failures_left.store(2, Ordering::SeqCst);
        let url = serve(f.clone()).await;
        let dead = "http://127.0.0.1:1".to_string();
        let c = ConfigClient::new(&[dead.clone(), format!("{url}/eureka/")], Some("tok".into()));
        let got = c.fetch_within("multi", Duration::from_secs(5), Duration::from_millis(10)).await.unwrap();
        assert_eq!((got.unit.as_str(), got.version.as_str(), got.sha.as_str()), ("multi", "aaaa.1111", "abc"));
        assert_eq!(got.document["server"]["port"], 1);
        // The server that answered stays first.
        assert_eq!(c.current.load(Ordering::Relaxed), 1);
        assert_eq!(c.version("multi", Some("aaaa.1111")).await.unwrap(), None);
        assert_eq!(c.version("multi", Some("old")).await.unwrap(), Some("aaaa.1111".into()));

        *f.status.write().unwrap() = 500;
        let e = c.fetch_within("multi", Duration::from_millis(50), Duration::from_millis(10)).await.unwrap_err();
        assert!(format!("{e:#}").contains("500"), "{e:#}");
        *f.status.write().unwrap() = 401;
        let started = tokio::time::Instant::now();
        let e = c.fetch_within("multi", Duration::from_secs(5), Duration::from_millis(10)).await.unwrap_err();
        assert!(format!("{e:#}").contains("401"), "{e:#}");
        assert!(started.elapsed() < Duration::from_secs(1), "a refusal is final");
        let none = ConfigClient::new::<String>(&[], None);
        assert!(none.fetch("multi").await.unwrap_err().to_string().contains("no Lighthouse"));
    }

    #[tokio::test]
    async fn the_watch_tells_live_from_restart() {
        let f = fake("aaaa.1111");
        let url = serve(f.clone()).await;
        let c = Arc::new(ConfigClient::new(&[url], None));
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let refuse_once = Arc::new(AtomicU32::new(1));
        let task = watch_version(c, "multi", "aaaa.1111", Duration::from_millis(20), move |change| {
            let (tx, refuse) = (tx.clone(), refuse_once.clone());
            async move {
                let _ = tx.send(change);
                // The first change is not applied: it must come again.
                refuse.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1)).is_err()
            }
        });
        *f.version.write().unwrap() = "aaaa.2222".into();
        assert_eq!(recv(&mut rx).await, Change::Live("aaaa.2222".into()));
        assert_eq!(recv(&mut rx).await, Change::Live("aaaa.2222".into()), "handed over again");
        *f.version.write().unwrap() = "bbbb.2222".into();
        assert_eq!(recv(&mut rx).await, Change::Restart("bbbb.2222".into()));
        task.abort();
    }

    async fn recv(rx: &mut tokio::sync::mpsc::UnboundedReceiver<Change>) -> Change {
        tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.unwrap().unwrap()
    }

    #[tokio::test]
    async fn a_failing_poll_is_retried() {
        let c = Arc::new(ConfigClient::new(&["http://127.0.0.1:1"], None));
        let task = watch_version(c, "multi", "a.b", Duration::from_millis(10), |_| async { true });
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(!task.is_finished());
        task.abort();
    }

    #[test]
    fn small_things() {
        assert_eq!(restart_part("abc.def"), "abc");
        assert_eq!(restart_part("abc"), "abc");
        assert!(required_from(Some("1")) && required_from(Some("true")));
        assert!(!required_from(None) && !required_from(Some("")) && !required_from(Some("false")) && !required_from(Some("0")));
        let _ = required();
        set_running_version("v1.x");
        assert_eq!(running_version().as_deref(), Some("v1.x"));
        let _ = ConfigClient::from_env();
    }
}
