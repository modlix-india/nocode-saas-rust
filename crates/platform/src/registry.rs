//! The Lighthouse registry client: registers this unit under `[registry] register_as`, renews it,
//! and lists the instances a `lighthouse:<APP>` upstream follows (blue/green included).
//!
//! The wire format is the one a Spring Boot instance sends (see `GET /eureka/apps/FILES`), which
//! Lighthouse and the Python services' client both speak.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Result};
use dashmap::DashMap;
use serde_json::{json, Value};
use tokio::sync::watch;

use crate::config::RegistryConfig;

#[derive(Debug, Clone)]
pub struct InstanceInfo {
    pub app: String,
    pub instance_id: String,
    pub ip: String,
    pub port: u16,
}

#[derive(Clone)]
pub struct Registry {
    inner: Arc<Inner>,
}

struct Inner {
    zones: Vec<String>,
    http: reqwest::Client,
    me: Option<InstanceInfo>,
    /// App name (upper case) to its UP base URLs, refreshed in the background.
    apps: DashMap<String, Vec<String>>,
    /// Apps to keep refreshed.
    watched: DashMap<String, ()>,
    round_robin: AtomicUsize,
}

impl Registry {
    /// Builds the client and starts the background refresh of watched apps. Registration starts
    /// with [`Registry::spawn_lifecycle`] when `cfg.register` is set.
    pub fn new(cfg: &RegistryConfig, port: u16) -> Result<Self> {
        let zones: Vec<String> = if cfg.zones.is_empty() {
            vec!["http://localhost:9999/eureka/".into()]
        } else {
            cfg.zones.clone()
        }
        .into_iter()
        .map(|z| {
            let z = z.trim().to_string();
            if z.ends_with('/') { z } else { format!("{z}/") }
        })
        .collect();

        let me = (cfg.register && !cfg.register_as.is_empty()).then(|| {
            let ip = Some(cfg.instance_ip.clone())
                .filter(|s| !s.is_empty())
                .or_else(|| local_ip_address::local_ip().ok().map(|ip| ip.to_string()))
                .unwrap_or_else(|| "127.0.0.1".into());
            let host = std::env::var("HOSTNAME").unwrap_or_else(|_| ip.clone());
            InstanceInfo {
                app: cfg.register_as.to_ascii_uppercase(),
                instance_id: format!("{host}:{}:{port}", cfg.register_as.to_ascii_lowercase()),
                ip,
                port,
            }
        });

        let this = Self {
            inner: Arc::new(Inner {
                zones,
                http: reqwest::Client::builder()
                    .timeout(Duration::from_secs(5))
                    .build()?,
                me,
                apps: DashMap::new(),
                watched: DashMap::new(),
                round_robin: AtomicUsize::new(0),
            }),
        };
        this.spawn_discovery();
        Ok(this)
    }

    /// Keeps `app`'s instance list fresh from now on.
    pub fn watch(&self, app: &str) {
        self.inner.watched.insert(app.to_ascii_uppercase(), ());
    }

    pub fn me(&self) -> Option<&InstanceInfo> {
        self.inner.me.as_ref()
    }

    fn instance_body(me: &InstanceInfo) -> Value {
        let base = format!("http://{}:{}/", me.ip, me.port);
        let now = now_millis().to_string();
        let mut metadata = json!({"management.port": me.port.to_string(), "runtime": "rust", "metrics.path": "/metrics"});
        // The configuration version from Lighthouse this process runs: keepup-rust.sh and the
        // dashboard compare it with the current one.
        if let Some(v) = lighthouse_client::config::running_version() {
            metadata["configVersion"] = json!(v);
        }
        json!({
            "instance": {
                "instanceId": me.instance_id,
                "hostName": me.ip,
                "app": me.app,
                "ipAddr": me.ip,
                "status": "UP",
                "overriddenStatus": "UNKNOWN",
                "port": {"$": me.port, "@enabled": "true"},
                "securePort": {"$": 443, "@enabled": "false"},
                "countryId": 1,
                "dataCenterInfo": {
                    "@class": "com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo",
                    "name": "MyOwn"
                },
                "leaseInfo": {"renewalIntervalInSecs": 30, "durationInSecs": 90},
                // `metrics.path`: where a scraper that discovers instances here finds the metrics.
                "metadata": metadata,
                "homePageUrl": base,
                "statusPageUrl": format!("{base}healthz"),
                "healthCheckUrl": format!("{base}readyz"),
                "vipAddress": me.app.to_ascii_lowercase(),
                "secureVipAddress": me.app.to_ascii_lowercase(),
                "isCoordinatingDiscoveryServer": "false",
                "lastUpdatedTimestamp": now,
                "lastDirtyTimestamp": now
            }
        })
    }

    async fn register(&self) -> Result<()> {
        let Some(me) = &self.inner.me else { return Ok(()) };
        let body = Self::instance_body(me);
        let mut last = None;
        for zone in &self.inner.zones {
            let url = format!("{zone}apps/{}", me.app);
            match self.inner.http.post(&url).json(&body).send().await {
                Ok(r) if r.status().is_success() => return Ok(()),
                Ok(r) => last = Some(anyhow!("{url}: {}", r.status())),
                Err(e) => last = Some(anyhow!("{url}: {e}")),
            }
        }
        Err(last.unwrap_or_else(|| anyhow!("no lighthouse zones configured")))
    }

    async fn heartbeat(&self) -> Result<()> {
        let Some(me) = &self.inner.me else { return Ok(()) };
        for zone in &self.inner.zones {
            let url = format!("{zone}apps/{}/{}?status=UP", me.app, me.instance_id);
            match self.inner.http.put(&url).send().await {
                Ok(r) if r.status().is_success() => return Ok(()),
                // Lighthouse forgot us (it restarted, or evicted a lease): register again.
                Ok(r) if r.status() == reqwest::StatusCode::NOT_FOUND => return self.register().await,
                Ok(r) => tracing::warn!(url, status = %r.status(), "lighthouse heartbeat rejected"),
                Err(e) => tracing::warn!(url, error = %e, "lighthouse heartbeat failed"),
            }
        }
        bail!("heartbeat failed on every zone")
    }

    pub async fn deregister(&self) {
        let Some(me) = &self.inner.me else { return };
        for zone in &self.inner.zones {
            let url = format!("{zone}apps/{}/{}", me.app, me.instance_id);
            let _ = self.inner.http.delete(&url).send().await;
        }
    }

    /// Registers (retrying until it works), then heartbeats every 30 seconds until `shutdown`
    /// flips, when it deregisters so the gateway stops sending traffic immediately instead of
    /// after the 90 second lease runs out.
    pub fn spawn_lifecycle(&self, mut shutdown: watch::Receiver<bool>) -> tokio::task::JoinHandle<()> {
        let this = self.clone();
        tokio::spawn(async move {
            if this.inner.me.is_none() {
                return;
            }
            loop {
                match this.register().await {
                    Ok(()) => {
                        tracing::info!(app = ?this.me().map(|m| &m.app), "registered with lighthouse");
                        break;
                    }
                    Err(e) => tracing::warn!(error = %e, "lighthouse registration failed, retrying"),
                }
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(10)) => {}
                    _ = shutdown.changed() => return,
                }
            }
            let mut tick = tokio::time::interval(Duration::from_secs(30));
            tick.tick().await;
            loop {
                tokio::select! {
                    _ = tick.tick() => { let _ = this.heartbeat().await; }
                    _ = shutdown.changed() => {
                        this.deregister().await;
                        tracing::info!("deregistered from lighthouse");
                        return;
                    }
                }
            }
        })
    }

    /// Refreshes every watched app every 30 seconds, like a Spring client.
    fn spawn_discovery(&self) {
        let this = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(30));
            loop {
                tick.tick().await;
                let apps: Vec<String> = this.inner.watched.iter().map(|e| e.key().clone()).collect();
                for app in apps {
                    if let Err(e) = this.refresh(&app).await {
                        tracing::warn!(app, error = %e, "lighthouse lookup failed, keeping the last list");
                    }
                }
            }
        });
    }

    /// Every UP base URL of `app` right now.
    pub async fn instances(&self, app: &str) -> Result<Vec<String>> {
        let app = app.to_ascii_uppercase();
        self.watch(&app);
        if !self.inner.apps.contains_key(&app) {
            self.refresh(&app).await?;
        }
        Ok(self.inner.apps.get(&app).map(|v| v.clone()).unwrap_or_default())
    }

    /// Fetches `app`'s instances now (the background loop does this every 30 seconds).
    pub async fn refresh(&self, app: &str) -> Result<()> {
        let mut last = None;
        for zone in &self.inner.zones {
            let url = format!("{zone}apps/{app}");
            match self
                .inner
                .http
                .get(&url)
                .header("Accept", "application/json")
                .send()
                .await
            {
                Ok(r) if r.status().is_success() => {
                    let body: Value = r.json().await?;
                    let urls = parse_instances(&body);
                    self.inner.apps.insert(app.to_string(), urls);
                    return Ok(());
                }
                Ok(r) if r.status() == reqwest::StatusCode::NOT_FOUND => {
                    self.inner.apps.insert(app.to_string(), vec![]);
                    return Ok(());
                }
                Ok(r) => last = Some(anyhow!("{url}: {}", r.status())),
                Err(e) => last = Some(anyhow!("{url}: {e}")),
            }
        }
        Err(last.unwrap_or_else(|| anyhow!("no lighthouse zones configured")))
    }

    /// A base URL (`http://ip:port`) of an UP instance of `app`, round robin.
    pub async fn resolve(&self, app: &str) -> Result<String> {
        let app = app.to_ascii_uppercase();
        self.watch(&app);
        if !self.inner.apps.contains_key(&app) {
            self.refresh(&app).await?;
        }
        let urls = self
            .inner
            .apps
            .get(&app)
            .map(|v| v.clone())
            .unwrap_or_default();
        if urls.is_empty() {
            bail!("no UP instance of {app} in lighthouse");
        }
        let i = self.inner.round_robin.fetch_add(1, Ordering::Relaxed);
        Ok(urls[i % urls.len()].clone())
    }
}

/// `application.instance` is an array normally, but older registry servers send a lone instance
/// as an object.
fn parse_instances(body: &Value) -> Vec<String> {
    let inst = &body["application"]["instance"];
    let list: Vec<&Value> = match inst {
        Value::Array(a) => a.iter().collect(),
        Value::Object(_) => vec![inst],
        _ => vec![],
    };
    list.into_iter()
        .filter(|i| i["status"] == "UP")
        .filter_map(|i| {
            let ip = i["ipAddr"].as_str()?;
            let port = match &i["port"]["$"] {
                Value::Number(n) => n.as_u64()?,
                Value::String(s) => s.parse().ok()?,
                _ => return None,
            };
            Some(format!("http://{ip}:{port}"))
        })
        .collect()
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeRegistry {
        calls: Mutex<Vec<String>>,
        /// Heartbeats answer 404 this many times (Lighthouse forgot the lease).
        forget: Mutex<u32>,
    }

    async fn fake_registry() -> (String, Arc<FakeRegistry>) {
        use axum::extract::{Path, State};
        use axum::http::StatusCode;
        use axum::routing::{get, post, put};
        let f = Arc::new(FakeRegistry::default());
        let app = axum::Router::new()
            .route(
                "/eureka/apps/{app}",
                post(|Path(app): Path<String>, State(f): State<Arc<FakeRegistry>>, body: String| async move {
                    let v: Value = serde_json::from_str(&body).unwrap();
                    assert_eq!(v["instance"]["app"], app);
                    f.calls.lock().unwrap().push(format!("register {app}"));
                    StatusCode::NO_CONTENT
                })
                .get(|Path(app): Path<String>| async move {
                    if app == "NONE" {
                        return StatusCode::NOT_FOUND.into_response();
                    }
                    if app == "BROKEN" {
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                    axum::Json(json!({"application": {"instance": [
                        {"ipAddr": "10.0.0.1", "port": {"$": 1}, "status": "UP"},
                        {"ipAddr": "10.0.0.2", "port": {"$": 2}, "status": "UP"}
                    ]}}))
                    .into_response()
                }),
            )
            .route(
                "/eureka/apps/{app}/{id}",
                put(|Path((app, _)): Path<(String, String)>, State(f): State<Arc<FakeRegistry>>| async move {
                    let mut forget = f.forget.lock().unwrap();
                    f.calls.lock().unwrap().push(format!("heartbeat {app}"));
                    if *forget > 0 {
                        *forget -= 1;
                        return StatusCode::NOT_FOUND;
                    }
                    StatusCode::OK
                })
                .delete(|Path((app, _)): Path<(String, String)>, State(f): State<Arc<FakeRegistry>>| async move {
                    f.calls.lock().unwrap().push(format!("deregister {app}"));
                    StatusCode::OK
                }),
            )
            .route("/eureka/health", get(|| async { "ok" }))
            .with_state(f.clone());
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}/eureka", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (base, f)
    }

    use axum::response::IntoResponse;

    #[tokio::test]
    async fn registers_heartbeats_and_deregisters() {
        let (base, f) = fake_registry().await;
        // The first zone is down: registration falls through to the next.
        let cfg = RegistryConfig {
            register: true,
            register_as: "files".into(),
            zones: vec!["http://127.0.0.1:1/eureka".into(), base],
            instance_ip: "10.1.1.1".into(),
        };
        let e = Registry::new(&cfg, 8104).unwrap();
        let me = e.me().unwrap();
        assert_eq!((me.app.as_str(), me.ip.as_str(), me.port), ("FILES", "10.1.1.1", 8104));
        assert!(me.instance_id.ends_with(":files:8104"));
        let body = Registry::instance_body(me);
        assert_eq!(body["instance"]["healthCheckUrl"], "http://10.1.1.1:8104/readyz");
        assert_eq!(body["instance"]["metadata"]["metrics.path"], "/metrics");
        lighthouse_client::config::set_running_version("0123456789abcdef.01234567");
        assert_eq!(Registry::instance_body(me)["instance"]["metadata"]["configVersion"], "0123456789abcdef.01234567");

        e.register().await.unwrap();
        e.heartbeat().await.unwrap();
        *f.forget.lock().unwrap() = 1;
        e.heartbeat().await.unwrap();
        let calls = f.calls.lock().unwrap().clone();
        assert_eq!(calls, vec!["register FILES", "heartbeat FILES", "heartbeat FILES", "register FILES"]);

        let (tx, rx) = watch::channel(false);
        let h = e.spawn_lifecycle(rx);
        for _ in 0..50 {
            if f.calls.lock().unwrap().len() >= 5 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        tx.send(true).unwrap();
        h.await.unwrap();
        assert_eq!(f.calls.lock().unwrap().last().unwrap(), "deregister FILES");
    }

    #[tokio::test]
    async fn discovers_and_round_robins() {
        let (base, _) = fake_registry().await;
        let e = Registry::new(&RegistryConfig { zones: vec![base], ..Default::default() }, 0).unwrap();
        assert!(e.me().is_none());
        e.register().await.unwrap();
        e.heartbeat().await.unwrap();
        e.deregister().await;
        let (tx, rx) = watch::channel(false);
        e.spawn_lifecycle(rx).await.unwrap();
        drop(tx);

        let a = e.resolve("svc").await.unwrap();
        let b = e.resolve("SVC").await.unwrap();
        assert_ne!(a, b);
        assert_eq!(e.instances("svc").await.unwrap().len(), 2);
        assert!(e.resolve("NONE").await.is_err(), "no UP instance");
        assert!(e.refresh("BROKEN").await.is_err());

        let none = Registry::new(&RegistryConfig { zones: vec!["http://127.0.0.1:1/eureka/".into()], ..Default::default() }, 0).unwrap();
        assert!(none.resolve("svc").await.is_err());
        let default_zone = Registry::new(&RegistryConfig::default(), 0).unwrap();
        assert_eq!(default_zone.inner.zones, vec!["http://localhost:9999/eureka/"]);
    }

    #[tokio::test]
    async fn registration_failures_are_errors() {
        let cfg = RegistryConfig {
            register: true,
            register_as: "x".into(),
            zones: vec!["http://127.0.0.1:1/eureka/".into()],
            instance_ip: String::new(),
        };
        let e = Registry::new(&cfg, 1).unwrap();
        assert!(!e.me().unwrap().ip.is_empty(), "falls back to this machine's address");
        assert!(e.register().await.is_err());
        assert!(e.heartbeat().await.is_err());
        let (tx, rx) = watch::channel(false);
        let h = e.spawn_lifecycle(rx);
        tokio::time::sleep(Duration::from_millis(50)).await;
        tx.send(true).unwrap();
        h.await.unwrap();
    }

    #[test]
    fn parses_array_and_single_instance() {
        let arr = json!({"application": {"instance": [
            {"ipAddr": "10.0.0.1", "port": {"$": 8003}, "status": "UP"},
            {"ipAddr": "10.0.0.2", "port": {"$": "8203"}, "status": "DOWN"}
        ]}});
        assert_eq!(parse_instances(&arr), vec!["http://10.0.0.1:8003"]);

        let one = json!({"application": {"instance":
            {"ipAddr": "10.0.0.3", "port": {"$": 9003}, "status": "UP"}}});
        assert_eq!(parse_instances(&one), vec!["http://10.0.0.3:9003"]);
    }
}
