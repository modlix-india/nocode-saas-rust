//! A unit's registration: in the registry only while it can serve.
//!
//! - Nothing is registered until the first readiness check passes, so the gateway never sees an
//!   instance that would fail its first request.
//! - The lease is 10 seconds of renewal in a 30 second lease (the registry protocol's default is 30/90): a
//!   crashed instance leaves the registry within half a minute.
//! - A heartbeat answered 404 (the server restarted, or evicted us) registers again at once.
//! - Readiness keeps being checked with every heartbeat. Three failures in a row report DOWN, so
//!   traffic moves elsewhere; the next pass reports UP again.
//! - Shutdown: OUT_OF_SERVICE (the gateway drains the instance), a grace period for requests
//!   already on their way, then DELETE on every server.
//!
//! Register and heartbeat go to one server at a time (the one that answered last), and fall
//! over to the next when it is unreachable or failing; replication carries them to the others.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use indexmap::IndexMap;
use reqwest::StatusCode;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::wire::{DataCenterInfo, InstanceEnvelope, InstanceInfo, LeaseInfo, Metadata, PortInfo, Status};

/// A readiness check: `true` when the instance can take traffic.
pub type Check = Arc<dyn Fn() -> Pin<Box<dyn Future<Output = bool> + Send>> + Send + Sync>;

/// Consecutive failed readiness checks before the instance reports DOWN.
const DOWN_AFTER: u32 = 3;

pub struct Registration {
    app: String,
    port: u16,
    health_path: String,
    ip: String,
    instance_id: String,
    metadata: IndexMap<String, String>,
    servers: Vec<String>,
    token: Option<String>,
    renewal: Duration,
    lease: Duration,
    grace: Duration,
    ready_poll: Duration,
    check: Option<Check>,
    http: reqwest::Client,
    state: Mutex<State>,
    current: AtomicUsize,
    registered: AtomicBool,
}

struct State {
    status: Status,
    last_dirty: i64,
}

/// A registration for `app` listening on `port`, ready when `health_path` (`/readyz`) answers
/// 2xx on this machine. Servers come from `LIGHTHOUSE_URLS` (else the local Lighthouse) and the
/// token from `LIGHTHOUSE_TOKEN`; the builder methods change any of it.
pub fn registration(app: &str, port: u16, health_path: &str) -> Registration {
    let ip = local_ip_address::local_ip().map(|ip| ip.to_string()).unwrap_or_else(|_| "127.0.0.1".into());
    let host = std::env::var("HOSTNAME").ok().filter(|h| !h.is_empty()).unwrap_or_else(|| ip.clone());
    let health_path = if health_path.starts_with('/') { health_path.to_string() } else { format!("/{health_path}") };
    Registration {
        app: app.to_ascii_uppercase(),
        port,
        instance_id: format!("{host}:{}:{port}", app.to_ascii_lowercase()),
        health_path,
        ip,
        metadata: IndexMap::new(),
        servers: crate::servers_from_env(),
        token: crate::token_from_env(),
        renewal: Duration::from_secs(10),
        lease: Duration::from_secs(30),
        grace: Duration::from_secs(5),
        ready_poll: Duration::from_secs(1),
        check: None,
        http: reqwest::Client::builder().timeout(Duration::from_secs(5)).build().unwrap_or_default(),
        state: Mutex::new(State { status: Status::Starting, last_dirty: crate::now_millis() }),
        current: AtomicUsize::new(0),
        registered: AtomicBool::new(false),
    }
}

impl Registration {
    /// Lighthouse servers, in any of the forms [`crate::registry_base`] accepts.
    pub fn servers<I, S>(mut self, servers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let list: Vec<String> = servers.into_iter().map(|s| crate::registry_base(s.as_ref())).collect();
        if !list.is_empty() {
            self.servers = list;
        }
        self
    }

    pub fn token(mut self, token: Option<String>) -> Self {
        self.token = token.filter(|t| !t.is_empty());
        self
    }

    /// The address to advertise (default: this machine's primary address).
    pub fn ip(mut self, ip: &str) -> Self {
        if !ip.is_empty() {
            self.ip = ip.to_string();
        }
        self
    }

    pub fn instance_id(mut self, id: &str) -> Self {
        if !id.is_empty() {
            self.instance_id = id.to_string();
        }
        self
    }

    pub fn metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }

    /// How often to renew, and how long the server keeps the lease without a renewal.
    pub fn lease(mut self, renewal: Duration, lease: Duration) -> Self {
        self.renewal = renewal;
        self.lease = lease;
        self
    }

    /// How long to keep serving between OUT_OF_SERVICE and the DELETE.
    pub fn grace(mut self, grace: Duration) -> Self {
        self.grace = grace;
        self
    }

    /// How often to retry the readiness check before the first pass.
    pub fn ready_poll(mut self, every: Duration) -> Self {
        self.ready_poll = every;
        self
    }

    /// Checks readiness with `check` instead of asking `health_path` over HTTP.
    pub fn with_check<F, Fut>(mut self, check: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = bool> + Send + 'static,
    {
        let check = Arc::new(check);
        self.check = Some(Arc::new(move || {
            let check = check.clone();
            Box::pin(async move { check().await })
        }));
        self
    }

    pub fn app(&self) -> &str {
        &self.app
    }

    pub fn id(&self) -> &str {
        &self.instance_id
    }

    pub fn status(&self) -> Status {
        self.lock().status
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// What this instance registers as right now.
    pub fn instance(&self) -> InstanceInfo {
        let (status, last_dirty) = {
            let s = self.lock();
            (s.status, s.last_dirty)
        };
        let base = format!("http://{}:{}/", self.ip, self.port);
        let mut metadata = IndexMap::new();
        metadata.insert("management.port".to_string(), self.port.to_string());
        metadata.insert("runtime".to_string(), "rust".to_string());
        // Where a scraper that discovers this instance in the registry finds its metrics.
        metadata.insert("metrics.path".to_string(), "/metrics".to_string());
        metadata.extend(self.metadata.clone());
        let vip = self.app.to_ascii_lowercase();
        InstanceInfo {
            instance_id: self.instance_id.clone(),
            host_name: self.ip.clone(),
            app: self.app.clone(),
            ip_addr: self.ip.clone(),
            status,
            overridden_status: Status::Unknown,
            port: PortInfo { port: self.port, enabled: true },
            secure_port: PortInfo { port: 443, enabled: false },
            country_id: 1,
            data_center_info: DataCenterInfo::default(),
            lease_info: LeaseInfo {
                renewal_interval_in_secs: self.renewal.as_secs().max(1) as u32,
                duration_in_secs: self.lease.as_secs().max(1) as u32,
                ..LeaseInfo::default()
            },
            metadata: Metadata(metadata),
            home_page_url: Some(base.clone()),
            status_page_url: Some(format!("{base}healthz")),
            health_check_url: Some(format!("{base}{}", self.health_path.trim_start_matches('/'))),
            vip_address: Some(vip.clone()),
            secure_vip_address: Some(vip),
            last_updated_timestamp: crate::now_millis(),
            last_dirty_timestamp: last_dirty,
            ..InstanceInfo::default()
        }
    }

    /// Sends `build(server)` to the current server, then to the others in turn while a server
    /// is unreachable or answers 5xx. The server that answers becomes the current one.
    async fn send<F>(&self, build: F) -> Result<StatusCode>
    where
        F: Fn(&str) -> reqwest::RequestBuilder,
    {
        let n = self.servers.len();
        let start = self.current.load(Ordering::Relaxed);
        let mut last = anyhow!("no Lighthouse servers configured");
        for k in 0..n {
            let i = (start + k) % n;
            let mut req = build(&self.servers[i]);
            if let Some(t) = &self.token {
                req = req.bearer_auth(t);
            }
            match req.send().await {
                Ok(r) if r.status().is_server_error() => last = anyhow!("{}: {}", self.servers[i], r.status()),
                Ok(r) => {
                    self.current.store(i, Ordering::Relaxed);
                    return Ok(r.status());
                }
                Err(e) => last = anyhow!("{}: {e}", self.servers[i]),
            }
        }
        Err(last)
    }

    /// Registers with the current status.
    pub async fn register(&self) -> Result<()> {
        let body = InstanceEnvelope { instance: self.instance() };
        let status = self.send(|s| self.http.post(format!("{s}/apps/{}", self.app)).json(&body)).await;
        let ok = matches!(status, Ok(s) if s.is_success());
        self.registered.store(ok, Ordering::Relaxed);
        metrics::counter!("lighthouse_client_registrations_total", "result" => if ok { "ok" } else { "failed" }).increment(1);
        match status {
            Ok(s) if s.is_success() => Ok(()),
            Ok(s) => bail!("registration of {} answered {s}", self.instance_id),
            Err(e) => Err(e),
        }
    }

    /// Reports `status` (UP or DOWN) by registering again with a newer `lastDirtyTimestamp`, as
    /// a Lighthouse client does. Nothing is sent when the status is unchanged and registered.
    pub async fn set_status(&self, status: Status) -> Result<()> {
        let changed = {
            let mut s = self.lock();
            let changed = s.status != status;
            if changed {
                s.status = status;
                s.last_dirty = crate::now_millis().max(s.last_dirty + 1);
            }
            changed
        };
        if changed || !self.registered.load(Ordering::Relaxed) {
            tracing::info!(app = self.app, id = self.instance_id, %status, "reporting status to lighthouse");
            self.register().await
        } else {
            Ok(())
        }
    }

    /// Registers as UP.
    pub async fn up(&self) -> Result<()> {
        self.set_status(Status::Up).await
    }

    /// Renews the lease; a server that does not know the instance gets a registration instead.
    pub async fn heartbeat(&self) -> Result<()> {
        let (status, dirty) = {
            let s = self.lock();
            (s.status, s.last_dirty)
        };
        let path = format!("apps/{}/{}?status={status}&lastDirtyTimestamp={dirty}", self.app, self.instance_id);
        let result = self.send(|s| self.http.put(format!("{s}/{path}"))).await;
        let label = match &result {
            Ok(s) if s.is_success() => "ok",
            Ok(StatusCode::NOT_FOUND) => "not_found",
            _ => "failed",
        };
        metrics::counter!("lighthouse_client_heartbeats_total", "result" => label).increment(1);
        match result? {
            s if s.is_success() => Ok(()),
            StatusCode::NOT_FOUND => {
                tracing::info!(app = self.app, id = self.instance_id, "lighthouse does not know this instance, registering again");
                self.register().await
            }
            s => bail!("heartbeat of {} answered {s}", self.instance_id),
        }
    }

    /// Marks the instance OUT_OF_SERVICE on every server, so callers drain it.
    pub async fn out_of_service(&self) {
        let dirty = self.lock().last_dirty;
        for s in &self.servers {
            let url = format!("{s}/apps/{}/{}/status?value=OUT_OF_SERVICE&lastDirtyTimestamp={dirty}", self.app, self.instance_id);
            let _ = self.authed(self.http.put(url)).send().await;
        }
    }

    /// Removes the instance from every server.
    pub async fn deregister(&self) {
        for s in &self.servers {
            let url = format!("{s}/apps/{}/{}", self.app, self.instance_id);
            let _ = self.authed(self.http.delete(url)).send().await;
        }
        self.registered.store(false, Ordering::Relaxed);
    }

    fn authed(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.token {
            Some(t) => req.bearer_auth(t),
            None => req,
        }
    }

    /// Runs the readiness check: the configured one, else `GET http://127.0.0.1:<port><path>`.
    pub async fn check(&self) -> bool {
        if let Some(c) = &self.check {
            return c().await;
        }
        let url = format!("http://127.0.0.1:{}{}", self.port, self.health_path);
        matches!(self.http.get(url).timeout(Duration::from_secs(2)).send().await, Ok(r) if r.status().is_success())
    }

    /// The whole lifecycle in a task: waits for the first passing readiness check, registers
    /// UP, renews and re-checks every renewal interval, and when `shutdown` flips (or its sender
    /// goes away) runs OUT_OF_SERVICE, the grace period and the DELETE before returning.
    pub fn spawn(self, shutdown: watch::Receiver<bool>) -> JoinHandle<()> {
        tokio::spawn(async move { self.run(shutdown).await })
    }

    async fn run(&self, mut shutdown: watch::Receiver<bool>) {
        loop {
            if *shutdown.borrow() {
                return;
            }
            if self.check().await {
                break;
            }
            tokio::select! {
                _ = tokio::time::sleep(self.ready_poll) => {}
                _ = shutdown.changed() => return,
            }
        }
        if let Err(e) = self.up().await {
            tracing::warn!(app = self.app, error = %e, "lighthouse registration failed, retrying with the next heartbeat");
        } else {
            tracing::info!(app = self.app, id = self.instance_id, "registered with lighthouse");
        }
        let mut failures = 0u32;
        let mut tick = tokio::time::interval(self.renewal);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tick.tick().await;
        loop {
            tokio::select! {
                _ = tick.tick() => {}
                _ = shutdown.changed() => break,
            }
            self.renew_once(&mut failures).await;
        }
        self.out_of_service().await;
        tokio::time::sleep(self.grace).await;
        self.deregister().await;
        tracing::info!(app = self.app, id = self.instance_id, "left lighthouse");
    }

    /// One renewal round: readiness first (it may change the status), then the heartbeat.
    async fn renew_once(&self, failures: &mut u32) {
        let reported = if self.check().await {
            *failures = 0;
            (self.status() != Status::Up).then_some(Status::Up)
        } else {
            *failures += 1;
            (*failures >= DOWN_AFTER && self.status() == Status::Up).then_some(Status::Down)
        };
        let result = match reported {
            Some(status) => self.set_status(status).await,
            None if !self.registered.load(Ordering::Relaxed) => self.register().await,
            None => self.heartbeat().await,
        };
        if let Err(e) = result {
            tracing::warn!(app = self.app, error = %e, "lighthouse heartbeat failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::{Path, Query, State};
    use axum::http::StatusCode as Http;
    use axum::routing::{get, post, put};
    use axum::Router;
    use std::collections::HashMap;
    use std::sync::atomic::AtomicU32;

    #[derive(Default)]
    struct Fake {
        calls: Mutex<Vec<String>>,
        /// Heartbeats answer 404 this many times.
        forget: AtomicU32,
        /// Every call answers 500.
        broken: AtomicBool,
    }

    impl Fake {
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
        /// Records a call the server accepted; a broken server records nothing.
        fn log(&self, s: String) -> Http {
            if self.broken.load(Ordering::SeqCst) {
                return Http::INTERNAL_SERVER_ERROR;
            }
            self.calls.lock().unwrap().push(s);
            Http::OK
        }
    }

    async fn fake() -> (String, Arc<Fake>) {
        let f = Arc::new(Fake::default());
        let app = Router::new()
            .route(
                "/eureka/apps/{app}",
                post(|Path(app): Path<String>, State(f): State<Arc<Fake>>, body: String| async move {
                    let v: InstanceEnvelope = serde_json::from_str(&body).unwrap();
                    let s = f.log(format!("register {app} {}", v.instance.status));
                    if s == Http::OK { Http::NO_CONTENT } else { s }
                }),
            )
            .route(
                "/eureka/apps/{app}/{id}",
                put(|Path((app, id)): Path<(String, String)>, Query(q): Query<HashMap<String, String>>, State(f): State<Arc<Fake>>| async move {
                    if id == "bad" {
                        return Http::BAD_REQUEST;
                    }
                    let s = f.log(format!("heartbeat {app} {}", q["status"]));
                    if f.forget.load(Ordering::SeqCst) > 0 {
                        f.forget.fetch_sub(1, Ordering::SeqCst);
                        return Http::NOT_FOUND;
                    }
                    s
                })
                .delete(|Path((app, _)): Path<(String, String)>, State(f): State<Arc<Fake>>| async move {
                    f.log(format!("delete {app}"))
                }),
            )
            .route(
                "/eureka/apps/{app}/{id}/status",
                put(|Path((app, _)): Path<(String, String)>, Query(q): Query<HashMap<String, String>>, State(f): State<Arc<Fake>>| async move {
                    f.log(format!("status {app} {}", q["value"]))
                }),
            )
            .route("/readyz", get(|| async { Http::OK }))
            .with_state(f.clone());
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}/eureka/", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (base, f)
    }

    fn quick(r: Registration) -> Registration {
        r.lease(Duration::from_millis(40), Duration::from_secs(1))
            .grace(Duration::from_millis(10))
            .ready_poll(Duration::from_millis(10))
            .ip("10.9.9.9")
            .token(Some("t".into()))
    }

    async fn wait_for(f: &Fake, what: &str) {
        for _ in 0..300 {
            if f.calls().iter().any(|c| c == what) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("never saw {what:?} in {:?}", f.calls());
    }

    #[tokio::test]
    async fn the_instance_it_sends() {
        let r = registration("files", 8104, "readyz").instance_id("x:files:8104").metadata("configVersion", "v1");
        let r = quick(r).servers(Vec::<String>::new()).ip("");
        assert_eq!((r.app(), r.id()), ("FILES", "x:files:8104"));
        let i = r.instance();
        assert_eq!(i.status, Status::Starting);
        assert_eq!(i.ip_addr, "10.9.9.9");
        assert_eq!(i.health_check_url.as_deref(), Some("http://10.9.9.9:8104/readyz"));
        assert_eq!(i.lease_info.renewal_interval_in_secs, 1, "never below a second on the wire");
        assert_eq!(i.lease_info.duration_in_secs, 1);
        let keys: Vec<&String> = i.metadata.0.keys().collect();
        assert_eq!(keys, ["management.port", "runtime", "metrics.path", "configVersion"]);
        assert_eq!(i.metadata.0["metrics.path"], "/metrics");
        let moved = quick(registration("files", 8104, "readyz")).metadata("metrics.path", "/m");
        assert_eq!(moved.instance().metadata.0["metrics.path"], "/m", "a unit can move it");
        assert_eq!(r.servers, crate::servers_from_env(), "an empty list keeps the default");
        assert_eq!(registration("a", 1, "/readyz").instance_id("").health_path, "/readyz");
    }

    #[tokio::test]
    async fn waits_for_readiness_then_registers_renews_and_leaves() {
        let (base, f) = fake().await;
        let ready = Arc::new(AtomicBool::new(false));
        let r2 = ready.clone();
        // The first server is down: everything falls over to the second.
        let r = quick(registration("files", 8104, "/readyz"))
            .servers(["http://127.0.0.1:1", base.as_str()])
            .with_check(move || {
                let ok = r2.load(Ordering::SeqCst);
                async move { ok }
            });
        let (tx, rx) = watch::channel(false);
        let task = r.spawn(rx);
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(f.calls().is_empty(), "nothing before the first readiness pass");

        ready.store(true, Ordering::SeqCst);
        wait_for(&f, "register FILES UP").await;
        wait_for(&f, "heartbeat FILES UP").await;

        // Three failed checks report DOWN; the next pass reports UP again.
        ready.store(false, Ordering::SeqCst);
        wait_for(&f, "register FILES DOWN").await;
        let downs = f.calls().iter().filter(|c| c.as_str() == "register FILES DOWN").count();
        assert_eq!(downs, 1, "reported once, not on every failed check");
        ready.store(true, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(f.calls().iter().filter(|c| c.as_str() == "register FILES UP").count(), 2);

        // A heartbeat the server does not know registers again.
        f.forget.store(1, Ordering::SeqCst);
        let before = f.calls().iter().filter(|c| c.as_str() == "register FILES UP").count();
        for _ in 0..100 {
            if f.calls().iter().filter(|c| c.as_str() == "register FILES UP").count() > before {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(f.calls().iter().filter(|c| c.as_str() == "register FILES UP").count() > before);

        tx.send(true).unwrap();
        task.await.unwrap();
        let calls = f.calls();
        let n = calls.len();
        assert_eq!(&calls[n - 2..], ["status FILES OUT_OF_SERVICE", "delete FILES"]);
    }

    #[tokio::test]
    async fn http_readiness_and_shutdown_before_ready() {
        let (base, f) = fake().await;
        let port: u16 = base.trim_start_matches("http://127.0.0.1:").split('/').next().unwrap().parse().unwrap();
        // The default check asks GET /readyz on this machine: the fake answers it.
        let r = quick(registration("svc", port, "/readyz")).servers([base.as_str()]);
        assert!(r.check().await);
        let r = quick(registration("svc", port, "/nothing")).servers([base.as_str()]);
        assert!(!r.check().await);
        let (tx, rx) = watch::channel(false);
        let task = r.spawn(rx);
        tokio::time::sleep(Duration::from_millis(50)).await;
        tx.send(true).unwrap();
        task.await.unwrap();
        assert!(f.calls().is_empty(), "never ready: never registered, nothing to undo");

        let (tx, rx) = watch::channel(true);
        quick(registration("svc", port, "/readyz")).servers([base.as_str()]).spawn(rx).await.unwrap();
        drop(tx);
        assert!(f.calls().is_empty(), "already shutting down");
    }

    #[tokio::test]
    async fn failures_are_reported_and_retried() {
        let (base, f) = fake().await;
        f.broken.store(true, Ordering::SeqCst);
        let r = quick(registration("svc", 1, "/readyz")).servers([base.as_str()]).with_check(|| async { true });
        assert!(r.register().await.unwrap_err().to_string().contains("500"));
        assert!(r.heartbeat().await.is_err());
        let none = quick(registration("svc", 1, "/readyz")).servers(["http://127.0.0.1:1"]);
        assert!(none.up().await.is_err());
        assert!(none.heartbeat().await.is_err());

        // A 4xx that is not 404 is an error, without falling over.
        let (base2, f2) = fake().await;
        let odd = quick(registration("svc", 1, "/readyz")).servers([base2.as_str()]).instance_id("bad");
        assert!(odd.heartbeat().await.is_err());
        assert!(f2.calls().is_empty());

        // The lifecycle keeps going while the server fails, and registers once it recovers.
        let (tx, rx) = watch::channel(false);
        let task = r.spawn(rx);
        tokio::time::sleep(Duration::from_millis(100)).await;
        f.broken.store(false, Ordering::SeqCst);
        wait_for(&f, "register SVC UP").await;
        // Unchanged and registered: set_status sends nothing.
        tx.send(true).unwrap();
        task.await.unwrap();
        assert_eq!(f.calls().last().unwrap(), "delete SVC");

        let r = quick(registration("svc", 1, "/readyz")).servers([base.as_str()]);
        r.up().await.unwrap();
        let n = f.calls().len();
        r.set_status(Status::Up).await.unwrap();
        assert_eq!(f.calls().len(), n, "no change, no call");
    }
}
