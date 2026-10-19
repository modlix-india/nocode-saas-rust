//! The metrics every unit exports besides the request histogram ([`crate::http::observe`]): the
//! process, the Tokio runtime, the build, the database pools and the calls to other services,
//! plus what a unit needs to export counters of its own and to test them. Everything goes through
//! the `metrics` facade to the Prometheus recorder [`crate::telemetry::init`] installs, so it
//! shows on `/metrics` with the `service`, `instance` and `environment` labels.
//! `deploy/METRICS.md` lists every family.
//!
//! Gauges that read a current value (the process, the runtime, the pools) are read when
//! `/metrics` is scraped ([`collect`]), so they are exactly as fresh as the scrape.

use std::borrow::Cow;
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Instant;

use metrics::{describe_counter, describe_gauge, describe_histogram, Unit};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder};
use sqlx::mysql::MySqlPool;

use crate::telemetry::{HTTP_BUCKETS, HTTP_DURATION};

/// Calls to other services (OpenTelemetry's `http.client.request.duration`).
pub const HTTP_CLIENT_DURATION: &str = "http_client_request_duration_seconds";
pub const BUILD_INFO: &str = "build_info";
/// Open connections of a pool by state (`idle`, `used`), OpenTelemetry's
/// `db.client.connection.count`.
pub const DB_CONNECTIONS: &str = "db_client_connection_count";
/// The most connections a pool opens (`db.client.connection.max`).
pub const DB_CONNECTIONS_MAX: &str = "db_client_connection_max";
pub const REDIS_ERRORS: &str = "redis_errors_total";
pub const TOKIO_WORKERS: &str = "tokio_runtime_workers";
pub const TOKIO_ALIVE_TASKS: &str = "tokio_runtime_alive_tasks";
pub const TOKIO_GLOBAL_QUEUE: &str = "tokio_runtime_global_queue_depth";

type Collector = Box<dyn Fn() + Send + Sync>;

static COLLECTORS: Mutex<Vec<Collector>> = Mutex::new(Vec::new());
static MYSQL_POOLS: Mutex<Vec<(String, MySqlPool, u32)>> = Mutex::new(Vec::new());
static MONGO_POOLS: Mutex<Vec<(String, Arc<PoolCounts>, u32)>> = Mutex::new(Vec::new());
/// Set once this process serves `/metrics` ([`start`]). Pools are watched only then: a watched
/// pool is kept open for the life of the process, which a test that opens and drops pools must
/// not pay for.
static SERVING: AtomicBool = AtomicBool::new(false);
static PROCESS: OnceLock<metrics_process::Collector> = OnceLock::new();

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn process() -> &'static metrics_process::Collector {
    PROCESS.get_or_init(metrics_process::Collector::default)
}

/// Called by [`crate::telemetry::init`] once the recorder is installed: the descriptions, the
/// build, and pools watched from now on.
pub(crate) fn start(service: &str) {
    SERVING.store(true, Ordering::Relaxed);
    describe();
    build_info(service, &commit(option_env!("GIT_SHA"), std::env::var("GIT_SHA").ok()));
}

/// Whether this process serves `/metrics`.
pub fn serving() -> bool {
    SERVING.load(Ordering::Relaxed)
}

/// `build_info{service,version,commit} 1`. The version is the workspace's; the commit is the
/// `GIT_SHA` the binary was compiled with (CI sets it), else the one in its environment.
pub fn build_info(service: &str, commit: &str) {
    metrics::gauge!(BUILD_INFO, "service" => service.to_string(), "version" => env!("CARGO_PKG_VERSION"), "commit" => commit.to_string())
        .set(1.0);
}

/// The first of the build-time and the run-time commit that is set, else `unknown`.
pub fn commit(built: Option<&str>, running: Option<String>) -> String {
    built
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map(str::to_string)
        .or_else(|| running.map(|c| c.trim().to_string()).filter(|c| !c.is_empty()))
        .unwrap_or_else(|| "unknown".into())
}

/// Reads the scrape-time gauges: the process, the runtime this is called on, and every
/// collector a unit added with [`on_scrape`]. `/metrics` calls it before rendering.
pub fn collect() {
    process().collect();
    if let Ok(rt) = tokio::runtime::Handle::try_current() {
        let m = rt.metrics();
        metrics::gauge!(TOKIO_WORKERS).set(m.num_workers() as f64);
        metrics::gauge!(TOKIO_ALIVE_TASKS).set(m.num_alive_tasks() as f64);
        metrics::gauge!(TOKIO_GLOBAL_QUEUE).set(m.global_queue_depth() as f64);
    }
    collect_mysql();
    collect_mongo();
    for c in lock(&COLLECTORS).iter() {
        c();
    }
}

/// Runs `f` on every scrape, for a gauge a unit reads from something it holds (a queue's length,
/// a connection's state).
pub fn on_scrape(f: impl Fn() + Send + Sync + 'static) {
    lock(&COLLECTORS).push(Box::new(f));
}

fn describe() {
    process().describe();
    describe_gauge!(BUILD_INFO, "Always 1: the service, its version and the commit it was built from.");
    describe_gauge!(TOKIO_WORKERS, Unit::Count, "Worker threads of the Tokio runtime.");
    describe_gauge!(TOKIO_ALIVE_TASKS, Unit::Count, "Tasks alive in the Tokio runtime.");
    describe_gauge!(TOKIO_GLOBAL_QUEUE, Unit::Count, "Tasks waiting in the Tokio runtime's global queue.");
    describe_gauge!(DB_CONNECTIONS, Unit::Count, "Open connections of a database pool, by state (idle, used).");
    describe_gauge!(DB_CONNECTIONS_MAX, Unit::Count, "The most connections a database pool opens.");
    describe_histogram!(HTTP_DURATION, Unit::Seconds, "Requests this service answered, by method, route template and status.");
    describe_histogram!(HTTP_CLIENT_DURATION, Unit::Seconds, "Calls to other services until their response headers, by target, method and status.");
    describe_counter!(REDIS_ERRORS, Unit::Count, "Redis connections and commands that failed, by operation.");
    describe_counter!(crate::error::CODED_ERRORS, Unit::Count, "Coded errors this service answered with, by code and status.");
    describe_counter!(crate::cache::CACHE_GETS, Unit::Count, "Local cache lookups, by cache and result (hit, miss).");
    describe_counter!(crate::cache::CACHE_EVICTIONS, Unit::Count, "Local cache entries dropped for size or age, by cache.");
}

// ------------------------------------------------------------------------------------ pools ---

/// Exports a MySQL pool from now on, under `name` (its database); pools of the same name add up.
/// The pool stays open for the life of the process: [`crate::db::mysql_pool`] calls this only
/// when the process serves metrics ([`serving`]).
pub fn watch_mysql_pool(name: &str, pool: &MySqlPool, max: u32) {
    lock(&MYSQL_POOLS).push((name.to_string(), pool.clone(), max));
}

fn collect_mysql() {
    let mut by_name: Vec<(String, u32, u32, u32)> = Vec::new();
    for (name, pool, max) in lock(&MYSQL_POOLS).iter() {
        let size = pool.size();
        let idle = (pool.num_idle() as u32).min(size);
        add_up(&mut by_name, name, size - idle, idle, *max);
    }
    for (name, used, idle, max) in by_name {
        set_pool("mysql", name, used as f64, idle as f64, max as f64);
    }
}

fn add_up(by_name: &mut Vec<(String, u32, u32, u32)>, name: &str, used: u32, idle: u32, max: u32) {
    match by_name.iter_mut().find(|(n, ..)| n == name) {
        Some(e) => {
            e.1 += used;
            e.2 += idle;
            e.3 += max;
        }
        None => by_name.push((name.to_string(), used, idle, max)),
    }
}

fn set_pool(system: &'static str, name: String, used: f64, idle: f64, max: f64) {
    metrics::gauge!(DB_CONNECTIONS, "system" => system, "pool" => name.clone(), "state" => "used").set(used);
    metrics::gauge!(DB_CONNECTIONS, "system" => system, "pool" => name.clone(), "state" => "idle").set(idle);
    metrics::gauge!(DB_CONNECTIONS_MAX, "system" => system, "pool" => name).set(max);
}

/// A pool's connections as its driver reports them in events (the MongoDB driver's CMAP
/// events): opened and closed, checked out and back in.
#[derive(Debug, Default)]
pub struct PoolCounts {
    open: AtomicI64,
    used: AtomicI64,
}

impl PoolCounts {
    pub fn opened(&self) {
        self.open.fetch_add(1, Ordering::Relaxed);
    }
    pub fn closed(&self) {
        self.open.fetch_sub(1, Ordering::Relaxed);
    }
    pub fn checked_out(&self) {
        self.used.fetch_add(1, Ordering::Relaxed);
    }
    pub fn checked_in(&self) {
        self.used.fetch_sub(1, Ordering::Relaxed);
    }
    /// Connections in use, and idle in the pool.
    pub fn used_idle(&self) -> (u32, u32) {
        let open = self.open.load(Ordering::Relaxed).max(0);
        let used = self.used.load(Ordering::Relaxed).clamp(0, open);
        (used as u32, (open - used) as u32)
    }
}

/// The counts for a MongoDB pool on `name` (its database), exported from now on.
pub fn watch_mongo_pool(name: &str, max: u32) -> Arc<PoolCounts> {
    let counts = Arc::new(PoolCounts::default());
    lock(&MONGO_POOLS).push((name.to_string(), counts.clone(), max));
    counts
}

fn collect_mongo() {
    let mut by_name: Vec<(String, u32, u32, u32)> = Vec::new();
    for (name, counts, max) in lock(&MONGO_POOLS).iter() {
        let (used, idle) = counts.used_idle();
        add_up(&mut by_name, name, used, idle, *max);
    }
    for (name, used, idle, max) in by_name {
        set_pool("mongodb", name, used as f64, idle as f64, max as f64);
    }
}

// ---------------------------------------------------------------------------- outbound HTTP ---

/// Sends `rb` and records [`HTTP_CLIENT_DURATION`] with `target`, which the caller keeps to a
/// fixed set of names (never a host or a path from a request).
pub async fn send(target: &str, rb: reqwest::RequestBuilder) -> reqwest::Result<reqwest::Response> {
    let (client, request) = rb.build_split();
    let request = request?;
    execute(target, client, request).await
}

/// [`send`] for a call to another Modlix service, named by its path (`/api/security/...` is
/// `security`, see [`service_of`]).
pub async fn send_to_service(rb: reqwest::RequestBuilder) -> reqwest::Result<reqwest::Response> {
    let (client, request) = rb.build_split();
    let request = request?;
    let target = service_of(request.url().path());
    execute(target, client, request).await
}

async fn execute(target: &str, client: reqwest::Client, request: reqwest::Request) -> reqwest::Result<reqwest::Response> {
    let method = request.method().as_str().to_string();
    let start = Instant::now();
    let result = client.execute(request).await;
    metrics::histogram!(HTTP_CLIENT_DURATION, "target" => target.to_string(), "method" => method, "status" => outcome(&result))
        .record(start.elapsed().as_secs_f64());
    result
}

/// The `status` label: the response's status code, or why there was none.
fn outcome(r: &reqwest::Result<reqwest::Response>) -> Cow<'static, str> {
    match r {
        Ok(resp) => resp.status().as_u16().to_string().into(),
        Err(e) if e.is_timeout() => "timeout".into(),
        Err(e) if e.is_connect() => "connect_error".into(),
        Err(_) => "error".into(),
    }
}

/// The service a Modlix API path belongs to, from a fixed list (`other` for anything else), so a
/// path can never add a label value.
pub fn service_of(path: &str) -> &'static str {
    let mut parts = path.trim_start_matches('/').split('/');
    if parts.next() != Some("api") {
        return "other";
    }
    match (parts.next().unwrap_or(""), parts.next().unwrap_or("")) {
        ("security", _) => "security",
        ("core", _) => "core",
        ("ui", _) => "ui",
        ("files", _) => "files",
        ("message", _) => "message",
        ("notification", _) => "notification",
        ("multi", _) => "multi",
        ("ai", _) => "ai",
        ("entity", "processor") => "entity-processor",
        ("entity", "collector") => "entity-collector",
        _ => "other",
    }
}

// ------------------------------------------------------------------------------------- redis ---

/// A Redis call that failed: `connect`, `command` or `subscribe`.
pub fn redis_error(operation: &'static str) {
    metrics::counter!(REDIS_ERRORS, "operation" => operation).increment(1);
}

// ------------------------------------------------------------------------------------- tests ---

/// Runs `f` with a Prometheus recorder of its own on this thread only, and returns what it
/// recorded as `/metrics` would render it. For tests: what a function counts, without the
/// process-wide recorder (and whatever other tests put in it).
pub fn capture<T>(f: impl FnOnce() -> T) -> (T, String) {
    let recorder = PrometheusBuilder::new()
        .set_buckets_for_metric(Matcher::Full(HTTP_DURATION.to_string()), HTTP_BUCKETS)
        .and_then(|b| b.set_buckets_for_metric(Matcher::Full(HTTP_CLIENT_DURATION.to_string()), HTTP_BUCKETS))
        .unwrap_or_default()
        .build_recorder();
    let handle = recorder.handle();
    let out = metrics::with_local_recorder(&recorder, f);
    (out, handle.render())
}

/// [`capture`] for a future, run to the end on a runtime of its own on this thread (so it must
/// not be called from inside a runtime).
pub fn capture_async<F: Future>(fut: F) -> (F::Output, String) {
    capture(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a current-thread runtime")
            .block_on(fut)
    })
}

/// The value of the series `name` in Prometheus text whose labels include all of `labels`.
pub fn sample(text: &str, name: &str, labels: &[(&str, &str)]) -> Option<f64> {
    text.lines().filter(|l| !l.starts_with('#')).find_map(|l| {
        let (series, v) = l.rsplit_once(' ')?;
        let rest = series.strip_prefix(name)?;
        let matches = match rest.strip_prefix('{') {
            Some(lbls) => labels.iter().all(|(k, val)| lbls.contains(&format!("{k}=\"{val}\""))),
            None => rest.is_empty() && labels.is_empty(),
        };
        matches.then(|| v.parse().ok())?
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commits_and_build_info() {
        assert_eq!(commit(Some(" abc "), Some("def".into())), "abc");
        assert_eq!(commit(Some(""), Some(" def ".into())), "def");
        assert_eq!(commit(None, Some("  ".into())), "unknown");
        assert_eq!(commit(None, None), "unknown");
        let (_, text) = capture(|| build_info("core-exec", "abc"));
        assert_eq!(sample(&text, BUILD_INFO, &[("service", "core-exec"), ("commit", "abc"), ("version", env!("CARGO_PKG_VERSION"))]), Some(1.0));
    }

    #[test]
    fn services_by_path_never_by_value() {
        assert_eq!(service_of("/api/security/clients/internal/x"), "security");
        assert_eq!(service_of("api/core/data"), "core");
        assert_eq!(service_of("/api/ui/pages"), "ui");
        assert_eq!(service_of("/api/files/static"), "files");
        assert_eq!(service_of("/api/message/x"), "message");
        assert_eq!(service_of("/api/notification/x"), "notification");
        assert_eq!(service_of("/api/multi/x"), "multi");
        assert_eq!(service_of("/api/ai/x"), "ai");
        assert_eq!(service_of("/api/entity/processor/functions"), "entity-processor");
        assert_eq!(service_of("/api/entity/collector/x"), "entity-collector");
        assert_eq!(service_of("/api/entity/x"), "other");
        assert_eq!(service_of("/api/client-42/x"), "other");
        assert_eq!(service_of("/eureka/apps"), "other");
        assert_eq!(service_of(""), "other");
    }

    #[test]
    fn calls_are_timed_by_target_method_and_status() {
        let ((), text) = capture_async(async {
            let app = axum::Router::new()
                .route("/api/core/x", axum::routing::post(|| async { "ok" }))
                .route("/slow", axum::routing::get(|| async { tokio::time::sleep(std::time::Duration::from_secs(2)).await }));
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", l.local_addr().unwrap());
            tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
            let http = reqwest::Client::new();
            assert_eq!(send_to_service(http.post(format!("{base}/api/core/x"))).await.unwrap().status(), 200);
            assert_eq!(send("security", http.get(format!("{base}/nowhere"))).await.unwrap().status(), 404);
            assert!(send("files", http.get("http://127.0.0.1:1/x")).await.unwrap_err().is_connect());
            let short = http.get(format!("{base}/slow")).timeout(std::time::Duration::from_millis(50));
            assert!(send("ui", short).await.unwrap_err().is_timeout());
            // A request that cannot be built is not a call: nothing is recorded.
            assert!(send("ui", http.get("http://[::1")).await.is_err());
            assert!(send_to_service(http.get("http://[::1")).await.is_err());
        });
        let count = |labels: &[(&str, &str)]| sample(&text, &format!("{HTTP_CLIENT_DURATION}_count"), labels);
        assert_eq!(count(&[("target", "core"), ("method", "POST"), ("status", "200")]), Some(1.0));
        assert_eq!(count(&[("target", "security"), ("method", "GET"), ("status", "404")]), Some(1.0));
        assert_eq!(count(&[("target", "files"), ("status", "connect_error")]), Some(1.0));
        assert_eq!(count(&[("target", "ui"), ("status", "timeout")]), Some(1.0));
        assert!(text.contains(&format!("{HTTP_CLIENT_DURATION}_bucket{{")), "a histogram with buckets, not a summary");
    }

    #[test]
    fn other_errors_are_errors() {
        let ((), text) = capture_async(async {
            // A server that closes the connection without answering.
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", l.local_addr().unwrap());
            tokio::spawn(async move {
                while let Ok((s, _)) = l.accept().await {
                    drop(s);
                }
            });
            assert!(send("core", reqwest::Client::new().get(format!("{base}/x"))).await.is_err());
        });
        assert_eq!(sample(&text, &format!("{HTTP_CLIENT_DURATION}_count"), &[("target", "core"), ("status", "error")]), Some(1.0));
    }

    #[test]
    fn pools_add_up_by_name() {
        let counts = PoolCounts::default();
        assert_eq!(counts.used_idle(), (0, 0));
        counts.opened();
        counts.opened();
        counts.checked_out();
        assert_eq!(counts.used_idle(), (1, 1));
        counts.checked_in();
        counts.closed();
        assert_eq!(counts.used_idle(), (0, 1));
        counts.closed();
        counts.closed();
        counts.checked_out();
        assert_eq!(counts.used_idle(), (0, 0), "never below zero, never more used than open");

        let ((), text) = capture_async(async {
            let a = watch_mongo_pool("meter-test-ui", 10);
            let b = watch_mongo_pool("meter-test-ui", 5);
            a.opened();
            a.opened();
            a.checked_out();
            b.opened();
            let lazy = sqlx::mysql::MySqlPoolOptions::new().connect_lazy("mysql://nobody@127.0.0.1:1/x").unwrap();
            watch_mysql_pool("meter-test-files", &lazy, 4);
            on_scrape(|| metrics::gauge!("meter_test_gauge").set(7.0));
            collect();
        });
        let pool = |system: &str, name: &str, state: &str| sample(&text, DB_CONNECTIONS, &[("system", system), ("pool", name), ("state", state)]);
        assert_eq!(pool("mongodb", "meter-test-ui", "used"), Some(1.0));
        assert_eq!(pool("mongodb", "meter-test-ui", "idle"), Some(2.0));
        assert_eq!(sample(&text, DB_CONNECTIONS_MAX, &[("system", "mongodb"), ("pool", "meter-test-ui")]), Some(15.0));
        assert_eq!(pool("mysql", "meter-test-files", "idle"), Some(0.0));
        assert_eq!(sample(&text, DB_CONNECTIONS_MAX, &[("system", "mysql"), ("pool", "meter-test-files")]), Some(4.0));
        assert_eq!(sample(&text, "meter_test_gauge", &[]), Some(7.0));
        assert!(sample(&text, TOKIO_WORKERS, &[]).is_some_and(|w| w >= 1.0));
        assert!(sample(&text, TOKIO_ALIVE_TASKS, &[]).is_some());
        assert!(sample(&text, TOKIO_GLOBAL_QUEUE, &[]).is_some());
        assert!(sample(&text, "process_resident_memory_bytes", &[]).is_some_and(|b| b > 0.0));
        assert!(sample(&text, "process_start_time_seconds", &[]).is_some_and(|s| s > 1.0e9));
    }

    #[test]
    fn redis_errors_and_sample_lookup() {
        let ((), text) = capture(|| {
            redis_error("connect");
            redis_error("connect");
            describe();
        });
        assert_eq!(sample(&text, REDIS_ERRORS, &[("operation", "connect")]), Some(2.0));
        assert!(text.contains(&format!("# HELP {REDIS_ERRORS}")));
        assert_eq!(sample("x 1\nx{a=\"b\"} 2", "x", &[]), Some(1.0));
        assert_eq!(sample("x{a=\"b\"} 2", "x", &[("a", "b")]), Some(2.0));
        assert_eq!(sample("x{a=\"b\"} 2", "x", &[("a", "c")]), None);
        assert_eq!(sample("xy 3", "x", &[]), None);
    }

    /// What `telemetry::init` starts: the build, and pools watched from then on.
    #[test]
    fn start_marks_the_process_as_serving() {
        let ((), text) = capture(|| start("meter-test"));
        assert!(serving());
        assert_eq!(sample(&text, BUILD_INFO, &[("service", "meter-test")]), Some(1.0));
        assert!(text.contains("# HELP build_info"));
    }
}
