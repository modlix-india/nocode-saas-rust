//! A thread pool of its own for function runs (`[runs]`), so that runs which keep their threads
//! busy cannot keep the unit from answering `/healthz`, `/readyz` and `/metrics`.
//!
//! Tokio schedules cooperatively: a KIRun step that computes without awaiting (a sort or a copy
//! of a big array, a loop of in-memory steps, a storage call building many rows) holds its
//! worker until it is done, and with every worker held that way nothing else on the runtime
//! runs, the health routes included. On dev (2026-10-30) core-events wrote nothing for 28 s
//! while AdZump syncs ran, the two statements it had in flight both finished 28 s later at the
//! same instant, and keepup, whose `/readyz` call had timed out, replaced the unit and killed
//! the runs. The threads of another runtime are preempted by the kernel instead, so the
//! server's workers keep getting the CPU however long a run computes.
//!
//! - core-events runs its queue consumer, and with it every event task, on the pool
//!   ([`events_pool`]), and takes no more deliveries at once than the pool has threads;
//! - core-exec runs its execute routes there ([`offload`]); its other routes stay on the
//!   server's runtime;
//! - `/readyz` asks MySQL and Mongo over connections of its own ([`readiness_checks`]): a
//!   pooled connection opened by a run is driven by the pool's runtime, which a busy pool does
//!   not get to, and the runs may hold every pooled connection. Readiness then says whether
//!   the unit can serve, not whether a connection is free.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use platform::config::{MongoConfig, MySqlConfig};
use platform::health::Health;
use serde::{Deserialize, Serialize};
use tokio::runtime::{Handle, Runtime};
use tokio::task::JoinHandle;
use tracing::Instrument;

use crate::config::{CoreConfig, EventsSection};

/// `[runs]`: where function runs execute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RunsSection {
    /// Run on a pool of their own. Off, they run on the server's runtime, as before.
    pub dedicated: bool,
    /// The pool's threads. 0: one per CPU, and in core-events at least one per delivery in
    /// flight (`[events] prefetch`).
    pub threads: usize,
}

impl Default for RunsSection {
    fn default() -> Self {
        Self { dedicated: true, threads: 0 }
    }
}

impl RunsSection {
    /// core-exec's pool size.
    pub fn exec_threads(&self) -> usize {
        if self.threads > 0 { self.threads } else { cpus() }
    }

    /// core-events' pool size: by default every delivery in flight has a thread.
    pub fn events_threads(&self, prefetch: u16) -> usize {
        if self.threads > 0 { self.threads } else { cpus().max(usize::from(prefetch.max(1))) }
    }
}

/// The CPUs this process may use (the container's quota included), at least 1.
pub fn cpus() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}

/// What `[events]` becomes on a pool of `threads`: no more deliveries in flight than threads,
/// so the queue cannot hand the pool more runs than it can run side by side.
pub fn events_settings(settings: &EventsSection, threads: usize) -> EventsSection {
    let cap = u16::try_from(threads.max(1)).unwrap_or(u16::MAX);
    let mut s = settings.clone();
    if s.prefetch.max(1) > cap {
        tracing::warn!(prefetch = s.prefetch, threads, "[events] prefetch is more than the run pool's threads: lowered to them");
        s.prefetch = cap;
    }
    s
}

/// A multi-thread runtime of its own. Clones share it; it stops when the last one is dropped,
/// without waiting for the runs on it (a delivery not acked goes back on the queue, a request
/// is answered by the proxy).
#[derive(Clone)]
pub struct RunPool {
    inner: Arc<Owned>,
}

struct Owned {
    runtime: Option<Runtime>,
    handle: Handle,
    threads: usize,
}

impl Drop for Owned {
    fn drop(&mut self) {
        // Dropping a runtime blocks, which a runtime's own thread may not do.
        if let Some(rt) = self.runtime.take() {
            rt.shutdown_background();
        }
    }
}

impl RunPool {
    /// A pool of `threads` workers named `name`, with its gauges on `/metrics` under
    /// `runtime="<name>"` when the process serves them.
    pub fn new(name: &str, threads: usize) -> std::io::Result<Self> {
        let threads = threads.max(1);
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(threads)
            .thread_name(name)
            .enable_all()
            .build()?;
        let handle = runtime.handle().clone();
        if platform::meter::serving() {
            watch(name, handle.clone());
        }
        Ok(Self { inner: Arc::new(Owned { runtime: Some(runtime), handle, threads }) })
    }

    pub fn threads(&self) -> usize {
        self.inner.threads
    }

    /// Starts `fut` on the pool.
    pub fn spawn<F>(&self, fut: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.inner.handle.spawn(fut)
    }

    /// Runs `fut` on the pool and hands back its output, inside the caller's message scope and
    /// span. Dropping the returned future stops the run, as dropping `fut` would; a panic of
    /// the run comes out here, so the panic layer answers it as before.
    pub async fn run<F>(&self, fut: F) -> F::Output
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let fut = fut.instrument(tracing::Span::current());
        let task = match platform::messages::scope::current() {
            Some(scope) => self.spawn(platform::messages::scope::within(scope, fut)),
            None => self.spawn(fut),
        };
        let mut task = AbortOnDrop(task);
        match (&mut task.0).await {
            Ok(out) => out,
            Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
            Err(e) => panic!("the run pool stopped under a run: {e}"),
        }
    }
}

struct AbortOnDrop<T>(JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The pool's gauges, labelled `runtime`, read on every scrape like the server runtime's.
fn watch(name: &str, handle: Handle) {
    let name = name.to_string();
    platform::meter::on_scrape(move || {
        let m = handle.metrics();
        let label = ("runtime", name.clone());
        metrics::gauge!(platform::meter::TOKIO_WORKERS, &[label.clone()]).set(m.num_workers() as f64);
        metrics::gauge!(platform::meter::TOKIO_ALIVE_TASKS, &[label.clone()]).set(m.num_alive_tasks() as f64);
        metrics::gauge!(platform::meter::TOKIO_GLOBAL_QUEUE, &[label]).set(m.global_queue_depth() as f64);
    });
}

/// core-events' pool, unless `[runs] dedicated` is off.
pub fn events_pool(cfg: &CoreConfig) -> Result<Option<RunPool>> {
    if !cfg.runs.dedicated {
        return Ok(None);
    }
    let threads = cfg.runs.events_threads(cfg.events.prefetch);
    tracing::info!(threads, "event runs on a thread pool of their own");
    Ok(Some(RunPool::new("core-events-runs", threads).context("starting the event run pool")?))
}

/// core-exec's pool, unless `[runs] dedicated` is off.
pub fn exec_pool(cfg: &CoreConfig) -> Result<Option<RunPool>> {
    if !cfg.runs.dedicated {
        return Ok(None);
    }
    let threads = cfg.runs.exec_threads();
    tracing::info!(threads, "function executions on a thread pool of their own");
    Ok(Some(RunPool::new("core-exec-runs", threads).context("starting the execution pool")?))
}

/// Route layer: the request's handler runs on the pool (state), the response is written here.
pub async fn offload(State(pool): State<RunPool>, req: Request, next: Next) -> Response {
    pool.run(next.run(req)).await
}

/// How long a readiness connection may take to open or answer: under the check's 2 s, so a
/// slow database is reported as what it is.
const READINESS_TIMEOUT: Duration = Duration::from_millis(1500);

/// `/readyz`'s `mysql` and `mongo` checks, each over a connection of its own that only
/// readiness uses. Call on the server's runtime, so the connections are driven by it. Nothing
/// is opened until the first check.
pub async fn readiness_checks(health: &Health, cfg: &CoreConfig) -> Result<()> {
    let mysql = readiness_mysql(&cfg.database);
    health.check("mysql", move || {
        let pool = mysql.clone();
        async move {
            sqlx::query("SELECT 1").execute(&pool).await?;
            Ok(())
        }
    });
    let mongo = readiness_mongo(&cfg.mongo).await?;
    health.check("mongo", move || {
        let db = mongo.clone();
        async move {
            db.run_command(mongodb::bson::doc! {"ping": 1}).await?;
            Ok(())
        }
    });
    Ok(())
}

/// One MySQL connection, opened when first asked for and kept.
pub fn readiness_mysql(cfg: &MySqlConfig) -> sqlx::MySqlPool {
    let opts = sqlx::mysql::MySqlConnectOptions::new()
        .host(&cfg.host)
        .port(cfg.port)
        .database(&cfg.database)
        .username(&cfg.username)
        .password(&cfg.password);
    sqlx::mysql::MySqlPoolOptions::new()
        .max_connections(1)
        .min_connections(0)
        .acquire_timeout(READINESS_TIMEOUT)
        .connect_lazy_with(opts)
}

/// A Mongo client of its own with one pooled connection, for the ping.
pub async fn readiness_mongo(cfg: &MongoConfig) -> Result<mongodb::Database> {
    let mut opts = mongodb::options::ClientOptions::parse(&cfg.uri).await.context("parsing the mongo uri")?;
    opts.max_pool_size = Some(1);
    opts.min_pool_size = Some(0);
    opts.connect_timeout = Some(READINESS_TIMEOUT);
    opts.server_selection_timeout = Some(READINESS_TIMEOUT);
    let name = if cfg.database.is_empty() { opts.default_database.clone().unwrap_or_default() } else { cfg.database.clone() };
    if name.is_empty() {
        anyhow::bail!("no mongo database: set one in the uri path or as `database`");
    }
    let client = mongodb::Client::with_options(opts).context("creating the readiness mongo client")?;
    Ok(client.database(&name))
}

#[cfg(test)]
#[path = "run_pool_tests.rs"]
mod tests;
