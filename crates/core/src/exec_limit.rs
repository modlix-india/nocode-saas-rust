//! How long one function execution may run (`[kirun] max_execution_seconds`) and, as a second
//! guard, how many steps it may run (`[kirun] max_steps`), so that one runaway call is stopped
//! and answered instead of holding a worker until the unit is replaced.
//!
//! The kirun runtime is async, but a function made only of in-memory steps (loops, array and
//! object work, expressions) never awaits anything that is pending: polled once, it runs to the
//! end on the worker thread. A `tokio::time::timeout` around it alone never gets to fire, and
//! the worker serves no other request meanwhile. So:
//!
//! - every step of every definition the run calls goes through [`LimitedStep`] (the run's
//!   function repository is wrapped once, in `exec::run`; nested definitions run on their
//!   caller's repository). Before the step it checks the clock and the step count: past the
//!   limit the step fails, and so does every later step of the run (a step that catches an
//!   error cannot keep it going). About every [`YIELD_EVERY`] it yields to the scheduler, so
//!   the other requests on that worker go on and a timer can fire;
//! - [`guard`], around the outermost run of a task, holds the budget (a task-local, so a run
//!   started inside it, such as a storage trigger, shares it) and, as a backstop for a run
//!   stuck in an await (a slow query, an outbound call), drops the run a little after the limit
//!   ([`BACKSTOP_GRACE`]). Dropping is what a disconnecting client already does to a request: a
//!   MySQL transaction left open is rolled back by sqlx when it is dropped (the rollback is
//!   sent when the connection goes back to the pool), and no lock outlives the future;
//! - a run that was stopped answers `CORE.EXECUTION_TIME_LIMIT` (or `CORE.EXECUTION_STEP_LIMIT`),
//!   422, whatever error the unwinding produced on the way, and is logged once at WARN with the
//!   function, app and client. 422 and not 504: the gateway retries a GET answered 502/503/504
//!   on another instance, counts those towards ejecting the instance and towards its circuit
//!   breaker, none of which a function that does too much should cause.
//!
//! The cooperative stop unwinds through the code that called the step, so a storage write
//! scope (`appdata::mysql::tx::scope`) sees an error and rolls back as it does for any failure.
//! One step that runs long by itself (one huge expression, one core function busy without an
//! await) cannot be cut short; it is stopped at its next step or await.

use std::any::Any;
use std::future::Future;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use axum::http::StatusCode;
use kirun::function::Function;
use kirun::json::schema::Schema;
use kirun::model::{Event, FunctionOutput, FunctionSignature};
use kirun::repository::Repository;
use kirun::runtime::FunctionExecutionParameters;
use kirun::Map;
use serde::{Deserialize, Serialize};

use crate::error::CoreError;

/// `[kirun]`: the limits of one function execution.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct KirunSection {
    /// Seconds one execution (the outermost function call of a request or an event task, with
    /// everything it calls) may run; 0 is no limit. Unset: the unit's default
    /// ([`DEFAULT_MAX_EXECUTION_SECONDS`], core-events [`EVENTS_MAX_EXECUTION_SECONDS`]).
    pub max_execution_seconds: Option<u64>,
    /// Steps one execution may run, every definition it calls included; 0 is no limit.
    pub max_steps: u64,
}

impl KirunSection {
    /// The limit in seconds, 0 for none.
    pub fn seconds(&self) -> u64 {
        self.max_execution_seconds.unwrap_or(DEFAULT_MAX_EXECUTION_SECONDS)
    }

    /// core-events: unless the file says otherwise, the longer limit of background work.
    pub fn for_events(mut self) -> Self {
        self.max_execution_seconds.get_or_insert(EVENTS_MAX_EXECUTION_SECONDS);
        self
    }
}

/// Requests (core-exec, core-editor): under nginx's 300 s for `/api/core/function/` (60 s for
/// the rest of `/api/`) and the gateway's 3600 s, so the caller gets this answer rather than a
/// proxy's 504; well over what an interactive call should take.
pub const DEFAULT_MAX_EXECUTION_SECONDS: u64 = 120;

/// Event tasks (core-events, scheduled jobs among them): what `[core] function_timeout_seconds`
/// (Java's five minutes per stored function) already allowed, and the scheduler's 300 s lease.
pub const EVENTS_MAX_EXECUTION_SECONDS: u64 = 300;

/// How often a long run lets the other tasks on its worker go on.
pub const YIELD_EVERY: Duration = Duration::from_millis(10);

/// How long after the limit a run that has not reached a step (stuck in an await) is dropped.
pub const BACKSTOP_GRACE: Duration = Duration::from_secs(2);

pub const TIME_LIMIT_CODE: &str = "CORE.EXECUTION_TIME_LIMIT";
pub const STEP_LIMIT_CODE: &str = "CORE.EXECUTION_STEP_LIMIT";

const RUNNING: u8 = 0;
const OUT_OF_TIME: u8 = 1;
const OUT_OF_STEPS: u8 = 2;

/// One execution's budget.
pub struct Budget {
    function: String,
    app_code: String,
    client_code: String,
    started: Instant,
    limit: Option<Duration>,
    max_steps: u64,
    steps: AtomicU64,
    /// Nanoseconds after `started` of the last yield.
    last_yield: AtomicU64,
    stopped: AtomicU8,
}

/// What a step may do.
#[derive(Debug, PartialEq, Eq)]
enum Gate {
    Go,
    Yield,
    Stop,
}

impl Budget {
    fn new(settings: &KirunSection, function: &str, app_code: &str, client_code: &str) -> Self {
        Self {
            function: function.to_string(),
            app_code: app_code.to_string(),
            client_code: client_code.to_string(),
            started: Instant::now(),
            limit: (settings.seconds() > 0).then(|| Duration::from_secs(settings.seconds())),
            max_steps: settings.max_steps,
            steps: AtomicU64::new(0),
            last_yield: AtomicU64::new(0),
            stopped: AtomicU8::new(RUNNING),
        }
    }

    fn stop(&self, why: u8) {
        let _ = self.stopped.compare_exchange(RUNNING, why, Ordering::SeqCst, Ordering::SeqCst);
    }

    fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst) != RUNNING
    }

    fn step(&self) -> Gate {
        if self.is_stopped() {
            return Gate::Stop;
        }
        let n = self.steps.fetch_add(1, Ordering::Relaxed) + 1;
        if self.max_steps > 0 && n > self.max_steps {
            self.stop(OUT_OF_STEPS);
            return Gate::Stop;
        }
        let elapsed = self.started.elapsed();
        if self.limit.is_some_and(|l| elapsed >= l) {
            self.stop(OUT_OF_TIME);
            return Gate::Stop;
        }
        let now = elapsed.as_nanos() as u64;
        let last = self.last_yield.load(Ordering::Relaxed);
        if now.saturating_sub(last) >= YIELD_EVERY.as_nanos() as u64
            && self.last_yield.compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed).is_ok()
        {
            return Gate::Yield;
        }
        Gate::Go
    }

    /// The answer of a stopped run.
    fn error(&self) -> CoreError {
        if self.stopped.load(Ordering::SeqCst) == OUT_OF_STEPS {
            return CoreError::coded(
                StatusCode::UNPROCESSABLE_ENTITY,
                STEP_LIMIT_CODE,
                format!("Function execution stopped after {} steps : {}", self.max_steps, self.function),
            )
            .param("function", &self.function)
            .param("steps", self.max_steps);
        }
        let seconds = self.limit.map(|l| l.as_secs()).unwrap_or_default();
        CoreError::coded(
            StatusCode::UNPROCESSABLE_ENTITY,
            TIME_LIMIT_CODE,
            format!("Function execution stopped after {seconds} seconds : {}", self.function),
        )
        .param("function", &self.function)
        .param("seconds", seconds)
    }

    fn log(&self, how: &str) {
        tracing::warn!(
            function = %self.function,
            app = %self.app_code,
            client = %self.client_code,
            limit_seconds = self.limit.map(|l| l.as_secs()).unwrap_or_default(),
            max_steps = self.max_steps,
            elapsed_ms = self.started.elapsed().as_millis() as u64,
            steps = self.steps.load(Ordering::Relaxed),
            reason = if self.stopped.load(Ordering::SeqCst) == OUT_OF_STEPS { "EXECUTION_STEP_LIMIT" } else { "EXECUTION_TIME_LIMIT" },
            stopped = how,
            "function execution stopped at its limit"
        );
    }
}

tokio::task_local! {
    static BUDGET: Arc<Budget>;
}

/// Whether the current task runs inside a budget.
pub fn active() -> bool {
    BUDGET.try_with(|_| ()).is_ok()
}

/// Whether the run of the current task has been stopped.
pub fn stopped() -> bool {
    BUDGET.try_with(|b| b.is_stopped()).unwrap_or(false)
}

/// Before a step (or any unit of work a run repeats): an error once the run is past its
/// limit, and a yield about every [`YIELD_EVERY`]. Outside a budget it does nothing.
pub async fn step() -> kirun::Result<()> {
    let Ok(gate) = BUDGET.try_with(|b| b.step()) else { return Ok(()) };
    match gate {
        Gate::Go => Ok(()),
        Gate::Yield => {
            tokio::task::yield_now().await;
            Ok(())
        }
        Gate::Stop => Err(kirun::KIRunError::runtime(
            BUDGET.try_with(|b| b.error().text()).unwrap_or_else(|_| "Function execution stopped".into()),
        )),
    }
}

/// Runs `run` (one execution of `function` for the app and client) within the limits. The
/// outermost call of a task holds the budget, logs a stop and drops a run stuck past the limit;
/// a call inside it shares that budget. `Err` only when the run was stopped.
pub async fn guard<T, F>(settings: &KirunSection, function: &str, app_code: &str, client_code: &str, run: F) -> Result<T, CoreError>
where
    F: Future<Output = T>,
{
    if let Ok(outer) = BUDGET.try_with(Arc::clone) {
        let out = run.await;
        return if outer.is_stopped() { Err(outer.error()) } else { Ok(out) };
    }
    let budget = Arc::new(Budget::new(settings, function, app_code, client_code));
    let scoped = BUDGET.scope(budget.clone(), run);
    let out = match budget.limit {
        Some(limit) => {
            let deadline = tokio::time::Instant::from_std(budget.started + limit + BACKSTOP_GRACE);
            match tokio::time::timeout_at(deadline, scoped).await {
                Ok(out) => out,
                Err(_) => {
                    budget.stop(OUT_OF_TIME);
                    budget.log("dropped");
                    return Err(budget.error());
                }
            }
        }
        None => scoped.await,
    };
    if budget.is_stopped() {
        budget.log("at a step");
        return Err(budget.error());
    }
    Ok(out)
}

/// The function repository of a run: every function it finds runs as a [`LimitedStep`].
pub fn limited(inner: Arc<dyn Repository<dyn Function>>) -> Arc<dyn Repository<dyn Function>> {
    Arc::new(LimitedRepository { inner })
}

struct LimitedRepository {
    inner: Arc<dyn Repository<dyn Function>>,
}

#[async_trait]
impl Repository<dyn Function> for LimitedRepository {
    async fn find(&self, namespace: &str, name: &str) -> Option<Arc<dyn Function>> {
        let inner = self.inner.find(namespace, name).await?;
        Some(Arc::new(LimitedStep { inner }))
    }

    async fn filter(&self, name: &str) -> Vec<String> {
        self.inner.filter(name).await
    }
}

/// A step's function, run only while the budget lasts. Everything else is the function's own
/// (`as_any` too, so the runtime still recognises a nested `KIRuntime`).
pub struct LimitedStep {
    inner: Arc<dyn Function>,
}

#[async_trait]
impl Function for LimitedStep {
    fn get_signature(&self) -> &FunctionSignature {
        self.inner.get_signature()
    }

    fn get_probable_event_signature(&self, probable_parameters: &Map<Vec<Schema>>) -> Map<Event> {
        self.inner.get_probable_event_signature(probable_parameters)
    }

    async fn execute(&self, context: &mut FunctionExecutionParameters) -> kirun::Result<FunctionOutput> {
        step().await?;
        self.inner.execute(context).await
    }

    fn as_any(&self) -> Option<&dyn Any> {
        self.inner.as_any()
    }
}

#[cfg(test)]
#[path = "exec_limit_tests.rs"]
mod tests;
