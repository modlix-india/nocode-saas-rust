//! `EventScheduler`, as core-scheduler runs it, and `trackCompletion`, as core-events runs it.
//!
//! A pass (every `core.scheduler.tick_ms`, on every core-scheduler instance; Mongo decides who
//! does each piece of work):
//!
//! 1. finds every stored EventDefinition that carries a schedule, grouped by (app, event);
//! 2. works out which clients run it: a per-client schedule runs for every client with write
//!    access to the app, any other for the clients holding a schedule document of their own.
//!    Each client's EFFECTIVE definition decides. A client that is deleted, inactive or locked,
//!    or is managed by one that is, runs nothing;
//! 3. takes the latest tick on that client's cron grid. A tick inside the fresh window is the
//!    current one; an older one is caught up only when a run was recorded before it;
//! 4. claims the tick by unique insert into `schedule_run` (SKIPPED instead when the previous
//!    tick is still RUNNING inside its lease), in a shuffled order;
//! 5. claims due one-offs from `scheduled_event`.
//!
//! Every claimed tick and one-off is PUBLISHED to the events queue (Java's "no runner" mode):
//! core-scheduler never runs KIRun. core-events runs the EventAction and closes the run through
//! [`RunCompletion`] (`trackCompletion`): the raised event carries `_schedule` in its data.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use connections::mq::EventMessage;
use futures::{StreamExt, TryStreamExt};
use mongodb::bson::{Bson, DateTime, Document};
use overridable::JMap;
use parking_lot::Mutex;
use rand::seq::SliceRandom;
use serde_json::{Map, Value};

use crate::cron::{self, CronExpression};
use crate::error::CoreError;
use crate::scheduler::{
    now_millis, Clock, EventDefinitionService, EventSchedule, EventSchedulerSettings, OneOffStore, RunState, ScheduleRun,
    ScheduleStore, ScheduledDefinition, ScheduledEvent, ScheduledEventService,
};
use crate::clients::SecurityCalls;

/// The key in a raised event's data that says which run it belongs to.
pub const SCHEDULE_DATA_KEY: &str = "_schedule";
pub const KIND_CRON: &str = "cron";
pub const KIND_ONCE: &str = "once";

// ---------------------------------------------------------------- what the pass talks to

/// `EventDefinitionService.readEffective`, as the scheduler reads it.
#[async_trait]
pub trait EffectiveDefinitions: Send + Sync {
    async fn read_effective(&self, name: &str, app_code: &str, client_code: &str) -> Result<Option<JMap>, CoreError>;
}

#[async_trait]
impl EffectiveDefinitions for EventDefinitionService {
    async fn read_effective(&self, name: &str, app_code: &str, client_code: &str) -> Result<Option<JMap>, CoreError> {
        EventDefinitionService::read_effective(self, name, app_code, client_code).await
    }
}

/// What security tells the scheduler about clients (`None` is an empty answer).
#[async_trait]
pub trait ClientDirectory: Send + Sync {
    async fn write_access_client_codes(&self, app_code: &str) -> Result<Option<Vec<String>>, CoreError>;
    async fn active_client_codes(&self, codes: &[String]) -> Result<Option<Vec<String>>, CoreError>;
}

#[async_trait]
impl ClientDirectory for SecurityCalls {
    async fn write_access_client_codes(&self, app_code: &str) -> Result<Option<Vec<String>>, CoreError> {
        SecurityCalls::write_access_client_codes(self, app_code).await
    }
    async fn active_client_codes(&self, codes: &[String]) -> Result<Option<Vec<String>>, CoreError> {
        SecurityCalls::active_client_codes(self, codes).await
    }
}

/// `EventCreationService.createEvent`, raising without a user, on the live or draft surface.
#[async_trait]
pub trait EventRaiser: Send + Sync {
    async fn create_event(&self, event: EventMessage, draft: bool) -> Result<bool, CoreError>;
}

#[async_trait]
impl EventRaiser for crate::integrations::Mq {
    async fn create_event(&self, event: EventMessage, draft: bool) -> Result<bool, CoreError> {
        let caller = connections::context::Caller { draft, ..Default::default() };
        crate::integrations::Mq::create_event(self, &caller, event).await
    }
}

/// An outcome that never reaches an EventAction, for the event run log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unrun {
    Skipped,
    Failed,
}

/// The event run log (`EventRunService.record`), for the outcomes a pass decides itself: a tick
/// skipped, a raise that failed, a one-off given up on or refused.
#[async_trait]
pub trait RunLog: Send + Sync {
    async fn record(&self, event: &EventMessage, status: Unrun, error: &str);
}

// ---------------------------------------------------------------- the pass

/// Scheduler passes, by `result` (`ok`, `failed`).
pub const PASSES: &str = "core_scheduler_passes_total";
/// Cron ticks and one-offs this instance claimed, by `kind` (`cron`, `once`).
pub const CLAIMED: &str = "core_scheduler_claimed_total";
/// Claims published to the events queue, by `kind`.
pub const PUBLISHED: &str = "core_scheduler_published_total";
/// Cron ticks claimed and closed as SKIPPED: the previous tick's run was still going.
pub const SKIPPED: &str = "core_scheduler_skipped_total";
/// Claims not published, by `kind`: the raise failed, a one-off was given up on or its client
/// is not active.
pub const FAILED: &str = "core_scheduler_failed_total";
/// Cron ticks another instance claimed first.
pub const LOST: &str = "core_scheduler_lost_total";

/// The descriptions of the counters above, for `/metrics`.
pub fn describe_metrics() {
    use metrics::{describe_counter, Unit};
    describe_counter!(PASSES, Unit::Count, "Scheduler passes, by result (ok, failed).");
    describe_counter!(CLAIMED, Unit::Count, "Cron ticks and one-offs this instance claimed, by kind (cron, once).");
    describe_counter!(PUBLISHED, Unit::Count, "Claims published to the events queue, by kind.");
    describe_counter!(SKIPPED, Unit::Count, "Cron ticks skipped because the previous run was still going.");
    describe_counter!(FAILED, Unit::Count, "Claims that were not published, by kind.");
    describe_counter!(LOST, Unit::Count, "Cron ticks another instance claimed first.");
}

/// What one pass did on this instance. `busy` is always 0 here: core-scheduler has no run
/// slots, it only publishes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PassReport {
    pub raised: i32,
    pub skipped: i32,
    pub lost: i32,
    pub failed: i32,
    pub one_offs_raised: i32,
    pub one_offs_failed: i32,
    pub busy: i32,
}

impl PassReport {
    fn anything(&self) -> bool {
        self.raised + self.skipped + self.failed + self.one_offs_raised > 0
    }

    /// Adds this pass to the counters above; `ok` when it ran to the end (one that failed half
    /// way still counts what it did).
    pub fn record(&self, ok: bool) {
        let n = |v: i32| v.max(0) as u64;
        metrics::counter!(PASSES, "result" => if ok { "ok" } else { "failed" }).increment(1);
        metrics::counter!(CLAIMED, "kind" => KIND_CRON).increment(n(self.raised) + n(self.skipped) + n(self.failed));
        metrics::counter!(CLAIMED, "kind" => KIND_ONCE).increment(n(self.one_offs_raised) + n(self.one_offs_failed));
        metrics::counter!(PUBLISHED, "kind" => KIND_CRON).increment(n(self.raised));
        metrics::counter!(PUBLISHED, "kind" => KIND_ONCE).increment(n(self.one_offs_raised));
        metrics::counter!(SKIPPED, "kind" => KIND_CRON).increment(n(self.skipped));
        metrics::counter!(FAILED, "kind" => KIND_CRON).increment(n(self.failed));
        metrics::counter!(FAILED, "kind" => KIND_ONCE).increment(n(self.one_offs_failed));
        metrics::counter!(LOST, "kind" => KIND_CRON).increment(n(self.lost));
    }
}

/// As Java writes the record.
impl fmt::Display for PassReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PassReport[raised={}, skipped={}, lost={}, failed={}, oneOffsRaised={}, oneOffsFailed={}, busy={}]",
            self.raised, self.skipped, self.lost, self.failed, self.one_offs_raised, self.one_offs_failed, self.busy
        )
    }
}

#[derive(Default)]
struct Counts {
    raised: AtomicI32,
    skipped: AtomicI32,
    lost: AtomicI32,
    failed: AtomicI32,
    one_offs_raised: AtomicI32,
    one_offs_failed: AtomicI32,
}

impl Counts {
    fn bump(c: &AtomicI32) {
        c.fetch_add(1, Ordering::SeqCst);
    }

    fn report(&self) -> PassReport {
        let g = |c: &AtomicI32| c.load(Ordering::SeqCst);
        PassReport {
            raised: g(&self.raised),
            skipped: g(&self.skipped),
            lost: g(&self.lost),
            failed: g(&self.failed),
            one_offs_raised: g(&self.one_offs_raised),
            one_offs_failed: g(&self.one_offs_failed),
            busy: 0,
        }
    }
}

/// One (app, event, client) a pass looks at.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Candidate {
    app_code: String,
    event_name: String,
    client_code: String,
    holder: bool,
    has_write_access: bool,
}

/// `Instant.toString()`: ISO-8601 in UTC, the fraction only when there is one, in groups of
/// three digits.
pub fn instant_text(millis: i64) -> String {
    match Utc.timestamp_millis_opt(millis).single() {
        Some(t) if millis.rem_euclid(1000) == 0 => t.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        Some(t) => t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
        None => millis.to_string(),
    }
}

/// The instance id Java builds: `HOSTNAME` (or "core") and eight characters of a UUID.
pub fn instance_id() -> String {
    let host = std::env::var("HOSTNAME").ok().filter(|h| !h.trim().is_empty()).unwrap_or_else(|| "core".into());
    format!("{host}-{}", &uuid::Uuid::new_v4().to_string()[..8])
}

/// A Mongo value as Jackson writes the `Object` Spring Data read it into.
pub fn bson_to_json(v: &Bson) -> Value {
    match v {
        Bson::Null | Bson::Undefined => Value::Null,
        Bson::Boolean(b) => Value::Bool(*b),
        Bson::Int32(i) => Value::from(*i),
        Bson::Int64(i) => Value::from(*i),
        Bson::Double(d) => serde_json::Number::from_f64(*d).map(Value::Number).unwrap_or(Value::Null),
        Bson::String(s) | Bson::Symbol(s) => Value::String(s.clone()),
        Bson::Array(a) => Value::Array(a.iter().map(bson_to_json).collect()),
        Bson::Document(d) => Value::Object(document_to_json(d)),
        Bson::DateTime(t) => Value::from(t.timestamp_millis()),
        Bson::ObjectId(o) => serde_json::json!({"timestamp": o.timestamp().timestamp_millis() / 1000, "date": o.timestamp().timestamp_millis()}),
        other => Value::String(other.to_string()),
    }
}

pub fn document_to_json(d: &Document) -> Map<String, Value> {
    d.iter().map(|(k, v)| (k.clone(), bson_to_json(v))).collect()
}

pub struct EventScheduler {
    definitions: Arc<dyn EffectiveDefinitions>,
    directory: Arc<dyn ClientDirectory>,
    raiser: Arc<dyn EventRaiser>,
    store: Arc<ScheduleStore>,
    one_offs: Arc<ScheduledEventService>,
    settings: EventSchedulerSettings,
    run_log: Option<Arc<dyn RunLog>>,
    instance_id: String,
    pass_running: AtomicBool,
    /// The last tick dealt with per schedule and client: only spares a repeat insert every
    /// pass between two ticks; the unique index is what guarantees one run.
    handled: Mutex<HashMap<String, i64>>,
    write_access: Mutex<HashMap<String, (HashSet<String>, i64)>>,
    crons: Mutex<HashMap<String, CronExpression>>,
    /// What security last said about each client: active, and when.
    client_states: Mutex<HashMap<String, (bool, i64)>>,
    clock: Clock,
}

impl EventScheduler {
    pub fn new(
        definitions: Arc<dyn EffectiveDefinitions>,
        directory: Arc<dyn ClientDirectory>,
        raiser: Arc<dyn EventRaiser>,
        store: Arc<ScheduleStore>,
        one_offs: Arc<ScheduledEventService>,
        settings: EventSchedulerSettings,
    ) -> Self {
        Self {
            definitions,
            directory,
            raiser,
            store,
            one_offs,
            settings,
            run_log: None,
            instance_id: instance_id(),
            pass_running: AtomicBool::new(false),
            handled: Mutex::default(),
            write_access: Mutex::default(),
            crons: Mutex::default(),
            client_states: Mutex::default(),
            clock: Arc::new(now_millis),
        }
    }

    pub fn with_run_log(mut self, run_log: Arc<dyn RunLog>) -> Self {
        self.run_log = Some(run_log);
        self
    }

    /// Tests only (`setClock`).
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    /// `onStartup` then `@Scheduled(initialDelay, fixedDelay = tickMs)` `onSchedule`, forever.
    pub async fn run_forever(self: Arc<Self>) {
        if !self.settings.enabled {
            tracing::info!("Scheduler is off (core.scheduler.enabled = false)");
            return;
        }
        if let Err(e) = self.store.ensure_indexes().await {
            tracing::error!("Scheduler indexes could not be created; no schedule runs until they are: {e}");
        }
        tokio::time::sleep(std::time::Duration::from_millis(self.settings.initial_delay_ms.max(0) as u64)).await;
        loop {
            self.on_schedule().await;
            tokio::time::sleep(std::time::Duration::from_millis(self.settings.tick_ms.max(1) as u64)).await;
        }
    }

    /// `onSchedule`: one pass unless one is already running here.
    pub async fn on_schedule(&self) {
        if !self.settings.enabled || self.pass_running.swap(true, Ordering::SeqCst) {
            return;
        }
        match self.pass().await {
            Ok(r) if r.anything() => tracing::info!("Scheduler pass on {}: {r}", self.instance_id),
            Ok(_) => {}
            Err(e) => tracing::error!("Scheduler pass failed on {}: {e}", self.instance_id),
        }
        self.pass_running.store(false, Ordering::SeqCst);
    }

    /// One pass at the current time. Nothing claims until the unique indexes exist.
    pub async fn pass(&self) -> Result<PassReport, CoreError> {
        let now = (self.clock)();
        let counts = Counts::default();
        let done = async {
            self.store.ensure_indexes().await?;
            self.recurring(now, &counts).await?;
            self.due_one_offs(now, &counts).await
        }
        .await;
        let report = counts.report();
        report.record(done.is_ok());
        done.map(|()| report)
    }

    // ------------------------------------------------------------ recurring

    async fn recurring(&self, now: i64, counts: &Counts) -> Result<(), CoreError> {
        let docs = self.store.find_scheduled_definitions().await?;
        // Grouped by (app, event) in the order first seen.
        let mut order: Vec<String> = Vec::new();
        let mut groups: HashMap<String, Vec<ScheduledDefinition>> = HashMap::new();
        for d in docs {
            let key = format!("{}\u{0}{}", d.app_code.as_deref().unwrap_or("null"), d.name.as_deref().unwrap_or("null"));
            if !groups.contains_key(&key) {
                order.push(key.clone());
            }
            groups.entry(key).or_default().push(d);
        }
        let mut list = Vec::new();
        for key in order {
            let group = &groups[&key];
            list.extend(self.candidates(group, now).await);
        }
        // No run for a client that is deleted, inactive or locked, or managed by one that is.
        let codes: HashSet<String> = list.iter().map(|c: &Candidate| c.client_code.clone()).collect();
        let inactive = self.inactive_clients(codes, now).await;
        list.retain(|c| !inactive.contains(&c.client_code));
        // Every instance walks the same candidates; a shuffled order keeps two of them from
        // reaching for the same client at the same moment.
        list.shuffle(&mut rand::thread_rng());
        futures::stream::iter(list)
            .for_each_concurrent(self.settings.concurrency.max(1) as usize, |c| async move {
                self.run_client(&c, now, counts).await;
            })
            .await;
        Ok(())
    }

    async fn candidates(&self, group: &[ScheduledDefinition], now: i64) -> Vec<Candidate> {
        let first = &group[0];
        let (Some(app_code), Some(event_name)) = (first.app_code.clone(), first.name.clone()) else {
            tracing::warn!("Scheduler skipped {:?}.{:?}: no app or name", first.app_code, first.name);
            return Vec::new();
        };
        let holders: HashSet<String> = group.iter().filter_map(|d| d.client_code.clone()).collect();
        // Security is asked only when some document in the chain turns perClient on.
        let any_per_client = group.iter().any(|d| d.per_client == Some(true));
        let writers = if any_per_client { self.write_access_clients(&app_code, now).await } else { HashSet::new() };
        let mut clients: Vec<String> = holders.union(&writers).cloned().collect();
        clients.sort();
        clients
            .into_iter()
            .map(|client| Candidate {
                app_code: app_code.clone(),
                event_name: event_name.clone(),
                holder: holders.contains(&client),
                has_write_access: writers.contains(&client),
                client_code: client,
            })
            .collect()
    }

    async fn run_client(&self, c: &Candidate, now: i64, counts: &Counts) {
        if let Err(e) = self.try_run_client(c, now, counts).await {
            tracing::warn!("Scheduler skipped {}.{} for {}: {e}", c.app_code, c.event_name, c.client_code);
        }
    }

    fn cron_of(&self, text: &str) -> Result<CronExpression, String> {
        if let Some(c) = self.crons.lock().get(text) {
            return Ok(c.clone());
        }
        let c = cron::parse_cron(text)?;
        self.crons.lock().insert(text.to_string(), c.clone());
        Ok(c)
    }

    async fn try_run_client(&self, c: &Candidate, now: i64, counts: &Counts) -> Result<(), CoreError> {
        let Some(ed) = self.definitions.read_effective(&c.event_name, &c.app_code, &c.client_code).await? else {
            return Ok(());
        };
        let Some(schedule) = ed.get("schedule").and_then(EventSchedule::from_j) else { return Ok(()) };
        if !schedule.is_active() {
            return Ok(());
        }
        // The client's own effective perClient decides, not the base's.
        if if schedule.is_for_each_client() { !c.has_write_access } else { !c.holder } {
            return Ok(());
        }
        let grid = self.cron_of(schedule.cron.as_deref().unwrap_or_default()).and_then(|cron| {
            cron::zone_of(schedule.effective_timezone()).map(|zone| (cron, zone))
        });
        let (cron, zone) = match grid {
            Ok(g) => g,
            Err(e) => {
                tracing::warn!("Scheduler cannot read the schedule of {}.{} for {}: {e}", c.app_code, c.event_name, c.client_code);
                return Ok(());
            }
        };
        let now_at = Utc.timestamp_millis_opt(now).single().unwrap_or_default();
        let key = format!("{}\u{0}{}\u{0}{}", c.app_code, c.client_code, c.event_name);
        let window = self.settings.catch_up_window();
        let tick = if schedule.is_spread_across_period() {
            cron::latest_spread_tick(&cron, &zone, now_at, window, &key)
        } else {
            cron::latest_tick(&cron, &zone, now_at, window)
        };
        let Some(tick) = tick.map(|t| t.timestamp_millis()) else { return Ok(()) };
        if self.handled.lock().get(&key) == Some(&tick) {
            return Ok(());
        }
        let fresh = tick >= now.saturating_sub(self.settings.fresh_window().num_milliseconds());
        let due = fresh
            || match self.store.last_run(&c.app_code, &c.client_code, &c.event_name).await? {
                Some(last) => last.tick_at.timestamp_millis() < tick,
                // No run ever recorded: a new schedule, not a missed tick.
                None => false,
            };
        if due {
            self.claim_and_raise(&c.app_code, &c.client_code, &c.event_name, tick, now, counts).await?;
        }
        self.handled.lock().insert(key, tick);
        Ok(())
    }

    async fn claim_and_raise(&self, app_code: &str, client_code: &str, event_name: &str, tick: i64, now: i64, counts: &Counts)
        -> Result<(), CoreError> {
        let busy = self.store.is_running(app_code, client_code, event_name, now).await?;
        let mut run = ScheduleRun {
            id: uuid::Uuid::new_v4().to_string(),
            app_code: app_code.into(),
            client_code: client_code.into(),
            event_name: event_name.into(),
            tick_at: DateTime::from_millis(tick),
            status: None,
            lease_until: None,
            owner: Some(self.instance_id.clone()),
            created_at: Some(DateTime::from_millis(now)),
            finished_at: None,
            error: None,
        };
        if busy {
            run.status = Some(RunState::Skipped);
            run.finished_at = Some(DateTime::from_millis(now));
        } else {
            run.status = Some(RunState::Running);
            run.lease_until = Some(DateTime::from_millis(now.saturating_add(self.settings.lease().num_milliseconds())));
        }
        if !self.store.claim(&run).await? {
            Counts::bump(&counts.lost);
            return Ok(());
        }
        let mut marker = Map::new();
        marker.insert("kind".into(), Value::from(KIND_CRON));
        marker.insert("runId".into(), Value::from(run.id.clone()));
        marker.insert("tickAt".into(), Value::from(instant_text(tick)));
        let mut data = Map::new();
        data.insert(SCHEDULE_DATA_KEY.into(), Value::Object(marker));
        let qob = que_object(app_code, client_code, event_name, data, false);
        if busy {
            Counts::bump(&counts.skipped);
            self.log_run(&qob, Unrun::Skipped, "Skipped: the run for the previous tick was still going.").await;
            return Ok(());
        }
        match self.raiser.create_event(qob.clone(), false).await {
            Ok(_) => Counts::bump(&counts.raised),
            Err(e) => {
                Counts::bump(&counts.failed);
                tracing::warn!("Scheduler could not raise {app_code}.{event_name} for {client_code}: {e}");
                let message = format!("Raise failed: {}", e.text());
                self.store.finish_run(&run.id, RunState::Failed, Some(&message), now).await?;
                self.log_run(&qob, Unrun::Failed, &format!("The scheduler could not raise the event: {}", e.text())).await;
            }
        }
        Ok(())
    }

    /// Owner plus EDIT_ACCESS clients from security, reused for `clients_refresh_seconds`.
    /// When security cannot be reached the last list keeps serving, or nobody runs.
    async fn write_access_clients(&self, app_code: &str, now: i64) -> HashSet<String> {
        let cached = self.write_access.lock().get(app_code).cloned();
        if let Some((codes, at)) = &cached {
            if at.saturating_add(self.settings.clients_refresh_seconds.saturating_mul(1000)) > now {
                return codes.clone();
            }
        }
        match self.directory.write_access_client_codes(app_code).await {
            Ok(Some(codes)) => {
                let set: HashSet<String> = codes.into_iter().collect();
                self.write_access.lock().insert(app_code.to_string(), (set.clone(), now));
                set
            }
            Ok(None) => HashSet::new(),
            Err(e) => {
                tracing::warn!("Scheduler could not read write-access clients of {app_code}: {e}");
                cached.map(|(c, _)| c).unwrap_or_default()
            }
        }
    }

    /// The codes among these that security says are not active, answers reused for
    /// `clients_refresh_seconds` and fetched in one call for every stale code. Only a client
    /// security has answered for is left out.
    async fn inactive_clients(&self, codes: HashSet<String>, now: i64) -> HashSet<String> {
        if codes.is_empty() {
            return HashSet::new();
        }
        let refresh = self.settings.clients_refresh_seconds.saturating_mul(1000);
        let mut stale: Vec<String> = {
            let states = self.client_states.lock();
            codes
                .iter()
                .filter(|c| states.get(*c).is_none_or(|(_, at)| at.saturating_add(refresh) <= now))
                .cloned()
                .collect()
        };
        stale.sort();
        if !stale.is_empty() {
            match self.directory.active_client_codes(&stale).await {
                Ok(Some(active)) => {
                    let active: HashSet<String> = active.into_iter().collect();
                    let mut states = self.client_states.lock();
                    for code in &stale {
                        states.insert(code.clone(), (active.contains(code), now));
                    }
                }
                Ok(None) => {}
                Err(e) => tracing::warn!("Scheduler could not read the status of {} clients: {e}", stale.len()),
            }
        }
        let states = self.client_states.lock();
        codes.into_iter().filter(|c| states.get(c).is_some_and(|(active, _)| !active)).collect()
    }

    // ------------------------------------------------------------ one-off

    async fn due_one_offs(&self, now: i64, counts: &Counts) -> Result<(), CoreError> {
        let list = self.store.claim_due_events(now, &self.instance_id, self.settings.lease(), self.settings.oneoff.batch_size).await?;
        // One status call for the whole batch, so each raise below reads it from memory.
        let codes: HashSet<String> = list.iter().filter_map(|e| e.client_code.clone()).collect();
        self.inactive_clients(codes, now).await;
        futures::stream::iter(list.into_iter().map(Ok::<_, CoreError>))
            .try_for_each_concurrent(self.settings.concurrency.max(1) as usize, |e| async move {
                self.raise_one_off(&e, now, counts).await
            })
            .await
    }

    fn one_off_data(event: &ScheduledEvent) -> Map<String, Value> {
        let mut marker = Map::new();
        marker.insert("kind".into(), Value::from(KIND_ONCE));
        marker.insert("id".into(), event.id.clone().map(Value::from).unwrap_or(Value::Null));
        marker.insert("key".into(), event.key.clone().map(Value::from).unwrap_or(Value::Null));
        marker.insert("claimToken".into(), event.claim_token.clone().map(Value::from).unwrap_or(Value::Null));
        marker.insert("attempt".into(), Value::from(event.attempts));
        marker.insert(
            "runAt".into(),
            event.run_at.map(|t| Value::from(instant_text(t.timestamp_millis()))).unwrap_or(Value::Null),
        );
        let mut data = event.data.as_ref().map(document_to_json).unwrap_or_default();
        data.insert(SCHEDULE_DATA_KEY.into(), Value::Object(marker));
        data
    }

    fn one_off_que_object(event: &ScheduledEvent) -> EventMessage {
        EventMessage {
            app_code: event.app_code.clone(),
            client_code: event.client_code.clone(),
            event_name: event.event_name.clone(),
            draft: event.draft,
            data: Some(Self::one_off_data(event)),
            ..Default::default()
        }
    }

    async fn raise_one_off(&self, event: &ScheduledEvent, now: i64, counts: &Counts) -> Result<(), CoreError> {
        let id = event.id.clone().unwrap_or_default();
        let token = event.claim_token.clone().unwrap_or_default();
        // A claim past the last attempt is one whose lease ran out on that last attempt.
        if event.attempts > event.max_attempts {
            Counts::bump(&counts.one_offs_failed);
            self.store.fail_scheduled_event(&id, &token, None, Some("Lease ran out on the last attempt"), now).await?;
            let text = format!(
                "Gave up after {} attempts: the last attempt did not report back before its lease ran out, so it is not tried again.",
                event.max_attempts
            );
            self.log_run(&Self::one_off_que_object(event), Unrun::Failed, &text).await;
            return Ok(());
        }
        if self.refuse_if_inactive(event, &id, &token, now).await? {
            Counts::bump(&counts.one_offs_failed);
            return Ok(());
        }
        let qob = Self::one_off_que_object(event);
        match self.raiser.create_event(qob.clone(), event.draft).await {
            Ok(_) => Counts::bump(&counts.one_offs_raised),
            Err(e) => {
                Counts::bump(&counts.one_offs_failed);
                self.one_offs.finish(&id, &token, false, Some(&format!("Raise failed: {}", e.text()))).await?;
                self.log_run(&qob, Unrun::Failed, &format!("The scheduler could not raise the event: {}", e.text())).await;
            }
        }
        Ok(())
    }

    /// Closes a claimed one-off without raising it when its client is not active: FAILED with
    /// the reason and a line in the run log. True when it was closed.
    async fn refuse_if_inactive(&self, event: &ScheduledEvent, id: &str, token: &str, now: i64) -> Result<bool, CoreError> {
        let Some(client) = event.client_code.clone() else { return Ok(false) };
        let inactive = self.inactive_clients(HashSet::from([client.clone()]), now).await;
        if !inactive.contains(&client) {
            return Ok(false);
        }
        let reason = format!("The client '{client}' is deleted, inactive or locked, so the event was not raised.");
        self.store.fail_scheduled_event(id, token, None, Some(&reason), now).await?;
        self.log_run(&Self::one_off_que_object(event), Unrun::Failed, &reason).await;
        Ok(true)
    }

    async fn log_run(&self, qob: &EventMessage, status: Unrun, error: &str) {
        if let Some(log) = &self.run_log {
            log.record(qob, status, error).await;
        }
    }
}

fn que_object(app_code: &str, client_code: &str, event_name: &str, data: Map<String, Value>, draft: bool) -> EventMessage {
    EventMessage {
        app_code: Some(app_code.into()),
        client_code: Some(client_code.into()),
        event_name: Some(event_name.into()),
        draft,
        data: Some(data),
        ..Default::default()
    }
}

// ---------------------------------------------------------------- completion

/// The `_schedule` marker of a raised event, when the scheduler raised it.
pub fn schedule_marker(qob: &EventMessage) -> Option<&Map<String, Value>> {
    qob.data.as_ref()?.get(SCHEDULE_DATA_KEY)?.as_object()
}

/// `EventScheduler.trackCompletion`, for core-events: closes a scheduled run with the outcome
/// of its tasks (DONE or FAILED for a tick, DONE or retry-with-backoff for a one-off).
pub struct RunCompletion {
    store: Arc<ScheduleStore>,
    one_offs: Arc<ScheduledEventService>,
    clock: Clock,
}

impl RunCompletion {
    pub fn new(store: Arc<ScheduleStore>, one_offs: Arc<ScheduledEventService>) -> Self {
        Self { store, one_offs, clock: Arc::new(now_millis) }
    }

    /// Tests only.
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    /// Wraps the processing of one event. `Ok(None)` (nothing ran, no EventAction) counts as
    /// done; `Ok(Some(false))` is a failure; an error is a failure too, passed on after it is
    /// recorded. An event that did not come from the scheduler passes through untouched.
    pub async fn track<F>(&self, qob: &EventMessage, processing: F) -> Result<Option<bool>, CoreError>
    where
        F: Future<Output = Result<Option<bool>, CoreError>>,
    {
        if schedule_marker(qob).is_none() {
            return processing.await;
        }
        match processing.await {
            Err(e) => {
                // `e.getMessage()`.
                self.complete(qob, false, Some(&e.text())).await;
                Err(e)
            }
            Ok(ok) => {
                let ok = ok.unwrap_or(true);
                self.complete(qob, ok, (!ok).then_some("The EventAction reported a failure")).await;
                Ok(Some(ok))
            }
        }
    }

    async fn complete(&self, qob: &EventMessage, success: bool, error: Option<&str>) -> bool {
        let Some(marker) = schedule_marker(qob) else { return false };
        let text = |k: &str| marker.get(k).and_then(Value::as_str);
        let done = match (text("kind"), text("runId"), text("id"), text("claimToken")) {
            (Some(KIND_CRON), Some(run_id), _, _) => {
                let status = if success { RunState::Done } else { RunState::Failed };
                self.store.finish_run(run_id, status, error, (self.clock)()).await
            }
            (Some(KIND_ONCE), _, Some(id), Some(token)) => self.one_offs.finish(id, token, success, error).await,
            _ => Ok(false),
        };
        done.unwrap_or_else(|e| {
            tracing::warn!(
                "Scheduler could not close the run of {}.{} for {}: {e}",
                qob.app_code.as_deref().unwrap_or("null"),
                qob.event_name.as_deref().unwrap_or("null"),
                qob.client_code.as_deref().unwrap_or("null")
            );
            false
        })
    }
}

#[cfg(test)]
#[path = "event_scheduler_tests.rs"]
mod tests;
