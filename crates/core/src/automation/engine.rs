//! Runs automations: starts a run when its trigger event comes in, walks the steps, and parks
//! the run while it waits. core-events calls it for every event it receives.
//!
//! A KIRun run cannot be suspended, so a wait is not a sleep. The run's position is saved in
//! `automation_run`, a one-off is scheduled for when it should wake ([`WAKE_EVENT`]), and the
//! walk stops. The wake-up, or the event the run waits for, picks the run up where it stopped.
//!
//! **Each step runs at most once per visit, unless the process dies while it runs.** The run
//! carries a version; it is saved, version checked, before an action runs and again after.
//! Two deliveries racing on one run cannot both get past the first save, so the loser stops.
//! A crash between the two saves leaves the step at the head of the queue, and it runs again
//! when the run is next picked up: an action is run at least once, never skipped.
//!
//! **An event that comes before its wait is parked is not lost.** An action often causes the
//! very event the next step waits for (send a message, wait until it is read), and the event can
//! reach core-events before the run is saved as waiting. So the run starts listening for those
//! events before the action runs; one that arrives early is kept in `automation_inbox`, and
//! the wait looks there once it is parked.
//!
//! **A run follows the version of the automation it started with.** The steps are copied into
//! the run when it starts, so publishing a change affects new runs only.
//!
//! **Actions run as the client's event runner** (`Authorities._Event_Runner`), whatever started
//! the run, so an action that works before a two-day wait also works after it. core-events
//! sets that context before calling in; the engine itself never builds one.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use super::expr::{holds, instant, lookup, render, render_map, text_of};
use super::{period_seconds, ACTION, BRANCH_OTHERWISE, BRANCH_YES, CHECK, END, JOIN, SPLIT, WAIT};
use crate::error::CoreError;

/// The one-off event a parked run is woken by. core-events hands it to the engine instead of
/// looking for an EventAction; it needs no EventDefinition.
pub const WAKE_EVENT: &str = "_AUTOMATION_WAKE";

/// How many times a failed action is tried again before its `onFail` applies.
pub const MAX_RETRIES: u32 = 3;
/// The first wait before trying a failed action again; it doubles on each try.
pub const RETRY_BASE_SECONDS: i64 = 60;
/// A test run never waits longer than this.
pub const TEST_WAIT_SECONDS: i64 = 60;
/// How many times a wake-up or an event looks at a run again after losing a save to another
/// delivery.
pub const RESUME_TRIES: usize = 5;
/// Steps one pick-up of a run may walk before it is stopped as a runaway.
pub const STEP_BUDGET: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RunStatus {
    #[default]
    Running,
    Waiting,
    Done,
    Failed,
    Cancelled,
}

impl RunStatus {
    pub fn finished(self) -> bool {
        matches!(self, RunStatus::Done | RunStatus::Failed | RunStatus::Cancelled)
    }
}

/// What a parked step waits for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WaitKind {
    /// A length of time, or until a time.
    Time,
    /// An event, with a time limit when `until` is set.
    Event,
    /// A failed action, to be tried again.
    Retry,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Wait {
    pub kind: WaitKind,
    /// Epoch milliseconds the wake-up is set for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<i64>,
    /// The one-off's key; a wake-up carrying another key is stale and ignored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timer: Option<String>,
    #[serde(default)]
    pub attempt: u32,
}

/// An event a run is listening for: to go on after a wait (`node`), or to stop (no `node`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Listen {
    pub event: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<Value>,
    /// Set before the action ahead of the wait runs, so an event that action causes is kept
    /// even when it arrives before the wait is parked (see [`RunStore::inbox_put`]).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub early: bool,
}

/// One line of a run's history, as the run view draws it on the cards.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    /// DONE, FAILED, WAITING, RETRY, TIMED_OUT, HAPPENED, STARTED, STOPPED, CANCELLED.
    pub status: String,
    pub at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// One run of one automation, as `automation_run` keeps it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Run {
    pub id: String,
    pub app_code: String,
    pub client_code: String,
    pub draft: bool,
    pub automation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// The automation as it was when the run started: start, nodes, transitions, exitWhen.
    pub flow: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// `<automation>|<subject>` for an automation that runs once per subject: unique.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub once_key: Option<String>,
    pub status: RunStatus,
    /// Steps to walk next, in order.
    #[serde(default)]
    pub ready: Vec<String>,
    #[serde(default)]
    pub waits: BTreeMap<String, Wait>,
    #[serde(default)]
    pub listen: Vec<Listen>,
    /// The lanes that have reached each join so far.
    #[serde(default)]
    pub arrivals: BTreeMap<String, u32>,
    /// How many times each failing action has been tried again.
    #[serde(default)]
    pub attempts: BTreeMap<String, u32>,
    /// `{ trigger, steps }`.
    pub context: Value,
    #[serde(default)]
    pub log: Vec<LogEntry>,
    #[serde(default)]
    pub test: bool,
    /// A test run: the user who started it. Messages to people go to them alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_user: Option<u64>,
    /// Checked on every save.
    pub version: i64,
    pub created_at: i64,
    pub updated_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Run {
    fn node(&self, key: &str) -> Option<&Map<String, Value>> {
        self.flow.get("nodes")?.get(key)?.as_object()
    }

    fn node_type(&self, key: &str) -> &str {
        self.node(key).and_then(|n| n.get("type")).and_then(Value::as_str).unwrap_or("")
    }

    /// The steps after `key`; for a check, after its branch.
    fn next(&self, key: &str, branch: Option<&str>) -> Vec<String> {
        let Some(Value::Array(ts)) = self.flow.get("transitions") else { return vec![] };
        ts.iter()
            .filter_map(Value::as_object)
            .filter(|t| t.get("from").and_then(Value::as_str) == Some(key))
            .filter(|t| branch.is_none() || t.get("branch").and_then(Value::as_str) == branch)
            .filter_map(|t| t.get("to").and_then(Value::as_str).map(str::to_string))
            .collect()
    }

    /// The event-waits reached from `key` without another action or wait in between, with the
    /// event each waits for.
    fn event_waits_after(&self, key: &str) -> Vec<(String, String)> {
        let mut out = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        let mut todo = self.next(key, None);
        while let Some(k) = todo.pop() {
            if !seen.insert(k.clone()) {
                continue;
            }
            match self.node_type(&k) {
                WAIT => {
                    if let Some(e) = self.node(&k).and_then(|n| n.get("untilEvent")).and_then(|u| u.get("key")).and_then(Value::as_str) {
                        out.push((k.clone(), e.to_string()));
                    }
                }
                CHECK | SPLIT | JOIN => todo.extend(self.next(&k, None)),
                _ => {}
            }
        }
        out
    }

    fn incoming(&self, key: &str) -> u32 {
        let Some(Value::Array(ts)) = self.flow.get("transitions") else { return 0 };
        ts.iter().filter(|t| t.get("to").and_then(Value::as_str) == Some(key)).count() as u32
    }

    /// The context an expression reads, with `event` when one is being looked at.
    fn scope(&self, event: Option<&Value>) -> Value {
        let mut c = self.context.as_object().cloned().unwrap_or_default();
        c.insert("run".into(), json!({ "id": self.id, "test": self.test, "automation": self.automation }));
        if let Some(e) = event {
            c.insert("event".into(), e.clone());
        }
        Value::Object(c)
    }

    fn set_output(&mut self, node: &str, output: Value) {
        if !self.context.is_object() {
            self.context = json!({});
        }
        let ctx = self.context.as_object_mut().expect("just made an object");
        let steps = ctx.entry("steps").or_insert_with(|| json!({}));
        if !steps.is_object() {
            *steps = json!({});
        }
        steps.as_object_mut().expect("just made an object").insert(node.to_string(), output);
    }

    fn timer_key(&self, node: &str, attempt: u32) -> String {
        format!("auto-{}-{node}-{}-{attempt}", self.id, self.log.len())
    }
}

// ---------------------------------------------------------------- the seams

/// The automations that start on an event, as the client sees them on the event's surface:
/// published (or, on the draft surface, drafted), not paused.
#[async_trait]
pub trait Automations: Send + Sync {
    async fn triggered_by(&self, app: &str, client: &str, draft: bool, event: &str) -> Result<Vec<Value>, CoreError>;
}

/// `automation_run`.
#[async_trait]
pub trait RunStore: Send + Sync {
    /// False when a run with the same `once_key` exists already.
    async fn insert(&self, run: &Run) -> Result<bool, CoreError>;
    async fn get(&self, id: &str) -> Result<Option<Run>, CoreError>;
    /// Saves `run` when the stored one is still at `expected`; false when it moved on.
    async fn save(&self, run: &Run, expected: i64) -> Result<bool, CoreError>;
    /// The unfinished runs of the client that listen for `event`.
    async fn listening(&self, app: &str, client: &str, draft: bool, event: &str) -> Result<Vec<Run>, CoreError>;
    /// Keeps an event that came for a step not yet waiting.
    async fn inbox_put(&self, run_id: &str, node: &str, event: &str, data: &Value) -> Result<(), CoreError>;
    /// The events kept for a step, oldest first, and forgets them.
    async fn inbox_take(&self, run_id: &str, node: &str) -> Result<Vec<Value>, CoreError>;
}

/// Runs one action: a built-in (`core:...`) or a server function (`namespace.name`), for the
/// step `node` of `run`. The output is what later steps read as `steps.<key>`.
#[async_trait]
pub trait Actions: Send + Sync {
    async fn run(&self, action: &str, node: &str, params: Map<String, Value>, run: &Run) -> Result<Value, CoreError>;
}

/// The one-offs that wake parked runs.
#[async_trait]
pub trait Timers: Send + Sync {
    async fn set(&self, run: &Run, key: &str, at: i64, data: Map<String, Value>) -> Result<(), CoreError>;
    async fn cancel(&self, run: &Run, key: &str) -> Result<(), CoreError>;
}

pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

pub struct Engine {
    pub automations: Arc<dyn Automations>,
    pub runs: Arc<dyn RunStore>,
    pub actions: Arc<dyn Actions>,
    pub timers: Arc<dyn Timers>,
    pub clock: Clock,
}

/// What one event did: the runs it started and the waiting runs it moved on or stopped.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Handled {
    pub started: usize,
    pub resumed: usize,
}

impl Handled {
    pub fn any(&self) -> bool {
        self.started + self.resumed > 0
    }
}

fn new_id() -> String {
    mongodb::bson::oid::ObjectId::new().to_hex()
}

/// The event's data without the scheduler's marker.
fn clean(data: Option<&Map<String, Value>>) -> Value {
    let mut d = data.cloned().unwrap_or_default();
    d.remove(crate::event_scheduler::SCHEDULE_DATA_KEY);
    Value::Object(d)
}

impl Engine {
    fn now(&self) -> i64 {
        (self.clock)()
    }

    /// Everything an event means for the client's automations: waiting runs it moves on or
    /// stops, then the runs it starts. Errors of one run are logged and do not stop the others.
    pub async fn on_event(&self, app: &str, client: &str, draft: bool, event: &str, data: Option<&Map<String, Value>>) -> Result<Handled, CoreError> {
        let data = clean(data);
        let mut handled = Handled::default();
        for run in self.runs.listening(app, client, draft, event).await? {
            match self.heard(run, event, &data).await {
                Ok(true) => handled.resumed += 1,
                Ok(false) => {}
                Err(e) => tracing::warn!("Automation run could not take event {event} in {app} for {client}: {}", e.text()),
            }
        }
        for automation in self.automations.triggered_by(app, client, draft, event).await? {
            match self.start(app, client, draft, &automation, &data, false).await {
                Ok(Some(_)) => handled.started += 1,
                Ok(None) => {}
                Err(e) => tracing::warn!("Automation could not start on event {event} in {app} for {client}: {}", e.text()),
            }
        }
        Ok(handled)
    }

    /// Starts one run of `automation` on `trigger` data. `None` when its trigger filter does
    /// not hold, or it runs once per subject and has run for this one.
    pub async fn start(&self, app: &str, client: &str, draft: bool, automation: &Value, trigger: &Value, test: bool) -> Result<Option<Run>, CoreError> {
        self.start_as(app, client, draft, automation, trigger, test, None).await
    }

    /// A test run started by `user`, on the draft surface.
    /// A test run on the live (`draft` false) or the draft data, waits cut short, kept to the tester.
    pub async fn start_test(&self, app: &str, client: &str, draft: bool, automation: &Value, trigger: &Value, user: u64) -> Result<Option<Run>, CoreError> {
        self.start_as(app, client, draft, automation, trigger, true, Some(user)).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn start_as(
        &self,
        app: &str,
        client: &str,
        draft: bool,
        automation: &Value,
        trigger: &Value,
        test: bool,
        test_user: Option<u64>,
    ) -> Result<Option<Run>, CoreError> {
        let name = automation.get("name").and_then(Value::as_str).unwrap_or_default().to_string();
        let filter = automation.get("trigger").and_then(|t| t.get("filter"));
        let ctx = json!({ "trigger": trigger });
        if !holds(filter, &ctx) {
            return Ok(None);
        }
        let entry = automation.get("entry");
        let subject = entry
            .and_then(|e| e.get("subjectPath"))
            .and_then(Value::as_str)
            .filter(|p| !p.trim().is_empty())
            .and_then(|p| lookup(trigger, p))
            .map(text_of)
            .filter(|s| !s.is_empty());
        let once = entry.and_then(|e| e.get("oncePerSubject")).and_then(Value::as_bool).unwrap_or(false);
        let now = self.now();
        let mut flow = Map::new();
        for f in ["start", "nodes", "transitions", "exitWhen"] {
            flow.insert(f.into(), automation.get(f).cloned().unwrap_or(Value::Null));
        }
        let listen = match automation.get("exitWhen") {
            Some(Value::Array(l)) => l
                .iter()
                .filter_map(|x| {
                    let event = x.get("key").and_then(Value::as_str)?.to_string();
                    Some(Listen { event, node: None, filter: x.get("filter").cloned(), early: false })
                })
                .collect(),
            _ => vec![],
        };
        let mut run = Run {
            id: new_id(),
            app_code: app.into(),
            client_code: client.into(),
            draft,
            automation: name.clone(),
            title: automation.get("title").and_then(Value::as_str).map(str::to_string),
            flow: Value::Object(flow),
            once_key: (once && !test).then(|| subject.clone().map(|s| format!("{name}|{s}"))).flatten(),
            subject,
            status: RunStatus::Running,
            ready: automation.get("start").and_then(Value::as_str).map(|s| vec![s.to_string()]).unwrap_or_default(),
            listen,
            context: json!({ "trigger": trigger, "steps": {} }),
            log: vec![LogEntry { node: None, status: "STARTED".into(), at: now, until: None, branch: None, error: None }],
            test,
            test_user: test_user.filter(|_| test),
            version: 0,
            created_at: now,
            updated_at: now,
            ..Default::default()
        };
        if !self.runs.insert(&run).await? {
            return Ok(None);
        }
        self.walk(&mut run).await?;
        Ok(Some(run))
    }

    /// Stops a run by hand. `None` when it had already finished, or another delivery moved it
    /// on while it was being stopped.
    pub async fn cancel(&self, id: &str, why: &str) -> Result<Option<Run>, CoreError> {
        let Some(mut run) = self.runs.get(id).await? else { return Ok(None) };
        if run.status.finished() {
            return Ok(None);
        }
        let now = self.now();
        self.stop(&mut run, RunStatus::Cancelled, Some(why.to_string()), now).await;
        Ok(self.save(&mut run).await?.then_some(run))
    }

    /// A wake-up one-off: the run goes on from the step that set it, if it still waits there.
    /// The one-off is kept by the run's app, client and surface, so a wake-up from anywhere
    /// else (another client naming this run) is not this run's and is ignored.
    pub async fn wake(&self, app: &str, client: &str, draft: bool, data: Option<&Map<String, Value>>) -> Result<bool, CoreError> {
        let text = |k: &str| data.and_then(|d| d.get(k)).and_then(Value::as_str).map(str::to_string);
        let (Some(id), Some(node), Some(timer)) = (text("runId"), text("node"), text("timer")) else { return Ok(false) };
        for _ in 0..RESUME_TRIES {
            let Some(mut run) = self.runs.get(&id).await? else { return Ok(false) };
            if run.app_code != app || run.client_code != client || run.draft != draft {
                tracing::warn!("A wake-up for run {id} came from {app} / {client}, not the run's own; ignored.");
                return Ok(false);
            }
            let Some(wait) = run.waits.get(&node).cloned() else { return Ok(false) };
            if run.status.finished() || wait.timer.as_deref() != Some(timer.as_str()) {
                return Ok(false);
            }
            let now = self.now();
            run.waits.remove(&node);
            match wait.kind {
                WaitKind::Retry => {
                    // The action itself again, at the head of the queue.
                    run.ready.insert(0, node.clone());
                }
                WaitKind::Time => {
                    run.set_output(&node, json!({ "waited": true }));
                    self.log(&mut run, &node, "DONE", now, None, None);
                    let next = run.next(&node, None);
                    run.ready.extend(next);
                }
                WaitKind::Event => {
                    run.listen.retain(|l| l.node.as_deref() != Some(node.as_str()));
                    run.set_output(&node, json!({ "happened": false, "timedOut": true }));
                    self.log(&mut run, &node, "TIMED_OUT", now, None, None);
                    let next = run.next(&node, None);
                    run.ready.extend(next);
                }
            }
            run.status = RunStatus::Running;
            // The resume is claimed by saving it; a delivery that lost the race looks again.
            if !self.save(&mut run).await? {
                continue;
            }
            self.walk(&mut run).await?;
            return Ok(true);
        }
        Err(CoreError::unknown(format!("Automation run {id} kept moving on; the wake-up will be tried again")))
    }

    /// An event a run listens for came in. True when it moved the run on, stopped it, or was
    /// kept for a step not yet waiting.
    async fn heard(&self, run: Run, event: &str, data: &Value) -> Result<bool, CoreError> {
        if run.status.finished() {
            return Ok(false);
        }
        let id = run.id.clone();
        // A step that listens early and is not parked yet: keep the event for it, then look
        // at the run again, since it may have parked in the meantime. Kept first, read after:
        // a wait parks, then reads the inbox, so one of the two always sees the event.
        let early: Vec<String> = run
            .listen
            .iter()
            .filter(|l| l.event == event)
            .filter_map(|l| l.node.clone())
            .filter(|n| !run.waits.contains_key(n))
            .collect();
        for node in &early {
            self.runs.inbox_put(&id, node, event, data).await?;
        }
        let mut fresh = early.is_empty().then_some(run);
        for _ in 0..RESUME_TRIES {
            let mut run = match fresh.take() {
                Some(r) => r,
                None => match self.runs.get(&id).await? {
                    Some(r) if !r.status.finished() => r,
                    _ => return Ok(true),
                },
            };
            let now = self.now();
            let scope = run.scope(Some(data));
            if run.listen.iter().any(|l| l.event == event && l.node.is_none() && holds(l.filter.as_ref(), &scope)) {
                self.stop(&mut run, RunStatus::Cancelled, Some(format!("Stopped: {event} happened.")), now).await;
                if self.save(&mut run).await? {
                    return Ok(true);
                }
                continue;
            }
            let parked: Option<String> = run
                .listen
                .iter()
                .filter(|l| l.event == event)
                .filter_map(|l| l.node.clone())
                .find(|n| run.waits.contains_key(n) && self.matches(&run, n, data));
            let Some(node) = parked else { return Ok(!early.is_empty()) };
            self.happened(&mut run, &node, data, now).await?;
            run.status = RunStatus::Running;
            // The resume is claimed by saving it; a delivery that lost the race looks again.
            if !self.save(&mut run).await? {
                continue;
            }
            // Taken: whatever the inbox kept for the step is spent too.
            self.runs.inbox_take(&id, &node).await?;
            self.walk(&mut run).await?;
            return Ok(true);
        }
        Err(CoreError::unknown(format!("Automation run {id} kept moving on while event {event} came in")))
    }

    /// Whether `data` is what the parked step `node` waits for.
    fn matches(&self, run: &Run, node: &str, data: &Value) -> bool {
        let scope = run.scope(Some(data));
        run.listen.iter().any(|l| l.node.as_deref() == Some(node) && !l.early && holds(l.filter.as_ref(), &scope))
    }

    /// The step's event came: its time limit cancelled, the steps after it ready.
    async fn happened(&self, run: &mut Run, node: &str, data: &Value, now: i64) -> Result<(), CoreError> {
        if let Some(wait) = run.waits.remove(node) {
            if let Some(t) = &wait.timer {
                self.timers.cancel(run, t).await?;
            }
        }
        run.listen.retain(|l| l.node.as_deref() != Some(node));
        run.set_output(node, json!({ "happened": true, "timedOut": false, "event": data }));
        self.log(run, node, "HAPPENED", now, None, None);
        let next = run.next(node, None);
        run.ready.extend(next);
        Ok(())
    }

    fn log(&self, run: &mut Run, node: &str, status: &str, at: i64, until: Option<i64>, error: Option<String>) {
        run.log.push(LogEntry { node: Some(node.to_string()), status: status.to_string(), at, until, branch: None, error });
    }

    /// Saves the run, version checked. False when another delivery moved it on first.
    async fn save(&self, run: &mut Run) -> Result<bool, CoreError> {
        let expected = run.version;
        run.version += 1;
        run.updated_at = self.now();
        let saved = self.runs.save(run, expected).await?;
        if !saved {
            tracing::info!("Automation run {} was moved on by another delivery; this one stops", run.id);
        }
        Ok(saved)
    }

    /// Ends the run: every wake-up cancelled, nothing left to walk or listen for.
    async fn stop(&self, run: &mut Run, status: RunStatus, error: Option<String>, now: i64) {
        for wait in std::mem::take(&mut run.waits).into_values() {
            if let Some(t) = &wait.timer {
                if let Err(e) = self.timers.cancel(run, t).await {
                    tracing::warn!("Automation run {}: a wake-up could not be cancelled: {}", run.id, e.text());
                }
            }
        }
        run.ready.clear();
        run.listen.clear();
        run.status = status;
        run.finished_at = Some(now);
        run.error = error.clone();
        run.log.push(LogEntry { node: None, status: format!("{status:?}").to_uppercase(), at: now, until: None, branch: None, error });
    }

    /// Parks a step: a wake-up at `at`, saved before the one-off exists, so a wake-up never
    /// finds a run that does not know it waits.
    async fn park(&self, run: &mut Run, node: &str, kind: WaitKind, at: i64, attempt: u32) -> Result<bool, CoreError> {
        let timer = run.timer_key(node, attempt);
        run.waits.insert(node.to_string(), Wait { kind, until: Some(at), timer: Some(timer.clone()), attempt });
        if !self.save(run).await? {
            return Ok(false);
        }
        let mut data = Map::new();
        data.insert("runId".into(), json!(run.id));
        data.insert("node".into(), json!(node));
        data.insert("timer".into(), json!(timer));
        self.timers.set(run, &timer, at, data).await?;
        Ok(true)
    }

    /// The length of a wait, cut short in a test run.
    fn wait_ms(&self, run: &Run, seconds: i64) -> i64 {
        let s = if run.test { seconds.min(TEST_WAIT_SECONDS) } else { seconds };
        s * 1000
    }

    /// Walks the run until nothing is ready: every lane ended, or parked on a wait.
    async fn walk(&self, run: &mut Run) -> Result<(), CoreError> {
        let mut budget = STEP_BUDGET;
        while !run.ready.is_empty() {
            if budget == 0 {
                let now = self.now();
                self.stop(run, RunStatus::Failed, Some("The automation ran too many steps at once and was stopped.".into()), now).await;
                self.save(run).await?;
                return Ok(());
            }
            budget -= 1;
            let node = run.ready[0].clone();
            let now = self.now();
            let kind = run.node_type(&node).to_string();
            match kind.as_str() {
                ACTION => {
                    // Listen for what the waits right after this action wait for, before it
                    // runs: the action may cause the event, and it may come back at once.
                    for (wait, event) in run.event_waits_after(&node) {
                        if !run.listen.iter().any(|l| l.node.as_deref() == Some(wait.as_str())) {
                            run.listen.push(Listen { event, node: Some(wait), filter: None, early: true });
                        }
                    }
                    // The claim: no other delivery can run this step from the same version.
                    if !self.save(run).await? {
                        return Ok(());
                    }
                    run.ready.remove(0);
                    if !self.act(run, &node, now).await? {
                        return Ok(());
                    }
                }
                WAIT => {
                    run.ready.remove(0);
                    if !self.wait(run, &node, now).await? {
                        return Ok(());
                    }
                }
                CHECK => {
                    run.ready.remove(0);
                    let scope = run.scope(None);
                    let yes = holds(run.node(&node).and_then(|n| n.get("condition")), &scope);
                    let branch = if yes { BRANCH_YES } else { BRANCH_OTHERWISE };
                    run.set_output(&node, json!({ "result": yes }));
                    run.log.push(LogEntry { node: Some(node.clone()), status: "DONE".into(), at: now, until: None, branch: Some(branch.into()), error: None });
                    let next = run.next(&node, Some(branch));
                    run.ready.extend(next);
                }
                SPLIT => {
                    run.ready.remove(0);
                    self.log(run, &node, "DONE", now, None, None);
                    let next = run.next(&node, None);
                    run.ready.extend(next);
                }
                JOIN => {
                    run.ready.remove(0);
                    let arrived = run.arrivals.entry(node.clone()).or_default();
                    *arrived += 1;
                    if *arrived >= run.incoming(&node).max(1) {
                        run.arrivals.remove(&node);
                        self.log(run, &node, "DONE", now, None, None);
                        let next = run.next(&node, None);
                        run.ready.extend(next);
                    }
                }
                END => {
                    run.ready.remove(0);
                    self.log(run, &node, "DONE", now, None, None);
                }
                _ => {
                    run.ready.remove(0);
                    self.stop(run, RunStatus::Failed, Some(format!("The step \"{node}\" is not one the automation knows.")), now).await;
                    self.save(run).await?;
                    return Ok(());
                }
            }
        }
        let now = self.now();
        if run.waits.is_empty() {
            if !run.status.finished() {
                run.status = RunStatus::Done;
                run.finished_at = Some(now);
                run.listen.clear();
                run.log.push(LogEntry { node: None, status: "DONE".into(), at: now, until: None, branch: None, error: None });
            }
        } else {
            run.status = RunStatus::Waiting;
        }
        self.save(run).await?;
        Ok(())
    }

    /// Runs an action step. False when the run was parked or stopped and the walk must end.
    async fn act(&self, run: &mut Run, node: &str, now: i64) -> Result<bool, CoreError> {
        let n = run.node(node).cloned().unwrap_or_default();
        let action = n.get("action").and_then(Value::as_str).unwrap_or_default().to_string();
        let params = match n.get("params") {
            Some(Value::Object(p)) => render_map(p, &run.scope(None)),
            _ => Map::new(),
        };
        let attempt = run.attempts.get(node).copied().unwrap_or(0);
        match self.actions.run(&action, node, params, run).await {
            Ok(output) => {
                run.attempts.remove(node);
                run.set_output(node, output);
                self.log(run, node, "DONE", now, None, None);
                let next = run.next(node, None);
                run.ready.extend(next);
                Ok(true)
            }
            Err(e) => {
                let error = e.text();
                // 422: the action answered "no" (an app function's `error` event). Asking
                // again gives the same answer, so it fails at once.
                let refused = e.status() == axum::http::StatusCode::UNPROCESSABLE_ENTITY;
                if attempt < MAX_RETRIES && !refused {
                    let at = now + self.wait_ms(run, RETRY_BASE_SECONDS << attempt);
                    self.log(run, node, "RETRY", now, Some(at), Some(error));
                    run.attempts.insert(node.to_string(), attempt + 1);
                    // This lane is parked; the walk goes on with the others.
                    return self.park(run, node, WaitKind::Retry, at, attempt + 1).await;
                }
                run.attempts.remove(node);
                self.log(run, node, "FAILED", now, None, Some(error.clone()));
                let go_on = n.get("onFail").and_then(Value::as_str).is_some_and(|f| f.eq_ignore_ascii_case("CONTINUE"));
                if go_on {
                    run.set_output(node, json!({ "failed": true, "error": error }));
                    let next = run.next(node, None);
                    run.ready.extend(next);
                    return Ok(true);
                }
                self.stop(run, RunStatus::Failed, Some(format!("\"{}\" did not work: {error}", step_title(&n, node))), now).await;
                self.save(run).await?;
                Ok(false)
            }
        }
    }

    /// Parks a wait step, or passes straight through one whose time has come.
    async fn wait(&self, run: &mut Run, node: &str, now: i64) -> Result<bool, CoreError> {
        let n = run.node(node).cloned().unwrap_or_default();
        let scope = run.scope(None);
        let (kind, at) = if let Some(p) = n.get("for").and_then(Value::as_str) {
            match period_seconds(p) {
                Some(s) => (WaitKind::Time, Some(now + self.wait_ms(run, s as i64))),
                None => return self.broken(run, node, format!("\"{p}\" is not a length of time"), now).await,
            }
        } else if let Some(u) = n.get("until") {
            match instant(&render(u, &scope)) {
                Some(t) if run.test => (WaitKind::Time, Some(t.min(now + self.wait_ms(run, TEST_WAIT_SECONDS)))),
                Some(t) => (WaitKind::Time, Some(t)),
                None => return self.broken(run, node, "the time to wait until is not a time".into(), now).await,
            }
        } else if let Some(Value::Object(e)) = n.get("untilEvent") {
            let Some(event) = e.get("key").and_then(Value::as_str) else {
                return self.broken(run, node, "it does not say what to wait for".into(), now).await;
            };
            // The filter is read with the run's context now, so `{{steps...}}` in it are the
            // values of this run, and the event's own fields stay `event.*` paths.
            let filter = e.get("filter").map(|f| render_filter(f, &scope));
            run.listen.retain(|l| l.node.as_deref() != Some(node));
            run.listen.push(Listen { event: event.to_string(), node: Some(node.to_string()), filter, early: false });
            let limit = n.get("timeout").and_then(Value::as_str).and_then(period_seconds).map(|s| now + self.wait_ms(run, s as i64));
            self.log(run, node, "WAITING", now, limit, None);
            let parked = match limit {
                Some(at) => self.park(run, node, WaitKind::Event, at, 0).await?,
                None => {
                    run.waits.insert(node.to_string(), Wait { kind: WaitKind::Event, until: None, timer: None, attempt: 0 });
                    self.save(run).await?
                }
            };
            if !parked {
                return Ok(false);
            }
            // Parked and saved: an event that came before now is in the inbox.
            for data in self.runs.inbox_take(&run.id, node).await? {
                if self.matches(run, node, &data) {
                    self.happened(run, node, &data, self.now()).await?;
                    break;
                }
            }
            return Ok(true);
        } else {
            return self.broken(run, node, "it does not say how long to wait".into(), now).await;
        };
        let at = at.expect("every branch above sets a time");
        if at <= now && kind == WaitKind::Time {
            run.set_output(node, json!({ "waited": false }));
            self.log(run, node, "DONE", now, None, None);
            let next = run.next(node, None);
            run.ready.extend(next);
            return Ok(true);
        }
        self.log(run, node, "WAITING", now, Some(at), None);
        self.park(run, node, kind, at, 0).await
    }

    async fn broken(&self, run: &mut Run, node: &str, why: String, now: i64) -> Result<bool, CoreError> {
        let title = run.node(node).map(|n| step_title(n, node)).unwrap_or_else(|| node.to_string());
        self.log(run, node, "FAILED", now, None, Some(why.clone()));
        self.stop(run, RunStatus::Failed, Some(format!("\"{title}\" cannot wait: {why}.")), now).await;
        self.save(run).await?;
        Ok(false)
    }
}

/// A filter's `value`s rendered against the run, its `field`s left as paths.
fn render_filter(f: &Value, scope: &Value) -> Value {
    match f {
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, v)| {
                    let v = match k.as_str() {
                        "value" | "toValue" => render(v, scope),
                        "conditions" => match v {
                            Value::Array(a) => Value::Array(a.iter().map(|c| render_filter(c, scope)).collect()),
                            other => other.clone(),
                        },
                        _ => v.clone(),
                    };
                    (k.clone(), v)
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

fn step_title(n: &Map<String, Value>, key: &str) -> String {
    n.get("title").and_then(Value::as_str).map(str::trim).filter(|t| !t.is_empty()).unwrap_or(key).to_string()
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;
