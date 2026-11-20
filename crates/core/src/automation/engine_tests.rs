use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicI64, Ordering};

use parking_lot::Mutex;

use super::*;

// ---------------------------------------------------------------- fakes

struct MemAutomations(Vec<Value>);

#[async_trait]
impl Automations for MemAutomations {
    async fn triggered_by(&self, _app: &str, _client: &str, _draft: bool, event: &str) -> Result<Vec<Value>, CoreError> {
        Ok(self.0.iter().filter(|a| a.get("trigger").and_then(|t| t.get("key")).and_then(Value::as_str) == Some(event)).cloned().collect())
    }
}

#[derive(Default)]
struct MemRuns {
    inbox: Mutex<Vec<(String, String, Value)>>,
    runs: Mutex<HashMap<String, Run>>,
    once: Mutex<HashSet<String>>,
    /// Bumps the stored version once, before the next save, as another delivery would.
    race_next_save: Mutex<bool>,
}

#[async_trait]
impl RunStore for MemRuns {
    async fn insert(&self, run: &Run) -> Result<bool, CoreError> {
        if let Some(k) = &run.once_key {
            if !self.once.lock().insert(k.clone()) {
                return Ok(false);
            }
        }
        self.runs.lock().insert(run.id.clone(), run.clone());
        Ok(true)
    }
    async fn get(&self, id: &str) -> Result<Option<Run>, CoreError> {
        Ok(self.runs.lock().get(id).cloned())
    }
    async fn save(&self, run: &Run, expected: i64) -> Result<bool, CoreError> {
        let mut runs = self.runs.lock();
        let stored = runs.get_mut(&run.id).expect("inserted first");
        if std::mem::take(&mut *self.race_next_save.lock()) {
            stored.version += 1;
        }
        if stored.version != expected {
            return Ok(false);
        }
        *stored = run.clone();
        Ok(true)
    }
    async fn listening(&self, _app: &str, _client: &str, _draft: bool, event: &str) -> Result<Vec<Run>, CoreError> {
        Ok(self.runs.lock().values().filter(|r| !r.status.finished() && r.listen.iter().any(|l| l.event == event)).cloned().collect())
    }
    async fn inbox_put(&self, run_id: &str, node: &str, _event: &str, data: &Value) -> Result<(), CoreError> {
        self.inbox.lock().push((run_id.into(), node.into(), data.clone()));
        Ok(())
    }
    async fn inbox_take(&self, run_id: &str, node: &str) -> Result<Vec<Value>, CoreError> {
        let mut inbox = self.inbox.lock();
        let (taken, kept): (Vec<_>, Vec<_>) = inbox.drain(..).partition(|(r, n, _)| r == run_id && n == node);
        *inbox = kept;
        Ok(taken.into_iter().map(|(_, _, d)| d).collect())
    }
}

#[derive(Default)]
struct Script {
    /// Set for the actions that deliver an event while they run (`Ns.echo`), as a fast queue would.
    engine: std::sync::OnceLock<Arc<Engine>>,
    calls: Mutex<Vec<(String, Map<String, Value>)>>,
    /// Per action, what its next runs answer; an empty queue answers `{ "ok": true }`.
    answers: Mutex<HashMap<String, VecDeque<Result<Value, String>>>>,
}

impl Script {
    fn answer(&self, action: &str, a: Result<Value, &str>) {
        self.answers.lock().entry(action.into()).or_default().push_back(a.map_err(str::to_string));
    }
    fn called(&self) -> Vec<String> {
        self.calls.lock().iter().map(|(a, _)| a.clone()).collect()
    }
}

#[async_trait]
impl Actions for Script {
    async fn run(&self, action: &str, _node: &str, params: Map<String, Value>, _run: &Run) -> Result<Value, CoreError> {
        self.calls.lock().push((action.to_string(), params.clone()));
        if action == "Ns.echo" {
            let engine = self.engine.get().expect("set by the test").clone();
            let data = json!({ "n": params.get("n").cloned().unwrap_or(Value::Null) });
            Box::pin(engine.on_event("leadzumptwo", "FIN", false, "ECHO", data.as_object())).await?;
        }
        match self.answers.lock().get_mut(action).and_then(VecDeque::pop_front) {
            Some(Ok(v)) => Ok(v),
            // "refused: ..." stands for an app function's `error` event (422, final).
            Some(Err(e)) => match e.strip_prefix("refused: ") {
                Some(r) => Err(CoreError::new(axum::http::StatusCode::UNPROCESSABLE_ENTITY, r)),
                None => Err(CoreError::unknown(e)),
            },
            None => Ok(json!({ "ok": true })),
        }
    }
}

#[derive(Default)]
struct MemTimers(Mutex<BTreeMap<String, (i64, Map<String, Value>)>>);

#[async_trait]
impl Timers for MemTimers {
    async fn set(&self, _run: &Run, key: &str, at: i64, data: Map<String, Value>) -> Result<(), CoreError> {
        self.0.lock().insert(key.to_string(), (at, data));
        Ok(())
    }
    async fn cancel(&self, _run: &Run, key: &str) -> Result<(), CoreError> {
        self.0.lock().remove(key);
        Ok(())
    }
}

struct World {
    engine: Arc<Engine>,
    runs: Arc<MemRuns>,
    script: Arc<Script>,
    timers: Arc<MemTimers>,
    now: Arc<AtomicI64>,
}

const T0: i64 = 1_800_000_000_000;
const DAY: i64 = 86_400_000;

fn world(automations: Vec<Value>) -> World {
    let runs = Arc::new(MemRuns::default());
    let script = Arc::new(Script::default());
    let timers = Arc::new(MemTimers::default());
    let now = Arc::new(AtomicI64::new(T0));
    let n = now.clone();
    let engine = Arc::new(Engine {
        automations: Arc::new(MemAutomations(automations)),
        runs: runs.clone(),
        actions: script.clone(),
        timers: timers.clone(),
        clock: Arc::new(move || n.load(Ordering::SeqCst)),
    });
    let _ = script.engine.set(engine.clone());
    World { engine, runs, script, timers, now }
}

impl World {
    async fn event(&self, name: &str, data: Value) -> Handled {
        self.engine.on_event("leadzumptwo", "FIN", false, name, data.as_object()).await.unwrap()
    }
    fn only_run(&self) -> Run {
        let runs = self.runs.runs.lock();
        assert_eq!(runs.len(), 1, "one run expected");
        runs.values().next().unwrap().clone()
    }
    /// Moves the clock to the earliest wake-up and delivers it.
    async fn fire_next_timer(&self) -> bool {
        let next = self.timers.0.lock().iter().min_by_key(|(_, (at, _))| *at).map(|(k, v)| (k.clone(), v.clone()));
        let Some((key, (at, data))) = next else { return false };
        self.timers.0.lock().remove(&key);
        self.now.store(at, Ordering::SeqCst);
        self.engine.wake("leadzumptwo", "FIN", false, Some(&data)).await.unwrap()
    }
    fn statuses(&self) -> Vec<String> {
        self.only_run().log.iter().map(|l| format!("{}:{}", l.node.clone().unwrap_or_default(), l.status)).collect()
    }
}

/// Deal created: send the welcome, wait up to two days for it to be read, then a task when it
/// was, a reminder when it was not.
fn follow_up() -> Value {
    json!({
        "name": "followUp", "title": "Follow up a new deal",
        "trigger": {"key": "DEAL_CREATED", "filter": {"field": "trigger.source", "operator": "NOT_EQUALS", "value": "IMPORT"}},
        "entry": {"subjectPath": "dealId", "oncePerSubject": true},
        "exitWhen": [{"key": "DEAL_CLOSED", "filter": {"field": "event.dealId", "operator": "EQUALS", "value": "{{trigger.dealId}}"}}],
        "start": "welcome",
        "nodes": {
            "welcome": {"type": "ACTION", "title": "Send welcome", "action": "Lz.waSend", "params": {"template": "welcome", "dealId": "{{trigger.dealId}}", "to": "Hi {{trigger.name}}"}},
            "hold": {"type": "WAIT", "title": "Wait for a read", "untilEvent": {"key": "WA_STATUS", "filter": {"operator": "AND", "conditions": [
                {"field": "event.messageId", "operator": "EQUALS", "value": "{{steps.welcome.messageId}}"},
                {"field": "event.status", "operator": "EQUALS", "value": "read"}]}}, "timeout": "P2D"},
            "read": {"type": "CHECK", "condition": {"field": "steps.hold.happened", "operator": "IS_TRUE"}},
            "task": {"type": "ACTION", "action": "Lz.taskCreate", "params": {"dealId": "{{trigger.dealId}}"}},
            "again": {"type": "ACTION", "action": "Lz.waSend", "params": {"template": "reminder"}},
            "done": {"type": "END"}
        },
        "transitions": [
            {"from": "welcome", "to": "hold"}, {"from": "hold", "to": "read"},
            {"from": "read", "to": "task", "branch": "yes"}, {"from": "read", "to": "again", "branch": "otherwise"},
            {"from": "task", "to": "done"}, {"from": "again", "to": "done"}
        ]
    })
}

// ---------------------------------------------------------------- the flows

#[tokio::test]
async fn read_in_time_takes_the_yes_path() {
    let w = world(vec![follow_up()]);
    w.script.answer("Lz.waSend", Ok(json!({"messageId": "wamid.7"})));
    let h = w.event("DEAL_CREATED", json!({"dealId": 42, "name": "Asha", "source": "WEB", "_schedule": {"kind": "once"}})).await;
    assert_eq!(h, Handled { started: 1, resumed: 0 });

    let run = w.only_run();
    assert_eq!(run.status, RunStatus::Waiting);
    assert_eq!(run.subject.as_deref(), Some("42"));
    assert_eq!(run.waits["hold"].until, Some(T0 + 2 * DAY));
    assert!(run.context["trigger"].get("_schedule").is_none(), "the scheduler's marker is not trigger data");
    let sent = w.script.calls.lock()[0].1.clone();
    assert_eq!(Value::Object(sent), json!({"template": "welcome", "dealId": 42, "to": "Hi Asha"}));
    assert_eq!(w.timers.0.lock().len(), 1);

    // Another message's status, and this message delivered but not read: still waiting.
    assert_eq!(w.event("WA_STATUS", json!({"messageId": "wamid.other", "status": "read"})).await.resumed, 0);
    assert_eq!(w.event("WA_STATUS", json!({"messageId": "wamid.7", "status": "delivered"})).await.resumed, 0);
    assert_eq!(w.event("WA_STATUS", json!({"messageId": "wamid.7", "status": "read"})).await.resumed, 1);

    let run = w.only_run();
    assert_eq!(run.status, RunStatus::Done);
    assert!(w.timers.0.lock().is_empty(), "the time limit is cancelled once the event came");
    assert_eq!(w.script.called(), vec!["Lz.waSend", "Lz.taskCreate"]);
    assert_eq!(run.context["steps"]["hold"]["event"]["status"], json!("read"));
    assert_eq!(
        w.statuses(),
        vec![":STARTED", "welcome:DONE", "hold:WAITING", "hold:HAPPENED", "read:DONE", "task:DONE", "done:DONE", ":DONE"]
    );
    assert_eq!(run.log.iter().find(|l| l.node.as_deref() == Some("read")).unwrap().branch.as_deref(), Some("yes"));
}

#[tokio::test]
async fn not_read_in_two_days_takes_the_otherwise_path() {
    let w = world(vec![follow_up()]);
    w.event("DEAL_CREATED", json!({"dealId": 42})).await;
    assert!(w.fire_next_timer().await);
    let run = w.only_run();
    assert_eq!(run.status, RunStatus::Done);
    assert!(run.listen.is_empty());
    assert_eq!(w.script.called(), vec!["Lz.waSend", "Lz.waSend"]);
    assert_eq!(w.script.calls.lock()[1].1["template"], json!("reminder"));
    assert!(w.statuses().contains(&"hold:TIMED_OUT".to_string()));
    // A late status for a finished run changes nothing.
    assert_eq!(w.event("WA_STATUS", json!({"status": "read"})).await, Handled::default());
}

#[tokio::test]
async fn filters_once_per_subject_and_exits() {
    let w = world(vec![follow_up()]);
    assert_eq!(w.event("DEAL_CREATED", json!({"dealId": 1, "source": "IMPORT"})).await.started, 0, "the trigger filter holds it back");
    assert_eq!(w.event("DEAL_CREATED", json!({"dealId": 1})).await.started, 1);
    assert_eq!(w.event("DEAL_CREATED", json!({"dealId": 1})).await.started, 0, "once per deal");

    assert_eq!(w.event("DEAL_CLOSED", json!({"dealId": 2})).await.resumed, 0, "another deal closing changes nothing");
    assert_eq!(w.event("DEAL_CLOSED", json!({"dealId": 1})).await.resumed, 1);
    let run = w.only_run();
    assert_eq!(run.status, RunStatus::Cancelled);
    assert!(run.error.as_deref().unwrap().contains("DEAL_CLOSED"));
    assert!(w.timers.0.lock().is_empty(), "the wake-up is cancelled with the run");
    assert!(!w.fire_next_timer().await);
}

#[tokio::test]
async fn stale_and_unknown_wake_ups_are_ignored() {
    let w = world(vec![follow_up()]);
    w.event("DEAL_CREATED", json!({"dealId": 5})).await;
    let run = w.only_run();
    let mut data = Map::new();
    data.insert("runId".into(), json!(run.id));
    data.insert("node".into(), json!("hold"));
    data.insert("timer".into(), json!("auto-not-this-one"));
    assert!(!w.engine.wake("leadzumptwo", "FIN", false, Some(&data)).await.unwrap());
    // The right timer, but raised for another client, app or surface: not this run's.
    let real = w.timers.0.lock().values().next().unwrap().1.clone();
    assert!(!w.engine.wake("leadzumptwo", "FIN2", false, Some(&real)).await.unwrap());
    assert!(!w.engine.wake("adzumptwo", "FIN", false, Some(&real)).await.unwrap());
    assert!(!w.engine.wake("leadzumptwo", "FIN", true, Some(&real)).await.unwrap());
    assert_eq!(w.only_run().status, RunStatus::Waiting);
    data.insert("runId".into(), json!("nope"));
    assert!(!w.engine.wake("leadzumptwo", "FIN", false, Some(&data)).await.unwrap());
    assert!(!w.engine.wake("leadzumptwo", "FIN", false, None).await.unwrap());
    assert_eq!(w.only_run().status, RunStatus::Waiting);
    assert!(w.engine.wake("leadzumptwo", "FIN", false, Some(&real)).await.unwrap(), "its own wake-up still works");
}

#[tokio::test]
async fn a_refusal_fails_the_step_at_once() {
    let flow = |on_fail: &str| json!({
        "name": "notify", "trigger": {"key": "E"}, "start": "a",
        "nodes": {"a": {"type": "ACTION", "title": "Email the customer", "action": "Ns.mail", "onFail": on_fail}, "b": {"type": "ACTION", "action": "Ns.after"}},
        "transitions": [{"from": "a", "to": "b"}]
    });
    let w = world(vec![flow("STOP")]);
    w.script.answer("Ns.mail", Err("refused: There is no address to send to."));
    w.event("E", json!({})).await;
    let run = w.only_run();
    assert_eq!(run.status, RunStatus::Failed, "no retry for an answer that will not change");
    assert_eq!(run.error.as_deref(), Some("\"Email the customer\" did not work: There is no address to send to."));
    assert!(w.timers.0.lock().is_empty());
    assert_eq!(w.script.called(), vec!["Ns.mail"]);

    let w = world(vec![flow("CONTINUE")]);
    w.script.answer("Ns.mail", Err("refused: NO_ADDRESS"));
    w.event("E", json!({})).await;
    let run = w.only_run();
    assert_eq!(run.status, RunStatus::Done);
    assert_eq!(run.context["steps"]["a"]["failed"], json!(true));
    assert_eq!(w.script.called(), vec!["Ns.mail", "Ns.after"]);
}

#[tokio::test]
async fn a_failing_action_is_tried_again_then_stops_the_run() {
    let flow = json!({
        "name": "notify", "trigger": {"key": "E"}, "start": "a",
        "nodes": {"a": {"type": "ACTION", "title": "Tell the owner", "action": "Ns.flaky"}, "b": {"type": "ACTION", "action": "Ns.after"}},
        "transitions": [{"from": "a", "to": "b"}]
    });
    let w = world(vec![flow.clone()]);
    w.script.answer("Ns.flaky", Err("busy"));
    w.script.answer("Ns.flaky", Err("busy"));
    w.event("E", json!({})).await;
    assert_eq!(w.only_run().waits["a"].until, Some(T0 + 60_000));
    assert!(w.fire_next_timer().await);
    assert_eq!(w.only_run().waits["a"].until, Some(T0 + 60_000 + 120_000), "the wait doubles");
    assert!(w.fire_next_timer().await);
    let run = w.only_run();
    assert_eq!(run.status, RunStatus::Done);
    assert!(run.attempts.is_empty());
    assert_eq!(w.script.called(), vec!["Ns.flaky", "Ns.flaky", "Ns.flaky", "Ns.after"]);

    let w = world(vec![flow]);
    for _ in 0..=MAX_RETRIES {
        w.script.answer("Ns.flaky", Err("down"));
    }
    w.event("E", json!({})).await;
    while w.fire_next_timer().await {}
    let run = w.only_run();
    assert_eq!(run.status, RunStatus::Failed);
    assert_eq!(run.error.as_deref(), Some("\"Tell the owner\" did not work: down"));
    assert_eq!(w.script.called().len(), 1 + MAX_RETRIES as usize);
    assert!(!w.script.called().contains(&"Ns.after".to_string()));
}

#[tokio::test]
async fn on_fail_continue_goes_on() {
    let w = world(vec![json!({
        "name": "n", "trigger": {"key": "E"}, "start": "a",
        "nodes": {"a": {"type": "ACTION", "action": "Ns.x", "onFail": "CONTINUE"}, "b": {"type": "ACTION", "action": "Ns.y"}},
        "transitions": [{"from": "a", "to": "b"}]
    })]);
    for _ in 0..=MAX_RETRIES {
        w.script.answer("Ns.x", Err("no"));
    }
    w.event("E", json!({})).await;
    while w.fire_next_timer().await {}
    let run = w.only_run();
    assert_eq!(run.status, RunStatus::Done);
    assert_eq!(run.context["steps"]["a"], json!({"failed": true, "error": "no"}));
    assert_eq!(w.script.called().last().unwrap(), "Ns.y");
}

#[tokio::test]
async fn lanes_split_and_join() {
    let w = world(vec![json!({
        "name": "both", "trigger": {"key": "E"}, "start": "s",
        "nodes": {
            "s": {"type": "SPLIT"},
            "mail": {"type": "ACTION", "action": "core:sendEmail"},
            "pause": {"type": "WAIT", "for": "PT1H"},
            "note": {"type": "ACTION", "action": "Ns.note"},
            "j": {"type": "JOIN"},
            "last": {"type": "ACTION", "action": "Ns.last"}
        },
        "transitions": [
            {"from": "s", "to": "mail"}, {"from": "s", "to": "pause"}, {"from": "pause", "to": "note"},
            {"from": "mail", "to": "j"}, {"from": "note", "to": "j"}, {"from": "j", "to": "last"}
        ]
    })]);
    w.event("E", json!({})).await;
    let run = w.only_run();
    assert_eq!(run.status, RunStatus::Waiting);
    assert_eq!(run.arrivals.get("j"), Some(&1), "one lane is at the join");
    assert_eq!(w.script.called(), vec!["core:sendEmail"]);
    assert!(w.fire_next_timer().await);
    assert_eq!(w.only_run().status, RunStatus::Done);
    assert_eq!(w.script.called(), vec!["core:sendEmail", "Ns.note", "Ns.last"], "the join goes on once, when both lanes are in");
}

#[tokio::test]
async fn a_delivery_that_loses_the_race_runs_nothing() {
    let w = world(vec![follow_up()]);
    *w.runs.race_next_save.lock() = true;
    w.event("DEAL_CREATED", json!({"dealId": 9})).await;
    assert!(w.script.called().is_empty(), "the claim before the action failed, so the action did not run");
}

#[tokio::test]
async fn a_test_run_waits_a_minute_at_most() {
    let w = world(vec![]);
    let run = w.engine.start("leadzumptwo", "FIN", true, &follow_up(), &json!({"dealId": 3}), true).await.unwrap().unwrap();
    assert!(run.test && run.draft);
    assert_eq!(run.once_key, None, "a test run never uses up the deal's one run");
    assert_eq!(run.waits["hold"].until, Some(T0 + TEST_WAIT_SECONDS * 1000));
}

#[tokio::test]
async fn a_test_run_can_use_the_live_data_or_the_draft_copy() {
    let w = world(vec![]);
    let live = w.engine.start_test("leadzumptwo", "FIN", false, &follow_up(), &json!({"dealId": 3}), 142).await.unwrap().unwrap();
    assert!(live.test && !live.draft, "a live test reads and writes the real records");
    assert_eq!(live.test_user, Some(142));
    assert_eq!(live.waits["hold"].until, Some(T0 + TEST_WAIT_SECONDS * 1000), "its waits are still cut short");
    let draft = w.engine.start_test("leadzumptwo", "FIN", true, &follow_up(), &json!({"dealId": 4}), 142).await.unwrap().unwrap();
    assert!(draft.test && draft.draft);
}

#[tokio::test]
async fn waits_until_a_time_and_broken_waits() {
    let at = "2027-01-15T10:00:00Z";
    let w = world(vec![json!({
        "name": "visit", "trigger": {"key": "E"}, "start": "w",
        "nodes": {"w": {"type": "WAIT", "until": "{{trigger.visitAt}}"}, "a": {"type": "ACTION", "action": "Ns.remind"}},
        "transitions": [{"from": "w", "to": "a"}]
    })]);
    w.event("E", json!({"visitAt": at})).await;
    assert_eq!(w.only_run().waits["w"].until, super::super::expr::instant(&json!(at)));

    // A time already past goes straight on.
    let w2 = world(vec![json!({
        "name": "visit", "trigger": {"key": "E"}, "start": "w",
        "nodes": {"w": {"type": "WAIT", "until": "{{trigger.visitAt}}"}, "a": {"type": "ACTION", "action": "Ns.remind"}},
        "transitions": [{"from": "w", "to": "a"}]
    })]);
    w2.event("E", json!({"visitAt": "2020-01-01"})).await;
    assert_eq!(w2.only_run().status, RunStatus::Done);
    assert_eq!(w2.script.called(), vec!["Ns.remind"]);

    // No time at all: the run stops and says why.
    let w3 = world(vec![json!({"name": "v", "title": "x", "trigger": {"key": "E"}, "start": "w", "nodes": {"w": {"type": "WAIT", "title": "Until the visit", "until": "{{trigger.nothing}}"}}})]);
    w3.event("E", json!({})).await;
    let run = w3.only_run();
    assert_eq!(run.status, RunStatus::Failed);
    assert_eq!(run.error.as_deref(), Some("\"Until the visit\" cannot wait: the time to wait until is not a time."));
}

#[tokio::test]
async fn a_runaway_is_stopped() {
    let w = world(vec![json!({
        "name": "spin", "trigger": {"key": "E"}, "start": "c",
        "nodes": {"c": {"type": "CHECK", "condition": {"operator": "AND", "conditions": []}}},
        "transitions": [{"from": "c", "to": "c", "branch": "yes"}]
    })]);
    w.event("E", json!({})).await;
    let run = w.only_run();
    assert_eq!(run.status, RunStatus::Failed);
    assert!(run.error.unwrap().contains("too many steps"));
}

#[tokio::test]
async fn a_wait_with_no_time_limit_listens_until_the_event() {
    let w = world(vec![json!({
        "name": "reply", "trigger": {"key": "E"}, "start": "w",
        "nodes": {"w": {"type": "WAIT", "untilEvent": {"key": "REPLY"}}, "a": {"type": "ACTION", "action": "Ns.thank"}},
        "transitions": [{"from": "w", "to": "a"}]
    })]);
    w.event("E", json!({})).await;
    let run = w.only_run();
    assert_eq!(run.status, RunStatus::Waiting);
    assert!(w.timers.0.lock().is_empty());
    assert_eq!(w.event("REPLY", json!({"text": "yes"})).await.resumed, 1);
    assert_eq!(w.only_run().status, RunStatus::Done);
    assert_eq!(w.script.called(), vec!["Ns.thank"]);
}

#[tokio::test]
async fn a_run_stopped_by_hand_cancels_its_wake_up() {
    let w = world(vec![follow_up()]);
    w.event("DEAL_CREATED", json!({"dealId": 8})).await;
    let id = w.only_run().id;
    let run = w.engine.cancel(&id, "Stopped by user 7.").await.unwrap().unwrap();
    assert_eq!(run.status, RunStatus::Cancelled);
    assert!(w.timers.0.lock().is_empty());
    assert_eq!(w.engine.cancel(&id, "again").await.unwrap(), None, "a finished run cannot be stopped again");
}

#[tokio::test]
async fn an_event_the_action_causes_before_the_wait_parks_is_not_lost() {
    let w = world(vec![json!({
        "name": "echo", "trigger": {"key": "E"}, "start": "send",
        "nodes": {
            "send": {"type": "ACTION", "action": "Ns.echo", "params": {"n": "{{trigger.n}}"}},
            "hear": {"type": "WAIT", "timeout": "PT2M",
                     "untilEvent": {"key": "ECHO", "filter": {"field": "event.n", "operator": "EQUALS", "value": "{{trigger.n}}"}}},
            "after": {"type": "ACTION", "action": "Ns.after"}
        },
        "transitions": [{"from": "send", "to": "hear"}, {"from": "hear", "to": "after"}]
    })]);
    w.event("E", json!({"n": 5})).await;
    let run = w.only_run();
    assert_eq!(run.status, RunStatus::Done, "{:?}", w.statuses());
    assert!(w.statuses().contains(&"hear:HAPPENED".to_string()), "{:?}", w.statuses());
    assert_eq!(w.script.called(), vec!["Ns.echo", "Ns.after"]);
    assert!(w.timers.0.lock().is_empty(), "the time limit is cancelled");
    assert!(w.runs.inbox.lock().is_empty(), "the kept event was taken");
    assert!(run.listen.is_empty());

    // An early event that does not match the filter is kept, looked at, and does not resume.
    let w = world(vec![json!({
        "name": "echo", "trigger": {"key": "E"}, "start": "send",
        "nodes": {
            "send": {"type": "ACTION", "action": "Ns.echo", "params": {"n": 1}},
            "hear": {"type": "WAIT", "timeout": "PT2M",
                     "untilEvent": {"key": "ECHO", "filter": {"field": "event.n", "operator": "EQUALS", "value": 2}}}
        },
        "transitions": [{"from": "send", "to": "hear"}]
    })]);
    w.event("E", json!({})).await;
    assert_eq!(w.only_run().status, RunStatus::Waiting);
    assert!(w.runs.inbox.lock().is_empty());
}

#[tokio::test]
async fn an_event_that_loses_a_save_looks_again() {
    let w = world(vec![follow_up()]);
    w.script.answer("Lz.waSend", Ok(json!({"messageId": "wamid.9"})));
    w.event("DEAL_CREATED", json!({"dealId": 77})).await;
    // Another delivery saves first, once: the event's resume must not be lost.
    *w.runs.race_next_save.lock() = true;
    assert_eq!(w.event("WA_STATUS", json!({"messageId": "wamid.9", "status": "read"})).await.resumed, 1);
    let run = w.only_run();
    assert_eq!(run.status, RunStatus::Done, "{:?}", w.statuses());
    assert_eq!(w.script.called(), vec!["Lz.waSend", "Lz.taskCreate"]);

    // The same for a wake-up.
    let w = world(vec![follow_up()]);
    w.event("DEAL_CREATED", json!({"dealId": 78})).await;
    *w.runs.race_next_save.lock() = true;
    assert!(w.fire_next_timer().await);
    assert_eq!(w.only_run().status, RunStatus::Done);
}
