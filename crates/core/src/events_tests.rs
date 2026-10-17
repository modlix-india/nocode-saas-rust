//! `EventsQueListenerTaskExecutionTest`, `EventsQueListenerRunLogTest`,
//! `EventsQueListenerAnonymousContextTest` and `UnhandledEventLogTest`.

use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;
use serde_json::json;

use super::*;
use crate::authorities::has_authority;

fn message() -> EventMessage {
    EventMessage {
        event_name: Some("leadCreated".into()),
        app_code: Some("leadzumptwo".into()),
        client_code: Some("FIN".into()),
        ..Default::default()
    }
}

/// Logs when it is called and when it finishes; a short sleep makes an overlapping second task
/// show up between the two.
struct Scripted {
    log: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl TaskExecutor for Scripted {
    async fn execute(&self, task: &ActionTask, _qob: &EventMessage) -> TaskResult {
        let p = task.parameters.clone().unwrap_or_default();
        let name = p.get("name").and_then(Value::as_str).unwrap_or("").to_string();
        let result = p.get("result").and_then(Value::as_str).unwrap_or("true").to_string();
        self.log.lock().push(format!("start {name}"));
        if result == "throw" {
            return TaskResult::from(Err(CoreError::unknown(format!("thrown by {name}"))));
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        self.log.lock().push(format!("end {name}"));
        match result.as_str() {
            "error" => Err(CoreError::unknown(format!("failed {name}"))),
            "empty" => Ok(None),
            "false" => Ok(Some(false)),
            _ => Ok(Some(true)),
        }
        .into()
    }
}

fn task(key: Option<&str>, order: Option<i32>, kind: Option<&str>, name: &str, result: &str) -> JValue {
    let mut m = JMap::new();
    if let Some(k) = key {
        m.insert("key".into(), JValue::Str(k.into()));
    }
    if let Some(o) = order {
        m.insert("order".into(), JValue::Int(o.into()));
    }
    if let Some(t) = kind {
        m.insert("type".into(), JValue::Str(t.into()));
    }
    let mut p = JMap::new();
    p.insert("name".into(), JValue::Str(name.into()));
    p.insert("result".into(), JValue::Str(result.into()));
    m.insert("parameters".into(), JValue::Object(p));
    JValue::Object(m)
}

fn action(tasks: Vec<(&str, JValue)>) -> JMap {
    let mut t = JMap::new();
    for (k, v) in tasks {
        t.insert(k.into(), v);
    }
    let mut a = JMap::new();
    a.insert("tasks".into(), JValue::Object(t));
    a
}

struct NoActions;

#[async_trait]
impl EventActions for NoActions {
    async fn read(&self, _: &str, _: &str, _: &str, _: bool) -> Result<Option<JMap>, CoreError> {
        Ok(None)
    }
}

struct NoClients;

#[async_trait]
impl ClientLookup for NoClients {
    async fn client_by_code(&self, _: &str) -> Result<Option<Value>, CoreError> {
        Ok(None)
    }
}

fn scripted_listener() -> (EventsListener, Arc<Mutex<Vec<String>>>) {
    let log = Arc::new(Mutex::new(Vec::new()));
    let ex: Arc<dyn TaskExecutor> = Arc::new(Scripted { log: log.clone() });
    let l = EventsListener::new(Arc::new(NoActions), Arc::new(NoClients))
        .with_executor(CALL_CORE_FUNCTION, ex.clone())
        .with_executor(SEND_EMAIL, ex);
    (l, log)
}

async fn execute(l: &EventsListener, a: &JMap) -> bool {
    l.execute_tasks(&sorted_tasks(a), &message(), &mut Vec::new()).await
}

#[tokio::test]
async fn tasks_run_one_after_another_in_order_not_insertion_order() {
    let (l, log) = scripted_listener();
    let a = action(vec![
        ("c", task(Some("c"), Some(3), Some(CALL_CORE_FUNCTION), "third", "true")),
        ("a", task(Some("a"), Some(1), Some(SEND_EMAIL), "first", "true")),
        ("b", task(Some("b"), Some(2), Some(CALL_CORE_FUNCTION), "second", "true")),
    ]);
    assert!(execute(&l, &a).await);
    assert_eq!(*log.lock(), ["start first", "end first", "start second", "end second", "start third", "end third"]);
}

#[tokio::test]
async fn equal_orders_are_broken_by_the_map_key_and_a_null_order_is_zero() {
    let (l, log) = scripted_listener();
    let a = action(vec![
        ("z", task(Some("z"), Some(0), Some(CALL_CORE_FUNCTION), "z", "true")),
        ("late", task(Some("late"), Some(5), Some(CALL_CORE_FUNCTION), "late", "true")),
        ("m", task(Some("m"), None, Some(CALL_CORE_FUNCTION), "m", "true")),
        ("a", task(Some("a"), Some(0), Some(CALL_CORE_FUNCTION), "a", "true")),
    ]);
    assert!(execute(&l, &a).await);
    assert_eq!(*log.lock(), ["start a", "end a", "start m", "end m", "start z", "end z", "start late", "end late"]);
}

#[tokio::test]
async fn a_failing_middle_task_does_not_stop_the_later_ones_and_the_action_fails() {
    let (l, log) = scripted_listener();
    let a = action(vec![
        ("a", task(Some("a"), Some(1), Some(CALL_CORE_FUNCTION), "first", "true")),
        ("b", task(Some("b"), Some(2), Some(CALL_CORE_FUNCTION), "second", "error")),
        ("c", task(Some("c"), Some(3), Some(SEND_EMAIL), "third", "true")),
    ]);
    assert!(!execute(&l, &a).await);
    assert_eq!(*log.lock(), ["start first", "end first", "start second", "end second", "start third", "end third"]);
}

#[tokio::test]
async fn an_executor_that_throws_is_isolated_the_same_way() {
    let (l, log) = scripted_listener();
    let a = action(vec![
        ("a", task(Some("a"), Some(1), Some(CALL_CORE_FUNCTION), "first", "throw")),
        ("b", task(Some("b"), Some(2), Some(CALL_CORE_FUNCTION), "second", "true")),
    ]);
    assert!(!execute(&l, &a).await);
    assert_eq!(*log.lock(), ["start first", "start second", "end second"]);
}

#[tokio::test]
async fn an_unknown_task_type_is_isolated_the_same_way() {
    let (l, log) = scripted_listener();
    let a = action(vec![
        ("a", task(Some("a"), Some(1), Some(CALL_CORE_FUNCTION), "first", "true")),
        ("b", task(Some("b"), Some(2), None, "unknown", "true")),
        ("c", task(Some("c"), Some(3), Some(SEND_EMAIL), "third", "true")),
    ]);
    let mut outcomes = Vec::new();
    assert!(!l.execute_tasks(&sorted_tasks(&a), &message(), &mut outcomes).await);
    assert_eq!(*log.lock(), ["start first", "end first", "start third", "end third"]);
    assert_eq!(outcomes[1].error.as_deref(), Some("Invalid task type : null"));
    // A null task in the map is the same unknown type.
    let mut nulls = JMap::new();
    nulls.insert("x".into(), JValue::Null);
    let mut a = JMap::new();
    a.insert("tasks".into(), JValue::Object(nulls));
    assert!(!execute(&l, &a).await);
}

#[tokio::test]
async fn a_task_reporting_false_fails_the_action() {
    let (l, log) = scripted_listener();
    let a = action(vec![
        ("a", task(Some("a"), Some(1), Some(CALL_CORE_FUNCTION), "first", "false")),
        ("b", task(Some("b"), Some(2), Some(CALL_CORE_FUNCTION), "second", "true")),
    ]);
    assert!(!execute(&l, &a).await);
    assert_eq!(log.lock().len(), 4);
}

#[tokio::test]
async fn tasks_with_a_null_key_do_not_throw() {
    let (l, log) = scripted_listener();
    let a = action(vec![
        ("b", task(None, Some(1), Some(CALL_CORE_FUNCTION), "b", "true")),
        ("a", task(None, Some(1), Some(CALL_CORE_FUNCTION), "a", "true")),
    ]);
    assert!(execute(&l, &a).await);
    assert_eq!(*log.lock(), ["start a", "end a", "start b", "end b"]);
}

#[tokio::test]
async fn all_succeeding_is_true_and_an_empty_task_counts_as_success() {
    let (l, log) = scripted_listener();
    let a = action(vec![
        ("a", task(Some("a"), Some(1), Some(CALL_CORE_FUNCTION), "first", "empty")),
        ("b", task(Some("b"), Some(2), Some(SEND_EMAIL), "second", "true")),
    ]);
    assert!(execute(&l, &a).await);
    assert_eq!(log.lock().len(), 4);
    let a = action(vec![("a", task(Some("a"), Some(1), Some(CALL_CORE_FUNCTION), "first", "empty"))]);
    assert!(execute(&l, &a).await);
}

#[tokio::test]
async fn no_tasks_is_true() {
    let (l, log) = scripted_listener();
    assert!(execute(&l, &JMap::new()).await);
    assert!(execute(&l, &action(vec![])).await);
    assert!(log.lock().is_empty());
}

// --- the run log -------------------------------------------------------------------------------

#[derive(Default)]
struct Runs {
    calls: Mutex<Vec<String>>,
    finished: Mutex<Vec<(Option<u64>, bool, Vec<TaskOutcome>, Option<String>)>>,
    start_id: Mutex<Option<u64>>,
}

#[async_trait]
impl EventRunLog for Runs {
    async fn start(&self, qob: &EventMessage, task_count: usize) -> Option<u64> {
        self.calls.lock().push(format!("start {} {task_count}", qob.event_name.clone().unwrap_or_default()));
        *self.start_id.lock()
    }
    async fn finish(&self, id: Option<u64>, _started: i64, success: bool, tasks: Vec<TaskOutcome>, error: Option<String>) {
        self.calls.lock().push("finish".into());
        self.finished.lock().push((id, success, tasks, error));
    }
    async fn record_failed(&self, _qob: &EventMessage, error: &str) {
        self.calls.lock().push(format!("failed {error}"));
    }
    async fn record_no_action(&self, _qob: &EventMessage) {
        self.calls.lock().push("no action".into());
    }
}

struct Actions(Mutex<Result<Option<JMap>, String>>);

#[async_trait]
impl EventActions for Actions {
    async fn read(&self, name: &str, app: &str, client: &str, _draft: bool) -> Result<Option<JMap>, CoreError> {
        assert_eq!((name, app, client), ("leadCreated", "leadzumptwo", "FIN"));
        self.0.lock().clone().map_err(CoreError::unknown)
    }
}

struct Clients(Option<Value>);

#[async_trait]
impl ClientLookup for Clients {
    async fn client_by_code(&self, code: &str) -> Result<Option<Value>, CoreError> {
        assert_eq!(code, "FIN");
        Ok(self.0.clone())
    }
}

/// Answers per task key: `notify` fails, `syncAll` fails, `false` reports false.
struct Functions {
    seen: Mutex<Vec<(String, Option<Arc<EventActionRun>>, Vec<String>)>>,
}

#[async_trait]
impl TaskExecutor for Functions {
    async fn execute(&self, task: &ActionTask, _qob: &EventMessage) -> TaskResult {
        let key = task.key.clone().unwrap_or_default();
        let authorities = context::authentication().authorities().to_vec();
        self.seen.lock().push((key.clone(), context::event_action(), authorities));
        match key.as_str() {
            "notify" => Err(CoreError::unknown("Template welcome not found")).into(),
            "one" => TaskResult {
                result: Err(CoreError::unknown("Concurrent modification")),
                traces: vec![crate::step_trace::StepTrace {
                    function_name: "Leads.syncAll".into(),
                    statement_name: "s1".into(),
                    step_function: "System.Loop".into(),
                    arguments: Some("{\"a\": 1}".into()),
                }],
            },
            "false" => Ok(Some(false)).into(),
            _ => Ok(Some(true)).into(),
        }
    }
}

fn fn_task(key: &str, order: i64, namespace: Option<&str>) -> JValue {
    let mut m = JMap::new();
    m.insert("key".into(), JValue::Str(key.into()));
    m.insert("order".into(), JValue::Int(order));
    m.insert("type".into(), JValue::Str(CALL_CORE_FUNCTION.into()));
    let mut p = JMap::new();
    if let Some(ns) = namespace {
        p.insert("namespace".into(), JValue::Str(ns.into()));
    }
    p.insert("name".into(), JValue::Str(if namespace.is_some() { "syncAll".into() } else { key.into() }));
    m.insert("parameters".into(), JValue::Object(p));
    JValue::Object(m)
}

fn logged(read: Result<Option<JMap>, String>, client: Option<Value>) -> (EventsListener, Arc<Runs>, Arc<Functions>) {
    let runs = Arc::new(Runs::default());
    *runs.start_id.lock() = Some(42);
    let functions = Arc::new(Functions { seen: Mutex::new(Vec::new()) });
    let l = EventsListener::new(Arc::new(Actions(Mutex::new(read))), Arc::new(Clients(client)))
        .with_executor(CALL_CORE_FUNCTION, functions.clone())
        .with_run_log(runs.clone());
    (l, runs, functions)
}

fn fin() -> Option<Value> {
    Some(json!({"id": 1, "code": "FIN", "typeCode": "BUS", "levelType": "CLIENT"}))
}

#[tokio::test]
async fn a_run_is_opened_then_closed_with_each_tasks_outcome() {
    let a = action(vec![("notify", fn_task("notify", 2, None)), ("store", fn_task("store", 1, None))]);
    let (l, runs, functions) = logged(Ok(Some(a)), fin());
    assert_eq!(l.run(&message()).await.unwrap(), Some(false));
    assert_eq!(runs.calls.lock()[0], "start leadCreated 2");
    let finished = runs.finished.lock();
    let (id, ok, tasks, error) = &finished[0];
    assert_eq!((*id, *ok, error.clone()), (Some(42), false, None));
    assert_eq!((tasks[0].key.as_str(), tasks[0].success), ("store", true));
    assert_eq!((tasks[1].key.as_str(), tasks[1].success), ("notify", false));
    assert!(tasks[1].error.as_deref().unwrap().contains("Template welcome not found"));
    assert_eq!(tasks[1].task_type.as_deref(), Some(CALL_CORE_FUNCTION));
    assert!(!runs.calls.lock().iter().any(|c| c.starts_with("failed")));
    // The tasks ran as the client's anonymous event runner, inside the event action.
    let seen = functions.seen.lock();
    let run = seen[0].1.clone().unwrap();
    assert_eq!((run.app_code.as_str(), run.client_code.as_str(), run.event_name.as_str()), ("leadzumptwo", "FIN", "leadCreated"));
    assert_eq!(seen[0].2, [ANONYMOUS_AUTHORITY, EVENT_RUNNER_AUTHORITY]);
}

#[tokio::test]
async fn a_failed_task_keeps_its_step_traces_and_the_function_it_called() {
    let (l, runs, _) = logged(Ok(Some(action(vec![("one", fn_task("one", 1, Some("Leads")))]))), fin());
    assert_eq!(l.run(&message()).await.unwrap(), Some(false));
    let finished = runs.finished.lock();
    let one = &finished[0].2[0];
    assert_eq!(one.target.as_deref(), Some("Leads.syncAll"));
    assert_eq!(one.error.as_deref(), Some("Concurrent modification, at step s1 (System.Loop) of Leads.syncAll"));
    let detail = one.detail.as_deref().unwrap();
    assert!(detail.starts_with("KIRun steps, innermost first:\n    at step s1 (System.Loop) of Leads.syncAll\n        arguments {\"a\": 1}\n"), "{detail}");
    assert!(detail.ends_with("Concurrent modification\n"), "{detail}");
}

#[tokio::test]
async fn a_task_reporting_false_is_a_failure_with_a_reason() {
    let (l, runs, _) = logged(Ok(Some(action(vec![("false", fn_task("false", 1, None))]))), fin());
    assert_eq!(l.run(&message()).await.unwrap(), Some(false));
    let finished = runs.finished.lock();
    assert_eq!(finished[0].2[0].error.as_deref(), Some("The task reported that it did not succeed."));
}

#[tokio::test]
async fn an_event_with_no_action_goes_to_the_no_action_rule() {
    let (l, runs, _) = logged(Ok(None), fin());
    assert_eq!(l.run(&message()).await.unwrap(), None);
    assert_eq!(*runs.calls.lock(), ["no action"]);
}

#[tokio::test]
async fn an_unknown_client_is_recorded_as_failed() {
    let (l, runs, _) = logged(Ok(None), None);
    assert_eq!(l.run(&message()).await.unwrap(), None);
    assert_eq!(*runs.calls.lock(), ["failed The client 'FIN' could not be found, so the event could not run."]);
}

#[tokio::test]
async fn an_error_before_the_action_runs_is_recorded_and_still_thrown() {
    let (l, runs, _) = logged(Err("mongo unreachable".into()), fin());
    assert!(l.run(&message()).await.is_err());
    assert_eq!(*runs.calls.lock(), ["failed The event could not run: mongo unreachable"]);
}

#[tokio::test]
async fn a_run_log_that_cannot_be_written_does_not_stop_the_tasks() {
    let (l, runs, functions) = logged(Ok(Some(action(vec![("only", fn_task("only", 1, None))]))), fin());
    *runs.start_id.lock() = None;
    assert_eq!(l.run(&message()).await.unwrap(), Some(true));
    assert_eq!(functions.seen.lock().len(), 1);
    assert_eq!(runs.finished.lock()[0].0, None);
}

#[tokio::test]
async fn an_event_runs_as_the_authentication_it_was_raised_with() {
    let (l, _, functions) = logged(Ok(Some(action(vec![("only", fn_task("only", 1, None))]))), None);
    let mut qob = message();
    qob.authentication = Some(json!({
        "user": {"id": 110, "clientId": 7, "stringAuthorities": ["Authorities.Logged_IN"]},
        "isAuthenticated": true, "clientCode": "FIN", "urlClientCode": "FIN", "urlAppCode": "leadzumptwo"
    }));
    assert_eq!(l.run(&qob).await.unwrap(), Some(true));
    assert_eq!(functions.seen.lock()[0].2, ["Authorities.Logged_IN"]);
    // Without a run log the outcome is the same.
    let l = EventsListener::new(Arc::new(Actions(Mutex::new(Ok(Some(action(vec![])))))), Arc::new(Clients(fin())));
    assert_eq!(l.run(&message()).await.unwrap(), Some(true));
}

// --- the anonymous context ---------------------------------------------------------------------

#[test]
fn anonymous_context_carries_app_and_client_in_the_right_fields() {
    let client = json!({"id": 7, "code": "FIN", "typeCode": "BUS", "levelType": "CLIENT"});
    let a = anonymous_authentication(Some("leadzumptwo"), Some("FIN"), &client).unwrap();
    assert_eq!((a.url_app_code(), a.url_client_code(), a.client_code()), (Some("leadzumptwo"), Some("FIN"), Some("FIN")));
    assert_eq!(a.ca.logged_in_from_client_code.as_deref(), Some("FIN"));
    assert_eq!(a.ca.user.client_id, 7);
    assert_eq!(a.verified_app_code(), None);
    assert!(!a.is_authenticated());
}

#[test]
fn anonymous_context_carries_the_event_runner_authority() {
    let a = anonymous_authentication(Some("leadzumptwo"), Some("FIN"), &json!({"id": 1, "code": "FIN"})).unwrap();
    assert_eq!(a.authorities(), [ANONYMOUS_AUTHORITY, EVENT_RUNNER_AUTHORITY]);
    let has = |required: &str, held: &[String]| has_authority(Some(required), held).unwrap();
    assert!(has(EVENT_RUNNER_AUTHORITY, a.authorities()));
    assert!(has(ANONYMOUS_AUTHORITY, a.authorities()));
    assert!(!has("Authorities.Logged_IN", a.authorities()));
    // A browser's anonymous context holds only _Anonymous, so the gate refuses it.
    assert!(!has(EVENT_RUNNER_AUTHORITY, &[ANONYMOUS_AUTHORITY.to_string()]));
}

#[test]
fn url_client_code_follows_the_event_not_the_resolved_client() {
    let a = anonymous_authentication(Some("appA"), Some("FIN2"), &json!({"id": 1, "code": "FIN2"})).unwrap();
    assert_eq!((a.url_app_code(), a.url_client_code()), (Some("appA"), Some("FIN2")));
}

// --- UnhandledEventLog -------------------------------------------------------------------------

fn named(name: &str, app: &str, client: &str) -> EventMessage {
    EventMessage { event_name: Some(name.into()), app_code: Some(app.into()), client_code: Some(client.into()), ..Default::default() }
}

#[test]
fn a_handoff_event_is_warned_about_every_time_naming_app_client_and_event() {
    let log = UnhandledEventLog::default();
    for name in HANDOFF_EVENTS {
        for i in 0..3 {
            let w = log.warning(Some(&named(name, "leadzumptwo", "FIN")), 1000 + i).unwrap();
            assert!(w.contains(&format!("'{name}'")) && w.contains("app 'leadzumptwo'") && w.contains("client 'FIN'"), "{w}");
            assert!(w.contains(&format!("EventAction named {name}")), "{w}");
        }
    }
}

#[test]
fn any_other_event_is_warned_about_once_per_hour_per_event_app_and_client() {
    let log = UnhandledEventLog::default();
    let first = log.warning(Some(&named("USER_CREATED", "leadzumptwo", "FIN")), 0).unwrap();
    assert!(first.contains("'USER_CREATED'") && first.contains("app 'leadzumptwo'") && first.contains("client 'FIN'"));
    assert!(first.ends_with("Not repeated for this event, app and client for an hour."));
    assert_eq!(log.warning(Some(&named("USER_CREATED", "leadzumptwo", "FIN")), 1000), None);
    assert!(log.warning(Some(&named("USER_CREATED", "leadzumptwo", "FIN2")), 1000).is_some());
    assert!(log.warning(Some(&named("USER_CREATED", "leadzump", "FIN")), 1000).is_some());
    assert!(log.warning(Some(&named("CLIENT_CREATED", "leadzumptwo", "FIN")), 1000).is_some());
    assert!(log.warning(Some(&named("USER_CREATED", "leadzumptwo", "FIN")), REPEAT_AFTER_MILLIS).is_some());
}

#[test]
fn nothing_to_say_about_no_event() {
    assert_eq!(UnhandledEventLog::default().warning(None, 0), None);
}

#[test]
fn the_remembered_keys_are_bounded() {
    let log = UnhandledEventLog::default();
    for i in 0..MAX_REMEMBERED {
        log.warning(Some(&named(&format!("E{i}"), "a", "c")), 0);
    }
    // The next new key clears the memory, so a key seen before warns again.
    assert!(log.warning(Some(&named("NEW", "a", "c")), 0).is_some());
    assert!(log.warning(Some(&named("E0", "a", "c")), 1).is_some());
}

// --- the message off the queue ------------------------------------------------------------------

#[test]
fn events_are_read_as_jackson_writes_them() {
    let body = br#"{"eventName":"E","clientCode":"FIN","appCode":"app","draft":true,"data":{"a":1},"authentication":null,"xdebug":"d1"}"#;
    let e = parse_event(body).unwrap();
    assert_eq!((e.event_name.as_deref(), e.client_code.as_deref(), e.app_code.as_deref()), (Some("E"), Some("FIN"), Some("app")));
    assert!(e.draft && e.authentication.is_none());
    assert_eq!((e.data.unwrap()["a"].clone(), e.x_debug.as_deref()), (json!(1), Some("d1")));
    assert!(parse_event(b"[1]").is_err() && parse_event(b"nope").is_err());
    assert!(authentication_of(&json!(1)).is_err());
    // What the scheduler raised carries `_schedule`.
    let marked = EventMessage { data: Some(json!({"_schedule": {"kind": "cron"}}).as_object().unwrap().clone()), ..Default::default() };
    assert!(EventsListener::is_scheduled(&marked) && !EventsListener::is_scheduled(&message()));
}

#[test]
fn a_task_names_the_function_it_calls() {
    let t = |p: Value| ActionTask { parameters: p.as_object().cloned(), ..Default::default() };
    assert_eq!(target_of(Some(&t(json!({"namespace": "Leads", "name": "sync"})))).as_deref(), Some("Leads.sync"));
    assert_eq!(target_of(Some(&t(json!({"name": "sync"})))).as_deref(), Some("sync"));
    assert_eq!(target_of(Some(&t(json!({"namespace": " ", "name": 5})))).as_deref(), Some("5"));
    assert_eq!(target_of(Some(&t(json!({"name": " "})))), None);
    assert_eq!(target_of(None), None);
}

#[tokio::test]
async fn a_plain_event_passes_through_the_completion_and_numbers_read_as_text() {
    let client = mongodb::Client::with_uri_str("mongodb://127.0.0.1:1/?serverSelectionTimeoutMS=200").await.unwrap();
    let settings = crate::scheduler::EventSchedulerSettings::default();
    let store = Arc::new(crate::scheduler::ScheduleStore::new(client.database("x"), settings.clone()));
    let one_offs = Arc::new(crate::scheduler::ScheduledEventService::new(store.clone(), settings));
    let completion = Arc::new(RunCompletion::new(store, one_offs));
    let (l, runs, _) = logged(Ok(Some(action(vec![("only", fn_task("only", 1, None))]))), fin());
    let l = l.with_completion(completion);
    assert_eq!(l.run(&message()).await.unwrap(), Some(true));
    assert_eq!(runs.finished.lock().len(), 1);
    // Jackson reads a number or a boolean into a String field as its text.
    let e = parse_event(br#"{"eventName": 5, "appCode": true, "clientCode": "FIN"}"#).unwrap();
    assert_eq!((e.event_name.as_deref(), e.app_code.as_deref()), (Some("5"), Some("true")));
    // A stored order written as a double is read as an int.
    let mut t = JMap::new();
    t.insert("order".into(), JValue::Float(2.0));
    assert_eq!(ActionTask::from_j(&JValue::Object(t)).unwrap().order, Some(2));
    // Security answers the client lookup over HTTP: an unreachable one is the run's error.
    let s: Arc<dyn ClientLookup> =
        Arc::new(crate::clients::SecurityCalls::new(platform::upstream::Upstream::fixed(&["http://127.0.0.1:1"])).unwrap());
    assert!(s.client_by_code("FIN").await.is_err());
}
