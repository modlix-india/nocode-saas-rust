//! core-events: `EventsQueListener`. Consumes the events queues (`events1..3`), and for each
//! event runs the tasks of the EventAction named after it, under the context it was raised with:
//! its own authentication, or, for an event raised without one (a scheduler tick or one-off, a
//! message-service hand-off), the client's anonymous event-runner context.
//!
//! The tasks run one after another in their order; one that fails is recorded and counts as
//! false, and the rest still run. The outcome is the AND of the tasks, which closes a
//! scheduled run ([`RunCompletion`], `trackCompletion`). Every run goes to the event run log.
//!
//! Only here is [`context::with_event_action`] set, around one EventAction's tasks: the guard of
//! `CoreServices.Platform.*` reads it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use axum::http::StatusCode;
use connections::mq::EventMessage;
use overridable::{JMap, JValue, Store};
use parking_lot::Mutex;
use serde_json::{Map, Value};

use crate::auth::Authentication;
use crate::clients::SecurityCalls;
use crate::context::{self, EventActionRun, RequestContext};
use crate::docs::EventActionDoc;
use crate::error::{messages, CoreError};
use crate::event_scheduler::{schedule_marker, RunCompletion};
use crate::exec::{self, Arguments};
use crate::gson::to_gson;
use crate::state::AppState;
use crate::step_trace::StepTrace;

pub const ANONYMOUS_AUTHORITY: &str = "Authorities._Anonymous";
/// Held only by the anonymous context built here, so a server function meant to run only from
/// an event sets `executeAuth = "Authorities._Event_Runner"`.
pub const EVENT_RUNNER_AUTHORITY: &str = "Authorities._Event_Runner";
/// Held only by the context of core's internal webhook route (a provider calling an app's
/// webhook URI path through ui-shell), so a tenant storage that takes webhook data sets
/// `createAuth = "Authorities._Webhook"` and a function meant only for webhooks sets it as its
/// `executeAuth`.
pub const WEBHOOK_AUTHORITY: &str = "Authorities._Webhook";

/// Events another service hands to core so an app can own a channel; losing one loses a
/// customer's message or call.
pub const HANDOFF_EVENTS: [&str; 2] = ["WHATSAPP_INBOUND", "CALL_EVENT"];

pub const SEND_EMAIL: &str = "SEND_EMAIL";
pub const CALL_CORE_FUNCTION: &str = "CALL_CORE_FUNCTION";

pub fn now_millis() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

// ---------------------------------------------------------------- the message

/// Jackson reading an `EventQueObject` off the queue.
pub fn parse_event(body: &[u8]) -> Result<EventMessage, CoreError> {
    let v: Value = serde_json::from_slice(body).map_err(|e| CoreError::unknown(format!("Could not read the event: {e}")))?;
    let Value::Object(m) = v else { return Err(CoreError::unknown("Could not read the event: not an object")) };
    let text = |k: &str| match m.get(k) {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Number(n)) => Some(n.to_string()),
        Some(Value::Bool(b)) => Some(b.to_string()),
        _ => None,
    };
    Ok(EventMessage {
        event_name: text("eventName"),
        client_code: text("clientCode"),
        app_code: text("appCode"),
        x_debug: text("xdebug").or_else(|| text("xDebug")),
        draft: m.get("draft").and_then(Value::as_bool).unwrap_or(false),
        data: m.get("data").and_then(Value::as_object).cloned(),
        authentication: m.get("authentication").filter(|a| a.is_object()).cloned(),
    })
}

/// The event's own `ContextAuthentication`, as Jackson wrote it.
pub fn authentication_of(raw: &Value) -> Result<Authentication, CoreError> {
    let Value::Object(map) = raw else { return Err(CoreError::unknown("The event's authentication is not an object")) };
    let mut ca: platform::security::ContextAuthentication =
        serde_json::from_value(raw.clone()).map_err(|e| CoreError::unknown(format!("Could not read the event's authentication: {e}")))?;
    ca.url_client_code = map.get("urlClientCode").and_then(Value::as_str).map(str::to_string);
    ca.url_app_code = map.get("urlAppCode").and_then(Value::as_str).map(str::to_string);
    Ok(Authentication { ca, raw: map.clone() })
}

/// `makeAnonymousContextAuth(appCode, clientCode, client)`: the user `_Anonymous` of the
/// client, with the anonymous and event-runner authorities, the URL codes from the event.
pub fn anonymous_authentication(app_code: Option<&str>, client_code: Option<&str>, client: &Value) -> Result<Authentication, CoreError> {
    anonymous_with(app_code, client_code, client, &[ANONYMOUS_AUTHORITY, EVENT_RUNNER_AUTHORITY])
}

/// The same anonymous user of the client for a webhook: the anonymous and webhook authorities,
/// never the event runner's.
pub fn webhook_authentication(app_code: Option<&str>, client_code: Option<&str>, client: &Value) -> Result<Authentication, CoreError> {
    anonymous_with(app_code, client_code, client, &[ANONYMOUS_AUTHORITY, WEBHOOK_AUTHORITY])
}

fn anonymous_with(app_code: Option<&str>, client_code: Option<&str>, client: &Value, authorities: &[&str]) -> Result<Authentication, CoreError> {
    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.f").to_string();
    let id = client.get("id").cloned().unwrap_or(Value::Null);
    let code = client.get("code").cloned().unwrap_or(Value::Null);
    let raw = serde_json::json!({
        "user": {
            "id": 0, "createdBy": 0, "updatedBy": 0, "createdAt": now, "updatedAt": now,
            "clientId": id, "userName": "_Anonymous", "emailId": "nothing@nothing", "phoneNumber": "+910000000000",
            "firstName": "Anonymous", "lastName": "", "localeCode": "en", "password": "", "passwordHashed": false,
            "accountNonExpired": true, "accountNonLocked": true, "credentialsNonExpired": true, "noFailedAttempt": 0,
            "stringAuthorities": authorities,
        },
        "isAuthenticated": false,
        "authenticated": false,
        "loggedInFromClientId": id,
        "loggedInFromClientCode": code,
        "clientTypeCode": client.get("typeCode").cloned().unwrap_or(Value::Null),
        "clientLevelType": client.get("levelType").cloned().unwrap_or(Value::Null),
        "clientCode": code,
        "accessToken": "",
        "accessTokenExpiryAt": "+999999999-12-31T23:59:59.999999999",
        "urlClientCode": client_code,
        "urlAppCode": app_code,
        "verifiedAppCode": Value::Null,
    });
    authentication_of(&raw)
}

// ---------------------------------------------------------------- the action

/// One task of an EventAction, as stored (`EventActionTask`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ActionTask {
    pub key: Option<String>,
    pub order: Option<i32>,
    pub task_type: Option<String>,
    pub parameters: Option<Map<String, Value>>,
}

fn j_to_json(v: &JValue) -> Value {
    serde_json::to_value(v).unwrap_or(Value::Null)
}

impl ActionTask {
    pub fn from_j(v: &JValue) -> Option<Self> {
        let m = v.as_object()?;
        let s = |k: &str| m.get(k).and_then(JValue::as_str).map(str::to_string);
        let order = match m.get("order") {
            Some(JValue::Int(i)) => Some(*i as i32),
            Some(JValue::Float(f)) => Some(*f as i32),
            _ => None,
        };
        let parameters = match m.get("parameters").map(j_to_json) {
            Some(Value::Object(p)) => Some(p),
            _ => None,
        };
        Some(Self { key: s("key"), order, task_type: s("type"), parameters })
    }
}

/// The action's tasks sorted as the listener runs them: by order (null is 0), ties by the map
/// key (the stored task's own key can be null; its identity is the map key).
pub fn sorted_tasks(action: &JMap) -> Vec<(String, Option<ActionTask>)> {
    let Some(JValue::Object(tasks)) = action.get("tasks") else { return Vec::new() };
    let mut out: Vec<(String, Option<ActionTask>)> = tasks.iter().map(|(k, v)| (k.clone(), ActionTask::from_j(v))).collect();
    out.sort_by(|(ka, a), (kb, b)| {
        let o = |t: &Option<ActionTask>| t.as_ref().and_then(|t| t.order).unwrap_or(0);
        o(a).cmp(&o(b)).then_with(|| ka.cmp(kb))
    });
    out
}

/// `targetOf`: namespace.name of the function a task calls, when its parameters name one.
pub fn target_of(task: Option<&ActionTask>) -> Option<String> {
    let p = task?.parameters.as_ref()?;
    let text = |k: &str| p.get(k).filter(|v| !v.is_null()).map(value_text);
    let name = text("name").filter(|n| !n.trim().is_empty())?;
    match text("namespace").filter(|n| !n.trim().is_empty()) {
        Some(ns) => Some(format!("{ns}.{name}")),
        None => Some(name),
    }
}

/// `String.valueOf` / `toString()` of a parameter value.
fn value_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => crate::gson::element_to_string(other),
    }
}

/// `StringUtil.safeValueOf`: null stays null, anything else its text.
fn safe_value_of(v: Option<&Value>) -> Option<String> {
    v.filter(|v| !v.is_null()).map(value_text)
}

fn safe_is_blank(s: &Option<String>) -> bool {
    s.as_deref().is_none_or(|s| s.trim().is_empty())
}

// ---------------------------------------------------------------- the seams

/// `EventActionService.read(name, appCode, clientCode)` on the event's surface.
#[async_trait]
pub trait EventActions: Send + Sync {
    async fn read(&self, name: &str, app_code: &str, client_code: &str, draft: bool) -> Result<Option<JMap>, CoreError>;
}

pub struct StoreActions(pub Store);

#[async_trait]
impl EventActions for StoreActions {
    async fn read(&self, name: &str, app_code: &str, client_code: &str, draft: bool) -> Result<Option<JMap>, CoreError> {
        let r = self.0.read(&EventActionDoc, name, app_code, client_code, client_code, draft).await?;
        Ok(r.map(|r| r.entity.clone()))
    }
}

/// `IFeignSecurityService.getClientByCode`.
#[async_trait]
pub trait ClientLookup: Send + Sync {
    async fn client_by_code(&self, code: &str) -> Result<Option<Value>, CoreError>;
}

#[async_trait]
impl ClientLookup for SecurityCalls {
    async fn client_by_code(&self, code: &str) -> Result<Option<Value>, CoreError> {
        SecurityCalls::client_by_code(self, code).await
    }
}

/// What one task's executor answers: its result (`Ok(None)` is a task that finished without
/// one) and, when it ran KIRun, the step traces of its failure.
pub struct TaskResult {
    pub result: Result<Option<bool>, CoreError>,
    pub traces: Vec<StepTrace>,
}

impl From<Result<Option<bool>, CoreError>> for TaskResult {
    fn from(result: Result<Option<bool>, CoreError>) -> Self {
        Self { result, traces: Vec::new() }
    }
}

/// `IEventActionService`.
#[async_trait]
pub trait TaskExecutor: Send + Sync {
    async fn execute(&self, task: &ActionTask, qob: &EventMessage) -> TaskResult;
}

/// How one task went, for the run log (`EventRunTask`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TaskOutcome {
    pub key: String,
    pub task_type: Option<String>,
    pub target: Option<String>,
    pub order: Option<i32>,
    pub success: bool,
    pub started_at: i64,
    pub duration_ms: i64,
    pub error: Option<String>,
    pub detail: Option<String>,
}

/// The event run log as the listener writes it (`EventRunService`).
#[async_trait]
pub trait EventRunLog: Send + Sync {
    async fn start(&self, qob: &EventMessage, task_count: usize) -> Option<u64>;
    async fn finish(&self, id: Option<u64>, started_at_millis: i64, success: bool, tasks: Vec<TaskOutcome>, error: Option<String>);
    async fn record_failed(&self, qob: &EventMessage, error: &str);
    async fn record_no_action(&self, qob: &EventMessage);
}

/// `EventRunService.errorOf`: the message, then the innermost step's location.
pub fn error_of(e: &CoreError, traces: &[StepTrace]) -> String {
    crate::event_runs::error_of(e, traces)
}

/// `EventRunService.detailOf`: the step traces, then the error.
pub fn detail_of(e: &CoreError, traces: &[StepTrace]) -> String {
    crate::event_runs::detail_of(e, traces)
}

// ---------------------------------------------------------------- the executors

/// `EventCallFunctionService`: runs `parameters.namespace`.`parameters.name` for the event's
/// app and client, the event's data as the argument named `functionParameterName`.
pub struct CallCoreFunction {
    pub state: AppState,
}

#[async_trait]
impl TaskExecutor for CallCoreFunction {
    async fn execute(&self, task: &ActionTask, qob: &EventMessage) -> TaskResult {
        let data = qob.data.clone().unwrap_or_default();
        let params = task.parameters.clone().unwrap_or_default();
        let namespace = safe_value_of(params.get("namespace"));
        let name = safe_value_of(params.get("name"));
        let parameter = safe_value_of(params.get("functionParameterName"));
        if safe_is_blank(&namespace) || safe_is_blank(&name) {
            let job = to_gson(&Value::Object(data));
            return TaskResult::from(Err(CoreError::msg(
                StatusCode::INTERNAL_SERVER_ERROR,
                messages::UNABLE_TO_EXECUTE,
                &[name.as_deref().unwrap_or("null"), namespace.as_deref().unwrap_or("null"), &job],
            )));
        }
        let (namespace, name) = (namespace.unwrap_or_default(), name.unwrap_or_default());
        let mut args = kirun::Map::new();
        if !safe_is_blank(&parameter) {
            args.insert(parameter.unwrap_or_default(), Value::Object(data));
        }
        let app = qob.app_code.clone().unwrap_or_default();
        let client = qob.client_code.clone().unwrap_or_default();
        tracing::info!("Executing function: {name} in namespace: {namespace}");
        let run = exec::run(&self.state, Some(&namespace), &name, &app, &client, Arguments::Body(args));
        // The steps of the KIRun run the error came out of (KIRuntimeStepTrace).
        let (run, traces) = crate::step_trace::traced(run).await;
        let result = match run {
            Ok(Some(_)) => Ok(Some(true)),
            Ok(None) => Err(CoreError::msg_as(
                StatusCode::NOT_FOUND,
                messages::OBJECT_NOT_FOUND,
                "CORE.FUNCTION_NOT_FOUND",
                &["Function", &format!("{namespace}.{name}")],
            )),
            Err(e) => Err(e),
        };
        TaskResult { result, traces }
    }
}

/// `EventEmailService`: sends the task's template through its connection, the event's data as
/// the template data.
pub struct SendEmailTask {
    pub integrations: Arc<crate::integrations::Integrations>,
}

#[async_trait]
impl TaskExecutor for SendEmailTask {
    async fn execute(&self, task: &ActionTask, qob: &EventMessage) -> TaskResult {
        let data = qob.data.clone().unwrap_or_default();
        let params = task.parameters.clone().unwrap_or_default();
        let template = safe_value_of(params.get("template"));
        let connection = safe_value_of(params.get("connectionName"));
        let i = &self.integrations;
        let ctx = connections::email::EmailContext {
            connections: i.connection_docs.as_ref(),
            templates: i.templates.as_ref(),
            http: &i.connections.provider_http,
            sendgrid_url: &i.connections.config.sendgrid_url,
            block_private_targets: i.connections.config.block_private_targets,
        };
        let sent = connections::email::send_email(
            &ctx,
            &crate::integrations::caller(),
            qob.app_code.as_deref(),
            qob.client_code.as_deref(),
            &[],
            template.as_deref().unwrap_or("null"),
            connection.as_deref(),
            &data,
        )
        .await
        .map_err(crate::integrations::core_error);
        sent.into()
    }
}

// ---------------------------------------------------------------- the listener

/// `UnhandledEventLog`: an event with no EventAction is still dropped, but not silently: a
/// hand-off every time, anything else once an hour per event, app and client.
#[derive(Default)]
pub struct UnhandledEventLog {
    last_warned: Mutex<HashMap<String, i64>>,
}

pub const REPEAT_AFTER_MILLIS: i64 = 60 * 60 * 1000;
pub const MAX_REMEMBERED: usize = 10_000;

impl UnhandledEventLog {
    pub fn warning(&self, event: Option<&EventMessage>, now: i64) -> Option<String> {
        let event = event?;
        let null = |s: &Option<String>| s.clone().unwrap_or_else(|| "null".into());
        let name = null(&event.event_name);
        let handoff = event.event_name.as_deref().is_some_and(|n| HANDOFF_EVENTS.contains(&n));
        if !handoff {
            let key = format!("{name}|{}|{}", null(&event.app_code), null(&event.client_code));
            let mut seen = self.last_warned.lock();
            if seen.get(&key).is_some_and(|last| now - last < REPEAT_AFTER_MILLIS) {
                return None;
            }
            if seen.len() >= MAX_REMEMBERED {
                seen.clear();
            }
            seen.insert(key, now);
        }
        let mut sb = format!(
            "No EventAction '{name}' for app '{}' client '{}': the event is dropped.",
            null(&event.app_code),
            null(&event.client_code)
        );
        if handoff {
            sb.push_str(&format!(
                " The message service handed this to core because the number or call is owned by core; define an EventAction named {name} in app '{}' (CALL_CORE_FUNCTION to a function that stores it), or every such event is lost.",
                null(&event.app_code)
            ));
        } else {
            sb.push_str(" Not repeated for this event, app and client for an hour.");
        }
        Some(sb)
    }
}

pub struct EventsListener {
    actions: Arc<dyn EventActions>,
    clients: Arc<dyn ClientLookup>,
    executors: HashMap<&'static str, Arc<dyn TaskExecutor>>,
    completion: Option<Arc<RunCompletion>>,
    runs: Option<Arc<dyn EventRunLog>>,
    unhandled: UnhandledEventLog,
}

impl EventsListener {
    pub fn new(actions: Arc<dyn EventActions>, clients: Arc<dyn ClientLookup>) -> Self {
        Self { actions, clients, executors: HashMap::new(), completion: None, runs: None, unhandled: UnhandledEventLog::default() }
    }

    pub fn with_executor(mut self, task_type: &'static str, executor: Arc<dyn TaskExecutor>) -> Self {
        self.executors.insert(task_type, executor);
        self
    }

    pub fn with_completion(mut self, completion: Arc<RunCompletion>) -> Self {
        self.completion = Some(completion);
        self
    }

    pub fn with_run_log(mut self, runs: Arc<dyn EventRunLog>) -> Self {
        self.runs = Some(runs);
        self
    }

    /// `run(qob)`: the event's tasks under the context it was raised with; their outcome.
    /// `Ok(None)` is Java's empty answer (no action, or the client is unknown).
    pub async fn run(&self, qob: &EventMessage) -> Result<Option<bool>, CoreError> {
        // Whether this run has put its row in the run log; anything that stops it before that
        // point is recorded at the end instead.
        let logged = AtomicBool::new(false);
        let outcome = self.run_in_context(qob, &logged).await;
        let Some(runs) = &self.runs else { return outcome };
        match outcome {
            Ok(None) if !logged.load(Ordering::SeqCst) => {
                let client = qob.client_code.as_deref().unwrap_or("null");
                runs.record_failed(qob, &format!("The client '{client}' could not be found, so the event could not run.")).await;
                Ok(None)
            }
            Err(e) if !logged.load(Ordering::SeqCst) => {
                runs.record_failed(qob, &format!("The event could not run: {}", error_of(&e, &[]))).await;
                Err(e)
            }
            other => other,
        }
    }

    async fn run_in_context(&self, qob: &EventMessage, logged: &AtomicBool) -> Result<Option<bool>, CoreError> {
        let auth = match &qob.authentication {
            Some(raw) => authentication_of(raw)?,
            None => {
                let Some(client) = self.clients.client_by_code(qob.client_code.as_deref().unwrap_or("")).await? else {
                    return Ok(None);
                };
                anonymous_authentication(qob.app_code.as_deref(), qob.client_code.as_deref(), &client)?
            }
        };
        let ctx = Arc::new(RequestContext {
            auth: Arc::new(auth),
            app_code: qob.app_code.clone(),
            client_code: qob.client_code.clone(),
            draft: qob.draft,
            debug: qob.x_debug.clone(),
            ..Default::default()
        });
        let run = EventActionRun {
            app_code: qob.app_code.clone().unwrap_or_default(),
            client_code: qob.client_code.clone().unwrap_or_default(),
            event_name: qob.event_name.clone().unwrap_or_default(),
        };
        let received = self.received(qob, logged);
        let tracked = async {
            match &self.completion {
                Some(c) => c.track(qob, received).await,
                None => received.await,
            }
        };
        context::with_request(ctx, context::with_event_action(run, tracked)).await
    }

    async fn received(&self, qob: &EventMessage, logged: &AtomicBool) -> Result<Option<bool>, CoreError> {
        let action = self
            .actions
            .read(
                qob.event_name.as_deref().unwrap_or(""),
                qob.app_code.as_deref().unwrap_or(""),
                qob.client_code.as_deref().unwrap_or(""),
                qob.draft,
            )
            .await?;
        let Some(action) = action else {
            logged.store(true, Ordering::SeqCst);
            if let Some(w) = self.unhandled.warning(Some(qob), now_millis()) {
                tracing::warn!("{w}");
            }
            if let Some(runs) = &self.runs {
                runs.record_no_action(qob).await;
            }
            return Ok(None);
        };
        self.run_logged(&action, qob, logged).await.map(Some)
    }

    /// The action's tasks with a row in the run log: RUNNING before the first task, then
    /// SUCCESS or FAILED with each task's own outcome.
    async fn run_logged(&self, action: &JMap, qob: &EventMessage, logged: &AtomicBool) -> Result<bool, CoreError> {
        logged.store(true, Ordering::SeqCst);
        let tasks = sorted_tasks(action);
        let Some(runs) = &self.runs else { return Ok(self.execute_tasks(&tasks, qob, &mut Vec::new()).await) };
        let started = now_millis();
        let run_id = runs.start(qob, tasks.len()).await;
        let mut outcomes = Vec::new();
        let ok = self.execute_tasks(&tasks, qob, &mut outcomes).await;
        runs.finish(run_id, started, ok, outcomes, None).await;
        Ok(ok)
    }

    /// The tasks one after another in their order; the AND of their outcomes (no tasks is
    /// true).
    pub async fn execute_tasks(&self, tasks: &[(String, Option<ActionTask>)], qob: &EventMessage, outcomes: &mut Vec<TaskOutcome>) -> bool {
        let mut all = true;
        for (key, task) in tasks {
            all &= self.execute_task(key, task.as_ref(), qob, outcomes).await;
        }
        all
    }

    async fn execute_task(&self, key: &str, task: Option<&ActionTask>, qob: &EventMessage, outcomes: &mut Vec<TaskOutcome>) -> bool {
        let started = now_millis();
        let task_type = task.and_then(|t| t.task_type.clone());
        let mut outcome = TaskOutcome {
            key: key.to_string(),
            task_type: task_type.clone(),
            target: target_of(task),
            order: task.and_then(|t| t.order),
            started_at: started,
            ..Default::default()
        };
        let executor = task_type.as_deref().and_then(|t| self.executors.get(t));
        let result = match (task, executor) {
            (Some(task), Some(ex)) => ex.execute(task, qob).await,
            _ => TaskResult::from(Err(CoreError::unknown(format!(
                "Invalid task type : {}",
                task_type.as_deref().unwrap_or("null")
            )))),
        };
        let ok = match result.result {
            Ok(r) => r.unwrap_or(true),
            Err(e) => {
                tracing::error!(
                    "Error while executing task {key} of event {} for app {} and client {} : {e}",
                    qob.event_name.as_deref().unwrap_or("null"),
                    qob.app_code.as_deref().unwrap_or("null"),
                    qob.client_code.as_deref().unwrap_or("null")
                );
                outcome.error = Some(error_of(&e, &result.traces));
                outcome.detail = Some(detail_of(&e, &result.traces));
                false
            }
        };
        outcome.success = ok;
        outcome.duration_ms = now_millis() - started;
        if !ok && outcome.error.is_none() {
            outcome.error = Some("The task reported that it did not succeed.".into());
        }
        outcomes.push(outcome);
        ok
    }

    /// Whether the scheduler raised this event (it carries `_schedule`).
    pub fn is_scheduled(qob: &EventMessage) -> bool {
        schedule_marker(qob).is_some()
    }
}

#[cfg(test)]
#[path = "events_tests.rs"]
mod tests;

// ---------------------------------------------------------------- the run log

impl From<TaskOutcome> for crate::event_runs::EventRunTask {
    fn from(t: TaskOutcome) -> Self {
        use crate::event_runs::TaskStatus;
        Self {
            key: Some(t.key),
            task_type: t.task_type,
            target: t.target,
            order: t.order,
            status: Some(if t.success { TaskStatus::Success } else { TaskStatus::Failed }),
            started_at: Some(t.started_at),
            duration_ms: Some(t.duration_ms),
            error: t.error,
            detail: t.detail,
            duration_text: None,
        }
    }
}

#[async_trait]
impl EventRunLog for crate::event_runs::EventRunService {
    async fn start(&self, qob: &EventMessage, task_count: usize) -> Option<u64> {
        crate::event_runs::EventRunService::start(self, qob, task_count).await
    }
    async fn finish(&self, id: Option<u64>, started_at_millis: i64, success: bool, tasks: Vec<TaskOutcome>, error: Option<String>) {
        let tasks = tasks.into_iter().map(Into::into).collect();
        crate::event_runs::EventRunService::finish(self, id, started_at_millis, success, tasks, error).await
    }
    async fn record_failed(&self, qob: &EventMessage, error: &str) {
        crate::event_runs::EventRunService::record(self, qob, crate::event_runs::RunStatus::Failed, Some(error)).await
    }
    async fn record_no_action(&self, qob: &EventMessage) {
        crate::event_runs::EventRunService::record_no_action(self, qob).await
    }
}

#[async_trait]
impl crate::event_scheduler::RunLog for crate::event_runs::EventRunService {
    async fn record(&self, event: &EventMessage, status: crate::event_scheduler::Unrun, error: &str) {
        use crate::event_runs::RunStatus;
        let status = match status {
            crate::event_scheduler::Unrun::Skipped => RunStatus::Skipped,
            crate::event_scheduler::Unrun::Failed => RunStatus::Failed,
        };
        crate::event_runs::EventRunService::record(self, event, status, Some(error)).await
    }
}
