//! `CoreServices.Event.ScheduleEvent`, `CancelScheduledEvent` and `SetScheduleEnabled`
//! (`functions/events/*`), `ScheduleTenant`: under which client a one-off is kept, and the
//! Rust only `GetScheduleState`.
//!
//! All of them act only inside a server function (outside one they answer false), take the app
//! from the caller's context, and keep the draft surface's one-offs apart from live's.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{NaiveDate, NaiveDateTime, NaiveTime};
use kirun::function::Function;
use kirun::json::schema::Schema;
use kirun::model::{Event, FunctionOutput, FunctionSignature, Parameter};
use kirun::{Map, Value};

use super::support::{forbidden, is_self_or_direct_managing_client_code, output_map, required_argument, Java, JavaFunction};
use super::{arg_string, Core, CoreFunction};
use crate::auth::Authentication;
use crate::clients::SecurityCalls;
use crate::context;
use crate::error::CoreError;
use crate::repos::core_functions::Deps;
use crate::scheduler::{
    java_blank, java_trim, json_util_map, now_millis, EventDefinitionService, OneOffs, ScheduleRequest, ScheduleState, ScheduleStore,
    ScheduleSwitch, ScheduledEventService,
};
use crate::storage::defs::Catalog;

const EVENT_NAME: &str = "eventName";
const DATA: &str = "data";
const RUN_AT: &str = "runAt";
const KEY: &str = "key";
const CLIENT_CODE: &str = "clientCode";
const ENABLED: &str = "enabled";

/// `ScheduleTenant.clientCode`: blank (or the caller's own) is the caller's client; another
/// must be the caller's client's DIRECT managing client, not SYSTEM, with write access to the
/// request's app (the partner case). A client the caller manages, a grandparent and SYSTEM are
/// refused.
pub async fn tenant_client_code(security: &SecurityCalls, auth: &Authentication, client_code: &str) -> Result<String, CoreError> {
    let own = auth.client_code();
    if java_blank(client_code) || own == Some(client_code) {
        return match own {
            Some(o) if !java_blank(o) => Ok(o.to_string()),
            _ => Err(required_argument("clientCode")),
        };
    }
    if is_self_or_direct_managing_client_code(security, own, Some(client_code), auth.url_app_code()).await? {
        Ok(client_code.to_string())
    } else {
        Err(forbidden("CORE.SCHEDULE_CLIENT_FORBIDDEN", format!("Not allowed to schedule events for client {client_code}")).param("client", client_code))
    }
}

/// `element == null || element.isJsonNull() ? "" : element.getAsString()`.
fn string_or_empty(args: &Map<Value>, name: &str) -> Result<String, CoreError> {
    match args.get(name) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(_) => arg_string(args, name),
    }
}

/// `ca.getUser().getId().toString()`, `None` without a user or an id.
fn scheduled_by(auth: &Authentication) -> Option<String> {
    match auth.raw.get("user").and_then(|u| u.get("id")) {
        Some(Value::Number(n)) => Some(n.to_string()),
        Some(Value::String(s)) => Some(s.clone()),
        _ => None,
    }
}

/// The caller, when the request has one (`SecurityContextUtil.getUsersContextAuthentication`).
fn caller() -> Option<Arc<Authentication>> {
    context::request().map(|r| r.auth.clone())
}

// ------------------------------------------------------------------ runAt

/// A position in the text being read.
struct Scan<'a> {
    b: &'a [u8],
    i: usize,
}

impl Scan<'_> {
    fn eat(&mut self, c: u8) -> bool {
        let hit = self.b.get(self.i).is_some_and(|x| x.eq_ignore_ascii_case(&c));
        self.i += usize::from(hit);
        hit
    }

    /// Up to `max` digits.
    fn run(&mut self, max: usize) -> &str {
        let start = self.i;
        while self.i - start < max && self.b.get(self.i).is_some_and(u8::is_ascii_digit) {
            self.i += 1;
        }
        std::str::from_utf8(&self.b[start..self.i]).unwrap_or_default()
    }

    /// Exactly `n` digits.
    fn digits(&mut self, n: usize) -> Option<u32> {
        let d = self.run(n);
        (d.len() == n).then(|| d.parse().ok()).flatten()
    }

    fn done(&self) -> bool {
        self.i == self.b.len()
    }

    /// `ISO_LOCAL_DATE_TIME`: `[+-]yyyy-MM-ddTHH:mm[:ss[.fffffffff]]`, case-insensitive, strict
    /// (a year past four digits needs its sign, a date or time must exist).
    fn local_date_time(&mut self) -> Option<NaiveDateTime> {
        let sign = if self.eat(b'+') {
            1
        } else if self.eat(b'-') {
            -1
        } else {
            0
        };
        let y = self.run(10);
        if y.len() < 4 || (sign == 0 && y.len() > 4) || (sign == 1 && y.len() == 4) {
            return None;
        }
        let year = i32::try_from(y.parse::<i64>().ok()? * if sign < 0 { -1 } else { 1 }).ok()?;
        self.eat(b'-').then_some(())?;
        let month = self.digits(2)?;
        self.eat(b'-').then_some(())?;
        let day = self.digits(2)?;
        self.eat(b'T').then_some(())?;
        let hour = self.digits(2)?;
        self.eat(b':').then_some(())?;
        let minute = self.digits(2)?;
        let (mut second, mut nano) = (0, 0);
        if self.eat(b':') {
            second = self.digits(2)?;
            if self.eat(b'.') {
                let f = self.run(9);
                nano = format!("{f:0<9}").parse().ok()?;
            }
        }
        Some(NaiveDateTime::new(NaiveDate::from_ymd_opt(year, month, day)?, NaiveTime::from_hms_nano_opt(hour, minute, second, nano)?))
    }

    /// `appendOffsetId()` as the JDK parses it: `Z`, or `+HH[:MM[:ss]]` within ±18:00.
    fn offset_seconds(&mut self) -> Option<i64> {
        if self.eat(b'Z') {
            return Some(0);
        }
        let negative = if self.eat(b'+') {
            false
        } else if self.eat(b'-') {
            true
        } else {
            return None;
        };
        let h = self.digits(2)?;
        let (mut m, mut s) = (0, 0);
        if self.eat(b':') {
            m = self.digits(2)?;
            if self.eat(b':') {
                s = self.digits(2)?;
            }
        }
        let total = i64::from(h * 3600 + m * 60 + s);
        if h > 23 || m > 59 || s > 59 || total > 18 * 3600 {
            return None;
        }
        Some(if negative { -total } else { total })
    }
}

/// `OffsetDateTime.parse(text)`, else `LocalDateTime.parse(text)` read in UTC: epoch millis.
fn iso_millis(text: &str) -> Option<i64> {
    let mut s = Scan { b: text.as_bytes(), i: 0 };
    let local = s.local_date_time()?;
    let offset = if s.done() { 0 } else { s.offset_seconds()? };
    s.done().then(|| local.and_utc().timestamp_millis() - offset * 1000)
}

/// `ScheduleEventFunction.parseRunAt`: epoch millis of an ISO timestamp (with an offset, or
/// UTC without one) or of epoch milliseconds; null or blank is now.
pub fn parse_run_at(element: Option<&Value>, now: i64) -> Result<i64, CoreError> {
    let text = match element {
        None | Some(Value::Null) => return Ok(now),
        Some(Value::Object(_) | Value::Array(_)) => {
            return Err(CoreError::unknown("runAt must be an ISO timestamp or epoch milliseconds"));
        }
        // `getAsLong()`: a long as is, past one its low 64 bits, a fraction cut off.
        Some(Value::Number(n)) => {
            return Ok(n.as_i64().or(n.as_u64().map(|u| u as i64)).unwrap_or_else(|| n.as_f64().unwrap_or(0.0) as i64));
        }
        Some(Value::Bool(b)) => b.to_string(),
        Some(Value::String(s)) => java_trim(s).to_string(),
    };
    if text.is_empty() {
        return Ok(now);
    }
    iso_millis(&text).ok_or_else(|| CoreError::unknown(format!("runAt is not an ISO timestamp: {text}")))
}

// ------------------------------------------------------------------ the functions

/// `ScheduleEventFunction`: raise `eventName` at `runAt` instead of now, under `key`
/// (scheduling a key again replaces it unless it is running; a blank key gets a fresh one).
pub struct ScheduleEvent {
    one_offs: Arc<dyn OneOffs>,
    definitions: Arc<dyn Catalog>,
    security: Arc<SecurityCalls>,
}

impl ScheduleEvent {
    pub fn new(one_offs: Arc<dyn OneOffs>, definitions: Arc<dyn Catalog>, security: Arc<SecurityCalls>) -> Self {
        Self { one_offs, definitions, security }
    }
}

fn scheduled_output(scheduled: bool, key: &str) -> FunctionOutput {
    output_map([("scheduled", Value::Bool(scheduled)), (KEY, Value::String(key.to_string()))])
}

#[async_trait]
impl JavaFunction for ScheduleEvent {
    fn full_name(&self) -> &'static str {
        "CoreServices.Event.ScheduleEvent"
    }

    async fn run(&self, args: &Map<Value>) -> Result<FunctionOutput, CoreError> {
        let event_name = arg_string(args, EVENT_NAME)?;
        let data = match args.get(DATA) {
            Some(Value::Object(o)) => json_util_map(o),
            _ => Default::default(),
        };
        let key = string_or_empty(args, KEY)?;
        let client_code = java_trim(&string_or_empty(args, CLIENT_CODE)?).to_string();
        let run_at = parse_run_at(args.get(RUN_AT), now_millis())?;

        let (true, Some(ca)) = (context::in_kirun(), caller()) else { return Ok(scheduled_output(false, &key)) };
        let client = tenant_client_code(&self.security, &ca, &client_code).await?;
        let app = ca.url_app_code().unwrap_or_default();
        // An event the app does not define is refused, as CreateEvent refuses it.
        if self.definitions.event_definition(&event_name, app, &client).await?.is_none() {
            return Ok(scheduled_output(false, &key));
        }
        let request = ScheduleRequest {
            app_code: app.to_string(),
            client_code: client,
            draft: context::is_draft(),
            event_name,
            data,
            run_at: Some(run_at),
            key,
            scheduled_by: scheduled_by(&ca),
        };
        let scheduled = self.one_offs.schedule(request).await?;
        Ok(scheduled_output(scheduled.event.is_some(), &scheduled.key))
    }
}

/// `CancelScheduledEventFunction`: cancels the pending one-off under `key`; `cancelled` is
/// false when nothing was pending under it.
pub struct CancelScheduledEvent {
    one_offs: Arc<dyn OneOffs>,
    security: Arc<SecurityCalls>,
}

impl CancelScheduledEvent {
    pub fn new(one_offs: Arc<dyn OneOffs>, security: Arc<SecurityCalls>) -> Self {
        Self { one_offs, security }
    }
}

#[async_trait]
impl JavaFunction for CancelScheduledEvent {
    fn full_name(&self) -> &'static str {
        "CoreServices.Event.CancelScheduledEvent"
    }

    async fn run(&self, args: &Map<Value>) -> Result<FunctionOutput, CoreError> {
        let key = arg_string(args, KEY)?;
        let client_code = java_trim(&string_or_empty(args, CLIENT_CODE)?).to_string();
        let cancelled = |c: bool| output_map([("cancelled", Value::Bool(c))]);

        let (true, Some(ca)) = (context::in_kirun(), caller()) else { return Ok(cancelled(false)) };
        let client = tenant_client_code(&self.security, &ca, &client_code).await?;
        let app = ca.url_app_code().unwrap_or_default();
        Ok(cancelled(self.one_offs.cancel(app, &client, context::is_draft(), &key).await?))
    }
}

/// `SetScheduleEnabledFunction`: turns the caller's own client's runs of a scheduled event on
/// or off, writing only `schedule.enabled` into the client's own copy. App and client come
/// from the caller's context; nothing happens on the draft surface.
pub struct SetScheduleEnabled {
    definitions: Arc<dyn ScheduleSwitch>,
}

impl SetScheduleEnabled {
    pub fn new(definitions: Arc<dyn ScheduleSwitch>) -> Self {
        Self { definitions }
    }
}

#[async_trait]
impl JavaFunction for SetScheduleEnabled {
    fn full_name(&self) -> &'static str {
        "CoreServices.Event.SetScheduleEnabled"
    }

    async fn run(&self, args: &Map<Value>) -> Result<FunctionOutput, CoreError> {
        let event_name = java_trim(&string_or_empty(args, EVENT_NAME)?).to_string();
        // `getAsBoolean()`: a boolean, or text read by `Boolean.parseBoolean`.
        let enabled = match args.get(ENABLED) {
            None | Some(Value::Null) => true,
            Some(Value::Bool(b)) => *b,
            Some(_) => arg_string(args, ENABLED)?.eq_ignore_ascii_case("true"),
        };
        let changed = |c: bool| output_map([("changed", Value::Bool(c))]);
        if event_name.is_empty() || !context::in_kirun() || context::is_draft() {
            return Ok(changed(false));
        }
        let Some(ca) = caller() else { return Ok(changed(false)) };
        let app = ca.url_app_code().unwrap_or_default();
        let client = ca.client_code().unwrap_or_default();
        let result = self.definitions.set_own_schedule_enabled(&event_name, app, client, enabled).await?;
        Ok(changed(result == Some(true)))
    }
}

/// Rust only. `GetScheduleState(eventName, appCode, clientCode)`: the schedule the caller's
/// own client runs on, read from the definition it sees (its own copy merged over the base,
/// else the base) on the live surface, which is what the scheduler runs, also when called on
/// the draft surface. Answers `{exists, enabled, cron, clientCode, ownCopy}`: `exists` is false
/// for an event the app does not have or one without a schedule, `enabled` is false then.
///
/// The access rules are `SetScheduleEnabled`'s: only inside a server function (outside one, or
/// without a caller or a name, `exists` is false), for the app it runs in and the caller's own
/// client. `appCode` and `clientCode` may be left empty or name those; any other is refused.
pub struct GetScheduleState {
    signature: FunctionSignature,
    definitions: Arc<dyn ScheduleSwitch>,
}

impl GetScheduleState {
    pub const FULL_NAME: &'static str = "CoreServices.Event.GetScheduleState";

    pub fn new(definitions: Arc<dyn ScheduleSwitch>) -> Self {
        let text = |name: &str| Parameter::of_entry(name, Schema::of_string(name).set_default_value(Value::String(String::new())), false);
        let outputs: Map<Schema> = [
            ("exists", Schema::of_boolean("exists")),
            ("enabled", Schema::of_boolean("enabled")),
            ("cron", Schema::of_any("cron")),
            ("clientCode", Schema::of_any("clientCode")),
            ("ownCopy", Schema::of_boolean("ownCopy")),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        let signature = FunctionSignature::new("GetScheduleState")
            .set_namespace("CoreServices.Event")
            .set_parameters([Parameter::of_entry(EVENT_NAME, Schema::of_string(EVENT_NAME), false), text("appCode"), text(CLIENT_CODE)].into_iter().collect())
            .set_events(Map::from([Event::output_event_map_entry(outputs)]));
        Self { signature, definitions }
    }

    fn output(state: ScheduleState) -> FunctionOutput {
        let text = |s: Option<String>| s.map(Value::String).unwrap_or(Value::Null);
        output_map([
            ("exists", Value::Bool(state.exists)),
            ("enabled", Value::Bool(state.enabled)),
            ("cron", text(state.cron)),
            ("clientCode", text(Some(state.client_code).filter(|c| !c.is_empty()))),
            ("ownCopy", Value::Bool(state.own_copy)),
        ])
    }
}

#[async_trait]
impl CoreFunction for GetScheduleState {
    fn signature(&self) -> &FunctionSignature {
        &self.signature
    }

    async fn internal_execute(&self, args: &Map<Value>) -> Result<FunctionOutput, CoreError> {
        let event_name = java_trim(&string_or_empty(args, EVENT_NAME)?).to_string();
        let app_arg = java_trim(&string_or_empty(args, "appCode")?).to_string();
        let client_arg = java_trim(&string_or_empty(args, CLIENT_CODE)?).to_string();
        let (true, Some(ca)) = (context::in_kirun(), caller()) else { return Ok(Self::output(ScheduleState::default())) };
        let app = ca.url_app_code().unwrap_or_default().to_string();
        let client = ca.client_code().unwrap_or_default().to_string();
        if (!app_arg.is_empty() && app_arg != app) || (!client_arg.is_empty() && client_arg != client) {
            let (c, a) = (if client_arg.is_empty() { &client } else { &client_arg }, if app_arg.is_empty() { &app } else { &app_arg });
            return Err(forbidden("CORE.SCHEDULE_STATE_FORBIDDEN", format!("Not allowed to read the schedule state for client {c} in app {a}"))
                .param("client", c)
                .param("app", a));
        }
        if event_name.is_empty() || app.is_empty() || client.is_empty() {
            return Ok(Self::output(ScheduleState { client_code: client, ..Default::default() }));
        }
        Ok(Self::output(self.definitions.schedule_state(&event_name, &app, &client).await?))
    }
}

/// `makeScheduledEventFunctions`, in its order: one store and one service shared by
/// ScheduleEvent and CancelScheduledEvent, as Java's beans are. `GetScheduleState` (Rust only)
/// after them.
pub fn all(deps: &Deps) -> Vec<Arc<dyn Function>> {
    let store = Arc::new(ScheduleStore::new(deps.mongo.clone(), deps.scheduler.clone()));
    let one_offs: Arc<dyn OneOffs> = Arc::new(ScheduledEventService::new(store, deps.scheduler.clone()));
    let switch: Arc<dyn ScheduleSwitch> =
        Arc::new(EventDefinitionService::new(deps.defs.definitions().store().clone(), deps.cache.clone()));
    let definitions: Arc<dyn Catalog> = deps.defs.clone();
    vec![
        Java::function(ScheduleEvent::new(one_offs.clone(), definitions, deps.security.clone())),
        Java::function(CancelScheduledEvent::new(one_offs, deps.security.clone())),
        Java::function(SetScheduleEnabled::new(switch.clone())),
        Arc::new(Core(GetScheduleState::new(switch))),
    ]
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use axum::extract::RawQuery;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::Router;
    use kirun::repository::{KIRunFunctionRepository, KIRunSchemaRepository};
    use kirun::runtime::FunctionExecutionParameters;
    use mongodb::bson::{doc, Bson, Document};
    use overridable::backend::{FakeDirectory, MemBackend};
    use overridable::{JMap, Store};
    use parking_lot::Mutex;
    use platform::upstream::Upstream;
    use serde_json::json;

    use super::*;
    use crate::scheduler::{Scheduled, ScheduledEvent};
    use crate::testing::{auth, request, serve, MemoryCatalog};

    const APP: &str = "leadzumptwo";

    /// What a run answered: the output map, or the error Java would answer with.
    async fn run(f: &dyn Function, args: serde_json::Value, auth: Option<Authentication>, in_definition: bool, draft: bool)
        -> Result<Map<Value>, CoreError> {
        let exec = async {
            let mut fep = FunctionExecutionParameters::new(Arc::new(KIRunFunctionRepository::new()), Arc::new(KIRunSchemaRepository::new()))
                .set_arguments(args.as_object().cloned().unwrap_or_default().into_iter().collect());
            match f.execute(&mut fep).await {
                Ok(mut o) => Ok(o.next().unwrap().get_result().clone()),
                Err(e) => Err(context::error_for(&e)),
            }
        };
        let scoped = async {
            if in_definition {
                context::with_run(context::RunScope::default(), exec).await
            } else {
                exec.await
            }
        };
        match auth {
            Some(a) => context::with_request(request(a, draft, None), scoped).await,
            None => scoped.await,
        }
    }

    // ---------------------------------------------------------------- ScheduleEvent / Cancel

    /// Port of commons-core `ScheduleEventClientCodeTest`'s fakes: SYSTEM(1) above FIN(7) and
    /// OTHER(55), FIN above BP1(90); FIN has write access to the app, SYSTEM to every app.
    async fn security() -> Arc<SecurityCalls> {
        fn q(r: Option<String>) -> HashMap<String, String> {
            crate::exec::parse_query(r.as_deref()).into_iter().collect()
        }
        let router = Router::new()
            .route("/api/security/clients/internal/getClientByCode", get(|RawQuery(r): RawQuery| async move {
                match q(r)["clientCode"].as_str() {
                    "SYSTEM" => r#"{"id":1,"code":"SYSTEM","typeCode":"SYS"}"#.into_response(),
                    "FIN" => r#"{"id":7,"code":"FIN","typeCode":"BUS"}"#.into_response(),
                    "BP1" => r#"{"id":90,"code":"BP1","typeCode":"BUS"}"#.into_response(),
                    "OTHER" => r#"{"id":55,"code":"OTHER","typeCode":"BUS"}"#.into_response(),
                    _ => StatusCode::OK.into_response(),
                }
            }))
            .route("/api/security/clients/internal/clientHierarchy", get(|RawQuery(r): RawQuery| async move {
                match q(r)["clientId"].as_str() {
                    "7" => "[7,1]",
                    "90" => "[90,7,1]",
                    "55" => "[55,1]",
                    _ => "[1]",
                }
            }))
            .route("/api/security/applications/internal/hasWriteAccess", get(|RawQuery(r): RawQuery| async move {
                let p = q(r);
                (p["clientCode"] == "SYSTEM" || (p["appCode"] == APP && p["clientCode"] == "FIN")).to_string()
            }));
        Arc::new(SecurityCalls::new(Upstream::fixed(&[&serve(router).await])).unwrap())
    }

    /// Every scheduler call, as "schedule|cancel appCode clientCode key".
    #[derive(Default)]
    struct FakeOneOffs {
        calls: Mutex<Vec<String>>,
        requests: Mutex<Vec<ScheduleRequest>>,
        in_flight: Mutex<bool>,
    }

    #[async_trait]
    impl OneOffs for FakeOneOffs {
        async fn schedule(&self, r: ScheduleRequest) -> Result<Scheduled, CoreError> {
            self.calls.lock().push(format!("schedule {} {} {}", r.app_code, r.client_code, r.key));
            self.requests.lock().push(r.clone());
            let key = if r.key.is_empty() { "generated".to_string() } else { r.key.clone() };
            let event = (!*self.in_flight.lock())
                .then(|| ScheduledEvent { key: Some(key.clone()), client_code: Some(r.client_code), ..Default::default() });
            Ok(Scheduled { key, event })
        }

        async fn cancel(&self, app: &str, client: &str, draft: bool, key: &str) -> Result<bool, CoreError> {
            self.calls.lock().push(format!("cancel {app} {client} {key}"));
            Ok(!draft)
        }
    }

    struct Fixture {
        one_offs: Arc<FakeOneOffs>,
        catalog: Arc<MemoryCatalog>,
        schedule: Arc<dyn Function>,
        cancel: Arc<dyn Function>,
    }

    async fn fixture() -> Fixture {
        let one_offs = Arc::new(FakeOneOffs::default());
        let catalog = Arc::new(MemoryCatalog::default());
        catalog.events.lock().insert("taskReminder".into(), JMap::new());
        let security = security().await;
        let schedule = Java::function(ScheduleEvent::new(one_offs.clone(), catalog.clone(), security.clone()));
        let cancel = Java::function(CancelScheduledEvent::new(one_offs.clone(), security));
        Fixture { one_offs, catalog, schedule, cancel }
    }

    fn user_of(client_code: &str) -> Authentication {
        auth(
            json!({"user": {"id": 110, "clientId": 1}, "authenticated": true, "clientCode": client_code,
                   "loggedInFromClientCode": client_code}),
            Some(client_code),
            Some(APP),
        )
    }

    fn schedule_args(client_code: Option<&str>) -> serde_json::Value {
        let mut a = json!({"eventName": "taskReminder", "data": {}, "runAt": "2026-10-09T09:00:00Z", "key": "task-1"});
        if let Some(c) = client_code {
            a["clientCode"] = json!(c);
        }
        a
    }

    fn cancel_args(client_code: Option<&str>) -> serde_json::Value {
        let mut a = json!({"key": "task-1"});
        if let Some(c) = client_code {
            a["clientCode"] = json!(c);
        }
        a
    }

    impl Fixture {
        async fn schedule(&self, client: Option<&str>, caller: &str) -> Result<Map<Value>, CoreError> {
            run(self.schedule.as_ref(), schedule_args(client), Some(user_of(caller)), true, false).await
        }

        async fn cancel(&self, client: Option<&str>, caller: &str) -> Result<Map<Value>, CoreError> {
            run(self.cancel.as_ref(), cancel_args(client), Some(user_of(caller)), true, false).await
        }

        fn calls(&self) -> Vec<String> {
            self.one_offs.calls.lock().clone()
        }

        fn reads(&self) -> Vec<String> {
            self.catalog.lookups.lock().clone()
        }
    }

    fn forbidden(r: Result<Map<Value>, CoreError>) -> bool {
        r.is_err_and(|e| e.status() == StatusCode::FORBIDDEN)
    }

    #[tokio::test]
    async fn own_client_by_default() {
        let f = fixture().await;
        assert_eq!(f.schedule(None, "FIN").await.unwrap()["scheduled"], json!(true));
        assert_eq!(f.schedule(Some(""), "BP1").await.unwrap().len(), 2);
        assert_eq!(f.cancel(Some("FIN"), "FIN").await.unwrap()["cancelled"], json!(true));
        assert_eq!(f.calls(), [format!("schedule {APP} FIN task-1"), format!("schedule {APP} BP1 task-1"), format!("cancel {APP} FIN task-1")]);
        assert_eq!(f.reads(), [format!("{APP}/FIN/taskReminder"), format!("{APP}/BP1/taskReminder")]);
    }

    #[tokio::test]
    async fn partner_uses_direct_managing_client() {
        let f = fixture().await;
        assert_eq!(f.schedule(Some("FIN"), "BP1").await.unwrap()["key"], json!("task-1"));
        assert_eq!(f.cancel(Some("FIN"), "BP1").await.unwrap()["cancelled"], json!(true));
        assert_eq!(f.calls(), [format!("schedule {APP} FIN task-1"), format!("cancel {APP} FIN task-1")]);
        assert_eq!(f.reads(), [format!("{APP}/FIN/taskReminder")], "the event definition is read as the managing client sees it");
    }

    #[tokio::test]
    async fn managed_client_refused() {
        let f = fixture().await;
        assert!(forbidden(f.schedule(Some("BP1"), "FIN").await));
        assert!(forbidden(f.cancel(Some("BP1"), "FIN").await));
        assert!(f.calls().is_empty());
        assert!(f.reads().is_empty());
    }

    #[tokio::test]
    async fn system_refused() {
        let f = fixture().await;
        for caller in ["FIN", "BP1", "OTHER"] {
            assert!(forbidden(f.schedule(Some("SYSTEM"), caller).await), "{caller}");
            assert!(forbidden(f.cancel(Some("SYSTEM"), caller).await), "{caller}");
        }
        assert!(forbidden(f.schedule(Some("FIN"), "SYSTEM").await));
        assert!(forbidden(f.cancel(Some("FIN"), "SYSTEM").await));
        assert!(f.calls().is_empty());
    }

    #[tokio::test]
    async fn unrelated_refused() {
        let f = fixture().await;
        let e = f.schedule(Some("OTHER"), "FIN").await.unwrap_err();
        assert_eq!((e.status(), e.text()), (StatusCode::FORBIDDEN, "Not allowed to schedule events for client OTHER".to_string()));
        assert!(forbidden(f.cancel(Some("FIN"), "OTHER").await));
        assert!(f.calls().is_empty());
    }

    #[tokio::test]
    async fn the_request_reaches_the_scheduler_as_java_builds_it() {
        let f = fixture().await;
        let a = json!({"eventName": "taskReminder", "data": {"job": "a", "campaignId": 1}, "runAt": 1_791_000_000_000_i64,
                       "key": " k ", "clientCode": " FIN "});
        // A draft surface, a caller whose id is text.
        let caller = auth(json!({"user": {"id": "110"}, "clientCode": "FIN"}), Some("FIN"), Some(APP));
        let out = run(f.schedule.as_ref(), a.clone(), Some(caller), true, true).await.unwrap();
        assert_eq!(out["key"], json!(" k "), "the key is not trimmed");
        let r = f.one_offs.requests.lock()[0].clone();
        assert_eq!(
            r,
            ScheduleRequest {
                app_code: APP.into(),
                client_code: "FIN".into(),
                draft: true,
                event_name: "taskReminder".into(),
                data: doc! {"campaignId": 1, "job": "a"},
                run_at: Some(1_791_000_000_000),
                key: " k ".into(),
                scheduled_by: Some("110".into()),
            }
        );
        // No user: nobody scheduled it. No data: an empty map. A blank key: the service's.
        let anonymous = auth(json!({"clientCode": "FIN"}), Some("FIN"), Some(APP));
        let out = run(f.schedule.as_ref(), json!({"eventName": "taskReminder", "data": null, "key": null}), Some(anonymous), true, false)
            .await
            .unwrap();
        assert_eq!(out["key"], json!("generated"));
        let r = f.one_offs.requests.lock()[1].clone();
        assert_eq!((r.scheduled_by, r.data, r.key), (None, Document::new(), String::new()));
        assert!((r.run_at.unwrap() - now_millis()).abs() < 60_000, "no runAt is now");
        // A key running right now: not scheduled, the key answered.
        *f.one_offs.in_flight.lock() = true;
        let out = f.schedule(None, "FIN").await.unwrap();
        assert_eq!((out["scheduled"].clone(), out["key"].clone()), (json!(false), json!("task-1")));
    }

    #[tokio::test]
    async fn nothing_happens_outside_a_definition_or_for_an_unknown_event() {
        let f = fixture().await;
        let out = run(f.schedule.as_ref(), schedule_args(None), Some(user_of("FIN")), false, false).await.unwrap();
        assert_eq!((out["scheduled"].clone(), out["key"].clone()), (json!(false), json!("task-1")));
        let out = run(f.cancel.as_ref(), cancel_args(None), Some(user_of("FIN")), false, false).await.unwrap();
        assert_eq!(out["cancelled"], json!(false));
        // Inside a definition, but no caller in the context.
        assert_eq!(run(f.schedule.as_ref(), schedule_args(None), None, true, false).await.unwrap()["scheduled"], json!(false));
        assert_eq!(run(f.cancel.as_ref(), cancel_args(None), None, true, false).await.unwrap()["cancelled"], json!(false));
        // An event the app does not define.
        let mut a = schedule_args(None);
        a["eventName"] = json!("nope");
        assert_eq!(run(f.schedule.as_ref(), a, Some(user_of("FIN")), true, false).await.unwrap()["scheduled"], json!(false));
        assert!(f.calls().is_empty());
        // The draft surface cancels the draft surface's key.
        assert_eq!(run(f.cancel.as_ref(), cancel_args(None), Some(user_of("FIN")), true, true).await.unwrap()["cancelled"], json!(false));
        assert_eq!(f.calls(), [format!("cancel {APP} FIN task-1")]);
    }

    #[tokio::test]
    async fn bad_arguments_fail_as_java_fails_them() {
        let f = fixture().await;
        let mut a = schedule_args(None);
        a["runAt"] = json!("tomorrow");
        let e = run(f.schedule.as_ref(), a, Some(user_of("FIN")), true, false).await.unwrap_err();
        assert_eq!((e.status(), e.text()), (StatusCode::INTERNAL_SERVER_ERROR, "runAt is not an ISO timestamp: tomorrow".to_string()));
        // A caller without a client.
        let nobody = auth(json!({"user": {"id": 1}}), None, Some(APP));
        let e = run(f.schedule.as_ref(), schedule_args(None), Some(nobody.clone()), true, false).await.unwrap_err();
        assert_eq!((e.status(), e.text()), (StatusCode::BAD_REQUEST, "clientCode is required".to_string()));
        let e = run(f.cancel.as_ref(), cancel_args(Some(" ")), Some(nobody.clone()), true, false).await.unwrap_err();
        assert_eq!(e.status(), StatusCode::BAD_REQUEST);
        // A client named by a caller without one is refused.
        assert!(forbidden(run(f.cancel.as_ref(), cancel_args(Some("FIN")), Some(nobody), true, false).await));
        // The signature refuses what is not a string.
        assert!(run(f.cancel.as_ref(), json!({"key": {}}), Some(user_of("FIN")), true, false).await.is_err());
        assert!(run(f.schedule.as_ref(), json!({"runAt": 1}), Some(user_of("FIN")), true, false).await.is_err());
        assert!(f.calls().is_empty());
    }

    #[tokio::test]
    async fn arguments_read_as_gson_reads_them() {
        let args: Map<Value> = json!({"a": null, "b": 5, "c": "x", "d": {}}).as_object().unwrap().clone().into_iter().collect();
        assert_eq!(string_or_empty(&args, "a").unwrap(), "");
        assert_eq!(string_or_empty(&args, "missing").unwrap(), "");
        assert_eq!(string_or_empty(&args, "b").unwrap(), "5");
        assert_eq!(string_or_empty(&args, "c").unwrap(), "x");
        assert!(string_or_empty(&args, "d").is_err());
        let with = |user: serde_json::Value| scheduled_by(&auth(json!({"user": user}), None, None));
        assert_eq!(with(json!({"id": 110})), Some("110".into()));
        assert_eq!(with(json!({"id": "7"})), Some("7".into()));
        assert_eq!(with(json!({"clientId": 1})), None);
        assert_eq!(scheduled_by(&auth(json!({}), None, None)), None);
    }

    // Port of `EventScheduleOverrideTest.runAtTakesIsoTimestampsAndEpochMillis`, and the edges
    // of Java's strict ISO parsing.

    fn at(iso: &str) -> i64 {
        chrono::DateTime::parse_from_rfc3339(iso).unwrap().timestamp_millis()
    }

    #[test]
    fn run_at_takes_iso_timestamps_and_epoch_millis() {
        let p = |v: Value| parse_run_at(Some(&v), 42);
        assert_eq!(p(json!("2026-10-09T09:00:00+05:30")).unwrap(), at("2026-10-09T03:30:00Z"));
        assert_eq!(p(json!("2026-10-09T09:00:00Z")).unwrap(), at("2026-10-09T09:00:00Z"));
        assert_eq!(p(json!("2026-10-09T09:00:00")).unwrap(), at("2026-10-09T09:00:00Z"));
        assert_eq!(p(json!(1_791_000_000_000_i64)).unwrap(), 1_791_000_000_000);
        assert_eq!(p(Value::Null).unwrap(), 42);
        assert_eq!(parse_run_at(None, 42).unwrap(), 42);
    }

    /// Each text against what Java 25 answers for it (`OffsetDateTime.parse`, then
    /// `LocalDateTime.parse` in UTC, of the trimmed text): epoch millis, or refused.
    #[test]
    fn run_at_edges_as_the_jdk_parses_them() {
        let p = |v: Value| parse_run_at(Some(&v), 42);
        assert_eq!(p(json!(" \t ")).unwrap(), 42, "blank is now");
        let java: &[(&str, Option<i64>)] = &[
            (" 2026-10-09t09:00z ", Some(1_791_536_400_000)),
            ("2026-10-09T09:00z", Some(1_791_536_400_000)),
            ("2026-10-09T09:00 ", Some(1_791_536_400_000)),
            ("2026-10-09T09:00:00.5Z", Some(1_791_536_400_500)),
            ("2026-10-09T09:00:00.123999999Z", Some(1_791_536_400_123)),
            ("2026-10-09T09:00:00.Z", Some(1_791_536_400_000)),
            ("2026-10-09T23:59:59.999Z", Some(1_791_590_399_999)),
            ("2026-10-09T09:00-03:00", Some(1_791_547_200_000)),
            ("2026-10-09T09:00+18:00", Some(1_791_471_600_000)),
            ("2026-10-09T09:00-18:00", Some(1_791_601_200_000)),
            ("2026-10-09T09:00:00+05:30:15", Some(1_791_516_585_000)),
            ("2026-10-09T09:00:00-00:00", Some(1_791_536_400_000)),
            ("2026-10-09T09:00+05", Some(1_791_518_400_000)),
            ("2026-10-09T09:00-05", Some(1_791_554_400_000)),
            ("2026-10-09T09:00+18", Some(1_791_471_600_000)),
            ("2026-10-09T09:00+00", Some(1_791_536_400_000)),
            ("2024-02-29T00:00Z", Some(1_709_164_800_000)),
            ("+12026-01-01T00:00Z", Some(317_336_745_600_000)),
            ("-12026-01-01T00:00Z", Some(-441_671_097_600_000)),
            ("-2026-01-01T00:00Z", Some(-126_101_577_600_000)),
            ("-0001-01-01T00:00", Some(-62_198_755_200_000)),
            ("+2026-10-09T09:00Z", None),
            ("+0000-01-01T00:00Z", None),
            ("20260-10-09T09:00Z", None),
            ("226-10-09T09:00Z", None),
            ("+9999999999-01-01T00:00Z", None),
            ("2026-02-30T09:00Z", None),
            ("2026-10-09T24:00Z", None),
            ("2026-10-09T09:60Z", None),
            ("2026-10-09T09:00:60Z", None),
            ("2026-10-09T09:00:00.1234567891Z", None),
            ("2026-10-09T09:00+0530", None),
            ("2026-10-09T09:00+053", None),
            ("2026-10-09T09:00+5", None),
            ("2026-10-09T09:00+05:", None),
            ("2026-10-09T09:00+05:3", None),
            ("2026-10-09T09:00+05:30:", None),
            ("2026-10-09T09:00+05:30:1", None),
            ("2026-10-09T09:00+05:3015", None),
            ("2026-10-09T09:00+05:30:155", None),
            ("2026-10-09T09:00+19:00", None),
            ("2026-10-09T09:00+19", None),
            ("2026-10-09T09:00+24", None),
            ("2026-10-09T09:00+24:00", None),
            ("2026-10-09T09:00+18:00:01", None),
            ("2026-10-09T09:00+05:60", None),
            ("2026-10-09T09:00:00+00:00:60", None),
            ("2026-10-09T09:00+05x", None),
            ("2026-10-09T09:00Zx", None),
            ("2026-10-09T09:00Z:00", None),
            ("2026-10-09 09:00", None),
            ("2026-10-09", None),
            ("2026/10/09T09:00", None),
            ("2026-10-09T9:00", None),
            ("2026-10-09T09", None),
            ("2026-10-09T09:00:0", None),
        ];
        for (text, millis) in java {
            match millis {
                Some(ms) => assert_eq!(p(json!(text)).unwrap(), *ms, "{text}"),
                None => assert_eq!(p(json!(text)).unwrap_err().text(), format!("runAt is not an ISO timestamp: {}", text.trim()), "{text}"),
            }
        }
        assert_eq!(p(json!(true)).unwrap_err().text(), "runAt is not an ISO timestamp: true");
        assert_eq!(p(json!({})).unwrap_err().text(), "runAt must be an ISO timestamp or epoch milliseconds");
        assert!(p(json!([1])).is_err());
        assert_eq!(p(json!(1.9)).unwrap(), 1);
        assert_eq!(p(json!(u64::MAX)).unwrap(), -1);
        assert_eq!(p(json!(-5)).unwrap(), -5);
    }

    // ---------------------------------------------------------------- SetScheduleEnabled

    // Port of commons-core `SetScheduleEnabledFunctionTest`, through the function and the real
    // read and write paths on in-memory documents.

    const EVENT: &str = "LZ_WA_OUTBOX";

    struct Switch {
        backend: Arc<MemBackend>,
        directory: Arc<FakeDirectory>,
        function: Arc<dyn Function>,
        /// `GetScheduleState` on the same definitions.
        state: Arc<dyn Function>,
    }

    fn switch() -> Switch {
        let backend = Arc::new(MemBackend::new());
        let directory = Arc::new(FakeDirectory::new());
        let cache = platform::cache::CacheService::new("cmn", "evictionChannel", None).unwrap();
        let store = Store::with_parts(backend.clone(), directory.clone(), &cache).unwrap();
        let definitions: Arc<dyn ScheduleSwitch> = Arc::new(EventDefinitionService::new(store, cache));
        let function = Java::function(SetScheduleEnabled::new(definitions.clone()));
        let state: Arc<dyn Function> = Arc::new(Core(GetScheduleState::new(definitions)));
        Switch { backend, directory, function, state }
    }

    impl Switch {
        fn put(&self, doc: Document) -> Bson {
            self.backend.put_raw("eventDefinition", doc)
        }

        fn saved(&self, client: &str) -> Vec<Document> {
            self.backend.all("eventDefinition").into_iter().filter(|d| d.get_str("clientCode") == Ok(client)).collect()
        }

        async fn run(&self, enabled: Option<bool>, client: &str, in_definition: bool, draft: bool) -> bool {
            let mut a = json!({"eventName": EVENT});
            if let Some(e) = enabled {
                a["enabled"] = json!(e);
            }
            let out = run(self.function.as_ref(), a, Some(event_runner_for(client)), in_definition, draft).await.unwrap();
            out["changed"].as_bool().unwrap()
        }
    }

    fn event_runner_for(client_code: &str) -> Authentication {
        auth(json!({"user": {"id": 0, "clientId": 7}, "clientCode": client_code, "loggedInFromClientCode": client_code}), Some(client_code), Some(APP))
    }

    fn base_schedule(enabled: Option<bool>) -> Document {
        let mut s = doc! {"cron": "0 */15 * * * ?", "timezone": "UTC", "perClient": true, "spread": true};
        if let Some(e) = enabled {
            s.insert("enabled", e);
        }
        s
    }

    #[tokio::test]
    async fn creates_a_copy_with_only_enabled() {
        let s = switch();
        s.directory.set(|a| {
            a.chains.insert("AKASH".into(), vec!["SYSTEM".into(), "FIN".into(), "AKASH".into()]);
        });
        s.put(doc! {"name": EVENT, "appCode": APP, "clientCode": "SYSTEM", "schema": {"type": "OBJECT"}, "schedule": base_schedule(None)});
        // AKASH sees FIN's copy, so that is the one its new copy overrides.
        s.put(doc! {"name": EVENT, "appCode": APP, "clientCode": "FIN", "baseClientCode": "SYSTEM", "schedule": {"enabled": false}});
        assert!(s.run(None, "AKASH", true, false).await);
        let saved = s.saved("AKASH");
        assert_eq!(saved.len(), 1);
        let mut copy = saved[0].clone();
        copy.remove("_id");
        assert_eq!(
            copy,
            doc! {"schedule": {"enabled": true}, "name": EVENT,
                  "message": "Schedule enabled for AKASH by CoreServices.Event.SetScheduleEnabled",
                  "clientCode": "AKASH", "appCode": APP, "baseClientCode": "FIN", "version": 1},
            "cron, perClient and the schema stay with the base; without the FIN link the copy is read on its own and never runs"
        );
    }

    #[tokio::test]
    async fn updates_an_existing_copy() {
        let s = switch();
        s.directory.chain(&["FIN"]);
        let id = s.put(doc! {"name": EVENT, "appCode": APP, "clientCode": "FIN", "version": 3,
                              "schedule": {"cron": "0 */5 * * * ?", "enabled": true}});
        assert!(s.run(Some(false), "FIN", true, false).await);
        let copy = s.saved("FIN").remove(0);
        assert_eq!(copy.get("_id"), Some(&id));
        assert_eq!(copy.get_document("schedule").unwrap(), &doc! {"cron": "0 */5 * * * ?", "enabled": false});
        assert_eq!(copy.get_i32("version").unwrap(), 4);
    }

    #[tokio::test]
    async fn no_change_writes_nothing() {
        let s = switch();
        s.put(doc! {"name": EVENT, "appCode": APP, "clientCode": "FIN", "schedule": base_schedule(Some(true))});
        s.put(doc! {"name": EVENT, "appCode": APP, "clientCode": "AKHIL", "schedule": base_schedule(None)});
        assert!(!s.run(Some(true), "FIN", true, false).await);
        assert!(!s.run(Some(true), "AKHIL", true, false).await, "absent enabled already means enabled");
        assert!(s.backend.all("eventDefinition").iter().all(|d| d.get("message").is_none()));
    }

    #[tokio::test]
    async fn unknown_or_unscheduled_event_writes_nothing() {
        let s = switch();
        s.put(doc! {"name": EVENT, "appCode": APP, "clientCode": "FIN"});
        assert!(!s.run(Some(true), "FIN", true, false).await);
        assert!(!s.run(Some(true), "NOBODY", true, false).await);
        assert_eq!(s.backend.all("eventDefinition").len(), 1);
    }

    #[tokio::test]
    async fn outside_a_definition_does_nothing() {
        let s = switch();
        s.put(doc! {"name": EVENT, "appCode": APP, "clientCode": "AKASH", "schedule": base_schedule(Some(false))});
        assert!(!s.run(Some(true), "AKASH", false, false).await);
        assert!(s.saved("AKASH")[0].get("message").is_none());
    }

    #[tokio::test]
    async fn draft_surface_does_nothing() {
        let s = switch();
        s.put(doc! {"name": EVENT, "appCode": APP, "clientCode": "AKASH", "schedule": base_schedule(Some(false))});
        assert!(!s.run(Some(true), "AKASH", true, true).await);
        // A surface named in the context counts the same.
        let out = context::with_surface(true, run(s.function.as_ref(), json!({"eventName": EVENT}), Some(event_runner_for("AKASH")), true, false))
            .await
            .unwrap();
        assert_eq!(out["changed"], json!(false));
        assert!(s.saved("AKASH")[0].get("message").is_none());
    }

    #[tokio::test]
    async fn a_blank_name_or_no_caller_does_nothing_and_failures_pass_up() {
        let s = switch();
        s.put(doc! {"name": EVENT, "appCode": APP, "clientCode": "AKASH", "schedule": base_schedule(Some(false))});
        for a in [json!({"eventName": "  "}), json!({"eventName": null})] {
            let out = run(s.function.as_ref(), a, Some(event_runner_for("AKASH")), true, false).await;
            assert!(out.is_err() || out.unwrap()["changed"] == json!(false));
        }
        let out = run(s.function.as_ref(), json!({"eventName": EVENT}), None, true, false).await.unwrap();
        assert_eq!(out["changed"], json!(false));
        assert!(s.saved("AKASH")[0].get("message").is_none());
        s.backend.fail("eventDefinition", true);
        assert!(run(s.function.as_ref(), json!({"eventName": EVENT}), Some(event_runner_for("AKASH")), true, false).await.is_err());
    }

    #[tokio::test]
    async fn enabled_and_names_read_as_gson_reads_them() {
        #[derive(Default)]
        struct Recorder(Mutex<Vec<String>>);
        #[async_trait]
        impl ScheduleSwitch for Recorder {
            async fn set_own_schedule_enabled(&self, name: &str, app: &str, client: &str, enabled: bool)
                -> Result<Option<bool>, CoreError> {
                self.0.lock().push(format!("{app} {client} {name} {enabled}"));
                Ok(None)
            }
            async fn schedule_state(&self, _name: &str, _app: &str, client: &str) -> Result<ScheduleState, CoreError> {
                Ok(ScheduleState { client_code: client.to_string(), ..Default::default() })
            }
        }
        let rec = Arc::new(Recorder::default());
        let f = SetScheduleEnabled::new(rec.clone());
        let ctx = request(event_runner_for("FIN"), false, None);
        context::with_request(ctx, context::with_run(context::RunScope::default(), async {
            for (enabled, name) in [(json!("TRUE"), " x "), (json!("no"), "y"), (json!(null), "z"), (json!(1), "n")] {
                let args: Map<Value> = json!({"eventName": name, "enabled": enabled}).as_object().unwrap().clone().into_iter().collect();
                let mut out = f.run(&args).await.unwrap();
                assert_eq!(out.next().unwrap().get_result()["changed"], json!(false));
            }
            let args: Map<Value> = json!({"eventName": "w", "enabled": {}}).as_object().unwrap().clone().into_iter().collect();
            assert!(f.run(&args).await.is_err());
        }))
        .await;
        assert_eq!(*rec.0.lock(), [format!("{APP} FIN x true"), format!("{APP} FIN y false"), format!("{APP} FIN z true"), format!("{APP} FIN n false")]);
    }

    // ---------------------------------------------------------------- GetScheduleState

    impl Switch {
        async fn state_of(&self, args: serde_json::Value, client: &str, in_definition: bool, draft: bool) -> Result<Map<Value>, CoreError> {
            run(self.state.as_ref(), args, Some(event_runner_for(client)), in_definition, draft).await
        }
    }

    #[tokio::test]
    async fn the_state_is_the_effective_definitions() {
        let s = switch();
        s.directory.set(|a| {
            a.chains.insert("AKASH".into(), vec!["SYSTEM".into(), "FIN".into(), "AKASH".into()]);
            a.chains.insert("BP1".into(), vec!["SYSTEM".into(), "BP1".into()]);
        });
        s.put(doc! {"name": EVENT, "appCode": APP, "clientCode": "SYSTEM", "schedule": base_schedule(None)});
        s.put(doc! {"name": EVENT, "appCode": APP, "clientCode": "FIN", "baseClientCode": "SYSTEM", "schedule": {"enabled": false}});
        let out = s.state_of(json!({"eventName": EVENT}), "BP1", true, false).await.unwrap();
        assert_eq!(
            Value::Object(out.into_iter().collect()),
            json!({"exists": true, "enabled": true, "cron": "0 */15 * * * ?", "clientCode": "BP1", "ownCopy": false}),
            "the base's, absent enabled is enabled"
        );

        // FIN's copy turns it off for AKASH, which has no copy of its own.
        let out = s.state_of(json!({"eventName": EVENT}), "AKASH", true, false).await.unwrap();
        assert_eq!((out["exists"].clone(), out["enabled"].clone(), out["ownCopy"].clone()), (json!(true), json!(false), json!(false)));
        assert_eq!(out["cron"], json!("0 */15 * * * ?"), "the cron stays the base's");

        // SetScheduleEnabled's copy is what the state reads next.
        assert!(s.run(Some(true), "AKASH", true, false).await);
        let out = s.state_of(json!({"eventName": EVENT, "appCode": APP, "clientCode": "AKASH"}), "AKASH", true, false).await.unwrap();
        assert_eq!((out["enabled"].clone(), out["ownCopy"].clone()), (json!(true), json!(true)));
        // On the draft surface it reads the live schedule, the one that runs.
        let out = s.state_of(json!({"eventName": EVENT}), "AKASH", true, true).await.unwrap();
        assert_eq!((out["enabled"].clone(), out["ownCopy"].clone()), (json!(true), json!(true)));
        assert_eq!(s.saved("AKASH").len(), 1, "reading writes nothing");
    }

    #[tokio::test]
    async fn no_schedule_no_event_no_definition_run_answers_it_does_not_exist() {
        let s = switch();
        s.put(doc! {"name": EVENT, "appCode": APP, "clientCode": "FIN"});
        let out = s.state_of(json!({"eventName": EVENT}), "FIN", true, false).await.unwrap();
        assert_eq!(
            Value::Object(out.into_iter().collect()),
            json!({"exists": false, "enabled": false, "cron": null, "clientCode": "FIN", "ownCopy": true}),
            "an event without a schedule"
        );
        let out = s.state_of(json!({"eventName": "NOPE"}), "FIN", true, false).await.unwrap();
        assert_eq!((out["exists"].clone(), out["ownCopy"].clone()), (json!(false), json!(false)));
        let out = s.state_of(json!({"eventName": "  "}), "FIN", true, false).await.unwrap();
        assert_eq!(out["exists"], json!(false));
        let out = s.state_of(json!({"eventName": EVENT}), "FIN", false, false).await.unwrap();
        assert_eq!((out["exists"].clone(), out["clientCode"].clone()), (json!(false), json!(null)), "outside a server function");
        let out = run(s.state.as_ref(), json!({"eventName": EVENT}), None, true, false).await.unwrap();
        assert_eq!(out["exists"], json!(false), "without a caller");
    }

    #[tokio::test]
    async fn the_state_is_only_for_the_callers_own_client_and_app() {
        let s = switch();
        s.put(doc! {"name": EVENT, "appCode": APP, "clientCode": "FIN", "schedule": base_schedule(Some(false))});
        s.put(doc! {"name": EVENT, "appCode": "otherapp", "clientCode": "FIN", "schedule": base_schedule(None)});
        for args in [json!({"eventName": EVENT, "clientCode": "SYSTEM"}), json!({"eventName": EVENT, "appCode": "otherapp"})] {
            let e = s.state_of(args.clone(), "FIN", true, false).await.unwrap_err();
            assert_eq!(e.status(), StatusCode::FORBIDDEN, "{args}");
            assert_eq!(e.code().map(|c| c.code.as_ref()), Some("CORE.SCHEDULE_STATE_FORBIDDEN"), "{args}");
        }
        let out = s.state_of(json!({"eventName": EVENT, "clientCode": " FIN ", "appCode": APP}), "FIN", true, false).await.unwrap();
        assert_eq!((out["exists"].clone(), out["enabled"].clone()), (json!(true), json!(false)));
        s.backend.fail("eventDefinition", true);
        assert!(s.state_of(json!({"eventName": EVENT}), "FIN", true, false).await.is_err(), "a failed read passes up");
    }

    // ---------------------------------------------------------------- registration

    #[tokio::test]
    async fn registered_in_java_order_with_java_signatures() {
        let storage = crate::testing::offline_storage_service().await;
        let deps = crate::testing::offline_deps("http://127.0.0.1:1", storage).await;
        let all = all(&deps);
        let names: Vec<String> = all.iter().map(|f| f.get_signature().get_full_name()).collect();
        assert_eq!(
            names,
            ["CoreServices.Event.ScheduleEvent", "CoreServices.Event.CancelScheduledEvent", "CoreServices.Event.SetScheduleEnabled", GetScheduleState::FULL_NAME]
        );
        for f in all.iter().take(3) {
            let full = f.get_signature().get_full_name();
            let back = crate::java_model::gson_signature(&f.get_signature().to_json(), false);
            assert_eq!(back["parameters"].as_object().unwrap().len(), crate::functions::java_sig::json(&full)["parameters"].as_object().unwrap().len());
        }
        // Outside a definition the wired functions answer without touching anything.
        let out = run(all[0].as_ref(), schedule_args(None), Some(user_of("FIN")), false, false).await.unwrap();
        assert_eq!(out["scheduled"], json!(false));
        let out = run(all[2].as_ref(), json!({"eventName": EVENT}), Some(user_of("FIN")), false, false).await.unwrap();
        assert_eq!(out["changed"], json!(false));
    }
}
