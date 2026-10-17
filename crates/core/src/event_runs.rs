//! The event run log (`EventRunService`, `EventRunDAO`, `EventRun`, `EventRunTask`): one
//! `core_event_runs` row per run of an event's EventAction, and per outcome that kept one from
//! running (`V9__Event Runs.sql`).
//!
//! **Writing never fails the run.** Every write swallows its own error (logged), because a log
//! that can stop the thing it logs is worse than a gap in the log.
//!
//! **Reading is per client.** A caller holding `Authorities.EventAction_READ` reads its own
//! client's runs, and a client it manages when its own client has read access to the app.
//!
//! - [`EventRunDao`]: the table, over MySQL ([`MySqlEventRunDao`]) or in memory
//!   ([`MemoryEventRunDao`], for tests);
//! - [`EventRunService`]: `start` / `finish` / `record` / `record_no_action` for the events
//!   consumer and the scheduler, the reads behind `/api/core/eventRuns`, the retention sweep;
//! - [`error_of`] / [`detail_of`]: what a failed task's row says, with the KIRun step traces
//!   [`traced`] collects (see [`crate::step_trace`]).

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use axum::http::StatusCode;
use chrono::{DateTime, NaiveDateTime, TimeDelta};
use connections::mq::EventMessage;
use futures::{StreamExt, TryStreamExt};
use overridable::write::spring::{page_json, Pageable};
use overridable::{JMap, JValue};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sqlx::mysql::MySqlRow;
use sqlx::{MySql, QueryBuilder, Row};

use crate::auth::Authentication;
use crate::clients::SecurityCalls;
use crate::error::{messages, CoreError};
use crate::scheduler::{java_blank, java_trim};
use crate::step_trace::truncate16;
pub use crate::step_trace::{traced, StepTrace};

/// The key in an event's data that says which scheduled run it belongs to
/// (`EventScheduler.SCHEDULE_DATA_KEY`).
pub const SCHEDULE_DATA_KEY: &str = "_schedule";

/// Events another service hands to core so an app can own a channel. Losing one loses a
/// customer's message or call, so an unhandled one is always recorded.
pub const HANDOFF_EVENTS: [&str; 2] = ["WHATSAPP_INBOUND", "CALL_EVENT"];

/// The authority `readPage` and `read` are behind (`@PreAuthorize`).
pub const EVENT_ACTION_READ: &str = "Authorities.EventAction_READ";

pub const MAX_ERROR_LENGTH: usize = 4000;
const DELETE_BATCH: i64 = 5000;

/// The sweep's floors and cap: the endpoint that drives it is unauthenticated, so nothing
/// younger than these is ever deleted or called stale, and one call removes at most this many.
pub const MIN_RETENTION_DAYS: i64 = 30;
pub const MIN_SUCCESS_RETENTION_DAYS: i64 = 1;
pub const MIN_STALE_HOURS: i64 = 1;
pub const MAX_CLEANUP_LIMIT: i64 = 200_000;

/// A NO_ACTION row is written at most once per app, client and event in this window, per
/// instance; the row after a window carries how many were not written. Hand-offs are exempt.
pub const NO_ACTION_WINDOW_MS: i64 = 60 * 60 * 1000;

/// Bound on the remembered keys, so an unbounded set of event names cannot grow the map.
pub const MAX_NO_ACTION_KEYS: usize = 10_000;

/// Most clients "all clients" considers at once.
pub const MAX_CANDIDATE_CLIENTS: usize = 5000;

/// Shown in full in a detail; the steps further out show only where they are.
pub const MAX_DETAIL_STEPS_WITH_ARGUMENTS: usize = 3;
pub const MAX_DETAIL_LENGTH: usize = 12000;
pub const MAX_DETAIL_CAUSES: usize = 5;

/// core's `messages_en.properties`, beyond [`messages`], and the texts the log writes.
pub mod run_messages {
    pub use crate::catalogue::keys::{APPLICATION_NAME_REQUIRED, FORBIDDEN_CLIENT_CODE};
    /// `HttpStatusServerAccessDeniedHandler`'s body for a `@PreAuthorize` refusal.
    pub const ACCESS_DENIED: &str = "Access Denied";
    pub const STALE_RUN: &str = "No outcome was reported for this run. The server running it may have stopped part way through; check whether its work was done.";
}

/// `core.eventRuns.*`: `[core.event_runs]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EventRunsSettings {
    /// Off stops writing the log; reading and the worker's sweep still work.
    pub enabled: bool,
}

impl Default for EventRunsSettings {
    fn default() -> Self {
        Self { enabled: true }
    }
}

// ------------------------------------------------------------------ the model

macro_rules! java_enum {
    ($name:ident { $($variant:ident = $text:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name { $($variant),+ }

        impl $name {
            pub const ALL: &'static [$name] = &[$($name::$variant),+];

            pub fn name(self) -> &'static str {
                match self { $($name::$variant => $text),+ }
            }

            /// `Enum.valueOf`.
            pub fn parse(s: &str) -> Option<Self> {
                Self::ALL.iter().copied().find(|v| v.name() == s)
            }
        }

        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(self.name())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                Self::parse(&s).ok_or_else(|| serde::de::Error::custom(format!("No enum constant {s}")))
            }
        }
    };
}

java_enum!(RunStatus { Running = "RUNNING", Success = "SUCCESS", Failed = "FAILED", Skipped = "SKIPPED", NoAction = "NO_ACTION" });
java_enum!(TriggerType { Schedule = "SCHEDULE", OneOff = "ONE_OFF", Event = "EVENT" });
java_enum!(TaskStatus { Success = "SUCCESS", Failed = "FAILED" });

/// How one task of an EventAction went in one run: an element of `core_event_runs.TASKS`, in
/// the order the tasks ran. Times are epoch milliseconds.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct EventRunTask {
    /// The task's key in the action's task map.
    pub key: Option<String>,
    #[serde(rename = "type")]
    pub task_type: Option<String>,
    /// What the task ran: namespace.name of the function for a CALL_CORE_FUNCTION task.
    pub target: Option<String>,
    pub order: Option<i32>,
    pub status: Option<TaskStatus>,
    pub started_at: Option<i64>,
    pub duration_ms: Option<i64>,
    pub error: Option<String>,
    /// [`detail_of`] the failure, for whoever fixes it.
    pub detail: Option<String>,
    /// Display text, filled with the run's.
    pub duration_text: Option<String>,
}

fn put_str(m: &mut Map<String, Value>, key: &str, v: &Option<String>) {
    // `NON_EMPTY`: no null, no empty string.
    if let Some(s) = v.as_ref().filter(|s| !s.is_empty()) {
        m.insert(key.into(), Value::String(s.clone()));
    }
}

fn put<T: Into<Value> + Copy>(m: &mut Map<String, Value>, key: &str, v: Option<T>) {
    if let Some(v) = v {
        m.insert(key.into(), v.into());
    }
}

/// `LocalDateTime` as `CommonsSerializationModule` writes it: epoch seconds.
fn epoch_seconds(t: NaiveDateTime) -> i64 {
    t.and_utc().timestamp()
}

impl EventRunTask {
    /// As the services' Jackson writes it (`NON_EMPTY`, declaration order).
    pub fn to_jackson(&self) -> Value {
        let mut m = Map::new();
        put_str(&mut m, "key", &self.key);
        put_str(&mut m, "type", &self.task_type);
        put_str(&mut m, "target", &self.target);
        put(&mut m, "order", self.order);
        put(&mut m, "status", self.status.map(TaskStatus::name));
        put(&mut m, "startedAt", self.started_at);
        put(&mut m, "durationMs", self.duration_ms);
        put_str(&mut m, "error", &self.error);
        put_str(&mut m, "detail", &self.detail);
        put_str(&mut m, "durationText", &self.duration_text);
        Value::Object(m)
    }
}

/// One run of an event's EventAction, or an outcome that kept it from running. Times are UTC.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EventRun {
    pub id: Option<u64>,
    pub app_code: Option<String>,
    pub client_code: Option<String>,
    pub event_name: Option<String>,
    pub trigger_type: Option<TriggerType>,
    pub status: Option<RunStatus>,
    pub schedule_run_id: Option<String>,
    pub scheduled_for: Option<NaiveDateTime>,
    pub attempt: Option<i32>,
    pub is_draft: Option<bool>,
    pub triggered_by: Option<u64>,
    pub task_count: Option<i32>,
    pub failed_task_count: Option<i32>,
    pub tasks: Option<Vec<EventRunTask>>,
    pub error: Option<String>,
    pub instance_id: Option<String>,
    pub started_at: Option<NaiveDateTime>,
    pub finished_at: Option<NaiveDateTime>,
    pub duration_ms: Option<i64>,
    /// Display text, filled when the reader names a time zone.
    pub started_text: Option<String>,
    pub scheduled_for_text: Option<String>,
    pub duration_text: Option<String>,
}

impl EventRun {
    /// As the services' Jackson writes it: `NON_EMPTY`, declaration order, times as epoch
    /// seconds.
    pub fn to_jackson(&self) -> Value {
        let mut m = Map::new();
        put(&mut m, "id", self.id);
        put_str(&mut m, "appCode", &self.app_code);
        put_str(&mut m, "clientCode", &self.client_code);
        put_str(&mut m, "eventName", &self.event_name);
        put(&mut m, "triggerType", self.trigger_type.map(TriggerType::name));
        put(&mut m, "status", self.status.map(RunStatus::name));
        put_str(&mut m, "scheduleRunId", &self.schedule_run_id);
        put(&mut m, "scheduledFor", self.scheduled_for.map(epoch_seconds));
        put(&mut m, "attempt", self.attempt);
        put(&mut m, "isDraft", self.is_draft);
        put(&mut m, "triggeredBy", self.triggered_by);
        put(&mut m, "taskCount", self.task_count);
        put(&mut m, "failedTaskCount", self.failed_task_count);
        if let Some(tasks) = self.tasks.as_ref().filter(|t| !t.is_empty()) {
            m.insert("tasks".into(), Value::Array(tasks.iter().map(EventRunTask::to_jackson).collect()));
        }
        put_str(&mut m, "error", &self.error);
        put_str(&mut m, "instanceId", &self.instance_id);
        put(&mut m, "startedAt", self.started_at.map(epoch_seconds));
        put(&mut m, "finishedAt", self.finished_at.map(epoch_seconds));
        put(&mut m, "durationMs", self.duration_ms);
        put_str(&mut m, "startedText", &self.started_text);
        put_str(&mut m, "scheduledForText", &self.scheduled_for_text);
        put_str(&mut m, "durationText", &self.duration_text);
        Value::Object(m)
    }

    /// The pretty JSON `ResponseEntity.ok(run)` answers with.
    pub fn to_jackson_text(&self) -> String {
        overridable::json::to_jackson_pretty(&jvalue(self.to_jackson()))
    }
}

fn jvalue(v: Value) -> JValue {
    serde_json::from_value(v).unwrap_or(JValue::Null)
}

/// `TASKS` as the DAO's `ObjectMapper` writes it; null for no tasks.
pub fn tasks_to_json(tasks: &[EventRunTask]) -> Option<String> {
    if tasks.is_empty() {
        return None;
    }
    Some(crate::gson::to_jackson_pretty(&Value::Array(tasks.iter().map(EventRunTask::to_jackson).collect())))
}

/// `TASKS` read back: empty when null, blank or unreadable.
pub fn tasks_from_json(json: Option<&str>) -> Vec<EventRunTask> {
    match json.filter(|j| !java_blank(j)) {
        Some(j) => serde_json::from_str(j).unwrap_or_default(),
        None => Vec::new(),
    }
}

/// What the run log screen asks for: `readPage`'s filters.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RunFilter {
    pub app_code: String,
    pub client_codes: Vec<String>,
    pub event_name: Option<String>,
    pub status: Option<RunStatus>,
    pub trigger_type: Option<TriggerType>,
    /// `STARTED_AT >= from`.
    pub from: Option<NaiveDateTime>,
    /// `STARTED_AT < to`.
    pub to: Option<NaiveDateTime>,
}

/// `new PageImpl<>(content, pageable, total)`.
#[derive(Debug, Clone, PartialEq)]
pub struct RunPage {
    pub content: Vec<EventRun>,
    pub pageable: Pageable,
    pub total: i64,
}

impl RunPage {
    pub fn empty(pageable: &Pageable) -> Self {
        Self { content: Vec::new(), pageable: pageable.clone(), total: 0 }
    }

    /// `PageImpl` as Jackson writes it.
    pub fn to_jackson_text(&self) -> String {
        let content = self.content.iter().map(|r| jvalue(r.to_jackson())).collect();
        overridable::json::to_jackson_pretty(&page_json(content, &self.pageable, self.total))
    }

    /// `getTotalElements()`, as `PageImpl` adjusts it.
    pub fn total_elements(&self) -> i64 {
        let len = self.content.len() as i64;
        if len != 0 && self.pageable.offset() + self.pageable.size > self.total {
            self.pageable.offset() + len
        } else {
            self.total
        }
    }
}

// ------------------------------------------------------------------ the DAO

/// `EventRunDAO`.
#[async_trait]
pub trait EventRunDao: Send + Sync {
    /// The new row's id.
    async fn insert(&self, run: &EventRun) -> Result<u64, CoreError>;

    /// Closes a RUNNING row. A row the stale sweep already closed is overwritten: the run did
    /// report.
    #[allow(clippy::too_many_arguments)]
    async fn finish(
        &self,
        id: u64,
        status: RunStatus,
        tasks: &[EventRunTask],
        failed_tasks: i32,
        error: Option<&str>,
        finished_at: NaiveDateTime,
        duration_ms: i64,
    ) -> Result<bool, CoreError>;

    async fn read(&self, id: u64) -> Result<Option<EventRun>, CoreError>;

    /// Newest first, for the filter's clients (none: an empty page without a query).
    async fn read_page(&self, filter: &RunFilter, pageable: &Pageable) -> Result<RunPage, CoreError>;

    /// The clients that have any run of this event (of any event when blank), at most `limit`.
    async fn distinct_clients(&self, app_code: &str, event_name: Option<&str>, limit: usize) -> Result<Vec<String>, CoreError>;

    /// The newest run of this event for each of the clients that has one, in their order.
    async fn latest_per_client(&self, app_code: &str, event_name: &str, client_codes: &[String]) -> Result<Vec<EventRun>, CoreError>;

    /// Deletes up to `limit` rows started before `before` (only those in `status` when given);
    /// how many went.
    async fn delete_started_before(&self, before: NaiveDateTime, status: Option<RunStatus>, limit: i64) -> Result<i64, CoreError>;

    /// Closes RUNNING rows started before `before` as FAILED with `error`.
    async fn fail_running_started_before(&self, before: NaiveDateTime, error: &str, now: NaiveDateTime) -> Result<i64, CoreError>;
}

fn non_negative(n: Option<i32>) -> i32 {
    n.filter(|n| *n >= 0).unwrap_or(0)
}

/// jOOQ's `UShort.valueOf` / `UInteger.valueOf`: a value out of range is refused.
fn unsigned<T: TryFrom<i64>>(v: i64) -> Result<T, CoreError> {
    T::try_from(v).map_err(|_| CoreError::unknown(format!("Value is out of range : {v}")))
}

/// `core_event_runs` over core's MySQL pool.
pub struct MySqlEventRunDao {
    pool: sqlx::MySqlPool,
}

const TABLE: &str = "core_event_runs";

/// Every column, the enums and the JSON read back as text.
const COLUMNS: &str = "ID, APP_CODE, CLIENT_CODE, EVENT_NAME, CAST(TRIGGER_TYPE AS CHAR) AS TRIGGER_TYPE, \
    CAST(STATUS AS CHAR) AS STATUS, SCHEDULE_RUN_ID, SCHEDULED_FOR, ATTEMPT, IS_DRAFT, TRIGGERED_BY, TASK_COUNT, \
    FAILED_TASK_COUNT, CAST(TASKS AS CHAR) AS TASKS, ERROR, INSTANCE_ID, STARTED_AT, FINISHED_AT, DURATION_MS";

fn db_error(e: sqlx::Error) -> CoreError {
    CoreError::unknown(e.to_string())
}

impl MySqlEventRunDao {
    pub fn new(pool: sqlx::MySqlPool) -> Self {
        Self { pool }
    }

    fn to_run(row: &MySqlRow) -> Result<EventRun, sqlx::Error> {
        // CHAR columns come back padded on some drivers.
        let trimmed = |c: &str| -> Result<Option<String>, sqlx::Error> {
            Ok(row.try_get::<Option<String>, _>(c)?.map(|s| java_trim(&s).to_string()))
        };
        Ok(EventRun {
            id: Some(row.try_get::<u64, _>("ID")?),
            app_code: trimmed("APP_CODE")?,
            client_code: trimmed("CLIENT_CODE")?,
            event_name: row.try_get("EVENT_NAME")?,
            trigger_type: row.try_get::<Option<String>, _>("TRIGGER_TYPE")?.as_deref().and_then(TriggerType::parse),
            status: row.try_get::<Option<String>, _>("STATUS")?.as_deref().and_then(RunStatus::parse),
            schedule_run_id: row.try_get("SCHEDULE_RUN_ID")?,
            scheduled_for: row.try_get("SCHEDULED_FOR")?,
            attempt: row.try_get::<Option<u32>, _>("ATTEMPT")?.map(|a| a as i32),
            is_draft: Some(row.try_get::<Option<i8>, _>("IS_DRAFT")?.is_some_and(|d| d != 0)),
            triggered_by: row.try_get("TRIGGERED_BY")?,
            task_count: Some(row.try_get::<Option<u16>, _>("TASK_COUNT")?.map_or(0, i32::from)),
            failed_task_count: Some(row.try_get::<Option<u16>, _>("FAILED_TASK_COUNT")?.map_or(0, i32::from)),
            tasks: Some(tasks_from_json(row.try_get::<Option<String>, _>("TASKS")?.as_deref())),
            error: row.try_get("ERROR")?,
            instance_id: row.try_get("INSTANCE_ID")?,
            started_at: row.try_get("STARTED_AT")?,
            finished_at: row.try_get("FINISHED_AT")?,
            duration_ms: row.try_get::<Option<u32>, _>("DURATION_MS")?.map(i64::from),
            ..Default::default()
        })
    }

    fn push_where(qb: &mut QueryBuilder<'_, MySql>, f: &RunFilter) {
        // (dates were checked by `mysql_datetime` before the query is built)
        if f.client_codes.len() == 1 {
            qb.push(" WHERE CLIENT_CODE = ").push_bind(f.client_codes[0].clone());
        } else {
            qb.push(" WHERE CLIENT_CODE IN (");
            let mut sep = qb.separated(", ");
            for c in &f.client_codes {
                sep.push_bind(c.clone());
            }
            sep.push_unseparated(")");
        }
        qb.push(" AND APP_CODE = ").push_bind(f.app_code.clone());
        if let Some(e) = f.event_name.as_ref().filter(|e| !java_blank(e)) {
            qb.push(" AND EVENT_NAME = ").push_bind(e.clone());
        }
        if let Some(s) = f.status {
            qb.push(" AND STATUS = ").push_bind(s.name());
        }
        if let Some(t) = f.trigger_type {
            qb.push(" AND TRIGGER_TYPE = ").push_bind(t.name());
        }
        if let Some(from) = f.from {
            qb.push(" AND STARTED_AT >= ").push_bind(from);
        }
        if let Some(to) = f.to {
            qb.push(" AND STARTED_AT < ").push_bind(to);
        }
    }
}

/// MySQL refuses a DATETIME past year 9999 ("Incorrect DATETIME value"), which jOOQ sends as
/// text and the Java query fails on (a 500); sqlx would bind it and match nothing.
fn mysql_datetime(t: NaiveDateTime) -> Result<NaiveDateTime, CoreError> {
    use chrono::{Datelike, Timelike};
    if t.year() <= 9999 {
        return Ok(t);
    }
    Err(CoreError::unknown(format!(
        "Incorrect DATETIME value: '{}-{:02}-{:02} {:02}:{:02}:{:02}'",
        t.year(),
        t.month(),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )))
}

#[async_trait]
impl EventRunDao for MySqlEventRunDao {
    async fn insert(&self, run: &EventRun) -> Result<u64, CoreError> {
        let attempt = run.attempt.map(|a| unsigned::<u32>(a.into())).transpose()?;
        let task_count = unsigned::<u16>(non_negative(run.task_count).into())?;
        let failed = unsigned::<u16>(non_negative(run.failed_task_count).into())?;
        let duration = run.duration_ms.map(|d| unsigned::<u32>(d.max(0))).transpose()?;
        let sql = format!(
            "INSERT INTO {TABLE} (APP_CODE, CLIENT_CODE, EVENT_NAME, TRIGGER_TYPE, STATUS, SCHEDULE_RUN_ID, SCHEDULED_FOR, \
             ATTEMPT, IS_DRAFT, TRIGGERED_BY, TASK_COUNT, FAILED_TASK_COUNT, TASKS, ERROR, INSTANCE_ID, STARTED_AT, FINISHED_AT, \
             DURATION_MS) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        );
        let r = sqlx::query(&sql)
            .bind(&run.app_code)
            .bind(&run.client_code)
            .bind(&run.event_name)
            .bind(run.trigger_type.map(TriggerType::name))
            .bind(run.status.map(RunStatus::name))
            .bind(&run.schedule_run_id)
            .bind(run.scheduled_for)
            .bind(attempt)
            .bind(i8::from(run.is_draft == Some(true)))
            .bind(run.triggered_by)
            .bind(task_count)
            .bind(failed)
            .bind(run.tasks.as_deref().and_then(tasks_to_json))
            .bind(&run.error)
            .bind(&run.instance_id)
            .bind(run.started_at)
            .bind(run.finished_at)
            .bind(duration)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(r.last_insert_id())
    }

    async fn finish(
        &self,
        id: u64,
        status: RunStatus,
        tasks: &[EventRunTask],
        failed_tasks: i32,
        error: Option<&str>,
        finished_at: NaiveDateTime,
        duration_ms: i64,
    ) -> Result<bool, CoreError> {
        let task_count = unsigned::<u16>(tasks.len() as i64)?;
        let failed = unsigned::<u16>(non_negative(Some(failed_tasks)).into())?;
        let duration = unsigned::<u32>(duration_ms.max(0))?;
        let sql = format!(
            "UPDATE {TABLE} SET STATUS = ?, TASKS = ?, TASK_COUNT = ?, FAILED_TASK_COUNT = ?, ERROR = ?, FINISHED_AT = ?, \
             DURATION_MS = ? WHERE ID = ?"
        );
        let r = sqlx::query(&sql)
            .bind(status.name())
            .bind(tasks_to_json(tasks))
            .bind(task_count)
            .bind(failed)
            .bind(error)
            .bind(finished_at)
            .bind(duration)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(r.rows_affected() > 0)
    }

    async fn read(&self, id: u64) -> Result<Option<EventRun>, CoreError> {
        let row = sqlx::query(&format!("SELECT {COLUMNS} FROM {TABLE} WHERE ID = ?"))
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_error)?;
        row.as_ref().map(Self::to_run).transpose().map_err(db_error)
    }

    async fn read_page(&self, filter: &RunFilter, pageable: &Pageable) -> Result<RunPage, CoreError> {
        if filter.client_codes.is_empty() {
            return Ok(RunPage::empty(pageable));
        }
        for t in [filter.from, filter.to].into_iter().flatten() {
            mysql_datetime(t)?;
        }
        let mut count = QueryBuilder::<MySql>::new(format!("SELECT COUNT(*) FROM {TABLE}"));
        Self::push_where(&mut count, filter);
        let mut rows = QueryBuilder::<MySql>::new(format!("SELECT {COLUMNS} FROM {TABLE}"));
        Self::push_where(&mut rows, filter);
        rows.push(" ORDER BY STARTED_AT DESC, ID DESC LIMIT ")
            .push_bind(pageable.size)
            .push(" OFFSET ")
            .push_bind(pageable.offset());
        let (total, found) = futures::try_join!(
            async { count.build_query_scalar::<i64>().fetch_one(&self.pool).await },
            async { rows.build().fetch_all(&self.pool).await },
        )
        .map_err(db_error)?;
        let content = found.iter().map(Self::to_run).collect::<Result<Vec<_>, _>>().map_err(db_error)?;
        Ok(RunPage { content, pageable: pageable.clone(), total })
    }

    async fn distinct_clients(&self, app_code: &str, event_name: Option<&str>, limit: usize) -> Result<Vec<String>, CoreError> {
        let mut qb = QueryBuilder::<MySql>::new(format!("SELECT DISTINCT CLIENT_CODE FROM {TABLE} WHERE APP_CODE = "));
        qb.push_bind(app_code.to_string());
        if let Some(e) = event_name.filter(|e| !java_blank(e)) {
            qb.push(" AND EVENT_NAME = ").push_bind(e.to_string());
        }
        qb.push(" LIMIT ").push_bind(limit as i64);
        let found: Vec<String> = qb.build_query_scalar().fetch_all(&self.pool).await.map_err(db_error)?;
        Ok(found.into_iter().map(|c| java_trim(&c).to_string()).collect())
    }

    async fn latest_per_client(&self, app_code: &str, event_name: &str, client_codes: &[String]) -> Result<Vec<EventRun>, CoreError> {
        let sql = format!(
            "SELECT {COLUMNS} FROM {TABLE} WHERE CLIENT_CODE = ? AND APP_CODE = ? AND EVENT_NAME = ? \
             ORDER BY STARTED_AT DESC, ID DESC LIMIT 1"
        );
        let found: Vec<Option<EventRun>> = futures::stream::iter(client_codes.iter().cloned())
            .map(|client| {
                let sql = sql.clone();
                async move {
                    let row = sqlx::query(&sql)
                        .bind(client)
                        .bind(app_code)
                        .bind(event_name)
                        .fetch_optional(&self.pool)
                        .await
                        .map_err(db_error)?;
                    row.as_ref().map(Self::to_run).transpose().map_err(db_error)
                }
            })
            .buffered(8)
            .try_collect()
            .await?;
        Ok(found.into_iter().flatten().collect())
    }

    async fn delete_started_before(&self, before: NaiveDateTime, status: Option<RunStatus>, limit: i64) -> Result<i64, CoreError> {
        let mut qb = QueryBuilder::<MySql>::new(format!("DELETE FROM {TABLE} WHERE "));
        if let Some(s) = status {
            qb.push("STATUS = ").push_bind(s.name()).push(" AND ");
        }
        qb.push("STARTED_AT < ").push_bind(before).push(" LIMIT ").push_bind(limit);
        let r = qb.build().execute(&self.pool).await.map_err(db_error)?;
        Ok(r.rows_affected() as i64)
    }

    async fn fail_running_started_before(&self, before: NaiveDateTime, error: &str, now: NaiveDateTime) -> Result<i64, CoreError> {
        let sql = format!(
            "UPDATE {TABLE} SET STATUS = 'FAILED', ERROR = ?, FINISHED_AT = ? WHERE STATUS = 'RUNNING' AND STARTED_AT < ?"
        );
        let r = sqlx::query(&sql).bind(error).bind(now).bind(before).execute(&self.pool).await.map_err(db_error)?;
        Ok(r.rows_affected() as i64)
    }
}

/// The table in memory, with the MySQL DAO's semantics (rows in id order; a limited delete
/// takes the oldest first, as the index walk does).
#[derive(Default)]
pub struct MemoryEventRunDao {
    rows: Mutex<Vec<EventRun>>,
    next_id: AtomicU64,
    /// Every write fails with this, while set.
    pub fail: Mutex<Option<CoreError>>,
}

impl MemoryEventRunDao {
    pub fn rows(&self) -> Vec<EventRun> {
        self.rows.lock().clone()
    }

    fn check(&self) -> Result<(), CoreError> {
        match self.fail.lock().clone() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn matches(r: &EventRun, f: &RunFilter) -> bool {
        r.client_code.as_ref().is_some_and(|c| f.client_codes.contains(c))
            && r.app_code.as_deref() == Some(f.app_code.as_str())
            && f.event_name.as_ref().filter(|e| !java_blank(e)).is_none_or(|e| r.event_name.as_ref() == Some(e))
            && f.status.is_none_or(|s| r.status == Some(s))
            && f.trigger_type.is_none_or(|t| r.trigger_type == Some(t))
            && f.from.is_none_or(|from| r.started_at.is_some_and(|s| s >= from))
            && f.to.is_none_or(|to| r.started_at.is_some_and(|s| s < to))
    }

    fn newest_first(runs: &mut [EventRun]) {
        runs.sort_by(|a, b| b.started_at.cmp(&a.started_at).then(b.id.cmp(&a.id)));
    }
}

#[async_trait]
impl EventRunDao for MemoryEventRunDao {
    async fn insert(&self, run: &EventRun) -> Result<u64, CoreError> {
        self.check()?;
        for required in [&run.app_code, &run.client_code, &run.event_name] {
            if required.is_none() {
                return Err(CoreError::unknown("Column cannot be null"));
            }
        }
        if run.trigger_type.is_none() || run.status.is_none() || run.started_at.is_none() {
            return Err(CoreError::unknown("Column cannot be null"));
        }
        let id = self.next_id.fetch_add(1, Ordering::SeqCst) + 1;
        let mut row = run.clone();
        row.id = Some(id);
        row.is_draft = Some(run.is_draft == Some(true));
        row.task_count = Some(non_negative(run.task_count));
        row.failed_task_count = Some(non_negative(run.failed_task_count));
        row.tasks = Some(run.tasks.clone().unwrap_or_default());
        row.duration_ms = run.duration_ms.map(|d| d.max(0));
        self.rows.lock().push(row);
        Ok(id)
    }

    async fn finish(
        &self,
        id: u64,
        status: RunStatus,
        tasks: &[EventRunTask],
        failed_tasks: i32,
        error: Option<&str>,
        finished_at: NaiveDateTime,
        duration_ms: i64,
    ) -> Result<bool, CoreError> {
        self.check()?;
        let mut rows = self.rows.lock();
        let Some(r) = rows.iter_mut().find(|r| r.id == Some(id)) else { return Ok(false) };
        r.status = Some(status);
        r.tasks = Some(tasks.to_vec());
        r.task_count = Some(tasks.len() as i32);
        r.failed_task_count = Some(non_negative(Some(failed_tasks)));
        r.error = error.map(str::to_string);
        r.finished_at = Some(finished_at);
        r.duration_ms = Some(duration_ms.max(0));
        Ok(true)
    }

    async fn read(&self, id: u64) -> Result<Option<EventRun>, CoreError> {
        Ok(self.rows.lock().iter().find(|r| r.id == Some(id)).cloned())
    }

    async fn read_page(&self, filter: &RunFilter, pageable: &Pageable) -> Result<RunPage, CoreError> {
        if filter.client_codes.is_empty() {
            return Ok(RunPage::empty(pageable));
        }
        let mut found: Vec<EventRun> = self.rows.lock().iter().filter(|r| Self::matches(r, filter)).cloned().collect();
        Self::newest_first(&mut found);
        let total = found.len() as i64;
        let content = found.into_iter().skip(pageable.offset().max(0) as usize).take(pageable.size.max(0) as usize).collect();
        Ok(RunPage { content, pageable: pageable.clone(), total })
    }

    async fn distinct_clients(&self, app_code: &str, event_name: Option<&str>, limit: usize) -> Result<Vec<String>, CoreError> {
        let mut out: Vec<String> = Vec::new();
        for r in self.rows.lock().iter() {
            let event_ok = event_name.filter(|e| !java_blank(e)).is_none_or(|e| r.event_name.as_deref() == Some(e));
            if r.app_code.as_deref() == Some(app_code) && event_ok {
                if let Some(c) = &r.client_code {
                    if !out.contains(c) && out.len() < limit {
                        out.push(c.clone());
                    }
                }
            }
        }
        Ok(out)
    }

    async fn latest_per_client(&self, app_code: &str, event_name: &str, client_codes: &[String]) -> Result<Vec<EventRun>, CoreError> {
        let rows = self.rows.lock();
        let mut out = Vec::new();
        for client in client_codes {
            let mut mine: Vec<EventRun> = rows
                .iter()
                .filter(|r| {
                    r.client_code.as_ref() == Some(client)
                        && r.app_code.as_deref() == Some(app_code)
                        && r.event_name.as_deref() == Some(event_name)
                })
                .cloned()
                .collect();
            Self::newest_first(&mut mine);
            out.extend(mine.into_iter().next());
        }
        Ok(out)
    }

    async fn delete_started_before(&self, before: NaiveDateTime, status: Option<RunStatus>, limit: i64) -> Result<i64, CoreError> {
        self.check()?;
        let mut rows = self.rows.lock();
        let mut doomed: Vec<(Option<NaiveDateTime>, Option<u64>)> = rows
            .iter()
            .filter(|r| r.started_at.is_some_and(|s| s < before) && status.is_none_or(|st| r.status == Some(st)))
            .map(|r| (r.started_at, r.id))
            .collect();
        doomed.sort();
        doomed.truncate(limit.max(0) as usize);
        let ids: HashSet<Option<u64>> = doomed.into_iter().map(|(_, id)| id).collect();
        rows.retain(|r| !ids.contains(&r.id));
        Ok(ids.len() as i64)
    }

    async fn fail_running_started_before(&self, before: NaiveDateTime, error: &str, now: NaiveDateTime) -> Result<i64, CoreError> {
        self.check()?;
        let mut n = 0;
        for r in self.rows.lock().iter_mut() {
            if r.status == Some(RunStatus::Running) && r.started_at.is_some_and(|s| s < before) {
                r.status = Some(RunStatus::Failed);
                r.error = Some(error.to_string());
                r.finished_at = Some(now);
                n += 1;
            }
        }
        Ok(n)
    }
}

// ------------------------------------------------------------------ what the service asks of others

/// `EventDefinitionService.readEffective`.
#[async_trait]
pub trait EventDefinitions: Send + Sync {
    async fn read_effective(&self, name: &str, app_code: &str, client_code: &str) -> Result<Option<JMap>, CoreError>;
}

#[async_trait]
impl EventDefinitions for crate::scheduler::EventDefinitionService {
    async fn read_effective(&self, name: &str, app_code: &str, client_code: &str) -> Result<Option<JMap>, CoreError> {
        crate::scheduler::EventDefinitionService::read_effective(self, name, app_code, client_code).await
    }
}

/// The three `IFeignSecurityService` calls the read rules use; `None` is security's empty
/// answer.
#[async_trait]
pub trait RunAccess: Send + Sync {
    async fn has_read_access(&self, app_code: &str, client_code: &str) -> Result<Option<bool>, CoreError>;
    async fn filter_managed_client_codes(&self, managing_client_code: &str, client_codes: &[String]) -> Result<Option<Vec<String>>, CoreError>;
    async fn does_client_manage_client_code(&self, managing_client_code: &str, client_code: &str) -> Result<Option<bool>, CoreError>;
}

#[async_trait]
impl RunAccess for SecurityCalls {
    async fn has_read_access(&self, app_code: &str, client_code: &str) -> Result<Option<bool>, CoreError> {
        SecurityCalls::has_read_access(self, app_code, client_code).await
    }

    async fn filter_managed_client_codes(&self, managing_client_code: &str, client_codes: &[String]) -> Result<Option<Vec<String>>, CoreError> {
        SecurityCalls::filter_managed_client_codes(self, managing_client_code, client_codes).await
    }

    async fn does_client_manage_client_code(&self, managing_client_code: &str, client_code: &str) -> Result<Option<bool>, CoreError> {
        SecurityCalls::does_client_manage_client_code(self, managing_client_code, client_code).await
    }
}

// ------------------------------------------------------------------ the service

/// `readPage`'s arguments.
#[derive(Debug, Clone, PartialEq)]
pub struct ReadPageRequest {
    pub app_code: String,
    /// The caller's own client when blank.
    pub client_code: Option<String>,
    /// Every client the caller may read that has a run of this event.
    pub all_clients: bool,
    pub event_name: Option<String>,
    pub status: Option<RunStatus>,
    pub trigger_type: Option<TriggerType>,
    pub from: Option<NaiveDateTime>,
    pub to: Option<NaiveDateTime>,
    pub pageable: Pageable,
    /// Display text for each run in this zone, when given.
    pub zone: Option<String>,
}

/// What the retention sweep did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Cleanup {
    /// All rows deleted.
    pub runs_removed: i64,
    /// Of those, the ones the shorter success retention took.
    pub successes_removed: i64,
    /// RUNNING rows closed as FAILED.
    pub stale_closed: i64,
}

impl Cleanup {
    /// `Map.of("runsRemoved", ..., "successesRemoved", ..., "staleClosed", ...)` as Jackson
    /// writes it.
    pub fn to_jackson_text(&self) -> String {
        let mut m = JMap::new();
        m.insert("runsRemoved".into(), JValue::Int(self.runs_removed));
        m.insert("successesRemoved".into(), JValue::Int(self.successes_removed));
        m.insert("staleClosed".into(), JValue::Int(self.stale_closed));
        overridable::json::to_jackson_pretty(&JValue::Object(m))
    }
}

/// `EventRunService`.
pub struct EventRunService {
    dao: Arc<dyn EventRunDao>,
    definitions: Arc<dyn EventDefinitions>,
    security: Arc<dyn RunAccess>,
    instance_id: String,
    enabled: bool,
    /// Per app|client|event: (start of the current window, occurrences not written in it).
    no_action_windows: Mutex<HashMap<String, (i64, i64)>>,
}

impl EventRunService {
    /// `enabled` is `core.eventRuns.enabled`; the instance is `HOSTNAME` (`core` without one).
    pub fn new(dao: Arc<dyn EventRunDao>, definitions: Arc<dyn EventDefinitions>, security: Arc<dyn RunAccess>, enabled: bool) -> Self {
        let host = std::env::var("HOSTNAME").ok().filter(|h| !java_blank(h));
        Self {
            dao,
            definitions,
            security,
            instance_id: host.unwrap_or_else(|| "core".into()),
            enabled,
            no_action_windows: Mutex::new(HashMap::new()),
        }
    }

    pub fn dao(&self) -> &Arc<dyn EventRunDao> {
        &self.dao
    }

    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    // -------------------------------------------------------------- writing

    /// Opens a RUNNING row for an event about to run its action; `None` when it could not be
    /// written (or the log is off).
    pub async fn start(&self, qob: &EventMessage, task_count: usize) -> Option<u64> {
        if !self.enabled {
            return None;
        }
        let mut run = describe(qob);
        run.status = Some(RunStatus::Running);
        run.task_count = Some(i32::try_from(task_count).unwrap_or(i32::MAX));
        run.instance_id = Some(self.instance_id.clone());
        run.started_at = Some(now());
        match self.dao.insert(&run).await {
            Ok(id) => Some(id),
            Err(e) => {
                tracing::warn!(
                    app = qob.app_code.as_deref().unwrap_or(""),
                    event = qob.event_name.as_deref().unwrap_or(""),
                    client = qob.client_code.as_deref().unwrap_or(""),
                    error = %e.text(),
                    "could not open the run log row"
                );
                None
            }
        }
    }

    /// Closes the row [`start`](Self::start) opened with the run's outcome. With no error and
    /// failed tasks, the error is "1 task failed" / "<n> tasks failed".
    pub async fn finish(&self, id: Option<u64>, started_at_millis: i64, success: bool, tasks: Vec<EventRunTask>, error: Option<String>) {
        let Some(id) = id else { return };
        let failed = tasks.iter().filter(|t| t.status == Some(TaskStatus::Failed)).count() as i32;
        let error = error.or_else(|| match failed {
            0 => None,
            1 => Some("1 task failed".to_string()),
            n => Some(format!("{n} tasks failed")),
        });
        let status = if success { RunStatus::Success } else { RunStatus::Failed };
        let duration = crate::scheduler::now_millis() - started_at_millis;
        let error = error.map(truncate_error);
        if let Err(e) = self.dao.finish(id, status, &tasks, failed, error.as_deref(), now(), duration).await {
            tracing::warn!(id, error = %e.text(), "could not close the run log row");
        }
    }

    /// Records an outcome that never ran an action (SKIPPED, a raise that FAILED, a
    /// NO_ACTION): one complete row.
    pub async fn record(&self, qob: &EventMessage, status: RunStatus, error: Option<&str>) {
        if !self.enabled {
            return;
        }
        let now = now();
        let mut run = describe(qob);
        run.status = Some(status);
        run.error = error.map(|e| truncate_error(e.to_string()));
        run.instance_id = Some(self.instance_id.clone());
        run.started_at = Some(now);
        run.finished_at = Some(now);
        run.duration_ms = Some(0);
        if let Err(e) = self.dao.insert(&run).await {
            tracing::warn!(
                status = status.name(),
                app = qob.app_code.as_deref().unwrap_or(""),
                event = qob.event_name.as_deref().unwrap_or(""),
                client = qob.client_code.as_deref().unwrap_or(""),
                error = %e.text(),
                "could not record the run"
            );
        }
    }

    /// An event arrived with no EventAction of its name. Recorded only when someone evidently
    /// meant it to run: it was scheduled, it is a hand-off, or the app defines it. Written once
    /// per app, client and event an hour (see [`NO_ACTION_WINDOW_MS`]).
    pub async fn record_no_action(&self, qob: &EventMessage) {
        self.record_no_action_at(qob, crate::scheduler::now_millis()).await
    }

    /// [`record_no_action`](Self::record_no_action) at `now` (epoch milliseconds).
    pub async fn record_no_action_at(&self, qob: &EventMessage, now: i64) {
        if !self.enabled {
            return;
        }
        let error = format!(
            "No Event action named '{}' exists for this app and client, so nothing ran. Create one with this exact name.",
            qob.event_name.as_deref().unwrap_or("null")
        );
        if qob.event_name.as_deref().is_some_and(|n| HANDOFF_EVENTS.contains(&n)) {
            return self.record(qob, RunStatus::NoAction, Some(&error)).await;
        }
        if schedule_marker(qob).is_some() {
            return self.record_throttled(qob, &error, now).await;
        }
        let defined = self
            .definitions
            .read_effective(
                qob.event_name.as_deref().unwrap_or(""),
                qob.app_code.as_deref().unwrap_or(""),
                qob.client_code.as_deref().unwrap_or(""),
            )
            .await;
        if let Ok(Some(_)) = defined {
            self.record_throttled(qob, &error, now).await;
        }
    }

    async fn record_throttled(&self, qob: &EventMessage, error: &str, now: i64) {
        let key = format!(
            "{}|{}|{}",
            qob.app_code.as_deref().unwrap_or("null"),
            qob.client_code.as_deref().unwrap_or("null"),
            qob.event_name.as_deref().unwrap_or("null")
        );
        // -1 when this occurrence is suppressed, else how many the window before it suppressed.
        let outcome = {
            let mut windows = self.no_action_windows.lock();
            if windows.len() >= MAX_NO_ACTION_KEYS && !windows.contains_key(&key) {
                windows.clear();
            }
            match windows.get_mut(&key) {
                Some(w) if now - w.0 < NO_ACTION_WINDOW_MS => {
                    w.1 += 1;
                    -1
                }
                Some(w) => {
                    let before = w.1;
                    *w = (now, 0);
                    before
                }
                None => {
                    windows.insert(key, (now, 0));
                    0
                }
            }
        };
        if outcome < 0 {
            return;
        }
        let mut text = format!("{error} Recorded once an hour; later occurrences in the hour are counted, not listed.");
        if outcome > 0 {
            text.push_str(&format!(
                " It also happened {outcome}{} in the hour before this.",
                if outcome == 1 { " more time" } else { " more times" }
            ));
        }
        self.record(qob, RunStatus::NoAction, Some(&text)).await
    }

    // -------------------------------------------------------------- reading

    /// Runs of the app, newest first: for `client_code` (the caller's own client when blank), or
    /// with `all_clients` for every client the caller may read that has a run of this event.
    pub async fn read_page(&self, ca: &Authentication, q: &ReadPageRequest) -> Result<RunPage, CoreError> {
        pre_authorize(ca)?;
        let clients = if q.all_clients {
            require_app(&q.app_code)?;
            let candidates = self.dao.distinct_clients(&q.app_code, q.event_name.as_deref(), MAX_CANDIDATE_CLIENTS).await?;
            self.visible_among(own_client(ca), &q.app_code, &candidates, true).await?
        } else {
            vec![self.allowed_client(ca, &q.app_code, q.client_code.as_deref()).await?]
        };
        let filter = RunFilter {
            app_code: q.app_code.clone(),
            client_codes: clients,
            event_name: q.event_name.clone(),
            status: q.status,
            trigger_type: q.trigger_type,
            from: q.from,
            to: q.to,
        };
        let mut page = self.dao.read_page(&filter, &q.pageable).await?;
        if let Some(zone) = q.zone.as_deref().filter(|z| !java_blank(z)) {
            for r in &mut page.content {
                decorate(r, Some(zone));
            }
        }
        Ok(page)
    }

    /// One run, when it is the caller's own client's or one it may read.
    pub async fn read(&self, ca: &Authentication, id: u64) -> Result<EventRun, CoreError> {
        pre_authorize(ca)?;
        let Some(run) = self.dao.read(id).await? else {
            return Err(CoreError::msg(StatusCode::NOT_FOUND, messages::OBJECT_NOT_FOUND, &["Event run", &id.to_string()]));
        };
        self.allowed_client(ca, run.app_code.as_deref().unwrap_or(""), run.client_code.as_deref()).await?;
        Ok(run)
    }

    /// Of `candidates`, the clients `own` may read for the app: its own, and those it manages
    /// when its own client may read the app (one batch call to security). With `include_own`
    /// the caller's client is in the answer even when it is not a candidate.
    pub async fn visible_among(&self, own: &str, app_code: &str, candidates: &[String], include_own: bool) -> Result<Vec<String>, CoreError> {
        let mut seen = HashSet::new();
        let others: Vec<String> = candidates.iter().filter(|c| c.as_str() != own && seen.insert(c.as_str())).cloned().collect();
        let own_in = include_own || candidates.iter().any(|c| c == own);
        let managed = if others.is_empty() {
            Vec::new()
        } else {
            match self.security.has_read_access(app_code, own).await? {
                Some(true) => self.security.filter_managed_client_codes(own, &others).await?.unwrap_or_default(),
                _ => Vec::new(),
            }
        };
        let mut out = Vec::new();
        if own_in {
            out.push(own.to_string());
        }
        out.extend(managed.into_iter().filter(|c| c != own));
        Ok(out)
    }

    /// The newest run of this event per client, keyed by client code. No access check: callers
    /// do their own. A failure reads as no runs (logged).
    pub async fn latest_runs(&self, app_code: &str, event_name: &str, client_codes: &[String]) -> HashMap<String, EventRun> {
        if client_codes.is_empty() {
            return HashMap::new();
        }
        match self.dao.latest_per_client(app_code, event_name, client_codes).await {
            Ok(runs) => runs.into_iter().filter_map(|r| r.client_code.clone().map(|c| (c, r))).collect(),
            Err(e) => {
                tracing::warn!(app = app_code, event = event_name, error = %e.text(), "could not read the latest runs");
                HashMap::new()
            }
        }
    }

    /// The client whose runs the caller may read: its own, or one it manages when its own
    /// client may read the app. Anything else is a 403, never an empty page.
    async fn allowed_client(&self, ca: &Authentication, app_code: &str, client_code: Option<&str>) -> Result<String, CoreError> {
        require_app(app_code)?;
        let own = own_client(ca);
        let client = match client_code.filter(|c| !java_blank(c)) {
            Some(c) => java_trim(c).to_string(),
            None => own.to_string(),
        };
        if client == own {
            return Ok(client);
        }
        let allowed = match self.security.does_client_manage_client_code(own, &client).await? {
            Some(true) => self.security.has_read_access(app_code, own).await? == Some(true),
            _ => false,
        };
        if allowed {
            Ok(client)
        } else {
            Err(CoreError::msg(StatusCode::FORBIDDEN, run_messages::FORBIDDEN_CLIENT_CODE, &[&client]))
        }
    }

    // -------------------------------------------------------------- cleanup

    /// Closes RUNNING rows with no outcome after `stale_after_hours` as FAILED, deletes SUCCESS
    /// rows started more than `success_retention_days` ago, then every row started more than
    /// `retention_days` ago: at most `limit` rows in all, in batches of 5000. Held to the floors
    /// and the cap whatever is asked.
    pub async fn cleanup_older_than(&self, retention_days: i32, success_retention_days: i32, stale_after_hours: i32, limit: i32)
        -> Result<Cleanup, CoreError> {
        let days = i64::from(retention_days).max(MIN_RETENTION_DAYS);
        let success_days = i64::from(success_retention_days).clamp(MIN_SUCCESS_RETENTION_DAYS, days);
        let stale = i64::from(stale_after_hours).max(MIN_STALE_HOURS);
        let cap = i64::from(limit).clamp(1, MAX_CLEANUP_LIMIT);
        let now = now();

        let ago = |d: Option<TimeDelta>| d.and_then(|d| now.checked_sub_signed(d));
        let stale_closed = match ago(TimeDelta::try_hours(stale)) {
            Some(before) => match self.dao.fail_running_started_before(before, run_messages::STALE_RUN, now).await {
                Ok(n) => n,
                Err(e) => {
                    tracing::warn!(error = %e.text(), "event run log: could not close stale runs");
                    0
                }
            },
            None => 0,
        };
        let successes = self.delete_batches(ago(TimeDelta::try_days(success_days)), Some(RunStatus::Success), cap, 0).await?;
        let removed = self.delete_batches(ago(TimeDelta::try_days(days)), None, cap, successes).await?;
        Ok(Cleanup { runs_removed: removed, successes_removed: successes, stale_closed })
    }

    /// Deletes in batches until a batch comes back short or `cap` rows in all are gone. A time
    /// before the calendar can hold has nothing older than it.
    async fn delete_batches(&self, before: Option<NaiveDateTime>, status: Option<RunStatus>, cap: i64, mut deleted: i64) -> Result<i64, CoreError> {
        let Some(before) = before else { return Ok(deleted) };
        loop {
            let batch = DELETE_BATCH.min(cap - deleted);
            if batch <= 0 {
                return Ok(deleted);
            }
            let n = self.dao.delete_started_before(before, status, batch).await?;
            deleted += n;
            if n < batch {
                return Ok(deleted);
            }
        }
    }
}

fn own_client(ca: &Authentication) -> &str {
    ca.client_code().unwrap_or("")
}

/// `@PreAuthorize("hasAuthority('Authorities.EventAction_READ')")`.
fn pre_authorize(ca: &Authentication) -> Result<(), CoreError> {
    if ca.is_authenticated() && ca.ca.has_authority(EVENT_ACTION_READ) {
        Ok(())
    } else {
        let refusal = if ca.is_authenticated() { "COMMON.PERMISSION_REQUIRED" } else { "COMMON.SIGN_IN_REQUIRED" };
        Err(CoreError::coded(StatusCode::FORBIDDEN, refusal, run_messages::ACCESS_DENIED).param("permission", EVENT_ACTION_READ))
    }
}

fn require_app(app_code: &str) -> Result<(), CoreError> {
    if java_blank(app_code) {
        return Err(CoreError::msg(StatusCode::BAD_REQUEST, run_messages::APPLICATION_NAME_REQUIRED, &[]));
    }
    Ok(())
}

// ------------------------------------------------------------------ describing an event

/// The parts of a row that come from the event itself: its app, client and name, the draft
/// surface, who raised it (the authentication's `user.id`), and from its schedule marker the
/// trigger, the run or one-off id, the time it was due and the attempt.
pub fn describe(qob: &EventMessage) -> EventRun {
    let mut run = EventRun {
        app_code: qob.app_code.clone(),
        client_code: qob.client_code.clone(),
        event_name: qob.event_name.clone(),
        is_draft: Some(qob.draft),
        trigger_type: Some(TriggerType::Event),
        ..Default::default()
    };
    run.triggered_by = qob
        .authentication
        .as_ref()
        .and_then(|a| a.get("user"))
        .and_then(|u| u.get("id"))
        .and_then(crate::security_calls::id_value);
    let Some(marker) = schedule_marker(qob) else { return run };
    match marker.get("kind").and_then(Value::as_str) {
        Some("cron") => {
            run.trigger_type = Some(TriggerType::Schedule);
            run.schedule_run_id = marker.get("runId").and_then(string_of);
            run.scheduled_for = marker.get("tickAt").and_then(time_of);
        }
        Some("once") => {
            run.trigger_type = Some(TriggerType::OneOff);
            run.schedule_run_id = marker.get("id").and_then(string_of);
            run.scheduled_for = marker.get("runAt").and_then(time_of);
            run.attempt = marker.get("attempt").and_then(int_value);
        }
        _ => {}
    }
    run
}

/// The event's `_schedule` marker, when its data has one that is an object.
pub fn schedule_marker(qob: &EventMessage) -> Option<&Map<String, Value>> {
    qob.data.as_ref()?.get(SCHEDULE_DATA_KEY)?.as_object()
}

/// `o.toString()` of what Jackson read: the text, a number as Java prints it, a map or list in
/// Java's `toString` form; nothing for null.
fn string_of(v: &Value) -> Option<String> {
    fn java(v: &Value) -> String {
        match v {
            Value::Null => "null".into(),
            Value::String(s) => s.clone(),
            Value::Number(n) => crate::gson::number_to_java_string(n),
            Value::Bool(b) => b.to_string(),
            Value::Array(a) => format!("[{}]", a.iter().map(java).collect::<Vec<_>>().join(", ")),
            Value::Object(o) => format!("{{{}}}", o.iter().map(|(k, v)| format!("{k}={}", java(v))).collect::<Vec<_>>().join(", ")),
        }
    }
    (!v.is_null()).then(|| java(v))
}

/// `Number.intValue()`.
fn int_value(v: &Value) -> Option<i32> {
    let Value::Number(n) = v else { return None };
    Some(match n.as_i64() {
        Some(i) => i as i32,
        None => n.as_f64().map_or(0, |f| f as i32),
    })
}

/// `LocalDateTime.ofInstant(Instant.parse(o.toString()), UTC)`; nothing when it is not an
/// ISO instant.
fn time_of(v: &Value) -> Option<NaiveDateTime> {
    let s = string_of(v)?;
    if s.as_bytes().get(10) != Some(&b'T') {
        return None;
    }
    DateTime::parse_from_rfc3339(&s).ok().map(|t| t.naive_utc())
}

// ------------------------------------------------------------------ describing an error

/// What a user should read for a failed task: the error's message, the root cause's when that
/// says more, and the step it came out of (the innermost trace's first line). At most 4000.
///
/// A [`CoreError`]'s message is its text without the status, as `GenericException.getMessage`.
pub fn error_of(error: &(dyn std::error::Error + 'static), traces: &[StepTrace]) -> String {
    let mut msg = message_of(error);
    let root = root_of(error);
    if !std::ptr::addr_eq(root as *const dyn std::error::Error, error as *const dyn std::error::Error) {
        let root_text = message_of(root);
        if !msg.contains(&root_text) {
            msg = format!("{msg} (cause: {root_text})");
        }
    }
    if let Some(first) = traces.first() {
        msg = format!("{msg}, {}", first.location());
    }
    truncate_error(msg)
}

/// What whoever fixes it needs: the KIRun steps the error came out of with the arguments they
/// got (the three innermost in full, the callers by where they are), then the error and each
/// cause, one per line. At most 12000.
pub fn detail_of(error: &(dyn std::error::Error + 'static), traces: &[StepTrace]) -> String {
    let mut sb = String::new();
    if !traces.is_empty() {
        sb.push_str("KIRun steps, innermost first:\n");
        for (i, t) in traces.iter().enumerate() {
            let message = t.message();
            let mut lines = message.lines();
            sb.push_str("    ");
            sb.push_str(lines.next().unwrap_or(""));
            sb.push('\n');
            if i < MAX_DETAIL_STEPS_WITH_ARGUMENTS {
                for line in lines {
                    sb.push_str("        ");
                    sb.push_str(line);
                    sb.push('\n');
                }
            }
        }
        sb.push('\n');
    }
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(error);
    let mut depth = 0;
    while let Some(e) = cur {
        if depth >= MAX_DETAIL_CAUSES {
            break;
        }
        if depth > 0 {
            sb.push_str("Caused by: ");
        }
        let line = e.to_string();
        sb.push_str(if java_blank(&line) { "(no message)" } else { &line });
        sb.push('\n');
        cur = e.source();
        depth += 1;
    }
    truncate16(sb, MAX_DETAIL_LENGTH)
}

/// The message Java's `getMessage` would give; an error without one is named by its debug form.
fn message_of(e: &(dyn std::error::Error + 'static)) -> String {
    let m = match e.downcast_ref::<CoreError>() {
        Some(c) => c.text(),
        None => e.to_string(),
    };
    if java_blank(&m) {
        format!("{e:?}")
    } else {
        m
    }
}

fn root_of<'a>(e: &'a (dyn std::error::Error + 'static)) -> &'a (dyn std::error::Error + 'static) {
    let mut root = e;
    for _ in 0..100 {
        match root.source() {
            Some(s) => root = s,
            None => break,
        }
    }
    root
}

fn truncate_error(s: String) -> String {
    truncate16(s, MAX_ERROR_LENGTH)
}

// ------------------------------------------------------------------ display text

/// A zone as `ZoneId.of` reads one: a region (`Asia/Kolkata`), an offset (`+05:30`, `Z`), or
/// `UTC` / `GMT` / `UT` with or without an offset.
enum Zone {
    Region(chrono_tz::Tz),
    Offset(chrono::FixedOffset),
}

impl Zone {
    fn parse(zone: Option<&str>) -> Zone {
        let utc = Zone::Offset(chrono::FixedOffset::east_opt(0).expect("utc"));
        let z = match zone {
            Some(z) if !java_blank(z) => java_trim(z),
            _ => return utc,
        };
        if let Some(offset) = parse_offset(z) {
            return Zone::Offset(offset);
        }
        for prefix in ["UTC", "GMT", "UT"] {
            if let Some(rest) = z.strip_prefix(prefix) {
                if rest.is_empty() {
                    return utc;
                }
                if rest.starts_with(['+', '-']) {
                    return parse_offset(rest).map(Zone::Offset).unwrap_or(utc);
                }
            }
        }
        z.parse::<chrono_tz::Tz>().map(Zone::Region).unwrap_or(utc)
    }

    fn format(&self, t: NaiveDateTime) -> String {
        const RUN_TIME: &str = "%a %-d %b, %H:%M:%S";
        let utc = t.and_utc();
        match self {
            Zone::Region(tz) => utc.with_timezone(tz).format(RUN_TIME).to_string(),
            Zone::Offset(o) => utc.with_timezone(o).format(RUN_TIME).to_string(),
        }
    }
}

/// `ZoneOffset.of`: `Z`, `+h`, `+hh`, `+hh:mm`, `+hhmm`, `+hh:mm:ss`, `+hhmmss`.
fn parse_offset(s: &str) -> Option<chrono::FixedOffset> {
    if s == "Z" {
        return chrono::FixedOffset::east_opt(0);
    }
    let sign = match s.as_bytes().first()? {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let body = &s[1..];
    let digits: String = body.chars().filter(|c| *c != ':').collect();
    if !digits.chars().all(|c| c.is_ascii_digit()) || body.contains("::") {
        return None;
    }
    let colon_form = body.contains(':');
    let (h, m, sec) = match (digits.len(), colon_form) {
        (1 | 2, false) => (digits.parse::<i32>().ok()?, 0, 0),
        (4, _) => (digits[..2].parse().ok()?, digits[2..].parse().ok()?, 0),
        (6, _) => (digits[..2].parse().ok()?, digits[2..4].parse().ok()?, digits[4..].parse().ok()?),
        _ => return None,
    };
    if h > 18 || m > 59 || sec > 59 || (h == 18 && (m > 0 || sec > 0)) {
        return None;
    }
    chrono::FixedOffset::east_opt(sign * (h * 3600 + m * 60 + sec))
}

/// Fills a run's display text in `zone` (UTC when it cannot be read): its start and its due
/// time as `EEE d MMM, HH:mm:ss`, its duration and each task's.
pub fn decorate(r: &mut EventRun, zone: Option<&str>) {
    let z = Zone::parse(zone);
    if let Some(t) = r.started_at {
        r.started_text = Some(z.format(t));
    }
    if let Some(t) = r.scheduled_for {
        r.scheduled_for_text = Some(z.format(t));
    }
    if let Some(d) = r.duration_ms {
        r.duration_text = Some(duration(d));
    }
    if let Some(tasks) = &mut r.tasks {
        for t in tasks {
            t.duration_text = t.duration_ms.map(duration);
        }
    }
}

/// `120 ms`, `1.3 s` (`%.1f`, half up), `2 min 5 s`.
pub fn duration(ms: i64) -> String {
    if ms < 1000 {
        return format!("{ms} ms");
    }
    if ms < 60_000 {
        let tenths = (ms + 50) / 100;
        return format!("{}.{} s", tenths / 10, tenths % 10);
    }
    format!("{} min {} s", ms / 60_000, (ms % 60_000) / 1000)
}

/// `LocalDateTime.now(ZoneOffset.UTC)`.
pub fn now() -> NaiveDateTime {
    chrono::Utc::now().naive_utc()
}

#[cfg(test)]
#[path = "event_runs_tests.rs"]
mod tests;

#[cfg(test)]
mod datetime_tests {
    #[test]
    fn a_date_past_year_9999_is_refused_as_mysql_refuses_it() {
        let ok = chrono::DateTime::from_timestamp(1_792_060_000, 0).unwrap().naive_utc();
        assert_eq!(super::mysql_datetime(ok).unwrap(), ok);
        let far = chrono::DateTime::from_timestamp(1_792_060_000_000, 0).unwrap().naive_utc();
        assert_eq!(super::mysql_datetime(far).unwrap_err().text(), "Incorrect DATETIME value: '58758-02-14 04:26:40'");
    }
}
