//! Stored server side KIRun debug runs (`core_function_debug_runs`, `V11__Function Debug Runs.sql`).
//!
//! A function run with the `x-debug` header by a caller holding [`FUNCTION_UPDATE`] leaves one
//! row: the execution log the KIRun `DebugCollector` kept, in the shape kirun-js
//! `DebugCollector.getExecution()` returns, so the function editor's debug view can show it.
//!
//! - **One row per top level run.** A definition a step calls runs under the execution id
//!   `<parent>_<statement>` (see `repos::definition`), which the collector keeps as an execution
//!   of its own; those logs are put back under the step that called them, so a row holds the
//!   whole tree.
//! - **Writing never fails or slows the run.** The row is built and written on a spawned task;
//!   every error is logged and dropped.
//! - **Masked and capped.** Keys that name a secret read `****` at any depth of a step's
//!   arguments and result; each step's arguments and result are cut at [`STEP_CAP_BYTES`]
//!   (unless the debug id starts with `full-`), and the whole log at [`LOG_CAP_BYTES`].
//! - **Kept small.** The newest [`KEEP_PER_FUNCTION`] rows per client, app and function, none
//!   older than [`RETENTION_DAYS`]: both applied for the key written at every insert, and the
//!   age rule for every key by `POST /api/core/functions/debugRuns/internal/cleanupOlderThan`.
//! - **Reading is per client.** A caller holding [`FUNCTION_UPDATE`] reads its own client's
//!   runs and those of a client it manages.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::{Path, RawQuery, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeDelta};
use kirun::runtime::debug::debug_collector::DebugCollector;
use overridable::write::spring::{page_json, Pageable, Params, Sort};
use overridable::JValue;
use parking_lot::Mutex;
use serde_json::{json, Map, Value};
use sqlx::mysql::MySqlRow;
use sqlx::{MySql, QueryBuilder, Row};

use crate::auth::Authentication;
use crate::context;
use crate::data_routes::query_params;
use crate::error::{messages, CoreError};
use crate::event_runs::{now, RunAccess};
use crate::handlers::{finish, request_context};
use crate::state::AppState;

/// The authority that saves a Function definition: needed to have a run stored and to read one.
pub const FUNCTION_UPDATE: &str = "Authorities.Function_UPDATE";

/// Debug ids with this prefix keep every step whole (the log cap still applies).
pub const FULL_PREFIX: &str = "full-";
pub const STEP_CAP_BYTES: usize = 10 * 1024;
pub const LOG_CAP_BYTES: usize = 1024 * 1024;
pub const KEEP_PER_FUNCTION: i64 = 100;
pub const RETENTION_DAYS: i64 = 10;
pub const MAX_PAGE_SIZE: i64 = 200;
pub const MAX_CLEANUP_LIMIT: i64 = 200_000;
const DELETE_BATCH: i64 = 5000;
/// How deep nested definition calls are put back under their steps.
const MAX_NESTING: usize = 32;
const MAX_DEBUG_ID: usize = 128;

/// Key fragments (lower case, `-` and `_` ignored) whose values are masked.
const SECRET_KEYS: [&str; 9] =
    ["password", "passwd", "secret", "token", "apikey", "authorization", "accesskey", "privatekey", "clientsecret"];
pub const MASK: &str = "****";

// ------------------------------------------------------------------ the model

#[derive(Debug, Clone, Default, PartialEq)]
pub struct DebugRun {
    pub id: Option<u64>,
    pub debug_id: String,
    pub app_code: String,
    pub client_code: String,
    /// Empty for a function without a namespace.
    pub namespace: String,
    pub name: String,
    pub user_id: Option<u64>,
    pub user_name: Option<String>,
    pub draft: bool,
    pub errored: bool,
    pub step_count: i64,
    pub started_at: NaiveDateTime,
    pub finished_at: Option<NaiveDateTime>,
    pub duration_ms: Option<i64>,
    /// Only on a read of one run.
    pub log: Option<Value>,
    pub log_bytes: i64,
}

fn epoch_seconds(t: NaiveDateTime) -> i64 {
    t.and_utc().timestamp()
}

impl DebugRun {
    /// The row as the read routes answer it; times are epoch seconds (as event runs write them).
    pub fn to_json(&self, with_log: bool) -> Value {
        let mut m = Map::new();
        m.insert("id".into(), json!(self.id));
        m.insert("debugId".into(), json!(self.debug_id));
        m.insert("appCode".into(), json!(self.app_code));
        m.insert("clientCode".into(), json!(self.client_code));
        m.insert("namespace".into(), if self.namespace.is_empty() { Value::Null } else { json!(self.namespace) });
        m.insert("name".into(), json!(self.name));
        m.insert("userId".into(), json!(self.user_id));
        m.insert("userName".into(), json!(self.user_name));
        m.insert("draft".into(), json!(self.draft));
        m.insert("errored".into(), json!(self.errored));
        m.insert("stepCount".into(), json!(self.step_count));
        m.insert("startedAt".into(), json!(epoch_seconds(self.started_at)));
        m.insert("finishedAt".into(), json!(self.finished_at.map(epoch_seconds)));
        m.insert("durationMs".into(), json!(self.duration_ms));
        m.insert("logBytes".into(), json!(self.log_bytes));
        if with_log {
            m.insert("log".into(), self.log.clone().unwrap_or(Value::Null));
        }
        Value::Object(m)
    }
}

/// What the list and the day counts filter on.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DebugRunFilter {
    pub client_code: String,
    pub app_code: String,
    pub namespace: Option<String>,
    pub name: Option<String>,
    /// `STARTED_AT` in this UTC day.
    pub day: Option<NaiveDate>,
    pub debug_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DayCount {
    pub day: NaiveDate,
    pub runs: i64,
    pub errored: i64,
}

impl DayCount {
    pub fn to_json(&self) -> Value {
        json!({"day": self.day.format("%Y-%m-%d").to_string(), "runs": self.runs, "errored": self.errored})
    }
}

// ------------------------------------------------------------------ the log

fn is_secret_key(key: &str) -> bool {
    let k: String = key.chars().filter(|c| *c != '_' && *c != '-').flat_map(char::to_lowercase).collect();
    SECRET_KEYS.iter().any(|s| k.contains(s))
}

/// Every value under a key naming a secret becomes `****`, at any depth.
pub fn mask(v: &mut Value) {
    match v {
        Value::Object(m) => {
            for (k, val) in m.iter_mut() {
                if is_secret_key(k) {
                    *val = Value::String(MASK.into());
                } else {
                    mask(val);
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(mask),
        _ => {}
    }
}

fn cut(text: &str, max: usize) -> String {
    let mut end = max.min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}

/// A value over `max` bytes of JSON becomes its JSON text cut to `max`; whether it was cut.
fn cap_value(v: &mut Value, max: usize) -> bool {
    if matches!(v, Value::Null | Value::Bool(_) | Value::Number(_)) {
        return false;
    }
    let text = serde_json::to_string(v).unwrap_or_default();
    if text.len() <= max {
        return false;
    }
    *v = Value::String(cut(&text, max));
    true
}

/// Masks and (with `cap`) cuts the arguments and result of every entry of the tree; the
/// number of entries.
fn clean_entries(entries: &mut [Value], cap: Option<usize>) -> i64 {
    let mut n = 0;
    for e in entries.iter_mut() {
        n += 1;
        let Value::Object(m) = e else { continue };
        let mut truncated = false;
        for key in ["arguments", "result"] {
            if let Some(v) = m.get_mut(key) {
                mask(v);
                if let Some(c) = cap {
                    truncated |= cap_value(v, c);
                }
            }
        }
        if truncated {
            m.insert("truncated".into(), Value::Bool(true));
        }
        if let Some(Value::Array(children)) = m.get_mut("children") {
            n += clean_entries(children, cap);
        }
    }
    n
}

fn size_of(v: &Value) -> usize {
    serde_json::to_string(v).map(|s| s.len()).unwrap_or(0)
}

/// Keeps entries, in order and depth first, while they fit in `budget` bytes; the rest go.
fn prune(entries: &mut Vec<Value>, budget: &mut usize, dropped: &mut bool) {
    let mut keep = 0;
    for e in entries.iter_mut() {
        if *budget == 0 {
            break;
        }
        let own = match &*e {
            Value::Object(m) => {
                let mut shallow = m.clone();
                shallow.insert("children".into(), Value::Array(Vec::new()));
                size_of(&Value::Object(shallow))
            }
            other => size_of(other),
        };
        if own > *budget {
            *budget = 0;
            break;
        }
        *budget -= own;
        keep += 1;
        if let Value::Object(m) = e {
            if let Some(Value::Array(children)) = m.get_mut("children") {
                prune(children, budget, dropped);
            }
        }
    }
    if keep < entries.len() {
        entries.truncate(keep);
        *dropped = true;
    }
}

/// The log as it is stored: masked, each step capped (not for `full`), the whole within
/// [`LOG_CAP_BYTES`] (the definitions go first, then the steps from the end, and the log says
/// `truncated: true`). Answers the log, its step count (before any were dropped) and its size.
pub fn prepare_log(mut log: Value, full: bool) -> (Value, i64, usize) {
    let steps = match log.get_mut("logs") {
        Some(Value::Array(entries)) => clean_entries(entries, (!full).then_some(STEP_CAP_BYTES)),
        _ => 0,
    };
    let mut bytes = size_of(&log);
    if bytes > LOG_CAP_BYTES {
        if let Value::Object(m) = &mut log {
            m.remove("definitions");
            m.insert("truncated".into(), Value::Bool(true));
        }
        bytes = size_of(&log);
    }
    if bytes > LOG_CAP_BYTES {
        if let Value::Object(m) = &mut log {
            let mut entries = match m.remove("logs") {
                Some(Value::Array(a)) => a,
                _ => Vec::new(),
            };
            let head = size_of(&Value::Object(m.clone())) + 16;
            let mut budget = LOG_CAP_BYTES.saturating_sub(head);
            let mut dropped = false;
            prune(&mut entries, &mut budget, &mut dropped);
            m.insert("logs".into(), Value::Array(entries));
        }
        bytes = size_of(&log);
    }
    (log, steps, bytes)
}

fn execution_json(id: &str, collector: &DebugCollector, used: &mut HashSet<String>) -> Option<(Value, bool)> {
    let exec = collector.get_execution(id)?;
    used.insert(id.to_string());
    let mut logs = serde_json::to_value(&exec.logs).unwrap_or(Value::Array(Vec::new()));
    let mut errored = exec.errored;
    let mut definitions: Map<String, Value> = exec.definitions.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    if let Value::Array(entries) = &mut logs {
        graft(id, entries, collector, used, &mut errored, &mut definitions, 0);
    }
    let log = json!({
        "executionId": exec.execution_id,
        "startTime": exec.start_time,
        "endTime": exec.end_time,
        "errored": errored,
        "logs": logs,
        "definitions": definitions,
    });
    Some((log, errored))
}

/// Puts the log of each nested definition call (`<execution>_<statement>`) under the first
/// step of that statement.
fn graft(
    exec_id: &str,
    entries: &mut [Value],
    collector: &DebugCollector,
    used: &mut HashSet<String>,
    errored: &mut bool,
    definitions: &mut Map<String, Value>,
    depth: usize,
) {
    if depth > MAX_NESTING {
        return;
    }
    for e in entries.iter_mut() {
        let Value::Object(m) = e else { continue };
        if let Some(Value::Array(children)) = m.get_mut("children") {
            graft(exec_id, children, collector, used, errored, definitions, depth);
        }
        let Some(stmt) = m.get("statementName").and_then(Value::as_str) else { continue };
        let child_id = format!("{exec_id}_{stmt}");
        if used.contains(&child_id) {
            continue;
        }
        let Some(child) = collector.get_execution(&child_id) else { continue };
        used.insert(child_id.clone());
        *errored |= child.errored;
        for (k, v) in child.definitions.iter() {
            definitions.entry(k.clone()).or_insert_with(|| v.clone());
        }
        let mut nested = serde_json::to_value(&child.logs).unwrap_or(Value::Array(Vec::new()));
        if let Value::Array(nested_entries) = &mut nested {
            graft(&child_id, nested_entries, collector, used, errored, definitions, depth + 1);
        }
        if let (Value::Array(nested_entries), Some(Value::Array(children))) = (nested, m.get_mut("children")) {
            children.extend(nested_entries);
        }
    }
}

/// The top level execution's log with its nested definition calls under their steps, in the
/// shape of kirun-js `ExecutionLog` (definitions as an object); with whether any part errored.
pub fn collect_execution(execution_id: &str) -> Option<(Value, bool)> {
    let mut used = HashSet::new();
    execution_json(execution_id, DebugCollector::get_instance(), &mut used)
}

// ------------------------------------------------------------------ the DAO

#[async_trait]
pub trait DebugRunDao: Send + Sync {
    async fn insert(&self, run: &DebugRun) -> Result<u64, CoreError>;
    /// One row with its log.
    async fn read(&self, id: u64) -> Result<Option<DebugRun>, CoreError>;
    /// Newest first, without logs; the rows and the total.
    async fn read_page(&self, f: &DebugRunFilter, pageable: &Pageable) -> Result<(Vec<DebugRun>, i64), CoreError>;
    /// Runs per UTC day, newest day first (the filter's day and debug id are ignored).
    async fn days(&self, f: &DebugRunFilter) -> Result<Vec<DayCount>, CoreError>;
    /// For one client, app and function: deletes rows beyond the newest `keep` and rows started
    /// before `before`; how many went.
    async fn trim(&self, client: &str, app: &str, namespace: &str, name: &str, keep: i64, before: NaiveDateTime) -> Result<i64, CoreError>;
    /// Deletes up to `limit` rows started before `before`.
    async fn delete_started_before(&self, before: NaiveDateTime, limit: i64) -> Result<i64, CoreError>;
}

fn db_error(e: sqlx::Error) -> CoreError {
    CoreError::unknown(e.to_string())
}

const TABLE: &str = "core_function_debug_runs";
const LIST_COLUMNS: &str = "ID, DEBUG_ID, APP_CODE, CLIENT_CODE, FUNCTION_NAMESPACE, FUNCTION_NAME, USER_ID, USER_NAME, \
    IS_DRAFT, ERRORED, STEP_COUNT, STARTED_AT, FINISHED_AT, DURATION_MS, LOG_BYTES";

pub struct MySqlDebugRunDao {
    pool: sqlx::MySqlPool,
}

impl MySqlDebugRunDao {
    pub fn new(pool: sqlx::MySqlPool) -> Self {
        Self { pool }
    }

    fn to_run(row: &MySqlRow, with_log: bool) -> Result<DebugRun, sqlx::Error> {
        let text = |c: &str| -> Result<String, sqlx::Error> { Ok(row.try_get::<Option<String>, _>(c)?.unwrap_or_default().trim().to_string()) };
        let log = if with_log {
            row.try_get::<Option<String>, _>("LOG")?.and_then(|l| serde_json::from_str(&l).ok())
        } else {
            None
        };
        Ok(DebugRun {
            id: Some(row.try_get("ID")?),
            debug_id: text("DEBUG_ID")?,
            app_code: text("APP_CODE")?,
            client_code: text("CLIENT_CODE")?,
            namespace: text("FUNCTION_NAMESPACE")?,
            name: text("FUNCTION_NAME")?,
            user_id: row.try_get("USER_ID")?,
            user_name: row.try_get("USER_NAME")?,
            draft: row.try_get::<i8, _>("IS_DRAFT")? != 0,
            errored: row.try_get::<i8, _>("ERRORED")? != 0,
            step_count: i64::from(row.try_get::<u32, _>("STEP_COUNT")?),
            started_at: row.try_get("STARTED_AT")?,
            finished_at: row.try_get("FINISHED_AT")?,
            duration_ms: row.try_get::<Option<u32>, _>("DURATION_MS")?.map(i64::from),
            log,
            log_bytes: i64::from(row.try_get::<u32, _>("LOG_BYTES")?),
        })
    }

    fn push_where(qb: &mut QueryBuilder<'_, MySql>, f: &DebugRunFilter, with_day: bool) {
        qb.push(" WHERE CLIENT_CODE = ").push_bind(f.client_code.clone());
        qb.push(" AND APP_CODE = ").push_bind(f.app_code.clone());
        if let Some(ns) = &f.namespace {
            qb.push(" AND FUNCTION_NAMESPACE = ").push_bind(ns.clone());
        }
        if let Some(n) = &f.name {
            qb.push(" AND FUNCTION_NAME = ").push_bind(n.clone());
        }
        if with_day {
            if let Some((from, to)) = f.day.and_then(day_range) {
                qb.push(" AND STARTED_AT >= ").push_bind(from).push(" AND STARTED_AT < ").push_bind(to);
            }
            if let Some(d) = &f.debug_id {
                qb.push(" AND DEBUG_ID = ").push_bind(d.clone());
            }
        }
    }
}

fn day_range(d: NaiveDate) -> Option<(NaiveDateTime, NaiveDateTime)> {
    let from = d.and_hms_opt(0, 0, 0)?;
    Some((from, from.checked_add_signed(TimeDelta::days(1))?))
}

#[async_trait]
impl DebugRunDao for MySqlDebugRunDao {
    async fn insert(&self, run: &DebugRun) -> Result<u64, CoreError> {
        let log = run.log.as_ref().map(|l| serde_json::to_string(l).unwrap_or_default());
        let r = sqlx::query(&format!(
            "INSERT INTO {TABLE} (DEBUG_ID, APP_CODE, CLIENT_CODE, FUNCTION_NAMESPACE, FUNCTION_NAME, USER_ID, USER_NAME, IS_DRAFT, \
             ERRORED, STEP_COUNT, STARTED_AT, FINISHED_AT, DURATION_MS, LOG, LOG_BYTES) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        ))
        .bind(&run.debug_id)
        .bind(&run.app_code)
        .bind(&run.client_code)
        .bind(&run.namespace)
        .bind(&run.name)
        .bind(run.user_id)
        .bind(run.user_name.as_deref().map(|n| cut(n, 255)))
        .bind(i8::from(run.draft))
        .bind(i8::from(run.errored))
        .bind(u32::try_from(run.step_count.max(0)).unwrap_or(u32::MAX))
        .bind(run.started_at)
        .bind(run.finished_at)
        .bind(run.duration_ms.map(|d| u32::try_from(d.max(0)).unwrap_or(u32::MAX)))
        .bind(log)
        .bind(u32::try_from(run.log_bytes.max(0)).unwrap_or(u32::MAX))
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(r.last_insert_id())
    }

    async fn read(&self, id: u64) -> Result<Option<DebugRun>, CoreError> {
        let row = sqlx::query(&format!("SELECT {LIST_COLUMNS}, CAST(LOG AS CHAR) AS LOG FROM {TABLE} WHERE ID = ?"))
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_error)?;
        row.as_ref().map(|r| Self::to_run(r, true)).transpose().map_err(db_error)
    }

    async fn read_page(&self, f: &DebugRunFilter, pageable: &Pageable) -> Result<(Vec<DebugRun>, i64), CoreError> {
        let mut count = QueryBuilder::<MySql>::new(format!("SELECT COUNT(*) FROM {TABLE}"));
        Self::push_where(&mut count, f, true);
        let mut rows = QueryBuilder::<MySql>::new(format!("SELECT {LIST_COLUMNS} FROM {TABLE}"));
        Self::push_where(&mut rows, f, true);
        rows.push(" ORDER BY STARTED_AT DESC, ID DESC LIMIT ").push_bind(pageable.size).push(" OFFSET ").push_bind(pageable.offset());
        let (total, found) = futures::try_join!(
            async { count.build_query_scalar::<i64>().fetch_one(&self.pool).await },
            async { rows.build().fetch_all(&self.pool).await },
        )
        .map_err(db_error)?;
        let content = found.iter().map(|r| Self::to_run(r, false)).collect::<Result<Vec<_>, _>>().map_err(db_error)?;
        Ok((content, total))
    }

    async fn days(&self, f: &DebugRunFilter) -> Result<Vec<DayCount>, CoreError> {
        let mut qb = QueryBuilder::<MySql>::new(format!(
            "SELECT DATE(STARTED_AT) AS D, COUNT(*) AS N, CAST(COALESCE(SUM(ERRORED), 0) AS SIGNED) AS E FROM {TABLE}"
        ));
        Self::push_where(&mut qb, f, false);
        qb.push(" GROUP BY D ORDER BY D DESC");
        let rows = qb.build().fetch_all(&self.pool).await.map_err(db_error)?;
        rows.iter()
            .map(|r| Ok(DayCount { day: r.try_get("D")?, runs: r.try_get("N")?, errored: r.try_get("E")? }))
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(db_error)
    }

    async fn trim(&self, client: &str, app: &str, namespace: &str, name: &str, keep: i64, before: NaiveDateTime) -> Result<i64, CoreError> {
        const KEY: &str = "CLIENT_CODE = ? AND APP_CODE = ? AND FUNCTION_NAMESPACE = ? AND FUNCTION_NAME = ?";
        let mut removed = sqlx::query(&format!("DELETE FROM {TABLE} WHERE {KEY} AND STARTED_AT < ?"))
            .bind(client)
            .bind(app)
            .bind(namespace)
            .bind(name)
            .bind(before)
            .execute(&self.pool)
            .await
            .map_err(db_error)?
            .rows_affected() as i64;
        // The id of the oldest row kept; everything before it goes.
        let cutoff: Option<u64> = sqlx::query_scalar(&format!("SELECT ID FROM {TABLE} WHERE {KEY} ORDER BY ID DESC LIMIT 1 OFFSET ?"))
            .bind(client)
            .bind(app)
            .bind(namespace)
            .bind(name)
            .bind((keep - 1).max(0))
            .fetch_optional(&self.pool)
            .await
            .map_err(db_error)?;
        if let Some(cutoff) = cutoff {
            removed += sqlx::query(&format!("DELETE FROM {TABLE} WHERE {KEY} AND ID < ?"))
                .bind(client)
                .bind(app)
                .bind(namespace)
                .bind(name)
                .bind(cutoff)
                .execute(&self.pool)
                .await
                .map_err(db_error)?
                .rows_affected() as i64;
        }
        Ok(removed)
    }

    async fn delete_started_before(&self, before: NaiveDateTime, limit: i64) -> Result<i64, CoreError> {
        let r = sqlx::query(&format!("DELETE FROM {TABLE} WHERE STARTED_AT < ? LIMIT ?"))
            .bind(before)
            .bind(limit)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(r.rows_affected() as i64)
    }
}

/// The table in memory, with the MySQL DAO's semantics.
#[derive(Default)]
pub struct MemoryDebugRunDao {
    rows: Mutex<Vec<DebugRun>>,
    next_id: AtomicU64,
    /// Every write fails with this, while set.
    pub fail: Mutex<Option<CoreError>>,
}

impl MemoryDebugRunDao {
    pub fn rows(&self) -> Vec<DebugRun> {
        self.rows.lock().clone()
    }

    fn matches(r: &DebugRun, f: &DebugRunFilter, with_day: bool) -> bool {
        r.client_code == f.client_code
            && r.app_code == f.app_code
            && f.namespace.as_ref().is_none_or(|n| &r.namespace == n)
            && f.name.as_ref().is_none_or(|n| &r.name == n)
            && (!with_day || f.day.is_none_or(|d| r.started_at.date() == d))
            && (!with_day || f.debug_id.as_ref().is_none_or(|d| &r.debug_id == d))
    }
}

#[async_trait]
impl DebugRunDao for MemoryDebugRunDao {
    async fn insert(&self, run: &DebugRun) -> Result<u64, CoreError> {
        if let Some(e) = self.fail.lock().clone() {
            return Err(e);
        }
        let id = self.next_id.fetch_add(1, Ordering::SeqCst) + 1;
        let mut row = run.clone();
        row.id = Some(id);
        self.rows.lock().push(row);
        Ok(id)
    }

    async fn read(&self, id: u64) -> Result<Option<DebugRun>, CoreError> {
        Ok(self.rows.lock().iter().find(|r| r.id == Some(id)).cloned())
    }

    async fn read_page(&self, f: &DebugRunFilter, pageable: &Pageable) -> Result<(Vec<DebugRun>, i64), CoreError> {
        let mut found: Vec<DebugRun> = self.rows.lock().iter().filter(|r| Self::matches(r, f, true)).cloned().collect();
        found.sort_by(|a, b| b.started_at.cmp(&a.started_at).then(b.id.cmp(&a.id)));
        let total = found.len() as i64;
        let content = found
            .into_iter()
            .skip(pageable.offset().max(0) as usize)
            .take(pageable.size.max(0) as usize)
            .map(|mut r| {
                r.log = None;
                r
            })
            .collect();
        Ok((content, total))
    }

    async fn days(&self, f: &DebugRunFilter) -> Result<Vec<DayCount>, CoreError> {
        let mut out: Vec<DayCount> = Vec::new();
        for r in self.rows.lock().iter().filter(|r| Self::matches(r, f, false)) {
            let day = r.started_at.date();
            match out.iter_mut().find(|d| d.day == day) {
                Some(d) => {
                    d.runs += 1;
                    d.errored += i64::from(r.errored);
                }
                None => out.push(DayCount { day, runs: 1, errored: i64::from(r.errored) }),
            }
        }
        out.sort_by(|a, b| b.day.cmp(&a.day));
        Ok(out)
    }

    async fn trim(&self, client: &str, app: &str, namespace: &str, name: &str, keep: i64, before: NaiveDateTime) -> Result<i64, CoreError> {
        if let Some(e) = self.fail.lock().clone() {
            return Err(e);
        }
        let mut rows = self.rows.lock();
        let same = |r: &DebugRun| r.client_code == client && r.app_code == app && r.namespace == namespace && r.name == name;
        let mut ids: Vec<u64> = rows.iter().filter(|r| same(r) && r.started_at >= before).filter_map(|r| r.id).collect();
        ids.sort_unstable_by(|a, b| b.cmp(a));
        ids.truncate(keep.max(0) as usize);
        let kept: HashSet<u64> = ids.into_iter().collect();
        let before_len = rows.len();
        rows.retain(|r| !same(r) || r.id.is_some_and(|id| kept.contains(&id)));
        Ok((before_len - rows.len()) as i64)
    }

    async fn delete_started_before(&self, before: NaiveDateTime, limit: i64) -> Result<i64, CoreError> {
        let mut rows = self.rows.lock();
        let mut doomed: Vec<(NaiveDateTime, Option<u64>)> = rows.iter().filter(|r| r.started_at < before).map(|r| (r.started_at, r.id)).collect();
        doomed.sort();
        doomed.truncate(limit.max(0) as usize);
        let ids: HashSet<Option<u64>> = doomed.into_iter().map(|(_, id)| id).collect();
        rows.retain(|r| !ids.contains(&r.id));
        Ok(ids.len() as i64)
    }
}

// ------------------------------------------------------------------ the service

/// The caller's display name: first and last name, else the user name.
pub fn display_name(auth: &Authentication) -> Option<String> {
    let user = auth.raw.get("user");
    let part = |k: &str| user.and_then(|u| u.get(k)).and_then(Value::as_str).map(str::trim).unwrap_or("").to_string();
    let full = format!("{} {}", part("firstName"), part("lastName")).trim().to_string();
    if !full.is_empty() {
        return Some(full);
    }
    auth.ca.user.user_name.clone().filter(|n| !n.trim().is_empty())
}

/// What a finished run hands to [`FunctionDebugRunService::record`].
#[derive(Debug, Clone, PartialEq)]
pub struct RunInfo {
    pub execution_id: String,
    pub debug_id: String,
    pub app_code: String,
    pub client_code: String,
    pub namespace: String,
    pub name: String,
    pub user_id: Option<u64>,
    /// [`display_name`] of the caller.
    pub user_name: Option<String>,
    pub draft: bool,
    /// The run itself failed (a step's failure is in the log too).
    pub failed: bool,
}

pub struct FunctionDebugRunService {
    dao: Arc<dyn DebugRunDao>,
    security: Arc<dyn RunAccess>,
}

fn millis_to_time(ms: i64) -> Option<NaiveDateTime> {
    DateTime::from_timestamp_millis(ms).map(|t| t.naive_utc())
}

impl FunctionDebugRunService {
    pub fn new(dao: Arc<dyn DebugRunDao>, security: Arc<dyn RunAccess>) -> Self {
        Self { dao, security }
    }

    pub fn dao(&self) -> &Arc<dyn DebugRunDao> {
        &self.dao
    }

    /// Whether a run by this caller with this debug id is stored at all.
    pub fn wanted(auth: &Authentication, debug_id: Option<&str>) -> bool {
        debug_id.is_some_and(|d| !d.trim().is_empty()) && auth.is_authenticated() && auth.ca.has_authority(FUNCTION_UPDATE)
    }

    /// Stores the run on a task of its own: never fails nor waits.
    pub fn record(self: &Arc<Self>, info: RunInfo) {
        let me = self.clone();
        tokio::spawn(async move {
            let Some((log, errored)) = collect_execution(&info.execution_id) else {
                tracing::debug!(execution = info.execution_id, "debug run: the collector has no log for the run");
                return;
            };
            if let Err(e) = me.store(info.clone(), log, errored).await {
                tracing::warn!(function = %format!("{}.{}", info.namespace, info.name), error = %e.text(), "debug run: could not store the run");
            }
        });
    }

    /// Masks and caps `log`, inserts the row, then trims the function's rows to the newest
    /// [`KEEP_PER_FUNCTION`] within [`RETENTION_DAYS`].
    pub async fn store(&self, info: RunInfo, log: Value, errored: bool) -> Result<u64, CoreError> {
        let full = info.debug_id.starts_with(FULL_PREFIX);
        let start = log.get("startTime").and_then(Value::as_i64);
        let end = log.get("endTime").and_then(Value::as_i64);
        let (log, steps, bytes) = prepare_log(log, full);
        let started_at = start.and_then(millis_to_time).unwrap_or_else(now);
        let finished_at = end.and_then(millis_to_time).unwrap_or_else(now);
        let run = DebugRun {
            id: None,
            debug_id: cut(&info.debug_id, MAX_DEBUG_ID),
            app_code: info.app_code,
            client_code: info.client_code,
            namespace: info.namespace,
            name: info.name,
            user_id: info.user_id,
            user_name: info.user_name,
            draft: info.draft,
            errored: errored || info.failed,
            step_count: steps,
            started_at,
            finished_at: Some(finished_at),
            duration_ms: Some((finished_at - started_at).num_milliseconds().max(0)),
            log: Some(log),
            log_bytes: bytes as i64,
        };
        let id = self.dao.insert(&run).await?;
        let before = now() - TimeDelta::days(RETENTION_DAYS);
        if let Err(e) = self.dao.trim(&run.client_code, &run.app_code, &run.namespace, &run.name, KEEP_PER_FUNCTION, before).await {
            tracing::warn!(error = %e.text(), "debug run: could not trim older runs");
        }
        Ok(id)
    }

    // -------------------------------------------------------------- reading

    fn pre_authorize(ca: &Authentication) -> Result<(), CoreError> {
        if ca.is_authenticated() && ca.ca.has_authority(FUNCTION_UPDATE) {
            Ok(())
        } else {
            let refusal = if ca.is_authenticated() { "COMMON.PERMISSION_REQUIRED" } else { "COMMON.SIGN_IN_REQUIRED" };
            Err(CoreError::coded(StatusCode::FORBIDDEN, refusal, "Access Denied").param("permission", FUNCTION_UPDATE))
        }
    }

    /// The caller's own client, or one it manages; anything else is a 403.
    async fn allowed_client(&self, ca: &Authentication, client_code: Option<&str>) -> Result<String, CoreError> {
        let own = ca.client_code().unwrap_or("");
        let client = match client_code.map(str::trim).filter(|c| !c.is_empty()) {
            Some(c) => c.to_string(),
            None => own.to_string(),
        };
        if client == own {
            return Ok(client);
        }
        match self.security.does_client_manage_client_code(own, &client).await? {
            Some(true) => Ok(client),
            _ => Err(CoreError::msg(StatusCode::FORBIDDEN, crate::event_runs::run_messages::FORBIDDEN_CLIENT_CODE, &[&client])),
        }
    }

    pub async fn read_page(&self, ca: &Authentication, mut f: DebugRunFilter, client_code: Option<&str>, pageable: &Pageable) -> Result<Value, CoreError> {
        Self::pre_authorize(ca)?;
        f.client_code = self.allowed_client(ca, client_code).await?;
        let (content, total) = self.dao.read_page(&f, pageable).await?;
        let content: Vec<JValue> = content.iter().map(|r| serde_json::from_value(r.to_json(false)).unwrap_or(JValue::Null)).collect();
        Ok(serde_json::to_value(page_json(content, pageable, total)).unwrap_or(Value::Null))
    }

    pub async fn days(&self, ca: &Authentication, mut f: DebugRunFilter, client_code: Option<&str>) -> Result<Vec<DayCount>, CoreError> {
        Self::pre_authorize(ca)?;
        f.client_code = self.allowed_client(ca, client_code).await?;
        self.dao.days(&f).await
    }

    pub async fn read(&self, ca: &Authentication, id: u64) -> Result<DebugRun, CoreError> {
        Self::pre_authorize(ca)?;
        let not_found = || CoreError::msg(StatusCode::NOT_FOUND, messages::OBJECT_NOT_FOUND, &["Function debug run", &id.to_string()]);
        let Some(run) = self.dao.read(id).await? else { return Err(not_found()) };
        self.allowed_client(ca, Some(&run.client_code)).await?;
        Ok(run)
    }

    /// Deletes rows older than `retention_days` (never fewer than [`RETENTION_DAYS`]), at most
    /// `limit`, in batches.
    pub async fn cleanup_older_than(&self, retention_days: i64, limit: i64) -> Result<i64, CoreError> {
        let days = retention_days.max(RETENTION_DAYS);
        let cap = limit.clamp(1, MAX_CLEANUP_LIMIT);
        let Some(before) = now().checked_sub_signed(TimeDelta::days(days)) else { return Ok(0) };
        let mut deleted = 0;
        loop {
            let batch = DELETE_BATCH.min(cap - deleted);
            if batch <= 0 {
                return Ok(deleted);
            }
            let n = self.dao.delete_started_before(before, batch).await?;
            deleted += n;
            if n < batch {
                return Ok(deleted);
            }
        }
    }
}

// ------------------------------------------------------------------ routes

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/core/functions/debugRuns", get(read_page_route))
        .route("/api/core/functions/debugRuns/days", get(days_route))
        .route("/api/core/functions/debugRuns/{id}", get(read_route))
        .route("/api/core/functions/debugRuns/internal/cleanupOlderThan", post(cleanup_route))
}

struct Query(Vec<(String, Option<String>)>);

impl Query {
    fn string(&self, name: &str) -> Option<String> {
        self.0.iter().find(|(k, _)| k == name).and_then(|(_, v)| v.clone()).map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
    }

    fn int(&self, name: &str, default: i64) -> Result<i64, CoreError> {
        match self.string(name) {
            None => Ok(default),
            Some(v) => v.parse().map_err(|_| crate::error::spring::type_mismatch(None, None, None)),
        }
    }
}

fn json_response(body: &Value) -> Response {
    let mut resp = (StatusCode::OK, serde_json::to_string(body).unwrap_or_default()).into_response();
    resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    resp
}

fn filter_of(q: &Query) -> Result<(DebugRunFilter, Option<String>), CoreError> {
    let app_code = q.string("appCode").ok_or_else(|| crate::error::spring::param_missing("appCode"))?;
    let day = match q.string("day") {
        None => None,
        Some(d) => Some(NaiveDate::parse_from_str(&d, "%Y-%m-%d").map_err(|_| crate::error::spring::type_mismatch(None, None, None))?),
    };
    let f = DebugRunFilter {
        client_code: String::new(),
        app_code,
        namespace: q.string("namespace"),
        name: q.string("name"),
        day,
        debug_id: q.string("debugId"),
    };
    Ok((f, q.string("clientCode")))
}

/// `GET /api/core/functions/debugRuns?appCode=&namespace=&name=&clientCode=&day=&debugId=&page=&size=`
async fn read_page_route(State(st): State<AppState>, RawQuery(raw): RawQuery, h: HeaderMap) -> Response {
    let r = async {
        let ctx = request_context(&st, &h).await?;
        if !ctx.auth.is_authenticated() {
            return Ok(crate::unmapped::unauthorized());
        }
        let q = Query(query_params(raw.as_deref()));
        let (f, client) = filter_of(&q)?;
        let p = Pageable::from_params(&Params::from_query(raw.as_deref()));
        let pageable = Pageable::of(p.page.max(0), p.size.clamp(1, MAX_PAGE_SIZE), Sort::unsorted());
        if !ctx.auth.ca.has_authority(FUNCTION_UPDATE) {
            return Ok(crate::unmapped::access_denied(&[FUNCTION_UPDATE]));
        }
        let service = st.inner().debug_runs.clone();
        let auth = ctx.auth.clone();
        let page = context::with_request(ctx, async move { service.read_page(&auth, f, client.as_deref(), &pageable).await }).await?;
        Ok(json_response(&page))
    }
    .await;
    finish(r, "/api/core/functions/debugRuns")
}

/// `GET /api/core/functions/debugRuns/days?appCode=&namespace=&name=&clientCode=`
async fn days_route(State(st): State<AppState>, RawQuery(raw): RawQuery, h: HeaderMap) -> Response {
    let r = async {
        let ctx = request_context(&st, &h).await?;
        if !ctx.auth.is_authenticated() {
            return Ok(crate::unmapped::unauthorized());
        }
        let q = Query(query_params(raw.as_deref()));
        let (f, client) = filter_of(&q)?;
        if !ctx.auth.ca.has_authority(FUNCTION_UPDATE) {
            return Ok(crate::unmapped::access_denied(&[FUNCTION_UPDATE]));
        }
        let service = st.inner().debug_runs.clone();
        let auth = ctx.auth.clone();
        let days = context::with_request(ctx, async move { service.days(&auth, f, client.as_deref()).await }).await?;
        Ok(json_response(&Value::Array(days.iter().map(DayCount::to_json).collect())))
    }
    .await;
    finish(r, "/api/core/functions/debugRuns/days")
}

/// `GET /api/core/functions/debugRuns/{id}`: the row with its `log`.
async fn read_route(State(st): State<AppState>, Path(id): Path<String>, h: HeaderMap) -> Response {
    let r = async {
        let ctx = request_context(&st, &h).await?;
        if !ctx.auth.is_authenticated() {
            return Ok(crate::unmapped::unauthorized());
        }
        let Ok(id) = id.trim().parse::<u64>() else {
            let mut resp = StatusCode::NOT_FOUND.into_response();
            resp.headers_mut().insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
            return Ok(resp);
        };
        if !ctx.auth.ca.has_authority(FUNCTION_UPDATE) {
            return Ok(crate::unmapped::access_denied(&[FUNCTION_UPDATE]));
        }
        let service = st.inner().debug_runs.clone();
        let auth = ctx.auth.clone();
        let run = context::with_request(ctx, async move { service.read(&auth, id).await }).await?;
        Ok(json_response(&run.to_json(true)))
    }
    .await;
    finish(r, "/api/core/functions/debugRuns/{id}")
}

/// `POST /api/core/functions/debugRuns/internal/cleanupOlderThan?retentionDays=10&limit=50000`:
/// open like the event runs sweep; never deletes anything younger than [`RETENTION_DAYS`].
async fn cleanup_route(State(st): State<AppState>, RawQuery(raw): RawQuery, h: HeaderMap) -> Response {
    let r = async {
        let ctx = request_context(&st, &h).await?;
        let q = Query(query_params(raw.as_deref()));
        let days = q.int("retentionDays", RETENTION_DAYS)?;
        let limit = q.int("limit", 50_000)?;
        let service = st.inner().debug_runs.clone();
        let removed = context::with_request(ctx, async move { service.cleanup_older_than(days, limit).await }).await?;
        Ok(json_response(&json!({"runsRemoved": removed})))
    }
    .await;
    finish(r, "/api/core/functions/debugRuns/internal/cleanupOlderThan")
}

#[cfg(test)]
#[path = "debug_runs_tests.rs"]
mod tests;
