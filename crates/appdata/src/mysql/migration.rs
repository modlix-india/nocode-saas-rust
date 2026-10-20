//! `MySQLMigrationRunner`, `MySQLFanOut`, `MySQLMigrationSweeper` and the inspector reads:
//! a definition change applied across every tenant schema, journalled step by step so an
//! interrupted run resumes rather than restarts, and recovered by a sweep when nobody is
//! driving it.

use std::sync::OnceLock;

use indexmap::IndexMap;
use sqlx::MySqlPool;

use super::column::MySqlColumn;
use super::db::{self, count_raw, execute_raw, fetch_raw};
use super::inspector;
use super::journal::{self, JournalEntry, MigrationState};
use super::migration_planner::{self, MigrationStep, Phase};
use super::table_planner::{self, SchemaChange};
use super::type_mapper::ID_COLUMN;
use crate::error::{AppDataError, AppDataResult};
use crate::ulid::ulid;
use crate::value::{Document, Value};

pub const DEFAULT_STALE_AFTER_SECONDS: i32 = 60;

/// Who holds a claim: the host and a per-process time. Java uses the JVM start time; this
/// is the first time the process asks, which is just as unique to one process.
pub fn node() -> &'static str {
    static NODE: OnceLock<String> = OnceLock::new();
    NODE.get_or_init(|| {
        let host = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .or_else(|| std::env::var("HOSTNAME").ok())
            .filter(|h| !h.is_empty())
            .unwrap_or_else(|| "unknown".into());
        format!("{host}:{}", chrono::Utc::now().timestamp_millis())
    })
}

/// What happened to one tenant's migration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationOutcome {
    pub state: MigrationState,
    pub applied: i32,
    pub skipped: i32,
    pub resumed_from: i32,
    pub blocked_by: Option<String>,
    pub offending: i64,
    pub error: Option<String>,
}

impl MigrationOutcome {
    pub fn applied(applied: i32, skipped: i32) -> Self {
        MigrationOutcome { state: MigrationState::Applied, applied, skipped, resumed_from: -1, blocked_by: None, offending: 0, error: None }
    }

    pub fn blocked(check: &str, offending: i64, applied: i32, skipped: i32) -> Self {
        MigrationOutcome {
            state: MigrationState::Failed,
            applied,
            skipped,
            resumed_from: -1,
            blocked_by: Some(check.into()),
            offending,
            error: Some(format!("{offending} row(s) would not survive this change")),
        }
    }

    pub fn failed(error: &str, applied: i32, skipped: i32) -> Self {
        MigrationOutcome {
            state: MigrationState::Failed,
            applied,
            skipped,
            resumed_from: -1,
            blocked_by: None,
            offending: 0,
            error: Some(error.into()),
        }
    }

    pub fn in_progress_elsewhere(note: &str) -> Self {
        MigrationOutcome { state: MigrationState::Running, error: Some(note.into()), ..Self::applied(0, 0) }
    }

    pub fn needs_attention(error: &str) -> Self {
        MigrationOutcome { state: MigrationState::NeedsAttention, error: Some(error.into()), ..Self::applied(0, 0) }
    }

    pub fn is_success(&self) -> bool {
        self.state == MigrationState::Applied
    }

    pub fn was_resumed(&self) -> bool {
        self.resumed_from >= 0
    }

    fn resumed_from(mut self, index: i32) -> Self {
        self.resumed_from = index;
        self
    }

    pub fn to_value(&self) -> Value {
        let mut d = Document::new();
        d.insert("state".into(), Value::from(self.state.name()));
        d.insert("applied".into(), Value::Int(self.applied as i64));
        d.insert("skipped".into(), Value::Int(self.skipped as i64));
        d.insert("resumedFrom".into(), Value::Int(self.resumed_from as i64));
        d.insert("blockedBy".into(), self.blocked_by.clone().map(Value::from).unwrap_or(Value::Null));
        d.insert("offending".into(), Value::Int(self.offending));
        d.insert("error".into(), self.error.clone().map(Value::from).unwrap_or(Value::Null));
        d.insert("success".into(), Value::Bool(self.is_success()));
        Value::Object(crate::value::non_empty(d))
    }
}

/// The result of a publish across every tenant: progress, not success.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct FanOutReport {
    pub by_tenant: IndexMap<String, MigrationOutcome>,
    pub blocked: Vec<String>,
    pub no_op: Vec<String>,
    pub resumed: Vec<String>,
}

impl FanOutReport {
    pub fn total(&self) -> usize {
        self.by_tenant.len() + self.no_op.len()
    }

    pub fn applied(&self) -> usize {
        self.by_tenant.values().filter(|o| o.is_success()).count()
    }

    pub fn all_clean(&self) -> bool {
        self.blocked.is_empty()
    }

    /// Live and draft halves of one publish, reported once.
    pub fn merge(a: FanOutReport, b: FanOutReport) -> FanOutReport {
        let mut by_tenant = a.by_tenant;
        by_tenant.extend(b.by_tenant);
        FanOutReport {
            by_tenant,
            blocked: [a.blocked, b.blocked].concat(),
            no_op: [a.no_op, b.no_op].concat(),
            resumed: [a.resumed, b.resumed].concat(),
        }
    }

    pub fn summary(&self) -> String {
        if self.total() == 0 {
            return "no tenants hold this storage".into();
        }
        let resumed = if self.resumed.is_empty() { String::new() } else { format!(", {} resumed", self.resumed.len()) };
        if self.blocked.is_empty() {
            return format!("{} migrated, {} already current{resumed}, none blocked", self.applied(), self.no_op.len());
        }
        format!(
            "{} migrated, {} already current{resumed}, {} blocked: [{}]",
            self.applied(),
            self.no_op.len(),
            self.blocked.len(),
            self.blocked.join(", ")
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TenantPlan {
    pub database: String,
    pub shape: String,
    pub changes: Vec<SchemaChange>,
    pub steps: Vec<MigrationStep>,
}

impl TenantPlan {
    pub fn is_no_op(&self) -> bool {
        self.steps.is_empty()
    }

    pub fn needs_check(&self) -> bool {
        self.changes.iter().any(SchemaChange::needs_data_check)
    }
}

/// How far one tenant got, read back from its journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantProgress {
    pub database: String,
    pub state: Option<MigrationState>,
    pub statement_index: i32,
    pub total: i32,
    pub attempt: i32,
}

impl TenantProgress {
    pub fn describe(&self) -> String {
        match self.state {
            None => format!("{}: not attempted", self.database),
            Some(MigrationState::Applied) => format!("{}: applied", self.database),
            Some(s) => format!(
                "{}: {} at step {} of {} (attempt {})",
                self.database,
                s.name(),
                self.statement_index,
                self.total,
                self.attempt
            ),
        }
    }
}

/// A migration nobody is driving, read straight out of a tenant's journal.
#[derive(Debug, Clone, PartialEq)]
pub struct InterruptedMigration {
    pub database: String,
    pub id: String,
    pub storage_name: String,
    pub table: String,
    pub shape: String,
    pub surface: String,
    pub statement_index: i32,
    pub applied_count: i32,
    pub attempt: i32,
    pub total_statements: i32,
    pub plan: Vec<MigrationStep>,
}

impl InterruptedMigration {
    pub fn is_replayable(&self) -> bool {
        !self.plan.is_empty()
    }

    pub fn is_mid_contract(&self) -> bool {
        self.is_replayable()
            && (self.statement_index as usize) < self.plan.len()
            && self.plan[self.statement_index as usize].phase == Phase::Contract
    }

    pub fn describe(&self) -> String {
        format!(
            "{}/{} step {} of {} (attempt {}){}",
            self.database,
            self.storage_name,
            self.statement_index,
            self.total_statements,
            self.attempt,
            if self.is_mid_contract() { " MID-CONTRACT" } else { "" }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct RecoveryReport {
    pub found: i32,
    pub claimed: i32,
    pub resumed: i32,
    pub outcomes: IndexMap<String, MigrationOutcome>,
    pub unplayable: Vec<String>,
}

impl RecoveryReport {
    pub fn is_quiet(&self) -> bool {
        self.found == 0
    }

    pub fn summary(&self) -> String {
        if self.found == 0 {
            return "no interrupted migrations".into();
        }
        format!(
            "{} interrupted, {} claimed by this node, {} finished{}",
            self.found,
            self.claimed,
            self.resumed,
            if self.unplayable.is_empty() {
                String::new()
            } else {
                format!(", {} with no replayable plan: [{}]", self.unplayable.len(), self.unplayable.join(", "))
            }
        )
    }
}

// ------------------------------------------------------------------ inspector

fn int_of(v: Option<&Value>) -> i32 {
    match v {
        Some(Value::Int(i)) => *i as i32,
        Some(Value::Decimal(d)) => d.int_value(),
        _ => 0,
    }
}

fn string_of(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => "null".into(),
        Some(v) => v.java_string(),
    }
}

/// The columns MySQL reports, id and migration temporaries left out.
pub async fn columns(pool: &MySqlPool, db_name: &str, table: &str) -> AppDataResult<Vec<MySqlColumn>> {
    let rows = fetch_raw(pool, &inspector::columns_sql(db_name, table)).await?;
    let mut out = Vec::new();
    for r in rows {
        let vals: Vec<&Value> = r.values().collect();
        let name = vals.first().map(|v| v.java_string()).unwrap_or_default();
        if name == ID_COLUMN || inspector::is_migration_temp(&name) {
            continue;
        }
        let column_type = vals.get(1).map(|v| v.java_string()).unwrap_or_default();
        let nullable = vals.get(2).map(|v| v.java_string().eq_ignore_ascii_case("YES")).unwrap_or(false);
        let collation = match vals.get(3) {
            None | Some(Value::Null) => None,
            Some(v) => Some(v.java_string()),
        };
        let c = MySqlColumn::full(&name, &column_type, nullable, None, collation)
            .map_err(|e| AppDataError::internal(e.to_string()))?;
        out.push(c);
    }
    Ok(out)
}

pub async fn table_exists(pool: &MySqlPool, db_name: &str, table: &str) -> AppDataResult<bool> {
    Ok(count_raw(pool, &inspector::table_exists_sql(db_name, table)).await? > 0)
}

async fn first_column_strings(pool: &MySqlPool, sql: &str) -> AppDataResult<Vec<String>> {
    Ok(fetch_raw(pool, sql).await?.iter().map(|r| string_of(r.values().next())).collect())
}

pub async fn tenants_with_table(pool: &MySqlPool, app_code: &str, table: &str) -> AppDataResult<Vec<String>> {
    first_column_strings(pool, &inspector::tenants_with_table_sql(app_code, table)).await
}

pub async fn tenant_schemas(pool: &MySqlPool, app_code: &str) -> AppDataResult<Vec<String>> {
    first_column_strings(pool, &inspector::tenant_schemas_sql(app_code)).await
}

// ------------------------------------------------------------------ journal

pub async fn ensure_journal(pool: &MySqlPool, db_name: &str) -> AppDataResult<()> {
    execute_raw(pool, &journal::create_table(db_name)).await?;
    for sql in journal::upgrades(db_name) {
        // Each tolerated on its own: the unique guard cannot be added over an old duplicate.
        let _ = execute_raw(pool, &sql).await;
    }
    Ok(())
}

async fn find_entry(pool: &MySqlPool, sql: &str) -> AppDataResult<Option<JournalEntry>> {
    let rows = fetch_raw(pool, sql).await?;
    let Some(r) = rows.first() else { return Ok(None) };
    let v: Vec<&Value> = r.values().collect();
    let state_name = string_of(v.get(1).copied());
    let state = MigrationState::from_name(&state_name)
        .ok_or_else(|| AppDataError::internal(format!("IllegalArgumentException: No enum constant {state_name}")))?;
    Ok(Some(JournalEntry {
        id: string_of(v.first().copied()),
        state,
        statement_index: int_of(v.get(2).copied()),
        attempt: int_of(v.get(3).copied()),
        applied_count: int_of(v.get(4).copied()),
        total: int_of(v.get(5).copied()),
    }))
}

// ------------------------------------------------------------------ issues

/// The kinds of [`Issue`], as written to the `kind` column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueKind {
    /// Rows in the tenant's table would not survive the change; nothing ran.
    PreflightBlocked,
    /// The pre-flight checks could not be run; nothing ran.
    PreflightFailed,
    /// The tenant's columns could not be read or the change could not be planned.
    PlanFailed,
    /// The migration journal could not be written or read.
    JournalFailed,
    /// An unresolved migration of this storage at another shape holds this one back.
    HeldBack,
    /// No storage definition resolves for the tenant's client.
    NoDefinition,
    /// The table's indexes could not be brought into line.
    IndexSync,
    /// The table's foreign keys could not be brought into line.
    ForeignKeySync,
}

impl IssueKind {
    pub fn name(&self) -> &'static str {
        match self {
            IssueKind::PreflightBlocked => "PREFLIGHT_BLOCKED",
            IssueKind::PreflightFailed => "PREFLIGHT_FAILED",
            IssueKind::PlanFailed => "PLAN_FAILED",
            IssueKind::JournalFailed => "JOURNAL_FAILED",
            IssueKind::HeldBack => "HELD_BACK",
            IssueKind::NoDefinition => "NO_DEFINITION",
            IssueKind::IndexSync => "INDEX_SYNC",
            IssueKind::ForeignKeySync => "FOREIGN_KEY_SYNC",
        }
    }
}

/// One thing a storage publish could not do for one tenant.
#[derive(Debug, Clone, PartialEq)]
pub struct Issue {
    pub storage_name: String,
    pub table: String,
    pub surface: Option<String>,
    pub kind: IssueKind,
    pub shape: Option<String>,
    pub to_version: Option<i32>,
    pub offending: i64,
    pub detail: String,
    pub applied_by: Option<String>,
}

impl Issue {
    pub fn new(storage_name: &str, table: &str, surface: Option<&str>, applied_by: Option<&str>) -> Self {
        Issue {
            storage_name: storage_name.into(),
            table: table.into(),
            surface: surface.map(Into::into),
            kind: IssueKind::PlanFailed,
            shape: None,
            to_version: None,
            offending: 0,
            detail: String::new(),
            applied_by: applied_by.map(Into::into),
        }
    }

    pub fn kind(&self, kind: IssueKind) -> Self {
        Issue { kind, ..self.clone() }
    }

    pub fn shape(mut self, shape: &str) -> Self {
        self.shape = Some(shape.into()).filter(|s: &String| !s.is_empty());
        self
    }

    pub fn version(mut self, v: i32) -> Self {
        self.to_version = Some(v);
        self
    }

    pub fn offending(mut self, n: i64) -> Self {
        self.offending = n;
        self
    }

    pub fn detail(mut self, d: &str) -> Self {
        self.detail = if d.chars().count() > 4000 { d.chars().take(4000).collect() } else { d.to_string() };
        self
    }
}

/// The pre-flight checks of a plan, for an issue's detail.
fn checks_of(p: &TenantPlan) -> String {
    p.steps
        .iter()
        .filter(|s| s.phase == Phase::Preflight)
        .filter_map(|s| s.data_check.clone())
        .collect::<Vec<_>>()
        .join("; ")
}

pub async fn ensure_issue_table(pool: &MySqlPool, db_name: &str) -> AppDataResult<()> {
    execute_raw(pool, &journal::create_issue_table(db_name)).await.map(|_| ())
}

/// Writes `issue` to the tenant's own issue table. Never fails the caller: when even this
/// write fails, the issue goes to the service log instead.
pub async fn record_issue(pool: &MySqlPool, db_name: &str, issue: &Issue) {
    let written = async {
        ensure_issue_table(pool, db_name).await?;
        execute_raw(
            pool,
            &journal::insert_issue(
                db_name,
                &ulid(),
                &issue.storage_name,
                &issue.table,
                issue.surface.as_deref(),
                issue.kind.name(),
                issue.shape.as_deref(),
                issue.to_version,
                issue.offending,
                &issue.detail,
                issue.applied_by.as_deref(),
                node(),
            ),
        )
        .await
    }
    .await;
    match written {
        Ok(_) => tracing::warn!(db = db_name, storage = issue.storage_name, kind = issue.kind.name(), detail = issue.detail, "storage migration issue"),
        Err(e) => tracing::error!(
            db = db_name,
            storage = issue.storage_name,
            kind = issue.kind.name(),
            detail = issue.detail,
            error = %e,
            "storage migration issue (could not be written to the tenant's issue table)"
        ),
    }
}

// ------------------------------------------------------------------ runner

fn error_message(e: &AppDataError) -> String {
    let m = db::message(e);
    if m.chars().count() > 900 {
        m.chars().take(900).collect()
    } else {
        m
    }
}

/// `MySQLMigrationRunner.alreadyRunning`: the concurrency guard rather than a real
/// problem, the unique active key.
pub fn already_running(e: &AppDataError) -> bool {
    db::is_integrity_violation(e) || db::message(e).contains("uk_active_migration")
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    pool: &MySqlPool,
    db_name: &str,
    storage_name: &str,
    table: &str,
    from_version: Option<i32>,
    to_version: i32,
    shape: &str,
    surface: &str,
    plan: &[MigrationStep],
    applied_by: Option<&str>,
) -> AppDataResult<MigrationOutcome> {
    if plan.is_empty() {
        return Ok(MigrationOutcome::applied(0, 0));
    }
    ensure_journal(pool, db_name).await?;
    let blocking = count_raw(pool, &journal::blocking_count(db_name, storage_name, shape)).await?;
    if blocking > 0 {
        return Ok(MigrationOutcome::needs_attention(&format!(
            "storage {storage_name} has {blocking} unresolved migration(s) to a different shape; resolve them before publishing again"
        )));
    }
    if let Some(entry) = find_entry(pool, &journal::find_at(db_name, storage_name, shape)).await? {
        if entry.is_complete() {
            return Ok(MigrationOutcome::applied(0, plan.len() as i32));
        }
        if entry.is_resumable() {
            let from = (entry.statement_index.min(plan.len() as i32 - 1)).max(0);
            let result = async {
                execute_raw(pool, &journal::reopen(db_name, &entry.id, plan.len(), applied_by)).await?;
                execute(pool, db_name, &entry.id, plan, from as usize, entry.applied_count).await
            }
            .await;
            return match result {
                Ok(o) => Ok(o.resumed_from(from)),
                Err(e) => fail(pool, db_name, &entry.id, entry.applied_count, &e).await,
            };
        }
    }

    let id = ulid();
    let result = async {
        execute_raw(
            pool,
            &journal::insert(
                db_name,
                &id,
                storage_name,
                table,
                from_version,
                to_version,
                shape,
                surface,
                plan.len(),
                applied_by,
                &migration_planner::write_plan(plan),
                Some(node()),
            ),
        )
        .await?;
        execute(pool, db_name, &id, plan, 0, 0).await
    }
    .await;
    match result {
        Ok(o) => Ok(o),
        Err(e) if already_running(&e) => Ok(MigrationOutcome::in_progress_elsewhere(&format!(
            "another publish is already applying this shape to {storage_name}"
        ))),
        Err(e) => fail(pool, db_name, &id, 0, &e).await,
    }
}

async fn fail(pool: &MySqlPool, db_name: &str, id: &str, applied_before: i32, e: &AppDataError) -> AppDataResult<MigrationOutcome> {
    let m = error_message(e);
    execute_raw(pool, &journal::finish(db_name, id, MigrationState::Failed, Some(&m), applied_before)).await?;
    Ok(MigrationOutcome::failed(&m, 0, 0))
}

/// Continue a row the recovery sweep has claimed, from the journal alone.
pub async fn resume(
    pool: &MySqlPool,
    db_name: &str,
    id: &str,
    plan: &[MigrationStep],
    statement_index: i32,
    applied_so_far: i32,
) -> AppDataResult<MigrationOutcome> {
    if plan.is_empty() {
        return Ok(MigrationOutcome::failed("the journal row carries no replayable plan", 0, 0));
    }
    let from = (statement_index.min(plan.len() as i32 - 1)).max(0);
    let result = async {
        execute_raw(pool, &journal::reopen(db_name, id, plan.len(), None)).await?;
        execute(pool, db_name, id, plan, from as usize, applied_so_far).await
    }
    .await;
    match result {
        Ok(o) => Ok(o.resumed_from(from)),
        Err(e) => fail(pool, db_name, id, applied_so_far, &e).await,
    }
}

/// Walk the plan one step at a time, then close the row off.
async fn execute(
    pool: &MySqlPool,
    db_name: &str,
    id: &str,
    plan: &[MigrationStep],
    from: usize,
    applied_before: i32,
) -> AppDataResult<MigrationOutcome> {
    let mut applied = 0i32;
    let mut skipped = from as i32;
    let mut outcome = None;

    for (index, s) in plan.iter().enumerate().skip(from) {
        execute_raw(
            pool,
            &journal::progress(db_name, id, MigrationState::Running, index, Some(s.phase), applied_before + applied),
        )
        .await?;

        if let Some(check) = &s.data_check {
            let offending = count_raw(pool, check).await?;
            if offending > 0 {
                outcome = Some(MigrationOutcome::blocked(check, offending, applied, skipped));
                break;
            }
        }

        let Some(sql) = &s.sql else { continue };
        let should_run = match &s.precondition {
            None => true,
            Some(p) => count_raw(pool, p).await? > 0,
        };
        if should_run {
            execute_raw(pool, sql).await?;
            applied += 1;
        } else {
            skipped += 1;
        }
    }

    let outcome = outcome.unwrap_or_else(|| MigrationOutcome::applied(applied, skipped));
    execute_raw(
        pool,
        &journal::finish(db_name, id, outcome.state, outcome.error.as_deref(), applied_before + outcome.applied),
    )
    .await?;
    Ok(outcome)
}

// ------------------------------------------------------------------ fan-out

/// One plan per tenant, each against its own desired columns.
pub async fn plan_tenants(
    pool: &MySqlPool,
    tenants: &[String],
    table: &str,
    to_version: i32,
    desired_for: &IndexMap<String, Vec<MySqlColumn>>,
) -> AppDataResult<Vec<TenantPlan>> {
    let mut out = Vec::new();
    for db_name in tenants {
        if !table_exists(pool, db_name, table).await? {
            out.push(TenantPlan { database: db_name.clone(), shape: String::new(), changes: vec![], steps: vec![] });
            continue;
        }
        let existing = columns(pool, db_name, table).await?;
        let desired = desired_for.get(db_name).cloned().unwrap_or_default();
        let changes = table_planner::diff(&existing, &desired);
        let steps = migration_planner::plan(db_name, table, to_version, &changes)
            .map_err(|e| AppDataError::internal(e.detail().to_string()))?;
        out.push(TenantPlan { database: db_name.clone(), shape: table_planner::shape_of(&desired), changes, steps });
    }
    Ok(out)
}

/// Every data check, without one DDL statement.
pub async fn preflight(pool: &MySqlPool, plans: &[TenantPlan]) -> AppDataResult<IndexMap<String, i64>> {
    let mut blocked = IndexMap::new();
    for p in plans {
        let mut offending = 0;
        for s in p.steps.iter().filter(|s| s.phase == Phase::Preflight) {
            if let Some(check) = &s.data_check {
                offending += count_raw(pool, check).await?;
            }
        }
        if offending > 0 {
            blocked.insert(p.database.clone(), offending);
        }
    }
    Ok(blocked)
}

/// Pre-flight, then migrate only the tenants that are clean. One tenant's trouble is that
/// tenant's outcome (and a row in its [`journal::ISSUE_TABLE`]); the others still migrate.
#[allow(clippy::too_many_arguments)]
pub async fn apply(
    pool: &MySqlPool,
    plans: &[TenantPlan],
    storage_name: &str,
    table: &str,
    from_version: Option<i32>,
    to_version: i32,
    surface: &str,
    applied_by: Option<&str>,
) -> AppDataResult<FanOutReport> {
    let work: Vec<&TenantPlan> = plans.iter().filter(|p| !p.is_no_op()).collect();
    let no_op: Vec<String> = plans.iter().filter(|p| p.is_no_op()).map(|p| p.database.clone()).collect();

    let mut outcomes = IndexMap::new();
    let mut blocked = IndexMap::new();
    for p in &work {
        let issue = Issue::new(storage_name, table, Some(surface), applied_by).shape(&p.shape).version(to_version);
        match preflight(pool, std::slice::from_ref(*p)).await {
            Ok(b) => {
                if let Some(offending) = b.get(&p.database) {
                    let o = MigrationOutcome::blocked("pre-flight", *offending, 0, 0);
                    record_issue(pool, &p.database, &issue.kind(IssueKind::PreflightBlocked).offending(*offending).detail(&checks_of(p))).await;
                    blocked.insert(p.database.clone(), *offending);
                    outcomes.insert(p.database.clone(), o);
                }
            }
            Err(e) => {
                let m = error_message(&e);
                record_issue(pool, &p.database, &issue.kind(IssueKind::PreflightFailed).detail(&m)).await;
                blocked.insert(p.database.clone(), 0);
                outcomes.insert(p.database.clone(), MigrationOutcome::failed(&m, 0, 0));
            }
        }
    }

    for p in work.iter().filter(|p| !blocked.contains_key(&p.database)) {
        let o = match run(pool, &p.database, storage_name, table, from_version, to_version, &p.shape, surface, &p.steps, applied_by)
            .await
        {
            Ok(o) => o,
            // The journal itself could not be written or read: nothing records this tenant's
            // migration but this row (if the database takes even that).
            Err(e) => {
                let m = error_message(&e);
                let issue = Issue::new(storage_name, table, Some(surface), applied_by).shape(&p.shape).version(to_version);
                record_issue(pool, &p.database, &issue.kind(IssueKind::JournalFailed).detail(&m)).await;
                MigrationOutcome::failed(&m, 0, 0)
            }
        };
        if matches!(o.state, MigrationState::NeedsAttention) {
            // Held back by an unresolved migration of this storage at another shape.
            let issue = Issue::new(storage_name, table, Some(surface), applied_by).shape(&p.shape).version(to_version);
            record_issue(pool, &p.database, &issue.kind(IssueKind::HeldBack).detail(o.error.as_deref().unwrap_or(""))).await;
        }
        outcomes.insert(p.database.clone(), o);
    }

    let mut blocked_dbs: Vec<String> = blocked.keys().cloned().collect();
    let mut resumed = Vec::new();
    for (db_name, o) in &outcomes {
        if !o.is_success() && !blocked_dbs.contains(db_name) {
            blocked_dbs.push(db_name.clone());
        }
        if o.was_resumed() {
            resumed.push(db_name.clone());
        }
    }
    Ok(FanOutReport { by_tenant: outcomes, blocked: blocked_dbs, no_op, resumed })
}

/// How far each tenant got, from its own journal.
pub async fn status(pool: &MySqlPool, tenants: &[String], storage_name: &str) -> AppDataResult<Vec<TenantProgress>> {
    let mut out = Vec::new();
    for db_name in tenants {
        let untouched = TenantProgress { database: db_name.clone(), state: None, statement_index: 0, total: 0, attempt: 0 };
        if !table_exists(pool, db_name, journal::TABLE).await? {
            out.push(untouched);
            continue;
        }
        match find_entry(pool, &journal::find_latest(db_name, storage_name)).await? {
            Some(e) => out.push(TenantProgress {
                database: db_name.clone(),
                state: Some(e.state),
                statement_index: e.statement_index,
                total: e.total,
                attempt: e.attempt,
            }),
            None => out.push(untouched),
        }
    }
    Ok(out)
}

// ------------------------------------------------------------------ sweeper

pub async fn interrupted(pool: &MySqlPool, db_name: &str, stale_after_seconds: i32) -> AppDataResult<Vec<InterruptedMigration>> {
    let rows = fetch_raw(pool, &journal::unfinished(db_name, stale_after_seconds)).await?;
    Ok(rows
        .iter()
        .map(|r| {
            let v: Vec<&Value> = r.values().collect();
            let plan_text = match v.get(9) {
                None | Some(Value::Null) => None,
                Some(p) => Some(p.java_string()),
            };
            InterruptedMigration {
                database: db_name.to_string(),
                id: string_of(v.first().copied()),
                storage_name: string_of(v.get(1).copied()),
                table: string_of(v.get(2).copied()),
                shape: string_of(v.get(3).copied()),
                surface: string_of(v.get(4).copied()),
                statement_index: int_of(v.get(5).copied()),
                applied_count: int_of(v.get(6).copied()),
                attempt: int_of(v.get(7).copied()),
                total_statements: int_of(v.get(8).copied()),
                plan: migration_planner::read_plan(plan_text.as_deref()),
            }
        })
        .collect())
}

/// `MySQLMigrationSweeper.schemas`: every schema on this connection that has a journal.
pub async fn schemas(pool: &MySqlPool) -> AppDataResult<Vec<String>> {
    first_column_strings(pool, &journal::schemas_with_journal()).await
}

/// One pass over every tenant on this connection: claim each stale row, finish it.
pub async fn sweep(pool: &MySqlPool, stale_after_seconds: i32) -> AppDataResult<RecoveryReport> {
    let all = schemas(pool).await?;
    sweep_schemas(pool, &all, stale_after_seconds).await
}

/// The sweep over the given schemas only. Java's sweeper always takes every schema on its
/// server; this split exists so a test on a shared server can sweep its own scratch
/// schemas and nobody else's.
pub async fn sweep_schemas(pool: &MySqlPool, schemas: &[String], stale_after_seconds: i32) -> AppDataResult<RecoveryReport> {
    let mut report = RecoveryReport::default();
    for db_name in schemas.iter().map(String::as_str) {
        // One tenant's trouble is logged and the sweep goes on to the next.
        let rows = match interrupted(pool, db_name, stale_after_seconds).await {
            Ok(rows) => rows,
            Err(e) => {
                tracing::error!(db = db_name, error = %e, "migration recovery could not read the journal");
                continue;
            }
        };
        for row in rows {
            report.found += 1;
            if !row.is_replayable() {
                report.unplayable.push(row.describe());
                continue;
            }
            let won = match execute_raw(pool, &journal::claim(db_name, &row.id, node(), stale_after_seconds)).await {
                Ok(n) => n == 1,
                Err(e) => {
                    tracing::error!(db = db_name, storage = row.storage_name, error = %e, "migration recovery could not claim a migration");
                    false
                }
            };
            if !won {
                continue;
            }
            report.claimed += 1;
            let outcome = match resume(pool, db_name, &row.id, &row.plan, row.statement_index, row.applied_count).await {
                Ok(o) => o,
                Err(e) => MigrationOutcome::failed(&error_message(&e), 0, 0),
            };
            if outcome.is_success() {
                report.resumed += 1;
            }
            report.outcomes.insert(format!("{}/{}", db_name, row.storage_name), outcome);
        }
    }
    Ok(report)
}
