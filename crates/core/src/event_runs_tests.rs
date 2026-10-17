//! Ports of `EventRunServiceTest` and `CoreInternalEventControllerTest`, the routes over HTTP,
//! the MySQL DAO against the local stack (gated), and what the Rust side adds (the step
//! traces, the Jackson shapes, the in-memory DAO).

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use async_trait::async_trait;
use axum::http::StatusCode;
use chrono::{NaiveDate, NaiveDateTime, TimeDelta};
use connections::mq::EventMessage;
use overridable::write::spring::{Pageable, Sort};
use overridable::JMap;
use parking_lot::Mutex;
use serde_json::{json, Value};

use super::*;
use crate::auth::Authentication;
use crate::error::CoreError;

const APP: &str = "leadzump";

// ------------------------------------------------------------------ doubles

/// A DAO that records what it was asked and answers what the test scripted.
#[derive(Default)]
struct FakeDao {
    inserts: Mutex<Vec<EventRun>>,
    insert_error: Mutex<Option<CoreError>>,
    finishes: Mutex<Vec<(u64, RunStatus, Vec<EventRunTask>, i32, Option<String>, i64)>>,
    runs: Mutex<HashMap<u64, EventRun>>,
    page_filters: Mutex<Vec<RunFilter>>,
    page_content: Mutex<Vec<EventRun>>,
    distinct: Mutex<Vec<String>>,
    distinct_calls: Mutex<Vec<(String, Option<String>, usize)>>,
    deletes: Mutex<Vec<(NaiveDateTime, Option<RunStatus>, i64)>>,
    /// Answers for deletes of SUCCESS rows, then of any rows; empty: the limit asked.
    success_answers: Mutex<VecDeque<i64>>,
    other_answers: Mutex<VecDeque<i64>>,
    stale: Mutex<Vec<NaiveDateTime>>,
    stale_answer: Mutex<i64>,
}

#[async_trait]
impl EventRunDao for FakeDao {
    async fn insert(&self, run: &EventRun) -> Result<u64, CoreError> {
        if let Some(e) = self.insert_error.lock().clone() {
            return Err(e);
        }
        self.inserts.lock().push(run.clone());
        Ok(1)
    }

    async fn finish(&self, id: u64, status: RunStatus, tasks: &[EventRunTask], failed: i32, error: Option<&str>, _: NaiveDateTime, duration: i64)
        -> Result<bool, CoreError> {
        self.finishes.lock().push((id, status, tasks.to_vec(), failed, error.map(str::to_string), duration));
        Ok(true)
    }

    async fn read(&self, id: u64) -> Result<Option<EventRun>, CoreError> {
        Ok(self.runs.lock().get(&id).cloned())
    }

    async fn read_page(&self, filter: &RunFilter, pageable: &Pageable) -> Result<RunPage, CoreError> {
        self.page_filters.lock().push(filter.clone());
        let content = self.page_content.lock().clone();
        let total = content.len() as i64;
        Ok(RunPage { content, pageable: pageable.clone(), total })
    }

    async fn distinct_clients(&self, app_code: &str, event_name: Option<&str>, limit: usize) -> Result<Vec<String>, CoreError> {
        self.distinct_calls.lock().push((app_code.to_string(), event_name.map(str::to_string), limit));
        Ok(self.distinct.lock().clone())
    }

    async fn latest_per_client(&self, _: &str, _: &str, _: &[String]) -> Result<Vec<EventRun>, CoreError> {
        Ok(Vec::new())
    }

    async fn delete_started_before(&self, before: NaiveDateTime, status: Option<RunStatus>, limit: i64) -> Result<i64, CoreError> {
        self.deletes.lock().push((before, status, limit));
        let scripted = match status {
            Some(RunStatus::Success) => self.success_answers.lock().pop_front(),
            _ => self.other_answers.lock().pop_front(),
        };
        Ok(scripted.unwrap_or(limit))
    }

    async fn fail_running_started_before(&self, before: NaiveDateTime, _: &str, _: NaiveDateTime) -> Result<i64, CoreError> {
        self.stale.lock().push(before);
        Ok(*self.stale_answer.lock())
    }
}

/// `EventDefinitionService.readEffective`: the names it defines (for any app and client).
#[derive(Default)]
struct FakeDefinitions {
    defined: Mutex<Vec<String>>,
    asked: Mutex<Vec<(String, String, String)>>,
}

#[async_trait]
impl EventDefinitions for FakeDefinitions {
    async fn read_effective(&self, name: &str, app_code: &str, client_code: &str) -> Result<Option<JMap>, CoreError> {
        self.asked.lock().push((name.into(), app_code.into(), client_code.into()));
        Ok(self.defined.lock().iter().any(|d| d == name).then(JMap::new))
    }
}

/// Security's three answers, scripted; every call recorded.
#[derive(Default)]
struct FakeSecurity {
    manages: Mutex<HashMap<(String, String), bool>>,
    read_access: Mutex<HashMap<(String, String), bool>>,
    filtered: Mutex<HashMap<String, Vec<String>>>,
    calls: Mutex<Vec<String>>,
}

#[async_trait]
impl RunAccess for FakeSecurity {
    async fn has_read_access(&self, app_code: &str, client_code: &str) -> Result<Option<bool>, CoreError> {
        self.calls.lock().push(format!("hasReadAccess {app_code} {client_code}"));
        Ok(self.read_access.lock().get(&(app_code.into(), client_code.into())).copied())
    }

    async fn filter_managed_client_codes(&self, managing: &str, client_codes: &[String]) -> Result<Option<Vec<String>>, CoreError> {
        self.calls.lock().push(format!("filterManagedClientCodes {managing} {}", client_codes.join(",")));
        Ok(self.filtered.lock().get(managing).cloned())
    }

    async fn does_client_manage_client_code(&self, managing: &str, client: &str) -> Result<Option<bool>, CoreError> {
        self.calls.lock().push(format!("doesClientManageClientCode {managing} {client}"));
        Ok(self.manages.lock().get(&(managing.into(), client.into())).copied())
    }
}

struct Setup {
    dao: Arc<FakeDao>,
    defs: Arc<FakeDefinitions>,
    security: Arc<FakeSecurity>,
    service: EventRunService,
}

fn setup() -> Setup {
    let dao = Arc::new(FakeDao::default());
    let defs = Arc::new(FakeDefinitions::default());
    let security = Arc::new(FakeSecurity::default());
    let service = EventRunService::new(dao.clone(), defs.clone(), security.clone(), true);
    Setup { dao, defs, security, service }
}

fn event(name: &str, data: Value) -> EventMessage {
    EventMessage {
        app_code: Some(APP.into()),
        client_code: Some("FIN".into()),
        event_name: Some(name.into()),
        data: data.as_object().cloned(),
        ..Default::default()
    }
}

/// A signed-in caller of `client_code` holding the run log's authority.
fn caller(client_code: &str) -> Authentication {
    crate::testing::auth(
        json!({"user": {"id": 7, "clientId": 1, "stringAuthorities": [EVENT_ACTION_READ]}, "authenticated": true, "clientCode": client_code}),
        Some(client_code),
        Some(APP),
    )
}

fn request(app_code: &str, client_code: Option<&str>, all_clients: bool, event_name: Option<&str>) -> ReadPageRequest {
    ReadPageRequest {
        app_code: app_code.into(),
        client_code: client_code.map(str::to_string),
        all_clients,
        event_name: event_name.map(str::to_string),
        status: None,
        trigger_type: None,
        from: None,
        to: None,
        pageable: Pageable::of(0, 20, Sort::unsorted()),
        zone: None,
    }
}

fn assert_about(actual: NaiveDateTime, expected: NaiveDateTime) {
    assert!((actual - expected).num_seconds().abs() < 5, "expected about {expected}, was {actual}");
}

fn ts(y: i32, mo: u32, d: u32, h: u32, mi: u32) -> NaiveDateTime {
    NaiveDate::from_ymd_opt(y, mo, d).unwrap().and_hms_opt(h, mi, 0).unwrap()
}

/// An error with an optional cause, standing in for Java's exception chains.
#[derive(Debug)]
struct Failure {
    message: String,
    cause: Option<Box<Failure>>,
}

impl Failure {
    fn new(message: &str) -> Self {
        Self { message: message.into(), cause: None }
    }

    fn caused_by(message: &str, cause: Failure) -> Self {
        Self { message: message.into(), cause: Some(Box::new(cause)) }
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause.as_deref().map(|c| c as &(dyn std::error::Error + 'static))
    }
}

// ------------------------------------------------------------------ describe

#[test]
fn an_event_without_a_marker_is_a_plain_event() {
    let run = describe(&event("Storage.Lead.Create", json!({"dataObject": {}})));
    assert_eq!(run.trigger_type, Some(TriggerType::Event));
    assert_eq!(run.schedule_run_id, None);
}

#[test]
fn a_cron_tick_carries_its_run_and_tick() {
    let run = describe(&event("LZ_WA_OUTBOX", json!({"_schedule": {"kind": "cron", "runId": "r-1", "tickAt": "2026-10-13T03:30:00Z"}})));
    assert_eq!(run.trigger_type, Some(TriggerType::Schedule));
    assert_eq!(run.schedule_run_id.as_deref(), Some("r-1"));
    assert_eq!(run.scheduled_for, Some(ts(2026, 10, 13, 3, 30)));
}

#[test]
fn a_one_off_carries_its_attempt() {
    let run = describe(&event("REMIND", json!({"_schedule": {"kind": "once", "id": "o-9", "attempt": 3, "runAt": "2026-10-13T10:00:00Z"}})));
    assert_eq!(run.trigger_type, Some(TriggerType::OneOff));
    assert_eq!(run.schedule_run_id.as_deref(), Some("o-9"));
    assert_eq!(run.attempt, Some(3));
}

#[test]
fn errors_name_the_root_cause() {
    let e = Failure::caused_by("Task failed", Failure::new("Template welcome not found"));
    assert_eq!(error_of(&e, &[]), "Task failed (cause: Template welcome not found)");
    // No message: Java names the class and where it was thrown; Rust has neither, so the
    // error's debug form stands in.
    assert_eq!(error_of(&Failure::new(""), &[]), "Failure { message: \"\", cause: None }");
    // A CoreError's message is its text, without the status.
    let core = CoreError::new(StatusCode::NOT_FOUND, "Template X not found");
    assert_eq!(error_of(&core, &[]), "Template X not found");
}

// ------------------------------------------------------------------ writing

#[tokio::test]
async fn finish_counts_failed_tasks_and_summarises() {
    let s = setup();
    let tasks = vec![
        EventRunTask { key: Some("a".into()), status: Some(TaskStatus::Success), ..Default::default() },
        EventRunTask { key: Some("b".into()), status: Some(TaskStatus::Failed), error: Some("boom".into()), ..Default::default() },
    ];
    s.service.finish(Some(7), crate::scheduler::now_millis(), false, tasks.clone(), None).await;
    let f = s.dao.finishes.lock().clone();
    assert_eq!(f.len(), 1);
    assert_eq!((f[0].0, f[0].1, &f[0].2, f[0].3, f[0].4.as_deref()), (7, RunStatus::Failed, &tasks, 1, Some("1 task failed")));
    // Several: "<n> tasks failed"; a given error wins.
    let failed = EventRunTask { status: Some(TaskStatus::Failed), ..Default::default() };
    s.service.finish(Some(8), 0, false, vec![failed.clone(), failed.clone()], None).await;
    s.service.finish(Some(9), 0, true, vec![failed], Some("own".into())).await;
    let f = s.dao.finishes.lock().clone();
    assert_eq!(f[1].4.as_deref(), Some("2 tasks failed"));
    assert_eq!((f[2].1, f[2].4.as_deref()), (RunStatus::Success, Some("own")));
}

#[tokio::test]
async fn a_failed_write_never_fails_the_run() {
    let s = setup();
    *s.dao.insert_error.lock() = Some(CoreError::unknown("db down"));
    assert_eq!(s.service.start(&event("X", json!({})), 2).await, None);
    s.service.record(&event("X", json!({})), RunStatus::Skipped, Some("s")).await;
    assert!(s.dao.inserts.lock().is_empty());
}

#[tokio::test]
async fn finish_without_a_row_does_nothing() {
    let s = setup();
    s.service.finish(None, 0, true, Vec::new(), None).await;
    assert!(s.dao.finishes.lock().is_empty());
}

// ------------------------------------------------------------------ no action

fn tick() -> EventMessage {
    event("JOB", json!({"_schedule": {"kind": "cron", "runId": "r", "tickAt": "2026-10-13T00:00:00Z"}}))
}

#[tokio::test]
async fn no_action_is_recorded_for_a_scheduled_event() {
    let s = setup();
    s.service.record_no_action(&tick()).await;
    let rows = s.dao.inserts.lock().clone();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status, Some(RunStatus::NoAction));
    assert!(rows[0].error.as_deref().unwrap().contains("JOB"));
    assert!(s.defs.asked.lock().is_empty());
}

#[tokio::test]
async fn no_action_is_recorded_for_a_hand_off() {
    let s = setup();
    s.service.record_no_action(&event("WHATSAPP_INBOUND", json!({}))).await;
    assert_eq!(s.dao.inserts.lock().len(), 1);
}

#[tokio::test]
async fn no_action_is_recorded_when_the_app_defines_the_event() {
    let s = setup();
    s.defs.defined.lock().push("Storage.Lead.Create".into());
    s.service.record_no_action(&event("Storage.Lead.Create", json!({}))).await;
    assert_eq!(s.dao.inserts.lock().len(), 1);
    assert_eq!(s.defs.asked.lock()[0], ("Storage.Lead.Create".into(), APP.into(), "FIN".into()));
}

#[tokio::test]
async fn an_undefined_platform_event_is_not_recorded() {
    let s = setup();
    s.service.record_no_action(&event("USER_REGISTERED", json!({}))).await;
    assert!(s.dao.inserts.lock().is_empty());
}

// ------------------------------------------------------------------ reading

#[tokio::test]
async fn reads_its_own_client_without_asking_security() {
    let s = setup();
    s.dao.page_content.lock().push(EventRun::default());
    let page = s.service.read_page(&caller("FIN"), &request(APP, None, false, None)).await.unwrap();
    assert_eq!(page.total_elements(), 1);
    assert_eq!(s.dao.page_filters.lock()[0].client_codes, ["FIN"]);
    assert!(s.security.calls.lock().is_empty());
}

#[tokio::test]
async fn reads_a_managed_client_when_its_own_client_may_read_the_app() {
    let s = setup();
    s.security.manages.lock().insert(("SYSTEM".into(), "FIN".into()), true);
    s.security.read_access.lock().insert((APP.into(), "SYSTEM".into()), true);
    s.service.read_page(&caller("SYSTEM"), &request(APP, Some("FIN"), false, None)).await.unwrap();
    assert_eq!(s.dao.page_filters.lock()[0].client_codes, ["FIN"]);
}

#[tokio::test]
async fn a_client_it_does_not_manage_is_forbidden() {
    let s = setup();
    s.security.manages.lock().insert(("FIN".into(), "OTHER".into()), false);
    let e = s.service.read_page(&caller("FIN"), &request(APP, Some("OTHER"), false, None)).await.unwrap_err();
    assert_eq!(e.status(), StatusCode::FORBIDDEN);
    assert_eq!(e.text(), "OTHER is not a client you can act for.");
    assert!(s.dao.page_filters.lock().is_empty());
}

#[tokio::test]
async fn a_managed_client_is_forbidden_without_app_access() {
    let s = setup();
    s.security.manages.lock().insert(("SYSTEM".into(), "FIN".into()), true);
    s.security.read_access.lock().insert((APP.into(), "SYSTEM".into()), false);
    let e = s.service.read_page(&caller("SYSTEM"), &request(APP, Some("FIN"), false, None)).await.unwrap_err();
    assert_eq!(e.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_run_of_another_client_is_forbidden_by_id() {
    let s = setup();
    s.dao.runs.lock().insert(5, EventRun { app_code: Some(APP.into()), client_code: Some("OTHER".into()), ..Default::default() });
    s.security.manages.lock().insert(("FIN".into(), "OTHER".into()), false);
    let e = s.service.read(&caller("FIN"), 5).await.unwrap_err();
    assert_eq!(e.status(), StatusCode::FORBIDDEN);
    // Not there at all: 404 naming the id.
    let e = s.service.read(&caller("FIN"), 6).await.unwrap_err();
    assert_eq!((e.status(), e.text()), (StatusCode::NOT_FOUND, "Event run with id 6 not found".to_string()));
}

#[tokio::test]
async fn an_app_code_is_required() {
    let s = setup();
    let e = s.service.read_page(&caller("FIN"), &request(" ", None, false, None)).await.unwrap_err();
    assert_eq!((e.status(), e.text()), (StatusCode::BAD_REQUEST, "Application name required for searching".to_string()));
    let e = s.service.read_page(&caller("FIN"), &request("", None, true, None)).await.unwrap_err();
    assert_eq!(e.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn all_clients_reads_own_plus_the_managed_clients_that_have_runs() {
    let s = setup();
    *s.dao.distinct.lock() = vec!["FIN".into(), "FIN2".into(), "OTHER".into(), "SYSTEM".into()];
    s.security.read_access.lock().insert((APP.into(), "SYSTEM".into()), true);
    s.security.filtered.lock().insert("SYSTEM".into(), vec!["FIN".into(), "FIN2".into()]);
    s.service.read_page(&caller("SYSTEM"), &request(APP, None, true, Some("JOB"))).await.unwrap();
    assert_eq!(s.dao.distinct_calls.lock()[0], (APP.into(), Some("JOB".into()), MAX_CANDIDATE_CLIENTS));
    assert!(s.security.calls.lock().contains(&"filterManagedClientCodes SYSTEM FIN,FIN2,OTHER".to_string()));
    let f = s.dao.page_filters.lock()[0].clone();
    assert_eq!((f.client_codes, f.event_name.as_deref()), (vec!["SYSTEM".to_string(), "FIN".into(), "FIN2".into()], Some("JOB")));
}

#[tokio::test]
async fn all_clients_without_app_access_is_only_your_own() {
    let s = setup();
    *s.dao.distinct.lock() = vec!["FIN".into(), "OTHER".into()];
    s.security.read_access.lock().insert((APP.into(), "FIN".into()), false);
    s.service.read_page(&caller("FIN"), &request(APP, None, true, Some("JOB"))).await.unwrap();
    assert_eq!(s.dao.page_filters.lock()[0].client_codes, ["FIN"]);
    assert!(!s.security.calls.lock().iter().any(|c| c.starts_with("filterManagedClientCodes")));
}

// ------------------------------------------------------------------ cleanup

#[tokio::test]
async fn successes_go_first_on_their_shorter_retention_then_everything_old() {
    let s = setup();
    *s.dao.stale_answer.lock() = 2;
    *s.dao.success_answers.lock() = VecDeque::from([5000, 300]);
    *s.dao.other_answers.lock() = VecDeque::from([12]);
    let done = s.service.cleanup_older_than(90, 7, 6, 50_000).await.unwrap();
    assert_eq!(done, Cleanup { runs_removed: 5312, successes_removed: 5300, stale_closed: 2 });
    let deletes = s.dao.deletes.lock().clone();
    let successes: Vec<_> = deletes.iter().filter(|d| d.1 == Some(RunStatus::Success)).collect();
    assert_eq!(successes.len(), 2);
    assert!(successes.iter().all(|d| d.2 == 5000));
    assert_about(successes[1].0, now() - TimeDelta::days(7));
    let all: Vec<_> = deletes.iter().filter(|d| d.1.is_none()).collect();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].2, 5000);
    assert_about(all[0].0, now() - TimeDelta::days(90));
    assert_about(s.dao.stale.lock()[0], now() - TimeDelta::hours(6));
    assert_eq!(done.to_jackson_text(), "{\n  \"runsRemoved\" : 5312,\n  \"successesRemoved\" : 5300,\n  \"staleClosed\" : 2\n}");
}

#[tokio::test]
async fn one_limit_covers_both_kinds() {
    let s = setup();
    let done = s.service.cleanup_older_than(90, 7, 6, 7000).await.unwrap();
    assert_eq!(done, Cleanup { runs_removed: 7000, successes_removed: 7000, stale_closed: 0 });
    // 5000 then the 2000 left under the limit, all spent on successes: nothing left for the rest.
    let deletes = s.dao.deletes.lock().clone();
    let limits: Vec<(Option<RunStatus>, i64)> = deletes.iter().map(|d| (d.1, d.2)).collect();
    assert_eq!(limits, [(Some(RunStatus::Success), 5000), (Some(RunStatus::Success), 2000)]);
}

#[tokio::test]
async fn any_caller_is_held_to_the_floors_and_the_cap() {
    let s = setup();
    *s.dao.success_answers.lock() = VecDeque::from([0]);
    *s.dao.other_answers.lock() = VecDeque::from([0]);
    s.service.cleanup_older_than(0, 0, 0, i32::MAX).await.unwrap();
    let deletes = s.dao.deletes.lock().clone();
    assert_about(deletes[0].0, now() - TimeDelta::days(MIN_SUCCESS_RETENTION_DAYS));
    assert_eq!(deletes[0].1, Some(RunStatus::Success));
    assert_about(deletes[1].0, now() - TimeDelta::days(MIN_RETENTION_DAYS));
    assert_eq!(deletes[1].1, None);
    assert_about(s.dao.stale.lock()[0], now() - TimeDelta::hours(MIN_STALE_HOURS));
    // The cap: a batch never asks for more than 5000, and the run stops at 200,000.
    let s = setup();
    let done = s.service.cleanup_older_than(90, 7, 6, i32::MAX).await.unwrap();
    assert_eq!(done.runs_removed, MAX_CLEANUP_LIMIT);
    assert_eq!(s.dao.deletes.lock().len(), (MAX_CLEANUP_LIMIT / 5000) as usize);
}

#[tokio::test]
async fn successes_never_outlive_the_overall_retention() {
    let s = setup();
    *s.dao.success_answers.lock() = VecDeque::from([0]);
    *s.dao.other_answers.lock() = VecDeque::from([0]);
    s.service.cleanup_older_than(60, 365, 6, 1000).await.unwrap();
    let success = s.dao.deletes.lock()[0];
    assert_eq!(success.1, Some(RunStatus::Success));
    assert_about(success.0, now() - TimeDelta::days(60));
}

#[tokio::test]
async fn a_retention_beyond_the_calendar_deletes_nothing() {
    let s = setup();
    *s.dao.success_answers.lock() = VecDeque::from([0]);
    let done = s.service.cleanup_older_than(i32::MAX, i32::MAX, i32::MAX, 10).await.unwrap();
    assert_eq!(done, Cleanup::default());
    assert!(s.dao.deletes.lock().is_empty());
}

// ------------------------------------------------------------------ no-action throttle

#[tokio::test]
async fn no_action_is_written_once_an_hour_and_the_next_row_counts_the_rest() {
    let s = setup();
    s.defs.defined.lock().push("Storage.Lead.Create".into());
    let e = event("Storage.Lead.Create", json!({}));
    let t0 = 1_000_000;
    s.service.record_no_action_at(&e, t0).await;
    for i in 1..=3 {
        s.service.record_no_action_at(&e, t0 + i * 60_000).await;
    }
    assert_eq!(s.dao.inserts.lock().len(), 1);
    s.service.record_no_action_at(&e, t0 + NO_ACTION_WINDOW_MS).await;
    let rows = s.dao.inserts.lock().clone();
    assert_eq!(rows.len(), 2);
    let second = rows[1].error.clone().unwrap();
    assert!(second.contains("3 more times"), "{second}");
    assert_eq!(
        second,
        "No Event action named 'Storage.Lead.Create' exists for this app and client, so nothing ran. Create one with this \
         exact name. Recorded once an hour; later occurrences in the hour are counted, not listed. It also happened 3 more \
         times in the hour before this."
    );
}

#[tokio::test]
async fn the_throttle_is_per_client_and_per_event() {
    let s = setup();
    s.defs.defined.lock().extend(["A".to_string(), "B".into()]);
    s.service.record_no_action_at(&event("A", json!({})), 0).await;
    s.service.record_no_action_at(&event("B", json!({})), 0).await;
    let mut other = event("A", json!({}));
    other.client_code = Some("FIN2".into());
    s.service.record_no_action_at(&other, 0).await;
    assert_eq!(s.dao.inserts.lock().len(), 3);
}

#[tokio::test]
async fn scheduled_no_action_is_throttled_too() {
    let s = setup();
    s.service.record_no_action_at(&tick(), 0).await;
    s.service.record_no_action_at(&tick(), 60_000).await;
    assert_eq!(s.dao.inserts.lock().len(), 1);
}

#[tokio::test]
async fn hand_offs_are_never_throttled() {
    let s = setup();
    for i in 0..5 {
        s.service.record_no_action_at(&event("WHATSAPP_INBOUND", json!({})), i).await;
    }
    assert_eq!(s.dao.inserts.lock().len(), 5);
}

#[tokio::test]
async fn the_remembered_keys_are_bounded() {
    let s = setup();
    for i in 0..MAX_NO_ACTION_KEYS {
        s.service.record_throttled(&event(&format!("E{i}"), json!({})), "x", 0).await;
    }
    assert_eq!(s.service.no_action_windows.lock().len(), MAX_NO_ACTION_KEYS);
    // A new key past the bound starts the map over; a known one keeps it.
    s.service.record_throttled(&event("E0", json!({})), "x", 1).await;
    assert_eq!(s.service.no_action_windows.lock().len(), MAX_NO_ACTION_KEYS);
    s.service.record_throttled(&event("NEW", json!({})), "x", 1).await;
    assert_eq!(s.service.no_action_windows.lock().len(), 1);
}

// ------------------------------------------------------------------ detail

#[test]
fn detail_keeps_each_cause() {
    // Java prints classes and frames, folding Reactor's; Rust has neither: each error of the
    // chain is a line.
    let outer = Failure::caused_by("Function failed", Failure::new("ConcurrentModificationException"));
    assert_eq!(detail_of(&outer, &[]), "Function failed\nCaused by: ConcurrentModificationException\n");
    assert_eq!(error_of(&outer, &[]), "Function failed (cause: ConcurrentModificationException)");
    // At most five errors of the chain.
    let mut deep = Failure::new("e0");
    for i in 1..8 {
        deep = Failure::caused_by(&format!("e{i}"), deep);
    }
    assert_eq!(detail_of(&deep, &[]).lines().count(), MAX_DETAIL_CAUSES);
    // A CoreError's line carries its status.
    assert_eq!(detail_of(&CoreError::unknown("boom"), &[]), "500 Internal Server Error: boom\n");
}

fn step(statement: &str, function: &str, of: &str, arguments: Option<&str>) -> StepTrace {
    StepTrace {
        function_name: of.into(),
        statement_name: statement.into(),
        step_function: function.into(),
        arguments: arguments.map(str::to_string),
    }
}

#[test]
fn kirun_steps_lead_the_detail_and_name_the_step_in_the_error() {
    // Innermost first, as they are collected while the error passes out of nested functions.
    let traces = [
        step("sortLeads", "System.Array.Sort", "Leads.sortAll", Some(r#"{"source": [3, 1, 2]}"#)),
        step("sort", "Leads.sortAll", "Leads.syncAll", Some(r#"{"leads": [3, 1, 2]}"#)),
    ];
    let wrapped = Failure::caused_by("Function failed", Failure::new("ConcurrentModificationException"));
    assert_eq!(
        error_of(&wrapped, &traces),
        "Function failed (cause: ConcurrentModificationException), at step sortLeads (System.Array.Sort) of Leads.sortAll"
    );
    assert_eq!(
        detail_of(&wrapped, &traces),
        "KIRun steps, innermost first:\n\
         \x20   at step sortLeads (System.Array.Sort) of Leads.sortAll\n\
         \x20       arguments {\"source\": [3, 1, 2]}\n\
         \x20   at step sort (Leads.sortAll) of Leads.syncAll\n\
         \x20       arguments {\"leads\": [3, 1, 2]}\n\
         \n\
         Function failed\n\
         Caused by: ConcurrentModificationException\n"
    );
    // Past the third step only where each is; a step with no arguments says so.
    let many: Vec<StepTrace> = (0..5).map(|i| step(&format!("s{i}"), "N.f", "F", if i == 0 { None } else { Some("{}") })).collect();
    let d = detail_of(&Failure::new("x"), &many);
    assert!(d.contains("    at step s0 (N.f) of F\n        before its arguments were evaluated\n"), "{d}");
    assert!(d.contains("    at step s3 (N.f) of F\n    at step s4 (N.f) of F\n\nx\n"), "{d}");
}

#[test]
fn errors_and_details_are_bounded() {
    let long = "é".repeat(5000);
    let e = error_of(&Failure::new(&long), &[]);
    assert_eq!(crate::step_trace::len16(&e), MAX_ERROR_LENGTH);
    assert!(e.ends_with('…'));
    let d = detail_of(&Failure::new(&"x".repeat(20_000)), &[]);
    assert_eq!(crate::step_trace::len16(&d), MAX_DETAIL_LENGTH);
}

/// The whole path the consumer takes: a definition fails inside `traced`, and the row's error
/// and detail name the step.
#[tokio::test]
async fn a_traced_run_names_its_step_in_the_row() {
    use kirun::repository::{KIRunFunctionRepository, KIRunSchemaRepository};
    use kirun::runtime::FunctionExecutionParameters;

    let def = crate::repos::definition::DefinitionFunction::new(
        json!({"name": "pick", "namespace": "Leads",
            "steps": {"first": {"statementName": "first", "namespace": "System.Math", "name": "Add",
                "parameterMap": {"value": {"one": {"key": "one", "type": "VALUE", "value": "abc"}}}}}}),
        None,
        None,
        std::time::Duration::from_secs(5),
    )
    .unwrap();
    let mut fep = FunctionExecutionParameters::new(Arc::new(KIRunFunctionRepository::new()), Arc::new(KIRunSchemaRepository::new()));
    let (result, traces) = traced(async { kirun::function::Function::execute(&def, &mut fep).await }).await;
    let err = result.err().expect("the step fails");
    assert_eq!(traces.len(), 1, "{err}");
    let row_error = error_of(&err, &traces);
    assert!(row_error.ends_with(", at step first (System.Math.Add) of Leads.pick"), "{row_error}");
    let detail = detail_of(&err, &traces);
    assert!(
        detail.starts_with("KIRun steps, innermost first:\n    at step first (System.Math.Add) of Leads.pick\n        arguments {\"value\": [\"abc\"]}\n\n"),
        "{detail}"
    );
}

// ------------------------------------------------------------------ the shapes

#[test]
fn runs_are_written_as_jackson_writes_them() {
    let mut run = EventRun {
        id: Some(7),
        app_code: Some(APP.into()),
        client_code: Some("FIN".into()),
        event_name: Some("JOB".into()),
        trigger_type: Some(TriggerType::Schedule),
        status: Some(RunStatus::Failed),
        schedule_run_id: Some("".into()),
        scheduled_for: Some(ts(2026, 10, 13, 3, 30)),
        is_draft: Some(false),
        task_count: Some(1),
        failed_task_count: Some(0),
        tasks: Some(vec![EventRunTask {
            key: Some("a".into()),
            task_type: Some("CALL_CORE_FUNCTION".into()),
            order: Some(1),
            status: Some(TaskStatus::Failed),
            started_at: Some(1_760_000_000_123),
            duration_ms: Some(1250),
            ..Default::default()
        }]),
        started_at: Some(ts(2026, 10, 13, 3, 30) + TimeDelta::milliseconds(999)),
        duration_ms: Some(65_000),
        ..Default::default()
    };
    decorate(&mut run, Some("Asia/Kolkata"));
    assert_eq!(
        run.to_jackson(),
        json!({"id": 7, "appCode": APP, "clientCode": "FIN", "eventName": "JOB", "triggerType": "SCHEDULE", "status": "FAILED",
               "scheduledFor": 1_791_862_200, "isDraft": false, "taskCount": 1, "failedTaskCount": 0,
               "tasks": [{"key": "a", "type": "CALL_CORE_FUNCTION", "order": 1, "status": "FAILED", "startedAt": 1_760_000_000_123_i64,
                          "durationMs": 1250, "durationText": "1.3 s"}],
               "startedAt": 1_791_862_200, "durationMs": 65_000, "startedText": "Tue 13 Oct, 09:00:00",
               "scheduledForText": "Tue 13 Oct, 09:00:00", "durationText": "1 min 5 s"})
    );
    // Key order is Jackson's (the declaration order), and the text pretty.
    let text = run.to_jackson_text();
    assert!(text.starts_with("{\n  \"id\" : 7,\n  \"appCode\" : \"leadzump\","), "{text}");
    let keys: Vec<String> = serde_json::from_str::<serde_json::Map<String, Value>>(&text).unwrap().keys().cloned().collect();
    assert_eq!(keys.first().map(String::as_str), Some("id"));
    assert_eq!(keys.last().map(String::as_str), Some("durationText"));
}

#[test]
fn tasks_go_to_json_and_back() {
    let tasks = vec![EventRunTask { key: Some("k".into()), status: Some(TaskStatus::Success), detail: Some("d".into()), ..Default::default() }];
    let text = tasks_to_json(&tasks).unwrap();
    assert_eq!(text, "[ {\n  \"key\" : \"k\",\n  \"status\" : \"SUCCESS\",\n  \"detail\" : \"d\"\n} ]");
    assert_eq!(tasks_from_json(Some(&text)), tasks);
    // MySQL hands JSON back in its own key order; unknown keys are ignored.
    assert_eq!(tasks_from_json(Some(r#"[{"status": "SUCCESS", "x": 1, "key": "k", "detail": "d"}]"#)), tasks);
    assert_eq!(tasks_to_json(&[]), None);
    assert!(tasks_from_json(None).is_empty());
    assert!(tasks_from_json(Some("  ")).is_empty());
    assert!(tasks_from_json(Some("not json")).is_empty());
    assert!(tasks_from_json(Some(r#"[{"status": "MAYBE"}]"#)).is_empty());
}

#[test]
fn display_text_follows_the_zone() {
    assert_eq!(duration(999), "999 ms");
    assert_eq!(duration(1000), "1.0 s");
    assert_eq!(duration(1150), "1.2 s");
    assert_eq!(duration(1249), "1.2 s");
    assert_eq!(duration(59_960), "60.0 s");
    assert_eq!(duration(60_000), "1 min 0 s");
    assert_eq!(duration(3_725_000), "62 min 5 s");
    let at = |zone: Option<&str>| {
        let mut r = EventRun { started_at: Some(ts(2026, 1, 5, 23, 15)), ..Default::default() };
        decorate(&mut r, zone);
        r.started_text.unwrap()
    };
    assert_eq!(at(None), "Mon 5 Jan, 23:15:00");
    assert_eq!(at(Some(" America/New_York ")), "Mon 5 Jan, 18:15:00");
    assert_eq!(at(Some("+05:30")), "Tue 6 Jan, 04:45:00");
    assert_eq!(at(Some("-0330")), "Mon 5 Jan, 19:45:00");
    assert_eq!(at(Some("UTC+1")), "Tue 6 Jan, 00:15:00");
    assert_eq!(at(Some("GMT")), "Mon 5 Jan, 23:15:00");
    assert_eq!(at(Some("Z")), "Mon 5 Jan, 23:15:00");
    // What ZoneId.of refuses reads as UTC.
    assert_eq!(at(Some("Mars/Base")), "Mon 5 Jan, 23:15:00");
    assert_eq!(at(Some("+19:00")), "Mon 5 Jan, 23:15:00");
    assert_eq!(at(Some("asia/kolkata")), "Mon 5 Jan, 23:15:00");
}

#[test]
fn the_marker_and_the_caller_read_as_java_reads_them() {
    let mut e = event("REMIND", json!({"_schedule": {"kind": "once", "id": 42, "attempt": 2.9, "runAt": "2026-10-13T10:00:00.250+05:30"}}));
    e.authentication = Some(json!({"user": {"id": "142"}, "authenticated": true}));
    e.draft = true;
    let run = describe(&e);
    assert_eq!(run.schedule_run_id.as_deref(), Some("42"));
    assert_eq!(run.attempt, Some(2));
    assert_eq!(run.scheduled_for, Some(ts(2026, 10, 13, 4, 30) + TimeDelta::milliseconds(250)));
    assert_eq!(run.triggered_by, Some(142));
    assert_eq!(run.is_draft, Some(true));
    // Not an instant, not a map, an unknown kind: nothing taken from it.
    assert_eq!(describe(&event("X", json!({"_schedule": {"kind": "cron", "tickAt": "2026-10-13 00:00:00Z"}}))).scheduled_for, None);
    assert_eq!(describe(&event("X", json!({"_schedule": "cron"}))).trigger_type, Some(TriggerType::Event));
    assert_eq!(describe(&event("X", json!({"_schedule": {"kind": "weekly"}}))).trigger_type, Some(TriggerType::Event));
    assert_eq!(describe(&event("X", json!({"_schedule": {"kind": "cron", "runId": {"a": [1, 2.5]}}}))).schedule_run_id.as_deref(), Some("{a=[1, 2.5]}"));
}

// ------------------------------------------------------------------ with the in-memory table

fn memory_service() -> (Arc<MemoryEventRunDao>, Arc<FakeSecurity>, EventRunService) {
    let dao = Arc::new(MemoryEventRunDao::default());
    let security = Arc::new(FakeSecurity::default());
    let service = EventRunService::new(dao.clone(), Arc::new(FakeDefinitions::default()), security.clone(), true);
    (dao, security, service)
}

#[tokio::test]
async fn a_run_is_opened_and_closed() {
    let (dao, _, service) = memory_service();
    let mut e = tick();
    e.authentication = Some(json!({"user": {"id": 9}}));
    let id = service.start(&e, 3).await.unwrap();
    let open = dao.read(id).await.unwrap().unwrap();
    assert_eq!((open.status, open.task_count, open.trigger_type), (Some(RunStatus::Running), Some(3), Some(TriggerType::Schedule)));
    assert_eq!((open.triggered_by, open.instance_id.as_deref()), (Some(9), Some(service.instance_id())));
    assert!(open.finished_at.is_none());
    let tasks = vec![EventRunTask { key: Some("t".into()), status: Some(TaskStatus::Failed), ..Default::default() }];
    service.finish(Some(id), crate::scheduler::now_millis() - 40, false, tasks.clone(), None).await;
    let closed = dao.read(id).await.unwrap().unwrap();
    assert_eq!((closed.status, closed.error.as_deref(), closed.failed_task_count), (Some(RunStatus::Failed), Some("1 task failed"), Some(1)));
    assert!(closed.duration_ms.unwrap() >= 40);
    assert_eq!(closed.tasks, Some(tasks));
    service.record(&e, RunStatus::Skipped, Some("still running")).await;
    let skipped = dao.rows().into_iter().find(|r| r.status == Some(RunStatus::Skipped)).unwrap();
    assert_eq!((skipped.duration_ms, skipped.started_at == skipped.finished_at), (Some(0), true));
}

#[tokio::test]
async fn the_switch_stops_the_writes_only() {
    let dao = Arc::new(MemoryEventRunDao::default());
    let service = EventRunService::new(dao.clone(), Arc::new(FakeDefinitions::default()), Arc::new(FakeSecurity::default()), false);
    assert!(!service.is_enabled());
    assert_eq!(service.start(&tick(), 1).await, None);
    service.record(&tick(), RunStatus::Skipped, None).await;
    service.record_no_action(&event("WHATSAPP_INBOUND", json!({}))).await;
    assert!(dao.rows().is_empty());
    // Reading still works.
    assert!(service.read_page(&caller("FIN"), &request(APP, None, false, None)).await.unwrap().content.is_empty());
}

#[tokio::test]
async fn the_memory_table_filters_pages_and_sweeps_as_mysql_does() {
    let (dao, _, service) = memory_service();
    let base = ts(2026, 10, 1, 0, 0);
    for (i, (client, event, status)) in [
        ("FIN", "JOB", RunStatus::Success),
        ("FIN", "JOB", RunStatus::Failed),
        ("FIN", "OTHER", RunStatus::Success),
        ("FIN2", "JOB", RunStatus::Running),
        ("SYSTEM", "JOB", RunStatus::Success),
    ]
    .into_iter()
    .enumerate()
    {
        let run = EventRun {
            app_code: Some(APP.into()),
            client_code: Some(client.into()),
            event_name: Some(event.into()),
            trigger_type: Some(TriggerType::Event),
            status: Some(status),
            started_at: Some(base + TimeDelta::hours(i as i64)),
            ..Default::default()
        };
        dao.insert(&run).await.unwrap();
    }
    let filter = RunFilter { app_code: APP.into(), client_codes: vec!["FIN".into(), "FIN2".into()], event_name: Some("JOB".into()), ..Default::default() };
    let page = dao.read_page(&filter, &Pageable::of(0, 2, Sort::unsorted())).await.unwrap();
    assert_eq!(page.total, 3);
    assert_eq!(page.content.iter().map(|r| r.id.unwrap()).collect::<Vec<_>>(), [4, 2]);
    let page = dao.read_page(&RunFilter { status: Some(RunStatus::Success), ..filter.clone() }, &Pageable::of(0, 20, Sort::unsorted())).await.unwrap();
    assert_eq!(page.content.len(), 1);
    let page = dao.read_page(&RunFilter { from: Some(base + TimeDelta::hours(1)), to: Some(base + TimeDelta::hours(3)), ..filter.clone() }, &Pageable::of(0, 20, Sort::unsorted())).await.unwrap();
    assert_eq!(page.content.iter().map(|r| r.id.unwrap()).collect::<Vec<_>>(), [2]);
    assert_eq!(dao.read_page(&RunFilter { client_codes: vec![], ..filter }, &Pageable::of(0, 20, Sort::unsorted())).await.unwrap().total, 0);
    assert_eq!(dao.distinct_clients(APP, Some("JOB"), 10).await.unwrap(), ["FIN", "FIN2", "SYSTEM"]);
    assert_eq!(dao.distinct_clients(APP, Some(" "), 2).await.unwrap(), ["FIN", "FIN2"]);
    let latest = service.latest_runs(APP, "JOB", &["FIN".into(), "NOPE".into(), "SYSTEM".into()]).await;
    assert_eq!((latest.len(), latest["FIN"].id, latest["SYSTEM"].id), (2, Some(2), Some(5)));
    assert!(service.latest_runs(APP, "JOB", &[]).await.is_empty());
    // The sweep: the RUNNING row is closed, then rows go oldest first.
    let closed = dao.fail_running_started_before(base + TimeDelta::days(1), "stale", base).await.unwrap();
    assert_eq!(closed, 1);
    assert_eq!(dao.read(4).await.unwrap().unwrap().status, Some(RunStatus::Failed));
    assert_eq!(dao.delete_started_before(base + TimeDelta::days(1), Some(RunStatus::Success), 2).await.unwrap(), 2);
    assert_eq!(dao.rows().iter().map(|r| r.id.unwrap()).collect::<Vec<_>>(), [2, 4, 5]);
    assert_eq!(dao.delete_started_before(base + TimeDelta::days(1), None, 10).await.unwrap(), 3);
    // A failing table: the read of the latest runs is empty, not an error.
    *dao.fail.lock() = Some(CoreError::unknown("down"));
    assert!(dao.insert(&EventRun::default()).await.is_err());
}

#[test]
fn pages_are_written_as_page_impl() {
    let page = RunPage {
        content: vec![EventRun { id: Some(1), status: Some(RunStatus::Success), ..Default::default() }],
        pageable: Pageable::of(0, 20, Sort::unsorted()),
        total: 1,
    };
    let v: Value = serde_json::from_str(&page.to_jackson_text()).unwrap();
    assert_eq!(v["content"], json!([{"id": 1, "status": "SUCCESS"}]));
    assert_eq!((v["totalElements"].clone(), v["size"].clone(), v["number"].clone(), v["sort"].clone()), (json!(1), json!(20), json!(0), json!([])));
    let empty: Value = serde_json::from_str(&RunPage::empty(&Pageable::of(2, 5, Sort::unsorted())).to_jackson_text()).unwrap();
    assert!(empty.get("content").is_none());
    assert_eq!((empty["empty"].clone(), empty["pageable"]["offset"].clone()), (json!(true), json!(10)));
}

#[test]
fn the_texts_are_core_s() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../nocode-saas/core/src/main/resources/messages_en.properties");
    let Ok(bundle) = std::fs::read_to_string(path) else { return };
    let text = |key: &str| bundle.lines().find_map(|l| l.strip_prefix(&format!("{key}="))).map(str::to_string);
    assert_eq!(text("application_name_required").as_deref(), Some(run_messages::APPLICATION_NAME_REQUIRED.template));
    assert_eq!(text("forbidden_client_code").as_deref(), Some(run_messages::FORBIDDEN_CLIENT_CODE.template));
}

// ------------------------------------------------------------------ CoreInternalEventControllerTest

mod raise {
    use super::*;
    use crate::event_routes::{raise, RaiseRequest};
    use crate::integrations::{Mq, Publish};

    #[derive(Default)]
    struct Recording {
        sent: Mutex<Vec<(String, Value)>>,
    }

    #[async_trait]
    impl Publish for Recording {
        async fn publish(&self, exchange: &str, _: &str, body: &str, _: &str) -> Result<(), CoreError> {
            self.sent.lock().push((exchange.to_string(), serde_json::from_str(body).unwrap()));
            Ok(())
        }
    }

    fn mq() -> (Arc<Recording>, Mq) {
        let rec = Arc::new(Recording::default());
        let mq = Mq::with(rec.clone(), &crate::config::MqSection::default());
        (rec, mq)
    }

    fn req(event: Option<&str>, app: Option<&str>, client: Option<&str>, data: Option<Value>) -> RaiseRequest {
        RaiseRequest {
            event_name: event.map(str::to_string),
            app_code: app.map(str::to_string),
            client_code: client.map(str::to_string),
            data: data.and_then(|d| d.as_object().cloned()),
        }
    }

    #[tokio::test]
    async fn raises_the_event_without_authentication_so_it_runs_as_the_event_runner() {
        let (rec, mq) = mq();
        let data = json!({"resourceType": "SECURED", "paths": ["/leadzumptwo/whatsapp/incoming/919/abc.jpg"]});
        let r = req(Some("FILES_EXPIRED"), Some("leadzumptwo"), Some("FIN"), Some(data.clone()));
        assert_eq!(raise(&mq, Some(&r)).await.unwrap(), (StatusCode::OK, true));
        let sent = rec.sent.lock().clone();
        assert_eq!(sent.len(), 1);
        let (exchange, qob) = &sent[0];
        assert_eq!(exchange, "events");
        assert_eq!((qob["eventName"].clone(), qob["appCode"].clone(), qob["clientCode"].clone()), (json!("FILES_EXPIRED"), json!("leadzumptwo"), json!("FIN")));
        assert_eq!(qob["data"], data);
        // No authentication: the consumer builds the client's anonymous event-runner context.
        assert!(qob.get("authentication").is_none());
    }

    #[tokio::test]
    async fn missing_data_is_an_empty_map() {
        let (rec, mq) = mq();
        let r = req(Some("FILES_EXPIRED"), Some("leadzumptwo"), Some("FIN"), None);
        assert_eq!(raise(&mq, Some(&r)).await.unwrap().1, true);
        // An empty map is left out of the message (`NON_EMPTY`), as Java writes `Map.of()`.
        assert!(rec.sent.lock()[0].1.get("data").is_none());
    }

    #[tokio::test]
    async fn refuses_an_event_that_is_not_raisable_here() {
        let (rec, mq) = mq();
        let r = req(Some("WHATSAPP_INBOUND"), Some("leadzumptwo"), Some("FIN"), Some(json!({})));
        assert_eq!(raise(&mq, Some(&r)).await.unwrap(), (StatusCode::BAD_REQUEST, false));
        assert!(rec.sent.lock().is_empty());
    }

    #[tokio::test]
    async fn refuses_missing_fields() {
        let (rec, mq) = mq();
        for r in [
            req(None, Some("leadzumptwo"), Some("FIN"), None),
            req(Some("FILES_EXPIRED"), Some(" "), Some("FIN"), None),
            req(Some("FILES_EXPIRED"), Some("leadzumptwo"), None, None),
        ] {
            assert_eq!(raise(&mq, Some(&r)).await.unwrap().0, StatusCode::BAD_REQUEST);
        }
        assert_eq!(raise(&mq, None).await.unwrap().0, StatusCode::BAD_REQUEST);
        assert!(rec.sent.lock().is_empty());
    }
}

// ------------------------------------------------------------------ the routes over HTTP

mod routes {
    use super::*;
    use axum::extract::RawQuery;
    use axum::http::HeaderMap;
    use axum::response::IntoResponse;
    use axum::routing::{get, post};
    use axum::Router;

    /// Security for the routes: `Basic reader` holds `EventAction_READ` in SYSTEM, `Basic user`
    /// is signed in without it, no `Authorization` is anonymous; SYSTEM manages FIN and may
    /// read the app.
    async fn security() -> String {
        async fn authentication(h: HeaderMap) -> axum::response::Response {
            let a = h.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
            let body = match a.to_lowercase().as_str() {
                "basic reader" => json!({"user": {"id": 7, "clientId": 1, "stringAuthorities": [EVENT_ACTION_READ]}, "authenticated": true, "clientCode": "SYSTEM"}),
                "basic user" => json!({"user": {"id": 8, "clientId": 1, "stringAuthorities": ["Authorities.Logged_IN"]}, "authenticated": true, "clientCode": "SYSTEM"}),
                _ => json!({"user": {"id": 0, "clientId": 1, "stringAuthorities": ["Authorities._Anonymous"]}, "authenticated": false, "clientCode": "SYSTEM"}),
            };
            axum::Json(body).into_response()
        }
        let q = |raw: Option<String>| -> HashMap<String, String> { crate::exec::parse_query(raw.as_deref()).into_iter().collect() };
        let router = Router::new()
            .route("/api/security/internal/securityContextAuthentication", get(authentication))
            .route(
                "/api/security/clients/internal/doesClientManageClientCode",
                get(move |RawQuery(r): RawQuery| async move {
                    let p = q(r);
                    (p.get("managingClientCode").map(String::as_str) == Some("SYSTEM") && p.get("clientCode").map(String::as_str) == Some("FIN")).to_string()
                }),
            )
            .route("/api/security/applications/internal/hasReadAccess", get(|| async { "true" }))
            .route("/api/security/clients/internal/filterManagedClientCodes", post(|| async { r#"["FIN"]"# }));
        crate::testing::serve(router).await
    }

    struct Http {
        base: String,
        http: reqwest::Client,
    }

    impl Http {
        async fn call(&self, method: reqwest::Method, path: &str, auth: Option<&str>, body: Option<&str>) -> (u16, String, String) {
            let mut rb = self.http.request(method, format!("{}{path}", self.base)).header("appCode", APP).header("clientCode", "SYSTEM");
            if let Some(a) = auth {
                rb = rb.header("Authorization", a);
            }
            if let Some(b) = body {
                rb = rb.header("content-type", "application/json").body(b.to_string());
            }
            let r = rb.send().await.unwrap();
            let status = r.status().as_u16();
            let ctype = r.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
            (status, ctype, r.text().await.unwrap())
        }

        async fn get(&self, path: &str, auth: Option<&str>) -> (u16, String, String) {
            self.call(reqwest::Method::GET, path, auth, None).await
        }

        async fn post(&self, path: &str, body: Option<&str>) -> (u16, String, String) {
            self.call(reqwest::Method::POST, path, None, body).await
        }
    }

    async fn serve_routes() -> (Http, crate::state::AppState) {
        let sec = security().await;
        let state = crate::testing::offline_state(crate::testing::offline_storage_service().await, &sec).await;
        let base = crate::testing::serve(crate::handlers::router(state.clone())).await;
        (Http { base, http: reqwest::Client::new() }, state)
    }

    async fn seed(state: &crate::state::AppState, client: &str, event: &str, started: NaiveDateTime) -> u64 {
        let run = EventRun {
            app_code: Some(APP.into()),
            client_code: Some(client.into()),
            event_name: Some(event.into()),
            trigger_type: Some(TriggerType::Event),
            status: Some(RunStatus::Success),
            started_at: Some(started),
            duration_ms: Some(1500),
            ..Default::default()
        };
        state.inner().event_runs.dao().insert(&run).await.unwrap()
    }

    #[tokio::test]
    async fn the_run_log_over_http() {
        let (c, state) = serve_routes().await;
        let base = ts(2026, 10, 1, 0, 0);
        let own = seed(&state, "SYSTEM", "JOB", base).await;
        let managed = seed(&state, "FIN", "JOB", base + TimeDelta::hours(1)).await;
        let other = seed(&state, "OTHER", "JOB", base).await;

        // Anonymous: a bare 401. Signed in without the authority: Spring's access-denied 403.
        // Both answer with a coded body naming what to do (Java sends none, or "Access Denied").
        let (s, _, body) = c.get(&format!("/api/core/eventRuns?appCode={APP}"), None).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!((s, v["code"].as_str()), (401, Some("COMMON.SIGN_IN_REQUIRED")));
        let (s, ctype, body) = c.get(&format!("/api/core/eventRuns?appCode={APP}"), Some("Basic user")).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!((s, ctype.as_str(), v["code"].as_str()), (403, "application/json", Some("COMMON.PERMISSION_REQUIRED")));
        assert_eq!(v["debugMessage"], "Access Denied: needs Authorities.EventAction_READ");
        // Parameters are resolved before the authority is checked.
        let (s, _, body) = c.get("/api/core/eventRuns", Some("Basic user")).await;
        assert_eq!(s, 400);
        assert!(body.contains("Required query parameter 'appCode' is not present."), "{body}");
        let (s, _, body) = c.get(&format!("/api/core/eventRuns?appCode={APP}&status=MAYBE"), Some("Basic reader")).await;
        assert_eq!(s, 400);
        assert!(body.contains("Type mismatch."), "{body}");

        // Own client by default, display text in the zone asked for.
        let (s, ctype, body) = c.get(&format!("/api/core/eventRuns?appCode={APP}&timezone=Asia/Kolkata"), Some("Basic reader")).await;
        assert_eq!((s, ctype.as_str()), (200, "application/json"));
        let page: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(page["totalElements"], json!(1));
        assert_eq!(page["content"][0]["id"], json!(own));
        assert_eq!(page["content"][0]["startedText"], json!("Thu 1 Oct, 05:30:00"));
        assert_eq!(page["content"][0]["durationText"], json!("1.5 s"));
        assert_eq!(page["pageable"]["pageSize"], json!(20));

        // A managed client; one it does not manage is a 403 GenericException.
        let page: Value = serde_json::from_str(&c.get(&format!("/api/core/eventRuns?appCode={APP}&clientCode=FIN"), Some("Basic reader")).await.2).unwrap();
        assert_eq!(page["content"][0]["id"], json!(managed));
        let (s, _, body) = c.get(&format!("/api/core/eventRuns?appCode={APP}&clientCode=OTHER"), Some("Basic reader")).await;
        assert_eq!(s, 403);
        let v = serde_json::from_str::<Value>(&body).unwrap();
        assert_eq!((v["code"].clone(), v["debugMessage"].clone()), (json!("CORE.FORBIDDEN_CLIENT_CODE"), json!("[forbidden_client_code] OTHER is not a client you can act for.")));
        assert_eq!(v["message"], json!("You can't act for the client OTHER: it is not your organisation or one it manages."));

        // All clients: own and the managed ones with runs, newest first; size held to 200,
        // filters and epoch-second bounds applied.
        let page: Value = serde_json::from_str(&c.get(&format!("/api/core/eventRuns?appCode={APP}&allClients=true&eventName=JOB&size=500"), Some("Basic reader")).await.2).unwrap();
        let ids: Vec<Value> = page["content"].as_array().unwrap().iter().map(|r| r["id"].clone()).collect();
        assert_eq!(ids, [json!(managed), json!(own)]);
        assert_eq!(page["size"], json!(200));
        let from = (base + TimeDelta::minutes(30)).and_utc().timestamp();
        let page: Value = serde_json::from_str(&c.get(&format!("/api/core/eventRuns?appCode={APP}&allClients=yes&from={from}&status=SUCCESS&triggerType=EVENT"), Some("Basic reader")).await.2).unwrap();
        assert_eq!(page["totalElements"], json!(1));

        // By id.
        let (s, _, body) = c.get(&format!("/api/core/eventRuns/{own}"), Some("Basic reader")).await;
        assert_eq!(s, 200);
        assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["clientCode"], json!("SYSTEM"));
        let (s, _, body) = c.get(&format!("/api/core/eventRuns/{other}"), Some("Basic reader")).await;
        assert_eq!(s, 403, "{body}");
        let (s, _, body) = c.get("/api/core/eventRuns/999", Some("Basic reader")).await;
        assert_eq!(s, 404);
        let v = serde_json::from_str::<Value>(&body).unwrap();
        assert_eq!((v["code"].clone(), v["message"].clone()), (json!("CORE.OBJECT_NOT_FOUND"), json!("We couldn't find the event run with id 999.")));
        assert_eq!(v["debugMessage"], json!("[object_not_found] Event run with id 999 not found"));
        let (s, _, body) = c.get("/api/core/eventRuns/abc", Some("Basic user")).await;
        assert_eq!((s, body.as_str()), (404, ""));
        assert_eq!(c.get(&format!("/api/core/eventRuns/{own}"), Some("Basic user")).await.0, 403);
        assert_eq!(c.get(&format!("/api/core/eventRuns/{own}"), None).await.0, 401);

        // The sweep is open; the three successes are older than the seven days successes keep.
        let (s, _, body) = c.post("/api/core/eventRuns/internal/cleanupOlderThan?retentionDays=&limit=10", None).await;
        assert_eq!(s, 200);
        assert_eq!(serde_json::from_str::<Value>(&body).unwrap(), json!({"runsRemoved": 3, "successesRemoved": 3, "staleClosed": 0}));
        assert_eq!(c.get(&format!("/api/core/eventRuns/{own}"), Some("Basic reader")).await.0, 404);
        assert_eq!(c.post("/api/core/eventRuns/internal/cleanupOlderThan?limit=many", None).await.0, 400);
    }

    #[tokio::test]
    async fn raising_over_http() {
        let (c, _) = serve_routes().await;
        // Publishing is off in the offline state: the event is dropped and reported sent.
        let (s, ctype, body) = c.post("/api/core/events/internal/raise", Some(r#"{"eventName":"FILES_EXPIRED","appCode":"a","clientCode":"FIN"}"#)).await;
        assert_eq!((s, ctype.as_str(), body.as_str()), (200, "application/json", "true"));
        let (s, _, body) = c.post("/api/core/events/internal/raise", Some(r#"{"eventName":"OTHER","appCode":"a","clientCode":"FIN"}"#)).await;
        assert_eq!((s, body.as_str()), (400, "false"));
        let (s, _, body) = c.post("/api/core/events/internal/raise", None).await;
        assert_eq!(s, 400);
        assert!(body.contains("No request body"), "{body}");
    }
}

// ------------------------------------------------------------------ the local stack

/// The MySQL DAO against the local `core.core_event_runs`. Writes only rows of an app code
/// made up for the run, started in the year 1000 so the sweep's table-wide statements can only
/// reach them, and deletes them at the end whatever happened.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs the local stack: CORE_LOCAL_STACK=1 and config/local.env"]
async fn the_mysql_table_on_the_local_stack() {
    use futures::FutureExt;

    if !crate::testing::local_stack() {
        return;
    }
    std::env::set_var("CONFIG_FILE", concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/core-exec.toml"));
    let cfg: crate::config::CoreConfig = platform::config::load("core-exec").expect("config");
    let pool = platform::db::mysql_pool(&cfg.database).await.expect("mysql");
    let app = format!("rs_scratch_runs_{}", crate::scheduler::now_millis() % 1_000_000_007);
    let dao = MySqlEventRunDao::new(pool.clone());

    let outcome = std::panic::AssertUnwindSafe(exercise(&dao, &pool, &app)).catch_unwind().await;

    let cleaned = sqlx::query("DELETE FROM core_event_runs WHERE APP_CODE = ?").bind(&app).execute(&pool).await.expect("cleanup");
    let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM core_event_runs WHERE APP_CODE = ?").bind(&app).fetch_one(&pool).await.unwrap();
    assert_eq!(left, 0);
    let _ = cleaned;
    if let Err(p) = outcome {
        std::panic::resume_unwind(p);
    }
}

async fn exercise(dao: &MySqlEventRunDao, pool: &sqlx::MySqlPool, app: &str) {
    let ancient = ts(1000, 1, 2, 0, 0);
    let run = |client: &str, event: &str, status: RunStatus, started: NaiveDateTime| EventRun {
        app_code: Some(app.into()),
        client_code: Some(client.into()),
        event_name: Some(event.into()),
        trigger_type: Some(TriggerType::Schedule),
        status: Some(status),
        schedule_run_id: Some("r-1".into()),
        scheduled_for: Some(started),
        attempt: Some(2),
        is_draft: Some(true),
        triggered_by: Some(142),
        task_count: Some(2),
        instance_id: Some("rs-test".into()),
        started_at: Some(started),
        ..Default::default()
    };

    // insert, read, finish: every column round trips.
    let id = dao.insert(&run("SYSTEM", "JOB", RunStatus::Running, ancient)).await.unwrap();
    let back = dao.read(id).await.unwrap().unwrap();
    assert_eq!((back.app_code.as_deref(), back.client_code.as_deref(), back.status, back.trigger_type), (Some(app), Some("SYSTEM"), Some(RunStatus::Running), Some(TriggerType::Schedule)));
    assert_eq!((back.attempt, back.is_draft, back.triggered_by, back.task_count, back.failed_task_count), (Some(2), Some(true), Some(142), Some(2), Some(0)));
    assert_eq!((back.scheduled_for, back.started_at, back.finished_at, back.tasks), (Some(ancient), Some(ancient), None, Some(vec![])));
    let tasks = vec![
        EventRunTask { key: Some("a".into()), task_type: Some("CALL_CORE_FUNCTION".into()), order: Some(1), status: Some(TaskStatus::Success), duration_ms: Some(4), ..Default::default() },
        EventRunTask { key: Some("b".into()), status: Some(TaskStatus::Failed), error: Some("boom é".into()), detail: Some("d\nline".into()), ..Default::default() },
    ];
    let finished_at = ancient + TimeDelta::milliseconds(1234);
    assert!(dao.finish(id, RunStatus::Failed, &tasks, 1, Some("1 task failed"), finished_at, 1234).await.unwrap());
    let back = dao.read(id).await.unwrap().unwrap();
    assert_eq!((back.status, back.tasks.as_ref(), back.failed_task_count, back.error.as_deref()), (Some(RunStatus::Failed), Some(&tasks), Some(1), Some("1 task failed")));
    assert_eq!((back.finished_at, back.duration_ms), (Some(finished_at), Some(1234)));
    assert!(!dao.finish(u64::MAX, RunStatus::Failed, &[], 0, None, finished_at, 0).await.unwrap());
    assert!(dao.read(u64::MAX).await.unwrap().is_none());
    // A NOT NULL column left empty is refused, as jOOQ's insert is.
    assert!(dao.insert(&EventRun { app_code: Some(app.into()), ..Default::default() }).await.is_err());

    // readPage / distinctClients / latestPerClient.
    let second = dao.insert(&run("FIN", "JOB", RunStatus::Success, ancient + TimeDelta::hours(1))).await.unwrap();
    let third = dao.insert(&run("FIN", "OTHER", RunStatus::Success, ancient + TimeDelta::hours(2))).await.unwrap();
    let filter = RunFilter { app_code: app.into(), client_codes: vec!["SYSTEM".into(), "FIN".into()], event_name: Some("JOB".into()), ..Default::default() };
    let page = dao.read_page(&filter, &Pageable::of(0, 1, Sort::unsorted())).await.unwrap();
    assert_eq!((page.total, page.content.iter().map(|r| r.id.unwrap()).collect::<Vec<_>>()), (2, vec![second]));
    let page = dao.read_page(&filter, &Pageable::of(1, 1, Sort::unsorted())).await.unwrap();
    assert_eq!(page.content[0].id, Some(id));
    let one = RunFilter { client_codes: vec!["FIN".into()], event_name: None, status: Some(RunStatus::Success), trigger_type: Some(TriggerType::Schedule), from: Some(ancient + TimeDelta::hours(2)), to: Some(ancient + TimeDelta::hours(3)), ..filter.clone() };
    assert_eq!(dao.read_page(&one, &Pageable::of(0, 20, Sort::unsorted())).await.unwrap().content.iter().map(|r| r.id.unwrap()).collect::<Vec<_>>(), [third]);
    assert_eq!(dao.read_page(&RunFilter { client_codes: vec![], ..filter.clone() }, &Pageable::of(0, 20, Sort::unsorted())).await.unwrap().total, 0);
    let mut clients = dao.distinct_clients(app, Some("JOB"), 10).await.unwrap();
    clients.sort();
    assert_eq!(clients, ["FIN", "SYSTEM"]);
    assert_eq!(dao.distinct_clients(app, Some("OTHER"), 10).await.unwrap(), ["FIN"]);
    assert_eq!(dao.distinct_clients(app, None, 1).await.unwrap().len(), 1);
    let latest = dao.latest_per_client(app, "JOB", &["FIN".into(), "NOPE".into(), "SYSTEM".into()]).await.unwrap();
    assert_eq!(latest.iter().map(|r| r.id.unwrap()).collect::<Vec<_>>(), [second, id]);

    // The sweep's statements reach the whole table: only rows from before 1001 are ever asked
    // for, and there must be none but this run's.
    let before = ts(1001, 1, 1, 0, 0);
    let foreign: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM core_event_runs WHERE STARTED_AT < ? AND APP_CODE <> ?")
        .bind(before)
        .bind(app)
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(foreign, 0, "rows from before 1001 that are not this test's: the sweep is not exercised");
    let running = dao.insert(&run("SYSTEM", "JOB", RunStatus::Running, ancient)).await.unwrap();
    assert_eq!(dao.fail_running_started_before(before, "stale", ancient).await.unwrap(), 1);
    let closed = dao.read(running).await.unwrap().unwrap();
    assert_eq!((closed.status, closed.error.as_deref(), closed.finished_at), (Some(RunStatus::Failed), Some("stale"), Some(ancient)));
    assert_eq!(dao.delete_started_before(before, Some(RunStatus::Success), 1).await.unwrap(), 1);
    assert_eq!(dao.delete_started_before(before, Some(RunStatus::Success), 10).await.unwrap(), 1);
    assert_eq!(dao.delete_started_before(before, None, 10).await.unwrap(), 2);
    let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM core_event_runs WHERE APP_CODE = ?").bind(app).fetch_one(pool).await.unwrap();
    assert_eq!(left, 0);
}
