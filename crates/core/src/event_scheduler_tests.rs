//! `EventSchedulerTest`, `ScheduledEventTest` and `EventSchedulerInactiveClientTest` over
//! `AbstractSchedulerMongoTest`: a real Mongo (a scratch database of the local stack per test,
//! dropped after it), fake definitions, a fake security and a fake raiser.
//!
//! `EventSchedulerInProcessTest` and the in-process half of the inactive-client test are not
//! ported: core-scheduler never runs work itself, it always publishes (Java's no-runner mode).

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use chrono::DateTime as ChronoDateTime;
use futures::TryStreamExt;
use mongodb::bson::{doc, Document};
use mongodb::Database;
use parking_lot::Mutex;
use serde_json::{json, Value};

use super::*;
use crate::scheduler::{json_util_map, OneOffs, ScheduleRequest, Scheduled, Status};

const APP: &str = "leadzumptwo";
const SWEEP: &str = "outboxSweep";
const REMIND: &str = "taskReminder";

fn at(iso: &str) -> i64 {
    ChronoDateTime::parse_from_rfc3339(iso).unwrap().timestamp_millis()
}

#[derive(Default)]
struct FakeDefinitions(Mutex<HashMap<(String, String), EventSchedule>>);

impl FakeDefinitions {
    fn put(&self, client: &str, event: &str, schedule: EventSchedule) {
        self.0.lock().insert((event.into(), client.into()), schedule);
    }
}

#[async_trait]
impl EffectiveDefinitions for FakeDefinitions {
    async fn read_effective(&self, name: &str, app_code: &str, client_code: &str) -> Result<Option<JMap>, CoreError> {
        let Some(s) = self.0.lock().get(&(name.to_string(), client_code.to_string())).cloned() else { return Ok(None) };
        let mut m = JMap::new();
        m.insert("name".into(), overridable::JValue::Str(name.into()));
        m.insert("appCode".into(), overridable::JValue::Str(app_code.into()));
        m.insert("schedule".into(), s.to_j());
        Ok(Some(m))
    }
}

#[derive(Default)]
struct FakeSecurity {
    write_access_down: AtomicBool,
    write_access: Mutex<HashMap<String, Vec<String>>>,
    write_access_calls: AtomicUsize,
    not_active: Mutex<HashSet<String>>,
    status_calls: AtomicUsize,
    status_down: AtomicBool,
}

#[async_trait]
impl ClientDirectory for FakeSecurity {
    async fn write_access_client_codes(&self, app_code: &str) -> Result<Option<Vec<String>>, CoreError> {
        self.write_access_calls.fetch_add(1, Ordering::SeqCst);
        if self.write_access_down.load(Ordering::SeqCst) {
            return Err(CoreError::unknown("security down"));
        }
        Ok(Some(self.write_access.lock().get(app_code).cloned().unwrap_or_default()))
    }
    async fn active_client_codes(&self, codes: &[String]) -> Result<Option<Vec<String>>, CoreError> {
        self.status_calls.fetch_add(1, Ordering::SeqCst);
        if self.status_down.load(Ordering::SeqCst) {
            return Err(CoreError::unknown("security down"));
        }
        let not = self.not_active.lock();
        Ok(Some(codes.iter().filter(|c| !not.contains(*c)).cloned().collect()))
    }
}

#[derive(Default)]
struct FakeEvents {
    raised: Mutex<Vec<(EventMessage, bool)>>,
    failing: AtomicBool,
}

impl FakeEvents {
    fn of(&self, client: &str, event: &str) -> Vec<EventMessage> {
        self.raised
            .lock()
            .iter()
            .filter(|(q, _)| q.client_code.as_deref() == Some(client) && q.event_name.as_deref() == Some(event))
            .map(|(q, _)| q.clone())
            .collect()
    }
    fn all(&self) -> Vec<EventMessage> {
        self.raised.lock().iter().map(|(q, _)| q.clone()).collect()
    }
}

#[async_trait]
impl EventRaiser for FakeEvents {
    async fn create_event(&self, event: EventMessage, draft: bool) -> Result<bool, CoreError> {
        if self.failing.load(Ordering::SeqCst) {
            return Err(CoreError::unknown("broker down"));
        }
        self.raised.lock().push((event, draft));
        Ok(true)
    }
}

#[derive(Default)]
struct FakeRunLog(Mutex<Vec<(String, Unrun, String)>>);

#[async_trait]
impl RunLog for FakeRunLog {
    async fn record(&self, event: &EventMessage, status: Unrun, error: &str) {
        self.0.lock().push((event.client_code.clone().unwrap_or_default(), status, error.to_string()));
    }
}

struct Instance {
    scheduler: Arc<EventScheduler>,
    one_offs: Arc<ScheduledEventService>,
    completion: RunCompletion,
}

struct Harness {
    db: Database,
    clock: Arc<AtomicI64>,
    definitions: Arc<FakeDefinitions>,
    security: Arc<FakeSecurity>,
    events: Arc<FakeEvents>,
    run_log: Arc<FakeRunLog>,
}

fn settings() -> EventSchedulerSettings {
    let mut s = EventSchedulerSettings::default();
    s.tick_ms = 30_000;
    s.lease_seconds = 300;
    s.catch_up_window_minutes = 1500;
    s.clients_refresh_seconds = 300;
    s.concurrency = 8;
    s.oneoff.batch_size = 500;
    s.oneoff.max_attempts = 3;
    s.oneoff.backoff_base_seconds = 30;
    s.oneoff.backoff_max_seconds = 3600;
    s
}

impl Harness {
    fn new(db: Database) -> Self {
        Self {
            db,
            clock: Arc::new(AtomicI64::new(at("2026-10-09T09:00:10Z"))),
            definitions: Arc::default(),
            security: Arc::default(),
            events: Arc::default(),
            run_log: Arc::default(),
        }
    }

    fn set(&self, iso: &str) {
        self.clock.store(at(iso), Ordering::SeqCst);
    }

    fn advance(&self, seconds: i64) {
        self.clock.fetch_add(seconds * 1000, Ordering::SeqCst);
    }

    fn now(&self) -> i64 {
        self.clock.load(Ordering::SeqCst)
    }

    fn instance(&self) -> Instance {
        self.instance_with(settings())
    }

    fn instance_with(&self, settings: EventSchedulerSettings) -> Instance {
        let c = self.clock.clone();
        let clock: Clock = Arc::new(move || c.load(Ordering::SeqCst));
        let store = Arc::new(ScheduleStore::new(self.db.clone(), settings.clone()));
        let one_offs = Arc::new(ScheduledEventService::new(store.clone(), settings.clone()).with_clock(clock.clone()));
        let scheduler = EventScheduler::new(
            self.definitions.clone(),
            self.security.clone(),
            self.events.clone(),
            store.clone(),
            one_offs.clone(),
            settings,
        )
        .with_clock(clock.clone())
        .with_run_log(self.run_log.clone());
        let completion = RunCompletion::new(store, one_offs.clone()).with_clock(clock);
        Instance { scheduler: Arc::new(scheduler), one_offs, completion }
    }

    async fn store_definition(&self, client: &str, event: &str, schedule: EventSchedule) {
        let d = doc! {"name": event, "appCode": APP, "clientCode": client, "schedule": schedule.to_bson()};
        self.db.collection::<Document>(crate::docs::EVENT_DEFINITION_COLLECTION).insert_one(d).await.unwrap();
    }

    async fn runs(&self, client: &str, event: &str) -> Vec<ScheduleRun> {
        ScheduleStore::new(self.db.clone(), settings()).runs_of(APP, client, event).await.unwrap()
    }

    async fn ticks(&self, client: &str, event: &str) -> Vec<i64> {
        self.runs(client, event)
            .await
            .into_iter()
            .filter(|r| r.status != Some(RunState::Skipped))
            .map(|r| r.tick_at.timestamp_millis())
            .collect()
    }

    async fn row(&self, key: &str) -> ScheduledEvent {
        let d = self.db.collection::<Document>(crate::scheduler::SCHEDULED_EVENT_COLLECTION).find_one(doc! {"key": key}).await.unwrap();
        ScheduledEvent::from_document(&d.unwrap())
    }

    async fn rows(&self) -> Vec<ScheduledEvent> {
        let docs: Vec<Document> = self
            .db
            .collection::<Document>(crate::scheduler::SCHEDULED_EVENT_COLLECTION)
            .find(doc! {})
            .await
            .unwrap()
            .try_collect()
            .await
            .unwrap();
        docs.iter().map(ScheduledEvent::from_document).collect()
    }

    async fn schedule(&self, i: &Instance, client: &str, draft: bool, key: &str, run_at: i64, data: Value) -> Scheduled {
        i.one_offs
            .schedule(ScheduleRequest {
                app_code: APP.into(),
                client_code: client.into(),
                draft,
                event_name: REMIND.into(),
                data: json_util_map(data.as_object().unwrap()),
                run_at: Some(run_at),
                key: key.into(),
                scheduled_by: Some("110".into()),
            })
            .await
            .unwrap()
    }

    fn per_client_sweep(&self, writers: &[&str], with_definition: &[&str]) -> impl std::future::Future<Output = ()> + '_ {
        self.security.write_access.lock().insert(APP.into(), writers.iter().map(|s| s.to_string()).collect());
        for c in with_definition {
            self.definitions.put(c, SWEEP, every_minute(true));
        }
        self.store_definition("SYSTEM", SWEEP, every_minute(true))
    }
}

fn every_minute(per_client: bool) -> EventSchedule {
    EventSchedule { cron: Some("* * * * *".into()), per_client: Some(per_client), ..Default::default() }
}

fn marker(q: &EventMessage) -> serde_json::Map<String, Value> {
    schedule_marker(q).cloned().unwrap()
}

/// Runs `body` on a fresh scratch database of the local stack, dropped afterwards.
async fn on_scratch<F, Fut>(body: F)
where
    F: FnOnce(Harness) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    use futures::FutureExt;
    if !crate::testing::local_stack() {
        return;
    }
    let uri = std::env::var("MODLIX__MONGO__URI").ok().filter(|u| !u.is_empty()).unwrap_or_else(|| "mongodb://localhost:27017".into());
    let client = mongodb::Client::with_uri_str(&uri).await.unwrap();
    let name = format!("rs_scratch_sched_{}", mongodb::bson::oid::ObjectId::new().to_hex());
    let db = client.database(&name);
    let outcome = std::panic::AssertUnwindSafe(body(Harness::new(db.clone()))).catch_unwind().await;
    db.drop().await.unwrap();
    if let Err(p) = outcome {
        std::panic::resume_unwind(p);
    }
}

async fn complete(i: &Instance, q: &EventMessage, ok: bool) {
    i.completion.track(q, async { Ok::<_, CoreError>(Some(ok)) }).await.unwrap();
}

const GATE: &str = "needs the local stack: CORE_LOCAL_STACK=1 and config/local.env";

// ---------------------------------------------------------------- EventSchedulerTest

#[tokio::test]
#[ignore = "needs the local stack: CORE_LOCAL_STACK=1 and config/local.env"]
async fn two_instances_racing_raise_each_tick_exactly_once() {
    let _ = GATE;
    on_scratch(|h| async move {
        let clients: Vec<String> = (0..12).map(|i| format!("CL{i}")).collect();
        let refs: Vec<&str> = clients.iter().map(String::as_str).collect();
        h.per_client_sweep(&refs, &refs).await;
        let (a, b) = (h.instance(), h.instance());
        let mut lost = 0;
        for minute in 0..5 {
            h.clock.store(at("2026-10-09T09:00:05Z") + 60_000 * minute, Ordering::SeqCst);
            for _ in 0..3 {
                let (ra, rb) = tokio::join!(a.scheduler.pass(), b.scheduler.pass());
                lost += ra.unwrap().lost + rb.unwrap().lost;
            }
            // A tick that has been dealt with is not run again by a later pass either.
            a.scheduler.pass().await.unwrap();
            // The listener finishing each run, so the next tick is not held back by its lease.
            for q in h.events.all() {
                complete(&a, &q, true).await;
            }
        }
        assert!(lost > 0, "the instances really did contend for the same ticks");
        for c in &clients {
            let rows = h.runs(c, SWEEP).await;
            assert_eq!(rows.len(), 5, "one row per tick for {c}");
            assert_eq!(h.events.of(c, SWEEP).len(), 5, "one raised event per tick for {c}");
            assert_eq!(rows.iter().map(|r| r.tick_at).collect::<HashSet<_>>().len(), 5);
            assert!(rows.iter().all(|r| r.status == Some(RunState::Done)));
        }
    })
    .await;
}

#[tokio::test]
#[ignore = "needs the local stack: CORE_LOCAL_STACK=1 and config/local.env"]
async fn instances_with_skewed_clocks_agree_on_the_tick() {
    on_scratch(|h| async move {
        h.per_client_sweep(&["FIN"], &["FIN"]).await;
        let (a, b) = (h.instance(), h.instance());
        h.set("2026-10-09T09:00:02Z");
        a.scheduler.pass().await.unwrap();
        h.set("2026-10-09T09:00:41Z");
        b.scheduler.pass().await.unwrap();
        let rows = h.runs("FIN", SWEEP).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].tick_at.timestamp_millis(), at("2026-10-09T09:00:00Z"));
        assert_eq!(h.events.of("FIN", SWEEP).len(), 1);
    })
    .await;
}

#[tokio::test]
#[ignore = "needs the local stack: CORE_LOCAL_STACK=1 and config/local.env"]
async fn each_client_runs_on_its_own_effective_schedule() {
    on_scratch(|h| async move {
        let report = "dailyReport";
        let base = EventSchedule { cron: Some("0 9 * * *".into()), per_client: Some(true), ..Default::default() };
        h.security.write_access.lock().insert(APP.into(), vec!["FIN".into(), "FIN2".into(), "FIN3".into(), "FIN4".into()]);
        h.store_definition("SYSTEM", report, base.clone()).await;
        let o2 = EventSchedule { cron: Some("0 10 * * *".into()), ..Default::default() };
        let o3 = EventSchedule { enabled: Some(false), ..Default::default() };
        let o4 = EventSchedule { timezone: Some("Asia/Kolkata".into()), ..Default::default() };
        h.store_definition("FIN2", report, o2.clone()).await;
        h.store_definition("FIN3", report, o3.clone()).await;
        h.store_definition("FIN4", report, o4.clone()).await;
        h.definitions.put("FIN", report, base.clone());
        h.definitions.put("FIN2", report, EventSchedule::merge(Some(&o2), Some(&base)).unwrap());
        h.definitions.put("FIN3", report, EventSchedule::merge(Some(&o3), Some(&base)).unwrap());
        h.definitions.put("FIN4", report, EventSchedule::merge(Some(&o4), Some(&base)).unwrap());
        let a = h.instance();
        // 09:00 Kolkata is 03:30 UTC: only FIN4.
        h.set("2026-10-09T03:30:05Z");
        a.scheduler.pass().await.unwrap();
        h.set("2026-10-09T09:00:05Z");
        a.scheduler.pass().await.unwrap();
        h.set("2026-10-09T10:00:05Z");
        a.scheduler.pass().await.unwrap();
        assert_eq!(h.ticks("FIN4", report).await, [at("2026-10-09T03:30:00Z")]);
        assert_eq!(h.ticks("FIN", report).await, [at("2026-10-09T09:00:00Z")]);
        assert_eq!(h.ticks("FIN2", report).await, [at("2026-10-09T10:00:00Z")]);
        assert!(h.ticks("FIN3", report).await.is_empty(), "enabled: false on the override stops that client");
        assert!(h.events.of("FIN3", report).is_empty());
    })
    .await;
}

#[tokio::test]
#[ignore = "needs the local stack: CORE_LOCAL_STACK=1 and config/local.env"]
async fn a_client_without_write_access_gets_no_run() {
    on_scratch(|h| async move {
        h.per_client_sweep(&["FIN", "FIN2"], &["FIN", "FIN2", "OUTSIDER"]).await;
        h.instance().scheduler.pass().await.unwrap();
        assert_eq!(h.events.of("FIN", SWEEP).len(), 1);
        assert_eq!(h.events.of("FIN2", SWEEP).len(), 1);
        assert!(h.events.of("OUTSIDER", SWEEP).is_empty());
        assert!(h.runs("OUTSIDER", SWEEP).await.is_empty());
    })
    .await;
}

#[tokio::test]
#[ignore = "needs the local stack: CORE_LOCAL_STACK=1 and config/local.env"]
async fn a_single_run_schedule_runs_only_for_the_client_holding_it() {
    on_scratch(|h| async move {
        let cleanup = "nightlyCleanup";
        let s = EventSchedule { cron: Some("* * * * *".into()), ..Default::default() };
        h.store_definition("FIN", cleanup, s.clone()).await;
        h.definitions.put("FIN", cleanup, s.clone());
        h.definitions.put("FIN2", cleanup, s);
        h.instance().scheduler.pass().await.unwrap();
        assert_eq!(h.events.of("FIN", cleanup).len(), 1);
        assert!(h.events.of("FIN2", cleanup).is_empty());
        assert_eq!(h.security.write_access_calls.load(Ordering::SeqCst), 0, "no perClient anywhere, so security is never asked");
    })
    .await;
}

#[tokio::test]
#[ignore = "needs the local stack: CORE_LOCAL_STACK=1 and config/local.env"]
async fn the_raised_event_carries_its_run_and_completion_closes_it() {
    on_scratch(|h| async move {
        h.per_client_sweep(&["FIN"], &["FIN"]).await;
        let a = h.instance();
        let report = a.scheduler.pass().await.unwrap();
        assert_eq!(report.to_string(), "PassReport[raised=1, skipped=0, lost=0, failed=0, oneOffsRaised=0, oneOffsFailed=0, busy=0]");
        let raised = h.events.of("FIN", SWEEP)[0].clone();
        assert_eq!(raised.app_code.as_deref(), Some(APP));
        assert!(raised.authentication.is_none());
        let m = marker(&raised);
        assert_eq!((m["kind"].clone(), m["tickAt"].clone()), (json!(KIND_CRON), json!("2026-10-09T09:00:00Z")));
        let row = &h.runs("FIN", SWEEP).await[0];
        assert_eq!(row.status, Some(RunState::Running));
        assert_eq!(m["runId"], json!(row.id));
        // As Spring Data inserts the row.
        let stored = h.db.collection::<Document>("schedule_run").find_one(doc! {}).await.unwrap().unwrap();
        assert_eq!(
            stored.keys().map(String::as_str).collect::<Vec<_>>(),
            ["_id", "appCode", "clientCode", "eventName", "tickAt", "status", "leaseUntil", "owner", "createdAt"]
        );
        complete(&a, &raised, true).await;
        assert_eq!(h.runs("FIN", SWEEP).await[0].status, Some(RunState::Done));
        h.advance(60);
        a.scheduler.pass().await.unwrap();
        let second = h.events.of("FIN", SWEEP)[1].clone();
        complete(&a, &second, false).await;
        let rows = h.runs("FIN", SWEEP).await;
        assert_eq!((rows[1].status, rows[1].error.as_deref()), (Some(RunState::Failed), Some("The EventAction reported a failure")));
        // An error is recorded as the failure and passed on.
        h.advance(60);
        a.scheduler.pass().await.unwrap();
        let third = h.events.of("FIN", SWEEP)[2].clone();
        let r = a.completion.track(&third, async { Err::<Option<bool>, _>(CoreError::unknown("tasks blew up")) }).await;
        assert!(r.is_err());
        assert_eq!(h.runs("FIN", SWEEP).await[2].error.as_deref(), Some("tasks blew up"));
        // Nothing ran (no action) counts as done.
        h.advance(60);
        a.scheduler.pass().await.unwrap();
        let fourth = h.events.of("FIN", SWEEP)[3].clone();
        assert_eq!(a.completion.track(&fourth, async { Ok::<_, CoreError>(None) }).await.unwrap(), Some(true));
        assert_eq!(h.runs("FIN", SWEEP).await[3].status, Some(RunState::Done));
        // An event that did not come from the scheduler passes straight through.
        let plain = EventMessage { event_name: Some("other".into()), ..Default::default() };
        assert_eq!(a.completion.track(&plain, async { Ok::<_, CoreError>(Some(true)) }).await.unwrap(), Some(true));
        // A marker that names nothing closes nothing.
        let odd = EventMessage { data: Some(json!({"_schedule": {"kind": "cron"}}).as_object().unwrap().clone()), ..Default::default() };
        assert_eq!(a.completion.track(&odd, async { Ok::<_, CoreError>(Some(true)) }).await.unwrap(), Some(true));
    })
    .await;
}

#[tokio::test]
#[ignore = "needs the local stack: CORE_LOCAL_STACK=1 and config/local.env"]
async fn a_tick_whose_predecessor_is_still_running_is_skipped_until_the_lease_runs_out() {
    on_scratch(|h| async move {
        h.per_client_sweep(&["FIN"], &["FIN"]).await;
        let mut s = settings();
        s.lease_seconds = 150;
        let a = h.instance_with(s);
        a.scheduler.pass().await.unwrap();
        h.set("2026-10-09T09:01:05Z");
        a.scheduler.pass().await.unwrap();
        h.set("2026-10-09T09:02:05Z");
        a.scheduler.pass().await.unwrap();
        h.set("2026-10-09T09:03:05Z");
        a.scheduler.pass().await.unwrap();
        let states: Vec<_> = h.runs("FIN", SWEEP).await.iter().map(|r| r.status).collect();
        assert_eq!(states, [Some(RunState::Running), Some(RunState::Skipped), Some(RunState::Skipped), Some(RunState::Running)]);
        assert_eq!(h.events.of("FIN", SWEEP).len(), 2);
        // The skips are in the run log.
        let log = h.run_log.0.lock();
        assert_eq!(log.len(), 2);
        assert_eq!((log[0].1, log[0].2.as_str()), (Unrun::Skipped, "Skipped: the run for the previous tick was still going."));
    })
    .await;
}

#[tokio::test]
#[ignore = "needs the local stack: CORE_LOCAL_STACK=1 and config/local.env"]
async fn an_outage_catches_up_only_the_latest_missed_tick() {
    on_scratch(|h| async move {
        let sync = "campaignSync";
        let every_ten = EventSchedule { cron: Some("*/10 * * * *".into()), per_client: Some(true), ..Default::default() };
        h.security.write_access.lock().insert(APP.into(), vec!["FIN".into()]);
        h.store_definition("SYSTEM", sync, every_ten.clone()).await;
        h.definitions.put("FIN", sync, every_ten);
        let a = h.instance();
        a.scheduler.pass().await.unwrap();
        complete(&a, &h.events.of("FIN", sync)[0], true).await;
        // Down from 09:00 to 09:35; a fresh instance, so nothing is remembered in memory either.
        h.set("2026-10-09T09:35:00Z");
        h.instance().scheduler.pass().await.unwrap();
        assert_eq!(h.ticks("FIN", sync).await, [at("2026-10-09T09:00:00Z"), at("2026-10-09T09:30:00Z")]);
        assert_eq!(h.events.of("FIN", sync).len(), 2);
    })
    .await;
}

#[tokio::test]
#[ignore = "needs the local stack: CORE_LOCAL_STACK=1 and config/local.env"]
async fn a_new_schedule_does_not_fire_for_a_tick_it_never_had() {
    on_scratch(|h| async move {
        let report = "dailyReport";
        let daily = EventSchedule { cron: Some("0 2 * * *".into()), per_client: Some(true), ..Default::default() };
        h.security.write_access.lock().insert(APP.into(), vec!["FIN".into()]);
        h.store_definition("SYSTEM", report, daily.clone()).await;
        h.definitions.put("FIN", report, daily);
        let a = h.instance();
        a.scheduler.pass().await.unwrap();
        assert!(h.ticks("FIN", report).await.is_empty());
        h.set("2026-10-10T02:00:20Z");
        a.scheduler.pass().await.unwrap();
        assert_eq!(h.ticks("FIN", report).await, [at("2026-10-10T02:00:00Z")]);
    })
    .await;
}

#[tokio::test]
#[ignore = "needs the local stack: CORE_LOCAL_STACK=1 and config/local.env"]
async fn a_failed_raise_is_recorded_as_failed() {
    on_scratch(|h| async move {
        h.per_client_sweep(&["FIN"], &["FIN"]).await;
        h.events.failing.store(true, Ordering::SeqCst);
        let report = h.instance().scheduler.pass().await.unwrap();
        assert_eq!(report.failed, 1);
        let row = &h.runs("FIN", SWEEP).await[0];
        assert_eq!(row.status, Some(RunState::Failed));
        assert!(row.error.as_deref().unwrap().contains("broker down"));
        let log = h.run_log.0.lock();
        assert_eq!((log[0].1, log[0].2.as_str()), (Unrun::Failed, "The scheduler could not raise the event: broker down"));
    })
    .await;
}

#[tokio::test]
#[ignore = "needs the local stack: CORE_LOCAL_STACK=1 and config/local.env"]
async fn a_schedule_it_cannot_read_is_skipped_and_the_others_still_run() {
    on_scratch(|h| async move {
        let bad = EventSchedule { cron: Some("not a cron".into()), ..Default::default() };
        let zone = EventSchedule { cron: Some("* * * * *".into()), timezone: Some("Mars/Base".into()), ..Default::default() };
        h.store_definition("FIN", "bad", bad.clone()).await;
        h.store_definition("FIN", "zone", zone.clone()).await;
        h.store_definition("FIN", SWEEP, every_minute(false)).await;
        h.definitions.put("FIN", "bad", bad);
        h.definitions.put("FIN", "zone", zone);
        h.definitions.put("FIN", SWEEP, every_minute(false));
        h.instance().scheduler.pass().await.unwrap();
        assert_eq!(h.events.all().len(), 1);
        assert_eq!(h.events.of("FIN", SWEEP).len(), 1);
        // A definition stored without an app is left alone; a perClient of the wrong type stops
        // the recurring half of the pass, as Spring's read does.
        h.db.collection::<Document>(crate::docs::EVENT_DEFINITION_COLLECTION)
            .insert_one(doc! {"name": "x", "clientCode": "FIN", "schedule": {"cron": "* * * * *"}})
            .await
            .unwrap();
        h.advance(60);
        h.instance().scheduler.pass().await.unwrap();
        h.db.collection::<Document>(crate::docs::EVENT_DEFINITION_COLLECTION)
            .insert_one(doc! {"name": "y", "appCode": APP, "clientCode": "FIN", "schedule": {"perClient": "yes"}})
            .await
            .unwrap();
        assert!(h.instance().scheduler.pass().await.is_err());
    })
    .await;
}

// ---------------------------------------------------------------- ScheduledEventTest

#[tokio::test]
#[ignore = "needs the local stack: CORE_LOCAL_STACK=1 and config/local.env"]
async fn a_due_one_off_is_raised_with_its_data_and_closed_on_success() {
    on_scratch(|h| async move {
        let a = h.instance();
        h.schedule(&a, "FIN", false, "task-1", h.now() + 60_000, json!({"taskId": "t1"})).await;
        a.scheduler.pass().await.unwrap();
        assert!(h.events.all().is_empty(), "not due yet");
        h.advance(61);
        a.scheduler.pass().await.unwrap();
        let raised = h.events.of("FIN", REMIND)[0].clone();
        assert_eq!(raised.app_code.as_deref(), Some(APP));
        assert_eq!(raised.data.as_ref().unwrap()["taskId"], json!("t1"));
        assert_eq!((marker(&raised)["key"].clone(), marker(&raised)["attempt"].clone()), (json!("task-1"), json!(1)));
        assert_eq!(h.row("task-1").await.status, Some(Status::Claimed));
        complete(&a, &raised, true).await;
        assert_eq!(h.row("task-1").await.status, Some(Status::Done));
        h.advance(3600);
        a.scheduler.pass().await.unwrap();
        assert_eq!(h.events.all().len(), 1, "a finished one-off is never raised again");
    })
    .await;
}

#[tokio::test]
#[ignore = "needs the local stack: CORE_LOCAL_STACK=1 and config/local.env"]
async fn a_failure_retries_with_doubling_backoff_then_fails() {
    on_scratch(|h| async move {
        let a = h.instance();
        let t0 = h.now();
        h.schedule(&a, "FIN", false, "outbox-9", t0, json!({})).await;
        a.scheduler.pass().await.unwrap();
        complete(&a, &h.events.all().last().unwrap().clone(), false).await;
        let after1 = h.row("outbox-9").await;
        assert_eq!((after1.status, after1.attempts), (Some(Status::Pending), 1));
        assert_eq!(after1.run_at.unwrap().timestamp_millis(), t0 + 30_000);
        assert!(after1.last_error.is_some());
        h.clock.store(t0 + 29_000, Ordering::SeqCst);
        a.scheduler.pass().await.unwrap();
        assert_eq!(h.events.all().len(), 1);
        h.clock.store(t0 + 30_000, Ordering::SeqCst);
        a.scheduler.pass().await.unwrap();
        assert_eq!(h.events.all().len(), 2);
        let second = h.events.all().last().unwrap().clone();
        assert_eq!(marker(&second)["attempt"], json!(2));
        let _ = a.completion.track(&second, async { Err::<Option<bool>, _>(CoreError::unknown("boom")) }).await;
        assert_eq!(h.row("outbox-9").await.run_at.unwrap().timestamp_millis(), t0 + 90_000, "second wait doubles");
        h.clock.store(t0 + 90_000, Ordering::SeqCst);
        a.scheduler.pass().await.unwrap();
        complete(&a, &h.events.all().last().unwrap().clone(), false).await;
        let failed = h.row("outbox-9").await;
        assert_eq!((failed.status, failed.attempts), (Some(Status::Failed), 3), "3 attempts is the maximum here");
        assert!(failed.finished_at.is_some());
        h.advance(7200);
        a.scheduler.pass().await.unwrap();
        assert_eq!(h.events.all().len(), 3);
    })
    .await;
}

#[tokio::test]
#[ignore = "needs the local stack: CORE_LOCAL_STACK=1 and config/local.env"]
async fn a_claim_whose_instance_died_is_reclaimed_after_its_lease() {
    on_scratch(|h| async move {
        let a = h.instance();
        h.schedule(&a, "FIN", false, "expiry-3", h.now(), json!({})).await;
        a.scheduler.pass().await.unwrap();
        let first = h.events.all()[0].clone();
        h.advance(200);
        h.instance().scheduler.pass().await.unwrap();
        assert_eq!(h.events.all().len(), 1);
        h.advance(101);
        let b = h.instance();
        b.scheduler.pass().await.unwrap();
        assert_eq!(h.events.all().len(), 2);
        let second = h.events.all()[1].clone();
        assert_eq!(marker(&second)["attempt"], json!(2));
        // The dead claim reporting late changes nothing; the live one closes the row.
        complete(&a, &first, true).await;
        assert_eq!(h.row("expiry-3").await.status, Some(Status::Claimed));
        assert_ne!(marker(&first)["claimToken"], marker(&second)["claimToken"]);
        complete(&b, &second, true).await;
        assert_eq!(h.row("expiry-3").await.status, Some(Status::Done));
        // A failure reported under a claim that is not the row's changes nothing either.
        complete(&a, &first, false).await;
        assert_eq!(h.row("expiry-3").await.status, Some(Status::Done));
    })
    .await;
}

#[tokio::test]
#[ignore = "needs the local stack: CORE_LOCAL_STACK=1 and config/local.env"]
async fn cancel_stops_a_pending_one_off() {
    on_scratch(|h| async move {
        let a = h.instance();
        h.schedule(&a, "FIN", false, "reminder-5", h.now() + 10_000, json!({})).await;
        assert!(a.one_offs.cancel(APP, "FIN", false, "reminder-5").await.unwrap());
        assert_eq!(h.row("reminder-5").await.status, Some(Status::Cancelled));
        assert!(!a.one_offs.cancel(APP, "FIN", false, "reminder-5").await.unwrap(), "already cancelled");
        assert!(!a.one_offs.cancel(APP, "FIN", false, "never-scheduled").await.unwrap());
        assert!(!a.one_offs.cancel(APP, "FIN2", false, "reminder-5").await.unwrap(), "another client's key");
        h.advance(60);
        a.scheduler.pass().await.unwrap();
        assert!(h.events.all().is_empty());
        assert!(h.schedule(&a, "FIN", false, "reminder-5", h.now(), json!({})).await.event.is_some());
        a.scheduler.pass().await.unwrap();
        assert_eq!(h.events.all().len(), 1);
    })
    .await;
}

#[tokio::test]
#[ignore = "needs the local stack: CORE_LOCAL_STACK=1 and config/local.env"]
async fn rescheduling_a_key_replaces_the_pending_one() {
    on_scratch(|h| async move {
        let a = h.instance();
        let now = h.now();
        h.schedule(&a, "FIN", false, "nudge-1", now + 3_600_000, json!({"v": 1})).await;
        h.schedule(&a, "FIN", false, "nudge-1", now + 7_200_000, json!({"v": 2})).await;
        let rows = h.rows().await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].run_at.unwrap().timestamp_millis(), now + 7_200_000);
        assert_eq!(rows[0].data.as_ref().unwrap().get_i32("v").unwrap(), 2);
        h.clock.store(now + 3_700_000, Ordering::SeqCst);
        a.scheduler.pass().await.unwrap();
        assert!(h.events.all().is_empty(), "the replaced time no longer fires");
    })
    .await;
}

#[tokio::test]
#[ignore = "needs the local stack: CORE_LOCAL_STACK=1 and config/local.env"]
async fn a_key_that_is_running_is_not_replaced_under_it() {
    on_scratch(|h| async move {
        let a = h.instance();
        h.schedule(&a, "FIN", false, "sync-1", h.now(), json!({})).await;
        a.scheduler.pass().await.unwrap();
        let again = h.schedule(&a, "FIN", false, "sync-1", h.now(), json!({"v": 2})).await;
        assert!(again.event.is_none(), "in flight, so refused");
        assert_eq!(h.row("sync-1").await.status, Some(Status::Claimed));
        h.advance(301);
        assert!(h.schedule(&a, "FIN", false, "sync-1", h.now(), json!({"v": 3})).await.event.is_some());
        let row = h.row("sync-1").await;
        assert_eq!((row.status, row.attempts), (Some(Status::Pending), 0));
    })
    .await;
}

#[tokio::test]
#[ignore = "needs the local stack: CORE_LOCAL_STACK=1 and config/local.env"]
async fn a_blank_key_gets_one_that_can_cancel_it() {
    on_scratch(|h| async move {
        let a = h.instance();
        let s = h.schedule(&a, "FIN", false, "", h.now() + 60_000, json!({})).await;
        assert!(!s.key.trim().is_empty());
        assert!(a.one_offs.cancel(APP, "FIN", false, &s.key).await.unwrap());
    })
    .await;
}

#[tokio::test]
#[ignore = "needs the local stack: CORE_LOCAL_STACK=1 and config/local.env"]
async fn two_instances_claim_each_one_off_exactly_once() {
    on_scratch(|h| async move {
        let (a, b) = (h.instance(), h.instance());
        for i in 0..60 {
            h.schedule(if i % 2 == 0 { &a } else { &b }, "FIN", false, &format!("k{i}"), h.now(), json!({"i": i})).await;
        }
        for _ in 0..3 {
            let (ra, rb) = tokio::join!(a.scheduler.pass(), b.scheduler.pass());
            ra.unwrap();
            rb.unwrap();
        }
        let mut per_key: HashMap<String, usize> = HashMap::new();
        for q in h.events.all() {
            *per_key.entry(marker(&q)["key"].as_str().unwrap().to_string()).or_default() += 1;
        }
        assert_eq!(per_key.len(), 60);
        assert!(per_key.values().all(|c| *c == 1), "each one-off raised once: {per_key:?}");
    })
    .await;
}

#[tokio::test]
#[ignore = "needs the local stack: CORE_LOCAL_STACK=1 and config/local.env"]
async fn a_draft_one_off_is_raised_onto_the_draft_surface_under_its_own_keys() {
    on_scratch(|h| async move {
        let a = h.instance();
        h.schedule(&a, "FIN", true, "same", h.now(), json!({})).await;
        h.schedule(&a, "FIN", false, "same", h.now(), json!({})).await;
        assert_eq!(h.rows().await.len(), 2);
        a.scheduler.pass().await.unwrap();
        let raised = h.events.raised.lock();
        assert_eq!(raised.len(), 2);
        assert_eq!(raised.iter().filter(|(_, draft)| *draft).count(), 1);
        assert!(raised.iter().all(|(q, draft)| q.draft == *draft));
    })
    .await;
}

#[tokio::test]
#[ignore = "needs the local stack: CORE_LOCAL_STACK=1 and config/local.env"]
async fn a_one_off_whose_raise_fails_goes_back_with_backoff_and_a_lease_spent_on_the_last_attempt_gives_up() {
    on_scratch(|h| async move {
        let a = h.instance();
        h.schedule(&a, "FIN", false, "r", h.now(), json!({})).await;
        h.events.failing.store(true, Ordering::SeqCst);
        let report = a.scheduler.pass().await.unwrap();
        assert_eq!((report.one_offs_raised, report.one_offs_failed), (0, 1));
        let row = h.row("r").await;
        assert_eq!((row.status, row.last_error.as_deref()), (Some(Status::Pending), Some("Raise failed: broker down")));
        assert_eq!(h.run_log.0.lock()[0].2, "The scheduler could not raise the event: broker down");
        // Claimed past the last attempt (its leases ran out): not raised again.
        h.events.failing.store(false, Ordering::SeqCst);
        h.db.collection::<Document>(crate::scheduler::SCHEDULED_EVENT_COLLECTION)
            .update_one(doc! {"key": "r"}, doc! {"$set": {"attempts": 3, "runAt": mongodb::bson::DateTime::from_millis(h.now())}})
            .await
            .unwrap();
        let report = a.scheduler.pass().await.unwrap();
        assert_eq!(report.one_offs_failed, 1);
        let row = h.row("r").await;
        assert_eq!((row.status, row.last_error.as_deref()), (Some(Status::Failed), Some("Lease ran out on the last attempt")));
        assert!(h.run_log.0.lock().last().unwrap().2.starts_with("Gave up after 3 attempts"));
        assert!(h.events.all().is_empty());
    })
    .await;
}

// ---------------------------------------------------------------- EventSchedulerInactiveClientTest

#[tokio::test]
#[ignore = "needs the local stack: CORE_LOCAL_STACK=1 and config/local.env"]
async fn an_inactive_client_holding_a_single_run_schedule_runs_nothing() {
    on_scratch(|h| async move {
        let s = every_minute(false);
        h.store_definition("FIN", SWEEP, s.clone()).await;
        h.store_definition("GONE", SWEEP, s.clone()).await;
        h.definitions.put("FIN", SWEEP, s.clone());
        h.definitions.put("GONE", SWEEP, s);
        h.security.not_active.lock().insert("GONE".into());
        h.instance().scheduler.pass().await.unwrap();
        assert_eq!(h.events.of("FIN", SWEEP).len(), 1);
        assert!(h.events.of("GONE", SWEEP).is_empty());
        assert!(h.runs("GONE", SWEEP).await.is_empty());
    })
    .await;
}

#[tokio::test]
#[ignore = "needs the local stack: CORE_LOCAL_STACK=1 and config/local.env"]
async fn a_per_client_schedule_skips_a_writer_that_is_not_active() {
    on_scratch(|h| async move {
        h.per_client_sweep(&["FIN", "LOCKED"], &["FIN", "LOCKED"]).await;
        h.security.not_active.lock().insert("LOCKED".into());
        h.instance().scheduler.pass().await.unwrap();
        assert_eq!(h.events.of("FIN", SWEEP).len(), 1);
        assert!(h.events.of("LOCKED", SWEEP).is_empty());
    })
    .await;
}

#[tokio::test]
#[ignore = "needs the local stack: CORE_LOCAL_STACK=1 and config/local.env"]
async fn status_is_asked_once_per_refresh_and_a_reactivated_client_runs_again() {
    on_scratch(|h| async move {
        let s = every_minute(false);
        h.store_definition("FIN", SWEEP, s.clone()).await;
        h.definitions.put("FIN", SWEEP, s);
        h.security.not_active.lock().insert("FIN".into());
        let a = h.instance();
        a.scheduler.pass().await.unwrap();
        h.advance(60);
        a.scheduler.pass().await.unwrap();
        assert!(h.events.of("FIN", SWEEP).is_empty());
        assert_eq!(h.security.status_calls.load(Ordering::SeqCst), 1, "the answer is reused inside clientsRefreshSeconds");
        h.security.not_active.lock().clear();
        h.advance(300);
        a.scheduler.pass().await.unwrap();
        assert_eq!(h.events.of("FIN", SWEEP).len(), 1);
        assert_eq!(h.security.status_calls.load(Ordering::SeqCst), 2);
    })
    .await;
}

#[tokio::test]
#[ignore = "needs the local stack: CORE_LOCAL_STACK=1 and config/local.env"]
async fn when_security_has_never_answered_the_schedule_runs_as_before() {
    on_scratch(|h| async move {
        let s = every_minute(false);
        h.store_definition("FIN", SWEEP, s.clone()).await;
        h.definitions.put("FIN", SWEEP, s);
        h.security.not_active.lock().insert("FIN".into());
        h.security.status_down.store(true, Ordering::SeqCst);
        h.instance().scheduler.pass().await.unwrap();
        assert_eq!(h.events.of("FIN", SWEEP).len(), 1, "only a client security has reported as not active is left out");
    })
    .await;
}

#[tokio::test]
#[ignore = "needs the local stack: CORE_LOCAL_STACK=1 and config/local.env"]
async fn when_security_goes_down_the_last_answer_keeps_serving() {
    on_scratch(|h| async move {
        let s = every_minute(false);
        h.store_definition("FIN", SWEEP, s.clone()).await;
        h.definitions.put("FIN", SWEEP, s);
        h.security.not_active.lock().insert("FIN".into());
        let a = h.instance();
        a.scheduler.pass().await.unwrap();
        h.security.status_down.store(true, Ordering::SeqCst);
        h.advance(600);
        a.scheduler.pass().await.unwrap();
        assert!(h.events.of("FIN", SWEEP).is_empty());
    })
    .await;
}

#[tokio::test]
#[ignore = "needs the local stack: CORE_LOCAL_STACK=1 and config/local.env"]
async fn a_one_off_for_an_inactive_client_is_closed_with_the_reason_and_not_raised() {
    on_scratch(|h| async move {
        let a = h.instance();
        h.schedule(&a, "GONE", false, "r-1", h.now(), json!({})).await;
        h.schedule(&a, "FIN", false, "r-2", h.now(), json!({})).await;
        h.security.not_active.lock().insert("GONE".into());
        a.scheduler.pass().await.unwrap();
        assert!(h.events.of("GONE", REMIND).is_empty());
        assert_eq!(h.events.of("FIN", REMIND).len(), 1);
        let closed = h.row("r-1").await;
        assert_eq!(closed.status, Some(Status::Failed));
        assert!(closed.last_error.as_deref().unwrap().contains("'GONE'"));
        h.advance(3600);
        a.scheduler.pass().await.unwrap();
        assert!(h.events.of("GONE", REMIND).is_empty(), "a closed one-off is never claimed again");
    })
    .await;
}

// ---------------------------------------------------------------- without a database

#[test]
fn instants_are_written_as_java_writes_them() {
    assert_eq!(instant_text(at("2026-10-09T09:00:00Z")), "2026-10-09T09:00:00Z");
    assert_eq!(instant_text(at("2026-10-09T09:00:00.120Z")), "2026-10-09T09:00:00.120Z");
    assert!(instance_id().len() > 9);
    assert_eq!(bson_to_json(&mongodb::bson::Bson::Int64(5)), json!(5));
    assert_eq!(bson_to_json(&mongodb::bson::Bson::Null), Value::Null);
    let d = doc! {"a": [1_i32, 2.5, "x", true], "b": {"c": mongodb::bson::DateTime::from_millis(7)}};
    assert_eq!(Value::Object(document_to_json(&d)), json!({"a": [1, 2.5, "x", true], "b": {"c": 7}}));
}

#[tokio::test]
async fn a_scheduler_that_is_off_does_nothing() {
    let client = mongodb::Client::with_uri_str("mongodb://127.0.0.1:1/?serverSelectionTimeoutMS=200").await.unwrap();
    let db = client.database("nothing");
    let mut s = settings();
    s.enabled = false;
    let h = Harness::new(db);
    let i = h.instance_with(s);
    i.scheduler.on_schedule().await;
    i.scheduler.clone().run_forever().await;
    // With the scheduler on, a pass against an unreachable Mongo fails and is logged.
    let i = h.instance();
    i.scheduler.on_schedule().await;
    assert!(h.events.all().is_empty());
}

#[tokio::test]
#[ignore = "needs the local stack: CORE_LOCAL_STACK=1 and config/local.env"]
async fn a_spread_schedule_runs_on_its_shifted_grid_and_write_access_survives_an_outage() {
    on_scratch(|h| async move {
        let spread = EventSchedule { cron: Some("*/10 * * * *".into()), per_client: Some(true), spread: Some(true), ..Default::default() };
        h.security.write_access.lock().insert(APP.into(), vec!["FIN".into()]);
        h.store_definition("SYSTEM", "spreadSweep", spread.clone()).await;
        h.definitions.put("FIN", "spreadSweep", spread);
        let key = format!("{APP}\u{0}FIN\u{0}spreadSweep");
        let cron = crate::cron::parse_cron("*/10 * * * *").unwrap();
        let utc = crate::cron::zone_of("UTC").unwrap();
        let offset = crate::cron::spread_offset_seconds(&cron, &utc, &key);
        // Just after this hour's shifted tick: the tick is the grid's, moved by the key's offset.
        h.clock.store(at("2026-10-09T09:00:00Z") + offset * 1000 + 5000, Ordering::SeqCst);
        let a = h.instance();
        a.scheduler.pass().await.unwrap();
        assert_eq!(h.ticks("FIN", "spreadSweep").await, [at("2026-10-09T09:00:00Z") + offset * 1000]);
        // Security unreachable later: the list it gave keeps serving.
        h.security.write_access_down.store(true, Ordering::SeqCst);
        h.advance(600 + 3600);
        complete(&a, &h.events.of("FIN", "spreadSweep")[0], true).await;
        a.scheduler.pass().await.unwrap();
        assert_eq!(h.ticks("FIN", "spreadSweep").await.len(), 2);
        // A fresh instance has no list to fall back on: nobody runs.
        h.advance(600);
        h.instance().scheduler.pass().await.unwrap();
        assert_eq!(h.ticks("FIN", "spreadSweep").await.len(), 2);
    })
    .await;
}

#[tokio::test]
async fn the_seams_reach_the_real_services() {
    // Definitions through the store (nothing stored: no definition).
    let cache = platform::cache::CacheService::new("cmn", "evictionChannel", None).unwrap();
    let backend = std::sync::Arc::new(overridable::backend::MemBackend::new());
    let store = overridable::Store::with_parts(backend, std::sync::Arc::new(overridable::backend::FakeDirectory::new()), &cache).unwrap();
    let eds = Arc::new(EventDefinitionService::new(store, cache));
    let defs: Arc<dyn EffectiveDefinitions> = eds.clone();
    assert!(defs.read_effective("x", APP, "FIN").await.unwrap().is_none());
    // Security over HTTP: an unreachable one is an error the pass logs.
    let security: Arc<dyn ClientDirectory> =
        Arc::new(crate::clients::SecurityCalls::new(platform::upstream::Upstream::fixed(&["http://127.0.0.1:1"])).unwrap());
    assert!(security.write_access_client_codes(APP).await.is_err());
    assert!(security.active_client_codes(&["FIN".into()]).await.is_err());
    // The publisher, off: the raise is dropped and answered as sent.
    let mq: Arc<dyn EventRaiser> = Arc::new(crate::integrations::Mq::from_config(&crate::config::MqSection { enabled: false, ..Default::default() }));
    assert!(mq.create_event(EventMessage { event_name: Some("E".into()), ..Default::default() }, true).await.unwrap());
    // The run log adapter writes what the scheduler decided.
    let dao = Arc::new(crate::event_runs::MemoryEventRunDao::default());
    let runs = crate::event_runs::EventRunService::new(dao.clone(), eds, Arc::new(crate::clients::SecurityCalls::new(platform::upstream::Upstream::fixed(&["http://127.0.0.1:1"])).unwrap()), true);
    let qob = EventMessage { app_code: Some(APP.into()), client_code: Some("FIN".into()), event_name: Some("E".into()), ..Default::default() };
    RunLog::record(&runs, &qob, Unrun::Skipped, "skipped").await;
    RunLog::record(&runs, &qob, Unrun::Failed, "failed").await;
    let rows = dao.rows();
    assert_eq!(rows.iter().map(|r| (r.status, r.error.clone())).collect::<Vec<_>>(), [
        (Some(crate::event_runs::RunStatus::Skipped), Some("skipped".into())),
        (Some(crate::event_runs::RunStatus::Failed), Some("failed".into())),
    ]);
    assert_eq!(instant_text(i64::MAX), i64::MAX.to_string());
    assert_eq!(bson_to_json(&mongodb::bson::Bson::Symbol("s".into())), json!("s"));
    let oid = mongodb::bson::oid::ObjectId::new();
    assert_eq!(bson_to_json(&mongodb::bson::Bson::ObjectId(oid))["timestamp"], json!(oid.timestamp().timestamp_millis() / 1000));
}
