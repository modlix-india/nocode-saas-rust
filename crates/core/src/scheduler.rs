//! The one-off half of core's event scheduler and the schedule switch of the event
//! definitions, which `CoreServices.Event.ScheduleEvent`, `CancelScheduledEvent` and
//! `SetScheduleEnabled` call:
//!
//! - [`EventSchedulerSettings`]: `core.scheduler.*`, with the Java defaults;
//! - [`EventSchedule`]: `EventDefinition.schedule` and how it folds down the override chain;
//! - [`ScheduledEvent`] / [`ScheduleStore`]: the `scheduled_event` rows and the indexes
//!   `ScheduleStore.ensureIndexes` makes, written as Spring Data writes them, so the Java
//!   scheduler claims and runs what Rust schedules;
//! - [`ScheduledEventService`]: `schedule` and `cancel`;
//! - [`EventDefinitionService`]: `readEffective` and `setOwnScheduleEnabled`, the own copy saved
//!   as Spring Data saves it and the definition caches evicted on every instance.
//!
//! The polling, claiming and running loop (`EventScheduler`, `ScheduledEventRunner`, claim and
//! finish) is the worker's and is not here.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::TimeDelta;
use mongodb::bson::{doc, Bson, DateTime, Document};
use mongodb::error::{ErrorKind, WriteFailure};
use mongodb::options::{IndexOptions, ReturnDocument};
use mongodb::{Database, IndexModel};
use overridable::backend::Find;
use overridable::bson_conv;
use overridable::java_map;
use overridable::json::java_double;
use overridable::{DocType, JMap, JValue, Store};
use platform::cache::CacheService;
use serde::{Deserialize, Serialize};

use crate::docs::EventDefinitionDoc;
use crate::error::CoreError;

// ------------------------------------------------------------------ settings

/// `EventSchedulerSettings`: `core.scheduler.*` of the Java service with its defaults, here
/// `[core.scheduler]` and `[core.scheduler.oneoff]` with the names in snake case
/// (`tickMs` is `tick_ms`, `oneoff.maxAttempts` is `oneoff.max_attempts`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EventSchedulerSettings {
    /// Off stops both the recurring and the one-off sweeps on this instance.
    pub enabled: bool,
    /// How often a pass runs (the wait after one pass ends before the next starts).
    pub tick_ms: i64,
    /// `core.scheduler.initialDelayMs`: the wait before the first pass.
    pub initial_delay_ms: i64,
    /// How long a claimed run or one-off may go without finishing before it can be retaken.
    pub lease_seconds: i64,
    /// How far back a missed tick is still caught up.
    pub catch_up_window_minutes: i64,
    /// How long the app's write-access client list is reused.
    pub clients_refresh_seconds: i64,
    /// `schedule_run` rows expire this long after they are created.
    pub run_retention_days: i64,
    /// Clients worked on at once within one pass.
    pub concurrency: i32,
    /// Scheduled runs this instance executes at once.
    pub run_concurrency: i32,
    pub oneoff: OneOffSettings,
}

/// `core.scheduler.oneoff.*`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct OneOffSettings {
    pub batch_size: i32,
    pub max_attempts: i32,
    pub backoff_base_seconds: i64,
    pub backoff_max_seconds: i64,
    /// Finished one-offs (DONE, FAILED, CANCELLED) expire this long after they finish.
    pub retention_days: i64,
}

impl Default for EventSchedulerSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            tick_ms: 30_000,
            initial_delay_ms: 30_000,
            lease_seconds: 300,
            catch_up_window_minutes: 1500,
            clients_refresh_seconds: 300,
            run_retention_days: 3,
            concurrency: 16,
            run_concurrency: 4,
            oneoff: OneOffSettings::default(),
        }
    }
}

impl Default for OneOffSettings {
    fn default() -> Self {
        Self { batch_size: 200, max_attempts: 5, backoff_base_seconds: 30, backoff_max_seconds: 3600, retention_days: 7 }
    }
}

/// `Duration.ofSeconds`, held at chrono's bounds instead of Java's wider ones.
fn seconds(s: i64) -> TimeDelta {
    TimeDelta::try_seconds(s).unwrap_or(if s < 0 { TimeDelta::MIN } else { TimeDelta::MAX })
}

impl EventSchedulerSettings {
    pub fn lease(&self) -> TimeDelta {
        seconds(self.lease_seconds)
    }

    pub fn catch_up_window(&self) -> TimeDelta {
        seconds(self.catch_up_window_minutes.saturating_mul(60))
    }

    /// A tick younger than this is the one due now rather than a missed one: three passes
    /// wide, at least a minute.
    pub fn fresh_window(&self) -> TimeDelta {
        TimeDelta::milliseconds(self.tick_ms.wrapping_mul(3).max(60_000))
    }

    /// Wait before attempt `attempts + 1`: the base doubled per attempt made, capped.
    pub fn one_off_backoff(&self, attempts: i32) -> TimeDelta {
        let base = self.oneoff.backoff_base_seconds.max(1);
        let shift = attempts.wrapping_sub(1).clamp(0, 30);
        let mut s = base << shift;
        if s <= 0 || s > self.oneoff.backoff_max_seconds {
            s = self.oneoff.backoff_max_seconds;
        }
        seconds(s)
    }
}

// ------------------------------------------------------------------ java text

/// `Character.isWhitespace`.
pub fn java_whitespace(c: char) -> bool {
    matches!(
        c,
        '\t'..='\r'
            | '\u{1c}'..='\u{1f}'
            | ' '
            | '\u{1680}'
            | '\u{2000}'..='\u{2006}'
            | '\u{2008}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{205f}'
            | '\u{3000}'
    )
}

/// `String.isBlank()`.
pub fn java_blank(s: &str) -> bool {
    s.chars().all(java_whitespace)
}

/// `String.trim()`: everything up to U+0020 off both ends.
pub fn java_trim(s: &str) -> &str {
    s.trim_matches(|c: char| c <= ' ')
}

/// The millisecond clock (`Clock.systemUTC().instant()`).
pub fn now_millis() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

// ------------------------------------------------------------------ schedule

/// `EventSchedule`: when an event raises itself. Every field is nullable: an override carries
/// only what it changes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventSchedule {
    pub cron: Option<String>,
    pub timezone: Option<String>,
    pub per_client: Option<bool>,
    pub enabled: Option<bool>,
    pub spread: Option<bool>,
}

pub const DEFAULT_TIMEZONE: &str = "UTC";

/// A scalar read into a `String` field.
fn j_string(v: &JValue) -> Option<String> {
    match v {
        JValue::Str(s) => Some(s.clone()),
        JValue::Int(i) => Some(i.to_string()),
        JValue::Float(f) => Some(java_double(*f)),
        JValue::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// A value read into a `Boolean` field (Spring's `StringToBooleanConverter` for text; text it
/// does not know is left out where Java fails the read).
fn j_bool(v: &JValue) -> Option<bool> {
    match v {
        JValue::Bool(b) => Some(*b),
        JValue::Str(s) => match java_trim(s).to_ascii_lowercase().as_str() {
            "true" | "on" | "yes" | "1" => Some(true),
            "false" | "off" | "no" | "0" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

impl EventSchedule {
    /// Spring Data reading the embedded document (or the resolved definition's map): the five
    /// fields, converted, anything else dropped. `None` unless it is an object.
    pub fn from_j(v: &JValue) -> Option<Self> {
        let m = v.as_object()?;
        let s = |k: &str| m.get(k).and_then(j_string);
        let b = |k: &str| m.get(k).and_then(j_bool);
        Some(Self { cron: s("cron"), timezone: s("timezone"), per_client: b("perClient"), enabled: b("enabled"), spread: b("spread") })
    }

    pub fn from_bson(d: &Document) -> Self {
        Self::from_j(&JValue::Object(bson_conv::doc_to_j(d))).unwrap_or_default()
    }

    fn entries(&self) -> [(&'static str, Option<JValue>); 5] {
        [
            ("cron", self.cron.clone().map(JValue::Str)),
            ("timezone", self.timezone.clone().map(JValue::Str)),
            ("perClient", self.per_client.map(JValue::Bool)),
            ("enabled", self.enabled.map(JValue::Bool)),
            ("spread", self.spread.map(JValue::Bool)),
        ]
    }

    /// As the converter writes it: declaration order, nulls left out.
    pub fn to_j(&self) -> JValue {
        JValue::Object(self.entries().into_iter().filter_map(|(k, v)| v.map(|v| (k.to_string(), v))).collect())
    }

    pub fn to_bson(&self) -> Document {
        self.entries().into_iter().filter_map(|(k, v)| v.map(|v| (k.to_string(), bson_conv::from_j(&v)))).collect()
    }

    /// Absent `enabled` means enabled; a blank cron never runs.
    pub fn is_active(&self) -> bool {
        self.enabled != Some(false) && self.cron.as_deref().is_some_and(|c| !java_blank(c))
    }

    pub fn is_spread_across_period(&self) -> bool {
        self.spread == Some(true)
    }

    pub fn is_for_each_client(&self) -> bool {
        self.per_client == Some(true)
    }

    pub fn effective_timezone(&self) -> &str {
        match self.timezone.as_deref() {
            Some(t) if !java_blank(t) => t,
            _ => DEFAULT_TIMEZONE,
        }
    }

    /// `EventSchedule.merge`: the override's fields where it has them, the base's elsewhere.
    pub fn merge(over: Option<&Self>, base: Option<&Self>) -> Option<Self> {
        let (o, b) = match (over, base) {
            (None, b) => return b.cloned(),
            (Some(o), None) => return Some(o.clone()),
            (Some(o), Some(b)) => (o, b),
        };
        Some(Self {
            cron: o.cron.clone().or_else(|| b.cron.clone()),
            timezone: o.timezone.clone().or_else(|| b.timezone.clone()),
            per_client: o.per_client.or(b.per_client),
            enabled: o.enabled.or(b.enabled),
            spread: o.spread.or(b.spread),
        })
    }

    /// `EventSchedule.difference`: what an override stores, `None` when nothing differs.
    pub fn difference(derived: Option<&Self>, base: Option<&Self>) -> Option<Self> {
        let d = derived?;
        let Some(b) = base else { return Some(d.clone()) };
        fn keep<T: Clone + PartialEq>(d: &Option<T>, b: &Option<T>) -> Option<T> {
            if d == b {
                None
            } else {
                d.clone()
            }
        }
        let diff = Self {
            cron: keep(&d.cron, &b.cron),
            timezone: keep(&d.timezone, &b.timezone),
            per_client: keep(&d.per_client, &b.per_client),
            enabled: keep(&d.enabled, &b.enabled),
            spread: keep(&d.spread, &b.spread),
        };
        (diff != Self::default()).then_some(diff)
    }

    /// `EventDefinition.applyOverride`'s schedule: both sides read as `EventSchedule`s and
    /// merged.
    pub fn merge_j(over: Option<&JValue>, base: Option<&JValue>) -> JValue {
        let o = over.and_then(Self::from_j);
        let b = base.and_then(Self::from_j);
        Self::merge(o.as_ref(), b.as_ref()).map(|s| s.to_j()).unwrap_or(JValue::Null)
    }
}

// ------------------------------------------------------------------ one-off rows

pub const SCHEDULED_EVENT_COLLECTION: &str = "scheduled_event";
pub const SCHEDULE_RUN_COLLECTION: &str = "schedule_run";
pub const RUN_UNIQUE_INDEX: &str = "scheduleRunTickUnique";
pub const EVENT_KEY_UNIQUE_INDEX: &str = "scheduledEventKeyUnique";

/// `ScheduledEvent.Status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pending,
    Claimed,
    Done,
    Failed,
    Cancelled,
}

impl Status {
    pub fn name(self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Claimed => "CLAIMED",
            Self::Done => "DONE",
            Self::Failed => "FAILED",
            Self::Cancelled => "CANCELLED",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [Self::Pending, Self::Claimed, Self::Done, Self::Failed, Self::Cancelled].into_iter().find(|x| x.name() == s)
    }
}

/// `ScheduledEvent`: a one-off to raise at `run_at`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ScheduledEvent {
    pub id: Option<String>,
    pub app_code: Option<String>,
    pub client_code: Option<String>,
    /// Raised from the draft surface; keys are separate per surface.
    pub draft: bool,
    /// Unique per (appCode, clientCode, draft).
    pub key: Option<String>,
    pub event_name: Option<String>,
    pub data: Option<Document>,
    pub run_at: Option<DateTime>,
    pub status: Option<Status>,
    pub attempts: i32,
    pub max_attempts: i32,
    pub owner: Option<String>,
    pub claim_token: Option<String>,
    pub lease_until: Option<DateTime>,
    pub last_error: Option<String>,
    /// The user whose function scheduled it.
    pub scheduled_by: Option<String>,
    pub created_at: Option<DateTime>,
    pub updated_at: Option<DateTime>,
    pub finished_at: Option<DateTime>,
}

impl ScheduledEvent {
    /// Spring Data reading a row.
    pub fn from_document(d: &Document) -> Self {
        let s = |k: &str| d.get(k).map(bson_conv::to_java_string).and_then(|v| j_string(&v));
        let date = |k: &str| match d.get(k) {
            Some(Bson::DateTime(t)) => Some(*t),
            _ => None,
        };
        let int = |k: &str| match d.get(k).map(bson_conv::to_j) {
            Some(JValue::Int(i)) => i as i32,
            Some(JValue::Float(f)) => f as i32,
            _ => 0,
        };
        Self {
            id: s("_id"),
            app_code: s("appCode"),
            client_code: s("clientCode"),
            draft: matches!(d.get("draft"), Some(Bson::Boolean(true))),
            key: s("key"),
            event_name: s("eventName"),
            data: d.get_document("data").ok().cloned(),
            run_at: date("runAt"),
            status: s("status").as_deref().and_then(Status::parse),
            attempts: int("attempts"),
            max_attempts: int("maxAttempts"),
            owner: s("owner"),
            claim_token: s("claimToken"),
            lease_until: date("leaseUntil"),
            last_error: s("lastError"),
            scheduled_by: s("scheduledBy"),
            created_at: date("createdAt"),
            updated_at: date("updatedAt"),
            finished_at: date("finishedAt"),
        }
    }
}

fn opt(s: &Option<String>) -> Bson {
    s.clone().map(Bson::String).unwrap_or(Bson::Null)
}

fn index(keys: Document, name: &str, unique: bool, partial: Option<Document>, expire_days: Option<i64>) -> IndexModel {
    let options = IndexOptions::builder()
        .name(name.to_string())
        .unique(unique.then_some(true))
        .partial_filter_expression(partial)
        .expire_after(expire_days.map(|d| std::time::Duration::from_secs((d.max(0) as u64).saturating_mul(86_400))))
        .build();
    IndexModel::builder().keys(keys).options(options).build()
}

/// The indexes `ScheduleStore.createIndexes` makes, in its order, with whether they are
/// required: the two unique ones claiming depends on first, then the ones that only keep the
/// collections small and fast (a failure there is logged and tolerated).
pub fn index_models(settings: &EventSchedulerSettings) -> Vec<(&'static str, IndexModel, bool)> {
    vec![
        (
            SCHEDULE_RUN_COLLECTION,
            index(doc! {"appCode": 1, "clientCode": 1, "eventName": 1, "tickAt": 1}, RUN_UNIQUE_INDEX, true, None, None),
            true,
        ),
        (
            SCHEDULED_EVENT_COLLECTION,
            index(doc! {"appCode": 1, "clientCode": 1, "draft": 1, "key": 1}, EVENT_KEY_UNIQUE_INDEX, true, None, None),
            true,
        ),
        (
            SCHEDULE_RUN_COLLECTION,
            index(
                doc! {"appCode": 1, "clientCode": 1, "eventName": 1},
                "scheduleRunRunning",
                false,
                Some(doc! {"status": "RUNNING"}),
                None,
            ),
            false,
        ),
        (
            SCHEDULE_RUN_COLLECTION,
            index(doc! {"createdAt": 1}, "scheduleRunExpiry", false, None, Some(settings.run_retention_days)),
            false,
        ),
        (SCHEDULED_EVENT_COLLECTION, index(doc! {"status": 1, "runAt": 1}, "scheduledEventDue", false, None, None), false),
        (SCHEDULED_EVENT_COLLECTION, index(doc! {"status": 1, "leaseUntil": 1}, "scheduledEventLease", false, None, None), false),
        (
            SCHEDULED_EVENT_COLLECTION,
            index(doc! {"finishedAt": 1}, "scheduledEventExpiry", false, None, Some(settings.oneoff.retention_days)),
            false,
        ),
    ]
}

/// `upsertScheduledEvent`'s query: the key, unless that row is claimed with its lease still
/// good. Plain equalities at the top level, which an upsert seeds the new row from.
pub fn upsert_filter(event: &ScheduledEvent, now: i64) -> Document {
    doc! {
        "appCode": opt(&event.app_code),
        "clientCode": opt(&event.client_code),
        "draft": event.draft,
        "key": opt(&event.key),
        "$or": [{"status": {"$ne": Status::Claimed.name()}}, {"leaseUntil": {"$lt": DateTime::from_millis(now)}}],
    }
}

/// `upsertScheduledEvent`'s update, as Spring's `Update` writes it.
pub fn upsert_update(event: &ScheduledEvent, now: i64) -> Document {
    let now = DateTime::from_millis(now);
    doc! {
        "$set": {
            "eventName": opt(&event.event_name),
            "data": event.data.clone().map(Bson::Document).unwrap_or(Bson::Null),
            "runAt": event.run_at.map(Bson::DateTime).unwrap_or(Bson::Null),
            "status": Status::Pending.name(),
            "attempts": 0,
            "maxAttempts": event.max_attempts,
            "scheduledBy": opt(&event.scheduled_by),
            "updatedAt": now,
        },
        "$unset": {"owner": 1, "claimToken": 1, "leaseUntil": 1, "lastError": 1, "finishedAt": 1},
        "$setOnInsert": {"createdAt": now},
    }
}

/// `cancelScheduledEvent`'s query and update: PENDING to CANCELLED.
pub fn cancel_filter_update(app_code: &str, client_code: &str, draft: bool, key: &str, now: i64) -> (Document, Document) {
    let now = DateTime::from_millis(now);
    (
        doc! {"appCode": app_code, "clientCode": client_code, "draft": draft, "key": key, "status": Status::Pending.name()},
        doc! {"$set": {"status": Status::Cancelled.name(), "finishedAt": now, "updatedAt": now}},
    )
}

/// What the one-off service needs of the store.
#[async_trait]
pub trait OneOffStore: Send + Sync {
    /// Creates the indexes once per instance; a failure is retried on the next call.
    async fn ensure_indexes(&self) -> Result<(), CoreError>;
    /// Writes the one-off over any row with its key unless that row is in flight (`None`).
    async fn upsert_scheduled_event(&self, event: &ScheduledEvent, now: i64) -> Result<Option<ScheduledEvent>, CoreError>;
    /// PENDING to CANCELLED; false when nothing pending had the key.
    async fn cancel_scheduled_event(&self, app_code: &str, client_code: &str, draft: bool, key: &str, now: i64)
        -> Result<bool, CoreError>;
    /// `findScheduledEvent`.
    async fn find_scheduled_event(&self, id: &str) -> Result<Option<ScheduledEvent>, CoreError>;
    /// CLAIMED to DONE, only under the claim that is finishing.
    async fn complete_scheduled_event(&self, id: &str, claim_token: &str, now: i64) -> Result<bool, CoreError>;
    /// CLAIMED back to PENDING at `retry_at`, or to FAILED when it is `None`; only under the
    /// claim that is finishing.
    async fn fail_scheduled_event(&self, id: &str, claim_token: &str, retry_at: Option<i64>, error: Option<&str>, now: i64)
        -> Result<bool, CoreError>;
}

/// `ScheduleStore` over core's Mongo (the one-off parts and the indexes).
pub struct ScheduleStore {
    db: Database,
    settings: EventSchedulerSettings,
    indexes: tokio::sync::OnceCell<()>,
}

/// Spring's `DuplicateKeyException` codes.
fn is_duplicate_key(e: &mongodb::error::Error) -> bool {
    let code = match e.kind.as_ref() {
        ErrorKind::Command(c) => c.code,
        ErrorKind::Write(WriteFailure::WriteError(w)) => w.code,
        _ => 0,
    };
    matches!(code, 11000 | 11001 | 12582)
}

fn mongo_error(e: mongodb::error::Error) -> CoreError {
    CoreError::unknown(e.to_string())
}

impl ScheduleStore {
    pub fn new(db: Database, settings: EventSchedulerSettings) -> Self {
        Self { db, settings, indexes: tokio::sync::OnceCell::new() }
    }

    async fn create_indexes(&self) -> Result<(), CoreError> {
        for (collection, model, required) in index_models(&self.settings) {
            match self.db.collection::<Document>(collection).create_index(model).await {
                Err(e) if required => return Err(mongo_error(e)),
                Err(e) => tracing::warn!("Scheduler index not created: {e}"),
                Ok(_) => {}
            }
        }
        Ok(())
    }
}

#[async_trait]
impl OneOffStore for ScheduleStore {
    async fn ensure_indexes(&self) -> Result<(), CoreError> {
        self.indexes.get_or_try_init(|| self.create_indexes()).await.map(|_| ())
    }

    async fn upsert_scheduled_event(&self, event: &ScheduledEvent, now: i64) -> Result<Option<ScheduledEvent>, CoreError> {
        let r = self
            .db
            .collection::<Document>(SCHEDULED_EVENT_COLLECTION)
            .find_one_and_update(upsert_filter(event, now), upsert_update(event, now))
            .upsert(true)
            .return_document(ReturnDocument::After)
            .await;
        match r {
            Ok(d) => Ok(d.as_ref().map(ScheduledEvent::from_document)),
            Err(e) if is_duplicate_key(&e) => Ok(None),
            Err(e) => Err(mongo_error(e)),
        }
    }

    async fn cancel_scheduled_event(&self, app_code: &str, client_code: &str, draft: bool, key: &str, now: i64)
        -> Result<bool, CoreError> {
        let (filter, update) = cancel_filter_update(app_code, client_code, draft, key, now);
        let r = self.db.collection::<Document>(SCHEDULED_EVENT_COLLECTION).update_one(filter, update).await;
        r.map(|r| r.modified_count > 0).map_err(mongo_error)
    }

    async fn find_scheduled_event(&self, id: &str) -> Result<Option<ScheduledEvent>, CoreError> {
        let r = self.events().find_one(doc! {"_id": spring_id(id)}).await.map_err(mongo_error)?;
        Ok(r.as_ref().map(ScheduledEvent::from_document))
    }

    async fn complete_scheduled_event(&self, id: &str, claim_token: &str, now: i64) -> Result<bool, CoreError> {
        let now = DateTime::from_millis(now);
        let update = doc! {"$set": {"status": Status::Done.name(), "finishedAt": now, "updatedAt": now}, "$unset": {"leaseUntil": 1}};
        let r = self.events().update_one(claimed_by(id, claim_token), update).await;
        r.map(|r| r.modified_count > 0).map_err(mongo_error)
    }

    async fn fail_scheduled_event(&self, id: &str, claim_token: &str, retry_at: Option<i64>, error: Option<&str>, now: i64)
        -> Result<bool, CoreError> {
        let update = fail_update(retry_at, error, now);
        let r = self.events().update_one(claimed_by(id, claim_token), update).await;
        r.map(|r| r.modified_count > 0).map_err(mongo_error)
    }
}

/// An `@Id String` in a query, as Spring's converter writes it: a valid ObjectId hex becomes
/// an ObjectId, anything else stays text (`schedule_run` ids are UUIDs).
pub fn spring_id(id: &str) -> Bson {
    match mongodb::bson::oid::ObjectId::parse_str(id) {
        Ok(oid) if id.len() == 24 => Bson::ObjectId(oid),
        _ => Bson::String(id.to_string()),
    }
}

/// `claimedBy`: the row, under this claim, still CLAIMED.
fn claimed_by(id: &str, claim_token: &str) -> Document {
    doc! {"_id": spring_id(id), "claimToken": claim_token, "status": Status::Claimed.name()}
}

/// `failScheduledEvent`'s update: back to PENDING at `retry_at` without its claim, or FAILED.
pub fn fail_update(retry_at: Option<i64>, error: Option<&str>, now: i64) -> Document {
    let now = DateTime::from_millis(now);
    let mut set = doc! {"lastError": error.map(Bson::from).unwrap_or(Bson::Null), "updatedAt": now};
    let mut unset = doc! {"leaseUntil": 1};
    match retry_at {
        None => {
            set.insert("status", Status::Failed.name());
            set.insert("finishedAt", now);
        }
        Some(at) => {
            set.insert("status", Status::Pending.name());
            set.insert("runAt", DateTime::from_millis(at));
            unset.insert("owner", 1);
            unset.insert("claimToken", 1);
        }
    }
    doc! {"$set": set, "$unset": unset}
}

// ------------------------------------------------------------------ recurring runs

/// `ScheduleRun.Status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunState {
    /// Claimed and raised; the EventAction has not reported back yet.
    Running,
    /// The EventAction finished.
    Done,
    /// Not run: the previous tick was still RUNNING inside its lease.
    Skipped,
    /// The event could not be raised, or the EventAction reported a failure.
    Failed,
}

impl RunState {
    pub fn name(self) -> &'static str {
        match self {
            Self::Running => "RUNNING",
            Self::Done => "DONE",
            Self::Skipped => "SKIPPED",
            Self::Failed => "FAILED",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [Self::Running, Self::Done, Self::Skipped, Self::Failed].into_iter().find(|x| x.name() == s)
    }
}

/// `ScheduleRun`: one tick of one recurring schedule for one client, and the claim on it.
#[derive(Debug, Clone, PartialEq)]
pub struct ScheduleRun {
    pub id: String,
    pub app_code: String,
    pub client_code: String,
    pub event_name: String,
    pub tick_at: DateTime,
    pub status: Option<RunState>,
    /// Until when a RUNNING row keeps the next tick from starting.
    pub lease_until: Option<DateTime>,
    /// The instance that claimed it, for diagnosis only.
    pub owner: Option<String>,
    pub created_at: Option<DateTime>,
    pub finished_at: Option<DateTime>,
    pub error: Option<String>,
}

impl ScheduleRun {
    /// As Spring Data inserts it: declaration order, nulls left out, no `_class`.
    pub fn to_document(&self) -> Document {
        let mut d = doc! {"_id": &self.id, "appCode": &self.app_code, "clientCode": &self.client_code,
                          "eventName": &self.event_name, "tickAt": self.tick_at};
        if let Some(s) = self.status {
            d.insert("status", s.name());
        }
        let opt_date = |d: &mut Document, k: &str, v: Option<DateTime>| {
            if let Some(v) = v {
                d.insert(k, v);
            }
        };
        opt_date(&mut d, "leaseUntil", self.lease_until);
        if let Some(o) = &self.owner {
            d.insert("owner", o);
        }
        opt_date(&mut d, "createdAt", self.created_at);
        opt_date(&mut d, "finishedAt", self.finished_at);
        if let Some(e) = &self.error {
            d.insert("error", e);
        }
        d
    }

    pub fn from_document(d: &Document) -> Self {
        let s = |k: &str| d.get(k).map(bson_conv::to_java_string).and_then(|v| j_string(&v));
        let date = |k: &str| match d.get(k) {
            Some(Bson::DateTime(t)) => Some(*t),
            _ => None,
        };
        Self {
            id: s("_id").unwrap_or_default(),
            app_code: s("appCode").unwrap_or_default(),
            client_code: s("clientCode").unwrap_or_default(),
            event_name: s("eventName").unwrap_or_default(),
            tick_at: date("tickAt").unwrap_or(DateTime::from_millis(0)),
            status: s("status").as_deref().and_then(RunState::parse),
            lease_until: date("leaseUntil"),
            owner: s("owner"),
            created_at: date("createdAt"),
            finished_at: date("finishedAt"),
            error: s("error"),
        }
    }
}

/// `ScheduleStore.ScheduledDefinition`: one EventDefinition document, any client's, that
/// carries a schedule of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledDefinition {
    pub app_code: Option<String>,
    pub name: Option<String>,
    pub client_code: Option<String>,
    pub per_client: Option<bool>,
}

/// `Document.getString` / `getBoolean`: a value of another type is a `ClassCastException`.
fn typed<'a, T>(d: &'a Document, key: &str, pick: impl Fn(&'a Bson) -> Option<T>, class: &str) -> Result<Option<T>, CoreError> {
    match d.get(key) {
        None | Some(Bson::Null) => Ok(None),
        Some(v) => pick(v).map(Some).ok_or_else(|| {
            CoreError::unknown(format!("class {} cannot be cast to class {class}", bson_class(v)))
        }),
    }
}

fn bson_class(v: &Bson) -> &'static str {
    match v {
        Bson::String(_) => "java.lang.String",
        Bson::Boolean(_) => "java.lang.Boolean",
        Bson::Int32(_) => "java.lang.Integer",
        Bson::Int64(_) => "java.lang.Long",
        Bson::Double(_) => "java.lang.Double",
        Bson::Document(_) => "org.bson.Document",
        Bson::Array(_) => "java.util.ArrayList",
        Bson::ObjectId(_) => "org.bson.types.ObjectId",
        Bson::DateTime(_) => "java.util.Date",
        _ => "java.lang.Object",
    }
}

impl ScheduledDefinition {
    pub fn from_document(d: &Document) -> Result<Self, CoreError> {
        let string = |k: &str| typed(d, k, |v| v.as_str().map(str::to_string), "java.lang.String");
        let per_client = match d.get("schedule") {
            Some(Bson::Document(s)) => typed(s, "perClient", Bson::as_bool, "java.lang.Boolean")?,
            _ => None,
        };
        Ok(Self { app_code: string("appCode")?, name: string("name")?, client_code: string("clientCode")?, per_client })
    }
}

impl ScheduleStore {
    fn events(&self) -> mongodb::Collection<Document> {
        self.db.collection(SCHEDULED_EVENT_COLLECTION)
    }

    fn runs(&self) -> mongodb::Collection<Document> {
        self.db.collection(SCHEDULE_RUN_COLLECTION)
    }

    /// `findScheduledDefinitions`: every stored EventDefinition document that sets a
    /// schedule, raw (not merged, not filtered for publication), in the collection's order.
    pub async fn find_scheduled_definitions(&self) -> Result<Vec<ScheduledDefinition>, CoreError> {
        use futures::TryStreamExt;
        let docs: Vec<Document> = self
            .db
            .collection::<Document>(crate::docs::EVENT_DEFINITION_COLLECTION)
            .find(doc! {"schedule": {"$ne": Bson::Null}})
            .projection(doc! {"appCode": 1, "name": 1, "clientCode": 1, "schedule.perClient": 1})
            .await
            .map_err(mongo_error)?
            .try_collect()
            .await
            .map_err(mongo_error)?;
        docs.iter().map(ScheduledDefinition::from_document).collect()
    }

    /// `isRunning`: a tick of this schedule is RUNNING with its lease still good.
    pub async fn is_running(&self, app_code: &str, client_code: &str, event_name: &str, now: i64) -> Result<bool, CoreError> {
        let filter = doc! {"appCode": app_code, "clientCode": client_code, "eventName": event_name,
                           "status": RunState::Running.name(), "leaseUntil": {"$gt": DateTime::from_millis(now)}};
        let found = self.runs().find_one(filter).projection(doc! {"_id": 1}).await.map_err(mongo_error)?;
        Ok(found.is_some())
    }

    /// `lastRun`: the newest recorded tick of this schedule, whatever its status.
    pub async fn last_run(&self, app_code: &str, client_code: &str, event_name: &str) -> Result<Option<ScheduleRun>, CoreError> {
        let filter = doc! {"appCode": app_code, "clientCode": client_code, "eventName": event_name};
        let r = self.runs().find_one(filter).sort(doc! {"tickAt": -1}).await.map_err(mongo_error)?;
        Ok(r.as_ref().map(ScheduleRun::from_document))
    }

    /// `claim`: inserts the tick's row; true for the one instance whose insert landed, false
    /// for every other (the duplicate key is the expected outcome, not an error).
    pub async fn claim(&self, run: &ScheduleRun) -> Result<bool, CoreError> {
        match self.runs().insert_one(run.to_document()).await {
            Ok(_) => Ok(true),
            Err(e) if is_duplicate_key(&e) => Ok(false),
            Err(e) => Err(mongo_error(e)),
        }
    }

    /// `finishRun`: closes a RUNNING row; one already closed (or never claimed) is left alone.
    pub async fn finish_run(&self, run_id: &str, status: RunState, error: Option<&str>, now: i64) -> Result<bool, CoreError> {
        let mut set = doc! {"status": status.name(), "finishedAt": DateTime::from_millis(now)};
        if let Some(e) = error {
            set.insert("error", e);
        }
        let r = self
            .runs()
            .update_one(doc! {"_id": run_id, "status": RunState::Running.name()}, doc! {"$set": set})
            .await;
        r.map(|r| r.modified_count > 0).map_err(mongo_error)
    }

    /// `claimDueEvent`: atomically claims the earliest due one-off (PENDING and due, or
    /// CLAIMED by an instance whose lease ran out); each claim counts as an attempt.
    pub async fn claim_due_event(&self, now: i64, owner: &str, lease: TimeDelta) -> Result<Option<ScheduledEvent>, CoreError> {
        let at = DateTime::from_millis(now);
        let filter = doc! {"$or": [
            {"status": Status::Pending.name(), "runAt": {"$lte": at}},
            {"status": Status::Claimed.name(), "leaseUntil": {"$lt": at}},
        ]};
        let update = doc! {
            "$set": {"status": Status::Claimed.name(), "owner": owner, "claimToken": mongodb::bson::Uuid::new().to_string(),
                     "leaseUntil": DateTime::from_millis(now.saturating_add(lease.num_milliseconds())), "updatedAt": at},
            "$inc": {"attempts": 1},
        };
        let r = self
            .events()
            .find_one_and_update(filter, update)
            .sort(doc! {"runAt": 1})
            .return_document(ReturnDocument::After)
            .await
            .map_err(mongo_error)?;
        Ok(r.as_ref().map(ScheduledEvent::from_document))
    }

    /// `claimDueEvents`: up to `limit` claims, stopping at the first empty one.
    pub async fn claim_due_events(&self, now: i64, owner: &str, lease: TimeDelta, limit: i32) -> Result<Vec<ScheduledEvent>, CoreError> {
        let mut out = Vec::new();
        for _ in 0..limit.max(0) {
            match self.claim_due_event(now, owner, lease).await? {
                Some(e) => out.push(e),
                None => break,
            }
        }
        Ok(out)
    }

    /// `runsOf`: rows of one schedule, oldest first (tests and diagnosis).
    pub async fn runs_of(&self, app_code: &str, client_code: &str, event_name: &str) -> Result<Vec<ScheduleRun>, CoreError> {
        use futures::TryStreamExt;
        let docs: Vec<Document> = self
            .runs()
            .find(doc! {"appCode": app_code, "clientCode": client_code, "eventName": event_name})
            .sort(doc! {"tickAt": 1})
            .await
            .map_err(mongo_error)?
            .try_collect()
            .await
            .map_err(mongo_error)?;
        Ok(docs.iter().map(ScheduleRun::from_document).collect())
    }
}

// ------------------------------------------------------------------ one-off service

/// What `CoreServices.Event.ScheduleEvent` asks to store.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ScheduleRequest {
    pub app_code: String,
    pub client_code: String,
    pub draft: bool,
    pub event_name: String,
    /// `JsonUtil.toMap` of the arguments' data (see [`json_util_map`]).
    pub data: Document,
    /// `None` is now.
    pub run_at: Option<i64>,
    /// Blank gets a fresh one.
    pub key: String,
    pub scheduled_by: Option<String>,
}

/// `ScheduledEventService.Scheduled`: the key it was stored under, and the row, `None` when a
/// run with that key is in flight.
#[derive(Debug, Clone, PartialEq)]
pub struct Scheduled {
    pub key: String,
    pub event: Option<ScheduledEvent>,
}

/// What the schedule functions call.
#[async_trait]
pub trait OneOffs: Send + Sync {
    async fn schedule(&self, request: ScheduleRequest) -> Result<Scheduled, CoreError>;
    /// True when a PENDING row with this key was cancelled.
    async fn cancel(&self, app_code: &str, client_code: &str, draft: bool, key: &str) -> Result<bool, CoreError>;
}

pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

/// `ScheduledEventService` (`schedule`, `cancel`).
pub struct ScheduledEventService {
    store: Arc<dyn OneOffStore>,
    settings: EventSchedulerSettings,
    clock: Clock,
}

impl ScheduledEventService {
    pub fn new(store: Arc<dyn OneOffStore>, settings: EventSchedulerSettings) -> Self {
        Self { store, settings, clock: Arc::new(now_millis) }
    }

    /// Tests only (`setClock`).
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    /// `finish`: closes a claim. Success is DONE; a failure goes back to PENDING after a
    /// backoff that doubles per attempt until the attempts are spent, then FAILED. Only the
    /// claim named by `claim_token` can be closed, so a late report is ignored.
    pub async fn finish(&self, id: &str, claim_token: &str, success: bool, error: Option<&str>) -> Result<bool, CoreError> {
        let now = (self.clock)();
        if success {
            return self.store.complete_scheduled_event(id, claim_token, now).await;
        }
        let Some(e) = self.store.find_scheduled_event(id).await? else { return Ok(false) };
        if e.claim_token.as_deref() != Some(claim_token) {
            return Ok(false);
        }
        let retry_at = (e.attempts < e.max_attempts)
            .then(|| now.saturating_add(self.settings.one_off_backoff(e.attempts).num_milliseconds()));
        self.store.fail_scheduled_event(id, claim_token, retry_at, error, now).await
    }
}

#[async_trait]
impl OneOffs for ScheduledEventService {
    async fn schedule(&self, r: ScheduleRequest) -> Result<Scheduled, CoreError> {
        let key = if java_blank(&r.key) { mongodb::bson::Uuid::new().to_string() } else { r.key };
        let now = (self.clock)();
        let event = ScheduledEvent {
            app_code: Some(r.app_code),
            client_code: Some(r.client_code),
            draft: r.draft,
            key: Some(key.clone()),
            event_name: Some(r.event_name),
            data: Some(hash_map_order(r.data, java_map::capacity_by_copy)),
            run_at: Some(DateTime::from_millis(r.run_at.unwrap_or(now))),
            max_attempts: self.settings.oneoff.max_attempts.max(1),
            scheduled_by: r.scheduled_by,
            ..Default::default()
        };
        self.store.ensure_indexes().await?;
        let event = self.store.upsert_scheduled_event(&event, now).await?;
        Ok(Scheduled { key, event })
    }

    async fn cancel(&self, app_code: &str, client_code: &str, draft: bool, key: &str) -> Result<bool, CoreError> {
        if java_blank(key) {
            return Ok(false);
        }
        self.store.ensure_indexes().await?;
        self.store.cancel_scheduled_event(app_code, client_code, draft, key, (self.clock)()).await
    }
}

/// A `java.util.HashMap`'s iteration order over `doc` taken as its insertion order, the table
/// sized by `capacity` for the entry count (`capacity_by_puts` for a map filled by puts,
/// `capacity_by_copy` for `new HashMap<>(map)`).
pub fn hash_map_order(doc: Document, capacity: fn(usize) -> usize) -> Document {
    let cap = capacity(doc.len());
    let mut entries: Vec<(usize, String, Bson)> = doc.into_iter().map(|(k, v)| (java_map::bucket(&k, cap), k, v)).collect();
    entries.sort_by_key(|e| e.0);
    entries.into_iter().map(|(_, k, v)| (k, v)).collect()
}

/// `JsonUtil.toMap(object)` as Spring Data then stores it: a `HashMap` by puts at every
/// level, nulls kept, numbers as `PrimitiveUtil.findPrimitive` leaves them (an integer that
/// fits is an `Integer`, else a `Long`; anything else a `Double`).
pub fn json_util_map(o: &serde_json::Map<String, serde_json::Value>) -> Document {
    let doc: Document = o.iter().map(|(k, v)| (k.clone(), json_util_object(v))).collect();
    hash_map_order(doc, java_map::capacity_by_puts)
}

fn json_util_object(v: &serde_json::Value) -> Bson {
    match v {
        serde_json::Value::Null => Bson::Null,
        serde_json::Value::Bool(b) => Bson::Boolean(*b),
        serde_json::Value::String(s) => Bson::String(s.clone()),
        serde_json::Value::Array(a) => Bson::Array(a.iter().map(json_util_object).collect()),
        serde_json::Value::Object(o) => Bson::Document(json_util_map(o)),
        serde_json::Value::Number(n) => match (n.as_i64(), n.as_u64()) {
            (Some(i), _) => i32::try_from(i).map(Bson::Int32).unwrap_or(Bson::Int64(i)),
            // Past a long: `BigDecimal.longValue()`, the low 64 bits.
            (None, Some(u)) => Bson::Int64(u as i64),
            _ => Bson::Double(n.as_f64().unwrap_or(0.0)),
        },
    }
}

// ------------------------------------------------------------------ event definitions

/// What `CoreServices.Event.SetScheduleEnabled` calls.
#[async_trait]
pub trait ScheduleSwitch: Send + Sync {
    /// `Some(true)` when the client's effective schedule changed, `Some(false)` when it already
    /// was so, `None` when the app has no such event with a schedule.
    async fn set_own_schedule_enabled(&self, name: &str, app_code: &str, client_code: &str, enabled: bool)
        -> Result<Option<bool>, CoreError>;
}

#[derive(Clone, Copy)]
enum Kind {
    Id,
    Map,
    Schedule,
    Bool,
    Str,
    Int,
    Date,
}

/// `EventDefinition`'s fields in the order Spring Data's converter writes them: `_id` first,
/// then the class's own fields, then each superclass's, in declaration order.
const EVENT_DEFINITION_FIELDS: [(&str, Kind); 20] = [
    ("_id", Kind::Id),
    ("schema", Kind::Map),
    ("includeContextAuthentication", Kind::Bool),
    ("schedule", Kind::Schedule),
    ("name", Kind::Str),
    ("message", Kind::Str),
    ("clientCode", Kind::Str),
    ("permission", Kind::Str),
    ("appCode", Kind::Str),
    ("baseClientCode", Kind::Str),
    ("notOverridable", Kind::Bool),
    ("description", Kind::Str),
    ("title", Kind::Str),
    ("published", Kind::Bool),
    ("blueprint", Kind::Map),
    ("version", Kind::Int),
    ("updatedAt", Kind::Date),
    ("updatedBy", Kind::Str),
    ("createdAt", Kind::Date),
    ("createdBy", Kind::Str),
];

fn spring_value(kind: Kind, b: &Bson) -> Option<Bson> {
    match (kind, b) {
        (_, Bson::Null | Bson::Undefined) => None,
        (Kind::Id, b) => Some(b.clone()),
        // Map keys are unescaped on read and escaped on write; nested values go back as read.
        (Kind::Map, Bson::Document(d)) => Some(Bson::Document(d.iter().map(|(k, v)| (bson_conv::escape_key(k), v.clone())).collect())),
        (Kind::Schedule, Bson::Document(d)) => Some(Bson::Document(EventSchedule::from_bson(d).to_bson())),
        (Kind::Bool, b) => j_bool(&bson_conv::to_j(b)).map(Bson::Boolean),
        (Kind::Str, b) => j_string(&bson_conv::to_java_string(b)).map(Bson::String),
        (Kind::Int, b) => match bson_conv::to_j(b) {
            JValue::Int(i) => Some(Bson::Int32(i as i32)),
            JValue::Float(f) => Some(Bson::Int32(f as i32)),
            JValue::Str(s) => s.trim().parse::<i32>().ok().map(Bson::Int32),
            _ => None,
        },
        (Kind::Date, Bson::DateTime(_)) => Some(b.clone()),
        _ => None,
    }
}

/// An `EventDefinition` as Spring Data writes it, from the fields `doc` holds: the class's
/// fields only, converted to their Java types, in the converter's order, nulls left out, no
/// type key (`DefaultMongoTypeMapper(null)`), `version` 1 when absent (its initial value).
pub fn spring_event_definition(doc: &Document) -> Document {
    let mut out = Document::new();
    for (name, kind) in EVENT_DEFINITION_FIELDS {
        let v = doc.get(name).and_then(|b| spring_value(kind, b));
        let v = if name == "version" { Some(v.unwrap_or(Bson::Int32(1))) } else { v };
        if let Some(v) = v {
            out.insert(name, v);
        }
    }
    out
}

/// The parts of `EventDefinitionService` the schedule functions use, over the overridable
/// store (documents in core's `eventDefinition` collection, the per-client definition cache).
#[derive(Clone)]
pub struct EventDefinitionService {
    store: Store,
    cache: CacheService,
}

impl EventDefinitionService {
    /// `cache` must be the one `store` was built on, so evicting reaches its cache.
    pub fn new(store: Store, cache: CacheService) -> Self {
        Self { store, cache }
    }

    /// `readEffective`: the definition as `client_code` sees it, merged down its chain, on the
    /// live surface, through the per-client cache.
    pub async fn read_effective(&self, name: &str, app_code: &str, client_code: &str) -> Result<Option<JMap>, CoreError> {
        let r = self.store.read(&EventDefinitionDoc, name, app_code, client_code, client_code, false).await?;
        Ok(r.map(|r| r.entity.clone()))
    }

    /// `repo.findOneByNameAndAppCodeAndClientCode`: more than one is an error, as Spring's
    /// `one()` raises it.
    async fn find_own(&self, name: &str, app_code: &str, client_code: &str) -> Result<Option<Document>, CoreError> {
        let filter = doc! {"name": name, "appCode": app_code, "clientCode": client_code};
        let mut found = self
            .store
            .backend()
            .find(EventDefinitionDoc.collection(), Find::new(filter.clone()).limit(2))
            .await?;
        if found.len() > 1 {
            return Err(CoreError::unknown(format!("Query {filter} returned non unique result.")));
        }
        Ok(found.pop())
    }

    /// `evictRecursively`: both surfaces' caches of the object and the app's read-page cache,
    /// here and on every instance.
    async fn evict_recursively(&self, app_code: &str, name: &str) {
        let dt = EventDefinitionDoc;
        let live = dt.cache_name(app_code, name);
        self.cache.evict_all_everywhere(&live).await;
        self.cache.evict_all_everywhere(&format!("{live}_DRAFT")).await;
        self.cache.evict_all_everywhere(&format!("{}_READ_PAGE", dt.cache_name(app_code, dt.object_name()))).await;
    }
}

#[async_trait]
impl ScheduleSwitch for EventDefinitionService {
    /// `setOwnScheduleEnabled`: writes only `schedule.enabled` into the client's own copy,
    /// creating the copy (over the definition the client sees now) when it has none.
    async fn set_own_schedule_enabled(&self, name: &str, app_code: &str, client_code: &str, enabled: bool)
        -> Result<Option<bool>, CoreError> {
        let Some(effective) = self.read_effective(name, app_code, client_code).await? else { return Ok(None) };
        let Some(schedule) = effective.get("schedule").and_then(EventSchedule::from_j) else { return Ok(None) };
        // Absent means enabled, as the scheduler reads it.
        if (schedule.enabled != Some(false)) == enabled {
            return Ok(Some(false));
        }
        let mut copy = match self.find_own(name, app_code, client_code).await? {
            Some(stored) => {
                let mut own = spring_event_definition(&stored);
                let mut s = own.get_document("schedule").map(EventSchedule::from_bson).unwrap_or_default();
                s.enabled = Some(enabled);
                own.insert("schedule", s.to_bson());
                let version = own.get_i32("version").unwrap_or(1);
                own.insert("version", version.wrapping_add(1));
                own
            }
            None => {
                let mut fresh = doc! {"schedule": EventSchedule { enabled: Some(enabled), ..Default::default() }.to_bson()};
                if let Some(base) = effective.get("clientCode").and_then(JValue::as_str) {
                    fresh.insert("baseClientCode", base);
                }
                fresh
            }
        };
        let message = format!(
            "{} for {client_code} by CoreServices.Event.SetScheduleEnabled",
            if enabled { "Schedule enabled" } else { "Schedule disabled" }
        );
        copy.insert("name", name);
        copy.insert("appCode", app_code);
        copy.insert("clientCode", client_code);
        copy.insert("message", message);
        let copy = spring_event_definition(&copy);
        let backend = self.store.backend();
        match copy.get("_id").cloned() {
            Some(id) => backend.replace(EventDefinitionDoc.collection(), id, copy).await?,
            None => {
                backend.insert(EventDefinitionDoc.collection(), copy).await?;
            }
        }
        self.evict_recursively(app_code, name).await;
        Ok(Some(true))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicI64, Ordering};

    use overridable::backend::{FakeDirectory, MemBackend};
    use parking_lot::Mutex;
    use serde_json::json;

    use super::*;

    // ---------------------------------------------------------------- settings

    #[test]
    fn settings_default_as_java_and_read_from_config() {
        let s = EventSchedulerSettings::default();
        assert!(s.enabled);
        assert_eq!((s.tick_ms, s.lease_seconds, s.catch_up_window_minutes, s.clients_refresh_seconds), (30_000, 300, 1500, 300));
        assert_eq!((s.run_retention_days, s.concurrency, s.run_concurrency), (3, 16, 4));
        assert_eq!(s.oneoff, OneOffSettings { batch_size: 200, max_attempts: 5, backoff_base_seconds: 30, backoff_max_seconds: 3600, retention_days: 7 });
        let read: EventSchedulerSettings = serde_json::from_value(json!({"tick_ms": 1000, "oneoff": {"max_attempts": 3}})).unwrap();
        assert_eq!(read.tick_ms, 1000);
        assert_eq!(read.oneoff.max_attempts, 3);
        assert_eq!(read.oneoff.retention_days, 7);
        assert_eq!(read.lease_seconds, 300);
        let mut core = crate::config::CoreConfig::default();
        assert_eq!(core.core.scheduler, EventSchedulerSettings::default());
        core.core.scheduler.oneoff.max_attempts = 0;
        assert_eq!(core.core.scheduler.oneoff.max_attempts, 0);
    }

    #[test]
    fn windows_and_backoff() {
        let mut s = EventSchedulerSettings::default();
        assert_eq!(s.lease(), TimeDelta::seconds(300));
        assert_eq!(s.catch_up_window(), TimeDelta::minutes(1500));
        assert_eq!(s.fresh_window(), TimeDelta::milliseconds(90_000));
        s.tick_ms = 1000;
        assert_eq!(s.fresh_window(), TimeDelta::milliseconds(60_000), "at least a minute");
        assert_eq!(s.one_off_backoff(0), TimeDelta::seconds(30));
        assert_eq!(s.one_off_backoff(1), TimeDelta::seconds(30));
        assert_eq!(s.one_off_backoff(2), TimeDelta::seconds(60));
        assert_eq!(s.one_off_backoff(3), TimeDelta::seconds(120));
        assert_eq!(s.one_off_backoff(20), TimeDelta::seconds(3600), "capped");
        assert_eq!(s.one_off_backoff(i32::MIN), TimeDelta::seconds(3600), "Java's int wraps to a large shift");
        s.oneoff.backoff_base_seconds = 0;
        assert_eq!(s.one_off_backoff(1), TimeDelta::seconds(1), "the base is at least a second");
        s.oneoff.backoff_base_seconds = i64::MAX / 2;
        assert_eq!(s.one_off_backoff(30), TimeDelta::seconds(3600), "an overflow is the cap");
        s.lease_seconds = i64::MAX;
        assert_eq!(s.lease(), TimeDelta::MAX);
        s.lease_seconds = i64::MIN;
        assert_eq!(s.lease(), TimeDelta::MIN);
    }

    #[test]
    fn java_text_rules() {
        assert!(java_blank("") && java_blank(" \t\u{1c}\u{3000}"));
        assert!(!java_blank("\u{a0}"), "a non-breaking space is not Java whitespace");
        assert!(!java_blank("\u{85}"));
        assert!(java_whitespace('\u{2029}') && java_whitespace('\u{2008}') && !java_whitespace('\u{2007}'));
        assert_eq!(java_trim("\u{1} x \u{a0}"), "x \u{a0}");
        assert!(now_millis() > 1_700_000_000_000);
    }

    // ---------------------------------------------------------------- schedule

    fn base() -> EventSchedule {
        EventSchedule { cron: Some("* * * * *".into()), timezone: Some("UTC".into()), per_client: Some(true), enabled: Some(true), spread: None }
    }

    // Port of commons-core `EventScheduleOverrideTest` (the merge and the copy; the runAt test
    // is in functions::schedule).

    #[test]
    fn an_override_keeps_the_base_fields_it_does_not_set() {
        let o = EventSchedule { cron: Some("*/5 * * * *".into()), ..Default::default() };
        let m = EventSchedule::merge(Some(&o), Some(&base())).unwrap();
        assert_eq!(m.cron.as_deref(), Some("*/5 * * * *"));
        assert_eq!(m.timezone.as_deref(), Some("UTC"));
        assert!(m.is_for_each_client());
        assert!(m.is_active());
    }

    #[test]
    fn an_override_can_switch_only_its_own_runs_off() {
        let o = EventSchedule { enabled: Some(false), ..Default::default() };
        let m = EventSchedule::merge(Some(&o), Some(&base())).unwrap();
        assert!(!m.is_active());
        assert_eq!(m.cron.as_deref(), Some("* * * * *"));
    }

    #[test]
    fn an_override_without_a_schedule_inherits_the_base_one() {
        assert_eq!(EventSchedule::merge(None, Some(&base())), Some(base()));
        assert_eq!(EventSchedule::merge(Some(&base()), None), Some(base()));
        assert_eq!(EventSchedule::merge(None, None), None);
    }

    #[test]
    fn saving_an_override_stores_only_what_differs() {
        let edited = EventSchedule { timezone: Some("Asia/Kolkata".into()), ..base() };
        assert_eq!(
            EventSchedule::difference(Some(&edited), Some(&base())),
            Some(EventSchedule { timezone: Some("Asia/Kolkata".into()), ..Default::default() })
        );
        assert_eq!(EventSchedule::difference(Some(&base()), Some(&base())), None);
        assert_eq!(EventSchedule::difference(Some(&base()), None), Some(base()));
        assert_eq!(EventSchedule::difference(None, Some(&base())), None);
    }

    #[test]
    fn spread_inherits_like_the_other_fields() {
        let b = EventSchedule { cron: Some("*/5 * * * *".into()), per_client: Some(true), spread: Some(true), ..Default::default() };
        assert_eq!(b.to_j(), JValue::Object(match overridable::json::parse(br#"{"cron":"*/5 * * * *","perClient":true,"spread":true}"#).unwrap() {
            JValue::Object(m) => m,
            _ => unreachable!(),
        }));
        assert!(EventSchedule::merge(Some(&EventSchedule { enabled: Some(true), ..Default::default() }), Some(&b)).unwrap().is_spread_across_period());
        assert!(!EventSchedule::merge(Some(&EventSchedule { spread: Some(false), ..Default::default() }), Some(&b)).unwrap().is_spread_across_period());
        assert_eq!(EventSchedule::difference(Some(&EventSchedule { spread: Some(false), ..b.clone() }), Some(&b)).unwrap().spread, Some(false));
    }

    #[test]
    fn schedules_read_as_spring_converts_them() {
        let d = doc! {"cron": 5_i32, "timezone": 1.5, "perClient": "Yes", "enabled": " off ", "spread": "maybe", "extra": 1};
        let s = EventSchedule::from_bson(&d);
        assert_eq!(s, EventSchedule { cron: Some("5".into()), timezone: Some("1.5".into()), per_client: Some(true), enabled: Some(false), spread: None });
        assert_eq!(s.to_bson(), doc! {"cron": "5", "timezone": "1.5", "perClient": true, "enabled": false});
        let t = EventSchedule::from_j(&JValue::Object(bson_conv::doc_to_j(&doc! {"cron": true, "enabled": 1_i32, "timezone": {"a": 1}}))).unwrap();
        assert_eq!((t.cron.as_deref(), t.enabled, t.timezone), (Some("true"), None, None));
        assert_eq!(EventSchedule::from_j(&JValue::Str("x".into())), None);
        assert_eq!(EventSchedule::default().effective_timezone(), "UTC");
        assert_eq!(EventSchedule { timezone: Some(" ".into()), ..Default::default() }.effective_timezone(), "UTC");
        assert_eq!(EventSchedule { timezone: Some("Asia/Kolkata".into()), ..Default::default() }.effective_timezone(), "Asia/Kolkata");
        assert!(!EventSchedule { cron: Some(" ".into()), ..Default::default() }.is_active());
        assert!(!EventSchedule::default().is_active());
        // The resolved definition's merge.
        let merged = EventSchedule::merge_j(Some(&EventSchedule { enabled: Some(false), ..Default::default() }.to_j()), Some(&base().to_j()));
        assert_eq!(EventSchedule::from_j(&merged).unwrap(), EventSchedule { enabled: Some(false), ..base() });
        assert_eq!(EventSchedule::merge_j(None, Some(&JValue::Null)), JValue::Null);
    }

    #[test]
    fn the_definition_merge_folds_the_schedule_field_by_field() {
        use overridable::store::apply_actual_override;
        let obj = |s: &str| match overridable::json::parse(s.as_bytes()).unwrap() {
            JValue::Object(m) => m,
            _ => unreachable!(),
        };
        let root = obj(r#"{"name":"e","schedule":{"cron":"0 * * * *","timezone":"UTC","perClient":true,"enabled":false,"junk":1}}"#);
        let own = obj(r#"{"name":"e","schedule":{"cron":"*/5 * * * *"}}"#);
        let m = apply_actual_override(&EventDefinitionDoc, own, Some(&root)).unwrap();
        assert_eq!(
            EventSchedule::from_j(&m["schedule"]).unwrap(),
            EventSchedule { cron: Some("*/5 * * * *".into()), timezone: Some("UTC".into()), per_client: Some(true), enabled: Some(false), spread: None },
            "a cron override keeps the base's enabled: false"
        );
        assert!(m["schedule"].as_object().unwrap().get("junk").is_none());
        let none = apply_actual_override(&EventDefinitionDoc, obj(r#"{"name":"e"}"#), Some(&obj(r#"{"name":"e"}"#))).unwrap();
        assert_eq!(none["schedule"], JValue::Null);
    }

    // ---------------------------------------------------------------- rows and indexes

    #[test]
    fn statuses_and_rows_read_as_spring_reads_them() {
        for s in [Status::Pending, Status::Claimed, Status::Done, Status::Failed, Status::Cancelled] {
            assert_eq!(Status::parse(s.name()), Some(s));
        }
        assert_eq!(Status::parse("pending"), None);
        let oid = mongodb::bson::oid::ObjectId::parse_str("6aceb6ea684b065f1b0a6520").unwrap();
        let d = doc! {
            "_id": oid, "appCode": "leadzumptwo", "draft": false, "key": "cps-disc-52", "clientCode": "FIN2", "attempts": 1_i32,
            "createdAt": DateTime::from_millis(1), "data": {"job": "discovery"}, "eventName": "LZ_CAMPAIGN_ONE", "maxAttempts": 5_i64,
            "runAt": DateTime::from_millis(2), "scheduledBy": "0", "status": "DONE", "updatedAt": DateTime::from_millis(3),
            "claimToken": "t", "owner": "core-1", "finishedAt": DateTime::from_millis(4), "leaseUntil": "not a date", "lastError": 7_i32,
        };
        let e = ScheduledEvent::from_document(&d);
        assert_eq!(e.id.as_deref(), Some("6aceb6ea684b065f1b0a6520"));
        assert_eq!((e.app_code.as_deref(), e.client_code.as_deref(), e.key.as_deref()), (Some("leadzumptwo"), Some("FIN2"), Some("cps-disc-52")));
        assert!(!e.draft);
        assert_eq!((e.attempts, e.max_attempts, e.status), (1, 5, Some(Status::Done)));
        assert_eq!(e.data, Some(doc! {"job": "discovery"}));
        assert_eq!((e.run_at, e.created_at, e.updated_at, e.finished_at), (
            Some(DateTime::from_millis(2)),
            Some(DateTime::from_millis(1)),
            Some(DateTime::from_millis(3)),
            Some(DateTime::from_millis(4))
        ));
        assert_eq!((e.owner.as_deref(), e.claim_token.as_deref(), e.scheduled_by.as_deref()), (Some("core-1"), Some("t"), Some("0")));
        assert_eq!((e.lease_until, e.last_error.as_deref()), (None, Some("7")));
        let f = ScheduledEvent::from_document(&doc! {"draft": true, "attempts": 2.9, "status": "WHAT"});
        assert!(f.draft);
        assert_eq!((f.attempts, f.max_attempts, f.status, f.key), (2, 0, None, None));
    }

    #[test]
    fn indexes_as_ensure_indexes_makes_them() {
        let models = index_models(&EventSchedulerSettings::default());
        let shown: Vec<(&str, Document, Option<String>, Option<bool>, Option<Document>, Option<u64>, bool)> = models
            .iter()
            .map(|(c, m, req)| {
                let o = m.options.clone().unwrap();
                (*c, m.keys.clone(), o.name, o.unique, o.partial_filter_expression, o.expire_after.map(|d| d.as_secs()), *req)
            })
            .collect();
        assert_eq!(
            shown,
            vec![
                ("schedule_run", doc! {"appCode": 1, "clientCode": 1, "eventName": 1, "tickAt": 1}, Some(RUN_UNIQUE_INDEX.into()), Some(true), None, None, true),
                ("scheduled_event", doc! {"appCode": 1, "clientCode": 1, "draft": 1, "key": 1}, Some(EVENT_KEY_UNIQUE_INDEX.into()), Some(true), None, None, true),
                ("schedule_run", doc! {"appCode": 1, "clientCode": 1, "eventName": 1}, Some("scheduleRunRunning".into()), None, Some(doc! {"status": "RUNNING"}), None, false),
                ("schedule_run", doc! {"createdAt": 1}, Some("scheduleRunExpiry".into()), None, None, Some(259_200), false),
                ("scheduled_event", doc! {"status": 1, "runAt": 1}, Some("scheduledEventDue".into()), None, None, None, false),
                ("scheduled_event", doc! {"status": 1, "leaseUntil": 1}, Some("scheduledEventLease".into()), None, None, None, false),
                ("scheduled_event", doc! {"finishedAt": 1}, Some("scheduledEventExpiry".into()), None, None, Some(604_800), false),
            ]
        );
    }

    fn event(key: &str) -> ScheduledEvent {
        ScheduledEvent {
            app_code: Some("leadzumptwo".into()),
            client_code: Some("FIN".into()),
            draft: false,
            key: Some(key.into()),
            event_name: Some("taskReminder".into()),
            data: Some(doc! {"taskId": "t1"}),
            run_at: Some(DateTime::from_millis(5_000)),
            max_attempts: 5,
            scheduled_by: Some("110".into()),
            ..Default::default()
        }
    }

    #[test]
    fn the_upsert_and_cancel_as_spring_sends_them() {
        let now = DateTime::from_millis(1_000);
        assert_eq!(
            upsert_filter(&event("task-1"), 1_000),
            doc! {"appCode": "leadzumptwo", "clientCode": "FIN", "draft": false, "key": "task-1",
                  "$or": [{"status": {"$ne": "CLAIMED"}}, {"leaseUntil": {"$lt": now}}]}
        );
        assert_eq!(
            upsert_update(&event("task-1"), 1_000),
            doc! {
                "$set": {"eventName": "taskReminder", "data": {"taskId": "t1"}, "runAt": DateTime::from_millis(5_000), "status": "PENDING",
                         "attempts": 0_i32, "maxAttempts": 5_i32, "scheduledBy": "110", "updatedAt": now},
                "$unset": {"owner": 1_i32, "claimToken": 1_i32, "leaseUntil": 1_i32, "lastError": 1_i32, "finishedAt": 1_i32},
                "$setOnInsert": {"createdAt": now},
            }
        );
        let bare = ScheduledEvent::default();
        let u = upsert_update(&bare, 0);
        let set = u.get_document("$set").unwrap();
        assert_eq!((set.get("eventName"), set.get("data"), set.get("runAt"), set.get("scheduledBy")), (Some(&Bson::Null), Some(&Bson::Null), Some(&Bson::Null), Some(&Bson::Null)));
        assert_eq!(upsert_filter(&bare, 0).get("appCode"), Some(&Bson::Null));
        assert_eq!(
            cancel_filter_update("a", "C", true, "k", 1_000),
            (
                doc! {"appCode": "a", "clientCode": "C", "draft": true, "key": "k", "status": "PENDING"},
                doc! {"$set": {"status": "CANCELLED", "finishedAt": now, "updatedAt": now}}
            )
        );
    }

    #[test]
    fn data_as_json_util_and_spring_store_it() {
        // Key orders taken from Java 25 (`HashMap` by puts, then `new HashMap<>(map)`).
        let o = json!({"zeta": 1, "campaignId": "52", "job": null, "alpha": [1, 2_147_483_648_i64, 1.5, {"y": 1, "x": 2}], "b": true,
                       "taskId": {"n": 18_446_744_073_709_551_615_u64}, "when": []});
        let m = json_util_map(o.as_object().unwrap());
        let keys: Vec<&str> = m.keys().map(String::as_str).collect();
        assert_eq!(keys, ["zeta", "b", "campaignId", "alpha", "job", "when", "taskId"]);
        assert_eq!(m.get("job"), Some(&Bson::Null));
        assert_eq!(m.get("zeta"), Some(&Bson::Int32(1)));
        let a = m.get_array("alpha").unwrap();
        assert_eq!(a[..3], [Bson::Int32(1), Bson::Int64(2_147_483_648), Bson::Double(1.5)]);
        assert_eq!(a[3], Bson::Document(doc! {"y": 1, "x": 2}));
        assert_eq!(m.get_document("taskId").unwrap().get("n"), Some(&Bson::Int64(-1)));
        let two = json_util_map(json!({"job": "discovery", "campaignId": "52"}).as_object().unwrap());
        assert_eq!(two.keys().collect::<Vec<_>>(), ["campaignId", "job"]);
        let copied = hash_map_order(two, java_map::capacity_by_copy);
        assert_eq!(copied.keys().collect::<Vec<_>>(), ["job", "campaignId"], "as the local rows hold it");
    }

    // ---------------------------------------------------------------- the service

    #[derive(Default)]
    struct FakeStore {
        calls: Mutex<Vec<String>>,
        events: Mutex<Vec<(ScheduledEvent, i64)>>,
        in_flight: Mutex<bool>,
        index_failure: Mutex<bool>,
    }

    #[async_trait]
    impl OneOffStore for FakeStore {
        async fn ensure_indexes(&self) -> Result<(), CoreError> {
            self.calls.lock().push("indexes".into());
            if *self.index_failure.lock() {
                return Err(CoreError::unknown("index refused"));
            }
            Ok(())
        }
        async fn upsert_scheduled_event(&self, event: &ScheduledEvent, now: i64) -> Result<Option<ScheduledEvent>, CoreError> {
            self.calls.lock().push(format!("upsert {}", event.key.clone().unwrap_or_default()));
            self.events.lock().push((event.clone(), now));
            Ok((!*self.in_flight.lock()).then(|| event.clone()))
        }
        async fn cancel_scheduled_event(&self, app: &str, client: &str, draft: bool, key: &str, now: i64) -> Result<bool, CoreError> {
            self.calls.lock().push(format!("cancel {app} {client} {draft} {key} {now}"));
            Ok(key == "pending")
        }
        async fn find_scheduled_event(&self, id: &str) -> Result<Option<ScheduledEvent>, CoreError> {
            self.calls.lock().push(format!("find {id}"));
            Ok(self.events.lock().iter().map(|(e, _)| e.clone()).find(|e| e.id.as_deref() == Some(id)))
        }
        async fn complete_scheduled_event(&self, id: &str, token: &str, now: i64) -> Result<bool, CoreError> {
            self.calls.lock().push(format!("complete {id} {token} {now}"));
            Ok(true)
        }
        async fn fail_scheduled_event(&self, id: &str, token: &str, retry_at: Option<i64>, error: Option<&str>, now: i64) -> Result<bool, CoreError> {
            self.calls.lock().push(format!("fail {id} {token} {retry_at:?} {error:?} {now}"));
            Ok(true)
        }
    }

    fn service(store: Arc<FakeStore>, settings: EventSchedulerSettings) -> ScheduledEventService {
        let t = Arc::new(AtomicI64::new(10_000));
        ScheduledEventService::new(store, settings).with_clock(Arc::new(move || t.fetch_add(1, Ordering::SeqCst)))
    }

    fn request(key: &str) -> ScheduleRequest {
        ScheduleRequest {
            app_code: "leadzumptwo".into(),
            client_code: "FIN".into(),
            draft: true,
            event_name: "taskReminder".into(),
            data: json_util_map(json!({"job": "x", "campaignId": "1"}).as_object().unwrap()),
            run_at: Some(77),
            key: key.into(),
            scheduled_by: Some("110".into()),
        }
    }

    #[tokio::test]
    async fn schedule_builds_the_row_java_builds() {
        let store = Arc::new(FakeStore::default());
        let svc = service(store.clone(), EventSchedulerSettings::default());
        let s = svc.schedule(request("task-1")).await.unwrap();
        assert_eq!(s.key, "task-1");
        let (row, now) = store.events.lock()[0].clone();
        assert_eq!(s.event, Some(row.clone()));
        assert_eq!(now, 10_000);
        assert_eq!(*store.calls.lock(), ["indexes", "upsert task-1"], "the indexes come first");
        assert_eq!(row.app_code.as_deref(), Some("leadzumptwo"));
        assert_eq!(row.client_code.as_deref(), Some("FIN"));
        assert!(row.draft);
        assert_eq!(row.event_name.as_deref(), Some("taskReminder"));
        assert_eq!(row.run_at, Some(DateTime::from_millis(77)));
        assert_eq!(row.max_attempts, 5);
        assert_eq!(row.scheduled_by.as_deref(), Some("110"));
        assert_eq!(row.data.unwrap().keys().collect::<Vec<_>>(), ["job", "campaignId"], "new HashMap<>(data)");
        assert_eq!(row.status, None);

        // A blank key gets a fresh one; no time is now; max attempts is at least one.
        let mut settings = EventSchedulerSettings::default();
        settings.oneoff.max_attempts = 0;
        let svc = service(store.clone(), settings);
        let mut r = request(" \t");
        r.run_at = None;
        let s = svc.schedule(r).await.unwrap();
        assert_eq!(s.key.len(), 36);
        assert!(mongodb::bson::Uuid::parse_str(&s.key).is_ok());
        let (row, now) = store.events.lock()[1].clone();
        assert_eq!(row.key.as_deref(), Some(s.key.as_str()));
        assert_eq!(row.run_at, Some(DateTime::from_millis(now)));
        assert_eq!(row.max_attempts, 1);

        // A key in flight: refused, the key still answered.
        *store.in_flight.lock() = true;
        let s = svc.schedule(request("sync-1")).await.unwrap();
        assert_eq!(s, Scheduled { key: "sync-1".into(), event: None });

        // Indexes that cannot be made stop the write.
        *store.index_failure.lock() = true;
        let before = store.events.lock().len();
        assert_eq!(svc.schedule(request("k")).await.unwrap_err().text(), "index refused");
        assert!(svc.cancel("a", "C", false, "pending").await.is_err());
        assert_eq!(store.events.lock().len(), before);
    }

    #[tokio::test]
    async fn cancel_needs_a_key() {
        let store = Arc::new(FakeStore::default());
        let svc = service(store.clone(), EventSchedulerSettings::default());
        assert!(!svc.cancel("leadzumptwo", "FIN", false, " ").await.unwrap());
        assert!(store.calls.lock().is_empty(), "a blank key never reaches the store");
        assert!(svc.cancel("leadzumptwo", "FIN", true, "pending").await.unwrap());
        assert!(!svc.cancel("leadzumptwo", "FIN", false, "gone").await.unwrap());
        assert_eq!(
            *store.calls.lock(),
            ["indexes", "cancel leadzumptwo FIN true pending 10000", "indexes", "cancel leadzumptwo FIN false gone 10001"]
        );
    }

    /// The store against a Mongo nobody listens on: every operation fails, the required index
    /// stops the rest, and nothing is remembered.
    #[tokio::test]
    async fn the_store_passes_mongo_failures_up() {
        let db = mongodb::Client::with_uri_str("mongodb://127.0.0.1:1/?serverSelectionTimeoutMS=200&connectTimeoutMS=200")
            .await
            .unwrap()
            .database("core");
        let store = ScheduleStore::new(db, EventSchedulerSettings::default());
        assert_eq!(store.ensure_indexes().await.unwrap_err().status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        assert!(store.indexes.get().is_none(), "a failure is retried on the next call");
        assert!(store.upsert_scheduled_event(&event("k"), 1).await.is_err());
        assert!(store.cancel_scheduled_event("a", "C", false, "k", 1).await.is_err());
    }

    // ---------------------------------------------------------------- event definitions

    const APP: &str = "leadzumptwo";
    const EVENT: &str = "LZ_WA_OUTBOX";

    struct Defs {
        backend: Arc<MemBackend>,
        directory: Arc<FakeDirectory>,
        service: EventDefinitionService,
    }

    fn defs() -> Defs {
        let backend = Arc::new(MemBackend::new());
        let directory = Arc::new(FakeDirectory::new());
        let cache = CacheService::new("cmn", "evictionChannel", None).unwrap();
        let store = Store::with_parts(backend.clone(), directory.clone(), &cache).unwrap();
        Defs { backend, directory, service: EventDefinitionService::new(store, cache) }
    }

    fn rows(d: &Defs, client: &str) -> Vec<Document> {
        d.backend.all("eventDefinition").into_iter().filter(|x| x.get_str("clientCode") == Ok(client)).collect()
    }

    fn base_schedule(enabled: Option<bool>) -> Document {
        let mut s = doc! {"cron": "0 */15 * * * ?", "timezone": "UTC", "perClient": true, "spread": true};
        if let Some(e) = enabled {
            s.insert("enabled", e);
        }
        s
    }

    fn put(d: &Defs, doc: Document) -> Bson {
        d.backend.put_raw("eventDefinition", doc)
    }

    // Port of commons-core `SetScheduleEnabledFunctionTest`, the service half (the function
    // half is in functions::schedule), over the real read path on in-memory documents.

    #[tokio::test]
    async fn creates_a_copy_with_only_enabled() {
        let d = defs();
        d.directory.set(|a| {
            a.chains.insert("AKASH".into(), vec!["SYSTEM".into(), "FIN".into(), "AKASH".into()]);
        });
        put(&d, doc! {"name": EVENT, "appCode": APP, "clientCode": "SYSTEM", "schema": {"type": "OBJECT"}, "schedule": base_schedule(None)});
        put(&d, doc! {"name": EVENT, "appCode": APP, "clientCode": "FIN", "baseClientCode": "SYSTEM", "schedule": {"enabled": false}});
        // AKASH sees FIN's copy, so that is the one its new copy overrides.
        let before = d.service.read_effective(EVENT, APP, "AKASH").await.unwrap().unwrap();
        assert_eq!(before["clientCode"], JValue::Str("FIN".into()));

        assert_eq!(d.service.set_own_schedule_enabled(EVENT, APP, "AKASH", true).await.unwrap(), Some(true));
        let saved = rows(&d, "AKASH");
        assert_eq!(saved.len(), 1);
        let mut copy = saved[0].clone();
        assert!(matches!(copy.remove("_id"), Some(Bson::ObjectId(_))));
        assert_eq!(saved[0].keys().next().map(String::as_str), Some("_id"), "the id is written first");
        assert_eq!(
            copy,
            doc! {"schedule": {"enabled": true}, "name": EVENT,
                  "message": "Schedule enabled for AKASH by CoreServices.Event.SetScheduleEnabled",
                  "clientCode": "AKASH", "appCode": APP, "baseClientCode": "FIN", "version": 1},
            "only enabled, the cron and the schema stay with the base, and the copy links to FIN"
        );
        // The cache the read above filled was evicted: the client now runs.
        let after = d.service.read_effective(EVENT, APP, "AKASH").await.unwrap().unwrap();
        let s = EventSchedule::from_j(&after["schedule"]).unwrap();
        assert_eq!(s.enabled, Some(true));
        assert_eq!(s.cron.as_deref(), Some("0 */15 * * * ?"));
        assert!(s.is_active());
    }

    #[tokio::test]
    async fn updates_an_existing_copy() {
        let d = defs();
        d.directory.chain(&["SYSTEM", "FIN"]);
        put(&d, doc! {"name": EVENT, "appCode": APP, "clientCode": "SYSTEM", "schedule": base_schedule(Some(true))});
        let created = DateTime::from_millis(1_760_000_000_000);
        let id = put(&d, doc! {
            "name": EVENT, "createdBy": "142", "appCode": APP, "clientCode": "FIN", "baseClientCode": "SYSTEM",
            "schedule": {"cron": "0 */5 * * * ?", "enabled": true, "junk": 1}, "version": 3_i64, "createdAt": created,
            "schema": {"a__d-o-t__b": {"c.d": 1}, "x.y": null}, "published": "true", "permission": 5_i32,
            "includeContextAuthentication": null, "_class": "x", "unknown": 1, "updatedAt": "not a date", "notOverridable": "maybe",
        });
        assert_eq!(d.service.set_own_schedule_enabled(EVENT, APP, "FIN", false).await.unwrap(), Some(true));
        let saved = rows(&d, "FIN");
        assert_eq!(saved.len(), 1);
        assert_eq!(
            saved[0],
            doc! {
                "_id": id, "schema": {"a__d-o-t__b": {"c.d": 1}, "x__d-o-t__y": null},
                "schedule": {"cron": "0 */5 * * * ?", "enabled": false}, "name": EVENT,
                "message": "Schedule disabled for FIN by CoreServices.Event.SetScheduleEnabled", "clientCode": "FIN",
                "permission": "5", "appCode": APP, "baseClientCode": "SYSTEM", "published": true, "version": 4_i32,
                "createdAt": created, "createdBy": "142",
            },
            "the copy as Spring Data writes it back: its fields only, in the class's order, only enabled moved"
        );
        assert_eq!(d.service.read_effective(EVENT, APP, "FIN").await.unwrap().unwrap()["version"], JValue::Int(4));
    }

    #[tokio::test]
    async fn an_own_copy_without_a_schedule_or_version_gets_both() {
        let d = defs();
        d.directory.chain(&["SYSTEM", "FIN"]);
        put(&d, doc! {"name": EVENT, "appCode": APP, "clientCode": "SYSTEM", "schedule": base_schedule(Some(false))});
        let id = put(&d, doc! {"name": EVENT, "appCode": APP, "clientCode": "FIN", "baseClientCode": "SYSTEM", "version": "x"});
        assert_eq!(d.service.set_own_schedule_enabled(EVENT, APP, "FIN", true).await.unwrap(), Some(true));
        assert_eq!(
            rows(&d, "FIN")[0],
            doc! {"_id": id, "schedule": {"enabled": true}, "name": EVENT,
                  "message": "Schedule enabled for FIN by CoreServices.Event.SetScheduleEnabled", "clientCode": "FIN",
                  "appCode": APP, "baseClientCode": "SYSTEM", "version": 2_i32}
        );
    }

    #[tokio::test]
    async fn no_change_writes_nothing() {
        let d = defs();
        d.directory.set(|a| {
            a.chains.insert("FIN".into(), vec!["FIN".into()]);
            a.chains.insert("AKHIL".into(), vec!["AKHIL".into()]);
        });
        put(&d, doc! {"name": EVENT, "appCode": APP, "clientCode": "FIN", "schedule": base_schedule(Some(true))});
        put(&d, doc! {"name": EVENT, "appCode": APP, "clientCode": "AKHIL", "schedule": base_schedule(None)});
        assert_eq!(d.service.set_own_schedule_enabled(EVENT, APP, "FIN", true).await.unwrap(), Some(false));
        assert_eq!(d.service.set_own_schedule_enabled(EVENT, APP, "AKHIL", true).await.unwrap(), Some(false), "absent enabled already means enabled");
        assert_eq!(d.backend.all("eventDefinition").len(), 2);
        assert!(rows(&d, "FIN")[0].get("message").is_none());
    }

    #[tokio::test]
    async fn an_unknown_or_unscheduled_event_writes_nothing() {
        let d = defs();
        put(&d, doc! {"name": EVENT, "appCode": APP, "clientCode": "FIN", "schema": {}});
        assert_eq!(d.service.set_own_schedule_enabled(EVENT, APP, "FIN", true).await.unwrap(), None);
        assert_eq!(d.service.set_own_schedule_enabled(EVENT, APP, "NOBODY", true).await.unwrap(), None);
        assert_eq!(d.backend.all("eventDefinition").len(), 1);
    }

    #[tokio::test]
    async fn two_own_copies_are_an_error_and_failures_pass_up() {
        let d = defs();
        d.directory.chain(&["FIN"]);
        put(&d, doc! {"name": EVENT, "appCode": APP, "clientCode": "FIN", "schedule": base_schedule(Some(true))});
        put(&d, doc! {"name": EVENT, "appCode": APP, "clientCode": "FIN", "schedule": base_schedule(Some(true))});
        let e = d.service.set_own_schedule_enabled(EVENT, APP, "FIN", false).await.unwrap_err();
        assert!(e.text().ends_with("returned non unique result."), "{}", e.text());
        let d = defs();
        d.backend.fail("eventDefinition", true);
        assert!(d.service.set_own_schedule_enabled(EVENT, APP, "FIN", false).await.is_err());
    }

    #[tokio::test]
    async fn eviction_reaches_both_surfaces() {
        let d = defs();
        d.directory.chain(&["FIN"]);
        put(&d, doc! {"name": EVENT, "appCode": APP, "clientCode": "FIN", "schedule": base_schedule(Some(true))});
        let store = d.service.store.clone();
        let enabled = |draft: bool| {
            let store = store.clone();
            async move {
                let r = store.read(&EventDefinitionDoc, EVENT, APP, "FIN", "FIN", draft).await.unwrap().unwrap();
                EventSchedule::from_j(&r.entity["schedule"]).unwrap().enabled
            }
        };
        assert_eq!((enabled(true).await, enabled(false).await), (Some(true), Some(true)));
        // Both surfaces are cached now: a change behind the caches' back is not seen.
        let id = rows(&d, "FIN")[0].get("_id").cloned().unwrap();
        put(&d, doc! {"_id": id.clone(), "name": EVENT, "appCode": APP, "clientCode": "FIN", "schedule": base_schedule(None)});
        assert_eq!((enabled(true).await, enabled(false).await), (Some(true), Some(true)));
        assert_eq!(d.service.set_own_schedule_enabled(EVENT, APP, "FIN", false).await.unwrap(), Some(true));
        assert_eq!((enabled(true).await, enabled(false).await), (Some(false), Some(false)), "both surfaces re-read");
    }

    #[test]
    fn spring_event_definitions_keep_only_the_class() {
        assert_eq!(spring_event_definition(&doc! {}), doc! {"version": 1_i32});
        assert_eq!(spring_event_definition(&doc! {"version": true, "_id": Bson::Null}), doc! {"version": 1_i32});
        assert_eq!(
            spring_event_definition(&doc! {"version": 2.7, "title": Bson::Undefined, "description": [1], "schedule": "x", "blueprint": 1_i32}),
            doc! {"version": 2_i32}
        );
    }

    // ---------------------------------------------------------------- local Mongo

    /// The store and the definition writes against a scratch database on the local Mongo,
    /// dropped at the end: the rows and indexes as the server keeps them.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs the local stack: CORE_LOCAL_STACK=1 and config/local.toml"]
    async fn against_a_scratch_database() {
        use futures::FutureExt;
        if !crate::testing::local_stack() {
            return;
        }
        let uri = std::env::var("MODLIX__MONGO__URI").ok().filter(|u| !u.is_empty()).unwrap_or_else(|| "mongodb://localhost:27017".into());
        let client = mongodb::Client::with_uri_str(&uri).await.expect("mongo");
        let name = format!("rs_scratch_schedule_{}", mongodb::bson::oid::ObjectId::new().to_hex());
        let db = client.database(&name);
        let outcome = std::panic::AssertUnwindSafe(scratch_checks(db.clone())).catch_unwind().await;
        db.drop().await.expect("drop the scratch database");
        assert!(!client.list_database_names().await.unwrap().contains(&name));
        if let Err(p) = outcome {
            std::panic::resume_unwind(p);
        }
    }

    async fn scratch_checks(db: Database) {
        use futures::TryStreamExt;
        let settings = EventSchedulerSettings::default();
        let store = Arc::new(ScheduleStore::new(db.clone(), settings.clone()));
        let clock = Arc::new(AtomicI64::new(1_791_000_000_000));
        let c = clock.clone();
        let svc = ScheduledEventService::new(store.clone(), settings.clone()).with_clock(Arc::new(move || c.load(Ordering::SeqCst)));
        let events = db.collection::<Document>(SCHEDULED_EVENT_COLLECTION);
        let row = |key: &'static str| {
            let events = events.clone();
            async move { events.find_one(doc! {"key": key}).await.unwrap().unwrap() }
        };
        let req = |key: &str, run_at: i64, data: serde_json::Value| ScheduleRequest {
            app_code: APP.into(),
            client_code: "FIN".into(),
            draft: false,
            event_name: "taskReminder".into(),
            data: json_util_map(data.as_object().unwrap()),
            run_at: Some(run_at),
            key: key.into(),
            scheduled_by: Some("110".into()),
        };
        let now = clock.load(Ordering::SeqCst);

        // The indexes, as the Java store makes them.
        let s = svc.schedule(req("nudge-1", now + 3_600_000, json!({"v": 1, "job": "a", "campaignId": "2"}))).await.unwrap();
        assert_eq!(s.key, "nudge-1");
        let e = s.event.unwrap();
        assert_eq!((e.status, e.attempts, e.max_attempts), (Some(Status::Pending), 0, 5));
        let mut names: Vec<String> = events.list_index_names().await.unwrap();
        names.sort();
        assert_eq!(names, ["_id_", "scheduledEventDue", "scheduledEventExpiry", "scheduledEventKeyUnique", "scheduledEventLease"]);
        let mut run_names: Vec<String> = db.collection::<Document>(SCHEDULE_RUN_COLLECTION).list_index_names().await.unwrap();
        run_names.sort();
        assert_eq!(run_names, ["_id_", "scheduleRunExpiry", "scheduleRunRunning", "scheduleRunTickUnique"]);
        let specs: Vec<IndexModel> = events.list_indexes().await.unwrap().try_collect().await.unwrap();
        let expiry = specs.iter().find(|m| m.options.as_ref().and_then(|o| o.name.as_deref()) == Some("scheduledEventExpiry")).unwrap();
        assert_eq!(expiry.options.as_ref().unwrap().expire_after.map(|d| d.as_secs()), Some(604_800));
        // A second instance over the same database makes them again without complaint.
        ScheduleStore::new(db.clone(), settings.clone()).ensure_indexes().await.unwrap();

        // The row as Java writes it.
        let r = row("nudge-1").await;
        // `JsonUtil.toMap` then `new HashMap<>(data)` (capacity 8): the JDK writes job, v, campaignId.
        assert_eq!(r.get_document("data").unwrap().keys().collect::<Vec<_>>(), ["job", "v", "campaignId"]);
        assert_eq!(r.get_datetime("runAt").unwrap().timestamp_millis(), now + 3_600_000);
        assert_eq!(r.get_datetime("createdAt").unwrap().timestamp_millis(), now);
        assert_eq!((r.get_str("status").unwrap(), r.get_i32("attempts").unwrap(), r.get_i32("maxAttempts").unwrap()), ("PENDING", 0, 5));
        assert_eq!(r.get_str("scheduledBy").unwrap(), "110");
        assert!(!r.get_bool("draft").unwrap());
        assert!(r.get("_class").is_none() && r.get("owner").is_none());

        // Rescheduling a key replaces the pending row.
        clock.fetch_add(1000, Ordering::SeqCst);
        svc.schedule(req("nudge-1", now + 7_200_000, json!({"v": 2}))).await.unwrap();
        assert_eq!(events.count_documents(doc! {}).await.unwrap(), 1);
        let r = row("nudge-1").await;
        assert_eq!(r.get_datetime("runAt").unwrap().timestamp_millis(), now + 7_200_000);
        assert_eq!(r.get_document("data").unwrap(), &doc! {"v": 2});
        assert_eq!(r.get_datetime("createdAt").unwrap().timestamp_millis(), now, "set on insert only");
        assert_eq!(r.get_datetime("updatedAt").unwrap().timestamp_millis(), now + 1000);

        // A key in flight is not replaced under it; once its lease ran out it is.
        let lease = clock.load(Ordering::SeqCst) + 300_000;
        events
            .update_one(doc! {"key": "nudge-1"}, doc! {"$set": {"status": "CLAIMED", "owner": "o", "claimToken": "t",
                        "leaseUntil": DateTime::from_millis(lease), "attempts": 1, "lastError": "e"}})
            .await
            .unwrap();
        let again = svc.schedule(req("nudge-1", now, json!({"v": 3}))).await.unwrap();
        assert_eq!(again.event, None, "in flight, so refused");
        assert_eq!(row("nudge-1").await.get_str("status").unwrap(), "CLAIMED");
        assert!(!svc.cancel(APP, "FIN", false, "nudge-1").await.unwrap(), "a claimed row is not cancelled");
        clock.store(lease + 1, Ordering::SeqCst);
        let replaced = svc.schedule(req("nudge-1", now, json!({"v": 3}))).await.unwrap().event.unwrap();
        assert_eq!((replaced.status, replaced.attempts, replaced.owner, replaced.claim_token), (Some(Status::Pending), 0, None, None));
        let r = row("nudge-1").await;
        assert!(r.get("leaseUntil").is_none() && r.get("lastError").is_none());

        // Cancel: once, only the caller's own key.
        assert!(svc.cancel(APP, "FIN", false, "nudge-1").await.unwrap());
        let r = row("nudge-1").await;
        assert_eq!(r.get_str("status").unwrap(), "CANCELLED");
        assert!(r.get_datetime("finishedAt").is_ok());
        assert!(!svc.cancel(APP, "FIN", false, "nudge-1").await.unwrap(), "already cancelled");
        assert!(!svc.cancel(APP, "FIN", false, "never-scheduled").await.unwrap());
        assert!(!svc.cancel(APP, "FIN2", false, "nudge-1").await.unwrap(), "another client's key");
        // A cancelled key can be scheduled again, and loses its finish time.
        assert!(svc.schedule(req("nudge-1", now, json!({}))).await.unwrap().event.is_some());
        assert!(row("nudge-1").await.get("finishedAt").is_none());

        // A blank key gets one that can cancel it.
        let blank = svc.schedule(req("", now + 60_000, json!({}))).await.unwrap();
        assert!(svc.cancel(APP, "FIN", false, &blank.key).await.unwrap());

        // Draft and live keep separate keys.
        let mut draft = req("same", now, json!({}));
        draft.draft = true;
        svc.schedule(draft).await.unwrap();
        svc.schedule(req("same", now, json!({}))).await.unwrap();
        assert_eq!(events.count_documents(doc! {"key": "same"}).await.unwrap(), 2);

        // An index the server refuses (another expiry on the same field) is tolerated.
        let cache = CacheService::new("cmn", "evictionChannel", None).unwrap();
        let mut odd = settings.clone();
        odd.oneoff.retention_days = 9;
        ScheduleStore::new(db.clone(), odd).ensure_indexes().await.unwrap();

        // The definition writes as the server keeps them.
        let directory = Arc::new(FakeDirectory::new());
        directory.set(|a| {
            a.chains.insert("AKASH".into(), vec!["SYSTEM".into(), "FIN".into(), "AKASH".into()]);
            a.chains.insert("FIN".into(), vec!["SYSTEM".into(), "FIN".into()]);
        });
        let backend = Arc::new(overridable::backend::MongoBackend::new(db.clone()));
        let defs = EventDefinitionService::new(Store::with_parts(backend, directory, &cache).unwrap(), cache.clone());
        let eds = db.collection::<Document>("eventDefinition");
        eds.insert_one(doc! {"name": EVENT, "appCode": APP, "clientCode": "SYSTEM", "schedule": base_schedule(Some(false))}).await.unwrap();
        eds.insert_one(doc! {"name": EVENT, "appCode": APP, "clientCode": "FIN", "baseClientCode": "SYSTEM", "schedule": {"cron": "* * * * *"},
                             "version": 2, "createdAt": DateTime::from_millis(now)})
            .await
            .unwrap();
        assert_eq!(defs.set_own_schedule_enabled(EVENT, APP, "AKASH", true).await.unwrap(), Some(true));
        assert_eq!(defs.set_own_schedule_enabled(EVENT, APP, "FIN", true).await.unwrap(), Some(true));
        let akash = eds.find_one(doc! {"clientCode": "AKASH"}).await.unwrap().unwrap();
        assert_eq!(akash.keys().collect::<Vec<_>>(), ["_id", "schedule", "name", "message", "clientCode", "appCode", "baseClientCode", "version"]);
        assert_eq!(akash.get_str("baseClientCode").unwrap(), "FIN");
        let fin = eds.find_one(doc! {"clientCode": "FIN"}).await.unwrap().unwrap();
        assert_eq!(fin.keys().collect::<Vec<_>>(), ["_id", "schedule", "name", "message", "clientCode", "appCode", "baseClientCode", "version", "createdAt"]);
        assert_eq!(fin.get_document("schedule").unwrap(), &doc! {"cron": "* * * * *", "enabled": true});
        assert_eq!(fin.get_i32("version").unwrap(), 3);
        assert_eq!(eds.count_documents(doc! {}).await.unwrap(), 3);
    }
}
