//! `CoreServices.Platform.*`: the platform jobs of the retired Java `worker`, as core functions
//! an EventAction of the `platform` app (client SYSTEM) calls on its schedule. Rust only: the
//! Java core has no such family.
//!
//! Each makes the calls the worker's execution service made, through
//! [`crate::platform_calls`], with the worker's defaults:
//!
//! | Function | Worker job | Calls |
//! |---|---|---|
//! | `RenewCertificates(daysBeforeExpiry=30)` | SSL_RENEWAL | security `ssl/internal/renew-certificates` |
//! | `CleanupTokens(unusedDays=90)` | TOKEN_CLEANUP | security `internal/tokens/cleanup` |
//! | `Meter(service)` | *_METERING | the service's `internal/billing/meter` |
//! | `ReconcileBilling()` | BILLING_RECONCILE | security, core, entity-processor, files `internal/billing/reconcile` |
//! | `CleanupExpiredFiles(limit=500)` | FILES_TTL_CLEANUP | files `cleanupExpired`, `applyRetention` per bucket, core `events/internal/raise`, entity-processor `whatsapp/internal/media/stampExpired` |
//! | `CleanupTransports(service, retentionDays=90, limit=200)` | TRANSPORT_CLEANUP | ui or core `transports/internal/cleanupOlderThan` |
//! | `CleanupEventRuns(retentionDays=90, successRetentionDays=7, staleAfterHours=6, limit=50000)` | EVENT_RUN_CLEANUP | core `eventRuns/internal/cleanupOlderThan` |
//!
//! **The guard.** They reach internal endpoints that delete and charge, so each runs only when
//! all of these hold, and otherwise answers 403 before reading its arguments or calling
//! anything:
//! - core-events is running an EventAction ([`context::event_action`], a task-local only the
//!   events consumer sets; a request, a page or the execute route never has it);
//! - that action is the `platform` app's, for client `SYSTEM`;
//! - it runs under the event runner's context (`Authorities._Event_Runner`): the event was
//!   raised without a caller (a scheduler tick or one-off), not by `CoreServices.Event.
//!   CreateEvent`, which lets any server function raise any app's event for any client and
//!   carries the raiser's authentication;
//! - no definition owned by another app is running ([`context::owner_app_code`] is none or
//!   `platform`), so another app cannot reach them through a function of its own that a
//!   platform action happens to run.
//!
//! **Listing.** `repositoryFind` / `repositoryFilter` do not show them to any app but
//! `platform` ([`listed`]), as Java lists no such functions; execution still resolves them, so
//! a call from elsewhere is refused by the guard (403), not missing (404).
//!
//! **Failures.** A one-call function fails with the service's status and message, so the event
//! run reads FAILED with the reason (the worker wrote the text into `LAST_FIRE_RESULT`).
//! `ReconcileBilling` and `CleanupExpiredFiles` make every call whatever the others did, as the
//! worker did, and then fail (502) naming each call that failed, with what the rest answered.
//! `CleanupExpiredFiles`' event raises and WhatsApp stamping stay best effort: counted and
//! listed in `errors`, never a failure.

use std::sync::Arc;

use async_trait::async_trait;
use axum::http::StatusCode;
use kirun::function::{validate_arguments, Function};
use kirun::json::schema::Schema;
use kirun::model::{Event, FunctionOutput, FunctionSignature, Parameter};
use kirun::runtime::FunctionExecutionParameters;
use kirun::{Map, Value};
use serde_json::json;

use super::output;
use crate::context;
use crate::error::CoreError;
use crate::platform_calls::{PlatformCalls, Service};
use crate::repos::FunctionSource;

pub const NAMESPACE: &str = "CoreServices.Platform";
/// The app whose EventActions may run these, and the only app they are listed for.
pub const PLATFORM_APP: &str = "platform";
/// The client the platform app's actions run for.
pub const SYSTEM_CLIENT: &str = "SYSTEM";
/// Held only by the anonymous context core-events runs an event raised without a caller under
/// (`EventsQueListener.EVENT_RUNNER_AUTHORITY`).
pub const EVENT_RUNNER_AUTHORITY: &str = "Authorities._Event_Runner";

// The worker's defaults (its execution services' `DEFAULT_*` constants).
const DEFAULT_DAYS_BEFORE_EXPIRY: i64 = 30;
const DEFAULT_UNUSED_DAYS: i64 = 90;
const DEFAULT_FILES_LIMIT: i64 = 500;
const DEFAULT_TRANSPORT_RETENTION_DAYS: i64 = 90;
const DEFAULT_TRANSPORT_LIMIT: i64 = 200;
const DEFAULT_EVENT_RUN_RETENTION_DAYS: i64 = 90;
const DEFAULT_EVENT_RUN_SUCCESS_RETENTION_DAYS: i64 = 7;
const DEFAULT_EVENT_RUN_STALE_AFTER_HOURS: i64 = 6;
const DEFAULT_EVENT_RUN_LIMIT: i64 = 50_000;

/// `FilesTtlCleanupService`: the lifetime the WhatsApp uploads stamp on their files, the
/// stamping batch, the event raised per client and app, and the paths per event.
const WHATSAPP_RETENTION_DAYS: i64 = 30;
const WHATSAPP_STAMP_LIMIT: i64 = 1000;
pub const FILES_EXPIRED_EVENT: &str = "FILES_EXPIRED";
pub const MAX_PATHS_PER_EVENT: usize = 500;

const BUCKETS: [&str; 2] = ["secured", "static"];

/// One of the seven functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Job {
    RenewCertificates,
    CleanupTokens,
    Meter,
    ReconcileBilling,
    CleanupExpiredFiles,
    CleanupTransports,
    CleanupEventRuns,
}

impl Job {
    pub const ALL: [Job; 7] = [
        Job::RenewCertificates,
        Job::CleanupTokens,
        Job::Meter,
        Job::ReconcileBilling,
        Job::CleanupExpiredFiles,
        Job::CleanupTransports,
        Job::CleanupEventRuns,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Job::RenewCertificates => "RenewCertificates",
            Job::CleanupTokens => "CleanupTokens",
            Job::Meter => "Meter",
            Job::ReconcileBilling => "ReconcileBilling",
            Job::CleanupExpiredFiles => "CleanupExpiredFiles",
            Job::CleanupTransports => "CleanupTransports",
            Job::CleanupEventRuns => "CleanupEventRuns",
        }
    }

    pub fn full_name(self) -> String {
        format!("{NAMESPACE}.{}", self.name())
    }

    pub fn signature(self) -> FunctionSignature {
        let (description, params, result): (&str, Vec<(String, Parameter)>, Schema) = match self {
            Job::RenewCertificates => (
                "Renews the SSL certificates that expire within daysBeforeExpiry days (security). \
                 Outputs security's answer: renewedCount, failedCount, errors.",
                vec![int_param("daysBeforeExpiry", DEFAULT_DAYS_BEFORE_EXPIRY, "Renew certificates expiring within this many days.")],
                Schema::of_object("result"),
            ),
            Job::CleanupTokens => (
                "Deletes expired tokens and tokens unused for unusedDays days (security). Outputs security's \
                 answer: expiredTokensRemoved, unusedTokensRemoved, expiredDraftTokensRemoved.",
                vec![int_param("unusedDays", DEFAULT_UNUSED_DAYS, "Tokens unused for this many days are deleted.")],
                Schema::of_object("result"),
            ),
            Job::Meter => (
                "Runs the 15-minute token metering of one service. Outputs the service's answer (true when it ran).",
                vec![Parameter::of_entry(
                    "service",
                    Schema::of_string("service")
                        .set_description("The service to meter: security, core, entity-processor or files.".into()),
                    false,
                )],
                Schema::of_boolean("result"),
            ),
            Job::ReconcileBilling => (
                "Reconciles yesterday's billing on security, core, entity-processor and files, in that order, \
                 each whatever the others answered. Outputs each service's answer.",
                vec![],
                Schema::of_object("result"),
            ),
            Job::CleanupExpiredFiles => (
                "Asks files to remove expired files (secured, then static), then to apply the retention \
                 policies of each bucket, raising FILES_EXPIRED in core for every client and app that lost \
                 files, then has entity-processor mark the WhatsApp messages whose attachments went. \
                 Outputs per bucket expiredRemoved, retentionRemoved, eventsRaised, eventsFailed, and \
                 messagesMarkedExpired and errors.",
                vec![int_param("limit", DEFAULT_FILES_LIMIT, "At most this many files per bucket and step.")],
                Schema::of_object("result"),
            ),
            Job::CleanupTransports => (
                "Deletes one service's app-transport import receipts (and their versions) older than \
                 retentionDays, at most limit. Outputs the service's answer: transportsRemoved, versionsRemoved.",
                vec![
                    Parameter::of_entry(
                        "service",
                        Schema::of_string("service").set_description("The service whose transports to sweep: ui or core.".into()),
                        false,
                    ),
                    int_param("retentionDays", DEFAULT_TRANSPORT_RETENTION_DAYS, "Transports older than this many days are deleted."),
                    int_param("limit", DEFAULT_TRANSPORT_LIMIT, "At most this many transports per run."),
                ],
                Schema::of_object("result"),
            ),
            Job::CleanupEventRuns => (
                "Keeps core's event run log to its retention: closes runs still RUNNING after staleAfterHours, \
                 deletes successful runs older than successRetentionDays and every run older than \
                 retentionDays, at most limit rows. Outputs core's answer: runsRemoved, successesRemoved, staleClosed.",
                vec![
                    int_param("retentionDays", DEFAULT_EVENT_RUN_RETENTION_DAYS, "Every run started longer ago than this is deleted."),
                    int_param(
                        "successRetentionDays",
                        DEFAULT_EVENT_RUN_SUCCESS_RETENTION_DAYS,
                        "Successful runs started longer ago than this are deleted.",
                    ),
                    int_param("staleAfterHours", DEFAULT_EVENT_RUN_STALE_AFTER_HOURS, "A run still RUNNING after this is closed as FAILED."),
                    int_param("limit", DEFAULT_EVENT_RUN_LIMIT, "At most this many rows deleted per run."),
                ],
                Schema::of_object("result"),
            ),
        };
        FunctionSignature::new(self.name())
            .set_namespace(NAMESPACE)
            .set_description(format!("{description} Runs only as a task of the platform app's events."))
            .set_parameters(params.into_iter().collect())
            .set_events(Map::from([Event::output_event_map_entry(Map::from([("result".to_string(), result)]))]))
    }
}

fn int_param(name: &str, default: i64, description: &str) -> (String, Parameter) {
    Parameter::of_entry(
        name,
        Schema::of_integer(name).set_default_value(json!(default)).set_description(description.to_string()),
        false,
    )
}

/// The functions, over `calls`.
pub fn all(calls: &Arc<PlatformCalls>) -> Vec<Arc<dyn Function>> {
    Job::ALL
        .into_iter()
        .map(|job| Arc::new(PlatformFunction { job, signature: job.signature(), calls: calls.clone() }) as Arc<dyn Function>)
        .collect()
}

/// The 403 every refusal answers with.
pub fn refusal(full_name: &str) -> CoreError {
    CoreError::coded(StatusCode::FORBIDDEN, "CORE.PLATFORM_FUNCTION_REFUSED", format!("{full_name} runs only as a task of the platform app's events"))
        .param("function", full_name)
}

/// Why a platform function may not run here, or `None` when it may (see the module's guard).
pub fn refused_because() -> Option<String> {
    let Some(action) = context::event_action() else {
        return Some("not running as an event action's task".into());
    };
    if action.client_code != SYSTEM_CLIENT {
        return Some(format!("an event action of client {}", action.client_code));
    }
    if action.app_code != PLATFORM_APP {
        return Some(format!("an event action of app {}", action.app_code));
    }
    if !context::authentication().authorities().iter().any(|a| a == EVENT_RUNNER_AUTHORITY) {
        return Some("the event was raised by a caller, not by the scheduler".into());
    }
    match context::owner_app_code() {
        Some(owner) if owner != PLATFORM_APP => Some(format!("inside a definition owned by app {owner}")),
        _ => None,
    }
}

/// The guard: `Ok` only inside a `platform` / `SYSTEM` EventAction run as the event runner,
/// with no other app's definition running.
pub fn guard(full_name: &str) -> Result<(), CoreError> {
    match refused_because() {
        None => Ok(()),
        Some(reason) => {
            tracing::warn!(function = full_name, reason = %reason, "platform function refused");
            Err(refusal(full_name))
        }
    }
}

pub struct PlatformFunction {
    job: Job,
    signature: FunctionSignature,
    calls: Arc<PlatformCalls>,
}

#[async_trait]
impl Function for PlatformFunction {
    fn get_signature(&self) -> &FunctionSignature {
        &self.signature
    }

    /// The guard first, then the arguments (so a refused caller learns nothing from a
    /// validation error), then the job.
    async fn execute(&self, fep: &mut FunctionExecutionParameters) -> kirun::Result<FunctionOutput> {
        let full = self.job.full_name();
        guard(&full).map_err(context::raise)?;
        let args = validate_arguments(
            &self.signature,
            fep.get_arguments().cloned().unwrap_or_default(),
            fep.get_schema_repository().as_ref(),
            fep.get_statement_execution().map(|s| s.as_ref()),
        )
        .await?;
        fep.set_arguments_in_place(args.clone());
        let result = run(self.job, &self.calls, &args).await.map_err(context::raise)?;
        Ok(output("result", result))
    }
}

/// An integer argument (after validation, which put the default in).
fn int(args: &Map<Value>, name: &str, default: i64) -> i64 {
    match args.get(name) {
        Some(Value::Number(n)) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)).unwrap_or(default),
        _ => default,
    }
}

/// `service`, trimmed and lower-cased as `TransportCleanupService` reads it.
fn service_arg(args: &Map<Value>) -> String {
    match args.get("service") {
        Some(Value::String(s)) => s.trim().to_lowercase(),
        _ => String::new(),
    }
}

/// A service argument the platform function does not know.
fn bad_service(function: &str, given: &str, expected: &str, message: String) -> CoreError {
    CoreError::coded(StatusCode::BAD_REQUEST, "CORE.PLATFORM_ARGUMENT_INVALID", message)
        .param("function", function)
        .param("argument", if given.is_empty() { "service".to_string() } else { format!("service ({given})") })
        .param("expected", expected)
}

fn metered_service(args: &Map<Value>) -> Result<Service, CoreError> {
    match service_arg(args).as_str() {
        "security" => Ok(Service::Security),
        "core" => Ok(Service::Core),
        "entity-processor" => Ok(Service::EntityProcessor),
        "files" => Ok(Service::Files),
        other => Err(bad_service(
            &format!("{NAMESPACE}.Meter"),
            other,
            "security, core, entity-processor or files",
            format!("{NAMESPACE}.Meter has no service '{other}'. Expected security, core, entity-processor or files."),
        )),
    }
}

/// `TransportCleanupService.getServiceJobData` and its switch: no default, as guessing would
/// sweep a collection nobody asked about.
fn transport_service(args: &Map<Value>) -> Result<Service, CoreError> {
    match service_arg(args).as_str() {
        "ui" => Ok(Service::Ui),
        "core" => Ok(Service::Core),
        "" => Err(bad_service(
            &format!("{NAMESPACE}.CleanupTransports"),
            "",
            "ui or core",
            format!("{NAMESPACE}.CleanupTransports has no 'service'. Expected 'ui' or 'core'."),
        )),
        other => Err(bad_service(
            &format!("{NAMESPACE}.CleanupTransports"),
            other,
            "ui or core",
            format!("Unknown service in transport cleanup: '{other}'. Expected 'ui' or 'core'."),
        )),
    }
}

/// A failed call as one line: the service's status and message.
fn describe(e: &CoreError) -> String {
    let text = e.text();
    if text.is_empty() {
        e.status().to_string()
    } else {
        format!("{} {text}", e.status().as_u16())
    }
}

/// Some of the independent calls failed: 502, naming them, with what every call answered.
fn partial_failure(job: Job, errors: &[String], result: &Value) -> CoreError {
    CoreError::coded(StatusCode::BAD_GATEWAY, "CORE.PLATFORM_PARTIAL_FAILURE", format!("{}: {} (result: {result})", job.full_name(), errors.join("; ")))
        .param("function", job.full_name())
        .param("errors", errors.join("; "))
}

fn object_or_null(m: Option<serde_json::Map<String, Value>>) -> Value {
    m.map(Value::Object).unwrap_or(Value::Null)
}

async fn run(job: Job, calls: &PlatformCalls, args: &Map<Value>) -> Result<Value, CoreError> {
    match job {
        Job::RenewCertificates => {
            let days = int(args, "daysBeforeExpiry", DEFAULT_DAYS_BEFORE_EXPIRY);
            tracing::info!(days, "renewing SSL certificates");
            let r = object_or_null(calls.renew_certificates(days).await?);
            tracing::info!(renewed = %r["renewedCount"], failed = %r["failedCount"], "SSL renewal complete");
            Ok(r)
        }
        Job::CleanupTokens => {
            let days = int(args, "unusedDays", DEFAULT_UNUSED_DAYS);
            tracing::info!(days, "token cleanup (expired and unused)");
            let r = object_or_null(calls.cleanup_tokens(days).await?);
            tracing::info!(result = %r, "token cleanup complete");
            Ok(r)
        }
        Job::Meter => {
            let service = metered_service(args)?;
            let r = calls.meter(service).await?.map(Value::Bool).unwrap_or(Value::Null);
            tracing::info!(service = service.name(), result = %r, "metering trigger complete");
            Ok(r)
        }
        Job::ReconcileBilling => reconcile_billing(calls).await,
        Job::CleanupExpiredFiles => cleanup_expired_files(calls, int(args, "limit", DEFAULT_FILES_LIMIT)).await,
        Job::CleanupTransports => {
            let service = transport_service(args)?;
            let retention_days = int(args, "retentionDays", DEFAULT_TRANSPORT_RETENTION_DAYS);
            let limit = int(args, "limit", DEFAULT_TRANSPORT_LIMIT);
            tracing::info!(service = service.name(), retention_days, limit, "transport cleanup");
            let r = object_or_null(calls.cleanup_transports(service, retention_days, limit).await?);
            tracing::info!(service = service.name(), result = %r, "transport cleanup complete");
            Ok(r)
        }
        Job::CleanupEventRuns => {
            let retention_days = int(args, "retentionDays", DEFAULT_EVENT_RUN_RETENTION_DAYS);
            let success_days = int(args, "successRetentionDays", DEFAULT_EVENT_RUN_SUCCESS_RETENTION_DAYS);
            let stale_hours = int(args, "staleAfterHours", DEFAULT_EVENT_RUN_STALE_AFTER_HOURS);
            let limit = int(args, "limit", DEFAULT_EVENT_RUN_LIMIT);
            tracing::info!(retention_days, success_days, stale_hours, limit, "event run log cleanup");
            let r = object_or_null(calls.cleanup_event_runs(retention_days, success_days, stale_hours, limit).await?);
            tracing::info!(result = %r, "event run log cleanup complete");
            Ok(r)
        }
    }
}

/// `MeteringExecutionService` BILLING_RECONCILE: the four, in order, each on its own.
async fn reconcile_billing(calls: &PlatformCalls) -> Result<Value, CoreError> {
    let mut result = serde_json::Map::new();
    let mut errors = Vec::new();
    for service in [Service::Security, Service::Core, Service::EntityProcessor, Service::Files] {
        let answer = match calls.reconcile(service).await {
            Ok(b) => b.map(Value::Bool).unwrap_or(Value::Null),
            Err(e) => {
                tracing::error!(service = service.name(), error = %e.text(), "billing reconcile failed");
                errors.push(format!("{}: {}", service.name(), describe(&e)));
                Value::Null
            }
        };
        result.insert(service.name().to_string(), answer);
    }
    let result = Value::Object(result);
    tracing::info!(result = %result, "billing reconcile complete");
    if errors.is_empty() {
        Ok(result)
    } else {
        Err(partial_failure(Job::ReconcileBilling, &errors, &result))
    }
}

/// What one bucket's run did.
#[derive(Default)]
struct Bucket {
    expired_removed: Option<i64>,
    retention_removed: Option<i64>,
    events_raised: i64,
    events_failed: i64,
}

impl Bucket {
    fn to_json(&self) -> Value {
        json!({
            "expiredRemoved": self.expired_removed,
            "retentionRemoved": self.retention_removed,
            "eventsRaised": self.events_raised,
            "eventsFailed": self.events_failed,
        })
    }
}

/// `FilesTtlCleanupService.execute`: both buckets' lifetimes, then both buckets' retention
/// (raising FILES_EXPIRED per group), then the WhatsApp stamping; each step on its own.
async fn cleanup_expired_files(calls: &PlatformCalls, limit: i64) -> Result<Value, CoreError> {
    tracing::info!(limit, "expired-file cleanup");
    let mut buckets: [Bucket; 2] = Default::default();
    // Lines for the output; `failed` marks the ones that fail the run (the files calls).
    let mut errors: Vec<String> = Vec::new();
    let mut failed: Vec<String> = Vec::new();

    for (i, rt) in BUCKETS.iter().enumerate() {
        match calls.cleanup_expired(rt, limit).await {
            Ok(n) => buckets[i].expired_removed = Some(n.unwrap_or(0)),
            Err(e) => {
                tracing::error!(resource_type = rt, error = %e.text(), "expired-file cleanup failed");
                failed.push(format!("{rt} cleanupExpired: {}", describe(&e)));
            }
        }
    }

    for (i, rt) in BUCKETS.iter().enumerate() {
        let groups = match calls.apply_retention(rt, limit).await.and_then(|g| retention_groups(g.unwrap_or_default())) {
            Ok(g) => g,
            Err(e) => {
                tracing::error!(resource_type = rt, error = %e.text(), "retention failed");
                failed.push(format!("{rt} applyRetention: {}", describe(&e)));
                continue;
            }
        };
        let b = &mut buckets[i];
        let mut removed = 0i64;
        for group in groups {
            let Some(paths) = group.get("paths").and_then(Value::as_array).filter(|p| !p.is_empty()) else { continue };
            removed += paths.len() as i64;
            for chunk in paths.chunks(MAX_PATHS_PER_EVENT) {
                match raise_files_expired(calls, &group, rt, chunk).await {
                    Ok(()) => b.events_raised += 1,
                    Err(why) => {
                        b.events_failed += 1;
                        errors.push(why);
                    }
                }
            }
        }
        b.retention_removed = Some(removed);
    }

    // After the deletes, so a message is never marked before its file has gone.
    let stamped = match calls.stamp_expired_whatsapp_media(WHATSAPP_RETENTION_DAYS, WHATSAPP_STAMP_LIMIT).await {
        Ok(n) => json!(n.unwrap_or(0)),
        Err(e) => {
            tracing::error!(error = %e.text(), "marking expired WhatsApp attachments failed");
            errors.push(format!("stampExpired: {}", describe(&e)));
            Value::Null
        }
    };

    let mut all_errors = failed.clone();
    all_errors.extend(errors);
    let result = json!({
        "secured": buckets[0].to_json(),
        "static": buckets[1].to_json(),
        "messagesMarkedExpired": stamped,
        "errors": all_errors,
    });
    tracing::info!(result = %result, "expired-file cleanup complete");
    if failed.is_empty() {
        Ok(result)
    } else {
        Err(partial_failure(Job::CleanupExpiredFiles, &failed, &result))
    }
}

/// `List<FilesRetentionResult>`: null entries are skipped (`group == null`); anything but an
/// object fails the read, as Jackson would.
fn retention_groups(list: Vec<Value>) -> Result<Vec<serde_json::Map<String, Value>>, CoreError> {
    let mut out = Vec::with_capacity(list.len());
    for g in list {
        match g {
            Value::Null => {}
            Value::Object(m) => out.push(m),
            other => {
                return Err(CoreError::unknown(format!(
                    "JSON decoding error: Cannot deserialize value of type `com.modlix.saas.worker.dto.FilesRetentionResult` from {other}"
                )))
            }
        }
    }
    Ok(out)
}

/// `raiseFilesExpired`: one event for one chunk of a group's paths. `Err` says why it was
/// not raised (refused or failed); never fails the run.
async fn raise_files_expired(
    calls: &PlatformCalls,
    group: &serde_json::Map<String, Value>,
    resource_type: &str,
    paths: &[Value],
) -> Result<(), String> {
    // `group.getResourceType() == null ? resourceType.toUpperCase() : group.getResourceType()`.
    let rtype = match group.get("resourceType") {
        None | Some(Value::Null) => Value::String(resource_type.to_uppercase()),
        Some(v) => v.clone(),
    };
    let app = group.get("appCode").cloned().unwrap_or(Value::Null);
    let client = group.get("clientCode").cloned().unwrap_or(Value::Null);
    let request = json!({
        "eventName": FILES_EXPIRED_EVENT,
        "appCode": app,
        "clientCode": client,
        "data": {"resourceType": rtype, "paths": paths},
    });
    let what = format!("{resource_type} {FILES_EXPIRED_EVENT} for app {app} client {client} ({} paths)", paths.len());
    match calls.raise_event(&request).await {
        Ok(Some(true)) => Ok(()),
        Ok(_) => {
            tracing::error!(what, "raising was refused");
            Err(format!("{what}: refused"))
        }
        Err(e) => {
            tracing::error!(what, error = %e.text(), "raising failed");
            Err(format!("{what}: {}", describe(&e)))
        }
    }
}

// ------------------------------------------------------------------ listing

/// Whether `full_name` is one of these functions.
pub fn is_platform_function(full_name: &str) -> bool {
    full_name.strip_prefix(NAMESPACE).is_some_and(|rest| rest.starts_with('.'))
}

/// Core's functions as `repositoryFind` / `repositoryFilter` list them for `app_code`: without
/// `CoreServices.Platform.*` unless the app is `platform`. Execution does not go through this.
pub fn listed(core: Arc<dyn FunctionSource>, app_code: &str) -> Arc<dyn FunctionSource> {
    if app_code == PLATFORM_APP {
        core
    } else {
        Arc::new(WithoutPlatform(core))
    }
}

struct WithoutPlatform(Arc<dyn FunctionSource>);

#[async_trait]
impl FunctionSource for WithoutPlatform {
    async fn find(&self, namespace: Option<&str>, name: &str) -> Result<Option<Arc<dyn Function>>, CoreError> {
        // The repository looks up `namespace + "." + name`, so the check is on that.
        if is_platform_function(&format!("{}.{name}", namespace.unwrap_or("null"))) {
            return Ok(None);
        }
        self.0.find(namespace, name).await
    }

    async fn filter(&self, name: &str) -> Result<Vec<String>, CoreError> {
        Ok(self.0.filter(name).await?.into_iter().filter(|n| !is_platform_function(n)).collect())
    }
}
