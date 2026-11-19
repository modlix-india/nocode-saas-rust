//! The engine's seams over the real stores: runs in Mongo (`automation_run`), automations read
//! through the overridable store, wake-ups as scheduler one-offs, actions as KIRun functions and
//! the built-ins.

use std::sync::Arc;

use async_trait::async_trait;
use axum::http::StatusCode;
use mongodb::bson::{doc, DateTime, Document};
use mongodb::error::{ErrorKind, WriteFailure};
use mongodb::options::IndexOptions;
use mongodb::{Database, IndexModel};
use overridable::backend::Find;
use overridable::{JValue, Store};
use serde_json::{json, Map, Value};

use super::catalog::{POST_WEBHOOK, RAISE_EVENT, SEND_EMAIL, SEND_NOTIFICATION};
use super::engine::{Actions, Automations, Run, RunStatus, RunStore, Timers, WAKE_EVENT};
use crate::docs::{AutomationDoc, AUTOMATION_COLLECTION};
use crate::error::CoreError;
use crate::exec::{self, Arguments};
use crate::scheduler::{OneOffs, ScheduleRequest};
use crate::state::AppState;

pub const RUN_COLLECTION: &str = "automation_run";
/// Events kept for a step that was not waiting yet; they expire after a day.
pub const INBOX_COLLECTION: &str = "automation_inbox";
/// How long a finished run is kept.
pub const RUN_RETENTION_DAYS: i64 = 90;
const DAY_MS: i64 = 86_400_000;

fn mongo_error(e: mongodb::error::Error) -> CoreError {
    CoreError::unknown(e.to_string())
}

fn is_duplicate_key(e: &mongodb::error::Error) -> bool {
    let code = match e.kind.as_ref() {
        ErrorKind::Command(c) => c.code,
        ErrorKind::Write(WriteFailure::WriteError(w)) => w.code,
        _ => 0,
    };
    matches!(code, 11000 | 11001 | 12582)
}

// ---------------------------------------------------------------- runs

/// `automation_run`: one document per run, its id the run's.
pub struct MongoRuns {
    db: Database,
    indexes: tokio::sync::OnceCell<()>,
}

impl MongoRuns {
    pub fn new(db: Database) -> Self {
        Self { db, indexes: tokio::sync::OnceCell::new() }
    }

    fn coll(&self) -> mongodb::Collection<Document> {
        self.db.collection::<Document>(RUN_COLLECTION)
    }

    async fn ensure_indexes(&self) -> Result<(), CoreError> {
        self.indexes
            .get_or_try_init(|| async {
                let model = |keys: Document, name: &str, unique: bool, partial: Option<Document>, expire: bool| {
                    let o = IndexOptions::builder()
                        .name(name.to_string())
                        .unique(unique.then_some(true))
                        .partial_filter_expression(partial)
                        .expire_after(expire.then_some(std::time::Duration::ZERO))
                        .build();
                    IndexModel::builder().keys(keys).options(o).build()
                };
                let once = model(
                    doc! {"appCode": 1, "clientCode": 1, "draft": 1, "onceKey": 1},
                    "automationRunOnce",
                    true,
                    Some(doc! {"onceKey": {"$exists": true}}),
                    false,
                );
                // Claiming a subject depends on this one; the others only keep reads fast.
                self.coll().create_index(once).await.map_err(mongo_error)?;
                for m in [
                    model(doc! {"appCode": 1, "clientCode": 1, "draft": 1, "listen.event": 1, "status": 1}, "automationRunListen", false, None, false),
                    model(doc! {"appCode": 1, "clientCode": 1, "automation": 1, "createdAt": -1}, "automationRunList", false, None, false),
                    model(doc! {"appCode": 1, "clientCode": 1, "subject": 1, "createdAt": -1}, "automationRunSubject", false, None, false),
                    model(doc! {"expireAt": 1}, "automationRunExpiry", false, None, true),
                ] {
                    if let Err(e) = self.coll().create_index(m).await {
                        tracing::warn!("Automation run index not created: {e}");
                    }
                }
                let inbox = self.db.collection::<Document>(INBOX_COLLECTION);
                for m in [
                    model(doc! {"runId": 1, "node": 1, "at": 1}, "automationInboxStep", false, None, false),
                    IndexModel::builder()
                        .keys(doc! {"keptAt": 1})
                        .options(IndexOptions::builder().name("automationInboxExpiry".to_string()).expire_after(std::time::Duration::from_secs(86_400)).build())
                        .build(),
                ] {
                    if let Err(e) = inbox.create_index(m).await {
                        tracing::warn!("Automation inbox index not created: {e}");
                    }
                }
                Ok::<(), CoreError>(())
            })
            .await
            .map(|_| ())
    }

    fn to_doc(run: &Run) -> Result<Document, CoreError> {
        let mut d = mongodb::bson::to_document(run).map_err(|e| CoreError::unknown(format!("Could not store the run: {e}")))?;
        d.insert("_id", run.id.clone());
        if let Some(f) = run.finished_at {
            d.insert("expireAt", DateTime::from_millis(f + RUN_RETENTION_DAYS * DAY_MS));
        }
        Ok(d)
    }

    pub fn from_doc(mut d: Document) -> Result<Run, CoreError> {
        d.remove("_id");
        d.remove("expireAt");
        mongodb::bson::from_document(d).map_err(|e| CoreError::unknown(format!("Could not read a run: {e}")))
    }

    /// The client's runs, newest first: of one automation, of one subject, or both.
    pub async fn list(
        &self,
        app: &str,
        client: &str,
        automation: Option<&str>,
        subject: Option<&str>,
        status: Option<&str>,
        page: u64,
        size: i64,
    ) -> Result<(Vec<Run>, u64), CoreError> {
        self.ensure_indexes().await?;
        let mut filter = doc! {"appCode": app, "clientCode": client};
        if let Some(a) = automation {
            filter.insert("automation", a);
        }
        if let Some(s) = subject {
            filter.insert("subject", s);
        }
        if let Some(s) = status {
            filter.insert("status", s);
        }
        let total = self.coll().count_documents(filter.clone()).await.map_err(mongo_error)?;
        let mut cursor = self
            .coll()
            .find(filter)
            .sort(doc! {"createdAt": -1})
            .skip(page * size.max(1) as u64)
            .limit(size.max(1))
            .await
            .map_err(mongo_error)?;
        let mut out = Vec::new();
        while cursor.advance().await.map_err(mongo_error)? {
            let d = cursor.deserialize_current().map_err(mongo_error)?;
            out.push(Self::from_doc(d)?);
        }
        Ok((out, total))
    }
}

#[async_trait]
impl RunStore for MongoRuns {
    async fn insert(&self, run: &Run) -> Result<bool, CoreError> {
        self.ensure_indexes().await?;
        match self.coll().insert_one(Self::to_doc(run)?).await {
            Ok(_) => Ok(true),
            Err(e) if is_duplicate_key(&e) => Ok(false),
            Err(e) => Err(mongo_error(e)),
        }
    }

    async fn get(&self, id: &str) -> Result<Option<Run>, CoreError> {
        let d = self.coll().find_one(doc! {"_id": id}).await.map_err(mongo_error)?;
        d.map(Self::from_doc).transpose()
    }

    async fn save(&self, run: &Run, expected: i64) -> Result<bool, CoreError> {
        let r = self.coll().replace_one(doc! {"_id": &run.id, "version": expected}, Self::to_doc(run)?).await.map_err(mongo_error)?;
        Ok(r.matched_count == 1)
    }

    async fn listening(&self, app: &str, client: &str, draft: bool, event: &str) -> Result<Vec<Run>, CoreError> {
        self.ensure_indexes().await?;
        let filter = doc! {
            "appCode": app, "clientCode": client, "draft": draft, "listen.event": event,
            "status": {"$in": ["RUNNING", "WAITING"]},
        };
        let mut cursor = self.coll().find(filter).await.map_err(mongo_error)?;
        let mut out = Vec::new();
        while cursor.advance().await.map_err(mongo_error)? {
            let d = cursor.deserialize_current().map_err(mongo_error)?;
            match Self::from_doc(d) {
                Ok(r) => out.push(r),
                Err(e) => tracing::warn!("{}", e.text()),
            }
        }
        Ok(out)
    }

    async fn inbox_put(&self, run_id: &str, node: &str, event: &str, data: &Value) -> Result<(), CoreError> {
        self.ensure_indexes().await?;
        let data = mongodb::bson::to_bson(data).map_err(|e| CoreError::unknown(e.to_string()))?;
        let now = chrono::Utc::now().timestamp_millis();
        let d = doc! {"runId": run_id, "node": node, "event": event, "data": data, "at": now, "keptAt": DateTime::from_millis(now)};
        self.db.collection::<Document>(INBOX_COLLECTION).insert_one(d).await.map_err(mongo_error)?;
        Ok(())
    }

    async fn inbox_take(&self, run_id: &str, node: &str) -> Result<Vec<Value>, CoreError> {
        let coll = self.db.collection::<Document>(INBOX_COLLECTION);
        let mut cursor = coll.find(doc! {"runId": run_id, "node": node}).sort(doc! {"at": 1, "_id": 1}).await.map_err(mongo_error)?;
        let (mut ids, mut out) = (Vec::new(), Vec::new());
        while cursor.advance().await.map_err(mongo_error)? {
            let d = cursor.deserialize_current().map_err(mongo_error)?;
            if let Some(id) = d.get("_id") {
                ids.push(id.clone());
            }
            if let Some(b) = d.get("data") {
                out.push(serde_json::to_value(b.clone().into_relaxed_extjson()).unwrap_or(Value::Null));
            }
        }
        if !ids.is_empty() {
            coll.delete_many(doc! {"_id": {"$in": ids}}).await.map_err(mongo_error)?;
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------- automations

/// The automations of a client that start on an event, read through the overridable store so
/// the client's own copy, the draft surface and publishing all apply as for any definition.
/// Only automations the client owns start: an inherited one (the app owner's) never does.
///
/// Every event asks this, so the names come from one indexed query on `automation`
/// (`appCode`, `trigger.key`), and each name is then read through the store's cache.
pub struct StoreAutomations {
    store: Store,
    db: Option<Database>,
    index: tokio::sync::OnceCell<()>,
}

impl StoreAutomations {
    pub fn new(store: Store, db: Option<Database>) -> Self {
        Self { store, db, index: tokio::sync::OnceCell::new() }
    }

    async fn ensure_index(&self) {
        let Some(db) = &self.db else { return };
        self.index
            .get_or_init(|| async {
                let o = IndexOptions::builder().name("automationTrigger".to_string()).build();
                let m = IndexModel::builder().keys(doc! {"appCode": 1, "trigger.key": 1}).options(o).build();
                if let Err(e) = db.collection::<Document>(AUTOMATION_COLLECTION).create_index(m).await {
                    tracing::warn!("Automation trigger index not created: {e}");
                }
            })
            .await;
    }
}

#[async_trait]
impl Automations for StoreAutomations {
    async fn triggered_by(&self, app: &str, client: &str, draft: bool, event: &str) -> Result<Vec<Value>, CoreError> {
        self.ensure_index().await;
        let rows = self
            .store
            .backend()
            .find(AUTOMATION_COLLECTION, Find::new(doc! {"appCode": app, "trigger.key": event}))
            .await
            .map_err(|e| CoreError::unknown(e.to_string()))?;
        let names: std::collections::BTreeSet<String> = rows.iter().filter_map(|d| d.get_str("name").ok().map(str::to_string)).collect();
        let mut out = Vec::new();
        for name in names {
            let Some(r) = self.store.read(&AutomationDoc, &name, app, client, client, draft).await? else { continue };
            let a = serde_json::to_value(JValue::Object(r.entity.clone())).unwrap_or(Value::Null);
            let starts_here = a.get("trigger").and_then(|t| t.get("key")).and_then(Value::as_str) == Some(event);
            let paused = a.get("paused").and_then(Value::as_bool).unwrap_or(false);
            let template = a.get("isTemplate").and_then(Value::as_bool).unwrap_or(false);
            // Only the client's own automations act on its events. One the client merely
            // inherits (the app owner's, say) would otherwise run on every tenant's data.
            let own = a.get("clientCode").and_then(Value::as_str) == Some(client);
            if starts_here && !paused && !template && own {
                out.push(a);
            }
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------- wake-ups

/// Wake-ups as one-off scheduled events ([`WAKE_EVENT`]), kept by the run's app, client and
/// surface, so the scheduler retries, leases and cancels them as any one-off.
pub struct OneOffTimers(pub Arc<dyn OneOffs>);

#[async_trait]
impl Timers for OneOffTimers {
    async fn set(&self, run: &Run, key: &str, at: i64, data: Map<String, Value>) -> Result<(), CoreError> {
        let data = mongodb::bson::to_document(&data).map_err(|e| CoreError::unknown(e.to_string()))?;
        self.0
            .schedule(ScheduleRequest {
                app_code: run.app_code.clone(),
                client_code: run.client_code.clone(),
                draft: run.draft,
                event_name: WAKE_EVENT.into(),
                data,
                run_at: Some(at),
                key: key.into(),
                scheduled_by: Some(format!("automation:{}", run.automation)),
            })
            .await?;
        Ok(())
    }

    async fn cancel(&self, run: &Run, key: &str) -> Result<(), CoreError> {
        self.0.cancel(&run.app_code, &run.client_code, run.draft, key).await.map(|_| ())
    }
}

// ---------------------------------------------------------------- actions

/// Actions in the running app: a server function by `namespace.name`, or a built-in.
pub struct CoreActions {
    pub state: AppState,
}

fn param_text(p: &Map<String, Value>, k: &str) -> Option<String> {
    p.get(k).map(super::expr::text_of).map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn refused(what: &str) -> CoreError {
    CoreError::unknown(what.to_string())
}

/// An answer that will not change on asking again (422): the step fails without retries.
fn final_refusal(what: &str) -> CoreError {
    CoreError::new(StatusCode::UNPROCESSABLE_ENTITY, what.to_string())
}

/// What a function's `error` event says: its `message`, `reason`, `error` or `code`, else the
/// values as JSON.
fn error_text(e: &Value) -> String {
    for k in ["message", "reason", "error", "code", "status"] {
        if let Some(t) = e.get(k).map(super::expr::text_of).filter(|t| !t.trim().is_empty()) {
            return t;
        }
    }
    let all = e.to_string();
    if all == "{}" { "The action refused the step.".to_string() } else { format!("The action refused the step: {all}") }
}

/// The addresses in `to`: a list, or text separated by commas or semicolons.
fn addresses(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Array(a)) => a.iter().map(super::expr::text_of).collect(),
        Some(other) => super::expr::text_of(other).split([',', ';']).map(str::to_string).collect(),
        None => vec![],
    }
    .into_iter()
    .map(|s| s.trim().to_string())
    .filter(|s| !s.is_empty())
    .collect()
}

impl CoreActions {
    /// A server function, its params as its arguments. It also gets `automation`
    /// (`{ runId, step, test, name }`): KIRun drops an argument a function does not declare, and
    /// one that does can use `runId` and `step` as a key, so a retried step does nothing twice.
    async fn function(&self, key: &str, node: &str, params: Map<String, Value>, run: &Run) -> Result<Value, CoreError> {
        let Some((namespace, name)) = key.rsplit_once('.') else {
            return Err(refused(&format!("\"{key}\" is not an action this app has.")));
        };
        let mut args = kirun::Map::new();
        for (k, v) in params {
            args.insert(k, v);
        }
        args.entry("automation".to_string())
            .or_insert_with(|| json!({ "runId": run.id, "step": node, "test": run.test, "testUser": run.test_user, "name": run.automation }));
        let out = exec::run(&self.state, Some(namespace), name, &run.app_code, &run.client_code, Arguments::Body(args)).await?;
        let Some(mut out) = out else {
            return Err(CoreError::msg_as(
                StatusCode::NOT_FOUND,
                crate::error::messages::OBJECT_NOT_FOUND,
                "CORE.FUNCTION_NOT_FOUND",
                &["Function", key],
            ));
        };
        // The `output` event's values. A function that answered only with its `error` event
        // refused the step: that fails it (without retries, see the engine's `act`). Else the
        // first event's values.
        let (mut first, mut error): (Option<Value>, Option<Value>) = (None, None);
        while let Some(er) = out.next() {
            let v = Value::Object(er.get_result().iter().map(|(k, v)| (k.clone(), v.clone())).collect());
            match er.get_name() {
                "output" => return Ok(v),
                "error" => {
                    error.get_or_insert(v);
                }
                _ => {
                    first.get_or_insert(v);
                }
            }
        }
        if let Some(e) = error {
            // A 5xx `status` (a provider that did not answer) may work later and is retried;
            // any other answer is final.
            let transient = e.get("status").and_then(|s| s.as_u64().or_else(|| s.as_str().and_then(|t| t.trim().parse().ok()))).is_some_and(|s| s >= 500);
            let status = if transient { StatusCode::BAD_GATEWAY } else { StatusCode::UNPROCESSABLE_ENTITY };
            return Err(CoreError::new(status, error_text(&e)));
        }
        Ok(first.unwrap_or_else(|| json!({})))
    }

    async fn send_email(&self, params: Map<String, Value>, run: &Run) -> Result<Value, CoreError> {
        let to = addresses(params.get("to"));
        let Some(template) = param_text(&params, "template") else { return Err(refused("Choose the email to send.")) };
        if to.is_empty() {
            return Err(refused("Say who the email goes to."));
        }
        let mut data = match params.get("data") {
            Some(Value::Object(d)) => d.clone(),
            _ => Map::new(),
        };
        for k in ["trigger", "steps"] {
            if let Some(v) = run.context.get(k) {
                data.entry(k.to_string()).or_insert_with(|| v.clone());
            }
        }
        let i = &self.state.inner().integrations;
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
            Some(&run.app_code),
            Some(&run.client_code),
            &to,
            &template,
            param_text(&params, "connectionName").as_deref(),
            &data,
        )
        .await
        .map_err(crate::integrations::core_error)?;
        match sent {
            Some(true) => Ok(json!({ "sent": true })),
            _ => Err(refused("The email was not sent: check that the email and its sender exist in this app.")),
        }
    }

    async fn post_webhook(&self, params: Map<String, Value>) -> Result<Value, CoreError> {
        let Some(url) = param_text(&params, "url") else { return Err(refused("Give the webhook's address.")) };
        if !(url.starts_with("https://") || url.starts_with("http://")) {
            return Err(refused("The webhook's address has to start with https://."));
        }
        let i = &self.state.inner().integrations;
        let client = connections::rest::http::HttpClient { block_private_targets: i.connections.config.block_private_targets };
        let body = serde_json::to_vec(params.get("body").unwrap_or(&json!({}))).unwrap_or_default();
        let req = connections::rest::http::OutboundRequest {
            method: "POST".into(),
            uri: url,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: Some(body),
        };
        let resp = client.send(req).await.map_err(crate::integrations::core_error)?;
        let status = resp.status;
        let bytes = resp.read_body(256 * 1024).await.map_err(crate::integrations::core_error)?;
        let answer = serde_json::from_slice::<Value>(&bytes).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        if !(200..300).contains(&status) {
            return Err(refused(&format!("The webhook answered {status}.")));
        }
        Ok(json!({ "status": status, "body": answer }))
    }

    /// One of the app's notifications, through the notification service as `SendNotification`
    /// sends it: its channels, templates and each person's preferences apply. The run's client
    /// sends it, so it reaches only that client's people (the service's hierarchy check). A
    /// test run sends it to the person testing, and to nobody else.
    async fn send_notification(&self, params: Map<String, Value>, run: &Run) -> Result<Value, CoreError> {
        use connections::notification::{NotificationRequest, CLIENT_CODE, USER_ID};
        let Some(name) = param_text(&params, "notification") else { return Err(final_refusal("Choose the notification to send.")) };
        let mut everyone = params.get("everyone").is_some_and(|v| v.as_bool() == Some(true) || super::expr::text_of(v) == "true");
        let mut users: Vec<i128> = Vec::new();
        for who in addresses(params.get("to")) {
            match who.parse::<i128>() {
                Ok(id) if id > 0 => users.push(id),
                _ => return Err(final_refusal(&format!("\"{who}\" is not a person (a user id).") )),
            }
        }
        users.sort_unstable();
        users.dedup();
        if run.test {
            let Some(me) = run.test_user else {
                return Ok(json!({ "sent": false, "count": 0, "test": "A test run sends a notification only to the person testing it." }));
            };
            (users, everyone) = (vec![me as i128], false);
        }
        if users.is_empty() && !everyone {
            return Err(final_refusal("Say who gets the notification."));
        }
        let mut payload = match params.get("data") {
            Some(Value::Object(d)) => d.clone(),
            _ => Map::new(),
        };
        for k in ["trigger", "steps"] {
            if let Some(v) = run.context.get(k) {
                payload.entry(k.to_string()).or_insert_with(|| v.clone());
            }
        }
        let request = |target_type: &str, target_id: Option<i128>, target_code: Option<String>, filter: Option<String>| NotificationRequest {
            app_code: Some(run.app_code.clone()),
            client_code: Some(run.client_code.clone()),
            connection_name: Some(String::new()),
            target_id,
            target_code,
            target_type: target_type.to_string(),
            filter_authorization: filter,
            notification_name: Some(name.clone()),
            notification_category: Some(String::new()),
            payload: Some(payload.clone()),
        };
        let i = &self.state.inner().integrations;
        let caller = crate::integrations::caller();
        let mut count = 0;
        if everyone {
            let filter = param_text(&params, "onlyWith");
            let req = request(CLIENT_CODE, Some(0), Some(run.client_code.clone()), filter);
            if i.mq.send_notification(i.checks.as_ref(), &caller, req).await? != Some(true) {
                return Err(final_refusal("The notification could not be sent to the business."));
            }
            count += 1;
        }
        for id in users {
            let req = request(USER_ID, Some(id), None, None);
            if i.mq.send_notification(i.checks.as_ref(), &caller, req).await? != Some(true) {
                if run.test {
                    return Ok(json!({ "sent": false, "count": 0, "test": "You are not a person in this business, so the test notification was not sent." }));
                }
                return Err(final_refusal(&format!("User {id} is not a person in this business, so the notification was not sent to them.")));
            }
            count += 1;
        }
        Ok(json!({ "sent": true, "count": count }))
    }

    async fn raise_event(&self, params: Map<String, Value>, run: &Run) -> Result<Value, CoreError> {
        let Some(event) = param_text(&params, "eventName") else { return Err(refused("Choose the event to raise.")) };
        if event == WAKE_EVENT {
            return Err(refused("That event cannot be raised."));
        }
        let data = match params.get("data") {
            Some(Value::Object(d)) => Some(d.clone()),
            _ => Some(Map::new()),
        };
        let qob = connections::mq::EventMessage {
            event_name: Some(event),
            app_code: Some(run.app_code.clone()),
            client_code: Some(run.client_code.clone()),
            draft: run.draft,
            data,
            ..Default::default()
        };
        let raised = self.state.inner().integrations.mq.create_event(&crate::integrations::caller(), qob).await?;
        Ok(json!({ "raised": raised }))
    }
}

#[async_trait]
impl Actions for CoreActions {
    async fn run(&self, action: &str, node: &str, params: Map<String, Value>, run: &Run) -> Result<Value, CoreError> {
        match action {
            SEND_EMAIL => self.send_email(params, run).await,
            POST_WEBHOOK => self.post_webhook(params).await,
            RAISE_EVENT => self.raise_event(params, run).await,
            SEND_NOTIFICATION => self.send_notification(params, run).await,
            "" => Err(refused("The step does not say what to do.")),
            a if a.starts_with(super::catalog::BUILT_IN_PREFIX) => Err(refused(&format!("\"{a}\" is not an action the engine has."))),
            a => self.function(a, node, params, run).await,
        }
    }
}

/// The run as the routes answer it.
pub fn run_json(run: &Run) -> Value {
    serde_json::to_value(run).unwrap_or(Value::Null)
}

/// Whether a run may still be stopped by hand.
pub fn cancellable(run: &Run) -> bool {
    matches!(run.status, RunStatus::Running | RunStatus::Waiting)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::automation::engine::Run;

    #[test]
    fn a_run_survives_the_trip_through_bson() {
        let mut run = Run {
            id: "r1".into(),
            app_code: "leadzumptwo".into(),
            client_code: "FIN".into(),
            automation: "followUp".into(),
            flow: json!({"start": "a", "nodes": {"a": {"type": "END"}}}),
            context: json!({"trigger": {"dealId": 42, "amount": 1.5, "tags": ["x"]}, "steps": {}}),
            version: 3,
            created_at: 1,
            updated_at: 2,
            ..Default::default()
        };
        run.waits.insert(
            "hold".into(),
            crate::automation::engine::Wait { kind: crate::automation::engine::WaitKind::Event, until: Some(10), timer: Some("t".into()), attempt: 0 },
        );
        let d = MongoRuns::to_doc(&run).unwrap();
        assert_eq!(d.get_str("_id").unwrap(), "r1");
        assert_eq!(d.get_i64("version").unwrap(), 3);
        assert_eq!(d.get_str("status").unwrap(), "RUNNING");
        assert!(d.get("expireAt").is_none(), "an unfinished run never expires");
        assert_eq!(MongoRuns::from_doc(d).unwrap(), run);

        run.finished_at = Some(1_000);
        run.status = RunStatus::Done;
        let d = MongoRuns::to_doc(&run).unwrap();
        assert_eq!(d.get_datetime("expireAt").unwrap().timestamp_millis(), 1_000 + RUN_RETENTION_DAYS * DAY_MS);
        assert_eq!(MongoRuns::from_doc(d).unwrap(), run);
    }

    #[test]
    fn addresses_from_a_list_or_text() {
        assert_eq!(addresses(Some(&json!("a@x.com; b@y.com,  "))), vec!["a@x.com", "b@y.com"]);
        assert_eq!(addresses(Some(&json!(["a@x.com", ""]))), vec!["a@x.com"]);
        assert!(addresses(None).is_empty());
    }
}
