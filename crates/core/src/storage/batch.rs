//! Rust only: several storage writes as one unit (`CoreServices.Storage.Batch`), a
//! compare-and-set update (`UpdateIf`) and named counters (`NextSequence`).
//!
//! A batch runs every write through the same policy layer as the single-row functions
//! (gates, validation, relations, triggers, version rows). On MySQL the whole run is one
//! transaction (`appdata::mysql::tx`): committed when every operation succeeds, rolled back
//! when one fails. An engine without transactions (a standalone Mongo) keeps an undo journal
//! instead: each write remembers how to reverse itself, the journal is replayed backwards on a
//! failure, and the result says `atomic: false`. Storage events raised inside a batch are sent
//! only after it succeeds.
//!
//! `onConflict` says what a conflict does: a unique index refusing a write
//! (`CORE.DUPLICATE_KEY`) or an `updateIf` whose `expected` no longer matches
//! (`CORE.STORAGE_CONDITION_FAILED`). `throw` (the default) fails the batch as any other
//! failure does. `report` rolls the batch back just the same and answers normally with
//! `committed: false` and the `conflict`, so a function can try the next seat or tell the user
//! politely. That is the "claim key" pattern: a nullable column under a unique index, written in
//! the same batch as the main write, is how an app holds something only one row may hold.

use std::sync::{Arc, Mutex};

use appdata::model::DataObject;
use appdata::mysql::tx;
use appdata::value::{Document, Value};
use axum::http::StatusCode;

use super::{ctx, has_authority, AppDataService, Backend, Gate};
use crate::error::{CoreError, CoreResult};

/// One event `generate_event` held back while a batch was running.
pub(super) struct DeferredEvent {
    pub app: String,
    pub client: String,
    pub name: String,
    pub event: Document,
}

tokio::task_local! {
    /// The events raised inside the running batch, sent once it succeeds.
    pub(super) static DEFERRED_EVENTS: Arc<Mutex<Vec<DeferredEvent>>>;
}

/// Holds the event back when a batch is running; gives it back otherwise.
pub(super) fn defer(app: &str, client: &str, name: &str, event: Document) -> Option<Document> {
    let pending = DeferredEvent { app: app.into(), client: client.into(), name: name.into(), event };
    let mut slot = Some(pending);
    let held = DEFERRED_EVENTS
        .try_with(|q| {
            if let Ok(mut q) = q.lock() {
                q.push(slot.take().expect("taken once"));
                true
            } else {
                false
            }
        })
        .unwrap_or(false);
    if held {
        None
    } else {
        slot.map(|e| e.event)
    }
}

/// What one operation of a batch asks for.
#[derive(Debug, Clone)]
pub enum BatchOp {
    Create { storage: String, data: Document },
    Update { storage: String, id: String, data: Document, partial: bool },
    UpdateIf { storage: String, id: String, expected: Document, data: Document, partial: bool },
    Delete { storage: String, id: String },
    NextSequence { storage: String, key: String, start: i64 },
}

/// One operation and the name later operations refer to its result by.
#[derive(Debug, Clone)]
pub struct NamedOp {
    pub op: BatchOp,
    pub name: Option<String>,
}

/// What a batch does when one of its operations meets a conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OnConflict {
    /// The batch fails with the conflict's error and leaves nothing written (as before
    /// `onConflict` existed).
    #[default]
    Throw,
    /// The batch is rolled back and answers normally: `committed: false` and the conflict.
    Report,
}

impl OnConflict {
    /// `onConflict`: `throw` or `report`, any case; absent, null or blank is `throw`.
    pub fn parse(v: Option<&str>) -> Option<OnConflict> {
        match v.map(str::trim).unwrap_or("") {
            "" => Some(OnConflict::Throw),
            t if t.eq_ignore_ascii_case("throw") => Some(OnConflict::Throw),
            t if t.eq_ignore_ascii_case("report") => Some(OnConflict::Report),
            _ => None,
        }
    }
}

/// Which kind of conflict stopped a batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictKind {
    /// A unique index already holds the value (`CORE.DUPLICATE_KEY`).
    Duplicate,
    /// An `updateIf` found the row changed (`CORE.STORAGE_CONDITION_FAILED`).
    Stale,
}

impl ConflictKind {
    pub fn name(self) -> &'static str {
        match self {
            ConflictKind::Duplicate => "DUPLICATE",
            ConflictKind::Stale => "STALE",
        }
    }
}

/// The operation a reported conflict stopped, and why.
#[derive(Debug, Clone, PartialEq)]
pub struct BatchConflict {
    /// The operation's place in `operations`.
    pub index: usize,
    /// Its `as` name, when it has one.
    pub name: Option<String>,
    /// Its `op`: create, update, updateIf, delete or nextSequence.
    pub op: &'static str,
    pub storage: String,
    pub kind: ConflictKind,
    /// The unique index that refused the write (none for a stale row).
    pub key: Option<String>,
    /// The conflict in plain words.
    pub message: String,
}

/// What a batch answers with.
#[derive(Debug, Clone)]
pub struct BatchOutcome {
    /// One entry per operation: the written row, `{"deleted": bool}`, or `{"value": n}`.
    /// Empty when a reported conflict rolled the batch back.
    pub results: Vec<Value>,
    /// Whether the run was one transaction (false: undone by the journal on failure).
    pub atomic: bool,
    /// Whether the writes were kept: false only for a reported conflict.
    pub committed: bool,
    /// The conflict that rolled the batch back (`onConflict: report`).
    pub conflict: Option<BatchConflict>,
}

/// What a compare-and-set answers with.
#[derive(Debug, Clone)]
pub struct UpdateIfOutcome {
    pub updated: bool,
    /// The row after the update, or the row as it stands when the comparison failed.
    pub row: Document,
}

/// How to reverse one write on an engine without transactions.
enum Undo {
    Delete { backend: Backend, client: String, storage: appdata::model::Storage, id: String },
    Restore { backend: Backend, client: String, storage: appdata::model::Storage, before: Document },
    Recreate { backend: Backend, client: String, storage: appdata::model::Storage, before: Document },
}

/// A failed batch: which operation and why.
fn failed_at(index: usize, e: CoreError) -> CoreError {
    e.param("failedIndex", index)
}

/// The conflict an operation's error stands for, when it is one: a duplicate key or a stale
/// `updateIf`. Any other failure is not a conflict and always fails the batch.
pub fn conflict_of(e: &CoreError) -> Option<(ConflictKind, Option<String>, String)> {
    let c = e.code()?;
    let value = |name: &str| c.params.iter().find(|(n, _)| n == name).map(|(_, v)| v.clone()).filter(|v| !v.is_empty());
    if c.code == appdata::error::DUPLICATE_KEY {
        Some((ConflictKind::Duplicate, value("index"), c.english().message))
    } else if c.code == "CORE.STORAGE_CONDITION_FAILED" {
        Some((ConflictKind::Stale, None, e.text()))
    } else {
        None
    }
}

fn op_label(op: &BatchOp) -> &'static str {
    match op {
        BatchOp::Create { .. } => "create",
        BatchOp::Update { .. } => "update",
        BatchOp::UpdateIf { .. } => "updateIf",
        BatchOp::Delete { .. } => "delete",
        BatchOp::NextSequence { .. } => "nextSequence",
    }
}

fn op_storage(op: &BatchOp) -> &str {
    match op {
        BatchOp::Create { storage, .. }
        | BatchOp::Update { storage, .. }
        | BatchOp::UpdateIf { storage, .. }
        | BatchOp::Delete { storage, .. }
        | BatchOp::NextSequence { storage, .. } => storage,
    }
}

fn condition_failed(storage: &str, id: &str) -> CoreError {
    CoreError::new(StatusCode::CONFLICT, format!("The row {id} of {storage} no longer matches what was expected."))
        .with_code("CORE.STORAGE_CONDITION_FAILED")
        .param("storage", storage)
        .param("id", id)
}

/// Whether the stored value is the one the caller expects: numbers by value (`1` = `1.0`),
/// MySQL's 0/1 as booleans, missing = null, everything else by its JSON form.
pub fn same_value(expected: &Value, actual: Option<&Value>) -> bool {
    let actual = actual.unwrap_or(&Value::Null);
    let number = |v: &Value| match v {
        Value::Int(i) => Some(*i as f64),
        Value::Double(d) => Some(*d),
        Value::Decimal(d) => Some(d.double_value()),
        _ => None,
    };
    match (expected, actual) {
        (Value::Null, a) => a.is_null(),
        (Value::Bool(b), Value::Bool(a)) => a == b,
        (Value::Bool(b), a) => number(a).is_some_and(|n| (n != 0.0) == *b),
        (e, Value::Bool(a)) => number(e).is_some_and(|n| (n != 0.0) == *a),
        (e, a) if number(e).is_some() && number(a).is_some() => number(e) == number(a),
        (Value::String(e), a) => !a.is_null() && *e == a.java_string(),
        (e, a) => crate::storage::values::gson_tree(e).ok() == crate::storage::values::gson_tree(a).ok(),
    }
}

/// Every expected field matches the row.
pub fn matches(expected: &Document, row: &Document) -> bool {
    expected.iter().all(|(k, v)| same_value(v, row.get(k)))
}

/// `{"$ref": "name.path.to.field"}` anywhere in an operation's data, replaced by that part of
/// an earlier operation's result.
fn resolve_refs(v: &Value, named: &[(String, Value)]) -> CoreResult<Value> {
    match v {
        Value::Object(o) if o.len() == 1 && o.contains_key("$ref") => {
            let path = o.get("$ref").map(Value::java_string).unwrap_or_default();
            let mut parts = path.split('.');
            let head = parts.next().unwrap_or_default();
            let Some((_, mut cur)) = named.iter().find(|(n, _)| n == head).map(|(n, v)| (n, v.clone())) else {
                return Err(CoreError::new(StatusCode::BAD_REQUEST, format!("{path}: no earlier operation is named {head}"))
                    .with_code("CORE.STORAGE_BATCH_REF"));
            };
            for p in parts {
                cur = match cur {
                    Value::Object(m) => m.get(p).cloned().unwrap_or(Value::Null),
                    Value::Array(a) => p.parse::<usize>().ok().and_then(|i| a.get(i).cloned()).unwrap_or(Value::Null),
                    _ => Value::Null,
                };
            }
            Ok(cur)
        }
        Value::Object(o) => {
            let mut out = Document::new();
            for (k, v) in o {
                out.insert(k.clone(), resolve_refs(v, named)?);
            }
            Ok(Value::Object(out))
        }
        Value::Array(a) => Ok(Value::Array(a.iter().map(|v| resolve_refs(v, named)).collect::<CoreResult<_>>()?)),
        other => Ok(other.clone()),
    }
}

fn resolve_doc(d: &Document, named: &[(String, Value)]) -> CoreResult<Document> {
    match resolve_refs(&Value::Object(d.clone()), named)? {
        Value::Object(o) => Ok(o),
        _ => Ok(Document::new()),
    }
}

fn resolve_text(s: &str, named: &[(String, Value)]) -> CoreResult<String> {
    // A whole-string reference written as `$ref:name.path`.
    match s.strip_prefix("$ref:") {
        Some(path) => {
            let mut o = Document::new();
            o.insert("$ref".into(), Value::String(path.to_string()));
            Ok(resolve_refs(&Value::Object(o), named)?.java_string())
        }
        None => Ok(s.to_string()),
    }
}

impl AppDataService {
    /// `CoreServices.Storage.Batch`. With [`OnConflict::Report`], a conflict rolls the batch back
    /// and answers `committed: false` with the conflict; a batch running inside another
    /// transaction (a trigger's batch inside a batch) cannot roll back only its own part, so
    /// there a conflict still fails it and the outer unit decides.
    pub async fn batch(
        &self,
        app_code: Option<&str>,
        client_code: Option<&str>,
        ops: Vec<NamedOp>,
        on_conflict: OnConflict,
    ) -> CoreResult<BatchOutcome> {
        if ops.is_empty() {
            return Ok(BatchOutcome { results: Vec::new(), atomic: true, committed: true, conflict: None });
        }
        self.prepare_batch(app_code, client_code, &ops).await?;
        let report = on_conflict == OnConflict::Report && !tx::active();
        let labels: Vec<(&'static str, String, Option<String>)> =
            ops.iter().map(|o| (op_label(&o.op), op_storage(&o.op).to_string(), o.name.clone())).collect();
        let failed: Mutex<Option<usize>> = Mutex::new(None);
        let journal: Mutex<Vec<Undo>> = Mutex::new(Vec::new());
        let atomic = Mutex::new(true);
        let events: Arc<Mutex<Vec<DeferredEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let run = async {
            let mut named: Vec<(String, Value)> = Vec::new();
            let mut results = Vec::with_capacity(ops.len());
            for (i, op) in ops.into_iter().enumerate() {
                let result = self.batch_op(app_code, client_code, op.op, &named, &journal, &atomic).await.map_err(|e| {
                    if let Ok(mut f) = failed.lock() {
                        *f = Some(i);
                    }
                    failed_at(i, e)
                })?;
                if let Some(n) = op.name {
                    named.push((n, result.clone()));
                }
                results.push(result);
            }
            Ok::<_, CoreError>(results)
        };
        let outcome = DEFERRED_EVENTS.scope(events.clone(), tx::scope(run)).await;
        let atomic = atomic.lock().map(|a| *a).unwrap_or(false);
        match outcome {
            Ok(results) => {
                let pending = std::mem::take(&mut *events.lock().map_err(|_| CoreError::unknown("batch events poisoned"))?);
                for e in pending {
                    self.events.create_event(&e.app, &e.client, &e.name, e.event).await?;
                }
                Ok(BatchOutcome { results, atomic, committed: true, conflict: None })
            }
            Err(e) => {
                let undo = std::mem::take(&mut *journal.lock().map_err(|_| CoreError::unknown("batch journal poisoned"))?);
                for u in undo.into_iter().rev() {
                    self.undo(u).await;
                }
                let at = failed.lock().ok().and_then(|f| *f);
                match (report, at, conflict_of(&e)) {
                    (true, Some(index), Some((kind, key, message))) => {
                        let (op, storage, name) = labels[index].clone();
                        let conflict = BatchConflict { index, name, op, storage, kind, key, message };
                        Ok(BatchOutcome { results: Vec::new(), atomic, committed: false, conflict: Some(conflict) })
                    }
                    _ => Err(e),
                }
            }
        }
    }

    /// Creates every table the batch will touch (its storages and their relation targets) before
    /// the transaction opens: DDL inside an open MySQL transaction fails it (error 1412).
    async fn prepare_batch(&self, app_code: Option<&str>, client_code: Option<&str>, ops: &[NamedOp]) -> CoreResult<()> {
        let mut names: Vec<String> = Vec::new();
        for op in ops {
            let name = match &op.op {
                BatchOp::Create { storage, .. }
                | BatchOp::Update { storage, .. }
                | BatchOp::UpdateIf { storage, .. }
                | BatchOp::Delete { storage, .. }
                | BatchOp::NextSequence { storage, .. } => storage.clone(),
            };
            if !names.contains(&name) {
                names.push(name);
            }
        }
        let mut i = 0;
        while i < names.len() {
            let t = self.target(app_code, client_code, &names[i]).await?;
            if let Some(s) = t.storage.as_ref() {
                t.backend.engine.prepare(&ctx(), &t.client, t.backend.conn(), s).await?;
                for r in s.relations.iter().flat_map(|m| m.values()) {
                    if let Some(target) = r.storage_name.clone() {
                        if !names.contains(&target) {
                            names.push(target);
                        }
                    }
                }
            }
            i += 1;
        }
        Ok(())
    }

    async fn batch_op(
        &self,
        app_code: Option<&str>,
        client_code: Option<&str>,
        op: BatchOp,
        named: &[(String, Value)],
        journal: &Mutex<Vec<Undo>>,
        atomic: &Mutex<bool>,
    ) -> CoreResult<Value> {
        let storage_name = match &op {
            BatchOp::Create { storage, .. }
            | BatchOp::Update { storage, .. }
            | BatchOp::UpdateIf { storage, .. }
            | BatchOp::Delete { storage, .. }
            | BatchOp::NextSequence { storage, .. } => storage.clone(),
        };
        let t = self.target(app_code, client_code, &storage_name).await?;
        let transactional = t.backend.engine.transactional(t.backend.conn()).await;
        if !transactional {
            if let Ok(mut a) = atomic.lock() {
                *a = false;
            }
        }
        let remember = |u: Undo| {
            if !transactional {
                if let Ok(mut j) = journal.lock() {
                    j.push(u);
                }
            }
        };
        let storage = || t.storage.clone().ok_or_else(|| CoreError::msg(StatusCode::NOT_FOUND, super::msg::STORAGE_NOT_FOUND, &[]));

        match op {
            BatchOp::Create { data, .. } => {
                let data = resolve_doc(&data, named)?;
                let row = self.create(app_code, client_code, &storage_name, DataObject::of(data), Some(false), None).await?;
                if let Some(id) = row.get("_id").map(Value::java_string) {
                    remember(Undo::Delete { backend: t.backend.clone(), client: t.client.clone(), storage: storage()?, id });
                }
                Ok(Value::Object(row))
            }
            BatchOp::Update { id, data, partial, .. } => {
                let id = resolve_text(&id, named)?;
                let mut data = resolve_doc(&data, named)?;
                if !transactional {
                    if let Some(before) = t.backend.engine.lock_row(&ctx(), &t.client, t.backend.conn(), &storage()?, &id).await? {
                        remember(Undo::Restore { backend: t.backend.clone(), client: t.client.clone(), storage: storage()?, before });
                    }
                }
                data.insert("_id".into(), Value::String(id));
                let row = self.update(app_code, client_code, &storage_name, DataObject::of(data), !partial, Some(false), None).await?;
                Ok(Value::Object(row))
            }
            BatchOp::UpdateIf { id, expected, data, partial, .. } => {
                let id = resolve_text(&id, named)?;
                let expected = resolve_doc(&expected, named)?;
                let data = resolve_doc(&data, named)?;
                let out = self.compare_and_update(app_code, client_code, &storage_name, &id, &expected, data, partial).await?;
                if !out.0.updated {
                    return Err(condition_failed(&storage_name, &id));
                }
                if let Some(before) = out.1 {
                    remember(Undo::Restore { backend: t.backend.clone(), client: t.client.clone(), storage: storage()?, before });
                }
                Ok(Value::Object(out.0.row))
            }
            BatchOp::Delete { id, .. } => {
                let id = resolve_text(&id, named)?;
                let before = if transactional {
                    None
                } else {
                    t.backend.engine.lock_row(&ctx(), &t.client, t.backend.conn(), &storage()?, &id).await?
                };
                let deleted = self.delete(app_code, client_code, &storage_name, &id, Some(false)).await?;
                if let Some(before) = before.filter(|_| deleted) {
                    remember(Undo::Recreate { backend: t.backend.clone(), client: t.client.clone(), storage: storage()?, before });
                }
                let mut o = Document::new();
                o.insert("deleted".into(), Value::Bool(deleted));
                Ok(Value::Object(o))
            }
            BatchOp::NextSequence { key, start, .. } => {
                let key = resolve_text(&key, named)?;
                let value = self.next_sequence(app_code, client_code, &storage_name, &key, start).await?;
                let mut o = Document::new();
                o.insert("value".into(), Value::Int(value));
                Ok(Value::Object(o))
            }
        }
    }

    /// Reverses one write directly on the engine: no gates, triggers or events, as the write it
    /// undoes already passed them. Failures are logged; the batch's own error is what the
    /// caller sees.
    async fn undo(&self, u: Undo) {
        let r = match u {
            Undo::Delete { backend, client, storage, id } => {
                backend.engine.delete(&ctx(), &client, backend.conn(), &storage, &id, Some(true)).await.map(|_| ())
            }
            Undo::Restore { backend, client, storage, before } => backend
                .engine
                .update(&ctx(), &client, backend.conn(), &storage, DataObject::of(before), Some(true))
                .await
                .map(|_| ()),
            Undo::Recreate { backend, client, storage, before } => {
                backend.engine.create(&ctx(), &client, backend.conn(), &storage, DataObject::of(before)).await.map(|_| ())
            }
        };
        if let Err(e) = r {
            tracing::error!(error = %e.message(), "Storage.Batch: undoing a write failed");
        }
    }

    /// Reads the row (locked on MySQL inside a transaction), compares, then updates through the
    /// normal update path. The second value is the row as it was before, when it was updated.
    #[allow(clippy::too_many_arguments)]
    async fn compare_and_update(
        &self,
        app_code: Option<&str>,
        client_code: Option<&str>,
        storage_name: &str,
        id: &str,
        expected: &Document,
        data: Document,
        partial: bool,
    ) -> CoreResult<(UpdateIfOutcome, Option<Document>)> {
        let t = self.target(app_code, client_code, storage_name).await?;
        let Some(s) = t.storage.as_ref() else {
            return Err(CoreError::msg(StatusCode::NOT_FOUND, super::msg::STORAGE_NOT_FOUND, &[]));
        };
        if !has_authority(Gate::Read.expression(s))? || !has_authority(Gate::Update.expression(s))? {
            return Err(super::gate_refusal(Gate::Update.message(), &s.name));
        }
        let Some(current) = t.backend.engine.lock_row(&ctx(), &t.client, t.backend.conn(), s, id).await? else {
            return Err(CoreError::from(appdata::AppDataError::object_not_found(&s.name, id)));
        };
        if !matches(expected, &current) {
            return Ok((UpdateIfOutcome { updated: false, row: current }, None));
        }
        let mut data = data;
        data.insert("_id".into(), Value::String(id.to_string()));
        let row = self.update(app_code, client_code, storage_name, DataObject::of(data), !partial, Some(false), None).await?;
        Ok((UpdateIfOutcome { updated: true, row }, Some(current)))
    }

    /// `CoreServices.Storage.UpdateIf`: atomic on MySQL (the row stays locked between the
    /// comparison and the write); on an engine without transactions the window is the time
    /// between one read and one write.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_if(
        &self,
        app_code: Option<&str>,
        client_code: Option<&str>,
        storage_name: &str,
        id: &str,
        expected: &Document,
        data: Document,
        partial: bool,
    ) -> CoreResult<UpdateIfOutcome> {
        let events: Arc<Mutex<Vec<DeferredEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let run = async {
            self.compare_and_update(app_code, client_code, storage_name, id, expected, data, partial)
                .await
                .map(|(o, _)| o)
        };
        let out = DEFERRED_EVENTS.scope(events.clone(), tx::scope(run)).await?;
        let pending = std::mem::take(&mut *events.lock().map_err(|_| CoreError::unknown("events poisoned"))?);
        for e in pending {
            self.events.create_event(&e.app, &e.client, &e.name, e.event).await?;
        }
        Ok(out)
    }

    /// `CoreServices.Storage.NextSequence`: the storage's create gate guards its counters.
    pub async fn next_sequence(&self, app_code: Option<&str>, client_code: Option<&str>, storage_name: &str, key: &str, start: i64)
        -> CoreResult<i64> {
        let t = self.target(app_code, client_code, storage_name).await?;
        let Some(s) = t.storage.as_ref() else {
            return Err(CoreError::msg(StatusCode::NOT_FOUND, super::msg::STORAGE_NOT_FOUND, &[]));
        };
        if !has_authority(Gate::Create.expression(s))? {
            return Err(super::gate_refusal(Gate::Create.message(), &s.name));
        }
        Ok(t.backend.engine.next_sequence(&ctx(), &t.client, t.backend.conn(), s, key, start).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(pairs: &[(&str, Value)]) -> Document {
        pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
    }

    #[test]
    fn values_compare_the_way_rows_come_back() {
        assert!(same_value(&Value::Int(1), Some(&Value::Double(1.0))));
        assert!(same_value(&Value::Bool(true), Some(&Value::Int(1))));
        assert!(same_value(&Value::Bool(false), Some(&Value::Int(0))));
        assert!(same_value(&Value::Null, None));
        assert!(!same_value(&Value::Null, Some(&Value::String("x".into()))));
        assert!(same_value(&Value::String("7".into()), Some(&Value::Int(7))));
        assert!(!same_value(&Value::String("AVAILABLE".into()), Some(&Value::String("BLOCKED".into()))));
        assert!(matches(&doc(&[("status", Value::String("AVAILABLE".into())), ("version", Value::Int(3))]),
            &doc(&[("status", Value::String("AVAILABLE".into())), ("version", Value::Double(3.0)), ("other", Value::Int(9))])));
    }

    /// Only a duplicate key and a stale `updateIf` are conflicts a batch can report.
    #[test]
    fn conflicts_are_duplicates_and_stale_rows() {
        assert_eq!(OnConflict::parse(None), Some(OnConflict::Throw));
        assert_eq!(OnConflict::parse(Some(" ")), Some(OnConflict::Throw));
        assert_eq!(OnConflict::parse(Some("THROW")), Some(OnConflict::Throw));
        assert_eq!(OnConflict::parse(Some("report")), Some(OnConflict::Report));
        assert_eq!(OnConflict::parse(Some("retry")), None);

        let dup = CoreError::from(appdata::AppDataError::duplicate_key("claimKey_unique").in_storage("cxCase"));
        let dup = failed_at(2, dup);
        assert_eq!(
            conflict_of(&dup),
            Some((ConflictKind::Duplicate, Some("claimKey_unique".to_string()), "That is already taken (claimKey_unique).".to_string()))
        );
        let (kind, key, message) = conflict_of(&failed_at(0, condition_failed("cxDiscount", "D1"))).unwrap();
        assert_eq!((kind.name(), key), ("STALE", None));
        assert_eq!(message, "The row D1 of cxDiscount no longer matches what was expected.");
        assert_eq!(conflict_of(&CoreError::from(appdata::AppDataError::object_not_found("s", "1"))), None);
        assert_eq!(conflict_of(&CoreError::unknown("boom")), None);
        assert_eq!(ConflictKind::Duplicate.name(), "DUPLICATE");
    }

    #[test]
    fn references_reach_into_earlier_results() {
        let named = vec![("case".to_string(), Value::Object(doc(&[("_id", Value::String("C1".into())), ("n", Value::Int(4))])))];
        let mut r = Document::new();
        r.insert("$ref".into(), Value::String("case._id".into()));
        let data = doc(&[("caseId", Value::Object(r)), ("amount", Value::Int(5))]);
        let out = resolve_doc(&data, &named).unwrap();
        assert_eq!(out.get("caseId"), Some(&Value::String("C1".into())));
        assert_eq!(resolve_text("$ref:case.n", &named).unwrap(), "4");
        assert_eq!(resolve_text("plain", &named).unwrap(), "plain");
        let mut bad = Document::new();
        bad.insert("$ref".into(), Value::String("nobody.x".into()));
        assert!(resolve_refs(&Value::Object(bad), &named).is_err());
    }
}
