//! Drafts: `AbstractDraftService` (the `draft` collection, storage with no policy of its own)
//! and the draft half of `AbstractOverridableDataService`: save, the editor's read, fork,
//! publish (reconciled onto live), discard, and create-unpublished.
//!
//! One draft per `(app, type, name, client)`: it belongs to a client, so two editors share it,
//! and its own `version` moves on every save so a stale save can be refused. `baseVersion` is
//! the live version the draft was taken from and never moves, which is what makes a publish
//! onto a newer live document reconcile (or fail) rather than overwrite.

use std::sync::Arc;

use axum::http::StatusCode;
use mongodb::bson::{doc, Bson, Document};
use platform::error::{AppError, AppResult};
use platform::security::ContextAuthentication;

use crate::backend::{Backend, Find};
use crate::json::{JMap, JValue};
use crate::pojo::{convert_json, decode_bson, str_field, CloneRule as C, Field, Kind as K, Pojo};
use crate::write::kind::{Kind, Method};
use crate::write::messages as msg;
use crate::write::persist::{jackson_document, to_document, Clock};
use crate::write::service::{jstr, version_of, OverridableService};

/// The `Draft` document class (`AbstractUpdatableDTO` + its own fields).
pub const DRAFT: Pojo = Pojo {
    name: "Draft",
    parts: &[
        &[
            Field::new("id", K::Str, C::Copy),
            Field::new("createdAt", K::DateTime, C::Copy),
            Field::new("createdBy", K::Str, C::Copy),
            Field::new("updatedAt", K::DateTime, C::Copy),
            Field::new("updatedBy", K::Str, C::Copy),
        ],
        &[
            Field::new("objectType", K::Str, C::Copy),
            Field::new("objectAppCode", K::Str, C::Copy),
            Field::new("objectName", K::Str, C::Copy),
            Field::new("clientCode", K::Str, C::Copy),
            Field::new("objectId", K::Str, C::Copy),
            Field::new("content", K::MapObject, C::Copy),
            Field::new("baseVersion", K::PrimInt(0), C::Copy),
            Field::new("version", K::PrimInt(1), C::Copy),
            Field::new("message", K::Str, C::Copy),
        ],
    ],
};

const COLLECTION: &str = "draft";

/// The `draft` collection.
#[derive(Clone)]
pub struct DraftStore {
    backend: Arc<dyn Backend>,
}

fn key(object_type: &str, app: &str, name: &str, client: &str) -> Document {
    doc! {"objectAppCode": app, "objectType": object_type, "objectName": name, "clientCode": client}
}

impl DraftStore {
    pub fn new(backend: Arc<dyn Backend>) -> Self {
        Self { backend }
    }

    pub fn decode(d: &Document) -> JMap {
        decode_bson(&DRAFT, d)
    }

    /// `upsert`: replaces the content of the client's draft (its version moves on, its
    /// `baseVersion` does not), or starts one. Answers the saved draft.
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert(
        &self,
        object_type: &str,
        app: &str,
        name: &str,
        client: &str,
        object_id: &str,
        content: Document,
        base_version: i64,
        message: Option<&str>,
    ) -> AppResult<JMap> {
        let clock = Clock::now();
        let existing = self.find(object_type, app, name, client).await?;
        let mut draft = match &existing {
            Some(d) => {
                let mut e = Self::decode(d);
                let v = e.get("version").and_then(JValue::as_i64).unwrap_or(1);
                e.insert("version".into(), JValue::Int(v + 1));
                e
            }
            None => {
                let mut e = Self::decode(&Document::new());
                for (k, v) in [("objectType", object_type), ("objectAppCode", app), ("objectName", name), ("clientCode", client)] {
                    e.insert(k.into(), JValue::Str(v.to_string()));
                }
                e.insert("baseVersion".into(), JValue::Int(base_version));
                e
            }
        };
        draft.insert("content".into(), JValue::Object(crate::bson_conv::doc_to_j(&content)));
        draft.insert("message".into(), message.map(|m| JValue::Str(m.to_string())).unwrap_or_default());
        draft.insert("objectId".into(), JValue::Str(object_id.to_string()));
        draft.insert("updatedAt".into(), clock.value());
        let priors: Vec<&Document> = existing.iter().collect();
        let mut d = to_document(&DRAFT, &draft, Some(&clock), &priors);
        d.insert("content", content);
        match existing.as_ref().and_then(|e| e.get("_id")) {
            Some(id) => self.backend.replace(COLLECTION, id.clone(), d).await?,
            None => {
                let id = self.backend.insert(COLLECTION, d).await?;
                let id = match id {
                    Bson::ObjectId(o) => o.to_hex(),
                    other => crate::bson_conv::to_java_string(&other).java_to_string(),
                };
                draft.insert("id".into(), JValue::Str(id));
            }
        }
        Ok(draft)
    }

    pub async fn find(&self, object_type: &str, app: &str, name: &str, client: &str) -> AppResult<Option<Document>> {
        Ok(self.backend.find_one(COLLECTION, key(object_type, app, name, client), None).await?)
    }

    pub async fn find_by_object_id(&self, object_id: &str) -> AppResult<Option<Document>> {
        Ok(self.backend.find_one(COLLECTION, doc! {"objectId": object_id}, None).await?)
    }

    /// Every draft of a client in an app, in stored order.
    pub async fn pending(&self, app: &str, client: &str) -> AppResult<Vec<Document>> {
        Ok(self.backend.find(COLLECTION, Find::new(doc! {"objectAppCode": app, "clientCode": client})).await?)
    }

    async fn delete_found(&self, found: Option<Document>) -> AppResult<bool> {
        match found.and_then(|d| d.get("_id").cloned()) {
            Some(id) => {
                self.backend.delete_one(COLLECTION, doc! {"_id": id}).await?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// `discard`: `true` when a draft was there and is gone.
    pub async fn discard(&self, object_type: &str, app: &str, name: &str, client: &str) -> AppResult<bool> {
        let found = self.find(object_type, app, name, client).await?;
        self.delete_found(found).await
    }

    pub async fn discard_by_object_id(&self, object_id: &str) -> AppResult<bool> {
        let found = self.find_by_object_id(object_id).await?;
        self.delete_found(found).await
    }

    /// Every draft of a client in an app, all types.
    pub async fn delete_everything(&self, app: &str, client: &str) -> AppResult<u64> {
        Ok(self.backend.delete_many(COLLECTION, doc! {"objectAppCode": app, "clientCode": client}).await?)
    }

    /// One type's drafts of a client in an app.
    pub async fn delete_by(&self, app: &str, object_type: &str, client: &str) -> AppResult<u64> {
        Ok(self
            .backend
            .delete_many(COLLECTION, doc! {"objectAppCode": app, "objectType": object_type, "clientCode": client})
            .await?)
    }
}

/// `annotate`: the publish message with the reconciliation note.
fn annotate(message: Option<&str>, note: Option<&str>) -> Option<String> {
    match (message, note) {
        (m, None) => m.map(str::to_string),
        (Some(m), Some(n)) if !m.trim().is_empty() => Some(format!("{m} {n}")),
        (_, Some(n)) => Some(n.to_string()),
    }
}

impl<K: Kind> OverridableService<K> {
    /// Java's "Draft with id <type> not found" (405), said as what it is.
    fn not_draftable(&self) -> AppError {
        self.commons()
            .messages
            .error_as("DEF.DRAFT_NOT_SUPPORTED", StatusCode::METHOD_NOT_ALLOWED, msg::OBJECT_NOT_FOUND, &["Draft", self.object_name()])
    }

    fn require_draftable(&self) -> AppResult<()> {
        if self.kind().draftable() {
            Ok(())
        } else {
            Err(self.not_draftable())
        }
    }

    fn forbidden(&self, ca: &ContextAuthentication) -> AppError {
        self.forbidden_permission(ca)
    }

    /// `createUnpublished`: a real document marked never-published, tracked by a draft row
    /// holding the full content as sent (publish and publish-all start from the row, and for a
    /// client override `create` stores only the difference from the base).
    pub async fn create_unpublished(&self, ca: &ContextAuthentication, mut entity: JMap) -> AppResult<JMap> {
        self.require_draftable()?;
        entity.insert("published".into(), JValue::Bool(false));
        let mut content = entity.clone();
        let message = str_field(&entity, "message").map(str::to_string);
        let created = self.create(ca, entity).await?;
        // The row is read back as the editor's object, so it names the document it belongs to.
        content.insert("id".into(), created.get("id").cloned().unwrap_or_default());
        content.insert("version".into(), created.get("version").cloned().unwrap_or_default());
        let (app, name, client) = (jstr(str_field(&created, "appCode")), jstr(str_field(&created, "name")), jstr(str_field(&created, "clientCode")));
        self.commons()
            .drafts
            .upsert(
                &self.object_type(),
                app,
                name,
                client,
                str_field(&created, "id").unwrap_or_default(),
                jackson_document(self.kind().pojo(), &content),
                version_of(&created),
                message.as_deref(),
            )
            .await?;
        self.evict_draft(app, client, name).await?;
        Ok(created)
    }

    /// `saveDraft`: stores the body as the caller's unpublished work on the document it
    /// belongs on (forking the caller an override when that is what it may do), leaving live
    /// alone. `expected_version` is the `X-Draft-Version` the caller last saw; `None` skips the
    /// check.
    pub async fn save_draft(&self, ca: &ContextAuthentication, entity: JMap, expected_version: Option<i64>) -> AppResult<JMap> {
        self.require_draftable()?;
        let id = str_field(&entity, "id").map(str::to_string).ok_or_else(|| self.forbidden(ca))?;
        let stored = self.find_by_id(&id).await?.ok_or_else(|| self.forbidden(ca))?;
        let target = self.resolve_draft_target(ca, &stored).await?.ok_or_else(|| self.forbidden(ca))?;
        let (app, name, client) = (jstr(str_field(&target, "appCode")), jstr(str_field(&target, "name")), jstr(str_field(&target, "clientCode")));
        let drafts = &self.commons().drafts;
        if let Some(expected) = expected_version {
            let current = match drafts.find(&self.object_type(), app, name, client).await? {
                Some(d) => DraftStore::decode(&d).get("version").and_then(JValue::as_i64).unwrap_or(1),
                None => 0,
            };
            if expected != current {
                return Err(self.err(StatusCode::PRECONDITION_FAILED, msg::VERSION_MISMATCH, &[]));
            }
        }
        let content = jackson_document(self.kind().pojo(), &entity);
        let saved = drafts
            .upsert(
                &self.object_type(),
                app,
                name,
                client,
                str_field(&target, "id").unwrap_or_default(),
                content,
                version_of(&target),
                str_field(&entity, "message"),
            )
            .await?;
        self.evict_draft(app, client, name).await?;
        Ok(saved)
    }

    /// `forkForCaller`: the caller's own override of the object, made if it may have one and
    /// has none yet. Idempotent.
    pub async fn fork_for_caller(&self, ca: &ContextAuthentication, id: &str) -> AppResult<JMap> {
        self.require_draftable()?;
        if id.trim().is_empty() {
            return Err(self.forbidden(ca));
        }
        let stored = self.find_by_id(id).await?.ok_or_else(|| self.forbidden(ca))?;
        let target = self.resolve_draft_target(ca, &stored).await?.ok_or_else(|| self.forbidden(ca))?;
        self.evict_draft(jstr(str_field(&target, "appCode")), jstr(str_field(&target, "clientCode")), jstr(str_field(&target, "name")))
            .await?;
        Ok(target)
    }

    /// `resolveDraftTarget`: the stored document when the caller may write it, else the
    /// caller's own override in its chain (forked when needed). `None` is a refusal.
    async fn resolve_draft_target(&self, ca: &ContextAuthentication, stored: &JMap) -> AppResult<Option<JMap>> {
        if self
            .access_check(ca, Method::Update, str_field(stored, "appCode"), str_field(stored, "clientCode"), true)
            .await?
        {
            return Ok(Some(stored.clone()));
        }
        let chain = self.caller_chain(ca, stored).await?;
        self.fork_target(ca, stored, &chain).await
    }

    /// `resolveDiscardTarget`: the same without the fork.
    async fn resolve_discard_target(&self, ca: &ContextAuthentication, stored: &JMap) -> AppResult<Option<JMap>> {
        if self
            .access_check(ca, Method::Update, str_field(stored, "appCode"), str_field(stored, "clientCode"), true)
            .await?
        {
            return Ok(Some(stored.clone()));
        }
        let chain = self.caller_chain(ca, stored).await?;
        if !in_chain(&chain, ca.client_code(), stored) {
            return Ok(None);
        }
        self.find_one(jstr(str_field(stored, "name")), jstr(str_field(stored, "appCode")), ca.client_code()).await
    }

    async fn caller_chain(&self, ca: &ContextAuthentication, stored: &JMap) -> AppResult<Arc<Vec<String>>> {
        let url = ca.url_client_code.as_deref().unwrap_or("");
        Ok(self
            .commons()
            .store
            .inheritance_order(jstr(str_field(stored, "appCode")), url, ca.client_code())
            .await?)
    }

    /// `forkTarget`: the anti-forgery gate (the stored document must be in the caller's own
    /// chain), then the caller's existing row, else a fork off the most derived published
    /// ancestor.
    async fn fork_target(&self, ca: &ContextAuthentication, stored: &JMap, chain: &[String]) -> AppResult<Option<JMap>> {
        let mine = ca.client_code();
        if !in_chain(chain, mine, stored) {
            return Ok(None);
        }
        let (name, app) = (jstr(str_field(stored, "name")), jstr(str_field(stored, "appCode")));
        let codes: Vec<Bson> = chain.iter().map(|c| Bson::String(c.clone())).collect();
        let rows: Vec<JMap> = self
            .commons()
            .backend()
            .find(self.collection(), Find::new(doc! {"name": name, "appCode": app, "clientCode": {"$in": codes}}))
            .await?
            .iter()
            .map(|d| decode_bson(self.kind().pojo(), d))
            .collect();
        if let Some(own) = rows.iter().find(|r| str_field(r, "clientCode") == Some(mine)) {
            return Ok(Some(own.clone()));
        }
        let Some(base) = pick_fork_base(&rows, chain, mine) else {
            return Ok(None);
        };
        if base.get("notOverridable") == Some(&JValue::Bool(true)) {
            return Err(self.err(StatusCode::FORBIDDEN, msg::FORBIDDEN_FORK_NOT_OVERRIDABLE, &[self.object_name(), jstr(str_field(base, "name"))]));
        }
        if !self.access_check(ca, Method::Create, Some(app), Some(mine), true).await? {
            return Ok(None);
        }
        self.fork_converging(ca, base, name, app, mine).await
    }

    /// `forkConverging`: a fork that lost a race to another one adopts the winner's row.
    async fn fork_converging(&self, ca: &ContextAuthentication, base: &JMap, name: &str, app: &str, client: &str) -> AppResult<Option<JMap>> {
        match self.fork_for_client(ca, base, client).await {
            Ok(created) => Ok(created),
            Err(AppError::Internal(e)) if crate::backend::is_duplicate_key(&e) => self.find_one(name, app, client).await,
            Err(e) if e.status() == StatusCode::CONFLICT => self.find_one(name, app, client).await,
            Err(e) => Err(e),
        }
    }

    /// `readDraftWithVersion`: the caller's draft with its own version, when the caller may
    /// write the object; otherwise the live document and version 0. Runs the live read's
    /// access check first.
    pub async fn read_draft_with_version(&self, ca: &ContextAuthentication, id: &str) -> AppResult<(JMap, i64)> {
        self.require_draftable()?;
        let live = self.read(ca, id).await?;
        let may_write = self
            .access_check(ca, Method::Update, str_field(&live, "appCode"), str_field(&live, "clientCode"), true)
            .await?;
        if may_write {
            if let Some(d) = self.commons().drafts.find_by_object_id(id).await? {
                let draft = DraftStore::decode(&d);
                let content = draft.get("content").and_then(JValue::as_object).cloned().unwrap_or_default();
                return Ok((convert_json(self.kind().pojo(), &content), version_of(&draft)));
            }
        }
        Ok((live, 0))
    }

    /// `publish`: the draft, reconciled onto the current live document, through `update`
    /// (so every eviction and the Version row happen), then the never-published marker
    /// cleared and the draft removed.
    pub async fn publish(&self, ca: &ContextAuthentication, id: &str, message: Option<&str>) -> AppResult<JMap> {
        self.require_draftable()?;
        let draft = self
            .commons()
            .drafts
            .find_by_object_id(id)
            .await?
            .ok_or_else(|| self.err(StatusCode::NOT_FOUND, msg::OBJECT_NOT_FOUND, &["Draft", id]))?;
        let stored = self.find_by_id(id).await?.ok_or_else(|| self.not_found(id))?;
        let rec = self.commons().store.reconcile(self.kind(), &draft, &stored).await?;
        let draft_message = draft.get_str("message").ok();
        let mut entity = rec.entity;
        let message = annotate(message.or(draft_message), rec.note.as_deref());
        entity.insert("message".into(), message.map(JValue::Str).unwrap_or_default());
        let published = self.update(ca, entity).await?;
        self.mark_published(id, &stored).await?;
        self.commons().drafts.discard_by_object_id(id).await?;
        Ok(published)
    }

    /// `markPublished`: flips a never-published document to published, and only that.
    async fn mark_published(&self, id: &str, stored: &JMap) -> AppResult<()> {
        if stored.get("published") != Some(&JValue::Bool(false)) {
            return Ok(());
        }
        if let Some((mut fresh, raw)) = self.find_raw(id).await? {
            fresh.insert("published".into(), JValue::Bool(true));
            self.replace(&fresh, None, Some(&raw)).await?;
        }
        self.evict_recursively(jstr(str_field(stored, "appCode")), jstr(str_field(stored, "clientCode")), jstr(str_field(stored, "name")))
            .await
    }

    /// `discardDraft`: throws away the caller's unpublished work; `false` when there was none.
    pub async fn discard_draft(&self, ca: &ContextAuthentication, id: &str) -> AppResult<bool> {
        self.require_draftable()?;
        let stored = self.find_by_id(id).await?.ok_or_else(|| self.forbidden(ca))?;
        let target = self.resolve_discard_target(ca, &stored).await?.ok_or_else(|| self.forbidden(ca))?;
        let discarded = self.commons().drafts.discard_by_object_id(str_field(&target, "id").unwrap_or_default()).await?;
        self.evict_draft(jstr(str_field(&target, "appCode")), jstr(str_field(&target, "clientCode")), jstr(str_field(&target, "name")))
            .await?;
        Ok(discarded)
    }
}

fn in_chain(chain: &[String], mine: &str, stored: &JMap) -> bool {
    let theirs = str_field(stored, "clientCode").unwrap_or_default();
    chain.iter().any(|c| c == mine) && chain.iter().any(|c| c == theirs)
}

/// `pickForkBase`: the most derived ancestor that is not the caller; a never-published one
/// is no base at all.
fn pick_fork_base<'a>(rows: &'a [JMap], chain: &[String], mine: &str) -> Option<&'a JMap> {
    for cc in chain.iter().rev() {
        if cc == mine {
            continue;
        }
        if let Some(row) = rows.iter().find(|r| str_field(r, "clientCode") == Some(cc.as_str())) {
            return (row.get("published") != Some(&JValue::Bool(false))).then_some(row);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_are_annotated_like_java() {
        assert_eq!(annotate(Some("ship"), None).as_deref(), Some("ship"));
        assert_eq!(annotate(None, None), None);
        assert_eq!(annotate(Some("ship"), Some("[n]")).as_deref(), Some("ship [n]"));
        assert_eq!(annotate(Some(" "), Some("[n]")).as_deref(), Some("[n]"));
        assert_eq!(annotate(None, Some("[n]")).as_deref(), Some("[n]"));
    }

    #[test]
    fn fork_base_is_the_most_derived_published_ancestor() {
        let row = |c: &str, published: Option<bool>| {
            let mut m = JMap::new();
            m.insert("clientCode".into(), JValue::Str(c.into()));
            m.insert("published".into(), published.map(JValue::Bool).unwrap_or_default());
            m
        };
        let chain: Vec<String> = ["SYSTEM", "MID", "ME"].iter().map(|s| s.to_string()).collect();
        let rows = vec![row("SYSTEM", None), row("MID", None)];
        assert_eq!(str_field(pick_fork_base(&rows, &chain, "ME").unwrap(), "clientCode"), Some("MID"));
        let rows = vec![row("SYSTEM", None), row("MID", Some(false))];
        assert!(pick_fork_base(&rows, &chain, "ME").is_none(), "a never-published ancestor is no base");
        assert!(pick_fork_base(&[], &chain, "ME").is_none());
    }
}
