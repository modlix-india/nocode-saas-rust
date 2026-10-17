//! `AbstractOverridableDataService` (with `AbstractMongoDataService` and
//! `AbstractMongoUpdatableDataService` under it): create, read by id, update, the plan-only
//! update, delete, the access checks, and the evictions every write makes.
//!
//! The draft and publish half is in [`crate::write::draft`], the list reads in
//! [`crate::write::list`], the transport reads in [`crate::write::transport`].
//!
//! Every write evicts what Java evicts, under the Java names, through
//! [`CacheService::evict_all_everywhere`] / [`CacheService::evict_everywhere`]: the local copy,
//! a message on `evictionChannel` (`cmn-<cache>:<key>` or `:*`) for every other instance, and
//! the Java L2 hash entry (`DEL` / `HDEL`).

use std::sync::Arc;

use axum::http::StatusCode;
use mongodb::bson::{doc, Bson, Document};
use platform::cache::{CacheService, LocalCaches};
use platform::error::{AppError, AppResult};
use platform::security::ContextAuthentication;

use crate::backend::{Backend, Directory};
use crate::bson_conv::from_j;
use crate::json::{JMap, JValue};
use crate::pojo::{decode_bson, str_field};
use crate::store::{apply_actual_override, make_actual_override, Resolved, Store};
use crate::write::draft::DraftStore;
use crate::write::kind::{Kind, Method};
use crate::write::list::LroPage;
use crate::write::messages::{self as msg, Messages};
use crate::write::persist::{id_bson, jackson_document, to_document, Clock};
use crate::write::version::{NewVersion, VersionStore};

/// `DRAFT_CACHE_SUFFIX`: the draft surface's caches are separate caches, not separate keys.
pub const DRAFT_SUFFIX: &str = "_DRAFT";
/// `READ_PAGE`: the list cache of one object type in one app.
pub const READ_PAGE_SUFFIX: &str = "_READ_PAGE";

/// What every overridable service of one process shares: the store (documents, security,
/// definition caches), the cache service (evictions), the message bundle, and the draft and
/// version collections.
#[derive(Clone)]
pub struct Commons {
    pub store: Store,
    pub cache: CacheService,
    pub messages: Arc<Messages>,
    pub drafts: DraftStore,
    pub versions: VersionStore,
}

impl Commons {
    /// `version_auth` maps a version's object type to the authority name its reads need
    /// ([`crate::write::version::UI_AUTH_NAMES`], [`crate::write::version::CORE_AUTH_NAMES`]).
    pub fn new(store: Store, cache: CacheService, messages: Messages, version_auth: &'static [(&'static str, &'static str)]) -> Self {
        let drafts = DraftStore::new(store.backend().clone());
        let versions = VersionStore::new(store.clone(), version_auth);
        Self { store, cache, messages: Arc::new(messages), drafts, versions }
    }

    pub fn backend(&self) -> &Arc<dyn Backend> {
        self.store.backend()
    }

    pub fn directory(&self) -> &Arc<dyn Directory> {
        self.store.directory()
    }

    /// `messageResourceService.throwMessage(status, id, params...)`.
    pub fn error(&self, status: StatusCode, id: &str, params: &[&str]) -> AppError {
        self.messages.error(status, id, params)
    }

    /// `cacheService.evictAll(name)`, everywhere.
    pub async fn evict_all(&self, cache_name: &str) {
        self.cache.evict_all_everywhere(cache_name).await;
    }

    /// `cacheService.evict(name, key)`, everywhere.
    pub async fn evict(&self, cache_name: &str, key: &str) {
        self.cache.evict_everywhere(cache_name, key).await;
    }

    /// A message on another Redis channel (`ssr:cache:invalidation`); `false` without Redis.
    pub async fn publish(&self, channel: &str, message: &str) -> bool {
        self.cache.publish(channel, message).await
    }
}

/// `getLoggedInUserId()`: the caller's user id, none for an anonymous caller.
pub fn user_id(ca: &ContextAuthentication) -> Option<String> {
    (ca.authenticated || ca.user.id != 0).then(|| ca.user.id.to_string())
}

/// `StringBuilder.append(String)`: a null appends `null`.
pub fn jstr(s: Option<&str>) -> &str {
    s.unwrap_or("null")
}

fn non_blank(s: Option<&str>) -> Option<&str> {
    s.filter(|v| !v.trim().is_empty())
}

pub(crate) fn version_of(m: &JMap) -> i64 {
    m.get("version").and_then(JValue::as_i64).unwrap_or(1)
}

struct Inner<K> {
    kind: K,
    cx: Commons,
    lro: Arc<LocalCaches<String, Arc<LroPage>>>,
}

/// One overridable document kind's service.
pub struct OverridableService<K: Kind> {
    inner: Arc<Inner<K>>,
}

impl<K: Kind> Clone for OverridableService<K> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }
}

impl<K: Kind> OverridableService<K> {
    pub fn new(kind: K, cx: Commons) -> Self {
        let lro = cx.cache.family();
        Self { inner: Arc::new(Inner { kind, cx, lro }) }
    }

    pub fn kind(&self) -> &K {
        &self.inner.kind
    }

    pub fn commons(&self) -> &Commons {
        &self.inner.cx
    }

    pub(crate) fn lro_cache(&self) -> &LocalCaches<String, Arc<LroPage>> {
        &self.inner.lro
    }

    pub fn object_name(&self) -> &'static str {
        self.kind().object_name()
    }

    /// The type name drafts and versions are filed under (`PAGE`, `STORAGE`, ...).
    pub fn object_type(&self) -> String {
        self.object_name().to_uppercase()
    }

    pub fn collection(&self) -> &'static str {
        self.kind().collection()
    }

    /// `getCacheName(appCode, name, draft)`.
    pub fn cache_name(&self, app: &str, name: &str, draft: bool) -> String {
        let base = self.kind().cache_name(app, name);
        if draft {
            base + DRAFT_SUFFIX
        } else {
            base
        }
    }

    /// `getCacheName(appCode, getObjectName()) + READ_PAGE`.
    pub fn read_page_cache_name(&self, app: &str) -> String {
        self.kind().cache_name(app, self.object_name()) + READ_PAGE_SUFFIX
    }

    pub(crate) fn err(&self, status: StatusCode, id: &str, params: &[&str]) -> AppError {
        self.commons().error(status, id, params)
    }

    /// `FORBIDDEN_PERMISSION` naming the object type (an anonymous caller is asked to sign in).
    pub(crate) fn forbidden_permission(&self, ca: &ContextAuthentication) -> AppError {
        self.commons().messages.refusal(ca, StatusCode::FORBIDDEN, msg::FORBIDDEN_PERMISSION, &[self.object_name()])
    }

    pub(crate) fn not_found(&self, id: &str) -> AppError {
        self.err(StatusCode::NOT_FOUND, msg::OBJECT_NOT_FOUND, &[self.object_name(), id])
    }

    // ── The repository ───────────────────────────────────────────

    /// `repo.findById`: the stored document as decoded, and as stored.
    pub async fn find_raw(&self, id: &str) -> AppResult<Option<(JMap, Document)>> {
        let raw = self.commons().backend().find_one(self.collection(), Store::id_filter(id), None).await?;
        Ok(raw.map(|d| (decode_bson(self.kind().pojo(), &d), d)))
    }

    pub async fn find_by_id(&self, id: &str) -> AppResult<Option<JMap>> {
        Ok(self.find_raw(id).await?.map(|(e, _)| e))
    }

    /// `findOneByNameAndAppCodeAndClientCode`.
    pub async fn find_one(&self, name: &str, app: &str, client: &str) -> AppResult<Option<JMap>> {
        let d = self
            .commons()
            .backend()
            .find_one(self.collection(), doc! {"name": name, "appCode": app, "clientCode": client}, None)
            .await?;
        Ok(d.map(|d| decode_bson(self.kind().pojo(), &d)))
    }

    /// Inserts a new document (the id is the database's), answering it with its id.
    async fn insert(&self, entity: &JMap, clock: &Clock) -> AppResult<JMap> {
        let mut entity = entity.clone();
        entity.insert("id".into(), JValue::Null);
        let d = to_document(self.kind().pojo(), &entity, Some(clock), &[]);
        let id = self.commons().backend().insert(self.collection(), d).await?;
        let id = match id {
            Bson::ObjectId(o) => o.to_hex(),
            other => crate::bson_conv::to_java_string(&other).java_to_string(),
        };
        entity.insert("id".into(), JValue::Str(id));
        Ok(entity)
    }

    /// `repo.save` of a document that has an id (public for the kinds' own saves, such as
    /// ui's page component patches, which save without a version snapshot).
    pub async fn replace(&self, entity: &JMap, clock: Option<&Clock>, prior: Option<&Document>) -> AppResult<()> {
        let id = str_field(entity, "id").unwrap_or_default();
        let priors: Vec<&Document> = prior.into_iter().collect();
        let d = to_document(self.kind().pojo(), entity, clock, &priors);
        self.commons().backend().replace(self.collection(), id_bson(id), d).await?;
        Ok(())
    }

    // ── Access ───────────────────────────────────────────────────

    /// `accessCheck`: whether `ca` may `method` an object of `client` in `app`. A read the
    /// inheritance chain refuses is checked again as a write would be, still under the `_READ`
    /// authority, so a caller can read whatever it can write (Java commit 13470b2f1).
    pub async fn access_check(&self, ca: &ContextAuthentication, method: Method, app: Option<&str>, client: Option<&str>, write: bool) -> AppResult<bool> {
        if let Some(answer) = self.kind().access_override(ca, method).await {
            return Ok(answer);
        }
        let checked = self.check_access(ca, method, app, client, write).await?;
        if write || method != Method::Read || checked {
            return Ok(checked);
        }
        self.check_access(ca, method, app, client, true).await
    }

    async fn check_access(&self, ca: &ContextAuthentication, method: Method, app: Option<&str>, client: Option<&str>, write: bool) -> AppResult<bool> {
        let (Some(app), Some(client)) = (non_blank(app), non_blank(client)) else {
            return Ok(false);
        };
        let authority = format!("Authorities.{}_{}", self.kind().access_check_name(), method.as_str());
        if !ca.has_authority(&authority) {
            return Ok(false);
        }
        let dir = self.commons().directory();
        let Some(explicit) = dir.app_explicit_info(app).await? else {
            return Ok(false);
        };
        let mine = ca.client_code();
        let managed = if mine == client {
            true
        } else if explicit.is_explicit() {
            explicit.client_code.as_deref() == Some(client) || explicit.explicit_owner_client_code.as_deref() == Some(client)
        } else if write {
            dir.does_client_manage_client_code(mine, client).await?
        } else {
            let url = ca.url_client_code.as_deref().unwrap_or("");
            let order = self.commons().store.inheritance_order(app, url, mine).await?;
            order.iter().any(|c| c == mine) && order.iter().any(|c| c == client)
        };
        if !managed {
            return Ok(false);
        }
        if !write {
            return Ok(dir.has_read_access(app, mine).await?);
        }
        // A write needs write access to the app on both sides: the client making the change and
        // the client whose object it is, so a manager cannot create or edit a customization for
        // a read-only client (Java commit 3cf6ebc54). A refused READ retried through this write
        // branch is still a read, so the target's own access is not asked then.
        let caller = dir.has_write_access(app, mine).await?;
        if !caller || client == mine || method == Method::Read {
            return Ok(caller);
        }
        Ok(dir.has_write_access(app, client).await?)
    }

    // ── Merging ──────────────────────────────────────────────────

    /// `getMergedSources`: everything below `entity` in its base chain, merged.
    pub async fn merged_sources(&self, entity: &JMap) -> AppResult<Option<JMap>> {
        Ok(self.commons().store.merged_sources(self.kind(), entity).await?)
    }

    /// `baseClientCodeOf`: the client a customization by `client` stands on (see
    /// [`crate::store::Store::base_client_code_of`]).
    pub async fn base_client_code_of(&self, app: &str, client: &str) -> AppResult<Option<String>> {
        Ok(self.commons().store.base_client_code_of(app, client).await?)
    }

    /// `extractOverride`: what `entity` stores over `merged`.
    pub fn extract_override(&self, entity: JMap, merged: Option<&JMap>) -> AppResult<JMap> {
        make_actual_override(self.kind(), entity, merged)
            .ok_or_else(|| AppError::Internal(anyhow::anyhow!("{} produced no override", self.object_name())))
    }

    /// `readInternal(id)`: the stored document merged onto its chain, no access check.
    pub async fn read_internal(&self, id: &str) -> AppResult<Option<JMap>> {
        Ok(self.commons().store.read_merged_by_id(self.kind(), id).await?)
    }

    /// `read(name, appCode, clientCode)` up to `applyChange`: the runtime read, cached per
    /// client, on the live or the draft surface, for the client it serves
    /// ([`Store::served_client_code`]: a signed-in tenant's own on a shared host).
    pub async fn read_resolved(&self, ca: &ContextAuthentication, name: &str, app: &str, client: &str, draft: bool) -> AppResult<Option<Arc<Resolved>>> {
        let store = &self.commons().store;
        let url = ca.url_client_code.as_deref().unwrap_or(client);
        let served = store.served_client_code(Some(ca), app, client).await;
        Ok(store.read(self.kind(), name, app, url, &served, draft).await?)
    }

    // ── Writes ───────────────────────────────────────────────────

    /// `create`. The id is never taken from the body (see `DIFFERENCES.md`).
    pub async fn create(&self, ca: &ContextAuthentication, mut entity: JMap) -> AppResult<JMap> {
        let clock = Clock::now();
        self.kind().before_create(self.commons(), ca, &mut entity).await?;
        entity.insert("id".into(), JValue::Null);
        if entity.get("clientCode").is_none_or(JValue::is_null) {
            entity.insert("clientCode".into(), JValue::Str(ca.client_code().to_string()));
        }
        self.check_if_exists(&entity).await?;
        let allowed = self
            .access_check(ca, Method::Create, str_field(&entity, "appCode"), str_field(&entity, "clientCode"), true)
            .await?;
        if !allowed {
            return Err(self.commons().messages.refusal(ca, StatusCode::FORBIDDEN, msg::FORBIDDEN_CREATE, &[self.object_name()]));
        }
        let merged = self.merged_sources(&entity).await?;
        let mut overridden = self.extract_override(entity.clone(), merged.as_ref())?;
        overridden.insert("createdAt".into(), clock.value());
        overridden.insert("updatedAt".into(), clock.value());
        overridden.insert("updatedBy".into(), JValue::Null);
        overridden.insert("createdBy".into(), user_id(ca).map(JValue::Str).unwrap_or_default());
        let created = self.insert(&overridden, &clock).await?;
        let snapshot = if self.kind().snapshot_is_override() { &created } else { &entity };
        self.snapshot(ca, &entity, snapshot, version_of(&created)).await?;
        let id = str_field(&created, "id").unwrap_or_default().to_string();
        let read = self.read(ca, &id).await?;
        self.evict_recursively_of(&read).await?;
        self.kind().after_create(self.commons(), &read).await?;
        Ok(read)
    }

    /// `checkIfExists`: 409 when the client already has an object of that name.
    async fn check_if_exists(&self, e: &JMap) -> AppResult<()> {
        let field = |k: &str| from_j(e.get(k).unwrap_or(&JValue::Null));
        let filter = doc! {"name": field("name"), "appCode": field("appCode"), "clientCode": field("clientCode")};
        if self.commons().backend().count(self.collection(), filter).await? > 0 {
            let name = e.get("name").cloned().unwrap_or_default().java_to_string();
            return Err(self.err(StatusCode::CONFLICT, msg::ALREADY_EXISTS, &[self.object_name(), &name]));
        }
        Ok(())
    }

    /// The `Version` row a create or update writes.
    async fn snapshot(&self, ca: &ContextAuthentication, identity: &JMap, object: &JMap, version_number: i64) -> AppResult<()> {
        if !self.kind().versionable() {
            return Ok(());
        }
        let s = |k: &str| str_field(identity, k).map(str::to_string);
        self.commons()
            .versions
            .create(
                ca,
                NewVersion {
                    client_code: s("clientCode"),
                    object_name: s("name"),
                    object_app_code: s("appCode"),
                    object_type: self.object_type(),
                    version_number,
                    message: s("message"),
                    object: jackson_document(self.kind().pojo(), object),
                },
            )
            .await?;
        Ok(())
    }

    /// `read(id)`: the stored document merged onto its chain, for a caller the access check
    /// lets read it; 404 otherwise.
    pub async fn read(&self, ca: &ContextAuthentication, id: &str) -> AppResult<JMap> {
        let entity = self.find_by_id(id).await?;
        let (app, client) = match &entity {
            Some(e) => (str_field(e, "appCode"), str_field(e, "clientCode")),
            None => (None, None),
        };
        let allowed = self.access_check(ca, Method::Read, app, client, false).await?;
        let merged = match entity {
            Some(e) if allowed => {
                let sources = self.merged_sources(&e).await?;
                apply_actual_override(self.kind(), e, sources.as_ref())
            }
            _ => None,
        };
        match merged {
            Some(e) => self.kind().after_read(self.commons(), ca, e).await,
            None => Err(self.not_found(id)),
        }
    }

    /// `update`: load the stored document first and authorize it (never the codes in the
    /// body), take identity from it, store only the difference from the chain below.
    pub async fn update(&self, ca: &ContextAuthentication, mut entity: JMap) -> AppResult<JMap> {
        let clock = Clock::now();
        self.kind().before_update(self.commons(), ca, &mut entity).await?;
        let request = entity.clone();
        let id = str_field(&entity, "id").map(str::to_string).ok_or_else(|| self.forbidden_permission(ca))?;
        let (stored, raw) = self.find_raw(&id).await?.ok_or_else(|| self.forbidden_permission(ca))?;
        let allowed = self
            .access_check(ca, Method::Update, str_field(&stored, "appCode"), str_field(&stored, "clientCode"), true)
            .await?;
        if !allowed {
            return Err(self.forbidden_permission(ca));
        }
        for f in ["appCode", "clientCode", "name", "baseClientCode"] {
            entity.insert(f.into(), stored.get(f).cloned().unwrap_or_default());
        }
        let merged = self.merged_sources(&entity).await?;
        let overridden = self.extract_override(entity.clone(), merged.as_ref())?;
        let saved = self.save_updatable(ca, &overridden, &clock, &raw).await?;
        let snapshot = if self.kind().snapshot_is_override() { &overridden } else { &entity };
        self.snapshot(ca, &entity, snapshot, version_of(&saved)).await?;
        let read = self.read(ca, &id).await?;
        self.evict_recursively_of(&read).await?;
        self.kind().after_update(self.commons(), &request, &read).await?;
        Ok(read)
    }

    /// `AbstractMongoUpdatableDataService.update` with the class's `updatableEntity`.
    async fn save_updatable(&self, ca: &ContextAuthentication, overridden: &JMap, clock: &Clock, raw: &Document) -> AppResult<JMap> {
        let id = str_field(overridden, "id").unwrap_or_default().to_string();
        let mut existing = self.read(ca, &id).await?;
        self.kind().updatable_precheck(self.commons(), ca, &existing, overridden).await?;
        if version_of(&existing) != version_of(overridden) {
            return Err(self.err(StatusCode::PRECONDITION_FAILED, msg::VERSION_MISMATCH, &[]));
        }
        existing.insert("version".into(), JValue::Int(version_of(&existing) + 1));
        self.kind().updatable_fill(self.commons(), ca, &mut existing, overridden).await?;
        for f in ["title", "description", "permission", "message"] {
            existing.insert(f.into(), overridden.get(f).cloned().unwrap_or_default());
        }
        if overridden.get("blueprint").is_some_and(|b| !b.is_null()) {
            existing.insert("blueprint".into(), overridden["blueprint"].clone());
        }
        if let Some(uid) = user_id(ca) {
            existing.insert("updatedBy".into(), JValue::Str(uid));
            existing.insert("updatedAt".into(), clock.value());
        }
        self.replace(&existing, Some(clock), Some(raw)).await?;
        Ok(existing)
    }

    /// `updateBlueprint`: only the plan (and the version and `updatedAt`) of the stored
    /// document, authorized on the stored codes. Answers the stored document as saved.
    pub async fn update_blueprint(&self, ca: &ContextAuthentication, id: &str, blueprint: Option<JMap>) -> AppResult<JMap> {
        let clock = Clock::now();
        if id.trim().is_empty() {
            return Err(self.forbidden_permission(ca));
        }
        let (mut stored, raw) = self.find_raw(id).await?.ok_or_else(|| self.forbidden_permission(ca))?;
        let allowed = self
            .access_check(ca, Method::Update, str_field(&stored, "appCode"), str_field(&stored, "clientCode"), true)
            .await?;
        if !allowed {
            return Err(self.forbidden_permission(ca));
        }
        stored.insert("blueprint".into(), blueprint.map(JValue::Object).unwrap_or_default());
        stored.insert("version".into(), JValue::Int(version_of(&stored) + 1));
        stored.insert("updatedAt".into(), clock.value());
        self.replace(&stored, Some(&clock), Some(&raw)).await?;
        self.evict_recursively_of(&stored).await?;
        Ok(stored)
    }

    /// `delete`: refused while any client overrides the object (403), and for a caller
    /// without delete access (404). Evicts the deleting client's cached copies and the list
    /// cache, and the object's draft goes with it.
    pub async fn delete(&self, ca: &ContextAuthentication, id: &str) -> AppResult<bool> {
        let read_first = match self.kind().delete_reads_first() {
            true => Some(self.read(ca, id).await?),
            false => None,
        };
        let stored = self.find_by_id(id).await?.ok_or_else(|| self.not_found(id))?;
        self.kind().before_delete(self.commons(), ca, read_first.as_ref().unwrap_or(&stored)).await?;
        let (app, client, name) = (str_field(&stored, "appCode"), str_field(&stored, "clientCode"), str_field(&stored, "name"));
        let opt = |s: Option<&str>| s.map(|v| Bson::String(v.to_string())).unwrap_or(Bson::Null);
        let count = self
            .commons()
            .backend()
            .count(self.collection(), doc! {"name": opt(name), "appCode": opt(app), "baseClientCode": opt(client)})
            .await?;
        if !self.access_check(ca, Method::Delete, app, client, true).await? {
            return Err(self.commons().messages.refusal(ca, StatusCode::NOT_FOUND, msg::UNABLE_TO_DELETE, &[self.object_name(), id]));
        }
        if count > 0 {
            let m = &self.commons().messages;
            return Err(m.error_as("DEF.DELETE_BLOCKED_BY_OVERRIDES", StatusCode::FORBIDDEN, msg::UNABLE_TO_DELETE, &[self.object_name(), id]));
        }
        self.commons().backend().delete_one(self.collection(), Store::id_filter(id)).await?;
        let (app, client, name) = (jstr(app), jstr(client), jstr(name));
        let cx = self.commons();
        cx.evict(&self.cache_name(app, name, false), client).await;
        cx.evict(&self.cache_name(app, name, true), client).await;
        cx.evict_all(&self.read_page_cache_name(app)).await;
        cx.drafts.discard(&self.object_type(), app, name, client).await?;
        self.kind().after_delete(cx, read_first.as_ref().unwrap_or(&stored), true).await
    }

    // ── Evictions ────────────────────────────────────────────────

    async fn evict_recursively_of(&self, e: &JMap) -> AppResult<()> {
        self.evict_recursively(jstr(str_field(e, "appCode")), jstr(str_field(e, "clientCode")), jstr(str_field(e, "name"))).await
    }

    /// `evictRecursively`: both surfaces of the object, and the app's list cache.
    pub async fn evict_recursively(&self, app: &str, client: &str, name: &str) -> AppResult<()> {
        let cx = self.commons();
        cx.evict_all(&self.cache_name(app, name, false)).await;
        cx.evict_all(&self.cache_name(app, name, true)).await;
        cx.evict_all(&self.read_page_cache_name(app)).await;
        self.kind().after_evict_recursively(cx, app, client, name).await
    }

    /// `evictDraft`: the draft surface of the object.
    pub async fn evict_draft(&self, app: &str, client: &str, name: &str) -> AppResult<()> {
        let cx = self.commons();
        cx.evict_all(&self.cache_name(app, name, true)).await;
        self.kind().after_evict_draft(cx, app, client, name).await
    }

    // ── Whole apps and forks ─────────────────────────────────────

    /// `createForClient`: a live derived copy of `id` for `client`; `None` for an unknown id
    /// (Java answers an empty 200).
    pub async fn create_for_client(&self, ca: &ContextAuthentication, id: &str, client: &str) -> AppResult<Option<JMap>> {
        match self.read_internal(id).await? {
            Some(merged) => Ok(Some(self.fork_from(ca, merged, client, None).await?)),
            None => Ok(None),
        }
    }

    /// `forkForClient`: a never-published derived copy of `base`, seeded with its merged
    /// content so the stored delta is against the whole chain.
    pub async fn fork_for_client(&self, ca: &ContextAuthentication, base: &JMap, client: &str) -> AppResult<Option<JMap>> {
        let id = str_field(base, "id").unwrap_or_default();
        match self.read_internal(id).await? {
            Some(merged) => Ok(Some(self.fork_from(ca, merged, client, Some(false)).await?)),
            None => Ok(None),
        }
    }

    /// `forkFrom`: the resolved object re-homed on `client`, version 1, created afresh.
    async fn fork_from(&self, ca: &ContextAuthentication, mut resolved: JMap, client: &str, published: Option<bool>) -> AppResult<JMap> {
        let base_client = resolved.get("clientCode").cloned().unwrap_or_default();
        resolved.insert("baseClientCode".into(), base_client);
        resolved.insert("clientCode".into(), JValue::Str(client.to_string()));
        resolved.insert("published".into(), published.map(JValue::Bool).unwrap_or_default());
        resolved.insert("version".into(), JValue::Int(1));
        resolved.insert("id".into(), JValue::Null);
        self.create(ca, resolved).await
    }

    /// `updatedBaseAppCode`: re-points `baseAppCode` on every object of `client` in `app`.
    pub async fn updated_base_app_code(&self, ca: &ContextAuthentication, app: &str, new_base_app: &str, client: &str) -> AppResult<bool> {
        let a = self.access_check(ca, Method::Update, Some(app), Some(client), true).await?;
        let b = self.access_check(ca, Method::Update, Some(new_base_app), Some(client), true).await?;
        if !a || !b {
            return Ok(false);
        }
        let filter = doc! {"$and": [{"appCode": app}, {"clientCode": client}, {"baseAppCode": {"$exists": true}}]};
        self.commons().backend().update_many(self.collection(), filter, doc! {"baseAppCode": new_base_app}).await?;
        Ok(true)
    }

    /// `deleteEverything`: every object, version and draft of this type that `client` has in
    /// `app`. `None` when the client has no write access to the app (Java's empty Mono).
    pub async fn delete_everything(&self, _ca: &ContextAuthentication, app: &str, client: &str) -> AppResult<Option<bool>> {
        let cx = self.commons();
        cx.store.inheritance_order(app, client, client).await?;
        if !cx.directory().has_write_access(app, client).await? {
            return Ok(None);
        }
        let filter = doc! {"appCode": app, "clientCode": client};
        let docs = cx.backend().find(self.collection(), crate::backend::Find::new(filter.clone())).await?;
        let names: Vec<String> = docs.iter().filter_map(|d| d.get_str("name").ok().map(str::to_string)).collect();
        cx.backend().delete_many(self.collection(), filter).await?;
        cx.versions.delete_by(app, client, &self.object_type()).await?;
        cx.drafts.delete_by(app, &self.object_type(), client).await?;
        cx.evict_all(&self.read_page_cache_name(app)).await;
        for n in &names {
            cx.evict_all(&self.cache_name(app, n, false)).await;
            cx.evict_all(&self.cache_name(app, n, true)).await;
        }
        self.kind().after_delete_everything(cx, app, client).await?;
        Ok(Some(true))
    }
}
