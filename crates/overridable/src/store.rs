//! The read path of `AbstractOverridableDataService` on MongoDB, generic over the document
//! class.
//!
//! An object is identified by `(appCode, name)` and exists once per client that has its own
//! copy. A read for a client:
//! 1. asks security for the app's inheritance order for that client (`appInheritance`, root
//!    first, cached as `inheritanceOrder`);
//! 2. fetches every copy of the object whose `clientCode` is in that order, drops the
//!    never-published ones (live surface only), and keeps the most derived;
//! 3. on the draft surface, substitutes that client's own draft, reconciled onto live;
//! 4. otherwise merges the document down its `baseClientCode` chain (each copy stores only its
//!    difference from its base);
//! 5. clones the result the way the Java copy constructors do, and caches it per client under
//!    the Java cache name (`PageCache_<app>_<name>`, `..._DRAFT`), so the Java services'
//!    evictions on save reach this cache too.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use mongodb::bson::{doc, oid::ObjectId, Bson, Document};
use mongodb::options::{ClientOptions, ServerAddress};
use mongodb::{Client, Database};
use platform::cache::{CacheService, LocalCaches};
use platform::security::{ContextAuthentication, SecurityClient};
use platform::upstream::Upstream;
use sha2::{Digest, Sha256};

use crate::backend::{Backend, Directory, Find, MongoBackend, RemoteDirectory};
use crate::bson_conv;
use crate::difference::apply_map;
use crate::json::{JMap, JValue};
use crate::pojo::{self, clone_pojo, convert_json, decode_bson, map_field, str_field, Pojo};
use crate::three_way;

/// One overridable document class (`Page`, `Application`, `UIFunction`, ...).
pub trait DocType: Send + Sync + 'static {
    /// `getObjectName()`: `Page`, `Application`, `Theme`, `Function`, ...
    fn object_name(&self) -> &'static str;
    /// The Mongo collection.
    fn collection(&self) -> &'static str;
    fn pojo(&self) -> &'static Pojo;
    /// `getCacheName(appCode, name)` of the Java service.
    fn cache_name(&self, app_code: &str, name: &str) -> String {
        format!("{}Cache_{}_{}", self.object_name(), app_code, name)
    }
    /// `isDraftable()`.
    fn draftable(&self) -> bool {
        true
    }
    /// The class's own `applyOverride(base)` with a base present. `None` is Java's empty Mono
    /// (only the classes that use `flatMapMono` over a merge that can be empty produce it).
    fn apply_override(&self, this: JMap, base: &JMap) -> Option<JMap>;
    /// The class's own `extractDifference(base)`: what `this` changes relative to `base`.
    /// The default is a class whose content is not diffed (`Style`, `Personalization`).
    fn extract_difference(&self, this: JMap, _base: &JMap) -> Option<JMap> {
        Some(this)
    }
}

/// `AbstractOverridableDTO.applyActualOverride(base)`.
pub fn apply_actual_override(dt: &dyn DocType, mut this: JMap, base: Option<&JMap>) -> Option<JMap> {
    let Some(base) = base else {
        return Some(this);
    };
    for f in ["description", "title"] {
        if this.get(f).is_none_or(JValue::is_null) {
            let v = base.get(f).cloned().unwrap_or(JValue::Null);
            this.insert(f.to_string(), v);
        }
    }
    let bp = apply_map(map_field(&this, "blueprint"), map_field(base, "blueprint"));
    pojo::set_opt_map(&mut this, "blueprint", bp);
    dt.apply_override(this, base)
}

/// `AbstractOverridableDTO.makeActualOverride(base)`: the override to store for `this` over
/// `base` (description and title dropped when inherited, the plan diffed key by key).
pub fn make_actual_override(dt: &dyn DocType, mut this: JMap, base: Option<&JMap>) -> Option<JMap> {
    let Some(base) = base else {
        return Some(this);
    };
    for f in ["description", "title"] {
        if this.get(f).is_some_and(|v| !v.is_null()) && this.get(f) == base.get(f) {
            this.insert(f.to_string(), JValue::Null);
        }
    }
    let bp = crate::difference::extract_map(map_field(&this, "blueprint"), map_field(base, "blueprint"));
    this.insert("blueprint".into(), JValue::Object(bp));
    dt.extract_difference(this, base)
}

/// A draft brought onto live (`AbstractOverridableDataService.Reconciled`): the content to
/// serve or publish, and the account of the reconciliation, `None` when the draft was taken
/// from the current live version.
#[derive(Debug, Clone)]
pub struct Reconciled {
    pub entity: JMap,
    pub note: Option<String>,
}

/// Conflicting paths named in the publish message before it turns into a count.
const RECONCILE_CONFLICTS_SHOWN: usize = 5;

/// `mergeOnto`'s note: `[reconciled from v1 onto live v2; draft kept over live at a, b and 3 more]`.
pub fn reconcile_note(base_version: i64, live_version: i64, conflicts: &[String]) -> String {
    let mut note = format!("[reconciled from v{base_version} onto live v{live_version}");
    if !conflicts.is_empty() {
        let shown = &conflicts[..conflicts.len().min(RECONCILE_CONFLICTS_SHOWN)];
        note.push_str("; draft kept over live at ");
        note.push_str(&shown.join(", "));
        if conflicts.len() > shown.len() {
            note.push_str(&format!(" and {} more", conflicts.len() - shown.len()));
        }
    }
    note.push(']');
    note
}

/// A resolved object: the cloned, merged document and the id its ETags are built from.
#[derive(Debug)]
pub struct Resolved {
    pub entity: JMap,
    pub unique_id: String,
}

/// The fields a reconciliation never merges (`RECONCILE_IGNORED_ROOT_KEYS`).
const RECONCILE_IGNORED: &[&str] = &[
    "id", "_id", "_class", "version", "createdAt", "createdBy", "updatedAt", "updatedBy", "published", "message",
    "name", "appCode", "clientCode", "baseClientCode",
];

/// The longest `baseClientCode` chain followed. Java follows it without a bound, so a cycle
/// would never finish there.
const MAX_CHAIN: usize = 32;

/// `MAX_BASE_HOPS`: the most missing levels one base lookup walks past.
const MAX_BASE_HOPS: usize = 16;

const SYSTEM_CLIENT_CODE: &str = "SYSTEM";

const CACHE_INHERITANCE_ORDER: &str = "inheritanceOrder";
const DRAFT_SUFFIX: &str = "_DRAFT";

#[derive(Clone)]
pub struct Store {
    inner: Arc<Inner>,
}

struct Inner {
    db: Database,
    security: SecurityClient,
    backend: Arc<dyn Backend>,
    directory: Arc<dyn Directory>,
    inheritance: Arc<LocalCaches<String, Arc<Vec<String>>>>,
    defs: Arc<LocalCaches<String, Arc<Resolved>>>,
}

/// A database handle that points at nothing, for a store whose documents live elsewhere.
/// Creating it needs a Tokio runtime (the driver starts its monitor) but never connects.
fn detached_database() -> Result<Database> {
    let opts = ClientOptions::builder()
        .hosts(vec![ServerAddress::Tcp { host: "127.0.0.1".into(), port: Some(9) }])
        .server_selection_timeout(Duration::from_millis(50))
        .build();
    Ok(Client::with_options(opts)?.database("detached"))
}

impl Store {
    /// The production store: documents in `db`, access decided by security.
    pub fn new(db: Database, security: SecurityClient, cache: &CacheService) -> Self {
        let backend: Arc<dyn Backend> = Arc::new(MongoBackend::new(db.clone()));
        let directory: Arc<dyn Directory> = Arc::new(RemoteDirectory::new(security.clone(), cache));
        Self::assemble(db, security, backend, directory, cache)
    }

    /// A store on other parts (tests: [`crate::backend::MemBackend`] and
    /// [`crate::backend::FakeDirectory`]). Its [`Self::db`] and [`Self::security`] are handles
    /// that reach nothing; everything this crate does goes through `backend` and `directory`.
    pub fn with_parts(backend: Arc<dyn Backend>, directory: Arc<dyn Directory>, cache: &CacheService) -> Result<Self> {
        let db = detached_database()?;
        let security = SecurityClient::new(Upstream::fixed(&["http://127.0.0.1:9"]), 0)?;
        Ok(Self::assemble(db, security, backend, directory, cache))
    }

    fn assemble(db: Database, security: SecurityClient, backend: Arc<dyn Backend>, directory: Arc<dyn Directory>, cache: &CacheService) -> Self {
        Self {
            inner: Arc::new(Inner {
                db,
                security,
                backend,
                directory,
                inheritance: cache.family(),
                defs: cache.family(),
            }),
        }
    }

    pub fn db(&self) -> &Database {
        &self.inner.db
    }

    pub fn security(&self) -> &SecurityClient {
        &self.inner.security
    }

    /// Where the documents are read and written.
    pub fn backend(&self) -> &Arc<dyn Backend> {
        &self.inner.backend
    }

    /// Who answers the access questions.
    pub fn directory(&self) -> &Arc<dyn Directory> {
        &self.inner.directory
    }

    /// `InheritanceService.order`: cached under `inheritanceOrder`, key `app:urlClient:client`.
    pub async fn inheritance_order(&self, app_code: &str, url_client_code: &str, client_code: &str) -> Result<Arc<Vec<String>>> {
        let key = format!("{app_code}:{url_client_code}:{client_code}");
        let dir = self.inner.directory.clone();
        let (a, u, c) = (app_code.to_string(), url_client_code.to_string(), client_code.to_string());
        let v = self
            .inner
            .inheritance
            .get_or_load(CACHE_INHERITANCE_ORDER, key, || async move {
                Ok::<_, anyhow::Error>(Some(Arc::new(dir.app_inheritance(&a, &u, &c).await?)))
            })
            .await?;
        Ok(v.unwrap_or_default())
    }

    /// `readOrder`: the clients a read looks through, base first: the app inheritance order
    /// with the reading client's managing chain ([`Self::base_client_code_of`] repeatedly)
    /// added just below the client itself, so a client with no copy of its own is served its
    /// managing client's customization, as a copy of its own would merge onto it.
    pub async fn read_order(&self, app_code: &str, url_client_code: &str, client_code: &str) -> Result<Arc<Vec<String>>> {
        let order = self.inheritance_order(app_code, url_client_code, client_code).await?;
        let chain = self.managing_chain(app_code, client_code).await;
        let Some(last) = order.last().filter(|_| !chain.is_empty()) else {
            return Ok(order);
        };
        let mut merged: Vec<String> = order[..order.len() - 1].to_vec();
        for c in chain.iter().rev() {
            if !merged.contains(c) && c != last {
                merged.push(c.clone());
            }
        }
        merged.push(last.clone());
        Ok(Arc::new(merged))
    }

    /// `managingChain`: `baseClientCodeOf` repeatedly, nearest first, stopping at the app owner,
    /// a repeat, [`MAX_BASE_HOPS`] or a failed lookup (what was found so far is kept).
    async fn managing_chain(&self, app_code: &str, client_code: &str) -> Vec<String> {
        let mut acc: Vec<String> = Vec::new();
        let mut current = client_code.to_string();
        for _ in 0..=MAX_BASE_HOPS {
            if current.trim().is_empty() {
                break;
            }
            match self.base_client_code_of(app_code, &current).await {
                Ok(Some(next)) if next != current && !acc.contains(&next) => {
                    acc.push(next.clone());
                    current = next;
                }
                _ => break,
            }
        }
        acc
    }

    pub async fn find_docs(&self, collection: &str, filter: Document) -> Result<Vec<Document>> {
        self.inner.backend.find(collection, Find::new(filter)).await
    }

    pub async fn find_doc(&self, collection: &str, filter: Document) -> Result<Option<Document>> {
        self.inner.backend.find_one(collection, filter, None).await
    }

    /// `findById`: a 24-hex id is an ObjectId, as Spring Data converts it.
    pub fn id_filter(id: &str) -> Document {
        match ObjectId::parse_str(id) {
            Ok(oid) => doc! {"_id": oid},
            Err(_) => doc! {"_id": id},
        }
    }

    pub async fn find_by_id(&self, dt: &dyn DocType, id: &str) -> Result<Option<JMap>> {
        Ok(self
            .find_doc(dt.collection(), Self::id_filter(id))
            .await?
            .map(|d| decode_bson(dt.pojo(), &d)))
    }

    /// `findOneByNameAndAppCodeAndClientCode`.
    pub async fn find_one_by(&self, dt: &dyn DocType, name: &JValue, app_code: &JValue, client_code: &str) -> Result<Option<JMap>> {
        let filter = doc! {
            "name": bson_conv::from_j(name),
            "appCode": bson_conv::from_j(app_code),
            "clientCode": client_code,
        };
        Ok(self.find_doc(dt.collection(), filter).await?.map(|d| decode_bson(dt.pojo(), &d)))
    }

    /// `getMergedSources`: everything below `entity` in its base chain, merged, excluding it.
    pub async fn merged_sources(&self, dt: &dyn DocType, entity: &JMap) -> Result<Option<JMap>> {
        if str_field(entity, "baseClientCode").is_none() {
            return Ok(None);
        }
        let mut chain = vec![entity.clone()];
        while chain.len() < MAX_CHAIN {
            let last = chain.last().expect("chain is never empty");
            let Some(base_cc) = str_field(last, "baseClientCode").map(str::to_string) else {
                break;
            };
            let name = last.get("name").cloned().unwrap_or_default();
            let app = last.get("appCode").cloned().unwrap_or_default();
            match self.base_document(dt, &name, &app, base_cc).await? {
                Some(next) => chain.push(next),
                None => break,
            }
        }
        if chain.len() == 1 {
            return Ok(None);
        }
        let mut current = chain.pop();
        while chain.len() > 1 {
            let next = chain.pop().expect("checked above");
            current = match current {
                Some(base) => apply_actual_override(dt, next, Some(&base)),
                None => None,
            };
        }
        Ok(current)
    }

    /// `baseDocument`: the document a derived one stands on, the base client's own copy or, when
    /// that client has none, the copy its own base would have ([`Self::base_client_code_of`]).
    /// Hops stop at the app owner, or after [`MAX_BASE_HOPS`] as a guard against a cycle.
    async fn base_document(&self, dt: &dyn DocType, name: &JValue, app_code: &JValue, base_client_code: String) -> Result<Option<JMap>> {
        let mut base = base_client_code;
        for _ in 0..=MAX_BASE_HOPS {
            if base.trim().is_empty() {
                return Ok(None);
            }
            if let Some(found) = self.find_one_by(dt, name, app_code, &base).await? {
                return Ok(Some(found));
            }
            let Some(app) = app_code.as_str() else { return Ok(None) };
            match self.base_client_code_of(app, &base).await? {
                Some(next) if next != base => base = next,
                _ => return Ok(None),
            }
        }
        Ok(None)
    }

    /// `baseClientCodeOf`: the client a customization by `client_code` stands on, its nearest
    /// managing client, except that a client managed by SYSTEM in an app someone else owns
    /// stands on the owner. `None` for the owner itself and for an unknown app.
    pub async fn base_client_code_of(&self, app_code: &str, client_code: &str) -> Result<Option<String>> {
        let Some(app) = self.inner.directory.app_explicit_info(app_code).await? else {
            return Ok(None);
        };
        let owner = app.client_code.unwrap_or_default();
        if owner == client_code {
            return Ok(None);
        }
        let hierarchy = self.inner.directory.client_hierarchy_codes(client_code).await?;
        match hierarchy.get(1) {
            Some(managing) if !(managing == SYSTEM_CLIENT_CODE && !owner.is_empty()) => Ok(Some(managing.clone())),
            _ => Ok((!owner.is_empty() && owner != client_code).then_some(owner)),
        }
    }

    /// `servedClientCode` (Java commit e2b7d48aa): the client whose copy a read serves.
    ///
    /// The browser names no client, so the gateway sends the host's: on a shared host every
    /// signed-in tenant was served the host's objects. When the client asked for is the URL's
    /// (the host's) and the caller is signed in to a client the host manages, which can read the
    /// app, the read is for the caller's client: its copy, else its managing chain's, else the
    /// host's ([`Self::read_order`]). Anonymous reads, the host's own users, a client named on
    /// purpose and a host that does not manage the caller's client are read as asked. A failed
    /// lookup reads as asked too.
    pub async fn served_client_code(&self, ca: Option<&ContextAuthentication>, app_code: &str, client_code: &str) -> String {
        let asked = || client_code.to_string();
        let Some(ca) = ca else { return asked() };
        let signed_in = ca.client_code();
        if client_code.trim().is_empty()
            || app_code.trim().is_empty()
            || !ca.authenticated
            || signed_in.trim().is_empty()
            || signed_in == client_code
            || ca.url_client_code.as_deref() != Some(client_code)
        {
            return asked();
        }
        let dir = &self.inner.directory;
        // The hierarchy is the client itself first, then its managers up to SYSTEM.
        let (line, read) = futures::join!(dir.client_hierarchy_codes(signed_in), dir.has_read_access(app_code, signed_in));
        match (line, read) {
            (Ok(line), Ok(true)) if line.iter().skip(1).any(|c| c == client_code) => signed_in.to_string(),
            _ => asked(),
        }
    }

    /// `readInternal(id)`: the stored document merged onto its base chain.
    pub async fn read_merged_by_id(&self, dt: &dyn DocType, id: &str) -> Result<Option<JMap>> {
        let Some(entity) = self.find_by_id(dt, id).await? else {
            return Ok(None);
        };
        self.merge_onto_sources(dt, entity).await
    }

    async fn merge_onto_sources(&self, dt: &dyn DocType, entity: JMap) -> Result<Option<JMap>> {
        match self.merged_sources(dt, &entity).await? {
            None => Ok(Some(entity)),
            Some(m) => Ok(apply_actual_override(dt, entity, Some(&m))),
        }
    }

    /// `readIfExistsInBase`: the most derived copy for the client along [`Self::read_order`],
    /// never-published copies left out on the live surface.
    pub async fn read_if_exists_in_base(
        &self,
        dt: &dyn DocType,
        name: &str,
        app_code: &str,
        url_client_code: &str,
        client_code: &str,
        draft: bool,
    ) -> Result<Option<JMap>> {
        let order = self.read_order(app_code, url_client_code, client_code).await?;
        let codes: Vec<Bson> = order.iter().map(|c| Bson::String(c.clone())).collect();
        let filter = doc! {"name": name, "appCode": app_code, "clientCode": {"$in": codes}};
        let list: Vec<JMap> = self
            .find_docs(dt.collection(), filter)
            .await?
            .iter()
            .map(|d| decode_bson(dt.pojo(), d))
            .filter(|e| draft || e.get("published") != Some(&JValue::Bool(false)))
            .collect();
        if list.len() <= 1 {
            return Ok(list.into_iter().next());
        }
        for cc in order.iter().rev() {
            if let Some(item) = list.iter().find(|e| str_field(e, "clientCode") == Some(cc.as_str())) {
                return Ok(Some(item.clone()));
            }
        }
        Ok(None)
    }

    /// `readDrafted`: on the draft surface, the requesting client's own draft of exactly this
    /// document, reconciled onto live; otherwise the ordinary merged read.
    pub async fn read_drafted(&self, dt: &dyn DocType, stored: &JMap, draft: bool, client_code: &str) -> Result<Option<JMap>> {
        let id = str_field(stored, "id").unwrap_or_default().to_string();
        if !draft || !dt.draftable() || str_field(stored, "clientCode") != Some(client_code) {
            return self.read_merged_by_id(dt, &id).await;
        }
        let filter = doc! {
            "objectAppCode": str_field(stored, "appCode").unwrap_or_default(),
            "objectType": dt.object_name().to_uppercase(),
            "objectName": str_field(stored, "name").unwrap_or_default(),
            "clientCode": client_code,
        };
        match self.find_doc("draft", filter).await? {
            Some(d) => Ok(Some(self.reconcile(dt, &d, stored).await?.entity)),
            None => self.read_merged_by_id(dt, &id).await,
        }
    }

    /// `reconcile(draft, stored)`: the draft content, merged three ways onto the current live
    /// document when live moved on after the draft was taken, with the note a publish appends
    /// to its message. The draft surface and publish share it, so the preview is what a
    /// publish produces.
    pub async fn reconcile(&self, dt: &dyn DocType, draft: &Document, stored: &JMap) -> Result<Reconciled> {
        let content = match draft.get("content") {
            Some(Bson::Document(c)) => bson_conv::doc_to_j(c),
            _ => JMap::new(),
        };
        let base_version = draft.get("baseVersion").map(|b| bson_conv::to_j(b).as_i64().unwrap_or(0)).unwrap_or(0);
        let stored_version = stored.get("version").and_then(JValue::as_i64).unwrap_or(1);

        let mut draft_entity = convert_json(dt.pojo(), &content);
        stamp_from_stored(&mut draft_entity, stored);
        draft_entity.insert("version".into(), JValue::Int(base_version));
        let unreconciled = |entity: JMap| Reconciled { entity, note: None };
        if stored_version == base_version {
            return Ok(unreconciled(draft_entity));
        }

        let filter = doc! {
            "objectType": dt.object_name().to_uppercase(),
            "objectAppCode": str_field(stored, "appCode").unwrap_or_default(),
            "objectName": str_field(stored, "name").unwrap_or_default(),
            "clientCode": str_field(stored, "clientCode").unwrap_or_default(),
            "versionNumber": base_version,
        };
        let version = self.inner.backend.find_one("version", filter, Some(doc! {"createdAt": -1})).await?;
        let base = match version.as_ref().and_then(|v| v.get("object")) {
            Some(Bson::Document(o)) => bson_conv::doc_to_j(o),
            _ => return Ok(unreconciled(draft_entity)),
        };
        let id = str_field(stored, "id").unwrap_or_default().to_string();
        let Some(live) = self.read_merged_by_id(dt, &id).await? else {
            return Ok(unreconciled(draft_entity));
        };
        let live_map = pojo::to_jackson(dt.pojo(), &live);
        let ignored: HashSet<&str> = RECONCILE_IGNORED.iter().copied().collect();
        let merged = three_way::merge(Some(&base), Some(&live_map), Some(&content), &ignored);
        let mut entity = convert_json(dt.pojo(), &merged.merged);
        stamp_from_stored(&mut entity, stored);
        entity.insert("version".into(), JValue::Int(stored_version));
        let note = reconcile_note(base_version, stored_version, &merged.conflicts);
        Ok(Reconciled { entity, note: Some(note) })
    }

    /// The read of `readInternal(name, appCode, urlClientCode, clientCode)` up to, not
    /// including, the class's `applyChange`.
    pub async fn read(
        &self,
        dt: &dyn DocType,
        name: &str,
        app_code: &str,
        url_client_code: &str,
        client_code: &str,
        draft: bool,
    ) -> Result<Option<Arc<Resolved>>> {
        let mut cache = dt.cache_name(app_code, name);
        if draft {
            cache.push_str(DRAFT_SUFFIX);
        }
        self.inner
            .defs
            .get_or_load(&cache, client_code.to_string(), || async {
                tracing::debug!(cache = cache.as_str(), client_code, "definition cache miss");
                let Some(stored) = self
                    .read_if_exists_in_base(dt, name, app_code, url_client_code, client_code, draft)
                    .await?
                else {
                    return Ok::<_, anyhow::Error>(None);
                };
                let Some(merged) = self.read_drafted(dt, &stored, draft, client_code).await? else {
                    return Ok(None);
                };
                Ok(Some(Arc::new(resolve(dt.pojo(), &merged))))
            })
            .await
    }
}

/// Clones `merged` as the copy constructor would and gives it a content id.
pub fn resolve(pojo: &Pojo, merged: &JMap) -> Resolved {
    let entity = clone_pojo(pojo, merged);
    let unique_id = unique_id(&entity);
    Resolved { entity, unique_id }
}

/// The id ETags are made from: a digest of the content, so every Rust instance gives the same
/// object the same id and it changes exactly when the content does. (Java draws a random one
/// each time its cache is filled.) Base62, 22 characters, like Java's `shortUUID`.
pub fn unique_id(entity: &JMap) -> String {
    let digest = Sha256::digest(crate::json::map_to_compact(entity).as_bytes());
    let mut n = u128::from_be_bytes(digest[..16].try_into().expect("16 bytes"));
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut out = Vec::with_capacity(22);
    for _ in 0..22 {
        out.push(ALPHABET[(n % 62) as usize]);
        n /= 62;
    }
    out.reverse();
    String::from_utf8(out).unwrap_or_default()
}

/// `stampFromStored`: identity and bookkeeping from the stored document.
pub fn stamp_from_stored(entity: &mut JMap, stored: &JMap) {
    for f in [
        "id", "appCode", "clientCode", "name", "baseClientCode", "published", "message", "createdAt", "createdBy",
        "updatedAt", "updatedBy",
    ] {
        entity.insert(f.to_string(), stored.get(f).cloned().unwrap_or(JValue::Null));
    }
}

#[cfg(test)]
mod tests {
    //! The commons `AbstractOverridableDTOBlueprintTest`, and the pure parts of the store.
    use super::*;
    use crate::json::parse;
    use crate::pojo::{CloneRule, Field, Kind, OVERRIDABLE_BASE};

    /// `AbstractOverridableDTOBlueprintTest.Thing`: the base class and nothing else.
    struct Thing;
    const THING: Pojo = Pojo { name: "Thing", parts: &[OVERRIDABLE_BASE, &[Field::new("x", Kind::Str, CloneRule::Copy)]] };
    impl DocType for Thing {
        fn object_name(&self) -> &'static str {
            "Thing"
        }
        fn collection(&self) -> &'static str {
            "thing"
        }
        fn pojo(&self) -> &'static Pojo {
            &THING
        }
        fn apply_override(&self, this: JMap, _base: &JMap) -> Option<JMap> {
            Some(this)
        }
    }

    fn obj(s: &str) -> JMap {
        match parse(s.as_bytes()).unwrap() {
            JValue::Object(m) => m,
            _ => panic!(),
        }
    }

    fn plan(sections: &str) -> JMap {
        obj(&format!(r#"{{"blueprint":{{"plan":{{"sections":{sections}}}}}}}"#))
    }

    fn sections(m: &JMap) -> &JMap {
        m["blueprint"].as_object().unwrap()["plan"].as_object().unwrap()["sections"].as_object().unwrap()
    }

    #[test]
    fn override_keeps_the_entries_the_tenant_did_not_touch() {
        let base = plan(r#"{"aHero":{"order":1000,"purpose":"Base hero"},"aForm":{"order":2000,"purpose":"Base form"}}"#);
        let tenant = plan(r#"{"aHero":{"order":1000,"purpose":"Tenant hero"}}"#);
        let t = apply_actual_override(&Thing, tenant, Some(&base)).unwrap();
        let merged = sections(&t);
        assert_eq!(merged.len(), 2, "the untouched base entry must survive");
        assert_eq!(merged["aHero"].as_object().unwrap()["purpose"], JValue::Str("Tenant hero".into()));
        assert_eq!(merged["aForm"].as_object().unwrap()["purpose"], JValue::Str("Base form".into()));
    }

    #[test]
    fn extracting_an_override_carries_only_what_changed() {
        let base = plan(r#"{"aHero":{"order":1000,"purpose":"Base hero"},"aForm":{"order":2000,"purpose":"Base form"}}"#);
        let edited = plan(r#"{"aHero":{"order":1000,"purpose":"Tenant hero"},"aForm":{"order":2000,"purpose":"Base form"}}"#);
        let t = make_actual_override(&Thing, edited, Some(&base)).unwrap();
        let diff = sections(&t);
        assert!(diff.contains_key("aHero"), "the changed entry belongs in the override");
        assert!(
            !diff.contains_key("aForm") || diff["aForm"].is_null() || diff["aForm"].as_object().is_some_and(|m| m.is_empty()),
            "the unchanged entry must not be copied into the override"
        );
    }

    #[test]
    fn an_object_with_no_plan_stays_an_object_with_no_plan() {
        let t = apply_actual_override(&Thing, JMap::new(), Some(&JMap::new())).unwrap();
        assert!(t["blueprint"].is_null());
    }

    #[test]
    fn a_tenant_with_no_plan_inherits_the_base_plan() {
        let base = plan(r#"{"aHero":{"order":1000,"purpose":"Base hero"}}"#);
        let t = apply_actual_override(&Thing, JMap::new(), Some(&base)).unwrap();
        assert_eq!(sections(&t).len(), 1);
    }

    #[test]
    fn clone_carries_the_blueprint_and_deep_copies_it() {
        let mut original = plan(r#"{"aHero":{"order":1000,"purpose":"Base hero"}}"#);
        original.insert("name".into(), JValue::Str("thing".into()));
        let copy = crate::pojo::clone_pojo(&THING, &original);
        assert_eq!(sections(&copy)["aHero"].as_object().unwrap()["purpose"], JValue::Str("Base hero".into()));
        // Values, not references: a later edit to the original does not reach the copy.
        original["blueprint"].as_object_mut().unwrap()["plan"].as_object_mut().unwrap()["sections"]
            .as_object_mut()
            .unwrap()
            .insert("aLater".into(), JValue::Null);
        assert_eq!(sections(&copy).len(), 1, "the copy must not see a later edit");
    }

    #[test]
    fn description_and_title_inherit_and_are_dropped_when_unchanged() {
        let base = obj(r#"{"description":"d","title":"t"}"#);
        let t = apply_actual_override(&Thing, JMap::new(), Some(&base)).unwrap();
        assert_eq!(t["description"], JValue::Str("d".into()));
        let t = make_actual_override(&Thing, obj(r#"{"description":"d","title":"mine"}"#), Some(&base)).unwrap();
        assert!(t["description"].is_null());
        assert_eq!(t["title"], JValue::Str("mine".into()));
        assert!(make_actual_override(&Thing, JMap::new(), None).is_some());
        assert!(apply_actual_override(&Thing, JMap::new(), None).is_some());
        assert!(Thing.extract_difference(JMap::new(), &JMap::new()).is_some());
        assert_eq!(Thing.cache_name("app", "n"), "ThingCache_app_n");
        assert!(Thing.draftable());
        assert_eq!(Thing.collection(), "thing");
    }

    #[test]
    fn ids_are_content_digests() {
        let a = resolve(&THING, &obj(r#"{"name":"a"}"#));
        let b = resolve(&THING, &obj(r#"{"name":"a"}"#));
        let c = resolve(&THING, &obj(r#"{"name":"b"}"#));
        assert_eq!(a.unique_id, b.unique_id);
        assert_ne!(a.unique_id, c.unique_id);
        assert_eq!(a.unique_id.len(), 22);
        assert!(a.unique_id.chars().all(|ch| ch.is_ascii_alphanumeric()));
        assert!(format!("{a:?}").contains("unique_id"));
    }

    #[test]
    fn ids_filter_like_spring_data() {
        assert!(matches!(Store::id_filter("63bd2d154d18a31536e81fa5").get("_id"), Some(Bson::ObjectId(_))));
        assert!(matches!(Store::id_filter("not-an-oid").get("_id"), Some(Bson::String(_))));
    }

    #[test]
    fn stamping_takes_identity_from_the_stored_document() {
        let mut e = obj(r#"{"id":"x","name":"evil","appCode":"other","version":9}"#);
        let stored = obj(r#"{"id":"1","name":"page","appCode":"app","clientCode":"C","createdAt":5}"#);
        stamp_from_stored(&mut e, &stored);
        assert_eq!(e["id"], JValue::Str("1".into()));
        assert_eq!(e["name"], JValue::Str("page".into()));
        assert_eq!(e["appCode"], JValue::Str("app".into()));
        assert_eq!(e["published"], JValue::Null);
        assert_eq!(e["version"], JValue::Int(9), "the version is the caller's to set");
    }
}
