//! The admin purge (Rust only, no Java counterpart): every ui trace of a dead client or of an
//! app, for every client. A client's purge deletes every `ui` document whose `clientCode` is
//! the client; an app's every document whose `appCode` (versions and drafts: `objectAppCode`)
//! is the app, whoever owns it; every collection, listed at run time. The ui has no tenant
//! data, so `mysql` and `dropped` stay empty. A dry run (the default) counts what a real run
//! deletes; the report has the same shape either way. core's half is
//! `DELETE /api/core/purge/...` (the same rules).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use futures::TryStreamExt;
use mongodb::bson::{doc, Document};
use overridable::backend::{Backend, Find};
use overridable::write::{Kind, OverridableService};
use overridable::{JMap, JValue};

use crate::editor::kinds::{APPLICATION_OUI, PAGE_OUI, STYLE_OUI, THEME_OUI};
use crate::editor::routes::EditorState;

pub const CLIENT_DELETE: &str = "Authorities.Client_DELETE";
pub const APPLICATION_DELETE: &str = "Authorities.Application_DELETE";

/// What is being purged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Client(String),
    App(String),
}

impl Target {
    /// A client code: letters and digits only, never SYSTEM.
    pub fn client(code: &str) -> Result<Target, String> {
        if code.is_empty() || !code.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(format!("Not a client code: '{code}'"));
        }
        if code.eq_ignore_ascii_case("SYSTEM") {
            return Err("The SYSTEM client cannot be purged".into());
        }
        Ok(Target::Client(code.to_string()))
    }

    /// An app code: letters, digits and (rarely) `_`, with at least one letter or digit.
    pub fn app(code: &str) -> Result<Target, String> {
        let chars_ok = code.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
        if !chars_ok || !code.bytes().any(|b| b.is_ascii_alphanumeric()) {
            return Err(format!("Not an app code: '{code}'"));
        }
        Ok(Target::App(code.to_string()))
    }

    /// The documents of the target in any collection (versions and drafts key the app by
    /// `objectAppCode`).
    pub fn doc_filter(&self) -> Document {
        match self {
            Target::Client(c) => doc! {"clientCode": c},
            Target::App(a) => doc! {"$or": [{"appCode": a}, {"objectAppCode": a}]},
        }
    }
}

/// Whether one client manages another, as security's hierarchy says.
#[async_trait]
pub trait ManagedClients: Send + Sync {
    async fn manages(&self, managing: &str, client: &str) -> Result<bool>;
}

#[async_trait]
impl ManagedClients for platform::security::SecurityClient {
    async fn manages(&self, managing: &str, client: &str) -> Result<bool> {
        self.does_client_manage_client_code(managing, client).await
    }
}

/// Who may purge a client: only a client that manages it. Never the client itself, and never
/// SYSTEM, whoever asks (Kiran, 2026-10-26). Security makes the same check first, with the
/// caller's client-manager role; this one stands on its own for a call that skips multi.
pub async fn may_purge_client(guard: Option<&dyn ManagedClients>, caller_client: &str, target: &str) -> Result<bool> {
    if target.eq_ignore_ascii_case("SYSTEM") || caller_client.is_empty() || caller_client == target {
        return Ok(false);
    }
    match guard {
        Some(g) => g.manages(caller_client, target).await,
        None => Ok(false),
    }
}

/// `dryRun`: only `false` deletes anything; absent or anything else is a dry run.
pub fn dry_run(param: Option<&str>) -> bool {
    !matches!(param, Some(v) if v.trim().eq_ignore_ascii_case("false"))
}

/// What a purge matched (dry run) or deleted.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Report {
    pub dry_run: bool,
    pub mongo: BTreeMap<String, i64>,
    pub errors: Vec<String>,
}

impl Report {
    /// The shape core answers too; the ui has no MySQL rows and no tenant databases.
    pub fn to_json(&self) -> JValue {
        let mut out = JMap::new();
        out.insert("dryRun".into(), JValue::Bool(self.dry_run));
        out.insert("mongo".into(), JValue::Object(self.mongo.iter().map(|(k, v)| (k.clone(), JValue::Int(*v))).collect()));
        out.insert("mysql".into(), JValue::Object(JMap::new()));
        out.insert("dropped".into(), JValue::Array(Vec::new()));
        out.insert("errors".into(), JValue::Array(self.errors.iter().map(|s| JValue::Str(s.clone())).collect()));
        JValue::Object(out)
    }
}

/// The `ui` Mongo database as the purge sees it.
#[async_trait]
pub trait DocStore: Send + Sync {
    fn db_name(&self) -> String;
    async fn collections(&self) -> Result<Vec<String>>;
    async fn count(&self, collection: &str, filter: Document) -> Result<u64>;
    /// The matching documents' app, client and name fields, for the cache evictions.
    async fn keys(&self, collection: &str, filter: Document) -> Result<Vec<Document>>;
    async fn delete(&self, collection: &str, filter: Document) -> Result<u64>;
    /// The filter that finds `target`'s documents in `collection`; a store that can read its
    /// indexes answers one that uses them.
    async fn filter_for(&self, _collection: &str, target: &Target) -> Result<Document> {
        Ok(target.doc_filter())
    }
}

/// Collections at least this big are only read through an index. `ui.version` is 27 GB on dev,
/// and both the app filter's `$or` (only `objectAppCode` is indexed there) and a bare
/// `clientCode` scan it whole: 217 s for one app.
const SCAN_LIMIT_BYTES: f64 = 64e6;

/// The filter for one big collection, over its index on `appCode` or `objectAppCode` (the first
/// such index key): the app itself for an app purge; for a client purge, the client inside the
/// index's every app (`$in` the distinct values, missing included), so the index bounds the
/// read. A small collection, or one without such an index, keeps [`Target::doc_filter`]. A big
/// collection is assumed to keep the app under its indexed field only (true of `version`,
/// `transport` and `page`).
async fn indexed_filter(db: &mongodb::Database, collection: &str, target: &Target) -> Result<Document> {
    let stats = db.run_command(doc! {"collStats": collection}).await;
    let size = stats.ok().and_then(|s| s.get("size").and_then(|v| match v {
        mongodb::bson::Bson::Int32(n) => Some(*n as f64),
        mongodb::bson::Bson::Int64(n) => Some(*n as f64),
        mongodb::bson::Bson::Double(n) => Some(*n),
        _ => None,
    }));
    if size.is_some_and(|s| s < SCAN_LIMIT_BYTES) {
        return Ok(target.doc_filter());
    }
    let coll = db.collection::<Document>(collection);
    let mut field = None;
    let mut indexes = coll.list_indexes().await?;
    while let Some(ix) = indexes.try_next().await? {
        if let Some(first) = ix.keys.keys().next() {
            if first == "objectAppCode" || first == "appCode" {
                field = Some(first.clone());
                break;
            }
        }
    }
    let Some(field) = field else { return Ok(target.doc_filter()) };
    Ok(match target {
        Target::App(a) => doc! {field: a},
        Target::Client(c) => {
            let mut apps = coll.distinct(&field, doc! {}).await?;
            apps.push(mongodb::bson::Bson::Null);
            doc! {field: {"$in": apps}, "clientCode": c}
        }
    })
}

fn key_projection() -> Document {
    doc! {"_id": 0, "appCode": 1, "objectAppCode": 1, "clientCode": 1, "name": 1}
}

#[async_trait]
impl DocStore for mongodb::Database {
    fn db_name(&self) -> String {
        self.name().to_string()
    }
    async fn collections(&self) -> Result<Vec<String>> {
        Ok(self.list_collection_names().await?)
    }
    async fn count(&self, collection: &str, filter: Document) -> Result<u64> {
        Ok(self.collection::<Document>(collection).count_documents(filter).await?)
    }
    async fn keys(&self, collection: &str, filter: Document) -> Result<Vec<Document>> {
        let cursor = self.collection::<Document>(collection).find(filter).projection(key_projection()).await?;
        Ok(cursor.try_collect().await?)
    }
    async fn delete(&self, collection: &str, filter: Document) -> Result<u64> {
        Ok(self.collection::<Document>(collection).delete_many(filter).await?.deleted_count)
    }
    async fn filter_for(&self, collection: &str, target: &Target) -> Result<Document> {
        indexed_filter(self, collection, target).await
    }
}

/// A [`DocStore`] over an overridable backend and a fixed list of collections (the in-memory
/// store has no listing).
pub struct BackendDocs {
    pub name: String,
    pub backend: Arc<dyn Backend>,
    pub collections: Vec<String>,
}

#[async_trait]
impl DocStore for BackendDocs {
    fn db_name(&self) -> String {
        self.name.clone()
    }
    async fn collections(&self) -> Result<Vec<String>> {
        Ok(self.collections.clone())
    }
    async fn count(&self, collection: &str, filter: Document) -> Result<u64> {
        self.backend.count(collection, filter).await
    }
    async fn keys(&self, collection: &str, filter: Document) -> Result<Vec<Document>> {
        self.backend.find(collection, Find::new(filter).projection(key_projection())).await
    }
    async fn delete(&self, collection: &str, filter: Document) -> Result<u64> {
        self.backend.delete_many(collection, filter).await
    }
}

/// An overridable service's cache names, whatever its kind.
trait CacheNames: Send + Sync {
    fn collection(&self) -> &'static str;
    fn cache_name(&self, app: &str, name: &str, draft: bool) -> String;
    fn read_page_cache_name(&self, app: &str) -> String;
}

impl<K: Kind> CacheNames for OverridableService<K> {
    fn collection(&self) -> &'static str {
        OverridableService::collection(self)
    }
    fn cache_name(&self, app: &str, name: &str, draft: bool) -> String {
        OverridableService::cache_name(self, app, name, draft)
    }
    fn read_page_cache_name(&self, app: &str) -> String {
        OverridableService::read_page_cache_name(self, app)
    }
}

/// A deleted document: collection, app, client, name.
struct Deleted {
    collection: String,
    app: String,
    client: Option<String>,
    name: Option<String>,
}

fn text(d: &Document, k: &str) -> Option<String> {
    d.get_str(k).ok().filter(|s| !s.is_empty()).map(str::to_string)
}

/// Runs the purge; never fails as a whole: each failure is a line in `errors`.
pub async fn run(st: &EditorState, target: &Target, dry_run: bool) -> Report {
    let mut r = Report { dry_run, ..Default::default() };
    let Some(docs) = &st.purge else {
        r.errors.push("ui documents: no document store configured".into());
        return r;
    };
    let db = docs.db_name();
    let mut collections = match docs.collections().await {
        Ok(c) => c,
        Err(e) => {
            r.errors.push(format!("{db}: list collections: {e}"));
            return r;
        }
    };
    collections.sort();
    let mut deleted: Vec<Deleted> = Vec::new();
    for c in collections.iter().filter(|c| !c.starts_with("system.")) {
        let filter = match docs.filter_for(c, target).await {
            Ok(f) => f,
            Err(e) => {
                r.errors.push(format!("{db}.{c}: filter: {e}"));
                continue;
            }
        };
        let n = if dry_run {
            docs.count(c, filter).await
        } else {
            match docs.keys(c, filter.clone()).await {
                Ok(keys) => {
                    for k in &keys {
                        if let Some(app) = text(k, "appCode").or_else(|| text(k, "objectAppCode")) {
                            deleted.push(Deleted { collection: c.clone(), app, client: text(k, "clientCode"), name: text(k, "name") });
                        }
                    }
                    docs.delete(c, filter).await
                }
                Err(e) => Err(e),
            }
        };
        match n {
            Ok(0) => {}
            Ok(n) => *r.mongo.entry(format!("{db}.{c}")).or_default() += n as i64,
            Err(e) => r.errors.push(format!("{db}.{c}: {e}")),
        }
    }
    // Nothing deleted, nothing to evict: most purged clients have no ui documents, and a full
    // eviction per purge would keep a whole environment's caches cold for the length of a sweep.
    if !dry_run && !deleted.is_empty() {
        let mut apps: BTreeSet<String> = deleted.iter().map(|d| d.app.clone()).collect();
        if let Target::App(a) = target {
            apps.insert(a.clone());
        }
        evict(st, &apps, &deleted).await;
    }
    r
}

/// Everything cached about what went: what `DELETE /api/ui/internal/cache` drops (every cache
/// Redis knows, and the SSR caches whole), then, by name on every instance (the Rust units keep
/// caches Redis never hears of), each deleted definition's caches on both surfaces, each
/// affected app's page, OUI, index, manifest and properties caches, its URI patterns, and the
/// inheritance order.
async fn evict(st: &EditorState, apps: &BTreeSet<String>, deleted: &[Deleted]) {
    let cx = &st.cx;
    cx.cache.evict_all_caches().await;
    let message = crate::ssr::ssr_message(None, None, None, true, chrono::Utc::now().timestamp_millis());
    cx.publish(&st.ev.ssr_channel, &message).await;
    let services: [&dyn CacheNames; 8] =
        [&st.applications, &st.pages, &st.styles, &st.themes, &st.functions, &st.schemas, &st.uripaths, &st.fillers];
    let mut names: BTreeSet<String> = BTreeSet::new();
    let mut uri_keys: BTreeSet<String> = BTreeSet::new();
    for d in deleted {
        if let Some(name) = &d.name {
            for s in services.iter().filter(|s| s.collection() == d.collection) {
                names.insert(s.cache_name(&d.app, name, false));
                names.insert(s.cache_name(&d.app, name, true));
            }
        }
        if let Some(client) = &d.client {
            uri_keys.insert(format!("{}-{client}", d.app));
        }
    }
    for app in apps {
        for s in &services {
            names.insert(s.read_page_cache_name(app));
        }
        for oui in [APPLICATION_OUI, PAGE_OUI, STYLE_OUI, THEME_OUI] {
            names.insert(format!("{oui}-{app}"));
        }
    }
    names.insert("inheritanceOrder".into());
    for n in &names {
        cx.evict_all(n).await;
    }
    for app in apps {
        st.ev.app_caches(cx, app).await;
    }
    for k in &uri_keys {
        cx.evict("URIPatternCache", k).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes() {
        assert!(Target::client("ZZPURGE1").is_ok());
        for bad in ["", "SYSTEM", "System", "AB_C", "AB-C"] {
            assert!(Target::client(bad).is_err(), "{bad}");
        }
        for ok in ["zzpurgeapp", "my_app"] {
            assert!(Target::app(ok).is_ok(), "{ok}");
        }
        for bad in ["", "_", "a-b", "a.b"] {
            assert!(Target::app(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn filters_and_dry_run() {
        assert_eq!(Target::client("X1").unwrap().doc_filter(), doc! {"clientCode": "X1"});
        assert_eq!(Target::app("a").unwrap().doc_filter(), doc! {"$or": [{"appCode": "a"}, {"objectAppCode": "a"}]});
        assert!(dry_run(None));
        assert!(dry_run(Some("true")));
        assert!(dry_run(Some("0")));
        assert!(!dry_run(Some("false")));
    }

    #[test]
    fn report_shape() {
        let mut r = Report { dry_run: false, ..Default::default() };
        r.mongo.insert("ui.page".into(), 3);
        r.errors.push("x".into());
        assert_eq!(
            overridable::json::to_compact(&r.to_json()),
            r#"{"dryRun":false,"mongo":{"ui.page":3},"mysql":{},"dropped":[],"errors":["x"]}"#
        );
    }
}
