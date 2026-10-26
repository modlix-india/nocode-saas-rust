//! The admin purge (Rust only, no Java counterpart): every core trace of a dead client or of an
//! app, for every client. A client's purge deletes every `core` document whose `clientCode` is
//! the client (every collection, listed at run time), the core MySQL rows whose `CLIENT_CODE`
//! is the client, and drops the client's tenant databases (`<CLIENT>_<app>` and their
//! `_draft` siblings) on every app-data server. An app's purge does the same by app code: the
//! documents whose `appCode` (versions and drafts: `objectAppCode`) is the app, the rows whose
//! `APP_CODE` is the app, and every `<client>_<app>[_draft]` database. A dry run (the default)
//! counts what a real run deletes; the report has the same shape either way.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use futures::TryStreamExt;
use mongodb::bson::{doc, Document};
use overridable::backend::{Backend, Find};
use overridable::write::{Kind, OverridableService};
use overridable::{JMap, JValue};

use crate::editor::routes::CoreEditor;

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

    pub fn authority(&self) -> &'static str {
        match self {
            Target::Client(_) => CLIENT_DELETE,
            Target::App(_) => APPLICATION_DELETE,
        }
    }

    /// The documents of the target in any collection (versions and drafts key the app by
    /// `objectAppCode`).
    pub fn doc_filter(&self) -> Document {
        match self {
            Target::Client(c) => doc! {"clientCode": c},
            Target::App(a) => doc! {"$or": [{"appCode": a}, {"objectAppCode": a}]},
        }
    }

    /// The MySQL column the target's rows carry.
    pub fn row_column(&self) -> &'static str {
        match self {
            Target::Client(_) => "CLIENT_CODE",
            Target::App(_) => "APP_CODE",
        }
    }

    /// Whether a tenant database is the target's: the name split at its first `_` (client
    /// codes have none), the left part the client exactly, or the right part the app or the
    /// app's draft. Names that cannot be tenant databases never match.
    pub fn owns_database(&self, name: &str) -> bool {
        if !appdata::engine::is_tenant_database_name(name) {
            return false;
        }
        let Some((client, rest)) = name.split_once('_') else { return false };
        match self {
            Target::Client(c) => client == c,
            Target::App(a) => rest == a || rest.strip_suffix(appdata::engine::DRAFT_DB_SUFFIX) == Some(a.as_str()),
        }
    }
}

/// The apps a tenant database may hold: the part after the client, and that without `_draft`.
pub fn apps_of(name: &str) -> Vec<String> {
    let Some((_, rest)) = name.split_once('_') else { return Vec::new() };
    let mut out = vec![rest.to_string()];
    if let Some(live) = rest.strip_suffix(appdata::engine::DRAFT_DB_SUFFIX).filter(|l| !l.is_empty()) {
        out.push(live.to_string());
    }
    out
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
    pub mysql: BTreeMap<String, i64>,
    pub dropped: Vec<String>,
    pub errors: Vec<String>,
}

impl Report {
    pub fn to_json(&self) -> JValue {
        let counts = |m: &BTreeMap<String, i64>| JValue::Object(m.iter().map(|(k, v)| (k.clone(), JValue::Int(*v))).collect::<JMap>());
        let texts = |v: &[String]| JValue::Array(v.iter().map(|s| JValue::Str(s.clone())).collect());
        let mut out = JMap::new();
        out.insert("dryRun".into(), JValue::Bool(self.dry_run));
        out.insert("mongo".into(), counts(&self.mongo));
        out.insert("mysql".into(), counts(&self.mysql));
        out.insert("dropped".into(), texts(&self.dropped));
        out.insert("errors".into(), texts(&self.errors));
        JValue::Object(out)
    }

    fn add(map: &mut BTreeMap<String, i64>, key: String, n: i64) {
        *map.entry(key).or_default() += n;
    }
}

/// The backend a tenant database lives on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantBackend {
    Mongo,
    MySql,
}

impl std::fmt::Display for TenantBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            TenantBackend::Mongo => "mongo",
            TenantBackend::MySql => "mysql",
        })
    }
}

/// One database on one app-data server.
#[derive(Debug, Clone)]
pub struct TenantDb {
    pub backend: TenantBackend,
    /// The server, for messages: `default` or `connection <id>` (never its URL).
    pub server: String,
    /// The connection to reach it with; `None` is the engine's default server.
    pub conn: Option<appdata::model::Connection>,
    pub name: String,
}

/// The core Mongo database as the purge sees it.
#[async_trait]
pub trait DocStore: Send + Sync {
    fn db_name(&self) -> String;
    async fn collections(&self) -> Result<Vec<String>>;
    async fn count(&self, collection: &str, filter: Document) -> Result<u64>;
    /// The matching documents' app and name fields, for the cache evictions.
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
    doc! {"_id": 0, "appCode": 1, "objectAppCode": 1, "name": 1, "uniqueName": 1}
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

/// The core MySQL schema as the purge sees it.
#[async_trait]
pub trait RowStore: Send + Sync {
    async fn schema(&self) -> Result<String>;
    /// The schema's base tables having `column`.
    async fn tables_with(&self, column: &str) -> Result<Vec<String>>;
    async fn count(&self, table: &str, column: &str, value: &str) -> Result<u64>;
    async fn delete(&self, table: &str, column: &str, value: &str) -> Result<u64>;
}

fn plain_identifier(s: &str) -> Result<&str> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        anyhow::bail!("not a plain identifier: {s}");
    }
    Ok(s)
}

#[async_trait]
impl RowStore for sqlx::MySqlPool {
    async fn schema(&self) -> Result<String> {
        let s: Option<String> = sqlx::query_scalar("SELECT CAST(DATABASE() AS CHAR)").fetch_one(self).await?;
        Ok(s.unwrap_or_default())
    }
    async fn tables_with(&self, column: &str) -> Result<Vec<String>> {
        let tables: Vec<String> = sqlx::query_scalar(
            "SELECT CAST(c.table_name AS CHAR) FROM information_schema.columns c \
             JOIN information_schema.tables t ON t.table_schema = c.table_schema AND t.table_name = c.table_name \
             WHERE c.table_schema = DATABASE() AND c.column_name = ? AND t.table_type = 'BASE TABLE' ORDER BY 1",
        )
        .bind(column)
        .fetch_all(self)
        .await?;
        Ok(tables)
    }
    async fn count(&self, table: &str, column: &str, value: &str) -> Result<u64> {
        let sql = format!("SELECT COUNT(*) FROM `{}` WHERE `{}` = ?", plain_identifier(table)?, plain_identifier(column)?);
        let n: i64 = sqlx::query_scalar(&sql).bind(value).fetch_one(self).await?;
        Ok(n.max(0) as u64)
    }
    async fn delete(&self, table: &str, column: &str, value: &str) -> Result<u64> {
        let sql = format!("DELETE FROM `{}` WHERE `{}` = ?", plain_identifier(table)?, plain_identifier(column)?);
        Ok(sqlx::query(&sql).bind(value).execute(self).await?.rows_affected())
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

/// A deleted document's collection, app and name.
type Deleted = (String, String, Option<String>);

fn text(d: &Document, k: &str) -> Option<String> {
    d.get_str(k).ok().filter(|s| !s.is_empty()).map(str::to_string)
}

/// Runs the purge; never fails as a whole: each failure is a line in `errors`.
pub async fn run(st: &CoreEditor, target: &Target, dry_run: bool) -> Report {
    let mut r = Report { dry_run, ..Default::default() };

    // The tenant databases first: listing them reads the connection documents purged below.
    let (dbs, errors) = st.data.tenant_databases().await;
    r.errors.extend(errors);
    let owned: Vec<TenantDb> = dbs.into_iter().filter(|d| target.owns_database(&d.name)).collect();
    let mut apps: BTreeSet<String> = owned.iter().flat_map(|d| apps_of(&d.name)).collect();
    if let Target::App(a) = target {
        apps.insert(a.clone());
    }
    // The storages whose tables lived there, read before their documents may go.
    let storages = if dry_run { Vec::new() } else { storage_names(st, &apps, &mut r).await };
    for db in &owned {
        match st.data.tenant_rows(db).await {
            Ok(n) => {
                let map = if db.backend == TenantBackend::Mongo { &mut r.mongo } else { &mut r.mysql };
                Report::add(map, format!("{}.*", db.name), n);
            }
            Err(e) => r.errors.push(format!("{} {} ({}): count: {e}", db.backend, db.name, db.server)),
        }
        if !dry_run {
            if let Err(e) = st.data.drop_tenant_database(db).await {
                r.errors.push(format!("{} {} ({}): drop: {e}", db.backend, db.name, db.server));
                continue;
            }
        }
        if !r.dropped.contains(&db.name) {
            r.dropped.push(db.name.clone());
        }
    }

    let mut deleted: Vec<Deleted> = Vec::new();
    match &st.purge_docs {
        Some(docs) => purge_docs(docs.as_ref(), target, dry_run, &mut r, &mut deleted).await,
        None => r.errors.push("core documents: no document store configured".into()),
    }
    match &st.purge_rows {
        Some(rows) => purge_rows(rows.as_ref(), target, dry_run, &mut r).await,
        None => r.errors.push("core rows: no MySQL pool configured".into()),
    }

    // Nothing deleted or dropped, nothing to evict: a full eviction per purge would keep a whole
    // environment's caches cold for the length of a sweep.
    let changed = !owned.is_empty() || !deleted.is_empty() || !r.mysql.is_empty();
    if !dry_run && changed {
        apps.extend(deleted.iter().map(|(_, a, _)| a.clone()));
        evict(st, &apps, &deleted, &storages).await;
    }
    r
}

async fn storage_names(st: &CoreEditor, apps: &BTreeSet<String>, r: &mut Report) -> Vec<String> {
    let Some(docs) = &st.purge_docs else { return Vec::new() };
    if apps.is_empty() {
        return Vec::new();
    }
    let list: Vec<&String> = apps.iter().collect();
    match docs.keys("storage", doc! {"appCode": {"$in": list}}).await {
        Ok(found) => {
            let names: BTreeSet<String> = found.iter().filter_map(|d| text(d, "uniqueName")).collect();
            names.into_iter().collect()
        }
        Err(e) => {
            r.errors.push(format!("storages of the apps: {e}"));
            Vec::new()
        }
    }
}

async fn purge_docs(docs: &dyn DocStore, target: &Target, dry_run: bool, r: &mut Report, deleted: &mut Vec<Deleted>) {
    let db = docs.db_name();
    let mut collections = match docs.collections().await {
        Ok(c) => c,
        Err(e) => {
            r.errors.push(format!("{db}: list collections: {e}"));
            return;
        }
    };
    collections.sort();
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
                            deleted.push((c.clone(), app, text(k, "name")));
                        }
                    }
                    docs.delete(c, filter).await
                }
                Err(e) => Err(e),
            }
        };
        match n {
            Ok(0) => {}
            Ok(n) => Report::add(&mut r.mongo, format!("{db}.{c}"), n as i64),
            Err(e) => r.errors.push(format!("{db}.{c}: {e}")),
        }
    }
}

async fn purge_rows(rows: &dyn RowStore, target: &Target, dry_run: bool, r: &mut Report) {
    let (schema, tables) = match (rows.schema().await, rows.tables_with(target.row_column()).await) {
        (Ok(s), Ok(t)) => (s, t),
        (Err(e), _) | (_, Err(e)) => {
            r.errors.push(format!("core rows: {e}"));
            return;
        }
    };
    let value = match target {
        Target::Client(c) | Target::App(c) => c.as_str(),
    };
    for t in tables {
        let n = if dry_run { rows.count(&t, target.row_column(), value).await } else { rows.delete(&t, target.row_column(), value).await };
        match n {
            Ok(0) => {}
            Ok(n) => Report::add(&mut r.mysql, format!("{schema}.{t}"), n as i64),
            Err(e) => r.errors.push(format!("{schema}.{t}: {e}")),
        }
    }
}

/// Everything cached about what went: what `DELETE /api/core/internal/cache` drops, then, by
/// name on every instance (the Rust units keep caches Redis never hears of), each deleted
/// definition's caches on both surfaces, each affected app's page caches, the engines' table
/// caches of the affected apps' storages, and the inheritance, dependency and storage
/// reference caches.
async fn evict(st: &CoreEditor, apps: &BTreeSet<String>, deleted: &[Deleted], storages: &[String]) {
    crate::editor::cache::evict_all(&st.cx.cache, st.redis.as_ref(), &st.eviction_channel).await;
    let services: [&dyn CacheNames; 11] = [
        &st.functions,
        &st.schemas,
        &st.storages,
        &st.connections,
        &st.templates,
        &st.notifications,
        &st.event_definitions,
        &st.event_actions,
        &st.workflows,
        &st.actions,
        &st.fillers,
    ];
    let mut names: BTreeSet<String> = BTreeSet::new();
    for (collection, app, name) in deleted {
        let Some(name) = name else { continue };
        for s in services.iter().filter(|s| s.collection() == collection) {
            names.insert(s.cache_name(app, name, false));
            names.insert(s.cache_name(app, name, true));
        }
    }
    for app in apps {
        for s in &services {
            names.insert(s.read_page_cache_name(app));
        }
    }
    for u in storages {
        names.extend(appdata::engine::storage_cache_names(u));
    }
    for n in ["inheritanceOrder", "appDepList", crate::storage::defs::CACHE_STORAGE_REFERENCES] {
        names.insert(n.to_string());
    }
    for n in &names {
        st.cx.cache.evict_all_everywhere(n).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_codes() {
        assert!(Target::client("ZZPURGE1").is_ok());
        for bad in ["", "SYSTEM", "system", "AB_C", "AB-C", "AB C", "ÄBC"] {
            assert!(Target::client(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn app_codes() {
        for ok in ["zzpurgeapp", "my_app", "app2"] {
            assert!(Target::app(ok).is_ok(), "{ok}");
        }
        for bad in ["", "_", "__", "a-b", "a b", "a.b"] {
            assert!(Target::app(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn client_owns_its_databases_only() {
        let t = Target::client("ABC").unwrap();
        assert!(t.owns_database("ABC_app"));
        assert!(t.owns_database("ABC_app_draft"));
        assert!(t.owns_database("ABC_my_app"));
        assert!(!t.owns_database("ABCD_app"));
        assert!(!t.owns_database("XABC_app"));
        assert!(!t.owns_database("abc_app"));
        assert!(!t.owns_database("ABC"));
        assert!(!t.owns_database("ABC_"));
    }

    #[test]
    fn app_owns_every_clients_databases() {
        let t = Target::app("app").unwrap();
        assert!(t.owns_database("ABC_app"));
        assert!(t.owns_database("SYSTEM_app_draft"));
        assert!(!t.owns_database("ABC_app2"));
        assert!(!t.owns_database("ABC_myapp"));
        assert!(!t.owns_database("ABC_app_draft2"));
        let u = Target::app("my_app").unwrap();
        assert!(u.owns_database("ABC_my_app"));
        assert!(u.owns_database("ABC_my_app_draft"));
        assert!(!u.owns_database("ABC_app"));
        assert!(!u.owns_database("ABCmy_app"));
        // The services' own databases never match, whatever the app.
        assert!(!Target::app("processor").unwrap().owns_database("entity_processor"));
        assert!(!Target::app("schema").unwrap().owns_database("performance_schema"));
    }

    #[test]
    fn apps_of_a_database() {
        assert_eq!(apps_of("ABC_app"), ["app"]);
        assert_eq!(apps_of("ABC_app_draft"), ["app_draft", "app"]);
        assert!(apps_of("ABC").is_empty());
    }

    #[test]
    fn dry_run_unless_false() {
        assert!(dry_run(None));
        assert!(dry_run(Some("true")));
        assert!(dry_run(Some("")));
        assert!(dry_run(Some("no")));
        assert!(!dry_run(Some("false")));
        assert!(!dry_run(Some("FALSE")));
    }

    #[test]
    fn filters() {
        assert_eq!(Target::client("X1").unwrap().doc_filter(), doc! {"clientCode": "X1"});
        assert_eq!(Target::app("a").unwrap().doc_filter(), doc! {"$or": [{"appCode": "a"}, {"objectAppCode": "a"}]});
        assert_eq!(Target::client("X1").unwrap().row_column(), "CLIENT_CODE");
        assert_eq!(Target::app("a").unwrap().row_column(), "APP_CODE");
    }

    #[test]
    fn report_shape() {
        let mut r = Report { dry_run: true, ..Default::default() };
        r.mongo.insert("core.function".into(), 2);
        r.dropped.push("X_a".into());
        let j = overridable::json::to_compact(&r.to_json());
        assert_eq!(j, r#"{"dryRun":true,"mongo":{"core.function":2},"mysql":{},"dropped":["X_a"],"errors":[]}"#);
    }
}
