//! `IAppDataService`: the operations both backends implement, and what they need from the
//! caller.
//!
//! The Java engines read the caller from the reactive security context and the surface
//! (live or draft) from the reactor context. Here both travel in [`Ctx`], and what the
//! engines pulled from Spring services (the write validator, the schema repository, the
//! per-tenant storage lookup) comes in through [`Hooks`]. The policy layer (auth gates,
//! triggers, relation filling, events) stays with the caller, exactly as `AppDataService`
//! sits above the Java engines.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;

use crate::error::{AppDataError, AppDataResult};
use crate::model::{AggregateQuery, Connection, DataObject, DraftCopyFilter, Page, Query, Schema, Storage, StorageRelation};
use crate::schema_refs::{HybridRepository, KirunSystemSchemas, SchemaRepository};
use crate::value::Document;

pub const CACHE_SUFFIX_FOR_INDEX_CREATION: &str = "_index_creation";
pub const CACHE_SUFFIX_FOR_TABLE_CREATION: &str = "_table_creation";
pub const CACHE_SUFFIX_FOR_FOREIGN_KEYS: &str = "_foreign_keys";
pub const DRAFT_DB_SUFFIX: &str = "_draft";

/// Rust only. Database (schema) names a whole-database drop never touches, even when they look
/// like `<client>_<app>`: the servers' own and the platform services' (compared ignoring case).
pub const PROTECTED_DATABASES: &[&str] = &[
    "admin",
    "config",
    "local",
    "ui",
    "core",
    "security",
    "files",
    "notification",
    "multi",
    "information_schema",
    "mysql",
    "performance_schema",
    "sys",
    "entity_processor",
    "entity_collector",
];

/// Rust only. Server and platform schemas named `<word>_<more>` (`mysql_audit` on dev,
/// `performance_schema`, `entity_processor`): the part before the first `_` is one of these
/// words, compared ignoring case. No client code is one of them, so no tenant database is lost.
pub const PROTECTED_DATABASE_PREFIXES: &[&str] = &["mysql", "sys", "performance", "information", "entity"];

/// Rust only, for the admin purge: whether `name` can be a tenant database
/// (`<CLIENT>_<app>[_draft]`): ASCII letters, digits and `_`, at most 64 long, a client part of
/// letters and digits before the first `_` and something after it, and not a protected name.
pub fn is_tenant_database_name(name: &str) -> bool {
    let Some((client, rest)) = name.split_once('_') else { return false };
    !client.is_empty()
        && client.bytes().all(|b| b.is_ascii_alphanumeric())
        && !rest.is_empty()
        && name.len() <= 64
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && !PROTECTED_DATABASES.iter().any(|p| p.eq_ignore_ascii_case(name))
        && !PROTECTED_DATABASE_PREFIXES.iter().any(|p| p.eq_ignore_ascii_case(client))
}

/// Rust only. Every cache the two engines keep per storage (tables and version tables made,
/// foreign keys read, indexes managed), each keyed by tenant database: what must go when a
/// tenant database is dropped under them, or a later write would skip creating its table.
pub fn storage_cache_names(unique_name: &str) -> Vec<String> {
    let version = crate::mysql::version_table::name_for(unique_name);
    vec![
        format!("{unique_name}{CACHE_SUFFIX_FOR_TABLE_CREATION}"),
        format!("{version}{CACHE_SUFFIX_FOR_TABLE_CREATION}"),
        format!("{unique_name}{CACHE_SUFFIX_FOR_FOREIGN_KEYS}"),
        format!("{unique_name}{CACHE_SUFFIX_FOR_INDEX_CREATION}"),
    ]
}

/// Who is calling and on which surface.
#[derive(Clone, Default)]
pub struct Ctx {
    /// `ContextAuthentication.getUrlClientCode()`: the tenant an app-level storage lives in.
    pub url_client_code: Option<String>,
    /// The signed-in user, recorded on version rows.
    pub user_id: Option<u64>,
    /// The caller's authorities, for the readAuth of a joined or sub-queried storage.
    pub authorities: Vec<String>,
    /// `LogUtil.isDraft()`: the draft surface, a sibling `<CLIENT>_<app>_draft` database.
    pub draft: bool,
}

impl Ctx {
    pub fn on_draft(&self, draft: bool) -> Ctx {
        Ctx { draft, ..self.clone() }
    }

    /// `SecurityContextUtil.hasAuthority`: a blank expression allows; otherwise each
    /// `or` alternative is a conjunction of authorities, `not` negates one.
    pub fn has_authority(&self, expression: Option<&str>) -> bool {
        let Some(expr) = expression.filter(|e| !e.trim().is_empty()) else { return true };
        if self.authorities.is_empty() {
            return false;
        }
        expr.split(" or ").any(|alt| {
            alt.split(" and ").all(|term| {
                let term = term.trim().trim_matches(|c| c == '(' || c == ')').trim();
                match term.strip_prefix("not ") {
                    Some(t) => !self.authorities.iter().any(|a| a == t.trim()),
                    None => self.authorities.iter().any(|a| a == term),
                }
            })
        })
    }

    /// The client whose database a storage's rows live in (Mongo honours isAppLevel).
    pub fn tenant(&self, client_code: &str, storage: &Storage) -> String {
        if storage.app_level() {
            self.url_client_code.clone().unwrap_or_default()
        } else {
            client_code.to_string()
        }
    }
}

/// `StorageWriteValidator`: checks a row against its schema and hands back the validated
/// JSON. The default passes the row through untouched.
#[async_trait]
pub trait WriteValidator: Send + Sync {
    async fn validate(&self, data: &Document, storage: &Storage, schema: Option<&Schema>) -> AppDataResult<Document>;
}

pub struct PassThrough;

#[async_trait]
impl WriteValidator for PassThrough {
    async fn validate(&self, data: &Document, _storage: &Storage, _schema: Option<&Schema>) -> AppDataResult<Document> {
        Ok(data.clone())
    }
}

/// `StorageService.readForTenant`: a storage as one client resolves it, on one surface.
#[async_trait]
pub trait StorageResolver: Send + Sync {
    async fn read_for_tenant(&self, name: &str, app_code: &str, client_code: &str, draft: bool)
        -> anyhow::Result<Option<Storage>>;
}

/// `CoreSchemaService.getSchemaRepository(appCode, clientCode)`.
pub trait SchemaRepositories: Send + Sync {
    fn for_app(&self, app_code: &str, client_code: &str) -> Arc<dyn SchemaRepository>;

    /// The repository as one surface sees it. Java calls `getSchemaRepository` under the
    /// reactor context's draft flag, so on the draft surface it reads the client's own
    /// drafted schemas and a schema draft reaches that client's draft tables. The default
    /// ignores the surface: right for a caller that has no schema drafts.
    fn for_surface(&self, app_code: &str, client_code: &str, draft: bool) -> Arc<dyn SchemaRepository> {
        let _ = draft;
        self.for_app(app_code, client_code)
    }
}

/// What the engines borrow from the services above them.
#[derive(Clone)]
pub struct Hooks {
    pub validator: Arc<dyn WriteValidator>,
    pub schemas: Option<Arc<dyn SchemaRepositories>>,
    pub storages: Option<Arc<dyn StorageResolver>>,
    /// The full `SecurityContextUtil.hasAuthority` (a KIRun expression over the
    /// authorities) for the readAuth of a joined or sub-queried storage. Without it the
    /// engines use [`Ctx::has_authority`], which covers `and` / `or` / `not` only.
    pub authority: Option<Arc<dyn AuthorityCheck>>,
}

/// Evaluates a readAuth expression against the caller's authorities.
pub trait AuthorityCheck: Send + Sync {
    fn has_authority(&self, expression: Option<&str>, authorities: &[String]) -> bool;
}

impl Default for Hooks {
    fn default() -> Self {
        Hooks { validator: Arc::new(PassThrough), schemas: None, storages: None, authority: None }
    }
}

impl Hooks {
    pub fn has_authority(&self, cx: &Ctx, expression: Option<&str>) -> bool {
        match &self.authority {
            Some(check) => check.has_authority(expression, &cx.authorities),
            None => cx.has_authority(expression),
        }
    }

    /// The repository a storage's refs resolve against on the live surface.
    pub fn repository(&self, storage: &Storage) -> Arc<dyn SchemaRepository> {
        self.repository_on(storage, false)
    }

    /// The repository a storage's refs resolve against on one surface: KIRun's own
    /// schemas, then the app's as that surface sees them.
    pub fn repository_on(&self, storage: &Storage, draft: bool) -> Arc<dyn SchemaRepository> {
        let mut repos: Vec<Arc<dyn SchemaRepository>> = vec![Arc::new(KirunSystemSchemas)];
        if let Some(s) = &self.schemas {
            repos.push(s.for_surface(&storage.app_code, &storage.client_code, draft));
        }
        Arc::new(HybridRepository(repos))
    }

    /// `StorageService.getResolvedSchema` on the live surface.
    pub async fn resolved_schema(&self, storage: &Storage) -> Option<Schema> {
        self.resolved_schema_on(storage, false).await
    }

    /// `StorageService.getResolvedSchema` under a surface: the refs resolved the way that
    /// surface resolves them.
    pub async fn resolved_schema_on(&self, storage: &Storage, draft: bool) -> Option<Schema> {
        let repo = self.repository_on(storage, draft);
        crate::schema_refs::resolved_schema(storage, Some(repo.as_ref())).await
    }

    pub async fn read_for_tenant(&self, name: &str, app_code: &str, client_code: &str, draft: bool)
        -> AppDataResult<Option<Storage>> {
        match &self.storages {
            None => Ok(None),
            Some(s) => Ok(s.read_for_tenant(name, app_code, client_code, draft).await?),
        }
    }
}

/// `IAppDataService`.
#[async_trait]
pub trait AppDataEngine: Send + Sync {
    fn backend(&self) -> &'static str;

    async fn create(&self, cx: &Ctx, client_code: &str, conn: Option<&Connection>, storage: &Storage, data: DataObject)
        -> AppDataResult<Document>;

    async fn update(
        &self,
        cx: &Ctx,
        client_code: &str,
        conn: Option<&Connection>,
        storage: &Storage,
        data: DataObject,
        override_: Option<bool>,
    ) -> AppDataResult<Document>;

    async fn read(&self, cx: &Ctx, client_code: &str, conn: Option<&Connection>, storage: &Storage, id: &str)
        -> AppDataResult<Document>;

    /// Rust only. Creates everything a write to the storage needs (table, version table, counters)
    /// ahead of time, so a transaction that writes it never meets DDL midway (MySQL 1412 "Table
    /// definition has changed" when a table is created after the transaction began).
    async fn prepare(&self, _cx: &Ctx, _client_code: &str, _conn: Option<&Connection>, _storage: &Storage) -> AppDataResult<()> {
        Ok(())
    }

    /// Rust only. Whether this engine can run a batch as one transaction in this deployment;
    /// when it cannot, a batch undoes its own writes on failure and says it was not atomic.
    async fn transactional(&self, _conn: Option<&Connection>) -> bool {
        false
    }

    /// Rust only. The row read for a compare-and-set: locked until the surrounding transaction
    /// ends where the engine has one (MySQL `SELECT ... FOR UPDATE`), a plain read otherwise.
    /// `None` when there is no such row.
    async fn lock_row(&self, cx: &Ctx, client_code: &str, conn: Option<&Connection>, storage: &Storage, id: &str)
        -> AppDataResult<Option<Document>> {
        match self.read(cx, client_code, conn, storage, id).await {
            Ok(row) => Ok(Some(row)),
            Err(e) if e.is_object_not_found() => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Rust only. The next value of the counter `key` kept beside the storage's rows (same
    /// tenant and surface): `start` the first time, then one more each call, atomically.
    async fn next_sequence(
        &self,
        _cx: &Ctx,
        _client_code: &str,
        _conn: Option<&Connection>,
        _storage: &Storage,
        _key: &str,
        _start: i64,
    ) -> AppDataResult<i64> {
        Err(AppDataError::unsupported_on_backend("sequences", self.backend()))
    }

    async fn read_page(&self, cx: &Ctx, client_code: &str, conn: Option<&Connection>, storage: &Storage, query: &Query)
        -> AppDataResult<Page<Document>>;

    /// `readPageAsFlux`, collected: the page bounds it, so it is never more than one page.
    async fn read_page_rows(&self, cx: &Ctx, client_code: &str, conn: Option<&Connection>, storage: &Storage, query: &Query)
        -> AppDataResult<Vec<Document>>;

    async fn aggregate(
        &self,
        cx: &Ctx,
        client_code: &str,
        conn: Option<&Connection>,
        storage: &Storage,
        query: &AggregateQuery,
    ) -> AppDataResult<Page<Document>>;

    async fn delete(
        &self,
        cx: &Ctx,
        client_code: &str,
        conn: Option<&Connection>,
        storage: &Storage,
        id: &str,
        delete_version: Option<bool>,
    ) -> AppDataResult<bool>;

    async fn delete_by_filter(
        &self,
        cx: &Ctx,
        client_code: &str,
        conn: Option<&Connection>,
        storage: &Storage,
        query: &Query,
        dev_mode: Option<bool>,
        delete_version: Option<bool>,
    ) -> AppDataResult<i64>;

    async fn read_version(&self, cx: &Ctx, client_code: &str, conn: Option<&Connection>, storage: &Storage, version_id: &str)
        -> AppDataResult<Document>;

    async fn read_page_version(
        &self,
        cx: &Ctx,
        client_code: &str,
        conn: Option<&Connection>,
        storage: &Storage,
        object_id: &str,
        query: &Query,
        include_object: Option<bool>,
    ) -> AppDataResult<Page<Document>>;

    async fn check_if_exists(&self, cx: &Ctx, client_code: &str, conn: Option<&Connection>, storage: &Storage, id: &str)
        -> AppDataResult<bool>;

    /// Whether the database IS enforcing this relation, so the service must not.
    async fn enforces_relation_constraint(
        &self,
        _cx: &Ctx,
        _client_code: &str,
        _conn: Option<&Connection>,
        _child: &Storage,
        _field: &str,
        _relation: &StorageRelation,
    ) -> AppDataResult<bool> {
        Ok(false)
    }

    async fn count_referencing(
        &self,
        cx: &Ctx,
        client_code: &str,
        conn: Option<&Connection>,
        child: &Storage,
        field: &str,
        many: bool,
        id: &str,
    ) -> AppDataResult<i64>;

    #[allow(clippy::too_many_arguments)]
    async fn ids_referencing(
        &self,
        cx: &Ctx,
        client_code: &str,
        conn: Option<&Connection>,
        child: &Storage,
        field: &str,
        many: bool,
        id: &str,
        limit: i64,
    ) -> AppDataResult<Vec<String>>;

    async fn delete_storage(&self, cx: &Ctx, client_code: &str, conn: Option<&Connection>, storage: &Storage)
        -> AppDataResult<bool>;

    async fn drop_draft_storage(&self, cx: &Ctx, client_code: &str, conn: Option<&Connection>, storage: &Storage)
        -> AppDataResult<bool>;

    async fn drop_draft_database(&self, conn: Option<&Connection>, app_code: &str, client_code: &str) -> AppDataResult<bool>;

    /// Rust only, for the admin purge: every database (schema) name on the connection's server
    /// (`None`: the engine's default server).
    async fn database_names(&self, _conn: Option<&Connection>) -> AppDataResult<Vec<String>> {
        Err(AppDataError::unsupported_on_backend("listing databases", self.backend()))
    }

    /// Rust only, for the admin purge: the rows in a whole database (MySQL: the tables'
    /// `table_rows` estimate; Mongo: `dbStats.objects`).
    async fn database_rows(&self, _conn: Option<&Connection>, _name: &str) -> AppDataResult<i64> {
        Err(AppDataError::unsupported_on_backend("counting a database", self.backend()))
    }

    /// Rust only, for the admin purge: drops a whole tenant database by its exact name. A name
    /// [`is_tenant_database_name`] refuses is never dropped (an error).
    async fn drop_database(&self, _conn: Option<&Connection>, _name: &str) -> AppDataResult<bool> {
        Err(AppDataError::unsupported_on_backend("dropping a database", self.backend()))
    }

    async fn copy_live_to_draft(
        &self,
        cx: &Ctx,
        client_code: &str,
        conn: Option<&Connection>,
        storage: &Storage,
        replace: Option<bool>,
    ) -> AppDataResult<i64>;

    async fn clear_draft_rows(&self, cx: &Ctx, client_code: &str, conn: Option<&Connection>, storage: &Storage)
        -> AppDataResult<i64>;

    #[allow(clippy::too_many_arguments)]
    async fn copy_live_to_draft_filtered(
        &self,
        cx: &Ctx,
        client_code: &str,
        conn: Option<&Connection>,
        storage: &Storage,
        filter: Option<&DraftCopyFilter>,
        followed: &HashMap<String, Storage>,
    ) -> AppDataResult<i64>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_database_names() {
        for ok in ["ZZPURGE1_zzpurgeapp", "ZZPURGE1_zzpurgeapp_draft", "SYSTEM_appbuilder", "ABC_my_app"] {
            assert!(is_tenant_database_name(ok), "{ok}");
        }
        for no in [
            "", "core", "ui", "admin", "_x", "ABC_", "ABC", "AB-C_app", "ABC_app-x", "entity_processor", "ENTITY_PROCESSOR",
            "performance_schema", "information_schema", "mysql_audit", "MySQL_audit", "sys_config", "entity_anything",
        ] {
            assert!(!is_tenant_database_name(no), "{no}");
        }
        assert!(!is_tenant_database_name(&format!("A_{}", "x".repeat(63))));
    }

    #[test]
    fn storage_caches_cover_both_engines() {
        assert_eq!(
            storage_cache_names("s1"),
            ["s1_table_creation", "s1_version_table_creation", "s1_foreign_keys", "s1_index_creation"]
        );
    }
}
