//! `MySQLAppDataService`: app data on MySQL, selected by an APP_DATA connection with
//! subtype MYSQL. One schema per `<CLIENT>_<app>`, a sibling `_draft` schema, the storage's
//! uniqueName as the table on both, ULIDs as row ids.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use indexmap::{IndexMap, IndexSet};
use platform::cache::{CacheService, LocalCaches};
use sqlx::MySqlPool;
use tokio::sync::Mutex;

use super::column::MySqlColumn;
use super::column_names::{self, PhysicalSchema};
use super::db::{self, count, count_raw, execute, execute_raw, fetch, Credentials};
use super::drift::{self, DriftRepair, Report};
use super::field_resolver::FieldResolver;
use super::filter_builder::{self, bind_of, FilterError};
use super::foreign_keys::{self, ForeignKey};
use super::indexes;
use super::join_planner::{self, JoinedTable, PARENT};
use super::migration::{self, FanOutReport, MigrationOutcome, RecoveryReport, TenantProgress};
use super::sql::{self, Bind, Cond, FieldOps, Select, Sql};
use super::subquery_planner::{self, SubQueryTable};
use super::table_planner;
use super::type_mapper::{self, ID_COLUMN, ID_TYPE};
use super::value_codec::{self, Columns};
use super::version_table;
use super::aggregate_builder;
use crate::aggregate_validator;
use crate::engine::{
    AppDataEngine, Ctx, Hooks, CACHE_SUFFIX_FOR_FOREIGN_KEYS, CACHE_SUFFIX_FOR_TABLE_CREATION, DRAFT_DB_SUFFIX,
};
use crate::error::{AppDataError, AppDataResult};
use crate::model::{
    AggregateFunction, AggregateQuery, ColumnDefinitions, Connection, DataObject, DraftCopyFilter, JoinType,
    Order, Page, Pageable, Query, Schema, Sort, Storage, StorageJoin, StorageRelation, StorageSubQuery,
};
use crate::retention::VersionRetention;
use crate::schema_refs::storage_schema;
use crate::ulid::ulid;
use crate::value::{Document, Value};

const BACKEND: &str = "MySQL";
const VERSION_PURGE_BATCH: usize = 500;

#[derive(Debug, Clone)]
pub struct MySqlEngineConfig {
    /// `core.appdata.mysql.textSearch.stemming`.
    pub text_search_stemming: bool,
    pub pool_initial_size: u32,
    pub pool_max_size: u32,
    pub pool_max_idle_minutes: u64,
    /// `spring.r2dbc.url` / username / password: what `useDefaultConnection` points at.
    pub default_url: Option<String>,
    pub default_username: Option<String>,
    pub default_password: Option<String>,
    pub retention: VersionRetention,
    /// Issue no DDL: no CREATE for a missing table, no index or key sync. Off in service;
    /// on for read-only tooling (the parity run) that must not change a real tenant.
    pub skip_provisioning: bool,
}

impl Default for MySqlEngineConfig {
    fn default() -> Self {
        MySqlEngineConfig {
            text_search_stemming: true,
            pool_initial_size: 0,
            pool_max_size: 10,
            pool_max_idle_minutes: 5,
            default_url: None,
            default_username: None,
            default_password: None,
            retention: VersionRetention::default(),
            skip_provisioning: false,
        }
    }
}

pub struct MySqlAppDataService {
    config: MySqlEngineConfig,
    hooks: Hooks,
    cache: CacheService,
    pools: Mutex<HashMap<String, MySqlPool>>,
    flags: Arc<LocalCaches<String, bool>>,
    key_columns: Arc<LocalCaches<String, Vec<String>>>,
}

/// `<client>_<app>[_draft]`, checked before it can become DDL.
pub fn database_name(client_code: &str, app_code: &str, draft: bool) -> AppDataResult<String> {
    let name = format!("{client_code}_{app_code}{}", if draft { DRAFT_DB_SUFFIX } else { "" });
    let ok = !name.is_empty() && name.len() <= 64 && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
    if !ok {
        return Err(AppDataError::internal(format!("IllegalArgumentException: not a usable tenant schema name: {name}")));
    }
    Ok(name)
}

/// `MySQLAppDataService.dataClientCode` (Java commit e2b7d48aa): the client whose schema holds a
/// storage's rows. An app-level storage is one table shared by every client of the app, held
/// by the client hosting it (the URL's client), as on Mongo; every other storage is per
/// tenant. Without a caller, or with no URL client, the client asked for.
pub fn data_client_code(cx: &Ctx, client_code: &str, storage: &Storage) -> String {
    if !storage.app_level() {
        return client_code.to_string();
    }
    cx.url_client_code.clone().filter(|u| !u.trim().is_empty()).unwrap_or_else(|| client_code.to_string())
}

/// `sameSchema`: both storages' rows sit in one schema, so a foreign key between them is
/// possible (both app level, or neither).
pub fn same_schema(a: &Storage, b: &Storage) -> bool {
    a.app_level() == b.app_level()
}

pub fn is_draft(db: &str) -> bool {
    db.ends_with(DRAFT_DB_SUFFIX)
}

/// The client a tenant schema belongs to.
pub fn client_code_of(db: &str, app_code: &str) -> String {
    let name = db.strip_suffix(DRAFT_DB_SUFFIX).unwrap_or(db);
    let suffix = format!("_{app_code}");
    name.strip_suffix(&suffix).unwrap_or(name).to_string()
}

fn table_cache(storage: &Storage) -> String {
    format!("{}{CACHE_SUFFIX_FOR_TABLE_CREATION}", storage.unique_name)
}

fn version_cache(storage: &Storage) -> String {
    format!("{}{CACHE_SUFFIX_FOR_TABLE_CREATION}", version_table::name_for(&storage.unique_name))
}

fn foreign_key_cache(storage: &Storage) -> String {
    format!("{}{CACHE_SUFFIX_FOR_FOREIGN_KEYS}", storage.unique_name)
}

fn defs(storage: &Storage) -> Option<ColumnDefinitions> {
    column_names::column_definitions(storage.column_definitions.as_ref())
}

fn table(db: &str, storage: &Storage) -> Sql {
    Sql::name(&[db, &storage.unique_name])
}

fn id_field() -> Sql {
    Sql::name(&[ID_COLUMN])
}

fn internal<E: std::fmt::Display>(e: E) -> AppDataError {
    AppDataError::internal(e.to_string())
}

/// A filter this backend cannot express: 400 for the caller's mistake, 501 for a gap.
fn unsupported_filter(e: FilterError) -> AppDataError {
    match e {
        FilterError::Malformed(d) => AppDataError::unsupported_condition(&d),
        FilterError::Unsupported(d) => AppDataError::unsupported_on_backend(&d, BACKEND),
        FilterError::Unbindable(d) => AppDataError::internal(d),
    }
}

fn mapped_columns(schema: &PhysicalSchema, defs: Option<&ColumnDefinitions>) -> AppDataResult<Vec<MySqlColumn>> {
    type_mapper::columns(schema.schema(), defs).map_err(internal)
}

/// How one storage's columns read back: JSON parsed, dates as ISO text, decimals as text,
/// booleans as true / false.
#[derive(Debug, Clone, Default)]
pub struct Decoding {
    json: Columns,
    dates: Columns,
    decimals: Columns,
    booleans: Columns,
}

impl Decoding {
    pub fn of(schema: &PhysicalSchema, defs: Option<&ColumnDefinitions>) -> AppDataResult<Decoding> {
        let s = schema.schema();
        Ok(Decoding {
            json: type_mapper::json_columns(s, defs).map_err(internal)?,
            dates: type_mapper::date_string_columns(s, defs).map_err(internal)?,
            decimals: type_mapper::decimal_columns(s, defs).map_err(internal)?,
            booleans: type_mapper::boolean_columns(s, defs).map_err(internal)?,
        })
    }

    fn columns(&self, raw: Document) -> Document {
        value_codec::decode(raw, &self.json, &self.dates, &self.decimals, &self.booleans)
    }

    pub fn row(&self, raw: Document, physical: &PhysicalSchema) -> Document {
        physical.to_fields(self.columns(raw))
    }

    pub fn boolean_fields(&self, physical: &PhysicalSchema) -> Columns {
        self.booleans.iter().map(|c| physical.field_names().get(c).cloned().unwrap_or_else(|| c.clone())).collect()
    }
}

/// Joins towards the parents and subqueries towards the children, resolved together
/// because their aliases share one namespace.
#[derive(Debug, Clone, Default)]
struct Attached {
    joins: Vec<JoinedTable>,
    sub_queries: Vec<SubQueryTable>,
}

impl Attached {
    fn is_empty(&self) -> bool {
        self.joins.is_empty() && self.sub_queries.is_empty()
    }
}

/// A value bound into a write: what jOOQ binds, or a 500 for a list or map outside a JSON
/// column, as the driver refuses it.
fn write_bind(v: &Value) -> AppDataResult<Bind> {
    match v {
        Value::LocalDateTime(dt) => Ok(Bind::DateTime(*dt)),
        other => bind_of(other).map_err(unsupported_filter),
    }
}

/// The column set of a row: the id plus everything the schema declares.
fn column_types(schema: &PhysicalSchema, defs: Option<&ColumnDefinitions>) -> AppDataResult<IndexMap<String, String>> {
    let mut out = IndexMap::new();
    out.insert(ID_COLUMN.to_string(), ID_TYPE.to_string());
    for c in mapped_columns(schema, defs)? {
        out.insert(c.name().to_string(), c.column_type.clone());
    }
    Ok(out)
}

fn parent_columns(schema: &PhysicalSchema, defs: Option<&ColumnDefinitions>) -> AppDataResult<IndexSet<String>> {
    Ok(column_types(schema, defs)?.into_keys().collect())
}

/// The fields the storage declared text-indexed, as columns that exist.
fn text_columns(storage: &Storage, schema: &PhysicalSchema, defs: Option<&ColumnDefinitions>) -> AppDataResult<IndexSet<String>> {
    let Some(fields) = storage.text_index_fields.as_ref().filter(|f| !f.is_empty()) else { return Ok(IndexSet::new()) };
    let cols = parent_columns(schema, defs)?;
    Ok(fields.iter().map(|f| column_names::column(f)).filter(|c| cols.contains(c)).collect())
}

fn columns_named(fields: &[String]) -> IndexSet<String> {
    fields.iter().map(|f| column_names::column(f)).collect()
}

/// `projection`: empty selects everything; otherwise the id and the named (or not
/// excluded) columns.
pub fn projection(schema: &PhysicalSchema, query: &Query) -> AppDataResult<Vec<Sql>> {
    let Some(fields) = query.fields.as_ref().filter(|f| !f.is_empty()) else { return Ok(Vec::new()) };
    let named = columns_named(fields);
    let mut out = vec![id_field()];
    if !query.excludes() {
        for f in named.iter().filter(|f| *f != ID_COLUMN) {
            out.push(Sql::name(&[f]));
        }
        return Ok(out);
    }
    for c in mapped_columns(schema, None)? {
        if !named.contains(c.name()) {
            out.push(Sql::name(&[c.name()]));
        }
    }
    Ok(out)
}

/// The parent columns a joined query wants, with any field selection applied.
pub fn selected_parent_columns(schema: &PhysicalSchema, query: &Query) -> AppDataResult<IndexSet<String>> {
    let mut all = IndexSet::new();
    all.insert(ID_COLUMN.to_string());
    for c in mapped_columns(schema, None)? {
        all.insert(c.name().to_string());
    }
    let Some(fields) = query.fields.as_ref().filter(|f| !f.is_empty()) else { return Ok(all) };
    let named = columns_named(fields);
    if query.excludes() {
        all.retain(|c| !named.contains(c));
        all.insert(ID_COLUMN.to_string());
        return Ok(all);
    }
    let mut out = IndexSet::new();
    out.insert(ID_COLUMN.to_string());
    for n in named.iter().filter(|n| all.contains(*n)) {
        out.insert(n.clone());
    }
    Ok(out)
}

/// Whether a sort can address this name: a known column, or a path into a JSON column.
fn addressable(name: &str, known: &IndexSet<String>, json: &IndexSet<String>) -> bool {
    if known.contains(name) || known.contains(&column_names::column(name)) {
        return true;
    }
    let Some(dot) = name.find('.').filter(|d| *d > 0 && *d < name.len() - 1) else { return false };
    let head = &name[..dot];
    json.contains(&column_names::column(head)) || known.contains(&format!("{head}.{}", column_names::column(&name[dot + 1..])))
}

/// One sort key, with ids ordered by length first so imported numeric ids sort as numbers.
fn add_order(out: &mut Vec<Sql>, o: &Order, f: Sql) {
    if o.property == ID_COLUMN || o.property.ends_with(&format!(".{ID_COLUMN}")) {
        let len = Sql::template("char_length({0})", &[f.clone()]);
        out.push(if o.is_ascending() { len.asc() } else { len.desc() });
    }
    out.push(if o.is_ascending() { f.asc() } else { f.desc() });
}

/// `order(schema, sort)`: a read's sort with the plain resolver.
pub fn order_plain(schema: &PhysicalSchema, sort: &Sort) -> AppDataResult<Vec<Sql>> {
    let json = type_mapper::json_columns(schema.schema(), None).map_err(internal)?;
    order(schema, sort, &FieldResolver::of(json))
}

/// Sorting restricted to columns that exist (the default `updatedAt` usually does not).
pub fn order(schema: &PhysicalSchema, sort: &Sort, resolver: &FieldResolver) -> AppDataResult<Vec<Sql>> {
    if sort.is_unsorted() {
        return Ok(Vec::new());
    }
    let mut known = IndexSet::new();
    known.insert(ID_COLUMN.to_string());
    for c in mapped_columns(schema, None)? {
        known.insert(c.name().to_string());
    }
    let json = type_mapper::json_columns(schema.schema(), None).map_err(internal)?;
    let mut out = Vec::new();
    for o in &sort.orders {
        if !addressable(&o.property, &known, &json) {
            continue;
        }
        add_order(&mut out, o, resolver.resolve(&o.property).map_err(unsupported_filter)?);
    }
    Ok(out)
}

fn joined_order(schema: &PhysicalSchema, sort: &Sort, resolver: &FieldResolver, attached: &Attached) -> AppDataResult<Vec<Sql>> {
    if sort.is_unsorted() {
        return Ok(Vec::new());
    }
    let mut known = IndexSet::new();
    known.insert(ID_COLUMN.to_string());
    for c in mapped_columns(schema, None)? {
        known.insert(c.name().to_string());
    }
    for j in &attached.joins {
        for c in j.columns() {
            known.insert(j.output_key(c));
        }
    }
    for sq in &attached.sub_queries {
        for m in &sq.measures {
            known.insert(sq.output_key(m));
        }
    }
    let json = type_mapper::json_columns(schema.schema(), None).map_err(internal)?;
    let mut out = Vec::new();
    for o in &sort.orders {
        if !addressable(&o.property, &known, &json) {
            continue;
        }
        add_order(&mut out, o, resolver.resolve(&o.property).map_err(unsupported_filter)?);
    }
    Ok(out)
}

/// Group keys that are a whole BOOLEAN column, so groups read true / false.
pub fn boolean_aliases(query: &AggregateQuery, boolean_columns: &Columns) -> Columns {
    if boolean_columns.is_empty() {
        return Columns::new();
    }
    query
        .group_by
        .iter()
        .flatten()
        .filter(|g| g.bucket.is_none() && g.field.as_ref().is_some_and(|f| boolean_columns.contains(&column_names::column(f))))
        .filter_map(|g| g.resolved_alias())
        .collect()
}

/// The fields sent as null whose column is NOT NULL.
pub fn nulls_on_required(resolved: &PhysicalSchema, data: &Document) -> AppDataResult<Vec<String>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let required: IndexSet<String> =
        mapped_columns(resolved, None)?.into_iter().filter(|c| !c.nullable).map(|c| c.name().to_string()).collect();
    Ok(data
        .iter()
        .filter(|(k, v)| v.is_null() && required.contains(&column_names::column(k)))
        .map(|(k, _)| k.clone())
        .collect())
}

/// The stored row with a PATCH applied: sent replaces, sent-null removes, the id dropped.
pub fn merged(existing: &Document, patch: &Document) -> Document {
    let mut out: Document = existing.iter().filter(|(_, v)| !v.is_null()).map(|(k, v)| (k.clone(), v.clone())).collect();
    for (k, v) in patch {
        if v.is_null() {
            out.shift_remove(k);
        } else {
            out.insert(k.clone(), v.clone());
        }
    }
    out.shift_remove(ID_COLUMN);
    out
}

/// The SET clause of an update; PUT (override) also clears every column left out.
pub fn update_values(
    storage: &Storage,
    resolved: &PhysicalSchema,
    data: &Document,
    override_: Option<bool>,
) -> AppDataResult<Vec<(String, Bind)>> {
    let row = column_names::to_columns(data);
    let d = defs(storage);
    let decoding = Decoding::of(resolved, d.as_ref())?;
    let encoded = value_codec::encode(&row, &decoding.json, &decoding.dates, &decoding.decimals);
    let mut values = Vec::new();
    for (k, v) in &encoded {
        if k != ID_COLUMN {
            values.push((k.clone(), write_bind(v)?));
        }
    }
    if override_ == Some(true) {
        for c in mapped_columns(resolved, d.as_ref())? {
            if !row.contains_key(c.name()) {
                values.push((c.name().to_string(), Bind::Null));
            }
        }
    }
    Ok(values)
}

/// The column MySQL refused a NULL for, from the error text.
pub fn null_column(message: &str) -> Option<String> {
    let start = message.find("Column '")? + "Column '".len();
    let end = message[start..].find('\'')? + start;
    if message[end..].starts_with("' cannot be null") {
        Some(message[start..end].to_string())
    } else {
        None
    }
}

fn is_date_type(t: &str) -> bool {
    let t = t.to_uppercase();
    t.starts_with("DATE") || t.starts_with("TIMESTAMP")
}

fn is_numeric_type(t: &str) -> bool {
    let t = t.to_uppercase();
    ["INT", "BIGINT", "TINYINT", "SMALLINT", "MEDIUMINT", "DOUBLE", "FLOAT", "DECIMAL"].iter().any(|p| t.starts_with(p))
}

/// The head of a field reference: a column, unless it names a join.
pub fn head(field: &str, columns: &IndexMap<String, String>) -> String {
    if columns.contains_key(field) {
        return field.to_string();
    }
    let column = column_names::column(field);
    if columns.contains_key(&column) {
        return column;
    }
    let Some(dot) = field.find('.') else { return column };
    let joined = format!("{}.{}", &field[..dot], column_names::column(&field[dot + 1..]));
    if columns.contains_key(&joined) {
        joined
    } else {
        column_names::column(&field[..dot])
    }
}

impl MySqlAppDataService {
    pub fn new(config: MySqlEngineConfig, hooks: Hooks, cache: &CacheService) -> MySqlAppDataService {
        MySqlAppDataService {
            config,
            hooks,
            cache: cache.clone(),
            pools: Mutex::new(HashMap::new()),
            flags: cache.family::<String, bool>(),
            key_columns: cache.family::<String, Vec<String>>(),
        }
    }

    fn default_credentials(&self) -> Credentials {
        Credentials {
            url: self.config.default_url.clone().filter(|u| !u.trim().is_empty()),
            username: self.config.default_username.clone().filter(|u| !u.trim().is_empty()),
            password: self.config.default_password.clone().filter(|u| !u.trim().is_empty()),
            from_default: false,
        }
    }

    /// One pool per connection document, replaced when its details change.
    pub async fn pool(&self, conn: Option<&Connection>) -> AppDataResult<MySqlPool> {
        let Some(conn) = conn else { return Err(AppDataError::connection_not_available(BACKEND)) };
        let key = format!("{}@{}", conn.id, db::fingerprint(conn));
        let mut pools = self.pools.lock().await;
        if let Some(p) = pools.get(&key) {
            return Ok(p.clone());
        }
        let opts = db::connect_options(&db::credentials(conn, &self.default_credentials()))?;
        let pool = db::create_pool(
            opts,
            self.config.pool_initial_size,
            self.config.pool_max_size,
            self.config.pool_max_idle_minutes,
        )
        .await?;
        let prefix = format!("{}@", conn.id);
        let stale: Vec<String> = pools.keys().filter(|k| k.starts_with(&prefix)).cloned().collect();
        for k in stale {
            if let Some(old) = pools.remove(&k) {
                old.close().await;
            }
        }
        pools.insert(key, pool.clone());
        Ok(pool)
    }

    /// `database(clientCode, storage)`: the data client's schema on the request's surface.
    fn database(&self, cx: &Ctx, client_code: &str, storage: &Storage) -> AppDataResult<String> {
        database_name(&data_client_code(cx, client_code, storage), &storage.app_code, cx.draft)
    }

    /// The resolved schema keyed by column, the only way this backend reads a schema.
    async fn physical_schema(&self, storage: &Storage, draft: bool) -> PhysicalSchema {
        let resolved = self.hooks.resolved_schema_on(storage, draft).await.unwrap_or_default();
        column_names::physical(resolved)
    }

    /// Create the tenant schema and the table if they are not there yet, memoised per
    /// storage version; indexes and keys are brought into line on the way.
    async fn ensure_table(&self, cx: &Ctx, pool: &MySqlPool, client_code: &str, storage: &Storage) -> AppDataResult<String> {
        let db_name = self.database(cx, client_code, storage)?;
        if self.config.skip_provisioning {
            return Ok(db_name);
        }
        let cache_name = table_cache(storage);
        let key = format!("{db_name}{}", storage.version);
        self.flags
            .get_or_load(&cache_name, key, || async {
                self.create_table(cx, pool, &db_name, storage).await?;
                Ok::<_, AppDataError>(Some(true))
            })
            .await?;
        Ok(db_name)
    }

    async fn create_table(&self, cx: &Ctx, pool: &MySqlPool, db_name: &str, storage: &Storage) -> AppDataResult<()> {
        let schema = self.physical_schema(storage, cx.draft).await;
        let columns = mapped_columns(&schema, defs(storage).as_ref())?;
        execute_raw(pool, &format!("CREATE DATABASE IF NOT EXISTS `{db_name}`")).await?;
        execute_raw(
            pool,
            &format!("USE `{db_name}`; {}", table_planner::create_table(&storage.unique_name, &columns)),
        )
        .await?;
        self.sync_indexes(pool, db_name, storage, &schema).await?;
        self.sync_foreign_keys(cx, pool, db_name, storage).await
    }

    async fn sync_indexes(&self, pool: &MySqlPool, db_name: &str, storage: &Storage, schema: &PhysicalSchema) -> AppDataResult<()> {
        for sql in self.planned_index_statements(pool, db_name, storage, schema).await? {
            // One index failing is not a reason to fail the write that triggered it.
            if let Err(e) = execute_raw(pool, &sql).await {
                tracing::error!(db = db_name, table = storage.unique_name, sql, error = %e, "could not apply index");
            }
        }
        Ok(())
    }

    async fn existing_keys(&self, pool: &MySqlPool, db_name: &str, table: &str) -> AppDataResult<Vec<ForeignKey>> {
        let rows = db::fetch_raw(pool, &foreign_keys::existing_sql(db_name, table)).await?;
        Ok(rows
            .iter()
            .map(|r| {
                let v: Vec<String> = r.values().map(Value::java_string).collect();
                ForeignKey {
                    name: v.first().cloned().unwrap_or_default(),
                    column: v.get(1).cloned().unwrap_or_default(),
                    target_table: v.get(2).cloned().unwrap_or_default(),
                    on_delete: v.get(3).cloned().unwrap_or_default(),
                    on_update: v.get(4).cloned().unwrap_or_default(),
                }
            })
            .collect())
    }

    async fn existing_indexes(&self, pool: &MySqlPool, db_name: &str, table: &str) -> AppDataResult<Vec<indexes::Index>> {
        let rows = db::fetch_raw(pool, &indexes::existing_sql(db_name, table)).await?;
        let stats = rows
            .iter()
            .map(|r| {
                let v: Vec<&Value> = r.values().collect();
                let s = |i: usize| v.get(i).map(|x| x.java_string()).unwrap_or_default();
                let non_unique = match v.get(2) {
                    Some(Value::Int(i)) => *i,
                    Some(other) => other.java_string().parse().unwrap_or(1),
                    None => 1,
                };
                let collation = match v.get(4) {
                    None | Some(Value::Null) => None,
                    Some(x) => Some(x.java_string()),
                };
                (s(0), s(1), non_unique, s(3), collation)
            })
            .collect();
        Ok(indexes::from_statistics(stats))
    }

    /// The index DDL this table is missing, without running any of it.
    async fn planned_index_statements(
        &self,
        pool: &MySqlPool,
        db_name: &str,
        storage: &Storage,
        schema: &PhysicalSchema,
    ) -> AppDataResult<Vec<String>> {
        let table = &storage.unique_name;
        let columns = parent_columns(schema, defs(storage).as_ref())?;
        let desired = indexes::desired(storage, &columns);
        let keys = self.existing_keys(pool, db_name, table).await?;
        let existing = self.existing_indexes(pool, db_name, table).await?;
        let key_columns: IndexSet<String> = keys.into_iter().map(|k| k.column).collect();
        Ok(indexes::sync(db_name, table, &existing, &desired, &key_columns))
    }

    fn enforceable_relations(storage: &Storage) -> IndexMap<String, StorageRelation> {
        storage
            .relations
            .iter()
            .flatten()
            .filter(|(_, r)| foreign_keys::enforceable_for(Some(storage), Some(r)))
            .map(|(k, r)| (k.clone(), r.clone()))
            .collect()
    }

    /// The keys this table should carry, each relation's target resolved for this tenant.
    async fn desired_foreign_keys(&self, cx: &Ctx, pool: &MySqlPool, db_name: &str, storage: &Storage) -> AppDataResult<Vec<ForeignKey>> {
        let enforceable = Self::enforceable_relations(storage);
        if enforceable.is_empty() {
            return Ok(Vec::new());
        }
        let client_code = client_code_of(db_name, &storage.app_code);
        let mut targets = IndexMap::new();
        for (field, relation) in &enforceable {
            let name = relation.storage_name.clone().unwrap_or_default();
            let resolved = async {
                let target = self
                    .hooks
                    .read_for_tenant(&name, &storage.app_code, &client_code, cx.draft)
                    .await?
                    .ok_or_else(|| AppDataError::internal(format!("storage {name} does not resolve")))?;
                // An app-level table and a per-tenant one live in different schemas, so no key
                // can join them; the service enforces such a relation itself (no key installed,
                // so `enforces_relation_constraint` answers false).
                if !same_schema(storage, &target) {
                    return Ok(None);
                }
                self.ensure_target_table(pool, db_name, &target).await?;
                Ok::<_, AppDataError>(Some(target.unique_name))
            }
            .await;
            match resolved {
                Ok(None) => {}
                Ok(Some(t)) => {
                    targets.insert(field.clone(), t);
                }
                Err(e) => tracing::error!(
                    relation = field,
                    storage = storage.name,
                    target = name,
                    error = %e,
                    "relation target does not resolve for this client; its delete constraint is NOT being enforced"
                ),
            }
        }
        Ok(foreign_keys::desired(&storage.unique_name, &enforceable, &targets))
    }

    /// The referenced table, created but not completed (no keys, so two storages pointing
    /// at each other cannot wait on each other).
    async fn ensure_target_table(&self, pool: &MySqlPool, db_name: &str, target: &Storage) -> AppDataResult<()> {
        let schema = self.physical_schema(target, is_draft(db_name)).await;
        let columns = mapped_columns(&schema, defs(target).as_ref())?;
        execute_raw(pool, &format!("USE `{db_name}`; {}", table_planner::create_table(&target.unique_name, &columns))).await?;
        Ok(())
    }

    async fn sync_foreign_keys(&self, cx: &Ctx, pool: &MySqlPool, db_name: &str, storage: &Storage) -> AppDataResult<()> {
        let desired = self.desired_foreign_keys(cx, pool, db_name, storage).await?;
        let table = &storage.unique_name;
        let existing = self.existing_keys(pool, db_name, table).await?;
        let statements = foreign_keys::sync(db_name, table, &existing, &desired);
        if statements.is_empty() {
            return Ok(());
        }
        for sql in &statements {
            let adding = desired.iter().find(|fk| sql.contains(&format!("`{}`", fk.name)));
            match adding {
                Some(fk) if sql.contains("ADD CONSTRAINT") => {
                    let orphans = count_raw(pool, &foreign_keys::orphan_count(db_name, table, fk)).await?;
                    if orphans > 0 {
                        tracing::error!(
                            key = fk.name,
                            db = db_name,
                            table,
                            orphans,
                            target = fk.target_table,
                            "foreign key NOT installed and its constraint is NOT being enforced: rows reference a missing target"
                        );
                        continue;
                    }
                    execute_raw(pool, sql).await?;
                }
                _ => {
                    execute_raw(pool, sql).await?;
                }
            }
        }
        self.cache.evict_all_everywhere(&foreign_key_cache(storage)).await;
        Ok(())
    }

    async fn planned_foreign_key_statements(&self, cx: &Ctx, pool: &MySqlPool, db_name: &str, storage: &Storage) -> AppDataResult<Vec<String>> {
        let desired = self.desired_foreign_keys(cx, pool, db_name, storage).await?;
        let existing = self.existing_keys(pool, db_name, &storage.unique_name).await?;
        Ok(foreign_keys::sync(db_name, &storage.unique_name, &existing, &desired))
    }

    async fn read_row(&self, pool: &MySqlPool, db_name: &str, storage: &Storage, schema: &PhysicalSchema, id: &str)
        -> AppDataResult<Option<Document>> {
        let decoding = Decoding::of(schema, defs(storage).as_ref())?;
        let select = Select::star(table(db_name, storage)).filter(id_field().equal(Sql::param(Bind::Text(id.into()))));
        let rows = fetch(pool, &select.to_sql()).await?;
        Ok(rows.into_iter().next().map(|r| decoding.row(r, schema)))
    }

    fn resolver(&self, schema: &PhysicalSchema, defs: Option<&ColumnDefinitions>, attached: &Attached, text: IndexSet<String>)
        -> AppDataResult<FieldResolver> {
        let json = type_mapper::json_columns(schema.schema(), defs).map_err(internal)?;
        let r = if attached.is_empty() {
            FieldResolver::of(json)
        } else {
            FieldResolver::joined(
                PARENT,
                json,
                attached.joins.iter().map(|j| (j.alias.clone(), j.clone())).collect(),
                subquery_planner::by_alias(&attached.sub_queries),
            )
        };
        Ok(r.with_text_columns(text).with_stemming(self.config.text_search_stemming))
    }

    fn can_read(&self, cx: &Ctx, target: &Storage) -> AppDataResult<()> {
        if self.hooks.has_authority(cx, target.read_auth.as_deref()) {
            Ok(())
        } else {
            Err(AppDataError::forbidden_read_storage(&target.name))
        }
    }

    async fn resolve_joins(
        &self,
        cx: &Ctx,
        pool: &MySqlPool,
        client_code: &str,
        storage: &Storage,
        schema: &PhysicalSchema,
        joins: Option<&Vec<StorageJoin>>,
    ) -> AppDataResult<Vec<JoinedTable>> {
        let Some(joins) = joins.filter(|j| !j.is_empty()) else { return Ok(Vec::new()) };
        let d = defs(storage);
        let parent = parent_columns(schema, d.as_ref())?;
        let json = type_mapper::json_columns(schema.schema(), d.as_ref()).map_err(internal)?;
        if let Some(invalid) = join_planner::check(storage, Some(joins), &parent, &json) {
            return Err(AppDataError::invalid_join(&invalid));
        }
        let mut out = Vec::new();
        for join in joins {
            let relation_name = join.relation.clone().unwrap_or_default();
            let relation = storage.relation(&relation_name).cloned().unwrap_or_default();
            let target_name = relation.storage_name.clone().unwrap_or_default();
            let target = self
                .hooks
                .read_for_tenant(&target_name, &storage.app_code, client_code, cx.draft)
                .await?
                .ok_or_else(|| {
                    AppDataError::invalid_join(&format!(
                        "relation '{relation_name}' points at storage '{target_name}', which does not resolve for this client"
                    ))
                })?;
            self.can_read(cx, &target)?;
            let target_db = self.ensure_table(cx, pool, client_code, &target).await?;
            let target_schema = self.physical_schema(&target, cx.draft).await;
            let td = defs(&target);
            let target_field = match relation.field_name.as_ref().filter(|f| !f.trim().is_empty()) {
                None => ID_COLUMN.to_string(),
                Some(f) => column_names::column(f),
            };
            let mut joined = JoinedTable::new(
                &join.resolved_alias().unwrap_or_default(),
                Sql::name(&[&target_db, &target.unique_name]),
                &relation_name,
                &target_field,
                join.join_type.unwrap_or(JoinType::Left),
                column_types(&target_schema, td.as_ref())?,
                type_mapper::json_columns(target_schema.schema(), td.as_ref()).map_err(internal)?,
                type_mapper::date_string_columns(target_schema.schema(), td.as_ref()).map_err(internal)?,
            );
            joined.field_names = target_schema.field_names().clone();
            joined.boolean_columns = type_mapper::boolean_columns(target_schema.schema(), td.as_ref()).map_err(internal)?;
            out.push(joined);
        }
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    async fn resolve_sub_queries(
        &self,
        cx: &Ctx,
        pool: &MySqlPool,
        client_code: &str,
        storage: &Storage,
        schema: &PhysicalSchema,
        sub_queries: Option<&Vec<StorageSubQuery>>,
        taken: &IndexSet<String>,
    ) -> AppDataResult<Vec<SubQueryTable>> {
        let Some(subs) = sub_queries.filter(|s| !s.is_empty()) else { return Ok(Vec::new()) };
        let mut children = Vec::new();
        for sq in subs {
            let name = sq.storage.clone().unwrap_or_default();
            children.push(self.hooks.read_for_tenant(&name, &storage.app_code, client_code, cx.draft).await?);
        }
        let parent = parent_columns(schema, defs(storage).as_ref())?;
        if let Some(invalid) = subquery_planner::check(storage, Some(subs), &children, taken, &parent) {
            return Err(AppDataError::invalid_join(&invalid));
        }
        let mut out = Vec::new();
        for (sq, child) in subs.iter().zip(children) {
            let Some(child) = child else { continue };
            out.push(self.build_sub_query(cx, pool, client_code, sq, &child).await?);
        }
        Ok(out)
    }

    async fn build_sub_query(&self, cx: &Ctx, pool: &MySqlPool, client_code: &str, sq: &StorageSubQuery, child: &Storage)
        -> AppDataResult<SubQueryTable> {
        let relation_name = sq.relation.clone().unwrap_or_default();
        let relation = child.relation(&relation_name).cloned().unwrap_or_default();
        self.can_read(cx, child)?;
        let child_db = self.ensure_table(cx, pool, client_code, child).await?;
        let child_schema = self.physical_schema(child, cx.draft).await;
        let child_json = type_mapper::json_columns(child_schema.schema(), defs(child).as_ref()).map_err(internal)?;
        let where_ = match &sq.condition {
            None => None,
            Some(c) => Some(filter_builder::build_for_read(Some(c), &FieldResolver::of(child_json.clone())).map_err(unsupported_filter)?),
        };
        let having = match &sq.having {
            None => None,
            Some(h) => Some(filter_builder::build_json(Some(h), IndexSet::new()).map_err(unsupported_filter)?),
        };
        let derived = subquery_planner::derived(
            &Sql::name(&[&child_db, &child.unique_name]),
            sq,
            &relation_name,
            where_,
            having,
            child_json,
        )
        .map_err(unsupported_filter)?;
        let parent_field = match relation.field_name.as_ref().filter(|f| !f.trim().is_empty()) {
            None => ID_COLUMN.to_string(),
            Some(f) => column_names::column(f),
        };
        Ok(SubQueryTable {
            alias: sq.resolved_alias().unwrap_or_default(),
            derived,
            key_column: subquery_planner::KEY.to_string(),
            parent_field,
            measures: subquery_planner::measures(sq),
            required: sq.required != Some(false),
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn resolve_attached(
        &self,
        cx: &Ctx,
        pool: &MySqlPool,
        client_code: &str,
        storage: &Storage,
        schema: &PhysicalSchema,
        joins: Option<&Vec<StorageJoin>>,
        sub_queries: Option<&Vec<StorageSubQuery>>,
    ) -> AppDataResult<Attached> {
        if joins.is_none_or(|j| j.is_empty()) && sub_queries.is_none_or(|s| s.is_empty()) {
            return Ok(Attached::default());
        }
        let joins = self.resolve_joins(cx, pool, client_code, storage, schema, joins).await?;
        let taken: IndexSet<String> = joins.iter().map(|j| j.alias.clone()).collect();
        let sub_queries = self.resolve_sub_queries(cx, pool, client_code, storage, schema, sub_queries, &taken).await?;
        Ok(Attached { joins, sub_queries })
    }

    fn from_clause(db_name: &str, storage: &Storage, attached: &Attached) -> Sql {
        if attached.is_empty() {
            return table(db_name, storage);
        }
        subquery_planner::attach(join_planner::from(&table(db_name, storage), &attached.joins), PARENT, &attached.sub_queries)
    }

    fn decode_joined(&self, flat: Document, decoding: &Decoding, attached: &Attached) -> Document {
        let mut decoded = decoding.columns(flat);
        for join in &attached.joins {
            let prefixed = |cols: &IndexSet<String>| -> Columns { cols.iter().map(|c| join.output_key(c)).collect() };
            let decimals: IndexSet<String> = join
                .column_types
                .iter()
                .filter(|(_, t)| type_mapper::is_decimal(t))
                .map(|(c, _)| c.clone())
                .collect();
            let (j, d, m, b) = (
                prefixed(&join.json_columns),
                prefixed(&join.date_columns),
                prefixed(&decimals),
                prefixed(&join.boolean_columns),
            );
            if !j.is_empty() || !d.is_empty() || !m.is_empty() || !b.is_empty() {
                decoded = value_codec::decode(decoded, &j, &d, &m, &b);
            }
        }
        join_planner::nest(decoded, &attached.joins, &attached.sub_queries)
    }

    #[allow(clippy::too_many_arguments)]
    async fn rows(
        &self,
        pool: &MySqlPool,
        db_name: &str,
        storage: &Storage,
        schema: &PhysicalSchema,
        query: &Query,
        page: &Pageable,
        attached: &Attached,
    ) -> AppDataResult<Vec<Document>> {
        let d = defs(storage);
        let decoding = Decoding::of(schema, d.as_ref())?;
        let resolver = self.resolver(schema, d.as_ref(), attached, text_columns(storage, schema, d.as_ref())?)?;
        let condition = filter_builder::build_for_read(query.condition.as_ref(), &resolver).map_err(unsupported_filter)?;

        if attached.is_empty() {
            let select = Select {
                fields: projection(schema, query)?,
                from: table(db_name, storage),
                where_: Some(condition),
                order_by: order(schema, &page.sort, &resolver)?,
                limit: Some((page.page_size(), page.offset())),
                ..Default::default()
            };
            let rows = fetch(pool, &select.to_sql()).await?;
            return Ok(rows.into_iter().map(|r| decoding.row(r, schema)).collect());
        }

        let mut selection = join_planner::selection(&selected_parent_columns(schema, query)?, &attached.joins);
        selection.extend(subquery_planner::selection(&attached.sub_queries));
        let select = Select {
            fields: selection,
            from: Self::from_clause(db_name, storage, attached),
            where_: Some(condition),
            order_by: joined_order(schema, &page.sort, &resolver, attached)?,
            limit: Some((page.page_size(), page.offset())),
            ..Default::default()
        };
        let rows = fetch(pool, &select.to_sql()).await?;
        Ok(rows.into_iter().map(|r| schema.to_fields(self.decode_joined(r, &decoding, attached))).collect())
    }

    async fn count_rows(
        &self,
        pool: &MySqlPool,
        db_name: &str,
        storage: &Storage,
        schema: &PhysicalSchema,
        query: &Query,
        attached: &Attached,
    ) -> AppDataResult<i64> {
        let d = defs(storage);
        let resolver = self.resolver(schema, d.as_ref(), attached, text_columns(storage, schema, d.as_ref())?)?;
        let condition = filter_builder::build_for_read(query.condition.as_ref(), &resolver).map_err(unsupported_filter)?;
        let select = Select::count(Self::from_clause(db_name, storage, attached)).filter(condition);
        count(pool, &select.to_sql()).await
    }

    fn check_aggregate_fields(storage: &Storage, schema: &PhysicalSchema, query: &AggregateQuery, attached: &Attached)
        -> AppDataResult<()> {
        let columns = {
            let mut c = column_types(schema, defs(storage).as_ref())?;
            for j in &attached.joins {
                for (col, t) in &j.column_types {
                    c.insert(j.output_key(col), t.clone());
                }
            }
            for sq in &attached.sub_queries {
                for m in &sq.measures {
                    c.insert(sq.output_key(m), "DOUBLE".to_string());
                }
            }
            c
        };
        for g in query.group_by.iter().flatten() {
            let field = g.field.clone().unwrap_or_default();
            let h = head(&field, &columns);
            let Some(t) = columns.get(&h) else {
                return Err(AppDataError::invalid_aggregation(&format!("storage {} declares no field '{field}'", storage.name)));
            };
            let Some(bucket) = g.bucket else { continue };
            let date = is_date_type(t);
            let numeric = is_numeric_type(t);
            if !date && !numeric {
                return Err(AppDataError::invalid_aggregation(&format!(
                    "field '{field}' is {t}, which is neither a date nor a number, so it cannot be bucketed by {}",
                    bucket.name()
                )));
            }
            if date && g.encoding.is_some() {
                return Err(AppDataError::invalid_aggregation(&format!(
                    "field '{field}' is a {t} column, so it needs no encoding; an encoding here would be applied to something that is not an epoch number"
                )));
            }
            if numeric && g.encoding.is_none() {
                return Err(AppDataError::invalid_aggregation(&format!(
                    "field '{field}' is {t}, so bucketing it needs an encoding (EPOCH_SECONDS or EPOCH_MILLIS); seconds cannot be told from milliseconds by the type"
                )));
            }
        }
        for a in query.aggregations.iter().flatten() {
            let Some(field) = a.field.as_ref().filter(|f| !f.trim().is_empty()) else { continue };
            let h = head(field, &columns);
            let Some(t) = columns.get(&h) else {
                return Err(AppDataError::invalid_aggregation(&format!("storage {} declares no field '{field}'", storage.name)));
            };
            let f = a.function.unwrap_or(AggregateFunction::Count);
            if matches!(f, AggregateFunction::Sum | AggregateFunction::Avg) && !is_numeric_type(t) && !type_mapper::is_json(t) {
                return Err(AppDataError::invalid_aggregation(&format!(
                    "cannot {f} field '{field}', which is {t}; a non-numeric value casts to zero rather than failing"
                )));
            }
        }
        Ok(())
    }

    async fn check_zones(&self, pool: &MySqlPool, query: &AggregateQuery) -> AppDataResult<()> {
        for zone in aggregate_builder::named_zones(query) {
            let known = count_raw(pool, &aggregate_builder::zone_check(&zone)).await? == 1;
            if !known {
                return Err(AppDataError::invalid_aggregation(&format!(
                    "this MySQL server does not know the timezone '{zone}'; its time zone tables have not been loaded, so bucketing in that zone would silently return nothing. Load them with mysql_tzinfo_to_sql, or use UTC"
                )));
            }
        }
        Ok(())
    }

    // ---------------------------------------------------------------- versions

    fn version_table(db_name: &str, storage: &Storage) -> Sql {
        Sql::name(&[db_name, &version_table::name_for(&storage.unique_name)])
    }

    async fn ensure_version_table(&self, pool: &MySqlPool, db_name: &str, storage: &Storage) -> AppDataResult<()> {
        self.flags
            .get_or_load(&version_cache(storage), db_name.to_string(), || async {
                execute_raw(pool, &version_table::create_table(db_name, &storage.unique_name)).await?;
                Ok::<_, AppDataError>(Some(true))
            })
            .await?;
        Ok(())
    }

    /// One history row; the snapshot only for a VERSIONED storage.
    #[allow(clippy::too_many_arguments)]
    async fn add_version(
        &self,
        cx: &Ctx,
        pool: &MySqlPool,
        db_name: &str,
        storage: &Storage,
        id: &str,
        operation: &str,
        snapshot: &Document,
        message: Option<&str>,
    ) -> AppDataResult<()> {
        if !storage.keeps_history() {
            return Ok(());
        }
        self.ensure_version_table(pool, db_name, storage).await?;
        let mut values = vec![
            (ID_COLUMN.to_string(), Bind::Text(ulid())),
            (version_table::OBJECT_ID.to_string(), Bind::Text(id.to_string())),
            (version_table::MESSAGE.to_string(), message.map(|m| Bind::Text(m.into())).unwrap_or(Bind::Null)),
            (version_table::CREATED_AT.to_string(), Bind::DateTime(chrono::Utc::now().naive_utc())),
            (version_table::OPERATION.to_string(), Bind::Text(operation.into())),
            (version_table::CREATED_BY.to_string(), cx.user_id.map(|u| Bind::Int(u as i64)).unwrap_or(Bind::Null)),
        ];
        if storage.versioned() {
            values.push((version_table::OBJECT.to_string(), Bind::Text(Value::Object(snapshot.clone()).to_java_json())));
        }
        execute(pool, &sql::insert(&Self::version_table(db_name, storage), &values)).await?;
        // Housekeeping: never fails the write.
        let _ = self.trim_versions(pool, db_name, storage, id).await;
        Ok(())
    }

    async fn trim_versions(&self, pool: &MySqlPool, db_name: &str, storage: &Storage, id: &str) -> AppDataResult<()> {
        let retention = VersionRetention::for_storage(storage, self.config.retention);
        version_table::trim(pool, &Self::version_table(db_name, storage), id, retention).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn record_delete(
        &self,
        cx: &Ctx,
        pool: &MySqlPool,
        db_name: &str,
        storage: &Storage,
        id: &str,
        delete_version: Option<bool>,
        row: &Document,
    ) -> AppDataResult<()> {
        let Some(delete_version) = delete_version else { return Ok(()) };
        if !storage.keeps_history() {
            return Ok(());
        }
        if delete_version {
            self.ensure_version_table(pool, db_name, storage).await?;
            let cond = Sql::name(&[version_table::OBJECT_ID]).equal(Sql::param(Bind::Text(id.into())));
            execute(pool, &sql::delete(&Self::version_table(db_name, storage), &cond)).await?;
            return Ok(());
        }
        if row.is_empty() {
            return Ok(());
        }
        self.add_version(cx, pool, db_name, storage, id, "DELETE", row, None).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn record_bulk_delete(
        &self,
        cx: &Ctx,
        pool: &MySqlPool,
        db_name: &str,
        storage: &Storage,
        schema: &PhysicalSchema,
        condition: &Cond,
        delete_version: Option<bool>,
    ) -> AppDataResult<()> {
        let Some(delete_version) = delete_version else { return Ok(()) };
        if !storage.keeps_history() {
            return Ok(());
        }
        if delete_version {
            self.ensure_version_table(pool, db_name, storage).await?;
            let ids = fetch(pool, &Select::fields(vec![id_field()], table(db_name, storage)).filter(condition.clone()).to_sql()).await?;
            let ids: Vec<Sql> = ids
                .iter()
                .map(|r| Sql::param(Bind::Text(r.values().next().map(Value::java_string).unwrap_or_else(|| "null".into()))))
                .collect();
            for batch in ids.chunks(VERSION_PURGE_BATCH) {
                let cond = Sql::name(&[version_table::OBJECT_ID]).in_list(batch.to_vec());
                execute(pool, &sql::delete(&Self::version_table(db_name, storage), &cond)).await?;
            }
            return Ok(());
        }
        let decoding = Decoding::of(schema, defs(storage).as_ref())?;
        let rows = fetch(pool, &Select::star(table(db_name, storage)).filter(condition.clone()).to_sql()).await?;
        for r in rows {
            let row = decoding.row(r, schema);
            let id = row.get(ID_COLUMN).map(Value::java_string).unwrap_or_else(|| "null".into());
            self.add_version(cx, pool, db_name, storage, &id, "DELETE", &row, None).await?;
        }
        Ok(())
    }

    /// The fields of this storage's snapshots that are BOOLEAN today.
    async fn snapshot_booleans(&self, storage: &Storage, draft: bool) -> Columns {
        let schema = self.physical_schema(storage, draft).await;
        Decoding::of(&schema, defs(storage).as_ref()).map(|d| d.boolean_fields(&schema)).unwrap_or_default()
    }

    fn decode_version(raw: Document, booleans: &Columns) -> Document {
        let object: Columns = [version_table::OBJECT.to_string()].into_iter().collect();
        let mut row = value_codec::decode(raw, &object, &Columns::new(), &Columns::new(), &Columns::new());
        if !booleans.is_empty() {
            if let Some(Value::Object(snapshot)) = row.get(version_table::OBJECT).cloned() {
                row.insert(version_table::OBJECT.into(), Value::Object(value_codec::booleans(snapshot, booleans)));
            }
        }
        row
    }

    // ---------------------------------------------------------------- draft helpers

    async fn shared_columns(&self, pool: &MySqlPool, live_db: &str, draft_db: &str, table_name: &str) -> AppDataResult<Vec<String>> {
        let live = migration::columns(pool, live_db, table_name).await?;
        let draft: IndexSet<String> = migration::columns(pool, draft_db, table_name).await?.into_iter().map(|c| c.name().to_string()).collect();
        let mut shared = vec![ID_COLUMN.to_string()];
        for c in live {
            if draft.contains(c.name()) {
                shared.push(c.name().to_string());
            }
        }
        Ok(shared)
    }

    /// Statements on ONE connection with foreign keys unchecked, turned back on before the
    /// connection returns to the pool, whatever happened.
    async fn without_foreign_key_checks(&self, pool: &MySqlPool, statements: &[Sql]) -> AppDataResult<Vec<u64>> {
        let mut conn = pool.acquire().await?;
        let mut result = db::execute_raw_on(&mut conn, "SET FOREIGN_KEY_CHECKS = 0").await.map(|_| Vec::new());
        for s in statements {
            let Ok(out) = result.as_mut() else { break };
            match db::execute_on(&mut conn, s).await {
                Ok(n) => out.push(n),
                Err(e) => result = Err(e),
            }
        }
        if let Err(e) = db::execute_raw_on(&mut conn, "SET FOREIGN_KEY_CHECKS = 1").await {
            tracing::error!(error = %e, "could not turn foreign key checks back on before releasing a connection");
            conn.detach();
        }
        result
    }

    #[allow(clippy::too_many_arguments)]
    async fn draft_copy_condition(
        &self,
        live_db: &str,
        table_name: &str,
        storage: &Storage,
        filter: Option<&DraftCopyFilter>,
        followed: &HashMap<String, Storage>,
        draft: bool,
        draft_db_of: &(dyn Fn(&Storage) -> AppDataResult<String> + Send + Sync),
    ) -> AppDataResult<Cond> {
        let Some(f) = filter else { return Ok(Cond::None) };
        let base = match &f.condition {
            None => Cond::None,
            Some(c) => {
                let schema = self.physical_schema(storage, draft).await;
                let json = type_mapper::json_columns(schema.schema(), defs(storage).as_ref()).map_err(internal)?;
                filter_builder::build_for_read(Some(c), &FieldResolver::of(json)).map_err(unsupported_filter)?
            }
        };
        if !f.has_follow() {
            return Ok(base);
        }
        let mut each = Vec::new();
        let mut filled = Vec::new();
        for follow in f.follow.iter().flatten() {
            let target = followed
                .get(&follow.storage)
                .ok_or_else(|| AppDataError::internal(format!("NullPointerException: storage {}", follow.storage)))?;
            // A followed storage can sit in the other schema (app level on one side only), so
            // its draft table is named from its own level.
            let ref_draft_db = draft_db_of(target)?;
            let column = Sql::name(&[live_db, table_name, &follow.field]);
            let inner = Select::fields(
                vec![Sql::name(&[&ref_draft_db, &target.unique_name, &follow.ref_field_or_default()])],
                Sql::name(&[&ref_draft_db, &target.unique_name]),
            );
            each.push(Cond::or(vec![column.is_null(), column.in_select(inner.to_sql())]));
            filled.push(column.is_not_null());
        }
        Ok(base.and_also(Cond::and(each)).and_also(Cond::or(filled)))
    }

    // ---------------------------------------------------------------- reconcile, drift

    /// Bring every tenant's table into line with the definition as it now stands.
    pub async fn reconcile(&self, conn: Option<&Connection>, app_code: &str, storage: &Storage, applied_by: Option<&str>)
        -> AppDataResult<FanOutReport> {
        if conn.is_none() {
            return Ok(FanOutReport::default());
        }
        let pool = self.pool(conn).await?;
        let table_name = storage.unique_name.clone();
        let all = migration::tenants_with_table(&pool, app_code, &table_name).await?;
        let tenants = self.tenants_owning(app_code, storage, &table_name, all).await;
        if tenants.is_empty() {
            return Ok(FanOutReport::default());
        }
        let (desired, unresolved) = self.desired_by_tenant(app_code, storage, &tenants).await;

        let live: Vec<String> = tenants.iter().filter(|d| desired.contains_key(*d) && !is_draft(d)).cloned().collect();
        let draft: Vec<String> = tenants.iter().filter(|d| desired.contains_key(*d) && is_draft(d)).cloned().collect();

        let version = storage.version;
        let live_report = self.surface(&pool, &live, &desired, storage, &table_name, version, "LIVE", applied_by).await?;
        let draft_report = self.surface(&pool, &draft, &desired, storage, &table_name, version, "DRAFT", applied_by).await?;
        let mut report = FanOutReport::merge(live_report, draft_report);
        let issue = |surface: &str| migration::Issue::new(&storage.name, &table_name, Some(surface), applied_by).version(version);
        let surface_of = |db_name: &str| if is_draft(db_name) { "DRAFT" } else { "LIVE" };
        for (db_name, why) in unresolved {
            migration::record_issue(&pool, &db_name, &issue(surface_of(&db_name)).kind(migration::IssueKind::NoDefinition).detail(&why)).await;
            report.by_tenant.insert(db_name.clone(), MigrationOutcome::needs_attention(&why));
            report.blocked.push(db_name);
        }

        let cx = Ctx::default();
        for db_name in &tenants {
            let tcx = cx.on_draft(is_draft(db_name));
            let synced = async {
                let ts = self
                    .hooks
                    .read_for_tenant(&storage.name, app_code, &client_code_of(db_name, app_code), tcx.draft)
                    .await?;
                if let Some(ts) = ts {
                    let schema = self.physical_schema(&ts, tcx.draft).await;
                    self.sync_indexes(&pool, db_name, &ts, &schema).await?;
                }
                Ok::<_, AppDataError>(())
            }
            .await;
            if let Err(e) = synced {
                let detail = format!("could not sync indexes: {e}");
                migration::record_issue(&pool, db_name, &issue(surface_of(db_name)).kind(migration::IssueKind::IndexSync).detail(&detail)).await;
            }
        }
        for db_name in &tenants {
            let tcx = cx.on_draft(is_draft(db_name));
            let synced = async {
                let ts = self
                    .hooks
                    .read_for_tenant(&storage.name, app_code, &client_code_of(db_name, app_code), tcx.draft)
                    .await?;
                if let Some(ts) = ts {
                    self.sync_foreign_keys(&tcx, &pool, db_name, &ts).await?;
                }
                Ok::<_, AppDataError>(())
            }
            .await;
            if let Err(e) = synced {
                let detail = format!("could not sync foreign keys: {e}");
                migration::record_issue(&pool, db_name, &issue(surface_of(db_name)).kind(migration::IssueKind::ForeignKeySync).detail(&detail)).await;
            }
        }
        Ok(report)
    }

    async fn tenants_owning(&self, app_code: &str, storage: &Storage, table_name: &str, tenants: Vec<String>) -> Vec<String> {
        let mut out = Vec::new();
        for db_name in tenants {
            let ts = self
                .hooks
                .read_for_tenant(&storage.name, app_code, &client_code_of(&db_name, app_code), is_draft(&db_name))
                .await;
            let own = match ts {
                Ok(Some(ts)) => ts.unique_name.trim().is_empty() || ts.unique_name == table_name,
                _ => true,
            };
            if own {
                out.push(db_name);
            } else {
                tracing::info!(db = db_name, table = table_name, "skipping: that tenant's storage is another table");
            }
        }
        out
    }

    /// Each tenant's columns, and why for the tenants that have none.
    async fn desired_by_tenant(&self, app_code: &str, storage: &Storage, tenants: &[String])
        -> (IndexMap<String, Vec<MySqlColumn>>, IndexMap<String, String>) {
        let mut out = IndexMap::new();
        let mut unresolved = IndexMap::new();
        for db_name in tenants {
            let ts = self
                .hooks
                .read_for_tenant(&storage.name, app_code, &client_code_of(db_name, app_code), is_draft(db_name))
                .await;
            let why = match ts {
                Ok(Some(ts)) => {
                    let schema = self.physical_schema(&ts, is_draft(db_name)).await;
                    match mapped_columns(&schema, defs(&ts).as_ref()) {
                        Ok(cols) => {
                            out.insert(db_name.clone(), cols);
                            continue;
                        }
                        Err(e) => format!("the storage's schema does not map to columns: {e}"),
                    }
                }
                Ok(None) => "no storage definition resolves for this client".to_string(),
                Err(e) => format!("the storage definition could not be read for this client: {e}"),
            };
            unresolved.insert(db_name.clone(), why);
        }
        (out, unresolved)
    }

    #[allow(clippy::too_many_arguments)]
    async fn surface(
        &self,
        pool: &MySqlPool,
        tenants: &[String],
        desired: &IndexMap<String, Vec<MySqlColumn>>,
        storage: &Storage,
        table_name: &str,
        version: i32,
        surface: &str,
        applied_by: Option<&str>,
    ) -> AppDataResult<FanOutReport> {
        if tenants.is_empty() {
            return Ok(FanOutReport::default());
        }
        // Planned one tenant at a time, so a tenant whose table cannot be read is that
        // tenant's issue and the others still migrate.
        let mut plans = Vec::new();
        let mut unplanned = IndexMap::new();
        for db_name in tenants {
            match migration::plan_tenants(pool, std::slice::from_ref(db_name), table_name, version, desired).await {
                Ok(p) => plans.extend(p),
                Err(e) => {
                    let detail = format!("could not plan the change: {}", db::message(&e));
                    let issue = migration::Issue::new(&storage.name, table_name, Some(surface), applied_by)
                        .version(version)
                        .kind(migration::IssueKind::PlanFailed)
                        .detail(&detail);
                    migration::record_issue(pool, db_name, &issue).await;
                    unplanned.insert(db_name.clone(), MigrationOutcome::failed(&detail, 0, 0));
                }
            }
        }
        let mut report = migration::apply(pool, &plans, &storage.name, table_name, None, version, surface, applied_by).await?;
        for (db_name, o) in unplanned {
            report.blocked.push(db_name.clone());
            report.by_tenant.insert(db_name, o);
        }
        Ok(report)
    }

    /// Finish any migration on this connection that nobody is driving.
    pub async fn sweep_interrupted(&self, conn: Option<&Connection>, stale_after_seconds: i32) -> AppDataResult<RecoveryReport> {
        if conn.is_none() {
            return Ok(RecoveryReport::default());
        }
        let pool = self.pool(conn).await?;
        migration::sweep(&pool, stale_after_seconds).await
    }

    /// How far each tenant got, from its own journal.
    pub async fn migration_status(&self, conn: Option<&Connection>, app_code: &str, storage: &Storage)
        -> AppDataResult<Vec<TenantProgress>> {
        let tenants = self.migration_tenants(conn, app_code, storage).await?;
        self.migration_status_of(conn, app_code, storage, &tenants).await
    }

    /// The tenant schemas that hold this storage's table.
    pub async fn migration_tenants(&self, conn: Option<&Connection>, app_code: &str, storage: &Storage)
        -> AppDataResult<Vec<String>> {
        if conn.is_none() {
            return Ok(Vec::new());
        }
        let pool = self.pool(conn).await?;
        migration::tenants_with_table(&pool, app_code, &storage.unique_name).await
    }

    /// How far each of these tenants got, with its client and newest issues.
    pub async fn migration_status_of(&self, conn: Option<&Connection>, app_code: &str, storage: &Storage, tenants: &[String])
        -> AppDataResult<Vec<TenantProgress>> {
        if conn.is_none() || tenants.is_empty() {
            return Ok(Vec::new());
        }
        let pool = self.pool(conn).await?;
        let mut out = migration::status(&pool, tenants, &storage.name).await?;
        for t in &mut out {
            t.client_code = client_code_of(&t.database, app_code);
        }
        Ok(out)
    }

    /// What every tenant's table has that its definition does not, and the reverse.
    /// Read only.
    pub async fn drift(&self, conn: Option<&Connection>, app_code: &str, storage: &Storage) -> AppDataResult<Vec<Report>> {
        if conn.is_none() {
            return Ok(Vec::new());
        }
        let pool = self.pool(conn).await?;
        let mut out = Vec::new();
        for db_name in migration::tenant_schemas(&pool, app_code).await? {
            let cx = Ctx::default().on_draft(is_draft(&db_name));
            let report = async {
                let Some(ts) = self
                    .hooks
                    .read_for_tenant(&storage.name, app_code, &client_code_of(&db_name, app_code), cx.draft)
                    .await?
                else {
                    return Ok::<_, AppDataError>(None);
                };
                let table_name = if ts.unique_name.trim().is_empty() { storage.unique_name.clone() } else { ts.unique_name.clone() };
                self.drift_for_table(&cx, &pool, &db_name, &ts, &table_name).await.map(Some)
            }
            .await;
            match report {
                Ok(Some(r)) => out.push(r),
                Ok(None) => {}
                Err(e) => tracing::error!(storage = storage.name, db = db_name, error = %e, "could not read drift"),
            }
        }
        Ok(out)
    }

    async fn drift_for_table(&self, cx: &Ctx, pool: &MySqlPool, db_name: &str, ts: &Storage, table_name: &str)
        -> AppDataResult<Report> {
        let schema = self.physical_schema(ts, cx.draft).await;
        if !migration::table_exists(pool, db_name, table_name).await? {
            return Ok(drift::of(db_name, table_name, false, &[], &[], vec![], vec![]));
        }
        let existing = migration::columns(pool, db_name, table_name).await?;
        let idx = self.planned_index_statements(pool, db_name, ts, &schema).await?;
        let keys = self.planned_foreign_key_statements(cx, pool, db_name, ts).await?;
        let desired = mapped_columns(&schema, defs(ts).as_ref())?;
        Ok(drift::of(db_name, table_name, true, &existing, &desired, idx, keys))
    }

    /// Apply what the drift report found; without approval only what cannot lose
    /// anything.
    pub async fn repair_drift(&self, conn: Option<&Connection>, app_code: &str, storage: &Storage, approved: bool)
        -> AppDataResult<Vec<DriftRepair>> {
        if conn.is_none() {
            return Ok(Vec::new());
        }
        let pool = self.pool(conn).await?;
        let mut out = Vec::new();
        for report in self.drift(conn, app_code, storage).await? {
            let plan = drift::repair_statements(&report, approved);
            let withheld = drift::withheld_statements(&report, approved);
            if plan.is_empty() {
                out.push(DriftRepair { db: report.db.clone(), table_missing: !report.table_exists, applied: vec![], withheld, failed: vec![] });
                continue;
            }
            let mut applied = Vec::new();
            let mut failed = Vec::new();
            for sql in plan {
                match execute_raw(&pool, &sql).await {
                    Ok(_) => applied.push(sql),
                    Err(e) => {
                        tracing::error!(db = report.db, sql, error = %e, "drift repair failed");
                        failed.push(sql);
                    }
                }
            }
            out.push(DriftRepair { db: report.db.clone(), table_missing: false, applied, withheld, failed });
        }
        Ok(out)
    }

    /// The tables of a storage on both surfaces, for callers that evict.
    pub async fn evict_table_caches(&self, storage: &Storage) {
        self.cache.evict_all_everywhere(&table_cache(storage)).await;
        self.cache.evict_all_everywhere(&version_cache(storage)).await;
    }

    async fn installed_foreign_key_columns(&self, cx: &Ctx, pool: &MySqlPool, client_code: &str, child: &Storage)
        -> AppDataResult<Vec<String>> {
        let db_name = self.database(cx, client_code, child)?;
        let key = format!("{db_name}{}", child.version);
        let loaded = self
            .key_columns
            .get_or_load(&foreign_key_cache(child), key, || async {
                let keys = self.existing_keys(pool, &db_name, &child.unique_name).await?;
                let mut cols: Vec<String> = Vec::new();
                for k in keys {
                    if !cols.contains(&k.column) {
                        cols.push(k.column);
                    }
                }
                Ok::<_, AppDataError>(Some(cols))
            })
            .await?;
        Ok(loaded.unwrap_or_default())
    }

    /// A TO_MANY relation is a JSON array here, so equality would find nothing.
    fn references(field: &str, many: bool, id: &str) -> Cond {
        if many {
            Cond::Plain(Sql::template(
                "JSON_CONTAINS({0}, JSON_QUOTE({1}))",
                &[Sql::name(&[field]), Sql::param(Bind::Text(id.into()))],
            ))
        } else {
            Sql::name(&[field]).equal(Sql::param(Bind::Text(id.into())))
        }
    }
}

#[async_trait]
impl AppDataEngine for MySqlAppDataService {
    fn backend(&self) -> &'static str {
        BACKEND
    }

    async fn create(&self, cx: &Ctx, client_code: &str, conn: Option<&Connection>, storage: &Storage, data: DataObject)
        -> AppDataResult<Document> {
        let pool = self.pool(conn).await?;
        let db_name = self.ensure_table(cx, &pool, client_code, storage).await?;
        let input = data.data.clone().unwrap_or_default();
        self.hooks.validator.validate(&input, storage, storage_schema(storage).as_ref()).await?;
        let resolved = self.physical_schema(storage, cx.draft).await;

        let mut row = column_names::to_columns(&input);
        let id = match row.get(ID_COLUMN) {
            None | Some(Value::Null) => ulid(),
            Some(v) if v.java_string().trim().is_empty() => ulid(),
            Some(v) => v.java_string(),
        };
        row.insert(ID_COLUMN.into(), Value::String(id.clone()));

        let d = defs(storage);
        let decoding = Decoding::of(&resolved, d.as_ref())?;
        let encoded = value_codec::encode(&row, &decoding.json, &decoding.dates, &decoding.decimals);
        let values: Vec<(String, Bind)> = encoded.iter().map(|(k, v)| Ok((k.clone(), write_bind(v)?))).collect::<AppDataResult<_>>()?;
        execute(&pool, &sql::insert(&table(&db_name, storage), &values)).await?;

        let saved = self
            .read_row(&pool, &db_name, storage, &resolved, &id)
            .await?
            .ok_or_else(|| AppDataError::internal("the created row could not be read back"))?;
        self.add_version(cx, &pool, &db_name, storage, &id, "CREATE", &saved, data.message.as_deref()).await?;
        Ok(saved)
    }

    async fn update(
        &self,
        cx: &Ctx,
        client_code: &str,
        conn: Option<&Connection>,
        storage: &Storage,
        data: DataObject,
        override_: Option<bool>,
    ) -> AppDataResult<Document> {
        let input = data.data.clone().unwrap_or_default();
        let id = match input.get(ID_COLUMN) {
            None | Some(Value::Null) => return Err(AppDataError::row_id_required(ID_COLUMN)),
            Some(v) if v.java_string().trim().is_empty() => return Err(AppDataError::row_id_required(ID_COLUMN)),
            Some(v) => v.java_string(),
        };

        let pool = self.pool(conn).await?;
        let db_name = self.ensure_table(cx, &pool, client_code, storage).await?;
        let resolved = self.physical_schema(storage, cx.draft).await;

        let nulls = nulls_on_required(&resolved, &input)?;
        if !nulls.is_empty() {
            return Err(AppDataError::field_cannot_be_null(&nulls.join(", "), &storage.name));
        }

        let to_validate = if override_ == Some(true) {
            input.clone()
        } else {
            let existing = self
                .read_row(&pool, &db_name, storage, &resolved, &id)
                .await?
                .ok_or_else(|| AppDataError::object_not_found(&storage.name, &id))?;
            merged(&existing, &input)
        };
        self.hooks.validator.validate(&to_validate, storage, storage_schema(storage).as_ref()).await?;

        let values = update_values(storage, &resolved, &input, override_)?;
        if values.is_empty() {
            return self.read_row(&pool, &db_name, storage, &resolved, &id).await?.ok_or(AppDataError::Empty);
        }

        let cond = id_field().equal(Sql::param(Bind::Text(id.clone())));
        if let Err(e) = execute(&pool, &sql::update(&table(&db_name, storage), &values, &cond)).await {
            if let Some(column) = null_column(&db::message(&e)) {
                let field = resolved.field_names().get(&column).cloned().unwrap_or(column);
                return Err(AppDataError::field_cannot_be_null(&field, &storage.name));
            }
            return Err(e);
        }
        let saved = self.read_row(&pool, &db_name, storage, &resolved, &id).await?.ok_or(AppDataError::Empty)?;
        self.add_version(cx, &pool, &db_name, storage, &id, "UPDATE", &saved, data.message.as_deref()).await?;
        Ok(saved)
    }

    async fn read(&self, cx: &Ctx, client_code: &str, conn: Option<&Connection>, storage: &Storage, id: &str)
        -> AppDataResult<Document> {
        let pool = self.pool(conn).await?;
        let db_name = self.ensure_table(cx, &pool, client_code, storage).await?;
        let schema = self.physical_schema(storage, cx.draft).await;
        self.read_row(&pool, &db_name, storage, &schema, id)
            .await?
            .ok_or_else(|| AppDataError::object_not_found(&storage.name, id))
    }

    async fn read_page(&self, cx: &Ctx, client_code: &str, conn: Option<&Connection>, storage: &Storage, query: &Query)
        -> AppDataResult<Page<Document>> {
        let page = query.pageable()?;
        let pool = self.pool(conn).await?;
        let db_name = self.ensure_table(cx, &pool, client_code, storage).await?;
        let schema = self.physical_schema(storage, cx.draft).await;
        let attached = self
            .resolve_attached(cx, &pool, client_code, storage, &schema, query.joins.as_ref(), query.sub_queries.as_ref())
            .await?;
        let rows = self.rows(&pool, &db_name, storage, &schema, query, &page, &attached).await?;
        let total = if query.counts() {
            self.count_rows(&pool, &db_name, storage, &schema, query, &attached).await?
        } else {
            page.offset() + rows.len() as i64
        };
        Ok(Page::of(rows, page, || total))
    }

    async fn read_page_rows(&self, cx: &Ctx, client_code: &str, conn: Option<&Connection>, storage: &Storage, query: &Query)
        -> AppDataResult<Vec<Document>> {
        let page = query.pageable()?;
        let pool = self.pool(conn).await?;
        let db_name = self.ensure_table(cx, &pool, client_code, storage).await?;
        let schema = self.physical_schema(storage, cx.draft).await;
        let attached = self
            .resolve_attached(cx, &pool, client_code, storage, &schema, query.joins.as_ref(), query.sub_queries.as_ref())
            .await?;
        self.rows(&pool, &db_name, storage, &schema, query, &page, &attached).await
    }

    async fn aggregate(
        &self,
        cx: &Ctx,
        client_code: &str,
        conn: Option<&Connection>,
        storage: &Storage,
        query: &AggregateQuery,
    ) -> AppDataResult<Page<Document>> {
        if let Some(invalid) = aggregate_validator::check(query) {
            return Err(AppDataError::invalid_aggregation(&invalid));
        }
        let page = query.pageable()?;
        let pool = self.pool(conn).await?;
        let db_name = self.ensure_table(cx, &pool, client_code, storage).await?;
        let schema = self.physical_schema(storage, cx.draft).await;
        let attached = self
            .resolve_attached(cx, &pool, client_code, storage, &schema, query.joins.as_ref(), query.sub_queries.as_ref())
            .await?;
        Self::check_aggregate_fields(storage, &schema, query, &attached)?;
        self.check_zones(&pool, query).await?;

        let d = defs(storage);
        let json = type_mapper::json_columns(schema.schema(), d.as_ref()).map_err(internal)?;
        let resolver = self.resolver(&schema, d.as_ref(), &attached, text_columns(storage, &schema, d.as_ref())?)?;
        let from = Self::from_clause(&db_name, storage, &attached);
        let where_ = filter_builder::build_for_read(query.condition.as_ref(), &resolver).map_err(unsupported_filter)?;
        let having = match &query.having {
            None => None,
            Some(h) => Some(filter_builder::build_json(Some(h), IndexSet::new()).map_err(unsupported_filter)?),
        };

        let json_aliases: Columns = query
            .group_by
            .iter()
            .flatten()
            .filter(|g| g.field.as_ref().is_some_and(|f| json.contains(f)))
            .filter_map(|g| g.resolved_alias())
            .collect();
        let booleans = type_mapper::boolean_columns(schema.schema(), d.as_ref()).map_err(internal)?;
        let boolean_aliases = boolean_aliases(query, &booleans);

        let select = aggregate_builder::page(&from, query, where_.clone(), having.clone(), &page, &resolver).map_err(unsupported_filter)?;
        let rows: Vec<Document> = fetch(&pool, &select.to_sql())
            .await?
            .into_iter()
            .map(|r| value_codec::decode(r, &json_aliases, &Columns::new(), &Columns::new(), &boolean_aliases))
            .collect();
        let total = if query.counts() {
            let c = aggregate_builder::count(&from, query, where_, having, &resolver).map_err(unsupported_filter)?;
            count(&pool, &c.to_sql()).await?
        } else {
            page.offset() + rows.len() as i64
        };
        Ok(Page::of(rows, page, || total))
    }

    async fn delete(
        &self,
        cx: &Ctx,
        client_code: &str,
        conn: Option<&Connection>,
        storage: &Storage,
        id: &str,
        delete_version: Option<bool>,
    ) -> AppDataResult<bool> {
        let pool = self.pool(conn).await?;
        let db_name = self.ensure_table(cx, &pool, client_code, storage).await?;
        let schema = self.physical_schema(storage, cx.draft).await;
        let row = if delete_version.is_none() || delete_version == Some(true) || !storage.keeps_history() {
            Document::new()
        } else {
            self.read_row(&pool, &db_name, storage, &schema, id).await?.unwrap_or_default()
        };
        let cond = id_field().equal(Sql::param(Bind::Text(id.into())));
        let deleted = match execute(&pool, &sql::delete(&table(&db_name, storage), &cond)).await {
            Ok(n) => n > 0,
            Err(e) if db::is_integrity_violation(&e) => return Err(AppDataError::cannot_delete_with_restrict(&storage.name)),
            Err(e) => return Err(e),
        };
        if !deleted {
            return Ok(false);
        }
        self.record_delete(cx, &pool, &db_name, storage, id, delete_version, &row).await?;
        Ok(true)
    }

    async fn delete_by_filter(
        &self,
        cx: &Ctx,
        client_code: &str,
        conn: Option<&Connection>,
        storage: &Storage,
        query: &Query,
        dev_mode: Option<bool>,
        delete_version: Option<bool>,
    ) -> AppDataResult<i64> {
        if query.has_joins() {
            return Err(AppDataError::unsupported_on_backend("a delete with joins", BACKEND));
        }
        let pool = self.pool(conn).await?;
        let db_name = self.ensure_table(cx, &pool, client_code, storage).await?;
        let schema = self.physical_schema(storage, cx.draft).await;
        let d = defs(storage);
        let json = type_mapper::json_columns(schema.schema(), d.as_ref()).map_err(internal)?;
        let resolver = FieldResolver::of(json).with_text_columns(text_columns(storage, &schema, d.as_ref())?);
        let condition = filter_builder::build(query.condition.as_ref(), &resolver).map_err(unsupported_filter)?;
        if dev_mode == Some(true) {
            return count(&pool, &Select::count(table(&db_name, storage)).filter(condition).to_sql()).await;
        }
        self.record_bulk_delete(cx, &pool, &db_name, storage, &schema, &condition, delete_version).await?;
        Ok(execute(&pool, &sql::delete(&table(&db_name, storage), &condition)).await? as i64)
    }

    async fn read_version(&self, cx: &Ctx, client_code: &str, conn: Option<&Connection>, storage: &Storage, version_id: &str)
        -> AppDataResult<Document> {
        let pool = self.pool(conn).await?;
        let db_name = self.database(cx, client_code, storage)?;
        self.ensure_version_table(&pool, &db_name, storage).await?;
        let booleans = self.snapshot_booleans(storage, cx.draft).await;
        let select = Select::star(Self::version_table(&db_name, storage))
            .filter(id_field().equal(Sql::param(Bind::Text(version_id.into()))));
        match fetch(&pool, &select.to_sql()).await?.into_iter().next() {
            Some(r) => Ok(Self::decode_version(r, &booleans)),
            None => Err(AppDataError::generic_not_found(&storage.name, version_id)),
        }
    }

    async fn read_page_version(
        &self,
        cx: &Ctx,
        client_code: &str,
        conn: Option<&Connection>,
        storage: &Storage,
        object_id: &str,
        query: &Query,
        include_object: Option<bool>,
    ) -> AppDataResult<Page<Document>> {
        let with_object = include_object != Some(false);
        let page = query.pageable()?;
        let pool = self.pool(conn).await?;
        let db_name = self.database(cx, client_code, storage)?;
        self.ensure_version_table(&pool, &db_name, storage).await?;
        let booleans = self.snapshot_booleans(storage, cx.draft).await;

        let mut condition = Sql::name(&[version_table::OBJECT_ID]).equal(Sql::param(Bind::Text(object_id.into())));
        if let Some(c) = &query.condition {
            let extra = filter_builder::build_for_read(Some(c), &FieldResolver::of(IndexSet::new())).map_err(unsupported_filter)?;
            condition = condition.and_also(extra);
        }
        let mut fields: Vec<Sql> = version_table::AUDIT_FIELDS.iter().map(|f| Sql::name(&[f])).collect();
        if with_object {
            fields.push(Sql::name(&[version_table::OBJECT]));
        }
        let vt = Self::version_table(&db_name, storage);
        let select = Select::fields(fields, vt.clone())
            .filter(condition.clone())
            .order(vec![Sql::name(&[version_table::CREATED_AT]).desc()])
            .page(page.page_size(), page.offset());
        let rows: Vec<Document> =
            fetch(&pool, &select.to_sql()).await?.into_iter().map(|r| Self::decode_version(r, &booleans)).collect();
        let total = if query.counts() {
            count(&pool, &Select::count(vt).filter(condition).to_sql()).await?
        } else {
            page.offset() + rows.len() as i64
        };
        Ok(Page::of(rows, page, || total))
    }

    async fn check_if_exists(&self, cx: &Ctx, client_code: &str, conn: Option<&Connection>, storage: &Storage, id: &str)
        -> AppDataResult<bool> {
        let pool = self.pool(conn).await?;
        let db_name = self.ensure_table(cx, &pool, client_code, storage).await?;
        let select = Select::count(table(&db_name, storage)).filter(id_field().equal(Sql::param(Bind::Text(id.into()))));
        Ok(count(&pool, &select.to_sql()).await? > 0)
    }

    async fn enforces_relation_constraint(
        &self,
        cx: &Ctx,
        client_code: &str,
        conn: Option<&Connection>,
        child: &Storage,
        field: &str,
        relation: &StorageRelation,
    ) -> AppDataResult<bool> {
        if !foreign_keys::enforceable_for(Some(child), Some(relation)) {
            return Ok(false);
        }
        let pool = self.pool(conn).await?;
        Ok(self.installed_foreign_key_columns(cx, &pool, client_code, child).await?.iter().any(|c| c == field))
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
    ) -> AppDataResult<i64> {
        let pool = self.pool(conn).await?;
        let db_name = self.ensure_table(cx, &pool, client_code, child).await?;
        count(&pool, &Select::count(table(&db_name, child)).filter(Self::references(field, many, id)).to_sql()).await
    }

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
    ) -> AppDataResult<Vec<String>> {
        let pool = self.pool(conn).await?;
        let db_name = self.ensure_table(cx, &pool, client_code, child).await?;
        let mut select = Select::fields(vec![id_field()], table(&db_name, child)).filter(Self::references(field, many, id));
        select.limit = Some((limit, 0));
        let rows = fetch(&pool, &select.to_sql()).await?;
        Ok(rows.iter().map(|r| r.values().next().map(Value::java_string).unwrap_or_else(|| "null".into())).collect())
    }

    async fn delete_storage(&self, cx: &Ctx, client_code: &str, conn: Option<&Connection>, storage: &Storage)
        -> AppDataResult<bool> {
        let db_name = self.database(cx, client_code, storage)?;
        let pool = self.pool(conn).await?;
        execute_raw(&pool, &format!("DROP TABLE IF EXISTS `{db_name}`.`{}`", storage.unique_name)).await?;
        self.cache.evict_all_everywhere(&table_cache(storage)).await;
        Ok(true)
    }

    async fn drop_draft_storage(&self, cx: &Ctx, client_code: &str, conn: Option<&Connection>, storage: &Storage)
        -> AppDataResult<bool> {
        let db_name = database_name(&cx.tenant(client_code, storage), &storage.app_code, true)?;
        let pool = self.pool(conn).await?;
        let t = &storage.unique_name;
        let dropped = async {
            execute_raw(&pool, &format!("DROP TABLE IF EXISTS `{db_name}`.`{t}`")).await?;
            execute_raw(&pool, &format!("DROP TABLE IF EXISTS `{db_name}`.`{}`", version_table::name_for(t))).await?;
            Ok::<_, AppDataError>(())
        }
        .await;
        if dropped.is_err() {
            return Ok(false);
        }
        self.cache.evict_all_everywhere(&table_cache(storage)).await;
        self.cache.evict_all_everywhere(&version_cache(storage)).await;
        Ok(true)
    }

    async fn drop_draft_database(&self, conn: Option<&Connection>, app_code: &str, client_code: &str) -> AppDataResult<bool> {
        if app_code.trim().is_empty() || client_code.trim().is_empty() {
            return Ok(false);
        }
        let name = database_name(client_code, app_code, true)?;
        let pool = self.pool(conn).await?;
        Ok(execute_raw(&pool, &format!("DROP DATABASE IF EXISTS `{name}`")).await.is_ok())
    }

    async fn copy_live_to_draft(
        &self,
        cx: &Ctx,
        client_code: &str,
        conn: Option<&Connection>,
        storage: &Storage,
        replace: Option<bool>,
    ) -> AppDataResult<i64> {
        let data_client = data_client_code(cx, client_code, storage);
        let live_db = database_name(&data_client, &storage.app_code, false)?;
        let draft_db = database_name(&data_client, &storage.app_code, true)?;
        let t = storage.unique_name.clone();
        let pool = self.pool(conn).await?;
        self.ensure_table(&cx.on_draft(true), &pool, client_code, storage).await?;
        let total = if migration::table_exists(&pool, &live_db, &t).await? {
            count_raw(&pool, &format!("SELECT COUNT(*) FROM `{live_db}`.`{t}`")).await?
        } else {
            0
        };
        if total == 0 {
            return Ok(0);
        }
        let columns = self.shared_columns(&pool, &live_db, &draft_db, &t).await?;
        if columns.is_empty() {
            return Ok(0);
        }
        let cols = columns.iter().map(|c| format!("`{c}`")).collect::<Vec<_>>().join(", ");
        if replace == Some(true) {
            execute_raw(&pool, &format!("DELETE FROM `{draft_db}`.`{t}`")).await?;
        }
        execute_raw(&pool, &format!("INSERT INTO `{draft_db}`.`{t}` ({cols}) SELECT {cols} FROM `{live_db}`.`{t}`")).await?;
        Ok(total)
    }

    async fn clear_draft_rows(&self, cx: &Ctx, client_code: &str, conn: Option<&Connection>, storage: &Storage)
        -> AppDataResult<i64> {
        let draft_db = database_name(&data_client_code(cx, client_code, storage), &storage.app_code, true)?;
        let t = storage.unique_name.clone();
        let versions = version_table::name_for(&t);
        let pool = self.pool(conn).await?;
        let has_table = migration::table_exists(&pool, &draft_db, &t).await?;
        let has_versions = migration::table_exists(&pool, &draft_db, &versions).await?;
        if !has_table && !has_versions {
            return Ok(0);
        }
        let mut statements = Vec::new();
        if has_table {
            statements.push(sql::delete(&Sql::name(&[&draft_db, &t]), &Cond::None));
        }
        if has_versions {
            statements.push(sql::delete(&Sql::name(&[&draft_db, &versions]), &Cond::None));
        }
        let counts = self.without_foreign_key_checks(&pool, &statements).await?;
        Ok(if has_table { counts.first().copied().unwrap_or(0) as i64 } else { 0 })
    }

    async fn copy_live_to_draft_filtered(
        &self,
        cx: &Ctx,
        client_code: &str,
        conn: Option<&Connection>,
        storage: &Storage,
        filter: Option<&DraftCopyFilter>,
        followed: &HashMap<String, Storage>,
    ) -> AppDataResult<i64> {
        let data_client = data_client_code(cx, client_code, storage);
        let live_db = database_name(&data_client, &storage.app_code, false)?;
        let draft_db = database_name(&data_client, &storage.app_code, true)?;
        let t = storage.unique_name.clone();
        let pool = self.pool(conn).await?;
        self.ensure_table(&cx.on_draft(true), &pool, client_code, storage).await?;
        let live_exists = migration::table_exists(&pool, &live_db, &t).await?;
        let columns = if live_exists { self.shared_columns(&pool, &live_db, &draft_db, &t).await? } else { Vec::new() };
        let host = cx.url_client_code.clone().filter(|u| !u.trim().is_empty()).unwrap_or_else(|| client_code.to_string());
        let draft_db_of = |s: &Storage| database_name(if s.app_level() { &host } else { client_code }, &s.app_code, true);
        let where_ = self.draft_copy_condition(&live_db, &t, storage, filter, followed, cx.draft, &draft_db_of).await?;

        let target = Sql::name(&[&draft_db, &t]);
        let mut statements = vec![sql::delete(&target, &Cond::None)];
        if !columns.is_empty() {
            let fields: Vec<Sql> = columns.iter().map(|c| Sql::name(&[c])).collect();
            let select = Select::fields(fields.clone(), Sql::name(&[&live_db, &t])).filter(where_);
            statements.push(
                Sql::raw("insert into ")
                    .then_sql(&target)
                    .then(" (")
                    .then_sql(&Sql::join(&fields, ", "))
                    .then(") ")
                    .then_sql(&select.to_sql()),
            );
        }
        let counts = self.without_foreign_key_checks(&pool, &statements).await?;
        Ok(if columns.is_empty() { 0 } else { counts.get(1).copied().unwrap_or(0) as i64 })
    }
}

/// The schema a test or tool needs in hand without the hooks.
pub fn physical_of(schema: Schema) -> PhysicalSchema {
    column_names::physical(schema)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sch(json: &str) -> PhysicalSchema {
        column_names::physical(Schema::from_value(&Value::parse_json(json).unwrap()).unwrap())
    }

    fn rendered(fields: &[Sql]) -> Vec<String> {
        fields.iter().map(|f| f.render().0).collect()
    }

    fn sort(orders: Vec<Order>) -> Sort {
        Sort::by(orders)
    }

    fn shaping() -> PhysicalSchema {
        sch(r#"{"type":"OBJECT","properties":{"region":{"type":"STRING","maxLength":20},"amount":{"type":"DOUBLE"},"notes":{"type":"STRING","maxLength":100}}}"#)
    }

    fn nested() -> PhysicalSchema {
        sch(r#"{"type":"OBJECT","properties":{"region":{"type":"STRING","maxLength":20},"address":{"type":"OBJECT","properties":{"city":{"type":"STRING","maxLength":40}}}}}"#)
    }

    fn q(json: &str) -> Query {
        Query::from_value(&Value::parse_json(json).unwrap()).unwrap()
    }

    fn storage(app_level: Option<bool>) -> Storage {
        let level = app_level.map(|b| format!(r#","isAppLevel":{b}"#)).unwrap_or_default();
        Storage::from_value(&Value::parse_json(&format!(r#"{{"name":"s","appCode":"app","uniqueName":"app_s"{level}}}"#)).unwrap()).unwrap()
    }

    /// `dataClientCode` and `sameSchema` (nocode-saas e2b7d48aa).
    #[test]
    fn an_app_level_storage_lives_with_the_host() {
        let on = |url: Option<&str>| Ctx { url_client_code: url.map(str::to_string), ..Ctx::default() };
        let (shared, own) = (storage(Some(true)), storage(None));
        assert_eq!(data_client_code(&on(Some("HOST")), "TEN", &shared), "HOST");
        assert_eq!(data_client_code(&on(Some("HOST")), "TEN", &own), "TEN");
        assert_eq!(data_client_code(&on(Some(" ")), "TEN", &shared), "TEN", "a blank URL client");
        assert_eq!(data_client_code(&on(None), "TEN", &shared), "TEN", "no caller");
        assert_eq!(data_client_code(&on(Some("HOST")), "TEN", &storage(Some(false))), "TEN");
        assert!(same_schema(&shared, &storage(Some(true))));
        assert!(same_schema(&own, &storage(Some(false))));
        assert!(!same_schema(&shared, &own));
    }

    #[test]
    fn read_page_shaping() {
        let out = rendered(&order_plain(&nested(), &sort(vec![Order::asc("address.city")])).unwrap());
        assert_eq!(out.len(), 1);
        assert!(out[0].contains("json_"), "{}", out[0]);
        let out = rendered(&order_plain(&nested(), &sort(vec![Order::desc("address.city")])).unwrap());
        assert!(!out[0].contains("`address`.`city`") && out[0].contains("desc"), "{}", out[0]);
        assert!(order_plain(&nested(), &sort(vec![Order::asc("nosuch.city")])).unwrap().is_empty());
        assert!(order_plain(&nested(), &sort(vec![Order::asc("region.")])).unwrap().is_empty());
        assert_eq!(rendered(&order_plain(&nested(), &sort(vec![Order::asc("region")])).unwrap()), vec!["`region` asc"]);

        assert!(projection(&shaping(), &Query::default()).unwrap().is_empty());
        assert!(projection(&shaping(), &q(r#"{"fields":[]}"#)).unwrap().is_empty());
        assert_eq!(rendered(&projection(&shaping(), &q(r#"{"fields":["region"]}"#)).unwrap()), vec!["`_id`", "`region`"]);
        assert_eq!(rendered(&projection(&shaping(), &q(r#"{"fields":["_id","region"]}"#)).unwrap()), vec!["`_id`", "`region`"]);
        assert_eq!(
            rendered(&projection(&shaping(), &q(r#"{"fields":["notes"],"excludeFields":true}"#)).unwrap()),
            vec!["`_id`", "`amount`", "`region`"]
        );
        assert_eq!(
            rendered(&projection(&shaping(), &q(r#"{"fields":["region","amount","notes"],"excludeFields":true}"#)).unwrap()),
            vec!["`_id`"]
        );

        assert!(order_plain(&shaping(), &Sort::default_query_sort()).unwrap().is_empty());
        assert_eq!(rendered(&order_plain(&shaping(), &sort(vec![Order::desc("amount")])).unwrap()), vec!["`amount` desc"]);
        assert_eq!(rendered(&order_plain(&shaping(), &sort(vec![Order::asc("region")])).unwrap()), vec!["`region` asc"]);
        assert_eq!(
            rendered(&order_plain(&shaping(), &sort(vec![Order::asc("_id")])).unwrap()),
            vec!["char_length(`_id`) asc", "`_id` asc"]
        );
        assert_eq!(
            rendered(&order_plain(&shaping(), &sort(vec![Order::desc("_id"), Order::asc("region")])).unwrap()),
            vec!["char_length(`_id`) desc", "`_id` desc", "`region` asc"]
        );
        assert_eq!(
            rendered(&order_plain(&shaping(), &sort(vec![Order::desc("nosuch"), Order::asc("region")])).unwrap()),
            vec!["`region` asc"]
        );
        assert!(order_plain(&shaping(), &Sort::unsorted()).unwrap().is_empty());
    }

    fn nulls_schema() -> PhysicalSchema {
        sch(r#"{"type":"OBJECT","required":["name"],"properties":{
            "name":{"type":"STRING","maxLength":100},"description":{"type":"STRING","maxLength":200},
            "active":{"type":"BOOLEAN"},"optIn":{"type":["BOOLEAN","NULL"]},"count":{"type":"INTEGER"},
            "IFSC Flag":{"type":"BOOLEAN"}}}"#)
    }

    fn project_storage() -> Storage {
        Storage { name: "project".into(), app_code: "leadzumptwo".into(), client_code: "SYSTEM".into(), version: 1, unique_name: "project_t".into(), ..Default::default() }
    }

    fn set_of(values: Vec<(String, Bind)>) -> IndexMap<String, Bind> {
        values.into_iter().collect()
    }

    fn d(json: &str) -> Document {
        Value::parse_json(json).unwrap().as_object().unwrap().clone()
    }

    #[test]
    fn nulls_and_booleans() {
        let set = set_of(update_values(&project_storage(), &nulls_schema(), &d(r#"{"_id":"426","description":null}"#), Some(false)).unwrap());
        assert_eq!(set.len(), 1);
        assert_eq!(set.get("description"), Some(&Bind::Null));

        let set = set_of(update_values(&project_storage(), &nulls_schema(), &d(r#"{"_id":"426","name":"Tower A","active":true}"#), Some(true)).unwrap());
        assert_eq!(set.get("name"), Some(&Bind::Text("Tower A".into())));
        assert_eq!(set.get("active"), Some(&Bind::Bool(true)));
        for cleared in ["description", "optIn", "count", "IFSC_Flag"] {
            assert_eq!(set.get(cleared), Some(&Bind::Null), "{cleared}");
        }
        assert!(!set.contains_key("_id"));

        let set = set_of(update_values(&project_storage(), &nulls_schema(), &d(r#"{"_id":"426","name":"Tower A"}"#), None).unwrap());
        assert_eq!(set.len(), 1);

        let out = merged(
            &d(r#"{"_id":"426","name":"Tower A","description":"unlink-test","active":true,"count":null}"#),
            &d(r#"{"_id":"426","description":null,"active":false}"#),
        );
        assert_eq!(Value::Object(out).to_java_json(), r#"{"name":"Tower A","active":false}"#);

        assert_eq!(nulls_on_required(&nulls_schema(), &d(r#"{"name":null,"description":null}"#)).unwrap(), vec!["name"]);
        assert!(nulls_on_required(&nulls_schema(), &d(r#"{"description":null,"name":"x"}"#)).unwrap().is_empty());

        let booleans = type_mapper::boolean_columns(nulls_schema().schema(), None).unwrap();
        assert_eq!(booleans.iter().cloned().collect::<Vec<_>>(), vec!["IFSC_Flag", "active", "optIn"]);
        let mut defs = ColumnDefinitions::new();
        defs.insert(
            "active".into(),
            crate::model::StorageColumnDefinition::mysql(crate::model::MySqlColumnDefinition {
                column_type: Some(crate::model::MySqlColumnType::Varchar),
                length: Some(5),
                ..Default::default()
            }),
        );
        assert!(!type_mapper::boolean_columns(nulls_schema().schema(), Some(&defs)).unwrap().contains("active"));

        let decoding = Decoding::of(&nulls_schema(), None).unwrap();
        let row = decoding.row(d(r#"{"_id":"426","IFSC_Flag":1,"active":0}"#), &nulls_schema());
        assert_eq!(row["IFSC Flag"], Value::Bool(true));
        assert_eq!(row["active"], Value::Bool(false));
        assert_eq!(decoding.boolean_fields(&nulls_schema()).into_iter().collect::<Vec<_>>(), vec!["IFSC Flag", "active", "optIn"]);

        let agg = AggregateQuery::from_value(&Value::parse_json(r#"{"groupBy":[{"field":"active"},{"field":"count"}],"aggregations":[{"function":"COUNT"}]}"#).unwrap()).unwrap();
        let cols: Columns = ["active", "optIn"].iter().map(|s| s.to_string()).collect();
        assert_eq!(boolean_aliases(&agg, &cols).into_iter().collect::<Vec<_>>(), vec!["active"]);
    }

    fn received() -> PhysicalSchema {
        sch(r#"{"type":"OBJECT","properties":{"IFSC Code":{"type":"STRING","maxLength":20},"Virtual Account ":{"type":"STRING","maxLength":40},
            "Amount":{"type":"DOUBLE"},"Bank Details":{"type":"OBJECT"},"some_thing":{"type":"STRING","maxLength":20}}}"#)
    }

    #[test]
    fn received_field_names() {
        let out = received().to_fields(d(r#"{"_id":"01J","IFSC_Code":"HDFC0000001","Virtual_Account_":"VA-1","Amount":500.0}"#));
        assert_eq!(out.keys().cloned().collect::<Vec<_>>(), vec!["_id", "IFSC Code", "Virtual Account ", "Amount"]);
        let nested = received().to_fields(d(r#"{"Bank_Details":{"Branch Name":"Koregaon Park"}}"#));
        assert_eq!(nested["Bank Details"], Value::parse_json(r#"{"Branch Name":"Koregaon Park"}"#).unwrap());
        let json = type_mapper::json_columns(received().schema(), None).unwrap();
        let resolver = FieldResolver::of(json);
        let where_ = filter_builder::build(Some(&crate::model::FilterCondition::eq("IFSC Code", "HDFC0000001").into()), &resolver).unwrap().inlined();
        assert!(where_.contains("`IFSC_Code`"), "{where_}");
        let where_ = filter_builder::build(Some(&crate::model::FilterCondition::eq("Bank Details.city", "Pune").into()), &resolver).unwrap().inlined();
        assert!(where_.contains("`Bank_Details`") && where_.contains("$.city"), "{where_}");
        assert_eq!(rendered(&order(&received(), &sort(vec![Order::desc("IFSC Code")]), &resolver).unwrap()), vec!["`IFSC_Code` desc"]);
        let o = rendered(&order(&received(), &sort(vec![Order::asc("Bank Details.city")]), &resolver).unwrap());
        assert!(o.len() == 1 && o[0].contains("`Bank_Details`"), "{o:?}");
        assert!(order(&received(), &sort(vec![Order::asc("some.thing")]), &resolver).unwrap().is_empty());
        assert_eq!(rendered(&projection(&received(), &q(r#"{"fields":["IFSC Code","Amount"]}"#)).unwrap()), vec!["`_id`", "`IFSC_Code`", "`Amount`"]);
        let out = rendered(&projection(&received(), &q(r#"{"fields":["IFSC Code"],"excludeFields":true}"#)).unwrap());
        assert!(!out.contains(&"`IFSC_Code`".to_string()) && out.contains(&"`Virtual_Account_`".to_string()), "{out:?}");
        assert_eq!(
            selected_parent_columns(&received(), &q(r#"{"fields":["IFSC Code"]}"#)).unwrap().into_iter().collect::<Vec<_>>(),
            vec!["_id", "IFSC_Code"]
        );
        let mut cols = IndexMap::new();
        cols.insert("IFSC_Code".to_string(), "VARCHAR(20)".to_string());
        cols.insert("Bank_Details".to_string(), "JSON".to_string());
        cols.insert("pay.Remitter_Name".to_string(), "VARCHAR(100)".to_string());
        assert_eq!(head("IFSC Code", &cols), "IFSC_Code");
        assert_eq!(head("Bank Details.city", &cols), "Bank_Details");
        assert_eq!(head("pay.Remitter Name", &cols), "pay.Remitter_Name");
    }

    struct ByClient(IndexMap<String, Result<Storage, String>>);

    #[async_trait]
    impl crate::engine::StorageResolver for ByClient {
        async fn read_for_tenant(&self, _name: &str, _app: &str, client: &str, _draft: bool) -> anyhow::Result<Option<Storage>> {
            match self.0.get(client) {
                None => Ok(None),
                Some(Ok(s)) => Ok(Some(s.clone())),
                Some(Err(e)) => Err(anyhow::anyhow!(e.clone())),
            }
        }
    }

    fn owning(by: IndexMap<String, Result<Storage, String>>, tenants: &[&str]) -> Vec<String> {
        let cache = CacheService::new("cmn", "evictionChannel", None).unwrap();
        let hooks = Hooks { storages: Some(Arc::new(ByClient(by))), ..Hooks::default() };
        let e = MySqlAppDataService::new(MySqlEngineConfig::default(), hooks, &cache);
        let base = Storage { name: "deal".into(), app_code: "app".into(), unique_name: "app_system_d_base".into(), ..Default::default() };
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        rt.block_on(e.tenants_owning("app", &base, "app_system_d_base", tenants.iter().map(|t| t.to_string()).collect()))
    }

    #[test]
    fn tenants_owning_the_table() {
        let base = |u: &str| Ok(Storage { unique_name: u.into(), ..Default::default() });
        let mut m = IndexMap::new();
        m.insert("FIN".to_string(), base("app_system_d_base"));
        assert_eq!(owning(m.clone(), &["FIN_app"]), vec!["FIN_app"]);
        m.insert("FIN2".to_string(), base("app_fin2_dea_fork"));
        assert_eq!(owning(m, &["FIN_app", "FIN2_app", "FIN_app_draft", "FIN2_app_draft"]), vec!["FIN_app", "FIN_app_draft"]);
        let mut bad = IndexMap::new();
        bad.insert("BAD".to_string(), Err("no definition".to_string()));
        assert_eq!(owning(bad, &["BAD_app", "NONE_app"]), vec!["BAD_app", "NONE_app"]);
    }

    /// `MySQLTenantsOwningTest`, one test per Java method (`tenants_owning` is private).
    mod mysql_tenants_owning_test {
        use super::*;

        fn storage(client: &str, unique_name: &str) -> Result<Storage, String> {
            Ok(Storage { name: "deal".into(), app_code: "app".into(), client_code: client.into(), unique_name: unique_name.into(), ..Default::default() })
        }

        #[test]
        fn base_tenant_kept() {
            let mut m = IndexMap::new();
            m.insert("FIN".to_string(), storage("SYSTEM", "app_system_d_base"));
            assert_eq!(owning(m, &["FIN_app"]), vec!["FIN_app"]);
        }

        #[test]
        fn fork_tenant_skipped() {
            let mut m = IndexMap::new();
            m.insert("FIN".to_string(), storage("SYSTEM", "app_system_d_base"));
            m.insert("FIN2".to_string(), storage("FIN2", "app_fin2_dea_fork"));
            let (live, draft) = ("FIN_app".to_string(), format!("FIN_app{DRAFT_DB_SUFFIX}"));
            let fork_draft = format!("FIN2_app{DRAFT_DB_SUFFIX}");
            assert_eq!(owning(m, &[&live, "FIN2_app", &draft, &fork_draft]), vec![live, draft]);
        }

        #[test]
        fn unresolved_kept() {
            let mut m = IndexMap::new();
            m.insert("BAD".to_string(), Err("no definition".to_string()));
            assert_eq!(owning(m, &["BAD_app", "NONE_app"]), vec!["BAD_app", "NONE_app"]);
        }
    }

    #[test]
    fn default_connection_credentials() {
        let default = db::Credentials {
            url: Some("r2dbc:mysql://platform-host:3306/core".into()),
            username: Some("platform".into()),
            password: Some("platform-pw".into()),
            from_default: false,
        };
        let resolve = |json: Option<&str>| {
            let conn = Connection { id: "x".into(), connection_details: json.map(d), ..Default::default() };
            db::credentials(&conn, &default)
        };
        let c = resolve(Some(r#"{"useDefaultConnection":true}"#));
        assert_eq!(c.url.as_deref(), Some("r2dbc:mysql://platform-host:3306/core"));
        assert!(c.from_default);
        let c = resolve(Some(r#"{"url":"r2dbc:mysql://other:3306/","username":"u","password":"p"}"#));
        assert_eq!(c.url.as_deref(), Some("r2dbc:mysql://other:3306/"));
        assert!(!c.from_default);
        let c = resolve(Some(r#"{"useDefaultConnection":true,"url":"r2dbc:mysql://stale:3306/","username":"stale","password":"stale-pw"}"#));
        assert_eq!(c.password.as_deref(), Some("platform-pw"));
        let c = resolve(Some(r#"{"useDefaultConnection":false,"url":"r2dbc:mysql://mine:3306/"}"#));
        assert_eq!(c.url.as_deref(), Some("r2dbc:mysql://mine:3306/"));
        assert!(resolve(Some("{}")).url.is_none());
        assert!(resolve(None).url.is_none());
        assert!(resolve(Some(r#"{"url":"   "}"#)).url.is_none());
        assert!(resolve(Some(r#"{"useDefaultConnection":"true"}"#)).from_default);
        assert!(!resolve(Some(r#"{"useDefaultConnection":"false"}"#)).from_default);
        assert!(!resolve(Some(r#"{"useDefaultConnection":null}"#)).from_default);
    }

    #[test]
    fn naming_round_trips() {
        assert_eq!(database_name("LZCLA", "leadzump", false).unwrap(), "LZCLA_leadzump");
        for draft in [false, true] {
            let db = database_name("LZCLA", "leadzump", draft).unwrap();
            assert_eq!(client_code_of(&db, "leadzump"), "LZCLA");
            assert_eq!(is_draft(&db), draft);
        }
        assert_eq!(client_code_of("SYSTEM_kyc", "kyc"), "SYSTEM");
        assert_eq!(client_code_of("kyc_team_kyc", "kyc"), "kyc_team");
        assert_ne!(database_name("CLIENTA", "app", false).unwrap(), database_name("CLIENTB", "app", false).unwrap());
    }

    #[test]
    fn naming() {
        assert_eq!(database_name("CL", "app", false).unwrap(), "CL_app");
        assert_eq!(database_name("CL", "app", true).unwrap(), "CL_app_draft");
        assert!(database_name("CL`; DROP", "app", false).is_err());
        assert!(database_name(&"x".repeat(60), "app", false).is_ok());
        assert!(database_name(&"x".repeat(61), "app", false).is_err());
        assert_eq!(client_code_of("CL_app", "app"), "CL");
        assert_eq!(client_code_of("CL_app_draft", "app"), "CL");
        assert_eq!(client_code_of("CL_other", "app"), "CL_other");
        assert!(is_draft("CL_app_draft"));
    }

    #[test]
    fn patch_merge_and_null_columns() {
        let existing = Value::parse_json(r#"{"_id":"1","a":1,"b":null,"c":3}"#).unwrap();
        let patch = Value::parse_json(r#"{"c":null,"d":4}"#).unwrap();
        let out = merged(existing.as_object().unwrap(), patch.as_object().unwrap());
        assert_eq!(Value::Object(out).to_java_json(), r#"{"a":1,"d":4}"#);
        assert_eq!(null_column("Column 'amount' cannot be null").as_deref(), Some("amount"));
        assert!(null_column("Duplicate entry").is_none());
    }

    #[test]
    fn heads() {
        let mut cols = IndexMap::new();
        cols.insert("_id".to_string(), "CHAR(26)".to_string());
        cols.insert("address".to_string(), "JSON".to_string());
        cols.insert("c.region".to_string(), "VARCHAR(10)".to_string());
        cols.insert("IFSC_Code".to_string(), "VARCHAR(10)".to_string());
        assert_eq!(head("address.city", &cols), "address");
        assert_eq!(head("c.region", &cols), "c.region");
        assert_eq!(head("IFSC Code", &cols), "IFSC_Code");
    }
}
