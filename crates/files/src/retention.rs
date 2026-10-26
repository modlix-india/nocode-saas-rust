//! Path retention policies (`FilesRetentionService`, `RetentionPolicyResolver`,
//! `FilesRetentionPolicyDao`): "files under `<appCode>/<path>` older than N days are removed",
//! registered by the app owner (APP rows) and tuned per client (CLIENT rows).

use anyhow::Result;
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use platform::error::{AppError, AppResult};
use platform::security::ContextAuthentication;
use serde_json::Value;
use sqlx::{FromRow, Row};

use crate::errors::{
    status, OrApp, ALREADY_EXISTS, FORBIDDEN_PERMISSION, INVALID_FIELD, MISSING_FIELD, OBJECT_NOT_FOUND,
    RETENTION_PREFIX_NOT_REGISTERED,
};
use crate::fs::Fs;
use crate::fsdao::ExpiredFile;
use crate::jackson::Obj;
use crate::paths::Kind;
use crate::state::AppState;

pub const RETENTION_AUTHORITY: &str = "Authorities.Files_RETENTION";
const PREVIEW_SAMPLE_SIZE: i64 = 20;
const CACHE_POLICIES: &str = "filesRetentionPolicies";
const CACHE_HIERARCHY: &str = "filesRetentionHierarchy";

/// One `files_retention_policy` row.
#[derive(Debug, Clone, PartialEq, FromRow)]
pub struct PolicyRow {
    #[sqlx(rename = "ID")]
    pub id: u64,
    #[sqlx(rename = "APP_CODE")]
    pub app_code: String,
    #[sqlx(rename = "CLIENT_CODE")]
    pub client_code: String,
    #[sqlx(rename = "RESOURCE_TYPE")]
    pub resource_type: String,
    #[sqlx(rename = "PATH")]
    pub path: String,
    #[sqlx(rename = "RETENTION_DAYS")]
    pub retention_days: Option<u32>,
    #[sqlx(rename = "APPLIES_TO")]
    pub applies_to: String,
    #[sqlx(rename = "LEVEL")]
    pub level: String,
    #[sqlx(rename = "CREATED_BY")]
    pub created_by: Option<u64>,
    #[sqlx(rename = "CREATED_AT")]
    pub created_at: Option<DateTime<Utc>>,
    #[sqlx(rename = "UPDATED_BY")]
    pub updated_by: Option<u64>,
    #[sqlx(rename = "UPDATED_AT")]
    pub updated_at: Option<DateTime<Utc>>,
}

const POLICY_COLUMNS: &str = "ID, APP_CODE, CLIENT_CODE, CAST(RESOURCE_TYPE AS CHAR) AS RESOURCE_TYPE, PATH, \
    RETENTION_DAYS, CAST(APPLIES_TO AS CHAR) AS APPLIES_TO, CAST(LEVEL AS CHAR) AS LEVEL, CREATED_BY, CREATED_AT, \
    UPDATED_BY, UPDATED_AT";

fn opt<T: Into<Value>>(v: Option<T>) -> Value {
    v.map(Into::into).unwrap_or(Value::Null)
}

impl PolicyRow {
    fn is_app(&self) -> bool {
        self.level == "APP"
    }

    pub fn json(&self) -> Value {
        Obj::new()
            .put("id", self.id)
            .put("createdAt", opt(self.created_at.map(|t| t.timestamp())))
            .put("createdBy", opt(self.created_by))
            .put("updatedAt", opt(self.updated_at.map(|t| t.timestamp())))
            .put("updatedBy", opt(self.updated_by))
            .put("appCode", self.app_code.as_str())
            .put("clientCode", self.client_code.as_str())
            .put("resourceType", self.resource_type.as_str())
            .put("path", self.path.as_str())
            .put("retentionDays", opt(self.retention_days))
            .put("appliesTo", self.applies_to.as_str())
            .put("level", self.level.as_str())
            .build()
    }
}

// ---------------------------------------------------------------------------------------------
// RetentionPolicyResolver
// ---------------------------------------------------------------------------------------------

/// `normalizePath`: trimmed, no leading, trailing or repeated slashes; `None` on `.`, `..` or a
/// backslash.
pub fn normalize_path(path: Option<&str>) -> Option<String> {
    let Some(p) = path.filter(|p| !p.trim().is_empty()) else { return Some(String::new()) };
    let mut parts = Vec::new();
    for part in p.trim().split('/') {
        let t = part.trim();
        if t.is_empty() {
            continue;
        }
        if t == "." || t == ".." || t.contains('\\') {
            return None;
        }
        parts.push(t);
    }
    Some(parts.join("/"))
}

pub fn segments(path: &str) -> Vec<String> {
    if path.trim().is_empty() {
        vec![]
    } else {
        path.split('/').map(str::to_string).collect()
    }
}

pub fn is_under(prefix: &str, path: &str) -> bool {
    prefix.trim().is_empty() || path == prefix || path.starts_with(&format!("{prefix}/"))
}

pub fn longest_prefix<'a>(registered: &'a [String], rest: &str) -> Option<&'a String> {
    let normalized = normalize_path(Some(rest)).unwrap_or_default();
    let mut best: Option<&String> = None;
    for p in registered {
        if !is_under(p, &normalized) {
            continue;
        }
        if best.is_none_or(|b| p.len() > b.len()) {
            best = Some(p);
        }
    }
    best
}

pub fn nested_prefixes<'a>(registered: &'a [String], prefix: &str) -> Vec<&'a String> {
    registered.iter().filter(|o| *o != prefix && is_under(prefix, o)).collect()
}

/// The decision for one prefix and client. `days` `None` is keep forever.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub days: Option<u32>,
    pub source: String,
}

fn find<'a>(rows: &[&'a PolicyRow], client: &str, applies_to: &str) -> Option<&'a PolicyRow> {
    rows.iter().copied().find(|r| r.applies_to == applies_to && r.client_code == client)
}

/// `resolve`: the client's own SELF row, else the nearest manager's MANAGED row, else the APP
/// row; `None` when the prefix is not registered.
pub fn resolve(prefix: &str, rows: &[PolicyRow], hierarchy: &[String]) -> Option<Resolved> {
    let mut app_row = None;
    let mut client_rows = Vec::new();
    for r in rows.iter().filter(|r| r.path == prefix) {
        if r.is_app() {
            app_row = Some(r);
        } else {
            client_rows.push(r);
        }
    }
    let app = app_row?;
    let app_resolved = Resolved { days: app.retention_days, source: "APP".into() };
    let Some(client) = hierarchy.first() else { return Some(app_resolved) };
    if let Some(own) = find(&client_rows, client, "SELF") {
        return Some(Resolved { days: own.retention_days, source: "OWN".into() });
    }
    for manager in hierarchy.iter().skip(1) {
        if manager == client {
            continue;
        }
        if let Some(m) = find(&client_rows, manager, "MANAGED") {
            return Some(Resolved { days: m.retention_days, source: format!("MANAGER:{manager}") });
        }
    }
    Some(app_resolved)
}

pub fn client_row<'a>(prefix: &str, rows: &'a [PolicyRow], client: &str, applies_to: &str) -> Option<&'a PolicyRow> {
    let client_rows: Vec<&PolicyRow> = rows.iter().filter(|r| !r.is_app() && r.path == prefix).collect();
    find(&client_rows, client, applies_to)
}

// ---------------------------------------------------------------------------------------------
// FilesRetentionPolicyDao
// ---------------------------------------------------------------------------------------------

async fn read_by_id(st: &AppState, id: u64) -> Result<Option<PolicyRow>> {
    Ok(sqlx::query_as(&format!("SELECT {POLICY_COLUMNS} FROM files_retention_policy WHERE ID = ?"))
        .bind(id)
        .fetch_optional(st.dao().pool())
        .await?)
}

async fn read_by_app(st: &AppState, app: &str, kind: Option<Kind>) -> Result<Vec<PolicyRow>> {
    let mut sql = format!("SELECT {POLICY_COLUMNS} FROM files_retention_policy WHERE APP_CODE = ?");
    if kind.is_some() {
        sql.push_str(" AND RESOURCE_TYPE = ?");
    }
    sql.push_str(" ORDER BY RESOURCE_TYPE, PATH, LEVEL, CLIENT_CODE, APPLIES_TO");
    let mut q = sqlx::query_as(&sql).bind(app);
    if let Some(k) = kind {
        q = q.bind(k.db_name());
    }
    Ok(q.fetch_all(st.dao().pool()).await?)
}

async fn read_app_rows(st: &AppState, kind: Kind) -> Result<Vec<PolicyRow>> {
    Ok(sqlx::query_as(&format!(
        "SELECT {POLICY_COLUMNS} FROM files_retention_policy WHERE LEVEL = 'APP' AND RESOURCE_TYPE = ? \
         ORDER BY APP_CODE, PATH"
    ))
    .bind(kind.db_name())
    .fetch_all(st.dao().pool())
    .await?)
}

async fn count(st: &AppState, sql: &str, binds: &[&str]) -> Result<i64> {
    let mut q = sqlx::query(sql);
    for b in binds {
        q = q.bind(*b);
    }
    Ok(q.fetch_one(st.dao().pool()).await?.try_get("C")?)
}

// ---------------------------------------------------------------------------------------------
// FilesRetentionService
// ---------------------------------------------------------------------------------------------

fn parse_kind(s: &str) -> Option<Kind> {
    match s.trim().to_uppercase().as_str() {
        "STATIC" => Some(Kind::Static),
        "SECURED" => Some(Kind::Secured),
        _ => None,
    }
}

fn parse_type(raw: Option<&str>) -> AppResult<Kind> {
    raw.filter(|s| !s.trim().is_empty())
        .and_then(parse_kind)
        .ok_or_else(|| status(StatusCode::BAD_REQUEST, INVALID_FIELD, &["resourceType", raw.unwrap_or("null")]))
}

fn require_field(v: Option<&str>, name: &str) -> AppResult<String> {
    match v.filter(|s| !s.trim().is_empty()) {
        Some(s) => Ok(s.trim().to_string()),
        None => Err(status(StatusCode::BAD_REQUEST, MISSING_FIELD, &[name])),
    }
}

fn require_authority(ca: &ContextAuthentication) -> AppResult<()> {
    if ca.has_authority(RETENTION_AUTHORITY) {
        Ok(())
    } else {
        Err(status(StatusCode::FORBIDDEN, FORBIDDEN_PERMISSION, &[RETENTION_AUTHORITY]))
    }
}

fn validate_days(days: Option<i64>) -> AppResult<()> {
    match days {
        Some(d) if d < 1 => Err(status(StatusCode::BAD_REQUEST, INVALID_FIELD, &["retentionDays", &d.to_string()])),
        _ => Ok(()),
    }
}

fn normalized(path: Option<&str>) -> AppResult<String> {
    normalize_path(path).ok_or_else(|| status(StatusCode::BAD_REQUEST, INVALID_FIELD, &["path", path.unwrap_or("null")]))
}

/// `checkAppOwner`: the caller's client created the app.
async fn check_app_owner(st: &AppState, ca: &ContextAuthentication, app: &str) -> AppResult<()> {
    let found = st.security().app_by_code(app).await.ok().flatten();
    let Some(found) = found else {
        return Err(crate::errors::err_as("FILES.APP_NOT_FOUND", StatusCode::NOT_FOUND, OBJECT_NOT_FOUND, &["App", app]));
    };
    let owner = match &found["clientId"] {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    };
    if owner.is_none() || owner != Some(ca.user.client_id) || ca.user.client_id == 0 {
        let named = vec![("app".to_string(), app.to_string())];
        return Err(crate::errors::err_named("FILES.APP_OWNER_REQUIRED", StatusCode::FORBIDDEN, FORBIDDEN_PERMISSION, &[&format!("owner of the app {app}")], named));
    }
    Ok(())
}

/// `checkClientAccess`: the caller's client or one it manages.
async fn check_client_access(st: &AppState, ca: &ContextAuthentication, cc: &str) -> AppResult<()> {
    if cc == ca.client_code() {
        return Ok(());
    }
    let managed = async {
        let Some(id) = st.security().client_id_by_code(cc).await? else { return Ok::<_, anyhow::Error>(false) };
        st.security()
            .is_user_client_manage_client(ca.url_app_code.as_deref(), ca.user.id, ca.user.client_id, Some(id))
            .await
    }
    .await
    .unwrap_or(false);
    if managed {
        Ok(())
    } else {
        let named = vec![("client".to_string(), cc.to_string())];
        Err(crate::errors::err_named("FILES.CLIENT_MANAGER_REQUIRED", StatusCode::FORBIDDEN, FORBIDDEN_PERMISSION, &[&format!("manager of the client {cc}")], named))
    }
}

async fn check_row_access(st: &AppState, ca: &ContextAuthentication, row: &PolicyRow) -> AppResult<()> {
    if row.is_app() {
        check_app_owner(st, ca, &row.app_code).await
    } else {
        check_client_access(st, ca, &row.client_code).await
    }
}

/// `policyRows`: the rows of an app and type, cached until any policy write.
async fn policy_rows(st: &AppState, app: &str, kind: Kind) -> Result<Vec<PolicyRow>> {
    let key = format!("{app}:{}", kind.db_name());
    let (st2, app2) = (st.clone(), app.to_string());
    Ok(st
        .inner()
        .retention_rows
        .get_or_load(CACHE_POLICIES, key, || async move { read_by_app(&st2, &app2, Some(kind)).await.map(Some) })
        .await?
        .unwrap_or_default())
}

/// `hierarchy`: the client then its managers, nearest first; a 404 for an unknown client.
async fn hierarchy(st: &AppState, cc: &str) -> AppResult<Vec<String>> {
    let (st2, cc2) = (st.clone(), cc.to_string());
    let list = st
        .inner()
        .hierarchies
        .get_or_load(CACHE_HIERARCHY, cc.to_string(), || async move {
            let mut codes = st2.security().client_hierarchy_codes(&cc2).await?;
            if codes.is_empty() {
                return Ok::<_, anyhow::Error>(None);
            }
            if codes[0] != cc2 {
                codes.insert(0, cc2.clone());
            }
            Ok(Some(codes))
        })
        .await
        .app()?;
    list.ok_or_else(|| crate::errors::literal("FILES.CLIENT_UNKNOWN", StatusCode::NOT_FOUND, format!("Unknown client {cc}")).param("client", cc).into())
}

pub(crate) async fn evict_caches(st: &AppState) {
    st.cache().evict_all_everywhere(CACHE_POLICIES).await;
    st.cache().evict_all_everywhere(CACHE_HIERARCHY).await;
}

/// `GET /api/files/retention`: the app's registered prefixes and the client's own rows.
pub async fn list(st: &AppState, ca: &ContextAuthentication, app: Option<&str>, cc: Option<&str>) -> AppResult<Value> {
    let app = require_field(app, "appCode")?;
    let target = cc.filter(|c| !c.trim().is_empty()).map(|c| c.trim().to_string()).unwrap_or_else(|| ca.client_code().to_string());
    check_client_access(st, ca, &target).await?;
    let rows = read_by_app(st, &app, None).await.app()?;
    Ok(Value::Array(rows.iter().filter(|r| r.is_app() || r.client_code == target).map(PolicyRow::json).collect()))
}

fn body_str<'a>(b: &'a Value, k: &str) -> Option<&'a str> {
    b.get(k).and_then(Value::as_str)
}

/// Java's "Invalid retentionDays": a value that is not a whole number.
fn bad_days() -> AppError {
    crate::errors::literal("FILES.INVALID_FIELD", StatusCode::BAD_REQUEST, "Invalid retentionDays").param("field", "retentionDays").into()
}

fn body_days(b: &Value) -> AppResult<Option<i64>> {
    match b.get("retentionDays") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n.as_i64().map(Some).ok_or_else(bad_days),
        Some(Value::String(s)) => s.trim().parse().map(Some).map_err(|_| bad_days()),
        _ => Err(bad_days()),
    }
}

fn body_enum(b: &Value, k: &str, allowed: &[&str]) -> AppResult<Option<String>> {
    match b.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if allowed.contains(&s.as_str()) => Ok(Some(s.clone())),
        Some(other) => {
            let value = other.to_string();
            let named = vec![("field".to_string(), k.to_string()), ("value".to_string(), value.clone())];
            Err(crate::errors::err_named("FILES.INVALID_FIELD", StatusCode::BAD_REQUEST, INVALID_FIELD, &[k, &value], named))
        }
    }
}

/// `POST /api/files/retention`.
pub async fn create(st: &AppState, ca: &ContextAuthentication, body: &Value) -> AppResult<Value> {
    require_authority(ca)?;
    if body.is_null() {
        return Err(status(StatusCode::BAD_REQUEST, MISSING_FIELD, &["body"]));
    }
    let app = require_field(body_str(body, "appCode"), "appCode")?;
    let kind = body_enum(body, "resourceType", &["STATIC", "SECURED"])?
        .and_then(|k| parse_kind(&k))
        .ok_or_else(|| status(StatusCode::BAD_REQUEST, MISSING_FIELD, &["resourceType"]))?;
    let level = body_enum(body, "level", &["APP", "CLIENT"])?
        .ok_or_else(|| status(StatusCode::BAD_REQUEST, MISSING_FIELD, &["level"]))?;
    let applies = body_enum(body, "appliesTo", &["SELF", "MANAGED"])?;
    let path = normalized(body_str(body, "path"))?;
    let days = body_days(body)?;
    validate_days(days)?;

    let (client, applies_to) = if level == "APP" {
        check_app_owner(st, ca, &app).await?;
        (ca.client_code().to_string(), "SELF".to_string())
    } else {
        let client = body_str(body, "clientCode")
            .filter(|c| !c.trim().is_empty())
            .map(|c| c.trim().to_string())
            .unwrap_or_else(|| ca.client_code().to_string());
        check_client_access(st, ca, &client).await?;
        let registered = count(
            st,
            "SELECT COUNT(*) AS C FROM files_retention_policy WHERE APP_CODE = ? AND RESOURCE_TYPE = ? AND PATH = ? AND LEVEL = 'APP'",
            &[&app, kind.db_name(), &path],
        )
        .await
        .app()?;
        if registered == 0 {
            return Err(status(StatusCode::BAD_REQUEST, RETENTION_PREFIX_NOT_REGISTERED, &[&path, &app, kind.db_name()]));
        }
        (client, applies.unwrap_or_else(|| "SELF".into()))
    };

    let exists = count(
        st,
        "SELECT COUNT(*) AS C FROM files_retention_policy WHERE APP_CODE = ? AND CLIENT_CODE = ? AND RESOURCE_TYPE = ? \
         AND PATH = ? AND APPLIES_TO = ? AND LEVEL = ?",
        &[&app, &client, kind.db_name(), &path, &applies_to, &level],
    )
    .await
    .app()?;
    if exists != 0 {
        return Err(status(StatusCode::CONFLICT, ALREADY_EXISTS, &["Retention policy", &format!("{app}/{path}")]));
    }

    let user = (ca.user.id != 0).then_some(ca.user.id);
    let id = sqlx::query(
        "INSERT INTO files_retention_policy (APP_CODE, CLIENT_CODE, RESOURCE_TYPE, PATH, RETENTION_DAYS, APPLIES_TO, \
         LEVEL, CREATED_BY, UPDATED_BY) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&app)
    .bind(&client)
    .bind(kind.db_name())
    .bind(&path)
    .bind(days)
    .bind(&applies_to)
    .bind(&level)
    .bind(user)
    .bind(user)
    .execute(st.dao().pool())
    .await
    .map_err(anyhow::Error::from)?
    .last_insert_id();
    let created = read_by_id(st, id).await.app()?;
    evict_caches(st).await;
    Ok(created.map(|r| r.json()).unwrap_or(Value::Null))
}

async fn existing(st: &AppState, id: u64) -> AppResult<PolicyRow> {
    read_by_id(st, id)
        .await
        .app()?
        .ok_or_else(|| status(StatusCode::NOT_FOUND, OBJECT_NOT_FOUND, &["Retention policy", &id.to_string()]))
}

/// `PUT /api/files/retention/{id}`: only the days change.
pub async fn update(st: &AppState, ca: &ContextAuthentication, id: u64, body: &Value) -> AppResult<Value> {
    require_authority(ca)?;
    let row = existing(st, id).await?;
    check_row_access(st, ca, &row).await?;
    let days = if body.is_null() { None } else { body_days(body)? };
    validate_days(days)?;
    sqlx::query("UPDATE files_retention_policy SET RETENTION_DAYS = ?, UPDATED_BY = ? WHERE ID = ?")
        .bind(days)
        .bind((ca.user.id != 0).then_some(ca.user.id))
        .bind(row.id)
        .execute(st.dao().pool())
        .await
        .map_err(anyhow::Error::from)?;
    evict_caches(st).await;
    Ok(read_by_id(st, row.id).await.app()?.map(|r| r.json()).unwrap_or(Value::Null))
}

/// `DELETE /api/files/retention/{id}`: an APP row takes its client rows with it.
pub async fn delete(st: &AppState, ca: &ContextAuthentication, id: u64) -> AppResult<Value> {
    require_authority(ca)?;
    let row = existing(st, id).await?;
    check_row_access(st, ca, &row).await?;
    let pool = st.dao().pool();
    if row.is_app() {
        sqlx::query(
            "DELETE FROM files_retention_policy WHERE APP_CODE = ? AND RESOURCE_TYPE = ? AND PATH = ? AND LEVEL = 'CLIENT'",
        )
        .bind(&row.app_code)
        .bind(&row.resource_type)
        .bind(&row.path)
        .execute(pool)
        .await
        .map_err(anyhow::Error::from)?;
    }
    let deleted = sqlx::query("DELETE FROM files_retention_policy WHERE ID = ?")
        .bind(row.id)
        .execute(pool)
        .await
        .map_err(anyhow::Error::from)?
        .rows_affected()
        > 0;
    evict_caches(st).await;
    Ok(Value::Bool(deleted))
}

/// `GET /api/files/retention/effective`.
pub async fn effective(
    st: &AppState,
    ca: &ContextAuthentication,
    app: Option<&str>,
    cc: Option<&str>,
    resource_type: Option<&str>,
) -> AppResult<Value> {
    let app = require_field(app, "appCode")?;
    let target = cc.filter(|c| !c.trim().is_empty()).map(|c| c.trim().to_string()).unwrap_or_else(|| ca.client_code().to_string());
    check_client_access(st, ca, &target).await?;
    let kinds = if resource_type.is_none_or(|r| r.trim().is_empty()) {
        vec![Kind::Static, Kind::Secured]
    } else {
        vec![parse_type(resource_type)?]
    };
    let chain = hierarchy(st, &target).await?;
    let mut out = Vec::new();
    for kind in kinds {
        let rows = policy_rows(st, &app, kind).await.app()?;
        for app_row in rows.iter().filter(|r| r.is_app()) {
            let prefix = &app_row.path;
            let Some(resolved) = resolve(prefix, &rows, &chain) else { continue };
            let own = client_row(prefix, &rows, &target, "SELF");
            let managed = client_row(prefix, &rows, &target, "MANAGED");
            out.push(
                Obj::new()
                    .put("appCode", app.as_str())
                    .put("clientCode", target.as_str())
                    .put("resourceType", kind.db_name())
                    .put("path", prefix.as_str())
                    .put("days", opt(resolved.days))
                    .put("keepForever", resolved.days.is_none())
                    .put("source", resolved.source.as_str())
                    .put("appPolicyId", app_row.id)
                    .put("appDays", opt(app_row.retention_days))
                    .put("ownPolicyId", opt(own.map(|r| r.id)))
                    .put("ownDays", opt(own.and_then(|r| r.retention_days)))
                    .put("managedPolicyId", opt(managed.map(|r| r.id)))
                    .put("managedDays", opt(managed.and_then(|r| r.retention_days)))
                    .build(),
            );
        }
    }
    Ok(Value::Array(out))
}

fn folder_path(app: &str, prefix: &str) -> String {
    if prefix.trim().is_empty() {
        format!("/{app}")
    } else {
        format!("/{app}/{prefix}")
    }
}

#[allow(clippy::too_many_arguments)]
fn preview_json(app: &str, cc: &str, kind: Kind, path: &str, days: Option<i64>, source: Option<&str>, n: i64, bytes: i64, samples: Vec<String>) -> Value {
    Obj::new()
        .put("appCode", app)
        .put("clientCode", cc)
        .put("resourceType", kind.db_name())
        .put("path", path)
        .put("days", opt(days))
        .put("source", opt(source))
        .put("count", n)
        .put("totalBytes", bytes)
        .put("samplePaths", Value::Array(samples.into_iter().map(Value::from).collect()))
        .build()
}

/// `GET /api/files/retention/preview`: a dry run.
pub async fn preview(
    st: &AppState,
    ca: &ContextAuthentication,
    app: Option<&str>,
    resource_type: Option<&str>,
    path: Option<&str>,
    cc: Option<&str>,
    days: Option<i64>,
) -> AppResult<Value> {
    require_authority(ca)?;
    let app = require_field(app, "appCode")?;
    let kind = parse_type(resource_type)?;
    let prefix = normalized(Some(path.unwrap_or("")))?;
    let target = cc.filter(|c| !c.trim().is_empty()).map(|c| c.trim().to_string()).unwrap_or_else(|| ca.client_code().to_string());
    check_client_access(st, ca, &target).await?;
    let rows = policy_rows(st, &app, kind).await.app()?;
    let registered: Vec<String> = rows.iter().filter(|r| r.is_app()).map(|r| r.path.clone()).collect();

    let (effective_days, source) = match days {
        Some(d) => {
            validate_days(Some(d))?;
            (Some(d), Some("PREVIEW".to_string()))
        }
        None => match longest_prefix(&registered, &prefix) {
            None => (None, None),
            Some(covering) => {
                let chain = hierarchy(st, &target).await?;
                match resolve(covering, &rows, &chain) {
                    None => (None, None),
                    Some(r) => (r.days.map(i64::from), Some(r.source)),
                }
            }
        },
    };
    let Some(days) = effective_days else {
        return Ok(preview_json(&app, &target, kind, &prefix, None, source.as_deref(), 0, 0, vec![]));
    };
    let dao = st.dao();
    let root = dao.read_root_folder_id(kind, &target, &app).await.app()?;
    let folder = match root {
        None => None,
        Some(r) => dao.read_sub_folder_id(kind, &target, r, &segments(&prefix)).await.app()?,
    };
    let (Some(root), Some(folder)) = (root, folder) else {
        return Ok(preview_json(&app, &target, kind, &prefix, Some(days), source.as_deref(), 0, 0, vec![]));
    };
    let mut excluded = Vec::new();
    for nested in nested_prefixes(&registered, &prefix) {
        if let Some(id) = dao.read_sub_folder_id(kind, &target, root, &segments(nested)).await.app()? {
            excluded.push(id);
        }
    }
    let fp = folder_path(&app, &prefix);
    let (n, bytes) = dao.count_retention_expired(kind, &target, folder, &excluded, days).await.app()?;
    let samples = dao
        .read_retention_expired(kind, &target, folder, &fp, &excluded, days, PREVIEW_SAMPLE_SIZE)
        .await
        .app()?
        .into_iter()
        .map(|f| f.path)
        .collect();
    Ok(preview_json(&app, &target, kind, &prefix, Some(days), source.as_deref(), n, bytes, samples))
}

/// `applyRetention`: one sweep of a file system type, at most `limit` files, grouped by client
/// and app. A client whose hierarchy cannot be read is skipped.
pub async fn apply(st: &AppState, kind: Kind, limit: i64) -> Result<Value> {
    if limit <= 0 {
        return Ok(Value::Array(vec![]));
    }
    let mut prefixes_by_app: Vec<(String, Vec<String>)> = Vec::new();
    for row in read_app_rows(st, kind).await? {
        match prefixes_by_app.iter_mut().find(|(a, _)| *a == row.app_code) {
            Some((_, v)) => v.push(row.path),
            None => prefixes_by_app.push((row.app_code, vec![row.path])),
        }
    }
    let fs = Fs::new(st, kind);
    let dao = st.dao();
    let mut groups: Vec<(String, String, Vec<String>)> = Vec::new();
    let mut remaining = limit;

    'apps: for (app, prefixes) in &prefixes_by_app {
        let rows = read_by_app(st, app, Some(kind)).await?;
        for (cc, root) in dao.read_app_root_folders(kind, app).await? {
            let chain = match hierarchy(st, &cc).await {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!(app, cc, error = %e, "skipping retention: client hierarchy unavailable");
                    continue;
                }
            };
            let mut folders: std::collections::HashMap<String, Option<u64>> = std::collections::HashMap::new();
            for prefix in prefixes {
                let res: Result<()> = async {
                    let Some(resolved) = resolve(prefix, &rows, &chain) else { return Ok(()) };
                    let Some(days) = resolved.days else { return Ok(()) };
                    let Some(folder) = folder_of(st, &mut folders, kind, &cc, root, prefix).await? else { return Ok(()) };
                    let mut excluded = Vec::new();
                    for nested in nested_prefixes(prefixes, prefix) {
                        if let Some(id) = folder_of(st, &mut folders, kind, &cc, root, nested).await? {
                            excluded.push(id);
                        }
                    }
                    let files: Vec<ExpiredFile> = dao
                        .read_retention_expired(kind, &cc, folder, &folder_path(app, prefix), &excluded, days as i64, remaining)
                        .await?;
                    if files.is_empty() {
                        return Ok(());
                    }
                    remaining -= files.len() as i64;
                    let removed = fs.delete_files(files).await;
                    if !removed.is_empty() {
                        let paths = removed.into_iter().map(|f| f.path);
                        match groups.iter_mut().find(|(c, a, _)| *c == cc && a == app) {
                            Some((_, _, p)) => p.extend(paths),
                            None => groups.push((cc.clone(), app.clone(), paths.collect())),
                        }
                    }
                    Ok(())
                }
                .await;
                if let Err(e) = res {
                    tracing::error!(app, prefix, cc, error = %e, "retention failed");
                }
                if remaining <= 0 {
                    break 'apps;
                }
            }
        }
    }
    let total: usize = groups.iter().map(|g| g.2.len()).sum();
    if total > 0 {
        tracing::info!(total, kind = kind.db_name(), "retention removed files");
    }
    Ok(Value::Array(
        groups
            .into_iter()
            .map(|(cc, app, paths)| {
                Obj::new()
                    .put("clientCode", cc)
                    .put("appCode", app)
                    .put("resourceType", kind.db_name())
                    .put("paths", Value::Array(paths.into_iter().map(Value::from).collect()))
                    .build()
            })
            .collect(),
    ))
}

async fn folder_of(
    st: &AppState,
    cache: &mut std::collections::HashMap<String, Option<u64>>,
    kind: Kind,
    cc: &str,
    root: u64,
    prefix: &str,
) -> Result<Option<u64>> {
    if let Some(v) = cache.get(prefix) {
        return Ok(*v);
    }
    let id = st.dao().read_sub_folder_id(kind, cc, root, &segments(prefix)).await?;
    cache.insert(prefix.to_string(), id);
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: u64, path: &str, cc: &str, level: &str, applies: &str, days: Option<u32>) -> PolicyRow {
        PolicyRow {
            id,
            app_code: "app".into(),
            client_code: cc.into(),
            resource_type: "SECURED".into(),
            path: path.into(),
            retention_days: days,
            applies_to: applies.into(),
            level: level.into(),
            created_by: None,
            created_at: None,
            updated_by: None,
            updated_at: None,
        }
    }

    #[test]
    fn normalizes_and_matches_on_segments() {
        assert_eq!(normalize_path(Some(" /a//b/ ")).as_deref(), Some("a/b"));
        assert_eq!(normalize_path(None).as_deref(), Some(""));
        assert_eq!(normalize_path(Some("a/../b")), None);
        let reg = vec!["whatsapp/in".to_string(), "whatsapp".to_string(), "".to_string()];
        assert_eq!(longest_prefix(&reg, "whatsapp/incoming/a.png").map(String::as_str), Some("whatsapp"));
        assert_eq!(longest_prefix(&reg, "whatsapp/in/a.png").map(String::as_str), Some("whatsapp/in"));
        assert_eq!(longest_prefix(&reg, "other").map(String::as_str), Some(""));
        assert_eq!(nested_prefixes(&reg, "whatsapp"), vec![&"whatsapp/in".to_string()]);
    }

    #[test]
    fn resolution_order() {
        let rows = vec![
            row(1, "p", "OWNER", "APP", "SELF", Some(30)),
            row(2, "p", "MGR", "CLIENT", "MANAGED", None),
            row(3, "p", "C", "CLIENT", "SELF", Some(5)),
            row(4, "q", "OWNER", "APP", "SELF", Some(7)),
        ];
        let chain = vec!["C".to_string(), "MGR".to_string(), "SYSTEM".to_string()];
        assert_eq!(resolve("p", &rows, &chain), Some(Resolved { days: Some(5), source: "OWN".into() }));
        let chain2 = vec!["D".to_string(), "MGR".to_string()];
        assert_eq!(resolve("p", &rows, &chain2), Some(Resolved { days: None, source: "MANAGER:MGR".into() }));
        assert_eq!(resolve("q", &rows, &chain2), Some(Resolved { days: Some(7), source: "APP".into() }));
        assert_eq!(resolve("r", &rows, &chain2), None);
        assert_eq!(client_row("p", &rows, "C", "SELF").map(|r| r.id), Some(3));
    }


    /// `RetentionPolicyResolverTest`, every case.
    #[test]
    fn retention_policy_resolver_test() {
        const P: &str = "whatsapp/incoming";
        let app = |path: &str, days: Option<u32>| row(0, path, "OWNER", "APP", "SELF", days);
        let client = |path: &str, cc: &str, to: &str, days: Option<u32>| row(0, path, cc, "CLIENT", to, days);
        let chain = |c: &[&str]| c.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let reg = |p: &[&str]| p.iter().map(|s| s.to_string()).collect::<Vec<_>>();

        // prefixMatchesOnSegmentBoundariesOnly
        let r = reg(&["whatsapp/in"]);
        assert_eq!(longest_prefix(&r, "whatsapp/incoming/a.png"), None);
        assert_eq!(longest_prefix(&r, "whatsapp/in/a.png").map(String::as_str), Some("whatsapp/in"));
        assert_eq!(longest_prefix(&r, "whatsapp/in").map(String::as_str), Some("whatsapp/in"));
        assert_eq!(longest_prefix(&r, "whatsapp"), None);
        assert_eq!(longest_prefix(&r, "other/whatsapp/in/a.png"), None);
        // longestPrefixWinsAndEmptyMatchesEverything
        let r = reg(&["", "whatsapp", "whatsapp/incoming"]);
        assert_eq!(longest_prefix(&r, "/whatsapp/incoming/x/y.jpg").map(String::as_str), Some("whatsapp/incoming"));
        assert_eq!(longest_prefix(&r, "whatsapp/outgoing/z.jpg").map(String::as_str), Some("whatsapp"));
        assert_eq!(longest_prefix(&r, "docs/readme.pdf").map(String::as_str), Some(""));
        // nestedPrefixesAreTheLongerOnesInside
        let r = reg(&["", "whatsapp", "whatsapp/incoming", "whatsappx"]);
        assert_eq!(nested_prefixes(&r, ""), vec!["whatsapp", "whatsapp/incoming", "whatsappx"]);
        assert_eq!(nested_prefixes(&r, "whatsapp"), vec!["whatsapp/incoming"]);
        assert!(nested_prefixes(&r, "whatsapp/incoming").is_empty());
        // normalizeStripsSlashesAndRefusesDotSegments
        assert_eq!(normalize_path(Some(" /a//b/ ")).as_deref(), Some("a/b"));
        assert_eq!(normalize_path(Some("/")).as_deref(), Some(""));
        assert_eq!(normalize_path(None).as_deref(), Some(""));
        assert_eq!(normalize_path(Some("a/../b")), None);
        assert_eq!(normalize_path(Some("./a")), None);
        assert_eq!(normalize_path(Some("a\\b")), None);
        assert_eq!(segments(""), Vec::<String>::new());
        assert_eq!(segments("a/b"), vec!["a", "b"]);
        // appRowAppliesWhenNothingOverrides
        let r = resolve(P, &[app(P, Some(30))], &chain(&["C", "M1", "SYSTEM"])).unwrap();
        assert_eq!((r.days, r.source.as_str()), (Some(30), "APP"));
        assert_eq!(resolve(P, &[app(P, Some(30))], &[]).unwrap().source, "APP");
        // ownSelfRowBeatsManagersAndApp (Resolved carries no appDays here: `effective` reads the APP row)
        let rows = [app(P, Some(30)), client(P, "M1", "MANAGED", Some(60)), client(P, "C", "SELF", Some(7))];
        let r = resolve(P, &rows, &chain(&["C", "M1", "SYSTEM"])).unwrap();
        assert_eq!((r.days, r.source.as_str()), (Some(7), "OWN"));
        // nearestManagerManagedRowBeatsFartherOnesAndApp
        let rows = [
            app(P, Some(30)),
            client(P, "SYSTEM", "MANAGED", Some(90)),
            client(P, "M2", "MANAGED", Some(60)),
            client(P, "M1", "SELF", Some(1)),
            client(P, "C", "MANAGED", Some(2)),
        ];
        let r = resolve(P, &rows, &chain(&["C", "M1", "M2", "SYSTEM"])).unwrap();
        assert_eq!((r.days, r.source.as_str()), (Some(60), "MANAGER:M2"));
        // A chain naming the client again does not make it its own manager.
        let r = resolve(P, &rows, &chain(&["C", "C", "SYSTEM"])).unwrap();
        assert_eq!(r.source, "MANAGER:SYSTEM");
        // systemManagedRowIsAPlatformWideOverride
        let rows = [app(P, Some(30)), client(P, "SYSTEM", "MANAGED", Some(90))];
        let r = resolve(P, &rows, &chain(&["C", "M1", "SYSTEM"])).unwrap();
        assert_eq!((r.days, r.source.as_str()), (Some(90), "MANAGER:SYSTEM"));
        // nullDaysIsKeepForeverWhereverItWins
        let rows = [app(P, Some(30)), client(P, "M1", "MANAGED", None)];
        assert_eq!(resolve(P, &rows, &chain(&["C", "M1"])).unwrap().days, None);
        let rows = [app(P, Some(30)), client(P, "M1", "MANAGED", None), client(P, "C", "SELF", Some(10))];
        assert_eq!(resolve(P, &rows, &chain(&["C", "M1"])).unwrap().days, Some(10));
        assert_eq!(resolve(P, &[app(P, None)], &chain(&["C"])).unwrap().days, None);
        // rowsOfOtherPrefixesDoNotApplyAndUnregisteredResolvesToNull
        let rows = [app("whatsapp", Some(30)), client("whatsapp", "C", "SELF", Some(5)), app(P, Some(45))];
        let r = resolve(P, &rows, &chain(&["C"])).unwrap();
        assert_eq!((r.days, r.source.as_str()), (Some(45), "APP"));
        assert_eq!(resolve("nope", &rows, &chain(&["C"])), None);
    }

    #[test]
    fn json_and_parsing_helpers() {
        let mut r = row(9, "p", "C", "CLIENT", "SELF", Some(3));
        r.created_by = Some(4);
        r.created_at = DateTime::from_timestamp(10, 0);
        let v = r.json();
        assert_eq!((v["id"].clone(), v["createdBy"].clone(), v["createdAt"].clone(), v["retentionDays"].clone()), (9.into(), 4.into(), 10.into(), 3.into()));
        assert!(v.get("updatedAt").is_none());
        assert_eq!(parse_kind(" secured "), Some(Kind::Secured));
        assert_eq!(parse_kind("x"), None);
        assert_eq!(folder_path("app", ""), "/app");
        assert_eq!(folder_path("app", "a/b"), "/app/a/b");
        assert_eq!(body_days(&serde_json::json!({"retentionDays": " 5 "})).unwrap(), Some(5));
        assert!(body_enum(&serde_json::json!({"level": 1}), "level", &["APP"]).is_err());
        assert_eq!(require_field(Some(" a "), "x").unwrap(), "a");
    }
}
