//! `AppService` and `AppDAO` behind `AppController`: app CRUD, client access to apps, app
//! properties and dependencies, and `AppAccessEventService`'s `APP_ACCESS_CHANGED` events.

use std::collections::HashMap;

use axum::http::StatusCode;
use serde_json::{json, Value};
use sqlx::Row as _;

use crate::web::page_of;
use super::common::{cache, err, Kind, APP_CODE_NO_SPL_CHAR, APP_DEPENDENCY_SAME_APP_CODE, APP_SUBDOMAIN_TAKEN};
use super::common::{FORBIDDEN_CREATE, MANDATORY_APP_ID_CODE, MANDATORY_APP_ID_NAME, OBJECT_NOT_FOUND, OBJECT_NOT_FOUND_TO_UPDATE};
use super::entity::{self, col, Col, Entity, Row, CREATED_AT, CREATED_BY, ID, UPDATED_AT, UPDATED_BY};
use crate::admin::AdminState;
use crate::condition::{ColType, Cond, Sql, Table};
use crate::errors::{AuthError, AuthResult};
use crate::events::EventMessage;
use crate::jackson::{opt, Obj};
use crate::javamap::{iteration_order, long_hash};
use crate::model::{App, ContextAuth};
use crate::spring::Pageable;

pub const APP_TYPES: &[&str] = &["APP", "SITE", "POSTER"];
pub const ACCESS_TYPES: &[&str] = &["OWN", "ANY", "EXPLICIT"];
pub const USAGE_TYPES: &[&str] = &["S", "B", "B2C", "B2B", "B2X", "B2B2B", "B2B2C", "B2B2X", "B2X2C", "B2X2X"];
pub const STATUSES: &[&str] = &["ACTIVE", "ARCHIVED"];

static COLS: [Col; 13] = [
    ID,
    CREATED_AT,
    CREATED_BY,
    UPDATED_AT,
    UPDATED_BY,
    col("clientId", "CLIENT_ID", Kind::U64, true),
    col("appName", "APP_NAME", Kind::Str, true),
    col("appCode", "APP_CODE", Kind::Str, true),
    col("appType", "APP_TYPE", Kind::Enum(APP_TYPES), true),
    col("appAccessType", "APP_ACCESS_TYPE", Kind::Enum(ACCESS_TYPES), true),
    col("thumbUrl", "THUMB_URL", Kind::Str, false),
    col("appUsageType", "APP_USAGE_TYPE", Kind::Enum(USAGE_TYPES), true),
    col("status", "STATUS", Kind::Enum(STATUSES), true),
];

/// The security `App` DTO over `security_app`.
pub static APP: Entity = Entity {
    pojo: "App",
    table: "security_app",
    cols: &COLS,
    setters: &[
        ("clientId", "clientId"),
        ("appName", "appName"),
        ("appCode", "appCode"),
        ("appType", "appType"),
        ("appAccessType", "appAccessType"),
        ("thumbUrl", "thumbUrl"),
        ("appUsageType", "appUsageType"),
        ("status", "status"),
    ],
    aliases: &[],
    filter: Table {
        name: "security_app",
        columns: &[
            ("ID", ColType::Num),
            ("CLIENT_ID", ColType::Num),
            ("APP_NAME", ColType::Str),
            ("APP_CODE", ColType::Str),
            ("APP_TYPE", ColType::Enum),
            ("APP_ACCESS_TYPE", ColType::Enum),
            ("THUMB_URL", ColType::Str),
            ("APP_USAGE_TYPE", ColType::Enum),
            ("STATUS", ColType::Enum),
            ("CREATED_BY", ColType::Num),
            ("CREATED_AT", ColType::Ts),
            ("UPDATED_BY", ColType::Num),
            ("UPDATED_AT", ColType::Ts),
        ],
    },
    client_column: None,
};

/// `App`'s field initializer: `appAccessType = OWN`.
pub fn initial() -> Row {
    json!({"appAccessType": "OWN"}).as_object().cloned().unwrap_or_default()
}

pub fn json_of(r: &Row) -> Value {
    APP.to_json(r, vec![])
}

const APPLICATION: &str = "Application";
const APPLICATION_ACCESS: &str = "Application access";

fn not_found(id: impl std::fmt::Display) -> AuthError {
    err(StatusCode::NOT_FOUND, OBJECT_NOT_FOUND, &[APPLICATION, &id.to_string()])
}

fn forbidden_create(what: &str) -> AuthError {
    err(StatusCode::FORBIDDEN, FORBIDDEN_CREATE, &[what])
}

// ---- access events ----

/// A client's access to an app (`AppAccessEventService.Level`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    None,
    Read,
    Edit,
}

impl Level {
    pub fn of(write: bool) -> Self {
        if write {
            Self::Edit
        } else {
            Self::Read
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::None => "NONE",
            Self::Read => "READ",
            Self::Edit => "EDIT",
        }
    }
}

/// `AppAccessEventService.Action.of(previous, current)`: `None` when nothing changed.
pub fn action(previous: Level, current: Level) -> Option<&'static str> {
    if previous == current {
        return None;
    }
    Some(match (previous, current) {
        (_, Level::None) => "REMOVED",
        (Level::None, Level::Edit) => "EDIT_ADDED",
        (Level::None, _) => "READ_ADDED",
        (_, Level::Edit) => "UPGRADED_TO_EDIT",
        _ => "DOWNGRADED_TO_READ",
    })
}

/// `AppAccessEventService.raise`: `APP_ACCESS_CHANGED` for one client's access to one app; false
/// when nothing changed, the client is unknown or the publish failed.
pub async fn raise(s: &AdminState, ca: &ContextAuth, app_code: &str, app_id: u64, client_id: u64, previous: Level, current: Level) -> bool {
    let Some(action) = action(previous, current) else { return false };
    let client = match super::dao::client_type_code_level(&s.db.pool, client_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return false,
        Err(e) => {
            tracing::error!(error = %e, app_code, client_id, "could not raise APP_ACCESS_CHANGED");
            return false;
        }
    };
    let (type_code, code, level) = client;
    let mut fields: HashMap<&str, Value> = HashMap::new();
    fields.insert("action", Value::from(action));
    fields.insert("previous", Value::from(previous.name()));
    fields.insert("current", Value::from(current.name()));
    fields.insert("appCode", Value::from(app_code));
    fields.insert("appId", Value::from(app_id.to_string()));
    fields.insert("clientCode", Value::from(code.clone()));
    fields.insert("clientId", Value::from(client_id.to_string()));
    fields.insert("clientTypeCode", Value::from(type_code));
    fields.insert("clientLevelType", Value::from(level));
    fields.insert("changedBy", Value::from(ca.user.id().to_string()));
    let keys: Vec<&str> = fields.keys().copied().collect();
    let data = crate::javamap::hash_map_order_str(keys).into_iter().map(|k| (k.to_string(), fields[k].clone())).collect();
    let event = EventMessage {
        event_name: "APP_ACCESS_CHANGED".into(),
        client_code: Some(code),
        app_code: Some(app_code.to_string()),
        data,
        ..Default::default()
    };
    match s.events.publish(&event).await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, app_code, client_id, "could not raise APP_ACCESS_CHANGED");
            false
        }
    }
}

// ---- reads ----

/// `AppService.read(id)` (`AppDAO.readById`: the access join does not restrict it).
pub async fn read(s: &AdminState, id: u64) -> AuthResult<Row> {
    entity::read_by_id(&s.db, &APP, id).await
}

/// `AppDAO.getByAppCode` (uncached).
pub async fn by_code(s: &AdminState, code: &str) -> AuthResult<Option<Row>> {
    let sql = format!("SELECT {} FROM security_app WHERE security_app.APP_CODE = ? LIMIT 1", APP.select_list());
    let r = sqlx::query(&sql).bind(code).fetch_optional(&s.db.pool).await?;
    r.as_ref().map(|r| APP.read_row(r)).transpose()
}

/// The shared `App` model as a row.
pub fn row_of(a: &App) -> Row {
    let ts = |t: Option<chrono::NaiveDateTime>| t.map(|t| Value::from(t.and_utc().timestamp())).unwrap_or(Value::Null);
    json!({
        "id": a.id, "createdAt": ts(a.created_at), "createdBy": a.created_by, "updatedAt": ts(a.updated_at), "updatedBy": a.updated_by,
        "clientId": a.client_id, "appName": a.app_name, "appCode": a.app_code, "appType": a.app_type,
        "appAccessType": a.app_access_type, "thumbUrl": a.thumb_url, "appUsageType": a.app_usage_type, "status": a.status
    })
    .as_object()
    .cloned()
    .unwrap_or_default()
}

/// `AppDAO.getSelectJointStep` + `filter`: a non-SYSTEM caller sees the apps its client owns or has
/// edit access to (any access with `read_access`).
pub async fn page(s: &AdminState, ca: &ContextAuth, pageable: &Pageable, cond: Option<&Cond>, read_access: bool) -> AuthResult<Value> {
    let mut sql = cond.map(|c| crate::condition::to_sql(c, &APP.filter)).transpose()?.flatten();
    let mut joins = String::new();
    if !ca.is_system_client() {
        let client = ca.user.client_id();
        joins = format!(
            " LEFT JOIN security_app_access ON (security_app_access.APP_ID = security_app.ID AND security_app_access.CLIENT_ID = {client})"
        );
        let edit = if read_access { "" } else { " AND security_app_access.EDIT_ACCESS = 1" };
        sql = Sql::and(
            sql,
            Some(Sql::text(format!("(security_app.CLIENT_ID = {client} OR (security_app_access.CLIENT_ID = {client}{edit}))"))),
        );
    }
    let build = |select: &str| {
        let mut qb = sqlx::QueryBuilder::<sqlx::MySql>::new(format!("SELECT {select} FROM security_app{joins}"));
        if let Some(c) = &sql {
            qb.push(" WHERE ");
            c.push_to(&mut qb);
        }
        qb
    };
    let mut qb = build(&APP.select_list());
    qb.push(crate::condition::order_by(&pageable.sort, &APP.filter));
    qb.push(" LIMIT ").push_bind(pageable.size).push(" OFFSET ").push_bind(pageable.offset());
    let rows = qb.build().fetch_all(&s.db.pool).await?;
    let count: i64 = build("COUNT(*)").build().fetch_one(&s.db.pool).await?.try_get(0)?;
    let content = rows.iter().map(|r| APP.read_row(r).map(|r| json_of(&r))).collect::<AuthResult<Vec<_>>>()?;
    Ok(page_of(content, pageable, count))
}

/// `findAnyAppsByPage`: the `ANY` apps of the client the caller signed in from; SYSTEM, or a
/// caller in its own client, gets `Page.empty()` (which Java cannot write: 500).
pub async fn find_any_apps(s: &AdminState, ca: &ContextAuth, pageable: &Pageable, cond: Option<&Cond>) -> AuthResult<Value> {
    if ca.is_system_client() || ca.logged_in_from_client_id == Some(ca.user.client_id()) {
        return Err(super::common::unpaged_empty_page());
    }
    let client = ca.logged_in_from_client_id.unwrap_or(0);
    let base = cond.map(|c| crate::condition::to_sql(c, &APP.filter)).transpose()?.flatten();
    let any = Sql::text(format!("security_app.CLIENT_ID = {client} AND security_app.APP_ACCESS_TYPE = 'ANY'"));
    let sql = match base {
        Some(b) => {
            let mut x = Sql::text("(");
            x.append(b);
            x.push_text(" AND ");
            x.append(any);
            x.push_text(")");
            x
        }
        None => {
            let mut x = Sql::text("(");
            x.append(any);
            x.push_text(")");
            x
        }
    };
    let build = |select: &str| {
        let mut qb = sqlx::QueryBuilder::<sqlx::MySql>::new(format!("SELECT {select} FROM security_app WHERE "));
        sql.push_to(&mut qb);
        qb
    };
    let mut qb = build(&APP.select_list());
    qb.push(crate::condition::order_by(&pageable.sort, &APP.filter));
    qb.push(" LIMIT ").push_bind(pageable.size).push(" OFFSET ").push_bind(pageable.offset());
    let rows = qb.build().fetch_all(&s.db.pool).await?;
    let count: i64 = build("COUNT(*)").build().fetch_one(&s.db.pool).await?.try_get(0)?;
    let content = rows.iter().map(|r| APP.read_row(r).map(|r| json_of(&r))).collect::<AuthResult<Vec<_>>>()?;
    Ok(page_of(content, pageable, count))
}

/// `getAppByCodeCheckAccess`: the app, when SYSTEM or the caller's client may read it.
pub async fn by_code_check_access(s: &AdminState, ca: &ContextAuth, code: &str) -> AuthResult<Option<Value>> {
    let Some(app) = s.dir().app_by_code(code).await? else { return Ok(None) };
    if ca.is_system_client() || s.dir().has_read_access(code, ca.client_code.as_deref()).await? {
        return Ok(Some(app.to_json()));
    }
    Ok(None)
}

/// `hasReadAccess(String[] appCodes)` for the caller's client, as Java's `HashMap` orders it.
pub async fn read_access_map(s: &AdminState, ca: &ContextAuth, codes: &[String]) -> AuthResult<Value> {
    let mut seen = std::collections::HashSet::new();
    let mut entries = Vec::new();
    for c in codes {
        if !seen.insert(c.clone()) {
            continue;
        }
        let b = s.dir().has_read_access(c, ca.client_code.as_deref()).await?;
        entries.push((platform::java::string_hash_code(c), (c.clone(), b)));
    }
    let mut m = serde_json::Map::new();
    for (k, b) in iteration_order(entries) {
        m.insert(k, Value::Bool(b));
    }
    Ok(Value::Object(m))
}

/// `findBaseClientCodeForOverride(appCode)`: `[ownerCode, explicit]` for an app another client
/// owns.
pub async fn base_client_code(s: &AdminState, ca: &ContextAuth, code: &str) -> AuthResult<Option<Value>> {
    let Some(app) = s.dir().app_by_code(code).await? else { return Ok(None) };
    if app.client_id == ca.user.client_id() {
        return Ok(None);
    }
    let Some(owner) = s.dir().client(app.client_id).await? else { return Ok(None) };
    if app.app_access_type.as_deref() == Some("EXPLICIT") {
        let write = s.db.has_write_access(code, ca.client_code.as_deref().unwrap_or("")).await?;
        return Ok(write.then(|| json!([owner.code(), true])));
    }
    Ok(Some(json!([owner.code(), false])))
}

/// `hasDeleteAccess(appCode, clientCode)`.
pub async fn has_delete_access(s: &AdminState, ca: &ContextAuth, app_code: &str, client_code: &str) -> AuthResult<bool> {
    if !s.db.has_write_access(app_code, client_code).await? {
        return Ok(false);
    }
    if !ca.is_system_client() {
        let managed = match s.client_by_code(client_code).await? {
            Some(c) => s.caller_manages_client(ca, c.id()).await?,
            None => false,
        };
        if !managed || !s.db.has_write_access(app_code, ca.client_code.as_deref().unwrap_or("")).await? {
            return Ok(false);
        }
    }
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM security_app_access JOIN security_app ON security_app_access.APP_ID = security_app.ID \
         JOIN security_client ON security_app_access.CLIENT_ID = security_client.ID WHERE (security_app.APP_CODE = ? AND security_client.CODE <> ?)",
    )
    .bind(app_code)
    .bind(client_code)
    .fetch_one(&s.db.pool)
    .await?;
    Ok(n == 0)
}

/// `AppDAO.getAppClients`: the clients holding access rows on the app, plus its owner.
pub async fn app_clients(s: &AdminState, ca: &ContextAuth, app_code: &str, only_write: Option<bool>, name: Option<&str>, pageable: &Pageable) -> AuthResult<Value> {
    let Some(only_write) = only_write else {
        return Err(AuthError::internal("Cannot invoke \"java.lang.Boolean.booleanValue()\" because \"onlyWriteAccess\" is null"));
    };
    if !ca.is_system_client() && !s.db.has_write_access(app_code, ca.client_code.as_deref().unwrap_or("")).await? {
        return Ok(page_of(vec![], pageable, 0));
    }
    let edit = if only_write { " AND security_app_access.EDIT_ACCESS = 1" } else { "" };
    let restrict = (!ca.is_system_client()).then(|| ca.user.client_id());
    let like = name.filter(|n| !n.trim().is_empty()).map(|n| format!("%{}%", n.trim()));
    let build = |select: &str| {
        let mut qb = sqlx::QueryBuilder::<sqlx::MySql>::new(format!(
            "SELECT {select} FROM security_client WHERE (security_client.ID IN (SELECT security_app_access.CLIENT_ID FROM security_app_access \
             JOIN security_app ON security_app_access.APP_ID = security_app.ID WHERE (security_app.APP_CODE = "
        ));
        qb.push_bind(app_code.to_string()).push(edit);
        qb.push(") UNION SELECT security_app.CLIENT_ID FROM security_app WHERE security_app.APP_CODE = ").push_bind(app_code.to_string());
        qb.push(")");
        if let Some(l) = &like {
            qb.push(" AND (LOWER(security_client.NAME) LIKE LOWER(").push_bind(l.clone());
            qb.push(") OR LOWER(security_client.CODE) LIKE LOWER(").push_bind(l.clone()).push("))");
        }
        if let Some(c) = restrict {
            qb.push(format!(
                " AND security_client.ID IN (SELECT security_client_hierarchy.CLIENT_ID FROM security_client_hierarchy WHERE {})",
                crate::data::manage_client_condition(c)
            ));
        }
        qb.push(")");
        qb
    };
    let mut orders: Vec<String> = pageable
        .sort
        .iter()
        .filter_map(|o| {
            let col = snake(&o.property);
            crate::data::filters::CLIENT
                .columns
                .iter()
                .find(|(c, _)| *c == col)
                .map(|(c, _)| format!("security_client.{c} {}", if o.ascending { "ASC" } else { "DESC" }))
        })
        .collect();
    if orders.is_empty() {
        orders.push("security_client.NAME ASC".into());
    }
    let cols = crate::mysql::CLIENT_COLUMNS.split(", ").map(|c| format!("security_client.{}", c.trim())).collect::<Vec<_>>().join(", ");
    let mut qb = build(&cols);
    qb.push(format!(" ORDER BY {}", orders.join(", ")));
    qb.push(" LIMIT ").push_bind(pageable.size).push(" OFFSET ").push_bind(pageable.offset());
    let rows = qb.build().fetch_all(&s.db.pool).await?;
    let count: i64 = build("COUNT(*)").build().fetch_one(&s.db.pool).await?.try_get(0)?;
    let content = rows
        .iter()
        .map(|r| crate::mysql::client(r).map(|c| crate::dto::client_json(&c, &Default::default())))
        .collect::<AuthResult<Vec<_>>>()?;
    Ok(page_of(content, pageable, count))
}

/// `([a-z])([A-Z])` -> `$1_$2`, upper case (the client listing's sort fields).
fn snake(property: &str) -> String {
    let mut out = String::new();
    let mut prev_lower = false;
    for c in property.chars() {
        if c.is_ascii_uppercase() && prev_lower {
            out.push('_');
        }
        prev_lower = c.is_ascii_lowercase();
        out.push(c.to_ascii_uppercase());
    }
    out
}

// ---- writes ----

/// `StringUtil.onlyAlphabetAllowed`.
pub fn only_letters(code: &str) -> bool {
    code.chars().all(|c| c.is_ascii_alphabetic())
}

/// `UniqueUtil.base36UUID()`: the first eight characters of a random UUID's text, read as a long,
/// in base 36.
fn base36_uuid() -> String {
    let hex = super::urls::random_hex();
    let text = format!("{}-{}", &hex[..8], &hex[8..12]);
    let bytes: [u8; 8] = text.as_bytes()[..8].try_into().unwrap_or([b'0'; 8]);
    // ASCII hex text: the long is never negative.
    let mut v = u64::from_be_bytes(bytes);
    let mut digits = Vec::new();
    loop {
        let d = (v % 36) as u8;
        digits.push(if d < 10 { b'0' + d } else { b'a' + d - 10 } as char);
        v /= 36;
        if v == 0 {
            break;
        }
    }
    digits.iter().rev().collect()
}

/// `UniqueUtil.uniqueNameOnlyLetters(36, name)`: up to 22 lower-case letters of the name and two
/// random strings.
pub fn unique_letters(name: &str) -> String {
    let mut out = String::new();
    let mut i = 0;
    let max = 36 - 15;
    for part in [name.to_string(), base36_uuid(), base36_uuid()] {
        if i > max {
            break;
        }
        for c in part.chars() {
            if i > max {
                break;
            }
            let l = c.to_ascii_lowercase();
            if l.is_ascii_lowercase() {
                out.push(l);
                i += 1;
            }
        }
    }
    out
}

/// `AppDAO.generateAppCode(app)`: from the name (or `newapp`), until no app has it.
pub async fn generate_app_code(s: &AdminState, app_name: Option<&str>) -> AuthResult<String> {
    let mut name: String = app_name.unwrap_or("newapp").to_string();
    if name.chars().count() > 24 {
        name = name.chars().take(24).collect();
    }
    let mut code = unique_letters(&name);
    loop {
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM security_app WHERE APP_CODE = ?").bind(&code).fetch_one(&s.db.pool).await?;
        if n == 0 {
            return Ok(code);
        }
        code = unique_letters(&code);
    }
}

/// `checkSubdomainFreeForAppCode`: nobody may already hold the hostnames the app would answer on.
async fn check_subdomain_free(s: &AdminState, app_code: &str) -> AuthResult<()> {
    let code = app_code.trim().to_lowercase();
    let hosts: Vec<String> = s.dir().subdomain_endings.iter().map(|e| format!("{code}{e}")).collect();
    if hosts.is_empty() {
        return Ok(());
    }
    let mut qb = sqlx::QueryBuilder::<sqlx::MySql>::new("SELECT URL_PATTERN FROM security_client_url WHERE (");
    let mut first = true;
    for h in &hosts {
        for p in [h.clone(), format!("http://{h}"), format!("https://{h}")] {
            if !first {
                qb.push(" OR ");
            }
            first = false;
            qb.push("LOWER(URL_PATTERN) = LOWER(").push_bind(p).push(")");
        }
    }
    qb.push(") LIMIT 1");
    let taken: Option<String> = qb.build_query_scalar().fetch_optional(&s.db.pool).await?;
    match taken {
        Some(t) => Err(err(StatusCode::CONFLICT, APP_SUBDOMAIN_TAKEN, &[&t, app_code])),
        None => Ok(()),
    }
}

/// `AppDAO.addClientAccess`: the access row, or its edit flag; true only when a row was added.
pub async fn add_access_row(s: &AdminState, ca: &ContextAuth, app_id: u64, client_id: u64, write: bool) -> AuthResult<bool> {
    let user = ca.user.id();
    let n = sqlx::query(
        "INSERT INTO security_app_access (APP_ID, CLIENT_ID, EDIT_ACCESS, CREATED_BY) VALUES (?, ?, ?, ?) \
         ON DUPLICATE KEY UPDATE EDIT_ACCESS = ?, UPDATED_BY = ?",
    )
    .bind(app_id)
    .bind(client_id)
    .bind(u8::from(write))
    .bind(user)
    .bind(u8::from(write))
    .bind(user)
    .execute(&s.db.pool)
    .await?
    .rows_affected();
    Ok(n == 1)
}

/// An access row: (id, app, client, edit).
async fn access_row(s: &AdminState, where_sql: &str, a: u64, b: Option<u64>) -> AuthResult<Option<(u64, u64, u64, bool)>> {
    let sql = format!("SELECT ID, APP_ID, CLIENT_ID, EDIT_ACCESS FROM security_app_access WHERE {where_sql} LIMIT 1");
    let mut q = sqlx::query(&sql).bind(a);
    if let Some(b) = b {
        q = q.bind(b);
    }
    let r = q.fetch_optional(&s.db.pool).await?;
    r.map(|r| Ok((r.try_get::<u64, _>(0)?, r.try_get::<u64, _>(1)?, r.try_get::<u64, _>(2)?, r.try_get::<u8, _>(3)? == 1)))
        .transpose()
}

fn level_of(row: &Option<(u64, u64, u64, bool)>) -> Level {
    match row {
        None => Level::None,
        Some((_, _, _, edit)) => Level::of(*edit),
    }
}

/// `AppService.evict(appId, clientId)`: the client's read and write access entries for the app.
/// Empty (`false`) when the client is unknown.
async fn evict_access(s: &AdminState, app_id: u64, client_id: u64) -> AuthResult<bool> {
    let app = read(s, app_id).await?;
    let Some((_, code, _)) = super::dao::client_type_code_level(&s.db.pool, client_id).await? else { return Ok(false) };
    let key = format!("{}:{code}", entity::str_of(&app, "appCode").unwrap_or("null"));
    let svc = &s.caches().service;
    svc.evict_everywhere(cache::APP_WRITE_ACCESS, &key).await;
    svc.evict_everywhere(cache::APP_READ_ACCESS, &key).await;
    Ok(true)
}

async fn evict_inheritance(s: &AdminState) {
    s.caches().service.evict_all_everywhere(cache::APP_INHERITANCE).await;
}

/// `addClientAccess(appId, clientId, writeAccess)`.
pub async fn add_client_access(s: &AdminState, ca: &ContextAuth, app_id: u64, client_id: Option<u64>, write: bool) -> AuthResult<bool> {
    let refused = || forbidden_create(APPLICATION_ACCESS);
    let app = read(s, app_id).await?;
    let client_id = client_id.ok_or_else(|| AuthError::internal("Cannot invoke \"org.jooq.types.ULong.equals(Object)\" because \"clientId\" is null"))?;
    let previous = level_of(&access_row(s, "APP_ID = ? AND CLIENT_ID = ?", app_id, Some(client_id)).await?);
    let user_client = ca.user.client_id();
    let app_client = entity::u64_of(&app, "clientId").unwrap_or(0);
    if !(ca.is_system_client() && app_client == user_client) {
        if !s.is_client_being_managed_by(app_client, client_id).await? {
            return Err(refused());
        }
        if user_client != app_client && entity::str_of(&app, "appAccessType") != Some("ANY") {
            return Err(refused());
        }
    }
    add_access_row(s, ca, app_id, client_id, write).await?;
    raise(s, ca, entity::str_of(&app, "appCode").unwrap_or(""), app_id, client_id, previous, Level::of(write)).await;
    let evicted = evict_access(s, app_id, client_id).await?;
    if !evicted {
        return Err(refused());
    }
    evict_inheritance(s).await;
    Ok(true)
}

/// `AppService.grantRegistrationAccess(appId, clientId, writeAccess)`: the access a
/// registration grants, announced and evicted like any other; no caller checks.
pub async fn grant_registration_access(s: &AdminState, ca: &ContextAuth, app_id: u64, client_id: u64, write: bool) -> AuthResult<bool> {
    let previous = level_of(&access_row(s, "APP_ID = ? AND CLIENT_ID = ?", app_id, Some(client_id)).await?);
    let added = add_access_row(s, ca, app_id, client_id, write).await?;
    if let Ok(app) = s.dir().app_by_id(app_id).await {
        raise(s, ca, &app.app_code, app_id, client_id, previous, Level::of(write)).await;
    }
    evict_access(s, app_id, client_id).await?;
    Ok(added)
}

/// SYSTEM may change anyone's access; anyone else only on an app their own client owns.
fn may_change_access(ca: &ContextAuth, app: &Row) -> bool {
    ca.is_system_client() || entity::u64_of(app, "clientId") == Some(ca.user.client_id())
}

/// `removeClient(appId, accessId)`.
pub async fn remove_client_access(s: &AdminState, ca: &ContextAuth, app_id: u64, access_id: u64) -> AuthResult<bool> {
    let app = read(s, app_id).await?;
    if !may_change_access(ca, &app) {
        // The message key passed is the literal "Application access", which the bundle lacks.
        return Err(err(StatusCode::FORBIDDEN, APPLICATION_ACCESS, &[&access_id.to_string()]));
    }
    let row = access_row(s, "ID = ?", access_id, None).await?.filter(|r| r.1 == app_id);
    let Some(row) = row else {
        evict_inheritance(s).await;
        return Ok(false);
    };
    let removed = sqlx::query("DELETE FROM security_app_access WHERE (ID = ? AND APP_ID = ?)")
        .bind(row.0)
        .bind(app_id)
        .execute(&s.db.pool)
        .await?
        .rows_affected()
        == 1;
    if removed {
        raise(s, ca, entity::str_of(&app, "appCode").unwrap_or(""), app_id, row.2, Level::of(row.3), Level::None).await;
        evict_access(s, app_id, row.2).await?;
    }
    evict_inheritance(s).await;
    Ok(removed)
}

/// `updateClientAccess(accessId, writeAccess)`: the affected-row count as MySQL reports it
/// (an unchanged flag is `false`).
pub async fn update_client_access(s: &AdminState, ca: &ContextAuth, access_id: Option<u64>, write: bool) -> AuthResult<bool> {
    let refused = || err(StatusCode::FORBIDDEN, OBJECT_NOT_FOUND_TO_UPDATE, &[APPLICATION_ACCESS, &opt_text(access_id)]);
    let Some(access_id) = access_id else { return Err(refused()) };
    let Some(row) = access_row(s, "ID = ?", access_id, None).await? else { return Err(refused()) };
    let app = read(s, row.1).await?;
    if !may_change_access(ca, &app) {
        return Err(refused());
    }
    let updated = sqlx::query("UPDATE security_app_access SET EDIT_ACCESS = ? WHERE ID = ?")
        .bind(u8::from(write))
        .bind(access_id)
        .execute(&s.db.pool)
        .await?
        .rows_affected()
        == 1;
    raise(s, ca, entity::str_of(&app, "appCode").unwrap_or(""), row.1, row.2, Level::of(row.3), Level::of(write)).await;
    if !evict_access(s, row.1, row.2).await? {
        return Err(refused());
    }
    evict_inheritance(s).await;
    Ok(updated)
}

fn opt_text(v: Option<u64>) -> String {
    v.map(|v| v.to_string()).unwrap_or_else(|| "null".into())
}

/// The evictions after an app changes (`update(entity)`).
async fn evict_after_update(s: &AdminState, r: &Row) {
    let svc = &s.caches().service;
    for name in [cache::APP_INHERITANCE, cache::CLIENT_URI, cache::CLIENT_URL, cache::GATEWAY_URL_CLIENT_APP_CODE] {
        svc.evict_all_everywhere(name).await;
    }
    let code = entity::str_of(r, "appCode").unwrap_or("null").to_string();
    svc.evict_everywhere(cache::APP_BY_CODE, &code).await;
    svc.evict_everywhere(cache::APP_STATUS, &code).await;
    svc.evict_everywhere(cache::APP_BY_ID, &opt_text(entity::u64_of(r, "id"))).await;
}

/// `AppService.create(entity)`.
pub async fn create(s: &AdminState, ca: &ContextAuth, mut entity: Row) -> AuthResult<Row> {
    if let Some(code) = entity::str_of(&entity, "appCode") {
        if !only_letters(code) {
            return Err(err(StatusCode::BAD_REQUEST, APP_CODE_NO_SPL_CHAR, &[]));
        }
    }
    let user_client = ca.user.client_id();
    let explicit = entity::str_of(&entity, "appAccessType") == Some("EXPLICIT");
    if explicit {
        let managed = s.dir().managed_client(user_client).await?;
        let owner = match managed.id {
            Some(id) => id,
            None => super::dao::system_client_id(&s.db.pool).await?.ok_or_else(|| forbidden_create(APPLICATION))?,
        };
        entity.insert("clientId".into(), Value::from(owner));
    } else {
        if entity.get("clientId").is_none_or(Value::is_null) {
            entity.insert("clientId".into(), Value::from(user_client));
        }
        let target = entity::u64_of(&entity, "clientId").unwrap_or(0);
        if !(ca.is_system_client() || target == user_client || s.caller_manages_client(ca, target).await?) {
            return Err(forbidden_create(APPLICATION));
        }
    }
    if entity.get("appCode").is_none_or(Value::is_null) {
        let code = generate_app_code(s, entity::str_of(&entity, "appName")).await?;
        entity.insert("appCode".into(), Value::from(code));
    }
    let code = entity::str_of(&entity, "appCode").unwrap_or("").to_string();
    check_subdomain_free(s, &code).await?;
    entity.insert("createdBy".into(), Value::Null);
    let id = entity::insert(&s.db, &APP, &entity).await?;
    let created = read(s, id).await?;
    if explicit {
        add_access_row(s, ca, id, user_client, true).await?;
        raise(s, ca, &code, id, user_client, Level::None, Level::Edit).await;
    }
    super::urls::mint_draft_url(s, ca, &code).await?;
    let svc = &s.caches().service;
    svc.evict_all_everywhere(cache::APP_INHERITANCE).await;
    svc.evict_all_everywhere(cache::CLIENT_URI).await;
    Ok(created)
}

/// `AppService.updatableEntity`: the stored app with the five editable fields copied over, when
/// the caller may change it (SYSTEM; edit access for an EXPLICIT app; else a managed owner).
async fn updatable(s: &AdminState, ca: &ContextAuth, entity: &Row) -> AuthResult<Option<Row>> {
    let id = entity::u64_of(entity, "id").unwrap_or(0);
    let mut existing = read(s, id).await?;
    for k in ["appName", "appAccessType", "thumbUrl", "appUsageType", "status"] {
        existing.insert(k.into(), entity.get(k).cloned().unwrap_or(Value::Null));
    }
    if ca.is_system_client() {
        return Ok(Some(existing));
    }
    if entity::str_of(&existing, "appAccessType") == Some("EXPLICIT") {
        let write = super::dao::has_access_by_id(&s.db.pool, id, Some(ca.user.client_id()), true).await?;
        return Ok(write.then_some(existing));
    }
    if s.caller_manages_client(ca, entity::u64_of(&existing, "clientId").unwrap_or(0)).await? {
        return Ok(Some(existing));
    }
    Err(not_found(id))
}

/// `AppService.update(entity)`.
pub async fn update(s: &AdminState, ca: &ContextAuth, entity: &Row) -> AuthResult<Row> {
    let id = entity::u64_of(entity, "id").unwrap_or(0);
    read(s, id).await?;
    let Some(e) = updatable(s, ca, entity).await? else { return Err(not_found(id)) };
    entity::update(&s.db, &APP, &e).await?;
    let updated = read(s, id).await?;
    evict_after_update(s, &updated).await;
    Ok(updated)
}

/// `AppService.update(key, fields)`.
pub async fn patch(s: &AdminState, ca: &ContextAuth, id: u64, fields: &serde_json::Map<String, Value>) -> AuthResult<Row> {
    let mut row = read(s, id).await?;
    APP.patch(&mut row, fields)?;
    let updated = update(s, ca, &row).await?;
    let svc = &s.caches().service;
    svc.evict_all_everywhere(cache::APP_INHERITANCE).await;
    svc.evict_everywhere(cache::APP_BY_CODE, entity::str_of(&updated, "appCode").unwrap_or("null")).await;
    svc.evict_everywhere(cache::APP_BY_ID, &id.to_string()).await;
    Ok(updated)
}

/// Whether the caller may delete the app (the comparison of the app's client with the app's own
/// id is Java's).
async fn may_delete(s: &AdminState, ca: &ContextAuth, id: u64, app: &Row) -> AuthResult<bool> {
    let app_client = entity::u64_of(app, "clientId").unwrap_or(0);
    if ca.is_system_client() || app_client == id {
        return Ok(true);
    }
    if entity::str_of(app, "appAccessType") == Some("EXPLICIT") {
        return super::dao::has_access_by_id(&s.db.pool, id, Some(ca.user.client_id()), true).await;
    }
    s.caller_manages_client(ca, app_client).await
}

/// `AppService.delete(id)`: an ACTIVE app is archived; an archived one is deleted with its draft
/// URLs.
pub async fn delete(s: &AdminState, ca: &ContextAuth, id: u64) -> AuthResult<()> {
    let mut app = read(s, id).await?;
    if !may_delete(s, ca, id, &app).await? {
        return Err(not_found(id));
    }
    if entity::str_of(&app, "status") == Some("ACTIVE") {
        app.insert("status".into(), Value::from("ARCHIVED"));
        update(s, ca, &app).await?;
        return Ok(());
    }
    let code = entity::str_of(&app, "appCode").unwrap_or("").to_string();
    sqlx::query("DELETE FROM security_client_url WHERE (APP_CODE = ? AND URL_TYPE = 'DRAFT')").bind(&code).execute(&s.db.pool).await?;
    entity::delete(&s.db, &APP, id).await?;
    let svc = &s.caches().service;
    svc.evict_all_everywhere(cache::APP_INHERITANCE).await;
    svc.evict_everywhere(cache::APP_BY_CODE, &code).await;
    svc.evict_everywhere(cache::APP_BY_ID, &id.to_string()).await;
    svc.evict_all_everywhere(cache::CLIENT_URL).await;
    svc.evict_all_everywhere(cache::GATEWAY_URL_CLIENT_APP_CODE).await;
    svc.evict_everywhere(cache::APP_STATUS, &code).await;
    Ok(())
}

/// `AppDAO.deleteEverythingRelated`, in one transaction.
async fn delete_everything_related(s: &AdminState, app_id: u64, app_code: &str) -> AuthResult<bool> {
    let mut tx = s.db.pool.begin().await?;
    sqlx::query("DELETE FROM security_app_property WHERE APP_ID = ?").bind(app_id).execute(&mut *tx).await?;
    let url_ids: Vec<u64> = sqlx::query_scalar("SELECT ID FROM security_client_url WHERE APP_CODE = ?").bind(app_code).fetch_all(&mut *tx).await?;
    let permission_ids: Vec<u64> = sqlx::query_scalar("SELECT ID FROM security_permission WHERE APP_ID = ?").bind(app_id).fetch_all(&mut *tx).await?;
    let list = |ids: &[u64]| if ids.is_empty() { "NULL".to_string() } else { ids.iter().map(u64::to_string).collect::<Vec<_>>().join(", ") };
    let in_or_false = |col: &str, ids: &[u64]| if ids.is_empty() { "1 = 0".to_string() } else { format!("{col} IN ({})", list(ids)) };
    let request_ids: Vec<u64> = sqlx::query_scalar(&format!("SELECT ID FROM security_ssl_request WHERE {}", in_or_false("URL_ID", &url_ids)))
        .fetch_all(&mut *tx)
        .await?;
    sqlx::query(&format!("DELETE FROM security_ssl_certificate WHERE {}", in_or_false("URL_ID", &url_ids))).execute(&mut *tx).await?;
    sqlx::query(&format!("DELETE FROM security_ssl_challenge WHERE {}", in_or_false("REQUEST_ID", &request_ids))).execute(&mut *tx).await?;
    sqlx::query(&format!("DELETE FROM security_ssl_request WHERE {}", in_or_false("ID", &request_ids))).execute(&mut *tx).await?;
    sqlx::query(&format!("DELETE FROM security_client_url WHERE {}", in_or_false("ID", &url_ids))).execute(&mut *tx).await?;
    sqlx::query(&format!("DELETE FROM security_permission WHERE {}", in_or_false("ID", &permission_ids))).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM security_app_access WHERE APP_ID = ?").bind(app_id).execute(&mut *tx).await?;
    let n = sqlx::query("DELETE FROM security_app WHERE ID = ?").bind(app_id).execute(&mut *tx).await?.rows_affected();
    tx.commit().await?;
    Ok(n == 1)
}

/// `deleteEverything(id, forceDelete)`.
pub async fn delete_everything(s: &AdminState, ca: &ContextAuth, id: u64, force: bool) -> AuthResult<bool> {
    let app = read(s, id).await?;
    let app_client = entity::u64_of(&app, "clientId").unwrap_or(0);
    let allowed = if ca.is_system_client() || app_client == id || Some(app_client) == ca.logged_in_from_client_id {
        if force {
            true
        } else {
            let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM security_app_access WHERE (APP_ID = ? AND CLIENT_ID <> ?)")
                .bind(id)
                .bind(ca.user.client_id())
                .fetch_one(&s.db.pool)
                .await?;
            n == 0
        }
    } else {
        false
    };
    if !allowed {
        return Err(not_found(id));
    }
    let code = entity::str_of(&app, "appCode").unwrap_or("").to_string();
    let done = delete_everything_related(s, id, &code).await?;
    let svc = &s.caches().service;
    svc.evict_all_everywhere(cache::APP_INHERITANCE).await;
    svc.evict_everywhere(cache::APP_BY_CODE, &code).await;
    svc.evict_everywhere(cache::APP_BY_ID, &id.to_string()).await;
    Ok(done)
}

// ---- properties ----

/// An `security_app_property` row as the DTO.
pub fn property_json(r: &sqlx::mysql::MySqlRow) -> AuthResult<(u64, String, Value)> {
    let ts = |c: &str| -> AuthResult<Value> { Ok(crate::mysql::ts(r, c)?.map(|t| Value::from(t.and_utc().timestamp())).unwrap_or(Value::Null)) };
    let client: u64 = r.try_get("CLIENT_ID")?;
    let name: String = r.try_get("NAME")?;
    let v = Obj::new()
        .put("id", r.try_get::<u64, _>("ID")?)
        .put("createdAt", ts("CREATED_AT")?)
        .put("createdBy", opt(r.try_get::<Option<u64>, _>("CREATED_BY")?))
        .put("updatedAt", ts("UPDATED_AT")?)
        .put("updatedBy", opt(r.try_get::<Option<u64>, _>("UPDATED_BY")?))
        .put("clientId", client)
        .put("appId", r.try_get::<u64, _>("APP_ID")?)
        .put("name", name.clone())
        .put("value", opt(r.try_get::<Option<String>, _>("VALUE")?))
        .build();
    Ok((client, name, v))
}

/// `AppDAO.convertAttributesToMap`: per client, its properties by name, the app owner's filling in
/// what another client lacks; written in `HashMap` order.
pub fn properties_map(app_client: u64, props: Vec<(u64, String, Value)>) -> Value {
    let mut defaults: Vec<(String, Value)> = Vec::new();
    let mut per_client: Vec<(u64, Vec<(String, Value)>)> = Vec::new();
    for (client, name, v) in props {
        if client == app_client {
            put(&mut defaults, name.clone(), v.clone());
        }
        match per_client.iter_mut().find(|(c, _)| *c == client) {
            Some((_, m)) => put(m, name, v),
            None => per_client.push((client, vec![(name, v)])),
        }
    }
    for (client, m) in per_client.iter_mut() {
        if *client == app_client {
            continue;
        }
        for (k, v) in &defaults {
            if !m.iter().any(|(n, _)| n == k) {
                m.push((k.clone(), v.clone()));
            }
        }
    }
    let mut out = serde_json::Map::new();
    let ordered = iteration_order(per_client.into_iter().map(|(c, m)| (long_hash(c), (c, m))).collect());
    for (c, m) in ordered {
        let mut inner = serde_json::Map::new();
        for (k, v) in iteration_order(m.into_iter().map(|(k, v)| (platform::java::string_hash_code(&k), (k, v))).collect()) {
            inner.insert(k, v);
        }
        out.insert(c.to_string(), Value::Object(inner));
    }
    Value::Object(out)
}

fn put(m: &mut Vec<(String, Value)>, k: String, v: Value) {
    match m.iter_mut().find(|(n, _)| *n == k) {
        Some(e) => e.1 = v,
        None => m.push((k, v)),
    }
}

/// `AppService.getProperties(clientId, appId, appCode, propName)`: the property map, or `None`
/// when the caller may not read the client's or the app is unknown (`Map.of()`).
pub async fn properties(s: &AdminState, ca: &ContextAuth, client_id: Option<u64>, app_id: Option<u64>, app_code: Option<&str>, prop: Option<&str>) -> AuthResult<Option<Value>> {
    if app_id.is_none() && super::common::blank(app_code) {
        return Err(err(StatusCode::BAD_REQUEST, MANDATORY_APP_ID_CODE, &[]));
    }
    let ids: Vec<u64> = if ca.is_system_client() {
        client_id.into_iter().collect()
    } else {
        let own = ca.user.client_id();
        match client_id {
            None => vec![own],
            Some(c) if c == own => vec![own],
            Some(c) if s.caller_manages_client(ca, c).await? => vec![c],
            Some(_) => return Ok(None),
        }
    };
    let app = match app_id {
        Some(id) => entity::by_id(&s.db, &APP, id).await?,
        None => by_code(s, app_code.unwrap_or("")).await?,
    };
    let Some(app) = app else { return Ok(None) };
    let app_id = entity::u64_of(&app, "id").unwrap_or(0);
    let app_client = entity::u64_of(&app, "clientId").unwrap_or(0);
    let mut qb = sqlx::QueryBuilder::<sqlx::MySql>::new("SELECT * FROM security_app_property WHERE (APP_ID = ");
    qb.push_bind(app_id);
    if let Some(p) = prop {
        qb.push(" AND NAME = ").push_bind(p.to_string());
    }
    // Only SYSTEM, without a client, reads every client's (a non-SYSTEM caller always has one).
    if !ids.is_empty() {
        qb.push(" AND (CLIENT_ID = ").push_bind(app_client).push(" OR ");
        crate::data::push_in_u64(&mut qb, "CLIENT_ID", &ids);
        qb.push(")");
    }
    qb.push(")");
    let rows = qb.build().fetch_all(&s.db.pool).await?;
    let props = rows.iter().map(property_json).collect::<AuthResult<Vec<_>>>()?;
    Ok(Some(properties_map(app_client, props)))
}

/// `getPropertiesWithClients`: `PropertiesResponse` (properties, then the clients they belong to).
pub async fn properties_with_clients(s: &AdminState, ca: &ContextAuth, client_id: Option<u64>, app_id: Option<u64>, app_code: Option<&str>, prop: Option<&str>) -> AuthResult<Value> {
    let props = properties(s, ca, client_id, app_id, app_code, prop).await?.unwrap_or_else(|| json!({}));
    let ids: Vec<u64> = props.as_object().map(|m| m.keys().filter_map(|k| k.parse().ok()).collect()).unwrap_or_default();
    let mut clients = serde_json::Map::new();
    if !ids.is_empty() {
        let mut qb = sqlx::QueryBuilder::<sqlx::MySql>::new(format!("SELECT {} FROM security_client WHERE ", crate::mysql::CLIENT_COLUMNS));
        crate::data::push_in_u64(&mut qb, "ID", &ids);
        let rows = qb.build().fetch_all(&s.db.pool).await?;
        let list = rows.iter().map(crate::mysql::client).collect::<AuthResult<Vec<_>>>()?;
        for c in iteration_order(list.into_iter().map(|c| (long_hash(c.id()), c)).collect()) {
            clients.insert(c.id().to_string(), crate::dto::client_json(&c, &Default::default()));
        }
    }
    // `NON_EMPTY` leaves an empty map out.
    let non_empty = |v: Value| if v.as_object().is_some_and(|m| m.is_empty()) { Value::Null } else { v };
    Ok(Obj::new().put("properties", non_empty(props)).put("clients", non_empty(Value::Object(clients))).build())
}

/// The caller may write a property of `client_id`: SYSTEM, its own client, or a managed one.
async fn may_use_client(s: &AdminState, ca: &ContextAuth, client_id: u64) -> AuthResult<bool> {
    Ok(ca.is_system_client() || ca.user.client_id() == client_id || s.caller_manages_client(ca, client_id).await?)
}

/// `updateProperty(property)`: upserted when the client has write access to the app.
pub async fn update_property(s: &AdminState, ca: &ContextAuth, app_id: Option<u64>, client_id: Option<u64>, name: Option<&str>, value: Option<&str>) -> AuthResult<Option<bool>> {
    let (Some(app_id), Some(client_id), Some(name)) = (app_id, client_id, name.filter(|n| !n.trim().is_empty())) else {
        return Err(err(StatusCode::BAD_REQUEST, MANDATORY_APP_ID_NAME, &[]));
    };
    if !may_use_client(s, ca, client_id).await? {
        return Ok(None);
    }
    if !super::dao::has_access_by_id(&s.db.pool, app_id, Some(client_id), true).await? {
        return Err(forbidden_create("Application property"));
    }
    sqlx::query("INSERT INTO security_app_property (APP_ID, CLIENT_ID, NAME, VALUE) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE VALUE = ?")
        .bind(app_id)
        .bind(client_id)
        .bind(name)
        .bind(value)
        .bind(value)
        .execute(&s.db.pool)
        .await?;
    Ok(Some(true))
}

/// `deletePropertyById(id)`: `None` for an unknown property or a client the caller may not use.
pub async fn delete_property_by_id(s: &AdminState, ca: &ContextAuth, id: u64) -> AuthResult<Option<bool>> {
    let row: Option<(u64, u64)> = sqlx::query_as("SELECT APP_ID, CLIENT_ID FROM security_app_property WHERE ID = ? LIMIT 1")
        .bind(id)
        .fetch_optional(&s.db.pool)
        .await?;
    let Some((app_id, client_id)) = row else { return Ok(None) };
    if !may_use_client(s, ca, client_id).await? {
        return Ok(None);
    }
    if !super::dao::has_access_by_id(&s.db.pool, app_id, Some(client_id), true).await? {
        return Ok(Some(false));
    }
    let n = sqlx::query("DELETE FROM security_app_property WHERE ID = ?").bind(id).execute(&s.db.pool).await?.rows_affected();
    Ok(Some(n == 1))
}

/// `deleteProperty(clientId, appId, name)`.
pub async fn delete_property(s: &AdminState, ca: &ContextAuth, client_id: u64, app_id: u64, name: &str) -> AuthResult<Option<bool>> {
    if name.trim().is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, MANDATORY_APP_ID_CODE, &[]));
    }
    if !may_use_client(s, ca, client_id).await? {
        return Ok(None);
    }
    if !super::dao::has_access_by_id(&s.db.pool, app_id, Some(client_id), true).await? {
        return Ok(Some(false));
    }
    let n = sqlx::query("DELETE FROM security_app_property WHERE (APP_ID = ? AND CLIENT_ID = ? AND NAME = ?)")
        .bind(app_id)
        .bind(client_id)
        .bind(name)
        .execute(&s.db.pool)
        .await?
        .rows_affected();
    Ok(Some(n == 1))
}

// ---- dependencies ----

/// `AppDependency` as Jackson writes it.
pub fn dependency_json(d: &crate::data::apps::AppDependency) -> Value {
    Obj::new()
        .put("appName", opt(d.app_name.clone()))
        .put("appCode", opt(d.app_code.clone()))
        .put("appId", d.app_id)
        .put("dependentAppName", opt(d.dependent_app_name.clone()))
        .put("dependentAppCode", opt(d.dependent_app_code.clone()))
        .put("dependentAppId", opt(d.dependent_app_id))
        .build()
}

async fn evict_dependencies(s: &AdminState, app_code: &str) {
    let svc = &s.caches().service;
    svc.evict_everywhere(cache::APP_DEPENDENCIES, app_code).await;
    svc.evict_everywhere(cache::APP_DEP_LIST, app_code).await;
}

/// `addAppDependency(appCode, dependentAppCode)`.
pub async fn add_dependency(s: &AdminState, ca: &ContextAuth, app_code: Option<&str>, dep_code: Option<&str>) -> AuthResult<Value> {
    let Some(app_code) = app_code else {
        return Err(AuthError::internal("Cannot invoke \"String.equals(Object)\" because \"appCode\" is null"));
    };
    if Some(app_code) == dep_code || app_code.trim().is_empty() || super::common::blank(dep_code) {
        return Err(err(StatusCode::BAD_REQUEST, APP_DEPENDENCY_SAME_APP_CODE, &[]));
    }
    let dep_code = dep_code.unwrap_or("");
    let refused = || forbidden_create("App Dependency");
    let Some(app) = by_code(s, app_code).await? else { return Err(refused()) };
    let Some(dep) = by_code(s, dep_code).await? else { return Err(refused()) };
    if !ca.is_system_client() {
        let client = ca.client_code.as_deref().unwrap_or("");
        let write = s.db.has_write_access(app_code, client).await?;
        let read = s.dir().has_read_access(dep_code, ca.client_code.as_deref()).await?;
        if !write || !read || !s.caller_manages_client(ca, entity::u64_of(&app, "clientId").unwrap_or(0)).await? {
            return Err(refused());
        }
    }
    let (app_id, dep_id) = (entity::u64_of(&app, "id").unwrap_or(0), entity::u64_of(&dep, "id").unwrap_or(0));
    sqlx::query("INSERT IGNORE INTO security_app_dependency (APP_ID, DEP_APP_ID) VALUES (?, ?)").bind(app_id).bind(dep_id).execute(&s.db.pool).await?;
    evict_dependencies(s, app_code).await;
    Ok(Obj::new().put("appId", app_id).put("dependentAppId", dep_id).build())
}

/// `removeAppDependency(appCode, dependentAppCode)`.
pub async fn remove_dependency(s: &AdminState, ca: &ContextAuth, app_code: &str, dep_code: &str) -> AuthResult<bool> {
    let refused = || forbidden_create("App Dependency");
    let Some(app) = by_code(s, app_code).await? else { return Err(refused()) };
    let Some(dep) = by_code(s, dep_code).await? else { return Err(refused()) };
    let app_client = entity::u64_of(&app, "clientId");
    if app_client != entity::u64_of(&dep, "clientId") {
        return Err(refused());
    }
    if !ca.is_system_client() && !s.caller_manages_client(ca, app_client.unwrap_or(0)).await? {
        return Err(refused());
    }
    let n = sqlx::query("DELETE FROM security_app_dependency WHERE (APP_ID = ? AND DEP_APP_ID = ?)")
        .bind(entity::u64_of(&app, "id"))
        .bind(entity::u64_of(&dep, "id"))
        .execute(&s.db.pool)
        .await?
        .rows_affected();
    evict_dependencies(s, app_code).await;
    Ok(n == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_and_actions() {
        assert_eq!(action(Level::None, Level::Edit), Some("EDIT_ADDED"));
        assert_eq!(action(Level::None, Level::Read), Some("READ_ADDED"));
        assert_eq!(action(Level::Read, Level::Edit), Some("UPGRADED_TO_EDIT"));
        assert_eq!(action(Level::Edit, Level::Read), Some("DOWNGRADED_TO_READ"));
        assert_eq!(action(Level::Edit, Level::None), Some("REMOVED"));
        assert_eq!(action(Level::Read, Level::Read), None);
        assert_eq!((Level::None.name(), Level::of(true), level_of(&None)), ("NONE", Level::Edit, Level::None));
        assert_eq!(level_of(&Some((1, 2, 3, false))), Level::Read);
    }

    #[test]
    fn codes() {
        assert!(only_letters("abcXYZ") && !only_letters("a1") && only_letters(""));
        let c = unique_letters("My App 1");
        assert!(c.starts_with("myapp") && c.len() <= 22 && c.chars().all(|x| x.is_ascii_lowercase()));
        assert!(!base36_uuid().is_empty());
        assert_eq!(snake("createdAt"), "CREATED_AT");
        assert_eq!(snake("name"), "NAME");
        assert_eq!(opt_text(None), "null");
    }

    #[test]
    fn property_maps_in_hash_order() {
        let p = |c: u64, n: &str| (c, n.to_string(), json!({"clientId": c, "name": n}));
        let v = properties_map(1, vec![p(1, "URL"), p(1, "REGISTRATION_TYPE"), p(5, "URL")]);
        assert_eq!(v["5"]["REGISTRATION_TYPE"]["clientId"], 1, "the owner's property fills the gap");
        assert_eq!(v["5"]["URL"]["clientId"], 5);
        assert_eq!(v["1"].as_object().unwrap().len(), 2);
        let mut d = vec![("a".to_string(), json!(1))];
        put(&mut d, "a".into(), json!(2));
        assert_eq!(d, vec![("a".to_string(), json!(2))]);
    }

    #[test]
    fn app_rows_and_dependencies() {
        let a = App { id: 2, client_id: 1, app_code: "x".into(), ..Default::default() };
        let r = row_of(&a);
        assert_eq!(json_of(&r), a.to_json());
        let d = crate::data::apps::AppDependency { app_id: 1, dependent_app_id: Some(2), ..Default::default() };
        let keys: Vec<String> = dependency_json(&d).as_object().unwrap().keys().cloned().collect();
        assert_eq!(keys, vec!["appId", "dependentAppId"]);
        assert_eq!(initial()["appAccessType"], "OWN");
    }
}
