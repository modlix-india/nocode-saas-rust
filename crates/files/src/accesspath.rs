//! `FilesAccessPathController` / `FilesAccessPathService` / `FilesAccessPathDao`: who may read or
//! write which folders, as rows the caller manages through the generic JOOQ data controller
//! (create, read, page filter, query, put, patch, delete) plus the internal create.

use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use platform::error::{AppError, AppResult};
use platform::security::ContextAuthentication;
use serde_json::Value;
use sqlx::{FromRow, QueryBuilder};

use crate::condition::{self, ColType, Cond, Filter, Table};
use crate::errors::{err_named, literal, status, OrApp, ACCESS_ONLY_TO_ONE, FORBIDDEN_PERMISSION, MISSING_FIELD, OBJECT_NOT_FOUND};
use crate::jackson::Obj;
use crate::spring::{known_total, page_json, Order, Pageable};
use crate::state::AppState;

pub const TABLE: Table = Table {
    name: "files_access_path",
    columns: &[
        ("ID", ColType::Num),
        ("CLIENT_CODE", ColType::Str),
        ("USER_ID", ColType::Num),
        ("RESOURCE_TYPE", ColType::Enum),
        ("ACCESS_NAME", ColType::Str),
        ("WRITE_ACCESS", ColType::Num),
        ("PATH", ColType::Str),
        ("ALLOW_SUB_PATH_ACCESS", ColType::Num),
        ("CREATED_BY", ColType::Num),
        ("CREATED_AT", ColType::Ts),
        ("UPDATED_BY", ColType::Num),
        ("UPDATED_AT", ColType::Ts),
    ],
};

const COLUMNS: &str = "ID, CLIENT_CODE, USER_ID, CAST(RESOURCE_TYPE AS CHAR) AS RESOURCE_TYPE, ACCESS_NAME, \
    WRITE_ACCESS, PATH, ALLOW_SUB_PATH_ACCESS, CREATED_BY, CREATED_AT, UPDATED_BY, UPDATED_AT";

/// `FilesAccessPath`.
#[derive(Debug, Clone, PartialEq, FromRow)]
pub struct AccessPath {
    #[sqlx(rename = "ID")]
    pub id: u64,
    #[sqlx(rename = "CLIENT_CODE")]
    pub client_code: String,
    #[sqlx(rename = "USER_ID")]
    pub user_id: Option<u64>,
    #[sqlx(rename = "RESOURCE_TYPE")]
    pub resource_type: Option<String>,
    #[sqlx(rename = "ACCESS_NAME")]
    pub access_name: Option<String>,
    #[sqlx(rename = "WRITE_ACCESS")]
    pub write_access: Option<i8>,
    #[sqlx(rename = "PATH")]
    pub path: String,
    #[sqlx(rename = "ALLOW_SUB_PATH_ACCESS")]
    pub allow_sub_path_access: Option<i8>,
    #[sqlx(rename = "CREATED_BY")]
    pub created_by: Option<u64>,
    #[sqlx(rename = "CREATED_AT")]
    pub created_at: Option<DateTime<Utc>>,
    #[sqlx(rename = "UPDATED_BY")]
    pub updated_by: Option<u64>,
    #[sqlx(rename = "UPDATED_AT")]
    pub updated_at: Option<DateTime<Utc>>,
}

fn opt<T: Into<Value>>(v: Option<T>) -> Value {
    v.map(Into::into).unwrap_or(Value::Null)
}

impl AccessPath {
    pub fn writes(&self) -> bool {
        self.write_access.is_some_and(|b| b != 0)
    }

    pub fn sub_paths(&self) -> bool {
        self.allow_sub_path_access.is_some_and(|b| b != 0)
    }

    pub fn json(&self) -> Value {
        Obj::new()
            .put("id", self.id)
            .put("createdAt", opt(self.created_at.map(|t| t.timestamp())))
            .put("createdBy", opt(self.created_by))
            .put("updatedAt", opt(self.updated_at.map(|t| t.timestamp())))
            .put("updatedBy", opt(self.updated_by))
            .put("clientCode", self.client_code.as_str())
            .put("userId", opt(self.user_id))
            .put("accessName", opt(self.access_name.clone()))
            .put("writeAccess", self.writes())
            .put("path", self.path.as_str())
            .put("allowSubPathAccess", self.sub_paths())
            .put("resourceType", opt(self.resource_type.clone()))
            .build()
    }
}

/// The fields a request body can set, read as Jackson reads them into the DTO.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AccessPathIn {
    pub user_id: Option<u64>,
    pub access_name: Option<String>,
    pub write_access: bool,
    pub path: Option<String>,
    pub allow_sub_path_access: bool,
    pub resource_type: Option<String>,
}

fn bad(field: &str) -> AppError {
    literal("FILES.FIELD_UNREADABLE", StatusCode::BAD_REQUEST, format!("{field} field cannot be read")).param("field", field).into()
}

fn json_bool(v: Option<&Value>, field: &str) -> AppResult<bool> {
    match v {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(Value::Number(n)) => Ok(n.as_f64().is_some_and(|f| f != 0.0)),
        Some(Value::String(s)) if s.eq_ignore_ascii_case("true") => Ok(true),
        Some(Value::String(s)) if s.eq_ignore_ascii_case("false") || s.is_empty() => Ok(false),
        _ => Err(bad(field)),
    }
}

fn json_u64(v: Option<&Value>, field: &str) -> AppResult<Option<u64>> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n.as_u64().map(Some).ok_or_else(|| bad(field)),
        Some(Value::String(s)) => s.trim().parse().map(Some).map_err(|_| bad(field)),
        _ => Err(bad(field)),
    }
}

fn json_str(v: Option<&Value>, field: &str) -> AppResult<Option<String>> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(Value::Number(n)) => Ok(Some(n.to_string())),
        Some(Value::Bool(b)) => Ok(Some(b.to_string())),
        _ => Err(bad(field)),
    }
}

impl AccessPathIn {
    pub fn from_json(v: &Value) -> AppResult<Self> {
        let Value::Object(m) = v else { return Err(literal("FILES.BODY_NOT_OBJECT", StatusCode::BAD_REQUEST, "Invalid body").into()) };
        let resource_type = match m.get("resourceType") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) if s == "STATIC" || s == "SECURED" => Some(s.clone()),
            Some(_) => return Err(bad("resourceType")),
        };
        Ok(Self {
            user_id: json_u64(m.get("userId"), "userId")?,
            access_name: json_str(m.get("accessName"), "accessName")?,
            write_access: json_bool(m.get("writeAccess"), "writeAccess")?,
            path: json_str(m.get("path"), "path")?,
            allow_sub_path_access: json_bool(m.get("allowSubPathAccess"), "allowSubPathAccess")?,
            resource_type,
        })
    }
}

fn authority(resource_type: &str) -> String {
    format!("Authorities.{resource_type}_Files_PATH")
}

/// `checkAccessNGetClientCode`: the caller is in the system client, signed in to their own
/// client, or manages `cc`, and holds `Authorities.<TYPE>_Files_PATH`. An unknown `cc` is a
/// refusal here (Java fails on it with a 500).
async fn check_access(st: &AppState, ca: &ContextAuthentication, resource_type: &str, cc: &str) -> AppResult<String> {
    let refused = || status(StatusCode::FORBIDDEN, FORBIDDEN_PERMISSION, &[&authority(resource_type)]);
    let own = ca.is_system_client() || ca.logged_in_from_client_id == ca.user.client_id;
    let Some(target) = st.security().client_id_by_code(cc).await.app()? else { return Err(refused()) };
    let managed = own
        || st
            .security()
            .is_user_client_manage_client(ca.url_app_code.as_deref(), ca.user.id, ca.user.client_id, Some(target))
            .await
            .app()?;
    if !managed || !ca.has_authority(&authority(resource_type)) {
        return Err(refused());
    }
    Ok(ca.logged_in_from_client_code.clone().unwrap_or_default())
}

async fn read_row(st: &AppState, id: u64) -> AppResult<AccessPath> {
    let row: Option<AccessPath> = sqlx::query_as(&format!("SELECT {COLUMNS} FROM files_access_path WHERE ID = ?"))
        .bind(id)
        .fetch_optional(st.dao().pool())
        .await
        .map_err(anyhow::Error::from)?;
    row.ok_or_else(|| status(StatusCode::NOT_FOUND, OBJECT_NOT_FOUND, &["FilesAccessPath", &id.to_string()]))
}

/// `FilesAccessPathDao.create`: a rule with the same path, client, type and access name is
/// reused, gaining write or sub path access if the new one asks for it.
async fn dao_create(st: &AppState, cc: &str, e: &AccessPathIn, path: &str) -> AppResult<AccessPath> {
    let pool = st.dao().pool();
    let existing: Option<AccessPath> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM files_access_path WHERE PATH = ? AND CLIENT_CODE = ? AND RESOURCE_TYPE = ? \
         AND ACCESS_NAME <=> ? LIMIT 1"
    ))
    .bind(path)
    .bind(cc)
    .bind(e.resource_type.as_deref())
    .bind(e.access_name.as_deref())
    .fetch_optional(pool)
    .await
    .map_err(anyhow::Error::from)?;

    let Some(mut existing) = existing else {
        let id = sqlx::query(
            "INSERT INTO files_access_path (CLIENT_CODE, USER_ID, RESOURCE_TYPE, ACCESS_NAME, WRITE_ACCESS, PATH, \
             ALLOW_SUB_PATH_ACCESS, CREATED_BY) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)",
        )
        .bind(cc)
        .bind(e.user_id)
        .bind(e.resource_type.as_deref())
        .bind(e.access_name.as_deref())
        .bind(i8::from(e.write_access))
        .bind(path)
        .bind(i8::from(e.allow_sub_path_access))
        .execute(pool)
        .await
        .map_err(anyhow::Error::from)?
        .last_insert_id();
        return read_row(st, id).await;
    };
    if e.write_access == existing.writes() && e.allow_sub_path_access == existing.sub_paths() {
        return Ok(existing);
    }
    if e.write_access {
        existing.write_access = Some(1);
    }
    if e.allow_sub_path_access {
        existing.allow_sub_path_access = Some(1);
    }
    dao_update(st, &existing).await
}

/// `AbstractUpdatableDAO.update`: every column but the creation ones, `UPDATED_AT` left to the
/// database.
async fn dao_update(st: &AppState, r: &AccessPath) -> AppResult<AccessPath> {
    sqlx::query(
        "UPDATE files_access_path SET CLIENT_CODE = ?, USER_ID = ?, RESOURCE_TYPE = ?, ACCESS_NAME = ?, \
         WRITE_ACCESS = ?, PATH = ?, ALLOW_SUB_PATH_ACCESS = ?, UPDATED_BY = ? WHERE ID = ?",
    )
    .bind(&r.client_code)
    .bind(r.user_id)
    .bind(r.resource_type.as_deref())
    .bind(r.access_name.as_deref())
    .bind(r.write_access)
    .bind(&r.path)
    .bind(r.allow_sub_path_access)
    .bind(r.updated_by)
    .bind(r.id)
    .execute(st.dao().pool())
    .await
    .map_err(anyhow::Error::from)?;
    read_row(st, r.id).await
}

/// A user or an access name, never both (`create` / `createInternalAccessPath`).
fn one_of(e: &mut AccessPathIn) -> AppResult<()> {
    if e.access_name.is_some() {
        e.user_id = None;
    } else if e.user_id.is_some() {
        e.access_name = None;
    } else {
        return Err(status(StatusCode::BAD_REQUEST, ACCESS_ONLY_TO_ONE, &[]));
    }
    if e.resource_type.is_none() {
        return Err(status(StatusCode::BAD_REQUEST, MISSING_FIELD, &["Resource Type"]));
    }
    Ok(())
}

/// `POST /api/files/accesspath`.
pub async fn create(st: &AppState, ca: &ContextAuthentication, body: &Value) -> AppResult<Value> {
    let mut e = AccessPathIn::from_json(body)?;
    one_of(&mut e)?;
    let path = e.path.as_deref().filter(|p| !p.trim().is_empty()).map(|p| p.trim().to_string()).unwrap_or_else(|| "/".into());
    let own_cc = ca.logged_in_from_client_code.clone().unwrap_or_default();
    let cc = check_access(st, ca, e.resource_type.as_deref().unwrap_or(""), &own_cc).await?;
    Ok(dao_create(st, &cc, &e, &path).await?.json())
}

/// `POST /api/files/internal/accesspath`: no checks; the client code is the body's.
pub async fn create_internal(st: &AppState, body: &Value) -> AppResult<Value> {
    let mut e = AccessPathIn::from_json(body)?;
    one_of(&mut e)?;
    let path = e.path.as_deref().map(str::trim).unwrap_or("").to_string();
    // A missing client code fails the NOT NULL column in Java (a 500).
    let cc = body
        .get("clientCode")
        .and_then(Value::as_str)
        .ok_or_else(|| status(StatusCode::BAD_REQUEST, MISSING_FIELD, &["clientCode"]))?
        .to_string();
    Ok(dao_create(st, &cc, &e, &path).await?.json())
}

/// `GET /api/files/accesspath/{id}`.
pub async fn read(st: &AppState, ca: &ContextAuthentication, id: u64) -> AppResult<Value> {
    let row = read_row(st, id).await?;
    check_access(st, ca, row.resource_type.as_deref().unwrap_or(""), &row.client_code).await?;
    Ok(row.json())
}

/// `updatableEntity` then the update: who it is for, write, sub paths and path change.
async fn apply_update(st: &AppState, ca: &ContextAuthentication, id: u64, e: &AccessPathIn) -> AppResult<Value> {
    let mut row = read_row(st, id).await?;
    check_access(st, ca, row.resource_type.as_deref().unwrap_or(""), &row.client_code).await?;
    if e.access_name.is_none() {
        row.user_id = e.user_id;
        row.access_name = None;
    } else if e.user_id.is_none() {
        row.access_name = e.access_name.clone();
        row.user_id = None;
    } else {
        return Err(status(StatusCode::BAD_REQUEST, ACCESS_ONLY_TO_ONE, &[]));
    }
    row.allow_sub_path_access = Some(i8::from(e.allow_sub_path_access));
    row.path = e.path.as_deref().filter(|p| !p.trim().is_empty()).map(|p| p.trim().to_string()).unwrap_or_else(|| "/".into());
    row.write_access = Some(i8::from(e.write_access));
    Ok(dao_update(st, &row).await?.json())
}

/// `PUT /api/files/accesspath/{id}`.
pub async fn put(st: &AppState, ca: &ContextAuthentication, id: u64, body: &Value) -> AppResult<Value> {
    let e = AccessPathIn::from_json(body)?;
    apply_update(st, ca, id, &e).await
}

/// `PATCH /api/files/accesspath/{id}`: the current row with the given fields set, then a PUT.
pub async fn patch(st: &AppState, ca: &ContextAuthentication, id: u64, body: &Value) -> AppResult<Value> {
    let Value::Object(fields) = body else { return Err(literal("FILES.BODY_NOT_OBJECT", StatusCode::BAD_REQUEST, "Invalid body").into()) };
    let row = read_row(st, id).await?;
    check_access(st, ca, row.resource_type.as_deref().unwrap_or(""), &row.client_code).await?;
    let mut e = AccessPathIn {
        user_id: row.user_id,
        access_name: row.access_name.clone(),
        write_access: row.writes(),
        path: Some(row.path.clone()),
        allow_sub_path_access: row.sub_paths(),
        resource_type: row.resource_type.clone(),
    };
    let cannot = |f: &str| -> AppError {
        let text = format!("{f} field cannot be updated, it might not be available or unmodifiable");
        literal("FILES.FIELD_NOT_UPDATABLE", StatusCode::BAD_REQUEST, text).param("field", f).into()
    };
    for (k, v) in fields {
        match k.as_str() {
            "userId" => e.user_id = json_u64(Some(v), k).map_err(|_| cannot(k))?,
            "accessName" => e.access_name = json_str(Some(v), k).map_err(|_| cannot(k))?,
            "writeAccess" => e.write_access = json_bool(Some(v), k).map_err(|_| cannot(k))?,
            "path" => e.path = json_str(Some(v), k).map_err(|_| cannot(k))?,
            "allowSubPathAccess" => e.allow_sub_path_access = json_bool(Some(v), k).map_err(|_| cannot(k))?,
            // The rest have setters but `updatableEntity` does not copy them.
            _ => {}
        }
    }
    apply_update(st, ca, id, &e).await
}

/// `DELETE /api/files/accesspath/{id}`.
pub async fn delete(st: &AppState, ca: &ContextAuthentication, id: u64) -> AppResult<()> {
    let row = read_row(st, id).await?;
    check_access(st, ca, row.resource_type.as_deref().unwrap_or(""), &row.client_code).await?;
    sqlx::query("DELETE FROM files_access_path WHERE ID = ?")
        .bind(id)
        .execute(st.dao().pool())
        .await
        .map_err(anyhow::Error::from)?;
    Ok(())
}

/// `FilesAccessPathService.readPageFilter`: the caller's own client's rules, of the types their
/// authorities cover.
pub async fn page(st: &AppState, ca: &ContextAuthentication, page: &Pageable, cond: Option<Cond>) -> AppResult<Value> {
    if !ca.is_system_client() && ca.logged_in_from_client_id != ca.user.client_id {
        return Err(status(StatusCode::FORBIDDEN, FORBIDDEN_PERMISSION, &[""]));
    }
    let has_static = ca.has_authority("Authorities.STATIC_Files_PATH");
    let has_secured = ca.has_authority("Authorities.SECURED_Files_PATH");
    let by_type: Vec<String> = cond
        .as_ref()
        .map(|c| c.filters_on("resourceType").iter().map(|f| f.value.as_ref().map(value_string).unwrap_or_default()).collect())
        .unwrap_or_default();

    let mut conditions: Vec<Cond> = cond.into_iter().collect();
    if by_type.is_empty() {
        match (has_static, has_secured) {
            (false, false) => {
                return Err(err_named(
                    "FILES.FORBIDDEN_PERMISSION",
                    StatusCode::FORBIDDEN,
                    FORBIDDEN_PERMISSION,
                    &["STATIC Files PATH / SECURED Files PATH"],
                    vec![("permission".into(), "Authorities.STATIC_Files_PATH,Authorities.SECURED_Files_PATH".into())],
                ))
            }
            (true, false) => conditions.push(Cond::Filter(Filter::eq("resourceType", "STATIC"))),
            (false, true) => conditions.push(Cond::Filter(Filter::eq("resourceType", "SECURED"))),
            (true, true) => {}
        }
    } else {
        for t in by_type {
            if t.contains("STATIC") && !has_static {
                return Err(status(StatusCode::FORBIDDEN, FORBIDDEN_PERMISSION, &["STATIC Files PATH"]));
            }
            if t.contains("SECURED") && !has_secured {
                return Err(status(StatusCode::FORBIDDEN, FORBIDDEN_PERMISSION, &["SECURED Files PATH"]));
            }
        }
    }
    conditions.push(Cond::Filter(Filter::eq(
        "clientCode",
        ca.logged_in_from_client_code.clone().unwrap_or_default(),
    )));
    let cond = Cond::and(conditions);
    read_page(st, page, &cond).await
}

fn value_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// `AbstractDAO.readPageFilter` over `files_access_path`.
async fn read_page(st: &AppState, page: &Pageable, cond: &Cond) -> AppResult<Value> {
    let sql = condition::to_sql(cond, &TABLE).map_err(|e| query_invalid(e.0))?;
    let pool = st.dao().pool();
    let total: i64 = {
        let mut cq = QueryBuilder::new("SELECT COUNT(*) AS C FROM files_access_path");
        if let Some(s) = &sql {
            cq.push(" WHERE ");
            s.push_to(&mut cq);
        }
        sqlx::Row::try_get(&cq.build().fetch_one(pool).await.map_err(anyhow::Error::from)?, "C").map_err(anyhow::Error::from)?
    };
    let mut qb = QueryBuilder::new(format!("SELECT {COLUMNS} FROM files_access_path"));
    if let Some(s) = &sql {
        qb.push(" WHERE ");
        s.push_to(&mut qb);
    }
    qb.push(condition::order_by(&page.sort, &TABLE));
    qb.push(" LIMIT ");
    qb.push_bind(page.size);
    qb.push(" OFFSET ");
    qb.push_bind(page.offset());
    let rows: Vec<AccessPath> = qb.build_query_as().fetch_all(pool).await.map_err(anyhow::Error::from)?;
    let content: Vec<Value> = rows.iter().map(AccessPath::json).collect();
    let total = known_total(content.len(), page).unwrap_or(total);
    Ok(page_json(content, page, total))
}

/// The `Query` body of `POST /query`: condition, page (0), size (10), sort (`updatedAt` DESC).
pub fn query_from_json(body: &Value) -> AppResult<(Pageable, Option<Cond>)> {
    let bad = |m: &str| query_invalid(m.to_string());
    let int = |k: &str, default: i64| -> AppResult<i64> {
        match body.get(k) {
            None | Some(Value::Null) => Ok(default),
            Some(v) => v.as_i64().ok_or_else(|| bad(&format!("Invalid {k}"))),
        }
    };
    let page = int("page", 0)?;
    let size = int("size", 10)?;
    if page < 0 {
        return Err(bad("Page index must not be less than zero"));
    }
    if size < 1 {
        return Err(bad("Page size must not be less than one"));
    }
    let sort = match body.get("sort") {
        None => vec![Order::new("updatedAt", false)],
        Some(Value::Null) => vec![],
        Some(Value::Object(_)) => vec![order_from_json(&body["sort"])?],
        Some(Value::Array(items)) => items.iter().map(order_from_json).collect::<AppResult<Vec<_>>>()?,
        Some(_) => vec![],
    };
    let cond = match body.get("condition") {
        None => None,
        Some(c) => condition::parse(c).map_err(|e| query_invalid(e.0))?,
    };
    Ok((Pageable::of(page, size, sort), cond))
}

/// A query, filter or sort the service cannot use; `text` (Java's) goes to `debugMessage`.
fn query_invalid(text: String) -> AppError {
    literal("FILES.QUERY_INVALID", StatusCode::BAD_REQUEST, text).into()
}

/// `SortSerializationModule.SortDeserializer`, one order.
fn order_from_json(v: &Value) -> AppResult<Order> {
    let property = v
        .get("property")
        .and_then(Value::as_str)
        .ok_or_else(|| query_invalid("Sort order without a property".into()))?;
    let ascending = match v.get("direction").and_then(Value::as_str) {
        None => true,
        Some("ASC") => true,
        Some("DESC") => false,
        Some(other) => return Err(query_invalid(format!("Invalid direction '{other}'"))),
    };
    let ignore_case = v.get("ignoreCase").and_then(Value::as_str).is_some_and(|s| crate::spring::safe_bool(Some(s)));
    Ok(Order { property: property.to_string(), ascending, ignore_case })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn json_shape_observed_on_the_java_service() {
        let r = AccessPath {
            id: 1,
            client_code: "SYSTEM".into(),
            user_id: Some(1),
            resource_type: Some("STATIC".into()),
            access_name: None,
            write_access: Some(1),
            path: String::new(),
            allow_sub_path_access: Some(1),
            created_by: None,
            created_at: DateTime::from_timestamp(1_680_178_443, 0),
            updated_by: None,
            updated_at: DateTime::from_timestamp(1_715_236_596, 0),
        };
        assert_eq!(
            crate::jackson::pretty(&r.json()),
            "{\n  \"id\" : 1,\n  \"createdAt\" : 1680178443,\n  \"updatedAt\" : 1715236596,\n  \"clientCode\" : \"SYSTEM\",\n  \"userId\" : 1,\n  \"writeAccess\" : true,\n  \"allowSubPathAccess\" : true,\n  \"resourceType\" : \"STATIC\"\n}"
        );
    }

    #[test]
    fn bodies() {
        let mut e = AccessPathIn::from_json(&json!({"accessName": "A", "userId": "5", "writeAccess": 1})).unwrap();
        assert!(e.write_access);
        one_of(&mut e).unwrap_err();
        e.resource_type = Some("STATIC".into());
        one_of(&mut e).unwrap();
        assert_eq!(e.user_id, None);
        assert!(AccessPathIn::from_json(&json!({"resourceType": "OTHER"})).is_err());
        let mut none = AccessPathIn::from_json(&json!({"resourceType": "STATIC"})).unwrap();
        assert_eq!(one_of(&mut none).unwrap_err().status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn query_defaults() {
        let (p, c) = query_from_json(&json!({"condition": {"field": "path", "value": "x"}})).unwrap();
        assert_eq!(p, Pageable::of(0, 10, vec![Order::new("updatedAt", false)]));
        assert!(c.is_some());
        let (p, _) = query_from_json(&json!({"sort": [{"property": "id"}], "size": 2})).unwrap();
        assert_eq!(p.sort, vec![Order::new("id", true)]);
        assert!(query_from_json(&json!({"page": -1})).is_err());
    }


    #[test]
    fn fields_as_jackson_reads_them() {
        let e = AccessPathIn::from_json(&json!({"accessName": 5, "path": true, "userId": " 7 ", "writeAccess": "TRUE", "allowSubPathAccess": ""})).unwrap();
        assert_eq!((e.access_name.as_deref(), e.path.as_deref(), e.user_id, e.write_access, e.allow_sub_path_access), (Some("5"), Some("true"), Some(7), true, false));
        let e = AccessPathIn::from_json(&json!({"writeAccess": "false", "allowSubPathAccess": 0.5, "userId": null})).unwrap();
        assert!(!e.write_access && e.allow_sub_path_access && e.user_id.is_none());
        assert!(AccessPathIn::from_json(&json!({"userId": true})).is_err());
        assert!(AccessPathIn::from_json(&json!({"userId": -1})).is_err());
        assert!(AccessPathIn::from_json(&json!({"writeAccess": []})).is_err());
        assert_eq!(value_string(&json!(5)), "5");
        assert_eq!(value_string(&json!("S")), "S");
        assert_eq!(authority("STATIC"), "Authorities.STATIC_Files_PATH");
        let (p, _) = query_from_json(&json!({"sort": {"property": "path", "direction": "DESC", "ignoreCase": "true"}})).unwrap();
        assert_eq!(p.sort, vec![Order { property: "path".into(), ascending: false, ignore_case: true }]);
        assert_eq!(query_from_json(&json!({"sort": null})).unwrap().0.sort, vec![]);
        assert!(query_from_json(&json!({"condition": "x"})).is_err());
    }
}
