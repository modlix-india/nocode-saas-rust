//! `ClientController`'s CRUD and activation routes over `ClientService` (the registration routes
//! are in [`super::registration`], the internal ones in security-internal).
//!
//! | Route | Who |
//! |---|---|
//! | `GET clients`, `POST clients/query`, `GET clients/{id}` | `Client_READ` (`{id}`: a managed client) |
//! | `POST clients` | `Client_CREATE` |
//! | `PUT`/`PATCH clients/{id}`, `GET makeClientActive`, `GET makeClientInActive` | `Client_UPDATE`, a managed client |
//! | `DELETE clients/{id}` | `Client_DELETE`, a managed client (marks it `DELETED`) |
//! | `POST clients/noMapping` | signed in: always 400 |

use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::Router;
use serde_json::{json, Value};

use super::common::{bare, bool_json, cache, err, no_content, object_body, pre_authorize, Kind};
use super::common::{ACTIVE_INACTIVE_ERROR, FORBIDDEN_CREATE, FORBIDDEN_PERMISSION};
use super::entity::{self, col, extra, prim, Col, Entity, Row, CREATED_AT, CREATED_BY, ID, UPDATED_AT, UPDATED_BY};
use crate::data::audit::{action, entity_changed, object};
use crate::admin::AdminState;
use crate::dto::{client_json, ClientExtras};
use crate::errors::{AuthError, AuthResult};
use crate::internal::clients::ClientFill;
use crate::jackson::json as json_resp;
use crate::model::{Client, ContextAuth};
use crate::spring::Pageable;
use crate::web::{opt_u64, query_body, to_u64};
use crate::{web_route, web_route_path};

pub const LEVELS: &[&str] = &["SYSTEM", "CLIENT", "CUSTOMER", "CONSUMER"];
pub const STATUSES: &[&str] = &["ACTIVE", "INACTIVE", "DELETED", "LOCKED"];

static COLS: [Col; 36] = [
    ID,
    CREATED_AT,
    CREATED_BY,
    UPDATED_AT,
    UPDATED_BY,
    col("code", "CODE", Kind::Str, true),
    col("name", "NAME", Kind::Str, true),
    col("typeCode", "TYPE_CODE", Kind::Str, true),
    prim("tokenValidityMinutes", "TOKEN_VALIDITY_MINUTES", Kind::I64),
    col("localeCode", "LOCALE_CODE", Kind::Str, false),
    col("timeZone", "TIME_ZONE", Kind::Str, true),
    col("statusCode", "STATUS_CODE", Kind::Enum(STATUSES), false),
    col("businessType", "BUSINESS_TYPE", Kind::Str, true),
    col("businessSize", "BUSINESS_SIZE", Kind::Str, false),
    col("industry", "INDUSTRY", Kind::Str, false),
    col("levelType", "LEVEL_TYPE", Kind::Enum(LEVELS), true),
    col("website", "WEBSITE", Kind::Str, false),
    col("emailId", "EMAIL_ID", Kind::Str, false),
    col("phoneNumber", "PHONE_NUMBER", Kind::Str, false),
    col("alternatePhoneNumber", "ALTERNATE_PHONE_NUMBER", Kind::Str, false),
    col("linkedinUrl", "LINKEDIN_URL", Kind::Str, false),
    col("description", "DESCRIPTION", Kind::Str, false),
    prim("activeUsers", "", Kind::I64),
    prim("inactiveUsers", "", Kind::I64),
    prim("deletedUsers", "", Kind::I64),
    prim("lockedUsers", "", Kind::I64),
    prim("passwordExpiredUsers", "", Kind::I64),
    extra("owners", Kind::Json),
    extra("managagingClient", Kind::Json),
    extra("apps", Kind::Json),
    extra("createdByUser", Kind::Json),
    extra("clientManagers", Kind::Json),
    extra("managerId", Kind::U64),
    extra("parentClientId", Kind::U64),
    // Placeholders keep the array's length stable for the two getter-only properties below.
    extra("totalUsers", Kind::I64),
    extra("_", Kind::Json),
];

/// The `Client` DTO over `security_client`.
pub static CLIENT: Entity = Entity {
    pojo: "Client",
    table: "security_client",
    cols: &COLS,
    setters: &[
        ("code", "code"),
        ("name", "name"),
        ("typeCode", "typeCode"),
        ("tokenValidityMinutes", "tokenValidityMinutes"),
        ("localeCode", "localeCode"),
        ("timeZone", "timeZone"),
        ("statusCode", "statusCode"),
        ("businessType", "businessType"),
        ("businessSize", "businessSize"),
        ("industry", "industry"),
        ("levelType", "levelType"),
        ("website", "website"),
        ("emailId", "emailId"),
        ("phoneNumber", "phoneNumber"),
        ("alternatePhoneNumber", "alternatePhoneNumber"),
        ("linkedinUrl", "linkedinUrl"),
        ("description", "description"),
        ("activeUsers", "activeUsers"),
        ("inactiveUsers", "inactiveUsers"),
        ("deletedUsers", "deletedUsers"),
        ("lockedUsers", "lockedUsers"),
        ("passwordExpiredUsers", "passwordExpiredUsers"),
        ("owners", "owners"),
        ("managagingClient", "managagingClient"),
        ("apps", "apps"),
        ("createdByUser", "createdByUser"),
        ("clientManagers", "clientManagers"),
        ("managerId", "managerId"),
        ("parentClientId", "parentClientId"),
    ],
    aliases: &[],
    filter: crate::data::filters::CLIENT,
    client_column: None,
};

/// `Client`'s field initializers (the `int` user counts).
pub fn initial() -> Row {
    json!({"tokenValidityMinutes": 0, "activeUsers": 0, "inactiveUsers": 0, "deletedUsers": 0, "lockedUsers": 0, "passwordExpiredUsers": 0})
        .as_object()
        .cloned()
        .unwrap_or_default()
}

/// The stored columns of a row as the shared `Client` model.
pub fn to_client(r: &Row) -> Client {
    let s = |k: &str| entity::str_of(r, k).map(str::to_string);
    let ts = |k: &str| r.get(k).and_then(Value::as_i64).and_then(|t| chrono::DateTime::from_timestamp(t, 0)).map(|t| t.naive_utc());
    Client {
        id: entity::u64_of(r, "id"),
        created_at: ts("createdAt"),
        created_by: entity::u64_of(r, "createdBy"),
        updated_at: ts("updatedAt"),
        updated_by: entity::u64_of(r, "updatedBy"),
        code: s("code"),
        name: s("name"),
        type_code: s("typeCode"),
        token_validity_minutes: r.get("tokenValidityMinutes").and_then(Value::as_i64).unwrap_or(0),
        locale_code: s("localeCode"),
        time_zone: s("timeZone"),
        status_code: s("statusCode"),
        business_type: s("businessType"),
        business_size: s("businessSize"),
        industry: s("industry"),
        level_type: s("levelType"),
        website: s("website"),
        email_id: s("emailId"),
        phone_number: s("phoneNumber"),
        alternate_phone_number: s("alternatePhoneNumber"),
        linkedin_url: s("linkedinUrl"),
        description: s("description"),
    }
}

/// The client through Jackson (no fills).
pub fn row_json(r: &Row) -> Value {
    client_json(&to_client(r), &ClientExtras::default())
}

/// `Client.getChildClientLevelType(level)`.
pub fn child_level(level: Option<&str>) -> Option<&'static str> {
    match level? {
        "SYSTEM" => Some("CLIENT"),
        "CLIENT" => Some("CUSTOMER"),
        "CUSTOMER" => Some("CONSUMER"),
        _ => None,
    }
}

/// `ClientService.trimCompanyDetails`: trimmed, a blank one stored as null.
pub fn trim_company_details(r: &mut Row) {
    for k in ["website", "emailId", "phoneNumber", "alternatePhoneNumber", "linkedinUrl", "description"] {
        let v = match entity::str_of(r, k) {
            Some(s) if !s.trim().is_empty() => Value::from(s.trim()),
            _ => Value::Null,
        };
        r.insert(k.into(), v);
    }
}

/// `ClientService.describeEntity`: `CODE (Name)`, else whichever is there.
pub fn describe(r: &Row) -> Option<String> {
    let code = entity::str_of(r, "code").filter(|c| !c.trim().is_empty());
    let name = entity::str_of(r, "name").filter(|c| !c.trim().is_empty());
    match (code, name) {
        (Some(c), Some(n)) => Some(format!("{c} ({n})")),
        (Some(c), None) => Some(c.to_string()),
        (None, n) => n.map(str::to_string),
    }
}

/// `evictClientCaches(id, code)`: the code-keyed and the id-keyed client caches.
pub async fn evict_client(s: &AdminState, id: Option<u64>, code: Option<&str>) {
    let svc = &s.caches().service;
    if let Some(code) = code {
        svc.evict_everywhere(cache::CLIENT_CODE, code).await;
    }
    if let Some(id) = id {
        svc.evict_everywhere(cache::CLIENT_ID, &id.to_string()).await;
    }
}

fn forbidden(what: &str) -> AuthError {
    err(StatusCode::FORBIDDEN, FORBIDDEN_PERMISSION, &[what])
}

/// `ClientService.read(id)`: the DAO's 404, then 403 unless SYSTEM or a managed client.
pub async fn read(s: &AdminState, ca: &ContextAuth, id: u64) -> AuthResult<Row> {
    let r = entity::read_by_id(&s.db, &CLIENT, id).await?;
    if !ca.is_system_client() && !s.caller_manages_client(ca, id).await? {
        return Err(forbidden("Client READ"));
    }
    Ok(r)
}

/// `ClientHierarchyService.create(managingClientId, clientId)`.
pub async fn create_hierarchy(s: &AdminState, managing: u64, client: u64) -> AuthResult<()> {
    let refused = || err(StatusCode::BAD_REQUEST, FORBIDDEN_CREATE, &["ClientHierarchy"]);
    if managing == client {
        return Err(refused());
    }
    let h = s.dir().hierarchy(managing).await?;
    if h.level3.is_some() {
        return Err(refused());
    }
    // `ClientHierarchyBuilder`: the managing client, then its managers until the first gap.
    let mut levels: Vec<u64> = vec![managing];
    for l in [h.level0, h.level1, h.level2] {
        match l {
            Some(id) => levels.push(id),
            None => break,
        }
    }
    let at = |i: usize| levels.get(i).copied();
    sqlx::query(
        "INSERT INTO security_client_hierarchy (CLIENT_ID, MANAGE_CLIENT_LEVEL_0, MANAGE_CLIENT_LEVEL_1, MANAGE_CLIENT_LEVEL_2, \
         MANAGE_CLIENT_LEVEL_3, CREATED_BY, UPDATED_BY) VALUES (?, ?, ?, ?, ?, NULL, NULL)",
    )
    .bind(client)
    .bind(at(0))
    .bind(at(1))
    .bind(at(2))
    .bind(at(3))
    .execute(&s.db.pool)
    .await?;
    Ok(())
}

/// `ClientManagerDAO.createIfNotExists`: the row, and the client's `UPDATED_AT` bumped when added.
pub async fn add_client_manager(s: &AdminState, client: u64, manager: u64, created_by: u64) -> AuthResult<u64> {
    let n = sqlx::query("INSERT IGNORE INTO security_client_manager (CLIENT_ID, MANAGER_ID, CREATED_BY) VALUES (?, ?, ?)")
        .bind(client)
        .bind(manager)
        .bind(created_by)
        .execute(&s.db.pool)
        .await?
        .rows_affected();
    if n != 0 {
        sqlx::query("UPDATE security_client SET UPDATED_AT = CURRENT_TIMESTAMP() WHERE ID IN (?)")
            .bind(client)
            .execute(&s.db.pool)
            .await?;
    }
    Ok(n)
}

/// `ClientService.create(entity)`.
pub async fn create(s: &AdminState, ca: &ContextAuth, mut entity: Row) -> AuthResult<Option<Row>> {
    let caller_client = ca.user.client_id();
    let parent_id = entity::u64_of(&entity, "parentClientId");
    let parent = match parent_id.filter(|p| *p != caller_client) {
        None => s.dir().client(caller_client).await?,
        Some(p) => {
            // An unreachable parent and a missing one answer alike.
            let managed = s.caller_manages_client(ca, p).await.unwrap_or(false);
            let found = if managed { s.dir().client(p).await? } else { None };
            Some(found.ok_or_else(|| err(StatusCode::FORBIDDEN, FORBIDDEN_CREATE, &["Client under the selected parent"]))?)
        }
    };
    let Some(parent) = parent else { return Ok(None) };
    let Some(level) = child_level(parent.level_type.as_deref()) else {
        return Err(err(StatusCode::BAD_REQUEST, FORBIDDEN_CREATE, &[&format!("Client under {}", parent.code())]));
    };
    trim_company_details(&mut entity);
    entity.insert("levelType".into(), Value::from(level));
    if entity.get("statusCode").is_none_or(Value::is_null) {
        entity.insert("statusCode".into(), Value::from("ACTIVE"));
    }
    entity.insert("createdBy".into(), Value::from(ca.user.id()));
    let id = entity::insert(&s.db, &CLIENT, &entity).await?;
    let created = entity::read_by_id(&s.db, &CLIENT, id).await?;
    entity_changed(&s.db, None, object::CLIENT, action::CREATE, id, Some(id), "Client", describe(&created).as_deref());
    create_hierarchy(s, parent.id(), id).await?;
    if !super::common::ca_has(ca, "Authorities.ROLE_Owner") {
        add_client_manager(s, id, ca.user.id(), ca.user.id()).await?;
    } else if let Some(manager) = entity::u64_of(&entity, "managerId") {
        add_client_manager(s, id, manager, ca.user.id()).await?;
    }
    Ok(Some(created))
}

/// `ClientService.updatableEntity`: company details trimmed; level and type kept as stored.
async fn updatable(s: &AdminState, mut entity: Row) -> AuthResult<Row> {
    let Some(id) = entity::u64_of(&entity, "id") else { return Ok(entity) };
    trim_company_details(&mut entity);
    if let Some(existing) = s.dir().client(id).await? {
        entity.insert("levelType".into(), existing.level_type.clone().map(Value::from).unwrap_or(Value::Null));
        entity.insert("typeCode".into(), existing.type_code.clone().map(Value::from).unwrap_or(Value::Null));
    }
    Ok(entity)
}

async fn may_update(s: &AdminState, ca: &ContextAuth, id: Option<u64>) -> AuthResult<()> {
    if ca.is_system_client() {
        return Ok(());
    }
    if s.caller_manages_client(ca, id.unwrap_or(0)).await? {
        return Ok(());
    }
    Err(forbidden("Client UPDATE"))
}

/// `ClientService.update(entity)`.
pub async fn update(s: &AdminState, ca: &ContextAuth, entity: Row) -> AuthResult<Row> {
    let id = entity::u64_of(&entity, "id");
    may_update(s, ca, id).await?;
    let mut e = updatable(s, entity).await?;
    e.insert("updatedBy".into(), Value::from(ca.user.id()));
    entity::update(&s.db, &CLIENT, &e).await?;
    let updated = entity::read_by_id(&s.db, &CLIENT, id.unwrap_or(0)).await?;
    let uid = entity::u64_of(&updated, "id").unwrap_or(0);
    entity_changed(&s.db, None, object::CLIENT, action::UPDATE, uid, Some(uid), "Client", describe(&updated).as_deref());
    evict_client(s, Some(uid), entity::str_of(&updated, "code")).await;
    Ok(updated)
}

/// `ClientService.update(key, fields)`: read (with its manage check), set, `update(entity)`, and
/// then the second round of logs and evictions Java's layering adds.
pub async fn patch(s: &AdminState, ca: &ContextAuth, id: u64, fields: &serde_json::Map<String, Value>) -> AuthResult<Row> {
    may_update(s, ca, Some(id)).await?;
    let mut row = read(s, ca, id).await?;
    row.extend(initial().into_iter().filter(|(k, _)| !row.contains_key(k)).collect::<Row>());
    CLIENT.patch(&mut row, fields)?;
    let updated = update(s, ca, row).await?;
    let uid = entity::u64_of(&updated, "id").unwrap_or(0);
    entity_changed(&s.db, None, object::CLIENT, action::UPDATE, uid, Some(uid), "Client", describe(&updated).as_deref());
    evict_client(s, Some(uid), entity::str_of(&updated, "code")).await;
    Ok(updated)
}

/// `ClientService.delete(id)`: marked `DELETED` through `update`.
pub async fn delete(s: &AdminState, ca: &ContextAuth, id: u64) -> AuthResult<()> {
    let mut row = read(s, ca, id).await?;
    row.insert("statusCode".into(), Value::from("DELETED"));
    let updated = update(s, ca, row).await?;
    evict_client(s, Some(id), entity::str_of(&updated, "code")).await;
    Ok(())
}

/// `makeClientActiveIfInActive` / `makeClientInActive`.
pub async fn set_active(s: &AdminState, ca: &ContextAuth, client_id: Option<u64>, active: bool) -> AuthResult<bool> {
    let id = client_id.unwrap_or_else(|| ca.user.client_id());
    let allowed = ca.is_system_client() || s.caller_manages_client(ca, id).await?;
    if !allowed {
        return Err(err(StatusCode::FORBIDDEN, ACTIVE_INACTIVE_ERROR, &["client"]));
    }
    let sql = if active {
        "UPDATE security_client SET STATUS_CODE = 'ACTIVE' WHERE (ID = ? AND STATUS_CODE = 'INACTIVE')"
    } else {
        "UPDATE security_client SET STATUS_CODE = 'INACTIVE' WHERE (ID = ? AND STATUS_CODE <> 'DELETED')"
    };
    let changed = sqlx::query(sql).bind(id).execute(&s.db.pool).await?.rows_affected() > 0;
    let code = entity::by_id(&s.db, &CLIENT, id).await?.and_then(|r| entity::str_of(&r, "code").map(str::to_string));
    evict_client(s, Some(id), code.as_deref()).await;
    Ok(changed)
}

/// `GET clients` / `POST clients/query`: `readPageFilter` then `fillDetails` with the query
/// parameters.
async fn page(s: &AdminState, ca: &ContextAuth, pageable: &Pageable, cond: Option<&crate::condition::Cond>, params: &crate::spring::Params) -> AuthResult<Value> {
    pre_authorize(ca, "Authorities.Client_READ")?;
    s.clients_page(ca, pageable, cond, &ClientFill::from_params(params)).await
}

pub fn router() -> Router<AdminState> {
    Router::new()
        .route("/api/security/clients", get(read_page).post(create_route))
        .route("/api/security/clients/query", post(query))
        .route("/api/security/clients/noMapping", post(no_mapping))
        .route("/api/security/clients/makeClientActive", get(make_active))
        .route("/api/security/clients/makeClientInActive", get(make_inactive))
        .route("/api/security/clients/{id}", get(read_route).put(put_route).patch(patch_route).delete(delete_route))
}

web_route!(read_page, AdminState, "/clients", true, |s, r, ca| {
    let pageable = Pageable::from_params(&r.params);
    let cond = crate::condition::from_params(&r.params.0);
    Ok(json_resp(&page(&s, &ca, &pageable, cond.as_ref(), &r.params).await?))
});

web_route!(query, AdminState, "/clients/query", true, |s, r, ca| {
    let (pageable, cond) = query_body(&r.body)?;
    Ok(json_resp(&page(&s, &ca, &pageable, cond.as_ref(), &r.params).await?))
});

web_route!(no_mapping, AdminState, "/clients/noMapping", true, |s, r, ca| {
    query_body(&r.body)?;
    Ok(bare(StatusCode::BAD_REQUEST))
});

web_route!(create_route, AdminState, "/clients", true, |s, r, ca| {
    let body = object_body(&r.body)?;
    let entity = CLIENT.from_body(&body, initial())?;
    pre_authorize(&ca, "Authorities.Client_CREATE")?;
    Ok(match create(&s, &ca, entity).await? {
        Some(c) => json_resp(&row_json(&c)),
        None => crate::web::nothing(),
    })
});

web_route!(make_active, AdminState, "/clients/makeClientActive", true, |s, r, ca| {
    let id = opt_u64(&r.params, "clientId")?;
    pre_authorize(&ca, "Authorities.Client_UPDATE")?;
    Ok(bool_json(set_active(&s, &ca, id, true).await?))
});

web_route!(make_inactive, AdminState, "/clients/makeClientInActive", true, |s, r, ca| {
    let id = opt_u64(&r.params, "clientId")?;
    pre_authorize(&ca, "Authorities.Client_UPDATE")?;
    Ok(bool_json(set_active(&s, &ca, id, false).await?))
});

web_route_path!(read_route, AdminState, "/clients/{id}", true, |s, r, ca, id| {
    let id = to_u64(&id)?;
    pre_authorize(&ca, "Authorities.Client_READ")?;
    Ok(json_resp(&row_json(&read(&s, &ca, id).await?)))
});

web_route_path!(put_route, AdminState, "/clients/{id}", true, |s, r, ca, id| {
    let id = to_u64(&id)?;
    let body = object_body(&r.body)?;
    let mut entity = CLIENT.from_body(&body, initial())?;
    entity.insert("id".into(), Value::from(id));
    pre_authorize(&ca, "Authorities.Client_UPDATE")?;
    Ok(json_resp(&row_json(&update(&s, &ca, entity).await?)))
});

web_route_path!(patch_route, AdminState, "/clients/{id}", true, |s, r, ca, id| {
    let id = to_u64(&id)?;
    let body = object_body(&r.body)?;
    pre_authorize(&ca, "Authorities.Client_UPDATE")?;
    let fields = body.as_object().cloned().unwrap_or_default();
    Ok(json_resp(&row_json(&patch(&s, &ca, id, &fields).await?)))
});

web_route_path!(delete_route, AdminState, "/clients/{id}", true, |s, r, ca, id| {
    let id = to_u64(&id)?;
    pre_authorize(&ca, "Authorities.Client_DELETE")?;
    delete(&s, &ca, id).await?;
    Ok(no_content())
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_details_and_descriptions() {
        assert_eq!(child_level(Some("SYSTEM")), Some("CLIENT"));
        assert_eq!(child_level(Some("CLIENT")), Some("CUSTOMER"));
        assert_eq!(child_level(Some("CUSTOMER")), Some("CONSUMER"));
        assert_eq!(child_level(Some("CONSUMER")), None);
        assert_eq!(child_level(None), None);
        let mut r = json!({"website": "  a.com ", "emailId": "  ", "code": "BUS", "name": "Biz"}).as_object().cloned().unwrap();
        trim_company_details(&mut r);
        assert_eq!(r["website"], "a.com");
        assert_eq!(r["emailId"], Value::Null);
        assert_eq!(r["description"], Value::Null);
        assert_eq!(describe(&r).as_deref(), Some("BUS (Biz)"));
        r.insert("name".into(), Value::Null);
        assert_eq!(describe(&r).as_deref(), Some("BUS"));
        r.insert("code".into(), json!(" "));
        r.insert("name".into(), json!("N"));
        assert_eq!(describe(&r).as_deref(), Some("N"));
    }

    #[test]
    fn rows_become_the_shared_client() {
        let r = CLIENT
            .from_body(&json!({"id": 3, "code": "BUS", "tokenValidityMinutes": "45", "levelType": "CLIENT", "createdAt": 1700000000}), initial())
            .unwrap();
        let c = to_client(&r);
        assert_eq!((c.id, c.code.as_deref(), c.token_validity_minutes), (Some(3), Some("BUS"), 45));
        assert_eq!(c.created_at.map(|t| t.and_utc().timestamp()), Some(1700000000));
        let v = row_json(&r);
        assert_eq!(v["totalUsers"], 0);
        assert!(CLIENT.from_body(&json!({"levelType": "BAD"}), initial()).is_err());
        assert!(CLIENT.select_list().contains("security_client.TIME_ZONE"));
        assert!(!CLIENT.select_list().contains("activeUsers"));
    }
}
