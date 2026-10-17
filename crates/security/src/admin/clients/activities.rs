//! `ClientActivityController` and `ClientActivityService`: a client's activity log.
//!
//! | Route | Who |
//! |---|---|
//! | `POST client-activities` | signed in, for a client the caller manages (its own by default) |
//! | `GET client-activities/{clientId}`, `POST .../{clientId}/query` | signed in, a managed client; a non-Owner sees only their own entries for their own client |

use std::collections::HashMap;
use std::sync::Arc;

use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::Router;
use serde_json::Value;

use super::common::{err, object_body, Kind, FORBIDDEN_PERMISSION, NAME_MANDATORY};
use super::entity::{self, col, extra, Col, Entity, Row, CREATED_AT, CREATED_BY, ID};
use crate::admin::AdminState;
use crate::condition::{ColType, Cond, Filter, Table};
use crate::dto::{user_json, UserExtras};
use crate::errors::AuthResult;
use crate::jackson::json as json_resp;
use crate::model::{ContextAuth, User};
use crate::spring::Pageable;
use crate::web::{query_body, to_u64};
use crate::{web_route, web_route_path};

static COLS: [Col; 7] = [
    ID,
    CREATED_AT,
    CREATED_BY,
    col("clientId", "CLIENT_ID", Kind::U64, true),
    col("activityName", "ACTIVITY_NAME", Kind::Str, true),
    col("description", "DESCRIPTION", Kind::Str, false),
    extra("createdByUser", Kind::Json),
];

pub static ACTIVITY: Entity = Entity {
    pojo: "ClientActivity",
    table: "security_client_activity",
    cols: &COLS,
    setters: &[("clientId", "clientId"), ("activityName", "activityName"), ("description", "description")],
    aliases: &[],
    filter: Table {
        name: "security_client_activity",
        columns: &[
            ("ID", ColType::Num),
            ("CLIENT_ID", ColType::Num),
            ("ACTIVITY_NAME", ColType::Str),
            ("DESCRIPTION", ColType::Str),
            ("CREATED_BY", ColType::Num),
            ("CREATED_AT", ColType::Ts),
        ],
    },
    client_column: None,
};

const OWNER_ROLE: &str = "Authorities.ROLE_Owner";

/// `ClientActivityService.create`: the name is required, the client defaults to the caller's and
/// must be one the caller manages; the caller is the creator.
pub async fn create(s: &AdminState, ca: &ContextAuth, mut entity: Row) -> AuthResult<Row> {
    if super::common::blank(entity::str_of(&entity, "activityName")) {
        return Err(err(StatusCode::BAD_REQUEST, NAME_MANDATORY, &["Activity"]));
    }
    if entity.get("clientId").is_none_or(Value::is_null) {
        entity.insert("clientId".into(), Value::from(ca.user.client_id()));
    }
    let client_id = entity::u64_of(&entity, "clientId").unwrap_or(0);
    if !s.caller_manages_client(ca, client_id).await? {
        return Err(err(StatusCode::FORBIDDEN, FORBIDDEN_PERMISSION, &["Client Activity"]));
    }
    entity.insert("createdBy".into(), Value::from(ca.user.id()));
    let id = entity::insert(&s.db, &ACTIVITY, &entity).await?;
    entity::read_by_id(&s.db, &ACTIVITY, id).await
}

/// `ClientActivityService.readPageFilter(clientId, pageable, condition)` + `fillCreatedByUser`.
pub async fn page(s: &AdminState, ca: &ContextAuth, client_id: u64, pageable: &Pageable, extra_cond: Option<Cond>) -> AuthResult<Value> {
    if !s.caller_manages_client(ca, client_id).await? {
        return Err(err(StatusCode::FORBIDDEN, FORBIDDEN_PERMISSION, &["Client Activity"]));
    }
    let can_see_all = ca.user.client_id() != client_id || super::common::ca_has(ca, OWNER_ROLE);
    let mut conditions = vec![Cond::Filter(Filter::eq("clientId", client_id))];
    if !can_see_all {
        conditions.push(Cond::Filter(Filter::eq("createdBy", ca.user.id())));
    }
    if let Some(c) = extra_cond.filter(|c| !matches!(c, Cond::Complex { conditions, .. } if conditions.is_empty())) {
        conditions.push(c);
    }
    let cond = if conditions.len() == 1 { conditions.remove(0) } else { Cond::and(conditions) };
    let sql = crate::condition::to_sql(&cond, &ACTIVITY.filter)?;
    let (mut rows, count) = entity::page(&s.db, &ACTIVITY, crate::data::crud::ClientCheck::All, sql, pageable).await?;
    fill_created_by(s, &mut rows).await?;
    let content = rows.iter().map(|r| ACTIVITY.to_json(r, vec![])).collect();
    Ok(crate::web::page_of(content, pageable, count))
}

/// `fillCreatedByUser`: each creator once, through the user cache.
async fn fill_created_by(s: &AdminState, rows: &mut [Row]) -> AuthResult<()> {
    let ids = crate::data::distinct(rows.iter().filter_map(|r| entity::u64_of(r, "createdBy")));
    let mut users: HashMap<u64, Arc<User>> = HashMap::new();
    for id in ids {
        if let Some(u) = s.dir().user(id).await? {
            users.insert(id, u);
        }
    }
    for r in rows.iter_mut() {
        if let Some(u) = entity::u64_of(r, "createdBy").and_then(|id| users.get(&id)) {
            r.insert("createdByUser".into(), user_json(u, &UserExtras::default()));
        }
    }
    Ok(())
}

pub fn router() -> Router<AdminState> {
    Router::new()
        .route("/api/security/client-activities", post(create_route))
        .route("/api/security/client-activities/{clientId}", get(read_page))
        .route("/api/security/client-activities/{clientId}/query", post(query))
}

web_route!(create_route, AdminState, "/client-activities", true, |s, r, ca| {
    let body = object_body(&r.body)?;
    let entity = ACTIVITY.from_body(&body, Row::new())?;
    Ok(json_resp(&ACTIVITY.to_json(&create(&s, &ca, entity).await?, vec![])))
});

web_route_path!(read_page, AdminState, "/client-activities/{clientId}", true, |s, r, ca, client| {
    let client = to_u64(&client)?;
    let pageable = Pageable::from_params(&r.params);
    let cond = crate::condition::from_params(&r.params.0);
    Ok(json_resp(&page(&s, &ca, client, &pageable, cond).await?))
});

web_route_path!(query, AdminState, "/client-activities/{clientId}/query", true, |s, r, ca, client| {
    let client = to_u64(&client)?;
    let (pageable, cond) = query_body(&r.body)?;
    Ok(json_resp(&page(&s, &ca, client, &pageable, cond).await?))
});

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn activity_json_in_dto_order() {
        let r = ACTIVITY
            .from_body(&json!({"clientId": "5", "activityName": "Client Update", "description": "x", "createdBy": 7}), Row::new())
            .unwrap();
        let v = ACTIVITY.to_json(&r, vec![]);
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(keys, vec!["createdBy", "clientId", "activityName", "description"]);
        assert_eq!(ACTIVITY.select_list(), "security_client_activity.ID, security_client_activity.CREATED_AT, security_client_activity.CREATED_BY, security_client_activity.CLIENT_ID, security_client_activity.ACTIVITY_NAME, security_client_activity.DESCRIPTION");
    }
}
