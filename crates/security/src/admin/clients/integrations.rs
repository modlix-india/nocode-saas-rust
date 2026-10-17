//! `AppRegistrationIntegrationController` (`AbstractJOOQDataController` over
//! `AppRegistrationIntegrationService`): an app's social sign-in integrations, and
//! `TransportController`, whose service is a stub in Java.
//!
//! | Route | Who |
//! |---|---|
//! | `POST appRegIntegration` | `Integration_CREATE` |
//! | `GET appRegIntegration`, `POST appRegIntegration/query` | `Integration_READ` |
//! | `GET appRegIntegration/{id}` | signed in |
//! | `DELETE appRegIntegration/{id}` | `Integration_DELETE` |
//! | `GET transports/makeTransport`, `POST transports/createAndApply` | signed in: always empty |

use axum::routing::{get, post};
use axum::Router;
use serde_json::Value;

use crate::web::page_of;
use super::common::{cache, no_content, object_body, pre_authorize, Kind};
use super::entity::{self, col, Col, Entity, Row, CREATED_AT, CREATED_BY, ID, UPDATED_AT, UPDATED_BY};
use crate::admin::AdminState;
use crate::condition::{ColType, Table};
use crate::errors::AuthResult;
use crate::jackson::json as json_resp;
use crate::model::ContextAuth;
use crate::spring::Pageable;
use crate::web::{self, query_body, req_str, to_u64};
use crate::{web_route, web_route_path};

pub const PLATFORMS: &[&str] = &["GOOGLE", "META", "APPLE", "SSO", "MICROSOFT", "X"];

static COLS: [Col; 12] = [
    ID,
    CREATED_AT,
    CREATED_BY,
    UPDATED_AT,
    UPDATED_BY,
    col("clientId", "CLIENT_ID", Kind::U64, true),
    col("appId", "APP_ID", Kind::U64, true),
    col("platform", "PLATFORM", Kind::Enum(PLATFORMS), true),
    col("intgId", "INTG_ID", Kind::Str, true),
    col("intgSecret", "INTG_SECRET", Kind::Str, true),
    col("loginUri", "LOGIN_URI", Kind::Str, true),
    col("signupUri", "SIGNUP_URI", Kind::Str, true),
];

/// The `AppRegistrationIntegration` DTO (`AppRegistrationIntegrationDAO` is a client-check DAO).
pub static INTEGRATION: Entity = Entity {
    pojo: "AppRegistrationIntegration",
    table: "security_app_reg_integration",
    cols: &COLS,
    setters: &[
        ("clientId", "clientId"),
        ("appId", "appId"),
        ("platform", "platform"),
        ("intgId", "intgId"),
        ("intgSecret", "intgSecret"),
        ("loginUri", "loginUri"),
        ("signupUri", "signupUri"),
    ],
    aliases: &[],
    filter: Table {
        name: "security_app_reg_integration",
        columns: &[
            ("ID", ColType::Num),
            ("APP_ID", ColType::Num),
            ("CLIENT_ID", ColType::Num),
            ("PLATFORM", ColType::Enum),
            ("INTG_ID", ColType::Str),
            ("INTG_SECRET", ColType::Str),
            ("LOGIN_URI", ColType::Str),
            ("SIGNUP_URI", ColType::Str),
            ("CREATED_BY", ColType::Num),
            ("CREATED_AT", ColType::Ts),
            ("UPDATED_BY", ColType::Num),
            ("UPDATED_AT", ColType::Ts),
        ],
    },
    client_column: Some("CLIENT_ID"),
};

/// `getCacheKeys(clientId, appId, platform)`: `String.join(clientId, ":", appId, ":", platform)`,
/// which uses the client id as the separator; kept, so the keys match Java's.
pub fn integration_cache_key(client_id: &str, app_id: &str, platform: &str) -> String {
    [":", app_id, ":", platform].join(client_id)
}

/// `AppRegistrationIntegrationService.create`: no checks beyond the authority; no creator.
pub async fn create(s: &AdminState, mut entity: Row) -> AuthResult<Row> {
    entity.insert("createdBy".into(), Value::Null);
    let id = entity::insert(&s.db, &INTEGRATION, &entity).await?;
    entity::read_by_id(&s.db, &INTEGRATION, id).await
}

/// `delete(id)`: the DAO's 404, then the row and its cache entry.
pub async fn delete(s: &AdminState, id: u64) -> AuthResult<u64> {
    let r = entity::read_by_id(&s.db, &INTEGRATION, id).await?;
    let n = entity::delete(&s.db, &INTEGRATION, id).await?;
    let text = |k: &str| match r.get(k) {
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::String(s)) => s.clone(),
        _ => "null".into(),
    };
    let key = integration_cache_key(&text("clientId"), &text("appId"), &text("platform"));
    s.caches().service.evict_everywhere(cache::INTEGRATION_PLATFORM, &key).await;
    Ok(n)
}

/// `readPageFilter`: the client-check restriction, then the page.
pub async fn page(s: &AdminState, ca: &ContextAuth, pageable: &Pageable, cond: Option<&crate::condition::Cond>) -> AuthResult<Value> {
    let sql = cond.map(|c| crate::condition::to_sql(c, &INTEGRATION.filter)).transpose()?.flatten();
    let (rows, count) = entity::page(&s.db, &INTEGRATION, crate::data::crud::client_check(ca), sql, pageable).await?;
    Ok(page_of(rows.iter().map(|r| INTEGRATION.to_json(r, vec![])).collect(), pageable, count))
}

pub fn router() -> Router<AdminState> {
    Router::new()
        .route("/api/security/appRegIntegration", get(read_page).post(create_route))
        .route("/api/security/appRegIntegration/query", post(query))
        .route("/api/security/appRegIntegration/{id}", get(read_route).delete(delete_route))
        .route("/api/security/transports/makeTransport", get(make_transport))
        .route("/api/security/transports/createAndApply", post(create_and_apply))
}

web_route!(read_page, AdminState, "/appRegIntegration", true, |s, r, ca| {
    let pageable = Pageable::from_params(&r.params);
    let cond = crate::condition::from_params(&r.params.0);
    pre_authorize(&ca, "Authorities.Integration_READ")?;
    Ok(json_resp(&page(&s, &ca, &pageable, cond.as_ref()).await?))
});

web_route!(query, AdminState, "/appRegIntegration/query", true, |s, r, ca| {
    let (pageable, cond) = query_body(&r.body)?;
    pre_authorize(&ca, "Authorities.Integration_READ")?;
    Ok(json_resp(&page(&s, &ca, &pageable, cond.as_ref()).await?))
});

web_route!(create_route, AdminState, "/appRegIntegration", true, |s, r, ca| {
    let body = object_body(&r.body)?;
    let entity = INTEGRATION.from_body(&body, Row::new())?;
    pre_authorize(&ca, "Authorities.Integration_CREATE")?;
    Ok(json_resp(&INTEGRATION.to_json(&create(&s, entity).await?, vec![])))
});

web_route_path!(read_route, AdminState, "/appRegIntegration/{id}", true, |s, r, ca, id| {
    let id = to_u64(&id)?;
    Ok(json_resp(&INTEGRATION.to_json(&entity::read_by_id(&s.db, &INTEGRATION, id).await?, vec![])))
});

web_route_path!(delete_route, AdminState, "/appRegIntegration/{id}", true, |s, r, ca, id| {
    let id = to_u64(&id)?;
    pre_authorize(&ca, "Authorities.Integration_DELETE")?;
    delete(&s, id).await?;
    Ok(no_content())
});

// `TransportService.makeTransport` / `createAndApply` return `Mono.empty()`.
web_route!(make_transport, AdminState, "/transports/makeTransport", true, |s, r, ca| {
    req_str(&r.params, "applicationCode")?;
    Ok(web::nothing())
});

web_route!(create_and_apply, AdminState, "/transports/createAndApply", true, |s, r, ca| {
    object_body(&r.body)?;
    Ok(web::nothing())
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn javas_cache_key() {
        // String.join("1", ":", "2", ":", "GOOGLE")
        assert_eq!(integration_cache_key("1", "2", "GOOGLE"), ":121:1GOOGLE");
        let r = INTEGRATION.from_body(&serde_json::json!({"platform": "GOOGLE", "intgId": "x"}), Row::new()).unwrap();
        assert_eq!(INTEGRATION.to_json(&r, vec![])["platform"], "GOOGLE");
        assert!(INTEGRATION.from_body(&serde_json::json!({"platform": "NOPE"}), Row::new()).is_err());
    }
}
