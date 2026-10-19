//! What this piece's in-crate live tests share: the unit over the local `security` schema (gated:
//! `SECURITY_AUTH_LIVE=1` with `eval "$(tools/local-env.py)"`), a caller's context as the routes
//! build it (Basic credentials of the local users, the local password), and scratch apps made
//! and removed through the services.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::http::HeaderMap;
use serde_json::Value;

use super::entity::{self, Row};
use crate::admin::{Admin, AdminState};
use crate::events::{EventMessage, EventSink};
use crate::errors::{AuthError, AuthResult};
use crate::model::ContextAuth;
use crate::request::RequestInfo;

/// The unit, or `None` when the live tests are not enabled.
pub async fn state() -> Option<AdminState> {
    state_with(None).await
}

/// [`state`] with another event sink.
pub async fn state_with(events: Option<Arc<dyn EventSink>>) -> Option<AdminState> {
    let (Ok(_), Ok(password), Ok(key)) =
        (std::env::var("SECURITY_AUTH_LIVE"), std::env::var("MODLIX__DATABASE__PASSWORD"), std::env::var("MODLIX__JWT__KEY"))
    else {
        return None;
    };
    let mut cfg = crate::config::AuthConfig::default();
    cfg.database = platform::config::MySqlConfig { database: "security".into(), password, max_connections: 2, ..Default::default() };
    cfg.jwt.key = key;
    cfg.security.app_code_suffix = ".local".into();
    cfg.security.subdomain_endings = ".local.modlix.com, .local.sitezump.ai".into();
    cfg.events.publish_events = false;
    cfg.otp.publish_events = false;
    cfg.wallet.publish_events = false;
    let pool = platform::db::mysql_pool(&cfg.database).await.unwrap();
    let s = crate::admin::build(&cfg, pool, platform::cache::CacheService::new("cmn", "evictionChannel", None).unwrap(), None).unwrap();
    Some(match events {
        None => s,
        Some(e) => Arc::new(Admin { internal: s.internal.clone(), events: e, files: s.files.clone() }),
    })
}

/// A request's parts: the URL's client and app, and the user's Basic credentials.
pub fn info(user: Option<u64>, client: &str, app: Option<&str>, extra: &[(&str, &str)]) -> RequestInfo {
    use base64::Engine;
    let mut h = HeaderMap::new();
    h.insert("host", "localhost:8001".parse().unwrap());
    h.insert("clientcode", client.parse().unwrap());
    if let Some(a) = app {
        h.insert("appcode", a.parse().unwrap());
    }
    if let Some(u) = user {
        let basic = base64::engine::general_purpose::STANDARD.encode(format!("{u}:Pass@1234"));
        h.insert("authorization", format!("Basic {basic}").parse().unwrap());
    }
    for (k, v) in extra {
        h.insert(axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(), v.parse().unwrap());
    }
    RequestInfo::new(h, Some(SocketAddr::from(([127, 0, 0, 1], 50000))))
}

/// The caller's context, as the routes build it.
pub async fn ctx(s: &AdminState, user: Option<u64>, client: &str, app: Option<&str>) -> ContextAuth {
    s.auth.context(&info(user, client, app, &[])).await.unwrap()
}

/// SYSTEM user 142 on appbuilder.
pub async fn system(s: &AdminState) -> ContextAuth {
    ctx(s, Some(142), "SYSTEM", Some("appbuilder")).await
}

/// User 110, an Owner of FIN, on appbuilder.
pub async fn owner(s: &AdminState) -> ContextAuth {
    ctx(s, Some(110), "FIN", Some("appbuilder")).await
}

pub fn row(v: Value) -> Row {
    v.as_object().cloned().unwrap_or_default()
}

/// A scratch code: the prefix and eight random letters.
pub fn scratch_code(prefix: &str) -> String {
    format!("{prefix}{}", super::apps::unique_letters("").chars().take(8).collect::<String>())
}

/// Removes the apps a run that stopped half-way left behind (codes starting with `prefix`).
pub async fn remove_leftovers(s: &AdminState, prefix: &str) {
    let sys = system(s).await;
    let left: Vec<u64> = sqlx::query_scalar(&format!("SELECT ID FROM security_app WHERE APP_CODE LIKE '{prefix}%'")).fetch_all(&s.db.pool).await.unwrap();
    for id in left {
        remove_app(s, &sys, id).await;
    }
}

/// An app made through the service (with its draft URL).
pub async fn scratch_app(s: &AdminState, ca: &ContextAuth, body: Value) -> Row {
    super::apps::create(s, ca, row(body)).await.unwrap()
}

/// The app removed with what it holds: its registration objects and integrations first (they
/// keep the app), then everything else.
pub async fn remove_app(s: &AdminState, sys: &ContextAuth, id: u64) {
    for t in super::app_reg::TYPES.iter() {
        let ids: Vec<u64> = sqlx::query_scalar(&format!("SELECT ID FROM {} WHERE APP_ID = {id}", t.entity.table)).fetch_all(&s.db.pool).await.unwrap_or_default();
        for rid in ids {
            let _ = super::app_reg::delete_object(s, sys, t, rid).await;
        }
    }
    let intgs: Vec<u64> = sqlx::query_scalar(&format!("SELECT ID FROM security_app_reg_integration WHERE APP_ID = {id}")).fetch_all(&s.db.pool).await.unwrap_or_default();
    for iid in intgs {
        let _ = super::integrations::delete(s, iid).await;
    }
    for (table, t) in [
        ("security_client_pin_policy", super::policies::PolicyType::Pin),
        ("security_client_otp_policy", super::policies::PolicyType::Otp),
        ("security_client_password_policy", super::policies::PolicyType::Password),
    ] {
        let ids: Vec<u64> = sqlx::query_scalar(&format!("SELECT ID FROM {table} WHERE APP_ID = {id}")).fetch_all(&s.db.pool).await.unwrap_or_default();
        for pid in ids {
            let _ = super::policies::delete(s, sys, t, pid).await;
        }
    }
    super::apps::delete_everything(s, sys, id, true).await.unwrap();
}

pub fn id_of(r: &Row) -> u64 {
    entity::u64_of(r, "id").unwrap()
}

/// An event sink that refuses everything.
pub struct FailingEvents;

#[async_trait::async_trait]
impl EventSink for FailingEvents {
    async fn publish(&self, _: &EventMessage) -> AuthResult<bool> {
        Err(AuthError::internal("no broker"))
    }
}

/// Scratch users (by e-mail pattern) and their clients marked DELETED through the services.
pub async fn retire_scratch_users(s: &AdminState, like: &str) {
    let sys = system(s).await;
    let left: Vec<(u64, u64)> = sqlx::query_as(&format!(
        "SELECT u.ID, u.CLIENT_ID FROM security_user u JOIN security_client c ON c.ID = u.CLIENT_ID \
         WHERE u.EMAIL_ID LIKE '{like}' AND (u.STATUS_CODE <> 'DELETED' OR c.STATUS_CODE <> 'DELETED')"
    ))
    .fetch_all(&s.db.pool)
    .await
    .unwrap();
    for (u, c) in left {
        // The manager rows these scratch users hold (made by the registrations they did).
        let managed: Vec<u64> = sqlx::query_scalar(&format!("SELECT CLIENT_ID FROM security_client_manager WHERE MANAGER_ID = {u}")).fetch_all(&s.db.pool).await.unwrap();
        for m in managed {
            let _ = s.client_manager_delete(&sys, u, m).await;
        }
        let _ = s.user_delete(&sys, u).await;
        let _ = super::client_admin::delete(s, &sys, c).await;
    }
}
