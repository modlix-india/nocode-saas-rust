//! The gated live fixture this piece's in-crate tests share (`SECURITY_AUTH_LIVE=1` with
//! `config/local.env` sourced; without them every test using it returns at once).
//!
//! Writes go only to the scratch clients `ZZRUL` (BUS, under SYSTEM), `ZZRUM` (BUS) and `ZZRUI`
//! (an individual's) under it (the first two are the ones `tests/live_admin_users.rs` uses), and
//! to what the tests make in them.
//! A MySQL advisory lock (`GET_LOCK`) is held for the whole of each test, so these tests and that
//! binary's never run at the same time, even from two processes. Each fixture first sweeps what a
//! failed run left in the two clients. Events are logged, not published; no Redis.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use sqlx::MySqlConnection;
use tower::ServiceExt;

use crate::admin::Admin;
use crate::model::{ContextAuth, ContextUser, User};

/// The advisory lock both test binaries take.
pub const LOCK: &str = "security-admin-users-live";
pub const PASSWORD: &str = "Pass@1234";
pub const NONE: u64 = 999_999_999;

/// Every authority the services of this piece ask for.
pub const ALL: &[&str] = &[
    "Authorities.Logged_IN",
    "Authorities.ROLE_Owner",
    "Authorities.ROLE_Client_MANAGE",
    "Authorities.ROLE_Client_Manager",
    "Authorities.User_CREATE",
    "Authorities.User_READ",
    "Authorities.User_UPDATE",
    "Authorities.User_DELETE",
    "Authorities.Role_CREATE",
    "Authorities.Role_READ",
    "Authorities.Role_UPDATE",
    "Authorities.Role_DELETE",
    "Authorities.Profile_CREATE",
    "Authorities.Profile_READ",
    "Authorities.Profile_UPDATE",
    "Authorities.Profile_DELETE",
    "Authorities.Client_CREATE",
    "Authorities.Client_READ",
    "Authorities.Client_UPDATE",
    "Authorities.Client_DELETE",
    "Authorities.Application_READ",
    "Authorities.Application_UPDATE",
];

pub struct Fx {
    pub s: Arc<Admin>,
    pub router: axum::Router,
    /// `ZZRUL`.
    pub c: u64,
    /// `ZZRUM`, under `ZZRUL`.
    pub m: u64,
    /// `ZZRUI`, an individual's client under `ZZRUL`.
    pub i: u64,
    /// A per-run tag for names.
    pub run: String,
    _lock: MySqlConnection,
}

/// The SYSTEM user 142 with every authority.
pub fn sys() -> ContextAuth {
    caller(142, 1, "SYSTEM", "SYS", ALL)
}

/// A signed-in caller of a client, with exactly these authorities (and `Logged_IN`).
pub fn caller(user: u64, client: u64, code: &str, type_code: &str, authorities: &[&str]) -> ContextAuth {
    let mut auths: Vec<String> = authorities.iter().map(|a| a.to_string()).collect();
    if !auths.iter().any(|a| a == "Authorities.Logged_IN") {
        auths.push("Authorities.Logged_IN".into());
    }
    ContextAuth {
        user: ContextUser {
            id: Some(user),
            client_id: Some(client),
            first_name: Some("Live".into()),
            email_id: Some(format!("zzlive{user}@example.invalid")),
            status_code: Some("ACTIVE".into()),
            account_non_expired: true,
            account_non_locked: true,
            credentials_non_expired: true,
            string_authorities: Some(auths),
            ..Default::default()
        },
        authenticated: true,
        logged_in_from_client_id: Some(client),
        logged_in_from_client_code: Some(code.into()),
        client_type_code: Some(type_code.into()),
        client_code: Some(code.into()),
        url_client_code: Some(code.into()),
        url_app_code: Some("appbuilder".into()),
        ..Default::default()
    }
}

/// An anonymous caller on a client's URL.
pub fn anonymous(client: u64, code: &str) -> ContextAuth {
    ContextAuth {
        user: ContextUser { id: Some(0), client_id: Some(client), ..Default::default() },
        authenticated: false,
        logged_in_from_client_id: Some(client),
        client_code: Some(code.into()),
        url_client_code: Some(code.into()),
        url_app_code: Some("appbuilder".into()),
        client_type_code: Some("BUS".into()),
        ..Default::default()
    }
}

/// The unit wired to a pool that never connects, for code that touches no database.
pub fn offline() -> Arc<Admin> {
    let mut cfg = crate::config::AuthConfig::default();
    cfg.jwt.key = "k".repeat(64);
    // Nothing listens on port 9: a statement that does reach for the pool fails at once.
    let pool = sqlx::mysql::MySqlPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(200))
        .connect_lazy("mysql://nobody@127.0.0.1:9/none")
        .unwrap();
    crate::admin::build(&cfg, pool, platform::cache::CacheService::new("cmn", "evictionChannel", None).unwrap(), None).unwrap()
}

fn basic(user: u64) -> String {
    use base64::Engine;
    format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{user}:{PASSWORD}")))
}

/// The fixture, or `None` when the live environment is not set.
pub async fn fx() -> Option<Fx> {
    std::env::var("SECURITY_AUTH_LIVE").ok()?;
    let password = std::env::var("MODLIX__DATABASE__PASSWORD").ok()?;
    let key = std::env::var("MODLIX__JWT__KEY").ok()?;
    let mut cfg = crate::config::AuthConfig::default();
    cfg.database = platform::config::MySqlConfig { database: "security".into(), password, max_connections: 4, ..Default::default() };
    cfg.jwt.key = key;
    cfg.security.app_code_suffix = ".local".into();
    cfg.security.subdomain_endings = ".local.modlix.com, .local.sitezump.ai".into();
    cfg.wallet.publish_events = false;
    cfg.events.publish_events = false;
    cfg.otp.publish_events = false;
    let pool = platform::db::mysql_pool(&cfg.database).await.unwrap();
    // A connection of its own holds the lock; dropping it ends the session and so the lock.
    let mut lock = pool.acquire().await.unwrap().detach();
    let got: Option<i64> = sqlx::query_scalar("SELECT GET_LOCK(?, 1800)").bind(LOCK).fetch_one(&mut lock).await.unwrap();
    assert_eq!(got, Some(1), "could not take the live-test lock");
    let cache = platform::cache::CacheService::new("cmn", "evictionChannel", None).unwrap();
    let s = crate::admin::build(&cfg, pool, cache, None).unwrap();
    let router = crate::admin::router(s.clone());
    let run = format!("{}", chrono::Utc::now().timestamp_millis() % 1_000_000_000);
    let mut fx = Fx { s, router, c: 0, m: 0, i: 0, run, _lock: lock };
    fx.c = fx.scratch_client("ZZRUL", "ZZ rust live users", None, "BUS").await;
    fx.m = fx.scratch_client("ZZRUM", "ZZ rust live managed", Some(fx.c), "BUS").await;
    fx.i = fx.scratch_client("ZZRUI", "ZZ rust live individual", Some(fx.c), "INDV").await;
    fx.sweep().await;
    Some(fx)
}

impl Fx {
    /// A request through the unit's router as the SYSTEM user (Basic `142`).
    pub async fn http(&self, method: &str, path: &str, body: Option<Value>) -> (StatusCode, Value) {
        let h = [("authorization", basic(142)), ("clientcode", "SYSTEM".to_string()), ("appcode", "appbuilder".to_string())];
        self.http_with(method, path, &h, body).await
    }

    pub async fn http_with(&self, method: &str, path: &str, headers: &[(&str, String)], body: Option<Value>) -> (StatusCode, Value) {
        let mut b = Request::builder()
            .method(method)
            .uri(format!("/api/security{path}"))
            .header("host", "localhost:8001")
            .header("x-real-ip", "127.0.0.1");
        for (k, v) in headers {
            b = b.header(*k, v);
        }
        let req = match body {
            Some(v) => b.header("content-type", "application/json").body(Body::from(v.to_string())).unwrap(),
            None => b.body(Body::empty()).unwrap(),
        };
        let resp = self.router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned())))
    }

    pub async fn ids(&self, sql: &str) -> Vec<u64> {
        sqlx::query_scalar(sql).fetch_all(&self.s.db.pool).await.unwrap()
    }

    pub async fn count(&self, sql: &str) -> i64 {
        sqlx::query_scalar::<_, i64>(sql).fetch_one(&self.s.db.pool).await.unwrap()
    }

    /// A scratch client by code: made through the clients route, or brought back to ACTIVE; with
    /// read access to appbuilder.
    pub async fn scratch_client(&self, code: &str, name: &str, parent: Option<u64>, type_code: &str) -> u64 {
        let row: Option<(u64, Option<String>)> =
            sqlx::query_as("SELECT ID, NAME FROM security_client WHERE CODE = ?").bind(code).fetch_optional(&self.s.db.pool).await.unwrap();
        let mut create = json!({"code": code, "name": name, "typeCode": type_code, "tokenValidityMinutes": 60, "localeCode": "en"});
        if let Some(p) = parent {
            create["parentClientId"] = json!(p);
        }
        let (method, path, body) = match row {
            Some((id, stored)) => {
                assert_eq!(stored.as_deref(), Some(name), "client {code} is not this test's scratch client");
                ("PATCH", format!("/clients/{id}"), json!({"statusCode": "ACTIVE"}))
            }
            None => ("POST", "/clients".to_string(), create),
        };
        let (st, v) = self.http(method, &path, Some(body)).await;
        assert_eq!(st, StatusCode::OK, "{v}");
        let id = v["id"].as_u64().unwrap();
        if self.count(&format!("SELECT COUNT(*) FROM security_app_access WHERE CLIENT_ID = {id} AND APP_ID = 2")).await == 0 {
            let (st, v) = self.http("POST", "/applications/2/access", Some(json!({"clientId": id, "writeAccess": false}))).await;
            assert_eq!(st, StatusCode::OK, "{v}");
        }
        id
    }

    /// What a failed run left in the scratch clients, removed through the services.
    pub async fn sweep(&self) {
        let sys = sys();
        let list = format!("{},{},{}", self.c, self.m, self.i);
        for (user, client) in sqlx::query_as::<_, (u64, u64)>(&format!("SELECT MANAGER_ID, CLIENT_ID FROM security_client_manager WHERE CLIENT_ID IN ({list})"))
            .fetch_all(&self.s.db.pool)
            .await
            .unwrap()
        {
            let _ = self.s.client_manager_delete(&sys, user, client).await;
        }
        // Registration rows keyed to the scratch clients (the registration tests' fixtures); their
        // links to each other first, as those keys restrict deletes.
        for sql in [
            "UPDATE security_app_reg_designation SET PARENT_DESIGNATION_ID = NULL, NEXT_DESIGNATION_ID = NULL, DEPARTMENT_ID = NULL WHERE CLIENT_ID IN",
            "UPDATE security_app_reg_department SET PARENT_DEPARTMENT_ID = NULL WHERE CLIENT_ID IN",
        ] {
            sqlx::query(&format!("{sql} ({list})")).execute(&self.s.db.pool).await.unwrap();
        }
        for table in [
            "security_app_reg_user_designation",
            "security_app_reg_user_profile",
            "security_app_reg_user_role_v2",
            "security_app_reg_designation",
            "security_app_reg_department",
        ] {
            sqlx::query(&format!("DELETE FROM {table} WHERE CLIENT_ID IN ({list})")).execute(&self.s.db.pool).await.unwrap();
        }
        // OTP policies, draft tokens and URL properties the tests key to the scratch clients.
        for sql in [
            "DELETE FROM security_client_otp_policy WHERE CLIENT_ID IN",
            "DELETE FROM security_draft_token WHERE CLIENT_ID IN",
            "DELETE FROM security_app_property WHERE CLIENT_ID IN",
        ] {
            sqlx::query(&format!("{sql} ({list})")).execute(&self.s.db.pool).await.unwrap();
        }
        // Wallets the billing store tests open for a scratch client.
        sqlx::query(&format!("DELETE FROM security_wallet_transaction WHERE WALLET_ID IN (SELECT ID FROM security_wallet WHERE CLIENT_ID IN ({list}))"))
            .execute(&self.s.db.pool)
            .await
            .unwrap();
        sqlx::query(&format!("DELETE FROM security_wallet WHERE CLIENT_ID IN ({list})")).execute(&self.s.db.pool).await.unwrap();
        let overrides: Vec<(u64, u64)> =
            sqlx::query_as(&format!("SELECT ID, CLIENT_ID FROM security_profile WHERE CLIENT_ID IN ({list}) AND ROOT_PROFILE_ID IS NOT NULL"))
                .fetch_all(&self.s.db.pool)
                .await
                .unwrap();
        for (id, client) in overrides {
            let _ = self.s.profile_delete(&caller(0, client, "ZZRU", "BUS", ALL), id).await;
        }
        for id in self.ids(&format!("SELECT ID FROM security_profile WHERE CLIENT_ID IN ({list}) ORDER BY ID DESC")).await {
            let _ = self.s.profile_delete(&sys, id).await;
        }
        for id in self.ids(&format!("SELECT ID FROM security_v2_role WHERE CLIENT_ID IN ({list})")).await {
            let _ = self.s.role_delete(&sys, id).await;
        }
        for id in self.ids(&format!("SELECT ID FROM security_designation WHERE CLIENT_ID IN ({list})")).await {
            self.http("DELETE", &format!("/designations/{id}"), None).await;
        }
        for id in self.ids(&format!("SELECT ID FROM security_department WHERE CLIENT_ID IN ({list}) ORDER BY PARENT_DEPARTMENT_ID IS NULL, ID")).await {
            self.http("DELETE", &format!("/departments/{id}"), None).await;
        }
        let codes: Vec<String> =
            sqlx::query_scalar(&format!("SELECT INVITE_CODE FROM security_user_invite WHERE CLIENT_ID IN ({list})")).fetch_all(&self.s.db.pool).await.unwrap();
        for code in codes {
            let _ = self.s.invite_revoke(&sys, &code).await;
        }
        for id in self.ids(&format!("SELECT ID FROM security_user WHERE CLIENT_ID IN ({list}) AND (STATUS_CODE IS NULL OR STATUS_CODE <> 'DELETED')")).await {
            let _ = self.s.user_delete(&sys, id).await;
        }
    }

    /// A registration row keyed to a scratch client (a test fixture: `ZZRUL`, appbuilder, an
    /// individual's client one level down, the common business type).
    pub async fn reg_row(&self, table: &str, values: &[(&str, Value)]) -> u64 {
        let mut qb = sqlx::QueryBuilder::<sqlx::MySql>::new(format!("INSERT INTO {table} (CLIENT_ID, CLIENT_TYPE, APP_ID, LEVEL, BUSINESS_TYPE"));
        for (k, _) in values {
            qb.push(format!(", {k}"));
        }
        qb.push(") VALUES (").push_bind(self.c).push(", 'INDV', 2, 'CUSTOMER', 'COMMON'");
        for (_, v) in values {
            qb.push(", ");
            match v.as_u64() {
                Some(n) => qb.push_bind(n),
                None => qb.push_bind(v.as_str().unwrap().to_string()),
            };
        }
        qb.push(")");
        qb.build().execute(&self.s.db.pool).await.unwrap().last_insert_id()
    }

    /// A scratch user of a client, made as SYSTEM, with its password set.
    pub async fn user(&self, client: u64, tag: &str) -> User {
        let u = User {
            client_id: client,
            user_name: Some(format!("zzrl{}{tag}", self.run)),
            email_id: Some(format!("zzrl{}{tag}@example.invalid", self.run)),
            first_name: Some(format!("First{tag}")),
            last_name: Some("Live".into()),
            status_code: "ACTIVE".into(),
            ..Default::default()
        };
        // An individual's client takes no users through `create`; registration inserts them.
        let created = if client == self.i {
            let id = self.s.db.entity_insert(&crate::data::users_admin::USER, &crate::data::users_admin::user_values(&u)).await.unwrap();
            self.s.user_dao_read(id).await.unwrap()
        } else {
            self.s.user_create(&sys(), u).await.unwrap()
        };
        let body = super::passwords::PasswordBody::read(json!({"newPassword": PASSWORD}).as_object().unwrap()).unwrap();
        assert!(self.s.update_password(&sys(), Some(created.id), &body).await.unwrap());
        created
    }

    /// A caller standing for a scratch user (no sign-in), with these authorities.
    pub fn as_user(&self, u: &User, code: &str, authorities: &[&str]) -> ContextAuth {
        let mut ca = caller(u.id, u.client_id, code, "BUS", authorities);
        ca.user.email_id = u.email_id.clone();
        ca.user.user_name = u.user_name.clone();
        ca
    }

    /// Ends the run: everything made in the two clients removed, and both clients marked DELETED.
    pub async fn finish(self) {
        self.sweep().await;
        for client in [self.i, self.m, self.c] {
            if let Some(access) = self.ids(&format!("SELECT ID FROM security_app_access WHERE CLIENT_ID = {client} AND APP_ID = 2")).await.first() {
                self.http("DELETE", &format!("/applications/2/access?accessId={access}"), None).await;
            }
            self.http("DELETE", &format!("/clients/{client}"), None).await;
        }
    }
}
