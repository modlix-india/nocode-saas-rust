//! The `UserService` (and `DepartmentService` / `DesignationService`) pieces client registration
//! uses (`ClientService.register`, `socialRegister`, `appRegister`, ported with the client
//! routes): the owner's user created with the app's registration roles, profiles, departments,
//! designations and designation; the duplicate checks; the one-time token a registration hands
//! back; and the user as a sign-in context reads it.

// The client registration routes call these; until they land, nothing in the crate does.
#![allow(dead_code)]

use std::collections::{HashMap, HashSet};

use axum::http::StatusCode;
use sqlx::Row;

use super::accounts::describe;
use super::passwords::SecretType;
use crate::admin::Admin;
use crate::data::audit::{action, activity, object, sox};
use crate::data::org::{department_values, designation_values, DEPARTMENT, DESIGNATION};
use crate::data::users_admin::{user_values, USER};
use crate::dto::{Department, Designation};
use crate::errors::{AuthError, AuthResult};
use crate::jwt;
use crate::model::{Client, ContextAuth, User};
use crate::request::RequestInfo;
use crate::store::NewToken;

/// `AppRegistrationServiceV2.DEFAULT_BUSINESS_TYPE`.
const DEFAULT_BUSINESS_TYPE: &str = "COMMON";
/// `UserService.VALIDITY_MINUTES` of a registration's one-time token.
const ONE_TIME_MINUTES: i64 = 30;

/// A registration row of `security_app_reg_department` / `_designation`.
#[derive(Debug, Clone, Default)]
pub struct RegOrg {
    pub id: u64,
    pub client_id: u64,
    pub name: Option<String>,
    pub description: Option<String>,
    pub parent_id: Option<u64>,
    pub next_id: Option<u64>,
    pub department_id: Option<u64>,
}

/// The token `makeOneTimeToken` stores (`TokenObject`).
#[derive(Debug, Clone)]
pub struct OneTimeToken {
    pub id: u64,
    pub user_id: u64,
    pub token: String,
    pub expires_at: chrono::NaiveDateTime,
}

/// What a registration lookup keys on.
#[derive(Debug, Clone, Copy)]
pub struct RegKey<'a> {
    pub app_id: u64,
    pub app_client_id: u64,
    pub url_client_id: u64,
    pub client_type: &'a str,
    pub level: &'a str,
    pub business_type: Option<&'a str>,
}

impl Admin {
    /// `ClientService.getClientLevelType(clientId, appId)`: where the client sits below the
    /// app's owner.
    pub(crate) async fn client_level_type(&self, client_id: u64, app_id: u64) -> AuthResult<&'static str> {
        let app = self.dir().app_by_id(app_id).await?;
        let h = self.dir().hierarchy(client_id).await?;
        Ok(if app.client_id == client_id {
            "OWNER"
        } else if Some(app.client_id) == h.level0 {
            "CLIENT"
        } else if Some(app.client_id) == h.level1 {
            "CUSTOMER"
        } else {
            "CONSUMER"
        })
    }

    /// The registration rows of one table for the key, the URL client's when it has any, else
    /// the app owner's (`getXForRegistration`).
    async fn reg_rows(&self, table: &str, cols: &str, k: RegKey<'_>) -> AuthResult<Vec<sqlx::mysql::MySqlRow>> {
        let sql = format!(
            "SELECT CLIENT_ID, {cols} FROM {table} WHERE APP_ID = ? AND CLIENT_ID IN (?, ?) AND CLIENT_TYPE = ? AND LEVEL = ? AND BUSINESS_TYPE = ?"
        );
        let rows = sqlx::query(&sql)
            .bind(k.app_id)
            .bind(k.app_client_id)
            .bind(k.url_client_id)
            .bind(k.client_type)
            .bind(k.level)
            .bind(k.business_type.unwrap_or(DEFAULT_BUSINESS_TYPE))
            .fetch_all(&self.db.pool)
            .await?;
        let has_url = rows.iter().any(|r| r.try_get::<u64, _>("CLIENT_ID").ok() == Some(k.url_client_id));
        let pick = if has_url { k.url_client_id } else { k.app_client_id };
        Ok(rows.into_iter().filter(|r| r.try_get::<u64, _>("CLIENT_ID").ok() == Some(pick)).collect())
    }

    /// `getRoleIdsForUserRegistration` / `getProfileIdsForUserRegistration` (a set each).
    async fn reg_ids(&self, table: &str, col: &str, k: RegKey<'_>) -> AuthResult<Vec<u64>> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for r in self.reg_rows(table, col, k).await? {
            let id: u64 = r.try_get(col)?;
            if seen.insert(id) {
                out.push(id);
            }
        }
        Ok(out)
    }

    async fn reg_orgs(&self, table: &str, designation: bool, k: RegKey<'_>) -> AuthResult<Vec<RegOrg>> {
        let cols = if designation {
            "ID, NAME, DESCRIPTION, DEPARTMENT_ID, PARENT_DESIGNATION_ID AS PARENT_ID, NEXT_DESIGNATION_ID AS NEXT_ID"
        } else {
            "ID, NAME, DESCRIPTION, PARENT_DEPARTMENT_ID AS PARENT_ID"
        };
        self.reg_rows(table, cols, k)
            .await?
            .iter()
            .map(|r| {
                Ok(RegOrg {
                    id: r.try_get("ID")?,
                    client_id: r.try_get("CLIENT_ID")?,
                    name: r.try_get("NAME")?,
                    description: r.try_get("DESCRIPTION")?,
                    parent_id: r.try_get("PARENT_ID")?,
                    next_id: if designation { r.try_get("NEXT_ID")? } else { None },
                    department_id: if designation { r.try_get("DEPARTMENT_ID")? } else { None },
                })
            })
            .collect()
    }

    fn reg_key<'a>(app_id: u64, app_client_id: u64, url_client_id: u64, client: &'a Client, level: &'a str) -> RegKey<'a> {
        RegKey {
            app_id,
            app_client_id,
            url_client_id,
            client_type: client.type_code.as_deref().unwrap_or(""),
            level,
            business_type: client.business_type.as_deref(),
        }
    }

    /// `UserService.addDefaultRoles`.
    pub(crate) async fn add_default_roles(&self, app_id: u64, app_client_id: u64, url_client_id: u64, client: &Client, user_id: u64) -> AuthResult<bool> {
        let level = self.client_level_type(client.id(), app_id).await?;
        let k = Self::reg_key(app_id, app_client_id, url_client_id, client, level);
        for role in self.reg_ids("security_app_reg_user_role_v2", "ROLE_ID", k).await? {
            self.db.add_role_to_user(user_id, role).await?;
        }
        Ok(true)
    }

    /// `UserService.addDefaultProfiles`.
    pub(crate) async fn add_default_profiles(&self, app_id: u64, app_client_id: u64, url_client_id: u64, client: &Client, user_id: u64) -> AuthResult<bool> {
        let level = self.client_level_type(client.id(), app_id).await?;
        let k = Self::reg_key(app_id, app_client_id, url_client_id, client, level);
        for profile in self.reg_ids("security_app_reg_user_profile", "PROFILE_ID", k).await? {
            self.db.add_profile_to_user(user_id, profile).await?;
        }
        Ok(true)
    }

    /// `UserService.addDesignation`: the registration's departments and designations made in the
    /// new client (linked as registered), and the user given the registered designation.
    pub(crate) async fn add_designation(&self, app_id: u64, app_client_id: u64, url_client_id: u64, client: &Client, user_id: u64) -> AuthResult<bool> {
        let level = self.client_level_type(client.id(), app_id).await?;
        let k = Self::reg_key(app_id, app_client_id, url_client_id, client, level);
        // `DepartmentDAO.createForRegistration`.
        let mut departments: HashMap<u64, u64> = HashMap::new();
        let regs = self.reg_orgs("security_app_reg_department", false, k).await?;
        for d in &regs {
            let row = Department { client_id: client.id, name: d.name.clone(), description: d.description.clone(), ..Default::default() };
            departments.insert(d.id, self.db.entity_insert(&DEPARTMENT, &department_values(&row)).await?);
        }
        for d in &regs {
            if let (Some(p), Some(me)) = (d.parent_id.and_then(|p| departments.get(&p)), departments.get(&d.id)) {
                sqlx::query("UPDATE security_department SET PARENT_DEPARTMENT_ID = ? WHERE ID = ?").bind(p).bind(me).execute(&self.db.pool).await?;
            }
        }
        // `DesignationDAO.createForRegistration`.
        let mut designations: HashMap<u64, u64> = HashMap::new();
        let regs = self.reg_orgs("security_app_reg_designation", true, k).await?;
        for d in &regs {
            let department_id = match d.department_id {
                None => None,
                Some(dep) => Some(*departments.get(&dep).ok_or_else(|| {
                    AuthError::internal("Cannot invoke \"reactor.util.function.Tuple2.getT2()\" because the return value of \"java.util.Map.get(Object)\" is null")
                })?),
            };
            let row = Designation { client_id: client.id, name: d.name.clone(), description: d.description.clone(), department_id, ..Default::default() };
            designations.insert(d.id, self.db.entity_insert(&DESIGNATION, &designation_values(&row)).await?);
        }
        for d in &regs {
            if d.parent_id.is_none() && d.next_id.is_none() {
                continue;
            }
            let Some(me) = designations.get(&d.id) else { continue };
            let parent = d.parent_id.and_then(|p| designations.get(&p).copied());
            let next = d.next_id.and_then(|n| designations.get(&n).copied());
            sqlx::query("UPDATE security_designation SET PARENT_DESIGNATION_ID = ?, NEXT_DESIGNATION_ID = ? WHERE ID = ?")
                .bind(parent)
                .bind(next)
                .bind(me)
                .execute(&self.db.pool)
                .await?;
        }
        let users = self.reg_ids("security_app_reg_user_designation", "DESIGNATION_ID", k).await?;
        let Some(first) = users.first() else { return Ok(true) };
        let Some(designation) = designations.get(first) else { return Ok(true) };
        let r = sqlx::query("UPDATE security_user SET DESIGNATION_ID = ? WHERE ID = ?").bind(designation).bind(user_id).execute(&self.db.pool).await?;
        Ok(r.rows_affected() > 0)
    }

    /// `UserService.addRegistrationObjects`.
    pub(crate) async fn add_registration_objects(&self, app_id: u64, app_client_id: u64, url_client_id: u64, client: &Client, user_id: u64) -> AuthResult<bool> {
        self.add_default_roles(app_id, app_client_id, url_client_id, client, user_id).await?;
        self.add_default_profiles(app_id, app_client_id, url_client_id, client, user_id).await?;
        self.add_designation(app_id, app_client_id, url_client_id, client, user_id).await
    }

    /// `UserService.createForRegistration`: the owner's user, its secret, and the registration
    /// objects. `password` is `user.getInputPass(passwordType)`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn create_for_registration(
        &self,
        ca: &ContextAuth,
        app_id: u64,
        app_client_id: u64,
        url_client_id: u64,
        client: &Client,
        mut user: User,
        pass_type: Option<SecretType>,
        password: Option<String>,
    ) -> AuthResult<User> {
        user.password = None;
        user.password_hashed = false;
        user.account_non_expired = true;
        user.account_non_locked = true;
        user.credentials_non_expired = true;
        if self
            .db
            .user_exists_under(user.client_id, user.user_name.as_deref(), user.email_id.as_deref(), user.phone_number.as_deref(), Some("INDV"), None)
            .await?
        {
            return Err(AuthError::msg(StatusCode::FORBIDDEN, "forbidden_create", &["User"]));
        }
        self.validate_user_check(ca, app_id, user.client_id, user.user_name.as_deref(), user.email_id.as_deref(), user.phone_number.as_deref(), None).await?;
        let id = self.db.entity_insert(&USER, &user_values(&user)).await?;
        let created = self.user_dao_read(id).await?;
        let label = describe(&created).unwrap_or_else(|| "null".into());
        sox(&self.db, Some(created.id), object::USER, action::CREATE, format!("User created: {label}"), None);
        activity(&self.db, Some(created.client_id), "User Create".into(), format!("User created: {label}"), None);
        // `setPassword`: PASSWORD and PIN are stored; anything else sets nothing (Java's empty).
        let set = match pass_type {
            Some(t @ (SecretType::Password | SecretType::Pin)) => {
                let hash = bcrypt::hash_with_result(format!("{}{}", created.id, password.unwrap_or_else(|| "null".into())), 10)
                    .map(|h| h.format_for_version(bcrypt::Version::TwoA))
                    .map_err(AuthError::internal)?;
                self.db.set_secret(created.id, created.id, &hash, t == SecretType::Pin).await? > 0
            }
            Some(SecretType::Otp) => false,
            None => return Err(AuthError::internal("Cannot invoke \"com.fincity.security.model.AuthenticationPasswordType.ordinal()\" because \"passwordType\" is null")),
        };
        if !set {
            return Err(AuthError::msg(StatusCode::FORBIDDEN, "forbidden_create", &["User"]));
        }
        self.add_registration_objects(app_id, app_client_id, url_client_id, client, created.id).await?;
        Ok(created)
    }

    /// `checkIndividualClientUser`: `None` when the URL client is unknown (Java's empty).
    pub(crate) async fn check_individual_client_user(&self, url_client_code: &str, user_name: Option<&str>, email: Option<&str>, phone: Option<&str>) -> AuthResult<Option<bool>> {
        let Some(c) = self.dir().client_by_code(url_client_code).await? else { return Ok(None) };
        Ok(Some(self.db.user_exists_under(c.id(), user_name, email, phone, Some("INDV"), None).await?))
    }

    /// `checkBusinessClientOwnerExists`: an owner already holds this identity in a business
    /// client under the URL client.
    pub(crate) async fn check_business_client_owner_exists(&self, url_client_code: &str, user_name: Option<&str>, email: Option<&str>, phone: Option<&str>) -> AuthResult<bool> {
        let Some(c) = self.dir().client_by_code(url_client_code).await? else { return Ok(false) };
        let ids = self.db.user_ids_existing_under(c.id(), user_name, email, phone, Some("BUS")).await?;
        if ids.is_empty() {
            return Ok(false);
        }
        Ok(!self.dir().store.owner_user_ids(&ids).await?.is_empty())
    }

    /// `checkIfUserIsOwner`: the user holds a profile with the Owner role.
    pub(crate) async fn check_if_user_is_owner(&self, user_id: u64) -> AuthResult<bool> {
        let n: Option<String> = sqlx::query_scalar(
            "SELECT security_v2_role.NAME FROM security_profile LEFT JOIN security_profile_user ON security_profile_user.PROFILE_ID = security_profile.ID \
             LEFT JOIN security_profile_role ON security_profile_role.PROFILE_ID = security_profile.ID \
             LEFT JOIN security_v2_role ON security_v2_role.ID = security_profile_role.ROLE_ID \
             WHERE security_profile_user.USER_ID = ? AND security_v2_role.NAME = 'Owner' LIMIT 1",
        )
        .bind(user_id)
        .fetch_optional(&self.db.pool)
        .await?;
        Ok(n.is_some())
    }

    /// `getUserForContext`: the user with their authorities for the app.
    pub(crate) async fn user_for_context(&self, app_code: Option<&str>, user_id: u64) -> AuthResult<(User, Vec<String>)> {
        let u = self.user_dao_read(user_id).await?;
        let authorities = self.dir().user_authorities(app_code, u.client_id, u.id).await?;
        Ok((u, authorities))
    }

    /// `makeOneTimeToken`: a 30-minute one-time JWT for the user, stored like a session token.
    pub(crate) async fn make_registration_token(&self, info: &RequestInfo, ca: &ContextAuth, user: &User, logged_in_client_id: u64) -> AuthResult<OneTimeToken> {
        let claims = jwt::Claims {
            user_id: user.id,
            host_name: Some(info.forwarded_host()),
            port: Some(info.forwarded_port()),
            logged_in_client_id,
            logged_in_client_code: ca.url_client_code.clone(),
            app_code: None,
            one_time: true,
        };
        let now = self.auth.clock.instant();
        let made = jwt::make(&self.auth.settings.jwt_key, &claims, now.timestamp(), ONE_TIME_MINUTES);
        let expires_at = now.naive_utc() + chrono::Duration::minutes(ONE_TIME_MINUTES);
        let origin = self.auth.origin(info, info.remote_host());
        let id = self
            .dir()
            .store
            .insert_token(&NewToken {
                user_id: user.id,
                token: made.token.clone(),
                part_token: crate::context::part_token(&made.token).to_string(),
                expires_at,
                origin,
                created_by: ca.authenticated.then(|| ca.user.id()),
            })
            .await?;
        Ok(OneTimeToken { id, user_id: user.id, token: made.token, expires_at })
    }
}

#[cfg(test)]
mod live {
    use super::*;
    use crate::admin::users::testkit::{fx, sys, PASSWORD};
    use serde_json::json;

    /// `UserServiceTest`'s registration cases: the owner made in an individual's client with the
    /// registration objects keyed to `ZZRUL`, the duplicate checks, the one-time token.
    #[tokio::test]
    async fn registration_objects_and_checks() {
        let Some(fx) = fx().await else { return };
        let (s, c, m, i) = (&fx.s, fx.c, fx.m, fx.i);
        let sys = sys();
        let run = fx.run.clone();
        let n = |v: u64| json!(v);
        let t = |v: String| json!(v);
        let d1 = fx.reg_row("security_app_reg_department", &[("NAME", t(format!("zz rd1 {run}")))]).await;
        let d2 = fx.reg_row("security_app_reg_department", &[("NAME", t(format!("zz rd2 {run}"))), ("PARENT_DEPARTMENT_ID", n(d1))]).await;
        let g1 = fx.reg_row("security_app_reg_designation", &[("NAME", t(format!("zz rg1 {run}"))), ("DEPARTMENT_ID", n(d1))]).await;
        let g2 = fx
            .reg_row(
                "security_app_reg_designation",
                &[("NAME", t(format!("zz rg2 {run}"))), ("DEPARTMENT_ID", n(d2)), ("PARENT_DESIGNATION_ID", n(g1)), ("NEXT_DESIGNATION_ID", n(g1))],
            )
            .await;
        fx.reg_row("security_app_reg_designation", &[("NAME", t(format!("zz rg3 {run}")))]).await;
        fx.reg_row("security_app_reg_user_designation", &[("DESIGNATION_ID", n(g2))]).await;
        let role = s
            .role_create(&sys, crate::dto::Role { client_id: Some(c), name: Some(format!("zz regrole {run}")), ..Default::default() })
            .await
            .unwrap();
        fx.reg_row("security_app_reg_user_role_v2", &[("ROLE_ID", n(role.id))]).await;
        let profile = super::super::profiles::profile_from_body(json!({"appId": 2, "clientId": c, "name": format!("zz regprof {run}")}).as_object().unwrap()).unwrap();
        let profile = s.profile_create(&sys, profile).await.unwrap().id.unwrap();
        fx.reg_row("security_app_reg_user_profile", &[("PROFILE_ID", n(profile))]).await;

        let client = s.dir().client(i).await.unwrap().unwrap();
        assert_eq!(s.client_level_type(i, 2).await.unwrap(), "CUSTOMER");
        assert_eq!(s.client_level_type(c, 2).await.unwrap(), "CLIENT");
        assert_eq!(s.client_level_type(1, 2).await.unwrap(), "OWNER");
        let other_app: u64 = sqlx::query_scalar("SELECT ID FROM security_app WHERE CLIENT_ID NOT IN (1) ORDER BY ID LIMIT 1").fetch_one(&s.db.pool).await.unwrap();
        assert_eq!(s.client_level_type(c, other_app).await.unwrap(), "CONSUMER");
        let owner = User {
            client_id: i,
            user_name: Some(format!("zzrl{run}r1")),
            email_id: Some(format!("zzrl{run}r1@example.invalid")),
            status_code: "ACTIVE".into(),
            ..Default::default()
        };
        let created = s.create_for_registration(&sys, 2, 1, c, &client, owner.clone(), Some(SecretType::Password), Some(PASSWORD.into())).await.unwrap();
        assert!(created.password.is_some() || created.password_hashed || created.id > 0);
        let designation = s.user_dao_read(created.id).await.unwrap().designation_id.expect("the registered designation");
        let name: Option<String> = sqlx::query_scalar("SELECT NAME FROM security_designation WHERE ID = ?").bind(designation).fetch_one(&s.db.pool).await.unwrap();
        assert_eq!(name, Some(format!("zz rg2 {run}")));
        assert_eq!(fx.count(&format!("SELECT COUNT(*) FROM security_department WHERE CLIENT_ID = {i} AND PARENT_DEPARTMENT_ID IS NOT NULL")).await, 1);
        assert!(s.db.role_assigned_for_user(created.id, role.id).await.unwrap());
        assert_eq!(s.db.assigned_profile_ids(created.id, Some(2)).await.unwrap(), vec![profile]);
        // The same identity under ZZRUL's individual clients.
        let twin = User { client_id: c, ..owner.clone() };
        assert_eq!(s.create_for_registration(&sys, 2, 1, c, &client, twin, Some(SecretType::Password), None).await.unwrap_err().status(), StatusCode::FORBIDDEN);
        let next = |tag: &str| User { client_id: i, user_name: Some(format!("zzrl{run}{tag}")), email_id: None, status_code: "ACTIVE".into(), ..Default::default() };
        assert_eq!(s.create_for_registration(&sys, 2, 1, c, &client, next("r2"), Some(SecretType::Otp), None).await.unwrap_err().status(), StatusCode::FORBIDDEN);
        assert_eq!(s.create_for_registration(&sys, 2, 1, c, &client, next("r3"), None, None).await.unwrap_err().status(), StatusCode::INTERNAL_SERVER_ERROR);
        // A PIN, for a business client (whose type no registration row names).
        let business = s.dir().client(m).await.unwrap().unwrap();
        let in_m = User { client_id: m, ..next("r4") };
        let pin = s.create_for_registration(&sys, 2, 1, c, &business, in_m, Some(SecretType::Pin), Some("1234".into())).await.unwrap();
        assert!(s.db.user_row(pin.id).await.unwrap().unwrap().pin.is_some());

        // The duplicate checks registration makes first.
        assert_eq!(s.check_individual_client_user("ZZRUL", owner.user_name.as_deref(), None, None).await.unwrap(), Some(true));
        assert_eq!(s.check_individual_client_user("NOSUCH", None, None, None).await.unwrap(), None);
        let e = fx.user(m, "e").await;
        assert!(!s.check_business_client_owner_exists("ZZRUL", e.user_name.as_deref(), None, None).await.unwrap());
        assert!(!s.check_business_client_owner_exists("ZZRUL", Some("nobody-here"), None, None).await.unwrap());
        assert!(!s.check_business_client_owner_exists("NOSUCH", None, None, None).await.unwrap());
        let owner_profile = super::super::profiles::profile_from_body(
            json!({"appId": 2, "clientId": c, "name": format!("zz ownerprof {run}"), "arrangement": {"o": {"roleId": 196}}}).as_object().unwrap(),
        )
        .unwrap();
        let owner_profile = s.profile_create(&sys, owner_profile).await.unwrap().id.unwrap();
        assert!(!s.check_if_user_is_owner(e.id).await.unwrap());
        assert!(s.user_assign_profile(&sys, e.id, owner_profile).await.unwrap());
        assert!(s.check_if_user_is_owner(e.id).await.unwrap());
        assert!(s.check_business_client_owner_exists("ZZRUL", e.user_name.as_deref(), None, None).await.unwrap());
        let (u, authorities) = s.user_for_context(Some("appbuilder"), e.id).await.unwrap();
        assert_eq!(u.id, e.id);
        assert!(authorities.iter().any(|a| a == "Authorities.ROLE_Owner"), "{authorities:?}");
        let mut h = axum::http::HeaderMap::new();
        h.insert("x-forwarded-host", axum::http::HeaderValue::from_static("zzrul.local.modlix.com"));
        let info = RequestInfo::new(h, Some("127.0.0.1:5000".parse().unwrap()));
        let mut anon = crate::admin::users::testkit::anonymous(c, "ZZRUL");
        let t = s.make_registration_token(&info, &anon, &u, c).await.unwrap();
        assert_eq!(t.user_id, e.id);
        anon.authenticated = true;
        anon.user.id = Some(142);
        assert!(s.make_registration_token(&info, &anon, &u, c).await.unwrap().id > t.id);
        fx.finish().await;
    }
}
