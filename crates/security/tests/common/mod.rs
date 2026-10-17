//! The in-memory `security` schema the ported Java tests run against (the Java unit tests mock
//! the DAOs with Mockito; this plays that part), and a harness that builds the service around it
//! with a stopped clock and recording event and SMS sinks.

#![allow(dead_code)]

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::http::{HeaderMap, HeaderValue};
use chrono::{NaiveDateTime, TimeZone, Utc};
use platform::cache::CacheService;
use security::caches::Caches;
use security::clock::Clock;
use security::directory::Directory;
use security::errors::{AuthError, AuthResult};
use security::events::{EventMessage, EventSink, SmsSender};
use security::model::{App, Client, ClientHierarchy, OneTimeTokenRow, PassType, Policy, TokenRow, UrlPattern, User};
use security::request::RequestInfo;
use security::service::{Auth, Settings};
use security::store::{
    IdentifierType, NamedRow, NewOneTimeToken, NewOtp, NewToken, OtpRow, PermissionRow, RoleRecord, StateRow, Store,
    UserQuery,
};

pub const KEY: &str = "test-key-test-key-test-key-test-key-test-key-test-key-test-key-0123456789abcdefghijklm";

#[derive(Debug, Clone)]
pub struct FakeProfile {
    pub id: u64,
    pub client_id: u64,
    pub name: Option<String>,
    pub app_id: u64,
    pub root: Option<u64>,
    pub default: bool,
}

#[derive(Debug, Clone)]
pub struct FakeToken {
    pub id: u64,
    pub user_id: u64,
    pub token: String,
    pub part: String,
    pub expires_at: NaiveDateTime,
    pub last_used: Option<NaiveDateTime>,
    pub created_by: Option<u64>,
    pub ip: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FakeOtt {
    pub row: NewOneTimeToken,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Clone)]
pub struct FakeOtp {
    pub id: u64,
    pub otp: NewOtp,
    pub legs: i64,
}

#[derive(Default)]
pub struct Data {
    pub users: Vec<User>,
    pub clients: Vec<Client>,
    pub hierarchies: Vec<ClientHierarchy>,
    pub apps: Vec<App>,
    /// (client, app)
    pub app_access: Vec<(u64, u64)>,
    pub dependencies: Vec<(u64, u64)>,
    /// (id, name, app id)
    pub roles: Vec<(u64, String, Option<u64>)>,
    /// (user, role)
    pub user_roles: Vec<(u64, u64)>,
    /// (role, sub role)
    pub sub_roles: Vec<(u64, u64)>,
    /// (id, name, app id)
    pub permissions: Vec<(u64, String, Option<u64>)>,
    /// (role, permission)
    pub role_permissions: Vec<(u64, u64)>,
    pub profiles: Vec<FakeProfile>,
    /// (profile, user)
    pub profile_users: Vec<(u64, u64)>,
    /// (profile, role, exclude)
    pub profile_roles: Vec<(u64, u64, i64)>,
    pub policies: Vec<(PassType, u64, u64, Policy)>,
    pub tokens: Vec<FakeToken>,
    pub otts: Vec<FakeOtt>,
    pub otps: Vec<FakeOtp>,
    pub sox: Vec<(u64, String, String)>,
    pub states: Vec<StateRow>,
    pub url_patterns: Vec<UrlPattern>,
    pub draft_tokens_expired: u64,
    pub next_id: u64,
    /// Store methods that answer with an error (to reach Java's error paths).
    pub fail: HashSet<&'static str>,
    /// Database "now" for one-time token freshness.
    pub db_now: Option<NaiveDateTime>,
}

pub struct FakeStore {
    pub data: Mutex<Data>,
    pub calls: Mutex<Vec<String>>,
}

impl FakeStore {
    pub fn new(data: Data) -> Arc<Self> {
        Arc::new(Self { data: Mutex::new(data), calls: Mutex::new(Vec::new()) })
    }

    fn enter(&self, name: &'static str) -> AuthResult<std::sync::MutexGuard<'_, Data>> {
        self.calls.lock().unwrap().push(name.to_string());
        let d = self.data.lock().unwrap();
        if d.fail.contains(name) {
            return Err(AuthError::internal(format!("{name} failed")));
        }
        Ok(d)
    }

    pub fn called(&self, name: &str) -> usize {
        self.calls.lock().unwrap().iter().filter(|c| c.as_str() == name).count()
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut Data) -> R) -> R {
        f(&mut self.data.lock().unwrap())
    }

    pub fn user(&self, id: u64) -> User {
        self.with(|d| d.users.iter().find(|u| u.id == id).cloned().unwrap())
    }
}

fn next(d: &mut Data) -> u64 {
    d.next_id += 1;
    d.next_id
}

fn app_code_of(d: &Data, app_id: Option<u64>) -> Option<String> {
    app_id.and_then(|a| d.apps.iter().find(|x| x.id == a)).map(|a| a.app_code.clone())
}

fn hierarchy_has(d: &Data, user_client: u64, client: u64) -> bool {
    d.hierarchies
        .iter()
        .find(|h| h.client_id == user_client)
        .map(|h| {
            h.client_id == client
                || [h.level0, h.level1, h.level2, h.level3].iter().any(|l| *l == Some(client))
        })
        .unwrap_or(false)
}

const NON_DELETED: [&str; 4] = ["ACTIVE", "INACTIVE", "LOCKED", "PASSWORD_EXPIRED"];

#[async_trait]
impl Store for FakeStore {
    async fn user_by_id(&self, id: u64) -> AuthResult<Option<User>> {
        let d = self.enter("user_by_id")?;
        Ok(d.users.iter().find(|u| u.id == id).cloned())
    }

    async fn users_by(&self, q: &UserQuery) -> AuthResult<Vec<User>> {
        let d = self.enter("users_by")?;
        let client = q.client_code.as_ref().and_then(|c| d.clients.iter().find(|x| x.code.as_deref() == Some(c.as_str())));
        let app = q.app_code.as_ref().and_then(|a| d.apps.iter().find(|x| &x.app_code == a));
        let out = d
            .users
            .iter()
            .filter(|u| {
                if let Some(name) = q.user_name.as_ref().filter(|n| !n.trim().is_empty() && n.as_str() != "NONE") {
                    let col = match q.identifier {
                        IdentifierType::PhoneNumber => &u.phone_number,
                        IdentifierType::EmailId => &u.email_id,
                        IdentifierType::UserName => &u.user_name,
                    };
                    if !col.as_deref().is_some_and(|c| c.eq_ignore_ascii_case(name)) {
                        return false;
                    }
                }
                if !NON_DELETED.contains(&u.status_code.as_str()) {
                    return false;
                }
                if q.user_id.is_some_and(|id| id != u.id) {
                    return false;
                }
                if q.app_code.is_some() {
                    let Some(app) = app else { return false };
                    let ok = app.app_access_type.as_deref() == Some("ANY")
                        || app.client_id == u.client_id
                        || d.app_access.contains(&(u.client_id, app.id));
                    if !ok {
                        return false;
                    }
                }
                let Some(client) = client else { return false };
                if !hierarchy_has(&d, u.client_id, client.id()) {
                    return false;
                }
                if q.active_client_only {
                    let uc = d.clients.iter().find(|c| c.id == Some(u.client_id));
                    if uc.and_then(|c| c.status_code.as_deref()) != Some("ACTIVE") {
                        return false;
                    }
                }
                true
            })
            .take(q.limit as usize)
            .cloned()
            .collect();
        Ok(out)
    }

    async fn owner_user_ids(&self, ids: &[u64]) -> AuthResult<Vec<u64>> {
        let d = self.enter("owner_user_ids")?;
        let owner_roles: HashSet<u64> = d.roles.iter().filter(|r| r.1 == "Owner").map(|r| r.0).collect();
        let mut out: Vec<u64> = Vec::new();
        for id in ids {
            let by_profile = d
                .profile_users
                .iter()
                .filter(|(_, u)| u == id)
                .any(|(p, _)| d.profile_roles.iter().any(|(pp, r, _)| pp == p && owner_roles.contains(r)));
            let direct = d.user_roles.iter().any(|(u, r)| u == id && owner_roles.contains(r));
            let nested = d
                .user_roles
                .iter()
                .filter(|(u, _)| u == id)
                .any(|(_, r)| d.sub_roles.iter().any(|(rr, s)| rr == r && owner_roles.contains(s)));
            if by_profile || direct || nested {
                out.push(*id);
            }
        }
        Ok(out)
    }

    async fn is_user_owner(&self, user_id: u64) -> AuthResult<bool> {
        let d = self.enter("is_user_owner")?;
        let owner_roles: HashSet<u64> = d.roles.iter().filter(|r| r.1 == "Owner").map(|r| r.0).collect();
        Ok(d.profile_users
            .iter()
            .filter(|(_, u)| *u == user_id)
            .any(|(p, _)| d.profile_roles.iter().any(|(pp, r, _)| pp == p && owner_roles.contains(r))))
    }

    async fn increase_failed_attempt(&self, user_id: u64, t: PassType) -> AuthResult<Option<i64>> {
        let mut d = self.enter("increase_failed_attempt")?;
        let Some(u) = d.users.iter_mut().find(|u| u.id == user_id) else { return Ok(None) };
        let f = match t {
            PassType::Password => &mut u.no_failed_attempt,
            PassType::Pin => &mut u.no_pin_failed_attempt,
            PassType::Otp => &mut u.no_otp_failed_attempt,
        };
        *f = Some(f.unwrap_or(0) + 1);
        Ok(*f)
    }

    async fn reset_failed_attempt(&self, user_id: u64, t: PassType) -> AuthResult<bool> {
        let mut d = self.enter("reset_failed_attempt")?;
        let Some(u) = d.users.iter_mut().find(|u| u.id == user_id) else { return Ok(false) };
        match t {
            PassType::Password => u.no_failed_attempt = Some(0),
            PassType::Pin => u.no_pin_failed_attempt = Some(0),
            PassType::Otp => u.no_otp_failed_attempt = Some(0),
        }
        Ok(true)
    }

    async fn increase_resend_attempts(&self, user_id: u64) -> AuthResult<Option<i64>> {
        let _d = self.enter("increase_resend_attempts")?;
        Ok(Some(user_id as i64))
    }

    async fn reset_resend_attempts(&self, _user_id: u64) -> AuthResult<bool> {
        let _d = self.enter("reset_resend_attempts")?;
        Ok(true)
    }

    async fn lock_user(&self, user_id: u64, until: NaiveDateTime, due_to: &str) -> AuthResult<bool> {
        let mut d = self.enter("lock_user")?;
        let Some(u) = d.users.iter_mut().find(|u| u.id == user_id) else { return Ok(false) };
        u.status_code = "LOCKED".into();
        u.account_non_locked = false;
        u.locked_until = Some(until);
        u.locked_due_to = Some(due_to.into());
        Ok(true)
    }

    async fn unlock_user(&self, user_id: u64) -> AuthResult<bool> {
        let mut d = self.enter("unlock_user")?;
        let Some(u) = d.users.iter_mut().find(|u| u.id == user_id && u.status_code != "DELETED") else { return Ok(false) };
        u.status_code = "ACTIVE".into();
        u.account_non_locked = true;
        u.no_failed_attempt = Some(0);
        u.no_pin_failed_attempt = Some(0);
        u.no_otp_failed_attempt = Some(0);
        u.locked_until = None;
        u.locked_due_to = None;
        Ok(true)
    }

    async fn client_by_id(&self, id: u64) -> AuthResult<Option<Client>> {
        let d = self.enter("client_by_id")?;
        Ok(d.clients.iter().find(|c| c.id == Some(id)).cloned())
    }

    async fn client_by_code(&self, code: &str) -> AuthResult<Option<Client>> {
        let d = self.enter("client_by_code")?;
        Ok(d.clients.iter().find(|c| c.code.as_deref() == Some(code)).cloned())
    }

    async fn client_type_code_level(&self, id: u64) -> AuthResult<Option<(String, String, String)>> {
        let d = self.enter("client_type_code_level")?;
        Ok(d.clients.iter().find(|c| c.id == Some(id)).map(|c| {
            (c.type_code.clone().unwrap_or_default(), c.code.clone().unwrap_or_default(), c.level_type.clone().unwrap_or_default())
        }))
    }

    async fn client_hierarchy(&self, client_id: u64) -> AuthResult<Option<ClientHierarchy>> {
        let d = self.enter("client_hierarchy")?;
        Ok(d.hierarchies.iter().find(|h| h.client_id == client_id).cloned())
    }

    async fn count_active_clients(&self, ids: &[u64]) -> AuthResult<i64> {
        let d = self.enter("count_active_clients")?;
        Ok(d.clients
            .iter()
            .filter(|c| c.id.is_some_and(|i| ids.contains(&i)) && c.status_code.as_deref() == Some("ACTIVE"))
            .count() as i64)
    }

    async fn client_url_patterns(&self) -> AuthResult<Vec<UrlPattern>> {
        let d = self.enter("client_url_patterns")?;
        Ok(d.url_patterns.clone())
    }

    async fn app_by_code(&self, code: &str) -> AuthResult<Option<App>> {
        let d = self.enter("app_by_code")?;
        Ok(d.apps.iter().find(|a| a.app_code == code).cloned())
    }

    async fn app_by_id(&self, id: u64) -> AuthResult<Option<App>> {
        let d = self.enter("app_by_id")?;
        Ok(d.apps.iter().find(|a| a.id == id).cloned())
    }

    async fn has_read_access(&self, app_code: &str, client_code: &str) -> AuthResult<bool> {
        let d = self.enter("has_read_access")?;
        let Some(app) = d.apps.iter().find(|a| a.app_code == app_code) else { return Ok(false) };
        let Some(client) = d.clients.iter().find(|c| c.code.as_deref() == Some(client_code)) else { return Ok(false) };
        Ok(app.client_id == client.id() || d.app_access.contains(&(client.id(), app.id)))
    }

    async fn has_dependency_either_direction(&self, a: u64, b: u64) -> AuthResult<bool> {
        let d = self.enter("has_dependency_either_direction")?;
        Ok(d.dependencies.contains(&(a, b)) || d.dependencies.contains(&(b, a)))
    }

    async fn user_roles(&self, user_id: u64) -> AuthResult<Vec<NamedRow>> {
        let d = self.enter("user_roles")?;
        let direct: Vec<u64> = d.user_roles.iter().filter(|(u, _)| *u == user_id).map(|(_, r)| *r).collect();
        let subs: Vec<u64> = d.sub_roles.iter().filter(|(r, _)| direct.contains(r)).map(|(_, s)| *s).collect();
        let ids: HashSet<u64> = direct.into_iter().chain(subs).collect();
        let mut roles: Vec<&(u64, String, Option<u64>)> = d.roles.iter().filter(|r| ids.contains(&r.0)).collect();
        roles.sort_by_key(|r| r.0);
        Ok(roles
            .into_iter()
            .map(|r| NamedRow { id: Some(r.0), name: Some(r.1.clone()), app_code: app_code_of(&d, r.2) })
            .collect())
    }

    async fn role_permissions(&self, role_ids: &[u64]) -> AuthResult<Vec<PermissionRow>> {
        let d = self.enter("role_permissions")?;
        Ok(d.role_permissions
            .iter()
            .filter(|(r, _)| role_ids.contains(r))
            .filter_map(|(_, p)| d.permissions.iter().find(|x| x.0 == *p))
            .map(|p| PermissionRow { name: Some(p.1.clone()), app_code: app_code_of(&d, p.2) })
            .collect())
    }

    async fn profile_ids(&self, app_code: Option<&str>, user_id: u64) -> AuthResult<Vec<u64>> {
        let d = self.enter("profile_ids")?;
        let all = app_code.is_none() || app_code == Some("nothing");
        Ok(d.profile_users
            .iter()
            .filter(|(_, u)| *u == user_id)
            .filter(|(p, _)| {
                all || d.profiles.iter().find(|x| x.id == *p).and_then(|x| app_code_of(&d, Some(x.app_id))).as_deref() == app_code
            })
            .map(|(p, _)| *p)
            .collect())
    }

    async fn default_profile_ids(&self, app_code: Option<&str>) -> AuthResult<Vec<u64>> {
        let d = self.enter("default_profile_ids")?;
        Ok(d.profiles
            .iter()
            .filter(|p| p.default && app_code_of(&d, Some(p.app_id)).as_deref() == app_code)
            .map(|p| p.id)
            .collect())
    }

    async fn profile_rows(&self, profile_id: u64, client_ids: &[u64]) -> AuthResult<Vec<NamedRow>> {
        let d = self.enter("profile_rows")?;
        Ok(d.profiles
            .iter()
            .filter(|p| p.id == profile_id || (p.root == Some(profile_id) && client_ids.contains(&p.client_id)))
            .map(|p| NamedRow { id: Some(p.id), name: p.name.clone(), app_code: app_code_of(&d, Some(p.app_id)) })
            .collect())
    }

    async fn profile_role_rows(&self, profile_ids: &[u64]) -> AuthResult<Vec<RoleRecord>> {
        let d = self.enter("profile_role_rows")?;
        let mut rows: Vec<&(u64, u64, i64)> = d.profile_roles.iter().filter(|(p, _, _)| profile_ids.contains(p)).collect();
        rows.sort_by_key(|(p, r, _)| (*p, *r));
        Ok(rows
            .into_iter()
            .map(|(p, r, ex)| {
                let role = d.roles.iter().find(|x| x.0 == *r);
                let profile = d.profiles.iter().find(|x| x.id == *p);
                RoleRecord {
                    role_id: role.map(|x| x.0),
                    profile_client_id: profile.map(|x| x.client_id),
                    profile_id: Some(*p),
                    role_name: role.map(|x| x.1.clone()),
                    app_code: role.and_then(|x| app_code_of(&d, x.2)),
                    exclude: Some(*ex),
                }
            })
            .collect())
    }

    async fn sub_role_rows(&self, role_ids: &[u64]) -> AuthResult<Vec<NamedRow>> {
        let d = self.enter("sub_role_rows")?;
        Ok(d.sub_roles
            .iter()
            .filter(|(r, _)| role_ids.contains(r))
            .filter_map(|(_, s)| d.roles.iter().find(|x| x.0 == *s))
            .map(|r| NamedRow { id: Some(r.0), name: Some(r.1.clone()), app_code: app_code_of(&d, r.2) })
            .collect())
    }

    async fn permission_rows(&self, role_ids: &[u64]) -> AuthResult<Vec<PermissionRow>> {
        let d = self.enter("permission_rows")?;
        Ok(d.role_permissions
            .iter()
            .filter(|(r, _)| role_ids.contains(r))
            .filter_map(|(_, p)| d.permissions.iter().find(|x| x.0 == *p))
            .map(|p| PermissionRow { name: Some(p.1.clone()), app_code: app_code_of(&d, p.2) })
            .collect())
    }

    async fn user_has_any_profile(&self, user_id: u64, app_code: &str) -> AuthResult<bool> {
        let d = self.enter("user_has_any_profile")?;
        let of_app = |p: &FakeProfile| app_code_of(&d, Some(p.app_id)).as_deref() == Some(app_code);
        let assigned = d
            .profile_users
            .iter()
            .filter(|(_, u)| *u == user_id)
            .any(|(p, _)| d.profiles.iter().any(|x| x.id == *p && of_app(x)));
        Ok(assigned || d.profiles.iter().any(|p| p.default && of_app(p)))
    }

    async fn has_assigned_profile(&self, user_id: u64, app_id: u64) -> AuthResult<bool> {
        let d = self.enter("has_assigned_profile")?;
        Ok(d.profile_users
            .iter()
            .filter(|(_, u)| *u == user_id)
            .any(|(p, _)| d.profiles.iter().any(|x| x.id == *p && x.app_id == app_id)))
    }

    async fn user_app_having_profile(&self, user_id: u64) -> AuthResult<Option<u64>> {
        let d = self.enter("user_app_having_profile")?;
        Ok(d.profile_users
            .iter()
            .filter(|(_, u)| *u == user_id)
            .filter_map(|(p, _)| d.profiles.iter().find(|x| x.id == *p))
            .map(|p| p.app_id)
            .next())
    }

    async fn policy(&self, t: PassType, client_id: u64, app_id: u64) -> AuthResult<Option<Policy>> {
        let d = self.enter("policy")?;
        Ok(d.policies.iter().find(|(pt, c, a, _)| *pt == t && *c == client_id && *a == app_id).map(|x| x.3.clone()))
    }

    async fn tokens_by_part(&self, part_token: &str) -> AuthResult<Vec<TokenRow>> {
        let d = self.enter("tokens_by_part")?;
        Ok(d.tokens
            .iter()
            .filter(|t| t.part.eq_ignore_ascii_case(part_token))
            .map(|t| TokenRow { id: t.id, user_id: t.user_id, token: t.token.clone(), expires_at: t.expires_at })
            .collect())
    }

    async fn insert_token(&self, t: &NewToken) -> AuthResult<u64> {
        let mut d = self.enter("insert_token")?;
        let id = next(&mut d);
        d.tokens.push(FakeToken {
            id,
            user_id: t.user_id,
            token: t.token.clone(),
            part: t.part_token.clone(),
            expires_at: t.expires_at,
            last_used: None,
            created_by: t.created_by,
            ip: t.origin.ip_address.clone(),
        });
        Ok(id)
    }

    async fn delete_token(&self, id: u64) -> AuthResult<u64> {
        let mut d = self.enter("delete_token")?;
        let before = d.tokens.len();
        d.tokens.retain(|t| t.id != id);
        Ok((before - d.tokens.len()) as u64)
    }

    async fn token_strings_of_user(&self, user_id: u64) -> AuthResult<Vec<String>> {
        let d = self.enter("token_strings_of_user")?;
        Ok(d.tokens.iter().filter(|t| t.user_id == user_id).map(|t| t.token.clone()).collect())
    }

    async fn delete_tokens_of_user(&self, user_id: u64) -> AuthResult<u64> {
        let mut d = self.enter("delete_tokens_of_user")?;
        let before = d.tokens.len();
        d.tokens.retain(|t| t.user_id != user_id);
        Ok((before - d.tokens.len()) as u64)
    }

    async fn update_last_used(&self, id: u64, at: NaiveDateTime) -> AuthResult<u64> {
        let mut d = self.enter("update_last_used")?;
        let mut n = 0;
        for t in d.tokens.iter_mut().filter(|t| t.id == id) {
            t.last_used = Some(at);
            n += 1;
        }
        Ok(n)
    }

    async fn delete_expired_tokens(&self, now: NaiveDateTime) -> AuthResult<u64> {
        let mut d = self.enter("delete_expired_tokens")?;
        let before = d.tokens.len();
        d.tokens.retain(|t| t.expires_at >= now);
        Ok((before - d.tokens.len()) as u64)
    }

    async fn delete_unused_tokens(&self, cutoff: NaiveDateTime) -> AuthResult<u64> {
        let mut d = self.enter("delete_unused_tokens")?;
        let before = d.tokens.len();
        d.tokens.retain(|t| t.last_used.is_none_or(|l| l >= cutoff));
        Ok((before - d.tokens.len()) as u64)
    }

    async fn delete_expired_draft_tokens(&self, _now_utc: NaiveDateTime) -> AuthResult<u64> {
        let d = self.enter("delete_expired_draft_tokens")?;
        Ok(d.draft_tokens_expired)
    }

    async fn insert_one_time_token(&self, t: &NewOneTimeToken) -> AuthResult<()> {
        let mut d = self.enter("insert_one_time_token")?;
        let now = d.db_now.unwrap_or_else(|| Utc::now().naive_utc());
        d.otts.push(FakeOtt { row: t.clone(), created_at: now });
        Ok(())
    }

    async fn redeem_one_time_token(&self, token: &str, max_age_minutes: i64) -> AuthResult<Option<OneTimeTokenRow>> {
        let mut d = self.enter("redeem_one_time_token")?;
        let now = d.db_now.unwrap_or_else(|| Utc::now().naive_utc());
        let Some(pos) = d.otts.iter().position(|o| o.row.token == token) else { return Ok(None) };
        let o = d.otts.remove(pos);
        if o.created_at < now - chrono::Duration::minutes(max_age_minutes) {
            return Ok(None);
        }
        Ok(Some(OneTimeTokenRow {
            user_id: o.row.user_id,
            remember_me: o.row.remember_me.unwrap_or(false),
            auth_mode: Some(o.row.auth_mode.clone().unwrap_or_else(|| "BEARER".into())),
            origin_app_code: o.row.origin_app_code.clone(),
            target_app_code: o.row.target_app_code.clone(),
        }))
    }

    async fn insert_sox_log(&self, object_id: u64, action: &str, _object: &str, description: &str) -> AuthResult<()> {
        let mut d = self.enter("insert_sox_log")?;
        d.sox.push((object_id, action.to_string(), description.to_string()));
        Ok(())
    }

    async fn latest_otp(&self, app_id: u64, user_id: u64, purpose: &str) -> AuthResult<Option<OtpRow>> {
        let d = self.enter("latest_otp")?;
        Ok(d.otps
            .iter()
            .filter(|o| o.otp.app_id == app_id && o.otp.user_id == Some(user_id) && o.otp.purpose == purpose)
            .max_by_key(|o| (o.otp.created_at, o.id))
            .map(|o| OtpRow { id: o.id, unique_code: o.otp.unique_code.clone(), expires_at: o.otp.expires_at, verify_legs_counts: o.legs }))
    }

    async fn latest_otp_code(&self, app_id: u64, user_id: u64, purpose: &str) -> AuthResult<Option<String>> {
        drop(self.enter("latest_otp_code")?);
        Ok(self.latest_otp(app_id, user_id, purpose).await?.map(|o| o.unique_code))
    }

    async fn latest_otp_by_target(&self, app_id: u64, email: Option<&str>, phone: Option<&str>, purpose: &str) -> AuthResult<Option<OtpRow>> {
        let d = self.enter("latest_otp_by_target")?;
        Ok(d.otps
            .iter()
            .filter(|o| o.otp.app_id == app_id && o.otp.purpose == purpose)
            .filter(|o| {
                (email.is_some() && o.otp.email_id.as_deref() == email) || (phone.is_some() && o.otp.phone_number.as_deref() == phone)
            })
            .max_by_key(|o| (o.otp.created_at, o.id))
            .map(|o| OtpRow { id: o.id, unique_code: o.otp.unique_code.clone(), expires_at: o.otp.expires_at, verify_legs_counts: o.legs }))
    }

    async fn insert_otp(&self, o: &NewOtp) -> AuthResult<()> {
        let mut d = self.enter("insert_otp")?;
        let id = next(&mut d);
        d.otps.push(FakeOtp { id, otp: o.clone(), legs: 0 });
        Ok(())
    }

    async fn delete_otp(&self, id: u64) -> AuthResult<u64> {
        let mut d = self.enter("delete_otp")?;
        let before = d.otps.len();
        d.otps.retain(|o| o.id != id);
        Ok((before - d.otps.len()) as u64)
    }

    async fn increase_otp_verify_count(&self, id: u64) -> AuthResult<bool> {
        let mut d = self.enter("increase_otp_verify_count")?;
        let mut found = false;
        for o in d.otps.iter_mut().filter(|o| o.id == id) {
            o.legs += 1;
            found = true;
        }
        Ok(found)
    }

    async fn state_by_value(&self, state: &str) -> AuthResult<Option<StateRow>> {
        let d = self.enter("state_by_value")?;
        Ok(d.states.iter().find(|s| s.state == state).cloned())
    }

    async fn consume_state(&self, state: &str) -> AuthResult<bool> {
        let mut d = self.enter("consume_state")?;
        let before = d.states.len();
        d.states.retain(|s| s.state != state);
        Ok(before != d.states.len())
    }
}

#[derive(Default)]
pub struct RecordingEvents {
    pub events: Mutex<Vec<EventMessage>>,
    pub fail: bool,
}

#[async_trait]
impl EventSink for RecordingEvents {
    async fn publish(&self, event: &EventMessage) -> AuthResult<bool> {
        if self.fail {
            return Err(AuthError::internal("mq down"));
        }
        self.events.lock().unwrap().push(event.clone());
        Ok(true)
    }
}

#[derive(Default)]
pub struct RecordingSms {
    /// (phone, purpose, otp, minutes)
    pub sent: Mutex<Vec<(String, String, String, i64)>>,
}

#[async_trait]
impl SmsSender for RecordingSms {
    async fn send_otp(&self, phone: &str, purpose: &str, otp: &str, minutes: i64) -> AuthResult<bool> {
        self.sent.lock().unwrap().push((phone.into(), purpose.into(), otp.into(), minutes));
        Ok(true)
    }
}

/// 2026-10-15 02:00:00 UTC, in a zone 5h30 east (as the local JVMs run).
pub fn clock() -> Clock {
    Clock::fixed(Utc.with_ymd_and_hms(2026, 10, 15, 2, 0, 0).unwrap(), 19_800)
}

pub fn dt(s: &str) -> NaiveDateTime {
    NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").unwrap()
}

pub struct Harness {
    pub store: Arc<FakeStore>,
    pub auth: Arc<Auth>,
    pub events: Arc<RecordingEvents>,
    pub sms: Arc<RecordingSms>,
    pub cache: CacheService,
}

pub fn harness_with(data: Data, clock: Clock, settings: Settings) -> Harness {
    let store = FakeStore::new(data);
    let cache = CacheService::new("cmn", "evictionChannel", None).unwrap();
    let events = Arc::new(RecordingEvents::default());
    let sms = Arc::new(RecordingSms::default());
    let auth = Arc::new(Auth {
        dir: Directory::new(store.clone(), Caches::new(cache.clone()), vec![".local.modlix.com".into()]),
        settings,
        clock,
        events: events.clone(),
        sms: sms.clone(),
    });
    Harness { store, auth, events, sms, cache }
}

pub fn settings() -> Settings {
    Settings { jwt_key: KEY.into(), app_code_suffix: ".local".into(), ..Settings::default() }
}

pub fn harness() -> Harness {
    harness_with(seed(), clock(), settings())
}

pub fn client(id: u64, code: &str, typ: &str, level: &str, validity: i64) -> Client {
    Client {
        id: Some(id),
        code: Some(code.into()),
        name: Some(format!("{code} name")),
        type_code: Some(typ.into()),
        level_type: Some(level.into()),
        token_validity_minutes: validity,
        status_code: Some("ACTIVE".into()),
        time_zone: Some("Asia/Kolkata".into()),
        business_type: Some("COMMON".into()),
        created_at: Some(dt("2024-01-01 00:00:00")),
        ..Default::default()
    }
}

pub fn user(id: u64, client_id: u64, name: &str, password: &str) -> User {
    User {
        id,
        client_id,
        user_name: Some(name.into()),
        email_id: Some(format!("{name}@example.com")),
        phone_number: Some("NONE".into()),
        first_name: Some(name.to_uppercase()),
        last_name: Some("".into()),
        locale_code: Some("en".into()),
        password: Some(password.into()),
        password_hashed: false,
        account_non_expired: true,
        account_non_locked: true,
        credentials_non_expired: true,
        no_failed_attempt: Some(0),
        no_pin_failed_attempt: Some(0),
        no_otp_failed_attempt: Some(0),
        status_code: "ACTIVE".into(),
        created_at: Some(dt("2024-01-02 00:00:00")),
        updated_at: Some(dt("2024-01-03 00:00:00")),
        ..Default::default()
    }
}

pub fn app(id: u64, client_id: u64, code: &str) -> App {
    App {
        id,
        client_id,
        app_name: Some(format!("{code} app")),
        app_code: code.into(),
        app_access_type: Some("OWN".into()),
        status: Some("ACTIVE".into()),
        ..Default::default()
    }
}

/// SYSTEM (1) manages BUS (2), which manages CUST (3). Apps: appbuilder (SYSTEM's), crm (BUS's,
/// with a dependency on appbuilder). Users: 142 sysadmin (plain password), 10 bus owner
/// (hashed password and PIN), 11 bus member, 12 inactive, 13 locked, 14 expired.
pub fn seed() -> Data {
    let mut d = Data { next_id: 1000, ..Default::default() };
    d.clients = vec![
        client(1, "SYSTEM", "SYS", "SYSTEM", 60),
        client(2, "BUS", "BUS", "CLIENT", 30),
        client(3, "CUST", "INDV", "CUSTOMER", 0),
    ];
    d.hierarchies = vec![
        ClientHierarchy { client_id: 1, ..Default::default() },
        ClientHierarchy { client_id: 2, level0: Some(1), ..Default::default() },
        ClientHierarchy { client_id: 3, level0: Some(2), level1: Some(1), ..Default::default() },
    ];
    d.apps = vec![app(1, 1, "appbuilder"), app(2, 2, "crm"), app(3, 1, "authzump")];
    d.apps[2].app_access_type = Some("ANY".into());
    d.app_access = vec![(2, 1)];
    d.dependencies = vec![(2, 1)];
    let mut sys = user(142, 1, "kirangrandhi", "Pass@1234");
    sys.time_zone = None;
    let mut owner = user(10, 2, "owner", "");
    owner.password = Some(bcrypt::hash("10secret", 4).unwrap());
    owner.password_hashed = true;
    owner.pin = Some(bcrypt::hash("101234", 4).unwrap());
    owner.pin_hashed = true;
    owner.time_zone = Some("Europe/London".into());
    let member = user(11, 2, "member", "memberpw");
    let mut inactive = user(12, 2, "inactive", "x");
    inactive.status_code = "INACTIVE".into();
    let mut locked = user(13, 2, "locked", "lockedpw");
    locked.status_code = "LOCKED".into();
    locked.locked_until = Some(dt("2026-10-15 07:45:00"));
    locked.locked_due_to = Some("Password".into());
    let mut expired = user(14, 2, "expired", "x");
    expired.status_code = "PASSWORD_EXPIRED".into();
    let mut deleted = user(15, 2, "deleted", "x");
    deleted.status_code = "DELETED".into();
    d.users = vec![sys, owner, member, inactive, locked, expired, deleted];
    d.roles = vec![
        (1, "Owner".into(), None),
        (2, "Page Manager".into(), None),
        (3, "Lead Viewer".into(), Some(2)),
        (4, "Page READ".into(), None),
    ];
    d.permissions = vec![(1, "Page READ".into(), None), (2, "Lead READ".into(), Some(2))];
    d.role_permissions = vec![(2, 1), (3, 2)];
    d.sub_roles = vec![(2, 4)];
    d.profiles = vec![
        FakeProfile { id: 1, client_id: 1, name: Some("Appbuilder Owner".into()), app_id: 1, root: None, default: false },
        FakeProfile { id: 2, client_id: 2, name: Some("Crm Owner".into()), app_id: 2, root: None, default: false },
        FakeProfile { id: 3, client_id: 2, name: Some("Crm Member".into()), app_id: 2, root: None, default: true },
    ];
    d.profile_users = vec![(1, 142), (2, 10), (1, 10)];
    d.profile_roles = vec![(1, 1, 0), (1, 2, 0), (2, 1, 0), (2, 3, 0), (3, 3, 0)];
    d
}

pub fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (k, v) in pairs {
        h.append(axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(), HeaderValue::from_str(v).unwrap());
    }
    h
}

pub fn req(pairs: &[(&str, &str)]) -> RequestInfo {
    let mut h = headers(pairs);
    if !h.contains_key("host") {
        h.insert("host", HeaderValue::from_static("apps.local:8080"));
    }
    RequestInfo::new(h, Some("10.1.2.3:4000".parse().unwrap()))
}

/// A request from the SYSTEM client to an app.
pub fn sys_req(app: &str) -> RequestInfo {
    req(&[("clientCode", "SYSTEM"), ("appCode", app), ("X-Forwarded-Host", "apps.local"), ("X-Forwarded-Port", "443")])
}

pub fn bus_req(app: &str) -> RequestInfo {
    req(&[("clientCode", "BUS"), ("appCode", app), ("X-Forwarded-Host", "bus.local"), ("X-Forwarded-Port", "443")])
}

pub fn with_bearer(r: &RequestInfo, token: &str) -> RequestInfo {
    let mut r = r.clone();
    r.headers.insert("authorization", HeaderValue::from_str(&format!("Bearer {token}")).unwrap());
    r
}

/// Lets fire-and-forget writes (the sox log) land.
pub async fn settle() {
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
}

/// A coded error body's code and Java's text for it (`debugMessage` ends with Java's message),
/// for asserting both at once: `(code, java_text_matches)`.
#[allow(dead_code)]
pub fn coded(v: &serde_json::Value, java: &str) -> (String, bool) {
    let code = v["code"].as_str().unwrap_or("").to_string();
    let matches = v["debugMessage"].as_str().is_some_and(|d| d.ends_with(java));
    (code, matches)
}
