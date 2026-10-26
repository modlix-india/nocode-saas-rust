//! `UserController` / `UserService` (and `UserSubOrganizationService.updateManager`): users read,
//! listed, created, edited, deleted (marked `DELETED`), activated, unblocked, given a designation
//! or a manager, given and relieved of roles and profiles; who exists; the caller's members and
//! sub-organisation.
//!
//! The access rule every edit runs through: the caller's client must manage the user's client
//! (`isUserClientManageClient`), and a non-Owner of that same client may only touch themselves or
//! people below them in the reporting tree (`checkSubOrgAndRun`).

use std::sync::Arc;

use axum::http::StatusCode;
use axum::routing::{get, patch, post, put};
use axum::Router;
use serde_json::{Map, Value};

use super::common::{
    has_any, i64_value, object_body, patch_error, pre_authorize, pre_authorize_all, refuse, string_value, u64_value,
    ulong_patch_failure, Fields,
};
use crate::admin::{Admin, AdminState};
use crate::caches;
use crate::condition::{from_params, Cond, Filter};
use crate::data::audit::{action, assignment, entity_changed, object, sox, activity};
use crate::data::users_admin::{user_values, USER};
use crate::dto::{user_json, UserExtras};
use crate::errors::{AuthError, AuthResult};
use crate::expr::has_authority;
use crate::internal::users::UserFill;
use crate::jackson::{json, Obj};
use crate::model::{ClientHierarchy, ContextAuth, User, PLACEHOLDER};
use crate::spring::Pageable;
use crate::web::{opt_u64, query_body, to_u64, unreadable};

const OWNER_ROLE: &str = "Authorities.ROLE_Owner";
const CLIENT_MANAGE_ROLE: &str = "Authorities.ROLE_Client_MANAGE";
const USER_CREATED_PREFIX: &str = "User created: ";
const ASSIGNED_ROLE: &str = " Role is assigned to the user ";
const UNASSIGNED_ROLE: &str = " Role is removed from the selected user";
/// `UserService.MEMBERS_DEFAULT_SIZE` / `MEMBERS_MAX_SIZE`.
pub const MEMBERS_DEFAULT_SIZE: i64 = 200;
const MEMBERS_MAX_SIZE: i64 = 500;
const STATUSES: [&str; 5] = ["ACTIVE", "INACTIVE", "DELETED", "LOCKED", "PASSWORD_EXPIRED"];

fn forbidden(key: &str, params: &[&str]) -> AuthError {
    refuse(StatusCode::FORBIDDEN, key, params)
}

/// `describeEntity`: the e-mail when there is one, else the user name (`NONE` reads as none).
pub fn describe(u: &User) -> Option<String> {
    u.email_id().filter(|e| !e.trim().is_empty()).or_else(|| u.user_name())
}

fn blank(s: &Option<String>) -> bool {
    s.as_deref().is_none_or(|v| v.trim().is_empty())
}

/// Jackson's `SecurityUserStatusCode`: a constant's name or its ordinal.
fn status_value(v: Option<&Value>) -> Result<Option<String>, ()> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => STATUSES.contains(&s.as_str()).then(|| Some(s.clone())).ok_or(()),
        Some(Value::Number(n)) => n.as_u64().and_then(|i| STATUSES.get(i as usize)).map(|s| Some(s.to_string())).ok_or(()),
        Some(_) => Err(()),
    }
}

/// `Short`: a number (or numeric text) in range.
fn short_value(v: Option<&Value>) -> Result<Option<i64>, ()> {
    match i64_value(v)? {
        Some(n) if !(-32768..=32767).contains(&n) => Err(()),
        other => Ok(other),
    }
}

/// `User` as Jackson reads a request body: `password`, `pin` and their flags are `@JsonIgnore`d,
/// so a body never sets them; the typed parts are read whole and unused.
pub fn user_from_body(m: &Map<String, Value>) -> AuthResult<User> {
    let f = Fields(m);
    for k in ["profiles", "authorities"] {
        if !matches!(m.get(k), None | Some(Value::Null) | Some(Value::Array(_))) {
            return Err(unreadable());
        }
    }
    for k in ["client", "managingClient", "createdByUser", "designation", "reportingUser"] {
        if !matches!(m.get(k), None | Some(Value::Null) | Some(Value::Object(_))) {
            return Err(unreadable());
        }
    }
    f.string("clientCode")?;
    let short = |k: &str| short_value(m.get(k)).map_err(|_| crate::web::unreadable_field(k));
    short("noOtpResendAttempts")?;
    Ok(User {
        id: f.u64("id")?.unwrap_or(0),
        designation_id: f.u64("designationId")?,
        reporting_to: f.u64("reportingTo")?,
        client_id: f.u64("clientId")?.unwrap_or(0),
        user_name: f.string("userName")?,
        email_id: f.string("emailId")?,
        phone_number: f.string("phoneNumber")?,
        first_name: f.string("firstName")?,
        last_name: f.string("lastName")?,
        middle_name: f.string("middleName")?,
        locale_code: f.string("localeCode")?,
        password: None,
        password_hashed: false,
        pin: None,
        pin_hashed: false,
        account_non_expired: f.bool("accountNonExpired")?,
        account_non_locked: f.bool("accountNonLocked")?,
        credentials_non_expired: f.bool("credentialsNonExpired")?,
        no_failed_attempt: short("noFailedAttempt")?,
        no_pin_failed_attempt: short("noPinFailedAttempt")?,
        no_otp_failed_attempt: short("noOtpFailedAttempt")?,
        status_code: status_value(m.get("statusCode")).map_err(|_| crate::web::unreadable_field("statusCode"))?.unwrap_or_default(),
        locked_until: f.ts("lockedUntil")?,
        locked_due_to: f.string("lockedDueTo")?,
        created_by: f.u64("createdBy")?,
        created_at: f.ts("createdAt")?,
        updated_by: f.u64("updatedBy")?,
        updated_at: f.ts("updatedAt")?,
        time_zone: f.string("timeZone")?,
    })
}

/// The setters `User` declares, as the reflective PATCH calls them. Whether the body named a
/// client is returned too (the update checks run on the patched client).
fn patch_user(u: &mut User, fields: &Map<String, Value>) -> AuthResult<()> {
    for (k, v) in fields {
        let text = || string_value(Some(v)).map_err(|_| patch_error(k));
        let ulong = || u64_value(Some(v)).map_err(|_| ulong_patch_failure());
        let flag = || super::common::bool_value(Some(v)).map_err(|_| patch_error(k));
        let short = || short_value(Some(v)).map_err(|_| patch_error(k));
        match k.as_str() {
            "clientId" => u.client_id = ulong()?.unwrap_or(0),
            "designationId" => u.designation_id = ulong()?,
            "reportingTo" => u.reporting_to = ulong()?,
            "userName" => u.user_name = text()?,
            "emailId" => u.email_id = text()?,
            "phoneNumber" => u.phone_number = text()?,
            "firstName" => u.first_name = text()?,
            "lastName" => u.last_name = text()?,
            "middleName" => u.middle_name = text()?,
            "localeCode" => u.locale_code = text()?,
            "timeZone" => u.time_zone = text()?,
            "lockedDueTo" => u.locked_due_to = text()?,
            "clientCode" | "password" | "pin" => {
                text()?;
            }
            "passwordHashed" | "pinHashed" | "accountNonExpired" | "accountNonLocked" | "credentialsNonExpired" => {
                flag()?;
            }
            "noFailedAttempt" | "noPinFailedAttempt" | "noOtpResendAttempts" | "noOtpFailedAttempt" => {
                short()?;
            }
            "statusCode" => u.status_code = status_value(Some(v)).map_err(|_| patch_error(k))?.unwrap_or_default(),
            "lockedUntil" => {
                super::common::ts_value(Some(v)).map_err(|_| patch_error(k))?;
            }
            "authorities" | "profiles" if !matches!(v, Value::Null | Value::Array(_)) => return Err(patch_error(k)),
            "client" | "managingClient" | "createdByUser" | "designation" | "reportingUser" if !matches!(v, Value::Null | Value::Object(_)) => {
                return Err(patch_error(k))
            }
            _ => {}
        }
    }
    Ok(())
}

/// `UserService.applyUpdatableFields`: what an edit may change; a caller editing themselves
/// without `User_UPDATE` keeps their status, designation and manager.
pub fn apply_updatable_fields(e: &mut User, entity: &User, ca: &ContextAuth) {
    let self_without_update = e.id == ca.user.id() && !has_any(ca, &["Authorities.User_UPDATE"]);
    e.user_name = entity.user_name();
    e.email_id = entity.email_id();
    e.phone_number = entity.phone_number();
    e.first_name = entity.first_name.clone();
    e.last_name = entity.last_name.clone();
    e.middle_name = entity.middle_name.clone();
    e.locale_code = entity.locale_code.clone();
    e.time_zone = crate::timezone::sanitize(entity.time_zone.as_deref());
    if self_without_update {
        return;
    }
    e.status_code = entity.status_code.clone();
    e.designation_id = entity.designation_id;
    e.reporting_to = entity.reporting_to;
}

/// `takenIdentity`: which identifier the other user already holds, for the 409.
fn taken_identity(other: &User, email: Option<&str>, phone: Option<&str>) -> &'static str {
    if email.is_some_and(|e| other.email_id.as_deref().is_some_and(|o| o.eq_ignore_ascii_case(e))) {
        return "email";
    }
    if phone.is_some_and(|p| other.phone_number.as_deref().is_some_and(|o| o.eq_ignore_ascii_case(p))) {
        return "phone number";
    }
    "user name"
}

/// U7 (2026-10-21): may a caller of `caller.client_id` read a user of `target.client_id` by id.
/// Yes for the same client, for a target client the caller's client manages at any level (its
/// partners and customers, without being their client manager), and for the caller's client's
/// direct managing client (a partner reading the business's user its deals are assigned to,
/// what core's `GetUser` allows) unless that is the root (SYSTEM, the one client nobody manages).
/// An unrelated client, a sibling, or a manager further up is not.
fn may_read_user_of(caller: &ClientHierarchy, target: &ClientHierarchy) -> bool {
    caller.client_id == target.client_id
        || target.is_managed_by(caller.client_id)
        || (caller.level0 == Some(target.client_id) && target.level0.is_some())
}

/// `validateUserCheckProperty`'s choice: the user's level under the app's client (`OWNER`, then
/// `CLIENT`, `CUSTOMER`, `CONSUMER` going down), and for a `USER_CHECK` value that applies at that
/// level, the client whose users are compared and whether its direct (level 0) and grand
/// (level 1) clients count. `None` when nothing is checked.
fn user_check_scope(check: &str, app_client: u64, client_id: u64, h: &ClientHierarchy) -> Option<(u64, bool, bool)> {
    let level = if app_client == client_id {
        "OWNER"
    } else if Some(app_client) == h.level0 {
        "CLIENT"
    } else if Some(app_client) == h.level1 {
        "CUSTOMER"
    } else {
        "CONSUMER"
    };
    let (parent, direct, grand) = match check {
        "NO_DUPLICATE_USER_CLIENT" if level == "CLIENT" => (Some(app_client), true, false),
        "NO_DUPLICATE_USER_CUSTOMER" if level == "CUSTOMER" || level == "CONSUMER" => {
            let p = if Some(app_client) == h.level1 {
                h.level0
            } else if Some(app_client) == h.level2 {
                h.level1
            } else if Some(app_client) == h.level3 {
                h.level2
            } else {
                return None;
            };
            (p, true, true)
        }
        "NO_DUPLICATE_USER_CONSUMER" if level == "CONSUMER" => {
            let p = if Some(app_client) == h.level2 {
                h.level0
            } else if Some(app_client) == h.level3 {
                h.level1
            } else {
                return None;
            };
            (p, true, false)
        }
        _ => return None,
    };
    parent.map(|p| (p, direct, grand))
}

/// `UserMember`.
fn member_json(id: u64, first: Option<String>, last: Option<String>, user_name: Option<String>, status: Option<String>, client_code: Option<String>) -> Value {
    let first = first.filter(|v| !v.trim().is_empty()).map(|v| v.trim().to_string());
    let last = last.filter(|v| !v.trim().is_empty()).map(|v| v.trim().to_string());
    let uname = user_name.filter(|u| !u.trim().is_empty() && u.trim() != PLACEHOLDER && !u.contains('@')).map(|u| u.trim().to_string());
    let mut name = [first.clone(), last.clone()].into_iter().flatten().collect::<Vec<_>>().join(" ");
    if name.is_empty() {
        name = uname.clone().unwrap_or_else(|| format!("User {id}"));
    }
    Obj::new()
        .put("id", id)
        .put("firstName", crate::jackson::opt(first))
        .put("lastName", crate::jackson::opt(last))
        .put("userName", crate::jackson::opt(uname))
        .put("name", name)
        .put("statusCode", crate::jackson::opt(status))
        .put("clientCode", crate::jackson::opt(client_code))
        .build()
}

impl Admin {
    /// `isSameClientNonOwner`.
    fn same_client_non_owner(ca: &ContextAuth, target_client: u64) -> bool {
        !ca.is_system_client() && ca.user.client_id() == target_client && !has_any(ca, &[OWNER_ROLE])
    }

    /// `checkSubOrgAndRun`'s test: may the caller act on the target user?
    async fn sub_org_allows(&self, ca: &ContextAuth, client_id: u64, target: u64) -> AuthResult<bool> {
        if !Self::same_client_non_owner(ca, client_id) || ca.user.id() == target {
            return Ok(true);
        }
        self.db.is_user_in_sub_org(client_id, ca.user.id(), target).await
    }

    /// `UserSubOrganizationService.evictOwnerCache`.
    pub async fn evict_owner_cache(&self, client_id: u64, user_id: Option<u64>) {
        let svc = &self.caches().service;
        svc.evict_everywhere(caches::USER_SUB_ORG, &format!("orgStructure:{client_id}")).await;
        svc.evict_everywhere(caches::USER_SUB_ORG, &format!("{client_id}:owner")).await;
        if let Some(u) = user_id {
            svc.evict_everywhere(caches::USER_SUB_ORG, &format!("{client_id}:{u}")).await;
        }
    }

    /// `evictManagerCaches` / `evictHierarchyCaches`.
    pub async fn evict_manager_caches(&self, client_id: u64, old: Option<u64>, new: Option<u64>) {
        let svc = &self.caches().service;
        svc.evict_everywhere(caches::USER_SUB_ORG, &format!("orgStructure:{client_id}")).await;
        for m in [old, new].into_iter().flatten() {
            svc.evict_everywhere(caches::USER_SUB_ORG, &format!("{client_id}:{m}")).await;
        }
    }

    /// `TokenService.evictTokensOfUser`: the cached contexts of every token the user holds.
    pub async fn evict_tokens(&self, user_id: u64) -> AuthResult<()> {
        for t in self.dir().store.token_strings_of_user(user_id).await? {
            self.caches().service.evict_everywhere(caches::TOKEN, &t).await;
        }
        Ok(())
    }

    /// `UserService.evictCache`: tokens, the owner list, the cached user.
    pub async fn evict_user(&self, user_id: u64, client_id: u64) -> AuthResult<()> {
        self.evict_tokens(user_id).await?;
        self.evict_owner_cache(client_id, Some(user_id)).await;
        self.caches().service.evict_everywhere(caches::USER, &user_id.to_string()).await;
        Ok(())
    }

    /// `UserDAO.readById`: 404 when missing.
    pub async fn user_dao_read(&self, id: u64) -> AuthResult<User> {
        self.db.user_row(id).await?.ok_or_else(|| super::common::not_found("User", id))
    }

    /// `UserService.read`: a user may read themselves; anyone else needs `User_READ`.
    pub async fn user_read(&self, ca: &ContextAuth, id: u64) -> AuthResult<User> {
        let u = self.user_dao_read(id).await?;
        if id != ca.user.id() && !has_any(ca, &["Authorities.User_READ"]) {
            return Err(forbidden("forbidden_permission", &["User READ"]));
        }
        Ok(u)
    }

    /// `GET /users/{id}`: `UserService.read` plus a client check Java does not make. A user of
    /// another client is read by SYSTEM, by a caller whose client manages the user's client at
    /// any level, and by a caller of a client the user's client directly manages; to anyone
    /// else the user is not found (DIFFERENCES.md U7, 2026-10-21).
    pub async fn user_read_managed(&self, ca: &ContextAuth, id: u64) -> AuthResult<User> {
        let u = self.user_read(ca, id).await?;
        if id == ca.user.id() || ca.is_system_client() {
            return Ok(u);
        }
        let own = ca.user.client_id();
        if own != u.client_id {
            let (caller, target) = (self.dir().hierarchy(own).await?, self.dir().hierarchy(u.client_id).await?);
            if !may_read_user_of(&caller, &target) {
                return Err(super::common::not_found("User", id));
            }
        }
        Ok(u)
    }

    /// `AbstractSecurityUpdatableDataService.update(entity)` with `UserService.updatableEntity`.
    pub async fn user_store_update(&self, ca: &ContextAuth, entity: &User) -> AuthResult<User> {
        let mut e = self.user_read(ca, entity.id).await?;
        apply_updatable_fields(&mut e, entity, ca);
        e.updated_by = Some(ca.user.id());
        e.updated_at = None;
        self.db.entity_update(&USER, e.id, &user_values(&e)).await?;
        let updated = self.user_dao_read(e.id).await?;
        entity_changed(&self.db, None, object::USER, action::UPDATE, updated.id, Some(updated.client_id), "User", describe(&updated).as_deref());
        Ok(updated)
    }

    /// `validateUserCheckProperty`: the app's `USER_CHECK` property may forbid a duplicate
    /// identity among the clients at the user's level under the app's client.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn validate_user_check(
        &self,
        ca: &ContextAuth,
        app_id: u64,
        client_id: u64,
        user_name: Option<&str>,
        email: Option<&str>,
        phone: Option<&str>,
        exclude: Option<u64>,
    ) -> AuthResult<()> {
        let app = self.dir().app_by_id(app_id).await?;
        let ids: Vec<u64> = if ca.is_system_client() { vec![] } else { vec![ca.user.client_id()] };
        let props = self.db.app_properties(&app, "USER_CHECK", &ids, ca.is_system_client()).await?;
        let check = props.iter().filter_map(|p| p.value.clone()).find(|v| !v.trim().is_empty()).unwrap_or_else(|| "NO_DUPLICATE_CHECK_REQUIRED".into());
        if check == "NO_DUPLICATE_CHECK_REQUIRED" {
            return Ok(());
        }
        let h = self.dir().hierarchy(client_id).await?;
        let Some((parent, direct, grand)) = user_check_scope(&check, app.client_id, client_id, &h) else { return Ok(()) };
        if self.db.user_exists_below(parent, direct, grand, user_name, email, phone, exclude).await? {
            let who = user_name.or(email).unwrap_or("null").to_string();
            return Err(refuse(StatusCode::CONFLICT, "user_already_exists", &[&who]));
        }
        Ok(())
    }

    /// The URL app's `USER_CHECK`, when the request names an app.
    async fn url_app_user_check(&self, ca: &ContextAuth, client_id: u64, u: (Option<&str>, Option<&str>, Option<&str>), exclude: Option<u64>) -> AuthResult<()> {
        let Some(code) = ca.url_app_code.as_deref().filter(|c| !c.trim().is_empty()) else { return Ok(()) };
        let Some(app) = self.dir().app_by_code(code).await? else { return Ok(()) };
        self.validate_user_check(ca, app.id, client_id, u.0, u.1, u.2, exclude).await
    }

    /// `UserService.create`.
    pub async fn user_create(&self, ca: &ContextAuth, mut e: User) -> AuthResult<User> {
        pre_authorize(ca, &["Authorities.User_CREATE"])?;
        let refused = || forbidden("forbidden_create", &["User"]);
        if e.client_id == 0 {
            e.client_id = ca.user.client_id();
        }
        for field in [&mut e.user_name, &mut e.email_id, &mut e.phone_number] {
            if blank(field) {
                *field = Some(PLACEHOLDER.into());
            }
        }
        if self.caller_manages_client(ca, e.client_id).await? {
            // `checkCreateSubOrg`.
            if Self::same_client_non_owner(ca, e.client_id) {
                if let Some(r) = e.reporting_to {
                    if !self.db.is_user_in_sub_org(e.client_id, ca.user.id(), r).await? {
                        return Err(refuse(StatusCode::BAD_REQUEST, "user_reporting_error", &[]));
                    }
                }
            }
        } else {
            // `validateCreateDesignationAndReporting`: a refusal names the bad field, else 403.
            let designation_ok = match e.designation_id {
                None => true,
                Some(d) => self.db.designation_in_client(e.client_id, d).await?,
            };
            let reporting_ok = match e.reporting_to {
                None => true,
                Some(r) => self.db.can_report_to(e.client_id, Some(r), None).await?,
            };
            if !designation_ok {
                return Err(refuse(StatusCode::BAD_REQUEST, "user_designation_mismatch", &[]));
            }
            if !reporting_ok {
                return Err(refuse(StatusCode::BAD_REQUEST, "user_reporting_error", &[]));
            }
            return Err(refused());
        }
        if [&e.user_name, &e.email_id, &e.phone_number].iter().all(|v| v.as_deref().is_none_or(|s| s == PLACEHOLDER)) {
            return Err(forbidden("user_identification_not_found", &[]));
        }
        // `checkBusinessClientUser`: an individual's client takes no users this way (its answer is
        // otherwise unused).
        match self.dir().type_code_level(e.client_id).await? {
            Some(t) if t.0 != "INDV" => {}
            _ => return Err(refused()),
        }
        self.url_app_user_check(ca, e.client_id, (e.user_name.as_deref(), e.email_id.as_deref(), e.phone_number.as_deref()), None).await?;
        let id = self.db.entity_insert(&USER, &user_values(&e)).await?;
        let created = self.user_dao_read(id).await?;
        let label = describe(&created).unwrap_or_else(|| "null".into());
        sox(&self.db, Some(created.id), object::USER, action::CREATE, format!("{USER_CREATED_PREFIX}{label}"), None);
        activity(&self.db, Some(created.client_id), "User Create".into(), format!("{USER_CREATED_PREFIX}{label}"), None);
        self.evict_owner_cache(created.client_id, Some(ca.user.id())).await;
        self.evict_owner_cache(created.client_id, created.reporting_to).await;
        Ok(created)
    }

    /// `UserService.update(User)`.
    pub async fn user_update(&self, ca: &ContextAuth, e: &User) -> AuthResult<User> {
        let refused = || forbidden("forbidden_update", &["user"]);
        let existing = self.user_dao_read(e.id).await?;
        if e.client_id == 0 {
            // `getClientTypeNCodeNClientLevel(null)`: the cache key cannot be made.
            return Err(AuthError::internal("Cannot invoke \"Object.toString()\" because \"args[0]\" is null"));
        }
        let Some(client_type) = self.dir().type_code_level(e.client_id).await? else { return Err(refused()) };
        let same_ids = existing.user_name() == e.user_name() && existing.email_id() == e.email_id() && existing.phone_number() == e.phone_number();
        // The stored (raw) identifiers against the edit's, as `Objects.equals` on the getters.
        let user_exists = if same_ids {
            false
        } else {
            match client_type.0.as_str() {
                "INDV" => match self.dir().hierarchy(e.client_id).await?.level0 {
                    Some(m) => {
                        self.db.user_exists_under(m, e.user_name().as_deref(), e.email_id().as_deref(), e.phone_number().as_deref(), Some("INDV"), Some(e.id)).await?
                    }
                    None => return Err(refused()),
                },
                "BUS" | "SYS" => {
                    let changed = |a: Option<String>, b: Option<String>| if a == b { None } else { b };
                    let (un, em, ph) = (
                        changed(existing.user_name(), e.user_name()),
                        changed(existing.email_id(), e.email_id()),
                        changed(existing.phone_number(), e.phone_number()),
                    );
                    let others = self.db.users_with_any_identity(e.client_id, un.as_deref(), em.as_deref(), ph.as_deref(), Some(e.id)).await?;
                    if let Some(other) = others.first() {
                        return Err(refuse(StatusCode::CONFLICT, "user_identity_taken", &[taken_identity(other, em.as_deref(), ph.as_deref())]));
                    }
                    false
                }
                _ => return Err(refused()),
            }
        };
        if user_exists {
            return Err(refused());
        }
        if !same_ids {
            self.url_app_user_check(ca, e.client_id, (e.user_name().as_deref(), e.email_id().as_deref(), e.phone_number().as_deref()), Some(e.id)).await?;
        }
        if !self.caller_manages_client(ca, e.client_id).await? || !self.sub_org_allows(ca, e.client_id, e.id).await? {
            return Err(refused());
        }
        let updated = self.user_store_update(ca, e).await?;
        self.evict_user(updated.id, updated.client_id).await?;
        if existing.reporting_to != updated.reporting_to {
            self.evict_manager_caches(updated.client_id, existing.reporting_to, updated.reporting_to).await;
        }
        Ok(updated)
    }

    /// `UserService.update(key, fields)`.
    pub async fn user_patch(&self, ca: &ContextAuth, key: u64, fields: &Map<String, Value>) -> AuthResult<User> {
        let refused = || forbidden("forbidden_update", &["user"]);
        let text_of = |k: &str| -> AuthResult<Option<String>> {
            match fields.get(k) {
                None => Ok(None),
                Some(Value::Null) => Err(AuthError::internal(
                    "Cannot invoke \"Object.toString()\" because the return value of \"java.util.Map.get(Object)\" is null",
                )),
                Some(Value::String(s)) => Ok(Some(s.clone())),
                Some(v) => Ok(Some(v.to_string())),
            }
        };
        let (un, em, ph) = (text_of("userName")?, text_of("emailId")?, text_of("phoneNumber")?);
        let Some(client_id) = self.db.user_client_id(key).await? else { return Err(refused()) };
        let Some(client_type) = self.dir().type_code_level(client_id).await? else { return Err(refused()) };
        let any = un.is_some() || em.is_some() || ph.is_some();
        if any {
            match client_type.0.as_str() {
                "INDV" => {
                    let Some(m) = self.dir().hierarchy(client_id).await?.level0 else { return Err(refused()) };
                    if self.db.user_exists_under(m, un.as_deref(), em.as_deref(), ph.as_deref(), Some("INDV"), Some(key)).await? {
                        return Err(refused());
                    }
                }
                "BUS" | "SYS" => {}
                _ => return Err(refused()),
            }
            if let Some(code) = ca.url_app_code.as_deref().filter(|c| !c.trim().is_empty()) {
                if let Some(app) = self.dir().app_by_code(code).await? {
                    let existing = self.user_dao_read(key).await?;
                    let eff = |v: &Option<String>, stored: &Option<String>| v.clone().or_else(|| stored.clone());
                    let (u2, e2, p2) = (eff(&un, &existing.user_name), eff(&em, &existing.email_id), eff(&ph, &existing.phone_number));
                    self.validate_user_check(ca, app.id, client_id, u2.as_deref(), e2.as_deref(), p2.as_deref(), Some(key)).await?;
                }
            }
        }
        if !self.caller_manages_client(ca, client_id).await? || !self.sub_org_allows(ca, client_id, key).await? {
            return Err(refused());
        }
        // `super.update(key, fields)`: the stored user patched, then `update(User)`, then its log.
        let mut u = self.user_read(ca, key).await?;
        patch_user(&mut u, fields)?;
        let updated = self.user_update(ca, &u).await?;
        entity_changed(&self.db, None, object::USER, action::UPDATE, updated.id, Some(updated.client_id), "User", describe(&updated).as_deref());
        self.evict_user(updated.id, updated.client_id).await?;
        Ok(updated)
    }

    /// `UserService.delete`: the user is marked `DELETED` through `update(User)`.
    pub async fn user_delete(&self, ca: &ContextAuth, id: u64) -> AuthResult<()> {
        pre_authorize(ca, &["Authorities.User_DELETE"])?;
        let refused = || forbidden("forbidden_update", &["user"]);
        let mut u = self.user_read(ca, id).await?;
        if !self.caller_manages_client(ca, u.client_id).await? || !self.sub_org_allows(ca, u.client_id, id).await? {
            return Err(refused());
        }
        u.status_code = "DELETED".into();
        let updated = self.user_update(ca, &u).await?;
        self.evict_user(updated.id, updated.client_id).await
    }

    /// `UserService.readPageFilter`: a non-Owner member of the caller's own client sees their
    /// sub-organisation (and its managed clients; the whole client too with `Client_MANAGE`).
    pub async fn user_page(&self, ca: &ContextAuth, page: &Pageable, cond: Option<&Cond>, fill: &UserFill) -> AuthResult<Value> {
        pre_authorize(ca, &["Authorities.User_READ"])?;
        let own = ca.user.client_id();
        if !Self::same_client_non_owner(ca, own) {
            return self.users_page(ca, page, cond, fill).await;
        }
        let sub_org = self.current_user_sub_org(ca).await?;
        let managed: Vec<u64> = self.db.client_ids_of_managers(&sub_org).await?.into_iter().filter(|c| *c != own).collect();
        let ids_in = crate::internal::clients::ids_in;
        let any = |conditions: Vec<Cond>| Cond::Complex { and: false, conditions, negate: false };
        let sub_cond = ids_in("id", &sub_org);
        let visible = if has_any(ca, &[CLIENT_MANAGE_ROLE]) {
            let own_cond = Cond::Filter(Filter::eq("clientId", own.to_string()));
            let mut parts = vec![own_cond, sub_cond];
            if !managed.is_empty() {
                parts.push(ids_in("clientId", &managed));
            }
            any(parts)
        } else if managed.is_empty() {
            sub_cond
        } else {
            any(vec![sub_cond, ids_in("clientId", &managed)])
        };
        let merged = match cond {
            Some(c) => Cond::and(vec![visible, c.clone()]),
            None => visible,
        };
        self.users_page(ca, page, Some(&merged), fill).await
    }

    /// `getCurrentUserSubOrg`.
    pub async fn current_user_sub_org(&self, ca: &ContextAuth) -> AuthResult<Vec<u64>> {
        let (client, user) = (ca.user.client_id(), ca.user.id());
        if has_authority(Some(OWNER_ROLE), &crate::internal::scope::authorities(ca)) {
            let db = self.db.clone();
            let dir = self.dir().clone();
            let ids = self
                .caches()
                .id_lists
                .get_or_load(caches::USER_SUB_ORG, format!("{client}:owner"), || async move {
                    let Some(t) = dir.type_code_level(client).await? else { return Ok::<_, AuthError>(Some(Arc::new(vec![]))) };
                    Ok(Some(Arc::new(db.user_ids_of_client(client, t.0 == "SYS").await?)))
                })
                .await?;
            return Ok(ids.map(|i| (*i).clone()).unwrap_or_default());
        }
        Ok(self.org_structure(client).await?.sub_org(user, true))
    }

    /// `makeUserActive` / `makeUserInActive`.
    pub async fn user_set_active(&self, ca: &ContextAuth, user_id: Option<u64>, active: bool) -> AuthResult<bool> {
        pre_authorize(ca, &["Authorities.User_UPDATE"])?;
        let refused = || forbidden("active_inactive_error", &["user"]);
        let id = user_id.unwrap_or(ca.user.id());
        let Some(u) = self.dir().user(id).await? else { return Err(refused()) };
        if !ca.is_system_client() && !self.caller_manages_client(ca, u.client_id).await? {
            return Err(refused());
        }
        let target = if active { "ACTIVE" } else { "INACTIVE" };
        let done = if u.status_code == target {
            true
        } else {
            if !self.sub_org_allows(ca, u.client_id, u.id).await? {
                return Err(refused());
            }
            let mut e = (*u).clone();
            e.status_code = target.into();
            self.user_store_update(ca, &e).await?;
            true
        };
        self.evict_user(u.id, u.client_id).await?;
        Ok(done)
    }

    /// `unblockUser`: the user unlocked and their counters reset.
    pub async fn user_unblock(&self, ca: &ContextAuth, user_id: Option<u64>) -> AuthResult<bool> {
        pre_authorize(ca, &["Authorities.User_UPDATE"])?;
        let refused = || forbidden("active_inactive_error", &["user"]);
        let id = user_id.unwrap_or(ca.user.id());
        if !ca.is_system_client() {
            let u = self.user_dao_read(id).await?;
            if !self.caller_manages_client(ca, u.client_id).await? {
                return Err(refused());
            }
        }
        let u = self.user_dao_read(id).await?;
        if !self.sub_org_allows(ca, u.client_id, id).await? {
            return Err(refused());
        }
        self.db.user_status_to_active(id).await
    }

    /// `updateDesignation`.
    pub async fn user_set_designation(&self, ca: &ContextAuth, user_id: u64, designation_id: u64) -> AuthResult<User> {
        pre_authorize(ca, &["Authorities.User_UPDATE"])?;
        let refused = || forbidden("forbidden_update", &["user designation"]);
        let u = self.user_dao_read(user_id).await?;
        if !ca.is_system_client() && !self.caller_manages_client(ca, u.client_id).await? {
            return Err(refused());
        }
        if !self.db.designation_in_client(u.client_id, designation_id).await? {
            return Err(refuse(StatusCode::BAD_REQUEST, "user_designation_mismatch", &[]));
        }
        if !self.sub_org_allows(ca, u.client_id, user_id).await? {
            return Err(refused());
        }
        let mut e = u.clone();
        e.designation_id = Some(designation_id);
        let updated = self.user_store_update(ca, &e).await?;
        self.evict_user(updated.id, updated.client_id).await?;
        Ok(updated)
    }

    /// `UserSubOrganizationService.updateManager`: `None` clears the manager.
    pub async fn user_set_manager(&self, ca: &ContextAuth, user_id: u64, manager: Option<u64>) -> AuthResult<User> {
        pre_authorize(ca, &["Authorities.User_UPDATE"])?;
        let u = self.user_dao_read(user_id).await?;
        if u.reporting_to == manager {
            return Ok(u);
        }
        let refused = || forbidden("forbidden_update", &["user reporting manager"]);
        if !ca.is_system_client() && !self.caller_manages_client(ca, u.client_id).await? {
            return Err(refused());
        }
        let can = match manager {
            None => true,
            Some(_) => self.db.can_report_to(u.client_id, manager, Some(u.id)).await?,
        };
        if !can {
            return Err(refuse(StatusCode::BAD_REQUEST, "user_reporting_error", &[]));
        }
        let old = u.reporting_to;
        // `UserSubOrganizationService.updatableEntity`: only the manager changes.
        let mut stored = self.user_read(ca, u.id).await?;
        stored.reporting_to = manager;
        stored.updated_by = Some(ca.user.id());
        stored.updated_at = None;
        self.db.entity_update(&USER, stored.id, &user_values(&stored)).await?;
        let updated = self.user_dao_read(stored.id).await?;
        entity_changed(&self.db, None, object::USER, action::UPDATE, updated.id, Some(updated.client_id), "User", describe(&updated).as_deref());
        self.evict_manager_caches(updated.client_id, old, manager).await;
        self.evict_tokens(updated.id).await?;
        Ok(updated)
    }

    /// `removeRoleFromUser`.
    pub async fn user_remove_role(&self, ca: &ContextAuth, user_id: u64, role_id: u64) -> AuthResult<bool> {
        pre_authorize_all(ca, &["Authorities.User_UPDATE", "Authorities.Role_READ"])?;
        let refused = || forbidden("role_remove_error", &[&role_id.to_string(), &user_id.to_string()]);
        let u = self.user_dao_read(user_id).await?;
        if !ca.is_system_client() && !self.caller_manages_client(ca, u.client_id).await? {
            return Err(refused());
        }
        if !self.sub_org_allows(ca, u.client_id, user_id).await? {
            return Err(refused());
        }
        let role = self.role_read_checked(ca, role_id).await?;
        let removed = self.db.remove_role_for_user(user_id, role_id).await? > 0;
        if removed {
            assignment(&self.db, None, object::USER, false, user_id, Some(u.client_id), format!("{UNASSIGNED_ROLE}: {}", role.name.unwrap_or_else(|| "null".into())));
        }
        self.evict_user(user_id, u.client_id).await?;
        self.caches().service.evict_everywhere(caches::USER_ROLES, &user_id.to_string()).await;
        Ok(removed)
    }

    /// `assignRoleToUser`.
    pub async fn user_assign_role(&self, ca: &ContextAuth, user_id: u64, role_id: u64) -> AuthResult<bool> {
        pre_authorize_all(ca, &["Authorities.User_UPDATE", "Authorities.Role_READ"])?;
        if self.db.role_assigned_for_user(user_id, role_id).await? {
            return Ok(true);
        }
        let refused = || forbidden("role_forbidden_for_selected_user", &[&role_id.to_string(), &user_id.to_string()]);
        let u = self.user_dao_read(user_id).await?;
        if !ca.is_system_client() && !self.caller_manages_client(ca, u.client_id).await? {
            return Err(refused());
        }
        if !self.user_has_access_to_roles(ca, u.client_id, &[role_id]).await? {
            return Err(refused());
        }
        if !self.sub_org_allows(ca, u.client_id, user_id).await? {
            return Err(refused());
        }
        let role = self.role_read_checked(ca, role_id).await?;
        let added = self.db.add_role_to_user(user_id, role_id).await?;
        if added {
            assignment(&self.db, None, object::USER, true, user_id, Some(u.client_id), format!("{ASSIGNED_ROLE}{}", role.name.unwrap_or_else(|| "null".into())));
        }
        self.evict_user(user_id, u.client_id).await?;
        self.caches().service.evict_everywhere(caches::USER_ROLES, &user_id.to_string()).await;
        Ok(added)
    }

    /// `assignProfileToUser`.
    pub async fn user_assign_profile(&self, ca: &ContextAuth, user_id: u64, profile_id: u64) -> AuthResult<bool> {
        pre_authorize_all(ca, &["Authorities.User_UPDATE", "Authorities.Profile_READ"])?;
        let refused = || forbidden("profile_forbidden_for_selected_user", &[&profile_id.to_string(), &user_id.to_string()]);
        let u = self.user_dao_read(user_id).await?;
        if !self.caller_manages_client(ca, u.client_id).await? {
            return Err(refused());
        }
        if !self.has_access_to_profiles(u.client_id, &[profile_id]).await? {
            return Err(refused());
        }
        if !self.sub_org_allows(ca, u.client_id, user_id).await? {
            return Err(refused());
        }
        let Some(profile) = self.db.profile(profile_id).await? else { return Err(refused()) };
        let Some(n) = self.db.add_profile_to_user(user_id, profile_id).await? else { return Err(refused()) };
        let assigned = n != 0;
        if assigned {
            activity(
                &self.db,
                Some(u.client_id),
                "Profile Assign".into(),
                format!("Profile '{}' assigned to user: {}", profile.name.unwrap_or_else(|| "null".into()), describe(&u).unwrap_or_else(|| "null".into())),
                None,
            );
        }
        self.evict_user(user_id, u.client_id).await?;
        Ok(assigned)
    }

    /// `removeProfileFromUser`.
    pub async fn user_remove_profile(&self, ca: &ContextAuth, user_id: u64, profile_id: u64) -> AuthResult<bool> {
        pre_authorize_all(ca, &["Authorities.User_UPDATE", "Authorities.Profile_READ"])?;
        let refused = || forbidden("profile_forbidden_for_selected_user", &[&profile_id.to_string(), &user_id.to_string()]);
        let u = self.user_dao_read(user_id).await?;
        if !self.caller_manages_client(ca, u.client_id).await? {
            return Err(refused());
        }
        if !self.sub_org_allows(ca, u.client_id, user_id).await? {
            return Err(refused());
        }
        let Some(profile) = self.db.profile(profile_id).await? else { return Err(refused()) };
        let removed = self.db.remove_profile_for_user(user_id, profile_id).await? != 0;
        if removed {
            activity(
                &self.db,
                Some(u.client_id),
                "Profile Unassign".into(),
                format!("Profile '{}' removed from user: {}", profile.name.unwrap_or_else(|| "null".into()), describe(&u).unwrap_or_else(|| "null".into())),
                None,
            );
        }
        self.evict_user(user_id, u.client_id).await?;
        Ok(removed)
    }

    /// `checkUserExistsAcrossApps`.
    pub async fn user_exists(&self, ca: &ContextAuth, user_name: Option<&str>, email: Option<&str>, phone: Option<&str>) -> AuthResult<bool> {
        if user_name.is_none() && email.is_none() && phone.is_none() {
            return Err(refuse(StatusCode::BAD_REQUEST, "user_designation_mismatch", &[]));
        }
        let from = ca.logged_in_from_client_id.unwrap_or_default();
        self.db.user_exists_under(from, user_name, email, phone, None, None).await
    }

    /// `getMembers`.
    pub async fn members(&self, ca: &ContextAuth, search: Option<&str>, include_inactive: bool, page: i64, size: i64) -> AuthResult<Vec<Value>> {
        let size = if size <= 0 { MEMBERS_DEFAULT_SIZE } else { size.min(MEMBERS_MAX_SIZE) };
        let offset = page.max(0) * size;
        if !ca.authenticated {
            return Err(forbidden("login_required", &[]));
        }
        let rows = self.db.members(ca.user.client_id(), include_inactive, search, offset, size).await?;
        Ok(rows.into_iter().map(|(id, f, l, u, st)| member_json(id, f, l, u, st, ca.client_code.clone())).collect())
    }
}

macro_rules! r {
    ($name:ident, $path:expr, |$s:ident, $r:ident, $ca:ident| $body:block) => {
        $crate::web_route!($name, AdminState, $path, true, |$s, $r, $ca| $body);
    };
}

macro_rules! rp {
    ($name:ident, $path:expr, |$s:ident, $r:ident, $ca:ident, $p:ident| $body:block) => {
        $crate::web_route_path!($name, AdminState, $path, true, |$s, $r, $ca, $p| $body);
    };
}

macro_rules! rp2 {
    ($name:ident, $path:expr, |$s:ident, $r:ident, $ca:ident, $p:ident, $q:ident| $body:block) => {
        $crate::web_route_path2!($name, AdminState, $path, true, |$s, $r, $ca, $p, $q| $body);
    };
}

/// Spring's `StringToBooleanConverter` for a `boolean` request parameter.
fn spring_bool(v: &str) -> Option<bool> {
    match v.trim().to_lowercase().as_str() {
        "true" | "on" | "yes" | "1" => Some(true),
        "false" | "off" | "no" | "0" | "" => Some(false),
        _ => None,
    }
}

fn user_out(u: &User) -> Value {
    user_json(u, &UserExtras::default())
}

fn bool_out(b: bool) -> axum::response::Response {
    json(&Value::Bool(b))
}

r!(list, "/users", |s, r, ca| {
    let page = Pageable::from_params(&r.params);
    let cond = from_params(&r.params.0);
    Ok(json(&s.user_page(&ca, &page, cond.as_ref(), &UserFill::from_params(&r.params)).await?))
});

r!(query, "/users/query", |s, r, ca| {
    let (page, cond) = query_body(&r.body)?;
    Ok(json(&s.user_page(&ca, &page, cond.as_ref(), &UserFill::from_params(&r.params)).await?))
});

r!(no_mapping, "/users/noMapping", |s, r, ca| { Ok(crate::jackson::empty(StatusCode::BAD_REQUEST)) });

r!(create, "/users", |s, r, ca| {
    let body = user_from_body(&object_body(&r.body)?)?;
    Ok(json(&user_out(&s.user_create(&ca, body).await?)))
});

rp!(read, "/users/{id}", |s, r, ca, id| {
    let id = to_u64(&id)?;
    Ok(json(&user_out(&s.user_read_managed(&ca, id).await?)))
});

rp!(update, "/users/{id}", |s, r, ca, id| {
    let id = to_u64(&id)?;
    let mut body = user_from_body(&object_body(&r.body)?)?;
    body.id = id;
    Ok(json(&user_out(&s.user_update(&ca, &body).await?)))
});

rp!(patch_one, "/users/{id}", |s, r, ca, id| {
    let id = to_u64(&id)?;
    let body = object_body(&r.body)?;
    Ok(json(&user_out(&s.user_patch(&ca, id, &body).await?)))
});

rp!(remove, "/users/{id}", |s, r, ca, id| {
    let id = to_u64(&id)?;
    s.user_delete(&ca, id).await?;
    Ok(crate::web::no_content_json())
});

r!(make_active, "/users/makeUserActive", |s, r, ca| {
    let id = opt_u64(&r.params, "userId")?;
    Ok(bool_out(s.user_set_active(&ca, id, true).await?))
});

r!(make_inactive, "/users/makeUserInActive", |s, r, ca| {
    let id = opt_u64(&r.params, "userId")?;
    Ok(bool_out(s.user_set_active(&ca, id, false).await?))
});

r!(unblock, "/users/unblockUser", |s, r, ca| {
    let id = opt_u64(&r.params, "userId")?;
    Ok(bool_out(s.user_unblock(&ca, id).await?))
});

r!(exists, "/users/exists", |s, r, ca| {
    let p = &r.params;
    Ok(bool_out(s.user_exists(&ca, p.get("username"), p.get("email"), p.get("phoneNumber")).await?))
});

r!(members, "/users/members", |s, r, ca| {
    let p = &r.params;
    let int = |k: &str, d: i64| -> AuthResult<i64> {
        match p.get(k) {
            None => Ok(d),
            Some(v) => v.trim().parse::<i32>().map(i64::from).map_err(|_| crate::web::type_mismatch()),
        }
    };
    let include = match p.get("includeInactive") {
        None => false,
        Some(v) => spring_bool(v).ok_or_else(crate::web::type_mismatch)?,
    };
    let (page, size) = (int("page", 0)?, int("size", MEMBERS_DEFAULT_SIZE)?);
    if !ca.authenticated {
        return Err(AuthError::denied(&ca, &[crate::authorities::LOGGED_IN]));
    }
    Ok(json(&Value::Array(s.members(&ca, p.get("q"), include, page, size).await?)))
});

r!(sub_org, "/users/sub-org", |s, r, ca| {
    Ok(json(&Value::from(s.current_user_sub_org(&ca).await?)))
});

rp2!(set_designation, "/users/{userId}/designation/{designationId}", |s, r, ca, u, d| {
    let (u, d) = (to_u64(&u)?, to_u64(&d)?);
    Ok(json(&user_out(&s.user_set_designation(&ca, u, d).await?)))
});

rp2!(set_manager, "/users/{userId}/reportingManager/{managerId}", |s, r, ca, u, m| {
    let (u, m) = (to_u64(&u)?, to_u64(&m)?);
    Ok(json(&user_out(&s.user_set_manager(&ca, u, Some(m)).await?)))
});

rp!(clear_manager, "/users/{userId}/reportingManager", |s, r, ca, u| {
    let u = to_u64(&u)?;
    Ok(json(&user_out(&s.user_set_manager(&ca, u, None).await?)))
});

rp2!(assign_role, "/users/{userId}/assignRole/{roleId}", |s, r, ca, u, x| {
    let (u, x) = (to_u64(&u)?, to_u64(&x)?);
    Ok(bool_out(s.user_assign_role(&ca, u, x).await?))
});

rp2!(remove_role, "/users/{userId}/removeRole/{roleId}", |s, r, ca, u, x| {
    let (u, x) = (to_u64(&u)?, to_u64(&x)?);
    Ok(bool_out(s.user_remove_role(&ca, u, x).await?))
});

rp2!(assign_profile, "/users/{userId}/assignProfile/{profileId}", |s, r, ca, u, x| {
    let (u, x) = (to_u64(&u)?, to_u64(&x)?);
    Ok(bool_out(s.user_assign_profile(&ca, u, x).await?))
});

rp2!(remove_profile, "/users/{userId}/removeProfile/{profileId}", |s, r, ca, u, x| {
    let (u, x) = (to_u64(&u)?, to_u64(&x)?);
    Ok(bool_out(s.user_remove_profile(&ca, u, x).await?))
});

rp2!(assigned_profiles, "/users/{userId}/app/{appId}/assignedProfiles", |s, r, ca, u, a| {
    let (u, a) = (to_u64(&u)?, to_u64(&a)?);
    let list = s.assigned_profiles(&ca, u, Some(a), true).await?;
    Ok(json(&Value::Array(list.iter().map(|p| p.to_json()).collect())))
});

pub fn router() -> Router<AdminState> {
    Router::new()
        .route("/api/security/users", get(list).post(create))
        .route("/api/security/users/query", post(query))
        .route("/api/security/users/noMapping", post(no_mapping))
        .route("/api/security/users/makeUserActive", patch(make_active))
        .route("/api/security/users/makeUserInActive", patch(make_inactive))
        .route("/api/security/users/unblockUser", post(unblock))
        .route("/api/security/users/exists", get(exists))
        .route("/api/security/users/members", get(members))
        .route("/api/security/users/sub-org", get(sub_org))
        .route("/api/security/users/{id}", get(read).put(update).patch(patch_one).delete(remove))
        .route("/api/security/users/{userId}/designation/{designationId}", put(set_designation))
        .route("/api/security/users/{userId}/reportingManager/{managerId}", put(set_manager))
        .route("/api/security/users/{userId}/reportingManager", axum::routing::delete(clear_manager))
        .route("/api/security/users/{userId}/assignRole/{roleId}", get(assign_role))
        .route("/api/security/users/{userId}/removeRole/{roleId}", get(remove_role))
        .route("/api/security/users/{userId}/assignProfile/{profileId}", get(assign_profile))
        .route("/api/security/users/{userId}/removeProfile/{profileId}", get(remove_profile))
        .route("/api/security/users/{userId}/app/{appId}/assignedProfiles", get(assigned_profiles))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn bodies_patches_and_members() {
        let u = user_from_body(json!({"clientId": 4, "userName": "a", "password": "x", "statusCode": "ACTIVE", "noFailedAttempt": 2}).as_object().unwrap()).unwrap();
        assert_eq!((u.client_id, u.user_name.as_deref(), u.password.as_deref(), u.status_code.as_str(), u.no_failed_attempt), (4, Some("a"), None, "ACTIVE", Some(2)));
        assert!(user_from_body(json!({"statusCode": "GONE"}).as_object().unwrap()).is_err());
        assert!(user_from_body(json!({"noFailedAttempt": 70000}).as_object().unwrap()).is_err());
        assert!(user_from_body(json!({"profiles": 1}).as_object().unwrap()).is_err());
        let mut p = u.clone();
        patch_user(&mut p, json!({"firstName": "F", "statusCode": "INACTIVE", "id": 5}).as_object().unwrap()).unwrap();
        assert_eq!((p.first_name.as_deref(), p.status_code.as_str(), p.id), (Some("F"), "INACTIVE", 0));
        assert_eq!(patch_user(&mut p, json!({"reportingTo": "x"}).as_object().unwrap()).unwrap_err().status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(patch_user(&mut p, json!({"firstName": [1]}).as_object().unwrap()).unwrap_err().status(), StatusCode::BAD_REQUEST);
        let m = member_json(7, Some(" A ".into()), None, Some("x@y".into()), Some("ACTIVE".into()), Some("FIN".into()));
        assert_eq!(m, json!({"id": 7, "firstName": "A", "name": "A", "statusCode": "ACTIVE", "clientCode": "FIN"}));
        assert_eq!(member_json(8, None, None, Some("NONE".into()), None, None)["name"], "User 8");
        let other = User { email_id: Some("A@B".into()), ..Default::default() };
        assert_eq!(taken_identity(&other, Some("a@b"), None), "email");
        assert_eq!(taken_identity(&other, None, Some("1")), "user name");
        let mut e = User { id: 3, status_code: "ACTIVE".into(), ..Default::default() };
        let ca = ContextAuth { user: crate::model::ContextUser { id: Some(3), ..Default::default() }, ..Default::default() };
        apply_updatable_fields(&mut e, &User { first_name: Some("N".into()), status_code: "INACTIVE".into(), ..Default::default() }, &ca);
        assert_eq!((e.first_name.as_deref(), e.status_code.as_str()), (Some("N"), "ACTIVE"));
        assert_eq!(describe(&User { user_name: Some("u".into()), email_id: Some("NONE".into()), ..Default::default() }).as_deref(), Some("u"));
    }

    #[test]
    fn jackson_conversions_and_patch_setters() {
        let o = |v: serde_json::Value| v.as_object().unwrap().clone();
        assert_eq!(status_value(Some(&json!(1))), Ok(Some("INACTIVE".into())));
        assert_eq!(status_value(Some(&json!(9))), Err(()));
        assert_eq!(status_value(Some(&json!(true))), Err(()));
        assert_eq!(status_value(Some(&json!(null))), Ok(None));
        assert_eq!(short_value(Some(&json!("12"))), Ok(Some(12)));
        assert_eq!(short_value(Some(&json!(-40000))), Err(()));
        assert!(user_from_body(&o(json!({"client": 1}))).is_err());
        assert!(user_from_body(&o(json!({"clientCode": [1]}))).is_err());
        assert!(user_from_body(&o(json!({"noOtpResendAttempts": "x"}))).is_err());
        let mut u = User::default();
        for (k, v) in [
            ("clientCode", json!("C")),
            ("password", json!("p")),
            ("passwordHashed", json!(true)),
            ("accountNonLocked", json!(false)),
            ("noFailedAttempt", json!(3)),
            ("lockedUntil", json!(1700000000)),
            ("authorities", json!(["a"])),
            ("client", json!({"id": 1})),
            ("unknown", json!({"x": 1})),
        ] {
            patch_user(&mut u, &o(json!({ k: v }))).unwrap();
        }
        for (k, v) in [
            ("clientCode", json!([1])),
            ("pinHashed", json!("maybe")),
            ("noPinFailedAttempt", json!(99999)),
            ("lockedUntil", json!("never")),
            ("profiles", json!(3)),
            ("designation", json!(2)),
            ("statusCode", json!("GONE")),
        ] {
            assert_eq!(patch_user(&mut u, &o(json!({ k: v }))).unwrap_err().status(), StatusCode::BAD_REQUEST, "{k}");
        }
        patch_user(
            &mut u,
            &o(json!({"clientId": 4, "designationId": "5", "userName": "n", "emailId": "e", "phoneNumber": "p", "lastName": "l",
                "middleName": "m", "localeCode": "en", "timeZone": "UTC", "lockedDueTo": "x"})),
        )
        .unwrap();
        assert_eq!((u.client_id, u.designation_id, u.middle_name.as_deref(), u.locked_due_to.as_deref()), (4, Some(5), Some("m"), Some("x")));
        let other = User { phone_number: Some("+1".into()), ..Default::default() };
        assert_eq!(taken_identity(&other, Some("x@y"), Some("+1")), "phone number");
        // A caller with User_UPDATE editing themselves changes their status and line too.
        let mut e = User { id: 3, status_code: "ACTIVE".into(), ..Default::default() };
        let mut ca = ContextAuth { user: crate::model::ContextUser { id: Some(3), ..Default::default() }, ..Default::default() };
        ca.user.string_authorities = Some(vec!["Authorities.User_UPDATE".into()]);
        apply_updatable_fields(&mut e, &User { status_code: "INACTIVE".into(), reporting_to: Some(9), ..Default::default() }, &ca);
        assert_eq!((e.status_code.as_str(), e.reporting_to), ("INACTIVE", Some(9)));
        assert_eq!((spring_bool(" ON "), spring_bool(""), spring_bool("x")), (Some(true), Some(false), None));
    }

    #[test]
    fn user_check_levels_and_scopes() {
        let h = |l: [Option<u64>; 4]| ClientHierarchy { client_id: 50, level0: l[0], level1: l[1], level2: l[2], level3: l[3] };
        // The app's own client checks nothing.
        assert_eq!(user_check_scope("NO_DUPLICATE_USER_CLIENT", 50, 50, &h([None; 4])), None);
        // A client directly under the app's.
        let direct = h([Some(1), None, None, None]);
        assert_eq!(user_check_scope("NO_DUPLICATE_USER_CLIENT", 1, 50, &direct), Some((1, true, false)));
        assert_eq!(user_check_scope("NO_DUPLICATE_USER_CUSTOMER", 1, 50, &direct), None);
        // A customer (two levels down) and below.
        let customer = h([Some(7), Some(1), None, None]);
        assert_eq!(user_check_scope("NO_DUPLICATE_USER_CUSTOMER", 1, 50, &customer), Some((7, true, true)));
        assert_eq!(user_check_scope("NO_DUPLICATE_USER_CLIENT", 1, 50, &customer), None);
        let consumer = h([Some(8), Some(7), Some(1), None]);
        assert_eq!(user_check_scope("NO_DUPLICATE_USER_CUSTOMER", 1, 50, &consumer), Some((7, true, true)));
        assert_eq!(user_check_scope("NO_DUPLICATE_USER_CONSUMER", 1, 50, &consumer), Some((8, true, false)));
        let deeper = h([Some(9), Some(8), Some(7), Some(1)]);
        assert_eq!(user_check_scope("NO_DUPLICATE_USER_CUSTOMER", 1, 50, &deeper), Some((7, true, true)));
        assert_eq!(user_check_scope("NO_DUPLICATE_USER_CONSUMER", 1, 50, &deeper), Some((8, true, false)));
        // Not under the app's client at all.
        let elsewhere = h([Some(2), Some(3), None, None]);
        assert_eq!(user_check_scope("NO_DUPLICATE_USER_CUSTOMER", 1, 50, &elsewhere), None);
        assert_eq!(user_check_scope("NO_DUPLICATE_USER_CONSUMER", 1, 50, &elsewhere), None);
        assert_eq!(user_check_scope("SOMETHING_ELSE", 1, 50, &consumer), None);
    }

    #[test]
    fn reading_another_clients_user_follows_the_hierarchy() {
        let h = |client_id: u64, l: [Option<u64>; 4]| ClientHierarchy { client_id, level0: l[0], level1: l[1], level2: l[2], level3: l[3] };
        // SYSTEM 1, business 28 under it, partner 3570 under the business, its customer 4286,
        // and 3919, another business under SYSTEM.
        let business = h(28, [Some(1), None, None, None]);
        let partner = h(3570, [Some(28), Some(1), None, None]);
        let customer = h(4286, [Some(3570), Some(28), Some(1), None]);
        let other = h(3919, [Some(1), None, None, None]);
        let sibling = h(3571, [Some(28), Some(1), None, None]);
        // Same client.
        assert!(may_read_user_of(&partner, &partner));
        // A managed child client, and one further down: the caller need not be its client manager.
        assert!(may_read_user_of(&business, &partner));
        assert!(may_read_user_of(&business, &customer));
        assert!(may_read_user_of(&partner, &customer));
        // The caller's client's direct managing client.
        assert!(may_read_user_of(&partner, &business));
        assert!(may_read_user_of(&customer, &partner));
        // Not: an unrelated client, a sibling, a manager above the direct one.
        assert!(!may_read_user_of(&business, &other));
        assert!(!may_read_user_of(&other, &customer));
        assert!(!may_read_user_of(&partner, &sibling));
        assert!(!may_read_user_of(&customer, &business));
        // SYSTEM's users are not read upward by the businesses directly under it.
        let system = h(1, [None; 4]);
        assert!(!may_read_user_of(&business, &system));
        assert!(may_read_user_of(&system, &customer));
    }
}

#[cfg(test)]
mod live {
    use super::*;
    use crate::admin::users::testkit::{anonymous, fx, sys, NONE};
    use crate::dto::Role;
    use serde_json::json;

    const MEMBER: &[&str] = &[
        "Authorities.User_CREATE",
        "Authorities.User_READ",
        "Authorities.User_UPDATE",
        "Authorities.User_DELETE",
        "Authorities.Role_READ",
        "Authorities.Profile_READ",
    ];

    fn status(r: AuthResult<impl std::fmt::Debug>) -> (StatusCode, String) {
        let e = r.unwrap_err();
        (e.status(), e.to_string())
    }

    /// `UserServiceTest` / `UserSubOrganizationServiceTest`: every refusal and edit of the
    /// accounts service, on the scratch clients.
    #[tokio::test]
    async fn accounts_refusals_and_edits() {
        let Some(fx) = fx().await else { return };
        let (s, c, m, i) = (&fx.s, fx.c, fx.m, fx.i);
        let sys = sys();
        let owner = fx.user(c, "o").await;
        let a = fx.user(c, "a").await;
        let b = fx.user(c, "b").await;
        let d = fx.user(c, "d").await;
        let e = fx.user(m, "e").await;
        s.user_set_manager(&sys, b.id, Some(a.id)).await.unwrap();
        let member = fx.as_user(&a, "ZZRUL", MEMBER);
        let mut owner_ca = fx.as_user(&owner, "ZZRUL", MEMBER);
        owner_ca.user.string_authorities.as_mut().unwrap().push(OWNER_ROLE.into());
        let below = fx.as_user(&e, "ZZRUM", MEMBER);
        let email = |t: &str| format!("zzrl{}{t}@example.invalid", fx.run);

        // ---- create ----
        let refused_line = User { user_name: Some(format!("zzrl{}x1", fx.run)), reporting_to: Some(d.id), ..Default::default() };
        let r = status(s.user_create(&member, refused_line).await);
        assert_eq!(r.0, StatusCode::BAD_REQUEST, "the line is not the member's: {}", r.1);
        let mine = User { email_id: Some(email("x2")), reporting_to: Some(b.id), status_code: "ACTIVE".into(), ..Default::default() };
        let x2 = s.user_create(&member, mine).await.unwrap();
        assert_eq!((x2.client_id, x2.reporting_to, x2.user_name.as_deref()), (c, Some(b.id), Some(PLACEHOLDER)));
        let into_c = |designation: Option<u64>, reporting: Option<u64>| User {
            client_id: c,
            user_name: Some(format!("zzrl{}x3", fx.run)),
            designation_id: designation,
            reporting_to: reporting,
            ..Default::default()
        };
        let r = status(s.user_create(&below, into_c(Some(NONE), None)).await);
        assert_eq!(r.0, StatusCode::BAD_REQUEST, "{}", r.1);
        // `canReportTo` with no user to check answers true, so a line alone never refuses here.
        assert_eq!(status(s.user_create(&below, into_c(None, Some(NONE))).await).0, StatusCode::FORBIDDEN);
        assert_eq!(status(s.user_create(&below, into_c(None, None)).await).0, StatusCode::FORBIDDEN);
        assert_eq!(status(s.user_create(&sys, User { client_id: c, ..Default::default() }).await).0, StatusCode::FORBIDDEN);
        let indv = User { client_id: i, user_name: Some(format!("zzrl{}x4", fx.run)), ..Default::default() };
        assert_eq!(status(s.user_create(&sys, indv).await).0, StatusCode::FORBIDDEN, "an individual's client");
        // leadzump's USER_CHECK (NO_DUPLICATE_USER_CUSTOMER): ZZRUM is a customer of SYSTEM's app,
        // so its users' identities may not repeat among ZZRUL's clients.
        let mut on_leadzump = sys.clone();
        on_leadzump.url_app_code = Some("leadzump".into());
        let twin = User { client_id: m, user_name: Some(format!("zzrl{}x5", fx.run)), email_id: e.email_id.clone(), ..Default::default() };
        let (st, msg) = status(s.user_create(&on_leadzump, twin).await);
        assert_eq!(st, StatusCode::CONFLICT, "{msg}");
        let app = s.dir().app_by_code("leadzump").await.unwrap().unwrap();
        s.validate_user_check(&sys, app.id, m, None, e.email_id.as_deref(), None, Some(e.id)).await.unwrap();
        s.validate_user_check(&sys, app.id, c, None, e.email_id.as_deref(), None, None).await.unwrap();
        s.validate_user_check(&member, app.id, m, None, Some("nobody@example.invalid"), None, None).await.unwrap();

        // ---- update ----
        assert_eq!(status(s.user_update(&sys, &User { id: a.id, ..Default::default() }).await).0, StatusCode::INTERNAL_SERVER_ERROR);
        let mut renamed = a.clone();
        renamed.email_id = Some(email("a2"));
        let updated = s.user_update(&sys, &renamed).await.unwrap();
        assert_eq!(updated.email_id, Some(email("a2")));
        let mut moved = b.clone();
        moved.reporting_to = Some(owner.id);
        moved.email_id = Some(email("b2"));
        assert_eq!(status(s.user_update(&below, &moved).await).0, StatusCode::FORBIDDEN, "ZZRUM does not manage ZZRUL");
        assert_eq!(s.user_update(&sys, &moved).await.unwrap().reporting_to, Some(owner.id));
        s.user_set_manager(&sys, b.id, Some(a.id)).await.unwrap();
        // Users of an individual's client (made as registration makes them).
        let mk = |tag: &str| User {
            client_id: i,
            user_name: Some(format!("zzrl{}{tag}", fx.run)),
            email_id: Some(email(tag)),
            status_code: "ACTIVE".into(),
            ..Default::default()
        };
        let i1 = s.user_dao_read(s.db.entity_insert(&USER, &user_values(&mk("i1"))).await.unwrap()).await.unwrap();
        let i2 = s.user_dao_read(s.db.entity_insert(&USER, &user_values(&mk("i2"))).await.unwrap()).await.unwrap();
        // `checkUserExists` counts a user holding every identifier the edit gives.
        let mut clash = i2.clone();
        clash.user_name = i1.user_name.clone();
        clash.email_id = i1.email_id.clone();
        assert_eq!(status(s.user_update(&sys, &clash).await).0, StatusCode::FORBIDDEN, "the identity is held under the manager");
        let mut fine = i2.clone();
        fine.email_id = Some(email("i3"));
        assert_eq!(s.user_update(&sys, &fine).await.unwrap().email_id, Some(email("i3")));

        // ---- patch ----
        let o = |v: serde_json::Value| v.as_object().unwrap().clone();
        assert_eq!(status(s.user_patch(&sys, a.id, &o(json!({"userName": null}))).await).0, StatusCode::INTERNAL_SERVER_ERROR);
        let p = s.user_patch(&sys, a.id, &o(json!({"phoneNumber": 9100000001u64, "lastName": "P"}))).await.unwrap();
        assert_eq!(p.phone_number.as_deref(), Some("9100000001"));
        assert_eq!(status(s.user_patch(&sys, i2.id, &o(json!({"userName": i1.user_name, "emailId": i1.email_id}))).await).0, StatusCode::FORBIDDEN);
        s.user_patch(&sys, i2.id, &o(json!({"firstName": "I"}))).await.unwrap();
        assert_eq!(s.user_patch(&sys, i2.id, &o(json!({"emailId": email("i4")}))).await.unwrap().email_id, Some(email("i4")));
        assert_eq!(status(s.user_patch(&on_leadzump, NONE, &o(json!({"lastName": "x"}))).await).0, StatusCode::FORBIDDEN);
        // Its own identity passes the app's check.
        s.user_patch(&on_leadzump, e.id, &o(json!({"userName": format!("zzrl{}e", fx.run), "emailId": e.email_id}))).await.unwrap();
        assert_eq!(status(s.user_patch(&below, a.id, &o(json!({"lastName": "x"}))).await).0, StatusCode::FORBIDDEN);
        assert_eq!(status(s.user_patch(&member, d.id, &o(json!({"lastName": "x"}))).await).0, StatusCode::FORBIDDEN, "not in the member's line");

        // ---- delete ----
        assert_eq!(status(s.user_delete(&below, d.id).await).0, StatusCode::FORBIDDEN);

        // ---- the member's page and sub-organisation ----
        let page = Pageable::from_params(&crate::spring::Params::default());
        let fill = UserFill::default();
        let only = |id: u64| Cond::Filter(Filter::eq("id", id.to_string()));
        let total = |v: &Value| v["totalElements"].as_i64().unwrap();
        let seen = s.user_page(&member, &page, None, &fill).await.unwrap();
        let ids: Vec<u64> = seen["content"].as_array().unwrap().iter().filter_map(|u| u["id"].as_u64()).collect();
        assert!(ids.contains(&a.id) && ids.contains(&b.id), "{ids:?}");
        assert_eq!(total(&s.user_page(&member, &page, Some(&only(d.id)), &fill).await.unwrap()), 0, "not in the member's line");
        s.client_manager_create(&sys, a.id, m).await.unwrap();
        let with_managed = s.user_page(&member, &page, Some(&Cond::Filter(Filter::eq("id", e.id.to_string()))), &fill).await.unwrap();
        assert_eq!(with_managed["content"][0]["id"], e.id, "a user of the client the member manages");
        let mut manage = member.clone();
        manage.user.string_authorities.as_mut().unwrap().push(CLIENT_MANAGE_ROLE.into());
        assert_eq!(total(&s.user_page(&manage, &page, Some(&only(d.id)), &fill).await.unwrap()), 1, "Client_MANAGE sees the whole client");
        s.client_manager_delete(&sys, a.id, m).await.unwrap();
        let mut manage_alone = fx.as_user(&d, "ZZRUL", MEMBER);
        manage_alone.user.string_authorities.as_mut().unwrap().push(CLIENT_MANAGE_ROLE.into());
        s.user_page(&manage_alone, &page, None, &fill).await.unwrap();
        let sub = s.current_user_sub_org(&member).await.unwrap();
        assert!(sub.contains(&a.id) && sub.contains(&b.id) && !sub.contains(&d.id), "{sub:?}");

        // ---- status, unblock, designation, manager ----
        assert_eq!(status(s.user_set_active(&sys, Some(NONE), true).await).0, StatusCode::FORBIDDEN);
        assert_eq!(status(s.user_set_active(&below, Some(a.id), false).await).0, StatusCode::FORBIDDEN);
        assert!(s.user_set_active(&member, Some(a.id), true).await.unwrap(), "already active");
        assert_eq!(status(s.user_set_active(&member, Some(d.id), false).await).0, StatusCode::FORBIDDEN);
        assert!(s.user_set_active(&member, None, false).await.unwrap());
        assert!(s.user_set_active(&sys, Some(a.id), true).await.unwrap());
        assert_eq!(status(s.user_unblock(&below, Some(a.id)).await).0, StatusCode::FORBIDDEN);
        assert_eq!(status(s.user_unblock(&member, Some(d.id)).await).0, StatusCode::FORBIDDEN);
        assert!(s.user_unblock(&member, Some(b.id)).await.unwrap());
        let (st, des) = fx.http("POST", "/designations", Some(json!({"clientId": c, "name": format!("zz des {}", fx.run)}))).await;
        assert_eq!(st, StatusCode::OK, "{des}");
        let des = des["id"].as_u64().unwrap();
        assert_eq!(status(s.user_set_designation(&below, b.id, des).await).0, StatusCode::FORBIDDEN);
        assert_eq!(status(s.user_set_designation(&member, d.id, des).await).0, StatusCode::FORBIDDEN);
        assert_eq!(s.user_set_designation(&member, b.id, des).await.unwrap().designation_id, Some(des));
        assert_eq!(s.user_set_manager(&sys, b.id, Some(a.id)).await.unwrap().reporting_to, Some(a.id), "unchanged");
        assert_eq!(status(s.user_set_manager(&below, b.id, None).await).0, StatusCode::FORBIDDEN);

        // ---- roles and profiles ----
        let role = s.role_create(&sys, Role { client_id: Some(c), name: Some(format!("zz role {}", fx.run)), ..Default::default() }).await.unwrap();
        assert_eq!(status(s.user_assign_role(&below, b.id, role.id).await).0, StatusCode::FORBIDDEN);
        assert_eq!(status(s.user_assign_role(&member, d.id, role.id).await).0, StatusCode::FORBIDDEN);
        assert!(s.user_assign_role(&owner_ca, b.id, role.id).await.unwrap());
        assert!(s.user_assign_role(&owner_ca, b.id, role.id).await.unwrap(), "already there");
        assert_eq!(status(s.user_remove_role(&below, b.id, role.id).await).0, StatusCode::FORBIDDEN);
        assert_eq!(status(s.user_remove_role(&member, d.id, role.id).await).0, StatusCode::FORBIDDEN);
        assert!(s.user_remove_role(&owner_ca, b.id, role.id).await.unwrap());
        assert!(!s.user_remove_role(&owner_ca, b.id, role.id).await.unwrap());
        let body = json!({"appId": 2, "clientId": c, "name": format!("zz prof {}", fx.run), "arrangement": {"k": {"roleId": 70}}});
        let prof = s.profile_create(&sys, super::super::profiles::profile_from_body(body.as_object().unwrap()).unwrap()).await.unwrap();
        let pid = prof.id.unwrap();
        assert_eq!(status(s.user_assign_profile(&below, b.id, pid).await).0, StatusCode::FORBIDDEN);
        assert_eq!(status(s.user_assign_profile(&sys, b.id, NONE).await).0, StatusCode::FORBIDDEN, "no such profile");
        assert_eq!(status(s.user_assign_profile(&member, d.id, pid).await).0, StatusCode::FORBIDDEN);
        assert!(s.user_assign_profile(&member, b.id, pid).await.unwrap());
        assert!(!s.user_assign_profile(&member, b.id, pid).await.unwrap(), "already assigned");
        assert_eq!(status(s.user_remove_profile(&below, b.id, pid).await).0, StatusCode::FORBIDDEN);
        assert_eq!(status(s.user_remove_profile(&member, d.id, pid).await).0, StatusCode::FORBIDDEN);
        assert_eq!(status(s.user_remove_profile(&member, b.id, NONE).await).0, StatusCode::FORBIDDEN);
        assert!(s.user_remove_profile(&member, b.id, pid).await.unwrap());
        assert!(!s.user_remove_profile(&member, b.id, pid).await.unwrap());

        // ---- exists and members ----
        assert!(s.user_exists(&sys, None, e.email_id.as_deref(), None).await.is_ok());
        assert_eq!(status(s.members(&anonymous(c, "ZZRUL"), None, false, 0, 10).await).0, StatusCode::FORBIDDEN);
        let found = s.members(&member, Some("First"), true, 0, 0).await.unwrap();
        assert!(found.iter().any(|v| v["id"] == b.id));
        // The routes that only wrap these.
        let (st, _) = fx.http("GET", &format!("/users/{}/removeProfile/{pid}", b.id), None).await;
        assert_eq!(st, StatusCode::OK);
        let (st, _) = fx.http("PATCH", "/users/makeUserActive?userId=x", None).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        fx.finish().await;
    }

    /// QA-0599 (2026-10-26): a client that overrides a profile reads the user's assignment
    /// under the OVERRIDE's id, while the row holds the root; removing by that id removes it.
    #[tokio::test]
    async fn removing_a_profile_by_its_override_id_removes_the_root_assignment() {
        let Some(fx) = fx().await else { return };
        let (s, c, m) = (&fx.s, fx.c, fx.m);
        let sys = sys();
        let body = |v: serde_json::Value| super::super::profiles::profile_from_body(v.as_object().unwrap()).unwrap();
        let root = s.profile_create(&sys, body(json!({"appId": 2, "clientId": c, "name": format!("zz rp {}", fx.run), "arrangement": {"k": {"roleId": 70}}}))).await.unwrap().id.unwrap();
        let over = s.profile_create(&sys, body(json!({"rootProfileId": root, "appId": 2, "clientId": m, "name": "", "title": "Below"}))).await.unwrap().id.unwrap();
        let u = fx.user(m, "po").await;
        let owner = fx.as_user(&u, "ZZRUM", MEMBER);

        assert!(s.user_assign_profile(&owner, u.id, over).await.unwrap());
        assert_eq!(s.db.assigned_profile_ids(u.id, Some(2)).await.unwrap(), vec![root], "the root is stored");
        let seen: Vec<_> = s.assigned_profiles(&owner, u.id, Some(2), true).await.unwrap().into_iter().map(|p| p.id).collect();
        assert_eq!(seen, vec![Some(over)], "the client below reads it as its override");

        assert!(s.user_remove_profile(&owner, u.id, over).await.unwrap(), "removed by the override's id");
        assert!(s.db.assigned_profile_ids(u.id, Some(2)).await.unwrap().is_empty());
        assert!(!s.user_remove_profile(&owner, u.id, over).await.unwrap(), "nothing left to remove");

        // By the root's id, as before.
        assert!(s.user_assign_profile(&owner, u.id, root).await.unwrap());
        assert!(s.user_remove_profile(&owner, u.id, root).await.unwrap());
        assert!(s.db.assigned_profile_ids(u.id, Some(2)).await.unwrap().is_empty());
        fx.finish().await;
    }

    /// U7 (2026-10-21, QA-0482): `GET users/{id}` by a plain `User_READ` holder, no client
    /// manager role or assignment: own client, a client its client manages, and its client's
    /// direct manager are read; a sibling client is not found.
    #[tokio::test]
    async fn reading_users_by_id_follows_the_client_hierarchy() {
        let Some(fx) = fx().await else { return };
        let (s, c, m, i) = (&fx.s, fx.c, fx.m, fx.i);
        let reader = &["Authorities.User_READ"];
        let lu = fx.user(c, "ra").await;
        let lu2 = fx.user(c, "rb").await;
        let mu = fx.user(m, "rc").await;
        let iu = fx.user(i, "rd").await;
        let on_c = fx.as_user(&lu, "ZZRUL", reader);
        let on_m = fx.as_user(&mu, "ZZRUM", reader);

        assert_eq!(s.user_read_managed(&on_c, lu2.id).await.unwrap().id, lu2.id, "same client");
        assert_eq!(s.user_read_managed(&on_c, mu.id).await.unwrap().id, mu.id, "a managed client, not as its manager");
        assert_eq!(s.user_read_managed(&on_c, iu.id).await.unwrap().id, iu.id, "an individual's client it manages");
        assert_eq!(s.user_read_managed(&on_m, lu.id).await.unwrap().id, lu.id, "the direct managing client");
        let (st, msg) = status(s.user_read_managed(&on_m, iu.id).await);
        assert_eq!(st, StatusCode::NOT_FOUND, "a sibling client stays not found: {msg}");
        fx.finish().await;
    }
}
