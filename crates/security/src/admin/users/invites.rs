//! `UserInviteService` and `UserRequestService`: invitations into a client (created, listed,
//! read by code, revoked, accepted into a new user with a sign-in), and app access requests
//! (raised by a signed-in user, listed, approved with a profile, rejected).

use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::Router;
use serde_json::{Map, Value};

use super::common::{object_body, pre_authorize, Fields};
use crate::admin::{Admin, AdminState};
use crate::condition::{from_params, Cond, Filter, Op};
use crate::data::audit::{action, activity, object, sox};
use crate::data::crud::own_or_managed;
use crate::data::users_admin::{access_request, access_request_values, invite, invite_values, user_values, AccessRequest, Invite, INVITE, REQUEST, USER};
use crate::errors::{AuthError, AuthResult};
use crate::events::EventMessage;
use crate::internal::urls::platform_app_url;
use crate::jackson::{epoch, json, opt, Obj};
use crate::model::{ContextAuth, User, PLACEHOLDER};
use crate::signin::AuthRequest;
use crate::spring::Pageable;
use crate::web::{query_body, req_str, unreadable};

fn forbidden(key: &str, params: &[&str]) -> AuthError {
    AuthError::msg(StatusCode::FORBIDDEN, key, params)
}

fn conflict(key: &str, params: &[&str]) -> AuthError {
    AuthError::msg(StatusCode::CONFLICT, key, params)
}

fn blank(s: Option<&str>) -> bool {
    s.is_none_or(|v| v.trim().is_empty())
}

/// The invite link's prefix: the first non blank of the invited client's app URL and the app
/// owner's (each as `checkUrl` wrote it), else the app's platform address. `checkUrl` puts
/// `https://` before a stored `http://` URL; the link keeps the stored scheme instead.
fn invite_link_prefix(client_url: &str, owner_url: &str, platform: &str) -> String {
    let u = if client_url.trim().is_empty() { owner_url.trim() } else { client_url.trim() };
    if u.is_empty() {
        return platform.to_string();
    }
    u.strip_prefix("https://").filter(|r| r.starts_with("http://") || r.starts_with("https://")).unwrap_or(u).to_string()
}

/// `matchesIfGiven`.
fn matches_if_given(given: Option<&str>, stored: Option<&str>) -> bool {
    blank(given) || given == Some(PLACEHOLDER) || given.zip(stored).is_some_and(|(g, s)| g.to_lowercase() == s.to_lowercase())
}

/// `firstNonBlank`.
fn first_non_blank<'a>(values: &[Option<&'a str>]) -> String {
    values.iter().flatten().find(|v| !v.trim().is_empty() && **v != PLACEHOLDER).map(|v| v.to_string()).unwrap_or_default()
}

/// The display names `fillDetails` adds to an invite.
#[derive(Debug, Clone, Default)]
struct InviteNames {
    client: Option<String>,
    profile: Option<String>,
    app_code: Option<String>,
    designation: Option<String>,
    reporting_to: Option<String>,
    created_by: Option<String>,
}

fn invite_json(i: &Invite, n: &InviteNames) -> Value {
    Obj::new()
        .put("id", i.id)
        .put("createdAt", epoch(i.created_at))
        .put("createdBy", opt(i.created_by))
        .put("clientId", opt(i.client_id))
        .put("emailId", opt(i.email_id.clone()))
        .put("firstName", opt(i.first_name.clone()))
        .put("lastName", opt(i.last_name.clone()))
        .put("phoneNumber", opt(i.phone_number.clone()))
        .put("userName", opt(i.user_name.clone()))
        .put("inviteCode", opt(i.invite_code.clone()))
        .put("profileId", opt(i.profile_id))
        .put("designationId", opt(i.designation_id))
        .put("reportingTo", opt(i.reporting_to))
        .put("clientName", opt(n.client.clone()))
        .put("profileName", opt(n.profile.clone()))
        .put("appCode", opt(n.app_code.clone()))
        .put("designationName", opt(n.designation.clone()))
        .put("reportingToName", opt(n.reporting_to.clone()))
        .put("createdByName", opt(n.created_by.clone()))
        .build()
}

/// `UserInvite` as Jackson reads a body.
fn invite_from_body(m: &Map<String, Value>) -> AuthResult<Invite> {
    let f = Fields(m);
    for k in ["clientName", "profileName", "appCode", "designationName", "reportingToName", "createdByName"] {
        f.string(k)?;
    }
    Ok(Invite {
        id: f.u64("id")?.unwrap_or(0),
        client_id: f.u64("clientId")?,
        user_name: f.string("userName")?,
        email_id: f.string("emailId")?,
        phone_number: f.string("phoneNumber")?,
        first_name: f.string("firstName")?,
        last_name: f.string("lastName")?,
        invite_code: f.string("inviteCode")?,
        profile_id: f.u64("profileId")?,
        designation_id: f.u64("designationId")?,
        reporting_to: f.u64("reportingTo")?,
        created_by: f.u64("createdBy")?,
        created_at: f.ts("createdAt")?,
    })
}

/// The names a request row resolves to.
#[derive(Debug, Clone, Default)]
struct RequestNames {
    requester: Option<(String, Option<String>, Option<String>)>,
    client: Option<String>,
    app_name: Option<String>,
    app_code: Option<String>,
    decided_by: Option<String>,
}

fn request_json(a: &AccessRequest, n: &RequestNames) -> Value {
    let (rn, ru, re) = n.requester.clone().map(|(a, b, c)| (Some(a), b, c)).unwrap_or((None, None, None));
    Obj::new()
        .put("id", a.id)
        .put("createdAt", epoch(a.created_at))
        .put("createdBy", opt(a.created_by))
        .put("updatedAt", epoch(a.updated_at))
        .put("updatedBy", opt(a.updated_by))
        .put("requestId", opt(a.request_id.clone()))
        .put("clientId", opt(a.client_id))
        .put("userId", opt(a.user_id))
        .put("appId", opt(a.app_id))
        .put("status", opt(a.status.clone()))
        .put("requesterName", opt(rn))
        .put("requesterUserName", opt(ru))
        .put("requesterEmail", opt(re))
        .put("clientName", opt(n.client.clone()))
        .put("appName", opt(n.app_name.clone()))
        .put("appCode", opt(n.app_code.clone()))
        .put("decidedByName", opt(n.decided_by.clone()))
        .build()
}

/// `displayNameOf` / `userDisplayName`.
fn display_name(u: &User) -> String {
    let name = format!("{} {}", u.first_name.clone().filter(|v| !v.trim().is_empty()).unwrap_or_default(), u.last_name.clone().filter(|v| !v.trim().is_empty()).unwrap_or_default());
    let name = name.trim().to_string();
    if !name.is_empty() {
        return name;
    }
    if let Some(u) = u.user_name().filter(|v| !v.trim().is_empty()) {
        return u;
    }
    u.email_id().filter(|v| !v.trim().is_empty()).unwrap_or_default()
}

/// `UserRegistrationRequest` as Jackson reads it.
#[derive(Debug, Clone, Default)]
pub struct RegistrationBody {
    pub user: User,
    pub pass_type: Option<super::passwords::SecretType>,
    pub password: Option<String>,
    pub pin: Option<String>,
    pub otp: Option<String>,
    pub social_register_state: Option<String>,
    pub invite_code: Option<String>,
}

impl RegistrationBody {
    fn read(m: &Map<String, Value>) -> AuthResult<Self> {
        let f = Fields(m);
        let user = User {
            locale_code: f.string("localeCode")?,
            time_zone: crate::timezone::sanitize(f.string("timeZone")?.as_deref()),
            user_name: f.string("userName")?,
            email_id: f.string("emailId")?,
            phone_number: f.string("phoneNumber")?,
            first_name: f.string("firstName")?,
            last_name: f.string("lastName")?,
            middle_name: f.string("middleName")?,
            ..Default::default()
        };
        let pass_type = match m.get("passType") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(match s.as_str() {
                "PASSWORD" => super::passwords::SecretType::Password,
                "PIN" => super::passwords::SecretType::Pin,
                "OTP" => super::passwords::SecretType::Otp,
                _ => return Err(unreadable()),
            }),
            Some(_) => return Err(unreadable()),
        };
        Ok(Self {
            user,
            pass_type,
            password: f.string("password")?,
            pin: f.string("pin")?,
            otp: f.string("otp")?,
            social_register_state: f.string("socialRegisterState")?,
            invite_code: f.string("inviteCode")?,
        })
    }

    /// `getInputPassType()`.
    fn input_pass_type(&self) -> Option<super::passwords::SecretType> {
        use super::passwords::SecretType;
        self.pass_type.or_else(|| {
            if !blank(self.password.as_deref()) {
                Some(SecretType::Password)
            } else if !blank(self.pin.as_deref()) {
                Some(SecretType::Pin)
            } else if !blank(self.otp.as_deref()) {
                Some(SecretType::Otp)
            } else {
                None
            }
        })
    }

    /// `getInputPass()`.
    fn input_pass(&self) -> Option<String> {
        use super::passwords::SecretType;
        match self.input_pass_type() {
            Some(SecretType::Password) => self.password.clone(),
            Some(SecretType::Pin) => self.pin.clone(),
            Some(SecretType::Otp) => self.otp.clone(),
            None => None,
        }
    }
}

impl Admin {
    /// `fillDetails` for invites: each id's display name, looked up once.
    async fn invite_names(&self, i: &Invite) -> AuthResult<InviteNames> {
        let nz = |v: Option<u64>| v.filter(|x| *x != 0);
        let nonblank = |s: Option<String>| s.filter(|v| !v.trim().is_empty());
        let mut n = InviteNames::default();
        if let Some(c) = nz(i.client_id) {
            n.client = nonblank(self.dir().client(c).await?.and_then(|c| c.name.clone()));
        }
        if let Some(p) = nz(i.profile_id) {
            if let Some(row) = self.db.profile(p).await? {
                n.profile = nonblank(row.name.clone());
                if let Some(app) = row.app_id {
                    n.app_code = nonblank(self.dir().store.app_by_id(app).await?.map(|a| a.app_code));
                }
            }
        }
        if let Some(d) = nz(i.designation_id) {
            n.designation = nonblank(self.designation(d).await?.and_then(|d| d.name.clone()));
        }
        if let Some(u) = nz(i.reporting_to) {
            n.reporting_to = nonblank(self.db.user_row(u).await?.map(|u| display_name(&u)));
        }
        if let Some(u) = nz(i.created_by) {
            n.created_by = nonblank(self.db.user_row(u).await?.map(|u| display_name(&u)));
        }
        Ok(n)
    }

    /// `getAllInvitedUsers`: the invites of the caller's own and managed clients, optionally of an
    /// app's profiles, each with its display names.
    pub async fn invite_page(&self, ca: &ContextAuth, page: &Pageable, cond: Option<Cond>, app_id: Option<u64>) -> AuthResult<Value> {
        pre_authorize(ca, &["Authorities.User_READ"])?;
        let cond = match app_id.filter(|a| *a != 0) {
            None => cond,
            Some(app) => {
                let ids = self.db.profile_ids_of_app(app).await?;
                let ids = if ids.is_empty() { vec![0] } else { ids };
                let app_cond = crate::internal::clients::ids_in("profileId", &ids);
                Some(match cond {
                    Some(c) => Cond::and(vec![c, app_cond]),
                    None => app_cond,
                })
            }
        };
        let sql = match &cond {
            Some(c) => crate::condition::to_sql(c, &INVITE.table)?,
            None => None,
        };
        let (rows, total) = self.db.entity_page(&INVITE, own_or_managed(ca), sql, page).await?;
        let mut out = Vec::new();
        for r in &rows {
            let i = invite(r)?;
            let n = self.invite_names(&i).await?;
            out.push(invite_json(&i, &n));
        }
        Ok(crate::web::page_of(out, page, total))
    }

    /// `revokeInvitation`.
    pub async fn invite_revoke(&self, ca: &ContextAuth, code: &str) -> AuthResult<bool> {
        pre_authorize(ca, &["Authorities.User_CREATE", "Authorities.User_DELETE"])?;
        let refused = || forbidden("forbidden_delete", &["User Invite"]);
        let Some(i) = self.db.invite_by_code(code).await? else { return Err(refused()) };
        if !self.caller_manages_client(ca, i.client_id.unwrap_or_default()).await? {
            return Err(refused());
        }
        let deleted = self.db.delete_invite(code).await?;
        if deleted {
            activity(&self.db, i.client_id, "User Invite Revoked".into(), format!("User invite revoked for {}", i.email_id.as_deref().unwrap_or("null")), None);
        }
        Ok(deleted)
    }

    /// The invite mail's `urlPrefix` (DIFFERENCES.md, RS3 and RS4): the app's URL for the invited
    /// client as `getAppUrl` answers it, read for the server's own mail (the client's `URL`
    /// property, else its own newest LIVE URL); else the same for the app's OWNER (its `URL`
    /// property, else its own newest LIVE URL); else the app's platform address. Never a sibling
    /// tenant's URL: one tenant's invite must not link to another tenant's site. `""` only for an
    /// unknown app or with no platform ending configured. A failure reading a URL falls through to
    /// the next step rather than dropping the mail.
    async fn invite_url_prefix(&self, app_code: &str, client_id: u64) -> AuthResult<String> {
        let Some(app) = self.dir().app_by_code(app_code).await? else { return Ok(String::new()) };
        let app = &app;
        let url_of = |id: u64| async move {
            self.app_url_internal(app, id).await.unwrap_or_else(|e| {
                tracing::warn!(error = %e, app = app_code, client = id, "no client URL for the invite mail");
                String::new()
            })
        };
        let client_url = url_of(client_id).await;
        let owner_url = if client_url.trim().is_empty() && app.client_id != client_id { url_of(app.client_id).await } else { String::new() };
        Ok(invite_link_prefix(&client_url, &owner_url, &platform_app_url(&app.app_code, &self.dir().subdomain_endings)))
    }

    /// `raiseInvitedEvent`: `USER_INVITED` for the app's mail (false without an app).
    async fn raise_invited(&self, ca: &ContextAuth, i: &Invite, existing: Option<&User>) -> bool {
        let Some(app_code) = ca.url_app_code.clone().filter(|a| !a.trim().is_empty()) else { return false };
        let result: AuthResult<bool> = async {
            let profile_name = match i.profile_id {
                None => String::new(),
                Some(p) => self.db.profile(p).await?.and_then(|p| p.name).unwrap_or_default(),
            };
            let invited_client = i.client_id.unwrap_or_else(|| ca.user.client_id());
            let url_prefix = self.invite_url_prefix(&app_code, invited_client).await?;
            // The link's host only (never the code), so a dead link can be traced to its prefix.
            tracing::info!(invite = i.id, app = %app_code, url_prefix = %url_prefix, "USER_INVITED link prefix");
            let email = first_non_blank(&[i.email_id.as_deref(), existing.and_then(|u| u.email_id.as_deref())]);
            let (first, last, phone) = match existing {
                None => (
                    first_non_blank(&[i.first_name.as_deref(), Some(email.as_str())]),
                    first_non_blank(&[i.last_name.as_deref()]),
                    first_non_blank(&[i.phone_number.as_deref()]),
                ),
                Some(u) => (
                    first_non_blank(&[u.first_name.as_deref(), i.first_name.as_deref(), Some(email.as_str())]),
                    first_non_blank(&[u.last_name.as_deref(), i.last_name.as_deref()]),
                    first_non_blank(&[u.phone_number.as_deref(), i.phone_number.as_deref()]),
                ),
            };
            let invited_by = first_non_blank(&[ca.user.first_name.as_deref(), ca.user.email_id.as_deref()]);
            let data = vec![
                ("firstName".into(), Value::from(first)),
                ("lastName".into(), Value::from(last)),
                ("phoneNumber".into(), Value::from(phone)),
                ("emailId".into(), Value::from(email)),
                ("profileName".into(), Value::from(profile_name)),
                ("inviteCode".into(), Value::from(first_non_blank(&[i.invite_code.as_deref()]))),
                ("urlPrefix".into(), Value::from(url_prefix)),
                ("userExisted".into(), Value::from(if existing.is_some() { "true" } else { "false" })),
                ("clientId".into(), Value::from(i.client_id.map(|c| c.to_string()).unwrap_or_default())),
                ("invitedBy".into(), Value::from(invited_by)),
            ];
            let event = EventMessage {
                event_name: "USER_INVITED".into(),
                client_code: ca.logged_in_from_client_code.clone(),
                app_code: Some(app_code.clone()),
                x_debug: None,
                draft: false,
                data,
            };
            self.events.publish(&event).await
        }
        .await;
        result.unwrap_or_else(|e| {
            tracing::error!(error = %e, invite = i.id, "could not raise USER_INVITED");
            false
        })
    }

    /// `createInvite`.
    pub async fn invite_create(&self, ca: &ContextAuth, mut i: Invite) -> AuthResult<Value> {
        pre_authorize(ca, &["Authorities.User_CREATE"])?;
        let refused = || forbidden("forbidden_create", &["User Invite"]);
        match i.client_id {
            None => i.client_id = Some(ca.user.client_id()),
            Some(c) if !self.caller_manages_client(ca, c).await? => return Err(refused()),
            Some(_) => {}
        }
        let client_id = i.client_id.unwrap_or_default();
        if let Some(r) = i.reporting_to {
            if self.user_dao_read(r).await?.client_id != client_id {
                return Err(refused());
            }
        }
        if let Some(p) = i.profile_id {
            if !self.has_access_to_profiles(ca.user.client_id(), &[p]).await? {
                return Err(refused());
            }
        }
        let existing = self.db.users_with_any_identity(client_id, i.user_name.as_deref(), i.email_id.as_deref(), i.phone_number.as_deref(), None).await?;
        if existing.is_empty() {
            return self.invite_new(ca, i).await;
        }
        let u = &existing[0];
        if existing.len() == 1
            && matches_if_given(i.user_name.as_deref(), u.user_name().as_deref())
            && matches_if_given(i.email_id.as_deref(), u.email_id().as_deref())
            && matches_if_given(i.phone_number.as_deref(), u.phone_number().as_deref())
        {
            // `addUserProfile`.
            let Some(p) = i.profile_id else { return Err(refused()) };
            if !self.has_access_to_profiles(u.client_id, &[p]).await? {
                return Err(refused());
            }
            self.db.add_profile_to_user(u.id, p).await?.ok_or_else(refused)?;
            self.raise_invited(ca, &i, Some(u)).await;
            // `Map.of`: its order is the JVM's (any order is Java's).
            return Ok(Obj::new().put("userRequest", invite_json(&i, &InviteNames::default())).put("existingUser", true).build());
        }
        let email = i.email_id.as_deref();
        let phone = i.phone_number.as_deref();
        let taken = if email.is_some_and(|e| u.email_id.as_deref().is_some_and(|o| o.eq_ignore_ascii_case(e))) {
            "email"
        } else if phone.is_some_and(|p| u.phone_number.as_deref().is_some_and(|o| o.eq_ignore_ascii_case(p))) {
            "phone number"
        } else {
            "user name"
        };
        Err(conflict("user_identity_taken", &[taken]))
    }

    /// `refuseIfIdentityInBusiness` (QA-0445, 2026-10-16): nobody may be added to a business, or
    /// to a client it manages, with an email or phone a user anywhere in that business holds (a
    /// channel partner's user cannot become staff, nor one partner's user another's). The
    /// business is the top client below SYSTEM; inviting into SYSTEM itself is not checked.
    async fn refuse_if_identity_in_business(&self, client_id: u64, email: Option<&str>, phone: Option<&str>) -> AuthResult<()> {
        let root = self.dir().hierarchy(client_id).await?.business_root_id();
        if self.db.identity_exists_in_client_family(root, email, phone).await? {
            return Err(conflict("user_already_exists", &[&first_non_blank(&[email, phone])]));
        }
        Ok(())
    }

    /// `createNewInvite`.
    async fn invite_new(&self, ca: &ContextAuth, mut i: Invite) -> AuthResult<Value> {
        let client_id = i.client_id.unwrap_or_default();
        self.refuse_if_identity_in_business(client_id, i.email_id.as_deref(), i.phone_number.as_deref()).await?;
        if let Some(code) = ca.url_app_code.as_deref().filter(|c| !c.trim().is_empty()) {
            if let Some(app) = self.dir().app_by_code(code).await? {
                self.invite_user_check(ca, &app, client_id, i.user_name.as_deref(), i.email_id.as_deref(), i.phone_number.as_deref()).await?;
            }
        }
        if let Some(pending) = self.db.invite_with_identity(i.client_id, i.email_id.as_deref(), i.phone_number.as_deref()).await? {
            let which = if matches_if_given(i.email_id.as_deref(), pending.email_id.as_deref()) { "email" } else { "phone number" };
            return Err(conflict("user_invite_pending", &[which]));
        }
        i.invite_code = Some(format!("{:032x}", rand::random::<u128>()));
        i.created_by = Some(ca.user.id());
        let id = match self.db.entity_insert(&INVITE, &invite_values(&i)).await {
            Ok(id) => id,
            Err(_) => return Err(conflict("user_invite_pending", &["email or phone number"])),
        };
        let created = self.db.invite_row(id).await?.ok_or_else(|| AuthError::internal("invite not found"))?;
        activity(&self.db, created.client_id, "User Invite Created".into(), format!("User invite created for {}", created.email_id.as_deref().unwrap_or("null")), None);
        self.raise_invited(ca, &created, None).await;
        // A `HashMap` of two keys: "existingUser" hashes into an earlier bucket than "userRequest".
        let mut m = Map::new();
        for k in crate::javamap::hash_map_order_str(["userRequest", "existingUser"]) {
            match k {
                "userRequest" => m.insert(k.into(), invite_json(&created, &InviteNames::default())),
                _ => m.insert(k.into(), Value::Bool(false)),
            };
        }
        Ok(Value::Object(m))
    }

    /// `validateUserCheckForInvite`.
    async fn invite_user_check(&self, ca: &ContextAuth, app: &crate::model::App, client_id: u64, un: Option<&str>, em: Option<&str>, ph: Option<&str>) -> AuthResult<()> {
        self.validate_user_check(ca, app.id, client_id, un, em, ph, None).await
    }

    /// `acceptInvite`: the invite's user created, the invite consumed, the new user signed in.
    pub async fn invite_accept(&self, ca: &ContextAuth, b: &RegistrationBody, info: &crate::request::RequestInfo) -> AuthResult<(Value, Option<String>)> {
        use super::passwords::SecretType;
        let unknown = || forbidden("User", &[]);
        let Some(i) = (match b.invite_code.as_deref() {
            Some(c) => self.db.invite_by_code(c).await?,
            None => None,
        }) else {
            return Err(forbidden("forbidden_create", &["User Invitation Error"]));
        };
        let pass_type = b.pass_type.ok_or_else(|| AuthError::internal("Cannot invoke \"com.fincity.security.model.AuthenticationPasswordType.ordinal()\" because \"passType\" is null"))?;
        let password = match pass_type {
            SecretType::Password => b.input_pass(),
            SecretType::Pin => b.pin.clone(),
            SecretType::Otp => b.otp.clone(),
        };
        let mut u = b.user.clone();
        u.password = None;
        u.password_hashed = false;
        u.account_non_expired = true;
        u.account_non_locked = true;
        u.credentials_non_expired = true;
        u.no_failed_attempt = Some(0);
        u.no_pin_failed_attempt = Some(0);
        u.no_otp_failed_attempt = Some(0);
        u.status_code = "ACTIVE".into();
        if u.first_name.is_none() {
            u.first_name = i.first_name.clone();
        }
        if u.last_name.is_none() {
            u.last_name = i.last_name.clone();
        }
        if !blank(i.phone_number.as_deref()) {
            u.phone_number = i.phone_number.clone();
        }
        if !blank(i.email_id.as_deref()) {
            u.email_id = i.email_id.clone();
        }
        if !blank(i.user_name.as_deref()) {
            u.user_name = i.user_name.clone();
        }
        u.client_id = i.client_id.unwrap_or_default();
        u.designation_id = i.designation_id;
        u.reporting_to = i.reporting_to;
        let already = |u: &User| {
            let who = u.email_id.clone().filter(|e| !e.trim().is_empty() && e != PLACEHOLDER).or_else(|| u.user_name.clone()).unwrap_or_else(|| "null".into());
            conflict("user_already_exists", &[&who])
        };
        if !self.db.users_with_any_identity(u.client_id, u.user_name.as_deref(), u.email_id.as_deref(), u.phone_number.as_deref(), None).await?.is_empty() {
            return Err(already(&u));
        }
        // Someone in the business may have taken the email or phone since the invite.
        self.refuse_if_identity_in_business(u.client_id, u.email_id.as_deref(), u.phone_number.as_deref()).await?;
        let Some(app) = (match ca.url_app_code.as_deref() {
            Some(a) => self.dir().app_by_code(a).await?,
            None => None,
        }) else {
            return Err(unknown());
        };
        self.invite_user_check(ca, &app, u.client_id, u.user_name.as_deref(), u.email_id.as_deref(), u.phone_number.as_deref()).await?;
        if let Some(p) = password.as_deref().filter(|p| !p.trim().is_empty()) {
            self.check_policy_for(u.client_id, app.id, pass_type, p).await?;
        }
        let id = match self.db.entity_insert(&USER, &user_values(&u)).await {
            Ok(id) => id,
            Err(e) if e.to_string().contains("Duplicate entry") => return Err(already(&u)),
            Err(e) => return Err(e),
        };
        let created = self.user_dao_read(id).await?;
        let email = created.email_id().unwrap_or_else(|| "null".into());
        sox(&self.db, Some(created.id), object::USER, action::CREATE, format!("User created: {email}"), None);
        activity(&self.db, Some(created.client_id), "User Invite Accepted".into(), format!("User invite accepted, user created: {email}"), None);
        let set = match pass_type {
            SecretType::Password | SecretType::Pin => {
                let hash = bcrypt::hash_with_result(format!("{}{}", created.id, password.clone().unwrap_or_else(|| "null".into())), 10)
                    .map(|h| h.format_for_version(bcrypt::Version::TwoA))
                    .map_err(AuthError::internal)?;
                self.db.set_secret(created.id, created.id, &hash, pass_type == SecretType::Pin).await? > 0
            }
            SecretType::Otp => false,
        };
        if !set {
            return Err(unknown());
        }
        let addable = match i.profile_id {
            Some(p) => self.has_access_to_profiles(u.client_id, &[p]).await?,
            None => false,
        };
        // The owner's cached sub-org (`<client>:owner`) lists every user of the client, so it has to
        // drop too, or an Owner cannot hand work to the new user until the cache expires (LZT-1716).
        self.evict_owner_cache(created.client_id, created.reporting_to).await;
        if addable {
            self.db.add_profile_to_user(created.id, i.profile_id.unwrap_or_default()).await?;
        }
        if let Some(code) = i.invite_code.as_deref() {
            self.db.delete_invite(code).await?;
        }
        // `getClientAuthenticationResponse`: the password or PIN signs the new user in. The input
        // type is the request's type here (a missing one failed above, and an OTP set no secret),
        // so Java's OTP and social-registration branches are never reached.
        let mut auth = AuthRequest { user_id: Some(created.id), ..Default::default() };
        if pass_type == SecretType::Pin {
            auth.pin = b.input_pass();
        } else {
            auth.password = b.input_pass();
        }
        let minted = self.auth.authenticate(&auth, info, ca.user.id()).await?;
        let body = Obj::new().put("created", true).put("userId", created.id).put("authentication", minted.response.to_json()).build();
        Ok((body, minted.cookie))
    }

    // ---- access requests ----

    async fn request_names(&self, a: &AccessRequest) -> AuthResult<RequestNames> {
        let nz = |v: Option<u64>| v.filter(|x| *x != 0);
        let nonblank = |s: Option<String>| s.filter(|v| !v.trim().is_empty());
        let mut n = RequestNames::default();
        if let Some(u) = nz(a.user_id) {
            if let Some(u) = self.db.user_row(u).await? {
                n.requester = Some((display_name(&u), u.user_name(), u.email_id()));
            }
        }
        if let Some(c) = nz(a.client_id) {
            n.client = nonblank(self.dir().client(c).await?.and_then(|c| c.name.clone()));
        }
        if let Some(app) = nz(a.app_id) {
            if let Some(app) = self.dir().store.app_by_id(app).await? {
                n.app_name = nonblank(app.app_name.clone());
                n.app_code = nonblank(Some(app.app_code.clone()));
            }
        }
        if let Some(u) = nz(a.updated_by) {
            n.decided_by = nonblank(self.db.user_row(u).await?.map(|u| display_name(&u)));
        }
        Ok(n)
    }

    /// `UserRequestService.readPageFilter`.
    pub async fn request_page(&self, ca: &ContextAuth, page: &Pageable, cond: Option<Cond>, requester: Option<&str>) -> AuthResult<Value> {
        pre_authorize(ca, &["Authorities.User_READ"])?;
        let cond = match requester.map(str::trim).filter(|r| !r.is_empty()) {
            None => cond.unwrap_or_else(|| {
                let mut f = Filter::eq("id", 0);
                f.op = Op::GreaterThan;
                Cond::Filter(f)
            }),
            Some(text) => {
                let ids = self.db.user_ids_matching(text).await?;
                let ids = if ids.is_empty() { vec![0] } else { ids };
                let user_cond = crate::internal::clients::ids_in("userId", &ids);
                match cond {
                    Some(c) => Cond::and(vec![c, user_cond]),
                    None => user_cond,
                }
            }
        };
        let sql = crate::condition::to_sql(&cond, &REQUEST.table)?;
        let (rows, total) = self.db.entity_page(&REQUEST, own_or_managed(ca), sql, page).await?;
        let mut out = Vec::new();
        for r in &rows {
            let a = access_request(r)?;
            let n = self.request_names(&a).await?;
            out.push(request_json(&a, &n));
        }
        Ok(crate::web::page_of(out, page, total))
    }

    /// `readEntitledRequest`.
    async fn entitled_request(&self, ca: &ContextAuth, request_id: &str) -> AuthResult<AccessRequest> {
        let Some(r) = self.db.request_by_request_id(request_id).await? else {
            return Err(AuthError::msg(StatusCode::NOT_FOUND, "object_not_found", &["User Request", request_id]));
        };
        if !self.caller_manages_client(ca, r.client_id.unwrap_or_default()).await? {
            return Err(forbidden("forbidden_permission", &["User Request"]));
        }
        Ok(r)
    }

    /// `hasPendingRequest`.
    pub async fn request_pending(&self, ca: &ContextAuth, app_code: &str) -> AuthResult<bool> {
        pre_authorize(ca, &["Authorities.Logged_IN"])?;
        let Some(app) = self.dir().app_by_code(app_code).await? else { return Ok(false) };
        self.db.pending_request_exists(ca.user.id(), app.id).await
    }

    /// `createRequest`.
    pub async fn request_create(&self, ca: &ContextAuth, app_code: Option<&str>) -> AuthResult<Value> {
        pre_authorize(ca, &["Authorities.Logged_IN"])?;
        let refused = || forbidden("forbidden_create", &["User Request"]);
        let Some(client) = (match ca.client_code.as_deref() {
            Some(c) => self.dir().client_by_code(c).await?,
            None => None,
        }) else {
            return Err(refused());
        };
        let Some(app) = (match app_code {
            Some(a) => self.dir().app_by_code(a).await?,
            None => None,
        }) else {
            return Err(refused());
        };
        if self.db.has_assigned_profile_in_app(ca.user.id(), app.id).await? {
            return Err(AuthError::msg(StatusCode::BAD_REQUEST, "user_already_having_app_access", &[&app.app_code])
                .with_param("app", app.app_name.as_deref().unwrap_or(&app.app_code)));
        }
        if self.db.pending_request_exists(ca.user.id(), app.id).await? {
            return Err(AuthError::msg(StatusCode::BAD_REQUEST, "user_app_request_already_exists", &[&app.app_code])
                .with_param("app", app.app_name.as_deref().unwrap_or(&app.app_code)));
        }
        let msb = rand::random::<i64>();
        let r = AccessRequest {
            request_id: Some(msb.wrapping_abs().to_string()),
            client_id: client.id,
            user_id: Some(ca.user.id()),
            app_id: Some(app.id),
            status: Some("PENDING".into()),
            created_by: Some(ca.user.id()),
            ..Default::default()
        };
        let id = self.db.entity_insert(&REQUEST, &access_request_values(&r)).await?;
        let created = self.db.request_row(id).await?.ok_or_else(|| AuthError::internal("request not found"))?;
        Ok(request_json(&created, &RequestNames::default()))
    }

    /// `super.update(request.setStatus(...))`: the row as given, `UPDATED_BY` the caller.
    async fn request_decide(&self, ca: &ContextAuth, mut r: AccessRequest, status: &str) -> AuthResult<()> {
        r.status = Some(status.into());
        r.updated_by = Some(ca.user.id());
        r.updated_at = None;
        self.db.entity_update(&REQUEST, r.id, &access_request_values(&r)).await?;
        Ok(())
    }

    /// `acceptRequest`.
    pub async fn request_accept(&self, ca: &ContextAuth, request_id: Option<&str>, profile_id: Option<u64>) -> AuthResult<bool> {
        pre_authorize(ca, &["Authorities.User_CREATE"])?;
        let (Some(rid), Some(pid)) = (request_id, profile_id) else {
            return Err(AuthError::msg(StatusCode::BAD_REQUEST, "user_app_request_accept_incorrect_data", &[]));
        };
        let r = self.entitled_request(ca, rid).await?;
        if r.status.as_deref() != Some("PENDING") {
            return Err(AuthError::msg(StatusCode::BAD_REQUEST, "user_app_request_incorrect_status", &[]));
        }
        let user = r.user_id.unwrap_or_default().to_string();
        let Some(profile) = self.db.profile(pid).await? else {
            return Err(AuthError::msg(StatusCode::NOT_FOUND, "object_not_found", &["Profile", &pid.to_string()]));
        };
        let profile_refused = || forbidden("profile_forbidden_for_selected_user", &[&pid.to_string(), &user]);
        if profile.app_id.is_none() || profile.app_id != r.app_id {
            return Err(profile_refused());
        }
        if !self.has_access_to_profiles(r.client_id.unwrap_or_default(), &[pid]).await? {
            return Err(profile_refused());
        }
        if self.db.add_profile_to_user(r.user_id.unwrap_or_default(), pid).await?.is_none() {
            return Err(forbidden("forbidden_update", &["User Request"]));
        }
        self.request_decide(ca, r, "APPROVED").await?;
        Ok(true)
    }

    /// `rejectRequest`.
    pub async fn request_reject(&self, ca: &ContextAuth, request_id: &str) -> AuthResult<bool> {
        pre_authorize(ca, &["Authorities.User_CREATE"])?;
        let r = self.entitled_request(ca, request_id).await?;
        if r.status.as_deref() != Some("PENDING") {
            return Err(AuthError::msg(StatusCode::BAD_REQUEST, "user_app_request_incorrect_status", &[]));
        }
        self.request_decide(ca, r, "REJECTED").await?;
        Ok(true)
    }

    /// `getRequestUser`.
    pub async fn request_user(&self, ca: &ContextAuth, request_id: &str) -> AuthResult<User> {
        pre_authorize(ca, &["Authorities.User_READ"])?;
        let r = self.entitled_request(ca, request_id).await?;
        self.user_dao_read(r.user_id.unwrap_or_default()).await
    }
}

macro_rules! r {
    ($name:ident, $path:expr, $protected:expr, |$s:ident, $r:ident, $ca:ident| $body:block) => {
        $crate::web_route!($name, AdminState, $path, $protected, |$s, $r, $ca| $body);
    };
}

macro_rules! rp {
    ($name:ident, $path:expr, $protected:expr, |$s:ident, $r:ident, $ca:ident, $p:ident| $body:block) => {
        $crate::web_route_path!($name, AdminState, $path, $protected, |$s, $r, $ca, $p| $body);
    };
}

/// Query parameters as conditions, without the paging ones.
fn conditions_without_paging(p: &crate::spring::Params) -> Option<Cond> {
    let rest: Vec<(String, String)> = p.0.iter().filter(|(k, _)| !matches!(k.as_str(), "page" | "size" | "sort")).cloned().collect();
    from_params(&rest)
}

r!(invite_route, "/users/invite", true, |s, r, ca| {
    let body = invite_from_body(&object_body(&r.body)?)?;
    Ok(json(&s.invite_create(&ca, body).await?))
});

rp!(invite_details, "/users/inviteDetails/{code}", false, |s, r, ca, code| {
    Ok(match s.db.invite_by_code(&code).await? {
        Some(i) => json(&invite_json(&i, &InviteNames::default())),
        None => crate::web::nothing(),
    })
});

rp!(invite_revoke, "/users/invite/{code}", true, |s, r, ca, code| {
    Ok(json(&Value::Bool(s.invite_revoke(&ca, &code).await?)))
});

r!(invites, "/users/invites", true, |s, r, ca| {
    let page = Pageable::from_params(&r.params);
    Ok(json(&s.invite_page(&ca, &page, conditions_without_paging(&r.params), None).await?))
});

r!(invites_query, "/users/invites/query", true, |s, r, ca| {
    let (page, cond) = query_body(&r.body)?;
    let app = crate::web::opt_u64(&r.params, "appId")?;
    Ok(json(&s.invite_page(&ca, &page, cond, app).await?))
});

r!(accept_invite, "/users/acceptInvite", false, |s, r, ca| {
    let body = RegistrationBody::read(&object_body(&r.body)?)?;
    let (v, cookie) = s.invite_accept(&ca, &body, &r.info).await?;
    let mut resp = json(&v);
    if let Some(c) = cookie.and_then(|c| axum::http::HeaderValue::from_str(&c).ok()) {
        resp.headers_mut().insert(axum::http::header::SET_COOKIE, c);
    }
    Ok(resp)
});

r!(request_create, "/users/request", true, |s, r, ca| {
    let body = object_body(&r.body)?;
    let f = Fields(&body);
    f.string("callbackUrl")?;
    f.string("requestId")?;
    f.u64("profileId")?;
    f.bool("rememberMe")?;
    let app = f.string("appCode")?;
    Ok(json(&s.request_create(&ca, app.as_deref()).await?))
});

r!(request_pending, "/users/request", true, |s, r, ca| {
    let app = req_str(&r.params, "appCode")?.to_string();
    Ok(json(&Value::Bool(s.request_pending(&ca, &app).await?)))
});

r!(request_accept, "/users/acceptRequest", true, |s, r, ca| {
    let body = object_body(&r.body)?;
    let f = Fields(&body);
    f.string("appCode")?;
    f.string("callbackUrl")?;
    f.bool("rememberMe")?;
    let rid = f.string("requestId")?;
    let pid = f.u64("profileId")?;
    Ok(json(&Value::Bool(s.request_accept(&ca, rid.as_deref(), pid).await?)))
});

rp!(request_reject, "/users/rejectRequest/{requestId}", true, |s, r, ca, rid| {
    Ok(json(&Value::Bool(s.request_reject(&ca, &rid).await?)))
});

rp!(request_user, "/users/requestUser/{requestId}", true, |s, r, ca, rid| {
    Ok(json(&crate::dto::user_json(&s.request_user(&ca, &rid).await?, &Default::default())))
});

r!(requests, "/users/requests", true, |s, r, ca| {
    let page = Pageable::from_params(&r.params);
    Ok(json(&s.request_page(&ca, &page, conditions_without_paging(&r.params), None).await?))
});

r!(requests_query, "/users/requests/query", true, |s, r, ca| {
    let (page, cond) = query_body(&r.body)?;
    Ok(json(&s.request_page(&ca, &page, cond, r.params.get("requesterSearch")).await?))
});

pub fn router() -> Router<AdminState> {
    Router::new()
        .route("/api/security/users/invite", post(invite_route))
        .route("/api/security/users/invite/{code}", axum::routing::delete(invite_revoke))
        .route("/api/security/users/inviteDetails/{code}", get(invite_details))
        .route("/api/security/users/invites", get(invites))
        .route("/api/security/users/invites/query", post(invites_query))
        .route("/api/security/users/acceptInvite", post(accept_invite))
        .route("/api/security/users/request", post(request_create).get(request_pending))
        .route("/api/security/users/acceptRequest", post(request_accept))
        .route("/api/security/users/rejectRequest/{requestId}", post(request_reject))
        .route("/api/security/users/requestUser/{requestId}", get(request_user))
        .route("/api/security/users/requests", get(requests))
        .route("/api/security/users/requests/query", post(requests_query))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn helpers() {
        assert!(matches_if_given(None, Some("a")) && matches_if_given(Some("NONE"), None) && matches_if_given(Some("A"), Some("a")));
        assert!(!matches_if_given(Some("b"), Some("a")));
        assert_eq!(first_non_blank(&[None, Some(" "), Some("NONE"), Some("x")]), "x");
        assert_eq!(display_name(&User { user_name: Some("NONE".into()), email_id: Some("e@x".into()), ..Default::default() }), "e@x");
        assert_eq!(display_name(&User { first_name: Some("A".into()), ..Default::default() }), "A");
        let i = invite_from_body(json!({"clientId": 3, "emailId": "a@b", "profileId": "7"}).as_object().unwrap()).unwrap();
        assert_eq!((i.client_id, i.profile_id), (Some(3), Some(7)));
        let b = RegistrationBody::read(json!({"inviteCode": "c", "password": "p", "timeZone": "Asia/Kolkata"}).as_object().unwrap()).unwrap();
        assert_eq!((b.input_pass_type(), b.input_pass().as_deref()), (Some(super::super::passwords::SecretType::Password), Some("p")));
        assert!(RegistrationBody::read(json!({"passType": "x"}).as_object().unwrap()).is_err());
        let v = invite_json(&i, &InviteNames { client: Some("C".into()), ..Default::default() });
        assert_eq!(v["clientName"], "C");
        let a = AccessRequest { id: 1, status: Some("PENDING".into()), ..Default::default() };
        assert_eq!(request_json(&a, &RequestNames::default()), json!({"id": 1, "status": "PENDING"}));
    }

    /// RS3 and RS4: the invited client's URL when it has one, else the app owner's, else the
    /// app's platform address.
    #[test]
    fn invite_link_prefix_is_the_clients_or_the_platforms() {
        let endings = vec![" .local.modlix.com".to_string(), ".local.sitezump.ai".to_string()];
        let platform = platform_app_url("CxZump", &endings);
        assert_eq!(platform, "https://cxzump.local.modlix.com");
        assert_eq!(platform_app_url("cxzump", &[]), "");
        assert_eq!(platform_app_url(" ", &endings), "");
        assert_eq!(platform_app_url("cxzump", &[" ".into(), ".modlix.com".into()]), "https://cxzump.modlix.com");

        let owner = "https://owner.example.test";
        assert_eq!(invite_link_prefix("https://anter.example.test", owner, &platform), "https://anter.example.test");
        assert_eq!(invite_link_prefix("https://anter.example.test", "", &platform), "https://anter.example.test");
        assert_eq!(invite_link_prefix("", owner, &platform), owner);
        assert_eq!(invite_link_prefix("  ", " https://http://owner.example.test ", &platform), "http://owner.example.test");
        assert_eq!(invite_link_prefix("", "", &platform), platform);
        assert_eq!(invite_link_prefix("  ", " ", &platform), platform);
        assert_eq!(invite_link_prefix("", "", ""), "");
        // `checkUrl` over a stored `http://` URL.
        assert_eq!(invite_link_prefix("https://http://anter.example.test:8080", "", &platform), "http://anter.example.test:8080");
        assert_eq!(invite_link_prefix("https://https://anter.example.test", "", &platform), "https://anter.example.test");
        assert_eq!(invite_link_prefix("https://httpbin.example.test", "", &platform), "https://httpbin.example.test");
    }
}

#[cfg(test)]
mod live {
    use super::*;
    use crate::admin::users::testkit::{fx, sys, NONE, PASSWORD};
    use crate::spring::Params;
    use std::sync::Arc;
    use super::super::passwords::SecretType;
    use serde_json::json;

    fn err(r: AuthResult<impl std::fmt::Debug>) -> (StatusCode, String) {
        let e = r.unwrap_err();
        (e.status(), e.message())
    }

    fn info() -> crate::request::RequestInfo {
        let mut h = axum::http::HeaderMap::new();
        h.insert("x-real-ip", axum::http::HeaderValue::from_static("127.0.0.1"));
        crate::request::RequestInfo::new(h, Some("127.0.0.1:5000".parse().unwrap()))
    }

    #[test]
    fn registration_bodies() {
        let o = |v: Value| v.as_object().unwrap().clone();
        let pin = RegistrationBody::read(&o(json!({"passType": "PIN", "pin": "1234"}))).unwrap();
        assert_eq!((pin.input_pass_type(), pin.input_pass().as_deref()), (Some(SecretType::Pin), Some("1234")));
        let otp = RegistrationBody::read(&o(json!({"passType": "OTP", "otp": "9"}))).unwrap();
        assert_eq!(otp.input_pass().as_deref(), Some("9"));
        assert!(RegistrationBody::read(&o(json!({"passType": 1}))).is_err());
        let guessed = RegistrationBody::read(&o(json!({"pin": "77"}))).unwrap();
        assert_eq!(guessed.input_pass_type(), Some(SecretType::Pin));
        let guessed = RegistrationBody::read(&o(json!({"otp": "5"}))).unwrap();
        assert_eq!(guessed.input_pass_type(), Some(SecretType::Otp));
        let none = RegistrationBody::read(&o(json!({}))).unwrap();
        assert_eq!((none.input_pass_type(), none.input_pass()), (None, None));
    }

    /// `UserInviteServiceTest` / `UserRequestServiceTest` on the scratch clients.
    #[tokio::test]
    async fn invites_and_requests() {
        let Some(fx) = fx().await else { return };
        let (s, c, m) = (&fx.s, fx.c, fx.m);
        let sys = sys();
        let run = fx.run.clone();
        let mail = |t: &str| format!("zzrl{run}{t}@example.invalid");
        let a = fx.user(c, "a").await;
        let b = fx.user(c, "b").await;
        let e = fx.user(m, "e").await;
        let phone = format!("+9100{}", &run[run.len() - 6..]);
        s.user_patch(&sys, b.id, json!({"phoneNumber": phone}).as_object().unwrap()).await.unwrap();
        let below = fx.as_user(&e, "ZZRUM", &["Authorities.User_CREATE", "Authorities.User_DELETE", "Authorities.User_READ"]);
        // Two profiles of appbuilder in ZZRUL, and ZZRUL restricted to the first.
        let mk = |n: &str| super::super::profiles::profile_from_body(json!({"appId": 2, "clientId": c, "name": format!("zz {n} {run}")}).as_object().unwrap()).unwrap();
        let p1 = s.profile_create(&sys, mk("p1")).await.unwrap().id.unwrap();
        let p2 = s.profile_create(&sys, mk("p2")).await.unwrap().id.unwrap();

        // ---- invites ----
        let new = |email: &str| Invite { email_id: Some(email.to_string()), ..Default::default() };
        let mut own = sys.clone();
        own.user.client_id = Some(c);
        own.client_code = Some("ZZRUL".into());
        let created = s.invite_create(&own, new(&mail("i1"))).await.unwrap();
        // On an app that does not exist: no user check, no URL for the mail.
        let mut on_nothing = sys.clone();
        on_nothing.url_app_code = Some("nosuchapp".into());
        assert_eq!(s.invite_create(&on_nothing, Invite { client_id: Some(c), ..new(&mail("i0")) }).await.unwrap()["existingUser"], false);
        assert_eq!(created["userRequest"]["clientId"], c, "the caller's own client");
        assert_eq!(err(s.invite_create(&sys, Invite { client_id: Some(c), reporting_to: Some(e.id), ..new(&mail("i2")) }).await).0, StatusCode::FORBIDDEN);
        s.profile_restrict_client(&sys, p1, c).await.unwrap();
        let mut in_c = fx.as_user(&a, "ZZRUL", &["Authorities.User_CREATE"]);
        in_c.url_app_code = None;
        assert_eq!(err(s.invite_create(&in_c, Invite { profile_id: Some(p2), ..new(&mail("i3")) }).await).0, StatusCode::FORBIDDEN, "restricted to p1");
        // An existing user: given the profile (and announced), or refused without one.
        let existing = Invite { client_id: Some(c), email_id: a.email_id.clone(), ..Default::default() };
        assert_eq!(err(s.invite_create(&sys, existing.clone()).await).0, StatusCode::FORBIDDEN);
        assert_eq!(err(s.invite_create(&sys, Invite { profile_id: Some(p2), ..existing.clone() }).await).0, StatusCode::FORBIDDEN);
        let added = s.invite_create(&sys, Invite { profile_id: Some(p1), ..existing.clone() }).await.unwrap();
        assert_eq!(added["existingUser"], true);
        // Which identity is taken.
        let (st, msg) = err(s.invite_create(&sys, Invite { phone_number: Some("+19999".into()), ..existing.clone() }).await);
        assert_eq!(st, StatusCode::CONFLICT, "{msg}");
        let by_phone = Invite { client_id: Some(c), email_id: Some(mail("i4")), phone_number: Some(phone.clone()), ..Default::default() };
        assert!(err(s.invite_create(&sys, by_phone).await).1.contains("phone"));
        let by_name = Invite { client_id: Some(c), user_name: b.user_name.clone(), email_id: Some(mail("i5")), ..Default::default() };
        assert!(err(s.invite_create(&sys, by_name).await).1.contains("user name"));
        // Revoking: refused for a client the caller does not manage.
        let code = created["userRequest"]["inviteCode"].as_str().unwrap().to_string();
        assert_eq!(err(s.invite_revoke(&below, &code).await).0, StatusCode::FORBIDDEN);
        assert_eq!(err(s.invite_revoke(&sys, "nope").await).0, StatusCode::FORBIDDEN);
        // The page, filtered to an app's profiles and a condition.
        let page = Pageable::from_params(&Params::default());
        let cond = Cond::Filter(Filter::eq("clientId", c.to_string()));
        s.invite_page(&sys, &page, Some(cond.clone()), Some(2)).await.unwrap();
        s.invite_page(&sys, &page, None, Some(NONE)).await.unwrap();

        // ---- accepting ----
        let mut on_c = crate::admin::users::testkit::anonymous(c, "ZZRUL");
        let reg = |code: &str, pass: Value| {
            let mut body = json!({"inviteCode": code});
            for (k, v) in pass.as_object().unwrap() {
                body[k] = v.clone();
            }
            RegistrationBody::read(body.as_object().unwrap()).unwrap()
        };
        // An invite with every identifier, a profile and a PIN.
        let full = Invite { client_id: Some(c), user_name: Some(format!("zzrl{run}k1")), email_id: Some(mail("k1")), phone_number: Some(format!("+9101{}", &run[run.len() - 6..])), profile_id: Some(p1), ..Default::default() };
        let full = s.invite_create(&sys, full).await.unwrap()["userRequest"]["inviteCode"].as_str().unwrap().to_string();
        let mut no_app = on_c.clone();
        no_app.url_app_code = None;
        let no_code = RegistrationBody::read(json!({"passType": "PASSWORD", "password": PASSWORD}).as_object().unwrap()).unwrap();
        assert_eq!(err(s.invite_accept(&on_c, &no_code, &info()).await).0, StatusCode::FORBIDDEN, "no invite code");
        assert_eq!(err(s.invite_accept(&no_app, &reg(&full, json!({"passType": "PASSWORD", "password": PASSWORD})), &info()).await).0, StatusCode::FORBIDDEN);
        let otp = s.invite_create(&sys, Invite { client_id: Some(c), email_id: Some(mail("k2")), ..Default::default() }).await.unwrap()["userRequest"]["inviteCode"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(err(s.invite_accept(&on_c, &reg(&otp, json!({"passType": "OTP", "otp": "1"})), &info()).await).0, StatusCode::FORBIDDEN, "OTP sets no secret");
        // An Owner's cached sub-org (every user of the client) must drop when the invite makes a
        // user, or a transfer to the new user is refused until it expires (LZT-1716).
        let owner_key = format!("{c}:owner");
        s.caches().id_lists.insert(crate::caches::USER_SUB_ORG, owner_key.clone(), std::sync::Arc::new(vec![])).await;
        assert!(s.caches().id_lists.get(crate::caches::USER_SUB_ORG, &owner_key).await.is_some());
        let (body, _) = s.invite_accept(&on_c, &reg(&full, json!({"passType": "PIN", "pin": "1234"})), &info()).await.map_err(|e| e.to_string()).unwrap_or_else(|e| (json!({"error": e}), None));
        // The user is made, with the invite's identifiers and profile; signing in with a PIN is
        // then refused, as appbuilder has no PIN sign-in for the client.
        assert!(body["error"].as_str().unwrap().contains("403"), "{body}");
        let made = fx.ids(&format!("SELECT ID FROM security_user WHERE CLIENT_ID = {c} AND USER_NAME = 'zzrl{run}k1' AND PHONE_NUMBER IS NOT NULL")).await;
        assert_eq!(made.len(), 1);
        assert!(s.caches().id_lists.get(crate::caches::USER_SUB_ORG, &owner_key).await.is_none(), "the owner sub-org cache is dropped");
        assert_eq!(s.db.assigned_profile_ids(made[0], Some(2)).await.unwrap(), vec![p1]);
        let twin = s.invite_create(&sys, Invite { client_id: Some(c), email_id: Some(mail("k3")), ..Default::default() }).await.unwrap()["userRequest"]["inviteCode"]
            .as_str()
            .unwrap()
            .to_string();
        s.user_create(&sys, User { client_id: c, email_id: Some(mail("k3")), status_code: "ACTIVE".into(), ..Default::default() }).await.unwrap();
        assert_eq!(err(s.invite_accept(&on_c, &reg(&twin, json!({"passType": "PASSWORD", "password": PASSWORD})), &info()).await).0, StatusCode::CONFLICT);
        on_c.url_app_code = Some("appbuilder".into());

        // An invite whose password is blank: the user is made with Java's "null" secret, and the
        // sign-in that follows fails.
        let blank = s.invite_create(&sys, Invite { client_id: Some(c), email_id: Some(mail("k4")), ..Default::default() }).await.unwrap()["userRequest"]["inviteCode"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(s.invite_accept(&on_c, &reg(&blank, json!({"passType": "PASSWORD", "password": " "})), &info()).await.is_err());
        // No app on the request: no user check for a new invite.
        let mut plain = sys.clone();
        plain.url_app_code = None;
        s.invite_create(&plain, Invite { client_id: Some(c), ..new(&mail("k5")) }).await.unwrap();
        // The names of an invite or a request whose ids name nothing.
        let names = s.invite_names(&Invite { client_id: None, profile_id: Some(NONE), ..Default::default() }).await.unwrap();
        assert!(names.client.is_none() && names.profile.is_none());
        let names = s.request_names(&AccessRequest { user_id: Some(NONE), client_id: None, app_id: Some(NONE), ..Default::default() }).await.unwrap();
        assert!(names.requester.is_none() && names.client.is_none() && names.app_code.is_none());
        let names = s.request_names(&AccessRequest { user_id: None, ..Default::default() }).await.unwrap();
        assert!(names.requester.is_none());

        // ---- access requests ----
        let mut ca = fx.as_user(&b, "ZZRUL", &["Authorities.Logged_IN"]);
        let mut unknown_client = ca.clone();
        unknown_client.client_code = Some("NOSUCH".into());
        assert_eq!(err(s.request_create(&unknown_client, Some("appbuilder")).await).0, StatusCode::FORBIDDEN);
        unknown_client.client_code = None;
        assert_eq!(err(s.request_create(&unknown_client, Some("appbuilder")).await).0, StatusCode::FORBIDDEN);
        assert_eq!(err(s.request_create(&ca, Some("nosuchapp")).await).0, StatusCode::FORBIDDEN);
        assert_eq!(err(s.request_create(&ca, None).await).0, StatusCode::FORBIDDEN);
        assert!(!s.request_pending(&ca, "nosuchapp").await.unwrap());
        let r1 = s.request_create(&ca, Some("appbuilder")).await.unwrap();
        let rid1 = r1["requestId"].as_str().unwrap().to_string();
        let r2 = s.request_create(&ca, Some("leadzump")).await.unwrap();
        let rid2 = r2["requestId"].as_str().unwrap().to_string();
        assert_eq!(err(s.request_accept(&below, Some(&rid1), Some(p1)).await).0, StatusCode::FORBIDDEN, "not ZZRUM's");
        assert_eq!(err(s.request_accept(&sys, Some(&rid2), Some(p1)).await).0, StatusCode::FORBIDDEN, "another app's profile");
        assert_eq!(err(s.request_accept(&sys, Some(&rid1), Some(p2)).await).0, StatusCode::FORBIDDEN, "restricted to p1");
        assert!(s.request_accept(&sys, Some(&rid1), Some(p1)).await.unwrap());
        assert_eq!(err(s.request_accept(&sys, Some(&rid1), Some(p1)).await).0, StatusCode::BAD_REQUEST, "decided");
        assert!(s.request_reject(&sys, &rid2).await.unwrap());
        assert_eq!(err(s.request_reject(&sys, &rid2).await).0, StatusCode::BAD_REQUEST);
        ca.user.string_authorities = Some(vec!["Authorities.Logged_IN".into()]);
        let (st, msg) = err(s.request_create(&ca, Some("appbuilder")).await);
        assert_eq!(st, StatusCode::BAD_REQUEST, "already has a profile of appbuilder: {msg}");
        s.request_page(&sys, &page, Some(cond), Some(&format!("zzrl{run}b"))).await.unwrap();
        assert_eq!(s.request_user(&sys, &rid1).await.unwrap().id, b.id);
        fx.finish().await;
    }

    /// Keeps the `urlPrefix` of every `USER_INVITED` it is handed.
    #[derive(Default)]
    struct Recorded(std::sync::Mutex<Vec<String>>);

    #[async_trait::async_trait]
    impl crate::events::EventSink for Recorded {
        async fn publish(&self, e: &EventMessage) -> AuthResult<bool> {
            let prefix = e.data.iter().find(|(k, _)| k == "urlPrefix").and_then(|(_, v)| v.as_str()).unwrap_or("<none>");
            self.0.lock().unwrap().push(prefix.to_string());
            Ok(true)
        }
    }

    /// RS3 and RS4: the invite mail's `urlPrefix` on a scratch app of SYSTEM, for an invite into
    /// ZZRUM: the platform address while neither ZZRUM nor the owner has a URL, whatever another
    /// client's LIVE row says; then the owner's LIVE row; then the owner's `URL` property over it;
    /// then ZZRUM's own LIVE row over the owner's; then ZZRUM's `URL` property over that. Then
    /// `POST users/invite` carries the same prefix.
    #[tokio::test]
    async fn invite_url_prefix_is_the_invited_clients_or_the_platforms() {
        let Some(mut fx) = fx().await else { return };
        let prefix = "zzrsinv";
        crate::admin::clients::testlive::remove_leftovers(&fx.s, prefix).await;
        let sys = sys();
        let (c, m) = (fx.c, fx.m);
        let code = crate::admin::clients::testlive::scratch_code(prefix);
        let made = crate::admin::clients::testlive::scratch_app(&fx.s, &sys, json!({"appName": "ZZ RS3 invite", "appCode": code})).await;
        let app_id = crate::admin::clients::testlive::id_of(&made);
        let app = fx.s.dir().app_by_code(&code).await.unwrap().unwrap();
        let owner = app.client_id;
        assert_eq!(owner, 1);
        let pool = fx.s.db.pool.clone();
        let exec = |sql: String| {
            let pool = pool.clone();
            async move { sqlx::query(&sql).execute(&pool).await.unwrap() }
        };
        let s = fx.s.clone();
        let url_of = |s: Arc<Admin>, code: String| async move { s.invite_url_prefix(&code, m).await.unwrap() };
        let platform = platform_app_url(&code, &s.dir().subdomain_endings);
        assert_eq!(platform, format!("https://{code}.local.modlix.com"));

        // Nothing of ZZRUM's or the owner's: the platform address.
        assert_eq!(url_of(s.clone(), code.clone()).await, platform);
        // Another client's (a sibling's) LIVE row never reaches it.
        exec(format!("INSERT INTO security_client_url (CLIENT_ID, URL_PATTERN, APP_CODE, URL_TYPE) VALUES ({c}, 'zzrs3-c.example.test', '{code}', 'LIVE')")).await;
        assert_eq!(url_of(s.clone(), code.clone()).await, platform);
        // RS4: no URL of ZZRUM's, the owner's LIVE row, then the owner's `URL` property over it.
        exec(format!("INSERT INTO security_client_url (CLIENT_ID, URL_PATTERN, APP_CODE, URL_TYPE) VALUES ({owner}, 'zzrs3-owner-live.example.test', '{code}', 'LIVE')")).await;
        assert_eq!(url_of(s.clone(), code.clone()).await, "https://zzrs3-owner-live.example.test");
        exec(format!("INSERT INTO security_app_property (APP_ID, CLIENT_ID, NAME, VALUE) VALUES ({app_id}, {owner}, 'URL', 'zzrs3-owner.example.test/')")).await;
        assert_eq!(url_of(s.clone(), code.clone()).await, "https://zzrs3-owner.example.test");
        // ZZRUM's own LIVE row wins over the owner's, as `checkUrl` writes it.
        exec(format!("INSERT INTO security_client_url (CLIENT_ID, URL_PATTERN, APP_CODE, URL_TYPE) VALUES ({m}, 'zzrs3-live.example.test', '{code}', 'LIVE')")).await;
        assert_eq!(url_of(s.clone(), code.clone()).await, "https://zzrs3-live.example.test");
        // ZZRUM's `URL` property comes first.
        exec(format!("INSERT INTO security_app_property (APP_ID, CLIENT_ID, NAME, VALUE) VALUES ({app_id}, {m}, 'URL', 'https://zzrs3-m.example.test/')")).await;
        assert_eq!(url_of(s.clone(), code.clone()).await, "https://zzrs3-m.example.test");
        // Another client's newer LIVE row still does not reach it.
        exec(format!("DELETE FROM security_app_property WHERE APP_ID = {app_id} AND CLIENT_ID = {m}")).await;
        exec(format!("UPDATE security_client_url SET UPDATED_AT = NOW() + INTERVAL 1 MINUTE WHERE APP_CODE = '{code}' AND CLIENT_ID = {c}")).await;
        assert_eq!(url_of(s.clone(), code.clone()).await, "https://zzrs3-live.example.test");

        exec(format!("DELETE FROM security_client_url WHERE APP_CODE = '{code}' AND URL_TYPE = 'LIVE'")).await;
        exec(format!("DELETE FROM security_app_property WHERE APP_ID = {app_id}")).await;
        crate::admin::clients::testlive::remove_app(&s, &sys, app_id).await;

        // Through the route, as SYSTEM: the mail carries what the lookup answers for ZZRUM.
        let rec = Arc::new(Recorded::default());
        let recording = Arc::new(Admin { internal: s.internal.clone(), events: rec.clone(), files: s.files.clone(), hosting: s.hosting.clone() });
        fx.router = crate::admin::router(recording);
        let h = [("authorization", basic_142()), ("clientcode", "SYSTEM".to_string()), ("appcode", "leadzump".to_string())];
        let expected = s.invite_url_prefix("leadzump", m).await.unwrap();
        assert!(expected.starts_with("https://"), "{expected}");
        let (st, v) = fx.http_with("POST", "/users/invite", &h, Some(json!({"clientId": m, "emailId": format!("zzrl{}u1@example.invalid", fx.run)}))).await;
        assert_eq!(st, StatusCode::OK, "{v}");
        assert_eq!(rec.0.lock().unwrap().pop(), Some(expected));
        fx.finish().await;
    }

    fn basic_142() -> String {
        use base64::Engine;
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("142:{PASSWORD}")))
    }
}
