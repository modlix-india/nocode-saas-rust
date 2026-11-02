//! `UserService`'s password routes: a signed-in change (`updatePassword`, for oneself or a user
//! one manages), the anonymous reset by OTP (`reset/password/otp/generate`, `/verify`,
//! `reset/password`), the password / PIN policy checks they run (`ClientPasswordPolicyService`,
//! `ClientPinPolicyService`), and the sign-in client picker (`findUserClients`).

use axum::http::StatusCode;
use axum::routing::post;
use axum::Router;
use serde_json::{Map, Value};

use super::accounts::describe;
use super::common::{object_body, Fields};
use crate::admin::{Admin, AdminState};
use crate::data::audit::{action, activity, object, sox};
use crate::data::users_admin::SecretPolicy;
use crate::dto::{client_json, ClientExtras};
use crate::errors::{AuthError, AuthResult};
use crate::events::EventMessage;
use crate::jackson::{json, Obj};
use crate::model::{ContextAuth, User};
use crate::otp::{OtpPurpose, OtpRequest};
use crate::signin::{matches_secret, AuthRequest};
use crate::store::UserQuery;
use crate::web::unreadable;

/// `AuthenticationPasswordType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretType {
    Password,
    Pin,
    Otp,
}

impl SecretType {
    /// The constant's name (`toString()`).
    pub fn constant(self) -> &'static str {
        match self {
            Self::Password => "PASSWORD",
            Self::Pin => "PIN",
            Self::Otp => "OTP",
        }
    }

    /// `getName()`.
    pub fn display(self) -> &'static str {
        match self {
            Self::Password => "Password",
            Self::Pin => "PIN",
            Self::Otp => "OTP",
        }
    }

    fn from_json(v: &Value) -> Result<Option<Self>, ()> {
        const ALL: [SecretType; 3] = [SecretType::Password, SecretType::Pin, SecretType::Otp];
        match v {
            Value::Null => Ok(None),
            Value::String(s) => ALL.iter().find(|t| t.constant() == s).copied().map(Some).ok_or(()),
            Value::Number(n) => n.as_u64().and_then(|i| ALL.get(i as usize)).copied().map(Some).ok_or(()),
            _ => Err(()),
        }
    }
}

/// `RequestUpdatePassword` (`passType` defaults to `PASSWORD`; an explicit null stays null).
#[derive(Debug, Clone, Default)]
pub struct PasswordBody {
    pub auth_request: Option<AuthRequest>,
    pub old_password: Option<String>,
    pub new_password: Option<String>,
    pub pass_type: Option<SecretType>,
}

impl PasswordBody {
    pub fn read(m: &Map<String, Value>) -> AuthResult<Self> {
        let f = Fields(m);
        let auth_request = match m.get("authRequest") {
            None | Some(Value::Null) => None,
            Some(v @ Value::Object(_)) => Some(serde_json::from_value::<AuthRequest>(v.clone()).map_err(|_| unreadable())?),
            Some(_) => return Err(unreadable()),
        };
        let pass_type = match m.get("passType") {
            None => Some(SecretType::Password),
            Some(v) => SecretType::from_json(v).map_err(|_| unreadable())?,
        };
        Ok(Self { auth_request, old_password: f.string("oldPassword")?, new_password: f.string("newPassword")?, pass_type })
    }
}

fn npe(what: &str) -> AuthError {
    AuthError::internal(format!("Cannot invoke \"{what}\""))
}

fn bad(key: &str, params: &[&str]) -> AuthError {
    AuthError::msg(StatusCode::BAD_REQUEST, key, params)
}

fn forbidden(key: &str, params: &[&str]) -> AuthError {
    AuthError::msg(StatusCode::FORBIDDEN, key, params)
}

/// `String.compareToIgnoreCase`: UTF-16 units folded upper then lower case.
fn compare_ignore_case(a: &str, b: &str) -> std::cmp::Ordering {
    let fold = |c: u16| -> u32 {
        let ch = char::from_u32(u32::from(c)).unwrap_or('\u{0}');
        let up = ch.to_uppercase().next().unwrap_or(ch);
        let low = up.to_lowercase().next().unwrap_or(up);
        if up.len_utf16() == 1 && low.len_utf16() == 1 { low as u32 } else { u32::from(c) }
    };
    let (x, y): (Vec<u16>, Vec<u16>) = (a.encode_utf16().collect(), b.encode_utf16().collect());
    for (p, q) in x.iter().zip(y.iter()) {
        let (p, q) = (fold(*p), fold(*q));
        if p != q {
            return p.cmp(&q);
        }
    }
    x.len().cmp(&y.len())
}

/// What `secret_change_rule` asks of the caller before a secret is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecretGate {
    /// Nothing more (one's own secret, whose old value `isPasswordUpdatable` checks).
    Allowed,
    /// Refused: another user's secret needs `User_UPDATE`.
    NoAuthority,
    /// The caller's client must manage the target's client.
    ManagedClient,
    /// The target must be the caller or below them in the reporting tree.
    SubOrg,
}

/// `checkHierarchy`, tightened (2026-10-30): Java let anyone signed in set the secret of any
/// user of their own client (no authority, no old secret), so a Sales Member could reset the
/// Owner's password. Now another user's secret needs `User_UPDATE` always; for a user of the
/// caller's own client also the reporting line, unless the caller sees the whole client (an
/// Owner, or `ROLE_Client_MANAGE` as in `readPageFilter`). SYSTEM's callers keep the reach every
/// other user route gives them; a user of another client still needs it to be managed.
fn secret_change_rule(ca: &ContextAuth, target: u64, target_client: u64) -> SecretGate {
    use super::accounts::{CLIENT_MANAGE_ROLE, OWNER_ROLE};
    use super::common::has_any;
    if target == ca.user.id() {
        return SecretGate::Allowed;
    }
    if !has_any(ca, &["Authorities.User_UPDATE"]) {
        return SecretGate::NoAuthority;
    }
    if ca.is_system_client() {
        return SecretGate::Allowed;
    }
    if target_client != ca.user.client_id() {
        return SecretGate::ManagedClient;
    }
    if has_any(ca, &[OWNER_ROLE, CLIENT_MANAGE_ROLE]) {
        return SecretGate::Allowed;
    }
    SecretGate::SubOrg
}

/// The special characters `ClientPasswordPolicyService` accepts.
const SPECIAL: &str = "~`!@#$%^&*()_-+={}[]|\\/:;\"'<>,.?";

impl Admin {
    /// `AbstractPolicyService.getClientAppPolicy(clientId, appId)` for passwords and PINs: the
    /// first policy up the hierarchy, else the default.
    async fn secret_policy_for(&self, client_id: u64, app_id: u64, pin: bool) -> AuthResult<SecretPolicy> {
        for cid in self.dir().hierarchy(client_id).await?.client_ids() {
            if let Some(p) = self.db.secret_policy(cid, app_id, pin).await? {
                return Ok(p);
            }
        }
        Ok(if pin { SecretPolicy::default_pin() } else { SecretPolicy::default_password() })
    }

    /// `checkAllConditions` of the password and PIN policies.
    async fn check_secret_policy(&self, p: &SecretPolicy, user_id: Option<u64>, secret: &str, pin: bool) -> AuthResult<()> {
        let name = if pin { "PIN" } else { "Password" };
        let used = || bad("password_used_error", &[name, name]);
        let len = secret.encode_utf16().count() as i64;
        if pin {
            if let Some(l) = p.length {
                if len != l {
                    return Err(bad("length_error", &[name, &l.to_string()]));
                }
            }
        }
        if let Some(uid) = user_id {
            for (stored, hashed) in self.db.past_secrets(uid, p.history, pin).await? {
                if matches_secret(uid, secret, Some(&stored), hashed) {
                    return Err(used());
                }
            }
        }
        if pin {
            return Ok(());
        }
        let none_in = |lo: char, hi: char| !secret.chars().any(|c| (lo..=hi).contains(&c));
        if p.upper && none_in('A', 'Z') {
            return Err(bad("capital_letters_missing", &[]));
        }
        if p.lower && none_in('a', 'z') {
            return Err(bad("small_letters_missing", &[]));
        }
        if p.digit && none_in('0', '9') {
            return Err(bad("numbers_missing", &[]));
        }
        if p.special && !secret.chars().any(|c| SPECIAL.contains(c)) {
            return Err(bad("special_characters_missing", &[]));
        }
        if !p.spaces_allowed && secret.contains(' ') {
            return Err(bad("spaces_missing", &[]));
        }
        if let Some(re) = p.regex.as_deref().filter(|r| !r.trim().is_empty()) {
            let re = regex::Regex::new(re).map_err(AuthError::internal)?;
            if !re.is_match(secret) {
                return Err(bad("regex_mismatch", &[]));
            }
        }
        if let Some(max) = p.max_length {
            if len > max {
                return Err(bad("max_length_error", &[&max.to_string()]));
            }
        }
        if let Some(min) = p.min_length {
            if len < min {
                return Err(bad("min_length_error", &[&min.to_string()]));
            }
        }
        Ok(())
    }

    /// `ClientService.validatePasswordPolicy(clientId, appCode, userId, type, password)`: true
    /// when the app is unknown; OTP has no conditions.
    async fn validate_secret_policy(&self, client_id: u64, app_code: Option<&str>, user_id: Option<u64>, t: Option<SecretType>, secret: &str) -> AuthResult<()> {
        let Some(app) = (match app_code {
            Some(a) => self.dir().app_by_code(a).await?,
            None => None,
        }) else {
            return Ok(());
        };
        let Some(t) = t else {
            return Err(AuthError::internal(
                "Cannot invoke \"com.fincity.security.service.policy.IPolicyService.checkAllConditions(org.jooq.types.ULong, org.jooq.types.ULong, org.jooq.types.ULong, String)\" because the return value of \"java.util.EnumMap.get(Object)\" is null",
            ));
        };
        match t {
            SecretType::Otp => Ok(()),
            SecretType::Password | SecretType::Pin => {
                let pin = t == SecretType::Pin;
                let p = self.secret_policy_for(client_id, app.id, pin).await?;
                self.check_secret_policy(&p, user_id, secret, pin).await
            }
        }
    }

    /// `ClientService.validatePasswordPolicy(clientId, appId, null, type, password)`.
    pub(crate) async fn check_policy_for(&self, client_id: u64, app_id: u64, t: SecretType, secret: &str) -> AuthResult<()> {
        match t {
            SecretType::Otp => Ok(()),
            SecretType::Password | SecretType::Pin => {
                let pin = t == SecretType::Pin;
                let p = self.secret_policy_for(client_id, app_id, pin).await?;
                self.check_secret_policy(&p, None, secret, pin).await
            }
        }
    }

    /// `checkPassword`: does the given secret (blank counts as matching) match the stored one?
    fn secret_matches(u: &User, given: Option<&str>, t: Option<SecretType>) -> AuthResult<bool> {
        let t = t.ok_or_else(|| npe("com.fincity.security.model.AuthenticationPasswordType.ordinal()"))?;
        let blank = given.is_none_or(|g| g.trim().is_empty());
        Ok(match t {
            SecretType::Password => blank || matches_secret(u.id, given.unwrap_or(""), u.password.as_deref(), u.password_hashed),
            SecretType::Pin => blank || matches_secret(u.id, given.unwrap_or(""), u.pin.as_deref(), u.pin_hashed),
            SecretType::Otp => false,
        })
    }

    /// `isPasswordUpdatable`: a new secret, unlike the old (when changing one's own), within the
    /// policy of the client signed in from.
    async fn password_updatable(&self, ca: &ContextAuth, u: &User, b: &PasswordBody, is_update: bool) -> AuthResult<()> {
        let Some(new) = b.new_password.as_deref().filter(|p| !p.trim().is_empty()) else {
            return Err(forbidden("new_password_missing", &[]));
        };
        if is_update && u.id == ca.user.id() {
            if !Self::secret_matches(u, b.old_password.as_deref(), b.pass_type)? {
                return Err(forbidden("old_password_match", &[]));
            }
            if Self::secret_matches(u, Some(new), b.pass_type)? {
                return Err(forbidden("new_password_match", &[]));
            }
        }
        self.validate_secret_policy(ca.logged_in_from_client_id.unwrap_or_default(), ca.url_app_code.as_deref(), Some(u.id), b.pass_type, new).await
    }

    /// `updatePasswordInternal`: the secret set, logged, announced, tokens evicted, user
    /// unlocked.
    async fn set_user_secret(&self, ca: &ContextAuth, u: &User, current_user: u64, t: SecretType, new: &str, reset: bool) -> AuthResult<bool> {
        let set = match t {
            SecretType::Password | SecretType::Pin => {
                let hash = bcrypt::hash_with_result(format!("{}{new}", u.id), 10)
                    .map(|h| h.format_for_version(bcrypt::Version::TwoA))
                    .map_err(AuthError::internal)?;
                self.db.set_secret(u.id, current_user, &hash, t == SecretType::Pin).await? > 0
            }
            SecretType::Otp => false,
        };
        if !set {
            return Err(forbidden("$ cannot be updated", &[t.constant()]));
        }
        let label = describe(u).unwrap_or_else(|| "null".into());
        let text = format!("{} updated for {label}", t.constant());
        sox(&self.db, Some(u.id), object::USER, action::OTHER, text.clone(), None);
        activity(&self.db, Some(u.client_id), "User Password Changed".into(), text, None);
        let event_name = if reset { format!("USER_{}_RESET_DONE", t.constant()) } else { format!("USER_{}_CHANGED", t.constant()) };
        let event = EventMessage {
            event_name,
            client_code: ca.url_client_code.clone(),
            app_code: ca.url_app_code.clone(),
            x_debug: None,
            draft: false,
            data: vec![("user".into(), crate::dto::user_json(u, &Default::default()))],
        };
        let sent = self.events.publish(&event).await?;
        self.evict_tokens(u.id).await?;
        self.db.user_status_to_active(u.id).await?;
        Ok(sent)
    }

    /// `updatePassword(userId, request)` (and, with the caller's id, `updatePassword(request)`).
    /// Who may set whose secret is `secret_change_rule`; the gate runs before the policy checks,
    /// so a refused caller learns nothing about the target's policy or history.
    pub async fn update_password(&self, ca: &ContextAuth, user_id: Option<u64>, b: &PasswordBody) -> AuthResult<bool> {
        if !ca.authenticated {
            return Err(forbidden("login_required", &[]));
        }
        let id = user_id.unwrap_or(ca.user.id());
        let Some(u) = self.db.user_row(id).await? else { return Ok(false) };
        let allowed = match secret_change_rule(ca, u.id, u.client_id) {
            SecretGate::Allowed => true,
            SecretGate::NoAuthority => return Err(forbidden(crate::errors::FORBIDDEN_PERMISSION, &["User UPDATE"])),
            SecretGate::ManagedClient => self.caller_manages_client(ca, u.client_id).await?,
            SecretGate::SubOrg => self.sub_org_allows(ca, u.client_id, u.id).await?,
        };
        if !allowed {
            return Err(forbidden("hierarchy_error", &[]));
        }
        self.password_updatable(ca, &u, b, true).await?;
        let t = b.pass_type.ok_or_else(|| npe("java.util.Map.get(Object)"))?;
        self.set_user_secret(ca, &u, ca.user.id(), t, b.new_password.as_deref().unwrap_or(""), false).await
    }

    /// `findNonDeletedUserNClient` + `checkUserAndClient` for the anonymous reset routes.
    async fn reset_user(&self, ca: &ContextAuth, r: &AuthRequest) -> AuthResult<Option<crate::context::Found>> {
        if ca.authenticated {
            return Err(forbidden("pass_reset_req_error", &[]));
        }
        let client = ca.url_client_code.as_deref();
        let Some(found) = self.auth.find_user(r.user_name.as_deref(), r.user_id, client, None, r.identifier(), false).await? else {
            return Ok(None);
        };
        Ok(crate::context::check_user_and_client(&found, client).then_some(found))
    }

    /// `generateOtpResetPassword`.
    pub async fn reset_otp_generate(&self, ca: &ContextAuth, r: &AuthRequest, ip: Option<String>, x_debug: Option<String>) -> AuthResult<bool> {
        let Some(found) = self.reset_user(ca, r).await? else { return Ok(false) };
        let Some(app) = (match ca.url_app_code.as_deref() {
            Some(a) => self.dir().app_by_code(a).await?,
            None => None,
        }) else {
            return Ok(false);
        };
        let blank_none = |s: Option<String>| s.filter(|v| !v.trim().is_empty());
        let req = OtpRequest {
            client_id: found.url_client.id(),
            client_code: found.url_client.code.clone(),
            app_id: app.id,
            app_code: app.app_code.clone(),
            app_name: app.app_name.clone(),
            user_id: Some(found.user.id),
            email_id: blank_none(found.user.email_id()),
            phone_number: blank_none(found.user.phone_number()),
            ip_address: ip,
            resend: r.resend,
            x_debug,
            purpose: Some(OtpPurpose::PasswordReset),
            with_user: true,
        };
        self.auth.generate_otp_internal(&req).await
    }

    /// `verifyOtpResetPassword`.
    pub async fn reset_otp_verify(&self, ca: &ContextAuth, r: &AuthRequest) -> AuthResult<bool> {
        let Some(found) = self.reset_user(ca, r).await? else { return Ok(false) };
        if self.auth.verify_user_otp(ca.url_app_code.as_deref(), found.user.id, OtpPurpose::PasswordReset, r.otp.as_deref()).await? {
            return Ok(true);
        }
        Err(forbidden("user_password_invalid", &["OTP", "OTP"]))
    }

    /// `resetPassword`.
    pub async fn reset_password(&self, ca: &ContextAuth, b: &PasswordBody) -> AuthResult<bool> {
        let Some(r) = b.auth_request.as_ref() else {
            return Err(AuthError::internal("Cannot invoke \"com.fincity.security.model.AuthenticationRequest.getOtp()\" because \"authRequest\" is null"));
        };
        let Some(found) = self.reset_user(ca, r).await? else {
            return Ok(false);
        };
        if found.user.status_code != "ACTIVE" {
            return Err(forbidden("user_not_active", &[]));
        }
        self.password_updatable(ca, &found.user, b, false).await?;
        if !self.auth.verify_user_otp(ca.url_app_code.as_deref(), found.user.id, OtpPurpose::PasswordReset, r.otp.as_deref()).await? {
            return Err(forbidden("user_password_invalid", &["OTP", "OTP"]));
        }
        let t = b.pass_type.ok_or_else(|| npe("java.util.Map.get(Object)"))?;
        self.set_user_secret(ca, &found.user, found.user.id, t, b.new_password.as_deref().unwrap_or(""), true).await
    }

    /// `findUserClients`: every client the identity has a (non-deleted) user in, under the
    /// request's client (and app, unless `appLevel=false`), active ones only, by client name.
    pub async fn find_user_clients(&self, r: &AuthRequest, app_code: Option<String>, client_code: Option<String>) -> AuthResult<Vec<Value>> {
        let q = UserQuery {
            user_name: r.user_name.clone(),
            identifier: r.identifier(),
            user_id: r.user_id,
            client_code,
            app_code,
            active_client_only: false,
            limit: u32::MAX,
        };
        let users = self.dir().store.users_by(&q).await?;
        let pairs: Vec<(i32, (u64, u64))> = users.iter().map(|u| (crate::javamap::long_hash(u.id), (u.id, u.client_id))).collect();
        let mut out: Vec<(Option<String>, Value)> = Vec::new();
        for (user_id, client_id) in crate::javamap::iteration_order(pairs) {
            let Some(client) = self.dir().client(client_id).await? else { continue };
            if client.status_code.as_deref() != Some("ACTIVE") {
                continue;
            }
            let managing = self.dir().managed_client(client_id).await?;
            let x = ClientExtras { managing_client: Some(managing), ..Default::default() };
            out.push((client.name.clone(), Obj::new().put("userId", user_id).put("client", client_json(&client, &x)).build()));
        }
        out.sort_by(|(a, _), (b, _)| match (a, b) {
            (None, None) => std::cmp::Ordering::Equal,
            (None, _) => std::cmp::Ordering::Greater,
            (_, None) => std::cmp::Ordering::Less,
            (Some(a), Some(b)) => compare_ignore_case(a, b),
        });
        Ok(out.into_iter().map(|(_, v)| v).collect())
    }
}

macro_rules! r {
    ($name:ident, $path:expr, $protected:expr, |$s:ident, $r:ident, $ca:ident| $body:block) => {
        $crate::web_route!($name, AdminState, $path, $protected, |$s, $r, $ca| $body);
    };
}

fn auth_body(bytes: &[u8]) -> AuthResult<AuthRequest> {
    crate::handlers::body::<AuthRequest>(bytes)
}

r!(update_mine, "/users/updatePassword", true, |s, r, ca| {
    let b = PasswordBody::read(&object_body(&r.body)?)?;
    Ok(json(&Value::Bool(s.update_password(&ca, None, &b).await?)))
});

crate::web_route_path!(update_theirs, AdminState, "/users/{userId}/updatePassword", true, |s, r, ca, user| {
    let user = crate::web::to_u64(&user)?;
    let b = PasswordBody::read(&object_body(&r.body)?)?;
    Ok(json(&Value::Bool(s.update_password(&ca, Some(user), &b).await?)))
});

r!(reset_generate, "/users/reset/password/otp/generate", false, |s, r, ca| {
    let body = auth_body(&r.body)?;
    Ok(json(&Value::Bool(s.reset_otp_generate(&ca, &body, r.info.remote_host(), r.info.header("x-debug")).await?)))
});

r!(reset_verify, "/users/reset/password/otp/verify", false, |s, r, ca| {
    let body = auth_body(&r.body)?;
    Ok(json(&Value::Bool(s.reset_otp_verify(&ca, &body).await?)))
});

r!(reset, "/users/reset/password", false, |s, r, ca| {
    let b = PasswordBody::read(&object_body(&r.body)?)?;
    Ok(json(&Value::Bool(s.reset_password(&ca, &b).await?)))
});

r!(user_clients, "/users/findUserClients", false, |s, r, ca| {
    let body = auth_body(&r.body)?;
    let app_level = match r.params.get("appLevel") {
        None => true,
        Some(v) => match v.trim().to_lowercase().as_str() {
            "true" | "on" | "yes" | "1" | "" => true,
            "false" | "off" | "no" | "0" => false,
            _ => return Err(crate::web::type_mismatch()),
        },
    };
    let app_code = if app_level { r.info.header("appCode") } else { None };
    let list = s.find_user_clients(&body, app_code, r.info.header("clientCode")).await?;
    Ok(json(&Value::Array(list)))
});

pub fn router() -> Router<AdminState> {
    Router::new()
        .route("/api/security/users/updatePassword", post(update_mine))
        .route("/api/security/users/{userId}/updatePassword", post(update_theirs))
        .route("/api/security/users/reset/password/otp/generate", post(reset_generate))
        .route("/api/security/users/reset/password/otp/verify", post(reset_verify))
        .route("/api/security/users/reset/password", post(reset))
        .route("/api/security/users/findUserClients", post(user_clients))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn bodies() {
        let b = PasswordBody::read(json!({"newPassword": "N", "authRequest": {"userName": "u", "otp": "1"}}).as_object().unwrap()).unwrap();
        assert_eq!((b.pass_type, b.new_password.as_deref()), (Some(SecretType::Password), Some("N")));
        assert_eq!(b.auth_request.unwrap().user_name.as_deref(), Some("u"));
        assert_eq!(PasswordBody::read(json!({"passType": null}).as_object().unwrap()).unwrap().pass_type, None);
        assert_eq!(PasswordBody::read(json!({"passType": "PIN"}).as_object().unwrap()).unwrap().pass_type, Some(SecretType::Pin));
        assert!(PasswordBody::read(json!({"passType": "pin"}).as_object().unwrap()).is_err());
        assert!(PasswordBody::read(json!({"authRequest": 5}).as_object().unwrap()).is_err());
        assert_eq!((SecretType::Pin.constant(), SecretType::Password.display()), ("PIN", "Password"));
        let u = User { id: 3, password: Some("p".into()), password_hashed: false, ..Default::default() };
        assert!(Admin::secret_matches(&u, Some("p"), Some(SecretType::Password)).unwrap());
        assert!(Admin::secret_matches(&u, Some(" "), Some(SecretType::Password)).unwrap());
        assert!(!Admin::secret_matches(&u, Some("q"), Some(SecretType::Password)).unwrap());
        assert!(!Admin::secret_matches(&u, Some("q"), Some(SecretType::Otp)).unwrap());
        assert!(Admin::secret_matches(&u, Some("q"), None).is_err());
        assert_eq!(compare_ignore_case("abc", "ABD"), std::cmp::Ordering::Less);
        assert_eq!(compare_ignore_case("Ab", "aB"), std::cmp::Ordering::Equal);
        assert_eq!(compare_ignore_case("a", "ab"), std::cmp::Ordering::Less);
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;
    use crate::admin::users::testkit::offline;
    use serde_json::json;

    fn policy() -> SecretPolicy {
        SecretPolicy { upper: false, lower: false, digit: false, special: false, spaces_allowed: true, ..Default::default() }
    }

    /// `ClientPasswordPolicyServiceTest` / `ClientPinPolicyServiceTest`: every condition, without a
    /// user (so no history is read).
    #[tokio::test]
    async fn every_condition() {
        let s = offline();
        let check = |p: SecretPolicy, secret: &'static str, pin: bool| {
            let s = s.clone();
            async move { s.check_secret_policy(&p, None, secret, pin).await.map_err(|e| e.message()) }
        };
        assert!(check(SecretPolicy { length: Some(4), ..policy() }, "123", true).await.unwrap_err().contains("4"));
        check(SecretPolicy { length: Some(4), upper: true, ..policy() }, "1234", true).await.unwrap();
        check(SecretPolicy { length: None, ..policy() }, "12", true).await.unwrap();
        for (p, secret) in [
            (SecretPolicy { upper: true, ..policy() }, "abc"),
            (SecretPolicy { lower: true, ..policy() }, "ABC"),
            (SecretPolicy { digit: true, ..policy() }, "abc"),
            (SecretPolicy { special: true, ..policy() }, "abc1"),
            (SecretPolicy { spaces_allowed: false, ..policy() }, "a b"),
            (SecretPolicy { regex: Some("^x+$".into()), ..policy() }, "abc"),
            (SecretPolicy { max_length: Some(2), ..policy() }, "abc"),
            (SecretPolicy { min_length: Some(9), ..policy() }, "abc"),
        ] {
            assert!(check(p, secret, false).await.is_err(), "{secret}");
        }
        let bad_regex = s.check_secret_policy(&SecretPolicy { regex: Some("(".into()), ..policy() }, None, "x", false).await.unwrap_err();
        assert_eq!(bad_regex.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let all = SecretPolicy {
            upper: true,
            lower: true,
            digit: true,
            special: true,
            spaces_allowed: false,
            regex: Some("^P".into()),
            min_length: Some(8),
            max_length: Some(20),
            ..Default::default()
        };
        check(all, "Pass@1234", false).await.unwrap();
        // OTPs have no conditions; no app means nothing to check.
        s.check_policy_for(1, 2, SecretType::Otp, "x").await.unwrap();
        s.validate_secret_policy(1, None, None, None, "x").await.unwrap();
    }

    /// 2026-10-30: who may set another user's secret.
    #[test]
    fn secret_change_rule_matrix() {
        use crate::admin::users::testkit::caller;
        const UPDATE: &str = "Authorities.User_UPDATE";
        let on = |user: u64, client: u64, auths: &[&str]| caller(user, client, "ZZ", "BUS", auths);
        // Oneself: always, with or without User_UPDATE (the old secret is checked after).
        assert_eq!(secret_change_rule(&on(5, 7, &[]), 5, 7), SecretGate::Allowed);
        // A Sales-Member-style caller (no User_UPDATE): refused for anyone else, even of their own client.
        assert_eq!(secret_change_rule(&on(5, 7, &["Authorities.User_READ"]), 6, 7), SecretGate::NoAuthority);
        assert_eq!(secret_change_rule(&on(5, 7, &[]), 6, 9), SecretGate::NoAuthority);
        // An Owner without User_UPDATE is refused too: the authority is always needed.
        assert_eq!(secret_change_rule(&on(5, 7, &["Authorities.ROLE_Owner"]), 6, 7), SecretGate::NoAuthority);
        // User_UPDATE in the same client: the reporting line, unless the whole client is theirs.
        assert_eq!(secret_change_rule(&on(5, 7, &[UPDATE]), 6, 7), SecretGate::SubOrg);
        assert_eq!(secret_change_rule(&on(5, 7, &[UPDATE, "Authorities.ROLE_Owner"]), 6, 7), SecretGate::Allowed);
        assert_eq!(secret_change_rule(&on(5, 7, &[UPDATE, "Authorities.ROLE_Client_MANAGE"]), 6, 7), SecretGate::Allowed);
        // Another client: it must be managed, Owner or not.
        assert_eq!(secret_change_rule(&on(5, 7, &[UPDATE, "Authorities.ROLE_Owner"]), 6, 9), SecretGate::ManagedClient);
        // SYSTEM with User_UPDATE reaches everyone; without it, no one but itself.
        assert_eq!(secret_change_rule(&caller(5, 1, "SYSTEM", "SYS", &[UPDATE]), 6, 9), SecretGate::Allowed);
        assert_eq!(secret_change_rule(&caller(5, 1, "SYSTEM", "SYS", &[]), 6, 1), SecretGate::NoAuthority);
    }

    #[test]
    fn secret_types() {
        assert_eq!((SecretType::Otp.constant(), SecretType::Pin.display(), SecretType::Otp.display()), ("OTP", "PIN", "OTP"));
        assert_eq!(SecretType::from_json(&json!(1)), Ok(Some(SecretType::Pin)));
        assert_eq!(SecretType::from_json(&json!(7)), Err(()));
        assert_eq!(SecretType::from_json(&json!(true)), Err(()));
        let u = User { id: 3, pin: Some("12".into()), ..Default::default() };
        assert!(Admin::secret_matches(&u, Some("12"), Some(SecretType::Pin)).unwrap());
    }
}

#[cfg(test)]
mod live {
    use super::*;
    use crate::admin::users::testkit::{anonymous, fx, sys, PASSWORD};
    use serde_json::json;

    fn body(v: Value) -> PasswordBody {
        PasswordBody::read(v.as_object().unwrap()).unwrap()
    }

    /// `UserServiceTest`'s password cases on scratch users.
    #[tokio::test]
    async fn changes_resets_and_the_picker() {
        let Some(fx) = fx().await else { return };
        let (s, c, m) = (&fx.s, fx.c, fx.m);
        let sys = sys();
        let a = fx.user(c, "a").await;
        let b = fx.user(c, "b").await;
        let e = fx.user(m, "e").await;
        let not_signed_in = anonymous(c, "ZZRUL");
        assert_eq!(s.update_password(&not_signed_in, Some(a.id), &body(json!({"newPassword": PASSWORD}))).await.unwrap_err().status(), StatusCode::FORBIDDEN);
        assert!(!s.update_password(&sys, Some(crate::admin::users::testkit::NONE), &body(json!({"newPassword": PASSWORD}))).await.unwrap());
        // A caller of another client: without User_UPDATE, or not managing it.
        let from_m = fx.as_user(&e, "ZZRUM", &[]);
        assert_eq!(s.update_password(&from_m, Some(a.id), &body(json!({"newPassword": "Zz@12345"}))).await.unwrap_err().status(), StatusCode::FORBIDDEN);
        let from_m = fx.as_user(&e, "ZZRUM", &["Authorities.User_UPDATE"]);
        assert_eq!(s.update_password(&from_m, Some(a.id), &body(json!({"newPassword": "Zz@12345"}))).await.unwrap_err().status(), StatusCode::FORBIDDEN);
        // Oneself: the old secret must match.
        let me = fx.as_user(&a, "ZZRUL", &[]);
        let wrong_old = body(json!({"oldPassword": "Zz@00000", "newPassword": "Zz@12345"}));
        assert_eq!(s.update_password(&me, None, &wrong_old).await.unwrap_err().message(), crate::errors::message("old_password_match", &[]));
        // The type is read before the policy: none is Java's EnumMap miss.
        assert_eq!(s.validate_secret_policy(c, Some("appbuilder"), None, None, "x").await.unwrap_err().status(), StatusCode::INTERNAL_SERVER_ERROR);
        // An OTP is no secret one sets.
        let otp = body(json!({"newPassword": "123456", "passType": "OTP"}));
        assert_eq!(s.update_password(&sys, Some(b.id), &otp).await.unwrap_err().status(), StatusCode::FORBIDDEN);

        // ---- the reset by OTP ----
        let on_c = anonymous(c, "ZZRUL");
        let who = |u: &User| AuthRequest { user_name: u.email_id.clone(), ..Default::default() };
        let nobody = AuthRequest { user_name: Some("nobody@example.invalid".into()), ..Default::default() };
        assert!(!s.reset_otp_generate(&on_c, &nobody, None, None).await.unwrap());
        let mut no_app = on_c.clone();
        no_app.url_app_code = Some("nosuchapp".into());
        assert!(!s.reset_otp_generate(&no_app, &who(&a), None, None).await.unwrap());
        no_app.url_app_code = None;
        assert!(!s.reset_otp_generate(&no_app, &who(&a), None, None).await.unwrap());
        assert!(!s.reset_otp_verify(&on_c, &nobody).await.unwrap());
        let wrong = AuthRequest { otp: Some("000000".into()), ..who(&a) };
        assert_eq!(s.reset_otp_verify(&on_c, &wrong).await.unwrap_err().status(), StatusCode::FORBIDDEN);
        assert!(!s.reset_password(&on_c, &body(json!({"authRequest": {"userName": "nobody@example.invalid"}, "newPassword": PASSWORD}))).await.unwrap());
        s.user_set_active(&sys, Some(b.id), false).await.unwrap();
        let inactive = body(json!({"authRequest": {"userName": b.email_id, "otp": "1"}, "newPassword": PASSWORD}));
        let r = s.reset_password(&on_c, &inactive).await;
        assert!(matches!(r, Ok(false)) || r.as_ref().is_err_and(|e| e.status() == StatusCode::FORBIDDEN), "{r:?}");

        // ---- the client picker: users of several clients, sorted by name ----
        let ids = [a.id, e.id];
        let picker = s.find_user_clients(&AuthRequest { user_name: None, ..Default::default() }, None, Some("ZZRUL".into())).await.unwrap();
        let listed: Vec<u64> = picker.iter().filter_map(|v| v["userId"].as_u64()).collect();
        assert!(ids.iter().all(|i| listed.contains(i)), "{listed:?}");
        let names: Vec<String> = picker.iter().map(|v| v["client"]["name"].as_str().unwrap_or("").to_lowercase()).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
        // An inactive client is left out.
        let (st, _) = fx.http("GET", &format!("/clients/makeClientInActive?clientId={m}"), None).await;
        assert_eq!(st, StatusCode::OK);
        let picker = s.find_user_clients(&AuthRequest::default(), None, Some("ZZRUL".into())).await.unwrap();
        assert!(!picker.iter().any(|v| v["userId"] == e.id));
        fx.finish().await;
    }

    /// 2026-10-30: another user of one's own client. A Sales-Member-style caller (no User_UPDATE)
    /// is refused, even for the Owner; User_UPDATE reaches the caller's reporting line only; an
    /// Owner or a Client_MANAGE holder reaches the whole client; one's own change is as before.
    #[tokio::test]
    async fn same_client_secret_changes_need_user_update_and_the_line() {
        let Some(fx) = fx().await else { return };
        let (s, c) = (&fx.s, fx.c);
        let sys = sys();
        let owner = fx.user(c, "po").await;
        let a = fx.user(c, "pa").await;
        let b = fx.user(c, "pb").await;
        let d = fx.user(c, "pd").await;
        s.user_set_manager(&sys, b.id, Some(a.id)).await.unwrap();
        let new = |p: &str| body(json!({"newPassword": p}));
        let code = |r: AuthResult<bool>| r.map_err(|e| (e.status(), e.message()));

        // Oneself, without any authority: the old secret must match, the new one must differ.
        let me = fx.as_user(&b, "ZZRUL", &[]);
        let same = body(json!({"oldPassword": PASSWORD, "newPassword": PASSWORD}));
        assert_eq!(code(s.update_password(&me, None, &same).await).unwrap_err().1, crate::errors::message("new_password_match", &[]));
        s.update_password(&me, None, &body(json!({"oldPassword": PASSWORD, "newPassword": "Zz@24680a"}))).await.unwrap();
        s.update_password(&me, Some(b.id), &body(json!({"oldPassword": "Zz@24680a", "newPassword": "Zz@24680b"}))).await.unwrap();

        // A member without User_UPDATE: not their reportee, not the Owner.
        let sales = fx.as_user(&a, "ZZRUL", &["Authorities.User_READ"]);
        for target in [b.id, owner.id, d.id] {
            let (st, msg) = code(s.update_password(&sales, Some(target), &new("Zz@13579a")).await).unwrap_err();
            assert_eq!((st, msg), (StatusCode::FORBIDDEN, crate::errors::message("forbidden_permission", &["User UPDATE"])), "{target}");
        }

        // User_UPDATE: the reportee yes; someone outside the line or the Owner, no.
        let manager = fx.as_user(&a, "ZZRUL", &["Authorities.User_READ", "Authorities.User_UPDATE"]);
        s.update_password(&manager, Some(b.id), &new("Zz@13579b")).await.unwrap();
        for target in [d.id, owner.id] {
            let (st, msg) = code(s.update_password(&manager, Some(target), &new("Zz@13579c")).await).unwrap_err();
            assert_eq!((st, msg), (StatusCode::FORBIDDEN, crate::errors::message("hierarchy_error", &[])), "{target}");
        }

        // The whole client: an Owner, or a Client_MANAGE holder; each still needs User_UPDATE.
        let owner_ca = fx.as_user(&owner, "ZZRUL", &["Authorities.User_UPDATE", "Authorities.ROLE_Owner"]);
        s.update_password(&owner_ca, Some(d.id), &new("Zz@13579d")).await.unwrap();
        let manage = fx.as_user(&d, "ZZRUL", &["Authorities.User_UPDATE", "Authorities.ROLE_Client_MANAGE"]);
        s.update_password(&manage, Some(a.id), &new("Zz@13579e")).await.unwrap();
        let owner_only = fx.as_user(&owner, "ZZRUL", &["Authorities.ROLE_Owner"]);
        assert_eq!(code(s.update_password(&owner_only, Some(a.id), &new("Zz@13579f")).await).unwrap_err().0, StatusCode::FORBIDDEN);

        // The anonymous reset by OTP never asks for an authority: a wrong OTP is its refusal.
        let on_c = anonymous(c, "ZZRUL");
        let reset = body(json!({"authRequest": {"userName": d.email_id, "otp": "000000"}, "newPassword": "Zz@13579g"}));
        assert_eq!(code(s.reset_password(&on_c, &reset).await).unwrap_err().1, crate::errors::message("user_password_invalid", &["OTP", "OTP"]));
        fx.finish().await;
    }
}
