//! Rows of the `security` schema and the beans the Java service answers with, written in
//! Jackson's property order (fields of the superclass first, then the class's own, then
//! getter-only properties).

use chrono::NaiveDateTime;
use serde_json::Value;

use crate::jackson::{epoch, opt, Obj, LOCAL_DATE_TIME_MAX_EPOCH};

pub const CLIENT_TYPE_SYSTEM: &str = "SYS";
/// `User.PLACEHOLDER`: an identity column nobody set.
pub const PLACEHOLDER: &str = "NONE";

/// A `security_user` row (`User` as `e.into(User.class)` fills it).
#[derive(Debug, Clone, Default)]
pub struct User {
    pub id: u64,
    pub designation_id: Option<u64>,
    pub reporting_to: Option<u64>,
    pub client_id: u64,
    pub user_name: Option<String>,
    pub email_id: Option<String>,
    pub phone_number: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub middle_name: Option<String>,
    pub locale_code: Option<String>,
    pub password: Option<String>,
    pub password_hashed: bool,
    pub pin: Option<String>,
    pub pin_hashed: bool,
    pub account_non_expired: bool,
    pub account_non_locked: bool,
    pub credentials_non_expired: bool,
    pub no_failed_attempt: Option<i64>,
    pub no_pin_failed_attempt: Option<i64>,
    pub no_otp_failed_attempt: Option<i64>,
    pub status_code: String,
    pub locked_until: Option<NaiveDateTime>,
    pub locked_due_to: Option<String>,
    pub created_by: Option<u64>,
    pub created_at: Option<NaiveDateTime>,
    pub updated_by: Option<u64>,
    pub updated_at: Option<NaiveDateTime>,
    pub time_zone: Option<String>,
}

impl User {
    fn identity(v: &Option<String>) -> Option<String> {
        v.clone().filter(|s| s != PLACEHOLDER)
    }

    /// `User.getUserName()`: `NONE` reads as absent.
    pub fn user_name(&self) -> Option<String> {
        Self::identity(&self.user_name)
    }

    pub fn email_id(&self) -> Option<String> {
        Self::identity(&self.email_id)
    }

    pub fn phone_number(&self) -> Option<String> {
        Self::identity(&self.phone_number)
    }

    /// `User.toContextUser()`. The time zone is not part of it; only the token path adds it.
    /// `noOtpResendAttempts` is always absent: the DTO field is plural and the column singular,
    /// so jOOQ never fills it.
    pub fn to_context_user(&self, authorities: Option<Vec<String>>) -> ContextUser {
        ContextUser {
            id: Some(self.id),
            created_by: self.created_by,
            updated_by: self.updated_by,
            created_at: self.created_at.map(|t| t.and_utc().timestamp()),
            updated_at: self.updated_at.map(|t| t.and_utc().timestamp()),
            client_id: Some(self.client_id),
            user_name: self.user_name(),
            email_id: self.email_id(),
            phone_number: self.phone_number(),
            first_name: self.first_name.clone(),
            last_name: self.last_name.clone(),
            middle_name: self.middle_name.clone(),
            locale_code: self.locale_code.clone(),
            time_zone: None,
            account_non_expired: self.account_non_expired,
            account_non_locked: self.account_non_locked,
            credentials_non_expired: self.credentials_non_expired,
            no_failed_attempt: self.no_failed_attempt,
            no_pin_failed_attempt: self.no_pin_failed_attempt,
            no_otp_resend_attempts: None,
            no_otp_failed_attempt: self.no_otp_failed_attempt,
            status_code: Some(self.status_code.clone()),
            locked_until: self.locked_until.map(|t| t.and_utc().timestamp()),
            locked_due_to: self.locked_due_to.clone(),
            string_authorities: authorities,
            designation_id: self.designation_id,
        }
    }
}

/// A `security_client` row.
#[derive(Debug, Clone, Default)]
pub struct Client {
    pub id: Option<u64>,
    pub created_at: Option<NaiveDateTime>,
    pub created_by: Option<u64>,
    pub updated_at: Option<NaiveDateTime>,
    pub updated_by: Option<u64>,
    pub code: Option<String>,
    pub name: Option<String>,
    pub type_code: Option<String>,
    pub token_validity_minutes: i64,
    pub locale_code: Option<String>,
    pub time_zone: Option<String>,
    pub status_code: Option<String>,
    pub business_type: Option<String>,
    pub business_size: Option<String>,
    pub industry: Option<String>,
    pub level_type: Option<String>,
    pub website: Option<String>,
    pub email_id: Option<String>,
    pub phone_number: Option<String>,
    pub alternate_phone_number: Option<String>,
    pub linkedin_url: Option<String>,
    pub description: Option<String>,
}

impl Client {
    pub fn id(&self) -> u64 {
        self.id.unwrap_or(0)
    }

    pub fn code(&self) -> &str {
        self.code.as_deref().unwrap_or("")
    }

    /// The `Client` DTO through Jackson. The user counts are `int`s that nothing here fills,
    /// so they are always 0, and `totalUsers` is their sum.
    pub fn to_json(&self) -> Value {
        Obj::new()
            .put("id", opt(self.id))
            .put("createdAt", epoch(self.created_at))
            .put("createdBy", opt(self.created_by))
            .put("updatedAt", epoch(self.updated_at))
            .put("updatedBy", opt(self.updated_by))
            .put("code", opt(self.code.clone()))
            .put("name", opt(self.name.clone()))
            .put("typeCode", opt(self.type_code.clone()))
            .put("tokenValidityMinutes", self.token_validity_minutes)
            .put("localeCode", opt(self.locale_code.clone()))
            .put("timeZone", opt(self.time_zone.clone()))
            .put("statusCode", opt(self.status_code.clone()))
            .put("businessType", opt(self.business_type.clone()))
            .put("businessSize", opt(self.business_size.clone()))
            .put("industry", opt(self.industry.clone()))
            .put("levelType", opt(self.level_type.clone()))
            .put("website", opt(self.website.clone()))
            .put("emailId", opt(self.email_id.clone()))
            .put("phoneNumber", opt(self.phone_number.clone()))
            .put("alternatePhoneNumber", opt(self.alternate_phone_number.clone()))
            .put("linkedinUrl", opt(self.linkedin_url.clone()))
            .put("description", opt(self.description.clone()))
            .put("activeUsers", 0)
            .put("inactiveUsers", 0)
            .put("deletedUsers", 0)
            .put("lockedUsers", 0)
            .put("passwordExpiredUsers", 0)
            .put("totalUsers", 0)
            .build()
    }
}

/// A `security_app` row.
#[derive(Debug, Clone, Default)]
pub struct App {
    pub id: u64,
    pub client_id: u64,
    pub app_name: Option<String>,
    pub app_code: String,
    pub app_type: Option<String>,
    pub app_access_type: Option<String>,
    pub thumb_url: Option<String>,
    pub app_usage_type: Option<String>,
    pub status: Option<String>,
    pub created_by: Option<u64>,
    pub created_at: Option<NaiveDateTime>,
    pub updated_by: Option<u64>,
    pub updated_at: Option<NaiveDateTime>,
}

impl App {
    /// The security `App` DTO through Jackson.
    pub fn to_json(&self) -> Value {
        Obj::new()
            .put("id", self.id)
            .put("createdAt", epoch(self.created_at))
            .put("createdBy", opt(self.created_by))
            .put("updatedAt", epoch(self.updated_at))
            .put("updatedBy", opt(self.updated_by))
            .put("clientId", self.client_id)
            .put("appName", opt(self.app_name.clone()))
            .put("appCode", self.app_code.as_str())
            .put("appType", opt(self.app_type.clone()))
            .put("appAccessType", opt(self.app_access_type.clone()))
            .put("thumbUrl", opt(self.thumb_url.clone()))
            .put("appUsageType", opt(self.app_usage_type.clone()))
            .put("status", opt(self.status.clone()))
            .build()
    }
}

/// A `security_client_hierarchy` row.
#[derive(Debug, Clone, Default)]
pub struct ClientHierarchy {
    pub client_id: u64,
    pub level0: Option<u64>,
    pub level1: Option<u64>,
    pub level2: Option<u64>,
    pub level3: Option<u64>,
}

impl ClientHierarchy {
    /// `getClientIds()` / `getClientIdsInOrder()`: the client, then its managers, nearest first.
    pub fn client_ids(&self) -> Vec<u64> {
        let mut ids = vec![self.client_id];
        for l in [self.level0, self.level1, self.level2, self.level3].into_iter().flatten() {
            if !ids.contains(&l) {
                ids.push(l);
            }
        }
        ids
    }

    /// `getClientIdsInOrder()`: the same ids as a list, a repeated level repeated.
    pub fn client_ids_in_order(&self) -> Vec<u64> {
        let mut ids = vec![self.client_id];
        ids.extend([self.level0, self.level1, self.level2, self.level3].into_iter().flatten());
        ids
    }

    /// `businessRootId()`: the business this client belongs to, the top client below SYSTEM in
    /// its chain (the client itself when it sits right under SYSTEM); `None` for SYSTEM.
    pub fn business_root_id(&self) -> Option<u64> {
        let chain = self.client_ids_in_order();
        (chain.len() >= 2).then(|| chain[chain.len() - 2])
    }

    /// `isManagedBy(clientId)`: the client itself or one of its managers.
    pub fn is_managed_by(&self, client_id: u64) -> bool {
        self.client_id == client_id || [self.level0, self.level1, self.level2, self.level3].contains(&Some(client_id))
    }

    /// `getClientOrder()`: 0 for the client, 1 for its manager, and so on (a later level wins
    /// for a repeated id, as `HashMap.put` does).
    pub fn client_order(&self, id: u64) -> Option<i32> {
        let mut found = None;
        for (i, l) in [Some(self.client_id), self.level0, self.level1, self.level2, self.level3].into_iter().enumerate() {
            if l == Some(id) {
                found = Some(i as i32);
            }
        }
        found
    }
}

/// A row of `security_client_url`, read as a `ClientUrlPattern`.
#[derive(Debug, Clone)]
pub struct UrlPattern {
    /// The client id as a string (`""` for a pattern made from an app's subdomain).
    pub identifier: String,
    pub client_code: Option<String>,
    pub url_pattern: Option<String>,
    pub app_code: Option<String>,
    /// Protocol, host and port parsed from the pattern (`makeHostnPort`).
    pub host: Option<String>,
    pub port: Option<String>,
    /// `LIVE` or `DRAFT`; `None` for a pattern made from an app's subdomain.
    pub url_type: Option<String>,
}

impl UrlPattern {
    pub fn new(identifier: String, client_code: Option<String>, url_pattern: Option<String>, app_code: Option<String>) -> Self {
        let (host, port) = match url_pattern.as_deref().map(str::trim).filter(|p| !p.is_empty()) {
            Some(p) => match host_and_port(&p.to_lowercase()) {
                Some((h, port)) => (Some(h), Some(port)),
                None => (Some(String::new()), Some(String::new())),
            },
            None => (None, None),
        };
        Self { identifier, client_code, url_pattern, app_code, host, port, url_type: None }
    }

    /// `isValidClientURLPattern(finHost, finPort)`.
    pub fn matches(&self, host: &str, port: &str) -> bool {
        let (Some(h), Some(p)) = (&self.host, &self.port) else { return false };
        if *h != host.to_lowercase() {
            return false;
        }
        if p.trim().is_empty() || port.trim().is_empty() {
            return true;
        }
        p.contains(port) || port.contains(p.as_str())
    }
}

/// `ClientUrlPattern.URL_PATTERN` with `find()`: optional scheme, a host up to the first `:`,
/// an optional port of up to five digits.
fn host_and_port(pattern: &str) -> Option<(String, String)> {
    use std::sync::OnceLock;
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    let re = RE.get_or_init(|| regex::Regex::new(r"(http://|https://)?([^:]+)(:(\d{0,5}))?").expect("static regex"));
    let c = re.captures(pattern)?;
    Some((c.get(2)?.as_str().to_string(), c.get(4).map(|m| m.as_str().to_string()).unwrap_or_default()))
}

/// The policy fields sign-in reads (`AbstractPolicy`), plus what OTP generation needs.
#[derive(Debug, Clone)]
pub struct Policy {
    pub no_failed_attempts: Option<i64>,
    pub user_lock_time: Option<i64>,
    pub otp: Option<OtpPolicy>,
}

#[derive(Debug, Clone)]
pub struct OtpPolicy {
    pub target_type: String,
    pub is_constant: bool,
    pub constant_value: Option<String>,
    pub is_numeric: bool,
    pub is_alphanumeric: bool,
    pub length: i64,
    pub resend_same_otp: bool,
    pub expire_interval: i64,
}

impl OtpPolicy {
    /// `ClientOtpPolicyService.getDefaultPolicy()`.
    pub fn defaults() -> Self {
        Self {
            target_type: "EMAIL".into(),
            is_constant: false,
            constant_value: None,
            is_numeric: true,
            is_alphanumeric: false,
            length: 4,
            resend_same_otp: false,
            expire_interval: 5,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassType {
    Password,
    Pin,
    Otp,
}

impl PassType {
    /// `AuthenticationPasswordType.getName()`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Password => "Password",
            Self::Pin => "PIN",
            Self::Otp => "OTP",
        }
    }

    pub fn policy_table(self) -> &'static str {
        match self {
            Self::Password => "security_client_password_policy",
            Self::Pin => "security_client_pin_policy",
            Self::Otp => "security_client_otp_policy",
        }
    }

    /// The cache each policy type lives in (`getPolicyCacheName`).
    pub fn policy_cache(self) -> &'static str {
        match self {
            Self::Password => "clientPasswordPolicy",
            Self::Pin => "clientPinPolicy",
            Self::Otp => "clientOtpPolicy",
        }
    }

    /// The default policy every type falls back to: 3 attempts, 15 minutes.
    pub fn default_policy(self) -> Policy {
        Policy {
            no_failed_attempts: Some(3),
            user_lock_time: Some(15),
            otp: (self == Self::Otp).then(OtpPolicy::defaults),
        }
    }
}

/// `ContextUser`.
#[derive(Debug, Clone, Default)]
pub struct ContextUser {
    pub id: Option<u64>,
    pub created_by: Option<u64>,
    pub updated_by: Option<u64>,
    pub created_at: Option<i64>,
    pub updated_at: Option<i64>,
    pub client_id: Option<u64>,
    pub user_name: Option<String>,
    pub email_id: Option<String>,
    pub phone_number: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub middle_name: Option<String>,
    pub locale_code: Option<String>,
    pub time_zone: Option<String>,
    pub account_non_expired: bool,
    pub account_non_locked: bool,
    pub credentials_non_expired: bool,
    pub no_failed_attempt: Option<i64>,
    pub no_pin_failed_attempt: Option<i64>,
    pub no_otp_resend_attempts: Option<i64>,
    pub no_otp_failed_attempt: Option<i64>,
    pub status_code: Option<String>,
    pub locked_until: Option<i64>,
    pub locked_due_to: Option<String>,
    pub string_authorities: Option<Vec<String>>,
    pub designation_id: Option<u64>,
}

impl ContextUser {
    /// The anonymous user `makeAnonymousSpringAuthentication` builds; `now` is the JVM's local
    /// wall time read as UTC, as `LocalDateTime.now()` serializes.
    pub fn anonymous(client_id: u64, now_epoch: i64) -> Self {
        Self {
            id: Some(0),
            created_by: Some(0),
            updated_by: Some(0),
            created_at: Some(now_epoch),
            updated_at: Some(now_epoch),
            client_id: Some(client_id),
            user_name: Some("_Anonymous".into()),
            email_id: Some("nothing@nothing".into()),
            phone_number: Some("+910000000000".into()),
            first_name: Some("Anonymous".into()),
            last_name: Some(String::new()),
            locale_code: Some("en".into()),
            account_non_expired: true,
            account_non_locked: true,
            credentials_non_expired: true,
            no_failed_attempt: Some(0),
            string_authorities: Some(vec!["Authorities._Anonymous".into()]),
            ..Default::default()
        }
    }

    pub fn id(&self) -> u64 {
        self.id.unwrap_or(0)
    }

    pub fn client_id(&self) -> u64 {
        self.client_id.unwrap_or(0)
    }

    pub fn to_json(&self) -> Value {
        Obj::new()
            .put("id", opt(self.id))
            .put("createdBy", opt(self.created_by))
            .put("updatedBy", opt(self.updated_by))
            .put("createdAt", opt(self.created_at))
            .put("updatedAt", opt(self.updated_at))
            .put("clientId", opt(self.client_id))
            .put("userName", opt(self.user_name.clone()))
            .put("emailId", opt(self.email_id.clone()))
            .put("phoneNumber", opt(self.phone_number.clone()))
            .put("firstName", opt(self.first_name.clone()))
            .put("lastName", opt(self.last_name.clone()))
            .put("middleName", opt(self.middle_name.clone()))
            .put("localeCode", opt(self.locale_code.clone()))
            .put("timeZone", opt(self.time_zone.clone()))
            .put("accountNonExpired", self.account_non_expired)
            .put("accountNonLocked", self.account_non_locked)
            .put("credentialsNonExpired", self.credentials_non_expired)
            .put("noFailedAttempt", opt(self.no_failed_attempt))
            .put("noPinFailedAttempt", opt(self.no_pin_failed_attempt))
            .put("noOtpResendAttempts", opt(self.no_otp_resend_attempts))
            .put("noOtpFailedAttempt", opt(self.no_otp_failed_attempt))
            .put("statusCode", opt(self.status_code.clone()))
            .put("lockedUntil", opt(self.locked_until))
            .put("lockedDueTo", opt(self.locked_due_to.clone()))
            .put("stringAuthorities", self.string_authorities.clone().map(Value::from).unwrap_or(Value::Null))
            .put("designationId", opt(self.designation_id))
            .build()
    }
}

/// `ContextAuthentication`.
#[derive(Debug, Clone, Default)]
pub struct ContextAuth {
    pub user: ContextUser,
    pub authenticated: bool,
    pub logged_in_from_client_id: Option<u64>,
    pub logged_in_from_client_code: Option<String>,
    pub client_type_code: Option<String>,
    pub client_level_type: Option<String>,
    pub client_code: Option<String>,
    pub access_token: Option<String>,
    /// Epoch seconds of the expiry as Jackson writes the `LocalDateTime`.
    pub access_token_expiry_at: Option<i64>,
    /// The expiry as the wall time it is (`refreshToken` compares it).
    pub access_token_expiry: Option<NaiveDateTime>,
    pub url_client_code: Option<String>,
    pub url_app_code: Option<String>,
    pub verified_app_code: Option<String>,
}

impl ContextAuth {
    pub fn anonymous(client: &Client, now_epoch: i64) -> Self {
        Self {
            user: ContextUser::anonymous(client.id(), now_epoch),
            authenticated: false,
            logged_in_from_client_id: client.id,
            logged_in_from_client_code: client.code.clone(),
            client_type_code: client.type_code.clone(),
            client_level_type: None,
            client_code: client.code.clone(),
            access_token: Some(String::new()),
            access_token_expiry_at: Some(LOCAL_DATE_TIME_MAX_EPOCH),
            access_token_expiry: None,
            url_client_code: None,
            url_app_code: None,
            verified_app_code: None,
        }
    }

    pub fn is_system_client(&self) -> bool {
        self.client_type_code.as_deref() == Some(CLIENT_TYPE_SYSTEM)
    }

    pub fn to_json(&self) -> Value {
        Obj::new()
            .put("user", self.user.to_json())
            .put("loggedInFromClientId", opt(self.logged_in_from_client_id))
            .put("loggedInFromClientCode", opt(self.logged_in_from_client_code.clone()))
            .put("clientTypeCode", opt(self.client_type_code.clone()))
            .put("clientLevelType", opt(self.client_level_type.clone()))
            .put("clientCode", opt(self.client_code.clone()))
            .put("accessToken", opt(self.access_token.clone()))
            .put("accessTokenExpiryAt", opt(self.access_token_expiry_at))
            .put("urlClientCode", opt(self.url_client_code.clone()))
            .put("urlAppCode", opt(self.url_app_code.clone()))
            .put("verifiedAppCode", opt(self.verified_app_code.clone()))
            .put("authenticated", self.authenticated)
            .put("systemClient", self.is_system_client())
            .put("name", opt(self.user.first_name.clone()))
            .build()
    }
}

/// `AuthenticationResponse`.
#[derive(Debug, Clone, Default)]
pub struct AuthResponse {
    pub user: ContextUser,
    pub client: Client,
    pub verified_app_code: Option<String>,
    pub logged_in_client_code: Option<String>,
    pub logged_in_client_id: Option<u64>,
    pub managed_client_id: Option<u64>,
    pub managed_client_code: Option<String>,
    pub access_token: Option<String>,
    pub access_token_expiry_at: Option<i64>,
    pub sso_token: Option<String>,
}

impl AuthResponse {
    pub fn to_json(&self) -> Value {
        Obj::new()
            .put("user", self.user.to_json())
            .put("client", self.client.to_json())
            .put("verifiedAppCode", opt(self.verified_app_code.clone()))
            .put("loggedInClientCode", opt(self.logged_in_client_code.clone()))
            .put("loggedInClientId", opt(self.logged_in_client_id))
            .put("managedClientId", opt(self.managed_client_id))
            .put("managedClientCode", opt(self.managed_client_code.clone()))
            .put("accessToken", opt(self.access_token.clone()))
            .put("accessTokenExpiryAt", opt(self.access_token_expiry_at))
            .put("ssoToken", opt(self.sso_token.clone()))
            .build()
    }

    /// `makeContextAuthentication()`: note it never sets `isAuthenticated`, so the redeemed
    /// one-time token answers `"authenticated": false` (as Java does).
    pub fn to_context_auth(&self) -> ContextAuth {
        ContextAuth {
            user: self.user.clone(),
            authenticated: false,
            logged_in_from_client_id: self.logged_in_client_id,
            logged_in_from_client_code: self.logged_in_client_code.clone(),
            access_token: self.access_token.clone(),
            access_token_expiry_at: self.access_token_expiry_at,
            verified_app_code: self.verified_app_code.clone(),
            ..Default::default()
        }
    }
}

/// A `security_user_token` row.
#[derive(Debug, Clone)]
pub struct TokenRow {
    pub id: u64,
    pub user_id: u64,
    pub token: String,
    pub expires_at: NaiveDateTime,
}

/// A redeemed `security_one_time_token` row.
#[derive(Debug, Clone)]
pub struct OneTimeTokenRow {
    pub user_id: u64,
    pub remember_me: bool,
    pub auth_mode: Option<String>,
    pub origin_app_code: Option<String>,
    pub target_app_code: Option<String>,
}

/// What a token row, a one-time token row and an OTP row record about where a request came
/// from (`UserAgentInfo`, the remote address).
#[derive(Debug, Clone, Default)]
pub struct Origin {
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub device_type: Option<String>,
    pub os: Option<String>,
    pub browser: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_patterns_match_like_client_url_pattern() {
        let p = UrlPattern::new("1".into(), Some("SYSTEM".into()), Some("https://Apps.Local:8080".into()), None);
        assert_eq!((p.host.as_deref(), p.port.as_deref()), (Some("apps.local"), Some("8080")));
        assert!(p.matches("APPS.local", "8080"));
        assert!(p.matches("apps.local", ""));
        assert!(p.matches("apps.local", "80"), "port containment is either way round");
        assert!(!p.matches("apps.local", "443"));
        let any_port = UrlPattern::new("2".into(), None, Some("leadzump.local.modlix.com".into()), None);
        assert!(any_port.matches("leadzump.local.modlix.com", "-1"));
        let empty = UrlPattern::new("3".into(), None, None, None);
        assert!(!empty.matches("", ""));
    }

    /// Ported from commons-security `ClientUrlPatternTest`.
    #[test]
    fn client_url_pattern_test() {
        let p = |pattern: &str| UrlPattern::new("x".into(), Some("ccode".into()), Some(pattern.into()), Some("appcode".into()));
        assert!(p("apps-dev.fincity.ai").matches("apps-dev.fincity.ai", "443"));
        assert!(p("https://apps-dev.fincity.ai:443").matches("apps-dev.fincity.ai", "443"));
        assert!(p("http://localhost:80").matches("localhost", "80"));
        assert!(p("localhost:8080").matches("localhost", "443,8080"));
        assert!(p("localhost").matches("localhost", "8011"));
        assert!(p("https://localhost").matches("localhost", "443"));
        assert!(!p("https://localhost:20").matches("localhost", "8011"));
        assert!(p("localhost").matches("localhost", "443"));
        assert!(p("localhost").matches("localhost", "80"));
        // Nothing a pattern could match: a lone colon.
        let colon = p(":");
        assert_eq!((colon.host.as_deref(), colon.port.as_deref()), (Some(""), Some("")));
    }

    #[test]
    fn json_of_responses() {
        let c = Client { id: Some(2), code: Some("BUS".into()), token_validity_minutes: 30, ..Default::default() };
        let v = c.to_json();
        assert_eq!(v["tokenValidityMinutes"], 30);
        assert_eq!(v["totalUsers"], 0);
        assert_eq!((c.id(), c.code()), (2, "BUS"));
        assert_eq!((Client::default().id(), Client::default().code()), (0, ""));
        let r = AuthResponse { access_token: Some("t".into()), logged_in_client_id: Some(2), ..Default::default() };
        assert_eq!(r.to_json()["accessToken"], "t");
        let ca = r.to_context_auth();
        assert!(!ca.authenticated);
        assert_eq!(ca.logged_in_from_client_id, Some(2));
        let u = User { user_name: Some("NONE".into()), email_id: Some("a@b".into()), phone_number: Some("NONE".into()), ..Default::default() };
        let cu = u.to_context_user(Some(vec!["x".into()]));
        assert_eq!((cu.user_name.clone(), cu.email_id.as_deref(), cu.phone_number.clone()), (None, Some("a@b"), None));
        assert_eq!((cu.id(), cu.client_id()), (0, 0));
        assert_eq!(ContextUser::default().id(), 0);
        for t in [PassType::Password, PassType::Pin, PassType::Otp] {
            assert!(!t.policy_table().is_empty());
            assert!(!t.policy_cache().is_empty());
            assert_eq!(t.default_policy().no_failed_attempts, Some(3));
        }
        assert_eq!((PassType::Password.name(), PassType::Pin.name(), PassType::Otp.name()), ("Password", "PIN", "OTP"));
        assert!(PassType::Otp.default_policy().otp.is_some());
    }

    #[test]
    fn business_root() {
        let h = |c, l: [Option<u64>; 2]| ClientHierarchy { client_id: c, level0: l[0], level1: l[1], level2: None, level3: None };
        assert_eq!(h(9, [Some(4), Some(1)]).business_root_id(), Some(4), "a partner's business is its manager");
        assert_eq!(h(4, [Some(1), None]).business_root_id(), Some(4), "a business right under SYSTEM is its own");
        assert_eq!(h(1, [None, None]).business_root_id(), None, "SYSTEM has none");
    }

    #[test]
    fn client_order_and_ids() {
        let h = ClientHierarchy { client_id: 9, level0: Some(4), level1: Some(1), level2: None, level3: None };
        assert_eq!(h.client_ids(), vec![9, 4, 1]);
        assert_eq!((h.client_order(9), h.client_order(1), h.client_order(7)), (Some(0), Some(2), None));
    }

    #[test]
    fn anonymous_context_json_matches_java() {
        let client = Client {
            id: Some(1),
            code: Some("SYSTEM".into()),
            type_code: Some("SYS".into()),
            ..Default::default()
        };
        let mut ca = ContextAuth::anonymous(&client, 1_792_049_284);
        ca.url_client_code = Some("SYSTEM".into());
        ca.url_app_code = Some("appbuilder".into());
        // Captured from the Java service (GET internal/securityContextAuthentication, 2026-10-15).
        let java = r#"{
  "user" : {
    "id" : 0,
    "createdBy" : 0,
    "updatedBy" : 0,
    "createdAt" : 1792049284,
    "updatedAt" : 1792049284,
    "clientId" : 1,
    "userName" : "_Anonymous",
    "emailId" : "nothing@nothing",
    "phoneNumber" : "+910000000000",
    "firstName" : "Anonymous",
    "localeCode" : "en",
    "accountNonExpired" : true,
    "accountNonLocked" : true,
    "credentialsNonExpired" : true,
    "noFailedAttempt" : 0,
    "stringAuthorities" : [ "Authorities._Anonymous" ]
  },
  "loggedInFromClientId" : 1,
  "loggedInFromClientCode" : "SYSTEM",
  "clientTypeCode" : "SYS",
  "clientCode" : "SYSTEM",
  "accessTokenExpiryAt" : 31556889832780799,
  "urlClientCode" : "SYSTEM",
  "urlAppCode" : "appbuilder",
  "authenticated" : false,
  "systemClient" : true,
  "name" : "Anonymous"
}"#;
        assert_eq!(crate::jackson::pretty(&ca.to_json()), java);
    }
}
