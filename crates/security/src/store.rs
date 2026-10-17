//! Everything this unit reads from or writes to the `security` schema, as one trait: the MySQL
//! implementation (`mysql.rs`) runs the Java DAOs' SQL, and the unit tests use an in-memory one
//! in its place, the way the Java tests mock the DAOs.

use async_trait::async_trait;
use chrono::NaiveDateTime;

use crate::errors::AuthResult;
use crate::model::{App, Client, ClientHierarchy, OneTimeTokenRow, Origin, PassType, Policy, TokenRow, UrlPattern, User};

/// `AuthenticationIdentifierType`: which column a user name is matched against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IdentifierType {
    #[default]
    UserName,
    PhoneNumber,
    EmailId,
}

impl IdentifierType {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "USER_NAME" => Some(Self::UserName),
            "PHONE_NUMBER" => Some(Self::PhoneNumber),
            "EMAIL_ID" => Some(Self::EmailId),
            _ => None,
        }
    }

    /// `getComputedIdentifierType()` when none was given: an `@` makes it an e-mail.
    pub fn computed(given: Option<Self>, user_name: Option<&str>) -> Self {
        given.unwrap_or(match user_name {
            Some(u) if !u.trim().is_empty() && u.contains('@') => Self::EmailId,
            _ => Self::UserName,
        })
    }
}

/// `UserDAO.getAllUsersPerAppQuery`: non-deleted users by identity under a client, for an app.
#[derive(Debug, Clone, Default)]
pub struct UserQuery {
    pub user_name: Option<String>,
    pub identifier: IdentifierType,
    pub user_id: Option<u64>,
    pub client_code: Option<String>,
    pub app_code: Option<String>,
    /// `SecurityClientStatusCode.ACTIVE` on the user's own client (`findNonDeletedUserNActiveClient`).
    pub active_client_only: bool,
    pub limit: u32,
}

/// A profile, sub-role or role row: id, name, and the code of the app it belongs to.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct NamedRow {
    pub id: Option<u64>,
    pub name: Option<String>,
    pub app_code: Option<String>,
}

/// A permission name and its app's code.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct PermissionRow {
    pub name: Option<String>,
    pub app_code: Option<String>,
}

/// `ProfileDAO.getProfileAuthorities`'s role query: a role of one of the profiles.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoleRecord {
    pub role_id: Option<u64>,
    pub profile_client_id: Option<u64>,
    pub profile_id: Option<u64>,
    pub role_name: Option<String>,
    pub app_code: Option<String>,
    pub exclude: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct NewToken {
    pub user_id: u64,
    pub token: String,
    pub part_token: String,
    pub expires_at: NaiveDateTime,
    pub origin: Origin,
    pub created_by: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct NewOneTimeToken {
    pub user_id: u64,
    pub token: String,
    pub origin: Origin,
    pub remember_me: Option<bool>,
    pub auth_mode: Option<String>,
    pub origin_app_code: Option<String>,
    pub target_app_code: Option<String>,
}

/// A `security_otp` row.
#[derive(Debug, Clone)]
pub struct OtpRow {
    pub id: u64,
    pub unique_code: String,
    pub expires_at: NaiveDateTime,
    pub verify_legs_counts: i64,
}

#[derive(Debug, Clone)]
pub struct NewOtp {
    pub app_id: u64,
    pub user_id: Option<u64>,
    pub email_id: Option<String>,
    pub phone_number: Option<String>,
    pub purpose: String,
    pub target_type: String,
    pub unique_code: String,
    pub expires_at: NaiveDateTime,
    pub ip_address: Option<String>,
    pub created_at: NaiveDateTime,
}

/// A social sign-in state (`security_app_reg_integration_tokens`).
#[derive(Debug, Clone)]
pub struct StateRow {
    pub state: String,
    pub username: Option<String>,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
}

#[async_trait]
pub trait Store: Send + Sync {
    // Users
    async fn user_by_id(&self, id: u64) -> AuthResult<Option<User>>;
    async fn users_by(&self, q: &UserQuery) -> AuthResult<Vec<User>>;
    async fn owner_user_ids(&self, ids: &[u64]) -> AuthResult<Vec<u64>>;
    async fn is_user_owner(&self, user_id: u64) -> AuthResult<bool>;
    async fn increase_failed_attempt(&self, user_id: u64, t: PassType) -> AuthResult<Option<i64>>;
    async fn reset_failed_attempt(&self, user_id: u64, t: PassType) -> AuthResult<bool>;
    async fn increase_resend_attempts(&self, user_id: u64) -> AuthResult<Option<i64>>;
    async fn reset_resend_attempts(&self, user_id: u64) -> AuthResult<bool>;
    async fn lock_user(&self, user_id: u64, until: NaiveDateTime, due_to: &str) -> AuthResult<bool>;
    async fn unlock_user(&self, user_id: u64) -> AuthResult<bool>;

    // Clients
    async fn client_by_id(&self, id: u64) -> AuthResult<Option<Client>>;
    async fn client_by_code(&self, code: &str) -> AuthResult<Option<Client>>;
    async fn client_type_code_level(&self, id: u64) -> AuthResult<Option<(String, String, String)>>;
    async fn client_hierarchy(&self, client_id: u64) -> AuthResult<Option<ClientHierarchy>>;
    async fn count_active_clients(&self, ids: &[u64]) -> AuthResult<i64>;
    async fn client_url_patterns(&self) -> AuthResult<Vec<UrlPattern>>;

    // Apps
    async fn app_by_code(&self, code: &str) -> AuthResult<Option<App>>;
    async fn app_by_id(&self, id: u64) -> AuthResult<Option<App>>;
    async fn has_read_access(&self, app_code: &str, client_code: &str) -> AuthResult<bool>;
    async fn has_dependency_either_direction(&self, app_a: u64, app_b: u64) -> AuthResult<bool>;

    // Roles, profiles, permissions
    async fn user_roles(&self, user_id: u64) -> AuthResult<Vec<NamedRow>>;
    async fn role_permissions(&self, role_ids: &[u64]) -> AuthResult<Vec<PermissionRow>>;
    async fn profile_ids(&self, app_code: Option<&str>, user_id: u64) -> AuthResult<Vec<u64>>;
    async fn default_profile_ids(&self, app_code: Option<&str>) -> AuthResult<Vec<u64>>;
    async fn profile_rows(&self, profile_id: u64, client_ids: &[u64]) -> AuthResult<Vec<NamedRow>>;
    async fn profile_role_rows(&self, profile_ids: &[u64]) -> AuthResult<Vec<RoleRecord>>;
    async fn sub_role_rows(&self, role_ids: &[u64]) -> AuthResult<Vec<NamedRow>>;
    async fn permission_rows(&self, role_ids: &[u64]) -> AuthResult<Vec<PermissionRow>>;
    async fn user_has_any_profile(&self, user_id: u64, app_code: &str) -> AuthResult<bool>;
    async fn has_assigned_profile(&self, user_id: u64, app_id: u64) -> AuthResult<bool>;
    async fn user_app_having_profile(&self, user_id: u64) -> AuthResult<Option<u64>>;

    // Policies
    async fn policy(&self, t: PassType, client_id: u64, app_id: u64) -> AuthResult<Option<Policy>>;

    // Access tokens
    async fn tokens_by_part(&self, part_token: &str) -> AuthResult<Vec<TokenRow>>;
    async fn insert_token(&self, t: &NewToken) -> AuthResult<u64>;
    async fn delete_token(&self, id: u64) -> AuthResult<u64>;
    async fn token_strings_of_user(&self, user_id: u64) -> AuthResult<Vec<String>>;
    async fn delete_tokens_of_user(&self, user_id: u64) -> AuthResult<u64>;
    async fn update_last_used(&self, id: u64, at: NaiveDateTime) -> AuthResult<u64>;
    async fn delete_expired_tokens(&self, now: NaiveDateTime) -> AuthResult<u64>;
    async fn delete_unused_tokens(&self, cutoff: NaiveDateTime) -> AuthResult<u64>;
    async fn delete_expired_draft_tokens(&self, now_utc: NaiveDateTime) -> AuthResult<u64>;

    // One-time tokens
    async fn insert_one_time_token(&self, t: &NewOneTimeToken) -> AuthResult<()>;
    async fn redeem_one_time_token(&self, token: &str, max_age_minutes: i64) -> AuthResult<Option<OneTimeTokenRow>>;

    // Audit
    async fn insert_sox_log(&self, object_id: u64, action: &str, object: &str, description: &str) -> AuthResult<()>;

    // OTP
    async fn latest_otp(&self, app_id: u64, user_id: u64, purpose: &str) -> AuthResult<Option<OtpRow>>;
    async fn latest_otp_code(&self, app_id: u64, user_id: u64, purpose: &str) -> AuthResult<Option<String>>;
    /// The latest OTP of the app and purpose sent to the e-mail or the phone (either given one).
    async fn latest_otp_by_target(&self, app_id: u64, email: Option<&str>, phone: Option<&str>, purpose: &str) -> AuthResult<Option<OtpRow>>;
    async fn insert_otp(&self, o: &NewOtp) -> AuthResult<()>;
    async fn delete_otp(&self, id: u64) -> AuthResult<u64>;
    async fn increase_otp_verify_count(&self, id: u64) -> AuthResult<bool>;

    // Social sign-in states
    async fn state_by_value(&self, state: &str) -> AuthResult<Option<StateRow>>;
    async fn consume_state(&self, state: &str) -> AuthResult<bool>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifier_type() {
        assert_eq!(IdentifierType::parse("EMAIL_ID"), Some(IdentifierType::EmailId));
        assert_eq!(IdentifierType::parse("PHONE_NUMBER"), Some(IdentifierType::PhoneNumber));
        assert_eq!(IdentifierType::parse("USER_NAME"), Some(IdentifierType::UserName));
        assert_eq!(IdentifierType::parse("x"), None);
        assert_eq!(IdentifierType::computed(None, Some("a@b")), IdentifierType::EmailId);
        assert_eq!(IdentifierType::computed(None, Some("ab")), IdentifierType::UserName);
        assert_eq!(IdentifierType::computed(None, None), IdentifierType::UserName);
        assert_eq!(IdentifierType::computed(Some(IdentifierType::PhoneNumber), Some("a@b")), IdentifierType::PhoneNumber);
    }
}
