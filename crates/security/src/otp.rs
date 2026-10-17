//! `OtpService`: `generateOtpInternal` (sign-in, `OtpController`, password reset, registration),
//! the `verifyOtp` variants, and the code generator (`CodeUtil`).

use rand::Rng;
use serde_json::Value;

use crate::errors::{AuthError, AuthResult};
use crate::events::{EventMessage, USER_OTP_GENERATE};
use crate::model::{OtpPolicy, PassType};
use crate::service::Auth;
use crate::store::{NewOtp, OtpRow};

/// `OtpPurpose`: name, display name, verify legs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpPurpose {
    Registration,
    Login,
    Verification,
    PasswordReset,
}

impl OtpPurpose {
    /// Jackson's enum reader: the constant's name, or its ordinal as a JSON number.
    pub fn from_json(v: &Value) -> Result<Option<Self>, ()> {
        const ALL: [OtpPurpose; 4] = [OtpPurpose::Registration, OtpPurpose::Login, OtpPurpose::Verification, OtpPurpose::PasswordReset];
        match v {
            Value::Null => Ok(None),
            Value::String(s) => ALL.iter().find(|p| p.name() == s).copied().map(Some).ok_or(()),
            Value::Number(n) => n.as_u64().and_then(|i| ALL.get(i as usize)).copied().map(Some).ok_or(()),
            _ => Err(()),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Registration => "REGISTRATION",
            Self::Login => "LOGIN",
            Self::Verification => "VERIFICATION",
            Self::PasswordReset => "PASSWORD_RESET",
        }
    }

    pub fn display_name(self) -> &'static str {
        match self {
            Self::Registration => "registration",
            Self::Login => "login",
            Self::Verification => "verification",
            Self::PasswordReset => "password reset",
        }
    }

    pub fn verify_legs(self) -> i64 {
        match self {
            Self::Registration | Self::PasswordReset => 1,
            Self::Login | Self::Verification => 0,
        }
    }
}

const NUMBERS: &str = "0123456789";
const UPPERCASE: &str = "BCDFGHJKLMNPQRSTVWXZ";
const LOWERCASE: &str = "bcdfghjklmnpqrstvwxz";

/// `ClientOtpPolicy.generate()`: the constant when the policy says so, else `length` characters
/// from the policy's sets (a set picked at random for each character).
pub fn generate_code(p: &OtpPolicy) -> AuthResult<Option<String>> {
    if p.is_constant {
        return Ok(p.constant_value.clone());
    }
    let mut sets = Vec::new();
    if p.is_numeric {
        sets.push(NUMBERS);
    }
    if p.is_alphanumeric {
        sets.push(UPPERCASE);
        sets.push(LOWERCASE);
    }
    if sets.is_empty() {
        // `charSets.get(0)` on an empty list.
        return Err(AuthError::internal("Index 0 out of bounds for length 0"));
    }
    let mut rng = rand::thread_rng();
    let code = (0..p.length.max(0))
        .map(|_| {
            let set = sets[if sets.len() > 1 { rng.gen_range(0..sets.len()) } else { 0 }].as_bytes();
            set[rng.gen_range(0..set.len())] as char
        })
        .collect();
    Ok(Some(code))
}

/// `OtpGenerationRequestInternal` for a sign-in.
#[derive(Debug, Clone, Default)]
pub struct OtpRequest {
    pub client_id: u64,
    pub client_code: Option<String>,
    pub app_id: u64,
    pub app_code: String,
    pub app_name: Option<String>,
    pub user_id: Option<u64>,
    pub email_id: Option<String>,
    pub phone_number: Option<String>,
    pub ip_address: Option<String>,
    pub resend: bool,
    pub x_debug: Option<String>,
    /// `null` only from an `OtpController` request without one.
    pub purpose: Option<OtpPurpose>,
    /// `setWithUserOption`: the user's own identifiers (sign-in, password reset).
    pub with_user: bool,
}

/// What Java answers when a null purpose is dereferenced.
fn null_purpose() -> AuthError {
    AuthError::internal("Cannot invoke \"com.fincity.security.enums.otp.OtpPurpose.name()\" because \"purpose\" is null")
}

fn non_blank(s: &Option<String>) -> Option<&str> {
    s.as_deref().filter(|v| !v.trim().is_empty())
}

impl Auth {
    /// `generateOtpInternal`: false when the app is unknown or nothing was sent.
    pub async fn generate_otp_internal(&self, req: &OtpRequest) -> AuthResult<bool> {
        let Some(app) = self.dir.app_by_code(&req.app_code).await? else { return Ok(false) };
        let policy = self.dir.policy_for_app(req.client_id, app.id, PassType::Otp).await?;
        let otp_policy = policy.otp.clone().unwrap_or_else(OtpPolicy::defaults);
        let target = match otp_policy.target_type.as_str() {
            "PHONE" | "BOTH" => otp_policy.target_type.clone(),
            _ => "EMAIL".to_string(),
        };
        let otp = if req.resend && otp_policy.resend_same_otp {
            // Java re-sends what it stored, which is the hash of the code (kept: DIFFERENCES.md).
            if req.with_user {
                match req.user_id {
                    Some(uid) => self.dir.store.latest_otp_code(app.id, uid, req.purpose.ok_or_else(null_purpose)?.name()).await?,
                    None => None,
                }
            } else if non_blank(&req.email_id).is_none() && non_blank(&req.phone_number).is_none() {
                None
            } else {
                let purpose = req.purpose.ok_or_else(null_purpose)?;
                self.dir
                    .store
                    .latest_otp_by_target(app.id, non_blank(&req.email_id), non_blank(&req.phone_number), purpose.name())
                    .await?
                    .map(|o| o.unique_code)
            }
        } else {
            generate_code(&otp_policy)?
        };
        let Some(otp) = otp else { return Ok(false) };
        if !self.send_otp(req, &target, otp_policy.expire_interval, &otp).await? {
            return Ok(false);
        }
        let purpose = req.purpose.ok_or_else(null_purpose)?;
        if req.resend && req.with_user {
            self.dir.store.increase_resend_attempts(req.user_id.unwrap_or_default()).await?;
        }
        let hash = bcrypt::hash_with_result(&otp, 10)
            .map(|h| h.format_for_version(bcrypt::Version::TwoA))
            .map_err(AuthError::internal)?;
        let now = self.clock.local();
        self.dir
            .store
            .insert_otp(&NewOtp {
                app_id: app.id,
                user_id: req.user_id,
                email_id: (target != "PHONE").then(|| req.email_id.clone()).flatten(),
                phone_number: (target != "EMAIL").then(|| req.phone_number.clone()).flatten(),
                purpose: purpose.name().into(),
                target_type: target,
                unique_code: hash,
                expires_at: now + chrono::Duration::minutes(otp_policy.expire_interval),
                ip_address: req.ip_address.clone(),
                created_at: now,
            })
            .await?;
        Ok(true)
    }

    /// `sendOtp`: by e-mail (the event), by SMS, or both (either one sent is enough).
    async fn send_otp(&self, req: &OtpRequest, target: &str, expire: i64, otp: &str) -> AuthResult<bool> {
        if otp.trim().is_empty() {
            return Ok(false);
        }
        let email = non_blank(&req.email_id);
        let phone = non_blank(&req.phone_number);
        let send_email = || async {
            let Some(email) = email else { return Ok(false) };
            // `Map.of` refuses a null value: an app without a name cannot send the mail.
            let app_name = req.app_name.clone().ok_or_else(|| AuthError::internal("appName is null"))?;
            let purpose = req.purpose.ok_or_else(null_purpose)?;
            let event = EventMessage {
                event_name: USER_OTP_GENERATE.into(),
                client_code: req.client_code.clone(),
                app_code: Some(req.app_code.clone()),
                x_debug: req.x_debug.clone(),
                draft: false,
                data: vec![
                    ("appName".into(), Value::from(app_name)),
                    ("email".into(), Value::from(email)),
                    ("otp".into(), Value::from(otp)),
                    ("otpPurpose".into(), Value::from(purpose.name())),
                    ("expireInterval".into(), Value::from(expire)),
                ],
            };
            self.events.publish(&event).await
        };
        let send_phone = || async {
            match phone {
                Some(p) => self.sms.send_otp(p, req.purpose.ok_or_else(null_purpose)?.display_name(), otp, expire).await,
                None => Ok(false),
            }
        };
        match target {
            "PHONE" => send_phone().await,
            "BOTH" => {
                if email.is_none() && phone.is_none() {
                    return Ok(false);
                }
                let (e, p) = tokio::join!(send_email(), send_phone());
                Ok(e? || p?)
            }
            _ => send_email().await,
        }
    }

    /// `verifyOtpInternal(appCode, user, LOGIN)`: the user's latest login OTP for the app, unexpired
    /// and matching; a used one is deleted (or its leg counted).
    pub async fn verify_otp(&self, app_code: Option<&str>, user_id: u64, otp: &str) -> AuthResult<bool> {
        self.verify_user_otp(app_code, user_id, OtpPurpose::Login, Some(otp)).await
    }

    /// `verifyOtpInternal(appCode, user, request)`.
    pub async fn verify_user_otp(&self, app_code: Option<&str>, user_id: u64, purpose: OtpPurpose, otp: Option<&str>) -> AuthResult<bool> {
        let Some(app_code) = app_code.filter(|a| !a.trim().is_empty()) else { return Ok(false) };
        let Some(app) = self.dir.app_by_code(app_code).await? else { return Ok(false) };
        let latest = self.dir.store.latest_otp(app.id, user_id, purpose.name()).await?;
        self.use_otp(latest, otp, purpose).await
    }

    /// `verifyOtp(request)` past the inheritance check, and `verifyOtpInternal(appCode, request)`:
    /// the latest OTP sent to the e-mail or phone for the app and purpose.
    pub async fn verify_target_otp(&self, app_id: u64, email: Option<&str>, phone: Option<&str>, purpose: Option<OtpPurpose>, otp: Option<&str>) -> AuthResult<bool> {
        let (email, phone) = (email.filter(|e| !e.trim().is_empty()), phone.filter(|p| !p.trim().is_empty()));
        if email.is_none() && phone.is_none() {
            return Ok(false);
        }
        let purpose = purpose.ok_or_else(null_purpose)?;
        let latest = self.dir.store.latest_otp_by_target(app_id, email, phone, purpose.name()).await?;
        self.use_otp(latest, otp, purpose).await
    }

    /// The private `verifyOtp(latestOtp, otp, purpose)`.
    async fn use_otp(&self, latest: Option<OtpRow>, otp: Option<&str>, purpose: OtpPurpose) -> AuthResult<bool> {
        let Some(latest) = latest else { return Ok(false) };
        if latest.expires_at < self.clock.local() {
            return Ok(false);
        }
        // BCryptPasswordEncoder.matches refuses a null raw password.
        let otp = otp.ok_or_else(|| AuthError::internal("rawPassword cannot be null"))?;
        if !bcrypt::verify(otp, &latest.unique_code).unwrap_or(false) {
            return Ok(false);
        }
        if latest.verify_legs_counts == purpose.verify_legs() {
            self.dir.store.delete_otp(latest.id).await?;
        } else {
            self.dir.store.increase_otp_verify_count(latest.id).await?;
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> OtpPolicy {
        PassType::Otp.default_policy().otp.unwrap()
    }

    #[test]
    fn codes() {
        let c = generate_code(&policy()).unwrap().unwrap();
        assert_eq!(c.len(), 4);
        assert!(c.chars().all(|ch| ch.is_ascii_digit()));
        let alpha = OtpPolicy { is_numeric: false, is_alphanumeric: true, length: 12, ..policy() };
        let c = generate_code(&alpha).unwrap().unwrap();
        assert!(c.chars().all(|ch| UPPERCASE.contains(ch) || LOWERCASE.contains(ch)));
        let both = OtpPolicy { is_alphanumeric: true, length: 30, ..policy() };
        assert_eq!(generate_code(&both).unwrap().unwrap().len(), 30);
        let constant = OtpPolicy { is_constant: true, constant_value: Some("1111".into()), ..policy() };
        assert_eq!(generate_code(&constant).unwrap().as_deref(), Some("1111"));
        let none = OtpPolicy { is_numeric: false, ..policy() };
        assert!(generate_code(&none).is_err());
    }

    #[test]
    fn purposes() {
        for (p, n, d, l) in [
            (OtpPurpose::Registration, "REGISTRATION", "registration", 1),
            (OtpPurpose::Login, "LOGIN", "login", 0),
            (OtpPurpose::Verification, "VERIFICATION", "verification", 0),
            (OtpPurpose::PasswordReset, "PASSWORD_RESET", "password reset", 1),
        ] {
            assert_eq!((p.name(), p.display_name(), p.verify_legs()), (n, d, l));
        }
    }
}

#[cfg(test)]
mod live {
    use super::*;
    use crate::admin::users::testkit::fx;

    #[test]
    fn purposes_from_json() {
        assert_eq!(OtpPurpose::from_json(&serde_json::json!(null)), Ok(None));
        assert_eq!(OtpPurpose::from_json(&serde_json::json!(1)), Ok(Some(OtpPurpose::Login)));
        assert_eq!(OtpPurpose::from_json(&serde_json::json!([1])), Err(()));
    }

    /// `OtpServiceTest`'s resend: with `RESEND_SAME_OTP`, a resend re-sends what is stored, for a
    /// user or for a target (an OTP policy keyed to the scratch client `ZZRUL`).
    #[tokio::test]
    async fn resending_the_same_otp() {
        let Some(fx) = fx().await else { return };
        let auth = &fx.s.auth;
        sqlx::query("INSERT INTO security_client_otp_policy (CLIENT_ID, APP_ID, RESEND_SAME_OTP, LENGTH) VALUES (?, 2, 1, 6)")
            .bind(fx.c)
            .execute(&fx.s.db.pool)
            .await
            .unwrap();
        let a = fx.user(fx.c, "a").await;
        let email = format!("zzrl{}otp@example.invalid", fx.run);
        let req = |resend: bool, with_user: bool| OtpRequest {
            client_id: fx.c,
            client_code: Some("ZZRUL".into()),
            app_id: 2,
            app_code: "appbuilder".into(),
            app_name: Some("App Builder".into()),
            user_id: with_user.then_some(a.id),
            email_id: Some(if with_user { a.email_id.clone().unwrap() } else { email.clone() }),
            phone_number: None,
            ip_address: Some("127.0.0.1".into()),
            resend,
            x_debug: None,
            purpose: Some(OtpPurpose::Verification),
            with_user,
        };
        assert!(auth.generate_otp_internal(&req(false, false)).await.unwrap());
        assert!(auth.generate_otp_internal(&req(true, false)).await.unwrap(), "the stored OTP again");
        let blank = OtpRequest { email_id: None, ..req(true, false) };
        assert!(!auth.generate_otp_internal(&blank).await.unwrap(), "no target to look up");
        assert!(auth.generate_otp_internal(&req(false, true)).await.unwrap());
        assert!(auth.generate_otp_internal(&req(true, true)).await.unwrap());
        let none = OtpRequest { user_id: None, ..req(true, true) };
        assert!(!auth.generate_otp_internal(&none).await.unwrap());
        assert!(!auth.verify_user_otp(Some("nosuchapp"), a.id, OtpPurpose::Verification, Some("1")).await.unwrap());
        sqlx::query("DELETE FROM security_otp WHERE APP_ID = 2 AND (USER_ID = ? OR EMAIL_ID = ?)").bind(a.id).bind(&email).execute(&fx.s.db.pool).await.unwrap();
        fx.finish().await;
    }
}
