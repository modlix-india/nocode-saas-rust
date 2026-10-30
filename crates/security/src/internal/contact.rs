//! Contact codes (Rust only, no Java counterpart): a one-time code sent to an e-mail address or a
//! phone number that a signed-in user says is theirs, so a server function can trust the answer.
//!
//! `POST /api/security/internal/contactCodes` issues a code and `.../contactCodes/verify` checks it.
//! Core's `CoreServices.Security.SendContactCode` / `VerifyContactCode` are the only callers: they
//! pass the signed-in user, the URL's app and client, and the target, all from the caller's own
//! context (never from a browser). nginx refuses every `/internal` path from outside.
//!
//! The rows live in `security_otp` under their own purpose, [`PURPOSE`], so the sign-in and
//! `/otp/verify` paths never read them. For these rows `VERIFY_LEGS_COUNTS` counts wrong tries,
//! and [`USED`] marks a code that was accepted. A used row is kept (not deleted, unlike the other
//! purposes) so the hourly limit still counts it.
//!
//! Rules, per app and user:
//! - one code per target every [`RESEND_AFTER_SECONDS`] seconds,
//! - at most [`SENDS_PER_HOUR`] codes in any hour (all targets together),
//! - at most [`MAX_WRONG_TRIES`] wrong tries per code, then a new code is needed,
//! - only the latest code of a target counts, once, before it expires (the app's OTP policy:
//!   length, characters, expiry; the policy's target type does not apply, the caller chose it).
//!
//! Delivery: `RETURN` hands the code back to core, which sends it (the app's
//! `USER_OTP_GENERATE` e-mail, or the institution's own SMS connection); `PLATFORM_SMS` sends it
//! here through the platform's 2Factor account, which covers Indian (+91) numbers only.

use async_trait::async_trait;
use chrono::{Duration, NaiveDateTime};
use serde_json::{json, Map, Value};

use crate::errors::{AuthError, AuthResult};
use crate::events::SmsSender;
use crate::model::OtpPolicy;
use crate::otp::generate_code;

/// The `security_otp.PURPOSE` of these rows.
pub const PURPOSE: &str = "CONTACT_VERIFICATION";
/// `VERIFY_LEGS_COUNTS` of a code that was accepted.
pub const USED: i64 = -1;
pub const RESEND_AFTER_SECONDS: i64 = 30;
pub const SENDS_PER_HOUR: u64 = 5;
pub const MAX_WRONG_TRIES: i64 = 5;
/// The 2Factor account's DLT template is registered in India only.
pub const PLATFORM_SMS_COUNTRY: &str = "91";

/// Which kind of address a code goes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Email,
    Phone,
}

impl Channel {
    pub fn target_type(self) -> &'static str {
        match self {
            Self::Email => "EMAIL",
            Self::Phone => "PHONE",
        }
    }
}

/// A normalized target: a lower-case e-mail address, or a phone number as `+<digits>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub channel: Channel,
    pub value: String,
}

impl Target {
    /// Exactly one of the two, well formed. `Err` holds the plain-words reason.
    pub fn read(email: Option<&str>, phone: Option<&str>) -> Result<Self, &'static str> {
        let email = email.map(str::trim).filter(|e| !e.is_empty());
        let phone = phone.map(str::trim).filter(|p| !p.is_empty());
        match (email, phone) {
            (Some(_), Some(_)) => Err("Send one e-mail address or one phone number, not both."),
            (None, None) => Err("Give an e-mail address or a phone number."),
            (Some(e), None) => {
                let e = e.to_lowercase();
                let ok = e.len() <= 320
                    && !e.chars().any(char::is_whitespace)
                    && matches!(e.split_once('@'), Some((local, domain)) if !local.is_empty() && !domain.contains('@')
                        && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.'));
                if ok {
                    Ok(Self { channel: Channel::Email, value: e })
                } else {
                    Err("This is not an e-mail address.")
                }
            }
            (None, Some(p)) => {
                let plus = p.starts_with('+');
                let digits: String = p.chars().filter(char::is_ascii_digit).collect();
                let clean = p.chars().all(|c| c.is_ascii_digit() || " +-().".contains(c));
                if !plus || !clean || !(8..=15).contains(&digits.len()) {
                    Err("Give the mobile number with its country code, for example +91 98450 12345.")
                } else {
                    Ok(Self { channel: Channel::Phone, value: format!("+{digits}") })
                }
            }
        }
    }

    pub fn email(&self) -> Option<&str> {
        (self.channel == Channel::Email).then_some(self.value.as_str())
    }

    pub fn phone(&self) -> Option<&str> {
        (self.channel == Channel::Phone).then_some(self.value.as_str())
    }

    /// An Indian mobile number: `+91` and ten digits.
    pub fn is_platform_sms_number(&self) -> bool {
        self.channel == Channel::Phone && self.value.len() == 13 && self.value[1..].starts_with(PLATFORM_SMS_COUNTRY)
    }
}

/// One contact code row.
#[derive(Debug, Clone)]
pub struct CodeRow {
    pub id: u64,
    pub unique_code: String,
    pub created_at: NaiveDateTime,
    pub expires_at: NaiveDateTime,
    /// Wrong tries, or [`USED`].
    pub tries: i64,
}

#[derive(Debug, Clone)]
pub struct NewCode {
    pub app_id: u64,
    pub user_id: u64,
    pub target: Target,
    pub unique_code: String,
    pub created_at: NaiveDateTime,
    pub expires_at: NaiveDateTime,
    pub ip_address: Option<String>,
}

#[async_trait]
pub trait ContactCodeStore: Send + Sync {
    /// Codes of the app issued to the user at or after `since`.
    async fn count_since(&self, app_id: u64, user_id: u64, since: NaiveDateTime) -> AuthResult<u64>;
    /// The user's latest code of the app for the target.
    async fn latest(&self, app_id: u64, user_id: u64, target: &Target) -> AuthResult<Option<CodeRow>>;
    async fn insert(&self, code: &NewCode) -> AuthResult<()>;
    /// Sets the row's tries (a wrong try, or [`USED`]); false when the row changed meanwhile.
    async fn set_tries(&self, id: u64, from: i64, to: i64) -> AuthResult<bool>;
}

/// How the issued code reaches the person.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// Back to the caller (core), who sends it.
    Return,
    /// By the platform's 2Factor SMS (Indian numbers only).
    PlatformSms,
}

impl Delivery {
    pub fn read(s: Option<&str>) -> Option<Self> {
        match s.map(str::trim) {
            None | Some("") | Some("RETURN") => Some(Self::Return),
            Some("PLATFORM_SMS") => Some(Self::PlatformSms),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct IssueRequest {
    pub app_id: u64,
    pub app_name: Option<String>,
    pub user_id: u64,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub ip_address: Option<String>,
    pub delivery: Delivery,
}

#[derive(Debug, Clone)]
pub struct VerifyRequest {
    pub app_id: u64,
    pub user_id: u64,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub code: Option<String>,
}

/// A refusal the caller expects (200, `ok: false`): not an error of the service.
fn refused(reason: &str, message: &str, extra: &[(&str, Value)]) -> Value {
    let mut m = Map::new();
    m.insert("ok".into(), Value::Bool(false));
    m.insert("reason".into(), Value::from(reason));
    m.insert("message".into(), Value::from(message));
    for (k, v) in extra {
        m.insert((*k).into(), v.clone());
    }
    Value::Object(m)
}

pub struct ContactCodes<'a> {
    pub store: &'a dyn ContactCodeStore,
    pub sms: &'a dyn SmsSender,
    /// The service's wall clock (`Clock::local`), as every `security_otp` row is written.
    pub now: NaiveDateTime,
}

impl ContactCodes<'_> {
    /// Issues a code for `req` under `policy`. The answer is `{ok, reason, message, ...}`; the
    /// code itself only with [`Delivery::Return`].
    pub async fn issue(&self, policy: &OtpPolicy, req: &IssueRequest) -> AuthResult<Value> {
        let target = match Target::read(req.email.as_deref(), req.phone.as_deref()) {
            Ok(t) => t,
            Err(m) => return Ok(refused("INVALID", m, &[])),
        };
        let base = [("channel", Value::from(target.channel.target_type())), ("target", Value::from(target.value.clone()))];
        if req.delivery == Delivery::PlatformSms && !target.is_platform_sms_number() {
            return Ok(refused(
                "NO_SMS",
                "We cannot send a text message to this number yet. Use an Indian (+91) mobile number, or ask the office to verify it.",
                &base,
            ));
        }
        if let Some(last) = self.store.latest(req.app_id, req.user_id, &target).await? {
            let wait = RESEND_AFTER_SECONDS - (self.now - last.created_at).num_seconds();
            if wait > 0 {
                let mut extra = base.to_vec();
                extra.push(("retryAfterSeconds", Value::from(wait)));
                return Ok(refused("WAIT", &format!("A code was just sent. You can ask for another in {wait} seconds."), &extra));
            }
        }
        if self.store.count_since(req.app_id, req.user_id, self.now - Duration::hours(1)).await? >= SENDS_PER_HOUR {
            return Ok(refused("LIMIT", "Too many codes were asked for in the last hour. Please try again later.", &base));
        }
        let Some(code) = generate_code(policy)?.filter(|c| !c.trim().is_empty()) else {
            return Err(AuthError::internal("the OTP policy gives no code"));
        };
        let expire = policy.expire_interval.max(1);
        if req.delivery == Delivery::PlatformSms {
            let phone = target.phone().unwrap_or_default();
            if !self.sms.send_otp(phone, "verification", &code, expire).await? {
                return Ok(refused("SEND_FAILED", "We could not send the text message. Please try again in a few minutes.", &base));
            }
        }
        let hash = bcrypt::hash_with_result(&code, 10)
            .map(|h| h.format_for_version(bcrypt::Version::TwoA))
            .map_err(AuthError::internal)?;
        self.store
            .insert(&NewCode {
                app_id: req.app_id,
                user_id: req.user_id,
                target: target.clone(),
                unique_code: hash,
                created_at: self.now,
                expires_at: self.now + Duration::minutes(expire),
                ip_address: req.ip_address.clone(),
            })
            .await?;
        let mut out = json!({
            "ok": true,
            "channel": target.channel.target_type(),
            "target": target.value,
            "expireMinutes": expire,
            "resendAfterSeconds": RESEND_AFTER_SECONDS,
            "appName": req.app_name.clone().unwrap_or_default(),
            "sent": req.delivery == Delivery::PlatformSms,
        });
        if req.delivery == Delivery::Return {
            out["code"] = Value::from(code);
        }
        Ok(out)
    }

    /// Checks a code: `{ok: true, target}` once, for the latest unexpired code of the target.
    pub async fn verify(&self, req: &VerifyRequest) -> AuthResult<Value> {
        let target = match Target::read(req.email.as_deref(), req.phone.as_deref()) {
            Ok(t) => t,
            Err(m) => return Ok(refused("INVALID", m, &[])),
        };
        let base = [("channel", Value::from(target.channel.target_type())), ("target", Value::from(target.value.clone()))];
        let code = req.code.as_deref().map(str::trim).unwrap_or_default();
        if code.is_empty() {
            return Ok(refused("WRONG_CODE", "Enter the code we sent you.", &base));
        }
        let Some(row) = self.store.latest(req.app_id, req.user_id, &target).await? else {
            return Ok(refused("NO_CODE", "Ask for a code first.", &base));
        };
        if row.tries == USED {
            return Ok(refused("NO_CODE", "This code was already used. Ask for a new one.", &base));
        }
        if row.expires_at < self.now {
            return Ok(refused("EXPIRED", "This code has expired. Ask for a new one.", &base));
        }
        if row.tries >= MAX_WRONG_TRIES {
            return Ok(refused("TOO_MANY_TRIES", "Too many wrong tries. Ask for a new code.", &base));
        }
        if !bcrypt::verify(code, &row.unique_code).unwrap_or(false) {
            let tries = row.tries + 1;
            self.store.set_tries(row.id, row.tries, tries).await?;
            let left = MAX_WRONG_TRIES - tries;
            if left <= 0 {
                return Ok(refused("TOO_MANY_TRIES", "Too many wrong tries. Ask for a new code.", &base));
            }
            let mut extra = base.to_vec();
            extra.push(("triesLeft", Value::from(left)));
            return Ok(refused("WRONG_CODE", "That code is not right. Check it and try again.", &extra));
        }
        // Only one caller may use it: the row must still hold the tries it was read with.
        if !self.store.set_tries(row.id, row.tries, USED).await? {
            return Ok(refused("NO_CODE", "This code was already used. Ask for a new one.", &base));
        }
        Ok(json!({"ok": true, "channel": target.channel.target_type(), "target": target.value}))
    }
}

/// The body's text field, blank as absent.
fn field(v: &Value, name: &str) -> AuthResult<Option<String>> {
    Ok(crate::web::opt_text(v.get(name))?.filter(|s| !s.trim().is_empty()))
}

impl super::Internal {
    /// The app, the client's OTP policy for it and the user, as the body names them; `Err` holds
    /// the refusal to answer with.
    async fn contact_scope(&self, v: &Value) -> AuthResult<Result<(std::sync::Arc<crate::model::App>, OtpPolicy, u64), Value>> {
        let user_id = crate::web::opt_u64_json(v.get("userId"))?.unwrap_or(0);
        if user_id == 0 {
            return Ok(Err(refused("SIGN_IN", "Please sign in to verify an e-mail address or a phone number.", &[])));
        }
        let unknown = || Ok(Err(refused("APP", "This app or organisation is not known.", &[])));
        let Some(app) = (match field(v, "appCode")? {
            Some(a) => self.dir().app_by_code(&a).await?,
            None => None,
        }) else {
            return unknown();
        };
        let Some(client) = (match field(v, "clientCode")? {
            Some(c) => self.dir().client_by_code(&c).await?,
            None => None,
        }) else {
            return unknown();
        };
        let policy = self.dir().policy_for_app(client.id(), app.id, crate::model::PassType::Otp).await?;
        Ok(Ok((app, policy.otp.unwrap_or_else(OtpPolicy::defaults), user_id)))
    }

    /// `POST /api/security/internal/contactCodes`.
    pub async fn contact_code_issue(&self, v: &Value) -> AuthResult<Value> {
        let Some(delivery) = Delivery::read(field(v, "delivery")?.as_deref()) else {
            return Ok(refused("INVALID", "Unknown delivery.", &[]));
        };
        let (app, policy, user_id) = match self.contact_scope(v).await? {
            Ok(s) => s,
            Err(refusal) => return Ok(refusal),
        };
        let req = IssueRequest {
            app_id: app.id,
            app_name: app.app_name.clone(),
            user_id,
            email: field(v, "emailId")?,
            phone: field(v, "phoneNumber")?,
            ip_address: field(v, "ipAddress")?,
            delivery,
        };
        let store = MySqlContactCodes { pool: self.db.pool.clone() };
        ContactCodes { store: &store, sms: self.auth.sms.as_ref(), now: self.auth.clock.local() }.issue(&policy, &req).await
    }

    /// `POST /api/security/internal/contactCodes/verify`.
    pub async fn contact_code_verify(&self, v: &Value) -> AuthResult<Value> {
        let (app, _, user_id) = match self.contact_scope(v).await? {
            Ok(s) => s,
            Err(refusal) => return Ok(refusal),
        };
        let req = VerifyRequest { app_id: app.id, user_id, email: field(v, "emailId")?, phone: field(v, "phoneNumber")?, code: field(v, "code")? };
        let store = MySqlContactCodes { pool: self.db.pool.clone() };
        ContactCodes { store: &store, sms: self.auth.sms.as_ref(), now: self.auth.clock.local() }.verify(&req).await
    }
}

/// The rows in `security_otp`.
pub struct MySqlContactCodes {
    pub pool: sqlx::MySqlPool,
}

#[async_trait]
impl ContactCodeStore for MySqlContactCodes {
    async fn count_since(&self, app_id: u64, user_id: u64, since: NaiveDateTime) -> AuthResult<u64> {
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM security_otp WHERE APP_ID = ? AND USER_ID = ? AND PURPOSE = ? AND CREATED_AT >= ?",
        )
        .bind(app_id)
        .bind(user_id)
        .bind(PURPOSE)
        .bind(since)
        .fetch_one(&self.pool)
        .await?;
        Ok(n.max(0) as u64)
    }

    async fn latest(&self, app_id: u64, user_id: u64, target: &Target) -> AuthResult<Option<CodeRow>> {
        use sqlx::Row;
        let column = match target.channel {
            Channel::Email => "EMAIL_ID",
            Channel::Phone => "PHONE_NUMBER",
        };
        let sql = format!(
            "SELECT ID, UNIQUE_CODE, CREATED_AT, EXPIRES_AT, VERIFY_LEGS_COUNTS FROM security_otp \
             WHERE APP_ID = ? AND USER_ID = ? AND PURPOSE = ? AND {column} = ? ORDER BY ID DESC LIMIT 1"
        );
        let row = sqlx::query(&sql)
            .bind(app_id)
            .bind(user_id)
            .bind(PURPOSE)
            .bind(&target.value)
            .fetch_optional(&self.pool)
            .await?;
        Ok(match row {
            Some(r) => Some(CodeRow {
                id: r.try_get("ID")?,
                unique_code: r.try_get("UNIQUE_CODE")?,
                created_at: r.try_get::<chrono::DateTime<chrono::Utc>, _>("CREATED_AT")?.naive_utc(),
                expires_at: r.try_get::<chrono::DateTime<chrono::Utc>, _>("EXPIRES_AT")?.naive_utc(),
                tries: i64::from(r.try_get::<i16, _>("VERIFY_LEGS_COUNTS")?),
            }),
            None => None,
        })
    }

    async fn insert(&self, c: &NewCode) -> AuthResult<()> {
        sqlx::query(
            "INSERT INTO security_otp (APP_ID, USER_ID, EMAIL_ID, PHONE_NUMBER, PURPOSE, TARGET_TYPE, UNIQUE_CODE, \
             EXPIRES_AT, IP_ADDRESS, CREATED_BY, CREATED_AT) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(c.app_id)
        .bind(c.user_id)
        .bind(c.target.email())
        .bind(c.target.phone())
        .bind(PURPOSE)
        .bind(c.target.channel.target_type())
        .bind(&c.unique_code)
        .bind(c.expires_at)
        .bind(&c.ip_address)
        .bind(c.user_id)
        .bind(c.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn set_tries(&self, id: u64, from: i64, to: i64) -> AuthResult<bool> {
        let r = sqlx::query("UPDATE security_otp SET VERIFY_LEGS_COUNTS = ? WHERE ID = ? AND PURPOSE = ? AND VERIFY_LEGS_COUNTS = ?")
            .bind(to as i16)
            .bind(id)
            .bind(PURPOSE)
            .bind(from as i16)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::Mutex;

    /// The table in memory.
    #[derive(Default)]
    pub struct MemoryCodes {
        rows: Mutex<Vec<(NewCode, u64, i64)>>,
    }

    #[async_trait]
    impl ContactCodeStore for MemoryCodes {
        async fn count_since(&self, app_id: u64, user_id: u64, since: NaiveDateTime) -> AuthResult<u64> {
            Ok(self.rows.lock().unwrap().iter().filter(|(c, _, _)| c.app_id == app_id && c.user_id == user_id && c.created_at >= since).count() as u64)
        }

        async fn latest(&self, app_id: u64, user_id: u64, target: &Target) -> AuthResult<Option<CodeRow>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .rev()
                .find(|(c, _, _)| c.app_id == app_id && c.user_id == user_id && &c.target == target)
                .map(|(c, id, tries)| CodeRow { id: *id, unique_code: c.unique_code.clone(), created_at: c.created_at, expires_at: c.expires_at, tries: *tries }))
        }

        async fn insert(&self, code: &NewCode) -> AuthResult<()> {
            let mut rows = self.rows.lock().unwrap();
            let id = rows.len() as u64 + 1;
            rows.push((code.clone(), id, 0));
            Ok(())
        }

        async fn set_tries(&self, id: u64, from: i64, to: i64) -> AuthResult<bool> {
            let mut rows = self.rows.lock().unwrap();
            match rows.iter_mut().find(|(_, i, t)| *i == id && *t == from) {
                Some(r) => {
                    r.2 = to;
                    Ok(true)
                }
                None => Ok(false),
            }
        }
    }

    /// Records each SMS instead of sending it.
    #[derive(Default)]
    pub struct LoggedSms {
        pub sent: Mutex<Vec<(String, String)>>,
        pub fail: bool,
    }

    #[async_trait]
    impl SmsSender for LoggedSms {
        async fn send_otp(&self, phone: &str, _purpose: &str, otp: &str, _expire: i64) -> AuthResult<bool> {
            self.sent.lock().unwrap().push((phone.into(), otp.into()));
            Ok(!self.fail)
        }
    }

    fn at(minute: i64, second: i64) -> NaiveDateTime {
        chrono::NaiveDate::from_ymd_opt(2026, 10, 30).unwrap().and_hms_opt(10, 0, 0).unwrap() + Duration::minutes(minute) + Duration::seconds(second)
    }

    fn policy() -> OtpPolicy {
        OtpPolicy { length: 6, expire_interval: 10, ..OtpPolicy::defaults() }
    }

    fn issue(user: u64, email: Option<&str>, phone: Option<&str>, delivery: Delivery) -> IssueRequest {
        IssueRequest {
            app_id: 7,
            app_name: Some("CXZump".into()),
            user_id: user,
            email: email.map(str::to_string),
            phone: phone.map(str::to_string),
            ip_address: Some("10.0.0.1".into()),
            delivery,
        }
    }

    fn check(user: u64, email: Option<&str>, phone: Option<&str>, code: &str) -> VerifyRequest {
        VerifyRequest { app_id: 7, user_id: user, email: email.map(str::to_string), phone: phone.map(str::to_string), code: Some(code.into()) }
    }

    fn reason(v: &Value) -> &str {
        v["reason"].as_str().unwrap_or("")
    }

    #[test]
    fn targets() {
        let e = Target::read(Some("  Asha.K+kyc@Example.COM "), None).unwrap();
        assert_eq!((e.channel, e.value.as_str()), (Channel::Email, "asha.k+kyc@example.com"));
        let p = Target::read(None, Some("+91 98450-12345")).unwrap();
        assert_eq!((p.channel, p.value.as_str(), p.is_platform_sms_number()), (Channel::Phone, "+919845012345", true));
        assert!(!Target::read(None, Some("+65 8123 4567")).unwrap().is_platform_sms_number());
        assert!(!Target::read(None, Some("+9198450123")).unwrap().is_platform_sms_number(), "too short for an Indian mobile");
        for bad in ["9845012345", "+91 98450 1234x", "+12", "+1234567890123456"] {
            assert!(Target::read(None, Some(bad)).is_err(), "{bad}");
        }
        for bad in ["a@b", "a b@c.d", "@c.d", "a@.d", "a@b.", "a@b@c.d", "plain"] {
            assert!(Target::read(Some(bad), None).is_err(), "{bad}");
        }
        assert!(Target::read(Some("a@b.c"), Some("+919845012345")).is_err(), "one at a time");
        assert!(Target::read(Some(" "), Some("")).is_err());
        assert_eq!(Delivery::read(None), Some(Delivery::Return));
        assert_eq!(Delivery::read(Some("PLATFORM_SMS")), Some(Delivery::PlatformSms));
        assert_eq!(Delivery::read(Some("EMAIL")), None);
    }

    #[tokio::test]
    async fn issue_and_verify_once() {
        let store = MemoryCodes::default();
        let sms = LoggedSms::default();
        let cc = |now| ContactCodes { store: &store, sms: &sms, now };
        let out = cc(at(0, 0)).issue(&policy(), &issue(1, Some("Asha@Example.com"), None, Delivery::Return)).await.unwrap();
        assert_eq!(out["ok"], true);
        assert_eq!((out["target"].as_str(), out["channel"].as_str(), out["expireMinutes"].as_i64()), (Some("asha@example.com"), Some("EMAIL"), Some(10)));
        assert_eq!((out["sent"].as_bool(), out["appName"].as_str()), (Some(false), Some("CXZump")));
        let code = out["code"].as_str().unwrap().to_string();
        assert_eq!(code.len(), 6);
        assert!(sms.sent.lock().unwrap().is_empty(), "RETURN sends nothing here");
        let stored = store.rows.lock().unwrap()[0].0.unique_code.clone();
        assert_ne!(stored, code, "only the hash is kept");

        let wrong = if code == "000000" { "111111" } else { "000000" };
        let v = cc(at(1, 0)).verify(&check(1, Some("asha@example.com"), None, wrong)).await.unwrap();
        assert_eq!((reason(&v), v["triesLeft"].as_i64()), ("WRONG_CODE", Some(4)));
        let other_user = cc(at(1, 0)).verify(&check(2, Some("asha@example.com"), None, &code)).await.unwrap();
        assert_eq!(reason(&other_user), "NO_CODE", "another user's code is not theirs");
        let other_target = cc(at(1, 0)).verify(&check(1, Some("someone@example.com"), None, &code)).await.unwrap();
        assert_eq!(reason(&other_target), "NO_CODE");
        let ok = cc(at(2, 0)).verify(&check(1, Some(" ASHA@example.com "), None, &format!(" {code} "))).await.unwrap();
        assert_eq!((ok["ok"].as_bool(), ok["target"].as_str()), (Some(true), Some("asha@example.com")));
        let again = cc(at(2, 1)).verify(&check(1, Some("asha@example.com"), None, &code)).await.unwrap();
        assert_eq!(reason(&again), "NO_CODE", "a code is good once");
        let empty = cc(at(2, 1)).verify(&check(1, Some("asha@example.com"), None, " ")).await.unwrap();
        assert_eq!(reason(&empty), "WRONG_CODE");
    }

    #[tokio::test]
    async fn expiry_and_wrong_tries() {
        let store = MemoryCodes::default();
        let sms = LoggedSms::default();
        let cc = |now| ContactCodes { store: &store, sms: &sms, now };
        let code = cc(at(0, 0)).issue(&policy(), &issue(1, None, Some("+919845012345"), Delivery::Return)).await.unwrap()["code"]
            .as_str()
            .unwrap()
            .to_string();
        let late = cc(at(10, 1)).verify(&check(1, None, Some("+91 98450 12345"), &code)).await.unwrap();
        assert_eq!(reason(&late), "EXPIRED");

        let code = cc(at(11, 0)).issue(&policy(), &issue(1, None, Some("+919845012345"), Delivery::Return)).await.unwrap()["code"]
            .as_str()
            .unwrap()
            .to_string();
        let wrong = if code == "000000" { "111111" } else { "000000" };
        for left in (1..MAX_WRONG_TRIES).rev() {
            let v = cc(at(12, 0)).verify(&check(1, None, Some("+919845012345"), wrong)).await.unwrap();
            assert_eq!((reason(&v), v["triesLeft"].as_i64()), ("WRONG_CODE", Some(left)));
        }
        let last = cc(at(12, 0)).verify(&check(1, None, Some("+919845012345"), wrong)).await.unwrap();
        assert_eq!(reason(&last), "TOO_MANY_TRIES");
        let right_too_late = cc(at(12, 0)).verify(&check(1, None, Some("+919845012345"), &code)).await.unwrap();
        assert_eq!(reason(&right_too_late), "TOO_MANY_TRIES", "the right code no longer counts");
    }

    #[tokio::test]
    async fn resend_wait_and_hourly_limit() {
        let store = MemoryCodes::default();
        let sms = LoggedSms::default();
        let cc = |now| ContactCodes { store: &store, sms: &sms, now };
        let req = |e: &str| issue(1, Some(e), None, Delivery::Return);
        assert_eq!(cc(at(0, 0)).issue(&policy(), &req("a@x.io")).await.unwrap()["ok"], true);
        let soon = cc(at(0, 10)).issue(&policy(), &req("a@x.io")).await.unwrap();
        assert_eq!((reason(&soon), soon["retryAfterSeconds"].as_i64()), ("WAIT", Some(20)));
        assert_eq!(cc(at(0, 10)).issue(&policy(), &req("b@x.io")).await.unwrap()["ok"], true, "the wait is per target");
        for (i, e) in ["a@x.io", "c@x.io", "d@x.io"].iter().enumerate() {
            assert_eq!(cc(at(1 + i as i64, 0)).issue(&policy(), &req(e)).await.unwrap()["ok"], true);
        }
        let sixth = cc(at(5, 0)).issue(&policy(), &req("e@x.io")).await.unwrap();
        assert_eq!(reason(&sixth), "LIMIT");
        assert_eq!(cc(at(5, 0)).issue(&policy(), &issue(2, Some("e@x.io"), None, Delivery::Return)).await.unwrap()["ok"], true, "per user");
        assert_eq!(cc(at(60, 1)).issue(&policy(), &req("e@x.io")).await.unwrap()["ok"], true, "an hour later");
        let bad = cc(at(61, 0)).issue(&policy(), &req("nope")).await.unwrap();
        assert_eq!(reason(&bad), "INVALID");
    }

    #[tokio::test]
    async fn platform_sms_only_for_indian_numbers() {
        let store = MemoryCodes::default();
        let sms = LoggedSms::default();
        let cc = ContactCodes { store: &store, sms: &sms, now: at(0, 0) };
        let abroad = cc.issue(&policy(), &issue(1, None, Some("+6581234567"), Delivery::PlatformSms)).await.unwrap();
        assert_eq!(reason(&abroad), "NO_SMS");
        let email = cc.issue(&policy(), &issue(1, Some("a@x.io"), None, Delivery::PlatformSms)).await.unwrap();
        assert_eq!(reason(&email), "NO_SMS");
        assert!(store.rows.lock().unwrap().is_empty(), "nothing issued, nothing counted");
        let out = cc.issue(&policy(), &issue(1, None, Some("+91 98450 12345"), Delivery::PlatformSms)).await.unwrap();
        assert_eq!((out["ok"].as_bool(), out["sent"].as_bool()), (Some(true), Some(true)));
        assert!(out.get("code").is_none(), "a code sent here never goes back");
        let sent = sms.sent.lock().unwrap().clone();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, "+919845012345");
        let ok = cc.verify(&check(1, None, Some("+919845012345"), &sent[0].1)).await.unwrap();
        assert_eq!(ok["ok"], true);

        let failing = LoggedSms { fail: true, ..Default::default() };
        let store2 = MemoryCodes::default();
        let cc2 = ContactCodes { store: &store2, sms: &failing, now: at(0, 0) };
        let out = cc2.issue(&policy(), &issue(1, None, Some("+919845012345"), Delivery::PlatformSms)).await.unwrap();
        assert_eq!(reason(&out), "SEND_FAILED");
        assert!(store2.rows.lock().unwrap().is_empty(), "an unsent code is not stored");
    }

    #[tokio::test]
    async fn constant_policy_and_used_row_counts() {
        let store = MemoryCodes::default();
        let sms = LoggedSms::default();
        let constant = OtpPolicy { is_constant: true, constant_value: Some("111111".into()), ..policy() };
        let cc = ContactCodes { store: &store, sms: &sms, now: at(0, 0) };
        let out = cc.issue(&constant, &issue(1, Some("a@x.io"), None, Delivery::Return)).await.unwrap();
        assert_eq!(out["code"], "111111");
        assert_eq!(cc.verify(&check(1, Some("a@x.io"), None, "111111")).await.unwrap()["ok"], true);
        assert_eq!(store.count_since(7, 1, at(0, 0)).await.unwrap(), 1, "a used code still counts toward the hour");
        let none = OtpPolicy { is_constant: true, constant_value: None, ..policy() };
        assert!(ContactCodes { store: &store, sms: &sms, now: at(5, 0) }.issue(&none, &issue(1, Some("b@x.io"), None, Delivery::Return)).await.is_err());
    }
}
