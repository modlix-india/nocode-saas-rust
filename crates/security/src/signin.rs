//! Signing in: `authenticate` (password, PIN or OTP), `authenticate/social`,
//! `authenticate/otp/generate`, the password check with its failed-attempt counting and
//! locking, and the token minted at the end (`makeToken`).

use axum::http::StatusCode;
use serde::Deserialize;

use crate::context::{check_user_and_client, Found};
use crate::errors::{
    AuthError, AuthResult, ACCESS_REQUEST_REQUIRED, NO_REGISTRATION_AVAILABLE, SESSION_EXPIRED, SOCIAL_LOGIN_FAILED,
    UNKNOWN_ERROR, USER_ACCOUNT_BLOCKED, USER_CREDENTIALS_MISMATCHED, USER_PASSWORD_INVALID_ATTEMPTS,
};
use crate::jwt::{self, Claims};
use crate::model::{AuthResponse, Client, Origin, PassType, Policy, User};
use crate::otp::OtpRequest;
use crate::request::RequestInfo;
use crate::service::{Auth, SOX_LOGIN, SOX_UPDATE};
use crate::store::{IdentifierType, NewOneTimeToken, NewToken, StateRow, UserQuery};

/// `AuthenticationRequest` as Jackson reads it (unknown properties ignored).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AuthRequest {
    pub user_name: Option<String>,
    pub password: Option<String>,
    #[serde(deserialize_with = "crate::handlers::de_opt_u64")]
    pub user_id: Option<u64>,
    pub otp: Option<String>,
    #[serde(deserialize_with = "crate::handlers::de_bool")]
    pub resend: bool,
    pub pin: Option<String>,
    pub social_register_state: Option<String>,
    pub identifier_type: Option<String>,
    #[serde(deserialize_with = "crate::handlers::de_bool")]
    pub remember_me: bool,
    #[serde(deserialize_with = "crate::handlers::de_bool")]
    pub cookie: bool,
    #[serde(deserialize_with = "crate::handlers::de_bool")]
    pub generate_otp: bool,
    #[serde(deserialize_with = "crate::handlers::de_bool")]
    pub sso_token: bool,
}

fn blank(s: &Option<String>) -> bool {
    s.as_deref().map(|v| v.trim().is_empty()).unwrap_or(true)
}

impl AuthRequest {
    /// `BasePassword.getInputPassType()`: password, else PIN, else OTP, whichever is given.
    pub fn pass_type(&self) -> Option<PassType> {
        if !blank(&self.password) {
            Some(PassType::Password)
        } else if !blank(&self.pin) {
            Some(PassType::Pin)
        } else if !blank(&self.otp) {
            Some(PassType::Otp)
        } else {
            None
        }
    }

    /// `getInputPass()`.
    pub fn pass(&self) -> Option<String> {
        match self.pass_type()? {
            PassType::Password => self.password.clone(),
            PassType::Pin => self.pin.clone(),
            PassType::Otp => self.otp.clone(),
        }
    }

    pub fn identifier(&self) -> IdentifierType {
        IdentifierType::computed(self.identifier_type.as_deref().and_then(IdentifierType::parse), self.user_name.as_deref())
    }
}

/// What the response carries besides its body: the `Authorization` cookie to set.
#[derive(Debug, Clone, Default)]
pub struct Minted {
    pub response: AuthResponse,
    pub cookie: Option<String>,
}

/// `ResponseCookie.from("Authorization", value).path("/").maxAge(seconds)` as reactor-netty's
/// cookie encoder writes it (Max-Age, Expires, then Path).
pub fn auth_cookie(value: &str, max_age_seconds: i64, now_millis: i64) -> String {
    let expires = chrono::DateTime::from_timestamp_millis(now_millis + max_age_seconds * 1000).unwrap_or_default();
    format!(
        "Authorization={value}; Max-Age={max_age_seconds}; Expires={}; Path=/",
        expires.format("%a, %d %b %Y %H:%M:%S GMT")
    )
}

/// `UUID.randomUUID().toString().replace("-", "")`.
pub fn random_uuid_hex() -> String {
    let mut b: [u8; 16] = rand::random();
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// `isStateExpired`: measured from when the provider verified the identity (`UPDATED_AT`), in UTC.
pub fn is_state_expired(s: &StateRow, now_utc: chrono::NaiveDateTime) -> bool {
    match s.updated_at.or(s.created_at) {
        Some(at) => at < now_utc - chrono::Duration::minutes(10),
        None => true,
    }
}

/// The token-minting part of a sign-in request.
#[derive(Debug, Clone, Copy, Default)]
pub struct MintOptions {
    pub remember_me: bool,
    pub cookie: bool,
    pub sso_token: bool,
}

impl From<&AuthRequest> for MintOptions {
    fn from(r: &AuthRequest) -> Self {
        Self { remember_me: r.remember_me, cookie: r.cookie, sso_token: r.sso_token }
    }
}

impl Auth {
    /// `POST authenticate`. `caller_id` is the requester's own user id (0 when anonymous), which
    /// Java records as the token row's `CREATED_BY`.
    pub async fn authenticate(&self, body: &AuthRequest, req: &RequestInfo, caller_id: u64) -> AuthResult<Minted> {
        if let Some(m) = self.authenticate_once(body, req, caller_id).await? {
            return Ok(m);
        }
        match self.authenticate_for_having_app(body, req, caller_id).await? {
            Some(m) => Ok(m),
            None => Err(AuthError::msg(StatusCode::FORBIDDEN, USER_CREDENTIALS_MISMATCHED, &[])),
        }
    }

    /// The main chain of `authenticate`: `None` where Java's chain completes empty.
    async fn authenticate_once(&self, body: &AuthRequest, req: &RequestInfo, caller_id: u64) -> AuthResult<Option<Minted>> {
        let app_code = req.app_code();
        let client_code = req.client_code();
        let Some(pass_type) = body.pass_type() else {
            return Err(AuthError::msg(StatusCode::BAD_REQUEST, UNKNOWN_ERROR, &[]).with_code("SEC.SIGN_IN_SECRET_MISSING"));
        };
        let Some(found) = self
            .find_user(body.user_name.as_deref(), body.user_id, client_code.as_deref(), app_code.as_deref(), body.identifier(), true)
            .await?
        else {
            return Ok(None);
        };
        // checkIfUserHasAnyProfile: asked, and not used to decide anything.
        if let Some(app) = app_code.as_deref().filter(|a| !a.trim().is_empty()) {
            self.dir.store.user_has_any_profile(found.user.id, app).await?;
        }
        if !check_user_and_client(&found, client_code.as_deref()) {
            return Ok(None);
        }
        self.check_user_status(&found.user).await?;
        let Some(policy) = self.dir.policy(found.user_client.id(), app_code.as_deref(), pass_type).await? else {
            return Ok(None);
        };
        self.check_password(&body.pass().unwrap_or_default(), app_code.as_deref(), &found.user, &policy, pass_type)
            .await?;
        self.reset_user_attempts(found.user.id, pass_type).await?;
        Ok(Some(self.log_and_make_token(body.into(), req, app_code.as_deref(), &found, caller_id).await?))
    }

    /// `authenticateUserForHavingApp`: the user named, signed in to the app they hold a profile in
    /// (the Owner one first). Java retries through this again when that inner sign-in also
    /// comes up empty, which never ends; here the second miss is the plain refusal.
    async fn authenticate_for_having_app(&self, body: &AuthRequest, req: &RequestInfo, caller_id: u64) -> AuthResult<Option<Minted>> {
        // The same answer whether the user is unknown or has no app here, so the text tells no
        // one which user names exist.
        let no_registration = || AuthError::msg(StatusCode::FORBIDDEN, NO_REGISTRATION_AVAILABLE, &[]).with_code("SEC.SIGN_IN_FAILED");
        let client_code = req.client_code();
        let found = self
            .find_user(body.user_name.as_deref(), body.user_id, client_code.as_deref(), None, body.identifier(), false)
            .await?
            .ok_or_else(no_registration)?;
        let app_id = self.dir.store.user_app_having_profile(found.user.id).await?.ok_or_else(no_registration)?;
        let app = self.dir.app_by_id(app_id).await?;
        let mut modified = req.clone();
        modified.headers.insert(
            "appCode",
            app.app_code.parse().map_err(|_| AuthError::internal("app code is not a header value"))?,
        );
        if blank(&body.social_register_state) {
            Ok(self.authenticate_once(body, &modified, caller_id).await?)
        } else {
            Ok(Some(self.authenticate_social(body, &modified, caller_id).await?))
        }
    }

    /// `checkPassword`: the password (or PIN) as stored, hashed with the user id in front, or
    /// the latest login OTP. A wrong one counts against the policy.
    pub async fn check_password(&self, pass: &str, app_code: Option<&str>, user: &User, policy: &Policy, t: PassType) -> AuthResult<()> {
        let valid = match t {
            PassType::Password => matches_secret(user.id, pass, user.password.as_deref(), user.password_hashed),
            PassType::Pin => matches_secret(user.id, pass, user.pin.as_deref(), user.pin_hashed),
            PassType::Otp => self.verify_otp(app_code, user.id, pass).await?,
        };
        if valid {
            return Ok(());
        }
        self.failed_attempt(user, policy, t).await
    }

    /// `checkFailedAttempts`: at the limit, lock the user for the policy's time; below it, count
    /// the attempt and say how many are left. The count compared is the one read at the start of
    /// this sign-in, so the lock lands on the attempt after the one that reached the limit.
    async fn failed_attempt(&self, user: &User, policy: &Policy, t: PassType) -> AuthResult<()> {
        let current = match t {
            PassType::Password => user.no_failed_attempt,
            PassType::Pin => user.no_pin_failed_attempt,
            PassType::Otp => user.no_otp_failed_attempt,
        }
        .unwrap_or(0);
        if policy.no_failed_attempts.is_some_and(|limit| current >= limit) {
            self.sox(user.id, SOX_LOGIN, "Failed password attempts are more than the configuration");
            let minutes = policy.user_lock_time.ok_or_else(|| AuthError::internal("userLockTime is null"))?;
            self.dir.store.lock_user(user.id, self.clock.local() + chrono::Duration::minutes(minutes), t.name()).await?;
            return Err(AuthError::msg(StatusCode::FORBIDDEN, USER_ACCOUNT_BLOCKED, &[]));
        }
        let increased = self.dir.store.increase_failed_attempt(user.id, t).await?;
        let limit = policy.no_failed_attempts.ok_or_else(|| AuthError::internal("noFailedAttempts is null"))?;
        let remaining = (limit - increased.unwrap_or(0)).max(0);
        self.sox(user.id, SOX_UPDATE, "Given Password is mismatching with existing.");
        Err(AuthError::msg(StatusCode::FORBIDDEN, USER_PASSWORD_INVALID_ATTEMPTS, &[t.name(), &remaining.to_string()]))
    }

    /// `resetUserAttempts`: an OTP sign-in also clears the resend count.
    async fn reset_user_attempts(&self, user_id: u64, t: PassType) -> AuthResult<()> {
        self.dir.store.reset_failed_attempt(user_id, t).await?;
        if t == PassType::Otp {
            self.dir.store.reset_resend_attempts(user_id).await?;
        }
        Ok(())
    }

    /// `logAndMakeToken`.
    pub async fn log_and_make_token(
        &self,
        opts: MintOptions,
        req: &RequestInfo,
        app_code: Option<&str>,
        found: &Found,
        caller_id: u64,
    ) -> AuthResult<Minted> {
        self.sox(found.user.id, SOX_LOGIN, "Successful");
        self.make_token(opts, req, app_code, found, caller_id).await
    }

    /// `makeToken`: the access token (and its row), the cookie, the optional SSO one-time token.
    async fn make_token(&self, opts: MintOptions, req: &RequestInfo, app_code: Option<&str>, found: &Found, caller_id: u64) -> AuthResult<Minted> {
        let client: &Client = &found.user_client;
        let mut minutes = if opts.remember_me { self.settings.remember_me_expiry_minutes } else { client.token_validity_minutes };
        if minutes <= 0 {
            minutes = self.settings.default_expiry_minutes;
        }
        let claims = Claims {
            user_id: found.user.id,
            host_name: Some(req.forwarded_host()),
            port: Some(req.forwarded_port()),
            logged_in_client_id: found.url_client.id(),
            logged_in_client_code: found.url_client.code.clone(),
            app_code: app_code.map(str::to_string),
            one_time: false,
        };
        let now = self.clock.instant();
        let made = jwt::make(&self.settings.jwt_key, &claims, now.timestamp(), minutes);
        let expires_at = now.naive_utc() + chrono::Duration::minutes(minutes);
        let cookie = opts.cookie.then(|| auth_cookie(&made.token, minutes * 60, now.timestamp_millis()));
        let origin = self.origin(req, req.real_ip());
        self.dir
            .store
            .insert_token(&NewToken {
                user_id: found.user.id,
                token: made.token.clone(),
                part_token: crate::context::part_token(&made.token).to_string(),
                expires_at,
                origin: origin.clone(),
                created_by: Some(caller_id),
            })
            .await?;
        let managed = self.dir.managed_client(client.id()).await?;
        let sso = if opts.sso_token {
            let token = random_uuid_hex();
            self.dir
                .store
                .insert_one_time_token(&NewOneTimeToken {
                    user_id: found.user.id,
                    token: token.clone(),
                    origin,
                    remember_me: Some(opts.remember_me),
                    ..Default::default()
                })
                .await?;
            Some(token)
        } else {
            None
        };
        Ok(Minted {
            response: AuthResponse {
                user: found.user.to_context_user(Some(found.authorities.clone())),
                client: client.clone(),
                verified_app_code: app_code.map(str::to_string),
                logged_in_client_code: found.url_client.code.clone(),
                logged_in_client_id: found.url_client.id,
                managed_client_id: managed.id,
                managed_client_code: managed.code.clone(),
                access_token: Some(made.token),
                access_token_expiry_at: Some(expires_at.and_utc().timestamp()),
                sso_token: sso,
            },
            cookie,
        })
    }

    /// Where the request came from, for token rows: the address given and the user agent.
    pub fn origin(&self, req: &RequestInfo, ip: Option<String>) -> Origin {
        let ua = req.user_agent();
        Origin { ip_address: ip, user_agent: ua.raw, device_type: ua.device_type, os: ua.os, browser: ua.browser }
    }

    /// `POST authenticate/social`.
    pub async fn authenticate_social(&self, body: &AuthRequest, req: &RequestInfo, caller_id: u64) -> AuthResult<Minted> {
        if blank(&body.social_register_state) {
            return Err(AuthError::msg(StatusCode::BAD_REQUEST, SOCIAL_LOGIN_FAILED, &[]));
        }
        let state = body.social_register_state.clone().unwrap_or_default();
        let app_code = req.app_code();
        let client_code = req.client_code();
        if let Some(found) = self.resolve_social_user(body, client_code.as_deref(), app_code.as_deref()).await? {
            if let Some(app) = app_code.as_deref().filter(|a| !a.trim().is_empty()) {
                self.dir.store.user_has_any_profile(found.user.id, app).await?;
            }
            if check_user_and_client(&found, client_code.as_deref()) {
                self.check_user_status(&found.user).await?;
                let token = self
                    .dir
                    .store
                    .state_by_value(&state)
                    .await?
                    .ok_or_else(|| AuthError::internal("Invalid state"))?;
                let verified = token.username.clone().filter(|u| !u.trim().is_empty());
                if verified.as_deref() != body.user_name.as_deref() || verified.is_none() {
                    return Err(AuthError::msg(StatusCode::FORBIDDEN, SOCIAL_LOGIN_FAILED, &[]));
                }
                if is_state_expired(&token, self.clock.utc()) {
                    return Err(AuthError::msg(StatusCode::FORBIDDEN, SESSION_EXPIRED, &[]));
                }
                let minted = self.log_and_make_token(body.into(), req, app_code.as_deref(), &found, caller_id).await?;
                self.dir.store.consume_state(&token.state).await?;
                return Ok(minted);
            }
        }
        Err(self.social_refusal(body, client_code.as_deref()).await?)
    }

    /// `resolveSocialUser`: the one user for this identity, or the owner among several.
    async fn resolve_social_user(&self, body: &AuthRequest, client_code: Option<&str>, app_code: Option<&str>) -> AuthResult<Option<Found>> {
        let candidates = self.identity_users(body, client_code, app_code).await?;
        let picked = match candidates.len() {
            0 => return Ok(None),
            1 => candidates[0].id,
            _ => match self.pick_owner(candidates, app_code).await? {
                Some(id) => id,
                None => return Ok(None),
            },
        };
        self.find_user(body.user_name.as_deref(), Some(picked), client_code, app_code, body.identifier(), false).await
    }

    /// `UserService.getUsersForIdentity`: up to 25 non-deleted users with this identity.
    async fn identity_users(&self, body: &AuthRequest, client_code: Option<&str>, app_code: Option<&str>) -> AuthResult<Vec<User>> {
        self.dir
            .store
            .users_by(&UserQuery {
                user_name: body.user_name.clone(),
                identifier: body.identifier(),
                user_id: None,
                client_code: client_code.map(str::to_string),
                app_code: app_code.map(str::to_string),
                active_client_only: false,
                limit: 25,
            })
            .await
    }

    /// `pickOwnerAmong`: owners by id; the first with a profile assigned in the app, else the
    /// first.
    async fn pick_owner(&self, mut candidates: Vec<User>, app_code: Option<&str>) -> AuthResult<Option<u64>> {
        candidates.sort_by_key(|u| u.id);
        let ids: Vec<u64> = candidates.iter().map(|u| u.id).collect();
        let owner_ids = self.dir.store.owner_user_ids(&ids).await?;
        let owners: Vec<u64> = ids.into_iter().filter(|i| owner_ids.contains(i)).collect();
        if owners.is_empty() {
            return Ok(None);
        }
        let app = match app_code.filter(|a| !a.trim().is_empty()) {
            Some(a) => self.dir.app_by_code(a).await?,
            None => None,
        };
        if let Some(app) = app {
            for o in &owners {
                if self.dir.store.has_assigned_profile(*o, app.id).await? {
                    return Ok(Some(*o));
                }
            }
        }
        Ok(owners.first().copied())
    }

    /// `socialSignInRefusal`: 409 when the verified identity already owns a client here (ask for
    /// access instead of registering again), else the plain 403 that means "register".
    async fn social_refusal(&self, body: &AuthRequest, client_code: Option<&str>) -> AuthResult<AuthError> {
        let unknown = || AuthError::msg(StatusCode::FORBIDDEN, USER_CREDENTIALS_MISMATCHED, &[]);
        let state = body.social_register_state.clone().unwrap_or_default();
        let Ok(Some(token)) = self.dir.store.state_by_value(&state).await else { return Ok(unknown()) };
        let verified = token.username.clone().filter(|u| !u.trim().is_empty());
        if verified.is_none() || verified.as_deref() != body.user_name.as_deref() || is_state_expired(&token, self.clock.utc()) {
            return Ok(unknown());
        }
        let existing = self.identity_users(body, client_code, None).await?;
        if existing.is_empty() {
            return Ok(unknown());
        }
        let ids: Vec<u64> = existing.iter().map(|u| u.id).collect();
        if self.dir.store.owner_user_ids(&ids).await?.is_empty() {
            return Ok(unknown());
        }
        Ok(AuthError::msg(StatusCode::CONFLICT, ACCESS_REQUEST_REQUIRED, &[]))
    }

    /// `POST authenticate/otp/generate`.
    pub async fn generate_otp(&self, body: &AuthRequest, req: &RequestInfo) -> AuthResult<bool> {
        if !body.generate_otp {
            return Ok(false);
        }
        let app_code = req.app_code();
        let client_code = req.client_code();
        let Some(found) = self
            .find_user(body.user_name.as_deref(), body.user_id, client_code.as_deref(), app_code.as_deref(), body.identifier(), true)
            .await?
        else {
            return Ok(false);
        };
        if !check_user_and_client(&found, client_code.as_deref()) {
            return Ok(false);
        }
        let Some(app) = (match app_code.as_deref() {
            Some(a) => self.dir.app_by_code(a).await?,
            None => None,
        }) else {
            return Ok(false);
        };
        let request = OtpRequest {
            client_id: found.url_client.id(),
            client_code: found.url_client.code.clone(),
            app_id: app.id,
            app_code: app.app_code.clone(),
            app_name: app.app_name.clone(),
            user_id: Some(found.user.id),
            email_id: found.user.email_id().filter(|e| !e.trim().is_empty()),
            phone_number: found.user.phone_number().filter(|p| !p.trim().is_empty()),
            ip_address: req.remote_host(),
            resend: body.resend,
            x_debug: req.header("x-debug"),
            purpose: Some(crate::otp::OtpPurpose::Login),
            with_user: true,
        };
        self.generate_otp_internal(&request).await
    }
}

/// The stored password or PIN check: BCrypt over `userId + secret` when hashed, else equality.
pub fn matches_secret(user_id: u64, given: &str, stored: Option<&str>, hashed: bool) -> bool {
    match (stored, hashed) {
        (Some(hash), true) => bcrypt::verify(format!("{user_id}{given}"), hash).unwrap_or(false),
        (None, true) => false,
        (stored, false) => stored == Some(given),
    }
}
