//! The caller's `ContextAuthentication`: what `JWTTokenFilter` asks
//! `AuthenticationService.getAuthentication` for on every request, and what
//! `internal/securityContextAuthentication` hands back to every other service.
//!
//! - No credentials: anonymous, on the client named by the `clientCode` header or by the host.
//! - A bearer token: verified (signature, expiry, issuing host), then the cached context or one
//!   built from the token row; a one-time token's row is deleted on use.
//! - Basic `user:password` (or `<userId>:password`): a full sign-in check on every call.
//!
//! An unusable credential is not an error: the caller continues anonymous. A signed-in caller's
//! status is checked and authorities recomputed on every request (a blocked user is refused
//! even with a cached token).

use std::sync::Arc;

use axum::http::StatusCode;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{Months, Timelike};
use regex::Regex;

use crate::caches;
use crate::errors::{
    AuthError, AuthResult, TOKEN_EXPIRED, UNKNOWN_CLIENT, UNKNOWN_TOKEN, USER_ACCOUNT_BLOCKED, USER_ACCOUNT_BLOCKED_LIMIT,
    USER_ACCOUNT_PASS_EXPIRED,
};
use crate::jwt::{self, Claims};
use crate::model::{Client, ContextAuth, PassType, TokenRow, User, CLIENT_TYPE_SYSTEM};
use crate::request::RequestInfo;
use crate::service::Auth;
use crate::store::{IdentifierType, UserQuery};
use crate::timezone;

/// The user, the client named in the request (`T1`) and the user's own client (`T2`), as
/// `findUserNClient` returns them, with the user's authorities for the app asked for.
#[derive(Debug, Clone)]
pub struct Found {
    pub url_client: Arc<Client>,
    pub user_client: Arc<Client>,
    pub user: Arc<User>,
    pub authorities: Vec<String>,
}

/// `toPartToken`: the indexed tail of a token.
pub fn part_token(token: &str) -> &str {
    if token.len() > 50 {
        &token[token.len() - 50..]
    } else {
        token
    }
}

impl Auth {
    /// The context `JWTTokenFilter` puts on the request (url codes included).
    pub async fn context(&self, req: &RequestInfo) -> AuthResult<ContextAuth> {
        let (basic, token) = req.basic_or_bearer();
        let app_code = req.app_code();
        let mut ca = if token.trim().is_empty() {
            self.anonymous(req).await?
        } else {
            match self.credential_context(basic, &token, app_code.as_deref(), req).await {
                Ok(ca) => ca,
                Err(e) => {
                    if e.is_client_error() {
                        tracing::debug!(error = %e, "credentials not usable, continuing anonymous");
                    } else {
                        tracing::error!(error = %e, "credentials could not be evaluated, continuing anonymous");
                    }
                    self.anonymous(req).await?
                }
            }
        };
        if ca.authenticated {
            if let Some(user) = self.dir.user(ca.user.id()).await? {
                self.check_user_status(&user).await?;
            }
            let app = ca.verified_app_code.clone().or_else(|| app_code.clone());
            let auths = self.dir.user_authorities(app.as_deref(), ca.user.client_id(), ca.user.id()).await?;
            ca.user.string_authorities = Some(auths);
        }
        ca.url_app_code = app_code;
        ca.url_client_code = req.client_code();
        Ok(ca)
    }

    /// `makeAnonymousSpringAuthentication`.
    pub async fn anonymous(&self, req: &RequestInfo) -> AuthResult<ContextAuth> {
        let client = match req.client_code() {
            Some(code) => self.dir.client_by_code(&code).await?,
            None => {
                let (scheme, host, port) = req.client_resolution_parts();
                self.dir.client_for_host(&scheme, &host, &port).await?
            }
        };
        let client = client.ok_or_else(|| AuthError::msg(StatusCode::UNAUTHORIZED, UNKNOWN_CLIENT, &[]))?;
        Ok(ContextAuth::anonymous(&client, self.clock.local().and_utc().timestamp()))
    }

    async fn credential_context(&self, basic: bool, token: &str, app_code: Option<&str>, req: &RequestInfo) -> AuthResult<ContextAuth> {
        if basic {
            return self.basic_context(token, app_code, req).await;
        }
        let claims = self.extract_claims(token)?;
        check_token_origin(req, &claims)?;
        if let Some(cached) = self.dir.caches.tokens.get(caches::TOKEN, &token.to_string()).await {
            return Ok((*cached).clone());
        }
        self.bearer_context(token, &claims, app_code, req).await
    }

    /// `extractClaims`: anything unparseable is `token_expired`, as Java reports it.
    pub fn extract_claims(&self, token: &str) -> AuthResult<Claims> {
        jwt::parse(&self.settings.jwt_key, token, self.clock.millis())
            .map_err(|e| AuthError::msg(StatusCode::UNAUTHORIZED, TOKEN_EXPIRED, &[]).with_debug(e.to_string()))
    }

    /// The token row holding exactly this token (`PART_TOKEN` is case-insensitive in MySQL).
    pub async fn token_row(&self, token: &str) -> AuthResult<Option<TokenRow>> {
        Ok(self.dir.store.tokens_by_part(part_token(token)).await?.into_iter().find(|t| t.token == token))
    }

    /// `getAuthenticationIfNotInCache` for a bearer token.
    async fn bearer_context(&self, token: &str, claims: &Claims, app_code: Option<&str>, req: &RequestInfo) -> AuthResult<ContextAuth> {
        // `.take(1).single()`: no row is "Source was empty" in Java, an error, and the request goes
        // on anonymous. A signed token without its row was signed out, revoked or cleaned up: the
        // caller's state, not the server's, so it is reported as such (logged at debug, not error).
        let row = self.token_row(token).await?.ok_or_else(|| {
            AuthError::msg(StatusCode::UNAUTHORIZED, UNKNOWN_TOKEN, &[]).with_debug("Source was empty: the token has no row (signed out, revoked or cleaned up)")
        })?;
        let store = self.dir.store.clone();
        let (ca, touched) = tokio::join!(
            self.spring_authentication(app_code, req, claims, &row),
            store.update_last_used(row.id, self.clock.local())
        );
        let ca = ca?.ok_or_else(|| AuthError::msg(StatusCode::UNAUTHORIZED, UNKNOWN_TOKEN, &[]))?;
        touched?;
        if claims.one_time {
            self.dir.store.delete_token(row.id).await?;
        } else {
            self.dir.caches.tokens.insert(caches::TOKEN, token.to_string(), Arc::new(ca.clone())).await;
        }
        Ok(ca)
    }

    /// `makeSpringAuthentication`: `None` where Java's chain completes empty.
    async fn spring_authentication(
        &self,
        app_code: Option<&str>,
        req: &RequestInfo,
        claims: &Claims,
        row: &TokenRow,
    ) -> AuthResult<Option<ContextAuth>> {
        check_token_origin(req, claims)?;
        let Some(user) = self.dir.user(row.user_id).await? else { return Ok(None) };
        self.check_user_status(&user).await?;
        let Some(typ) = self.dir.type_code_level(user.client_id).await? else { return Ok(None) };
        let client = self.dir.client(user.client_id).await?;
        let mut cu = user.to_context_user(None);
        cu.time_zone = timezone::effective(user.time_zone.as_deref(), client.as_ref().and_then(|c| c.time_zone.as_deref()));
        Ok(Some(ContextAuth {
            user: cu,
            authenticated: true,
            logged_in_from_client_id: Some(claims.logged_in_client_id),
            logged_in_from_client_code: claims.logged_in_client_code.clone(),
            client_type_code: Some(typ.0.clone()),
            client_level_type: Some(typ.2.clone()),
            client_code: Some(typ.1.clone()),
            access_token: Some(row.token.clone()),
            access_token_expiry_at: Some(row.expires_at.and_utc().timestamp()),
            access_token_expiry: Some(row.expires_at),
            url_client_code: None,
            url_app_code: None,
            verified_app_code: claims.app_code.clone().or_else(|| app_code.map(str::to_string)),
        }))
    }

    /// `getAuthenticationIfNotInCache` for Basic credentials: a sign-in on every request.
    async fn basic_context(&self, token: &str, app_code: Option<&str>, req: &RequestInfo) -> AuthResult<ContextAuth> {
        let fin_token = format!("Basic {token}");
        let bytes = STANDARD.decode(token).map_err(|e| AuthError::internal(format!("Illegal base64 character: {e}")))?;
        let decoded = String::from_utf8_lossy(&bytes).into_owned();
        let colon = decoded.find(':').ok_or_else(|| AuthError::internal("begin 0, end -1"))?;
        let (username, password) = (&decoded[..colon], &decoded[colon + 1..]);
        let req_app = req.app_code();
        let client_code = req.client_code();
        let identifier = if username.contains('@') { IdentifierType::EmailId } else { IdentifierType::UserName };

        let by_name = || self.find_user(Some(username), None, client_code.as_deref(), req_app.as_deref(), identifier, false);
        let found = match basic_user_id(username) {
            Some(id) => match self.find_user(None, Some(id), client_code.as_deref(), req_app.as_deref(), identifier, false).await? {
                Some(f) => Some(f),
                None => by_name().await?,
            },
            None => by_name().await?,
        };
        let unknown = || AuthError::msg(StatusCode::UNAUTHORIZED, UNKNOWN_TOKEN, &[]);
        let found = found.ok_or_else(unknown)?;
        if !check_user_and_client(&found, client_code.as_deref()) {
            return Err(unknown());
        }
        self.check_user_status(&found.user).await?;
        let policy = self
            .dir
            .policy(found.user_client.id(), req_app.as_deref(), PassType::Password)
            .await?
            .ok_or_else(unknown)?;
        self.check_password(password, None, &found.user, &policy, PassType::Password).await?;
        let expiry = self.clock.local().checked_add_months(Months::new(12)).unwrap_or(self.clock.local());
        Ok(ContextAuth {
            user: found.user.to_context_user(Some(found.authorities.clone())),
            authenticated: true,
            logged_in_from_client_id: found.url_client.id,
            logged_in_from_client_code: found.url_client.code.clone(),
            client_type_code: found.user_client.type_code.clone(),
            client_level_type: found.user_client.level_type.clone(),
            client_code: found.user_client.code.clone(),
            access_token: Some(fin_token),
            access_token_expiry_at: Some(expiry.and_utc().timestamp()),
            access_token_expiry: Some(expiry),
            url_client_code: client_code,
            url_app_code: req_app,
            verified_app_code: app_code.map(str::to_string),
        })
    }

    /// `UserService.findUserNClient`: exactly one non-deleted user for this identity under the
    /// client, with their authorities for the app, their (active) client and the request's.
    pub async fn find_user(
        &self,
        user_name: Option<&str>,
        user_id: Option<u64>,
        client_code: Option<&str>,
        app_code: Option<&str>,
        identifier: IdentifierType,
        active_client_only: bool,
    ) -> AuthResult<Option<Found>> {
        let q = UserQuery {
            user_name: user_name.map(str::to_string),
            identifier,
            user_id,
            client_code: client_code.map(str::to_string),
            app_code: app_code.map(str::to_string),
            active_client_only,
            limit: 2,
        };
        let mut users = self.dir.store.users_by(&q).await?;
        if users.len() != 1 {
            return Ok(None);
        }
        let user = Arc::new(users.remove(0));
        let authorities = self.dir.user_authorities(app_code, user.client_id, user.id).await?;
        let user_client = self.dir.active_client(user.client_id).await?;
        let url_client = if Some(user_client.code()) == client_code {
            Some(user_client.clone())
        } else {
            match client_code {
                Some(c) => self.dir.client_by_code(c).await?,
                None => None,
            }
        };
        Ok(url_client.map(|url_client| Found { url_client, user_client, user, authorities }))
    }

    /// `AuthenticationService.checkUserStatus`.
    pub async fn check_user_status(&self, user: &User) -> AuthResult<()> {
        match user.status_code.as_str() {
            "ACTIVE" => Ok(()),
            "LOCKED" => self.check_user_lock_status(user).await,
            "PASSWORD_EXPIRED" => {
                let due = user.locked_due_to.clone().unwrap_or_else(|| "null".into());
                Err(AuthError::msg(StatusCode::FORBIDDEN, USER_ACCOUNT_PASS_EXPIRED, &[&due]))
            }
            _ => Err(AuthError::msg(StatusCode::FORBIDDEN, USER_ACCOUNT_BLOCKED, &[])),
        }
    }

    /// `checkUserLockStatus`: a lock that has run out is lifted (and the attempts reset);
    /// otherwise the minutes left, computed Java's way from the minute fields alone.
    async fn check_user_lock_status(&self, user: &User) -> AuthResult<()> {
        let until = user.locked_until.ok_or_else(|| AuthError::internal("lockedUntil is null"))?;
        let now = self.clock.local();
        if until < now {
            return if self.dir.store.unlock_user(user.id).await? {
                Ok(())
            } else {
                Err(AuthError::msg(StatusCode::FORBIDDEN, USER_ACCOUNT_BLOCKED, &[]))
            };
        }
        let minutes = lock_minutes_left(until.minute(), now.minute());
        let due = user.locked_due_to.clone().unwrap_or_else(|| "null".into());
        Err(AuthError::msg(StatusCode::FORBIDDEN, USER_ACCOUNT_BLOCKED_LIMIT, &[&due, &minutes.to_string()]))
    }
}

/// `lockedUntil.minusMinutes(now.getMinute()).getMinute()`.
pub fn lock_minutes_left(until_minute: u32, now_minute: u32) -> u32 {
    (until_minute + 60 - now_minute) % 60
}

/// `"<userId>:password"`: an all-digit user name of up to 19 digits is tried as a user id first.
pub fn basic_user_id(user_name: &str) -> Option<u64> {
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"^[0-9]{1,19}$").expect("static regex"));
    re.is_match(user_name).then(|| user_name.parse().ok()).flatten()
}

/// `UserService.checkUserAndClient`.
pub fn check_user_and_client(f: &Found, client_code: Option<&str>) -> bool {
    let Some(code) = client_code else { return false };
    f.url_client.type_code.as_deref() == Some(CLIENT_TYPE_SYSTEM) || f.url_client.code() == code || f.url_client.id == f.user_client.id
}

/// `checkTokenOrigin`: the request's host must contain the host the token was issued to.
pub fn check_token_origin(req: &RequestInfo, claims: &Claims) -> AuthResult<()> {
    let host = req.forwarded_host();
    match &claims.host_name {
        Some(h) if host.contains(h.as_str()) => Ok(()),
        Some(_) => Err(AuthError::msg(StatusCode::UNAUTHORIZED, UNKNOWN_TOKEN, &[])),
        None => Err(AuthError::internal("hostName claim is null")),
    }
}
