//! The token endpoints: revoke, refresh, verify, one-time tokens (mint and redeem), app access
//! and the cleanup job.

use axum::http::{header, StatusCode};
use serde::Deserialize;
use serde_json::Value;

use crate::caches;
use crate::context::{check_user_and_client, part_token};
use crate::errors::{AuthError, AuthResult, FORBIDDEN_PERMISSION, UNKNOWN_TOKEN, UNSUPPORTED_AUTH_MODE, USER_CREDENTIALS_MISMATCHED};
use crate::jackson::{opt, Obj};
use crate::jwt::{self, Claims};
use crate::model::{AuthResponse, ContextAuth};
use crate::request::RequestInfo;
use crate::service::Auth;
use crate::signin::{auth_cookie, random_uuid_hex, MintOptions, Minted};
use crate::store::{IdentifierType, NewOneTimeToken, NewToken};

const SSO_TARGET_APP: &str = "SSO target app";
const AUTHZUMP: &str = "authzump";

/// `MakeOneTimeTimeTokenRequest`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct OneTimeTokenRequest {
    pub callback_url: Option<String>,
    #[serde(deserialize_with = "crate::handlers::de_bool")]
    pub remember_me: bool,
    pub target_app_code: Option<String>,
    pub target_client_code: Option<String>,
    pub auth_mode: Option<String>,
}

/// `UserAppAccessRequest`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AppAccessRequest {
    pub app_code: Option<String>,
    pub callback_url: Option<String>,
}

fn blank(s: Option<&str>) -> bool {
    s.map(|v| v.trim().is_empty()).unwrap_or(true)
}

impl Auth {
    /// `revoke(ssoLogout, request)`: forget this token everywhere (or, for an SSO logout, every
    /// token of the user) and delete its rows.
    pub async fn revoke(&self, sso_logout: bool, req: &RequestInfo, ca: &ContextAuth) -> AuthResult<()> {
        let mut bearer = req.header(header::AUTHORIZATION.as_str());
        if bearer.as_deref().map(|b| b.trim().is_empty()).unwrap_or(true) {
            if let Some(c) = req.auth_cookie() {
                bearer = Some(c);
            }
        }
        let Some(bearer) = bearer else { return Ok(()) };
        let mut token = bearer.trim().to_string();
        let lower = token.to_lowercase();
        if lower.starts_with("bearer ") {
            token = token[7..].trim().to_string();
        } else if lower.starts_with("basic ") {
            token = token[6..].trim().to_string();
        }
        if sso_logout {
            return self.revoke_all(ca.user.id()).await;
        }
        self.dir.caches.service.evict_everywhere(caches::TOKEN, &token).await;
        for row in self.dir.store.tokens_by_part(part_token(&token)).await? {
            if row.token == token {
                self.dir.store.delete_token(row.id).await?;
            }
        }
        Ok(())
    }

    /// `TokenService.deleteTokens`: every token of the user evicted, then deleted.
    async fn revoke_all(&self, user_id: u64) -> AuthResult<()> {
        for t in self.dir.store.token_strings_of_user(user_id).await? {
            self.dir.caches.service.evict_everywhere(caches::TOKEN, &t).await;
        }
        self.dir.store.delete_tokens_of_user(user_id).await?;
        Ok(())
    }

    /// `verifyToken`: the signed-in caller's response; for anyone else the token is revoked and
    /// the answer is 403 without a token, 401 with one.
    pub async fn verify_token(&self, req: &RequestInfo, ca: &ContextAuth) -> AuthResult<Option<AuthResponse>> {
        if !ca.authenticated {
            let (_, token) = req.basic_or_bearer();
            self.revoke(false, req, ca).await?;
            return Err(if token.trim().is_empty() {
                AuthError::literal(StatusCode::FORBIDDEN, "SEC.TOKEN_FORBIDDEN", "Forbidden")
            } else {
                AuthError::literal(StatusCode::UNAUTHORIZED, "SEC.TOKEN_UNAUTHORIZED", "Unauthorized")
            });
        }
        let Some(client) = self.dir.client(ca.user.client_id()).await? else { return Ok(None) };
        let managed = self.dir.managed_client(client.id()).await?;
        Ok(Some(AuthResponse {
            user: ca.user.clone(),
            client: (*client).clone(),
            verified_app_code: ca.verified_app_code.clone(),
            logged_in_client_code: ca.logged_in_from_client_code.clone(),
            logged_in_client_id: ca.logged_in_from_client_id,
            managed_client_id: managed.id,
            managed_client_code: managed.code.clone(),
            access_token: ca.access_token.clone(),
            access_token_expiry_at: ca.access_token_expiry_at,
            sso_token: None,
        }))
    }

    /// `refreshToken`: within `jwt.token.default.refresh` minutes of expiry the token is revoked
    /// and a new one minted (without an app code claim, as Java mints it); otherwise the current
    /// one is returned. `None` where Java answers an empty 200 (the client is gone).
    pub async fn refresh_token(&self, req: &RequestInfo, ca: &ContextAuth) -> AuthResult<Option<Minted>> {
        if !ca.authenticated {
            return Err(AuthError::literal(StatusCode::UNAUTHORIZED, "SEC.TOKEN_UNAUTHORIZED", "Unauthorized"));
        }
        let Some(client) = self.dir.client(ca.user.client_id()).await? else { return Ok(None) };
        let renew_by = self.clock.utc() + chrono::Duration::minutes(self.settings.refresh_minutes);
        let expiry = ca.access_token_expiry.ok_or_else(|| AuthError::internal("accessTokenExpiryAt is null"))?;
        let managed;
        let response = if renew_by > expiry {
            self.revoke(false, req, ca).await?;
            let token = ca.access_token.clone().unwrap_or_default();
            let old = jwt::parse(&self.settings.jwt_key, &token, self.clock.millis()).map_err(AuthError::internal)?;
            let minutes = if client.token_validity_minutes <= 0 { self.settings.default_expiry_minutes } else { client.token_validity_minutes };
            let claims = Claims {
                user_id: ca.user.id(),
                host_name: old.host_name.clone(),
                port: old.port.clone(),
                logged_in_client_id: old.logged_in_client_id,
                logged_in_client_code: old.logged_in_client_code.clone(),
                app_code: None,
                one_time: false,
            };
            let now = self.clock.instant();
            let made = jwt::make(&self.settings.jwt_key, &claims, now.timestamp(), minutes);
            let expires_at = now.naive_utc() + chrono::Duration::minutes(minutes);
            self.dir
                .store
                .insert_token(&NewToken {
                    user_id: ca.user.id(),
                    token: made.token.clone(),
                    part_token: part_token(&made.token).to_string(),
                    expires_at,
                    origin: self.origin(req, req.remote_host()),
                    created_by: Some(ca.user.id()),
                })
                .await?;
            managed = self.dir.managed_client(client.id()).await?;
            AuthResponse {
                access_token: Some(made.token),
                access_token_expiry_at: Some(expires_at.and_utc().timestamp()),
                ..self.current(ca, &client, &managed)
            }
        } else {
            managed = self.dir.managed_client(client.id()).await?;
            self.current(ca, &client, &managed)
        };
        // Java re-sets the cookie only when the one sent is blank: a no-op kept as it is.
        let cookie = match req.auth_cookie() {
            Some(c) if c.trim().is_empty() => response.access_token_expiry_at.and_then(|exp| {
                let max_age = (exp * 1000 - self.clock.millis()) / 1000;
                (max_age >= 0).then(|| auth_cookie(&c, max_age, self.clock.millis()))
            }),
            _ => None,
        };
        Ok(Some(Minted { response, cookie }))
    }

    fn current(&self, ca: &ContextAuth, client: &crate::model::Client, managed: &crate::model::Client) -> AuthResponse {
        AuthResponse {
            user: ca.user.clone(),
            client: client.clone(),
            verified_app_code: None,
            logged_in_client_code: ca.logged_in_from_client_code.clone(),
            logged_in_client_id: ca.logged_in_from_client_id,
            managed_client_id: managed.id,
            managed_client_code: managed.code.clone(),
            access_token: ca.access_token.clone(),
            access_token_expiry_at: ca.access_token_expiry_at,
            sso_token: None,
        }
    }

    /// `isRememberMeToken`: a valid token whose whole lifetime is the remember-me expiry (one
    /// minute of slack for the rounding of `iat` and `exp`).
    pub fn is_remember_me_token(&self, token: Option<&str>) -> bool {
        let Some(token) = token.filter(|t| !t.trim().is_empty()) else { return false };
        if self.settings.remember_me_expiry_minutes <= 0 {
            return false;
        }
        match jwt::lifetime_seconds(&self.settings.jwt_key, token, self.clock.millis()) {
            Some(l) => l >= self.settings.remember_me_expiry_minutes * 60 - 60,
            None => false,
        }
    }

    /// `makeOneTimeToken` (public, `allow_remember_me` false) and `makeOneTimeTokenInternal`.
    pub async fn make_one_time_token(
        &self,
        body: &OneTimeTokenRequest,
        req: &RequestInfo,
        ca: &ContextAuth,
        allow_remember_me: bool,
    ) -> AuthResult<Value> {
        let auth_mode = match body.auth_mode.as_deref().filter(|m| !m.trim().is_empty()) {
            None => if req.auth_cookie().is_some() { "COOKIE" } else { "BEARER" }.to_string(),
            Some(m) => {
                let m = m.trim().to_uppercase();
                if m != "COOKIE" && m != "BEARER" {
                    return Err(AuthError::msg(StatusCode::BAD_REQUEST, UNSUPPORTED_AUTH_MODE, &[]));
                }
                m
            }
        };
        if !ca.authenticated {
            return Err(AuthError::msg(StatusCode::UNAUTHORIZED, UNKNOWN_TOKEN, &[]));
        }
        let target = body.target_app_code.clone();
        let source = ca.verified_app_code.clone();
        let trusted = blank(target.as_deref())
            || target == source
            || target.as_deref() == Some(AUTHZUMP)
            || source.as_deref() == Some(AUTHZUMP);
        if !trusted {
            let forbidden = || AuthError::msg(StatusCode::FORBIDDEN, FORBIDDEN_PERMISSION, &[SSO_TARGET_APP]).with_code("SEC.SSO_TARGET_APP_FORBIDDEN");
            let Some(source) = source.clone().filter(|s| !s.trim().is_empty()) else { return Err(forbidden()) };
            if !self.has_dependency_either_direction(&source, target.as_deref().unwrap_or("")).await? {
                return Err(forbidden());
            }
        }
        let token = random_uuid_hex();
        self.dir
            .store
            .insert_one_time_token(&NewOneTimeToken {
                user_id: ca.user.id(),
                token: token.clone(),
                origin: self.origin(req, req.real_ip()),
                remember_me: Some(body.remember_me && (allow_remember_me || self.is_remember_me_token(ca.access_token.as_deref()))),
                auth_mode: Some(auth_mode),
                origin_app_code: ca.verified_app_code.clone(),
                target_app_code: target,
            })
            .await?;
        let url = self.fill_values(body.callback_url.as_deref(), &token);
        Ok(Obj::new().put("token", token).put("url", url).build())
    }

    /// `AppService.hasDependencyEitherDirection`: read straight from the tables, no cache.
    async fn has_dependency_either_direction(&self, a: &str, b: &str) -> AuthResult<bool> {
        if a.trim().is_empty() || b.trim().is_empty() {
            return Ok(false);
        }
        if a == b {
            return Ok(true);
        }
        let (Some(app_a), Some(app_b)) = (self.dir.store.app_by_code(a).await?, self.dir.store.app_by_code(b).await?) else {
            return Ok(false);
        };
        self.dir.store.has_dependency_either_direction(app_a.id, app_b.id).await
    }

    /// `authenticateWithOneTimeToken/{token}`: a fresh, unused one-time token becomes a session
    /// in the app it was minted for. The answer is the session as a context (whose
    /// `authenticated` is false: `makeContextAuthentication` never sets it).
    pub async fn redeem_one_time_token(&self, token: &str, req: &RequestInfo, caller_id: u64) -> AuthResult<Minted> {
        let mismatch = || AuthError::msg(StatusCode::FORBIDDEN, USER_CREDENTIALS_MISMATCHED, &[]);
        let request_app = req.app_code();
        let client_code = req.client_code();
        let Some(ott) = self.dir.store.redeem_one_time_token(token, self.settings.one_time_token_max_age_minutes).await? else {
            return Err(mismatch());
        };
        if !blank(ott.target_app_code.as_deref()) && !blank(request_app.as_deref()) && ott.target_app_code != request_app {
            return Err(AuthError::msg(StatusCode::FORBIDDEN, FORBIDDEN_PERMISSION, &[SSO_TARGET_APP]).with_code("SEC.SSO_TARGET_APP_FORBIDDEN"));
        }
        let effective = if !blank(ott.target_app_code.as_deref()) {
            ott.target_app_code.clone()
        } else if !blank(ott.origin_app_code.as_deref()) {
            ott.origin_app_code.clone()
        } else {
            request_app.clone()
        };
        let Some(found) = self
            .find_user(None, Some(ott.user_id), client_code.as_deref(), effective.as_deref(), IdentifierType::UserName, false)
            .await?
        else {
            return Err(mismatch());
        };
        if let Some(app) = effective.as_deref().filter(|a| !a.trim().is_empty()) {
            self.dir.store.user_has_any_profile(found.user.id, app).await?;
        }
        if !check_user_and_client(&found, client_code.as_deref()) {
            return Err(mismatch());
        }
        self.check_user_status(&found.user).await?;
        let opts = MintOptions { remember_me: ott.remember_me, cookie: ott.auth_mode.as_deref() == Some("COOKIE"), sso_token: false };
        self.log_and_make_token(opts, req, effective.as_deref(), &found, caller_id).await
    }

    /// `user/access`: whether the caller can reach the app (a profile there), is an owner, and
    /// whether their client can read it; with a one-time token into it when they can.
    pub async fn user_app_access(&self, body: &AppAccessRequest, req: &RequestInfo, ca: &ContextAuth) -> AuthResult<Value> {
        // getAppByCode(null) fails on the null cache key in Java.
        let app_code = body.app_code.clone().ok_or_else(|| AuthError::internal("appCode is null"))?;
        self.dir.app_by_code(&app_code).await?;
        let user_id = ca.user.id();
        let app_access = if app_code.trim().is_empty() { false } else { self.dir.store.user_has_any_profile(user_id, &app_code).await? };
        let owner = if app_access { None } else { Some(self.dir.store.is_user_owner(user_id).await?) };
        let token = if app_access {
            let t = random_uuid_hex();
            self.dir
                .store
                .insert_one_time_token(&NewOneTimeToken {
                    user_id,
                    token: t.clone(),
                    origin: self.origin(req, req.real_ip()),
                    ..Default::default()
                })
                .await?;
            Some(t)
        } else {
            None
        };
        let client_access = if !app_access && owner == Some(true) {
            Some(self.dir.has_read_access(&app_code, ca.client_code.as_deref()).await?)
        } else {
            None
        };
        let url = token.as_deref().map(|t| self.fill_values(body.callback_url.as_deref(), t));
        Ok(Obj::new()
            .put("app", app_access)
            .put("owner", owner.unwrap_or(false))
            .put("clientAccess", client_access.unwrap_or(false))
            .put("appOneTimeToken", opt(token))
            .put("appURL", opt(url))
            .build())
    }

    /// `internal/tokens/cleanup`: expired tokens, tokens unused for `unused_days`, expired draft
    /// tokens. Expiry is compared in UTC, the clock it is written in (DIFFERENCES.md).
    pub async fn cleanup_tokens(&self, unused_days: i64) -> AuthResult<Value> {
        let expired = self.dir.store.delete_expired_tokens(self.clock.utc()).await?;
        let unused = self.dir.store.delete_unused_tokens(self.clock.local() - chrono::Duration::days(unused_days)).await?;
        let drafts = self.dir.store.delete_expired_draft_tokens(self.clock.utc()).await?;
        Ok(Obj::new()
            .put("expiredTokensRemoved", expired)
            .put("unusedTokensRemoved", unused)
            .put("expiredDraftTokensRemoved", drafts)
            .build())
    }
}
