//! The authentication service: what `AuthenticationService` and the pieces of `UserService`,
//! `TokenService` and `OtpService` it calls do, over a [`Store`](crate::store::Store) and the
//! shared caches.

use std::sync::Arc;

use crate::clock::Clock;
use crate::directory::Directory;
use crate::events::{EventSink, SmsSender};

/// The Java properties the service reads.
#[derive(Debug, Clone)]
pub struct Settings {
    /// `jwt.key`.
    pub jwt_key: String,
    /// `jwt.token.default.expiry`.
    pub default_expiry_minutes: i64,
    /// `jwt.token.rememberme.expiry`.
    pub remember_me_expiry_minutes: i64,
    /// `jwt.token.default.refresh`.
    pub refresh_minutes: i64,
    /// `security.appCodeSuffix`.
    pub app_code_suffix: String,
    /// `security.oneTimeToken.maxAgeMinutes`.
    pub one_time_token_max_age_minutes: i64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            jwt_key: String::new(),
            default_expiry_minutes: 30,
            remember_me_expiry_minutes: 525_600,
            refresh_minutes: 10,
            app_code_suffix: String::new(),
            one_time_token_max_age_minutes: 5,
        }
    }
}

pub struct Auth {
    pub dir: Directory,
    pub settings: Settings,
    pub clock: Clock,
    pub events: Arc<dyn EventSink>,
    pub sms: Arc<dyn SmsSender>,
}

/// `security_sox_log` names.
pub const SOX_LOGIN: &str = "LOGIN";
pub const SOX_UPDATE: &str = "UPDATE";
pub const SOX_USER: &str = "USER";

impl Auth {
    /// `SoxLogService.createLog(...)`: fire and forget, as Java's `.subscribe()` is.
    pub fn sox(&self, user_id: u64, action: &'static str, description: &'static str) {
        let store = self.dir.store.clone();
        tokio::spawn(async move {
            if let Err(e) = store.insert_sox_log(user_id, action, SOX_USER, description).await {
                tracing::warn!(error = %e, "sox log not written");
            }
        });
    }

    /// `fillValues(callbackUrl, token)`: the callback with `{env}`, `{envDotPrefix}`,
    /// `{envDotSuffix}` and `{token}` filled in; `""` when there is none.
    pub fn fill_values(&self, url: Option<&str>, token: &str) -> String {
        let Some(url) = url.filter(|u| !u.trim().is_empty()) else { return String::new() };
        let env = self.settings.app_code_suffix.replace('.', "");
        url.replace("{env}", &env)
            .replace("{envDotPrefix}", &format!(".{env}"))
            .replace("{envDotSuffix}", &format!("{env}."))
            .replace("{token}", token)
    }
}
