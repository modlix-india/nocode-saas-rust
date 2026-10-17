//! The security units' configuration (security-auth, security-internal: one shape, one file each).
//! Every value here mirrors a Java `security` property; the Java name is on each field so the two
//! can be kept in step while both run.

use platform::config::{EurekaConfig, MessagesConfig, MySqlConfig, RedisConfig, ServerConfig, TelemetryConfig, UpstreamConfig};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    pub server: ServerConfig,
    pub telemetry: TelemetryConfig,
    pub eureka: EurekaConfig,
    pub redis: RedisConfig,
    /// The `security` schema (`security.db.*`).
    pub database: MySqlConfig,
    pub jwt: JwtConfig,
    pub security: SecurityProps,
    pub mq: MqConfig,
    pub otp: OtpConfig,
    pub sms: SmsConfig,
    pub wallet: WalletConfig,
    pub events: EventsConfig,
    pub files: FilesConfig,
    /// The error texts: override files (`[messages] override_dir`) and the default language.
    pub messages: MessagesConfig,
}

/// The events security-admin raises through `EventCreationService` (users, invites, ...).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EventsConfig {
    /// Publish them on `[mq]`. Off on the local stack, where they are logged instead.
    pub publish_events: bool,
}

impl Default for EventsConfig {
    fn default() -> Self {
        Self { publish_events: true }
    }
}

/// The files service (`IFeignFilesService`): `internal/accesspath`, `internal/secured/createKey`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FilesConfig {
    /// Base URL(s) or `eureka:FILES`. Empty: the routes that need files answer 500.
    pub upstream: UpstreamConfig,
}

/// The wallet events `WalletService` raises (`WALLET_LOW_BALANCE`, `WALLET_SUSPENDED`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WalletConfig {
    /// Publish them on `[mq]`. Off on the local stack, where they are logged instead.
    pub publish_events: bool,
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self { publish_events: true }
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig { port: 8101, ..Default::default() },
            telemetry: TelemetryConfig::default(),
            eureka: EurekaConfig::default(),
            redis: RedisConfig::default(),
            database: MySqlConfig { database: "security".into(), max_connections: 16, ..Default::default() },
            jwt: JwtConfig::default(),
            security: SecurityProps::default(),
            mq: MqConfig::default(),
            otp: OtpConfig::default(),
            sms: SmsConfig::default(),
            wallet: WalletConfig::default(),
            events: EventsConfig::default(),
            files: FilesConfig::default(),
            messages: MessagesConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct JwtConfig {
    /// `jwt.key`: the HMAC key, used as its UTF-8 bytes. A secret: `MODLIX__JWT__KEY`.
    pub key: String,
    /// `jwt.token.default.expiry`, minutes.
    pub default_expiry_minutes: i64,
    /// `jwt.token.rememberme.expiry`, minutes.
    pub remember_me_expiry_minutes: i64,
    /// `jwt.token.default.refresh`, minutes: refreshToken renews a token this close to expiry.
    pub refresh_minutes: i64,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self { key: String::new(), default_expiry_minutes: 30, remember_me_expiry_minutes: 525_600, refresh_minutes: 10 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityProps {
    /// `security.appCodeSuffix`, e.g. `.local`, `.dev`, empty in production.
    pub app_code_suffix: String,
    /// `security.subdomain.endings`, comma separated as in the yml.
    pub subdomain_endings: String,
    /// `security.oneTimeToken.maxAgeMinutes`.
    pub one_time_token_max_age_minutes: i64,
}

impl Default for SecurityProps {
    fn default() -> Self {
        Self { app_code_suffix: String::new(), subdomain_endings: String::new(), one_time_token_max_age_minutes: 5 }
    }
}

impl SecurityProps {
    /// Spring's String[] conversion: split on commas, trim each, drop nothing else.
    pub fn subdomain_endings(&self) -> Vec<String> {
        if self.subdomain_endings.trim().is_empty() {
            return Vec::new();
        }
        self.subdomain_endings.split(',').map(|s| s.trim().to_string()).collect()
    }
}

/// RabbitMQ, for the `USER_OTP_GENERATE` event (`EventCreationService`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MqConfig {
    /// `amqp://user:password@host:5672/%2f`, from `MODLIX__MQ__URI`. Empty disables publishing.
    pub uri: String,
    /// `events.mq.exchange`.
    pub exchange: String,
    /// `events.mq.routingkeys`.
    pub routing_keys: String,
}

impl Default for MqConfig {
    fn default() -> Self {
        Self { uri: String::new(), exchange: "events".into(), routing_keys: "events1,events2,events3".into() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OtpConfig {
    /// Publish `USER_OTP_GENERATE` (which ends in an e-mail). Off on the local stack, where the
    /// event is logged instead and treated as sent, so a test sign-in never mails anybody.
    pub publish_events: bool,
}

impl Default for OtpConfig {
    fn default() -> Self {
        Self { publish_events: true }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct SmsConfig {
    /// `sms.provider.2factor.api.key`. Empty: the SMS is logged and treated as sent, exactly as
    /// `TwoFactorService` does without a key.
    pub two_factor_api_key: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_java_properties() {
        let c = AuthConfig::default();
        assert_eq!(c.server.port, 8101);
        assert_eq!(c.database.database, "security");
        assert_eq!((c.jwt.default_expiry_minutes, c.jwt.remember_me_expiry_minutes, c.jwt.refresh_minutes), (30, 525_600, 10));
        assert_eq!(c.security.one_time_token_max_age_minutes, 5);
        assert_eq!((c.mq.exchange.as_str(), c.mq.routing_keys.as_str()), ("events", "events1,events2,events3"));
        assert!(c.otp.publish_events);
        assert!(c.sms.two_factor_api_key.is_empty());
        assert!(c.security.subdomain_endings().is_empty());
        let s = SecurityProps { subdomain_endings: ".local.modlix.com, .local.sitezump.ai".into(), ..Default::default() };
        assert_eq!(s.subdomain_endings(), vec![".local.modlix.com", ".local.sitezump.ai"]);
    }

    #[test]
    fn loads_from_toml_and_environment() {
        figment::Jail::expect_with(|jail| {
            jail.create_dir("config")?;
            jail.create_file("config/security-auth.toml", "[jwt]\nrefresh_minutes = 5\n[otp]\npublish_events = false\n")?;
            jail.set_env("MODLIX__JWT__KEY", "k");
            let c: AuthConfig = platform::config::load("security-auth").map_err(|e| e.to_string())?;
            assert_eq!((c.jwt.refresh_minutes, c.jwt.key.as_str(), c.otp.publish_events), (5, "k", false));
            Ok(())
        });
    }
}
