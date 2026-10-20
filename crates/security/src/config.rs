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
    /// The certificate authority security-admin's SSL routes order certificates from.
    pub letsencrypt: LetsEncryptConfig,
    /// Cloudflare for SaaS custom hostnames for LIVE client URLs (security-admin).
    pub cloudflare: CloudflareConfig,
}

/// Let's Encrypt's production directory (`[letsencrypt] directory`'s default).
pub const LETS_ENCRYPT_DIRECTORY: &str = "https://acme-v02.api.letsencrypt.org/directory";

/// The ACME account security-admin orders certificates with. Java's `letsencrypt.session`,
/// `.login` and `.key` (an acme4j session URL, account URL and RSA account key) become
/// instant-acme's credentials: `security-admin acme-rollover` moves that same account to a new
/// P-256 key and prints them (see `admin/clients/rollover.rs`).
///
/// ```toml
/// [letsencrypt]
/// # The ACME directory (Let's Encrypt staging and Pebble are just other URLs). Used when the
/// # credentials do not name one; the credentials' own directory wins (an account lives on one
/// # server).
/// directory = "https://acme-v02.api.letsencrypt.org/directory"
/// # A secret: MODLIX__LETSENCRYPT__CREDENTIALS. Empty: no authority, and the SSL routes that
/// # would reach one answer 500 `lets_encrypt_credentials`.
/// credentials = ""
/// ```
#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LetsEncryptConfig {
    pub directory: String,
    /// The account credentials JSON `acme-rollover` (or `acme-register`) prints (account URL,
    /// key, directory).
    pub credentials: String,
}

impl Default for LetsEncryptConfig {
    fn default() -> Self {
        Self { directory: LETS_ENCRYPT_DIRECTORY.into(), credentials: String::new() }
    }
}

/// Key names only: the credentials hold the account's private key.
impl std::fmt::Debug for LetsEncryptConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LetsEncryptConfig").field("directory", &self.directory).field("credentials", &secret(&self.credentials)).finish()
    }
}

/// `security.cloudflare.*`: `CloudflareCustomHostnameService`'s settings.
///
/// ```toml
/// [cloudflare]
/// # security.cloudflare.apiToken. A secret: MODLIX__CLOUDFLARE__API_TOKEN.
/// api_token = ""
/// # security.cloudflare.zoneId.
/// zone_id = ""
/// # security.cloudflare.ownDomains: hosts at or under these are never registered.
/// own_domains = ["modlix.com", "sitezump.ai", "authzump.ai", "adzump.ai", "leadzump.ai", "fincity.com"]
/// ```
///
/// An empty token or zone leaves it off, as Java was on local, dev and stage.
#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CloudflareConfig {
    pub api_token: String,
    pub zone_id: String,
    pub own_domains: Vec<String>,
}

impl Default for CloudflareConfig {
    fn default() -> Self {
        Self {
            api_token: String::new(),
            zone_id: String::new(),
            own_domains: crate::admin::clients::cloudflare::OWN_DOMAINS.iter().map(|d| d.to_string()).collect(),
        }
    }
}

/// Key names only: the token is a secret.
impl std::fmt::Debug for CloudflareConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareConfig")
            .field("api_token", &secret(&self.api_token))
            .field("zone_id", &self.zone_id)
            .field("own_domains", &self.own_domains)
            .finish()
    }
}

fn secret(v: &str) -> &'static str {
    if v.trim().is_empty() {
        "<empty>"
    } else {
        "<set>"
    }
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
            letsencrypt: LetsEncryptConfig::default(),
            cloudflare: CloudflareConfig::default(),
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
        assert_eq!((c.letsencrypt.directory.as_str(), c.letsencrypt.credentials.as_str()), (LETS_ENCRYPT_DIRECTORY, ""));
        assert!(c.cloudflare.api_token.is_empty() && c.cloudflare.zone_id.is_empty());
        assert_eq!(c.cloudflare.own_domains.len(), 6);
    }

    #[test]
    fn secrets_never_print() {
        let le = LetsEncryptConfig { credentials: "{\"id\":\"zz-secret\"}".into(), ..Default::default() };
        let cf = CloudflareConfig { api_token: "zz-token".into(), zone_id: "z".into(), ..Default::default() };
        let shown = format!("{:?}", AuthConfig { letsencrypt: le, cloudflare: cf, ..Default::default() });
        assert!(!shown.contains("zz-secret") && !shown.contains("zz-token"), "{shown}");
        assert!(shown.contains("credentials: \"<set>\"") && shown.contains("api_token: \"<set>\""));
        assert!(format!("{:?}", LetsEncryptConfig::default()).contains("<empty>"));
    }

    #[test]
    fn loads_from_toml_and_environment() {
        figment::Jail::expect_with(|jail| {
            jail.create_dir("config")?;
            jail.create_file(
                "config/security-auth.toml",
                "[jwt]\nrefresh_minutes = 5\n[otp]\npublish_events = false\n[letsencrypt]\ndirectory = \"https://pebble.test/dir\"\n[cloudflare]\nzone_id = \"z\"\nown_domains = [\"a.io\"]\n",
            )?;
            jail.set_env("MODLIX__JWT__KEY", "k");
            jail.set_env("MODLIX__LETSENCRYPT__CREDENTIALS", r#"{"id":"https://ca.test/acct/1","key_pkcs8":"MIGH-_x","directory":"https://ca.test/dir"}"#);
            jail.set_env("MODLIX__CLOUDFLARE__API_TOKEN", "t");
            let c: AuthConfig = platform::config::load("security-auth").map_err(|e| e.to_string())?;
            assert_eq!((c.jwt.refresh_minutes, c.jwt.key.as_str(), c.otp.publish_events), (5, "k", false));
            assert_eq!(c.letsencrypt.directory, "https://pebble.test/dir");
            assert_eq!(c.letsencrypt.credentials, r#"{"id":"https://ca.test/acct/1","key_pkcs8":"MIGH-_x","directory":"https://ca.test/dir"}"#);
            assert_eq!((c.cloudflare.api_token.as_str(), c.cloudflare.zone_id.as_str(), c.cloudflare.own_domains.clone()), ("t", "z", vec!["a.io".to_string()]));
            Ok(())
        });
    }
}
