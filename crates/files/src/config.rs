//! files-serve / files-manage configuration. See `deploy/config/files-*.example.toml`.

use platform::config::{EurekaConfig, MySqlConfig, RedisConfig, SecurityConfig, ServerConfig, TelemetryConfig};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FilesConfig {
    pub server: ServerConfig,
    pub telemetry: TelemetryConfig,
    pub eureka: EurekaConfig,
    pub redis: RedisConfig,
    pub security: SecurityConfig,
    pub database: MySqlConfig,
    pub storage: StorageConfig,
    pub secured_keys: SecuredKeysConfig,
    pub billing: BillingConfig,
}

impl Default for FilesConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig { port: 8103, ..Default::default() },
            telemetry: TelemetryConfig::default(),
            eureka: EurekaConfig::default(),
            redis: RedisConfig::default(),
            security: SecurityConfig::default(),
            database: MySqlConfig { database: "files".into(), ..Default::default() },
            storage: StorageConfig::default(),
            secured_keys: SecuredKeysConfig::default(),
            billing: BillingConfig::default(),
        }
    }
}

/// The object store (Cloudflare R2 over the S3 API).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct StorageConfig {
    pub endpoint: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    /// Buckets are `<prefix>-static` and `<prefix>-secured`.
    pub bucket_prefix: String,
    /// Where downloaded copies and upload staging live. Empty: the system temp directory.
    pub temp_dir: String,
}

/// Secured access keys (`createKey`, `downloadFileByKey`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecuredKeysConfig {
    /// Default lifetime when the caller gives none (`files.timeLimit`).
    pub default_time_limit: i64,
    /// `DAYS`, `HOURS`, ... (`files.timeUnit`).
    pub default_time_unit: String,
    /// What `createKey` prefixes the key with (`files.secureKeyURI`).
    pub key_uri: String,
}

impl Default for SecuredKeysConfig {
    fn default() -> Self {
        Self {
            default_time_limit: 365,
            default_time_unit: "DAYS".into(),
            key_uri: "api/files/secured/downloadFileByKey/".into(),
        }
    }
}

/// Token billing for storage (`/internal/billing/*`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct BillingConfig {
    pub enabled: bool,
}
