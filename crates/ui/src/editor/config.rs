//! ui-editor configuration: `config/ui-editor.toml`; secrets (`MODLIX__MONGO__URI`,
//! `MODLIX__REDIS__URL`, `MODLIX__EDITOR__APPLE_API_KEY_CONTENT`) from the environment.

use platform::config::{EurekaConfig, MongoConfig, RedisConfig, SecurityConfig, ServerConfig, TelemetryConfig};
use serde::{Deserialize, Serialize};

use crate::config::{UiConfig, UiSection};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EditorConfig {
    pub server: ServerConfig,
    pub telemetry: TelemetryConfig,
    pub eureka: EurekaConfig,
    pub redis: RedisConfig,
    pub security: SecurityConfig,
    pub mongo: MongoConfig,
    pub ui: UiSection,
    pub editor: EditorSection,
}

impl Default for EditorConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig { port: 8107, ..Default::default() },
            telemetry: TelemetryConfig::default(),
            eureka: EurekaConfig::default(),
            redis: RedisConfig { cache_prefix: "cmn".into(), ..Default::default() },
            security: SecurityConfig::default(),
            mongo: MongoConfig::default(),
            ui: UiSection::default(),
            editor: EditorSection::default(),
        }
    }
}

impl EditorConfig {
    /// The engine's configuration, for the pieces the editor shares with it.
    pub fn engine_config(&self) -> UiConfig {
        UiConfig {
            server: self.server.clone(),
            telemetry: self.telemetry.clone(),
            eureka: self.eureka.clone(),
            redis: self.redis.clone(),
            security: self.security.clone(),
            mongo: self.mongo.clone(),
            ui: self.ui.clone(),
        }
    }
}

/// The Java ui's `security.appCodeSuffix` and `ui.apple.*` values.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EditorSection {
    /// `security.appCodeSuffix`: the mobile app's default start URL names the environment.
    pub app_code_suffix: String,
    /// The SSR renderers' invalidation channel.
    pub ssr_channel: String,
    /// `ui.apple.apiKeyId`, `.apiIssuerId`, `.apiKeyContent` (a base64 `.p8`), `.bundleIdPrefix`,
    /// `.teamId`, `.certificateId`: App Store Connect, for iOS builds on the platform account.
    pub apple_api_key_id: String,
    pub apple_api_issuer_id: String,
    pub apple_api_key_content: String,
    pub apple_bundle_id_prefix: String,
    pub apple_team_id: String,
    pub apple_certificate_id: String,
    /// The App Store Connect API (a test points it elsewhere).
    pub apple_api_url: String,
}

impl Default for EditorSection {
    fn default() -> Self {
        Self {
            app_code_suffix: String::new(),
            ssr_channel: crate::ssr::SSR_CHANNEL.into(),
            apple_api_key_id: String::new(),
            apple_api_issuer_id: String::new(),
            apple_api_key_content: String::new(),
            apple_bundle_id_prefix: "com.modlix.apps".into(),
            apple_team_id: String::new(),
            apple_certificate_id: String::new(),
            apple_api_url: "https://api.appstoreconnect.apple.com".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_java_ones() {
        let c = EditorConfig::default();
        assert_eq!(c.server.port, 8107);
        assert_eq!(c.redis.cache_prefix, "cmn");
        assert_eq!(c.editor.apple_bundle_id_prefix, "com.modlix.apps");
        assert_eq!(c.editor.ssr_channel, "ssr:cache:invalidation");
        assert_eq!(c.engine_config().server.port, 8107);
    }
}
