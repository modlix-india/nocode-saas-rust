//! ui-shell configuration: `config/ui-shell.toml`; secrets (`MODLIX__MONGO__URI`,
//! `MODLIX__REDIS__URL`, `MODLIX__SHELL__ANALYTICS_ENGINE_SECRET`) from the environment.

use platform::config::{
    EurekaConfig, MongoConfig, RedisConfig, SecurityConfig, ServerConfig, TelemetryConfig, UpstreamConfig,
};
use serde::{Deserialize, Serialize};

use crate::config::{UiConfig, UiSection};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ShellConfig {
    pub server: ServerConfig,
    pub telemetry: TelemetryConfig,
    pub eureka: EurekaConfig,
    pub redis: RedisConfig,
    pub security: SecurityConfig,
    pub mongo: MongoConfig,
    pub ui: UiSection,
    pub shell: ShellSection,
    pub core: CoreConfig,
}

impl Default for ShellConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig { port: 8106, ..Default::default() },
            telemetry: TelemetryConfig::default(),
            eureka: EurekaConfig::default(),
            redis: RedisConfig { cache_prefix: "cmn".into(), ..Default::default() },
            security: SecurityConfig::default(),
            mongo: MongoConfig::default(),
            ui: UiSection::default(),
            shell: ShellSection::default(),
            core: CoreConfig::default(),
        }
    }
}

impl ShellConfig {
    /// The engine's configuration, for the definition reads the shell shares with it.
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

/// The Java ui's `ui.*` and `security.appCodeSuffix` values the shell reads.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ShellSection {
    /// `ui.cdnHostName`: the CDN host the page loads scripts from; empty serves `/js/dist/`.
    pub cdn_host_name: String,
    /// `ui.cdnStripAPIPrefix`.
    pub cdn_strip_api_prefix: bool,
    /// `ui.cdnReplacePlus`.
    pub cdn_replace_plus: bool,
    /// `ui.cdnResizeOptionsType`.
    pub cdn_resize_options_type: String,
    /// `security.appCodeSuffix` (`.local`, `.dev`, ...): picks the SSO beacon host.
    pub app_code_suffix: String,
    /// `ui.jsURL`: where `/js/dist/**` is fetched from; empty answers an empty body.
    pub js_url: String,
    /// A local `asset-manifest.json` to read instead of the CDN's (the Java classpath copy).
    pub asset_manifest_file: String,
    /// `ui.analytics.ingestionHost`: the beacon's host; empty leaves the beacon out.
    pub analytics_ingestion_host: String,
    /// `ui.analytics.engine.url` and `.secret`: the analytics engine the query proxy calls.
    pub analytics_engine_url: String,
    pub analytics_engine_secret: String,
    /// The Redis channel the SSR renderers listen on for cache invalidations.
    pub ssr_channel: String,
}

impl Default for ShellSection {
    fn default() -> Self {
        Self {
            cdn_host_name: String::new(),
            cdn_strip_api_prefix: true,
            cdn_replace_plus: false,
            cdn_resize_options_type: "none".into(),
            app_code_suffix: String::new(),
            js_url: String::new(),
            asset_manifest_file: String::new(),
            analytics_ingestion_host: String::new(),
            analytics_engine_url: String::new(),
            analytics_engine_secret: String::new(),
            ssr_channel: "ssr:cache:invalidation".into(),
        }
    }
}

/// Where the core service is, for the URI path routes that run a KIRun function.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CoreConfig {
    pub upstream: UpstreamConfig,
    /// Feign's `readTimeoutMillis` (60 s in the Java configuration).
    pub timeout_seconds: u64,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self { upstream: UpstreamConfig::One("eureka:CORE".into()), timeout_seconds: 60 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_java_ones() {
        let c = ShellConfig::default();
        assert_eq!(c.server.port, 8106);
        assert_eq!(c.redis.cache_prefix, "cmn");
        assert!(c.shell.cdn_strip_api_prefix);
        assert!(!c.shell.cdn_replace_plus);
        assert_eq!(c.shell.cdn_resize_options_type, "none");
        assert_eq!(c.shell.ssr_channel, "ssr:cache:invalidation");
        assert_eq!(c.core.upstream.entries(), vec!["eureka:CORE".to_string()]);
        assert_eq!(c.engine_config().server.port, 8106);
    }
}
