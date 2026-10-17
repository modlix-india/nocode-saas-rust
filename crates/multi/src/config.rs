//! multi's configuration: where security, core and ui are.

use platform::config::{EurekaConfig, SecurityConfig, ServerConfig, TelemetryConfig, UpstreamConfig};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MultiConfig {
    pub server: ServerConfig,
    pub telemetry: TelemetryConfig,
    pub eureka: EurekaConfig,
    /// Caller identity and the security calls (apps, transports).
    pub security: SecurityConfig,
    pub core: ServiceConfig,
    pub ui: ServiceConfig,
}

impl Default for MultiConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig { port: 8110, ..Default::default() },
            telemetry: TelemetryConfig::default(),
            eureka: EurekaConfig::default(),
            security: SecurityConfig::default(),
            core: ServiceConfig::default(),
            ui: ServiceConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ServiceConfig {
    /// Base URL(s) or `eureka:<APP>`.
    pub upstream: UpstreamConfig,
}
