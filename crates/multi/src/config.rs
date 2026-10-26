//! multi's configuration: where security, core, ui and files are.

use platform::config::{RegistryConfig, SecurityConfig, ServerConfig, TelemetryConfig, UpstreamConfig};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MultiConfig {
    pub server: ServerConfig,
    pub telemetry: TelemetryConfig,
    pub registry: RegistryConfig,
    /// Caller identity and the security calls (apps, transports).
    pub security: SecurityConfig,
    pub core: ServiceConfig,
    pub ui: ServiceConfig,
    /// files-manage, for the purge only.
    pub files: ServiceConfig,
}

impl Default for MultiConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig { port: 8110, ..Default::default() },
            telemetry: TelemetryConfig::default(),
            registry: RegistryConfig::default(),
            security: SecurityConfig::default(),
            core: ServiceConfig::default(),
            ui: ServiceConfig::default(),
            files: ServiceConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ServiceConfig {
    /// Base URL(s) or `lighthouse:<APP>`.
    pub upstream: UpstreamConfig,
}
