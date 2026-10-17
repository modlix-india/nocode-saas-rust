//! multi in Rust: application operations that span security, core and ui.

pub mod catalogue;
pub mod config;
pub mod errors;
pub mod index;
pub mod service;
pub mod transport;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use platform::app::Service;
use platform::eureka::Eureka;
use platform::health::Health;
use platform::security::SecurityClient;
use platform::upstream::Upstream;

use crate::config::MultiConfig;
use crate::service::AppState;

pub const NAME: &str = "multi";

pub async fn run() -> Result<()> {
    let cfg: MultiConfig = platform::config::load(NAME)?;
    catalogue::register();
    let telemetry = platform::telemetry::init(NAME, &cfg.telemetry)?;
    if let Some(file) = platform::config::config_file(NAME) {
        tracing::info!(file = %file.display(), "configuration file");
    }
    let eureka = if cfg.eureka.register || !cfg.eureka.zones.is_empty() {
        Some(Eureka::new(&cfg.eureka, cfg.server.port)?)
    } else {
        None
    };
    // The calls multi makes to security itself go where they run: the internal routes to
    // security-internal, the rest to security-admin (`[security]` as the security client reads it).
    let security_up = platform::security::security_upstream(&cfg.security, eureka.as_ref())?;
    let state = Arc::new(AppState {
        security: SecurityClient::from_config(&cfg.security, eureka.as_ref())?,
        security_up,
        core_up: Upstream::from_config(&cfg.core.upstream, eureka.as_ref())?,
        ui_up: Upstream::from_config(&cfg.ui.upstream, eureka.as_ref())?,
        // Transports of big apps take a while on every side.
        http: reqwest::Client::builder().timeout(Duration::from_secs(600)).build()?,
        port: cfg.server.port,
    });
    let health = Health::new(telemetry.metrics.clone());
    Service { name: NAME.to_string(), server: cfg.server.clone(), telemetry, health, eureka, cors: true }
        .run(service::router(state))
        .await
}
