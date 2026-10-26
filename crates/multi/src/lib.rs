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
use platform::registry::Registry;
use platform::health::Health;
use platform::security::SecurityClient;
use platform::upstream::Upstream;

use crate::config::MultiConfig;
use crate::service::AppState;

pub const NAME: &str = "multi";

/// How often the version of multi's configuration is asked when it comes from Lighthouse.
const VERSION_POLL: Duration = Duration::from_secs(30);

pub async fn run() -> Result<()> {
    // With LIGHTHOUSE_URLS set the configuration comes from Lighthouse (between the TOML file
    // and the environment); without it, as before.
    let loaded = platform::config::load_async::<MultiConfig>(NAME).await?;
    let mut cfg = loaded.config;
    catalogue::register();
    let telemetry = platform::telemetry::init(NAME, &cfg.telemetry)?;
    if let Some(file) = platform::config::config_file(NAME) {
        tracing::info!(file = %file.display(), "configuration file");
    }
    if let Some(w) = &loaded.warning {
        tracing::warn!("{w}");
    }
    // From Lighthouse, multi registers there through the readiness-gated registration with the
    // version it runs as `configVersion` (keepup-rust.sh compares it with the current one), and
    // the Lighthouse client is left to discovery. Its live keys are kept current in place.
    let registration = loaded.lighthouse.as_ref().filter(|_| cfg.registry.register).map(|l| {
        let app = Some(cfg.registry.register_as.as_str()).filter(|a| !a.is_empty()).unwrap_or(NAME);
        lighthouse_client::registration(app, cfg.server.port, "/readyz")
            .ip(&cfg.registry.instance_ip)
            .metadata("configVersion", &l.version)
    });
    if registration.is_some() {
        cfg.registry.register = false;
    }
    let _live = loaded.lighthouse.as_ref().map(|l| {
        tracing::info!(version = l.version, "configuration from lighthouse");
        let live = platform::config::LiveConfig::new(cfg.clone(), &l.version);
        (platform::config::spawn_live_watch(NAME, l, live.clone(), VERSION_POLL), live)
    });
    let registry = if cfg.registry.register || !cfg.registry.zones.is_empty() {
        Some(Registry::new(&cfg.registry, cfg.server.port)?)
    } else {
        None
    };
    // The calls multi makes to security itself go where they run: the internal routes to
    // security-internal, the rest to security-admin (`[security]` as the security client reads it).
    let security_up = platform::security::security_upstream(&cfg.security, registry.as_ref())?;
    let state = Arc::new(AppState {
        security: SecurityClient::from_config(&cfg.security, registry.as_ref())?,
        security_up,
        core_up: Upstream::from_config(&cfg.core.upstream, registry.as_ref())?,
        ui_up: Upstream::from_config(&cfg.ui.upstream, registry.as_ref())?,
        // Optional: without `[files]` multi still serves everything else and refuses only the purge.
        files_up: if cfg.files.upstream.entries().is_empty() {
            None
        } else {
            Some(Upstream::from_config(&cfg.files.upstream, registry.as_ref())?)
        },
        // Transports of big apps take a while on every side.
        http: reqwest::Client::builder().timeout(Duration::from_secs(600)).build()?,
        port: cfg.server.port,
    });
    let health = Health::new(telemetry.metrics.clone());
    Service { name: NAME.to_string(), server: cfg.server.clone(), telemetry, health, registry, cors: true }
        .run_with(service::router(state), registration)
        .await
}
