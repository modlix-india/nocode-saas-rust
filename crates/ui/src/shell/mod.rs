//! ui-shell: the rest of the Java ui's request-time surface (`UniversalController`,
//! `AnalyticsController`, `UICacheController`), on port 8106. It shares the engine's
//! definition reads (the application for the index page, URI paths) and its caches' names.

pub mod analytics;
pub mod config;
pub mod gson;
pub mod index;
pub mod javautil;
pub mod paths;
pub mod server;
pub mod uripath;

use anyhow::Result;
use platform::app::Service;
use platform::cache::{normalize_redis_url, CacheService};
use platform::eureka::Eureka;
use platform::health::Health;
use platform::security::SecurityClient;
use platform::upstream::Upstream;

use crate::shell::config::ShellConfig;
use crate::shell::server::{load_entrypoints, router, ShellInner, ShellState};
use crate::state::{AppState, Inner};

pub const NAME: &str = "ui-shell";

/// Loads configuration, connects everything, and serves until shut down.
pub async fn run() -> Result<()> {
    let cfg: ShellConfig = platform::config::load(NAME)?;
    let telemetry = platform::telemetry::init(NAME, &cfg.telemetry)?;
    if let Some(file) = platform::config::config_file(NAME) {
        tracing::info!(file = %file.display(), "configuration file");
    }
    overridable::pojo::set_java_zone_offset_seconds(cfg.ui.zone_offset_seconds()?);

    let db = platform::db::mongo_database(&cfg.mongo).await?;
    let cache = CacheService::new(&cfg.redis.cache_prefix, &cfg.redis.eviction_channel, Some(cfg.redis.url.as_str()))?;
    let eureka = if cfg.eureka.register || !cfg.eureka.zones.is_empty() {
        Some(Eureka::new(&cfg.eureka, cfg.server.port)?)
    } else {
        None
    };
    let security = SecurityClient::from_config(&cfg.security, eureka.as_ref())?;
    let core = Upstream::from_config(&cfg.core.upstream, eureka.as_ref())?;
    let store = overridable::Store::new(db.clone(), security.clone(), &cache);
    let health = Health::new(telemetry.metrics.clone());
    {
        let db = db.clone();
        health.check("mongo", move || {
            let db = db.clone();
            async move {
                db.run_command(mongodb::bson::doc! {"ping": 1}).await?;
                Ok(())
            }
        });
    }
    let ui = AppState::new(Inner {
        store,
        security,
        properties: cache.family(),
        fillers: cache.family(),
        app_status: cache.family(),
        app_dependencies: cache.family(),
        cache: cache.clone(),
        config: cfg.engine_config(),
    });
    let http = reqwest::Client::builder().build()?;
    let entrypoints = load_entrypoints(&cfg, &http).await;
    let redis = match cfg.redis.url.trim() {
        "" => None,
        url => Some(redis::Client::open(normalize_redis_url(url).as_str())?),
    };
    let state = ShellState::new(ShellInner {
        ui,
        cfg: cfg.clone(),
        http,
        core,
        index: cache.family(),
        js: cache.family(),
        patterns: cache.family(),
        analytics: cache.family(),
        entrypoints,
        redis,
    });
    cache.spawn_eviction_listener();

    // CORS is answered inside the router, under the security headers, as the Java ui does.
    Service { name: NAME.to_string(), server: cfg.server.clone(), telemetry, health, eureka, cors: false }
        .run(router(state))
        .await
}
