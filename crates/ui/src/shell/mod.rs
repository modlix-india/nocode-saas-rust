//! ui-shell: the rest of the Java ui's request-time surface (`UniversalController`,
//! `AnalyticsController`, `UICacheController`), on port 8106. It shares the engine's
//! definition reads (the application for the index page, URI paths) and its caches' names.

pub mod analytics;
pub mod config;
pub mod gson;
pub mod index;
pub mod ipfilter;
pub mod javautil;
pub mod paths;
pub mod server;
pub mod uripath;
pub mod webhook;

use anyhow::Result;
use platform::app::Service;
use platform::cache::{normalize_redis_url, CacheService};
use platform::registry::Registry;
use platform::health::Health;
use platform::security::SecurityClient;
use platform::upstream::Upstream;

use crate::shell::config::ShellConfig;
use crate::shell::server::{load_entrypoints, router, ShellInner, ShellState};
use crate::state::{AppState, Inner};

pub const NAME: &str = "ui-shell";

/// Loads configuration, connects everything, and serves until shut down.
pub async fn run() -> Result<()> {
    let loaded = platform::config::load_async::<ShellConfig>(NAME).await?;
    let telemetry = platform::telemetry::init(NAME, &loaded.config.telemetry)?;
    loaded.log_source(NAME);
    let cfg = loaded.config;
    overridable::pojo::set_java_zone_offset_seconds(cfg.ui.zone_offset_seconds()?);

    let db = platform::db::mongo_database(&cfg.mongo).await?;
    let cache = CacheService::configured(&cfg.redis)?;
    let registry = if cfg.registry.register || !cfg.registry.zones.is_empty() {
        Some(Registry::new(&cfg.registry, cfg.server.port)?)
    } else {
        None
    };
    let security = SecurityClient::from_config(&cfg.security, registry.as_ref())?;
    let core = Upstream::from_config(&cfg.core.upstream, registry.as_ref())?;
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
        properties: cache.family_weighed(|v: &std::sync::Arc<overridable::JMap>| overridable::json::map_heap_bytes(v)),
        fillers: cache.family_weighed(|v: &std::sync::Arc<Option<std::sync::Arc<overridable::Resolved>>>| v.as_ref().as_ref().map_or(0, |r| r.approx_bytes())),
        app_status: cache.family(),
        app_dependencies: cache.family_weighed(|v: &std::sync::Arc<Vec<String>>| platform::cache::strings_bytes(v)),
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
        index: cache.family_weighed(|v: &std::sync::Arc<index::IndexPage>| {
            v.html.capacity() + v.unique_id.capacity() + v.headers.iter().map(|(k, x)| 48 + k.capacity() + x.capacity()).sum::<usize>()
        }),
        js: cache.family_weighed(|v: &std::sync::Arc<server::JsFile>| v.body.capacity() + v.unique_id.capacity()),
        patterns: cache.family_weighed(|v: &std::sync::Arc<Vec<String>>| platform::cache::strings_bytes(v)),
        analytics: cache.family_weighed(|v: &std::sync::Arc<Option<overridable::JValue>>| v.as_ref().as_ref().map_or(0, overridable::JValue::heap_bytes)),
        entrypoints,
        redis,
    });
    cache.spawn_eviction_listener();

    // CORS is answered inside the router, under the security headers, as the Java ui does.
    Service { name: NAME.to_string(), server: cfg.server.clone(), telemetry, health, registry, cors: false }
        .run(router(state))
        .await
}
