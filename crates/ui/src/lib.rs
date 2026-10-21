//! ui-engine: the read routes of the Java ui service, which are nearly all of its traffic.
//!
//! - `EngineController`: application, page, style, theme, function, urlDetails;
//! - `PersonalizationController`: get, save, delete a user's setting;
//! - `FunctionController` / `SchemaController`: `repositoryFind`, `repositoryFilter`.
//!
//! It reads the Java ui's Mongo database through the `overridable` crate, keeps its
//! definition caches under the Java cache names (prefix `cmn`) so editor saves made through
//! the Java ui evict them, and answers with the same status codes, headers, ETags rules and
//! JSON. Editor CRUD stays on the Java service.
//!
//! The second binary, ui-shell ([`shell`]), serves the rest of the request-time surface: the
//! index page, the URI path routes, SSO, analytics and the cache endpoints.

pub mod authority;
pub mod catalogue;
pub mod config;
pub mod docs;
pub mod editor;
pub mod engine;
pub mod handlers;
pub mod kirun;
pub mod personalization;
pub mod repository;
pub mod respond;
pub mod shell;
pub mod ssr;
pub mod state;

use anyhow::Result;
use platform::app::Service;
use platform::cache::CacheService;
use platform::registry::Registry;
use platform::health::Health;
use platform::security::SecurityClient;

use crate::config::UiConfig;
use crate::state::{AppState, Inner};

pub const NAME: &str = "ui-engine";

/// Loads configuration, connects everything, and serves until shut down.
pub async fn run() -> Result<()> {
    let loaded = platform::config::load_async::<UiConfig>(NAME).await?;
    catalogue::register();
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

    let state = AppState::new(Inner {
        store,
        security,
        properties: cache.family_weighed(|v: &std::sync::Arc<overridable::JMap>| overridable::json::map_heap_bytes(v)),
        fillers: cache.family_weighed(|v: &std::sync::Arc<Option<std::sync::Arc<overridable::Resolved>>>| v.as_ref().as_ref().map_or(0, |r| r.approx_bytes())),
        app_status: cache.family(),
        app_dependencies: cache.family_weighed(|v: &std::sync::Arc<Vec<String>>| platform::cache::strings_bytes(v)),
        cache: cache.clone(),
        config: cfg.clone(),
    });
    cache.spawn_eviction_listener();

    // CORS is answered inside the router, under the security headers, as the Java ui does.
    Service { name: NAME.to_string(), server: cfg.server.clone(), telemetry, health, registry, cors: false }
        .run(handlers::router(state))
        .await
}
