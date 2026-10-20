//! security-admin: the rest of the Java security service's routes (SPLIT.md), in three pieces
//! that each own one module and its `data/<area>.rs` files:
//!
//! - [`users`]: users and organisation (users, profiles, roles, designations, departments,
//!   client managers, OTP, authority expressions);
//! - [`clients`]: clients, apps and hosting (clients and registration, apps, client URLs, SSL,
//!   client policies, client activities, transports);
//! - [`billing`]: billing bundles and configs, billing profile, purchases, invoices, wallets.
//!
//! Each piece exposes `router() -> Router<AdminState>`; [`router`] merges them under one state,
//! the security headers and the 405 answer. Handlers get the caller's context first through
//! [`crate::web_route!`] (most admin paths refuse an anonymous caller).
//!
//! [`Admin`] dereferences to [`Internal`], so the pieces reuse its service methods (clients,
//! users, apps, scopes, wallets) and its shared state (`auth`, `db`, `billing`).

pub mod billing;
pub mod clients;
pub mod users;

use std::ops::Deref;
use std::sync::Arc;

use anyhow::Result;
use axum::{middleware, Router};
use platform::app::Service;
use platform::cache::CacheService;
use platform::eureka::Eureka;
use platform::health::Health;
use platform::upstream::Upstream;

use crate::config::AuthConfig;
use crate::events::{AmqpEvents, EventSink, LoggedEvents};
pub use clients::hosting::Hosting;
use crate::handlers::security_headers;
use crate::internal::Internal;

pub const NAME: &str = "security-admin";

pub struct Admin {
    /// The shared service and state security-internal runs on.
    pub internal: Arc<Internal>,
    /// `EventCreationService` for what the admin services raise (user, invite, invoice events).
    pub events: Arc<dyn EventSink>,
    /// `IFeignFilesService`; `None` when `[files] upstream` is not configured.
    pub files: Option<Upstream>,
    /// The certificate authority, key maker and Cloudflare client (`[letsencrypt]`,
    /// `[cloudflare]`), one per process.
    pub hosting: Arc<Hosting>,
}

impl Deref for Admin {
    type Target = Internal;

    fn deref(&self) -> &Internal {
        &self.internal
    }
}

pub type AdminState = Arc<Admin>;

/// The unit, wired from configuration (no network is touched until it is used).
pub fn build(cfg: &AuthConfig, pool: sqlx::MySqlPool, cache: CacheService, eureka: Option<&Eureka>) -> Result<Arc<Admin>> {
    let internal = crate::internal::build(cfg, pool, cache);
    let events: Arc<dyn EventSink> = if cfg.events.publish_events && !cfg.mq.uri.is_empty() {
        Arc::new(AmqpEvents::new(&cfg.mq.uri, &cfg.mq.exchange, &cfg.mq.routing_keys))
    } else {
        Arc::new(LoggedEvents)
    };
    let files = if cfg.files.upstream.entries().is_empty() { None } else { Some(Upstream::from_config(&cfg.files.upstream, eureka)?) };
    let hosting = Arc::new(Hosting::from_config(cfg)?);
    Ok(Arc::new(Admin { internal, events, files, hosting }))
}

/// The commands besides serving (`security-admin acme-register ...`, see
/// [`clients::acme::run_if_asked`]); `None` for a normal start.
pub async fn run_if_asked(args: &[String]) -> Option<i32> {
    clients::acme::run_if_asked(args).await
}

pub fn router(state: AdminState) -> Router {
    Router::new()
        .merge(users::router())
        .merge(clients::router())
        .merge(billing::router())
        .method_not_allowed_fallback(crate::web::method_not_allowed)
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

/// Loads configuration, connects, and serves until shut down.
pub async fn run() -> Result<()> {
    let loaded = platform::config::load_async::<AuthConfig>(NAME).await?;
    let telemetry = platform::telemetry::init(NAME, &loaded.config.telemetry)?;
    loaded.log_source(NAME);
    let cfg = loaded.config;
    crate::check_jwt_key(&cfg)?;
    crate::configure_messages(&cfg)?;
    let pool = platform::db::mysql_pool(&cfg.database).await?;
    let cache = CacheService::new(&cfg.redis.cache_prefix, &cfg.redis.eviction_channel, Some(cfg.redis.url.as_str()))?;
    let eureka = crate::eureka_for(&cfg)?;
    let state = build(&cfg, pool.clone(), cache.clone(), eureka.as_ref())?;
    cache.spawn_eviction_listener();

    let health = Health::new(telemetry.metrics.clone());
    health.check("mysql", move || {
        let pool = pool.clone();
        async move {
            sqlx::query("SELECT 1").execute(&pool).await?;
            Ok(())
        }
    });

    Service { name: NAME.to_string(), server: cfg.server.clone(), telemetry, health, eureka, cors: true }
        .run(router(state))
        .await
}
