//! security-internal: the Java security service's service-to-service routes (see SPLIT.md).
//!
//! Every request still gets its caller's context first, as `JWTTokenFilter` does for every path,
//! and the list reads restrict themselves by that context exactly as the Java DAOs do; most of
//! these paths are open to anonymous callers, which on the local stack are SYSTEM's.

pub mod apps;
pub mod billing;
pub mod clients;
pub mod contact;
pub mod routes;
pub mod scope;
pub mod ssl;
pub mod urls;
pub mod users;

use std::sync::Arc;

use anyhow::Result;
use platform::app::Service;
use platform::cache::CacheService;
use platform::health::Health;

use crate::caches::Caches;
use crate::config::AuthConfig;
use crate::data::billing::BillingStore;
use crate::data::Db;
use crate::directory::Directory;
use crate::events::{AmqpEvents, EventSink, LoggedEvents};
use crate::service::Auth;

pub const NAME: &str = "security-internal";

pub struct Internal {
    /// The caller's context and the cached directory reads (shared with security-auth).
    pub auth: Arc<Auth>,
    pub db: Db,
    pub billing: Arc<dyn BillingStore>,
    /// `EventCreationService` for the wallet events.
    pub wallet_events: Arc<dyn EventSink>,
}

impl Internal {
    pub fn dir(&self) -> &Directory {
        &self.auth.dir
    }

    pub fn caches(&self) -> &Caches {
        &self.auth.dir.caches
    }
}

/// The unit, wired from configuration (no network is touched until it is used).
pub fn build(cfg: &AuthConfig, pool: sqlx::MySqlPool, cache: CacheService) -> Arc<Internal> {
    let auth = crate::build(cfg, pool.clone(), cache);
    let wallet_events: Arc<dyn EventSink> = if cfg.wallet.publish_events && !cfg.mq.uri.is_empty() {
        Arc::new(AmqpEvents::new(&cfg.mq.uri, &cfg.mq.exchange, &cfg.mq.routing_keys))
    } else {
        Arc::new(LoggedEvents)
    };
    let db = Db::new(pool);
    Arc::new(Internal { auth, billing: Arc::new(db.clone()), db, wallet_events })
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
    let cache = CacheService::configured(&cfg.redis)?;
    let state = build(&cfg, pool.clone(), cache.clone());
    cache.spawn_eviction_listener();

    let registry = crate::registry_for(&cfg)?;
    let health = Health::new(telemetry.metrics.clone());
    health.check("mysql", move || {
        let pool = pool.clone();
        async move {
            sqlx::query("SELECT 1").execute(&pool).await?;
            Ok(())
        }
    });

    Service { name: NAME.to_string(), server: cfg.server.clone(), telemetry, health, registry, cors: true }
        .run(routes::router(state))
        .await
}
