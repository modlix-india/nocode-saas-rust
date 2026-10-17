//! The Java security service in Rust: security-auth (`AuthenticationController`, the
//! modules below `handlers`), security-internal (the service-to-service routes, in `internal`)
//! and security-admin (the rest, in `admin`), over one shared data layer (see SPLIT.md).
//!
//! It runs beside the Java security service on the same `security` schema and the same Redis:
//! tokens either one mints the other accepts, a revoke on either is honoured by both, failed
//! attempts and locks are the same rows, and cache evictions travel both ways on
//! `evictionChannel` (see `caches.rs`).

pub mod admin;
pub mod authorities;
pub mod caches;
pub mod catalogue;
pub mod clock;
pub mod condition;
pub mod config;
pub mod context;
pub mod data;
pub mod decimal;
pub mod directory;
pub mod dto;
pub mod errors;
pub mod events;
pub mod expr;
pub mod handlers;
pub mod internal;
pub mod jackson;
pub mod javamap;
pub mod jwt;
pub mod messages;
pub mod model;
pub mod mysql;
pub mod org;
pub mod otp;
pub mod request;
pub mod service;
pub mod signin;
pub mod spring;
pub mod store;
pub mod timezone;
pub mod tokens;
pub mod useragent;
pub mod web;


use std::sync::Arc;

use anyhow::{bail, Result};
use platform::app::Service;
use platform::cache::CacheService;
use platform::eureka::Eureka;
use platform::health::Health;

use crate::caches::Caches;
use crate::clock::Clock;
use crate::config::AuthConfig;
use crate::directory::Directory;
use crate::events::{AmqpEvents, EventSink, LoggedEvents, TwoFactorSms, TWO_FACTOR_API_URL};
use crate::mysql::MySqlStore;
use crate::service::{Auth, Settings};

pub const NAME: &str = "security-auth";

/// The service, wired from configuration (no network is touched until it is used).
pub fn build(cfg: &AuthConfig, pool: sqlx::MySqlPool, cache: CacheService) -> Arc<Auth> {
    let events: Arc<dyn EventSink> = if cfg.otp.publish_events && !cfg.mq.uri.is_empty() {
        Arc::new(AmqpEvents::new(&cfg.mq.uri, &cfg.mq.exchange, &cfg.mq.routing_keys))
    } else {
        Arc::new(LoggedEvents)
    };
    Arc::new(Auth {
        dir: Directory::new(Arc::new(MySqlStore::new(pool)), Caches::new(cache), cfg.security.subdomain_endings()),
        settings: Settings {
            jwt_key: cfg.jwt.key.clone(),
            default_expiry_minutes: cfg.jwt.default_expiry_minutes,
            remember_me_expiry_minutes: cfg.jwt.remember_me_expiry_minutes,
            refresh_minutes: cfg.jwt.refresh_minutes,
            app_code_suffix: cfg.security.app_code_suffix.clone(),
            one_time_token_max_age_minutes: cfg.security.one_time_token_max_age_minutes,
        },
        clock: Clock::system(),
        events,
        sms: Arc::new(TwoFactorSms::new(&cfg.sms.two_factor_api_key, TWO_FACTOR_API_URL)),
    })
}

/// Logs which configuration file a unit read, if any.
pub(crate) fn log_config_file(name: &str) {
    if let Some(file) = platform::config::config_file(name) {
        tracing::info!(file = %file.display(), "configuration file");
    }
}

/// The error catalogue every unit answers with, and `[messages]`' override files.
pub(crate) fn configure_messages(cfg: &AuthConfig) -> Result<()> {
    catalogue::register();
    platform::messages::configure(&cfg.messages)?;
    Ok(())
}

/// The start-up check every unit makes: the signing key is long enough for HS512.
pub(crate) fn check_jwt_key(cfg: &AuthConfig) -> Result<()> {
    if cfg.jwt.key.len() < 64 {
        bail!("jwt.key must be set (MODLIX__JWT__KEY) and at least 64 bytes for HS512");
    }
    Ok(())
}

/// Discovery, when the unit registers in it or reaches other units through it.
pub(crate) fn eureka_for(cfg: &AuthConfig) -> Result<Option<Eureka>> {
    if cfg.eureka.register || !cfg.eureka.zones.is_empty() {
        Ok(Some(Eureka::new(&cfg.eureka, cfg.server.port)?))
    } else {
        Ok(None)
    }
}

/// Loads configuration, connects, and serves until shut down.
pub async fn run() -> Result<()> {
    let cfg: AuthConfig = platform::config::load(NAME)?;
    let telemetry = platform::telemetry::init(NAME, &cfg.telemetry)?;
    crate::log_config_file(NAME);
    crate::check_jwt_key(&cfg)?;
    crate::configure_messages(&cfg)?;
    let pool = platform::db::mysql_pool(&cfg.database).await?;
    let cache = CacheService::new(&cfg.redis.cache_prefix, &cfg.redis.eviction_channel, Some(cfg.redis.url.as_str()))?;
    let auth = build(&cfg, pool.clone(), cache.clone());
    cache.spawn_eviction_listener();

    let eureka = crate::eureka_for(&cfg)?;
    let health = Health::new(telemetry.metrics.clone());
    health.check("mysql", move || {
        let pool = pool.clone();
        async move {
            sqlx::query("SELECT 1").execute(&pool).await?;
            Ok(())
        }
    });

    Service { name: NAME.to_string(), server: cfg.server.clone(), telemetry, health, eureka, cors: true }
        .run(handlers::router(auth))
        .await
}

#[cfg(test)]
mod startup_tests {
    use super::*;

    /// (`Eureka::new` starts its refresh task, so a runtime is needed.)
    #[tokio::test]
    async fn key_and_discovery() {
        let mut cfg = AuthConfig::default();
        cfg.jwt.key = "short".into();
        assert!(check_jwt_key(&cfg).unwrap_err().to_string().contains("64 bytes"));
        cfg.jwt.key = "k".repeat(64);
        check_jwt_key(&cfg).unwrap();
        configure_messages(&cfg).unwrap();
        assert!(eureka_for(&cfg).unwrap().is_none());
        cfg.eureka.zones = vec!["http://127.0.0.1:9/eureka".into()];
        assert!(eureka_for(&cfg).unwrap().is_some());
        // A unit with no configuration file logs nothing.
        log_config_file("no-such-unit");
    }

    /// Every unit wired with events on, an MQ address and a files upstream (nothing connects
    /// until used).
    #[tokio::test]
    async fn units_with_every_option() {
        let mut cfg = AuthConfig::default();
        cfg.jwt.key = "k".repeat(64);
        cfg.otp.publish_events = true;
        cfg.events.publish_events = true;
        cfg.wallet.publish_events = true;
        cfg.mq.uri = "amqp://nobody@127.0.0.1:9/%2f".into();
        cfg.files.upstream = platform::config::UpstreamConfig::One("http://127.0.0.1:9".into());
        let pool = sqlx::mysql::MySqlPoolOptions::new().connect_lazy("mysql://nobody@127.0.0.1:9/none").unwrap();
        let cache = CacheService::new("cmn", "evictionChannel", None).unwrap();
        let admin = admin::build(&cfg, pool, cache, None).unwrap();
        assert!(admin.files.is_some());
    }
}
