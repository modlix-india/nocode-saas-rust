//! The files service in Rust: two deployable units over one library.
//!
//! - `files-serve`: every way a file is read (static, secured, by key, internal). Scales out on
//!   its own; 93% of files traffic.
//! - `files-manage`: everything else (upload, delete, folders, zip import/export, transforms,
//!   access paths, billing, cleanup), plus the read routes, so the Java services that call
//!   `FILES` through Feign reach one place. Registers in Eureka as `FILES` while Java callers
//!   remain.
//!
//! Both read the same MySQL schema and R2 buckets as the Java service, and take part in its
//! cache evictions (`cmn-fs*` on `evictionChannel`) for as long as Java instances run.

pub mod access;
pub mod accesspath;
pub mod billing;
pub mod condition;
pub mod config;
pub mod dao;
pub mod download;
pub mod errors;
pub mod fs;
pub mod fsdao;
pub mod handlers;
pub mod image_ops;
pub mod image_transform;
pub mod jackson;
pub mod jobs;
pub mod keys;
pub mod manage;
pub mod model;
pub mod options;
pub mod paths;
pub mod retention;
pub mod spring;
pub mod state;
pub mod store;
pub mod upload;
pub mod zipio;

use std::path::PathBuf;

use anyhow::Result;
use axum::Router;
use platform::app::Service;
use platform::cache::CacheService;
use platform::eureka::Eureka;
use platform::health::Health;
use platform::security::SecurityClient;

use crate::config::FilesConfig;
use crate::dao::Dao;
use crate::state::{AppState, Inner};
use crate::store::{s3_client, Store};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unit {
    Serve,
    Manage,
}

impl Unit {
    pub fn name(self) -> &'static str {
        match self {
            Self::Serve => "files-serve",
            Self::Manage => "files-manage",
        }
    }
}

/// Loads configuration, connects everything, and serves until shut down.
pub async fn run(unit: Unit) -> Result<()> {
    let name = unit.name();
    let loaded = platform::config::load_async::<FilesConfig>(name).await?;
    errors::register();
    let telemetry = platform::telemetry::init(name, &loaded.config.telemetry)?;
    loaded.log_source(name);
    let cfg = loaded.config;

    let pool = platform::db::mysql_pool(&cfg.database).await?;
    let s3 = s3_client(&cfg.storage.endpoint, &cfg.storage.access_key_id, &cfg.storage.secret_access_key);
    let temp_base = if cfg.storage.temp_dir.is_empty() {
        std::env::temp_dir()
    } else {
        PathBuf::from(&cfg.storage.temp_dir)
    };
    let work_dir = temp_base.join(format!("{name}-work"));
    std::fs::create_dir_all(&work_dir)?;
    let static_store = Store::new(s3.clone(), format!("{}-static", cfg.storage.bucket_prefix), &temp_base)?;
    let secured_store = Store::new(s3, format!("{}-secured", cfg.storage.bucket_prefix), &temp_base)?;

    let cache = CacheService::new(
        &cfg.redis.cache_prefix,
        &cfg.redis.eviction_channel,
        Some(cfg.redis.url.as_str()),
    )?;
    let details = cache.family();
    let exists = cache.family();
    let lists = cache.family();
    let retention_rows = cache.family();
    let hierarchies = cache.family();
    cache.spawn_eviction_listener();

    let eureka = if cfg.eureka.register || !cfg.eureka.zones.is_empty() {
        Some(Eureka::new(&cfg.eureka, cfg.server.port)?)
    } else {
        None
    };
    let security = SecurityClient::from_config(&cfg.security, eureka.as_ref())?;

    let health = Health::new(telemetry.metrics.clone());
    {
        let pool = pool.clone();
        health.check("mysql", move || {
            let pool = pool.clone();
            async move {
                sqlx::query("SELECT 1").execute(&pool).await?;
                Ok(())
            }
        });
    }

    let state = AppState::new(Inner {
        dao: Dao::new(pool),
        static_store,
        secured_store,
        details,
        exists,
        lists,
        retention_rows,
        hierarchies,
        cache,
        security,
        server_port: cfg.server.port,
        config: cfg.clone(),
        work_dir,
    });

    let app: Router = handlers::router(unit, state);

    Service {
        name: name.to_string(),
        server: cfg.server.clone(),
        telemetry,
        health,
        eureka,
        cors: true,
    }
    .run(app)
    .await
}
