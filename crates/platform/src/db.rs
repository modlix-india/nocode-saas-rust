//! Database pools from configuration.

use std::time::Duration;

use anyhow::{Context, Result};
use sqlx::mysql::{MySqlConnectOptions, MySqlPool, MySqlPoolOptions};

use crate::config::MySqlConfig;

/// A MySQL pool. Sessions run in UTC, so `TIMESTAMP` columns decode to the right instant
/// whatever zone the server is in.
pub async fn mysql_pool(cfg: &MySqlConfig) -> Result<MySqlPool> {
    let opts = MySqlConnectOptions::new()
        .host(&cfg.host)
        .port(cfg.port)
        .database(&cfg.database)
        .username(&cfg.username)
        .password(&cfg.password)
        .timezone(Some(String::from("+00:00")));
    MySqlPoolOptions::new()
        .max_connections(cfg.max_connections.max(1))
        .min_connections(1)
        .acquire_timeout(Duration::from_secs(10))
        .connect_with(opts)
        .await
        .with_context(|| format!("connecting to mysql {}:{}/{}", cfg.host, cfg.port, cfg.database))
}

/// A MongoDB database handle from configuration (feature `mongo`). The driver pools
/// connections itself; the handle is cheap to clone and meant to be shared.
#[cfg(feature = "mongo")]
pub async fn mongo_database(cfg: &crate::config::MongoConfig) -> Result<mongodb::Database> {
    use mongodb::options::ClientOptions;

    let mut opts = ClientOptions::parse(&cfg.uri)
        .await
        .context("parsing the mongo uri")?;
    opts.max_pool_size = Some(cfg.max_pool_size.max(1));
    opts.min_pool_size = Some(cfg.min_pool_size);
    opts.connect_timeout = Some(Duration::from_secs(10));
    opts.server_selection_timeout = Some(Duration::from_secs(10));
    let name = if cfg.database.is_empty() {
        opts.default_database.clone().unwrap_or_default()
    } else {
        cfg.database.clone()
    };
    if name.is_empty() {
        anyhow::bail!("no mongo database: set one in the uri path or as `database`");
    }
    let client = mongodb::Client::with_options(opts).context("creating the mongo client")?;
    Ok(client.database(&name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unreachable_mysql_is_an_error() {
        let cfg = MySqlConfig { host: "127.0.0.1".into(), port: 1, database: "x".into(), ..Default::default() };
        let err = mysql_pool(&cfg).await.unwrap_err();
        assert!(err.to_string().contains("127.0.0.1:1/x"));
    }

    /// `PLATFORM_LOCAL_STACK=1` with `MODLIX__DATABASE__PASSWORD` set: the local MySQL.
    #[tokio::test]
    #[ignore]
    async fn live_local_mysql() {
        if std::env::var("PLATFORM_LOCAL_STACK").is_err() {
            return;
        }
        let cfg = MySqlConfig {
            database: "files".into(),
            password: std::env::var("MODLIX__DATABASE__PASSWORD").unwrap_or_default(),
            ..Default::default()
        };
        let pool = mysql_pool(&cfg).await.unwrap();
        let one: (i64,) = sqlx::query_as("SELECT 1").fetch_one(&pool).await.unwrap();
        assert_eq!(one.0, 1);
    }
}
