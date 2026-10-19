//! Database pools from configuration.

use std::time::Duration;

use anyhow::{Context, Result};
use sqlx::mysql::{MySqlConnectOptions, MySqlPool, MySqlPoolOptions};

use crate::config::MySqlConfig;

/// A MySQL pool. Sessions run in UTC, so `TIMESTAMP` columns decode to the right instant
/// whatever zone the server is in. Its connections are on `/metrics` under its database's name
/// when the process serves metrics.
pub async fn mysql_pool(cfg: &MySqlConfig) -> Result<MySqlPool> {
    let opts = MySqlConnectOptions::new()
        .host(&cfg.host)
        .port(cfg.port)
        .database(&cfg.database)
        .username(&cfg.username)
        .password(&cfg.password)
        .timezone(Some(String::from("+00:00")));
    let pool = MySqlPoolOptions::new()
        .max_connections(cfg.max_connections.max(1))
        .min_connections(1)
        .acquire_timeout(Duration::from_secs(10))
        .connect_with(opts)
        .await
        .with_context(|| format!("connecting to mysql {}:{}/{}", cfg.host, cfg.port, cfg.database))?;
    if crate::meter::serving() {
        crate::meter::watch_mysql_pool(&cfg.database, &pool, cfg.max_connections.max(1));
    }
    Ok(pool)
}

/// A MongoDB database handle from configuration (feature `mongo`). The driver pools
/// connections itself; the handle is cheap to clone and meant to be shared. The pool's
/// connections are on `/metrics` under the database's name, counted from the driver's events.
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
    let counts = crate::meter::watch_mongo_pool(&name, cfg.max_pool_size.max(1));
    opts.cmap_event_handler = Some(mongodb::event::EventHandler::callback(move |e| count_mongo(&counts, &e)));
    let client = mongodb::Client::with_options(opts).context("creating the mongo client")?;
    Ok(client.database(&name))
}

/// A pool event as connection counts. A connection that fails while checked out is checked in
/// before it is closed, so the two counts stay in step.
#[cfg(feature = "mongo")]
fn count_mongo(counts: &crate::meter::PoolCounts, e: &mongodb::event::cmap::CmapEvent) {
    use mongodb::event::cmap::CmapEvent;
    match e {
        CmapEvent::ConnectionCreated(_) => counts.opened(),
        CmapEvent::ConnectionClosed(_) => counts.closed(),
        CmapEvent::ConnectionCheckedOut(_) => counts.checked_out(),
        CmapEvent::ConnectionCheckedIn(_) => counts.checked_in(),
        _ => {}
    }
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

    /// The local MongoDB (no credentials): a ping opens, checks out and checks in a connection,
    /// and the pool counts follow. Passes without counting when nothing listens there.
    #[cfg(feature = "mongo")]
    #[tokio::test]
    async fn mongo_pool_counts_follow_the_driver() {
        use mongodb::bson::doc;
        let cfg = crate::config::MongoConfig {
            uri: "mongodb://127.0.0.1:27017/?serverSelectionTimeoutMS=1500&connectTimeoutMS=1500".into(),
            database: "db-test-metrics".into(),
            ..Default::default()
        };
        let db = mongo_database(&cfg).await.unwrap();
        if db.run_command(doc! {"ping": 1}).await.is_err() {
            return;
        }
        // The driver checks a connection back in, and says so, just after the answer arrives.
        let open = |text: &str, state: &str| crate::meter::sample(text, crate::meter::DB_CONNECTIONS, &[("pool", "db-test-metrics"), ("state", state)]);
        let mut text = String::new();
        for _ in 0..100 {
            text = crate::meter::capture(crate::meter::collect).1;
            if open(&text, "used") == Some(0.0) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(open(&text, "used"), Some(0.0));
        assert!(open(&text, "idle").is_some_and(|n| n >= 1.0), "{text}");
        let missing = crate::config::MongoConfig { uri: "mongodb://127.0.0.1:27017/".into(), ..Default::default() };
        assert!(mongo_database(&missing).await.is_err(), "no database named");
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
