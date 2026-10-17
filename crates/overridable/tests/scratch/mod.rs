//! A scratch database for the tests that need a real MongoDB, under the crate's rules:
//!
//! - only when `OVERRIDABLE_TEST_MONGO=1` (the tests are `#[ignore]` as well);
//! - only the LOCAL MongoDB (`mongodb://localhost:27017`, or `OVERRIDABLE_TEST_MONGO_URI` if it
//!   names localhost or 127.0.0.1);
//! - only a database named `overridable_rusttest_<epoch>_<rand>`, created here and dropped when
//!   the [`Scratch`] is dropped, which happens on a failed assertion too (the drop runs while
//!   the panic unwinds, on its own thread and client);
//! - leftovers of that name older than two hours are dropped first.
#![allow(dead_code)]

use std::time::{SystemTime, UNIX_EPOCH};

use mongodb::{Client, Database};

pub const PREFIX: &str = "overridable_rusttest_";
const STALE_SECONDS: u64 = 2 * 60 * 60;

pub struct Scratch {
    pub db: Database,
    pub name: String,
    uri: String,
}

fn local_uri() -> String {
    let uri = std::env::var("OVERRIDABLE_TEST_MONGO_URI").unwrap_or_else(|_| "mongodb://localhost:27017".into());
    let host = uri.split("://").nth(1).unwrap_or("").split(['/', '?']).next().unwrap_or("");
    let host = host.rsplit('@').next().unwrap_or("");
    assert!(
        host.split(',').all(|h| h.starts_with("localhost") || h.starts_with("127.0.0.1")),
        "the gated tests only ever use the local MongoDB"
    );
    uri
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl Scratch {
    /// `None` (the test skips) unless `OVERRIDABLE_TEST_MONGO=1`.
    pub async fn new() -> Option<Scratch> {
        if std::env::var("OVERRIDABLE_TEST_MONGO").as_deref() != Ok("1") {
            eprintln!("OVERRIDABLE_TEST_MONGO=1 not set: skipped");
            return None;
        }
        let uri = local_uri();
        let client = Client::with_uri_str(&uri).await.expect("local mongo");
        sweep(&client).await;
        let name = format!("{PREFIX}{}_{:08x}", now(), rand::random::<u32>());
        Some(Scratch { db: client.database(&name), name, uri })
    }
}

/// Drops scratch databases left by runs more than two hours old.
async fn sweep(client: &Client) {
    let Ok(names) = client.list_database_names().await else { return };
    for n in names {
        let Some(rest) = n.strip_prefix(PREFIX) else { continue };
        let epoch: u64 = rest.split('_').next().and_then(|e| e.parse().ok()).unwrap_or(u64::MAX);
        if epoch != u64::MAX && now().saturating_sub(epoch) > STALE_SECONDS {
            let _ = client.database(&n).drop().await;
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let (uri, name) = (self.uri.clone(), self.name.clone());
        let dropped = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
            rt.block_on(async move {
                let client = Client::with_uri_str(&uri).await?;
                client.database(&name).drop().await
            })
        })
        .join();
        if !matches!(dropped, Ok(Ok(()))) {
            eprintln!("could not drop the scratch database {}", self.name);
        }
    }
}
