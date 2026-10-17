//! What the live test files share: the same helpers `live_mysql.rs` and `live_mongo.rs`
//! define for themselves, plus [`guarded`], which drops a test's scratch databases even
//! when the test fails.
//!
//! Every database a live test touches is named `RUSTTEST_*` (client codes `RUSTTEST`,
//! `RUSTTEST_A`, `RUSTTEST_B`, ...), is created by the test, and is dropped before and
//! after it. Nothing else on the local servers is written.

#![allow(dead_code)]

use std::collections::HashMap;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use appdata::engine::{Ctx, Hooks, PassThrough, StorageResolver};
use appdata::model::*;
use appdata::mongo::{MongoAppDataService, MongoEngineConfig};
use appdata::mysql::{MySqlAppDataService, MySqlEngineConfig};
use appdata::retention::VersionRetention;
use appdata::value::{Document, Value};
use async_trait::async_trait;
use futures::FutureExt;
use platform::cache::CacheService;
use sqlx::MySqlPool;
use tokio::sync::Mutex;

pub const CLIENT: &str = "RUSTTEST";

/// Runs `body`, then `cleanup` whether or not `body` panicked, then lets the panic go on.
pub async fn guarded<B, C>(body: B, cleanup: C)
where
    B: Future<Output = ()>,
    C: Future<Output = ()>,
{
    let outcome = AssertUnwindSafe(body).catch_unwind().await;
    cleanup.await;
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

// ------------------------------------------------------------------ values

pub fn v(s: &str) -> Value {
    Value::parse_json(s).unwrap()
}

pub fn doc(s: &str) -> Document {
    match v(s) {
        Value::Object(o) => o,
        other => panic!("not an object: {other:?}"),
    }
}

pub fn data(json: &str) -> DataObject {
    DataObject::of(doc(json))
}

pub fn query(json: &str) -> Query {
    Query::from_value(&v(json)).unwrap()
}

pub fn agg(json: &str) -> AggregateQuery {
    AggregateQuery::from_value(&v(json)).unwrap()
}

/// A SYSTEM storage of `app` whose uniqueName (the table / collection) is `<app>_<name>`
/// unless the JSON names one.
pub fn storage(app: &str, name: &str, json: &str) -> Storage {
    let mut value = v(json);
    if let Value::Object(o) = &mut value {
        o.insert("name".into(), Value::from(name));
        o.insert("appCode".into(), Value::from(app));
        o.entry("clientCode".to_string()).or_insert_with(|| Value::from("SYSTEM"));
        o.entry("uniqueName".to_string()).or_insert_with(|| Value::from(format!("{app}_{name}")));
    }
    Storage::from_value(&value).unwrap()
}

pub fn cx() -> Ctx {
    Ctx { url_client_code: Some(CLIENT.into()), user_id: Some(142), authorities: vec!["Authorities.Logged_IN".into()], draft: false }
}

pub fn cx_for(client: &str) -> Ctx {
    Ctx { url_client_code: Some(client.into()), ..cx() }
}

pub fn names(page: &Page<Document>) -> Vec<String> {
    page.content.iter().map(|r| r.get("name").map(Value::java_string).unwrap_or_default()).collect()
}

// ------------------------------------------------------------------ MySQL

/// Core's own datasource from the config server (or `APPDATA_TEST_MYSQL_*`), so no
/// credentials live in the tests.
pub async fn conn() -> Connection {
    static CREDS: tokio::sync::OnceCell<(String, String, String)> = tokio::sync::OnceCell::const_new();
    let (url, user, password) = CREDS
        .get_or_init(|| async {
            let base = std::env::var("CONFIG_SERVER").unwrap_or_else(|_| "http://localhost:8888".into());
            let config: serde_json::Value = match reqwest::get(format!("{base}/core/default")).await {
                Ok(r) => r.json().await.unwrap_or_default(),
                Err(_) => serde_json::Value::Null,
            };
            let key = |env: &str, key: &str| {
                std::env::var(env).ok().or_else(|| {
                    config["propertySources"]
                        .as_array()?
                        .iter()
                        .find_map(|ps| ps["source"][key].as_str().map(str::to_string))
                })
            };
            (
                key("APPDATA_TEST_MYSQL_URL", "core.db.url").expect("core.db.url from the config server"),
                key("APPDATA_TEST_MYSQL_USER", "core.db.username").expect("core.db.username from the config server"),
                key("APPDATA_TEST_MYSQL_PASSWORD", "core.db.password").expect("core.db.password from the config server"),
            )
        })
        .await
        .clone();
    let mut d = Document::new();
    d.insert("url".into(), Value::from(url));
    d.insert("username".into(), Value::from(user));
    d.insert("password".into(), Value::from(password));
    Connection {
        id: "rusttest-mysql".into(),
        connection_sub_type: Some(ConnectionSubType::MySql),
        connection_details: Some(d),
        ..Default::default()
    }
}

/// `StorageService.readForTenant` for the tests: a definition per client (and surface)
/// when one was put for it, otherwise the one put by name.
#[derive(Default)]
pub struct Storages {
    by_name: Mutex<HashMap<String, Storage>>,
    by_client: Mutex<HashMap<(String, String, bool), Storage>>,
}

impl Storages {
    pub async fn put(&self, s: &Storage) {
        self.by_name.lock().await.insert(s.name.clone(), s.clone());
    }

    /// What `client` resolves `s.name` to on one surface.
    pub async fn put_for(&self, client: &str, draft: bool, s: &Storage) {
        self.by_client.lock().await.insert((client.to_string(), s.name.clone(), draft), s.clone());
    }
}

#[async_trait]
impl StorageResolver for Storages {
    async fn read_for_tenant(&self, name: &str, _app: &str, client: &str, draft: bool) -> anyhow::Result<Option<Storage>> {
        if let Some(s) = self.by_client.lock().await.get(&(client.to_string(), name.to_string(), draft)) {
            return Ok(Some(s.clone()));
        }
        Ok(self.by_name.lock().await.get(name).cloned())
    }
}

pub fn mysql_hooks(storages: Arc<Storages>) -> Hooks {
    Hooks { validator: Arc::new(PassThrough), schemas: None, storages: Some(storages), authority: None }
}

pub fn mysql_engine(storages: Arc<Storages>) -> MySqlAppDataService {
    mysql_engine_with(MySqlEngineConfig { retention: VersionRetention::clamped(0, 0), ..Default::default() }, mysql_hooks(storages))
}

pub fn mysql_engine_with(config: MySqlEngineConfig, hooks: Hooks) -> MySqlAppDataService {
    let cache = CacheService::new("cmn", "evictionChannel", None).unwrap();
    MySqlAppDataService::new(config, hooks, &cache)
}

pub async fn pool(e: &MySqlAppDataService) -> MySqlPool {
    e.pool(Some(&conn().await)).await.unwrap()
}

/// The local MySQL is shared with the Java services and allows 151 connections. A live
/// suite waits while more than 120 are open rather than starve them, and gives up after
/// five minutes. The count goes to stderr (`--nocapture` shows it).
pub async fn wait_for_headroom(p: &MySqlPool) {
    const LIMIT: i64 = 120;
    for _ in 0..60 {
        let open: i64 = scalar(p, "SELECT VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME = 'Threads_connected'")
            .await
            .parse()
            .unwrap_or(0);
        if open <= LIMIT {
            eprintln!("local MySQL: {open} connections open");
            return;
        }
        eprintln!("local MySQL: {open} connections open (over {LIMIT}), waiting");
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
    panic!("the local MySQL stayed above {LIMIT} connections for five minutes");
}

/// Drops `<client>_<app>` and `<client>_<app>_draft` for each client; every one must be a
/// `RUSTTEST_*` name.
pub async fn drop_schemas(p: &MySqlPool, clients: &[&str], app: &str) {
    for client in clients {
        for s in [format!("{client}_{app}"), format!("{client}_{app}_draft")] {
            assert!(s.starts_with("RUSTTEST_"), "{s} is not a scratch schema");
            sqlx::raw_sql(&format!("DROP DATABASE IF EXISTS `{s}`")).execute(p).await.unwrap();
        }
    }
}

pub async fn create_schema(p: &MySqlPool, name: &str) {
    assert!(name.starts_with("RUSTTEST_"), "{name} is not a scratch schema");
    sqlx::raw_sql(&format!("CREATE DATABASE IF NOT EXISTS `{name}`")).execute(p).await.unwrap();
}

pub async fn exec(p: &MySqlPool, sql: &str) {
    sqlx::raw_sql(sql).execute(p).await.unwrap();
}

pub async fn scalar(p: &MySqlPool, sql: &str) -> String {
    let rows = appdata::mysql::db::fetch_raw(p, sql).await.unwrap();
    rows.first().and_then(|r| r.values().next()).map(Value::java_string).unwrap_or_default()
}

pub async fn rows(p: &MySqlPool, sql: &str) -> Vec<Document> {
    appdata::mysql::db::fetch_raw(p, sql).await.unwrap()
}

/// `COLUMN_TYPE IS_NULLABLE` of one column, e.g. `varchar(20) YES`.
pub async fn column_type(p: &MySqlPool, db: &str, table: &str, column: &str) -> String {
    scalar(
        p,
        &format!(
            "SELECT CONCAT(COLUMN_TYPE, ' ', IS_NULLABLE) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = '{db}' AND TABLE_NAME = '{table}' AND COLUMN_NAME = '{column}'"
        ),
    )
    .await
}

// ------------------------------------------------------------------ Mongo

pub fn mongo_uri() -> String {
    std::env::var("APPDATA_TEST_MONGO_URI").unwrap_or_else(|_| "mongodb://localhost:27017".into())
}

pub fn mongo_engine() -> MongoAppDataService {
    mongo_engine_with(
        MongoEngineConfig { default_uri: Some(mongo_uri()), retention: VersionRetention::clamped(0, 0), ..Default::default() },
        Hooks::default(),
    )
}

pub fn mongo_engine_with(config: MongoEngineConfig, hooks: Hooks) -> MongoAppDataService {
    let cache = CacheService::new("cmn", "evictionChannel", None).unwrap();
    MongoAppDataService::new(config, hooks, &cache)
}

pub async fn mongo_client() -> mongodb::Client {
    mongodb::Client::with_uri_str(mongo_uri()).await.unwrap()
}

/// Drops `<client>_<app>` and `<client>_<app>_draft` for each client; every one must be a
/// `RUSTTEST_*` name.
pub async fn drop_mongo_dbs(clients: &[&str], app: &str) {
    let c = mongo_client().await;
    for client in clients {
        for name in [format!("{client}_{app}"), format!("{client}_{app}_draft")] {
            assert!(name.starts_with("RUSTTEST_"), "{name} is not a scratch database");
            c.database(&name).drop().await.unwrap();
        }
    }
}

/// Drops one scratch Mongo database by its full name.
pub async fn drop_mongo_db(name: &str) {
    assert!(name.starts_with("RUSTTEST_"), "{name} is not a scratch database");
    mongo_client().await.database(name).drop().await.unwrap();
}
