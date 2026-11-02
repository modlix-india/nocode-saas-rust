//! The admin purge against the LOCAL stack, wired as `run` wires it (`assemble`): the `core`
//! Mongo database, the core MySQL schema and both app-data engines' default servers and
//! connections.
//!
//! The only things written, purged and cleaned up are throwaway fixtures named `ZZPURGE...`
//! (authorised for this test only): Mongo databases `ZZPURGE1_zzpurgeapp`,
//! `ZZPURGE1_zzpurgeapp_draft` and `ZZPURGE10_zzpurgeapp`, the MySQL schema
//! `ZZPURGE1_zzpurgeapp`, and two marker documents in `core.function` (clients `ZZPURGE1` and
//! `ZZPURGE10`). A real purge also flushes the caches (what `DELETE /api/core/internal/cache`
//! does), which costs the running local units a cache refill and nothing else.
//!
//! Run: `eval "$(tools/local-env.py)"; CORE_LOCAL_STACK=1 cargo test -p core purge_on_the_local_stack -- --include-ignored`.

use std::panic::AssertUnwindSafe;

use futures::FutureExt;
use mongodb::bson::{doc, Document};

use super::purge::{run, Report, Target};
use crate::config::CoreConfig;
use crate::local_stack_tests::connected;
use crate::testing::local_stack;

const MONGO_DBS: [&str; 3] = ["ZZPURGE1_zzpurgeapp", "ZZPURGE1_zzpurgeapp_draft", "ZZPURGE10_zzpurgeapp"];
const MYSQL_SCHEMA: &str = "ZZPURGE1_zzpurgeapp";

async fn mongo_dbs(exec: &crate::Exec) -> Vec<String> {
    let all = exec.mongo.client().list_database_names().await.expect("list databases");
    all.into_iter().filter(|n| n.starts_with("ZZPURGE")).collect()
}

async fn mysql_schemas(exec: &crate::Exec) -> Vec<String> {
    sqlx::query_scalar("SELECT CAST(schema_name AS CHAR) FROM information_schema.schemata WHERE schema_name LIKE 'ZZPURGE%'")
        .fetch_all(&exec.pool)
        .await
        .expect("list schemas")
}

async fn markers(exec: &crate::Exec) -> Vec<String> {
    use futures::TryStreamExt;
    let found: Vec<Document> = exec.mongo.collection::<Document>("function").find(doc! {"zzpurge": true}).await.expect("find").try_collect().await.expect("collect");
    let mut v: Vec<String> = found.iter().filter_map(|d| d.get_str("clientCode").ok().map(str::to_string)).collect();
    v.sort();
    v
}

async fn seed(exec: &crate::Exec) {
    for db in MONGO_DBS {
        exec.mongo.client().database(db).collection::<Document>("zzpurge").insert_one(doc! {"v": 1}).await.expect("seed mongo");
    }
    let functions = exec.mongo.collection::<Document>("function");
    functions.insert_one(doc! {"name": "zzpurgeFn", "appCode": "zzpurgeapp", "clientCode": "ZZPURGE1", "zzpurge": true}).await.expect("seed doc");
    functions.insert_one(doc! {"name": "zzpurgeFn", "appCode": "zzpurgeapp2", "clientCode": "ZZPURGE10", "zzpurge": true}).await.expect("seed doc");
    for sql in [
        format!("CREATE DATABASE IF NOT EXISTS `{MYSQL_SCHEMA}`"),
        format!("CREATE TABLE IF NOT EXISTS `{MYSQL_SCHEMA}`.`zzpurge` (`ID` INT PRIMARY KEY)"),
        format!("INSERT IGNORE INTO `{MYSQL_SCHEMA}`.`zzpurge` VALUES (1)"),
    ] {
        sqlx::query(&sql).execute(&exec.pool).await.expect("seed mysql");
    }
}

/// Removes whatever of the fixtures is left, and nothing else.
async fn clean(exec: &crate::Exec) {
    for db in mongo_dbs(exec).await {
        let _ = exec.mongo.client().database(&db).drop().await;
    }
    let _ = exec.mongo.collection::<Document>("function").delete_many(doc! {"zzpurge": true}).await;
    for s in mysql_schemas(exec).await {
        if s.starts_with("ZZPURGE") {
            let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS `{s}`")).execute(&exec.pool).await;
        }
    }
}

fn show(what: &str, r: &Report) {
    eprintln!("{what}: {}", overridable::json::to_compact(&r.to_json()));
}

async fn scenario(exec: &crate::Exec, st: &super::routes::CoreEditor) {
    seed(exec).await;
    let client = Target::client("ZZPURGE1").unwrap();

    let dry = run(st, &client, true).await;
    show("client dry run", &dry);
    assert!(dry.dry_run);
    for db in ["ZZPURGE1_zzpurgeapp", "ZZPURGE1_zzpurgeapp_draft"] {
        assert!(dry.dropped.contains(&db.to_string()), "{db} not among {:?}", dry.dropped);
        assert!(dry.mongo.contains_key(&format!("{db}.*")), "{db} not counted");
    }
    assert!(dry.mysql.contains_key(&format!("{MYSQL_SCHEMA}.*")), "the MySQL schema was not counted");
    assert!(!dry.dropped.iter().any(|d| d.starts_with("ZZPURGE10")), "ZZPURGE1 matched ZZPURGE10's databases");
    assert_eq!(dry.mongo.get("core.function"), Some(&1));
    assert_eq!(mongo_dbs(exec).await.len(), 3, "a dry run dropped a database");
    assert_eq!(mysql_schemas(exec).await, [MYSQL_SCHEMA], "a dry run dropped the schema");
    assert_eq!(markers(exec).await, ["ZZPURGE1", "ZZPURGE10"], "a dry run deleted a document");

    let real = run(st, &client, false).await;
    show("client purge", &real);
    assert_eq!(mongo_dbs(exec).await, ["ZZPURGE10_zzpurgeapp"]);
    assert!(mysql_schemas(exec).await.is_empty(), "the client's MySQL schema outlived the purge");
    assert_eq!(markers(exec).await, ["ZZPURGE10"]);

    let app = Target::app("zzpurgeapp").unwrap();
    let dry = run(st, &app, true).await;
    show("app dry run", &dry);
    assert_eq!(dry.dropped, ["ZZPURGE10_zzpurgeapp"]);
    let real = run(st, &app, false).await;
    show("app purge", &real);
    assert!(mongo_dbs(exec).await.is_empty(), "the app's databases outlived the purge");
    assert_eq!(markers(exec).await, ["ZZPURGE10"], "the app purge took another app's document");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs the local stack: CORE_LOCAL_STACK=1 and config/local.toml"]
async fn purge_on_the_local_stack() {
    if !local_stack() {
        return;
    }
    let exec = connected().await;
    let cfg: CoreConfig = platform::config::load("core-exec").expect("config");
    let (st, _, _) = super::assemble(&cfg, &exec).expect("assemble");
    clean(&exec).await;
    let result = AssertUnwindSafe(scenario(&exec, &st)).catch_unwind().await;
    clean(&exec).await;
    if let Err(p) = result {
        std::panic::resume_unwind(p);
    }
}
