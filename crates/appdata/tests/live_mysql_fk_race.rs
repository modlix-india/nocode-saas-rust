//! The first use of a storage with a foreign key in a brand-new tenant schema, by several
//! engines at once (as core-exec and core-editor, or two requests, would): every read
//! succeeds and the table ends with one copy of each key and index. Once with the per-table
//! DDL lock as the engines take it, and once with the lock held elsewhere so that they all go
//! on without it at the same moment and must tolerate "1826 Duplicate foreign key constraint
//! name" and its kin.
//!
//! Scratch schemas only: `zz_fkrace_*`, created by the test and dropped before and after it.
//!
//! Run with: cargo test -p appdata --test live_mysql_fk_race -- --ignored --test-threads=1
//! (MySQL credentials from the config server, or APPDATA_TEST_MYSQL_URL / _USER / _PASSWORD.)

mod support;

use std::sync::Arc;

use appdata::engine::AppDataEngine;
use appdata::model::*;
use appdata::mysql::db;
use appdata::mysql::MySqlAppDataService;
use sqlx::MySqlPool;
use support::*;

const CLIENT: &str = "zz";
const ENGINES: usize = 6;

fn units(app: &str) -> Storage {
    storage(
        app,
        "cxUnit",
        r#"{"version":1,"uniqueName":"cxUnit",
            "indexes":{"byCode":{"fields":[{"fieldName":"code","direction":"ASC"}],"unique":true}},
            "schema":{"type":"OBJECT","properties":{"code":{"type":"STRING","maxLength":40},"name":{"type":"STRING","maxLength":80}}}}"#,
    )
}

fn payments(app: &str) -> Storage {
    storage(
        app,
        "cxPayment",
        r#"{"version":1,"uniqueName":"cxPayment",
            "relations":{"unit":{"storageName":"cxUnit","relationType":"TO_ONE","fieldName":"_id","deleteConstraint":"RESTRICT"}},
            "indexes":{"byRef":{"fields":[{"fieldName":"ref","direction":"ASC"}],"unique":false}},
            "schema":{"type":"OBJECT","properties":{"ref":{"type":"STRING","maxLength":40},"amount":{"type":"DOUBLE"}}}}"#,
    )
}

async fn drop_scratch(p: &MySqlPool, db_name: &str) {
    assert!(db_name.starts_with("zz_fkrace_"), "{db_name} is not a scratch schema");
    exec(p, &format!("DROP DATABASE IF EXISTS `{db_name}`")).await;
}

async fn count(p: &MySqlPool, sql: &str) -> i64 {
    scalar(p, sql).await.parse().unwrap_or(-1)
}

/// `ENGINES` engines, each with its own caches (as separate units have), read both storages
/// for the first time at once.
async fn first_reads_at_once(app: &str, storages: Arc<Storages>) -> Vec<String> {
    let c = conn().await;
    let engines: Vec<Arc<MySqlAppDataService>> = (0..ENGINES).map(|_| Arc::new(mysql_engine(storages.clone()))).collect();
    let mut tasks = Vec::new();
    for (i, engine) in engines.iter().enumerate() {
        // Every engine reads the referencing storage (the path that adds the key), and every
        // other one the referenced storage as well.
        let mut reads = vec![payments(app)];
        if i % 2 == 1 {
            reads.push(units(app));
        }
        for s in reads {
            let (e, c) = (engine.clone(), c.clone());
            tasks.push(tokio::spawn(async move {
                e.read_page(&cx_for(CLIENT), CLIENT, Some(&c), &s, &query(r#"{"page":0,"size":5,"count":true}"#)).await.map(|_| ()).map_err(|e| e.to_string())
            }));
        }
    }
    let mut errors = Vec::new();
    for t in tasks {
        if let Err(e) = t.await.unwrap() {
            errors.push(e);
        }
    }
    errors
}

async fn assert_one_of_each(p: &MySqlPool, db_name: &str) {
    let keys = count(
        p,
        &format!("SELECT COUNT(*) FROM information_schema.REFERENTIAL_CONSTRAINTS WHERE CONSTRAINT_SCHEMA = '{db_name}' AND TABLE_NAME = 'cxPayment'"),
    )
    .await;
    assert_eq!(keys, 1, "one foreign key on cxPayment");
    let on = scalar(
        p,
        &format!("SELECT REFERENCED_TABLE_NAME FROM information_schema.REFERENTIAL_CONSTRAINTS WHERE CONSTRAINT_SCHEMA = '{db_name}' AND TABLE_NAME = 'cxPayment'"),
    )
    .await;
    assert_eq!(on, "cxUnit");
    for (table, index) in [("cxUnit", "code"), ("cxPayment", "ref")] {
        let n = count(
            p,
            &format!(
                "SELECT COUNT(DISTINCT INDEX_NAME) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = '{db_name}' AND TABLE_NAME = '{table}' AND COLUMN_NAME = '{index}'"
            ),
        )
        .await;
        assert_eq!(n, 1, "one index on {table}.{index}");
    }
}

#[tokio::test]
#[ignore = "needs the local MySQL"]
async fn first_reads_at_once_with_the_ddl_lock() {
    let app = "fkrace_lock";
    let db_name = format!("{CLIENT}_{app}");
    let storages = Arc::new(Storages::default());
    storages.put(&units(app)).await;
    storages.put(&payments(app)).await;
    let p = pool(&mysql_engine(storages.clone())).await;
    wait_for_headroom(&p).await;
    drop_scratch(&p, &db_name).await;
    guarded(
        async {
            let errors = first_reads_at_once(app, storages.clone()).await;
            assert!(errors.is_empty(), "{errors:?}");
            assert_one_of_each(&p, &db_name).await;
        },
        drop_scratch(&p, &db_name),
    )
    .await;
}

/// The test holds both tables' DDL locks, so every engine waits them out and then provisions
/// unguarded, all at once: the losers of each ADD CONSTRAINT / CREATE INDEX read the table again
/// and find the key in place.
#[tokio::test]
#[ignore = "needs the local MySQL"]
async fn first_reads_at_once_without_the_lock_tolerate_the_race() {
    let app = "fkrace_nolock";
    let db_name = format!("{CLIENT}_{app}");
    let storages = Arc::new(Storages::default());
    storages.put(&units(app)).await;
    storages.put(&payments(app)).await;
    let p = pool(&mysql_engine(storages.clone())).await;
    wait_for_headroom(&p).await;
    drop_scratch(&p, &db_name).await;
    guarded(
        async {
            let mut held = Vec::new();
            for t in ["cxUnit", "cxPayment"] {
                held.push(db::NamedLock::take(&p, &db::ddl_lock_name(&db_name, t), 5).await.expect("the test takes the DDL lock"));
            }
            let errors = first_reads_at_once(app, storages.clone()).await;
            for l in held {
                l.release().await;
            }
            assert!(errors.is_empty(), "{errors:?}");
            assert_one_of_each(&p, &db_name).await;
        },
        drop_scratch(&p, &db_name),
    )
    .await;
}
