//! The transaction scope (`appdata::mysql::tx`), row locks and named counters that
//! `CoreServices.Storage.Batch` / `UpdateIf` / `NextSequence` stand on, against the local
//! MySQL and Mongo in scratch databases `RUSTTEST_rtx*` that each test creates and drops.
//!
//! Run with: cargo test -p appdata --test live_storage_tx -- --ignored --test-threads=1
//! (MySQL credentials from the config server, or APPDATA_TEST_MYSQL_URL / _USER / _PASSWORD.)

mod support;

use std::sync::Arc;

use appdata::engine::AppDataEngine;
use appdata::error::AppDataError;
use appdata::model::*;
use appdata::mysql::tx;
use appdata::value::Value;
use support::*;

const APP: &str = "rtxapp";

fn rows_storage() -> Storage {
    storage(
        APP,
        "rows",
        r#"{"version":1,"schema":{"type":"OBJECT","properties":{"name":{"type":"STRING","maxLength":40},"status":{"type":"STRING","maxLength":20},"n":{"type":"INTEGER"}}}}"#,
    )
}

async fn count_rows(e: &appdata::mysql::MySqlAppDataService, c: &Connection, s: &Storage) -> i64 {
    e.read_page(&cx(), CLIENT, Some(c), s, &query(r#"{"page":0,"size":100,"count":true}"#)).await.unwrap().total
}

#[tokio::test]
#[ignore = "needs the local MySQL"]
async fn mysql_scope_rolls_back_every_write_when_one_fails() {
    let storages = Arc::new(Storages::default());
    let e = mysql_engine(storages.clone());
    let p = pool(&e).await;
    wait_for_headroom(&p).await;
    drop_schemas(&p, &[CLIENT], APP).await;
    guarded(
        async {
            let s = rows_storage();
            storages.put(&s).await;
            let c = conn().await;
            // The table exists before the scope, as it would after the app's first write.
            let seed = e.create(&cx(), CLIENT, Some(&c), &s, data(r#"{"name":"seed","status":"AVAILABLE","n":1}"#)).await.unwrap();
            let seed_id = seed.get("_id").unwrap().java_string();

            let r: Result<(), AppDataError> = tx::scope(async {
                e.create(&cx(), CLIENT, Some(&c), &s, data(r#"{"name":"a","n":2}"#)).await?;
                let mut patch = doc(r#"{"status":"SOLD"}"#);
                patch.insert("_id".into(), Value::String(seed_id.clone()));
                e.update(&cx(), CLIENT, Some(&c), &s, DataObject::of(patch), Some(false)).await?;
                // Inside the scope the writes are visible to the same task.
                assert_eq!(count_rows(&e, &c, &s).await, 2);
                Err(AppDataError::illegal_argument("third operation fails"))
            })
            .await;
            assert!(r.is_err());
            assert_eq!(count_rows(&e, &c, &s).await, 1, "the create was rolled back");
            let back = e.read(&cx(), CLIENT, Some(&c), &s, &seed_id).await.unwrap();
            assert_eq!(back.get("status").map(Value::java_string).as_deref(), Some("AVAILABLE"), "the update was rolled back");

            let ok: Result<(), AppDataError> = tx::scope(async {
                e.create(&cx(), CLIENT, Some(&c), &s, data(r#"{"name":"b","n":3}"#)).await?;
                e.create(&cx(), CLIENT, Some(&c), &s, data(r#"{"name":"c","n":4}"#)).await?;
                Ok(())
            })
            .await;
            ok.unwrap();
            assert_eq!(count_rows(&e, &c, &s).await, 3, "a successful scope commits");
        },
        drop_schemas(&p, &[CLIENT], APP),
    )
    .await;
}

#[tokio::test]
#[ignore = "needs the local MySQL"]
async fn mysql_lock_row_serialises_compare_and_set() {
    let storages = Arc::new(Storages::default());
    let e = Arc::new(mysql_engine(storages.clone()));
    let p = pool(&e).await;
    wait_for_headroom(&p).await;
    drop_schemas(&p, &[CLIENT], APP).await;
    guarded(
        async {
            let s = rows_storage();
            storages.put(&s).await;
            let c = conn().await;
            let unit = e.create(&cx(), CLIENT, Some(&c), &s, data(r#"{"name":"A-1203","status":"AVAILABLE","n":0}"#)).await.unwrap();
            let id = unit.get("_id").unwrap().java_string();

            // Twenty tasks try to block the same unit; exactly one may win.
            let mut handles = Vec::new();
            for i in 0..20 {
                let (e, s, c, id) = (e.clone(), s.clone(), c.clone(), id.clone());
                handles.push(tokio::spawn(async move {
                    tx::scope(async {
                        let row = e.lock_row(&cx(), CLIENT, Some(&c), &s, &id).await?.expect("row");
                        if row.get("status").map(Value::java_string).as_deref() != Some("AVAILABLE") {
                            return Ok::<bool, AppDataError>(false);
                        }
                        let mut patch = doc(&format!(r#"{{"status":"BLOCKED","n":{i}}}"#));
                        patch.insert("_id".into(), Value::String(id.clone()));
                        e.update(&cx(), CLIENT, Some(&c), &s, DataObject::of(patch), Some(false)).await?;
                        Ok(true)
                    })
                    .await
                    .unwrap()
                }));
            }
            let mut wins = 0;
            for h in handles {
                if h.await.unwrap() {
                    wins += 1;
                }
            }
            assert_eq!(wins, 1, "only one compare-and-set may succeed");
        },
        drop_schemas(&p, &[CLIENT], APP),
    )
    .await;
}

#[tokio::test]
#[ignore = "needs the local MySQL"]
async fn mysql_sequence_is_unique_under_concurrency_and_rolls_back_with_its_scope() {
    let storages = Arc::new(Storages::default());
    let e = Arc::new(mysql_engine(storages.clone()));
    let p = pool(&e).await;
    wait_for_headroom(&p).await;
    drop_schemas(&p, &[CLIENT], APP).await;
    guarded(
        async {
            let s = rows_storage();
            storages.put(&s).await;
            let c = conn().await;
            assert_eq!(e.next_sequence(&cx(), CLIENT, Some(&c), &s, "receipt", 1001).await.unwrap(), 1001);

            let mut handles = Vec::new();
            for _ in 0..200 {
                let (e, s, c) = (e.clone(), s.clone(), c.clone());
                handles.push(tokio::spawn(async move { e.next_sequence(&cx(), CLIENT, Some(&c), &s, "receipt", 1001).await.unwrap() }));
            }
            let mut got: Vec<i64> = Vec::new();
            for h in handles {
                got.push(h.await.unwrap());
            }
            got.sort();
            got.dedup();
            assert_eq!(got.len(), 200, "every caller got its own number");
            assert_eq!((got[0], got[199]), (1002, 1201), "no gaps");

            // A number taken inside a scope that fails is given back.
            let r: Result<i64, AppDataError> = tx::scope(async {
                let n = e.next_sequence(&cx(), CLIENT, Some(&c), &s, "receipt", 1001).await?;
                assert_eq!(n, 1202);
                Err(AppDataError::illegal_argument("batch fails"))
            })
            .await;
            assert!(r.is_err());
            assert_eq!(e.next_sequence(&cx(), CLIENT, Some(&c), &s, "receipt", 1001).await.unwrap(), 1202);
            // Keys are independent counters.
            assert_eq!(e.next_sequence(&cx(), CLIENT, Some(&c), &s, "case", 1).await.unwrap(), 1);
        },
        drop_schemas(&p, &[CLIENT], APP),
    )
    .await;
}

#[tokio::test]
#[ignore = "needs the local Mongo"]
async fn mongo_sequence_is_unique_under_concurrency() {
    let e = Arc::new(mongo_engine());
    drop_mongo_dbs(&[CLIENT], APP).await;
    guarded(
        async {
            let s = rows_storage();
            assert!(!e.transactional(None).await, "a standalone Mongo batch is not atomic");
            let mut handles = Vec::new();
            for _ in 0..200 {
                let (e, s) = (e.clone(), s.clone());
                handles.push(tokio::spawn(async move { e.next_sequence(&cx(), CLIENT, None, &s, "receipt", 1).await.unwrap() }));
            }
            let mut got: Vec<i64> = Vec::new();
            for h in handles {
                got.push(h.await.unwrap());
            }
            got.sort();
            got.dedup();
            assert_eq!(got.len(), 200);
            assert_eq!((got[0], got[199]), (1, 200));
        },
        drop_mongo_dbs(&[CLIENT], APP),
    )
    .await;
}

#[tokio::test]
#[ignore = "needs the local MySQL"]
async fn mysql_prepared_tables_can_be_first_written_inside_one_transaction() {
    // Error 1412: a table created (on the pool) after a transaction began cannot be used inside it.
    // `prepare` creates the tables first, which is what CoreServices.Storage.Batch does.
    let storages = Arc::new(Storages::default());
    let e = mysql_engine(storages.clone());
    let p = pool(&e).await;
    wait_for_headroom(&p).await;
    drop_schemas(&p, &[CLIENT], APP).await;
    guarded(
        async {
            let a = storage(APP, "fresh_a", r#"{"version":1,"schema":{"type":"OBJECT","properties":{"name":{"type":"STRING","maxLength":20}}}}"#);
            let b = storage(APP, "fresh_b", r#"{"version":1,"schema":{"type":"OBJECT","properties":{"name":{"type":"STRING","maxLength":20}}}}"#);
            storages.put(&a).await;
            storages.put(&b).await;
            let c = conn().await;
            e.prepare(&cx(), CLIENT, Some(&c), &a).await.unwrap();
            e.prepare(&cx(), CLIENT, Some(&c), &b).await.unwrap();
            let r: Result<(), AppDataError> = tx::scope(async {
                e.create(&cx(), CLIENT, Some(&c), &a, data(r#"{"name":"one"}"#)).await?;
                e.create(&cx(), CLIENT, Some(&c), &b, data(r#"{"name":"two"}"#)).await?;
                e.next_sequence(&cx(), CLIENT, Some(&c), &b, "k", 1).await?;
                Ok(())
            })
            .await;
            r.unwrap();
            assert_eq!(count_rows(&e, &c, &b).await, 1);
        },
        drop_schemas(&p, &[CLIENT], APP),
    )
    .await;
}

#[tokio::test]
#[ignore = "needs the local MySQL"]
async fn mysql_history_trim_inside_a_scope_does_not_wait_on_its_own_locks() {
    // The version-history trim ran on a pool connection while the scope held the row's fresh version
    // row: the DELETE waited on the transaction's own lock until innodb_lock_wait_timeout (50 s), seen as
    // a 504 on a cxzump cancellation that touched a much-updated schedule entry. It now runs in the scope.
    let storages = Arc::new(Storages::default());
    let e = mysql_engine(storages.clone());
    let p = pool(&e).await;
    wait_for_headroom(&p).await;
    drop_schemas(&p, &[CLIENT], APP).await;
    guarded(
        async {
            let s = storage(
                APP,
                "audited_rows",
                r#"{"version":1,"isAudited":true,"versionRetentionDays":30,"schema":{"type":"OBJECT","properties":{"name":{"type":"STRING","maxLength":40},"n":{"type":"INTEGER"}}}}"#,
            );
            storages.put(&s).await;
            let c = conn().await;
            // Two rows: ids are ULIDs, so `first` sorts before `second` in the (objectId, createdAt) index.
            // The trim for `first` scans to the end of its range and needs the next index record, which is
            // `second`'s version row written moments earlier in the same scope.
            let first = e.create(&cx(), CLIENT, Some(&c), &s, data(r#"{"name":"first","n":0}"#)).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            let second = e.create(&cx(), CLIENT, Some(&c), &s, data(r#"{"name":"second","n":0}"#)).await.unwrap();
            let id = first.get("_id").unwrap().java_string();
            let id2 = second.get("_id").unwrap().java_string();
            e.prepare(&cx(), CLIENT, Some(&c), &s).await.unwrap();
            let started = std::time::Instant::now();
            let r: Result<(), AppDataError> = tokio::time::timeout(std::time::Duration::from_secs(20), tx::scope(async {
                for n in 1..=3 {
                    for target in [&id2, &id] {
                        let mut patch = doc(&format!(r#"{{"n":{n}}}"#));
                        patch.insert("_id".into(), Value::String(target.clone()));
                        e.update(&cx(), CLIENT, Some(&c), &s, DataObject::of(patch), Some(false)).await?;
                    }
                }
                Ok(())
            }))
            .await
            .expect("the scope must not hang on its own history trim");
            r.unwrap();
            assert!(started.elapsed().as_secs() < 10, "took {:?}", started.elapsed());
            let back = e.read(&cx(), CLIENT, Some(&c), &s, &id).await.unwrap();
            assert_eq!(back.get("n").map(Value::java_string).as_deref(), Some("3"));
        },
        drop_schemas(&p, &[CLIENT], APP),
    )
    .await;
}

/// A storage holding a claim key: nullable, under a unique index (the `cxCallBooking` shape).
fn claims_storage() -> Storage {
    storage(
        APP,
        "claims",
        r#"{"version":1,"schema":{"type":"OBJECT","properties":{"name":{"type":"STRING","maxLength":40},"claimKey":{"type":"STRING","maxLength":200}}},
            "indexes":{"claimKey_unique":{"fields":[{"fieldName":"claimKey"}],"unique":true}}}"#,
    )
}

#[tokio::test]
#[ignore = "needs the local MySQL"]
async fn mysql_duplicate_key_is_a_409_naming_the_index_and_rolls_back_its_scope() {
    let storages = Arc::new(Storages::default());
    let e = mysql_engine(storages.clone());
    let p = pool(&e).await;
    wait_for_headroom(&p).await;
    drop_schemas(&p, &[CLIENT], APP).await;
    guarded(
        async {
            let s = claims_storage();
            storages.put(&s).await;
            let c = conn().await;
            e.create(&cx(), CLIENT, Some(&c), &s, data(r#"{"name":"first","claimKey":"P1|10:00|1"}"#)).await.unwrap();
            // Many rows may leave the claim empty (MySQL allows many NULLs under a unique index).
            e.create(&cx(), CLIENT, Some(&c), &s, data(r#"{"name":"free1"}"#)).await.unwrap();
            e.create(&cx(), CLIENT, Some(&c), &s, data(r#"{"name":"free2","claimKey":null}"#)).await.unwrap();

            let dup = e.create(&cx(), CLIENT, Some(&c), &s, data(r#"{"name":"second","claimKey":"P1|10:00|1"}"#)).await.unwrap_err();
            assert!(dup.is_duplicate_key(), "{dup:?}");
            assert_eq!(dup.status(), http::StatusCode::CONFLICT);
            let code = dup.code().unwrap();
            assert!(code.params.contains(&("index".to_string(), "claimKey_unique".to_string())), "{:?}", code.params);
            assert!(code.params.contains(&("storage".to_string(), "claims".to_string())), "{:?}", code.params);
            assert!(!dup.message().contains("P1|10:00|1"), "the value stays out of the text");
            assert!(appdata::mysql::db::is_integrity_violation(&dup));

            // Inside a scope the earlier write goes with the refused one.
            let r: Result<(), AppDataError> = tx::scope(async {
                e.create(&cx(), CLIENT, Some(&c), &s, data(r#"{"name":"inside","claimKey":"P1|10:00|2"}"#)).await?;
                e.create(&cx(), CLIENT, Some(&c), &s, data(r#"{"name":"clash","claimKey":"P1|10:00|1"}"#)).await?;
                Ok(())
            })
            .await;
            assert!(r.unwrap_err().is_duplicate_key());
            assert_eq!(count_rows(&e, &c, &s).await, 3);

            // An update onto a held claim is refused the same way.
            let free = e.create(&cx(), CLIENT, Some(&c), &s, data(r#"{"name":"mover"}"#)).await.unwrap();
            let mut patch = doc(r#"{"claimKey":"P1|10:00|1"}"#);
            patch.insert("_id".into(), free.get("_id").unwrap().clone());
            let upd = e.update(&cx(), CLIENT, Some(&c), &s, DataObject::of(patch), Some(false)).await.unwrap_err();
            assert!(upd.is_duplicate_key(), "{upd:?}");
        },
        drop_schemas(&p, &[CLIENT], APP),
    )
    .await;
}

#[tokio::test]
#[ignore = "needs the local Mongo"]
async fn mongo_duplicate_key_is_a_409_naming_the_index() {
    let e = Arc::new(mongo_engine());
    drop_mongo_dbs(&[CLIENT], APP).await;
    guarded(
        async {
            let s = claims_storage();
            e.create(&cx(), CLIENT, None, &s, data(r#"{"name":"first","claimKey":"P1|10:00|1"}"#)).await.unwrap();
            let dup = e.create(&cx(), CLIENT, None, &s, data(r#"{"name":"second","claimKey":"P1|10:00|1"}"#)).await.unwrap_err();
            assert!(dup.is_duplicate_key(), "{dup:?}");
            let code = dup.code().unwrap();
            assert!(code.params.contains(&("index".to_string(), "claimKey_unique".to_string())), "{:?}", code.params);
            assert!(code.params.contains(&("storage".to_string(), "claims".to_string())), "{:?}", code.params);
        },
        drop_mongo_dbs(&[CLIENT], APP),
    )
    .await;
}
