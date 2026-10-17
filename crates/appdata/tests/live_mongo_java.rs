//! Java's Mongo integration tests (core, integration), their engine parts ported against the
//! local MongoDB: `MongoFilterConditionIntegrationTest`, `DraftDataNamespaceIntegrationTest`
//! and `AppDataSurfaceIntegrationTest`. Then the draft-copy engine methods nocode-saas added
//! in aca9929dd (`clearDraftRows`, the filtered `copyLiveToDraft`), which came with no Java
//! tests: those are written from the Java code. `mod extra` is not a Java port.
//!
//! Every database is a scratch one, `RUSTTEST_*` with an app code starting `mgj_`, dropped
//! before and after each test.
//!
//! Run with: cargo test -p appdata --test live_mongo_java -- --include-ignored --test-threads=1
//! (APPDATA_TEST_MONGO_URI overrides mongodb://localhost:27017.)

mod support;

use std::collections::HashMap;
use std::time::Duration;

use appdata::engine::{AppDataEngine, Ctx};
use appdata::error::AppDataResult;
use appdata::model::*;
use appdata::mongo::{MongoAppDataService, MongoEngineConfig};
use appdata::retention::VersionRetention;
use appdata::value::Value;
use futures::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, Bson, DateTime, Document as BsonDocument};
use support::*;

fn live_db(app: &str) -> String {
    format!("{CLIENT}_{app}")
}

fn draft_db(app: &str) -> String {
    format!("{CLIENT}_{app}_draft")
}

fn draft() -> Ctx {
    cx().on_draft(true)
}

/// Every document of one collection, read straight from Mongo: where the bytes landed is
/// the claim, so going back through the engine would prove nothing.
async fn raw(db: &str, coll: &str) -> Vec<BsonDocument> {
    mongo_client().await.database(db).collection::<BsonDocument>(coll).find(doc! {}).await.unwrap().try_collect().await.unwrap()
}

async fn collections(db: &str) -> Vec<String> {
    mongo_client().await.database(db).list_collection_names().await.unwrap()
}

async fn databases() -> Vec<String> {
    mongo_client().await.list_database_names().await.unwrap()
}

/// Rows written past the engine, into a scratch database only.
async fn insert_raw(db: &str, coll: &str, docs: Vec<BsonDocument>) {
    assert!(db.starts_with("RUSTTEST_"), "{db} is not a scratch database");
    mongo_client().await.database(db).collection::<BsonDocument>(coll).insert_many(docs).await.unwrap();
}

/// A created row's id.
async fn add(e: &MongoAppDataService, c: &Ctx, s: &Storage, json: &str) -> String {
    e.create(c, CLIENT, None, s, data(json)).await.unwrap()["_id"].java_string()
}

/// The names on one surface, sorted by name.
async fn names_on(e: &MongoAppDataService, c: &Ctx, s: &Storage) -> Vec<String> {
    names(&e.read_page(c, CLIENT, None, s, &query(r#"{"size":200,"sort":{"property":"name"}}"#)).await.unwrap())
}

fn oid(hex: &str) -> ObjectId {
    ObjectId::parse_str(hex).unwrap()
}

fn sorted_ids(docs: &[BsonDocument]) -> Vec<ObjectId> {
    let mut ids: Vec<ObjectId> = docs.iter().map(|d| d.get_object_id("_id").unwrap()).collect();
    ids.sort_by_key(|o| o.to_hex());
    ids
}

fn cond(json: &str) -> Condition {
    Condition::from_value(&v(json)).unwrap().unwrap()
}

// ====================================================================== Java ports

/// `MongoFilterConditionIntegrationTest`: filters asserted on the ROWS they return, one
/// Rust test per nested group, each seeded as the Java `setUp` seeds every method.
mod mongo_filter_condition_integration_test {
    use super::*;

    const APP: &str = "mgj_filter";

    /// `givenStorage` and the five rows `setUp` writes.
    async fn seeded(e: &MongoAppDataService) -> Storage {
        let s = storage(
            APP,
            "filterlab",
            r#"{"uniqueName":"testapp_filterlab","isAudited":false,"schema":{"type":"OBJECT","properties":{
                "name":{"type":"STRING","maxLength":60},"amount":{"type":"INTEGER"},"phone":{"type":"STRING","maxLength":40}}}}"#,
        );
        let rows = [
            ("alpha", 5, "+91 98000 11111"),
            ("bravo", 15, "+91 98000 22222"),
            ("charlie", 25, "(080) 4000-1234"),
            ("delta", 35, "50% off line"),
            ("echo", 45, "plain12345"),
        ];
        for (name, amount, phone) in rows {
            add(e, &cx(), &s, &format!(r#"{{"name":"{name}","amount":{amount},"phone":"{phone}"}}"#)).await;
        }
        s
    }

    /// `names(condition)`: the names a condition selects, sorted, so it reads as a set.
    async fn select(e: &MongoAppDataService, s: &Storage, condition: &str) -> AppDataResult<Vec<String>> {
        let page = e.read_page(&cx(), CLIENT, None, s, &query(&format!(r#"{{"condition":{condition},"size":50}}"#))).await?;
        let mut n = names(&page);
        n.sort();
        Ok(n)
    }

    async fn refused(e: &MongoAppDataService, s: &Storage, condition: &str) {
        let err = select(e, s, condition).await.unwrap_err();
        assert_eq!(err.status().as_u16(), 400, "{condition}: {}", err.message());
    }

    fn range(from: i64, to: &str) -> String {
        format!(r#"{{"field":"amount","operator":"BETWEEN","value":{from},"toValue":{to}}}"#)
    }

    fn in_(value: &str) -> String {
        format!(r#"{{"field":"name","operator":"IN","value":"{value}"}}"#)
    }

    fn loose(value: &str) -> String {
        format!(r#"{{"field":"phone","operator":"STRING_LOOSE_EQUAL","value":"{value}"}}"#)
    }

    #[tokio::test]
    #[ignore = "needs the local MongoDB"]
    async fn between() {
        drop_mongo_dbs(&[CLIENT], APP).await;
        guarded(
            async {
                let e = mongo_engine();
                let s = seeded(&e).await;
                // inRange: selects the rows inside the range.
                assert_eq!(select(&e, &s, &range(10, "30")).await.unwrap(), ["bravo", "charlie"]);
                // negated: selects the rows outside it.
                let negated = range(10, "30").replacen('{', r#"{"negate":true,"#, 1);
                assert_eq!(select(&e, &s, &negated).await.unwrap(), ["alpha", "delta", "echo"]);
                // inclusive: the bounds are inclusive at both ends.
                assert_eq!(select(&e, &s, &range(5, "15")).await.unwrap(), ["alpha", "bravo"]);
                // missingToValue: refused, not read as an open range.
                refused(&e, &s, &range(10, "null")).await;
            },
            drop_mongo_dbs(&[CLIENT], APP),
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "needs the local MongoDB"]
    async fn in_list() {
        drop_mongo_dbs(&[CLIENT], APP).await;
        guarded(
            async {
                let e = mongo_engine();
                let s = seeded(&e).await;
                // keepsTheTail
                assert_eq!(select(&e, &s, &in_("alpha,bravo,charlie")).await.unwrap(), ["alpha", "bravo", "charlie"]);
                // singleValue: a list of one, not an empty list.
                assert_eq!(select(&e, &s, &in_("alpha")).await.unwrap(), ["alpha"]);
                // trimsAndSkipsBlanks
                assert_eq!(select(&e, &s, &in_(" alpha , ,bravo ")).await.unwrap(), ["alpha", "bravo"]);
                // emptyListRefused
                refused(&e, &s, &in_(" , , ")).await;
                refused(&e, &s, &in_("")).await;
                // emptyListNegatedRefused
                refused(&e, &s, &in_(" , , ").replacen('{', r#"{"negate":true,"#, 1)).await;
                // multiValueStillWorks
                let multi = r#"{"field":"name","operator":"IN","multiValue":["alpha","bravo"]}"#;
                assert_eq!(select(&e, &s, multi).await.unwrap(), ["alpha", "bravo"]);
                // idsAsCommaSeparated: a comma separated list of ids on _id works.
                let all = e.read_page(&cx(), CLIENT, None, &s, &query(r#"{"size":50}"#)).await.unwrap().content;
                let ids = format!("{},{}", all[0]["_id"].java_string(), all[1]["_id"].java_string());
                let by_id = format!(r#"{{"field":"_id","operator":"IN","value":"{ids}"}}"#);
                assert_eq!(select(&e, &s, &by_id).await.unwrap().len(), 2);
            },
            drop_mongo_dbs(&[CLIENT], APP),
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "needs the local MongoDB"]
    async fn loose_equal() {
        drop_mongo_dbs(&[CLIENT], APP).await;
        guarded(
            async {
                let e = mongo_engine();
                let s = seeded(&e).await;
                // plusIsLiteral: a leading + is text, not a quantifier.
                assert_eq!(select(&e, &s, &loose("+91")).await.unwrap(), ["alpha", "bravo"]);
                // bracketsAreLiteral
                assert_eq!(select(&e, &s, &loose("(080)")).await.unwrap(), ["charlie"]);
                assert!(select(&e, &s, &loose("(080) 4000")).await.unwrap().contains(&"charlie".to_string()));
                // stillContains
                assert_eq!(select(&e, &s, &loose("50%")).await.unwrap(), ["delta"]);
                assert_eq!(select(&e, &s, &loose("123")).await.unwrap(), ["charlie", "echo"]);
                // caseInsensitive
                assert_eq!(select(&e, &s, &loose("OFF LINE")).await.unwrap(), ["delta"]);
            },
            drop_mongo_dbs(&[CLIENT], APP),
        )
        .await;
    }
}

/// `DraftDataNamespaceIntegrationTest`, the engine parts. `deletingStorageDropsDraftOnly`
/// and `deletingAppDropsDraftDatabaseOnly` call the engine methods `StorageService.delete`
/// and `DeletionService.deleteEverything` reach (`drop_draft_storage`,
/// `drop_draft_database`); the services themselves are not in this crate.
mod draft_data_namespace_integration_test {
    use super::*;

    const APP: &str = "mgj_ns";
    const UNIQUE_NAME: &str = "testapp_system_teststorage";

    /// `storedStorage`.
    fn stored() -> Storage {
        storage(
            APP,
            "testStorage",
            &format!(r#"{{"uniqueName":"{UNIQUE_NAME}","schema":{{"name":"TestStorage","type":"OBJECT","properties":{{"title":{{"type":"STRING"}}}}}}}}"#),
        )
    }

    async fn row(e: &MongoAppDataService, c: &Ctx, title: &str) {
        e.create(c, CLIENT, None, &stored(), data(&format!(r#"{{"title":"{title}"}}"#))).await.unwrap();
    }

    async fn run<F: std::future::Future<Output = ()>>(body: F) {
        drop_mongo_dbs(&[CLIENT], APP).await;
        guarded(body, drop_mongo_dbs(&[CLIENT], APP)).await;
    }

    #[tokio::test]
    #[ignore = "needs the local MongoDB"]
    async fn draft_write_isolated() {
        run(async {
            let e = mongo_engine();
            row(&e, &draft(), "draft row").await;
            assert!(collections(&draft_db(APP)).await.contains(&UNIQUE_NAME.to_string()));
            assert!(!collections(&live_db(APP)).await.contains(&UNIQUE_NAME.to_string()));
        })
        .await;
    }

    #[tokio::test]
    #[ignore = "needs the local MongoDB"]
    async fn surfaces_read_their_own_rows() {
        run(async {
            let e = mongo_engine();
            row(&e, &cx(), "live row").await;
            row(&e, &draft(), "draft row").await;
            let all = query(r#"{"page":0,"size":50}"#);
            let live = e.read_page(&cx(), CLIENT, None, &stored(), &all).await.unwrap();
            let drafted = e.read_page(&draft(), CLIENT, None, &stored(), &all).await.unwrap();
            assert_eq!(live.content.len(), 1, "the live surface must see only its own row");
            assert_eq!(drafted.content.len(), 1, "the draft surface must see only its own row");
            assert_eq!(live.content[0]["title"], Value::from("live row"));
            assert_eq!(drafted.content[0]["title"], Value::from("draft row"));
        })
        .await;
    }

    #[tokio::test]
    #[ignore = "needs the local MongoDB"]
    async fn deleting_storage_drops_draft_only() {
        run(async {
            let e = mongo_engine();
            row(&e, &cx(), "live row").await;
            row(&e, &draft(), "draft row").await;
            assert!(collections(&live_db(APP)).await.contains(&UNIQUE_NAME.to_string()));
            assert!(collections(&draft_db(APP)).await.contains(&UNIQUE_NAME.to_string()));
            // Called from the live surface, as a definition delete is.
            assert!(e.drop_draft_storage(&cx(), CLIENT, None, &stored()).await.unwrap());
            assert!(!collections(&draft_db(APP)).await.contains(&UNIQUE_NAME.to_string()), "draft rows outlived the definition");
            assert!(collections(&live_db(APP)).await.contains(&UNIQUE_NAME.to_string()), "live data must not be destroyed");
        })
        .await;
    }

    #[tokio::test]
    #[ignore = "needs the local MongoDB"]
    async fn deleting_app_drops_draft_database_only() {
        run(async {
            let e = mongo_engine();
            row(&e, &cx(), "live row").await;
            row(&e, &draft(), "draft row").await;
            assert!(databases().await.contains(&live_db(APP)));
            assert!(databases().await.contains(&draft_db(APP)));
            assert!(e.drop_draft_database(None, APP, CLIENT).await.unwrap());
            assert!(!databases().await.contains(&draft_db(APP)), "the app's draft database outlived the app");
            assert!(databases().await.contains(&live_db(APP)), "app deletion must not destroy live data");
        })
        .await;
    }

    #[tokio::test]
    #[ignore = "needs the local MongoDB"]
    async fn metering_counts_both_surfaces() {
        run(async {
            let e = mongo_engine();
            row(&e, &cx(), "live one").await;
            row(&e, &cx(), "live two").await;
            row(&e, &draft(), "draft one").await;
            // No draft context: the meter names both databases itself.
            assert_eq!(e.estimated_row_count(None, APP, CLIENT).await, 3);
        })
        .await;
    }

    #[tokio::test]
    #[ignore = "needs the local MongoDB"]
    async fn metering_with_no_draft_database() {
        run(async {
            let e = mongo_engine();
            row(&e, &cx(), "live one").await;
            assert!(!databases().await.contains(&draft_db(APP)));
            assert_eq!(e.estimated_row_count(None, APP, CLIENT).await, 1);
        })
        .await;
    }

    #[tokio::test]
    #[ignore = "needs the local MongoDB"]
    async fn same_collection_name_both_surfaces() {
        run(async {
            let e = mongo_engine();
            row(&e, &cx(), "live row").await;
            row(&e, &draft(), "draft row").await;
            assert!(collections(&live_db(APP)).await.contains(&UNIQUE_NAME.to_string()));
            assert!(collections(&draft_db(APP)).await.contains(&UNIQUE_NAME.to_string()));
        })
        .await;
    }
}

/// `AppDataSurfaceIntegrationTest`, the engine parts. `clearAllRows` is the engine's
/// `deleteByFilter(new Query(), dryRun, null)` and `copyLiveDataToDraft` its
/// `copyLiveToDraft(replace)`; the surface naming (`onSurface`) and every auth bar are the
/// policy layer's.
mod app_data_surface_integration_test {
    use super::*;

    const APP: &str = "mgj_surface";
    const UNIQUE_NAME: &str = "testapp_system_surfacestorage";
    const VERSION_COLLECTION: &str = "testapp_system_surfacestorage_version";

    /// `storedStorage(versioned)`.
    fn stored(versioned: bool) -> Storage {
        storage(
            APP,
            "surfaceStorage",
            &format!(
                r#"{{"uniqueName":"{UNIQUE_NAME}","isVersioned":{versioned},
                    "schema":{{"name":"SurfaceStorage","type":"OBJECT","properties":{{"title":{{"type":"STRING"}}}}}}}}"#
            ),
        )
    }

    async fn row(e: &MongoAppDataService, c: &Ctx, s: &Storage, title: &str) {
        e.create(c, CLIENT, None, s, data(&format!(r#"{{"title":"{title}"}}"#))).await.unwrap();
    }

    async fn run<F: std::future::Future<Output = ()>>(body: F) {
        drop_mongo_dbs(&[CLIENT], APP).await;
        guarded(body, drop_mongo_dbs(&[CLIENT], APP)).await;
    }

    #[tokio::test]
    #[ignore = "needs the local MongoDB"]
    async fn unwritten_draft_reads_empty() {
        run(async {
            let e = mongo_engine();
            let s = stored(false);
            row(&e, &cx(), &s, "live row").await;
            let drafted = e.read_page(&draft(), CLIENT, None, &s, &query(r#"{"page":0,"size":50}"#)).await.unwrap();
            assert!(drafted.content.is_empty());
            assert_eq!(drafted.total, 0);
        })
        .await;
    }

    #[tokio::test]
    #[ignore = "needs the local MongoDB"]
    async fn clear_keeps_collection_and_history() {
        run(async {
            let e = mongo_engine();
            let s = stored(true);
            row(&e, &cx(), &s, "one").await;
            row(&e, &cx(), &s, "two").await;
            assert_eq!(raw(&live_db(APP), UNIQUE_NAME).await.len(), 2);
            assert_eq!(raw(&live_db(APP), VERSION_COLLECTION).await.len(), 2, "one version row per create");

            let deleted = e.delete_by_filter(&cx(), CLIENT, None, &s, &Query::default(), Some(false), None).await.unwrap();
            assert_eq!(deleted, 2);
            assert!(raw(&live_db(APP), UNIQUE_NAME).await.is_empty());
            assert!(collections(&live_db(APP)).await.contains(&UNIQUE_NAME.to_string()), "the collection must survive a clear");
            assert_eq!(raw(&live_db(APP), VERSION_COLLECTION).await.len(), 2, "clearing rows must not destroy their history");
        })
        .await;
    }

    #[tokio::test]
    #[ignore = "needs the local MongoDB"]
    async fn dry_run_counts_only() {
        run(async {
            let e = mongo_engine();
            let s = stored(false);
            row(&e, &cx(), &s, "one").await;
            row(&e, &cx(), &s, "two").await;
            assert_eq!(e.delete_by_filter(&cx(), CLIENT, None, &s, &Query::default(), Some(true), None).await.unwrap(), 2);
            assert_eq!(raw(&live_db(APP), UNIQUE_NAME).await.len(), 2, "a dry run must not delete");
        })
        .await;
    }

    #[tokio::test]
    #[ignore = "needs the local MongoDB"]
    async fn clear_on_draft_leaves_live() {
        run(async {
            let e = mongo_engine();
            let s = stored(false);
            row(&e, &cx(), &s, "live row").await;
            row(&e, &draft(), &s, "draft row").await;
            assert_eq!(e.delete_by_filter(&draft(), CLIENT, None, &s, &Query::default(), Some(false), None).await.unwrap(), 1);
            assert!(raw(&draft_db(APP), UNIQUE_NAME).await.is_empty());
            assert_eq!(raw(&live_db(APP), UNIQUE_NAME).await.len(), 1, "clearing the sandbox must never reach live data");
        })
        .await;
    }

    #[tokio::test]
    #[ignore = "needs the local MongoDB"]
    async fn copy_preserves_ids_and_keeps_live() {
        run(async {
            let e = mongo_engine();
            let s = stored(false);
            row(&e, &cx(), &s, "one").await;
            row(&e, &cx(), &s, "two").await;
            assert_eq!(e.copy_live_to_draft(&cx(), CLIENT, None, &s, Some(true)).await.unwrap(), 2);
            let live = raw(&live_db(APP), UNIQUE_NAME).await;
            let drafted = raw(&draft_db(APP), UNIQUE_NAME).await;
            assert_eq!(live.len(), 2, "the source must be untouched");
            assert_eq!(drafted.len(), 2);
            assert_eq!(sorted_ids(&live), sorted_ids(&drafted), "draft rows keep the ids their live originals had");
        })
        .await;
    }

    #[tokio::test]
    #[ignore = "needs the local MongoDB"]
    async fn copy_with_replace_clears_draft_first() {
        run(async {
            let e = mongo_engine();
            let s = stored(false);
            row(&e, &cx(), &s, "live only").await;
            row(&e, &draft(), &s, "sandbox scratch").await;
            e.copy_live_to_draft(&cx(), CLIENT, None, &s, Some(true)).await.unwrap();
            let drafted = raw(&draft_db(APP), UNIQUE_NAME).await;
            assert_eq!(drafted.len(), 1, "the pre-existing sandbox row must be gone, not added to");
            assert_eq!(drafted[0].get_str("title").unwrap(), "live only");
        })
        .await;
    }

    #[tokio::test]
    #[ignore = "needs the local MongoDB"]
    async fn copy_twice_is_idempotent() {
        run(async {
            let e = mongo_engine();
            let s = stored(false);
            row(&e, &cx(), &s, "one").await;
            e.copy_live_to_draft(&cx(), CLIENT, None, &s, Some(false)).await.unwrap();
            assert_eq!(e.copy_live_to_draft(&cx(), CLIENT, None, &s, Some(false)).await.unwrap(), 1);
            assert_eq!(raw(&draft_db(APP), UNIQUE_NAME).await.len(), 1);
        })
        .await;
    }

    /// The engine half: an empty source answers 0 and the draft rows stay. The 400 the
    /// caller gets is `AppDataService` turning that 0 into a refusal.
    #[tokio::test]
    #[ignore = "needs the local MongoDB"]
    async fn copy_with_empty_source_changes_nothing() {
        run(async {
            let e = mongo_engine();
            let s = stored(false);
            row(&e, &draft(), &s, "sandbox scratch").await;
            assert_eq!(e.copy_live_to_draft(&cx(), CLIENT, None, &s, Some(true)).await.unwrap(), 0);
            assert_eq!(raw(&draft_db(APP), UNIQUE_NAME).await.len(), 1, "a refused copy must not have cleared the draft rows");
        })
        .await;
    }
}

// ====================================================================== aca9929dd

/// `clearDraftRows` and the filtered `copyLiveToDraft` (with `DraftCopyFilter`), which came
/// with no Java tests; each expectation is read off the Java code and its javadoc. What
/// `live_mongo.rs::the_draft_surface` covers (copy with replace, a condition, a default
/// follow, metering, the drops) is not repeated.
mod draft_copy {
    use super::*;

    const APP: &str = "mgj_copy";

    async fn run<F: std::future::Future<Output = ()>>(body: F) {
        drop_mongo_dbs(&[CLIENT], APP).await;
        guarded(body, drop_mongo_dbs(&[CLIENT], APP)).await;
    }

    fn follow(field: &str, storage: &str, ref_field: Option<&str>) -> Follow {
        Follow { field: field.into(), storage: storage.into(), ref_field: ref_field.map(str::to_string) }
    }

    fn filter(condition: Option<&str>, follows: Vec<Follow>) -> DraftCopyFilter {
        DraftCopyFilter { condition: condition.map(cond), follow: if follows.is_empty() { None } else { Some(follows) } }
    }

    struct Crm {
        leads: Storage,
        deals: Storage,
        activities: Storage,
        notes: Storage,
        all: HashMap<String, Storage>,
    }

    fn crm() -> Crm {
        let named = r#""schema":{"type":"OBJECT","properties":{"name":{"type":"STRING"},"amount":{"type":"INTEGER"}}}"#;
        let leads = storage(APP, "leads", &format!("{{{named}}}"));
        let deals = storage(APP, "deals", &format!(r#"{{"relations":{{"owner":{{"storageName":"leads","relationType":"TO_ONE"}}}},{named}}}"#));
        let activities = storage(
            APP,
            "activities",
            &format!(
                r#"{{"relations":{{"deal":{{"storageName":"deals","relationType":"TO_ONE"}},"lead":{{"storageName":"leads","relationType":"TO_ONE"}}}},{named}}}"#
            ),
        );
        let notes = storage(APP, "notes", &format!(r#"{{"relations":{{"activity":{{"storageName":"activities","relationType":"TO_ONE"}}}},{named}}}"#));
        let all = [&leads, &deals, &activities, &notes].into_iter().map(|s| (s.name.clone(), s.clone())).collect();
        Crm { leads, deals, activities, notes, all }
    }

    /// `clearDraftRows`: the draft rows and the draft history go, the draft collection
    /// stays (deleteMany, not drop), live is not touched; 0 when there was never a draft.
    #[tokio::test]
    #[ignore = "needs the local MongoDB"]
    async fn clear_draft_rows() {
        run(async {
            let e = mongo_engine();
            let s = storage(APP, "things", r#"{"isVersioned":true,"schema":{"type":"OBJECT","properties":{"name":{"type":"STRING"}}}}"#);
            assert_eq!(e.clear_draft_rows(&cx(), CLIENT, None, &s).await.unwrap(), 0);

            add(&e, &cx(), &s, r#"{"name":"live"}"#).await;
            add(&e, &draft(), &s, r#"{"name":"d1"}"#).await;
            add(&e, &draft(), &s, r#"{"name":"d2"}"#).await;
            assert_eq!(raw(&draft_db(APP), "mgj_copy_things_version").await.len(), 2);

            // Called from the live surface; the method names the draft surface itself.
            assert_eq!(e.clear_draft_rows(&cx(), CLIENT, None, &s).await.unwrap(), 2);
            assert!(raw(&draft_db(APP), "mgj_copy_things").await.is_empty());
            assert!(raw(&draft_db(APP), "mgj_copy_things_version").await.is_empty());
            assert!(collections(&draft_db(APP)).await.contains(&"mgj_copy_things".to_string()), "kept, so its indexes stay");
            assert_eq!(raw(&live_db(APP), "mgj_copy_things").await.len(), 1);
            assert_eq!(raw(&live_db(APP), "mgj_copy_things_version").await.len(), 1);
        })
        .await;
    }

    /// No filter copies every live row, after emptying the draft; a filter that selects
    /// nothing still empties it.
    #[tokio::test]
    #[ignore = "needs the local MongoDB"]
    async fn the_draft_is_replaced_whatever_is_selected() {
        run(async {
            let e = mongo_engine();
            let c = crm();
            for n in ["L1", "L2"] {
                add(&e, &cx(), &c.leads, &format!(r#"{{"name":"{n}"}}"#)).await;
            }
            add(&e, &draft(), &c.leads, r#"{"name":"stale"}"#).await;

            assert_eq!(e.copy_live_to_draft_filtered(&cx(), CLIENT, None, &c.leads, None, &c.all).await.unwrap(), 2);
            assert_eq!(names_on(&e, &draft(), &c.leads).await, ["L1", "L2"]);

            let nothing = filter(Some(r#"{"field":"name","value":"nobody"}"#), vec![]);
            assert_eq!(e.copy_live_to_draft_filtered(&cx(), CLIENT, None, &c.leads, Some(&nothing), &c.all).await.unwrap(), 0);
            assert!(names_on(&e, &draft(), &c.leads).await.is_empty());
            assert_eq!(names_on(&e, &cx(), &c.leads).await, ["L1", "L2"], "live is never touched");
        })
        .await;
    }

    /// A slice of an app: root rows by condition, then everything that hangs off them by
    /// follow, each storage copied after the ones it follows.
    #[tokio::test]
    #[ignore = "needs the local MongoDB"]
    async fn follows() {
        run(async {
            let e = mongo_engine();
            let c = crm();
            let mut id = HashMap::new();
            for n in ["L1", "L2", "L3"] {
                id.insert(n, add(&e, &cx(), &c.leads, &format!(r#"{{"name":"{n}"}}"#)).await);
            }
            for (n, amount, owner) in [("D1", 100, "L1"), ("D2", 5, "L2"), ("D3", 50, "L1")] {
                let row = format!(r#"{{"name":"{n}","amount":{amount},"owner":"{}"}}"#, id[owner]);
                id.insert(n, add(&e, &cx(), &c.deals, &row).await);
            }
            let activities = [
                ("A1", Some("D1"), Some("L1")),
                ("A2", Some("D2"), Some("L2")),
                ("A3", None, Some("L1")),
                ("A4", None, Some("L3")),
                ("A5", Some("D3"), Some("L1")),
                ("A6", None, None),
                ("A7", Some("D2"), Some("L1")),
            ];
            for (n, deal, lead) in activities {
                let mut row = format!(r#"{{"name":"{n}""#);
                if let Some(d) = deal {
                    row.push_str(&format!(r#","deal":"{}""#, id[d]));
                }
                if let Some(l) = lead {
                    row.push_str(&format!(r#","lead":"{}""#, id[l]));
                }
                row.push('}');
                id.insert(n, add(&e, &cx(), &c.activities, &row).await);
            }
            for (n, activity) in [("N1", "A1"), ("N2", "A2"), ("N3", "A3"), ("N4", "A7")] {
                add(&e, &cx(), &c.notes, &format!(r#"{{"name":"{n}","activity":"{}"}}"#, id[activity])).await;
            }
            add(&e, &draft(), &c.activities, r#"{"name":"stale"}"#).await;

            // A follow whose storage has no draft rows yet: $in over nothing, so no row
            // is kept, and the draft is still emptied.
            let by_deal = filter(None, vec![follow("deal", "deals", None)]);
            assert_eq!(e.copy_live_to_draft_filtered(&cx(), CLIENT, None, &c.activities, Some(&by_deal), &c.all).await.unwrap(), 0);
            assert!(names_on(&e, &draft(), &c.activities).await.is_empty());

            // The root: the big deals.
            let big = filter(Some(r#"{"field":"amount","operator":"GREATER_THAN_EQUAL","value":50}"#), vec![]);
            assert_eq!(e.copy_live_to_draft_filtered(&cx(), CLIENT, None, &c.deals, Some(&big), &c.all).await.unwrap(), 2);

            // refField reads the other way round: a lead is kept when a draft deal points at it.
            let owners = filter(None, vec![follow("_id", "deals", Some("owner"))]);
            assert_eq!(e.copy_live_to_draft_filtered(&cx(), CLIENT, None, &c.leads, Some(&owners), &c.all).await.unwrap(), 1);
            assert_eq!(names_on(&e, &draft(), &c.leads).await, ["L1"]);

            // Two follows: each column empty or satisfied, at least one filled. A blank
            // refField is _id. A7's lead came across but its deal did not, so it stays out.
            let both = filter(None, vec![follow("deal", "deals", None), follow("lead", "leads", Some(" "))]);
            assert_eq!(e.copy_live_to_draft_filtered(&cx(), CLIENT, None, &c.activities, Some(&both), &c.all).await.unwrap(), 3);
            assert_eq!(names_on(&e, &draft(), &c.activities).await, ["A1", "A3", "A5"]);

            // Chained one level further.
            let by_activity = filter(None, vec![follow("activity", "activities", None)]);
            assert_eq!(e.copy_live_to_draft_filtered(&cx(), CLIENT, None, &c.notes, Some(&by_activity), &c.all).await.unwrap(), 2);
            assert_eq!(names_on(&e, &draft(), &c.notes).await, ["N1", "N3"]);

            // A condition and follows together: AND of both.
            let not_a5 = filter(Some(r#"{"field":"name","value":"A5","negate":true}"#), vec![follow("deal", "deals", None), follow("lead", "leads", None)]);
            assert_eq!(e.copy_live_to_draft_filtered(&cx(), CLIENT, None, &c.activities, Some(&not_a5), &c.all).await.unwrap(), 2);
            assert_eq!(names_on(&e, &draft(), &c.activities).await, ["A1", "A3"]);

            // A follow naming a storage the caller did not resolve: Java's
            // getCollection(null) is a NullPointerException, a 500.
            let err = e.copy_live_to_draft_filtered(&cx(), CLIENT, None, &c.notes, Some(&by_activity), &HashMap::new()).await.unwrap_err();
            assert_eq!(err.status().as_u16(), 500);
        })
        .await;
    }

    /// `_id` carried across unchanged (as ObjectIds, relation fields too), so a row keeps
    /// its id on both surfaces; history is not copied; the draft collection gets its
    /// indexes in its own right. A follow compares the stored values, so an id held as
    /// text in a field that is not a relation matches no ObjectId `_id`.
    #[tokio::test]
    #[ignore = "needs the local MongoDB"]
    async fn ids_carry_across() {
        run(async {
            let e = mongo_engine();
            let people = storage(
                APP,
                "people",
                r#"{"isVersioned":true,"indexes":{"byName":{"fields":[{"fieldName":"name","direction":"ASC"}],"unique":false}},
                    "schema":{"type":"OBJECT","properties":{"name":{"type":"STRING"}}}}"#,
            );
            let orders = storage(APP, "orders", r#"{"relations":{"owner":{"storageName":"people","relationType":"TO_ONE"}},"schema":{"type":"OBJECT"}}"#);
            let mut followed = HashMap::new();
            followed.insert("people".to_string(), people.clone());
            let p1 = add(&e, &cx(), &people, r#"{"name":"p1"}"#).await;
            let p2 = add(&e, &cx(), &people, r#"{"name":"p2"}"#).await;
            add(&e, &cx(), &orders, &format!(r#"{{"name":"o1","owner":"{p1}","ownerRef":"{p1}"}}"#)).await;
            add(&e, &cx(), &orders, &format!(r#"{{"name":"o2","owner":"{p2}","ownerRef":"{p2}"}}"#)).await;

            assert_eq!(e.copy_live_to_draft_filtered(&cx(), CLIENT, None, &people, None, &followed).await.unwrap(), 2);
            let live = raw(&live_db(APP), "mgj_copy_people").await;
            let drafted = raw(&draft_db(APP), "mgj_copy_people").await;
            assert_eq!(sorted_ids(&live), sorted_ids(&drafted));
            assert_eq!(e.read(&draft(), CLIENT, None, &people, &p1).await.unwrap()["name"], Value::from("p1"));
            let draft_collections = collections(&draft_db(APP)).await;
            assert!(!draft_collections.contains(&"mgj_copy_people_version".to_string()), "history is not copied: {draft_collections:?}");
            let indexes = mongo_client().await.database(&draft_db(APP)).collection::<BsonDocument>("mgj_copy_people").list_index_names().await.unwrap();
            assert!(indexes.contains(&"byName".to_string()), "{indexes:?}");

            let by_owner = filter(None, vec![follow("owner", "people", None)]);
            assert_eq!(e.copy_live_to_draft_filtered(&cx(), CLIENT, None, &orders, Some(&by_owner), &followed).await.unwrap(), 2);
            let o = raw(&draft_db(APP), "mgj_copy_orders").await;
            assert!(o.iter().any(|d| d.get("owner") == Some(&Bson::ObjectId(oid(&p1)))), "{o:?}");

            let by_text = filter(None, vec![follow("ownerRef", "people", None)]);
            assert_eq!(e.copy_live_to_draft_filtered(&cx(), CLIENT, None, &orders, Some(&by_text), &followed).await.unwrap(), 0);
        })
        .await;
    }

    /// `copyLiveToDraft(replace)` without replace: the rows already in the draft stay, and
    /// a live row copied again replaces its draft copy (upsert by `_id`).
    #[tokio::test]
    #[ignore = "needs the local MongoDB"]
    async fn copy_without_replace_merges() {
        run(async {
            let e = mongo_engine();
            let c = crm();
            let a = add(&e, &cx(), &c.leads, r#"{"name":"a"}"#).await;
            add(&e, &cx(), &c.leads, r#"{"name":"b"}"#).await;
            add(&e, &draft(), &c.leads, r#"{"name":"x"}"#).await;
            assert_eq!(e.copy_live_to_draft(&cx(), CLIENT, None, &c.leads, None).await.unwrap(), 2);
            assert_eq!(names_on(&e, &draft(), &c.leads).await, ["a", "b", "x"]);
            e.update(&cx(), CLIENT, None, &c.leads, data(&format!(r#"{{"_id":"{a}","name":"a2"}}"#)), Some(false)).await.unwrap();
            assert_eq!(e.copy_live_to_draft(&cx(), CLIENT, None, &c.leads, Some(false)).await.unwrap(), 2);
            assert_eq!(names_on(&e, &draft(), &c.leads).await, ["a2", "b", "x"]);
        })
        .await;
    }
}

// ====================================================================== extra

/// Not Java ports: the rest of `MongoAppDataService` and `lookup::MongoDefinitions`,
/// checked against the Java code.
mod extra {
    use super::*;

    const APP: &str = "mgj_extra";

    async fn run<F: std::future::Future<Output = ()>>(body: F) {
        drop_mongo_dbs(&[CLIENT], APP).await;
        guarded(body, drop_mongo_dbs(&[CLIENT], APP)).await;
    }

    fn engine_with(retention: VersionRetention, skip_index_management: bool) -> MongoAppDataService {
        mongo_engine_with(
            MongoEngineConfig { default_uri: Some(mongo_uri()), retention, skip_index_management },
            Default::default(),
        )
    }

    fn plain(name: &str, json: &str) -> Storage {
        storage(APP, name, json)
    }

    /// `getMongoClient(conn)`: a connection with its own url gets its own client, kept by
    /// connection id until evicted; one without a url is CONNECTION_DETAILS_MISSING (404).
    #[tokio::test]
    #[ignore = "needs the local MongoDB"]
    async fn a_connection_with_its_own_url() {
        run(async {
            let e = mongo_engine();
            let mut details = appdata::value::Document::new();
            details.insert("url".into(), Value::from(mongo_uri()));
            let conn = Connection {
                id: "rusttest-mgj-conn".into(),
                connection_sub_type: Some(ConnectionSubType::Mongo),
                connection_details: Some(details),
                ..Default::default()
            };
            let s = plain("things", r#"{"schema":{"type":"OBJECT"}}"#);
            let id = e.create(&cx(), CLIENT, Some(&conn), &s, data(r#"{"name":"via conn"}"#)).await.unwrap()["_id"].java_string();
            assert_eq!(e.read(&cx(), CLIENT, Some(&conn), &s, &id).await.unwrap()["name"], Value::from("via conn"));
            assert_eq!(e.estimated_row_count(Some(&conn), APP, CLIENT).await, 1);
            e.evict_connection("rusttest-mgj-conn").await;
            assert!(e.check_if_exists(&cx(), CLIENT, Some(&conn), &s, &id).await.unwrap());

            let mut no_url = appdata::value::Document::new();
            no_url.insert("url".into(), Value::Null);
            let bad = Connection { id: "rusttest-mgj-bad".into(), connection_details: Some(no_url), ..conn.clone() };
            let err = e.read(&cx(), CLIENT, Some(&bad), &s, &id).await.unwrap_err();
            assert_eq!(err.status().as_u16(), 404, "{}", err.message());
        })
        .await;
    }

    /// `manageIndexes`: what the definition names is created (compound, unique, text),
    /// what it no longer names is dropped, an index with no fields is skipped. Index work
    /// runs once per engine cache, so each definition change is a fresh engine.
    #[tokio::test]
    #[ignore = "needs the local MongoDB"]
    async fn indexes_follow_the_definition() {
        run(async {
            let keep = VersionRetention::clamped(0, 0);
            let first = plain(
                "indexed",
                r#"{"textIndexFields":["name"],"indexes":{
                    "byAmount":{"fields":[{"fieldName":"amount","direction":"DESC"}],"unique":false},
                    "byName":{"fields":[{"fieldName":"name","direction":"ASC"},{"fieldName":"amount","direction":"DESC"}],"unique":true},
                    "empty":{"fields":[],"unique":false}},"schema":{"type":"OBJECT"}}"#,
            );
            let id = add(&engine_with(keep, false), &cx(), &first, r#"{"name":"a","amount":1}"#).await;
            let coll = mongo_client().await.database(&live_db(APP)).collection::<BsonDocument>("mgj_extra_indexed");
            let listed = |c: mongodb::Collection<BsonDocument>| async move {
                let mut out: Vec<(String, BsonDocument, bool)> = c
                    .list_indexes()
                    .await
                    .unwrap()
                    .try_collect::<Vec<_>>()
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|i| {
                        let o = i.options.unwrap_or_default();
                        (o.name.unwrap_or_default(), i.keys, o.unique.unwrap_or(false))
                    })
                    .collect();
                out.sort_by(|a, b| a.0.cmp(&b.0));
                out
            };
            let before = listed(coll.clone()).await;
            let index_names: Vec<&str> = before.iter().map(|i| i.0.as_str()).collect();
            assert_eq!(index_names, ["_id_", "_textIndex", "byAmount", "byName"]);
            let by_name = before.iter().find(|i| i.0 == "byName").unwrap();
            assert_eq!(by_name.1, doc! { "name": 1, "amount": -1 });
            assert!(by_name.2, "byName is unique");

            // byAmount and the text index leave the definition.
            let second = plain(
                "indexed",
                r#"{"indexes":{"byName":{"fields":[{"fieldName":"name","direction":"ASC"},{"fieldName":"amount","direction":"DESC"}],"unique":true}},"schema":{"type":"OBJECT"}}"#,
            );
            engine_with(keep, false).read(&cx(), CLIENT, None, &second, &id).await.unwrap();
            let names: Vec<String> = listed(coll.clone()).await.into_iter().map(|i| i.0).collect();
            assert_eq!(names, ["_id_", "byName"]);

            // A tool that must not change a tenant leaves them alone.
            engine_with(keep, true).read(&cx(), CLIENT, None, &plain("indexed", r#"{"schema":{"type":"OBJECT"}}"#), &id).await.unwrap();
            assert_eq!(listed(coll.clone()).await.len(), 2);

            // None at all: everything but _id_ goes.
            engine_with(keep, false).read(&cx(), CLIENT, None, &plain("indexed", r#"{"schema":{"type":"OBJECT"}}"#), &id).await.unwrap();
            let names: Vec<String> = listed(coll).await.into_iter().map(|i| i.0).collect();
            assert_eq!(names, ["_id_"]);
        })
        .await;
    }

    /// `trimVersions` with the installation's retention: by count (the Nth newest and
    /// newer survive), and by age (older than the cutoff goes, whatever the count).
    #[tokio::test]
    #[ignore = "needs the local MongoDB"]
    async fn history_is_trimmed() {
        run(async {
            let s = plain("kept", r#"{"isVersioned":true,"schema":{"type":"OBJECT"}}"#);
            let versions = |id: String| async move {
                raw(&live_db(APP), "mgj_extra_kept_version").await.into_iter().filter(|d| d.get_str("objectId") == Ok(id.as_str())).collect::<Vec<_>>()
            };

            let by_count = engine_with(VersionRetention::clamped(30, 2), false);
            let id = add(&by_count, &cx(), &s, r#"{"n":0}"#).await;
            assert_eq!(versions(id.clone()).await.len(), 1);
            for n in 1..4 {
                tokio::time::sleep(Duration::from_millis(5)).await;
                by_count.update(&cx(), CLIENT, None, &s, data(&format!(r#"{{"_id":"{id}","n":{n}}}"#)), Some(false)).await.unwrap();
            }
            let left = versions(id.clone()).await;
            assert_eq!(left.len(), 2);
            let ns: Vec<i32> = left.iter().map(|d| d.get_document("object").unwrap().get_i32("n").unwrap()).collect();
            assert_eq!(ns, [2, 3], "the newest two");

            // Age only (count 0 keeps any number): a row 400 days old goes on the next write.
            let by_age = engine_with(VersionRetention::clamped(30, 0), false);
            let old = DateTime::from_millis(DateTime::now().timestamp_millis() - 400 * 86_400_000);
            insert_raw(&live_db(APP), "mgj_extra_kept_version", vec![doc! { "objectId": &id, "createdAt": old, "operation": "UPDATE" }]).await;
            for n in 4..7 {
                by_age.update(&cx(), CLIENT, None, &s, data(&format!(r#"{{"_id":"{id}","n":{n}}}"#)), Some(false)).await.unwrap();
            }
            let left = versions(id.clone()).await;
            assert_eq!(left.len(), 5, "2 kept before, 3 new, the old one gone");
            assert!(left.iter().all(|d| d.get_datetime("createdAt").unwrap().timestamp_millis() > old.timestamp_millis()));
        })
        .await;
    }

    /// `recordDelete` / `recordBulkDelete`: deleteVersion true purges the rows' history,
    /// false writes a DELETE row per deleted row, null does neither; a storage that keeps
    /// no history writes none.
    #[tokio::test]
    #[ignore = "needs the local MongoDB"]
    async fn deletes_and_their_history() {
        run(async {
            let e = mongo_engine();
            let s = plain("audited", r#"{"isAudited":true,"schema":{"type":"OBJECT"}}"#);
            let history = || async { raw(&live_db(APP), "mgj_extra_audited_version").await };
            let ops_of = |rows: Vec<BsonDocument>, id: String| -> Vec<String> {
                rows.iter().filter(|d| d.get_str("objectId") == Ok(id.as_str())).map(|d| d.get_str("operation").unwrap().to_string()).collect()
            };

            let a = add(&e, &cx(), &s, r#"{"name":"a"}"#).await;
            e.update(&cx(), CLIENT, None, &s, data(&format!(r#"{{"_id":"{a}","name":"a1"}}"#)), Some(false)).await.unwrap();
            assert_eq!(ops_of(history().await, a.clone()), ["CREATE", "UPDATE"]);
            // Audited, not versioned: the history rows carry no object.
            assert!(history().await.iter().all(|d| !d.contains_key("object")));
            // Projected fields are honoured as given, even with includeObject false.
            let page = e.read_page_version(&cx(), CLIENT, None, &s, &a, &query(r#"{"fields":["operation"]}"#), Some(false)).await.unwrap();
            assert_eq!(page.content[0].keys().collect::<Vec<_>>(), ["operation", "_id"]);
            assert!(e.delete(&cx(), CLIENT, None, &s, &a, Some(true)).await.unwrap());
            assert!(ops_of(history().await, a.clone()).is_empty(), "purged");

            let b = add(&e, &cx(), &s, r#"{"name":"b"}"#).await;
            assert!(e.delete(&cx(), CLIENT, None, &s, &b, None).await.unwrap());
            assert_eq!(ops_of(history().await, b.clone()), ["CREATE"]);

            let c1 = add(&e, &cx(), &s, r#"{"name":"c1","bulk":true}"#).await;
            let c2 = add(&e, &cx(), &s, r#"{"name":"c2","bulk":true}"#).await;
            let bulk = query(r#"{"condition":{"field":"bulk","operator":"IS_TRUE"}}"#);
            assert_eq!(e.delete_by_filter(&cx(), CLIENT, None, &s, &bulk, Some(false), Some(false)).await.unwrap(), 2);
            assert_eq!(ops_of(history().await, c1), ["CREATE", "DELETE"]);
            assert_eq!(ops_of(history().await, c2), ["CREATE", "DELETE"]);

            // No history kept: nothing recorded, whichever deleteVersion.
            let quiet = plain("quiet", r#"{"schema":{"type":"OBJECT"}}"#);
            let q = add(&e, &cx(), &quiet, r#"{"name":"q"}"#).await;
            assert!(e.delete(&cx(), CLIENT, None, &quiet, &q, Some(false)).await.unwrap());
            add(&e, &cx(), &quiet, r#"{"name":"r"}"#).await;
            assert_eq!(e.delete_by_filter(&cx(), CLIENT, None, &quiet, &Query::default(), None, Some(true)).await.unwrap(), 1);
            assert!(!collections(&live_db(APP)).await.contains(&"mgj_extra_quiet_version".to_string()));
        })
        .await;
    }

    /// The purge path collects ids and deletes their history in batches of 1000, so a
    /// wide delete never holds the whole match set.
    #[tokio::test]
    #[ignore = "needs the local MongoDB"]
    async fn bulk_history_purge_in_batches() {
        run(async {
            let e = mongo_engine();
            let s = plain("wide", r#"{"isAudited":true,"schema":{"type":"OBJECT"}}"#);
            add(&e, &cx(), &s, r#"{"name":"provisioned"}"#).await;
            let ids: Vec<ObjectId> = (0..1001).map(|_| ObjectId::new()).collect();
            insert_raw(&live_db(APP), "mgj_extra_wide", ids.iter().map(|i| doc! { "_id": i, "wide": true }).collect()).await;
            let mut history: Vec<BsonDocument> = ids.iter().map(|i| doc! { "objectId": i.to_hex(), "operation": "CREATE" }).collect();
            history.push(doc! { "objectId": ObjectId::new().to_hex(), "operation": "CREATE" });
            insert_raw(&live_db(APP), "mgj_extra_wide_version", history).await;

            let wide = query(r#"{"condition":{"field":"wide","operator":"IS_TRUE"}}"#);
            assert_eq!(e.delete_by_filter(&cx(), CLIENT, None, &s, &wide, None, Some(true)).await.unwrap(), 1001);
            // What is left: the other row's CREATE and the unrelated history row.
            assert_eq!(raw(&live_db(APP), "mgj_extra_wide_version").await.len(), 2);
        })
        .await;
    }

    /// `updateDocWithIds`: a relation list reads as hex strings, nulls dropped and any
    /// other value as its Java `toString` (`Long`, `ArrayList`); a relation value that is
    /// not an ObjectId is left alone.
    #[tokio::test]
    #[ignore = "needs the local MongoDB"]
    async fn relation_lists_read_as_hex() {
        run(async {
            let e = mongo_engine();
            let s = plain(
                "tagged",
                r#"{"relations":{"tags":{"storageName":"tags","relationType":"TO_MANY"},"owner":{"storageName":"people","relationType":"TO_ONE"}},"schema":{"type":"OBJECT"}}"#,
            );
            let (t1, t2) = ("6ac7d4a11a578c042996bca5", "6ac7d4a11a578c042996bca6");
            let id = add(&e, &cx(), &s, &format!(r#"{{"name":"made","tags":["{t1}","{t2}"]}}"#)).await;
            let stored = raw(&live_db(APP), "mgj_extra_tagged").await;
            assert_eq!(stored[0].get_array("tags").unwrap(), &vec![Bson::ObjectId(oid(t1)), Bson::ObjectId(oid(t2))]);
            assert_eq!(e.read(&cx(), CLIENT, None, &s, &id).await.unwrap()["tags"], v(&format!(r#"["{t1}","{t2}"]"#)));

            let odd = ObjectId::new();
            let mixed = Bson::Array(vec![
                Bson::ObjectId(oid(t1)), Bson::Null, "plain".into(), Bson::Int32(5), Bson::Double(2.5), Bson::Boolean(true),
                Bson::Int64(5_000_000_000), Bson::Array(vec![Bson::Int32(1), Bson::Int32(2)]),
            ]);
            insert_raw(&live_db(APP), "mgj_extra_tagged", vec![doc! { "_id": odd, "name": "raw", "tags": mixed, "owner": "not an id" }]).await;
            let read = e.read(&cx(), CLIENT, None, &s, &odd.to_hex()).await.unwrap();
            assert_eq!(read["tags"], v(&format!(r#"["{t1}","plain","5","2.5","true","5000000000","[1, 2]"]"#)));
            assert_eq!(read["owner"], Value::from("not an id"));
        })
        .await;
    }

    /// The smaller paths: `takeGivenId` for a null or non-hex `_id`, PATCH of a row that is
    /// not there, `readPageAsFlux`, `checkIfExists`, subqueries refused, and `idsReferencing`
    /// over a row whose `_id` is not an ObjectId (`getObjectId` throws: a 500).
    #[tokio::test]
    #[ignore = "needs the local MongoDB"]
    async fn small_paths() {
        run(async {
            let e = mongo_engine();
            let s = plain("small", r#"{"relations":{"owner":{"storageName":"people","relationType":"TO_ONE"}},"schema":{"type":"OBJECT"}}"#);
            let null_id = add(&e, &cx(), &s, r#"{"_id":null,"name":"a"}"#).await;
            let number_id = add(&e, &cx(), &s, r#"{"_id":12345,"name":"b"}"#).await;
            assert_eq!(null_id.len(), 24);
            assert_eq!(number_id.len(), 24);

            let missing = ObjectId::new().to_hex();
            let err = e.update(&cx(), CLIENT, None, &s, data(&format!(r#"{{"_id":"{missing}","name":"x"}}"#)), Some(false)).await.unwrap_err();
            assert_eq!(err.status().as_u16(), 404);
            assert_eq!(err.message(), format!("small with id {missing} not found to update"));

            let q = query(r#"{"sort":{"property":"name"}}"#);
            let rows = e.read_page_rows(&cx(), CLIENT, None, &s, &q).await.unwrap();
            assert_eq!(rows, e.read_page(&cx(), CLIENT, None, &s, &q).await.unwrap().content);
            assert_eq!(rows.len(), 2);

            assert!(e.check_if_exists(&cx(), CLIENT, None, &s, &null_id).await.unwrap());
            assert!(!e.check_if_exists(&cx(), CLIENT, None, &s, &missing).await.unwrap());
            assert!(!e.check_if_exists(&cx(), CLIENT, None, &s, "nope").await.unwrap());

            let sub = query(r#"{"subQueries":[{"relation":"owner"}]}"#);
            let err = e.read_page(&cx(), CLIENT, None, &s, &sub).await.unwrap_err();
            assert_eq!(err.status().as_u16(), 501);
            assert_eq!(err.message(), "subqueries is not supported on the Mongo storage backend yet.");

            let owner = ObjectId::new();
            insert_raw(&live_db(APP), "mgj_extra_small", vec![doc! { "_id": "text-id", "owner": owner }]).await;
            let err = e.ids_referencing(&cx(), CLIENT, None, &s, "owner", false, &owner.to_hex(), 5).await.unwrap_err();
            assert_eq!(err.status().as_u16(), 500);
        })
        .await;
    }

    /// `sanityCheckBuckets`: one real value of an EPOCH_SECONDS field is looked at, and a
    /// milliseconds value is refused rather than bucketed into the year 56000.
    #[tokio::test]
    #[ignore = "needs the local MongoDB"]
    async fn epoch_seconds_are_checked() {
        run(async {
            let e = mongo_engine();
            let schema = r#""schema":{"type":"OBJECT","properties":{"at":{"type":"LONG"}}}"#;
            let by_day = agg(r#"{"groupBy":[{"field":"at","bucket":"DAY","encoding":"EPOCH_SECONDS"}],"aggregations":[{"function":"COUNT","alias":"n"}]}"#);

            let millis = plain("millis", &format!("{{{schema}}}"));
            add(&e, &cx(), &millis, r#"{"at":1767000000000}"#).await;
            let err = e.aggregate(&cx(), CLIENT, None, &millis, &by_day).await.unwrap_err();
            assert_eq!(err.status().as_u16(), 400);
            assert!(
                err.message().contains("field 'at' is declared EPOCH_SECONDS but holds 1767000000000, which is milliseconds"),
                "{}",
                err.message()
            );

            let seconds = plain("seconds", &format!("{{{schema}}}"));
            add(&e, &cx(), &seconds, r#"{"at":1767000000}"#).await;
            add(&e, &cx(), &seconds, r#"{"at":1767000100}"#).await;
            let page = e.aggregate(&cx(), CLIENT, None, &seconds, &by_day).await.unwrap();
            assert_eq!(page.content.len(), 1);
            assert_eq!(page.content[0]["n"], Value::Int(2));
        })
        .await;
    }

    /// `estimatedRowCount`: a blank app or client counts nothing; `system.*` and
    /// `*_version` collections are not counted.
    #[tokio::test]
    #[ignore = "needs the local MongoDB"]
    async fn metering_skips_system_and_history() {
        run(async {
            let e = mongo_engine();
            assert_eq!(e.estimated_row_count(None, " ", CLIENT).await, 0);
            assert_eq!(e.estimated_row_count(None, APP, "").await, 0);
            let s = plain("metered", r#"{"isAudited":true,"schema":{"type":"OBJECT"}}"#);
            add(&e, &cx(), &s, r#"{"name":"a"}"#).await;
            add(&e, &cx(), &s, r#"{"name":"b"}"#).await;
            // A view adds system.views (one document) to the database; the view itself
            // selects nothing, so whatever it counts as is zero.
            mongo_client()
                .await
                .database(&live_db(APP))
                .create_collection("metered_view")
                .view_on("mgj_extra_metered".to_string())
                .pipeline(vec![doc! { "$match": { "name": "nobody" } }])
                .await
                .unwrap();
            let listed = collections(&live_db(APP)).await;
            assert!(listed.contains(&"system.views".to_string()), "{listed:?}");
            let counted = e.estimated_row_count(None, APP, CLIENT).await;
            assert_eq!(counted, 2, "{listed:?}");
        })
        .await;
    }

    /// `lookup::MongoDefinitions` over a scratch core database: definitions as stored,
    /// ids as hex and dates as epoch millis, a client's own definition before SYSTEM's.
    #[tokio::test]
    #[ignore = "needs the local MongoDB"]
    async fn definitions_from_a_core_database() {
        use appdata::engine::{SchemaRepositories, StorageResolver};
        use appdata::lookup::{plain as plain_doc, MongoDefinitions};

        const CORE: &str = "RUSTTEST_mgj_core";
        const LAPP: &str = "mgj_lookup";
        drop_mongo_db(CORE).await;
        guarded(
            async {
                let storage_id = ObjectId::new();
                let at = DateTime::from_millis(1_767_000_000_000);
                insert_raw(
                    CORE,
                    "storage",
                    vec![
                        doc! {
                            "_id": storage_id, "name": "orders", "appCode": LAPP, "clientCode": "SYSTEM", "uniqueName": "sys_orders",
                            "isVersioned": true, "createdAt": at, "relations": { "owner": { "storageName": "people", "relationType": "TO_ONE" } },
                            "schema": { "type": "OBJECT", "properties": { "name": { "type": "STRING" } } },
                        },
                        doc! { "_id": ObjectId::new(), "name": "orders", "appCode": LAPP, "clientCode": CLIENT, "uniqueName": "own_orders" },
                    ],
                )
                .await;
                insert_raw(
                    CORE,
                    "connection",
                    vec![
                        doc! {
                            "_id": ObjectId::new(), "name": "appData", "appCode": LAPP, "clientCode": "SYSTEM", "connectionType": "APP_DATA",
                            "connectionSubType": "MONGO", "connectionDetails": { "url": "mongodb://elsewhere:27017" },
                        },
                        doc! { "_id": ObjectId::new(), "name": "appData", "appCode": LAPP, "clientCode": CLIENT, "connectionType": "MAIL" },
                    ],
                )
                .await;
                insert_raw(
                    CORE,
                    "schema",
                    vec![
                        doc! { "name": "mgj.Address", "appCode": LAPP, "clientCode": "SYSTEM", "definition": { "name": "Address", "type": "OBJECT" } },
                        doc! { "name": "mgj.Phone", "appCode": LAPP, "clientCode": "SYSTEM", "definition": { "name": "Phone", "type": "STRING" } },
                        doc! { "name": "mgj.Phone", "appCode": LAPP, "clientCode": CLIENT, "definition": { "name": "Phone", "type": "LONG" } },
                    ],
                )
                .await;
                let defs = MongoDefinitions::new(mongo_client().await.database(CORE));

                let s = defs.storage("orders", LAPP, "SYSTEM").await.unwrap().unwrap();
                assert_eq!(s.id.as_deref(), Some(storage_id.to_hex().as_str()));
                assert_eq!(s.unique_name, "sys_orders");
                assert!(s.versioned());
                assert!(s.relation("owner").is_some());
                assert!(defs.storage("orders", LAPP, "RUSTTEST_A").await.unwrap().is_none());
                // read_for_tenant: the client's own first, then SYSTEM's.
                assert_eq!(defs.read_for_tenant("orders", LAPP, CLIENT, false).await.unwrap().unwrap().unique_name, "own_orders");
                assert_eq!(defs.read_for_tenant("orders", LAPP, "RUSTTEST_A", true).await.unwrap().unwrap().unique_name, "sys_orders");
                assert!(defs.read_for_tenant("nothing", LAPP, CLIENT, false).await.unwrap().is_none());

                // Exactly this client's APP_DATA connection named appData.
                let c = defs.app_data_connection(LAPP, "SYSTEM").await.unwrap().unwrap();
                assert_eq!(c.connection_sub_type, Some(ConnectionSubType::Mongo));
                assert_eq!(c.detail("url"), Some(&Value::from("mongodb://elsewhere:27017")));
                assert_eq!(c.id.len(), 24);
                assert!(defs.app_data_connection(LAPP, CLIENT).await.unwrap().is_none());

                // Schemas: the client's, else SYSTEM's; through the repository too.
                let own = defs.schema("mgj.Phone", LAPP, CLIENT).await.unwrap().unwrap();
                assert!(own.has_type(SchemaType::Long));
                let inherited = defs.schema("mgj.Address", LAPP, CLIENT).await.unwrap().unwrap();
                assert_eq!(inherited.name.as_deref(), Some("Address"));
                assert!(defs.schema("mgj.None", LAPP, CLIENT).await.unwrap().is_none());
                let repo = defs.for_app(LAPP, CLIENT);
                assert!(repo.find("mgj", "Phone").await.unwrap().unwrap().has_type(SchemaType::Long));
                assert!(repo.find("mgj", "Missing").await.unwrap().is_none());

                let p = plain_doc(&doc! { "id": storage_id, "at": at, "nested": { "list": [storage_id, 1] } });
                assert_eq!(
                    Value::Object(p).to_java_json(),
                    format!(r#"{{"id":"{0}","at":1767000000000,"nested":{{"list":["{0}",1]}}}}"#, storage_id.to_hex())
                );
            },
            drop_mongo_db(CORE),
        )
        .await;
    }
}
