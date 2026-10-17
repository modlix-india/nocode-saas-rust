//! The Java MySQL data-operation, relation and index integration tests (core), and the
//! draft copy of nocode-saas aca9929dd, against the local MySQL in scratch schemas named
//! `RUSTTEST_rtd_*` that each test creates and drops (even when it fails).
//!
//! The core classes drive the engine through `AppDataService`; the ports go straight to
//! `MySqlAppDataService` with the same storages and rows, and leave out what only the
//! policy layer does (its own relation checks and cascades when the database does not
//! enforce a relation, auth gates, refusing an empty copy). Java resets the tenant before
//! every test; so do these, and a fresh engine stands in for `evictAllCaches`.
//!
//! Run with: cargo test -p appdata --test live_mysql_data -- --ignored --test-threads=1

mod support;

use std::collections::HashMap;
use std::sync::Arc;

use appdata::engine::AppDataEngine;
use appdata::model::*;
use appdata::mysql::MySqlAppDataService;
use appdata::value::{Document, Value};
use sqlx::MySqlPool;
use support::*;

fn schema_of(app: &str) -> String {
    format!("{CLIENT}_{app}")
}

async fn scratch_pool() -> MySqlPool {
    let e = mysql_engine(Arc::new(Storages::default()));
    let p = pool(&e).await;
    wait_for_headroom(&p).await;
    p
}

fn num(v: &Value) -> f64 {
    match v {
        Value::Int(i) => *i as f64,
        Value::Double(d) => *d,
        Value::Decimal(d) => d.double_value(),
        other => panic!("not a number: {other:?}"),
    }
}

/// One app's tenant, the storages it resolves, and an engine over them.
struct Fx {
    p: MySqlPool,
    app: &'static str,
    storages: Arc<Storages>,
    e: MySqlAppDataService,
    c: Connection,
}

impl Fx {
    /// Both surfaces of the tenant dropped and a fresh engine.
    async fn fresh(p: &MySqlPool, app: &'static str) -> Fx {
        drop_schemas(p, &[CLIENT], app).await;
        let storages = Arc::new(Storages::default());
        Fx { p: p.clone(), app, e: mysql_engine(storages.clone()), storages, c: conn().await }
    }

    /// `cacheService.evictAllCaches()`: an engine with nothing memoised.
    fn evict_all_caches(&mut self) {
        self.e = mysql_engine(self.storages.clone());
    }

    fn db(&self) -> String {
        schema_of(self.app)
    }

    fn draft_db(&self) -> String {
        format!("{}_draft", self.db())
    }

    async fn put(&self, s: &Storage) {
        self.storages.put(s).await;
    }

    async fn create(&self, s: &Storage, row: &str) -> appdata::AppDataResult<Document> {
        self.e.create(&cx(), CLIENT, Some(&self.c), s, data(row)).await
    }

    async fn id_of(&self, s: &Storage, row: &str) -> String {
        self.create(s, row).await.unwrap()["_id"].java_string()
    }

    async fn delete(&self, s: &Storage, id: &str, delete_version: Option<bool>) -> appdata::AppDataResult<bool> {
        self.e.delete(&cx(), CLIENT, Some(&self.c), s, id, delete_version).await
    }

    async fn read(&self, s: &Storage, q: &str) -> appdata::AppDataResult<Page<Document>> {
        self.e.read_page(&cx(), CLIENT, Some(&self.c), s, &query(q)).await
    }

    async fn aggregate(&self, s: &Storage, q: &str) -> appdata::AppDataResult<Page<Document>> {
        self.e.aggregate(&cx(), CLIENT, Some(&self.c), s, &agg(q)).await
    }

    async fn count(&self, sql: &str) -> i64 {
        appdata::mysql::db::count_raw(&self.p, sql).await.unwrap()
    }

    async fn rows_in(&self, db: &str, table: &str) -> i64 {
        self.count(&format!("SELECT COUNT(*) FROM `{db}`.`{table}`")).await
    }
}

// ------------------------------------------------------------------ MySQLArrayMatchIntegrationTest

mod mysql_array_match_integration_test {
    use super::*;

    const APP: &str = "rtd_arr";

    fn articles() -> Storage {
        storage(APP, "articles", r#"{"version":1,"schema":{"type":"OBJECT","properties":{"title":{"type":"STRING","maxLength":40},"tags":{"type":"ARRAY"},"scores":{"type":"ARRAY"}}}}"#)
    }

    async fn titles(f: &Fx, condition: &str) -> Vec<String> {
        let page = f.read(&articles(), &format!(r#"{{"condition":{condition},"size":50}}"#)).await.unwrap();
        let mut out: Vec<String> = page.content.iter().map(|r| r["title"].java_string()).collect();
        out.sort();
        out
    }

    fn matching(field: &str, op: &str, value: &str) -> String {
        format!(r#"{{"field":"{field}","operator":"MATCH","matchOperator":"{op}","value":{value}}}"#)
    }

    fn all(values: &str) -> String {
        format!(r#"{{"field":"tags","operator":"MATCH_ALL","multiValue":{values}}}"#)
    }

    #[tokio::test]
    #[ignore = "needs the local MySQL"]
    async fn match_and_match_all_over_json_arrays() {
        let p = scratch_pool().await;
        drop_schemas(&p, &[CLIENT], APP).await;
        guarded(
            async {
                let f = Fx::fresh(&p, APP).await;
                f.put(&articles()).await;
                for (title, tags, scores) in [("a", r#"["red","blue"]"#, "[1,5,9]"), ("b", r#"["green"]"#, "[2,3]"), ("c", r#"["red","green"]"#, "[10,20]")] {
                    f.create(&articles(), &format!(r#"{{"title":"{title}","tags":{tags},"scores":{scores}}}"#)).await.unwrap();
                }

                // Match
                assert_eq!(titles(&f, &matching("tags", "EQUALS", r#""red""#)).await, ["a", "c"]);
                assert!(titles(&f, &matching("tags", "EQUALS", r#""purple""#)).await.is_empty());
                assert_eq!(titles(&f, &matching("tags", "LIKE", r#""gre%""#)).await, ["b", "c"]);
                assert_eq!(titles(&f, &matching("tags", "STRING_LOOSE_EQUAL", r#""lu""#)).await, ["a"]);
                assert_eq!(titles(&f, &matching("tags", "STRING_LOOSE_EQUAL", r#""e""#)).await, ["a", "b", "c"]);
                assert_eq!(titles(&f, &matching("scores", "GREATER_THAN", "8")).await, ["a", "c"]);
                assert_eq!(titles(&f, &matching("scores", "GREATER_THAN_EQUAL", "10")).await, ["c"]);
                assert_eq!(titles(&f, &matching("scores", "LESS_THAN", "4")).await, ["a", "b"]);
                let negated = r#"{"field":"tags","operator":"MATCH","matchOperator":"EQUALS","value":"red","negate":true}"#;
                assert_eq!(titles(&f, negated).await, ["b"]);

                // MatchAll
                assert_eq!(titles(&f, &all(r#"["red","green"]"#)).await, ["c"]);
                assert_eq!(titles(&f, &matching("tags", "EQUALS", r#""red""#)).await, ["a", "c"]);
                assert_eq!(titles(&f, &all(r#"["green"]"#)).await, ["b", "c"]);
            },
            drop_schemas(&p, &[CLIENT], APP),
        )
        .await;
    }
}

// ------------------------------------------------------------------ MySQLColumnDefinitionIntegrationTest

mod mysql_column_definition_integration_test {
    use super::*;

    const APP: &str = "rtd_cols";
    const TABLE: &str = "rtd_cols_products";

    fn products(definitions: Option<&str>) -> Storage {
        let defs = definitions.map(|d| format!(r#","columnDefinitions":{d}"#)).unwrap_or_default();
        storage(
            APP,
            "products",
            &format!(r#"{{"version":1{defs},"schema":{{"type":"OBJECT","properties":{{"price":{{"type":"STRING","format":"DECIMAL"}},"sku":{{"type":"STRING","maxLength":20}}}}}}}}"#),
        )
    }

    async fn collation(f: &Fx, column: &str) -> String {
        scalar(&f.p, &format!("SELECT COLLATION_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = '{}' AND TABLE_NAME = '{TABLE}' AND COLUMN_NAME = '{column}'", f.db())).await
    }

    #[tokio::test]
    #[ignore = "needs the local MySQL"]
    async fn declared_column_shapes_reach_the_table() {
        let p = scratch_pool().await;
        drop_schemas(&p, &[CLIENT], APP).await;
        guarded(
            async {
                let price_10_2 = r#"{"price":{"mysql":{"type":"DECIMAL","precision":10,"scale":2}}}"#;

                // theDefault
                let f = Fx::fresh(&p, APP).await;
                f.create(&products(None), r#"{"price":"10.50","sku":"A1"}"#).await.unwrap();
                assert_eq!(column_type(&p, &f.db(), TABLE, "price").await, "decimal(19,4) YES");

                // declaredDecimal
                let f = Fx::fresh(&p, APP).await;
                f.create(&products(Some(price_10_2)), r#"{"price":"10.50","sku":"A1"}"#).await.unwrap();
                assert_eq!(column_type(&p, &f.db(), TABLE, "price").await, "decimal(10,2) YES");

                // roundTrip
                let f = Fx::fresh(&p, APP).await;
                let s = products(Some(price_10_2));
                let written = f.create(&s, r#"{"price":"10.5","sku":"A1"}"#).await.unwrap();
                assert_eq!(written["price"], Value::from("10.50"), "text at the declared scale");
                let id = written["_id"].java_string();
                let again = f
                    .e
                    .update(&cx(), CLIENT, Some(&f.c), &s, data(&format!(r#"{{"_id":"{id}","price":"10.50","sku":"A2"}}"#)), Some(true))
                    .await
                    .unwrap();
                assert_eq!(again["price"], Value::from("10.50"));
                assert_eq!(again["sku"], Value::from("A2"));

                // collation
                let f = Fx::fresh(&p, APP).await;
                f.create(&products(Some(r#"{"sku":{"mysql":{"type":"VARCHAR","length":32,"collation":"utf8mb4_bin"}}}"#)), r#"{"price":"1.00","sku":"A1"}"#).await.unwrap();
                assert_eq!(column_type(&p, &f.db(), TABLE, "sku").await, "varchar(32) YES");
                assert_eq!(collation(&f, "sku").await, "utf8mb4_bin");

                // onlyTheDeclaredField
                let f = Fx::fresh(&p, APP).await;
                f.create(&products(Some(r#"{"price":{"mysql":{"type":"DECIMAL","precision":8,"scale":3}}}"#)), r#"{"price":"1.000","sku":"A1"}"#).await.unwrap();
                assert_eq!(column_type(&p, &f.db(), TABLE, "price").await, "decimal(8,3) YES");
                assert_eq!(column_type(&p, &f.db(), TABLE, "sku").await, "varchar(20) YES");
            },
            drop_schemas(&p, &[CLIENT], APP),
        )
        .await;
    }
}

// ------------------------------------------------------------------ MySQLDataOperationsIntegrationTest

mod mysql_data_operations_integration_test {
    use super::*;

    const APP: &str = "rtd_ops";
    const TABLE: &str = "rtd_ops_sales";

    fn sales(region_length: i32) -> Storage {
        storage(
            APP,
            "sales",
            &format!(
                r#"{{"version":1,"isVersioned":true,"schema":{{"type":"OBJECT","properties":{{
                    "region":{{"type":"STRING","maxLength":{region_length}}},"amount":{{"type":"DOUBLE"}},
                    "placedAt":{{"type":"STRING","format":"DATETIME"}},"ts":{{"type":"LONG"}}}}}}}}"#
            ),
        )
    }

    async fn write(f: &Fx, region: &str, amount: f64, placed_at: &str, ts: i64) -> Document {
        f.create(&sales(20), &format!(r#"{{"region":"{region}","amount":{amount},"placedAt":"{placed_at}","ts":{ts}}}"#)).await.unwrap()
    }

    async fn given_rows(f: &Fx) {
        write(f, "north", 100.0, "2026-01-15T10:00:00", 1768471200).await;
        write(f, "north", 200.0, "2026-01-21T10:00:00", 1768903200).await;
        write(f, "south", 50.0, "2026-02-03T10:00:00", 1770112800).await;
        write(f, "east", 400.0, "2026-02-28T23:30:00", 1772321400).await;
    }

    async fn fresh(p: &MySqlPool) -> Fx {
        let f = Fx::fresh(p, APP).await;
        f.put(&sales(20)).await;
        f
    }

    fn refused(r: appdata::AppDataResult<Page<Document>>) -> String {
        r.err().expect("refused").message()
    }

    #[tokio::test]
    #[ignore = "needs the local MySQL"]
    async fn aggregates_history_status_and_the_draft_surface() {
        let p = scratch_pool().await;
        drop_schemas(&p, &[CLIENT], APP).await;
        guarded(
            async {
                let s = sales(20);

                // Aggregate.groupAndSum
                let f = fresh(&p).await;
                given_rows(&f).await;
                let page = f.aggregate(&s, r#"{"groupBy":[{"field":"region"}],"aggregations":[{"function":"SUM","field":"amount","alias":"total"}],"count":true}"#).await.unwrap();
                assert_eq!(page.content.len(), 3);
                assert_eq!(page.total, 3, "the total is groups, not rows");
                assert_eq!(num(&page.content.iter().find(|r| r["region"] == Value::from("north")).unwrap()["total"]), 300.0);

                // Aggregate.dateColumnBucket
                let by_date = f.aggregate(&s, r#"{"groupBy":[{"field":"placedAt","bucket":"MONTH","alias":"m"}],"aggregations":[{"function":"COUNT","alias":"n"}]}"#).await.unwrap();
                assert_eq!(by_date.content.len(), 2);

                // Aggregate.epochNeedsEncoding
                let m = refused(f.aggregate(&s, r#"{"groupBy":[{"field":"ts","bucket":"MONTH"}],"aggregations":[{"function":"COUNT","alias":"n"}]}"#).await);
                assert!(m.contains("encoding"), "{m}");

                // Aggregate.encodingOnADateColumn
                let m = refused(f.aggregate(&s, r#"{"groupBy":[{"field":"placedAt","bucket":"MONTH","encoding":"EPOCH_SECONDS"}],"aggregations":[{"function":"COUNT","alias":"n"}]}"#).await);
                assert!(m.contains("needs no encoding"), "{m}");

                // Aggregate.epochAgreesWithTheDateColumn
                let by_epoch = f.aggregate(&s, r#"{"groupBy":[{"field":"ts","bucket":"MONTH","encoding":"EPOCH_SECONDS","alias":"m"}],"aggregations":[{"function":"COUNT","alias":"n"}]}"#).await.unwrap();
                assert_eq!(by_date.content.len(), by_epoch.content.len());

                // Aggregate.undeclaredField
                let m = refused(f.aggregate(&s, r#"{"groupBy":[{"field":"nosuch"}],"aggregations":[{"function":"COUNT","alias":"n"}]}"#).await);
                assert!(m.contains("declares no field"), "{m}");

                // Aggregate.sumOnText
                let m = refused(f.aggregate(&s, r#"{"aggregations":[{"function":"SUM","field":"region","alias":"total"}]}"#).await);
                assert!(m.contains("casts to zero"), "{m}");

                // Aggregate.havingAndSort
                let page = f
                    .aggregate(&s, r#"{"groupBy":[{"field":"region"}],"aggregations":[{"function":"SUM","field":"amount","alias":"total"}],"having":{"field":"total","value":100,"operator":"GREATER_THAN"},"sort":[{"property":"total","direction":"DESC"}]}"#)
                    .await
                    .unwrap();
                assert_eq!(page.content.len(), 2);
                assert_eq!(page.content[0]["region"], Value::from("east"));

                // History.createThenUpdate
                let f = fresh(&p).await;
                let created = write(&f, "north", 100.0, "2026-01-15T10:00:00", 1768471200).await;
                let id = created["_id"].java_string();
                let mut edit = created.clone();
                edit.insert("amount".into(), Value::Double(150.0));
                f.e.update(&cx(), CLIENT, Some(&f.c), &s, DataObject::of(edit), Some(false)).await.unwrap();
                let history = f.e.read_page_version(&cx(), CLIENT, Some(&f.c), &s, &id, &query(r#"{"count":true}"#), Some(true)).await.unwrap();
                assert_eq!(history.content.len(), 2);
                assert_eq!(history.content[0]["operation"], Value::from("UPDATE"), "newest first");
                assert_eq!(history.content[1]["operation"], Value::from("CREATE"));

                // History.snapshotIsAnObject
                let f = fresh(&p).await;
                let id = write(&f, "north", 100.0, "2026-01-15T10:00:00", 1768471200).await["_id"].java_string();
                let history = f.e.read_page_version(&cx(), CLIENT, Some(&f.c), &s, &id, &Query::default(), Some(true)).await.unwrap();
                let snapshot = history.content[0]["object"].as_object().expect("an object, not text");
                assert_eq!(snapshot["region"], Value::from("north"));

                // History.auditOnly
                let history = f.e.read_page_version(&cx(), CLIENT, Some(&f.c), &s, &id, &Query::default(), Some(false)).await.unwrap();
                assert!(!history.content[0].contains_key("object"));
                assert!(!history.content[0]["operation"].is_null());

                // History.readOneVersion
                let history = f.e.read_page_version(&cx(), CLIENT, Some(&f.c), &s, &id, &Query::default(), Some(true)).await.unwrap();
                let version_id = history.content[0]["_id"].java_string();
                assert_eq!(f.e.read_version(&cx(), CLIENT, Some(&f.c), &s, &version_id).await.unwrap()["operation"], Value::from("CREATE"));

                // History.deleteRecordsOrPurges
                let f = fresh(&p).await;
                let kept = write(&f, "north", 100.0, "2026-01-15T10:00:00", 1768471200).await["_id"].java_string();
                let purged = write(&f, "south", 50.0, "2026-02-03T10:00:00", 1770112800).await["_id"].java_string();
                f.delete(&s, &kept, Some(false)).await.unwrap();
                f.delete(&s, &purged, Some(true)).await.unwrap();
                let versions = format!("`{}`.`{TABLE}_version`", f.db());
                assert_eq!(f.count(&format!("SELECT COUNT(*) FROM {versions} WHERE `objectId` = '{kept}'")).await, 2, "the create and the delete");
                assert_eq!(f.count(&format!("SELECT COUNT(*) FROM {versions} WHERE `objectId` = '{purged}'")).await, 0, "asked to be purged");

                // Status.reportsTenants
                let f = fresh(&p).await;
                given_rows(&f).await;
                let status = f.e.migration_status(Some(&f.c), APP, &s).await.unwrap();
                assert_eq!(status.len(), 1);
                assert!(status[0].state.is_none(), "{}", status[0].describe());
                assert!(status[0].describe().contains("not attempted"));

                // Status.reportsApplied: the storage edit, and the reconcile it triggers.
                f.put(&sales(60)).await;
                f.e.reconcile(Some(&f.c), APP, &sales(60), Some("rusttest")).await.unwrap();
                let status = f.e.migration_status(Some(&f.c), APP, &sales(60)).await.unwrap();
                assert_eq!(status.len(), 1);
                assert_eq!(status[0].state, Some(appdata::mysql::journal::MigrationState::Applied), "{}", status[0].describe());

                // Rest.devModeCounts
                let f = fresh(&p).await;
                given_rows(&f).await;
                let north = query(r#"{"condition":{"field":"region","value":"north"}}"#);
                assert_eq!(f.e.delete_by_filter(&cx(), CLIENT, Some(&f.c), &s, &north, Some(true), None).await.unwrap(), 2);
                assert_eq!(f.rows_in(&f.db(), TABLE).await, 4);

                // Rest.deleteByFilter
                assert_eq!(f.e.delete_by_filter(&cx(), CLIENT, Some(&f.c), &s, &north, Some(false), None).await.unwrap(), 2);
                assert_eq!(f.rows_in(&f.db(), TABLE).await, 2);

                // Rest.copyLiveToDraft
                let f = fresh(&p).await;
                given_rows(&f).await;
                assert_eq!(f.e.copy_live_to_draft(&cx(), CLIENT, Some(&f.c), &s, Some(true)).await.unwrap(), 4);
                assert_eq!(f.rows_in(&f.draft_db(), TABLE).await, 4);

                // Rest.copyNothing: the engine answers 0 and fills nothing (the 400 is the service's).
                let f = fresh(&p).await;
                assert_eq!(f.e.copy_live_to_draft(&cx(), CLIENT, Some(&f.c), &s, Some(true)).await.unwrap(), 0);
                assert_eq!(f.count(&format!("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = '{}' AND TABLE_NAME = '{TABLE}' AND TABLE_ROWS > 0", f.draft_db())).await, 0);

                // Rest.dropDraftStorage
                let f = fresh(&p).await;
                given_rows(&f).await;
                f.e.copy_live_to_draft(&cx(), CLIENT, Some(&f.c), &s, Some(true)).await.unwrap();
                assert!(f.e.drop_draft_storage(&cx(), CLIENT, Some(&f.c), &s).await.unwrap());
                assert_eq!(f.count(&format!("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = '{}' AND TABLE_NAME LIKE '{TABLE}%'", f.draft_db())).await, 0);
                assert_eq!(f.rows_in(&f.db(), TABLE).await, 4, "the live table is untouched");

                // Rest.dropDraftDatabase
                let f = fresh(&p).await;
                given_rows(&f).await;
                f.e.copy_live_to_draft(&cx(), CLIENT, Some(&f.c), &s, Some(true)).await.unwrap();
                assert!(f.e.drop_draft_database(Some(&f.c), APP, CLIENT).await.unwrap());
                assert_eq!(f.count(&format!("SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = '{}'", f.draft_db())).await, 0);
                assert_eq!(f.count(&format!("SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = '{}'", f.db())).await, 1);
            },
            drop_schemas(&p, &[CLIENT], APP),
        )
        .await;
    }
}

// ------------------------------------------------------------------ MySQLIndexIntegrationTest

mod mysql_index_integration_test {
    use super::*;

    const APP: &str = "rtd_idx";
    const BOOKS: &str = "rtd_idx_books";

    fn authors() -> Storage {
        storage(APP, "authors", r#"{"version":1,"schema":{"type":"OBJECT","properties":{"name":{"type":"STRING","maxLength":40}}}}"#)
    }

    fn books(indexes: Option<&str>, text_fields: Option<&str>, with_relation: bool) -> Storage {
        let mut extra = String::new();
        if let Some(i) = indexes {
            extra.push_str(&format!(r#","indexes":{i}"#));
        }
        if let Some(t) = text_fields {
            extra.push_str(&format!(r#","textIndexFields":{t}"#));
        }
        if with_relation {
            extra.push_str(r#","relations":{"author":{"storageName":"authors","relationType":"TO_ONE","fieldName":"_id"}}"#);
        }
        storage(
            APP,
            "books",
            &format!(r#"{{"version":1{extra},"schema":{{"type":"OBJECT","properties":{{"title":{{"type":"STRING","maxLength":120}},"blurb":{{"type":"STRING","maxLength":400}},"isbn":{{"type":"STRING","maxLength":20}}}}}}}}"#),
        )
    }

    fn index(unique: bool, fields: &[&str]) -> String {
        let fields: Vec<String> = fields.iter().map(|f| format!(r#"{{"fieldName":"{f}"}}"#)).collect();
        format!(r#"{{"unique":{unique},"fields":[{}]}}"#, fields.join(","))
    }

    async fn given(p: &MySqlPool, s: &Storage) -> Fx {
        let f = Fx::fresh(p, APP).await;
        f.put(&authors()).await;
        f.put(s).await;
        f
    }

    async fn write_book(f: &Fx, s: &Storage, title: &str, blurb: &str, isbn: &str) -> appdata::AppDataResult<Document> {
        f.create(s, &format!(r#"{{"title":"{title}","blurb":"{blurb}","isbn":"{isbn}"}}"#)).await
    }

    async fn names(f: &Fx, sql: &str) -> Vec<String> {
        rows(&f.p, sql).await.iter().map(|r| r.values().next().unwrap().java_string()).collect()
    }

    async fn index_names(f: &Fx) -> Vec<String> {
        names(f, &format!("SELECT DISTINCT INDEX_NAME FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = '{}' AND TABLE_NAME = '{BOOKS}' ORDER BY INDEX_NAME", f.db())).await
    }

    async fn index_columns(f: &Fx, index: &str) -> Vec<String> {
        names(f, &format!("SELECT COLUMN_NAME FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = '{}' AND TABLE_NAME = '{BOOKS}' AND INDEX_NAME = '{index}' ORDER BY SEQ_IN_INDEX", f.db())).await
    }

    #[tokio::test]
    #[ignore = "needs the local MySQL"]
    async fn declared_text_and_relation_indexes() {
        let p = scratch_pool().await;
        drop_schemas(&p, &[CLIENT], APP).await;
        guarded(
            async {
                // Declared.created
                let s = books(Some(&format!(r#"{{"byTitle":{}}}"#, index(false, &["title"]))), None, false);
                let f = given(&p, &s).await;
                write_book(&f, &s, "Dune", "sand", "1").await.unwrap();
                assert!(index_names(&f).await.contains(&"byTitle".to_string()), "{:?}", index_names(&f).await);
                assert_eq!(index_columns(&f, "byTitle").await, ["title"]);

                // Declared.idempotent
                let after = index_names(&f).await;
                write_book(&f, &s, "Elantris", "chalk", "2").await.unwrap();
                assert_eq!(after, index_names(&f).await);

                // Declared.droppedWhenRemoved: the definition changes and its table caches go.
                let without = books(Some("{}"), None, false);
                f.put(&without).await;
                f.e.evict_table_caches(&without).await;
                write_book(&f, &without, "Mistborn", "ash", "3").await.unwrap();
                assert!(!index_names(&f).await.contains(&"byTitle".to_string()), "{:?}", index_names(&f).await);

                // Declared.compound
                let s = books(Some(&format!(r#"{{"byTitleIsbn":{}}}"#, index(false, &["title", "isbn"]))), None, false);
                let f = given(&p, &s).await;
                write_book(&f, &s, "Dune", "sand", "1").await.unwrap();
                assert_eq!(index_columns(&f, "byTitleIsbn").await, ["title", "isbn"]);

                // Declared.uniqueIsEnforced
                let s = books(Some(&format!(r#"{{"byIsbn":{}}}"#, index(true, &["isbn"]))), None, false);
                let f = given(&p, &s).await;
                write_book(&f, &s, "Dune", "sand", "1").await.unwrap();
                assert!(write_book(&f, &s, "Dune Again", "more sand", "1").await.is_err());

                // TextSearch.fullTextIndex
                let s = books(None, Some(r#"["title","blurb"]"#), false);
                let f = given(&p, &s).await;
                write_book(&f, &s, "Dune", "a story about sand", "1").await.unwrap();
                assert!(index_names(&f).await.contains(&"ft_all".to_string()));
                assert_eq!(
                    scalar(&p, &format!("SELECT INDEX_TYPE FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = '{}' AND TABLE_NAME = '{BOOKS}' AND INDEX_NAME = 'ft_all' LIMIT 1", f.db())).await,
                    "FULLTEXT"
                );

                // TextSearch.textSearchWorks
                write_book(&f, &s, "Elantris", "a story about chalk", "2").await.unwrap();
                let page = f.read(&s, r#"{"page":0,"size":10,"condition":{"field":"blurb","operator":"TEXT_SEARCH","value":"sand"}}"#).await.unwrap();
                assert_eq!(page.content.len(), 1, "{:?}", page.content);
                assert_eq!(page.content[0]["title"], Value::from("Dune"));

                // TextSearch.refusedWithoutDeclaration
                let s = books(None, None, false);
                let f = given(&p, &s).await;
                write_book(&f, &s, "Dune", "sand", "1").await.unwrap();
                let e = f.read(&s, r#"{"page":0,"size":10,"condition":{"field":"blurb","operator":"TEXT_SEARCH","value":"sand"}}"#).await.unwrap_err();
                assert!(e.message().contains("textIndexFields"), "{}", e.message());

                // Relations.relationIndexed
                let s = books(None, None, true);
                let f = given(&p, &s).await;
                write_book(&f, &s, "Dune", "sand", "1").await.unwrap();
                assert!(index_columns(&f, "rel_author").await.contains(&"author".to_string()), "{:?}", index_names(&f).await);

                // Relations.declaredWins
                let s = books(Some(&format!(r#"{{"byAuthor":{}}}"#, index(false, &["author"]))), None, true);
                let f = given(&p, &s).await;
                write_book(&f, &s, "Dune", "sand", "1").await.unwrap();
                let names = index_names(&f).await;
                assert!(names.contains(&"byAuthor".to_string()), "{names:?}");
                assert!(!names.contains(&"rel_author".to_string()), "{names:?}");
            },
            drop_schemas(&p, &[CLIENT], APP),
        )
        .await;
    }
}

// ------------------------------------------------------------------ MySQLRelationConstraintIntegrationTest

mod mysql_relation_constraint_integration_test {
    use super::*;

    const APP: &str = "rtd_rel";
    const ORDERS: &str = "rtd_rel_orders";

    fn customers(versioned: bool) -> Storage {
        storage(APP, "customers", &format!(r#"{{"version":1,"isVersioned":{versioned},"schema":{{"type":"OBJECT","properties":{{"name":{{"type":"STRING","maxLength":40}}}}}}}}"#))
    }

    fn tags() -> Storage {
        storage(APP, "tags", r#"{"version":1,"schema":{"type":"OBJECT","properties":{"label":{"type":"STRING","maxLength":20}}}}"#)
    }

    fn orders(on_customer: &str, on_tags: &str, versioned: bool) -> Storage {
        storage(
            APP,
            "orders",
            &format!(
                r#"{{"version":1,"isVersioned":{versioned},"relations":{{
                    "customer":{{"storageName":"customers","relationType":"TO_ONE","fieldName":"_id","deleteConstraint":"{on_customer}"}},
                    "labels":{{"storageName":"tags","relationType":"TO_MANY","fieldName":"_id","deleteConstraint":"{on_tags}"}}}},
                    "schema":{{"type":"OBJECT","properties":{{"amount":{{"type":"DOUBLE"}}}}}}}}"#
            ),
        )
    }

    /// The three storages as the definition now says, put where the engine resolves them.
    async fn define(f: &Fx, on_customer: &str, on_tags: &str, orders_versioned: bool, customers_versioned: bool) -> (Storage, Storage, Storage) {
        let (c, t, o) = (customers(customers_versioned), tags(), orders(on_customer, on_tags, orders_versioned));
        f.put(&c).await;
        f.put(&t).await;
        f.put(&o).await;
        (c, t, o)
    }

    async fn delete_rule(f: &Fx) -> Option<String> {
        let rule = scalar(
            &f.p,
            &format!(
                "SELECT r.DELETE_RULE FROM information_schema.REFERENTIAL_CONSTRAINTS r JOIN information_schema.KEY_COLUMN_USAGE k ON k.CONSTRAINT_NAME = r.CONSTRAINT_NAME AND k.CONSTRAINT_SCHEMA = r.CONSTRAINT_SCHEMA WHERE r.CONSTRAINT_SCHEMA = '{}' AND k.TABLE_NAME = '{ORDERS}' AND k.COLUMN_NAME = 'customer'",
                f.db()
            ),
        )
        .await;
        Some(rule).filter(|r| !r.is_empty())
    }

    async fn write_order(f: &Fx, o: &Storage, amount: f64, customer: Option<&str>, labels: Option<&[&str]>) {
        let mut row = doc(&format!(r#"{{"amount":{amount}}}"#));
        if let Some(c) = customer {
            row.insert("customer".into(), Value::from(c));
        }
        if let Some(l) = labels {
            row.insert("labels".into(), Value::Array(l.iter().map(|x| Value::from(*x)).collect()));
        }
        f.e.create(&cx(), CLIENT, Some(&f.c), o, DataObject::of(row)).await.unwrap();
    }

    async fn enforces(f: &Fx, o: &Storage, field: &str) -> bool {
        let relation = o.relation(field).unwrap().clone();
        f.e.enforces_relation_constraint(&cx(), CLIENT, Some(&f.c), o, field, &relation).await.unwrap()
    }

    #[tokio::test]
    #[ignore = "needs the local MySQL"]
    async fn delete_constraints_as_real_foreign_keys() {
        let p = scratch_pool().await;
        drop_schemas(&p, &[CLIENT], APP).await;
        guarded(
            async {
                let customers_table = "rtd_rel_customers";

                // Nothing.noKey
                let f = Fx::fresh(&p, APP).await;
                let (c, _, o) = define(&f, "NOTHING", "NOTHING", false, false).await;
                let asha = f.id_of(&c, r#"{"name":"Asha"}"#).await;
                write_order(&f, &o, 100.0, Some(&asha), None).await;
                assert_eq!(delete_rule(&f).await, None);
                // Nothing.deleteAllowed
                assert!(f.delete(&c, &asha, None).await.unwrap());
                assert_eq!(f.rows_in(&f.db(), ORDERS).await, 1);

                // Restrict.realKey
                let f = Fx::fresh(&p, APP).await;
                let (c, _, o) = define(&f, "RESTRICT", "NOTHING", false, false).await;
                let asha = f.id_of(&c, r#"{"name":"Asha"}"#).await;
                let bo = f.id_of(&c, r#"{"name":"Bo"}"#).await;
                write_order(&f, &o, 100.0, Some(&asha), None).await;
                assert_eq!(delete_rule(&f).await.as_deref(), Some("RESTRICT"));
                assert!(enforces(&f, &o, "customer").await, "the database enforces it, so the service stands down");
                // Restrict.refusesTheDelete, and RefusedDelete.cleanError
                let e = f.delete(&c, &asha, None).await.unwrap_err();
                assert_eq!(e.status().as_u16(), 400, "{}", e.message());
                assert!(!e.message().contains("fk_"), "{}", e.message());
                assert_eq!(f.rows_in(&f.db(), customers_table).await, 2);
                // Restrict.allowsUnreferenced
                assert!(f.delete(&c, &bo, None).await.unwrap());
                // Restrict.holdsAgainstRawSql
                assert!(appdata::mysql::db::execute_raw(&p, &format!("DELETE FROM `{}`.`{customers_table}` WHERE `_id` = '{asha}'", f.db())).await.is_err());

                // Cascade.cascades and Cascade.inTheDatabase
                let f = Fx::fresh(&p, APP).await;
                let (c, _, o) = define(&f, "CASCADE", "NOTHING", false, false).await;
                let asha = f.id_of(&c, r#"{"name":"Asha"}"#).await;
                let bo = f.id_of(&c, r#"{"name":"Bo"}"#).await;
                write_order(&f, &o, 100.0, Some(&asha), None).await;
                write_order(&f, &o, 200.0, Some(&asha), None).await;
                write_order(&f, &o, 50.0, Some(&bo), None).await;
                assert_eq!(delete_rule(&f).await.as_deref(), Some("CASCADE"));
                assert!(f.delete(&c, &asha, None).await.unwrap());
                assert_eq!(f.rows_in(&f.db(), ORDERS).await, 1);

                // Cascade.versionedChildStaysInTheService: no key, so the service must cascade
                // (that half is AppDataService's); the engine says it is not enforcing.
                let f = Fx::fresh(&p, APP).await;
                let (c, _, o) = define(&f, "CASCADE", "NOTHING", true, false).await;
                let asha = f.id_of(&c, r#"{"name":"Asha"}"#).await;
                write_order(&f, &o, 100.0, Some(&asha), None).await;
                write_order(&f, &o, 200.0, Some(&asha), None).await;
                assert_eq!(delete_rule(&f).await, None);
                assert!(!enforces(&f, &o, "customer").await);
                assert_eq!(f.e.count_referencing(&cx(), CLIENT, Some(&f.c), &o, "customer", false, &asha).await.unwrap(), 2);

                // ToMany.noKey
                let f = Fx::fresh(&p, APP).await;
                let (_, t, o) = define(&f, "NOTHING", "RESTRICT", false, false).await;
                let urgent = f.id_of(&t, r#"{"label":"urgent"}"#).await;
                let spare = f.id_of(&t, r#"{"label":"spare"}"#).await;
                write_order(&f, &o, 100.0, None, Some(&[&urgent])).await;
                let keys = f
                    .count(&format!("SELECT COUNT(*) FROM information_schema.KEY_COLUMN_USAGE WHERE CONSTRAINT_SCHEMA = '{}' AND TABLE_NAME = '{ORDERS}' AND COLUMN_NAME = 'labels' AND REFERENCED_TABLE_NAME IS NOT NULL", f.db()))
                    .await;
                assert_eq!(keys, 0);
                // ToMany.serviceRefuses: the engine half, the count the service refuses on,
                // matched inside the JSON array.
                assert!(!enforces(&f, &o, "labels").await);
                assert_eq!(f.e.count_referencing(&cx(), CLIENT, Some(&f.c), &o, "labels", true, &urgent).await.unwrap(), 1);
                assert_eq!(f.e.ids_referencing(&cx(), CLIENT, Some(&f.c), &o, "labels", true, &urgent, 10).await.unwrap().len(), 1);
                assert_eq!(f.e.count_referencing(&cx(), CLIENT, Some(&f.c), &o, "labels", true, &spare).await.unwrap(), 0);
                // ToMany.unreferencedGoes
                assert!(f.delete(&t, &spare, None).await.unwrap());

                // Changing.keyIsDropped
                let mut f = Fx::fresh(&p, APP).await;
                let (c, _, o) = define(&f, "RESTRICT", "NOTHING", false, false).await;
                write_order(&f, &o, 100.0, Some(&f.id_of(&c, r#"{"name":"Asha"}"#).await), None).await;
                assert_eq!(delete_rule(&f).await.as_deref(), Some("RESTRICT"));
                let (c, _, o) = define(&f, "NOTHING", "NOTHING", false, false).await;
                f.evict_all_caches();
                write_order(&f, &o, 200.0, Some(&f.id_of(&c, r#"{"name":"Bo"}"#).await), None).await;
                assert_eq!(delete_rule(&f).await, None);

                // Changing.keyIsAdded
                let mut f = Fx::fresh(&p, APP).await;
                let (c, _, o) = define(&f, "NOTHING", "NOTHING", false, false).await;
                write_order(&f, &o, 100.0, Some(&f.id_of(&c, r#"{"name":"Asha"}"#).await), None).await;
                assert_eq!(delete_rule(&f).await, None);
                let (c, _, o) = define(&f, "RESTRICT", "NOTHING", false, false).await;
                f.evict_all_caches();
                write_order(&f, &o, 200.0, Some(&f.id_of(&c, r#"{"name":"Bo"}"#).await), None).await;
                assert_eq!(delete_rule(&f).await.as_deref(), Some("RESTRICT"));

                // RefusedDelete.historyIsIntact
                let f = Fx::fresh(&p, APP).await;
                let (c, _, o) = define(&f, "RESTRICT", "NOTHING", false, true).await;
                let asha = f.id_of(&c, r#"{"name":"Asha"}"#).await;
                write_order(&f, &o, 100.0, Some(&asha), None).await;
                let before = f.rows_in(&f.db(), "rtd_rel_customers_version").await;
                assert!(before > 0);
                assert!(f.delete(&c, &asha, Some(true)).await.is_err());
                assert_eq!(f.rows_in(&f.db(), "rtd_rel_customers_version").await, before);
                assert_eq!(f.rows_in(&f.db(), customers_table).await, 1);
                // RefusedDelete.noPhantomVersion
                assert!(f.delete(&c, &asha, None).await.is_err());
                assert_eq!(f.count(&format!("SELECT COUNT(*) FROM `{}`.`rtd_rel_customers_version` WHERE `operation` = 'DELETE'", f.db())).await, 0);

                // KeyBlocked.keyIsNotAdded: a RESTRICT declared over rows that already break it.
                let mut f = Fx::fresh(&p, APP).await;
                let (c, _, o) = define(&f, "NOTHING", "NOTHING", false, false).await;
                write_order(&f, &o, 100.0, Some(&f.id_of(&c, r#"{"name":"Asha"}"#).await), None).await;
                exec(&p, &format!("UPDATE `{}`.`{ORDERS}` SET `customer` = 'NOTAREALIDNOTAREALIDNOTARE'", f.db())).await;
                let (c, _, o) = define(&f, "RESTRICT", "NOTHING", false, false).await;
                f.evict_all_caches();
                let bo = f.id_of(&c, r#"{"name":"Bo"}"#).await;
                write_order(&f, &o, 200.0, Some(&bo), None).await;
                assert_eq!(delete_rule(&f).await, None);
                assert!(f.rows_in(&f.db(), ORDERS).await > 0);
                // KeyBlocked.serviceTakesItBack: the table has no key, so the engine says so
                // and the service enforces the RESTRICT itself (its half is policy).
                assert!(!enforces(&f, &o, "customer").await, "asked of the table, not the definition");
                assert_eq!(f.e.count_referencing(&cx(), CLIENT, Some(&f.c), &o, "customer", false, &bo).await.unwrap(), 1);
                // KeyBlocked.handsBackWhenInstalled
                exec(&p, &format!("DELETE FROM `{}`.`{ORDERS}` WHERE `customer` = 'NOTAREALIDNOTAREALIDNOTARE'", f.db())).await;
                f.evict_all_caches();
                write_order(&f, &o, 300.0, Some(&f.id_of(&c, r#"{"name":"Cal"}"#).await), None).await;
                assert_eq!(delete_rule(&f).await.as_deref(), Some("RESTRICT"));
                assert!(enforces(&f, &o, "customer").await);
            },
            drop_schemas(&p, &[CLIENT], APP),
        )
        .await;
    }
}

// ------------------------------------------------------------------ the draft copy (aca9929dd)

/// `clearDraftRows` and `copyLiveToDraft` with a `DraftCopyFilter`, from the Java code
/// of nocode-saas aca9929dd (no Java tests came with it), plus the copy expectations of
/// `AppDataSurfaceIntegrationTest` where Java's MySQL engine shares them.
mod draft_copy {
    use super::*;

    const APP: &str = "rtd_copy";

    fn customers() -> Storage {
        storage(APP, "customers", r#"{"version":1,"isVersioned":true,"schema":{"type":"OBJECT","properties":{"name":{"type":"STRING","maxLength":40},"tier":{"type":"STRING","maxLength":10}}}}"#)
    }

    fn orders() -> Storage {
        storage(
            APP,
            "orders",
            r#"{"version":1,"relations":{"customer":{"storageName":"customers","relationType":"TO_ONE","fieldName":"_id","deleteConstraint":"RESTRICT"}},
                "schema":{"type":"OBJECT","properties":{"amount":{"type":"DOUBLE"},"code":{"type":"STRING","maxLength":10}}}}"#,
        )
    }

    fn items() -> Storage {
        storage(APP, "items", r#"{"version":1,"schema":{"type":"OBJECT","properties":{"orderCode":{"type":"STRING","maxLength":10},"sku":{"type":"STRING","maxLength":10}}}}"#)
    }

    fn follow(field: &str, storage: &str, ref_field: Option<&str>) -> Follow {
        Follow { field: field.into(), storage: storage.into(), ref_field: ref_field.map(str::to_string) }
    }

    fn by(json: &str) -> Option<Condition> {
        Condition::from_value(&v(json)).unwrap()
    }

    fn followed(storages: &[Storage]) -> HashMap<String, Storage> {
        storages.iter().map(|s| (s.name.clone(), s.clone())).collect()
    }

    async fn copy(f: &Fx, s: &Storage, filter: Option<DraftCopyFilter>, with: &[Storage]) -> appdata::AppDataResult<i64> {
        f.e.copy_live_to_draft_filtered(&cx(), CLIENT, Some(&f.c), s, filter.as_ref(), &followed(with)).await
    }

    async fn draft_names(f: &Fx, table: &str, column: &str) -> Vec<String> {
        let mut out: Vec<String> = rows(&f.p, &format!("SELECT `{column}` FROM `{}`.`{table}`", f.draft_db()))
            .await
            .iter()
            .map(|r| r.values().next().unwrap().java_string())
            .collect();
        out.sort();
        out
    }

    /// Asha (gold) with orders A1 and A2, Bo (silver) with B1, an order with no customer,
    /// and items following orders by code.
    async fn given(p: &MySqlPool) -> (Fx, String, String) {
        let f = Fx::fresh(p, APP).await;
        for s in [customers(), orders(), items()] {
            f.put(&s).await;
        }
        let asha = f.id_of(&customers(), r#"{"name":"Asha","tier":"gold"}"#).await;
        let bo = f.id_of(&customers(), r#"{"name":"Bo","tier":"silver"}"#).await;
        for (code, amount, customer) in [("A1", 10, Some(&asha)), ("A2", 20, Some(&asha)), ("B1", 5, Some(&bo)), ("N1", 1, None)] {
            let mut row = doc(&format!(r#"{{"amount":{amount},"code":"{code}"}}"#));
            if let Some(c) = customer {
                row.insert("customer".into(), Value::from(c.as_str()));
            }
            f.e.create(&cx(), CLIENT, Some(&f.c), &orders(), DataObject::of(row)).await.unwrap();
        }
        for (order, sku) in [("A1", "x"), ("A2", "y"), ("B1", "z")] {
            f.create(&items(), &format!(r#"{{"orderCode":"{order}","sku":"{sku}"}}"#)).await.unwrap();
        }
        (f, asha, bo)
    }

    #[tokio::test]
    #[ignore = "needs the local MySQL"]
    async fn clear_and_filtered_copies() {
        let p = scratch_pool().await;
        drop_schemas(&p, &[CLIENT], APP).await;
        guarded(
            async {
                let (f, asha, bo) = given(&p).await;
                let draft = cx().on_draft(true);

                // clearDraftRows with no draft table at all is 0, not an error.
                assert_eq!(f.e.clear_draft_rows(&cx(), CLIENT, Some(&f.c), &customers()).await.unwrap(), 0);

                // copyPreservesIdsAndKeepsLive: the same ids on both surfaces, live untouched.
                assert_eq!(f.e.copy_live_to_draft(&cx(), CLIENT, Some(&f.c), &customers(), Some(true)).await.unwrap(), 2);
                assert_eq!(f.rows_in(&f.db(), "rtd_copy_customers").await, 2, "the source must be untouched");
                let mut live_ids: Vec<String> = rows(&p, &format!("SELECT `_id` FROM `{}`.`rtd_copy_customers`", f.db())).await.iter().map(|r| r["_id"].java_string()).collect();
                live_ids.sort();
                assert_eq!(draft_names(&f, "rtd_copy_customers", "_id").await, live_ids);

                // copyWithReplaceClearsDraftFirst, and copying twice with replace is idempotent.
                f.e.create(&draft, CLIENT, Some(&f.c), &customers(), data(r#"{"name":"Sandbox"}"#)).await.unwrap();
                assert_eq!(f.e.copy_live_to_draft(&cx(), CLIENT, Some(&f.c), &customers(), Some(true)).await.unwrap(), 2);
                assert_eq!(draft_names(&f, "rtd_copy_customers", "name").await, ["Asha", "Bo"], "the sandbox row is gone, not added to");
                // Without replace Java's MySQL engine inserts plainly, so rows already in the
                // draft are a duplicate key (Mongo upserts instead).
                assert!(f.e.copy_live_to_draft(&cx(), CLIENT, Some(&f.c), &customers(), Some(false)).await.is_err());

                // clearDraftRows: the draft rows and the draft history go, the table and live stay.
                f.e.create(&draft, CLIENT, Some(&f.c), &customers(), data(r#"{"name":"Sandbox"}"#)).await.unwrap();
                assert!(f.rows_in(&f.draft_db(), "rtd_copy_customers_version").await > 0);
                assert_eq!(f.e.clear_draft_rows(&cx(), CLIENT, Some(&f.c), &customers()).await.unwrap(), 3);
                assert_eq!(f.rows_in(&f.draft_db(), "rtd_copy_customers").await, 0);
                assert_eq!(f.rows_in(&f.draft_db(), "rtd_copy_customers_version").await, 0);
                assert_eq!(f.rows_in(&f.db(), "rtd_copy_customers").await, 2, "clearing the draft leaves live alone");
                assert!(f.rows_in(&f.db(), "rtd_copy_customers_version").await > 0, "and live history");

                // No filter: every live row, after the draft is emptied. Orders reference
                // customers the draft does not hold: the copy runs with key checks off.
                assert_eq!(copy(&f, &orders(), None, &[]).await.unwrap(), 4);
                assert_eq!(draft_names(&f, "rtd_copy_orders", "code").await, ["A1", "A2", "B1", "N1"]);

                // A condition that selects nothing still empties the draft.
                let none = DraftCopyFilter { condition: by(r#"{"field":"code","value":"ZZ"}"#), follow: None };
                assert_eq!(copy(&f, &orders(), Some(none), &[]).await.unwrap(), 0);
                assert_eq!(f.rows_in(&f.draft_db(), "rtd_copy_orders").await, 0);

                // A follow whose storage has no draft rows copies nothing.
                f.e.clear_draft_rows(&cx(), CLIENT, Some(&f.c), &customers()).await.unwrap();
                let by_customer = DraftCopyFilter { condition: None, follow: Some(vec![follow("customer", "customers", None)]) };
                assert_eq!(copy(&f, &orders(), Some(by_customer.clone()), &[customers()]).await.unwrap(), 0);

                // The root by condition, then the orders that follow a copied customer: a
                // follow column must be empty or satisfied, and some follow filled, so the
                // order with no customer stays behind.
                let gold = DraftCopyFilter { condition: by(r#"{"field":"tier","value":"gold"}"#), follow: None };
                assert_eq!(copy(&f, &customers(), Some(gold), &[]).await.unwrap(), 1);
                assert_eq!(copy(&f, &orders(), Some(by_customer), &[customers()]).await.unwrap(), 2);
                assert_eq!(draft_names(&f, "rtd_copy_orders", "code").await, ["A1", "A2"]);

                // A chained third level, matched on a field other than _id (refField).
                let by_order = DraftCopyFilter { condition: None, follow: Some(vec![follow("orderCode", "orders", Some("code"))]) };
                assert_eq!(copy(&f, &items(), Some(by_order), &[orders()]).await.unwrap(), 2);
                assert_eq!(draft_names(&f, "rtd_copy_items", "sku").await, ["x", "y"]);

                // A condition together with a follow: both must hold.
                let big = DraftCopyFilter {
                    condition: by(r#"{"field":"amount","operator":"GREATER_THAN","value":15}"#),
                    follow: Some(vec![follow("customer", "customers", Some(""))]),
                };
                assert_eq!(copy(&f, &orders(), Some(big), &[customers()]).await.unwrap(), 1);
                assert_eq!(draft_names(&f, "rtd_copy_orders", "code").await, ["A2"]);

                // The reverse direction: customers kept when a draft order points at them.
                let pointed_at = DraftCopyFilter { condition: None, follow: Some(vec![follow("_id", "orders", Some("customer"))]) };
                assert_eq!(copy(&f, &customers(), Some(pointed_at), &[orders()]).await.unwrap(), 1);
                assert_eq!(draft_names(&f, "rtd_copy_customers", "_id").await, [asha.clone()]);
                let _ = bo;

                // A follow naming a storage the caller did not hand over is a server error.
                let missing = DraftCopyFilter { condition: None, follow: Some(vec![follow("customer", "customers", None)]) };
                let e = copy(&f, &orders(), Some(missing), &[]).await.unwrap_err();
                assert_eq!(e.status().as_u16(), 500, "{}", e.message());
            },
            drop_schemas(&p, &[CLIENT], APP),
        )
        .await;
    }
}

// ------------------------------------------------------------------ MySQLAppLevelStorageIntegrationTest

/// App-level storages on MySQL (nocode-saas e2b7d48aa): one table for every client of the app,
/// in the schema of the client hosting it (the URL's client), as on Mongo. Two tenants use the
/// app on the host's site; `shared` is app level, `own` is not and relates to `shared`.
mod mysql_app_level_storage_integration_test {
    use super::*;
    use appdata::engine::Ctx;

    const APP: &str = "rtd_applvl";
    const HOST: &str = CLIENT;
    const TENA: &str = "RUSTTEST_A";
    const TENB: &str = "RUSTTEST_B";
    const SHARED_TABLE: &str = "rtd_applvl_shared";
    const OWN_TABLE: &str = "rtd_applvl_own";

    fn label_schema() -> &'static str {
        r#""schema":{"type":"OBJECT","properties":{"label":{"type":"STRING","maxLength":40}}}"#
    }

    fn shared() -> Storage {
        storage(APP, "shared", &format!(r#"{{"version":1,"isAppLevel":true,{}}}"#, label_schema()))
    }

    fn own() -> Storage {
        storage(
            APP,
            "own",
            &format!(
                r#"{{"version":1,"relations":{{"customer":{{"storageName":"shared","relationType":"TO_ONE","fieldName":"_id","deleteConstraint":"RESTRICT"}}}},{}}}"#,
                label_schema()
            ),
        )
    }

    /// A user of a tenant on the host's site: the URL's client is the host, not the tenant.
    fn on_host() -> Ctx {
        Ctx { url_client_code: Some(HOST.into()), ..cx() }
    }

    struct Fx {
        p: MySqlPool,
        e: MySqlAppDataService,
        c: Connection,
    }

    impl Fx {
        async fn fresh(p: &MySqlPool) -> Fx {
            drop_schemas(p, &[HOST, TENA, TENB], APP).await;
            let storages = Arc::new(Storages::default());
            storages.put(&shared()).await;
            storages.put(&own()).await;
            Fx { p: p.clone(), e: mysql_engine(storages), c: conn().await }
        }

        async fn write(&self, client: &str, s: &Storage, row: Document) -> Document {
            self.e.create(&on_host(), client, Some(&self.c), s, DataObject::of(row)).await.unwrap()
        }

        async fn rows(&self, client: &str, s: &Storage) -> Vec<Document> {
            self.e.read_page(&on_host(), client, Some(&self.c), s, &query(r#"{"page":0,"size":50}"#)).await.unwrap().content
        }

        async fn table_exists(&self, schema: &str, table: &str) -> bool {
            appdata::mysql::db::count_raw(
                &self.p,
                &format!("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = '{schema}' AND TABLE_NAME = '{table}'"),
            )
            .await
            .unwrap()
                > 0
        }

        async fn foreign_keys_on(&self, schema: &str, table: &str) -> i64 {
            appdata::mysql::db::count_raw(
                &self.p,
                &format!("SELECT COUNT(*) FROM information_schema.REFERENTIAL_CONSTRAINTS WHERE CONSTRAINT_SCHEMA = '{schema}' AND TABLE_NAME = '{table}'"),
            )
            .await
            .unwrap()
        }
    }

    fn schema_of_client(client: &str) -> String {
        format!("{client}_{APP}")
    }

    #[tokio::test]
    #[ignore = "needs the local MySQL"]
    async fn app_level_rows_are_shared_and_tenant_rows_stay_per_tenant() {
        let p = scratch_pool().await;
        let cleanup = drop_schemas(&p, &[HOST, TENA, TENB], APP);
        guarded(
            async {
                // appLevelRowsAreShared
                let f = Fx::fresh(&p).await;
                f.write(TENA, &shared(), doc(r#"{"label":"from A"}"#)).await;
                let seen_by_b = f.rows(TENB, &shared()).await;
                assert_eq!(seen_by_b.len(), 1);
                assert_eq!(seen_by_b[0]["label"].java_string(), "from A");
                assert!(f.table_exists(&schema_of_client(HOST), SHARED_TABLE).await, "held by the host");
                assert!(!f.table_exists(&schema_of_client(TENA), SHARED_TABLE).await, "not a table per tenant");
                assert!(!f.table_exists(&schema_of_client(TENB), SHARED_TABLE).await);

                // tenantRowsStayPerTenant
                let f = Fx::fresh(&p).await;
                f.write(TENA, &own(), doc(r#"{"label":"A only"}"#)).await;
                assert_eq!(f.rows(TENA, &own()).await.len(), 1);
                assert_eq!(f.rows(TENB, &own()).await.len(), 0);
                assert!(f.table_exists(&schema_of_client(TENA), OWN_TABLE).await);
                assert!(!f.table_exists(&schema_of_client(HOST), OWN_TABLE).await);

                // noForeignKeyAcrossSchemas
                let f = Fx::fresh(&p).await;
                let customer = f.write(TENA, &shared(), doc(r#"{"label":"customer"}"#)).await;
                let id = customer["_id"].java_string();
                assert!(!id.is_empty());
                let mut order = doc(r#"{"label":"order"}"#);
                order.insert("customer".into(), Value::from(id.as_str()));
                f.write(TENA, &own(), order).await;
                assert_eq!(f.foreign_keys_on(&schema_of_client(TENA), OWN_TABLE).await, 0, "the key would point at a table that is not in this schema");
                assert!(!f.table_exists(&schema_of_client(TENA), SHARED_TABLE).await, "and no stray per-tenant copy of the shared table was created for it");
                assert_eq!(f.rows(TENA, &own()).await.len(), 1);
                let relation = own().relation("customer").unwrap().clone();
                assert!(!f.e.enforces_relation_constraint(&on_host(), TENA, Some(&f.c), &own(), "customer", &relation).await.unwrap(), "the service enforces it itself");

                // The draft copy and clear follow the same schema.
                let copied = f.e.copy_live_to_draft(&on_host(), TENB, Some(&f.c), &shared(), Some(true)).await.unwrap();
                assert_eq!(copied, 1, "TENB's copy of the shared table is the host's");
                assert!(f.table_exists(&format!("{}_draft", schema_of_client(HOST)), SHARED_TABLE).await);
                assert!(!f.table_exists(&format!("{}_draft", schema_of_client(TENB)), SHARED_TABLE).await);
                assert_eq!(f.e.clear_draft_rows(&on_host(), TENB, Some(&f.c), &shared()).await.unwrap(), 1);
            },
            cleanup,
        )
        .await;
    }
}
