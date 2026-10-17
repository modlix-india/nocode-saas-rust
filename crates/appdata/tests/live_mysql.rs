//! The MySQL engine against the local MySQL, in scratch schemas named `RUSTTEST_*` that the
//! tests create and drop themselves. Nothing else on the server is touched.
//!
//! Run with: cargo test -p appdata --test live_mysql -- --ignored --test-threads=1
//! (APPDATA_TEST_MYSQL_URL / _USER / _PASSWORD override the local defaults.)

use std::collections::HashMap;
use std::sync::Arc;

use appdata::engine::{AppDataEngine, Ctx, Hooks, PassThrough, StorageResolver};
use appdata::model::*;
use appdata::mysql::{migration, MySqlAppDataService, MySqlEngineConfig};
use appdata::retention::VersionRetention;
use appdata::value::{Document, Value};
use async_trait::async_trait;
use indexmap::IndexMap;
use platform::cache::CacheService;
use sqlx::MySqlPool;
use tokio::sync::Mutex;

mod support;
use support::guarded;

const CLIENT: &str = "RUSTTEST";

/// Core's own datasource from the config server (or `APPDATA_TEST_MYSQL_*`), so no
/// credentials live in this file.
async fn conn() -> Connection {
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

#[derive(Default)]
struct Storages(Mutex<IndexMap<String, Storage>>);

#[async_trait]
impl StorageResolver for Storages {
    async fn read_for_tenant(&self, name: &str, _app: &str, _client: &str, _draft: bool) -> anyhow::Result<Option<Storage>> {
        Ok(self.0.lock().await.get(name).cloned())
    }
}

fn engine(storages: Arc<Storages>) -> MySqlAppDataService {
    let cache = CacheService::new("cmn", "evictionChannel", None).unwrap();
    MySqlAppDataService::new(
        MySqlEngineConfig { retention: VersionRetention::clamped(0, 0), ..Default::default() },
        Hooks { validator: Arc::new(PassThrough), schemas: None, storages: Some(storages), authority: None },
        &cache,
    )
}

fn v(s: &str) -> Value {
    Value::parse_json(s).unwrap()
}

fn doc(s: &str) -> Document {
    match v(s) {
        Value::Object(o) => o,
        other => panic!("not an object: {other:?}"),
    }
}

fn storage(app: &str, name: &str, json: &str) -> Storage {
    let mut value = v(json);
    if let Value::Object(o) = &mut value {
        o.insert("name".into(), Value::from(name));
        o.insert("appCode".into(), Value::from(app));
        o.insert("clientCode".into(), Value::from("SYSTEM"));
        o.entry("uniqueName".to_string()).or_insert_with(|| Value::from(format!("{app}_{name}")));
    }
    Storage::from_value(&value).unwrap()
}

async fn pool(e: &MySqlAppDataService) -> MySqlPool {
    e.pool(Some(&conn().await)).await.unwrap()
}

async fn drop_schemas(p: &MySqlPool, app: &str) {
    for s in [format!("{CLIENT}_{app}"), format!("{CLIENT}_{app}_draft")] {
        assert!(s.starts_with("RUSTTEST_"));
        sqlx::raw_sql(&format!("DROP DATABASE IF EXISTS `{s}`")).execute(p).await.unwrap();
    }
}

async fn scalar(p: &MySqlPool, sql: &str) -> String {
    let rows = appdata::mysql::db::fetch_raw(p, sql).await.unwrap();
    rows.first().and_then(|r| r.values().next()).map(Value::java_string).unwrap_or_default()
}

fn query(json: &str) -> Query {
    Query::from_value(&v(json)).unwrap()
}

fn data(json: &str) -> DataObject {
    DataObject::of(doc(json))
}

fn cx() -> Ctx {
    Ctx { url_client_code: Some(CLIENT.into()), user_id: Some(142), authorities: vec!["Authorities.Logged_IN".into()], draft: false }
}

async fn names(e: &MySqlAppDataService, s: &Storage, q: &str) -> Vec<String> {
    let page = e.read_page(&cx(), CLIENT, Some(&conn().await), s, &query(q)).await.unwrap();
    page.content.iter().map(|r| r.get("name").map(Value::java_string).unwrap_or_default()).collect()
}

#[tokio::test]
#[ignore = "needs the local MySQL"]
async fn rows_round_trip_with_java_shapes() {
    let app = "my_crud";
    let storages = Arc::new(Storages::default());
    let e = engine(storages.clone());
    let p = pool(&e).await;
    drop_schemas(&p, app).await;
    guarded(
        async {
            let orders = storage(
                app,
                "orders",
                r#"{"isAudited":true,"isVersioned":true,"versionRetentionCount":3,"textIndexFields":["name"],
                    "indexes":{"byAmount":{"fields":[{"fieldName":"amount","direction":"DESC"}],"unique":false}},
                    "schema":{"type":"OBJECT","required":["name"],"properties":{
                      "name":{"type":"STRING","maxLength":60},
                      "amount":{"type":"DOUBLE"},
                      "price":{"type":"STRING","format":"DECIMAL"},
                      "placedAt":{"type":"STRING","format":"DATETIME"},
                      "active":{"type":"BOOLEAN"},
                      "address":{"type":"OBJECT","properties":{"city":{"type":"STRING"}}},
                      "tags":{"type":"ARRAY","items":{"type":"STRING"}},
                      "IFSC Code":{"type":"STRING","maxLength":20}}}}"#,
            );
            let c = conn().await;
            let created = e
                .create(
                    &cx(),
                    CLIENT,
                    Some(&c),
                    &orders,
                    data(r#"{"name":"alpha","amount":5,"price":"10.50","placedAt":"2026-01-15T10:00:00+05:30","active":true,
                            "address":{"city":"Pune"},"tags":["red","blue"],"IFSC Code":"HDFC1"}"#),
                )
                .await
                .unwrap();
            let id = created["_id"].java_string();
            assert_eq!(id.len(), 26, "a ULID");
            assert_eq!(created["price"], Value::from("10.5000"));
            assert_eq!(created["placedAt"], Value::from("2026-01-15T04:30:00"));
            assert_eq!(created["active"], Value::Bool(true));
            assert_eq!(created["address"], v(r#"{"city":"Pune"}"#));
            assert_eq!(created["tags"], v(r#"["red","blue"]"#));
            assert_eq!(created["IFSC Code"], Value::from("HDFC1"));
            assert_eq!(created["amount"], Value::Double(5.0));

            let db = format!("{CLIENT}_{app}");
            let col = |c: &str| {
                format!(
                    "SELECT CONCAT(COLUMN_TYPE, ' ', IS_NULLABLE) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = '{db}' AND TABLE_NAME = 'my_crud_orders' AND COLUMN_NAME = '{c}'"
                )
            };
            assert_eq!(scalar(&p, &col("IFSC_Code")).await, "varchar(20) YES");
            assert_eq!(scalar(&p, &col("price")).await, "decimal(19,4) YES");
            assert_eq!(scalar(&p, &col("placedAt")).await, "datetime(3) YES");
            assert_eq!(scalar(&p, &col("active")).await, "tinyint(1) YES");
            assert_eq!(scalar(&p, &col("name")).await, "varchar(60) NO");
            assert_eq!(scalar(&p, &col("_id")).await, "char(26) NO");
            let idx = scalar(
                &p,
                &format!("SELECT GROUP_CONCAT(DISTINCT INDEX_NAME ORDER BY INDEX_NAME) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = '{db}' AND TABLE_NAME = 'my_crud_orders'"),
            )
            .await;
            assert_eq!(idx, "byAmount,ft_all,PRIMARY");

            e.create(&cx(), CLIENT, Some(&c), &orders, data(r#"{"_id":"999","name":"bravo","amount":15,"tags":["green"],"active":false}"#))
                .await
                .unwrap();
            e.create(&cx(), CLIENT, Some(&c), &orders, data(r#"{"name":"charlie","amount":25,"address":{"city":"Delhi"},"tags":["red"]}"#))
                .await
                .unwrap();

            assert_eq!(names(&e, &orders, r#"{"condition":{"field":"name","value":"alpha"}}"#).await, vec!["alpha"]);
            assert_eq!(
                names(&e, &orders, r#"{"condition":{"field":"amount","operator":"IN","value":"5,15"},"sort":{"property":"amount"}}"#).await,
                vec!["alpha", "bravo"]
            );
            assert_eq!(names(&e, &orders, r#"{"condition":{"field":"address.city","value":"Pune"}}"#).await, vec!["alpha"]);
            assert_eq!(
                names(&e, &orders, r#"{"condition":{"field":"tags","operator":"MATCH","value":"red"},"sort":{"property":"name"}}"#).await,
                vec!["alpha", "charlie"]
            );
            assert_eq!(names(&e, &orders, r#"{"condition":{"field":"tags","operator":"MATCH_ALL","multiValue":["red","blue"]}}"#).await, vec!["alpha"]);
            assert_eq!(names(&e, &orders, r#"{"condition":{"field":"name","operator":"TEXT_SEARCH","value":"charlies"}}"#).await, vec!["charlie"]);
            assert_eq!(
                names(&e, &orders, r#"{"condition":{"field":"amount","operator":"BETWEEN","value":10,"toValue":30,"negate":true}}"#).await,
                vec!["alpha"]
            );
            assert_eq!(names(&e, &orders, r#"{"condition":{"field":"active","operator":"IS_FALSE"}}"#).await, vec!["bravo"]);
            // A value-less condition drops out of a read, as on Mongo.
            assert_eq!(names(&e, &orders, r#"{"condition":{"field":"name","value":null},"sort":{"property":"name"}}"#).await.len(), 3);
            // Ids sort by length first, so an imported "999" comes before every ULID.
            let first = names(&e, &orders, r#"{"sort":{"property":"_id"},"size":1}"#).await;
            assert_eq!(first, vec!["bravo"]);
            let page = e.read_page(&cx(), CLIENT, Some(&c), &orders, &query(r#"{"fields":["name"],"size":2,"sort":{"property":"name"}}"#)).await.unwrap();
            assert_eq!(page.content[0].keys().collect::<Vec<_>>(), vec!["_id", "name"]);
            assert_eq!(page.total, 3);
            assert_eq!(page.to_value().to_java_json().contains("\"totalPages\":2"), true);
            let page = e.read_page(&cx(), CLIENT, Some(&c), &orders, &query(r#"{"count":false,"size":2}"#)).await.unwrap();
            assert_eq!(page.total, 2, "no count: offset + rows, and a full page reads as possibly more");
            let err = e
                .read_page(&cx(), CLIENT, Some(&c), &orders, &query(r#"{"condition":{"field":"amount","operator":"BETWEEN","value":1}}"#))
                .await
                .unwrap_err();
            assert_eq!(err.status().as_u16(), 400);
            assert_eq!(err.message(), "BETWEEN on 'amount' without a toValue is not a condition this data filter supports.");

            // PATCH keeps what it does not name; PUT clears it.
            let patched = e.update(&cx(), CLIENT, Some(&c), &orders, data(&format!(r#"{{"_id":"{id}","amount":7}}"#)), Some(false)).await.unwrap();
            assert_eq!(patched["name"], Value::from("alpha"));
            assert_eq!(patched["amount"], Value::Double(7.0));
            let put = e.update(&cx(), CLIENT, Some(&c), &orders, data(&format!(r#"{{"_id":"{id}","name":"alpha2"}}"#)), Some(true)).await.unwrap();
            assert_eq!(put["amount"], Value::Null);
            assert_eq!(put["tags"], Value::Null);
            let err = e.update(&cx(), CLIENT, Some(&c), &orders, data(&format!(r#"{{"_id":"{id}","name":null}}"#)), Some(false)).await.unwrap_err();
            assert_eq!(err.message(), "name cannot be null in orders: the field is required.");
            let err = e.update(&cx(), CLIENT, Some(&c), &orders, data(r#"{"name":"x"}"#), None).await.unwrap_err();
            assert_eq!(err.message(), "_id is required to update a row.");
            let err = e.update(&cx(), CLIENT, Some(&c), &orders, data(r#"{"_id":"nope","name":"x"}"#), Some(true)).await.unwrap_err();
            assert!(matches!(err, appdata::AppDataError::Empty), "a PUT to a missing row completes empty, as in Java");

            // History: CREATE + 2 UPDATEs, then more updates trimmed to the newest 3.
            let versions = e.read_page_version(&cx(), CLIENT, Some(&c), &orders, &id, &Query::default(), None).await.unwrap();
            assert_eq!(versions.total, 3);
            let ops: Vec<String> = versions.content.iter().map(|r| r["operation"].java_string()).collect();
            assert_eq!(ops, vec!["UPDATE", "UPDATE", "CREATE"]);
            assert!(matches!(versions.content[0]["createdAt"], Value::LocalDateTime(_)));
            assert_eq!(versions.content[0]["createdBy"], Value::Int(142));
            assert_eq!(versions.content[2]["object"].as_object().unwrap()["active"], Value::Bool(true));
            for n in 0..3 {
                e.update(&cx(), CLIENT, Some(&c), &orders, data(&format!(r#"{{"_id":"{id}","amount":{n}}}"#)), Some(false)).await.unwrap();
            }
            let audit = e.read_page_version(&cx(), CLIENT, Some(&c), &orders, &id, &Query::default(), Some(false)).await.unwrap();
            assert_eq!(audit.total, 3, "retention keeps the newest three");
            assert!(!audit.content[0].contains_key("object"));
            let vid = audit.content[0]["_id"].java_string();
            let one = e.read_version(&cx(), CLIENT, Some(&c), &orders, &vid).await.unwrap();
            assert_eq!(one["objectId"], Value::from(id.as_str()));
            let err = e.read_version(&cx(), CLIENT, Some(&c), &orders, "missing").await.unwrap_err();
            assert_eq!(err.message(), "orders with id missing not found");

            // Aggregates: grouped, bucketed in a named zone, and a refused SUM over text.
            let agg = AggregateQuery::from_value(&v(
                r#"{"groupBy":[{"field":"name"}],"aggregations":[{"function":"SUM","field":"amount","alias":"total"}],"sort":{"property":"name"},"count":true}"#,
            ))
            .unwrap();
            let page = e.aggregate(&cx(), CLIENT, Some(&c), &orders, &agg).await.unwrap();
            assert_eq!(page.total, 3);
            assert_eq!(page.content[0]["name"], Value::from("alpha2"));
            let bucket = AggregateQuery::from_value(&v(
                r#"{"groupBy":[{"field":"placedAt","bucket":"DAY","timezone":"Asia/Kolkata","alias":"day"}],"aggregations":[{"function":"COUNT"}]}"#,
            ))
            .unwrap();
            assert!(e.aggregate(&cx(), CLIENT, Some(&c), &orders, &bucket).await.is_ok());
            let bad = AggregateQuery::from_value(&v(r#"{"aggregations":[{"function":"SUM","field":"name"}]}"#)).unwrap();
            let err = e.aggregate(&cx(), CLIENT, Some(&c), &orders, &bad).await.unwrap_err();
            assert!(err.message().starts_with("Invalid aggregation request: cannot SUM field 'name'"), "{}", err.message());

            // Deletes: a DELETE version, a filtered delete counted first.
            assert!(e.delete(&cx(), CLIENT, Some(&c), &orders, "999", Some(false)).await.unwrap());
            assert!(!e.delete(&cx(), CLIENT, Some(&c), &orders, "999", Some(false)).await.unwrap());
            let deleted = e.read_page_version(&cx(), CLIENT, Some(&c), &orders, "999", &Query::default(), None).await.unwrap();
            assert_eq!(deleted.content[0]["operation"], Value::from("DELETE"));
            let all = query(r#"{"condition":{"field":"amount","operator":"GREATER_THAN","value":-1}}"#);
            assert_eq!(e.delete_by_filter(&cx(), CLIENT, Some(&c), &orders, &all, Some(true), None).await.unwrap(), 2);
            assert!(e.check_if_exists(&cx(), CLIENT, Some(&c), &orders, &id).await.unwrap());
            assert_eq!(e.delete_by_filter(&cx(), CLIENT, Some(&c), &orders, &all, None, Some(true)).await.unwrap(), 2);
            assert!(!e.check_if_exists(&cx(), CLIENT, Some(&c), &orders, &id).await.unwrap());
            assert!(e.delete_storage(&cx(), CLIENT, Some(&c), &orders).await.unwrap());
            assert_eq!(scalar(&p, &format!("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = '{db}' AND TABLE_NAME = 'my_crud_orders'")).await, "0");
        },
        drop_schemas(&p, app),
    )
    .await;
}

#[tokio::test]
#[ignore = "needs the local MySQL"]
async fn joins_subqueries_and_foreign_keys() {
    let app = "my_join";
    let storages = Arc::new(Storages::default());
    let e = engine(storages.clone());
    let p = pool(&e).await;
    drop_schemas(&p, app).await;
    guarded(
        async {
            let c = conn().await;

            let customers = storage(app, "customers", r#"{"schema":{"type":"OBJECT","properties":{"name":{"type":"STRING","maxLength":40},"region":{"type":"STRING","maxLength":20}}}}"#);
            let orders = storage(
                app,
                "orders",
                r#"{"relations":{"customer":{"storageName":"customers","relationType":"TO_ONE","deleteConstraint":"RESTRICT"}},
                    "schema":{"type":"OBJECT","properties":{"name":{"type":"STRING","maxLength":40},"amount":{"type":"DOUBLE"}}}}"#,
            );
            storages.0.lock().await.insert("customers".into(), customers.clone());
            storages.0.lock().await.insert("orders".into(), orders.clone());

            let c1 = e.create(&cx(), CLIENT, Some(&c), &customers, data(r#"{"name":"c1","region":"north"}"#)).await.unwrap()["_id"].java_string();
            let c2 = e.create(&cx(), CLIENT, Some(&c), &customers, data(r#"{"name":"c2","region":"south"}"#)).await.unwrap()["_id"].java_string();
            for (n, cust, amt) in [("o1", Some(&c1), 10), ("o2", Some(&c1), 20), ("o3", Some(&c2), 5), ("o4", None, 1)] {
                let mut d = doc(&format!(r#"{{"name":"{n}","amount":{amt}}}"#));
                if let Some(cu) = cust {
                    d.insert("customer".into(), Value::from(cu.as_str()));
                }
                e.create(&cx(), CLIENT, Some(&c), &orders, DataObject::of(d)).await.unwrap();
            }

            let joined = e
                .read_page(&cx(), CLIENT, Some(&c), &orders, &query(r#"{"joins":[{"relation":"customer"}],"sort":{"property":"name"}}"#))
                .await
                .unwrap();
            assert_eq!(joined.total, 4);
            assert_eq!(joined.content[0]["customer"].as_object().unwrap()["region"], Value::from("north"));
            assert!(!joined.content[3].contains_key("customer"), "a LEFT join that matched nothing drops the key");
            let north = e
                .read_page(
                    &cx(),
                    CLIENT,
                    Some(&c),
                    &orders,
                    &query(r#"{"joins":[{"relation":"customer"}],"condition":{"field":"customer.region","value":"north"}}"#),
                )
                .await
                .unwrap();
            assert_eq!(north.total, 2);
            let inner = e
                .read_page(&cx(), CLIENT, Some(&c), &orders, &query(r#"{"joins":[{"relation":"customer","type":"INNER","alias":"cu"}]}"#))
                .await
                .unwrap();
            assert_eq!(inner.total, 3);

            let counted = e
                .read_page(
                    &cx(),
                    CLIENT,
                    Some(&c),
                    &customers,
                    &query(r#"{"subQueries":[{"storage":"orders","relation":"customer","alias":"orders","aggregations":[{"function":"COUNT","alias":"n"},{"function":"SUM","field":"amount","alias":"total"}]}],"sort":{"property":"orders.n","direction":"DESC"}}"#),
                )
                .await
                .unwrap();
            assert_eq!(counted.content[0]["orders"].as_object().unwrap()["n"], Value::Int(2));
            assert_eq!(counted.content[0]["orders"].as_object().unwrap()["total"], Value::Double(30.0));

            let agg = AggregateQuery::from_value(&v(
                r#"{"joins":[{"relation":"customer"}],"groupBy":[{"field":"customer.region","alias":"region"}],"aggregations":[{"function":"SUM","field":"amount","alias":"total"}],"sort":{"property":"total","direction":"DESC"}}"#,
            ))
            .unwrap();
            let page = e.aggregate(&cx(), CLIENT, Some(&c), &orders, &agg).await.unwrap();
            assert_eq!(page.content[0]["region"], Value::from("north"));

            let relation = orders.relation("customer").unwrap().clone();
            assert!(e.enforces_relation_constraint(&cx(), CLIENT, Some(&c), &orders, "customer", &relation).await.unwrap());
            assert_eq!(e.count_referencing(&cx(), CLIENT, Some(&c), &orders, "customer", false, &c1).await.unwrap(), 2);
            assert_eq!(e.ids_referencing(&cx(), CLIENT, Some(&c), &orders, "customer", false, &c1, 10).await.unwrap().len(), 2);
            let err = e.delete(&cx(), CLIENT, Some(&c), &customers, &c1, None).await.unwrap_err();
            assert_eq!(err.message(), "Following objects exists and cannot be deleted: [customers (other rows still reference this one)]");

            let forbidden = Ctx { authorities: vec![], ..cx() };
            let mut locked = customers.clone();
            locked.read_auth = Some("Authorities.Secret".into());
            storages.0.lock().await.insert("customers".into(), locked);
            let err = e
                .read_page(&forbidden, CLIENT, Some(&c), &orders, &query(r#"{"joins":[{"relation":"customer"}]}"#))
                .await
                .unwrap_err();
            assert_eq!(err.message(), "Unable to read data from storage customers");
        },
        drop_schemas(&p, app),
    )
    .await;
}

#[tokio::test]
#[ignore = "needs the local MySQL"]
async fn migrations_drift_and_recovery() {
    let app = "my_migr";
    let storages = Arc::new(Storages::default());
    let e = engine(storages.clone());
    let p = pool(&e).await;
    drop_schemas(&p, app).await;
    guarded(
        async {
            let c = conn().await;
            let db = format!("{CLIENT}_{app}");

            let v1 = storage(app, "items", r#"{"version":1,"schema":{"type":"OBJECT","properties":{"code":{"type":"STRING","maxLength":40},"qty":{"type":"STRING","maxLength":40}}}}"#);
            storages.0.lock().await.insert("items".into(), v1.clone());
            e.create(&cx(), CLIENT, Some(&c), &v1, data(r#"{"code":"a","qty":"12"}"#)).await.unwrap();
            let bad = e.create(&cx(), CLIENT, Some(&c), &v1, data(r#"{"code":"b","qty":"twelve"}"#)).await.unwrap()["_id"].java_string();

            let v2 = storage(app, "items", r#"{"version":2,"schema":{"type":"OBJECT","properties":{"code":{"type":"STRING","maxLength":40},"qty":{"type":"INTEGER"}}}}"#);
            storages.0.lock().await.insert("items".into(), v2.clone());
            let report = e.reconcile(Some(&c), app, &v2, Some("rusttest")).await.unwrap();
            assert_eq!(report.blocked, vec![db.clone()], "{}", report.summary());
            assert_eq!(report.by_tenant[&db].offending, 1);

            e.delete(&cx(), CLIENT, Some(&c), &v1, &bad, None).await.unwrap();
            let report = e.reconcile(Some(&c), app, &v2, Some("rusttest")).await.unwrap();
            assert!(report.all_clean(), "{}", report.summary());
            assert_eq!(report.summary(), "1 migrated, 0 already current, none blocked");
            let t = scalar(&p, &format!("SELECT COLUMN_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = '{db}' AND TABLE_NAME = 'my_migr_items' AND COLUMN_NAME = 'qty'")).await;
            assert_eq!(t, "int");
            assert_eq!(scalar(&p, &format!("SELECT qty FROM `{db}`.`my_migr_items`")).await, "12");
            let again = e.reconcile(Some(&c), app, &v2, Some("rusttest")).await.unwrap();
            assert_eq!(again.summary(), "0 migrated, 1 already current, none blocked");
            let status = e.migration_status(Some(&c), app, &v2).await.unwrap();
            assert_eq!(status[0].describe(), format!("{db}: applied"));

            // Drift: a column added by hand is reported as a drop that needs approval.
            sqlx::raw_sql(&format!("ALTER TABLE `{db}`.`my_migr_items` ADD COLUMN `extra` INT NULL")).execute(&p).await.unwrap();
            let drift = e.drift(Some(&c), app, &v2).await.unwrap();
            let mine: Vec<_> = drift.iter().filter(|r| r.db == db).collect();
            assert_eq!(mine.len(), 1);
            assert!(mine[0].needs_approval(), "{}", mine[0].summary());
            assert_eq!(mine[0].summary(), format!("{db}.my_migr_items: 1 column change(s) (1 needing approval), 0 index statement(s), 0 key statement(s)"));
            let repaired = e.repair_drift(Some(&c), app, &v2, false).await.unwrap();
            assert_eq!(repaired[0].withheld, vec![format!("ALTER TABLE `{db}`.`my_migr_items` DROP COLUMN `extra`")]);
            let repaired = e.repair_drift(Some(&c), app, &v2, true).await.unwrap();
            assert!(repaired[0].complete(), "{:?}", repaired[0]);
            assert!(e.drift(Some(&c), app, &v2).await.unwrap().iter().all(|r| r.db != db || r.clean()));

            // Recovery: a RUNNING row nobody claims is finished by the sweep.
            let plan = vec![appdata::mysql::migration_planner::MigrationStep::new(
                appdata::mysql::migration_planner::Phase::Expand,
                Some(format!("ALTER TABLE `{db}`.`my_migr_items` ADD COLUMN `swept` INT NULL")),
                Some(appdata::mysql::migration_planner::column_absent(&db, "my_migr_items", "swept")),
                None,
                &appdata::mysql::table_planner::SchemaChange::new(appdata::mysql::table_planner::Kind::Widening, "swept", None, Some("INT"), "test"),
            )];
            let insert = appdata::mysql::journal::insert(&db, "01RUSTTESTSWEEP00000000000", "items", "my_migr_items", None, 3, "ffffffffffffffffffffffffffffffff", "LIVE", 1, Some("rusttest"), &appdata::mysql::migration_planner::write_plan(&plan), None);
            sqlx::raw_sql(&insert).execute(&p).await.unwrap();
            sqlx::raw_sql(&format!("UPDATE `{db}`.`storage_migration` SET `state` = 'RUNNING', `claimed_at` = NULL WHERE `id` = '01RUSTTESTSWEEP00000000000'")).execute(&p).await.unwrap();
            // Only our own scratch schema: a server-wide sweep would also finish real tenants' rows.
            let recovery = migration::sweep_schemas(&p, std::slice::from_ref(&db), 60).await.unwrap();
            let ours = recovery.outcomes.get(&format!("{db}/items")).expect("our row was swept");
            assert!(ours.is_success(), "{ours:?}");
            assert_eq!(scalar(&p, &format!("SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = '{db}' AND TABLE_NAME = 'my_migr_items' AND COLUMN_NAME = 'swept'")).await, "1");
        },
        drop_schemas(&p, app),
    )
    .await;
}

#[tokio::test]
#[ignore = "needs the local MySQL"]
async fn the_draft_surface() {
    let app = "my_draft";
    let storages = Arc::new(Storages::default());
    let e = engine(storages.clone());
    let p = pool(&e).await;
    drop_schemas(&p, app).await;
    guarded(
        async {
            let c = conn().await;

            let items = storage(app, "items", r#"{"isAudited":true,"schema":{"type":"OBJECT","properties":{"name":{"type":"STRING","maxLength":40},"n":{"type":"INTEGER"}}}}"#);
            storages.0.lock().await.insert("items".into(), items.clone());
            for (name, n) in [("a", 1), ("b", 2), ("c", 3)] {
                e.create(&cx(), CLIENT, Some(&c), &items, data(&format!(r#"{{"name":"{name}","n":{n}}}"#))).await.unwrap();
            }
            let draft = cx().on_draft(true);
            assert_eq!(e.read_page(&draft, CLIENT, Some(&c), &items, &Query::default()).await.unwrap().total, 0);
            assert_eq!(e.copy_live_to_draft(&cx(), CLIENT, Some(&c), &items, Some(true)).await.unwrap(), 3);
            assert_eq!(e.read_page(&draft, CLIENT, Some(&c), &items, &Query::default()).await.unwrap().total, 3);
            e.create(&draft, CLIENT, Some(&c), &items, data(r#"{"name":"d","n":4}"#)).await.unwrap();
            assert_eq!(e.read_page(&cx(), CLIENT, Some(&c), &items, &Query::default()).await.unwrap().total, 3, "draft writes stay in the draft");
            assert_eq!(e.clear_draft_rows(&cx(), CLIENT, Some(&c), &items).await.unwrap(), 4);
            let filter = DraftCopyFilter {
                condition: Some(Condition::Filter(FilterCondition::new("n", FilterOperator::GreaterThan, Some(Value::Int(1))))),
                follow: None,
            };
            let copied = e.copy_live_to_draft_filtered(&cx(), CLIENT, Some(&c), &items, Some(&filter), &HashMap::new()).await.unwrap();
            assert_eq!(copied, 2);
            assert!(e.drop_draft_storage(&cx(), CLIENT, Some(&c), &items).await.unwrap());
            assert!(e.drop_draft_database(Some(&c), app, CLIENT).await.unwrap());
            assert_eq!(scalar(&p, &format!("SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = '{CLIENT}_{app}_draft'")).await, "0");
        },
        drop_schemas(&p, app),
    )
    .await;
}
