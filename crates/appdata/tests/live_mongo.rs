//! The Mongo engine against the local MongoDB, in scratch databases named `RUSTTEST_*` that
//! the tests create and drop themselves.
//!
//! Run with: cargo test -p appdata --test live_mongo -- --ignored --test-threads=1
//! (APPDATA_TEST_MONGO_URI overrides mongodb://localhost:27017.)

use std::collections::HashMap;

use appdata::engine::{AppDataEngine, Ctx, Hooks};
use appdata::model::*;
use appdata::mongo::{MongoAppDataService, MongoEngineConfig};
use appdata::retention::VersionRetention;
use appdata::value::Value;
use futures::TryStreamExt;
use mongodb::bson::{doc, Bson, Document as BsonDocument};
use platform::cache::CacheService;

mod support;
use support::guarded;

const CLIENT: &str = "RUSTTEST";

fn uri() -> String {
    std::env::var("APPDATA_TEST_MONGO_URI").unwrap_or_else(|_| "mongodb://localhost:27017".into())
}

fn engine() -> MongoAppDataService {
    let cache = CacheService::new("cmn", "evictionChannel", None).unwrap();
    MongoAppDataService::new(
        MongoEngineConfig { default_uri: Some(uri()), retention: VersionRetention::clamped(0, 0), ..Default::default() },
        Hooks::default(),
        &cache,
    )
}

async fn client() -> mongodb::Client {
    mongodb::Client::with_uri_str(uri()).await.unwrap()
}

async fn drop_dbs(app: &str) {
    let c = client().await;
    for name in [format!("{CLIENT}_{app}"), format!("{CLIENT}_{app}_draft")] {
        assert!(name.starts_with("RUSTTEST_"));
        c.database(&name).drop().await.unwrap();
    }
}

fn v(s: &str) -> Value {
    Value::parse_json(s).unwrap()
}

fn data(json: &str) -> DataObject {
    match v(json) {
        Value::Object(o) => DataObject::of(o),
        _ => panic!(),
    }
}

fn storage(app: &str, name: &str, json: &str) -> Storage {
    let mut value = v(json);
    if let Value::Object(o) = &mut value {
        o.insert("name".into(), Value::from(name));
        o.insert("appCode".into(), Value::from(app));
        o.insert("clientCode".into(), Value::from("SYSTEM"));
        o.insert("uniqueName".into(), Value::from(format!("{app}_{name}")));
    }
    Storage::from_value(&value).unwrap()
}

fn query(json: &str) -> Query {
    Query::from_value(&v(json)).unwrap()
}

fn cx() -> Ctx {
    Ctx { url_client_code: Some(CLIENT.into()), user_id: Some(142), authorities: vec![], draft: false }
}

async fn names(e: &MongoAppDataService, s: &Storage, q: &str) -> Vec<String> {
    let page = e.read_page(&cx(), CLIENT, None, s, &query(q)).await.unwrap();
    page.content.iter().map(|r| r.get("name").map(Value::java_string).unwrap_or_default()).collect()
}

async fn raw(app: &str, coll: &str) -> Vec<BsonDocument> {
    client().await.database(&format!("{CLIENT}_{app}")).collection::<BsonDocument>(coll).find(doc! {}).await.unwrap().try_collect().await.unwrap()
}

#[tokio::test]
#[ignore = "needs the local MongoDB"]
async fn rows_round_trip_with_java_shapes() {
    let app = "mg_crud";
    drop_dbs(app).await;
    guarded(
        async {
            let e = engine();
            let s = storage(
                app,
                "orders",
                r#"{"isAudited":true,"isVersioned":true,"versionRetentionCount":2,"textIndexFields":["name"],
                    "indexes":{"byAmount":{"fields":[{"fieldName":"amount","direction":"DESC"}],"unique":false}},
                    "relations":{"owner":{"storageName":"people","relationType":"TO_ONE"}},
                    "columnDefinitions":{"price":{"mongo":{"bsonType":"DECIMAL128"}},"at":{"mongo":{"bsonType":"DATE"}}},
                    "schema":{"type":"OBJECT","properties":{"name":{"type":"STRING"},"amount":{"type":"LONG"},"price":{"type":"STRING"},"at":{"type":"STRING"},"tags":{"type":"ARRAY"}}}}"#,
            );

            let a = e
                .create(&cx(), CLIENT, None, &s, data(r#"{"name":"alpha","amount":5,"price":"10.50","at":"2026-01-15T10:00:00Z","tags":["red","blue"],"owner":"6ac7d4a11a578c042996bca5"}"#))
                .await
                .unwrap();
            let id = a["_id"].java_string();
            assert_eq!(id.len(), 24);
            // Handed back as stored, as Java does: _id last (the history write took it out), the
            // relation still an ObjectId bean, the declared types as their BSON values.
            assert_eq!(a.keys().last().unwrap(), "_id");
            assert!(a["owner"].as_object().is_some_and(|o| o.contains_key("timestamp")));
            let stored = raw(app, "mg_crud_orders").await;
            assert!(matches!(stored[0].get("price"), Some(Bson::Decimal128(_))));
            assert!(matches!(stored[0].get("at"), Some(Bson::DateTime(_))));
            assert!(matches!(stored[0].get("owner"), Some(Bson::ObjectId(_))));
            assert!(matches!(stored[0].get("amount"), Some(Bson::Int32(5))));

            let read = e.read(&cx(), CLIENT, None, &s, &id).await.unwrap();
            assert_eq!(read["price"], Value::from("10.50"));
            assert_eq!(read["at"], Value::from("2026-01-15T10:00:00"));
            assert_eq!(read["owner"], Value::from("6ac7d4a11a578c042996bca5"));
            assert_eq!(read.keys().last().unwrap(), "_id");
            let err = e.read(&cx(), CLIENT, None, &s, "nope").await.unwrap_err();
            assert_eq!(err.message(), "orders with id nope not found");
            assert!(err.is_object_not_found());

            let given = "6ac7d4a11a578c042996bcff";
            e.create(&cx(), CLIENT, None, &s, data(&format!(r#"{{"_id":"{given}","name":"bravo","amount":15,"tags":["green"]}}"#))).await.unwrap();
            let err = e.create(&cx(), CLIENT, None, &s, data(&format!(r#"{{"_id":"{given}","name":"again"}}"#))).await.unwrap_err();
            assert_eq!(err.status().as_u16(), 409);
            assert_eq!(err.message(), format!("A row with _id {given} already exists in orders. Remove the _id from the data to store it as a new row, or update the existing row instead."));
            e.create(&cx(), CLIENT, None, &s, data(r#"{"name":"charlie","amount":25,"tags":["red"],"note":null}"#)).await.unwrap();

            assert_eq!(names(&e, &s, r#"{"condition":{"field":"amount","operator":"IN","value":"5,15"},"sort":{"property":"amount"}}"#).await, Vec::<String>::new(), "IN on a comma list compares text");
            assert_eq!(names(&e, &s, r#"{"condition":{"field":"amount","operator":"IN","multiValue":[5,15]},"sort":{"property":"amount"}}"#).await, vec!["alpha", "bravo"]);
            assert_eq!(names(&e, &s, r#"{"condition":{"field":"tags","operator":"MATCH","value":"red"},"sort":{"property":"name"}}"#).await, vec!["alpha", "charlie"]);
            assert_eq!(names(&e, &s, r#"{"condition":{"field":"name","operator":"STRING_LOOSE_EQUAL","value":"RAV"}}"#).await, vec!["bravo"]);
            assert_eq!(names(&e, &s, r#"{"condition":{"field":"amount","operator":"BETWEEN","value":10,"toValue":20}}"#).await, vec!["bravo"]);
            assert_eq!(names(&e, &s, r#"{"condition":{"field":"note","operator":"IS_NULL"},"sort":{"property":"name"}}"#).await.len(), 3);
            assert_eq!(names(&e, &s, r#"{"condition":{"field":"owner","value":"6ac7d4a11a578c042996bca5"}}"#).await, vec!["alpha"]);
            assert_eq!(names(&e, &s, r#"{"condition":{"field":"name","operator":"TEXT_SEARCH","value":"charlie"}}"#).await, vec!["charlie"]);
            let page = e.read_page(&cx(), CLIENT, None, &s, &query(r#"{"fields":["name"],"sort":{"property":"name"},"size":2}"#)).await.unwrap();
            assert_eq!(page.content[0].keys().collect::<Vec<_>>(), vec!["name", "_id"]);
            assert_eq!(page.total, 3);
            let page = e.read_page(&cx(), CLIENT, None, &s, &query(r#"{"fields":["tags"],"excludeFields":true,"size":1,"page":1,"sort":{"property":"name"}}"#)).await.unwrap();
            assert_eq!(page.content[0]["name"], Value::from("bravo"));
            assert!(!page.content[0].contains_key("tags"));
            let err = e.read_page(&cx(), CLIENT, None, &s, &query(r#"{"joins":[{"relation":"owner"}]}"#)).await.unwrap_err();
            assert_eq!(err.status().as_u16(), 501);
            assert_eq!(err.message(), "joins is not supported on the Mongo storage backend yet.");

            // PATCH merges into the stored row; the merged keys land in Java HashMap order.
            let patched = e.update(&cx(), CLIENT, None, &s, data(&format!(r#"{{"_id":"{id}","amount":7}}"#)), Some(false)).await.unwrap();
            assert_eq!(patched["name"], Value::from("alpha"));
            assert_eq!(patched["amount"], Value::Int(7));
            assert_eq!(patched["owner"], Value::from("6ac7d4a11a578c042996bca5"));
            let put = e.update(&cx(), CLIENT, None, &s, data(&format!(r#"{{"_id":"{id}","name":"alpha2"}}"#)), Some(true)).await.unwrap();
            assert!(!put.contains_key("amount"));
            let err = e.update(&cx(), CLIENT, None, &s, data(r#"{"name":"x"}"#), None).await.unwrap_err();
            assert_eq!(err.message(), "orders with id null not found to update");

            // History, trimmed to the newest two.
            let versions = e.read_page_version(&cx(), CLIENT, None, &s, &id, &query(r#"{"sort":{"property":"createdAt","direction":"DESC"}}"#), None).await.unwrap();
            assert_eq!(versions.total, 2);
            assert_eq!(versions.content[0]["operation"], Value::from("UPDATE"));
            assert!(matches!(versions.content[0]["createdAt"], Value::Int(_)), "epoch seconds");
            assert_eq!(versions.content[0]["createdBy"], Value::Int(142));
            let audit = e.read_page_version(&cx(), CLIENT, None, &s, &id, &Query::default(), Some(false)).await.unwrap();
            assert!(!audit.content[0].contains_key("object"));
            let vid = audit.content[0]["_id"].java_string();
            assert_eq!(e.read_version(&cx(), CLIENT, None, &s, &vid).await.unwrap()["objectId"], Value::from(id.as_str()));

            // Aggregates: grouped and counted in one facet, an epoch bucket checked for units.
            let agg = AggregateQuery::from_value(&v(r#"{"groupBy":[{"field":"name"}],"aggregations":[{"function":"SUM","field":"amount","alias":"total"}],"sort":{"property":"total","direction":"DESC"},"count":true}"#)).unwrap();
            let page = e.aggregate(&cx(), CLIENT, None, &s, &agg).await.unwrap();
            assert_eq!(page.total, 3);
            assert_eq!(page.content[0]["name"], Value::from("charlie"));
            let millis = AggregateQuery::from_value(&v(r#"{"groupBy":[{"field":"amount","bucket":"DAY"}],"aggregations":[{"function":"COUNT"}]}"#)).unwrap();
            let err = e.aggregate(&cx(), CLIENT, None, &s, &millis).await.unwrap_err();
            assert!(err.message().contains("needs an encoding"), "{}", err.message());

            // References (the PUT above replaced the row, owner and all) and deletes.
            assert_eq!(e.count_referencing(&cx(), CLIENT, None, &s, "owner", false, "6ac7d4a11a578c042996bca5").await.unwrap(), 0);
            e.update(&cx(), CLIENT, None, &s, data(&format!(r#"{{"_id":"{id}","owner":"6ac7d4a11a578c042996bca5"}}"#)), Some(false)).await.unwrap();
            assert_eq!(e.count_referencing(&cx(), CLIENT, None, &s, "owner", false, "6ac7d4a11a578c042996bca5").await.unwrap(), 1);
            assert_eq!(e.ids_referencing(&cx(), CLIENT, None, &s, "owner", false, "6ac7d4a11a578c042996bca5", 5).await.unwrap(), vec![id.clone()]);
            assert!(e.delete(&cx(), CLIENT, None, &s, given, Some(false)).await.unwrap());
            let err = e.delete(&cx(), CLIENT, None, &s, given, Some(false)).await.unwrap_err();
            assert_eq!(err.message(), format!("orders with id {given} not found"));
            let history = e.read_page_version(&cx(), CLIENT, None, &s, given, &Query::default(), None).await.unwrap();
            // No sort given means natural order here (the default updatedAt sort is dropped).
            let ops: Vec<String> = history.content.iter().map(|r| r["operation"].java_string()).collect();
            assert_eq!(ops, vec!["CREATE", "DELETE"]);
            let all = query(r#"{"condition":{"field":"amount","operator":"IS_NULL","negate":true}}"#);
            assert_eq!(e.delete_by_filter(&cx(), CLIENT, None, &s, &all, Some(true), None).await.unwrap(), 1);
            assert_eq!(e.delete_by_filter(&cx(), CLIENT, None, &s, &query("{}"), None, Some(true)).await.unwrap(), 2);
            assert!(raw(app, "mg_crud_orders_version").await.iter().all(|v| v.get_str("objectId") == Ok(given)));

            // Indexes follow the definition.
            let indexes: Vec<String> = client()
                .await
                .database(&format!("{CLIENT}_{app}"))
                .collection::<BsonDocument>("mg_crud_orders")
                .list_index_names()
                .await
                .unwrap();
            assert!(indexes.contains(&"byAmount".to_string()) && indexes.contains(&"_textIndex".to_string()), "{indexes:?}");

            assert!(e.delete_storage(&cx(), CLIENT, None, &s).await.unwrap());
        },
        drop_dbs(app),
    )
    .await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB"]
async fn the_draft_surface() {
    let app = "mg_draft";
    drop_dbs(app).await;
    guarded(
        async {
            let e = engine();
            let people = storage(app, "people", r#"{"schema":{"type":"OBJECT","properties":{"name":{"type":"STRING"}}}}"#);
            let orders = storage(app, "orders", r#"{"relations":{"owner":{"storageName":"people","relationType":"TO_ONE"}},"schema":{"type":"OBJECT","properties":{"name":{"type":"STRING"},"n":{"type":"INTEGER"}}}}"#);
            let p1 = e.create(&cx(), CLIENT, None, &people, data(r#"{"name":"p1"}"#)).await.unwrap()["_id"].java_string();
            let p2 = e.create(&cx(), CLIENT, None, &people, data(r#"{"name":"p2"}"#)).await.unwrap()["_id"].java_string();
            for (n, owner) in [(1, &p1), (2, &p1), (3, &p2)] {
                e.create(&cx(), CLIENT, None, &orders, data(&format!(r#"{{"name":"o{n}","n":{n},"owner":"{owner}"}}"#))).await.unwrap();
            }
            let draft = cx().on_draft(true);
            assert_eq!(e.copy_live_to_draft(&cx(), CLIENT, None, &orders, Some(true)).await.unwrap(), 3);
            assert_eq!(e.read_page(&draft, CLIENT, None, &orders, &Query::default()).await.unwrap().total, 3);
            assert_eq!(e.clear_draft_rows(&cx(), CLIENT, None, &orders).await.unwrap(), 3);

            // Copy one person, then only the orders that follow a copied person.
            let only_p1 = DraftCopyFilter {
                condition: Some(Condition::Filter(FilterCondition::eq("name", "p1"))),
                follow: None,
            };
            assert_eq!(e.copy_live_to_draft_filtered(&cx(), CLIENT, None, &people, Some(&only_p1), &HashMap::new()).await.unwrap(), 1);
            let follow = DraftCopyFilter {
                condition: None,
                follow: Some(vec![Follow { field: "owner".into(), storage: "people".into(), ref_field: None }]),
            };
            let mut followed = HashMap::new();
            followed.insert("people".to_string(), people.clone());
            assert_eq!(e.copy_live_to_draft_filtered(&cx(), CLIENT, None, &orders, Some(&follow), &followed).await.unwrap(), 2);

            assert_eq!(e.estimated_row_count(None, app, CLIENT).await, 5 + 1 + 2);
            assert!(e.drop_draft_storage(&cx(), CLIENT, None, &orders).await.unwrap());
            assert!(e.drop_draft_database(None, app, CLIENT).await.unwrap());
            let names = client().await.list_database_names().await.unwrap();
            assert!(!names.contains(&format!("{CLIENT}_{app}_draft")));
        },
        drop_dbs(app),
    )
    .await;
}
