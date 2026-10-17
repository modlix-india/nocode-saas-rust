//! The write path against the real local MongoDB and Redis.
//!
//! Gated: `#[ignore]`, plus `OVERRIDABLE_TEST_MONGO=1` (Mongo) or `OVERRIDABLE_TEST_REDIS=1`
//! with `MODLIX__REDIS__URL` (Redis). Mongo tests use only a scratch database
//! (`overridable_rusttest_<epoch>_<rand>`, see `scratch`), dropped however the test ends. The
//! Redis test publishes under a cache prefix no service uses (`overridable_rusttest_<rand>`),
//! so no real cache is touched, and deletes the hashes it made.
//!
//! `OVERRIDABLE_TEST_MONGO=1 OVERRIDABLE_TEST_REDIS=1 cargo test -p overridable --test write_mongo -- --include-ignored`

mod common;
mod scratch;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::Query;
use axum::routing::get;
use axum::{Json, Router};
use common::*;
use futures::StreamExt;
use mongodb::bson::{doc, Bson, Document};
use mongodb::options::IndexOptions;
use mongodb::IndexModel;
use overridable::backend::{is_duplicate_key, Backend, FakeDirectory, Find, MemBackend, MongoBackend};
use overridable::json::parse;
use overridable::pojo::str_field;
use overridable::write::condition::Condition;
use overridable::write::publish::PublishService;
use overridable::write::spring::{Pageable, Params, Sort};
use overridable::write::version::UI_AUTH_NAMES;
use overridable::write::{AnyService, Commons, Messages, OverridableService};
use overridable::{JValue, Store};
use platform::cache::{normalize_redis_url, CacheService};
use platform::security::SecurityClient;
use platform::upstream::Upstream;
use serde_json::json;

async fn draft_index(db: &mongodb::Database) {
    let keys = doc! {"objectAppCode": 1, "objectType": 1, "objectName": 1, "clientCode": 1};
    let model = IndexModel::builder().keys(keys).options(IndexOptions::builder().unique(true).name("draftFilteringIndex".to_string()).build()).build();
    db.collection::<Document>("draft").create_index(model).await.unwrap();
}

#[tokio::test]
#[ignore = "needs the local MongoDB (OVERRIDABLE_TEST_MONGO=1)"]
async fn the_mongo_backend_does_what_spring_data_does() {
    let Some(s) = scratch::Scratch::new().await else { return };
    let b = MongoBackend::new(s.db.clone());
    assert_eq!(b.db().name(), s.name);
    let id = b.insert("thing", doc! {"name": "a", "n": 1}).await.unwrap();
    assert!(matches!(id, Bson::ObjectId(_)), "a generated ObjectId");
    b.insert("thing", doc! {"_id": "fixed", "name": "b", "n": 2}).await.unwrap();
    let dup = b.insert("thing", doc! {"_id": "fixed"}).await.unwrap_err();
    assert!(is_duplicate_key(&dup), "error 11000 is a DuplicateKey");
    draft_index(&s.db).await;
    let key = doc! {"objectAppCode": "a", "objectType": "PAGE", "objectName": "p", "clientCode": "C"};
    b.insert("draft", key.clone()).await.unwrap();
    assert!(is_duplicate_key(&b.insert("draft", key.clone()).await.unwrap_err()));
    let mut other = key.clone();
    other.insert("_id", "d2");
    other.insert("clientCode", "D");
    b.replace("draft", Bson::String("d2".into()), other).await.unwrap();
    let mut clash = key.clone();
    clash.insert("_id", "d2");
    assert!(is_duplicate_key(&b.replace("draft", Bson::String("d2".into()), clash).await.unwrap_err()), "a save onto another row's key");

    b.replace("thing", Bson::String("fixed".into()), doc! {"_id": "fixed", "name": "b2", "n": 3}).await.unwrap();
    b.replace("thing", Bson::String("new".into()), doc! {"name": "c", "n": 0}).await.unwrap();
    let all = b.find("thing", Find::new(doc! {}).sort(doc! {"n": -1}).projection(doc! {"name": 1}).skip(1).limit(2)).await.unwrap();
    let names: Vec<&str> = all.iter().map(|d| d.get_str("name").unwrap()).collect();
    assert_eq!(names, ["a", "c"]);
    assert!(!all[0].contains_key("n"));
    assert_eq!(b.count("thing", doc! {"n": {"$gte": 1}}).await.unwrap(), 2);
    assert_eq!(b.find_one("thing", doc! {"name": "b2"}, None).await.unwrap().unwrap().get_i32("n").unwrap(), 3);
    assert_eq!(b.update_many("thing", doc! {"n": {"$gt": 0}}, doc! {"flag": true}).await.unwrap(), 2);
    assert_eq!(b.delete_one("thing", doc! {"flag": true}).await.unwrap(), 1);
    assert_eq!(b.delete_many("thing", doc! {}).await.unwrap(), 2);
    assert!(b.find("thing", Find::new(doc! {"$bad": 1})).await.is_err());
    b.insert("thing", doc! {"_id": "a"}).await.unwrap();
    let not_dup = b.replace("thing", Bson::String("a".into()), doc! {"_id": "b"}).await;
    assert!(not_dup.is_err_and(|e| !is_duplicate_key(&e)), "changing _id is refused, and is no duplicate");
}

#[tokio::test]
#[ignore = "needs the local MongoDB (OVERRIDABLE_TEST_MONGO=1)"]
async fn conditions_select_the_same_documents_in_mongo_and_in_memory() {
    let Some(s) = scratch::Scratch::new().await else { return };
    let mongo = MongoBackend::new(s.db.clone());
    let mem = MemBackend::new();
    let docs = [
        doc! {"_id": "1", "name": "home", "n": 1, "flag": true, "tags": ["a", "b"], "object": {"id": "x"}},
        doc! {"_id": "2", "name": "homework", "n": 5, "flag": false, "nul": null},
        doc! {"_id": "3", "name": "about", "n": 10},
        doc! {"_id": "4", "name": "Home", "n": 7.5, "object": {"id": "y"}},
    ];
    for d in &docs {
        mongo.insert("c", d.clone()).await.unwrap();
        mem.insert("c", d.clone()).await.unwrap();
    }
    let conditions = [
        r#"{"field":"name","value":"home"}"#,
        r#"{"field":"name","operator":"STRING_LOOSE_EQUAL","value":"home"}"#,
        r#"{"field":"name","operator":"LIKE","value":"^h","negate":true}"#,
        r#"{"field":"n","operator":"BETWEEN","value":2,"toValue":8}"#,
        r#"{"field":"n","operator":"BETWEEN","value":2,"toValue":8,"negate":true}"#,
        r#"{"field":"nul","operator":"IS_NULL"}"#,
        r#"{"field":"nul","operator":"IS_NULL","negate":true}"#,
        r#"{"field":"flag","operator":"IS_TRUE"}"#,
        r#"{"field":"name","operator":"IN","value":"home,about"}"#,
        r#"{"field":"n","operator":"IN","multiValue":[1,10],"negate":true}"#,
        r#"{"field":"n","operator":"GREATER_THAN_EQUAL","value":5}"#,
        r#"{"field":"object.id","value":"y"}"#,
        r#"{"field":"tags","value":"b"}"#,
        r#"{"operator":"OR","conditions":[{"field":"n","operator":"LESS_THAN","value":2},{"field":"name","value":"about"}]}"#,
        r#"{"operator":"AND","conditions":[{"field":"n","operator":"GREATER_THAN","value":2},{"field":"n","operator":"LESS_THAN_EQUAL","value":7.5}],"negate":true}"#,
    ];
    for c in conditions {
        let cond = Condition::from_json(&parse(c.as_bytes()).unwrap()).unwrap();
        let filter = Condition::to_mongo(cond.as_ref()).unwrap();
        let ids = |v: Vec<Document>| -> Vec<String> { v.iter().map(|d| d.get_str("_id").unwrap().to_string()).collect() };
        let q = Find::new(filter).sort(doc! {"_id": 1});
        assert_eq!(ids(mongo.find("c", q.clone()).await.unwrap()), ids(mem.find("c", q).await.unwrap()), "{c}");
    }
    let expr = Condition::from_json(&parse(br#"{"fieldExpr":{"function":"LOWER","fields":["name"]},"value":"home"}"#).unwrap()).unwrap();
    let found = mongo.find("c", Find::new(Condition::to_mongo(expr.as_ref()).unwrap())).await.unwrap();
    assert_eq!(found.len(), 2, "$expr runs on the database");
}

async fn mongo_pages(s: &scratch::Scratch) -> (OverridableService<PageKind>, Commons, Arc<FakeDirectory>) {
    draft_index(&s.db).await;
    let dir = Arc::new(FakeDirectory::new());
    dir.chain(&[SYSTEM]);
    let cache = CacheService::new("cmn", "evictionChannel", None).unwrap();
    let store = Store::with_parts(Arc::new(MongoBackend::new(s.db.clone())), dir.clone(), &cache).unwrap();
    let cx = Commons::new(store, cache, Messages::ui(), UI_AUTH_NAMES);
    (OverridableService::new(PageKind::default(), cx.clone()), cx, dir)
}

#[tokio::test]
#[ignore = "needs the local MongoDB (OVERRIDABLE_TEST_MONGO=1)"]
async fn the_write_path_on_a_real_database() {
    let Some(s) = scratch::Scratch::new().await else { return };
    let (pages, cx, dir) = mongo_pages(&s).await;
    let sys = system();
    let created = pages.create(&sys, obj(r#"{"name":"p","appCode":"testapp","rootComponent":"root","properties":{"shared":"s","a.b":"dotted"}}"#)).await.unwrap();
    let id = str_field(&created, "id").unwrap().to_string();
    let raw = s.db.collection::<Document>("page").find_one(doc! {}).await.unwrap().unwrap();
    assert!(raw.get_document("properties").unwrap().contains_key("a__d-o-t__b"), "dotted keys stored escaped");
    assert_eq!(prop_str(&pages.read(&sys, &id).await.unwrap(), "a.b"), Some("dotted"));

    let draft = obj(&format!(r#"{{"id":"{id}","properties":{{"shared":"s","fromDraft":"d"}}}}"#));
    pages.save_draft(&sys, draft.clone(), Some(0)).await.unwrap();
    assert_eq!(pages.save_draft(&sys, draft, Some(0)).await.unwrap_err().status(), axum::http::StatusCode::PRECONDITION_FAILED);
    let mut live = pages.read(&sys, &id).await.unwrap();
    live.get_mut("properties").unwrap().as_object_mut().unwrap().insert("fromLive".into(), JValue::Str("L".into()));
    pages.update(&sys, live).await.unwrap();
    let preview = pages.read_resolved(&sys, "p", APP, SYSTEM, true).await.unwrap().unwrap();
    assert_eq!((prop_str(&preview.entity, "fromDraft"), prop_str(&preview.entity, "fromLive")), (Some("d"), Some("L")));
    let published = PublishService::new(cx.clone(), vec![Arc::new(pages.clone()) as Arc<dyn AnyService>]).publish_all(&sys, APP, None).await.unwrap();
    assert_eq!(published["published"], JValue::Int(1));
    let stored = pages.read(&sys, &id).await.unwrap();
    assert_eq!(str_field(&stored, "message"), Some("[reconciled from v1 onto live v2]"));
    assert_eq!(stored["version"], JValue::Int(3));

    dir.chain(&[SYSTEM, "LZCLB"]);
    dir.set(|a| a.manages_all = false);
    let tenant = auth_for("LZCLB", &all_for("Page"));
    let fork = pages.fork_for_caller(&tenant, &id).await.unwrap();
    assert_eq!((str_field(&fork, "baseClientCode"), &fork["published"]), (Some(SYSTEM), &JValue::Bool(false)));
    let list = pages.read_page_filter_lro(&tenant, false, false, &Pageable::of(0, 10, Sort::unsorted()), &Params::of(&[("appCode", APP)])).await.unwrap();
    assert_eq!(list.total, 1);
    assert_eq!(str_field(&list.content[0], "clientCode"), Some("LZCLB"));
    let history = cx.versions.read_page_per_object_id(&sys, &id, &overridable::write::condition::Query::from_json(&JValue::Null).unwrap()).await.unwrap();
    assert_eq!(history.as_object().unwrap()["totalElements"], JValue::Int(3));
    let fork_id = str_field(&fork, "id").unwrap().to_string();
    assert!(pages.delete(&tenant, &fork_id).await.unwrap());
    dir.set(|a| a.manages_all = true);
    assert_eq!(pages.delete_everything(&sys, APP, SYSTEM).await.unwrap(), Some(true));
    assert_eq!(s.db.collection::<Document>("page").count_documents(doc! {}).await.unwrap(), 0);
}

#[tokio::test]
#[ignore = "needs the local MongoDB (OVERRIDABLE_TEST_MONGO=1)"]
async fn the_production_store_answers_through_security() {
    let Some(s) = scratch::Scratch::new().await else { return };
    let app = Router::new()
        .route(
            "/api/security/applications/internal/appInheritance",
            get(|Query(q): Query<HashMap<String, String>>| async move { Json(json!(["SYSTEM", q.get("clientCode").cloned().unwrap_or_default()])) }),
        )
        .route("/api/security/applications/internal/explicitInfo/{app}", get(|| async { Json(json!({"appAccessType": "ANY", "clientCode": "SYSTEM"})) }))
        .route("/api/security/applications/internal/hasReadAccess", get(|| async { Json(json!(true)) }))
        .route("/api/security/applications/internal/hasWriteAccess", get(|| async { Json(json!(true)) }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await });
    let security = SecurityClient::new(Upstream::fixed(&[&format!("http://{addr}")]), 0).unwrap();
    let cache = CacheService::new("cmn", "evictionChannel", None).unwrap();
    let store = Store::new(s.db.clone(), security, &cache);
    let pages = OverridableService::new(PageKind::default(), Commons::new(store, cache, Messages::ui(), UI_AUTH_NAMES));
    let created = pages.create(&system(), obj(r#"{"name":"p","appCode":"testapp"}"#)).await.unwrap();
    let mid = auth_for("LZCLA", &all_for("Page"));
    assert!(pages.read(&mid, str_field(&created, "id").unwrap()).await.is_ok(), "the chain from security lets LZCLA read SYSTEM's page");
}

#[tokio::test]
#[ignore = "needs the local Redis (OVERRIDABLE_TEST_REDIS=1, MODLIX__REDIS__URL)"]
async fn evictions_reach_redis_as_java_publishes_them() {
    if std::env::var("OVERRIDABLE_TEST_REDIS").as_deref() != Ok("1") {
        return;
    }
    let url = std::env::var("MODLIX__REDIS__URL").expect("MODLIX__REDIS__URL");
    let prefix = format!("overridable_rusttest_{:08x}", rand::random::<u32>());
    let client = redis::Client::open(normalize_redis_url(&url).as_str()).unwrap();
    let mut conn = client.get_multiplexed_async_connection().await.unwrap();
    let mut pubsub = client.get_async_pubsub().await.unwrap();
    pubsub.subscribe("evictionChannel").await.unwrap();
    let mut messages = Box::pin(pubsub.into_on_message());

    let hp = format!("{prefix}-PageCache_testapp_p");
    let hq = format!("{prefix}-PageCache_testapp_q");
    for (h, k) in [(&hp, SYSTEM), (&hq, SYSTEM), (&hq, "OTHER")] {
        let _: i64 = redis::cmd("HSET").arg(h).arg(k).arg("x").query_async(&mut conn).await.unwrap();
    }

    let mem = Arc::new(MemBackend::new());
    let dir = Arc::new(FakeDirectory::new());
    dir.chain(&[SYSTEM]);
    let cache = CacheService::new(&prefix, "evictionChannel", Some(&url)).unwrap();
    let store = Store::with_parts(mem.clone(), dir, &cache).unwrap();
    let pages = OverridableService::new(PageKind::default(), Commons::new(store, cache, Messages::ui(), UI_AUTH_NAMES));
    let sys = system();
    let p = pages.create(&sys, obj(r#"{"name":"p","appCode":"testapp"}"#)).await.unwrap();
    let q = pages.create(&sys, obj(r#"{"name":"q","appCode":"testapp"}"#)).await.unwrap();
    let _: i64 = redis::cmd("HSET").arg(&hp).arg(SYSTEM).arg("x").query_async(&mut conn).await.unwrap();
    let _: i64 = redis::cmd("HSET").arg(&hq).arg(SYSTEM).arg("x").arg("OTHER").arg("x").query_async(&mut conn).await.unwrap();

    let mut got: Vec<String> = Vec::new();
    collect(&mut messages, &mut got, &prefix, 6).await;
    pages.update(&sys, p).await.unwrap();
    collect(&mut messages, &mut got, &prefix, 10).await;
    pages.delete(&sys, str_field(&q, "id").unwrap()).await.unwrap();
    collect(&mut messages, &mut got, &prefix, 13).await;
    assert_eq!(
        got,
        [
            "PageCache_testapp_p:*",
            "PageCache_testapp_p_DRAFT:*",
            "PageCache_testapp_Page_READ_PAGE:*",
            "PageCache_testapp_q:*",
            "PageCache_testapp_q_DRAFT:*",
            "PageCache_testapp_Page_READ_PAGE:*",
            "PageCache_testapp_p:*",
            "PageCache_testapp_p_DRAFT:*",
            "PageCache_testapp_Page_READ_PAGE:*",
            "pageOUICache-testapp:*",
            "PageCache_testapp_q:SYSTEM",
            "PageCache_testapp_q_DRAFT:SYSTEM",
            "PageCache_testapp_Page_READ_PAGE:*",
        ]
    );
    let exists: i64 = redis::cmd("EXISTS").arg(&hp).query_async(&mut conn).await.unwrap();
    assert_eq!(exists, 0, "an evictAll deletes the Java L2 hash");
    let left: Vec<String> = redis::cmd("HKEYS").arg(&hq).query_async(&mut conn).await.unwrap();
    assert_eq!(left, ["OTHER"], "a single-key eviction deletes only that field");
    let _: i64 = redis::cmd("DEL").arg(&hp).arg(&hq).query_async(&mut conn).await.unwrap();
}

/// Messages on the channel under `prefix`, until `got` holds `n` of them (or 5s pass).
async fn collect<S: futures::Stream<Item = redis::Msg> + Unpin>(messages: &mut S, got: &mut Vec<String>, prefix: &str, n: usize) {
    while got.len() < n {
        let Ok(Some(m)) = tokio::time::timeout(Duration::from_secs(5), messages.next()).await else { break };
        let payload: String = m.get_payload().unwrap_or_default();
        if let Some(rest) = payload.strip_prefix(&format!("{prefix}-")) {
            got.push(rest.to_string());
        }
    }
}
