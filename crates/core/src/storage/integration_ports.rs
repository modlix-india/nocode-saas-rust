//! Ports of core's Spring integration tests for `AppDataService` (Testcontainers Mongo,
//! security mocked): `AppDataKIRunOnlyIntegrationTest`, `AppDataSurfaceIntegrationTest`,
//! `EagerFetchIntegrationTest`. One Rust test per Java test, same names in snake case.
//!
//! The Java tests insert their storages and fixture rows straight into a throwaway Mongo; here
//! the definitions and the engine are the in-memory doubles (`testing::doubles`), which keep
//! live and draft rows apart as the two databases do. What the doubles cannot show (a Mongo
//! collection surviving a clear, the version collection's rows, the number of `find`
//! commands) is the engines' business and is checked in `crates/appdata`; those assertions are
//! kept here as what the policy layer hands the engine.

use std::sync::Arc;

use appdata::model::{DataObject, Query, Storage};
use appdata::value::{Document, Value};
use axum::http::StatusCode;
use serde_json::json;

use super::service::AppDataService;
use crate::context::{self, RequestContext};
use crate::testing::{auth, policy, request, security_stub, MemoryCatalog, MemoryEngine, RecordingEvents};

const APP_CODE: &str = "testapp";
const SYSTEM: &str = "SYSTEM";

fn st(v: serde_json::Value) -> Storage {
    Storage::from_value(&Value::from_json(&v)).unwrap()
}

fn row(title: &str) -> DataObject {
    let mut d = Document::new();
    d.insert("title".into(), Value::from(title));
    DataObject::of(d)
}

fn all() -> Query {
    Query { page: 0, size: 50, ..Query::default() }
}

/// `authFor(SYSTEM, allAuthoritiesFor("Storage"))`, with a verified app code.
fn caller(verified: &str, draft: bool) -> Arc<RequestContext> {
    request(
        auth(
            json!({"user": {"id": 7, "clientId": 1, "stringAuthorities": ["Authorities.Storage_CREATE", "Authorities.Storage_READ",
                                                                     "Authorities.Storage_UPDATE", "Authorities.Storage_DELETE"]},
                   "authenticated": true, "clientCode": SYSTEM, "verifiedAppCode": verified}),
            Some(SYSTEM),
            Some(APP_CODE),
        ),
        draft,
        None,
    )
}

async fn service(storages: Vec<Storage>, writable: bool) -> (AppDataService, Arc<MemoryEngine>) {
    let base = security_stub(&[], if writable { &[APP_CODE] } else { &[] }).await;
    let engine = Arc::new(MemoryEngine::default());
    let svc = policy(MemoryCatalog::with(storages), engine.clone(), &base, Arc::new(RecordingEvents::default()));
    (svc, engine)
}

// ------------------------------------------------------------------ AppDataKIRunOnlyIntegrationTest

const KIRUN_STORAGE: &str = "KIRunOnlyStorage";

fn kirun_storage(only: bool) -> Storage {
    st(json!({"name": KIRUN_STORAGE, "appCode": APP_CODE, "clientCode": SYSTEM, "onlyThruKIRun": only,
              "schema": {"name": "KIRunOnlyStorage", "type": "OBJECT", "properties": {"title": {"type": "STRING"}, "child": {"type": "STRING"}}}}))
}

fn parent_storage() -> Storage {
    st(json!({"name": "KIRunOnlyParent", "appCode": APP_CODE, "clientCode": SYSTEM,
              "relations": {"child": {"storageName": KIRUN_STORAGE, "relationType": "TO_ONE", "fieldName": "child"}}}))
}

#[tokio::test]
async fn builder_session_reads_live_rows() {
    let (svc, engine) = service(vec![kirun_storage(true)], true).await;
    engine.insert(KIRUN_STORAGE, "1", Document::from_iter([("title".to_string(), Value::from("live row"))]));
    let page = context::with_request(caller("appbuilder", false), svc.read_page(Some(APP_CODE), Some(SYSTEM), KIRUN_STORAGE, &all()))
        .await
        .unwrap();
    assert_eq!(page.total, 1);
    assert_eq!(page.content[0]["title"], Value::from("live row"));
}

#[tokio::test]
async fn builder_session_writes_live_rows() {
    let (svc, engine) = service(vec![kirun_storage(true)], true).await;
    let created = context::with_request(
        caller("appbuilder", false),
        svc.create(Some(APP_CODE), Some(SYSTEM), KIRUN_STORAGE, row("written"), Some(false), None),
    )
    .await
    .unwrap();
    assert_eq!(created["title"], Value::from("written"));
    assert_eq!(engine.count(KIRUN_STORAGE), 1);
}

#[tokio::test]
async fn builder_session_reads_draft_rows() {
    let (svc, engine) = service(vec![kirun_storage(true)], true).await;
    engine.insert(KIRUN_STORAGE, "1", Document::from_iter([("title".to_string(), Value::from("live row"))]));
    engine.insert_draft(KIRUN_STORAGE, "2", Document::from_iter([("title".to_string(), Value::from("draft row"))]));
    let page = context::with_request(caller("appbuilder", true), svc.read_page(Some(APP_CODE), Some(SYSTEM), KIRUN_STORAGE, &all()))
        .await
        .unwrap();
    assert_eq!(page.total, 1);
    assert_eq!(page.content[0]["title"], Value::from("draft row"));
}

#[tokio::test]
async fn copy_to_draft_from_a_builder_session_copies_rows() {
    let (svc, engine) = service(vec![kirun_storage(true)], true).await;
    engine.insert(KIRUN_STORAGE, "1", Document::new());
    engine.insert(KIRUN_STORAGE, "2", Document::new());
    let copied = context::with_request(
        caller("appbuilder", false),
        svc.copy_live_data_to_draft(Some(APP_CODE), Some(SYSTEM), KIRUN_STORAGE, Some(true)),
    )
    .await
    .unwrap();
    assert_eq!(copied, 2);
    assert_eq!(engine.draft_count(KIRUN_STORAGE), 2);
}

#[tokio::test]
async fn configured_builder_app_codes_are_all_honoured() {
    let (svc, engine) = service(vec![kirun_storage(true)], true).await;
    engine.insert(KIRUN_STORAGE, "1", Document::new());
    let page = context::with_request(caller("sitezump", false), svc.read_page(Some(APP_CODE), Some(SYSTEM), KIRUN_STORAGE, &all()))
        .await
        .unwrap();
    assert_eq!(page.total, 1);
}

#[tokio::test]
async fn non_builder_session_is_refused_with_a_reason() {
    let (svc, engine) = service(vec![kirun_storage(true)], true).await;
    engine.insert(KIRUN_STORAGE, "1", Document::new());
    let e = context::with_request(caller("", false), svc.read_page(Some(APP_CODE), Some(SYSTEM), KIRUN_STORAGE, &all()))
        .await
        .unwrap_err();
    assert_eq!(e.status(), StatusCode::FORBIDDEN);
    assert!(e.text().contains("onlyThruKIRun"), "{}", e.text());
    assert!(!e.text().contains("not found"));
}

#[tokio::test]
async fn copy_to_draft_from_a_non_builder_session_is_refused() {
    let (svc, engine) = service(vec![kirun_storage(true)], true).await;
    engine.insert(KIRUN_STORAGE, "1", Document::new());
    let e = context::with_request(caller("", false), svc.copy_live_data_to_draft(Some(APP_CODE), Some(SYSTEM), KIRUN_STORAGE, Some(true)))
        .await
        .unwrap_err();
    assert_eq!(e.status(), StatusCode::FORBIDDEN);
    assert!(e.text().contains("onlyThruKIRun"));
    assert_eq!(engine.draft_count(KIRUN_STORAGE), 0);
}

#[tokio::test]
async fn non_builder_session_is_refused_on_write() {
    let (svc, engine) = service(vec![kirun_storage(true)], true).await;
    let e = context::with_request(caller("", false), svc.create(Some(APP_CODE), Some(SYSTEM), KIRUN_STORAGE, row("nope"), Some(false), None))
        .await
        .unwrap_err();
    assert_eq!(e.status(), StatusCode::FORBIDDEN);
    assert_eq!(engine.count(KIRUN_STORAGE), 0);
}

#[tokio::test]
async fn an_unconfigured_app_code_is_refused() {
    let (svc, engine) = service(vec![kirun_storage(true)], true).await;
    engine.insert(KIRUN_STORAGE, "1", Document::new());
    let e = context::with_request(caller("leadzump", false), svc.read_page(Some(APP_CODE), Some(SYSTEM), KIRUN_STORAGE, &all()))
        .await
        .unwrap_err();
    assert_eq!(e.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_storage_without_the_flag_is_unaffected() {
    let (svc, engine) = service(vec![kirun_storage(false)], true).await;
    engine.insert(KIRUN_STORAGE, "1", Document::new());
    let as_user = context::with_request(caller("", false), svc.read_page(Some(APP_CODE), Some(SYSTEM), KIRUN_STORAGE, &all())).await.unwrap();
    let as_builder =
        context::with_request(caller("appbuilder", false), svc.read_page(Some(APP_CODE), Some(SYSTEM), KIRUN_STORAGE, &all())).await.unwrap();
    assert_eq!((as_user.total, as_builder.total), (1, 1));
}

#[tokio::test]
async fn eager_relation_to_a_kirun_only_storage_is_skipped() {
    let (svc, engine) = service(vec![kirun_storage(true), parent_storage()], true).await;
    engine.insert(KIRUN_STORAGE, "c1", Document::from_iter([("title".to_string(), Value::from("child row"))]));
    engine.insert(
        "KIRunOnlyParent",
        "p1",
        Document::from_iter([("title".to_string(), Value::from("parent row")), ("child".to_string(), Value::from("c1"))]),
    );
    let read = context::with_request(
        caller("", false),
        svc.read(Some(APP_CODE), Some(SYSTEM), "KIRunOnlyParent", "p1", Some(true), Some(vec!["child".into()])),
    )
    .await
    .unwrap();
    assert_eq!(read["title"], Value::from("parent row"));
}

// ------------------------------------------------------------------ AppDataSurfaceIntegrationTest

const SURFACE: &str = "SurfaceStorage";
const RUNTIME_ONLY_AUTH: &str = "Authorities.CXAPP.ROLE_Super_Admin";

fn surface_storage(runtime_auth: Option<&str>) -> Storage {
    st(json!({"name": SURFACE, "appCode": APP_CODE, "clientCode": SYSTEM, "createAuth": runtime_auth, "deleteAuth": runtime_auth,
              "updateAuth": runtime_auth, "schema": {"name": "SurfaceStorage", "type": "OBJECT", "properties": {"title": {"type": "STRING"}}}}))
}

async fn surface(writable: bool, runtime_auth: Option<&str>) -> (AppDataService, Arc<MemoryEngine>) {
    service(vec![surface_storage(runtime_auth)], writable).await
}

async fn create_on(svc: &AppDataService, draft: bool, title: &str) {
    context::with_request(caller("", draft), svc.create(Some(APP_CODE), Some(SYSTEM), SURFACE, row(title), Some(false), None))
        .await
        .unwrap();
}

fn titles(rows: &[Document]) -> Vec<String> {
    rows.iter().map(|r| r["title"].java_string()).collect()
}

#[tokio::test]
async fn explicit_draft_reads_draft_rows() {
    let (svc, _) = surface(true, None).await;
    create_on(&svc, false, "live row").await;
    create_on(&svc, true, "draft row").await;
    let q = all();
    let page = context::with_request(
        caller("", false),
        svc.on_surface(Some(APP_CODE), Some(true), svc.read_page(Some(APP_CODE), Some(SYSTEM), SURFACE, &q)),
    )
    .await
    .unwrap();
    assert_eq!(titles(&page.content), ["draft row"]);
}

#[tokio::test]
async fn explicit_live_overrides_ambient_draft() {
    let (svc, _) = surface(true, None).await;
    create_on(&svc, false, "live row").await;
    create_on(&svc, true, "draft row").await;
    let q = all();
    let page = context::with_request(
        caller("", true),
        svc.on_surface(Some(APP_CODE), Some(false), svc.read_page(Some(APP_CODE), Some(SYSTEM), SURFACE, &q)),
    )
    .await
    .unwrap();
    assert_eq!(titles(&page.content), ["live row"]);
}

#[tokio::test]
async fn absent_parameter_keeps_ambient_surface() {
    let (svc, _) = surface(true, None).await;
    create_on(&svc, false, "live row").await;
    create_on(&svc, true, "draft row").await;
    let q = all();
    let page = context::with_request(caller("", true), svc.on_surface(Some(APP_CODE), None, svc.read_page(Some(APP_CODE), Some(SYSTEM), SURFACE, &q)))
        .await
        .unwrap();
    assert_eq!(titles(&page.content), ["draft row"]);
}

#[tokio::test]
async fn naming_surface_needs_write_access() {
    let (svc, _) = surface(false, None).await;
    let q = all();
    let e = context::with_request(
        caller("", false),
        svc.on_surface(Some(APP_CODE), Some(true), svc.read_page(Some(APP_CODE), Some(SYSTEM), SURFACE, &q)),
    )
    .await
    .unwrap_err();
    assert_eq!(e.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn unwritten_draft_reads_empty() {
    let (svc, _) = surface(true, None).await;
    create_on(&svc, false, "live row").await;
    let q = all();
    let page = context::with_request(
        caller("", false),
        svc.on_surface(Some(APP_CODE), Some(true), svc.read_page(Some(APP_CODE), Some(SYSTEM), SURFACE, &q)),
    )
    .await
    .unwrap();
    assert!(page.content.is_empty());
}

#[tokio::test]
async fn clear_keeps_collection_and_history() {
    let (svc, engine) = surface(true, None).await;
    create_on(&svc, false, "one").await;
    create_on(&svc, false, "two").await;
    let deleted = context::with_request(
        caller("", false),
        svc.delete_by_filter(Some(APP_CODE), Some(SYSTEM), SURFACE, &Query::default(), Some(false), None),
    )
    .await
    .unwrap();
    assert_eq!(deleted, 2);
    assert_eq!(engine.count(SURFACE), 0);
    // The collection and the version rows are the engine's (crates/appdata); the policy layer
    // asked for a row delete, never a drop.
    assert!(!engine.calls.lock().iter().any(|c| c.starts_with("drop")));
}

#[tokio::test]
async fn dry_run_counts_only() {
    let (svc, engine) = surface(true, None).await;
    create_on(&svc, false, "one").await;
    create_on(&svc, false, "two").await;
    let counted = context::with_request(
        caller("", false),
        svc.delete_by_filter(Some(APP_CODE), Some(SYSTEM), SURFACE, &Query::default(), Some(true), None),
    )
    .await
    .unwrap();
    assert_eq!(counted, 2);
    assert_eq!(engine.count(SURFACE), 2);
}

#[tokio::test]
async fn clear_on_draft_leaves_live() {
    let (svc, engine) = surface(true, None).await;
    create_on(&svc, false, "live row").await;
    create_on(&svc, true, "draft row").await;
    let q = Query::default();
    let deleted = context::with_request(
        caller("", false),
        svc.on_surface(Some(APP_CODE), Some(true), svc.delete_by_filter(Some(APP_CODE), Some(SYSTEM), SURFACE, &q, Some(false), None)),
    )
    .await
    .unwrap();
    assert_eq!(deleted, 1);
    assert_eq!(engine.draft_count(SURFACE), 0);
    assert_eq!(engine.count(SURFACE), 1);
}

#[tokio::test]
async fn copy_preserves_ids_and_keeps_live() {
    let (svc, engine) = surface(true, None).await;
    create_on(&svc, false, "one").await;
    create_on(&svc, false, "two").await;
    let copied = context::with_request(caller("", false), svc.copy_live_data_to_draft(Some(APP_CODE), Some(SYSTEM), SURFACE, Some(true)))
        .await
        .unwrap();
    assert_eq!(copied, 2);
    let rows = engine.rows.lock();
    let live: Vec<&String> = rows[SURFACE].keys().collect();
    let draft: Vec<&String> = rows[&format!("{SURFACE}#draft")].keys().collect();
    assert_eq!(live, draft);
}

#[tokio::test]
async fn copy_with_replace_clears_draft_first() {
    let (svc, engine) = surface(true, None).await;
    create_on(&svc, false, "live only").await;
    create_on(&svc, true, "sandbox scratch").await;
    context::with_request(caller("", false), svc.copy_live_data_to_draft(Some(APP_CODE), Some(SYSTEM), SURFACE, Some(true)))
        .await
        .unwrap();
    let rows = engine.rows.lock();
    let draft: Vec<Document> = rows[&format!("{SURFACE}#draft")].values().cloned().collect();
    assert_eq!(titles(&draft), ["live only"]);
}

#[tokio::test]
async fn copy_twice_is_idempotent() {
    let (svc, engine) = surface(true, None).await;
    create_on(&svc, false, "one").await;
    let ctx = caller("", false);
    context::with_request(ctx.clone(), svc.copy_live_data_to_draft(Some(APP_CODE), Some(SYSTEM), SURFACE, Some(false))).await.unwrap();
    let second = context::with_request(ctx, svc.copy_live_data_to_draft(Some(APP_CODE), Some(SYSTEM), SURFACE, Some(false))).await.unwrap();
    assert_eq!(second, 1);
    assert_eq!(engine.draft_count(SURFACE), 1);
}

#[tokio::test]
async fn copy_with_empty_source_changes_nothing() {
    let (svc, engine) = surface(true, None).await;
    create_on(&svc, true, "sandbox scratch").await;
    let e = context::with_request(caller("", false), svc.copy_live_data_to_draft(Some(APP_CODE), Some(SYSTEM), SURFACE, Some(true)))
        .await
        .unwrap_err();
    assert_eq!(e.status(), StatusCode::BAD_REQUEST);
    assert_eq!(engine.draft_count(SURFACE), 1);
}

#[tokio::test]
async fn copy_ignores_runtime_create_auth() {
    let (svc, engine) = surface(true, Some(RUNTIME_ONLY_AUTH)).await;
    engine.insert(SURFACE, "1", Document::from_iter([("title".to_string(), Value::from("live one"))]));
    let copied = context::with_request(caller("", false), svc.copy_live_data_to_draft(Some(APP_CODE), Some(SYSTEM), SURFACE, Some(true)))
        .await
        .unwrap();
    assert_eq!(copied, 1);
    assert_eq!(engine.draft_count(SURFACE), 1);
}

#[tokio::test]
async fn clear_ignores_runtime_delete_auth() {
    let (svc, engine) = surface(true, Some(RUNTIME_ONLY_AUTH)).await;
    engine.insert(SURFACE, "1", Document::new());
    engine.insert(SURFACE, "2", Document::new());
    let cleared = context::with_request(caller("", false), svc.clear_all_rows(Some(APP_CODE), Some(SYSTEM), SURFACE, Some(false)))
        .await
        .unwrap();
    assert_eq!(cleared, 2);
    assert_eq!(engine.count(SURFACE), 0);
}

#[tokio::test]
async fn clear_needs_one_of_the_two_bars() {
    let (svc, engine) = surface(false, Some(RUNTIME_ONLY_AUTH)).await;
    engine.insert(SURFACE, "1", Document::new());
    let e = context::with_request(caller("", false), svc.clear_all_rows(Some(APP_CODE), Some(SYSTEM), SURFACE, Some(false)))
        .await
        .unwrap_err();
    assert_eq!(e.status(), StatusCode::FORBIDDEN);
    assert_eq!(engine.count(SURFACE), 1);
}

#[tokio::test]
async fn clear_still_honours_delete_auth() {
    let (svc, engine) = surface(false, Some("Authorities.Storage_DELETE")).await;
    engine.insert(SURFACE, "1", Document::new());
    let cleared = context::with_request(caller("", false), svc.clear_all_rows(Some(APP_CODE), Some(SYSTEM), SURFACE, Some(false)))
        .await
        .unwrap();
    assert_eq!(cleared, 1);
    assert_eq!(engine.count(SURFACE), 0);
}

#[tokio::test]
async fn copy_needs_write_access() {
    let (svc, _) = surface(false, None).await;
    create_on(&svc, false, "one").await;
    let e = context::with_request(caller("", false), svc.copy_live_data_to_draft(Some(APP_CODE), Some(SYSTEM), SURFACE, Some(true)))
        .await
        .unwrap_err();
    assert_eq!(e.status(), StatusCode::FORBIDDEN);
}

// ------------------------------------------------------------------ EagerFetchIntegrationTest

const CUSTOMERS: &str = "customers";
const TAGS: &str = "tags";
const ORDERS: &str = "orders";

async fn given_storages(customer_read_auth: Option<&str>) -> (AppDataService, Arc<MemoryEngine>) {
    service(
        vec![
            st(json!({"name": CUSTOMERS, "appCode": APP_CODE, "clientCode": SYSTEM, "readAuth": customer_read_auth})),
            st(json!({"name": TAGS, "appCode": APP_CODE, "clientCode": SYSTEM})),
            st(json!({"name": ORDERS, "appCode": APP_CODE, "clientCode": SYSTEM, "relations": {
                "customer": {"storageName": CUSTOMERS, "relationType": "TO_ONE", "fieldName": "_id"},
                "labels": {"storageName": TAGS, "relationType": "TO_MANY", "fieldName": "_id"}}})),
        ],
        true,
    )
    .await
}

async fn write(svc: &AppDataService, storage: &str, field: &str, value: Value) -> String {
    let d = Document::from_iter([(field.to_string(), value)]);
    context::with_request(caller("", false), svc.create(Some(APP_CODE), Some(SYSTEM), storage, DataObject::of(d), Some(false), None))
        .await
        .unwrap()["_id"]
        .java_string()
}

async fn write_order(svc: &AppDataService, r: &str, customer: Option<&str>, tags: Option<Vec<String>>) -> String {
    let mut d = Document::from_iter([("ref".to_string(), Value::from(r))]);
    if let Some(c) = customer {
        d.insert("customer".into(), Value::from(c));
    }
    if let Some(t) = tags {
        d.insert("labels".into(), Value::Array(t.into_iter().map(Value::String).collect()));
    }
    context::with_request(caller("", false), svc.create(Some(APP_CODE), Some(SYSTEM), ORDERS, DataObject::of(d), Some(false), None))
        .await
        .unwrap()["_id"]
        .java_string()
}

async fn read_eager(svc: &AppDataService, id: &str) -> crate::error::CoreResult<Document> {
    context::with_request(caller("", false), svc.read(Some(APP_CODE), Some(SYSTEM), ORDERS, id, Some(true), None)).await
}

#[tokio::test]
async fn read_auth_is_enforced() {
    let (svc, _) = given_storages(Some("Authorities.SECRET")).await;
    let asha = write(&svc, CUSTOMERS, "name", Value::from("Asha")).await;
    let order = write_order(&svc, "A1", Some(&asha), None).await;
    let e = read_eager(&svc, &order).await.unwrap_err();
    assert!(e.status().is_client_error());
}

#[tokio::test]
async fn open_target_still_works() {
    let (svc, _) = given_storages(None).await;
    let asha = write(&svc, CUSTOMERS, "name", Value::from("Asha")).await;
    let order = write_order(&svc, "A1", Some(&asha), None).await;
    let read = read_eager(&svc, &order).await.unwrap();
    assert_eq!(read["customer"].as_object().unwrap()["name"], Value::from("Asha"));
}

#[tokio::test]
async fn no_silent_cap() {
    let (svc, _) = given_storages(None).await;
    let mut ids = Vec::new();
    for i in 0..60 {
        ids.push(write(&svc, TAGS, "label", Value::from(format!("t{i}"))).await);
    }
    let order = write_order(&svc, "A1", None, Some(ids)).await;
    assert_eq!(read_eager(&svc, &order).await.unwrap()["labels"].as_array().unwrap().len(), 60);
}

#[tokio::test]
async fn order_preserved() {
    let (svc, _) = given_storages(None).await;
    let mut ids = Vec::new();
    for i in 0..5 {
        ids.push(write(&svc, TAGS, "label", Value::from(format!("t{i}"))).await);
    }
    ids.reverse();
    let order = write_order(&svc, "A1", None, Some(ids)).await;
    let labels: Vec<String> = read_eager(&svc, &order).await.unwrap()["labels"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l.as_object().unwrap()["label"].java_string())
        .collect();
    assert_eq!(labels, ["t4", "t3", "t2", "t1", "t0"]);
}

async fn read_page_eager(svc: &AppDataService, size: i32) -> Vec<Document> {
    let q = Query { page: 0, size, eager: Some(true), ..Query::default() };
    context::with_request(caller("", false), svc.read_page(Some(APP_CODE), Some(SYSTEM), ORDERS, &q)).await.unwrap().content
}

#[tokio::test]
async fn not_once_per_row() {
    let (svc, engine) = given_storages(None).await;
    let asha = write(&svc, CUSTOMERS, "name", Value::from("Asha")).await;
    let bo = write(&svc, CUSTOMERS, "name", Value::from("Bo")).await;
    for i in 0..10 {
        write_order(&svc, &format!("A{i}"), Some(if i % 2 == 0 { &asha } else { &bo }), None).await;
    }
    engine.calls.lock().clear();
    let page = read_page_eager(&svc, 20).await;
    assert_eq!(page.len(), 10);
    let reads = engine.calls.lock().iter().filter(|c| *c == &format!("rows {CUSTOMERS}")).count();
    assert_eq!(reads, 1, "customers should be read once for the whole page");
}

#[tokio::test]
async fn every_row_is_still_filled() {
    let (svc, _) = given_storages(None).await;
    let asha = write(&svc, CUSTOMERS, "name", Value::from("Asha")).await;
    let bo = write(&svc, CUSTOMERS, "name", Value::from("Bo")).await;
    for i in 0..10 {
        write_order(&svc, &format!("A{i}"), Some(if i % 2 == 0 { &asha } else { &bo }), None).await;
    }
    let names: Vec<String> = read_page_eager(&svc, 20)
        .await
        .iter()
        .map(|r| r["customer"].as_object().unwrap()["name"].java_string())
        .collect();
    assert_eq!(names.iter().filter(|n| *n == "Asha").count(), 5);
    assert_eq!(names.iter().filter(|n| *n == "Bo").count(), 5);
}
