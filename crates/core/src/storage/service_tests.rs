//! The policy layer against in-memory definitions and engines (`testing::doubles`), with
//! security's two answers served by a stub.
//!
//! Java ports: `AppDataServiceClientCodeTest`, `AppDataServiceEventTenantTest`,
//! `AppDataServiceUpdateNullTest` (one test per Java test, same names in snake case); the
//! rest cover the policy branches the Java integration tests reach through the stack.

use std::sync::Arc;

use appdata::model::{AggregateQuery, Connection, ConnectionSubType, DataObject, DraftCopyFilter, Follow, Query, Storage};
use appdata::value::{Document, Value};
use axum::http::StatusCode;
use indexmap::IndexMap;
use serde_json::json;

use super::*;
use crate::context::{self, RunScope};
use crate::testing::{
    auth, policy, request, security_stub, MemoryCatalog, MemoryEngine, RecordingEvents, RecordingTriggers,
};

fn st(v: serde_json::Value) -> Storage {
    Storage::from_value(&Value::from_json(&v)).unwrap()
}

fn doc(v: serde_json::Value) -> Document {
    match Value::from_json(&v) {
        Value::Object(o) => o,
        _ => panic!("object"),
    }
}

/// A signed-in (or not) caller of `client` with `authorities`.
fn caller(client: &str, authenticated: bool, authorities: &[&str], verified: &str) -> Arc<context::RequestContext> {
    request(
        auth(
            json!({"user": {"id": 110, "clientId": 28, "stringAuthorities": authorities},
                   "authenticated": authenticated, "clientCode": client, "clientLevelType": "CLIENT",
                   "verifiedAppCode": verified}),
            Some("FIN"),
            Some("leadzumptwo"),
        ),
        false,
        None,
    )
}

struct Fixture {
    svc: AppDataService,
    catalog: Arc<MemoryCatalog>,
    engine: Arc<MemoryEngine>,
    events: Arc<RecordingEvents>,
    triggers: Arc<RecordingTriggers>,
}

const MANAGES: &[(&str, &str)] = &[("FIN", "BP1"), ("FIN", "FINSUB")];

async fn fixture(storages: Vec<Storage>) -> Fixture {
    let base = security_stub(MANAGES, &["leadzumptwo", "appa"]).await;
    let catalog = MemoryCatalog::with(storages);
    let engine = Arc::new(MemoryEngine::default());
    let events = Arc::new(RecordingEvents::default());
    let svc = policy(catalog.clone(), engine.clone(), &base, events.clone());
    let triggers = Arc::new(RecordingTriggers::default());
    svc.set_trigger_runner(triggers.clone());
    Fixture { svc, catalog, engine, events, triggers }
}

async fn as_caller<F: std::future::Future>(ctx: Arc<context::RequestContext>, f: F) -> F::Output {
    context::with_request(ctx, f).await
}

/// The code an error answers with.
fn code(e: &CoreError) -> String {
    e.code().map(|c| c.code.to_string()).unwrap_or_default()
}

/// An anonymous caller is only asked to sign in: the storage refused is not named.
#[tokio::test]
async fn anonymous_refusals_name_nothing() {
    let locked = st(json!({"name": "locked", "appCode": "leadzumptwo", "clientCode": "SYSTEM", "readAuth": "Authorities.Nope"}));
    let f = fixture(vec![locked]).await;
    as_caller(caller("SYSTEM", false, &[], ""), async {
        let e = f.svc.read(None, None, "locked", "1", None, None).await.unwrap_err();
        assert_eq!((e.status(), e.text()), (StatusCode::FORBIDDEN, "Unable to read data from storage locked".to_string()));
        let c = e.code().unwrap();
        assert!(c.params.is_empty(), "{:?}", c.params);
        let r = c.english();
        assert_eq!(r.message, "You can't view this data without signing in.");
        assert_eq!(r.action.as_deref(), Some("Sign in and try again."));
    })
    .await;
}

fn fin() -> Arc<context::RequestContext> {
    caller("FIN", true, &["Authorities.Logged_IN"], "leadzumptwo")
}

// ---------------------------------------------------------------- AppDataServiceClientCodeTest

async fn client_code_of(cc: Option<&str>, ctx: Arc<context::RequestContext>) -> CoreResult<String> {
    let f = fixture(vec![]).await;
    as_caller(ctx, async { f.svc.client_code(cc).await }).await
}

#[tokio::test]
async fn a_partner_user_may_name_its_managing_client() {
    assert_eq!(client_code_of(Some("FIN"), caller("BP1", true, &[], "")).await.unwrap(), "FIN");
}

#[tokio::test]
async fn a_managing_client_may_name_a_client_it_manages() {
    assert_eq!(client_code_of(Some("BP1"), caller("FIN", true, &[], "")).await.unwrap(), "BP1");
}

#[tokio::test]
async fn no_client_code_is_the_callers_own() {
    assert_eq!(client_code_of(Some(""), caller("BP1", true, &[], "")).await.unwrap(), "BP1");
    assert_eq!(client_code_of(None, caller("BP1", true, &[], "")).await.unwrap(), "BP1");
}

#[tokio::test]
async fn a_sibling_partner_is_refused() {
    let e = client_code_of(Some("FINSUB"), caller("BP1", true, &[], "")).await.unwrap_err();
    assert_eq!(e.status(), StatusCode::FORBIDDEN);
    assert_eq!(e.text(), "FINSUB is not a client you can act for.");
}

#[tokio::test]
async fn an_unknown_client_is_refused_not_empty() {
    let e = client_code_of(Some("GHOST"), caller("BP1", true, &[], "")).await.unwrap_err();
    assert_eq!(e.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn an_anonymous_caller_keeps_what_it_sent() {
    assert_eq!(client_code_of(Some("FIN"), caller("SYSTEM", false, &[], "")).await.unwrap(), "FIN");
    // The url client code (FIN in these callers' requests).
    assert_eq!(client_code_of(Some(""), caller("SYSTEM", false, &[], "")).await.unwrap(), "FIN");
}

// ---------------------------------------------------------------- AppDataServiceEventTenantTest

fn event_storage() -> Storage {
    st(json!({"name": "whatsappOutbox", "appCode": "leadzumptwo", "clientCode": "SYSTEM", "generateEvents": true}))
}

async fn event_fixture() -> Fixture {
    let f = fixture(vec![event_storage()]).await;
    f.catalog.events.lock().insert("Storage.whatsappOutbox.Delete".into(), overridable::JMap::new());
    f.engine.insert("whatsappOutbox", "42", doc(json!({"name": "row 42"})));
    f
}

#[tokio::test]
async fn a_delete_with_blank_app_and_client_raises_its_event_for_the_resolved_tenant() {
    let f = event_fixture().await;
    let deleted = as_caller(fin(), f.svc.delete(Some(""), Some(""), "whatsappOutbox", "42", Some(false))).await.unwrap();
    assert!(deleted);
    assert_eq!(*f.catalog.lookups.lock(), ["leadzumptwo/FIN/Storage.whatsappOutbox.Delete"]);
    let raised = f.events.raised.lock();
    assert_eq!(raised[0].0, "leadzumptwo/FIN/Storage.whatsappOutbox.Delete");
    assert_eq!(raised[0].1["dataObject"].as_object().unwrap()["name"], Value::from("row 42"));
}

#[tokio::test]
async fn a_delete_with_null_app_and_client_raises_its_event_for_the_resolved_tenant() {
    let f = event_fixture().await;
    assert!(as_caller(fin(), f.svc.delete(None, None, "whatsappOutbox", "42", Some(false))).await.unwrap());
    assert_eq!(f.events.raised.lock()[0].0, "leadzumptwo/FIN/Storage.whatsappOutbox.Delete");
}

#[tokio::test]
async fn an_explicit_app_and_client_are_kept() {
    let f = event_fixture().await;
    assert!(as_caller(fin(), f.svc.delete(Some("leadzumptwo"), Some("FIN"), "whatsappOutbox", "42", Some(false)))
        .await
        .unwrap());
    assert_eq!(f.events.raised.lock()[0].0, "leadzumptwo/FIN/Storage.whatsappOutbox.Delete");
}

// ---------------------------------------------------------------- AppDataServiceUpdateNullTest

fn project_with_relation() -> Storage {
    st(json!({"name": "project", "appCode": "leadzumptwo", "clientCode": "SYSTEM",
              "relations": {"ownerId": {"storageName": "owner", "relationType": "TO_ONE"}}}))
}

async fn update_null(data: serde_json::Value, override_: bool) -> Fixture {
    let owner = st(json!({"name": "owner", "appCode": "leadzumptwo", "clientCode": "SYSTEM"}));
    let f = fixture(vec![project_with_relation(), owner]).await;
    f.engine.insert("project", "426", doc(json!({"description": "old", "ownerId": "9003"})));
    f.engine.insert("owner", "9003", doc(json!({"name": "o"})));
    as_caller(fin(), f.svc.update(Some("leadzumptwo"), Some("FIN"), "project", DataObject::of(doc(data)), override_, Some(false), Some(vec![])))
        .await
        .unwrap();
    f
}

#[tokio::test]
async fn a_patch_with_a_plain_field_set_to_null_hands_the_null_on() {
    let f = update_null(json!({"_id": "426", "description": null}), false).await;
    let updates = f.engine.updates.lock();
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0].0.get("description"), Some(&Value::Null));
    assert_eq!(updates[0].1, Some(false));
}

#[tokio::test]
async fn a_put_with_a_relation_set_to_null_hands_the_null_on() {
    let f = update_null(json!({"_id": "426", "name": "Project", "ownerId": null}), true).await;
    let updates = f.engine.updates.lock();
    assert_eq!(updates[0].0.get("ownerId"), Some(&Value::Null));
    assert_eq!(updates[0].0["name"], Value::from("Project"));
    assert_eq!(updates[0].1, Some(true));
}

#[tokio::test]
async fn a_non_null_relation_is_still_checked_and_kept() {
    let f = update_null(json!({"_id": "426", "ownerId": "9003", "description": null}), false).await;
    let updates = f.engine.updates.lock();
    assert_eq!(updates[0].0["ownerId"], Value::from("9003"));
    assert!(updates[0].0.contains_key("description"));
}

#[test]
fn the_copy_keeps_nulls() {
    // `copyKeepingNulls` is the row as given: the Rust update works on its own copy of it.
    let data = doc(json!({"a": null, "b": 1}));
    let copy = data.clone();
    assert_eq!(copy, data);
    assert!(copy.contains_key("a"));
}

// ---------------------------------------------------------------- EagerTreeTest

#[test]
fn flat_field_is_unchanged() {
    let t = EagerTree::of(Some(&["category".to_string()]));
    assert_eq!(t.0.len(), 1);
    assert!(t.0["category"].is_empty());
}

#[test]
fn dotted_path_nests() {
    let t = EagerTree::of(Some(&["category.parent".to_string()]));
    assert_eq!(t.0.keys().collect::<Vec<_>>(), ["category"]);
    assert_eq!(t.0["category"].0.keys().collect::<Vec<_>>(), ["parent"]);
}

#[test]
fn siblings_merge() {
    let t = EagerTree::of(Some(&["category.parent".to_string(), "category.owner".into(), "author".into()]));
    assert_eq!(t.0.len(), 2);
    assert_eq!(t.0["category"].0.len(), 2);
    assert!(t.0["author"].is_empty());
}

#[test]
fn deep_path() {
    let t = EagerTree::of(Some(&["a.b.c".to_string()]));
    assert!(t.0["a"].0["b"].0.contains_key("c"));
}

#[test]
fn tolerates_rubbish() {
    assert!(EagerTree::of(None).is_empty());
    assert!(EagerTree::of(Some(&["".to_string()])).is_empty());
    assert!(EagerTree::of(Some(&["   ".to_string()])).is_empty());
    let trailing = EagerTree::of(Some(&["category.".to_string()]));
    assert_eq!(trailing.0.keys().collect::<Vec<_>>(), ["category"]);
    assert!(trailing.0["category"].is_empty());
}

#[test]
fn trims_segments() {
    let t = EagerTree::of(Some(&[" category . parent ".to_string()]));
    assert!(t.0["category"].0.contains_key("parent"));
}

// ---------------------------------------------------------------- the policy branches

fn plain(name: &str) -> Storage {
    st(json!({"name": name, "appCode": "leadzumptwo", "clientCode": "SYSTEM"}))
}

#[tokio::test]
async fn gates_answer_as_generic_operation_does() {
    let locked = st(json!({"name": "locked", "appCode": "leadzumptwo", "clientCode": "SYSTEM",
                           "readAuth": "Authorities.Nope", "createAuth": "Authorities.Nope", "updateAuth": "Authorities.Nope",
                           "deleteAuth": "Authorities.Nope"}));
    let f = fixture(vec![locked, plain("open")]).await;
    as_caller(fin(), async {
        let e = f.svc.read(None, None, "missing", "1", None, None).await.unwrap_err();
        assert_eq!((e.status(), e.text()), (StatusCode::NOT_FOUND, "Storage not found".to_string()));
        assert_eq!(code(&e), "CORE.STORAGE_NOT_FOUND");
        let e = f.svc.read(None, None, "locked", "1", None, None).await.unwrap_err();
        assert_eq!(e.text(), "Unable to read data from storage locked");
        assert_eq!(code(&e), "CORE.FORBIDDEN_READ_STORAGE");
        assert_eq!(e.code().unwrap().english().message, "You can't view the data in locked: your account does not have the permission this storage needs for reading.");
        let e = f.svc.create(None, None, "locked", DataObject::default(), None, None).await.unwrap_err();
        assert_eq!(e.text(), "Unable to add data to storage locked");
        let e = f.svc.update(None, None, "locked", DataObject::default(), true, None, None).await.unwrap_err();
        assert_eq!(e.text(), "Unable to update data in storage locked");
        let e = f.svc.delete(None, None, "locked", "1", None).await.unwrap_err();
        assert_eq!(e.text(), "Unable to delete data from storage locked");
        // An engine that completes empty (MySQL's update of a missing row) is the gate's 403.
        *f.engine.empty_update.lock() = true;
        let e = f
            .svc
            .update(None, None, "open", DataObject::of(doc(json!({"_id": "x"}))), true, None, None)
            .await
            .unwrap_err();
        assert_eq!((e.status(), e.text()), (StatusCode::FORBIDDEN, "Unable to update data in storage open".to_string()));
        assert_eq!(code(&e), "CORE.STORAGE_ROW_GONE");
        // Mongo's update of a missing row is its own 404, which the KIRun functions catch.
        *f.engine.empty_update.lock() = false;
        let e = f
            .svc
            .update(None, None, "open", DataObject::of(doc(json!({"_id": "x"}))), true, None, None)
            .await
            .unwrap_err();
        assert!(e.is_object_not_found());
        // A bad authority expression is KIRun's error, a 500.
        f.catalog.storages.lock().push(st(json!({"name": "bad", "appCode": "a", "clientCode": "SYSTEM", "readAuth": "Authorities.A +"})));
        assert_eq!(f.svc.read(None, None, "bad", "1", None, None).await.unwrap_err().status(), StatusCode::INTERNAL_SERVER_ERROR);
    })
    .await;
}

#[tokio::test]
async fn only_thru_kirun_storages() {
    let k = st(json!({"name": "k", "appCode": "leadzumptwo", "clientCode": "SYSTEM", "onlyThruKIRun": true}));
    let parent = st(json!({"name": "p", "appCode": "leadzumptwo", "clientCode": "SYSTEM",
                           "relations": {"k": {"storageName": "k", "relationType": "TO_ONE"}}}));
    let f = fixture(vec![k, parent]).await;
    f.engine.insert("k", "1", doc(json!({"v": "x"})));
    f.engine.insert("p", "2", doc(json!({"k": "1"})));
    // A runtime session is refused outright.
    as_caller(fin(), async {
        let e = f.svc.read(None, None, "k", "1", None, None).await.unwrap_err();
        assert_eq!(e.status(), StatusCode::FORBIDDEN);
        assert!(e.text().starts_with("Storage k is marked onlyThruKIRun"));
        // As a relation it is skipped and the id stays as it is.
        let row = f.svc.read(None, None, "p", "2", Some(true), None).await.unwrap();
        assert_eq!(row["k"], Value::from("1"));
    })
    .await;
    // Inside a KIRun run, and for a builder session, it is reachable.
    as_caller(fin(), context::with_run(RunScope { owner_app_code: None }, async {
        assert!(f.svc.read(None, None, "k", "1", None, None).await.is_ok());
    }))
    .await;
    as_caller(caller("FIN", true, &[], "appbuilder"), async {
        let row = f.svc.read(None, None, "p", "2", Some(true), None).await.unwrap();
        assert_eq!(row["k"].as_object().unwrap()["v"], Value::from("x"));
    })
    .await;
}

fn relations_storages() -> Vec<Storage> {
    vec![
        plain("parent"),
        st(json!({"name": "child", "appCode": "leadzumptwo", "clientCode": "SYSTEM", "relations": {
            "one": {"storageName": "parent", "relationType": "TO_ONE", "deleteConstraint": "RESTRICT"},
            "many": {"storageName": "parent", "relationType": "TO_MANY"}}})),
    ]
}

#[tokio::test]
async fn relations_on_create() {
    let f = fixture(relations_storages()).await;
    f.engine.insert("parent", "p1", doc(json!({"n": 1})));
    as_caller(fin(), async {
        // Ids that exist are kept, objects without ids are created, a comma list is split.
        let row = f
            .svc
            .create(None, None, "child", DataObject::of(doc(json!({"one": {"n": 2}, "many": "p1, p1", "skip": null}))), None, None)
            .await
            .unwrap();
        assert_eq!(f.engine.count("parent"), 2);
        assert_eq!(row["many"], Value::Array(vec![Value::from("p1"), Value::from("p1")]));
        assert!(!row.contains_key("skip"));
        // eager: every relation expanded, each row in its own order.
        let read = f.svc.read(None, None, "child", &row["_id"].java_string(), Some(true), None).await.unwrap();
        assert_eq!(read["many"].as_array().unwrap().len(), 2);
        assert_eq!(read["one"].as_object().unwrap()["n"], Value::Int(2));
        // A missing id fails the write with INVALID_RELATION_DATA, and what was created for it is
        // deleted again.
        let e = f
            .svc
            .create(None, None, "child", DataObject::of(doc(json!({"one": {"n": 3}, "many": ["nope"]}))), None, None)
            .await
            .unwrap_err();
        assert_eq!(e.status(), StatusCode::BAD_REQUEST);
        assert_eq!(e.text(), "Invalid relation data in the field many with data {_id=nope}");
        assert_eq!(f.engine.count("parent"), 2);
        let CoreError::Message { cause, .. } = &e else { panic!("message") };
        assert_eq!(cause.as_deref(), Some("parent with id nope not found"));
        // Only a failure, nothing created: the same answer.
        let e = f.svc.create(None, None, "child", DataObject::of(doc(json!({"one": "nope"}))), None, None).await.unwrap_err();
        assert_eq!(e.text(), "Invalid relation data in the field one with data {_id=nope}");
        // A relation value that names no objects is left as it is.
        let row = f.svc.create(None, None, "child", DataObject::of(doc(json!({"many": 5}))), None, None).await.unwrap();
        assert_eq!(row["many"], Value::Int(5));
    })
    .await;
}

#[tokio::test]
async fn relations_on_update_and_delete() {
    let mut storages = relations_storages();
    storages.push(st(json!({"name": "owned", "appCode": "leadzumptwo", "clientCode": "SYSTEM", "relations": {
        "items": {"storageName": "parent", "relationType": "TO_MANY", "updateConstraint": "CASCADE"},
        "owner": {"storageName": "box", "relationType": "TO_ONE", "deleteConstraint": "CASCADE"}}})));
    storages.push(plain("box"));
    let f = fixture(storages).await;
    for id in ["p1", "p2", "p3"] {
        f.engine.insert("parent", id, doc(json!({})));
    }
    f.engine.insert("owned", "o1", doc(json!({"items": ["p1", "p2"]})));
    as_caller(fin(), async {
        // An override that drops a CASCADE relation's id deletes the detached row.
        f.svc
            .update(None, None, "owned", DataObject::of(doc(json!({"_id": "o1", "items": ["p1", "p3"]}))), true, None, None)
            .await
            .unwrap();
        assert!(!f.engine.rows.lock()["parent"].contains_key("p2"));
        // A partial update leaves a CASCADE relation alone.
        f.svc
            .update(None, None, "owned", DataObject::of(doc(json!({"_id": "o1", "items": ["p1"]}))), false, None, None)
            .await
            .unwrap();
        assert!(f.engine.rows.lock()["parent"].contains_key("p3"));
        // An update without an id cannot read the row it changes.
        let e = f.svc.update(None, None, "owned", DataObject::of(doc(json!({"items": []}))), true, None, None).await.unwrap_err();
        assert_eq!(e.status(), StatusCode::INTERNAL_SERVER_ERROR);

        // RESTRICT counts every referencing storage before anything goes.
        f.engine.insert("child", "c1", doc(json!({"one": "p1"})));
        let e = f.svc.delete(None, None, "parent", "p1", None).await.unwrap_err();
        assert_eq!(e.text(), "Following objects exists and cannot be deleted: [child.one (1)]");
        // A constraint the database enforces is left to it.
        *f.engine.enforces.lock() = true;
        assert!(f.svc.delete(None, None, "parent", "p1", None).await.unwrap());
        *f.engine.enforces.lock() = false;

        // CASCADE deletes the referencing rows through the ordinary delete.
        f.engine.insert("box", "b1", doc(json!({})));
        f.engine.insert("owned", "o2", doc(json!({"owner": "b1"})));
        f.engine.insert("owned", "o3", doc(json!({"owner": "b1"})));
        assert!(f.svc.delete(None, None, "box", "b1", None).await.unwrap());
        assert_eq!(f.engine.count("owned"), 1);
    })
    .await;
}

#[tokio::test]
async fn cascades_need_the_childs_delete_authority_and_stop_at_a_depth() {
    let f = fixture(vec![
        plain("a"),
        st(json!({"name": "b", "appCode": "x", "clientCode": "SYSTEM", "deleteAuth": "Authorities.Nope",
                  "relations": {"a": {"storageName": "a", "relationType": "TO_ONE", "deleteConstraint": "CASCADE"}}})),
        st(json!({"name": "loop", "appCode": "x", "clientCode": "SYSTEM",
                  "relations": {"me": {"storageName": "loop", "relationType": "TO_ONE", "deleteConstraint": "CASCADE"}}})),
    ])
    .await;
    f.engine.insert("a", "a1", doc(json!({})));
    f.engine.insert("b", "b1", doc(json!({"a": "a1"})));
    for i in 0..10 {
        f.engine.insert("loop", &format!("l{i}"), doc(json!({"me": format!("l{}", i + 1)})));
    }
    as_caller(fin(), async {
        let e = f.svc.delete(None, None, "a", "a1", None).await.unwrap_err();
        assert_eq!((e.status(), e.text()), (StatusCode::FORBIDDEN, "Unable to delete data from storage b".to_string()));
        assert_eq!(code(&e), "CORE.CASCADE_DELETE_FORBIDDEN");
        let e = f.svc.delete(None, None, "loop", "l9", None).await.unwrap_err();
        assert!(e.text().contains("cascade deeper than 8"), "{}", e.text());
        assert_eq!(code(&e), "CORE.CASCADE_TOO_DEEP");
    })
    .await;
}

#[tokio::test]
async fn triggers_events_and_their_failures() {
    let trig = st(json!({"name": "t", "appCode": "leadzumptwo", "clientCode": "SYSTEM", "generateEvents": true,
                         "triggers": {"BEFORE_CREATE": ["NS.before"], "AFTER_CREATE": ["NS.after"],
                                      "BEFORE_UPDATE": ["NS.bu"], "AFTER_UPDATE": ["NS.au"],
                                      "BEFORE_DELETE": ["NS.bd"], "AFTER_DELETE": ["NS.ad"]}}));
    let nodot = st(json!({"name": "nodot", "appCode": "a", "clientCode": "SYSTEM", "triggers": {"BEFORE_CREATE": ["plain"]}}));
    let ev = st(json!({"name": "ev", "appCode": "leadzumptwo", "clientCode": "SYSTEM", "generateEvents": true}));
    let f = fixture(vec![trig, nodot, ev]).await;
    let mut def = overridable::JMap::new();
    def.insert("includeContextAuthentication".into(), overridable::JValue::Bool(true));
    f.catalog.events.lock().insert("Storage.ev.Create".into(), def.clone());
    f.catalog.events.lock().insert("Storage.ev.Update".into(), def);
    as_caller(fin(), async {
        let row = f.svc.create(None, None, "t", DataObject::of(doc(json!({"v": 1, "n": null}))), None, None).await.unwrap();
        let id = row["_id"].java_string();
        f.svc.update(None, None, "t", DataObject::of(doc(json!({"_id": id, "v": 2}))), false, None, None).await.unwrap();
        f.svc.delete(None, None, "t", &id, None).await.unwrap();
        let ran: Vec<String> = f.triggers.ran.lock().iter().map(|r| r.0.clone()).collect();
        assert_eq!(
            ran,
            ["NS.before leadzumptwo/SYSTEM", "NS.after leadzumptwo/SYSTEM", "NS.bu leadzumptwo/SYSTEM", "NS.au leadzumptwo/SYSTEM",
             "NS.bd leadzumptwo/SYSTEM", "NS.ad leadzumptwo/SYSTEM"]
        );
        // The row as Gson writes it: no nulls.
        assert_eq!(f.triggers.ran.lock()[0].1, json!({"dataObject": {"v": 1}}));
        assert!(f.triggers.ran.lock()[2].1.get("existingDataObject").is_some());

        // createMany on a generateEvents storage answers the event's data map, as Java's does.
        let many = f
            .svc
            .create_many(None, None, "ev", vec![DataObject::of(doc(json!({"v": 1})))], None, None)
            .await
            .unwrap();
        assert!(many[0].contains_key("dataArr"));
        let raised = f.events.raised.lock().clone();
        assert!(raised[0].1.contains_key("authentication"));
        let row = f.svc.create(None, None, "ev", DataObject::of(doc(json!({"v": 3}))), None, None).await.unwrap();
        f.svc
            .update(None, None, "ev", DataObject::of(doc(json!({"_id": row["_id"].java_string(), "v": 4}))), false, None, None)
            .await
            .unwrap();
        assert!(f.events.raised.lock().iter().any(|e| e.0.ends_with("Storage.ev.Update") && e.1.contains_key("existingDataObject")));

        let e = f.svc.create(None, None, "nodot", DataObject::of(doc(json!({}))), None, None).await.unwrap_err();
        assert_eq!(e.text(), "begin 0, end -1, length 5");
        *f.triggers.fail.lock() = Some(CoreError::new(StatusCode::FORBIDDEN, "no"));
        let e = f.svc.create(None, None, "t", DataObject::of(doc(json!({}))), None, None).await.unwrap_err();
        assert_eq!(e.status(), StatusCode::FORBIDDEN);
    })
    .await;
}

#[tokio::test]
async fn triggers_need_a_runner() {
    let base = security_stub(MANAGES, &[]).await;
    let catalog = MemoryCatalog::with(vec![st(json!({"name": "t", "appCode": "a", "clientCode": "SYSTEM",
                                                      "triggers": {"BEFORE_CREATE": ["N.f"]}}))]);
    let svc = policy(catalog, Arc::new(MemoryEngine::default()), &base, Arc::new(RecordingEvents::default()));
    let e = as_caller(fin(), svc.create(None, None, "t", DataObject::default(), None, None)).await.unwrap_err();
    assert!(e.text().contains("no execution state"));
}

#[tokio::test]
async fn reads_pages_aggregates_and_versions() {
    let mut storages = relations_storages();
    storages.push(st(json!({"name": "secret", "appCode": "x", "clientCode": "SYSTEM", "readAuth": "Authorities.Nope"})));
    storages.push(st(json!({"name": "pointsAtSecret", "appCode": "x", "clientCode": "SYSTEM",
                            "relations": {"s": {"storageName": "secret", "relationType": "TO_ONE"},
                                          "gone": {"storageName": "nowhere", "relationType": "TO_ONE"}}})));
    let f = fixture(storages).await;
    f.engine.insert("parent", "p1", doc(json!({"n": 1})));
    f.engine.insert("child", "c1", doc(json!({"one": "p1", "many": ["p1", "zz", null]})));
    f.engine.insert("child", "c2", doc(json!({"one": "missing"})));
    f.engine.insert("secret", "s1", doc(json!({})));
    f.engine.insert("pointsAtSecret", "x1", doc(json!({"s": "s1", "gone": "g"})));
    as_caller(fin(), async {
        let q = Query { eager: Some(true), ..Query::default() };
        let page = f.svc.read_page(None, None, "child", &q).await.unwrap();
        assert_eq!(page.content.len(), 2);
        assert_eq!(page.content[0]["many"].as_array().unwrap().len(), 1);
        assert!(!page.content[1].contains_key("one"));
        let page = f.svc.read_page(None, None, "parent", &Query::default()).await.unwrap();
        assert_eq!(page.total, 1);
        // Expanding into a storage the caller may not read is that storage's refusal.
        let e = f.svc.read(None, None, "pointsAtSecret", "x1", None, Some(vec!["s".into()])).await.unwrap_err();
        assert_eq!(e.text(), "Unable to read data from storage secret");
        // A relation to a storage that does not resolve is skipped.
        let row = f.svc.read(None, None, "pointsAtSecret", "x1", None, Some(vec!["gone".into()])).await.unwrap();
        assert_eq!(row["gone"], Value::from("g"));
        let agg = f.svc.aggregate(None, None, "child", &AggregateQuery::default()).await.unwrap();
        assert_eq!(agg.content[0]["n"], Value::Int(2));
        assert!(f.svc.read_version(None, None, "child", "v1").await.unwrap_err().text().contains("not found"));
        assert_eq!(f.svc.read_page_version(None, None, "child", "c1", &Query::default(), Some(true)).await.unwrap().total, 0);
        let (s, rows) = f.svc.read_rows_for_download(None, None, "child", &Query::default()).await.unwrap();
        assert_eq!((s.name.as_str(), rows.len()), ("child", 2));
        assert_eq!(f.svc.delete_by_filter(None, None, "child", &Query::default(), Some(true), None).await.unwrap(), 2);
        assert!(f.svc.delete_storage(None, None, "child").await.unwrap());
        assert_eq!(f.engine.count("child"), 0);
    })
    .await;
}

#[tokio::test]
async fn builder_operations() {
    let locked = st(json!({"name": "locked", "appCode": "leadzumptwo", "clientCode": "SYSTEM", "deleteAuth": "Authorities.Nope"}));
    let f = fixture(vec![locked.clone(), plain("empty")]).await;
    f.engine.insert("locked", "r1", doc(json!({})));
    as_caller(fin(), async {
        // Write access to the app stands in for the storage's deleteAuth.
        assert_eq!(f.svc.clear_all_rows(None, None, "locked", Some(true)).await.unwrap(), 1);
        assert_eq!(f.svc.clear_all_rows(Some("other"), None, "locked", Some(true)).await.unwrap_err().status(), StatusCode::FORBIDDEN);
        assert_eq!(f.svc.clear_all_rows(None, None, "nope", None).await.unwrap_err().status(), StatusCode::NOT_FOUND);
        assert_eq!(f.svc.copy_live_data_to_draft(None, None, "locked", Some(true)).await.unwrap(), 1);
        let e = f.svc.copy_live_data_to_draft(None, None, "empty", None).await.unwrap_err();
        assert_eq!(e.text(), "Storage empty has no live rows to copy into the draft surface.");
        assert_eq!(f.svc.copy_live_data_to_draft(None, None, "nope", None).await.unwrap_err().status(), StatusCode::INTERNAL_SERVER_ERROR);
        let e = f.svc.copy_live_data_to_draft(Some("other"), None, "locked", None).await.unwrap_err();
        assert!(e.text().starts_with("Naming the data surface needs write access to the application other."));
        let cleared = f.svc.clear_draft_data(None, None).await.unwrap();
        assert_eq!(cleared.get("locked"), Some(&1));
        let copied = f.svc.copy_app_to_draft(None, None, IndexMap::new()).await.unwrap();
        assert_eq!(copied.keys().collect::<Vec<_>>(), ["empty", "locked"]);
        assert!(f.svc.clear_draft_data(Some("other"), None).await.is_err());

        // No appData connection (Mongo): nothing at all; a Mongo connection: an empty list; a
        // MySQL connection asks the MySQL engine.
        assert!(f.svc.migration_status(None, None, "empty").await.unwrap().is_none());
        *f.catalog.connection.lock() =
            Some(Connection { id: "c".into(), connection_sub_type: Some(ConnectionSubType::Mongo), ..Default::default() });
        assert!(f.svc.migration_status(None, None, "empty").await.unwrap().unwrap().is_empty());
        *f.catalog.connection.lock() =
            Some(Connection { id: "c".into(), connection_sub_type: Some(ConnectionSubType::MySql), ..Default::default() });
        // only the caller's own client (FIN) and the ones it manages (BP1): SYSTEM and STRANGER
        // are left out
        let seen = f.svc.migration_status(None, None, "empty").await.unwrap().unwrap();
        assert_eq!(seen.iter().map(|t| t.client_code.as_str()).collect::<Vec<_>>(), ["FIN", "BP1"]);
        assert_eq!(seen[0].attempt, 3);
        assert!(f.svc.migration_status(None, None, "nope").await.unwrap().is_none());
        assert!(f.svc.drift(None, None, "empty").await.unwrap().is_empty());
        assert!(f.svc.drift(None, None, "nope").await.unwrap().is_empty());
        assert!(f.svc.repair_drift(None, None, "empty", true).await.unwrap().is_empty());
        assert!(f.svc.repair_drift(None, None, "nope", false).await.unwrap().is_empty());
        let e = f.svc.drift(Some("other"), None, "empty").await.unwrap_err();
        assert_eq!((e.text().as_str(), code(&e).as_str()), ("Unable to update data in storage other", "CORE.STORAGE_BUILDER_ONLY"));
        assert!(f.svc.repair_drift(Some("other"), None, "empty", false).await.is_err());
        // A connection whose subtype is no app-data backend selects nothing.
        *f.catalog.connection.lock() =
            Some(Connection { id: "c".into(), connection_sub_type: Some(ConnectionSubType::Other("SMTP".into())), ..Default::default() });
        assert_eq!(f.svc.read(None, None, "empty", "1", None, None).await.unwrap_err().status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(f.svc.template_storage("leadzumptwo", "SYSTEM", "empty").await.is_err());
        *f.catalog.connection.lock() = None;
        assert_eq!(f.svc.template_storage("leadzumptwo", "SYSTEM", "empty").await.unwrap().name, "empty");
        assert_eq!(f.svc.template_storage("leadzumptwo", "SYSTEM", "nope").await.unwrap_err().status(), StatusCode::NOT_FOUND);
    })
    .await;
}

#[tokio::test]
async fn surfaces_and_app_codes() {
    let f = fixture(vec![plain("s")]).await;
    as_caller(fin(), async {
        // No surface named: the operation as it is.
        assert_eq!(f.svc.on_surface(Some("x"), None, async { Ok(context::is_draft()) }).await.unwrap(), false);
        // Named with write access: the operation runs on that surface.
        assert!(f.svc.on_surface(None, Some(true), async { Ok(context::is_draft()) }).await.unwrap());
        let e = f.svc.on_surface(Some("other"), Some(false), async { Ok(1) }).await.unwrap_err();
        assert_eq!(e.status(), StatusCode::FORBIDDEN);
        // A KIRun function's owner app is the default app.
        let app = context::with_run(RunScope { owner_app_code: Some("owner".into()) }, async { AppDataService::app_code(None) }).await;
        assert_eq!(app, "owner");
        assert_eq!(AppDataService::app_code(Some(" ")), "leadzumptwo");
        assert_eq!(AppDataService::app_code(Some("given")), "given");
    })
    .await;
}

#[tokio::test]
async fn uploads_write_rows_straight_to_the_engine() {
    let f = fixture(vec![plain("s")]).await;
    as_caller(fin(), async {
        let ok = f
            .svc
            .upload_rows(None, None, "s", |_| async { Ok(Some(vec![doc(json!({"a": 1})), doc(json!({"a": 2}))])) }.boxed(), "CSV")
            .await
            .unwrap();
        assert!(ok);
        assert_eq!(f.engine.count("s"), 2);
        let e = f.svc.upload_rows(None, None, "s", |_| async { Ok(None) }.boxed(), "CSV").await.unwrap_err();
        assert_eq!(e.text(), "Not able to read file with given CSV format");
    })
    .await;
}

#[test]
fn draft_copy_orders() {
    let mut storages = IndexMap::new();
    for n in ["a", "b", "c"] {
        storages.insert(n.to_string(), plain(n));
    }
    let follow = |s: &str| DraftCopyFilter {
        condition: None,
        follow: Some(vec![Follow { field: "f".into(), storage: s.into(), ref_field: None }]),
    };
    let mut filters = IndexMap::new();
    filters.insert("a".to_string(), follow("b"));
    let order: Vec<String> = draft_copy_order(&storages, &filters).unwrap().into_iter().map(|s| s.name).collect();
    assert_eq!(order, ["b", "c", "a"]);
    filters.insert("b".to_string(), follow("a"));
    assert_eq!(
        draft_copy_order(&storages, &filters).unwrap_err().text(),
        "these storages follow each other: [a, b] is not a condition this data filter supports."
    );
    let mut bad = IndexMap::new();
    bad.insert("z".to_string(), DraftCopyFilter::default());
    assert!(draft_copy_order(&storages, &bad).unwrap_err().text().starts_with("no storage named z"));
    let mut bad = IndexMap::new();
    bad.insert("a".to_string(), follow("zz"));
    assert!(draft_copy_order(&storages, &bad).unwrap_err().text().contains("a follows zz.f, which is not there"));
    let mut own = IndexMap::new();
    own.insert("a".to_string(), follow("a"));
    assert!(draft_copy_order(&storages, &own).is_err());
}

#[test]
fn helpers() {
    assert_eq!(java_split_commas(""), vec![String::new()]);
    assert_eq!(java_split_commas("a,b,,"), ["a", "b"]);
    assert!(java_split_commas(",,").is_empty());
    let s = plain("x");
    assert_eq!(resolve_eager_fields(&s, Some(true), None), Some(vec![]));
    assert_eq!(resolve_eager_fields(&s, Some(false), Some(&[])), Some(vec![]));
    assert_eq!(resolve_eager_fields(&s, None, None), None);
    assert_eq!(resolve_eager_fields(&s, Some(true), Some(&["a".to_string()])), Some(vec!["a".to_string()]));
    let m = msg::STORAGE_DELETE_ALL_NOT_CONFIRMED;
    assert!(m.template.contains("deleteAll=true"));
    assert_eq!(Gate::Create.message(), msg::FORBIDDEN_CREATE_STORAGE);
    let c = ctx();
    assert!(!c.draft);
}

#[tokio::test]
async fn a_created_rows_object_ids_expand_by_the_ids_it_was_written_with() {
    let f = fixture(relations_storages()).await;
    f.engine.insert("parent", "p1", doc(json!({"n": 1})));
    as_caller(fin(), async {
        // What the Mongo engine answers a create with: the stored ObjectIds as Jackson's beans.
        let bean = json!({"timestamp": 1, "date": "1970-01-01T00:00:01.000+00:00"});
        f.engine.insert("child", "c9", doc(json!({"one": bean, "many": [bean]})));
        let sent = doc(json!({"one": "p1", "many": ["p1"]}));
        let row = f.engine.rows.lock()["child"]["c9"].clone();
        let storage = relations_storages().pop().unwrap();
        let backend = Backend { engine: f.engine.clone(), conn: None };
        let filled = f
            .svc
            .fill_created("app", "SYSTEM", &storage, row.clone(), &sent, &backend, Some(&["one".to_string(), "many".to_string()]))
            .await
            .unwrap();
        assert_eq!(filled["one"].as_object().unwrap()["n"], Value::Int(1));
        assert_eq!(filled["many"].as_array().unwrap().len(), 1);
        // Not asked for: the bean stays.
        let kept = f.svc.fill_created("app", "SYSTEM", &storage, row, &sent, &backend, None).await.unwrap();
        assert_eq!(kept["one"], Value::from_json(&bean));
    })
    .await;
}

#[tokio::test]
async fn writing_no_data_fails_in_the_engine_as_java_does() {
    let f = fixture(vec![plain("s")]).await;
    as_caller(fin(), async {
        let e = f.svc.create(None, None, "s", DataObject::default(), None, None).await.unwrap_err();
        assert_eq!(e.text(), "Not a JSON Object: null");
        let e = f.svc.update(None, None, "s", DataObject::default(), true, None, None).await.unwrap_err();
        assert!(e.text().contains("getData()"));
    })
    .await;
}

