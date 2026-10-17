//! Personalization and the function / schema repositories against a scratch MongoDB.
//!
//! Gated: `#[ignore]` and `MODLIX__MONGO__URI`; see `common`.

mod common;

use axum::http::StatusCode;
use common::*;
use mongodb::bson::{doc, Document};
use overridable::JValue;

const P: &str = "/api/ui/personalization/testapp/grid";

// Personalization

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn personalization_round_trip() {
    let Some(e) = env().await else { return };
    let user = |r: Req| r.user("SYSTEM", "Authorities.Logged_IN");
    // Nothing stored yet.
    assert_eq!(e.call(user(get_req(P))).await.text(), "{ }");
    // Create, in the body's order, dotted keys and all.
    let r = e.call(user(get_req(P).method("POST").body(r#"{"z":1,"a.b":{"y":2.5,"x":[1,null]}}"#))).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.text(), "{\n  \"z\" : 1,\n  \"a.b\" : {\n    \"y\" : 2.5,\n    \"x\" : [ 1, null ]\n  }\n}");
    let stored = e.db.collection::<Document>("personalization").find_one(doc! {}).await.unwrap().unwrap();
    assert_eq!(stored.get_str("name").unwrap(), "grid142");
    assert_eq!(stored.get_str("createdBy").unwrap(), "142");
    assert!(stored.get_document("personalization").unwrap().contains_key("a__d-o-t__b"));
    assert_eq!(e.call(user(get_req(P))).await.obj()["z"], JValue::Int(1));
    // Update.
    let r = e.call(user(get_req(P).method("POST").body(r#"{"z":2}"#))).await;
    assert_eq!(r.obj()["z"], JValue::Int(2));
    let stored = e.db.collection::<Document>("personalization").find_one(doc! {}).await.unwrap().unwrap();
    assert_eq!(stored.get_i32("version").unwrap(), 2);
    assert_eq!(stored.get_str("updatedBy").unwrap(), "142");
    // Delete, then nothing again.
    let r = e.call(user(get_req(P).method("DELETE"))).await;
    assert_eq!(r.text(), "true");
    assert_eq!(e.call(user(get_req(P))).await.text(), "{ }");
    // Deleting what is not there: Java's NullPointerException.
    assert_eq!(e.call(user(get_req(P).method("DELETE"))).await.status, StatusCode::INTERNAL_SERVER_ERROR);
    e.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn personalization_for_the_anonymous_user() {
    let Some(e) = env().await else { return };
    assert_eq!(e.call(get_req(P)).await.text(), "{ }");
    let r = e.call(get_req(P).method("POST").body(r#"{"echo":true}"#)).await;
    assert_eq!(r.obj()["echo"], JValue::Bool(true), "echoed, never stored");
    assert_eq!(e.db.collection::<Document>("personalization").count_documents(doc! {}).await.unwrap(), 0);
    assert_eq!(e.call(get_req(P).method("DELETE")).await.status, StatusCode::INTERNAL_SERVER_ERROR);
    e.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn personalization_refusals() {
    let Some(e) = env().await else { return };
    let user = |r: Req| r.user("SYSTEM", "Authorities.Logged_IN");
    let oops = e.call(user(get_req(P).method("POST").body("{oops"))).await;
    assert_eq!((oops.status, oops.obj()["code"].clone()), (StatusCode::BAD_REQUEST, JValue::Str("COMMON.BODY_UNREADABLE".into())));
    let list = e.call(user(get_req(P).method("POST").body("[1]"))).await;
    assert_eq!((list.status, list.obj()["code"].clone()), (StatusCode::BAD_REQUEST, JValue::Str("UI.PERSONALIZATION_NOT_OBJECT".into())));
    // A row someone else created under this user's name cannot be changed or deleted.
    e.insert(
        "personalization",
        doc! {"name": "grid142", "appCode": "testapp", "clientCode": "SYSTEM", "createdBy": "7", "version": 1_i32,
        "personalization": {"a": 1_i32}},
    )
    .await;
    let r = e.call(user(get_req(P).method("POST").body(r#"{"a":2}"#))).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.obj()["code"], JValue::Str("UI.CANNOT_CHANGE_PREF".into()));
    assert_eq!(r.obj()["debugMessage"], JValue::Str("[cannot_change_pref] Cannot change preference.".into()));
    assert_eq!(e.call(user(get_req(P).method("DELETE"))).await.status, StatusCode::FORBIDDEN);
    // A row that others override cannot be deleted.
    e.db.collection::<Document>("personalization").delete_many(doc! {}).await.unwrap();
    e.insert(
        "personalization",
        doc! {"name": "grid142", "appCode": "testapp", "clientCode": "SYSTEM", "createdBy": "142", "version": 1_i32,
        "personalization": {"a": 1_i32}},
    )
    .await;
    e.insert("personalization", doc! {"name": "grid142", "appCode": "testapp", "clientCode": "C", "baseClientCode": "SYSTEM"})
        .await;
    let r = e.call(user(get_req(P).method("DELETE"))).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert!(r.obj()["debugMessage"].java_to_string().starts_with("[unable_to_delete] Unable to delete Personalization with id "));
    assert_eq!(r.obj()["code"], JValue::Str("UI.UNABLE_TO_DELETE".into()));
    // A row without a personalization map: Java maps it to null and fails.
    e.db.collection::<Document>("personalization").delete_many(doc! {}).await.unwrap();
    e.insert("personalization", doc! {"name": "grid142", "appCode": "testapp", "clientCode": "SYSTEM", "createdBy": "142"})
        .await;
    assert_eq!(e.call(user(get_req(P))).await.status, StatusCode::INTERNAL_SERVER_ERROR);
    // Without a version the update still lands.
    let r = e.call(user(get_req(P).method("POST").body(r#"{"b":1}"#))).await;
    assert_eq!(r.obj()["b"], JValue::Int(1));
    e.done().await;
}

// Function and schema repositories

async fn seed_repos(e: &Env) {
    e.insert(
        "function",
        doc! {"name": "Ns.fn", "appCode": "testapp", "clientCode": "SYSTEM", "executeAuth": "Authorities.X",
        "definition": {"name": "fn", "namespace": "Ns", "steps": {"s": {"statementName": "s", "namespace": "System",
            "name": "If", "position": {"left": 1.5, "top": 2_i32}}},
            "parameters": {"a": {"parameterName": "a", "schema": {"type": "INTEGER"}}}}},
    )
    .await;
    e.insert("function", doc! {"name": "plainName", "appCode": "testapp", "clientCode": "SYSTEM", "definition": {"name": "plainName"}})
        .await;
    e.insert("function", doc! {"name": "Dep.other", "appCode": "dep", "clientCode": "SYSTEM", "definition": {"name": "other", "namespace": "Dep"}})
        .await;
    e.insert(
        "schema",
        doc! {"name": "Ns.S", "appCode": "testapp", "clientCode": "SYSTEM",
        "definition": {"name": "S", "namespace": "Ns", "type": ["OBJECT"], "properties": {"p": {"type": "STRING"}}}},
    )
    .await;
    e.insert(
        "schema",
        doc! {"name": "Ns.E", "appCode": "testapp", "clientCode": "SYSTEM", "definition": {"name": "E", "namespace": "Ns", "enums": ["A"]}},
    )
    .await;
    e.insert("schema", doc! {"name": "Ns.Bad", "appCode": "testapp", "clientCode": "SYSTEM", "definition": {"type": "NOPE"}})
        .await;
    e.insert("function", doc! {"name": "Ns.bad", "appCode": "testapp", "clientCode": "SYSTEM", "definition": {"version": "x"}})
        .await;
    e.deps("testapp", &["dep"]);
}

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn function_repository_find() {
    let Some(e) = env().await else { return };
    seed_repos(&e).await;
    let r = e.call(get_req("/api/ui/functions/repositoryFind?namespace=Ns&name=fn")).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.header("content-type").as_deref(), Some("application/json"));
    let text = r.text();
    assert!(text.starts_with(r#"{"definition":{"version":1,"steps":{"s":{"statementName":"s","namespace":"System","name":"If","position":{"left":1.5,"top":2.0},"override":false}}"#), "{text}");
    assert!(text.ends_with(r#","executionAuthorization":"Authorities.X","ownerAppCode":"testapp"}"#), "{text}");
    // Through a dependency, codes as parameters, and a full name with no namespace.
    let r = e.call(get_req("/api/ui/functions/repositoryFind?appCode=testapp&clientCode=SYSTEM&namespace=Dep&name=other").app("x").client("y")).await;
    assert!(r.text().ends_with(r#""ownerAppCode":"dep"}"#), "{}", r.text());
    let r = e.call(get_req("/api/ui/functions/repositoryFind?namespace=&name=plainName")).await;
    assert!(r.text().contains(r#""name":"plainName""#));
    let r = e.call(get_req("/api/ui/functions/repositoryFind?name=plainName")).await;
    assert_eq!(r.status, StatusCode::OK);
    // Not found: an empty 200.
    let r = e.call(get_req("/api/ui/functions/repositoryFind?namespace=No&name=Such")).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.body.is_empty());
    // A definition Gson cannot read.
    let r = e.call(get_req("/api/ui/functions/repositoryFind?namespace=Ns&name=bad")).await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
    // Built-ins.
    let r = e.call(get_req("/api/ui/functions/repositoryFind?namespace=System&name=If&includeKIRunRepos=true")).await;
    assert_eq!(r.text(), "{}");
    let r = e.call(get_req("/api/ui/functions/repositoryFind?namespace=Ns&name=fn&includeKIRunRepos=yes")).await;
    assert!(r.text().contains("ownerAppCode"));
    assert_eq!(
        e.call(get_req("/api/ui/functions/repositoryFind?namespace=Ns&name=fn&includeKIRunRepos=maybe")).await.status,
        StatusCode::BAD_REQUEST
    );
    let r = e.call(get_req("/api/ui/functions/repositoryFind?namespace=Ns&name=fn&includeKIRunRepos=")).await;
    assert_eq!(r.status, StatusCode::OK);
    let r = e.call(get_req("/api/ui/functions/repositoryFind?namespace=Ns&name=fn&includeKIRunRepos=0")).await;
    assert_eq!(r.status, StatusCode::OK);
    e.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn function_and_schema_filters() {
    let Some(e) = env().await else { return };
    seed_repos(&e).await;
    let r = e.call(get_req("/api/ui/functions/repositoryFilter")).await;
    let JValue::Array(names) = r.json() else { panic!() };
    let names: Vec<String> = names.iter().map(JValue::java_to_string).collect();
    assert!(names.contains(&"Ns.fn".to_string()) && names.contains(&"Dep.other".to_string()), "{names:?}");
    let r = e.call(get_req("/api/ui/functions/repositoryFilter?filter=FN")).await;
    assert!(r.text().contains("Ns.fn") && !r.text().contains("Dep.other"), "{}", r.text());
    let r = e.call(get_req("/api/ui/functions/repositoryFilter?includeKIRunRepos=true&filter=math.add")).await;
    assert!(r.text().contains("System.Math.Add"));
    let r = e.call(get_req("/api/ui/schemas/repositoryFilter")).await;
    assert!(r.text().contains("Ns.S"));
    let r = e.call(get_req("/api/ui/schemas/repositoryFilter?includeKIRunRepos=true")).await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR, "Java's null filter on the built-in schemas");
    let r = e.call(get_req("/api/ui/schemas/repositoryFilter?includeKIRunRepos=true&filter=string")).await;
    assert!(r.text().contains("System.string"));
    assert_eq!(
        e.call(get_req("/api/ui/functions/repositoryFilter?includeKIRunRepos=x")).await.status,
        StatusCode::BAD_REQUEST
    );
    e.db.collection::<Document>("function").insert_one(doc! {"appCode": "testapp", "clientCode": "SYSTEM"}).await.unwrap();
    assert!(e.call(get_req("/api/ui/functions/repositoryFilter")).await.text().contains("null"));
    for path in ["/api/ui/functions/repositoryFilter", "/api/ui/schemas/repositoryFilter", "/api/ui/functions/repositoryFind", "/api/ui/schemas/repositoryFind"] {
        assert_eq!(e.call(get_req(path).header("Authorization", "refuse")).await.status, StatusCode::UNAUTHORIZED);
    }
    e.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn schema_repository_find() {
    let Some(e) = env().await else { return };
    seed_repos(&e).await;
    let r = e.call(get_req("/api/ui/schemas/repositoryFind?namespace=Ns&name=S")).await;
    let s = r.obj();
    assert_eq!(s["type"], overridable::json::parse(br#"["OBJECT"]"#).unwrap());
    assert_eq!(s["title"], JValue::Str("Ns.S".into()));
    assert_eq!(s["properties"].as_object().unwrap()["p"].as_object().unwrap()["fullName"], JValue::Str("_.null".into()));
    // Jackson cannot write a JsonElement: 500, as in Java.
    assert_eq!(e.call(get_req("/api/ui/schemas/repositoryFind?namespace=Ns&name=E")).await.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(e.call(get_req("/api/ui/schemas/repositoryFind?namespace=Ns&name=Bad")).await.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(e.call(get_req("/api/ui/schemas/repositoryFind?namespace=Ns&name=None")).await.body.is_empty());
    // Built-ins.
    let r = e.call(get_req("/api/ui/schemas/repositoryFind?namespace=System&name=string&includeKIRunRepos=true")).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.text().contains("\"STRING\""));
    let r = e.call(get_req("/api/ui/schemas/repositoryFind?namespace=System.Date&name=Timeunit&includeKIRunRepos=true")).await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR, "Java cannot write its enums either");
    let r = e.call(get_req("/api/ui/schemas/repositoryFind?namespace=System&name=nosuch&includeKIRunRepos=true")).await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR, "Mono.just(null)");
    let r = e.call(get_req("/api/ui/schemas/repositoryFind?namespace=Ns&name=S&includeKIRunRepos=true")).await;
    assert_eq!(r.status, StatusCode::OK, "outside System the app repository answers");
    let r = e.call(get_req("/api/ui/functions/repositoryFind?namespace=System.Date&name=AddTime&includeKIRunRepos=true")).await;
    assert_eq!(r.status, StatusCode::OK);
    let catalog: serde_json::Value = serde_json::from_str(include_str!("../src/kirun_catalog.json")).unwrap();
    let failing = catalog["functions"]["find"]
        .as_object()
        .unwrap()
        .iter()
        .find(|(_, v)| v["status"] == 500)
        .map(|(k, _)| k.clone())
        .unwrap();
    let (ns, name) = failing.rsplit_once('.').unwrap();
    let r = e.call(get_req(&format!("/api/ui/functions/repositoryFind?namespace={ns}&name={name}&includeKIRunRepos=true"))).await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
    e.done().await;
}
