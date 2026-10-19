//! The storage layer against the local stack: the definitions read from the `core` Mongo
//! database, both engines (Mongo for `monkbars`, MySQL for `appa`), security, KIRun triggers
//! run through the execution state, and the data routes over HTTP.
//!
//! Writes go only into scratch storages this test creates through the Java definitions API
//! (`POST /api/core/storages`, `/api/core/functions` on 8005), and everything is deleted through
//! that API at the end, whatever happened in between.
//!
//! Run: `eval "$(tools/local-env.py)"; CORE_LOCAL_STACK=1 cargo test -p core -- --include-ignored`.

use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

use appdata::engine::{SchemaRepositories, StorageResolver};
use futures::FutureExt;
use serde_json::{json, Value};

use crate::context;
use crate::local_stack_tests::connected;
use crate::storage::defs::{Catalog, StorageDefs};
use crate::testing::{local_stack, request, serve, user};

const BASIC: &str = "Basic MTQyOlBhc3NAMTIzNA==";
const JAVA: &str = "http://localhost:8005";
const MONGO_APP: &str = "monkbars";
const MYSQL_APP: &str = "appa";

struct Http {
    http: reqwest::Client,
}

impl Http {
    /// One request, retried while security is not answering (it stalls under load at times).
    async fn send(&self, base: &str, method: &str, path: &str, app: &str, body: Option<String>, ct: Option<&str>) -> (u16, Value, Vec<u8>) {
        for _ in 0..6 {
            let mut rb = self
                .http
                .request(reqwest::Method::from_bytes(method.as_bytes()).unwrap(), format!("{base}{path}"))
                .header("Authorization", BASIC)
                .header("clientCode", "SYSTEM")
                .header("appCode", app)
                .header("X-Forwarded-Host", "localhost")
                .header("X-Forwarded-Port", "8080")
                .timeout(Duration::from_secs(120));
            if let Some(b) = &body {
                rb = rb.header("content-type", ct.unwrap_or("application/json")).body(b.clone());
            }
            let Ok(r) = rb.send().await else {
                tokio::time::sleep(Duration::from_secs(10)).await;
                continue;
            };
            let status = r.status().as_u16();
            let bytes = r.bytes().await.unwrap_or_default().to_vec();
            let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
            if status == 500 && v.to_string().contains("securityContextAuthentication") {
                tokio::time::sleep(Duration::from_secs(10)).await;
                continue;
            }
            return (status, v, bytes);
        }
        panic!("{method} {path}: no answer");
    }
}

struct Created {
    storages: Vec<(String, String, String)>,
    functions: Vec<String>,
}

async fn define(h: &Http, created: &mut Created, app: &str, storage: Value) {
    let name = storage["name"].as_str().unwrap().to_string();
    let mut body = storage;
    body["appCode"] = json!(app);
    body["clientCode"] = json!("SYSTEM");
    let (s, v, _) = h.send(JAVA, "POST", "/api/core/storages", "appbuilder", Some(body.to_string()), None).await;
    assert_eq!(s, 200, "storage {name}: {v}");
    created.storages.push((v["id"].as_str().unwrap().to_string(), name, app.to_string()));
}

async fn cleanup(h: &Http, created: &Created) {
    for (_, name, app) in &created.storages {
        for draft in ["", "&draft=true"] {
            h.send(JAVA, "DELETE", &format!("/api/core/data/{name}?deleteAll=true{draft}"), app, None, None).await;
        }
    }
    for (id, _, _) in &created.storages {
        h.send(JAVA, "DELETE", &format!("/api/core/storages/{id}"), "appbuilder", None, None).await;
    }
    for id in &created.functions {
        h.send(JAVA, "DELETE", &format!("/api/core/functions/{id}"), "appbuilder", None, None).await;
    }
}

fn schema(props: Value) -> Value {
    json!({"type": "OBJECT", "properties": props})
}

async fn scenario(h: &Http, rust: &str, exec: &crate::Exec, created: &mut Created) {
    // Scratch definitions.
    let (s, v, _) = h
        .send(
            JAVA,
            "POST",
            "/api/core/functions",
            "appbuilder",
            Some(
                json!({"name": "RustGated.noop", "appCode": MONGO_APP, "clientCode": "SYSTEM",
                       "definition": {"name": "noop", "namespace": "RustGated", "steps": {}}})
                .to_string(),
            ),
            None,
        )
        .await;
    assert_eq!(s, 200, "{v}");
    created.functions.push(v["id"].as_str().unwrap().to_string());
    let props = json!({"name": {"type": "STRING"}, "age": {"type": "INTEGER"}, "addr": {"type": "OBJECT", "properties": {"city": {"type": "STRING"}}}});
    define(h, created, MONGO_APP, json!({"name": "rgParent", "isVersioned": true, "schema": schema(props.clone())})).await;
    define(
        h,
        created,
        MONGO_APP,
        json!({"name": "rgChild", "schema": schema(json!({"title": {"type": "STRING"}})),
               "relations": {"parent": {"storageName": "rgParent", "relationType": "TO_ONE", "deleteConstraint": "RESTRICT"}}}),
    )
    .await;
    define(
        h,
        created,
        MONGO_APP,
        json!({"name": "rgTrig", "schema": schema(json!({"v": {"type": "STRING"}})),
               "triggers": {"BEFORE_CREATE": ["RustGated.noop"], "AFTER_CREATE": ["RustGated.missing"]}}),
    )
    .await;
    define(h, created, MONGO_APP, json!({"name": "rgKirun", "onlyThruKIRun": true, "schema": schema(json!({"v": {"type": "STRING"}}))})).await;
    define(h, created, MYSQL_APP, json!({"name": "rgMy", "schema": schema(props)})).await;

    let d = "/api/core/data";
    // Mongo rows through the Rust routes.
    let (s, row, _) = h
        .send(rust, "POST", &format!("{d}/rgParent"), MONGO_APP, Some(r#"{"data":{"name":"Ann","age":3,"addr":{"city":"Pune"}}}"#.into()), None)
        .await;
    assert_eq!(s, 200, "{row}");
    let id = row["_id"].as_str().unwrap().to_string();
    let (s, read, _) = h.send(rust, "GET", &format!("{d}/rgParent/{id}"), MONGO_APP, None, None).await;
    assert_eq!((s, read["name"].clone()), (200, json!("Ann")));
    let (s, _, _) = h.send(rust, "PATCH", &format!("{d}/rgParent/{id}"), MONGO_APP, Some(r#"{"data":{"age":4}}"#.into()), None).await;
    assert_eq!(s, 200);
    let (s, bad, _) = h.send(rust, "POST", &format!("{d}/rgParent"), MONGO_APP, Some(r#"{"data":{"age":"x"}}"#.into()), None).await;
    assert_eq!(s, 500, "{bad}");
    let (_, versions, _) = h.send(rust, "POST", &format!("{d}/rgParent/version/{id}/query"), MONGO_APP, Some("{}".into()), None).await;
    assert!(versions["totalElements"].as_i64().unwrap() >= 1, "{versions}");
    let (_, page, _) = h.send(rust, "GET", &format!("{d}/rgParent?name=Ann"), MONGO_APP, None, None).await;
    assert_eq!(page["totalElements"], json!(1));
    let (_, agg, _) = h
        .send(rust, "POST", &format!("{d}/rgParent/aggregate"), MONGO_APP, Some(r#"{"aggregations":[{"function":"COUNT","alias":"n"}]}"#.into()), None)
        .await;
    assert_eq!(agg["content"][0]["n"], json!(1));
    let (_, _, csv) = h.send(rust, "GET", &format!("{d}/download/CSV/rgParent"), MONGO_APP, None, None).await;
    assert_eq!(String::from_utf8(csv).unwrap(), "age,name,addr.city\n4,Ann,Pune\n");
    let (_, _, tpl) = h.send(rust, "GET", &format!("{d}/template/rgParent"), MONGO_APP, None, None).await;
    assert_eq!(String::from_utf8(tpl).unwrap(), "age,name,addr.city\n,,\n");
    let upload = "--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"u.csv\"\r\n\r\nname,age\nUp,9\n\r\n--b--\r\n";
    let (s, up, _) = h.send(rust, "POST", &format!("{d}/upload/rgParent"), MONGO_APP, Some(upload.into()), Some("multipart/form-data; boundary=b")).await;
    assert_eq!((s, up), (200, json!(true)));

    // Relations and their constraint.
    let (s, child, _) = h
        .send(rust, "POST", &format!("{d}/rgChild?eager=true"), MONGO_APP, Some(json!({"data": {"title": "c", "parent": id}}).to_string()), None)
        .await;
    assert_eq!((s, child["parent"]["name"].clone()), (200, json!("Ann")), "{child}");
    let (s, refused, _) = h.send(rust, "DELETE", &format!("{d}/rgParent/{id}"), MONGO_APP, None, None).await;
    assert_eq!(s, 400, "{refused}");

    // A trigger runs through the execution state; a missing one is skipped.
    let (s, t, _) = h.send(rust, "POST", &format!("{d}/rgTrig"), MONGO_APP, Some(r#"{"data":{"v":"t"}}"#.into()), None).await;
    assert_eq!(s, 200, "{t}");

    // onlyThruKIRun: refused to a runtime session, open on the internal route and in KIRun.
    // Basic credentials sign in to the header's app, so the session is not a builder's.
    let (s, refused, _) = h.send(rust, "POST", &format!("{d}/rgKirun/query"), MONGO_APP, Some("{}".into()), None).await;
    assert_eq!(s, 403, "{refused}");
    let (s, _, _) = h.send(rust, "GET", "/api/core/internal/data/rgKirun", MONGO_APP, None, None).await;
    assert_eq!(s, 200);
    let (s, out, _) = h
        .send(
            rust,
            "POST",
            "/api/core/function/execute/CoreServices.Storage/ReadPage",
            MONGO_APP,
            Some(json!({"storageName": "rgParent", "size": 5}).to_string()),
            None,
        )
        .await;
    assert_eq!((s, out[0]["result"]["result"]["total"].clone()), (200, json!(2)), "{out}");
    let (s, empty, bytes) = h.send(rust, "GET", &format!("{d}/rgParent/migrationStatus"), MONGO_APP, None, None).await;
    assert_eq!((s, empty, bytes.len()), (200, Value::Null, 0));
    // monkbars has MySQL clients (MONKA, MONKC): the drift report covers their servers, where
    // this Mongo storage has no table.
    let (_, drift, _) = h.send(rust, "GET", &format!("{d}/rgParent/drift"), MONGO_APP, None, None).await;
    assert!(drift.as_array().is_some_and(|a| a.iter().all(|r| r["tableExists"] == json!(false))), "{drift}");

    // MySQL rows (appa runs on the platform MySQL).
    let (s, my, _) = h.send(rust, "POST", &format!("{d}/rgMy"), MYSQL_APP, Some(r#"{"data":{"name":"Sql","age":5}}"#.into()), None).await;
    assert_eq!(s, 200, "{my}");
    let my_id = my["_id"].as_str().unwrap().to_string();
    let (_, read, _) = h.send(rust, "GET", &format!("{d}/rgMy/{my_id}"), MYSQL_APP, None, None).await;
    assert_eq!(read["name"], json!("Sql"));
    let (s, status, _) = h.send(rust, "GET", &format!("{d}/rgMy/migrationStatus"), MYSQL_APP, None, None).await;
    assert!(s == 200 && status.is_array(), "{status}");
    let (s, report, _) = h.send(rust, "GET", &format!("{d}/rgMy/drift"), MYSQL_APP, None, None).await;
    assert!(s == 200 && report.is_array(), "{report}");
    let (s, deleted, _) = h.send(rust, "DELETE", &format!("{d}/rgMy/{my_id}"), MYSQL_APP, None, None).await;
    assert_eq!((s, deleted), (200, json!(true)));

    // The definitions as the policy layer reads them.
    let s = exec.state.inner();
    let defs = StorageDefs::new(s.definitions.clone(), s.core_schemas.clone(), exec.cache.family());
    let ctx = request(user(&["Authorities.Logged_IN"]), false, None);
    context::with_request(ctx, async {
        assert_eq!(defs.storages_referencing(MONGO_APP, "rgParent").await.unwrap(), ["rgChild"]);
        assert!(defs.storage_names(MONGO_APP).await.unwrap().contains(&"rgParent".to_string()));
        assert!(!defs.all_app_data("MYSQL", MYSQL_APP).await.unwrap().is_empty());
        assert!(defs.all_app_data("MYSQL", "").await.unwrap().is_empty());
        assert!(defs.connection("appData", MYSQL_APP, "SYSTEM", "APP_DATA").await.unwrap().is_some());
        assert!(defs.connection("appData", MYSQL_APP, "SYSTEM", "MAIL").await.unwrap().is_none());
        assert!(defs.connection("appData", MONGO_APP, "SYSTEM", "APP_DATA").await.unwrap().is_none());
        assert!(defs.raw_connection("appData", MYSQL_APP, "SYSTEM").await.unwrap().is_some());
        assert!(defs.event_definition("Storage.rgParent.Create", MONGO_APP, "SYSTEM").await.unwrap().is_none());
        assert!(defs.storage_for_tenant("rgParent", MONGO_APP, "SYSTEM", false).await.unwrap().is_some());
        assert!(defs.read_for_tenant("nope", MONGO_APP, "SYSTEM", false).await.unwrap().is_none());
        let repo = defs.for_app("appbuilder", "SYSTEM");
        assert!(repo.find("Nope", "Nope").await.unwrap().is_none());
        assert!(Catalog::schema_source(&defs, "appbuilder", "SYSTEM").await.is_ok());
        assert!(defs.schema_sources("appbuilder", "SYSTEM").find_json("Security.Context", "ContextUser").await.unwrap().is_some());
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the local stack: CORE_LOCAL_STACK=1 and config/local.toml"]
async fn storage_on_the_local_stack() {
    if !local_stack() {
        return;
    }
    let exec = connected().await;
    let rust = serve(crate::handlers::router(exec.state.clone())).await;
    let h = Http { http: reqwest::Client::new() };
    let mut created = Created { storages: Vec::new(), functions: Vec::new() };
    let result = AssertUnwindSafe(scenario(&h, &rust, &exec, &mut created)).catch_unwind().await;
    cleanup(&h, &created).await;
    let _ = Arc::new(());
    if let Err(p) = result {
        std::panic::resume_unwind(p);
    }
}
