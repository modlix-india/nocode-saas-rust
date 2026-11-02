//! core-editor against the local stack, wired as `run` wires it (`assemble`): the definitions
//! in the `core` Mongo database, security, both app-data engines, core functions run as
//! definition triggers, the schedule view's reads. The deletion half of Java's
//! `DraftDataNamespaceIntegrationTest` runs here: a storage's draft collection goes with its
//! definition and the app's draft database with the app; the live data stays.
//!
//! Writes go only into the scratch app `coreedparity` (made through security's API by
//! `tools/parity_core_editor.py`; this test makes it the same way when it is missing) and into
//! a scratch storage of the MySQL app `appa` (no rows, so no table), all through the APIs, and
//! everything is deleted through them at the end.
//!
//! Run: `eval "$(tools/local-env.py)"; CORE_LOCAL_STACK=1 cargo test -p core -- --include-ignored`.

use std::panic::AssertUnwindSafe;
use std::time::Duration;

use futures::FutureExt;
use serde_json::{json, Value};

use crate::config::CoreConfig;
use crate::local_stack_tests::connected;
use crate::testing::{local_stack, serve};

const BASIC: &str = "Basic MTQyOlBhc3NAMTIzNA==";
const APP: &str = "coreedparity";
const MYSQL_APP: &str = "appa";

struct Http {
    http: reqwest::Client,
}

impl Http {
    async fn send(&self, base: &str, method: &str, path: &str, app: &str, draft: bool, body: Option<Value>) -> (u16, Value) {
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
            if draft {
                rb = rb.header("x-draft", "true");
            }
            if let Some(b) = &body {
                rb = rb.header("content-type", "application/json").body(b.to_string());
            }
            let Ok(r) = rb.send().await else {
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            };
            let status = r.status().as_u16();
            let text = r.text().await.unwrap_or_default();
            let v: Value = serde_json::from_str(&text).unwrap_or(Value::String(text.clone()));
            if status == 500 && text.contains("securityContextAuthentication") {
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
            return (status, v);
        }
        panic!("{method} {path}: no answer");
    }
}

async fn collections(exec: &crate::Exec, db: &str) -> Vec<String> {
    exec.mongo.client().database(db).list_collection_names().await.unwrap_or_default()
}

async fn scenario(h: &Http, editor: &str, data: &str, exec: &crate::Exec, st: &super::routes::CoreEditor, made: &mut Vec<(String, String)>) {
    let b = "appbuilder";
    // The app exists (security's API).
    let (s, _) = h.send("http://localhost:8001", "GET", &format!("/api/security/applications/appCode/{APP}"), b, false, None).await;
    if s != 200 {
        let (s, v) = h
            .send("http://localhost:8001", "POST", "/api/security/applications", b, false,
                  Some(json!({"appCode": APP, "appName": "Core Editor Parity (scratch)", "appType": "APP", "appAccessType": "OWN"})))
            .await;
        assert_eq!(s, 200, "{v}");
    }

    // A definition trigger is a core function, run as the caller.
    let (s, f) = h
        .send(editor, "POST", "/api/core/functions", b, false,
              Some(json!({"appCode": APP, "clientCode": "SYSTEM", "definition": {"namespace": "CedL", "name": "noop", "steps": {}}})))
        .await;
    assert_eq!(s, 200, "{f}");
    made.push(("functions".into(), f["id"].as_str().unwrap().to_string()));
    let (s, st1) = h
        .send(editor, "POST", "/api/core/storages", b, false,
              Some(json!({"name": "cedLocal", "appCode": APP, "clientCode": "SYSTEM",
                          "schema": {"type": "OBJECT", "properties": {"v": {"type": "STRING"}}},
                          "triggers": {"BEFORE_UPDATE_STORAGE": ["CedL.noop"], "AFTER_UPDATE_STORAGE": ["CedL.missing"]}})))
        .await;
    assert_eq!(s, 200, "{st1}");
    let id = st1["id"].as_str().unwrap().to_string();
    made.push(("storages".into(), id.clone()));
    let unique = st1["uniqueName"].as_str().unwrap().to_string();
    let mut body = st1.clone();
    body["isAudited"] = json!(true);
    let (s, up) = h.send(editor, "PUT", &format!("/api/core/storages/{id}"), b, false, Some(body)).await;
    assert_eq!(s, 200, "{up}");

    // Rows on both surfaces, through core-exec's data routes.
    let (s, row) = h.send(data, "POST", "/api/core/data/cedLocal", APP, false, Some(json!({"data": {"v": "live"}}))).await;
    assert_eq!(s, 200, "{row}");
    let (s, row) = h.send(data, "POST", "/api/core/data/cedLocal", APP, true, Some(json!({"data": {"v": "draft"}}))).await;
    assert_eq!(s, 200, "{row}");
    let live_db = format!("SYSTEM_{APP}");
    let draft_db = format!("SYSTEM_{APP}_draft");
    assert!(collections(exec, &draft_db).await.contains(&unique), "the draft row is in the draft database");
    assert!(st.data.estimated_row_count(APP, "SYSTEM").await >= 2, "metering counts rows on both surfaces");

    assert!(collections(exec, &live_db).await.contains(&unique), "the live row is in the live database");
    // The live rows go through the data route (the definition delete never touches live data:
    // the unit tests pin that only the draft collection is dropped).
    let (s, gone) = h.send(data, "DELETE", "/api/core/data/cedLocal?deleteAll=true", APP, false, None).await;
    assert_eq!(s, 200, "{gone}");

    // Deleting the definition drops its draft collection and keeps the live one.
    let (s, d) = h.send(editor, "DELETE", &format!("/api/core/storages/{id}"), b, false, None).await;
    assert_eq!((s, d), (200, json!(true)));
    made.retain(|(_, x)| x != &id);
    assert!(!collections(exec, &draft_db).await.contains(&unique), "draft rows outlived their definition");

    // The schedule view reads the run log, security and the definitions.
    let (s, ev) = h
        .send(editor, "POST", "/api/core/eventDefinitions", b, false,
              Some(json!({"name": "cedLocalEv", "appCode": APP, "clientCode": "SYSTEM", "schedule": {"cron": "0 9 * * *", "enabled": false}})))
        .await;
    assert_eq!(s, 200, "{ev}");
    made.push(("eventDefinitions".into(), ev["id"].as_str().unwrap().to_string()));
    let (s, page) = h.send(editor, "GET", &format!("/api/core/eventDefinitions/schedules?appCode={APP}&name=cedLocalEv"), b, false, None).await;
    assert_eq!(s, 200, "{page}");
    assert_eq!(page["content"][0]["state"], json!("PAUSED"), "{page}");

    // A MySQL app's storage: its tables reconciled on every change (none exist: no rows).
    let (s, my) = h
        .send(editor, "POST", "/api/core/storages", b, false,
              Some(json!({"name": "cedLocalMy", "appCode": MYSQL_APP, "clientCode": "SYSTEM",
                          "schema": {"type": "OBJECT", "properties": {"v": {"type": "STRING"}}}})))
        .await;
    assert_eq!(s, 200, "{my}");
    let my_id = my["id"].as_str().unwrap().to_string();
    made.push(("storages".into(), my_id.clone()));
    let mut body = my.clone();
    body["schema"]["properties"]["w"] = json!({"type": "INTEGER"});
    let (s, up) = h.send(editor, "PUT", &format!("/api/core/storages/{my_id}"), b, false, Some(body)).await;
    assert_eq!(s, 200, "{up}");

    // The app wipe drops the app's draft database (the live rows were removed above).
    let (s, w) = h.send(editor, "DELETE", &format!("/api/core?deleteAppCode={APP}"), b, false, None).await;
    assert_eq!((s, w), (200, json!(true)));
    made.retain(|(kind, _)| kind == "storages");
    let dbs = exec.mongo.client().list_database_names().await.unwrap_or_default();
    assert!(!dbs.contains(&draft_db), "the app's draft database outlived the app");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the local stack: CORE_LOCAL_STACK=1 and config/local.toml"]
async fn editor_on_the_local_stack() {
    if !local_stack() {
        return;
    }
    let exec = connected().await;
    let cfg: CoreConfig = platform::config::load("core-exec").expect("config");
    let (st, router, _) = super::assemble(&cfg, &exec).expect("assemble");
    let editor = serve(router).await;
    let data = serve(crate::handlers::router(exec.state.clone())).await;
    let h = Http { http: reqwest::Client::new() };
    let mut made: Vec<(String, String)> = Vec::new();
    let result = AssertUnwindSafe(scenario(&h, &editor, &data, &exec, &st, &mut made)).catch_unwind().await;
    for (kind, id) in &made {
        h.send(&editor, "DELETE", &format!("/api/core/{kind}/{id}"), "appbuilder", false, None).await;
    }
    if let Err(p) = result {
        std::panic::resume_unwind(p);
    }
}
