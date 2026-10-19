//! Tests against the local stack: the Mongo `core` database, MySQL `core`, security,
//! entity-processor, as `config/core-exec.toml` names them, with the secrets of
//! `config/local.toml` in the environment. They only read: the definitions they execute are the
//! local ones (appbuilder `Test.fibonacci`, leadzumptwo `LeadZumpV2.wzHoldText`, leadzump's
//! entity-processor and marketingai dependency), nothing is written.
//!
//! Run: `eval "$(tools/local-env.py)"; CORE_LOCAL_STACK=1 cargo test -p core -- --include-ignored`.
//!
//! Java ports: `ContextLoadsTest` (core-exec starts and is ready), `ISecurityConfigurationTest
//! .excludedPathStaysOpen` (the execute route answers an anonymous caller).

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use serde_json::{json, Value};

use crate::config::CoreConfig;
use crate::context;
use crate::docs::{FunctionDoc, SchemaDoc};
use crate::exec::{self, Arguments};
use crate::repos::app::{app_function_repository, app_schema_repository, AppFunctions, AppSchemas};
use crate::repos::{FunctionSource, SchemaSource};
use crate::testing::{local_stack, request, user};

const PORT: u16 = 18105;
const BASIC: &str = "Basic MTQyOlBhc3NAMTIzNA==";

fn configure() -> CoreConfig {
    std::env::set_var("CONFIG_FILE", concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/core-exec.toml"));
    std::env::set_var("MODLIX__SERVER__PORT", PORT.to_string());
    std::env::set_var("MODLIX__TELEMETRY__LOG_LEVEL", "warn");
    platform::config::load("core-exec").expect("config")
}

struct Client {
    http: reqwest::Client,
    base: String,
}

struct Answer {
    status: StatusCode,
    content_type: String,
    text: String,
}

impl Answer {
    fn json(&self) -> Value {
        serde_json::from_str(&self.text).unwrap_or(Value::Null)
    }
}

impl Client {
    async fn send(&self, method: reqwest::Method, path: &str, headers: &[(&str, &str)], body: Option<&str>) -> Answer {
        let mut rb = self.http.request(method, format!("{}{path}", self.base));
        for (k, v) in headers {
            rb = rb.header(*k, *v);
        }
        if let Some(b) = body {
            rb = rb.header("content-type", "application/json").body(b.to_string());
        }
        let r = rb.send().await.expect("request");
        let status = StatusCode::from_u16(r.status().as_u16()).unwrap();
        let content_type = r.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        Answer { status, content_type, text: r.text().await.unwrap_or_default() }
    }

    async fn get(&self, path: &str, headers: &[(&str, &str)]) -> Answer {
        self.send(reqwest::Method::GET, path, headers, None).await
    }

    async fn post(&self, path: &str, headers: &[(&str, &str)], body: Option<&str>) -> Answer {
        self.send(reqwest::Method::POST, path, headers, body).await
    }
}

fn caller<'a>(app: &'a str) -> Vec<(&'a str, &'a str)> {
    vec![
        ("Authorization", BASIC),
        ("clientCode", "SYSTEM"),
        ("appCode", app),
        ("X-Forwarded-Host", "localhost"),
        ("X-Forwarded-Port", "8080"),
    ]
}

fn with<'a>(mut h: Vec<(&'a str, &'a str)>, extra: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
    h.extend_from_slice(extra);
    h
}

fn without<'a>(h: &[(&'a str, &'a str)], name: &str) -> Vec<(&'a str, &'a str)> {
    h.iter().filter(|(k, _)| *k != name).cloned().collect()
}

/// `ContextLoadsTest`, and every route of core-exec over HTTP.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the local stack: CORE_LOCAL_STACK=1 and config/local.toml"]
async fn serves_every_route_on_the_local_stack() {
    if !local_stack() {
        return;
    }
    configure();
    let server = tokio::spawn(crate::run_exec());
    let c = Client { http: reqwest::Client::new(), base: format!("http://127.0.0.1:{PORT}") };
    let mut ready = false;
    for _ in 0..100 {
        if c.http.get(format!("{}/readyz", c.base)).send().await.is_ok_and(|r| r.status().is_success()) {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ready, "core-exec did not become ready");

    let ex = "/api/core/function/execute";
    let app = caller("appbuilder");

    // Execution: System, core and stored functions, GET and POST.
    let a = c.get(&format!("{ex}/System.Math/Add?value=1&value=2"), &app).await;
    assert_eq!(a.status, StatusCode::OK);
    assert_eq!(a.content_type, "application/json");
    // A GET value is converted to its DOUBLE schema type, and kirun (as kirun-java since
    // 2026-10-17) keeps the double: `3.0`, as the Java core answers.
    assert_eq!(a.json(), json!([{"name": "output", "result": {"value": 3.0}}]));
    assert_eq!(c.get(&format!("{ex}/System.Math.Add?value=4"), &app).await.json()[0]["result"]["value"], json!(4.0));
    let a = c.post(&format!("{ex}/System.Math/Add"), &app, Some(r#"{"value":[1.5,2]}"#)).await;
    assert_eq!(a.json()[0]["result"]["value"], json!(3.5));
    let a = c.post(&format!("{ex}/System.Math.Add"), &app, Some("  ")).await;
    assert_eq!(a.status, StatusCode::OK);
    let a = c.get(&format!("{ex}/Test/fibonacci?n=7"), &with(app.clone(), &[("x-debug", "core-it"), ("x-draft", "true")])).await;
    assert_eq!(a.json()[0]["result"]["result"], json!([0, 1, 1, 2, 3, 5, 8]));
    let a = c.post(&format!("{ex}/CoreServices.SecurityContext/GetAuthentication"), &app, Some("{}")).await;
    assert_eq!(a.json()[0]["result"]["auth"]["isAuthenticated"], json!(true));
    let a = c.post(&format!("{ex}/CoreServices.Hash/HashData"), &app, Some(r#"{"data":"abc","algorithm":"MD4"}"#)).await;
    assert_eq!(a.status, StatusCode::BAD_REQUEST);
    assert_eq!(a.json()["code"], json!("CORE.HASH_ALGORITHM_UNSUPPORTED"));
    assert_eq!(a.json()["message"], json!("The hash algorithm MD4 is not supported."));
    assert_eq!(a.json()["debugMessage"], json!("MD4 MessageDigest not available"));
    let a = c.get(&format!("{ex}/CoreServices.Security/GetAppUrl?appCode=appbuilder"), &app).await;
    assert_eq!(a.status, StatusCode::OK);

    // `ISecurityConfigurationTest.excludedPathStaysOpen`: an anonymous caller is served.
    let anon = without(&app, "Authorization");
    let a = c.get(&format!("{ex}/System.Math/Add?value=1"), &anon).await;
    assert_eq!(a.status, StatusCode::OK);
    let a = c.get(&format!("{ex}/System.Math/Add?value=1"), &with(anon.clone(), &[("Authorization", "Bearer abc.def.ghi")])).await;
    assert_eq!(a.status, StatusCode::OK);

    // Errors.
    let a = c.get(&format!("{ex}/Nope/Nothing"), &app).await;
    assert_eq!(a.status, StatusCode::NOT_FOUND);
    assert_eq!(a.json()["code"], json!("CORE.FUNCTION_NOT_FOUND"));
    assert_eq!(a.json()["debugMessage"], json!("[object_not_found] Function with id Nope.Nothing not found"));
    let a = c.get(&format!("{ex}/NoDot"), &app).await;
    assert_eq!((a.status, a.json()["debugMessage"].clone()), (StatusCode::INTERNAL_SERVER_ERROR, json!("t1")));
    for header in ["X-Forwarded-Host", "X-Forwarded-Port", "appCode", "clientCode"] {
        let a = c.get(&format!("{ex}/System.Math/Add?value=1"), &without(&app, header)).await;
        assert_eq!(a.status, StatusCode::BAD_REQUEST, "{header}");
        assert_eq!(a.json()["debugMessage"], json!(format!("400 BAD_REQUEST \"Required header '{header}' is not present.\"")));
    }
    let a = c.post(&format!("{ex}/System.Math/Add"), &app, None).await;
    assert_eq!((a.status, a.json()["debugMessage"].clone()), (StatusCode::BAD_REQUEST, json!("400 BAD_REQUEST \"No request body\"")));
    for body in ["[1]", "null", "1", "\"x\"", "{bad"] {
        assert_eq!(c.post(&format!("{ex}/System.Math/Add"), &app, Some(body)).await.status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    }
    let a = c.get(&format!("{ex}/System.Math/Add?value=abc"), &app).await;
    assert_eq!(a.json()["debugMessage"], json!("For input string: \"abc\""));
    let a = c.post(&format!("{ex}/LeadZumpV2/wzHoldText"), &caller("leadzumptwo"), Some(r#"{"reason":"x"}"#)).await;
    assert_eq!(a.status, StatusCode::FORBIDDEN);
    assert_eq!(a.json()["code"], json!("CORE.FORBIDDEN_EXECUTION"));
    assert_eq!(a.json()["debugMessage"], json!("[forbidden_execution] Authorization $ is required to execute the function"));

    // Remote (entity-processor) and dependency functions for leadzump.
    let lz = caller("leadzump");
    let a = c.post(&format!("{ex}/EntityProcessor.Campaign/ReadPageFilter"), &lz, Some(r#"{"pageable":{"page":0,"size":1}}"#)).await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.text);
    // Found through the marketingai dependency; with a wrong verify token it raises no event,
    // as it does in Java.
    let a = c.get(&format!("{ex}/MarketingAI/verifyLeadgen?hubChallenge=5&hubMode=subscribe&hubVerifyToken=x"), &lz).await;
    assert_eq!(a.status, StatusCode::INTERNAL_SERVER_ERROR);
    // KIRun's own text first; the steps it came out of (if any) follow on their own lines.
    assert!(a.json()["debugMessage"].as_str().is_some_and(|d| d.lines().next() == Some("No events raised")), "{}", a.text);

    // repositoryFind / repositoryFilter.
    let f = "/api/core/functions";
    let a = c.get(&format!("{f}/repositoryFind?appCode=appbuilder&clientCode=SYSTEM&namespace=Test&name=fibonacci"), &app).await;
    assert_eq!(a.json()["definition"]["steps"], json!({}));
    let a = c.get(&format!("{f}/repositoryFind?namespace=Test&name=fibonacci"), &app).await;
    assert_eq!(a.json()["definition"]["name"], json!("fibonacci"));
    let a = c.get(&format!("{f}/repositoryFind?appCode=appbuilder&clientCode=SYSTEM&namespace=CoreServices.Hash&name=HashData"), &app).await;
    assert_eq!(a.json()["definition"]["namespace"], json!("CoreServices.Hash"));
    let a = c.get(&format!("{f}/repositoryFind?appCode=appbuilder&clientCode=SYSTEM&namespace=System.Math&name=Add&includeKIRunRepos=true"), &app).await;
    assert_eq!(a.json()["definition"]["name"], json!("Add"));
    for q in ["namespace=Nope&name=Nope", "namespace=Test"] {
        let a = c.get(&format!("{f}/repositoryFind?appCode=appbuilder&clientCode=SYSTEM&{q}"), &app).await;
        assert_eq!((a.status, a.text.as_str()), (StatusCode::OK, ""), "{q}");
    }
    let a = c.get(&format!("{f}/repositoryFind?appCode=leadzump&clientCode=SYSTEM&namespace=EntityProcessor.Campaign&name=Create"), &lz).await;
    assert_eq!(a.json()["definition"]["name"], json!("Create"));
    let a = c.get(&format!("{f}/repositoryFilter?appCode=appbuilder&clientCode=SYSTEM&filter=hash"), &app).await;
    assert_eq!(a.text, "[ \"CoreServices.Hash.HashData\" ]");
    for flag in ["on", "0", ""] {
        let a = c.get(&format!("{f}/repositoryFilter?appCode=appbuilder&clientCode=SYSTEM&filter=math&includeKIRunRepos={flag}"), &app).await;
        assert_eq!(a.status, StatusCode::OK, "{flag}");
    }
    let a = c.get(&format!("{f}/repositoryFilter?appCode=appbuilder&clientCode=SYSTEM&includeKIRunRepos=maybe"), &app).await;
    assert_eq!(a.status, StatusCode::BAD_REQUEST);
    let a = c.get(&format!("{f}/repositoryFilter?appCode=leadzump&clientCode=SYSTEM&filter=Campaign"), &lz).await;
    assert!(a.json().as_array().unwrap().iter().any(|n| n == "EntityProcessor.Campaign.Create"));

    let s = "/api/core/schemas";
    let a = c.get(&format!("{s}/repositoryFind?appCode=appbuilder&clientCode=SYSTEM&namespace=Test&name=UserRecord"), &app).await;
    assert_eq!(a.json()["fullName"], json!("Test.UserRecord"));
    let a = c.get(&format!("{s}/repositoryFind?appCode=appbuilder&clientCode=SYSTEM&namespace=Security.Context&name=ContextUser"), &app).await;
    assert_eq!(a.json()["name"], json!("ContextUser"));
    let a = c.get(&format!("{s}/repositoryFind?appCode=appbuilder&clientCode=SYSTEM&namespace=System&name=any&includeKIRunRepos=true"), &app).await;
    assert_eq!(a.json()["name"], json!("any"));
    let a = c.get(&format!("{s}/repositoryFind?appCode=leadzump&clientCode=SYSTEM&namespace=EntityProcessor.DTO&name=Owner"), &lz).await;
    assert_eq!(a.json()["name"], json!("Owner"));
    for q in ["namespace=Nope&name=Nope", "namespace=Test"] {
        let a = c.get(&format!("{s}/repositoryFind?appCode=appbuilder&clientCode=SYSTEM&{q}"), &app).await;
        assert_eq!((a.status, a.text.as_str()), (StatusCode::OK, ""), "{q}");
    }
    let a = c.get(&format!("{s}/repositoryFilter?appCode=appbuilder&clientCode=SYSTEM"), &app).await;
    assert!(a.json().as_array().unwrap().iter().any(|n| n == "Test.UserRecord"));
    let a = c.get(&format!("{s}/repositoryFilter?appCode=leadzump&clientCode=SYSTEM&filter=DTO.Owner&includeKIRunRepos=yes"), &lz).await;
    assert!(a.json().as_array().unwrap().iter().any(|n| n == "EntityProcessor.DTO.Owner"));

    server.abort();
}

pub(crate) async fn connected() -> crate::Exec {
    crate::connect(&configure()).await.expect("connect")
}

/// The execution path with a caller holding the function's execution authority, and the owner
/// app code of a function found through an app dependency.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs the local stack: CORE_LOCAL_STACK=1 and config/local.toml"]
async fn executes_with_the_execution_authority() {
    if !local_stack() {
        return;
    }
    let exec = connected().await;
    let st = exec.state.clone();
    let mut ctx = request(user(&["Authorities.LEADZUMPTWO.ROLE_Internal_Helper_Only"]), false, None);
    Arc::get_mut(&mut ctx).unwrap().app_code = Some("leadzumptwo".into());
    let out = context::with_request(ctx, async {
        let args = Arguments::Body(kirun::Map::from([("reason".to_string(), json!("x"))]));
        exec::execute(&st, Some("LeadZumpV2"), "wzHoldText", "leadzumptwo", "SYSTEM", args).await
    })
    .await
    .unwrap();
    assert!(out.starts_with("[{\"name\":\"output\""));

    // A function leadzump reaches through its marketingai dependency belongs to marketingai.
    let repo = app_function_repository(&exec.state.inner().definitions, "leadzump", "SYSTEM").await.unwrap();
    let f = repo.find(Some("MarketingAI"), "verifyLeadgen").await.unwrap().unwrap();
    let d = f.as_any().unwrap().downcast_ref::<crate::repos::definition::DefinitionFunction>().unwrap();
    assert_eq!(d.owner_app_code(), Some("marketingai"));
}

/// The app repositories and the remote-repository lookup, read directly.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs the local stack: CORE_LOCAL_STACK=1 and config/local.toml"]
async fn reads_definitions_and_remote_repositories() {
    if !local_stack() {
        return;
    }
    let exec = connected().await;
    let defs = exec.state.inner().definitions.clone();

    let functions = AppFunctions { defs: defs.clone(), app_code: "appbuilder".into(), client_code: "SYSTEM".into() };
    let first = functions.find(Some("Test"), "fibonacci").await.unwrap().unwrap();
    // The second read is the parsed definition kept for the same document.
    let second = functions.find(Some("Test"), "fibonacci").await.unwrap().unwrap();
    assert!(Arc::ptr_eq(&first, &second));
    assert!(functions.find(None, "Test.fibonacci").await.unwrap().is_some());
    assert!(functions.find(Some("Test"), "nothingHere").await.unwrap().is_none());
    assert!(functions.filter("fibo").await.unwrap().contains(&"Test.fibonacci".to_string()));
    assert!(!functions.filter("").await.unwrap().is_empty());

    let schemas = AppSchemas { defs: defs.clone(), app_code: "appbuilder".into(), client_code: "SYSTEM".into() };
    let s1 = schemas.find(Some("Test"), "UserRecord").await.unwrap().unwrap();
    let s2 = schemas.find(Some("Test"), "UserRecord").await.unwrap().unwrap();
    assert!(Arc::ptr_eq(&s1, &s2));
    assert!(schemas.find(None, "UserRecord").await.unwrap().is_none());
    assert_eq!(schemas.filter("user").await.unwrap(), ["Test.UserRecord"]);
    assert!(defs.filter(&SchemaDoc, "appbuilder", "SYSTEM", "").await.unwrap().len() >= 3);
    assert!(defs.filter(&FunctionDoc, "appbuilder", "SYSTEM", "Test").await.unwrap().len() >= 1);
    assert!(defs.store().db().name() == "core");

    let deps = defs.dependencies("leadzump").await.unwrap();
    assert!(deps.contains(&"marketingai".to_string()));
    assert!(app_schema_repository(&defs, "leadzump", "SYSTEM").await.unwrap().filter("").await.is_ok());
    assert!(app_schema_repository(&defs, "appbuilder", "SYSTEM").await.unwrap().find(Some("Test"), "UserRecord").await.unwrap().is_some());

    let remote = &exec.state.inner().remote;
    assert_eq!(remote.names("leadzump").await.unwrap().as_slice(), ["PROCESSOR"]);
    assert!(remote.names("appbuilder").await.unwrap().is_empty());
    assert!(remote.repositories("appbuilder", "SYSTEM").await.unwrap().is_none());
    assert!(remote.repositories("leadzump", "SYSTEM").await.unwrap().is_some());
}
