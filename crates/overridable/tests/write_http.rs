//! The routers and controller functions over HTTP (axum, `tower::oneshot`), the Java
//! `PublishRouteRegistrationTest` (ui and core) among them, and the security-backed pieces
//! (`SecurityCallers`, `RemoteDirectory`) against an in-process fake security service.

mod common;

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::extract::{Path, Query};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use common::*;
use http_body_util::BodyExt;
use overridable::backend::{Directory, RemoteDirectory};
use overridable::json::{parse, JValue};
use overridable::pojo::str_field;
use overridable::write::controller::{self as c, Reply, ReplyBody};
use overridable::write::deletion::DeletionService;
use overridable::write::publish::PublishService;
use overridable::write::router::{self, CallerSource, SecurityCallers};
use overridable::write::spring::Params;
use overridable::write::transport::TransportService;
use overridable::write::AnyService;
use platform::error::{AppError, AppResult};
use platform::security::{ContextAuthentication, OnBehalfOf, SecurityClient};
use platform::upstream::Upstream;
use serde_json::{json, Value};
use tower::ServiceExt;

/// The caller named by `x-test-client` (with every authority), anonymous without it, and a
/// refusal with `x-test-fail`.
struct TestCallers;

#[async_trait]
impl CallerSource for TestCallers {
    async fn caller(&self, headers: &HeaderMap) -> AppResult<ContextAuthentication> {
        if headers.contains_key("x-test-fail") {
            return Err(AppError::new(StatusCode::UNAUTHORIZED, "no"));
        }
        Ok(match headers.get("x-test-client").and_then(|v| v.to_str().ok()) {
            Some(client) => {
                let mut auths = all_for("Page");
                auths.extend(all_for("Transport"));
                auth_for(client, &auths)
            }
            None => anonymous(),
        })
    }
}

struct App {
    e: Env,
    router: Router,
}

fn app() -> App {
    let e = env();
    let callers: Arc<dyn CallerSource> = Arc::new(TestCallers);
    let services: Vec<Arc<dyn AnyService>> = vec![Arc::new(e.pages.clone())];
    let publish = Arc::new(PublishService::new(e.cx.clone(), services.clone()));
    let deletion = Arc::new(DeletionService::new(e.dir.clone(), services.clone()));
    let transport = Arc::new(TransportService::new(e.cx.clone(), services, "ui", "umodl"));
    let router = Router::new()
        .merge(router::overridable_router("/api/ui/pages", e.pages.clone(), callers.clone()))
        .merge(router::version_router("/api/ui/versions", e.cx.versions.clone(), callers.clone()))
        .merge(router::publish_router("/api/ui/publish", publish, callers.clone()))
        .merge(router::deletion_router("/api/ui", deletion, callers.clone()))
        .merge(router::transport_router("/api/ui/transports", transport, callers));
    App { e, router }
}

struct Answer {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Answer {
    fn json(&self) -> JValue {
        parse(&self.body).unwrap_or(JValue::Null)
    }

    fn message(&self) -> String {
        self.field("message")
    }

    fn field(&self, name: &str) -> String {
        self.json().as_object().and_then(|m| str_field(m, name).map(str::to_string)).unwrap_or_default()
    }

    /// The code and Java's text (`debugMessage` without its `[key] `).
    fn coded(&self) -> (String, String) {
        let d = self.field("debugMessage");
        let java = d.strip_prefix('[').and_then(|r| r.split_once("] ")).map(|(_, t)| t.to_string()).unwrap_or(d);
        (self.field("code"), java)
    }
}

impl App {
    async fn call(&self, method: &str, uri: &str, client: Option<&str>, body: &str) -> Answer {
        self.send(method, uri, client, &[], Body::from(body.to_string())).await
    }

    async fn send(&self, method: &str, uri: &str, client: Option<&str>, headers: &[(&str, &str)], body: Body) -> Answer {
        let mut req = Request::builder().method(method).uri(uri);
        if let Some(c) = client {
            req = req.header("x-test-client", c);
        }
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let resp = self.router.clone().oneshot(req.body(body).unwrap()).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = resp.into_body().collect().await.unwrap().to_bytes().to_vec();
        Answer { status, headers, body }
    }
}

fn forwarded() -> Vec<(&'static str, &'static str)> {
    vec![("x-forwarded-host", "localhost"), ("x-forwarded-port", "8080"), ("clientCode", SYSTEM), ("appCode", APP)]
}

#[tokio::test]
async fn the_page_routes_end_to_end() {
    let a = app();
    let s = Some(SYSTEM);
    let created = a.call("POST", "/api/ui/pages", s, r#"{"name":"home","appCode":"testapp","properties":{"title":"t"}}"#).await;
    assert_eq!(created.status, StatusCode::OK);
    assert_eq!(created.headers["content-type"], "application/json");
    assert_eq!(created.headers["x-frame-options"], "DENY");
    assert!(String::from_utf8_lossy(&created.body).contains("\n  \"name\" : \"home\""), "indented like Jackson");
    let id = created.json().as_object().and_then(|m| str_field(m, "id").map(str::to_string)).unwrap();

    let one = a.call("GET", &format!("/api/ui/pages/{id}"), s, "").await;
    assert_eq!(one.status, StatusCode::OK);
    let draft_read = a.call("GET", &format!("/api/ui/pages/{id}?draft=true"), s, "").await;
    assert_eq!(draft_read.headers["x-draft-version"], "0");
    let not_draft = a.call("GET", &format!("/api/ui/pages/{id}?draft=false"), s, "").await;
    assert!(not_draft.headers.get("x-draft-version").is_none());

    let saved = a.call("PUT", &format!("/api/ui/pages/{id}?draft=true&draftVersion=0"), s, r#"{"properties":{"title":"d"}}"#).await;
    assert_eq!(saved.status, StatusCode::OK);
    assert_eq!(saved.json().as_object().unwrap()["objectType"], JValue::Str("PAGE".into()));
    let stale = a.call("PUT", &format!("/api/ui/pages/{id}?draft=true&draftVersion=0"), s, r#"{"properties":{"title":"d"}}"#).await;
    assert_eq!(stale.status, StatusCode::PRECONDITION_FAILED);
    let refused = a.call("PUT", &format!("/api/ui/pages/{id}?draft=false"), s, "{}").await;
    assert_eq!((refused.status, refused.body.len()), (StatusCode::BAD_REQUEST, 0));
    assert_eq!(a.call("PUT", &format!("/api/ui/pages/{id}?draft=maybe"), s, "{}").await.status, StatusCode::BAD_REQUEST);
    assert_eq!(a.call("PUT", &format!("/api/ui/pages/{id}?draft=true&draftVersion=x"), s, "{}").await.status, StatusCode::BAD_REQUEST);
    assert_eq!(a.call("PUT", &format!("/api/ui/pages/{id}"), s, "[1]").await.status, StatusCode::BAD_REQUEST);

    let published = a.call("POST", &format!("/api/ui/pages/{id}/publish?message=go"), s, "").await;
    assert_eq!(published.status, StatusCode::OK);
    let live = a.call("PUT", &format!("/api/ui/pages/{id}"), s, r#"{"version":2,"properties":{"title":"live"}}"#).await;
    assert_eq!(live.status, StatusCode::OK, "{}", live.message());

    let plan = a.call("PATCH", &format!("/api/ui/pages/{id}/blueprint"), s, r#"{"plan":{}}"#).await;
    assert_eq!(plan.status, StatusCode::OK);
    assert_eq!(a.call("PATCH", &format!("/api/ui/pages/{id}/blueprint"), s, "").await.status, StatusCode::OK);
    assert_eq!(a.call("PATCH", &format!("/api/ui/pages/{id}/blueprint"), s, "null").await.status, StatusCode::OK);
    assert_eq!(a.call("PATCH", &format!("/api/ui/pages/{id}/blueprint"), s, "[]").await.status, StatusCode::BAD_REQUEST);

    let list = a.call("GET", "/api/ui/pages?appCode=testapp&size=5&eager=true", s, "").await;
    assert_eq!(list.json().as_object().unwrap()["totalElements"], JValue::Int(1));
    assert_eq!(a.call("GET", "/api/ui/pages?appCode=testapp&eager=nope", s, "").await.status, StatusCode::BAD_REQUEST);
    for m in ["GET", "POST"] {
        let n = a.call(m, "/api/ui/pages/nomap2", s, "").await;
        assert_eq!((n.status, n.body.len()), (StatusCode::BAD_REQUEST, 0));
    }

    let unknown = a.call("GET", "/api/ui/pages/createForClient/64b7f1c2e4b0a1c2d3e4f5a6/LZCLA", s, "").await;
    assert_eq!((unknown.status, unknown.body.len()), (StatusCode::OK, 0), "an empty Mono is an empty 200");
    let copy = a.call("GET", &format!("/api/ui/pages/createForClient/{id}/LZCLA"), s, "").await;
    assert_eq!(copy.status, StatusCode::OK);
    let fork = a.call("POST", &format!("/api/ui/pages/{id}/fork"), s, "").await;
    assert_eq!(fork.status, StatusCode::OK);
    let discard = a.call("DELETE", &format!("/api/ui/pages/{id}/draft"), s, "").await;
    assert_eq!(discard.json(), JValue::Bool(false));
    let unpublished = a.call("POST", "/api/ui/pages?draft=true", s, r#"{"name":"wip","appCode":"testapp"}"#).await;
    assert_eq!(unpublished.json().as_object().unwrap()["published"], JValue::Bool(false));
    let plain = a.call("POST", "/api/ui/pages?draft=false", s, r#"{"name":"plain","appCode":"testapp"}"#).await;
    assert_eq!(plain.status, StatusCode::OK);

    let refused = a.call("DELETE", &format!("/api/ui/pages/{id}"), s, "").await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN, "the LZCLA copy overrides it");
    let (code, java) = refused.coded();
    assert!(java.starts_with("Unable to delete Page with id"), "{java}");
    assert_eq!(code, "DEF.DELETE_BLOCKED_BY_OVERRIDES");
    assert!(refused.message().starts_with("We couldn't delete the page with id "), "{}", refused.message());
    let anon = a.call("GET", &format!("/api/ui/pages/{id}"), None, "").await;
    assert_eq!((anon.status, anon.coded()), (StatusCode::NOT_FOUND, ("DEF.OBJECT_NOT_FOUND".into(), format!("Page with id {id} not found"))));
    let anon_edit = a.call("PUT", &format!("/api/ui/pages/{id}"), None, r#"{"version":3}"#).await;
    assert_eq!((anon_edit.status, anon_edit.field("code")), (StatusCode::FORBIDDEN, "DEF.SIGN_IN_REQUIRED".into()));
    let bad_flag = a.call("GET", "/api/ui/pages?appCode=testapp&eager=nope", s, "").await;
    assert_eq!(bad_flag.field("code"), "COMMON.PARAM_INVALID");
    assert_eq!(bad_flag.message(), "The value of the eager parameter is not valid: it should be true or false.");
    assert_eq!(bad_flag.field("debugMessage"), "400 BAD_REQUEST \"Type mismatch.\"");
    let failed = a.send("GET", &format!("/api/ui/pages/{id}"), None, &[("x-test-fail", "1")], Body::empty()).await;
    assert_eq!(failed.status, StatusCode::UNAUTHORIZED);
    let wip_id = unpublished.json().as_object().and_then(|m| str_field(m, "id").map(str::to_string)).unwrap();
    assert_eq!(a.call("DELETE", &format!("/api/ui/pages/{wip_id}"), s, "").await.json(), JValue::Bool(true));
}

#[tokio::test]
async fn publish_routes_are_registered_and_answer() {
    let a = app();
    let id = a.e.page(&page_json("p", SYSTEM, "t", "r", ""));
    a.call("PUT", &format!("/api/ui/pages/{id}?draft=true"), Some(SYSTEM), r#"{"properties":{"title":"d"}}"#).await;
    let pending = a.call("GET", "/api/ui/publish/app/testapp/pending", Some(SYSTEM), "").await;
    assert_eq!(pending.status, StatusCode::OK);
    assert!(pending.json().as_object().unwrap().contains_key("PAGE"));
    let anon = a.call("GET", "/api/ui/publish/app/testapp/pending?clientCode=SYSTEM", None, "").await;
    assert_eq!(anon.status, StatusCode::FORBIDDEN);
    let all = a.call("POST", "/api/ui/publish/app/testapp?clientCode=SYSTEM", Some(SYSTEM), "").await;
    assert_eq!(all.json().as_object().unwrap()["published"], JValue::Int(1));
    for (m, uri) in [("GET", "/api/ui/publish/app/x/pending"), ("POST", "/api/ui/publish/app/x")] {
        let r = a.send(m, uri, None, &[("x-test-fail", "1")], Body::empty()).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{uri} is mapped");
    }
}

#[tokio::test]
async fn version_and_deletion_routes() {
    let a = app();
    let created = a.call("POST", "/api/ui/pages", Some(SYSTEM), r#"{"name":"v","appCode":"testapp"}"#).await;
    let id = created.json().as_object().and_then(|m| str_field(m, "id").map(str::to_string)).unwrap();
    let vid = overridable::bson_conv::to_java_string(a.e.raw("version")[0].get("_id").unwrap()).java_to_string();
    let v = a.call("GET", &format!("/api/ui/versions/{vid}"), Some(SYSTEM), "").await;
    assert_eq!(v.json().as_object().unwrap()["versionNumber"], JValue::Int(1));
    let missing = a.call("GET", "/api/ui/versions/64b7f1c2e4b0a1c2d3e4f5a6", Some(SYSTEM), "").await;
    assert_eq!((missing.status, missing.body.len()), (StatusCode::OK, 0));
    assert_eq!(a.send("GET", "/api/ui/versions/x", None, &[("x-test-fail", "1")], Body::empty()).await.status, StatusCode::UNAUTHORIZED);
    let q = a.call("POST", &format!("/api/ui/versions/{id}/query"), Some(SYSTEM), r#"{"size":5}"#).await;
    assert_eq!(q.json().as_object().unwrap()["totalElements"], JValue::Int(1));
    let anon = a.call("POST", &format!("/api/ui/versions/{id}/query"), None, r#"{"size":5}"#).await;
    assert_eq!(anon.json().as_object().unwrap()["totalElements"], JValue::Int(0), "history is not open to anonymous callers");
    assert_eq!(a.call("POST", &format!("/api/ui/versions/{id}/query"), Some(SYSTEM), "{").await.status, StatusCode::BAD_REQUEST);
    assert_eq!(a.send("POST", "/api/ui/versions/x/query", None, &[("x-test-fail", "1")], Body::from("{}")).await.status, StatusCode::UNAUTHORIZED);

    let no_headers = a.call("DELETE", "/api/ui?deleteAppCode=testapp", Some(SYSTEM), "").await;
    assert_eq!(no_headers.status, StatusCode::BAD_REQUEST);
    let no_param = a.send("DELETE", "/api/ui", Some(SYSTEM), &forwarded(), Body::empty()).await;
    assert_eq!(no_param.status, StatusCode::BAD_REQUEST);
    let wiped = a.send("DELETE", "/api/ui?deleteAppCode=testapp", Some(SYSTEM), &forwarded(), Body::empty()).await;
    assert_eq!(wiped.json(), JValue::Bool(true));
    a.e.dir.set(|x| x.delete_access = false);
    let refused = a.send("DELETE", "/api/ui?deleteAppCode=testapp", Some(SYSTEM), &forwarded(), Body::empty()).await;
    assert_eq!((refused.status, refused.body.len()), (StatusCode::OK, 0));
    assert_eq!(a.send("DELETE", "/api/ui", None, &[("x-test-fail", "1")], Body::empty()).await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn transport_routes() {
    let a = app();
    a.e.page(&page_json("home", SYSTEM, "t", "r", ""));
    let s = Some(SYSTEM);
    let refused = a.call("POST", "/api/ui/transports", s, r#"{"name":"x"}"#).await;
    assert_eq!(
        (refused.status, refused.coded()),
        (StatusCode::FORBIDDEN, ("DEF.TRANSPORT_UPLOAD_REQUIRED".into(), "Error while Creating transport : You need to upload a transport file using /createAndApply".into()))
    );
    let made = a.call("POST", "/api/ui/transports?draft=false", s, r#"{"name":"t","appCode":"testapp","clientCode":"SYSTEM","uniqueTransportCode":"T1"}"#).await;
    assert_eq!(made.status, StatusCode::OK);
    let no_drafts = a.call("POST", "/api/ui/transports?draft=true", s, "{}").await;
    assert_eq!((no_drafts.status, no_drafts.coded()), (StatusCode::METHOD_NOT_ALLOWED, ("DEF.DRAFT_NOT_SUPPORTED".into(), "Draft with id Transport not found".into())));
    let odd_type = a.call("POST", "/api/ui/transports/makeTransport", s, r#"{"appCode":"testapp","fileType":"XML"}"#).await;
    assert_eq!((odd_type.status, odd_type.coded()), (StatusCode::BAD_REQUEST, ("DEF.TRANSPORT_FILE_TYPE_UNKNOWN".into(), "Unknown file type XML".into())));
    assert_eq!(odd_type.message(), "The transport file type XML is not known.");
    let types = a.call("GET", "/api/ui/transports/transportTypes", None, "").await;
    assert_eq!(types.json(), JValue::Array(vec![JValue::Str("Page".into())]));

    let zip = a.call("POST", "/api/ui/transports/makeTransport", s, r#"{"appCode":"testapp","clientCode":"SYSTEM"}"#).await;
    assert_eq!(zip.headers["content-type"], "application/zip");
    assert_eq!(zip.headers["content-disposition"], "attachment; filename=testapp_SYSTEM.umodl");
    let json = a.call("POST", "/api/ui/transports/internal/makeTransport", s, r#"{"appCode":"testapp","clientCode":"SYSTEM","fileType":"JSON"}"#).await;
    assert_eq!(json.headers["content-type"], "application/json");
    assert_eq!(a.call("POST", "/api/ui/transports/makeTransport", s, "{").await.status, StatusCode::BAD_REQUEST);

    let id = made.json().as_object().and_then(|m| str_field(m, "id").map(str::to_string)).unwrap();
    let mut h = forwarded();
    h.push(("x-test-client", SYSTEM));
    let applied = a.send("GET", &format!("/api/ui/transports/applyTransport/{id}"), None, &h, Body::empty()).await;
    assert_eq!(applied.json(), JValue::Bool(true));
    let no_headers = a.call("GET", &format!("/api/ui/transports/applyTransport/{id}"), s, "").await;
    assert_eq!((no_headers.status, no_headers.field("code")), (StatusCode::BAD_REQUEST, "COMMON.HEADER_MISSING".into()));
    assert_eq!(no_headers.field("debugMessage"), "400 BAD_REQUEST \"Required header is not present\"");
    let by_code = a.send("GET", "/api/ui/transports/applyTransportCode/T1", None, &h, Body::empty()).await;
    assert_eq!(by_code.json(), JValue::Bool(true));
    assert_eq!(a.call("GET", "/api/ui/transports/applyTransportCode/T1", s, "").await.status, StatusCode::BAD_REQUEST);
    let swept = a.call("POST", "/api/ui/transports/internal/cleanupOlderThan?retentionDays=30", None, "").await;
    assert_eq!(swept.json().as_object().unwrap()["transportsRemoved"], JValue::Int(0));
    assert_eq!(a.call("POST", "/api/ui/transports/internal/cleanupOlderThan?limit=x", None, "").await.status, StatusCode::BAD_REQUEST);

    let upload = a
        .send("POST", "/api/ui/transports/internal/createAndApply?fileName=t.json&applicationCode=newapp", None, &h, Body::from(json.body.clone()))
        .await;
    assert_eq!(upload.status, StatusCode::OK, "{}", upload.message());
    assert!(a.e.raw("page").iter().any(|d| d.get_str("appCode") == Ok("newapp")));
    let no_name = a.send("POST", "/api/ui/transports/internal/createAndApply", None, &h, Body::empty()).await;
    assert_eq!((no_name.status, no_name.field("code")), (StatusCode::BAD_REQUEST, "COMMON.PARAM_MISSING".into()));
    assert_eq!(no_name.message(), "The request is missing the fileName parameter.");
    assert_eq!(a.call("POST", "/api/ui/transports/internal/createAndApply?fileName=x", s, "").await.status, StatusCode::BAD_REQUEST);

    let boundary = "XBOUNDARY";
    let mut multipart = format!("--{boundary}\r\nContent-Disposition: form-data; name=\"other\"\r\n\r\nx\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"t.umodl\"\r\nContent-Type: application/zip\r\n\r\n").into_bytes();
    multipart.extend_from_slice(&zip.body);
    multipart.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let mut mh = h.clone();
    let ct = format!("multipart/form-data; boundary={boundary}");
    mh.push(("content-type", &ct));
    let up = a.send("POST", "/api/ui/transports/createAndApply?applicationCode=zipapp", None, &mh, Body::from(multipart)).await;
    assert_eq!(up.status, StatusCode::OK, "{}", up.message());
    let empty = format!("--{boundary}--\r\n");
    let none = a.send("POST", "/api/ui/transports/createAndApply", None, &mh, Body::from(empty)).await;
    assert_eq!(none.status, StatusCode::BAD_REQUEST);
    let bad = a.send("POST", "/api/ui/transports/createAndApply", None, &mh, Body::from("garbage")).await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    let mut no_fwd = vec![("x-test-client", SYSTEM), ("content-type", ct.as_str())];
    no_fwd.push(("x", "y"));
    assert_eq!(a.send("POST", "/api/ui/transports/createAndApply", None, &no_fwd, Body::from(format!("--{boundary}--\r\n"))).await.status, StatusCode::BAD_REQUEST);
    for (m, uri) in [
        ("POST", "/api/ui/transports/makeTransport"),
        ("POST", "/api/ui/transports/internal/makeTransport"),
        ("GET", "/api/ui/transports/applyTransport/x"),
        ("GET", "/api/ui/transports/applyTransportCode/x"),
        ("POST", "/api/ui/transports/internal/createAndApply"),
    ] {
        assert_eq!(a.send(m, uri, None, &[("x-test-fail", "1")], Body::empty()).await.status, StatusCode::UNAUTHORIZED, "{uri}");
    }
    let r = a.send("POST", "/api/ui/transports/createAndApply", None, &[("x-test-fail", "1"), ("content-type", &ct)], Body::from(format!("--{boundary}--\r\n"))).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
}

#[test]
fn replies_and_parameters() {
    let r = Reply::json(JValue::Bool(true)).header("bad header", "x".into()).header("X-Ok", "1".into());
    assert_eq!(r.json_body(), Some(&JValue::Bool(true)));
    let resp = r.into_response();
    assert_eq!(resp.headers()["x-ok"], "1");
    assert!(Reply::empty(StatusCode::OK).json_body().is_none());
    let f = Reply { status: StatusCode::OK, headers: vec![], body: ReplyBody::File { content_type: "text/plain", bytes: b"x".to_vec() } };
    assert_eq!(f.into_response().headers()["content-type"], "text/plain");
    let p = Params::of(&[("a", "on"), ("b", "OFF"), ("n", " 7 ")]);
    assert!(c::bool_param(&p, "a", false).unwrap());
    assert!(!c::bool_param(&p, "b", true).unwrap());
    assert!(c::bool_param(&p, "z", true).unwrap());
    assert_eq!(c::int_param(&p, "n").unwrap(), Some(7));
    assert_eq!(c::int_param(&p, "z").unwrap(), None);
    assert!(c::read_entity(&PAGE, b"{").is_err());
}

// ── Security-backed pieces ───────────────────────────────────────────────

#[derive(Default)]
struct Fake {
    calls: HashMap<&'static str, AtomicUsize>,
}

impl Fake {
    fn new() -> Self {
        let mut calls = HashMap::new();
        for k in ["read", "write", "explicit", "manage", "inherit", "delete", "base", "ca"] {
            calls.insert(k, AtomicUsize::new(0));
        }
        Self { calls }
    }
    fn hit(&self, k: &str) {
        self.calls[k].fetch_add(1, Ordering::SeqCst);
    }
    fn count(&self, k: &str) -> usize {
        self.calls[k].load(Ordering::SeqCst)
    }
}

async fn fake_security() -> (SecurityClient, Arc<Fake>) {
    let fake = Arc::new(Fake::new());
    let f = fake.clone();
    let app = Router::new()
        .route(
            "/api/security/internal/securityContextAuthentication",
            get({
                let f = f.clone();
                move |h: HeaderMap| async move {
                    f.hit("ca");
                    match h.get("authorization").and_then(|v| v.to_str().ok()) {
                        Some("Bearer good") | Some("good") => Json(json!({"user": {"id": 5, "stringAuthorities": ["Authorities.Page_READ"]}, "authenticated": true, "clientCode": "SYSTEM", "clientTypeCode": "SYS"})).into_response(),
                        Some("silent") => StatusCode::FORBIDDEN.into_response(),
                        Some("coded") => (
                            StatusCode::UNAUTHORIZED,
                            Json(json!({"exceptionId": "x", "message": "Your sign-in is no longer valid. Please sign in again.", "stackTrace": "",
                                "debugMessage": "[unknown_token] Unknown token", "code": "SEC.UNKNOWN_TOKEN", "params": {}, "locale": "en"})),
                        )
                            .into_response(),
                        _ => (StatusCode::UNAUTHORIZED, Json(json!({"message": "bad token"}))).into_response(),
                    }
                }
            }),
        )
        .route("/api/security/applications/internal/hasReadAccess", get({ let f = f.clone(); move || async move { f.hit("read"); Json(json!(true)) } }))
        .route("/api/security/applications/internal/hasWriteAccess", get({ let f = f.clone(); move || async move { f.hit("write"); Json(json!(false)) } }))
        .route(
            "/api/security/applications/internal/explicitInfo/{app}",
            get({
                let f = f.clone();
                move |Path(app): Path<String>| async move {
                    f.hit("explicit");
                    if app == "unknown" {
                        String::new().into_response()
                    } else {
                        Json(json!({"appAccessType": "EXPLICIT", "clientCode": "OWN"})).into_response()
                    }
                }
            }),
        )
        .route("/api/security/clients/internal/doesClientManageClientCode", get({ let f = f.clone(); move || async move { f.hit("manage"); Json(json!(true)) } }))
        .route(
            "/api/security/applications/internal/appInheritance",
            get({ let f = f.clone(); move |Query(q): Query<HashMap<String, String>>| async move { f.hit("inherit"); Json(json!(["SYSTEM", q.get("clientCode").cloned().unwrap_or_default()])) } }),
        )
        .route(
            "/api/security/applications/hasDeleteAccess",
            get({
                let f = f.clone();
                move |h: HeaderMap| async move {
                    f.hit("delete");
                    if h.get("authorization").is_some() && h.get("x-forwarded-host").is_some() { Json(json!(true)).into_response() } else { String::new().into_response() }
                }
            }),
        )
        .route(
            "/api/security/applications/findBaseClientCode/{app}",
            get({
                let f = f.clone();
                move |Path(app): Path<String>| async move {
                    f.hit("base");
                    match app.as_str() {
                        "none" => String::new().into_response(),
                        "odd" => Json(json!([1, 2])).into_response(),
                        _ => Json(json!(["BASECL", true])).into_response(),
                    }
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await });
    (SecurityClient::new(Upstream::fixed(&[&format!("http://{addr}")]), 0).unwrap(), fake)
}

#[tokio::test]
async fn the_remote_directory_asks_security_and_caches_like_java() {
    let (security, fake) = fake_security().await;
    let cache = platform::cache::CacheService::new("cmn", "evictionChannel", None).unwrap();
    let dir = RemoteDirectory::new(security, &cache);
    for _ in 0..2 {
        assert!(dir.has_read_access("a", "C").await.unwrap());
        assert!(!dir.has_write_access("a", "C").await.unwrap());
        assert!(dir.app_explicit_info("a").await.unwrap().unwrap().is_explicit());
        assert!(dir.app_explicit_info("unknown").await.unwrap().is_none());
        assert!(dir.does_client_manage_client_code("A", "B").await.unwrap());
        assert_eq!(dir.app_inheritance("a", "", "FIN").await.unwrap(), ["SYSTEM", "FIN"]);
    }
    assert_eq!((fake.count("read"), fake.count("write"), fake.count("explicit")), (1, 1, 3), "appReadAccess, appWriteAccess and byAppCodeExplicit are cached; an unknown app is not");
    assert_eq!((fake.count("manage"), fake.count("inherit")), (2, 2), "doesClientManageClientCode is not; appInheritance is cached by the store");
    cache.evict_all_everywhere("appReadAccess").await;
    dir.has_read_access("a", "C").await.unwrap();
    assert_eq!(fake.count("read"), 2, "security's evictions reach the copy");
    let ob = OnBehalfOf { access_token: Some("t".into()), forwarded_host: "h".into(), forwarded_port: "1".into(), client_code: "C".into(), app_code: "A".into() };
    assert!(dir.has_delete_access(&ob, "a", "C").await.unwrap());
    assert!(!dir.has_delete_access(&OnBehalfOf { access_token: None, ..ob.clone() }, "a", "C").await.unwrap());
    assert_eq!(dir.find_base_client_code_for_override(&ob, "app").await.unwrap(), Some(("BASECL".into(), true)));
    assert_eq!(dir.find_base_client_code_for_override(&ob, "none").await.unwrap(), None);
    assert_eq!(dir.find_base_client_code_for_override(&ob, "odd").await.unwrap(), None);
}

#[tokio::test]
async fn security_callers_relay_securitys_answer() {
    let (security, _) = fake_security().await;
    let callers = SecurityCallers { security, server_port: 8080 };
    let mut h = HeaderMap::new();
    h.insert("authorization", "Bearer good".parse().unwrap());
    h.insert("clientCode", "FIN".parse().unwrap());
    h.insert("appCode", "app1".parse().unwrap());
    let ca = callers.caller(&h).await.unwrap();
    assert_eq!((ca.url_client_code.as_deref(), ca.url_app_code.as_deref(), ca.user.id), (Some("FIN"), Some("app1"), 5));
    h.insert("authorization", "Bearer bad".parse().unwrap());
    let e = callers.caller(&h).await.unwrap_err();
    assert_eq!((e.status(), overridable::write::messages::error_message(&e)), (StatusCode::UNAUTHORIZED, "bad token".into()));
    h.insert("authorization", "silent".parse().unwrap());
    let silent = callers.caller(&h).await.unwrap_err();
    assert_eq!(silent.status(), StatusCode::FORBIDDEN);
    assert!(matches!(&silent, AppError::Coded(c) if c.code == "COMMON.SIGNED_OUT"), "{silent:?}");
    // A coded refusal from Rust security passes on as it came.
    h.insert("authorization", "coded".parse().unwrap());
    let coded = callers.caller(&h).await.unwrap_err();
    assert_eq!(coded.status(), StatusCode::UNAUTHORIZED);
    assert!(matches!(&coded, AppError::Coded(c) if c.code == "SEC.UNKNOWN_TOKEN"), "{coded:?}");
    let nowhere = SecurityCallers { security: SecurityClient::new(Upstream::fixed(&["http://127.0.0.1:9"]), 0).unwrap(), server_port: 1 };
    assert_eq!(nowhere.caller(&HeaderMap::new()).await.unwrap_err().status(), StatusCode::INTERNAL_SERVER_ERROR);
    let mut fwd = HeaderMap::new();
    assert!(router::on_behalf(&fwd, &ca).is_none());
    for (k, v) in forwarded() {
        fwd.insert(k, v.parse().unwrap());
    }
    let ob = router::on_behalf(&fwd, &ca).unwrap();
    assert_eq!((ob.forwarded_host.as_str(), ob.client_code.as_str()), ("localhost", SYSTEM));
    let _ = Value::Null;
}
