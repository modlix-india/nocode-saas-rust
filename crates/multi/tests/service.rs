//! The routes against in-process fakes of security, core and ui: every path, success and
//! failure, without the local stack.

use std::io::{Cursor, Read, Write};
use std::sync::{Arc, Mutex};

use std::time::Duration;

use axum::body::{to_bytes, Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::middleware;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use base64::Engine;
use multi::service::{router, AppState};
use platform::security::SecurityClient;
use platform::upstream::Upstream;
use serde_json::{json, Value};
use tower::ServiceExt;

#[derive(Default)]
struct Fake {
    /// (method + path, body) of every call the fake received.
    calls: Mutex<Vec<(String, Vec<u8>)>>,
    authenticated: Mutex<bool>,
    system: Mutex<bool>,
    authorities: Mutex<Vec<String>>,
    write_access: Mutex<bool>,
    app_status: Mutex<String>,
    base_client: Mutex<Option<String>>,
    fail_core_index: Mutex<bool>,
    /// What core's createAndApply answers instead of success: a status and a body (sent as
    /// JSON unless empty).
    core_apply_error: Mutex<Option<(u16, String)>>,
    /// Security refuses the caller's credential (401 on the context call).
    refuse_credential: Mutex<bool>,
    /// ui's delete answers after two seconds.
    slow_ui_delete: Mutex<bool>,
}

type F = Arc<Fake>;

fn record(f: &F, what: &str, body: &[u8]) {
    f.calls.lock().unwrap().push((what.to_string(), body.to_vec()));
}

fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (n, b) in entries {
        out.start_file(*n, zip::write::SimpleFileOptions::default()).unwrap();
        out.write_all(b).unwrap();
    }
    out.finish().unwrap().into_inner()
}

fn fake_app() -> Router<F> {
    Router::new()
        .route(
            "/api/security/internal/securityContextAuthentication",
            get(|State(f): State<F>| async move {
                if *f.refuse_credential.lock().unwrap() {
                    return (StatusCode::UNAUTHORIZED, Json(json!({"message": "expired"}))).into_response();
                }
                let auth = *f.authenticated.lock().unwrap();
                let system = *f.system.lock().unwrap();
                Json(json!({
                    "authenticated": auth,
                    "clientCode": if system { "SYSTEM" } else { "FIN" },
                    "clientTypeCode": if system { "SYS" } else { "BUS" },
                    "accessToken": "Bearer tok",
                    "user": {"id": 7, "clientId": 3, "stringAuthorities": *f.authorities.lock().unwrap()}
                }))
                .into_response()
            }),
        )
        .route(
            "/api/security/applications/internal/hasWriteAccess",
            get(|State(f): State<F>| async move { Json(json!(*f.write_access.lock().unwrap())) }),
        )
        .route(
            "/api/security/transports/makeTransport",
            get(|State(f): State<F>, h: HeaderMap| async move {
                let header = |n: &str| h.get(n).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                record(&f, &format!("GET makeTransport auth={} lang={}", header("authorization"), header("accept-language")), b"");
                Json(json!({"name": "sec"}))
            }),
        )
        .route(
            "/api/core/transports/internal/makeTransport",
            post(|State(f): State<F>, b: Bytes| async move {
                record(&f, "POST core makeTransport", &b);
                zip_of(&[("transport.json", b"{}")])
            }),
        )
        .route(
            "/api/ui/transports/internal/makeTransport",
            post(|State(f): State<F>, b: Bytes| async move {
                record(&f, "POST ui makeTransport", &b);
                zip_of(&[("transport.json", b"{}")])
            }),
        )
        .route(
            "/api/ui/applications/internal/index/{app}",
            get(|Path(app): Path<String>| async move {
                Json(json!({"clientCode": "SYSTEM", "pages": [{"name": format!("{app}Home"), "id": "1", "version": 1}]}))
            }),
        )
        .route(
            "/api/core/index/internal/{app}",
            get(|State(f): State<F>| async move {
                if *f.fail_core_index.lock().unwrap() {
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
                Json(json!({"storages": [{"name": "lead", "id": "s", "version": 2}]})).into_response()
            }),
        )
        .route(
            "/api/security/applications",
            post(|State(f): State<F>, Json(b): Json<Value>| async move {
                record(&f, "POST createApp", b.to_string().as_bytes());
                Json(json!({"id": 99, "clientId": 3, "appCode": b["appCode"], "appName": b["appName"], "status": "ACTIVE", "template": false, "createdAt": 1}))
            }),
        )
        .route(
            "/api/security/applications/{id}",
            get(|Path(id): Path<String>, State(f): State<F>| async move {
                record(&f, &format!("GET app {id}"), b"");
                Json(json!({"id": id.parse::<u64>().unwrap_or(0), "appCode": "found", "status": *f.app_status.lock().unwrap(), "explicitClientId": null}))
            })
            .delete(|Path(id): Path<String>, State(f): State<F>| async move {
                record(&f, &format!("DELETE app {id}"), b"");
                Json(json!(true))
            }),
        )
        .route(
            "/api/security/applications/internal/appCode/{code}",
            get(|Path(code): Path<String>, State(f): State<F>| async move {
                if code == "missing" {
                    return (StatusCode::OK, "").into_response();
                }
                Json(json!({"id": 5, "appCode": code, "status": *f.app_status.lock().unwrap()})).into_response()
            }),
        )
        .route(
            "/api/security/applications/findBaseClientCode/{code}",
            get(|State(f): State<F>| async move {
                match f.base_client.lock().unwrap().clone() {
                    Some(c) => Json(json!([c, true])).into_response(),
                    None => (StatusCode::OK, "").into_response(),
                }
            }),
        )
        .route(
            "/api/security/transports/createAndApply",
            post(|State(f): State<F>, b: Bytes| async move {
                record(&f, "POST security createAndApply", &b);
                Json(json!(true))
            }),
        )
        .route(
            "/api/core/transports/internal/createAndApply",
            post(|State(f): State<F>, Query(q): Query<Vec<(String, String)>>, b: Bytes| async move {
                record(&f, &format!("POST core createAndApply {q:?}"), &b);
                if let Some((status, body)) = f.core_apply_error.lock().unwrap().clone() {
                    let status = StatusCode::from_u16(status).unwrap();
                    if body.is_empty() {
                        return status.into_response();
                    }
                    return (status, [("content-type", "application/json")], body).into_response();
                }
                Json(json!({"id": "t"})).into_response()
            }),
        )
        .route(
            "/api/ui/transports/internal/createAndApply",
            post(|State(f): State<F>, Query(q): Query<Vec<(String, String)>>, b: Bytes| async move {
                record(&f, &format!("POST ui createAndApply {q:?}"), &b);
                Json(json!({"id": "t"}))
            }),
        )
        .route(
            "/api/ui",
            delete(|State(f): State<F>| async move {
                record(&f, "DELETE ui", b"");
                let slow = *f.slow_ui_delete.lock().unwrap();
                if slow {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                Json(json!(true))
            }),
        )
        .route("/api/core", delete(|State(f): State<F>| async move { record(&f, "DELETE core", b""); Json(json!(true)) }))
        .route(
            "/api/security/applications/everything/{id}",
            delete(|State(f): State<F>| async move {
                record(&f, "DELETE everything", b"");
                Json(json!(true))
            }),
        )
        .route("/definition.json", get(|| async { Json(json!({"security": {}, "core": {"objects": []}, "ui": {"objects": []}})) }))
        .route("/missing.json", get(|| async { StatusCode::NOT_FOUND }))
        .route("/huge.json", get(|| async { vec![b' '; 50 * 1024 * 1024 + 1] }))
}

async fn setup() -> (Router, F, String) {
    let fake: F = Arc::new(Fake::default());
    *fake.authenticated.lock().unwrap() = true;
    *fake.system.lock().unwrap() = true;
    *fake.authorities.lock().unwrap() = vec!["Authorities.Application_CREATE".into()];
    *fake.write_access.lock().unwrap() = true;
    *fake.app_status.lock().unwrap() = "ACTIVE".into();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = fake_app().with_state(fake.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let up = Upstream::fixed(&[&base]);
    let state = AppState {
        security: SecurityClient::new(up.clone(), 0).unwrap(),
        security_up: up.clone(),
        core_up: up.clone(),
        ui_up: up,
        http: reqwest::Client::new(),
        port: 8110,
    };
    (app_of(state), fake, base)
}

/// The routes with the message scope the service runs them in (`platform::app::Service`).
fn app_of(state: AppState) -> Router {
    router(Arc::new(state)).layer(middleware::from_fn(platform::messages::layer))
}

/// The coded body's code, message and action.
fn coded(b: &[u8]) -> (String, String, Option<String>) {
    let v = json_of(b);
    assert_eq!(v["stackTrace"], "", "{v}");
    assert!(v["exceptionId"].as_str().is_some_and(|i| !i.is_empty()), "{v}");
    (v["code"].as_str().unwrap_or("").to_string(), v["message"].as_str().unwrap_or("").to_string(), v["action"].as_str().map(str::to_string))
}

fn req(method: &str, uri: &str, body: Option<Value>) -> Request<Body> {
    let b = Request::builder()
        .method(method)
        .uri(uri)
        .header("Authorization", "Bearer abc")
        .header("X-Forwarded-Host", "localhost")
        .header("X-Forwarded-Port", "8080")
        .header("clientCode", "SYSTEM")
        .header("appCode", "appbuilder")
        .header("x-debug", "dbg")
        .header("x-draft", "true");
    match body {
        Some(v) => b.header("content-type", "application/json").body(Body::from(v.to_string())).unwrap(),
        None => b.body(Body::empty()).unwrap(),
    }
}

async fn call(app: &Router, r: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
    let resp = app.clone().oneshot(r).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec();
    (status, headers, body)
}

fn json_of(b: &[u8]) -> Value {
    serde_json::from_slice(b).unwrap()
}

fn calls(f: &F) -> Vec<String> {
    f.calls.lock().unwrap().iter().map(|(c, _)| c.clone()).collect()
}

#[tokio::test]
async fn index_and_search() {
    let (app, fake, _) = setup().await;
    let (s, h, b) = call(&app, req("GET", "/api/multi/application/app1/index", None)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(h["cache-control"], "no-cache, no-store, max-age=0, must-revalidate");
    assert_eq!(h["referrer-policy"], "no-referrer");
    let v = json_of(&b);
    assert_eq!(v["count"], 2);
    assert_eq!(v["services"], json!({"ui": true, "core": true}));
    assert_eq!(v["clientCode"], "SYSTEM");

    let (_, _, b) = call(&app, req("GET", "/api/multi/application/app1/search?q=LEAD&type=storage&clientCode=FIN", None)).await;
    assert_eq!(json_of(&b)["count"], 1);

    *fake.fail_core_index.lock().unwrap() = true;
    let (s, _, b) = call(&app, req("GET", "/api/multi/application/app1/index", None)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(json_of(&b)["services"], json!({"ui": true, "core": false}));
}

#[tokio::test]
async fn anonymous_and_missing_headers() {
    let (app, fake, _) = setup().await;
    let r = Request::builder().uri("/api/multi/application/app1/index").body(Body::empty()).unwrap();
    *fake.authenticated.lock().unwrap() = false;
    let (s, h, b) = call(&app, r).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert!(h.get("www-authenticate").is_none(), "no Basic challenge");
    assert_eq!(h["x-frame-options"], "DENY");
    assert_eq!(h["content-type"], "application/json");
    assert_eq!(coded(&b), ("COMMON.SIGN_IN_REQUIRED".into(), "Please sign in to continue.".into(), None));

    // A token security turns down: signed out, whether security refuses it or says anonymous.
    let (s, _, b) = call(&app, req("GET", "/api/multi/application/app1/index", None)).await;
    assert_eq!((s, coded(&b).0), (StatusCode::UNAUTHORIZED, "COMMON.SIGNED_OUT".to_string()));
    *fake.refuse_credential.lock().unwrap() = true;
    let (s, _, b) = call(&app, req("GET", "/api/multi/application/app1/index", None)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(coded(&b).1, "You're signed out. Please sign in again.");
    assert!(json_of(&b)["debugMessage"].as_str().unwrap().contains("refused"));
    *fake.refuse_credential.lock().unwrap() = false;

    *fake.authenticated.lock().unwrap() = true;
    let r = Request::builder().uri("/api/multi/application/app1/index").header("clientCode", "SYSTEM").body(Body::empty()).unwrap();
    let (s, _, b) = call(&app, r).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (code, message, action) = coded(&b);
    assert_eq!((code.as_str(), message.as_str()), ("COMMON.HEADER_MISSING", "The request is missing the X-Forwarded-Host header."));
    assert_eq!(action.as_deref(), Some("Send the request through the gateway, which adds it, or add X-Forwarded-Host and try again."));
    assert_eq!(json_of(&b)["debugMessage"], "Required header 'X-Forwarded-Host' is not present.");

    // Query and path values that do not read are 400s too, after the caller and the headers.
    let (s, _, b) = call(&app, req("GET", "/api/multi/application/app1/index?type=a&type=b", None)).await;
    assert_eq!((s, coded(&b).0), (StatusCode::BAD_REQUEST, "COMMON.BAD_REQUEST".to_string()));
    let (s, _, b) = call(&app, req("GET", "/api/multi/application/%FF/index", None)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(coded(&b).0.starts_with("COMMON."), "{}", String::from_utf8_lossy(&b));
    let (s, _, _) = call(&app, req("DELETE", "/api/multi/application/%FF", None)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn transport_export_zip() {
    let (app, fake, _) = setup().await;
    let (s, h, b) = call(&app, req("GET", "/api/multi/application/transport?appCode=app1", None)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(h["content-type"], "application/zip");
    assert_eq!(h["content-disposition"], "inline; filename=app1_SYSTEM.modl");
    let mut z = zip::ZipArchive::new(Cursor::new(b)).unwrap();
    let mut sec = String::new();
    z.by_name("security.json").unwrap().read_to_string(&mut sec).unwrap();
    assert_eq!(json_of(sec.as_bytes()), json!({"name": "sec"}));
    assert!(z.by_name("core.cmodl").is_ok() && z.by_name("ui.umodl").is_ok());
    let c = calls(&fake);
    assert!(c.iter().any(|c| c == "GET makeTransport auth=Bearer tok lang="), "{c:?}");
    let core_body = fake.calls.lock().unwrap().iter().find(|(c, _)| c == "POST core makeTransport").unwrap().1.clone();
    assert_eq!(json_of(&core_body), json!({"appCode": "app1", "clientCode": "SYSTEM"}));

    // The caller's languages travel with the calls made for it.
    let mut r = req("GET", "/api/multi/application/transport?appCode=app1", None);
    r.headers_mut().insert("accept-language", "pt-BR,pt;q=0.9".parse().unwrap());
    call(&app, r).await;
    assert!(calls(&fake).iter().any(|c| c == "GET makeTransport auth=Bearer tok lang=pt-BR,pt;q=0.9"), "{:?}", calls(&fake));

    let (s, _, b) = call(&app, req("GET", "/api/multi/application/transport", None)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(coded(&b).1, "The request is missing the appCode parameter.");
    let (s, _, b) = call(&app, req("GET", "/api/multi/application/transport?appCode=a&appCode=b", None)).await;
    assert_eq!((s, coded(&b).0), (StatusCode::BAD_REQUEST, "COMMON.BAD_REQUEST".to_string()));

    *fake.system.lock().unwrap() = false;
    *fake.write_access.lock().unwrap() = false;
    let (s, _, b) = call(&app, req("GET", "/api/multi/application/transport?appCode=app1", None)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (code, message, action) = coded(&b);
    assert_eq!(code, "MULTI.TRANSPORT_EXPORT_FORBIDDEN");
    assert_eq!(message, "You can't export this app: your organisation does not have write access to it.");
    assert_eq!(action.as_deref(), Some("Ask the app's owner to give your organisation write access to it."));
    assert_eq!(json_of(&b)["debugMessage"], "[forbidden_create] Cannot create transport for the selected client (appCode=app1)");
}

#[tokio::test]
async fn create_by_id_and_new() {
    let (app, fake, base) = setup().await;
    let (s, _, b) = call(&app, req("POST", "/api/multi/application", Some(json!({"appId": 843})))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(json_of(&b), json!({"id": 843, "appCode": "found", "status": "ACTIVE", "template": false}));

    let def = json!({"appCode": "newapp", "appName": "New", "appType": "APP",
                     "transportDefinitionURL": format!("{base}/definition.json")});
    let (s, _, b) = call(&app, req("POST", "/api/multi/application", Some(def))).await;
    assert_eq!(s, StatusCode::OK);
    let v = json_of(&b);
    assert_eq!(v["appCode"], "newapp");
    assert!(v.get("createdAt").is_none(), "only App DTO fields");
    let c = calls(&fake);
    assert!(c.iter().any(|c| c.starts_with("POST core createAndApply") && c.contains("core.json") && c.contains("\"isForBaseApp\", \"true\"")), "{c:?}");
    let create = fake.calls.lock().unwrap().iter().find(|(c, _)| c == "POST createApp").unwrap().1.clone();
    assert_eq!(json_of(&create)["appAccessType"], "OWN");
    assert_eq!(json_of(&create)["clientId"], 3);

    // Bodies that do not read: named 400s.
    let (s, _, b) = call(&app, req("POST", "/api/multi/application", Some(json!({"appCode": 5})))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(coded(&b).1, "The value of appCode is not valid: it should be text.");
    let mut r = req("POST", "/api/multi/application", None);
    r.headers_mut().insert("content-type", "application/json".parse().unwrap());
    *r.body_mut() = Body::from("{nope");
    let (s, _, b) = call(&app, r).await;
    assert_eq!((s, coded(&b).0), (StatusCode::BAD_REQUEST, "COMMON.BODY_UNREADABLE".to_string()));
    let mut r = req("POST", "/api/multi/application", None);
    r.headers_mut().insert("content-type", "text/plain".parse().unwrap());
    *r.body_mut() = Body::from("{}");
    let (s, _, b) = call(&app, r).await;
    assert_eq!((s, coded(&b).0), (StatusCode::UNSUPPORTED_MEDIA_TYPE, "COMMON.BODY_NOT_JSON".to_string()));

    *fake.authorities.lock().unwrap() = vec![];
    let (s, _, b) = call(&app, req("POST", "/api/multi/application", Some(json!({"appCode": "x"})))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (code, message, action) = coded(&b);
    assert_eq!(code, "MULTI.APP_CREATE_FORBIDDEN");
    assert_eq!(message, "You can't create apps: your account does not have the Create applications permission.");
    assert_eq!(action.as_deref(), Some("Ask an owner of your organisation to give you the Create applications permission."));
    assert_eq!(json_of(&b)["debugMessage"], "[forbidden_create] Cannot create Application for the selected client (needs Authorities.Application_CREATE)");

    let r = Request::builder()
        .method("POST")
        .uri("/api/multi/application")
        .header("Authorization", "Bearer abc")
        .header("X-Forwarded-Host", "h")
        .header("X-Forwarded-Port", "1")
        .header("clientCode", "S")
        .header("appCode", "a")
        .body(Body::empty())
        .unwrap();
    let (s, _, b) = call(&app, r).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(coded(&b), ("COMMON.BODY_MISSING".into(), "The request has no body.".into(), Some("Send the details as JSON in the request body.".into())));
}

#[tokio::test]
async fn update_json_zip_and_encoded() {
    let (app, fake, _) = setup().await;
    // No definition at all.
    let (_, _, b) = call(&app, req("POST", "/api/multi/application/update", Some(json!({"appCode": "a"})))).await;
    assert_eq!(json_of(&b), json!(false));

    // JSON definition, no base client (null client code, as Java).
    let def = json!({"appCode": "a", "transportDefinition": {"security": {"x": 1}, "core": {"objects": [{"objectType": "Filler", "data": {}}]}, "ui": {"objects": []}}});
    let (s, _, b) = call(&app, req("POST", "/api/multi/application/update", Some(def))).await;
    assert_eq!((s, json_of(&b)), (StatusCode::OK, json!(true)));
    let core = fake.calls.lock().unwrap().iter().find(|(c, _)| c.starts_with("POST core createAndApply")).unwrap().1.clone();
    let core = json_of(&core);
    assert_eq!(core["clientCode"], Value::Null);
    assert_eq!(core["objects"][0]["data"]["name"], "a");

    // A zip (encoded), with a base client.
    *fake.base_client.lock().unwrap() = Some("FIN".into());
    let inner = zip_of(&[("Page/p.json", br#"{"name":"p","clientCode":"X","appCode":"y"}"#)]);
    let modl = zip_of(&[("security.json", br#"{"a":1}"#), ("core.cmodl", &inner), ("ui.umodl", &inner)]);
    let enc = base64::engine::general_purpose::STANDARD.encode(&modl);
    fake.calls.lock().unwrap().clear();
    let (s, _, b) = call(&app, req("POST", "/api/multi/application/update", Some(json!({"appCode": "a", "isBaseUpdate": false, "encodedModl": enc})))).await;
    assert_eq!((s, json_of(&b)), (StatusCode::OK, json!(true)));
    let (q, body) = fake.calls.lock().unwrap().iter().find(|(c, _)| c.starts_with("POST ui createAndApply")).cloned().unwrap();
    assert!(q.contains("ui.umodl") && q.contains("\"isJson\", \"false\"") && q.contains("\"isForBaseApp\", \"false\""), "{q}");
    let mut z = zip::ZipArchive::new(Cursor::new(body)).unwrap();
    let mut s = String::new();
    z.by_name("Page/p.json").unwrap().read_to_string(&mut s).unwrap();
    assert_eq!(json_of(s.as_bytes()), json!({"name": "p", "clientCode": "FIN", "appCode": "a"}));

    // Definitions that cannot be read.
    let update = |def: Value| req("POST", "/api/multi/application/update", Some(def));
    let enc = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    let (s, _, b) = call(&app, update(json!({"appCode": "a", "encodedModl": "%%%"}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(coded(&b).0, "MULTI.ENCODED_MODL_INVALID");
    assert!(json_of(&b)["debugMessage"].as_str().unwrap().starts_with("[multi_transport_error] Error while creating/updating application"));
    for broken in [enc(b"{nope"), enc(b"not a zip"), enc(&zip_of(&[("security.json", b"{}"), ("core.cmodl", b"not a zip"), ("ui.umodl", b"x")]))] {
        let (s, _, b) = call(&app, update(json!({"appCode": "a", "encodedModl": broken}))).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        let (code, message, _) = coded(&b);
        assert_eq!(code, "MULTI.DEFINITION_UNREADABLE");
        assert_eq!(message, "The app definition could not be read: it is neither a JSON definition nor an exported app file.");
    }

    // A downstream refusal: Java's JSON message relayed with its status.
    let def = json!({"appCode": "a", "transportDefinition": {"core": {"objects": []}}});
    *fake.core_apply_error.lock().unwrap() = Some((403, json!({"message": "Cannot create Transport for the selected client"}).to_string()));
    let (s, _, b) = call(&app, update(def.clone())).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(json_of(&b)["message"], "Cannot create Transport for the selected client");
    assert!(json_of(&b).get("code").is_none());

    // A Rust unit's coded refusal: passed on byte for byte.
    let sent = json!({"exceptionId": "2026-10-17-ab", "code": "CORE.FORBIDDEN_CREATE", "message": "You can't.", "action": "Ask.",
                      "params": {}, "locale": "en", "stackTrace": "", "debugMessage": "x"})
    .to_string();
    *fake.core_apply_error.lock().unwrap() = Some((403, sent.clone()));
    let (s, h, b) = call(&app, update(def.clone())).await;
    assert_eq!((s, h["content-type"].to_str().unwrap()), (StatusCode::FORBIDDEN, "application/json"));
    assert_eq!(String::from_utf8(b).unwrap(), sent);
    assert_eq!(h["x-frame-options"], "DENY");

    // Empty refusals, said by their status.
    for (status, code, message) in [
        (401, "COMMON.SIGNED_OUT", "You're signed out. Please sign in again."),
        (403, "COMMON.FORBIDDEN", "You don't have access to this."),
        (500, "MULTI.SERVICE_FAILED", "We couldn't finish the request: the core service did not answer as expected."),
        (404, "MULTI.SERVICE_FAILED", "We couldn't finish the request: the core service did not answer as expected."),
    ] {
        *fake.core_apply_error.lock().unwrap() = Some((status, String::new()));
        let (s, _, b) = call(&app, update(def.clone())).await;
        assert_eq!(s.as_u16(), status);
        let (c, m, _) = coded(&b);
        assert_eq!((c.as_str(), m.as_str()), (code, message));
        assert_eq!(json_of(&b)["debugMessage"], format!("core createAndApply answered {}", s));
    }
}

#[tokio::test]
async fn definition_addresses() {
    let (app, _, base) = setup().await;
    let update = |url: String| req("POST", "/api/multi/application/update", Some(json!({"appCode": "a", "transportDefinitionURL": url})));
    let (s, _, b) = call(&app, update(format!("{base}/missing.json"))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (code, message, action) = coded(&b);
    assert_eq!(code, "MULTI.DEFINITION_URL_FAILED");
    assert_eq!(message, "We couldn't download the app definition from its address: the address answered with status 404.");
    assert_eq!(action.as_deref(), Some("Check that the definition's address is right and can be reached, then try again."));
    let (s, _, b) = call(&app, update("http://127.0.0.1:1/x.json".into())).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(coded(&b).1, "We couldn't download the app definition from its address.");
    let (s, _, b) = call(&app, update(format!("{base}/huge.json"))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(coded(&b), ("MULTI.DEFINITION_TOO_LARGE".into(), "The app definition is too large: the limit is 50 MB.".into(), Some("Use a smaller definition and try again.".into())));
}

#[tokio::test]
async fn services_that_do_not_answer() {
    let (_, fake, base) = setup().await;
    let dead = Upstream::fixed(&["http://127.0.0.1:1"]);
    let up = Upstream::fixed(&[&base]);
    let state = |security: &Upstream, core: &Upstream, timeout: Option<Duration>| AppState {
        security: SecurityClient::new(security.clone(), 0).unwrap(),
        security_up: security.clone(),
        core_up: core.clone(),
        ui_up: up.clone(),
        http: timeout.map(|t| reqwest::Client::builder().timeout(t).build().unwrap()).unwrap_or_default(),
        port: 8110,
    };

    // Security unreachable: the caller cannot even be checked.
    let app = app_of(state(&dead, &up, None));
    let (s, _, b) = call(&app, req("GET", "/api/multi/application/app1/index", None)).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    let (code, message, action) = coded(&b);
    assert_eq!(code, "MULTI.SERVICE_UNAVAILABLE");
    assert_eq!(message, "The security service is not answering right now. Try again in a few seconds.");
    assert!(action.unwrap().starts_with("If it keeps happening, give support the error id "));

    // Core unreachable during an export.
    let app = app_of(state(&up, &dead, None));
    let (s, _, b) = call(&app, req("GET", "/api/multi/application/transport?appCode=app1", None)).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(coded(&b).1, "The core service is not answering right now. Try again in a few seconds.");

    // No answer in time: 504, same words.
    *fake.app_status.lock().unwrap() = "DELETED".into();
    *fake.slow_ui_delete.lock().unwrap() = true;
    let app = app_of(state(&up, &up, Some(Duration::from_millis(500))));
    let (s, _, b) = call(&app, req("DELETE", "/api/multi/application/someapp", None)).await;
    assert_eq!(s, StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(coded(&b).1, "The UI service is not answering right now. Try again in a few seconds.");
}

#[tokio::test]
async fn delete_soft_and_full() {
    let (app, fake, _) = setup().await;
    let (s, _, b) = call(&app, req("DELETE", "/api/multi/application/42", None)).await;
    assert_eq!((s, json_of(&b)), (StatusCode::OK, json!(true)));
    assert!(calls(&fake).contains(&"DELETE app 42".to_string()));

    *fake.app_status.lock().unwrap() = "DELETED".into();
    fake.calls.lock().unwrap().clear();
    let (_, _, b) = call(&app, req("DELETE", "/api/multi/application/someapp", None)).await;
    assert_eq!(json_of(&b), json!(true));
    assert_eq!(calls(&fake), vec!["DELETE ui", "DELETE core", "DELETE everything"]);

    let (_, _, b) = call(&app, req("DELETE", "/api/multi/application/missing", None)).await;
    assert_eq!(json_of(&b), json!(false));
}
