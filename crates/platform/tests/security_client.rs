//! `SecurityClient` against a scripted fake of the security service.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use platform::security::{
    CallerContext, ContextAuthentication, OnBehalfOf, RawAnswer, SecurityClient, SecurityRefusal, SecurityRefused,
};
use platform::upstream::Upstream;

#[derive(Default)]
struct Fake {
    /// path -> (status, content type, body)
    answers: Mutex<HashMap<String, (u16, String, String)>>,
    /// (path, query, headers)
    seen: Mutex<Vec<(String, String, HeaderMap)>>,
}

type F = Arc<Fake>;

async fn handle(State(f): State<F>, req: Request) -> Response {
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    f.seen.lock().unwrap().push((path.clone(), query, req.headers().clone()));
    match f.answers.lock().unwrap().get(&path).cloned() {
        Some((status, content_type, body)) => (
            StatusCode::from_u16(status).unwrap(),
            [("content-type", content_type)],
            body,
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn setup(cache_seconds: u64) -> (SecurityClient, F) {
    let f: F = Arc::new(Fake::default());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    let app = Router::new().fallback(handle).with_state(f.clone());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (SecurityClient::new(Upstream::fixed(&[&base]), cache_seconds).unwrap(), f)
}

fn answer(f: &F, path: &str, status: u16, body: &str) {
    answer_as(f, path, status, "application/json", body);
}

fn answer_as(f: &F, path: &str, status: u16, content_type: &str, body: &str) {
    f.answers
        .lock()
        .unwrap()
        .insert(path.to_string(), (status, content_type.to_string(), body.to_string()));
}

fn count(f: &F, path: &str) -> usize {
    f.seen.lock().unwrap().iter().filter(|(p, _, _)| p == path).count()
}

/// The query and headers of the latest request to `path`.
fn last(f: &F, path: &str) -> (String, HeaderMap) {
    let seen = f.seen.lock().unwrap();
    let (_, q, h) = seen.iter().rev().find(|(p, _, _)| p == path).expect("a request to the path");
    (q.clone(), h.clone())
}

/// The status and message a relayed refusal carries.
fn refusal(e: &anyhow::Error) -> (u16, Option<String>) {
    let status = e.downcast_ref::<SecurityRefused>().expect("a refusal, not a transport error").0;
    let message = e.downcast_ref::<SecurityRefusal>().expect("with security's message").message.clone();
    (status, message)
}

const CTX: &str = "/api/security/internal/securityContextAuthentication";

fn caller(token: &str, basic: bool) -> CallerContext {
    CallerContext {
        is_basic: basic,
        token: token.into(),
        client_code: Some("SYSTEM".into()),
        app_code: Some("appbuilder".into()),
        forwarded_host: "apps.local".into(),
        forwarded_port: "443".into(),
        debug: Some("tag-1".into()),
    }
}

#[tokio::test]
async fn context_authentication_sends_what_jwt_filter_sends() {
    let (sec, f) = setup(0).await;
    answer(
        &f,
        CTX,
        200,
        r#"{"authenticated":true,"clientCode":"SYSTEM","clientTypeCode":"SYS","accessToken":"Bearer x",
            "user":{"id":"142","clientId":1,"stringAuthorities":["Authorities.A"]}}"#,
    );
    let ca = sec.context_authentication(&caller("tok", false)).await.unwrap();
    assert!(ca.authenticated && ca.is_system_client());
    assert_eq!(ca.user.id, 142, "string ids are read too");
    assert_eq!(ca.url_app_code.as_deref(), Some("appbuilder"));
    assert_eq!(ca.access_token.as_deref(), Some("Bearer x"));
    let (_, _, h) = f.seen.lock().unwrap()[0].clone();
    assert_eq!(h["authorization"], "tok");
    assert_eq!(h["x-forwarded-host"], "apps.local");
    assert_eq!(h["x-forwarded-port"], "443");
    assert_eq!(h["clientcode"], "SYSTEM");
    assert_eq!(h["appcode"], "appbuilder");
    assert_eq!(h["x-debug"], "tag-1");

    sec.context_authentication(&caller("dXNlcjpw", true)).await.unwrap();
    let (_, _, h) = f.seen.lock().unwrap()[1].clone();
    assert_eq!(h["authorization"], "basic dXNlcjpw");

    // Anonymous: no Authorization header at all.
    sec.context_authentication(&caller("", false)).await.unwrap();
    let (_, _, h) = f.seen.lock().unwrap()[2].clone();
    assert!(h.get("authorization").is_none());

    // No cache configured: every call asks.
    sec.context_authentication(&caller("tok", false)).await.unwrap();
    assert_eq!(count(&f, CTX), 4);
}

#[tokio::test]
async fn refusals_and_bodies() {
    let (sec, f) = setup(0).await;
    answer(&f, CTX, 401, r#"{"message":"Unknown token"}"#);
    let err = sec.context_authentication(&caller("bad", false)).await.unwrap_err();
    let refused = err.downcast_ref::<SecurityRefused>().expect("a refusal, not a transport error");
    assert_eq!(refused.0, 401);
    assert!(err.to_string().contains("Unknown token"));

    answer(&f, CTX, 403, "");
    let err = sec.context_authentication(&caller("bad", false)).await.unwrap_err();
    assert!(err.to_string().contains("(no message)"));

    answer(&f, CTX, 200, "not json");
    assert!(sec.context_authentication(&caller("x", false)).await.is_err());
}

/// A Rust security unit's coded refusal rides along whole, so a unit can pass it on with its
/// code; the request's languages go to security so the texts it writes are the caller's.
#[tokio::test]
async fn coded_refusals_ride_along() {
    let (sec, f) = setup(0).await;
    let coded = r#"{"exceptionId":"e","message":"Your sign-in is no longer valid. Please sign in again.","stackTrace":"",
        "debugMessage":"[unknown_token] Unknown token","code":"SEC.UNKNOWN_TOKEN","params":{},"locale":"en"}"#;
    answer(&f, CTX, 401, coded);
    let mut h = HeaderMap::new();
    h.insert("accept-language", "pt-BR,pt;q=0.8".parse().unwrap());
    let scope = platform::messages::RequestScope::from_headers(&h);
    let err = platform::messages::scope::with_scope(scope, sec.context_authentication(&caller("bad", false))).await.unwrap_err();
    let (_, sent) = last(&f, CTX);
    assert_eq!(sent["accept-language"], "pt-BR, pt");
    let r = err.downcast_ref::<SecurityRefusal>().unwrap();
    assert_eq!(r.coded.as_ref().map(|c| c.code.to_string()).as_deref(), Some("SEC.UNKNOWN_TOKEN"));
    match platform::security::refusal_error(&err) {
        Some(platform::error::AppError::Coded(c)) => {
            assert_eq!(c.status, Some(StatusCode::UNAUTHORIZED));
            assert_eq!(c.debug.as_deref(), Some("[unknown_token] Unknown token"));
        }
        other => panic!("{other:?}"),
    }
    // Outside a request no language is sent.
    sec.context_authentication(&caller("bad", false)).await.unwrap_err();
    assert!(last(&f, CTX).1.get("accept-language").is_none());

    // The other security calls relay it too.
    answer(&f, CLIENT_BY_CODE, 403, coded);
    let err = sec.client_by_code("A").await.unwrap_err();
    assert!(err.downcast_ref::<SecurityRefusal>().unwrap().coded.is_some());
}

#[tokio::test]
async fn token_cache_when_configured() {
    let (sec, f) = setup(60).await;
    answer(&f, CTX, 200, r#"{"authenticated":true,"user":{"id":1}}"#);
    for _ in 0..3 {
        sec.context_authentication(&caller("tok", false)).await.unwrap();
    }
    assert_eq!(count(&f, CTX), 1, "signed-in answers are reused");

    answer(&f, CTX, 200, r#"{"authenticated":false}"#);
    for _ in 0..2 {
        sec.context_authentication(&caller("anon-but-token", false)).await.unwrap();
    }
    assert_eq!(count(&f, CTX), 3, "anonymous answers are not cached");
    for _ in 0..2 {
        sec.context_authentication(&caller("", false)).await.unwrap();
    }
    assert_eq!(count(&f, CTX), 5, "no token, no cache");
}

#[tokio::test]
async fn lookups() {
    let (sec, f) = setup(0).await;
    answer(&f, "/api/security/clients/internal/getClientByCode", 200, r#"{"id":12,"code":"FIN"}"#);
    assert_eq!(sec.client_id_by_code("FIN").await.unwrap(), Some(12));
    assert_eq!(sec.client_id_by_code("FIN").await.unwrap(), Some(12));
    assert_eq!(count(&f, "/api/security/clients/internal/getClientByCode"), 1, "cached");
    answer(&f, "/api/security/clients/internal/getClientByCode", 200, r#"{"id":"13"}"#);
    assert_eq!(sec.client_id_by_code("STR").await.unwrap(), Some(13));
    answer(&f, "/api/security/clients/internal/getClientByCode", 200, "");
    assert_eq!(sec.client_id_by_code("NONE").await.unwrap(), None);
    answer(&f, "/api/security/clients/internal/getClientByCode", 500, "{}");
    assert!(sec.client_id_by_code("ERR").await.is_err());

    answer(&f, "/api/security/clients/internal/isUserClientManageClient", 200, "true");
    assert!(sec.is_user_client_manage_client(Some("app"), 1, 2, Some(3)).await.unwrap());
    assert!(sec.is_user_client_manage_client(None, 1, 2, None).await.unwrap());
    let q = f.seen.lock().unwrap().iter().rev().find(|(p, _, _)| p.ends_with("isUserClientManageClient")).unwrap().1.clone();
    assert!(!q.contains("targetClientId"));

    answer(&f, "/api/security/clients/internal/validateClientCode", 200, "false");
    assert_eq!(sec.valid_client_code("X").await.unwrap(), Some(false));
    answer(&f, "/api/security/clients/internal/validateClientCode", 200, "");
    assert_eq!(sec.valid_client_code("X").await.unwrap(), None);

    answer(&f, "/api/security/clients/internal/getClientById", 200, r#"{"id":1,"code":"SYSTEM"}"#);
    assert_eq!(sec.client_by_id(1).await.unwrap().unwrap()["code"], "SYSTEM");
    answer(&f, "/api/security/users/internal/7", 200, r#"{"id":7}"#);
    assert_eq!(sec.user_internal(7).await.unwrap().unwrap()["id"], 7);
    answer(&f, "/api/security/users/internal/8", 200, "");
    assert!(sec.user_internal(8).await.unwrap().is_none());

    answer(&f, "/api/security/applications/internal/appCode/my%20app", 200, r#"{"appCode":"my app"}"#);
    assert_eq!(sec.app_by_code("my app").await.unwrap().unwrap()["appCode"], "my app");

    answer(&f, "/api/security/clients/internal/clientHierarchyCodes", 200, r#"["A","B"]"#);
    assert_eq!(sec.client_hierarchy_codes("A").await.unwrap(), vec!["A", "B"]);
    answer(&f, "/api/security/clients/internal/clientHierarchyCodes", 200, r#"{"x":1}"#);
    assert!(sec.client_hierarchy_codes("A").await.unwrap().is_empty());

    answer(&f, "/api/security/internal/billing/instructions", 200, r#"{"rate":1}"#);
    assert_eq!(sec.billing_instructions("files.gb").await.unwrap()["rate"], 1);
    answer(&f, "/api/security/internal/billing/charge", 200, r#"{"ok":true}"#);
    assert_eq!(sec.billing_charge("{}".into()).await.unwrap()["ok"], true);
    answer(&f, "/api/security/internal/billing/charge", 200, "");
    assert!(sec.billing_charge("{}".into()).await.unwrap().is_null());
    answer(&f, "/api/security/internal/billing/charge", 500, "{}");
    assert!(sec.billing_charge("{}".into()).await.is_err());

    answer(&f, "/api/security/applications/internal/hasWriteAccess", 200, "true");
    assert!(sec.has_write_access("a", "C").await.unwrap());
    answer(&f, "/api/security/clients/internal/doesClientManageClientCode", 200, "false");
    assert!(!sec.does_client_manage_client_code("A", "B").await.unwrap());

    answer(&f, "/api/security/applications/internal/appInheritance", 200, r#"["SYSTEM","FIN"]"#);
    assert_eq!(sec.app_inheritance("a", "FIN", "FIN").await.unwrap(), vec!["SYSTEM", "FIN"]);
    answer(&f, "/api/security/applications/internal/appStatus/a", 200, "ACTIVE");
    assert_eq!(sec.app_status("a").await.unwrap().as_deref(), Some("ACTIVE"));
    answer(&f, "/api/security/applications/internal/appStatus/b", 200, "");
    assert_eq!(sec.app_status("b").await.unwrap(), None);
    answer(&f, "/api/security/applications/internal/hasReadAccess", 200, "true");
    assert!(sec.has_read_access("a", "C").await.unwrap());
    answer(&f, "/api/security/applications/internal/dependencies", 200, r#"["dep"]"#);
    assert_eq!(sec.app_dependencies("a").await.unwrap(), vec!["dep"]);
    answer(&f, "/api/security/applications/internal/explicitInfo/a", 200, r#"{"appCode":"a"}"#);
    assert_eq!(sec.app_explicit_info("a").await.unwrap()["appCode"], "a");
}

#[tokio::test]
async fn unreachable_security_is_an_error() {
    let sec = SecurityClient::new(Upstream::fixed(&["http://127.0.0.1:1"]), 0).unwrap();
    assert!(sec.context_authentication(&caller("t", false)).await.is_err());
    assert!(sec.has_write_access("a", "b").await.is_err());
    let err = sec.client_by_code("FIN").await.unwrap_err();
    assert!(err.downcast_ref::<SecurityRefused>().is_none(), "no answer is not a refusal");
    assert!(sec.has_delete_access(&on_behalf(None), "a", "b").await.is_err());
}

#[tokio::test]
async fn a_refused_member_moves_the_call_to_the_next() {
    // The first member refuses every connection; each kind of call still lands, once, on the
    // second (a GET with the caller's headers, a POST with its body, a plain-text read).
    let (base, f) = fake().await;
    let sec = SecurityClient::new(Upstream::fixed(&["http://127.0.0.1:1", &base]), 0).unwrap();
    answer(&f, CTX, 200, r#"{"authenticated":true,"clientCode":"SYSTEM"}"#);
    answer(&f, "/api/security/clients/internal/activeClientCodes", 200, r#"["FIN"]"#);
    answer_as(&f, "/api/security/applications/internal/appStatus/a", 200, "text/plain", "ACTIVE");
    answer(&f, CLIENT_BY_CODE, 200, r#"{"id":7}"#);
    for _ in 0..2 {
        assert!(sec.context_authentication(&caller("tok", false)).await.unwrap().authenticated);
        let codes = vec!["FIN".to_string()];
        assert_eq!(sec.active_client_codes(&codes).await.unwrap(), ["FIN"]);
        assert_eq!(sec.app_status("a").await.unwrap().as_deref(), Some("ACTIVE"));
        assert_eq!(sec.client_by_code("FIN").await.unwrap().unwrap()["id"], 7);
    }
    assert_eq!(count(&f, CTX), 2);
    let (_, h) = last(&f, CTX);
    assert_eq!((h["authorization"].to_str().unwrap(), h["x-debug"].to_str().unwrap()), ("tok", "tag-1"));
    let seen = f.seen.lock().unwrap();
    assert_eq!(seen.iter().filter(|(p, _, _)| p.ends_with("activeClientCodes")).count(), 2);
}

#[tokio::test]
async fn active_client_codes_posts_the_codes() {
    let (c, f) = setup(0).await;
    answer(&f, "/api/security/clients/internal/activeClientCodes", 200, r#"["FIN"]"#);
    let codes = vec!["FIN".to_string(), "GONE".to_string()];
    assert_eq!(c.active_client_codes(&codes).await.unwrap(), ["FIN"]);
    assert_eq!(count(&f, "/api/security/clients/internal/activeClientCodes"), 1);
    answer(&f, "/api/security/clients/internal/activeClientCodes", 200, "");
    assert!(c.active_client_codes(&codes).await.unwrap().is_empty());
    answer(&f, "/api/security/clients/internal/activeClientCodes", 500, "{}");
    assert!(c.active_client_codes(&codes).await.is_err());
}

const HOSTING: &str = "/api/security/internal/billing/hosting";
const HOST: &str = "/api/security/clients/internal/getClientNAppCodeNType";
const CLIENT_BY_CODE: &str = "/api/security/clients/internal/getClientByCode";

#[tokio::test]
async fn hosting_check_relays_refusals() {
    let (sec, f) = setup(0).await;
    // As the local security answers it.
    answer(&f, HOSTING, 200, r#"{"suspended":false,"serveAppCode":"appbuilder","serveClientCode":"SYSTEM"}"#);
    let h = sec.billing_hosting("appbuilder", "SYSTEM").await.unwrap().unwrap();
    assert_eq!((h["suspended"].as_bool(), h["serveClientCode"].as_str()), (Some(false), Some("SYSTEM")));
    assert_eq!(last(&f, HOSTING).0, "urlAppCode=appbuilder&urlClientCode=SYSTEM");

    answer(&f, HOSTING, 200, "");
    assert!(sec.billing_hosting("a", "C").await.unwrap().is_none(), "an empty answer is None");
    answer(&f, HOSTING, 200, "{not json");
    let err = sec.billing_hosting("a", "C").await.unwrap_err();
    assert!(err.downcast_ref::<SecurityRefused>().is_none(), "a bad body is not a refusal");
    answer(&f, HOSTING, 403, r#"{"message":"Hosting is suspended"}"#);
    let err = sec.billing_hosting("a", "C").await.unwrap_err();
    assert_eq!(refusal(&err), (403, Some("Hosting is suspended".into())));
}

#[tokio::test]
async fn host_lookup() {
    let (sec, f) = setup(0).await;
    // The Java Tuple3, written as an array, as the local security answers an unknown host.
    answer(&f, HOST, 200, r#"[ "SYSTEM", "nothing", "LIVE" ]"#);
    let t = sec.client_n_app_code_n_type("http", "apps.local", "8080").await.unwrap();
    assert_eq!(t, Some(("SYSTEM".into(), "nothing".into(), "LIVE".into())));
    assert_eq!(last(&f, HOST).0, "scheme=http&host=apps.local&port=8080");

    answer(&f, HOST, 200, r#"["FIN", 7]"#);
    let t = sec.client_n_app_code_n_type("https", "fin.example", "443").await.unwrap();
    assert_eq!(t, Some(("FIN".into(), String::new(), String::new())), "missing or non-text parts read as empty");
    answer(&f, HOST, 200, "");
    assert_eq!(sec.client_n_app_code_n_type("http", "h", "80").await.unwrap(), None);
    answer(&f, HOST, 200, "oops");
    assert!(sec.client_n_app_code_n_type("http", "h", "80").await.is_err());
    answer(&f, HOST, 500, r#"{"message":"boom"}"#);
    let err = sec.client_n_app_code_n_type("http", "h", "80").await.unwrap_err();
    assert_eq!(refusal(&err), (500, Some("boom".into())));
}

#[tokio::test]
async fn acme_token() {
    let (sec, f) = setup(0).await;
    answer_as(&f, "/api/security/ssl/token/abc-_.~9", 200, "text/plain;charset=UTF-8", "abc.thumbprint");
    assert_eq!(sec.ssl_token("abc-_.~9").await.unwrap().as_deref(), Some("abc.thumbprint"));

    // The token is one escaped path segment, as Feign expands a @PathVariable.
    let escaped = "/api/security/ssl/token/a%20b%2Fc%C3%A9";
    answer_as(&f, escaped, 200, "text/plain;charset=UTF-8", "");
    assert_eq!(sec.ssl_token("a b/cé").await.unwrap(), None, "an unknown token is an empty 200");
    assert_eq!(count(&f, escaped), 1);

    answer_as(&f, "/api/security/ssl/token/x", 500, "text/plain", "down");
    let err = sec.ssl_token("x").await.unwrap_err();
    assert_eq!(refusal(&err), (500, None), "a non-JSON error carries no message");
}

#[tokio::test]
async fn one_time_token_login() {
    let (sec, f) = setup(0).await;
    let path = "/api/security/authenticateWithOneTimeToken/t%2B1";
    answer(&f, path, 200, r#"{"authenticated":true,"accessToken":"abc"}"#);
    let v = sec
        .authenticate_with_one_time_token("t+1", Some("apps.local"), Some("SYSTEM"), Some("appbuilder"), "10.0.0.1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(v["accessToken"], "abc");
    let h = last(&f, path).1;
    assert_eq!(h["x-real-ip"], "10.0.0.1");
    assert_eq!(h["x-forwarded-host"], "apps.local");
    assert_eq!(h["clientcode"], "SYSTEM");
    assert_eq!(h["appcode"], "appbuilder");

    // Feign leaves out the headers it has no value for.
    sec.authenticate_with_one_time_token("t+1", None, None, None, "10.0.0.2").await.unwrap();
    let h = last(&f, path).1;
    assert_eq!(h["x-real-ip"], "10.0.0.2");
    assert!(h.get("x-forwarded-host").is_none() && h.get("clientcode").is_none() && h.get("appcode").is_none());

    answer(&f, path, 200, "");
    assert!(sec.authenticate_with_one_time_token("t+1", None, None, None, "ip").await.unwrap().is_none());
    answer(&f, path, 200, "nope");
    let err = sec.authenticate_with_one_time_token("t+1", None, None, None, "ip").await.unwrap_err();
    assert!(err.downcast_ref::<SecurityRefused>().is_none());
    answer(&f, path, 401, r#"{"message":"Token expired"}"#);
    let err = sec.authenticate_with_one_time_token("t+1", None, None, None, "ip").await.unwrap_err();
    assert_eq!(refusal(&err), (401, Some("Token expired".into())));
}

#[tokio::test]
async fn client_by_code_relays_errors_as_controller_advice_does() {
    let (sec, f) = setup(0).await;
    answer(&f, CLIENT_BY_CODE, 200, r#"{"id":1,"code":"SYSTEM","timeZone":"Asia/Kolkata"}"#);
    assert_eq!(sec.client_by_code("SYSTEM").await.unwrap().unwrap()["timeZone"], "Asia/Kolkata");
    assert_eq!(sec.client_by_code("SYSTEM").await.unwrap().unwrap()["id"], 1);
    assert_eq!(count(&f, CLIENT_BY_CODE), 2, "the record is not cached, unlike the id");
    assert_eq!(last(&f, CLIENT_BY_CODE).0, "clientCode=SYSTEM");

    answer(&f, CLIENT_BY_CODE, 200, "");
    assert!(sec.client_by_code("NONE").await.unwrap().is_none());
    answer(&f, CLIENT_BY_CODE, 200, "[");
    assert!(sec.client_by_code("BAD").await.is_err());

    answer(&f, CLIENT_BY_CODE, 404, r#"{"message":"Unknown client information requested"}"#);
    let err = sec.client_by_code("GONE").await.unwrap_err();
    assert_eq!(refusal(&err), (404, Some("Unknown client information requested".into())));
    assert!(format!("{err:#}").contains("Unknown client information requested"));

    // ControllerAdvice.handleFeignException: a JSON error without a message relays an empty one;
    // a body that is not JSON, or a content type other than exactly application/json, is not
    // read at all.
    answer(&f, CLIENT_BY_CODE, 400, r#"{"eid":"x"}"#);
    assert_eq!(refusal(&sec.client_by_code("A").await.unwrap_err()), (400, Some(String::new())));
    answer(&f, CLIENT_BY_CODE, 502, "<html>");
    assert_eq!(refusal(&sec.client_by_code("A").await.unwrap_err()), (502, None));
    answer_as(&f, CLIENT_BY_CODE, 503, "application/json;charset=UTF-8", r#"{"message":"m"}"#);
    assert_eq!(refusal(&sec.client_by_code("A").await.unwrap_err()), (503, None));
}

#[test]
fn raw_answer_success_range() {
    let raw = |status| RawAnswer { status, content_type: None, body: bytes::Bytes::new() };
    assert!(raw(200).is_success() && raw(204).is_success() && raw(299).is_success());
    assert!(!raw(199).is_success() && !raw(300).is_success() && !raw(404).is_success());
    let err = raw(304).into_error();
    assert_eq!(refusal(&err), (304, None));
    assert!(err.to_string().contains("(no message)"));
}

fn on_behalf(token: Option<&str>) -> OnBehalfOf {
    OnBehalfOf {
        access_token: token.map(str::to_string),
        forwarded_host: "apps.local".into(),
        forwarded_port: "443".into(),
        client_code: "SYSTEM".into(),
        app_code: "appbuilder".into(),
    }
}

#[tokio::test]
async fn delete_access_on_the_callers_behalf() {
    let (sec, f) = setup(0).await;
    let path = "/api/security/applications/hasDeleteAccess";
    answer(&f, path, 200, "true");
    assert!(sec.has_delete_access(&on_behalf(Some("Bearer t")), "app1", "FIN").await.unwrap());
    let (q, h) = last(&f, path);
    assert_eq!(q, "deleteAppCode=app1&deleteClientCode=FIN");
    assert_eq!(h["authorization"], "Bearer t");
    assert_eq!(h["x-forwarded-host"], "apps.local");
    assert_eq!(h["x-forwarded-port"], "443");
    assert_eq!(h["clientcode"], "SYSTEM");
    assert_eq!(h["appcode"], "appbuilder");

    // A missing or empty token sends no Authorization header, as Feign drops a null one.
    for token in [None, Some("")] {
        sec.has_delete_access(&on_behalf(token), "a", "C").await.unwrap();
        assert!(last(&f, path).1.get("authorization").is_none());
    }
    assert!(OnBehalfOf::default().access_token.is_none());

    for (body, expected) in [("false", false), ("", false), (r#"{"x":1}"#, false)] {
        answer(&f, path, 200, body);
        assert_eq!(sec.has_delete_access(&on_behalf(None), "a", "C").await.unwrap(), expected, "{body:?}");
    }
    answer(&f, path, 200, "yes");
    assert!(sec.has_delete_access(&on_behalf(None), "a", "C").await.is_err());
    answer(&f, path, 403, r#"{"message":"Forbidden"}"#);
    let err = sec.has_delete_access(&on_behalf(None), "a", "C").await.unwrap_err();
    assert_eq!(refusal(&err), (403, Some("Forbidden".into())));
}

#[tokio::test]
async fn base_client_code_for_override() {
    let (sec, f) = setup(0).await;
    let path = "/api/security/applications/findBaseClientCode/my%20app";
    // The Java Tuple2<String, Boolean>, written as an array.
    answer(&f, path, 200, r#"["SYSTEM",true]"#);
    let r = sec.find_base_client_code_for_override(&on_behalf(Some("tok")), "my app").await.unwrap();
    assert_eq!(r, Some(("SYSTEM".into(), true)));
    let h = last(&f, path).1;
    assert_eq!((h["authorization"].to_str().unwrap(), h["clientcode"].to_str().unwrap()), ("tok", "SYSTEM"));

    answer(&f, path, 200, r#"["FIN"]"#);
    let r = sec.find_base_client_code_for_override(&on_behalf(None), "my app").await.unwrap();
    assert_eq!(r, Some(("FIN".into(), false)), "a missing flag is false");
    for body in [r#"[null,true]"#, "[]", ""] {
        answer(&f, path, 200, body);
        assert_eq!(sec.find_base_client_code_for_override(&on_behalf(None), "my app").await.unwrap(), None, "{body:?}");
    }
    answer(&f, path, 200, "x");
    assert!(sec.find_base_client_code_for_override(&on_behalf(None), "my app").await.is_err());
    answer(&f, path, 401, r#"{"message":"Not signed in"}"#);
    let err = sec.find_base_client_code_for_override(&on_behalf(None), "my app").await.unwrap_err();
    assert_eq!(refusal(&err), (401, Some("Not signed in".into())));
}

#[tokio::test]
async fn odd_answers() {
    let (sec, f) = setup(0).await;
    answer(&f, "/api/security/applications/internal/appStatus/a", 500, "{}");
    assert!(sec.app_status("a").await.is_err(), "a failed status lookup is an error, not unknown");
    answer(&f, "/api/security/clients/internal/activeClientCodes", 200, r#"{"x":1}"#);
    assert!(sec.active_client_codes(&["FIN".to_string()]).await.unwrap().is_empty());

    // No credentials at all: an anonymous caller with no token.
    let c = CallerContext::from_headers(&HeaderMap::new(), 8003);
    assert_eq!((c.is_basic, c.token.as_str(), c.forwarded_host.as_str(), c.forwarded_port.as_str()), (false, "", "", "8003"));

    // Ids that are neither numbers nor strings read as 0.
    let ca: ContextAuthentication = serde_json::from_str(r#"{"user":{"id":null,"clientId":true}}"#).unwrap();
    assert_eq!((ca.user.id, ca.user.client_id, ca.client_code()), (0, 0, ""));
    let ca: ContextAuthentication = serde_json::from_str(r#"{"clientCode":"FIN"}"#).unwrap();
    assert_eq!(ca.client_code(), "FIN");
}

/// A fake listening on its own port, for the split between security and security-auth.
async fn fake() -> (String, F) {
    let f: F = Arc::new(Fake::default());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    let app = Router::new().fallback(handle).with_state(f.clone());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (base, f)
}

#[tokio::test]
async fn auth_upstream_takes_the_authentication_controller_calls() {
    let (main_base, main) = fake().await;
    let (auth_base, auth) = fake().await;
    let cfg = platform::config::SecurityConfig {
        upstream: platform::config::UpstreamConfig::One(main_base.clone()),
        auth_upstream: platform::config::UpstreamConfig::Many(vec![auth_base.clone()]),
        auth_cache_seconds: 0,
        ..Default::default()
    };
    let sec = SecurityClient::from_config(&cfg, None).unwrap();
    answer(&auth, CTX, 200, r#"{"authenticated":false,"clientCode":"SYSTEM"}"#);
    let ott = "/api/security/authenticateWithOneTimeToken/t1";
    answer(&auth, ott, 200, r#"{"accessToken":"a"}"#);
    answer(&main, "/api/security/clients/internal/getClientByCode", 200, r#"{"id":1}"#);

    sec.context_authentication(&caller("", false)).await.unwrap();
    sec.authenticate_with_one_time_token("t1", None, None, None, "ip").await.unwrap();
    assert_eq!(sec.client_id_by_code("SYSTEM").await.unwrap(), Some(1));
    assert_eq!((count(&auth, CTX), count(&auth, ott)), (1, 1));
    assert_eq!((count(&main, CTX), count(&main, ott)), (0, 0));
    assert_eq!(count(&main, "/api/security/clients/internal/getClientByCode"), 1);
    assert_eq!(count(&auth, "/api/security/clients/internal/getClientByCode"), 0);

    // Without an auth upstream every call goes to security.
    let cfg = platform::config::SecurityConfig { auth_upstream: Default::default(), ..cfg };
    let sec = SecurityClient::from_config(&cfg, None).unwrap();
    answer(&main, CTX, 200, r#"{"authenticated":false}"#);
    sec.context_authentication(&caller("", false)).await.unwrap();
    assert_eq!(count(&main, CTX), 1);

    // A registry name needs the registry.
    let cfg = platform::config::SecurityConfig {
        auth_upstream: platform::config::UpstreamConfig::One("eureka:SECURITY-AUTH".into()),
        ..cfg
    };
    assert!(SecurityClient::from_config(&cfg, None).is_err());
}

#[tokio::test]
async fn internal_upstream_takes_the_internal_calls() {
    let (main_base, main) = fake().await;
    let (auth_base, auth) = fake().await;
    let (internal_base, internal) = fake().await;
    let cfg = platform::config::SecurityConfig {
        upstream: platform::config::UpstreamConfig::One(main_base.clone()),
        auth_upstream: platform::config::UpstreamConfig::One(auth_base.clone()),
        internal_upstream: platform::config::UpstreamConfig::One(internal_base.clone()),
        auth_cache_seconds: 0,
    };
    let sec = SecurityClient::from_config(&cfg, None).unwrap();
    answer(&auth, CTX, 200, r#"{"authenticated":false}"#);
    answer(&internal, "/api/security/clients/internal/getClientByCode", 200, r#"{"id":1}"#);
    answer(&internal, "/api/security/applications/internal/appStatus/a", 200, "ACTIVE");
    answer(&main, "/api/security/ssl/token/x", 200, "proof");
    sec.context_authentication(&caller("", false)).await.unwrap();
    assert_eq!(sec.client_id_by_code("SYSTEM").await.unwrap(), Some(1));
    assert_eq!(sec.app_status("a").await.unwrap().as_deref(), Some("ACTIVE"));
    assert_eq!(sec.ssl_token("x").await.unwrap().as_deref(), Some("proof"));
    assert_eq!((count(&auth, CTX), count(&internal, CTX), count(&main, CTX)), (1, 0, 0));
    assert_eq!(count(&internal, "/api/security/clients/internal/getClientByCode"), 1);
    assert_eq!(count(&main, "/api/security/clients/internal/getClientByCode"), 0);
    assert_eq!(count(&main, "/api/security/ssl/token/x"), 1);

    // The same routing for callers that build their own requests.
    let up = platform::security::security_upstream(&cfg, None).unwrap();
    assert_eq!(up.base_for("/api/security/users/internal/5?x=1").await.unwrap(), internal_base);
    assert_eq!(up.base_for("/api/security/internal/securityContextAuthentication").await.unwrap(), auth_base);
    assert_eq!(up.base_for("/api/security/users/query").await.unwrap(), main_base);
    assert_eq!(up.base().await.unwrap(), main_base);
    // Without one, internal calls stay on security.
    let plain = platform::security::security_upstream(&platform::config::SecurityConfig { internal_upstream: Default::default(), ..cfg.clone() }, None).unwrap();
    assert_eq!(plain.base_for("/api/security/users/internal/5").await.unwrap(), main_base);
}

#[test]
fn route_classes_follow_the_split() {
    use platform::security::{is_auth_route, is_internal_route};
    for p in [
        "/api/security/authenticate",
        "/api/security/authenticateWithOneTimeToken/abc",
        "/api/security/internal/securityContextAuthentication?x=1",
        "/api/security/internal/makeOneTimeToken",
        "/api/security/internal/tokens/cleanup",
        "/api/security/revoke",
        "/api/security/verifyToken",
        "/api/security/user/access",
    ] {
        assert!(is_auth_route(p), "{p}");
        assert!(!is_internal_route(p), "{p}");
    }
    for p in [
        "/api/security/clients/internal",
        "/api/security/clients/internal/getClientNAppCodeNType?scheme=http",
        "/api/security/users/internal/5",
        "/api/security/users/internal/clients/batch",
        "/api/security/users/internal/5/sub-org",
        "/api/security/app/profiles/internal/users",
        "/api/security/internal/billing/charge",
        "/api/security/internal/cache/x",
        "/api/security/ssl/internal/certificates",
        "/api/security/clienturls/internal/draft/token/resolve",
    ] {
        assert!(is_internal_route(p), "{p}");
        assert!(!is_auth_route(p), "{p}");
    }
    for p in [
        "/api/security/users/query",
        "/api/security/ssl/internal/renew-certificates",
        "/api/security/clients/internal/managedClient",
        "/api/security/clients/internal/clients/denorm/delta",
        "/api/security/users/internal/clients",
        "/api/security/users/internal/recordAudience",
        "/api/security/users/internal/5/processor",
        "/api/security/designations/internal/3",
        "/api/security/departments/internal",
        "/api/security/app/profiles/internal",
        "/api/security/app/profiles/internal/7",
        "/api/security/authenticateWithOneTimeTokenX",
    ] {
        assert!(!is_internal_route(p) && !(is_auth_route(p) && p.contains("Token")), "{p}");
    }
}

#[test]
fn auth_upstream_from_toml_and_environment() {
    figment::Jail::expect_with(|jail| {
        #[derive(Debug, serde::Serialize, serde::Deserialize, Default)]
        #[serde(default)]
        struct C {
            security: platform::config::SecurityConfig,
        }
        jail.create_dir("config")?;
        jail.create_file("config/split.toml", "[security]\nupstream = \"eureka:SECURITY\"\n")?;
        jail.set_env("MODLIX__SECURITY__AUTH_UPSTREAM", "http://localhost:8101");
        jail.set_env("MODLIX__SECURITY__INTERNAL_UPSTREAM", "http://localhost:8112");
        let c: C = platform::config::load("split").map_err(|e| e.to_string())?;
        assert_eq!(c.security.auth_upstream.entries(), vec!["http://localhost:8101"]);
        assert_eq!(c.security.internal_upstream.entries(), vec!["http://localhost:8112"]);
        assert_eq!(c.security.upstream.entries(), vec!["eureka:SECURITY"]);
        Ok(())
    });
}
