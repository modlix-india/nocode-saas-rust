//! The connections wiring, the integration functions and the connection routes, against
//! in-process stand-ins: documents in memory, a recording publisher, fake security and fake
//! outbound targets (REST, SendGrid, OpenAI). Nothing leaves the machine and nothing reaches
//! the local RabbitMQ.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::Path;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Router;
use connections::connection::ConnectionStore;
use connections::email::TemplateStore;
use connections::error::{ConnError, ConnResult};
use connections::tokens::{CoreToken, TokenStore, TokenType};
use connections::mq::EventMessage;
use connections::notification::{HierarchyChecks, NotificationRequest};
use connections::rest::auth::AuthTokenFunction;
use connections::rest::call::DownloadSink;
use kirun::function::Function;
use overridable::{JMap, JValue};
use parking_lot::Mutex;
use platform::upstream::Upstream;
use serde_json::{json, Map, Value};

use crate::clients::SecurityCalls;
use crate::error::CoreError;
use crate::functions::security_world::{run, user, World};
use crate::integrations::*;
use crate::storage::service::EventSink;
use crate::testing::serve;

fn jmap(v: Value) -> JMap {
    match overridable::json::parse(v.to_string().as_bytes()).unwrap() {
        JValue::Object(m) => m,
        _ => panic!("not an object"),
    }
}

#[derive(Default)]
pub struct MemoryDocs {
    pub connections: Mutex<HashMap<String, JMap>>,
    pub templates: Mutex<HashMap<String, JMap>>,
    pub fail: Mutex<bool>,
}

impl MemoryDocs {
    fn add_connection(&self, v: Value) {
        let name = v["name"].as_str().unwrap().to_string();
        self.connections.lock().insert(name, jmap(v));
    }
}

#[async_trait]
impl DocSource for MemoryDocs {
    async fn connection(&self, name: &str, _: &str, _: &str, _: &str) -> Result<Option<JMap>, CoreError> {
        if *self.fail.lock() {
            return Err(CoreError::new(StatusCode::FORBIDDEN, "no access"));
        }
        Ok(self.connections.lock().get(name).cloned())
    }
    async fn template(&self, name: &str, _: &str, _: &str) -> Result<Option<JMap>, CoreError> {
        if *self.fail.lock() {
            return Err(CoreError::unknown("store down"));
        }
        Ok(self.templates.lock().get(name).cloned())
    }
}

#[derive(Default)]
pub struct Recording {
    pub sent: Mutex<Vec<(String, String, Value, String)>>,
    pub fail: Mutex<bool>,
}

#[async_trait]
impl Publish for Recording {
    async fn publish(&self, exchange: &str, routing_key: &str, body: &str, type_id: &str) -> Result<(), CoreError> {
        if *self.fail.lock() {
            return Err(CoreError::unknown("AMQP connection failed"));
        }
        self.sent.lock().push((exchange.into(), routing_key.into(), serde_json::from_str(body).unwrap(), type_id.into()));
        Ok(())
    }
}

#[derive(Default)]
struct Files {
    created: Mutex<Vec<(String, String, bool, String, String, usize)>>,
}

#[async_trait]
impl FileCreate for Files {
    async fn create(&self, file_type: &str, client_code: &str, o: bool, path: &str, name: &str, bytes: Vec<u8>) -> Result<Option<Map<String, Value>>, CoreError> {
        self.created.lock().push((file_type.into(), client_code.into(), o, path.into(), name.into(), bytes.len()));
        Ok(Some(json!({"name": name, "url": format!("/api/files/{file_type}/{client_code}{path}/{name}")}).as_object().unwrap().clone()))
    }
}

/// `core_tokens` in memory.
#[derive(Default)]
pub struct MemoryTokens {
    pub rows: Mutex<Vec<CoreToken>>,
}

#[async_trait]
impl TokenStore for MemoryTokens {
    async fn active_access_token_tuple(&self, c: &str, a: &str, n: &str) -> ConnResult<Option<(Option<String>, Option<chrono::NaiveDateTime>)>> {
        Ok(self.active_token(c, a, n, TokenType::Access).await?.map(|t| (t.token, t.expires_at)))
    }
    async fn active_token(&self, c: &str, a: &str, n: &str, ty: TokenType) -> ConnResult<Option<CoreToken>> {
        Ok(self.rows.lock().iter().find(|t| {
            t.client_code.as_deref() == Some(c) && t.app_code.as_deref() == Some(a) && t.connection_name.as_deref() == Some(n)
                && t.token_type == Some(ty) && t.is_revoked != Some(true) && t.token.is_some()
        }).cloned())
    }
    async fn by_state(&self, state: Option<&str>) -> ConnResult<Option<CoreToken>> {
        Ok(self.rows.lock().iter().find(|t| state.is_some() && t.state.as_deref() == state).cloned())
    }
    async fn consent_row(&self, c: &str, a: &str, n: &str, state: &str) -> ConnResult<Option<CoreToken>> {
        Ok(self.rows.lock().iter().filter(|t| {
            t.client_code.as_deref() == Some(c) && t.app_code.as_deref() == Some(a) && t.connection_name.as_deref() == Some(n)
                && t.state.as_deref() == Some(state)
        }).min_by_key(|t| t.id).cloned())
    }
    async fn revoke(&self, c: &str, a: &str, n: &str, _: Option<TokenType>) -> ConnResult<bool> {
        let mut any = false;
        for t in self.rows.lock().iter_mut() {
            if t.client_code.as_deref() == Some(c) && t.app_code.as_deref() == Some(a) && t.connection_name.as_deref() == Some(n) {
                t.is_revoked = Some(true);
                any = true;
            }
        }
        Ok(any)
    }
    async fn create(&self, token: &CoreToken) -> ConnResult<CoreToken> {
        let mut t = token.clone();
        t.id = Some(self.rows.lock().len() as u64 + 1);
        self.rows.lock().push(t.clone());
        Ok(t)
    }
    async fn update(&self, token: &CoreToken) -> ConnResult<Option<CoreToken>> {
        let mut rows = self.rows.lock();
        match rows.iter_mut().find(|t| t.id == token.id) {
            Some(t) => {
                *t = token.clone();
                Ok(Some(t.clone()))
            }
            None => Ok(None),
        }
    }
}

/// REST targets, SendGrid and OpenAI.
async fn outside() -> (String, Arc<Mutex<Vec<String>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s1 = seen.clone();
    let s2 = seen.clone();
    let s3 = seen.clone();
    let router = Router::new()
        .route("/rest/ok", get(|h: HeaderMap| async move {
            let auth = h.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
            ([("content-type", "application/json"), ("x-a", "1")], json!({"a": 1, "auth": auth}).to_string())
        }).post(|body: String| async move { ([("content-type", "application/json")], body) }))
        .route("/rest/fail", get(|| async { (StatusCode::NOT_FOUND, [("content-type", "application/json")], r#"{"error":"none"}"#) }))
        .route("/rest/file.pdf", get(|| async { ([("content-type", "application/pdf")], vec![1u8, 2, 3]) }))
        .route("/sendgrid", post(move |body: String| {
            let s = s1.clone();
            async move {
                s.lock().push(format!("sendgrid {body}"));
                StatusCode::ACCEPTED
            }
        }))
        .route("/openai/chat/completions", post(move |h: HeaderMap, body: String| {
            let s = s2.clone();
            async move {
                s.lock().push(format!("openai {} {body}", h.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("")));
                if body.contains("fail") {
                    return (StatusCode::BAD_REQUEST, r#"{"error":{"message":"bad prompt"}}"#).into_response();
                }
                Json(json!({"choices": [{"message": {"content": "hello there"}}]})).into_response()
            }
        }))
        .route("/oauth/token", post(|| async {
            Json(json!({"access_token": "at1", "refresh_token": "rt1", "expires_in": 3600}))
        }))
        .route("/files/{rest}", get(move |Path(rest): Path<String>| {
            let s = s3.clone();
            async move {
                s.lock().push(rest);
                ""
            }
        }));
    (serve(router).await, seen)
}

use axum::Json;

struct Setup {
    integrations: Arc<Integrations>,
    docs: Arc<MemoryDocs>,
    published: Arc<Recording>,
    files: Arc<Files>,
    world: Arc<World>,
    seen: Arc<Mutex<Vec<String>>>,
    target: String,
    security_base: String,
    tokens: Arc<MemoryTokens>,
}

async fn setup() -> Setup {
    let world = World::new();
    let security_base = world.serve().await;
    let (target, seen) = outside().await;
    let docs = Arc::new(MemoryDocs::default());
    let published = Arc::new(Recording::default());
    let files = Arc::new(Files::default());
    let mut cfg = crate::config::CoreConfig::default();
    cfg.connections.block_private_targets = false;
    cfg.connections.sendgrid_url = format!("{target}/sendgrid");
    cfg.connections.openai_base_url = format!("{target}/openai");
    let mq = Arc::new(Mq::with(published.clone(), &cfg.mq));
    let tokens = Arc::new(MemoryTokens::default());
    let cache = platform::cache::CacheService::new("cmn", "evictionChannel", None).unwrap();
    let security = Arc::new(SecurityCalls::new(Upstream::fixed(&[&security_base])).unwrap());
    let integrations = Arc::new(
        Integrations::new(&cfg, docs.clone(), security, tokens.clone(), cache, mq, Some(files.clone() as Arc<dyn FileCreate>)).unwrap(),
    );
    Setup { integrations, docs, published, files, world, seen, target, security_base, tokens }
}

fn fin() -> crate::auth::Authentication {
    user(110, 7, "FIN", &[])
}

fn find(fns: &[Arc<dyn Function>], name: &str) -> Arc<dyn Function> {
    crate::functions::security_world::find(fns, name)
}

// --- the wiring ------------------------------------------------------------------------------

#[tokio::test]
async fn the_caller_comes_from_the_request_context() {
    let outside = caller();
    assert!(!outside.present && !outside.in_kirun);
    let ctx = crate::testing::request(crate::testing::user(&["Authorities.X"]), true, Some("dbg"));
    crate::context::with_request(ctx, crate::context::with_run(Default::default(), async {
        let c = caller();
        assert!(c.present && c.authenticated && c.in_kirun && c.draft && c.system_client);
        assert_eq!((c.user_id, c.user_client_id), (Some(142), Some(1)));
        assert_eq!((c.client_code.as_deref(), c.url_client_code.as_deref(), c.url_app_code.as_deref()), (Some("SYSTEM"), Some("SYSTEM"), Some("appbuilder")));
        assert_eq!(c.debug.as_deref(), Some("dbg"));
        assert_eq!(c.authorities, ["Authorities.X"]);
    }))
    .await;
}

#[test]
fn errors_cross_both_ways() {
    let e = core_error(ConnError::new(StatusCode::NOT_FOUND, "missing"));
    assert_eq!((e.status(), e.text()), (StatusCode::NOT_FOUND, "missing".to_string()));
    let e = core_error(ConnError::Feign { status: 409, message: "taken".into(), body: None });
    assert_eq!(e.status(), StatusCode::CONFLICT);
    let e = core_error(ConnError::Feign { status: -1, message: "gone".into(), body: None });
    assert_eq!(e.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(core_error(ConnError::other("x")).status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(conn_error(CoreError::new(StatusCode::FORBIDDEN, "no")).status(), StatusCode::FORBIDDEN);
    assert_eq!(conn_error(CoreError::unknown("boom")).message(), "boom");
    let nf = CoreError::ObjectNotFound { status: StatusCode::NOT_FOUND, message: "nf".into(), code: None };
    assert_eq!(conn_error(nf).status(), StatusCode::NOT_FOUND);
    // Codes cross both ways; another unit's coded refusal is relayed with its code.
    let coded = conn_error(CoreError::coded(StatusCode::FORBIDDEN, "CORE.MESSAGE_APP_FORBIDDEN", "Not allowed to message for app x"));
    assert_eq!(coded.code().map(|c| c.code.to_string()).as_deref(), Some("CORE.MESSAGE_APP_FORBIDDEN"));
    assert_eq!(core_error(coded).code().map(|c| c.code.to_string()).as_deref(), Some("CORE.MESSAGE_APP_FORBIDDEN"));
    let body = serde_json::json!({"exceptionId": "e", "message": "You can't do this.", "debugMessage": "[forbidden_permission] Permission/Role User READ is required to use this operation", "code": "SEC.FORBIDDEN_PERMISSION"});
    let e = core_error(ConnError::Feign { status: 403, message: "Forbidden".into(), body: Some(body) });
    assert_eq!(e.text(), "Permission/Role User READ is required to use this operation");
    assert!(e.code().unwrap().is_relayed());
}

#[tokio::test]
async fn documents_are_read_for_the_library() {
    let s = setup().await;
    s.docs.add_connection(json!({"name": "m", "connectionType": "MAIL", "connectionSubType": "SMTP", "connectionDetails": {"mail.smtp.host": "h"}, "version": 3}));
    s.docs.templates.lock().insert("t".into(), jmap(json!({"name": "t", "templateParts": {"en": {"subject": "S"}}, "toExpression": "x"})));
    let c = s.integrations.connection_docs.read_internal("m", "a", "b", "c").await.unwrap().unwrap();
    assert_eq!(c.detail_str("mail.smtp.host"), Some("h"));
    assert!(s.integrations.connection_docs.read_internal("none", "a", "b", "c").await.unwrap().is_none());
    let t = s.integrations.templates.read("t", "a", "b").await.unwrap().unwrap();
    assert_eq!(t.to_expression.as_deref(), Some("x"));
    assert!(s.integrations.templates.read("none", "a", "b").await.unwrap().is_none());
    *s.docs.fail.lock() = true;
    assert_eq!(s.integrations.connection_docs.read_internal("m", "a", "b", "c").await.unwrap_err().status(), StatusCode::FORBIDDEN);
    assert!(s.integrations.templates.read("t", "a", "b").await.is_err());
    // A document the library cannot read.
    *s.docs.fail.lock() = false;
    s.docs.add_connection(json!({"name": "bad", "connectionType": 5}));
    assert!(s.integrations.connection_docs.read_internal("bad", "a", "b", "c").await.is_err());
}

#[tokio::test]
async fn hierarchy_checks_and_downloads_ask_security() {
    let s = setup().await;
    s.world.answer("GET", "/api/security/clients/internal/isUserPartOfHierarchy", 200, "true");
    s.world.set_manages_code(|m, c| m == "FIN" && c == "BP1");
    let checks = s.integrations.checks.as_ref();
    assert!(checks.is_user_part_of_hierarchy(5, "FIN").await.unwrap());
    assert_eq!(s.world.last("/api/security/clients/internal/isUserPartOfHierarchy").raw_query, "userId=5&clientCode=FIN");
    assert!(checks.does_client_manage_client(7, 90).await.unwrap());
    assert!(!checks.does_client_manage_client(55, 90).await.unwrap());
    assert!(checks.does_client_manage_client_code("FIN", "BP1").await.unwrap());
    s.world.answer("GET", "/api/security/clients/internal/isUserPartOfHierarchy", 200, "");
    assert!(!checks.is_user_part_of_hierarchy(5, "FIN").await.unwrap());
    s.world.answer("GET", "/api/security/clients/internal/isUserPartOfHierarchy", 500, r#"{"message":"down"}"#);
    assert_eq!(checks.is_user_part_of_hierarchy(5, "FIN").await.unwrap_err().message(), "down");

    let d = s.integrations.downloads.as_ref().unwrap();
    assert!(d.does_client_manage_client_code("FIN", "BP1").await.unwrap());
    let f = d.create_file("secured", "FIN", true, "/x", "a.pdf", vec![1, 2]).await.unwrap();
    assert_eq!(f["name"], "a.pdf");
    assert_eq!(s.files.created.lock()[0], ("secured".into(), "FIN".into(), true, "/x".into(), "a.pdf".into(), 2));
}

#[tokio::test]
async fn auth_functions_need_core_running() {
    let a = AuthFunctions::default();
    assert_eq!(a.execute(Some("A"), "b", None, None).await.unwrap_err().message(), "core is not running");
}

#[tokio::test]
async fn publishers() {
    let mut cfg = crate::config::MqSection::default();
    cfg.enabled = false;
    cfg.uri = Some("amqp://u:p@127.0.0.1:1/%2f".into());
    let off = Mq::from_config(&cfg);
    assert!(off.publisher.publish("events", "events1", "{}", "t").await.is_ok());
    cfg.enabled = true;
    let on = Mq::from_config(&cfg);
    // Nothing listens on port 1: the failure is the broker's, not a publish to a real exchange.
    let e = on.publisher.publish("rs-scratch-events", "k", "{}", "t").await.unwrap_err();
    assert_eq!(e.status(), StatusCode::INTERNAL_SERVER_ERROR);
    cfg.uri = None;
    assert!(Mq::from_config(&cfg).publisher.publish("x", "y", "{}", "t").await.is_ok());

    let rec = Arc::new(Recording::default());
    let mq = Mq::with(rec.clone(), &crate::config::MqSection::default());
    let ctx = crate::testing::request(crate::testing::user(&[]), true, Some("dbg"));
    let sent = crate::context::with_request(ctx, async {
        mq.create_event(&caller(), EventMessage { event_name: Some("E".into()), app_code: Some("a".into()), ..Default::default() }).await
    })
    .await
    .unwrap();
    assert!(sent);
    let (exchange, key, body, type_id) = rec.sent.lock()[0].clone();
    assert_eq!((exchange.as_str(), key.as_str(), type_id.as_str()), ("events", "events2", connections::mq::EVENT_TYPE_ID));
    assert_eq!((body["eventName"].clone(), body["draft"].clone(), body["xdebug"].clone()), (json!("E"), json!(true), json!("dbg")));
    *rec.fail.lock() = true;
    assert!(mq.create_event(&caller(), EventMessage::default()).await.is_err());

    // Storage events go to the same exchange with the operation's data.
    *rec.fail.lock() = false;
    let events = MqEvents { mq: Arc::new(Mq::with(rec.clone(), &crate::config::MqSection::default())) };
    let mut data = appdata::value::Document::new();
    data.insert("data".into(), appdata::value::Value::from_json(&json!({"n": 1})));
    assert!(events.create_event("app", "SYSTEM", "Storage.s.CREATE", data).await.unwrap());
    let (_, _, body, _) = rec.sent.lock().last().unwrap().clone();
    assert_eq!((body["eventName"].clone(), body["appCode"].clone(), body["data"]["data"]["n"].clone()), (json!("Storage.s.CREATE"), json!("app"), json!(1)));
}

// --- the functions ---------------------------------------------------------------------------

fn all(i: &Arc<Integrations>, catalog: Arc<dyn crate::storage::defs::Catalog>) -> Vec<Arc<dyn Function>> {
    use crate::functions::integration_fns as f;
    let mut v = f::rest(i);
    // A files service nobody answers on: only the attachment test reads files.
    let files = Arc::new(crate::files_calls::FilesCalls::new(Upstream::fixed(&["http://127.0.0.1:1"])).unwrap());
    v.extend(f::email(i, &files));
    v.extend(f::create_event(i, &catalog));
    v.extend(f::notification(i));
    v.extend(f::ai(i));
    v
}

#[tokio::test]
async fn rest_requests() {
    let s = setup().await;
    let fns = all(&s.integrations, crate::testing::MemoryCatalog::with(Vec::new()));
    s.docs.add_connection(json!({"name": "rest", "appCode": "leadzumptwo", "clientCode": "FIN", "connectionType": "REST_API",
                                 "connectionSubType": "REST_API_BASIC", "connectionDetails": {"baseUrl": s.target, "userName": "u", "password": "p"}}));
    let get_request = find(&fns, "GetRequest");
    let r = run(get_request.as_ref(), json!({"connectionName": "rest", "url": "/rest/ok"}), fin(), true, true).await.unwrap();
    assert_eq!(r["statusCode"], 200);
    // Gson reads the body's numbers as doubles.
    assert_eq!(r["data"]["a"], json!(1.0));
    assert!(r["data"]["auth"].as_str().unwrap().starts_with("Basic "));
    assert_eq!(r["headers"]["x-a"], "1");
    // Outside a definition too (REST does not ask for the context key).
    let r = run(get_request.as_ref(), json!({"connectionName": "rest", "url": "/rest/ok"}), fin(), false, true).await.unwrap();
    assert_eq!(r["statusCode"], 200);

    let call = find(&fns, "CallRequest");
    let r = run(call.as_ref(), json!({"connectionName": "rest", "url": "/rest/ok", "methodName": "POST", "payload": {"x": [1]}, "headers": {"h": "1"}}), fin(), true, true)
        .await
        .unwrap();
    assert_eq!(r["data"], json!({"x": [1.0]}));
    let post = find(&fns, "PostRequest");
    let r = run(post.as_ref(), json!({"connectionName": "rest", "url": "/rest/ok", "payload": "text", "queryParams": {"q": "1"}, "pathParams": {"p": "x"}}), fin(), true, true).await;
    assert!(r.is_ok());
    // Errors are events, not failures.
    let r = run(get_request.as_ref(), json!({"connectionName": "rest", "url": "/rest/fail"}), fin(), true, true).await.unwrap();
    assert_eq!((r["statusCode"].clone(), r["data"].clone()), (json!(404), json!({"error": "none"})));
    let r = run(get_request.as_ref(), json!({"connectionName": "none", "url": "/rest/ok"}), fin(), true, true).await.unwrap();
    assert_eq!(r["statusCode"], 500);
    // A header value that is not a string fails the call.
    let r = run(get_request.as_ref(), json!({"connectionName": "rest", "url": "/rest/ok", "headers": {"h": {"x": 1}}}), fin(), true, true).await;
    assert_eq!(r.unwrap_err().status(), StatusCode::INTERNAL_SERVER_ERROR);

    // A download goes to files, as the caller's client.
    let r = run(
        get_request.as_ref(),
        json!({"connectionName": "rest", "url": "/rest/file.pdf", "downloadAsAFile": true, "fileName": "doc", "fileLocation": "/in", "fileType": "secured", "fileOverride": true}),
        fin(),
        true,
        true,
    )
    .await
    .unwrap();
    assert_eq!(r["data"]["name"], "doc.pdf");
    assert_eq!(s.files.created.lock().last().unwrap().clone(), ("secured".into(), "FIN".into(), true, "/in".into(), "doc.pdf".into(), 3));
    // An anonymous caller downloads nothing: Java's chain completes empty.
    let r = run(get_request.as_ref(), json!({"connectionName": "rest", "url": "/rest/file.pdf", "downloadAsAFile": true}), crate::functions::security_world::anonymous(7, "FIN"), true, true).await;
    assert_eq!(r.unwrap_err().status(), StatusCode::NOT_FOUND);
    // A webhook or event run stores it, always as a secured file of the run's own client.
    let client = json!({"id": 7, "code": "FIN"});
    for auth in [
        crate::events::webhook_authentication(Some("leadzumptwo"), Some("FIN"), &client).unwrap(),
        crate::events::anonymous_authentication(Some("leadzumptwo"), Some("FIN"), &client).unwrap(),
    ] {
        let args = json!({"connectionName": "rest", "url": "/rest/file.pdf", "downloadAsAFile": true, "fileName": "rec", "fileLocation": "/calls", "fileType": "static"});
        let r = run(get_request.as_ref(), args, auth, true, true).await.unwrap();
        assert_eq!(r["data"]["name"], "rec.pdf");
        assert_eq!(s.files.created.lock().last().unwrap().clone(), ("secured".into(), "FIN".into(), false, "/calls".into(), "rec.pdf".into(), 3));
    }
    // The connections crate names the same authorities core's run contexts carry.
    assert_eq!(connections::rest::call::WEBHOOK_AUTHORITY, crate::events::WEBHOOK_AUTHORITY);
    assert_eq!(connections::rest::call::EVENT_RUNNER_AUTHORITY, crate::events::EVENT_RUNNER_AUTHORITY);
    for name in ["PutRequest", "PatchRequest", "DeleteRequest"] {
        assert_eq!(find(&fns, name).get_signature().get_namespace(), "CoreServices.REST");
    }
}

#[tokio::test]
async fn send_email_and_chat() {
    let s = setup().await;
    let fns = all(&s.integrations, crate::testing::MemoryCatalog::with(Vec::new()));
    s.docs.add_connection(json!({"name": "mail", "appCode": "leadzumptwo", "clientCode": "FIN", "connectionType": "MAIL",
                                 "connectionSubType": "SENDGRID", "connectionDetails": {"apiKey": "k"}}));
    s.docs.templates.lock().insert(
        "welcome".into(),
        jmap(json!({"name": "welcome", "templateParts": {"en": {"subject": "Hi ${name}", "body": "<p>${name}</p>"}},
                    "fromExpression": "from@x.com", "toExpression": "${email}"})),
    );
    // A default language without an expression is the language (Java failed on it).
    s.docs.templates.lock().insert(
        "nolang".into(),
        jmap(json!({"name": "nolang", "templateParts": {"en": {"subject": "S"}}, "defaultLanguage": "en", "toExpression": "${email}"})),
    );
    let send = find(&fns, "SendEmail");
    let args = json!({"connectionName": "mail", "templateName": "welcome", "templateData": {"name": "Asha", "email": "a@x.com"}});
    let r = run(send.as_ref(), args.clone(), fin(), false, true).await;
    assert_eq!(r.unwrap_err().text(), "Context does not contain key: KIRun Runtime");
    let r = run(send.as_ref(), args.clone(), fin(), true, true).await.unwrap();
    assert_eq!(r["sent"], json!(true));
    let sent = s.seen.lock().iter().find(|l| l.starts_with("sendgrid")).cloned().unwrap();
    assert!(sent.contains("a@x.com") && sent.contains("Hi Asha"), "{sent}");
    let r = run(send.as_ref(), json!({"connectionName": "mail", "templateName": "nolang", "templateData": {"email": "a@x.com"}}), fin(), true, true).await;
    assert_eq!(r.unwrap()["sent"], json!(true));
    // An unknown template is the template's 404.
    let r = run(send.as_ref(), json!({"connectionName": "mail", "templateName": "none"}), fin(), true, true).await;
    assert_eq!(r.unwrap_err().status(), StatusCode::NOT_FOUND);

    s.docs.add_connection(json!({"name": "ai", "appCode": "leadzumptwo", "clientCode": "FIN", "connectionType": "AI",
                                 "connectionSubType": "OPENAI", "connectionDetails": {"apiKey": "sk-test"}}));
    let chat = find(&fns, "Chat");
    let r = run(chat.as_ref(), json!({"connectionName": "ai", "prompt": "hi"}), fin(), true, true).await.unwrap();
    assert_eq!(r["response"], "hello there");
    assert!(s.seen.lock().iter().any(|l| l.starts_with("openai Bearer sk-test")));
    // A failure is the error event (then an empty response).
    let r = run(chat.as_ref(), json!({"connectionName": "none", "prompt": "hi"}), fin(), true, true).await.unwrap();
    assert_eq!(r["error"], "Connection details missing none");
    assert_eq!(run(chat.as_ref(), json!({"connectionName": "ai", "prompt": "hi"}), fin(), false, true).await.unwrap_err().status(), StatusCode::INTERNAL_SERVER_ERROR);
}

/// A files service holding one secured PDF for FIN, recording who read what.
async fn attachment_files() -> (String, Arc<Mutex<Vec<String>>>) {
    let reads: Arc<Mutex<Vec<String>>> = Default::default();
    let r = reads.clone();
    let router = Router::new().route(
        "/api/files/internal/{resourceType}/convertToBase64",
        get(move |Path(kind): Path<String>, axum::extract::RawQuery(q): axum::extract::RawQuery| {
            let r = r.clone();
            async move {
                let q = q.unwrap_or_default();
                r.lock().push(format!("{kind} {q}"));
                if kind == "secured" && q.contains("url=%2Fapi%2Ffiles%2Fsecured%2Ffile%2FFIN%2Finvoices%2FMay.pdf") {
                    "data:application/pdf;name:May.pdf;base64,JVBERi0x".into_response()
                } else {
                    StatusCode::OK.into_response()
                }
            }
        }),
    );
    (serve(router).await, reads)
}

#[tokio::test]
async fn send_email_with_attachments() {
    let s = setup().await;
    let (files_base, reads) = attachment_files().await;
    let files = Arc::new(crate::files_calls::FilesCalls::new(Upstream::fixed(&[&files_base])).unwrap());
    let fns = crate::functions::integration_fns::email(&s.integrations, &files);
    s.docs.add_connection(json!({"name": "mail", "appCode": "leadzumptwo", "clientCode": "FIN", "connectionType": "MAIL",
                                 "connectionSubType": "SENDGRID", "connectionDetails": {"apiKey": "k"}}));
    s.docs.templates.lock().insert(
        "welcome".into(),
        jmap(json!({"name": "welcome", "templateParts": {"en": {"subject": "Hi ${name}", "body": "<p>${name}</p>"}},
                    "fromExpression": "from@x.com", "toExpression": "${email}"})),
    );
    let send = find(&fns, "SendEmail");
    let args = json!({"connectionName": "mail", "templateName": "welcome", "templateData": {"name": "Asha", "email": "a@x.com"},
                      "attachments": ["/api/files/secured/file/FIN/invoices/May.pdf", {"content": "aGk=", "name": "notes.txt"}]});
    let r = run(send.as_ref(), args, fin(), true, true).await.unwrap();
    assert_eq!(r["sent"], json!(true));
    // Read as the caller's client, with the metadata.
    let read = reads.lock().clone();
    assert_eq!(read.len(), 1);
    assert!(read[0].starts_with("secured clientCode=FIN&") && read[0].ends_with("&metadataRequired=true"), "{read:?}");
    let sent = s.seen.lock().iter().find(|l| l.starts_with("sendgrid")).cloned().unwrap();
    assert!(
        sent.ends_with(r#""attachments":[{"content":"JVBERi0x","type":"application/pdf","filename":"May.pdf","disposition":"attachment"},{"content":"aGk=","type":"text/plain","filename":"notes.txt","disposition":"attachment"}]}"#),
        "{sent}"
    );
    // A file the files service does not give is the send's error; nothing more is posted.
    let before = s.seen.lock().len();
    let args = json!({"connectionName": "mail", "templateName": "welcome", "templateData": {"name": "A", "email": "a@x.com"},
                      "attachments": ["/api/files/secured/file/OTHER/x.pdf"]});
    let e = run(send.as_ref(), args, fin(), true, true).await.unwrap_err();
    assert_eq!(e.text(), "Unable to send the email: Attachment not found: /api/files/secured/file/OTHER/x.pdf");
    assert_eq!(s.seen.lock().len(), before);
    // Not a stored file.
    let args = json!({"connectionName": "mail", "templateName": "welcome", "templateData": {"email": "a@x.com"},
                      "attachments": ["https://example.com/x.pdf"]});
    let e = run(send.as_ref(), args, fin(), true, true).await.unwrap_err();
    assert_eq!(e.text(), "Unable to send the email: Attachment is not a stored file: https://example.com/x.pdf");
}

#[tokio::test]
async fn send_email_with_cc_and_bcc() {
    let s = setup().await;
    let (files_base, _) = attachment_files().await;
    let files = Arc::new(crate::files_calls::FilesCalls::new(Upstream::fixed(&[&files_base])).unwrap());
    let fns = crate::functions::integration_fns::email(&s.integrations, &files);
    s.docs.add_connection(json!({"name": "mail", "appCode": "leadzumptwo", "clientCode": "FIN", "connectionType": "MAIL",
                                 "connectionSubType": "SENDGRID", "connectionDetails": {"apiKey": "k"}}));
    s.docs.templates.lock().insert(
        "welcome".into(),
        jmap(json!({"name": "welcome", "templateParts": {"en": {"subject": "Hi ${name}", "body": "<p>${name}</p>"}},
                    "fromExpression": "from@x.com", "toExpression": "${email}"})),
    );
    let send = find(&fns, "SendEmail");
    // A string (as a step passes one) and an array; a copy already in `to` and a BCC already in CC are dropped.
    let args = json!({"connectionName": "mail", "templateName": "welcome", "templateData": {"name": "Asha", "email": "a@x.com"},
                      "cc": "ops@x.com, A@x.com", "bcc": ["audit@x.com; ops@x.com", null]});
    let r = run(send.as_ref(), args, fin(), true, true).await.unwrap();
    assert_eq!(r["sent"], json!(true));
    let sent = s.seen.lock().iter().find(|l| l.starts_with("sendgrid")).cloned().unwrap();
    assert!(sent.contains(r#""to":[{"email":"a@x.com"}],"cc":[{"email":"ops@x.com"}],"bcc":[{"email":"audit@x.com"}]"#), "{sent}");
    // Empty and null are no copies.
    let args = json!({"connectionName": "mail", "templateName": "welcome", "templateData": {"name": "A", "email": "a@x.com"}, "cc": "", "bcc": null});
    assert_eq!(run(send.as_ref(), args, fin(), true, true).await.unwrap()["sent"], json!(true));
    // One bad address: 400, nothing posted.
    let before = s.seen.lock().len();
    let args = json!({"connectionName": "mail", "templateName": "welcome", "templateData": {"name": "A", "email": "a@x.com"},
                      "cc": "ops@x.com", "bcc": "audit@x.com, nope"});
    let e = run(send.as_ref(), args, fin(), true, true).await.unwrap_err();
    assert_eq!(e.status(), StatusCode::BAD_REQUEST);
    assert_eq!(e.text(), "Unable to send the email: Not an email address: nope");
    assert_eq!(s.seen.lock().len(), before);
}

#[tokio::test]
async fn send_notification() {
    let s = setup().await;
    let fns = all(&s.integrations, crate::testing::MemoryCatalog::with(Vec::new()));
    let f = find(&fns, "SendNotification");
    s.world.answer("GET", "/api/security/clients/internal/isUserPartOfHierarchy", 200, "true");
    let args = json!({"connectionName": "n", "notificationName": "welcome", "targetId": 500, "payload": {"a": 1}, "filterAuthorization": "Authorities.X"});
    assert_eq!(run(f.as_ref(), args.clone(), fin(), false, true).await.unwrap_err().status(), StatusCode::INTERNAL_SERVER_ERROR);
    let r = run(f.as_ref(), args.clone(), fin(), true, true).await.unwrap();
    assert_eq!(r["sent"], json!(true));
    let (exchange, key, body, type_id) = s.published.sent.lock()[0].clone();
    assert_eq!((exchange.as_str(), key.as_str(), type_id.as_str()), ("notifications", "notifications2", connections::mq::NOTIFICATION_TYPE_ID));
    assert_eq!((body["targetId"].clone(), body["notificationName"].clone(), body["filterAuthorization"].clone()), (json!(500), json!("welcome"), json!("Authorities.X")));
    // No access: not sent.
    s.world.answer("GET", "/api/security/clients/internal/isUserPartOfHierarchy", 200, "false");
    let r = run(f.as_ref(), args.clone(), fin(), true, true).await.unwrap();
    assert_eq!(r["sent"], json!(false));
    assert_eq!(s.published.sent.lock().len(), 1);
    let r = run(f.as_ref(), json!({"connectionName": "n", "notificationName": "w", "targetId": 1.5}), fin(), true, true).await;
    assert_eq!(r.unwrap_err().status(), StatusCode::INTERNAL_SERVER_ERROR);
    let _ = NotificationRequest::default();
}

#[tokio::test]
async fn send_data_notification() {
    let s = setup().await;
    let fns = all(&s.integrations, crate::testing::MemoryCatalog::with(Vec::new()));
    let f = find(&fns, "SendDataNotification");
    assert_eq!(f.get_signature().get_full_name(), "CoreServices.Notification.SendDataNotification");
    s.world.answer("GET", "/api/security/clients/internal/isUserPartOfHierarchy", 200, "true");
    let args = json!({"targetId": 500, "eventName": "incomingCall", "data": {"from": "+9180", "lead": {"id": 9}},
                      "filterAuthorization": "Authorities.Calls"});
    // Only inside a server function, as SendNotification.
    assert_eq!(run(f.as_ref(), args.clone(), fin(), false, true).await.unwrap_err().status(), StatusCode::INTERNAL_SERVER_ERROR);
    let before = chrono::Utc::now().timestamp_millis();
    let r = run(f.as_ref(), args.clone(), fin(), true, true).await.unwrap();
    assert_eq!(r["sent"], json!(true));
    let (exchange, key, body, type_id) = s.published.sent.lock()[0].clone();
    assert_eq!((exchange.as_str(), key.as_str(), type_id.as_str()), ("notifications", "notifications2", connections::mq::NOTIFICATION_TYPE_ID));
    assert_eq!((body["kind"].clone(), body["eventName"].clone()), (json!("DATA"), json!("incomingCall")));
    assert_eq!(body["data"], json!({"from": "+9180", "lead": {"id": 9}}));
    assert_eq!((body["targetId"].clone(), body["targetType"].clone(), body["filterAuthorization"].clone()), (json!(500), json!("User Id"), json!("Authorities.Calls")));
    let expires = body["expiresAt"].as_i64().unwrap();
    assert!(expires >= before + 60_000 && expires <= chrono::Utc::now().timestamp_millis() + 60_000, "the default ttl is 60 s");
    assert!(body.get("notificationName").is_none() && body.get("connectionName").is_none());

    // Any JSON as data, and a ttl of its own.
    let r = run(f.as_ref(), json!({"targetId": 500, "eventName": "tick", "data": [1, "a"], "ttlSeconds": 5}), fin(), true, true).await.unwrap();
    assert_eq!(r["sent"], json!(true));
    let body = s.published.sent.lock()[1].2.clone();
    assert_eq!(body["data"], json!([1, "a"]));
    assert!(body["expiresAt"].as_i64().unwrap() <= chrono::Utc::now().timestamp_millis() + 5_000);
    // The ttl stays within 1 to 3600 s: the signature refuses others.
    assert!(run(f.as_ref(), json!({"targetId": 500, "eventName": "tick", "ttlSeconds": 0}), fin(), true, true).await.is_err());
    assert!(run(f.as_ref(), json!({"targetId": 500, "eventName": "tick", "ttlSeconds": 3601}), fin(), true, true).await.is_err());

    // Refused names and sizes, coded, before anything is checked or published.
    let code = |e: CoreError| e.code().map(|c| c.code.to_string()).unwrap_or_default();
    let e = run(f.as_ref(), json!({"targetId": 500, "eventName": "init"}), fin(), true, true).await.unwrap_err();
    assert_eq!((e.status(), code(e)), (StatusCode::BAD_REQUEST, "CORE.DATA_NOTIFICATION_EVENT_RESERVED".to_string()));
    let e = run(f.as_ref(), json!({"targetId": 500, "eventName": "a b"}), fin(), true, true).await.unwrap_err();
    assert_eq!(code(e), "CORE.DATA_NOTIFICATION_EVENT_INVALID");
    let e = run(f.as_ref(), json!({"targetId": 500, "eventName": "big", "data": "x".repeat(70_000)}), fin(), true, true).await.unwrap_err();
    assert_eq!(code(e), "CORE.DATA_NOTIFICATION_TOO_LARGE");
    // No event name at all: the signature requires one.
    assert!(run(f.as_ref(), json!({"targetId": 500}), fin(), true, true).await.is_err());
    assert_eq!(s.published.sent.lock().len(), 2);

    // A target the caller may not reach: not sent.
    s.world.answer("GET", "/api/security/clients/internal/isUserPartOfHierarchy", 200, "false");
    let r = run(f.as_ref(), args, fin(), true, true).await.unwrap();
    assert_eq!(r["sent"], json!(false));
    assert_eq!(s.published.sent.lock().len(), 2);
    // A publish that fails is the function's error.
    s.world.answer("GET", "/api/security/clients/internal/isUserPartOfHierarchy", 200, "true");
    *s.published.fail.lock() = true;
    assert!(run(f.as_ref(), json!({"targetId": 500, "eventName": "x"}), fin(), true, true).await.is_err());
    let _ = connections::notification::DataNotificationRequest::default();
}

#[tokio::test]
async fn create_event() {
    let s = setup().await;
    let catalog = crate::testing::MemoryCatalog::with(Vec::new());
    catalog.events.lock().insert("Deal.Won".into(), jmap(json!({"name": "Deal.Won"})));
    let fns = all(&s.integrations, catalog.clone());
    let f = find(&fns, "CreateEvent");
    assert_eq!(run(f.as_ref(), json!({"eventName": "Deal.Won"}), fin(), false, true).await.unwrap_err().status(), StatusCode::INTERNAL_SERVER_ERROR);
    let r = run(f.as_ref(), json!({"eventName": "Deal.Won", "eventData": {"deal": 9}}), fin(), true, true).await.unwrap();
    assert_eq!(r["created"], json!(true));
    // The definition is read for the caller's app and client; the event carries the arguments as given.
    assert_eq!(catalog.lookups.lock().last().unwrap(), "leadzumptwo/FIN/Deal.Won");
    let (_, _, body, _) = s.published.sent.lock()[0].clone();
    assert_eq!((body["eventName"].clone(), body["data"]["deal"].clone()), (json!("Deal.Won"), json!(9)));
    assert!(body.get("appCode").is_none());
    assert_eq!(body["authentication"]["user"]["id"], 110);
    let r = run(f.as_ref(), json!({"eventName": "Deal.Won", "appCode": "x", "clientCode": "Y"}), fin(), true, true).await.unwrap();
    assert_eq!(r["created"], json!(true));
    assert_eq!(catalog.lookups.lock().last().unwrap(), "x/Y/Deal.Won");
    // No definition: not sent.
    let r = run(f.as_ref(), json!({"eventName": "Nope"}), fin(), true, true).await.unwrap();
    assert_eq!(r["created"], json!(false));
    assert_eq!(s.published.sent.lock().len(), 2);
    *s.published.fail.lock() = true;
    assert!(run(f.as_ref(), json!({"eventName": "Deal.Won"}), fin(), true, true).await.is_err());
    // Without a request there is no caller: not sent.
    let out = crate::context::with_run(Default::default(), async {
        let mut fep = kirun::runtime::FunctionExecutionParameters::new(
            Arc::new(kirun::repository::KIRunFunctionRepository::new()),
            Arc::new(kirun::repository::KIRunSchemaRepository::new()),
        )
        .set_arguments(json!({"eventName": "Deal.Won"}).as_object().unwrap().clone().into_iter().collect());
        f.execute(&mut fep).await
    })
    .await
    .unwrap()
    .next()
    .unwrap();
    assert_eq!(out.get_result()["created"], json!(false));
}

// --- the routes --------------------------------------------------------------------------------

async fn routes(s: &Setup) -> String {
    let storage = crate::testing::offline_storage_service().await;
    let state = crate::testing::offline_state_with(storage, &s.security_base, Some(s.integrations.clone())).await;
    serve(crate::handlers::router(state)).await
}

async fn http_get(base: &str, path: &str, auth: bool) -> (u16, String, String) {
    let mut rb = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap().get(format!("{base}{path}"));
    rb = rb.header("appCode", "leadzumptwo").header("clientCode", "FIN").header("X-Forwarded-Host", "app.local");
    if auth {
        rb = rb.header("Authorization", "Basic dXNlcg==");
    }
    let r = rb.send().await.unwrap();
    let status = r.status().as_u16();
    let location = r.headers().get("location").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    (status, location, r.text().await.unwrap())
}

#[tokio::test]
async fn connection_routes() {
    let s = setup().await;
    s.world.answer("GET", "/api/security/internal/securityContextAuthentication", 200, &json!({
        "user": {"id": 110, "clientId": 7, "stringAuthorities": ["Authorities.Logged_IN"]}, "authenticated": true, "clientCode": "FIN"
    }).to_string());
    s.docs.add_connection(json!({"name": "notify", "appCode": "leadzumptwo", "clientCode": "FIN", "connectionType": "NOTIFICATION",
                                 "connectionDetails": {"mail": "mail", "inapp": true, "push": "pushKeys"}}));
    s.docs.add_connection(json!({"name": "pushKeys", "appCode": "leadzumptwo", "clientCode": "FIN", "connectionType": "PUSH",
                                 "connectionDetails": {"apns": {"keyId": "K", "teamId": "T", "privateKey": "p"}}}));
    s.docs.add_connection(json!({"name": "notifyDefault", "appCode": "leadzumptwo", "clientCode": "FIN", "connectionType": "NOTIFICATION",
                                 "connectionDetails": {"inapp": true, "push": true}}));
    s.docs.add_connection(json!({"name": "mail", "appCode": "leadzumptwo", "clientCode": "FIN", "connectionType": "MAIL", "version": 2,
                                 "connectionSubType": "SMTP", "connectionDetails": {"host": "h"}, "isAppLevel": false}));
    s.docs.add_connection(json!({"name": "bare", "appCode": "leadzumptwo", "clientCode": "FIN", "connectionType": "NOTIFICATION", "connectionDetails": {}}));
    let base = routes(&s).await;
    let q = "appCode=leadzumptwo&clientCode=FIN&urlClientCode=FIN";

    let (st, _, body) = http_get(&base, &format!("/api/core/connections/internal/notification/notify?{q}"), false).await;
    assert_eq!(st, 200);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["inApp"], json!(true));
    assert_eq!(v["mail"]["name"], "mail");
    assert_eq!(v["mail"]["connectionSubType"], "SMTP");
    assert_eq!(v["push"]["connectionDetails"]["apns"]["teamId"], "T", "the PUSH connection is inlined, secrets and all");
    let (_, _, body) = http_get(&base, &format!("/api/core/connections/internal/notification/notifyDefault?{q}"), false).await;
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!((v["inApp"].clone(), v["push"].clone()), (json!(true), json!({})));
    let (st, _, body) = http_get(&base, &format!("/api/core/connections/internal/notification/bare?{q}"), false).await;
    assert_eq!((st, body.as_str()), (200, ""));
    let (st, _, body) = http_get(&base, &format!("/api/core/connections/internal/notification/mail?{q}"), false).await;
    assert_eq!((st, body.as_str()), (200, ""));
    let (st, _, _) = http_get(&base, "/api/core/connections/internal/notification/notify?appCode=a", false).await;
    assert_eq!(st, 400);

    let (st, _, body) = http_get(&base, &format!("/api/core/connections/internal/mail?{q}&connectionType=MAIL"), false).await;
    assert_eq!(st, 200);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!((v["name"].clone(), v["connectionDetails"]["host"].clone()), (json!("mail"), json!("h")));
    let (st, _, body) = http_get(&base, &format!("/api/core/connections/internal/mail?{q}&connectionType=AI"), false).await;
    assert_eq!((st, body.as_str()), (200, ""));
    let (st, _, _) = http_get(&base, &format!("/api/core/connections/internal/mail?{q}&connectionType=NOPE"), false).await;
    assert_eq!(st, 400);

    // The OAuth2 routes over the library.
    let (st, _, body) = http_get(&base, "/api/core/connections/internal/oauth2/token/none", false).await;
    assert_eq!((st, body.as_str()), (200, ""));
    let (st, _, _) = http_get(&base, "/api/core/connections/oauth/revoke?connectionName=x", false).await;
    assert_eq!(st, 401);
    let (st, _, _) = http_get(&base, "/api/core/connections/oauth/revoke?connectionName=x", true).await;
    assert!(st >= 400);
    let (st, _, _) = http_get(&base, "/api/core/connections/oauth/revoke", true).await;
    assert_eq!(st, 400);
    let (st, _, _) = http_get(&base, "/api/core/connections/oauth/callback?state=s", false).await;
    assert!(st == 302 || st == 200 || st >= 400, "{st}");
    let r = reqwest::Client::new()
        .post(format!("{base}/api/core/connections/oauth/evoke?connectionName=none"))
        .header("appCode", "leadzumptwo")
        .header("clientCode", "FIN")
        .header("X-Forwarded-Host", "app.local")
        .send()
        .await
        .unwrap();
    assert!(r.status().as_u16() == 200 || r.status().as_u16() >= 400);
    let r = reqwest::Client::new().post(format!("{base}/api/core/connections/oauth/evoke")).send().await.unwrap();
    assert_eq!(r.status().as_u16(), 400);
}

/// The consent gate on `POST /oauth/evoke`, through the route and KIRun's evaluator.
#[tokio::test]
async fn oauth_evoke_honours_consent_auth() {
    let s = setup().await;
    let signed_in = |authorities: &[&str]| {
        json!({"user": {"id": 110, "clientId": 7, "stringAuthorities": authorities}, "authenticated": true, "clientCode": "FIN"}).to_string()
    };
    let oauth = |name: &str, gate: Option<&str>| {
        let mut c = json!({"name": name, "appCode": "leadzumptwo", "clientCode": "FIN", "connectionType": "REST_API",
                           "connectionSubType": "REST_API_OAUTH2",
                           "connectionDetails": {"grantType": "AUTHORIZATION_CODE",
                                                 "consentDetails": {"url": "https://provider.example.com/oauth", "queryParams": {"client_id": "1"}}}});
        if let Some(g) = gate {
            c["consentAuth"] = json!(g);
        }
        c
    };
    s.docs.add_connection(oauth("gated", Some("Authorities.LEADZUMPTWO.ROLE_Account_MANAGE or Authorities.ROLE_Owner")));
    s.docs.add_connection(oauth("open", None));
    s.docs.add_connection(oauth("blank", Some("  ")));
    let base = routes(&s).await;
    let evoke = |name: &str| {
        reqwest::Client::new()
            .post(format!("{base}/api/core/connections/oauth/evoke?connectionName={name}"))
            .header("appCode", "leadzumptwo")
            .header("clientCode", "FIN")
            .header("X-Forwarded-Host", "app.local")
            .header("Authorization", "Basic dXNlcg==")
            .send()
    };

    s.world.answer("GET", "/api/security/internal/securityContextAuthentication", 200, &signed_in(&["Authorities.Logged_IN"]));
    let r = evoke("gated").await.unwrap();
    assert_eq!(r.status().as_u16(), 403);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["code"], json!("CORE.CONNECTION_CONSENT_FORBIDDEN"), "{body}");
    assert!(s.tokens.rows.lock().is_empty(), "nothing stored for a refused consent");
    for open in ["open", "blank"] {
        let r = evoke(open).await.unwrap();
        assert_eq!(r.status().as_u16(), 200, "{open}");
        assert!(r.text().await.unwrap().starts_with("https://provider.example.com/oauth?client_id=1&redirect_uri="), "{open}");
    }

    for holder in ["Authorities.LEADZUMPTWO.ROLE_Account_MANAGE", "Authorities.ROLE_Owner"] {
        s.world.answer("GET", "/api/security/internal/securityContextAuthentication", 200, &signed_in(&["Authorities.Logged_IN", holder]));
        let r = evoke("gated").await.unwrap();
        assert_eq!(r.status().as_u16(), 200, "{holder}");
        let url = r.text().await.unwrap();
        assert!(url.starts_with("https://provider.example.com/oauth?client_id=1&redirect_uri=https://app.local/api/core/connections/oauth/callback&state="), "{url}");
    }
}

/// `GET /oauth/revoke` honours the same `consentAuth`, before anything is looked up or revoked.
#[tokio::test]
async fn oauth_revoke_honours_consent_auth() {
    let s = setup().await;
    let signed_in = |authorities: &[&str]| {
        json!({"user": {"id": 110, "clientId": 7, "stringAuthorities": authorities}, "authenticated": true, "clientCode": "FIN"}).to_string()
    };
    for (name, gate) in [("gated", Some("Authorities.LEADZUMPTWO.ROLE_Account_MANAGE")), ("open", None)] {
        let mut c = json!({"name": name, "appCode": "leadzumptwo", "clientCode": "FIN", "connectionType": "REST_API",
                           "connectionSubType": "REST_API_OAUTH2", "connectionDetails": {"grantType": "AUTHORIZATION_CODE"}});
        if let Some(g) = gate {
            c["consentAuth"] = json!(g);
        }
        s.docs.add_connection(c);
    }
    s.tokens.rows.lock().push(CoreToken {
        id: Some(1),
        client_code: Some("FIN".into()),
        app_code: Some("leadzumptwo".into()),
        connection_name: Some("gated".into()),
        token_type: Some(TokenType::Access),
        token: Some("live".into()),
        is_revoked: Some(false),
        ..Default::default()
    });
    let base = routes(&s).await;
    let revoked = || s.tokens.rows.lock()[0].is_revoked;

    s.world.answer("GET", "/api/security/internal/securityContextAuthentication", 200, &signed_in(&["Authorities.Logged_IN"]));
    let (st, _, body) = http_get(&base, "/api/core/connections/oauth/revoke?connectionName=gated", true).await;
    assert_eq!(st, 403, "{body}");
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["code"], json!("CORE.CONNECTION_REVOKE_FORBIDDEN"));
    assert_eq!(revoked(), Some(false), "a refused revoke revokes nothing");
    let (st, _, body) = http_get(&base, "/api/core/connections/oauth/revoke?connectionName=open", true).await;
    assert_eq!(st, 400, "no consentAuth: the normal path ({body})");

    s.world.answer("GET", "/api/security/internal/securityContextAuthentication", 200,
                   &signed_in(&["Authorities.Logged_IN", "Authorities.LEADZUMPTWO.ROLE_Account_MANAGE"]));
    let (st, _, body) = http_get(&base, "/api/core/connections/oauth/revoke?connectionName=gated", true).await;
    assert_eq!((st, body.as_str()), (200, "true"));
    assert_eq!(revoked(), Some(true));
    let (st, _, _) = http_get(&base, "/api/core/connections/oauth/revoke?connectionName=gated", true).await;
    assert_eq!(st, 400, "nothing left to revoke");
}

/// `GET /oauth/status` (Rust only): the caller's stored sign-in, its consent's start and user,
/// for the caller's own client and URL app; and `oauth/revoke` also drops a sign-in whose access
/// token has expired while its refresh token is active.
#[tokio::test]
async fn oauth_status_and_revoke_of_a_refresh_only_sign_in() {
    let s = setup().await;
    s.world.answer("GET", "/api/security/internal/securityContextAuthentication", 200, &json!({
        "user": {"id": 110, "clientId": 7, "stringAuthorities": ["Authorities.Logged_IN"]}, "authenticated": true, "clientCode": "FIN"
    }).to_string());
    s.docs.add_connection(json!({"name": "G", "appCode": "leadzumptwo", "clientCode": "FIN", "connectionType": "REST_API",
                                 "connectionSubType": "REST_API_OAUTH2", "connectionDetails": {"grantType": "AUTHORIZATION_CODE"}}));
    let at = |t: &str| chrono::NaiveDateTime::parse_from_str(t, "%Y-%m-%d %H:%M:%S").unwrap();
    let row = |id: u64, client: &str, app: &str, ty: TokenType, revoked: bool, created: &str, user: u64| CoreToken {
        id: Some(id),
        client_code: Some(client.into()),
        app_code: Some(app.into()),
        connection_name: Some("G".into()),
        token_type: Some(ty),
        token: Some(format!("t{id}")),
        state: Some("consent-1".into()),
        is_revoked: Some(revoked),
        user_id: Some(user),
        created_at: Some(at(created)),
        ..Default::default()
    };
    {
        let mut rows = s.tokens.rows.lock();
        // The consent's first row (its access token, since refreshed and revoked), its refresh
        // token, a later access token that expired, and another client's and another app's.
        rows.push(row(1, "FIN", "leadzumptwo", TokenType::Access, true, "2026-10-20 09:15:00", 110));
        rows.push(row(2, "FIN", "leadzumptwo", TokenType::Refresh, false, "2026-10-20 09:16:00", 110));
        rows.push(row(3, "FIN", "leadzumptwo", TokenType::Access, true, "2026-10-28 11:00:00", 0));
        rows.push(row(4, "OTHER", "leadzumptwo", TokenType::Access, false, "2026-10-21 08:00:00", 9));
        rows.push(row(5, "FIN", "marketingai", TokenType::Access, false, "2026-10-22 08:00:00", 9));
    }
    let base = routes(&s).await;

    let (st, _, _) = http_get(&base, "/api/core/connections/oauth/status?connectionName=G", false).await;
    assert_eq!(st, 401);
    let (st, _, _) = http_get(&base, "/api/core/connections/oauth/status", true).await;
    assert_eq!(st, 400);
    let (st, _, body) = http_get(&base, "/api/core/connections/oauth/status?connectionName=G", true).await;
    assert_eq!(st, 200, "{body}");
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v, json!({"hasToken": true, "connectedAt": "2026-10-20T09:15:00Z", "connectedBy": 110}));
    assert!(!body.contains("t2"), "never the token");
    let (st, _, body) = http_get(&base, "/api/core/connections/oauth/status?connectionName=none", true).await;
    assert_eq!(st, 200);
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap(), json!({"hasToken": false, "connectedAt": null, "connectedBy": null}));

    // Only the refresh token is active: revoke drops the caller's rows, no other client's or app's.
    let (st, _, body) = http_get(&base, "/api/core/connections/oauth/revoke?connectionName=G", true).await;
    assert_eq!((st, body.as_str()), (200, "true"));
    let revoked: Vec<_> = s.tokens.rows.lock().iter().map(|t| (t.id.unwrap(), t.is_revoked == Some(true))).collect();
    assert_eq!(revoked, vec![(1, true), (2, true), (3, true), (4, false), (5, false)]);
    let (st, _, body) = http_get(&base, "/api/core/connections/oauth/status?connectionName=G", true).await;
    assert_eq!(st, 200);
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["hasToken"], json!(false));
    let (st, _, _) = http_get(&base, "/api/core/connections/oauth/revoke?connectionName=G", true).await;
    assert_eq!(st, 400, "nothing left to revoke");
}

// --- DraftEventPropagationTest / DraftNotificationPropagationTest ------------------------------

async fn on_surface<F: std::future::Future>(draft: bool, fut: F) -> F::Output {
    let ctx = crate::testing::request(crate::testing::user(&[]), draft, None);
    crate::context::with_request(ctx, fut).await
}

#[tokio::test]
async fn the_draft_marker_travels_with_events() {
    let rec = Arc::new(Recording::default());
    let mq = Mq::with(rec.clone(), &crate::config::MqSection::default());
    let event = || EventMessage { event_name: Some("Storage.testStorage.Create".into()), app_code: Some("app".into()), client_code: Some("SYSTEM".into()), ..Default::default() };
    on_surface(true, async { mq.create_event(&caller(), event()).await.unwrap() }).await;
    on_surface(false, async { mq.create_event(&caller(), event()).await.unwrap() }).await;
    let sent = rec.sent.lock().clone();
    // What goes on the wire is the JSON the consumer reads back: the marker and the name survive it.
    assert_eq!((sent[0].2["draft"].clone(), sent[0].2["eventName"].clone()), (json!(true), json!("Storage.testStorage.Create")));
    assert_eq!(sent[1].2["draft"], json!(false));
    // A storage write on the draft surface raises its event with the marker too.
    let events = MqEvents { mq: Arc::new(Mq::with(rec.clone(), &crate::config::MqSection::default())) };
    crate::context::with_surface(true, async { events.create_event("app", "SYSTEM", "Storage.s.Create", Default::default()).await.unwrap() }).await;
    assert_eq!(rec.sent.lock().last().unwrap().2["draft"], json!(true));
}

#[tokio::test]
async fn the_draft_marker_travels_with_notifications() {
    let s = setup().await;
    let req = || NotificationRequest {
        app_code: Some("app".into()),
        client_code: Some("SYSTEM".into()),
        connection_name: Some("appNotification".into()),
        target_id: Some(1),
        target_type: connections::notification::USER_ID.into(),
        notification_name: Some("testNotification".into()),
        notification_category: Some("SYSTEM".into()),
        payload: Some(json!({"k": "v"}).as_object().unwrap().clone()),
        ..Default::default()
    };
    // A system client skips the target access check, which is not under test.
    let checks = s.integrations.checks.clone();
    let mq = s.integrations.mq.clone();
    let sent = on_surface(true, async { mq.send_notification(checks.as_ref(), &caller(), req()).await.unwrap() }).await;
    assert_eq!(sent, Some(true));
    on_surface(false, async { mq.send_notification(checks.as_ref(), &caller(), req()).await.unwrap() }).await;
    let published = s.published.sent.lock().clone();
    assert_eq!((published[0].2["draft"].clone(), published[0].2["notificationName"].clone()), (json!(true), json!("testNotification")));
    assert_eq!(published[1].2["draft"], json!(false));
    // Publishing that fails is the caller's error; a target the caller may not reach sends nothing.
    *s.published.fail.lock() = true;
    assert!(on_surface(false, async { mq.send_notification(checks.as_ref(), &caller(), req()).await }).await.is_err());
    let none = on_surface(false, async { mq.send_notification(checks.as_ref(), &caller(), NotificationRequest { target_type: "Nope".into(), ..req() }).await })
        .await
        .unwrap();
    assert_eq!(none, None);
}

// --- SendEmailAddressesTest / CallRequestErrorOutputTest ---------------------------------------

#[test]
fn given_addresses_as_send_email_reads_them() {
    use connections::email::given_addresses;
    assert!(given_addresses(Some(&json!([""]))).is_empty());
    assert_eq!(given_addresses(Some(&json!(["", " a@x.com ", null, "   ", "b@x.com"]))), vec!["a@x.com", "b@x.com"]);
    assert!(given_addresses(None).is_empty());
    assert!(given_addresses(Some(&Value::Null)).is_empty());
}

#[tokio::test]
async fn rest_errors_carry_the_status_on_both_events() {
    let s = setup().await;
    let fns = all(&s.integrations, crate::testing::MemoryCatalog::with(Vec::new()));
    s.docs.add_connection(json!({"name": "rest", "appCode": "leadzumptwo", "clientCode": "FIN", "connectionType": "REST_API",
                                 "connectionSubType": "REST_API_BASIC", "connectionDetails": {"baseUrl": s.target}}));
    let f = find(&fns, "GetRequest");
    let events = |url: &'static str, conn: &'static str| {
        let f = f.clone();
        async move {
            let ctx = crate::testing::request(fin(), false, None);
            crate::context::with_request(ctx, async move {
                let mut fep = kirun::runtime::FunctionExecutionParameters::new(
                    Arc::new(kirun::repository::KIRunFunctionRepository::new()),
                    Arc::new(kirun::repository::KIRunSchemaRepository::new()),
                )
                .set_arguments(json!({"connectionName": conn, "url": url}).as_object().unwrap().clone().into_iter().collect());
                let mut out = f.execute(&mut fep).await.unwrap();
                let mut all = Vec::new();
                while let Some(e) = out.next() {
                    all.push((e.get_name().to_string(), e.get_result().clone()));
                }
                all
            })
            .await
        }
    };
    let got = events("/rest/fail", "rest").await;
    assert_eq!(got.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(), ["error", "output"]);
    assert!(got.iter().all(|(_, r)| r["statusCode"] == json!(404)));
    // No answer at all (the target refuses the connection): 500, the exception's text as data.
    s.docs.add_connection(json!({"name": "dead", "appCode": "leadzumptwo", "clientCode": "FIN", "connectionType": "REST_API",
                                 "connectionSubType": "REST_API_BASIC", "connectionDetails": {"baseUrl": "http://127.0.0.1:1"}}));
    let got = events("/x", "dead").await;
    assert!(got.iter().all(|(_, r)| r["statusCode"] == json!(500)));
    assert!(got[0].1["data"].is_string());
}

#[tokio::test]
async fn the_oauth2_consent_flow_over_the_routes() {
    let s = setup().await;
    s.world.answer("GET", "/api/security/internal/securityContextAuthentication", 200, &json!({
        "user": {"id": 110, "clientId": 7, "stringAuthorities": ["Authorities.Logged_IN"]}, "authenticated": true, "clientCode": "FIN"
    }).to_string());
    s.docs.add_connection(json!({"name": "oauth", "appCode": "leadzumptwo", "clientCode": "FIN", "connectionType": "REST_API",
        "connectionSubType": "REST_API_OAUTH2", "connectionDetails": {
            "grantType": "AUTHORIZATION_CODE", "consentDetails": {"url": "https://provider.example/auth", "client_id": "cid"},
            "tokenDetails": {"url": format!("{}/oauth/token", s.target), "methodType": "POST"},
            "tokenKey": "access_token", "refreshTokenKey": "refresh_token", "pagePath": "/page"}}));
    let base = routes(&s).await;
    let http = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
    let r = http
        .post(format!("{base}/api/core/connections/oauth/evoke?connectionName=oauth"))
        .header("appCode", "leadzumptwo")
        .header("clientCode", "FIN")
        .header("X-Forwarded-Host", "app.local")
        .header("Authorization", "Basic dXNlcg==")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    assert!(r.headers()["content-type"].to_str().unwrap().starts_with("text/plain"));
    let consent = r.text().await.unwrap();
    assert!(consent.starts_with("https://provider.example/auth?"), "{consent}");
    let state = s.tokens.rows.lock()[0].state.clone().unwrap();
    assert!(consent.contains(&state));

    // The provider sends the browser back with a code: tokens stored, back to the page.
    let (st, location, _) = http_get(&base, &format!("/api/core/connections/oauth/callback?code=c1&state={state}"), false).await;
    assert_eq!((st, location.as_str()), (302, "https://app.local/page?oauth=success"));
    // Without a code: back with "invalid"; an unknown state: a bare 302.
    let (st, location, _) = http_get(&base, &format!("/api/core/connections/oauth/callback?state={state}"), false).await;
    assert_eq!((st, location.as_str()), (302, "https://app.local/page?oauth=invalid"));
    let (st, location, _) = http_get(&base, "/api/core/connections/oauth/callback?state=nope", false).await;
    assert_eq!((st, location.as_str()), (302, ""));
    let (st, _, body) = http_get(&base, "/api/core/connections/oauth/callback?code=c1&state=nope", false).await;
    assert_eq!((st, body.as_str()), (200, ""));

    // The other services read the token by name.
    let (st, _, body) = http_get(&base, "/api/core/connections/internal/oauth2/token/oauth", false).await;
    assert_eq!((st, body.as_str()), (200, "at1"));

    // Revoking: the caller's token, once.
    let (st, _, body) = http_get(&base, "/api/core/connections/oauth/revoke?connectionName=oauth", true).await;
    assert_eq!((st, body.as_str()), (200, "true"));
    let (st, _, _) = http_get(&base, "/api/core/connections/oauth/revoke?connectionName=oauth", true).await;
    assert_eq!(st, 400);
}

#[tokio::test]
async fn argument_readers_as_gson_reads_them() {
    // Values the signatures keep out of reach of a call, read as the Java classes would.
    let s = setup().await;
    let fns = all(&s.integrations, crate::testing::MemoryCatalog::with(Vec::new()));
    let call = |name: &'static str| find(&fns, name);
    for (name, args) in [
        ("GetRequest", json!({"connectionName": "x", "url": "/", "headers": "h"})),
        ("GetRequest", json!({"connectionName": "x", "url": "/", "timeout": "abc"})),
        ("SendNotification", json!({"connectionName": "x", "notificationName": "n", "targetId": "abc"})),
    ] {
        let r = run(call(name).as_ref(), args, fin(), true, true).await;
        assert_eq!(r.unwrap_err().status(), StatusCode::INTERNAL_SERVER_ERROR, "{name}");
    }
}

#[tokio::test]
async fn downloads_are_uploaded_through_the_files_client() {
    let (base, uploads) = crate::files_calls::tests::fake().await;
    let files: Arc<dyn FileCreate> = Arc::new(crate::files_calls::FilesCalls::new(Upstream::fixed(&[&base])).unwrap());
    let r = files.create("secured", "FIN", true, "/dl", "a.txt", b"hello".to_vec()).await.unwrap();
    assert!(r.is_some());
    let up = uploads.lock().clone();
    assert_eq!((up.len(), up[0].bytes.as_slice()), (1, b"hello".as_slice()));
    assert!(up[0].query.contains("fileName=a.txt") && up[0].query.contains("override=true"), "{}", up[0].query);
}

// --- against the local stack ------------------------------------------------------------------

/// security-internal and files-manage as `config/core-exec.toml` names them, and the gateway
/// the files API is read through as the SYSTEM user 142.
const LOCAL_SECURITY_INTERNAL: &str = "http://localhost:8112";
const LOCAL_FILES_MANAGE: &str = "http://localhost:8104";
const LOCAL_GATEWAY: &str = "http://localhost:8080";
const LOCAL_BASIC: &str = "Basic MTQyOlBhc3NAMTIzNA==";
/// A scratch folder of FIN's secured files, emptied again at the end.
const SCRATCH_FOLDER: &str = "_scratch_r2_webhook_downloads";

async fn files_api(method: reqwest::Method, path: &str) -> (u16, Vec<u8>) {
    let r = reqwest::Client::new()
        .request(method, format!("{LOCAL_GATEWAY}{path}"))
        .header("Authorization", LOCAL_BASIC)
        .header("clientCode", "SYSTEM")
        .header("appCode", "appbuilder")
        .send()
        .await
        .expect("files api");
    (r.status().as_u16(), r.bytes().await.unwrap_or_default().to_vec())
}

/// A webhook run (the real client lookup of FIN, `Authorities._Webhook`) downloads a recording
/// from a local stub into FIN's secured files through the real files-manage, refuses a client
/// FIN does not manage (real security), and the file is then found and deleted through the
/// files API.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs the local stack: CORE_LOCAL_STACK=1"]
async fn local_stack_webhook_download_lands_in_the_clients_secured_files() {
    if !crate::testing::local_stack() {
        return;
    }
    // What an earlier, failed run left behind.
    files_api(reqwest::Method::DELETE, &format!("/api/files/secured/{SCRATCH_FOLDER}?clientCode=FIN")).await;
    let recording = b"ID3-r2-webhook-download".to_vec();
    let body = recording.clone();
    let stub = serve(Router::new().route("/media/rec.mp3", get(move || {
        let body = body.clone();
        async move { ([("content-type", "audio/mpeg")], body) }
    })))
    .await;

    let docs = Arc::new(MemoryDocs::default());
    docs.add_connection(json!({"name": "media", "appCode": "leadzumptwo", "clientCode": "FIN", "connectionType": "REST_API",
                               "connectionSubType": "REST_API_BASIC", "connectionDetails": {"baseUrl": stub}}));
    let mut cfg = crate::config::CoreConfig::default();
    cfg.connections.block_private_targets = false;
    let mq = Arc::new(Mq::with(Arc::new(Recording::default()), &cfg.mq));
    let cache = platform::cache::CacheService::new("cmn", "evictionChannel", None).unwrap();
    let security = Arc::new(SecurityCalls::new(Upstream::fixed(&[LOCAL_SECURITY_INTERNAL])).unwrap());
    let files: Arc<dyn FileCreate> = Arc::new(crate::files_calls::FilesCalls::new(Upstream::fixed(&[LOCAL_FILES_MANAGE])).unwrap());
    let integrations = Arc::new(
        Integrations::new(&cfg, docs, security.clone(), Arc::new(MemoryTokens::default()), cache, mq, Some(files)).unwrap(),
    );
    let get_request = find(&crate::functions::integration_fns::rest(&integrations), "GetRequest");

    // The context core's webhook route builds: FIN as security has it, `Authorities._Webhook`.
    let client = security.client_by_code("FIN").await.unwrap().expect("FIN on the local stack");
    let auth = crate::events::webhook_authentication(Some("leadzumptwo"), Some("FIN"), &client).unwrap();

    let name = format!("rec{}", chrono::Utc::now().timestamp_millis());
    let args = json!({"connectionName": "media", "url": "/media/rec.mp3", "downloadAsAFile": true, "fileName": name,
                      "fileLocation": format!("/{SCRATCH_FOLDER}"), "fileType": "static"});
    let r = run(get_request.as_ref(), args.clone(), auth.clone(), true, true).await.unwrap();
    assert_eq!(r["statusCode"], json!(200), "{r:?}");
    // The stub (hyper) sends `content-type` in lower case, which the exact `Content-Type`
    // lookup does not see, so the extension comes from the URL. The URL is files' own, without
    // a leading slash.
    assert_eq!(r["data"]["url"], json!(format!("api/files/secured/file/FIN/{SCRATCH_FOLDER}/{name}.mp3")), "{r:?}");

    // A client FIN does not manage is refused, and nothing is written for it.
    let mut foreign = args.clone();
    foreign["fileClientCode"] = json!("SYSTEM");
    let r = run(get_request.as_ref(), foreign, auth, true, true).await.unwrap();
    assert_eq!(r["data"], json!("Client code is invalid"));

    // Found in FIN's secured files, with the bytes downloaded, then deleted.
    let (status, listed) = files_api(reqwest::Method::GET, &format!("/api/files/secured/{SCRATCH_FOLDER}?clientCode=FIN&size=100")).await;
    assert_eq!(status, 200);
    let listed: Value = serde_json::from_slice(&listed).unwrap();
    let names: Vec<&str> = listed["content"].as_array().unwrap().iter().filter_map(|f| f["name"].as_str()).collect();
    assert!(names.contains(&format!("{name}.mp3").as_str()), "{names:?}");
    let (status, bytes) = files_api(reqwest::Method::GET, &format!("/api/files/secured/file/FIN/{SCRATCH_FOLDER}/{name}.mp3")).await;
    assert_eq!((status, bytes), (200, recording));
    let (status, deleted) = files_api(reqwest::Method::DELETE, &format!("/api/files/secured/{SCRATCH_FOLDER}?clientCode=FIN")).await;
    assert_eq!((status, deleted), (200, b"true".to_vec()));
    let (_, listed) = files_api(reqwest::Method::GET, &format!("/api/files/secured/{SCRATCH_FOLDER}?clientCode=FIN&size=100")).await;
    assert!(!String::from_utf8_lossy(&listed).contains(&name), "still listed after the delete");
}
