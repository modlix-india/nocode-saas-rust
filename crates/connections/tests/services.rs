//! The service layer over in-memory stores and local endpoints: connection reads, the
//! controller routes, REST dispatch, `CallRequest`'s events, auth-function tokens, and the
//! notification access rules.

mod common;

use std::sync::Arc;

use async_trait::async_trait;
use chrono::Duration;
use common::{caller, server, service, Canned, Functions, MemTokens, Store};
use connections::connection::{self, Connection, ConnectionType};
use connections::controller;
use connections::error::{ConnError, ConnResult};
use connections::mq::{prepare_event, EventMessage, Route};
use connections::notification::{prepare, HierarchyChecks, NotificationRequest};
use connections::rest::auth::{self, EventResult};
use connections::rest::call::{self, CallArgs, DownloadSink};
use connections::rest::{do_call, RestData, RestRequest};
use connections::tokens::{CoreToken, TokenStore, TokenType};
use serde_json::{json, Map, Value};

fn conn(v: Value) -> Connection {
    Connection::from_json(v).unwrap()
}

fn rest(name: &str, sub: &str, details: Value) -> Connection {
    conn(json!({"name": name, "appCode": "app", "clientCode": "SYSTEM", "isAppLevel": true,
                "connectionType": "REST_API", "connectionSubType": sub, "connectionDetails": details}))
}

#[tokio::test]
async fn connection_reads() {
    let mail = conn(json!({"name": "mail", "clientCode": "SYSTEM", "connectionType": "MAIL", "connectionSubType": "SMTP", "connectionDetails": {"host": "h"}}));
    let notif = conn(json!({"name": "note", "clientCode": "SYSTEM", "connectionType": "NOTIFICATION",
                             "connectionDetails": {"inapp": true, "mail": "mail", "blank": "", "gone": "nothing"}}));
    let store = Store(vec![mail.clone(), notif.clone(), conn(json!({"name": "bare", "clientCode": "FIN", "connectionType": "NOTIFICATION"}))]);
    let c = caller();
    assert!(connection::read(&store, &c, "mail", "app", "SYSTEM", ConnectionType::Mail).await.unwrap().is_some());
    assert!(connection::read(&store, &c, "mail", "app", "SYSTEM", ConnectionType::Ai).await.unwrap().is_none());
    assert!(connection::read(&store, &c, "none", "app", "SYSTEM", ConnectionType::Mail).await.unwrap().is_none());

    // readInternalConnection: a notification connection's details become the connections they name.
    let expanded = connection::read_internal_connection(&store, "note", "app", "SYSTEM", ConnectionType::Notification).await.unwrap().unwrap();
    let d = expanded.details().unwrap();
    assert_eq!(d["mail"]["name"], "mail");
    assert_eq!(d["blank"], "");
    assert!(!d.contains_key("gone"));
    assert!(!d.contains_key("inapp"), "`true` names no connection, so the key goes");
    assert!(connection::read_internal_connection(&store, "mail", "app", "SYSTEM", ConnectionType::Ai).await.unwrap().is_none());
    assert!(connection::read_internal_connection(&store, "bare", "app", "SYSTEM", ConnectionType::Notification).await.unwrap().is_none());
    assert!(connection::read_internal_connection(&store, "mail", "app", "SYSTEM", ConnectionType::Mail).await.unwrap().is_some());
    assert!(connection::read_internal_connection(&store, "x", "app", "SYSTEM", ConnectionType::Mail).await.unwrap().is_none());
    let bare_own = connection::read_internal_connection(&store, "bare", "app", "FIN", ConnectionType::Notification).await.unwrap();
    assert!(bare_own.unwrap().connection_details.is_none());

    // The internal notification and connection routes.
    let n = connection::notification_connections(&store, "note", "app", "SYSTEM", "SYSTEM").await.unwrap().unwrap();
    assert!(n.in_app);
    assert_eq!(n.mail.as_ref().unwrap().name(), "mail");
    assert_eq!(serde_json::to_value(&n).unwrap()["inApp"], json!(true));
    assert!(connection::notification_connections(&store, "mail", "app", "SYSTEM", "SYSTEM").await.unwrap().is_none());
    assert!(connection::notification_connections(&store, "bare", "app", "SYSTEM", "SYSTEM").await.unwrap().is_none());
    let store2 = Store(vec![
        conn(json!({"name": "n2", "connectionType": "NOTIFICATION", "connectionDetails": {"mail": ""}})),
        conn(json!({"name": "n3", "connectionType": "NOTIFICATION", "connectionDetails": {"mail": "n2", "inapp": false}})),
    ]);
    let n2 = connection::notification_connections(&store2, "n2", "a", "c", "c").await.unwrap().unwrap();
    assert!(!n2.in_app && n2.mail.is_none());
    let n3 = connection::notification_connections(&store2, "n3", "a", "c", "c").await.unwrap().unwrap();
    assert!(n3.in_app && n3.mail.is_none(), "a non-mail connection is no mail connection");
    assert!(connection::connection_of_type(&store, "mail", "a", "c", "c", ConnectionType::Mail).await.unwrap().is_some());
}

#[tokio::test]
async fn controller_routes() {
    let tokens = Arc::new(MemTokens::default());
    let svc = service(
        vec![
            conn(json!({"name": "mail", "connectionType": "MAIL", "connectionDetails": {}})),
            conn(json!({"name": "note", "connectionType": "NOTIFICATION", "connectionDetails": {"inapp": 1}})),
            rest("oa", "REST_API_OAUTH2", json!({"grantType": "CLIENT_CREDENTIALS", "tokenDetails": {"url": "http://127.0.0.1:1/t", "queryParams": {}}})),
        ],
        tokens.clone(),
        Functions::answering(None),
    );
    let c = caller();
    assert!(controller::internal_connection(&svc, "mail", "a", "c", "c", "MAIL").await.unwrap().is_some());
    assert!(controller::internal_connection(&svc, "mail", "a", "c", "c", "AI").await.unwrap().is_none());
    let e = controller::internal_connection(&svc, "mail", "a", "c", "c", "FAX").await.unwrap_err();
    assert_eq!(e.status(), http::StatusCode::BAD_REQUEST);
    assert!(controller::notification_connections(&svc, "note", "a", "c", "c").await.unwrap().unwrap().in_app);
    assert_eq!(controller::evoke_oauth(&svc, &c, "missing", Some("h")).await.unwrap(), None);
    assert_eq!(controller::oauth_callback(&svc, &c, Some("code"), Some("nope"), Some("h")).await.unwrap(), controller::CallbackOutcome::Empty);
    assert_eq!(controller::oauth_callback(&svc, &c, None, Some("nope"), Some("h")).await.unwrap(), controller::CallbackOutcome::FoundWithoutLocation);
    assert!(controller::revoke_token(&svc, &c, "oa").await.is_err());
    assert_eq!(controller::oauth2_token(&svc, &c, "oa", None, Some("SYSTEM")).await.unwrap(), None);
    assert_eq!(controller::oauth2_token(&svc, &c, "missing", Some("app"), Some("SYSTEM")).await.unwrap(), None);
    // A valid stored token is answered by the internal token route.
    tokens
        .create(&CoreToken {
            client_code: Some("SYSTEM".into()),
            app_code: Some("app".into()),
            connection_name: Some("oa".into()),
            token_type: Some(TokenType::Access),
            token: Some("t-1".into()),
            expires_at: Some(tokens.clock.now() + Duration::seconds(60)),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(controller::oauth2_token(&svc, &c, "oa", Some("app"), Some("SYSTEM")).await.unwrap().as_deref(), Some("t-1"));
}

#[tokio::test]
async fn rest_dispatch_and_call_events() {
    let (port, log) = server(vec![
        Canned::json(200, r#"{"ok":1}"#),
        Canned::json(404, r#"{"error":"missing"}"#),
        Canned { status: 200, headers: vec![("Content-Type".into(), "application/pdf".into())], body: b"%PDF".to_vec(), delay_ms: 0 },
    ])
    .await;
    let base = format!("http://127.0.0.1:{port}");
    let svc = service(
        vec![
            rest("basic", "REST_API_BASIC", json!({"baseUrl": base})),
            conn(json!({"name": "nosub", "clientCode": "SYSTEM", "connectionType": "REST_API", "connectionDetails": {"baseUrl": base}})),
        ],
        Arc::new(MemTokens::default()),
        Functions::answering(None),
    );
    let c = caller();
    let args = |name: &str, url: &str| CallArgs {
        connection_name: name.into(),
        url: url.into(),
        method: "GET".into(),
        headers: json!({"X-A": "1"}).as_object().unwrap().clone(),
        query_params: json!({"q": "1"}).as_object().unwrap().clone(),
        ..Default::default()
    };

    let ok = call::call(&svc, &c, &args("basic", "/a"), None).await.unwrap().unwrap();
    assert_eq!(ok.len(), 1);
    assert_eq!(ok[0].result["data"], json!({"ok": 1.0}));
    assert_eq!(ok[0].result["statusCode"], json!(200));
    assert!(log.lock()[0].starts_with("GET /a?q=1 HTTP/1.1"));

    let err = call::call(&svc, &c, &args("basic", "/b"), None).await.unwrap().unwrap();
    assert_eq!((err[0].name, err[1].name), ("error", "output"));
    assert_eq!(err[0].result["data"], json!({"error": "missing"}));

    let missing = call::call(&svc, &c, &args("none", "/c"), None).await.unwrap().unwrap();
    assert_eq!(missing[0].result["data"], json!("Connection Not found"));
    assert_eq!(missing[0].result["statusCode"], json!(500));

    let nosub = call::call(&svc, &c, &args("nosub", "/c"), None).await.unwrap().unwrap();
    assert_eq!(nosub[0].result["data"], json!("value"));

    // Downloads: the binary body goes to the files service.
    struct Files(parking_lot::Mutex<Vec<(String, String, String)>>, bool);
    #[async_trait]
    impl DownloadSink for Files {
        async fn does_client_manage_client_code(&self, _: &str, _: &str) -> ConnResult<bool> {
            Ok(self.1)
        }
        async fn create_file(&self, ty: &str, cc: &str, _: bool, path: &str, name: &str, bytes: Vec<u8>) -> ConnResult<Map<String, Value>> {
            self.0.lock().push((ty.into(), cc.into(), format!("{path}{name}")));
            Ok(json!({"name": name, "size": bytes.len()}).as_object().unwrap().clone())
        }
    }
    let files = Files(parking_lot::Mutex::new(Vec::new()), true);
    let mut d = args("basic", "/report");
    d.download_as_a_file = true;
    d.file_name = "monthly".into();
    d.file_location = "/reports/".into();
    d.file_type = "secured".into();
    d.file_client_code = "FIN".into();
    let out = call::call(&svc, &c, &d, Some(&files)).await.unwrap().unwrap();
    assert_eq!(out[0].result["data"], json!({"name": "monthly.pdf", "size": 4}));
    assert_eq!(files.0.lock()[0], ("secured".to_string(), "FIN".to_string(), "/reports/monthly.pdf".to_string()));
    // A client the caller does not manage, and an anonymous caller.
    let deny = Files(parking_lot::Mutex::new(Vec::new()), false);
    let out = call::call(&svc, &c, &d, Some(&deny)).await.unwrap().unwrap();
    assert_eq!(out[0].result["data"], json!("Client code is invalid"));
    let mut anon = caller();
    anon.authenticated = false;
    assert!(call::call(&svc, &anon, &d, Some(&files)).await.unwrap().is_none());
    // Text is not a file.
    let (tport, _) = server(vec![Canned { status: 200, headers: vec![], body: b"plain".to_vec(), delay_ms: 0 }]).await;
    let svc2 = service(vec![rest("t", "REST_API_BASIC", json!({"baseUrl": format!("http://127.0.0.1:{tport}")}))], Arc::new(MemTokens::default()), Functions::answering(None));
    let mut t = args("t", "/x");
    t.download_as_a_file = true;
    t.file_client_code = String::new();
    let out = call::call(&svc2, &c, &t, Some(&files)).await.unwrap().unwrap();
    assert_eq!(out[0].result["data"], json!("Data is not a file"));
    // A bad argument fails the step itself.
    let mut bad = args("basic", "/x");
    bad.path_params = json!({"p": [1, 2]}).as_object().unwrap().clone();
    assert!(call::call(&svc, &c, &bad, None).await.is_err());

    // do_call without codes or a caller: the connection cannot be looked up.
    let r = do_call(&svc, &Default::default(), None, None, "basic", RestRequest::default(), false).await.unwrap();
    assert_eq!(r.data, RestData::Text("Connection Not found".into()));
}

fn auth_conn(base: &str, details: Value) -> Connection {
    let mut d = json!({"baseUrl": base, "authTokenFunctionName": "GetToken", "authTokenFunctionNamespace": "Zoho", "headerPrefix": "Zoho-oauthtoken"});
    for (k, v) in details.as_object().unwrap() {
        d[k] = v.clone();
    }
    rest("zoho", "REST_API_AUTH", d)
}

fn event(name: &str, result: Value) -> EventResult {
    EventResult { name: name.into(), result: result.as_object().unwrap().clone() }
}

#[tokio::test]
async fn auth_function_tokens() {
    let (port, log) = server(vec![Canned::json(200, "{}")]).await;
    let base = format!("http://127.0.0.1:{port}");
    let tokens = Arc::new(MemTokens::default());
    let functions = Functions::answering(Some(vec![event("output", json!({"accessToken": "tok-1", "expiresIn": 3600}))]));
    let svc = service(vec![auth_conn(&base, json!({}))], tokens.clone(), functions.clone());
    let c = caller();
    let args = CallArgs { connection_name: "zoho".into(), url: "/x".into(), method: "GET".into(), ..Default::default() };
    call::call(&svc, &c, &args, None).await.unwrap().unwrap();
    call::call(&svc, &c, &args, None).await.unwrap().unwrap();
    assert_eq!(*functions.1.lock(), 1, "the second call uses the stored token");
    assert!(log.lock()[0].contains("authorization: Zoho-oauthtoken tok-1"));
    let row = tokens.rows.lock()[0].clone();
    assert_eq!((row.client_code.as_deref(), row.app_code.as_deref(), row.is_revoked), (Some("SYSTEM"), Some("app"), Some(false)));

    let refuse = |events: Option<Vec<EventResult>>, details: Value| {
        let base = base.clone();
        async move {
            let svc = service(vec![auth_conn(&base, details)], Arc::new(MemTokens::default()), Functions::answering(events));
            let conn = svc.store.read_internal("zoho", "a", "c", "c").await.unwrap().unwrap();
            auth::access_token(&svc, &conn).await.unwrap_err().message().to_string()
        }
    };
    assert_eq!(
        refuse(Some(vec![event("errorOutput", json!({"error": "nope"}))]), json!({})).await,
        "Not able to create a token for the connection zoho: EventResult(name=errorOutput, result={error=\"nope\"})"
    );
    assert_eq!(refuse(None, json!({})).await, "Not able to create a token for the connection zoho: Zoho.GetToken produced no output");
    assert_eq!(refuse(Some(vec![]), json!({})).await, "Not able to create a token for the connection zoho: Zoho.GetToken raised no events");
    assert_eq!(
        refuse(Some(vec![event("output", json!({"expiresIn": 1}))]), json!({})).await,
        "Not able to create a token for the connection zoho: auth token function returned no 'accessToken'"
    );
    assert_eq!(
        refuse(Some(vec![event("output", json!({"accessToken": "a"}))]), json!({})).await,
        "Not able to create a token for the connection zoho: auth token function returned no 'expiresIn'"
    );
    assert_eq!(
        refuse(Some(vec![event("output", json!({"accessToken": " ", "expiresIn": "60"}))]), json!({})).await,
        "Not able to create a token for the connection zoho: auth token function returned a blank 'accessToken'"
    );
    assert_eq!(
        refuse(Some(vec![]), json!({"authTokenFunctionName": ""})).await,
        "Not able to create a token for the connection zoho: authTokenFunctionName is not configured"
    );
    // The event values as Gson reads them.
    for (token, expires, ok) in [
        (json!(true), json!("60"), true),
        (json!(12345), json!(60.9), true),
        (json!(["one"]), json!([60]), true),
        (json!({}), json!(60), false),
        (json!([1, 2]), json!(60), false),
        (json!("t"), json!("x"), false),
        (json!("t"), json!({}), false),
    ] {
        let svc = service(vec![auth_conn(&base, json!({}))], Arc::new(MemTokens::default()), Functions::answering(Some(vec![event("output", json!({"accessToken": token, "expiresIn": expires}))])));
        let conn = svc.store.read_internal("zoho", "a", "c", "c").await.unwrap().unwrap();
        assert_eq!(auth::access_token(&svc, &conn).await.is_ok(), ok, "{token} {expires}");
    }
    // No prefix: the token alone.
    let (p2, log2) = server(vec![Canned::json(200, "{}")]).await;
    let plain = auth_conn(&format!("http://127.0.0.1:{p2}"), json!({"headerPrefix": null}));
    let svc = service(vec![plain.clone()], Arc::new(MemTokens::default()), Functions::answering(Some(vec![event("output", json!({"accessToken": "bare", "expiresIn": 60}))])));
    auth::call(&svc, &c, &plain, RestRequest { url: "/x".into(), ..Default::default() }, false).await.unwrap();
    assert!(log2.lock()[0].contains("authorization: bare"));
    let svc = service(vec![], Arc::new(MemTokens::default()), Functions::answering(None));
    let no_details = conn(json!({"name": "zoho"}));
    assert_eq!(
        auth::access_token(&svc, &no_details).await.unwrap_err().message(),
        "Not able to create a token for the connection zoho: connection has no connection details"
    );
}

struct Checks(bool);
#[async_trait]
impl HierarchyChecks for Checks {
    async fn is_user_part_of_hierarchy(&self, _: i128, _: &str) -> ConnResult<bool> {
        Ok(self.0)
    }
    async fn does_client_manage_client(&self, _: u64, _: i128) -> ConnResult<bool> {
        Ok(self.0)
    }
    async fn does_client_manage_client_code(&self, _: &str, _: &str) -> ConnResult<bool> {
        Ok(self.0)
    }
}

#[tokio::test]
async fn notification_access_rules() {
    let route = Route::notifications();
    let mut c = caller();
    c.url_client_code = Some("FIN".into());
    c.draft = true;
    c.debug = Some("d".into());
    let req = |ty: &str, id: Option<i128>, code: Option<&str>| NotificationRequest {
        target_type: ty.into(),
        target_id: id,
        target_code: code.map(str::to_string),
        notification_name: Some("n".into()),
        ..Default::default()
    };
    let (key, m) = prepare(&route, &Checks(true), &c, req("User Id", Some(7), None)).await.unwrap().unwrap();
    assert_eq!(key, "notifications2");
    assert_eq!((m.client_code.as_deref(), m.url_client_code.as_deref(), m.app_code.as_deref()), (Some("FIN"), Some("FIN"), Some("app")));
    assert!(m.draft);
    assert_eq!(m.x_debug.as_deref(), Some("d"));
    assert!(prepare(&route, &Checks(false), &c, req("User Id", Some(7), None)).await.unwrap().is_none());
    assert!(prepare(&route, &Checks(true), &c, req("User Id", Some(0), None)).await.unwrap().is_none());
    assert!(prepare(&route, &Checks(true), &c, req("Client Id", Some(3), None)).await.unwrap().is_some());
    assert!(prepare(&route, &Checks(true), &c, req("Client Id", None, None)).await.unwrap().is_none());
    assert!(prepare(&route, &Checks(true), &c, req("Client Code", None, Some("FIN"))).await.unwrap().is_some());
    assert!(prepare(&route, &Checks(true), &c, req("Client Code", None, Some(""))).await.unwrap().is_none());
    assert!(prepare(&route, &Checks(true), &c, req("Group", Some(1), None)).await.unwrap().is_none());
    let mut sys = caller();
    sys.system_client = true;
    assert!(prepare(&route, &Checks(false), &sys, req("User Id", Some(0), None)).await.unwrap().is_some());
    assert!(prepare(&route, &Checks(false), &sys, req("Client Id", Some(0), None)).await.unwrap().is_some());
    assert!(prepare(&route, &Checks(false), &sys, req("Client Code", None, None)).await.unwrap().is_some());
    assert!(prepare(&route, &Checks(true), &Default::default(), req("User Id", Some(1), None)).await.unwrap().is_none());

    let (key, body) = prepare_event(&Route::events(), &c, EventMessage { event_name: Some("E".into()), ..Default::default() });
    assert_eq!(key, "events2");
    assert!(body.contains("\"draft\" : true") && body.contains("\"xdebug\" : \"d\""));
    let _ = ConnError::other("unused");
}
