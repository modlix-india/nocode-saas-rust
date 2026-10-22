//! Every route through `handlers::router`, against a fake security and a `RUSTTEST_notif_*`
//! scratch schema (gated: `NOTIFICATION_LOCAL_STACK=1`, dropped afterwards). The expected
//! answers are the ones Java notification gave on 2026-10-16.

mod common;

use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use axum::middleware;
use axum::response::Response;
use axum::Router;
use common::{context, local_stack, with_scratch, Answer, Fake, AUTH_PATH};
use futures::StreamExt;
use notification::calls::DirectoryClient;
use notification::dao::Dao;
use notification::handlers::{router, AppState};
use notification::inapp::{InAppService, InAppSink};
use notification::push::Push;
use notification::model::{CoreNotification, NotificationUser};
use notification::preference::PreferenceService;
use notification::sse::Hub;
use platform::cache::CacheService;
use platform::security::SecurityClient;
use platform::upstream::Upstream;
use serde_json::{json, Map, Value};
use sqlx::MySqlPool;
use tower::ServiceExt;

const BASIC: &str = "Basic MTQyOlBhc3NAMTIzNA==";

struct Rig {
    app: Router,
    security: Arc<Fake>,
    hub: Arc<Hub>,
    inapp: InAppService,
    pool: MySqlPool,
}

async fn rig(pool: MySqlPool) -> Rig {
    let (security, base) = Fake::start().await;
    security.answer("GET", AUTH_PATH, Answer::json(context(true)));
    let hub = Hub::new(16);
    let dao = Dao::new(pool.clone());
    let st = Arc::new(AppState {
        security: SecurityClient::new(Upstream::fixed(&[&base]), 0).unwrap(),
        inapp: InAppService { dao: dao.clone(), push: Push::local(hub.clone()) },
        prefs: PreferenceService {
            dao: dao.clone(),
            directory: DirectoryClient::new(Upstream::fixed(&[&base]), Duration::from_secs(5)).unwrap(),
            cache: Some(CacheService::new("cmn", "evictionChannel", None).unwrap()),
        },
        hub: hub.clone(),
        server_port: 8114,
    });
    Rig { app: with_scope(router(st)), security, hub: hub.clone(), inapp: InAppService { dao, push: Push::local(hub) }, pool }
}

/// The routes with the message scope the service runs them in (`platform::app::Service`).
fn with_scope(app: Router) -> Router {
    app.layer(middleware::from_fn(platform::messages::layer))
}

struct Got {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: String,
}

impl Got {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// A coded error: its status and code (the body checked for the platform's shape).
    fn coded(&self) -> (StatusCode, String) {
        let v = self.json();
        assert_eq!(v["stackTrace"], "", "{}", self.body);
        assert!(v["exceptionId"].as_str().is_some_and(|i| !i.is_empty()), "{}", self.body);
        assert!(v["message"].as_str().is_some_and(|m| !m.is_empty() && !m.contains('{')), "{}", self.body);
        assert_eq!(self.header("content-type"), Some("application/json"));
        (self.status, v["code"].as_str().unwrap_or("").to_string())
    }

    /// An unexpected failure: 500 with the error id in the message.
    fn is_internal_500(&self) -> bool {
        self.coded() == (StatusCode::INTERNAL_SERVER_ERROR, "COMMON.INTERNAL_ERROR".to_string())
    }
}

fn is(status: StatusCode, code: &str) -> (StatusCode, String) {
    (status, code.to_string())
}

async fn call(app: &Router, req: Request<Body>) -> Got {
    let resp: Response = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = String::from_utf8(to_bytes(resp.into_body(), 1 << 20).await.unwrap().to_vec()).unwrap();
    Got { status, headers, body }
}

fn req(method: &str, uri: &str) -> axum::http::request::Builder {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", BASIC)
        .header("clientCode", "SYSTEM")
        .header("appCode", "appbuilder")
        .header("host", "localhost:8114")
}

async fn get(app: &Router, uri: &str) -> Got {
    call(app, req("GET", uri).body(Body::empty()).unwrap()).await
}

async fn post(app: &Router, uri: &str, body: &str) -> Got {
    call(app, req("POST", uri).header("content-type", "application/json").body(Body::from(body.to_string())).unwrap()).await
}

fn notification() -> CoreNotification {
    CoreNotification::from_json(&json!({
        "name": "rsNotifParity", "notificationType": "ALERT", "defaultLanguage": "en",
        "channelTemplates": {"inapp": {"templateParts": {"en": {
            "title": "H\u{e9}llo ${who}", "description": "Line one\nline \"two\" ${n}", "image": "api/files/x.svg", "url": "/page/${who}"
        }}}}
    }))
    .unwrap()
}

fn users(ids: &[i64]) -> Vec<NotificationUser> {
    ids.iter().map(|i| NotificationUser { id: Some(*i), ..Default::default() }).collect()
}

fn payload(who: &str) -> Map<String, Value> {
    json!({"who": who, "n": 3}).as_object().unwrap().clone()
}

#[tokio::test]
#[ignore = "needs the local MySQL: NOTIFICATION_LOCAL_STACK=1"]
async fn the_security_gate_and_spring_answers() {
    if !local_stack() {
        return;
    }
    with_scratch(|pool, _| async move {
        let r = rig(pool).await;
        // Not signed in: Spring Security's 403, with the servlet header set, now asking to sign in.
        r.security.answer("GET", AUTH_PATH, Answer::json(context(false)));
        let anonymous = Request::builder().uri("/api/notification/new?appCode=a").header("host", "localhost:8114").body(Body::empty()).unwrap();
        let g = call(&r.app, anonymous).await;
        assert_eq!(g.coded(), is(StatusCode::FORBIDDEN, "COMMON.SIGN_IN_REQUIRED"));
        assert_eq!(g.json()["message"], "Please sign in to continue.");
        assert_eq!(g.header("x-frame-options"), Some("SAMEORIGIN"));
        assert_eq!(g.header("content-security-policy"), Some("frame-ancestors 'self'"));
        assert_eq!(g.header("cache-control"), Some("no-cache, no-store, max-age=0, must-revalidate"));
        assert!(g.headers.get("referrer-policy").is_none());
        assert_eq!(g.headers.get_all("vary").iter().count(), 3);
        // Credentials security does not accept: "signed out".
        let g = get(&r.app, "/api/notification/new?appCode=a").await;
        assert_eq!(g.coded(), is(StatusCode::FORBIDDEN, "COMMON.SIGNED_OUT"));
        assert_eq!(g.json()["message"], "You're signed out. Please sign in again.");
        // Not signed in on an unmapped path and an unsupported method: still the 403.
        assert_eq!(get(&r.app, "/api/notification/nothing").await.status, StatusCode::FORBIDDEN);
        assert_eq!(call(&r.app, req("DELETE", "/api/notification/preference").body(Body::empty()).unwrap()).await.status, StatusCode::FORBIDDEN);
        // A token security refuses.
        r.security.answer("GET", AUTH_PATH, Answer::error(401, "expired"));
        let g = get(&r.app, "/api/notification/new").await;
        assert_eq!(g.coded(), is(StatusCode::FORBIDDEN, "COMMON.SIGNED_OUT"));
        assert!(g.json()["debugMessage"].as_str().unwrap().contains("refused"));
        // OPTIONS needs no caller: Spring's Allow answer, or the unmapped path's 404.
        let o = call(&r.app, req("OPTIONS", "/api/notification/preference").body(Body::empty()).unwrap()).await;
        assert_eq!((o.status, o.header("allow"), o.header("accept-patch")), (StatusCode::OK, Some("GET,HEAD,POST,OPTIONS"), Some("")));
        let o = call(&r.app, req("OPTIONS", "/api/notification/new").body(Body::empty()).unwrap()).await;
        assert_eq!(o.header("allow"), Some("GET,HEAD,OPTIONS"));
        let o = call(&r.app, req("OPTIONS", "/api/notification/nothing").body(Body::empty()).unwrap()).await;
        assert_eq!(o.coded(), is(StatusCode::NOT_FOUND, "COMMON.NOT_FOUND"));
        // A CORS preflight, answered before security.
        let pre = call(
            &r.app,
            req("OPTIONS", "/api/notification/subscribe")
                .header("origin", "http://x.com")
                .header("access-control-request-method", "GET")
                .header("access-control-request-headers", "authorization,clientcode")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(pre.status, StatusCode::OK);
        assert_eq!(pre.header("access-control-allow-origin"), Some("*"));
        assert_eq!(pre.header("access-control-allow-methods"), Some("GET"));
        assert_eq!(pre.header("access-control-allow-headers"), Some("authorization, clientcode"));
        assert!(pre.headers.get("access-control-max-age").is_none());
        // A cross-origin request carries the origin header.
        let x = call(&r.app, req("GET", "/api/notification/new").header("origin", "http://x.com").body(Body::empty()).unwrap()).await;
        assert_eq!(x.header("access-control-allow-origin"), Some("*"));

        // Signed in: unmapped paths are 404s, unsupported methods 405s.
        r.security.answer("GET", AUTH_PATH, Answer::json(context(true)));
        assert_eq!(get(&r.app, "/api/notification/nothing").await.coded(), is(StatusCode::NOT_FOUND, "COMMON.NOT_FOUND"));
        assert_eq!(get(&r.app, "/api/notification/new/").await.coded(), is(StatusCode::NOT_FOUND, "COMMON.NOT_FOUND"));
        let d = call(&r.app, req("DELETE", "/api/notification/preference?appCode=x").body(Body::empty()).unwrap()).await;
        assert_eq!(d.coded(), is(StatusCode::METHOD_NOT_ALLOWED, "COMMON.METHOD_NOT_ALLOWED"));
        assert_eq!(d.json()["message"], "This address does not accept DELETE requests.");
        let p = call(&r.app, req("POST", "/api/notification/notifications").body(Body::empty()).unwrap()).await;
        assert_eq!(p.coded(), is(StatusCode::METHOD_NOT_ALLOWED, "COMMON.METHOD_NOT_ALLOWED"));
        let head = call(&r.app, req("HEAD", "/api/notification/new").body(Body::empty()).unwrap()).await;
        assert_eq!((head.status, head.body.as_str()), (StatusCode::OK, ""));

        // Security unreachable: a 500.
        let dead = Arc::new(AppState {
            security: SecurityClient::new(Upstream::fixed(&["http://127.0.0.1:1"]), 0).unwrap(),
            inapp: InAppService { dao: Dao::new(r.pool.clone()), push: Push::local(r.hub.clone()) },
            prefs: PreferenceService {
                dao: Dao::new(r.pool.clone()),
                directory: DirectoryClient::new(Upstream::fixed(&["http://127.0.0.1:1"]), Duration::from_secs(1)).unwrap(),
                cache: None,
            },
            hub: r.hub.clone(),
            server_port: 8114,
        });
        assert!(get(&with_scope(router(dead)), "/api/notification/new").await.is_internal_500());
    })
    .await;
}

#[tokio::test]
#[ignore = "needs the local MySQL: NOTIFICATION_LOCAL_STACK=1"]
async fn in_app_notifications_count_list_and_mark_read() {
    if !local_stack() {
        return;
    }
    with_scratch(|pool, _| async move {
        let r = rig(pool).await;
        // Nothing yet.
        let g = get(&r.app, "/api/notification/new?appCode=rsapp").await;
        assert_eq!((g.status, g.body.as_str(), g.header("content-type")), (StatusCode::OK, "0", Some("application/json")));
        let g = get(&r.app, "/api/notification/notifications?appCode=rsapp").await;
        assert_eq!(
            g.json(),
            json!({"pageable": {"pageNumber": 0, "pageSize": 20, "sort": [], "offset": 0, "unpaged": false, "paged": true},
                   "last": true, "totalElements": 0, "totalPages": 0, "first": true, "sort": [], "numberOfElements": 0,
                   "size": 20, "number": 0, "empty": true})
        );

        // Two sends for 142 (and one other user), in different seconds so the order is fixed.
        r.inapp.send_in_app(&users(&[142, 7]), &notification(), Some("rsapp"), Some("Parity"), &payload("Ann")).await.unwrap();
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let mut info = notification();
        info.notification_type = Some("INFO".into());
        r.inapp.send_in_app(&users(&[142]), &info, Some("rsapp"), None, &payload("Bob")).await.unwrap();

        assert_eq!(get(&r.app, "/api/notification/new?appCode=rsapp").await.body, "2");
        assert_eq!(get(&r.app, "/api/notification/new?appCode=rsapp&type=ALERT").await.body, "1");
        assert_eq!(get(&r.app, "/api/notification/new?appCode=rsapp&type=").await.body, "2", "a blank type filters nothing");
        assert_eq!(get(&r.app, "/api/notification/new?appCode=").await.body, "0", "a blank app code counts nothing");
        assert_eq!(get(&r.app, "/api/notification/new").await.body, "0", "the appCode header is appbuilder");
        let by_header = call(&r.app, req("GET", "/api/notification/new").header("appcode", "rsapp").body(Body::empty()).unwrap()).await;
        // The request carries two appCode headers now; Spring joins them.
        assert_eq!(by_header.body, "0");

        // A filtered page leaves the other row unread.
        let g = get(&r.app, "/api/notification/notifications?appCode=rsapp&category=Default").await;
        let content = g.json()["content"].clone();
        assert_eq!(content.as_array().unwrap().len(), 1);
        assert_eq!(content[0]["title"], "H\u{e9}llo Bob");
        assert_eq!(content[0]["notificationCategory"], "Default");
        assert!(content[0].get("readAt").is_none(), "the page shows the rows as they were read");
        assert!(content[0].get("type").is_none(), "Java never fills `type`");
        assert_eq!(get(&r.app, "/api/notification/new?appCode=rsapp").await.body, "1");

        // The full page, newest first; then everything is read.
        let g = get(&r.app, "/api/notification/notifications?appCode=rsapp&size=1&sort=title,desc").await;
        let v = g.json();
        assert_eq!(v["content"][0]["title"], "H\u{e9}llo Bob");
        assert!(v["content"][0]["readAt"].as_i64().is_some(), "read by the filtered page");
        // A full first page: the supplier's -1, which PageImpl replaces with the page's own count.
        assert_eq!((v["totalElements"].clone(), v["totalPages"].clone(), v["last"].clone()), (json!(1), json!(1), json!(true)));
        assert_eq!(v["pageable"]["sort"][0]["property"], "title");
        let g = get(&r.app, "/api/notification/notifications?appCode=rsapp&page=1&size=1").await;
        let v = g.json();
        assert_eq!(v["content"][0]["title"], "H\u{e9}llo Ann");
        assert_eq!(v["content"][0]["message"], "Line one\nline \"two\" 3");
        assert_eq!(v["content"][0]["url"], "/page/Ann");
        assert_eq!(v["content"][0]["mimeUrl"], "api/files/x.svg");
        assert!(v["content"][0]["createdAt"].as_i64().unwrap() > 1_700_000_000);
        assert_eq!(get(&r.app, "/api/notification/new?appCode=rsapp").await.body, "0");
        let g = get(&r.app, "/api/notification/notifications?appCode=rsapp&page=5&size=5&type=ALERT").await;
        assert_eq!(g.json()["totalElements"], -1);
        let g = get(&r.app, "/api/notification/notifications").await;
        assert_eq!(g.json()["empty"], true, "appbuilder from the header has nothing");

        // The other user's row is untouched.
        let unread: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM notification_inapp WHERE USER_ID = 7 AND READ_AT IS NULL")
            .fetch_one(&r.pool)
            .await
            .unwrap();
        assert_eq!(unread.0, 1);
    })
    .await;
}

#[tokio::test]
#[ignore = "needs the local MySQL: NOTIFICATION_LOCAL_STACK=1"]
async fn in_app_send_rules() {
    if !local_stack() {
        return;
    }
    with_scratch(|pool, _| async move {
        let r = rig(pool).await;
        let p = payload("Ann");
        // No title: TITLE is NOT NULL, the insert fails and nothing is sent.
        let no_title = CoreNotification::from_json(&json!({"name": "n", "channelTemplates": {"inapp": {"templateParts": {"en": {"description": "d"}}}}})).unwrap();
        assert!(r.inapp.send_in_app(&users(&[1]), &no_title, Some("a"), None, &p).await.is_err());
        // Parts that render to nothing: no rows.
        let empty = CoreNotification::from_json(&json!({"name": "n", "channelTemplates": {"inapp": {"templateParts": {"en": {}}}}})).unwrap();
        r.inapp.send_in_app(&users(&[1]), &empty, Some("a"), None, &p).await.unwrap();
        // A null notification type, a null user id, no app code, a failing language expression.
        let mut null_type = notification();
        null_type.notification_type = None;
        assert!(r.inapp.send_in_app(&users(&[1]), &null_type, Some("a"), None, &p).await.is_err());
        assert!(r.inapp.send_in_app(&[NotificationUser::default()], &notification(), Some("a"), None, &p).await.is_err());
        assert!(r.inapp.send_in_app(&users(&[-1]), &notification(), Some("a"), None, &p).await.is_err());
        assert!(r.inapp.send_in_app(&users(&[1]), &notification(), None, None, &p).await.is_err());
        let mut bad_lang = notification();
        bad_lang.language_expression = Some("${nope}".into());
        assert!(r.inapp.send_in_app(&users(&[1]), &bad_lang, Some("a"), None, &p).await.is_err());
        // An empty category is Default.
        r.inapp.send_in_app(&users(&[1]), &notification(), Some("a"), Some(""), &p).await.unwrap();
        let rows: Vec<(String, String)> = sqlx::query_as("SELECT NOTIFICATION_CATEGORY, NOTIFICATION_TYPE FROM notification_inapp").fetch_all(&r.pool).await.unwrap();
        assert_eq!(rows, vec![("Default".to_string(), "ALERT".to_string())]);
    })
    .await;
}

#[tokio::test]
#[ignore = "needs the local MySQL: NOTIFICATION_LOCAL_STACK=1"]
async fn the_stream_delivers_notifications() {
    if !local_stack() {
        return;
    }
    with_scratch(|pool, _| async move {
        let r = rig(pool).await;
        let resp = r
            .app
            .clone()
            .oneshot(req("GET", "/api/notification/subscribe?appCode=rsapp").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let h = resp.headers().clone();
        assert_eq!(h["content-type"], "text/event-stream;charset=UTF-8");
        assert_eq!(h["cache-control"], "no-cache");
        assert_eq!(h["x-accel-buffering"], "no");
        assert_eq!(h["connection"], "keep-alive");
        assert_eq!(h["x-frame-options"], "SAMEORIGIN");
        assert!(h.get("pragma").is_none());
        let mut body = resp.into_body().into_data_stream();
        let init = String::from_utf8(body.next().await.unwrap().unwrap().to_vec()).unwrap();
        assert!(init.starts_with("event:init\ndata:connected\nid:") && init.ends_with("\nretry:5000\n\n"), "{init}");
        assert_eq!(r.hub.open_streams(), 1);

        r.inapp.send_in_app(&users(&[142, 7]), &notification(), Some("rsapp"), Some("Parity"), &payload("Ann")).await.unwrap();
        let event = String::from_utf8(body.next().await.unwrap().unwrap().to_vec()).unwrap();
        let id: (u64,) = sqlx::query_as("SELECT ID FROM notification_inapp WHERE USER_ID = 142").fetch_one(&r.pool).await.unwrap();
        let expected_head = format!(
            "event:notification\ndata:{{\ndata:  \"id\" : {},\ndata:  \"userId\" : 142,\ndata:  \"appCode\" : \"rsapp\",\ndata:  \"notificationName\" : \"rsNotifParity\",\ndata:  \"title\" : \"H\u{e9}llo Ann\",\ndata:  \"message\" : \"Line one\\nline \\\"two\\\" 3\",\ndata:  \"mimeUrl\" : \"api/files/x.svg\",\ndata:  \"notificationType\" : \"ALERT\"\ndata:}}\nid:",
            id.0
        );
        assert!(event.starts_with(&expected_head), "{event}");
        assert!(event.ends_with("\nretry:5000\n\n"));

        // Another app's notification does not reach this stream; the keepalive does.
        r.inapp.send_in_app(&users(&[142]), &notification(), Some("other"), None, &payload("X")).await.unwrap();
        assert_eq!(r.hub.heartbeat(), 1);
        assert_eq!(body.next().await.unwrap().unwrap(), ":keepalive\n\n");
        drop(body);
        assert_eq!(r.hub.open_streams(), 0);

        // appCode is required; a request that does not accept an event stream finds no handler.
        let g = get(&r.app, "/api/notification/subscribe").await;
        assert_eq!(g.coded(), is(StatusCode::BAD_REQUEST, "COMMON.PARAM_MISSING"));
        assert_eq!(g.json()["message"], "The request is missing the appCode parameter.");
        let g = call(&r.app, req("GET", "/api/notification/subscribe?appCode=a").header("accept", "application/json").body(Body::empty()).unwrap()).await;
        assert_eq!(g.coded(), is(StatusCode::NOT_ACCEPTABLE, "NOTIF.STREAM_NOT_ACCEPTABLE"));
        let ok = r
            .app
            .clone()
            .oneshot(req("GET", "/api/notification/subscribe?appCode=a").header("accept", "text/event-stream").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::OK);
    })
    .await;
}

#[tokio::test]
#[ignore = "needs the local MySQL: NOTIFICATION_LOCAL_STACK=1"]
async fn preferences_read_and_write() {
    if !local_stack() {
        return;
    }
    with_scratch(|pool, _| async move {
        let r = rig(pool).await;
        let url = "/api/notification/preference?appCode=rsapp";
        assert_eq!(get(&r.app, url).await.body, "{ }");
        // Create: the answer is what was sent, in the order sent.
        let p = post(&r.app, url, r#"{"zz":1,"a":{"y":2,"b":1.0},"n":null}"#).await;
        assert_eq!(p.status, StatusCode::OK);
        assert_eq!(p.body, "{\n  \"zz\" : 1,\n  \"a\" : {\n    \"y\" : 2,\n    \"b\" : 1.0\n  },\n  \"n\" : null\n}");
        // Read back in MySQL's key order.
        assert_eq!(get(&r.app, url).await.body, "{\n  \"a\" : {\n    \"b\" : 1.0,\n    \"y\" : 2\n  },\n  \"n\" : null,\n  \"zz\" : 1\n}");
        // Update.
        assert_eq!(post(&r.app, url, r#"{"email":false}"#).await.json(), json!({"email": false}));
        assert_eq!(get(&r.app, url).await.json(), json!({"email": false}));
        let by: (u64, u64) = sqlx::query_as("SELECT CREATED_BY, UPDATED_BY FROM notification_preference").fetch_one(&r.pool).await.unwrap();
        assert_eq!(by, (142, 142));
        // An empty map deletes the row.
        assert_eq!(post(&r.app, url, "{}").await.body, "{ }");
        assert_eq!(sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM notification_preference").fetch_one(&r.pool).await.unwrap().0, 0);
        // No body for a new row: a row with no preference, and an empty answer.
        let none = call(&r.app, req("POST", url).body(Body::empty()).unwrap()).await;
        assert_eq!((none.status, none.body.as_str()), (StatusCode::OK, ""));
        assert_eq!(get(&r.app, url).await.body, "{ }");
        // JSON null for the existing row: deleted.
        assert_eq!(post(&r.app, url, "null").await.body, "{ }");
        // An empty map for a new row is stored.
        assert_eq!(post(&r.app, url, "{}").await.body, "{ }");
        assert_eq!(sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM notification_preference").fetch_one(&r.pool).await.unwrap().0, 1);

        // Binding errors name what is wrong.
        let g = post(&r.app, url, "[1]").await;
        assert_eq!(g.coded(), is(StatusCode::BAD_REQUEST, "COMMON.BODY_INVALID"));
        assert_eq!(g.json()["message"], "The request body does not have the expected shape: a value should be an object.");
        assert_eq!(post(&r.app, url, "{nope").await.coded(), is(StatusCode::BAD_REQUEST, "COMMON.BODY_UNREADABLE"));
        let text = call(&r.app, req("POST", url).header("content-type", "text/plain").body(Body::from("{}")).unwrap()).await;
        assert_eq!(text.coded(), is(StatusCode::UNSUPPORTED_MEDIA_TYPE, "COMMON.BODY_NOT_JSON"));
        let bare = call(&r.app, req("POST", url).body(Body::from("{}")).unwrap()).await;
        assert_eq!(bare.coded(), is(StatusCode::UNSUPPORTED_MEDIA_TYPE, "COMMON.BODY_NOT_JSON"), "a body without a content type");
        assert_eq!(bare.json()["debugMessage"], "Content-Type 'application/octet-stream' is not supported");
        let big = call(&r.app, req("POST", url).header("content-type", "application/json").body(Body::from(vec![b' '; 16 * 1024 * 1024 + 1])).unwrap()).await;
        assert_eq!(big.coded(), is(StatusCode::PAYLOAD_TOO_LARGE, "COMMON.PAYLOAD_TOO_LARGE"));
        assert_eq!(get(&r.app, "/api/notification/preference").await.coded(), is(StatusCode::BAD_REQUEST, "COMMON.PARAM_MISSING"));
        assert_eq!(post(&r.app, "/api/notification/preference", "{}").await.coded(), is(StatusCode::BAD_REQUEST, "COMMON.PARAM_MISSING"));
        let g = get(&r.app, &format!("{url}&userId=abc")).await;
        assert_eq!(g.coded(), is(StatusCode::BAD_REQUEST, "COMMON.PARAM_INVALID"));
        assert_eq!(g.json()["message"], "The value of the userId parameter is not valid: it should be a whole number.");

        // Two rows for one user and app: jOOQ's fetchOne fails.
        sqlx::query("INSERT INTO notification_preference (USER_ID, APP_CODE, CREATED_BY, UPDATED_BY) VALUES (142, 'rsapp', 1, 1)")
            .execute(&r.pool)
            .await
            .unwrap();
        assert!(get(&r.app, url).await.is_internal_500());
    })
    .await;
}

#[tokio::test]
#[ignore = "needs the local MySQL: NOTIFICATION_LOCAL_STACK=1"]
async fn another_users_preference_needs_the_management_check() {
    if !local_stack() {
        return;
    }
    with_scratch(|pool, _| async move {
        let r = rig(pool).await;
        let sec = &r.security;
        sec.answer("GET", "/api/security/clients/internal/getClientByCode", Answer::json(json!({"id": 1, "code": "SYSTEM"})));
        sec.answer("GET", "/api/security/users/internal/", Answer::json(json!({"id": 7, "clientId": 4})));
        sec.answer("GET", "/api/security/clients/internal/isUserClientManageClient", Answer::json(json!(true)));
        let url = "/api/notification/preference?appCode=rsapp&userId=7";
        assert_eq!(post(&r.app, url, r#"{"x":1}"#).await.json(), json!({"x": 1}));
        assert_eq!(get(&r.app, url).await.json(), json!({"x": 1}));
        let row: (u64, u64) = sqlx::query_as("SELECT USER_ID, CREATED_BY FROM notification_preference").fetch_one(&r.pool).await.unwrap();
        assert_eq!(row, (7, 142), "stored for the named user, by the caller");
        // The check's arguments, in Java's order: the named user, its client, the caller's client.
        let check = sec.calls_to("/api/security/clients/internal/isUserClientManageClient").last().unwrap().clone();
        assert_eq!(check.query, "appCode=appbuilder&userId=7&userClientId=4&targetClientId=1");
        assert_eq!(sec.calls_to("/api/security/clients/internal/getClientByCode").last().unwrap().query, "clientCode=SYSTEM");
        assert_eq!(sec.calls_to("/api/security/users/internal/").last().unwrap().path, "/api/security/users/internal/7");

        // Not managed: the 403 Java raises, in plain words.
        sec.answer("GET", "/api/security/clients/internal/isUserClientManageClient", Answer::json(json!(false)));
        let g = get(&r.app, url).await;
        assert_eq!(g.coded(), is(StatusCode::FORBIDDEN, "NOTIF.USER_PREFERENCE_FORBIDDEN"));
        assert_eq!(g.json()["message"], "You can't manage this user's notification preferences: you don't manage their account.");
        assert_eq!(g.json()["debugMessage"], "User don't have access to this user Id : 7");
        // No answer: Java unboxes null.
        sec.answer("GET", "/api/security/clients/internal/isUserClientManageClient", Answer::empty());
        assert!(get(&r.app, url).await.is_internal_500());
        // An unknown user: Java dereferences null.
        sec.answer("GET", "/api/security/users/internal/", Answer::empty());
        assert!(get(&r.app, url).await.is_internal_500());
        // A Java service's error is relayed with its status and message.
        sec.answer("GET", "/api/security/users/internal/", Answer::error(400, "Please try again. A server error - 2026-10-16-bb6969"));
        let g = get(&r.app, url).await;
        assert_eq!(g.status, StatusCode::BAD_REQUEST);
        assert_eq!(g.json()["message"], "Please try again. A server error - 2026-10-16-bb6969");
        // A Rust unit's coded error is passed on as it came.
        let sent = json!({"exceptionId": "2026-10-17-aa", "code": "SEC.OBJECT_NOT_FOUND", "message": "We couldn't find the user.",
                          "stackTrace": "", "debugMessage": "x", "params": {}, "locale": "en"})
        .to_string();
        sec.answer("GET", "/api/security/users/internal/", Answer { status: 404, content_type: Some("application/json"), body: sent.clone() });
        let g = get(&r.app, url).await;
        assert_eq!((g.status, g.body.as_str()), (StatusCode::NOT_FOUND, sent.as_str()));
        assert_eq!(g.header("x-frame-options"), Some("SAMEORIGIN"));
        // An unknown client code.
        sec.answer("GET", "/api/security/clients/internal/getClientByCode", Answer::empty());
        assert!(get(&r.app, url).await.is_internal_500());
        // A negative id passes the checks in Java's order and then fails as a ULong.
        sec.answer("GET", "/api/security/clients/internal/getClientByCode", Answer::json(json!({"id": 1})));
        sec.answer("GET", "/api/security/users/internal/", Answer::json(json!({"id": -5, "clientId": 1})));
        sec.answer("GET", "/api/security/clients/internal/isUserClientManageClient", Answer::json(json!(true)));
        assert!(get(&r.app, "/api/notification/preference?appCode=rsapp&userId=-5").await.is_internal_500());
        // The caller's own id named explicitly.
        assert_eq!(get(&r.app, "/api/notification/preference?appCode=rsapp&userId=142").await.body, "{ }");
    })
    .await;
}
