//! The billing routes of security-admin over the fake schema: who may call them (the bare 401,
//! Spring's `Access Denied` for `@PreAuthorize`), how Spring reads their arguments (the `ULong`
//! binder, `@RequestParam`, `@RequestBody`), the refused generic lists, and the answers that need
//! no billing row (an unknown app, the webhook's no-ops). The billing tables are behind a pool
//! that cannot connect, so nothing here can write.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, Method, Request, StatusCode};
use common::*;
use security::admin::{Admin, AdminState};
use security::data::Db;
use security::internal::Internal;
use serde_json::{json, Value};
use tower::ServiceExt;

struct World {
    h: Harness,
    state: AdminState,
}

fn world() -> World {
    let h = harness();
    let pool = sqlx::mysql::MySqlPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(300))
        .connect_lazy("mysql://nobody:nothing@127.0.0.1:1/security")
        .unwrap();
    let db = Db::new(pool);
    let events = Arc::new(RecordingEvents::default());
    let internal = Arc::new(Internal { auth: h.auth.clone(), db: db.clone(), billing: Arc::new(db), wallet_events: events.clone() });
    let state = Arc::new(Admin { internal, events, files: None, hosting: Default::default() });
    World { h, state }
}

fn request(method: Method, uri: &str, headers: &[(&str, String)], body: Option<&str>) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri).header("host", "apps.local:8080");
    for (k, v) in headers {
        b = b.header(*k, v.as_str());
    }
    if body.is_some() {
        b = b.header(header::CONTENT_TYPE, "application/json");
    }
    b.body(Body::from(body.unwrap_or("").to_string())).unwrap()
}

struct Answer {
    status: StatusCode,
    ctype: Option<String>,
    text: String,
    json: Value,
}

async fn call(w: &World, method: Method, uri: &str, headers: &[(&str, String)], body: Option<&str>) -> Answer {
    let resp = security::admin::router(w.state.clone()).oneshot(request(method, uri, headers, body)).await.unwrap();
    let status = resp.status();
    let ctype = resp.headers().get(header::CONTENT_TYPE).map(|v| v.to_str().unwrap().to_string());
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let text = String::from_utf8_lossy(&bytes).into_owned();
    Answer { status, ctype, json: serde_json::from_str(&text).unwrap_or(Value::Null), text }
}

fn hdrs(client: &str, app: Option<&str>, token: Option<&str>) -> Vec<(&'static str, String)> {
    let mut v = vec![("clientCode", client.to_string()), ("X-Forwarded-Host", "apps.local".into()), ("X-Forwarded-Port", "443".into())];
    if let Some(a) = app {
        v.push(("appCode", a.to_string()));
    }
    if let Some(t) = token {
        v.push(("authorization", format!("Bearer {t}")));
    }
    v
}

/// A bearer token minted by security-auth over the same fake schema.
async fn token(w: &World, client: &str, app: &str, user: &str, password: &str) -> String {
    let body = json!({"userName": user, "password": password}).to_string();
    let resp = security::handlers::router(w.h.auth.clone())
        .oneshot(request(Method::POST, "/api/security/authenticate", &hdrs(client, Some(app), None), Some(&body)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v: Value = serde_json::from_slice(&to_bytes(resp.into_body(), 1 << 20).await.unwrap()).unwrap();
    v["accessToken"].as_str().unwrap().to_string()
}

async fn sys(w: &World) -> String {
    token(w, "SYSTEM", "appbuilder", "kirangrandhi", "Pass@1234").await
}

const P: &str = "/api/security";

#[tokio::test]
async fn anonymous_callers_get_a_bare_401_except_on_the_open_two() {
    let w = world();
    let anon = hdrs("SYSTEM", Some("appbuilder"), None);
    for (m, path) in [
        (Method::GET, "/billing-bundles"),
        (Method::GET, "/billing-bundles/1"),
        (Method::GET, "/billing-bundles/config/1"),
        (Method::POST, "/billing-configs"),
        (Method::GET, "/billing-configs/app/1"),
        (Method::GET, "/billing-profile"),
        (Method::POST, "/billing/quote"),
        (Method::POST, "/billing/repay"),
        (Method::GET, "/invoices"),
        (Method::GET, "/invoices/my"),
        (Method::GET, "/wallets/status"),
        (Method::POST, "/wallets/credit"),
        (Method::POST, "/wallets/1/adjust"),
    ] {
        let a = call(&w, m.clone(), &format!("{P}{path}"), &anon, None).await;
        assert_eq!((a.status, a.json["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("COMMON.SIGN_IN_REQUIRED")), "{m} {path}");
    }
    // The webhook and the serving bundles are open.
    let a = call(&w, Method::POST, &format!("{P}/billing/razorpay/webhook"), &anon, Some("not-json")).await;
    assert_eq!((a.status, a.text.as_str(), a.ctype.as_deref()), (StatusCode::OK, "OK", Some("text/plain;charset=UTF-8")));
    let a = call(&w, Method::POST, &format!("{P}/billing/razorpay/webhook"), &anon, None).await;
    assert_eq!((a.status, a.json["debugMessage"].as_str()), (StatusCode::BAD_REQUEST, Some("400 BAD_REQUEST \"No request body\"")));
    let a = call(&w, Method::GET, &format!("{P}/billing-bundles/serving"), &hdrs("SYSTEM", Some("nope"), None), None).await;
    assert_eq!((a.status, a.text.as_str()), (StatusCode::OK, "[ ]"));
    let a = call(&w, Method::GET, &format!("{P}/billing-bundles/serving"), &hdrs("SYSTEM", None, None), None).await;
    assert_eq!((a.status, a.json["debugMessage"].as_str()), (StatusCode::INTERNAL_SERVER_ERROR, Some(security::admin::billing::service::NULL_KEY)));
}

#[tokio::test]
async fn spring_reads_the_arguments_first() {
    let w = world();
    let t = sys(&w).await;
    let h = hdrs("SYSTEM", Some("appbuilder"), Some(&t));
    let mismatch = "400 BAD_REQUEST \"Type mismatch.\"";
    for (m, path) in [
        (Method::GET, "/billing-bundles/abc"),
        (Method::PUT, "/billing-bundles/-2"),
        (Method::PATCH, "/billing-bundles/x"),
        (Method::DELETE, "/billing-bundles/1.5"),
        (Method::GET, "/billing-bundles/config/abc"),
        (Method::GET, "/billing-configs/abc"),
        (Method::PUT, "/billing-configs/abc"),
        (Method::PATCH, "/billing-configs/abc"),
        (Method::DELETE, "/billing-configs/abc"),
        (Method::GET, "/billing-configs/app/abc"),
        (Method::GET, "/invoices/abc"),
        (Method::GET, "/invoices/abc/documents"),
        (Method::POST, "/wallets/abc/adjust?tokens=1&reason=x"),
        (Method::POST, "/wallets/5/adjust?tokens=x&reason=x"),
    ] {
        let a = call(&w, m.clone(), &format!("{P}{path}"), &h, Some("{}")).await;
        assert_eq!((a.status, a.json["debugMessage"].as_str()), (StatusCode::BAD_REQUEST, Some(mismatch)), "{m} {path}");
    }
    let missing = |n: &str| format!("400 BAD_REQUEST \"Required query parameter '{n}' is not present.\"");
    // `wallets/{walletId}/adjust` is off by default: Java's "Type mismatch." whatever the rest.
    for q in ["?reason=x", "?tokens=1", "?tokens=1&reason=x", ""] {
        let a = call(&w, Method::POST, &format!("{P}/wallets/5/adjust{q}"), &h, None).await;
        assert_eq!((a.status, a.json["debugMessage"].as_str()), (StatusCode::BAD_REQUEST, Some(mismatch)), "{q}");
    }
    let a = call(&w, Method::GET, &format!("{P}/wallets/lookup?appCode=a&urlClientCode=b"), &h, None).await;
    assert_eq!(a.json["debugMessage"].as_str(), Some(missing("clientCode").as_str()));
    let a = call(&w, Method::GET, &format!("{P}/wallets/lookup"), &h, None).await;
    assert_eq!(a.json["debugMessage"].as_str(), Some(missing("appCode").as_str()));
    let unreadable = Some("400 BAD_REQUEST \"Failed to read HTTP message\"");
    let no_body = Some("400 BAD_REQUEST \"No request body\"");
    for (m, path, body, expected) in [
        (Method::POST, "/billing/quote", "x", unreadable),
        (Method::POST, "/billing/quote", "", no_body),
        (Method::POST, "/billing/quote", "null", no_body),
        (Method::POST, "/billing/quote", r#"{"bundleId": -1}"#, unreadable),
        (Method::POST, "/billing/purchase", r#"{"tokens": "x"}"#, unreadable),
        (Method::POST, "/billing/purchase/order", "[1]", unreadable),
        (Method::POST, "/billing/repay", r#"{"invoiceId": true}"#, unreadable),
        (Method::POST, "/wallets/credit", r#"{"tokens": {}}"#, unreadable),
        (Method::POST, "/billing-bundles", r#"{"bundleType": "BIG"}"#, unreadable),
        (Method::POST, "/billing-configs", r#"{"paymentGatewayConfig": [1]}"#, unreadable),
        (Method::PUT, "/billing-bundles/1", "[]", unreadable),
        (Method::PUT, "/billing-profile", r#"{"city": []}"#, unreadable),
        (Method::PATCH, "/billing-configs/1", "x", unreadable),
        (Method::POST, "/billing-bundles/query", "{", unreadable),
        (Method::POST, "/billing-configs/query", r#"{"sort": [{"direction": "UP", "property": "id"}]}"#, unreadable),
        (Method::POST, "/invoices/query", "[", unreadable),
    ] {
        let a = call(&w, m.clone(), &format!("{P}{path}"), &h, Some(body)).await;
        assert_eq!((a.status, a.json["debugMessage"].as_str()), (StatusCode::BAD_REQUEST, expected), "{m} {path} {body}");
    }
    // An unmapped method on a mapped path.
    let a = call(&w, Method::PUT, &format!("{P}/billing/quote"), &h, None).await;
    assert_eq!(a.status, StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn generic_lists_are_refused() {
    let w = world();
    let t = sys(&w).await;
    let h = hdrs("SYSTEM", Some("appbuilder"), Some(&t));
    let a = call(&w, Method::GET, &format!("{P}/billing-bundles?size=2&label=x"), &h, None).await;
    assert_eq!((a.status, coded(&a.json, "Listing all billing bundles is not permitted")), (StatusCode::FORBIDDEN, ("SEC.BUNDLE_LIST_FORBIDDEN".into(), true)));
    let a = call(&w, Method::POST, &format!("{P}/billing-bundles/query"), &h, Some("{}")).await;
    assert_eq!(a.status, StatusCode::FORBIDDEN);
    let a = call(&w, Method::GET, &format!("{P}/billing-configs"), &h, None).await;
    assert_eq!(
        (a.status, coded(&a.json, "Permission/Role list billing configs is required to use this operation")),
        (StatusCode::FORBIDDEN, ("SEC.BILLING_FORBIDDEN".into(), true))
    );
    let a = call(&w, Method::POST, &format!("{P}/billing-configs/query"), &h, Some(r#"{"size": 1}"#)).await;
    assert_eq!(a.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn pre_authorize_refusals_are_springs() {
    let w = world();
    let t = token(&w, "BUS", "crm", "member", "memberpw").await;
    let h = hdrs("BUS", Some("crm"), Some(&t));
    for (m, path, body) in [
        (Method::POST, "/billing-bundles", Some("{}")),
        (Method::PUT, "/billing-bundles/1", Some("{}")),
        (Method::DELETE, "/billing-bundles/1", None),
        (Method::POST, "/billing-configs", Some("{}")),
        (Method::PUT, "/billing-configs/1", Some("{}")),
        (Method::DELETE, "/billing-configs/1", None),
        (Method::GET, "/billing-profile", None),
        (Method::PUT, "/billing-profile", Some("{}")),
        (Method::POST, "/billing/purchase", Some(r#"{"bundleId": 1}"#)),
        (Method::POST, "/billing/purchase/order", Some(r#"{"bundleId": 1}"#)),
        (Method::POST, "/billing/quote", Some(r#"{"bundleId": 1}"#)),
        (Method::POST, "/billing/repay", Some(r#"{"invoiceId": 1}"#)),
        (Method::GET, "/invoices", None),
        (Method::POST, "/invoices/query", Some("{}")),
        (Method::GET, "/invoices/1", None),
        (Method::GET, "/invoices/1/documents", None),
        (Method::GET, "/wallets", None),
        (Method::GET, "/wallets/lookup?appCode=a&urlClientCode=b&clientCode=c", None),
        (Method::POST, "/wallets/credit", Some("{}")),
    ] {
        let a = call(&w, m.clone(), &format!("{P}{path}"), &h, body).await;
        assert_eq!((a.status, a.ctype.as_deref(), a.json["code"].as_str()), (StatusCode::FORBIDDEN, Some("application/json"), Some("COMMON.PERMISSION_REQUIRED")), "{m} {path}");
        assert!(a.json["debugMessage"].as_str().unwrap().starts_with("Access Denied: needs Authorities."), "{m} {path}");
    }
}

#[tokio::test]
async fn answers_that_need_no_billing_row() {
    let w = world();
    let t = sys(&w).await;
    let nope = hdrs("SYSTEM", Some("nope"), Some(&t));
    let a = call(&w, Method::GET, &format!("{P}/billing-profile"), &nope, None).await;
    assert_eq!((a.status, a.text.as_str()), (StatusCode::OK, "{ }"));
    let a = call(&w, Method::PUT, &format!("{P}/billing-profile"), &nope, Some(r#"{"legalName": "x"}"#)).await;
    assert_eq!((a.status, a.text.as_str()), (StatusCode::OK, ""));
    let a = call(&w, Method::GET, &format!("{P}/wallets"), &nope, None).await;
    assert_eq!((a.status, a.text.as_str()), (StatusCode::NO_CONTENT, ""));
    let a = call(&w, Method::GET, &format!("{P}/wallets/status"), &nope, None).await;
    assert_eq!(a.text, "{\n  \"status\" : \"ACTIVE\"\n}");
    let a = call(&w, Method::GET, &format!("{P}/wallets/plan"), &nope, None).await;
    assert_eq!(a.text, "{ }");
    let a = call(&w, Method::GET, &format!("{P}/wallets/transactions"), &nope, None).await;
    assert_eq!((a.json["totalElements"].as_i64(), a.json["pageable"]["pageSize"].as_i64()), (Some(0), Some(20)));
    let keys: Vec<&String> = a.json.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["pageable", "totalPages", "totalElements", "last", "sort", "first", "numberOfElements", "size", "number", "empty"]);
    for path in ["/invoices", "/invoices/my", "/invoices?status=PAID&size=2"] {
        let a = call(&w, Method::GET, &format!("{P}{path}"), &nope, None).await;
        assert_eq!((a.status, a.text.as_str()), (StatusCode::OK, ""), "{path}");
    }
    let a = call(&w, Method::POST, &format!("{P}/invoices/query"), &nope, Some(r#"{"size": 2}"#)).await;
    assert_eq!((a.status, a.text.as_str()), (StatusCode::OK, ""));
    let missing_app = hdrs("SYSTEM", None, Some(&t));
    for path in ["/billing-profile", "/wallets", "/wallets/status", "/wallets/plan", "/wallets/transactions", "/invoices", "/invoices/my"] {
        let a = call(&w, Method::GET, &format!("{P}{path}"), &missing_app, None).await;
        assert_eq!((a.status, a.json["debugMessage"].as_str()), (StatusCode::INTERNAL_SERVER_ERROR, Some(security::admin::billing::service::NULL_KEY)), "{path}");
    }
    // Wallet credit with an app that does not exist: refused before any wallet is touched.
    let a = call(&w, Method::POST, &format!("{P}/wallets/credit"), &nope, Some(r#"{"appCode": "nope", "urlClientCode": "SYSTEM", "clientCode": "BUS", "tokens": 1}"#)).await;
    assert_eq!(
        (a.status, coded(&a.json, "Permission/Role the application is required to use this operation")),
        (StatusCode::FORBIDDEN, ("SEC.BILLING_FORBIDDEN".into(), true))
    );
    let a = call(&w, Method::GET, &format!("{P}/wallets/lookup?appCode=nope&urlClientCode=SYSTEM&clientCode=BUS"), &nope, None).await;
    assert_eq!(a.status, StatusCode::FORBIDDEN);
    // The webhook's unparseable or unhandled bodies.
    for body in ["[1]", r#"{"event": "refund.created"}"#, r#"{"event": "payment_link.paid", "payload": {}}"#] {
        let a = call(&w, Method::POST, &format!("{P}/billing/razorpay/webhook"), &nope, Some(body)).await;
        assert_eq!((a.status, a.text.as_str()), (StatusCode::OK, "OK"), "{body}");
    }
}

/// `[billing] serve_wallet_adjust = true`: the route is the service's, in Spring's order (the
/// path, `tokens`, `reason`, then `@PreAuthorize`).
#[tokio::test]
async fn wallet_adjust_when_it_is_served() {
    use security::admin::billing::settings::BillingSettings;
    let w = world();
    let on = BillingSettings { serve_wallet_adjust: true, ..Default::default() };
    let router = || security::admin::billing::router_with(on.clone()).with_state(w.state.clone());
    let send = |uri: String, headers: Vec<(&'static str, String)>| {
        let r = router();
        async move {
            let resp = r.oneshot(request(Method::POST, &uri, &headers, None)).await.unwrap();
            let status = resp.status();
            let text = String::from_utf8_lossy(&to_bytes(resp.into_body(), 1 << 20).await.unwrap()).into_owned();
            (status, text)
        }
    };
    let (s, t) = send(format!("{P}/wallets/5/adjust?tokens=1&reason=x"), hdrs("SYSTEM", Some("appbuilder"), None)).await;
    assert!(s == StatusCode::UNAUTHORIZED && t.contains("COMMON.SIGN_IN_REQUIRED"), "{t}");
    let sys_t = sys(&w).await;
    let h = hdrs("SYSTEM", Some("appbuilder"), Some(&sys_t));
    let (s, t) = send(format!("{P}/wallets/abc/adjust?tokens=1&reason=x"), h.clone()).await;
    assert!(s == StatusCode::BAD_REQUEST && t.contains("Type mismatch."));
    let (s, t) = send(format!("{P}/wallets/5/adjust?reason=x"), h.clone()).await;
    assert!(s == StatusCode::BAD_REQUEST && t.contains("Required query parameter 'tokens' is not present."));
    let (s, t) = send(format!("{P}/wallets/5/adjust?tokens=1"), h.clone()).await;
    assert!(s == StatusCode::BAD_REQUEST && t.contains("Required query parameter 'reason' is not present."));
    let (s, t) = send(format!("{P}/wallets/5/adjust?tokens=x&reason=x"), h.clone()).await;
    assert!(s == StatusCode::BAD_REQUEST && t.contains("Type mismatch."));
    let member = token(&w, "BUS", "crm", "member", "memberpw").await;
    let (s, t) = send(format!("{P}/wallets/5/adjust?tokens=1&reason=x"), hdrs("BUS", Some("crm"), Some(&member))).await;
    assert!(s == StatusCode::FORBIDDEN && t.contains("COMMON.PERMISSION_REQUIRED") && t.contains("Access Denied: needs Authorities.ROLE_Owner"), "{t}");
    // An owner gets as far as the wallet (behind a pool that cannot connect here).
    let (s, _) = send(format!("{P}/wallets/5/adjust?tokens=1&reason=x"), h).await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR);
}
