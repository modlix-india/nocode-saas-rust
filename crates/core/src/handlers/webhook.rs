//! `POST /api/core/function/internal/webhook/{namespace}/{name}` (Rust only): ui-shell runs a
//! webhook URI path's function here. A provider calling an app for one tenant signs in as nobody,
//! so the function runs as the tenant client's anonymous user with `Authorities._Anonymous` and
//! `Authorities._Webhook` ([`crate::events::webhook_authentication`]): a tenant storage that takes
//! webhook data sets `createAuth` to `Authorities._Webhook` and stays closed to every other
//! anonymous caller, and a function only for webhooks sets it as its `executeAuth`.
//!
//! The route is internal: nginx refuses every path containing `/internal` from outside, as for the
//! other internal routes. It trusts the `appCode` and `clientCode` it is given (the shell sends the
//! URL's), so the function must verify the provider's signature before it acts.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::post;
use axum::Router;

use super::{body_arguments, finish, header, json_response};
use crate::context::{self, RequestContext};
use crate::error::{messages, CoreError};
use crate::events::{webhook_authentication, ClientLookup};
use crate::exec;
use crate::state::AppState;

pub const WEBHOOK: &str = "/api/core/function/internal/webhook/{namespace}/{name}";

pub fn router() -> Router<AppState> {
    Router::new().route(WEBHOOK, post(webhook))
}

async fn webhook(State(st): State<AppState>, Path((namespace, name)): Path<(String, String)>, h: HeaderMap, body: Bytes) -> Response {
    let clients = st.inner().integrations.checks.security.clone();
    finish(run(&st, clients.as_ref(), &h, &namespace, &name, &body).await, WEBHOOK)
}

async fn run(st: &AppState, clients: &dyn ClientLookup, h: &HeaderMap, namespace: &str, name: &str, body: &Bytes) -> Result<Response, CoreError> {
    let (ctx, app, client) = webhook_context(clients, h).await?;
    let arguments = body_arguments(body)?;
    context::with_request(ctx, exec::execute(st, Some(namespace), name, &app, &client, arguments))
        .await
        .map(json_response)
}

/// The request context of a webhook run: the `appCode` and `clientCode` headers (both
/// required), the client's webhook user, the forwarded host, port, `x-draft` and `x-debug` as
/// the shell passed them.
pub async fn webhook_context(clients: &dyn ClientLookup, h: &HeaderMap) -> Result<(Arc<RequestContext>, String, String), CoreError> {
    let mut codes = Vec::with_capacity(2);
    for name in ["appCode", "clientCode"] {
        match header(h, name).filter(|v| !v.trim().is_empty()) {
            Some(v) => codes.push(v),
            None => return Err(crate::error::spring::header_missing(name)),
        }
    }
    let (app, client) = (codes[0].clone(), codes[1].clone());
    let Some(found) = clients.client_by_code(&client).await? else {
        return Err(CoreError::msg(StatusCode::NOT_FOUND, messages::OBJECT_NOT_FOUND, &["Client", &client]));
    };
    let auth = webhook_authentication(Some(&app), Some(&client), &found)?;
    let ctx = Arc::new(RequestContext {
        auth: Arc::new(auth),
        app_code: Some(app.clone()),
        client_code: Some(client.clone()),
        forwarded_host: header(h, "x-forwarded-host").unwrap_or_default(),
        forwarded_port: header(h, "x-forwarded-port").unwrap_or_default(),
        draft: header(h, "x-draft").is_some_and(|v| v.eq_ignore_ascii_case("true")),
        debug: header(h, "x-debug"),
        raised: Default::default(),
    });
    Ok((ctx, app, client))
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use axum::http::HeaderValue;
    use serde_json::{json, Value};

    use super::*;
    use crate::authorities::has_authority;
    use crate::events::{anonymous_authentication, ANONYMOUS_AUTHORITY, EVENT_RUNNER_AUTHORITY, WEBHOOK_AUTHORITY};

    struct Clients;

    #[async_trait]
    impl ClientLookup for Clients {
        async fn client_by_code(&self, code: &str) -> Result<Option<Value>, CoreError> {
            match code {
                "FIN" => Ok(Some(json!({"id": 7, "code": "FIN", "typeCode": "BUS", "levelType": "CLIENT"}))),
                "DOWN" => Err(CoreError::unknown("security is down")),
                _ => Ok(None),
            }
        }
    }

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(), HeaderValue::from_static(v));
        }
        h
    }

    #[tokio::test]
    async fn the_webhook_user_of_the_url_client() {
        let h = headers(&[("appCode", "leadzumptwo"), ("clientCode", "FIN"), ("X-Forwarded-Host", "leadzump.ai"), ("x-draft", "TRUE"), ("x-debug", "d1")]);
        let (ctx, app, client) = webhook_context(&Clients, &h).await.unwrap();
        assert_eq!((app.as_str(), client.as_str()), ("leadzumptwo", "FIN"));
        let a = &ctx.auth;
        assert_eq!(a.authorities(), [ANONYMOUS_AUTHORITY, WEBHOOK_AUTHORITY]);
        assert_eq!((a.url_app_code(), a.url_client_code(), a.client_code()), (Some("leadzumptwo"), Some("FIN"), Some("FIN")));
        assert_eq!(a.ca.user.client_id, 7);
        assert!(!a.is_authenticated());
        assert_eq!((ctx.forwarded_host.as_str(), ctx.forwarded_port.as_str(), ctx.draft, ctx.debug.as_deref()), ("leadzump.ai", "", true, Some("d1")));
        // The webhook authority and the event runner's are kept apart.
        let has = |required: &str, held: &[String]| has_authority(Some(required), held).unwrap();
        assert!(has(WEBHOOK_AUTHORITY, a.authorities()));
        assert!(!has(EVENT_RUNNER_AUTHORITY, a.authorities()));
        let event = anonymous_authentication(Some("leadzumptwo"), Some("FIN"), &json!({"id": 7, "code": "FIN"})).unwrap();
        assert!(!has(WEBHOOK_AUTHORITY, event.authorities()));
        assert!(!has(WEBHOOK_AUTHORITY, &[ANONYMOUS_AUTHORITY.to_string()]), "a browser's anonymous caller");
    }

    #[tokio::test]
    async fn refusals() {
        let e = webhook_context(&Clients, &headers(&[("clientCode", "FIN")])).await.unwrap_err();
        assert_eq!(e.status(), StatusCode::BAD_REQUEST);
        assert!(e.text().contains("'appCode'"), "{}", e.text());
        let e = webhook_context(&Clients, &headers(&[("appCode", "a"), ("clientCode", " ")])).await.unwrap_err();
        assert!(e.text().contains("'clientCode'"), "{}", e.text());
        let e = webhook_context(&Clients, &headers(&[("appCode", "a"), ("clientCode", "NOPE")])).await.unwrap_err();
        assert_eq!(e.status(), StatusCode::NOT_FOUND);
        let e = webhook_context(&Clients, &headers(&[("appCode", "a"), ("clientCode", "DOWN")])).await.unwrap_err();
        assert_eq!(e.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// The route over HTTP on the local stack: a tenant of monkbars that has no copy of its own
    /// runs the app's function as its webhook user; only reads.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs the local stack: CORE_LOCAL_STACK=1 and config/local.toml"]
    async fn the_route_on_the_local_stack() {
        if !crate::testing::local_stack() {
            return;
        }
        let exec = crate::local_stack_tests::connected().await;
        let base = crate::testing::serve(crate::handlers::router(exec.state.clone())).await;
        let http = reqwest::Client::new();
        let post = |path: &str, client: &str, body: &str| {
            http.post(format!("{base}{path}"))
                .header("appCode", "monkbars")
                .header("clientCode", client.to_string())
                .header("X-Forwarded-Host", "localhost")
                .header("X-Forwarded-Port", "8080")
                .header("content-type", "application/json")
                .body(body.to_string())
                .send()
        };
        let r = post("/api/core/function/internal/webhook/CoreServices.SecurityContext/GetAuthentication", "KIRAN54", "{}").await.unwrap();
        assert_eq!(r.status(), 200);
        let v: Value = r.json().await.unwrap();
        let auth = &v[0]["result"]["auth"];
        assert_eq!(auth["urlClientCode"], "KIRAN54");
        assert_eq!(auth["user"]["stringAuthorities"], json!([ANONYMOUS_AUTHORITY, WEBHOOK_AUTHORITY]));
        let r = post("/api/core/function/internal/webhook/System.Math/Add", "NO_SUCH_CLIENT", "{}").await.unwrap();
        assert_eq!(r.status(), 404);
        let r = post("/api/core/function/internal/webhook/System.Math/Add", "KIRAN54", "[1]").await.unwrap();
        assert_eq!(r.status(), 500);
        // The open execute route never carries the webhook authority.
        let r = post("/api/core/function/execute/CoreServices.SecurityContext/GetAuthentication", "KIRAN54", "{}").await.unwrap();
        let v: Value = r.json().await.unwrap();
        assert_eq!(v[0]["result"]["auth"]["user"]["stringAuthorities"], json!([ANONYMOUS_AUTHORITY]));
    }

    /// A tenant storage that takes webhook data: created only with `_Webhook`.
    #[tokio::test]
    async fn storages_open_to_the_webhook_user_only() {
        use appdata::model::{DataObject, Storage};
        use appdata::value::{Document, Value as AValue};

        use crate::testing::{auth, policy, request, security_stub, MemoryCatalog, MemoryEngine, RecordingEvents};

        let base = security_stub(&[], &[]).await;
        let storage = Storage::from_value(&AValue::from_json(&json!({
            "name": "inbound", "appCode": "app", "clientCode": "SYSTEM", "createAuth": WEBHOOK_AUTHORITY,
            "schema": {"type": "OBJECT", "properties": {"raw": {"type": "STRING"}}}
        })))
        .unwrap();
        let engine = Arc::new(MemoryEngine::default());
        let svc = policy(MemoryCatalog::with(vec![storage]), engine.clone(), &base, Arc::new(RecordingEvents::default()));
        let row = || {
            let mut d = Document::new();
            d.insert("raw".into(), AValue::from("{}"));
            DataObject::of(d)
        };
        let create = |ctx: Arc<RequestContext>| {
            let svc = &svc;
            let row = row();
            async move { context::with_request(ctx, svc.create(Some("app"), Some("FIN"), "inbound", row, Some(false), None)).await }
        };

        let (ctx, _, _) = webhook_context(&Clients, &headers(&[("appCode", "app"), ("clientCode", "FIN")])).await.unwrap();
        assert!(create(ctx).await.is_ok(), "the webhook user writes");

        let browser = request(
            auth(json!({"user": {"id": 0, "clientId": 7, "stringAuthorities": [ANONYMOUS_AUTHORITY]}, "authenticated": false, "clientCode": "FIN"}), Some("FIN"), Some("app")),
            false,
            None,
        );
        assert_eq!(create(browser).await.unwrap_err().status(), StatusCode::FORBIDDEN, "an anonymous caller does not");
        let event = anonymous_authentication(Some("app"), Some("FIN"), &json!({"id": 7, "code": "FIN"})).unwrap();
        assert_eq!(create(request(event, false, None)).await.unwrap_err().status(), StatusCode::FORBIDDEN, "nor the event runner");
    }
}
