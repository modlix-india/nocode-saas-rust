//! Coded errors end to end through the message layer: the request's language, a second
//! language with its fallback chain, the caller's locale, and a client override source.

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use axum::middleware;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use platform::error::{AppError, Coded};
use platform::messages::{self, CallerHint, OverrideKey, OverrideSource, Texts};
use serde_json::Value;
use tower::ServiceExt;

const EN: &str = r#"
[ZT.NOT_YOURS]
status = 403
params = ["app"]
text = "You can't open {app|this app}."
action = "Ask an owner for access."
"#;

const PT: &str = r#"
[ZT.NOT_YOURS]
text = "Você não pode abrir {app|este app}."
"#;

fn register() {
    messages::register("zt", "en", EN);
    messages::register("zt", "pt", PT);
}

async fn refused() -> axum::response::Response {
    AppError::from(Coded::new("ZT.NOT_YOURS").param("app", "LeadZump")).into_response()
}

async fn refused_for_a_french_user() -> axum::response::Response {
    messages::note_caller(CallerHint { locale: Some("fr_FR".into()), authenticated: true, ..Default::default() });
    AppError::from(Coded::new("COMMON.SIGNED_OUT")).into_response()
}

async fn ok() -> &'static str {
    "fine"
}

fn app() -> Router {
    Router::new()
        .route("/refused", get(refused))
        .route("/fr", get(refused_for_a_french_user))
        .route("/ok", get(ok))
}

async fn call(app: Router, path: &str, headers: &[(&str, &str)]) -> (StatusCode, Value) {
    let mut b = Request::builder().uri(path);
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    let r = app.oneshot(b.body(axum::body::Body::empty()).unwrap()).await.unwrap();
    let status = r.status();
    let bytes = to_bytes(r.into_body(), 100_000).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::String(String::from_utf8_lossy(&bytes).into())))
}

#[tokio::test]
async fn languages_follow_the_request() {
    register();
    let app = app().layer(middleware::from_fn(messages::layer));

    let (s, v) = call(app.clone(), "/refused", &[]).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!((v["message"].as_str(), v["locale"].as_str()), (Some("You can't open LeadZump."), Some("en")));
    assert_eq!(v["code"], "ZT.NOT_YOURS");
    assert_eq!(v["params"]["app"], "LeadZump");

    let (_, v) = call(app.clone(), "/refused", &[("accept-language", "pt-BR,pt;q=0.9,en;q=0.5")]).await;
    assert_eq!((v["message"].as_str(), v["locale"].as_str()), (Some("Você não pode abrir LeadZump."), Some("pt")));
    assert!(v.get("action").is_none(), "Portuguese has no action yet: none rather than English");

    let (_, v) = call(app.clone(), "/refused", &[("accept-language", "de")]).await;
    assert_eq!(v["locale"], "en", "a language without texts falls back to English");

    // The caller's own locale counts after Accept-Language; French has no text, so English.
    let (s, v) = call(app.clone(), "/fr", &[]).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(v["locale"], "en");

    let (s, v) = call(app, "/ok", &[]).await;
    assert_eq!((s, v), (StatusCode::OK, Value::String("fine".into())));
}

/// A store that customised one code for one client, in Portuguese only.
struct Store;

#[async_trait]
impl OverrideSource for Store {
    async fn lookup(&self, key: OverrideKey<'_>) -> Option<Texts> {
        if key.client_code == "ACME" && key.code == "ZT.NOT_YOURS" && key.locale == "pt" {
            return Texts::from_strings(Some("ACME: sem acesso a {app}."), Some("Fale com o suporte da ACME.")).ok();
        }
        if key.client_code == "ACME" && key.code == "ZT.NOT_YOURS" && key.locale == "en" && key.app_code == Some("crm") {
            return Texts::from_strings(Some("CRM is for ACME staff only."), None).ok();
        }
        None
    }
}

#[tokio::test]
async fn a_client_override_source_comes_first() {
    register();
    let source: Arc<dyn OverrideSource> = Arc::new(Store);
    let app = app().layer(middleware::from_fn_with_state(source, messages::layer_with));

    let (_, v) = call(app.clone(), "/refused", &[("clientCode", "ACME"), ("accept-language", "pt")]).await;
    assert_eq!(v["message"], "ACME: sem acesso a LeadZump.");
    assert_eq!(v["action"], "Fale com o suporte da ACME.");
    assert_eq!(v["locale"], "pt");
    assert_eq!(v["code"], "ZT.NOT_YOURS");

    let (_, v) = call(app.clone(), "/refused", &[("clientCode", "ACME"), ("appCode", "crm")]).await;
    assert_eq!(v["message"], "CRM is for ACME staff only.");
    assert_eq!(v["action"], "Ask an owner for access.", "the built-in action stays when the override has none");

    // Another client, or no client at all: the built-in text.
    let (_, v) = call(app.clone(), "/refused", &[("clientCode", "OTHER"), ("accept-language", "pt")]).await;
    assert_eq!(v["message"], "Você não pode abrir LeadZump.");
    let (_, v) = call(app.clone(), "/refused", &[]).await;
    assert_eq!(v["message"], "You can't open LeadZump.");

    // English requested: the Portuguese override is not used.
    let (_, v) = call(app, "/refused", &[("clientCode", "ACME")]).await;
    assert_eq!(v["message"], "You can't open LeadZump.");
}

#[tokio::test]
async fn the_installed_source_is_used_by_the_default_layer() {
    register();
    messages::set_override_source(Arc::new(Store));
    let app = app().layer(middleware::from_fn(messages::layer));
    let (_, v) = call(app, "/refused", &[("clientCode", "ACME"), ("accept-language", "pt")]).await;
    assert_eq!(v["message"], "ACME: sem acesso a LeadZump.");
    messages::set_override_source(Arc::new(messages::NoOverrides));
}
