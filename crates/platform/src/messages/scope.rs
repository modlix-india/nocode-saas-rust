//! What one request contributes to its messages: the languages it accepts, who is calling (their
//! locale, once known), and which client and app it is for (for client and app overrides).
//!
//! [`layer`] opens the scope around every request ([`crate::app::Service`] installs it), so an
//! error rendered anywhere in the handler reads it without being passed anything. After the
//! handler, the layer gives the client and app override source (when one is installed) the
//! chance to replace the text of a coded error.

use std::sync::{Arc, Mutex, RwLock};

use async_trait::async_trait;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap};
use axum::middleware::Next;
use axum::response::Response;

use super::catalogue::Texts;
use super::locale::{chain, parse_accept_language, LocaleSources};

/// What is known about the caller once the handler has asked security.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CallerHint {
    /// The signed-in user's `localeCode` (Java's `en_US` style is fine).
    pub locale: Option<String>,
    /// The user's client's locale, when the service knows it.
    pub client_locale: Option<String>,
    /// The caller's own client code.
    pub client_code: Option<String>,
    pub authenticated: bool,
    /// The request carried a token or Basic credentials (accepted or not): a refusal then says
    /// "signed out" rather than "please sign in".
    pub credential_sent: bool,
}

/// One request's message context.
#[derive(Debug, Default)]
pub struct RequestScope {
    pub accept_language: Vec<String>,
    /// The `clientCode` header: whose site or app the request is on.
    pub url_client: Option<String>,
    /// The `appCode` header.
    pub url_app: Option<String>,
    caller: Mutex<CallerHint>,
}

impl RequestScope {
    pub fn from_headers(h: &HeaderMap) -> Self {
        let get = |n: &str| h.get(n).and_then(|v| v.to_str().ok()).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
        Self {
            accept_language: get(header::ACCEPT_LANGUAGE.as_str()).map(|v| parse_accept_language(&v)).unwrap_or_default(),
            url_client: get("clientcode"),
            url_app: get("appcode"),
            caller: Mutex::new(CallerHint::default()),
        }
    }

    pub fn caller(&self) -> CallerHint {
        self.caller.lock().map(|c| c.clone()).unwrap_or_default()
    }

    /// The languages to try, best first.
    pub fn chain(&self, default: Option<&str>) -> Vec<String> {
        let c = self.caller();
        chain(&LocaleSources {
            accept_language: &self.accept_language,
            user: c.locale.as_deref(),
            client: c.client_locale.as_deref(),
            default,
        })
    }

    /// Whose overrides apply: the client whose site the request is on, else the caller's own.
    pub fn override_client(&self) -> Option<String> {
        self.url_client.clone().or_else(|| self.caller().client_code)
    }
}

tokio::task_local! {
    static SCOPE: Arc<RequestScope>;
}

/// The current request's scope, if the code runs inside one.
pub fn current() -> Option<Arc<RequestScope>> {
    SCOPE.try_with(Arc::clone).ok()
}

/// Records what the handler learnt about the caller. Outside a request it does nothing.
pub fn note_caller(hint: CallerHint) {
    if let Some(s) = current() {
        if let Ok(mut c) = s.caller.lock() {
            *c = hint;
        }
    }
}

/// Runs `fut` inside `scope` (the layer does this; tests and background work may too).
pub async fn with_scope<F: std::future::Future>(scope: RequestScope, fut: F) -> F::Output {
    SCOPE.scope(Arc::new(scope), fut).await
}

/// Who asks the client and app override source for a text.
#[derive(Debug, Clone, Copy)]
pub struct OverrideKey<'a> {
    pub client_code: &'a str,
    pub app_code: Option<&'a str>,
    pub locale: &'a str,
    pub code: &'a str,
}

/// Texts a client (or a client's app) set for a code: the hook for a store of customised
/// messages. The planned store is described in `messages/OVERRIDES.md`.
#[async_trait]
pub trait OverrideSource: Send + Sync {
    /// The client's texts for the code in that language (app-specific first, then the
    /// client's own), or `None` to leave the built-in ones.
    async fn lookup(&self, key: OverrideKey<'_>) -> Option<Texts>;
}

/// The source in use until a store is plugged in: nothing is customised.
pub struct NoOverrides;

#[async_trait]
impl OverrideSource for NoOverrides {
    async fn lookup(&self, _key: OverrideKey<'_>) -> Option<Texts> {
        None
    }
}

static SOURCE: RwLock<Option<Arc<dyn OverrideSource>>> = RwLock::new(None);

/// Installs the client and app override source for this process.
pub fn set_override_source(source: Arc<dyn OverrideSource>) {
    if let Ok(mut s) = SOURCE.write() {
        *s = Some(source);
    }
}

fn installed_source() -> Option<Arc<dyn OverrideSource>> {
    SOURCE.read().ok().and_then(|s| s.clone())
}

/// The layer every service runs: opens the request's scope, and lets the installed override
/// source replace a coded error's text.
pub async fn layer(req: Request, next: Next) -> Response {
    apply(installed_source(), req, next).await
}

/// [`layer`] with a given source instead of the installed one.
pub async fn layer_with(State(source): State<Arc<dyn OverrideSource>>, req: Request, next: Next) -> Response {
    apply(Some(source), req, next).await
}

async fn apply(source: Option<Arc<dyn OverrideSource>>, req: Request, next: Next) -> Response {
    let scope = Arc::new(RequestScope::from_headers(req.headers()));
    let resp = SCOPE.scope(scope.clone(), next.run(req)).await;
    match source {
        Some(source) => customise(resp, &scope, source.as_ref()).await,
        None => resp,
    }
}

/// Asks the source for each language up to the one the message was rendered in; the first
/// text found replaces the body.
async fn customise(resp: Response, scope: &RequestScope, source: &dyn OverrideSource) -> Response {
    let Some(report) = resp.extensions().get::<crate::error::ErrorReport>().cloned() else { return resp };
    let Some(client) = scope.override_client() else { return resp };
    let chain = {
        let cat = super::global();
        scope.chain(cat.default_locale())
    };
    for locale in &chain {
        let key = OverrideKey { client_code: &client, app_code: scope.url_app.as_deref(), locale, code: &report.code };
        if let Some(texts) = source.lookup(key).await {
            let rendered = super::global().render_with(&report.code, &report.params, &chain, &report.exception_id, Some((locale, &texts)));
            let (mut parts, _) = resp.into_parts();
            parts.headers.remove(header::CONTENT_LENGTH);
            let body = crate::error::coded_body(&report, &rendered);
            return Response::from_parts(parts, Body::from(body));
        }
        if *locale == report.locale {
            break;
        }
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn scope_from_headers() {
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT_LANGUAGE, HeaderValue::from_static("pt-BR,pt;q=0.9"));
        h.insert("clientCode", HeaderValue::from_static("FIN"));
        h.insert("appCode", HeaderValue::from_static(" "));
        let s = RequestScope::from_headers(&h);
        assert_eq!(s.accept_language, vec!["pt-BR", "pt"]);
        assert_eq!(s.url_client.as_deref(), Some("FIN"));
        assert_eq!(s.url_app, None);
        assert_eq!(s.chain(Some("hi")), vec!["pt-BR", "pt", "hi", "en"]);
        assert_eq!(s.override_client().as_deref(), Some("FIN"));
    }

    #[tokio::test]
    async fn caller_hints_live_in_the_scope() {
        note_caller(CallerHint { locale: Some("fr".into()), ..Default::default() });
        assert!(current().is_none(), "outside a request nothing is recorded");
        let chain = with_scope(RequestScope::default(), async {
            note_caller(CallerHint {
                locale: Some("fr_CA".into()),
                client_locale: Some("de".into()),
                client_code: Some("ACME".into()),
                authenticated: true,
                credential_sent: true,
            });
            let s = current().unwrap();
            assert_eq!(s.override_client().as_deref(), Some("ACME"));
            assert!(s.caller().credential_sent);
            s.chain(None)
        })
        .await;
        assert_eq!(chain, vec!["fr-CA", "fr", "de", "en"]);
    }

    #[tokio::test]
    async fn no_overrides_finds_nothing() {
        let key = OverrideKey { client_code: "A", app_code: None, locale: "en", code: "X" };
        assert!(NoOverrides.lookup(key).await.is_none());
    }
}
