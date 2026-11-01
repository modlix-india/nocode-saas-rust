//! The request's context, available to every core function while it runs: what Java keeps in
//! the Reactor `Context` (the security context, `x-debug`, `x-draft`, the forwarded host and
//! port) and what `DefinitionFunction` adds around a running definition (that a KIRun runtime
//! is running, and the app the running definition belongs to).
//!
//! Both are tokio task-locals: the request's is set once by the handler, the definition's is
//! set again by every nested definition function, so a step always sees the innermost owner.
//! KIRun runs the steps of one execution as futures of the same task (never spawned), so the
//! values follow them.

use std::future::Future;
use std::sync::Arc;

use crate::auth::Authentication;
use crate::error::CoreError;

#[derive(Debug, Default)]
pub struct RequestContext {
    pub auth: Arc<Authentication>,
    /// The `appCode` header.
    pub app_code: Option<String>,
    /// The `clientCode` header.
    pub client_code: Option<String>,
    pub forwarded_host: String,
    pub forwarded_port: String,
    /// `x-draft: true` from the gateway: reads use the draft surface.
    pub draft: bool,
    /// The `x-debug` header: definitions run with the debug collector, and their step logs are
    /// written to the log.
    pub debug: Option<String>,
    /// The caller's address ([`client_ip`]); empty for event and webhook runs.
    pub client_ip: String,
    /// The caller's `User-Agent` ([`user_agent`]); empty for event and webhook runs.
    pub user_agent: String,
    /// The last Java-shaped error a core function or a definition raised. KIRun errors carry
    /// only text, so a `GenericException` (with its status) travels up the runtime as its
    /// message and is recovered here at the edge: Java lets it through unwrapped.
    pub raised: parking_lot::Mutex<Option<CoreError>>,
}

/// What `DefinitionFunction` puts in the context of the runtime it starts.
#[derive(Debug, Clone, Default)]
pub struct RunScope {
    /// `KIRun Owner AppCode`: the app the running definition's document belongs to (not
    /// always the request's app: a function resolved through an app dependency belongs to the
    /// dependency).
    pub owner_app_code: Option<String>,
}

/// The EventAction core-events is running: set only by the events consumer around one
/// action's tasks, never by a request, so a function can tell that it runs as an event's task
/// (and for which app and client) rather than from a page, an execute call or another
/// definition started by a request. `CoreServices.Platform.*` refuse to run without it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventActionRun {
    /// The app the event was raised in, which is the EventAction's app.
    pub app_code: String,
    pub client_code: String,
    pub event_name: String,
}

/// The longest `User-Agent` kept.
pub const USER_AGENT_MAX_CHARS: usize = 300;

/// The caller's address as our own proxies wrote it: `X-Real-IP`, which the load balancer's nginx
/// sets to the address it saw (`proxy_set_header X-Real-IP $remote_addr`, after the Cloudflare
/// real-ip rule), overwriting anything the browser sent; else the hop the gateway appended last
/// to `X-Forwarded-For` (its own peer). The first `X-Forwarded-For` entry is the browser's to
/// write, so it is never read. Empty when neither holds an address.
pub fn client_ip(h: &axum::http::HeaderMap) -> String {
    let text = |name: &str| h.get(name).and_then(|v| v.to_str().ok()).map(str::to_string);
    let real = text("x-real-ip").map(|v| v.split(',').next().unwrap_or_default().trim().to_string());
    let hop = || {
        h.get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .map(str::trim)
            .rfind(|v| !v.is_empty())
            .map(str::to_string)
    };
    let as_ip = |v: String| v.parse::<std::net::IpAddr>().is_ok().then_some(v);
    real.and_then(as_ip).or_else(|| hop().and_then(as_ip)).unwrap_or_default()
}

/// The `User-Agent` header, trimmed, at most [`USER_AGENT_MAX_CHARS`] characters.
pub fn user_agent(h: &axum::http::HeaderMap) -> String {
    let ua = h.get(axum::http::header::USER_AGENT).map(|v| String::from_utf8_lossy(v.as_bytes()).trim().to_string()).unwrap_or_default();
    ua.chars().take(USER_AGENT_MAX_CHARS).collect::<String>().trim_end().to_string()
}

tokio::task_local! {
    static REQUEST: Arc<RequestContext>;
    static RUN: Arc<RunScope>;
    static SURFACE: bool;
    static EVENT_ACTION: Arc<EventActionRun>;
}

/// Runs `fut` as the tasks of an EventAction. Only core-events calls this.
pub async fn with_event_action<F: Future>(run: EventActionRun, fut: F) -> F::Output {
    EVENT_ACTION.scope(Arc::new(run), fut).await
}

/// The EventAction whose tasks are running, if any.
pub fn event_action() -> Option<Arc<EventActionRun>> {
    EVENT_ACTION.try_with(Arc::clone).ok()
}

/// Runs `fut` with `ctx` as the request context.
pub async fn with_request<F: Future>(ctx: Arc<RequestContext>, fut: F) -> F::Output {
    REQUEST.scope(ctx, fut).await
}

/// Runs `fut` inside a definition function's scope.
pub async fn with_run<F: Future>(scope: RunScope, fut: F) -> F::Output {
    RUN.scope(Arc::new(scope), fut).await
}

/// The request context, if the caller is inside a request.
pub fn request() -> Option<Arc<RequestContext>> {
    REQUEST.try_with(Arc::clone).ok()
}

/// Records `err` for the edge and turns it into the KIRun error that carries it up.
pub fn raise(err: CoreError) -> kirun::KIRunError {
    let text = err.text();
    if let Some(r) = request() {
        *r.raised.lock() = Some(err);
    }
    kirun::KIRunError::runtime(text)
}

/// The error a failed execution should answer with: the raised `GenericException` when the
/// runtime's error is exactly its text (it came up unwrapped), otherwise an unknown error.
pub fn error_for(err: &kirun::KIRunError) -> CoreError {
    raised_or_unknown(err).0
}

/// [`error_for`], and whether the error is one a core function raised (rather than the
/// runtime's own: a value that does not fit a parameter, an expression that fails).
pub fn raised_or_unknown(err: &kirun::KIRunError) -> (CoreError, bool) {
    let text = err.to_string();
    let raised = request().and_then(|r| r.raised.lock().take());
    match raised {
        Some(r) if r.text() == text => (r, true),
        _ => (CoreError::unknown(text), false),
    }
}

/// The caller's authentication; an anonymous, empty one outside a request.
pub fn authentication() -> Arc<Authentication> {
    request().map(|r| r.auth.clone()).unwrap_or_default()
}

/// `LogUtil.isDraft()`: the request is on the draft surface; false outside a request. A
/// surface named explicitly (`AppDataService.onSurface`, `LogUtil.DRAFT_KEY` written into the
/// context) wins over the gateway's flag.
pub fn is_draft() -> bool {
    if let Ok(d) = SURFACE.try_with(|d| *d) {
        return d;
    }
    request().is_some_and(|r| r.draft)
}

/// Runs `fut` on a named surface (`contextWrite(Context.of(LogUtil.DRAFT_KEY, draft))`).
pub async fn with_surface<F: Future>(draft: bool, fut: F) -> F::Output {
    SURFACE.scope(draft, fut).await
}

/// `DefinitionFunction.CONTEXT_KEY` is set: a KIRun definition is running.
pub fn in_kirun() -> bool {
    RUN.try_with(|_| ()).is_ok()
}

/// `DefinitionFunction.OWNER_APP_CODE`, when a definition with an owner is running.
pub fn owner_app_code() -> Option<String> {
    RUN.try_with(|r| r.owner_app_code.clone()).ok().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        for (k, v) in pairs {
            h.append(axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(), axum::http::HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn the_caller_address_is_the_one_our_proxies_wrote() {
        // nginx's X-Real-IP wins over everything the browser could have sent.
        let h = headers(&[("x-real-ip", "203.0.113.7"), ("x-forwarded-for", "6.6.6.6, 10.0.0.2")]);
        assert_eq!(client_ip(&h), "203.0.113.7");
        assert_eq!(client_ip(&headers(&[("x-real-ip", " 2001:db8::1 ")])), "2001:db8::1");
        // Without it: the gateway's own hop, the LAST entry, never the browser's first one.
        assert_eq!(client_ip(&headers(&[("x-forwarded-for", "6.6.6.6, 198.51.100.4")])), "198.51.100.4");
        assert_eq!(client_ip(&headers(&[("x-forwarded-for", "6.6.6.6"), ("x-forwarded-for", "0:0:0:0:0:0:0:1")])), "0:0:0:0:0:0:0:1");
        // Junk is no address.
        assert_eq!(client_ip(&headers(&[("x-real-ip", "<script>")])), "");
        assert_eq!(client_ip(&headers(&[("x-real-ip", "nope"), ("x-forwarded-for", "192.0.2.9")])), "192.0.2.9");
        assert_eq!(client_ip(&headers(&[("x-forwarded-for", " , ")])), "");
        assert_eq!(client_ip(&headers(&[])), "");
    }

    #[test]
    fn the_user_agent_is_trimmed_and_capped() {
        assert_eq!(user_agent(&headers(&[("user-agent", "  Mozilla/5.0 (iPhone)  ")])), "Mozilla/5.0 (iPhone)");
        let long = "a".repeat(USER_AGENT_MAX_CHARS + 50);
        assert_eq!(user_agent(&headers(&[("user-agent", &long)])).chars().count(), USER_AGENT_MAX_CHARS);
        assert_eq!(user_agent(&headers(&[])), "");
    }

    #[tokio::test]
    async fn the_event_action_is_seen_only_inside_its_scope() {
        assert_eq!(event_action(), None);
        let run = EventActionRun { app_code: "platform".into(), client_code: "SYSTEM".into(), event_name: "TOKEN_CLEANUP".into() };
        with_event_action(run.clone(), async {
            assert_eq!(event_action().as_deref(), Some(&run));
            // A spawned task does not inherit it.
            assert_eq!(tokio::spawn(async { event_action() }).await.unwrap(), None);
        })
        .await;
        assert_eq!(event_action(), None);
    }

    #[tokio::test]
    async fn nested_runs_see_the_innermost_owner() {
        assert!(!in_kirun());
        let ctx = Arc::new(RequestContext { app_code: Some("caller".into()), ..Default::default() });
        with_request(ctx, async {
            assert_eq!(request().unwrap().app_code.as_deref(), Some("caller"));
            with_run(RunScope { owner_app_code: Some("outer".into()) }, async {
                assert!(in_kirun());
                assert_eq!(owner_app_code().as_deref(), Some("outer"));
                with_run(RunScope { owner_app_code: Some("dep".into()) }, async {
                    assert_eq!(owner_app_code().as_deref(), Some("dep"));
                })
                .await;
                assert_eq!(owner_app_code().as_deref(), Some("outer"));
            })
            .await;
            assert!(!in_kirun());
        })
        .await;
    }

    fn draft_request() -> Arc<RequestContext> {
        Arc::new(RequestContext { draft: true, ..Default::default() })
    }

    // Port of core `DraftContextPropagationTest`.

    #[tokio::test]
    async fn defaults_to_false() {
        assert!(!is_draft());
        with_request(Arc::new(RequestContext::default()), async { assert!(!is_draft()) }).await;
    }

    #[tokio::test]
    async fn visible_on_draft_surface() {
        with_request(draft_request(), async { assert!(is_draft()) }).await;
    }

    #[tokio::test]
    async fn survives_security_context_write() {
        // The caller is part of the same context here, so writing it cannot shadow the flag.
        let ctx = Arc::new(RequestContext {
            draft: true,
            auth: Arc::new(crate::testing::user(&["Authorities.Storage_READ"])),
            ..Default::default()
        });
        with_request(ctx, async {
            assert!(is_draft());
            assert!(authentication().is_authenticated());
        })
        .await;
    }

    #[tokio::test]
    async fn survives_nesting() {
        with_request(draft_request(), async {
            let nested = async { async { is_draft() }.await }.await;
            assert!(nested);
            with_run(RunScope { owner_app_code: None }, async { assert!(is_draft()) }).await;
        })
        .await;
    }

    #[tokio::test]
    async fn raised_errors_are_recovered_only_when_they_came_up_unwrapped() {
        // Outside a request nothing is recorded.
        let e = raise(CoreError::new(axum::http::StatusCode::BAD_REQUEST, "x"));
        assert_eq!(error_for(&e).status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        with_request(Arc::new(RequestContext::default()), async {
            let e = raise(CoreError::new(axum::http::StatusCode::BAD_REQUEST, "bad"));
            assert_eq!(error_for(&e).status(), axum::http::StatusCode::BAD_REQUEST);
            let _ = raise(CoreError::new(axum::http::StatusCode::BAD_REQUEST, "bad"));
            let wrapped = kirun::KIRunError::runtime("Error while executing: bad");
            let got = error_for(&wrapped);
            assert_eq!(got.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(got.text(), "Error while executing: bad");
        })
        .await;
        assert!(!authentication().is_authenticated());
        assert_eq!(owner_app_code(), None);
    }

}
