//! What core answers for a path no controller maps, and for a method a mapped path does not
//! take. Spring Security runs before the `DispatcherHandler` (`CoreConfiguration.filterChain`),
//! so an anonymous caller outside the permitted paths gets Spring Security's bare 401 whether
//! or not anything is mapped there; a signed-in caller (or anyone on a permitted path) gets the
//! dispatcher's 404 or 405 as `ControllerAdvice` writes it.
//!
//! core-editor resolves its caller in a layer around every route, the fallbacks included
//! (`editor::caller::layer`), so its fallbacks only answer. core-exec's routes resolve the
//! caller themselves, so its fallbacks ([`exec_not_found`], [`exec_method_not_allowed`]) do
//! the same check first.

use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, Method, StatusCode, Uri};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Router;

use crate::error::CoreError;
use crate::state::AppState;

/// The paths core's `SecurityWebFilterChain` lets an anonymous caller reach
/// (`CoreConfiguration.filterChain`); everything else needs a signed-in caller.
pub const PERMITTED: [&str; 16] = [
    "/api/core/function/**",
    "/api/core/functions/repositoryFilter",
    "/api/core/functions/repositoryFind",
    "/api/core/schemas/repositoryFilter",
    "/api/core/schemas/repositoryFind",
    "/api/core/connections/oauth/evoke",
    "/api/core/connections/oauth/callback",
    "/api/core/connections/internal",
    "/api/core/connections/internal/**",
    "/api/core/notifications/internal/**",
    "/api/core/internal/billing/**",
    "/api/core/internal/data/**",
    "/api/core/index/internal/**",
    "/api/core/transports/internal/**",
    "/api/core/eventRuns/internal/**",
    "/api/core/events/internal/**",
];

/// Spring's `PathPatternParser` on [`PERMITTED`]: exact, or `/**` for the path and below.
pub fn permitted(path: &str) -> bool {
    PERMITTED.iter().any(|p| match p.strip_suffix("/**") {
        Some(base) => path == base || path.starts_with(&format!("{base}/")),
        None => path == *p,
    })
}

/// Spring Security's `HttpStatusServerEntryPoint(UNAUTHORIZED)`: 401 and no
/// `WWW-Authenticate`, now with a body asking to sign in (`COMMON.SIGNED_OUT` when the request
/// carried a credential that was not accepted, `COMMON.SIGN_IN_REQUIRED` when it carried none;
/// Java sends no body).
pub fn unauthorized() -> Response {
    let c = platform::error::Coded::unauthenticated().debug("Not signed in: Spring Security's 401");
    platform::error::coded_response(&c)
}

/// Spring Security's `HttpStatusServerAccessDeniedHandler(FORBIDDEN)` for a `@PreAuthorize`
/// that refused a signed-in caller: 403, now JSON naming the permission (any one of `any_of`)
/// and who can grant it (Java sends `text/plain` "Access Denied").
pub fn access_denied(any_of: &[&str]) -> Response {
    platform::error::coded_response(&platform::error::Coded::permission_required(any_of))
}

/// The dispatcher's `ResponseStatusException(NOT_FOUND)` through `ControllerAdvice`.
pub fn not_found() -> Response {
    CoreError::spring(StatusCode::NOT_FOUND, "404 NOT_FOUND", None).into_response()
}

/// `MethodNotAllowedException` through `ControllerAdvice`.
pub fn method_not_allowed(method: &Method) -> Response {
    CoreError::spring(
        StatusCode::METHOD_NOT_ALLOWED,
        format!("405 METHOD_NOT_ALLOWED \"Request method '{method}' is not supported.\""),
        Some(platform::error::Coded::new("COMMON.METHOD_NOT_ALLOWED").param("method", method)),
    )
    .into_response()
}

/// Spring never lists the allowed methods; axum adds `Allow` to whatever a route's method
/// fallback answers (the 405, or the 401 in front of it), outside any layer the router's routes
/// carry. No core route sets `Allow` itself.
async fn without_allow(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    resp.headers_mut().remove(header::ALLOW);
    resp
}

/// `r` served whole behind a layer that takes axum's `Allow` off its 405s (a `Router::layer`
/// on `r` itself would sit inside the method routers that add it).
pub fn without_allow_header(r: Router) -> Router {
    Router::new().fallback_service(r).layer(axum::middleware::from_fn(without_allow))
}

/// The filter chain's verdict for core-exec: `Some` refusal (a failed authentication as the
/// filter answers it, or the bare 401 for an anonymous caller off the permitted paths).
async fn refused(st: &AppState, path: &str, h: &HeaderMap) -> Option<Response> {
    match crate::handlers::request_context(st, h).await {
        Err(e) => Some(e.into_response()),
        Ok(ctx) if !ctx.auth.is_authenticated() && !permitted(path) => Some(unauthorized()),
        Ok(_) => None,
    }
}

/// core-exec's fallback: a path nothing maps.
pub async fn exec_not_found(State(st): State<AppState>, uri: Uri, h: HeaderMap) -> Response {
    match refused(&st, uri.path(), &h).await {
        Some(r) => r,
        None => not_found(),
    }
}

/// core-exec's answer to a method a mapped path does not take.
pub async fn exec_method_not_allowed(State(st): State<AppState>, method: Method, uri: Uri, h: HeaderMap) -> Response {
    match refused(&st, uri.path(), &h).await {
        Some(r) => r,
        None => method_not_allowed(&method),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_permitted_paths() {
        assert!(permitted("/api/core/index/internal/app"));
        assert!(permitted("/api/core/internal/billing/meter"));
        assert!(permitted("/api/core/functions/repositoryFind"));
        assert!(permitted("/api/core/connections/internal"));
        assert!(permitted("/api/core/function/nothing"));
        assert!(!permitted("/api/core/functions/repositoryFindX"));
        assert!(!permitted("/api/core/index"));
        assert!(!permitted("/api/core/index/nothing"));
        assert!(!permitted("/api/core/internal/cache"));
        assert!(!permitted("/api/core/internal/nothing"));
        assert!(!permitted("/api/core/nonexistent"));
    }

    #[tokio::test]
    async fn the_dispatchers_answers_as_core_writes_them() {
        let body = |r: Response| async move {
            let s = r.status();
            let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
            (s, serde_json::from_slice::<serde_json::Value>(&b).unwrap_or_default())
        };
        let (s, b) = body(not_found()).await;
        assert_eq!((s, b["debugMessage"].as_str()), (StatusCode::NOT_FOUND, Some("404 NOT_FOUND")));
        assert_eq!((b["code"].as_str(), b["message"].as_str()), (Some("COMMON.NOT_FOUND"), Some("We couldn't find what you asked for.")));
        let (s, b) = body(method_not_allowed(&Method::PUT)).await;
        assert_eq!(
            (s, b["debugMessage"].as_str()),
            (StatusCode::METHOD_NOT_ALLOWED, Some("405 METHOD_NOT_ALLOWED \"Request method 'PUT' is not supported.\""))
        );
        assert_eq!(b["message"], "This address does not accept PUT requests.");
        let r = unauthorized();
        assert_eq!((r.status(), r.headers().get(header::WWW_AUTHENTICATE)), (StatusCode::UNAUTHORIZED, None));
        let (_, b) = body(r).await;
        assert_eq!((b["code"].as_str(), b["debugMessage"].as_str()), (Some("COMMON.SIGN_IN_REQUIRED"), Some("Not signed in: Spring Security's 401")));
        let (s, b) = body(access_denied(&["Authorities.EventAction_READ"])).await;
        assert_eq!((s, b["code"].as_str()), (StatusCode::FORBIDDEN, Some("COMMON.PERMISSION_REQUIRED")));
        assert_eq!(b["debugMessage"], "Access Denied: needs Authorities.EventAction_READ");
    }

    /// core-exec's router, served: Spring Security's verdict comes before the dispatcher's.
    #[tokio::test]
    async fn core_exec_refuses_an_anonymous_caller_before_it_finds_nothing() {
        use crate::testing::{offline_state, policy, security_stub, serve, MemoryCatalog, MemoryEngine, RecordingEvents};
        let base = security_stub(&[], &["app"]).await;
        let svc = std::sync::Arc::new(policy(MemoryCatalog::with(vec![]), std::sync::Arc::new(MemoryEngine::default()), &base, std::sync::Arc::new(RecordingEvents::default())));
        let url = serve(crate::handlers::router(offline_state(svc, &base).await)).await;
        let http = reqwest::Client::new();
        let call = |method: &'static str, path: &'static str, signed: bool| {
            let (http, url) = (http.clone(), url.clone());
            async move {
                let mut rb = http
                    .request(reqwest::Method::from_bytes(method.as_bytes()).unwrap(), format!("{url}{path}"))
                    .header("appCode", "app")
                    .header("clientCode", "SYSTEM");
                if signed {
                    rb = rb.header("Authorization", "Basic user");
                }
                let r = rb.send().await.unwrap();
                let (status, allow, www) = (r.status().as_u16(), r.headers().contains_key("allow"), r.headers().contains_key("www-authenticate"));
                let body: serde_json::Value = serde_json::from_slice(&r.bytes().await.unwrap()).unwrap_or_default();
                (status, body["debugMessage"].as_str().unwrap_or_default().to_string(), allow, www)
            }
        };
        for path in ["/api/core/nonexistent", "/api/core/internal/nothing", "/api/core/index/nothing", "/api/core/data/a/b/c/d"] {
            assert_eq!(call("GET", path, false).await, (401, "Not signed in: Spring Security's 401".into(), false, false), "{path}");
            assert_eq!(call("GET", path, true).await, (404, "404 NOT_FOUND".into(), false, false), "{path}");
        }
        // Permitted: past the filter chain, to the dispatcher.
        assert_eq!(call("GET", "/api/core/function/nothing", false).await.0, 404);
        assert_eq!(call("GET", "/api/core/internal/data/a/b/c", false).await.0, 404);
        // A mapped path, a method it does not take.
        assert_eq!(call("PUT", "/api/core/eventRuns", false).await, (401, "Not signed in: Spring Security's 401".into(), false, false));
        assert_eq!(
            call("PUT", "/api/core/eventRuns", true).await,
            (405, "405 METHOD_NOT_ALLOWED \"Request method 'PUT' is not supported.\"".into(), false, false)
        );
        assert_eq!(call("POST", "/api/core/functions/repositoryFind", false).await.0, 405);
    }
}
