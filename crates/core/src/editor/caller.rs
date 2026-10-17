//! The caller, as `JWTTokenFilter` establishes it, resolved once per request by a layer
//! around the whole editor router and kept for the request's task: the overridable routers
//! read it through [`EditorCallers`], and the hooks that act on the caller's behalf
//! (a schema save creating its storage overrides, a storage's definition triggers) read it
//! with [`current`].

use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::Request;
use axum::http::HeaderMap;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use overridable::write::router::CallerSource;
use platform::error::AppResult;
use platform::security::ContextAuthentication;

use crate::context::{self, RequestContext};

tokio::task_local! {
    static CALLER: Arc<ContextAuthentication>;
}

/// The request's caller, when a request is being served.
pub fn current() -> Option<ContextAuthentication> {
    CALLER.try_with(|c| (**c).clone()).ok()
}

/// Runs `fut` as `ca`.
pub async fn with_caller<F: std::future::Future>(ca: ContextAuthentication, fut: F) -> F::Output {
    CALLER.scope(Arc::new(ca), fut).await
}

/// The caller the routers see: the one the layer resolved, else asked of `inner`.
pub struct EditorCallers {
    pub inner: Arc<dyn CallerSource>,
}

#[async_trait]
impl CallerSource for EditorCallers {
    async fn caller(&self, headers: &HeaderMap) -> AppResult<ContextAuthentication> {
        match current() {
            Some(ca) => Ok(ca),
            None => self.inner.caller(headers).await,
        }
    }
}

/// What the layer needs: how to resolve a caller, and how to make core's request context
/// (for definition triggers, which run core functions).
#[async_trait]
pub trait Resolver: Send + Sync {
    async fn caller(&self, headers: &HeaderMap) -> AppResult<ContextAuthentication>;
    /// Core's request context, for the requests whose hooks run core functions.
    async fn request_context(&self, headers: &HeaderMap) -> Option<Arc<RequestContext>>;
}

/// Whether a request may run a storage's definition triggers: a write to a storage.
fn runs_functions(req: &Request) -> bool {
    req.method() != axum::http::Method::GET && req.uri().path().starts_with("/api/core/storages")
}

pub use crate::unmapped::permitted;

/// The layer: the caller resolved once; a refusal answered as the routes would answer it, and
/// an anonymous caller outside the permitted paths refused with Spring Security's bare 401.
pub async fn layer(resolver: Arc<dyn Resolver>, req: Request, next: Next) -> Response {
    let ca = match resolver.caller(req.headers()).await {
        Ok(ca) => ca,
        Err(e) => return overridable::write::controller::error_response(e),
    };
    if !ca.authenticated && !permitted(req.uri().path()) {
        return crate::unmapped::unauthorized();
    }
    if runs_functions(&req) {
        if let Some(ctx) = resolver.request_context(req.headers()).await {
            return with_caller(ca, context::with_request(ctx, next.run(req))).await.into_response();
        }
    }
    with_caller(ca, next.run(req)).await.into_response()
}
