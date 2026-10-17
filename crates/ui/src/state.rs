use std::sync::Arc;

use axum::http::HeaderMap;
use overridable::{JMap, Resolved, Store};
use platform::cache::{CacheService, LocalCaches};
use platform::error::AppError;
use platform::security::{CallerContext, ContextAuthentication, SecurityClient};

use crate::config::UiConfig;

#[derive(Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

pub struct Inner {
    pub store: Store,
    pub security: SecurityClient,
    pub cache: CacheService,
    /// `ApplicationCache_<app>_cacheProperties_<app>[_DRAFT]`: the app definition the runtime
    /// reads its settings from, per client.
    pub properties: Arc<LocalCaches<String, Arc<JMap>>>,
    /// `UIFillerCache_<app>_<app>_FILLER_READ`: cached even when there is none
    /// (`cacheEmptyValueOrGet`).
    pub fillers: Arc<LocalCaches<String, Arc<Option<Arc<Resolved>>>>>,
    /// `appStatus`, `appDepList`: security answers the Java ui caches the same way.
    pub app_status: Arc<LocalCaches<String, Arc<String>>>,
    pub app_dependencies: Arc<LocalCaches<String, Arc<Vec<String>>>>,
    pub config: UiConfig,
}

impl AppState {
    pub fn new(inner: Inner) -> Self {
        Self { inner: Arc::new(inner) }
    }

    pub fn inner(&self) -> &Inner {
        &self.inner
    }

    pub fn store(&self) -> &Store {
        &self.inner.store
    }

    pub fn config(&self) -> &UiConfig {
        &self.inner.config
    }

    /// `FeignAuthenticationService.getAppStatusByCode`, cached under `appStatus`.
    pub async fn app_status(&self, app_code: &str) -> anyhow::Result<Option<Arc<String>>> {
        let sec = self.inner.security.clone();
        let app = app_code.to_string();
        self.inner
            .app_status
            .get_or_load("appStatus", app_code.to_string(), || async move {
                Ok::<_, anyhow::Error>(sec.app_status(&app).await?.map(Arc::new))
            })
            .await
    }

    /// `FeignAuthenticationService.getDependencies`, cached under `appDepList`.
    pub async fn app_dependencies(&self, app_code: &str) -> anyhow::Result<Arc<Vec<String>>> {
        let sec = self.inner.security.clone();
        let app = app_code.to_string();
        Ok(self
            .inner
            .app_dependencies
            .get_or_load("appDepList", app_code.to_string(), || async move {
                Ok::<_, anyhow::Error>(Some(Arc::new(sec.app_dependencies(&app).await?)))
            })
            .await?
            .unwrap_or_default())
    }

    /// The caller as `JWTTokenFilter` establishes it: security's answer for the token, the
    /// `clientCode` / `appCode` headers, and the gateway's draft flag.
    pub async fn caller(&self, headers: &HeaderMap) -> Result<Caller, AppError> {
        let ctx = CallerContext::from_headers(headers, self.inner.config.server.port);
        let ca = match self.inner.security.context_authentication(&ctx).await {
            Ok(ca) => ca,
            // Java relays the refusal: its status, and security's message (its coded error as it
            // came, here); a credential turned down without a word is "signed out" (Java's body
            // is empty).
            Err(e) => {
                return Err(match platform::security::refusal_error(&e) {
                    Some(AppError::Empty(status)) if matches!(status.as_u16(), 401 | 403) => platform::error::Coded::new("COMMON.SIGNED_OUT")
                        .status(status)
                        .debug(format!("security refused the caller ({})", status.as_u16()))
                        .into(),
                    Some(refusal) => refusal,
                    None => AppError::Internal(e),
                })
            }
        };
        let draft = headers
            .get("x-draft")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("true"));
        Ok(Caller { ca, client_code: ctx.client_code, app_code: ctx.app_code, draft })
    }
}

#[derive(Debug, Clone)]
pub struct Caller {
    pub ca: ContextAuthentication,
    /// The `clientCode` header (the gateway sets it from the host).
    pub client_code: Option<String>,
    /// The `appCode` header.
    pub app_code: Option<String>,
    /// `x-draft: true`, set by the gateway on draft hosts.
    pub draft: bool,
}

impl Caller {
    pub fn authenticated(&self) -> bool {
        self.ca.authenticated
    }

    pub fn authorities(&self) -> &[String] {
        &self.ca.user.string_authorities
    }

    /// `ca.getUrlClientCode()`, falling back to the client the read is for.
    pub fn url_client_code<'a>(&'a self, client_code: &'a str) -> &'a str {
        self.ca.url_client_code.as_deref().unwrap_or(client_code)
    }
}
