//! What the billing services share: the [`Billing`] context they run in, the lookups through
//! the cached directory, the refusals they raise, and [`Outside`], the three calls that leave
//! the process (files' `internal/secured/createKey`, Razorpay, and the app URL a billing e-mail
//! links to), kept behind a trait so the tests answer them in process.

use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use axum::http::StatusCode;
use base64::Engine;
use chrono::{NaiveDate, NaiveDateTime};
use platform::upstream::Upstream;
use serde_json::Value;

use crate::caches;
use crate::data::billing_admin::{AdminBillingStore, Find, Rec, Schema, Val, CONFIG};
use crate::directory::Directory;
use crate::errors::{AuthError, AuthResult, FORBIDDEN_PERMISSION, OBJECT_NOT_FOUND};
use crate::events::EventSink;
use crate::internal::Internal;
use crate::model::{App, Client, ContextAuth};

/// `CacheService.makeKey` on a null first key: what every `getAppByCode(null)` /
/// `getClientBy(null)` answers (the header was not sent).
pub const NULL_KEY: &str = "Cannot invoke \"Object.toString()\" because \"args[0]\" is null";

pub const RAZORPAY_BASE_URL: &str = "https://api.razorpay.com/v1";

/// `throwMessage(..., FORBIDDEN_PERMISSION, what)`: 403.
pub fn forbidden(what: &str) -> AuthError {
    AuthError::msg(StatusCode::FORBIDDEN, FORBIDDEN_PERMISSION, &[what]).with_code("SEC.BILLING_FORBIDDEN")
}

/// `throwMessage(..., PARAMS_NOT_FOUND, what)`: 400.
pub fn params_not_found(what: &str) -> AuthError {
    AuthError::msg(StatusCode::BAD_REQUEST, "params_not_found", &[what])
}

/// `AbstractDAO.getRecordById`'s 404.
pub fn not_found(pojo: &str, id: Option<u64>) -> AuthError {
    let id = id.map(|i| i.to_string()).unwrap_or_else(|| "null".into());
    AuthError::msg(StatusCode::NOT_FOUND, OBJECT_NOT_FOUND, &[pojo, &id])
}

/// `@PreAuthorize("hasAnyAuthority(...)")`: the caller holds one of them exactly.
pub fn pre_authorize(ca: &ContextAuth, any_of: &[&str]) -> AuthResult<()> {
    let held = ca.user.string_authorities.as_deref().unwrap_or_default();
    if any_of.iter().any(|a| held.iter().any(|h| h == a)) {
        Ok(())
    } else {
        Err(AuthError::denied(ca, any_of))
    }
}

pub const APPLICATION_CREATE: &str = "Authorities.Application_CREATE";
pub const ROLE_OWNER: &str = "Authorities.ROLE_Owner";
pub const PAYMENT_CREATE: &str = "Authorities.Payment_CREATE";
pub const INVOICE_READ: &str = "Authorities.Invoice_READ";

/// The calls that leave the process.
#[async_trait]
pub trait Outside: Send + Sync {
    /// `IFeignFilesService.createSecuredKeyInternal(filePath)`: the relative download URL.
    async fn secured_key(&self, file_path: &str) -> AuthResult<String>;
    /// `WebClient.post(base + path)` with the seller's Basic credentials: the response map.
    async fn razorpay(&self, path: &str, key_id: &str, key_secret: &str, body: &Value) -> AuthResult<Value>;
    /// `ClientUrlService.getAppUrlInternal(appCode, appId, clientId)`.
    async fn app_url(&self, internal: &Internal, ca: &ContextAuth, app: &App, client_id: u64) -> AuthResult<String>;
}

fn http() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder().timeout(std::time::Duration::from_secs(30)).build().unwrap_or_else(|_| reqwest::Client::new())
    })
}

/// The real calls: files through its upstream, Razorpay's API, the app URL from the schema.
pub struct Live {
    pub files: Option<Upstream>,
    pub razorpay_base: String,
}

impl Live {
    pub fn new(files: Option<Upstream>, razorpay_base: &str) -> Self {
        Self { files, razorpay_base: razorpay_base.to_string() }
    }
}

#[async_trait]
impl Outside for Live {
    async fn secured_key(&self, file_path: &str) -> AuthResult<String> {
        let Some(files) = &self.files else {
            return Err(AuthError::internal("files upstream is not configured ([files] upstream)"));
        };
        let url = format!("{}/api/files/internal/secured/createKey", files.base().await?);
        let resp = http().get(&url).query(&[("filePath", file_path)]).send().await.map_err(AuthError::internal)?;
        let status = resp.status();
        let text = resp.text().await.map_err(AuthError::internal)?;
        if !status.is_success() {
            return Err(AuthError::internal(format!("[{status}] during [GET] to [{url}]: {text}")));
        }
        Ok(text)
    }

    async fn razorpay(&self, path: &str, key_id: &str, key_secret: &str, body: &Value) -> AuthResult<Value> {
        let url = format!("{}{path}", self.razorpay_base);
        let basic = base64::engine::general_purpose::STANDARD.encode(format!("{key_id}:{key_secret}"));
        let resp = http()
            .post(&url)
            .header("Authorization", format!("Basic {basic}"))
            .json(body)
            .send()
            .await
            .map_err(AuthError::internal)?;
        let status = resp.status();
        if !status.is_success() {
            // `WebClientResponseException`'s message.
            return Err(AuthError::internal(format!("{} {} from POST {url}", status.as_u16(), status.canonical_reason().unwrap_or(""))));
        }
        resp.json::<Value>().await.map_err(AuthError::internal)
    }

    async fn app_url(&self, internal: &Internal, ca: &ContextAuth, app: &App, client_id: u64) -> AuthResult<String> {
        internal.app_url_for(ca, app, client_id).await
    }
}

/// One request's billing services: security-internal's state (the directory, the caches, the
/// client checks), the billing tables, the event sink and the outside calls.
pub struct Billing<'a> {
    pub internal: &'a Internal,
    pub store: &'a dyn AdminBillingStore,
    pub events: &'a dyn EventSink,
    pub outside: &'a dyn Outside,
}

impl<'a> Billing<'a> {
    pub fn dir(&self) -> &Directory {
        self.internal.dir()
    }

    /// `LocalDateTime.now()`: the server's wall time.
    pub fn now_local(&self) -> NaiveDateTime {
        self.internal.auth.clock.local()
    }

    /// `LocalDateTime.now(ZoneOffset.UTC)`.
    pub fn now_utc(&self) -> NaiveDateTime {
        self.internal.auth.clock.utc()
    }

    /// `LocalDate.now()`.
    pub fn today(&self) -> NaiveDate {
        self.now_local().date()
    }

    /// `AppService.getAppByCode(code)`.
    pub async fn app_by_code(&self, code: Option<&str>) -> AuthResult<Option<Arc<App>>> {
        let Some(code) = code else { return Err(AuthError::internal(NULL_KEY)) };
        self.dir().app_by_code(code).await
    }

    /// `ClientService.getClientBy(code)`.
    pub async fn client_by_code(&self, code: Option<&str>) -> AuthResult<Option<Arc<Client>>> {
        let Some(code) = code else { return Err(AuthError::internal(NULL_KEY)) };
        self.dir().client_by_code(code).await
    }

    /// `AppService.getAppByIdInternal` / `getAppById`: the cached app, `None` when there is none.
    pub async fn app_by_id(&self, id: u64) -> AuthResult<Option<Arc<App>>> {
        match self.dir().app_by_id(id).await {
            Ok(a) => Ok(Some(a)),
            Err(e) if e.status() == StatusCode::NOT_FOUND => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// `ClientService.getClientInfoById`.
    pub async fn client_info(&self, id: u64) -> AuthResult<Option<Arc<Client>>> {
        self.dir().client(id).await
    }

    /// `ClientService.isUserClientManageClient(ca, clientId)`.
    pub async fn manages(&self, ca: &ContextAuth, client_id: u64) -> AuthResult<bool> {
        self.internal.caller_manages_client(ca, client_id).await
    }

    /// `AppService.hasWriteAccess(appId, clientId)`; a null id matches nothing.
    pub async fn write_access(&self, app: Option<u64>, client: Option<u64>) -> AuthResult<bool> {
        match (app, client) {
            (Some(a), Some(c)) => self.store.has_write_access(a, c).await,
            _ => Ok(false),
        }
    }

    /// `dao.readById(id)`: the row or the 404.
    pub async fn read(&self, s: &'static Schema, id: Option<u64>) -> AuthResult<Rec> {
        let row = match id {
            Some(i) => self.store.by_id(s, i).await?,
            None => None,
        };
        row.ok_or_else(|| not_found(s.pojo, id))
    }

    /// `AppBillingConfigDAO.findByAppAndClient`: the first non-DELETED config.
    pub async fn config_of(&self, app: u64, client: u64) -> AuthResult<Option<Rec>> {
        let f = Find { not_deleted: true, first: true, ..Find::eq(vec![("APP_ID", Val::Id(app)), ("CLIENT_ID", Val::Id(client))]) };
        Ok(self.store.find(&CONFIG, &f).await?.into_iter().next())
    }

    /// `resolveConfigForBilledClient` / `resolveConfigForClient`: the client's own config for
    /// the app, else the nearest managing client's.
    pub async fn config_for_client(&self, app: u64, client: u64) -> AuthResult<Option<Rec>> {
        for ancestor in self.internal.client_hierarchy_ids(client).await? {
            if let Some(c) = self.config_of(app, ancestor).await? {
                return Ok(Some(c));
            }
        }
        Ok(None)
    }

    /// `evict(CACHE_NAME_CONFIG_BY_CODES, appCode, clientCode)` for a config.
    pub async fn evict_config(&self, config: &Rec) -> AuthResult<()> {
        let (Some(app), Some(client)) = (config.u64("appId"), config.u64("clientId")) else { return Ok(()) };
        let Some(app) = self.app_by_id(app).await? else { return Ok(()) };
        let Some(client) = self.client_info(client).await? else { return Ok(()) };
        let key = format!("{}{}", app.app_code, client.code());
        self.internal.caches().service.evict_everywhere(caches::BILLING_CONFIG_BY_CODES, &key).await;
        Ok(())
    }

    /// `evictWalletStatus(clientId, appId)`.
    pub async fn evict_wallet_status(&self, client: u64, app: u64) {
        self.internal.caches().service.evict_everywhere(caches::WALLET_STATUS, &format!("{client}{app}")).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusals() {
        assert_eq!(forbidden("the invoice").message(), "Permission/Role the invoice is required to use this operation");
        assert_eq!(params_not_found("bundle").message(), "Required params {bundle} for $ not found");
        assert_eq!(params_not_found("bundle").status(), StatusCode::BAD_REQUEST);
        assert_eq!(not_found("Invoice", None).message(), "Invoice with id null not found");
        assert_eq!(not_found("Invoice", Some(4)).status(), StatusCode::NOT_FOUND);
        let mut ca = ContextAuth::default();
        assert!(matches!(pre_authorize(&ca, &[ROLE_OWNER]), Err(AuthError::AccessDenied { .. })));
        ca.user.string_authorities = Some(vec!["Authorities.Logged_IN".into(), PAYMENT_CREATE.into()]);
        assert!(pre_authorize(&ca, &[ROLE_OWNER, PAYMENT_CREATE]).is_ok());
        assert!(pre_authorize(&ca, &[ROLE_OWNER]).is_err());
    }

    #[tokio::test]
    async fn live_calls_fail_without_their_targets() {
        let live = Live::new(None, RAZORPAY_BASE_URL);
        assert_eq!(live.razorpay_base, RAZORPAY_BASE_URL);
        assert!(live.secured_key("A/b.pdf").await.unwrap_err().to_string().contains("files upstream"));
        let refused = Live { files: Some(Upstream::fixed(&["http://127.0.0.1:1"])), razorpay_base: "http://127.0.0.1:1".into() };
        assert_eq!(refused.secured_key("A/b.pdf").await.unwrap_err().status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(refused.razorpay("/orders", "k", "s", &serde_json::json!({})).await.unwrap_err().status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
