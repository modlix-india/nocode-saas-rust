//! [`Directory`] on the security service, cached the way `FeignAuthenticationService` caches:
//! `appReadAccess` and `appWriteAccess` keyed `appCode:clientCode`, `byAppCodeExplicit` keyed
//! by app code, `clientHierarchyCodes` keyed by client code. Same names as Java, so security's
//! evictions of them reach these copies.

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use platform::cache::{CacheService, LocalCaches};
use platform::security::{OnBehalfOf, SecurityClient};
use serde_json::Value;

use super::Directory;

pub const CACHE_APP_READ_ACCESS: &str = "appReadAccess";
pub const CACHE_APP_WRITE_ACCESS: &str = "appWriteAccess";
pub const CACHE_APP_EXPLICIT: &str = "byAppCodeExplicit";
pub const CACHE_CLIENT_HIERARCHY_CODES: &str = "clientHierarchyCodes";

/// The fields of security's `App` the access check reads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExplicitApp {
    pub app_access_type: Option<String>,
    pub client_code: Option<String>,
    pub explicit_owner_client_code: Option<String>,
}

impl ExplicitApp {
    /// From security's JSON; `None` for the empty answer an unknown app gets.
    pub fn from_json(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        let s = |k: &str| o.get(k).and_then(Value::as_str).map(str::to_string);
        Some(Self {
            app_access_type: s("appAccessType"),
            client_code: s("clientCode"),
            explicit_owner_client_code: s("explicitOwnerClientCode"),
        })
    }

    pub fn is_explicit(&self) -> bool {
        self.app_access_type.as_deref() == Some("EXPLICIT")
    }
}

pub struct RemoteDirectory {
    security: SecurityClient,
    read: Arc<LocalCaches<String, bool>>,
    write: Arc<LocalCaches<String, bool>>,
    explicit: Arc<LocalCaches<String, ExplicitApp>>,
    hierarchy: Arc<LocalCaches<String, Vec<String>>>,
}

impl RemoteDirectory {
    pub fn new(security: SecurityClient, cache: &CacheService) -> Self {
        Self { security, read: cache.family(), write: cache.family(), explicit: cache.family(), hierarchy: cache.family() }
    }
}

#[async_trait]
impl Directory for RemoteDirectory {
    async fn app_inheritance(&self, app_code: &str, url_client_code: &str, client_code: &str) -> Result<Vec<String>> {
        self.security.app_inheritance(app_code, url_client_code, client_code).await
    }

    async fn has_read_access(&self, app_code: &str, client_code: &str) -> Result<bool> {
        let (sec, a, c) = (self.security.clone(), app_code.to_string(), client_code.to_string());
        let v = self
            .read
            .get_or_load(CACHE_APP_READ_ACCESS, format!("{app_code}:{client_code}"), || async move {
                Ok::<_, anyhow::Error>(Some(sec.has_read_access(&a, &c).await?))
            })
            .await?;
        Ok(v.unwrap_or(false))
    }

    async fn has_write_access(&self, app_code: &str, client_code: &str) -> Result<bool> {
        let (sec, a, c) = (self.security.clone(), app_code.to_string(), client_code.to_string());
        let v = self
            .write
            .get_or_load(CACHE_APP_WRITE_ACCESS, format!("{app_code}:{client_code}"), || async move {
                Ok::<_, anyhow::Error>(Some(sec.has_write_access(&a, &c).await?))
            })
            .await?;
        Ok(v.unwrap_or(false))
    }

    async fn does_client_manage_client_code(&self, managing: &str, client: &str) -> Result<bool> {
        self.security.does_client_manage_client_code(managing, client).await
    }

    async fn app_explicit_info(&self, app_code: &str) -> Result<Option<ExplicitApp>> {
        let (sec, a) = (self.security.clone(), app_code.to_string());
        self.explicit
            .get_or_load(CACHE_APP_EXPLICIT, app_code.to_string(), || async move {
                Ok::<_, anyhow::Error>(ExplicitApp::from_json(&sec.app_explicit_info(&a).await?))
            })
            .await
    }

    async fn has_delete_access(&self, caller: &OnBehalfOf, delete_app_code: &str, delete_client_code: &str) -> Result<bool> {
        self.security.has_delete_access(caller, delete_app_code, delete_client_code).await
    }

    async fn find_base_client_code_for_override(&self, caller: &OnBehalfOf, application_code: &str) -> Result<Option<(String, bool)>> {
        self.security.find_base_client_code_for_override(caller, application_code).await
    }

    async fn client_hierarchy_codes(&self, client_code: &str) -> Result<Vec<String>> {
        let (sec, c) = (self.security.clone(), client_code.to_string());
        let v = self
            .hierarchy
            .get_or_load(CACHE_CLIENT_HIERARCHY_CODES, client_code.to_string(), || async move {
                Ok::<_, anyhow::Error>(Some(sec.client_hierarchy_codes(&c).await?))
            })
            .await?;
        Ok(v.unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn explicit_app_from_security_json() {
        let a = ExplicitApp::from_json(&json!({"appAccessType": "EXPLICIT", "clientCode": "SYSTEM", "explicitOwnerClientCode": "FIN"})).unwrap();
        assert!(a.is_explicit());
        assert_eq!(a.explicit_owner_client_code.as_deref(), Some("FIN"));
        assert!(ExplicitApp::from_json(&Value::Null).is_none());
        assert!(!ExplicitApp::default().is_explicit());
    }
}
