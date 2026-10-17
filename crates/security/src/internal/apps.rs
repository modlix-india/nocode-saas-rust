//! `AppService`, as the internal application routes use it.

use std::sync::Arc;

use super::Internal;
use crate::caches;
use crate::data::apps::AppDependency;
use crate::dto::ExplicitApp;
use crate::errors::{AuthError, AuthResult};

/// `AppDAO.appInheritance`'s rule: the owner's code, then the URL client's and the client's
/// where they differ.
pub fn inheritance(owner: Option<&str>, url_client_code: Option<&str>, client_code: &str) -> Vec<Option<String>> {
    let owner_s = owner.map(str::to_string);
    let same = owner == Some(client_code);
    match url_client_code {
        Some(u) if u != client_code => vec![owner_s, Some(u.to_string()), Some(client_code.to_string())],
        _ if same => vec![owner_s],
        _ => vec![owner_s, Some(client_code.to_string())],
    }
}

impl Internal {
    /// `AppService.appInheritance`, cached by appCode:urlClientCode:clientCode. `None` for an
    /// unknown app.
    pub async fn app_inheritance(&self, app_code: &str, url_client_code: &str, client_code: &str) -> AuthResult<Option<Arc<Vec<String>>>> {
        let db = self.db.clone();
        let (a, u, c) = (app_code.to_string(), url_client_code.to_string(), client_code.to_string());
        self.caches()
            .string_lists
            .get_or_load(caches::APP_INHERITANCE, format!("{app_code}:{url_client_code}:{client_code}"), || async move {
                let Some(owner) = db.app_owner_code(&a).await? else { return Ok::<_, AuthError>(None) };
                // A null element would make Java's List.of throw; an app always has an owner.
                let list = inheritance(owner.as_deref(), Some(&u), &c).into_iter().map(Option::unwrap_or_default).collect();
                Ok(Some(Arc::new(list)))
            })
            .await
    }

    /// `AppService.getAppExplicitInfoByCode`, cached by appCode.
    pub async fn app_explicit_info(&self, app_code: &str) -> AuthResult<Option<Arc<ExplicitApp>>> {
        let this_db = self.db.clone();
        let dir = self.dir().clone();
        let code = app_code.to_string();
        self.caches()
            .explicit_apps
            .get_or_load(caches::APP_BY_CODE_EXPLICIT, app_code.to_string(), || async move {
                let Some(app) = this_db.app_by_code(&code).await? else { return Ok::<_, AuthError>(None) };
                let explicit_client_id = if app.app_access_type.as_deref() == Some("EXPLICIT") {
                    this_db.explicit_edit_client(app.id).await?
                } else {
                    None
                };
                let Some(owner) = dir.client(app.client_id).await? else { return Ok(None) };
                let explicit_owner_client_code = match explicit_client_id {
                    Some(id) => dir.client(id).await?.and_then(|c| c.code.clone()),
                    None => None,
                };
                Ok(Some(Arc::new(ExplicitApp { client_code: owner.code.clone(), explicit_client_id, explicit_owner_client_code, app })))
            })
            .await
    }

    /// `AppService.getAppDependencies` (`cacheEmptyValueOrGet`): `None` for an unknown app or one
    /// without dependencies.
    pub async fn app_dependencies(&self, app_code: &str) -> AuthResult<Option<Vec<AppDependency>>> {
        let db = self.db.clone();
        let code = app_code.to_string();
        let v = self
            .caches()
            .dependencies
            .get_or_load(caches::APP_DEPENDENCIES, app_code.to_string(), || async move {
                let deps = match db.app_by_code(&code).await? {
                    Some(app) => Some(db.app_dependencies(app.id).await?).filter(|d| !d.is_empty()),
                    None => None,
                };
                Ok::<_, AuthError>(Some(Arc::new(deps)))
            })
            .await?;
        Ok(v.and_then(|v| (*v).clone()))
    }

    /// `AppService.getAppStatus`, cached by appCode.
    pub async fn app_status(&self, app_code: &str) -> AuthResult<Option<Arc<String>>> {
        let dir = self.dir().clone();
        let code = app_code.to_string();
        self.caches()
            .strings
            .get_or_load(caches::APP_STATUS, app_code.to_string(), || async move {
                Ok::<_, AuthError>(dir.app_by_code(&code).await?.and_then(|a| a.status.clone()).map(Arc::new))
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> Option<String> {
        Some(v.to_string())
    }

    #[test]
    fn inheritance_like_app_dao() {
        assert_eq!(inheritance(Some("SYSTEM"), None, "SYSTEM"), vec![s("SYSTEM")]);
        assert_eq!(inheritance(Some("SYSTEM"), None, "BUS"), vec![s("SYSTEM"), s("BUS")]);
        assert_eq!(inheritance(Some("SYSTEM"), Some("BUS"), "BUS"), vec![s("SYSTEM"), s("BUS")]);
        assert_eq!(inheritance(Some("BUS"), Some("BUS"), "BUS"), vec![s("BUS")]);
        assert_eq!(inheritance(Some("SYSTEM"), Some("BUS"), "CUST"), vec![s("SYSTEM"), s("BUS"), s("CUST")]);
        assert_eq!(inheritance(None, Some("A"), "A"), vec![None, s("A")]);
    }
}
