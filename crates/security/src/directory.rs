//! The cached reads the authentication paths make of users, clients, apps, policies and
//! authorities: `UserService`, `ClientService`, `ClientHierarchyService`, `AppService`,
//! `ProfileService` and the policy services, each through the same cache Java uses.

use std::sync::Arc;

use axum::http::StatusCode;

use crate::authorities;
use crate::caches::{self, Caches, RoleMap};
use crate::errors::{AuthError, AuthResult, INACTIVE_CLIENT, OBJECT_NOT_FOUND};
use crate::javamap::hash_set_order_u64;
use crate::model::{App, Client, ClientHierarchy, PassType, Policy, UrlPattern, User};
use crate::store::Store;

#[derive(Clone)]
pub struct Directory {
    pub store: Arc<dyn Store>,
    pub caches: Caches,
    /// `security.subdomain.endings`.
    pub subdomain_endings: Vec<String>,
}

impl Directory {
    pub fn new(store: Arc<dyn Store>, caches: Caches, subdomain_endings: Vec<String>) -> Self {
        Self { store, caches, subdomain_endings }
    }

    /// `UserService.readInternal`.
    pub async fn user(&self, id: u64) -> AuthResult<Option<Arc<User>>> {
        let store = self.store.clone();
        self.caches
            .users
            .get_or_load(caches::USER, id.to_string(), || async move { Ok(store.user_by_id(id).await?.map(Arc::new)) })
            .await
    }

    /// `ClientService.readInternal` / `getClientInfoById`.
    pub async fn client(&self, id: u64) -> AuthResult<Option<Arc<Client>>> {
        let store = self.store.clone();
        self.caches
            .clients
            .get_or_load(caches::CLIENT_ID, id.to_string(), || async move { Ok(store.client_by_id(id).await?.map(Arc::new)) })
            .await
    }

    /// `ClientService.getClientBy(clientCode)`.
    pub async fn client_by_code(&self, code: &str) -> AuthResult<Option<Arc<Client>>> {
        let store = self.store.clone();
        let c = code.to_string();
        self.caches
            .clients
            .get_or_load(caches::CLIENT_CODE, code.to_string(), || async move { Ok(store.client_by_code(&c).await?.map(Arc::new)) })
            .await
    }

    /// `ClientService.getClientTypeNCodeNClientLevel`: (type, code, level).
    pub async fn type_code_level(&self, id: u64) -> AuthResult<Option<Arc<(String, String, String)>>> {
        let store = self.store.clone();
        self.caches
            .type_levels
            .get_or_load(caches::CLIENT_TYPE_CODE_LEVEL, id.to_string(), || async move {
                Ok(store.client_type_code_level(id).await?.map(Arc::new))
            })
            .await
    }

    /// `ClientHierarchyService.getClientHierarchy`: a client without a row is a 500, as in Java.
    pub async fn hierarchy(&self, client_id: u64) -> AuthResult<Arc<ClientHierarchy>> {
        let store = self.store.clone();
        let h = self
            .caches
            .hierarchies
            .get_or_load(caches::CLIENT_HIERARCHY, client_id.to_string(), || async move {
                Ok::<_, AuthError>(store.client_hierarchy(client_id).await?.map(Arc::new))
            })
            .await?;
        h.ok_or_else(|| {
            AuthError::literal(StatusCode::INTERNAL_SERVER_ERROR, "SEC.CLIENT_HIERARCHY_MISSING", format!("No client hierarchy found for client id: {client_id}"))
                .with_param("client", client_id)
        })
    }

    /// `ClientService.getActiveClient`: every client up the hierarchy must be active.
    pub async fn active_client(&self, client_id: u64) -> AuthResult<Arc<Client>> {
        let ids = self.hierarchy(client_id).await?.client_ids();
        let active = self.store.count_active_clients(&ids).await? == ids.len() as i64;
        let client = if active { self.client(client_id).await? } else { None };
        client.ok_or_else(|| AuthError::msg(StatusCode::BAD_REQUEST, INACTIVE_CLIENT, &[]))
    }

    /// `ClientService.getManagedClientOfClientById`: the client's direct manager, or an empty
    /// client for a top-level one.
    pub async fn managed_client(&self, client_id: u64) -> AuthResult<Arc<Client>> {
        let this = self.clone();
        let c = self
            .caches
            .clients
            .get_or_load(caches::MANAGED_CLIENT, client_id.to_string(), || async move {
                let manager = this.hierarchy(client_id).await?.level0;
                let client = match manager {
                    Some(m) => this.client(m).await?,
                    None => None,
                };
                Ok::<_, AuthError>(Some(client.unwrap_or_default()))
            })
            .await?;
        Ok(c.unwrap_or_default())
    }

    /// `AppService.getAppByCode`.
    pub async fn app_by_code(&self, code: &str) -> AuthResult<Option<Arc<App>>> {
        let store = self.store.clone();
        let c = code.to_string();
        self.caches
            .apps
            .get_or_load(caches::APP_BY_CODE, code.to_string(), || async move { Ok(store.app_by_code(&c).await?.map(Arc::new)) })
            .await
    }

    /// `AppService.getAppById`: a missing app is the DAO's 404.
    pub async fn app_by_id(&self, id: u64) -> AuthResult<Arc<App>> {
        let store = self.store.clone();
        let app = self
            .caches
            .apps
            .get_or_load(caches::APP_BY_ID, id.to_string(), || async move {
                Ok::<_, AuthError>(store.app_by_id(id).await?.map(Arc::new))
            })
            .await?;
        app.ok_or_else(|| AuthError::msg(StatusCode::NOT_FOUND, OBJECT_NOT_FOUND, &["App", &id.to_string()]))
    }

    /// `AppService.hasReadAccess(appCode, clientCode)`.
    pub async fn has_read_access(&self, app_code: &str, client_code: Option<&str>) -> AuthResult<bool> {
        let store = self.store.clone();
        let (a, c) = (app_code.to_string(), client_code.unwrap_or("").to_string());
        let key = format!("{app_code}:{}", client_code.unwrap_or(""));
        let v = self
            .caches
            .flags
            .get_or_load(caches::APP_READ_ACCESS, key, || async move { Ok::<_, AuthError>(Some(store.has_read_access(&a, &c).await?)) })
            .await?;
        Ok(v.unwrap_or(false))
    }

    /// `ClientService.getClientAppPolicy(clientId, appCode, type)`: `None` when the app is unknown.
    pub async fn policy(&self, client_id: u64, app_code: Option<&str>, t: PassType) -> AuthResult<Option<Policy>> {
        let app = match app_code {
            Some(a) => self.app_by_code(a).await?,
            None => None,
        };
        match app {
            Some(app) => Ok(Some(self.policy_for_app(client_id, app.id, t).await?)),
            None => Ok(None),
        }
    }

    /// `AbstractPolicyService.getClientAppPolicy(clientId, appId)`: the first policy up the
    /// client hierarchy, else the type's default.
    pub async fn policy_for_app(&self, client_id: u64, app_id: u64, t: PassType) -> AuthResult<Policy> {
        for cid in self.hierarchy(client_id).await?.client_ids() {
            let store = self.store.clone();
            let p = self
                .caches
                .policies
                .get_or_load(t.policy_cache(), format!("{cid}:{app_id}"), || async move {
                    Ok::<_, AuthError>(Some(Arc::new(store.policy(t, cid, app_id).await?)))
                })
                .await?;
            if let Some(p) = p.and_then(|p| (*p).clone()) {
                return Ok(p);
            }
        }
        Ok(t.default_policy())
    }

    async fn url_patterns(&self) -> AuthResult<Arc<Vec<UrlPattern>>> {
        let store = self.store.clone();
        let list = self
            .caches
            .url_lists
            .get_or_load(caches::CLIENT_URL, caches::CLIENT_URL_KEY.to_string(), || async move {
                Ok::<_, AuthError>(Some(Arc::new(store.client_url_patterns().await?)))
            })
            .await?;
        Ok(list.unwrap_or_default())
    }

    /// `ClientService.subdomainAppCode`: the app a platform subdomain host names, if any.
    pub fn subdomain_app_code(&self, host: &str) -> Option<String> {
        let host = host.trim().to_lowercase();
        let ending = self.subdomain_endings.iter().find(|e| host.ends_with(e.as_str()))?;
        let code = &host[..host.len() - ending.len()];
        (!code.is_empty() && !code.contains('.')).then(|| code.to_string())
    }

    /// `ClientService.getClientPattern(scheme, host, port)`. Unlike Java, a host that resolves to
    /// no pattern is cached as such (see [`caches::Caches::url_patterns`]).
    pub async fn client_pattern(&self, scheme: &str, host: &str, port: &str) -> AuthResult<Option<Arc<UrlPattern>>> {
        let this = self.clone();
        let (h, p) = (host.to_string(), port.to_string());
        let found = self
            .caches
            .url_patterns
            .get_or_load(caches::CLIENT_URI, format!("{scheme}{host}:{port}"), || async move {
                if let Some(found) = this.url_patterns().await?.iter().find(|u| u.matches(&h, &p)) {
                    return Ok(Some(Some(Arc::new(found.clone()))));
                }
                let Some(code) = this.subdomain_app_code(&h) else { return Ok(Some(None)) };
                let Some(app) = this.app_by_code(&code).await?.filter(|a| a.status.as_deref() == Some("ACTIVE")) else {
                    return Ok(Some(None));
                };
                let client = this.client(app.client_id).await?;
                Ok::<_, AuthError>(Some(client.map(|c| {
                    Arc::new(UrlPattern::new(String::new(), c.code.clone(), Some(h.clone()), Some(app.app_code.clone())))
                })))
            })
            .await?;
        Ok(found.flatten())
    }

    /// `ClientService.getClientBy(request)`: the client a host names, else SYSTEM (id 1).
    ///
    /// A pattern made from an app's subdomain carries an empty identifier, which Java turns
    /// into a ULong and fails on ("Empty input string"): kept, so both answer 500.
    pub async fn client_for_host(&self, scheme: &str, host: &str, port: &str) -> AuthResult<Option<Arc<Client>>> {
        let id = match self.client_pattern(scheme, host, port).await? {
            Some(p) => p.identifier.parse::<u64>().map_err(|_| {
                AuthError::internal(if p.identifier.is_empty() { "Empty input string".into() } else { p.identifier.clone() })
            })?,
            None => 1,
        };
        self.client(id).await
    }

    /// `RoleV2Service.getRoleAuthoritiesPerApp`, cached as `userRoles`.
    pub async fn role_map(&self, user_id: u64) -> AuthResult<Arc<RoleMap>> {
        let store = self.store.clone();
        let m = self
            .caches
            .role_maps
            .get_or_load(caches::USER_ROLES, user_id.to_string(), || async move {
                let roles = authorities::distinct_rows(store.user_roles(user_id).await?);
                let ids: Vec<u64> = roles.iter().filter_map(|r| r.id).collect();
                let perms = authorities::distinct_rows(store.role_permissions(&ids).await?);
                Ok::<_, AuthError>(Some(Arc::new(authorities::role_map(&roles, &perms)?)))
            })
            .await?;
        Ok(m.unwrap_or_default())
    }

    /// `ProfileDAO.getProfileAuthorities(profileId, hierarchy)`, cached per profile and client.
    pub async fn profile_authorities_of(&self, profile_id: u64, h: Arc<ClientHierarchy>) -> AuthResult<Arc<Vec<String>>> {
        let store = self.store.clone();
        let cache = format!("{}{profile_id}", caches::PROFILE_AUTHS_PREFIX);
        let list = self
            .caches
            .string_lists
            .get_or_load(&cache, h.client_id.to_string(), || async move {
                let profiles = store.profile_rows(profile_id, &h.client_ids()).await?;
                let profile_ids: Vec<u64> = distinct_ids(profiles.iter().filter_map(|p| p.id));
                let rows = store.profile_role_rows(&profile_ids).await?;
                let roles = authorities::select_role_records(&rows, profile_id, &h)?;
                let role_ids: Vec<u64> = distinct_ids(roles.iter().filter_map(|r| r.role_id));
                let sub_roles = store.sub_role_rows(&role_ids).await?;
                let all_ids: Vec<u64> = role_ids.iter().copied().chain(sub_roles.iter().filter_map(|s| s.id)).collect();
                let permissions = store.permission_rows(&all_ids).await?;
                Ok::<_, AuthError>(Some(Arc::new(authorities::profile_authority_names(&profiles, &roles, &sub_roles, &permissions)?)))
            })
            .await?;
        Ok(list.unwrap_or_default())
    }

    /// `ProfileService.getProfileAuthorities(appCode, clientId, userId)`.
    pub async fn profile_authorities(&self, app_code: Option<&str>, client_id: u64, user_id: u64) -> AuthResult<Vec<String>> {
        let mut ids = self.store.profile_ids(app_code, user_id).await?;
        if ids.is_empty() {
            ids = self.store.default_profile_ids(app_code).await?;
        }
        let h = self.hierarchy(client_id).await?;
        let mut lists = Vec::new();
        for pid in hash_set_order_u64(ids) {
            lists.push((*self.profile_authorities_of(pid, h.clone()).await?).clone());
        }
        Ok(authorities::merge_profile_lists(lists))
    }

    /// `UserService.getUserAuthorities(appCode, clientId, userId)`.
    pub async fn user_authorities(&self, app_code: Option<&str>, client_id: u64, user_id: u64) -> AuthResult<Vec<String>> {
        let roles = authorities::role_authorities(&*self.role_map(user_id).await?, app_code);
        let profiles = self.profile_authorities(app_code, client_id, user_id).await?;
        Ok(authorities::user_authorities(roles, profiles))
    }
}

/// The ids of a `Collectors.toSet()`: the `IN (...)` list does not depend on their order.
fn distinct_ids(ids: impl Iterator<Item = u64>) -> Vec<u64> {
    let mut seen = std::collections::HashSet::new();
    ids.filter(|i| seen.insert(*i)).collect()
}
