//! The caller restrictions the Java DAOs add to their list queries (`ClientDAO.filter`,
//! `UserDAO.filter`): nothing for a SYSTEM client caller, the managed hierarchy for an Owner,
//! otherwise the clients managed by the people in the caller's reporting tree.

use super::Internal;
use crate::data::clients::Scope;
use crate::data::users::UserScope;
use crate::errors::AuthResult;
use crate::expr::has_authority;
use crate::model::ContextAuth;

pub const OWNER_ROLE: &str = "Authorities.ROLE_Owner";
/// `ClientManagerService.AUTHORIZED_ROLE`.
pub const CLIENT_MANAGER_ROLES: &str = "Authorities.ROLE_Owner or Authorities.ROLE_Client_Manager";

/// `ContextAuthentication.getAuthorities()` as strings.
pub fn authorities(ca: &ContextAuth) -> Vec<String> {
    ca.user.string_authorities.clone().unwrap_or_default()
}

impl Internal {
    /// `getSubOrgManagedClientIds`: the clients managed by the caller or anyone below them.
    async fn sub_org_managed_clients(&self, client_id: u64, user_id: u64) -> AuthResult<Vec<u64>> {
        let sub_org = self.db.sub_org_user_ids(client_id, user_id).await?;
        self.db.client_ids_of_managers(&sub_org).await
    }

    /// `ClientDAO.filter`'s restriction.
    pub async fn client_scope(&self, ca: &ContextAuth) -> AuthResult<Scope> {
        if ca.is_system_client() {
            return Ok(Scope::All);
        }
        let client_id = ca.user.client_id();
        if has_authority(Some(OWNER_ROLE), &authorities(ca)) {
            return Ok(Scope::Owner { client_id });
        }
        let managed = self.sub_org_managed_clients(client_id, ca.user.id()).await?;
        Ok(Scope::Managed { client_id, managed })
    }

    /// `UserDAO.filter`'s restriction.
    pub async fn user_scope(&self, ca: &ContextAuth) -> AuthResult<UserScope> {
        if ca.is_system_client() {
            return Ok(UserScope::All);
        }
        let client_id = ca.user.client_id();
        if has_authority(Some(OWNER_ROLE), &authorities(ca)) {
            return Ok(UserScope::Owner { client_id });
        }
        let external =
            self.sub_org_managed_clients(client_id, ca.user.id()).await?.into_iter().filter(|c| *c != client_id).collect();
        Ok(UserScope::Managed { client_id, external })
    }
}
