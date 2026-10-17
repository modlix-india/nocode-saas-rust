//! `ClientManagerController` / `ClientManagerService`: which users manage which clients
//! (`security_client_manager`): listed per manager, added, replaced, removed, moved from one
//! manager to another, and synced for a client.

use axum::http::StatusCode;
use axum::routing::{get, post, put};
use axum::Router;
use serde_json::Value;

use super::common::pre_authorize;
use crate::admin::{Admin, AdminState};
use crate::caches;
use crate::dto::{client_json, ClientExtras};
use crate::errors::{AuthError, AuthResult};
use crate::expr::has_authority;
use crate::jackson::json;
use crate::model::ContextAuth;
use crate::spring::Pageable;
use crate::web::{id_list_body, req_u64, to_u64, type_mismatch};

/// `ClientManagerService.AUTHORIZED_ROLE`.
const AUTHORIZED_ROLE: &str = "Authorities.ROLE_Owner or Authorities.ROLE_Client_Manager";

fn forbidden(what: &str) -> AuthError {
    AuthError::msg(StatusCode::FORBIDDEN, "forbidden_permission", &[what])
}

fn hierarchy_error(what: &str) -> AuthError {
    AuthError::msg(StatusCode::BAD_REQUEST, "hierarchy_error", &[what])
}

impl Admin {
    /// `checkAccess`: may the caller make managers of the target user's client?
    async fn manager_access(&self, ca: &ContextAuth, target_client: u64) -> AuthResult<bool> {
        if ca.is_system_client() {
            return Ok(true);
        }
        let own = ca.user.client_id();
        if own == target_client {
            return Ok(has_authority(Some(AUTHORIZED_ROLE), &crate::internal::scope::authorities(ca)));
        }
        Ok(self.dir().hierarchy(target_client).await?.is_managed_by(own))
    }

    /// `evictCacheForUserAndClient`.
    async fn evict_manager_flag(&self, user_id: u64, client_id: u64) {
        self.caches().service.evict_everywhere(caches::CLIENT_MANAGER, &format!("{user_id}{client_id}")).await;
    }

    /// `ClientManagerService.create`.
    pub async fn client_manager_create(&self, ca: &ContextAuth, user_id: u64, client_id: u64) -> AuthResult<bool> {
        pre_authorize(ca, &["Authorities.Client_UPDATE"])?;
        let refused = || forbidden("Client Manager CREATE");
        let Some(u) = self.dir().user(user_id).await? else { return Err(refused()) };
        if u.client_id == client_id {
            return Err(hierarchy_error("Client manager"));
        }
        if !self.manager_access(ca, u.client_id).await? {
            return Err(refused());
        }
        self.db.add_client_manager(client_id, user_id, ca.user.id()).await?;
        self.evict_manager_flag(user_id, client_id).await;
        Ok(true)
    }

    /// `getClientsOfUser`: a page of the clients the user manages.
    pub async fn clients_of_manager(&self, ca: &ContextAuth, user_id: u64, page: &Pageable) -> AuthResult<Value> {
        pre_authorize(ca, &["Authorities.Client_READ"])?;
        let refused = || forbidden("Client Manager READ");
        let Some(u) = self.dir().user(user_id).await? else { return Err(refused()) };
        if !self.manager_access(ca, u.client_id).await? {
            return Err(refused());
        }
        let (ids, total) = self.db.manager_client_page(user_id, page.size, page.offset()).await?;
        let mut clients = Vec::new();
        for id in ids {
            if let Some(c) = self.dir().client(id).await? {
                clients.push(client_json(&c, &ClientExtras::default()));
            }
        }
        Ok(crate::web::page_of(clients, page, total))
    }

    /// `updateManager`: the new manager added (and the old one, when named, removed).
    pub async fn client_manager_replace(&self, ca: &ContextAuth, client_id: u64, old: Option<u64>, new: u64) -> AuthResult<bool> {
        pre_authorize(ca, &["Authorities.Client_UPDATE"])?;
        let refused = || forbidden("Client Manager UPDATE");
        let Some(m) = self.dir().user(new).await? else { return Err(refused()) };
        if m.client_id == client_id {
            return Err(hierarchy_error("Client manager"));
        }
        if !self.manager_access(ca, m.client_id).await? {
            return Err(refused());
        }
        if let Some(o) = old {
            self.db.remove_client_manager(client_id, o).await?;
        }
        self.db.add_client_manager(client_id, new, ca.user.id()).await?;
        if let Some(o) = old {
            self.evict_manager_flag(o, client_id).await;
        }
        self.evict_manager_flag(new, client_id).await;
        Ok(true)
    }

    /// `ClientManagerService.delete`.
    pub async fn client_manager_delete(&self, ca: &ContextAuth, user_id: u64, client_id: u64) -> AuthResult<bool> {
        pre_authorize(ca, &["Authorities.Client_UPDATE"])?;
        let refused = || forbidden("Client Manager DELETE");
        let Some(u) = self.dir().user(user_id).await? else { return Err(refused()) };
        if !self.manager_access(ca, u.client_id).await? {
            return Err(refused());
        }
        self.db.remove_client_manager(client_id, user_id).await?;
        self.evict_manager_flag(user_id, client_id).await;
        Ok(true)
    }

    /// `migrateClientManagersFrom`.
    pub async fn client_managers_migrate(&self, ca: &ContextAuth, from: u64, to: u64, remove: bool) -> AuthResult<u64> {
        pre_authorize(ca, &["Authorities.Client_UPDATE"])?;
        let refused = || forbidden("Client Manager MIGRATE");
        if from == to {
            return Err(hierarchy_error("Client manager migration"));
        }
        let Some(f) = self.dir().user(from).await? else { return Err(refused()) };
        if self.dir().user(to).await?.is_none() {
            return Err(refused());
        }
        if !self.manager_access(ca, f.client_id).await? {
            return Err(refused());
        }
        let clients = self.db.client_ids_of_manager(from).await?;
        let n = self.db.migrate_client_managers(from, to, ca.user.id(), remove).await?;
        for c in clients {
            if remove {
                self.evict_manager_flag(from, c).await;
            }
            self.evict_manager_flag(to, c).await;
        }
        Ok(n)
    }

    /// `syncManagers`: the client's managers made exactly these.
    pub async fn client_managers_sync(&self, ca: &ContextAuth, client_id: u64, managers: &[u64]) -> AuthResult<bool> {
        pre_authorize(ca, &["Authorities.Client_UPDATE"])?;
        if managers.is_empty() {
            return Err(AuthError::msg(StatusCode::BAD_REQUEST, "params_not_found", &["manager list", "sync"]));
        }
        for m in managers {
            if self.dir().user(*m).await?.is_some_and(|u| u.client_id == client_id) {
                return Err(hierarchy_error("Client manager"));
            }
        }
        if !self.manager_access(ca, client_id).await? {
            return Err(forbidden("Client Manager SYNC"));
        }
        let current: Vec<u64> = self.db.manager_rows(&[client_id]).await?.into_iter().map(|(_, m)| m).collect();
        self.db.replace_client_managers(client_id, managers, ca.user.id()).await?;
        let mut affected: Vec<u64> = current.into_iter().chain(managers.iter().copied()).collect();
        affected.sort_unstable();
        affected.dedup();
        for u in affected {
            self.evict_manager_flag(u, client_id).await;
        }
        Ok(true)
    }
}

macro_rules! rp {
    ($name:ident, $path:expr, |$s:ident, $r:ident, $ca:ident, $p:ident| $body:block) => {
        $crate::web_route_path!($name, AdminState, $path, true, |$s, $r, $ca, $p| $body);
    };
}

macro_rules! rp2 {
    ($name:ident, $path:expr, |$s:ident, $r:ident, $ca:ident, $p:ident, $q:ident| $body:block) => {
        $crate::web_route_path2!($name, AdminState, $path, true, |$s, $r, $ca, $p, $q| $body);
    };
}

fn bool_out(b: bool) -> axum::response::Response {
    json(&Value::Bool(b))
}

rp!(clients_of_user, "/client-managers/{uid}", |s, r, ca, uid| {
    let uid = to_u64(&uid)?;
    let page = Pageable::from_params(&r.params);
    Ok(json(&s.clients_of_manager(&ca, uid, &page).await?))
});

rp2!(create, "/client-managers/{uid}/{clientId}", |s, r, ca, uid, cid| {
    let (uid, cid) = (to_u64(&uid)?, to_u64(&cid)?);
    Ok(bool_out(s.client_manager_create(&ca, uid, cid).await?))
});

rp2!(remove, "/client-managers/{uid}/{clientId}", |s, r, ca, uid, cid| {
    let (uid, cid) = (to_u64(&uid)?, to_u64(&cid)?);
    Ok(bool_out(s.client_manager_delete(&ca, uid, cid).await?))
});

rp!(replace, "/client-managers/{clientId}", |s, r, ca, cid| {
    let cid = to_u64(&cid)?;
    let old = crate::web::opt_u64(&r.params, "oldManagerId")?;
    let new = req_u64(&r.params, "newManagerId")?;
    Ok(bool_out(s.client_manager_replace(&ca, cid, old, new).await?))
});

rp!(migrate, "/client-managers/migrateTo/{uid}", |s, r, ca, uid| {
    let to = to_u64(&uid)?;
    let from = req_u64(&r.params, "fromUid")?;
    let remove = match r.params.get("removeManager") {
        None => true,
        Some(v) => match v.trim().to_lowercase().as_str() {
            "true" | "on" | "yes" | "1" | "" => true,
            "false" | "off" | "no" | "0" => false,
            _ => return Err(type_mismatch()),
        },
    };
    Ok(json(&Value::from(s.client_managers_migrate(&ca, from, to, remove).await?)))
});

rp!(sync, "/client-managers/{clientId}/managers", |s, r, ca, cid| {
    let cid = to_u64(&cid)?;
    let ids = id_list_body(&r.body)?;
    Ok(bool_out(s.client_managers_sync(&ca, cid, &ids).await?))
});

pub fn router() -> Router<AdminState> {
    Router::new()
        .route("/api/security/client-managers/migrateTo/{uid}", post(migrate))
        .route("/api/security/client-managers/{uid}", get(clients_of_user).post(replace))
        .route("/api/security/client-managers/{clientId}/managers", put(sync))
        .route("/api/security/client-managers/{uid}/{clientId}", post(create).delete(remove))
}

#[cfg(test)]
mod live {
    use super::*;
    use crate::admin::users::testkit::{fx, sys, NONE};

    /// `ClientManagerServiceTest`: callers of the client itself and of other clients.
    #[tokio::test]
    async fn managers_and_their_refusals() {
        let Some(fx) = fx().await else { return };
        let (s, c, m, i) = (&fx.s, fx.c, fx.m, fx.i);
        let sys = sys();
        let a = fx.user(c, "a").await;
        let b = fx.user(c, "b").await;
        let e = fx.user(m, "e").await;
        let x = fx.user(i, "x").await;
        let update = &["Authorities.Client_UPDATE", "Authorities.Client_READ"];
        // A caller of ZZRUL: an Owner may make managers of its users, a plain member may not.
        let mut owner = fx.as_user(&a, "ZZRUL", update);
        owner.user.string_authorities.as_mut().unwrap().push("Authorities.ROLE_Owner".into());
        let plain = fx.as_user(&a, "ZZRUL", update);
        assert!(s.client_manager_create(&owner, b.id, m).await.unwrap());
        assert_eq!(s.client_manager_create(&plain, b.id, i).await.unwrap_err().status(), StatusCode::FORBIDDEN);
        // A caller of ZZRUI manages nothing of ZZRUL's.
        let other = fx.as_user(&x, "ZZRUI", update);
        assert_eq!(s.client_manager_create(&other, NONE, m).await.unwrap_err().status(), StatusCode::FORBIDDEN);
        let page = Pageable::from_params(&crate::spring::Params::default());
        assert_eq!(s.clients_of_manager(&other, b.id, &page).await.unwrap_err().status(), StatusCode::FORBIDDEN);
        assert_eq!(s.client_manager_replace(&sys, m, None, e.id).await.unwrap_err().status(), StatusCode::BAD_REQUEST, "of its own client");
        assert_eq!(s.client_manager_replace(&other, m, None, b.id).await.unwrap_err().status(), StatusCode::FORBIDDEN);
        assert!(s.client_manager_replace(&owner, m, Some(b.id), a.id).await.unwrap());
        assert!(s.client_manager_replace(&owner, m, None, b.id).await.unwrap());
        assert_eq!(s.client_manager_delete(&other, b.id, m).await.unwrap_err().status(), StatusCode::FORBIDDEN);
        assert_eq!(s.client_managers_migrate(&sys, NONE, a.id, true).await.unwrap_err().status(), StatusCode::FORBIDDEN);
        assert_eq!(s.client_managers_migrate(&sys, a.id, NONE, true).await.unwrap_err().status(), StatusCode::FORBIDDEN);
        assert_eq!(s.client_managers_migrate(&other, a.id, b.id, true).await.unwrap_err().status(), StatusCode::FORBIDDEN);
        assert_eq!(s.client_managers_migrate(&owner, a.id, b.id, false).await.unwrap(), 0, "b manages ZZRUM already");
        assert_eq!(s.client_managers_sync(&other, m, &[a.id]).await.unwrap_err().status(), StatusCode::FORBIDDEN);
        assert!(s.client_managers_sync(&owner, m, &[a.id]).await.unwrap());
        assert!(s.client_manager_delete(&owner, a.id, m).await.unwrap());
        // One left for the fixture's sweep to remove.
        assert!(s.client_manager_create(&sys, a.id, m).await.unwrap());
        fx.finish().await;
    }
}
