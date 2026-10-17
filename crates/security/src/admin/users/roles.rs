//! `RoleV2Controller` / `RoleV2Service`: roles (client-check reads), their sub-role tree, and the
//! roles a caller can hand out in an app.

use std::collections::HashMap;

use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::Router;
use serde_json::{Map, Value};

use super::common::{
    not_found, object_body, page_response, patch_error, pre_authorize, pre_authorize_all, refuse, string_value, u64_value, ulong_patch_failure, Fields,
};
use crate::admin::{Admin, AdminState};
use crate::caches;
use crate::condition::{from_params, to_sql, Cond};
use crate::data::audit::{action, entity_changed, object};
use crate::data::crud::client_check;
use crate::data::roles::{role, role_values, ROLE};
use crate::dto::Role;
use crate::errors::AuthResult;
use crate::jackson::json;
use crate::javamap::{grouping_order, long_hash};
use crate::model::ContextAuth;
use crate::spring::Pageable;
use crate::web::{no_content_json, query_body, to_u64};

/// The name in Java's messages.
const ROLE_NAME: &str = "Role";
/// `RoleV2.class.getSimpleName()`: the 404 of a read and the audit texts.
const CLASS: &str = "RoleV2";

/// `RoleV2` as Jackson reads a request body (`permissions` is ignored).
pub fn role_from_body(m: &Map<String, Value>) -> AuthResult<Role> {
    let f = Fields(m);
    // The typed parts are read (and refused) whole; their content is never used.
    for k in ["subRoles"] {
        if !matches!(m.get(k), None | Some(Value::Null) | Some(Value::Array(_))) {
            return Err(crate::web::unreadable());
        }
    }
    if !matches!(m.get("app"), None | Some(Value::Null) | Some(Value::Object(_))) {
        return Err(crate::web::unreadable());
    }
    f.string("authority")?;
    f.u64("parentRoleId")?;
    Ok(Role {
        id: f.u64("id")?.unwrap_or(0),
        client_id: f.u64("clientId")?,
        app_id: f.u64("appId")?,
        app_name: f.string("appName")?,
        name: f.string("name")?,
        short_name: f.string("shortName")?,
        description: f.string("description")?,
        created_by: f.u64("createdBy")?,
        created_at: f.ts("createdAt")?,
        updated_by: f.u64("updatedBy")?,
        updated_at: f.ts("updatedAt")?,
        sub_roles: None,
    })
}

/// The setters `RoleV2` declares, as the reflective PATCH calls them.
fn patch_role(r: &mut Role, fields: &Map<String, Value>) -> AuthResult<()> {
    for (k, v) in fields {
        match k.as_str() {
            "clientId" => r.client_id = u64_value(Some(v)).map_err(|_| ulong_patch_failure())?,
            "appId" => r.app_id = u64_value(Some(v)).map_err(|_| ulong_patch_failure())?,
            "parentRoleId" => {
                u64_value(Some(v)).map_err(|_| ulong_patch_failure())?;
            }
            "appName" => r.app_name = string_value(Some(v)).map_err(|_| patch_error(k))?,
            "name" => r.name = string_value(Some(v)).map_err(|_| patch_error(k))?,
            "shortName" => r.short_name = string_value(Some(v)).map_err(|_| patch_error(k))?,
            "description" => r.description = string_value(Some(v)).map_err(|_| patch_error(k))?,
            "authority" => {
                string_value(Some(v)).map_err(|_| patch_error(k))?;
            }
            "subRoles" | "permissions" if !matches!(v, Value::Null | Value::Array(_)) => return Err(patch_error(k)),
            "app" if !matches!(v, Value::Null | Value::Object(_)) => return Err(patch_error(k)),
            _ => {}
        }
    }
    Ok(())
}

impl Admin {
    /// `RoleV2Service.read` as another service calls it (through its proxy): `Role_READ`, then
    /// the read.
    pub async fn role_read_checked(&self, ca: &ContextAuth, id: u64) -> AuthResult<Role> {
        pre_authorize(ca, &["Authorities.Role_READ"])?;
        self.role_read(ca, id).await
    }

    /// `RoleV2DAO.readById`: the client-check read, 404 when missing.
    pub async fn role_read(&self, ca: &ContextAuth, id: u64) -> AuthResult<Role> {
        let row = self.db.entity_by_id(&ROLE, client_check(ca), id).await?;
        row.as_ref().map(role).transpose()?.ok_or_else(|| not_found(CLASS, id))
    }

    /// `RoleV2Service.create`.
    pub async fn role_create(&self, ca: &ContextAuth, mut r: Role) -> AuthResult<Role> {
        pre_authorize(ca, &["Authorities.Role_CREATE"])?;
        match r.client_id {
            None => r.client_id = Some(ca.user.client_id()),
            Some(c) if !ca.is_system_client() && !self.caller_manages_client(ca, c).await? => {
                return Err(refuse(StatusCode::FORBIDDEN, "forbidden_create", &[ROLE_NAME]));
            }
            Some(_) => {}
        }
        r.created_by = None;
        let id = self.db.entity_insert(&ROLE, &role_values(&r)).await?;
        let created = self.db.role(id).await?.ok_or_else(|| not_found(CLASS, id))?;
        entity_changed(&self.db, None, object::ROLE, action::CREATE, id, created.client_id, CLASS, created.name.as_deref());
        Ok(created)
    }

    /// `RoleV2Service.update(entity)`: only the names and the description change.
    pub async fn role_update(&self, ca: &ContextAuth, r: &Role) -> AuthResult<Role> {
        if !self.db.entity_can_be_updated(&ROLE, client_check(ca), r.id).await? {
            return Err(refuse(StatusCode::NOT_FOUND, "object_not_found", &[ROLE_NAME, &r.id.to_string()]));
        }
        let mut existing = self.role_read(ca, r.id).await?;
        existing.short_name = r.short_name.clone();
        existing.description = r.description.clone();
        existing.name = r.name.clone();
        existing.updated_at = None;
        self.db.entity_update(&ROLE, existing.id, &role_values(&existing)).await?;
        let updated = self.role_read(ca, existing.id).await?;
        entity_changed(&self.db, None, object::ROLE, action::UPDATE, updated.id, updated.client_id, CLASS, updated.name.as_deref());
        Ok(updated)
    }

    /// `RoleV2Service.update(id, fields)`.
    pub async fn role_patch(&self, ca: &ContextAuth, id: u64, fields: &Map<String, Value>) -> AuthResult<Role> {
        if !self.db.entity_can_be_updated(&ROLE, client_check(ca), id).await? {
            return Err(refuse(StatusCode::NOT_FOUND, "object_not_found", &[ROLE_NAME, &id.to_string()]));
        }
        let mut r = self.role_read(ca, id).await?;
        patch_role(&mut r, fields)?;
        let updated = self.role_update(ca, &r).await?;
        entity_changed(&self.db, None, object::ROLE, action::UPDATE, updated.id, updated.client_id, CLASS, updated.name.as_deref());
        Ok(updated)
    }

    /// `RoleV2Service.delete`.
    pub async fn role_delete(&self, ca: &ContextAuth, id: u64) -> AuthResult<()> {
        pre_authorize(ca, &["Authorities.Role_DELETE"])?;
        self.role_read(ca, id).await?;
        let existing = self.role_read(ca, id).await?;
        match self.db.delete_role(id).await {
            Ok(_) => {}
            Err(sqlx::Error::Database(_)) => return Err(refuse(StatusCode::FORBIDDEN, "delete_role_error", &[])),
            Err(e) => return Err(e.into()),
        }
        entity_changed(&self.db, None, object::ROLE, action::DELETE, id, existing.client_id, CLASS, existing.name.as_deref());
        Ok(())
    }

    /// `readPageFilter` with `enrich`: each role's app code and sub-roles.
    pub async fn role_page(&self, ca: &ContextAuth, page: &Pageable, cond: Option<&Cond>) -> AuthResult<(Vec<Role>, i64)> {
        pre_authorize(ca, &["Authorities.Role_READ"])?;
        let sql = match cond {
            Some(c) => to_sql(c, &ROLE.table)?,
            None => None,
        };
        let (rows, total) = self.db.entity_page(&ROLE, client_check(ca), sql, page).await?;
        let mut roles = rows.iter().map(role).collect::<AuthResult<Vec<_>>>()?;
        if roles.is_empty() {
            return Ok((roles, total));
        }
        let mut app_ids: Vec<u64> = roles.iter().filter_map(|r| r.app_id).collect();
        app_ids.sort_unstable();
        app_ids.dedup();
        let codes = self.db.app_codes_of(&app_ids).await?;
        let ids: Vec<u64> = roles.iter().map(|r| r.id).collect();
        let mut subs: HashMap<u64, Vec<Role>> = HashMap::new();
        for (parent, sub) in self.db.sub_role_rows(&ids).await? {
            subs.entry(parent).or_default().push(sub);
        }
        for r in &mut roles {
            if let Some(a) = r.app_id {
                r.app_name = codes.get(&a).cloned();
            }
            r.sub_roles = Some(subs.get(&r.id).cloned().unwrap_or_default());
        }
        Ok((roles, total))
    }

    /// `getSubRoles`.
    pub async fn role_sub_roles(&self, ca: &ContextAuth, id: u64) -> AuthResult<Vec<Role>> {
        pre_authorize(ca, &["Authorities.Role_READ"])?;
        self.role_read(ca, id).await?;
        self.db.sub_roles_of(id).await
    }

    /// `canManage`.
    async fn can_manage_role(&self, ca: &ContextAuth, r: &Role) -> AuthResult<bool> {
        if ca.is_system_client() {
            return Ok(true);
        }
        self.caller_manages_client(ca, r.client_id.unwrap_or_default()).await
    }

    /// `assignSubRole`.
    pub async fn role_assign_sub_role(&self, ca: &ContextAuth, role_id: u64, sub_role_id: u64) -> AuthResult<bool> {
        pre_authorize_all(ca, &["Authorities.Role_UPDATE", "Authorities.Role_READ"])?;
        if role_id == sub_role_id {
            return Err(refuse(StatusCode::BAD_REQUEST, "sub_role_self", &[]));
        }
        let forbidden = || refuse(StatusCode::FORBIDDEN, "forbidden_update", &[ROLE_NAME]);
        let r = self.role_read(ca, role_id).await?;
        let sub = self.role_read(ca, sub_role_id).await?;
        if !self.can_manage_role(ca, &r).await? || !self.can_manage_role(ca, &sub).await? {
            return Err(forbidden());
        }
        if self.db.role_closure(sub_role_id, true).await?.contains(&role_id) {
            let (a, b) = (sub.name.clone().unwrap_or_else(|| "null".into()), r.name.clone().unwrap_or_else(|| "null".into()));
            return Err(refuse(StatusCode::BAD_REQUEST, "sub_role_cycle", &[&a, &b]));
        }
        let added = self.db.has_sub_role(role_id, sub_role_id).await? || self.db.add_sub_role(role_id, sub_role_id).await?;
        self.evict_role_authorities(role_id).await?;
        Ok(added)
    }

    /// `removeSubRole`.
    pub async fn role_remove_sub_role(&self, ca: &ContextAuth, role_id: u64, sub_role_id: u64) -> AuthResult<bool> {
        pre_authorize_all(ca, &["Authorities.Role_UPDATE", "Authorities.Role_READ"])?;
        let r = self.role_read(ca, role_id).await?;
        if !self.can_manage_role(ca, &r).await? {
            return Err(refuse(StatusCode::FORBIDDEN, "forbidden_update", &[ROLE_NAME]));
        }
        let removed = self.db.remove_sub_role(role_id, sub_role_id).await?;
        self.evict_role_authorities(role_id).await?;
        Ok(removed > 0)
    }

    /// `evictRoleAuthorities`: the authorities of every profile holding an ancestor of the role,
    /// and every user's roles.
    pub async fn evict_role_authorities(&self, role_id: u64) -> AuthResult<()> {
        let ancestors: Vec<u64> = self.db.role_closure(role_id, false).await?.into_iter().collect();
        for pid in self.db.profile_ids_with_any_role(&ancestors).await? {
            self.caches().service.evict_all_everywhere(&format!("{}{pid}", caches::PROFILE_AUTHS_PREFIX)).await;
        }
        self.caches().service.evict_all_everywhere(caches::USER_ROLES).await;
        Ok(())
    }

    /// `ProfileService.getRolesForAssignmentInApp`: the roles in the profiles the caller's
    /// client sees in the app.
    async fn profile_roles_for_app(&self, ca: &ContextAuth, app_code: &str) -> AuthResult<Vec<Role>> {
        let refused = || refuse(StatusCode::FORBIDDEN, "forbidden_role_access", &[]);
        let Some(app) = self.dir().app_by_code(app_code).await? else { return Err(refused()) };
        let h = self.dir().hierarchy(ca.user.client_id()).await?;
        if !self.db.has_read_access_ids(app.id, h.client_id).await? {
            return Err(refused());
        }
        let mut profiles = self.db.restricted_profile_ids_distinct(h.client_id, app.id).await?;
        if profiles.is_empty() {
            profiles = self.db.visible_profile_ids(app.id, &h.client_ids()).await?;
        }
        self.db.roles_of_profiles(&profiles).await
    }

    /// `RoleV2Controller.assignableRoles` with `fetchSubRolesAlso`.
    pub async fn assignable_roles(&self, ca: &ContextAuth, app_code: &str) -> AuthResult<Vec<Role>> {
        let h = self.dir().hierarchy(ca.user.client_id()).await?;
        let own = self.db.client_roles_for_app(app_code, h.client_id).await?;
        let from_profiles = self.profile_roles_for_app(ca, app_code).await?;
        let mut list = if own.is_empty() {
            from_profiles
        } else if from_profiles.is_empty() {
            own
        } else {
            own.into_iter().chain(from_profiles).collect()
        };
        let ids: Vec<u64> = list.iter().map(|r| r.id).collect();
        let mut groups: HashMap<u64, Vec<Role>> = HashMap::new();
        let mut first_seen = Vec::new();
        for (parent, sub) in self.db.sub_role_rows(&ids).await? {
            if !groups.contains_key(&parent) {
                first_seen.push(parent);
            }
            groups.entry(parent).or_default().push(sub);
        }
        for r in &mut list {
            if let Some(g) = groups.get(&r.id) {
                r.sub_roles = Some(g.clone());
            }
        }
        for parent in grouping_order(first_seen.into_iter().map(|p| (long_hash(p), p)).collect()) {
            list.extend(groups.remove(&parent).unwrap_or_default());
        }
        Ok(list)
    }
}

fn role_json(r: &Role) -> Value {
    r.to_json()
}

macro_rules! r {
    ($name:ident, $path:expr, |$s:ident, $r:ident, $ca:ident| $body:block) => {
        $crate::web_route!($name, AdminState, $path, true, |$s, $r, $ca| $body);
    };
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

r!(list, "/rolev2", |s, r, ca| {
    let page = Pageable::from_params(&r.params);
    let cond = from_params(&r.params.0);
    let (items, total) = s.role_page(&ca, &page, cond.as_ref()).await?;
    Ok(page_response(items.iter().map(role_json).collect(), &page, total))
});

r!(query, "/rolev2/query", |s, r, ca| {
    let (page, cond) = query_body(&r.body)?;
    let (items, total) = s.role_page(&ca, &page, cond.as_ref()).await?;
    Ok(page_response(items.iter().map(role_json).collect(), &page, total))
});

r!(create, "/rolev2", |s, r, ca| {
    let body = role_from_body(&object_body(&r.body)?)?;
    Ok(json(&s.role_create(&ca, body).await?.to_json()))
});

rp!(read, "/rolev2/{id}", |s, r, ca, id| {
    let id = to_u64(&id)?;
    pre_authorize(&ca, &["Authorities.Role_READ"])?;
    Ok(json(&s.role_read(&ca, id).await?.to_json()))
});

rp!(put, "/rolev2/{id}", |s, r, ca, id| {
    let id = to_u64(&id)?;
    let mut body = role_from_body(&object_body(&r.body)?)?;
    body.id = id;
    pre_authorize(&ca, &["Authorities.Role_UPDATE"])?;
    Ok(json(&s.role_update(&ca, &body).await?.to_json()))
});

rp!(patch, "/rolev2/{id}", |s, r, ca, id| {
    let id = to_u64(&id)?;
    let body = object_body(&r.body)?;
    pre_authorize(&ca, &["Authorities.Role_UPDATE"])?;
    Ok(json(&s.role_patch(&ca, id, &body).await?.to_json()))
});

rp!(remove, "/rolev2/{id}", |s, r, ca, id| {
    let id = to_u64(&id)?;
    s.role_delete(&ca, id).await?;
    Ok(no_content_json())
});

rp!(sub_roles, "/rolev2/{id}/subRoles", |s, r, ca, id| {
    let id = to_u64(&id)?;
    Ok(json(&Value::Array(s.role_sub_roles(&ca, id).await?.iter().map(role_json).collect())))
});

rp2!(assign_sub_role, "/rolev2/{roleId}/subRoles/{subRoleId}", |s, r, ca, a, b| {
    let (a, b) = (to_u64(&a)?, to_u64(&b)?);
    Ok(json(&Value::Bool(s.role_assign_sub_role(&ca, a, b).await?)))
});

rp2!(remove_sub_role, "/rolev2/{roleId}/subRoles/{subRoleId}", |s, r, ca, a, b| {
    let (a, b) = (to_u64(&a)?, to_u64(&b)?);
    Ok(json(&Value::Bool(s.role_remove_sub_role(&ca, a, b).await?)))
});

rp!(assignable, "/rolev2/assignable/{appCode}", |s, r, ca, app_code| {
    Ok(json(&Value::Array(s.assignable_roles(&ca, &app_code).await?.iter().map(role_json).collect())))
});

pub fn router() -> Router<AdminState> {
    Router::new()
        .route("/api/security/rolev2", get(list).post(create))
        .route("/api/security/rolev2/query", post(query))
        .route("/api/security/rolev2/{id}", get(read).put(put).patch(patch).delete(remove))
        .route("/api/security/rolev2/{id}/subRoles", get(sub_roles))
        .route("/api/security/rolev2/{roleId}/subRoles/{subRoleId}", post(assign_sub_role).delete(remove_sub_role))
        .route("/api/security/rolev2/assignable/{appCode}", get(assignable))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn bodies_and_patches() {
        let r = role_from_body(json!({"clientId": "4", "name": "R", "permissions": 5, "subRoles": [], "app": {"id": 1}}).as_object().unwrap()).unwrap();
        assert_eq!((r.client_id, r.name.as_deref()), (Some(4), Some("R")));
        assert!(role_from_body(json!({"subRoles": 1}).as_object().unwrap()).is_err());
        assert!(role_from_body(json!({"app": "x"}).as_object().unwrap()).is_err());
        assert!(role_from_body(json!({"parentRoleId": "x"}).as_object().unwrap()).is_err());
        let mut p = r.clone();
        patch_role(&mut p, json!({"name": "N", "shortName": 3, "id": 9}).as_object().unwrap()).unwrap();
        assert_eq!((p.name.as_deref(), p.short_name.as_deref(), p.id), (Some("N"), Some("3"), 0));
        assert_eq!(patch_role(&mut p, json!({"appId": "x"}).as_object().unwrap()).unwrap_err().status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(patch_role(&mut p, json!({"name": [1]}).as_object().unwrap()).unwrap_err().status(), StatusCode::BAD_REQUEST);
        assert!(patch_role(&mut p, json!({"subRoles": "x"}).as_object().unwrap()).is_err());
        assert!(patch_role(&mut p, json!({"app": 1}).as_object().unwrap()).is_err());
        assert!(patch_role(&mut p, json!({"permissions": [1], "app": null}).as_object().unwrap()).is_ok());
        let j = Role { id: 1, sub_roles: Some(vec![]), ..Default::default() }.to_json();
        assert!(j.get("subRoles").is_none());
    }
}

#[cfg(test)]
mod live {
    use super::*;
    use crate::admin::users::testkit::{fx, sys, NONE};
    use crate::spring::Params;
    use serde_json::json;

    #[test]
    fn patch_setters() {
        let o = |v: Value| v.as_object().unwrap().clone();
        let mut r = Role::default();
        patch_role(&mut r, &o(json!({"parentRoleId": 3, "authority": "A", "appName": "x", "subRoles": [], "app": {}}))).unwrap();
        assert_eq!(r.app_name.as_deref(), Some("x"));
        assert_eq!(patch_role(&mut r, &o(json!({"parentRoleId": "x"}))).unwrap_err().status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(patch_role(&mut r, &o(json!({"authority": [1]}))).unwrap_err().status(), StatusCode::BAD_REQUEST);
        assert_eq!(patch_role(&mut r, &o(json!({"permissions": 1}))).unwrap_err().status(), StatusCode::BAD_REQUEST);
        assert_eq!(patch_role(&mut r, &o(json!({"app": 1}))).unwrap_err().status(), StatusCode::BAD_REQUEST);
    }

    /// `RoleV2ServiceTest`: a client's own caller, refusals, sub-roles and the assignable roles.
    #[tokio::test]
    async fn roles_of_a_client() {
        let Some(fx) = fx().await else { return };
        let (s, c, m) = (&fx.s, fx.c, fx.m);
        let sys = sys();
        let run = fx.run.clone();
        let a = fx.user(c, "a").await;
        let auth = &["Authorities.Role_CREATE", "Authorities.Role_READ", "Authorities.Role_UPDATE", "Authorities.Role_DELETE"];
        let own = fx.as_user(&a, "ZZRUL", auth);
        let r1 = s.role_create(&own, Role { name: Some(format!("zz r1 {run}")), ..Default::default() }).await.unwrap();
        assert_eq!(r1.client_id, Some(c));
        let r2 = s.role_create(&own, Role { name: Some(format!("zz r2 {run}")), ..Default::default() }).await.unwrap();
        assert_eq!(s.role_create(&own, Role { client_id: Some(1), name: Some("x".into()), ..Default::default() }).await.unwrap_err().status(), StatusCode::FORBIDDEN);
        let in_m = s.role_create(&sys, Role { client_id: Some(m), name: Some(format!("zz rm {run}")), ..Default::default() }).await.unwrap();
        assert_eq!(s.role_update(&sys, &Role { id: NONE, name: Some("x".into()), ..Default::default() }).await.unwrap_err().status(), StatusCode::NOT_FOUND);
        assert_eq!(s.role_patch(&sys, NONE, json!({"name": "x"}).as_object().unwrap()).await.unwrap_err().status(), StatusCode::NOT_FOUND);
        // Sub-roles by the client's own caller; ZZRUM's role is not theirs to change.
        assert_eq!(s.role_assign_sub_role(&own, r1.id, r1.id).await.unwrap_err().status(), StatusCode::BAD_REQUEST);
        assert!(s.role_assign_sub_role(&own, r1.id, r2.id).await.unwrap());
        assert_eq!(s.role_assign_sub_role(&own, in_m.id, r2.id).await.unwrap_err().status(), StatusCode::FORBIDDEN);
        assert_eq!(s.role_remove_sub_role(&own, in_m.id, r2.id).await.unwrap_err().status(), StatusCode::FORBIDDEN);
        // A role held by a profile: its authorities are evicted with it.
        let p = super::super::profiles::profile_from_body(json!({"appId": 2, "clientId": c, "name": format!("zz rp {run}"), "arrangement": {"k": {"roleId": r1.id}}}).as_object().unwrap()).unwrap();
        s.profile_create(&sys, p).await.unwrap();
        s.evict_role_authorities(r2.id).await.unwrap();
        assert!(s.role_remove_sub_role(&own, r1.id, r2.id).await.unwrap());
        // A page that finds nothing.
        let page = Pageable::from_params(&Params::default());
        let none = crate::condition::Cond::Filter(crate::condition::Filter::eq("id", NONE.to_string()));
        let (found, total) = s.role_page(&own, &page, Some(&none)).await.unwrap();
        assert_eq!((found.len(), total), (0, 0));
        // The assignable roles: the client's own and its profiles' (both, or only one of them).
        let both = s.assignable_roles(&own, "appbuilder").await.unwrap();
        assert!(both.iter().any(|r| r.id == r1.id) && both.iter().any(|r| r.id == 70), "{:?}", both.iter().map(|r| r.id).collect::<Vec<_>>());
        let e = fx.user(m, "e").await;
        let below = fx.as_user(&e, "ZZRUM", auth);
        s.role_delete(&sys, in_m.id).await.unwrap();
        let profiles_only = s.assignable_roles(&below, "appbuilder").await.unwrap();
        assert!(!profiles_only.is_empty());
        let empty = super::super::profiles::profile_from_body(json!({"appId": 2, "clientId": c, "name": format!("zz re {run}")}).as_object().unwrap()).unwrap();
        let empty = s.profile_create(&sys, empty).await.unwrap().id.unwrap();
        s.profile_restrict_client(&sys, empty, c).await.unwrap();
        let own_only = s.assignable_roles(&own, "appbuilder").await.unwrap();
        assert!(own_only.iter().all(|r| r.client_id == Some(c)), "restricted to a profile without roles");
        fx.finish().await;
    }
}
