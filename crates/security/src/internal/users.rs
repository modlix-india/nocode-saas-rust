//! `UserService`, `UserSubOrganizationService` and `ProfileService`, as the internal user routes
//! use them.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;

use super::clients::ids_in;
use super::scope::OWNER_ROLE;
use super::Internal;
use crate::caches;
use crate::condition::{from_params, to_sql_with, Cond};
use crate::data::clients::Rows;
use crate::data::filters;
use crate::data::users::UsersListRequest;
use crate::dto::{user_json, Designation, UserExtras, PLACEHOLDER};
use crate::errors::{AuthError, AuthResult};
use crate::expr::has_authority;
use crate::javamap::hash_set_order_u64;
use crate::jackson::Obj;
use crate::model::{ContextAuth, User};
use crate::org::OrgStructure;
use crate::spring::{safe_bool, Pageable, Params};

/// The fill options `UserService.fillDetails` reads off the query parameters.
#[derive(Debug, Clone, Default)]
pub struct UserFill {
    pub app_code: Option<String>,
    pub app_id: Option<String>,
    pub profiles: bool,
    pub client: bool,
    pub managing_client: bool,
    pub created_by: bool,
    pub designation: bool,
    pub reporting_to: bool,
}

impl UserFill {
    pub fn from_params(p: &Params) -> Self {
        Self {
            app_code: p.get("appCode").map(str::to_string),
            app_id: p.get("appId").map(str::to_string),
            profiles: safe_bool(p.get("fetchProfiles")),
            client: safe_bool(p.get("fetchClients")),
            managing_client: safe_bool(p.get("fetchManagingClients")),
            created_by: safe_bool(p.get("fetchCreatedBy")),
            designation: safe_bool(p.get("fetchDesignation")),
            reporting_to: safe_bool(p.get("fetchReportingTo")),
        }
    }
}

/// `EntityProcessorUser`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcessorUser {
    pub id: u64,
    pub role_id: Option<u64>,
    pub designation_id: Option<u64>,
    pub department_id: Option<u64>,
    /// A `HashSet<Long>`: written in its iteration order.
    pub profile_ids: Vec<u64>,
}

impl ProcessorUser {
    pub fn to_json(&self) -> Value {
        Obj::new()
            .put("id", self.id)
            .put("roleId", crate::jackson::opt(self.role_id))
            .put("designationId", crate::jackson::opt(self.designation_id))
            .put("departmentId", crate::jackson::opt(self.department_id))
            .put("profileIds", Value::from(hash_set_order_u64(self.profile_ids.iter().copied())))
            .build()
    }
}

/// `UserDAO.mapUsers`: one entry per user in first-seen order; designation, department and role
/// from the user's first row; every profile collected.
#[allow(clippy::type_complexity)]
pub fn processor_users(rows: &[(u64, Option<u64>, Option<u64>, Option<u64>, Option<u64>)]) -> Vec<ProcessorUser> {
    let mut order: Vec<u64> = Vec::new();
    let mut by_id: HashMap<u64, ProcessorUser> = HashMap::new();
    for (id, designation, department, role, profile) in rows {
        let u = by_id.entry(*id).or_insert_with(|| {
            order.push(*id);
            ProcessorUser { id: *id, role_id: *role, designation_id: *designation, department_id: *department, profile_ids: vec![] }
        });
        if let Some(p) = profile {
            if !u.profile_ids.contains(p) {
                u.profile_ids.push(*p);
            }
        }
    }
    order.into_iter().filter_map(|id| by_id.remove(&id)).collect()
}

/// `getUserAdminEmails` / `getOwnersEmails` bodies (`Map.of`: any key order is Java's).
pub fn emails_json(emails: Vec<String>, add_app: Option<bool>) -> Value {
    let mut m = serde_json::Map::new();
    m.insert("emails".into(), Value::from(emails));
    if let Some(a) = add_app {
        m.insert("addApp".into(), Value::Bool(a));
    }
    Value::Object(m)
}

impl Internal {
    /// `UserService.fillDetails`: every user kept, in order, filled where a lookup finds
    /// something.
    pub async fn fill_users(&self, ca: &ContextAuth, users: Vec<Arc<User>>, fill: &UserFill) -> AuthResult<Vec<Value>> {
        let mut out = Vec::with_capacity(users.len());
        for u in users {
            let mut x = UserExtras::default();
            let id_of = |v: Option<u64>| v.filter(|i| *i != 0);
            if fill.profiles {
                x.profiles = self.user_profiles(ca, &u, fill).await?;
            }
            if fill.client {
                if let Some(id) = id_of(Some(u.client_id)) {
                    x.client = self.dir().client(id).await.unwrap_or(None);
                }
            }
            if fill.managing_client {
                if let Some(id) = id_of(Some(u.client_id)) {
                    x.managing_client = self.dir().managed_client(id).await.ok();
                }
            }
            if fill.created_by {
                if let Some(id) = id_of(u.created_by) {
                    x.created_by_user = self.dir().user(id).await.unwrap_or(None);
                }
            }
            if fill.designation {
                if let Some(id) = id_of(u.designation_id) {
                    x.designation = self.designation(id).await.unwrap_or(None);
                }
            }
            if fill.reporting_to {
                if let Some(id) = id_of(u.reporting_to) {
                    x.reporting_user = self.dir().user(id).await.unwrap_or(None);
                }
            }
            out.push(user_json(&u, &x));
        }
        Ok(out)
    }

    /// `ProfileService.fillUser`: the user's profiles (of the app named by code, or by id; all of
    /// them when neither resolves), each read as the caller, as Java's `read` would.
    async fn user_profiles(&self, ca: &ContextAuth, u: &User, fill: &UserFill) -> AuthResult<Option<Vec<Value>>> {
        let app_id = match fill.app_code.as_deref().filter(|c| !c.trim().is_empty()) {
            Some(code) => self.dir().app_by_code(code).await?.map(|a| a.id),
            None => fill.app_id.as_deref().and_then(|a| a.trim().parse::<u64>().ok()),
        };
        let list = self.assigned_profiles(ca, u.id, app_id, false).await?;
        Ok(Some(list.iter().map(|p| p.to_json()).collect()))
    }

    /// `DesignationService.readInternal`, cached by id.
    pub async fn designation(&self, id: u64) -> AuthResult<Option<Arc<Designation>>> {
        let db = self.db.clone();
        self.caches()
            .designations
            .get_or_load(caches::DESIGNATION, id.to_string(), || async move {
                Ok::<_, AuthError>(db.designation(id).await?.map(Arc::new))
            })
            .await
    }

    /// `UserService.readById(userId, queryParams)`.
    pub async fn user_by_id_filled(&self, ca: &ContextAuth, id: u64, fill: &UserFill) -> AuthResult<Option<Value>> {
        let Some(u) = self.dir().user(id).await? else { return Ok(None) };
        Ok(self.fill_users(ca, vec![u], fill).await?.into_iter().next())
    }

    async fn users_where(&self, ca: &ContextAuth, cond: &Cond) -> AuthResult<Vec<Arc<User>>> {
        let scope = self.user_scope(ca).await?;
        let sql = to_sql_with(cond, &filters::USER, &filters::user_hook)?;
        let Rows { rows, .. } = self.db.users_matching(&scope, sql, None).await?;
        Ok(rows.into_iter().map(Arc::new).collect())
    }

    /// `UserService.readByIds`.
    pub async fn users_by_ids(&self, ca: &ContextAuth, ids: &[u64], fill: &UserFill) -> AuthResult<Vec<Value>> {
        let users = self.users_where(ca, &ids_in("id", ids)).await?;
        self.fill_users(ca, users, fill).await
    }

    /// `UserService.readByClientIds`: every query parameter is also a filter
    /// (`ConditionUtil.parameterMapToMap`), so `appCode` restricts the users to the app.
    pub async fn users_by_client_ids(&self, ca: &ContextAuth, client_ids: &[u64], params: &Params, fill: &UserFill) -> AuthResult<Vec<Value>> {
        let mut cond = ids_in("clientId", client_ids);
        if let Some(extra) = from_params(&params.0) {
            cond = Cond::and(vec![cond, extra]);
        }
        let users = self.users_where(ca, &cond).await?;
        self.fill_users(ca, users, fill).await
    }

    /// `UserService.readPageFilterInternal` + `fillDetails`.
    pub async fn users_page(&self, ca: &ContextAuth, page: &Pageable, cond: Option<&Cond>, fill: &UserFill) -> AuthResult<Value> {
        let scope = self.user_scope(ca).await?;
        let sql = match cond {
            Some(c) => to_sql_with(c, &filters::USER, &filters::user_hook)?,
            None => None,
        };
        let order = crate::condition::order_by(&page.sort, &filters::USER);
        let Rows { rows, total } = self.db.users_matching(&scope, sql, Some((page, order))).await?;
        let len = rows.len();
        let content = self.fill_users(ca, rows.into_iter().map(Arc::new).collect(), fill).await?;
        let total = crate::spring::known_total(len, page).unwrap_or(total.unwrap_or(0));
        Ok(crate::web::page_json(content, page, total))
    }

    /// `ProfileService.getAppProfilesHavingAuthorities`: the app's profiles visible to the
    /// client (its restricted ones, else all) that grant any of the authorities.
    async fn app_profiles_having(&self, app_id: u64, client_id: u64, authorities: &[&str]) -> AuthResult<Vec<u64>> {
        let h = self.dir().hierarchy(client_id).await?;
        let mut ids = self.db.restricted_profiles(h.client_id, app_id).await?;
        if ids.is_empty() {
            ids = self.db.app_profiles(app_id, &h.client_ids()).await?;
        }
        let mut out = Vec::new();
        for pid in ids {
            let granted = self.dir().profile_authorities_of(pid, h.clone()).await?;
            if authorities.iter().any(|a| granted.iter().any(|g| g == a)) {
                out.push(pid);
            }
        }
        Ok(out)
    }

    /// `UserService.getUserAdminEmails`: the e-mails of the users who may create users in the
    /// app, else of the client's owners (`addApp`).
    pub async fn admin_emails(&self, app_code: Option<&str>, client_code: Option<&str>) -> AuthResult<Value> {
        let fallback = || emails_json(vec![], Some(false));
        let Some(app) = (match app_code {
            Some(a) => self.dir().app_by_code(a).await?,
            None => None,
        }) else {
            return Ok(fallback());
        };
        let Some(client) = (match client_code {
            Some(c) => self.client_by_code(c).await?,
            None => None,
        }) else {
            return Ok(fallback());
        };
        let profiles = self.app_profiles_having(app.id, client.id(), &["Authorities.User_CREATE", OWNER_ROLE]).await?;
        let admins = self.db.users_for_profiles(&profiles, client.id()).await?;
        let emails = |users: &[User]| -> Vec<String> {
            users.iter().filter_map(|u| u.email_id.clone().filter(|e| e != PLACEHOLDER)).collect()
        };
        if !admins.is_empty() {
            return Ok(emails_json(emails(&admins), Some(false)));
        }
        let owners = self.db.owners_of(client.id()).await?;
        Ok(emails_json(emails(&owners), Some(true)))
    }

    /// `UserService.getOwnersEmails`.
    pub async fn owner_emails(&self, app_code: Option<&str>, client_code: Option<&str>) -> AuthResult<Value> {
        let fallback = || emails_json(vec![], None);
        let Some(app) = (match app_code {
            Some(a) => self.dir().app_by_code(a).await?,
            None => None,
        }) else {
            return Ok(fallback());
        };
        let Some(client) = (match client_code {
            Some(c) => self.client_by_code(c).await?,
            None => None,
        }) else {
            return Ok(fallback());
        };
        Ok(match self.owners_emails(client.id(), app_code, Some(app.id)).await? {
            Some(e) => emails_json(e, None),
            None => fallback(),
        })
    }

    /// `UserService.getUsersForNotification`.
    pub async fn users_for_notification(&self, r: &UsersListRequest) -> AuthResult<Vec<Value>> {
        Ok(self
            .db
            .users_for_notification(r)
            .await?
            .into_iter()
            .map(|(id, client_id, email)| {
                Obj::new().put("id", id).put("clientId", client_id).put("emailId", crate::jackson::opt(email)).build()
            })
            .collect())
    }

    /// `UserService.getUsersForEntityProcessor`.
    pub async fn users_for_processor(&self, r: &UsersListRequest) -> AuthResult<Vec<Value>> {
        Ok(processor_users(&self.db.processor_rows(r).await?).iter().map(ProcessorUser::to_json).collect())
    }

    /// `UserSubOrganizationService.getUserSubOrgInternal`: an Owner sees every user of the client,
    /// anyone else themselves and everyone below them.
    pub async fn user_sub_org(&self, app_code: &str, client_id: u64, user_id: u64) -> AuthResult<Vec<u64>> {
        let authorities = self.dir().user_authorities(Some(app_code), client_id, user_id).await?;
        if has_authority(Some(OWNER_ROLE), &authorities) {
            let db = self.db.clone();
            let dir = self.dir().clone();
            let ids = self
                .caches()
                .id_lists
                .get_or_load(caches::USER_SUB_ORG, format!("{client_id}:owner"), || async move {
                    let Some(t) = dir.type_code_level(client_id).await? else { return Ok::<_, AuthError>(Some(Arc::new(vec![]))) };
                    Ok(Some(Arc::new(db.user_ids_of_client(client_id, t.0 == "SYS").await?)))
                })
                .await?;
            return Ok(ids.map(|i| (*i).clone()).unwrap_or_default());
        }
        let tree = self.org_structure(client_id).await?;
        Ok(tree.sub_org(user_id, true))
    }

    /// `OrgStructureService.getOrgStructure`, cached as `orgStructure:<clientId>`.
    pub async fn org_structure(&self, client_id: u64) -> AuthResult<Arc<OrgStructure>> {
        let db = self.db.clone();
        let t = self
            .caches()
            .orgs
            .get_or_load(caches::USER_SUB_ORG, format!("orgStructure:{client_id}"), || async move {
                Ok::<_, AuthError>(Some(Arc::new(OrgStructure::new(&db.org_edges(client_id).await?))))
            })
            .await?;
        Ok(t.unwrap_or_default())
    }

    /// `ProfileService.getProfileUsers`: `None` for an unknown app.
    pub async fn profile_users(&self, app_code: Option<&str>, profile_ids: &[u64]) -> AuthResult<Option<Vec<u64>>> {
        let Some(app) = (match app_code {
            Some(a) => self.dir().app_by_code(a).await?,
            None => None,
        }) else {
            return Ok(None);
        };
        if profile_ids.is_empty() {
            return Ok(Some(vec![]));
        }
        Ok(Some(self.db.profile_user_ids(app.id, profile_ids).await?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn processor_users_group_like_map_users() {
        let rows = vec![
            (5, Some(1), Some(2), Some(3), Some(40)),
            (5, None, None, Some(9), Some(17)),
            (5, None, None, None, Some(40)),
            (6, None, None, None, None),
        ];
        let users = processor_users(&rows);
        assert_eq!(users.len(), 2);
        assert_eq!(users[0], ProcessorUser { id: 5, role_id: Some(3), designation_id: Some(1), department_id: Some(2), profile_ids: vec![40, 17] });
        assert_eq!(users[0].to_json()["profileIds"], serde_json::json!([17, 40]));
        assert_eq!(users[1].to_json(), serde_json::json!({"id": 6}));
    }

    #[test]
    fn email_bodies_and_flags() {
        assert_eq!(emails_json(vec!["a@b".into()], Some(true)), serde_json::json!({"emails": ["a@b"], "addApp": true}));
        assert_eq!(emails_json(vec![], None), serde_json::json!({"emails": []}));
        let f = UserFill::from_params(&Params::from_query(Some("fetchClients=true&fetchDesignation=1&appId=4")));
        assert!(f.client && f.designation && !f.profiles && !f.reporting_to);
    }
}

#[cfg(test)]
mod live {
    use super::*;
    use crate::admin::users::testkit::{fx, sys};

    /// `UserServiceTest.fillDetails` and the notification look-ups' fallbacks.
    #[tokio::test]
    async fn fills_and_fallbacks() {
        let Some(fx) = fx().await else { return };
        let s = &fx.s;
        let a = fx.user(fx.c, "a").await;
        let (st, des) = fx.http("POST", "/designations", Some(serde_json::json!({"clientId": fx.c, "name": format!("zz fd {}", fx.run)}))).await;
        assert!(st.is_success(), "{des}");
        let made = User {
            client_id: fx.c,
            user_name: Some(format!("zzrl{}f", fx.run)),
            created_by: Some(a.id),
            reporting_to: Some(a.id),
            designation_id: des["id"].as_u64(),
            status_code: "ACTIVE".into(),
            ..Default::default()
        };
        let b = s.user_create(&sys(), made).await.unwrap();
        let fill = UserFill { client: true, managing_client: true, created_by: true, designation: true, reporting_to: true, ..Default::default() };
        let out = s.fill_users(&sys(), vec![Arc::new(b.clone())], &fill).await.unwrap();
        let v = &out[0];
        assert_eq!((v["reportingUser"]["id"].as_u64(), v["createdByUser"]["id"].as_u64()), (Some(a.id), Some(a.id)), "{v}");
        assert!(v["designation"].is_object() && v["managingClient"].is_object(), "{v}");
        // The look-ups with no app, no client, or neither.
        let empty = |v: Value| v["emails"].as_array().is_some_and(|e| e.is_empty());
        assert!(empty(s.admin_emails(None, Some("ZZRUL")).await.unwrap()));
        assert!(empty(s.admin_emails(Some("appbuilder"), None).await.unwrap()));
        assert!(empty(s.admin_emails(Some("appbuilder"), Some("NOSUCH")).await.unwrap()));
        assert!(s.admin_emails(Some("appbuilder"), Some("ZZRUL")).await.unwrap()["emails"].is_array());
        assert!(empty(s.owner_emails(None, Some("ZZRUL")).await.unwrap()));
        assert!(empty(s.owner_emails(Some("appbuilder"), None).await.unwrap()));
        s.owner_emails(Some("appbuilder"), Some("ZZRUL")).await.unwrap();
        assert_eq!(s.profile_users(None, &[1]).await.unwrap(), None);
        assert_eq!(s.profile_users(Some("appbuilder"), &[]).await.unwrap(), Some(vec![]));
        fx.finish().await;
    }
}
