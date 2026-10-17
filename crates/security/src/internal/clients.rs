//! `ClientService`, `ClientHierarchyService` and `ClientManagerService`, as the internal client
//! routes use them.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use serde_json::Value;

use super::Internal;
use crate::caches;
use crate::condition::{Cond, Filter, Op};
use crate::data::clients::{multimap, Rows};
use crate::data::{distinct, filters};
use crate::dto::{client_json, ClientExtras, UserCounts};
use crate::errors::{AuthError, AuthResult};
use crate::expr::has_authority;
use crate::javamap::{iteration_order, long_hash};
use crate::jackson::Obj;
use crate::model::{Client, ContextAuth, User};
use crate::spring::{safe_bool, Pageable, Params};

use super::scope::CLIENT_MANAGER_ROLES;

const NO_CLIENT_HIERARCHY_MESSAGE: &str = "No client hierarchy found";

/// `ClientDenormData`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Denorm {
    pub client_name: Option<String>,
    pub status_code: Option<String>,
    pub active_users: i64,
    pub user_names: Option<String>,
    pub user_phones: Option<String>,
    pub client_manager_ids: Option<String>,
}

impl Denorm {
    pub fn to_json(&self) -> Value {
        Obj::new()
            .put("clientName", crate::jackson::opt(self.client_name.clone()))
            .put("statusCode", crate::jackson::opt(self.status_code.clone()))
            .put("activeUsers", self.active_users)
            .put("userNames", crate::jackson::opt(self.user_names.clone()))
            .put("userPhones", crate::jackson::opt(self.user_phones.clone()))
            .put("clientManagerIds", crate::jackson::opt(self.client_manager_ids.clone()))
            .build()
    }
}

/// `ClientDAO.UserAggregation`: ACTIVE users counted, names and phones listed in row order.
pub fn aggregate_users(rows: &[(u64, Option<String>, Option<String>, Option<String>, Option<String>)]) -> HashMap<u64, (i64, Vec<String>, Vec<String>)> {
    let mut agg: HashMap<u64, (i64, Vec<String>, Vec<String>)> = HashMap::new();
    for (client, status, first, last, phone) in rows {
        let a = agg.entry(*client).or_default();
        if status.as_deref() == Some("ACTIVE") {
            a.0 += 1;
        }
        let mut name = String::new();
        if let Some(f) = first.as_deref().filter(|f| !f.trim().is_empty()) {
            name.push_str(f.trim());
        }
        if let Some(l) = last.as_deref().filter(|l| !l.trim().is_empty()) {
            if !name.is_empty() {
                name.push(' ');
            }
            name.push_str(l.trim());
        }
        if !name.is_empty() {
            a.1.push(name);
        }
        if let Some(p) = phone.as_deref().filter(|p| !p.trim().is_empty() && *p != "PLACEHOLDER") {
            a.2.push(p.to_string());
        }
    }
    agg
}

/// The fill options `ClientService.fillDetails` reads off the query parameters.
#[derive(Debug, Clone, Default)]
pub struct ClientFill {
    pub app_code: Option<String>,
    pub app_id: Option<String>,
    pub user_counts: bool,
    pub owners: bool,
    pub managing_client: bool,
    pub apps: bool,
    pub created_by_user: bool,
    pub client_managers: bool,
}

impl ClientFill {
    pub fn from_params(p: &Params) -> Self {
        Self {
            app_code: p.get("appCode").map(str::to_string),
            app_id: p.get("appId").map(str::to_string),
            user_counts: safe_bool(p.get("fetchUserCounts")),
            owners: safe_bool(p.get("fetchOwners")),
            managing_client: safe_bool(p.get("fetchManagingClient")),
            apps: safe_bool(p.get("fetchApps")),
            created_by_user: safe_bool(p.get("fetchCreatedByUser")),
            client_managers: safe_bool(p.get("fetchClientManagers")),
        }
    }
}

/// `id IN (...)` as `readByIds` builds it.
pub fn ids_in(field: &str, ids: &[u64]) -> Cond {
    Cond::Filter(Filter {
        field: Some(field.to_string()),
        field_expr: None,
        op: Op::In,
        value: None,
        to_value: None,
        multi_value: Some(ids.iter().map(|i| Value::from(*i)).collect()),
        value_field: false,
        to_value_field: false,
        negate: false,
    })
}

impl Internal {
    /// `ClientService.getClientBy(clientCode)`.
    pub async fn client_by_code(&self, code: &str) -> AuthResult<Option<Arc<Client>>> {
        self.dir().client_by_code(code).await
    }

    /// `ClientHierarchyService.isClientBeingManagedBy`.
    pub async fn is_client_being_managed_by(&self, managing: u64, client: u64) -> AuthResult<bool> {
        if managing == client {
            return Ok(true);
        }
        Ok(self.dir().hierarchy(client).await?.is_managed_by(managing))
    }

    /// `ClientManagerService.isUserClientManager(appCode, userId, userClientId, targetClientId)`.
    pub async fn is_user_client_manager(&self, app_code: Option<&str>, user_id: u64, user_client_id: u64, target: u64) -> AuthResult<bool> {
        let authorities = self.dir().user_authorities(app_code, user_client_id, user_id).await?;
        if has_authority(Some(CLIENT_MANAGER_ROLES), &authorities) {
            return Ok(true);
        }
        self.client_manager_check(user_id, user_client_id, target).await
    }

    /// `ClientManagerService.isUserClientManager(ca, targetClientId)`.
    pub async fn is_caller_client_manager(&self, ca: &ContextAuth, target: u64) -> AuthResult<bool> {
        if has_authority(Some(CLIENT_MANAGER_ROLES), &super::scope::authorities(ca)) {
            return Ok(true);
        }
        self.client_manager_check(ca.user.id(), ca.user.client_id(), target).await
    }

    async fn client_manager_check(&self, user_id: u64, user_client_id: u64, target: u64) -> AuthResult<bool> {
        if user_client_id == target {
            return Ok(false);
        }
        let db = self.db.clone();
        let v = self
            .caches()
            .flags
            .get_or_load(caches::CLIENT_MANAGER, format!("{user_id}{target}"), || async move {
                Ok::<_, AuthError>(Some(db.is_manager_for_client(user_id, target).await?))
            })
            .await?;
        Ok(v.unwrap_or(false))
    }

    /// `ClientService.isUserClientManageClient(appCode, userId, userClientId, targetClientId)`.
    pub async fn is_user_client_manage_client(&self, app_code: Option<&str>, user_id: u64, user_client_id: u64, target: u64) -> AuthResult<bool> {
        if user_client_id == target {
            return Ok(true);
        }
        if !self.is_client_being_managed_by(user_client_id, target).await? {
            return Ok(false);
        }
        self.is_user_client_manager(app_code, user_id, user_client_id, target).await
    }

    /// `ClientService.isUserClientManageClient(ca, targetClientId)`.
    pub async fn caller_manages_client(&self, ca: &ContextAuth, target: u64) -> AuthResult<bool> {
        let own = ca.user.client_id();
        if own == target {
            return Ok(true);
        }
        if !self.is_client_being_managed_by(own, target).await? {
            return Ok(false);
        }
        self.is_caller_client_manager(ca, target).await
    }

    /// `ClientService.filterManagedClientCodes`: the listed codes the managing client manages,
    /// duplicates and unknown codes left out.
    pub async fn filter_managed_client_codes(&self, managing_code: &str, codes: &[String]) -> AuthResult<Vec<String>> {
        if codes.is_empty() {
            return Ok(vec![]);
        }
        let Some(managing) = self.client_by_code(managing_code).await? else { return Ok(vec![]) };
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for code in codes {
            if !seen.insert(code.as_str()) {
                continue;
            }
            let Some(c) = self.client_by_code(code).await? else { continue };
            if self.is_client_being_managed_by(managing.id(), c.id()).await? {
                out.push(c.code().to_string());
            }
        }
        Ok(out)
    }

    /// `ClientService.isUserPartOfHierarchy`.
    pub async fn is_user_part_of_hierarchy(&self, client_code: &str, user_id: u64) -> AuthResult<bool> {
        let Some(user) = self.dir().user(user_id).await? else { return Ok(false) };
        let Some(client) = self.client_by_code(client_code).await? else { return Ok(false) };
        let down = self.is_client_being_managed_by(user.client_id, client.id()).await?;
        let up = self.is_client_being_managed_by(client.id(), user.client_id).await?;
        Ok(down || up)
    }

    /// `ClientHierarchyService.getClientHierarchyIdInOrder`.
    pub async fn client_hierarchy_ids(&self, client_id: u64) -> AuthResult<Vec<u64>> {
        Ok(self.dir().hierarchy(client_id).await?.client_ids_in_order())
    }

    /// `ClientService.getClientHierarchyCodes`.
    pub async fn client_hierarchy_codes(&self, client_code: &str) -> AuthResult<Vec<String>> {
        if client_code.trim().is_empty() {
            return Ok(vec![]);
        }
        let Some(client) = self.client_by_code(client_code).await? else { return Ok(vec![]) };
        let ids = match self.client_hierarchy_ids(client.id()).await {
            Ok(ids) => ids,
            Err(AuthError::Generic { message, .. }) if message.starts_with(NO_CLIENT_HIERARCHY_MESSAGE) => vec![client.id()],
            Err(e) => return Err(e),
        };
        let mut out = Vec::new();
        for id in ids {
            if id == client.id() {
                out.push(client.code().to_string());
            } else if let Some(c) = self.dir().client(id).await? {
                out.push(c.code().to_string());
            }
        }
        Ok(out)
    }

    /// `ClientService.getClientsDenormData`: per existing client, keyed as Java's `HashMap`
    /// iterates them.
    pub async fn clients_denorm(&self, ids: &[u64]) -> AuthResult<Vec<(u64, Denorm)>> {
        if ids.is_empty() {
            return Ok(vec![]);
        }
        let names = self.db.client_names(ids).await?;
        let users = aggregate_users(&self.db.user_denorm_rows(ids).await?);
        let managers = multimap(&self.db.manager_rows(ids).await?);
        let mut out = Vec::new();
        for (id, name, status) in names.iter().cloned() {
            let mut d = Denorm { client_name: name, status_code: status, ..Default::default() };
            if let Some((active, n, p)) = users.get(&id) {
                d.active_users = *active;
                d.user_names = Some(n.join(", "));
                d.user_phones = Some(p.join(", "));
            }
            if let Some(m) = managers.get(&id).filter(|m| !m.is_empty()) {
                d.client_manager_ids = Some(format!(",{},", m.iter().map(u64::to_string).collect::<Vec<_>>().join(",")));
            }
            out.push((id, d));
        }
        let keys: Vec<(i32, (u64, Denorm))> = out.into_iter().map(|(id, d)| (long_hash(id), (id, d))).collect();
        Ok(iteration_order(keys))
    }

    /// `ClientService.readByIds`: `readAllFilter(id IN ids)` then `fillDetails`.
    pub async fn clients_by_ids(&self, ca: &ContextAuth, ids: &[u64], fill: &ClientFill) -> AuthResult<Vec<Value>> {
        let scope = self.client_scope(ca).await?;
        let cond = crate::condition::to_sql_with(&ids_in("id", ids), &filters::CLIENT, &filters::client_hook)?;
        let Rows { rows, .. } = self.db.clients_matching(&scope, cond, None).await?;
        let filled = self.fill_clients(rows.into_iter().map(Arc::new).collect(), fill).await?;
        Ok(filled.iter().map(|(c, x)| client_json(c, x)).collect())
    }

    /// `ClientService.readById`: the cached client, filled.
    pub async fn client_by_id_filled(&self, id: u64, fill: &ClientFill) -> AuthResult<Option<Value>> {
        let Some(c) = self.dir().client(id).await? else { return Ok(None) };
        let filled = self.fill_clients(vec![c], fill).await?;
        Ok(filled.first().map(|(c, x)| client_json(c, x)))
    }

    /// `ClientService.readPageFilterInternal` + `fillDetails`: a page of clients as JSON.
    pub async fn clients_page(&self, ca: &ContextAuth, page: &Pageable, cond: Option<&Cond>, fill: &ClientFill) -> AuthResult<Value> {
        let scope = self.client_scope(ca).await?;
        let sql = match cond {
            Some(c) => crate::condition::to_sql_with(c, &filters::CLIENT, &filters::client_hook)?,
            None => None,
        };
        let order = crate::condition::order_by(&page.sort, &filters::CLIENT);
        let Rows { rows, total } = self.db.clients_matching(&scope, sql, Some((page, order))).await?;
        let content_len = rows.len();
        // The page keeps its own order; fillDetails only adds to the clients in it.
        let filled = self.fill_clients(rows.iter().cloned().map(Arc::new).collect(), fill).await?;
        let by_id: HashMap<u64, &(Arc<Client>, ClientExtras)> = filled.iter().map(|f| (f.0.id(), f)).collect();
        let content: Vec<Value> = rows.iter().map(|c| by_id.get(&c.id()).map(|(c, x)| client_json(c, x)).unwrap_or(Value::Null)).collect();
        let total = crate::spring::known_total(content_len, page).unwrap_or(total.unwrap_or(0));
        Ok(crate::web::page_json(content, page, total))
    }

    /// `ClientService.fillDetails`. A list that went through the apps, counts or owners fill
    /// comes back in the order of Java's `HashMap` of the clients by id.
    pub async fn fill_clients(&self, clients: Vec<Arc<Client>>, fill: &ClientFill) -> AuthResult<Vec<(Arc<Client>, ClientExtras)>> {
        let mut list: Vec<(Arc<Client>, ClientExtras)> = clients.into_iter().map(|c| (c, ClientExtras::default())).collect();
        let ids: Vec<u64> = list.iter().map(|(c, _)| c.id()).collect();
        let map_order = |list: Vec<(Arc<Client>, ClientExtras)>| {
            iteration_order(list.into_iter().map(|e| (long_hash(e.0.id()), e)).collect())
        };
        let users = |ids: Vec<u64>| async move {
            let mut m: HashMap<u64, Arc<User>> = HashMap::new();
            for id in distinct(ids) {
                if let Some(u) = self.dir().user(id).await? {
                    m.insert(id, u);
                }
            }
            Ok::<_, AuthError>(m)
        };

        if fill.created_by_user {
            for (c, x) in list.iter_mut() {
                if let Some(id) = c.created_by {
                    x.created_by_user = self.dir().user(id).await?;
                }
            }
        }
        if fill.apps {
            let rows = self.db.app_rows_per_client(&ids).await?;
            let per_client = grouped(&rows);
            let mut apps = HashMap::new();
            for id in distinct(rows.iter().map(|r| r.1)) {
                apps.insert(id, self.dir().app_by_id(id).await?);
            }
            list = map_order(list);
            for (c, x) in list.iter_mut() {
                if let Some(app_ids) = per_client.get(&c.id()) {
                    x.apps = Some(app_ids.iter().filter_map(|a| apps.get(a).cloned()).collect());
                }
            }
        }
        if fill.managing_client {
            for (c, x) in list.iter_mut() {
                if let Ok(h) = self.dir().hierarchy(c.id()).await {
                    if let Some(m) = h.level0 {
                        x.managing_client = self.dir().client(m).await.unwrap_or(None);
                    }
                }
            }
        }
        if fill.user_counts {
            let counts = self.db.user_counts(&ids, fill.app_code.as_deref(), fill.app_id.as_deref()).await?;
            list = map_order(list);
            for (c, x) in list.iter_mut() {
                for (_, status, n) in counts.iter().filter(|r| r.0 == c.id()) {
                    set_count(&mut x.counts, status, *n);
                }
            }
        }
        if fill.owners {
            let rows = self.db.owner_rows(&ids, fill.app_code.as_deref(), fill.app_id.as_deref()).await?;
            let per_client = multimap(&rows);
            let user_map = users(rows.iter().map(|r| r.1).collect()).await?;
            list = map_order(list);
            for (c, x) in list.iter_mut() {
                if let Some(owner_ids) = per_client.get(&c.id()) {
                    x.owners = Some(owner_ids.iter().filter_map(|u| user_map.get(u).cloned()).collect());
                }
            }
        }
        if fill.client_managers {
            let current: Vec<u64> = list.iter().map(|(c, _)| c.id()).collect();
            let rows = self.db.manager_rows(&current).await?;
            let per_client = multimap(&rows);
            let user_map = users(rows.iter().map(|r| r.1).collect()).await?;
            for (c, x) in list.iter_mut() {
                if let Some(manager_ids) = per_client.get(&c.id()) {
                    x.client_managers = Some(manager_ids.iter().filter_map(|u| user_map.get(u).cloned()).collect());
                }
            }
        }
        Ok(list)
    }

    /// `ClientService.getOwnersEmails`.
    pub async fn owners_emails(&self, client_id: u64, app_code: Option<&str>, app_id: Option<u64>) -> AuthResult<Option<Vec<String>>> {
        if self.dir().client(client_id).await?.is_none() {
            return Ok(None);
        }
        let app_id = app_id.map(|a| a.to_string());
        let rows = self.db.owner_rows(&[client_id], app_code, app_id.as_deref()).await?;
        let ids: Vec<u64> = rows.iter().map(|r| r.1).collect();
        Ok(Some(self.db.emails_of_users(&ids).await?))
    }
}

/// `Collectors.groupingBy(value1, mapping(value2, toList()))`: per key, values in row order
/// (only the lookups matter, so the map's own order does not).
fn grouped(rows: &[(u64, u64)]) -> HashMap<u64, Vec<u64>> {
    multimap(rows)
}

fn set_count(c: &mut UserCounts, status: &str, n: i64) {
    match status {
        "ACTIVE" => c.active = n,
        "INACTIVE" => c.inactive = n,
        "DELETED" => c.deleted = n,
        "LOCKED" => c.locked = n,
        "PASSWORD_EXPIRED" => c.password_expired = n,
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> Option<String> {
        Some(v.to_string())
    }

    #[test]
    fn user_aggregation_like_java() {
        let rows = vec![
            (1, s("ACTIVE"), s(" Ann "), s("Lee"), s("+91 1")),
            (1, s("INACTIVE"), None, s("Solo"), s("PLACEHOLDER")),
            (1, s("ACTIVE"), s(""), None, Some(" ".into())),
            (2, s("DELETED"), s("Bo"), None, None),
        ];
        let a = aggregate_users(&rows);
        assert_eq!(a[&1], (2, vec!["Ann Lee".to_string(), "Solo".to_string()], vec!["+91 1".to_string()]));
        assert_eq!(a[&2], (0, vec!["Bo".to_string()], vec![]));
        let d = Denorm { client_name: s("C"), active_users: 0, user_names: Some(String::new()), ..Default::default() };
        assert_eq!(d.to_json(), serde_json::json!({"clientName": "C", "activeUsers": 0}));
    }

    #[test]
    fn counts_and_fill_flags() {
        let mut c = UserCounts::default();
        for (st, n) in [("ACTIVE", 1), ("INACTIVE", 2), ("DELETED", 3), ("LOCKED", 4), ("PASSWORD_EXPIRED", 5), ("X", 6)] {
            set_count(&mut c, st, n);
        }
        assert_eq!(c, UserCounts { active: 1, inactive: 2, deleted: 3, locked: 4, password_expired: 5 });
        let f = ClientFill::from_params(&Params::from_query(Some("fetchOwners=true&fetchApps=yes&appCode=a&fetchUserCounts=0")));
        assert!(f.owners && f.apps && !f.user_counts && !f.managing_client);
        assert_eq!(f.app_code.as_deref(), Some("a"));
        assert!(matches!(ids_in("id", &[1, 2]), Cond::Filter(Filter { op: Op::In, .. })));
        assert_eq!(grouped(&[(1, 5), (1, 6), (2, 7)])[&1], vec![5, 6]);
    }
}
