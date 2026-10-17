//! `ClientDAO`, `ClientManagerDAO` and `ClientHierarchyDAO` reads.

use std::collections::HashMap;

use sqlx::{MySql, QueryBuilder, Row};

use super::{manage_client_condition, push_in_str, push_in_u64, Db};
use crate::condition::Sql;
use crate::errors::AuthResult;
use crate::model::Client;
use crate::mysql::{client, CLIENT_COLUMNS};
use crate::spring::Pageable;

/// Who the caller may see, as the DAO filters add it to every list query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// A SYSTEM client caller: no restriction and no joins.
    All,
    /// An Owner of a client: the clients that client manages (itself included).
    Owner { client_id: u64 },
    /// Anyone else: the managed clients of the people in the caller's reporting tree.
    Managed { client_id: u64, managed: Vec<u64> },
}

fn qualified_client_columns() -> String {
    CLIENT_COLUMNS.split(", ").map(|c| format!("security_client.{}", c.trim())).collect::<Vec<_>>().join(", ")
}

/// A `Page` query's result: the rows, and the count when one was asked for.
pub struct Rows<T> {
    pub rows: Vec<T>,
    pub total: Option<i64>,
}

impl Db {
    /// `ClientDAO.readAll` / `readPageFilter`: `getSelectJointStep` (a hierarchy join for a
    /// non-SYSTEM caller), the filter, then `ClientDAO.filter`'s scope.
    pub async fn clients_matching(&self, scope: &Scope, cond: Option<Sql>, page: Option<(&Pageable, String)>) -> AuthResult<Rows<Client>> {
        let joined = !matches!(scope, Scope::All);
        let scoped = match scope {
            Scope::All => cond,
            Scope::Owner { client_id } => Sql::and(cond, Some(Sql::text(manage_client_condition(*client_id)))),
            Scope::Managed { managed, .. } if managed.is_empty() => Sql::and(cond, Some(Sql::text("1 = 0"))),
            Scope::Managed { client_id, managed } => {
                let ids: Vec<String> = managed.iter().map(u64::to_string).collect();
                let restriction = format!("({} AND security_client.ID IN ({}))", manage_client_condition(*client_id), ids.join(", "));
                Sql::and(cond, Some(Sql::text(restriction)))
            }
        };
        let from = if joined {
            " FROM security_client LEFT JOIN security_client_hierarchy ON security_client_hierarchy.CLIENT_ID = security_client.ID"
        } else {
            " FROM security_client"
        };
        let build = |select: &str| {
            let mut qb: QueryBuilder<MySql> = QueryBuilder::new(format!("SELECT {select}{from}"));
            if let Some(s) = &scoped {
                qb.push(" WHERE ");
                s.push_to(&mut qb);
            }
            qb
        };
        let mut qb = build(&qualified_client_columns());
        let mut total = None;
        if let Some((p, order)) = &page {
            qb.push(order.as_str());
            qb.push(" LIMIT ").push_bind(p.size).push(" OFFSET ").push_bind(p.offset());
            let mut count = build("COUNT(*)");
            total = Some(count.build().fetch_one(&self.pool).await?.try_get::<i64, _>(0)?);
        }
        let rows = qb.build().fetch_all(&self.pool).await?;
        Ok(Rows { rows: rows.iter().map(client).collect::<AuthResult<_>>()?, total })
    }

    /// `ClientDAO.getActiveClientCodes`.
    pub async fn active_client_codes(&self, codes: &[String]) -> AuthResult<Vec<String>> {
        if codes.is_empty() {
            return Ok(vec![]);
        }
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new(
            "SELECT security_client.CODE FROM security_client LEFT JOIN security_client_hierarchy \
             ON security_client_hierarchy.CLIENT_ID = security_client.ID WHERE ",
        );
        push_in_str(&mut qb, "security_client.CODE", codes);
        qb.push(
            " AND (security_client.STATUS_CODE IS NULL OR security_client.STATUS_CODE = 'ACTIVE') AND NOT EXISTS \
             (SELECT 1 FROM security_client manager WHERE manager.ID IN (security_client_hierarchy.MANAGE_CLIENT_LEVEL_0, \
             security_client_hierarchy.MANAGE_CLIENT_LEVEL_1, security_client_hierarchy.MANAGE_CLIENT_LEVEL_2, \
             security_client_hierarchy.MANAGE_CLIENT_LEVEL_3) AND manager.STATUS_CODE <> 'ACTIVE')",
        );
        let rows = qb.build().fetch_all(&self.pool).await?;
        rows.iter().map(|r| Ok(r.try_get::<String, _>(0)?)).collect()
    }

    /// `ClientManagerDAO.getClientIdsOfManager`.
    pub async fn client_ids_of_manager(&self, manager_id: u64) -> AuthResult<Vec<u64>> {
        let rows = sqlx::query("SELECT CLIENT_ID FROM security_client_manager WHERE MANAGER_ID = ?")
            .bind(manager_id)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(|r| Ok(r.try_get::<u64, _>(0)?)).collect()
    }

    /// `ClientManagerDAO.getClientIdsOfManagers`: distinct.
    pub async fn client_ids_of_managers(&self, manager_ids: &[u64]) -> AuthResult<Vec<u64>> {
        if manager_ids.is_empty() {
            return Ok(vec![]);
        }
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new("SELECT DISTINCT CLIENT_ID FROM security_client_manager WHERE ");
        push_in_u64(&mut qb, "MANAGER_ID", manager_ids);
        let rows = qb.build().fetch_all(&self.pool).await?;
        rows.iter().map(|r| Ok(r.try_get::<u64, _>(0)?)).collect()
    }

    /// `ClientManagerDAO.isManagerForClient`.
    pub async fn is_manager_for_client(&self, manager_id: u64, client_id: u64) -> AuthResult<bool> {
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM security_client_manager WHERE MANAGER_ID = ? AND CLIENT_ID = ?")
            .bind(manager_id)
            .bind(client_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(n > 0)
    }

    /// `ClientManagerDAO.getManagerIds`: (client, manager) rows, as `collectMultimap` sees them.
    pub async fn manager_rows(&self, client_ids: &[u64]) -> AuthResult<Vec<(u64, u64)>> {
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new("SELECT CLIENT_ID, MANAGER_ID FROM security_client_manager WHERE ");
        push_in_u64(&mut qb, "CLIENT_ID", client_ids);
        let rows = qb.build().fetch_all(&self.pool).await?;
        rows.iter().map(|r| Ok((r.try_get::<u64, _>(0)?, r.try_get::<u64, _>(1)?))).collect()
    }

    /// `ClientHierarchyDAO.getManagingClientIds`: the clients this one manages, itself included.
    pub async fn managing_client_ids(&self, client_id: u64) -> AuthResult<Vec<u64>> {
        let sql = format!("SELECT security_client_hierarchy.CLIENT_ID FROM security_client_hierarchy WHERE {}", manage_client_condition(client_id));
        let rows = sqlx::query(&sql).fetch_all(&self.pool).await?;
        rows.iter().map(|r| Ok(r.try_get::<u64, _>(0)?)).collect()
    }

    /// The app condition `fillUserCounts` and `getOwnersPerClient` share: the app code wins over
    /// the app id; a blank one is no condition. A non-numeric app id fails as `ULongUtil` does.
    fn push_app_condition(qb: &mut QueryBuilder<'_, MySql>, app_code: Option<&str>, app_id: Option<&str>) -> AuthResult<()> {
        if let Some(code) = app_code.filter(|c| !c.trim().is_empty()) {
            qb.push(" AND security_app.APP_CODE = ").push_bind(code.to_string());
        } else if let Some(id) = app_id.filter(|c| !c.trim().is_empty()) {
            let id: u64 = id.trim().parse().map_err(|_| crate::errors::AuthError::internal(format!("For input string: \"{id}\"")))?;
            qb.push(" AND security_app.ID = ").push_bind(id);
        }
        Ok(())
    }

    /// `ClientDAO.fillUserCounts`: (client, status, count) for users with a status.
    pub async fn user_counts(&self, client_ids: &[u64], app_code: Option<&str>, app_id: Option<&str>) -> AuthResult<Vec<(u64, String, i64)>> {
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new(
            "SELECT clientId, statusCode, COUNT(*) AS count FROM (SELECT DISTINCT security_user.ID, \
             security_user.CLIENT_ID AS clientId, security_user.STATUS_CODE AS statusCode FROM security_user \
             LEFT JOIN security_profile_user ON security_profile_user.USER_ID = security_user.ID \
             LEFT JOIN security_profile ON security_profile.ID = security_profile_user.PROFILE_ID \
             LEFT JOIN security_app ON security_app.ID = security_profile.APP_ID WHERE 1 = 1",
        );
        Self::push_app_condition(&mut qb, app_code, app_id)?;
        qb.push(" AND ");
        push_in_u64(&mut qb, "security_user.CLIENT_ID", client_ids);
        qb.push(" AND security_user.STATUS_CODE IS NOT NULL) AS counted GROUP BY clientId, statusCode");
        let rows = qb.build().fetch_all(&self.pool).await?;
        rows.iter()
            .map(|r| Ok((r.try_get::<u64, _>(0)?, r.try_get::<Option<String>, _>(1)?.unwrap_or_default(), r.try_get::<i64, _>(2)?)))
            .collect()
    }

    /// `ClientDAO.getOwnersPerClient`: distinct (client, user) rows of users holding an Owner role.
    pub async fn owner_rows(&self, client_ids: &[u64], app_code: Option<&str>, app_id: Option<&str>) -> AuthResult<Vec<(u64, u64)>> {
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new(
            "SELECT DISTINCT security_user.CLIENT_ID, security_user.ID FROM security_user \
             LEFT JOIN security_profile_user ON security_profile_user.USER_ID = security_user.ID \
             LEFT JOIN security_profile ON security_profile.ID = security_profile_user.PROFILE_ID \
             LEFT JOIN security_profile_role ON security_profile_role.PROFILE_ID = security_profile_user.PROFILE_ID \
             LEFT JOIN security_v2_role ON security_v2_role.ID = security_profile_role.ROLE_ID \
             LEFT JOIN security_app ON security_app.ID = security_profile.APP_ID \
             WHERE security_v2_role.NAME = 'Owner'",
        );
        Self::push_app_condition(&mut qb, app_code, app_id)?;
        qb.push(" AND ");
        push_in_u64(&mut qb, "security_user.CLIENT_ID", client_ids);
        let rows = qb.build().fetch_all(&self.pool).await?;
        rows.iter().map(|r| Ok((r.try_get::<u64, _>(0)?, r.try_get::<u64, _>(1)?))).collect()
    }

    /// `ClientDAO.fetchClientNames`: (id, name, status).
    pub async fn client_names(&self, client_ids: &[u64]) -> AuthResult<Vec<(u64, Option<String>, Option<String>)>> {
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new("SELECT ID, NAME, STATUS_CODE FROM security_client WHERE ");
        push_in_u64(&mut qb, "ID", client_ids);
        let rows = qb.build().fetch_all(&self.pool).await?;
        rows.iter().map(|r| Ok((r.try_get(0)?, r.try_get(1)?, r.try_get(2)?))).collect()
    }

    /// `ClientDAO.fetchUserAggregations`' rows: (client, status, first, last, phone).
    #[allow(clippy::type_complexity)]
    pub async fn user_denorm_rows(
        &self,
        client_ids: &[u64],
    ) -> AuthResult<Vec<(u64, Option<String>, Option<String>, Option<String>, Option<String>)>> {
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new(
            "SELECT CLIENT_ID, STATUS_CODE, FIRST_NAME, LAST_NAME, PHONE_NUMBER FROM security_user WHERE ",
        );
        push_in_u64(&mut qb, "CLIENT_ID", client_ids);
        qb.push(" AND STATUS_CODE IS NOT NULL");
        let rows = qb.build().fetch_all(&self.pool).await?;
        rows.iter().map(|r| Ok((r.try_get(0)?, r.try_get(1)?, r.try_get(2)?, r.try_get(3)?, r.try_get(4)?))).collect()
    }

    /// `ClientDAO/UserDAO.getSubOrgUserIds`: the user and everyone reporting to them, directly or
    /// not, within the client (`expandDeep` with a visited set).
    pub async fn sub_org_user_ids(&self, client_id: u64, user_id: u64) -> AuthResult<Vec<u64>> {
        let mut found = vec![user_id];
        let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::new();
        let mut i = 0;
        while i < found.len() {
            let id = found[i];
            i += 1;
            if !seen.insert(id) {
                continue;
            }
            let rows = sqlx::query("SELECT ID FROM security_user WHERE REPORTING_TO = ? AND CLIENT_ID = ?")
                .bind(id)
                .bind(client_id)
                .fetch_all(&self.pool)
                .await?;
            for r in rows {
                found.push(r.try_get::<u64, _>(0)?);
            }
        }
        Ok(found)
    }

    /// `AppDAO.getAppsIDsPerClient`: (client, app) rows of owned and accessible apps.
    pub async fn app_rows_per_client(&self, client_ids: &[u64]) -> AuthResult<Vec<(u64, u64)>> {
        if client_ids.is_empty() {
            return Ok(vec![]);
        }
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new("SELECT CLIENT_ID, ID FROM security_app WHERE ");
        push_in_u64(&mut qb, "CLIENT_ID", client_ids);
        qb.push(" UNION SELECT CLIENT_ID, APP_ID FROM security_app_access WHERE ");
        push_in_u64(&mut qb, "CLIENT_ID", client_ids);
        let rows = qb.build().fetch_all(&self.pool).await?;
        rows.iter().map(|r| Ok((r.try_get::<u64, _>(0)?, r.try_get::<u64, _>(1)?))).collect()
    }
}

/// `collectMultimap(key, value)`: values per key in row order.
pub fn multimap(rows: &[(u64, u64)]) -> HashMap<u64, Vec<u64>> {
    let mut m: HashMap<u64, Vec<u64>> = HashMap::new();
    for (k, v) in rows {
        m.entry(*k).or_default().push(*v);
    }
    m
}
