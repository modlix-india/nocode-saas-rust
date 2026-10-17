//! `UserDAO` reads (and the `ProfileDAO` / `DesignationDAO` ones the user routes need).

use sqlx::{MySql, QueryBuilder, Row};

use super::clients::Rows;
use super::{manage_client_condition, push_in_u64, Db};
use crate::condition::Sql;
use crate::dto::Designation;
use crate::errors::AuthResult;
use crate::model::User;
use crate::mysql::{ts, user, USER_COLUMNS};
use crate::spring::Pageable;

/// Who the caller may see among users (`UserDAO.filter`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserScope {
    /// A SYSTEM client caller: no restriction and no joins.
    All,
    /// An Owner: users of the clients their client manages.
    Owner { client_id: u64 },
    /// Anyone else: users of their own client, plus those of other clients the people in their
    /// reporting tree manage.
    Managed { client_id: u64, external: Vec<u64> },
}

fn qualified_user_columns() -> String {
    USER_COLUMNS.replace("u.", "security_user.")
}

/// `UserService.getUsersForNotification`'s request (`UsersListRequest`).
#[derive(Debug, Clone, Default)]
pub struct UsersListRequest {
    pub user_ids: Option<Vec<i64>>,
    pub client_code: Option<String>,
    pub client_id: Option<i64>,
    pub app_code: Option<String>,
}

impl Db {
    /// `UserDAO.readAll` / `readPageFilter`: `ClientCheckDAOHelper.getSelectJointStep` (DISTINCT
    /// with the client, hierarchy and manager joins for a non-SYSTEM caller), the filter, then
    /// `UserDAO.filter`'s scope.
    pub async fn users_matching(&self, scope: &UserScope, cond: Option<Sql>, page: Option<(&Pageable, String)>) -> AuthResult<Rows<User>> {
        let joined = !matches!(scope, UserScope::All);
        let scoped = match scope {
            UserScope::All => cond,
            UserScope::Owner { client_id } => Sql::and(cond, Some(Sql::text(manage_client_condition(*client_id)))),
            UserScope::Managed { client_id, external } if external.is_empty() => {
                Sql::and(cond, Some(Sql::text(format!("security_user.CLIENT_ID = {client_id}"))))
            }
            UserScope::Managed { client_id, external } => {
                let ids: Vec<String> = external.iter().map(u64::to_string).collect();
                Sql::and(
                    cond,
                    Some(Sql::text(format!(
                        "({} AND (security_user.CLIENT_ID = {client_id} OR security_user.CLIENT_ID IN ({})))",
                        manage_client_condition(*client_id),
                        ids.join(", ")
                    ))),
                )
            }
        };
        let from = if joined {
            " FROM security_user LEFT JOIN security_client ON security_client.ID = security_user.CLIENT_ID \
             LEFT JOIN security_client_hierarchy ON security_client_hierarchy.CLIENT_ID = security_client.ID \
             LEFT JOIN security_client_manager ON security_client_manager.CLIENT_ID = security_user.CLIENT_ID"
        } else {
            " FROM security_user"
        };
        let build = |select: &str| {
            let mut qb: QueryBuilder<MySql> = QueryBuilder::new(format!("SELECT {select}{from}"));
            if let Some(s) = &scoped {
                qb.push(" WHERE ");
                s.push_to(&mut qb);
            }
            qb
        };
        let select = if joined { format!("DISTINCT {}", qualified_user_columns()) } else { qualified_user_columns() };
        let mut qb = build(&select);
        let mut total = None;
        if let Some((p, order)) = &page {
            qb.push(order.as_str());
            qb.push(" LIMIT ").push_bind(p.size).push(" OFFSET ").push_bind(p.offset());
            let mut count = build(if joined { "COUNT(DISTINCT security_user.ID)" } else { "COUNT(*)" });
            total = Some(count.build().fetch_one(&self.pool).await?.try_get::<i64, _>(0)?);
        }
        let rows = qb.build().fetch_all(&self.pool).await?;
        Ok(Rows { rows: rows.iter().map(user).collect::<AuthResult<_>>()?, total })
    }

    /// `UserDAO.getUsersForProfiles`: users of the client holding any of the profiles,
    /// duplicates dropped (`Flux.distinct()` on whole rows).
    pub async fn users_for_profiles(&self, profile_ids: &[u64], client_id: u64) -> AuthResult<Vec<User>> {
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new(format!(
            "SELECT {} FROM security_profile_user LEFT JOIN security_profile ON security_profile.ID = security_profile_user.PROFILE_ID \
             LEFT JOIN security_user ON security_user.ID = security_profile_user.USER_ID WHERE ",
            qualified_user_columns()
        ));
        push_in_u64(&mut qb, "security_profile_user.PROFILE_ID", profile_ids);
        qb.push(" AND security_user.CLIENT_ID = ").push_bind(client_id);
        let rows = qb.build().fetch_all(&self.pool).await?;
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for r in &rows {
            if seen.insert(r.try_get::<u64, _>("ID")?) {
                out.push(user(r)?);
            }
        }
        Ok(out)
    }

    /// `UserDAO.getOwners`: the client's ACTIVE users with an Owner role, distinct.
    pub async fn owners_of(&self, client_id: u64) -> AuthResult<Vec<User>> {
        let sql = format!(
            "SELECT {} FROM security_user JOIN security_profile_user ON security_profile_user.USER_ID = security_user.ID \
             JOIN security_profile ON security_profile.ID = security_profile_user.PROFILE_ID \
             JOIN security_profile_role ON security_profile_role.PROFILE_ID = security_profile.ID \
             JOIN security_v2_role ON security_v2_role.ID = security_profile_role.ROLE_ID \
             WHERE security_v2_role.NAME = 'Owner' AND security_user.CLIENT_ID = ? AND security_user.STATUS_CODE = 'ACTIVE'",
            qualified_user_columns()
        );
        let rows = sqlx::query(&sql).bind(client_id).fetch_all(&self.pool).await?;
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for r in &rows {
            if seen.insert(r.try_get::<u64, _>("ID")?) {
                out.push(user(r)?);
            }
        }
        Ok(out)
    }

    /// `UserDAO.getEmailsOfUsers`.
    pub async fn emails_of_users(&self, user_ids: &[u64]) -> AuthResult<Vec<String>> {
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new("SELECT EMAIL_ID FROM security_user WHERE ");
        push_in_u64(&mut qb, "ID", user_ids);
        qb.push(" AND EMAIL_ID IS NOT NULL AND EMAIL_ID <> 'NONE' AND STATUS_CODE <> 'DELETED'");
        let rows = qb.build().fetch_all(&self.pool).await?;
        rows.iter().map(|r| Ok(r.try_get::<String, _>(0)?)).collect()
    }

    /// `UserDAO.buildUserFilterServerCondition`.
    fn push_server_condition(qb: &mut QueryBuilder<'_, MySql>, r: &UsersListRequest) {
        qb.push(" WHERE 1 = 1");
        if let Some(code) = &r.client_code {
            qb.push(" AND security_client.CODE = ").push_bind(code.clone());
        } else if let Some(id) = r.client_id {
            qb.push(" AND security_user.CLIENT_ID = ").push_bind(id);
        }
        if let Some(ids) = r.user_ids.as_ref().filter(|i| !i.is_empty()) {
            qb.push(" AND security_user.ID IN (");
            let mut sep = qb.separated(", ");
            for id in ids {
                sep.push_bind(*id);
            }
            qb.push(")");
        }
        qb.push(" AND security_app.APP_CODE = ").push_bind(r.app_code.clone());
    }

    /// `UserDAO.getUsersForNotification`: distinct (id, client, email) of users with a profile in
    /// the app.
    pub async fn users_for_notification(&self, r: &UsersListRequest) -> AuthResult<Vec<(u64, u64, Option<String>)>> {
        if r.app_code.is_none() {
            return Ok(vec![]);
        }
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new(
            "SELECT DISTINCT security_user.ID, security_user.CLIENT_ID, security_user.EMAIL_ID FROM security_user \
             LEFT JOIN security_profile_user ON security_profile_user.USER_ID = security_user.ID \
             LEFT JOIN security_profile ON security_profile.ID = security_profile_user.PROFILE_ID \
             LEFT JOIN security_app ON security_app.ID = security_profile.APP_ID",
        );
        if r.client_code.is_some() {
            qb.push(" LEFT JOIN security_client ON security_client.ID = security_user.CLIENT_ID");
        }
        Self::push_server_condition(&mut qb, r);
        let rows = qb.build().fetch_all(&self.pool).await?;
        rows.iter().map(|row| Ok((row.try_get(0)?, row.try_get(1)?, row.try_get(2)?))).collect()
    }

    /// `UserDAO.getUsersForEntityProcessor`'s rows: (user, designation, department, role,
    /// profile) of ACTIVE users with a profile in the app.
    #[allow(clippy::type_complexity)]
    pub async fn processor_rows(&self, r: &UsersListRequest) -> AuthResult<Vec<(u64, Option<u64>, Option<u64>, Option<u64>, Option<u64>)>> {
        if r.app_code.is_none() {
            return Ok(vec![]);
        }
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new(
            "SELECT security_user.ID, security_user.DESIGNATION_ID, security_designation.DEPARTMENT_ID, \
             security_v2_user_role.ROLE_ID, security_profile_user.PROFILE_ID FROM security_user \
             LEFT JOIN security_designation ON security_designation.ID = security_user.DESIGNATION_ID \
             LEFT JOIN security_v2_user_role ON security_v2_user_role.USER_ID = security_user.ID \
             LEFT JOIN security_profile_user ON security_profile_user.USER_ID = security_user.ID \
             LEFT JOIN security_profile ON security_profile.ID = security_profile_user.PROFILE_ID \
             LEFT JOIN security_app ON security_app.ID = security_profile.APP_ID",
        );
        if r.client_code.is_some() {
            qb.push(" LEFT JOIN security_client ON security_client.ID = security_user.CLIENT_ID");
        }
        Self::push_server_condition(&mut qb, r);
        qb.push(" AND security_user.STATUS_CODE = 'ACTIVE'");
        let rows = qb.build().fetch_all(&self.pool).await?;
        rows.iter().map(|row| Ok((row.try_get(0)?, row.try_get(1)?, row.try_get(2)?, row.try_get(3)?, row.try_get(4)?))).collect()
    }

    /// `UserDAO.getOrgEdges`: (user, reports to, status) of every user of the client.
    pub async fn org_edges(&self, client_id: u64) -> AuthResult<Vec<(u64, Option<u64>, Option<String>)>> {
        let rows = sqlx::query("SELECT ID, REPORTING_TO, STATUS_CODE FROM security_user WHERE CLIENT_ID = ?")
            .bind(client_id)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(|r| Ok((r.try_get(0)?, r.try_get(1)?, r.try_get(2)?))).collect()
    }

    /// `UserDAO.getUserIdsByClientId(clientId, null, false)`: every user of the client, deleted
    /// ones included. A non-SYSTEM client is also joined to its hierarchy row, so a client
    /// without one has none.
    pub async fn user_ids_of_client(&self, client_id: u64, system: bool) -> AuthResult<Vec<u64>> {
        let sql = if system {
            "SELECT security_user.ID FROM security_user WHERE security_user.CLIENT_ID = ?".to_string()
        } else {
            format!(
                "SELECT security_user.ID FROM security_user LEFT JOIN security_client_hierarchy \
                 ON security_client_hierarchy.CLIENT_ID = security_user.CLIENT_ID \
                 WHERE (security_user.CLIENT_ID = ? AND {})",
                manage_client_condition(client_id)
            )
        };
        let rows = sqlx::query(&sql).bind(client_id).fetch_all(&self.pool).await?;
        rows.iter().map(|r| Ok(r.try_get::<u64, _>(0)?)).collect()
    }

    /// `ProfileDAO.getUsersForProfiles(appId, profileIds)`: distinct user ids.
    pub async fn profile_user_ids(&self, app_id: u64, profile_ids: &[u64]) -> AuthResult<Vec<u64>> {
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new(
            "SELECT security_profile_user.USER_ID FROM security_profile_user LEFT JOIN security_profile \
             ON security_profile.ID = security_profile_user.PROFILE_ID WHERE ",
        );
        push_in_u64(&mut qb, "security_profile_user.PROFILE_ID", profile_ids);
        qb.push(" AND security_profile.APP_ID = ").push_bind(app_id);
        let rows = qb.build().fetch_all(&self.pool).await?;
        Ok(super::distinct(rows.iter().map(|r| r.try_get::<u64, _>(0)).collect::<Result<Vec<_>, _>>()?))
    }

    /// `ProfileDAO.getRestrictedProfiles`.
    pub async fn restricted_profiles(&self, client_id: u64, app_id: u64) -> AuthResult<Vec<u64>> {
        let rows = sqlx::query(
            "SELECT security_profile_client_restriction.PROFILE_ID FROM security_profile_client_restriction \
             LEFT JOIN security_profile ON security_profile.ID = security_profile_client_restriction.PROFILE_ID \
             WHERE security_profile.APP_ID = ? AND security_profile_client_restriction.CLIENT_ID = ?",
        )
        .bind(app_id)
        .bind(client_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(|r| Ok(r.try_get::<u64, _>(0)?)).collect()
    }

    /// `ProfileDAO.getAppProfiles`: the root ids of the app's profiles the hierarchy can see.
    pub async fn app_profiles(&self, app_id: u64, hierarchy_ids: &[u64]) -> AuthResult<Vec<u64>> {
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new(
            "SELECT security_profile.ID, security_profile.ROOT_PROFILE_ID FROM security_profile \
             LEFT JOIN security_app ON security_app.ID = security_profile.APP_ID WHERE security_profile.APP_ID = ",
        );
        qb.push_bind(app_id).push(" AND (");
        push_in_u64(&mut qb, "security_profile.CLIENT_ID", hierarchy_ids);
        qb.push(" OR security_profile.CLIENT_ID = security_app.CLIENT_ID)");
        let rows = qb.build().fetch_all(&self.pool).await?;
        let ids = rows
            .iter()
            .map(|r| Ok(r.try_get::<Option<u64>, _>(1)?.unwrap_or(r.try_get::<u64, _>(0)?)))
            .collect::<AuthResult<Vec<u64>>>()?;
        Ok(super::distinct(ids))
    }

    /// `DesignationDAO.readInternal`.
    pub async fn designation(&self, id: u64) -> AuthResult<Option<Designation>> {
        let row = sqlx::query(
            "SELECT ID, CLIENT_ID, NAME, DESCRIPTION, DEPARTMENT_ID, PARENT_DESIGNATION_ID, NEXT_DESIGNATION_ID, PROFILE_ID, \
             CREATED_BY, CREATED_AT, UPDATED_BY, UPDATED_AT FROM security_designation WHERE ID = ? LIMIT 1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        let Some(r) = row else { return Ok(None) };
        Ok(Some(Designation {
            id: r.try_get("ID")?,
            client_id: r.try_get("CLIENT_ID")?,
            name: r.try_get("NAME")?,
            description: r.try_get("DESCRIPTION")?,
            department_id: r.try_get("DEPARTMENT_ID")?,
            parent_designation_id: r.try_get("PARENT_DESIGNATION_ID")?,
            next_designation_id: r.try_get("NEXT_DESIGNATION_ID")?,
            profile_id: r.try_get("PROFILE_ID")?,
            created_by: r.try_get("CREATED_BY")?,
            created_at: ts(&r, "CREATED_AT")?,
            updated_by: r.try_get("UPDATED_BY")?,
            updated_at: ts(&r, "UPDATED_AT")?,
        }))
    }
}
