//! `RoleV2DAO`: roles (a client-check table), the sub-role tree in `security_v2_role_role`, and
//! the lookups the role and profile services make.

use std::collections::{HashMap, HashSet};

use sqlx::mysql::MySqlRow;
use sqlx::{MySql, QueryBuilder, Row};

use super::crud::Entity;
use super::Db;
use crate::condition::{Bind, ColType, Table};
use crate::dto::Role;
use crate::errors::AuthResult;
use crate::mysql::ts;

use ColType::{Num, Str, Ts};

pub const ROLE: Entity = Entity {
    table: Table {
        name: "security_v2_role",
        columns: &[
            ("ID", Num),
            ("CLIENT_ID", Num),
            ("NAME", Str),
            ("SHORT_NAME", Str),
            ("DESCRIPTION", Str),
            ("APP_ID", Num),
            ("CREATED_BY", Num),
            ("CREATED_AT", Ts),
            ("UPDATED_BY", Num),
            ("UPDATED_AT", Ts),
        ],
    },
    client_column: Some("CLIENT_ID"),
    not_null: &["ID", "CLIENT_ID", "NAME", "CREATED_AT", "UPDATED_AT"],
};

/// `rec.into(RoleV2.class)`.
pub fn role(r: &MySqlRow) -> AuthResult<Role> {
    Ok(Role {
        id: r.try_get("ID")?,
        client_id: r.try_get("CLIENT_ID")?,
        app_id: r.try_get("APP_ID")?,
        name: r.try_get("NAME")?,
        short_name: r.try_get("SHORT_NAME")?,
        description: r.try_get("DESCRIPTION")?,
        created_by: r.try_get("CREATED_BY")?,
        created_at: ts(r, "CREATED_AT")?,
        updated_by: r.try_get("UPDATED_BY")?,
        updated_at: ts(r, "UPDATED_AT")?,
        ..Default::default()
    })
}

fn n(v: Option<u64>) -> Bind {
    v.map(Bind::U64).unwrap_or(Bind::Null)
}

fn s(v: &Option<String>) -> Bind {
    v.clone().map(Bind::Str).unwrap_or(Bind::Null)
}

fn t(v: Option<chrono::NaiveDateTime>) -> Bind {
    v.map(|t| Bind::Ts(t.and_utc())).unwrap_or(Bind::Null)
}

/// The record jOOQ makes from a `RoleV2` (its table's columns).
pub fn role_values(r: &Role) -> Vec<(&'static str, Bind)> {
    vec![
        ("CLIENT_ID", n(r.client_id)),
        ("NAME", s(&r.name)),
        ("SHORT_NAME", s(&r.short_name)),
        ("DESCRIPTION", s(&r.description)),
        ("APP_ID", n(r.app_id)),
        ("CREATED_BY", n(r.created_by)),
        ("CREATED_AT", t(r.created_at)),
        ("UPDATED_BY", n(r.updated_by)),
        ("UPDATED_AT", t(r.updated_at)),
    ]
}

fn in_list(qb: &mut QueryBuilder<'_, MySql>, ids: &[u64]) {
    let mut sep = qb.separated(", ");
    for id in ids {
        sep.push_bind(*id);
    }
}

/// The depth `RoleV2DAO.expandClosure` stops at.
const MAX_ROLE_DEPTH: usize = 32;

impl Db {
    /// A role by id, no joins.
    pub async fn role(&self, id: u64) -> AuthResult<Option<Role>> {
        let row = sqlx::query("SELECT * FROM security_v2_role WHERE ID = ? LIMIT 1").bind(id).fetch_optional(&self.pool).await?;
        row.as_ref().map(role).transpose()
    }

    /// `appCodesOf`: app code per app id.
    pub async fn app_codes_of(&self, app_ids: &[u64]) -> AuthResult<HashMap<u64, String>> {
        if app_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new("SELECT ID, APP_CODE FROM security_app WHERE ID IN (");
        in_list(&mut qb, app_ids);
        qb.push(")");
        let rows = qb.build().fetch_all(&self.pool).await?;
        rows.iter().map(|r| Ok((r.try_get("ID")?, r.try_get("APP_CODE")?))).collect()
    }

    /// `fetchSubRoles` / the sub-role half of `getRoles`: (parent role id, sub-role) rows in the
    /// order MySQL returns them (Java groups them in that order).
    pub async fn sub_role_rows(&self, role_ids: &[u64]) -> AuthResult<Vec<(u64, Role)>> {
        if role_ids.is_empty() {
            return Ok(vec![]);
        }
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new(
            "SELECT security_v2_role.*, security_v2_role_role.ROLE_ID AS RR_ROLE_ID FROM security_v2_role_role \
             LEFT JOIN security_v2_role ON security_v2_role.ID = security_v2_role_role.SUB_ROLE_ID \
             WHERE security_v2_role_role.ROLE_ID IN (",
        );
        in_list(&mut qb, role_ids);
        qb.push(")");
        let rows = qb.build().fetch_all(&self.pool).await?;
        rows.iter().map(|r| Ok((r.try_get("RR_ROLE_ID")?, role(r)?))).collect()
    }

    /// `fetchSubRolesOf`.
    pub async fn sub_roles_of(&self, role_id: u64) -> AuthResult<Vec<Role>> {
        let rows = sqlx::query(
            "SELECT security_v2_role.* FROM security_v2_role_role \
             LEFT JOIN security_v2_role ON security_v2_role.ID = security_v2_role_role.SUB_ROLE_ID \
             WHERE security_v2_role_role.ROLE_ID = ?",
        )
        .bind(role_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(role).collect()
    }

    /// The role half of `getRoles`: the roles with these ids.
    pub async fn roles_by_ids(&self, ids: &[u64]) -> AuthResult<Vec<Role>> {
        if ids.is_empty() {
            return Ok(vec![]);
        }
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new("SELECT * FROM security_v2_role WHERE ID IN (");
        in_list(&mut qb, ids);
        qb.push(")");
        qb.build().fetch_all(&self.pool).await?.iter().map(role).collect()
    }

    /// `RoleV2DAO.getRolesForAssignmentInApp`: the client's roles of the app or of no app
    /// (`nothing` means every app).
    pub async fn client_roles_for_app(&self, app_code: &str, client_id: u64) -> AuthResult<Vec<Role>> {
        let rows = if app_code == "nothing" {
            sqlx::query("SELECT * FROM security_v2_role WHERE CLIENT_ID = ?").bind(client_id).fetch_all(&self.pool).await?
        } else {
            sqlx::query(
                "SELECT * FROM security_v2_role WHERE CLIENT_ID = ? AND \
                 (APP_ID = (SELECT ID FROM security_app WHERE APP_CODE = ?) OR APP_ID IS NULL)",
            )
            .bind(client_id)
            .bind(app_code)
            .fetch_all(&self.pool)
            .await?
        };
        rows.iter().map(role).collect()
    }

    pub async fn has_sub_role(&self, role_id: u64, sub_role_id: u64) -> AuthResult<bool> {
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM security_v2_role_role WHERE ROLE_ID = ? AND SUB_ROLE_ID = ?")
            .bind(role_id)
            .bind(sub_role_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(n > 0)
    }

    pub async fn add_sub_role(&self, role_id: u64, sub_role_id: u64) -> AuthResult<bool> {
        let r = sqlx::query("INSERT INTO security_v2_role_role (ROLE_ID, SUB_ROLE_ID) VALUES (?, ?)")
            .bind(role_id)
            .bind(sub_role_id)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    pub async fn remove_sub_role(&self, role_id: u64, sub_role_id: u64) -> AuthResult<u64> {
        let r = sqlx::query("DELETE FROM security_v2_role_role WHERE ROLE_ID = ? AND SUB_ROLE_ID = ?")
            .bind(role_id)
            .bind(sub_role_id)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected())
    }

    /// `descendantsOf` (downwards) / `ancestorsOf`: every role reached, the start included.
    pub async fn role_closure(&self, start: u64, downwards: bool) -> AuthResult<HashSet<u64>> {
        let (from, to) = if downwards { ("ROLE_ID", "SUB_ROLE_ID") } else { ("SUB_ROLE_ID", "ROLE_ID") };
        let mut seen = HashSet::from([start]);
        let mut frontier = vec![start];
        let mut depth = 0;
        while !frontier.is_empty() && depth < MAX_ROLE_DEPTH {
            let mut qb: QueryBuilder<MySql> = QueryBuilder::new(format!("SELECT {to} FROM security_v2_role_role WHERE {from} IN ("));
            in_list(&mut qb, &frontier);
            qb.push(")");
            let next: Vec<u64> = qb.build().fetch_all(&self.pool).await?.iter().map(|r| r.try_get(0)).collect::<Result<_, _>>()?;
            frontier = next.into_iter().filter(|id| seen.insert(*id)).collect::<HashSet<_>>().into_iter().collect();
            depth += 1;
        }
        Ok(seen)
    }

    /// `profileIdsWithAnyRole`: the profiles holding any of the roles, and their roots.
    pub async fn profile_ids_with_any_role(&self, role_ids: &[u64]) -> AuthResult<HashSet<u64>> {
        if role_ids.is_empty() {
            return Ok(HashSet::new());
        }
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new(
            "SELECT DISTINCT security_profile_role.PROFILE_ID, security_profile.ROOT_PROFILE_ID FROM security_profile_role \
             LEFT JOIN security_profile ON security_profile.ID = security_profile_role.PROFILE_ID \
             WHERE security_profile_role.ROLE_ID IN (",
        );
        in_list(&mut qb, role_ids);
        qb.push(")");
        let mut out = HashSet::new();
        for r in qb.build().fetch_all(&self.pool).await? {
            out.insert(r.try_get::<u64, _>(0)?);
            if let Some(root) = r.try_get::<Option<u64>, _>(1)? {
                out.insert(root);
            }
        }
        Ok(out)
    }

    /// `AppDAO.hasReadAccess(appId, clientId)`: the app is the client's own, or the client has an
    /// access row.
    pub async fn has_read_access_ids(&self, app_id: u64, client_id: u64) -> AuthResult<bool> {
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM security_app LEFT JOIN security_client ON security_client.ID = security_app.CLIENT_ID \
             WHERE security_app.ID = ? AND (security_client.ID = ? OR security_app.ID IN \
             (SELECT security_app_access.APP_ID FROM security_app_access LEFT JOIN security_client \
             ON security_client.ID = security_app_access.CLIENT_ID WHERE security_app_access.APP_ID = ? AND security_client.ID = ?)) LIMIT 1",
        )
        .bind(app_id)
        .bind(client_id)
        .bind(app_id)
        .bind(client_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(n != 0)
    }

    /// The profile half of `ProfileDAO.getRolesForAssignmentInApp`: the app's profiles the
    /// hierarchy sees (no root mapping here).
    pub async fn visible_profile_ids(&self, app_id: u64, hierarchy_ids: &[u64]) -> AuthResult<Vec<u64>> {
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new(
            "SELECT DISTINCT security_profile.ID FROM security_profile \
             LEFT JOIN security_app ON security_app.ID = security_profile.APP_ID WHERE security_profile.APP_ID = ",
        );
        qb.push_bind(app_id).push(" AND (security_profile.CLIENT_ID IN (");
        in_list(&mut qb, hierarchy_ids);
        qb.push(") OR security_profile.CLIENT_ID = security_app.CLIENT_ID)");
        qb.build().fetch_all(&self.pool).await?.iter().map(|r| Ok(r.try_get::<u64, _>(0)?)).collect()
    }

    /// The distinct restricted profiles of the client in the app.
    pub async fn restricted_profile_ids_distinct(&self, client_id: u64, app_id: u64) -> AuthResult<Vec<u64>> {
        let rows = sqlx::query(
            "SELECT DISTINCT security_profile_client_restriction.PROFILE_ID FROM security_profile_client_restriction \
             LEFT JOIN security_profile ON security_profile.ID = security_profile_client_restriction.PROFILE_ID \
             WHERE security_profile_client_restriction.CLIENT_ID = ? AND security_profile.APP_ID = ?",
        )
        .bind(client_id)
        .bind(app_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(|r| Ok(r.try_get::<u64, _>(0)?)).collect()
    }

    /// The roles in these profiles (`security_profile_role` rows, excluded ones too).
    pub async fn roles_of_profiles(&self, profile_ids: &[u64]) -> AuthResult<Vec<Role>> {
        if profile_ids.is_empty() {
            return Ok(vec![]);
        }
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new(
            "SELECT security_v2_role.* FROM security_profile_role \
             LEFT JOIN security_v2_role ON security_v2_role.ID = security_profile_role.ROLE_ID \
             WHERE security_profile_role.PROFILE_ID IN (",
        );
        in_list(&mut qb, profile_ids);
        qb.push(")");
        qb.build().fetch_all(&self.pool).await?.iter().map(role).collect()
    }

    /// `AbstractDAO.delete` for a role; the database's refusal is kept apart.
    pub async fn delete_role(&self, id: u64) -> Result<u64, sqlx::Error> {
        Ok(sqlx::query("DELETE FROM security_v2_role WHERE ID = ?").bind(id).execute(&self.pool).await?.rows_affected())
    }
}
