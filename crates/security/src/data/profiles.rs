//! `ProfileDAO`: profiles (an app's bundles of roles), their overrides down the client
//! hierarchy (`ROOT_PROFILE_ID`), their role relations and client restrictions, and who holds
//! them. The arrangement column is read as MySQL's JSON text (its key order is MySQL's).

use serde_json::Value;
use sqlx::mysql::MySqlRow;
use sqlx::{MySql, QueryBuilder, Row};

use super::{push_in_u64, Db};
use crate::errors::AuthResult;
use crate::mysql::ts;

/// A `security_profile` row as the DAO reads it.
#[derive(Debug, Clone, Default)]
pub struct ProfileRow {
    pub id: u64,
    pub client_id: Option<u64>,
    pub default_profile: bool,
    pub name: Option<String>,
    pub title: Option<String>,
    pub app_id: Option<u64>,
    pub description: Option<String>,
    pub root_profile_id: Option<u64>,
    /// `JSONMysqlMapConvertor.from`: a null column is an empty map.
    pub arrangement: serde_json::Map<String, Value>,
    pub created_by: Option<u64>,
    pub created_at: Option<chrono::NaiveDateTime>,
    pub updated_by: Option<u64>,
    pub updated_at: Option<chrono::NaiveDateTime>,
}

const COLUMNS: &str = "security_profile.ID, security_profile.CLIENT_ID, security_profile.DEFAULT_PROFILE, security_profile.NAME, \
     security_profile.TITLE, security_profile.APP_ID, security_profile.DESCRIPTION, security_profile.ROOT_PROFILE_ID, \
     CAST(security_profile.ARRANGEMENT AS CHAR) AS ARRANGEMENT, security_profile.CREATED_BY, security_profile.CREATED_AT, \
     security_profile.UPDATED_BY, security_profile.UPDATED_AT";

fn profile(r: &MySqlRow) -> AuthResult<ProfileRow> {
    let text: Option<String> = r.try_get("ARRANGEMENT")?;
    let arrangement = match text.as_deref().map(serde_json::from_str::<Value>) {
        Some(Ok(Value::Object(m))) => m,
        _ => serde_json::Map::new(),
    };
    Ok(ProfileRow {
        id: r.try_get("ID")?,
        client_id: r.try_get("CLIENT_ID")?,
        default_profile: r.try_get::<i8, _>("DEFAULT_PROFILE")? != 0,
        name: r.try_get("NAME")?,
        title: r.try_get("TITLE")?,
        app_id: r.try_get("APP_ID")?,
        description: r.try_get("DESCRIPTION")?,
        root_profile_id: r.try_get("ROOT_PROFILE_ID")?,
        arrangement,
        created_by: r.try_get("CREATED_BY")?,
        created_at: ts(r, "CREATED_AT")?,
        updated_by: r.try_get("UPDATED_BY")?,
        updated_at: ts(r, "UPDATED_AT")?,
    })
}

/// What `createUpdateProfile` writes.
#[derive(Debug, Clone, Default)]
pub struct ProfileWrite {
    pub client_id: Option<u64>,
    pub default_profile: bool,
    pub name: Option<String>,
    pub title: Option<String>,
    pub app_id: Option<u64>,
    pub description: Option<String>,
    pub root_profile_id: Option<u64>,
    /// The JSON text of the arrangement, or `None` for a null column.
    pub arrangement: Option<String>,
    pub created_by: Option<u64>,
    pub created_at: Option<chrono::NaiveDateTime>,
    pub updated_by: Option<u64>,
    pub updated_at: Option<chrono::NaiveDateTime>,
}

impl Db {
    /// A profile by id (`readInternal`; also the client-check `readById`, whose joins never drop
    /// the row).
    pub async fn profile(&self, id: u64) -> AuthResult<Option<ProfileRow>> {
        let sql = format!("SELECT {COLUMNS} FROM security_profile WHERE security_profile.ID = ? LIMIT 1");
        sqlx::query(&sql).bind(id).fetch_optional(&self.pool).await?.as_ref().map(profile).transpose()
    }

    /// `readRootProfile`'s query: the profile and its overrides by the listed clients.
    pub async fn profile_and_overrides(&self, id: u64, client_ids: &[u64]) -> AuthResult<Vec<ProfileRow>> {
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new(format!("SELECT {COLUMNS} FROM security_profile WHERE (security_profile.ID = "));
        qb.push_bind(id).push(" OR (security_profile.ROOT_PROFILE_ID = ").push_bind(id).push(" AND ");
        push_in_u64(&mut qb, "security_profile.CLIENT_ID", client_ids);
        qb.push("))");
        qb.build().fetch_all(&self.pool).await?.iter().map(profile).collect()
    }

    /// The ids of the app's profiles the hierarchy sees, unmapped (`hasAccessToRoles`).
    pub async fn app_profile_ids_unmapped(&self, app_id: u64, client_ids: &[u64]) -> AuthResult<Vec<u64>> {
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new(
            "SELECT security_profile.ID FROM security_profile LEFT JOIN security_app ON security_app.ID = security_profile.APP_ID \
             WHERE security_profile.APP_ID = ",
        );
        qb.push_bind(app_id).push(" AND (");
        push_in_u64(&mut qb, "security_profile.CLIENT_ID", client_ids);
        qb.push(" OR security_profile.CLIENT_ID = security_app.CLIENT_ID)");
        qb.build().fetch_all(&self.pool).await?.iter().map(|r| Ok(r.try_get::<u64, _>(0)?)).collect()
    }

    /// `hasAccessToRoles`' union: the listed roles the profiles hold, and every sub-role of any
    /// role they hold.
    pub async fn roles_reachable_in_profiles(&self, profile_ids: &[u64], role_ids: &[u64]) -> AuthResult<Vec<u64>> {
        let mut qb: QueryBuilder<MySql> =
            QueryBuilder::new("(SELECT DISTINCT security_profile_role.ROLE_ID FROM security_profile_role WHERE ");
        push_in_u64(&mut qb, "security_profile_role.PROFILE_ID", profile_ids);
        qb.push(" AND ");
        push_in_u64(&mut qb, "security_profile_role.ROLE_ID", role_ids);
        qb.push(
            ") UNION (SELECT DISTINCT security_v2_role_role.SUB_ROLE_ID FROM security_v2_role_role \
             LEFT JOIN security_profile_role ON security_profile_role.ROLE_ID = security_v2_role_role.ROLE_ID WHERE ",
        );
        push_in_u64(&mut qb, "security_profile_role.PROFILE_ID", profile_ids);
        qb.push(")");
        qb.build().fetch_all(&self.pool).await?.iter().map(|r| Ok(r.try_get::<u64, _>(0)?)).collect()
    }

    /// `hasAccessToRoles`' last count: the client's own roles of the app (or of no app).
    pub async fn count_client_app_roles(&self, role_ids: &[u64], app_id: u64, client_id: u64) -> AuthResult<i64> {
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new("SELECT COUNT(*) FROM security_v2_role WHERE ");
        push_in_u64(&mut qb, "ID", role_ids);
        qb.push(" AND (APP_ID = ").push_bind(app_id).push(" OR APP_ID IS NULL) AND CLIENT_ID = ").push_bind(client_id);
        Ok(qb.build().fetch_one(&self.pool).await?.try_get(0)?)
    }

    /// `AbstractDAO.create` for a profile; the error is the database's.
    pub async fn insert_profile(&self, p: &ProfileWrite) -> Result<u64, sqlx::Error> {
        let mut cols: Vec<&str> = vec!["CLIENT_ID", "DEFAULT_PROFILE", "NAME", "TITLE", "APP_ID", "DESCRIPTION", "ROOT_PROFILE_ID", "ARRANGEMENT", "CREATED_BY"];
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new("");
        // NOT NULL columns without a value are left to their defaults, as jOOQ leaves them out.
        if p.created_at.is_some() {
            cols.push("CREATED_AT");
        }
        cols.push("UPDATED_BY");
        if p.updated_at.is_some() {
            cols.push("UPDATED_AT");
        }
        let cols: Vec<&str> = cols.into_iter().filter(|c| !(*c == "CLIENT_ID" && p.client_id.is_none()) && !(*c == "APP_ID" && p.app_id.is_none())).collect();
        qb.push(format!("INSERT INTO security_profile ({}) VALUES (", cols.join(", ")));
        let mut sep = qb.separated(", ");
        for c in &cols {
            match *c {
                "CLIENT_ID" => sep.push_bind(p.client_id),
                "DEFAULT_PROFILE" => sep.push_bind(i8::from(p.default_profile)),
                "NAME" => sep.push_bind(p.name.clone()),
                "TITLE" => sep.push_bind(p.title.clone()),
                "APP_ID" => sep.push_bind(p.app_id),
                "DESCRIPTION" => sep.push_bind(p.description.clone()),
                "ROOT_PROFILE_ID" => sep.push_bind(p.root_profile_id),
                "ARRANGEMENT" => sep.push_bind(p.arrangement.clone()),
                "CREATED_BY" => sep.push_bind(p.created_by),
                "CREATED_AT" => sep.push_bind(p.created_at),
                "UPDATED_BY" => sep.push_bind(p.updated_by),
                _ => sep.push_bind(p.updated_at),
            };
        }
        qb.push(")");
        Ok(qb.build().execute(&self.pool).await?.last_insert_id())
    }

    /// `ProfileDAO.update`'s statement (`UPDATED_BY` only for an override).
    pub async fn update_profile(&self, id: u64, p: &ProfileWrite, with_updated_by: bool) -> Result<u64, sqlx::Error> {
        let sql = if with_updated_by {
            "UPDATE security_profile SET NAME = ?, TITLE = ?, DESCRIPTION = ?, ARRANGEMENT = ?, DEFAULT_PROFILE = ?, UPDATED_BY = ? WHERE ID = ?"
        } else {
            "UPDATE security_profile SET NAME = ?, TITLE = ?, DESCRIPTION = ?, ARRANGEMENT = ?, DEFAULT_PROFILE = ? WHERE ID = ?"
        };
        let mut q = sqlx::query(sql).bind(p.name.clone()).bind(p.title.clone()).bind(p.description.clone()).bind(p.arrangement.clone()).bind(i8::from(p.default_profile));
        if with_updated_by {
            q = q.bind(p.updated_by);
        }
        Ok(q.bind(id).execute(&self.pool).await?.rows_affected())
    }

    /// `createRoleRelations`: the profile's role rows replaced (included roles, then excluded).
    pub async fn replace_profile_roles(&self, profile_id: u64, included: &[u64], excluded: &[u64]) -> AuthResult<()> {
        sqlx::query("DELETE FROM security_profile_role WHERE PROFILE_ID = ?").bind(profile_id).execute(&self.pool).await?;
        if included.is_empty() && excluded.is_empty() {
            return Ok(());
        }
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new("INSERT IGNORE INTO security_profile_role (PROFILE_ID, ROLE_ID, EXCLUDE) ");
        let rows = included.iter().map(|r| (*r, 0i8)).chain(excluded.iter().map(|r| (*r, 1i8)));
        qb.push_values(rows, |mut b, (role, ex)| {
            b.push_bind(profile_id).push_bind(role).push_bind(ex);
        });
        qb.build().execute(&self.pool).await?;
        Ok(())
    }

    /// `ProfileDAO.delete`'s check: overrides of the profile.
    pub async fn count_profile_overrides(&self, id: u64) -> AuthResult<i64> {
        Ok(sqlx::query_scalar("SELECT COUNT(*) FROM security_profile WHERE ROOT_PROFILE_ID = ?").bind(id).fetch_one(&self.pool).await?)
    }

    pub async fn delete_profile(&self, id: u64) -> Result<u64, sqlx::Error> {
        Ok(sqlx::query("DELETE FROM security_profile WHERE ID = ?").bind(id).execute(&self.pool).await?.rows_affected())
    }

    /// `checkProfileAppAccess`: the client has an access row for the profile's app.
    pub async fn profile_app_access(&self, profile_id: u64, client_id: u64) -> AuthResult<bool> {
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM security_profile LEFT JOIN security_app_access ON security_profile.APP_ID = security_app_access.APP_ID \
             WHERE security_profile.ID = ? AND security_app_access.CLIENT_ID = ?",
        )
        .bind(profile_id)
        .bind(client_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(n > 0)
    }

    pub async fn restrict_profile(&self, profile_id: u64, client_id: u64) -> AuthResult<bool> {
        let r = sqlx::query("INSERT INTO security_profile_client_restriction (PROFILE_ID, CLIENT_ID) VALUES (?, ?)")
            .bind(profile_id)
            .bind(client_id)
            .execute(&self.pool)
            .await;
        match r {
            Ok(r) => Ok(r.rows_affected() > 0),
            // jOOQ's DataAccessException text: the statement, then the server's message.
            Err(sqlx::Error::Database(db)) => Err(crate::errors::AuthError::internal(format!(
                "SQL [insert into `security`.`security_profile_client_restriction` (`PROFILE_ID`, `CLIENT_ID`) values (?, ?)]; {}",
                db.message()
            ))),
            Err(e) => Err(e.into()),
        }
    }

    /// `isBeingUsedByManagingClients` (every level equal to the client, as Java asks).
    pub async fn profile_used_by_managing_clients(&self, client_id: u64, root_id: u64) -> AuthResult<bool> {
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM security_profile LEFT JOIN security_client_hierarchy \
             ON security_profile.CLIENT_ID = security_client_hierarchy.CLIENT_ID WHERE security_profile.ROOT_PROFILE_ID = ? \
             AND security_client_hierarchy.MANAGE_CLIENT_LEVEL_0 = ? AND security_client_hierarchy.MANAGE_CLIENT_LEVEL_1 = ? \
             AND security_client_hierarchy.MANAGE_CLIENT_LEVEL_2 = ? AND security_client_hierarchy.MANAGE_CLIENT_LEVEL_3 = ?",
        )
        .bind(root_id)
        .bind(client_id)
        .bind(client_id)
        .bind(client_id)
        .bind(client_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(n > 0)
    }

    /// `getAssignedProfileIds`: the user's profiles (of the app, when given), in row order.
    pub async fn assigned_profile_ids(&self, user_id: u64, app_id: Option<u64>) -> AuthResult<Vec<u64>> {
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new(
            "SELECT security_profile_user.PROFILE_ID FROM security_profile_user \
             LEFT JOIN security_profile ON security_profile.ID = security_profile_user.PROFILE_ID WHERE security_profile_user.USER_ID = ",
        );
        qb.push_bind(user_id);
        if let Some(a) = app_id {
            qb.push(" AND security_profile.APP_ID = ").push_bind(a);
        }
        qb.build().fetch_all(&self.pool).await?.iter().map(|r| Ok(r.try_get::<u64, _>(0)?)).collect()
    }

    /// `hasAccessToProfiles`' reads: the apps the client owns or has access to, and its
    /// restricted (app, profile) pairs.
    pub async fn client_app_ids_and_restrictions(&self, client_id: u64) -> AuthResult<(Vec<u64>, Vec<(u64, u64)>)> {
        let apps: Vec<u64> = sqlx::query_scalar(
            "SELECT ID FROM security_app WHERE CLIENT_ID = ? UNION SELECT APP_ID FROM security_app_access WHERE CLIENT_ID = ?",
        )
        .bind(client_id)
        .bind(client_id)
        .fetch_all(&self.pool)
        .await?;
        let rows = sqlx::query(
            "SELECT security_profile.APP_ID, security_profile_client_restriction.PROFILE_ID FROM security_profile_client_restriction \
             LEFT JOIN security_profile ON security_profile.ID = security_profile_client_restriction.PROFILE_ID \
             WHERE security_profile_client_restriction.CLIENT_ID = ?",
        )
        .bind(client_id)
        .fetch_all(&self.pool)
        .await?;
        let restrictions = rows
            .iter()
            .map(|r| Ok((r.try_get::<Option<u64>, _>(0)?.unwrap_or_default(), r.try_get::<u64, _>(1)?)))
            .collect::<AuthResult<Vec<_>>>()?;
        Ok((apps, restrictions))
    }

    /// Profiles among these whose app is not in the list (an empty list excludes nothing).
    pub async fn count_profiles_outside_apps(&self, profile_ids: &[u64], app_ids: &[u64]) -> AuthResult<i64> {
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new("SELECT COUNT(*) FROM security_profile WHERE ");
        push_in_u64(&mut qb, "ID", profile_ids);
        if !app_ids.is_empty() {
            qb.push(" AND APP_ID NOT IN (");
            let mut sep = qb.separated(", ");
            for a in app_ids {
                sep.push_bind(*a);
            }
            qb.push(")");
        }
        Ok(qb.build().fetch_one(&self.pool).await?.try_get(0)?)
    }
}
