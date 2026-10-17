//! The `security` schema through sqlx: the SQL each Java DAO method renders, column for column.
//!
//! Sessions run in UTC (`platform::db::mysql_pool`), like the Java service's R2DBC pool
//! (`serverTimezone=UTC`), so a `TIMESTAMP` reads back as the wall time Java wrote.

use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::mysql::{MySqlPool, MySqlRow};
use sqlx::{QueryBuilder, Row};

use crate::errors::AuthResult;
use crate::model::{App, Client, ClientHierarchy, OneTimeTokenRow, OtpPolicy, PassType, Policy, TokenRow, UrlPattern, User};
use crate::store::{
    IdentifierType, NamedRow, NewOneTimeToken, NewOtp, NewToken, OtpRow, PermissionRow, RoleRecord, StateRow, Store,
    UserQuery,
};

const NON_DELETED: &str = "('ACTIVE','INACTIVE','LOCKED','PASSWORD_EXPIRED')";

pub const USER_COLUMNS: &str = "u.ID, u.DESIGNATION_ID, u.REPORTING_TO, u.CLIENT_ID, u.USER_NAME, u.EMAIL_ID, u.PHONE_NUMBER, \
    u.FIRST_NAME, u.LAST_NAME, u.MIDDLE_NAME, u.LOCALE_CODE, u.PASSWORD, u.PASSWORD_HASHED, u.PIN, u.PIN_HASHED, \
    u.ACCOUNT_NON_EXPIRED, u.ACCOUNT_NON_LOCKED, u.CREDENTIALS_NON_EXPIRED, u.NO_FAILED_ATTEMPT, \
    u.NO_PIN_FAILED_ATTEMPT, u.NO_OTP_FAILED_ATTEMPT, u.STATUS_CODE, u.LOCKED_UNTIL, u.LOCKED_DUE_TO, \
    u.CREATED_BY, u.CREATED_AT, u.UPDATED_BY, u.UPDATED_AT, u.TIME_ZONE";

pub const CLIENT_COLUMNS: &str = "ID, CODE, NAME, TYPE_CODE, LEVEL_TYPE, TOKEN_VALIDITY_MINUTES, LOCALE_CODE, \
    STATUS_CODE, BUSINESS_TYPE, CREATED_BY, CREATED_AT, UPDATED_BY, UPDATED_AT, BUSINESS_SIZE, INDUSTRY, \
    TIME_ZONE, WEBSITE, EMAIL_ID, PHONE_NUMBER, ALTERNATE_PHONE_NUMBER, LINKEDIN_URL, DESCRIPTION";

pub const APP_COLUMNS: &str = "ID, CLIENT_ID, APP_NAME, APP_CODE, APP_TYPE, APP_ACCESS_TYPE, THUMB_URL, \
    APP_USAGE_TYPE, STATUS, CREATED_BY, CREATED_AT, UPDATED_BY, UPDATED_AT";

#[derive(Clone)]
pub struct MySqlStore {
    pool: MySqlPool,
}

impl MySqlStore {
    pub fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }
}

pub fn ts(row: &MySqlRow, col: &str) -> AuthResult<Option<NaiveDateTime>> {
    Ok(row.try_get::<Option<DateTime<Utc>>, _>(col)?.map(|t| t.naive_utc()))
}

fn small(row: &MySqlRow, col: &str) -> AuthResult<Option<i64>> {
    Ok(row.try_get::<Option<i16>, _>(col)?.map(i64::from))
}

pub fn user(row: &MySqlRow) -> AuthResult<User> {
    Ok(User {
        id: row.try_get("ID")?,
        designation_id: row.try_get("DESIGNATION_ID")?,
        reporting_to: row.try_get("REPORTING_TO")?,
        client_id: row.try_get("CLIENT_ID")?,
        user_name: row.try_get("USER_NAME")?,
        email_id: row.try_get("EMAIL_ID")?,
        phone_number: row.try_get("PHONE_NUMBER")?,
        first_name: row.try_get("FIRST_NAME")?,
        last_name: row.try_get("LAST_NAME")?,
        middle_name: row.try_get("MIDDLE_NAME")?,
        locale_code: row.try_get("LOCALE_CODE")?,
        password: row.try_get("PASSWORD")?,
        password_hashed: row.try_get::<Option<bool>, _>("PASSWORD_HASHED")?.unwrap_or(false),
        pin: row.try_get("PIN")?,
        pin_hashed: row.try_get::<Option<bool>, _>("PIN_HASHED")?.unwrap_or(false),
        account_non_expired: row.try_get("ACCOUNT_NON_EXPIRED")?,
        account_non_locked: row.try_get("ACCOUNT_NON_LOCKED")?,
        credentials_non_expired: row.try_get("CREDENTIALS_NON_EXPIRED")?,
        no_failed_attempt: small(row, "NO_FAILED_ATTEMPT")?,
        no_pin_failed_attempt: small(row, "NO_PIN_FAILED_ATTEMPT")?,
        no_otp_failed_attempt: small(row, "NO_OTP_FAILED_ATTEMPT")?,
        status_code: row.try_get::<Option<String>, _>("STATUS_CODE")?.unwrap_or_default(),
        locked_until: ts(row, "LOCKED_UNTIL")?,
        locked_due_to: row.try_get("LOCKED_DUE_TO")?,
        created_by: row.try_get("CREATED_BY")?,
        created_at: ts(row, "CREATED_AT")?,
        updated_by: row.try_get("UPDATED_BY")?,
        updated_at: ts(row, "UPDATED_AT")?,
        time_zone: row.try_get("TIME_ZONE")?,
    })
}

pub fn client(row: &MySqlRow) -> AuthResult<Client> {
    Ok(Client {
        id: row.try_get("ID")?,
        created_at: ts(row, "CREATED_AT")?,
        created_by: row.try_get("CREATED_BY")?,
        updated_at: ts(row, "UPDATED_AT")?,
        updated_by: row.try_get("UPDATED_BY")?,
        code: row.try_get("CODE")?,
        name: row.try_get("NAME")?,
        type_code: row.try_get("TYPE_CODE")?,
        token_validity_minutes: i64::from(row.try_get::<u32, _>("TOKEN_VALIDITY_MINUTES")?),
        locale_code: row.try_get("LOCALE_CODE")?,
        time_zone: row.try_get("TIME_ZONE")?,
        status_code: row.try_get("STATUS_CODE")?,
        business_type: row.try_get("BUSINESS_TYPE")?,
        business_size: row.try_get("BUSINESS_SIZE")?,
        industry: row.try_get("INDUSTRY")?,
        level_type: row.try_get("LEVEL_TYPE")?,
        website: row.try_get("WEBSITE")?,
        email_id: row.try_get("EMAIL_ID")?,
        phone_number: row.try_get("PHONE_NUMBER")?,
        alternate_phone_number: row.try_get("ALTERNATE_PHONE_NUMBER")?,
        linkedin_url: row.try_get("LINKEDIN_URL")?,
        description: row.try_get("DESCRIPTION")?,
    })
}

pub fn app(row: &MySqlRow) -> AuthResult<App> {
    Ok(App {
        id: row.try_get("ID")?,
        client_id: row.try_get("CLIENT_ID")?,
        app_name: row.try_get("APP_NAME")?,
        app_code: row.try_get("APP_CODE")?,
        app_type: row.try_get("APP_TYPE")?,
        app_access_type: row.try_get("APP_ACCESS_TYPE")?,
        thumb_url: row.try_get("THUMB_URL")?,
        app_usage_type: row.try_get("APP_USAGE_TYPE")?,
        status: row.try_get("STATUS")?,
        created_by: row.try_get("CREATED_BY")?,
        created_at: ts(row, "CREATED_AT")?,
        updated_by: row.try_get("UPDATED_BY")?,
        updated_at: ts(row, "UPDATED_AT")?,
    })
}

fn named(row: &MySqlRow) -> AuthResult<NamedRow> {
    Ok(NamedRow { id: row.try_get("ID")?, name: row.try_get("NAME")?, app_code: row.try_get("APP_CODE")? })
}

fn permission(row: &MySqlRow) -> AuthResult<PermissionRow> {
    Ok(PermissionRow { name: row.try_get("NAME")?, app_code: row.try_get("APP_CODE")? })
}

/// `col IN (?, ?, ...)`, or jOOQ's rendering of an empty `IN`: a false condition.
fn push_in<'a>(qb: &mut QueryBuilder<'a, sqlx::MySql>, col: &str, ids: &'a [u64]) {
    if ids.is_empty() {
        qb.push(" 1 = 0 ");
        return;
    }
    qb.push(format!(" {col} IN ("));
    let mut sep = qb.separated(", ");
    for id in ids {
        sep.push_bind(*id);
    }
    sep.push_unseparated(") ");
}

fn failed_column(t: PassType) -> &'static str {
    match t {
        PassType::Password => "NO_FAILED_ATTEMPT",
        PassType::Pin => "NO_PIN_FAILED_ATTEMPT",
        PassType::Otp => "NO_OTP_FAILED_ATTEMPT",
    }
}

#[async_trait]
impl Store for MySqlStore {
    async fn user_by_id(&self, id: u64) -> AuthResult<Option<User>> {
        let sql = format!("SELECT {USER_COLUMNS} FROM security_user u WHERE u.ID = ? LIMIT 1");
        let row = sqlx::query(&sql).bind(id).fetch_optional(&self.pool).await?;
        row.as_ref().map(user).transpose()
    }

    async fn users_by(&self, q: &UserQuery) -> AuthResult<Vec<User>> {
        let mut qb: QueryBuilder<sqlx::MySql> = QueryBuilder::new(format!("SELECT {USER_COLUMNS} FROM security_user u"));
        if let Some(app) = &q.app_code {
            qb.push(" LEFT JOIN security_app a ON a.APP_CODE = ").push_bind(app.clone());
            qb.push(" LEFT JOIN security_app_access aa ON aa.CLIENT_ID = u.CLIENT_ID AND aa.APP_ID = a.ID");
        }
        if q.active_client_only {
            qb.push(" LEFT JOIN security_client uc ON uc.ID = u.CLIENT_ID");
        }
        qb.push(" LEFT JOIN security_client c ON c.CODE = ").push_bind(q.client_code.clone());
        qb.push(" LEFT JOIN security_client_hierarchy h ON h.CLIENT_ID = u.CLIENT_ID WHERE ");
        if let Some(name) = q.user_name.as_ref().filter(|n| !n.trim().is_empty() && n.as_str() != crate::model::PLACEHOLDER) {
            let col = match q.identifier {
                IdentifierType::PhoneNumber => "u.PHONE_NUMBER",
                IdentifierType::EmailId => "u.EMAIL_ID",
                IdentifierType::UserName => "u.USER_NAME",
            };
            qb.push(format!("{col} = ")).push_bind(name.clone()).push(" AND ");
        }
        qb.push(format!("u.STATUS_CODE IN {NON_DELETED}"));
        if let Some(id) = q.user_id {
            qb.push(" AND u.ID = ").push_bind(id);
        }
        if q.app_code.is_some() {
            qb.push(" AND (a.APP_ACCESS_TYPE = 'ANY' OR a.CLIENT_ID = u.CLIENT_ID OR aa.CLIENT_ID = u.CLIENT_ID)");
        }
        qb.push(
            " AND (h.CLIENT_ID = c.ID OR h.MANAGE_CLIENT_LEVEL_0 = c.ID OR h.MANAGE_CLIENT_LEVEL_1 = c.ID \
             OR h.MANAGE_CLIENT_LEVEL_2 = c.ID OR h.MANAGE_CLIENT_LEVEL_3 = c.ID)",
        );
        if q.active_client_only {
            qb.push(" AND uc.STATUS_CODE = 'ACTIVE'");
        }
        qb.push(" LIMIT ").push_bind(q.limit);
        let rows = qb.build().fetch_all(&self.pool).await?;
        rows.iter().map(user).collect()
    }

    async fn owner_user_ids(&self, ids: &[u64]) -> AuthResult<Vec<u64>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut qb: QueryBuilder<sqlx::MySql> = QueryBuilder::new(
            "SELECT pu.USER_ID FROM security_profile_user pu \
             JOIN security_profile_role pr ON pr.PROFILE_ID = pu.PROFILE_ID \
             JOIN security_v2_role r ON r.ID = pr.ROLE_ID WHERE r.NAME = 'Owner' AND ",
        );
        push_in(&mut qb, "pu.USER_ID", ids);
        qb.push(
            " UNION SELECT ur.USER_ID FROM security_v2_user_role ur \
             JOIN security_v2_role r ON r.ID = ur.ROLE_ID WHERE r.NAME = 'Owner' AND ",
        );
        push_in(&mut qb, "ur.USER_ID", ids);
        qb.push(
            " UNION SELECT ur.USER_ID FROM security_v2_user_role ur \
             JOIN security_v2_role_role rr ON rr.ROLE_ID = ur.ROLE_ID \
             JOIN security_v2_role r ON r.ID = rr.SUB_ROLE_ID WHERE r.NAME = 'Owner' AND ",
        );
        push_in(&mut qb, "ur.USER_ID", ids);
        let rows = qb.build().fetch_all(&self.pool).await?;
        rows.iter().map(|r| Ok(r.try_get::<u64, _>(0)?)).collect()
    }

    async fn is_user_owner(&self, user_id: u64) -> AuthResult<bool> {
        let row = sqlx::query(
            "SELECT r.NAME FROM security_profile p \
             LEFT JOIN security_profile_user pu ON pu.PROFILE_ID = p.ID \
             LEFT JOIN security_profile_role pr ON pr.PROFILE_ID = p.ID \
             LEFT JOIN security_v2_role r ON r.ID = pr.ROLE_ID \
             WHERE pu.USER_ID = ? AND r.NAME = 'Owner' LIMIT 1",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.is_some())
    }

    async fn increase_failed_attempt(&self, user_id: u64, t: PassType) -> AuthResult<Option<i64>> {
        let col = failed_column(t);
        sqlx::query(&format!(
            "UPDATE security_user SET {col} = CASE WHEN {col} IS NULL THEN 1 ELSE {col} + 1 END WHERE ID = ?"
        ))
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        let row = sqlx::query(&format!("SELECT {col} FROM security_user WHERE ID = ?"))
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(match row {
            Some(r) => small(&r, col)?,
            None => None,
        })
    }

    async fn reset_failed_attempt(&self, user_id: u64, t: PassType) -> AuthResult<bool> {
        let col = failed_column(t);
        let r = sqlx::query(&format!("UPDATE security_user SET {col} = 0 WHERE ID = ?")).bind(user_id).execute(&self.pool).await?;
        Ok(r.rows_affected() > 0)
    }

    async fn increase_resend_attempts(&self, user_id: u64) -> AuthResult<Option<i64>> {
        sqlx::query("UPDATE security_user SET NO_OTP_RESEND_ATTEMPT = NO_OTP_RESEND_ATTEMPT + 1 WHERE ID = ?")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        let row = sqlx::query("SELECT NO_OTP_RESEND_ATTEMPT FROM security_user WHERE ID = ?")
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(match row {
            Some(r) => small(&r, "NO_OTP_RESEND_ATTEMPT")?,
            None => None,
        })
    }

    async fn reset_resend_attempts(&self, user_id: u64) -> AuthResult<bool> {
        let r = sqlx::query("UPDATE security_user SET NO_OTP_RESEND_ATTEMPT = 0 WHERE ID = ?").bind(user_id).execute(&self.pool).await?;
        Ok(r.rows_affected() > 0)
    }

    async fn lock_user(&self, user_id: u64, until: NaiveDateTime, due_to: &str) -> AuthResult<bool> {
        let r = sqlx::query(
            "UPDATE security_user SET STATUS_CODE = 'LOCKED', ACCOUNT_NON_LOCKED = 0, LOCKED_UNTIL = ?, LOCKED_DUE_TO = ? \
             WHERE ID = ?",
        )
        .bind(until)
        .bind(due_to)
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() > 0)
    }

    async fn unlock_user(&self, user_id: u64) -> AuthResult<bool> {
        let r = sqlx::query(
            "UPDATE security_user SET STATUS_CODE = 'ACTIVE', ACCOUNT_NON_EXPIRED = 1, ACCOUNT_NON_LOCKED = 1, \
             CREDENTIALS_NON_EXPIRED = 1, NO_FAILED_ATTEMPT = 0, NO_PIN_FAILED_ATTEMPT = 0, NO_OTP_RESEND_ATTEMPT = 0, \
             NO_OTP_FAILED_ATTEMPT = 0, LOCKED_UNTIL = NULL, LOCKED_DUE_TO = NULL \
             WHERE ID = ? AND STATUS_CODE <> 'DELETED'",
        )
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() > 0)
    }

    async fn client_by_id(&self, id: u64) -> AuthResult<Option<Client>> {
        let sql = format!("SELECT {CLIENT_COLUMNS} FROM security_client WHERE ID = ? LIMIT 1");
        let row = sqlx::query(&sql).bind(id).fetch_optional(&self.pool).await?;
        row.as_ref().map(client).transpose()
    }

    async fn client_by_code(&self, code: &str) -> AuthResult<Option<Client>> {
        let sql = format!("SELECT {CLIENT_COLUMNS} FROM security_client WHERE CODE = ? LIMIT 1");
        let row = sqlx::query(&sql).bind(code).fetch_optional(&self.pool).await?;
        row.as_ref().map(client).transpose()
    }

    async fn client_type_code_level(&self, id: u64) -> AuthResult<Option<(String, String, String)>> {
        let row = sqlx::query("SELECT TYPE_CODE, CODE, LEVEL_TYPE FROM security_client WHERE ID = ? LIMIT 1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(match row {
            Some(r) => Some((r.try_get("TYPE_CODE")?, r.try_get("CODE")?, r.try_get("LEVEL_TYPE")?)),
            None => None,
        })
    }

    async fn client_hierarchy(&self, client_id: u64) -> AuthResult<Option<ClientHierarchy>> {
        let row = sqlx::query(
            "SELECT CLIENT_ID, MANAGE_CLIENT_LEVEL_0, MANAGE_CLIENT_LEVEL_1, MANAGE_CLIENT_LEVEL_2, MANAGE_CLIENT_LEVEL_3 \
             FROM security_client_hierarchy WHERE CLIENT_ID = ?",
        )
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(match row {
            Some(r) => Some(ClientHierarchy {
                client_id: r.try_get("CLIENT_ID")?,
                level0: r.try_get("MANAGE_CLIENT_LEVEL_0")?,
                level1: r.try_get("MANAGE_CLIENT_LEVEL_1")?,
                level2: r.try_get("MANAGE_CLIENT_LEVEL_2")?,
                level3: r.try_get("MANAGE_CLIENT_LEVEL_3")?,
            }),
            None => None,
        })
    }

    async fn count_active_clients(&self, ids: &[u64]) -> AuthResult<i64> {
        let mut qb: QueryBuilder<sqlx::MySql> =
            QueryBuilder::new("SELECT COUNT(*) FROM security_client WHERE STATUS_CODE = 'ACTIVE' AND ");
        push_in(&mut qb, "ID", ids);
        let row = qb.build().fetch_one(&self.pool).await?;
        Ok(row.try_get::<i64, _>(0)?)
    }

    async fn client_url_patterns(&self) -> AuthResult<Vec<UrlPattern>> {
        let rows = sqlx::query(
            "SELECT cu.CLIENT_ID, c.CODE, cu.URL_PATTERN, cu.APP_CODE, cu.URL_TYPE FROM security_client_url cu \
             LEFT JOIN security_app a ON a.APP_CODE = cu.APP_CODE AND a.STATUS = 'ACTIVE' \
             LEFT JOIN security_client c ON c.ID = cu.CLIENT_ID",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                let mut p = UrlPattern::new(
                    r.try_get::<u64, _>("CLIENT_ID")?.to_string(),
                    r.try_get("CODE")?,
                    r.try_get("URL_PATTERN")?,
                    r.try_get("APP_CODE")?,
                );
                p.url_type = Some(r.try_get::<Option<String>, _>("URL_TYPE")?.unwrap_or_else(|| "LIVE".into()));
                Ok(p)
            })
            .collect()
    }

    async fn app_by_code(&self, code: &str) -> AuthResult<Option<App>> {
        let sql = format!("SELECT {APP_COLUMNS} FROM security_app WHERE APP_CODE = ? LIMIT 1");
        let row = sqlx::query(&sql).bind(code).fetch_optional(&self.pool).await?;
        row.as_ref().map(app).transpose()
    }

    async fn app_by_id(&self, id: u64) -> AuthResult<Option<App>> {
        let sql = format!("SELECT {APP_COLUMNS} FROM security_app WHERE ID = ? LIMIT 1");
        let row = sqlx::query(&sql).bind(id).fetch_optional(&self.pool).await?;
        row.as_ref().map(app).transpose()
    }

    async fn has_read_access(&self, app_code: &str, client_code: &str) -> AuthResult<bool> {
        // AppDAO.hasOnlyInternalAccess(appCode, clientCode, 0).
        let row = sqlx::query(
            "SELECT COUNT(*) FROM security_app a LEFT JOIN security_client c ON c.ID = a.CLIENT_ID \
             WHERE a.APP_CODE = ? AND (c.CODE = ? OR a.ID IN (SELECT aa.APP_ID FROM security_app_access aa \
             LEFT JOIN security_client c2 ON c2.ID = aa.CLIENT_ID WHERE c2.CODE = ?)) LIMIT 1",
        )
        .bind(app_code)
        .bind(client_code)
        .bind(client_code)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.try_get::<i64, _>(0)? != 0)
    }

    async fn has_dependency_either_direction(&self, app_a: u64, app_b: u64) -> AuthResult<bool> {
        let row = sqlx::query(
            "SELECT COUNT(*) FROM security_app_dependency \
             WHERE (APP_ID = ? AND DEP_APP_ID = ?) OR (APP_ID = ? AND DEP_APP_ID = ?)",
        )
        .bind(app_a)
        .bind(app_b)
        .bind(app_b)
        .bind(app_a)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.try_get::<i64, _>(0)? > 0)
    }

    async fn user_roles(&self, user_id: u64) -> AuthResult<Vec<NamedRow>> {
        // RoleV2DAO.getRoleAuthoritiesPerApp: the user's roles and their direct sub-roles.
        let rows = sqlx::query(
            "SELECT a.APP_CODE, r.NAME, r.ID FROM security_v2_role r LEFT JOIN security_app a ON r.APP_ID = a.ID \
             WHERE r.ID IN (SELECT rr.SUB_ROLE_ID FROM security_v2_role_role rr \
             LEFT JOIN security_v2_user_role ur ON ur.ROLE_ID = rr.ROLE_ID WHERE ur.USER_ID = ? \
             UNION SELECT ur2.ROLE_ID FROM security_v2_user_role ur2 WHERE ur2.USER_ID = ?)",
        )
        .bind(user_id)
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(named).collect()
    }

    async fn role_permissions(&self, role_ids: &[u64]) -> AuthResult<Vec<PermissionRow>> {
        let mut qb: QueryBuilder<sqlx::MySql> = QueryBuilder::new(
            "SELECT a.APP_CODE, p.NAME FROM security_permission p LEFT JOIN security_app a ON p.APP_ID = a.ID \
             LEFT JOIN security_v2_role_permission rp ON p.ID = rp.PERMISSION_ID WHERE ",
        );
        push_in(&mut qb, "rp.ROLE_ID", role_ids);
        let rows = qb.build().fetch_all(&self.pool).await?;
        rows.iter().map(permission).collect()
    }

    async fn profile_ids(&self, app_code: Option<&str>, user_id: u64) -> AuthResult<Vec<u64>> {
        let all_apps = app_code.is_none() || app_code == Some("nothing");
        let mut qb: QueryBuilder<sqlx::MySql> = QueryBuilder::new(
            "SELECT pu.PROFILE_ID FROM security_profile_user pu LEFT JOIN security_profile p ON pu.PROFILE_ID = p.ID \
             LEFT JOIN security_app a ON p.APP_ID = a.ID WHERE pu.USER_ID = ",
        );
        qb.push_bind(user_id);
        if !all_apps {
            qb.push(" AND a.APP_CODE = ").push_bind(app_code.map(str::to_string));
        }
        let rows = qb.build().fetch_all(&self.pool).await?;
        rows.iter().map(|r| Ok(r.try_get::<u64, _>(0)?)).collect()
    }

    async fn default_profile_ids(&self, app_code: Option<&str>) -> AuthResult<Vec<u64>> {
        let rows = sqlx::query(
            "SELECT p.ID FROM security_profile p LEFT JOIN security_app a ON p.APP_ID = a.ID \
             WHERE p.DEFAULT_PROFILE = 1 AND a.APP_CODE = ?",
        )
        .bind(app_code)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(|r| Ok(r.try_get::<u64, _>(0)?)).collect()
    }

    async fn profile_rows(&self, profile_id: u64, client_ids: &[u64]) -> AuthResult<Vec<NamedRow>> {
        let mut qb: QueryBuilder<sqlx::MySql> = QueryBuilder::new(
            "SELECT p.ID, p.NAME, a.APP_CODE FROM security_profile p LEFT JOIN security_app a ON a.ID = p.APP_ID \
             WHERE p.ID = ",
        );
        qb.push_bind(profile_id).push(" OR (p.ROOT_PROFILE_ID = ").push_bind(profile_id).push(" AND ");
        push_in(&mut qb, "p.CLIENT_ID", client_ids);
        qb.push(")");
        let rows = qb.build().fetch_all(&self.pool).await?;
        rows.iter().map(named).collect()
    }

    async fn profile_role_rows(&self, profile_ids: &[u64]) -> AuthResult<Vec<RoleRecord>> {
        let mut qb: QueryBuilder<sqlx::MySql> = QueryBuilder::new(
            "SELECT r.ID AS ROLE_ID, p.CLIENT_ID AS PROFILE_CLIENT_ID, p.ID AS PROFILE_ID, r.NAME AS ROLE_NAME, \
             a.APP_CODE, pr.EXCLUDE FROM security_profile_role pr LEFT JOIN security_v2_role r ON pr.ROLE_ID = r.ID \
             LEFT JOIN security_app a ON r.APP_ID = a.ID LEFT JOIN security_profile p ON p.ID = pr.PROFILE_ID WHERE ",
        );
        push_in(&mut qb, "pr.PROFILE_ID", profile_ids);
        let rows = qb.build().fetch_all(&self.pool).await?;
        rows.iter()
            .map(|r| {
                Ok(RoleRecord {
                    role_id: r.try_get("ROLE_ID")?,
                    profile_client_id: r.try_get("PROFILE_CLIENT_ID")?,
                    profile_id: r.try_get("PROFILE_ID")?,
                    role_name: r.try_get("ROLE_NAME")?,
                    app_code: r.try_get("APP_CODE")?,
                    exclude: r.try_get::<Option<bool>, _>("EXCLUDE")?.map(i64::from),
                })
            })
            .collect()
    }

    async fn sub_role_rows(&self, role_ids: &[u64]) -> AuthResult<Vec<NamedRow>> {
        let mut qb: QueryBuilder<sqlx::MySql> = QueryBuilder::new(
            "SELECT r.ID, r.NAME, a.APP_CODE FROM security_v2_role_role rr LEFT JOIN security_v2_role r \
             ON rr.SUB_ROLE_ID = r.ID LEFT JOIN security_app a ON r.APP_ID = a.ID WHERE ",
        );
        push_in(&mut qb, "rr.ROLE_ID", role_ids);
        let rows = qb.build().fetch_all(&self.pool).await?;
        rows.iter().map(named).collect()
    }

    async fn permission_rows(&self, role_ids: &[u64]) -> AuthResult<Vec<PermissionRow>> {
        let mut qb: QueryBuilder<sqlx::MySql> = QueryBuilder::new(
            "SELECT p.NAME, a.APP_CODE FROM security_v2_role_permission rp LEFT JOIN security_permission p \
             ON p.ID = rp.PERMISSION_ID LEFT JOIN security_app a ON a.ID = p.APP_ID WHERE ",
        );
        push_in(&mut qb, "rp.ROLE_ID", role_ids);
        let rows = qb.build().fetch_all(&self.pool).await?;
        rows.iter().map(permission).collect()
    }

    async fn user_has_any_profile(&self, user_id: u64, app_code: &str) -> AuthResult<bool> {
        let row = sqlx::query(
            "SELECT COUNT(*) FROM security_profile_user pu LEFT JOIN security_profile p ON p.ID = pu.PROFILE_ID \
             LEFT JOIN security_app a ON a.ID = p.APP_ID WHERE pu.USER_ID = ? AND a.APP_CODE = ?",
        )
        .bind(user_id)
        .bind(app_code)
        .fetch_one(&self.pool)
        .await?;
        if row.try_get::<i64, _>(0)? > 0 {
            return Ok(true);
        }
        let row = sqlx::query(
            "SELECT COUNT(*) FROM security_profile p LEFT JOIN security_app a ON a.ID = p.APP_ID \
             WHERE a.APP_CODE = ? AND p.DEFAULT_PROFILE = 1",
        )
        .bind(app_code)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.try_get::<i64, _>(0)? > 0)
    }

    async fn has_assigned_profile(&self, user_id: u64, app_id: u64) -> AuthResult<bool> {
        let row = sqlx::query(
            "SELECT pu.PROFILE_ID FROM security_profile_user pu LEFT JOIN security_profile p ON p.ID = pu.PROFILE_ID \
             WHERE pu.USER_ID = ? AND p.APP_ID = ? LIMIT 1",
        )
        .bind(user_id)
        .bind(app_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.is_some())
    }

    async fn user_app_having_profile(&self, user_id: u64) -> AuthResult<Option<u64>> {
        let row = sqlx::query(
            "SELECT p.APP_ID FROM security_profile p LEFT JOIN security_profile_user pu ON pu.PROFILE_ID = p.ID \
             LEFT JOIN security_profile_role pr ON pr.PROFILE_ID = p.ID LEFT JOIN security_v2_role r ON r.ID = pr.ROLE_ID \
             WHERE pu.USER_ID = ? ORDER BY CASE WHEN r.NAME = 'Owner' THEN 1 ELSE 2 END, p.ID LIMIT 1",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(match row {
            Some(r) => Some(r.try_get::<u64, _>(0)?),
            None => None,
        })
    }

    async fn policy(&self, t: PassType, client_id: u64, app_id: u64) -> AuthResult<Option<Policy>> {
        let extra = if t == PassType::Otp {
            ", TARGET_TYPE, IS_CONSTANT, CONSTANT_VALUE, IS_NUMERIC, IS_ALPHANUMERIC, LENGTH, RESEND_SAME_OTP, EXPIRE_INTERVAL"
        } else {
            ""
        };
        let sql = format!(
            "SELECT NO_FAILED_ATTEMPTS, USER_LOCK_TIME{extra} FROM {} WHERE CLIENT_ID = ? AND APP_ID = ?",
            t.policy_table()
        );
        let row = sqlx::query(&sql).bind(client_id).bind(app_id).fetch_optional(&self.pool).await?;
        let Some(r) = row else { return Ok(None) };
        let otp = if t == PassType::Otp {
            Some(OtpPolicy {
                target_type: r.try_get("TARGET_TYPE")?,
                is_constant: r.try_get::<i8, _>("IS_CONSTANT")? != 0,
                constant_value: r.try_get("CONSTANT_VALUE")?,
                is_numeric: r.try_get::<i8, _>("IS_NUMERIC")? != 0,
                is_alphanumeric: r.try_get::<i8, _>("IS_ALPHANUMERIC")? != 0,
                length: i64::from(r.try_get::<u16, _>("LENGTH")?),
                resend_same_otp: r.try_get::<i8, _>("RESEND_SAME_OTP")? != 0,
                expire_interval: r.try_get::<u64, _>("EXPIRE_INTERVAL")? as i64,
            })
        } else {
            None
        };
        Ok(Some(Policy {
            no_failed_attempts: r.try_get::<Option<u16>, _>("NO_FAILED_ATTEMPTS")?.map(i64::from),
            user_lock_time: r.try_get::<Option<u64>, _>("USER_LOCK_TIME")?.map(|v| v as i64),
            otp,
        }))
    }

    async fn tokens_by_part(&self, part_token: &str) -> AuthResult<Vec<TokenRow>> {
        let rows = sqlx::query("SELECT ID, USER_ID, TOKEN, EXPIRES_AT FROM security_user_token WHERE PART_TOKEN = ?")
            .bind(part_token)
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|r| {
                Ok(TokenRow {
                    id: r.try_get("ID")?,
                    user_id: r.try_get("USER_ID")?,
                    token: r.try_get("TOKEN")?,
                    expires_at: r.try_get::<DateTime<Utc>, _>("EXPIRES_AT")?.naive_utc(),
                })
            })
            .collect()
    }

    async fn insert_token(&self, t: &NewToken) -> AuthResult<u64> {
        let r = sqlx::query(
            "INSERT INTO security_user_token (USER_ID, TOKEN, PART_TOKEN, EXPIRES_AT, IP_ADDRESS, USER_AGENT, \
             DEVICE_TYPE, OS, BROWSER, CREATED_BY) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(t.user_id)
        .bind(&t.token)
        .bind(&t.part_token)
        .bind(t.expires_at)
        .bind(&t.origin.ip_address)
        .bind(&t.origin.user_agent)
        .bind(&t.origin.device_type)
        .bind(&t.origin.os)
        .bind(&t.origin.browser)
        .bind(t.created_by)
        .execute(&self.pool)
        .await?;
        Ok(r.last_insert_id())
    }

    async fn delete_token(&self, id: u64) -> AuthResult<u64> {
        let r = sqlx::query("DELETE FROM security_user_token WHERE ID = ?").bind(id).execute(&self.pool).await?;
        Ok(r.rows_affected())
    }

    async fn token_strings_of_user(&self, user_id: u64) -> AuthResult<Vec<String>> {
        let rows = sqlx::query("SELECT TOKEN FROM security_user_token WHERE USER_ID = ?").bind(user_id).fetch_all(&self.pool).await?;
        rows.iter().map(|r| Ok(r.try_get::<String, _>(0)?)).collect()
    }

    async fn delete_tokens_of_user(&self, user_id: u64) -> AuthResult<u64> {
        let r = sqlx::query("DELETE FROM security_user_token WHERE USER_ID = ?").bind(user_id).execute(&self.pool).await?;
        Ok(r.rows_affected())
    }

    async fn update_last_used(&self, id: u64, at: NaiveDateTime) -> AuthResult<u64> {
        let r = sqlx::query("UPDATE security_user_token SET LAST_USED_AT = ? WHERE ID = ?").bind(at).bind(id).execute(&self.pool).await?;
        Ok(r.rows_affected())
    }

    async fn delete_expired_tokens(&self, now: NaiveDateTime) -> AuthResult<u64> {
        let r = sqlx::query("DELETE FROM security_user_token WHERE EXPIRES_AT < ?").bind(now).execute(&self.pool).await?;
        Ok(r.rows_affected())
    }

    async fn delete_unused_tokens(&self, cutoff: NaiveDateTime) -> AuthResult<u64> {
        let r = sqlx::query("DELETE FROM security_user_token WHERE LAST_USED_AT IS NOT NULL AND LAST_USED_AT < ?")
            .bind(cutoff)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected())
    }

    async fn delete_expired_draft_tokens(&self, now_utc: NaiveDateTime) -> AuthResult<u64> {
        let r = sqlx::query("DELETE FROM security_draft_token WHERE EXPIRES_AT < ?").bind(now_utc).execute(&self.pool).await?;
        Ok(r.rows_affected())
    }

    async fn insert_one_time_token(&self, t: &NewOneTimeToken) -> AuthResult<()> {
        // Columns the Java DTO leaves null take their defaults (REMEMBER_ME 0, AUTH_MODE BEARER).
        sqlx::query(
            "INSERT INTO security_one_time_token (USER_ID, TOKEN, IP_ADDRESS, USER_AGENT, DEVICE_TYPE, OS, BROWSER, \
             REMEMBER_ME, AUTH_MODE, ORIGIN_APP_CODE, TARGET_APP_CODE) \
             VALUES (?, ?, ?, ?, ?, ?, ?, COALESCE(?, 0), COALESCE(?, 'BEARER'), ?, ?)",
        )
        .bind(t.user_id)
        .bind(&t.token)
        .bind(&t.origin.ip_address)
        .bind(&t.origin.user_agent)
        .bind(&t.origin.device_type)
        .bind(&t.origin.os)
        .bind(&t.origin.browser)
        .bind(t.remember_me)
        .bind(&t.auth_mode)
        .bind(&t.origin_app_code)
        .bind(&t.target_app_code)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn redeem_one_time_token(&self, token: &str, max_age_minutes: i64) -> AuthResult<Option<OneTimeTokenRow>> {
        // OneTimeTokenDAO.readOneTimeTokenAndDeleteBy: only the call whose DELETE removed the row
        // gets it, and only while it is fresh by the database's own clock.
        let row = sqlx::query(
            "SELECT ID, USER_ID, REMEMBER_ME, AUTH_MODE, ORIGIN_APP_CODE, TARGET_APP_CODE, \
             (CREATED_AT >= (CURRENT_TIMESTAMP - INTERVAL ? MINUTE)) AS FRESH \
             FROM security_one_time_token WHERE TOKEN = ?",
        )
        .bind(max_age_minutes)
        .bind(token)
        .fetch_optional(&self.pool)
        .await?;
        let Some(r) = row else { return Ok(None) };
        let id: u64 = r.try_get("ID")?;
        let deleted = sqlx::query("DELETE FROM security_one_time_token WHERE ID = ?").bind(id).execute(&self.pool).await?;
        let fresh = r.try_get::<Option<bool>, _>("FRESH")?.unwrap_or(false);
        if deleted.rows_affected() != 1 || !fresh {
            return Ok(None);
        }
        Ok(Some(OneTimeTokenRow {
            user_id: r.try_get("USER_ID")?,
            remember_me: r.try_get::<bool, _>("REMEMBER_ME")?,
            auth_mode: r.try_get("AUTH_MODE")?,
            origin_app_code: r.try_get("ORIGIN_APP_CODE")?,
            target_app_code: r.try_get("TARGET_APP_CODE")?,
        }))
    }

    async fn insert_sox_log(&self, object_id: u64, action: &str, object: &str, description: &str) -> AuthResult<()> {
        sqlx::query("INSERT INTO security_sox_log (OBJECT_ID, OBJECT_NAME, ACTION_NAME, DESCRIPTION) VALUES (?, ?, ?, ?)")
            .bind(object_id)
            .bind(object)
            .bind(action)
            .bind(description)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn latest_otp(&self, app_id: u64, user_id: u64, purpose: &str) -> AuthResult<Option<OtpRow>> {
        let row = sqlx::query(
            "SELECT ID, UNIQUE_CODE, EXPIRES_AT, VERIFY_LEGS_COUNTS FROM security_otp \
             WHERE APP_ID = ? AND PURPOSE = ? AND USER_ID = ? ORDER BY CREATED_AT DESC LIMIT 1",
        )
        .bind(app_id)
        .bind(purpose)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(match row {
            Some(r) => Some(OtpRow {
                id: r.try_get("ID")?,
                unique_code: r.try_get("UNIQUE_CODE")?,
                expires_at: r.try_get::<DateTime<Utc>, _>("EXPIRES_AT")?.naive_utc(),
                verify_legs_counts: i64::from(r.try_get::<i16, _>("VERIFY_LEGS_COUNTS")?),
            }),
            None => None,
        })
    }

    async fn latest_otp_code(&self, app_id: u64, user_id: u64, purpose: &str) -> AuthResult<Option<String>> {
        Ok(self.latest_otp(app_id, user_id, purpose).await?.map(|o| o.unique_code))
    }

    async fn latest_otp_by_target(&self, app_id: u64, email: Option<&str>, phone: Option<&str>, purpose: &str) -> AuthResult<Option<OtpRow>> {
        let ids: Vec<(&str, &str)> = [("EMAIL_ID", email), ("PHONE_NUMBER", phone)].into_iter().filter_map(|(c, v)| v.map(|v| (c, v))).collect();
        if ids.is_empty() {
            return Ok(None);
        }
        let which = ids.iter().map(|(c, _)| format!("{c} = ?")).collect::<Vec<_>>().join(" OR ");
        let sql = format!(
            "SELECT ID, UNIQUE_CODE, EXPIRES_AT, VERIFY_LEGS_COUNTS FROM security_otp \
             WHERE APP_ID = ? AND PURPOSE = ? AND ({which}) ORDER BY CREATED_AT DESC LIMIT 1"
        );
        let mut q = sqlx::query(&sql).bind(app_id).bind(purpose);
        for (_, v) in &ids {
            q = q.bind(*v);
        }
        Ok(match q.fetch_optional(&self.pool).await? {
            Some(r) => Some(OtpRow {
                id: r.try_get("ID")?,
                unique_code: r.try_get("UNIQUE_CODE")?,
                expires_at: r.try_get::<DateTime<Utc>, _>("EXPIRES_AT")?.naive_utc(),
                verify_legs_counts: i64::from(r.try_get::<i16, _>("VERIFY_LEGS_COUNTS")?),
            }),
            None => None,
        })
    }

    async fn insert_otp(&self, o: &NewOtp) -> AuthResult<()> {
        sqlx::query(
            "INSERT INTO security_otp (APP_ID, USER_ID, EMAIL_ID, PHONE_NUMBER, PURPOSE, TARGET_TYPE, UNIQUE_CODE, \
             EXPIRES_AT, IP_ADDRESS, CREATED_BY, CREATED_AT) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(o.app_id)
        .bind(o.user_id)
        .bind(&o.email_id)
        .bind(&o.phone_number)
        .bind(&o.purpose)
        .bind(&o.target_type)
        .bind(&o.unique_code)
        .bind(o.expires_at)
        .bind(&o.ip_address)
        .bind(o.user_id)
        .bind(o.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn delete_otp(&self, id: u64) -> AuthResult<u64> {
        let r = sqlx::query("DELETE FROM security_otp WHERE ID = ?").bind(id).execute(&self.pool).await?;
        Ok(r.rows_affected())
    }

    async fn increase_otp_verify_count(&self, id: u64) -> AuthResult<bool> {
        let r = sqlx::query("UPDATE security_otp SET VERIFY_LEGS_COUNTS = VERIFY_LEGS_COUNTS + 1 WHERE ID = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    async fn state_by_value(&self, state: &str) -> AuthResult<Option<StateRow>> {
        let row = sqlx::query(
            "SELECT STATE, USERNAME, CREATED_AT, UPDATED_AT FROM security_app_reg_integration_tokens WHERE STATE = ? LIMIT 1",
        )
        .bind(state)
        .fetch_optional(&self.pool)
        .await?;
        Ok(match row {
            Some(r) => Some(StateRow {
                state: r.try_get::<Option<String>, _>("STATE")?.unwrap_or_default(),
                username: r.try_get("USERNAME")?,
                created_at: ts(&r, "CREATED_AT")?,
                updated_at: ts(&r, "UPDATED_AT")?,
            }),
            None => None,
        })
    }

    async fn consume_state(&self, state: &str) -> AuthResult<bool> {
        let r = sqlx::query("UPDATE security_app_reg_integration_tokens SET STATE = NULL WHERE STATE = ?")
            .bind(state)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() == 1)
    }
}
