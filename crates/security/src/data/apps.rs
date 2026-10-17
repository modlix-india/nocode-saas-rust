//! `AppDAO` reads.

use sqlx::Row;

use super::Db;
use crate::errors::AuthResult;
use crate::model::App;
use crate::mysql::{app, APP_COLUMNS};

/// `AppDependency` as `getAppDependencies` fills it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AppDependency {
    pub app_id: u64,
    pub app_name: Option<String>,
    pub app_code: Option<String>,
    pub dependent_app_id: Option<u64>,
    pub dependent_app_name: Option<String>,
    pub dependent_app_code: Option<String>,
}

/// An `security_app_property` row.
#[derive(Debug, Clone, Default)]
pub struct AppProperty {
    pub client_id: u64,
    pub name: String,
    pub value: Option<String>,
}

impl Db {
    /// `AppDAO.getByAppCode` (uncached).
    pub async fn app_by_code(&self, code: &str) -> AuthResult<Option<App>> {
        let sql = format!("SELECT {APP_COLUMNS} FROM security_app WHERE APP_CODE = ? LIMIT 1");
        let row = sqlx::query(&sql).bind(code).fetch_optional(&self.pool).await?;
        row.as_ref().map(app).transpose()
    }

    /// The owning client's code (`appInheritance`'s first query).
    pub async fn app_owner_code(&self, app_code: &str) -> AuthResult<Option<Option<String>>> {
        let row = sqlx::query(
            "SELECT security_client.CODE FROM security_app LEFT JOIN security_client ON security_client.ID = security_app.CLIENT_ID \
             WHERE security_app.APP_CODE = ? LIMIT 1",
        )
        .bind(app_code)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|r| r.try_get::<Option<String>, _>(0)).transpose().map_err(Into::into)
    }

    /// `AppDAO.hasOnlyInternalAccess(appCode, clientCode, 1)`: owner, or an access row with
    /// `EDIT_ACCESS = 1`.
    pub async fn has_write_access(&self, app_code: &str, client_code: &str) -> AuthResult<bool> {
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM security_app LEFT JOIN security_client ON security_client.ID = security_app.CLIENT_ID \
             WHERE security_app.APP_CODE = ? AND (security_client.CODE = ? OR security_app.ID IN \
             (SELECT security_app_access.APP_ID FROM security_app_access LEFT JOIN security_client \
             ON security_client.ID = security_app_access.CLIENT_ID WHERE security_client.CODE = ? \
             AND security_app_access.EDIT_ACCESS = 1)) LIMIT 1",
        )
        .bind(app_code)
        .bind(client_code)
        .bind(client_code)
        .fetch_one(&self.pool)
        .await?;
        Ok(n != 0)
    }

    /// `AppDAO.getWriteAccessClientCodes`: the owner and every client with edit access, not
    /// deleted or inactive, by code.
    pub async fn write_access_client_codes(&self, app_code: &str) -> AuthResult<Vec<String>> {
        let rows = sqlx::query(
            "SELECT security_client.CODE FROM security_client WHERE (security_client.ID IN \
             (SELECT security_app_access.CLIENT_ID FROM security_app_access JOIN security_app \
             ON security_app_access.APP_ID = security_app.ID WHERE (security_app.APP_CODE = ? AND security_app_access.EDIT_ACCESS = 1) \
             UNION SELECT security_app.CLIENT_ID FROM security_app WHERE security_app.APP_CODE = ?) \
             AND (security_client.STATUS_CODE IS NULL OR security_client.STATUS_CODE NOT IN ('DELETED', 'INACTIVE'))) \
             ORDER BY security_client.CODE",
        )
        .bind(app_code)
        .bind(app_code)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(|r| Ok(r.try_get::<String, _>(0)?)).collect()
    }

    /// The first edit-access client of an EXPLICIT app (`getByAppCodeExplicitInfo`).
    pub async fn explicit_edit_client(&self, app_id: u64) -> AuthResult<Option<u64>> {
        let row = sqlx::query("SELECT CLIENT_ID FROM security_app_access WHERE APP_ID = ? AND EDIT_ACCESS = 1 LIMIT 1")
            .bind(app_id)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|r| r.try_get::<u64, _>(0)).transpose().map_err(Into::into)
    }

    /// `AppDAO.getAppDependencies`: empty when the app has none.
    pub async fn app_dependencies(&self, app_id: u64) -> AuthResult<Vec<AppDependency>> {
        let rows = sqlx::query(
            "SELECT security_app.ID, security_app.APP_NAME, security_app.APP_CODE FROM security_app_dependency \
             LEFT JOIN security_app ON security_app_dependency.DEP_APP_ID = security_app.ID WHERE security_app_dependency.APP_ID = ?",
        )
        .bind(app_id)
        .fetch_all(&self.pool)
        .await?;
        if rows.is_empty() {
            return Ok(vec![]);
        }
        let own = sqlx::query("SELECT APP_NAME, APP_CODE FROM security_app WHERE ID = ?").bind(app_id).fetch_optional(&self.pool).await?;
        let Some(own) = own else { return Ok(vec![]) };
        let (name, code): (Option<String>, Option<String>) = (own.try_get(0)?, own.try_get(1)?);
        rows.iter()
            .map(|r| {
                Ok(AppDependency {
                    app_id,
                    app_name: name.clone(),
                    app_code: code.clone(),
                    dependent_app_id: r.try_get(0)?,
                    dependent_app_name: r.try_get(1)?,
                    dependent_app_code: r.try_get(2)?,
                })
            })
            .collect()
    }

    /// `AppDAO.getProperties` rows: the app's properties named `name` for the app's own client
    /// and `client_ids` (or the owner's alone when the list is empty and the caller is not
    /// SYSTEM).
    pub async fn app_properties(&self, app: &App, name: &str, client_ids: &[u64], system: bool) -> AuthResult<Vec<AppProperty>> {
        let mut qb = sqlx::QueryBuilder::<sqlx::MySql>::new("SELECT CLIENT_ID, NAME, VALUE FROM security_app_property WHERE APP_ID = ");
        qb.push_bind(app.id).push(" AND NAME = ").push_bind(name.to_string());
        if !client_ids.is_empty() {
            qb.push(" AND (CLIENT_ID = ").push_bind(app.client_id).push(" OR ");
            super::push_in_u64(&mut qb, "CLIENT_ID", client_ids);
            qb.push(")");
        } else if !system {
            qb.push(" AND CLIENT_ID = ").push_bind(app.client_id);
        }
        let rows = qb.build().fetch_all(&self.pool).await?;
        rows.iter().map(|r| Ok(AppProperty { client_id: r.try_get(0)?, name: r.try_get(1)?, value: r.try_get(2)? })).collect()
    }
}
