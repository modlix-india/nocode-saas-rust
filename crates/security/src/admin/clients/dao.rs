//! `AppDAO` / `ClientDAO` statements this piece needs beyond the shared readers in
//! [`crate::data`], as free functions over the pool (the shared `Db` keeps its own names).

use sqlx::{MySqlPool, Row};

use crate::errors::AuthResult;

/// `AppDAO.hasOnlyInternalAccess(appId, clientId, accessType)`: the app is the client's own, or
/// the client has an access row on it (with `EDIT_ACCESS = 1` when `write`).
pub async fn has_access_by_id(pool: &MySqlPool, app_id: u64, client_id: Option<u64>, write: bool) -> AuthResult<bool> {
    let edit = if write { " AND security_app_access.EDIT_ACCESS = 1" } else { "" };
    let sql = format!(
        "SELECT COUNT(*) FROM security_app LEFT JOIN security_client ON security_client.ID = security_app.CLIENT_ID \
         WHERE security_app.ID = ? AND (security_client.ID = ? OR security_app.ID IN (SELECT security_app_access.APP_ID \
         FROM security_app_access LEFT JOIN security_client ON security_client.ID = security_app_access.CLIENT_ID \
         WHERE security_app_access.APP_ID = ? AND security_client.ID = ?{edit})) LIMIT 1"
    );
    let n: i64 = sqlx::query_scalar(&sql).bind(app_id).bind(client_id).bind(app_id).bind(client_id).fetch_one(pool).await?;
    Ok(n != 0)
}

/// `ClientDAO.getClientTypeNCode(id)`: (type, code, level).
pub async fn client_type_code_level(pool: &MySqlPool, id: u64) -> AuthResult<Option<(String, String, String)>> {
    let row = sqlx::query("SELECT TYPE_CODE, CODE, LEVEL_TYPE FROM security_client WHERE ID = ? LIMIT 1")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    row.map(|r| Ok((r.try_get(0)?, r.try_get(1)?, r.try_get(2)?))).transpose()
}

/// `ClientDAO.getSystemClientId()`.
pub async fn system_client_id(pool: &MySqlPool) -> AuthResult<Option<u64>> {
    let row = sqlx::query("SELECT ID FROM security_client WHERE TYPE_CODE = 'SYS' LIMIT 1").fetch_optional(pool).await?;
    row.map(|r| r.try_get::<u64, _>(0)).transpose().map_err(Into::into)
}
