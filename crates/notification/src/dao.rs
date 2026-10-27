//! `notification_inapp` and `notification_preference`, with the statements jOOQ runs for the
//! Java services.
//!
//! Tables are named without a schema (Java's generated code writes `notification`.`...`), so a
//! pool on any schema with the same DDL works, which is how the tests use scratch schemas.
//! Timestamps are read as epoch seconds (`CommonsSerializationModule` writes a `LocalDateTime`
//! as its UTC epoch second) and written as the current instant in the session's UTC.

use std::collections::HashMap;

use anyhow::{bail, Result};
use serde_json::{Map, Value};
use sqlx::mysql::MySqlPool;
use sqlx::Row;

/// A `notification_inapp` row, as the in-app event and the list read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InAppRow {
    pub id: u64,
    pub user_id: u64,
    pub app_code: String,
    pub notification_name: String,
    pub title: String,
    pub message: String,
    pub mime_url: Option<String>,
    pub notification_type: String,
    pub notification_category: String,
    pub url: Option<String>,
    pub read_at: Option<i64>,
    pub created_at: i64,
}

/// One row to insert (`NotificationInappRecord` with the fields `sendInApp` sets).
#[derive(Debug, Clone, Default)]
pub struct NewInApp<'a> {
    pub user_id: u64,
    pub app_code: &'a str,
    pub notification_name: Option<&'a str>,
    pub notification_type: &'a str,
    pub notification_category: &'a str,
    pub title: Option<&'a str>,
    pub message: Option<&'a str>,
    pub mime_url: Option<&'a str>,
    pub url: Option<&'a str>,
}

/// The filters of the list and count reads.
#[derive(Debug, Clone, Copy, Default)]
pub struct InAppFilter<'a> {
    pub app_code: &'a str,
    pub user_id: u64,
    pub notification_type: Option<&'a str>,
    pub category: Option<&'a str>,
}

const INAPP_COLUMNS: &str = "ID, USER_ID, APP_CODE, NOTIFICATION_NAME, TITLE, MESSAGE, MIME_URL, NOTIFICATION_TYPE, \
     NOTIFICATION_CATEGORY, URL, CAST(UNIX_TIMESTAMP(READ_AT) AS SIGNED) AS READ_AT_S, \
     CAST(UNIX_TIMESTAMP(CREATED_AT) AS SIGNED) AS CREATED_AT_S";

fn inapp_row(r: &sqlx::mysql::MySqlRow) -> Result<InAppRow> {
    Ok(InAppRow {
        id: r.try_get("ID")?,
        user_id: r.try_get("USER_ID")?,
        app_code: r.try_get("APP_CODE")?,
        notification_name: r.try_get("NOTIFICATION_NAME")?,
        title: r.try_get("TITLE")?,
        message: r.try_get("MESSAGE")?,
        mime_url: r.try_get("MIME_URL")?,
        notification_type: r.try_get("NOTIFICATION_TYPE")?,
        notification_category: r.try_get("NOTIFICATION_CATEGORY")?,
        url: r.try_get("URL")?,
        read_at: r.try_get("READ_AT_S")?,
        created_at: r.try_get::<Option<i64>, _>("CREATED_AT_S")?.unwrap_or(0),
    })
}

/// A value bound to a filter's placeholder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bind<'a> {
    Text(&'a str),
    Id(u64),
}

type Query<'q> = sqlx::query::Query<'q, sqlx::MySql, sqlx::mysql::MySqlArguments>;

impl<'a> Bind<'a> {
    fn onto<'q>(self, q: Query<'q>) -> Query<'q>
    where
        'a: 'q,
    {
        match self {
            Self::Text(s) => q.bind(s),
            Self::Id(i) => q.bind(i),
        }
    }
}

/// A `notification_preference` row: its id and the `PREFERENCE` JSON as MySQL prints it.
#[derive(Debug, Clone, PartialEq)]
pub struct PreferenceRow {
    pub id: u64,
    pub preference: Option<String>,
}

#[derive(Clone)]
pub struct Dao {
    pool: MySqlPool,
}

impl Dao {
    pub fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &MySqlPool {
        &self.pool
    }

    /// `insertInto(NOTIFICATION_INAPP).set(record).returning().fetchOne()`: the insert, then
    /// the row as stored (jOOQ reads it back by the generated id on MySQL).
    pub async fn insert_inapp(&self, n: &NewInApp<'_>) -> Result<InAppRow> {
        let done = sqlx::query(
            "INSERT INTO notification_inapp (USER_ID, APP_CODE, NOTIFICATION_NAME, TITLE, MESSAGE, MIME_URL, \
             NOTIFICATION_TYPE, NOTIFICATION_CATEGORY, URL) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(n.user_id)
        .bind(n.app_code)
        .bind(n.notification_name)
        .bind(n.title)
        .bind(n.message)
        .bind(n.mime_url)
        .bind(n.notification_type)
        .bind(n.notification_category)
        .bind(n.url)
        .execute(&self.pool)
        .await?;
        let id = done.last_insert_id();
        let row = sqlx::query(&format!("SELECT {INAPP_COLUMNS} FROM notification_inapp WHERE ID = ?"))
            .bind(id)
            .fetch_one(&self.pool)
            .await?;
        inapp_row(&row)
    }

    fn filtered<'a>(f: &InAppFilter<'a>, unread_only: bool) -> (String, Vec<Bind<'a>>) {
        let mut sql = String::from(" WHERE (APP_CODE = ? AND USER_ID = ?");
        let mut binds = vec![Bind::Text(f.app_code), Bind::Id(f.user_id)];
        if unread_only {
            sql.push_str(" AND READ_AT IS NULL");
        }
        sql.push(')');
        if let Some(t) = f.notification_type {
            sql.push_str(" AND NOTIFICATION_TYPE = ?");
            binds.push(Bind::Text(t));
        }
        if let Some(c) = f.category {
            sql.push_str(" AND NOTIFICATION_CATEGORY = ?");
            binds.push(Bind::Text(c));
        }
        (sql, binds)
    }

    /// `checkForNewNotifications`: the unread rows of the user in the app (and type).
    pub async fn count_unread(&self, f: &InAppFilter<'_>) -> Result<i64> {
        let (cond, binds) = Self::filtered(&InAppFilter { category: None, ..*f }, true);
        let sql = format!("SELECT COUNT(*) FROM notification_inapp{cond}");
        let mut q = sqlx::query(&sql);
        for b in binds {
            q = b.onto(q);
        }
        Ok(q.fetch_one(&self.pool).await?.try_get::<i64, _>(0)?)
    }

    /// `readNotifications`' select: newest first, one page.
    pub async fn page(&self, f: &InAppFilter<'_>, limit: i64, offset: i64) -> Result<Vec<InAppRow>> {
        let (cond, binds) = Self::filtered(f, false);
        let sql = format!("SELECT {INAPP_COLUMNS} FROM notification_inapp{cond} ORDER BY CREATED_AT DESC LIMIT ? OFFSET ?");
        let mut q = sqlx::query(&sql);
        for b in binds {
            q = b.onto(q);
        }
        let rows = q.bind(limit).bind(offset).fetch_all(&self.pool).await?;
        rows.iter().map(inapp_row).collect()
    }

    /// The rows just read are marked read now.
    pub async fn mark_read(&self, ids: &[u64]) -> Result<u64> {
        if ids.is_empty() {
            return Ok(0);
        }
        let marks = vec!["?"; ids.len()].join(", ");
        let sql = format!("UPDATE notification_inapp SET READ_AT = CURRENT_TIMESTAMP WHERE ID IN ({marks})");
        let mut q = sqlx::query(&sql);
        for id in ids {
            q = q.bind(*id);
        }
        Ok(q.execute(&self.pool).await?.rows_affected())
    }

    /// The rows of these users that are theirs and still unread, or all of the user's unread
    /// rows in the app when `ids` is `None`, marked read now. Answers how many changed.
    pub async fn mark_read_of(&self, app_code: &str, user_id: u64, ids: Option<&[u64]>) -> Result<u64> {
        let mut sql = String::from("UPDATE notification_inapp SET READ_AT = CURRENT_TIMESTAMP WHERE APP_CODE = ? AND USER_ID = ? AND READ_AT IS NULL");
        if let Some(ids) = ids {
            if ids.is_empty() {
                return Ok(0);
            }
            sql.push_str(&format!(" AND ID IN ({})", vec!["?"; ids.len()].join(", ")));
        }
        let mut q = sqlx::query(&sql).bind(app_code).bind(user_id);
        for id in ids.unwrap_or_default() {
            q = q.bind(*id);
        }
        Ok(q.execute(&self.pool).await?.rows_affected())
    }

    /// The preference maps of these users in the app, for the sender. Where a user has more
    /// than one row (there is no unique key), the newest wins.
    pub async fn preferences_of(&self, app_code: &str, user_ids: &[u64]) -> Result<HashMap<u64, Map<String, Value>>> {
        let mut out = HashMap::new();
        if user_ids.is_empty() {
            return Ok(out);
        }
        let sql = format!(
            "SELECT USER_ID, CAST(PREFERENCE AS CHAR) AS P FROM notification_preference WHERE APP_CODE = ? AND USER_ID IN ({}) ORDER BY ID",
            vec!["?"; user_ids.len()].join(", ")
        );
        let mut q = sqlx::query(&sql).bind(app_code);
        for id in user_ids {
            q = q.bind(*id);
        }
        for r in q.fetch_all(&self.pool).await? {
            let uid: u64 = r.try_get("USER_ID")?;
            let p: Option<String> = r.try_get("P")?;
            out.insert(uid, preference_map(p.as_deref()));
        }
        Ok(out)
    }

    /// `getNotificationPreferenceRecord`: jOOQ's `fetchOne` fails when more than one row
    /// matches (there is no unique key on user and app).
    pub async fn preference(&self, app_code: &str, user_id: u64) -> Result<Option<PreferenceRow>> {
        let rows = sqlx::query(
            "SELECT ID, CAST(PREFERENCE AS CHAR) AS P FROM notification_preference WHERE USER_ID = ? AND APP_CODE = ?",
        )
        .bind(user_id)
        .bind(app_code)
        .fetch_all(&self.pool)
        .await?;
        if rows.len() > 1 {
            bail!("Cursor returned more than one result");
        }
        rows.first()
            .map(|r| Ok(PreferenceRow { id: r.try_get("ID")?, preference: r.try_get("P")? }))
            .transpose()
    }

    pub async fn insert_preference(&self, app_code: &str, user_id: u64, preference: Option<&str>, by: u64) -> Result<u64> {
        let done = sqlx::query(
            "INSERT INTO notification_preference (USER_ID, APP_CODE, PREFERENCE, CREATED_BY, CREATED_AT, UPDATED_BY, UPDATED_AT) \
             VALUES (?, ?, CAST(? AS JSON), ?, CURRENT_TIMESTAMP, ?, CURRENT_TIMESTAMP)",
        )
        .bind(user_id)
        .bind(app_code)
        .bind(preference)
        .bind(by)
        .bind(by)
        .execute(&self.pool)
        .await?;
        Ok(done.last_insert_id())
    }

    pub async fn update_preference(&self, id: u64, preference: &str, by: u64) -> Result<u64> {
        let done = sqlx::query(
            "UPDATE notification_preference SET PREFERENCE = CAST(? AS JSON), UPDATED_BY = ?, UPDATED_AT = CURRENT_TIMESTAMP WHERE ID = ?",
        )
        .bind(preference)
        .bind(by)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected())
    }

    pub async fn delete_preference(&self, id: u64) -> Result<u64> {
        let done = sqlx::query("DELETE FROM notification_preference WHERE ID = ?").bind(id).execute(&self.pool).await?;
        Ok(done.rows_affected())
    }
}

/// `JSONMysqlMapConvertor.from`: the column's JSON as a map in MySQL's key order; a null or
/// unreadable value is an empty map.
pub fn preference_map(stored: Option<&str>) -> Map<String, Value> {
    let Some(s) = stored else { return Map::new() };
    match serde_json::from_str::<Value>(s) {
        Ok(Value::Object(m)) => m,
        _ => {
            tracing::error!("Unable to convert {s} to map of string and objects.");
            Map::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preference_column_reading() {
        assert!(preference_map(None).is_empty());
        assert!(preference_map(Some("[1]")).is_empty());
        assert!(preference_map(Some("nope")).is_empty());
        let m = preference_map(Some(r#"{"b": 1, "aa": {"x": null}}"#));
        assert_eq!(m.keys().collect::<Vec<_>>(), ["b", "aa"]);
    }

    #[test]
    fn filters_like_jooq() {
        let (sql, binds) = Dao::filtered(&InAppFilter { app_code: "a", user_id: 3, notification_type: Some("INFO"), category: Some("c") }, false);
        assert_eq!(sql, " WHERE (APP_CODE = ? AND USER_ID = ?) AND NOTIFICATION_TYPE = ? AND NOTIFICATION_CATEGORY = ?");
        assert_eq!(binds, [Bind::Text("a"), Bind::Id(3), Bind::Text("INFO"), Bind::Text("c")]);
        let (sql, _) = Dao::filtered(&InAppFilter { app_code: "a", user_id: 3, ..Default::default() }, true);
        assert_eq!(sql, " WHERE (APP_CODE = ? AND USER_ID = ? AND READ_AT IS NULL)");
    }
}
