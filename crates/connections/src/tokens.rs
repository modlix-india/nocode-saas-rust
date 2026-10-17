//! `core_tokens` (`CoreTokenDAO`): OAuth2 and auth-function tokens per client, app and
//! connection.
//!
//! The Java DAO writes `LocalDateTime` values as they are, so `EXPIRES_AT` holds the Java
//! core's wall clock (its JVM zone) and "now" in every comparison is that wall clock too. The
//! pool's session runs in UTC like the Java one (`serverTimezone=UTC`), and "now" is computed
//! with the configured offset of the Java zone, so both sides read and write the same values.
//!
//! The SQL is what jOOQ generates for these calls (checked against jOOQ itself): null values
//! of the NOT NULL columns with defaults (`IS_REVOKED`, `IS_LIFETIME_TOKEN`) are left out of
//! inserts and updates, every other column is written, nulls included.

use async_trait::async_trait;
use chrono::{DateTime, Duration as ChronoDuration, NaiveDateTime, Utc};
use serde_json::{Map, Value};
use sqlx::mysql::MySqlRow;
use sqlx::{MySqlPool, Row};

use crate::error::{ConnError, ConnResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    Access,
    Refresh,
}

impl TokenType {
    pub fn as_str(&self) -> &'static str {
        match self {
            TokenType::Access => "ACCESS",
            TokenType::Refresh => "REFRESH",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "ACCESS" => Some(Self::Access),
            "REFRESH" => Some(Self::Refresh),
            _ => None,
        }
    }
}

/// `CoreToken`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CoreToken {
    pub id: Option<u64>,
    pub user_id: Option<u64>,
    pub client_code: Option<String>,
    pub app_code: Option<String>,
    pub connection_name: Option<String>,
    pub token_type: Option<TokenType>,
    pub token: Option<String>,
    pub state: Option<String>,
    pub token_metadata: Option<Map<String, Value>>,
    pub is_revoked: Option<bool>,
    pub is_lifetime_token: Option<bool>,
    pub expires_at: Option<NaiveDateTime>,
    pub created_by: Option<u64>,
    pub updated_by: Option<u64>,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
}

/// The Java core's wall clock, `LocalDateTime.now()` in its JVM zone.
#[derive(Debug, Clone, Copy, Default)]
pub struct JavaClock {
    pub zone_offset_seconds: i32,
}

impl JavaClock {
    pub fn now(&self) -> NaiveDateTime {
        (Utc::now() + ChronoDuration::seconds(self.zone_offset_seconds as i64)).naive_utc()
    }
}

/// The `CoreTokenDAO` operations the services use. [`TokenDao`] is the MySQL one.
#[async_trait]
pub trait TokenStore: Send + Sync {
    /// `getActiveAccessTokenTuple`: the first unrevoked, unexpired token of the connection,
    /// whatever its type (Java does not filter on it).
    async fn active_access_token_tuple(
        &self,
        client_code: &str,
        app_code: &str,
        connection_name: &str,
    ) -> ConnResult<Option<(Option<String>, Option<NaiveDateTime>)>>;
    /// `getActiveToken`: a token of the type, not revoked, and either unexpired or, without an
    /// expiry, a lifetime token.
    async fn active_token(
        &self,
        client_code: &str,
        app_code: &str,
        connection_name: &str,
        token_type: TokenType,
    ) -> ConnResult<Option<CoreToken>>;
    /// `getCoreTokenByState`.
    async fn by_state(&self, state: Option<&str>) -> ConnResult<Option<CoreToken>>;
    /// `revokeToken`: every unrevoked token of the connection (of the type, when given) marked
    /// revoked; true when any row changed.
    async fn revoke(&self, client_code: &str, app_code: &str, connection_name: &str, token_type: Option<TokenType>) -> ConnResult<bool>;
    /// `create`: inserts and reads the row back.
    async fn create(&self, token: &CoreToken) -> ConnResult<CoreToken>;
    /// `update`: every column but `CREATED_BY` / `CREATED_AT` from the entity, then the row.
    async fn update(&self, token: &CoreToken) -> ConnResult<Option<CoreToken>>;
}

/// A bind parameter of the statements below.
#[derive(Debug, Clone, PartialEq)]
pub enum Param {
    Str(Option<String>),
    U64(Option<u64>),
    I8(i8),
    Time(Option<NaiveDateTime>),
}

/// A statement and its parameters, in order.
#[derive(Debug, Clone, PartialEq)]
pub struct Statement {
    pub sql: String,
    pub params: Vec<Param>,
}

const COLUMNS: &str = "ID, USER_ID, CLIENT_CODE, APP_CODE, STATE, CONNECTION_NAME, TOKEN_TYPE, TOKEN, \
     CAST(TOKEN_METADATA AS CHAR) AS TOKEN_METADATA, \
     IS_REVOKED, EXPIRES_AT, IS_LIFETIME_TOKEN, CREATED_BY, UPDATED_BY, CREATED_AT, UPDATED_AT";

fn s(v: &str) -> Param {
    Param::Str(Some(v.to_string()))
}

fn metadata_json(m: &Option<Map<String, Value>>) -> Option<String> {
    m.as_ref().map(|m| serde_json::to_string(m).unwrap_or_else(|_| "{}".into()))
}

pub fn active_access_token_tuple_sql(client_code: &str, app_code: &str, connection_name: &str, now: NaiveDateTime) -> Statement {
    Statement {
        sql: "SELECT TOKEN, EXPIRES_AT FROM core_tokens WHERE CLIENT_CODE = ? AND APP_CODE = ? AND CONNECTION_NAME = ? \
              AND IS_REVOKED = 0 AND EXPIRES_AT > ? LIMIT 1"
            .into(),
        params: vec![s(client_code), s(app_code), s(connection_name), Param::Time(Some(now))],
    }
}

pub fn active_token_sql(client_code: &str, app_code: &str, connection_name: &str, token_type: TokenType, now: NaiveDateTime) -> Statement {
    Statement {
        sql: format!(
            "SELECT {COLUMNS} FROM core_tokens WHERE CLIENT_CODE = ? AND APP_CODE = ? AND CONNECTION_NAME = ? \
             AND TOKEN_TYPE = ? AND TOKEN IS NOT NULL AND IS_REVOKED = 0 \
             AND CASE WHEN EXPIRES_AT IS NULL THEN (IS_LIFETIME_TOKEN = 1) ELSE (EXPIRES_AT > ?) END LIMIT 1"
        ),
        params: vec![s(client_code), s(app_code), s(connection_name), s(token_type.as_str()), Param::Time(Some(now))],
    }
}

pub fn by_state_sql(state: &str) -> Statement {
    Statement { sql: format!("SELECT {COLUMNS} FROM core_tokens WHERE STATE = ? LIMIT 1"), params: vec![s(state)] }
}

pub fn by_id_sql(id: u64) -> Statement {
    Statement { sql: format!("SELECT {COLUMNS} FROM core_tokens WHERE ID = ? LIMIT 1"), params: vec![Param::U64(Some(id))] }
}

pub fn revoke_sql(client_code: &str, app_code: &str, connection_name: &str, token_type: Option<TokenType>) -> Statement {
    let mut sql = String::from("UPDATE core_tokens SET IS_REVOKED = 1 WHERE ");
    let mut params = Vec::new();
    if let Some(t) = token_type {
        sql.push_str("TOKEN_TYPE = ? AND ");
        params.push(s(t.as_str()));
    }
    sql.push_str("CLIENT_CODE = ? AND APP_CODE = ? AND CONNECTION_NAME = ? AND IS_REVOKED = 0");
    params.extend([s(client_code), s(app_code), s(connection_name)]);
    Statement { sql, params }
}

/// The columns jOOQ writes for a token and their values: null values of the NOT NULL columns
/// with defaults are left out.
fn written_columns(t: &CoreToken) -> Vec<(&'static str, Param)> {
    let mut cols = vec![
        ("USER_ID", Param::U64(t.user_id)),
        ("CLIENT_CODE", Param::Str(t.client_code.clone())),
        ("APP_CODE", Param::Str(t.app_code.clone())),
        ("STATE", Param::Str(t.state.clone())),
        ("CONNECTION_NAME", Param::Str(t.connection_name.clone())),
        ("TOKEN_TYPE", Param::Str(t.token_type.map(|x| x.as_str().to_string()))),
        ("TOKEN", Param::Str(t.token.clone())),
        ("TOKEN_METADATA", Param::Str(metadata_json(&t.token_metadata))),
    ];
    if let Some(r) = t.is_revoked {
        cols.push(("IS_REVOKED", Param::I8(r as i8)));
    }
    cols.push(("EXPIRES_AT", Param::Time(t.expires_at)));
    if let Some(l) = t.is_lifetime_token {
        cols.push(("IS_LIFETIME_TOKEN", Param::I8(l as i8)));
    }
    cols
}

pub fn insert_sql(t: &CoreToken) -> Statement {
    let mut cols = written_columns(t);
    cols.push(("CREATED_BY", Param::U64(t.created_by)));
    cols.push(("UPDATED_BY", Param::U64(t.updated_by)));
    Statement {
        sql: format!(
            "INSERT INTO core_tokens ({}) VALUES ({})",
            cols.iter().map(|(c, _)| *c).collect::<Vec<_>>().join(", "),
            cols.iter().map(|_| "?").collect::<Vec<_>>().join(", ")
        ),
        params: cols.into_iter().map(|(_, p)| p).collect(),
    }
}

/// `None` for an entity without an id (nothing to update).
pub fn update_sql(t: &CoreToken) -> Option<Statement> {
    let id = t.id?;
    let mut cols = vec![("ID", Param::U64(Some(id)))];
    cols.extend(written_columns(t));
    cols.push(("UPDATED_BY", Param::U64(t.updated_by)));
    let mut params: Vec<Param> = Vec::new();
    let sets: Vec<String> = cols
        .into_iter()
        .map(|(c, p)| {
            params.push(p);
            format!("{c} = ?")
        })
        .collect();
    params.push(Param::U64(Some(id)));
    Some(Statement { sql: format!("UPDATE core_tokens SET {} WHERE ID = ?", sets.join(", ")), params })
}

/// The MySQL `core_tokens` of the `core` database.
#[derive(Debug, Clone)]
pub struct TokenDao {
    pool: MySqlPool,
    pub clock: JavaClock,
}

fn db_err(e: sqlx::Error) -> ConnError {
    ConnError::other(e.to_string())
}

fn bind<'q>(st: &'q Statement) -> sqlx::query::Query<'q, sqlx::MySql, sqlx::mysql::MySqlArguments> {
    let mut q = sqlx::query(&st.sql);
    for p in &st.params {
        q = match p {
            Param::Str(v) => q.bind(v.as_deref()),
            Param::U64(v) => q.bind(*v),
            Param::I8(v) => q.bind(*v),
            Param::Time(v) => q.bind(*v),
        };
    }
    q
}

/// A `TIMESTAMP` column as the wall value the session (UTC) shows: sqlx decodes `TIMESTAMP` only
/// to `DateTime<Utc>`.
fn timestamp(r: &MySqlRow, column: &str) -> ConnResult<Option<NaiveDateTime>> {
    Ok(r.try_get::<Option<DateTime<Utc>>, _>(column).map_err(db_err)?.map(|t| t.naive_utc()))
}

fn from_row(r: &MySqlRow) -> ConnResult<CoreToken> {
    let metadata: Option<String> = r.try_get("TOKEN_METADATA").map_err(db_err)?;
    let token_type: String = r.try_get("TOKEN_TYPE").map_err(db_err)?;
    Ok(CoreToken {
        id: r.try_get("ID").map_err(db_err)?,
        user_id: r.try_get("USER_ID").map_err(db_err)?,
        client_code: r.try_get("CLIENT_CODE").map_err(db_err)?,
        app_code: r.try_get("APP_CODE").map_err(db_err)?,
        connection_name: r.try_get("CONNECTION_NAME").map_err(db_err)?,
        token_type: TokenType::parse(&token_type),
        token: r.try_get("TOKEN").map_err(db_err)?,
        state: r.try_get("STATE").map_err(db_err)?,
        token_metadata: metadata.and_then(|s| serde_json::from_str::<Map<String, Value>>(&s).ok()),
        is_revoked: r.try_get::<Option<bool>, _>("IS_REVOKED").map_err(db_err)?,
        is_lifetime_token: r.try_get::<Option<bool>, _>("IS_LIFETIME_TOKEN").map_err(db_err)?,
        expires_at: timestamp(r, "EXPIRES_AT")?,
        created_by: r.try_get("CREATED_BY").map_err(db_err)?,
        updated_by: r.try_get("UPDATED_BY").map_err(db_err)?,
        created_at: timestamp(r, "CREATED_AT")?,
        updated_at: timestamp(r, "UPDATED_AT")?,
    })
}

impl TokenDao {
    pub fn new(pool: MySqlPool, clock: JavaClock) -> Self {
        Self { pool, clock }
    }

    async fn one(&self, st: Statement) -> ConnResult<Option<CoreToken>> {
        let row = bind(&st).fetch_optional(&self.pool).await.map_err(db_err)?;
        row.as_ref().map(from_row).transpose()
    }

    async fn execute(&self, st: Statement) -> ConnResult<sqlx::mysql::MySqlQueryResult> {
        bind(&st).execute(&self.pool).await.map_err(db_err)
    }
}

#[async_trait]
impl TokenStore for TokenDao {
    async fn active_access_token_tuple(
        &self,
        client_code: &str,
        app_code: &str,
        connection_name: &str,
    ) -> ConnResult<Option<(Option<String>, Option<NaiveDateTime>)>> {
        let st = active_access_token_tuple_sql(client_code, app_code, connection_name, self.clock.now());
        let row = bind(&st).fetch_optional(&self.pool).await.map_err(db_err)?;
        row.map(|r| Ok((r.try_get("TOKEN").map_err(db_err)?, timestamp(&r, "EXPIRES_AT")?))).transpose()
    }

    async fn active_token(&self, client_code: &str, app_code: &str, connection_name: &str, token_type: TokenType) -> ConnResult<Option<CoreToken>> {
        self.one(active_token_sql(client_code, app_code, connection_name, token_type, self.clock.now())).await
    }

    async fn by_state(&self, state: Option<&str>) -> ConnResult<Option<CoreToken>> {
        // `STATE = null` matches nothing in SQL.
        match state {
            Some(st) => self.one(by_state_sql(st)).await,
            None => Ok(None),
        }
    }

    async fn revoke(&self, client_code: &str, app_code: &str, connection_name: &str, token_type: Option<TokenType>) -> ConnResult<bool> {
        Ok(self.execute(revoke_sql(client_code, app_code, connection_name, token_type)).await?.rows_affected() > 0)
    }

    async fn create(&self, t: &CoreToken) -> ConnResult<CoreToken> {
        let id = self.execute(insert_sql(t)).await?.last_insert_id();
        self.one(by_id_sql(id)).await?.ok_or_else(|| ConnError::other("The token just created could not be read"))
    }

    async fn update(&self, t: &CoreToken) -> ConnResult<Option<CoreToken>> {
        let Some(st) = update_sql(t) else { return Ok(None) };
        let id = t.id.unwrap_or_default();
        self.execute(st).await?;
        self.one(by_id_sql(id)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> NaiveDateTime {
        NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").unwrap()
    }

    /// The column lists jOOQ produced for the same entities (`JooqTok` harness, 2026-10-15).
    #[test]
    fn statements_match_jooq() {
        let t = CoreToken {
            client_code: Some("SYSTEM".into()),
            app_code: Some("app".into()),
            connection_name: Some("c".into()),
            token_type: Some(TokenType::Access),
            token: Some("tok".into()),
            expires_at: Some(at("2026-01-01 10:00:00")),
            token_metadata: Some(serde_json::json!({"a": 1}).as_object().unwrap().clone()),
            ..Default::default()
        };
        let ins = insert_sql(&t);
        assert_eq!(
            ins.sql,
            "INSERT INTO core_tokens (USER_ID, CLIENT_CODE, APP_CODE, STATE, CONNECTION_NAME, TOKEN_TYPE, TOKEN, TOKEN_METADATA, EXPIRES_AT, CREATED_BY, UPDATED_BY) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        );
        assert_eq!(ins.params[7], Param::Str(Some("{\"a\":1}".into())));
        assert!(update_sql(&t).is_none());
        let mut u = t.clone();
        u.id = Some(5);
        let up = update_sql(&u).unwrap();
        assert_eq!(
            up.sql,
            "UPDATE core_tokens SET ID = ?, USER_ID = ?, CLIENT_CODE = ?, APP_CODE = ?, STATE = ?, CONNECTION_NAME = ?, TOKEN_TYPE = ?, TOKEN = ?, TOKEN_METADATA = ?, EXPIRES_AT = ?, UPDATED_BY = ? WHERE ID = ?"
        );
        u.is_revoked = Some(false);
        u.is_lifetime_token = Some(true);
        let up = update_sql(&u).unwrap();
        assert!(up.sql.contains("IS_REVOKED = ?, EXPIRES_AT = ?, IS_LIFETIME_TOKEN = ?"));
        assert_eq!(up.params.len(), 14);
        assert!(insert_sql(&u).sql.contains("IS_REVOKED, EXPIRES_AT, IS_LIFETIME_TOKEN"));
    }

    #[test]
    fn selects_and_revokes() {
        let now = at("2026-10-15 10:00:00");
        let st = active_token_sql("S", "a", "c", TokenType::Refresh, now);
        assert!(st.sql.contains("CASE WHEN EXPIRES_AT IS NULL THEN (IS_LIFETIME_TOKEN = 1) ELSE (EXPIRES_AT > ?) END"));
        assert_eq!(st.params[3], Param::Str(Some("REFRESH".into())));
        assert_eq!(active_access_token_tuple_sql("S", "a", "c", now).params.len(), 4);
        assert_eq!(revoke_sql("S", "a", "c", None).params.len(), 3);
        let r = revoke_sql("S", "a", "c", Some(TokenType::Access));
        assert!(r.sql.starts_with("UPDATE core_tokens SET IS_REVOKED = 1 WHERE TOKEN_TYPE = ? AND CLIENT_CODE = ?"));
        assert_eq!(by_state_sql("x").params, vec![Param::Str(Some("x".into()))]);
        assert_eq!(by_id_sql(3).params, vec![Param::U64(Some(3))]);
        assert_eq!(TokenType::parse("REFRESH"), Some(TokenType::Refresh));
        assert_eq!(TokenType::parse("X"), None);
        let c = JavaClock { zone_offset_seconds: 19_800 };
        let diff = c.now() - JavaClock::default().now();
        assert!((diff.num_seconds() - 19_800).abs() <= 1);
    }
}
