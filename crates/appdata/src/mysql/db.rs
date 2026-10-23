//! The MySQL connection side: pools per appData connection, bound statements, raw text
//! statements, and rows decoded into the Java types the jOOQ/R2DBC stack hands back.

use std::time::Duration;

use futures::future::BoxFuture;

use chrono::{NaiveDate, NaiveDateTime, NaiveTime};
use sha2::{Digest, Sha256};
use sqlx::mysql::{MySqlConnectOptions, MySqlPool, MySqlPoolOptions, MySqlRow};
use sqlx::{Column, Executor, MySql, Row, TypeInfo, ValueRef};

use super::sql::{Bind, Sql};
use crate::error::{AppDataError, AppDataResult};
use crate::model::Connection;
use crate::value::{float_as_double, Decimal, Document, Value};

/// Where a connection's server details came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    pub url: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub from_default: bool,
}

/// `BooleanUtil.safeValueOf`: a Boolean, yes / y / true / t / on in any case, or a
/// non-zero integer.
pub fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(other) => {
            let s = other.java_string();
            if s.trim().is_empty() {
                return false;
            }
            if ["yes", "y", "true", "t", "on"].iter().any(|t| s.eq_ignore_ascii_case(t)) {
                return true;
            }
            s.parse::<i32>().map(|i| i != 0).unwrap_or(false)
        }
    }
}

fn text(v: Option<&Value>) -> Option<String> {
    match v {
        None | Some(Value::Null) => None,
        Some(v) => Some(v.java_string()).filter(|s| !s.trim().is_empty()),
    }
}

/// Either what the connection states, or the platform's own datasource, all or nothing.
pub fn credentials(conn: &Connection, default: &Credentials) -> Credentials {
    let details = conn.connection_details.as_ref();
    if details.is_some_and(|d| truthy(d.get("useDefaultConnection"))) {
        return Credentials { from_default: true, ..default.clone() };
    }
    let Some(d) = details else { return Credentials { url: None, username: None, password: None, from_default: false } };
    Credentials {
        url: text(d.get("url")),
        username: text(d.get("username")),
        password: text(d.get("password")),
        from_default: false,
    }
}

/// A stable digest of the connection details, so a changed host or password gets a new
/// pool: SHA-256 of the sorted `key=value` lines, first 16 bytes in hex.
pub fn fingerprint(conn: &Connection) -> String {
    let Some(details) = conn.connection_details.as_ref().filter(|d| !d.is_empty()) else { return "none".into() };
    let mut keys: Vec<&String> = details.keys().collect();
    keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
    let mut sb = String::new();
    for k in keys {
        sb.push_str(k);
        sb.push('=');
        sb.push_str(&details[k].java_string());
        sb.push('\n');
    }
    hex::encode(&Sha256::digest(sb.as_bytes())[..16])
}

/// Connection options from an R2DBC url (`r2dbc:mysql://user:pw@host:port/db?opts`), the
/// form the Java connections and `spring.r2dbc.url` use.
pub fn connect_options(creds: &Credentials) -> AppDataResult<MySqlConnectOptions> {
    let url = creds.url.clone().ok_or_else(|| {
        AppDataError::connection_details_missing(if creds.from_default { "spring.r2dbc.url" } else { "url" })
    })?;
    let rest = url
        .strip_prefix("r2dbc:pool:mysql://")
        .or_else(|| url.strip_prefix("r2dbc:mysql://"))
        .or_else(|| url.strip_prefix("r2dbcs:mysql://"))
        .or_else(|| url.strip_prefix("mysql://"))
        .ok_or_else(|| AppDataError::internal(format!("not an r2dbc mysql url: {}", redact(&url))))?;
    let rest = rest.split('?').next().unwrap_or("");
    let (auth, host_part) = match rest.rfind('@') {
        Some(i) => (Some(&rest[..i]), &rest[i + 1..]),
        None => (None, rest),
    };
    let (hostport, database) = match host_part.find('/') {
        Some(i) => (&host_part[..i], Some(&host_part[i + 1..])),
        None => (host_part, None),
    };
    let (host, port) = match hostport.rfind(':') {
        Some(i) => (&hostport[..i], hostport[i + 1..].parse().unwrap_or(3306)),
        None => (hostport, 3306),
    };

    let mut opts = MySqlConnectOptions::new()
        .host(host)
        .port(port)
        .timezone(Some("+00:00".to_string()))
        .charset("utf8mb4");
    if let Some(db) = database.filter(|d| !d.is_empty()) {
        opts = opts.database(db);
    }
    if let Some(auth) = auth {
        let (u, p) = match auth.find(':') {
            Some(i) => (&auth[..i], Some(&auth[i + 1..])),
            None => (auth, None),
        };
        opts = opts.username(&decode_pct(u));
        if let Some(p) = p {
            opts = opts.password(&decode_pct(p));
        }
    }
    if let Some(u) = &creds.username {
        opts = opts.username(u);
    }
    if let Some(p) = &creds.password {
        opts = opts.password(p);
    }
    Ok(opts)
}

fn decode_pct(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn redact(url: &str) -> String {
    match url.rfind('@') {
        Some(i) => format!("***{}", &url[i..]),
        None => url.to_string(),
    }
}

/// Small by default: pools are per app, and an idle app should cost nothing. Connections
/// are checked on the way out, so a restarted server does not leave dead ones behind.
pub async fn create_pool(opts: MySqlConnectOptions, min: u32, max: u32, idle_minutes: u64) -> AppDataResult<MySqlPool> {
    Ok(MySqlPoolOptions::new()
        .min_connections(min)
        .max_connections(max.max(1))
        .idle_timeout(Duration::from_secs(idle_minutes * 60))
        .test_before_acquire(true)
        .acquire_timeout(Duration::from_secs(30))
        .connect_lazy_with(opts))
}

fn bind_query<'q>(
    mut q: sqlx::query::Query<'q, MySql, sqlx::mysql::MySqlArguments>,
    binds: &[Bind],
) -> sqlx::query::Query<'q, MySql, sqlx::mysql::MySqlArguments> {
    for b in binds {
        q = match b {
            Bind::Null => q.bind(None::<String>),
            Bind::Bool(v) => q.bind(*v),
            Bind::Int(v) => q.bind(*v),
            Bind::Double(v) => q.bind(*v),
            Bind::Float(v) => q.bind(*v as f64),
            Bind::Decimal(d) => q.bind(d.to_plain_string()),
            Bind::Text(s) => q.bind(s.clone()),
            Bind::DateTime(dt) => q.bind(*dt),
        };
    }
    q
}

/// A bound statement; the number of rows it changed.
pub async fn execute<'e, E: Executor<'e, Database = MySql>>(e: E, sql: &Sql) -> AppDataResult<u64> {
    let (text, binds) = sql.render();
    Ok(bind_query(sqlx::query(&text), &binds).execute(e).await?.rows_affected())
}

/// A bound statement on one pinned connection. Boxed with concrete lifetimes, so the
/// future is provably Send inside the engines' `async_trait` methods.
pub fn execute_on<'a>(conn: &'a mut sqlx::MySqlConnection, sql: &'a Sql) -> BoxFuture<'a, AppDataResult<u64>> {
    Box::pin(async move {
        let (text, binds) = sql.render();
        let q = bind_query(sqlx::query(&text), &binds);
        Ok(sqlx::Executor::execute(conn, q).await?.rows_affected())
    })
}

/// A bound SELECT on one pinned connection, decoded.
pub fn fetch_on<'a>(conn: &'a mut sqlx::MySqlConnection, sql: &'a Sql) -> BoxFuture<'a, AppDataResult<Vec<Document>>> {
    Box::pin(async move {
        let (text, binds) = sql.render();
        let q = bind_query(sqlx::query(&text), &binds);
        let rows = sqlx::Executor::fetch_all(conn, q).await?;
        rows.iter().map(decode_row).collect()
    })
}

/// A text statement on one pinned connection.
pub fn execute_raw_on<'a>(conn: &'a mut sqlx::MySqlConnection, sql: &'a str) -> BoxFuture<'a, AppDataResult<u64>> {
    Box::pin(async move { Ok(sqlx::Executor::execute(conn, sqlx::raw_sql(sql)).await?.rows_affected()) })
}

/// A bound SELECT, decoded.
pub async fn fetch<'e, E: Executor<'e, Database = MySql>>(e: E, sql: &Sql) -> AppDataResult<Vec<Document>> {
    let (text, binds) = sql.render();
    let rows = bind_query(sqlx::query(&text), &binds).fetch_all(e).await?;
    rows.iter().map(decode_row).collect()
}

/// Statements as text (DDL, the journal, information_schema reads); several may be
/// separated by semicolons, and all run on one connection.
pub async fn execute_raw<'e, 'q: 'e, E: Executor<'e, Database = MySql>>(e: E, sql: &'q str) -> AppDataResult<u64> {
    Ok(sqlx::raw_sql(sql).execute(e).await?.rows_affected())
}

pub async fn fetch_raw<'e, 'q: 'e, E: Executor<'e, Database = MySql>>(e: E, sql: &'q str) -> AppDataResult<Vec<Document>> {
    let rows = sqlx::raw_sql(sql).fetch_all(e).await?;
    rows.iter().map(decode_row).collect()
}

/// The first column of the first row as a count; zero when there is none.
pub fn first_number(rows: &[Document]) -> i64 {
    match rows.first().and_then(|r| r.values().next()) {
        Some(Value::Int(i)) => *i,
        Some(Value::Decimal(d)) => d.long_value(),
        Some(Value::Double(d)) => *d as i64,
        Some(Value::Bool(b)) => *b as i64,
        _ => 0,
    }
}

pub async fn count_raw<'e, 'q: 'e, E: Executor<'e, Database = MySql>>(e: E, sql: &'q str) -> AppDataResult<i64> {
    Ok(first_number(&fetch_raw(e, sql).await?))
}

pub async fn count<'e, E: Executor<'e, Database = MySql>>(e: E, sql: &Sql) -> AppDataResult<i64> {
    Ok(first_number(&fetch(e, sql).await?))
}

/// A row as the Java types R2DBC returns, keyed by column label.
pub fn decode_row(row: &MySqlRow) -> AppDataResult<Document> {
    let mut out = Document::new();
    for (i, col) in row.columns().iter().enumerate() {
        out.insert(col.name().to_string(), decode_value(row, i)?);
    }
    Ok(out)
}

fn decode_value(row: &MySqlRow, i: usize) -> AppDataResult<Value> {
    let raw = row.try_get_raw(i)?;
    if raw.is_null() {
        return Ok(Value::Null);
    }
    let type_name = raw.type_info().name().to_string();
    drop(raw);
    let v = match type_name.as_str() {
        "BOOLEAN" | "TINYINT" | "SMALLINT" | "INT" | "MEDIUMINT" | "BIGINT" | "YEAR" => {
            Value::Int(row.try_get_unchecked::<i64, _>(i)?)
        }
        t if t.ends_with("UNSIGNED") => {
            let u: u64 = row.try_get_unchecked(i)?;
            match i64::try_from(u) {
                Ok(x) => Value::Int(x),
                Err(_) => Value::Decimal(Decimal::from_u128(u as u128)),
            }
        }
        "FLOAT" => Value::Double(float_as_double(row.try_get_unchecked::<f32, _>(i)?)),
        "DOUBLE" => Value::Double(row.try_get_unchecked::<f64, _>(i)?),
        "DECIMAL" => {
            let s: String = row.try_get_unchecked(i)?;
            match Decimal::parse(s.trim()) {
                Some(d) => Value::Decimal(d),
                None => Value::String(s),
            }
        }
        "DATE" => match row.try_get_unchecked::<NaiveDate, _>(i) {
            Ok(d) => Value::LocalDate(d),
            Err(_) => Value::String(row.try_get_unchecked::<String, _>(i)?),
        },
        "DATETIME" | "TIMESTAMP" => match row.try_get_unchecked::<NaiveDateTime, _>(i) {
            Ok(d) => Value::LocalDateTime(d),
            Err(_) => Value::String(row.try_get_unchecked::<String, _>(i)?),
        },
        "TIME" => match row.try_get_unchecked::<NaiveTime, _>(i) {
            Ok(t) => Value::LocalTime(t),
            Err(_) => Value::String(row.try_get_unchecked::<String, _>(i)?),
        },
        // The driver calls a column binary from its BINARY flag, which MySQL also sets for a
        // `_bin` collation (and for JSON_UNQUOTE results). Text that is valid UTF-8 is read as
        // text, as R2DBC (which looks at the charset) reads it; real bytes are base64, as
        // Jackson writes a byte[].
        "BINARY" | "VARBINARY" | "TINYBLOB" | "BLOB" | "MEDIUMBLOB" | "LONGBLOB" => {
            let bytes: Vec<u8> = row.try_get_unchecked(i)?;
            match String::from_utf8(bytes) {
                Ok(s) => Value::String(s),
                Err(e) => Value::String(base64(e.as_bytes())),
            }
        }
        "GEOMETRY" | "BIT" => Value::String(base64(&row.try_get_unchecked::<Vec<u8>, _>(i)?)),
        _ => match row.try_get_unchecked::<String, _>(i) {
            Ok(s) => Value::String(s),
            Err(_) => Value::String(String::from_utf8_lossy(&row.try_get_unchecked::<Vec<u8>, _>(i)?).into_owned()),
        },
    };
    Ok(v)
}

/// A `byte[]` as Jackson writes it.
fn base64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

/// The SQLSTATE of a driver error, when it has one.
pub fn sql_state(e: &AppDataError) -> Option<String> {
    match e {
        // A duplicate key is answered as a 409 rather than the driver's error; its state stays 23000.
        e if e.is_duplicate_key() => Some("23000".to_string()),
        AppDataError::Internal(inner) => inner
            .downcast_ref::<sqlx::Error>()
            .and_then(|s| s.as_database_error())
            .and_then(|d| d.code().map(|c| c.to_string())),
        _ => None,
    }
}

/// An integrity-constraint violation (SQLSTATE class 23).
pub fn is_integrity_violation(e: &AppDataError) -> bool {
    sql_state(e).is_some_and(|s| s.starts_with("23"))
}

/// The error text, for matching and for the journal.
pub fn message(e: &AppDataError) -> String {
    match e {
        AppDataError::Internal(inner) => match inner.downcast_ref::<sqlx::Error>().and_then(|s| s.as_database_error()) {
            Some(d) => d.message().to_string(),
            None => inner.to_string(),
        },
        other => other.message(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_ignore_key_order() {
        let mut a = Document::new();
        a.insert("url".into(), Value::from("r2dbc:mysql://h/db"));
        a.insert("password".into(), Value::from("x"));
        let mut b = Document::new();
        b.insert("password".into(), Value::from("x"));
        b.insert("url".into(), Value::from("r2dbc:mysql://h/db"));
        let c1 = Connection { id: "1".into(), connection_details: Some(a), ..Default::default() };
        let c2 = Connection { id: "1".into(), connection_details: Some(b), ..Default::default() };
        assert_eq!(fingerprint(&c1), fingerprint(&c2));
        assert_eq!(fingerprint(&c1).len(), 32);
        assert_eq!(fingerprint(&Connection::default()), "none");
    }

    #[test]
    fn default_connection_is_all_or_nothing() {
        let default = Credentials {
            url: Some("r2dbc:mysql://localhost:3306/core".into()),
            username: Some("root".into()),
            password: Some("pw".into()),
            from_default: false,
        };
        let mut d = Document::new();
        d.insert("useDefaultConnection".into(), Value::Bool(true));
        d.insert("password".into(), Value::from("other"));
        let c = Connection { id: "1".into(), connection_details: Some(d), ..Default::default() };
        let creds = credentials(&c, &default);
        assert!(creds.from_default);
        assert_eq!(creds.password.as_deref(), Some("pw"));
        let none = credentials(&Connection { id: "2".into(), ..Default::default() }, &default);
        assert!(none.url.is_none());
        assert!(connect_options(&none).is_err());
    }

    #[test]
    fn base64_matches_java() {
        assert_eq!(base64(b"hello"), "aGVsbG8=");
        assert_eq!(base64(b""), "");
        assert_eq!(base64(&[0xff]), "/w==");
    }
}
