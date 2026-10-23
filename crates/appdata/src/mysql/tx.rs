//! One MySQL transaction around a run of writes (`CoreServices.Storage.Batch`, `UpdateIf`).
//!
//! The scope is task-local. Inside [`scope`], every bound statement the engine sends to a pool
//! runs on the one connection the transaction was opened on, the first time a statement needs
//! it. The policy layer above the engine (validation, relations, triggers, version rows) runs
//! unchanged, and everything it writes commits or rolls back as one unit. All the writes in a
//! scope go through one appData connection (one pool); a write through a second pool is
//! refused rather than silently left outside the transaction.
//!
//! Text statements (`execute_raw`, `fetch_raw`: CREATE TABLE, ALTER, information_schema reads)
//! keep using the pool, because MySQL commits the open transaction before any DDL sent on the
//! same connection.

use std::collections::HashSet;
use std::future::Future;
use std::sync::{Arc, OnceLock};

use futures::future::BoxFuture;
use sqlx::mysql::MySqlConnectOptions;
use sqlx::{MySql, MySqlConnection, MySqlPool, Transaction};
use tokio::sync::Mutex;

use super::db;
use super::sql::Sql;
use crate::error::{AppDataError, AppDataResult};
use crate::value::Document;

/// SQLSTATE of a deadlock (and of a serialization failure): InnoDB has already rolled the
/// whole transaction back, so whatever the caller does next must not commit.
const DEADLOCK_STATE: &str = "40001";

struct Open {
    opts: Arc<MySqlConnectOptions>,
    tx: Transaction<'static, MySql>,
}

#[derive(Default)]
struct Scope {
    open: Mutex<Option<Open>>,
    /// Set when the server rolled the transaction back on its own (a deadlock).
    poisoned: std::sync::Mutex<Option<String>>,
}

tokio::task_local! {
    static SCOPE: Arc<Scope>;
}

/// Whether the current task is inside a transaction scope.
pub fn active() -> bool {
    SCOPE.try_with(|_| ()).is_ok()
}

/// Runs `op` inside one transaction: committed when `op` succeeds, rolled back when it fails.
/// A scope inside a scope joins the outer one (a trigger's writes belong to the batch that
/// caused them). No statement, no transaction: a read-only `op` never opens one.
pub async fn scope<T, E, F>(op: F) -> Result<T, E>
where
    F: Future<Output = Result<T, E>>,
    E: From<AppDataError>,
{
    if active() {
        return op.await;
    }
    let s = Arc::new(Scope::default());
    let result = SCOPE.scope(s.clone(), op).await;
    let open = s.open.lock().await.take();
    let poisoned = s.poisoned.lock().map(|p| p.clone()).unwrap_or(None);
    match (result, open) {
        (Ok(v), Some(o)) => {
            if let Some(reason) = poisoned {
                let _ = o.tx.rollback().await;
                return Err(AppDataError::internal(format!("the transaction was rolled back by the server: {reason}")).into());
            }
            o.tx.commit().await.map_err(AppDataError::from)?;
            Ok(v)
        }
        (Ok(v), None) => Ok(v),
        (Err(e), Some(o)) => {
            let _ = o.tx.rollback().await;
            Err(e)
        }
        (Err(e), None) => Err(e),
    }
}

impl Scope {
    /// The transaction's connection, opened on `pool` the first time.
    async fn connection<'g>(open: &'g mut Option<Open>, pool: &MySqlPool) -> AppDataResult<&'g mut MySqlConnection> {
        let opts = pool.connect_options();
        match open {
            Some(o) if Arc::ptr_eq(&o.opts, &opts) => {}
            Some(_) => {
                return Err(AppDataError::illegal_argument(
                    "A batch writes through one appData connection; this storage uses another one.",
                ))
            }
            None => {
                let tx = pool.begin().await?;
                *open = Some(Open { opts, tx });
            }
        }
        Ok(&mut *open.as_mut().expect("opened above").tx)
    }

    fn note<T>(&self, r: &AppDataResult<T>) {
        if let Err(e) = r {
            if db::sql_state(e).as_deref() == Some(DEADLOCK_STATE) {
                if let Ok(mut p) = self.poisoned.lock() {
                    p.get_or_insert_with(|| db::message(e));
                }
            }
        }
    }
}

/// Runs `f` on the transaction's connection inside a scope, else on a pooled connection
/// held for the whole of `f` (for statements that must share a session, such as
/// `LAST_INSERT_ID()`).
pub async fn on_connection<R, F>(pool: &MySqlPool, f: F) -> AppDataResult<R>
where
    F: for<'c> FnOnce(&'c mut MySqlConnection) -> BoxFuture<'c, AppDataResult<R>>,
{
    match SCOPE.try_with(Arc::clone) {
        Ok(scope) => {
            let mut open = scope.open.lock().await;
            let conn = Scope::connection(&mut open, pool).await?;
            let r = f(conn).await;
            scope.note(&r);
            r
        }
        Err(_) => {
            let mut conn = pool.acquire().await?;
            f(&mut conn).await
        }
    }
}

/// [`db::execute`], on the scope's transaction when there is one.
pub async fn execute(pool: &MySqlPool, sql: &Sql) -> AppDataResult<u64> {
    if !active() {
        return db::execute(pool, sql).await;
    }
    let sql = sql.clone();
    on_connection(pool, move |c| Box::pin(async move { db::execute_on(c, &sql).await })).await
}

/// [`db::fetch`], on the scope's transaction when there is one, so a batch reads its own writes.
pub async fn fetch(pool: &MySqlPool, sql: &Sql) -> AppDataResult<Vec<Document>> {
    if !active() {
        return db::fetch(pool, sql).await;
    }
    let sql = sql.clone();
    on_connection(pool, move |c| Box::pin(async move { db::fetch_on(c, &sql).await })).await
}

/// [`db::count`], on the scope's transaction when there is one.
pub async fn count(pool: &MySqlPool, sql: &Sql) -> AppDataResult<i64> {
    Ok(db::first_number(&fetch(pool, sql).await?))
}

/// The tenant schemas whose sequence table is known to exist.
fn sequence_tables() -> &'static std::sync::Mutex<HashSet<String>> {
    static TABLES: OnceLock<std::sync::Mutex<HashSet<String>>> = OnceLock::new();
    TABLES.get_or_init(Default::default)
}

/// The per-schema table that holds named counters.
pub const SEQUENCE_TABLE: &str = "_mlx_sequence";

/// The next value of the counter `name` in `db_name`: `start` the first time, then one more
/// each call. One statement, atomic under concurrency; inside a scope the counter row stays
/// locked until the batch commits, so numbers are handed out in commit order without gaps.
/// The counter table of a tenant schema, created once per process (DDL: always on the pool).
pub async fn ensure_sequence_table(pool: &MySqlPool, db_name: &str) -> AppDataResult<()> {
    let known = sequence_tables().lock().map(|t| t.contains(db_name)).unwrap_or(false);
    if !known {
        db::execute_raw(
            pool,
            &format!(
                "CREATE TABLE IF NOT EXISTS `{db_name}`.`{SEQUENCE_TABLE}` (`NAME` VARCHAR(255) NOT NULL PRIMARY KEY, `VALUE` BIGINT NOT NULL)"
            ),
        )
        .await?;
        if let Ok(mut t) = sequence_tables().lock() {
            t.insert(db_name.to_string());
        }
    }
    Ok(())
}

pub async fn next_sequence(pool: &MySqlPool, db_name: &str, name: &str, start: i64) -> AppDataResult<i64> {
    ensure_sequence_table(pool, db_name).await?;
    match bump(pool, db_name, name, start).await {
        // The schema was dropped and made again since this process created the table (a draft
        // database cleared, a tenant reset): forget it, create it again, try once more.
        Err(e) if db::sql_state(&e).as_deref() == Some("42S02") => {
            if let Ok(mut t) = sequence_tables().lock() {
                t.remove(db_name);
            }
            ensure_sequence_table(pool, db_name).await?;
            bump(pool, db_name, name, start).await
        }
        other => other,
    }
}

async fn bump(pool: &MySqlPool, db_name: &str, name: &str, start: i64) -> AppDataResult<i64> {
    let upsert = Sql::template(
        &format!(
            "INSERT INTO `{db_name}`.`{SEQUENCE_TABLE}` (`NAME`, `VALUE`) VALUES ({{0}}, LAST_INSERT_ID({{1}})) \
             ON DUPLICATE KEY UPDATE `VALUE` = LAST_INSERT_ID(`VALUE` + 1)"
        ),
        &[Sql::param(super::sql::Bind::Text(name.to_string())), Sql::param(super::sql::Bind::Int(start))],
    );
    let last = Sql::raw("SELECT LAST_INSERT_ID()");
    on_connection(pool, move |c| {
        Box::pin(async move {
            db::execute_on(c, &upsert).await?;
            Ok(db::first_number(&db::fetch_on(c, &last).await?))
        })
    })
    .await
}
