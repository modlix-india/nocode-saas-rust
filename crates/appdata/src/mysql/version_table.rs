//! `MySQLVersionTable`: the history table behind a versioned or audited storage, with the
//! Mongo version collection's field names.

use sqlx::MySqlPool;

use super::db::{execute, fetch};
use super::sql::{self, Bind, FieldOps, Select, Sql};
use super::type_mapper::{ID_COLUMN, ID_TYPE};
use crate::error::AppDataResult;
use crate::retention::VersionRetention;
use crate::value::Value;

pub const SUFFIX: &str = "_version";
pub const OBJECT_ID: &str = "objectId";
pub const MESSAGE: &str = "message";
pub const CREATED_AT: &str = "createdAt";
pub const OPERATION: &str = "operation";
pub const CREATED_BY: &str = "createdBy";
pub const OBJECT: &str = "object";

/// Everything except the snapshot.
pub const AUDIT_FIELDS: [&str; 6] = [ID_COLUMN, OBJECT_ID, MESSAGE, CREATED_AT, OPERATION, CREATED_BY];

pub fn name_for(table: &str) -> String {
    format!("{table}{SUFFIX}")
}

pub fn create_table(db: &str, table: &str) -> String {
    format!(
        "CREATE TABLE IF NOT EXISTS `{db}`.`{}` (`{ID_COLUMN}` {ID_TYPE} NOT NULL,`{OBJECT_ID}` {ID_TYPE} NOT NULL,`{MESSAGE}` TEXT NULL,`{CREATED_AT}` DATETIME(3) NOT NULL,`{OPERATION}` VARCHAR(16) NOT NULL,`{CREATED_BY}` BIGINT NULL,`{OBJECT}` JSON NULL,PRIMARY KEY (`{ID_COLUMN}`),KEY `idx_object_history` (`{OBJECT_ID}`, `{CREATED_AT}` DESC))",
        name_for(table)
    )
}

/// `MySQLVersionTrim.trim`: one object's history cut to the retention, a row surviving only
/// by satisfying both bounds. The count bound reads the timestamp of the Nth newest and
/// deletes what is strictly older (MySQL takes no LIMIT inside an IN subquery), so rows
/// sharing that exact timestamp all survive.
pub async fn trim(pool: &MySqlPool, table: &Sql, object_id: &str, retention: VersionRetention) -> AppDataResult<()> {
    if retention.keeps_everything() {
        return Ok(());
    }
    let created_at = Sql::name(&[CREATED_AT]);
    let by_object = Sql::name(&[OBJECT_ID]).equal(Sql::param(Bind::Text(object_id.into())));
    if retention.trims_by_age() {
        let cond = by_object.clone().and_also(created_at.cmp("<", Sql::param(Bind::DateTime(retention.cutoff()))));
        execute(pool, &sql::delete(table, &cond)).await?;
    }
    if retention.trims_by_count() {
        let select = Select::fields(vec![created_at.clone()], table.clone())
            .filter(by_object.clone())
            .order(vec![created_at.desc()])
            .page(1, (retention.count - 1) as i64);
        let rows = fetch(pool, &select.to_sql()).await?;
        if let Some(Value::LocalDateTime(kept)) = rows.first().and_then(|r| r.values().next()).cloned() {
            let cond = by_object.and_also(created_at.cmp("<", Sql::param(Bind::DateTime(kept))));
            execute(pool, &sql::delete(table, &cond)).await?;
        }
    }
    Ok(())
}
