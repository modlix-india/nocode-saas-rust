//! `MySQLTableInspector`: a tenant's table as it actually is, read from
//! information_schema. The queries are text, as in Java.

use super::migration_planner::NEW_SUFFIX;

pub const DRAFT_DB_SUFFIX: &str = "_draft";

pub fn columns_sql(db: &str, table: &str) -> String {
    format!(
        "SELECT COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, COLLATION_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = '{db}' AND TABLE_NAME = '{table}' ORDER BY COLUMN_NAME"
    )
}

pub fn table_exists_sql(db: &str, table: &str) -> String {
    format!("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = '{db}' AND TABLE_NAME = '{table}'")
}

pub fn tenants_with_table_sql(app_code: &str, table: &str) -> String {
    format!(
        "SELECT TABLE_SCHEMA FROM information_schema.TABLES WHERE TABLE_NAME = '{table}' AND (TABLE_SCHEMA LIKE '%\\_{app_code}' OR TABLE_SCHEMA LIKE '%\\_{app_code}{DRAFT_DB_SUFFIX}') ORDER BY TABLE_SCHEMA"
    )
}

pub fn tenant_schemas_sql(app_code: &str) -> String {
    format!(
        "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME LIKE '%\\_{app_code}' OR SCHEMA_NAME LIKE '%\\_{app_code}{DRAFT_DB_SUFFIX}' ORDER BY SCHEMA_NAME"
    )
}

/// A temporary column left by an interrupted migration: `<name>__v<digits>`.
pub fn is_migration_temp(column: &str) -> bool {
    match column.rfind(NEW_SUFFIX) {
        None => false,
        Some(i) => {
            let tail = &column[i + NEW_SUFFIX.len()..];
            !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit())
        }
    }
}
