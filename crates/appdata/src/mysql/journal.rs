//! `MySQLMigrationJournal`: the record of how far a migration got, written before the
//! first statement, in the tenant schema it describes. The statements are text (they run
//! beside DDL), with every free-text value escaped.

use super::migration_planner::Phase;

pub const TABLE: &str = "storage_migration";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationState {
    Planned,
    Running,
    Applied,
    Failed,
    NeedsAttention,
    Abandoned,
}

impl MigrationState {
    pub fn name(&self) -> &'static str {
        match self {
            MigrationState::Planned => "PLANNED",
            MigrationState::Running => "RUNNING",
            MigrationState::Applied => "APPLIED",
            MigrationState::Failed => "FAILED",
            MigrationState::NeedsAttention => "NEEDS_ATTENTION",
            MigrationState::Abandoned => "ABANDONED",
        }
    }

    pub fn from_name(s: &str) -> Option<MigrationState> {
        Some(match s {
            "PLANNED" => MigrationState::Planned,
            "RUNNING" => MigrationState::Running,
            "APPLIED" => MigrationState::Applied,
            "FAILED" => MigrationState::Failed,
            "NEEDS_ATTENTION" => MigrationState::NeedsAttention,
            "ABANDONED" => MigrationState::Abandoned,
            _ => return None,
        })
    }
}

/// The journal's answer to "how far did this get".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalEntry {
    pub id: String,
    pub state: MigrationState,
    pub statement_index: i32,
    pub attempt: i32,
    pub applied_count: i32,
    pub total: i32,
}

impl JournalEntry {
    pub fn is_complete(&self) -> bool {
        self.state == MigrationState::Applied
    }

    pub fn is_resumable(&self) -> bool {
        matches!(self.state, MigrationState::Failed | MigrationState::Running)
    }
}

pub fn create_table(db: &str) -> String {
    format!(
        "CREATE TABLE IF NOT EXISTS `{db}`.`{TABLE}` (`id` CHAR(26) NOT NULL,`storage_name` VARCHAR(255) NOT NULL,`table_name` VARCHAR(255) NOT NULL,`from_version` INT NULL,`to_version` INT NOT NULL,`surface` VARCHAR(16) NOT NULL,`shape` CHAR(32) NOT NULL,`phase` VARCHAR(20) NULL,`statement_index` INT NOT NULL DEFAULT 0,`total_statements` INT NOT NULL,`applied_count` INT NOT NULL DEFAULT 0,`attempt` INT NOT NULL DEFAULT 1,`state` VARCHAR(20) NOT NULL,`started_at` DATETIME(3) NULL,`resumed_at` DATETIME(3) NULL,`finished_at` DATETIME(3) NULL,`error` TEXT NULL,`applied_by` VARCHAR(255) NULL,`plan` MEDIUMTEXT NULL,`claimed_by` VARCHAR(255) NULL,`claimed_at` DATETIME(3) NULL,`active_key` VARCHAR(320) GENERATED ALWAYS AS (IF(`state` IN ('PLANNED', 'RUNNING'), CONCAT(`storage_name`, ':', `shape`, ':', `surface`), NULL)) STORED,PRIMARY KEY (`id`),UNIQUE KEY `uk_active_migration` (`active_key`),KEY `idx_storage_state` (`storage_name`, `state`),KEY `idx_storage_shape` (`storage_name`, `shape`),KEY `idx_state_claim` (`state`, `claimed_at`))"
    )
}

/// Columns an older journal table is missing, each guarded by its own existence check.
pub fn upgrades(db: &str) -> Vec<String> {
    vec![
        add_column(db, "plan", "MEDIUMTEXT NULL"),
        add_column(db, "claimed_by", "VARCHAR(255) NULL"),
        add_column(db, "claimed_at", "DATETIME(3) NULL"),
        add_column(db, "shape", "CHAR(32) NULL"),
        add_column(db, "applied_count", "INT NOT NULL DEFAULT 0"),
        add_column(db, "attempt", "INT NOT NULL DEFAULT 1"),
        add_column(db, "resumed_at", "DATETIME(3) NULL"),
        add_column(
            db,
            "active_key",
            "VARCHAR(320) GENERATED ALWAYS AS (IF(`state` IN ('PLANNED', 'RUNNING'), CONCAT(`storage_name`, ':', `shape`, ':', `surface`), NULL)) STORED",
        ),
        add_unique_index(db, "uk_active_migration", "active_key"),
    ]
}

fn add_unique_index(db: &str, index: &str, column: &str) -> String {
    format!(
        "SET @s = (SELECT IF(COUNT(*) > 0, 'SELECT 1', 'ALTER TABLE `{db}`.`{TABLE}` ADD UNIQUE KEY `{index}` (`{column}`)') FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = '{db}' AND TABLE_NAME = '{TABLE}' AND INDEX_NAME = '{index}'); PREPARE stmt FROM @s; EXECUTE stmt; DEALLOCATE PREPARE stmt;"
    )
}

fn add_column(db: &str, column: &str, definition: &str) -> String {
    format!(
        "SET @s = (SELECT IF(COUNT(*) > 0, 'SELECT 1', 'ALTER TABLE `{db}`.`{TABLE}` ADD COLUMN `{column}` {definition}') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = '{db}' AND TABLE_NAME = '{TABLE}' AND COLUMN_NAME = '{column}'); PREPARE stmt FROM @s; EXECUTE stmt; DEALLOCATE PREPARE stmt;"
    )
}

pub fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "''")
}

/// Where this exact migration got to, newest first.
pub fn find_at(db: &str, storage_name: &str, shape: &str) -> String {
    find(db, &format!("`storage_name` = '{}' AND `shape` = '{}'", escape(storage_name), escape(shape)))
}

/// The most recent migration of this storage, whatever its shape.
pub fn find_latest(db: &str, storage_name: &str) -> String {
    find(db, &format!("`storage_name` = '{}'", escape(storage_name)))
}

fn find(db: &str, where_: &str) -> String {
    format!(
        "SELECT `id`, `state`, `statement_index`, `attempt`, `applied_count`, `total_statements` FROM `{db}`.`{TABLE}` WHERE {where_} ORDER BY `started_at` DESC, `id` DESC LIMIT 1"
    )
}

/// Migrations to resolve by hand first: failed or running at another shape, or anything
/// a human marked NEEDS_ATTENTION.
pub fn blocking_count(db: &str, storage_name: &str, shape: &str) -> String {
    format!(
        "SELECT COUNT(*) FROM `{db}`.`{TABLE}` WHERE `storage_name` = '{}' AND ((`state` IN ('FAILED', 'RUNNING') AND `shape` <> '{}') OR `state` = 'NEEDS_ATTENTION')",
        escape(storage_name),
        escape(shape)
    )
}

#[allow(clippy::too_many_arguments)]
pub fn insert(
    db: &str,
    id: &str,
    storage_name: &str,
    table: &str,
    from_version: Option<i32>,
    to_version: i32,
    shape: &str,
    surface: &str,
    total_statements: usize,
    applied_by: Option<&str>,
    plan_json: &str,
    node: Option<&str>,
) -> String {
    format!(
        "INSERT INTO `{db}`.`{TABLE}` (`id`, `storage_name`, `table_name`, `from_version`, `to_version`, `shape`, `surface`, `statement_index`, `total_statements`, `applied_count`, `attempt`, `state`, `started_at`, `applied_by`, `plan`, `claimed_by`, `claimed_at`) VALUES ('{id}', '{}', '{}', {}, {to_version}, '{}', '{surface}', 0, {total_statements}, 0, 1, 'PLANNED', NOW(3), {}, '{}', {}, NOW(3))",
        escape(storage_name),
        escape(table),
        from_version.map(|v| v.to_string()).unwrap_or_else(|| "NULL".into()),
        escape(shape),
        applied_by.map(|a| format!("'{}'", escape(a))).unwrap_or_else(|| "NULL".into()),
        escape(plan_json),
        node.map(|n| format!("'{}'", escape(n))).unwrap_or_else(|| "NULL".into()),
    )
}

pub fn reopen(db: &str, id: &str, total_statements: usize, applied_by: Option<&str>) -> String {
    format!(
        "UPDATE `{db}`.`{TABLE}` SET `state` = 'RUNNING', `attempt` = `attempt` + 1, `resumed_at` = NOW(3), `finished_at` = NULL, `error` = NULL, `total_statements` = {total_statements}{} WHERE `id` = '{id}'",
        applied_by.map(|a| format!(", `applied_by` = '{}'", escape(a))).unwrap_or_default()
    )
}

/// Progress, which doubles as the heartbeat.
pub fn progress(db: &str, id: &str, state: MigrationState, index: usize, phase: Option<Phase>, applied_count: i32) -> String {
    format!(
        "UPDATE `{db}`.`{TABLE}` SET `state` = '{}', `statement_index` = {index}, `applied_count` = {applied_count}, `claimed_at` = NOW(3), `phase` = {} WHERE `id` = '{id}'",
        state.name(),
        phase.map(|p| format!("'{}'", p.name())).unwrap_or_else(|| "NULL".into())
    )
}

/// Take ownership of an interrupted row, if nobody else has.
pub fn claim(db: &str, id: &str, node: &str, stale_after_seconds: i32) -> String {
    format!(
        "UPDATE `{db}`.`{TABLE}` SET `claimed_by` = '{}', `claimed_at` = NOW(3) WHERE `id` = '{id}' AND `state` = 'RUNNING' AND (`claimed_at` IS NULL OR `claimed_at` < NOW(3) - INTERVAL {stale_after_seconds} SECOND)",
        escape(node)
    )
}

/// Rows nobody is driving any more.
pub fn unfinished(db: &str, stale_after_seconds: i32) -> String {
    format!(
        "SELECT `id`, `storage_name`, `table_name`, `shape`, `surface`, `statement_index`, `applied_count`, `attempt`, `total_statements`, `plan` FROM `{db}`.`{TABLE}` WHERE `state` IN ('PLANNED', 'RUNNING') AND (`claimed_at` IS NULL OR `claimed_at` < NOW(3) - INTERVAL {stale_after_seconds} SECOND) ORDER BY `claimed_at` ASC"
    )
}

pub fn schemas_with_journal() -> String {
    format!("SELECT TABLE_SCHEMA FROM information_schema.TABLES WHERE TABLE_NAME = '{TABLE}' ORDER BY TABLE_SCHEMA")
}

// ------------------------------------------------------------------ issues

/// What a storage publish could not do for one tenant, beside the journal. Kept apart because
/// the journal's FAILED and NEEDS_ATTENTION rows hold back later publishes of the storage, and
/// these issues must not: nothing in the tenant's table changed when they were written.
pub const ISSUE_TABLE: &str = "storage_migration_issue";

pub fn create_issue_table(db: &str) -> String {
    format!(
        "CREATE TABLE IF NOT EXISTS `{db}`.`{ISSUE_TABLE}` (`id` CHAR(26) NOT NULL,`storage_name` VARCHAR(255) NOT NULL,`table_name` VARCHAR(255) NOT NULL,`surface` VARCHAR(16) NULL,`kind` VARCHAR(32) NOT NULL,`shape` CHAR(32) NULL,`to_version` INT NULL,`offending` BIGINT NOT NULL DEFAULT 0,`detail` TEXT NULL,`applied_by` VARCHAR(255) NULL,`node` VARCHAR(255) NULL,`created_at` DATETIME(3) NOT NULL,PRIMARY KEY (`id`),KEY `idx_storage_created` (`storage_name`, `created_at`),KEY `idx_kind_created` (`kind`, `created_at`))"
    )
}

#[allow(clippy::too_many_arguments)]
pub fn insert_issue(
    db: &str,
    id: &str,
    storage_name: &str,
    table: &str,
    surface: Option<&str>,
    kind: &str,
    shape: Option<&str>,
    to_version: Option<i32>,
    offending: i64,
    detail: &str,
    applied_by: Option<&str>,
    node: &str,
) -> String {
    let text = |v: Option<&str>| v.map(|s| format!("'{}'", escape(s))).unwrap_or_else(|| "NULL".into());
    format!(
        "INSERT INTO `{db}`.`{ISSUE_TABLE}` (`id`, `storage_name`, `table_name`, `surface`, `kind`, `shape`, `to_version`, `offending`, `detail`, `applied_by`, `node`, `created_at`) VALUES ('{id}', '{}', '{}', {}, '{}', {}, {}, {offending}, '{}', {}, '{}', NOW(3))",
        escape(storage_name),
        escape(table),
        text(surface),
        escape(kind),
        text(shape.filter(|s| !s.is_empty())),
        to_version.map(|v| v.to_string()).unwrap_or_else(|| "NULL".into()),
        escape(detail),
        text(applied_by),
        escape(node),
    )
}

pub fn finish(db: &str, id: &str, state: MigrationState, error: Option<&str>, applied_count: i32) -> String {
    format!(
        "UPDATE `{db}`.`{TABLE}` SET `state` = '{}', `finished_at` = NOW(3), `applied_count` = {applied_count}, `error` = {} WHERE `id` = '{id}'",
        state.name(),
        error.map(|e| format!("'{}'", escape(e))).unwrap_or_else(|| "NULL".into())
    )
}
