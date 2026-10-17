//! The Java MySQL migration, journal, sweeper and drift integration tests, ported against
//! the local MySQL in scratch schemas named `RUSTTEST_rtm_*` that each test creates and
//! drops (even when it fails).
//!
//! The commons-core classes drive the Java planner, runner, journal and sweeper on a raw
//! connection; the ports drive `appdata::mysql::{migration_planner, migration, journal,
//! drift}` the same way. Java's sweeper tests own their server, so `sweep` there only
//! ever sees the test's schema; on the shared local server the ports sweep their own
//! schema alone (`migration::sweep_schemas`). `MySQLDriftReconcilerIntegrationTest`
//! goes through the service, so its port goes through `MySqlAppDataService`.
//!
//! Run with: cargo test -p appdata --test live_mysql_migrations -- --ignored --test-threads=1

mod support;

use std::sync::Arc;

use appdata::engine::AppDataEngine;
use appdata::model::*;
use appdata::mysql::column::MySqlColumn;
use appdata::mysql::drift;
use appdata::mysql::journal::{self, MigrationState};
use appdata::mysql::migration::{self, MigrationOutcome};
use appdata::mysql::migration_planner::{self, MigrationStep, Phase};
use appdata::mysql::table_planner::{self, Kind, SchemaChange};
use appdata::mysql::MySqlAppDataService;
use sqlx::MySqlPool;
use support::*;

fn schema_of(app: &str) -> String {
    format!("{CLIENT}_{app}")
}

async fn scratch_pool() -> MySqlPool {
    let e = mysql_engine(Arc::new(Storages::default()));
    let p = pool(&e).await;
    wait_for_headroom(&p).await;
    p
}

async fn number(p: &MySqlPool, sql: &str) -> i64 {
    appdata::mysql::db::count_raw(p, sql).await.unwrap()
}

async fn column_type_of(p: &MySqlPool, db: &str, table: &str, column: &str) -> String {
    scalar(p, &format!("SELECT COLUMN_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = '{db}' AND TABLE_NAME = '{table}' AND COLUMN_NAME = '{column}'")).await
}

/// A table with a string `amount` column, seeded with the given values.
async fn make_table(p: &MySqlPool, db: &str, table: &str, amounts: &[Option<&str>]) {
    exec(p, &format!("DROP TABLE IF EXISTS `{db}`.`{table}`")).await;
    exec(p, &format!("CREATE TABLE `{db}`.`{table}` (`_id` CHAR(26) NOT NULL, `amount` VARCHAR(40) NULL, PRIMARY KEY (`_id`))")).await;
    for (i, a) in amounts.iter().enumerate() {
        let value = a.map(|a| format!("'{a}'")).unwrap_or_else(|| "NULL".into());
        exec(p, &format!("INSERT INTO `{db}`.`{table}` VALUES ('{i:026}', {value})")).await;
    }
}

fn narrowing(db: &str, table: &str) -> Vec<MigrationStep> {
    migration_planner::plan(db, table, 7, &[SchemaChange::new(Kind::Narrowing, "amount", Some("VARCHAR(40)"), Some("DOUBLE"), "retype")]).unwrap()
}

/// The shape a plan to `amount DOUBLE` heads for, which the journal keys on.
fn shape_double() -> String {
    table_planner::shape_of(&[MySqlColumn::new("amount", "DOUBLE", true).unwrap()])
}

/// Each statement of the plan the way the runner runs it, skipping guarded ones.
async fn run_steps<'a>(p: &MySqlPool, steps: impl IntoIterator<Item = &'a MigrationStep>) {
    for s in steps {
        let Some(sql) = &s.sql else { continue };
        if let Some(pre) = &s.precondition {
            if number(p, pre).await == 0 {
                continue;
            }
        }
        exec(p, sql).await;
    }
}

// ------------------------------------------------------------------ MySQLMigrationConcurrencyIntegrationTest

mod mysql_migration_concurrency_integration_test {
    use super::*;

    const APP: &str = "rtm_conc";

    fn insert_running(db: &str, id: &str, storage: &str, shape: &str, surface: &str) -> String {
        journal::insert(db, id, storage, &format!("{storage}_tbl"), Some(1), 2, shape, surface, 3, Some("tester"), "[]", Some(&format!("node-{id}")))
    }

    async fn active(p: &MySqlPool, db: &str) -> i64 {
        number(p, &format!("SELECT COUNT(*) FROM `{db}`.`{}` WHERE `storage_name` = 'orders' AND `state` IN ('PLANNED', 'RUNNING')", journal::TABLE)).await
    }

    async fn fresh_journal(p: &MySqlPool, db: &str) {
        exec(p, &format!("DROP TABLE IF EXISTS `{db}`.`{}`", journal::TABLE)).await;
        migration::ensure_journal(p, db).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "needs the local MySQL"]
    async fn one_active_migration_per_storage_shape_and_surface() {
        let p = scratch_pool().await;
        drop_schemas(&p, &[CLIENT], APP).await;
        guarded(
            async {
                let db = schema_of(APP);
                create_schema(&p, &db).await;

                // onlyOneActiveRow: two inserts at once, on two connections.
                fresh_journal(&p, &db).await;
                let (a, b) = (insert_running(&db, &format!("{:026}", 0), "orders", "shapeA", "LIVE"), insert_running(&db, &format!("{:026}", 1), "orders", "shapeA", "LIVE"));
                let (ra, rb) = tokio::join!(appdata::mysql::db::execute_raw(&p, &a), appdata::mysql::db::execute_raw(&p, &b));
                assert_eq!([ra.is_ok(), rb.is_ok()].iter().filter(|ok| **ok).count(), 1, "exactly one insert should succeed");
                assert_eq!(active(&p, &db).await, 1);

                // differentShapeIsAllowed
                fresh_journal(&p, &db).await;
                exec(&p, &insert_running(&db, &format!("{:026}", 1), "orders", "shapeA", "LIVE")).await;
                exec(&p, &insert_running(&db, &format!("{:026}", 2), "orders", "shapeB", "LIVE")).await;
                assert_eq!(active(&p, &db).await, 2);

                // differentSurfaceIsAllowed
                fresh_journal(&p, &db).await;
                exec(&p, &insert_running(&db, &format!("{:026}", 3), "orders", "shapeA", "LIVE")).await;
                exec(&p, &insert_running(&db, &format!("{:026}", 4), "orders", "shapeA", "DRAFT")).await;
                assert_eq!(active(&p, &db).await, 2);

                // finishedRowReleasesTheKey
                fresh_journal(&p, &db).await;
                let first = format!("{:026}", 5);
                exec(&p, &insert_running(&db, &first, "orders", "shapeA", "LIVE")).await;
                exec(&p, &format!("UPDATE `{db}`.`{}` SET `state` = 'APPLIED' WHERE `id` = '{first}'", journal::TABLE)).await;
                exec(&p, &insert_running(&db, &format!("{:026}", 6), "orders", "shapeA", "LIVE")).await;
                assert_eq!(active(&p, &db).await, 1);

                // lostRaceIsRecognised
                fresh_journal(&p, &db).await;
                exec(&p, &insert_running(&db, &format!("{:026}", 7), "orders", "shapeA", "LIVE")).await;
                let duplicate = appdata::mysql::db::execute_raw(&p, &insert_running(&db, &format!("{:026}", 8), "orders", "shapeA", "LIVE")).await.unwrap_err();
                assert!(migration::already_running(&duplicate), "{duplicate:?}");
            },
            drop_schemas(&p, &[CLIENT], APP),
        )
        .await;
    }
}

// ------------------------------------------------------------------ MySQLMigrationIntegrationTest

mod mysql_migration_integration_test {
    use super::*;

    const APP: &str = "rtm_mig";

    #[tokio::test]
    #[ignore = "needs the local MySQL"]
    async fn plans_run_against_real_tables() {
        let p = scratch_pool().await;
        drop_schemas(&p, &[CLIENT], APP).await;
        guarded(
            async {
                let db = schema_of(APP);
                create_schema(&p, &db).await;
                let first_check = |plan: &[MigrationStep]| plan.iter().find_map(|s| s.data_check.clone()).expect("a pre-flight");

                // happyPath
                make_table(&p, &db, "m_clean", &[Some("10.5"), Some("20"), Some("30.25")]).await;
                let plan = narrowing(&db, "m_clean");
                assert_eq!(number(&p, &first_check(&plan)).await, 0, "clean data should fail nothing");
                run_steps(&p, &plan).await;
                assert_eq!(column_type_of(&p, &db, "m_clean", "amount").await, "double");
                assert_eq!(number(&p, &format!("SELECT COUNT(*) FROM `{db}`.`m_clean` WHERE `amount` IS NOT NULL")).await, 3);
                assert_eq!(number(&p, &format!("SELECT COUNT(*) FROM `{db}`.`m_clean` WHERE `amount` = 20")).await, 1);

                // dirtyDataIsCaught
                make_table(&p, &db, "m_dirty", &[Some("10.5"), Some("not-a-number"), Some("30")]).await;
                let plan = narrowing(&db, "m_dirty");
                assert_eq!(number(&p, &first_check(&plan)).await, 1, "the junk row must be counted before anything runs");
                assert_eq!(column_type_of(&p, &db, "m_dirty", "amount").await, "varchar(40)", "the pre-flight must not have touched the table");

                // failureLeavesDataIntact: the DDL run anyway, up to the contract.
                make_table(&p, &db, "m_intact", &[Some("10.5"), Some("junk"), Some("30")]).await;
                let plan = narrowing(&db, "m_intact");
                run_steps(&p, plan.iter().take_while(|s| s.phase != Phase::Contract)).await;
                assert_eq!(column_type_of(&p, &db, "m_intact", "amount").await, "varchar(40)", "the original column must be untouched");
                assert_eq!(number(&p, &format!("SELECT COUNT(*) FROM `{db}`.`m_intact` WHERE `amount` IS NOT NULL")).await, 3);
                assert_eq!(number(&p, &format!("SELECT COUNT(*) FROM `{db}`.`m_intact` WHERE `amount` = 'junk'")).await, 1);

                // planIsRerunnable
                make_table(&p, &db, "m_rerun", &[Some("1"), Some("2")]).await;
                run_steps(&p, &narrowing(&db, "m_rerun")).await;
                assert_eq!(column_type_of(&p, &db, "m_rerun", "amount").await, "double");
                run_steps(&p, &narrowing(&db, "m_rerun")).await;
                assert_eq!(column_type_of(&p, &db, "m_rerun", "amount").await, "double");
                assert_eq!(number(&p, &format!("SELECT COUNT(*) FROM `{db}`.`m_rerun`")).await, 2);

                // partialPlanResumes: stop after the expand, as a crash would.
                make_table(&p, &db, "m_resume", &[Some("5"), Some("6")]).await;
                let plan = narrowing(&db, "m_resume");
                let expand_end = plan.iter().position(|s| s.phase == Phase::Expand && s.sql.is_some()).unwrap();
                run_steps(&p, &plan[..=expand_end]).await;
                assert_eq!(column_type_of(&p, &db, "m_resume", "amount").await, "varchar(40)", "half way: original still there");
                run_steps(&p, &narrowing(&db, "m_resume")).await;
                assert_eq!(column_type_of(&p, &db, "m_resume", "amount").await, "double");
                assert_eq!(number(&p, &format!("SELECT COUNT(*) FROM `{db}`.`m_resume` WHERE `amount` = 5")).await, 1);

                // dropIsSnapshotted
                make_table(&p, &db, "m_drop", &[Some("1"), Some("2")]).await;
                let plan = migration_planner::plan(&db, "m_drop", 7, &[SchemaChange::new(Kind::Destructive, "amount", Some("VARCHAR(40)"), None, "drop")]).unwrap();
                run_steps(&p, &plan).await;
                assert_eq!(number(&p, &format!("SELECT COUNT(*) FROM `{db}`.`m_drop__bak_7`")).await, 2, "the snapshot holds the rows");
                assert_eq!(column_type_of(&p, &db, "m_drop", "amount").await, "", "the column is gone from the live table");
                assert_eq!(column_type_of(&p, &db, "m_drop__bak_7", "amount").await, "varchar(40)", "but recoverable from the snapshot");
            },
            drop_schemas(&p, &[CLIENT], APP),
        )
        .await;
    }
}

// ------------------------------------------------------------------ MySQLMigrationRunnerIntegrationTest

mod mysql_migration_runner_integration_test {
    use super::*;

    const APP: &str = "rtm_run";

    async fn run(p: &MySqlPool, db: &str, storage: &str, table: &str, plan: &[MigrationStep], shape: &str) -> MigrationOutcome {
        migration::run(p, db, storage, table, Some(6), 7, shape, "LIVE", plan, Some("kiran")).await.unwrap()
    }

    async fn clear_journal(p: &MySqlPool, db: &str, storage: &str) {
        migration::ensure_journal(p, db).await.unwrap();
        exec(p, &format!("DELETE FROM `{db}`.`{}` WHERE `storage_name` = '{storage}'", journal::TABLE)).await;
    }

    fn journal_of(db: &str, column: &str, storage: &str) -> String {
        format!("SELECT `{column}` FROM `{db}`.`{}` WHERE `storage_name` = '{storage}'", journal::TABLE)
    }

    fn rows_of(db: &str, storage: &str) -> String {
        format!("SELECT COUNT(*) FROM `{db}`.`{}` WHERE `storage_name` = '{storage}'", journal::TABLE)
    }

    #[tokio::test]
    #[ignore = "needs the local MySQL"]
    async fn the_runner_journals_every_outcome() {
        let p = scratch_pool().await;
        drop_schemas(&p, &[CLIENT], APP).await;
        guarded(
            async {
                let db = schema_of(APP);
                create_schema(&p, &db).await;
                let shape = shape_double();

                // successIsJournalled
                clear_journal(&p, &db, "s_ok").await;
                make_table(&p, &db, "r_ok", &[Some("1"), Some("2.5")]).await;
                let out = run(&p, &db, "s_ok", "r_ok", &narrowing(&db, "r_ok"), &shape).await;
                assert!(out.is_success(), "{:?}", out.error);
                assert_eq!(column_type_of(&p, &db, "r_ok", "amount").await, "double");
                assert_eq!(number(&p, &format!("SELECT COUNT(*) FROM `{db}`.`{}` WHERE `storage_name` = 's_ok' AND `state` = 'APPLIED' AND `finished_at` IS NOT NULL", journal::TABLE)).await, 1);

                // blockedIsJournalled
                clear_journal(&p, &db, "s_bad").await;
                make_table(&p, &db, "r_bad", &[Some("1"), Some("junk")]).await;
                let out = run(&p, &db, "s_bad", "r_bad", &narrowing(&db, "r_bad"), &shape).await;
                assert_eq!(out.state, MigrationState::Failed);
                assert_eq!(out.offending, 1, "one junk row");
                assert!(out.blocked_by.is_some());
                assert_eq!(column_type_of(&p, &db, "r_bad", "amount").await, "varchar(40)");
                assert!(scalar(&p, &journal_of(&db, "error", "s_bad")).await.contains("would not survive"));

                // failClosedAcrossShapes
                clear_journal(&p, &db, "s_closed").await;
                make_table(&p, &db, "r_closed", &[Some("1"), Some("junk")]).await;
                assert_eq!(run(&p, &db, "s_closed", "r_closed", &narrowing(&db, "r_closed"), &shape).await.state, MigrationState::Failed);
                let to_int = migration_planner::plan(&db, "r_closed", 8, &[SchemaChange::new(Kind::Narrowing, "amount", Some("VARCHAR(40)"), Some("INT"), "retype")]).unwrap();
                let int_shape = table_planner::shape_of(&[MySqlColumn::new("amount", "INT", true).unwrap()]);
                let later = migration::run(&p, &db, "s_closed", "r_closed", Some(7), 8, &int_shape, "LIVE", &to_int, Some("kiran")).await.unwrap();
                assert_eq!(later.state, MigrationState::NeedsAttention);
                assert!(later.error.as_deref().unwrap_or("").contains("unresolved"), "{:?}", later.error);
                assert_eq!(column_type_of(&p, &db, "r_closed", "amount").await, "varchar(40)");

                // sameVersionRetriesAfterItsOwnFailure
                clear_journal(&p, &db, "s_retry").await;
                make_table(&p, &db, "r_retry", &[Some("1"), Some("junk")]).await;
                assert_eq!(run(&p, &db, "s_retry", "r_retry", &narrowing(&db, "r_retry"), &shape).await.state, MigrationState::Failed);
                exec(&p, &format!("UPDATE `{db}`.`r_retry` SET `amount` = '2' WHERE `amount` = 'junk'")).await;
                let second = run(&p, &db, "s_retry", "r_retry", &narrowing(&db, "r_retry"), &shape).await;
                assert!(second.is_success(), "{:?}", second.error);
                assert!(second.was_resumed(), "the retry should report that it continued an earlier attempt");
                assert_eq!(column_type_of(&p, &db, "r_retry", "amount").await, "double");

                // retryKeepsOneRow
                clear_journal(&p, &db, "s_one_row").await;
                make_table(&p, &db, "r_one_row", &[Some("1"), Some("junk")]).await;
                run(&p, &db, "s_one_row", "r_one_row", &narrowing(&db, "r_one_row"), &shape).await;
                exec(&p, &format!("UPDATE `{db}`.`r_one_row` SET `amount` = '5' WHERE `amount` = 'junk'")).await;
                run(&p, &db, "s_one_row", "r_one_row", &narrowing(&db, "r_one_row"), &shape).await;
                assert_eq!(number(&p, &rows_of(&db, "s_one_row")).await, 1, "two attempts at one migration are one migration");
                assert_eq!(number(&p, &journal_of(&db, "attempt", "s_one_row")).await, 2);
                assert_eq!(scalar(&p, &journal_of(&db, "state", "s_one_row")).await, "APPLIED");
                assert!(!rows(&p, &journal_of(&db, "resumed_at", "s_one_row")).await[0]["resumed_at"].is_null());

                // resumesFromInsideContract: a row written by hand, as a crash leaves it.
                clear_journal(&p, &db, "s_contract").await;
                make_table(&p, &db, "r_contract", &[Some("9")]).await;
                let plan = narrowing(&db, "r_contract");
                let stop_after = plan.iter().position(|s| s.phase == Phase::Contract && s.sql.is_some()).unwrap();
                for s in &plan[..=stop_after] {
                    if let Some(sql) = &s.sql {
                        exec(&p, sql).await;
                    }
                }
                exec(&p, &journal::insert(&db, "01JCRASHCRASHCRASHCRASH01", "s_contract", "r_contract", Some(6), 7, &shape, "LIVE", plan.len(), Some("kiran"), &migration_planner::write_plan(&plan), Some("dead-node"))).await;
                exec(&p, &format!("UPDATE `{db}`.`{}` SET `state` = 'RUNNING', `statement_index` = {stop_after} WHERE `id` = '01JCRASHCRASHCRASHCRASH01'", journal::TABLE)).await;
                assert_eq!(column_type_of(&p, &db, "r_contract", "amount").await, "", "amount is gone mid-contract");
                let out = run(&p, &db, "s_contract", "r_contract", &plan, &shape).await;
                assert!(out.is_success(), "{:?}", out.error);
                assert_eq!(out.resumed_from, stop_after as i32);
                assert_eq!(column_type_of(&p, &db, "r_contract", "amount").await, "double");
                assert_eq!(number(&p, &format!("SELECT COUNT(*) FROM `{db}`.`r_contract` WHERE `amount` = 9")).await, 1);

                // appliedCountAccumulates
                clear_journal(&p, &db, "s_count").await;
                make_table(&p, &db, "r_count", &[Some("1"), Some("junk")]).await;
                run(&p, &db, "s_count", "r_count", &narrowing(&db, "r_count"), &shape).await;
                let after_failure = number(&p, &journal_of(&db, "applied_count", "s_count")).await;
                exec(&p, &format!("UPDATE `{db}`.`r_count` SET `amount` = '6' WHERE `amount` = 'junk'")).await;
                run(&p, &db, "s_count", "r_count", &narrowing(&db, "r_count"), &shape).await;
                let after_success = number(&p, &journal_of(&db, "applied_count", "s_count")).await;
                assert!(after_success > after_failure, "{after_failure} then {after_success}");

                // resolvingUnblocks
                clear_journal(&p, &db, "s_fixed").await;
                make_table(&p, &db, "r_fixed", &[Some("1"), Some("junk")]).await;
                run(&p, &db, "s_fixed", "r_fixed", &narrowing(&db, "r_fixed"), &shape).await;
                exec(&p, &format!("UPDATE `{db}`.`r_fixed` SET `amount` = '2' WHERE `amount` = 'junk'")).await;
                exec(&p, &format!("UPDATE `{db}`.`{}` SET `state` = 'ABANDONED' WHERE `storage_name` = 's_fixed'", journal::TABLE)).await;
                assert!(run(&p, &db, "s_fixed", "r_fixed", &narrowing(&db, "r_fixed"), &shape).await.is_success());
                assert_eq!(column_type_of(&p, &db, "r_fixed", "amount").await, "double");

                // completedPlanIsNotRepeated
                clear_journal(&p, &db, "s_again").await;
                make_table(&p, &db, "r_again", &[Some("3")]).await;
                let first = run(&p, &db, "s_again", "r_again", &narrowing(&db, "r_again"), &shape).await;
                assert!(first.applied > 0);
                let second = run(&p, &db, "s_again", "r_again", &narrowing(&db, "r_again"), &shape).await;
                assert!(second.is_success(), "{:?}", second.error);
                assert_eq!(second.applied, 0, "a finished plan must not execute anything again");
                assert_eq!(number(&p, &rows_of(&db, "s_again")).await, 1, "no second journal row");
                assert_eq!(number(&p, &format!("SELECT COUNT(*) FROM `{db}`.`r_again` WHERE `amount` = 3")).await, 1);

                // partialPlanResumes: up to the expand, with no journal row at all.
                clear_journal(&p, &db, "s_resume").await;
                make_table(&p, &db, "r_resume", &[Some("8")]).await;
                let plan = narrowing(&db, "r_resume");
                let expand = plan.iter().position(|s| s.phase == Phase::Expand && s.sql.is_some()).unwrap();
                for s in &plan[..=expand] {
                    if let Some(sql) = &s.sql {
                        exec(&p, sql).await;
                    }
                }
                assert_eq!(column_type_of(&p, &db, "r_resume", "amount").await, "varchar(40)");
                let out = run(&p, &db, "s_resume", "r_resume", &narrowing(&db, "r_resume"), &shape).await;
                assert!(out.is_success(), "{:?}", out.error);
                assert!(out.skipped > 0, "the already-applied expand should be skipped");
                assert_eq!(column_type_of(&p, &db, "r_resume", "amount").await, "double");
                assert_eq!(number(&p, &format!("SELECT COUNT(*) FROM `{db}`.`r_resume` WHERE `amount` = 8")).await, 1);

                // shapeChangeWithoutVersionChange
                clear_journal(&p, &db, "s_schema").await;
                make_table(&p, &db, "r_schema", &[Some("4")]).await;
                assert!(run(&p, &db, "s_schema", "r_schema", &narrowing(&db, "r_schema"), &shape).await.is_success());
                let add_column = migration_planner::plan(&db, "r_schema", 7, &[SchemaChange::new(Kind::Widening, "currency", None, Some("VARCHAR(3)"), "new field from the schema")]).unwrap();
                let new_shape = table_planner::shape_of(&[MySqlColumn::new("amount", "DOUBLE", true).unwrap(), MySqlColumn::new("currency", "VARCHAR(3)", true).unwrap()]);
                let out = run(&p, &db, "s_schema", "r_schema", &add_column, &new_shape).await;
                assert!(out.is_success(), "{:?}", out.error);
                assert!(out.applied > 0, "the shape changed, so there is work to do");
                assert_eq!(column_type_of(&p, &db, "r_schema", "currency").await, "varchar(3)");
                assert_eq!(number(&p, &rows_of(&db, "s_schema")).await, 2, "two shapes, two rows");

                // sameShapeStillSkips
                clear_journal(&p, &db, "s_same").await;
                make_table(&p, &db, "r_same", &[Some("4")]).await;
                run(&p, &db, "s_same", "r_same", &narrowing(&db, "r_same"), &shape).await;
                let second = run(&p, &db, "s_same", "r_same", &narrowing(&db, "r_same"), &shape).await;
                assert!(second.is_success(), "{:?}", second.error);
                assert_eq!(second.applied, 0);
                assert_eq!(number(&p, &rows_of(&db, "s_same")).await, 1);

                // journalIsWrittenAhead
                clear_journal(&p, &db, "s_track").await;
                make_table(&p, &db, "r_track", &[Some("4")]).await;
                run(&p, &db, "s_track", "r_track", &narrowing(&db, "r_track"), &shape).await;
                assert_eq!(number(&p, &journal_of(&db, "total_statements", "s_track")).await, narrowing(&db, "r_track").len() as i64, "the plan size is recorded up front");
                assert!(!rows(&p, &journal_of(&db, "started_at", "s_track")).await[0]["started_at"].is_null());
                assert_eq!(scalar(&p, &journal_of(&db, "applied_by", "s_track")).await, "kiran");

                // emptyPlanWritesNothing
                clear_journal(&p, &db, "s_empty").await;
                let out = migration::run(&p, &db, "s_empty", "r_empty", Some(1), 2, &shape, "LIVE", &[], Some("k")).await.unwrap();
                assert!(out.is_success());
                assert_eq!(number(&p, &rows_of(&db, "s_empty")).await, 0);

                // escapesFreeText
                clear_journal(&p, &db, "s_quote").await;
                make_table(&p, &db, "r_quote", &[Some("9")]).await;
                let out = migration::run(&p, &db, "s_quote", "r_quote", Some(1), 7, &shape, "LIVE", &narrowing(&db, "r_quote"), Some("o'brien")).await.unwrap();
                assert!(out.is_success(), "{:?}", out.error);
                assert_eq!(scalar(&p, &journal_of(&db, "applied_by", "s_quote")).await, "o'brien");
            },
            drop_schemas(&p, &[CLIENT], APP),
        )
        .await;
    }
}

// ------------------------------------------------------------------ MySQLMigrationSweeperIntegrationTest

mod mysql_migration_sweeper_integration_test {
    use super::*;

    const APP: &str = "rtm_sweep";
    const OTHER: &str = "rtm_sweep_other";
    const TABLE: &str = "ledger";
    const STORAGE: &str = "ledger";

    fn plan(db: &str) -> Vec<MigrationStep> {
        narrowing(db, TABLE)
    }

    async fn fresh_table(p: &MySqlPool, db: &str) {
        exec(p, &format!("DROP TABLE IF EXISTS `{db}`.`{TABLE}`")).await;
        exec(p, &format!("DROP TABLE IF EXISTS `{db}`.`{TABLE}__bak_7`")).await;
        exec(p, &format!("CREATE TABLE `{db}`.`{TABLE}` (`_id` CHAR(26) NOT NULL, `amount` VARCHAR(40) NULL, PRIMARY KEY (`_id`))")).await;
        exec(p, &format!("INSERT INTO `{db}`.`{TABLE}` VALUES ('00000000000000000000000001', '42')")).await;
        exec(p, &format!("DROP TABLE IF EXISTS `{db}`.`{}`", journal::TABLE)).await;
        migration::ensure_journal(p, db).await.unwrap();
    }

    async fn amount_type(p: &MySqlPool, db: &str) -> String {
        column_type_of(p, db, TABLE, "amount").await
    }

    /// The plan run up to and including `phase`, then left as a killed process leaves
    /// it: a RUNNING row pointing at the next step, claimed `stale_seconds` ago.
    async fn interrupt_after(p: &MySqlPool, db: &str, phase: Phase, stale_seconds: i32) -> String {
        let plan = plan(db);
        let mut stopped_at = 0;
        for (i, s) in plan.iter().enumerate() {
            if let Some(sql) = &s.sql {
                exec(p, sql).await;
            }
            if s.phase == phase {
                stopped_at = i + 1;
                break;
            }
        }
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
        let id = format!("01SWEEP{:019}", nanos);
        exec(p, &journal::insert(db, &id, STORAGE, TABLE, Some(6), 7, &shape_double(), "LIVE", plan.len(), Some("kiran"), &migration_planner::write_plan(&plan), Some("dead-node"))).await;
        exec(p, &format!("UPDATE `{db}`.`{}` SET `state` = 'RUNNING', `statement_index` = {stopped_at}, `claimed_at` = NOW(3) - INTERVAL {stale_seconds} SECOND WHERE `id` = '{id}'", journal::TABLE)).await;
        id
    }

    async fn sweep(p: &MySqlPool, db: &str) -> migration::RecoveryReport {
        migration::sweep_schemas(p, &[db.to_string()], 60).await.unwrap()
    }

    #[tokio::test]
    #[ignore = "needs the local MySQL"]
    async fn the_sweep_finishes_what_a_crash_left() {
        let p = scratch_pool().await;
        drop_schemas(&p, &[CLIENT], APP).await;
        drop_schemas(&p, &[CLIENT], OTHER).await;
        guarded(
            async {
                let db = schema_of(APP);
                create_schema(&p, &db).await;

                // sweepFinishesIt
                fresh_table(&p, &db).await;
                interrupt_after(&p, &db, Phase::Expand, 600).await;
                assert_eq!(amount_type(&p, &db).await, "varchar(40)", "left part way");
                let report = sweep(&p, &db).await;
                assert_eq!((report.found, report.claimed, report.resumed), (1, 1, 1), "{}", report.summary());
                assert_eq!(amount_type(&p, &db).await, "double");
                assert_eq!(number(&p, &format!("SELECT COUNT(*) FROM `{db}`.`{TABLE}` WHERE `amount` = 42")).await, 1);
                assert_eq!(scalar(&p, &format!("SELECT `state` FROM `{db}`.`{}`", journal::TABLE)).await, "APPLIED");

                // sweepRecoversMidContract
                fresh_table(&p, &db).await;
                let id = interrupt_after(&p, &db, Phase::Contract, 600).await;
                assert_eq!(amount_type(&p, &db).await, "");
                let rows = migration::interrupted(&p, &db, 60).await.unwrap();
                assert_eq!(rows.len(), 1);
                assert!(rows[0].is_mid_contract(), "{}", rows[0].describe());
                let report = sweep(&p, &db).await;
                assert_eq!(report.resumed, 1, "{}", report.summary());
                assert_eq!(amount_type(&p, &db).await, "double");
                assert_eq!(number(&p, &format!("SELECT COUNT(*) FROM `{db}`.`{TABLE}` WHERE `amount` = 42")).await, 1);
                assert_eq!(scalar(&p, &format!("SELECT `state` FROM `{db}`.`{}` WHERE `id` = '{id}'", journal::TABLE)).await, "APPLIED");

                // freshClaimIsNotStolen
                fresh_table(&p, &db).await;
                interrupt_after(&p, &db, Phase::Expand, 0).await;
                let report = sweep(&p, &db).await;
                assert_eq!(report.found, 0, "{}", report.summary());
                assert_eq!(amount_type(&p, &db).await, "varchar(40)", "untouched");

                // onlyOneNodeWins: the guard is in the WHERE clause.
                fresh_table(&p, &db).await;
                interrupt_after(&p, &db, Phase::Expand, 600).await;
                let rows = migration::interrupted(&p, &db, 60).await.unwrap();
                assert_eq!(rows.len(), 1);
                let claim = journal::claim(&db, &rows[0].id, migration::node(), 60);
                let first = appdata::mysql::db::execute_raw(&p, &claim).await.unwrap();
                let second = appdata::mysql::db::execute_raw(&p, &claim).await.unwrap();
                assert_eq!((first, second), (1, 0));

                // failedIsNotSwept
                fresh_table(&p, &db).await;
                let id = interrupt_after(&p, &db, Phase::Expand, 600).await;
                exec(&p, &format!("UPDATE `{db}`.`{}` SET `state` = 'FAILED' WHERE `id` = '{id}'", journal::TABLE)).await;
                assert_eq!(sweep(&p, &db).await.found, 0);

                // appliedIsNotSwept
                fresh_table(&p, &db).await;
                let id = interrupt_after(&p, &db, Phase::Expand, 600).await;
                exec(&p, &format!("UPDATE `{db}`.`{}` SET `state` = 'APPLIED' WHERE `id` = '{id}'", journal::TABLE)).await;
                assert_eq!(sweep(&p, &db).await.found, 0);

                // unplayableIsReported
                fresh_table(&p, &db).await;
                let id = interrupt_after(&p, &db, Phase::Expand, 600).await;
                exec(&p, &format!("UPDATE `{db}`.`{}` SET `plan` = NULL WHERE `id` = '{id}'", journal::TABLE)).await;
                let report = sweep(&p, &db).await;
                assert_eq!((report.found, report.claimed, report.unplayable.len()), (1, 0, 1), "{}", report.summary());
                assert_eq!(amount_type(&p, &db).await, "varchar(40)", "and nothing was attempted");

                // discoversSchemas: read only, so it may see every journal on the server.
                fresh_table(&p, &db).await;
                let other = schema_of(OTHER);
                create_schema(&p, &other).await;
                migration::ensure_journal(&p, &other).await.unwrap();
                let schemas = migration::schemas(&p).await.unwrap();
                assert!(schemas.contains(&db) && schemas.contains(&other), "{schemas:?}");
                exec(&p, &format!("DROP DATABASE IF EXISTS `{other}`")).await;

                // quietWhenNothingToDo
                fresh_table(&p, &db).await;
                let report = sweep(&p, &db).await;
                assert!(report.is_quiet());
                assert_eq!(report.summary(), "no interrupted migrations");

                // journalUpgradesItself: the journal as its first version shipped.
                exec(&p, &format!("DROP TABLE IF EXISTS `{db}`.`{}`", journal::TABLE)).await;
                exec(&p, &format!("CREATE TABLE `{db}`.`{}` (`id` CHAR(26) NOT NULL, `storage_name` VARCHAR(255) NOT NULL, `table_name` VARCHAR(255) NOT NULL, `from_version` INT NULL, `to_version` INT NOT NULL, `surface` VARCHAR(16) NOT NULL, `phase` VARCHAR(20) NULL, `statement_index` INT NOT NULL DEFAULT 0, `total_statements` INT NOT NULL, `state` VARCHAR(20) NOT NULL, `started_at` DATETIME(3) NULL, `finished_at` DATETIME(3) NULL, `error` TEXT NULL, `applied_by` VARCHAR(255) NULL, PRIMARY KEY (`id`))", journal::TABLE)).await;
                migration::ensure_journal(&p, &db).await.unwrap();
                let has = |column: &'static str| {
                    let (p, db) = (&p, &db);
                    async move { number(p, &format!("SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = '{db}' AND TABLE_NAME = '{}' AND COLUMN_NAME = '{column}'", journal::TABLE)).await }
                };
                for column in ["plan", "claimed_by", "claimed_at", "shape", "applied_count", "attempt", "resumed_at"] {
                    assert_eq!(has(column).await, 1, "{column} should have been added");
                }
                migration::ensure_journal(&p, &db).await.unwrap();
                assert_eq!(has("plan").await, 1);
                exec(&p, &journal::insert(&db, "01UPGRADE000000000000001", STORAGE, TABLE, Some(6), 7, &shape_double(), "LIVE", 1, Some("kiran"), &migration_planner::write_plan(&plan(&db)), Some("node"))).await;
                assert_eq!(number(&p, &format!("SELECT COUNT(*) FROM `{db}`.`{}`", journal::TABLE)).await, 1);

                // planRoundTrips
                let original = plan(&db);
                let back = migration_planner::read_plan(Some(&migration_planner::write_plan(&original)));
                assert_eq!(original, back, "a plan that does not come back exactly is not a plan");

                // damagedPlan
                assert!(migration_planner::read_plan(None).is_empty());
                assert!(migration_planner::read_plan(Some("")).is_empty());
                assert!(migration_planner::read_plan(Some("{not json")).is_empty());
            },
            async {
                drop_schemas(&p, &[CLIENT], APP).await;
                drop_schemas(&p, &[CLIENT], OTHER).await;
            },
        )
        .await;
    }
}

// ------------------------------------------------------------------ MySQLDriftIntegrationTest

mod mysql_drift_integration_test {
    use super::*;

    const APP: &str = "rtm_drift";
    const TABLE: &str = "thing";

    /// The declared shape, without `_id`: the table planner adds the key itself.
    fn definition() -> Vec<MySqlColumn> {
        vec![MySqlColumn::new("title", "VARCHAR(100)", true).unwrap(), MySqlColumn::new("qty", "INT", true).unwrap()]
    }

    async fn fresh_table(p: &MySqlPool, db: &str) {
        exec(p, &format!("DROP TABLE IF EXISTS `{db}`.`{TABLE}`")).await;
        exec(p, &table_planner::create_table(&format!("{db}`.`{TABLE}"), &definition())).await;
    }

    async fn live(p: &MySqlPool, db: &str) -> Vec<MySqlColumn> {
        migration::columns(p, db, TABLE).await.unwrap()
    }

    async fn report(p: &MySqlPool, db: &str) -> drift::Report {
        drift::of(db, TABLE, true, &live(p, db).await, &definition(), vec![], vec![])
    }

    async fn run(p: &MySqlPool, statements: Vec<String>) {
        for s in statements {
            exec(p, &s).await;
        }
    }

    #[tokio::test]
    #[ignore = "needs the local MySQL"]
    async fn drift_against_a_real_table() {
        let p = scratch_pool().await;
        drop_schemas(&p, &[CLIENT], APP).await;
        guarded(
            async {
                let db = schema_of(APP);
                create_schema(&p, &db).await;

                // freshTableIsClean
                fresh_table(&p, &db).await;
                let r = report(&p, &db).await;
                assert!(r.clean(), "unexpected drift: {}", r.summary());

                // extraColumnNeedsApproval
                fresh_table(&p, &db).await;
                exec(&p, &format!("ALTER TABLE `{db}`.`{TABLE}` ADD COLUMN `rogue` VARCHAR(10)")).await;
                let before = report(&p, &db).await;
                assert!(!before.clean());
                assert!(before.needs_approval());
                run(&p, drift::repair_statements(&before, false)).await;
                assert!(live(&p, &db).await.iter().any(|c| c.name() == "rogue"), "an unapproved repair must not drop a column that may hold data");
                run(&p, drift::repair_statements(&report(&p, &db).await, true)).await;
                assert!(!live(&p, &db).await.iter().any(|c| c.name() == "rogue"));
                assert!(report(&p, &db).await.clean());

                // missingColumnIsRepairedUnapproved
                fresh_table(&p, &db).await;
                exec(&p, &format!("ALTER TABLE `{db}`.`{TABLE}` DROP COLUMN `qty`")).await;
                let before = report(&p, &db).await;
                assert!(!before.clean());
                assert!(!before.needs_approval(), "adding a missing column loses nothing");
                run(&p, drift::repair_statements(&before, false)).await;
                assert!(live(&p, &db).await.iter().any(|c| c.name() == "qty"));
                assert!(report(&p, &db).await.clean());

                // missingTableIsReported
                fresh_table(&p, &db).await;
                exec(&p, &format!("DROP TABLE `{db}`.`{TABLE}`")).await;
                assert!(!migration::table_exists(&p, &db, TABLE).await.unwrap());
                let r = drift::of(&db, TABLE, false, &[], &definition(), vec![], vec![]);
                assert!(r.needs_approval());
                assert!(drift::repair_statements(&r, false).is_empty());
            },
            drop_schemas(&p, &[CLIENT], APP),
        )
        .await;
    }
}

// ------------------------------------------------------------------ MySQLDriftReconcilerIntegrationTest

/// The engine half of `MySQLDriftReconcilerIntegrationTest` (core): drift and repair
/// across the app's tenant schemas, through `MySqlAppDataService`. Java resets the
/// tenant before every test; so does this, with a fresh engine each time so no table
/// flag survives the drop.
mod mysql_drift_reconciler_integration_test {
    use super::*;

    const APP: &str = "rtm_books";
    const TABLE: &str = "rtm_books_books";

    fn books() -> Storage {
        storage(APP, "books", r#"{"version":1,"schema":{"type":"OBJECT","properties":{"title":{"type":"STRING","maxLength":120},"isbn":{"type":"STRING","maxLength":20}}}}"#)
    }

    /// Every schema of the app dropped, the storage resolvable, and one book written,
    /// which builds the table.
    async fn reset(p: &MySqlPool) -> MySqlAppDataService {
        drop_schemas(p, &[CLIENT], APP).await;
        let storages = Arc::new(Storages::default());
        storages.put(&books()).await;
        let e = mysql_engine(storages);
        e.create(&cx(), CLIENT, Some(&conn().await), &books(), data(r#"{"title":"Dune","isbn":"1"}"#)).await.unwrap();
        e
    }

    async fn names(p: &MySqlPool, sql: &str) -> Vec<String> {
        rows(p, sql).await.iter().map(|r| r.values().next().unwrap().java_string()).collect()
    }

    async fn column_names(p: &MySqlPool, db: &str) -> Vec<String> {
        names(p, &format!("SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = '{db}' AND TABLE_NAME = '{TABLE}' ORDER BY COLUMN_NAME")).await
    }

    async fn index_names(p: &MySqlPool, db: &str) -> Vec<String> {
        names(p, &format!("SELECT DISTINCT INDEX_NAME FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = '{db}' AND TABLE_NAME = '{TABLE}' ORDER BY INDEX_NAME")).await
    }

    async fn report(e: &MySqlAppDataService) -> drift::Report {
        let mut reports = e.drift(Some(&conn().await), APP, &books()).await.unwrap();
        assert_eq!(reports.len(), 1, "one schema holds this app, so there is exactly one report");
        reports.remove(0)
    }

    async fn repair(e: &MySqlAppDataService, approved: bool) -> drift::DriftRepair {
        let mut out = e.repair_drift(Some(&conn().await), APP, &books(), approved).await.unwrap();
        assert_eq!(out.len(), 1);
        out.remove(0)
    }

    #[tokio::test]
    #[ignore = "needs the local MySQL"]
    async fn drift_and_repair_through_the_engine() {
        let p = scratch_pool().await;
        drop_schemas(&p, &[CLIENT], APP).await;
        guarded(
            async {
                let db = schema_of(APP);

                // Reporting.cleanAfterCreate
                let e = reset(&p).await;
                let r = report(&e).await;
                assert!(r.clean(), "{} / columns {:?}", r.summary(), r.columns);
                assert!(!r.needs_approval());

                // Reporting.missingColumnFound
                let e = reset(&p).await;
                exec(&p, &format!("ALTER TABLE `{db}`.`{TABLE}` DROP COLUMN `isbn`")).await;
                let r = report(&e).await;
                assert!(!r.clean());
                assert_eq!(r.columns.len(), 1);
                assert_eq!(r.columns[0].column, "isbn");
                assert!(!r.needs_approval(), "adding a missing column is additive");

                // Reporting.extraColumnNeedsApproval
                let e = reset(&p).await;
                exec(&p, &format!("ALTER TABLE `{db}`.`{TABLE}` ADD COLUMN `rogue` VARCHAR(10)")).await;
                let r = report(&e).await;
                assert!(!r.clean());
                assert!(r.needs_approval());
                assert!(!r.dangerous().is_empty(), "dropping a column that may hold data is dangerous");

                // Repairing.unapprovedRepairAdds
                let e = reset(&p).await;
                exec(&p, &format!("ALTER TABLE `{db}`.`{TABLE}` DROP COLUMN `isbn`")).await;
                assert!(!column_names(&p, &db).await.contains(&"isbn".to_string()));
                let out = repair(&e, false).await;
                assert_eq!(out.applied.len(), 1, "the ADD should have run: {out:?}");
                assert!(out.failed.is_empty());
                assert!(column_names(&p, &db).await.contains(&"isbn".to_string()));
                assert!(report(&e).await.clean(), "and the table is back in sync");

                // Repairing.unapprovedRepairWithholds
                let e = reset(&p).await;
                exec(&p, &format!("ALTER TABLE `{db}`.`{TABLE}` ADD COLUMN `rogue` VARCHAR(10)")).await;
                let out = repair(&e, false).await;
                assert!(out.applied.is_empty());
                assert_eq!(out.withheld.len(), 1);
                assert!(out.withheld[0].contains("DROP COLUMN `rogue`"), "{:?}", out.withheld);
                assert!(!out.complete());
                assert!(column_names(&p, &db).await.contains(&"rogue".to_string()), "and the column is still there");

                // Repairing.approvedRepairDrops
                let e = reset(&p).await;
                exec(&p, &format!("ALTER TABLE `{db}`.`{TABLE}` ADD COLUMN `rogue` VARCHAR(10)")).await;
                let out = repair(&e, true).await;
                assert!(out.withheld.is_empty());
                assert!(out.failed.is_empty(), "{:?}", out.failed);
                assert!(!column_names(&p, &db).await.contains(&"rogue".to_string()));
                assert!(report(&e).await.clean());

                // Repairing.handMadeIndex
                let e = reset(&p).await;
                exec(&p, &format!("CREATE INDEX `by_hand` ON `{db}`.`{TABLE}` (`title`)")).await;
                assert!(index_names(&p, &db).await.contains(&"by_hand".to_string()));
                let r = report(&e).await;
                assert!(!r.clean());
                assert!(!r.drops().is_empty(), "the stale index is a drop: {:?}", r.index_statements);
                assert!(r.needs_approval());
                assert!(repair(&e, false).await.applied.is_empty());
                assert!(index_names(&p, &db).await.contains(&"by_hand".to_string()), "an unapproved repair leaves it alone");
                repair(&e, true).await;
                assert!(!index_names(&p, &db).await.contains(&"by_hand".to_string()));

                // MissingTable.missingTableIsFound
                let e = reset(&p).await;
                let draft_db = format!("{db}_draft");
                create_schema(&p, &draft_db).await;
                exec(&p, &format!("CREATE TABLE IF NOT EXISTS `{draft_db}`.`something_else` (`_id` CHAR(26) PRIMARY KEY)")).await;
                let all = e.drift(Some(&conn().await), APP, &books()).await.unwrap();
                let missing = all.iter().find(|r| r.db.ends_with("_draft")).unwrap_or_else(|| panic!("the draft schema should be reported: {all:?}"));
                assert!(!missing.table_exists);
                assert!(!missing.clean());
                assert!(missing.needs_approval(), "a table that is not there is not something to fix unasked");
                assert!(missing.summary().contains("MISSING"), "{}", missing.summary());

                // MissingTable.missingTableIsNotSilentlyComplete
                let repaired = e.repair_drift(Some(&conn().await), APP, &books(), true).await.unwrap();
                let draft = repaired.iter().find(|r| r.db.ends_with("_draft")).expect("the draft schema");
                assert!(draft.table_missing);
                assert!(!draft.complete(), "a tenant with no table is not a clean run");
                assert!(draft.applied.is_empty());
            },
            drop_schemas(&p, &[CLIENT], APP),
        )
        .await;
    }
}
