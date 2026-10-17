//! The Java fan-out tests: one storage across many tenants and both surfaces, ported
//! against the local MySQL in scratch schemas named `RUSTTEST_*_rtf_*` that each test
//! creates and drops (even when it fails).
//!
//! `MySQLFanOutIntegrationTest` (commons-core) drives `MySQLFanOut` on a raw connection,
//! and so does its port. The core classes drive the engine through Spring:
//! `CoreSchemaService` edits a schema (or `StorageService` a storage, `CorePublishService`
//! publishes a draft) and the rebuild hanging off it reconciles every tenant. Those
//! services are not in this crate, so the ports replay what they hand the engine: the
//! definition each client resolves on each surface (through `Storages` and [`Schemas`])
//! and then `MySqlAppDataService::reconcile`, and assert the tables as the Java tests do.
//!
//! Client codes: SYSTEM is `RUSTTEST`, every other client `RUSTTEST_<code>`.
//!
//! Run with: cargo test -p appdata --test live_mysql_fanout -- --ignored --test-threads=1

mod support;

use std::collections::HashMap;
use std::sync::Arc;

use appdata::engine::{AppDataEngine, Hooks, PassThrough, SchemaRepositories};
use appdata::model::*;
use appdata::mysql::column::MySqlColumn;
use appdata::mysql::journal::MigrationState;
use appdata::mysql::migration::{self, FanOutReport, TenantPlan};
use appdata::mysql::{MySqlAppDataService, MySqlEngineConfig};
use appdata::retention::VersionRetention;
use appdata::schema_refs::SchemaRepository;
use appdata::value::Value;
use async_trait::async_trait;
use indexmap::IndexMap;
use sqlx::MySqlPool;
use support::*;

async fn scratch_pool() -> MySqlPool {
    let e = mysql_engine(Arc::new(Storages::default()));
    let p = pool(&e).await;
    wait_for_headroom(&p).await;
    p
}

async fn number(p: &MySqlPool, sql: &str) -> i64 {
    appdata::mysql::db::count_raw(p, sql).await.unwrap()
}

async fn column_of(p: &MySqlPool, db: &str, table: &str, column: &str) -> Option<String> {
    let t = scalar(p, &format!("SELECT COLUMN_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = '{db}' AND TABLE_NAME = '{table}' AND COLUMN_NAME = '{column}'")).await;
    Some(t).filter(|t| !t.is_empty())
}

/// Journal rows in a tenant, or 0 when it never had a migration.
async fn journal_rows(p: &MySqlPool, db: &str, filter: &str) -> i64 {
    if number(p, &format!("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = '{db}' AND TABLE_NAME = 'storage_migration'")).await == 0 {
        return 0;
    }
    number(p, &format!("SELECT COUNT(*) FROM `{db}`.`storage_migration`{filter}")).await
}

/// `RUSTTEST` for SYSTEM, `RUSTTEST_<code>` for anyone else.
fn client(code: &str) -> String {
    if code == "SYSTEM" {
        CLIENT.to_string()
    } else {
        format!("{CLIENT}_{code}")
    }
}

// ------------------------------------------------------------------ the schema service

#[derive(Default)]
struct SchemaStore {
    live: HashMap<String, Schema>,
    /// A client's own draft of a schema, which only that client's draft surface reads.
    drafts: HashMap<(String, String), Schema>,
}

/// `CoreSchemaService.getSchemaRepository` for the tests: the live schemas, and on the
/// draft surface the asking client's own drafts first (`readDrafted` serves no other
/// client's draft).
#[derive(Clone, Default)]
struct Schemas(Arc<std::sync::Mutex<SchemaStore>>);

impl Schemas {
    fn set_live(&self, full_name: &str, definition: &str) {
        self.0.lock().unwrap().live.insert(full_name.into(), Schema::from_value(&v(definition)).unwrap());
    }

    fn save_draft(&self, client: &str, full_name: &str, definition: &str) {
        self.0.lock().unwrap().drafts.insert((client.into(), full_name.into()), Schema::from_value(&v(definition)).unwrap());
    }

    fn discard_draft(&self, client: &str, full_name: &str) {
        self.0.lock().unwrap().drafts.remove(&(client.to_string(), full_name.to_string()));
    }

    fn publish(&self, client: &str, full_name: &str) {
        let mut store = self.0.lock().unwrap();
        let draft = store.drafts.remove(&(client.to_string(), full_name.to_string())).expect("a draft to publish");
        store.live.insert(full_name.into(), draft);
    }
}

struct SurfaceView {
    store: Arc<std::sync::Mutex<SchemaStore>>,
    client: String,
    draft: bool,
}

#[async_trait]
impl SchemaRepository for SurfaceView {
    async fn find(&self, namespace: &str, name: &str) -> anyhow::Result<Option<Schema>> {
        let full = format!("{namespace}.{name}");
        let store = self.store.lock().unwrap();
        if self.draft {
            if let Some(s) = store.drafts.get(&(self.client.clone(), full.clone())) {
                return Ok(Some(s.clone()));
            }
        }
        Ok(store.live.get(&full).cloned())
    }
}

impl SchemaRepositories for Schemas {
    fn for_app(&self, app_code: &str, client_code: &str) -> Arc<dyn SchemaRepository> {
        self.for_surface(app_code, client_code, false)
    }

    fn for_surface(&self, _app_code: &str, client_code: &str, draft: bool) -> Arc<dyn SchemaRepository> {
        Arc::new(SurfaceView { store: self.0.clone(), client: client_code.into(), draft })
    }
}

/// An engine wired to both test services.
fn engine_for(storages: Arc<Storages>, schemas: &Schemas) -> MySqlAppDataService {
    let hooks = Hooks { validator: Arc::new(PassThrough), schemas: Some(Arc::new(schemas.clone())), storages: Some(storages), authority: None };
    mysql_engine_with(MySqlEngineConfig { retention: VersionRetention::clamped(0, 0), ..Default::default() }, hooks)
}

/// A storage as `client` resolves it (the stored deltas already folded in).
fn resolved(app: &str, name: &str, client_code: &str, properties: &str) -> Storage {
    storage(
        app,
        name,
        &format!(r#"{{"clientCode":"{client_code}","version":1,"schema":{{"type":"OBJECT","properties":{properties}}}}}"#),
    )
}

// ------------------------------------------------------------------ MySQLFanOutIntegrationTest

mod mysql_fan_out_integration_test {
    use super::*;

    const APP: &str = "rtf_fan";
    const TABLE: &str = "orders";

    fn tenants() -> Vec<String> {
        ["A", "B", "C"].iter().map(|c| format!("{}_{APP}", client(c))).collect()
    }

    fn tenant(code: &str) -> String {
        format!("{}_{APP}", client(code))
    }

    async fn fresh_tenants(p: &MySqlPool) {
        for (i, db) in tenants().iter().enumerate() {
            exec(p, &format!("DROP DATABASE IF EXISTS `{db}`")).await;
            create_schema(p, db).await;
            exec(p, &format!("CREATE TABLE `{db}`.`{TABLE}` (`_id` CHAR(26) NOT NULL, `amount` VARCHAR(40) NULL, PRIMARY KEY (`_id`))")).await;
            exec(p, &format!("INSERT INTO `{db}`.`{TABLE}` VALUES ('{i:026}', '10')")).await;
        }
    }

    fn desired(columns: &[(&str, &str)]) -> IndexMap<String, Vec<MySqlColumn>> {
        let cols: Vec<MySqlColumn> = columns.iter().map(|(n, t)| MySqlColumn::new(n, t, true).unwrap()).collect();
        tenants().into_iter().map(|db| (db, cols.clone())).collect()
    }

    fn doubles() -> IndexMap<String, Vec<MySqlColumn>> {
        desired(&[("amount", "DOUBLE")])
    }

    async fn plans(p: &MySqlPool, desired_for: &IndexMap<String, Vec<MySqlColumn>>) -> Vec<TenantPlan> {
        migration::plan_tenants(p, &tenants(), TABLE, 9, desired_for).await.unwrap()
    }

    async fn apply(p: &MySqlPool, desired_for: &IndexMap<String, Vec<MySqlColumn>>) -> FanOutReport {
        let plans = plans(p, desired_for).await;
        migration::apply(p, &plans, "orders", TABLE, Some(8), 9, "LIVE", Some("kiran")).await.unwrap()
    }

    async fn amount_type(p: &MySqlPool, db: &str) -> String {
        column_of(p, db, TABLE, "amount").await.unwrap_or_default()
    }

    #[tokio::test]
    #[ignore = "needs the local MySQL"]
    async fn one_plan_per_tenant() {
        let p = scratch_pool().await;
        let clients: Vec<String> = ["A", "B", "C"].iter().map(|c| client(c)).collect();
        let clients: Vec<&str> = clients.iter().map(String::as_str).collect();
        drop_schemas(&p, &clients, APP).await;
        guarded(
            async {
                // schemaChangeAtSameVersion
                fresh_tenants(&p).await;
                assert!(apply(&p, &doubles()).await.all_clean());
                let report = apply(&p, &desired(&[("amount", "DOUBLE"), ("currency", "VARCHAR(3)")])).await;
                assert!(report.all_clean(), "{}", report.summary());
                assert_eq!(report.applied(), 3, "{}", report.summary());
                for db in tenants() {
                    assert_eq!(column_of(&p, &db, TABLE, "currency").await.as_deref(), Some("varchar(3)"));
                }

                // overrideUnaffected
                fresh_tenants(&p).await;
                exec(&p, &format!("ALTER TABLE `{}`.`{TABLE}` MODIFY COLUMN `amount` DOUBLE NULL", tenant("B"))).await;
                let report = apply(&p, &doubles()).await;
                assert!(report.no_op.contains(&tenant("B")), "{}", report.summary());
                assert_eq!(report.applied(), 2, "{}", report.summary());

                // progressIsReadable
                fresh_tenants(&p).await;
                exec(&p, &format!("UPDATE `{}`.`{TABLE}` SET `amount` = 'nope'", tenant("B"))).await;
                apply(&p, &doubles()).await;
                let by_db: IndexMap<String, migration::TenantProgress> =
                    migration::status(&p, &tenants(), "orders").await.unwrap().into_iter().map(|t| (t.database.clone(), t)).collect();
                assert_eq!(by_db[&tenant("A")].state, Some(MigrationState::Applied));
                assert_eq!(by_db[&tenant("C")].state, Some(MigrationState::Applied));
                assert_eq!(by_db[&tenant("B")].state, None, "{}", by_db[&tenant("B")].describe());

                // rerunResumes
                fresh_tenants(&p).await;
                exec(&p, &format!("UPDATE `{}`.`{TABLE}` SET `amount` = 'nope'", tenant("B"))).await;
                let first = apply(&p, &doubles()).await;
                assert_eq!(first.applied(), 2);
                assert_eq!(first.blocked, vec![tenant("B")]);
                exec(&p, &format!("UPDATE `{}`.`{TABLE}` SET `amount` = '11'", tenant("B"))).await;
                let second = apply(&p, &doubles()).await;
                assert!(second.all_clean(), "{}", second.summary());
                assert_eq!(amount_type(&p, &tenant("B")).await, "double");
                assert_eq!(second.applied(), 1, "{}", second.summary());
                assert_eq!(second.no_op.len(), 2, "{}", second.summary());
                assert!(second.no_op.contains(&tenant("A")), "{}", second.summary());

                // progressBeforeAnything
                fresh_tenants(&p).await;
                let progress = migration::status(&p, &tenants(), "orders").await.unwrap();
                assert_eq!(progress.len(), 3);
                assert!(progress.iter().all(|t| t.state.is_none()));
                assert!(progress[0].describe().contains("not attempted"));

                // onePlanPerTenant
                let ps = plans(&p, &doubles()).await;
                assert_eq!(ps.len(), 3);
                assert!(ps.iter().all(|p| !p.is_no_op()));
                assert!(ps.iter().all(TenantPlan::needs_check), "a retype must be pre-flighted");

                // allClean
                let report = apply(&p, &doubles()).await;
                assert!(report.all_clean(), "{}", report.summary());
                assert_eq!(report.applied(), 3);
                for db in tenants() {
                    assert_eq!(amount_type(&p, &db).await, "double");
                }

                // oneBlockedTheOthersProceed
                fresh_tenants(&p).await;
                exec(&p, &format!("UPDATE `{}`.`{TABLE}` SET `amount` = 'junk'", tenant("B"))).await;
                let report = apply(&p, &doubles()).await;
                assert!(!report.all_clean());
                assert_eq!(report.blocked, vec![tenant("B")]);
                assert_eq!(report.applied(), 2, "{}", report.summary());
                assert_eq!(amount_type(&p, &tenant("A")).await, "double");
                assert_eq!(amount_type(&p, &tenant("C")).await, "double");
                assert_eq!(amount_type(&p, &tenant("B")).await, "varchar(40)", "the blocked tenant is untouched");

                // blockedTenantIsNotAttempted
                assert_eq!(journal_rows(&p, &tenant("B"), "").await, 0);
                assert_eq!(
                    number(&p, &format!("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = '{}' AND TABLE_NAME = 'storage_migration'", tenant("B"))).await,
                    0,
                    "no journal table should even have been created for a tenant that never ran"
                );

                // preflightIsReadOnly
                fresh_tenants(&p).await;
                let blocked = migration::preflight(&p, &plans(&p, &doubles()).await).await.unwrap();
                assert!(blocked.is_empty());
                for db in tenants() {
                    assert_eq!(amount_type(&p, &db).await, "varchar(40)", "pre-flight must not touch the table");
                }

                // preflightReportsAllFailures
                exec(&p, &format!("UPDATE `{}`.`{TABLE}` SET `amount` = 'junk'", tenant("A"))).await;
                exec(&p, &format!("UPDATE `{}`.`{TABLE}` SET `amount` = 'rubbish'", tenant("C"))).await;
                let blocked = migration::preflight(&p, &plans(&p, &doubles()).await).await.unwrap();
                assert_eq!(blocked.len(), 2, "{blocked:?}");
                assert!(blocked.contains_key(&tenant("A")) && blocked.contains_key(&tenant("C")));

                // alreadyCurrentIsANoOp
                fresh_tenants(&p).await;
                apply(&p, &doubles()).await;
                let ps = plans(&p, &doubles()).await;
                let second = migration::apply(&p, &ps, "orders", TABLE, Some(9), 10, "LIVE", Some("kiran")).await.unwrap();
                assert_eq!(second.no_op.len(), 3, "{}", second.summary());
                assert_eq!(second.applied(), 0);

                // missingTableIsNotAMigration
                fresh_tenants(&p).await;
                exec(&p, &format!("DROP TABLE `{}`.`{TABLE}`", tenant("C"))).await;
                let ps = plans(&p, &doubles()).await;
                let c = ps.iter().find(|p| p.database == tenant("C")).unwrap();
                assert!(c.is_no_op(), "a table that does not exist is created at the right shape, not migrated");

                // discoversTenantsIncludingDrafts
                fresh_tenants(&p).await;
                let draft = format!("{}_draft", tenant("A"));
                create_schema(&p, &draft).await;
                exec(&p, &format!("CREATE TABLE `{draft}`.`{TABLE}` (`_id` CHAR(26) NOT NULL, PRIMARY KEY (`_id`))")).await;
                let found = migration::tenants_with_table(&p, APP, TABLE).await.unwrap();
                assert!(tenants().iter().all(|t| found.contains(t)), "{found:?}");
                assert!(found.contains(&draft), "the draft surface is a tenant too");
            },
            drop_schemas(&p, &clients, APP),
        )
        .await;
    }
}


// ------------------------------------------------------------------ the core tests' tenants

/// SYSTEM, a mid client inheriting it, and a leaf inheriting the mid, as the core tests
/// chain them.
const CHAIN: [&str; 3] = ["SYSTEM", "LZCLA", "LZACP1"];

/// One app's tenants: the definition each client resolves on each surface (what
/// `StorageService.readForTenant` would fold out of the stored deltas), the schema
/// service, and an engine over both.
struct Tenants {
    p: MySqlPool,
    app: &'static str,
    name: String,
    table: String,
    storages: Arc<Storages>,
    schemas: Schemas,
    resolved: std::sync::Mutex<HashMap<(String, bool), Storage>>,
    e: MySqlAppDataService,
    c: Connection,
}

impl Tenants {
    /// Every schema of these clients dropped, and a fresh engine so no table flag
    /// survives from a previous case.
    async fn fresh(p: &MySqlPool, app: &'static str, name: &str, codes: &[&str]) -> Tenants {
        let clients: Vec<String> = codes.iter().map(|c| client(c)).collect();
        drop_schemas(p, &clients.iter().map(String::as_str).collect::<Vec<_>>(), app).await;
        let storages = Arc::new(Storages::default());
        let schemas = Schemas::default();
        let e = engine_for(storages.clone(), &schemas);
        Tenants {
            p: p.clone(),
            app,
            name: name.to_string(),
            table: format!("{app}_{name}"),
            storages,
            schemas,
            resolved: std::sync::Mutex::new(HashMap::new()),
            e,
            c: conn().await,
        }
    }

    fn db(&self, code: &str) -> String {
        format!("{}_{}", client(code), self.app)
    }

    async fn live(&self, code: &str, column: &str) -> Option<String> {
        column_of(&self.p, &self.db(code), &self.table, column).await
    }

    async fn draft(&self, code: &str, column: &str) -> Option<String> {
        column_of(&self.p, &format!("{}_draft", self.db(code)), &self.table, column).await
    }

    /// What `code` resolves on one surface: these properties.
    async fn resolve(&self, code: &str, draft: bool, properties: &str) {
        let s = resolved(self.app, &self.name, &client(code), properties);
        self.storages.put_for(&client(code), draft, &s).await;
        self.resolved.lock().unwrap().insert((client(code), draft), s);
    }

    async fn resolve_both(&self, code: &str, properties: &str) {
        self.resolve(code, false, properties).await;
        self.resolve(code, true, properties).await;
    }

    fn storage(&self, code: &str, draft: bool) -> Storage {
        self.resolved.lock().unwrap()[&(client(code), draft)].clone()
    }

    /// A write through the engine, which is what makes a tenant's table exist.
    async fn write(&self, code: &str, row: &str, on_draft: bool) -> appdata::value::Document {
        let who = client(code);
        let s = self.storage(code, on_draft);
        self.e.create(&cx_for(&who).on_draft(on_draft), &who, Some(&self.c), &s, data(row)).await.unwrap()
    }

    /// The rebuild the Java services hang off a definition change.
    async fn reconcile(&self) -> FanOutReport {
        self.e.reconcile(Some(&self.c), self.app, &self.storage("SYSTEM", false), Some("rusttest")).await.unwrap()
    }

    async fn count(&self, sql: &str) -> i64 {
        number(&self.p, sql).await
    }
}

fn names_of(codes: &[&str]) -> Vec<String> {
    codes.iter().map(|c| client(c)).collect()
}

// ------------------------------------------------------------------ MySQLTenantMigrationSafetyIntegrationTest

mod mysql_tenant_migration_safety_integration_test {
    use super::*;

    const APP: &str = "rtf_safety";
    const AMOUNT: &str = r#"{"amount":{"ref":"App.Amount"}}"#;

    async fn given(p: &MySqlPool) -> Tenants {
        let t = Tenants::fresh(p, APP, "ledger", &CHAIN).await;
        t.schemas.set_live("App.Amount", r#"{"namespace":"App","name":"Amount","type":"STRING","maxLength":40}"#);
        for code in CHAIN {
            t.resolve_both(code, AMOUNT).await;
        }
        t
    }

    /// `whenSchemaBecomesNumeric`: the shared schema retyped, and the rebuild it triggers.
    async fn schema_becomes_numeric(t: &Tenants) -> FanOutReport {
        t.schemas.set_live("App.Amount", r#"{"namespace":"App","name":"Amount","type":"DOUBLE"}"#);
        t.reconcile().await
    }

    #[tokio::test]
    #[ignore = "needs the local MySQL"]
    async fn one_tenants_dirty_data_blocks_only_that_tenant() {
        let p = scratch_pool().await;
        let clients = names_of(&CHAIN);
        let clients: Vec<&str> = clients.iter().map(String::as_str).collect();
        drop_schemas(&p, &clients, APP).await;
        guarded(
            async {
                let (system, mid, leaf) = (CHAIN[0], CHAIN[1], CHAIN[2]);

                // PartialFanOut.dirtyTenantIsIsolated
                let t = given(&p).await;
                t.write(system, r#"{"amount":"10"}"#, false).await;
                t.write(mid, r#"{"amount":"not a number"}"#, false).await;
                t.write(leaf, r#"{"amount":"30"}"#, false).await;
                schema_becomes_numeric(&t).await;
                assert_eq!(t.live(system, "amount").await.as_deref(), Some("double"));
                assert_eq!(t.live(leaf, "amount").await.as_deref(), Some("double"));
                assert_eq!(t.live(mid, "amount").await.as_deref(), Some("varchar(40)"));
                assert_eq!(t.count(&format!("SELECT COUNT(*) FROM `{}`.`{}` WHERE `amount` = 'not a number'", t.db(mid), t.table)).await, 1);

                // PartialFanOut.blockedTenantIsNotJournalled
                let t = given(&p).await;
                t.write(system, r#"{"amount":"10"}"#, false).await;
                t.write(mid, r#"{"amount":"not a number"}"#, false).await;
                schema_becomes_numeric(&t).await;
                assert_eq!(journal_rows(&p, &t.db(mid), "").await, 0);
                assert_eq!(t.count(&format!("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = '{}' AND TABLE_NAME = 'storage_migration'", t.db(mid))).await, 0);

                // PartialFanOut.recoveryIsARerun
                let t = given(&p).await;
                t.write(system, r#"{"amount":"10"}"#, false).await;
                t.write(mid, r#"{"amount":"not a number"}"#, false).await;
                schema_becomes_numeric(&t).await;
                assert_eq!(t.live(mid, "amount").await.as_deref(), Some("varchar(40)"));
                exec(&p, &format!("UPDATE `{}`.`{}` SET `amount` = '42'", t.db(mid), t.table)).await;
                let report = t.reconcile().await;
                assert!(report.all_clean(), "{}", report.summary());
                assert_eq!(t.live(mid, "amount").await.as_deref(), Some("double"));
                assert_eq!(t.count(&format!("SELECT COUNT(*) FROM `{}`.`{}` WHERE `amount` = 42", t.db(mid), t.table)).await, 1);

                // PartialFanOut.reportNamesThemAll
                let t = given(&p).await;
                t.write(system, r#"{"amount":"10"}"#, false).await;
                t.write(mid, r#"{"amount":"bad"}"#, false).await;
                t.write(leaf, r#"{"amount":"worse"}"#, false).await;
                schema_becomes_numeric(&t).await;
                let report = t.reconcile().await;
                assert!(!report.all_clean());
                assert!(report.blocked.contains(&t.db(mid)) && report.blocked.contains(&t.db(leaf)), "{}", report.summary());

                // Surfaces.draftIsMigratedToo
                let t = given(&p).await;
                t.write(system, r#"{"amount":"10"}"#, false).await;
                t.write(system, r#"{"amount":"20"}"#, true).await;
                assert_eq!(t.draft(system, "amount").await.as_deref(), Some("varchar(40)"));
                schema_becomes_numeric(&t).await;
                assert_eq!(t.live(system, "amount").await.as_deref(), Some("double"));
                assert_eq!(t.draft(system, "amount").await.as_deref(), Some("double"));

                // Surfaces.surfaceIsRecorded
                let t = given(&p).await;
                t.write(system, r#"{"amount":"10"}"#, false).await;
                t.write(system, r#"{"amount":"20"}"#, true).await;
                schema_becomes_numeric(&t).await;
                assert_eq!(journal_rows(&p, &t.db(system), " WHERE `surface` = 'LIVE'").await, 1);
                assert_eq!(journal_rows(&p, &format!("{}_draft", t.db(system)), " WHERE `surface` = 'DRAFT'").await, 1);

                // Surfaces.surfacesFailIndependently
                let t = given(&p).await;
                t.write(system, r#"{"amount":"10"}"#, false).await;
                t.write(system, r#"{"amount":"scratch value"}"#, true).await;
                schema_becomes_numeric(&t).await;
                assert_eq!(t.live(system, "amount").await.as_deref(), Some("double"));
                assert_eq!(t.draft(system, "amount").await.as_deref(), Some("varchar(40)"));
            },
            drop_schemas(&p, &clients, APP),
        )
        .await;
    }
}

// ------------------------------------------------------------------ MySQLSchemaChangeIntegrationTest

mod mysql_schema_change_integration_test {
    use super::*;

    const APP: &str = "rtf_schema";
    const BASE: &str = r#"{"amount":{"ref":"App.Money"},"note":{"type":"STRING","maxLength":30}}"#;
    /// LEAF's stored `{"amount": {"type": "STRING", "maxLength": 10}}` folded over the base.
    const LEAF: &str = r#"{"amount":{"ref":"App.Money","type":"STRING","maxLength":10},"note":{"type":"STRING","maxLength":30}}"#;

    fn money(max_length: i32) -> String {
        format!(r#"{{"namespace":"App","name":"Money","type":"STRING","maxLength":{max_length}}}"#)
    }

    async fn given(p: &MySqlPool) -> Tenants {
        let t = Tenants::fresh(p, APP, "orders", &CHAIN).await;
        t.schemas.set_live("App.Money", &money(40));
        t.resolve_both(CHAIN[0], BASE).await;
        t.resolve_both(CHAIN[1], BASE).await;
        t.resolve_both(CHAIN[2], LEAF).await;
        t
    }

    async fn tables_for_every_client(t: &Tenants) {
        for code in CHAIN {
            t.write(code, r#"{"amount":"10","note":"seed"}"#, false).await;
        }
    }

    async fn schema_changes_to(t: &Tenants, max_length: i32) {
        t.schemas.set_live("App.Money", &money(max_length));
        t.reconcile().await;
    }

    #[tokio::test]
    #[ignore = "needs the local MySQL"]
    async fn a_schema_or_storage_edit_reaches_every_inheritor() {
        let p = scratch_pool().await;
        let clients = names_of(&CHAIN);
        let clients: Vec<&str> = clients.iter().map(String::as_str).collect();
        drop_schemas(&p, &clients, APP).await;
        guarded(
            async {
                let (system, mid, leaf) = (CHAIN[0], CHAIN[1], CHAIN[2]);

                // Baseline.threeClientsThreeTables
                let t = given(&p).await;
                tables_for_every_client(&t).await;
                assert_eq!(t.live(system, "amount").await.as_deref(), Some("varchar(40)"));
                assert_eq!(t.live(mid, "amount").await.as_deref(), Some("varchar(40)"));
                assert_eq!(t.live(leaf, "amount").await.as_deref(), Some("varchar(10)"));
                for code in CHAIN {
                    assert_eq!(t.live(code, "note").await.as_deref(), Some("varchar(30)"));
                }

                // Baseline.writeAndRead
                let t = given(&p).await;
                let created = t.write(mid, r#"{"amount":"25","note":"hello"}"#, false).await;
                assert_eq!(created["amount"], Value::from("25"));
                assert_eq!(created["_id"].java_string().len(), 26, "the backend mints a ULID");

                // SchemaEdited.widensInheritorsOnly
                let t = given(&p).await;
                tables_for_every_client(&t).await;
                schema_changes_to(&t, 120).await;
                assert_eq!(t.live(system, "amount").await.as_deref(), Some("varchar(120)"));
                assert_eq!(t.live(mid, "amount").await.as_deref(), Some("varchar(120)"));
                assert_eq!(t.live(leaf, "amount").await.as_deref(), Some("varchar(10)"));

                // SchemaEdited.dataSurvives
                for code in [system, mid] {
                    assert_eq!(t.count(&format!("SELECT COUNT(*) FROM `{}`.`{}` WHERE `amount` = '10'", t.db(code), t.table)).await, 1);
                }

                // SchemaEdited.journalled
                for code in [system, mid] {
                    assert_eq!(journal_rows(&p, &t.db(code), " WHERE `storage_name` = 'orders' AND `state` = 'APPLIED'").await, 1, "{code}");
                }
                assert_eq!(t.count(&format!("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = '{}' AND TABLE_NAME = 'storage_migration'", t.db(leaf))).await, 0);

                // SchemaEdited.addedField: the schema becomes an object, so amount a JSON column.
                let t = given(&p).await;
                tables_for_every_client(&t).await;
                assert_eq!(t.live(system, "currency").await, None);
                t.schemas.set_live("App.Money", r#"{"namespace":"App","name":"Money","type":"OBJECT","properties":{"value":{"type":"DOUBLE"}}}"#);
                t.reconcile().await;
                assert_eq!(t.live(system, "amount").await.as_deref(), Some("json"));
                assert_eq!(t.live(mid, "amount").await.as_deref(), Some("json"));
                assert_eq!(t.live(leaf, "amount").await.as_deref(), Some("varchar(10)"), "the pinned override still wins");

                // SchemaEdited.absentTenantIsNotCreated
                let t = given(&p).await;
                t.write(mid, r#"{"amount":"10","note":"seed"}"#, false).await;
                schema_changes_to(&t, 120).await;
                assert_eq!(t.live(mid, "amount").await.as_deref(), Some("varchar(120)"));
                assert_eq!(t.count(&format!("SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = '{}'", t.db(leaf))).await, 0);

                // SchemaEdited.successiveEdits
                let t = given(&p).await;
                tables_for_every_client(&t).await;
                schema_changes_to(&t, 120).await;
                schema_changes_to(&t, 200).await;
                assert_eq!(t.live(system, "amount").await.as_deref(), Some("varchar(200)"));
                assert_eq!(journal_rows(&p, &t.db(system), " WHERE `storage_name` = 'orders'").await, 2);

                // StorageEdited.baseEditReachesEveryone: everyone resolves the base's new field.
                let t = given(&p).await;
                tables_for_every_client(&t).await;
                let with_ref1 = |props: &str| props.replacen('{', r#"{"ref1":{"type":"STRING","maxLength":12},"#, 1);
                t.resolve_both(system, &with_ref1(BASE)).await;
                t.resolve_both(mid, &with_ref1(BASE)).await;
                t.resolve_both(leaf, &with_ref1(LEAF)).await;
                t.reconcile().await;
                for code in CHAIN {
                    assert_eq!(t.live(code, "ref1").await.as_deref(), Some("varchar(12)"), "{code} should have the new column");
                }

                // StorageEdited.overrideSurvivesBaseEdit
                let t = given(&p).await;
                tables_for_every_client(&t).await;
                let wide_note = |props: &str| props.replace(r#""note":{"type":"STRING","maxLength":30}"#, r#""note":{"type":"STRING","maxLength":90}"#);
                t.resolve_both(system, &wide_note(BASE)).await;
                t.resolve_both(mid, &wide_note(BASE)).await;
                t.resolve_both(leaf, &wide_note(LEAF)).await;
                t.reconcile().await;
                assert!(t.live(leaf, "note").await.unwrap_or_default().starts_with("varchar(90"), "the leaf inherits note");
                assert_eq!(t.live(leaf, "amount").await.as_deref(), Some("varchar(10)"), "but what it pinned stays pinned");
            },
            drop_schemas(&p, &clients, APP),
        )
        .await;
    }
}

// ------------------------------------------------------------------ MySQLWideFanOutIntegrationTest

mod mysql_wide_fan_out_integration_test {
    use super::*;

    const APP: &str = "rtf_wide";
    const OVERRIDING_MID: &str = "M2";
    const OVERRIDING_LEAF: &str = "M1L5";
    const DEEP_MID: &str = "M0L0";
    const DEEP_CHILD: &str = "M0L0C0";
    const DEEP_LEAF: &str = "M0L0C1";

    /// The 71-client tree: SYSTEM, five mids with 13, 13, 13, 12 and 12 leaves, and a
    /// deep branch under M0L0. Each client with its base-first chain.
    fn tree() -> (Vec<String>, HashMap<String, Vec<String>>) {
        let mut clients = vec!["SYSTEM".to_string()];
        let mut chains: HashMap<String, Vec<String>> = HashMap::new();
        chains.insert("SYSTEM".into(), vec!["SYSTEM".into()]);
        let mut register = |client: String, parent: &str, clients: &mut Vec<String>| {
            let mut chain = chains[parent].clone();
            chain.push(client.clone());
            chains.insert(client.clone(), chain);
            clients.push(client);
        };
        for (m, leaves) in [13, 13, 13, 12, 12].iter().enumerate() {
            let mid = format!("M{m}");
            register(mid.clone(), "SYSTEM", &mut clients);
            for l in 0..*leaves {
                register(format!("{mid}L{l}"), &mid, &mut clients);
            }
        }
        register(DEEP_CHILD.into(), DEEP_MID, &mut clients);
        register(DEEP_LEAF.into(), DEEP_CHILD, &mut clients);
        (clients, chains)
    }

    fn pinned_width(client: &str) -> Option<i32> {
        match client {
            OVERRIDING_MID => Some(15),
            OVERRIDING_LEAF => Some(7),
            DEEP_LEAF => Some(5),
            _ => None,
        }
    }

    /// The width a client resolves for itself, pinned on it or on an ancestor (the
    /// nearest wins).
    fn resolved_width(chain: &[String]) -> Option<i32> {
        chain.iter().rev().find_map(|c| pinned_width(c))
    }

    fn amount(max_length: i32) -> String {
        format!(r#"{{"namespace":"App","name":"Amount","type":"STRING","maxLength":{max_length}}}"#)
    }

    /// Every tenant at the base shape with one short row, seeded directly, on one or both
    /// surfaces; each client resolving its own folded definition on both.
    async fn given(p: &MySqlPool, both_surfaces: bool) -> (Tenants, Vec<String>, HashMap<String, Vec<String>>) {
        let (clients, chains) = tree();
        let codes: Vec<&str> = clients.iter().map(String::as_str).collect();
        let t = Tenants::fresh(p, APP, "ledger", &codes).await;
        t.schemas.set_live("App.Amount", &amount(40));
        for (i, code) in clients.iter().enumerate() {
            let props = match resolved_width(&chains[code]) {
                None => r#"{"amount":{"ref":"App.Amount"}}"#.to_string(),
                Some(w) => format!(r#"{{"amount":{{"ref":"App.Amount","type":"STRING","maxLength":{w}}}}}"#),
            };
            t.resolve_both(code, &props).await;
            let mut dbs = vec![t.db(code)];
            if both_surfaces {
                dbs.push(format!("{}_draft", t.db(code)));
            }
            for db in dbs {
                create_schema(p, &db).await;
                exec(p, &format!("CREATE TABLE `{db}`.`{}` (`_id` CHAR(26) NOT NULL, `amount` VARCHAR(40) NULL, PRIMARY KEY (`_id`))", t.table)).await;
                exec(p, &format!("INSERT INTO `{db}`.`{}` VALUES ('{i:026}', '10')", t.table)).await;
            }
        }
        (t, clients, chains)
    }

    fn inheritors(clients: &[String], chains: &HashMap<String, Vec<String>>) -> Vec<String> {
        clients.iter().filter(|c| resolved_width(&chains[*c]).is_none()).cloned().collect()
    }

    async fn widen_to(t: &Tenants, max_length: i32) {
        t.schemas.set_live("App.Amount", &amount(max_length));
        t.reconcile().await;
    }

    async fn becomes_numeric(t: &Tenants) {
        t.schemas.set_live("App.Amount", r#"{"namespace":"App","name":"Amount","type":"DOUBLE"}"#);
        t.reconcile().await;
    }

    #[tokio::test]
    #[ignore = "needs the local MySQL"]
    async fn one_publish_across_seventy_one_tenants() {
        let p = scratch_pool().await;
        let (all, chains) = tree();
        let clients = names_of(&all.iter().map(String::as_str).collect::<Vec<_>>());
        let client_refs: Vec<&str> = clients.iter().map(String::as_str).collect();
        drop_schemas(&p, &client_refs, APP).await;
        guarded(
            async {
                // treeShape
                assert_eq!(all.len(), 71);
                assert_eq!(chains[DEEP_LEAF], vec!["SYSTEM", "M0", DEEP_MID, DEEP_CHILD, DEEP_LEAF]);
                assert_eq!(all.iter().filter(|c| resolved_width(&chains[*c]).is_some()).count(), 16);
                assert_eq!(inheritors(&all, &chains).len(), 55);

                // eachTenantGetsItsOwnShape
                let (t, clients, chains) = given(&p, false).await;
                let report = t.reconcile().await;
                assert!(report.all_clean(), "{}", report.summary());
                assert_eq!(t.live(OVERRIDING_MID, "amount").await.as_deref(), Some("varchar(15)"));
                assert_eq!(t.live(OVERRIDING_LEAF, "amount").await.as_deref(), Some("varchar(7)"));
                assert_eq!(t.live(DEEP_LEAF, "amount").await.as_deref(), Some("varchar(5)"));
                assert_eq!(t.live("M2L0", "amount").await.as_deref(), Some("varchar(15)"));
                assert_eq!(t.live("M2L12", "amount").await.as_deref(), Some("varchar(15)"));
                assert_eq!(t.live(DEEP_MID, "amount").await.as_deref(), Some("varchar(40)"));
                assert_eq!(t.live(DEEP_CHILD, "amount").await.as_deref(), Some("varchar(40)"));
                for c in inheritors(&clients, &chains) {
                    assert_eq!(t.live(&c, "amount").await.as_deref(), Some("varchar(40)"), "{c}");
                }

                // schemaEditAcrossSeventyOne
                let (t, clients, chains) = given(&p, false).await;
                t.reconcile().await;
                let pinned_rows_before = journal_rows(&p, &t.db(OVERRIDING_LEAF), "").await;
                assert_eq!(pinned_rows_before, 1);
                widen_to(&t, 120).await;
                let following = inheritors(&clients, &chains);
                assert_eq!(following.len(), 55);
                for c in &following {
                    assert_eq!(t.live(c, "amount").await.as_deref(), Some("varchar(120)"), "{c}");
                }
                assert_eq!(t.live(OVERRIDING_MID, "amount").await.as_deref(), Some("varchar(15)"));
                assert_eq!(t.live("M2L7", "amount").await.as_deref(), Some("varchar(15)"));
                assert_eq!(t.live(OVERRIDING_LEAF, "amount").await.as_deref(), Some("varchar(7)"));
                assert_eq!(t.live(DEEP_LEAF, "amount").await.as_deref(), Some("varchar(5)"));
                assert_eq!(journal_rows(&p, &t.db("M3L3"), "").await, 1);
                assert_eq!(journal_rows(&p, &t.db("M3L3"), " WHERE `state` = 'APPLIED'").await, 1);
                assert_eq!(journal_rows(&p, &t.db(OVERRIDING_LEAF), "").await, pinned_rows_before, "no row for DDL that never ran");

                // bothSurfacesAtWidth
                let (t, clients, chains) = given(&p, true).await;
                assert_eq!(t.count(&format!("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_NAME = '{}'", t.table)).await, 142, "71 clients on two surfaces");
                let start = std::time::Instant::now();
                t.reconcile().await;
                widen_to(&t, 120).await;
                eprintln!("142-schema publish across 71 tenants took {}ms", start.elapsed().as_millis());
                for c in inheritors(&clients, &chains) {
                    assert_eq!(t.live(&c, "amount").await.as_deref(), Some("varchar(120)"), "{c} live");
                    assert_eq!(t.draft(&c, "amount").await.as_deref(), Some("varchar(120)"), "{c} draft");
                }
                assert_eq!(t.draft(OVERRIDING_MID, "amount").await.as_deref(), Some("varchar(15)"));
                assert_eq!(t.draft("M2L9", "amount").await.as_deref(), Some("varchar(15)"));
                assert_eq!(t.draft(OVERRIDING_LEAF, "amount").await.as_deref(), Some("varchar(7)"));
                assert_eq!(t.draft(DEEP_LEAF, "amount").await.as_deref(), Some("varchar(5)"));

                // partialFailureAtWidth
                let (t, _, _) = given(&p, false).await;
                t.reconcile().await;
                let dirty = ["M3", "M4L2", DEEP_CHILD];
                for c in dirty {
                    exec(&p, &format!("UPDATE `{}`.`{}` SET `amount` = 'not a number'", t.db(c), t.table)).await;
                }
                becomes_numeric(&t).await;
                let report = t.reconcile().await;
                assert!(!report.all_clean(), "{}", report.summary());
                for c in dirty {
                    assert_eq!(t.live(c, "amount").await.as_deref(), Some("varchar(40)"), "{c} must be untouched");
                }
                assert_eq!(t.live("M3L0", "amount").await.as_deref(), Some("double"));
                assert_eq!(t.live("M3L11", "amount").await.as_deref(), Some("double"));
                assert_eq!(t.live(DEEP_MID, "amount").await.as_deref(), Some("double"));
                for c in dirty {
                    exec(&p, &format!("UPDATE `{}`.`{}` SET `amount` = '99'", t.db(c), t.table)).await;
                }
                let second = t.reconcile().await;
                assert!(second.all_clean(), "{}", second.summary());
                for c in dirty {
                    assert_eq!(t.live(c, "amount").await.as_deref(), Some("double"), "{c} should have caught up");
                }
                assert_eq!(t.count(&format!("SELECT COUNT(*) FROM `{}`.`{}` WHERE `amount` = 99", t.db("M3"), t.table)).await, 1);
            },
            drop_schemas(&p, &client_refs, APP),
        )
        .await;
    }
}

// ------------------------------------------------------------------ MySQLDraftPublishIntegrationTest

/// The engine half of `MySQLDraftPublishIntegrationTest`: each surface resolves its own
/// definition, a client's draft (of a schema or of its storage) is read only on that
/// client's draft surface, and the reconcile that follows a save, a publish or a discard
/// moves exactly the tables whose definition moved.
mod mysql_draft_publish_integration_test {
    use super::*;

    const APP: &str = "rtf_pub";
    const AMOUNT: &str = r#"{"amount":{"ref":"App.Amount"}}"#;

    fn amount(max_length: i32) -> String {
        format!(r#"{{"namespace":"App","name":"Amount","type":"STRING","maxLength":{max_length}}}"#)
    }

    /// Six tables: every client written once on each surface.
    async fn given(p: &MySqlPool) -> Tenants {
        let t = Tenants::fresh(p, APP, "invoices", &CHAIN).await;
        t.schemas.set_live("App.Amount", &amount(40));
        for code in CHAIN {
            t.resolve_both(code, AMOUNT).await;
        }
        for code in CHAIN {
            t.write(code, r#"{"amount":"10"}"#, false).await;
            t.write(code, r#"{"amount":"10"}"#, true).await;
        }
        t
    }

    /// `coreSchemaService.saveDraft` by SYSTEM, and the rebuild it triggers.
    async fn system_drafts_width(t: &Tenants, max_length: i32) {
        t.schemas.save_draft(&client("SYSTEM"), "App.Amount", &amount(max_length));
        t.reconcile().await;
    }

    #[tokio::test]
    #[ignore = "needs the local MySQL"]
    async fn drafts_move_draft_tables_and_publish_moves_live() {
        let p = scratch_pool().await;
        let clients = names_of(&CHAIN);
        let clients: Vec<&str> = clients.iter().map(String::as_str).collect();
        drop_schemas(&p, &clients, APP).await;
        guarded(
            async {
                let (system, mid, leaf) = (CHAIN[0], CHAIN[1], CHAIN[2]);

                // baseline
                let t = given(&p).await;
                for code in CHAIN {
                    assert_eq!(t.live(code, "amount").await.as_deref(), Some("varchar(40)"), "{code}");
                    assert_eq!(t.draft(code, "amount").await.as_deref(), Some("varchar(40)"), "{code}");
                }

                // draftSaveMovesOnlyDraftTables
                let t = given(&p).await;
                system_drafts_width(&t, 120).await;
                assert_eq!(t.draft(system, "amount").await.as_deref(), Some("varchar(120)"), "the drafting client's sandbox follows its draft");
                for code in CHAIN {
                    assert_eq!(t.live(code, "amount").await.as_deref(), Some("varchar(40)"), "{code} live must not move on a draft save");
                }
                // ancestorDraftDoesNotLeakDownstream
                assert_eq!(t.draft(mid, "amount").await.as_deref(), Some("varchar(40)"), "MID has no draft of its own");
                assert_eq!(t.draft(leaf, "amount").await.as_deref(), Some("varchar(40)"), "nor does LEAF");

                // publishMovesLiveTables
                let t = given(&p).await;
                system_drafts_width(&t, 120).await;
                t.schemas.publish(&client("SYSTEM"), "App.Amount");
                t.reconcile().await;
                for code in CHAIN {
                    assert_eq!(t.live(code, "amount").await.as_deref(), Some("varchar(120)"), "{code} live should have moved on publish");
                    assert_eq!(t.draft(code, "amount").await.as_deref(), Some("varchar(120)"), "{code}");
                }
                // dataSurvivesOnBothSurfaces
                assert_eq!(t.count(&format!("SELECT COUNT(*) FROM `{}`.`{}` WHERE `amount` = '10'", t.db(mid), t.table)).await, 1, "live row");
                assert_eq!(t.count(&format!("SELECT COUNT(*) FROM `{}_draft`.`{}` WHERE `amount` = '10'", t.db(mid), t.table)).await, 1, "draft row");

                // discardRestoresDraftTables
                let t = given(&p).await;
                system_drafts_width(&t, 120).await;
                assert_eq!(t.draft(system, "amount").await.as_deref(), Some("varchar(120)"));
                t.schemas.discard_draft(&client("SYSTEM"), "App.Amount");
                t.reconcile().await;
                for code in CHAIN {
                    assert_eq!(t.draft(code, "amount").await.as_deref(), Some("varchar(40)"), "{code} draft should be back");
                    assert_eq!(t.live(code, "amount").await.as_deref(), Some("varchar(40)"), "{code}");
                }

                // storageDraftStaysWithItsClient: SYSTEM's draft of the storage, on its draft surface only.
                let t = given(&p).await;
                t.resolve(system, true, r#"{"amount":{"ref":"App.Amount"},"memo":{"type":"STRING","maxLength":25}}"#).await;
                t.reconcile().await;
                assert_eq!(t.draft(system, "memo").await.as_deref(), Some("varchar(25)"), "the drafting client's sandbox gets the new column");
                for code in [mid, leaf] {
                    assert_eq!(t.draft(code, "memo").await, None, "{code} has no draft of its own");
                }
                for code in CHAIN {
                    assert_eq!(t.live(code, "memo").await, None, "{code} live must not have it yet");
                }

                // derivedClientDraftsForItself
                let t = given(&p).await;
                t.resolve(mid, true, r#"{"amount":{"ref":"App.Amount"},"midOnly":{"type":"STRING","maxLength":18}}"#).await;
                t.reconcile().await;
                assert_eq!(t.draft(mid, "midOnly").await.as_deref(), Some("varchar(18)"));
                assert_eq!(t.draft(system, "midOnly").await, None);
                assert_eq!(t.draft(leaf, "midOnly").await, None);
                assert_eq!(t.live(mid, "midOnly").await, None, "and not into its own live table");
            },
            drop_schemas(&p, &clients, APP),
        )
        .await;
    }
}
