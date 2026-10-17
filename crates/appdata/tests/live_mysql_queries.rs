//! The Java MySQL read, aggregate, join and history integration tests, ported against the
//! local MySQL in scratch schemas named `RUSTTEST_rtq_*` that each test creates and drops
//! (even when it fails).
//!
//! The commons-core classes run the Java builders on a raw connection, each against a
//! schema of its own; the ports do the same with the Rust builders and
//! `appdata::mysql::db`. `MySQLJoinOperationsIntegrationTest` goes through the service, so
//! its port goes through `MySqlAppDataService`.
//!
//! Run with: cargo test -p appdata --test live_mysql_queries -- --ignored --test-threads=1

mod support;

use std::sync::Arc;

use appdata::engine::{AppDataEngine, Ctx};
use appdata::model::*;
use appdata::mysql::aggregate_builder;
use appdata::mysql::column_names::{self, PhysicalSchema};
use appdata::mysql::db;
use appdata::mysql::field_resolver::FieldResolver;
use appdata::mysql::filter_builder;
use appdata::mysql::indexes;
use appdata::mysql::join_planner::{self, JoinedTable, PARENT};
use appdata::mysql::service::{null_column, update_values, Decoding};
use appdata::mysql::sql::{self, Bind, Cond, FieldOps, Select, Sql};
use appdata::mysql::table_planner;
use appdata::mysql::type_mapper::{self, ID_COLUMN};
use appdata::mysql::value_codec;
use appdata::mysql::version_table;
use appdata::retention::VersionRetention;
use appdata::value::{Decimal, Document, Value};
use indexmap::{IndexMap, IndexSet};
use sqlx::MySqlPool;
use support::*;

// ------------------------------------------------------------------ helpers

/// A scratch schema of its own for one ported class: `RUSTTEST_<app>`.
fn schema_of(app: &str) -> String {
    format!("{CLIENT}_{app}")
}

async fn scratch_pool() -> MySqlPool {
    let e = mysql_engine(Arc::new(Storages::default()));
    let p = pool(&e).await;
    wait_for_headroom(&p).await;
    p
}

fn set(items: &[&str]) -> IndexSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

fn none() -> IndexSet<String> {
    IndexSet::new()
}

fn schema(json: &str) -> Schema {
    Schema::from_value(&v(json)).unwrap()
}

fn condition(json: &str) -> Condition {
    Condition::from_value(&v(json)).unwrap().expect("a condition")
}

/// A number as a double, whatever Java type the driver handed back.
fn num(v: &Value) -> f64 {
    match v {
        Value::Int(i) => *i as f64,
        Value::Double(d) => *d,
        Value::Decimal(d) => d.double_value(),
        Value::String(s) => s.parse().unwrap(),
        other => panic!("not a number: {other:?}"),
    }
}

/// `BigDecimal.compareTo == 0`: the same number, whatever its scale.
fn same_decimal(expected: &str, actual: &Value) -> bool {
    let a = Decimal::parse(&actual.java_string()).unwrap().strip_trailing_zeros();
    let e = Decimal::parse(expected).unwrap().strip_trailing_zeros();
    a.to_plain_string() == e.to_plain_string()
}

fn bind(v: &Value) -> Bind {
    filter_builder::bind_of(v).unwrap()
}

async fn insert_row(p: &MySqlPool, table: &Sql, row: &Document) {
    let values: Vec<(String, Bind)> = row.iter().map(|(k, v)| (k.clone(), bind(v))).collect();
    db::execute(p, &sql::insert(table, &values)).await.unwrap();
}

async fn select_where(p: &MySqlPool, table: &Sql, cond: Cond) -> Vec<Document> {
    db::fetch(p, &Select::star(table.clone()).filter(cond).to_sql()).await.unwrap()
}

/// The first row with this key (numbers compared by value), and the measure in it.
fn value_for<'a>(rows: &'a [Document], key_field: &str, key: &Value, measure: &str) -> &'a Value {
    let same = |actual: &Value| match (actual, key) {
        (Value::Null, Value::Null) => true,
        (Value::Null, _) | (_, Value::Null) => false,
        (a, k) if a.is_number() && k.is_number() => num(a) as i64 == num(k) as i64,
        (a, k) => a == k,
    };
    let row = rows.iter().find(|r| same(r.get(key_field).unwrap_or(&Value::Null))).expect("a row with that key");
    &row[measure]
}

/// `MySQLAggregateBuilder.page` then run: the condition and HAVING built with no JSON columns.
async fn run_aggregate(p: &MySqlPool, table: &Sql, q: &AggregateQuery, resolver: &FieldResolver) -> Vec<Document> {
    let where_ = filter_builder::build(q.condition.as_ref(), resolver).unwrap();
    let having = q.having.as_ref().map(|h| filter_builder::build(Some(h), &FieldResolver::of(none())).unwrap());
    let select = aggregate_builder::page(table, q, where_, having, &q.pageable().unwrap(), resolver).unwrap();
    db::fetch(p, &select.to_sql()).await.unwrap()
}

async fn group_count(p: &MySqlPool, table: &Sql, q: &AggregateQuery, resolver: &FieldResolver) -> i64 {
    let where_ = filter_builder::build(q.condition.as_ref(), resolver).unwrap();
    let having = q.having.as_ref().map(|h| filter_builder::build(Some(h), &FieldResolver::of(none())).unwrap());
    let select = aggregate_builder::count(table, q, where_, having, resolver).unwrap();
    db::count(p, &select.to_sql()).await.unwrap()
}

// ------------------------------------------------------------------ MySQLAggregateIntegrationTest

mod mysql_aggregate_integration_test {
    use super::*;

    const APP: &str = "rtq_agg";

    async fn row(p: &MySqlPool, db: &str, i: i32, region: Option<&str>, amount: Option<f64>, placed_at: &str, ts: i64, note: Option<&str>) {
        let text = |s: Option<&str>| s.map(|s| format!("'{s}'")).unwrap_or_else(|| "NULL".into());
        exec(
            p,
            &format!(
                "INSERT INTO `{db}`.`sales` VALUES ('{i:026}', {}, {}, '{placed_at}', {ts}, {})",
                text(region),
                amount.map(|a| a.to_string()).unwrap_or_else(|| "NULL".into()),
                text(note)
            ),
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "needs the local MySQL"]
    async fn the_numbers_a_grouped_read_returns() {
        let p = scratch_pool().await;
        drop_schemas(&p, &[CLIENT], APP).await;
        guarded(
            async {
                let db = schema_of(APP);
                create_schema(&p, &db).await;
                exec(&p, &format!("CREATE TABLE `{db}`.`sales` (`_id` CHAR(26) NOT NULL, `region` VARCHAR(20) NULL, `amount` DOUBLE NULL, `placedAt` DATETIME(3) NULL, `ts` BIGINT NULL, `note` VARCHAR(40) NULL, PRIMARY KEY (`_id`))")).await;
                row(&p, &db, 1, Some("north"), Some(100.0), "2026-01-15 10:00:00", 1768471200, Some("a")).await;
                row(&p, &db, 2, Some("north"), Some(200.0), "2026-01-20 10:00:00", 1768903200, Some("b")).await;
                row(&p, &db, 3, Some("south"), Some(50.0), "2026-02-03 10:00:00", 1770112800, Some("c")).await;
                row(&p, &db, 4, Some("south"), None, "2026-02-10 10:00:00", 1770717600, None).await;
                row(&p, &db, 5, Some("east"), Some(400.0), "2026-02-28 23:30:00", 1772321400, Some("d")).await;
                row(&p, &db, 6, None, Some(7.0), "2026-01-01 00:30:00", 1767227400, Some("e")).await;

                let table = Sql::name(&[&db, "sales"]);
                let r = FieldResolver::of(none());
                let run = |q: &str| {
                    let q = agg(q);
                    let (p, table, r) = (&p, &table, &r);
                    async move { run_aggregate(p, table, &q, r).await }
                };

                // groupAndSum
                let rows = run(r#"{"groupBy":[{"field":"region"}],"aggregations":[{"function":"SUM","field":"amount","alias":"total"}]}"#).await;
                assert_eq!(rows.len(), 4, "three regions and the null one");
                assert_eq!(num(value_for(&rows, "region", &Value::from("north"), "total")), 300.0);
                assert_eq!(num(value_for(&rows, "region", &Value::from("south"), "total")), 50.0);

                // nullIsAGroup
                let rows = run(r#"{"groupBy":[{"field":"region"}],"aggregations":[{"function":"COUNT","alias":"n"}]}"#).await;
                assert_eq!(num(value_for(&rows, "region", &Value::Null, "n")), 1.0);

                // countSemantics
                let rows = run(r#"{"groupBy":[{"field":"region"}],"aggregations":[{"function":"COUNT","alias":"rows"},{"function":"COUNT","field":"amount","alias":"withAmount"}]}"#).await;
                assert_eq!(num(value_for(&rows, "region", &Value::from("south"), "rows")), 2.0);
                assert_eq!(num(value_for(&rows, "region", &Value::from("south"), "withAmount")), 1.0);

                // grandTotal
                let rows = run(r#"{"aggregations":[{"function":"SUM","field":"amount","alias":"total"}]}"#).await;
                assert_eq!(rows.len(), 1);
                assert_eq!(num(&rows[0]["total"]), 757.0);

                // dateColumnByMonth
                let rows = run(r#"{"groupBy":[{"field":"placedAt","bucket":"MONTH","alias":"month"}],"aggregations":[{"function":"COUNT","alias":"n"}]}"#).await;
                assert_eq!(rows.len(), 2, "January and February");
                let january: f64 = rows.iter().filter(|r| r["month"].java_string().starts_with("2026-01")).map(|r| num(&r["n"])).sum();
                assert_eq!(january, 3.0);

                // epochColumnByMonth
                let rows = run(r#"{"groupBy":[{"field":"ts","bucket":"MONTH","encoding":"EPOCH_SECONDS","alias":"month"}],"aggregations":[{"function":"COUNT","alias":"n"}]}"#).await;
                assert_eq!(rows.len(), 2);
                assert_eq!(num(value_for(&rows, "month", &Value::Int(1767225600), "n")), 3.0);
                assert_eq!(num(value_for(&rows, "month", &Value::Int(1769904000), "n")), 3.0);

                // epochBucketReturnsANumber
                let rows = run(r#"{"groupBy":[{"field":"ts","bucket":"YEAR","encoding":"EPOCH_SECONDS","alias":"year"}],"aggregations":[{"function":"COUNT","alias":"n"}]}"#).await;
                assert_eq!(rows.len(), 1);
                assert!(rows[0]["year"].is_number(), "{:?}", rows[0]["year"]);
                assert_eq!(num(&rows[0]["year"]) as i64, 1767225600);

                // millisRoundTrip
                exec(&p, &format!("CREATE TABLE `{db}`.`ms` (`_id` CHAR(26) NOT NULL, `ts` BIGINT NULL, PRIMARY KEY (`_id`))")).await;
                exec(&p, &format!("INSERT INTO `{db}`.`ms` VALUES ('00000000000000000000000001', 1767225600000)")).await;
                let q = agg(r#"{"groupBy":[{"field":"ts","bucket":"YEAR","encoding":"EPOCH_MILLIS","alias":"year"}],"aggregations":[{"function":"COUNT","alias":"n"}]}"#);
                let select = aggregate_builder::page(&Sql::name(&[&db, "ms"]), &q, Cond::None, None, &q.pageable().unwrap(), &r).unwrap();
                let year = &db::fetch(&p, &select.to_sql()).await.unwrap()[0]["year"];
                assert_eq!(num(year) as i64, 1767225600000);

                // timezoneShiftsTheBucket: only meaningful where the zone tables exist.
                let known = db::count_raw(&p, &aggregate_builder::zone_check("Asia/Kolkata")).await.unwrap() == 1;
                if known {
                    let utc = run(r#"{"groupBy":[{"field":"placedAt","bucket":"DAY","alias":"d"}],"aggregations":[{"function":"COUNT","alias":"n"}],"condition":{"field":"note","value":"d"}}"#).await;
                    let ist = run(r#"{"groupBy":[{"field":"placedAt","bucket":"DAY","timezone":"Asia/Kolkata","alias":"d"}],"aggregations":[{"function":"COUNT","alias":"n"}],"condition":{"field":"note","value":"d"}}"#).await;
                    assert!(!utc[0]["d"].is_null());
                    assert_ne!(utc[0]["d"].java_string(), ist[0]["d"].java_string(), "UTC vs IST");
                } else {
                    eprintln!("this server has no time zone tables, which the backend detects and refuses");
                }

                // having
                let q = agg(r#"{"groupBy":[{"field":"region"}],"aggregations":[{"function":"SUM","field":"amount","alias":"total"}],"having":{"field":"total","value":100,"operator":"GREATER_THAN"}}"#);
                assert_eq!(run_aggregate(&p, &table, &q, &r).await.len(), 2, "north 300 and east 400");
                assert_eq!(group_count(&p, &table, &q, &r).await, 2, "the count has to agree with the page it describes");

                // countIsGroups
                let q = agg(r#"{"groupBy":[{"field":"region"}],"aggregations":[{"function":"COUNT","alias":"n"}]}"#);
                assert_eq!(group_count(&p, &table, &q, &r).await, 4);

                // sortAndPage
                let first = run(r#"{"groupBy":[{"field":"region"}],"aggregations":[{"function":"SUM","field":"amount","alias":"total"}],"sort":[{"property":"total","direction":"DESC"}],"size":2}"#).await;
                assert_eq!(first.len(), 2);
                assert_eq!(first[0]["region"], Value::from("east"));
                assert_eq!(first[1]["region"], Value::from("north"));
                let second = run(r#"{"groupBy":[{"field":"region"}],"aggregations":[{"function":"SUM","field":"amount","alias":"total"}],"sort":[{"property":"total","direction":"DESC"}],"size":2,"page":1}"#).await;
                assert_eq!(second[0]["region"], Value::from("south"));

                // conditionBeforeGrouping
                let rows = run(r#"{"groupBy":[{"field":"region"}],"aggregations":[{"function":"SUM","field":"amount","alias":"total"}],"condition":{"field":"region","value":"north"}}"#).await;
                assert_eq!(rows.len(), 1);
                assert_eq!(num(&rows[0]["total"]), 300.0);

                // twoKeys
                let rows = run(r#"{"groupBy":[{"field":"region"},{"field":"placedAt","bucket":"MONTH","alias":"month"}],"aggregations":[{"function":"COUNT","alias":"n"}]}"#).await;
                assert!(rows.len() >= 4, "{}", rows.len());
                assert!(rows[0].contains_key("region") && rows[0].contains_key("month"));

                // textMinMax
                let rows = run(r#"{"aggregations":[{"function":"MIN","field":"note","alias":"first"},{"function":"MAX","field":"note","alias":"last"}]}"#).await;
                assert_eq!(rows[0]["first"], Value::from("a"));
                assert_eq!(rows[0]["last"], Value::from("e"));
            },
            drop_schemas(&p, &[CLIENT], APP),
        )
        .await;
    }
}

// ------------------------------------------------------------------ MySQLAggregatePrecisionIntegrationTest

mod mysql_aggregate_precision_integration_test {
    use super::*;

    const APP: &str = "rtq_prec";

    async fn by_region(p: &MySqlPool, table: &Sql, aggregations: &str) -> IndexMap<String, Document> {
        let q = agg(&format!(r#"{{"groupBy":[{{"field":"region"}}],"aggregations":{aggregations}}}"#));
        let rows = run_aggregate(p, table, &q, &FieldResolver::of(set(&["meta"]))).await;
        rows.into_iter().map(|r| (r["region"].java_string(), r)).collect()
    }

    #[tokio::test]
    #[ignore = "needs the local MySQL"]
    async fn sums_and_averages_keep_their_precision() {
        let p = scratch_pool().await;
        drop_schemas(&p, &[CLIENT], APP).await;
        guarded(
            async {
                let db = schema_of(APP);
                create_schema(&p, &db).await;
                exec(&p, &format!("CREATE TABLE `{db}`.`metrics` (`_id` CHAR(26) NOT NULL, `region` VARCHAR(20) NULL, `spend` DECIMAL(19,4) NULL, `rate` DOUBLE NULL, `qty` INT NULL, `meta` JSON NULL, PRIMARY KEY (`_id`))")).await;
                for (i, region, spend, rate, qty, meta) in [
                    (1, "north", "0.1234", "0.25", "1", r#"'{"cost": 1.25}'"#),
                    (2, "north", "1.5000", "0.5", "2", r#"'{"cost": "2.5"}'"#),
                    (3, "north", "2.2500", "0.125", "4", r#"'{"cost": 0.75}'"#),
                    (4, "south", "12345678901.5678", "1.75", "3", "'{}'"),
                    (5, "south", "NULL", "NULL", "NULL", "NULL"),
                ] {
                    exec(&p, &format!("INSERT INTO `{db}`.`metrics` VALUES ('{i:026}', '{region}', {spend}, {rate}, {qty}, {meta})")).await;
                }
                let table = Sql::name(&[&db, "metrics"]);

                // sumDecimal
                let rows = by_region(&p, &table, r#"[{"function":"SUM","field":"spend","alias":"spend"}]"#).await;
                assert!(same_decimal("3.8734", &rows["north"]["spend"]), "{:?}", rows["north"]["spend"]);
                assert!(same_decimal("12345678901.5678", &rows["south"]["spend"]), "{:?}", rows["south"]["spend"]);

                // avgDecimal
                let rows = by_region(&p, &table, r#"[{"function":"AVG","field":"spend","alias":"avgSpend"}]"#).await;
                assert!((num(&rows["north"]["avgSpend"]) - 1.29113333).abs() < 5e-9, "{:?}", rows["north"]["avgSpend"]);
                assert!(same_decimal("12345678901.5678", &rows["south"]["avgSpend"]));

                // sumDouble
                let rows = by_region(&p, &table, r#"[{"function":"SUM","field":"rate","alias":"rate"},{"function":"AVG","field":"rate","alias":"avgRate"}]"#).await;
                assert!((num(&rows["north"]["rate"]) - 0.875).abs() < 1e-9);
                assert!((num(&rows["north"]["avgRate"]) - 0.875 / 3.0).abs() < 1e-9);

                // sumInt
                let rows = by_region(&p, &table, r#"[{"function":"SUM","field":"qty","alias":"qty"},{"function":"AVG","field":"qty","alias":"avgQty"}]"#).await;
                assert!(same_decimal("7", &rows["north"]["qty"]));
                assert!((num(&rows["north"]["avgQty"]) - 7.0 / 3.0).abs() < 1e-4);

                // sumJsonPath
                let rows = by_region(&p, &table, r#"[{"function":"SUM","field":"meta.cost","alias":"cost"}]"#).await;
                assert!((num(&rows["north"]["cost"]) - 4.5).abs() < 1e-9);
                assert!(rows["south"]["cost"].is_null(), "a group whose rows lack the path sums to NULL");
            },
            drop_schemas(&p, &[CLIENT], APP),
        )
        .await;
    }
}

// ------------------------------------------------------------------ MySQLDateColumnIntegrationTest

mod mysql_date_column_integration_test {
    use super::*;

    const APP: &str = "rtq_date";

    fn storage_schema() -> Schema {
        schema(r#"{"type":"OBJECT","properties":{"placedAt":{"type":"STRING","format":"DATETIME"},"opensAt":{"type":"STRING","format":"TIME"}}}"#)
    }

    fn dates() -> IndexSet<String> {
        type_mapper::date_string_columns(Some(&storage_schema()), None).unwrap()
    }

    async fn fresh_table(p: &MySqlPool, db: &str) {
        exec(p, &format!("DROP TABLE IF EXISTS `{db}`.`orders`")).await;
        let cols = type_mapper::columns(Some(&storage_schema()), None).unwrap();
        exec(p, &format!("USE `{db}`; {}", table_planner::create_table("orders", &cols))).await;
    }

    async fn insert(p: &MySqlPool, db: &str, id: &str, encoded: Document) {
        let mut row = encoded;
        row.insert(ID_COLUMN.into(), Value::from(id));
        insert_row(p, &Sql::name(&[db, "orders"]), &row).await;
    }

    async fn read(p: &MySqlPool, db: &str, id: &str) -> Document {
        let rows = select_where(p, &Sql::name(&[db, "orders"]), Sql::name(&[ID_COLUMN]).equal(Sql::param(Bind::Text(id.into())))).await;
        value_codec::decode(rows.into_iter().next().unwrap(), &none(), &dates(), &none(), &none())
    }

    fn row(placed_at: &str, opens_at: Option<&str>) -> Document {
        let mut m = Document::new();
        m.insert("placedAt".into(), Value::from(placed_at));
        m.insert("opensAt".into(), opens_at.map(Value::from).unwrap_or(Value::Null));
        m
    }

    #[tokio::test]
    #[ignore = "needs the local MySQL"]
    async fn dates_are_stored_as_utc_instants() {
        let p = scratch_pool().await;
        drop_schemas(&p, &[CLIENT], APP).await;
        guarded(
            async {
                let db = schema_of(APP);
                create_schema(&p, &db).await;

                // offsetStoredAsUtc
                fresh_table(&p, &db).await;
                insert(&p, &db, "a", value_codec::encode(&row("2026-01-15T10:00:00+05:30", Some("10:00:00+05:30")), &none(), &dates(), &none())).await;
                let back = read(&p, &db, "a").await;
                assert_eq!(back["placedAt"], Value::from("2026-01-15T04:30:00"));
                assert_eq!(back["opensAt"], Value::from("04:30:00"));

                // zuluWithMillis
                fresh_table(&p, &db).await;
                insert(&p, &db, "b", value_codec::encode(&row("2026-01-15T10:00:00.123Z", Some("10:00:00Z")), &none(), &dates(), &none())).await;
                let back = read(&p, &db, "b").await;
                assert_eq!(back["placedAt"], Value::from("2026-01-15T10:00:00.123"));
                assert_eq!(back["opensAt"], Value::from("10:00:00"));

                // noOffset
                fresh_table(&p, &db).await;
                insert(&p, &db, "c", value_codec::encode(&row("2026-01-20T10:00:00", Some("10:00:00")), &none(), &dates(), &none())).await;
                assert_eq!(read(&p, &db, "c").await["placedAt"], Value::from("2026-01-20T10:00:00"));

                // sessionIsUtc
                let now = &rows(&p, "SELECT NOW() AS n, UTC_TIMESTAMP() AS u").await[0];
                assert_eq!(now["n"].java_string()[..16], now["u"].java_string()[..16]);

                // offsetIsNormalisedNotPreserved: not encoded at all, so MySQL does the folding.
                fresh_table(&p, &db).await;
                insert(&p, &db, "d", value_codec::encode(&row("2026-01-15T10:00:00+05:30", None), &none(), &none(), &none())).await;
                assert_eq!(read(&p, &db, "d").await["placedAt"], Value::from("2026-01-15T04:30:00"));
            },
            drop_schemas(&p, &[CLIENT], APP),
        )
        .await;
    }
}

// ------------------------------------------------------------------ MySQLGeneratedSqlIntegrationTest

mod mysql_generated_sql_integration_test {
    use super::*;

    const APP: &str = "rtq_gen";

    fn storage_schema() -> Schema {
        schema(
            r#"{"type":"OBJECT","properties":{
                "region":{"type":"STRING","maxLength":40},"channel":{"type":"STRING","maxLength":40},
                "amount":{"type":"DOUBLE"},"quantity":{"type":"INTEGER"},"active":{"type":"BOOLEAN"},
                "notes":{"type":"STRING"},"placedAt":{"type":"STRING","format":"DATETIME"},"payload":{"type":"OBJECT"}}}"#,
        )
    }

    fn data_type(db: &str, column: &str) -> String {
        format!("SELECT DATA_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = '{db}' AND TABLE_NAME = 'sales' AND COLUMN_NAME = '{column}'")
    }

    #[tokio::test]
    #[ignore = "needs the local MySQL"]
    async fn the_generated_ddl_and_filters_run_on_mysql() {
        let p = scratch_pool().await;
        drop_schemas(&p, &[CLIENT], APP).await;
        guarded(
            async {
                let db = schema_of(APP);
                create_schema(&p, &db).await;
                let create = format!("USE `{db}`; {}", table_planner::create_table("sales", &type_mapper::columns(Some(&storage_schema()), None).unwrap()));
                exec(&p, &create).await;
                let table = Sql::name(&[&db, "sales"]);
                for (region, channel, amount, qty, active) in
                    [("North", "Web", 100.0, 1, true), ("North", "Retail", 250.0, 2, true), ("South", "Web", 70.0, 3, false), ("East", "Partner", 410.0, 4, true)]
                {
                    let mut row = Document::new();
                    row.insert("_id".into(), Value::from(appdata::ulid::ulid()));
                    row.insert("region".into(), Value::from(region));
                    row.insert("channel".into(), Value::from(channel));
                    row.insert("amount".into(), Value::Double(amount));
                    row.insert("quantity".into(), Value::Int(qty));
                    row.insert("active".into(), Value::Bool(active));
                    insert_row(&p, &table, &row).await;
                }
                let r = FieldResolver::of(none());
                let count = |c: &str| {
                    let cond = filter_builder::build(Some(&condition(c)), &r).unwrap();
                    let (p, table) = (&p, &table);
                    async move { select_where(p, table, cond).await.len() }
                };

                // Ddl.tableExistsWithEveryColumn
                let names: Vec<String> = rows(&p, &format!("SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = '{db}' AND TABLE_NAME = 'sales'"))
                    .await
                    .iter()
                    .map(|r| r.values().next().unwrap().java_string())
                    .collect();
                for c in ["_id", "region", "channel", "amount", "quantity", "active", "notes", "placedAt", "payload"] {
                    assert!(names.contains(&c.to_string()), "{c} in {names:?}");
                }
                // Ddl.dateIsARealDateColumn
                assert_eq!(scalar(&p, &data_type(&db, "placedAt")).await, "datetime");
                // Ddl.unboundedStringIsText
                assert_eq!(scalar(&p, &data_type(&db, "notes")).await, "text");
                // Ddl.ulidFitsThePrimaryKey
                assert_eq!(scalar(&p, &format!("SELECT `_id` FROM `{db}`.`sales` LIMIT 1")).await.len(), 26);
                // Ddl.createIsIdempotent
                exec(&p, &create).await;

                // Filters
                assert_eq!(count(r#"{"field":"region","operator":"EQUALS","value":"North"}"#).await, 2);
                assert_eq!(count(r#"{"field":"amount","operator":"GREATER_THAN","value":200}"#).await, 2);
                assert_eq!(count(r#"{"field":"amount","operator":"LESS_THAN","value":100}"#).await, 1);
                assert_eq!(count(r#"{"field":"amount","operator":"BETWEEN","value":100,"toValue":300}"#).await, 2);
                assert_eq!(count(r#"{"field":"region","operator":"IN","value":"North,South"}"#).await, 3);
                assert_eq!(count(r#"{"field":"channel","operator":"STRING_LOOSE_EQUAL","value":"eb"}"#).await, 2);
                assert_eq!(count(r#"{"field":"active","operator":"IS_TRUE"}"#).await, 3);
                assert_eq!(count(r#"{"field":"active","operator":"IS_FALSE"}"#).await, 1);
                assert_eq!(count(r#"{"field":"notes","operator":"IS_NULL"}"#).await, 4);
                assert_eq!(count(r#"{"field":"region","operator":"EQUALS","value":"North","negate":true}"#).await, 2);
                let and = r#"{"operator":"AND","conditions":[{"field":"region","operator":"EQUALS","value":"North"},{"field":"channel","operator":"EQUALS","value":"Web"}]}"#;
                assert_eq!(count(and).await, 1);
                // deMorganHoldsInTheDatabase
                let not_and = r#"{"operator":"AND","negate":true,"conditions":[{"field":"region","operator":"EQUALS","value":"North"},{"field":"channel","operator":"EQUALS","value":"Web"}]}"#;
                assert_eq!(count(not_and).await, 3);
            },
            drop_schemas(&p, &[CLIENT], APP),
        )
        .await;
    }
}

// ------------------------------------------------------------------ MySQLJoinIntegrationTest

mod mysql_join_integration_test {
    use super::*;

    const APP: &str = "rtq_joindata";

    fn id(i: i32) -> String {
        format!("{i:026}")
    }

    fn customer_join(db: &str, alias: &str, join_type: JoinType) -> JoinedTable {
        let types: IndexMap<String, String> =
            [("_id", "CHAR(26)"), ("name", "VARCHAR(40)"), ("region", "VARCHAR(20)"), ("profile", "JSON")].iter().map(|(a, b)| (a.to_string(), b.to_string())).collect();
        JoinedTable::new(alias, Sql::name(&[db, "customers"]), "customer", "_id", join_type, types, set(&["profile"]), none())
    }

    fn resolver_for(joins: &[JoinedTable]) -> FieldResolver {
        FieldResolver::joined(PARENT, none(), joins.iter().map(|j| (j.alias.clone(), j.clone())).collect(), IndexMap::new())
    }

    async fn select(p: &MySqlPool, db: &str, joins: &[JoinedTable], c: Option<&str>) -> Vec<Document> {
        let resolver = resolver_for(joins);
        let cond = filter_builder::build(c.map(condition).as_ref(), &resolver).unwrap();
        let fields = join_planner::selection(&set(&["_id", "amount", "customer"]), joins);
        let s = Select::fields(fields, join_planner::from(&Sql::name(&[db, "orders"]), joins)).filter(cond);
        db::fetch(p, &s.to_sql()).await.unwrap().into_iter().map(|r| join_planner::nest(r, joins, &[])).collect()
    }

    async fn aggregate(p: &MySqlPool, db: &str, joins: &[JoinedTable], q: &str) -> Vec<Document> {
        let q = agg(q);
        let resolver = resolver_for(joins);
        run_aggregate(p, &join_planner::from(&Sql::name(&[db, "orders"]), joins), &q, &resolver).await
    }

    #[tokio::test]
    #[ignore = "needs the local MySQL"]
    async fn joins_on_real_tables() {
        let p = scratch_pool().await;
        drop_schemas(&p, &[CLIENT], APP).await;
        guarded(
            async {
                let db = schema_of(APP);
                create_schema(&p, &db).await;
                exec(&p, &format!("CREATE TABLE `{db}`.`customers` (`_id` CHAR(26) NOT NULL, `name` VARCHAR(40) NULL, `region` VARCHAR(20) NULL, `profile` JSON NULL, PRIMARY KEY (`_id`))")).await;
                exec(&p, &format!("CREATE TABLE `{db}`.`orders` (`_id` CHAR(26) NOT NULL, `amount` DOUBLE NULL, `customer` CHAR(26) NULL, PRIMARY KEY (`_id`))")).await;
                exec(&p, &format!("CREATE TABLE `{db}`.`nodes` (`_id` CHAR(26) NOT NULL, `label` VARCHAR(20) NULL, `parent` CHAR(26) NULL, PRIMARY KEY (`_id`))")).await;
                for (i, name, region, tier) in [(1, "Asha", "north", "gold"), (2, "Bo", "south", "silver"), (3, "Cy", "north", "gold")] {
                    exec(&p, &format!(r#"INSERT INTO `{db}`.`customers` VALUES ('{}', '{name}', '{region}', '{{"tier":"{tier}"}}')"#, id(i))).await;
                }
                for (i, amount, customer) in [(1, 100, Some(1)), (2, 200, Some(1)), (3, 50, Some(2)), (4, 400, Some(3)), (5, 7, None), (6, 9, Some(99))] {
                    let c = customer.map(|c| format!("'{}'", id(c))).unwrap_or_else(|| "NULL".into());
                    exec(&p, &format!("INSERT INTO `{db}`.`orders` VALUES ('{}', {amount}, {c})", id(i))).await;
                }
                exec(&p, &format!("INSERT INTO `{db}`.`nodes` VALUES ('{}', 'root', NULL), ('{}', 'child', '{}')", id(1), id(2), id(1))).await;

                let left = [customer_join(&db, "customer", JoinType::Left)];
                let inner = [customer_join(&db, "customer", JoinType::Inner)];
                let by_id = |i: i32| format!(r#"{{"field":"_id","value":"{}"}}"#, id(i));

                // leftKeepsEveryone
                assert_eq!(select(&p, &db, &left, None).await.len(), 6);
                // innerDropsUnmatched
                assert_eq!(select(&p, &db, &inner, None).await.len(), 4);
                // nestedObject
                let rows = select(&p, &db, &inner, Some(&by_id(1))).await;
                assert_eq!(rows.len(), 1);
                let customer = rows[0]["customer"].as_object().expect("a nested customer");
                assert_eq!(customer["name"], Value::from("Asha"));
                assert_eq!(customer["region"], Value::from("north"));
                // unmatchedLeavesNothing
                let rows = select(&p, &db, &left, Some(&by_id(6))).await;
                assert_eq!(rows.len(), 1);
                assert!(!rows[0].contains_key("customer"), "{:?}", rows[0]);
                // filterAcrossTheJoin
                assert_eq!(select(&p, &db, &inner, Some(r#"{"field":"customer.region","value":"north"}"#)).await.len(), 3);
                // filterOnJoinedJsonPath
                let rows = select(&p, &db, &inner, Some(r#"{"field":"customer.profile.tier","value":"silver"}"#)).await;
                assert_eq!(rows.len(), 1);
                assert_eq!(num(&rows[0]["amount"]), 50.0);
                // bareRelationIsTheId
                assert_eq!(select(&p, &db, &left, Some(&format!(r#"{{"field":"customer","value":"{}"}}"#, id(1)))).await.len(), 2);

                // revenueByJoinedRegion
                let rows = aggregate(&p, &db, &inner, r#"{"groupBy":[{"field":"customer.region","alias":"region"}],"aggregations":[{"function":"SUM","field":"amount","alias":"total"}]}"#).await;
                assert_eq!(rows.len(), 2);
                let by_region: IndexMap<String, f64> = rows.iter().map(|r| (r["region"].java_string(), num(&r["total"]))).collect();
                assert_eq!(by_region["north"], 700.0);
                assert_eq!(by_region["south"], 50.0);
                // measureFromTheJoinedSide
                let rows = aggregate(&p, &db, &inner, r#"{"groupBy":[{"field":"customer.region","alias":"region"}],"aggregations":[{"function":"COUNT","field":"customer.name","alias":"named"}]}"#).await;
                assert_eq!(rows.len(), 2);
                // leftJoinKeepsUnmatchedInAggregate
                let rows = aggregate(&p, &db, &left, r#"{"groupBy":[{"field":"customer.region","alias":"region"}],"aggregations":[{"function":"SUM","field":"amount","alias":"total"}]}"#).await;
                assert_eq!(rows.len(), 3);
                let orphaned: f64 = rows.iter().filter(|r| r["region"].is_null()).map(|r| num(&r["total"])).sum();
                assert_eq!(orphaned, 16.0, "7 + 9");
                // countAcrossTheJoin
                let q = agg(r#"{"groupBy":[{"field":"customer.region","alias":"region"}],"aggregations":[{"function":"SUM","field":"amount","alias":"total"}]}"#);
                let resolver = resolver_for(&inner);
                let counted = aggregate_builder::count(&join_planner::from(&Sql::name(&[&db, "orders"]), &inner), &q, Cond::None, None, &resolver).unwrap();
                assert_eq!(db::count(&p, &counted.to_sql()).await.unwrap(), 2, "two regions, not four orders");

                // selfJoin
                let types: IndexMap<String, String> = [("_id", "CHAR(26)"), ("label", "VARCHAR(20)")].iter().map(|(a, b)| (a.to_string(), b.to_string())).collect();
                let parent = [JoinedTable::new("up", Sql::name(&[&db, "nodes"]), "parent", "_id", JoinType::Inner, types, none(), none())];
                let resolver = resolver_for(&parent);
                let cond = filter_builder::build(Some(&condition(r#"{"field":"up.label","value":"root"}"#)), &resolver).unwrap();
                let s = Select::fields(join_planner::selection(&set(&["_id", "label", "parent"]), &parent), join_planner::from(&Sql::name(&[&db, "nodes"]), &parent)).filter(cond);
                let rows: Vec<Document> = db::fetch(&p, &s.to_sql()).await.unwrap().into_iter().map(|r| join_planner::nest(r, &parent, &[])).collect();
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0]["label"], Value::from("child"));

                // twoJoinsOneTarget
                let two = [customer_join(&db, "customer", JoinType::Left), customer_join(&db, "alt", JoinType::Left)];
                let rows = select(&p, &db, &two, Some(&by_id(1))).await;
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0]["customer"].as_object().unwrap()["name"], Value::from("Asha"));
                assert_eq!(rows[0]["alt"].as_object().unwrap()["name"], Value::from("Asha"));
            },
            drop_schemas(&p, &[CLIENT], APP),
        )
        .await;
    }
}

// ------------------------------------------------------------------ MySQLJsonColumnIntegrationTest

mod mysql_json_column_integration_test {
    use super::*;

    const APP: &str = "rtq_json";

    fn storage_schema() -> Schema {
        schema(
            r#"{"type":"OBJECT","properties":{"name":{"type":"STRING","maxLength":60},
                "address":{"type":"OBJECT","properties":{"city":{"type":"STRING","maxLength":60},"floor":{"type":"INTEGER"}}},
                "tags":{"type":"ARRAY","items":{"type":"STRING"}}}}"#,
        )
    }

    fn json() -> IndexSet<String> {
        type_mapper::json_columns(Some(&storage_schema()), None).unwrap()
    }

    async fn fresh_table(p: &MySqlPool, db: &str) {
        exec(p, &format!("DROP TABLE IF EXISTS `{db}`.`people`")).await;
        exec(p, &format!("USE `{db}`; {}", table_planner::create_table("people", &type_mapper::columns(Some(&storage_schema()), None).unwrap()))).await;
    }

    async fn insert(p: &MySqlPool, db: &str, id: &str, name: &str, address: Value, tags: Value) {
        let mut row = Document::new();
        row.insert(ID_COLUMN.into(), Value::from(id));
        row.insert("name".into(), Value::from(name));
        row.insert("address".into(), address);
        row.insert("tags".into(), tags);
        insert_row(p, &Sql::name(&[db, "people"]), &value_codec::encode(&row, &json(), &none(), &none())).await;
    }

    async fn select(p: &MySqlPool, db: &str, c: Option<&str>) -> Vec<Document> {
        let cond = filter_builder::build_json(c.map(condition).as_ref(), json()).unwrap();
        select_where(p, &Sql::name(&[db, "people"]), cond)
            .await
            .into_iter()
            .map(|r| value_codec::decode(r, &json(), &none(), &none(), &none()))
            .collect()
    }

    #[tokio::test]
    #[ignore = "needs the local MySQL"]
    async fn nested_values_live_in_json_columns() {
        let p = scratch_pool().await;
        drop_schemas(&p, &[CLIENT], APP).await;
        guarded(
            async {
                let db = schema_of(APP);
                create_schema(&p, &db).await;

                // columnTypes
                fresh_table(&p, &db).await;
                let types: IndexMap<String, String> = rows(&p, &format!("SELECT COLUMN_NAME, DATA_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = '{db}' AND TABLE_NAME = 'people'"))
                    .await
                    .iter()
                    .map(|r| {
                        let mut vals = r.values();
                        (vals.next().unwrap().java_string(), vals.next().unwrap().java_string())
                    })
                    .collect();
                assert_eq!(types["name"], "varchar");
                assert_eq!(types["address"], "json");
                assert_eq!(types["tags"], "json");
                assert_eq!(types["_id"], "char");

                // objectRoundTrip
                fresh_table(&p, &db).await;
                insert(&p, &db, "01A00000000000000000000001", "Asha", v(r#"{"city":"Pune","floor":3}"#), v(r#"["a","b"]"#)).await;
                let back = &select(&p, &db, None).await[0];
                let address = back["address"].as_object().expect("an object");
                assert_eq!(address["city"], Value::from("Pune"));
                assert_eq!(address["floor"], Value::Int(3));
                assert_eq!(back["tags"], v(r#"["a","b"]"#));

                // nullStays
                fresh_table(&p, &db).await;
                insert(&p, &db, "01A00000000000000000000002", "Bo", Value::Null, Value::Null).await;
                let back = &select(&p, &db, None).await[0];
                assert!(back["address"].is_null());
                assert!(back["tags"].is_null());

                // unencodedIsRejected
                fresh_table(&p, &db).await;
                let refused = db::execute_raw(&p, &format!("INSERT INTO `{db}`.`people` (`_id`, `address`) VALUES ('01A00000000000000000000003', 'Pune')")).await;
                assert!(refused.is_err());

                // filterByPath
                fresh_table(&p, &db).await;
                insert(&p, &db, "01A00000000000000000000004", "Asha", v(r#"{"city":"Pune"}"#), Value::Null).await;
                insert(&p, &db, "01A00000000000000000000005", "Bo", v(r#"{"city":"Mumbai"}"#), Value::Null).await;
                let found = select(&p, &db, Some(r#"{"field":"address.city","value":"Pune"}"#)).await;
                assert_eq!(found.len(), 1);
                assert_eq!(found[0]["name"], Value::from("Asha"));

                // unquoteMatters
                fresh_table(&p, &db).await;
                insert(&p, &db, "01A00000000000000000000006", "Asha", v(r#"{"city":"Pune"}"#), Value::Null).await;
                let quoted = db::count_raw(&p, &format!("SELECT COUNT(*) FROM `{db}`.`people` WHERE JSON_EXTRACT(`address`, '$.city') LIKE 'Pun%'")).await.unwrap();
                assert_eq!(quoted, 0, "without the unquote an anchored LIKE matches the quote, not the letter");
                assert_eq!(select(&p, &db, Some(r#"{"field":"address.city","value":"Pun%","operator":"LIKE"}"#)).await.len(), 1);

                // numericPath
                fresh_table(&p, &db).await;
                insert(&p, &db, "01A00000000000000000000013", "Asha", v(r#"{"city":"Pune","floor":12}"#), Value::Null).await;
                insert(&p, &db, "01A00000000000000000000014", "Bo", v(r#"{"city":"Pune","floor":3}"#), Value::Null).await;
                let gt = select(&p, &db, Some(r#"{"field":"address.floor","value":9,"operator":"GREATER_THAN"}"#)).await;
                assert_eq!(gt.len(), 1);
                assert_eq!(gt[0]["name"], Value::from("Asha"));

                // missingPath
                fresh_table(&p, &db).await;
                insert(&p, &db, "01A00000000000000000000007", "Asha", v(r#"{"city":"Pune"}"#), Value::Null).await;
                insert(&p, &db, "01A00000000000000000000008", "Bo", v(r#"{"pin":"400001"}"#), Value::Null).await;
                assert_eq!(select(&p, &db, Some(r#"{"field":"address.city","value":"Pune"}"#)).await.len(), 1);

                // deeplyNested
                fresh_table(&p, &db).await;
                let deep = v(r#"{"city":"Pune","geo":{"lat":18.5,"lng":73.8,"box":[{"x":1}]}}"#);
                insert(&p, &db, "01A00000000000000000000009", "Asha", deep.clone(), Value::Null).await;
                let back = select(&p, &db, None).await[0]["address"].clone();
                // Compared as maps, as Java's Map.equals does: MySQL orders JSON keys its own way.
                let (Value::Object(a), Value::Object(b)) = (&back, &deep) else { panic!("{back:?}") };
                assert_eq!(a.len(), b.len());
                assert!(b.iter().all(|(k, w)| match (a.get(k), w) {
                    (Some(Value::Object(x)), Value::Object(y)) => x.len() == y.len() && y.iter().all(|(k2, w2)| x.get(k2) == Some(w2)),
                    (got, want) => got == Some(want),
                }), "{back:?}");

                // mixedFilter
                fresh_table(&p, &db).await;
                insert(&p, &db, "01A00000000000000000000010", "Asha", v(r#"{"city":"Pune"}"#), Value::Null).await;
                insert(&p, &db, "01A00000000000000000000011", "Asha", v(r#"{"city":"Mumbai"}"#), Value::Null).await;
                insert(&p, &db, "01A00000000000000000000012", "Bo", v(r#"{"city":"Pune"}"#), Value::Null).await;
                let found = select(&p, &db, Some(r#"{"operator":"AND","conditions":[{"field":"name","value":"Asha"},{"field":"address.city","value":"Pune"}]}"#)).await;
                assert_eq!(found.len(), 1);
                assert!(found[0]["_id"].java_string().ends_with("10"));
            },
            drop_schemas(&p, &[CLIENT], APP),
        )
        .await;
    }
}

// ------------------------------------------------------------------ MySQLReceivedFieldNamesIntegrationTest

mod mysql_received_field_names_integration_test {
    use super::*;

    const APP: &str = "rtq_recv";

    fn physical() -> PhysicalSchema {
        column_names::physical(schema(
            r#"{"type":"OBJECT","required":["IFSC Code"],"properties":{
                "IFSC Code":{"type":"STRING","maxLength":20},"Virtual Account ":{"type":"STRING","maxLength":40},
                "Amount":{"type":"DOUBLE"},"Remitter Name":{"type":"STRING","maxLength":100},"Bank Details":{"type":"OBJECT"}}}"#,
        ))
    }

    async fn read(p: &MySqlPool, db: &str, filter: Option<&str>, sort_by: &str) -> Vec<Document> {
        let physical = physical();
        let resolver = FieldResolver::of(type_mapper::json_columns(physical.schema(), None).unwrap());
        let cond = filter_builder::build(filter.map(condition).as_ref(), &resolver).unwrap();
        let s = Select::star(Sql::name(&[db, "hdfc"])).filter(cond).order(vec![resolver.resolve(sort_by).unwrap().desc()]);
        db::fetch(p, &s.to_sql()).await.unwrap().into_iter().map(|r| physical.to_fields(r)).collect()
    }

    #[tokio::test]
    #[ignore = "needs the local MySQL"]
    async fn received_field_names_reach_their_columns() {
        let p = scratch_pool().await;
        drop_schemas(&p, &[CLIENT], APP).await;
        guarded(
            async {
                let db = schema_of(APP);
                create_schema(&p, &db).await;
                let physical = physical();
                let cols = type_mapper::columns(physical.schema(), None).unwrap();
                exec(&p, &format!("USE `{db}`; {}", table_planner::create_table("hdfc", &cols))).await;
                let s = Storage::from_value(&v(
                    r#"{"name":"hdfc","appCode":"cxapp","clientCode":"SYSTEM","version":1,"uniqueName":"hdfc",
                        "indexes":{"byIfsc":{"unique":true,"fields":[{"fieldName":"IFSC Code"}]}},"textIndexFields":["Remitter Name"]}"#,
                ))
                .unwrap();
                let names: IndexSet<String> = cols.iter().map(|c| c.name().to_string()).collect();
                for index in indexes::desired(&s, &names) {
                    exec(&p, &index.ddl(&db, "hdfc")).await;
                }
                for (ifsc, va, amount, remitter, bank) in
                    [("HDFC0000001", "VA-1", 500.0, "Asha", r#"{"city": "Pune"}"#), ("HDFC0000002", "VA-2", 150.0, "Ravi", r#"{"city": "Hyderabad"}"#)]
                {
                    let mut row = Document::new();
                    row.insert("_id".into(), Value::from(ifsc));
                    row.insert("IFSC Code".into(), Value::from(ifsc));
                    row.insert("Virtual Account ".into(), Value::from(va));
                    row.insert("Amount".into(), Value::Double(amount));
                    row.insert("Remitter Name".into(), Value::from(remitter));
                    row.insert("Bank Details".into(), Value::from(bank));
                    insert_row(&p, &Sql::name(&[&db, "hdfc"]), &column_names::to_columns(&row)).await;
                }

                // ddl
                let columns: Vec<String> = rows(&p, &format!("SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = '{db}' AND TABLE_NAME = 'hdfc'"))
                    .await
                    .iter()
                    .map(|r| r.values().next().unwrap().java_string())
                    .collect();
                for c in ["IFSC_Code", "Virtual_Account_", "Amount", "Remitter_Name"] {
                    assert!(columns.contains(&c.to_string()), "{columns:?}");
                }
                let indexed: Vec<String> = rows(&p, &format!("SELECT DISTINCT COLUMN_NAME FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = '{db}' AND TABLE_NAME = 'hdfc'"))
                    .await
                    .iter()
                    .map(|r| r.values().next().unwrap().java_string())
                    .collect();
                for c in ["IFSC_Code", "Remitter_Name"] {
                    assert!(indexed.contains(&c.to_string()), "{indexed:?}");
                }

                // filterSortAndRead
                let found = read(&p, &db, Some(r#"{"field":"IFSC Code","operator":"EQUALS","value":"HDFC0000002"}"#), "Amount").await;
                assert_eq!(found.len(), 1);
                assert_eq!(found[0]["Virtual Account "], Value::from("VA-2"));
                assert_eq!(found[0]["Remitter Name"], Value::from("Ravi"));
                let all = read(&p, &db, None, "Amount").await;
                assert_eq!(all[0]["IFSC Code"], Value::from("HDFC0000001"));

                // jsonPath
                let found = read(&p, &db, Some(r#"{"field":"Bank Details.city","operator":"EQUALS","value":"Pune"}"#), "Amount").await;
                assert_eq!(found.len(), 1);
                assert_eq!(found[0]["IFSC Code"], Value::from("HDFC0000001"));
            },
            drop_schemas(&p, &[CLIENT], APP),
        )
        .await;
    }
}

// ------------------------------------------------------------------ MySQLVersionRetentionIntegrationTest

mod mysql_version_retention_integration_test {
    use super::*;

    const APP: &str = "rtq_ret";

    fn table(db: &str) -> Sql {
        Sql::name(&[db, &version_table::name_for("thing")])
    }

    async fn wipe(p: &MySqlPool, db: &str, object_id: &str) {
        db::execute(p, &sql::delete(&table(db), &Sql::name(&[version_table::OBJECT_ID]).equal(Sql::param(Bind::Text(object_id.into()))))).await.unwrap();
    }

    async fn version(p: &MySqlPool, db: &str, object_id: &str, days_old: i64) {
        let at = chrono::Utc::now().naive_utc() - chrono::Duration::days(days_old) - chrono::Duration::seconds(days_old);
        let values = vec![
            (ID_COLUMN.to_string(), Bind::Text(appdata::ulid::ulid())),
            (version_table::OBJECT_ID.to_string(), Bind::Text(object_id.into())),
            (version_table::OPERATION.to_string(), Bind::Text("UPDATE".into())),
            (version_table::CREATED_AT.to_string(), Bind::DateTime(at)),
        ];
        db::execute(p, &sql::insert(&table(db), &values)).await.unwrap();
    }

    async fn count(p: &MySqlPool, db: &str, object_id: &str) -> i64 {
        let s = Select::count(table(db)).filter(Sql::name(&[version_table::OBJECT_ID]).equal(Sql::param(Bind::Text(object_id.into()))));
        db::count(p, &s.to_sql()).await.unwrap()
    }

    async fn trim(p: &MySqlPool, db: &str, object_id: &str, days: i32, count: i32) {
        version_table::trim(p, &table(db), object_id, VersionRetention { days, count }).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "needs the local MySQL"]
    async fn history_is_trimmed_to_both_bounds() {
        let p = scratch_pool().await;
        drop_schemas(&p, &[CLIENT], APP).await;
        guarded(
            async {
                let db = schema_of(APP);
                create_schema(&p, &db).await;
                exec(&p, &version_table::create_table(&db, "thing")).await;

                // trimsByAge
                wipe(&p, &db, "age").await;
                for d in [200, 150, 100, 10, 1] {
                    version(&p, &db, "age", d).await;
                }
                assert_eq!(count(&p, &db, "age").await, 5);
                trim(&p, &db, "age", 90, 0).await;
                assert_eq!(count(&p, &db, "age").await, 2, "only the two rows newer than 90 days should remain");

                // trimsByCount
                wipe(&p, &db, "count").await;
                for d in [50, 40, 30, 20, 10] {
                    version(&p, &db, "count", d).await;
                }
                trim(&p, &db, "count", 0, 2).await;
                assert_eq!(count(&p, &db, "count").await, 2);
                let s = Select::fields(vec![Sql::name(&[version_table::CREATED_AT])], table(&db))
                    .filter(Sql::name(&[version_table::OBJECT_ID]).equal(Sql::param(Bind::Text("count".into()))));
                let twenty_days_ago = chrono::Utc::now().naive_utc() - chrono::Duration::days(21);
                for r in db::fetch(&p, &s.to_sql()).await.unwrap() {
                    let Value::LocalDateTime(t) = r[version_table::CREATED_AT] else { panic!("{r:?}") };
                    assert!(t > twenty_days_ago, "the survivors must be the NEWEST two");
                }

                // bothBoundsApply
                wipe(&p, &db, "both").await;
                for d in [300, 5, 4, 3, 2] {
                    version(&p, &db, "both", d).await;
                }
                trim(&p, &db, "both", 90, 2).await;
                assert_eq!(count(&p, &db, "both").await, 2);

                // keepsEverythingWhenUnlimited
                wipe(&p, &db, "unlimited").await;
                for d in [500, 400, 300] {
                    version(&p, &db, "unlimited", d).await;
                }
                trim(&p, &db, "unlimited", 0, 0).await;
                assert_eq!(count(&p, &db, "unlimited").await, 3);

                // isScopedToOneObject
                wipe(&p, &db, "mine").await;
                wipe(&p, &db, "yours").await;
                for d in [300, 200, 100] {
                    version(&p, &db, "mine", d).await;
                    version(&p, &db, "yours", d).await;
                }
                trim(&p, &db, "mine", 90, 0).await;
                assert_eq!(count(&p, &db, "mine").await, 0);
                assert_eq!(count(&p, &db, "yours").await, 3, "another object's history must be untouched");

                // toleratesFewerThanTheBound
                wipe(&p, &db, "few").await;
                version(&p, &db, "few", 1).await;
                trim(&p, &db, "few", 90, 50).await;
                assert_eq!(count(&p, &db, "few").await, 1);
            },
            drop_schemas(&p, &[CLIENT], APP),
        )
        .await;
    }
}

// ------------------------------------------------------------------ MySQLNullAndBooleanIntegrationTest

mod mysql_null_and_boolean_integration_test {
    use super::*;

    const APP: &str = "rtq_nullbool";

    /// `MySQLNullAndBooleanTest.schema()`.
    fn physical() -> PhysicalSchema {
        column_names::physical(schema(
            r#"{"type":"OBJECT","required":["name"],"properties":{
                "name":{"type":"STRING","maxLength":100},"description":{"type":"STRING","maxLength":200},
                "active":{"type":"BOOLEAN"},"optIn":{"type":["BOOLEAN","NULL"]},"count":{"type":"INTEGER"},
                "IFSC Flag":{"type":"BOOLEAN"}}}"#,
        ))
    }

    /// `MySQLNullAndBooleanTest.storage()`.
    fn project() -> Storage {
        Storage::from_value(&v(r#"{"name":"project","appCode":"leadzumptwo","clientCode":"SYSTEM","version":1,"uniqueName":"project_t"}"#)).unwrap()
    }

    fn by_id() -> Cond {
        Sql::name(&["_id"]).equal(Sql::param(Bind::Text("426".into())))
    }

    async fn seed(p: &MySqlPool, db: &str) {
        exec(p, &format!("DELETE FROM `{db}`.`project_t`")).await;
        insert_row(p, &Sql::name(&[db, "project_t"]), &doc(r#"{"_id":"426","name":"Tower A","description":"unlink-test","active":true,"optIn":false,"count":3}"#)).await;
    }

    async fn update(p: &MySqlPool, db: &str, data: &str, override_: bool) -> appdata::AppDataResult<u64> {
        let values = update_values(&project(), &physical(), &doc(data), Some(override_)).unwrap();
        db::execute(p, &sql::update(&Sql::name(&[db, "project_t"]), &values, &by_id())).await
    }

    async fn read(p: &MySqlPool, db: &str) -> Document {
        let physical = physical();
        let decoding = Decoding::of(&physical, None).unwrap();
        decoding.row(select_where(p, &Sql::name(&[db, "project_t"]), by_id()).await.remove(0), &physical)
    }

    #[tokio::test]
    #[ignore = "needs the local MySQL"]
    async fn nulls_clear_and_booleans_read_back() {
        let p = scratch_pool().await;
        drop_schemas(&p, &[CLIENT], APP).await;
        guarded(
            async {
                let db = schema_of(APP);
                create_schema(&p, &db).await;
                exec(&p, &format!("USE `{db}`; {}", table_planner::create_table("project_t", &type_mapper::columns(physical().schema(), None).unwrap()))).await;

                // patchNullClears
                seed(&p, &db).await;
                update(&p, &db, r#"{"_id":"426","description":null}"#, false).await.unwrap();
                let row = read(&p, &db).await;
                assert!(row["description"].is_null(), "{row:?}");
                assert_eq!(row["name"], Value::from("Tower A"));
                assert_eq!(num(&row["count"]), 3.0);

                // putReplaces
                seed(&p, &db).await;
                update(&p, &db, r#"{"_id":"426","name":"Tower B","description":null,"active":false}"#, true).await.unwrap();
                let row = read(&p, &db).await;
                assert_eq!(row["name"], Value::from("Tower B"));
                assert!(row["description"].is_null());
                assert!(row["count"].is_null(), "left out of a PUT, so cleared: {row:?}");
                assert!(row["optIn"].is_null());
                assert_eq!(row["active"], Value::Bool(false));

                // booleansReadBack
                seed(&p, &db).await;
                let row = read(&p, &db).await;
                assert_eq!(row["active"], Value::Bool(true), "{row:?}");
                assert_eq!(row["optIn"], Value::Bool(false));
                assert!(row.contains_key("IFSC Flag"));
                assert!(row["IFSC Flag"].is_null());
                assert!(row["count"].is_number());

                // notNullIsNamed
                seed(&p, &db).await;
                let e = update(&p, &db, r#"{"_id":"426","name":null}"#, false).await.unwrap_err();
                assert_eq!(null_column(&db::message(&e)).as_deref(), Some("name"), "unrecognised: {e:?}");
                assert!(!read(&p, &db).await["name"].is_null());
            },
            drop_schemas(&p, &[CLIENT], APP),
        )
        .await;
    }
}

// ------------------------------------------------------------------ MySQLJoinOperationsIntegrationTest

/// The engine half of `MySQLJoinOperationsIntegrationTest` (core). Java drives it through
/// `AppDataService` with an app-level MySQL connection; here the same storages and rows go
/// straight to `MySqlAppDataService`, the relations resolved through `Storages`.
mod mysql_join_operations_integration_test {
    use super::*;

    const APP: &str = "rtq_joinops";

    fn customers(read_auth: Option<&str>) -> Storage {
        let mut s = storage(APP, "customers", r#"{"version":1,"schema":{"type":"OBJECT","properties":{"name":{"type":"STRING","maxLength":40},"region":{"type":"STRING","maxLength":20}}}}"#);
        s.read_auth = read_auth.map(str::to_string);
        s
    }

    fn tags() -> Storage {
        storage(APP, "tags", r#"{"version":1,"schema":{"type":"OBJECT","properties":{"label":{"type":"STRING","maxLength":20}}}}"#)
    }

    /// `customer` is deliberately absent from the schema: the column comes from the relation.
    fn orders() -> Storage {
        storage(
            APP,
            "orders",
            r#"{"version":1,"relations":{"customer":{"storageName":"customers","relationType":"TO_ONE","fieldName":"_id"},
                "labels":{"storageName":"tags","relationType":"TO_MANY","fieldName":"_id"}},
                "schema":{"type":"OBJECT","properties":{"amount":{"type":"DOUBLE"}}}}"#,
        )
    }

    struct Fixture {
        e: appdata::mysql::MySqlAppDataService,
        c: Connection,
        storages: Arc<Storages>,
    }

    impl Fixture {
        async fn given_storages(&self, customer_read_auth: Option<&str>) {
            self.storages.put(&customers(customer_read_auth)).await;
            self.storages.put(&tags()).await;
            self.storages.put(&orders()).await;
        }

        async fn write_customer(&self, name: &str, region: &str) -> String {
            let row = data(&format!(r#"{{"name":"{name}","region":"{region}"}}"#));
            self.e.create(&cx(), CLIENT, Some(&self.c), &customers(None), row).await.unwrap()["_id"].java_string()
        }

        async fn write_order(&self, amount: f64, customer: Option<&str>) {
            let mut row = doc(&format!(r#"{{"amount":{amount}}}"#));
            row.insert("customer".into(), customer.map(Value::from).unwrap_or(Value::Null));
            self.e.create(&cx(), CLIENT, Some(&self.c), &orders(), DataObject::of(row)).await.unwrap();
        }

        async fn given_rows(&self) -> (String, String) {
            let asha = self.write_customer("Asha", "north").await;
            let bo = self.write_customer("Bo", "south").await;
            self.write_order(100.0, Some(&asha)).await;
            self.write_order(200.0, Some(&asha)).await;
            self.write_order(50.0, Some(&bo)).await;
            self.write_order(7.0, None).await;
            (asha, bo)
        }

        async fn read(&self, cx: &Ctx, s: &Storage, q: &str) -> appdata::AppDataResult<Page<Document>> {
            self.e.read_page(cx, CLIENT, Some(&self.c), s, &query(q)).await
        }

        async fn aggregate(&self, s: &Storage, q: &str) -> Page<Document> {
            self.e.aggregate(&cx(), CLIENT, Some(&self.c), s, &agg(q)).await.unwrap()
        }
    }

    fn named<'a>(page: &'a Page<Document>, name: &str) -> &'a Document {
        page.content.iter().find(|r| r["name"] == Value::from(name)).expect(name)
    }

    #[tokio::test]
    #[ignore = "needs the local MySQL"]
    async fn joins_subqueries_and_refusals_through_the_engine() {
        let storages = Arc::new(Storages::default());
        let f = Fixture { e: mysql_engine(storages.clone()), c: conn().await, storages };
        let p = pool(&f.e).await;
        wait_for_headroom(&p).await;
        drop_schemas(&p, &[CLIENT], APP).await;
        guarded(
            async {
                let db = schema_of(APP);
                f.given_storages(None).await;
                let (asha, _bo) = f.given_rows().await;
                let (o, cu) = (orders(), customers(None));

                // RelationColumn.relationHasAColumn
                assert_eq!(column_type(&p, &db, "rtq_joinops_orders", "customer").await, "char(26) YES");
                assert_eq!(column_type(&p, &db, "rtq_joinops_orders", "_id").await, "char(26) NO");
                // RelationColumn.toManyIsJson
                assert_eq!(column_type(&p, &db, "rtq_joinops_orders", "labels").await, "json YES");
                // RelationColumn.valueRoundTrips
                let page = f.read(&cx(), &o, "{}").await.unwrap();
                assert_eq!(page.content[0]["customer"], Value::from(asha.as_str()));

                // Reading.nested
                let page = f.read(&cx(), &o, r#"{"joins":[{"relation":"customer","type":"INNER"}]}"#).await.unwrap();
                assert_eq!(page.content.len(), 3);
                assert!(page.content[0]["customer"].as_object().is_some_and(|c| !c["region"].is_null()));
                // Reading.filterAcross
                let page = f
                    .read(&cx(), &o, r#"{"joins":[{"relation":"customer","type":"INNER"}],"condition":{"field":"customer.region","value":"north"},"count":true}"#)
                    .await
                    .unwrap();
                assert_eq!(page.content.len(), 2);
                assert_eq!(page.total, 2, "the count has to agree with the page");
                // Reading.leftKeepsOrphans
                assert_eq!(f.read(&cx(), &o, r#"{"joins":[{"relation":"customer","type":"LEFT"}]}"#).await.unwrap().content.len(), 4);
                // Reading.sortAcross
                let page = f.read(&cx(), &o, r#"{"joins":[{"relation":"customer","type":"INNER"}],"sort":[{"property":"customer.region","direction":"ASC"}]}"#).await.unwrap();
                assert_eq!(page.content[0]["customer"].as_object().unwrap()["region"], Value::from("north"));
                // Reading.noJoinsUnchanged
                let page = f.read(&cx(), &o, "{}").await.unwrap();
                assert_eq!(page.content.len(), 4);
                assert!(page.content[0]["customer"].as_object().is_none());

                // Aggregating.revenueByJoinedRegion
                let page = f
                    .aggregate(&o, r#"{"joins":[{"relation":"customer","type":"INNER"}],"groupBy":[{"field":"customer.region","alias":"region"}],"aggregations":[{"function":"SUM","field":"amount","alias":"total"}],"count":true}"#)
                    .await;
                assert_eq!(page.content.len(), 2);
                assert_eq!(page.total, 2);
                let by_region: IndexMap<String, f64> = page.content.iter().map(|r| (r["region"].java_string(), num(&r["total"]))).collect();
                assert_eq!(by_region["north"], 300.0);
                assert_eq!(by_region["south"], 50.0);
                // Aggregating.measureAcross
                let page = f.aggregate(&o, r#"{"joins":[{"relation":"customer","type":"INNER"}],"aggregations":[{"function":"COUNT","field":"customer.name","alias":"named"}]}"#).await;
                assert_eq!(num(&page.content[0]["named"]), 3.0);

                // SubQueries.customersWithMoreThanOneOrder
                let page = f
                    .read(&cx(), &cu, r#"{"subQueries":[{"storage":"orders","relation":"customer","alias":"orders","having":{"field":"count","value":1,"operator":"GREATER_THAN"}}],"count":true}"#)
                    .await
                    .unwrap();
                assert_eq!(page.content.len(), 1, "only Asha has two");
                assert_eq!(page.content[0]["name"], Value::from("Asha"));
                assert_eq!(page.total, 1);
                // SubQueries.measureIsReturned
                let page = f.read(&cx(), &cu, r#"{"subQueries":[{"storage":"orders","relation":"customer","alias":"orders"}]}"#).await.unwrap();
                assert_eq!(num(&named(&page, "Asha")["orders"].as_object().expect("an object")["count"]), 2.0);
                // SubQueries.oneRowPerParent
                let page = f.read(&cx(), &cu, r#"{"subQueries":[{"storage":"orders","relation":"customer","alias":"orders"}],"count":true}"#).await.unwrap();
                assert_eq!(page.content.len(), 2);
                assert_eq!(page.total, 2);
                // SubQueries.conditionOnTheChildren
                let page = f
                    .read(&cx(), &cu, r#"{"subQueries":[{"storage":"orders","relation":"customer","alias":"big","condition":{"field":"amount","value":150,"operator":"GREATER_THAN"}}]}"#)
                    .await
                    .unwrap();
                assert_eq!(page.content.len(), 1);
                assert_eq!(page.content[0]["name"], Value::from("Asha"));
                // SubQueries.sumOverChildren
                let page = f
                    .read(&cx(), &cu, r#"{"subQueries":[{"storage":"orders","relation":"customer","alias":"orders","aggregations":[{"function":"SUM","field":"amount","alias":"total"}]}]}"#)
                    .await
                    .unwrap();
                assert_eq!(num(&named(&page, "Asha")["orders"].as_object().unwrap()["total"]), 300.0);
                // SubQueries.sortByChildCount
                let page = f
                    .read(&cx(), &cu, r#"{"subQueries":[{"storage":"orders","relation":"customer","alias":"orders"}],"sort":[{"property":"orders.count","direction":"DESC"}]}"#)
                    .await
                    .unwrap();
                assert_eq!(page.content[0]["name"], Value::from("Asha"));
                assert_eq!(page.content[1]["name"], Value::from("Bo"));
                // SubQueries.aggregateOverSubQuery
                let page = f
                    .aggregate(&cu, r#"{"subQueries":[{"storage":"orders","relation":"customer","alias":"orders"}],"groupBy":[{"field":"region"}],"aggregations":[{"function":"SUM","field":"orders.count","alias":"placed"}]}"#)
                    .await;
                let by_region: IndexMap<String, f64> = page.content.iter().map(|r| (r["region"].java_string(), num(&r["placed"]))).collect();
                assert_eq!(by_region["north"], 2.0, "Asha's two");
                assert_eq!(by_region["south"], 1.0, "Bo's one");
                // SubQueries.wrongTargetRefused
                let e = f.read(&cx(), &cu, r#"{"subQueries":[{"storage":"orders","relation":"labels","alias":"x"}]}"#).await.unwrap_err();
                assert!(e.message().contains("points at"), "{}", e.message());

                // Refusals.toManyRefused
                let e = f.read(&cx(), &o, r#"{"joins":[{"relation":"labels"}]}"#).await.unwrap_err();
                assert!(e.message().contains("cannot use an index"), "{}", e.message());
                // Refusals.unknownRelation
                let e = f.read(&cx(), &o, r#"{"joins":[{"relation":"supplier"}]}"#).await.unwrap_err();
                assert!(e.message().contains("no relation"), "{}", e.message());
                // Refusals.deleteWithJoins
                let q = query(r#"{"joins":[{"relation":"customer","type":"INNER"}],"condition":{"field":"customer.region","value":"north"}}"#);
                let e = f.e.delete_by_filter(&cx(), CLIENT, Some(&f.c), &o, &q, Some(false), None).await.unwrap_err();
                assert_eq!(e.status().as_u16(), 501, "{}", e.message());
                assert_eq!(f.read(&cx(), &o, "{}").await.unwrap().content.len(), 4, "and nothing went");

                // SubQueries.optionalKeepsChildless (Dee is written after the other cases, which count customers)
                f.write_customer("Dee", "west").await;
                let required = f.read(&cx(), &cu, r#"{"subQueries":[{"storage":"orders","relation":"customer","alias":"orders"}]}"#).await.unwrap();
                let optional = f.read(&cx(), &cu, r#"{"subQueries":[{"storage":"orders","relation":"customer","alias":"orders","required":false}]}"#).await.unwrap();
                assert_eq!(required.content.len(), 2, "Dee has no orders");
                assert_eq!(optional.content.len(), 3, "and is kept when the subquery is optional");
                let dee = named(&optional, "Dee");
                assert!(dee.contains_key("orders"));
                assert!(dee["orders"].as_object().unwrap()["count"].is_null());

                // With customers locked behind an authority the caller may not hold.
                f.given_storages(Some("Authorities.CUSTOMER_READ")).await;
                // SubQueries.childReadAuth
                let e = f.read(&cx(), &o, r#"{"subQueries":[{"storage":"orders","relation":"customer","alias":"self"}]}"#).await.unwrap_err();
                assert!(e.message().contains("points at") || e.status().as_u16() == 403, "{}", e.message());
                // Refusals.joinedStorageReadAuth
                let e = f.read(&cx(), &o, r#"{"joins":[{"relation":"customer","type":"INNER"}]}"#).await.unwrap_err();
                assert_eq!(e.status().as_u16(), 403, "{}", e.message());
                // Refusals.joinedStorageReadAuthGranted
                let granted = Ctx { authorities: vec!["Authorities.Logged_IN".into(), "Authorities.CUSTOMER_READ".into()], ..cx() };
                assert_eq!(f.read(&granted, &o, r#"{"joins":[{"relation":"customer","type":"INNER"}]}"#).await.unwrap().content.len(), 3);
            },
            drop_schemas(&p, &[CLIENT], APP),
        )
        .await;
    }
}
