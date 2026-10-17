//! Ports of the Java unit tests for the rules both app-data backends share: the aggregate
//! validator, schema reference resolution, storage field names, version retention and the
//! number handling of a parsed row. No database: everything here is pure.
//!
//! Java sources (nocode-saas): `commons-core/src/test/java/.../service/connection/appdata/`
//! `AggregateQueryValidatorTest`, `SchemaRefResolverTest`, `StorageFieldNamesTest`,
//! `VersionRetentionTest`, `StorageJsonNumbersTest`, and
//! `core/src/test/java/.../service/appdata/VersionRetentionPropertyBindingTest`.
//!
//! The `extra` module at the end is not a port: it covers what the ports leave untouched in
//! the shared models and helpers, each expectation checked against the Java code (values
//! marked "JVM" were taken from a JVM).

use std::collections::HashSet;

use appdata::aggregate_validator::{self as validator, alias_ok, zone_id_ok, ALIAS_PATTERN};
use appdata::field_names;
use appdata::model::*;
use appdata::mysql::column::MySqlColumn;
use appdata::mysql::{table_planner, type_mapper};
use appdata::retention::{VersionRetention, DEFAULT_COUNT, DEFAULT_DAYS};
use appdata::schema_refs::{self, SchemaRepository};
use appdata::value::{Document, Value};
use async_trait::async_trait;
use indexmap::IndexMap;

fn v(s: &str) -> Value {
    Value::parse_json(s).unwrap()
}

fn doc(s: &str) -> Document {
    match v(s) {
        Value::Object(o) => o,
        other => panic!("not an object: {other:?}"),
    }
}

/// A KIRun schema from its JSON, as Gson reads it.
fn schema(json: &str) -> Schema {
    Schema::from_value(&v(json)).unwrap()
}

fn set(items: &[&str]) -> HashSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

/// `Schema.ofObject(name).setProperties(props)`.
fn object(props: Vec<(&str, Schema)>) -> Schema {
    Schema {
        name: Some("t".into()),
        types: Some(vec![SchemaType::Object]),
        properties: Some(props.into_iter().map(|(k, s)| (k.to_string(), s)).collect()),
        ..Default::default()
    }
}

/// `Schema.ofString(name).setMaxLength(max)`.
fn string(name: &str, max: i32) -> Schema {
    Schema { max_length: Some(max), ..Schema::of_string(name) }
}

/// `Schema.ofInteger(name)`.
fn integer(name: &str) -> Schema {
    Schema { name: Some(name.into()), types: Some(vec![SchemaType::Integer]), ..Default::default() }
}

/// `Schema.ofRef(ref)`.
fn reference(r: &str) -> Schema {
    Schema { reference: Some(r.into()), ..Default::default() }
}

fn columns(resolved: &Schema) -> Vec<MySqlColumn> {
    type_mapper::columns(Some(resolved), None).unwrap()
}

fn column(resolved: &Schema, name: &str) -> MySqlColumn {
    columns(resolved).into_iter().find(|c| c.name() == name).unwrap_or_else(|| panic!("no column {name}"))
}

/// A repository of schemas held by name, which is all the resolver asks of one.
#[derive(Default)]
struct Repo(IndexMap<String, Schema>);

impl Repo {
    fn put(mut self, namespace: &str, name: &str, mut schema: Schema) -> Repo {
        schema.namespace = Some(namespace.into());
        schema.name = Some(name.into());
        self.0.insert(format!("{namespace}.{name}"), schema);
        self
    }
}

#[async_trait]
impl SchemaRepository for Repo {
    async fn find(&self, namespace: &str, name: &str) -> anyhow::Result<Option<Schema>> {
        Ok(self.0.get(&format!("{namespace}.{name}")).cloned())
    }
}

async fn resolve(s: &Schema, repo: &Repo) -> Schema {
    schema_refs::resolve(s, Some(repo)).await
}

// ------------------------------------------------------------------ AggregateQueryValidatorTest

mod aggregate_query_validator_test {
    //! Skipped: `nullQuery` (a null query is refused rather than throwing). `check` takes
    //! `&AggregateQuery`, so there is no null to refuse.

    use super::*;

    fn agg(f: AggregateFunction, field: Option<&str>, alias: &str) -> Aggregation {
        Aggregation::new(f, field).with_alias(alias)
    }

    fn valid() -> AggregateQuery {
        AggregateQuery {
            group_by: Some(vec![GroupByField::new("region")]),
            aggregations: Some(vec![agg(AggregateFunction::Sum, Some("amount"), "total")]),
            ..Default::default()
        }
    }

    fn measures(aggs: Vec<Aggregation>) -> AggregateQuery {
        AggregateQuery { aggregations: Some(aggs), ..Default::default() }
    }

    fn grouped(g: GroupByField, aggs: Vec<Aggregation>) -> AggregateQuery {
        AggregateQuery { group_by: Some(vec![g]), aggregations: Some(aggs), ..Default::default() }
    }

    #[test]
    fn ok() {
        assert_eq!(validator::check(&valid()), None);
    }

    #[test]
    fn no_aggregations() {
        assert!(validator::check(&AggregateQuery::default()).is_some());
    }

    /// `HavingCondition.make("total", SUM, 1)`.
    #[test]
    fn having_condition() {
        let having = HavingCondition {
            negate: false,
            aggregate_function: Some(AggregateFunction::Sum),
            condition: Some(FilterCondition::eq("total", 1)),
        };
        let err = validator::check(&AggregateQuery { having: Some(Condition::Having(having)), ..valid() }).unwrap();
        assert!(err.contains("HavingCondition"), "{err}");
    }

    #[test]
    fn plain_having() {
        let q = AggregateQuery { having: Some(FilterCondition::eq("total", 1).into()), ..valid() };
        assert_eq!(validator::check(&q), None);
    }

    #[test]
    fn dollar_in_field() {
        let q = grouped(GroupByField::new("$where"), vec![agg(AggregateFunction::Count, None, "n")]);
        assert!(validator::check(&q).is_some());
        assert!(validator::check(&measures(vec![agg(AggregateFunction::Sum, Some("a$b"), "total")])).is_some());
    }

    #[test]
    fn bad_alias() {
        for alias in ["has space", "has-dash", "1leading", "has.dot", "has$dollar"] {
            let err = validator::check(&measures(vec![agg(AggregateFunction::Count, None, alias)]));
            assert!(err.is_some(), "'{alias}' should be refused");
        }
    }

    #[test]
    fn blank_alias_falls_back() {
        let q = measures(vec![agg(AggregateFunction::Count, None, "")]);
        assert_eq!(validator::check(&q), None);
        assert_eq!(validator::aliases(&q).into_iter().collect::<HashSet<_>>(), set(&["count"]));
    }

    #[test]
    fn duplicate_alias() {
        let mut g = GroupByField::new("region");
        g.alias = Some("x".into());
        let err = validator::check(&grouped(g, vec![agg(AggregateFunction::Count, None, "x")])).unwrap();
        assert!(err.contains("duplicate"), "{err}");
    }

    #[test]
    fn field_required() {
        use AggregateFunction::*;
        for f in [Sum, Avg, Min, Max, CountDistinct] {
            assert!(validator::check(&measures(vec![agg(f, None, "a")])).is_some(), "{f} should need a field");
        }
        assert_eq!(validator::check(&measures(vec![agg(Count, None, "n")])), None);
    }

    #[test]
    fn sort_on_alias() {
        let q = AggregateQuery { sort: Some(Sort::by(vec![Order::desc("total")])), ..valid() };
        assert_eq!(validator::check(&q), None);
        let q = AggregateQuery { sort: Some(Sort::by(vec![Order::desc("amount")])), ..valid() };
        let err = validator::check(&q).unwrap();
        assert!(err.contains("cannot sort on"), "{err}");
    }

    #[test]
    fn encoding_without_bucket() {
        let mut g = GroupByField::new("ts");
        g.encoding = Some(DateEncoding::EpochSeconds);
        let err = validator::check(&grouped(g, vec![agg(AggregateFunction::Count, None, "n")])).unwrap();
        assert!(err.contains("only meaningful with a bucket"), "{err}");
    }

    #[test]
    fn bucket_without_encoding_is_backend_specific() {
        let mut g = GroupByField::new("ts");
        g.bucket = Some(DateBucketUnit::Day);
        assert_eq!(validator::check(&grouped(g, vec![agg(AggregateFunction::Count, None, "n")])), None);
    }

    #[test]
    fn unknown_zone() {
        let mut g = GroupByField::new("ts");
        g.bucket = Some(DateBucketUnit::Day);
        g.timezone = Some("Mars/Olympus".into());
        let err = validator::check(&grouped(g, vec![agg(AggregateFunction::Count, None, "n")])).unwrap();
        assert!(err.contains("not a known IANA timezone"), "{err}");
    }

    #[test]
    fn aliases() {
        assert_eq!(validator::aliases(&valid()).into_iter().collect::<HashSet<_>>(), set(&["region", "total"]));
    }

    #[test]
    fn default_aliases() {
        let q = AggregateQuery {
            group_by: Some(vec![GroupByField::new("region")]),
            aggregations: Some(vec![Aggregation::new(AggregateFunction::Sum, Some("amount"))]),
            ..Default::default()
        };
        assert_eq!(validator::check(&q), None);
        assert_eq!(validator::aliases(&q).into_iter().collect::<HashSet<_>>(), set(&["region", "sum_amount"]));
    }
}

// ------------------------------------------------------------------ SchemaRefResolverTest

mod schema_ref_resolver_test {
    use super::*;

    mod top_level {
        use super::*;

        #[tokio::test]
        async fn bare_ref() {
            let repo = Repo::default().put(
                "App",
                "Customer",
                object(vec![("name", string("name", 80)), ("age", integer("age"))]),
            );
            let resolved = resolve(&reference("App.Customer"), &repo).await;
            assert_eq!(columns(&resolved).len(), 2);
            assert_eq!(column(&resolved, "name").column_type, "VARCHAR(80)");
            assert_eq!(column(&resolved, "age").column_type, "INT");
        }

        #[tokio::test]
        async fn local_properties_survive() {
            let repo = Repo::default().put("App", "Base", object(vec![("code", string("code", 10))]));
            let local = Schema { properties: Some([("extra".to_string(), string("extra", 5))].into()), ..reference("App.Base") };
            let resolved = resolve(&local, &repo).await;
            column(&resolved, "code");
            column(&resolved, "extra");
        }

        #[tokio::test]
        async fn required_is_merged() {
            let base = Schema { required: Some(vec!["code".into()]), ..object(vec![("code", string("code", 10))]) };
            let repo = Repo::default().put("App", "Base", base);
            let local = Schema {
                properties: Some([("extra".to_string(), string("extra", 5))].into()),
                required: Some(vec!["extra".into()]),
                ..reference("App.Base")
            };
            let resolved = resolve(&local, &repo).await;
            assert!(!column(&resolved, "code").nullable);
            assert!(!column(&resolved, "extra").nullable);
        }

        #[tokio::test]
        async fn missing_target() {
            let resolved = resolve(&reference("App.Gone"), &Repo::default()).await;
            assert_eq!(resolved, reference("App.Gone"));
            assert!(columns(&resolved).is_empty());
        }
    }

    mod fields {
        //! Skipped as written: `noSchema` (a null schema resolves to nothing), since
        //! `resolve` takes `&Schema`. Its counterpart one level up, a storage with no
        //! schema, is ported as `no_schema`.

        use super::*;

        #[tokio::test]
        async fn scalar_field() {
            let repo = Repo::default().put("App", "Email", string("Email", 120));
            let resolved = resolve(&object(vec![("contact", reference("App.Email"))]), &repo).await;
            assert_eq!(column(&resolved, "contact").column_type, "VARCHAR(120)");
        }

        #[tokio::test]
        async fn date_field() {
            let repo = Repo::default().put("App", "Stamp", Schema::of_string("Stamp").with_format(StringFormat::DateTime));
            let resolved = resolve(&object(vec![("createdAt", reference("App.Stamp"))]), &repo).await;
            assert_eq!(column(&resolved, "createdAt").column_type, "DATETIME(3)");
        }

        #[tokio::test]
        async fn object_field() {
            let repo = Repo::default()
                .put("App", "Address", object(vec![("city", string("city", 60)), ("pin", string("pin", 6))]));
            let resolved = resolve(&object(vec![("address", reference("App.Address"))]), &repo).await;
            let c = column(&resolved, "address");
            assert_eq!(c.column_type, "JSON");
            let note = c.note.unwrap_or_default();
            assert!(note.contains("nested object"), "{note}");
        }

        #[tokio::test]
        async fn local_overlay_wins() {
            let repo = Repo::default().put("App", "Code", string("Code", 40));
            let field = Schema { max_length: Some(12), ..reference("App.Code") };
            let resolved = resolve(&object(vec![("code", field)]), &repo).await;
            assert_eq!(column(&resolved, "code").column_type, "VARCHAR(12)");
        }

        #[tokio::test]
        async fn chained_refs() {
            let repo = Repo::default().put("App", "Outer", reference("App.Inner")).put("App", "Inner", string("Inner", 25));
            let resolved = resolve(&object(vec![("v", reference("App.Outer"))]), &repo).await;
            assert_eq!(column(&resolved, "v").column_type, "VARCHAR(25)");
        }

        #[tokio::test]
        async fn cyclic_ref() {
            let repo = Repo::default()
                .put("App", "Node", object(vec![("label", string("label", 30)), ("child", reference("App.Node"))]));
            let resolved = resolve(&object(vec![("tree", reference("App.Node"))]), &repo).await;
            assert_eq!(column(&resolved, "tree").column_type, "JSON");
        }

        #[tokio::test]
        async fn untouched() {
            let resolved = resolve(&object(vec![("plain", string("plain", 7))]), &Repo::default()).await;
            assert_eq!(column(&resolved, "plain").column_type, "VARCHAR(7)");
        }

        #[tokio::test]
        async fn no_repository() {
            let s = object(vec![("a", integer("a"))]);
            assert_eq!(schema_refs::resolve(&s, None).await, s);
        }

        /// `noSchema`, where the Rust API can have one: a storage with no schema resolves
        /// to nothing.
        #[tokio::test]
        async fn no_schema() {
            let repo = Repo::default();
            assert_eq!(schema_refs::resolved_schema(&Storage::default(), Some(&repo)).await, None);
        }
    }
}

// ------------------------------------------------------------------ StorageFieldNamesTest

mod storage_field_names_test {
    //! Skipped: the `null` inputs of `valid`, `storable` and `safeQueryPath` (the Rust
    //! functions take `&str`, so there is no null name).

    use super::*;

    const HOSTILE: &str = "a` INT, ADD COLUMN `pwned";

    mod rule {
        use super::*;

        #[test]
        fn ordinary() {
            for n in ["name", "createdAt", "_id", "line_1"] {
                assert!(field_names::valid(n), "{n}");
            }
        }

        #[test]
        fn backtick() {
            assert!(!field_names::valid(HOSTILE));
            assert!(!field_names::valid("a`b"));
        }

        #[test]
        fn other_shapes() {
            for n in ["2fast", "with space", "dotted.path", "$where", ""] {
                assert!(!field_names::valid(n), "{n}");
            }
            assert!(!field_names::valid(&"a".repeat(64)));
            assert!(field_names::valid(&"a".repeat(63)));
        }
    }

    mod received {
        use super::*;

        /// What the HDFC collection webhook sends, and what cxapp's schemas declare.
        const HDFC: [&str; 16] = [
            "Alert Sequence No",
            "Virtual Account ",
            "Account number",
            "Debit Credit",
            "Amount",
            "Remitter Name",
            "Remitter Account",
            "Remitter Bank",
            "User Reference Number",
            "Cheque No",
            "Mnemonic Code",
            "Value Date",
            "IFSC Code",
            "Transaction Description",
            "Transaction Date",
            "paymentId",
        ];

        #[test]
        fn spaced_names_save() {
            let s = object(HDFC.iter().map(|n| (*n, Schema::of_string(n))).collect());
            assert_eq!(field_names::problems(Some(&s), &[]), Vec::<String>::new());
        }

        #[test]
        fn normalised() {
            assert_eq!(field_names::column("IFSC Code"), "IFSC_Code");
            assert_eq!(field_names::column("Virtual Account "), "Virtual_Account_");
            assert_eq!(field_names::column("2fast"), "_2fast");
            assert_eq!(field_names::column("a-b"), "a_b");
            for n in HDFC {
                assert!(field_names::valid(&field_names::column(n)), "{n}");
            }
        }

        #[test]
        fn identity() {
            assert_eq!(field_names::column("amount"), "amount");
            assert_eq!(field_names::column("_id"), "_id");
            assert_eq!(field_names::column(&"a".repeat(63)), "a".repeat(63));
        }

        #[test]
        fn long() {
            let a = format!("{}one", "x ".repeat(40));
            let b = format!("{}two", "x ".repeat(40));
            assert_eq!(field_names::column(&a).len(), 63);
            assert!(field_names::valid(&field_names::column(&a)));
            assert_ne!(field_names::column(&a), field_names::column(&b));
        }

        #[test]
        fn collision() {
            let s = object(vec![("Debit Credit", Schema::of_string("a")), ("Debit_Credit", Schema::of_string("b"))]);
            let problems = field_names::problems(Some(&s), &[]);
            assert_eq!(problems.len(), 1);
            assert!(problems[0].contains("Debit Credit"), "{}", problems[0]);
            assert!(problems[0].contains("Debit_Credit"), "{}", problems[0]);
        }

        #[test]
        fn collides_with_id() {
            let s = object(vec![("-id", Schema::of_string("x"))]);
            assert_eq!(field_names::problems(Some(&s), &[]).len(), 1);
        }

        #[test]
        fn still_refused() {
            for n in ["$where", "address.city", HOSTILE, "tab\there", " "] {
                assert!(!field_names::storable(n), "{n:?}");
            }
        }

        #[test]
        fn relations_stay_strict() {
            assert_eq!(field_names::problems(Some(&object(vec![])), &["my customer".into()]).len(), 1);
        }
    }

    mod query_paths {
        use super::*;

        #[test]
        fn ordinary() {
            for p in ["name", "address.city", "items[0].sku"] {
                assert!(field_names::safe_query_path(p), "{p}");
            }
        }

        #[test]
        fn operators() {
            for p in ["$where", "$expr", "a.$where", "", "a..b"] {
                assert!(!field_names::safe_query_path(p), "{p}");
            }
        }
    }

    mod filter_values {
        use super::*;

        fn safe(json: &str) -> bool {
            field_names::safe_filter_value(Some(&v(json)))
        }

        #[test]
        fn ordinary() {
            assert!(safe(r#""hello""#));
            assert!(safe("42"));
            assert!(field_names::safe_filter_value(None));
            assert!(safe(r#"{"city":"Hyderabad"}"#));
            assert!(safe(r#"["a","b"]"#));
        }

        #[test]
        fn operators() {
            assert!(!safe(r#"{"$gt":0}"#));
            assert!(!safe(r#"{"$ne":{"a":1}}"#));
        }

        #[test]
        fn nested() {
            assert!(!safe(r#"[{"$where":"1"}]"#));
            assert!(!safe(r#"{"inner":{"$gt":1}}"#));
        }
    }

    mod enforcement {
        use super::*;

        #[test]
        fn reported_at_save() {
            let s = object(vec![(HOSTILE, integer(HOSTILE))]);
            let problems = field_names::problems(Some(&s), &[]);
            assert_eq!(problems.len(), 1);
            assert!(!problems[0].contains('`'), "{}", problems[0]);
        }

        #[test]
        fn relation_keys() {
            assert_eq!(field_names::problems(Some(&object(vec![])), &[HOSTILE.into()]).len(), 1);
        }

        #[test]
        fn refused_at_the_column() {
            assert!(MySqlColumn::new(HOSTILE, "INT", true).is_err());
            let s = object(vec![(HOSTILE, integer(HOSTILE))]);
            assert!(type_mapper::columns(Some(&s), None).is_err());
        }

        #[test]
        fn ordinary_still_works() {
            let amount = Schema { name: Some("amount".into()), types: Some(vec![SchemaType::Double]), ..Default::default() };
            let ddl = table_planner::create_table("t", &columns(&object(vec![("amount", amount)])));
            assert!(ddl.contains("`amount` DOUBLE"), "{ddl}");
        }
    }
}

// ------------------------------------------------------------------ VersionRetentionTest

mod version_retention_test {
    //! Skipped: `defaultsForNullStorage` and `nullDefaultFallsBackToCompiled` (`for_storage`
    //! takes `&Storage` and a `VersionRetention`, neither of which can be null; the engine
    //! configs default to the compiled policy, see the property binding port), and the
    //! placeholder-string half of `propertyDefaultsMatchConstants` (Spring `@Value` text).

    use super::*;
    use chrono::Utc;

    /// The installation default when nobody has configured one.
    fn of(s: &Storage) -> VersionRetention {
        VersionRetention::for_storage(s, VersionRetention::default())
    }

    fn storage(days: Option<i32>, count: Option<i32>) -> Storage {
        Storage { version_retention_days: days, version_retention_count: count, ..Default::default() }
    }

    #[test]
    fn defaults_when_unset() {
        let r = of(&storage(None, None));
        assert_eq!(r.days, DEFAULT_DAYS);
        assert_eq!(r.count, DEFAULT_COUNT);
        assert!(r.trims_by_age());
        assert!(r.trims_by_count());
    }

    #[test]
    fn honours_each_bound() {
        assert_eq!(of(&storage(Some(7), None)).days, 7);
        assert_eq!(of(&storage(Some(7), None)).count, DEFAULT_COUNT);
        assert_eq!(of(&storage(None, Some(3))).count, 3);
        assert_eq!(of(&storage(None, Some(3))).days, DEFAULT_DAYS);
    }

    #[test]
    fn zero_means_unlimited() {
        assert!(!of(&storage(Some(0), Some(10))).trims_by_age());
        assert!(of(&storage(Some(0), Some(10))).trims_by_count());
        assert!(!of(&storage(Some(10), Some(0))).trims_by_count());
        assert!(of(&storage(Some(0), Some(0))).keeps_everything());
        assert!(!of(&storage(Some(0), Some(10))).keeps_everything());
    }

    #[test]
    fn negative_is_treated_as_unlimited() {
        let r = of(&storage(Some(-5), Some(-1)));
        assert_eq!(r.days, 0);
        assert_eq!(r.count, 0);
        assert!(r.keeps_everything());
    }

    #[test]
    fn cutoff_is_days_back_in_utc() {
        let cutoff = of(&storage(Some(30), None)).cutoff();
        let expected = Utc::now().naive_utc() - chrono::Duration::days(30);
        assert!((cutoff - expected).num_seconds().abs() < 5, "cutoff should be ~30 days before now in UTC");
    }

    #[test]
    fn configured_default_wins() {
        let r = VersionRetention::for_storage(&storage(None, None), VersionRetention { days: 7, count: 3 });
        assert_eq!(r.days, 7);
        assert_eq!(r.count, 3);
    }

    #[test]
    fn configured_unlimited_keeps_everything() {
        assert!(VersionRetention::for_storage(&storage(None, None), VersionRetention { days: 0, count: 0 }).keeps_everything());
    }

    #[test]
    fn storage_overrides_configured_default() {
        let configured = VersionRetention { days: 7, count: 3 };
        assert_eq!(VersionRetention::for_storage(&storage(Some(30), None), configured).days, 30);
        assert_eq!(VersionRetention::for_storage(&storage(Some(30), None), configured).count, 3);
        assert_eq!(VersionRetention::for_storage(&storage(None, Some(400)), configured).days, 7);
        assert_eq!(VersionRetention::for_storage(&storage(None, Some(400)), configured).count, 400);
    }

    #[test]
    fn storage_zero_beats_configured_bound() {
        let r = VersionRetention::for_storage(&storage(Some(0), Some(0)), VersionRetention { days: 90, count: 50 });
        assert!(r.keeps_everything());
    }

    /// `VersionRetentionDefaults(days, count)` is `VersionRetention.clamped` plus
    /// `of(storage, defaults)`; the Rust engines take the clamped pair in their config.
    #[test]
    fn bean_clamps_negative_configuration() {
        assert!(VersionRetention::clamped(-1, -1).keeps_everything());
        let defaults = VersionRetention::clamped(14, 5);
        assert_eq!(defaults.days, 14);
        assert_eq!(defaults.count, 5);
        assert_eq!(VersionRetention::for_storage(&storage(None, None), defaults).days, 14);
        assert_eq!(VersionRetention::for_storage(&storage(None, None), defaults).count, 5);
        assert_eq!(VersionRetention::for_storage(&storage(Some(2), None), defaults).days, 2);
        assert_eq!(VersionRetention::for_storage(&storage(Some(2), None), defaults).count, 5);
    }

    /// The constants half: the compiled fallback is 90 days / 50 versions.
    #[test]
    fn property_defaults_match_constants() {
        assert_eq!(DEFAULT_DAYS, 90);
        assert_eq!(DEFAULT_COUNT, 50);
        assert_eq!(VersionRetention::default(), VersionRetention { days: DEFAULT_DAYS, count: DEFAULT_COUNT });
    }
}

// ------------------------------------------------------------------ VersionRetentionPropertyBindingTest

mod version_retention_property_binding_test {
    //! The property binding itself (`core.appdata.versionRetention.*`) is read by
    //! `crates/core` (`config.rs` / `lib.rs`), not by this crate: the engines take a
    //! `VersionRetention` in `MySqlEngineConfig` / `MongoEngineConfig`. Ported: what an
    //! unconfigured engine gets, and what a 0/0 default does. Skipped:
    //! `configurationBinds` and `dashedSpellingDoesNotBind` (Spring property names).

    use super::*;
    use appdata::mongo::MongoEngineConfig;
    use appdata::mysql::MySqlEngineConfig;

    #[test]
    fn unconfigured_uses_compiled_default() {
        for r in [MySqlEngineConfig::default().retention, MongoEngineConfig::default().retention] {
            assert_eq!(r.days, DEFAULT_DAYS);
            assert_eq!(r.count, DEFAULT_COUNT);
        }
    }

    /// `forStorage(null)` on a 0/0 installation; an unset storage here.
    #[test]
    fn configured_off_keeps_everything() {
        assert!(VersionRetention::for_storage(&Storage::default(), VersionRetention::clamped(0, 0)).keeps_everything());
    }
}

// ------------------------------------------------------------------ StorageJsonNumbersTest

mod storage_json_numbers_test {
    //! Java's `StorageJson.toMap` (Gson with LONG_OR_DOUBLE) is the KIRun functions' row
    //! parser; here the row parser is `Value::parse_json`, which reads numbers the same way
    //! for every input below. Skipped: `defaultGsonLosesTheInteger`, which pins Gson's
    //! default strategy (the premise of the Java fix), and has no counterpart.

    use super::*;

    const BEYOND_DOUBLE: &str = "9007199254740993"; // 2^53 + 1

    fn row(json: &str) -> Document {
        doc(json)
    }

    #[test]
    fn keeps_integer_beyond_double_precision() {
        let r = row(&format!(r#"{{"big":{BEYOND_DOUBLE}}}"#));
        assert_eq!(r["big"], Value::Int(9007199254740993));
    }

    #[test]
    fn keeps_small_whole_numbers() {
        assert_eq!(row(r#"{"n":42}"#)["n"], Value::Int(42));
    }

    #[test]
    fn leaves_fractional_numbers_as_double() {
        let r = row(r#"{"a":3.0,"b":0.125}"#);
        assert_eq!(r["a"], Value::Double(3.0));
        assert_eq!(r["b"], Value::Double(0.125));
    }

    #[test]
    fn falls_back_for_oversized_numbers() {
        assert!(matches!(row(r#"{"huge":1e30}"#)["huge"], Value::Double(_)));
    }

    #[test]
    fn applies_through_nesting() {
        let r = row(&format!(r#"{{"outer":{{"big":{BEYOND_DOUBLE}}},"list":[{BEYOND_DOUBLE}]}}"#));
        assert_eq!(r["outer"].as_object().unwrap()["big"], Value::Int(9007199254740993));
        assert_eq!(r["list"], Value::Array(vec![Value::Int(9007199254740993)]));
    }

    /// Also read as the condition the engines get: the value keeps its precision.
    #[test]
    fn keeps_precision_in_filter_values() {
        let json = format!(r#"{{"field":"big","operator":"EQUALS","value":{BEYOND_DOUBLE}}}"#);
        assert_eq!(row(&json)["value"], Value::Int(9007199254740993));
        let Some(Condition::Filter(f)) = Condition::from_value(&v(&json)).unwrap() else { panic!("not a filter") };
        assert_eq!(f.value, Some(Value::Int(9007199254740993)));
    }

    #[test]
    fn null_is_kept() {
        let map = row(r#"{"description": null, "ownerId": null, "name": "x"}"#);
        assert_eq!(map.get("description"), Some(&Value::Null));
        assert!(map.contains_key("ownerId"));
        assert_eq!(map["name"], Value::from("x"));
    }
}

// ------------------------------------------------------------------ extra (not Java ports)

mod extra {
    //! Not ports: the rest of the shared rules and models, each expectation checked against
    //! the Java code it mirrors. "JVM" marks a value taken from a JVM (jshell, JDK 25).

    use super::*;

    mod aggregate_validator {
        use super::*;

        fn count() -> Aggregation {
            Aggregation::new(AggregateFunction::Count, None)
        }

        fn grouped(groups: Vec<GroupByField>, aggs: Vec<Aggregation>) -> AggregateQuery {
            AggregateQuery { group_by: Some(groups), aggregations: Some(aggs), ..Default::default() }
        }

        #[test]
        fn a_group_by_needs_a_field() {
            let blank = GroupByField { field: Some("  ".into()), ..GroupByField::new("x") };
            assert_eq!(validator::check(&grouped(vec![blank], vec![count()])).as_deref(), Some("a groupBy entry has no field"));
        }

        /// `a.b` and `a_b` both default to the alias `a_b`.
        #[test]
        fn two_group_keys_cannot_share_an_alias() {
            let q = grouped(vec![GroupByField::new("a.b"), GroupByField::new("a_b")], vec![count()]);
            assert_eq!(validator::check(&q).as_deref(), Some("duplicate alias 'a_b'"));
        }

        #[test]
        fn an_aggregation_needs_a_function() {
            let q = grouped(vec![], vec![Aggregation { function: None, field: Some("a".into()), alias: None }]);
            assert_eq!(validator::check(&q).as_deref(), Some("an aggregation has no function"));
        }

        /// Java writes the alias set with `Set.toString()`.
        #[test]
        fn the_sort_refusal_lists_the_aliases() {
            let q = AggregateQuery {
                group_by: Some(vec![GroupByField::new("region")]),
                aggregations: Some(vec![Aggregation::new(AggregateFunction::Sum, Some("amount")).with_alias("total")]),
                sort: Some(Sort::by(vec![Order::asc("amount")])),
                ..Default::default()
            };
            assert_eq!(
                validator::check(&q).as_deref(),
                Some("cannot sort on 'amount'; sort is only possible on a group key or measure alias [region, total]")
            );
        }

        #[test]
        fn a_bad_alias_names_the_pattern() {
            let q = grouped(vec![], vec![count().with_alias("has space")]);
            assert_eq!(validator::check(&q).as_deref(), Some("alias 'has space' must match [A-Za-z_][A-Za-z0-9_]*"));
            assert_eq!(ALIAS_PATTERN, "[A-Za-z_][A-Za-z0-9_]*");
            assert!(alias_ok("_a1") && !alias_ok("") && !alias_ok("1a"));
        }

        /// What `ZoneId.of` accepts and refuses (JVM).
        #[test]
        fn zones_as_zone_id_reads_them() {
            for z in ["+053000", "+05:30:00", "UTC+05:30:00", "GMT0", "UT+01", "-1", "+18:00", "Z", "Etc/GMT+5", "GMT+2"] {
                assert!(zone_id_ok(z), "{z} should be accepted");
            }
            for z in ["UTCX", "+18:00:01", "+5:30"] {
                assert!(!zone_id_ok(z), "{z} should be refused");
            }
        }
    }

    mod schema_refs_extra {
        use super::*;
        use appdata::schema_refs::{HybridRepository, KirunSystemSchemas};
        use std::sync::Arc;

        fn note(c: &MySqlColumn) -> String {
            c.note.clone().unwrap_or_default()
        }

        /// `#/$defs/Row` resolves against the storage schema itself.
        #[tokio::test]
        async fn a_local_defs_reference() {
            let s = schema(r##"{"ref":"#/$defs/Row","$defs":{"Row":{"type":"OBJECT","properties":{"code":{"type":"STRING","maxLength":9}}}}}"##);
            let resolved = resolve(&s, &Repo::default()).await;
            assert_eq!(column(&resolved, "code").column_type, "VARCHAR(9)");
        }

        /// The part after the first `/` walks `$defs` and properties of the found schema.
        #[tokio::test]
        async fn a_reference_with_a_path() {
            let lib = schema(r#"{"type":"OBJECT","$defs":{"Email":{"type":"STRING","maxLength":120}},"properties":{"name":{"type":"STRING","maxLength":44}}}"#);
            let repo = Repo::default().put("App", "Lib", lib).put("App", "Text", string("Text", 5));
            let s = object(vec![
                ("email", reference("App.Lib/$defs/Email")),
                ("name", reference("App.Lib/name")),
                ("gone", reference("App.Lib/$defs/Nope")),
                ("flat", reference("App.Text/inner")),
            ]);
            let resolved = resolve(&s, &repo).await;
            assert_eq!(column(&resolved, "email").column_type, "VARCHAR(120)");
            assert_eq!(column(&resolved, "name").column_type, "VARCHAR(44)");
            // A path that leads nowhere, or into something that is not an object, leaves the
            // field as written, which the type mapper makes JSON with a note.
            for f in ["gone", "flat"] {
                let c = column(&resolved, f);
                assert_eq!(c.column_type, "JSON", "{f}");
                assert!(note(&c).starts_with("unresolved reference App."), "{f}: {}", note(&c));
            }
        }

        /// No repository answers an empty namespace or a missing name, so these stay as
        /// written on both sides.
        #[tokio::test]
        async fn a_reference_without_a_namespace_is_left_as_written() {
            let repo = Repo::default();
            for r in [".Name", "NoDot", "App."] {
                let resolved = resolve(&object(vec![("f", reference(r))]), &repo).await;
                assert_eq!(column(&resolved, "f").column_type, "JSON", "{r}");
            }
        }

        /// Two types that are nothing but references to each other: `follow` stops at the
        /// one it has seen, rather than looping.
        #[tokio::test]
        async fn a_pure_reference_cycle_stops() {
            let repo = Repo::default().put("App", "A", reference("App.B")).put("App", "B", reference("App.A"));
            let resolved = resolve(&object(vec![("f", reference("App.A"))]), &repo).await;
            let c = column(&resolved, "f");
            assert_eq!(c.column_type, "JSON");
            assert_eq!(note(&c), "unresolved reference App.A, so the shape is not known at publish time");
        }

        /// A chain is followed `MAX_DEPTH` (10) links and no further.
        #[tokio::test]
        async fn a_chain_is_followed_to_max_depth() {
            fn chain(len: usize) -> Repo {
                let mut repo = Repo::default();
                for i in 0..len - 1 {
                    repo = repo.put("App", &format!("C{i}"), reference(&format!("App.C{}", i + 1)));
                }
                repo.put("App", &format!("C{}", len - 1), string("end", 9))
            }
            assert_eq!(schema_refs::MAX_DEPTH, 10);
            let s = object(vec![("v", reference("App.C0"))]);
            assert_eq!(column(&resolve(&s, &chain(10)).await, "v").column_type, "VARCHAR(9)");
            assert_eq!(column(&resolve(&s, &chain(12)).await, "v").column_type, "JSON");
        }

        #[tokio::test]
        async fn the_local_type_and_format_win() {
            let repo = Repo::default()
                .put("App", "Stamp", Schema::of_string("Stamp").with_format(StringFormat::DateTime))
                .put("App", "Num", integer("Num"));
            let s = object(vec![
                ("day", Schema { format: Some(StringFormat::Date), ..reference("App.Stamp") }),
                ("big", Schema { types: Some(vec![SchemaType::Long]), ..reference("App.Num") }),
            ]);
            let resolved = resolve(&s, &repo).await;
            assert_eq!(column(&resolved, "day").column_type, "DATE");
            assert_eq!(column(&resolved, "big").column_type, "BIGINT");
            // The field keeps its own name, not the referenced schema's.
            assert_eq!(resolved.properties.unwrap()["day"].name, None);
        }

        /// `StorageService.withRelations`: a to-one is one id, a to-many a list of them, and
        /// a relation the schema already declares keeps the declared shape.
        #[tokio::test]
        async fn resolved_schema_adds_relation_columns() {
            let storage = Storage::from_value(&v(r#"{
                "name":"Order","appCode":"shop","clientCode":"SYSTEM",
                "schema":{"type":"OBJECT","properties":{"name":{"type":"STRING","maxLength":20}}},
                "relations":{"customer":{"storageName":"Customer","relationType":"TO_ONE"},
                             "tags":{"storageName":"Tag","relationType":"TO_MANY"},
                             "name":{"storageName":"Other","relationType":"TO_ONE"}}}"#))
            .unwrap();
            let resolved = schema_refs::resolved_schema(&storage, Some(&Repo::default())).await.unwrap();
            assert_eq!(column(&resolved, "customer").column_type, "CHAR(26)");
            assert_eq!(column(&resolved, "tags").column_type, "JSON");
            assert_eq!(column(&resolved, "name").column_type, "VARCHAR(20)");
            let tags = &resolved.properties.as_ref().unwrap()["tags"];
            assert_eq!(schema_refs::single_item(tags).and_then(|i| i.format), Some(StringFormat::Id));
            assert_eq!(schema_refs::single_item(&resolved.properties.as_ref().unwrap()["customer"]), None);
        }

        /// KIRun's own schemas, asked first, then the app's.
        #[tokio::test]
        async fn system_schemas_then_the_app() {
            let app: Arc<dyn SchemaRepository> = Arc::new(Repo::default().put("App", "Code", string("Code", 6)));
            let hybrid = HybridRepository(vec![Arc::new(KirunSystemSchemas), app]);
            let s = object(vec![
                ("text", reference("System.string")),
                ("stamp", reference("Date.Timestamp")),
                ("n", reference("System.long")),
                ("code", reference("App.Code")),
                ("x", reference("System.nothing")),
            ]);
            let resolved = schema_refs::resolve(&s, Some(&hybrid)).await;
            assert_eq!(column(&resolved, "text").column_type, "TEXT");
            assert_eq!(column(&resolved, "stamp").column_type, "TEXT");
            assert_eq!(column(&resolved, "n").column_type, "BIGINT");
            assert_eq!(column(&resolved, "code").column_type, "VARCHAR(6)");
            assert_eq!(column(&resolved, "x").column_type, "JSON");
        }

        #[test]
        fn the_schema_as_written() {
            let storage = Storage { schema: Some(v(r#"{"type":"OBJECT","properties":{"a":{"type":"INTEGER"}}}"#)), ..Default::default() };
            let written = schema_refs::storage_schema(&storage).unwrap();
            assert!(written.has_type(SchemaType::Object));
            assert_eq!(schema_refs::schema_from_definition(storage.schema.as_ref().unwrap()), Some(written));
            assert_eq!(schema_refs::schema_from_definition(&v("[1]")), None);
        }
    }

    mod field_names_extra {
        use super::*;

        fn props(names: &[&str]) -> Schema {
            object(names.iter().map(|n| (*n, Schema::of_string(n))).collect())
        }

        /// A relation key is checked against the schema's columns too; the same name twice
        /// is one field (Java keeps relation keys in a Set).
        #[test]
        fn relation_keys_against_the_columns() {
            assert!(field_names::problems(Some(&props(&["customer"])), &["customer".into()]).is_empty());
            assert!(field_names::problems(Some(&props(&[])), &["customer".into(), "customer".into()]).is_empty());
            let p = field_names::problems(Some(&props(&["Debit Credit"])), &["Debit_Credit".into()]);
            assert_eq!(
                p,
                vec![r#"field names "Debit Credit" and "Debit_Credit" are both stored as the column "Debit_Credit"; rename one of them"#]
            );
            assert!(field_names::problems(None, &[]).is_empty());
        }

        /// Control characters, quotes and backslashes print as `?`.
        #[test]
        fn a_refused_name_is_quoted_safely() {
            let p = field_names::problems(Some(&props(&["tab\there", "a\"b.c"])), &[]);
            assert_eq!(
                p[0],
                "field name \"tab?here\" is not usable: a field may not be blank, start with '$', or contain a dot, a backtick or a control character"
            );
            assert!(p[1].starts_with("field name \"a?b.c\""), "{}", p[1]);
            let r = field_names::problems(None, &["a\\b".into()]);
            assert_eq!(
                r,
                vec!["relation name \"a?b\" is not usable: a relation has to start with a letter or underscore and continue with letters, digits or underscores, up to 63 characters"]
            );
        }

        /// JVM: `StorageFieldNames.column` for these.
        #[test]
        fn columns_as_java_computes_them() {
            assert_eq!(field_names::column(""), "_");
            assert_eq!(field_names::column("Ünïcode name"), "_n_code_name");
            assert_eq!(
                field_names::column(&format!("{}one", "x ".repeat(40))),
                "x_x_x_x_x_x_x_x_x_x_x_x_x_x_x_x_x_x_x_x_x_x_x_x_x_x_x__7741b426"
            );
            assert_eq!(
                field_names::column(&format!("{}two", "x ".repeat(40))),
                "x_x_x_x_x_x_x_x_x_x_x_x_x_x_x_x_x_x_x_x_x_x_x_x_x_x_x__7741c80c"
            );
        }

        #[test]
        fn multi_values_are_checked_too() {
            assert!(field_names::safe_filter_values(None));
            assert!(field_names::safe_filter_values(Some(&vec![v("1"), v(r#"{"a":1}"#)])));
            assert!(!field_names::safe_filter_values(Some(&vec![v("1"), v(r#"{"$gt":1}"#)])));
        }

        /// `MongoAppDataService.filter` refuses an operator where a field name or a value
        /// belongs, as a 400 `unsupported_condition`.
        #[test]
        fn the_mongo_filter_refuses_operators() {
            use appdata::mongo::filter::filter;
            let s = Storage::default();
            let err = filter(&s, Some(&FilterCondition::eq("$where", "1").into())).unwrap_err();
            assert_eq!(err.status().as_u16(), 400);
            assert_eq!(err.message(), "a field named $where is not a condition this data filter supports.");
            let gt = FilterCondition { value: Some(v(r#"{"$gt":0}"#)), ..FilterCondition::eq("price", 0) };
            let err = filter(&s, Some(&gt.into())).unwrap_err();
            assert_eq!(err.message(), "an operator in the value of price is not a condition this data filter supports.");
            let ok = FilterCondition::eq("address.city", "Hyderabad");
            assert!(filter(&s, Some(&ok.into())).is_ok());
        }

        /// The MySQL filter addresses a field through its column, so a hostile name ends up
        /// as one quoted identifier.
        #[test]
        fn the_mysql_filter_reads_the_column() {
            use appdata::mysql::field_resolver::FieldResolver;
            use appdata::mysql::filter_builder::build;
            let resolver = FieldResolver::of(Default::default());
            let hostile = "a` INT, ADD COLUMN `pwned";
            let sql = build(Some(&FilterCondition::eq(hostile, 1).into()), &resolver).unwrap().inlined();
            assert!(sql.contains("`a__INT__ADD_COLUMN__pwned`"), "{sql}");
            let sql = build(Some(&FilterCondition::eq("IFSC Code", "X").into()), &resolver).unwrap().inlined();
            assert!(sql.contains("`IFSC_Code`"), "{sql}");
        }

        /// `MySQLColumnNames.physical`: the table is built from columns, and rows read back
        /// under the field names the caller declared.
        #[test]
        fn column_names_translate_at_the_edges() {
            use appdata::mysql::column_names;
            let physical = column_names::physical(Schema {
                required: Some(vec!["IFSC Code".into()]),
                ..object(vec![("IFSC Code", string("IFSC Code", 11)), ("amount", integer("amount"))])
            });
            let cols: Vec<String> = columns(&physical.schema).iter().map(|c| c.name().to_string()).collect();
            assert_eq!(cols, vec!["IFSC_Code", "amount"]);
            assert!(!column(&physical.schema, "IFSC_Code").nullable);
            let row = physical.to_fields(doc(r#"{"IFSC_Code":"HDFC0001","amount":5}"#));
            assert_eq!(row.keys().collect::<Vec<_>>(), vec!["IFSC Code", "amount"]);
            assert_eq!(column_names::to_columns(&doc(r#"{"IFSC Code":"x"}"#)).keys().collect::<Vec<_>>(), vec!["IFSC_Code"]);
            assert_eq!(column_names::column("address.city"), "address.city");
        }
    }

    mod retention_extra {
        use super::*;
        use chrono::Utc;

        /// `cutoffEpochMillis`: the same instant as `cutoff`, for Mongo.
        #[test]
        fn the_cutoff_in_epoch_millis() {
            let r = VersionRetention { days: 30, count: 0 };
            let expected = (Utc::now() - chrono::Duration::days(30)).timestamp_millis();
            assert!((r.cutoff_epoch_millis() - expected).abs() < 5_000);
            assert_eq!(VersionRetention { days: 0, count: 0 }.cutoff().and_utc().timestamp() / 10, Utc::now().timestamp() / 10);
        }
    }

    mod value_extra {
        use super::*;
        use appdata::value::{
            document_to_java_json, float_as_double, java_double, non_empty, write_json_string, Decimal,
        };
        use chrono::{NaiveDate, NaiveTime};

        fn dec(s: &str) -> Decimal {
            Decimal::parse(s).unwrap()
        }

        #[test]
        fn accessors() {
            assert_eq!(v("[1]").as_array(), Some(&vec![Value::Int(1)]));
            assert_eq!(v("1").as_array(), None);
            assert_eq!(v("1").as_str(), None);
            assert_eq!(v("1").as_object(), None);
            assert!(v("1.5").is_number() && !v(r#""1""#).is_number());
        }

        /// `String.valueOf(object)` (JVM for the date types).
        #[test]
        fn java_string() {
            assert_eq!(Value::Null.java_string(), "null");
            assert_eq!(Value::Decimal(dec("10.50")).java_string(), "10.50");
            let dt = NaiveDate::from_ymd_opt(2026, 1, 15).unwrap().and_hms_milli_opt(10, 30, 45, 500).unwrap();
            assert_eq!(Value::LocalDateTime(dt).java_string(), "2026-01-15T10:30:45.500");
            assert_eq!(Value::LocalDate(dt.date()).java_string(), "2026-01-15");
            let t = NaiveTime::from_hms_milli_opt(10, 30, 45, 123).unwrap();
            assert_eq!(Value::LocalTime(t).java_string(), "10:30:45.123");
        }

        /// Jackson with `CommonsSerializationModule`: dates as epoch seconds, a LocalTime as
        /// ISO text, a java.util.Date with `StdDateFormat`, non-finite doubles quoted.
        #[test]
        fn java_json_of_the_other_types() {
            let day = NaiveDate::from_ymd_opt(1970, 1, 2).unwrap();
            assert_eq!(Value::LocalDateTime(day.and_hms_opt(0, 0, 1).unwrap()).to_java_json(), "86401");
            assert_eq!(Value::LocalDate(day).to_java_json(), "86400");
            assert_eq!(Value::LocalTime(NaiveTime::from_hms_opt(10, 30, 0).unwrap()).to_java_json(), r#""10:30:00""#);
            assert_eq!(Value::Date(0).to_java_json(), r#""1970-01-01T00:00:00.000+00:00""#);
            assert_eq!(Value::Double(f64::NAN).to_java_json(), r#""NaN""#);
            assert_eq!(Value::Double(f64::INFINITY).to_java_json(), r#""Infinity""#);
            assert_eq!(Value::Double(f64::NEG_INFINITY).to_java_json(), r#""-Infinity""#);
        }

        /// Jackson's escapes: the short forms, `\u00XX` (upper case) for other control
        /// characters, everything else as it is.
        #[test]
        fn json_string_escapes() {
            let mut out = String::new();
            write_json_string(&mut out, "a\"b\\c\nd\re\tf\u{8}g\u{c}h\u{1}i é/");
            assert_eq!(out, r#""a\"b\\c\nd\re\tf\bg\fh\u0001i é/""#);
        }

        /// Jackson's number typing: past a long is a BigInteger.
        #[test]
        fn from_serde_json() {
            assert_eq!(Value::from_json(&serde_json::json!(u64::MAX)), Value::Decimal(dec("18446744073709551615")));
            assert_eq!(Value::from_json(&serde_json::json!(-3)), Value::Int(-3));
            assert_eq!(Value::from_json(&serde_json::json!(1.5)), Value::Double(1.5));
            assert_eq!(Value::from_json(&serde_json::json!({"a":[true,null,"x"]})), v(r#"{"a":[true,null,"x"]}"#));
        }

        #[test]
        fn to_serde_json() {
            let mut d = Document::new();
            d.insert("a".into(), Value::Decimal(dec("10.5000")));
            d.insert("b".into(), Value::Double(1e10));
            d.insert("c".into(), Value::Array(vec![Value::Bool(true), Value::Null]));
            assert_eq!(Value::Object(d).to_json(), serde_json::json!({"a":10.5,"b":1e10,"c":[true,null]}));
        }

        #[test]
        fn from_conversions() {
            assert_eq!(Value::from(5i64), Value::Int(5));
            assert_eq!(Value::from(true), Value::Bool(true));
            assert_eq!(Value::from(1.5f64), Value::Double(1.5));
            assert_eq!(Value::from(doc(r#"{"a":1}"#)), v(r#"{"a":1}"#));
            assert_eq!(Value::from(vec![Value::Int(1)]), v("[1]"));
        }

        #[test]
        fn documents() {
            assert_eq!(document_to_java_json(&doc(r#"{"b":1,"a":[2.5,1e7]}"#)), r#"{"b":1,"a":[2.5,1.0E7]}"#);
            let kept = non_empty(doc(r#"{"a":null,"b":"","c":[],"d":{},"e":0,"f":{"x":1}}"#));
            assert_eq!(kept.keys().collect::<Vec<_>>(), vec!["e", "f"]);
        }

        /// `Double.toString` (JVM).
        #[test]
        fn doubles() {
            assert_eq!(java_double(f64::NAN), "NaN");
            assert_eq!(java_double(f64::INFINITY), "Infinity");
            assert_eq!(java_double(f64::NEG_INFINITY), "-Infinity");
            assert_eq!(java_double(f64::MIN_POSITIVE), "2.2250738585072014E-308");
            assert_eq!(java_double(1.0e-300), "1.0E-300");
            assert_eq!(java_double(1.0e-5), "1.0E-5");
            assert_eq!(java_double(-0.0), "-0.0");
        }

        /// `Float.toString(f)` read back as a double (JVM), not the float widened.
        #[test]
        fn floats() {
            assert_eq!(float_as_double(0.1), 0.1);
            assert_ne!(0.1f32 as f64, 0.1);
            assert_eq!(float_as_double(1.0e10), 1.0e10);
            assert_eq!(float_as_double(f32::MAX), 3.4028235e38);
            assert!(float_as_double(f32::NAN).is_nan());
            assert_eq!(float_as_double(f32::INFINITY), f64::INFINITY);
        }

        /// `BigDecimal` (JVM).
        #[test]
        fn decimals() {
            assert_eq!(Decimal::zero().to_java_string(), "0");
            assert!(Decimal::zero().is_zero());
            assert_eq!(Decimal::from_i64(i64::MIN).to_java_string(), "-9223372036854775808");
            assert_eq!(Decimal::from_i64(42).long_value_exact(), Some(42));
            assert_eq!(Decimal::from_u128(u128::MAX).to_java_string(), u128::MAX.to_string());
            assert_eq!(Decimal::parse("1x"), None);
            assert_eq!(Decimal::parse(""), None);
            assert_eq!(Decimal::parse("1E-2147483648"), None);
            assert_eq!((dec("0.00").precision(), dec("123.45").precision(), dec("1E+3").precision()), (1, 5, 1));
            assert_eq!(dec("0.000").strip_trailing_zeros().to_java_string(), "0");
            assert_eq!(dec("0E+3").to_java_string(), "0E+3");
            assert_eq!(dec("0E+3").to_plain_string(), "0");
            assert_eq!((dec("0E+3").long_value(), dec("0.5").long_value()), (0, 0));
            assert_eq!((dec("4294967297").int_value(), dec("-7.9").int_value()), (1, -7));
            assert_eq!(dec("-1.5E+3").double_value(), -1500.0);
            assert_eq!(dec("0.1").double_value(), 0.1);
            assert_eq!(dec("12345678901234567890.5").double_value(), 1.2345678901234567e19);
            assert_eq!((dec("-0.5").signum(), dec("0.000").signum(), dec("2").signum()), (-1, 0, 1));
            assert_eq!(dec("-12.30").to_string(), "-12.30");
        }

        /// Through serde: numbers and dates keep their Java text.
        #[test]
        fn serde_round_trip() {
            assert_eq!(serde_json::to_string(&Value::Null).unwrap(), "null");
            assert_eq!(serde_json::to_string(&Value::Bool(false)).unwrap(), "false");
            assert_eq!(serde_json::to_string(&Value::Decimal(dec("10.5000"))).unwrap(), "10.5000");
            assert_eq!(serde_json::to_string(&Value::Date(0)).unwrap(), r#""1970-01-01T00:00:00.000+00:00""#);
            let owned: Value = serde_json::from_value(serde_json::json!({"s":"x","n":null})).unwrap();
            assert_eq!(owned, v(r#"{"s":"x","n":null}"#));
            let big: Value = serde_json::from_value(serde_json::json!(u64::MAX)).unwrap();
            assert_eq!(big, Value::Decimal(dec("18446744073709551615")));
        }

        /// BSON binary is not JSON, and is refused rather than misread.
        #[test]
        fn a_binary_is_not_a_json_value() {
            use mongodb::bson::{spec::BinarySubtype, Binary, Bson};
            let err = mongodb::bson::from_bson::<Value>(Bson::Binary(Binary { subtype: BinarySubtype::Generic, bytes: vec![1] }))
                .unwrap_err();
            assert!(err.to_string().contains("any JSON value"), "{err}");
        }
    }

    mod error_extra {
        use appdata::error::{AppDataError, ErrorKind};
        use platform::error::AppError;

        #[test]
        fn empty_and_internal() {
            let e = AppDataError::Empty;
            assert_eq!(e.status().as_u16(), 403);
            assert_eq!(e.message(), "");
            assert_eq!(e.kind(), ErrorKind::Generic);
            let e = AppDataError::internal("driver down");
            assert_eq!(e.status().as_u16(), 500);
            assert_eq!(e.message(), "driver down");
            assert!(!e.is_object_not_found());
            let e = AppDataError::illegal_argument("Page size must not be less than one");
            assert_eq!(e.status().as_u16(), 500);
            assert!(e.message().contains("IllegalArgumentException"), "{}", e.message());
        }

        /// `messages_en.properties`, with the statuses the Java engines raise them with.
        #[test]
        fn messages() {
            let e = AppDataError::invalid_join("no relation 'x'");
            assert_eq!((e.status().as_u16(), e.message()), (400, "Invalid join request: no relation 'x'".to_string()));
            let e = AppDataError::connection_not_available("MySQL");
            assert_eq!((e.status().as_u16(), e.message()), (404, "Connection MySQL not available".to_string()));
            assert!(AppDataError::object_not_found("Order", "1").is_object_not_found());
            assert!(!AppDataError::generic_not_found("Order", "1").is_object_not_found());
        }

        #[test]
        fn at_the_http_edge() {
            let e: AppError = AppDataError::invalid_aggregation("x").into();
            assert_eq!(e.status().as_u16(), 400);
            assert!(matches!(AppError::from(AppDataError::Empty), AppError::Empty(s) if s.as_u16() == 403));
            assert_eq!(AppError::from(AppDataError::internal("x")).status().as_u16(), 500);
            let e: AppDataError = mongodb::error::Error::custom("lost").into();
            assert_eq!(e.status().as_u16(), 500);
        }
    }

    mod engine_extra {
        use super::*;
        use appdata::engine::{AppDataEngine, AuthorityCheck, Ctx, Hooks, SchemaRepositories};
        use std::sync::Arc;

        fn caller(authorities: &[&str]) -> Ctx {
            Ctx { authorities: authorities.iter().map(|a| a.to_string()).collect(), ..Default::default() }
        }

        /// The fallback for single names and `or` / `and` / `not` lists (DIFFERENCES.md:
        /// readAuth of a joined or sub-queried storage). Each answer is what
        /// `SecurityContextUtil.hasAuthority` gives (JVM).
        #[test]
        fn has_authority() {
            let cx = caller(&["Authorities.A", "Authorities.B"]);
            assert!(cx.has_authority(None));
            assert!(cx.has_authority(Some("  ")));
            assert!(!caller(&[]).has_authority(Some("Authorities.A")));
            assert!(cx.has_authority(Some("Authorities.A")));
            assert!(cx.has_authority(Some("Authorities.C or Authorities.B")));
            assert!(!cx.has_authority(Some("Authorities.A and Authorities.C")));
            assert!(cx.has_authority(Some("Authorities.A and not Authorities.C")));
            assert!(!cx.has_authority(Some("not Authorities.A")));
            assert!(cx.has_authority(Some("(Authorities.C or Authorities.A)")));
        }

        /// Mongo honours isAppLevel: the url client's database.
        #[test]
        fn tenant() {
            let app_level = Storage { is_app_level: Some(true), ..Default::default() };
            let cx = Ctx { url_client_code: Some("URLC".into()), ..Default::default() };
            assert_eq!(cx.tenant("OWNER", &app_level), "URLC");
            assert_eq!(cx.tenant("OWNER", &Storage::default()), "OWNER");
            assert!(cx.on_draft(true).draft);
        }

        struct Only(&'static str);

        impl AuthorityCheck for Only {
            fn has_authority(&self, expression: Option<&str>, _authorities: &[String]) -> bool {
                expression == Some(self.0)
            }
        }

        struct AppSchemas;

        impl SchemaRepositories for AppSchemas {
            fn for_app(&self, app_code: &str, client_code: &str) -> Arc<dyn SchemaRepository> {
                assert_eq!((app_code, client_code), ("shop", "SYSTEM"));
                Arc::new(Repo::default().put("App", "Customer", object(vec![("name", string("name", 30))])))
            }
        }

        #[test]
        fn a_plugged_authority_check_decides() {
            let hooks = Hooks { authority: Some(Arc::new(Only("magic"))), ..Default::default() };
            assert!(hooks.has_authority(&caller(&[]), Some("magic")));
            assert!(!hooks.has_authority(&caller(&["Authorities.A"]), Some("Authorities.A")));
            assert!(Hooks::default().has_authority(&caller(&["Authorities.A"]), Some("Authorities.A")));
        }

        /// KIRun's schemas, then the app's repository for the storage's app and client.
        #[tokio::test]
        async fn resolved_schema_through_the_app_repository() {
            let hooks = Hooks { schemas: Some(Arc::new(AppSchemas)), ..Default::default() };
            let storage = Storage {
                app_code: "shop".into(),
                client_code: "SYSTEM".into(),
                schema: Some(v(r#"{"ref":"App.Customer","properties":{"n":{"ref":"System.integer"}}}"#)),
                ..Default::default()
            };
            let resolved = hooks.resolved_schema(&storage).await.unwrap();
            assert_eq!(column(&resolved, "name").column_type, "VARCHAR(30)");
            assert_eq!(column(&resolved, "n").column_type, "INT");
            assert_eq!(hooks.read_for_tenant("Order", "shop", "SYSTEM", false).await.unwrap(), None);
        }

        /// `IAppDataService.enforcesRelationConstraint` defaults to false, and the Mongo
        /// engine does not override it. No database is touched.
        #[tokio::test]
        async fn mongo_never_enforces_a_relation() {
            use appdata::mongo::{MongoAppDataService, MongoEngineConfig};
            let cache = platform::cache::CacheService::new("cmn", "evictionChannel", None).unwrap();
            let engine = MongoAppDataService::new(MongoEngineConfig::default(), Hooks::default(), &cache);
            let rel = StorageRelation::to_one("Customer").with_delete(RelationConstraint::Restrict);
            assert!(!engine.enforces_relation_constraint(&Ctx::default(), "C", None, &Storage::default(), "customer", &rel).await.unwrap());
        }
    }

    mod java_time_and_difference {
        use super::*;
        use appdata::difference::apply;
        use appdata::java_time::{parse_local_time, parse_offset_date_time_utc};

        /// `LocalTime.parse` takes at most nine fraction digits; an offset stops at ±18:00
        /// (JVM).
        #[test]
        fn java_time_limits() {
            assert_eq!(parse_local_time("10:00:00.123456789").map(|t| t.to_string()).as_deref(), Some("10:00:00.123456789"));
            assert_eq!(parse_local_time("10:00:00.1234567890"), None);
            assert!(parse_offset_date_time_utc("2026-01-15T10:00:00+18:00").is_some());
            assert_eq!(parse_offset_date_time_utc("2026-01-15T10:00:00+19:00"), None);
        }

        /// `DifferenceApplicator.apply`: an empty side hands back the other one as it is.
        #[test]
        fn an_empty_side() {
            let base = doc(r#"{"b":1,"a":null}"#);
            assert_eq!(apply(&Document::new(), &base), base);
            assert_eq!(apply(&base, &Document::new()), base);
        }
    }

    mod storage_model {
        use super::*;

        #[test]
        fn a_stored_storage() {
            let s = Storage::from_value(&v(r#"{
                "_id":"s1","name":"Order","appCode":"shop","clientCode":"SYSTEM","version":2.0,"uniqueName":"shop_Order",
                "relations":{"customer":{"storageName":"Customer","relationType":"TO_ONE","deleteConstraint":"NOTHING"},
                             "tags":{"storageName":"Tag","relationType":"TO_MANY","updateConstraint":"CASCADE"}},
                "triggers":{"BEFORE_CREATE":["App.fn1","App.fn2"]},
                "indexes":{"byCode":{"fields":[{"fieldName":"code","direction":"ASC"},{"fieldName":"at"},{"fieldName":"z","direction":"DESC"}],"unique":true},
                           "empty":{}},
                "columnDefinitions":{"amount":{"mysql":{"type":"DECIMAL","precision":12,"scale":2.0,"unsigned":true,"collation":"utf8mb4_bin"}},
                                     "flag":{"mongo":{"bsonType":"BOOLEAN"}},"name":{"mongo":{"bsonType":"STRING"}}},
                "versionRetentionDays":30}"#))
            .unwrap();
            assert_eq!(s.id.as_deref(), Some("s1"));
            assert_eq!(s.version, 2);
            assert_eq!(s.version_retention_days, Some(30));
            assert!(s.has_relations());
            assert_eq!(s.relation_keys(), vec!["customer", "tags"]);
            let customer = s.relation("customer").unwrap();
            assert_eq!(customer.relation_type.map(|t| t.name()), Some("TO_ONE"));
            assert_eq!(customer.delete_constraint, Some(RelationConstraint::Nothing));
            let tags = s.relation("tags").unwrap();
            assert_eq!(tags.relation_type, Some(RelationType::ToMany));
            assert_eq!((tags.delete_constraint, tags.update_constraint), (Some(RelationConstraint::Nothing), Some(RelationConstraint::Cascade)));
            assert_eq!(s.triggers.as_ref().unwrap()["BEFORE_CREATE"], vec!["App.fn1", "App.fn2"]);
            let ix = &s.indexes.as_ref().unwrap()["byCode"];
            assert!(ix.unique);
            let dirs: Vec<Option<Direction>> = ix.fields.iter().map(|f| f.direction).collect();
            assert_eq!(dirs, vec![Some(Direction::Asc), Some(Direction::Asc), Some(Direction::Desc)]);
            assert_eq!(s.indexes.as_ref().unwrap()["empty"], StorageIndex::default());
            let defs = s.column_definitions.as_ref().unwrap();
            assert_eq!(
                defs["amount"].mysql,
                Some(MySqlColumnDefinition {
                    column_type: Some(MySqlColumnType::Decimal),
                    length: None,
                    precision: Some(12),
                    scale: Some(2),
                    unsigned: Some(true),
                    collation: Some("utf8mb4_bin".into()),
                })
            );
            assert_eq!(defs["flag"], StorageColumnDefinition::mongo(MongoBsonType::Boolean));
            assert_eq!(defs["name"], StorageColumnDefinition::mongo(MongoBsonType::String));
            assert!(Storage::from_value(&v("[]")).is_err());
            assert!(!Storage::default().has_relations());
        }

        #[test]
        fn builders() {
            let r = StorageRelation::to_one("Customer").with_delete(RelationConstraint::Cascade).with_field_name("id");
            assert_eq!(
                (r.delete_constraint, r.update_constraint, r.field_name.as_deref()),
                (Some(RelationConstraint::Cascade), Some(RelationConstraint::Nothing), Some("id"))
            );
            let ix = StorageIndex::of(&[("code", Direction::Desc), ("at", Direction::Asc)], true);
            assert_eq!(ix.fields[0], StorageIndexField { field_name: Some("code".into()), direction: Some(Direction::Desc) });
            assert!(ix.unique);
            let d = DataObject::of(doc(r#"{"a":1}"#)).with_message("first");
            assert_eq!(d.message.as_deref(), Some("first"));
        }

        /// `MySQLColumnType`: every name, its arity and whether it is numeric or textual.
        #[test]
        fn mysql_column_types() {
            use Arity::{FractionalSeconds, Length, PrecisionScale};
            const NONE: Arity = Arity::None;
            let table = [
                ("TINYINT", NONE, true),
                ("SMALLINT", NONE, true),
                ("MEDIUMINT", NONE, true),
                ("INT", NONE, true),
                ("BIGINT", NONE, true),
                ("DECIMAL", PrecisionScale, true),
                ("FLOAT", NONE, true),
                ("DOUBLE", NONE, true),
                ("CHAR", Length, false),
                ("VARCHAR", Length, false),
                ("TINYTEXT", NONE, false),
                ("TEXT", NONE, false),
                ("MEDIUMTEXT", NONE, false),
                ("LONGTEXT", NONE, false),
                ("BINARY", Length, false),
                ("VARBINARY", Length, false),
                ("TINYBLOB", NONE, false),
                ("BLOB", NONE, false),
                ("MEDIUMBLOB", NONE, false),
                ("LONGBLOB", NONE, false),
                ("DATE", NONE, false),
                ("DATETIME", FractionalSeconds, false),
                ("TIME", FractionalSeconds, false),
                ("TIMESTAMP", FractionalSeconds, false),
                ("YEAR", NONE, false),
                ("JSON", NONE, false),
            ];
            let textual = ["CHAR", "VARCHAR", "TINYTEXT", "TEXT", "MEDIUMTEXT", "LONGTEXT"];
            for (name, arity, numeric) in table {
                let t = MySqlColumnType::from_name(name).unwrap_or_else(|| panic!("{name}"));
                assert_eq!(t.name(), name);
                assert_eq!(t.arity(), arity, "{name}");
                assert_eq!(t.numeric(), numeric, "{name}");
                assert_eq!(t.textual(), textual.contains(&name), "{name}");
            }
            assert_eq!(MySqlColumnType::from_name("varchar"), None);
        }

        /// `DraftCopyFilter.Follow.refFieldOrDefault`.
        #[test]
        fn follow_ref_field() {
            let f = |r: Option<&str>| Follow { field: "a".into(), storage: "S".into(), ref_field: r.map(str::to_string) };
            assert_eq!(f(Some("code")).ref_field_or_default(), "code");
            assert_eq!(f(Some("  ")).ref_field_or_default(), "_id");
            assert_eq!(f(None).ref_field_or_default(), "_id");
            assert!(DraftCopyFilter { follow: Some(vec![f(None)]), ..Default::default() }.has_follow());
            assert!(!DraftCopyFilter::default().has_follow());
        }

        #[test]
        fn connections() {
            let c = Connection::from_value(&v(r#"{"_id":"c1","name":"appData","appCode":"shop","clientCode":"SYSTEM",
                "connectionType":"APP_DATA","connectionSubType":"MYSQL","connectionDetails":{"url":"r2dbc:mysql://h/db"}}"#))
            .unwrap();
            assert_eq!(c.id, "c1");
            assert_eq!(c.connection_sub_type, Some(ConnectionSubType::MySql));
            assert_eq!(c.connection_type.as_deref(), Some("APP_DATA"));
            assert_eq!(c.detail("url"), Some(&Value::from("r2dbc:mysql://h/db")));
            assert_eq!(c.detail("user"), None);
            let c = Connection::from_value(&v(r#"{"id":"c2","connectionSubType":"MONGO"}"#)).unwrap();
            assert_eq!((c.id.as_str(), c.connection_sub_type.clone()), ("c2", Some(ConnectionSubType::Mongo)));
            assert_eq!(c.detail("url"), None);
            let c = Connection::from_value(&v(r#"{"connectionSubType":"REST_API"}"#)).unwrap();
            assert_eq!(c.connection_sub_type, Some(ConnectionSubType::Other("REST_API".into())));
            assert!(Connection::from_value(&v("1")).is_err());
        }
    }

    mod schema_model {
        use super::*;

        #[test]
        fn type_names() {
            use SchemaType::*;
            let all = [Integer, Long, Float, Double, String, Object, Array, Boolean, Null];
            let names: Vec<&str> = all.iter().map(|t| t.name()).collect();
            assert_eq!(names, vec!["INTEGER", "LONG", "FLOAT", "DOUBLE", "STRING", "OBJECT", "ARRAY", "BOOLEAN", "NULL"]);
            let listed = schema(r#"{"type":["integer","LONG","Float","double","STRING","object","ARRAY","boolean","NULL","STRING"]}"#);
            assert_eq!(listed.allowed_types(), all.to_vec());
            assert_eq!(schema(r#"{"type":"number"}"#).allowed_types(), vec![Double]);
            assert!(schema("{}").allowed_types().is_empty());
        }

        #[test]
        fn formats_lengths_and_enums() {
            let s = schema(r#"{"type":"STRING","format":"ID","maxLength":12.0,"enums":["A","B"]}"#);
            assert_eq!(s.format, Some(StringFormat::Id));
            assert_eq!(s.max_length, Some(12));
            assert_eq!(s.enums, Some(vec![Value::from("A"), Value::from("B")]));
            assert_eq!(schema(r#"{"format":"PHONE"}"#).format, None);
            assert_eq!(Schema::from_value(&v(r#""STRING""#)), None);
        }

        /// KIRun's `ArraySchemaTypeAdapter`: a schema, `singleSchema`, `tupleSchema`, or a
        /// list.
        #[test]
        fn items() {
            let single = |json: &str| match schema(json).items {
                Some(Items::Single(s)) => s.allowed_types(),
                other => panic!("{other:?}"),
            };
            let tuple = |json: &str| match schema(json).items {
                Some(Items::Tuple(t)) => t.len(),
                other => panic!("{other:?}"),
            };
            assert_eq!(single(r#"{"type":"ARRAY","items":{"type":"STRING"}}"#), vec![SchemaType::String]);
            assert_eq!(single(r#"{"type":"ARRAY","items":{"singleSchema":{"type":"LONG"}}}"#), vec![SchemaType::Long]);
            assert_eq!(tuple(r#"{"type":"ARRAY","items":{"tupleSchema":[{"type":"STRING"},{"type":"INTEGER"}]}}"#), 2);
            assert_eq!(tuple(r#"{"type":"ARRAY","items":[{"type":"STRING"}]}"#), 1);
            let a = Schema::of_array("tags", Schema::of_string("tag"));
            assert!(a.has_type(SchemaType::Array));
            assert_eq!(schema_refs::single_item(&a).and_then(|i| i.name.clone()).as_deref(), Some("tag"));
        }

        #[test]
        fn defs() {
            let s = schema(r#"{"$defs":{"A":{"type":"STRING"},"bad":1}}"#);
            let defs = s.defs.unwrap();
            assert_eq!(defs.keys().collect::<Vec<_>>(), vec!["A"]);
        }
    }

    mod query_model {
        use super::*;

        fn sort(json: &str) -> Result<Option<Sort>, String> {
            Sort::from_value(&v(json))
        }

        /// Spring Data's `SortJsonComponent` for one order.
        #[test]
        fn an_order_as_json() {
            let o = Order { null_handling: NullHandling::NullsFirst, ..Order::desc("a") };
            assert_eq!(
                o.to_value().to_java_json(),
                r#"{"direction":"DESC","property":"a","ignoreCase":false,"nullHandling":"NULLS_FIRST","ascending":false,"descending":true}"#
            );
            assert_eq!(NullHandling::NullsLast.name(), "NULLS_LAST");
        }

        /// `SortSerializationModule.SortDeserializer`.
        #[test]
        fn sorts() {
            assert_eq!(sort("null"), Ok(None));
            assert_eq!(sort(r#""updatedAt""#), Ok(None));
            assert!(sort(r#"["a"]"#).is_err());
            assert!(sort(r#"{"property":"a","direction":"desc"}"#).is_err());
            let handled = |h: &str| sort(&format!(r#"{{"property":"a","nullHandling":"{h}"}}"#)).unwrap().unwrap().orders[0].null_handling;
            assert_eq!(handled("NATIVE"), NullHandling::Native);
            assert_eq!(handled("NULLS_FIRST"), NullHandling::NullsFirst);
            assert_eq!(handled("NULLS_LAST"), NullHandling::NullsLast);
            assert!(sort(r#"{"property":"a","nullHandling":"LAST"}"#).is_err());
            assert!(sort(r#"{"direction":"ASC"}"#).is_err());
            assert_eq!(sort(r#"{"property":" "}"#), Err("Property must not be null or empty".into()));
            // textValue() of a JSON boolean is null, so only the string turns it on.
            let ic = |x: &str| sort(&format!(r#"{{"property":"a","ignoreCase":{x}}}"#)).unwrap().unwrap().orders[0].ignore_case;
            assert!(!ic("true"));
            assert!(ic(r#""true""#));
        }

        /// `PageRequest.of` refuses a negative page and a size under one.
        #[test]
        fn pageable_refusals() {
            let e = Pageable::of(-1, 10, Sort::unsorted()).unwrap_err();
            assert_eq!(e.status().as_u16(), 500);
            assert!(e.message().contains("Page index must not be less than zero"), "{}", e.message());
            let e = Pageable::of(0, 0, Sort::unsorted()).unwrap_err();
            assert!(e.message().contains("Page size must not be less than one"), "{}", e.message());
            let q = Query { sort: None, ..Default::default() };
            assert!(q.pageable().unwrap_err().message().contains("Sort must not be null"));
        }

        /// Jackson's coercions for the bean's fields (JVM, with the services' modules).
        #[test]
        fn query_fields() {
            let q = Query::from_value(&v(
                r#"{"eager":true,"eagerFields":["a",1],"size":"5","page":2.0,"count":"false","excludeFields":"true","fields":["x"]}"#,
            ))
            .unwrap();
            assert_eq!((q.eager, q.eager_fields.as_deref()), (Some(true), Some(&["a".to_string(), "1".to_string()][..])));
            assert_eq!((q.size, q.page, q.count, q.exclude_fields), (5, 2, Some(false), Some(true)));
            assert!(!q.counts() && q.excludes());
            assert_eq!(Query::from_value(&v(r#"{"size":null}"#)).unwrap().size, 0);
            for bad in [r#"{"size":"abc"}"#, r#"{"size":true}"#, r#"{"size":3000000000}"#, "[]"] {
                assert!(Query::from_value(&v(bad)).is_err(), "{bad}");
            }
            let q = Query::from_value(&v(r#"{"count":null,"fields":null}"#)).unwrap();
            assert_eq!((q.count, q.fields), (None, None));
        }

        #[test]
        fn serde_entry_points() {
            let q: Query = serde_json::from_str(r#"{"size":3,"condition":{"field":"a","value":1}}"#).unwrap();
            assert_eq!(q.size, 3);
            assert!(serde_json::from_str::<Query>(r#"{"sort":{"property":"a","direction":"UP"}}"#).is_err());
            let a: AggregateQuery = serde_json::from_str(r#"{"aggregations":[{"function":"COUNT"}],"count":true}"#).unwrap();
            assert!(a.counts());
            assert!(serde_json::from_str::<AggregateQuery>(r#"{"aggregations":[{"function":"MEDIAN"}]}"#).is_err());
        }

        #[test]
        fn builders_and_aliases() {
            let q = Query::default()
                .with_condition(FilterCondition::eq("a", 1))
                .with_sort(Sort::by(vec![Order::asc("a")]))
                .with_page(3, 7);
            assert_eq!((q.page, q.size), (3, 7));
            assert!(q.condition.is_some() && q.sort.as_ref().unwrap().is_sorted());
            let j = StorageJoin::new("customer");
            assert_eq!((j.join_type, j.resolved_alias().as_deref()), (Some(JoinType::Left), Some("customer")));
            assert_eq!(Direction::Desc.name(), "DESC");
            assert_eq!((DateEncoding::EpochSeconds.name(), DateEncoding::EpochMillis.name()), ("EPOCH_SECONDS", "EPOCH_MILLIS"));
            let g = GroupByField { alias: Some(" ".into()), ..GroupByField::new("a.b") };
            assert_eq!(g.resolved_alias().as_deref(), Some("a_b"));
            let sq = StorageSubQuery {
                storage: Some("Line".into()),
                relation: None,
                alias: Some("".into()),
                condition: None,
                aggregations: None,
                having: None,
                required: Some(true),
            };
            assert_eq!(sq.resolved_alias().as_deref(), Some("Line"));
        }

        #[test]
        fn aggregate_query_parts() {
            let a = AggregateQuery::from_value(&v(r#"{
                "subQueries":[{"storage":"Line","relation":"order","aggregations":[{"function":"SUM","field":"amt"}]},
                              {"storage":"Note","required":false}],
                "groupBy":[{"field":"at","bucket":"DAY","encoding":"EPOCH_MILLIS","timezone":"Asia/Kolkata"}],
                "joins":[{"relation":"customer","type":null},{"relation":"owner","type":"INNER"}],
                "aggregations":[{"function":null,"field":"x"}]}"#))
            .unwrap();
            assert!(a.has_sub_queries() && a.has_joins());
            let subs = a.sub_queries.unwrap();
            assert_eq!((subs[0].required, subs[0].aggregations.as_ref().map(Vec::len)), (Some(true), Some(1)));
            assert_eq!((subs[1].required, subs[1].aggregations.as_ref()), (Some(false), None));
            let groups = a.group_by.unwrap();
            assert_eq!(groups.len(), 1);
            assert_eq!((groups[0].bucket, groups[0].encoding), (Some(DateBucketUnit::Day), Some(DateEncoding::EpochMillis)));
            let joins = a.joins.unwrap();
            assert_eq!((joins[0].join_type, joins[1].join_type), (None, Some(JoinType::Inner)));
            assert_eq!(a.aggregations.unwrap()[0].function, None);
            for bad in [
                r#"{"joins":[{"relation":"c","type":5}]}"#,
                r#"{"aggregations":[{"function":"MEDIAN"}]}"#,
                r#"{"aggregations":[{"function":true}]}"#,
                r#"{"groupBy":[{"field":"at","bucket":true}]}"#,
                r#"{"groupBy":[{"field":"at","bucket":"FORTNIGHT"}]}"#,
                r#"{"groupBy":[{"field":"at","encoding":"EPOCH_NANOS"}]}"#,
                "1",
            ] {
                assert!(AggregateQuery::from_value(&v(bad)).is_err(), "{bad}");
            }
        }
    }

    mod condition_model {
        use super::*;
        use appdata::model::condition::FieldExpression;

        fn parse(json: &str) -> Result<Option<Condition>, String> {
            Condition::from_value(&v(json))
        }

        fn filter(json: &str) -> FilterCondition {
            match parse(json) {
                Ok(Some(Condition::Filter(f))) => f,
                other => panic!("{other:?}"),
            }
        }

        /// `FieldExpression.isValid`.
        #[test]
        fn field_expressions() {
            let fx = |f: Option<&str>, fields: &[&str]| FieldExpression {
                function: f.map(str::to_string),
                fields: Some(fields.iter().map(|s| s.to_string()).collect()),
                separator: None,
            };
            for f in ["UPPER", "LOWER", "TRIM"] {
                assert!(fx(Some(f), &["a"]).is_valid(), "{f}");
                assert!(!fx(Some(f), &["a", "b"]).is_valid(), "{f}");
            }
            for f in ["CONCAT", "COALESCE"] {
                assert!(fx(Some(f), &["a", "b"]).is_valid(), "{f}");
                assert!(!fx(Some(f), &["a"]).is_valid(), "{f}");
            }
            assert!(!fx(None, &["a"]).is_valid());
            assert!(!fx(Some("UPPER"), &[]).is_valid());
            assert!(!FieldExpression { function: Some("UPPER".into()), fields: None, separator: None }.is_valid());
        }

        #[test]
        fn negate_and_class_name() {
            let f: Condition = FilterCondition::eq("a", 1).negated().into();
            assert!(f.negate());
            assert_eq!(f.class_name(), "FilterCondition");
            let c: Condition = ComplexCondition::and(vec![]).into();
            assert!(!c.negate());
            assert_eq!(c.class_name(), "ComplexCondition");
            let h = parse(r#"{"aggregateFunction":"SUM","negate":true,"condition":{"field":"a"}}"#).unwrap().unwrap();
            assert!(h.negate());
            let g = parse(r#"{"havingConditions":[],"negate":true}"#).unwrap().unwrap();
            assert!(g.negate());
        }

        /// A non-empty list is not a condition (`AbstractConditionDeserializer`: "Invalid
        /// condition").
        #[test]
        fn a_list_is_refused() {
            assert_eq!(parse(r#"[{"field":"a"}]"#), Err("Invalid condition".into()));
        }

        #[test]
        fn through_serde() {
            let c: Condition = serde_json::from_str(r#"{"field":"a","value":1}"#).unwrap();
            assert!(matches!(c, Condition::Filter(_)));
            assert!(serde_json::from_str::<Condition>("{}").is_err());
            assert!(serde_json::from_str::<Condition>(r#"{"value":1}"#).is_err());
        }

        /// Jackson's scalar coercions on the bean's fields (JVM, with the services' modules).
        #[test]
        fn filter_fields() {
            assert!(filter(r#"{"field":"a","negate":"true"}"#).negate);
            assert!(!filter(r#"{"field":"a","negate":""}"#).negate);
            assert!(!filter(r#"{"field":"a","negate":"false"}"#).negate);
            assert!(filter(r#"{"field":"a","negate":1}"#).negate);
            assert!(!filter(r#"{"field":"a","negate":0}"#).negate);
            let f = filter(r#"{"field":"a","valueField":true,"toValueField":true}"#);
            assert!(f.value_field && f.to_value_field);
            // The Gson spelling too (DIFFERENCES.md: condition JSON).
            assert!(filter(r#"{"field":"a","isValueField":true,"isToValueField":true}"#).to_value_field);
            assert!(parse(r#"{"field":"a","negate":[1]}"#).is_err());
            assert!(parse(r#"{"field":"a","operator":true}"#).is_err());
            assert!(parse(r#"{"field":"a","multiValue":"x"}"#).is_err());
            let f = filter(r#"{"field":"a","operator":null,"matchOperator":"LIKE"}"#);
            assert_eq!((f.operator, f.match_operator), (None, Some(FilterOperator::Like)));
        }

        /// A filter addressed through an expression rather than a field.
        #[test]
        fn field_expression_filters() {
            let f = filter(r#"{"fieldExpr":{"function":"CONCAT","fields":["first","last"],"separator":" "},"value":"A B"}"#);
            assert_eq!(f.field, None);
            let fx = f.field_expr.unwrap();
            assert!(fx.is_valid());
            assert_eq!(fx.separator.as_deref(), Some(" "));
            let f = filter(r#"{"field":5,"fieldExpr":{"function":"UPPER","fields":["a"],"separator":1.5}}"#);
            assert_eq!((f.field.as_deref(), f.field_expr.unwrap().separator.as_deref()), (Some("5"), Some("1.5")));
            let f = filter(r#"{"field":true,"fieldExpr":{"function":"UPPER","fields":["a"]}}"#);
            assert_eq!(f.field.as_deref(), Some("true"));
            assert!(parse(r#"{"field":[1],"fieldExpr":{"function":"UPPER","fields":["a"]}}"#).is_err());
            assert_eq!(parse(r#"{"fieldExpr":{}}"#), Err("Invalid condition".into()));
        }

        #[test]
        fn complex_and_group_parts() {
            let Some(Condition::Complex(c)) = parse(r#"{"operator":"AND","conditions":null}"#).unwrap() else { panic!() };
            assert_eq!(c.conditions, None);
            assert!(parse(r#"{"operator":"OR","conditions":"x"}"#).is_err());
            let Some(Condition::Complex(c)) =
                parse(r#"{"operator":"OR","conditions":[],"groupCondition":{"fields":["region"],"operator":"OR"}}"#).unwrap()
            else {
                panic!()
            };
            let g = c.group_condition.unwrap();
            assert_eq!((g.operator, g.fields), (Some(ComplexOperator::Or), vec!["region".to_string()]));

            let Some(Condition::Group(g)) = parse(
                r#"{"havingConditions":[{"condition":{"field":"a","value":1}},{"aggregateFunction":null,"condition":null}],
                    "operator":null}"#,
            )
            .unwrap() else {
                panic!()
            };
            assert_eq!(g.operator, None);
            // HavingCondition's aggregateFunction defaults to MAX; an explicit null stays null.
            assert_eq!(g.having_conditions[0].aggregate_function, Some(AggregateFunction::Max));
            assert!(g.having_conditions[0].condition.is_some());
            assert_eq!((g.having_conditions[1].aggregate_function, &g.having_conditions[1].condition), (None, &None));
            assert!(parse(r#"{"havingConditions":[{"aggregateFunction":true}]}"#).is_err());
            let Some(Condition::Group(g)) = parse(r#"{"havingConditions":[]}"#).unwrap() else { panic!() };
            assert_eq!(g.operator, Some(ComplexOperator::And));
        }
    }

    mod page_model {
        use super::*;

        #[test]
        fn map_and_json() {
            let p = Page::of(vec![1, 2], Pageable::of(0, 10, Sort::unsorted()).unwrap(), || 2);
            let docs = p.map(|i| doc(&format!(r#"{{"n":{i}}}"#)));
            assert_eq!(docs.content[1]["n"], Value::Int(2));
            assert_eq!(docs.to_java_json(), docs.to_value().to_java_json());
            assert!(docs.to_java_json().starts_with(r#"{"content":[{"n":1},{"n":2}],"pageable":"#));
            let empty: Page<Document> = Page::of(vec![], Pageable::of(0, 10, Sort::unsorted()).unwrap(), || 0);
            assert!(empty.to_java_json().starts_with(r#"{"pageable":"#));
        }

        /// Spring's `getTotalPages`: a size of zero is one page.
        #[test]
        fn a_size_of_zero_is_one_page() {
            let p: Page<i32> = Page { content: vec![], pageable: Pageable { page: 0, size: 0, sort: Sort::unsorted() }, total: 0 };
            assert_eq!(p.total_pages(), 1);
        }
    }
}
