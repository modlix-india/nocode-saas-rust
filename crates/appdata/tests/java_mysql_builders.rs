//! Ports of the Java unit tests for the pure MySQL builders, same inputs and expectations:
//! `MySQLAggregateBuilderTest`, `MySQLColumnDefinitionsTest`, `MySQLColumnNamesTest`,
//! `MySQLColumnOverrideTest`, `MySQLDriftTest`, `MySQLFieldResolverTest`,
//! `MySQLFilterBuilderTest`, `MySQLForeignKeysTest`, `MySQLIndexesTest` and
//! `MySQLJoinPlannerTest` (commons-core `src/test/java/.../service/connection/appdata/mysql/`).
//!
//! No database. Where Java renders a jOOQ statement with `ParamType.INLINED`, the Rust side
//! renders the same statement with `Sql::inlined()` / `Cond::inlined()`.
//!
//! `mod extra` at the end is not a port: focused tests for reachable lines the ports leave
//! uncovered, each expectation checked against the Java code (and, for jOOQ's rendering
//! and the stemmer, against jOOQ 3.19.21 and the compiled Java `PorterStemmer`).

use std::collections::BTreeSet;

use indexmap::{IndexMap, IndexSet};

use appdata::model::{
    AggregateFunction, AggregateQuery, Aggregation, ColumnDefinitions, ComplexCondition, Condition, DateBucketUnit,
    DateEncoding, Direction, FilterCondition, FilterOperator, GroupByField, HavingCondition, JoinType,
    MySqlColumnDefinition, MySqlColumnType, Order, RelationConstraint, RelationType, Schema, SchemaType, Sort, Storage,
    StorageColumnDefinition, StorageIndex, StorageIndexField, StorageJoin, StorageRelation, StorageSubQuery,
    StringFormat,
};
use appdata::mysql::column::{self, MySqlColumn};
use appdata::mysql::field_resolver::FieldResolver;
use appdata::mysql::filter_builder::{self, FilterError, FilterResult};
use appdata::mysql::join_planner::{self, JoinedTable, MAX_JOINS, PARENT};
use appdata::mysql::sql::{Bind, Cond, FieldOps, Select, Sql};
use appdata::mysql::{aggregate_builder, column_names, drift, foreign_keys, indexes, table_planner, type_mapper, value_codec};
use appdata::value::{Decimal, Document, Value};

fn set(items: &[&str]) -> IndexSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

fn none() -> IndexSet<String> {
    IndexSet::new()
}

/// `new FilterCondition().setField(field).setOperator(op).setValue(value)`.
fn fc(field: Option<&str>, op: FilterOperator, value: Option<Value>) -> FilterCondition {
    FilterCondition { field: field.map(str::to_string), operator: Some(op), value, ..Default::default() }
}

fn f(field: &str, op: FilterOperator, value: impl Into<Value>) -> FilterCondition {
    fc(Some(field), op, Some(value.into()))
}

mod mysql_aggregate_builder_test {
    use super::*;

    fn table() -> Sql {
        Sql::name(&["db", "orders"])
    }

    fn query(group_by: Option<Vec<GroupByField>>, aggs: Vec<Aggregation>) -> AggregateQuery {
        AggregateQuery { group_by, aggregations: Some(aggs), ..Default::default() }
    }

    fn agg(function: AggregateFunction, field: Option<&str>, alias: &str) -> Aggregation {
        Aggregation::new(function, field).with_alias(alias)
    }

    fn sql(q: &AggregateQuery) -> String {
        aggregate_builder::grouped(&table(), q, Cond::None, &FieldResolver::of(none())).unwrap().to_sql().inlined()
    }

    fn bucket(field: &str, unit: DateBucketUnit) -> GroupByField {
        GroupByField { bucket: Some(unit), ..GroupByField::new(field) }
    }

    fn count_n() -> Vec<Aggregation> {
        vec![agg(AggregateFunction::Count, None, "n")]
    }

    mod measures {
        use super::*;

        #[test]
        fn count_rows() {
            assert!(sql(&query(None, count_n())).contains("count(*)"));
        }

        #[test]
        fn count_column() {
            let s = sql(&query(None, vec![agg(AggregateFunction::Count, Some("amount"), "n")]));
            assert!(s.contains("count(`amount`)"), "{s}");
        }

        #[test]
        fn sum_does_not_cast() {
            let s = sql(&query(
                None,
                vec![agg(AggregateFunction::Sum, Some("amount"), "total"), agg(AggregateFunction::Avg, Some("amount"), "mean")],
            ));
            assert!(s.contains("sum(`amount`)"), "{s}");
            assert!(s.contains("avg(`amount`)"), "{s}");
            assert!(!s.to_lowercase().contains("cast("), "{s}");
            assert!(s.contains("total"), "{s}");
        }

        #[test]
        fn min_max() {
            let s = sql(&query(None, vec![agg(AggregateFunction::Min, Some("code"), "lowest")]));
            assert!(s.contains("min(`code`)"), "{s}");
        }

        #[test]
        fn count_distinct() {
            let s = sql(&query(None, vec![agg(AggregateFunction::CountDistinct, Some("ticketId"), "deals")]));
            assert!(s.contains("count(distinct `ticketId`)"), "{s}");
            assert!(s.contains("`deals`"), "{s}");
        }

        #[test]
        fn aliased() {
            let s = sql(&query(
                None,
                vec![agg(AggregateFunction::Sum, Some("amount"), "total"), agg(AggregateFunction::Count, None, "n")],
            ));
            assert!(s.contains("`total`"), "{s}");
            assert!(s.contains("`n`"), "{s}");
        }
    }

    mod group_keys {
        use super::*;

        #[test]
        fn plain() {
            let s = sql(&query(Some(vec![GroupByField::new("region")]), count_n()));
            assert!(s.contains("group by `region`"), "{s}");
            assert!(s.contains("`region`"), "{s}");
        }

        #[test]
        fn groups_by_expression() {
            let g = GroupByField { alias: Some("r".into()), ..GroupByField::new("region") };
            let s = sql(&query(Some(vec![g]), count_n()));
            assert!(s.contains("group by `region`"), "{s}");
            assert!(!s.contains("group by `r`"), "{s}");
        }

        #[test]
        fn date_column_bucket() {
            let s = sql(&query(Some(vec![bucket("createdAt", DateBucketUnit::Month)]), count_n()));
            assert!(!s.contains("1970-01-01"), "{s}");
            assert!(s.contains("DAYOFMONTH"), "{s}");
        }

        #[test]
        fn epoch_seconds_bucket() {
            let g = GroupByField { encoding: Some(DateEncoding::EpochSeconds), ..bucket("ts", DateBucketUnit::Day) };
            let s = sql(&query(Some(vec![g]), count_n()));
            assert!(s.contains("1970-01-01"), "{s}");
            assert!(s.contains("* 1000 / 1000"), "{s}");
            assert!(s.contains("TIMESTAMPDIFF(SECOND"), "{s}");
        }

        #[test]
        fn epoch_millis_bucket() {
            let g = GroupByField { encoding: Some(DateEncoding::EpochMillis), ..bucket("ts", DateBucketUnit::Day) };
            let s = sql(&query(Some(vec![g]), count_n()));
            assert!(s.contains(") * 1000"), "{s}");
        }

        #[test]
        fn utc_is_plain() {
            let s = sql(&query(Some(vec![bucket("createdAt", DateBucketUnit::Day)]), count_n()));
            assert!(!s.contains("CONVERT_TZ"), "{s}");
        }

        #[test]
        fn named_zone() {
            let g = GroupByField { timezone: Some("Asia/Kolkata".into()), ..bucket("createdAt", DateBucketUnit::Day) };
            let s = sql(&query(Some(vec![g]), count_n()));
            assert!(s.contains("'+00:00', 'Asia/Kolkata'"), "{s}");
            assert!(s.contains("'Asia/Kolkata', '+00:00'"), "{s}");
        }

        /// `DateBucketUnit.values()`, spelled out.
        #[test]
        fn truncation_is_not_a_string() {
            for unit in [
                DateBucketUnit::Year,
                DateBucketUnit::Quarter,
                DateBucketUnit::Month,
                DateBucketUnit::Week,
                DateBucketUnit::IsoWeek,
                DateBucketUnit::Day,
                DateBucketUnit::Hour,
            ] {
                let t = aggregate_builder::truncate(unit, "d");
                assert!(!t.contains("DATE_FORMAT"), "{} -> {t}", unit.name());
            }
        }

        #[test]
        fn week_start() {
            assert!(aggregate_builder::truncate(DateBucketUnit::Week, "d").contains("DAYOFWEEK"));
        }

        #[test]
        fn iso_week_start() {
            assert_eq!(
                aggregate_builder::truncate(DateBucketUnit::IsoWeek, "d"),
                "DATE_SUB(DATE(d), INTERVAL WEEKDAY(d) DAY)"
            );
        }

        #[test]
        fn iso_week_in_zone() {
            let g = GroupByField {
                alias: Some("wk".into()),
                timezone: Some("Asia/Kolkata".into()),
                ..bucket("createdAt", DateBucketUnit::IsoWeek)
            };
            let s = sql(&query(Some(vec![g]), count_n()));
            assert!(s.contains("WEEKDAY(CONVERT_TZ("), "{s}");
            assert!(s.contains("'Asia/Kolkata', '+00:00'"), "{s}");
        }

        #[test]
        fn json_path_key() {
            let g = GroupByField { alias: Some("city".into()), ..GroupByField::new("address.city") };
            let s = aggregate_builder::grouped(&table(), &query(Some(vec![g]), count_n()), Cond::None, &FieldResolver::of(set(&["address"])))
                .unwrap()
                .to_sql()
                .inlined();
            assert!(s.contains("json_extract"), "{s}");
        }
    }

    mod shape {
        use super::*;

        #[test]
        fn no_group_by() {
            let s = sql(&query(None, vec![agg(AggregateFunction::Sum, Some("amount"), "total")]));
            assert!(!s.contains("group by"), "{s}");
        }

        #[test]
        fn having() {
            let mut q = query(Some(vec![GroupByField::new("region")]), vec![agg(AggregateFunction::Sum, Some("amount"), "total")]);
            q.having = Some(FilterCondition::eq("total", 100).into());
            let having = filter_builder::build_json(q.having.as_ref(), none()).unwrap();
            let s = aggregate_builder::page(&table(), &q, Cond::None, Some(having), &q.pageable().unwrap(), &FieldResolver::of(none()))
                .unwrap()
                .to_sql()
                .inlined();
            assert!(s.contains("having"), "{s}");
            assert!(s.contains("`total`"), "{s}");
        }

        #[test]
        fn sort_by_alias() {
            let mut q = query(Some(vec![GroupByField::new("region")]), vec![agg(AggregateFunction::Sum, Some("amount"), "total")]);
            q.sort = Some(Sort::by(vec![Order::desc("total")]));
            let s = aggregate_builder::page(&table(), &q, Cond::None, None, &q.pageable().unwrap(), &FieldResolver::of(none()))
                .unwrap()
                .to_sql()
                .inlined();
            assert!(s.contains("order by `total` desc"), "{s}");
        }

        #[test]
        fn count_wraps() {
            let q = query(Some(vec![GroupByField::new("region")]), count_n());
            let s = aggregate_builder::count(&table(), &q, Cond::None, None, &FieldResolver::of(none())).unwrap().to_sql().inlined();
            assert!(s.contains("grouped"), "{s}");
            assert!(s.contains("group by"), "{s}");
        }

        #[test]
        fn count_keeps_having() {
            let mut q = query(Some(vec![GroupByField::new("region")]), vec![agg(AggregateFunction::Sum, Some("amount"), "total")]);
            q.having = Some(FilterCondition::eq("total", 100).into());
            let having = filter_builder::build_json(q.having.as_ref(), none()).unwrap();
            let s = aggregate_builder::count(&table(), &q, Cond::None, Some(having), &FieldResolver::of(none()))
                .unwrap()
                .to_sql()
                .inlined();
            assert!(s.contains("having"), "{s}");
        }

        #[test]
        fn paging() {
            let mut q = query(Some(vec![GroupByField::new("region")]), count_n());
            q.size = 5_000;
            q.page = 2;
            let s = aggregate_builder::page(&table(), &q, Cond::None, None, &q.pageable().unwrap(), &FieldResolver::of(none()))
                .unwrap()
                .to_sql()
                .inlined();
            assert!(s.contains(&format!("limit {}", AggregateQuery::MAX_SIZE)), "{s}");
        }

        #[test]
        fn named_zones_listed() {
            let a = GroupByField { timezone: Some("Asia/Kolkata".into()), ..bucket("a", DateBucketUnit::Day) };
            let q = query(Some(vec![a, bucket("b", DateBucketUnit::Day)]), count_n());
            assert_eq!(aggregate_builder::named_zones(&q), set(&["Asia/Kolkata"]));
        }
    }
}

mod mysql_column_definitions_test {
    use super::*;

    fn def(t: MySqlColumnType) -> MySqlColumnDefinition {
        MySqlColumnDefinition { column_type: Some(t), ..Default::default() }
    }

    /// `MySQLColumnDefinitions.problems(field, def)`, which requires a type.
    fn problems(field: &str, def: Option<&MySqlColumnDefinition>) -> Vec<String> {
        column::problems(field, def, true)
    }

    mod rendering {
        use super::*;

        #[test]
        fn decimal() {
            let d = MySqlColumnDefinition { precision: Some(10), scale: Some(2), ..def(MySqlColumnType::Decimal) };
            assert_eq!(column::render_type(&d), "DECIMAL(10,2)");
        }

        #[test]
        fn unsigned() {
            let d = MySqlColumnDefinition {
                precision: Some(10),
                scale: Some(2),
                unsigned: Some(true),
                ..def(MySqlColumnType::Decimal)
            };
            assert_eq!(column::render_type(&d), "DECIMAL(10,2) UNSIGNED");
        }

        #[test]
        fn unsigned_on_text() {
            let d = MySqlColumnDefinition { length: Some(20), unsigned: Some(true), ..def(MySqlColumnType::Varchar) };
            assert_eq!(column::render_type(&d), "VARCHAR(20)");
        }

        #[test]
        fn fractional_seconds() {
            assert_eq!(column::render_type(&def(MySqlColumnType::Datetime)), "DATETIME");
            let zero = MySqlColumnDefinition { precision: Some(0), ..def(MySqlColumnType::Datetime) };
            assert_eq!(column::render_type(&zero), "DATETIME");
            let six = MySqlColumnDefinition { precision: Some(6), ..def(MySqlColumnType::Datetime) };
            assert_eq!(column::render_type(&six), "DATETIME(6)");
        }

        #[test]
        fn bare() {
            assert_eq!(column::render_type(&def(MySqlColumnType::Json)), "JSON");
            assert_eq!(column::render_type(&def(MySqlColumnType::Bigint)), "BIGINT");
        }

        #[test]
        fn collation_is_separate() {
            let d = MySqlColumnDefinition { length: Some(30), collation: Some("utf8mb4_bin".into()), ..def(MySqlColumnType::Varchar) };
            assert_eq!(column::render_type(&d), "VARCHAR(30)");
            assert_eq!(column::collation(&d).as_deref(), Some("utf8mb4_bin"));
        }
    }

    mod refusals {
        use super::*;

        #[test]
        fn decimal_needs_both() {
            let p = problems("price", Some(&def(MySqlColumnType::Decimal)));
            assert_eq!(p.len(), 1);
            assert!(p[0].contains("precision and a scale"), "{}", p[0]);
        }

        #[test]
        fn varchar_needs_length() {
            assert!(problems("name", Some(&def(MySqlColumnType::Varchar))).iter().any(|p| p.contains("needs a length")));
        }

        #[test]
        fn scale_beyond_precision() {
            let d = MySqlColumnDefinition { precision: Some(4), scale: Some(6), ..def(MySqlColumnType::Decimal) };
            assert!(problems("rate", Some(&d)).iter().any(|p| p.contains("cannot exceed precision")));
        }

        #[test]
        fn char_is_capped_lower() {
            let c = MySqlColumnDefinition { length: Some(300), ..def(MySqlColumnType::Char) };
            assert!(problems("code", Some(&c)).iter().any(|p| p.contains("between 1 and 255")));
            let v = MySqlColumnDefinition { length: Some(300), ..def(MySqlColumnType::Varchar) };
            assert!(problems("blurb", Some(&v)).is_empty());
        }

        #[test]
        fn stray_arguments() {
            let j = MySqlColumnDefinition { length: Some(10), ..def(MySqlColumnType::Json) };
            assert!(problems("flag", Some(&j)).iter().any(|p| p.contains("takes no length")));
        }

        #[test]
        fn collation_on_non_text() {
            let b = MySqlColumnDefinition { collation: Some("utf8mb4_bin".into()), ..def(MySqlColumnType::Bigint) };
            assert!(problems("n", Some(&b)).iter().any(|p| p.contains("only to a text column")));
        }

        #[test]
        fn collation_is_not_an_escape_hatch() {
            let d = MySqlColumnDefinition {
                length: Some(10),
                collation: Some("utf8mb4_bin, DROP COLUMN secret".into()),
                ..def(MySqlColumnType::Varchar)
            };
            assert!(!problems("x", Some(&d)).is_empty());
            assert!(column::collation(&d).is_none());
        }

        #[test]
        fn no_definition() {
            assert!(problems("x", None).is_empty());
        }

        #[test]
        fn type_required() {
            assert!(problems("x", Some(&MySqlColumnDefinition::default())).iter().any(|p| p.contains("mysql.type is required")));
        }
    }
}

mod mysql_column_names_test {
    use super::*;

    fn hdfc() -> Schema {
        let mut props = IndexMap::new();
        for n in ["IFSC Code", "Virtual Account ", "paymentId"] {
            props.insert(n.to_string(), Schema::of_string(n));
        }
        Schema {
            name: Some("t".into()),
            types: Some(vec![SchemaType::Object]),
            properties: Some(props),
            required: Some(vec!["IFSC Code".into()]),
            ..Default::default()
        }
    }

    fn keys(d: &Document) -> BTreeSet<String> {
        d.keys().cloned().collect()
    }

    #[test]
    fn ddl() {
        let physical = column_names::physical(hdfc());
        let props: BTreeSet<String> = physical.schema.properties.as_ref().unwrap().keys().cloned().collect();
        assert_eq!(props, ["IFSC_Code", "Virtual_Account_", "paymentId"].iter().map(|s| s.to_string()).collect());
        assert_eq!(physical.schema.required, Some(vec!["IFSC_Code".to_string()]));

        let ddl = table_planner::create_table("t", &type_mapper::columns(physical.schema(), None).unwrap());
        assert!(ddl.contains("`IFSC_Code` "), "{ddl}");
        assert!(ddl.contains("`Virtual_Account_` "), "{ddl}");
        assert!(ddl.contains("NOT NULL"), "{ddl}");
    }

    #[test]
    fn round_trip() {
        let physical = column_names::physical(hdfc());

        let mut input = Document::new();
        input.insert("IFSC Code".into(), Value::from("HDFC0000001"));
        input.insert("Virtual Account ".into(), Value::from("VA1"));
        input.insert("paymentId".into(), Value::from("p1"));

        let mut stored = column_names::to_columns(&input);
        assert_eq!(keys(&stored), ["IFSC_Code", "Virtual_Account_", "paymentId"].iter().map(|s| s.to_string()).collect());

        stored.insert("_id".into(), Value::from("01J"));
        let out = physical.to_fields(stored);
        assert_eq!(out.get("IFSC Code"), Some(&Value::from("HDFC0000001")));
        assert_eq!(out.get("Virtual Account "), Some(&Value::from("VA1")));
        assert_eq!(out.get("paymentId"), Some(&Value::from("p1")));
        assert_eq!(out.get("_id"), Some(&Value::from("01J")));
    }

    /// `assertSame` becomes equality: the Rust functions take and return values.
    #[test]
    fn identity() {
        let mut props = IndexMap::new();
        props.insert(
            "amount".to_string(),
            Schema { name: Some("amount".into()), types: Some(vec![SchemaType::Double]), ..Default::default() },
        );
        let plain = Schema { name: Some("t".into()), types: Some(vec![SchemaType::Object]), properties: Some(props), ..Default::default() };

        let physical = column_names::physical(plain.clone());
        assert_eq!(physical.schema, plain);
        assert!(physical.field_names().is_empty());

        let mut defs = ColumnDefinitions::new();
        defs.insert("amount".into(), StorageColumnDefinition::default());
        assert_eq!(column_names::column_definitions(Some(&defs)), Some(defs));
    }

    #[test]
    fn column_definitions() {
        let def = StorageColumnDefinition::default();
        let mut defs = ColumnDefinitions::new();
        defs.insert("IFSC Code".into(), def.clone());
        assert_eq!(column_names::column_definitions(Some(&defs)).unwrap().get("IFSC_Code"), Some(&def));
    }

    #[test]
    fn filters() {
        let resolver = FieldResolver::of(set(&["Bank_Details"]));
        assert_eq!(format!("select {}", resolver.resolve("IFSC Code").unwrap().inlined()), "select `IFSC_Code`");
        assert!(resolver.resolve("Bank Details.city").unwrap().inlined().contains("`Bank_Details`"));
    }

    #[test]
    fn joined() {
        let mut types = IndexMap::new();
        types.insert("_id".to_string(), "CHAR(26)".to_string());
        types.insert("IFSC_Code".to_string(), "VARCHAR(20)".to_string());
        let mut join = JoinedTable::new("pay", Sql::name(&["db", "payments"]), "pay", "_id", JoinType::Left, types, none(), none());
        join.field_names.insert("IFSC_Code".into(), "IFSC Code".into());

        let mut flat = Document::new();
        flat.insert("_id".into(), Value::from("parent"));
        flat.insert("pay._id".into(), Value::from("child"));
        flat.insert("pay.IFSC_Code".into(), Value::from("HDFC0000001"));

        let out = join_planner::nest(flat, std::slice::from_ref(&join), &[]);
        let side = out.get("pay").and_then(Value::as_object).unwrap();
        assert_eq!(side.get("IFSC Code"), Some(&Value::from("HDFC0000001")));
        assert_eq!(format!("select {}", join.column("IFSC Code").inlined()), "select `pay`.`IFSC_Code`");
    }
}

mod mysql_column_override_test {
    use super::*;

    fn schema() -> Schema {
        let mut props = IndexMap::new();
        props.insert("price".to_string(), Schema::of_string("price").with_format(StringFormat::Decimal));
        props.insert("note".to_string(), Schema { max_length: Some(40), ..Schema::of_string("note") });
        props.insert("placedAt".to_string(), Schema::of_string("placedAt").with_format(StringFormat::DateTime));
        Schema { name: Some("order".into()), types: Some(vec![SchemaType::Object]), properties: Some(props), ..Default::default() }
    }

    fn defs(field: &str, mysql: MySqlColumnDefinition) -> ColumnDefinitions {
        let mut d = ColumnDefinitions::new();
        d.insert(field.into(), StorageColumnDefinition::mysql(mysql));
        d
    }

    fn mysql(t: MySqlColumnType) -> MySqlColumnDefinition {
        MySqlColumnDefinition { column_type: Some(t), ..Default::default() }
    }

    fn type_of(columns: &[MySqlColumn], name: &str) -> String {
        columns.iter().find(|c| c.name() == name).unwrap().column_type.clone()
    }

    mod mapping {
        use super::*;

        #[test]
        fn default_stands() {
            assert_eq!(type_of(&type_mapper::columns(Some(&schema()), None).unwrap(), "price"), "DECIMAL(19,4)");
        }

        #[test]
        fn override_wins() {
            let d = defs("price", MySqlColumnDefinition { precision: Some(12), scale: Some(6), ..mysql(MySqlColumnType::Decimal) });
            let columns = type_mapper::columns(Some(&schema()), Some(&d)).unwrap();
            assert_eq!(type_of(&columns, "price"), "DECIMAL(12,6)");
            assert_eq!(type_of(&columns, "note"), "VARCHAR(40)");
        }

        #[test]
        fn required_still_rules() {
            let mut props = IndexMap::new();
            props.insert("price".to_string(), Schema::of_string("price").with_format(StringFormat::Decimal));
            let required = Schema {
                types: Some(vec![SchemaType::Object]),
                properties: Some(props),
                required: Some(vec!["price".into()]),
                ..Default::default()
            };
            let d = defs("price", MySqlColumnDefinition { precision: Some(8), scale: Some(2), ..mysql(MySqlColumnType::Decimal) });
            let columns = type_mapper::columns(Some(&required), Some(&d)).unwrap();
            let c = &columns[0];
            assert!(!c.nullable);
            assert!(c.ddl().contains("NOT NULL"), "{}", c.ddl());
        }
    }

    mod derived_sets {
        use super::*;

        #[test]
        fn date_turned_into_text() {
            let d = defs("placedAt", MySqlColumnDefinition { length: Some(40), ..mysql(MySqlColumnType::Varchar) });
            assert!(type_mapper::date_string_columns(Some(&schema()), None).unwrap().contains("placedAt"));
            assert!(!type_mapper::date_string_columns(Some(&schema()), Some(&d)).unwrap().contains("placedAt"));
        }

        #[test]
        fn text_turned_into_date() {
            let d = defs("note", mysql(MySqlColumnType::Datetime));
            assert!(type_mapper::date_string_columns(Some(&schema()), Some(&d)).unwrap().contains("note"));
        }

        #[test]
        fn decimals() {
            assert_eq!(type_mapper::decimal_columns(Some(&schema()), None).unwrap(), set(&["price"]));
            let d = defs("note", MySqlColumnDefinition { precision: Some(5), scale: Some(2), ..mysql(MySqlColumnType::Decimal) });
            assert!(type_mapper::decimal_columns(Some(&schema()), Some(&d)).unwrap().contains("note"));
        }

        #[test]
        fn json() {
            let d = defs("note", mysql(MySqlColumnType::Json));
            assert!(type_mapper::json_columns(Some(&schema()), Some(&d)).unwrap().contains("note"));
        }
    }

    /// `MySQLValueCodec.decode(row, json, dates, decimals)` is the Rust `decode` with no
    /// boolean columns.
    mod decimal_round_trip {
        use super::*;

        fn row(v: Value) -> Document {
            let mut d = Document::new();
            d.insert("price".into(), v);
            d
        }

        fn decode(v: Value) -> Value {
            value_codec::decode(row(v), &none(), &none(), &set(&["price"]), &none()).shift_remove("price").unwrap()
        }

        fn encode(v: Value) -> Value {
            value_codec::encode(&row(v), &none(), &none(), &set(&["price"])).shift_remove("price").unwrap()
        }

        fn big(s: &str) -> Value {
            Value::Decimal(Decimal::parse(s).unwrap())
        }

        #[test]
        fn decoded_as_text() {
            assert_eq!(decode(big("10.5000")), Value::from("10.5000"));
        }

        #[test]
        fn trailing_zeros_kept() {
            let out = decode(big("10.5000")).java_string();
            assert!(!out.contains('E'), "{out}");
            assert_eq!(out, "10.5000");
        }

        #[test]
        fn no_exponent() {
            assert_eq!(decode(big("1E+3")), Value::from("1000"));
        }

        #[test]
        fn encoded_exactly() {
            assert_eq!(encode(Value::from("10.50")), big("10.50"));
        }

        #[test]
        fn double_is_not_taken_literally() {
            assert_eq!(encode(Value::Double(0.1)), big("0.1"));
        }

        #[test]
        fn unparseable() {
            assert_eq!(encode(Value::from("ten")), Value::from("ten"));
        }
    }
}

mod mysql_drift_test {
    use super::*;

    const DB: &str = "T_app";
    const TABLE: &str = "thing";

    fn col(name: &str, t: &str) -> MySqlColumn {
        MySqlColumn::new(name, t, true).unwrap()
    }

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn report(existing: &[MySqlColumn], desired: &[MySqlColumn], idx: &[&str], fks: &[&str]) -> drift::Report {
        drift::of(DB, TABLE, true, existing, desired, strings(idx), strings(fks))
    }

    fn id() -> Vec<MySqlColumn> {
        vec![col("_id", "VARCHAR(40)")]
    }

    #[test]
    fn clean_when_in_sync() {
        let same = vec![col("_id", "VARCHAR(40)"), col("title", "VARCHAR(100)")];
        let r = report(&same, &same, &[], &[]);
        assert!(r.clean());
        assert!(!r.needs_approval());
        assert!(drift::repair_statements(&r, false).is_empty());
        assert!(drift::repair_statements(&r, true).is_empty());
        assert!(r.summary().contains("in sync"));
    }

    #[test]
    fn missing_table_is_reported() {
        let r = drift::of(DB, TABLE, false, &[], &[col("_id", "VARCHAR(40)")], vec![], vec![]);
        assert!(!r.clean());
        assert!(r.needs_approval(), "a missing table is not something to fix without being asked");
        assert!(r.summary().contains("MISSING"));
    }

    mod approval_gate {
        use super::*;

        #[test]
        fn additive_work_needs_no_approval() {
            let r = report(
                &id(),
                &id(),
                &["CREATE INDEX `rel_x` ON `T_app`.`thing` (`x`)"],
                &["ALTER TABLE `T_app`.`thing` ADD CONSTRAINT `fk_x` FOREIGN KEY (`x`) REFERENCES `o` (`_id`)"],
            );
            assert!(!r.needs_approval());
            assert_eq!(drift::repair_statements(&r, false).len(), 2);
        }

        #[test]
        fn drops_are_withheld() {
            let r = report(
                &id(),
                &id(),
                &["DROP INDEX `stale` ON `T_app`.`thing`", "CREATE INDEX `rel_x` ON `T_app`.`thing` (`x`)"],
                &["ALTER TABLE `T_app`.`thing` DROP FOREIGN KEY `fk_old`"],
            );
            assert!(r.needs_approval());
            assert_eq!(r.drops().len(), 2);

            let unapproved = drift::repair_statements(&r, false);
            assert_eq!(unapproved.len(), 1);
            assert!(unapproved[0].starts_with("CREATE INDEX"));

            assert_eq!(drift::repair_statements(&r, true).len(), 3);
        }

        #[test]
        fn destructive_column_work_is_withheld() {
            let existing = vec![col("_id", "VARCHAR(40)"), col("gone", "VARCHAR(100)")];
            let r = report(&existing, &id(), &[], &[]);
            assert!(!r.clean());
            assert!(r.needs_approval());
            assert!(!r.dangerous().is_empty());
            assert!(drift::repair_statements(&r, false).is_empty(), "an unapproved repair must not touch a column that holds data");

            let approved = drift::repair_statements(&r, true);
            assert_eq!(approved.len(), 1);
            assert!(approved[0].contains("DROP COLUMN `gone`"));
        }

        #[test]
        fn missing_column_is_additive() {
            let desired = vec![col("_id", "VARCHAR(40)"), col("title", "VARCHAR(100)")];
            let r = report(&id(), &desired, &[], &[]);
            let unapproved = drift::repair_statements(&r, false);
            assert_eq!(unapproved.len(), 1);
            assert!(unapproved[0].contains("ADD COLUMN `title`"));
        }
    }

    mod plan_order {
        use super::*;

        #[test]
        fn keys_before_indexes() {
            let r = report(
                &id(),
                &id(),
                &["DROP INDEX `rel_x` ON `T_app`.`thing`"],
                &["ALTER TABLE `T_app`.`thing` DROP FOREIGN KEY `fk_x`"],
            );
            let plan = drift::repair_statements(&r, true);
            assert!(plan[0].contains("DROP FOREIGN KEY"));
            assert!(plan[1].starts_with("DROP INDEX"));
        }

        #[test]
        fn columns_before_the_things_that_need_them() {
            let r = report(
                &id(),
                &[col("_id", "VARCHAR(40)"), col("owner", "CHAR(26)")],
                &["CREATE INDEX `rel_owner` ON `T_app`.`thing` (`owner`)"],
                &["ALTER TABLE `T_app`.`thing` ADD CONSTRAINT `fk_owner` FOREIGN KEY (`owner`) REFERENCES `o` (`_id`)"],
            );
            let plan = drift::repair_statements(&r, false);
            assert_eq!(plan.len(), 3);
            assert!(plan[0].contains("ADD COLUMN `owner`"), "the column has to exist first");
            assert!(plan[1].starts_with("CREATE INDEX"), "then the index on it");
            assert!(plan[2].contains("ADD CONSTRAINT"), "then the key that needs the index");
        }

        #[test]
        fn outside_in() {
            let r = report(
                &id(),
                &[col("_id", "VARCHAR(40)"), col("owner", "CHAR(26)")],
                &["DROP INDEX `stale` ON `T_app`.`thing`", "CREATE INDEX `rel_owner` ON `T_app`.`thing` (`owner`)"],
                &[
                    "ALTER TABLE `T_app`.`thing` DROP FOREIGN KEY `fk_old`",
                    "ALTER TABLE `T_app`.`thing` ADD CONSTRAINT `fk_owner` FOREIGN KEY (`owner`) REFERENCES `o` (`_id`)",
                ],
            );
            let plan = drift::repair_statements(&r, true);
            assert_eq!(plan.len(), 5);
            assert!(plan[0].contains("DROP FOREIGN KEY"));
            assert!(plan[1].starts_with("DROP INDEX"));
            assert!(plan[2].contains("ADD COLUMN `owner`"));
            assert!(plan[3].starts_with("CREATE INDEX"));
            assert!(plan[4].contains("ADD CONSTRAINT"));
        }
    }
}

mod mysql_field_resolver_test {
    use super::*;

    fn customers() -> JoinedTable {
        let mut types = IndexMap::new();
        types.insert("_id".to_string(), "CHAR(26)".to_string());
        types.insert("region".to_string(), "VARCHAR(20)".to_string());
        types.insert("profile".to_string(), "JSON".to_string());
        JoinedTable::new("customer", Sql::name(&["CL_app", "customers"]), "customer", "_id", JoinType::Left, types, set(&["profile"]), none())
    }

    fn joined() -> FieldResolver {
        let mut joins = IndexMap::new();
        joins.insert("customer".to_string(), customers());
        FieldResolver::joined(PARENT, set(&["address"]), joins, IndexMap::new())
    }

    fn sql(r: &FieldResolver, name: &str) -> String {
        format!("select {}", r.resolve(name).unwrap().inlined())
    }

    #[test]
    fn unqualified_without_joins() {
        let r = FieldResolver::of(set(&["address"]));
        assert!(sql(&r, "amount").contains("`amount`"));
        assert!(sql(&r, "amount").contains("select `amount`"));
    }

    #[test]
    fn qualified_with_joins() {
        assert!(sql(&joined(), "amount").contains("`p`.`amount`"));
        assert!(sql(&joined(), "_id").contains("`p`.`_id`"));
    }

    #[test]
    fn join_beats_json_path() {
        let s = sql(&joined(), "customer.region");
        assert!(s.contains("`customer`.`region`"), "{s}");
        assert!(!s.contains("json_extract"), "{s}");
    }

    #[test]
    fn parent_json_path() {
        let s = sql(&joined(), "address.city");
        assert!(s.contains("json_extract"), "{s}");
        assert!(s.contains("`p`.`address`"), "{s}");
        assert!(s.contains("$.city"), "{s}");
    }

    #[test]
    fn joined_json_path() {
        let s = sql(&joined(), "customer.profile.tier");
        assert!(s.contains("json_extract"), "{s}");
        assert!(s.contains("`customer`.`profile`"), "{s}");
        assert!(s.contains("$.tier"), "{s}");
    }

    #[test]
    fn joined_non_json_dotted() {
        let s = sql(&joined(), "customer.odd.name");
        assert!(s.contains("`customer`.`odd.name`"), "{s}");
    }

    #[test]
    fn unknown_dotted() {
        assert!(sql(&joined(), "some.thing").contains("`p`.`some.thing`"));
    }

    #[test]
    fn trailing_dot() {
        assert!(sql(&joined(), "customer.").contains("`p`.`customer.`"));
    }

    #[test]
    fn bare_relation_is_the_column() {
        let s = sql(&joined(), "customer");
        assert!(s.contains("`p`.`customer`"), "{s}");
    }

    /// `UnsupportedFilterException.malformed`, which is `FilterError::Malformed`.
    #[test]
    fn refuses_junk() {
        assert!(matches!(joined().resolve("address.c'ty"), Err(FilterError::Malformed(_))));
        assert!(matches!(joined().resolve("customer.profile.t'er"), Err(FilterError::Malformed(_))));
    }

    #[test]
    fn has_joins() {
        assert!(!FieldResolver::of(none()).has_joins());
        assert!(joined().has_joins());
    }
}

mod mysql_filter_builder_test {
    use super::*;

    /// `UnsupportedFilterException` is a `FilterError`; `sql` returns it instead of throwing.
    fn sql(c: impl Into<Condition>) -> FilterResult<String> {
        Ok(filter_builder::build(Some(&c.into()), &FieldResolver::of(none()))?.inlined())
    }

    fn text_sql(term: &str, stemming: bool) -> String {
        let resolver = FieldResolver::of(none()).with_text_columns(set(&["title", "body"])).with_stemming(stemming);
        filter_builder::build(Some(&f("title", FilterOperator::TextSearch, term).into()), &resolver).unwrap().inlined()
    }

    fn group(and: bool, cs: Vec<Condition>) -> ComplexCondition {
        if and {
            ComplexCondition::and(cs)
        } else {
            ComplexCondition::or(cs)
        }
    }

    fn eq(field: &str, v: i64) -> Condition {
        f(field, FilterOperator::Equals, v).into()
    }

    mod comparisons {
        use super::*;

        #[test]
        fn equals() {
            assert_eq!(sql(f("region", FilterOperator::Equals, "North")).unwrap(), "`region` = 'North'");
        }

        #[test]
        fn ordering_operators() {
            assert_eq!(sql(f("n", FilterOperator::GreaterThan, 5)).unwrap(), "`n` > 5");
            assert_eq!(sql(f("n", FilterOperator::GreaterThanEqual, 5)).unwrap(), "`n` >= 5");
            assert_eq!(sql(f("n", FilterOperator::LessThan, 5)).unwrap(), "`n` < 5");
            assert_eq!(sql(f("n", FilterOperator::LessThanEqual, 5)).unwrap(), "`n` <= 5");
        }

        #[test]
        fn value_field_compares_columns() {
            assert_eq!(sql(f("a", FilterOperator::Equals, "b").with_value_field()).unwrap(), "`a` = `b`");
        }
    }

    mod predicates {
        use super::*;

        #[test]
        fn is_null() {
            assert_eq!(sql(fc(Some("a"), FilterOperator::IsNull, None)).unwrap(), "`a` is null");
        }

        #[test]
        fn is_true_and_is_false() {
            assert!(sql(fc(Some("a"), FilterOperator::IsTrue, None)).unwrap().contains("`a`"));
            assert!(sql(fc(Some("a"), FilterOperator::IsFalse, None)).unwrap().contains("`a`"));
        }

        #[test]
        fn need_no_value() {
            for op in [FilterOperator::IsNull, FilterOperator::IsTrue, FilterOperator::IsFalse] {
                assert!(!sql(fc(Some("a"), op, None)).unwrap().is_empty(), "{op} should not require a value");
            }
        }
    }

    /// Java's nested class `In`.
    mod in_ {
        use super::*;

        #[test]
        fn explicit_multi_value_wins() {
            let c = fc(Some("s"), FilterOperator::In, None).with_multi_value(vec!["A".into(), "B".into()]);
            assert_eq!(sql(c).unwrap(), "`s` in ('A', 'B')");
        }

        #[test]
        fn comma_separated_value_is_split() {
            assert_eq!(sql(f("s", FilterOperator::In, "A,B,C")).unwrap(), "`s` in ('A', 'B', 'C')");
        }

        #[test]
        fn whitespace_around_items_is_trimmed() {
            assert_eq!(sql(f("s", FilterOperator::In, " A , B ")).unwrap(), "`s` in ('A', 'B')");
        }

        #[test]
        fn empty_in_is_rejected() {
            assert!(sql(f("s", FilterOperator::In, " , ")).is_err());
            assert!(sql(fc(Some("s"), FilterOperator::In, None)).is_err());
        }
    }

    mod strings_and_ranges {
        use super::*;

        #[test]
        fn like_passes_the_pattern_through() {
            assert_eq!(sql(f("a", FilterOperator::Like, "x%")).unwrap(), "`a` like 'x%'");
        }

        #[test]
        fn loose_equal_wraps_in_wildcards() {
            assert_eq!(sql(f("a", FilterOperator::StringLooseEqual, "x")).unwrap(), "`a` like '%x%'");
        }

        #[test]
        fn between() {
            assert_eq!(sql(f("n", FilterOperator::Between, 1).with_to_value(10)).unwrap(), "`n` between 1 and 10");
        }

        #[test]
        fn between_needs_both_ends() {
            assert!(sql(f("n", FilterOperator::Between, 1)).is_err());
        }
    }

    mod negation {
        use super::*;

        #[test]
        fn negates_a_single_condition() {
            assert_eq!(sql(f("a", FilterOperator::Equals, 1).negated()).unwrap(), "not (`a` = 1)");
        }

        #[test]
        fn de_morgan_on_and() {
            let cc = group(true, vec![eq("a", 1), eq("b", 2)]).negated();
            assert_eq!(sql(cc).unwrap(), "(not (`a` = 1) or not (`b` = 2))");
        }

        #[test]
        fn de_morgan_on_or() {
            let cc = group(false, vec![eq("a", 1), eq("b", 2)]).negated();
            assert_eq!(sql(cc).unwrap(), "(not (`a` = 1) and not (`b` = 2))");
        }
    }

    mod grouping {
        use super::*;

        #[test]
        fn and_group() {
            assert_eq!(sql(group(true, vec![eq("a", 1), eq("b", 2)])).unwrap(), "(`a` = 1 and `b` = 2)");
        }

        #[test]
        fn or_group() {
            assert_eq!(sql(group(false, vec![eq("a", 1), eq("b", 2)])).unwrap(), "(`a` = 1 or `b` = 2)");
        }

        #[test]
        fn nested_groups() {
            let inner = group(false, vec![eq("b", 2), eq("c", 3)]);
            let outer = group(true, vec![eq("a", 1), inner.into()]);
            assert_eq!(sql(outer).unwrap(), "(`a` = 1 and (`b` = 2 or `c` = 3))");
        }

        #[test]
        fn empty_group_is_no_condition() {
            assert_eq!(sql(group(true, vec![])).unwrap(), "true");
        }

        #[test]
        fn null_condition_matches_everything() {
            assert_eq!(filter_builder::build(None, &FieldResolver::of(none())).unwrap().inlined(), "true");
        }
    }

    mod unsupported {
        use super::*;

        #[test]
        fn text_search_throws() {
            let e = sql(f("a", FilterOperator::TextSearch, "x")).unwrap_err();
            assert!(e.detail().contains("textIndexFields"), "{}", e.detail());
        }

        #[test]
        fn unsupported_match_operator_throws() {
            let e = sql(f("a", FilterOperator::Match, "x").with_match_operator(FilterOperator::In)).unwrap_err();
            assert!(e.detail().contains("IN"), "{}", e.detail());
        }

        #[test]
        fn match_all_needs_values() {
            assert!(sql(fc(Some("a"), FilterOperator::MatchAll, None)).is_err());
        }

        #[test]
        fn having_condition_throws() {
            let having = Condition::Having(HavingCondition { negate: false, aggregate_function: None, condition: None });
            assert!(sql(having).is_err());
        }

        #[test]
        fn missing_field_throws() {
            assert!(sql(fc(None, FilterOperator::Equals, Some(1.into()))).is_err());
            assert!(sql(fc(Some("  "), FilterOperator::Equals, Some(1.into()))).is_err());
        }

        #[test]
        fn missing_operator_throws() {
            let c = FilterCondition { field: Some("a".into()), operator: None, ..Default::default() };
            assert!(sql(c).is_err());
        }

        #[test]
        fn comparison_without_a_value_throws() {
            assert!(sql(fc(Some("a"), FilterOperator::Equals, None)).is_err());
        }
    }

    mod malformed_vs_unsupported {
        use super::*;

        #[test]
        fn between_without_to_value() {
            let e = sql(f("a", FilterOperator::Between, 1)).unwrap_err();
            assert!(e.is_malformed(), "a missing toValue is malformed, not unsupported");
            assert!(e.detail().contains("toValue"), "{}", e.detail());
            assert!(e.detail().contains("'a'"), "the message should name the field: {}", e.detail());
        }

        #[test]
        fn empty_in_list() {
            assert!(sql(f("a", FilterOperator::In, " , , ")).unwrap_err().is_malformed());
        }

        #[test]
        fn missing_field_or_operator() {
            assert!(sql(fc(None, FilterOperator::Equals, Some(1.into()))).unwrap_err().is_malformed());
        }

        #[test]
        fn genuinely_unsupported() {
            let c = f("a", FilterOperator::Match, "x").with_match_operator(FilterOperator::In);
            assert!(!sql(c).unwrap_err().is_malformed());
        }

        #[test]
        fn text_search_stays_unsupported() {
            assert!(!sql(f("a", FilterOperator::TextSearch, "x")).unwrap_err().is_malformed());
        }
    }

    mod stemming {
        use super::*;

        #[test]
        fn stemmed_and_truncated() {
            let s = text_sql("guides", true);
            assert!(s.contains("IN BOOLEAN MODE"), "{s}");
            assert!(s.contains("guid*"), "{s}");
        }

        #[test]
        fn terms_stay_optional() {
            let s = text_sql("southern regions", true);
            assert!(s.contains("southern*"), "{s}");
            assert!(s.contains("region*"), "{s}");
            assert!(!s.contains('+'), "a leading + would make every term required: {s}");
        }

        #[test]
        fn operators_are_neutralised() {
            let s = text_sql("C++ (best) ~thing", true);
            assert!(!s.contains("++"), "{s}");
            assert!(!s.contains('~'), "{s}");
            assert!(!s.contains("(best)"), "{s}");
        }

        #[test]
        fn y_ending_stays_a_prefix() {
            let s = text_sql("quarterly", true);
            assert!(s.contains("quarterl*"), "{s}");
            assert!(!s.contains("quarterli*"), "{s}");
        }

        #[test]
        fn nothing_usable() {
            let s = text_sql("+++ ---", true);
            assert!(!s.contains("AGAINST"), "{s}");
        }

        #[test]
        fn off_is_unchanged() {
            let s = text_sql("guides", false);
            assert!(s.contains("IN NATURAL LANGUAGE MODE"), "{s}");
            assert!(s.contains("guides"), "{s}");
            assert!(!s.contains("guid*"), "{s}");
        }
    }

    mod read_skips_empty {
        use super::*;

        fn read(c: impl Into<Condition>) -> FilterResult<String> {
            Ok(filter_builder::build_for_read(Some(&c.into()), &FieldResolver::of(none()))?.inlined())
        }

        fn and(cs: Vec<FilterCondition>) -> ComplexCondition {
            ComplexCondition::and(cs.into_iter().map(Condition::from).collect())
        }

        #[test]
        fn dropped_from_group() {
            let c = and(vec![f("a", FilterOperator::Equals, 1), fc(Some("b"), FilterOperator::Equals, None)]);
            assert_eq!(read(c).unwrap(), "`a` = 1");
        }

        #[test]
        fn every_value_operator() {
            for op in [
                FilterOperator::Equals,
                FilterOperator::GreaterThan,
                FilterOperator::GreaterThanEqual,
                FilterOperator::LessThan,
                FilterOperator::LessThanEqual,
                FilterOperator::Like,
                FilterOperator::StringLooseEqual,
                FilterOperator::Between,
                FilterOperator::In,
                FilterOperator::Match,
                FilterOperator::MatchAll,
                FilterOperator::TextSearch,
            ] {
                assert_eq!(read(fc(Some("a"), op, None)).unwrap(), "true", "{op} with no value should drop out");
            }
        }

        #[test]
        fn negated_drops_out() {
            let c = and(vec![f("a", FilterOperator::Equals, 1), fc(Some("b"), FilterOperator::Equals, None).negated()]);
            assert_eq!(read(c).unwrap(), "`a` = 1");
        }

        #[test]
        fn negated_group() {
            let g = and(vec![f("a", FilterOperator::Equals, 1), fc(Some("b"), FilterOperator::Equals, None)]).negated();
            assert_eq!(read(g).unwrap(), "not (`a` = 1)");
        }

        #[test]
        fn emptied_group() {
            let c = and(vec![fc(Some("a"), FilterOperator::Equals, None), fc(Some("b"), FilterOperator::In, None)]);
            assert_eq!(read(c).unwrap(), "true");
        }

        #[test]
        fn valueless_operators_stay() {
            assert_eq!(read(fc(Some("a"), FilterOperator::IsNull, None)).unwrap(), "`a` is null");
            assert!(read(fc(Some("a"), FilterOperator::IsTrue, None)).unwrap().contains("`a`"));
        }

        #[test]
        fn in_with_multi_value() {
            let c = fc(Some("s"), FilterOperator::In, None).with_multi_value(vec!["A".into()]);
            assert_eq!(read(c).unwrap(), "`s` in ('A')");
        }

        #[test]
        fn supplied_but_empty_still_refused() {
            assert!(read(f("s", FilterOperator::In, " , ")).is_err());
            assert!(read(f("n", FilterOperator::Between, 1)).is_err());
            assert!(read(fc(None, FilterOperator::Equals, Some(1.into()))).is_err());
        }

        #[test]
        fn empty_string_applies() {
            assert_eq!(read(f("a", FilterOperator::Equals, "")).unwrap(), "`a` = ''");
        }

        #[test]
        fn delete_still_refuses() {
            let c = and(vec![f("a", FilterOperator::Equals, 1), fc(Some("b"), FilterOperator::Equals, None)]);
            assert!(sql(c).is_err());
        }
    }
}

mod mysql_foreign_keys_test {
    use super::*;

    fn relation(t: RelationType, on_delete: Option<RelationConstraint>) -> StorageRelation {
        StorageRelation {
            storage_name: Some("customers".into()),
            relation_type: Some(t),
            field_name: Some("_id".into()),
            delete_constraint: on_delete,
            ..Default::default()
        }
    }

    fn versioned() -> Storage {
        Storage { is_versioned: Some(true), ..Default::default() }
    }

    mod enforceable {
        use super::*;

        #[test]
        fn to_one_with_constraint() {
            assert!(foreign_keys::enforceable(Some(&relation(RelationType::ToOne, Some(RelationConstraint::Restrict)))));
            assert!(foreign_keys::enforceable(Some(&relation(RelationType::ToOne, Some(RelationConstraint::Cascade)))));
        }

        #[test]
        fn nothing_is_not_a_constraint() {
            assert!(!foreign_keys::enforceable(Some(&relation(RelationType::ToOne, Some(RelationConstraint::Nothing)))));
            assert!(!foreign_keys::enforceable(Some(&relation(RelationType::ToOne, None))));
        }

        #[test]
        fn to_many_cannot() {
            assert!(!foreign_keys::enforceable(Some(&relation(RelationType::ToMany, Some(RelationConstraint::Restrict)))));
        }

        #[test]
        fn only_the_row_id() {
            let r = relation(RelationType::ToOne, Some(RelationConstraint::Restrict)).with_field_name("externalRef");
            assert!(!foreign_keys::enforceable(Some(&r)));
        }

        #[test]
        fn cascade_with_side_effects() {
            let r = relation(RelationType::ToOne, Some(RelationConstraint::Cascade));
            assert!(foreign_keys::enforceable_for(Some(&Storage::default()), Some(&r)));
            assert!(!foreign_keys::enforceable_for(Some(&versioned()), Some(&r)));
        }

        #[test]
        fn restrict_is_always_safe() {
            let r = relation(RelationType::ToOne, Some(RelationConstraint::Restrict));
            assert!(foreign_keys::enforceable_for(Some(&versioned()), Some(&r)));
        }

        #[test]
        fn delete_trigger() {
            let mut triggers = IndexMap::new();
            triggers.insert("AFTER_DELETE".to_string(), vec!["notifyWarehouse".to_string()]);
            let triggered = Storage { triggers: Some(triggers), ..Default::default() };
            let r = relation(RelationType::ToOne, Some(RelationConstraint::Cascade));
            assert!(!foreign_keys::enforceable_for(Some(&triggered), Some(&r)));
        }

        #[test]
        fn blank_field_means_id() {
            let r = StorageRelation { field_name: None, ..relation(RelationType::ToOne, Some(RelationConstraint::Cascade)) };
            assert!(foreign_keys::enforceable(Some(&r)));
        }
    }

    mod statements {
        use super::*;

        fn desired(on_delete: RelationConstraint) -> Vec<foreign_keys::ForeignKey> {
            let mut relations = IndexMap::new();
            relations.insert("customer".to_string(), relation(RelationType::ToOne, Some(on_delete)));
            let mut targets = IndexMap::new();
            targets.insert("customer".to_string(), "app_customers".to_string());
            foreign_keys::desired("app_orders", &relations, &targets)
        }

        #[test]
        fn add_clause() {
            let sql = desired(RelationConstraint::Cascade)[0].add_clause();
            assert!(sql.contains("FOREIGN KEY (`customer`) REFERENCES `app_customers` (`_id`)"), "{sql}");
            assert!(sql.contains("ON DELETE CASCADE"), "{sql}");
        }

        #[test]
        fn on_update_is_inert() {
            assert!(desired(RelationConstraint::Cascade)[0].add_clause().contains("ON UPDATE RESTRICT"));
        }

        #[test]
        fn idempotent() {
            let want = desired(RelationConstraint::Restrict);
            assert!(foreign_keys::sync("db", "app_orders", &want, &want).is_empty());
        }

        #[test]
        fn drops_before_adding() {
            let sql = foreign_keys::sync("db", "app_orders", &desired(RelationConstraint::Restrict), &desired(RelationConstraint::Cascade));
            assert_eq!(sql.len(), 2);
            assert!(sql[0].contains("DROP FOREIGN KEY"), "{}", sql[0]);
            assert!(sql[1].contains("ADD CONSTRAINT"), "{}", sql[1]);
        }

        #[test]
        fn dropped_when_no_longer_wanted() {
            let sql = foreign_keys::sync("db", "app_orders", &desired(RelationConstraint::Restrict), &[]);
            assert_eq!(sql.len(), 1);
            assert!(sql[0].contains("DROP FOREIGN KEY"), "{}", sql[0]);
        }

        #[test]
        fn name_is_bounded() {
            let name = foreign_keys::name(&"a".repeat(120), "customer");
            assert!(name.len() <= 64, "{name}");
            assert!(name.ends_with("_customer"), "{name}");
        }

        #[test]
        fn orphan_count() {
            let sql = foreign_keys::orphan_count("db", "app_orders", &desired(RelationConstraint::Restrict)[0]);
            assert!(sql.contains("NOT EXISTS"), "{sql}");
            assert!(sql.contains("IS NOT NULL"), "{sql}");
        }

        #[test]
        fn unresolved_target() {
            let mut relations = IndexMap::new();
            relations.insert("customer".to_string(), relation(RelationType::ToOne, Some(RelationConstraint::Cascade)));
            assert!(foreign_keys::desired("app_orders", &relations, &IndexMap::new()).is_empty());
        }
    }

    mod audited_children_owe_history {
        use super::*;

        #[test]
        fn audited_child_is_not_enforceable() {
            let child = Storage { is_audited: Some(true), is_versioned: Some(false), ..Default::default() };
            assert!(
                foreign_keys::owes_anything_on_delete(Some(&child)),
                "an audited child writes a version row on delete, which ON DELETE CASCADE cannot do"
            );
            assert!(
                !foreign_keys::enforceable_for(Some(&child), Some(&relation(RelationType::ToOne, Some(RelationConstraint::Cascade)))),
                "a database cascade would silently skip this child's audit rows"
            );
        }

        #[test]
        fn restrict_is_still_enforceable() {
            let child = Storage { is_audited: Some(true), ..Default::default() };
            assert!(foreign_keys::enforceable_for(Some(&child), Some(&relation(RelationType::ToOne, Some(RelationConstraint::Restrict)))));
        }

        #[test]
        fn plain_child_still_cascades_in_the_database() {
            let child = Storage { is_audited: Some(false), is_versioned: Some(false), ..Default::default() };
            assert!(!foreign_keys::owes_anything_on_delete(Some(&child)));
            assert!(foreign_keys::enforceable_for(Some(&child), Some(&relation(RelationType::ToOne, Some(RelationConstraint::Cascade)))));
        }
    }
}

mod mysql_indexes_test {
    use super::*;

    /// `new StorageIndexField().setFieldName(f)`: no direction.
    pub(super) fn index(unique: bool, fields: &[&str]) -> StorageIndex {
        StorageIndex {
            unique,
            fields: fields.iter().map(|f| StorageIndexField { field_name: Some(f.to_string()), direction: None }).collect(),
        }
    }

    pub(super) fn storage(indexes: Option<Vec<(&str, StorageIndex)>>, text_fields: Option<&[&str]>) -> Storage {
        Storage {
            name: "orders".into(),
            app_code: "testapp".into(),
            client_code: "SYSTEM".into(),
            version: 1,
            unique_name: "testapp_orders".into(),
            indexes: indexes.map(|i| i.into_iter().map(|(k, v)| (k.to_string(), v)).collect()),
            text_index_fields: text_fields.map(|t| t.iter().map(|s| s.to_string()).collect()),
            ..Default::default()
        }
    }

    pub(super) fn desired(s: &Storage) -> Vec<indexes::Index> {
        indexes::desired(s, &set(&["ref", "amount", "note", "customer"]))
    }

    mod desired {
        use super::*;

        #[test]
        fn declared() {
            let out = desired(&storage(Some(vec![("byRef", index(false, &["ref"]))]), None));
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].name, "byRef");
            assert_eq!(out[0].columns, vec!["ref"]);
            assert!(!out[0].unique);
        }

        #[test]
        fn compound() {
            let idx = StorageIndex {
                unique: false,
                fields: vec![
                    StorageIndexField { field_name: Some("ref".into()), direction: Some(Direction::Asc) },
                    StorageIndexField { field_name: Some("amount".into()), direction: Some(Direction::Desc) },
                ],
            };
            let out = desired(&storage(Some(vec![("byRefAmount", idx)]), None)).remove(0);
            assert_eq!(out.columns, vec!["ref", "amount"]);
            let ddl = out.ddl("db", "testapp_orders");
            assert!(ddl.contains("`ref` ASC"), "{ddl}");
            assert!(ddl.contains("`amount` DESC"), "{ddl}");
        }

        #[test]
        fn unique() {
            assert!(desired(&storage(Some(vec![("bySku", index(true, &["ref"]))]), None))[0].unique);
        }

        #[test]
        fn full_text() {
            let out = desired(&storage(None, Some(&["ref", "note"])));
            assert_eq!(out.len(), 1);
            assert!(out[0].full_text);
            assert_eq!(out[0].columns, vec!["ref", "note"]);
            assert!(out[0].ddl("db", "testapp_orders").contains("FULLTEXT"));
        }

        #[test]
        fn unknown_field_ignored() {
            assert!(desired(&storage(Some(vec![("byGhost", index(false, &["nosuchfield"]))]), None)).is_empty());
        }

        #[test]
        fn relation_columns() {
            let mut s = storage(None, None);
            let mut relations = IndexMap::new();
            relations.insert("customer".to_string(), StorageRelation::to_one("customers"));
            relations.insert("labels".to_string(), StorageRelation::to_many("tags"));
            s.relations = Some(relations);

            let names: Vec<String> =
                indexes::desired(&s, &set(&["ref", "customer", "labels"])).into_iter().map(|i| i.name).collect();
            assert_eq!(names.len(), 1, "{names:?}");
            assert!(names[0].contains("customer"), "{}", names[0]);
        }
    }

    mod sync {
        use super::*;

        #[test]
        fn idempotent() {
            let want = desired(&storage(Some(vec![("byRef", index(false, &["ref"]))]), None));
            assert!(indexes::sync("db", "testapp_orders", &want, &want, &none()).is_empty());
        }

        #[test]
        fn dropped_when_removed() {
            let had = desired(&storage(Some(vec![("byRef", index(false, &["ref"]))]), None));
            let sql = indexes::sync("db", "testapp_orders", &had, &[], &none());
            assert_eq!(sql.len(), 1);
            assert!(sql[0].starts_with("DROP INDEX"), "{}", sql[0]);
        }

        #[test]
        fn replaced() {
            let had = desired(&storage(Some(vec![("byRef", index(false, &["ref"]))]), None));
            let want = desired(&storage(Some(vec![("byRef", index(true, &["ref"]))]), None));
            let sql = indexes::sync("db", "testapp_orders", &had, &want, &none());
            assert_eq!(sql.len(), 2);
            assert!(sql[0].starts_with("DROP INDEX"), "{}", sql[0]);
            assert!(sql[1].contains("UNIQUE"), "{}", sql[1]);
        }

        #[test]
        fn primary_is_safe() {
            let primary = indexes::Index { name: "PRIMARY".into(), columns: vec!["_id".into()], directions: vec![], unique: true, full_text: false };
            assert!(indexes::sync("db", "testapp_orders", &[primary], &[], &none()).is_empty());
        }

        #[test]
        fn foreign_key_index_is_safe() {
            let backing = indexes::Index {
                name: "fk_testapp_orders_customer".into(),
                columns: vec!["customer".into()],
                directions: vec![],
                unique: false,
                full_text: false,
            };
            assert!(indexes::sync("db", "testapp_orders", &[backing], &[], &set(&["customer"])).is_empty());
        }
    }
}

mod mysql_join_planner_test {
    use super::*;

    pub(super) fn orders() -> Sql {
        Sql::name(&["CL_app", "orders"])
    }

    pub(super) fn parent_columns() -> IndexSet<String> {
        set(&["_id", "amount", "customer"])
    }

    pub(super) fn storage_with(relations: Vec<(&str, StorageRelation)>) -> Storage {
        Storage {
            name: "orders".into(),
            relations: Some(relations.into_iter().map(|(k, v)| (k.to_string(), v)).collect()),
            ..Default::default()
        }
    }

    pub(super) fn to_one(target: &str) -> StorageRelation {
        StorageRelation::to_one(target).with_field_name("_id")
    }

    fn to_many(target: &str) -> StorageRelation {
        StorageRelation::to_many(target).with_field_name("_id")
    }

    pub(super) fn join(relation: &str, alias: Option<&str>) -> StorageJoin {
        StorageJoin { alias: alias.map(str::to_string), ..StorageJoin::new(relation) }
    }

    pub(super) fn joined(alias: &str, t: JoinType, columns: &[&str]) -> JoinedTable {
        let mut types = IndexMap::new();
        types.insert("_id".to_string(), "CHAR(26)".to_string());
        for c in columns {
            types.insert(c.to_string(), "VARCHAR(40)".to_string());
        }
        JoinedTable::new(alias, Sql::name(&["CL_app", "customers"]), "customer", "_id", t, types, none(), none())
    }

    /// The three-argument Java `check`: no parent JSON columns.
    pub(super) fn check(s: &Storage, joins: Option<&Vec<StorageJoin>>) -> Option<String> {
        join_planner::check(s, joins, &parent_columns(), &none())
    }

    mod validation {
        use super::*;

        #[test]
        fn none() {
            assert!(check(&storage_with(vec![]), None).is_none());
            assert!(check(&storage_with(vec![]), Some(&vec![])).is_none());
        }

        #[test]
        fn to_one_is_fine() {
            assert!(check(&storage_with(vec![("customer", to_one("customers"))]), Some(&vec![join("customer", None)])).is_none());
        }

        #[test]
        fn unknown_relation() {
            let err = check(&storage_with(vec![("customer", to_one("customers"))]), Some(&vec![join("supplier", None)])).unwrap();
            assert!(err.contains("no relation 'supplier'"), "{err}");
        }

        #[test]
        fn to_many_is_refused() {
            let err = check(&storage_with(vec![("tags", to_many("tagList"))]), Some(&vec![join("tags", None)])).unwrap();
            assert!(err.contains("cannot use an index"), "{err}");
        }

        #[test]
        fn bad_alias() {
            for alias in ["has space", "has-dash", "1leading", "has$dollar"] {
                let s = storage_with(vec![("customer", to_one("customers"))]);
                assert!(check(&s, Some(&vec![join("customer", Some(alias))])).is_some(), "'{alias}' should be refused");
            }
        }

        #[test]
        fn duplicate_alias() {
            let s = storage_with(vec![("customer", to_one("customers")), ("payer", to_one("customers"))]);
            let err = check(&s, Some(&vec![join("customer", Some("c")), join("payer", Some("c"))])).unwrap();
            assert!(err.contains("duplicate join alias"), "{err}");
        }

        #[test]
        fn alias_collides_with_column() {
            let err = check(&storage_with(vec![("customer", to_one("customers"))]), Some(&vec![join("customer", Some("amount"))])).unwrap();
            assert!(err.contains("is also a column"), "{err}");
        }

        #[test]
        fn alias_may_shadow_its_own_relation() {
            assert!(check(&storage_with(vec![("customer", to_one("customers"))]), Some(&vec![join("customer", None)])).is_none());
        }

        #[test]
        fn alias_cannot_shadow_json() {
            let err = join_planner::check(
                &storage_with(vec![("customer", to_one("customers"))]),
                Some(&vec![join("customer", Some("address"))]),
                &set(&["_id", "amount", "customer", "address"]),
                &set(&["address"]),
            )
            .unwrap();
            assert!(err.contains("JSON column"), "{err}");
        }

        #[test]
        fn same_relation_twice() {
            let s = storage_with(vec![("customer", to_one("customers"))]);
            assert!(check(&s, Some(&vec![join("customer", Some("a")), join("customer", Some("b"))])).is_none());
        }

        #[test]
        fn too_many() {
            let mut relations = Vec::new();
            let mut joins = Vec::new();
            let names: Vec<(String, String)> = (0..=MAX_JOINS).map(|i| (format!("r{i}"), format!("a{i}"))).collect();
            for (r, a) in &names {
                relations.push((r.as_str(), to_one("customers")));
                joins.push(join(r, Some(a)));
            }
            assert!(check(&storage_with(relations), Some(&joins)).is_some());
        }

        #[test]
        fn default_alias() {
            assert_eq!(StorageJoin::new("customer").resolved_alias().as_deref(), Some("customer"));
            assert_eq!(join("customer", Some("c")).resolved_alias().as_deref(), Some("c"));
        }
    }

    mod sql {
        use super::*;

        fn from(joins: &[JoinedTable]) -> String {
            Select::star(join_planner::from(&orders(), joins)).to_sql().inlined()
        }

        #[test]
        fn left_join() {
            let s = from(&[joined("c", JoinType::Left, &["region"])]);
            assert!(s.contains("left outer join"), "{s}");
            assert!(s.contains("`CL_app`.`customers` as `c`"), "{s}");
            assert!(s.contains("`p`.`customer` = `c`.`_id`"), "{s}");
        }

        #[test]
        fn inner_join() {
            let s = from(&[joined("c", JoinType::Inner, &["region"])]);
            assert!(s.contains("join `CL_app`.`customers` as `c`"), "{s}");
            assert!(!s.contains("left outer join"), "{s}");
        }

        #[test]
        fn parent_aliased() {
            assert!(from(&[joined("c", JoinType::Left, &["region"])]).contains("as `p`"));
        }

        #[test]
        fn two_joins() {
            let s = from(&[joined("a", JoinType::Left, &["x"]), joined("b", JoinType::Inner, &["y"])]);
            assert!(s.contains("as `a`"), "{s}");
            assert!(s.contains("as `b`"), "{s}");
        }

        #[test]
        fn columns_are_named() {
            let fields = join_planner::selection(&set(&["_id", "amount"]), &[joined("c", JoinType::Left, &["region"])]);
            let s = Select::fields(fields, orders()).to_sql().inlined();
            assert!(s.contains("`p`.`_id`"), "{s}");
            assert!(s.contains("`c`.`_id` as `c._id`"), "{s}");
            assert!(s.contains("`c`.`region` as `c.region`"), "{s}");
        }
    }

    mod nesting {
        use super::*;

        #[test]
        fn nests() {
            let mut flat = Document::new();
            flat.insert("_id".into(), Value::from("1"));
            flat.insert("amount".into(), Value::Int(10));
            flat.insert("c._id".into(), Value::from("9"));
            flat.insert("c.region".into(), Value::from("north"));
            flat.insert("c".into(), Value::from("9"));

            let out = join_planner::nest(flat, &[joined("c", JoinType::Left, &["region"])], &[]);
            assert_eq!(out.get("_id"), Some(&Value::from("1")));
            let side = out.get("c").and_then(Value::as_object).expect("an object under the alias");
            assert_eq!(side.get("region"), Some(&Value::from("north")));
        }

        #[test]
        fn unmatched_is_dropped() {
            let mut flat = Document::new();
            flat.insert("_id".into(), Value::from("1"));
            flat.insert("c._id".into(), Value::Null);
            flat.insert("c.region".into(), Value::Null);
            flat.insert("c".into(), Value::from("9"));

            let out = join_planner::nest(flat, &[joined("c", JoinType::Left, &["region"])], &[]);
            assert!(!out.contains_key("c"), "{out:?}");
        }

        #[test]
        fn no_joins() {
            let mut flat = Document::new();
            flat.insert("_id".into(), Value::from("1"));
            assert_eq!(join_planner::nest(flat.clone(), &[], &[]), flat);
        }
    }
}

/// Not Java ports: reachable lines of the builders the ports above leave uncovered.
mod extra {
    use super::*;

    mod column {
        use super::*;
        use appdata::mysql::column::{problems, render_type};

        fn def(t: MySqlColumnType) -> MySqlColumnDefinition {
            MySqlColumnDefinition { column_type: Some(t), ..Default::default() }
        }

        /// `MySQLColumn.ddl`: the collation sits between the type and the nullability.
        #[test]
        fn collation_is_written_into_the_ddl() {
            let c = MySqlColumn::new("title", "VARCHAR(30)", false).unwrap().with_collation(Some("utf8mb4_bin".into()));
            assert_eq!(c.ddl(), "`title` VARCHAR(30) COLLATE utf8mb4_bin NOT NULL");
            assert_eq!(c.with_collation(None).ddl(), "`title` VARCHAR(30) NOT NULL");
        }

        #[test]
        fn every_argument_a_type_does_not_take_is_named() {
            let v = MySqlColumnDefinition { length: Some(10), scale: Some(2), ..def(MySqlColumnType::Varchar) };
            assert_eq!(problems("f", Some(&v), true), vec!["f: VARCHAR takes no scale"]);

            let d = MySqlColumnDefinition { length: Some(5), precision: Some(10), scale: Some(2), ..def(MySqlColumnType::Decimal) };
            assert_eq!(problems("f", Some(&d), true), vec!["f: DECIMAL takes no length"]);

            let t = MySqlColumnDefinition { length: Some(5), scale: Some(1), ..def(MySqlColumnType::Datetime) };
            assert_eq!(problems("f", Some(&t), true), vec!["f: DATETIME takes no length", "f: DATETIME takes no scale"]);

            let j = MySqlColumnDefinition { precision: Some(3), scale: Some(1), ..def(MySqlColumnType::Json) };
            assert_eq!(problems("f", Some(&j), true), vec!["f: JSON takes no precision", "f: JSON takes no scale"]);
        }

        #[test]
        fn numbers_out_of_range() {
            let wide = MySqlColumnDefinition { precision: Some(70), scale: Some(31), ..def(MySqlColumnType::Decimal) };
            assert_eq!(
                problems("f", Some(&wide), true),
                vec!["f: precision must be between 1 and 65, not 70", "f: scale must be between 0 and 30, not 31"]
            );

            let fine = MySqlColumnDefinition { precision: Some(7), ..def(MySqlColumnType::Timestamp) };
            assert_eq!(problems("f", Some(&fine), true), vec!["f: TIMESTAMP fractional seconds must be between 0 and 6, not 7"]);
            let negative = MySqlColumnDefinition { precision: Some(-1), ..def(MySqlColumnType::Time) };
            assert_eq!(problems("f", Some(&negative), true), vec!["f: TIME fractional seconds must be between 0 and 6, not -1"]);
            let six = MySqlColumnDefinition { precision: Some(6), ..def(MySqlColumnType::Time) };
            assert!(problems("f", Some(&six), true).is_empty());
            assert_eq!(render_type(&six), "TIME(6)");
        }

        #[test]
        fn unsigned_and_collation_misuse() {
            let v = MySqlColumnDefinition { length: Some(10), unsigned: Some(true), ..def(MySqlColumnType::Varchar) };
            assert_eq!(problems("f", Some(&v), true), vec!["f: unsigned means nothing for VARCHAR"]);

            let c = MySqlColumnDefinition { length: Some(10), collation: Some("utf8-bin".into()), ..def(MySqlColumnType::Char) };
            assert_eq!(problems("f", Some(&c), true), vec!["f: utf8-bin is not a collation name"]);

            let blank = MySqlColumnDefinition { length: Some(10), collation: Some("  ".into()), ..def(MySqlColumnType::Char) };
            assert!(problems("f", Some(&blank), true).is_empty());
            assert!(appdata::mysql::column::collation(&blank).is_none());
        }

        /// The three-argument Java `problems` with `requireType` false.
        #[test]
        fn a_missing_type_is_only_a_problem_when_required() {
            assert!(problems("f", Some(&MySqlColumnDefinition::default()), false).is_empty());
        }
    }

    mod column_names {
        use super::*;
        use appdata::mysql::column_names::{column, column_definitions, physical, to_fields};

        #[test]
        fn a_schema_without_properties_is_handed_back() {
            let s = Schema { types: Some(vec![SchemaType::Object]), ..Default::default() };
            let p = physical(s.clone());
            assert_eq!(p.schema(), Some(&s));
            assert!(p.field_names().is_empty());
        }

        #[test]
        fn a_dotted_name_is_left_as_it_is() {
            assert_eq!(column("Bank Details.city"), "Bank Details.city");
            assert_eq!(column("IFSC Code"), "IFSC_Code");
            assert_eq!(column("amount"), "amount");
        }

        #[test]
        fn nothing_to_rename() {
            let mut row = Document::new();
            row.insert("IFSC_Code".into(), Value::from("x"));
            assert_eq!(to_fields(row.clone(), &IndexMap::new()), row);
            assert_eq!(column_definitions(None), None);
        }
    }

    mod drift {
        use super::*;
        use appdata::mysql::drift::{of, repair_statements, withheld_statements};

        fn col(name: &str, t: &str) -> MySqlColumn {
            MySqlColumn::new(name, t, true).unwrap()
        }

        /// `MySQLDrift.columnDdl`'s MODIFY branch: a widening needs no approval.
        #[test]
        fn a_widened_column_is_modified_without_approval() {
            let r = of("T_app", "thing", true, &[col("title", "VARCHAR(40)")], &[col("title", "VARCHAR(100)")], vec![], vec![]);
            assert!(!r.needs_approval());
            assert_eq!(repair_statements(&r, false), vec!["ALTER TABLE `T_app`.`thing` MODIFY COLUMN `title` VARCHAR(100)"]);
            assert!(withheld_statements(&r, false).is_empty());
        }

        #[test]
        fn a_collation_change_carries_its_clause() {
            let desired = col("title", "VARCHAR(40)").with_collation(Some("utf8mb4_bin".into()));
            let r = of("T_app", "thing", true, &[col("title", "VARCHAR(40)")], &[desired], vec![], vec![]);
            assert_eq!(
                repair_statements(&r, false),
                vec!["ALTER TABLE `T_app`.`thing` MODIFY COLUMN `title` VARCHAR(40) COLLATE utf8mb4_bin"]
            );
        }

        #[test]
        fn a_narrowed_column_waits_for_approval() {
            let r = of("T_app", "thing", true, &[col("title", "VARCHAR(100)")], &[col("title", "VARCHAR(40)")], vec![], vec![]);
            assert!(r.needs_approval());
            assert!(repair_statements(&r, false).is_empty());
            let modify = "ALTER TABLE `T_app`.`thing` MODIFY COLUMN `title` VARCHAR(40)".to_string();
            assert_eq!(withheld_statements(&r, false), vec![modify.clone()]);
            assert_eq!(repair_statements(&r, true), vec![modify]);
            assert!(withheld_statements(&r, true).is_empty());
        }
    }

    mod field_resolver {
        use super::*;

        #[test]
        fn joins_are_kept_by_alias() {
            let mut joins = IndexMap::new();
            joins.insert("c".to_string(), crate::mysql_join_planner_test::joined("c", JoinType::Left, &["region"]));
            let r = FieldResolver::joined(PARENT, none(), joins, IndexMap::new());
            assert_eq!(r.joins().keys().collect::<Vec<_>>(), vec!["c"]);
            assert!(FieldResolver::of(none()).joins().is_empty());
        }
    }

    mod filter_builder {
        use super::*;
        use appdata::mysql::filter_builder::build;

        fn sql(c: impl Into<Condition>, json: &[&str]) -> FilterResult<String> {
            Ok(build(Some(&c.into()), &FieldResolver::of(set(json)))?.inlined())
        }

        /// Java's `String.split("\\.")` drops trailing empty segments, so a trailing dot
        /// on a JSON path is not part of the path.
        #[test]
        fn trailing_dots_in_a_json_path() {
            assert_eq!(
                sql(f("address.city.", FilterOperator::Equals, "x"), &["address"]).unwrap(),
                "json_unquote(json_extract(`address`, '$.city')) = 'x'"
            );
            assert_eq!(
                sql(f("address..", FilterOperator::Equals, "x"), &["address"]).unwrap(),
                "json_unquote(json_extract(`address`, '$')) = 'x'"
            );
            assert!(sql(f("address.a..b", FilterOperator::Equals, "x"), &["address"]).unwrap_err().is_malformed());
        }

        #[test]
        fn match_needs_a_field() {
            let e = sql(fc(None, FilterOperator::Match, Some("x".into())), &[]).unwrap_err();
            assert!(e.is_malformed());
            assert_eq!(e.detail(), "a filter condition has no field");
        }

        #[test]
        fn match_compares_each_element() {
            let ge = f("tags", FilterOperator::Match, 5).with_match_operator(FilterOperator::GreaterThanEqual);
            assert_eq!(
                sql(ge, &[]).unwrap(),
                "((select count(*) from json_table(`tags`, '$[*]' columns (v decimal(38,10) path '$')) as jt where jt.v >= 5) > 0)"
            );
            let lt = f("tags", FilterOperator::Match, "m").with_match_operator(FilterOperator::LessThan);
            assert_eq!(
                sql(lt, &[]).unwrap(),
                "((select count(*) from json_table(`tags`, '$[*]' columns (v char(1024) path '$')) as jt where jt.v < 'm') > 0)"
            );
        }

        /// `jsonLiteral`: the escapes Java writes by hand, checked on the bound candidate.
        #[test]
        fn match_escapes_the_json_candidate() {
            let c = f("tags", FilterOperator::Match, "a\"b\\c\nd\re\tf\u{1}");
            let cond = build(Some(&c.into()), &FieldResolver::of(none())).unwrap();
            let (text, binds) = cond.to_sql().render();
            assert_eq!(text, "(json_contains(`tags`, cast(? as json)))");
            assert_eq!(binds, vec![Bind::Text("\"a\\\"b\\\\c\\nd\\re\\tf\\u0001\"".into())]);
        }

        /// jOOQ renders `field.in("A", null)` as `` `s` in ('A', null) ``.
        #[test]
        fn a_null_in_an_in_list() {
            let c = fc(Some("s"), FilterOperator::In, None).with_multi_value(vec!["A".into(), Value::Null]);
            assert_eq!(sql(c, &[]).unwrap(), "`s` in ('A', null)");
        }

        /// jOOQ flattens `or(or(a, b), c)` into one group.
        #[test]
        fn nested_ors_flatten() {
            let inner = ComplexCondition::or(vec![f("a", FilterOperator::Equals, 1).into(), f("b", FilterOperator::Equals, 2).into()]);
            let outer = ComplexCondition::or(vec![inner.into(), f("c", FilterOperator::Equals, 3).into()]);
            assert_eq!(sql(outer, &[]).unwrap(), "(`a` = 1 or `b` = 2 or `c` = 3)");
        }

        /// A search with nothing usable is `falseCondition()`; negated as a group member it
        /// is `falseCondition().not()`, which jOOQ writes `not false`.
        #[test]
        fn a_negated_group_over_an_unusable_search() {
            let resolver = FieldResolver::of(none()).with_text_columns(set(&["title"]));
            let search = f("title", FilterOperator::TextSearch, "+++ ---");
            assert_eq!(build(Some(&search.clone().into()), &resolver).unwrap().inlined(), "false");
            assert_eq!(build(Some(&search.clone().negated().into()), &resolver).unwrap().inlined(), "true");
            let g = ComplexCondition::and(vec![search.into()]).negated();
            assert_eq!(build(Some(&g.into()), &resolver).unwrap().inlined(), "not false");
        }
    }

    mod foreign_keys {
        use super::*;
        use appdata::mysql::foreign_keys::{desired, enforceable, enforceable_for, name, owes_anything_on_delete};

        fn cascade() -> StorageRelation {
            StorageRelation::to_one("customers").with_delete(RelationConstraint::Cascade)
        }

        #[test]
        fn no_relation_is_not_enforceable() {
            assert!(!enforceable(None));
            assert!(!enforceable_for(Some(&Storage::default()), None));
        }

        /// A null child owes everything, so a cascade stays in the service.
        #[test]
        fn what_a_child_owes_on_delete() {
            assert!(owes_anything_on_delete(None));
            assert!(!enforceable_for(None, Some(&cascade())));
            assert!(owes_anything_on_delete(Some(&Storage { generate_events: Some(true), ..Default::default() })));

            let triggers = |kind: &str, fns: Vec<String>| {
                let mut t = IndexMap::new();
                t.insert(kind.to_string(), fns);
                Storage { triggers: Some(t), ..Default::default() }
            };
            assert!(owes_anything_on_delete(Some(&triggers("BEFORE_DELETE", vec!["audit".into()]))));
            assert!(!owes_anything_on_delete(Some(&triggers("AFTER_DELETE", vec![]))));
            assert!(!owes_anything_on_delete(Some(&triggers("AFTER_CREATE", vec!["notify".into()]))));
        }

        #[test]
        fn a_relation_that_cannot_be_a_key_is_left_out() {
            let mut relations = IndexMap::new();
            relations.insert("customer".to_string(), StorageRelation::to_one("customers"));
            relations.insert("tags".to_string(), StorageRelation::to_many("tags").with_delete(RelationConstraint::Restrict));
            relations.insert("payer".to_string(), cascade());
            let mut targets = IndexMap::new();
            for f in ["customer", "tags", "payer"] {
                targets.insert(f.to_string(), format!("app_{f}"));
            }
            let keys = desired("app_orders", &relations, &targets);
            assert_eq!(keys.len(), 1);
            assert_eq!(keys[0].name, "fk_app_orders_payer");
            assert_eq!(keys[0].on_delete, "CASCADE");
        }

        /// Java leaves no room for the table when the column alone fills the name.
        #[test]
        fn a_column_too_long_for_any_table_part() {
            let column = "c".repeat(61);
            assert_eq!(name("app_orders", &column), format!("fk__{column}"));
        }
    }

    mod indexes {
        use super::*;
        use appdata::mysql::indexes::{desired, relation_index_name, Index};
        use crate::mysql_indexes_test::{index, storage};

        /// `Index.ddl` writes a direction only for the columns that have one.
        #[test]
        fn directions_shorter_than_columns() {
            let i = Index { name: "i".into(), columns: vec!["a".into(), "b".into()], directions: vec![Direction::Desc], unique: false, full_text: false };
            assert_eq!(i.ddl("db", "t"), "CREATE INDEX `i` ON `db`.`t` (`a` DESC, `b`)");
        }

        #[test]
        fn unusable_declarations_are_skipped() {
            let cols = set(&["ref", "amount"]);
            let empty = StorageIndex { unique: false, fields: vec![] };
            assert!(desired(&storage(Some(vec![("byNothing", empty)]), None), &cols).is_empty());
            assert!(desired(&storage(Some(vec![("by-ref", index(false, &["ref"]))]), None), &cols).is_empty());
            let unnamed = StorageIndex { unique: false, fields: vec![StorageIndexField { field_name: None, direction: None }] };
            assert!(desired(&storage(Some(vec![("byNull", unnamed)]), None), &cols).is_empty());
            assert!(desired(&storage(None, Some(&["ghost"])), &cols).is_empty());
        }

        /// A field name that is not an identifier is indexed by its column.
        #[test]
        fn fields_are_read_through_their_columns() {
            let out = desired(&storage(Some(vec![("byIfsc", index(false, &["IFSC Code"]))]), Some(&["IFSC Code"])), &set(&["IFSC_Code"]));
            assert_eq!(out.len(), 2);
            assert_eq!(out[0].columns, vec!["IFSC_Code"]);
            assert_eq!(out[0].directions, vec![Direction::Asc]);
            assert_eq!(out[1].name, "ft_all");
            assert_eq!(out[1].columns, vec!["IFSC_Code"]);
            assert!(out[1].directions.is_empty());
        }

        #[test]
        fn relation_indexes_only_where_needed() {
            let mut s = storage(Some(vec![("byCustomer", index(false, &["customer", "ref"]))]), None);
            let mut relations = IndexMap::new();
            relations.insert("customer".to_string(), StorageRelation::to_one("customers"));
            relations.insert("missing".to_string(), StorageRelation::to_one("customers"));
            relations.insert("bad name".to_string(), StorageRelation::to_one("customers"));
            relations.insert("owner".to_string(), StorageRelation::to_one("users"));
            s.relations = Some(relations);

            let out = desired(&s, &set(&["customer", "ref", "bad name", "owner"]));
            let names: Vec<&str> = out.iter().map(|i| i.name.as_str()).collect();
            assert_eq!(names, vec!["byCustomer", "rel_owner"]);
            assert_eq!(out[1].directions, vec![Direction::Asc]);
        }

        #[test]
        fn a_relation_index_name_fits_64() {
            let field = "x".repeat(63);
            let n = relation_index_name(&field);
            assert_eq!(n.len(), 64);
            assert_eq!(n, format!("rel_{}", &field[..60]));
            assert_eq!(relation_index_name("customer"), "rel_customer");
        }
    }

    mod join_planner {
        use super::*;
        use crate::mysql_join_planner_test::{check, storage_with, to_one};

        #[test]
        fn a_join_must_name_a_relation() {
            let s = storage_with(vec![("customer", to_one("customers"))]);
            let unnamed = StorageJoin { relation: None, alias: Some("c".into()), join_type: Some(JoinType::Left) };
            assert_eq!(check(&s, Some(&vec![unnamed])).as_deref(), Some("a join names no relation"));
            assert_eq!(check(&s, Some(&vec![StorageJoin::new("  ")])).as_deref(), Some("a join names no relation"));
        }
    }

    /// The jOOQ 3.19.21 renderings these pin were produced with `DSL.using(MYSQL)
    /// .renderInlined(...)`.
    mod sql {
        use super::*;

        #[test]
        fn doubles_inline_as_jooq_writes_them() {
            for (d, want) in [
                (1e10, "1E10"),
                (0.0, "0E0"),
                (-0.0, "-0E0"),
                (-2.5, "-2.5E0"),
                (0.001, "1E-3"),
                (123.456, "1.23456E2"),
                (1.0e-7, "1E-7"),
                (1e20, "1E20"),
                (100.0, "1E2"),
            ] {
                assert_eq!(Bind::Double(d).inline(), want, "{d}");
            }
        }

        #[test]
        fn in_a_subselect() {
            let inner = Select::fields(vec![Sql::name(&["b"])], Sql::name(&["t"])).to_sql();
            assert_eq!(Sql::name(&["a"]).in_select(inner).inlined(), "`a` in (select `b` from `t`)");
        }

        #[test]
        fn emptiness() {
            assert!(Sql::default().is_empty());
            assert!(!Sql::raw("x").is_empty());
        }
    }

    /// Expectations from the compiled Java `PorterStemmer`.
    mod porter_stemmer {
        use appdata::mysql::porter_stemmer::{search_prefix, search_prefixes, stem};

        #[test]
        fn blank_input() {
            assert_eq!(search_prefix("   "), "");
            assert!(search_prefixes("   ").is_empty());
        }

        #[test]
        fn short_stems() {
            assert_eq!(stem("aed"), "a");
            assert_eq!(stem("abed"), "ab");
        }

        #[test]
        fn step_two_suffixes() {
            for (word, want) in [
                ("hesitanci", "hesit"),
                ("hesitancy", "hesit"),
                ("relevancy", "relev"),
                ("vileli", "vile"),
                ("callousness", "callous"),
                ("sensibiliti", "sensibl"),
                ("archaeology", "archaeolog"),
            ] {
                assert_eq!(stem(word), want, "{word}");
            }
            assert_eq!(search_prefix("sensibiliti"), "sensib");
            assert_eq!(search_prefixes("archaeology hesitancy"), vec!["archaeolog", "hesit"]);
        }
    }

    /// Messages from `MySQLSubQueryPlanner.check`, and the derived table jOOQ renders.
    mod subquery_planner {
        use super::*;
        use appdata::mysql::subquery_planner::{check, derived, measures};

        fn parent() -> Storage {
            Storage { name: "orders".into(), ..Default::default() }
        }

        fn child(relation: StorageRelation) -> Storage {
            let mut relations = IndexMap::new();
            relations.insert("order".to_string(), relation);
            Storage { name: "items".into(), relations: Some(relations), ..Default::default() }
        }

        fn sq(storage: Option<&str>, relation: Option<&str>) -> StorageSubQuery {
            StorageSubQuery {
                storage: storage.map(str::to_string),
                relation: relation.map(str::to_string),
                alias: None,
                condition: None,
                aggregations: None,
                having: None,
                required: Some(true),
            }
        }

        fn items() -> StorageSubQuery {
            sq(Some("items"), Some("order"))
        }

        fn good_child() -> Option<Storage> {
            Some(child(StorageRelation::to_one("orders")))
        }

        fn run(list: Vec<StorageSubQuery>, children: Vec<Option<Storage>>) -> Option<String> {
            check(&parent(), Some(&list), &children, &set(&["c"]), &set(&["_id", "amount"]))
        }

        fn one(s: StorageSubQuery) -> Option<String> {
            run(vec![s], vec![good_child()])
        }

        #[test]
        fn the_list_itself() {
            assert_eq!(check(&parent(), None, &[], &none(), &none()), None);
            assert_eq!(check(&parent(), Some(&vec![]), &[], &none(), &none()), None);
            assert_eq!(one(items()), None);
            let four = vec![items(), items(), items(), items()];
            assert_eq!(run(four, vec![]).as_deref(), Some("a query may carry at most 3 subqueries"));
        }

        #[test]
        fn what_each_subquery_must_name() {
            assert_eq!(one(sq(Some(" "), Some("order"))).as_deref(), Some("a subquery names no storage"));
            assert_eq!(
                one(sq(Some("items"), None)).as_deref(),
                Some("subquery on 'items' names no relation back to orders")
            );
            assert_eq!(
                run(vec![items()], vec![None]).as_deref(),
                Some("subquery storage 'items' does not resolve for this client")
            );
            assert_eq!(one(sq(Some("items"), Some("owner"))).as_deref(), Some("storage 'items' has no relation 'owner'"));
        }

        #[test]
        fn the_relation_back_to_the_parent() {
            let elsewhere = run(vec![items()], vec![Some(child(StorageRelation::to_one("customers")))]);
            assert_eq!(elsewhere.as_deref(), Some("relation 'order' on 'items' points at 'customers', not at orders"));
            let unnamed = run(vec![items()], vec![Some(child(StorageRelation { storage_name: None, ..StorageRelation::to_one("x") }))]);
            assert_eq!(unnamed.as_deref(), Some("relation 'order' on 'items' points at 'null', not at orders"));
            let many = run(vec![items()], vec![Some(child(StorageRelation::to_many("orders")))]);
            assert_eq!(
                many.as_deref(),
                Some("relation 'order' on 'items' is TO_MANY; the child must hold a single id for its parent, which is what a to-one is")
            );
        }

        #[test]
        fn having_and_aliases() {
            let having = StorageSubQuery {
                having: Some(Condition::Having(HavingCondition { negate: false, aggregate_function: None, condition: None })),
                ..items()
            };
            assert_eq!(one(having).as_deref(), Some("a subquery's having must be a plain condition over its measure aliases"));
            let bad = StorageSubQuery { alias: Some("has space".into()), ..items() };
            assert_eq!(one(bad).as_deref(), Some("subquery alias 'has space' must match [A-Za-z_][A-Za-z0-9_]*"));
            let taken = StorageSubQuery { alias: Some("c".into()), ..items() };
            assert_eq!(one(taken).as_deref(), Some("duplicate alias 'c'"));
            let column = StorageSubQuery { alias: Some("amount".into()), ..items() };
            assert_eq!(one(column).as_deref(), Some("subquery alias 'amount' is also a column of orders"));
        }

        #[test]
        fn measures_are_checked() {
            let with = |aggs: Vec<Aggregation>| one(StorageSubQuery { aggregations: Some(aggs), ..items() });
            let no_function = Aggregation { function: None, field: Some("qty".into()), alias: Some("q".into()) };
            assert_eq!(with(vec![no_function]).as_deref(), Some("a measure of subquery 'items' has no function"));
            assert_eq!(
                with(vec![Aggregation::new(AggregateFunction::Sum, None)]).as_deref(),
                Some("SUM in subquery 'items' needs a field")
            );
            assert_eq!(
                with(vec![Aggregation::new(AggregateFunction::Max, Some("a$b"))]).as_deref(),
                Some("field 'a$b' may not contain '$'")
            );
            assert_eq!(
                with(vec![Aggregation::new(AggregateFunction::Count, None).with_alias("bad alias")]).as_deref(),
                Some("measure alias 'bad alias' must match [A-Za-z_][A-Za-z0-9_]*")
            );
            let twice = vec![
                Aggregation::new(AggregateFunction::Count, None).with_alias("n"),
                Aggregation::new(AggregateFunction::Sum, Some("qty")).with_alias("n"),
            ];
            assert_eq!(with(twice).as_deref(), Some("duplicate measure 'n' in subquery 'items'"));
            assert_eq!(with(vec![Aggregation::new(AggregateFunction::Count, None), Aggregation::new(AggregateFunction::Sum, Some("qty"))]), None);
        }

        #[test]
        fn the_measures_exposed() {
            assert_eq!(measures(&items()), set(&["count"]));
            let aggs = vec![Aggregation::new(AggregateFunction::Sum, Some("qty")), Aggregation::new(AggregateFunction::Count, None).with_alias("n")];
            assert_eq!(measures(&StorageSubQuery { aggregations: Some(aggs), ..items() }), set(&["sum_qty", "n"]));
        }

        fn outer(derived: &Sql, alias: &str, measures: &[&str]) -> String {
            let fields: Vec<Sql> = std::iter::once("__parent").chain(measures.iter().copied()).map(|m| Sql::name(&[alias, m])).collect();
            Select::fields(fields, derived.clone()).to_sql().inlined()
        }

        #[test]
        fn the_derived_table() {
            let table = Sql::name(&["db", "items"]);
            let d = derived(&table, &items(), "order", None, None, none()).unwrap();
            assert_eq!(
                outer(&d, "items", &["count"]),
                "select `items`.`__parent`, `items`.`count` from (select `order` as `__parent`, count(*) as `count` from `db`.`items` where `order` is not null group by `order`) as `items`"
            );

            let lines = StorageSubQuery {
                alias: Some("lines".into()),
                aggregations: Some(vec![Aggregation::new(AggregateFunction::Sum, Some("qty")).with_alias("total")]),
                ..items()
            };
            let where_ = Sql::name(&["status"]).equal(Sql::param(Bind::Text("open".into())));
            let having = Sql::name(&["total"]).cmp(">", Sql::param(Bind::Int(5)));
            let d = derived(&table, &lines, "order", Some(where_), Some(having), none()).unwrap();
            assert_eq!(
                outer(&d, "lines", &["total"]),
                "select `lines`.`__parent`, `lines`.`total` from (select `order` as `__parent`, sum(`qty`) as `total` from `db`.`items` where (`status` = 'open' and `order` is not null) group by `order` having `total` > 5) as `lines`"
            );
        }
    }
}
