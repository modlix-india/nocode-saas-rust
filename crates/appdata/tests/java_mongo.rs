//! Java's unit tests of the Mongo engine, ported: `MongoValueCodecTest` (commons-core,
//! service/connection/appdata). No database.
//!
//! `mod extra` is not a Java port: focused tests of the codec's other declared types, the
//! decimal128 edges, the BSON conversions, two filter shapes, the aggregate schema check
//! and the engine selection, each checked against the Java code it mirrors.
//!
//! Run with: cargo test -p appdata --test java_mongo

use appdata::model::{ColumnDefinitions, MongoBsonType, StorageColumnDefinition};
use appdata::mongo::{codec, decimal128};
use appdata::value::Decimal;
use mongodb::bson::{oid::ObjectId, Bson, DateTime, Decimal128, Document as BsonDocument};

/// `defs(field, type)`: one field declared as one BSON type.
fn defs(field: &str, t: MongoBsonType) -> ColumnDefinitions {
    let mut d = ColumnDefinitions::new();
    d.insert(field.into(), StorageColumnDefinition::mongo(t));
    d
}

/// `new Decimal128(new BigDecimal(s))`.
fn dec128(s: &str) -> Decimal128 {
    decimal128::from_decimal(&Decimal::parse(s).unwrap()).unwrap()
}

/// A Decimal128 from its 128 bits.
fn bits(b: u128) -> Decimal128 {
    Decimal128::from_bytes(b.to_le_bytes())
}

fn one(field: &str, value: impl Into<Bson>) -> BsonDocument {
    let mut d = BsonDocument::new();
    d.insert(field, value.into());
    d
}

/// The value `field` holds after encoding `value` as `t`.
fn encoded(value: impl Into<Bson>, t: MongoBsonType) -> Bson {
    let mut d = one("f", value);
    codec::encode(&mut d, Some(&defs("f", t)));
    d.get("f").cloned().unwrap()
}

/// The value `field` holds after decoding `value`.
fn decoded(value: impl Into<Bson>) -> Bson {
    let mut d = one("f", value);
    codec::decode(&mut d);
    d.get("f").cloned().unwrap()
}

mod mongo_value_codec_test {
    use super::*;

    mod encoding {
        use super::*;

        /// Money declared DECIMAL128 stops being a string.
        #[test]
        fn decimal() {
            let mut doc = one("price", "10.50");
            codec::encode(&mut doc, Some(&defs("price", MongoBsonType::Decimal128)));
            assert_eq!(doc.get("price"), Some(&Bson::Decimal128(dec128("10.50"))));
        }

        /// An ISO date becomes a real BSON date.
        #[test]
        fn iso_date() {
            let mut doc = one("at", "2026-01-15T10:00:00Z");
            codec::encode(&mut doc, Some(&defs("at", MongoBsonType::Date)));
            assert!(matches!(doc.get("at"), Some(Bson::DateTime(_))), "{doc:?}");
        }

        /// An epoch number becomes one too, whichever unit it is in.
        #[test]
        fn epoch_date() {
            let mut seconds = one("at", Bson::Int64(1_767_000_000));
            let mut millis = one("at", Bson::Int64(1_767_000_000_000));
            codec::encode(&mut seconds, Some(&defs("at", MongoBsonType::Date)));
            codec::encode(&mut millis, Some(&defs("at", MongoBsonType::Date)));
            let (Some(Bson::DateTime(s)), Some(Bson::DateTime(m))) = (seconds.get("at"), millis.get("at")) else {
                panic!("{seconds:?} {millis:?}")
            };
            assert_eq!(s.timestamp_millis(), m.timestamp_millis());
        }

        /// A list is coerced element by element.
        #[test]
        fn arrays() {
            let mut doc = one("prices", Bson::Array(vec!["1.5".into(), "2.5".into()]));
            codec::encode(&mut doc, Some(&defs("prices", MongoBsonType::Decimal128)));
            assert!(matches!(doc.get_array("prices").unwrap()[0], Bson::Decimal128(_)));
        }

        /// A field with no definition is left exactly as it was.
        #[test]
        fn untouched() {
            let mut doc = one("price", "10.50");
            codec::encode(&mut doc, Some(&ColumnDefinitions::new()));
            codec::encode(&mut doc, Some(&defs("other", MongoBsonType::Decimal128)));
            assert_eq!(doc.get("price"), Some(&Bson::String("10.50".into())));
        }
    }

    mod decoding {
        use super::*;

        /// A Decimal128 comes back as plain text, because the schema says STRING.
        #[test]
        fn decimal() {
            let mut doc = one("price", dec128("10.50"));
            codec::decode(&mut doc);
            assert_eq!(doc.get_str("price").unwrap(), "10.50");
        }

        /// A BSON date comes back as ISO text.
        #[test]
        fn date() {
            let mut doc = one("at", DateTime::from_millis(1_767_000_000_000));
            codec::decode(&mut doc);
            assert_eq!(doc.get_str("at").unwrap(), "2025-12-29T09:20:00");
        }

        /// Decoding needs no definitions, so a row written before one still reads.
        #[test]
        fn value_driven() {
            let mut doc = one("price", dec128("1.25"));
            codec::decode(&mut doc);
            assert_eq!(doc.get_str("price").unwrap(), "1.25");
        }

        /// Everything else passes through.
        #[test]
        fn untouched() {
            let mut doc = BsonDocument::new();
            doc.insert("n", 42);
            doc.insert("s", "hello");
            doc.insert("b", true);
            doc.insert("l", Bson::Array(vec![Bson::Int32(1), Bson::Int32(2)]));
            codec::decode(&mut doc);
            assert_eq!(doc.get("n"), Some(&Bson::Int32(42)));
            assert_eq!(doc.get_str("s").unwrap(), "hello");
            assert_eq!(doc.get("b"), Some(&Bson::Boolean(true)));
            assert_eq!(doc.get("l"), Some(&Bson::Array(vec![Bson::Int32(1), Bson::Int32(2)])));
        }
    }
}

/// Not Java ports: the rest of the Mongo engine's pure parts, checked against the Java code.
mod extra {
    use super::*;

    /// `MongoValueCodec.coerce` for the declared types the Java test does not reach.
    mod codec_encode {
        use super::*;
        use MongoBsonType::*;

        /// LONG / INT / DOUBLE go through `number(value)`: the BSON number itself, else
        /// `new BigDecimal(text.trim())`, else 0.
        #[test]
        fn numbers() {
            assert_eq!(encoded(Bson::Int32(7), Long), Bson::Int64(7));
            assert_eq!(encoded(Bson::Double(3.9), Long), Bson::Int64(3));
            assert_eq!(encoded(" 12.7 ", Long), Bson::Int64(12));
            assert_eq!(encoded(dec128("42.9"), Long), Bson::Int64(42));
            assert_eq!(encoded("abc", Long), Bson::Int64(0));
            // text(BsonBoolean) is its toString, which is not a number.
            assert_eq!(encoded(true, Long), Bson::Int64(0));

            // Long.intValue() and (int) double: wrap and truncate.
            assert_eq!(encoded(Bson::Int64(5_000_000_000), Int), Bson::Int32(705_032_704));
            assert_eq!(encoded(Bson::Double(-2.7), Int), Bson::Int32(-2));
            assert_eq!(encoded(Bson::Int32(9), Int), Bson::Int32(9));
            assert_eq!(encoded("8", Int), Bson::Int32(8));
            assert_eq!(encoded(dec128("12.5"), Int), Bson::Int32(12));

            assert_eq!(encoded("2.5", Double), Bson::Double(2.5));
            assert_eq!(encoded(Bson::Int32(2), Double), Bson::Double(2.0));
            assert_eq!(encoded(Bson::Int64(3), Double), Bson::Double(3.0));
            assert_eq!(encoded(Bson::Double(0.5), Double), Bson::Double(0.5));
            assert_eq!(encoded(dec128("0.125"), Double), Bson::Double(0.125));
            assert_eq!(encoded("x", Double), Bson::Double(0.0));
        }

        /// BOOLEAN is the boolean itself or `Boolean.parseBoolean(text)`; STRING is
        /// `text(value)`, which for a BsonValue with no case of its own is its toString.
        #[test]
        fn booleans_and_text() {
            assert_eq!(encoded(true, Boolean), Bson::Boolean(true));
            assert_eq!(encoded("TRUE", Boolean), Bson::Boolean(true));
            assert_eq!(encoded("yes", Boolean), Bson::Boolean(false));
            assert_eq!(encoded(Bson::Int32(1), Boolean), Bson::Boolean(false));

            assert_eq!(encoded(Bson::Int32(5), String), Bson::String("5".into()));
            assert_eq!(encoded(Bson::Int64(5_000_000_000), String), Bson::String("5000000000".into()));
            assert_eq!(encoded(Bson::Double(2.5), String), Bson::String("2.5".into()));
            assert_eq!(encoded(Bson::Double(1.0e10), String), Bson::String("1.0E10".into()));
            assert_eq!(encoded(dec128("1E+3"), String), Bson::String("1000".into()));
            assert_eq!(encoded("as is", String), Bson::String("as is".into()));
            assert_eq!(encoded(true, String), Bson::String("BsonBoolean{value=true}".into()));
            let oid = ObjectId::parse_str("6ac7d4a11a578c042996bca5").unwrap();
            assert_eq!(encoded(oid, String), Bson::String("BsonObjectId{value=6ac7d4a11a578c042996bca5}".into()));
            assert_eq!(
                encoded(DateTime::from_millis(1_767_000_000_000), String),
                Bson::String("BsonDateTime{value=1767000000000}".into())
            );
        }

        /// A null stays a null whatever the type, inside a list too.
        #[test]
        fn nulls() {
            for t in [Decimal128, Long, Int, Double, Date, Boolean, String] {
                assert_eq!(encoded(Bson::Null, t), Bson::Null, "{t:?}");
            }
            assert_eq!(
                encoded(Bson::Array(vec![Bson::Null, "3".into()]), Long),
                Bson::Array(vec![Bson::Null, Bson::Int64(3)])
            );
        }

        /// DECIMAL128 keeps the text when it cannot be held, untrimmed, as Java's catch does.
        #[test]
        fn decimals() {
            assert_eq!(encoded(Bson::Int32(5), Decimal128), Bson::Decimal128(dec128("5")));
            assert_eq!(encoded(" 1.25 ", Decimal128), Bson::Decimal128(dec128("1.25")));
            assert_eq!(encoded(" 12abc ", Decimal128), Bson::String(" 12abc ".into()));
            // Too far out of range for Decimal128: NumberFormatException, caught.
            assert_eq!(encoded("1E+7000", Decimal128), Bson::String("1E+7000".into()));
        }

        /// DATE: a BSON date as it is; a number as seconds below 1e11 and millis above;
        /// then Instant, LocalDateTime and LocalDate text (UTC); anything else the trimmed text.
        #[test]
        fn dates() {
            let millis = |b: Bson| match b {
                Bson::DateTime(d) => d.timestamp_millis(),
                other => panic!("not a date: {other:?}"),
            };
            assert_eq!(millis(encoded(DateTime::from_millis(123), Date)), 123);
            assert_eq!(millis(encoded(Bson::Int32(-5), Date)), -5000);
            assert_eq!(millis(encoded(Bson::Double(1.767e9), Date)), 1_767_000_000_000);
            assert_eq!(millis(encoded(dec128("1767000000"), Date)), 1_767_000_000_000);
            assert_eq!(millis(encoded("2026-01-15T10:00:00.250Z", Date)), 1_768_471_200_250);
            assert_eq!(millis(encoded("2026-01-15T10:00:00+05:30", Date)), 1_768_451_400_000);
            assert_eq!(millis(encoded("2026-01-15T10:00:00", Date)), 1_768_471_200_000);
            assert_eq!(millis(encoded("2026-01-15T10:00", Date)), 1_768_471_200_000);
            assert_eq!(millis(encoded(" 2026-01-15 ", Date)), 1_768_435_200_000);
            assert_eq!(encoded("  soon ", Date), Bson::String("soon".into()));
            assert_eq!(encoded("2026-02-30", Date), Bson::String("2026-02-30".into()));
        }

        /// A document with no definitions, or a declaration on a field it does not hold, is
        /// left as it is.
        #[test]
        fn absent_definitions() {
            let mut doc = one("price", "10.50");
            codec::encode(&mut doc, None);
            assert_eq!(doc, one("price", "10.50"));
            let mut none = ColumnDefinitions::new();
            none.insert("price".into(), StorageColumnDefinition::default());
            codec::encode(&mut doc, Some(&none));
            assert_eq!(doc, one("price", "10.50"));
        }
    }

    /// `MongoValueCodec.readable` beyond the Java test.
    mod codec_decode {
        use super::*;

        /// ISO_LOCAL_DATE_TIME: seconds always, the fraction only when it is not zero.
        #[test]
        fn dates_keep_their_fraction() {
            assert_eq!(decoded(DateTime::from_millis(1_767_000_000_100)), Bson::String("2025-12-29T09:20:00.1".into()));
            assert_eq!(decoded(DateTime::from_millis(1_767_000_000_123)), Bson::String("2025-12-29T09:20:00.123".into()));
            assert_eq!(decoded(DateTime::from_millis(-1000)), Bson::String("1969-12-31T23:59:59".into()));
        }

        /// toPlainString, never the scientific form.
        #[test]
        fn decimals_are_plain() {
            assert_eq!(decoded(dec128("1E+3")), Bson::String("1000".into()));
            assert_eq!(decoded(dec128("-0.000001")), Bson::String("-0.000001".into()));
        }

        /// A list is decoded element by element, nested lists too; a nested document is not.
        #[test]
        fn lists_and_documents() {
            let list = Bson::Array(vec![dec128("1.5").into(), "x".into(), Bson::Array(vec![dec128("2").into()])]);
            assert_eq!(
                decoded(list),
                Bson::Array(vec!["1.5".into(), "x".into(), Bson::Array(vec!["2".into()])])
            );
            let inner = one("price", dec128("3"));
            assert_eq!(decoded(inner.clone()), Bson::Document(inner));
        }

        /// DIFFERENCES.md "Decimal128 that is not a finite number": Java's
        /// `bigDecimalValue()` throws; this reads the value as its text.
        #[test]
        fn non_finite_decimals_read_as_text() {
            assert_eq!(decoded(bits(0x7c00u128 << 112)), Bson::String("NaN".into()));
            assert_eq!(decoded(bits(0x7800u128 << 112)), Bson::String("Infinity".into()));
            assert_eq!(decoded(bits(0xf800u128 << 112)), Bson::String("-Infinity".into()));
            assert_eq!(decoded(bits((1u128 << 127) | (6176u128 << 113))), Bson::String("-0".into()));
        }
    }

    /// `new Decimal128(BigDecimal)` (its clampAndRound) and `bigDecimalValue()`.
    mod decimal128_edges {
        use super::*;

        fn refused(s: &str) -> String {
            decimal128::from_decimal(&Decimal::parse(s).unwrap()).unwrap_err().0
        }

        fn round_trip(s: &str) -> String {
            match decimal128::to_decimal(&dec128(s)) {
                decimal128::Decoded::Finite(d) => d.to_java_string(),
                other => panic!("{other:?}"),
            }
        }

        /// An exponent above 6111 is brought down by adding zeros when the digits allow it.
        #[test]
        fn exponent_above_the_range() {
            assert_eq!(round_trip("0E+7000"), "0E+6111");
            assert_eq!(round_trip("1E+6112"), "1.0E+6112");
            assert_eq!(refused("1E+6200"), "Exponent is out of range for Decimal128 encoding of 1E+6200");
            // 35 digits at the top exponent: rounding the zero away pushes it past 6111.
            assert_eq!(
                refused("10000000000000000000000000000000000E+6111"),
                "Exponent is out of range for Decimal128 encoding: 6112"
            );
        }

        /// An exponent below -6176 is brought up by dropping trailing zeros, and only those.
        #[test]
        fn exponent_below_the_range() {
            assert_eq!(round_trip("1.000E-6174"), "1.00E-6174");
            assert_eq!(round_trip("0E-7000"), "0E-6176");
            assert_eq!(refused("1.001E-6174"), "Conversion to Decimal128 would require inexact rounding of 1.001E-6174");
            assert_eq!(refused("1E-6200"), "Conversion to Decimal128 would require inexact rounding of 1E-6200");
        }

        /// The special values, which `bigDecimalValue()` refuses.
        #[test]
        fn special_values() {
            use decimal128::Decoded;
            assert_eq!(decimal128::to_decimal(&bits(0x7c00u128 << 112)), Decoded::NaN);
            assert_eq!(decimal128::to_decimal(&bits(0x7800u128 << 112)), Decoded::Infinite(false));
            assert_eq!(decimal128::to_decimal(&bits(0xf800u128 << 112)), Decoded::Infinite(true));
            assert_eq!(decimal128::to_decimal(&bits((1u128 << 127) | (6176u128 << 113))), Decoded::NegativeZero);
            assert_eq!(decimal128::to_java_string(&bits(0x7c00u128 << 112)), "NaN");
            assert_eq!(decimal128::to_java_string(&bits(0x7800u128 << 112)), "Infinity");
            assert_eq!(decimal128::to_java_string(&bits(0xf800u128 << 112)), "-Infinity");
            assert_eq!(decimal128::to_java_string(&bits((1u128 << 127) | (6176u128 << 113))), "-0");
            assert_eq!(decimal128::to_java_string(&dec128("1E+3")), "1E+3");
        }

        /// The two highest combination bits set (and not NaN / Infinity): a coefficient
        /// too large for 113 bits, which Java reads as zero with the exponent from bit 111.
        #[test]
        fn non_canonical_is_zero() {
            let exponent = 6176u128 - 2;
            let b = (0b11u128 << 125) | (exponent << 111) | 12345;
            assert_eq!(decimal128::to_decimal(&bits(b)), decimal128::Decoded::Finite(Decimal::parse("0.00").unwrap()));
            assert_eq!(decimal128::to_decimal(&bits(b | (1u128 << 127))), decimal128::Decoded::NegativeZero);
        }
    }

    /// `BJsonUtil.from` / `fromElement` / `number`, and the reads.
    mod bson_conversions {
        use super::*;
        use appdata::mongo::bson_util;
        use appdata::value::{Document, Value};

        fn row(key: &str, value: &str) -> Document {
            let mut d = Document::new();
            d.insert(key.into(), Value::parse_json(value).unwrap());
            d
        }

        /// A relation value Gson cannot read as a string, or as an ObjectId, fails the write.
        #[test]
        fn relation_values_that_are_not_ids() {
            let keys = vec!["owner".to_string()];
            for bad in ["null", r#"{"a":1}"#, "[[1]]", "5", r#"["6ac7d4a11a578c042996bca5", null]"#] {
                let e = bson_util::from_validated(&keys, &row("owner", bad)).unwrap_err();
                assert_eq!(e.status(), http::StatusCode::INTERNAL_SERVER_ERROR, "{bad}");
            }
            let e = bson_util::from_validated(&keys, &row("owner", "5")).unwrap_err();
            assert!(e.to_string().contains("invalid hexadecimal representation of an ObjectId: [5]"), "{e}");
        }

        /// Everything else follows `fromElement`: booleans, nested objects with their
        /// numbers narrowed, and arrays, none of them treated as ids below the top level.
        #[test]
        fn elements() {
            let b = bson_util::from_validated(&["owner".into()], &row("x", r#"{"on":true,"n":3.0,"owner":"x","l":[1.5,null]}"#)).unwrap();
            let x = b.get_document("x").unwrap();
            assert_eq!(x.get("on"), Some(&Bson::Boolean(true)));
            assert_eq!(x.get("n"), Some(&Bson::Int32(3)));
            assert_eq!(x.get("owner"), Some(&Bson::String("x".into())));
            assert_eq!(x.get("l"), Some(&Bson::Array(vec![Bson::Double(1.5), Bson::Null])));
        }

        /// `number`: decided from the literal, a double when it is not a whole long.
        #[test]
        fn numbers_from_decimals() {
            let d = |s: &str| Value::Decimal(Decimal::parse(s).unwrap());
            assert_eq!(bson_util::number(&d("5.00")), Bson::Int32(5));
            assert_eq!(bson_util::number(&d("0.125")), Bson::Double(0.125));
            assert_eq!(bson_util::number(&d("1E+30")), Bson::Double(1e30));
            assert_eq!(bson_util::number(&Value::from("5")), Bson::Null);
        }

        /// Filter values as the driver's codecs encode the Jackson objects.
        #[test]
        fn filter_values() {
            assert_eq!(bson_util::filter_value(&Value::Null), Bson::Null);
            assert_eq!(bson_util::filter_value(&Value::Int(5_000_000_000)), Bson::Int64(5_000_000_000));
            assert_eq!(bson_util::filter_value(&Value::Decimal(Decimal::parse("10.50").unwrap())), Bson::Decimal128(dec128("10.50")));
            assert_eq!(bson_util::filter_value(&Value::Date(1000)), Bson::DateTime(DateTime::from_millis(1000)));
            assert_eq!(
                bson_util::filter_value(&Value::parse_json(r#"{"a":[true,"s"]}"#).unwrap()),
                Bson::Document(one("a", Bson::Array(vec![Bson::Boolean(true), "s".into()])))
            );
        }

        /// What Jackson writes for the decoded Java objects.
        #[test]
        fn reads() {
            assert_eq!(bson_util::to_value(&Bson::Boolean(false)), Value::Bool(false));
            assert_eq!(bson_util::to_value(&Bson::Double(2.5)), Value::Double(2.5));
            assert_eq!(bson_util::to_value(&Bson::Undefined), Value::Null);
            assert_eq!(bson_util::to_value(&Bson::Int64(7)), Value::Int(7));
            // DIFFERENCES.md "Decimal128 that is not a finite number".
            assert_eq!(bson_util::to_value(&Bson::Decimal128(bits(0x7c00u128 << 112))), Value::from("NaN"));
        }
    }

    /// `filterConditionFilter` shapes the Rust unit tests do not reach.
    mod filter_shapes {
        use super::*;
        use appdata::model::{Condition, FilterCondition, FilterOperator, Storage};
        use appdata::mongo::filter::filter;

        fn json(c: FilterCondition) -> String {
            Bson::Document(filter(&Storage::default(), Some(&Condition::Filter(c))).unwrap()).into_relaxed_extjson().to_string()
        }

        /// MATCH maps its matchOperator through FILTER_MATCH_OPERATOR, `$eq` for one it
        /// does not list.
        #[test]
        fn match_operators() {
            let m = |op| FilterCondition::new("tags", FilterOperator::Match, Some(5.into())).with_match_operator(op);
            assert_eq!(json(m(FilterOperator::GreaterThanEqual)), r#"{"tags":{"$elemMatch":{"$gte":5}}}"#);
            assert_eq!(json(m(FilterOperator::LessThan)), r#"{"tags":{"$elemMatch":{"$lt":5}}}"#);
            assert_eq!(json(m(FilterOperator::In)), r#"{"tags":{"$elemMatch":{"$eq":5}}}"#);
        }

        /// An explicit null matchOperator: `Map.of(...).get(null)` throws, a 500.
        #[test]
        fn null_match_operator() {
            let c = FilterCondition { match_operator: None, ..FilterCondition::new("tags", FilterOperator::Match, Some(5.into())) };
            let e = filter(&Storage::default(), Some(&Condition::Filter(c))).unwrap_err();
            assert_eq!(e.status(), http::StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    /// `validateFieldsAgainstSchema`.
    mod aggregate_schema {
        use appdata::model::{AggregateQuery, Schema};
        use appdata::mongo::aggregate::schema_problem;
        use appdata::value::Value;

        fn schema() -> Schema {
            Schema::from_value(
                &Value::parse_json(
                    r#"{"type":"OBJECT","properties":{"name":{"type":"STRING"},"at":{"type":"LONG"},
                        "address":{"type":"OBJECT"},"_id":{"type":"STRING"}}}"#,
                )
                .unwrap(),
            )
            .unwrap()
        }

        fn problem(q: &str) -> Option<String> {
            schema_problem("orders", Some(&schema()), &AggregateQuery::from_value(&Value::parse_json(q).unwrap()).unwrap())
        }

        #[test]
        fn declared_fields_only() {
            assert_eq!(problem(r#"{"groupBy":[{"field":"nope"}],"aggregations":[{"function":"COUNT"}]}"#).as_deref(), Some("storage orders declares no field 'nope'"));
            assert_eq!(
                problem(r#"{"groupBy":[{"field":"name","bucket":"DAY","encoding":"EPOCH_SECONDS"}],"aggregations":[{"function":"COUNT"}]}"#).as_deref(),
                Some("field 'name' is bucketed as a date but is not a number in the storage schema; only epoch-number dates can be bucketed")
            );
            assert_eq!(
                problem(r#"{"groupBy":[{"field":"name"}],"aggregations":[{"function":"SUM","field":"amount"}]}"#).as_deref(),
                Some("storage orders declares no field 'amount'")
            );
            // A nested path is declared by its first segment, _id only by an _id property.
            assert_eq!(problem(r#"{"groupBy":[{"field":"address.city"},{"field":"_id"}],"aggregations":[{"function":"COUNT","field":" "}]}"#), None);
            assert_eq!(problem(r#"{"groupBy":[{"field":"at","bucket":"DAY","encoding":"EPOCH_SECONDS"}],"aggregations":[{"function":"MAX","field":"at"}]}"#), None);
            // A schema with no properties checks nothing.
            let q = AggregateQuery::from_value(&Value::parse_json(r#"{"groupBy":[{"field":"nope"}],"aggregations":[{"function":"COUNT"}]}"#).unwrap()).unwrap();
            assert_eq!(schema_problem("orders", Some(&Schema::default()), &q), None);
        }
    }

    /// `AppDataService`'s choice of engine by the appData connection.
    mod engine_selection {
        use std::sync::Arc;

        use appdata::engine::Hooks;
        use appdata::model::{Connection, ConnectionSubType};
        use appdata::mongo::{MongoAppDataService, MongoEngineConfig};
        use appdata::mysql::{MySqlAppDataService, MySqlEngineConfig};
        use appdata::selection::Engines;
        use platform::cache::CacheService;

        #[tokio::test]
        async fn for_connection() {
            let cache = CacheService::new("cmn", "evictionChannel", None).unwrap();
            let engines = Engines {
                mongo: Arc::new(MongoAppDataService::new(MongoEngineConfig::default(), Hooks::default(), &cache)),
                mysql: Arc::new(MySqlAppDataService::new(MySqlEngineConfig::default(), Hooks::default(), &cache)),
            };
            let conn = |sub| Connection { id: "c".into(), connection_sub_type: sub, ..Default::default() };
            assert_eq!(engines.for_connection(None).unwrap().backend(), "Mongo");
            assert_eq!(engines.for_connection(Some(&conn(Some(ConnectionSubType::Mongo)))).unwrap().backend(), "Mongo");
            assert_eq!(engines.for_connection(Some(&conn(Some(ConnectionSubType::MySql)))).unwrap().backend(), "MySQL");
            let e = engines.for_connection(Some(&conn(Some(ConnectionSubType::Other("SMTP".into()))))).err().unwrap();
            assert_eq!(e.status(), http::StatusCode::INTERNAL_SERVER_ERROR);
        }
    }
}
