//! Between the engines' values (`appdata::Value`, what the Java engines hand back as
//! `Map<String, Object>`) and the two other shapes the policy layer meets:
//!
//! - KIRun's values (`serde_json::Value`, Java's `JsonElement`): rows go in as
//!   `gson.toJsonTree(row)` with core's `Gson` bean, and come out as `StorageJson.toMap`
//!   (`ToNumberPolicy.LONG_OR_DOUBLE`).
//! - Upload files: a JSON object read with a plain `new Gson().fromJson(text, HashMap.class)`.

use appdata::value::{Decimal, Document, Value};
use chrono::{DateTime, Datelike, Timelike};
use serde_json::{Map, Number};

use crate::error::CoreError;

/// `gson.toJsonTree(value)` with core's `Gson` bean: members whose value is null are left
/// out, nulls in lists stay, `LocalDateTime` and `LocalDate` are epoch seconds (the bean's
/// adapters), a `java.util.Date` is Gson's default text, a non-finite double is refused.
pub fn gson_tree(v: &Value) -> Result<serde_json::Value, CoreError> {
    Ok(match v {
        Value::Null => serde_json::Value::Null,
        Value::Bool(b) => serde_json::Value::Bool(*b),
        Value::Int(i) => serde_json::Value::Number((*i).into()),
        Value::Double(d) => serde_json::Value::Number(finite(*d)?),
        Value::Decimal(d) => decimal_number(d),
        Value::String(s) => serde_json::Value::String(s.clone()),
        Value::Array(a) => serde_json::Value::Array(a.iter().map(gson_tree).collect::<Result<_, _>>()?),
        Value::Object(o) => serde_json::Value::Object(gson_object(o)?),
        Value::LocalDateTime(dt) => serde_json::Value::Number(dt.and_utc().timestamp().into()),
        Value::LocalDate(d) => serde_json::Value::Number(
            d.and_hms_opt(0, 0, 0).map(|x| x.and_utc().timestamp()).unwrap_or(0).into(),
        ),
        // Java has no adapter for LocalTime and Gson cannot reach into java.time on 21; the
        // ISO text is what the REST answer carries for the same value.
        Value::LocalTime(t) => serde_json::Value::String(appdata::value::iso_local_time(*t)),
        Value::Date(ms) => serde_json::Value::String(gson_date(*ms, overridable::pojo::java_zone_offset_seconds())),
    })
}

/// [`gson_tree`] of a row.
pub fn gson_object(o: &Document) -> Result<Map<String, serde_json::Value>, CoreError> {
    let mut out = Map::new();
    for (k, v) in o {
        if v.is_null() {
            continue;
        }
        out.insert(k.clone(), gson_tree(v)?);
    }
    Ok(out)
}

fn finite(d: f64) -> Result<Number, CoreError> {
    Number::from_f64(d).ok_or_else(|| {
        CoreError::unknown(format!(
            "{} is not a valid double value as per JSON specification. To override this behavior, use \
             GsonBuilder.serializeSpecialFloatingPointValues() method.",
            appdata::value::java_double(d)
        ))
    })
}

/// A `BigDecimal` as a JSON number: exact when it is a whole number that fits a long,
/// otherwise its double (see DIFFERENCES.md: a scale like `12.50` is not kept).
fn decimal_number(d: &Decimal) -> serde_json::Value {
    if let Some(l) = d.long_value_exact() {
        return serde_json::Value::Number(l.into());
    }
    Number::from_f64(d.double_value()).map(serde_json::Value::Number).unwrap_or(serde_json::Value::Null)
}

/// Gson's default `java.util.Date` text: `DateFormat.getDateTimeInstance(DEFAULT, DEFAULT,
/// Locale.US)` on Java 21 (CLDR), in the JVM's zone: `Oct 15, 2026, 7:59:00 AM` with a narrow
/// no-break space before the marker.
pub fn gson_date(ms: i64, offset_seconds: i32) -> String {
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let Some(utc) = DateTime::from_timestamp_millis(ms) else { return ms.to_string() };
    let local = utc.naive_utc() + chrono::Duration::seconds(offset_seconds as i64);
    let h = local.hour();
    let (h12, marker) = match h {
        0 => (12, "AM"),
        1..=11 => (h, "AM"),
        12 => (12, "PM"),
        _ => (h - 12, "PM"),
    };
    format!(
        "{} {}, {}, {}:{:02}:{:02}\u{202f}{}",
        MONTHS[local.month0() as usize],
        local.day(),
        local.year(),
        h12,
        local.minute(),
        local.second(),
        marker
    )
}

/// `StorageJson.toMap` / `toMapList`: Gson with `ToNumberPolicy.LONG_OR_DOUBLE`. A number
/// literal that parses as a long is a `Long`, anything else a `Double`; nulls are kept.
pub fn storage_value(v: &serde_json::Value) -> Value {
    match v {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => match n.as_i64() {
            Some(i) => Value::Int(i),
            None => Value::Double(n.as_f64().unwrap_or(0.0)),
        },
        serde_json::Value::String(s) => Value::String(s.clone()),
        serde_json::Value::Array(a) => Value::Array(a.iter().map(storage_value).collect()),
        serde_json::Value::Object(o) => Value::Object(storage_document(o)),
    }
}

pub fn storage_document(o: &Map<String, serde_json::Value>) -> Document {
    o.iter().map(|(k, v)| (k.clone(), storage_value(v))).collect()
}

/// `new Gson().fromJson(text, HashMap.class)`: every number a `Double`, the top level a
/// `HashMap` (its iteration order), nested objects in their own order.
pub fn plain_gson_map(text: &str) -> Result<Document, String> {
    let v: serde_json::Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let serde_json::Value::Object(o) = v else { return Err("Expected BEGIN_OBJECT".into()) };
    let doc: Document = o.iter().map(|(k, v)| (k.clone(), all_doubles(v))).collect();
    Ok(hash_map_order(doc))
}

fn all_doubles(v: &serde_json::Value) -> Value {
    match v {
        serde_json::Value::Number(n) => Value::Double(n.as_f64().unwrap_or(0.0)),
        serde_json::Value::Array(a) => Value::Array(a.iter().map(all_doubles).collect()),
        serde_json::Value::Object(o) => Value::Object(o.iter().map(|(k, v)| (k.clone(), all_doubles(v))).collect()),
        other => storage_value(other),
    }
}

/// A `java.util.HashMap` filled by puts in the document's order, iterated as Java does.
pub fn hash_map_order(doc: Document) -> Document {
    let cap = overridable::java_map::capacity_by_puts(doc.len());
    let mut entries: Vec<(usize, String, Value)> =
        doc.into_iter().map(|(k, v)| (overridable::java_map::bucket(&k, cap), k, v)).collect();
    entries.sort_by_key(|e| e.0);
    entries.into_iter().map(|(_, k, v)| (k, v)).collect()
}

/// `CloneUtil.cloneMapObject`: nulls dropped at every depth (from lists too), every map
/// rebuilt as a `HashMap`.
pub fn clone_map_object(doc: &Document) -> Document {
    let kept: Document = doc
        .iter()
        .filter(|(_, v)| !v.is_null())
        .map(|(k, v)| (k.clone(), clone_object(v)))
        .collect();
    hash_map_order(kept)
}

fn clone_object(v: &Value) -> Value {
    match v {
        Value::Object(o) => Value::Object(clone_map_object(o)),
        Value::Array(a) => Value::Array(a.iter().filter(|x| !x.is_null()).map(clone_object).collect()),
        other => other.clone(),
    }
}

/// `Object.toString()` of a value Java would hold (`Long`, `Double`, a `String`, a list).
pub fn java_to_string(v: &Value) -> String {
    v.java_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    fn doc(pairs: &[(&str, Value)]) -> Document {
        pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
    }

    #[test]
    fn gson_tree_drops_null_members_and_writes_dates_as_core_does() {
        let row = doc(&[
            ("a", Value::Null),
            ("b", Value::Array(vec![Value::Null, Value::Int(1)])),
            ("c", Value::LocalDateTime(NaiveDate::from_ymd_opt(2024, 1, 2).unwrap().and_hms_opt(3, 4, 5).unwrap())),
            ("d", Value::LocalDate(NaiveDate::from_ymd_opt(1970, 1, 2).unwrap())),
            ("e", Value::Double(3.0)),
            ("f", Value::Decimal(Decimal::parse("12").unwrap())),
            ("g", Value::Decimal(Decimal::parse("1.5").unwrap())),
            ("h", Value::Object(doc(&[("x", Value::Null), ("y", Value::Bool(true))]))),
            ("i", Value::LocalTime(chrono::NaiveTime::from_hms_opt(10, 0, 0).unwrap())),
        ]);
        let t = gson_tree(&Value::Object(row)).unwrap();
        assert_eq!(
            crate::gson::to_gson(&t),
            r#"{"b":[null,1],"c":1704164645,"d":86400,"e":3.0,"f":12,"g":1.5,"h":{"y":true},"i":"10:00:00"}"#
        );
        assert!(gson_tree(&Value::Double(f64::NAN)).unwrap_err().text().contains("NaN is not a valid double"));
        // In the JVM's zone, which the gated tests set process-wide.
        let expected = gson_date(0, overridable::pojo::java_zone_offset_seconds());
        assert_eq!(gson_tree(&Value::Date(0)).unwrap(), serde_json::json!(expected));
    }

    #[test]
    fn gson_dates_in_the_jvm_zone() {
        // 2026-10-13T02:29:00Z in +05:30.
        assert_eq!(gson_date(1_791_858_540_000, 19_800), "Oct 13, 2026, 7:59:00\u{202f}AM");
        assert_eq!(gson_date(1_791_858_540_000 + 6 * 3_600_000, 19_800), "Oct 13, 2026, 1:59:00\u{202f}PM");
        assert_eq!(gson_date(43_200_000, 0), "Jan 1, 1970, 12:00:00\u{202f}PM");
        assert_eq!(gson_date(i64::MAX, 0), i64::MAX.to_string());
    }

    #[test]
    fn storage_json_keeps_longs_and_doubles_apart() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"a":9007199254740993,"b":3.0,"c":18446744073709551615,"d":null,"e":[1,"x"],"f":true}"#)
                .unwrap();
        let d = storage_value(&v);
        let o = d.as_object().unwrap();
        assert_eq!(o["a"], Value::Int(9_007_199_254_740_993));
        assert_eq!(o["b"], Value::Double(3.0));
        assert!(matches!(o["c"], Value::Double(_)));
        assert_eq!(o["d"], Value::Null);
        assert_eq!(o["e"], Value::Array(vec![Value::Int(1), Value::from("x")]));
        assert_eq!(o["f"], Value::Bool(true));
    }

    #[test]
    fn plain_gson_reads_every_number_as_a_double_into_a_hash_map() {
        let d = plain_gson_map(r#"{"zeta":1,"alpha":{"n":2,"m":[3]},"s":"x"}"#).unwrap();
        assert_eq!(d["zeta"], Value::Double(1.0));
        assert_eq!(d["alpha"].as_object().unwrap()["m"], Value::Array(vec![Value::Double(3.0)]));
        let keys: Vec<&str> = d.keys().map(String::as_str).collect();
        // HashMap order of ["zeta", "alpha", "s"] at capacity 16.
        assert_eq!(keys, ["zeta", "s", "alpha"]);
        assert!(plain_gson_map("[1]").is_err());
        assert!(plain_gson_map("{").is_err());
    }

    #[test]
    fn clone_map_object_drops_nulls_everywhere() {
        let d = doc(&[
            ("a", Value::Null),
            ("b", Value::Array(vec![Value::Null, Value::Int(1)])),
            ("c", Value::Object(doc(&[("x", Value::Null), ("y", Value::Int(2))]))),
        ]);
        let c = clone_map_object(&d);
        assert!(!c.contains_key("a"));
        assert_eq!(c["b"], Value::Array(vec![Value::Int(1)]));
        assert_eq!(c["c"], Value::Object(doc(&[("y", Value::Int(2))])));
        assert_eq!(java_to_string(&Value::Int(5)), "5");
    }

    // Port of commons-core `StorageJsonNumbersTest`.

    const BEYOND_DOUBLE: &str = "9007199254740993";

    fn obj(text: &str) -> Document {
        match storage_value(&serde_json::from_str(text).unwrap()) {
            Value::Object(o) => o,
            _ => panic!("object"),
        }
    }

    #[test]
    fn default_gson_loses_the_integer() {
        // The premise: a double cannot hold it (what Gson's default strategy reads it as).
        let d: f64 = BEYOND_DOUBLE.parse().unwrap();
        assert_eq!(appdata::value::java_double(d), "9.007199254740992E15");
    }

    #[test]
    fn keeps_integer_beyond_double_precision() {
        assert_eq!(obj(&format!("{{\"big\":{BEYOND_DOUBLE}}}"))["big"], Value::Int(9_007_199_254_740_993));
    }

    #[test]
    fn keeps_small_whole_numbers() {
        assert_eq!(obj("{\"n\":42}")["n"], Value::Int(42));
    }

    #[test]
    fn leaves_fractional_numbers_as_double() {
        let row = obj("{\"a\":3.0,\"b\":0.125}");
        assert_eq!(row["a"], Value::Double(3.0));
        assert_eq!(row["b"], Value::Double(0.125));
    }

    #[test]
    fn falls_back_for_oversized_numbers() {
        assert!(matches!(obj("{\"huge\":1e30}")["huge"], Value::Double(_)));
    }

    #[test]
    fn applies_through_nesting() {
        let row = obj(&format!("{{\"outer\":{{\"big\":{BEYOND_DOUBLE}}},\"list\":[{BEYOND_DOUBLE}]}}"));
        assert_eq!(row["outer"].as_object().unwrap()["big"], Value::Int(9_007_199_254_740_993));
        assert_eq!(row["list"].as_array().unwrap()[0], Value::Int(9_007_199_254_740_993));
    }

    #[test]
    fn keeps_precision_in_filter_values() {
        let f = obj(&format!("{{\"field\":\"big\",\"operator\":\"EQUALS\",\"value\":{BEYOND_DOUBLE}}}"));
        assert_eq!(f["value"], Value::Int(9_007_199_254_740_993));
    }

    #[test]
    fn null_is_kept() {
        let row = obj("{\"description\": null, \"ownerId\": null, \"name\": \"x\"}");
        assert_eq!(row.get("description"), Some(&Value::Null));
        assert_eq!(row.get("ownerId"), Some(&Value::Null));
        assert_eq!(row["name"], Value::from("x"));
    }
}