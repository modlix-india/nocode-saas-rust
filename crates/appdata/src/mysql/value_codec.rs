//! `MySQLValueCodec`: between what callers hand the app-data API and what MySQL columns
//! hold. JSON columns take and return text; declared dates are real DATETIME columns read
//! back as ISO text; declared decimals are exact DECIMALs read back as plain text; BOOLEAN
//! fields are TINYINT(1) read back as true / false.

use indexmap::IndexSet;

use crate::java_time;
use crate::value::{iso_local_date, iso_local_date_time, iso_local_time, Decimal, Document, Value};

pub type Columns = IndexSet<String>;

/// The row as the driver should see it. Only the named columns are touched.
pub fn encode(row: &Document, json: &Columns, dates: &Columns, decimals: &Columns) -> Document {
    if row.is_empty() || (json.is_empty() && dates.is_empty() && decimals.is_empty()) {
        return row.clone();
    }
    row.iter()
        .map(|(k, v)| {
            let out = if json.contains(k) {
                to_json(v)
            } else if dates.contains(k) {
                utc_text(v)
            } else if decimals.contains(k) {
                exact(v)
            } else {
                v.clone()
            };
            (k.clone(), out)
        })
        .collect()
}

/// An exact decimal: a number through its own text, a string parsed, anything else (or
/// a string that is not a decimal) passed on for MySQL to refuse more clearly.
pub fn exact(value: &Value) -> Value {
    match value {
        Value::Null | Value::Decimal(_) => value.clone(),
        Value::Int(i) => Value::Decimal(Decimal::from_i64(*i)),
        Value::Double(_) => match Decimal::parse(&value.java_string()) {
            Some(d) => Value::Decimal(d),
            None => value.clone(),
        },
        Value::String(s) => {
            if s.trim().is_empty() {
                return Value::Null;
            }
            match Decimal::parse(s.trim()) {
                Some(d) => Value::Decimal(d),
                None => value.clone(),
            }
        }
        _ => value.clone(),
    }
}

/// ISO text with any offset folded into UTC; a value with no offset is already UTC.
pub fn utc_text(value: &Value) -> Value {
    let Value::String(s) = value else { return value.clone() };
    if !has_offset_suffix(s) {
        return value.clone();
    }
    if s.contains('T') {
        match java_time::parse_offset_date_time_utc(s) {
            Some(dt) => Value::String(iso_local_date_time(dt)),
            None => value.clone(),
        }
    } else {
        match java_time::parse_offset_time_utc(s) {
            Some(t) => Value::String(iso_local_time(t)),
            None => value.clone(),
        }
    }
}

/// `(Z|[+-]\d{2}:\d{2})$`.
fn has_offset_suffix(s: &str) -> bool {
    if s.ends_with('Z') {
        return true;
    }
    let b = s.as_bytes();
    if b.len() < 6 {
        return false;
    }
    let t = &b[b.len() - 6..];
    (t[0] == b'+' || t[0] == b'-')
        && t[1].is_ascii_digit()
        && t[2].is_ascii_digit()
        && t[3] == b':'
        && t[4].is_ascii_digit()
        && t[5].is_ascii_digit()
}

/// The row as the caller expects it.
pub fn decode(row: Document, json: &Columns, dates: &Columns, decimals: &Columns, booleans: &Columns) -> Document {
    if row.is_empty() || (json.is_empty() && dates.is_empty() && decimals.is_empty() && booleans.is_empty()) {
        return row;
    }
    row.into_iter()
        .map(|(k, v)| {
            let out = if json.contains(&k) {
                from_json(v)
            } else if dates.contains(&k) {
                iso_text(v)
            } else if decimals.contains(&k) {
                decimal_text(v)
            } else if booleans.contains(&k) {
                bool_of(v)
            } else {
                v
            };
            (k, out)
        })
        .collect()
}

/// true or false for whatever integer the driver used; anything else passed on.
pub fn bool_of(value: Value) -> Value {
    match value {
        Value::Bool(_) => value,
        Value::Decimal(d) => Value::Bool(d.signum() != 0),
        Value::Int(i) => Value::Bool(i != 0),
        Value::Double(d) => Value::Bool(d as i64 != 0),
        other => other,
    }
}

/// The same for a row already keyed by field, such as a version snapshot.
pub fn booleans(row: Document, fields: &Columns) -> Document {
    if fields.is_empty() {
        return row;
    }
    row.into_iter()
        .map(|(k, v)| if fields.contains(&k) { (k, bool_of(v)) } else { (k, v) })
        .collect()
}

/// Plain decimal text, the column's scale kept.
pub fn decimal_text(value: Value) -> Value {
    match value {
        Value::Decimal(d) => Value::String(d.to_plain_string()),
        other => other,
    }
}

/// ISO-8601 for the temporal types a driver hands back.
pub fn iso_text(value: Value) -> Value {
    match value {
        Value::LocalDateTime(dt) => Value::String(iso_local_date_time(dt)),
        Value::LocalDate(d) => Value::String(iso_local_date(d)),
        Value::LocalTime(t) => Value::String(iso_local_time(t)),
        Value::Date(ms) => match chrono::DateTime::from_timestamp_millis(ms) {
            Some(dt) => Value::String(iso_local_date_time(dt.naive_utc())),
            None => Value::Date(ms),
        },
        other => other,
    }
}

/// The JSON text a JSON column is bound with; SQL NULL for a null.
pub fn to_json(value: &Value) -> Value {
    match value {
        Value::Null => Value::Null,
        Value::String(s) => {
            if is_json_text(s) {
                value.clone()
            } else {
                Value::String(value.to_java_json())
            }
        }
        other => Value::String(other.to_java_json()),
    }
}

/// JSON text back into a structure. Blank is null; text that does not parse is handed
/// back as it is, rather than failing the read for one row.
pub fn from_json(value: Value) -> Value {
    match value {
        Value::String(s) => {
            if s.trim().is_empty() {
                return Value::Null;
            }
            match Value::parse_json(&s) {
                Ok(v) => v,
                Err(_) => Value::String(s),
            }
        }
        other => other,
    }
}

/// Only structures count as already-encoded: a bare `123` or `"x"` is encoded again.
fn is_json_text(s: &str) -> bool {
    let t = s.trim();
    if !(t.starts_with('{') || t.starts_with('[')) {
        return false;
    }
    serde_json::from_str::<serde::de::IgnoredAny>(t).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{NaiveDate, NaiveDateTime, NaiveTime};

    fn set(names: &[&str]) -> Columns {
        names.iter().map(|s| s.to_string()).collect()
    }

    fn row(address: Value) -> Document {
        let mut m = Document::new();
        m.insert("_id".into(), Value::from("01HZZZZZZZZZZZZZZZZZZZZZZZ"));
        m.insert("name".into(), Value::from("Asha"));
        m.insert("address".into(), address);
        m
    }

    fn json() -> Columns {
        set(&["address", "tags"])
    }

    fn none() -> Columns {
        Columns::new()
    }

    fn v(s: &str) -> Value {
        Value::parse_json(s).unwrap()
    }

    #[test]
    fn encoding() {
        let encoded = encode(&row(v(r#"{"city":"Pune"}"#)), &json(), &none(), &none());
        assert!(encoded["address"].as_str().unwrap().contains("\"city\""));
        assert_eq!(encoded["name"], Value::from("Asha"));
        let mut m = Document::new();
        m.insert("tags".into(), v(r#"["a","b"]"#));
        assert_eq!(encode(&m, &json(), &none(), &none())["tags"], Value::from(r#"["a","b"]"#));
        assert_eq!(encode(&row(Value::Null), &json(), &none(), &none())["address"], Value::Null);
        assert_eq!(
            encode(&row(Value::from(r#"{"city":"Pune"}"#)), &json(), &none(), &none())["address"],
            Value::from(r#"{"city":"Pune"}"#)
        );
        assert_eq!(encode(&row(Value::from("Pune")), &json(), &none(), &none())["address"], Value::from("\"Pune\""));
        assert_eq!(
            encode(&row(Value::from("{not json")), &json(), &none(), &none())["address"],
            Value::from("\"{not json\"")
        );
    }

    #[test]
    fn decoding() {
        let d = decode(row(Value::from(r#"{"city":"Pune","pin":"411001"}"#)), &json(), &none(), &none(), &none());
        assert_eq!(d["address"].as_object().unwrap()["city"], Value::from("Pune"));
        let mut m = Document::new();
        m.insert("tags".into(), Value::from(r#"["a","b"]"#));
        assert_eq!(decode(m, &json(), &none(), &none(), &none())["tags"], v(r#"["a","b"]"#));
        let mut m = Document::new();
        m.insert("address".into(), Value::from(r#"{"floor":3}"#));
        assert_eq!(decode(m, &json(), &none(), &none(), &none())["address"].as_object().unwrap()["floor"], Value::Int(3));
        let mut m = Document::new();
        m.insert("address".into(), Value::from("not json at all"));
        assert_eq!(decode(m, &json(), &none(), &none(), &none())["address"], Value::from("not json at all"));
        let mut m = Document::new();
        m.insert("address".into(), Value::from("  "));
        assert_eq!(decode(m, &json(), &none(), &none(), &none())["address"], Value::Null);
        let m = row(Value::from(r#"{"city":"Pune"}"#));
        assert_eq!(decode(m.clone(), &none(), &none(), &none(), &none()), m);
    }

    fn dated(value: Value) -> Document {
        let mut m = Document::new();
        m.insert("placedAt".into(), value);
        m
    }

    #[test]
    fn dates() {
        let dates = set(&["placedAt"]);
        let dt = NaiveDateTime::parse_from_str("2026-01-15 10:00:00", "%Y-%m-%d %H:%M:%S").unwrap();
        assert_eq!(
            decode(dated(Value::LocalDateTime(dt)), &none(), &dates, &none(), &none())["placedAt"],
            Value::from("2026-01-15T10:00:00")
        );
        assert_eq!(
            decode(dated(Value::LocalDate(NaiveDate::from_ymd_opt(2026, 1, 15).unwrap())), &none(), &dates, &none(), &none())
                ["placedAt"],
            Value::from("2026-01-15")
        );
        assert_eq!(
            decode(dated(Value::LocalTime(NaiveTime::from_hms_opt(10, 30, 0).unwrap())), &none(), &dates, &none(), &none())
                ["placedAt"],
            Value::from("10:30:00")
        );
        assert_eq!(decode(dated(Value::Null), &none(), &dates, &none(), &none())["placedAt"], Value::Null);
        let enc = |s: &str, d: &Columns| encode(&dated(Value::from(s)), &none(), d, &none())["placedAt"].clone();
        assert_eq!(enc("2026-01-15T10:00:00+05:30", &dates), Value::from("2026-01-15T04:30:00"));
        assert_eq!(enc("2026-01-15T10:00:00.123Z", &dates), Value::from("2026-01-15T10:00:00.123"));
        assert_eq!(enc("2026-01-15T05:00:00+05:30", &dates), Value::from("2026-01-14T23:30:00"));
        assert_eq!(enc("10:00:00+05:30", &dates), Value::from("04:30:00"));
        assert_eq!(enc("2026-01-15T10:00:00", &dates), Value::from("2026-01-15T10:00:00"));
        assert_eq!(enc("2026-01-15", &dates), Value::from("2026-01-15"));
        assert_eq!(enc("9:00+05:30", &dates), Value::from("9:00+05:30"));
        assert_eq!(enc("2026-01-15T10:00:00+05:30", &none()), Value::from("2026-01-15T10:00:00+05:30"));
        let raw = Value::LocalDateTime(dt);
        assert_eq!(decode(dated(raw.clone()), &none(), &none(), &none(), &none())["placedAt"], raw);
    }

    #[test]
    fn round_trip() {
        let original = v(r#"{"city":"Pune","floor":3,"lines":["a","b"]}"#);
        let written = encode(&row(original.clone()), &json(), &none(), &none());
        let back = decode(written, &json(), &none(), &none(), &none());
        assert_eq!(back["address"], original);
    }

    #[test]
    fn decimals_and_booleans() {
        let decs = set(&["price"]);
        let mut m = Document::new();
        m.insert("price".into(), Value::Decimal(Decimal::parse("10.5000").unwrap()));
        assert_eq!(decode(m, &none(), &none(), &decs, &none())["price"], Value::from("10.5000"));
        let mut m = Document::new();
        m.insert("price".into(), Value::Double(0.1));
        assert_eq!(encode(&m, &none(), &none(), &decs)["price"], Value::Decimal(Decimal::parse("0.1").unwrap()));
        let mut m = Document::new();
        m.insert("price".into(), Value::from(" "));
        assert_eq!(encode(&m, &none(), &none(), &decs)["price"], Value::Null);
        let bools = set(&["active"]);
        let mut m = Document::new();
        m.insert("active".into(), Value::Int(1));
        assert_eq!(decode(m, &none(), &none(), &none(), &bools)["active"], Value::Bool(true));
    }
}
