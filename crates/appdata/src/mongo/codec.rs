//! `MongoValueCodec`: a field stored as the BSON type the author declared, and handed back
//! as the schema still describes it. Encoding is driven by the declaration, decoding by the
//! value, so a row written before or after a definition still reads.

use chrono::TimeZone;
use mongodb::bson::{Bson, DateTime, Document as BsonDocument};

use super::decimal128;
use crate::java_time;
use crate::model::{ColumnDefinitions, MongoBsonType};
use crate::value::{iso_local_date_time, java_double, Decimal};

/// Coerce the declared fields of a document about to be written.
pub fn encode(document: &mut BsonDocument, definitions: Option<&ColumnDefinitions>) {
    let Some(defs) = definitions.filter(|d| !d.is_empty()) else { return };
    for (field, def) in defs {
        let Some(t) = def.mongo.as_ref().and_then(|m| m.bson_type) else { continue };
        if let Some(v) = document.get(field).cloned() {
            document.insert(field.clone(), coerce(&v, t));
        }
    }
}

/// Turn a Decimal128 back into plain text and a BSON date into ISO local text, at the top
/// level and inside top-level lists.
pub fn decode(document: &mut BsonDocument) {
    let keys: Vec<String> = document.keys().cloned().collect();
    for k in keys {
        if let Some(v) = document.get(&k) {
            if let Some(decoded) = readable(v) {
                document.insert(k, decoded);
            }
        }
    }
}

/// The readable form, or None when the value is left as it is.
fn readable(value: &Bson) -> Option<Bson> {
    match value {
        Bson::Decimal128(d) => Some(Bson::String(match decimal128::to_decimal(d) {
            decimal128::Decoded::Finite(x) => x.to_plain_string(),
            _ => decimal128::to_java_string(d),
        })),
        Bson::DateTime(dt) => {
            let utc = chrono::Utc.timestamp_millis_opt(dt.timestamp_millis()).single()?;
            Some(Bson::String(iso_local_date_time(utc.naive_utc())))
        }
        Bson::Array(list) => {
            let mut changed = false;
            let out: Vec<Bson> = list
                .iter()
                .map(|o| match readable(o) {
                    Some(r) => {
                        changed = true;
                        r
                    }
                    None => o.clone(),
                })
                .collect();
            if changed {
                Some(Bson::Array(out))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn coerce(value: &Bson, t: MongoBsonType) -> Bson {
    match value {
        Bson::Null => return Bson::Null,
        Bson::Array(a) => return Bson::Array(a.iter().map(|v| coerce(v, t)).collect()),
        _ => {}
    }
    match t {
        MongoBsonType::Decimal128 => decimal(value),
        MongoBsonType::Long => Bson::Int64(long_value(value)),
        MongoBsonType::Int => Bson::Int32(long_or_int(value)),
        MongoBsonType::Double => Bson::Double(double_value(value)),
        MongoBsonType::Date => date(value),
        MongoBsonType::Boolean => Bson::Boolean(match value {
            Bson::Boolean(b) => *b,
            other => text(other).eq_ignore_ascii_case("true"),
        }),
        MongoBsonType::String => Bson::String(text(value)),
    }
}

fn decimal(value: &Bson) -> Bson {
    let s = text(value);
    match Decimal::parse(s.trim()).map(|d| decimal128::from_decimal(&d)) {
        Some(Ok(d)) => Bson::Decimal128(d),
        _ => Bson::String(s),
    }
}

fn date(value: &Bson) -> Bson {
    if let Bson::DateTime(_) = value {
        return value.clone();
    }
    if is_numeric(value) {
        let n = long_value(value);
        let millis = if n.unsigned_abs() < 100_000_000_000 { n.wrapping_mul(1000) } else { n };
        return Bson::DateTime(DateTime::from_millis(millis));
    }
    let s = text(value);
    let s = s.trim();
    if let Some(ms) = java_time::parse_instant_millis(s) {
        return Bson::DateTime(DateTime::from_millis(ms));
    }
    if let Some(dt) = java_time::parse_local_date_time(s) {
        return Bson::DateTime(DateTime::from_millis(dt.and_utc().timestamp_millis()));
    }
    if let Some(d) = java_time::parse_local_date(s) {
        let ms = d.and_hms_opt(0, 0, 0).map(|x| x.and_utc().timestamp_millis()).unwrap_or(0);
        return Bson::DateTime(DateTime::from_millis(ms));
    }
    Bson::String(s.to_string())
}

fn is_numeric(v: &Bson) -> bool {
    matches!(v, Bson::Int32(_) | Bson::Int64(_) | Bson::Double(_) | Bson::Decimal128(_))
}

/// `number(value)` as a decimal, or zero when the text is not one.
fn as_decimal(value: &Bson) -> Option<Decimal> {
    match value {
        Bson::Decimal128(d) => match decimal128::to_decimal(d) {
            decimal128::Decoded::Finite(x) => Some(x),
            _ => None,
        },
        Bson::Int32(_) | Bson::Int64(_) | Bson::Double(_) => None,
        other => Decimal::parse(text(other).trim()),
    }
}

/// `number(value).longValue()`.
fn long_value(value: &Bson) -> i64 {
    match value {
        Bson::Int32(i) => *i as i64,
        Bson::Int64(l) => *l,
        Bson::Double(d) => *d as i64,
        other => as_decimal(other).map(|d| d.long_value()).unwrap_or(0),
    }
}

/// `number(value).intValue()`.
fn long_or_int(value: &Bson) -> i32 {
    match value {
        Bson::Int32(i) => *i,
        Bson::Int64(l) => *l as i32,
        Bson::Double(d) => *d as i32,
        other => as_decimal(other).map(|d| d.int_value()).unwrap_or(0),
    }
}

fn double_value(value: &Bson) -> f64 {
    match value {
        Bson::Int32(i) => *i as f64,
        Bson::Int64(l) => *l as f64,
        Bson::Double(d) => *d,
        other => as_decimal(other).map(|d| d.double_value()).unwrap_or(0.0),
    }
}

/// `text(value)`: the value's text, falling back to the Java `toString` of the BsonValue.
fn text(value: &Bson) -> String {
    match value {
        Bson::String(s) => s.clone(),
        Bson::Int32(i) => i.to_string(),
        Bson::Int64(l) => l.to_string(),
        Bson::Double(d) => java_double(*d),
        Bson::Decimal128(d) => match decimal128::to_decimal(d) {
            decimal128::Decoded::Finite(x) => x.to_plain_string(),
            _ => decimal128::to_java_string(d),
        },
        Bson::Boolean(b) => format!("BsonBoolean{{value={b}}}"),
        Bson::ObjectId(o) => format!("BsonObjectId{{value={}}}", o.to_hex()),
        Bson::DateTime(dt) => format!("BsonDateTime{{value={}}}", dt.timestamp_millis()),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::StorageColumnDefinition;

    fn defs(field: &str, t: MongoBsonType) -> ColumnDefinitions {
        let mut d = ColumnDefinitions::new();
        d.insert(field.into(), StorageColumnDefinition::mongo(t));
        d
    }

    #[test]
    fn writing() {
        let mut doc = BsonDocument::new();
        doc.insert("price", "10.50");
        encode(&mut doc, Some(&defs("price", MongoBsonType::Decimal128)));
        let Some(Bson::Decimal128(d)) = doc.get("price") else { panic!("{doc:?}") };
        assert_eq!(decimal128::to_java_string(d), "10.50");

        let mut doc = BsonDocument::new();
        doc.insert("at", "2026-01-15T10:00:00Z");
        encode(&mut doc, Some(&defs("at", MongoBsonType::Date)));
        assert!(matches!(doc.get("at"), Some(Bson::DateTime(_))));

        let mut s = BsonDocument::new();
        s.insert("at", Bson::Int64(1_767_000_000));
        let mut m = BsonDocument::new();
        m.insert("at", Bson::Int64(1_767_000_000_000));
        encode(&mut s, Some(&defs("at", MongoBsonType::Date)));
        encode(&mut m, Some(&defs("at", MongoBsonType::Date)));
        assert_eq!(s.get("at"), m.get("at"));

        let mut doc = BsonDocument::new();
        doc.insert("prices", Bson::Array(vec!["1.5".into(), "2.5".into()]));
        encode(&mut doc, Some(&defs("prices", MongoBsonType::Decimal128)));
        assert!(matches!(doc.get_array("prices").unwrap()[0], Bson::Decimal128(_)));

        let mut doc = BsonDocument::new();
        doc.insert("price", "10.50");
        encode(&mut doc, Some(&ColumnDefinitions::new()));
        encode(&mut doc, Some(&defs("other", MongoBsonType::Decimal128)));
        assert_eq!(doc.get("price"), Some(&Bson::String("10.50".into())));
    }

    #[test]
    fn reading() {
        let mut doc = BsonDocument::new();
        doc.insert("price", Bson::Decimal128(decimal128::from_decimal(&Decimal::parse("10.50").unwrap()).unwrap()));
        decode(&mut doc);
        assert_eq!(doc.get_str("price").unwrap(), "10.50");

        let mut doc = BsonDocument::new();
        doc.insert("at", Bson::DateTime(DateTime::from_millis(1_767_000_000_000)));
        decode(&mut doc);
        assert_eq!(doc.get_str("at").unwrap(), "2025-12-29T09:20:00");

        let mut doc = BsonDocument::new();
        doc.insert("n", 42);
        doc.insert("s", "hello");
        doc.insert("b", true);
        doc.insert("l", Bson::Array(vec![Bson::Int32(1), Bson::Int32(2)]));
        let before = doc.clone();
        decode(&mut doc);
        assert_eq!(doc, before);
    }
}
