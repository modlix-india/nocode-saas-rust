//! Between the engine's values and BSON.
//!
//! Writes follow `BJsonUtil.from`: relation keys become ObjectIds, and a number becomes the
//! narrowest BSON number that holds its Java text exactly (3.0 is stored as an Int32, as it
//! always has been). Filter values follow the Java driver's codecs for the objects Jackson
//! produced. Reads produce what Jackson would write for the Java object the driver handed
//! back: a nested ObjectId as its bean (`timestamp`, `date`), a Date as ISO text, a
//! Decimal128 as a bare number.

use mongodb::bson::{oid::ObjectId, Bson, DateTime, Document as BsonDocument};

use super::decimal128;
use crate::error::{AppDataError, AppDataResult};
use crate::value::{java_double, Decimal, Document, Value};

/// `BJsonUtil.from(idKeys, json)`.
pub fn from_validated(relation_keys: &[String], doc: &Document) -> AppDataResult<BsonDocument> {
    let mut out = BsonDocument::new();
    for (k, v) in doc {
        let b = if relation_keys.contains(k) { relation_value(v)? } else { from_element(v) };
        out.insert(k.clone(), b);
    }
    Ok(out)
}

fn object_id(v: &Value) -> AppDataResult<Bson> {
    let text = match v {
        Value::Null => return Err(AppDataError::internal("UnsupportedOperationException: JsonNull")),
        Value::Array(_) | Value::Object(_) => {
            return Err(AppDataError::internal("IllegalStateException: Not a JSON Primitive"))
        }
        other => other.java_string(),
    };
    ObjectId::parse_str(&text)
        .map(Bson::ObjectId)
        .map_err(|_| AppDataError::internal(format!("IllegalArgumentException: invalid hexadecimal representation of an ObjectId: [{text}]")))
}

fn relation_value(v: &Value) -> AppDataResult<Bson> {
    match v {
        Value::Array(a) => Ok(Bson::Array(a.iter().map(object_id).collect::<AppDataResult<Vec<_>>>()?)),
        other => object_id(other),
    }
}

/// `BJsonUtil.fromElement`.
pub fn from_element(v: &Value) -> Bson {
    match v {
        Value::Null => Bson::Null,
        Value::Bool(b) => Bson::Boolean(*b),
        Value::String(s) => Bson::String(s.clone()),
        Value::Int(_) | Value::Double(_) | Value::Decimal(_) => number(v),
        Value::Array(a) => Bson::Array(a.iter().map(from_element).collect()),
        Value::Object(o) => Bson::Document(o.iter().map(|(k, v)| (k.clone(), from_element(v))).collect()),
        other => Bson::String(other.java_string()),
    }
}

/// `BJsonUtil.number`: decided from the literal Gson would print.
pub fn number(v: &Value) -> Bson {
    let text = match v {
        Value::Int(i) => i.to_string(),
        Value::Double(d) => java_double(*d),
        Value::Decimal(d) => d.to_java_string(),
        _ => return Bson::Null,
    };
    if let Some(d) = Decimal::parse(&text) {
        if d.strip_trailing_zeros().scale() <= 0 {
            if let Some(l) = d.long_value_exact() {
                return match i32::try_from(l) {
                    Ok(i) => Bson::Int32(i),
                    Err(_) => Bson::Int64(l),
                };
            }
        }
    }
    let d = match v {
        Value::Double(d) => *d,
        Value::Decimal(d) => d.double_value(),
        Value::Int(i) => *i as f64,
        _ => 0.0,
    };
    Bson::Double(d)
}

/// A value from a filter, as the Java driver's codecs encode the Jackson object.
pub fn filter_value(v: &Value) -> Bson {
    match v {
        Value::Null => Bson::Null,
        Value::Bool(b) => Bson::Boolean(*b),
        Value::Int(i) => match i32::try_from(*i) {
            Ok(x) => Bson::Int32(x),
            Err(_) => Bson::Int64(*i),
        },
        Value::Double(d) => Bson::Double(*d),
        Value::Decimal(d) => match decimal128::from_decimal(d) {
            Ok(x) => Bson::Decimal128(x),
            Err(_) => Bson::Double(d.double_value()),
        },
        Value::String(s) => Bson::String(s.clone()),
        Value::Array(a) => Bson::Array(a.iter().map(filter_value).collect()),
        Value::Object(o) => Bson::Document(o.iter().map(|(k, v)| (k.clone(), filter_value(v))).collect()),
        Value::Date(ms) => Bson::DateTime(DateTime::from_millis(*ms)),
        other => Bson::String(other.java_string()),
    }
}

/// What Jackson writes for the Java object the driver decodes this BSON value into.
pub fn to_value(b: &Bson) -> Value {
    match b {
        Bson::Null | Bson::Undefined => Value::Null,
        Bson::Boolean(x) => Value::Bool(*x),
        Bson::Int32(i) => Value::Int(*i as i64),
        Bson::Int64(i) => Value::Int(*i),
        Bson::Double(d) => Value::Double(*d),
        Bson::String(s) | Bson::Symbol(s) | Bson::JavaScriptCode(s) => Value::String(s.clone()),
        Bson::Decimal128(d) => match decimal128::to_decimal(d) {
            decimal128::Decoded::Finite(x) => Value::Decimal(x),
            _ => Value::String(decimal128::to_java_string(d)),
        },
        Bson::DateTime(dt) => Value::Date(dt.timestamp_millis()),
        Bson::ObjectId(oid) => object_id_bean(oid),
        Bson::Array(a) => Value::Array(a.iter().map(to_value).collect()),
        Bson::Document(d) => Value::Object(document_to_value(d)),
        Bson::RegularExpression(r) => Value::String(format!("/{}/{}", r.pattern, r.options)),
        Bson::Timestamp(t) => Value::Int(((t.time as i64) << 32) | t.increment as i64),
        Bson::Binary(bin) => Value::String(hex::encode(&bin.bytes)),
        other => Value::String(other.to_string()),
    }
}

/// Jackson's bean view of an `org.bson.types.ObjectId`.
fn object_id_bean(oid: &ObjectId) -> Value {
    let ts = oid.timestamp().timestamp_millis();
    let mut d = Document::new();
    d.insert("timestamp".into(), Value::Int(ts / 1000));
    d.insert("date".into(), Value::Date(ts));
    Value::Object(d)
}

pub fn document_to_value(d: &BsonDocument) -> Document {
    d.iter().map(|(k, v)| (k.clone(), to_value(v))).collect()
}

/// A hex id as an ObjectId, or None when it is not one (`ObjectId.isValid`).
pub fn parse_object_id(id: &str) -> Option<ObjectId> {
    if id.len() != 24 {
        return None;
    }
    ObjectId::parse_str(id).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_take_the_narrowest_exact_type() {
        assert_eq!(number(&Value::Int(5)), Bson::Int32(5));
        assert_eq!(number(&Value::Int(9_007_199_254_740_993)), Bson::Int64(9_007_199_254_740_993));
        assert_eq!(number(&Value::Double(3.0)), Bson::Int32(3));
        assert_eq!(number(&Value::Double(0.125)), Bson::Double(0.125));
        assert_eq!(number(&Value::Double(1e30)), Bson::Double(1e30));
        assert_eq!(number(&Value::Double(1.0e10)), Bson::Int64(10_000_000_000));
    }

    #[test]
    fn relation_keys_become_object_ids() {
        let mut d = Document::new();
        d.insert("owner".into(), Value::from("6ac7d4a11a578c042996bca5"));
        d.insert("tags".into(), Value::Array(vec!["6ac7d4a11a578c042996bca6".into()]));
        d.insert("n".into(), Value::Int(1));
        let b = from_validated(&["owner".into(), "tags".into()], &d).unwrap();
        assert!(matches!(b.get("owner"), Some(Bson::ObjectId(_))));
        assert!(matches!(b.get("tags"), Some(Bson::Array(a)) if matches!(a[0], Bson::ObjectId(_))));
        let mut bad = Document::new();
        bad.insert("owner".into(), Value::from("nope"));
        assert!(from_validated(&["owner".into()], &bad).is_err());
    }

    #[test]
    fn reads_render_as_jackson_would() {
        let oid = ObjectId::parse_str("6ac7d4a11a578c042996bca5").unwrap();
        assert_eq!(
            to_value(&Bson::ObjectId(oid)).to_java_json(),
            r#"{"timestamp":1791480993,"date":"2026-10-08T17:36:33.000+00:00"}"#
        );
        assert_eq!(to_value(&Bson::DateTime(DateTime::from_millis(1_767_000_000_123))).to_java_json(), "\"2025-12-29T09:20:00.123+00:00\"");
        let d = decimal128::from_decimal(&Decimal::parse("1E+3").unwrap()).unwrap();
        assert_eq!(to_value(&Bson::Decimal128(d)).to_java_json(), "1E+3");
        assert!(parse_object_id("6ac7d4a11a578c042996bca5").is_some());
        assert!(parse_object_id("xyz").is_none());
    }
}
