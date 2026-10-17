//! BSON to [`JValue`] and back, as Spring Data maps an untyped (`Object`) value and Jackson
//! then writes it.

use mongodb::bson::{Bson, Document};

use crate::json::{java_double, JMap, JValue};

/// An untyped value: `Int32`/`Int64` are `Integer`/`Long`, `Double` is `Double`, nested
/// documents are maps in stored order.
///
/// Values the ui definitions never hold are approximated (checked over the whole local `ui`
/// database on 2026-10-15: only strings, booleans, numbers, nulls, arrays and documents
/// occur): a date is written as Jackson writes a `java.util.Date` (ISO-8601 in UTC), an
/// ObjectId as its hex string rather than Jackson's `{timestamp, date}` bean.
pub fn to_j(b: &Bson) -> JValue {
    match b {
        Bson::Double(d) => JValue::Float(*d),
        Bson::String(s) => JValue::Str(s.clone()),
        Bson::Array(a) => JValue::Array(a.iter().map(to_j).collect()),
        Bson::Document(d) => JValue::Object(doc_to_j(d)),
        Bson::Boolean(v) => JValue::Bool(*v),
        Bson::Null | Bson::Undefined => JValue::Null,
        Bson::Int32(i) => JValue::Int(*i as i64),
        Bson::Int64(i) => JValue::Int(*i),
        Bson::ObjectId(o) => JValue::Str(o.to_hex()),
        Bson::DateTime(dt) => {
            let ms = dt.timestamp_millis();
            match chrono::DateTime::from_timestamp_millis(ms) {
                Some(t) => JValue::Str(t.format("%Y-%m-%dT%H:%M:%S%.3f+00:00").to_string()),
                None => JValue::Null,
            }
        }
        Bson::Symbol(s) => JValue::Str(s.clone()),
        Bson::Decimal128(d) => JValue::Str(d.to_string()),
        Bson::Timestamp(t) => JValue::Int(t.time as i64),
        Bson::RegularExpression(r) => JValue::Str(r.pattern.clone()),
        Bson::JavaScriptCode(c) => JValue::Str(c.clone()),
        _ => JValue::Null,
    }
}

/// Spring Data's `mapKeyDotReplacement` (`IMongoConfiguration`): a `.` in a map key is stored
/// as this, and turned back on read.
pub const DOT_REPLACEMENT: &str = "__d-o-t__";

pub fn unescape_key(k: &str) -> String {
    if k.contains(DOT_REPLACEMENT) {
        k.replace(DOT_REPLACEMENT, ".")
    } else {
        k.to_string()
    }
}

pub fn escape_key(k: &str) -> String {
    if k.contains('.') {
        k.replace('.', DOT_REPLACEMENT)
    } else {
        k.to_string()
    }
}

/// A stored map, keys unescaped.
pub fn doc_to_j(d: &Document) -> JMap {
    d.iter().map(|(k, v)| (unescape_key(k), to_j(v))).collect()
}

/// A scalar as Spring's conversion service turns it into a `String` field.
pub fn to_java_string(b: &Bson) -> JValue {
    match b {
        Bson::String(s) => JValue::Str(s.clone()),
        Bson::Null | Bson::Undefined => JValue::Null,
        Bson::ObjectId(o) => JValue::Str(o.to_hex()),
        Bson::Int32(i) => JValue::Str(i.to_string()),
        Bson::Int64(i) => JValue::Str(i.to_string()),
        Bson::Double(d) => JValue::Str(java_double(*d)),
        Bson::Boolean(v) => JValue::Str(v.to_string()),
        Bson::Symbol(s) => JValue::Str(s.clone()),
        other => to_j(other),
    }
}

/// A value as Spring Data writes the Java object Jackson made of a request body: `Integer`
/// when it fits, else `Long`; maps as documents in their order.
pub fn from_j(v: &JValue) -> Bson {
    match v {
        JValue::Null => Bson::Null,
        JValue::Bool(b) => Bson::Boolean(*b),
        JValue::Int(i) => match i32::try_from(*i) {
            Ok(x) => Bson::Int32(x),
            Err(_) => Bson::Int64(*i),
        },
        JValue::Float(f) => Bson::Double(*f),
        JValue::Str(s) => Bson::String(s.clone()),
        JValue::Array(a) => Bson::Array(a.iter().map(from_j).collect()),
        JValue::Object(m) => Bson::Document(map_to_doc(m)),
    }
}

/// A map as Spring Data stores it, keys escaped.
pub fn map_to_doc(m: &JMap) -> Document {
    let mut d = Document::new();
    for (k, v) in m {
        d.insert(escape_key(k), from_j(v));
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;
    use mongodb::bson::{doc, oid::ObjectId, spec::BinarySubtype, Binary, DateTime, Decimal128, JavaScriptCodeWithScope, Regex, Timestamp};

    #[test]
    fn untyped_values_map_like_spring_then_jackson() {
        let oid = ObjectId::parse_str("63bd2d154d18a31536e81fa5").unwrap();
        let d = doc! {
            "d": 1.5, "s": "x", "a": [1_i32, "y"], "o": {"a__d-o-t__b": true}, "n": null,
            "i": 7_i32, "l": 8_i64, "oid": oid, "t": DateTime::from_millis(1_673_342_229_657),
            "sym": Bson::Symbol("sy".into()), "dec": Decimal128::from_bytes([0; 16]),
            "ts": Timestamp { time: 5, increment: 1 }, "re": Regex { pattern: "^a".into(), options: String::new() },
            "js": Bson::JavaScriptCode("f()".into()), "u": Bson::Undefined, "max": Bson::MaxKey,
            "bin": Binary { subtype: BinarySubtype::Generic, bytes: vec![1] },
            "jsw": JavaScriptCodeWithScope { code: "g()".into(), scope: doc! {} },
        };
        let m = doc_to_j(&d);
        assert_eq!(m["d"], JValue::Float(1.5));
        assert_eq!(m["s"], JValue::Str("x".into()));
        assert_eq!(m["a"], JValue::Array(vec![JValue::Int(1), JValue::Str("y".into())]));
        assert!(m["o"].as_object().unwrap().contains_key("a.b"));
        assert_eq!(m["n"], JValue::Null);
        assert_eq!(m["i"], JValue::Int(7));
        assert_eq!(m["l"], JValue::Int(8));
        assert_eq!(m["oid"], JValue::Str("63bd2d154d18a31536e81fa5".into()));
        assert_eq!(m["t"], JValue::Str("2023-01-10T09:17:09.657+00:00".into()));
        assert_eq!(m["sym"], JValue::Str("sy".into()));
        assert!(matches!(m["dec"], JValue::Str(_)));
        assert_eq!(m["ts"], JValue::Int(5));
        assert_eq!(m["re"], JValue::Str("^a".into()));
        assert_eq!(m["js"], JValue::Str("f()".into()));
        assert_eq!(m["u"], JValue::Null);
        assert_eq!(m["max"], JValue::Null);
        assert_eq!(m["bin"], JValue::Null);
        assert_eq!(m["jsw"], JValue::Null);
        assert_eq!(to_j(&Bson::DateTime(DateTime::MAX)), JValue::Null);
    }

    #[test]
    fn scalars_become_strings_for_string_fields() {
        let oid = ObjectId::parse_str("63bd2d154d18a31536e81fa5").unwrap();
        assert_eq!(to_java_string(&Bson::String("a".into())), JValue::Str("a".into()));
        assert_eq!(to_java_string(&Bson::Null), JValue::Null);
        assert_eq!(to_java_string(&Bson::Undefined), JValue::Null);
        assert_eq!(to_java_string(&Bson::ObjectId(oid)), JValue::Str(oid.to_hex()));
        assert_eq!(to_java_string(&Bson::Int32(5)), JValue::Str("5".into()));
        assert_eq!(to_java_string(&Bson::Int64(6)), JValue::Str("6".into()));
        assert_eq!(to_java_string(&Bson::Double(1.0)), JValue::Str("1.0".into()));
        assert_eq!(to_java_string(&Bson::Boolean(true)), JValue::Str("true".into()));
        assert_eq!(to_java_string(&Bson::Symbol("q".into())), JValue::Str("q".into()));
        assert!(matches!(to_java_string(&Bson::Document(doc! {"a": 1})), JValue::Object(_)));
    }

    #[test]
    fn values_go_back_as_spring_stores_them() {
        let v = crate::json::parse(br#"{"a.b":{"c":[1,3000000000,1.5,"s",null,false]}}"#).unwrap();
        let JValue::Object(m) = v else { panic!() };
        let d = map_to_doc(&m);
        let inner = d.get_document("a__d-o-t__b").unwrap();
        let arr = inner.get_array("c").unwrap();
        assert_eq!(arr[0], Bson::Int32(1));
        assert_eq!(arr[1], Bson::Int64(3_000_000_000));
        assert_eq!(arr[2], Bson::Double(1.5));
        assert_eq!(arr[3], Bson::String("s".into()));
        assert_eq!(arr[4], Bson::Null);
        assert_eq!(arr[5], Bson::Boolean(false));
        assert_eq!(escape_key("plain"), "plain");
        assert_eq!(unescape_key("plain"), "plain");
    }
}
