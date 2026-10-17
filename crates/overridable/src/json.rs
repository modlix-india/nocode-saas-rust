//! A JSON value that keeps what the Java side can tell apart, and writers that print it the way
//! Jackson and Gson do.
//!
//! `serde_json::Value` is not used for documents because it cannot keep key order without the
//! workspace-wide `preserve_order` feature (which would change the output of every other crate
//! in the build), and because the Java services distinguish integers from doubles: a Mongo
//! `Int32` prints as `1`, a `Double` as `1.0`, and the two are not `equals` in Java.

use std::fmt::Write as _;

use indexmap::IndexMap;
use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};

pub type JMap = IndexMap<String, JValue>;

#[derive(Debug, Clone, Default)]
pub enum JValue {
    #[default]
    Null,
    Bool(bool),
    /// `Integer` or `Long`.
    Int(i64),
    /// `Double`.
    Float(f64),
    Str(String),
    Array(Vec<JValue>),
    /// Entries in iteration order: insertion order for a `LinkedHashMap` or a Mongo document,
    /// table order for a `java.util.HashMap` (see [`crate::java_map`]).
    Object(JMap),
}

/// `Objects.equals` on the Java values: maps compare as maps (order does not matter), lists in
/// order, `Integer` never equals `Double`.
impl PartialEq for JValue {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (JValue::Null, JValue::Null) => true,
            (JValue::Bool(a), JValue::Bool(b)) => a == b,
            (JValue::Int(a), JValue::Int(b)) => a == b,
            // Double.equals: NaN equals NaN, 0.0 does not equal -0.0.
            (JValue::Float(a), JValue::Float(b)) => a.to_bits() == b.to_bits(),
            (JValue::Str(a), JValue::Str(b)) => a == b,
            (JValue::Array(a), JValue::Array(b)) => a == b,
            (JValue::Object(a), JValue::Object(b)) => a == b,
            _ => false,
        }
    }
}

impl JValue {
    pub fn is_null(&self) -> bool {
        matches!(self, JValue::Null)
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            JValue::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&JMap> {
        match self {
            JValue::Object(m) => Some(m),
            _ => None,
        }
    }

    pub fn as_object_mut(&mut self) -> Option<&mut JMap> {
        match self {
            JValue::Object(m) => Some(m),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            JValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            JValue::Int(i) => Some(*i),
            _ => None,
        }
    }

    /// `String.valueOf(value)` / `toString()` of the Java object, for the few places Java
    /// stringifies whatever is there (`e.get("name").toString()`).
    pub fn java_to_string(&self) -> String {
        match self {
            JValue::Null => "null".into(),
            JValue::Bool(b) => b.to_string(),
            JValue::Int(i) => i.to_string(),
            JValue::Float(f) => java_double(*f),
            JValue::Str(s) => s.clone(),
            // AbstractMap.toString / AbstractCollection.toString.
            JValue::Array(a) => {
                let parts: Vec<String> = a.iter().map(JValue::java_to_string).collect();
                format!("[{}]", parts.join(", "))
            }
            JValue::Object(m) => {
                let parts: Vec<String> = m.iter().map(|(k, v)| format!("{k}={}", v.java_to_string())).collect();
                format!("{{{}}}", parts.join(", "))
            }
        }
    }

    /// Jackson's `NON_EMPTY` test for a property value: null, an empty string, map or list.
    pub fn is_jackson_empty(&self) -> bool {
        match self {
            JValue::Null => true,
            JValue::Str(s) => s.is_empty(),
            JValue::Array(a) => a.is_empty(),
            JValue::Object(m) => m.is_empty(),
            _ => false,
        }
    }
}

impl From<&str> for JValue {
    fn from(s: &str) -> Self {
        JValue::Str(s.to_string())
    }
}

impl From<String> for JValue {
    fn from(s: String) -> Self {
        JValue::Str(s)
    }
}

impl<'de> Deserialize<'de> for JValue {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = JValue;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("any JSON value")
            }
            fn visit_bool<E>(self, v: bool) -> Result<JValue, E> {
                Ok(JValue::Bool(v))
            }
            fn visit_i64<E>(self, v: i64) -> Result<JValue, E> {
                Ok(JValue::Int(v))
            }
            fn visit_u64<E>(self, v: u64) -> Result<JValue, E> {
                // Beyond Long: Jackson would make a BigInteger; a double keeps the magnitude.
                Ok(i64::try_from(v).map(JValue::Int).unwrap_or(JValue::Float(v as f64)))
            }
            fn visit_f64<E>(self, v: f64) -> Result<JValue, E> {
                Ok(JValue::Float(v))
            }
            fn visit_str<E>(self, v: &str) -> Result<JValue, E> {
                Ok(JValue::Str(v.to_string()))
            }
            fn visit_string<E>(self, v: String) -> Result<JValue, E> {
                Ok(JValue::Str(v))
            }
            fn visit_unit<E>(self) -> Result<JValue, E> {
                Ok(JValue::Null)
            }
            fn visit_none<E>(self) -> Result<JValue, E> {
                Ok(JValue::Null)
            }
            fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<JValue, D::Error> {
                JValue::deserialize(d)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<JValue, A::Error> {
                let mut v = Vec::new();
                while let Some(x) = seq.next_element()? {
                    v.push(x);
                }
                Ok(JValue::Array(v))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<JValue, A::Error> {
                let mut m = JMap::new();
                while let Some((k, v)) = map.next_entry::<String, JValue>()? {
                    m.insert(k, v);
                }
                Ok(JValue::Object(m))
            }
        }
        d.deserialize_any(V)
    }
}

impl Serialize for JValue {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            JValue::Null => s.serialize_unit(),
            JValue::Bool(b) => s.serialize_bool(*b),
            JValue::Int(i) => s.serialize_i64(*i),
            JValue::Float(f) => s.serialize_f64(*f),
            JValue::Str(x) => s.serialize_str(x),
            JValue::Array(a) => {
                let mut seq = s.serialize_seq(Some(a.len()))?;
                for x in a {
                    seq.serialize_element(x)?;
                }
                seq.end()
            }
            JValue::Object(m) => {
                let mut map = s.serialize_map(Some(m.len()))?;
                for (k, v) in m {
                    map.serialize_entry(k, v)?;
                }
                map.end()
            }
        }
    }
}

/// Parses JSON text, keeping key order and the integer/double distinction.
pub fn parse(bytes: &[u8]) -> anyhow::Result<JValue> {
    Ok(serde_json::from_slice(bytes)?)
}

/// `Double.toString(d)` (JDK 19+): the shortest digits that round-trip, written plainly for
/// `1e-3 <= |d| < 1e7` and as `d.dddE±n` otherwise, always with a digit after the point.
pub fn java_double(d: f64) -> String {
    if d.is_nan() {
        return "NaN".into();
    }
    if d.is_infinite() {
        return if d > 0.0 { "Infinity".into() } else { "-Infinity".into() };
    }
    if d == 0.0 {
        return if d.is_sign_negative() { "-0.0".into() } else { "0.0".into() };
    }
    let mut buf = ryu::Buffer::new();
    let s = buf.format_finite(d.abs());
    let (digits, exp) = decimal_digits(s);
    let mut out = String::new();
    if d < 0.0 {
        out.push('-');
    }
    let abs = d.abs();
    if (1e-3..1e7).contains(&abs) {
        if exp >= 0 {
            let int_len = (exp + 1) as usize;
            if digits.len() <= int_len {
                out.push_str(&digits);
                out.extend(std::iter::repeat_n('0', int_len - digits.len()));
                out.push_str(".0");
            } else {
                out.push_str(&digits[..int_len]);
                out.push('.');
                out.push_str(&digits[int_len..]);
            }
        } else {
            out.push_str("0.");
            out.extend(std::iter::repeat_n('0', (-exp - 1) as usize));
            out.push_str(&digits);
        }
    } else {
        out.push_str(&digits[..1]);
        out.push('.');
        if digits.len() > 1 {
            out.push_str(&digits[1..]);
        } else {
            out.push('0');
        }
        let _ = write!(out, "E{exp}");
    }
    out
}

/// The significant digits of a ryu rendering and the decimal exponent of the first digit
/// (`123.4` is `("1234", 2)`, `1e-7` is `("1", -7)`).
fn decimal_digits(s: &str) -> (String, i32) {
    let (mantissa, e) = match s.split_once('e') {
        Some((m, e)) => (m, e.parse::<i32>().unwrap_or(0)),
        None => (s, 0),
    };
    let (int_part, frac_part) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let all: String = format!("{int_part}{frac_part}");
    let lead = all.chars().take_while(|c| *c == '0').count();
    let digits = all[lead..].trim_end_matches('0').to_string();
    let exp = int_part.len() as i32 - 1 - lead as i32 + e;
    if digits.is_empty() {
        ("0".into(), 0)
    } else {
        (digits, exp)
    }
}

fn number_text(v: &JValue, out: &mut String) {
    match v {
        JValue::Int(i) => {
            let _ = write!(out, "{i}");
        }
        JValue::Float(f) => {
            if f.is_finite() {
                out.push_str(&java_double(*f));
            } else {
                // Jackson's QUOTE_NON_NUMERIC_NUMBERS (on by default).
                out.push('"');
                out.push_str(&java_double(*f));
                out.push('"');
            }
        }
        _ => {}
    }
}

const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

/// Jackson's string escaping: the two-character escapes for `" \ \b \t \n \f \r`, `\u00XX`
/// (upper-case) for other control characters, everything else as is.
fn jackson_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{0C}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                let b = c as u32 as u8;
                out.push_str("\\u00");
                out.push(HEX_UPPER[(b >> 4) as usize] as char);
                out.push(HEX_UPPER[(b & 0xF) as usize] as char);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Gson's escaping with its default HTML-safe set: control characters as `\u00xx`
/// (lower-case), `< > & = '` as `<` and friends, and U+2028/U+2029 escaped.
fn gson_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\u{0C}' => out.push_str("\\f"),
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '=' => out.push_str("\\u003d"),
            '\'' => out.push_str("\\u0027"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn indent(out: &mut String, level: usize) {
    out.push('\n');
    for _ in 0..level {
        out.push_str("  ");
    }
}

/// Jackson with `INDENT_OUTPUT` (`DefaultPrettyPrinter`): objects one entry per line,
/// two-space indent, `"key" : value`, `{ }` when empty; arrays on one line, `[ a, b ]`,
/// `[ ]` when empty. No trailing newline.
pub fn to_jackson_pretty(v: &JValue) -> String {
    let mut out = String::with_capacity(4096);
    jackson_pretty(v, 0, &mut out);
    out
}

fn jackson_pretty(v: &JValue, level: usize, out: &mut String) {
    match v {
        JValue::Null => out.push_str("null"),
        JValue::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        JValue::Int(_) | JValue::Float(_) => number_text(v, out),
        JValue::Str(s) => jackson_string(s, out),
        JValue::Array(a) => {
            if a.is_empty() {
                out.push_str("[ ]");
                return;
            }
            out.push_str("[ ");
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                jackson_pretty(x, level, out);
            }
            out.push_str(" ]");
        }
        JValue::Object(m) => {
            if m.is_empty() {
                out.push_str("{ }");
                return;
            }
            out.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                indent(out, level + 1);
                jackson_string(k, out);
                out.push_str(" : ");
                jackson_pretty(x, level + 1, out);
            }
            indent(out, level);
            out.push('}');
        }
    }
}

/// `Gson.toJson`: compact, HTML-safe escaping.
pub fn to_gson(v: &JValue) -> String {
    let mut out = String::with_capacity(4096);
    gson(v, &mut out);
    out
}

fn gson(v: &JValue, out: &mut String) {
    match v {
        JValue::Null => out.push_str("null"),
        JValue::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        JValue::Int(_) | JValue::Float(_) => number_text(v, out),
        JValue::Str(s) => gson_string(s, out),
        JValue::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                gson(x, out);
            }
            out.push(']');
        }
        JValue::Object(m) => {
            out.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                gson_string(k, out);
                out.push(':');
                gson(x, out);
            }
            out.push('}');
        }
    }
}

/// Compact JSON of a map, for hashing.
pub fn map_to_compact(m: &JMap) -> String {
    struct R<'a>(&'a JMap);
    impl Serialize for R<'_> {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            let mut map = s.serialize_map(Some(self.0.len()))?;
            for (k, v) in self.0 {
                map.serialize_entry(k, v)?;
            }
            map.end()
        }
    }
    serde_json::to_string(&R(m)).unwrap_or_default()
}

/// Compact JSON for hashing and logs (not a Java format).
pub fn to_compact(v: &JValue) -> String {
    serde_json::to_string(v).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doubles_print_like_java() {
        assert_eq!(java_double(50.0), "50.0");
        assert_eq!(java_double(55.5), "55.5");
        assert_eq!(java_double(0.001), "0.001");
        assert_eq!(java_double(0.0001), "1.0E-4");
        assert_eq!(java_double(1234567.0), "1234567.0");
        assert_eq!(java_double(1e7), "1.0E7");
        assert_eq!(java_double(12345678.9), "1.23456789E7");
        assert_eq!(java_double(-2.5), "-2.5");
        assert_eq!(java_double(0.1), "0.1");
        assert_eq!(java_double(100.0), "100.0");
        assert_eq!(java_double(1.0E-5), "1.0E-5");
        assert_eq!(java_double(9.223372036854776E18), "9.223372036854776E18");
        assert_eq!(java_double(0.0), "0.0");
    }

    #[test]
    fn jackson_pretty_shape() {
        let v = parse(br#"{"a":1,"b":{"c":[1,2.0,"x"],"d":{},"e":[]},"f":[{"g":true}]}"#).unwrap();
        let expected = "{\n  \"a\" : 1,\n  \"b\" : {\n    \"c\" : [ 1, 2.0, \"x\" ],\n    \"d\" : { },\n    \"e\" : [ ]\n  },\n  \"f\" : [ {\n    \"g\" : true\n  } ]\n}";
        assert_eq!(to_jackson_pretty(&v), expected);
    }

    #[test]
    fn gson_escapes_html() {
        let v = parse(br#"{"e":"(a % 2) = 1 <b> & 'c'"}"#).unwrap();
        let expected = "{\"e\":\"(a % 2) \\u003d 1 \\u003cb\\u003e \\u0026 \\u0027c\\u0027\"}";
        assert_eq!(to_gson(&v), expected);
    }

    #[test]
    fn int_and_double_differ() {
        assert_ne!(JValue::Int(1), JValue::Float(1.0));
        let a = parse(br#"{"x":1,"y":2}"#).unwrap();
        let b = parse(br#"{"y":2,"x":1}"#).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn java_to_string_and_accessors() {
        let v = parse(br#"{"a":[1,2.5,"x",true,null],"b":{"c":1}}"#).unwrap();
        assert_eq!(v.java_to_string(), "{a=[1, 2.5, x, true, null], b={c=1}}");
        assert!(v.as_object().is_some());
        let mut w = v.clone();
        assert!(w.as_object_mut().is_some());
        assert_eq!(JValue::Bool(true).as_bool(), Some(true));
        assert_eq!(JValue::Int(3).as_i64(), Some(3));
        assert_eq!(JValue::Str("x".into()).as_str(), Some("x"));
        assert_eq!(JValue::Int(3).as_str(), None);
        assert_eq!(JValue::Int(3).as_object(), None);
        assert!(JValue::Int(3).clone().as_object_mut().is_none());
        assert_eq!(JValue::Str("x".into()).as_bool(), None);
        assert_eq!(JValue::Str("x".into()).as_i64(), None);
        assert_eq!(JValue::from("a"), JValue::Str("a".into()));
        assert_eq!(JValue::from(String::from("a")), JValue::Str("a".into()));
        assert!(JValue::Null.is_jackson_empty());
        assert!(JValue::Str(String::new()).is_jackson_empty());
        assert!(JValue::Array(vec![]).is_jackson_empty());
        assert!(JValue::Object(JMap::new()).is_jackson_empty());
        assert!(!JValue::Bool(false).is_jackson_empty());
        assert!(!JValue::Int(0).is_jackson_empty());
        assert_eq!(JValue::default(), JValue::Null);
    }

    #[test]
    fn equality_follows_java() {
        assert_eq!(JValue::Float(f64::NAN), JValue::Float(f64::NAN));
        assert_ne!(JValue::Float(0.0), JValue::Float(-0.0));
        assert_ne!(JValue::Null, JValue::Bool(false));
        assert_eq!(parse(b"[1,2]").unwrap(), parse(b"[1,2]").unwrap());
        assert_ne!(parse(b"[1,2]").unwrap(), parse(b"[2,1]").unwrap());
    }

    #[test]
    fn parse_keeps_numbers_apart() {
        let v = parse(br#"[1,-2,1.0,1e3,18446744073709551615,"s",null,true]"#).unwrap();
        let JValue::Array(a) = v else { panic!() };
        assert_eq!(a[0], JValue::Int(1));
        assert_eq!(a[1], JValue::Int(-2));
        assert_eq!(a[2], JValue::Float(1.0));
        assert_eq!(a[3], JValue::Float(1000.0));
        assert!(matches!(a[4], JValue::Float(_)));
        assert_eq!(a[5], JValue::Str("s".into()));
        assert_eq!(a[6], JValue::Null);
        assert_eq!(a[7], JValue::Bool(true));
        assert!(parse(b"{oops").is_err());
        // Through serde's Option path too.
        let o: Option<JValue> = serde_json::from_str("null").unwrap();
        assert!(o.is_none());
        let o: Option<JValue> = serde_json::from_str("{\"a\":1}").unwrap();
        assert!(o.is_some());
    }

    #[test]
    fn compact_and_map_writers() {
        let v = parse(br#"{"a":[1,2.5,null,true,"q"],"b":{}}"#).unwrap();
        assert_eq!(to_compact(&v), r#"{"a":[1,2.5,null,true,"q"],"b":{}}"#);
        let JValue::Object(m) = v else { panic!() };
        assert_eq!(map_to_compact(&m), r#"{"a":[1,2.5,null,true,"q"],"b":{}}"#);
    }

    #[test]
    fn doubles_edge_cases() {
        assert_eq!(java_double(f64::NAN), "NaN");
        assert_eq!(java_double(f64::INFINITY), "Infinity");
        assert_eq!(java_double(f64::NEG_INFINITY), "-Infinity");
        assert_eq!(java_double(-0.0), "-0.0");
        assert_eq!(java_double(1e21), "1.0E21");
        assert_eq!(java_double(1.5e-7), "1.5E-7");
        assert_eq!(java_double(-1.0E-5), "-1.0E-5");
        assert_eq!(java_double(123456.0), "123456.0");
        assert_eq!(java_double(0.0012), "0.0012");
        assert_eq!(java_double(9999999.0), "9999999.0");
        assert_eq!(decimal_digits("0.000"), ("0".to_string(), 0));
    }

    #[test]
    fn escaping_in_both_writers() {
        let s = "q\"b\\s\u{08}t\tn\nf\u{0C}r\r\u{01}\u{7F}é\u{2028}";
        let mut j = String::new();
        jackson_string(s, &mut j);
        assert_eq!(j, "\"q\\\"b\\\\s\\bt\\tn\\nf\\fr\\r\\u0001\u{7F}é\u{2028}\"");
        let mut g = String::new();
        gson_string(s, &mut g);
        assert_eq!(g, "\"q\\\"b\\\\s\\bt\\tn\\nf\\fr\\r\\u0001\u{7F}é\\u2028\"");
        let mut g2 = String::new();
        gson_string("\u{2029}", &mut g2);
        assert_eq!(g2, "\"\\u2029\"");
    }

    #[test]
    fn non_finite_numbers_are_quoted_by_jackson() {
        let v = JValue::Array(vec![JValue::Float(f64::NAN), JValue::Bool(false), JValue::Null, JValue::Int(-3)]);
        assert_eq!(to_jackson_pretty(&v), "[ \"NaN\", false, null, -3 ]");
        assert_eq!(to_gson(&v), "[\"NaN\",false,null,-3]");
        assert_eq!(to_gson(&parse(br#"{"a":[],"b":{}}"#).unwrap()), r#"{"a":[],"b":{}}"#);
    }

}
