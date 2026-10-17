//! Bodies written the way the security service's `ObjectMapper` writes them.
//!
//! `AbstractBaseConfiguration` turns on `INDENT_OUTPUT` and `NON_EMPTY` inclusion, and the
//! `CommonsSerializationModule` writes every `LocalDateTime` as epoch seconds read as UTC. So a
//! body is pretty printed by Jackson's `DefaultPrettyPrinter` (`"key" : value`, arrays inline),
//! and leaves out nulls, empty strings and empty arrays. Objects are built here in Jackson's
//! property order, so the bytes match the Java service's.

use axum::body::Body;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::Response;
use chrono::NaiveDateTime;
use serde_json::{Map, Value};

/// `LocalDateTime.MAX.toEpochSecond(UTC)`: the anonymous caller's token never expires.
pub const LOCAL_DATE_TIME_MAX_EPOCH: i64 = 31_556_889_832_780_799;

/// Marks a string that [`pretty`] writes as a bare number: a `BigDecimal` keeps its scale
/// (`1.0000`), which a JSON `f64` cannot.
pub const RAW_NUMBER: &str = "\u{1}num:";

/// A number written exactly as given.
pub fn raw_number(text: impl std::fmt::Display) -> Value {
    Value::String(format!("{RAW_NUMBER}{text}"))
}

/// Jackson's `DefaultPrettyPrinter` output for `v`.
pub fn pretty(v: &Value) -> String {
    let mut out = String::new();
    write(v, 0, &mut out);
    out
}

fn write(v: &Value, nesting: usize, out: &mut String) {
    match v {
        Value::Array(items) => {
            if items.is_empty() {
                out.push_str("[ ]");
                return;
            }
            // Arrays are inline: they do not deepen the indentation of what they contain.
            out.push_str("[ ");
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write(item, nesting, out);
            }
            out.push_str(" ]");
        }
        Value::Object(map) => {
            if map.is_empty() {
                out.push_str("{ }");
                return;
            }
            out.push('{');
            for (i, (k, val)) in map.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('\n');
                indent(nesting + 1, out);
                out.push_str(&Value::String(k.clone()).to_string());
                out.push_str(" : ");
                write(val, nesting + 1, out);
            }
            out.push('\n');
            indent(nesting, out);
            out.push('}');
        }
        Value::String(s) if s.starts_with(RAW_NUMBER) => out.push_str(&s[RAW_NUMBER.len()..]),
        other => out.push_str(&other.to_string()),
    }
}

fn indent(level: usize, out: &mut String) {
    for _ in 0..level {
        out.push_str("  ");
    }
}

/// `NON_EMPTY`: what Jackson leaves out of a bean. Nested beans are never empty.
pub fn is_empty_value(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        _ => false,
    }
}

/// A bean in property order, leaving out what `NON_EMPTY` leaves out.
#[derive(Default)]
pub struct Obj(Map<String, Value>);

impl Obj {
    pub fn new() -> Self {
        Self(Map::new())
    }

    pub fn put(mut self, key: &str, v: impl Into<Value>) -> Self {
        let v = v.into();
        if !is_empty_value(&v) {
            self.0.insert(key.to_string(), v);
        }
        self
    }

    /// A property Jackson writes even when empty (a `Page`'s `sort`).
    pub fn put_always(mut self, key: &str, v: impl Into<Value>) -> Self {
        self.0.insert(key.to_string(), v.into());
        self
    }

    pub fn build(self) -> Value {
        Value::Object(self.0)
    }
}

/// An optional value as JSON (`null` when absent, which `Obj::put` then drops).
pub fn opt<T: Into<Value>>(v: Option<T>) -> Value {
    v.map(Into::into).unwrap_or(Value::Null)
}

/// A `LocalDateTime` as `CommonsSerializationModule` writes it: the wall time read as UTC.
pub fn epoch(t: Option<NaiveDateTime>) -> Value {
    t.map(|t| Value::from(t.and_utc().timestamp())).unwrap_or(Value::Null)
}

/// `ResponseEntity.ok(object)` through Jackson. The security headers are added by the
/// unit's response layer.
pub fn json(v: &Value) -> Response {
    json_status(StatusCode::OK, v)
}

pub fn json_status(status: StatusCode, v: &Value) -> Response {
    let mut resp = Response::new(Body::from(pretty(v)));
    *resp.status_mut() = status;
    resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    resp
}

/// `ResponseEntity.ok().build()` / `ResponseEntity.status(s).build()`: no body at all.
pub fn empty(status: StatusCode) -> Response {
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = status;
    resp.headers_mut().insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn matches_jackson_default_pretty_printer() {
        let v = json!({"user": {"id": 0, "stringAuthorities": ["Authorities._Anonymous"]}, "authenticated": false});
        let expected = "{\n  \"user\" : {\n    \"id\" : 0,\n    \"stringAuthorities\" : [ \"Authorities._Anonymous\" ]\n  },\n  \"authenticated\" : false\n}";
        assert_eq!(pretty(&v), expected);
    }

    #[test]
    fn local_date_time_max() {
        // LocalDateTime.MAX: epoch day 365241780471, second of day 86399.
        assert_eq!(LOCAL_DATE_TIME_MAX_EPOCH, 365_241_780_471 * 86_400 + 86_399);
    }

    #[test]
    fn non_empty_inclusion() {
        let v = Obj::new().put("a", Value::Null).put("b", "").put("c", json!([])).put("d", 0).put("e", false).build();
        assert_eq!(v, json!({"d": 0, "e": false}));
        let v = Obj::new().put_always("s", json!([])).put("n", raw_number("1.0000")).build();
        assert_eq!(pretty(&v), "{\n  \"s\" : [ ],\n  \"n\" : 1.0000\n}");
    }
}
