//! The three JSON writers the Java code paths use, over `serde_json::Value`:
//!
//! - [`jackson`]: Jackson's default `ObjectMapper` (WebClient's codec, the AMQP converter):
//!   nulls kept, control characters escaped with upper-case hex, doubles as `Double.toString`.
//! - [`gson_element`]: `JsonElement.toString()`: nulls kept, lower-case hex, U+2028/U+2029
//!   escaped.
//! - [`gson_tree`]: what `gson.toJsonTree(object)` leaves of a value read into Java maps:
//!   members whose value is null are dropped at every depth (nulls in arrays stay).

use std::fmt::Write as _;

use serde_json::{Map, Number, Value};

use super::java_double;

fn number(n: &Number, out: &mut String) {
    if let Some(i) = n.as_i64() {
        let _ = write!(out, "{i}");
    } else if let Some(u) = n.as_u64() {
        let _ = write!(out, "{u}");
    } else {
        out.push_str(&java_double(n.as_f64().unwrap_or(0.0)));
    }
}

pub fn jackson(v: &Value) -> String {
    let mut out = String::new();
    write_jackson(v, &mut out);
    out
}

fn write_jackson(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => number(n, out),
        Value::String(s) => jackson_string(s, out),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_jackson(x, out);
            }
            out.push(']');
        }
        Value::Object(m) => {
            out.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                jackson_string(k, out);
                out.push(':');
                write_jackson(x, out);
            }
            out.push('}');
        }
    }
}

fn jackson_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\u{0C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04X}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Jackson with `INDENT_OUTPUT` (the services' `ObjectMapper`): `DefaultPrettyPrinter`'s two
/// space indent, `"key" : value`, arrays inline as `[ 1, 2 ]`, empty containers as `{ }` and
/// `[ ]`.
pub fn jackson_pretty(v: &Value) -> String {
    let mut out = String::new();
    write_pretty(v, &mut out, 0);
    out
}

fn newline_indent(out: &mut String, level: usize) {
    out.push('\n');
    for _ in 0..level {
        out.push_str("  ");
    }
}

fn write_pretty(v: &Value, out: &mut String, nesting: usize) {
    match v {
        Value::Object(m) => {
            out.push('{');
            if m.is_empty() {
                out.push_str(" }");
                return;
            }
            let level = nesting + 1;
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline_indent(out, level);
                jackson_string(k, out);
                out.push_str(" : ");
                write_pretty(x, out, level);
            }
            newline_indent(out, nesting);
            out.push('}');
        }
        Value::Array(a) => {
            out.push('[');
            if a.is_empty() {
                out.push_str(" ]");
                return;
            }
            out.push(' ');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_pretty(x, out, nesting);
            }
            out.push_str(" ]");
        }
        other => write_jackson(other, out),
    }
}

/// Jackson's `NON_EMPTY` for a bean property: null, an empty string, list or map is left out.
pub fn jackson_non_empty(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(m) => !m.is_empty(),
        _ => true,
    }
}

pub fn gson_element(v: &Value) -> String {
    let mut out = String::new();
    write_gson(v, &mut out);
    out
}

fn write_gson(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => number(n, out),
        Value::String(s) => gson_string(s, out),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_gson(x, out);
            }
            out.push(']');
        }
        Value::Object(m) => {
            out.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                gson_string(k, out);
                out.push(':');
                write_gson(x, out);
            }
            out.push('}');
        }
    }
}

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

/// `gson.toJsonTree(x)` for a value that went through Java maps and lists.
pub fn gson_tree(v: Value) -> Value {
    match v {
        Value::Object(m) => {
            let m: Map<String, Value> = m.into_iter().filter(|(_, x)| !x.is_null()).map(|(k, x)| (k, gson_tree(x))).collect();
            Value::Object(m)
        }
        Value::Array(a) => Value::Array(a.into_iter().map(gson_tree).collect()),
        other => other,
    }
}

/// Every number turned into a double, as Gson's `ObjectTypeAdapter` reads JSON into
/// `Map<String, Object>` / `List<Object>` (`1` becomes `1.0`).
pub fn numbers_as_doubles(v: Value) -> Value {
    match v {
        Value::Number(n) => match n.as_f64().and_then(Number::from_f64) {
            Some(d) => Value::Number(d),
            None => Value::Number(n),
        },
        Value::Array(a) => Value::Array(a.into_iter().map(numbers_as_doubles).collect()),
        Value::Object(m) => Value::Object(m.into_iter().map(|(k, x)| (k, numbers_as_doubles(x))).collect()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn pretty_like_jackson() {
        let v = json!({"a": 1, "e": {}, "f": {"g": null, "h": []}, "d": [1, "x"], "o": [{"k": 1}]});
        assert_eq!(
            jackson_pretty(&v),
            "{\n  \"a\" : 1,\n  \"e\" : { },\n  \"f\" : {\n    \"g\" : null,\n    \"h\" : [ ]\n  },\n  \"d\" : [ 1, \"x\" ],\n  \"o\" : [ {\n    \"k\" : 1\n  } ]\n}"
        );
    }

    #[test]
    fn writers() {
        let v = json!({"a": "x\u{1}\"", "b": null, "c": 1.0, "d": [null, 2]});
        assert_eq!(jackson(&v), "{\"a\":\"x\\u0001\\\"\",\"b\":null,\"c\":1.0,\"d\":[null,2]}");
        assert_eq!(gson_element(&v), "{\"a\":\"x\\u0001\\\"\",\"b\":null,\"c\":1.0,\"d\":[null,2]}");
        assert_eq!(gson_tree(v), json!({"a": "x\u{1}\"", "c": 1.0, "d": [null, 2]}));
        assert_eq!(gson_element(&json!(1e10)), "1.0E10");
        assert_eq!(numbers_as_doubles(json!({"a": 1, "b": [2]})).to_string(), "{\"a\":1.0,\"b\":[2.0]}");
    }
}
