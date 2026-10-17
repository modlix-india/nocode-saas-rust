//! The two JSON writers core's Java code answers with, over `serde_json::Value` (the kirun
//! crate's value type):
//!
//! - [`to_gson`]: `Gson.toJson` with core's `Gson` bean. Members whose value is null are left
//!   out at every depth (`serializeNulls` is off, and a `JsonNull` written after a name drops
//!   the name too), nulls inside arrays stay, and strings are escaped HTML-safe.
//! - [`element_to_string`]: `JsonElement.toString()`, which hashing and signing use on their
//!   input: a plain `JsonWriter`, so nulls are kept and nothing is HTML-escaped.
//!
//! - [`to_jackson_pretty`]: Jackson with `INDENT_OUTPUT`, which the `ResponseEntity` routes
//!   (`repositoryFilter`, schemas `repositoryFind`) answer with.
//!
//! Numbers are written as Java writes the boxed value: an integer as is, a double through
//! `Double.toString` (`3.0`, `1.0E7`).

use std::fmt::Write as _;

use overridable::json::java_double;
use serde_json::{Number, Value};

/// `Gson.toJson(element)` with the default (HTML-safe, nulls skipped) settings.
pub fn to_gson(v: &Value) -> String {
    let mut out = String::with_capacity(256);
    write(v, &mut out, true, false);
    out
}

/// `JsonElement.toString()`.
pub fn element_to_string(v: &Value) -> String {
    let mut out = String::with_capacity(64);
    write(v, &mut out, false, true);
    out
}

/// Jackson's `DefaultPrettyPrinter`: one object entry per line, two-space indent,
/// `"key" : value`, `{ }` when empty; arrays on one line, `[ a, b ]`, `[ ]` when empty.
pub fn to_jackson_pretty(v: &Value) -> String {
    let mut out = String::with_capacity(256);
    jackson_pretty(v, 0, &mut out);
    out
}

fn jackson_pretty(v: &Value, level: usize, out: &mut String) {
    let newline = |out: &mut String, level: usize| {
        out.push('\n');
        for _ in 0..level {
            out.push_str("  ");
        }
    };
    match v {
        Value::Array(a) if a.is_empty() => out.push_str("[ ]"),
        Value::Array(a) => {
            out.push_str("[ ");
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                jackson_pretty(x, level, out);
            }
            out.push_str(" ]");
        }
        Value::Object(m) if m.is_empty() => out.push_str("{ }"),
        Value::Object(m) => {
            out.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline(out, level + 1);
                jackson_string(k, out);
                out.push_str(" : ");
                jackson_pretty(x, level + 1, out);
            }
            newline(out, level);
            out.push('}');
        }
        Value::String(s) => jackson_string(s, out),
        other => write(other, out, false, true),
    }
}

/// [`to_jackson_pretty`] over an app-data value: rows keep their nulls (the services'
/// `ObjectMapper` includes map content `ALWAYS`), scalars are written as the engines' values
/// are (`LocalDateTime` as epoch seconds, a `java.util.Date` as ISO text).
pub fn to_jackson_pretty_data(v: &appdata::Value) -> String {
    let mut out = String::with_capacity(256);
    jackson_pretty_data(v, 0, &mut out);
    out
}

fn jackson_pretty_data(v: &appdata::Value, level: usize, out: &mut String) {
    use appdata::Value as V;
    let newline = |out: &mut String, level: usize| {
        out.push('\n');
        for _ in 0..level {
            out.push_str("  ");
        }
    };
    match v {
        V::Array(a) if a.is_empty() => out.push_str("[ ]"),
        V::Array(a) => {
            out.push_str("[ ");
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                jackson_pretty_data(x, level, out);
            }
            out.push_str(" ]");
        }
        V::Object(m) if m.is_empty() => out.push_str("{ }"),
        V::Object(m) => {
            out.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline(out, level + 1);
                jackson_string(k, out);
                out.push_str(" : ");
                jackson_pretty_data(x, level + 1, out);
            }
            newline(out, level);
            out.push('}');
        }
        V::String(s) => jackson_string(s, out),
        other => other.write_java_json(out),
    }
}

/// Jackson's escaping: the short escapes, other control characters as `\u00XX` (upper case).
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
                let _ = write!(out, "\\u{:04X}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// `Number.toString()` of the value Java would hold: `3`, `3.0`, `1.0E-4`.
pub fn number_to_java_string(n: &Number) -> String {
    if let Some(i) = n.as_i64() {
        return i.to_string();
    }
    if let Some(u) = n.as_u64() {
        return u.to_string();
    }
    java_double(n.as_f64().unwrap_or(0.0))
}

fn write(v: &Value, out: &mut String, html_safe: bool, keep_nulls: bool) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&number_to_java_string(n)),
        Value::String(s) => string(s, out, html_safe),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(x, out, html_safe, keep_nulls);
            }
            out.push(']');
        }
        Value::Object(m) => {
            out.push('{');
            let mut first = true;
            for (k, x) in m {
                if x.is_null() && !keep_nulls {
                    continue;
                }
                if !first {
                    out.push(',');
                }
                first = false;
                string(k, out, html_safe);
                out.push(':');
                write(x, out, html_safe, keep_nulls);
            }
            out.push('}');
        }
    }
}

/// `JsonWriter.string`: `"` and `\`, the short escapes, other control characters as
/// `\u00xx` (lower-case hex), U+2028 / U+2029, and with HTML safety `< > & = '` too.
fn string(s: &str, out: &mut String, html_safe: bool) {
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
            '<' if html_safe => out.push_str("\\u003c"),
            '>' if html_safe => out.push_str("\\u003e"),
            '&' if html_safe => out.push_str("\\u0026"),
            '=' if html_safe => out.push_str("\\u003d"),
            '\'' if html_safe => out.push_str("\\u0027"),
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn gson_drops_null_members_and_escapes_html() {
        let v = json!([{"name": "output", "result": {"a": null, "b": [1, null, 2.0], "c": "x<y>&'='", "d": {"e": null}}}]);
        assert_eq!(
            to_gson(&v),
            "[{\"name\":\"output\",\"result\":{\"b\":[1,null,2.0],\"c\":\"x\\u003cy\\u003e\\u0026\\u0027\\u003d\\u0027\",\"d\":{}}}]"
        );
    }

    #[test]
    fn element_to_string_keeps_nulls_and_html() {
        let v = json!({"a": null, "b": "<p>", "c": 1.5, "d": 10000000.0});
        assert_eq!(element_to_string(&v), r#"{"a":null,"b":"<p>","c":1.5,"d":1.0E7}"#);
        assert_eq!(element_to_string(&json!("a\u{1}b")), "\"a\\u0001b\"");
    }

    #[test]
    fn jackson_pretty_shape() {
        let v = json!({"a": 1, "b": {"c": [1, 2.0, "x"], "d": {}, "e": []}, "f": [{"g": true}]});
        let expected = "{\n  \"a\" : 1,\n  \"b\" : {\n    \"c\" : [ 1, 2.0, \"x\" ],\n    \"d\" : { },\n    \"e\" : [ ]\n  },\n  \"f\" : [ {\n    \"g\" : true\n  } ]\n}";
        assert_eq!(to_jackson_pretty(&v), expected);
        assert_eq!(to_jackson_pretty(&json!(["a<b", "c"])), "[ \"a<b\", \"c\" ]");
    }

    #[test]
    fn numbers_as_java() {
        assert_eq!(to_gson(&json!(3.0)), "3.0");
        assert_eq!(to_gson(&json!(3)), "3");
        assert_eq!(to_gson(&json!(0.0001)), "1.0E-4");
    }

    #[test]
    fn other_numbers_and_escapes() {
        assert_eq!(number_to_java_string(&serde_json::Number::from(u64::MAX)), u64::MAX.to_string());
        assert_eq!(to_gson(&json!("\t\u{8}\n\r\u{c}\"\\\u{2028}\u{2029}")), r#""\t\b\n\r\f\"\\\u2028\u2029""#);
        assert_eq!(to_jackson_pretty(&json!({"k": "\u{1}\t\"\\\u{8}\n\u{c}\r"})), "{\n  \"k\" : \"\\u0001\\t\\\"\\\\\\b\\n\\f\\r\"\n}");
        assert_eq!(to_jackson_pretty(&json!([null, true, 1.5])), "[ null, true, 1.5 ]");
        assert_eq!(element_to_string(&json!([1, {"a": [true]}])), r#"[1,{"a":[true]}]"#);
    }

}
