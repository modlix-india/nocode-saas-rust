//! Response bodies written the way the Java service's `ObjectMapper` writes them.
//!
//! `AbstractBaseConfiguration` turns on `INDENT_OUTPUT` and `NON_EMPTY` inclusion, so every JSON
//! body is pretty printed by Jackson's `DefaultPrettyPrinter` (`"key" : value`, objects one entry
//! a line, arrays inline as `[ a, b ]`) and leaves out nulls, empty strings and empty arrays.
//! Bodies built here come out byte for byte the same, which keeps the parity checks simple and
//! leaves nothing for a client to notice.

use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use platform::http::spring_security_headers;
use serde_json::{Map, Value};

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
        other => out.push_str(&other.to_string()),
    }
}

fn indent(level: usize, out: &mut String) {
    for _ in 0..level {
        out.push_str("  ");
    }
}

/// `NON_EMPTY`: what Jackson leaves out of an object.
pub fn is_empty_value(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        _ => false,
    }
}

/// Builds an object in insertion order, leaving out what `NON_EMPTY` leaves out.
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

    /// Kept even when empty: values Jackson writes through a custom serializer (a `Sort`).
    pub fn put_always(mut self, key: &str, v: impl Into<Value>) -> Self {
        self.0.insert(key.to_string(), v.into());
        self
    }

    pub fn build(self) -> Value {
        Value::Object(self.0)
    }
}

fn with_headers(status: StatusCode, content_type: &'static str, body: String) -> Response {
    let mut h = HeaderMap::new();
    spring_security_headers(&mut h, true);
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    let mut resp = Response::new(Body::from(body));
    *resp.status_mut() = status;
    resp.headers_mut().extend(h);
    resp
}

/// `ResponseEntity.ok(object)` through `MappingJackson2HttpMessageConverter`.
pub fn json(v: &Value) -> Response {
    with_headers(StatusCode::OK, "application/json", pretty(v))
}

/// `ResponseEntity.ok(string)`: a `String` goes through `StringHttpMessageConverter`.
pub fn text(s: impl Into<String>) -> Response {
    with_headers(StatusCode::OK, "text/plain;charset=UTF-8", s.into())
}

/// A `@ResponseStatus(NO_CONTENT)` handler: no body, but the JSON type of the value it
/// returned.
pub fn no_content() -> Response {
    let mut h = HeaderMap::new();
    spring_security_headers(&mut h, true);
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::NO_CONTENT;
    resp.headers_mut().extend(h);
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn matches_jackson_default_pretty_printer() {
        let v = json!({
            "content": [{"name": "a", "size": 0}, {"name": "b"}],
            "pageable": {"pageNumber": 0, "sort": []},
            "empty": false
        });
        let expected = "{\n  \"content\" : [ {\n    \"name\" : \"a\",\n    \"size\" : 0\n  }, {\n    \"name\" : \"b\"\n  } ],\n  \"pageable\" : {\n    \"pageNumber\" : 0,\n    \"sort\" : [ ]\n  },\n  \"empty\" : false\n}";
        assert_eq!(pretty(&v), expected);
    }

    #[test]
    fn root_arrays_and_scalars() {
        assert_eq!(pretty(&json!([])), "[ ]");
        assert_eq!(pretty(&json!([{"id": 3}])), "[ {\n  \"id\" : 3\n} ]");
        assert_eq!(pretty(&json!(true)), "true");
        assert_eq!(pretty(&json!({})), "{ }");
        assert_eq!(pretty(&json!([1, 2])), "[ 1, 2 ]");
    }

    #[test]
    fn non_empty_inclusion() {
        let v = Obj::new()
            .put("a", Value::Null)
            .put("b", "")
            .put("c", json!([]))
            .put("d", 0)
            .put("e", false)
            .put_always("f", json!([]))
            .build();
        assert_eq!(v, json!({"d": 0, "e": false, "f": []}));
    }
}
