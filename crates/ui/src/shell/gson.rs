//! Gson's `JsonElement` tree as the URI path routes use it: `gson.fromJson(text, JsonObject.class)`
//! (a lenient reader), `JsonElement.toString()` (not HTML-safe), `addProperty`, `deepCopy`.
//!
//! Numbers keep the text they were read with (`LazilyParsedNumber`), so a body or a function
//! output is passed on digit for digit, the way the Java ui passes it.

use std::fmt::Write as _;

#[derive(Debug, Clone, PartialEq)]
pub enum G {
    Null,
    Bool(bool),
    /// The number as written.
    Num(String),
    Str(String),
    Arr(Vec<G>),
    /// Members in insertion order (`LinkedTreeMap`).
    Obj(Vec<(String, G)>),
}

impl G {
    /// `getClass().getName()` of the element.
    pub fn class_name(&self) -> &'static str {
        match self {
            G::Null => "com.google.gson.JsonNull",
            G::Bool(_) | G::Num(_) | G::Str(_) => "com.google.gson.JsonPrimitive",
            G::Arr(_) => "com.google.gson.JsonArray",
            G::Obj(_) => "com.google.gson.JsonObject",
        }
    }

    pub fn is_primitive(&self) -> bool {
        matches!(self, G::Bool(_) | G::Num(_) | G::Str(_))
    }

    pub fn get(&self, key: &str) -> Option<&G> {
        match self {
            G::Obj(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn has(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// `JsonObject.add` / `addProperty`: a key already there keeps its place.
    pub fn set(&mut self, key: &str, value: G) {
        if let G::Obj(m) = self {
            match m.iter_mut().find(|(k, _)| k == key) {
                Some(slot) => slot.1 = value,
                None => m.push((key.to_string(), value)),
            }
        }
    }

    /// `JsonPrimitive.getAsString()`.
    pub fn as_string(&self) -> Option<String> {
        match self {
            G::Str(s) => Some(s.clone()),
            G::Num(n) => Some(n.clone()),
            G::Bool(b) => Some(b.to_string()),
            _ => None,
        }
    }

    /// `JsonPrimitive.getAsDouble()`: `None` where Java throws `NumberFormatException`.
    pub fn as_double(&self) -> Option<f64> {
        let s = self.as_string()?;
        java_parse_double(&s)
    }
}

/// `Double.parseDouble`: surrounding whitespace allowed, a trailing `d`/`f` type suffix,
/// `Infinity` and `NaN`, hex floats aside.
pub fn java_parse_double(s: &str) -> Option<f64> {
    let t = s.trim_matches(|c: char| c <= ' ');
    let t = t.strip_suffix(['d', 'D', 'f', 'F']).unwrap_or(t);
    match t {
        "NaN" | "+NaN" | "-NaN" => return Some(f64::NAN),
        "Infinity" | "+Infinity" => return Some(f64::INFINITY),
        "-Infinity" => return Some(f64::NEG_INFINITY),
        _ => {}
    }
    if t.is_empty() || !t.chars().all(|c| c.is_ascii_digit() || matches!(c, '+' | '-' | '.' | 'e' | 'E')) {
        return None;
    }
    t.parse::<f64>().ok()
}

/// `JsonElement.toString()`.
pub fn to_string(v: &G) -> String {
    let mut out = String::new();
    write(v, &mut out);
    out
}

fn write(v: &G, out: &mut String) {
    match v {
        G::Null => out.push_str("null"),
        G::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        G::Num(n) => out.push_str(n),
        G::Str(s) => write_string(s, out),
        G::Arr(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(x, out);
            }
            out.push(']');
        }
        G::Obj(m) => {
            out.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(k, out);
                out.push(':');
                write(x, out);
            }
            out.push('}');
        }
    }
}

/// `JsonWriter.string` without HTML escaping.
fn write_string(s: &str, out: &mut String) {
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

/// `gson.fromJson(text, JsonElement.class)` with Gson's default (lenient) reader: one value,
/// and nothing after it but whitespace and comments.
pub fn parse(text: &str) -> Result<G, String> {
    let mut r = Reader { s: text.as_bytes(), text, i: 0 };
    r.skip_non_execute_prefix();
    let v = r.value()?;
    r.end()?;
    Ok(v)
}

/// `gson.fromJson(text, JsonObject.class)`: anything but an object (a `null` included) is
/// Gson's type mismatch.
pub fn parse_object(text: &str) -> Result<G, String> {
    let mut r = Reader { s: text.as_bytes(), text, i: 0 };
    r.skip_non_execute_prefix();
    let v = r.value()?;
    if !matches!(v, G::Obj(_)) {
        return Err(format!("Expected a com.google.gson.JsonObject but was {}; at path $", v.class_name()));
    }
    r.end()?;
    Ok(v)
}

/// `gson.fromJson(text, JsonArray.class)`.
pub fn parse_array(text: &str) -> Result<G, String> {
    let mut r = Reader { s: text.as_bytes(), text, i: 0 };
    r.skip_non_execute_prefix();
    let v = r.value()?;
    if !matches!(v, G::Arr(_)) {
        return Err(format!("Expected a com.google.gson.JsonArray but was {}; at path $", v.class_name()));
    }
    r.end()?;
    Ok(v)
}

struct Reader<'a> {
    s: &'a [u8],
    text: &'a str,
    i: usize,
}

impl Reader<'_> {
    fn err<T>(&self, what: &str) -> Result<T, String> {
        Err(format!("com.google.gson.stream.MalformedJsonException: {what} at character {}", self.i))
    }

    /// `assertFullConsumption`: the reader is back to its default strictness by then, so only
    /// whitespace may follow the value (a comment does not).
    fn end(&mut self) -> Result<(), String> {
        while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
        if self.i < self.s.len() {
            return self.err("Use JsonReader.setStrictness(Strictness.LENIENT) to accept malformed JSON");
        }
        Ok(())
    }

    fn skip_non_execute_prefix(&mut self) {
        if self.s.starts_with(b")]}'\n") {
            self.i = 5;
        }
    }

    /// Whitespace and the three comment forms the lenient reader skips.
    fn skip_ws(&mut self) -> Result<(), String> {
        while self.i < self.s.len() {
            match self.s[self.i] {
                b' ' | b'\t' | b'\n' | b'\r' => self.i += 1,
                b'#' => self.skip_line(),
                b'/' if self.s.get(self.i + 1) == Some(&b'/') => self.skip_line(),
                b'/' if self.s.get(self.i + 1) == Some(&b'*') => {
                    match self.text[self.i + 2..].find("*/") {
                        Some(end) => self.i += 2 + end + 2,
                        None => return self.err("Unterminated comment"),
                    }
                }
                _ => break,
            }
        }
        Ok(())
    }

    fn skip_line(&mut self) {
        while self.i < self.s.len() && self.s[self.i] != b'\n' && self.s[self.i] != b'\r' {
            self.i += 1;
        }
    }

    fn peek(&mut self) -> Result<Option<u8>, String> {
        self.skip_ws()?;
        Ok(self.s.get(self.i).copied())
    }

    fn value(&mut self) -> Result<G, String> {
        match self.peek()? {
            None => Err("java.io.EOFException: End of input at line 1 column 1 path $".into()),
            Some(b'{') => {
                self.i += 1;
                self.object()
            }
            Some(b'[') => {
                self.i += 1;
                self.array()
            }
            Some(q @ (b'"' | b'\'')) => {
                self.i += 1;
                Ok(G::Str(self.quoted(q)?))
            }
            Some(_) => self.literal(),
        }
    }

    fn object(&mut self) -> Result<G, String> {
        let mut m: Vec<(String, G)> = Vec::new();
        if self.peek()? == Some(b'}') {
            self.i += 1;
            return Ok(G::Obj(m));
        }
        loop {
            let name = match self.peek()? {
                Some(q @ (b'"' | b'\'')) => {
                    self.i += 1;
                    self.quoted(q)?
                }
                Some(b'}') => return self.err("Expected name"),
                Some(_) => self.unquoted()?,
                None => return self.err("End of input"),
            };
            match self.peek()? {
                Some(b':') => self.i += 1,
                Some(b'=') => {
                    self.i += 1;
                    if self.s.get(self.i) == Some(&b'>') {
                        self.i += 1;
                    }
                }
                _ => return self.err("Expected ':'"),
            }
            let v = self.value()?;
            match m.iter_mut().find(|(k, _)| *k == name) {
                Some(slot) => slot.1 = v,
                None => m.push((name, v)),
            }
            match self.peek()? {
                Some(b',' | b';') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(G::Obj(m));
                }
                _ => return self.err("Unterminated object"),
            }
        }
    }

    fn array(&mut self) -> Result<G, String> {
        let mut a = Vec::new();
        if self.peek()? == Some(b']') {
            self.i += 1;
            return Ok(G::Arr(a));
        }
        loop {
            match self.peek()? {
                // An omitted element is a null in a lenient array.
                Some(b',' | b';') => a.push(G::Null),
                Some(b']') => {
                    a.push(G::Null);
                    self.i += 1;
                    return Ok(G::Arr(a));
                }
                _ => a.push(self.value()?),
            }
            match self.peek()? {
                Some(b',' | b';') => {
                    self.i += 1;
                    if self.peek()? == Some(b']') {
                        // `[1,]` reads as [1, null].
                        continue;
                    }
                }
                Some(b']') => {
                    self.i += 1;
                    return Ok(G::Arr(a));
                }
                _ => return self.err("Unterminated array"),
            }
        }
    }

    fn quoted(&mut self, q: u8) -> Result<String, String> {
        let mut out = String::new();
        loop {
            let Some(rest) = self.text.get(self.i..) else { return self.err("Unterminated string") };
            let Some(c) = rest.chars().next() else { return self.err("Unterminated string") };
            self.i += c.len_utf8();
            if c as u32 == q as u32 {
                return Ok(out);
            }
            if c != '\\' {
                out.push(c);
                continue;
            }
            let Some(&e) = self.s.get(self.i) else { return self.err("Unterminated escape sequence") };
            self.i += 1;
            match e {
                b'u' => {
                    let hex = self.text.get(self.i..self.i + 4).ok_or_else(|| "Unterminated escape sequence".to_string())?;
                    let code = u32::from_str_radix(hex, 16).map_err(|_| format!("Malformed Unicode escape \\u{hex}"))?;
                    self.i += 4;
                    // A surrogate pair arrives as two escapes.
                    if (0xD800..0xDC00).contains(&code) && self.text.get(self.i..self.i + 2) == Some("\\u") {
                        if let Some(low) = self.text.get(self.i + 2..self.i + 6).and_then(|h| u32::from_str_radix(h, 16).ok()) {
                            if (0xDC00..0xE000).contains(&low) {
                                self.i += 6;
                                let cp = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
                                out.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
                                continue;
                            }
                        }
                    }
                    out.push(char::from_u32(code).unwrap_or('\u{FFFD}'));
                }
                b't' => out.push('\t'),
                b'b' => out.push('\u{08}'),
                b'n' => out.push('\n'),
                b'r' => out.push('\r'),
                b'f' => out.push('\u{0C}'),
                b'\n' => out.push('\n'),
                b'\'' | b'"' | b'\\' | b'/' => out.push(e as char),
                _ => return self.err("Invalid escape sequence"),
            }
        }
    }

    fn unquoted(&mut self) -> Result<String, String> {
        let start = self.i;
        while self.i < self.s.len() && !is_literal_end(self.s[self.i]) {
            self.i += 1;
        }
        if self.i == start {
            return self.err("Expected value");
        }
        Ok(self.text[start..self.i].to_string())
    }

    /// `true`/`false`/`null` (any case per letter), a number, or an unquoted string.
    fn literal(&mut self) -> Result<G, String> {
        let word = self.unquoted()?;
        for (kw, v) in [("true", G::Bool(true)), ("false", G::Bool(false)), ("null", G::Null)] {
            if word.eq_ignore_ascii_case(kw) {
                return Ok(v);
            }
        }
        if is_json_number(&word) {
            return Ok(G::Num(word));
        }
        Ok(G::Str(word))
    }
}

fn is_literal_end(b: u8) -> bool {
    matches!(b, b'/' | b'\\' | b';' | b'#' | b'=' | b'{' | b'}' | b'[' | b']' | b':' | b',' | b' ' | b'\t' | b'\x0C' | b'\r' | b'\n')
}

/// `JsonReader.peekNumber`: `-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?`.
fn is_json_number(s: &str) -> bool {
    let b = s.as_bytes();
    let mut i = 0;
    if b.first() == Some(&b'-') {
        i += 1;
    }
    let int_start = i;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    let int_len = i - int_start;
    if int_len == 0 || (int_len > 1 && b[int_start] == b'0') {
        return false;
    }
    if i < b.len() && b[i] == b'.' {
        i += 1;
        let f = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == f {
            return false;
        }
    }
    if i < b.len() && (b[i] == b'e' || b[i] == b'E') {
        i += 1;
        if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
            i += 1;
        }
        let e = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == e {
            return false;
        }
    }
    i == b.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_like_json_element_to_string() {
        for (input, out) in [
            (r#"{"a":1}"#, r#"{"a":1}"#),
            (r#"{ "a" : 1.50, "b": [1, 2e3, -0], "c": null }"#, r#"{"a":1.50,"b":[1,2e3,-0],"c":null}"#),
            (r#"{"s":"<a & b='c'>"}"#, r#"{"s":"<a & b='c'>"}"#),
            ("{\"s\":\"tab\\t nl\\n \\u0001 \\u2028\"}", "{\"s\":\"tab\\t nl\\n \\u0001 \\u2028\"}"),
            (r#"{"u":"\ud83d\ude00 \u00e9"}"#, "{\"u\":\"\u{1F600} \u{e9}\"}"),
            (r#"{"a":1,"a":2,"b":3}"#, r#"{"a":2,"b":3}"#),
            ("{a:1, 'b':'x' ; c=2, d=>tRuE}  ", r#"{"a":1,"b":"x","c":2,"d":true}"#),
            ("[,1]", "[null,1]"),
            ("[,]", "[null,null]"),
            (r#"{"a":NaN,"b":-Infinity,"c":00,"d":-,"e":Null,"f":nul,"g":9223372036854775808}"#, r#"{"a":"NaN","b":"-Infinity","c":"00","d":"-","e":null,"f":"nul","g":9223372036854775808}"#),
            (r#"{"a":'x\'y',"b":"x\'y"}"#, r#"{"a":"x'y","b":"x'y"}"#),
            ("# lead\n/* x */ [1,,2,]", "[1,null,2,null]"),
            ("[]", "[]"),
            ("{}", "{}"),
            ("[01, 1.]", r#"["01","1."]"#),
            (")]}'\n{\"x\":\"\\/\"}", r#"{"x":"/"}"#),
        ] {
            assert_eq!(to_string(&parse(input).unwrap()), out, "{input}");
        }
    }

    #[test]
    fn refuses_like_gson() {
        assert_eq!(
            parse_object("not json").unwrap_err(),
            "Expected a com.google.gson.JsonObject but was com.google.gson.JsonPrimitive; at path $"
        );
        assert_eq!(
            parse_object("[1]").unwrap_err(),
            "Expected a com.google.gson.JsonObject but was com.google.gson.JsonArray; at path $"
        );
        assert_eq!(
            parse_object("null").unwrap_err(),
            "Expected a com.google.gson.JsonObject but was com.google.gson.JsonNull; at path $"
        );
        assert_eq!(
            parse_array("{}").unwrap_err(),
            "Expected a com.google.gson.JsonArray but was com.google.gson.JsonObject; at path $"
        );
        assert!(parse_array("[1] x").is_err());
        assert!(parse("{} // a comment after the value").is_err());
        assert!(parse("not json").is_err());
        assert!(parse(r#"{"a":1,}"#).is_err());
        assert!(parse_object("{} x").is_err());
        for bad in ["", "{", "{\"a\"", "{\"a\":", "{\"a\":1", "[1", "[1 2]", "\"abc", "{\"a\" 1}", "{,}", "\"\\x\"", "\"\\u12", "/* x", "{}}", "\"\\uzzzz\""] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
        assert!(parse_array("[1]").is_ok());
        assert!(parse_object("{}").is_ok());
    }

    #[test]
    fn element_accessors() {
        let mut o = parse(r#"{"s":"403","n":403.0,"b":true,"x":[1]}"#).unwrap();
        assert_eq!(o.get("n").unwrap().as_double(), Some(403.0));
        assert_eq!(o.get("s").unwrap().as_double(), Some(403.0));
        assert_eq!(o.get("b").unwrap().as_double(), None);
        assert_eq!(o.get("x").unwrap().as_string(), None);
        assert!(o.get("s").unwrap().is_primitive() && !o.get("x").unwrap().is_primitive());
        assert!(o.has("b") && !o.has("q"));
        assert_eq!(o.get("x").unwrap().get("a"), None);
        o.set("s", G::Str("y".into()));
        o.set("new", G::Null);
        assert_eq!(to_string(&o), r#"{"s":"y","n":403.0,"b":true,"x":[1],"new":null}"#);
        let mut arr = G::Arr(vec![]);
        arr.set("k", G::Null);
        assert_eq!(to_string(&arr), "[]");
        assert_eq!(G::Null.class_name(), "com.google.gson.JsonNull");
        assert_eq!(java_parse_double(" 12d "), Some(12.0));
        assert!(java_parse_double("NaN").unwrap().is_nan());
        assert_eq!(java_parse_double("-Infinity"), Some(f64::NEG_INFINITY));
        assert_eq!(java_parse_double("Infinity"), Some(f64::INFINITY));
        assert_eq!(java_parse_double("1e400"), Some(f64::INFINITY));
        assert_eq!(java_parse_double("abc"), None);
        assert_eq!(java_parse_double(""), None);
    }
}
