//! The JDK behaviours this crate reproduces: string helpers whose Rust namesakes differ
//! (`trim`, `isBlank`, `toString` of a JSON-read value), `java.net.URI`, `InetAddress`, and
//! the `HashMap` iteration order Java maps are sent in.

pub mod inet;
pub mod json;
pub mod uri;

use std::fmt::Write as _;

use serde_json::{Map, Value};

/// `String.trim()`: strips every char at or below U+0020 from both ends (not Unicode
/// whitespace, which is what `str::trim` strips).
pub fn trim(s: &str) -> &str {
    s.trim_matches(|c: char| (c as u32) <= 0x20)
}

/// `Character.isWhitespace(codePoint)`.
pub fn is_whitespace(c: char) -> bool {
    match c {
        '\u{00A0}' | '\u{2007}' | '\u{202F}' => false,
        '\t' | '\n' | '\u{000B}' | '\u{000C}' | '\r' | '\u{001C}'..='\u{001F}' => true,
        ' ' | '\u{1680}' | '\u{2000}'..='\u{200A}' | '\u{2028}' | '\u{2029}' | '\u{205F}' | '\u{3000}' => true,
        _ => false,
    }
}

/// `String.isBlank()`.
pub fn is_blank(s: &str) -> bool {
    s.chars().all(is_whitespace)
}

/// `StringUtil.safeIsBlank(Object)`: null, or a value whose `toString()` is blank.
pub fn safe_is_blank(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => true,
        Some(v) => is_blank(&to_java_string(v)),
    }
}

/// `toString()` of a value as Spring Data reads it from Mongo into a `Map<String, Object>`:
/// numbers as their boxed type prints them, maps as `{k=v, ...}`, lists as `[a, b]`.
pub fn to_java_string(v: &Value) -> String {
    match v {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.to_string()
            } else if let Some(u) = n.as_u64() {
                u.to_string()
            } else {
                java_double(n.as_f64().unwrap_or(0.0))
            }
        }
        Value::String(s) => s.clone(),
        Value::Array(a) => format!("[{}]", a.iter().map(to_java_string).collect::<Vec<_>>().join(", ")),
        Value::Object(m) => format!(
            "{{{}}}",
            m.iter().map(|(k, v)| format!("{k}={}", to_java_string(v))).collect::<Vec<_>>().join(", ")
        ),
    }
}

/// `Double.toString(d)`: the shortest digits that round-trip (JDK 19+), plain between 1e-3 and
/// 1e7, computerized scientific notation outside.
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
    let mut out = String::new();
    if d < 0.0 {
        out.push('-');
    }
    let (digits, exp) = decimal_digits(&format!("{:e}", d.abs()));
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

fn decimal_digits(s: &str) -> (String, i32) {
    let (mantissa, e) = match s.split_once('e') {
        Some((m, e)) => (m, e.parse::<i32>().unwrap_or(0)),
        None => (s, 0),
    };
    let (int_part, frac_part) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let all = format!("{int_part}{frac_part}");
    let lead = all.chars().take_while(|c| *c == '0').count();
    let digits = all[lead..].trim_end_matches('0').to_string();
    let exp = int_part.len() as i32 - 1 - lead as i32 + e;
    if digits.is_empty() {
        ("0".into(), 0)
    } else {
        (digits, exp)
    }
}

/// The bucket order of a `java.util.HashMap` filled by successive puts in the map's current
/// order: the key order Java writes a `HashMap` in. Buckets of eight or more keys (which Java
/// turns into trees) are not modelled; real payloads never have them.
pub fn hash_map_order(map: Map<String, Value>) -> Map<String, Value> {
    let mut cap = 16usize;
    while map.len() > cap * 3 / 4 {
        cap *= 2;
    }
    let mut entries: Vec<(usize, String, Value)> = map
        .into_iter()
        .map(|(k, v)| {
            let h = platform::java::string_hash_code(&k) as u32;
            (((h ^ (h >> 16)) as usize) & (cap - 1), k, v)
        })
        .collect();
    entries.sort_by_key(|e| e.0);
    entries.into_iter().map(|(_, k, v)| (k, v)).collect()
}

/// [`hash_map_order`] applied to every map at every depth, as `JsonUtil.toMap` rebuilds them.
pub fn hash_map_order_deep(v: Value) -> Value {
    match v {
        Value::Object(m) => {
            let m: Map<String, Value> = m.into_iter().map(|(k, v)| (k, hash_map_order_deep(v))).collect();
            Value::Object(hash_map_order(m))
        }
        Value::Array(a) => Value::Array(a.into_iter().map(hash_map_order_deep).collect()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trims_like_java() {
        assert_eq!(trim("\u{00A0}x\t\n"), "\u{00A0}x");
        assert_eq!(trim(" \u{0001}x "), "x");
        assert!(is_blank(" \t\u{2003}"));
        assert!(!is_blank("\u{00A0}"));
    }

    #[test]
    fn doubles_like_java() {
        assert_eq!(java_double(1.0), "1.0");
        assert_eq!(java_double(30000.0), "30000.0");
        assert_eq!(java_double(1e7), "1.0E7");
        assert_eq!(java_double(0.001), "0.001");
        assert_eq!(java_double(0.0001), "1.0E-4");
        assert_eq!(java_double(123.45), "123.45");
    }

    #[test]
    fn hash_map_order_of_known_keys() {
        // From the Java ui, captured on the wire (see overridable::java_map).
        let m: Map<String, Value> = ["defaultPage", "notFoundPage", "links", "styles", "themes", "fontPacks"]
            .iter()
            .map(|k| (k.to_string(), Value::Null))
            .collect();
        let keys: Vec<String> = hash_map_order(m).keys().cloned().collect();
        assert_eq!(keys, ["fontPacks", "themes", "defaultPage", "links", "styles", "notFoundPage"]);
    }
}
