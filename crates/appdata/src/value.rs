//! The values a row is made of, as the Java engines hold them.
//!
//! The Java backends hand `Map<String, Object>` rows to Jackson, and what a client reads
//! depends on which Java type each value happened to be: a `Long` and a `BigDecimal` of the
//! same amount serialise differently (`10` and `10.5000`), a `Double` is written the way
//! `Double.toString` writes it (`1.0E10`), a `LocalDateTime` leaves the service as epoch
//! seconds through `CommonsSerializationModule`, and a `java.util.Date` as ISO text. A
//! `serde_json::Value` cannot carry those distinctions without the workspace-wide
//! `arbitrary_precision` feature, so the engines use this type and write JSON the way
//! Jackson does ([`Value::to_java_json`]).

use std::fmt;

use chrono::{NaiveDate, NaiveDateTime, NaiveTime, TimeZone, Utc};
use indexmap::IndexMap;
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};

/// A row, or any nested object: keys keep the order they were written in, as a Java
/// `LinkedHashMap` (and a BSON `Document`) does.
pub type Document = IndexMap<String, Value>;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    /// `Integer` or `Long`.
    Int(i64),
    /// `Double` (and `Float`, held at the precision its own `toString` shows).
    Double(f64),
    /// `BigDecimal` or `BigInteger`: exact, written as `BigDecimal.toString()` writes it.
    Decimal(Decimal),
    String(String),
    Array(Vec<Value>),
    Object(Document),
    /// A `LocalDateTime` a driver handed back without the codec turning it into text.
    /// Jackson writes it as epoch seconds (`CommonsSerializationModule`).
    LocalDateTime(NaiveDateTime),
    /// A `LocalDate`, written as the epoch seconds of its midnight.
    LocalDate(NaiveDate),
    /// A `LocalTime`, written as ISO text by the JSR-310 module.
    LocalTime(NaiveTime),
    /// A `java.util.Date` (a BSON date the codec did not reach), in epoch milliseconds.
    /// Spring Boot's Jackson writes it as `yyyy-MM-dd'T'HH:mm:ss.SSS+00:00`.
    Date(i64),
}

impl Value {
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&Document> {
        match self {
            Value::Object(o) => Some(o),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&Vec<Value>> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn is_number(&self) -> bool {
        matches!(self, Value::Int(_) | Value::Double(_) | Value::Decimal(_))
    }

    /// `String.valueOf(object)` for the values a filter or an id can hold, which is what
    /// the Java code does with them before building a list or an ObjectId.
    pub fn java_string(&self) -> String {
        match self {
            Value::Null => "null".into(),
            Value::Bool(b) => b.to_string(),
            Value::Int(i) => i.to_string(),
            Value::Double(d) => java_double(*d),
            Value::Decimal(d) => d.to_java_string(),
            Value::String(s) => s.clone(),
            Value::Array(a) => {
                let parts: Vec<String> = a.iter().map(Value::java_string).collect();
                format!("[{}]", parts.join(", "))
            }
            Value::Object(o) => {
                let parts: Vec<String> =
                    o.iter().map(|(k, v)| format!("{k}={}", v.java_string())).collect();
                format!("{{{}}}", parts.join(", "))
            }
            Value::LocalDateTime(dt) => dt.format("%Y-%m-%dT%H:%M:%S%.f").to_string(),
            Value::LocalDate(d) => d.format("%Y-%m-%d").to_string(),
            Value::LocalTime(t) => t.format("%H:%M:%S%.f").to_string(),
            Value::Date(ms) => ms.to_string(),
        }
    }

    /// The JSON Jackson writes for this value, compact, keys in order.
    pub fn to_java_json(&self) -> String {
        let mut out = String::new();
        self.write_java_json(&mut out);
        out
    }

    pub fn write_java_json(&self, out: &mut String) {
        match self {
            Value::Null => out.push_str("null"),
            Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Value::Int(i) => out.push_str(&i.to_string()),
            Value::Double(d) => {
                if d.is_finite() {
                    out.push_str(&java_double(*d))
                } else {
                    // Jackson writes the non-finite doubles as quoted tokens when
                    // QUOTE_NON_NUMERIC_NUMBERS is on, which is its default.
                    write_json_string(out, &java_double(*d))
                }
            }
            Value::Decimal(d) => out.push_str(&d.to_java_string()),
            Value::String(s) => write_json_string(out, s),
            Value::Array(a) => {
                out.push('[');
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    v.write_java_json(out);
                }
                out.push(']');
            }
            Value::Object(o) => write_object(out, o),
            Value::LocalDateTime(dt) => out.push_str(&dt.and_utc().timestamp().to_string()),
            Value::LocalDate(d) => out.push_str(
                &d.and_hms_opt(0, 0, 0).map(|x| x.and_utc().timestamp()).unwrap_or(0).to_string(),
            ),
            Value::LocalTime(t) => write_json_string(out, &iso_local_time(*t)),
            Value::Date(ms) => write_json_string(out, &java_util_date_iso(*ms)),
        }
    }

    /// From a parsed `serde_json::Value`, with Jackson's number typing: an integer that fits
    /// a long is a Long, a larger one a BigInteger, anything with a fraction a Double.
    pub fn from_json(v: &serde_json::Value) -> Value {
        match v {
            serde_json::Value::Null => Value::Null,
            serde_json::Value::Bool(b) => Value::Bool(*b),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Value::Int(i)
                } else if let Some(u) = n.as_u64() {
                    Value::Decimal(Decimal::from_u128(u as u128))
                } else {
                    Value::Double(n.as_f64().unwrap_or(0.0))
                }
            }
            serde_json::Value::String(s) => Value::String(s.clone()),
            serde_json::Value::Array(a) => Value::Array(a.iter().map(Value::from_json).collect()),
            serde_json::Value::Object(o) => {
                Value::Object(o.iter().map(|(k, v)| (k.clone(), Value::from_json(v))).collect())
            }
        }
    }

    /// Parse JSON text into a value, keeping key order (Jackson reads into a LinkedHashMap).
    pub fn parse_json(text: &str) -> Result<Value, serde_json::Error> {
        serde_json::from_str(text)
    }

    /// The same value as plain `serde_json`, for callers that want one. Decimals and doubles
    /// go through their Java text, so nothing is rounded twice.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::from_str(&self.to_java_json()).unwrap_or(serde_json::Value::Null)
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::String(s.to_string())
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::String(s)
    }
}

impl From<i64> for Value {
    fn from(i: i64) -> Self {
        Value::Int(i)
    }
}

impl From<i32> for Value {
    fn from(i: i32) -> Self {
        Value::Int(i as i64)
    }
}

impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}

impl From<f64> for Value {
    fn from(d: f64) -> Self {
        Value::Double(d)
    }
}

impl From<Document> for Value {
    fn from(d: Document) -> Self {
        Value::Object(d)
    }
}

impl From<Vec<Value>> for Value {
    fn from(a: Vec<Value>) -> Self {
        Value::Array(a)
    }
}

pub fn write_object(out: &mut String, o: &Document) {
    out.push('{');
    for (i, (k, v)) in o.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        write_json_string(out, k);
        out.push(':');
        v.write_java_json(out);
    }
    out.push('}');
}

/// A document as Jackson writes it.
/// What the services' ObjectMapper leaves of a bean's properties: its default inclusion is
/// `NON_EMPTY`, so a null, an empty string, an empty list and an empty map are not written.
pub fn non_empty(d: Document) -> Document {
    d.into_iter()
        .filter(|(_, v)| match v {
            Value::Null => false,
            Value::String(s) => !s.is_empty(),
            Value::Array(a) => !a.is_empty(),
            Value::Object(o) => !o.is_empty(),
            _ => true,
        })
        .collect()
}

pub fn document_to_java_json(d: &Document) -> String {
    let mut out = String::new();
    write_object(&mut out, d);
    out
}

/// JSON string escaping as Jackson does it: the short escapes for the usual five, `\u00XX`
/// for every other control character, everything else (including non-ASCII) as it is.
pub fn write_json_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// `DateTimeFormatter.ISO_LOCAL_TIME`: seconds always, the fraction only when it is not
/// zero, and then without trailing zeros.
pub fn iso_local_time(t: NaiveTime) -> String {
    use chrono::Timelike;
    let mut s = format!("{:02}:{:02}:{:02}", t.hour(), t.minute(), t.second());
    let nanos = t.nanosecond() % 1_000_000_000;
    if nanos != 0 {
        let frac = format!("{nanos:09}");
        s.push('.');
        s.push_str(frac.trim_end_matches('0'));
    }
    s
}

/// `DateTimeFormatter.ISO_LOCAL_DATE_TIME`.
pub fn iso_local_date_time(dt: NaiveDateTime) -> String {
    format!("{}T{}", dt.date().format("%Y-%m-%d"), iso_local_time(dt.time()))
}

/// `DateTimeFormatter.ISO_LOCAL_DATE`.
pub fn iso_local_date(d: NaiveDate) -> String {
    d.format("%Y-%m-%d").to_string()
}

/// Jackson's `StdDateFormat` for a `java.util.Date` in UTC.
pub fn java_util_date_iso(ms: i64) -> String {
    match Utc.timestamp_millis_opt(ms) {
        chrono::LocalResult::Single(dt) => dt.format("%Y-%m-%dT%H:%M:%S%.3f+00:00").to_string(),
        _ => ms.to_string(),
    }
}

// ------------------------------------------------------------------ doubles

/// The shortest decimal digits that read back as `d`, and the exponent of the first one:
/// `d = 0.d1d2d3... x 10^point`.
fn shortest_digits(d: f64) -> (String, i32) {
    let mut buf = ryu::Buffer::new();
    let s = buf.format_finite(d.abs());
    let (mantissa, exp) = match s.find(['e', 'E']) {
        Some(i) => (&s[..i], s[i + 1..].parse::<i32>().unwrap_or(0)),
        None => (s, 0),
    };
    let (int_part, frac_part) = match mantissa.find('.') {
        Some(i) => (&mantissa[..i], &mantissa[i + 1..]),
        None => (mantissa, ""),
    };
    let mut digits = format!("{int_part}{frac_part}");
    let mut point = int_part.len() as i32 + exp;
    let lead = digits.len() - digits.trim_start_matches('0').len();
    digits.drain(..lead);
    point -= lead as i32;
    let trimmed = digits.trim_end_matches('0').len();
    digits.truncate(trimmed);
    if digits.is_empty() {
        return ("0".into(), 1);
    }
    (digits, point)
}

/// `Double.toString(d)`: plain between 10^-3 and 10^7, computerized scientific outside it,
/// always with at least one digit after the point.
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
    let sign = if d < 0.0 { "-" } else { "" };
    let (digits, point) = shortest_digits(d);
    let abs = d.abs();
    if (1e-3..1e7).contains(&abs) {
        let s = if point <= 0 {
            format!("0.{}{}", "0".repeat((-point) as usize), digits)
        } else if point as usize >= digits.len() {
            format!("{}{}.0", digits, "0".repeat(point as usize - digits.len()))
        } else {
            format!("{}.{}", &digits[..point as usize], &digits[point as usize..])
        };
        format!("{sign}{s}")
    } else {
        let exp = point - 1;
        let rest = if digits.len() > 1 { &digits[1..] } else { "0" };
        format!("{sign}{}.{}E{}", &digits[..1], rest, exp)
    }
}

/// `Float.toString(f)`, then read back as a double: what a FLOAT column becomes once it is
/// a JSON number, without the binary noise of widening the float itself.
pub fn float_as_double(f: f32) -> f64 {
    if !f.is_finite() {
        return f as f64;
    }
    let mut buf = ryu::Buffer::new();
    buf.format_finite(f).parse::<f64>().unwrap_or(f as f64)
}

// ------------------------------------------------------------------ decimals

/// A `java.math.BigDecimal`: unscaled digits, a sign and a scale.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Decimal {
    negative: bool,
    /// The unscaled value's digits, without leading zeros ("0" for zero).
    digits: String,
    scale: i32,
}

impl Decimal {
    pub fn zero() -> Decimal {
        Decimal { negative: false, digits: "0".into(), scale: 0 }
    }

    pub fn from_i64(i: i64) -> Decimal {
        Decimal {
            negative: i < 0,
            digits: i.unsigned_abs().to_string(),
            scale: 0,
        }
    }

    pub fn from_u128(u: u128) -> Decimal {
        Decimal { negative: false, digits: u.to_string(), scale: 0 }
    }

    /// `new BigDecimal(String)`: an optional sign, digits with an optional point, an
    /// optional exponent. Leading and trailing whitespace is NOT accepted, as in Java.
    pub fn parse(s: &str) -> Option<Decimal> {
        let bytes = s.as_bytes();
        if bytes.is_empty() {
            return None;
        }
        let mut i = 0;
        let mut negative = false;
        if bytes[0] == b'+' || bytes[0] == b'-' {
            negative = bytes[0] == b'-';
            i = 1;
        }
        let mut digits = String::new();
        let mut scale: i64 = 0;
        let mut seen_point = false;
        let mut seen_digit = false;
        while i < bytes.len() {
            let c = bytes[i];
            if c.is_ascii_digit() {
                digits.push(c as char);
                seen_digit = true;
                if seen_point {
                    scale += 1;
                }
            } else if c == b'.' && !seen_point {
                seen_point = true;
            } else {
                break;
            }
            i += 1;
        }
        if !seen_digit {
            return None;
        }
        if i < bytes.len() {
            if bytes[i] != b'e' && bytes[i] != b'E' {
                return None;
            }
            let exp: i64 = s[i + 1..].parse().ok()?;
            if s[i + 1..].starts_with('+') && s[i + 2..].starts_with(['+', '-']) {
                return None;
            }
            scale -= exp;
        }
        if scale > i32::MAX as i64 || scale < i32::MIN as i64 {
            return None;
        }
        let trimmed = digits.trim_start_matches('0');
        let digits = if trimmed.is_empty() { "0".to_string() } else { trimmed.to_string() };
        let negative = negative && digits != "0";
        Some(Decimal { negative, digits, scale: scale as i32 })
    }

    pub fn is_zero(&self) -> bool {
        self.digits == "0"
    }

    pub fn is_negative(&self) -> bool {
        self.negative
    }

    pub fn scale(&self) -> i32 {
        self.scale
    }

    /// The number of digits in the unscaled value, as `BigDecimal.precision()`.
    pub fn precision(&self) -> usize {
        self.digits.len()
    }

    pub fn unscaled_digits(&self) -> &str {
        &self.digits
    }

    /// `BigDecimal.stripTrailingZeros()`; zero becomes plain `0`.
    pub fn strip_trailing_zeros(&self) -> Decimal {
        if self.is_zero() {
            return Decimal::zero();
        }
        let trimmed = self.digits.trim_end_matches('0');
        let removed = (self.digits.len() - trimmed.len()) as i32;
        Decimal {
            negative: self.negative,
            digits: trimmed.to_string(),
            scale: self.scale - removed,
        }
    }

    /// `BigDecimal.toString()`: plain unless the exponent says otherwise.
    pub fn to_java_string(&self) -> String {
        let sign = if self.negative { "-" } else { "" };
        let n = self.digits.len() as i64;
        let adjusted = -(self.scale as i64) + (n - 1);
        if self.scale >= 0 && adjusted >= -6 {
            if self.scale == 0 {
                return format!("{sign}{}", self.digits);
            }
            let scale = self.scale as i64;
            let body = if n > scale {
                let split = (n - scale) as usize;
                format!("{}.{}", &self.digits[..split], &self.digits[split..])
            } else {
                format!("0.{}{}", "0".repeat((scale - n) as usize), self.digits)
            };
            return format!("{sign}{body}");
        }
        let mut s = String::from(sign);
        s.push_str(&self.digits[..1]);
        if n > 1 {
            s.push('.');
            s.push_str(&self.digits[1..]);
        }
        s.push('E');
        if adjusted > 0 {
            s.push('+');
        }
        s.push_str(&adjusted.to_string());
        s
    }

    /// `BigDecimal.toPlainString()`.
    pub fn to_plain_string(&self) -> String {
        let sign = if self.negative { "-" } else { "" };
        if self.scale == 0 {
            return format!("{sign}{}", self.digits);
        }
        if self.scale < 0 {
            if self.is_zero() {
                return "0".into();
            }
            return format!("{sign}{}{}", self.digits, "0".repeat((-self.scale) as usize));
        }
        let n = self.digits.len();
        let scale = self.scale as usize;
        if n > scale {
            format!("{sign}{}.{}", &self.digits[..n - scale], &self.digits[n - scale..])
        } else {
            format!("{sign}0.{}{}", "0".repeat(scale - n), self.digits)
        }
    }

    /// The integer part's digits (truncated towards zero), as a decimal string.
    fn integer_digits(&self) -> String {
        if self.scale <= 0 {
            if self.is_zero() {
                return "0".into();
            }
            return format!("{}{}", self.digits, "0".repeat((-self.scale) as usize));
        }
        let n = self.digits.len();
        let scale = self.scale as usize;
        if n > scale {
            self.digits[..n - scale].to_string()
        } else {
            "0".into()
        }
    }

    /// `BigDecimal.longValue()`: the integer part, keeping only its low 64 bits.
    pub fn long_value(&self) -> i64 {
        let mut acc: u64 = 0;
        for c in self.integer_digits().bytes() {
            acc = acc.wrapping_mul(10).wrapping_add((c - b'0') as u64);
        }
        let v = acc as i64;
        if self.negative {
            v.wrapping_neg()
        } else {
            v
        }
    }

    /// `BigDecimal.intValue()`: the low 32 bits of the integer part.
    pub fn int_value(&self) -> i32 {
        self.long_value() as i32
    }

    /// `BigDecimal.longValueExact()`: None when there is a fraction or it does not fit.
    pub fn long_value_exact(&self) -> Option<i64> {
        let stripped = self.strip_trailing_zeros();
        if stripped.scale > 0 {
            return None;
        }
        let digits = stripped.integer_digits();
        if digits.len() > 19 {
            return None;
        }
        let magnitude: i128 = digits.parse().ok()?;
        let v = if self.negative { -magnitude } else { magnitude };
        i64::try_from(v).ok()
    }

    /// `BigDecimal.doubleValue()`, correctly rounded.
    pub fn double_value(&self) -> f64 {
        format!("{}{}E{}", if self.negative { "-" } else { "" }, self.digits, -(self.scale as i64))
            .parse()
            .unwrap_or(0.0)
    }

    /// The sign of the value: -1, 0 or 1, as `signum()`.
    pub fn signum(&self) -> i32 {
        if self.is_zero() {
            0
        } else if self.negative {
            -1
        } else {
            1
        }
    }

    pub fn from_parts(negative: bool, digits: &str, scale: i32) -> Decimal {
        let trimmed = digits.trim_start_matches('0');
        let digits = if trimmed.is_empty() { "0" } else { trimmed };
        Decimal { negative: negative && digits != "0", digits: digits.to_string(), scale }
    }
}

impl fmt::Display for Decimal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_java_string())
    }
}

// ------------------------------------------------------------------ serde

impl Serialize for Value {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Value::Null => serializer.serialize_unit(),
            Value::Bool(b) => serializer.serialize_bool(*b),
            Value::Int(i) => serializer.serialize_i64(*i),
            Value::String(s) => serializer.serialize_str(s),
            Value::Array(a) => {
                let mut seq = serializer.serialize_seq(Some(a.len()))?;
                for v in a {
                    seq.serialize_element(v)?;
                }
                seq.end()
            }
            Value::Object(o) => {
                let mut map = serializer.serialize_map(Some(o.len()))?;
                for (k, v) in o {
                    map.serialize_entry(k, v)?;
                }
                map.end()
            }
            // Numbers whose text Jackson decides, and the date types: written through
            // their exact Java JSON so serde_json does not re-render them.
            other => {
                let raw = serde_json::value::RawValue::from_string(other.to_java_json())
                    .map_err(serde::ser::Error::custom)?;
                raw.serialize(serializer)
            }
        }
    }
}

impl<'de> Deserialize<'de> for Value {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(ValueVisitor)
    }
}

struct ValueVisitor;

impl<'de> Visitor<'de> for ValueVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Int(v))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(match i64::try_from(v) {
            Ok(i) => Value::Int(i),
            Err(_) => Value::Decimal(Decimal::from_u128(v as u128)),
        })
    }

    fn visit_f64<E>(self, v: f64) -> Result<Value, E> {
        Ok(Value::Double(v))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_string()))
    }

    fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        Deserialize::deserialize(d)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut out = Vec::new();
        while let Some(v) = seq.next_element()? {
            out.push(v);
        }
        Ok(Value::Array(out))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut out = Document::new();
        while let Some((k, v)) = map.next_entry::<String, Value>()? {
            out.insert(k, v);
        }
        Ok(Value::Object(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doubles_print_as_java_does() {
        assert_eq!(java_double(1.0), "1.0");
        assert_eq!(java_double(100.0), "100.0");
        assert_eq!(java_double(1.5), "1.5");
        assert_eq!(java_double(0.001), "0.001");
        assert_eq!(java_double(0.0001), "1.0E-4");
        assert_eq!(java_double(1e7), "1.0E7");
        assert_eq!(java_double(1234567.0), "1234567.0");
        assert_eq!(java_double(1.0e10), "1.0E10");
        assert_eq!(java_double(-2.5e-5), "-2.5E-5");
        assert_eq!(java_double(0.1 + 0.2), "0.30000000000000004");
        assert_eq!(java_double(123456789.123), "1.23456789123E8");
    }

    #[test]
    fn decimals_print_as_big_decimal_does() {
        let d = |s: &str| Decimal::parse(s).unwrap();
        assert_eq!(d("10.5000").to_java_string(), "10.5000");
        assert_eq!(d("0.0000001234").to_java_string(), "1.234E-7");
        assert_eq!(d("0.000001234").to_java_string(), "0.000001234");
        assert_eq!(d("1E+3").to_java_string(), "1E+3");
        assert_eq!(d("1E+3").to_plain_string(), "1000");
        assert_eq!(d("-12.30").to_plain_string(), "-12.30");
        assert_eq!(d("0.00").to_plain_string(), "0.00");
        assert_eq!(d("3.0").strip_trailing_zeros().scale(), 0);
        assert_eq!(d("9223372036854775807").long_value_exact(), Some(i64::MAX));
        assert_eq!(d("9223372036854775808").long_value_exact(), None);
        assert_eq!(d("1.5").long_value_exact(), None);
        assert_eq!(d("-7.9").long_value(), -7);
        assert_eq!(d("18446744073709551617").long_value(), 1);
        assert!(Decimal::parse(" 1").is_none());
        assert!(Decimal::parse("abc").is_none());
        assert_eq!(d(".5").to_java_string(), "0.5");
    }

    #[test]
    fn json_keeps_order_and_java_number_text() {
        let v = Value::parse_json(r#"{"b":1,"a":2.0,"c":[1e10,"x"]}"#).unwrap();
        assert_eq!(v.to_java_json(), r#"{"b":1,"a":2.0,"c":[1.0E10,"x"]}"#);
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(json, r#"{"b":1,"a":2.0,"c":[1.0E10,"x"]}"#);
    }

    #[test]
    fn local_times_print_iso() {
        let t = NaiveTime::from_hms_milli_opt(10, 0, 0, 500).unwrap();
        assert_eq!(iso_local_time(t), "10:00:00.5");
        let t = NaiveTime::from_hms_opt(10, 0, 0).unwrap();
        assert_eq!(iso_local_time(t), "10:00:00");
    }
}
