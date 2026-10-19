//! YAML for the config server: yaml-rust2's events, typed the way each reader of oci-config
//! types them.
//!
//! - [`Typing::Snake`]: SnakeYAML 2.3 under Spring Boot (YAML 1.1 implicit types without
//!   timestamps, which Spring's loader removes), for the Spring compat endpoint. Integers in
//!   octal, hex, binary and base 60, floats with or without a dot, `.inf` and `.nan`.
//! - [`Typing::Py`]: `MiniYaml.resolve_plain` of `tools/render_config.py` (PyYAML's YAML 1.1
//!   resolvers), for the unit renderer, so its output stays byte-identical to the script's: a
//!   float needs a dot and a signed exponent (`1e5` stays text), and keys are typed even when
//!   quoted, as the script's reader does.
//!
//! Both keep the order of keys, take anchors, aliases and merge keys (`<<`) the way SnakeYAML
//! does, and drop empty documents. Flattening follows Spring's `YamlProcessor` (nulls and empty
//! lists become `""`, a non-text key becomes `[key]`) or the script's `flatten`.

use std::collections::HashMap;
use std::sync::LazyLock;

use anyhow::{anyhow, bail, Result};
use indexmap::IndexMap;
use regex::Regex;
use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser, Tag};
use yaml_rust2::scanner::{Marker, TScalarStyle};

/// Whose typing rules apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Typing {
    Snake,
    Py,
}

/// A typed YAML value. Mappings keep their order and their typed keys.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i128),
    Float(f64),
    Str(String),
    Seq(Vec<Value>),
    Map(Vec<(Value, Value)>),
}

impl Value {
    /// The value under a text key of a mapping.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Map(entries) => entries.iter().find(|(k, _)| matches!(k, Value::Str(s) if s == key)).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }
}

/// A parsed node before typing: scalars keep their text, style and tag.
#[derive(Debug, Clone)]
enum Node {
    Scalar { text: String, style: TScalarStyle, tag: Option<Tag> },
    Seq(Vec<Node>),
    Map(Vec<(Node, Node)>),
}

enum Open {
    Seq(Vec<Node>, usize),
    Map(Vec<(Node, Node)>, Option<Node>, usize),
}

#[derive(Default)]
struct Builder {
    stack: Vec<Open>,
    docs: Vec<Node>,
    anchors: HashMap<usize, Node>,
    error: Option<String>,
}

impl Builder {
    fn add(&mut self, node: Node, anchor: usize) {
        if anchor > 0 {
            self.anchors.insert(anchor, node.clone());
        }
        match self.stack.last_mut() {
            None => self.docs.push(node),
            Some(Open::Seq(items, _)) => items.push(node),
            Some(Open::Map(entries, key, _)) => match key.take() {
                None => *key = Some(node),
                Some(k) => entries.push((k, node)),
            },
        }
    }
}

impl MarkedEventReceiver for Builder {
    fn on_event(&mut self, ev: Event, mark: Marker) {
        if self.error.is_some() {
            return;
        }
        match ev {
            Event::Scalar(text, style, anchor, tag) => self.add(Node::Scalar { text, style, tag }, anchor),
            Event::SequenceStart(anchor, _) => self.stack.push(Open::Seq(Vec::new(), anchor)),
            Event::MappingStart(anchor, _) => self.stack.push(Open::Map(Vec::new(), None, anchor)),
            Event::SequenceEnd | Event::MappingEnd => match self.stack.pop() {
                Some(Open::Seq(items, anchor)) => self.add(Node::Seq(items), anchor),
                Some(Open::Map(entries, _, anchor)) => self.add(Node::Map(entries), anchor),
                None => self.error = Some(format!("unbalanced collection at line {}", mark.line())),
            },
            Event::Alias(id) => match self.anchors.get(&id).cloned() {
                Some(node) => self.add(node, 0),
                None => self.error = Some(format!("an alias to an unknown anchor at line {}", mark.line())),
            },
            _ => {}
        }
    }
}

/// The documents of a YAML text, typed. Empty documents (and ones that are only a null) are
/// left out, as both Spring and the script leave them out.
pub fn documents(text: &str, typing: Typing) -> Result<Vec<Value>> {
    let mut b = Builder::default();
    Parser::new_from_str(text).load(&mut b, true).map_err(|e| anyhow!("YAML: {e}"))?;
    if let Some(e) = b.error {
        bail!("YAML: {e}");
    }
    let mut out = Vec::new();
    for doc in &b.docs {
        let v = typed(doc, typing)?;
        if v != Value::Null {
            out.push(v);
        }
    }
    Ok(out)
}

fn is_merge_key(node: &Node) -> bool {
    matches!(node, Node::Scalar { text, style: TScalarStyle::Plain, tag: None } if text == "<<")
}

/// An identity for a typed key, to find a key again (floats are not `Hash`).
fn key_id(v: &Value) -> String {
    format!("{v:?}")
}

fn typed(node: &Node, typing: Typing) -> Result<Value> {
    match node {
        Node::Scalar { text, style, tag } => scalar(text, *style, tag.as_ref(), typing),
        Node::Seq(items) => Ok(Value::Seq(items.iter().map(|n| typed(n, typing)).collect::<Result<_>>()?)),
        Node::Map(entries) => {
            let mut out: Vec<(Value, Value)> = Vec::new();
            let mut index: HashMap<String, usize> = HashMap::new();
            merge(entries, true, typing, &mut out, &mut index)?;
            Ok(Value::Map(out))
        }
    }
}

/// SnakeYAML's `mergeNode`: the mapping's own keys in order, a `<<` merging the keys of its
/// mapping (or of each mapping of its sequence) at its place unless they are already there,
/// and an own key replacing a merged one in place. Two own keys alike are an error under
/// Spring (duplicate keys are refused); the script keeps the last.
fn merge(
    entries: &[(Node, Node)],
    preferred: bool,
    typing: Typing,
    out: &mut Vec<(Value, Value)>,
    index: &mut HashMap<String, usize>,
) -> Result<()> {
    let mut own: HashMap<String, ()> = HashMap::new();
    for (k, v) in entries {
        if is_merge_key(k) {
            match v {
                Node::Map(inner) => merge(inner, false, typing, out, index)?,
                Node::Seq(items) => {
                    for item in items {
                        let Node::Map(inner) = item else { bail!("YAML: a merge key (<<) takes mappings only") };
                        merge(inner, false, typing, out, index)?;
                    }
                }
                Node::Scalar { .. } => bail!("YAML: a merge key (<<) takes mappings only"),
            }
            continue;
        }
        let key = typed_key(k, typing)?;
        let id = key_id(&key);
        if preferred && own.insert(id.clone(), ()).is_some() && typing == Typing::Snake {
            bail!("YAML: duplicate key {}", key_text(&key));
        }
        let value = typed(v, typing)?;
        match index.get(&id) {
            Some(&i) if preferred => out[i].1 = value,
            Some(_) => {}
            None => {
                index.insert(id, out.len());
                out.push((key, value));
            }
        }
    }
    Ok(())
}

/// A key: typed like a value under Spring; under the script, typed even when quoted (its reader
/// unquotes a key before typing it).
fn typed_key(node: &Node, typing: Typing) -> Result<Value> {
    match (node, typing) {
        (Node::Scalar { text, tag: None, .. }, Typing::Py) => Ok(resolve_py(text)),
        (Node::Scalar { .. }, _) => typed(node, typing),
        _ => bail!("YAML: a key must be a scalar"),
    }
}

fn key_text(v: &Value) -> String {
    match v {
        Value::Str(s) => s.clone(),
        other => format!("{other:?}"),
    }
}

fn scalar(text: &str, style: TScalarStyle, tag: Option<&Tag>, typing: Typing) -> Result<Value> {
    if let Some(tag) = tag {
        let core = tag.handle == "!!" || tag.handle == "tag:yaml.org,2002:";
        return match (core, tag.suffix.as_str()) {
            (true, "str") => Ok(Value::Str(text.to_string())),
            (true, "null") => Ok(Value::Null),
            (true, "bool" | "int" | "float") => {
                let v = resolve(text, typing);
                let ok = matches!(
                    (tag.suffix.as_str(), &v),
                    ("bool", Value::Bool(_)) | ("int", Value::Int(_)) | ("float", Value::Float(_) | Value::Int(_))
                );
                match (ok, v) {
                    (true, Value::Int(i)) if tag.suffix == "float" => Ok(Value::Float(i as f64)),
                    (true, v) => Ok(v),
                    // The value itself stays out of the message: it may be a secret.
                    (false, _) => bail!("YAML: a value tagged !!{} does not read as one", tag.suffix),
                }
            }
            _ => bail!("YAML: the tag {}{} is not supported", tag.handle, tag.suffix),
        };
    }
    if style == TScalarStyle::Plain {
        Ok(resolve(text, typing))
    } else {
        Ok(Value::Str(text.to_string()))
    }
}

/// A plain scalar typed under `typing`.
pub fn resolve(s: &str, typing: Typing) -> Value {
    match typing {
        Typing::Snake => resolve_snake(s),
        Typing::Py => resolve_py(s),
    }
}

static SNAKE_BOOL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:yes|Yes|YES|no|No|NO|true|True|TRUE|false|False|FALSE|on|On|ON|off|Off|OFF)$").unwrap());
static SNAKE_INT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:[-+]?0b_*[0-1][0-1_]*|[-+]?0_*[0-7][0-7_]*|[-+]?(?:0|[1-9][0-9_]*)|[-+]?0x_*[0-9a-fA-F][0-9a-fA-F_]*|[-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+)$",
    )
    .unwrap()
});
static SNAKE_FLOAT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^([-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+]?[0-9]+)?|[-+]?(?:[0-9][0-9_]*)(?:[eE][-+]?[0-9]+)|[-+]?\.[0-9_]+(?:[eE][-+]?[0-9]+)?|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$",
    )
    .unwrap()
});
static SNAKE_NULL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(?:~|null|Null|NULL| )$").unwrap());

/// SnakeYAML's implicit resolvers in their order for the first character (BOOL and NULL only
/// for 10 characters at most), then its constructors.
pub fn resolve_snake(s: &str) -> Value {
    let first = s.chars().next();
    let has = |set: &str| first.is_some_and(|c| set.contains(c));
    if s.is_empty() || (has("~nN") && s.len() <= 10 && SNAKE_NULL.is_match(s)) {
        return Value::Null;
    }
    if has("yYnNtTfFoO") && s.len() <= 10 && SNAKE_BOOL.is_match(s) {
        return Value::Bool(matches!(s.to_ascii_lowercase().as_str(), "yes" | "true" | "on"));
    }
    if has("-+0123456789") && SNAKE_INT.is_match(s) {
        if let Some(i) = snake_int(s) {
            return Value::Int(i);
        }
    }
    if has("-+0123456789.") && SNAKE_FLOAT.is_match(s) {
        if let Some(f) = snake_float(s) {
            return Value::Float(f);
        }
    }
    Value::Str(s.to_string())
}

fn sign_and_rest(s: &str) -> (i128, &str) {
    match s.as_bytes().first() {
        Some(b'-') => (-1, &s[1..]),
        Some(b'+') => (1, &s[1..]),
        _ => (1, s),
    }
}

/// `ConstructYamlInt`: underscores dropped, then `0b`, `0x`, a leading `0` (octal), `a:b:c`
/// (base 60) or decimal.
fn snake_int(s: &str) -> Option<i128> {
    let cleaned = s.replace('_', "");
    let (sign, v) = sign_and_rest(&cleaned);
    if v == "0" {
        return Some(0);
    }
    let n = if let Some(b) = v.strip_prefix("0b") {
        i128::from_str_radix(b, 2).ok()?
    } else if let Some(h) = v.strip_prefix("0x") {
        i128::from_str_radix(h, 16).ok()?
    } else if let Some(o) = v.strip_prefix('0') {
        i128::from_str_radix(o, 8).ok()?
    } else if v.contains(':') {
        base60(v)?
    } else {
        v.parse::<i128>().ok()?
    };
    Some(sign * n)
}

fn base60(v: &str) -> Option<i128> {
    let mut n: i128 = 0;
    for part in v.split(':') {
        n = n.checked_mul(60)?.checked_add(part.parse::<i128>().ok()?)?;
    }
    Some(n)
}

/// `ConstructYamlFloat`: underscores dropped, `.inf` and `.nan` in any case, base 60 with a
/// fraction, else Java's `Double.valueOf`.
fn snake_float(s: &str) -> Option<f64> {
    let cleaned = s.replace('_', "");
    let (sign, v) = sign_and_rest(&cleaned);
    let sign = sign as f64;
    match v.to_ascii_lowercase().as_str() {
        ".inf" => return Some(sign * f64::INFINITY),
        ".nan" => return Some(f64::NAN),
        _ => {}
    }
    if v.contains(':') {
        let mut val = 0.0;
        let mut bes = 1.0;
        for part in v.split(':').rev() {
            val += part.parse::<f64>().ok()? * bes;
            bes *= 60.0;
        }
        return Some(sign * val);
    }
    v.parse::<f64>().ok().map(|f| f * sign)
}

static PY_INT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[-+]?(0b[0-1_]+|0[0-7_]+|(0|[1-9][0-9_]*)|0x[0-9a-fA-F_]+|[1-9][0-9_]*(:[0-5]?[0-9])+)$").unwrap()
});
static PY_FLOAT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:[-+]?([0-9][0-9_]*)\.[0-9_]*([eE][-+][0-9]+)?|\.[0-9_]+([eE][-+][0-9]+)?|[-+]?\.(inf|Inf|INF)|\.(nan|NaN|NAN))$",
    )
    .unwrap()
});

/// `MiniYaml.resolve_plain` of `tools/render_config.py`, line for line.
pub fn resolve_py(s: &str) -> Value {
    match s {
        "" | "~" | "null" | "Null" | "NULL" => return Value::Null,
        "yes" | "Yes" | "YES" | "true" | "True" | "TRUE" | "on" | "On" | "ON" => return Value::Bool(true),
        "no" | "No" | "NO" | "false" | "False" | "FALSE" | "off" | "Off" | "OFF" => return Value::Bool(false),
        _ => {}
    }
    if PY_INT.is_match(s) {
        let sign: i128 = if s.starts_with('-') { -1 } else { 1 };
        let t = s.trim_start_matches(['+', '-']).replace('_', "");
        let n = if t == "0" {
            Some(0)
        } else if let Some(b) = t.strip_prefix("0b") {
            i128::from_str_radix(b, 2).ok()
        } else if let Some(h) = t.strip_prefix("0x") {
            i128::from_str_radix(h, 16).ok()
        } else if t.starts_with('0') {
            i128::from_str_radix(&t, 8).ok()
        } else if t.contains(':') {
            base60(&t)
        } else {
            t.parse::<i128>().ok()
        };
        if let Some(n) = n {
            return Value::Int(sign * n);
        }
    }
    if PY_FLOAT.is_match(s) {
        let t = s.replace('_', "");
        let low = t.to_ascii_lowercase();
        if low.ends_with("inf") {
            return Value::Float(if t.starts_with('-') { f64::NEG_INFINITY } else { f64::INFINITY });
        }
        if low.ends_with("nan") {
            return Value::Float(f64::NAN);
        }
        if let Ok(f) = t.parse::<f64>() {
            return Value::Float(f);
        }
    }
    Value::Str(s.to_string())
}

/// The shortest decimal digits of a finite, non-zero `f` and the exponent of its first digit
/// (`f = d.ddd × 10^exp`).
fn shortest(f: f64) -> (String, i32) {
    let s = format!("{:e}", f.abs());
    let (mantissa, exp) = s.split_once('e').unwrap_or((&s, "0"));
    (mantissa.replace('.', ""), exp.parse().unwrap_or(0))
}

/// Places `digits` (first digit at `10^exp`) as a plain decimal with at least one fraction digit.
fn plain_decimal(digits: &str, exp: i32) -> String {
    if exp < 0 {
        return format!("0.{}{digits}", "0".repeat((-exp - 1) as usize));
    }
    let int_len = exp as usize + 1;
    if digits.len() <= int_len {
        format!("{digits}{}.0", "0".repeat(int_len - digits.len()))
    } else {
        format!("{}.{}", &digits[..int_len], &digits[int_len..])
    }
}

/// Java's `Double.toString` (JDK 19 and later): plain between 10^-3 and 10^7, else
/// `d.dddE±n`; `NaN`, `Infinity`, `-Infinity`.
pub fn java_double(f: f64) -> String {
    if f.is_nan() {
        return "NaN".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "Infinity".into() } else { "-Infinity".into() };
    }
    let sign = if f.is_sign_negative() { "-" } else { "" };
    if f == 0.0 {
        return format!("{sign}0.0");
    }
    let (digits, exp) = shortest(f);
    if (-3..7).contains(&exp) {
        return format!("{sign}{}", plain_decimal(&digits, exp));
    }
    let rest = if digits.len() > 1 { &digits[1..] } else { "0" };
    format!("{sign}{}.{rest}E{exp}", &digits[..1])
}

/// Python's `repr(float)`: plain while the exponent is between -4 and 15, else `d.ddde±XX`;
/// `nan`, `inf`, `-inf`.
pub fn py_float(f: f64) -> String {
    if f.is_nan() {
        return "nan".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "inf".into() } else { "-inf".into() };
    }
    let sign = if f.is_sign_negative() { "-" } else { "" };
    if f == 0.0 {
        return format!("{sign}0.0");
    }
    let (digits, exp) = shortest(f);
    if (-4..16).contains(&exp) {
        return format!("{sign}{}", plain_decimal(&digits, exp));
    }
    let mantissa = if digits.len() > 1 { format!("{}.{}", &digits[..1], &digits[1..]) } else { digits };
    let esign = if exp < 0 { '-' } else { '+' };
    format!("{sign}{mantissa}e{esign}{:02}", exp.abs())
}

/// Java's `toString` of a scalar, for a key Spring writes as `[key]`.
fn java_text(v: &Value) -> Result<String> {
    Ok(match v {
        Value::Str(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Int(i) => i.to_string(),
        Value::Float(f) => java_double(*f),
        Value::Null => bail!("a null key cannot be flattened (Spring fails on it too)"),
        Value::Seq(_) | Value::Map(_) => bail!("a collection key cannot be flattened"),
    })
}

/// Python's `str()` of a scalar, for the script's keys.
pub fn py_text(v: &Value) -> String {
    match v {
        Value::Str(s) => s.clone(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Int(i) => i.to_string(),
        Value::Float(f) => py_float(*f),
        Value::Null => "None".into(),
        Value::Seq(_) | Value::Map(_) => format!("{v:?}"),
    }
}

/// A document flattened as Spring's `YamlProcessor` does it: `a.b`, `list[0]`, a non-text key
/// as `a[8080]`, nulls and empty lists as `""`, empty maps as nothing. A document that is not a
/// mapping becomes `document`.
pub fn flatten_spring(doc: &Value) -> Result<IndexMap<String, Value>> {
    let mut out = IndexMap::new();
    match doc {
        Value::Map(entries) => spring_map(entries, "", true, &mut out)?,
        other => {
            out.insert("document".to_string(), spring_leaf(other));
        }
    }
    Ok(out)
}

fn spring_leaf(v: &Value) -> Value {
    match v {
        Value::Null => Value::Str(String::new()),
        other => other.clone(),
    }
}

/// `as_map` is true for a mapping reached through mappings only: Spring turns its non-text keys
/// into `[key]`. A mapping inside a list keeps its raw keys, and Spring fails on a non-text one.
fn spring_map(entries: &[(Value, Value)], path: &str, as_map: bool, out: &mut IndexMap<String, Value>) -> Result<()> {
    for (k, v) in entries {
        let key = match k {
            Value::Str(s) => s.clone(),
            other if as_map => format!("[{}]", java_text(other)?),
            _ => bail!("a non-text key inside a list item cannot be flattened (Spring fails on it too)"),
        };
        let full = if path.is_empty() {
            key
        } else if key.starts_with('[') {
            format!("{path}{key}")
        } else {
            format!("{path}.{key}")
        };
        spring_value(v, full, as_map, out)?;
    }
    Ok(())
}

fn spring_value(v: &Value, path: String, as_map: bool, out: &mut IndexMap<String, Value>) -> Result<()> {
    match v {
        Value::Map(inner) => spring_map(inner, &path, as_map, out),
        Value::Seq(items) if items.is_empty() => {
            out.insert(path, Value::Str(String::new()));
            Ok(())
        }
        Value::Seq(items) => {
            for (i, item) in items.iter().enumerate() {
                spring_value(item, format!("{path}[{i}]"), false, out)?;
            }
            Ok(())
        }
        leaf => {
            out.insert(path, spring_leaf(leaf));
            Ok(())
        }
    }
}

/// `flatten` of `tools/render_config.py`: `a.b` with keys as Python prints them, `list[0]`,
/// nothing for an empty list or map, nulls kept.
pub fn flatten_py(node: &Value, prefix: &str, out: &mut IndexMap<String, Value>) {
    match node {
        Value::Map(entries) => {
            for (k, v) in entries {
                let key = py_text(k);
                let full = if prefix.is_empty() { key } else { format!("{prefix}.{key}") };
                flatten_py(v, &full, out);
            }
        }
        Value::Seq(items) => {
            for (i, v) in items.iter().enumerate() {
                flatten_py(v, &format!("{prefix}[{i}]"), out);
            }
        }
        leaf => {
            out.insert(prefix.to_string(), leaf.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(text: &str, typing: Typing) -> Value {
        documents(text, typing).unwrap().remove(0)
    }

    #[test]
    fn snake_typing() {
        let cases: &[(&str, Value)] = &[
            ("0", Value::Int(0)),
            ("-7", Value::Int(-7)),
            ("+12", Value::Int(12)),
            ("010", Value::Int(8)),
            ("0o17", Value::Str("0o17".into())),
            ("0x1F", Value::Int(31)),
            ("0b101", Value::Int(5)),
            ("1_000", Value::Int(1000)),
            ("1:30", Value::Int(90)),
            ("190:20:30", Value::Int(685230)),
            ("9223372036854775808", Value::Int(9223372036854775808)),
            ("1e5", Value::Float(100000.0)),
            ("1.5e+3", Value::Float(1500.0)),
            (".5", Value::Float(0.5)),
            ("-.Inf", Value::Float(f64::NEG_INFINITY)),
            ("1:30.5", Value::Float(90.5)),
            ("yes", Value::Bool(true)),
            ("OFF", Value::Bool(false)),
            ("y", Value::Str("y".into())),
            ("~", Value::Null),
            ("", Value::Null),
            ("2024-01-02", Value::Str("2024-01-02".into())),
            ("1.2.3", Value::Str("1.2.3".into())),
            ("0xZZ", Value::Str("0xZZ".into())),
        ];
        for (s, want) in cases {
            assert_eq!(&resolve_snake(s), want, "{s}");
        }
        assert!(matches!(resolve_snake(".NaN"), Value::Float(f) if f.is_nan()));
        assert_eq!(resolve_snake("99999999999999999999999999999999999999999"), Value::Str("99999999999999999999999999999999999999999".into()));
    }

    #[test]
    fn py_typing_follows_the_script() {
        let cases: &[(&str, Value)] = &[
            ("1e5", Value::Str("1e5".into())),
            ("6.02e23", Value::Str("6.02e23".into())),
            ("6.02e+23", Value::Float(6.02e23)),
            ("1.50", Value::Float(1.5)),
            ("010", Value::Int(8)),
            ("0b11", Value::Int(3)),
            ("-0x10", Value::Int(-16)),
            ("1:30", Value::Int(90)),
            ("0", Value::Int(0)),
            ("+5", Value::Int(5)),
            ("on", Value::Bool(true)),
            ("No", Value::Bool(false)),
            ("NULL", Value::Null),
            (".inf", Value::Float(f64::INFINITY)),
            ("-.INF", Value::Float(f64::NEG_INFINITY)),
            ("v1", Value::Str("v1".into())),
            ("0b", Value::Str("0b".into())),
        ];
        for (s, want) in cases {
            assert_eq!(&resolve_py(s), want, "{s}");
        }
        assert!(matches!(resolve_py(".nan"), Value::Float(f) if f.is_nan()));
    }

    #[test]
    fn number_texts() {
        for (f, java, py) in [
            (1.0, "1.0", "1.0"),
            (-2.5, "-2.5", "-2.5"),
            (100000.0, "100000.0", "100000.0"),
            (6.02e23, "6.02E23", "6.02e+23"),
            (1.0e8, "1.0E8", "100000000.0"),
            (1.0e-4, "1.0E-4", "0.0001"),
            (1.0e-5, "1.0E-5", "1e-05"),
            (0.001, "0.001", "0.001"),
            (1234567.0, "1234567.0", "1234567.0"),
            (12345678.0, "1.2345678E7", "12345678.0"),
            (1.0e16, "1.0E16", "1e+16"),
            (0.0, "0.0", "0.0"),
            (-0.0, "-0.0", "-0.0"),
            (f64::INFINITY, "Infinity", "inf"),
            (f64::NEG_INFINITY, "-Infinity", "-inf"),
            (f64::NAN, "NaN", "nan"),
        ] {
            assert_eq!(java_double(f), java, "{f}");
            assert_eq!(py_float(f), py, "{f}");
        }
    }

    #[test]
    fn documents_anchors_and_merges() {
        let docs = documents("# only a comment\n", Typing::Snake).unwrap();
        assert!(docs.is_empty());
        let docs = documents("---\n---\na: 1\n...\n---\n~\n", Typing::Snake).unwrap();
        assert_eq!(docs, vec![Value::Map(vec![(Value::Str("a".into()), Value::Int(1))])]);
        let v = one("base: &b {h: x, p: 1}\nm:\n  <<: *b\n  p: 2\ns:\n  <<: [*b, {q: 3, h: y}]\n", Typing::Snake);
        let flat = flatten_spring(&v).unwrap();
        let keys: Vec<_> = flat.keys().cloned().collect();
        assert_eq!(keys, ["base.h", "base.p", "m.h", "m.p", "s.h", "s.p", "s.q"]);
        assert_eq!(flat["m.p"], Value::Int(2));
        assert_eq!(flat["s.h"], Value::Str("x".into()), "the first merged mapping wins");
        assert!(documents("a: 1\na: 2\n", Typing::Snake).unwrap_err().to_string().contains("duplicate key"));
        assert_eq!(one("a: 1\na: 2\n", Typing::Py), Value::Map(vec![(Value::Str("a".into()), Value::Int(2))]));
        assert!(documents("a: *nope\n", Typing::Snake).is_err());
        assert!(documents("a: [1\n", Typing::Snake).is_err());
        assert!(documents("<<: 1\n", Typing::Snake).is_err());
        assert!(documents("<<: [1]\n", Typing::Snake).is_err());
        assert!(documents("? [a]\n: 1\n", Typing::Snake).is_err());
        assert!(documents("? [a]\n: 1\n", Typing::Py).is_err());
    }

    #[test]
    fn tags() {
        let v = one("a: !!str 12\nb: !!int '7'\nc: !!float 2\nd: !!null x\ne: !!bool yes\n", Typing::Snake);
        assert_eq!(v.get("a"), Some(&Value::Str("12".into())));
        assert_eq!(v.get("b"), Some(&Value::Int(7)));
        assert_eq!(v.get("c"), Some(&Value::Float(2.0)));
        assert_eq!(v.get("d"), Some(&Value::Null));
        assert_eq!(v.get("e"), Some(&Value::Bool(true)));
        assert!(documents("a: !!int x\n", Typing::Snake).is_err());
        assert!(documents("a: !custom x\n", Typing::Snake).is_err());
        assert_eq!(v.get("zz"), None);
        assert_eq!(Value::Int(1).get("a"), None);
        assert_eq!(Value::Str("s".into()).as_str(), Some("s"));
        assert_eq!(Value::Int(1).as_str(), None);
    }

    #[test]
    fn flattening_both_ways() {
        let text = "keys:\n  8080: a\n  on: b\n  \"q.k\": c\n  1.5: d\nl: []\nm: {}\nn:\nnested:\n  - [x]\n  - {k: 1}\n";
        let flat = flatten_spring(&one(text, Typing::Snake)).unwrap();
        let got: Vec<(String, Value)> = flat.into_iter().collect();
        assert_eq!(
            got,
            vec![
                ("keys[8080]".into(), Value::Str("a".into())),
                ("keys[true]".into(), Value::Str("b".into())),
                ("keys.q.k".into(), Value::Str("c".into())),
                ("keys[1.5]".into(), Value::Str("d".into())),
                ("l".into(), Value::Str(String::new())),
                ("n".into(), Value::Str(String::new())),
                ("nested[0][0]".into(), Value::Str("x".into())),
                ("nested[1].k".into(), Value::Int(1)),
            ]
        );
        let mut py = IndexMap::new();
        flatten_py(&one(text, Typing::Py), "", &mut py);
        let keys: Vec<_> = py.keys().cloned().collect();
        assert_eq!(keys, ["keys.8080", "keys.True", "keys.q.k", "keys.1.5", "n", "nested[0][0]", "nested[1].k"]);
        assert_eq!(py["n"], Value::Null);
        assert!(flatten_spring(&one("a:\n  ~: x\n", Typing::Snake)).is_err());
        assert!(flatten_spring(&one("a:\n  - {1: x}\n", Typing::Snake)).is_err());
        assert_eq!(flatten_spring(&Value::Int(3)).unwrap()["document"], Value::Int(3));
        assert_eq!(py_text(&Value::Null), "None");
        assert_eq!(py_text(&Value::Bool(false)), "False");
        assert_eq!(py_text(&Value::Float(2.0)), "2.0");
        assert!(py_text(&Value::Seq(vec![])).contains("Seq"));
        assert!(java_text(&Value::Seq(vec![])).is_err());
        assert_eq!(key_text(&Value::Int(4)), "Int(4)");
    }
}
