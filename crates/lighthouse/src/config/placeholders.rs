//! The Java services' settings as `tools/render_config.py` reads them (`JavaSettings`,
//! `resolve`, `spring_text` and the small helpers), ported line for line so that what the
//! renderer fills in stays byte-identical to the script's output.
//!
//! Layers per service, later ones winning: the documents of `application.yml` and
//! `<service>.yml` without a profile, then their documents activated for `oci<env>`, then
//! `application-oci<env>.yml`, then `<service>-oci<env>.yml`. (Spring itself ranks
//! `<service>.yml` above the activated documents of `application.yml`; the script does not, and
//! oci-config has no activated documents, so the two agree on it.)

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::sync::LazyLock;

use anyhow::{Context, Result};
use indexmap::IndexMap;
use regex::{Captures, Regex};

use super::source::Snapshot;
use super::yaml::{self, py_float, Typing, Value};

pub type Props = IndexMap<String, Value>;

/// `spring_text`: how Spring prints a value into text (a reference, a variable).
pub fn spring_text(v: &Value) -> String {
    match v {
        Value::Bool(true) => "true".into(),
        Value::Bool(false) => "false".into(),
        Value::Null => String::new(),
        Value::Str(s) => s.clone(),
        Value::Int(i) => i.to_string(),
        Value::Float(f) => py_float(*f),
        other => yaml::py_text(other),
    }
}

/// Python's truthiness, for the script's `a or b` and `if not x`.
pub fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Int(i) => *i != 0,
        Value::Float(f) => *f != 0.0,
        Value::Str(s) => !s.is_empty(),
        Value::Seq(items) => !items.is_empty(),
        Value::Map(entries) => !entries.is_empty(),
    }
}

/// The script's `a or b` over optional values.
pub fn or(a: Option<Value>, b: impl FnOnce() -> Option<Value>) -> Option<Value> {
    match a {
        Some(v) if truthy(&v) => Some(v),
        _ => b(),
    }
}

static REF: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\$\{([^$\{\}]*)\}").unwrap());

/// `${key}` and `${key:default}` replaced, innermost first; an unresolvable one is kept. At
/// most 20 rounds, as in the script.
pub fn resolve(props: &Props, value: &Value, seen: &HashSet<String>) -> Value {
    let Value::Str(text) = value else { return value.clone() };
    let mut text = text.clone();
    for _ in 0..20 {
        let mut changed = false;
        let next = REF
            .replace_all(&text, |m: &Captures| {
                let inner = &m[1];
                let (key, default) = match inner.split_once(':') {
                    Some((k, d)) => (k.trim(), Some(d)),
                    None => (inner.trim(), None),
                };
                if let Some(v) = props.get(key).filter(|_| !seen.contains(key)) {
                    changed = true;
                    let mut deeper = seen.clone();
                    deeper.insert(key.to_string());
                    return spring_text(&resolve(props, v, &deeper));
                }
                if let Some(d) = default {
                    changed = true;
                    return d.to_string();
                }
                format!("\u{1}{{{inner}}}")
            })
            .into_owned();
        text = next;
        if !changed {
            break;
        }
    }
    Value::Str(text.replace("\u{1}{", "${"))
}

/// The profile expression a document is activated by, or `None` for an always-on document.
pub fn activation(doc: &Value) -> Option<Value> {
    let spring = doc.get("spring").filter(|s| matches!(s, Value::Map(_)))?;
    let act = spring
        .get("config")
        .filter(|c| matches!(c, Value::Map(_)))
        .and_then(|c| c.get("activate"))
        .filter(|a| matches!(a, Value::Map(_)))
        .and_then(|a| a.get("on-profile"))
        .filter(|v| **v != Value::Null)
        .cloned();
    act.or_else(|| spring.get("profiles").filter(|p| !matches!(p, Value::Map(_) | Value::Null)).cloned())
}

/// `profile_matches`: terms split on `,` or `|`, each a conjunction (`&`) of names or `!name`.
pub fn profile_matches(expr: &Value, profile: &str) -> bool {
    let terms: Vec<String> = match expr {
        Value::Seq(items) => items.iter().map(yaml::py_text).collect(),
        other => yaml::py_text(other).split([',', '|']).map(str::to_string).collect(),
    };
    terms.iter().any(|term| {
        term.split('&').all(|part| {
            let p = part.trim().trim_matches(['(', ')']);
            match p.strip_prefix('!') {
                Some(not) => not.trim() != profile,
                None => p == profile,
            }
        })
    })
}

/// The effective, resolved settings of each Java service for one environment.
pub struct JavaSettings<'a> {
    snap: &'a Snapshot,
    profile: String,
    docs: RefCell<HashMap<String, Rc<Vec<Value>>>>,
    props: RefCell<HashMap<String, Rc<Props>>>,
    first: RefCell<HashMap<String, Rc<Props>>>,
}

impl<'a> JavaSettings<'a> {
    pub fn new(snap: &'a Snapshot, env: &str) -> Self {
        Self {
            snap,
            profile: format!("oci{env}"),
            docs: RefCell::default(),
            props: RefCell::default(),
            first: RefCell::default(),
        }
    }

    pub fn exists(&self, name: &str) -> bool {
        self.snap.file(&format!("{name}.yml")).is_some()
    }

    /// The documents of `<name>.yml`, typed as the script types them; none when it is absent.
    pub fn documents(&self, name: &str) -> Result<Rc<Vec<Value>>> {
        if let Some(d) = self.docs.borrow().get(name) {
            return Ok(d.clone());
        }
        let path = format!("{name}.yml");
        let docs = match self.snap.file(&path) {
            None => Vec::new(),
            Some(text) => yaml::documents(text, Typing::Py).with_context(|| path.clone())?,
        };
        let docs = Rc::new(docs);
        self.docs.borrow_mut().insert(name.to_string(), docs.clone());
        Ok(docs)
    }

    fn raw(&self, service: &str) -> Result<Props> {
        let (mut base, mut profiled) = (Vec::new(), Vec::new());
        for name in ["application", service] {
            for doc in self.documents(name)?.iter() {
                match activation(doc) {
                    None => base.push(doc.clone()),
                    Some(act) if profile_matches(&act, &self.profile) => profiled.push(doc.clone()),
                    Some(_) => {}
                }
            }
        }
        let mut layers = base;
        layers.extend(profiled);
        for name in [format!("application-{}", self.profile), format!("{service}-{}", self.profile)] {
            for doc in self.documents(&name)?.iter() {
                if activation(doc).is_none_or(|act| profile_matches(&act, &self.profile)) {
                    layers.push(doc.clone());
                }
            }
        }
        let mut flat = Props::new();
        for doc in &layers {
            yaml::flatten_py(doc, "", &mut flat);
        }
        Ok(flat)
    }

    pub fn props(&self, service: &str) -> Result<Rc<Props>> {
        if let Some(p) = self.props.borrow().get(service) {
            return Ok(p.clone());
        }
        let p = Rc::new(self.raw(service)?);
        self.props.borrow_mut().insert(service.to_string(), p.clone());
        Ok(p)
    }

    /// The resolved value as Spring would render it, or `None` when unset or unresolvable.
    pub fn get(&self, service: &str, key: &str) -> Result<Option<Value>> {
        let props = self.props(service)?;
        let Some(v) = props.get(key) else { return Ok(None) };
        let value = resolve(&props, v, &HashSet::new());
        Ok(match value {
            Value::Null => None,
            Value::Str(ref s) if s.contains("${") => None,
            v => Some(v),
        })
    }

    /// The first property source config-server sends `service` (its highest):
    /// `<service>-oci<env>.yml` when it exists, else `application-oci<env>.yml`.
    pub fn first_source(&self, service: &str) -> Result<Rc<Props>> {
        if let Some(p) = self.first.borrow().get(service) {
            return Ok(p.clone());
        }
        let mut flat = Props::new();
        for name in [format!("{service}-{}", self.profile), format!("application-{}", self.profile)] {
            if self.exists(&name) {
                for doc in self.documents(&name)?.iter() {
                    if activation(doc).is_none_or(|act| profile_matches(&act, &self.profile)) {
                        yaml::flatten_py(doc, "", &mut flat);
                    }
                }
                break;
            }
        }
        let flat = Rc::new(flat);
        self.first.borrow_mut().insert(service.to_string(), flat.clone());
        Ok(flat)
    }

    /// Whether config-server sends `key` to `service` and its resolved value (a YAML null as
    /// `""`). With `first_only`, only the first property source counts, as ssr-server reads no
    /// other.
    pub fn lookup(&self, service: &str, key: &str, first_only: bool) -> Result<Option<Value>> {
        let source = if first_only { self.first_source(service)? } else { self.props(service)? };
        let Some(v) = source.get(key) else { return Ok(None) };
        let props = self.props(service)?;
        Ok(match resolve(&props, v, &HashSet::new()) {
            Value::Str(s) if s.contains("${") => None,
            Value::Null => Some(Value::Str(String::new())),
            v => Some(v),
        })
    }
}

/// A database URL read as the script reads it: one `host[:port]` and a database name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbUrl {
    pub host: String,
    pub port: i128,
    pub name: String,
}

static DB_URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:jdbc:|r2dbcs?:)(?:pool:)?(?:mysql|mariadb)://([^/?#]+)/([^?#]*)").unwrap());
static PORT_SUFFIX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r":[0-9]+$").unwrap());

pub fn parse_db_url(url: &str) -> Option<DbUrl> {
    let m = DB_URL.captures(url)?;
    let hostport = m[1].rsplit('@').next().unwrap_or(&m[1]);
    if hostport.contains(',') {
        return None;
    }
    let (mut host, mut port) = (hostport.to_string(), 3306);
    if PORT_SUFFIX.is_match(hostport) {
        let (h, p) = hostport.rsplit_once(':')?;
        host = h.to_string();
        port = p.parse().ok()?;
    }
    Some(DbUrl { host, port, name: unquote(&m[2]) })
}

/// `urllib.parse.unquote`: `%XX` decoded as UTF-8, invalid sequences replaced.
pub fn unquote(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(hi), Some(lo)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push(hi * 16 + lo);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `urllib.parse.quote(s, safe="")`: everything but letters, digits and `_.-~` as `%XX`.
pub fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        if byte.is_ascii_alphanumeric() || b"_.-~".contains(&byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// A value the renderer writes into a template.
#[derive(Debug, Clone, PartialEq)]
pub enum Literal {
    Str(String),
    Int(i128),
    Bool(bool),
    List(Vec<String>),
}

impl Literal {
    pub fn from_toml(v: &toml::Value) -> Self {
        match v {
            toml::Value::Boolean(b) => Literal::Bool(*b),
            toml::Value::Integer(i) => Literal::Int(i128::from(*i)),
            toml::Value::String(s) => Literal::Str(s.clone()),
            toml::Value::Array(items) => {
                Literal::List(items.iter().map(|i| i.as_str().map_or_else(|| i.to_string(), str::to_string)).collect())
            }
            other => Literal::Str(other.to_string()),
        }
    }
}

/// `toml_literal`: a TOML value, strings escaped as the script escapes them.
pub fn toml_literal(v: &Literal) -> String {
    match v {
        Literal::Bool(b) => b.to_string(),
        Literal::Int(i) => i.to_string(),
        Literal::List(items) => {
            let parts: Vec<String> = items.iter().map(|s| toml_literal(&Literal::Str(s.clone()))).collect();
            format!("[{}]", parts.join(", "))
        }
        Literal::Str(s) => {
            let mut out = String::from("\"");
            for ch in s.chars() {
                match ch {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    c if (c as u32) < 0x20 || c as u32 == 0x7f => out.push_str(&format!("\\u{:04x}", c as u32)),
                    c => out.push(c),
                }
            }
            out.push('"');
            out
        }
    }
}

/// Python's `int(text)` for base 10: a sign, digits, single underscores between digits.
pub fn py_int(text: &str) -> Option<i128> {
    let (neg, digits) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    let ok = !digits.is_empty()
        && !digits.starts_with('_')
        && !digits.ends_with('_')
        && !digits.contains("__")
        && digits.bytes().all(|b| b.is_ascii_digit() || b == b'_');
    if !ok {
        return None;
    }
    let n: i128 = digits.replace('_', "").parse().ok()?;
    Some(if neg { -n } else { n })
}

/// `as_kind`: a setting's value in its kind, `None` when it does not read as one.
pub fn as_kind(value: &Value, kind: super::manifest::Kind) -> Option<Literal> {
    use super::manifest::Kind;
    match kind {
        Kind::Bool => match value {
            Value::Bool(b) => Some(Literal::Bool(*b)),
            other => match spring_text(other).trim().to_lowercase().as_str() {
                "true" => Some(Literal::Bool(true)),
                "false" => Some(Literal::Bool(false)),
                _ => None,
            },
        },
        Kind::Int => match value {
            Value::Bool(_) => None,
            other => py_int(spring_text(other).trim()).map(Literal::Int),
        },
        Kind::Str => Some(Literal::Str(spring_text(value))),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::config::manifest::Kind;

    fn snap(files: &[(&str, &str)]) -> Snapshot {
        let files: BTreeMap<String, String> = files.iter().map(|(p, t)| (p.to_string(), t.to_string())).collect();
        Snapshot::new("sha", "master", "dir:/x", files)
    }

    fn props(pairs: &[(&str, Value)]) -> Props {
        pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
    }

    #[test]
    fn references() {
        let p = props(&[
            ("a", Value::Str("A".into())),
            ("n", Value::Int(7)),
            ("b", Value::Str("${a}-${n}".into())),
            ("self", Value::Str("${self}".into())),
            ("t", Value::Bool(true)),
        ]);
        let none = HashSet::new();
        assert_eq!(resolve(&p, &Value::Str("x ${b} ${t}".into()), &none), Value::Str("x A-7 true".into()));
        assert_eq!(resolve(&p, &Value::Str("${zz:def}/${ q :}".into()), &none), Value::Str("def/".into()));
        assert_eq!(resolve(&p, &Value::Str("${zz}".into()), &none), Value::Str("${zz}".into()));
        assert_eq!(resolve(&p, &Value::Str("${zz:${a}}".into()), &none), Value::Str("A".into()));
        assert_eq!(resolve(&p, &Value::Str("${self}".into()), &none), Value::Str("${self}".into()));
        assert_eq!(resolve(&p, &Value::Int(3), &none), Value::Int(3));
    }

    #[test]
    fn activations() {
        let doc = |t: &str| yaml::documents(t, Typing::Py).unwrap().remove(0);
        assert_eq!(activation(&doc("a: 1")), None);
        assert_eq!(activation(&doc("spring: 1")), None);
        let on = activation(&doc("spring:\n  config:\n    activate:\n      on-profile: ocidev | ociprod\n")).unwrap();
        assert!(profile_matches(&on, "ociprod") && !profile_matches(&on, "ocistage"));
        let legacy = activation(&doc("spring:\n  profiles: [ocidev, x]\n")).unwrap();
        assert!(profile_matches(&legacy, "x"));
        assert_eq!(activation(&doc("spring:\n  profiles:\n    active: x\n")), None);
        let not = Value::Str("!ocidev & (ociprod)".into());
        assert!(profile_matches(&not, "ociprod") && !profile_matches(&not, "ocidev"));
        assert!(!profile_matches(&Value::Str("! ocidev".into()), "ocidev"));
    }

    #[test]
    fn settings_by_layer() {
        let s = snap(&[
            ("application.yml", "a: base\nb: base\nr: ${a}\n---\nspring:\n  config:\n    activate:\n      on-profile: ocidev\nb: act\n---\nspring:\n  config:\n    activate:\n      on-profile: ociprod\nb: prod\n"),
            ("svc.yml", "c: svc\nd: ~\nu: ${missing}\n"),
            ("application-ocidev.yml", "e: appdev\nssr-in:\n  x: 1\n"),
            ("svc-ocidev.yml", "f: svcdev\n"),
            ("bad.yml", "a: [1\n"),
        ]);
        let j = JavaSettings::new(&s, "dev");
        assert_eq!(j.get("svc", "b").unwrap(), Some(Value::Str("act".into())));
        assert_eq!(j.get("svc", "r").unwrap(), Some(Value::Str("base".into())));
        assert_eq!(j.get("svc", "d").unwrap(), None);
        assert_eq!(j.get("svc", "u").unwrap(), None);
        assert_eq!(j.get("svc", "zz").unwrap(), None);
        assert_eq!(j.lookup("svc", "d", false).unwrap(), Some(Value::Str(String::new())));
        assert_eq!(j.lookup("svc", "u", false).unwrap(), None);
        assert_eq!(j.lookup("svc", "e", true).unwrap(), None, "svc-ocidev.yml is svc's first source");
        assert_eq!(j.lookup("svc", "f", true).unwrap(), Some(Value::Str("svcdev".into())));
        assert_eq!(j.lookup("other", "e", true).unwrap(), Some(Value::Str("appdev".into())));
        assert_eq!(j.lookup("other", "e", true).unwrap(), Some(Value::Str("appdev".into())), "cached");
        assert!(j.props("bad").is_err());
        assert!(!j.exists("nope") && j.exists("svc"));
    }

    #[test]
    fn db_urls_and_quoting() {
        assert_eq!(
            parse_db_url("r2dbc:pool:mysql://u:p@db.x:3310/core%20db?ssl=1"),
            Some(DbUrl { host: "db.x".into(), port: 3310, name: "core db".into() })
        );
        assert_eq!(parse_db_url("jdbc:mariadb://db.x/files").unwrap().port, 3306);
        assert_eq!(parse_db_url("jdbc:mysql://a:1,b:2/x"), None);
        assert_eq!(parse_db_url("postgres://a/x"), None);
        assert_eq!(unquote("a%2Fb%zz%"), "a/b%zz%");
        assert_eq!(quote("p@ss/word~_.-"), "p%40ss%2Fword~_.-");
    }

    #[test]
    fn literals_and_kinds() {
        assert_eq!(toml_literal(&Literal::Str("a\"b\\c\u{1}\u{7f}é".into())), "\"a\\\"b\\\\c\\u0001\\u007fé\"");
        assert_eq!(toml_literal(&Literal::List(vec!["x".into(), "y".into()])), "[\"x\", \"y\"]");
        assert_eq!(toml_literal(&Literal::Int(-3)), "-3");
        assert_eq!(toml_literal(&Literal::Bool(false)), "false");
        assert_eq!(Literal::from_toml(&toml::Value::Integer(10)), Literal::Int(10));
        assert_eq!(Literal::from_toml(&toml::Value::Boolean(true)), Literal::Bool(true));
        assert_eq!(Literal::from_toml(&toml::Value::String("s".into())), Literal::Str("s".into()));
        assert_eq!(
            Literal::from_toml(&toml::Value::Array(vec![toml::Value::String("a".into()), toml::Value::Integer(1)])),
            Literal::List(vec!["a".into(), "1".into()])
        );
        assert_eq!(Literal::from_toml(&toml::Value::Float(1.5)), Literal::Str("1.5".into()));
        assert_eq!(py_int("1_000"), Some(1000));
        assert_eq!(py_int("-007"), Some(-7));
        for bad in ["", "+", "_1", "1_", "1__0", "1.0", "x"] {
            assert_eq!(py_int(bad), None, "{bad}");
        }
        assert_eq!(as_kind(&Value::Str(" True ".into()), Kind::Bool), Some(Literal::Bool(true)));
        assert_eq!(as_kind(&Value::Bool(false), Kind::Bool), Some(Literal::Bool(false)));
        assert_eq!(as_kind(&Value::Str("maybe".into()), Kind::Bool), None);
        assert_eq!(as_kind(&Value::Int(30), Kind::Int), Some(Literal::Int(30)));
        assert_eq!(as_kind(&Value::Bool(true), Kind::Int), None);
        assert_eq!(as_kind(&Value::Float(1.5), Kind::Str), Some(Literal::Str("1.5".into())));
        assert_eq!(spring_text(&Value::Seq(vec![])), "Seq([])");
        assert!(!truthy(&Value::Float(0.0)) && truthy(&Value::Seq(vec![Value::Null])) && !truthy(&Value::Map(vec![])));
        assert_eq!(or(Some(Value::Str(String::new())), || Some(Value::Int(1))), Some(Value::Int(1)));
        assert_eq!(or(Some(Value::Int(2)), || None), Some(Value::Int(2)));
    }
}
