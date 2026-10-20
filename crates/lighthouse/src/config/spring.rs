//! Spring Cloud Config's `GET /{app}/{profile}[/{label}]`, answered from a snapshot exactly as
//! the Java config server answered it: the same `Environment` JSON (`name`, `profiles`,
//! `label`, `version`, `state`, `propertySources` most specific first), the same source names,
//! values typed by SnakeYAML's rules and written as Jackson writes them, `${...}` left as is.
//!
//! Order of the sources, as the Java server gave it (goldens in `tests/fixtures/spring`):
//! for each profile from the last to the first, `<app>-<profile>.yml` then
//! `application-<profile>.yml`; then `<app>.yml` and then `application.yml`, each file's
//! documents from the last to the first, the ones activated for another profile left out.
//!
//! Lighthouse adds guardrails the Java server lacked: only the apps configured are served, only
//! the profiles this deployment serves, each app's keys can be limited to some prefixes, and
//! `eureka` (the registry API's path prefix) and `v1` are never app names.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use super::source::Snapshot;
use super::yaml::{self, java_double, Typing, Value};

/// App names that are routes of Lighthouse itself.
pub const RESERVED: [&str; 2] = ["eureka", "v1"];

/// What one app may read through the compat endpoint.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AppRule {
    /// Served without a token (ssr-server's fetch cannot send one).
    pub open: bool,
    /// Only keys starting with one of these; empty: every key.
    pub prefixes: Vec<String>,
    /// One property source with the winning value of every key, instead of the files.
    pub merge_sources: bool,
}

/// A property source: its name and its flattened, typed keys in file order.
#[derive(Debug, Clone, PartialEq)]
pub struct PropertySource {
    pub name: String,
    pub source: IndexMap<String, Value>,
}

/// Spring's `Environment`.
#[derive(Debug, Clone, PartialEq)]
pub struct Environment {
    pub name: String,
    pub profiles: Vec<String>,
    pub label: Option<String>,
    pub version: Option<String>,
    pub sources: Vec<PropertySource>,
}

/// How a property source is named for this snapshot: the native backend's names for a
/// directory, the git backend's (`<uri>/<file>`) for GitHub.
fn source_name(snap: &Snapshot, uri: &str, file: &str, doc: Option<usize>) -> String {
    match snap.origin.strip_prefix("dir:") {
        Some(root) => match doc {
            None => format!("file:{root}/{file}"),
            Some(i) => format!("Config resource 'file [{root}/{file}]' via location 'file:{root}/' (document #{i})"),
        },
        None => match doc {
            None => format!("{uri}/{file}"),
            Some(i) => format!("{uri}/{file} (document #{i})"),
        },
    }
}

/// Spring's profile expressions: `a`, `!a`, `a & b`, `a | b`, parentheses; a list matches when
/// any item does.
pub fn profiles_match(expr: &Value, active: &[String]) -> bool {
    match expr {
        Value::Seq(items) => items.iter().any(|i| profiles_match(i, active)),
        other => {
            let text = yaml::py_text(other);
            text.split(',').any(|e| {
                let tokens = tokenize(e);
                let mut pos = 0;
                let ok = parse_or(&tokens, &mut pos, active);
                ok && pos == tokens.len()
            })
        }
    }
}

fn tokenize(e: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut word = String::new();
    for c in e.chars() {
        if matches!(c, '!' | '&' | '|' | '(' | ')') || c.is_whitespace() {
            if !word.is_empty() {
                out.push(std::mem::take(&mut word));
            }
            if !c.is_whitespace() {
                out.push(c.to_string());
            }
        } else {
            word.push(c);
        }
    }
    if !word.is_empty() {
        out.push(word);
    }
    out
}

fn parse_or(t: &[String], pos: &mut usize, active: &[String]) -> bool {
    let mut v = parse_and(t, pos, active);
    while t.get(*pos).is_some_and(|x| x == "|") {
        *pos += 1;
        v |= parse_and(t, pos, active);
    }
    v
}

fn parse_and(t: &[String], pos: &mut usize, active: &[String]) -> bool {
    let mut v = parse_not(t, pos, active);
    while t.get(*pos).is_some_and(|x| x == "&") {
        *pos += 1;
        v &= parse_not(t, pos, active);
    }
    v
}

fn parse_not(t: &[String], pos: &mut usize, active: &[String]) -> bool {
    match t.get(*pos).map(String::as_str) {
        Some("!") => {
            *pos += 1;
            !parse_not(t, pos, active)
        }
        Some("(") => {
            *pos += 1;
            let v = parse_or(t, pos, active);
            if t.get(*pos).is_some_and(|x| x == ")") {
                *pos += 1;
            }
            v
        }
        Some(name) => {
            *pos += 1;
            active.iter().any(|a| a == name)
        }
        None => false,
    }
}

fn on_profile(doc: &Value) -> Option<&Value> {
    doc.get("spring")?.get("config")?.get("activate")?.get("on-profile")
}

/// The sources of one file, last document first, the ones activated for other profiles left out.
fn file_sources(snap: &Snapshot, uri: &str, file: &str, active: &[String], out: &mut Vec<PropertySource>) -> Result<()> {
    let Some(text) = snap.file(file) else { return Ok(()) };
    let docs = yaml::documents(text, Typing::Snake).with_context(|| file.to_string())?;
    let multi = docs.len() > 1;
    for (i, doc) in docs.iter().enumerate().rev() {
        if on_profile(doc).is_some_and(|p| !profiles_match(p, active)) {
            continue;
        }
        let source = yaml::flatten_spring(doc).with_context(|| file.to_string())?;
        out.push(PropertySource { name: source_name(snap, uri, file, multi.then_some(i)), source });
    }
    Ok(())
}

/// The environment the Java config server would answer for `app` and `profiles` (comma
/// separated, as requested).
pub fn environment(snap: &Snapshot, uri: &str, app: &str, profiles: &str, label: Option<&str>) -> Result<Environment> {
    let active: Vec<String> = profiles.split(',').map(|p| p.trim().to_string()).filter(|p| !p.is_empty()).collect();
    let mut names = vec![app.to_string()];
    if app != "application" {
        names.push("application".to_string());
    }
    let mut sources = Vec::new();
    for p in active.iter().rev() {
        for n in &names {
            file_sources(snap, uri, &format!("{n}-{p}.yml"), &active, &mut sources)?;
        }
    }
    for n in &names {
        file_sources(snap, uri, &format!("{n}.yml"), &active, &mut sources)?;
    }
    Ok(Environment {
        name: app.to_string(),
        profiles: vec![profiles.to_string()],
        label: label.map(str::to_string),
        version: Some(snap.sha.clone()),
        sources,
    })
}

impl Environment {
    /// Keeps only the keys under `prefixes` (every source stays, so the first is still the
    /// first), and with `merge` folds the sources into one with each key's winning value.
    pub fn guard(mut self, rule: &AppRule) -> Self {
        if !rule.prefixes.is_empty() {
            for s in &mut self.sources {
                s.source.retain(|k, _| rule.prefixes.iter().any(|p| k.starts_with(p.as_str())));
            }
        }
        if rule.merge_sources {
            let mut merged: IndexMap<String, Value> = IndexMap::new();
            for s in &self.sources {
                for (k, v) in &s.source {
                    merged.entry(k.clone()).or_insert_with(|| v.clone());
                }
            }
            let name = format!("lighthouse:{}/{} (merged)", self.name, self.profiles.join(","));
            self.sources = vec![PropertySource { name, source: merged }];
        }
        self
    }

    /// The JSON the Java server writes: Jackson's field order, escapes and number forms.
    pub fn to_json(&self) -> String {
        let mut o = String::from("{\"name\":");
        json_str(&self.name, &mut o);
        o.push_str(",\"profiles\":[");
        for (i, p) in self.profiles.iter().enumerate() {
            if i > 0 {
                o.push(',');
            }
            json_str(p, &mut o);
        }
        o.push_str("],\"label\":");
        opt_str(self.label.as_deref(), &mut o);
        o.push_str(",\"version\":");
        opt_str(self.version.as_deref(), &mut o);
        o.push_str(",\"state\":null,\"propertySources\":[");
        for (i, s) in self.sources.iter().enumerate() {
            if i > 0 {
                o.push(',');
            }
            o.push_str("{\"name\":");
            json_str(&s.name, &mut o);
            o.push_str(",\"source\":{");
            for (j, (k, v)) in s.source.iter().enumerate() {
                if j > 0 {
                    o.push(',');
                }
                json_str(k, &mut o);
                o.push(':');
                json_value(v, &mut o);
            }
            o.push_str("}}");
        }
        o.push_str("]}");
        o
    }
}

fn opt_str(v: Option<&str>, o: &mut String) {
    match v {
        Some(s) => json_str(s, o),
        None => o.push_str("null"),
    }
}

fn json_value(v: &Value, o: &mut String) {
    match v {
        Value::Null => o.push_str("\"\""),
        Value::Bool(b) => o.push_str(if *b { "true" } else { "false" }),
        Value::Int(i) => o.push_str(&i.to_string()),
        Value::Float(f) if f.is_finite() => o.push_str(&java_double(*f)),
        Value::Float(f) => json_str(&java_double(*f), o),
        Value::Str(s) => json_str(s, o),
        // Flattening leaves no collections.
        other => json_str(&yaml::py_text(other), o),
    }
}

/// A JSON string as Jackson escapes it: `"`, `\`, the short escapes, other control characters
/// as `\u00XX` in capitals; everything else as is.
pub fn json_str(s: &str, o: &mut String) {
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\t' => o.push_str("\\t"),
            '\r' => o.push_str("\\r"),
            '\u{8}' => o.push_str("\\b"),
            '\u{c}' => o.push_str("\\f"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04X}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
}

/// Spring Boot's error body for a failure (what the Java server answered with a 500).
pub fn error_json(status: u16, error: &str, path: &str) -> String {
    let mut o = format!("{{\"timestamp\":\"{}\",\"status\":{status},\"error\":", chrono_now());
    json_str(error, &mut o);
    o.push_str(",\"path\":");
    json_str(path, &mut o);
    o.push('}');
    o
}

fn chrono_now() -> String {
    let ms = lighthouse_client::now_millis();
    let secs = ms.div_euclid(1000);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}+00:00", rem / 3600, rem % 3600 / 60, rem % 60, ms.rem_euclid(1000))
}

/// Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// The compat endpoint's settings (`[config.spring]`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SpringConfig {
    /// The profiles this deployment serves (dev: `ocidev`). Empty: `oci<env>`.
    pub profiles: Vec<String>,
    /// The repository URI the source names start with for a GitHub source. Empty:
    /// `https://github.com/<owner>/<repo>.git`, the URI the Java server cloned.
    pub uri: String,
    /// The apps served, by name; any other answers 404.
    pub apps: BTreeMap<String, AppRule>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_expressions() {
        let a = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let e = |s: &str| Value::Str(s.into());
        assert!(profiles_match(&e("ocidev"), &a(&["ocidev"])));
        assert!(!profiles_match(&e("ocidev"), &a(&["ociprod"])));
        assert!(profiles_match(&e("ocistage | ociprod"), &a(&["ociprod"])));
        assert!(profiles_match(&e("!ocidev"), &a(&["ociprod"])));
        assert!(!profiles_match(&e("!ocidev"), &a(&["ocidev"])));
        assert!(profiles_match(&e("(a & b) | c"), &a(&["a", "b"])));
        assert!(!profiles_match(&e("a & b"), &a(&["a"])));
        assert!(profiles_match(&e("x, a"), &a(&["a"])));
        assert!(profiles_match(&Value::Seq(vec![e("x"), e("a")]), &a(&["a"])));
        assert!(!profiles_match(&e("a )"), &a(&["a"])), "trailing tokens do not match");
        assert!(!profiles_match(&e(""), &a(&["a"])));
    }

    #[test]
    fn jackson_strings_and_dates() {
        let mut o = String::new();
        json_str("a\"b\\c\n\t\r\u{8}\u{c}\u{1}é/", &mut o);
        assert_eq!(o, "\"a\\\"b\\\\c\\n\\t\\r\\b\\f\\u0001é/\"");
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(20_726), (2026, 9, 30));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        let e = error_json(500, "Internal Server Error", "/x/y");
        assert!(e.starts_with("{\"timestamp\":\"20") && e.ends_with("\"status\":500,\"error\":\"Internal Server Error\",\"path\":\"/x/y\"}"));
        let mut o = String::new();
        json_value(&Value::Seq(vec![]), &mut o);
        assert_eq!(o, "\"Seq([])\"");
    }

    #[test]
    fn guards() {
        let mut src = IndexMap::new();
        src.insert("ssr.a".to_string(), Value::Int(1));
        src.insert("other".to_string(), Value::Int(2));
        let mut second = IndexMap::new();
        second.insert("ssr.a".to_string(), Value::Int(9));
        second.insert("ssr.b".to_string(), Value::Int(3));
        let env = Environment {
            name: "ssr".into(),
            profiles: vec!["ocidev".into()],
            label: None,
            version: None,
            sources: vec![PropertySource { name: "one".into(), source: src }, PropertySource { name: "two".into(), source: second }],
        };
        let only = env.clone().guard(&AppRule { prefixes: vec!["ssr.".into()], ..AppRule::default() });
        assert_eq!(only.sources.len(), 2);
        assert_eq!(only.sources[0].source.keys().collect::<Vec<_>>(), ["ssr.a"]);
        let merged = env.guard(&AppRule { prefixes: vec!["ssr.".into()], merge_sources: true, open: true });
        assert_eq!(merged.sources.len(), 1);
        assert_eq!(merged.sources[0].name, "lighthouse:ssr/ocidev (merged)");
        assert_eq!(merged.sources[0].source["ssr.a"], Value::Int(1));
        assert_eq!(merged.sources[0].source["ssr.b"], Value::Int(3));
        assert!(merged.to_json().contains("\"label\":null,\"version\":null,\"state\":null"));
    }

    #[test]
    fn git_backend_names() {
        let mut s = Snapshot::new("abc", "master", "github:o/r", Default::default());
        s.files.insert("a.yml".into(), "x: 1\n---\ny: 2\n".into());
        s.files.insert("bad.yml".into(), "x: [1\n".into());
        let mut out = Vec::new();
        file_sources(&s, "https://github.com/o/r.git", "a.yml", &[], &mut out).unwrap();
        assert_eq!(out[0].name, "https://github.com/o/r.git/a.yml (document #1)");
        assert_eq!(source_name(&s, "u", "f.yml", None), "u/f.yml");
        assert!(environment(&s, "u", "bad", "ocidev", None).is_err());
    }
}
