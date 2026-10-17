//! The catalogue: every message code, its HTTP status and the values it names, and its texts
//! per language in layers (a service's override files above the built-in texts).
//!
//! A catalogue file is TOML, one table per code. The code is the table's path, so
//! `[SEC.APP_ACCESS_FORBIDDEN]` is the code `SEC.APP_ACCESS_FORBIDDEN`:
//!
//! ```toml
//! [SEC.APP_ACCESS_FORBIDDEN]
//! status = 403                      # built-in base file only
//! params = ["app", "client"]        # the values, in the order Java passes them
//! text = "You can't open {app|this app}: your account has no access to it."
//! action = "Ask an owner of {client|your organisation} to give your account access."
//! java = "forbidden_app_access"     # the Java bundle key(s) it replaces (review and parity)
//! java_text = "..."                 # or Java's literal text, when it is not a bundle key
//! when = "..."                      # review sheet: when it happens
//! audience = "signed-in"            # review sheet: who sees it
//! ```
//!
//! Only `text` and `action` are read from translations and override files; the rest belongs
//! to the built-in English file. A param may name a kind after a colon: `permission:authority`
//! shows an authority as its plain label, `what:entity` a Java class name as words.

use std::collections::HashMap;

use anyhow::{anyhow, bail, Context, Result};
use toml::{Table, Value};

use super::template::Template;

/// How a value is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamKind {
    /// As it is.
    Plain,
    /// `Authorities.Page_UPDATE` (or several, comma separated) as "Edit pages".
    Authority,
    /// A Java class name (`ClientUrl`) as words ("client URL").
    Entity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParamSpec {
    pub name: String,
    pub kind: ParamKind,
}

impl ParamSpec {
    fn parse(s: &str) -> Result<Self> {
        let (name, kind) = s.split_once(':').unwrap_or((s, "plain"));
        let kind = match kind.trim() {
            "plain" => ParamKind::Plain,
            "authority" => ParamKind::Authority,
            "entity" => ParamKind::Entity,
            other => bail!("unknown param kind {other:?}"),
        };
        let name = name.trim();
        if name.is_empty() {
            bail!("a param has no name");
        }
        Ok(Self { name: name.to_string(), kind })
    }
}

/// What the built-in English file says about a code beyond its texts.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Meta {
    pub status: Option<u16>,
    pub params: Vec<ParamSpec>,
    pub java: Vec<String>,
    pub java_text: Vec<String>,
    pub when: Option<String>,
    pub audience: Option<String>,
}

/// One code's texts in one language and layer. `None` leaves the field to the next layer; an
/// empty action in an override removes the built-in one.
#[derive(Debug, Clone, Default)]
pub struct Texts {
    pub text: Option<Template>,
    pub action: Option<Template>,
}

impl Texts {
    pub fn from_strings(text: Option<&str>, action: Option<&str>) -> Result<Self> {
        Ok(Self {
            text: text.map(Template::parse).transpose()?,
            action: action.map(Template::parse).transpose()?,
        })
    }
}

/// One code as a file states it.
#[derive(Debug, Clone)]
pub struct Entry {
    pub code: String,
    pub texts: Texts,
    pub meta: Meta,
}

const KEYS: &[&str] = &["text", "action", "status", "params", "java", "java_text", "when", "audience"];

fn strings(v: &Value, what: &str) -> Result<Vec<String>> {
    match v {
        Value::String(s) => Ok(vec![s.clone()]),
        Value::Array(a) => a
            .iter()
            .map(|x| x.as_str().map(str::to_string).ok_or_else(|| anyhow!("{what} must hold strings")))
            .collect(),
        _ => bail!("{what} must be a string or a list of strings"),
    }
}

fn entry(code: &str, t: &Table) -> Result<Entry> {
    if let Some(k) = t.keys().find(|k| !KEYS.contains(&k.as_str())) {
        bail!("unknown key {k:?}");
    }
    let s = |k: &str| -> Result<Option<&str>> {
        t.get(k).map(|v| v.as_str().ok_or_else(|| anyhow!("{k} must be a string"))).transpose()
    };
    let texts = Texts::from_strings(s("text")?, s("action")?)?;
    let status = t
        .get("status")
        .map(|v| {
            v.as_integer()
                .and_then(|n| u16::try_from(n).ok())
                .filter(|n| (100..600).contains(n))
                .ok_or_else(|| anyhow!("status must be an HTTP status"))
        })
        .transpose()?;
    let params = match t.get("params") {
        None => Vec::new(),
        Some(v) => strings(v, "params")?.iter().map(|p| ParamSpec::parse(p)).collect::<Result<_>>()?,
    };
    let meta = Meta {
        status,
        params,
        java: t.get("java").map(|v| strings(v, "java")).transpose()?.unwrap_or_default(),
        java_text: t.get("java_text").map(|v| strings(v, "java_text")).transpose()?.unwrap_or_default(),
        when: s("when")?.map(str::to_string),
        audience: s("audience")?.map(str::to_string),
    };
    Ok(Entry { code: code.to_string(), texts, meta })
}

/// A table holding `text` or `action` is a code; any other table is a namespace to walk.
fn walk(prefix: &str, t: &Table, out: &mut Vec<Entry>) -> Result<()> {
    for (k, v) in t {
        let code = if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
        let Value::Table(inner) = v else { bail!("{code}: expected a table") };
        if inner.contains_key("text") || inner.contains_key("action") {
            out.push(entry(&code, inner).with_context(|| code.clone())?);
        } else {
            walk(&code, inner, out)?;
        }
    }
    Ok(())
}

/// Every code a catalogue file states.
pub fn parse_file(text: &str) -> Result<Vec<Entry>> {
    let table: Table = toml::from_str(text)?;
    let mut out = Vec::new();
    walk("", &table, &mut out)?;
    Ok(out)
}

/// The texts for one language, keyed by code.
pub type LocaleTexts = HashMap<String, Texts>;

/// Codes, their facts, and their texts by layer and language.
#[derive(Default)]
pub struct Catalogue {
    pub(crate) meta: HashMap<String, Meta>,
    /// locale -> code -> texts, compiled in.
    pub(crate) builtin: HashMap<String, LocaleTexts>,
    /// locale -> code -> texts, from the service's override directory.
    pub(crate) files: HashMap<String, LocaleTexts>,
    /// (namespace, Java key) -> codes.
    pub(crate) java: HashMap<(String, String), Vec<String>>,
    pub(crate) sources: Vec<String>,
    pub(crate) default_locale: Option<String>,
}

fn namespace(code: &str) -> &str {
    code.split('.').next().unwrap_or(code)
}

fn merge(layer: &mut LocaleTexts, code: String, texts: Texts) {
    let slot = layer.entry(code).or_default();
    if texts.text.is_some() {
        slot.text = texts.text;
    }
    if texts.action.is_some() {
        slot.action = texts.action;
    }
}

impl Catalogue {
    /// Adds a compiled-in file once per `source` and locale. The first file seen for a code
    /// (the English one) gives its status, params and Java keys.
    pub fn add_builtin(&mut self, source: &str, locale: &str, text: &str) -> Result<usize> {
        let key = format!("{source}:{locale}");
        if self.sources.contains(&key) {
            return Ok(0);
        }
        let locale = super::locale::normalize(locale).ok_or_else(|| anyhow!("bad locale {locale:?}"))?;
        let entries = parse_file(text).with_context(|| format!("built-in catalogue {key}"))?;
        let n = entries.len();
        for e in entries {
            if !self.meta.contains_key(&e.code) {
                for j in &e.meta.java {
                    self.java.entry((namespace(&e.code).to_string(), j.clone())).or_default().push(e.code.clone());
                }
                self.meta.insert(e.code.clone(), e.meta);
            }
            merge(self.builtin.entry(locale.clone()).or_default(), e.code, e.texts);
        }
        self.sources.push(key);
        Ok(n)
    }

    /// Adds a service override file's texts for `locale`.
    pub fn add_override(&mut self, locale: &str, text: &str) -> Result<usize> {
        let locale = super::locale::normalize(locale).ok_or_else(|| anyhow!("bad locale {locale:?}"))?;
        let entries = parse_file(text)?;
        let n = entries.len();
        for e in entries {
            merge(self.files.entry(locale.clone()).or_default(), e.code, e.texts);
        }
        Ok(n)
    }

    /// Reads every `<locale>.toml` in `dir`. A missing directory is not an error (nothing is
    /// overridden); a file that does not parse is.
    pub fn load_override_dir(&mut self, dir: &std::path::Path) -> Result<usize> {
        let Ok(read) = std::fs::read_dir(dir) else { return Ok(0) };
        let mut n = 0;
        let mut files: Vec<_> = read.filter_map(|e| e.ok()).map(|e| e.path()).collect();
        files.sort();
        for path in files {
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }
            let Some(locale) = path.file_stem().and_then(|s| s.to_str()) else { continue };
            let text = std::fs::read_to_string(&path).with_context(|| path.display().to_string())?;
            n += self.add_override(locale, &text).with_context(|| path.display().to_string())?;
        }
        Ok(n)
    }

    pub fn set_default_locale(&mut self, locale: Option<&str>) {
        self.default_locale = locale.and_then(super::locale::normalize);
    }

    pub fn default_locale(&self) -> Option<&str> {
        self.default_locale.as_deref()
    }

    pub fn meta(&self, code: &str) -> Option<&Meta> {
        self.meta.get(code)
    }

    pub fn has(&self, code: &str) -> bool {
        self.meta.contains_key(code)
    }

    /// Every code with its facts, sorted.
    pub fn codes(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self.meta.keys().map(String::as_str).collect();
        v.sort_unstable();
        v
    }

    /// The code that replaces a Java bundle key in a namespace: `<NS>.<KEY>` when that one names
    /// the key, else the first code that does.
    pub fn code_for_java(&self, ns: &str, key: &str) -> Option<&str> {
        let codes = self.java.get(&(ns.to_string(), key.to_string()))?;
        let preferred = format!("{ns}.{}", key.to_ascii_uppercase());
        codes.iter().find(|c| **c == preferred).or_else(|| codes.first()).map(String::as_str)
    }

    /// The text and action layers for `code` in `locale`, highest first.
    pub(crate) fn layers(&self, locale: &str, code: &str) -> [Option<&Texts>; 2] {
        [
            self.files.get(locale).and_then(|l| l.get(code)),
            self.builtin.get(locale).and_then(|l| l.get(code)),
        ]
    }

    /// The languages with any built-in text.
    pub fn builtin_locales(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self.builtin.keys().map(String::as_str).collect();
        v.sort_unstable();
        v
    }

    /// The built-in texts of `code` in `locale`.
    pub fn builtin_texts(&self, locale: &str, code: &str) -> Option<&Texts> {
        self.builtin.get(locale).and_then(|l| l.get(code))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EN: &str = r#"
        [T.ONE]
        status = 404
        params = ["what:entity", "id", "permission:authority"]
        text = "No {what|thing}[ {id}]."
        action = "Look again."
        java = ["object_not_found", "other"]
        java_text = "x"
        when = "w"
        audience = "anyone"

        [T.NESTED.TWO]
        text = "Two"

        [T.ONE_DUP]
        text = "dup"
        java = "object_not_found"

        [PERMISSION."CRM.Lead_READ"]
        text = "View leads"
    "#;

    #[test]
    fn parses_entries_and_paths() {
        let entries = parse_file(EN).unwrap();
        let codes: Vec<&str> = entries.iter().map(|e| e.code.as_str()).collect();
        assert!(codes.contains(&"T.ONE") && codes.contains(&"T.NESTED.TWO") && codes.contains(&"PERMISSION.CRM.Lead_READ"));
        let one = entries.iter().find(|e| e.code == "T.ONE").unwrap();
        assert_eq!(one.meta.status, Some(404));
        assert_eq!(one.meta.params[0], ParamSpec { name: "what".into(), kind: ParamKind::Entity });
        assert_eq!(one.meta.params[2].kind, ParamKind::Authority);
        assert_eq!(one.meta.java, vec!["object_not_found", "other"]);
        assert_eq!(one.meta.java_text, vec!["x"]);
        assert_eq!(one.meta.when.as_deref(), Some("w"));
        assert_eq!(one.meta.audience.as_deref(), Some("anyone"));
    }

    #[test]
    fn refuses_mistakes() {
        for (bad, why) in [
            ("[A.B]\ntext = 1", "text must be a string"),
            ("[A.B]\ntext = \"x\"\ntxet = \"y\"", "unknown key"),
            ("[A.B]\ntext = \"x\"\nstatus = 99", "HTTP status"),
            ("[A.B]\ntext = \"x\"\nstatus = \"x\"", "HTTP status"),
            ("[A.B]\ntext = \"x\"\nparams = [1]", "strings"),
            ("[A.B]\ntext = \"x\"\nparams = 1", "list of strings"),
            ("[A.B]\ntext = \"x\"\nparams = [\"a:weird\"]", "unknown param kind"),
            ("[A.B]\ntext = \"x\"\nparams = [\":plain\"]", "no name"),
            ("[A.B]\ntext = \"{x\"", "never closed"),
            ("A = 1", "expected a table"),
            ("[A", "TOML"),
        ] {
            let e = parse_file(bad).unwrap_err();
            let chain = format!("{e:#}");
            assert!(chain.contains(why) || why == "TOML", "{bad}: {chain}");
        }
    }

    #[test]
    fn layers_and_java_keys() {
        let mut c = Catalogue::default();
        assert_eq!(c.add_builtin("t", "en", EN).unwrap(), 4);
        assert_eq!(c.add_builtin("t", "en", EN).unwrap(), 0, "once per source and locale");
        c.add_builtin("t", "pt_BR", "[T.ONE]\ntext = \"Nada\"\nstatus = 500").unwrap();
        assert_eq!(c.meta("T.ONE").unwrap().status, Some(404), "status comes from the first file");
        assert!(c.builtin_texts("pt-BR", "T.ONE").is_some());
        assert_eq!(c.builtin_locales(), vec!["en", "pt-BR"]);
        assert_eq!(c.code_for_java("T", "object_not_found"), Some("T.ONE"));
        assert_eq!(c.code_for_java("T", "other"), Some("T.ONE"));
        assert_eq!(c.code_for_java("X", "object_not_found"), None);
        assert!(c.has("T.ONE_DUP") && !c.has("T.NOPE"));
        assert_eq!(c.codes()[0], "PERMISSION.CRM.Lead_READ");

        c.add_override("en", "[T.ONE]\naction = \"\"").unwrap();
        let [file, builtin] = c.layers("en", "T.ONE");
        assert!(file.unwrap().text.is_none() && file.unwrap().action.is_some());
        assert!(builtin.unwrap().text.is_some());
        assert!(c.layers("fr", "T.ONE").iter().all(Option::is_none));
        assert!(c.add_builtin("t", "??", EN).is_err());
        assert!(c.add_override("??", EN).is_err());
        assert!(c.add_builtin("u", "en", "[A").is_err());

        c.set_default_locale(Some("pt_br"));
        assert_eq!(c.default_locale(), Some("pt-BR"));
    }

    #[test]
    fn preferred_code_for_a_shared_java_key() {
        let mut c = Catalogue::default();
        c.add_builtin("t", "en", "[S.A]\ntext = \"a\"\njava = \"k\"\n[S.K]\ntext = \"k\"\njava = \"k\"").unwrap();
        assert_eq!(c.code_for_java("S", "k"), Some("S.K"));
    }

    #[test]
    fn override_directory() {
        let dir = std::env::temp_dir().join(format!("platform-msg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("en.toml"), "[T.ONE]\ntext = \"Custom\"").unwrap();
        std::fs::write(dir.join("README.txt"), "ignored").unwrap();
        let mut c = Catalogue::default();
        assert_eq!(c.load_override_dir(&dir).unwrap(), 1);
        assert!(c.files["en"].contains_key("T.ONE"));
        std::fs::write(dir.join("fr.toml"), "[T").unwrap();
        assert!(c.load_override_dir(&dir).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(c.load_override_dir(&dir).unwrap(), 0, "a missing directory overrides nothing");
    }
}
