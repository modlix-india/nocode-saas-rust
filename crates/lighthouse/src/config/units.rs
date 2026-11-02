//! The units' configuration: a port of `tools/render_config.py`'s `Renderer` (`render_unit`,
//! `env_values`, `ai_env_values`, `ssr_env_values`), its files and its report, driven by the
//! manifest (`rust/units.toml`) instead of the script's constants, plus what Lighthouse serves
//! from it: each unit's document (its rendered TOML with its own secrets at their paths) and the
//! document's version.
//!
//! The version is `<restart>.<live>`: a hash of the document without its live keys, then a
//! hash of the live keys. A unit applies a change of the live part in place; a change of the
//! restart part waits for the rolling restart (`keepup-rust.sh health` compares the restart
//! parts). Both hashes cover the secrets, and neither shows anything of them.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::LazyLock;

use anyhow::{anyhow, bail, Result};
use indexmap::IndexMap;
use regex::{Captures, Regex};
use serde_json::{json, Map, Value as Json};
use sha2::{Digest, Sha256};

use super::manifest::{AppVar, Discovery, Kind, Manifest, VarKind};
use super::placeholders::{
    as_kind, or, parse_db_url, quote, spring_text, toml_literal, truthy, JavaSettings, Literal,
};
use super::source::Snapshot;
use super::yaml::Value;

/// Names that a note under `where` lists, in the order they were noted, once each.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Notes(BTreeMap<String, Vec<String>>);

impl Notes {
    fn note(&mut self, place: &str, name: impl Into<String>) {
        let name = name.into();
        let list = self.0.entry(place.to_string()).or_default();
        if !list.contains(&name) {
            list.push(name);
        }
    }

    pub fn total(&self) -> usize {
        self.0.values().map(Vec::len).sum()
    }

    pub fn get(&self, place: &str) -> &[String] {
        self.0.get(place).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn is_empty(&self) -> bool {
        self.total() == 0
    }

    fn report(&self, title: &str, out: &mut String) {
        out.push_str(&format!("{title}: {}\n", self.total()));
        for (place, names) in &self.0 {
            for n in names {
                out.push_str(&format!("  {place}: {n}\n"));
            }
        }
    }
}

static PLACEHOLDER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#""<([A-Za-z][A-Za-z0-9_.:\-]*)>""#).unwrap());
static LEFTOVER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<[A-Za-z][A-Za-z0-9_.:\-]*>").unwrap());
static MONGO_WITH_DB: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^mongodb(\+srv)?://[^/]+/[^/?]+").unwrap());
static SSR_REGION: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^ssr-([a-z0-9]+)\.").unwrap());

/// The script's `Renderer` over one snapshot and one environment.
pub struct Renderer<'a> {
    pub env: String,
    manifest: &'a Manifest,
    java: JavaSettings<'a>,
    snap: &'a Snapshot,
    pub filled: Notes,
    pub defaulted: Notes,
    pub missing: Notes,
    pub optional_empty: Notes,
    defaulted_names: HashSet<(String, String)>,
    /// The notes of `missing` under rust-units.env, by secret.
    secret_missing: BTreeMap<String, Vec<String>>,
    /// Notes of `missing` that only warn (a value ssr-server reads with no variable for it).
    warnings: BTreeSet<(String, String)>,
}

impl<'a> Renderer<'a> {
    pub fn new(snap: &'a Snapshot, manifest: &'a Manifest, env: &str) -> Self {
        Self {
            env: env.to_string(),
            manifest,
            java: JavaSettings::new(snap, env),
            snap,
            filled: Notes::default(),
            defaulted: Notes::default(),
            missing: Notes::default(),
            optional_empty: Notes::default(),
            defaulted_names: HashSet::new(),
            secret_missing: BTreeMap::new(),
            warnings: BTreeSet::new(),
        }
    }

    fn discovery(&self) -> Discovery {
        self.manifest.env.get(&self.env).map_or(Discovery::Alias, |e| e.discovery)
    }

    /// `<urls:target>` as `unit`'s template gets it.
    fn urls(&self, target: &str, unit: &str) -> Result<Literal> {
        let t = self.manifest.unit(target).ok_or_else(|| anyhow!("{unit}.toml: unknown unit in placeholder urls:{target}"))?;
        let for_gateway = self.manifest.unit(unit).is_some_and(|u| u.service == "gateway");
        Ok(Literal::List(match self.discovery() {
            Discovery::Alias => vec![format!("http://{}:{}", t.name, t.port)],
            Discovery::Lighthouse if for_gateway => vec![format!("lighthouse:{}", t.registry_name())],
            Discovery::Lighthouse if self.manifest.gateway_pair.is_empty() => {
                bail!("{unit}.toml: discovery is lighthouse but the manifest has no gateway_pair")
            }
            Discovery::Lighthouse => self.manifest.gateway_pair.clone(),
        }))
    }

    fn db(&mut self, schema: &str, field: &str, place: &str, name: &str) -> Result<Option<Literal>> {
        let prefix = self.manifest.db_prefix[schema].clone();
        let get = |r: &Self, key: String| r.java.get(schema, &key);
        if field == "user" {
            let a = get(self, format!("{prefix}.username"))?;
            let user = match a {
                Some(v) if truthy(&v) => Some(v),
                _ => get(self, format!("{schema}.db.username"))?,
            };
            return Ok(match user.filter(truthy) {
                Some(u) => Some(Literal::Str(spring_text(&u))),
                None => {
                    self.missing.note(place, format!("{name} ({prefix}.username)"));
                    None
                }
            });
        }
        let a = get(self, format!("{prefix}.url"))?;
        let url = match a {
            Some(v) if truthy(&v) => Some(v),
            _ => get(self, format!("{schema}.db.url"))?,
        };
        let Some(url) = url.filter(truthy) else {
            self.missing.note(place, format!("{name} ({prefix}.url)"));
            return Ok(None);
        };
        let Some(parsed) = parse_db_url(&spring_text(&url)) else {
            self.missing.note(place, format!("{name} ({prefix}.url does not read as one mysql://host:port/db)"));
            return Ok(None);
        };
        Ok(Some(match field {
            "host" => Literal::Str(parsed.host),
            "port" => Literal::Int(parsed.port),
            _ => Literal::Str(parsed.name),
        }))
    }

    pub fn placeholder(&mut self, unit: &str, name: &str) -> Result<Option<Literal>> {
        let place = format!("{unit}.toml");
        let service = self.manifest.unit(unit).map(|u| u.service.clone()).ok_or_else(|| anyhow!("unknown unit {unit}"))?;
        if name == "env" {
            return Ok(Some(Literal::Str(self.env.clone())));
        }
        if let Some(target) = name.strip_prefix("urls:") {
            return self.urls(target, unit).map(Some);
        }
        if let Some(rest) = name.strip_prefix("db.") {
            let (field, schema) = rest.split_once(':').unwrap_or((rest, ""));
            if !self.manifest.db_prefix.contains_key(schema) || !matches!(field, "host" | "port" | "name" | "user") {
                bail!("{place}: unknown placeholder {name}");
            }
            return self.db(schema, field, &place, name);
        }
        let Some(setting) = self.manifest.setting(name).cloned() else { bail!("{place}: unknown placeholder {name}") };
        let key = setting.java_key();
        let value = self.java.get(&service, key)?;
        let empty = match &value {
            None => true,
            Some(Value::Str(s)) => s.trim().is_empty(),
            Some(_) => false,
        };
        if empty && setting.required {
            self.missing.note(&place, format!("{name} ({service}: {key})"));
            return Ok(None);
        }
        if value.is_none() || (empty && setting.kind != Kind::Str) {
            // Unset: Spring injects the `@Value` default. Set but empty: a string stays empty.
            self.defaulted.note(&place, format!("{name} ({service}: {key})"));
            self.defaulted_names.insert((place, name.to_string()));
            return Ok(setting.default.as_ref().map(Literal::from_toml));
        }
        let value = value.unwrap_or(Value::Null);
        match as_kind(&value, setting.kind) {
            Some(l) => Ok(Some(l)),
            None => {
                self.missing.note(&place, format!("{name} ({service}: {key} is not a {})", setting.kind.py_name()));
                Ok(None)
            }
        }
    }

    /// The rendered text of `rust/<unit>.toml` and the placeholders left unfilled.
    pub fn render_unit(&mut self, unit: &str) -> Result<(String, Vec<String>)> {
        let path = format!("rust/{unit}.toml");
        let template = self.snap.file(&path).ok_or_else(|| anyhow!("{path} is missing"))?.to_string();
        let mut names = Vec::new();
        let mut unfilled = Vec::new();
        let mut failure = None;
        let text = PLACEHOLDER
            .replace_all(&template, |m: &Captures| {
                let name = m[1].to_string();
                if failure.is_some() {
                    return m[0].to_string();
                }
                match self.placeholder(unit, &name) {
                    Ok(Some(v)) => {
                        names.push(name);
                        toml_literal(&v)
                    }
                    Ok(None) => {
                        unfilled.push(name);
                        m[0].to_string()
                    }
                    Err(e) => {
                        failure = Some(e);
                        m[0].to_string()
                    }
                }
            })
            .into_owned();
        if let Some(e) = failure {
            return Err(e);
        }
        let place = format!("{unit}.toml");
        for n in names {
            if !n.starts_with("urls:") && !n.starts_with("env") && !self.defaulted_names.contains(&(place.clone(), n.clone())) {
                self.filled.note(&place, n);
            }
        }
        Ok((text, unfilled))
    }

    fn first_get(&self, service: &str, keys: [&str; 2]) -> Result<Option<Value>> {
        let a = self.java.get(service, keys[0])?;
        let b = self.java.get(service, keys[1])?;
        Ok(or(a, || b))
    }

    /// The AMQP URI of a service's RabbitMQ settings, or the keys it lacks.
    fn mq_uri(&mut self, service: &str) -> Result<(Option<String>, Vec<&'static str>)> {
        let host = self.first_get(service, ["spring.rabbitmq.host", "mq.host"])?;
        let user = self.first_get(service, ["spring.rabbitmq.username", "mq.username"])?;
        let password = self.first_get(service, ["spring.rabbitmq.password", "mq.password"])?;
        let port = self.first_get(service, ["spring.rabbitmq.port", "mq.port"])?;
        let unset = |v: &Option<Value>| matches!(v, None | Some(Value::Null)) || matches!(v, Some(Value::Str(s)) if s.is_empty());
        let missing: Vec<&'static str> = [("mq.host", &host), ("mq.username", &user), ("mq.password", &password)]
            .into_iter()
            .filter(|(_, v)| unset(v))
            .map(|(k, _)| k)
            .collect();
        if !missing.is_empty() {
            return Ok((None, missing));
        }
        let port = if unset(&port) {
            self.defaulted.note("rust-units.env", "MODLIX__MQ__URI port (mq.port unset: 5672, Spring's default)");
            5672
        } else {
            let text = spring_text(port.as_ref().unwrap_or(&Value::Null));
            super::placeholders::py_int(text.trim()).ok_or_else(|| anyhow!("mq.port of {service} is not a number"))?
        };
        let text = |v: &Option<Value>| spring_text(v.as_ref().unwrap_or(&Value::Null));
        Ok((Some(format!("amqp://{}:{}@{}:{port}/%2F", quote(&text(&user)), quote(&text(&password)), text(&host))), vec![]))
    }

    /// rust-units.env: every secret, in the manifest's order.
    pub fn env_values(&mut self) -> Result<IndexMap<String, String>> {
        let place = "rust-units.env";
        let mut values = IndexMap::new();
        for s in self.manifest.secrets.clone() {
            let value = if s.key == "mq" {
                match self.mq_uri(&s.service)? {
                    (Some(v), _) => Some(v),
                    (None, missing) => {
                        let note = format!("{} ({}: {})", s.name, s.service, missing.join(", "));
                        self.secret_missing.entry(s.name.clone()).or_default().push(note.clone());
                        self.missing.note(place, note);
                        continue;
                    }
                }
            } else {
                self.java.get(&s.service, &s.key)?.map(|v| spring_text(&v))
            };
            let note = format!("{} ({}: {})", s.name, s.service, s.key);
            let value = match value {
                Some(v) if !v.is_empty() => {
                    self.filled.note(place, note);
                    v
                }
                _ if s.required => {
                    self.secret_missing.entry(s.name.clone()).or_default().push(note.clone());
                    self.missing.note(place, note);
                    continue;
                }
                _ => {
                    self.optional_empty.note(place, note);
                    String::new()
                }
            };
            values.insert(s.name.clone(), value);
        }
        let uri = values.get("UI_MONGO_URI").cloned().unwrap_or_default();
        if !uri.is_empty() && !MONGO_WITH_DB.is_match(&uri) {
            let note = "UI_MONGO_URI names no database (ui-* take theirs from the URI)".to_string();
            self.secret_missing.entry("UI_MONGO_URI".into()).or_default().push(note.clone());
            self.missing.note(place, note);
        }
        Ok(values)
    }

    fn kept_unset(&mut self, place: &str, name: &str, keys: &[String], required: bool) {
        let note = format!("{name} ({}: not set, the app's default stays)", keys.join(", "));
        if required {
            self.missing.note(place, note);
        } else {
            self.defaulted.note(place, note);
        }
    }

    /// The first of `keys` config-server sends `service`, with its value.
    fn first_set(&self, service: &str, keys: &[String], first_only: bool) -> Result<Option<(String, Value)>> {
        for k in keys {
            if let Some(v) = self.java.lookup(service, k, first_only)? {
                return Ok(Some((k.clone(), v)));
            }
        }
        Ok(None)
    }

    /// Writes one variable from a config-server value; false when it does not fit `kind`.
    fn put(&mut self, place: &str, values: &mut IndexMap<String, String>, name: &str, hit: &(String, Value), bool_kind: bool) -> bool {
        let (key, value) = hit;
        let value = if bool_kind {
            match as_kind(value, Kind::Bool) {
                Some(Literal::Bool(b)) => Value::Str(if b { "true" } else { "false" }.into()),
                _ => {
                    self.missing.note(place, format!("{name} ({key} is not a boolean)"));
                    return false;
                }
            }
        } else {
            value.clone()
        };
        let text = spring_text(&value);
        let note = format!("{name} ({key})");
        if text.is_empty() {
            self.optional_empty.note(place, note);
        } else {
            self.filled.note(place, note);
        }
        values.insert(name.to_string(), text);
        true
    }

    /// ai.env: what nocode-ai applies from config-server, as the variables it reads.
    pub fn ai_env_values(&mut self) -> Result<IndexMap<String, String>> {
        let place = "ai.env";
        let gateway = self.manifest.gateway_url.clone();
        let mut values = IndexMap::new();
        for var in self.manifest.ai.env.clone() {
            let hit = self.first_set("ai", &var.keys, false)?;
            if var.kind == VarKind::Gateway {
                values.insert(var.name.clone(), gateway.clone());
                let label = match &hit {
                    None => format!("{} not set; written", var.keys[0]),
                    Some((k, _)) => format!("{k},"),
                };
                let note = format!("{} ({label} as {gateway})", var.name);
                if hit.is_some() {
                    self.filled.note(place, note);
                } else {
                    self.defaulted.note(place, note);
                }
                continue;
            }
            if var.only_with.as_ref().is_some_and(|w| !values.contains_key(w)) {
                continue;
            }
            match hit {
                None => self.kept_unset(place, &var.name, &var.keys, var.required),
                Some((k, v)) if var.kind != VarKind::Str && spring_text(&v).is_empty() => {
                    self.optional_empty.note(place, format!("{} ({k})", var.name));
                }
                Some(h) => {
                    self.put(place, &mut values, &var.name, &h, var.kind == VarKind::Bool);
                }
            }
        }
        self.then(&self.manifest.ai.then.clone(), &mut values);
        Ok(values)
    }

    fn then(&self, list: &[super::manifest::Then], values: &mut IndexMap<String, String>) {
        for t in list {
            if t.when.as_ref().is_none_or(|w| values.contains_key(w)) {
                values.insert(t.name.clone(), t.value.clone());
            }
        }
    }

    /// One key group: `ssr-<region>.<key>` falling back to `ssr.<key>`, or a shared key.
    fn ssr_group(&self, group: &str, prefix: &str) -> Result<Option<(String, Value)>> {
        let mut keys = vec![group.replace("{ssr}", prefix)];
        if group.contains("{ssr}") && prefix != "ssr" {
            keys.push(group.replace("{ssr}", "ssr"));
        }
        self.first_set("ssr", &keys, true)
    }

    /// What configLoader.ts takes for one setting: the first group set (`??`), or for `||` the
    /// first group set to a truthy value.
    fn ssr_value(&self, var: &AppVar, prefix: &str) -> Result<Option<(String, Value)>> {
        for group in &var.keys {
            let Some(hit) = self.ssr_group(group, prefix)? else { continue };
            let falsy = match &hit.1 {
                Value::Str(s) => s.is_empty(),
                Value::Bool(b) => !b,
                Value::Int(i) => *i == 0,
                Value::Float(f) => *f == 0.0,
                _ => false,
            };
            if !matches!(var.kind, VarKind::Or | VarKind::Gateway) || !falsy {
                return Ok(Some(hit));
            }
        }
        Ok(None)
    }

    /// ssr.env (or ssr-<region>.env): what configLoader.ts reads from config-server.
    pub fn ssr_env_values(&mut self, region: &str) -> Result<IndexMap<String, String>> {
        let prefix = if region.is_empty() { "ssr".to_string() } else { format!("ssr-{region}") };
        let place = format!("{prefix}.env");
        let gateway = self.manifest.gateway_url.clone();
        let mut values = IndexMap::new();
        for var in self.manifest.ssr.env.clone() {
            let hit = self.ssr_value(&var, &prefix)?;
            if var.kind == VarKind::Gateway && region.is_empty() {
                values.insert(var.name.clone(), gateway.clone());
                let label = match &hit {
                    None => "not set; written".to_string(),
                    Some((k, _)) => format!("{k},"),
                };
                let note = format!("{} ({label} as {gateway})", var.name);
                if hit.is_some() {
                    self.filled.note(&place, note);
                } else {
                    self.defaulted.note(&place, note);
                }
            } else if let Some(h) = hit {
                self.put(&place, &mut values, &var.name, &h, var.kind == VarKind::Bool);
            } else {
                let keys: Vec<String> = var.keys.iter().map(|g| g.replace("{ssr}", &prefix)).collect();
                self.kept_unset(&place, &var.name, &keys, var.required);
            }
        }
        for group in self.manifest.ssr.unmapped.clone() {
            if let Some((k, _)) = self.ssr_group(&group, &prefix)? {
                let note = format!("{k} (read by ssr-server, which reads no environment variable for it)");
                self.warnings.insert((place.clone(), note.clone()));
                self.missing.note(&place, note);
            }
        }
        self.then(&self.manifest.ssr.then.clone(), &mut values);
        Ok(values)
    }

    /// The regions application-oci<env>.yml has an `ssr-<region>` block for.
    pub fn ssr_regions(&self) -> Result<Vec<String>> {
        let set: BTreeSet<String> =
            self.java.first_source("ssr")?.keys().filter_map(|k| SSR_REGION.captures(k).map(|m| m[1].to_string())).collect();
        Ok(set.into_iter().collect())
    }

    /// The required values a file lacks (not the warnings).
    pub fn required_missing(&self, place: &str) -> Vec<String> {
        self.missing.get(place).iter().filter(|n| !self.warnings.contains(&(place.to_string(), (*n).clone()))).cloned().collect()
    }
}

/// `env_line`: a dotenv line docker compose reads literally: single quotes, unless the value
/// has one or a newline.
pub fn env_line(name: &str, value: &str) -> String {
    if !value.contains('\'') && !value.contains('\n') {
        return format!("{name}='{value}'\n");
    }
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"").replace('$', "\\$").replace('\n', "\\n");
    format!("{name}=\"{escaped}\"\n")
}

/// One file the renderer writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct File {
    pub name: String,
    pub text: String,
    pub mode: u32,
}

/// An app's env file: its name (`ai`, `ssr`, `ssr-in`), text and the required values it lacks.
#[derive(Debug, Clone)]
pub struct AppEnv {
    pub name: String,
    pub who: String,
    pub text: String,
    pub missing: Vec<String>,
}

/// Everything the script renders for one environment, in its order.
pub struct Output {
    pub env: String,
    /// Per unit, in the manifest's order: its rendered TOML and what it left unfilled.
    pub units: Vec<(String, String, Vec<String>)>,
    pub secrets: IndexMap<String, String>,
    pub apps: Vec<AppEnv>,
    pub filled: Notes,
    pub defaulted: Notes,
    pub missing: Notes,
    pub optional_empty: Notes,
    /// Missing notes per unit: its TOML's, then those of its secrets.
    pub unit_missing: BTreeMap<String, Vec<String>>,
}

/// Renders everything for `env`, as `tools/render_config.py <dir> <env> <out>` does.
pub fn render(snap: &Snapshot, manifest: &Manifest, env: &str) -> Result<Output> {
    let mut r = Renderer::new(snap, manifest, env);
    let mut units = Vec::new();
    for u in &manifest.units {
        let (text, unfilled) = r.render_unit(&u.name)?;
        units.push((u.name.clone(), text, unfilled));
    }
    let secrets = r.env_values()?;
    let header = |who: &str| format!("# {who}, {env}: rendered by tools/render_config.py from what it read from config-server. Secrets: keep 0600.\n");
    let mut apps = Vec::new();
    let ai = r.ai_env_values()?;
    let ssr = r.ssr_env_values("")?;
    let mut sets = vec![("ai".to_string(), "ai-server".to_string(), ai), ("ssr".to_string(), "ssr-server".to_string(), ssr)];
    for region in r.ssr_regions()? {
        let values = r.ssr_env_values(&region)?;
        sets.push((format!("ssr-{region}"), format!("the ssr-server nodes with SSR_REGION={region}"), values));
    }
    for (name, who, values) in sets {
        let mut text = header(&who);
        for (k, v) in &values {
            text.push_str(&env_line(k, v));
        }
        let missing = r.required_missing(&format!("{name}.env"));
        apps.push(AppEnv { name, who, text, missing });
    }
    let mut unit_missing = BTreeMap::new();
    for u in &manifest.units {
        let mut list: Vec<String> = r.missing.get(&format!("{}.toml", u.name)).to_vec();
        for s in manifest.secrets_of(&u.name) {
            list.extend(r.secret_missing.get(&s.name).cloned().unwrap_or_default());
        }
        unit_missing.insert(u.name.clone(), list);
    }
    Ok(Output {
        env: env.to_string(),
        units,
        secrets,
        apps,
        filled: r.filled,
        defaulted: r.defaulted,
        missing: r.missing,
        optional_empty: r.optional_empty,
        unit_missing,
    })
}

impl Output {
    pub fn secrets_text(&self) -> String {
        let mut text = format!("# Rust units, {}: rendered by tools/render_config.py from the Java settings. Secrets: keep 0600.\n", self.env);
        for (k, v) in &self.secrets {
            text.push_str(&env_line(k, v));
        }
        text
    }

    /// The files, in the order the script writes them, with their modes.
    pub fn files(&self) -> Vec<File> {
        let mut out: Vec<File> =
            self.units.iter().map(|(u, text, _)| File { name: format!("{u}.toml"), text: text.clone(), mode: 0o644 }).collect();
        out.push(File { name: "rust-units.env".into(), text: self.secrets_text(), mode: 0o600 });
        for a in &self.apps {
            out.push(File { name: format!("{}.env", a.name), text: a.text.clone(), mode: 0o600 });
        }
        out
    }

    /// `check_output` over every file: only template names and counts, never a value.
    pub fn problems(&self) -> Vec<String> {
        let mut problems = Vec::new();
        for f in self.files() {
            let unfilled = self.units.iter().find(|(u, _, _)| format!("{u}.toml") == f.name).map(|(_, _, un)| un.clone()).unwrap_or_default();
            if !unfilled.is_empty() {
                let set: BTreeSet<&String> = unfilled.iter().collect();
                let names: Vec<&str> = set.into_iter().map(String::as_str).collect();
                problems.push(format!("{}: placeholders left unfilled: {}", f.name, names.join(", ")));
            }
            let left = LEFTOVER.find_iter(&f.text).count();
            if left > 0 && unfilled.is_empty() {
                problems.push(format!("{}: {left} text(s) shaped like a placeholder remain", f.name));
            }
            if f.name.ends_with(".toml") {
                if let Err(e) = f.text.parse::<toml::Table>() {
                    let line = e.span().map_or("?".to_string(), |s| (f.text[..s.start].matches('\n').count() + 1).to_string());
                    problems.push(format!("{}: does not parse as TOML (TOMLDecodeError at line {line})", f.name));
                }
            }
        }
        problems
    }

    /// The script's report: what was filled, defaulted, empty and missing, by name only.
    pub fn report(&self, out_dir: &str) -> String {
        let apps: Vec<String> = self.apps.iter().map(|a| format!("{}.env", a.name)).collect();
        let mut out = format!(
            "Rendered {} unit configs, rust-units.env and {} for {} into {out_dir} (TOMLs 0644, env files 0600).\n",
            self.units.len(),
            apps.join(", "),
            self.env
        );
        self.filled.report("Filled from the Java settings", &mut out);
        self.defaulted.report("Not set in the Java settings, Java's default used", &mut out);
        self.optional_empty.report("Optional and empty in the Java settings", &mut out);
        self.missing.report("REQUIRED and not found", &mut out);
        let problems = self.problems();
        if !problems.is_empty() {
            out.push_str(&format!("Problems: {}\n", problems.len()));
            for p in problems {
                out.push_str(&format!("  {p}\n"));
            }
        }
        out
    }

    /// The script's exit status: 1 when a required value is missing or a file has a problem.
    pub fn failed(&self) -> bool {
        !self.missing.is_empty() || !self.problems().is_empty()
    }
}

/// A unit's document as Lighthouse serves it.
#[derive(Debug, Clone, PartialEq)]
pub struct UnitDoc {
    pub unit: String,
    pub document: Json,
    pub version: String,
    pub live: Vec<String>,
    /// Where its secrets sit in the document, and their names in rust-units.env.
    pub secrets: Vec<(String, String)>,
}

/// A unit's configuration, or why there is none.
#[derive(Debug, Clone, PartialEq)]
pub enum UnitState {
    Ready(UnitDoc),
    /// Required values are missing: their names (never values).
    Missing(Vec<String>),
    /// The rendered TOML does not parse, or a secret does not fit the document.
    Invalid(String),
}

/// The documents of every unit of one environment.
pub fn documents(out: &Output, manifest: &Manifest) -> Vec<(String, UnitState)> {
    out.units
        .iter()
        .map(|(unit, text, _)| {
            let missing = out.unit_missing.get(unit).cloned().unwrap_or_default();
            let state = if missing.is_empty() { unit_doc(unit, text, out, manifest) } else { UnitState::Missing(missing) };
            (unit.clone(), state)
        })
        .collect()
}

fn unit_doc(unit: &str, text: &str, out: &Output, manifest: &Manifest) -> UnitState {
    let table: toml::Table = match text.parse() {
        Ok(t) => t,
        Err(_) => return UnitState::Invalid(format!("{unit}.toml does not parse as TOML")),
    };
    let mut document = toml_to_json(&toml::Value::Table(table));
    let mut secrets = Vec::new();
    for s in manifest.secrets_of(unit) {
        let Some(v) = out.secrets.get(&s.name) else { continue };
        if let Err(e) = set_path(&mut document, &s.path, Json::String(v.clone())) {
            return UnitState::Invalid(format!("secret {} does not fit {unit}'s document: {e}", s.name));
        }
        secrets.push((s.path.clone(), s.name.clone()));
    }
    let live = manifest.live_of(unit);
    let version = version(&document, &live);
    UnitState::Ready(UnitDoc { unit: unit.to_string(), document, version, live, secrets })
}

pub fn toml_to_json(v: &toml::Value) -> Json {
    match v {
        toml::Value::String(s) => Json::String(s.clone()),
        toml::Value::Integer(i) => json!(i),
        toml::Value::Float(f) => serde_json::Number::from_f64(*f).map_or_else(|| Json::String(f.to_string()), Json::Number),
        toml::Value::Boolean(b) => Json::Bool(*b),
        toml::Value::Datetime(d) => Json::String(d.to_string()),
        toml::Value::Array(items) => Json::Array(items.iter().map(toml_to_json).collect()),
        toml::Value::Table(t) => Json::Object(t.iter().map(|(k, v)| (k.clone(), toml_to_json(v))).collect()),
    }
}

/// Sets a dotted path, making the tables on the way.
pub fn set_path(doc: &mut Json, path: &str, value: Json) -> Result<()> {
    let parts: Vec<&str> = path.split('.').collect();
    let mut cur = doc;
    for p in &parts[..parts.len() - 1] {
        let obj = cur.as_object_mut().ok_or_else(|| anyhow!("{p} is not a table"))?;
        cur = obj.entry(p.to_string()).or_insert_with(|| Json::Object(Map::new()));
    }
    let obj = cur.as_object_mut().ok_or_else(|| anyhow!("the parent of {path} is not a table"))?;
    obj.insert(parts[parts.len() - 1].to_string(), value);
    Ok(())
}

/// Removes a dotted path and returns what was there.
pub fn take_path(doc: &mut Json, path: &str) -> Option<Json> {
    let parts: Vec<&str> = path.split('.').collect();
    let mut cur = doc;
    for p in &parts[..parts.len() - 1] {
        cur = cur.as_object_mut()?.get_mut(*p)?;
    }
    cur.as_object_mut()?.remove(parts[parts.len() - 1])
}

pub fn get_path<'j>(doc: &'j Json, path: &str) -> Option<&'j Json> {
    path.split('.').try_fold(doc, |cur, p| cur.as_object()?.get(p))
}

/// JSON with sorted keys and no spaces, the same whatever serde_json's features: what the
/// versions hash.
pub fn canonical(v: &Json) -> String {
    let mut out = String::new();
    write_canonical(v, &mut out);
    out
}

fn write_canonical(v: &Json, out: &mut String) {
    match v {
        Json::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Json::String((*k).clone()).to_string());
                out.push(':');
                write_canonical(&m[*k], out);
            }
            out.push('}');
        }
        Json::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

fn sha_hex(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

/// `<restart>.<live>`: 16 hex characters of the document without its live keys, 8 of the live
/// keys' values.
pub fn version(document: &Json, live: &[String]) -> String {
    let mut rest = document.clone();
    let mut live_part = Map::new();
    for key in live {
        live_part.insert(key.clone(), take_path(&mut rest, key).unwrap_or(Json::Null));
    }
    format!("{}.{}", &sha_hex(&canonical(&rest))[..16], &sha_hex(&canonical(&Json::Object(live_part)))[..8])
}

/// The part of a version a running unit must restart for.
pub fn restart_part(version: &str) -> &str {
    version.split('.').next().unwrap_or(version)
}

/// The document as TOML, its secrets replaced with `<redacted>` when asked.
pub fn document_toml(doc: &UnitDoc, redact: bool) -> Result<String> {
    let mut d = doc.document.clone();
    if redact {
        for (p, _) in &doc.secrets {
            set_path(&mut d, p, Json::String("<redacted>".into()))?;
        }
    }
    let value = json_to_toml(&d).ok_or_else(|| anyhow!("the document is not a table"))?;
    Ok(toml::to_string(&value)?)
}

pub fn json_to_toml(v: &Json) -> Option<toml::Value> {
    Some(match v {
        Json::Null => return None,
        Json::Bool(b) => toml::Value::Boolean(*b),
        Json::Number(n) => n.as_i64().map_or_else(|| toml::Value::Float(n.as_f64().unwrap_or(0.0)), toml::Value::Integer),
        Json::String(s) => toml::Value::String(s.clone()),
        Json::Array(items) => toml::Value::Array(items.iter().filter_map(json_to_toml).collect()),
        Json::Object(m) => toml::Value::Table(m.iter().filter_map(|(k, v)| json_to_toml(v).map(|t| (k.clone(), t))).collect()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_lines() {
        assert_eq!(env_line("A", "plain $x \"q\""), "A='plain $x \"q\"'\n");
        assert_eq!(env_line("A", "it's"), "A=\"it's\"\n");
        assert_eq!(env_line("A", "a\nb\\ $c \"d\""), "A=\"a\\nb\\\\ \\$c \\\"d\\\"\"\n");
    }

    #[test]
    fn versions_split_live_keys() {
        let doc = json!({"server": {"port": 1}, "telemetry": {"log_level": "info"}, "routes": [1]});
        let live = vec!["telemetry.log_level".to_string(), "routes".to_string(), "features".to_string()];
        let v1 = version(&doc, &live);
        let mut d2 = doc.clone();
        set_path(&mut d2, "telemetry.log_level", json!("debug")).unwrap();
        let v2 = version(&d2, &live);
        assert_eq!(restart_part(&v1), restart_part(&v2), "a live change keeps the restart part");
        assert_ne!(v1, v2);
        let mut d3 = doc.clone();
        set_path(&mut d3, "server.port", json!(2)).unwrap();
        assert_ne!(restart_part(&version(&d3, &live)), restart_part(&v1));
        assert_eq!(v1.len(), 16 + 1 + 8);
        assert_eq!(restart_part("abc"), "abc");
    }

    #[test]
    fn paths_and_canonical_json() {
        let mut d = json!({"a": {"b": 1}, "z": [{"y": 1, "x": 2}]});
        set_path(&mut d, "c.d.e", json!("v")).unwrap();
        assert_eq!(get_path(&d, "c.d.e"), Some(&json!("v")));
        assert!(set_path(&mut d, "a.b.c", json!(1)).is_err());
        assert!(set_path(&mut d, "z.q", json!(1)).is_err());
        assert_eq!(take_path(&mut d, "a.b"), Some(json!(1)));
        assert_eq!(take_path(&mut d, "a.nope.x"), None);
        assert_eq!(canonical(&d), r#"{"a":{},"c":{"d":{"e":"v"}},"z":[{"x":2,"y":1}]}"#);
        assert_eq!(canonical(&json!({"b": "\"", "a": 1.5, "c": null, "d": true})), r#"{"a":1.5,"b":"\"","c":null,"d":true}"#);
    }

    #[test]
    fn documents_as_toml() {
        let doc = UnitDoc {
            unit: "u".into(),
            document: json!({"database": {"password": "s3cret", "host": "h"}, "n": null, "list": [1, null], "f": 1.5}),
            version: "v".into(),
            live: vec![],
            secrets: vec![("database.password".into(), "DB".into())],
        };
        let redacted = document_toml(&doc, true).unwrap();
        assert!(redacted.contains("password = \"<redacted>\"") && !redacted.contains("s3cret"));
        assert!(document_toml(&doc, false).unwrap().contains("s3cret"));
        assert!(json_to_toml(&json!([1])).is_some());
        let bad = UnitDoc { document: json!([1]), ..doc.clone() };
        assert!(document_toml(&UnitDoc { secrets: vec![], ..bad }, false).is_err());
        assert_eq!(toml_to_json(&toml::Value::Float(f64::NAN)), json!("NaN"));
        let dt: toml::Value = "a = 1979-05-27T07:32:00Z".parse::<toml::Table>().unwrap()["a"].clone();
        assert_eq!(toml_to_json(&dt), json!("1979-05-27T07:32:00Z"));
    }

    const MANIFEST: &str = include_str!("../../tests/fixtures/oci-config/rust/units.toml");

    /// A small oci-config: every unit's template trivial unless given.
    fn snapshot(manifest: &str, yml: &[(&str, &str)], templates: &[(&str, &str)]) -> Snapshot {
        let m = Manifest::parse(manifest).unwrap();
        let mut files: BTreeMap<String, String> = m.units.iter().map(|u| (format!("rust/{}.toml", u.name), "[server]\nport = 1\n".into())).collect();
        files.insert("rust/units.toml".into(), manifest.into());
        for (p, t) in yml {
            files.insert(p.to_string(), t.to_string());
        }
        for (u, t) in templates {
            files.insert(format!("rust/{u}.toml"), t.to_string());
        }
        Snapshot::new("sha", "master", "dir:/x", files)
    }

    fn rendered(snap: &Snapshot) -> Result<Output> {
        let m = Manifest::parse(snap.file("rust/units.toml").unwrap()).unwrap();
        render(snap, &m, "dev")
    }

    #[test]
    fn discovery_through_lighthouse() {
        let lh = MANIFEST.replacen("[env.dev]\ndiscovery = \"alias\"", "[env.dev]\ndiscovery = \"lighthouse\"", 1);
        let templates = [("gateway-rust", "[a]\nu = \"<urls:multi>\"\n"), ("multi", "[a]\nu = \"<urls:core-exec>\"\n")];
        let out = rendered(&snapshot(&lh, &[], &templates)).unwrap();
        let text = |u: &str| out.units.iter().find(|(n, _, _)| n == u).unwrap().1.clone();
        assert_eq!(text("gateway-rust"), "[a]\nu = [\"lighthouse:MULTI\"]\n");
        assert_eq!(text("multi"), "[a]\nu = [\"http://gateway-1:8080\", \"http://gateway-2:8080\"]\n");
        let no_pair = lh.replacen("gateway_pair = [\"http://gateway-1:8080\", \"http://gateway-2:8080\"]", "gateway_pair = []", 1);
        let e = rendered(&snapshot(&no_pair, &[], &templates)).err().unwrap();
        assert!(e.to_string().contains("no gateway_pair"), "{e}");
        let unknown = rendered(&snapshot(MANIFEST, &[], &[("multi", "u = \"<urls:nope>\"\n")])).err().unwrap();
        assert!(unknown.to_string().contains("unknown unit in placeholder urls:nope"));
        for bad in ["\"<nope>\"", "\"<db.host:nope>\"", "\"<db.size:core>\""] {
            let e = rendered(&snapshot(MANIFEST, &[], &[("multi", &format!("u = {bad}\n"))])).err().unwrap();
            assert!(e.to_string().contains("unknown placeholder"), "{bad}: {e}");
        }
        let (snap, m) = (snapshot(MANIFEST, &[], &[]), Manifest::parse(MANIFEST).unwrap());
        let mut r = Renderer::new(&snap, &m, "dev");
        assert!(r.placeholder("nope", "env").is_err());
    }

    #[test]
    fn what_is_missing_and_what_does_not_parse() {
        let yml = [
            ("application.yml", "notification:\n  db:\n    url: jdbc:mysql://n:1/x\n"),
            ("application-ocidev.yml", "redis:\n  url: ''\n"),
        ];
        let templates = [
            ("notification", "[database]\nhost = \"<db.host:notification>\"\nuser = \"<db.user:notification>\"\n"),
            ("core-exec", "[database]\nhost = \"<db.host:core>\"\n"),
            ("multi", "# a <leftover> text\n[server]\nport = 1\n"),
            ("ui-shell", "[server\nport = 1\n"),
            ("gateway-rust", "redis = \"not a table\"\n"),
        ];
        let out = rendered(&snapshot(MANIFEST, &yml, &templates)).unwrap();
        assert!(out.missing.get("notification.toml").contains(&"db.user:notification (spring.datasource.username)".to_string()));
        assert_eq!(out.missing.get("core-exec.toml"), ["db.host:core (spring.r2dbc.url)"]);
        let env = out.missing.get("rust-units.env");
        assert!(env.contains(&"MODLIX__MQ__URI (core: mq.host, mq.username, mq.password)".to_string()), "{env:?}");
        assert!(env.contains(&"MODLIX__REDIS__URL (gateway: redis.url)".to_string()), "{env:?}");
        let problems = out.problems();
        assert!(problems.contains(&"multi.toml: 1 text(s) shaped like a placeholder remain".to_string()), "{problems:?}");
        assert!(problems.iter().any(|p| p.starts_with("ui-shell.toml: does not parse as TOML (TOMLDecodeError at line 1)")), "{problems:?}");
        let m = Manifest::parse(MANIFEST).unwrap();
        let docs = documents(&out, &m);
        let state = |u: &str| docs.iter().find(|(n, _)| n == u).unwrap().1.clone();
        assert!(matches!(state("ui-shell"), UnitState::Missing(_)), "ui-shell lacks its Mongo URI first");
        assert!(matches!(state("multi"), UnitState::Ready(_)));
        assert!(matches!(state("core-exec"), UnitState::Missing(_)));

        // With every secret present, a TOML that does not parse and a secret that does not fit.
        let mut full = out;
        full.unit_missing.values_mut().for_each(Vec::clear);
        full.secrets.insert("MODLIX__REDIS__URL".into(), "redis://x".into());
        let docs = documents(&full, &m);
        let state = |u: &str| docs.iter().find(|(n, _)| n == u).unwrap().1.clone();
        assert_eq!(state("ui-shell"), UnitState::Invalid("ui-shell.toml does not parse as TOML".into()));
        assert!(matches!(state("gateway-rust"), UnitState::Invalid(e) if e.contains("does not fit")));
    }

    #[test]
    fn ssr_falsy_values() {
        let yml = [("application-ocidev.yml", "ssr:\n  redis:\n    url: [a]\n  cache:\n    ttlSeconds: 0.0\n")];
        let snap = snapshot(MANIFEST, &yml, &[]);
        let m = Manifest::parse(MANIFEST).unwrap();
        let mut r = Renderer::new(&snap, &m, "dev");
        let values = r.ssr_env_values("").unwrap();
        assert!(!values.contains_key("CACHE_TTL_SECONDS"), "0.0 is falsy for ||");
        assert!(!values.contains_key("REDIS_URL"), "a list is no value: it does not flatten to the key");
    }

    #[test]
    fn notes_keep_order_and_count_once() {
        let mut n = Notes::default();
        n.note("b", "x");
        n.note("a", "y");
        n.note("b", "x");
        n.note("b", "w");
        assert_eq!(n.total(), 3);
        assert_eq!(n.get("b"), ["x", "w"]);
        assert!(n.get("c").is_empty() && !n.is_empty());
        let mut out = String::new();
        n.report("T", &mut out);
        assert_eq!(out, "T: 3\n  a: y\n  b: x\n  b: w\n");
    }
}
