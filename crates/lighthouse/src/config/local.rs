//! The local stack's configuration: `[config] env = "local"`.
//!
//! On a laptop there is no oci-config environment to render. Each unit's document is its own
//! `config/<unit>.toml`, and ai's and ssr's are `config/ai.toml` and `config/ssr.toml` (their
//! Spring settings as TOML). The passwords and keys of all of them live in one git-ignored file,
//! `config/local.toml`, in the same shape:
//!
//! - `[units.<section>]`: merged into every Rust unit's document (`[units.database] password`
//!   is every unit's `database.password`).
//! - `[ai]`, `[ssr]`: merged into that app's settings, as Spring keys (`ai.db.password = ...`).
//! - `[lighthouse]`: what tools/run-local.sh reads (the admin token); merged into nothing.
//!
//! The units start with no TOML file and no secrets of their own: only `LIGHTHOUSE_URLS` and a
//! token. ai and ssr read their settings from the Spring endpoint (`/ai/default`,
//! `/ssr/default`), built from their documents.
//!
//! The files are read on every poll into the snapshot under `local/`, so a change to one of them
//! changes the snapshot's sha and the versions of what it feeds, as a commit does on a host.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as Json};

use super::units::{get_path, set_path, toml_to_json, version, AppEnv, UnitDoc, UnitState};

/// Where the local files sit in a snapshot.
pub const PREFIX: &str = "local/";
const SECRETS_FILE: &str = "local/secrets.toml";
/// The table of `config/local.toml` merged into every unit.
const UNITS_TABLE: &str = "units";

/// `[config.local]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LocalConfig {
    /// The directory of the TOML files. Set: the deployment is the local stack.
    pub dir: String,
    /// The passwords and keys (`config/local.toml`), merged as the module says.
    pub secrets_file: String,
    /// The Rust units served, in the dashboard's order.
    pub units: Vec<String>,
    /// The apps that read Spring settings (`ai`, `ssr`): `<dir>/<app>.toml`, served at
    /// `/<app>/<profile>` and listed with the units.
    pub apps: Vec<String>,
    /// A unit whose file is not `<unit>.toml`, by unit.
    pub files: BTreeMap<String, String>,
    /// Keys every unit applies in place (as `live` in oci-config's `rust/units.toml`).
    pub live: Vec<String>,
    /// More live keys, by unit.
    pub unit_live: BTreeMap<String, Vec<String>>,
}

impl LocalConfig {
    pub fn enabled(&self) -> bool {
        !self.dir.trim().is_empty()
    }

    fn file_of(&self, unit: &str) -> String {
        self.files.get(unit).cloned().unwrap_or_else(|| format!("{unit}.toml"))
    }

    fn live_of(&self, unit: &str) -> Vec<String> {
        let mut keys = self.live.clone();
        keys.extend(self.unit_live.get(unit).into_iter().flatten().cloned());
        keys
    }

    pub fn is_app(&self, name: &str) -> bool {
        self.apps.iter().any(|a| a == name)
    }

    /// The local files as snapshot entries: `local/units/<unit>.toml`, `local/apps/<app>.toml`
    /// for each one that exists, and `local/secrets.toml`.
    pub fn read(&self) -> Result<BTreeMap<String, String>> {
        let dir = Path::new(self.dir.trim());
        let mut files = BTreeMap::new();
        let wanted = self
            .units
            .iter()
            .map(|u| (dir.join(self.file_of(u)), format!("{PREFIX}units/{u}.toml")))
            .chain(self.apps.iter().map(|a| (dir.join(format!("{a}.toml")), format!("{PREFIX}apps/{a}.toml"))));
        let secrets = Some(self.secrets_file.trim()).filter(|s| !s.is_empty()).map(|s| (Path::new(s).to_path_buf(), SECRETS_FILE.to_string()));
        for (path, key) in wanted.chain(secrets) {
            match std::fs::read_to_string(&path) {
                Ok(text) => {
                    files.insert(key, text);
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e).with_context(|| format!("{} cannot be read", path.display())),
            }
        }
        Ok(files)
    }

    /// The document of every unit, then of every app, from a snapshot holding
    /// [`LocalConfig::read`]'s files, and their names in the registry (a unit's
    /// `[eureka] register_as`, else the name in capitals).
    pub fn documents(&self, files: &BTreeMap<String, String>) -> (Vec<(String, UnitState)>, Vec<(String, String)>) {
        let secrets = match files.get(SECRETS_FILE).map(|t| t.parse::<toml::Table>()) {
            None => Ok(Json::Object(Map::new())),
            Some(Ok(t)) => Ok(toml_to_json(&toml::Value::Table(t))),
            Some(Err(_)) => Err(format!("{} does not parse as TOML", self.secrets_file)),
        };
        let mut out = Vec::new();
        let mut names = Vec::new();
        let entries = self
            .units
            .iter()
            .map(|u| (u, format!("{PREFIX}units/{u}.toml"), self.file_of(u), UNITS_TABLE, self.live_of(u)))
            .chain(self.apps.iter().map(|a| (a, format!("{PREFIX}apps/{a}.toml"), format!("{a}.toml"), a.as_str(), vec![])));
        for (name, key, file, table, live) in entries {
            let state = match (&secrets, files.get(&key)) {
                (Err(e), _) => UnitState::Invalid(e.clone()),
                (_, None) => UnitState::Invalid(format!("{file} is missing in {}", self.dir)),
                (Ok(s), Some(text)) => document(name, &file, text, s.get(table), live),
            };
            let registry = match &state {
                UnitState::Ready(d) if !self.is_app(name) => {
                    get_path(&d.document, "eureka.register_as").and_then(Json::as_str).filter(|s| !s.is_empty()).map(str::to_string)
                }
                _ => None,
            };
            names.push((name.clone(), registry.unwrap_or_else(|| name.to_ascii_uppercase())));
            out.push((name.clone(), state));
        }
        (out, names)
    }
}

/// `[config] layout = "repo"`: one environment's folder of a repository such as
/// oci-config-rust (the source URL names it; the snapshot holds its files relative to it):
///
/// - `units/<unit>.toml`: each unit's whole document, secrets inline (the repository is
///   private). The units are the files there, in `[config.local] units` order first.
/// - `apps/<app>.toml`: an app's Spring settings, served at `/<app>/<profile>`.
/// - `apps/<name>.env`: an env file, served at `GET /v1/env/<name>` (`ssr-in.env` as
///   `/v1/env/ssr?region=in`).
///
/// - `live.toml`: the keys units apply in place (`live = [...]`, and per unit under `[units]`);
///   without it, `[config.local]`'s `live` and `unit_live`.
///
/// `[config.local] units` orders them; its `dir` and `secrets_file` are not used.
pub fn repo_documents(local: &LocalConfig, files: &BTreeMap<String, String>) -> (Vec<(String, UnitState)>, Vec<(String, String)>, Vec<AppEnv>) {
    let in_dir = |dir: &str, ext: &str| -> Vec<(String, String)> {
        let prefix = format!("{dir}/");
        files
            .iter()
            .filter_map(|(k, v)| {
                let name = k.strip_prefix(&prefix)?.strip_suffix(ext)?;
                (!name.is_empty() && !name.contains('/')).then(|| (name.to_string(), v.clone()))
            })
            .collect()
    };
    let units = in_dir("units", ".toml");
    let apps = in_dir("apps", ".toml");
    let mut order: Vec<String> = local.units.iter().filter(|u| units.iter().any(|(n, _)| n == *u)).cloned().collect();
    let mut rest: Vec<String> = units.iter().map(|(n, _)| n.clone()).filter(|n| !order.contains(n)).collect();
    rest.sort();
    order.extend(rest);
    let mut mapped = BTreeMap::new();
    for (name, text) in &units {
        mapped.insert(format!("{PREFIX}units/{name}.toml"), text.clone());
    }
    for (name, text) in &apps {
        mapped.insert(format!("{PREFIX}apps/{name}.toml"), text.clone());
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Live {
        live: Vec<String>,
        units: BTreeMap<String, Vec<String>>,
    }
    let (live, unit_live) = match files.get("live.toml").map(|t| toml::from_str::<Live>(t)) {
        Some(Ok(l)) => (l.live, l.units),
        Some(Err(e)) => {
            tracing::warn!(error = %e, "live.toml does not parse: no live keys");
            (vec![], BTreeMap::new())
        }
        None => (local.live.clone(), local.unit_live.clone()),
    };
    let view = LocalConfig {
        dir: "the repository".into(),
        secrets_file: String::new(),
        units: order,
        apps: apps.iter().map(|(n, _)| n.clone()).collect(),
        files: BTreeMap::new(),
        live,
        unit_live,
    };
    let (docs, names) = view.documents(&mapped);
    let envs = in_dir("apps", ".env").into_iter().map(|(name, text)| AppEnv { who: name.clone(), name, text, missing: vec![] }).collect();
    (docs, names, envs)
}

/// `file`'s document with `overlay` (its table of `config/local.toml`) merged in.
fn document(name: &str, file: &str, text: &str, overlay: Option<&Json>, live: Vec<String>) -> UnitState {
    let table: toml::Table = match text.parse() {
        Ok(t) => t,
        Err(_) => return UnitState::Invalid(format!("{file} does not parse as TOML")),
    };
    let mut document = toml_to_json(&toml::Value::Table(table));
    let mut secrets = Vec::new();
    if let Some(overlay) = overlay {
        let mut leaves = Vec::new();
        leaf_paths(overlay, "", &mut leaves);
        for (path, value) in leaves {
            if let Err(e) = set_path(&mut document, &path, value) {
                return UnitState::Invalid(format!("local.toml's {path} does not fit {name}'s document: {e}"));
            }
            secrets.push((path, "local.toml".to_string()));
        }
    }
    let version = version(&document, &live);
    UnitState::Ready(UnitDoc { unit: name.to_string(), document, version, live, secrets })
}

/// Every leaf (a non-table value) of a table, with its dotted path.
fn leaf_paths(v: &Json, prefix: &str, out: &mut Vec<(String, Json)>) {
    match v {
        Json::Object(m) => {
            for (k, v) in m {
                let path = if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
                leaf_paths(v, &path, out);
            }
        }
        other if !prefix.is_empty() => out.push((prefix.to_string(), other.clone())),
        _ => {}
    }
}

/// A document as Spring flattens settings: `a.b.c`, lists as `a[0]`, values typed.
pub fn spring_keys(doc: &Json) -> Result<indexmap::IndexMap<String, super::yaml::Value>> {
    use super::yaml::Value;
    fn walk(v: &Json, prefix: &str, out: &mut indexmap::IndexMap<String, Value>) -> Result<()> {
        match v {
            Json::Object(m) => {
                for (k, v) in m {
                    walk(v, &if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") }, out)?;
                }
            }
            Json::Array(items) => {
                for (i, v) in items.iter().enumerate() {
                    walk(v, &format!("{prefix}[{i}]"), out)?;
                }
            }
            Json::Null => {
                out.insert(prefix.to_string(), Value::Null);
            }
            Json::Bool(b) => {
                out.insert(prefix.to_string(), Value::Bool(*b));
            }
            Json::Number(n) => {
                let value = match (n.as_i64(), n.as_f64()) {
                    (Some(i), _) => Value::Int(i128::from(i)),
                    (None, Some(f)) => Value::Float(f),
                    _ => return Err(anyhow!("{prefix} is not a number Spring can carry")),
                };
                out.insert(prefix.to_string(), value);
            }
            Json::String(s) => {
                out.insert(prefix.to_string(), Value::Str(s.clone()));
            }
        }
        Ok(())
    }
    let mut out = indexmap::IndexMap::new();
    walk(doc, "", &mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::units::restart_part;
    use crate::config::yaml::Value;

    fn tempdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("lighthouse-local-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn cfg(dir: &str) -> LocalConfig {
        LocalConfig {
            dir: dir.into(),
            secrets_file: format!("{dir}/local.toml"),
            units: vec!["security-auth".into(), "gateway-rust".into(), "gone".into()],
            apps: vec!["ai".into()],
            files: [("gateway-rust".to_string(), "gateway-rust-allrust.toml".to_string())].into(),
            live: vec!["telemetry.log_level".into()],
            unit_live: [("gateway-rust".to_string(), vec!["routes".to_string()])].into(),
        }
    }

    const SECRETS: &str = "[lighthouse]\nadmin_token = \"t\"\n[units.database]\npassword = \"pw\"\n[ai]\nai.db.password = \"aipw\"\n";

    #[test]
    fn documents_from_the_local_files() {
        let d = tempdir("docs");
        std::fs::write(d.join("security-auth.toml"), "[server]\nport = 8101\n[telemetry]\nlog_level = \"info\"\n[eureka]\nregister_as = \"SECURITY-AUTH\"\n").unwrap();
        std::fs::write(d.join("gateway-rust-allrust.toml"), "[server]\nport = 8080\nroutes = 1\n").unwrap();
        std::fs::write(d.join("ai.toml"), "[ai.db]\nurl = \"mysql://h/ai\"\n[redis]\ncodec = \"string\"\n").unwrap();
        std::fs::write(d.join("local.toml"), SECRETS).unwrap();
        let c = cfg(d.to_str().unwrap());
        assert!(c.enabled() && !LocalConfig::default().enabled() && c.is_app("ai") && !c.is_app("gone"));
        let files = c.read().unwrap();
        assert_eq!(
            files.keys().collect::<Vec<_>>(),
            ["local/apps/ai.toml", "local/secrets.toml", "local/units/gateway-rust.toml", "local/units/security-auth.toml"]
        );
        let (docs, names) = c.documents(&files);
        assert_eq!(
            names,
            [
                ("security-auth".into(), "SECURITY-AUTH".into()),
                ("gateway-rust".into(), "GATEWAY-RUST".into()),
                ("gone".into(), "GONE".into()),
                ("ai".into(), "AI".into())
            ]
        );
        let UnitState::Ready(auth) = &docs[0].1 else { panic!("{:?}", docs[0].1) };
        assert_eq!((auth.document["server"]["port"].as_i64(), auth.document["database"]["password"].as_str()), (Some(8101), Some("pw")));
        assert!(auth.document.get("lighthouse").is_none() && auth.document.get("ai").is_none(), "only [units] reaches a unit");
        assert_eq!(auth.secrets, [("database.password".to_string(), "local.toml".to_string())]);
        let UnitState::Ready(gw) = &docs[1].1 else { panic!() };
        assert_eq!(gw.live.len(), 2);
        assert!(matches!(&docs[2].1, UnitState::Invalid(e) if e.contains("gone.toml is missing")));
        let UnitState::Ready(ai) = &docs[3].1 else { panic!() };
        assert_eq!(ai.document["ai"]["db"]["password"], "aipw");
        assert!(ai.document.get("database").is_none() && ai.live.is_empty());

        // A live key's change keeps the restart part; any other change does not.
        let mut f2 = files.clone();
        f2.insert("local/units/security-auth.toml".into(), files["local/units/security-auth.toml"].replace("\"info\"", "\"debug\""));
        let UnitState::Ready(a2) = &c.documents(&f2).0[0].1 else { panic!() };
        assert_eq!(restart_part(&a2.version), restart_part(&auth.version));
        assert_ne!(a2.version, auth.version);
        f2.insert("local/secrets.toml".into(), SECRETS.replace("\"pw\"", "\"other\""));
        let UnitState::Ready(a3) = &c.documents(&f2).0[0].1 else { panic!() };
        assert_ne!(restart_part(&a3.version), restart_part(&auth.version));

        f2.insert("local/units/security-auth.toml".into(), "[server\n".into());
        assert!(matches!(&c.documents(&f2).0[0].1, UnitState::Invalid(e) if e.contains("does not parse")));
        f2.insert("local/units/security-auth.toml".into(), "database = 1\n".into());
        assert!(matches!(&c.documents(&f2).0[0].1, UnitState::Invalid(e) if e.contains("does not fit")));
        f2.insert("local/secrets.toml".into(), "[units\n".into());
        assert!(c.documents(&f2).0.iter().all(|(_, s)| matches!(s, UnitState::Invalid(e) if e.contains("local.toml does not parse"))));
    }

    #[test]
    fn read_without_a_secrets_file_or_with_an_unreadable_one() {
        let tmp = tempdir("read");
        let mut c = cfg(tmp.to_str().unwrap());
        assert!(c.read().unwrap().is_empty());
        c.secrets_file = tmp.to_str().unwrap().to_string();
        assert!(c.read().is_err(), "a directory is not a file");
    }

    #[test]
    fn a_repository_folder_is_read() {
        let mut files = BTreeMap::new();
        for (k, v) in [
            ("units/multi.toml", "[server]\nport = 8110\n[eureka]\nregister_as = \"MULTI\"\n"),
            ("units/gateway-rust.toml", "[server]\nport = 8080\nroutes = 1\n[redis]\nurl = \"rediss://secret@h\"\n"),
            ("units/zeta.toml", "[server]\nport = 1\n"),
            ("units/nested/x.toml", "x = 1\n"),
            ("apps/ai.env", "# ai\nA='1'\n"),
            ("apps/ssr-in.env", "B='2'\n"),
            ("apps/ai.toml", "[ai]\nn = 1\n"),
            ("README.md", "x"),
        ] {
            files.insert(k.to_string(), v.to_string());
        }
        let local = LocalConfig { units: vec!["gateway-rust".into(), "multi".into(), "gone".into()], unit_live: [("gateway-rust".to_string(), vec!["routes".to_string()])].into(), ..Default::default() };
        let (docs, names, envs) = repo_documents(&local, &files);
        assert_eq!(docs.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(), ["gateway-rust", "multi", "zeta", "ai"]);
        assert_eq!(names[1], ("multi".to_string(), "MULTI".to_string()));
        let UnitState::Ready(gw) = &docs[0].1 else { panic!("{:?}", docs[0].1) };
        assert_eq!((gw.document["redis"]["url"].as_str(), gw.live.len()), (Some("rediss://secret@h"), 1));
        assert!(gw.secrets.is_empty(), "secrets are inline: nothing is merged in");
        assert_eq!(envs.iter().map(|a| a.name.as_str()).collect::<Vec<_>>(), ["ai", "ssr-in"]);
        assert_eq!(envs[0].text, "# ai\nA='1'\n");
        let (none, _, no_envs) = repo_documents(&local, &BTreeMap::new());
        assert!(none.is_empty() && no_envs.is_empty());
        files.insert("live.toml".into(), "live = [\"telemetry.log_level\"]\n[units]\nmulti = [\"features\"]\n".into());
        let (docs, _, _) = repo_documents(&local, &files);
        let live = |i: usize| match &docs[i].1 { UnitState::Ready(d) => d.live.clone(), s => panic!("{s:?}") };
        assert_eq!((live(0), live(1)), (vec!["telemetry.log_level".to_string()], vec!["telemetry.log_level".to_string(), "features".to_string()]));
        files.insert("live.toml".into(), "live = 3\n".into());
        let (docs, _, _) = repo_documents(&local, &files);
        assert!(matches!(&docs[1].1, UnitState::Ready(d) if d.live.is_empty()));
    }

    #[test]
    fn spring_keys_flatten_and_type() {
        let doc = serde_json::json!({"ai": {"db": {"url": "u"}, "n": 3, "f": 1.5, "on": true, "list": ["a", "b"], "none": null}});
        let keys = spring_keys(&doc).unwrap();
        assert_eq!(keys["ai.db.url"], Value::Str("u".into()));
        assert_eq!(keys["ai.n"], Value::Int(3));
        assert_eq!(keys["ai.f"], Value::Float(1.5));
        assert_eq!(keys["ai.on"], Value::Bool(true));
        assert_eq!((keys["ai.list[0]"].clone(), keys["ai.list[1]"].clone()), (Value::Str("a".into()), Value::Str("b".into())));
        assert_eq!(keys["ai.none"], Value::Null);
    }
}
