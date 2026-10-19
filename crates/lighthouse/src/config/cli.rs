//! The commands besides serving:
//!
//! - `lighthouse render <oci-config-dir> <dev|stage|prod> <out-dir>`: what
//!   `tools/render_config.py` writes, byte for byte, with the same report and exit status (0,
//!   1 when a required value is missing or a file has a problem, 2 on bad arguments).
//! - `lighthouse parity <old-dir> <base-url> <dev|stage|prod>`: compares a rendered directory
//!   with what a Lighthouse serves, key by key by SHA-256, and prints names only. The token
//!   comes from `LIGHTHOUSE_TOKEN` (scopes `units` and `ai`, or `ops`).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{Map, Value as Json};
use sha2::{Digest, Sha256};

use super::manifest::{self, Manifest};
use super::source::Snapshot;
use super::units::{self, canonical, set_path, toml_to_json};

const ENVS: [&str; 3] = ["dev", "stage", "prod"];

/// Runs the command `args` names (the arguments after the program), printing to stdout and
/// stderr. `None` when they name none: a normal start.
pub async fn run_if_asked(args: &[String]) -> Option<i32> {
    match args.first().map(String::as_str) {
        Some("render") => Some(render_command(&args[1..], &mut std::io::stdout(), &mut std::io::stderr())),
        Some("parity") => Some(parity_command(&args[1..], &mut std::io::stdout(), &mut std::io::stderr()).await),
        _ => None,
    }
}

/// How Python prints a `Path`: no empty or `.` components, no trailing slash.
fn py_path(p: &str) -> String {
    let abs = p.starts_with('/');
    let parts: Vec<&str> = p.split('/').filter(|c| !c.is_empty() && *c != ".").collect();
    match (abs, parts.is_empty()) {
        (true, _) => format!("/{}", parts.join("/")),
        (false, true) => ".".to_string(),
        (false, false) => parts.join("/"),
    }
}

pub fn render_command(args: &[String], out: &mut dyn std::io::Write, err: &mut dyn std::io::Write) -> i32 {
    if args.len() != 3 || !ENVS.contains(&args[1].as_str()) {
        let _ = writeln!(err, "Usage: lighthouse render <oci-config-dir> <dev|stage|prod> <out-dir>");
        return 2;
    }
    let (dir, env, out_dir) = (Path::new(&args[0]), args[1].as_str(), Path::new(&args[2]));
    if !dir.join("application.yml").exists() || !dir.join(format!("application-oci{env}.yml")).exists() {
        let _ = writeln!(err, "{} has no application.yml / application-oci{env}.yml", py_path(&args[0]));
        return 2;
    }
    match render_to(dir, env, out_dir, &py_path(&args[2])) {
        Ok((report, failed)) => {
            let _ = write!(out, "{report}");
            i32::from(failed)
        }
        Err(e) => {
            let _ = writeln!(err, "lighthouse render: {e:#}");
            1
        }
    }
}

/// Writes every file into `out_dir` with the script's modes; the report and whether it failed.
pub fn render_to(dir: &Path, env: &str, out_dir: &Path, shown: &str) -> Result<(String, bool)> {
    let snap = Snapshot::from_dir(dir, "master")?;
    let text = snap.file(manifest::PATH).ok_or_else(|| anyhow!("{} has no {}", dir.display(), manifest::PATH))?;
    let m = Manifest::parse(text)?;
    let output = units::render(&snap, &m, env)?;
    std::fs::create_dir_all(out_dir).with_context(|| format!("{} cannot be created", out_dir.display()))?;
    set_mode(out_dir, 0o755)?;
    for f in output.files() {
        let path = out_dir.join(&f.name);
        write_file(&path, &f.text, f.mode)?;
    }
    Ok((output.report(shown), output.failed()))
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(mode))?;
    #[cfg(not(unix))]
    let _ = (path, mode);
    Ok(())
}

fn write_file(path: &Path, text: &str, mode: u32) -> Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, mode);
    let mut f = opts.open(path).with_context(|| format!("{} cannot be written", path.display()))?;
    f.write_all(text.as_bytes())?;
    set_mode(path, mode)
}

/// A dotenv value as `env_line` wrote it, read back.
pub fn env_value(raw: &str) -> String {
    if let Some(inner) = raw.strip_prefix('\'').and_then(|r| r.strip_suffix('\'')) {
        return inner.to_string();
    }
    let Some(inner) = raw.strip_prefix('"').and_then(|r| r.strip_suffix('"')) else { return raw.to_string() };
    let mut out = String::new();
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

/// The `NAME=raw` lines of a dotenv text, comments left out.
pub fn env_lines(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter(|l| !l.trim_start().starts_with('#') && l.contains('='))
        .filter_map(|l| l.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())))
        .collect()
}

fn sha(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

/// Every leaf of a document as `dotted.key` to the SHA-256 of its canonical JSON (an array is
/// one leaf).
pub fn key_hashes(doc: &Json) -> BTreeMap<String, String> {
    fn walk(v: &Json, prefix: &str, out: &mut BTreeMap<String, String>) {
        match v {
            Json::Object(m) if !m.is_empty() => {
                for (k, v) in m {
                    let key = if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
                    walk(v, &key, out);
                }
            }
            other => {
                out.insert(prefix.to_string(), sha(&canonical(other)));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(doc, "", &mut out);
    out
}

/// The names that differ between two key maps.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Diff {
    pub keys: usize,
    pub differ: Vec<String>,
    pub only_old: Vec<String>,
    pub only_new: Vec<String>,
}

impl Diff {
    pub fn of(old: &BTreeMap<String, String>, new: &BTreeMap<String, String>) -> Self {
        let all: BTreeSet<&String> = old.keys().chain(new.keys()).collect();
        let mut d = Diff { keys: all.len(), ..Diff::default() };
        for k in all {
            match (old.get(k), new.get(k)) {
                (Some(a), Some(b)) if a != b => d.differ.push(k.clone()),
                (Some(_), None) => d.only_old.push(k.clone()),
                (None, Some(_)) => d.only_new.push(k.clone()),
                _ => {}
            }
        }
        d
    }

    pub fn count(&self) -> usize {
        self.differ.len() + self.only_old.len() + self.only_new.len()
    }

    fn print(&self, what: &str, noun: &str, out: &mut dyn std::io::Write) {
        let _ = writeln!(out, "{what}: {} {noun}, {} differ", self.keys, self.count());
        for (label, list) in [("differs", &self.differ), ("only in the old render", &self.only_old), ("only on the server", &self.only_new)] {
            for k in list {
                let _ = writeln!(out, "  {label}: {k}");
            }
        }
    }
}

struct Client {
    base: String,
    token: Option<String>,
    http: reqwest::Client,
}

impl Client {
    async fn get(&self, path: &str) -> Result<reqwest::Response> {
        let mut req = self.http.get(format!("{}{path}", self.base));
        if let Some(t) = &self.token {
            req = req.bearer_auth(t);
        }
        let resp = req.send().await.with_context(|| format!("{path}: no answer"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            // The body names what is missing, never a value.
            let body = resp.text().await.unwrap_or_default();
            bail!("{path} answered {status}: {}", body.chars().take(500).collect::<String>());
        }
        Ok(resp)
    }
}

pub async fn parity_command(args: &[String], out: &mut dyn std::io::Write, err: &mut dyn std::io::Write) -> i32 {
    if args.len() != 3 || !ENVS.contains(&args[2].as_str()) {
        let _ = writeln!(err, "Usage: lighthouse parity <old-dir> <base-url> <dev|stage|prod>   (token in LIGHTHOUSE_TOKEN)");
        return 2;
    }
    let client = Client {
        base: args[1].trim_end_matches('/').to_string(),
        token: lighthouse_client::token_from_env(),
        http: reqwest::Client::new(),
    };
    match parity(Path::new(&args[0]), &client, &args[2], out).await {
        Ok(0) => 0,
        Ok(_) => 1,
        Err(e) => {
            let _ = writeln!(err, "lighthouse parity: {e:#}");
            2
        }
    }
}

/// Compares and prints; the number of differing keys and variables.
async fn parity(dir: &Path, client: &Client, env: &str, out: &mut dyn std::io::Write) -> Result<usize> {
    let secrets_text = std::fs::read_to_string(dir.join("rust-units.env")).with_context(|| format!("{}/rust-units.env", dir.display()))?;
    let secrets = env_lines(&secrets_text);
    let mut total = 0;
    let mut served_vars = BTreeSet::new();
    let mut units_seen = 0;
    let mut names: Vec<String> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".toml"))
        .collect();
    names.sort();
    for file in names {
        let unit = file.trim_end_matches(".toml");
        let text = std::fs::read_to_string(dir.join(&file))?;
        let table: toml::Table = text.parse().with_context(|| format!("{file} does not parse"))?;
        let mut old = toml_to_json(&toml::Value::Table(table));
        let served: Json = client.get(&format!("/v1/units/{unit}/config")).await?.json().await?;
        if served["env"] != Json::String(env.to_string()) {
            bail!("the server renders {}, not {env}", served["env"]);
        }
        let paths = served["secrets"].as_object().cloned().unwrap_or_else(Map::new);
        for (path, var) in &paths {
            let var = var.as_str().unwrap_or_default();
            served_vars.insert(var.to_string());
            if let Some(raw) = secrets.get(var) {
                set_path(&mut old, path, Json::String(env_value(raw)))?;
            }
        }
        let d = Diff::of(&key_hashes(&old), &key_hashes(&served["config"]));
        d.print(unit, "keys", out);
        total += d.count();
        units_seen += 1;
    }
    let _ = writeln!(out, "units compared: {units_seen}");
    let unused: Vec<&String> = secrets.keys().filter(|k| !served_vars.contains(*k)).collect();
    let _ = writeln!(out, "rust-units.env: {} variables, {} served to no unit", secrets.len(), unused.len());
    for k in &unused {
        let _ = writeln!(out, "  served to no unit: {k}");
    }
    let mut envs: Vec<String> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n == "ai.env" || n == "ssr.env" || (n.starts_with("ssr-") && n.ends_with(".env")))
        .collect();
    envs.sort();
    for file in envs {
        let path = match file.as_str() {
            "ai.env" => "/v1/env/ai".to_string(),
            "ssr.env" => "/v1/env/ssr".to_string(),
            other => format!("/v1/env/ssr?region={}", other.trim_start_matches("ssr-").trim_end_matches(".env")),
        };
        let old = std::fs::read_to_string(dir.join(&file))?;
        let new = client.get(&path).await?.text().await?;
        let hashed = |t: &str| env_lines(t).into_iter().map(|(k, v)| (k, sha(&v))).collect::<BTreeMap<_, _>>();
        let d = Diff::of(&hashed(&old), &hashed(&new));
        d.print(&file, "variables", out);
        let same = sha(&old) == sha(&new);
        let _ = writeln!(out, "  byte-identical: {}", if same { "yes" } else { "no" });
        total += d.count() + usize::from(!same && d.count() == 0);
    }
    let _ = writeln!(out, "differing: {total}");
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_paths() {
        assert_eq!(py_path("a/b/"), "a/b");
        assert_eq!(py_path("./a//b/."), "a/b");
        assert_eq!(py_path("/x/"), "/x");
        assert_eq!(py_path("."), ".");
        assert_eq!(py_path("/"), "/");
    }

    #[test]
    fn env_values_read_back() {
        assert_eq!(env_value("'a b'"), "a b");
        assert_eq!(env_value("\"it's \\\"q\\\" \\$x \\\\ \\nz\""), "it's \"q\" $x \\ \nz");
        assert_eq!(env_value("bare"), "bare");
        assert_eq!(env_value("\"end\\\""), "end\\");
        let lines = env_lines("# c\nA='1'\nB=\"x=y\"\nnot a line\n");
        assert_eq!(lines.len(), 2);
        assert_eq!(lines["B"], "\"x=y\"");
        for v in ["plain", "it's", "a\nb", "q\"$\\"] {
            let line = units::env_line("K", v);
            assert_eq!(env_value(line.trim_end().split_once('=').unwrap().1), v);
        }
    }

    #[test]
    fn hashes_and_diffs() {
        let a = serde_json::json!({"a": {"b": 1, "c": [1, 2]}, "e": {}});
        let b = serde_json::json!({"a": {"b": 2, "d": 1}, "f": "x"});
        let d = Diff::of(&key_hashes(&a), &key_hashes(&b));
        assert_eq!(d.differ, ["a.b"]);
        assert_eq!(d.only_old, ["a.c", "e"]);
        assert_eq!(d.only_new, ["a.d", "f"]);
        assert_eq!(d.count(), 5);
        let mut out = Vec::new();
        d.print("u", "keys", &mut out);
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("u: 5 keys, 5 differ\n  differs: a.b\n"));
    }

    #[tokio::test]
    async fn which_command() {
        assert_eq!(run_if_asked(&[]).await, None);
        assert_eq!(run_if_asked(&["serve".into()]).await, None);
        assert_eq!(run_if_asked(&["render".into()]).await, Some(2));
        assert_eq!(run_if_asked(&["parity".into()]).await, Some(2));
    }

    #[test]
    fn bad_arguments() {
        let (mut o, mut e) = (Vec::new(), Vec::new());
        assert_eq!(render_command(&["x".into()], &mut o, &mut e), 2);
        assert_eq!(render_command(&["/nonexistent".into(), "dev".into(), "/tmp/x".into()], &mut o, &mut e), 2);
        assert!(String::from_utf8(e).unwrap().contains("has no application.yml"));
    }
}
