//! Where oci-config comes from, as immutable snapshots of the files the config server reads:
//! the root `*.yml` (the Spring settings) and everything under `rust/` (the unit templates and
//! the manifest).
//!
//! - `github:<owner>/<repo>`: `GET /repos/<owner>/<repo>/commits/<label>` with the last ETag
//!   (`Accept: application/vnd.github.sha`, so the answer is the sha alone; a 304 costs nothing
//!   against the rate limit), and on a new sha the tarball of that commit. The token is a
//!   read-only one from the environment (`MODLIX__CONFIG__GITHUB_TOKEN`).
//! - `dir:<path>`: a local checkout, read again on every poll. Its "sha" is a hash of the files.
//!
//! A snapshot is written to a peer, or to disk as the last good copy, as a gzipped tar of its
//! files with a small JSON header first (`.lighthouse-snapshot.json`).

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The biggest tarball or snapshot accepted.
const MAX_BYTES: u64 = 64 * 1024 * 1024;
const META: &str = ".lighthouse-snapshot.json";

/// The files of one commit (or one read of a directory). Never changed once built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// The commit (GitHub) or a hash of the files (a directory).
    pub sha: String,
    pub label: String,
    /// `github:<owner>/<repo>` or `dir:<absolute path>`.
    pub origin: String,
    pub fetched_ms: i64,
    pub files: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize)]
struct Meta {
    sha: String,
    label: String,
    origin: String,
    #[serde(rename = "fetchedMs")]
    fetched_ms: i64,
}

/// Whether the config server keeps a file: a root `*.yml`, or anything under `rust/`.
pub fn wanted(path: &str) -> bool {
    (!path.contains('/') && path.ends_with(".yml")) || (path.starts_with("rust/") && path.len() > 5)
}

/// A hash of the files: what a directory's snapshot calls its sha.
pub fn content_sha(files: &BTreeMap<String, String>) -> String {
    let mut h = Sha256::new();
    for (path, text) in files {
        h.update(path.as_bytes());
        h.update([0]);
        h.update((text.len() as u64).to_be_bytes());
        h.update(text.as_bytes());
    }
    hex::encode(h.finalize())
}

impl Snapshot {
    pub fn new(sha: &str, label: &str, origin: &str, files: BTreeMap<String, String>) -> Self {
        Self { sha: sha.into(), label: label.into(), origin: origin.into(), fetched_ms: lighthouse_client::now_millis(), files }
    }

    pub fn file(&self, path: &str) -> Option<&str> {
        self.files.get(path).map(String::as_str)
    }

    /// The short sha the dashboard shows.
    pub fn short(&self) -> &str {
        &self.sha[..self.sha.len().min(12)]
    }

    /// Reads a checkout: its root `*.yml` and its `rust/` tree.
    pub fn from_dir(dir: &Path, label: &str) -> Result<Self> {
        let root = dir.canonicalize().with_context(|| format!("{} cannot be read", dir.display()))?;
        let mut files = BTreeMap::new();
        for entry in std::fs::read_dir(&root)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if entry.file_type()?.is_file() && wanted(&name) {
                files.insert(name, std::fs::read_to_string(entry.path()).with_context(|| format!("{}", entry.path().display()))?);
            }
        }
        let rust = root.join("rust");
        if rust.is_dir() {
            walk(&rust, "rust", &mut files)?;
        }
        let origin = format!("dir:{}", root.display());
        Ok(Self::new(&content_sha(&files), label, &origin, files))
    }

    /// A GitHub tarball: its top directory (`<owner>-<repo>-<sha>/`) dropped, only the files the
    /// config server reads kept.
    pub fn from_tarball(bytes: &[u8], sha: &str, label: &str, origin: &str) -> Result<Self> {
        let mut files = BTreeMap::new();
        let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(bytes).take(MAX_BYTES));
        for entry in archive.entries().context("the tarball cannot be read")? {
            let mut entry = entry?;
            if !entry.header().entry_type().is_file() {
                continue;
            }
            let path = entry.path()?.to_string_lossy().into_owned();
            let Some((_, inner)) = path.split_once('/') else { continue };
            if !wanted(inner) {
                continue;
            }
            let mut text = String::new();
            if entry.read_to_string(&mut text).is_ok() {
                files.insert(inner.to_string(), text);
            } else {
                tracing::warn!(file = inner, "skipped a file that is not UTF-8 text");
            }
        }
        if files.is_empty() {
            bail!("the tarball holds none of the files the config server reads");
        }
        Ok(Self::new(sha, label, origin, files))
    }

    /// The snapshot as a gzipped tar: what goes to disk and to a peer.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        {
            let mut tar = tar::Builder::new(&mut gz);
            let meta = serde_json::to_vec(&Meta {
                sha: self.sha.clone(),
                label: self.label.clone(),
                origin: self.origin.clone(),
                fetched_ms: self.fetched_ms,
            })?;
            append(&mut tar, META, &meta)?;
            for (path, text) in &self.files {
                append(&mut tar, path, text.as_bytes())?;
            }
            tar.finish()?;
        }
        Ok(gz.finish()?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut meta: Option<Meta> = None;
        let mut files = BTreeMap::new();
        let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(bytes).take(MAX_BYTES));
        for entry in archive.entries().context("the snapshot cannot be read")? {
            let mut entry = entry?;
            let path = entry.path()?.to_string_lossy().into_owned();
            let mut text = String::new();
            entry.read_to_string(&mut text)?;
            if path == META {
                meta = Some(serde_json::from_str(&text)?);
            } else if wanted(&path) {
                files.insert(path, text);
            }
        }
        let m = meta.ok_or_else(|| anyhow!("the snapshot has no {META}"))?;
        Ok(Self { sha: m.sha, label: m.label, origin: m.origin, fetched_ms: m.fetched_ms, files })
    }

    /// Writes the snapshot to `dir/snapshot.tar.gz`, readable by this user only, replacing the
    /// previous one in one step.
    pub fn persist(&self, dir: &Path) -> Result<PathBuf> {
        std::fs::create_dir_all(dir).with_context(|| format!("{} cannot be created", dir.display()))?;
        let target = dir.join("snapshot.tar.gz");
        let tmp = dir.join(".snapshot.tar.gz.tmp");
        let bytes = self.encode()?;
        {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
            let mut f = opts.open(&tmp).with_context(|| format!("{} cannot be written", tmp.display()))?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        #[cfg(unix)]
        std::fs::set_permissions(&tmp, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
        std::fs::rename(&tmp, &target)?;
        Ok(target)
    }

    /// The last good snapshot written by [`Snapshot::persist`], if any.
    pub fn load(dir: &Path) -> Result<Option<Self>> {
        let path = dir.join("snapshot.tar.gz");
        match std::fs::read(&path) {
            Ok(bytes) => Ok(Some(Self::decode(&bytes).with_context(|| format!("{} is not a snapshot", path.display()))?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("{} cannot be read", path.display())),
        }
    }
}

fn append<W: Write>(tar: &mut tar::Builder<W>, path: &str, data: &[u8]) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o600);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();
    tar.append_data(&mut header, path, data)?;
    Ok(())
}

fn walk(dir: &Path, prefix: &str, files: &mut BTreeMap<String, String>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = format!("{prefix}/{}", entry.file_name().to_string_lossy());
        let ty = entry.file_type()?;
        if ty.is_dir() {
            walk(&entry.path(), &name, files)?;
        } else if ty.is_file() {
            match std::fs::read_to_string(entry.path()) {
                Ok(text) => {
                    files.insert(name, text);
                }
                Err(_) => tracing::warn!(file = name, "skipped a file that is not UTF-8 text"),
            }
        }
    }
    Ok(())
}

/// Where snapshots come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Spec {
    Dir(PathBuf),
    GitHub { owner: String, repo: String },
}

impl Spec {
    /// `dir:<path>` or `github:<owner>/<repo>`; empty is no source.
    pub fn parse(s: &str) -> Result<Option<Self>> {
        let s = s.trim();
        if s.is_empty() {
            return Ok(None);
        }
        if let Some(p) = s.strip_prefix("dir:") {
            return Ok(Some(Spec::Dir(PathBuf::from(p))));
        }
        if let Some(r) = s.strip_prefix("github:") {
            if let Some((owner, repo)) = r.split_once('/') {
                if !owner.is_empty() && !repo.is_empty() && !repo.contains('/') {
                    return Ok(Some(Spec::GitHub { owner: owner.into(), repo: repo.trim_end_matches(".git").into() }));
                }
            }
        }
        bail!("[config] source must be dir:<path> or github:<owner>/<repo>, not {s:?}")
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Spec::Dir(_) => "dir",
            Spec::GitHub { .. } => "github",
        }
    }

    /// What the dashboard shows: the repository or the directory.
    pub fn describe(&self) -> String {
        match self {
            Spec::Dir(p) => p.display().to_string(),
            Spec::GitHub { owner, repo } => format!("{owner}/{repo}"),
        }
    }
}

/// The outcome of one poll.
#[derive(Debug)]
pub enum Poll {
    Unchanged,
    Changed(Snapshot),
}

/// Polls one source.
pub struct Source {
    pub spec: Spec,
    pub label: String,
    api: String,
    token: Option<String>,
    http: reqwest::Client,
    etag: Mutex<Option<String>>,
}

impl Source {
    pub fn new(spec: Spec, label: &str, api: &str, token: Option<String>) -> Result<Self> {
        Ok(Self {
            spec,
            label: label.to_string(),
            api: api.trim_end_matches('/').to_string(),
            token: token.filter(|t| !t.is_empty()),
            http: reqwest::Client::builder().timeout(Duration::from_secs(60)).user_agent("modlix-lighthouse").build()?,
            etag: Mutex::new(None),
        })
    }

    /// Asks the source whether it moved past `current` (a sha), and reads the new snapshot if so.
    pub async fn poll(&self, current: Option<&str>) -> Result<Poll> {
        match &self.spec {
            Spec::Dir(dir) => {
                let (dir, label) = (dir.clone(), self.label.clone());
                let snap = tokio::task::spawn_blocking(move || Snapshot::from_dir(&dir, &label)).await??;
                Ok(if current == Some(snap.sha.as_str()) { Poll::Unchanged } else { Poll::Changed(snap) })
            }
            Spec::GitHub { owner, repo } => self.poll_github(owner, repo, current).await,
        }
    }

    fn get(&self, url: &str) -> reqwest::RequestBuilder {
        let req = self.http.get(url).header("X-GitHub-Api-Version", "2022-11-28");
        match &self.token {
            Some(t) => req.bearer_auth(t),
            None => req,
        }
    }

    async fn poll_github(&self, owner: &str, repo: &str, current: Option<&str>) -> Result<Poll> {
        let url = format!("{}/repos/{owner}/{repo}/commits/{}", self.api, self.label);
        let mut req = self.get(&url).header(reqwest::header::ACCEPT, "application/vnd.github.sha");
        let etag = self.etag.lock().clone();
        if let (Some(e), Some(_)) = (&etag, current) {
            req = req.header(reqwest::header::IF_NONE_MATCH, e);
        }
        let resp = req.send().await.with_context(|| format!("GitHub did not answer for {owner}/{repo}"))?;
        if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
            return Ok(Poll::Unchanged);
        }
        if !resp.status().is_success() {
            bail!("GitHub answered {} for the {} commit of {owner}/{repo}", resp.status(), self.label);
        }
        let new_etag = resp.headers().get(reqwest::header::ETAG).and_then(|v| v.to_str().ok()).map(str::to_string);
        let sha = resp.text().await?.trim().to_string();
        if sha.len() < 7 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("GitHub's answer for the {} commit of {owner}/{repo} is not a sha", self.label);
        }
        if current == Some(sha.as_str()) {
            *self.etag.lock() = new_etag;
            return Ok(Poll::Unchanged);
        }
        let tar_url = format!("{}/repos/{owner}/{repo}/tarball/{sha}", self.api);
        let resp = self.get(&tar_url).send().await.with_context(|| format!("the tarball of {sha} did not download"))?;
        if !resp.status().is_success() {
            bail!("GitHub answered {} for the tarball of {sha}", resp.status());
        }
        if resp.content_length().is_some_and(|n| n > MAX_BYTES) {
            bail!("the tarball of {sha} is over {MAX_BYTES} bytes");
        }
        let bytes = resp.bytes().await?;
        let origin = format!("github:{owner}/{repo}");
        let (label, sha2) = (self.label.clone(), sha.clone());
        let snap = tokio::task::spawn_blocking(move || Snapshot::from_tarball(&bytes, &sha2, &label, &origin)).await??;
        *self.etag.lock() = new_etag;
        Ok(Poll::Changed(snap))
    }

    /// Forgets the ETag, so the next poll asks GitHub in full.
    pub fn forget_etag(&self) {
        *self.etag.lock() = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(p, t)| (p.to_string(), t.to_string())).collect()
    }

    #[test]
    fn which_files_are_kept() {
        assert!(wanted("application.yml") && wanted("rust/units.toml") && wanted("rust/a/b.md"));
        assert!(!wanted("scripts/x.yml") && !wanted("README.md") && !wanted("rust/") && !wanted("a.yaml"));
    }

    #[test]
    fn encode_decode_and_persist() {
        let s = Snapshot::new("abc", "master", "github:o/r", files(&[("a.yml", "x: 1\n"), ("rust/units.toml", "u")]));
        let back = Snapshot::decode(&s.encode().unwrap()).unwrap();
        assert_eq!(back, s);
        assert_eq!(s.short(), "abc");
        let dir = std::env::temp_dir().join(format!("lighthouse-persist-{}", std::process::id()));
        assert_eq!(Snapshot::load(&dir).unwrap(), None);
        let path = s.persist(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        assert_eq!(Snapshot::load(&dir).unwrap(), Some(s));
        std::fs::write(&path, b"garbage").unwrap();
        assert!(Snapshot::load(&dir).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(Snapshot::decode(b"not gzip").is_err());
        let no_meta = {
            let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            {
                let mut t = tar::Builder::new(&mut gz);
                append(&mut t, "a.yml", b"x").unwrap();
                t.finish().unwrap();
            }
            gz.finish().unwrap()
        };
        assert!(Snapshot::decode(&no_meta).unwrap_err().to_string().contains("no .lighthouse-snapshot.json"));
    }

    pub(crate) fn tarball(top: &str, entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        {
            let mut t = tar::Builder::new(&mut gz);
            let mut dir = tar::Header::new_gnu();
            dir.set_entry_type(tar::EntryType::Directory);
            dir.set_size(0);
            dir.set_mode(0o755);
            dir.set_cksum();
            t.append_data(&mut dir, format!("{top}/"), std::io::empty()).unwrap();
            for (p, data) in entries {
                append(&mut t, &format!("{top}/{p}"), data).unwrap();
            }
            t.finish().unwrap();
        }
        gz.finish().unwrap()
    }

    #[test]
    fn github_tarballs() {
        let bytes = tarball(
            "o-r-abc",
            &[("application.yml", b"a: 1\n"), ("rust/multi.toml", b"x"), ("scripts/k.sh", b"no"), ("rust/bin.dat", &[0xff, 0xfe])],
        );
        let s = Snapshot::from_tarball(&bytes, "abc", "master", "github:o/r").unwrap();
        assert_eq!(s.files.keys().collect::<Vec<_>>(), ["application.yml", "rust/multi.toml"]);
        let empty = tarball("o-r-abc", &[("scripts/k.sh", b"no")]);
        assert!(Snapshot::from_tarball(&empty, "abc", "master", "o").is_err());
        assert!(Snapshot::from_tarball(b"junk", "abc", "master", "o").is_err());
    }

    #[test]
    fn directories_and_specs() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/oci-config");
        let s = Snapshot::from_dir(&fixture, "master").unwrap();
        assert!(s.file("application.yml").is_some() && s.file("rust/units.toml").is_some());
        assert!(s.origin.starts_with("dir:/"));
        assert_eq!(s.sha, Snapshot::from_dir(&fixture, "other").unwrap().sha, "the same files, the same sha");
        assert!(Snapshot::from_dir(Path::new("/nonexistent/lighthouse"), "m").is_err());
        let tmp = std::env::temp_dir().join(format!("lighthouse-walk-{}", std::process::id()));
        std::fs::create_dir_all(tmp.join("rust/deeper")).unwrap();
        std::fs::write(tmp.join("application.yml"), "a: 1\n").unwrap();
        std::fs::write(tmp.join("notes.txt"), "no").unwrap();
        std::fs::write(tmp.join("rust/deeper/x.toml"), "x = 1\n").unwrap();
        std::fs::write(tmp.join("rust/bin.dat"), [0xffu8, 0xfe]).unwrap();
        let s = Snapshot::from_dir(&tmp, "m").unwrap();
        assert_eq!(s.files.keys().collect::<Vec<_>>(), ["application.yml", "rust/deeper/x.toml"]);
        std::fs::remove_dir_all(&tmp).unwrap();
        assert_eq!(Spec::parse(" ").unwrap(), None);
        assert_eq!(Spec::parse("dir:../oci-config").unwrap(), Some(Spec::Dir("../oci-config".into())));
        let gh = Spec::parse("github:modlix-india/oci-config.git").unwrap().unwrap();
        assert_eq!(gh, Spec::GitHub { owner: "modlix-india".into(), repo: "oci-config".into() });
        assert_eq!((gh.kind(), gh.describe()), ("github", "modlix-india/oci-config".to_string()));
        assert_eq!(Spec::Dir("/x".into()).kind(), "dir");
        for bad in ["github:x", "github:/r", "github:a/b/c", "svn:x"] {
            assert!(Spec::parse(bad).is_err(), "{bad}");
        }
    }
}
