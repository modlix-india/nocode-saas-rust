//! The config server: the snapshot being served, the poll that replaces it, and the routes.
//!
//! - `GET /{app}/{profile}[/{label}]`: Spring Cloud Config's environment ([`super::spring`]).
//! - `GET /v1/units/{unit}/config`: the unit's document (JSON, its secrets included), with its
//!   version in the body and as the ETag. `GET /v1/units/{unit}/version`: the version alone.
//!   `GET /v1/units/{unit}/config.toml?redact=true`: the document as TOML.
//! - `GET /v1/env/{ai|ssr}[?region=in]`: the env file, byte for byte what the script wrote.
//! - `POST /v1/admin/refresh`: poll now. `GET /v1/peer/snapshot`: the snapshot, for a peer.
//! - `GET /v1/config`: what the dashboard's Config tab shows (no secrets, no values).
//!
//! A required value that is missing answers 500 with the names of what is missing, never a
//! value. A new snapshot that does not render (a manifest or YAML mistake) is not swapped in:
//! the last good one stays, and the error shows on the dashboard.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{anyhow, Result};
use arc_swap::ArcSwapOption;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use parking_lot::Mutex;
use serde_json::{json, Value as JsonValue};
use sha2::{Digest, Sha256};

use super::auth::{Auth, Scope};
use super::manifest::{self, Manifest};
use super::source::{Poll, Snapshot, Source, Spec};
use super::spring;
use super::units::{self, restart_part, AppEnv, UnitState};
use super::ConfigServerConfig;
use crate::registry::Registry;

/// One snapshot as served: the files, and for this deployment's environment the units'
/// documents and the env files.
pub struct Served {
    pub snapshot: Arc<Snapshot>,
    /// `github`, `dir`, `disk` (the last good copy) or `peer`.
    pub from: &'static str,
    pub units: Vec<(String, UnitState)>,
    pub apps: Vec<AppEnv>,
    /// Registry names of the units, by unit.
    pub registry_names: Vec<(String, String)>,
    /// Why the units cannot be rendered from this snapshot.
    pub render_error: Option<String>,
    encoded: OnceLock<Vec<u8>>,
}

impl Served {
    /// Renders `snapshot` for `settings.env`. A failure is kept in `render_error`: the Spring
    /// endpoint still serves the files.
    pub fn prepare(snapshot: Snapshot, settings: &ConfigServerConfig, from: &'static str) -> Self {
        let snapshot = Arc::new(snapshot);
        if settings.layout == "repo" {
            let (units, registry_names, apps) = super::local::repo_documents(&settings.local, &snapshot.files);
            return Self { snapshot, from, units, apps, registry_names, render_error: None, encoded: OnceLock::new() };
        }
        if settings.env == "local" {
            let (units, registry_names) = settings.local.documents(&snapshot.files);
            return Self { snapshot, from, units, apps: vec![], registry_names, render_error: None, encoded: OnceLock::new() };
        }
        let env = settings.env.as_str();
        let rendered = (|| -> Result<_> {
            let text = snapshot.file(manifest::PATH).ok_or_else(|| anyhow!("{} is missing", manifest::PATH))?;
            let m = Manifest::parse(text)?;
            let out = units::render(&snapshot, &m, env)?;
            let names = m.units.iter().map(|u| (u.name.clone(), u.registry_name())).collect();
            Ok((units::documents(&out, &m), out.apps, names))
        })();
        let (units, apps, registry_names, render_error) = match rendered {
            Ok((u, a, n)) => (u, a, n, None),
            Err(e) => (vec![], vec![], vec![], Some(format!("{e:#}"))),
        };
        Self { snapshot, from, units, apps, registry_names, render_error, encoded: OnceLock::new() }
    }

    pub fn unit(&self, name: &str) -> Option<&UnitState> {
        self.units.iter().find(|(u, _)| u == name).map(|(_, s)| s)
    }

    fn encoded(&self) -> Result<&[u8]> {
        if let Some(b) = self.encoded.get() {
            return Ok(b);
        }
        let bytes = self.snapshot.encode()?;
        Ok(self.encoded.get_or_init(|| bytes))
    }
}

/// How the source has been doing.
#[derive(Debug, Clone, Default)]
pub struct SourceStatus {
    /// The newest commit that was not served (it does not render), until a snapshot is served.
    pub rejected: Option<String>,
    pub last_poll_ms: i64,
    pub last_change_ms: i64,
    pub last_error: Option<String>,
    pub last_error_ms: i64,
    pub polls: u64,
    pub failures: u64,
}

pub struct ConfigServer {
    pub settings: ConfigServerConfig,
    pub source: Source,
    served: ArcSwapOption<Served>,
    status: Mutex<SourceStatus>,
    pub auth: Arc<Auth>,
    peers: Vec<String>,
    peer_token: Option<String>,
    http: reqwest::Client,
    polling: tokio::sync::Mutex<()>,
}

impl ConfigServer {
    /// `None` when `[config] source` is empty: no config server on this instance.
    pub fn new(settings: &ConfigServerConfig, auth: Arc<Auth>, peers: Vec<String>, peer_token: &str) -> Result<Option<Arc<Self>>> {
        let Some(spec) = Spec::parse(&settings.source)? else { return Ok(None) };
        let mut settings = settings.clone();
        match settings.layout.as_str() {
            "" => match (settings.env.as_str(), settings.local.enabled()) {
                ("dev" | "stage" | "prod", false) => {}
                ("local", true) if matches!(spec, Spec::Dir(_)) => {}
                ("local", true) => anyhow::bail!("[config] env local reads its Spring settings from a dir: source"),
                ("local", false) => anyhow::bail!("[config] env local needs [config.local] dir"),
                (_, true) => anyhow::bail!("[config.local] is only for env local, not {:?}", settings.env),
                _ => anyhow::bail!("[config] env must be dev, stage or prod, not {:?}", settings.env),
            },
            // Any environment: the URL's folder is what is served. Its name is the folder's
            // unless [config] env names it.
            "repo" if !settings.local.enabled() => {
                if settings.env.trim().is_empty() {
                    let named = match &spec {
                        Spec::Dir(p) => p.canonicalize().unwrap_or_else(|_| p.clone()).file_name().map(|n| n.to_string_lossy().into_owned()),
                        Spec::GitHub { folder, .. } => folder.rsplit('/').next().map(str::to_string),
                    };
                    settings.env = named.filter(|n| !n.is_empty()).unwrap_or_else(|| "default".into());
                }
            }
            "repo" => anyhow::bail!("[config] layout repo reads its folder from the source, not [config.local] dir"),
            other => anyhow::bail!("[config] layout must be empty or repo, not {other:?}"),
        }
        let settings = &settings;
        let token = Some(settings.github_token.clone()).filter(|t| !t.is_empty());
        let folder = spec.folder();
        let mut source = Source::new(spec, &settings.label, &settings.github_api, token)?;
        if settings.layout == "repo" {
            source.keep = super::source::Keep::Folder(folder);
        }
        Ok(Some(Arc::new(Self {
            settings: settings.clone(),
            source,
            served: ArcSwapOption::empty(),
            status: Mutex::new(SourceStatus::default()),
            auth,
            peers,
            peer_token: Some(peer_token.to_string()).filter(|t| !t.is_empty()),
            http: reqwest::Client::builder().timeout(Duration::from_secs(30)).build()?,
            polling: tokio::sync::Mutex::new(()),
        })))
    }

    pub fn served(&self) -> Option<Arc<Served>> {
        self.served.load_full()
    }

    pub fn status(&self) -> SourceStatus {
        self.status.lock().clone()
    }

    /// The profiles the Spring endpoint serves.
    pub fn profiles(&self) -> Vec<String> {
        if self.settings.spring.profiles.is_empty() {
            vec![format!("oci{}", self.settings.env)]
        } else {
            self.settings.spring.profiles.clone()
        }
    }

    fn snapshot_dir(&self) -> Option<PathBuf> {
        Some(self.settings.snapshot_dir.trim()).filter(|d| !d.is_empty()).map(PathBuf::from)
    }

    fn fail(&self, e: String) {
        let mut s = self.status.lock();
        s.failures += 1;
        s.last_error_ms = lighthouse_client::now_millis();
        tracing::warn!(error = %e, "config source");
        s.last_error = Some(e);
    }

    /// Serves `served` if it renders, or if nothing better is served yet. True when swapped.
    pub fn offer(&self, served: Served) -> bool {
        let current = self.served.load_full();
        if let (Some(err), Some(_)) = (&served.render_error, &current) {
            self.fail(format!("commit {} is not served: {err}", served.snapshot.short()));
            self.status.lock().rejected = Some(served.snapshot.sha.clone());
            return false;
        }
        if let Some(e) = &served.render_error {
            self.fail(format!("commit {} does not render: {e}", served.snapshot.short()));
        }
        if let (Some(dir), "github" | "peer") = (self.snapshot_dir(), served.from) {
            if served.render_error.is_none() {
                if let Err(e) = served.snapshot.persist(&dir) {
                    tracing::warn!(error = %format!("{e:#}"), "could not keep the last good snapshot");
                }
            }
        }
        tracing::info!(sha = served.snapshot.short(), from = served.from, files = served.snapshot.files.len(), "config snapshot served");
        metrics::counter!("lighthouse_config_snapshots_total", "from" => served.from).increment(1);
        {
            let mut st = self.status.lock();
            st.last_change_ms = lighthouse_client::now_millis();
            st.rejected = None;
        }
        self.served.store(Some(Arc::new(served)));
        true
    }

    /// Loads the last good snapshot from disk, if one was kept.
    pub fn load_kept(&self) {
        let Some(dir) = self.snapshot_dir() else { return };
        match Snapshot::load(&dir) {
            Ok(Some(snap)) => {
                self.offer(Served::prepare(snap, &self.settings, "disk"));
            }
            Ok(None) => {}
            Err(e) => self.fail(format!("{e:#}")),
        }
    }

    /// One poll of the source. True when a new snapshot is served.
    pub async fn poll_once(&self) -> bool {
        let _one = self.polling.lock().await;
        let current = self.served().map(|s| s.snapshot.sha.clone());
        let result = if self.settings.local.enabled() { self.poll_local(current.as_deref()).await } else { self.source.poll(current.as_deref()).await };
        {
            let mut s = self.status.lock();
            s.polls += 1;
            s.last_poll_ms = lighthouse_client::now_millis();
        }
        match result {
            Ok(Poll::Unchanged) => {
                // A rejected commit stays the source's head: its error stays shown.
                let mut st = self.status.lock();
                if st.rejected.is_none() {
                    st.last_error = None;
                }
                false
            }
            Ok(Poll::Changed(snap)) => {
                let from = self.source.spec.kind();
                let swapped = self.offer(Served::prepare(snap, &self.settings, from));
                if swapped {
                    self.status.lock().last_error = None;
                }
                swapped
            }
            Err(e) => {
                self.fail(format!("{e:#}"));
                if self.served.load().is_none() {
                    self.from_peers().await
                } else {
                    false
                }
            }
        }
    }

    /// The local stack's poll: the Spring directory and the local files read again, one sha over
    /// both.
    async fn poll_local(&self, current: Option<&str>) -> Result<Poll> {
        let Spec::Dir(dir) = self.source.spec.clone() else { anyhow::bail!("env local needs a dir: source") };
        let (label, local) = (self.source.label.clone(), self.settings.local.clone());
        let snap = tokio::task::spawn_blocking(move || -> Result<Snapshot> {
            let spring = Snapshot::from_dir(&dir, &label)?;
            let mut files = spring.files;
            files.extend(local.read()?);
            Ok(Snapshot::new(&super::source::content_sha(&files), &label, &spring.origin, files))
        })
        .await??;
        Ok(if current == Some(snap.sha.as_str()) { Poll::Unchanged } else { Poll::Changed(snap) })
    }

    /// Takes a peer's snapshot (when this instance has none and the source fails).
    pub async fn from_peers(&self) -> bool {
        let Some(token) = &self.peer_token else { return false };
        for p in &self.peers {
            let url = format!("{p}/v1/peer/snapshot");
            let resp = self.http.get(&url).bearer_auth(token).header(lighthouse_client::replication::REPLICATION_HEADER, "true").send().await;
            let Ok(resp) = resp else { continue };
            if !resp.status().is_success() {
                continue;
            }
            let Ok(bytes) = resp.bytes().await else { continue };
            match Snapshot::decode(&bytes) {
                Ok(snap) => {
                    tracing::info!(peer = p, sha = snap.short(), "config snapshot taken from a peer");
                    return self.offer(Served::prepare(snap, &self.settings, "peer"));
                }
                Err(e) => self.fail(format!("{p}: {e:#}")),
            }
        }
        false
    }

    /// Polls every `poll_seconds`, the first time at once.
    pub async fn run(self: Arc<Self>) {
        let mut tick = tokio::time::interval(Duration::from_secs(self.settings.poll_seconds.max(1)));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            self.poll_once().await;
        }
    }

    /// The compat endpoint's source names start with this for a GitHub source.
    fn spring_uri(&self) -> String {
        if !self.settings.spring.uri.is_empty() {
            return self.settings.spring.uri.clone();
        }
        match &self.source.spec {
            Spec::GitHub { owner, repo, .. } => format!("https://github.com/{owner}/{repo}.git"),
            Spec::Dir(p) => p.display().to_string(),
        }
    }
}

pub fn routes(cs: Arc<ConfigServer>, registry: Arc<Registry>) -> Router {
    let status = Router::new().route("/v1/config", get(config_view)).with_state((cs.clone(), registry));
    Router::new()
        .route("/v1/units/{unit}/config", get(unit_config))
        .route("/v1/units/{unit}/version", get(unit_version))
        .route("/v1/units/{unit}/config.toml", get(unit_toml))
        .route("/v1/env/{name}", get(env_file))
        .route("/v1/admin/refresh", post(refresh))
        .route("/v1/peer/snapshot", get(peer_snapshot))
        .route("/{app}/{profile}", get(spring_env))
        .route("/{app}/{profile}/{label}", get(spring_env_labelled))
        .with_state(cs)
        .merge(status)
}

/// The routes when this instance has no config server: everything answers 404 but the view.
pub fn disabled_routes() -> Router {
    Router::new().route("/v1/config", get(|| async { Json(json!({"enabled": false})) }))
}

fn error(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(json!({ "error": msg.into() }))).into_response()
}

fn not_ready() -> Response {
    error(StatusCode::SERVICE_UNAVAILABLE, "no configuration snapshot is loaded yet")
}

fn etag_matches(h: &HeaderMap, version: &str) -> bool {
    h.get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|t| t.trim().trim_start_matches("W/").trim_matches('"') == version))
}

fn with_etag(mut r: Response, version: &str) -> Response {
    if let Ok(v) = HeaderValue::from_str(&format!("\"{version}\"")) {
        r.headers_mut().insert(header::ETAG, v);
    }
    r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

/// The unit's document, or the response that says why there is none.
fn unit_doc(cs: &ConfigServer, h: &HeaderMap, unit: &str) -> Result<(Arc<Served>, units::UnitDoc), Response> {
    cs.auth.check_unit(h, &[Scope::Units, Scope::Ops], unit).map_err(IntoResponse::into_response)?;
    let served = cs.served().ok_or_else(not_ready)?;
    if let Some(e) = &served.render_error {
        return Err(error(StatusCode::INTERNAL_SERVER_ERROR, format!("the configuration does not render: {e}")));
    }
    match served.unit(unit) {
        None => Err(error(StatusCode::NOT_FOUND, format!("no unit {unit}"))),
        Some(UnitState::Missing(names)) => {
            tracing::warn!(unit, missing = ?names, "a unit's configuration lacks required values");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "required configuration is missing", "unit": unit, "missing": names})),
            )
                .into_response())
        }
        Some(UnitState::Invalid(e)) => Err(error(StatusCode::INTERNAL_SERVER_ERROR, e.clone())),
        Some(UnitState::Ready(doc)) => {
            let doc = doc.clone();
            Ok((served, doc))
        }
    }
}

async fn unit_config(State(cs): State<Arc<ConfigServer>>, Path(unit): Path<String>, h: HeaderMap) -> Response {
    let (served, doc) = match unit_doc(&cs, &h, &unit) {
        Ok(x) => x,
        Err(r) => return r,
    };
    if etag_matches(&h, &doc.version) {
        return with_etag(StatusCode::NOT_MODIFIED.into_response(), &doc.version);
    }
    let body = json!({
        "unit": doc.unit,
        "env": cs.settings.env,
        "version": doc.version,
        "sha": served.snapshot.sha,
        "live": doc.live,
        "secrets": doc.secrets.iter().map(|(p, n)| (p.clone(), JsonValue::String(n.clone()))).collect::<serde_json::Map<_, _>>(),
        "config": doc.document,
    });
    with_etag(Json(body).into_response(), &doc.version)
}

async fn unit_version(State(cs): State<Arc<ConfigServer>>, Path(unit): Path<String>, h: HeaderMap) -> Response {
    let (_, doc) = match unit_doc(&cs, &h, &unit) {
        Ok(x) => x,
        Err(r) => return r,
    };
    if etag_matches(&h, &doc.version) {
        return with_etag(StatusCode::NOT_MODIFIED.into_response(), &doc.version);
    }
    with_etag(([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], doc.version.clone()).into_response(), &doc.version)
}

async fn unit_toml(
    State(cs): State<Arc<ConfigServer>>,
    Path(unit): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    let (_, doc) = match unit_doc(&cs, &h, &unit) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let redact = q.get("redact").is_none_or(|v| v != "false");
    match units::document_toml(&doc, redact) {
        Ok(text) => with_etag(([(header::CONTENT_TYPE, "application/toml; charset=utf-8")], text).into_response(), &doc.version),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")),
    }
}

/// A short hash of an env file, its ETag.
pub fn text_version(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))[..16].to_string()
}

async fn env_file(
    State(cs): State<Arc<ConfigServer>>,
    Path(name): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    if let Err(d) = cs.auth.check(&h, &[Scope::Ai, Scope::Ops]) {
        return d.into_response();
    }
    let Some(served) = cs.served() else { return not_ready() };
    if let Some(e) = &served.render_error {
        return error(StatusCode::INTERNAL_SERVER_ERROR, format!("the configuration does not render: {e}"));
    }
    let wanted = match (name.as_str(), q.get("region").map(|r| r.trim()).filter(|r| !r.is_empty())) {
        ("ai", None) => "ai".to_string(),
        ("ssr", None) => "ssr".to_string(),
        ("ssr", Some(region)) => format!("ssr-{region}"),
        _ => return error(StatusCode::NOT_FOUND, "the env files are ai, ssr and ssr?region=<region>"),
    };
    let Some(app) = served.apps.iter().find(|a| a.name == wanted) else {
        return error(StatusCode::NOT_FOUND, format!("{wanted}.env is not rendered for {}", cs.settings.env));
    };
    if !app.missing.is_empty() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "required configuration is missing", "file": format!("{wanted}.env"), "missing": app.missing})),
        )
            .into_response();
    }
    let version = text_version(&app.text);
    if etag_matches(&h, &version) {
        return with_etag(StatusCode::NOT_MODIFIED.into_response(), &version);
    }
    with_etag(([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], app.text.clone()).into_response(), &version)
}

async fn refresh(State(cs): State<Arc<ConfigServer>>, Query(q): Query<HashMap<String, String>>, h: HeaderMap) -> Response {
    let who = match cs.auth.check(&h, &[Scope::Ops]) {
        Ok(w) => w,
        Err(d) => return d.into_response(),
    };
    if q.get("full").is_some_and(|v| v == "true") {
        cs.source.forget_etag();
    }
    let changed = cs.poll_once().await;
    tracing::info!(by = who, changed, "config refreshed on request");
    let st = cs.status();
    Json(json!({
        "changed": changed,
        "sha": cs.served().map(|s| s.snapshot.sha.clone()),
        "error": st.last_error,
    }))
    .into_response()
}

async fn peer_snapshot(State(cs): State<Arc<ConfigServer>>, h: HeaderMap) -> Response {
    if let Err(d) = cs.auth.check(&h, &[Scope::Peer]) {
        return d.into_response();
    }
    let Some(served) = cs.served() else { return not_ready() };
    match served.encoded() {
        Ok(bytes) => ([(header::CONTENT_TYPE, "application/gzip")], bytes.to_vec()).into_response(),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")),
    }
}

async fn spring_env(State(cs): State<Arc<ConfigServer>>, Path((app, profile)): Path<(String, String)>, h: HeaderMap) -> Response {
    spring_answer(&cs, &app, &profile, None, &h)
}

async fn spring_env_labelled(
    State(cs): State<Arc<ConfigServer>>,
    Path((app, profile, label)): Path<(String, String, String)>,
    h: HeaderMap,
) -> Response {
    spring_answer(&cs, &app, &profile, Some(&label), &h)
}

fn spring_answer(cs: &ConfigServer, app: &str, profile: &str, label: Option<&str>, h: &HeaderMap) -> Response {
    if spring::RESERVED.contains(&app) {
        return error(StatusCode::NOT_FOUND, format!("{app} is not an application"));
    }
    // In a repository folder, an app with `apps/<app>.toml` is served as that file says, without
    // a token, as the Java config-server served everyone; [config.spring.apps] can still narrow it.
    let repo_rule = (cs.settings.layout == "repo")
        .then(|| cs.served())
        .flatten()
        .filter(|s| s.snapshot.files.contains_key(&format!("apps/{app}.toml")))
        .map(|_| spring::AppRule { open: true, ..Default::default() });
    let Some(rule) = cs.settings.spring.apps.get(app).cloned().or(repo_rule) else {
        return error(StatusCode::NOT_FOUND, format!("{app} is not served here"));
    };
    let rule = &rule;
    // An open app is served without a token to the trusted networks only (the host's Docker
    // network); anyone else needs one, as for a unit's configuration.
    if !(rule.open && crate::allowed::is_trusted(h)) {
        if let Err(d) = cs.auth.check(h, &[Scope::Ai, Scope::Ops]) {
            return d.into_response();
        }
    }
    let allowed = cs.profiles();
    if let Some(bad) = profile.split(',').map(str::trim).find(|p| !allowed.iter().any(|a| a == p)) {
        return error(StatusCode::FORBIDDEN, format!("profile {bad} is not served here"));
    }
    let Some(served) = cs.served() else { return not_ready() };
    let label = label.map(|l| l.replace("(_)", "/"));
    if let Some(l) = &label {
        if l != &served.snapshot.label && l != &served.snapshot.sha {
            return error(StatusCode::NOT_FOUND, format!("label {l} is not served here"));
        }
    }
    // The git backend answers its default label when none is asked; the native one null.
    let label = label.or_else(|| matches!(cs.source.spec, Spec::GitHub { .. }).then(|| served.snapshot.label.clone()));
    let path = match &label {
        Some(l) => format!("/{app}/{profile}/{l}"),
        None => format!("/{app}/{profile}"),
    };
    let repo_app = cs.settings.layout == "repo" && served.snapshot.files.contains_key(&format!("apps/{app}.toml"));
    let built = if cs.settings.local.is_app(app) || repo_app {
        local_environment(cs, &served, app, profile, label.as_deref())
    } else {
        spring::environment(&served.snapshot, &cs.spring_uri(), app, profile, label.as_deref())
    };
    match built {
        Ok(env) => ([(header::CONTENT_TYPE, "application/json")], env.guard(rule).to_json()).into_response(),
        Err(e) => {
            tracing::warn!(app, profile, error = %format!("{e:#}"), "the Spring environment cannot be built");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::CONTENT_TYPE, "application/json")],
                spring::error_json(500, "Internal Server Error", &path),
            )
                .into_response()
        }
    }
}

/// The local stack's answer for ai or ssr: one source, the app's document (`config/<app>.toml`
/// with its table of `config/local.toml`) as Spring keys.
fn local_environment(cs: &ConfigServer, served: &Served, app: &str, profile: &str, label: Option<&str>) -> Result<spring::Environment> {
    let doc = match served.unit(app) {
        Some(UnitState::Ready(d)) => d,
        Some(UnitState::Invalid(e)) => anyhow::bail!("{e}"),
        Some(UnitState::Missing(names)) => anyhow::bail!("missing: {}", names.join("; ")),
        None => anyhow::bail!("no document for {app}"),
    };
    let name = if cs.settings.layout == "repo" {
        format!("{}/apps/{app}.toml", cs.spring_uri())
    } else {
        let dir = std::path::Path::new(cs.settings.local.dir.trim());
        let dir = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
        format!("file:{}/{app}.toml", dir.display())
    };
    Ok(spring::Environment {
        name: app.to_string(),
        profiles: vec![profile.to_string()],
        label: label.map(str::to_string),
        version: Some(served.snapshot.sha.clone()),
        sources: vec![spring::PropertySource {
            name,
            source: super::local::spring_keys(&doc.document)?,
        }],
    })
}

/// How an instance's running configuration compares with the current one.
pub fn instance_state(running: Option<&str>, current: Option<&str>) -> &'static str {
    match (running, current) {
        (None, _) => "unmanaged",
        (Some(_), None) => "unknown",
        (Some(r), Some(c)) if r == c => "current",
        (Some(r), Some(c)) if restart_part(r) == restart_part(c) => "live",
        _ => "stale",
    }
}

async fn config_view(State((cs, registry)): State<(Arc<ConfigServer>, Arc<Registry>)>, h: HeaderMap) -> Response {
    // The configuration's view (commit, units, versions) is the admin's whenever an admin token is
    // configured, as on every host; the registry stays readable without it.
    if cs.auth.has(Scope::Ops) {
        if let Err(d) = cs.auth.check(&h, &[Scope::Ops]) {
            return d.into_response();
        }
    }
    let st = cs.status();
    let served = cs.served();
    let snapshot = served.as_ref().map(|s| {
        json!({
            "sha": s.snapshot.sha,
            "short": s.snapshot.short(),
            "label": s.snapshot.label,
            "from": s.from,
            "fetchedMs": s.snapshot.fetched_ms,
            "files": s.snapshot.files.len(),
        })
    });
    let mut units_out = Vec::new();
    if let Some(s) = &served {
        for (unit, state) in &s.units {
            let reg = s.registry_names.iter().find(|(u, _)| u == unit).map_or_else(|| unit.to_ascii_uppercase(), |(_, r)| r.clone());
            let (version, problem) = match state {
                UnitState::Ready(d) => (Some(d.version.clone()), None),
                UnitState::Missing(names) => (None, Some(format!("missing: {}", names.join("; ")))),
                UnitState::Invalid(e) => (None, Some(e.clone())),
            };
            let instances: Vec<JsonValue> = registry
                .application(&reg)
                .0
                .map(|a| {
                    a.instances
                        .iter()
                        .map(|i| {
                            let running = i.metadata.0.get("configVersion").map(String::as_str);
                            json!({
                                "id": i.instance_id,
                                "status": i.status,
                                "configVersion": running,
                                "state": instance_state(running, version.as_deref()),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            units_out.push(json!({"unit": unit, "registry": reg, "version": version, "problem": problem, "instances": instances}));
        }
    }
    let env_files: Vec<JsonValue> = served
        .as_ref()
        .map(|s| {
            s.apps
                .iter()
                .map(|a| {
                    let problem = (!a.missing.is_empty()).then(|| format!("missing: {}", a.missing.join("; ")));
                    json!({"name": a.name, "version": text_version(&a.text), "problem": problem})
                })
                .collect()
        })
        .unwrap_or_default();
    Json(json!({
        "enabled": true,
        "env": cs.settings.env,
        "source": {
            "kind": cs.source.spec.kind(),
            "where": cs.source.spec.describe(),
            "label": cs.source.label,
            "pollSeconds": cs.settings.poll_seconds,
        },
        "snapshot": snapshot,
        "lastPollMs": st.last_poll_ms,
        "lastChangeMs": st.last_change_ms,
        "lastError": st.last_error,
        "lastErrorMs": st.last_error_ms,
        "rejectedCommit": st.rejected,
        "polls": st.polls,
        "failures": st.failures,
        "renderError": served.as_ref().and_then(|s| s.render_error.clone()),
        "profiles": cs.profiles(),
        "manageable": cs.auth.has(Scope::Ops),
        "units": units_out,
        "envFiles": env_files,
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_states() {
        assert_eq!(instance_state(None, Some("a.b")), "unmanaged");
        assert_eq!(instance_state(Some("a.b"), None), "unknown");
        assert_eq!(instance_state(Some("a.b"), Some("a.b")), "current");
        assert_eq!(instance_state(Some("a.b"), Some("a.c")), "live");
        assert_eq!(instance_state(Some("a.b"), Some("z.b")), "stale");
    }

    #[test]
    fn settings_are_checked() {
        let auth = Arc::new(Auth::new(&Default::default(), "", "").unwrap());
        let mut c = ConfigServerConfig { source: "dir:/x".into(), env: "qa".into(), ..ConfigServerConfig::default() };
        assert!(ConfigServer::new(&c, auth.clone(), vec![], "").err().unwrap().to_string().contains("dev, stage or prod"));
        c.source = String::new();
        assert!(ConfigServer::new(&c, auth.clone(), vec![], "").unwrap().is_none());
        c.source = "dir:/x".into();
        c.env = "prod".into();
        let cs = ConfigServer::new(&c, auth.clone(), vec![], "").unwrap().unwrap();
        assert_eq!(cs.profiles(), ["ociprod"]);
        assert_eq!(cs.spring_uri(), "/x");
        c.spring.uri = "https://example.test/repo.git".into();
        assert_eq!(ConfigServer::new(&c, auth, vec![], "").unwrap().unwrap().spring_uri(), "https://example.test/repo.git");
    }

    #[test]
    fn local_settings_are_checked() {
        let auth = Arc::new(Auth::new(&Default::default(), "", "").unwrap());
        let mut c = ConfigServerConfig { source: "dir:/x".into(), env: "local".into(), ..ConfigServerConfig::default() };
        assert!(ConfigServer::new(&c, auth.clone(), vec![], "").err().unwrap().to_string().contains("needs [config.local] dir"));
        c.local.dir = "config".into();
        assert!(ConfigServer::new(&c, auth.clone(), vec![], "").unwrap().is_some());
        c.env = "dev".into();
        assert!(ConfigServer::new(&c, auth.clone(), vec![], "").err().unwrap().to_string().contains("only for env local"));
        c.env = "local".into();
        c.source = "github:o/r".into();
        assert!(ConfigServer::new(&c, auth, vec![], "").err().unwrap().to_string().contains("dir: source"));
    }

    #[tokio::test]
    async fn the_local_stack_is_served_from_its_files() {
        let root = std::env::temp_dir().join(format!("lighthouse-local-serve-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (spring, units_dir) = (root.join("spring"), root.join("units"));
        std::fs::create_dir_all(&spring).unwrap();
        std::fs::create_dir_all(&units_dir).unwrap();
        std::fs::write(spring.join("application-default.yml"), "ai:\n  x: 1\n").unwrap();
        std::fs::write(units_dir.join("multi.toml"), "[server]\nport = 8110\n[eureka]\nregister_as = \"MULTI\"\n").unwrap();
        std::fs::write(units_dir.join("local.toml"), "[units.database]\npassword = 'pw'\n[ai]\nai.db.password = 'aipw'\n").unwrap();
        std::fs::write(units_dir.join("ai.toml"), "[ai.db]\nurl = 'u'\nport = 1\n").unwrap();
        let mut c = ConfigServerConfig { source: format!("dir:{}", spring.display()), env: "local".into(), ..ConfigServerConfig::default() };
        c.local = super::super::local::LocalConfig {
            dir: units_dir.display().to_string(),
            secrets_file: units_dir.join("local.toml").display().to_string(),
            units: vec!["multi".into()],
            apps: vec!["ai".into()],
            live: vec!["telemetry.log_level".into()],
            ..Default::default()
        };
        let auth = Arc::new(Auth::new(&Default::default(), "", "").unwrap());
        let cs = ConfigServer::new(&c, auth, vec![], "").unwrap().unwrap();
        assert!(cs.poll_once().await, "the first poll serves");
        assert!(!cs.poll_once().await, "nothing changed");
        let served = cs.served().unwrap();
        assert!(served.snapshot.file("application-default.yml").is_some());
        assert_eq!(served.registry_names, [("multi".to_string(), "MULTI".to_string()), ("ai".to_string(), "AI".to_string())]);
        let env = local_environment(&cs, &served, "ai", "default", None).unwrap();
        assert_eq!(env.sources.len(), 1);
        assert!(env.sources[0].name.ends_with("/ai.toml"));
        assert_eq!(env.sources[0].source["ai.db.password"], crate::config::yaml::Value::Str("aipw".into()));
        assert_eq!(env.sources[0].source["ai.db.port"], crate::config::yaml::Value::Int(1));
        assert!(local_environment(&cs, &served, "nope", "default", None).is_err());
        let Some(UnitState::Ready(d)) = served.unit("multi") else { panic!() };
        assert_eq!(d.document["database"]["password"], "pw");
        let v1 = d.version.clone();
        std::fs::write(units_dir.join("multi.toml"), "[server]\nport = 8111\n").unwrap();
        assert!(cs.poll_once().await, "a changed unit file is a new snapshot");
        let Some(UnitState::Ready(d)) = cs.served().unwrap().unit("multi").cloned() else { panic!() };
        assert_ne!(restart_part(&d.version), restart_part(&v1));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_repository_is_served() {
        let root = std::env::temp_dir().join(format!("lighthouse-repo-serve-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("qa/units")).unwrap();
        std::fs::create_dir_all(root.join("qa/apps")).unwrap();
        std::fs::write(root.join("qa/units/multi.toml"), "[server]\nport = 8110\n[database]\npassword = 'pw'\n").unwrap();
        std::fs::write(root.join("qa/apps/ai.env"), "A='1'\n").unwrap();
        std::fs::write(root.join("qa/apps/ai.toml"), "[ai.db]\nurl = 'u'\n").unwrap();
        // Any folder is an environment; its name comes from the folder unless [config] env says.
        let c = ConfigServerConfig { source: format!("dir:{}", root.join("qa").display()), layout: "repo".into(), ..ConfigServerConfig::default() };
        let auth = Arc::new(Auth::new(&Default::default(), "", "").unwrap());
        let cs = ConfigServer::new(&c, auth.clone(), vec![], "").unwrap().unwrap();
        assert!(cs.poll_once().await);
        let served = cs.served().unwrap();
        let Some(UnitState::Ready(d)) = served.unit("multi") else { panic!() };
        assert_eq!(d.document["database"]["password"], "pw");
        assert_eq!(served.apps.len(), 1);
        assert_eq!(cs.settings.env, "qa");
        let env = local_environment(&cs, &served, "ai", "ociqa", None).unwrap();
        assert!(env.sources[0].name.ends_with("/apps/ai.toml"), "{}", env.sources[0].name);
        std::fs::write(root.join("qa/units/multi.toml"), "[server]\nport = 8111\n").unwrap();
        assert!(cs.poll_once().await, "a changed unit file is a new snapshot");
        let named = ConfigServerConfig { env: "uat".into(), ..c.clone() };
        assert_eq!(ConfigServer::new(&named, auth.clone(), vec![], "").unwrap().unwrap().settings.env, "uat");
        let mut bad = c.clone();
        bad.local.dir = "config".into();
        assert!(ConfigServer::new(&bad, auth.clone(), vec![], "").is_err());
        let bad = ConfigServerConfig { layout: "other".into(), ..c };
        assert!(ConfigServer::new(&bad, auth, vec![], "").err().unwrap().to_string().contains("layout"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn etags() {
        let mut h = HeaderMap::new();
        assert!(!etag_matches(&h, "v1"));
        h.insert(header::IF_NONE_MATCH, "W/\"x\", \"v1\"".parse().unwrap());
        assert!(etag_matches(&h, "v1") && !etag_matches(&h, "v2"));
        let r = with_etag(StatusCode::OK.into_response(), "v1");
        assert_eq!(r.headers()[header::ETAG], "\"v1\"");
        assert_eq!(text_version("x").len(), 16);
    }
}
