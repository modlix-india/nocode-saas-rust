//! Typed configuration, loaded once at start.
//!
//! Sources, later ones overriding earlier ones:
//! 1. the defaults in the service's config struct (`#[serde(default)]`),
//! 2. a TOML file: `$CONFIG_FILE`, else `/etc/modlix/<service>.toml`, else `./config/<service>.toml`
//!    (the first that exists; none is fine),
//! 3. environment variables `MODLIX__<SECTION>__<KEY>` (double underscore nests, case-insensitive),
//!    e.g. `MODLIX__DATABASE__PASSWORD`.
//!
//! Secrets belong in the environment (or a mounted file read through `*_file` keys by the
//! service), never in a TOML file kept in git.
//!
//! With `LIGHTHOUSE_URLS` set, [`load_async`] puts the unit's document from Lighthouse between
//! the TOML file and the environment, and remembers its version (the unit registers it as
//! `configVersion`). A change of anything but the document's live keys is a rolling restart, so
//! every instance runs a known configuration; the live keys (log level, feature flags, the
//! gateway's routes and pools) reach a [`LiveConfig`] in place through [`spawn_live_watch`].
//! Without `LIGHTHOUSE_URLS` nothing changes: defaults, TOML, environment, as before.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use figment::providers::{Env, Format, Serialized, Toml};
use figment::Figment;
use lighthouse_client::config::{restart_part, Change, ConfigClient};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Where a service's TOML comes from, for the startup log. `CONFIG_FILE=none` reads no file
/// (the local stack driven by Lighthouse).
pub fn config_file(service: &str) -> Option<PathBuf> {
    if let Ok(p) = std::env::var("CONFIG_FILE") {
        if p == "none" {
            return None;
        }
        if !p.is_empty() {
            return Some(PathBuf::from(p));
        }
    }
    [
        PathBuf::from(format!("/etc/modlix/{service}.toml")),
        PathBuf::from(format!("config/{service}.toml")),
    ]
    .into_iter()
    .find(|p| p.exists())
}

/// Loads `T` for `service`. `T: Default` provides the defaults layer.
pub fn load<T>(service: &str) -> Result<T>
where
    T: DeserializeOwned + Serialize + Default,
{
    layered(service, None)
}

/// Defaults < TOML file < `document` (from Lighthouse) < `MODLIX__` environment.
fn layered<T>(service: &str, document: Option<&serde_json::Value>) -> Result<T>
where
    T: DeserializeOwned + Serialize + Default,
{
    // Configuration is the first thing every unit loads, before any TLS client exists.
    crate::crypto::install();
    let mut fig = Figment::from(Serialized::defaults(T::default()));
    if let Some(file) = config_file(service) {
        fig = fig.merge(Toml::file(&file));
    }
    if let Some(doc) = document {
        fig = fig.merge(Serialized::defaults(doc));
    }
    fig = fig.merge(Env::prefixed("MODLIX__").split("__").lowercase(true));
    fig.extract::<T>()
        .with_context(|| format!("configuration of {service} is invalid"))
}

/// A configuration loaded at start, and where it came from.
pub struct Loaded<T> {
    pub config: T,
    /// Set when the unit's document came from Lighthouse.
    pub lighthouse: Option<FromLighthouse>,
    /// Why Lighthouse was not used although `LIGHTHOUSE_URLS` is set; for the log, once
    /// telemetry runs.
    pub warning: Option<String>,
}

impl<T> Loaded<T> {
    /// Logs where the configuration came from; once telemetry runs.
    pub fn log_source(&self, service: &str) {
        if let Some(file) = config_file(service) {
            tracing::info!(file = %file.display(), "configuration file");
        }
        if let Some(l) = &self.lighthouse {
            tracing::info!(version = l.version, "configuration from lighthouse");
        }
        if let Some(w) = &self.warning {
            tracing::warn!("{w}");
        }
    }
}

/// The unit's document as Lighthouse served it at start.
#[derive(Clone)]
pub struct FromLighthouse {
    pub unit: String,
    /// What the unit registers as `configVersion`.
    pub version: String,
    pub live: Vec<String>,
    pub document: serde_json::Value,
    pub client: Arc<ConfigClient>,
}

fn lighthouse_urls_set() -> bool {
    std::env::var("LIGHTHOUSE_URLS").is_ok_and(|v| !v.trim().is_empty())
}

/// Loads `T` for `service`, with Lighthouse's document for the unit when `LIGHTHOUSE_URLS` is
/// set (tried across the servers for up to a minute). Without it, or when Lighthouse does not
/// answer, the local layers alone, unless `LIGHTHOUSE_REQUIRED` is set: then the unit does not
/// start.
pub async fn load_async<T>(service: &str) -> Result<Loaded<T>>
where
    T: DeserializeOwned + Serialize + Default,
{
    crate::crypto::install();
    if !lighthouse_urls_set() {
        return Ok(Loaded { config: load(service)?, lighthouse: None, warning: None });
    }
    let client = Arc::new(ConfigClient::from_env());
    load_from(service, client, Duration::from_secs(60), Duration::from_secs(2), lighthouse_client::config::required()).await
}

async fn load_from<T>(service: &str, client: Arc<ConfigClient>, within: Duration, pause: Duration, required: bool) -> Result<Loaded<T>>
where
    T: DeserializeOwned + Serialize + Default,
{
    match client.fetch_within(service, within, pause).await {
        Ok(doc) => {
            let config = layered(service, Some(&doc.document))?;
            lighthouse_client::config::set_running_version(&doc.version);
            let from = FromLighthouse { unit: service.to_string(), version: doc.version, live: doc.live, document: doc.document, client };
            Ok(Loaded { config, lighthouse: Some(from), warning: None })
        }
        Err(e) if required => Err(e.context("LIGHTHOUSE_REQUIRED is set")),
        Err(e) => Ok(Loaded {
            config: load(service)?,
            lighthouse: None,
            warning: Some(format!("configuration from Lighthouse failed, running on the local layers: {e:#}")),
        }),
    }
}

/// A configuration that changes in place: the live keys of a unit's document. Reads are a
/// pointer load; the version watch stores a new value whole.
pub struct LiveConfig<T> {
    current: Arc<ArcSwap<T>>,
    version: Arc<ArcSwap<String>>,
}

impl<T> Clone for LiveConfig<T> {
    fn clone(&self) -> Self {
        Self { current: self.current.clone(), version: self.version.clone() }
    }
}

impl<T> LiveConfig<T> {
    pub fn new(value: T, version: &str) -> Self {
        Self { current: Arc::new(ArcSwap::from_pointee(value)), version: Arc::new(ArcSwap::from_pointee(version.to_string())) }
    }

    pub fn get(&self) -> Arc<T> {
        self.current.load_full()
    }

    /// The version of the document the current value was built from.
    pub fn version(&self) -> Arc<String> {
        self.version.load_full()
    }

    pub fn store(&self, value: T, version: &str) {
        self.current.store(Arc::new(value));
        self.version.store(Arc::new(version.to_string()));
    }
}

/// The live keys whose value differs between two documents.
fn changed_keys(old: &serde_json::Value, new: &serde_json::Value, live: &[String]) -> Vec<String> {
    let at = |d: &serde_json::Value, k: &str| k.split('.').try_fold(d, |c, p| c.get(p)).cloned();
    live.iter().filter(|k| at(old, k) != at(new, k)).cloned().collect()
}

/// Polls the unit's version every `every`. When only live keys changed it rebuilds `T` from the
/// new document (the same layers as at start) and stores it in `live`; any other change is
/// left to the rolling restart. Logs key names, never values.
pub fn spawn_live_watch<T>(service: &str, from: &FromLighthouse, live: LiveConfig<T>, every: Duration) -> tokio::task::JoinHandle<()>
where
    T: DeserializeOwned + Serialize + Default + Send + Sync + 'static,
{
    let service = service.to_string();
    let client = from.client.clone();
    let running = from.version.clone();
    let doc = Arc::new(LastDocument::new(from.document.clone()));
    lighthouse_client::config::watch_version(from.client.clone(), &from.unit, &from.version, every, move |change| {
        let (service, client, running, live, doc) = (service.clone(), client.clone(), running.clone(), live.clone(), doc.clone());
        async move {
            match change {
                Change::Restart(v) => {
                    tracing::info!(unit = service, version = v, "configuration changed beyond its live keys: the rolling restart applies it");
                    true
                }
                Change::Live(_) => match client.fetch(&service).await {
                    Ok(cfg) if restart_part(&cfg.version) != restart_part(&running) => {
                        tracing::info!(unit = service, version = cfg.version, "configuration changed beyond its live keys: the rolling restart applies it");
                        true
                    }
                    Ok(cfg) => match layered::<T>(&service, Some(&cfg.document)) {
                        Ok(value) => {
                            let keys = changed_keys(&doc.get(), &cfg.document, &cfg.live);
                            live.store(value, &cfg.version);
                            doc.set(cfg.document);
                            tracing::info!(unit = service, version = cfg.version, keys = ?keys, "live configuration applied");
                            true
                        }
                        Err(e) => {
                            tracing::warn!(unit = service, error = %format!("{e:#}"), "live configuration not applied");
                            false
                        }
                    },
                    Err(e) => {
                        tracing::warn!(unit = service, error = %format!("{e:#}"), "live configuration not fetched");
                        false
                    }
                },
            }
        }
    })
}

/// The last document applied, shared by the watch's calls.
struct LastDocument(std::sync::Mutex<serde_json::Value>);

impl LastDocument {
    fn new(v: serde_json::Value) -> Self {
        Self(std::sync::Mutex::new(v))
    }

    fn get(&self) -> serde_json::Value {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn set(&self, v: serde_json::Value) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = v;
    }
}

/// The sections every service has.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub port: u16,
    /// How long to keep serving after leaving discovery, so requests already on their way land.
    pub shutdown_grace_seconds: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self { port: 8080, shutdown_grace_seconds: 5 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TelemetryConfig {
    /// `json` (one object per line, for collectors) or `pretty` (for a terminal).
    pub log_format: String,
    /// A `tracing` filter, e.g. `info,files=debug`. `RUST_LOG` overrides it.
    pub log_level: String,
    /// OTLP/HTTP endpoint for traces, e.g. `http://alloy:4318`. Empty disables tracing export;
    /// `OTEL_EXPORTER_OTLP_ENDPOINT` also sets it.
    pub otlp_endpoint: String,
    /// Fraction of traces kept when exporting, 0.0 to 1.0.
    pub trace_sample_ratio: f64,
    /// `deployment.environment` on every span and metric, e.g. `production`.
    pub environment: String,
    /// Which copy this is (`blue`, `green-2`, a pod name). Defaults to the hostname.
    pub instance: String,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            log_format: "json".into(),
            log_level: "info".into(),
            otlp_endpoint: String::new(),
            trace_sample_ratio: 1.0,
            environment: "local".into(),
            instance: String::new(),
        }
    }
}

/// How to reach another service: a fixed list of base URLs (round robin), or `eureka:<APP>`
/// to follow the Java registry while it still exists.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum UpstreamConfig {
    One(String),
    Many(Vec<String>),
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self::Many(vec![])
    }
}

impl UpstreamConfig {
    pub fn entries(&self) -> Vec<String> {
        match self {
            Self::One(s) => s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect(),
            Self::Many(v) => v.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct EurekaConfig {
    /// Register this instance in Eureka so Java Feign clients can call it by name. Off unless a
    /// Java service calls this unit.
    pub register: bool,
    /// The name to register under, e.g. `FILES`.
    pub register_as: String,
    /// Eureka base URLs, e.g. `http://eureka:9999/eureka/`. Needed by `register` and by any
    /// `eureka:<APP>` upstream.
    pub zones: Vec<String>,
    /// The address to advertise. Defaults to this machine's primary IP.
    pub instance_ip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RedisConfig {
    /// Empty disables cross-instance cache eviction.
    pub url: String,
    /// The Java services' effective `redis.cache.prefix`. It is `cmn` for every service in every
    /// environment: `application-<profile>.yml` sets it and outranks the per-service yml
    /// (`fil`, `ui`, `cor`...). Must match while Java instances still write the same data.
    pub cache_prefix: String,
    pub eviction_channel: String,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            cache_prefix: "cmn".into(),
            eviction_channel: "evictionChannel".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct SecurityConfig {
    /// Where the security service is: base URL(s) or `eureka:SECURITY`.
    pub upstream: UpstreamConfig,
    /// Where `AuthenticationController` runs when it runs apart from the rest of security
    /// (security-auth): the caller's context (`internal/securityContextAuthentication`, 73% of
    /// security's traffic) and one-time token sign-ins go here. Empty sends them to `upstream`.
    pub auth_upstream: UpstreamConfig,
    /// Where security's service-to-service routes run when they run apart (security-internal):
    /// paths with an `internal` segment, except `AuthenticationController`'s (which follow
    /// `auth_upstream`) and the few security-internal does not serve. Empty sends them to
    /// `upstream`. See `security::is_internal_route`.
    pub internal_upstream: UpstreamConfig,
    /// Seconds to reuse an answer for the same token. 0 asks security every time, as the Java
    /// services do today.
    pub auth_cache_seconds: u64,
}

/// `[messages]`: how this service's error messages are customised (see `platform::messages`).
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(default)]
pub struct MessagesConfig {
    /// A directory of `<locale>.toml` files (`en.toml`, `pt-BR.toml`) whose texts replace the
    /// built-in ones, code by code. Empty: none.
    pub override_dir: String,
    /// The language tried after the request's and the caller's, before English. Empty: none.
    pub default_locale: String,
}

/// A MySQL connection. `password` should come from `MODLIX__<SECTION>__PASSWORD`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MySqlConfig {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub username: String,
    pub password: String,
    pub max_connections: u32,
}

impl Default for MySqlConfig {
    fn default() -> Self {
        Self {
            host: "localhost".into(),
            port: 3306,
            database: String::new(),
            username: "root".into(),
            password: String::new(),
            max_connections: 8,
        }
    }
}

/// A MongoDB connection, as the Java services' `<service>.mongo.uri`. The URI carries the
/// credentials, so it belongs in `MODLIX__<SECTION>__URI`, never in a TOML file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MongoConfig {
    pub uri: String,
    /// The database to use; empty takes the one named in the URI's path.
    pub database: String,
    pub max_pool_size: u32,
    pub min_pool_size: u32,
}

impl Default for MongoConfig {
    fn default() -> Self {
        Self {
            uri: "mongodb://localhost:27017".into(),
            database: String::new(),
            max_pool_size: 32,
            min_pool_size: 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Serialize, Deserialize, Default)]
    #[serde(default)]
    struct Sample {
        server: ServerConfig,
        security: SecurityConfig,
        database: MySqlConfig,
    }

    #[test]
    fn finds_the_config_file() {
        figment::Jail::expect_with(|jail| {
            assert!(config_file("nothing-here").is_none());
            jail.create_dir("config")?;
            jail.create_file("config/svc.toml", "")?;
            assert_eq!(config_file("svc"), Some(PathBuf::from("config/svc.toml")));
            jail.set_env("CONFIG_FILE", "/elsewhere/x.toml");
            assert_eq!(config_file("svc"), Some(PathBuf::from("/elsewhere/x.toml")));
            jail.set_env("CONFIG_FILE", "none");
            assert_eq!(config_file("svc"), None, "none reads no file, not even config/svc.toml");
            jail.set_env("MODLIX__SERVER__PORT", "not-a-port");
            assert!(load::<Sample>("svc").is_err(), "a bad value stops startup");
            Ok(())
        });
        assert_eq!(UpstreamConfig::default().entries(), Vec::<String>::new());
        assert_eq!(UpstreamConfig::Many(vec!["a".into()]).entries(), vec!["a"]);
        let t = TelemetryConfig::default();
        assert_eq!((t.log_format.as_str(), t.trace_sample_ratio), ("json", 1.0));
        assert_eq!(RedisConfig::default().cache_prefix, "cmn");
        assert_eq!(MongoConfig::default().uri, "mongodb://localhost:27017");
    }

    #[test]
    fn layers_defaults_toml_env() {
        figment::Jail::expect_with(|jail| {
            jail.create_dir("config")?;
            jail.create_file(
                "config/sample.toml",
                r#"
                [server]
                port = 9000
                [security]
                upstream = "http://a:1, http://b:2"
                [database]
                database = "files"
                "#,
            )?;
            jail.set_env("MODLIX__DATABASE__PASSWORD", "s3cret");
            jail.set_env("MODLIX__SERVER__SHUTDOWN_GRACE_SECONDS", "9");
            let c: Sample = load("sample").map_err(|e| e.to_string())?;
            assert_eq!(c.server.port, 9000);
            assert_eq!(c.server.shutdown_grace_seconds, 9);
            assert_eq!(c.database.database, "files");
            assert_eq!(c.database.password, "s3cret");
            assert_eq!(c.database.port, 3306);
            assert_eq!(c.security.upstream.entries(), vec!["http://a:1", "http://b:2"]);
            Ok(())
        });
    }

    #[derive(Debug, Serialize, Deserialize, Default, Clone)]
    #[serde(default)]
    struct Unit {
        server: ServerConfig,
        telemetry: TelemetryConfig,
        database: MySqlConfig,
    }

    /// The version `/version` answers, the one `/config` answers, and the document.
    type Shared = std::sync::Arc<std::sync::Mutex<(String, String, serde_json::Value)>>;

    /// A Lighthouse that serves one unit's document and version.
    async fn fake_lighthouse(state: Shared) -> String {
        use axum::extract::State;
        use axum::http::{HeaderMap, StatusCode};
        use axum::response::IntoResponse;
        use axum::routing::get;
        let app = axum::Router::new()
            .route(
                "/v1/units/{unit}/config",
                get(|State(s): State<Shared>| async move {
                    let (_, v, doc) = s.lock().unwrap().clone();
                    axum::Json(serde_json::json!({"unit": "u", "env": "dev", "version": v, "sha": "abc",
                        "live": ["telemetry.log_level", "features"], "config": doc}))
                }),
            )
            .route(
                "/v1/units/{unit}/version",
                get(|State(s): State<Shared>, h: HeaderMap| async move {
                    let v = s.lock().unwrap().0.clone();
                    if h.get("if-none-match").and_then(|x| x.to_str().ok()) == Some(&format!("\"{v}\"")) {
                        StatusCode::NOT_MODIFIED.into_response()
                    } else {
                        v.into_response()
                    }
                }),
            )
            .with_state(state);
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        url
    }

    fn doc(port: u16, level: &str) -> serde_json::Value {
        serde_json::json!({"server": {"port": port}, "telemetry": {"log_level": level}, "database": {"password": "from-doc", "port": 3307}})
    }

    #[test]
    fn lighthouse_sits_between_the_file_and_the_environment() {
        figment::Jail::expect_with(|jail| {
            jail.create_dir("config")?;
            jail.create_file("config/u.toml", "[server]\nport = 9000\n[database]\ndatabase = \"files\"\nport = 3306\n")?;
            jail.set_env("MODLIX__DATABASE__PASSWORD", "from-env");
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let state: Shared = std::sync::Arc::new(std::sync::Mutex::new(("aaaa.1111".into(), "aaaa.1111".into(), doc(9001, "info"))));
                let url = fake_lighthouse(state.clone()).await;
                let client = std::sync::Arc::new(ConfigClient::new(&[url], None));
                let l: Loaded<Unit> = load_from("u", client.clone(), Duration::from_secs(5), Duration::from_millis(10), true).await.unwrap();
                let c = &l.config;
                assert_eq!(c.server.port, 9001, "the document outranks the file");
                assert_eq!(c.database.database, "files", "the file fills what the document lacks");
                assert_eq!(c.database.port, 3307);
                assert_eq!(c.database.password, "from-env", "the environment outranks the document");
                let from = l.lighthouse.clone().unwrap();
                assert_eq!(from.version, "aaaa.1111");
                assert_eq!(lighthouse_client::config::running_version().as_deref(), Some("aaaa.1111"));

                // Live: only the log level changes, and it is applied in place.
                let live = LiveConfig::new(l.config.clone(), &from.version);
                let watch = spawn_live_watch("u", &from, live.clone(), Duration::from_millis(20));
                *state.lock().unwrap() = ("aaaa.2222".into(), "aaaa.2222".into(), doc(9001, "debug"));
                let mut applied = false;
                for _ in 0..250 {
                    if live.get().telemetry.log_level == "debug" {
                        applied = true;
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                assert!(applied, "the live key was applied");
                assert_eq!(live.version().as_str(), "aaaa.2222");
                assert_eq!(live.get().database.password, "from-env");
                // Restart: the port changes; nothing is applied in place.
                *state.lock().unwrap() = ("bbbb.3333".into(), "bbbb.3333".into(), doc(9100, "warn"));
                tokio::time::sleep(Duration::from_millis(200)).await;
                assert_eq!(live.get().server.port, 9001);
                assert_eq!(live.get().telemetry.log_level, "debug");
                // The poll says live, but the document moved on to a restart by the time it is read:
                // not applied.
                *state.lock().unwrap() = ("aaaa.4444".into(), "cccc.4444".into(), doc(9200, "error"));
                tokio::time::sleep(Duration::from_millis(200)).await;
                assert_eq!(live.get().server.port, 9001);
                watch.abort();
                assert_eq!(changed_keys(&doc(1, "a"), &doc(1, "b"), &["telemetry.log_level".into(), "features".into()]), ["telemetry.log_level"]);
            });
            Ok(())
        });
    }

    #[test]
    fn without_lighthouse() {
        figment::Jail::expect_with(|jail| {
            let rt = tokio::runtime::Runtime::new().unwrap();
            // Not set: the local layers, nothing asked.
            jail.set_env("LIGHTHOUSE_URLS", "");
            let l: Loaded<Unit> = rt.block_on(load_async("u")).unwrap();
            assert!(l.lighthouse.is_none() && l.warning.is_none());
            assert_eq!(l.config.server.port, 8080);
            // Set but unreachable: the local layers and a warning, or no start when required.
            let dead = std::sync::Arc::new(ConfigClient::new(&["http://127.0.0.1:1"], None));
            let l: Loaded<Unit> =
                rt.block_on(load_from("u", dead.clone(), Duration::from_millis(30), Duration::from_millis(10), false)).unwrap();
            assert!(l.lighthouse.is_none() && l.warning.unwrap().contains("Lighthouse failed"));
            let e = rt.block_on(load_from::<Unit>("u", dead, Duration::from_millis(30), Duration::from_millis(10), true)).err().unwrap();
            assert!(format!("{e:#}").contains("LIGHTHOUSE_REQUIRED"));
            jail.set_env("LIGHTHOUSE_URLS", "http://127.0.0.1:1");
            jail.set_env("LIGHTHOUSE_REQUIRED", "true");
            let started = std::time::Instant::now();
            let handle = rt.spawn(load_async::<Unit>("u"));
            std::thread::sleep(Duration::from_millis(50));
            handle.abort();
            assert!(started.elapsed() < Duration::from_secs(5));
            Ok(())
        });
    }
}
