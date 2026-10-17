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
//! service), never in a TOML file kept in git. There is no reload: a change is a redeploy, so
//! every instance runs a known configuration.

use std::path::PathBuf;

use anyhow::{Context, Result};
use figment::providers::{Env, Format, Serialized, Toml};
use figment::Figment;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Where a service's TOML comes from, for the startup log.
pub fn config_file(service: &str) -> Option<PathBuf> {
    if let Ok(p) = std::env::var("CONFIG_FILE") {
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
    let mut fig = Figment::from(Serialized::defaults(T::default()));
    if let Some(file) = config_file(service) {
        fig = fig.merge(Toml::file(&file));
    }
    fig = fig.merge(Env::prefixed("MODLIX__").split("__").lowercase(true));
    fig.extract::<T>()
        .with_context(|| format!("configuration of {service} is invalid"))
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
}
