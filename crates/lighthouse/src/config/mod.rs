//! Lighthouse's own configuration (its TOML and `MODLIX__` environment only: it never reads
//! configuration from itself or from a peer, and it never registers in its own registry), and
//! the config server it runs for everyone else:
//!
//! - [`source`]: oci-config snapshots from GitHub or a directory, kept on disk, shared with peers.
//! - [`yaml`]: yaml-rust2 typed as SnakeYAML (Spring) or as `tools/render_config.py` types it.
//! - [`spring`]: Spring Cloud Config's environment endpoint.
//! - [`manifest`], [`placeholders`], [`units`]: the units' documents and the ai and ssr env
//!   files, a port of `tools/render_config.py` driven by oci-config's `rust/units.toml`.
//! - [`auth`]: tokens and scopes. [`server`]: the routes. [`cli`]: `lighthouse render` and
//!   `lighthouse parity`.
//!
//! Where secrets come from: on the hosts, oci-config-rust (`[config] layout = "repo"`), a private
//! repository whose unit files hold them inline; locally, `config/local.toml`. Lighthouse reads
//! the repository with a read-only GitHub token that reaches it only at deploy time (CI, as
//! `MODLIX__CONFIG__GITHUB_TOKEN`), and serves units and ai/ssr without a token on the host's
//! private Docker network (`[auth] open`), as the Java config-server did.

pub mod auth;
pub mod cli;
pub mod local;
pub mod manifest;
pub mod placeholders;
pub mod server;
pub mod source;
pub mod spring;
pub mod units;
pub mod yaml;

use platform::config::{ServerConfig, TelemetryConfig};
use serde::{Deserialize, Serialize};

use self::auth::AuthConfig;
use self::local::LocalConfig;
use self::spring::SpringConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LighthouseConfig {
    /// SHA-256 (hex) of the token that unlocks managing instances from the dashboard
    /// (`MODLIX__ADMIN_TOKEN_SHA256`). Empty: the dashboard is read-only. Reads stay open, as
    /// Eureka's are.
    pub admin_token_sha256: String,
    pub server: ServerConfig,
    pub telemetry: TelemetryConfig,
    pub registry: RegistryConfig,
    pub allowed: AllowedConfig,
    /// The config server. Off while `source` is empty.
    pub config: ConfigServerConfig,
    /// Tokens for the config endpoints, besides the admin and peer tokens.
    pub auth: AuthConfig,
}

impl Default for LighthouseConfig {
    fn default() -> Self {
        Self {
            admin_token_sha256: String::new(),
            server: ServerConfig { port: 8761, ..ServerConfig::default() },
            telemetry: TelemetryConfig::default(),
            registry: RegistryConfig::default(),
            allowed: AllowedConfig::default(),
            config: ConfigServerConfig::default(),
            auth: AuthConfig::default(),
        }
    }
}

/// `[config]`: where oci-config comes from and what this deployment serves of it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ConfigServerConfig {
    /// `github:<owner>/<repo>` or `dir:<path>`. Empty: no config server on this instance.
    pub source: String,
    /// The branch read (Spring's label).
    pub label: String,
    /// The environment whose units this deployment configures: dev, stage or prod, or `local`
    /// with `[config.local]` (the local stack).
    pub env: String,
    /// What the source holds: empty for oci-config (the Java settings, rendered through
    /// `rust/`), `repo` for oci-config-rust (each environment's unit files as they are; see
    /// [`local::repo_documents`]).
    pub layout: String,
    pub poll_seconds: u64,
    /// Where the last good snapshot is kept (a volume), readable by Lighthouse only. Empty: not
    /// kept.
    pub snapshot_dir: String,
    pub github_api: String,
    /// A read-only token for the repository: `MODLIX__CONFIG__GITHUB_TOKEN`, never a file.
    pub github_token: String,
    pub spring: SpringConfig,
    /// The local stack's units ([`local`]); only with `env = "local"`.
    pub local: LocalConfig,
}

impl Default for ConfigServerConfig {
    fn default() -> Self {
        Self {
            source: String::new(),
            label: "master".into(),
            env: String::new(),
            layout: String::new(),
            poll_seconds: 30,
            snapshot_dir: String::new(),
            github_api: "https://api.github.com".into(),
            github_token: String::new(),
            spring: SpringConfig::default(),
            local: LocalConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RegistryConfig {
    /// How the peers reach this instance (`http://lighthouse-1:8761`). A peer with this URL is
    /// this instance and is skipped, so every instance can share one peer list.
    pub self_url: String,
    /// Every Lighthouse instance of the environment, this one included or not.
    pub peers: Vec<String>,
    /// Bearer token on every call between peers. Empty: no token is sent or required.
    pub peer_token: String,
    /// How often expired leases are evicted.
    pub eviction_interval_ms: u64,
    /// An eviction tick that runs this much later than planned is skipped: the process was
    /// stalled, and heartbeats were probably held up with it.
    pub late_tick_skip_ms: u64,
    /// Eureka's self-preservation: no eviction while the renewals of the last minute are below
    /// this fraction of the renewals expected.
    pub renewal_percent_threshold: f64,
    pub self_preservation: bool,
    /// How long a change stays in `/apps/delta`.
    pub delta_retention_seconds: u64,
    /// How long a cancelled instance refuses replicated registrations that are not newer.
    pub tombstone_seconds: u64,
    /// After this long without any peer answering the startup sync, serve what this instance has.
    pub startup_wait_seconds: u64,
    pub sync_retry_ms: u64,
    /// Replication batches go out this often, or as soon as `replication_batch` items wait.
    pub replication_flush_ms: u64,
    pub replication_batch: usize,
    /// Items waiting for one peer at most; on overflow heartbeats are dropped first.
    pub replication_queue_limit: usize,
    /// How often the peers' digests are compared to repair what replication lost.
    pub digest_interval_seconds: u64,
    pub peer_timeout_ms: u64,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            self_url: String::new(),
            peers: vec![],
            peer_token: String::new(),
            eviction_interval_ms: 5_000,
            late_tick_skip_ms: 10_000,
            renewal_percent_threshold: 0.85,
            self_preservation: true,
            delta_retention_seconds: 180,
            tombstone_seconds: 120,
            startup_wait_seconds: 40,
            sync_retry_ms: 1_000,
            replication_flush_ms: 100,
            replication_batch: 250,
            replication_queue_limit: 10_000,
            digest_interval_seconds: 60,
            peer_timeout_ms: 5_000,
        }
    }
}

/// Who may call the registry. Internal traffic stays on each host's private Docker network
/// and the host ports bind to 127.0.0.1; this is the last check, on the source address.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AllowedConfig {
    /// Source networks (CIDR or single addresses) allowed on every registry route. Empty allows
    /// any address. The health and metrics routes are always open.
    pub networks: Vec<String>,
    /// App names allowed to register (any case). Empty allows any app.
    pub apps: Vec<String>,
    /// The networks trusted with tokenless configuration reads, registry writes and peer calls
    /// (on a host: its own Docker network). Callers from the other allowed networks see the
    /// registry and the dashboard read-only. Empty trusts every allowed caller.
    pub trusted: Vec<String>,
}

impl Default for AllowedConfig {
    fn default() -> Self {
        Self {
            networks: ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7"]
                .map(String::from)
                .to_vec(),
            apps: vec![],
            trusted: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_layers() {
        let c = LighthouseConfig::default();
        assert_eq!(c.server.port, 8761);
        assert_eq!((c.registry.eviction_interval_ms, c.registry.renewal_percent_threshold), (5_000, 0.85));
        assert_eq!(c.allowed.networks.len(), 6);
        let t: LighthouseConfig = toml::from_str("[registry]\npeers = [\"http://a:8761\"]\n[server]\nport = 9\n").unwrap();
        assert_eq!((t.server.port, t.registry.peers.len(), t.registry.startup_wait_seconds), (9, 1, 40));
        assert_eq!((c.config.label.as_str(), c.config.poll_seconds, c.config.source.as_str()), ("master", 30, ""));
        let t: LighthouseConfig = toml::from_str(
            "[config]\nsource = \"dir:x\"\nenv = \"dev\"\n[config.spring.apps.ssr]\nopen = true\nprefixes = [\"ssr.\"]\n\
             [[auth.tokens]]\nname = \"u\"\nsha256 = \"ab\"\nscopes = [\"units\"]\n",
        )
        .unwrap();
        assert!(t.config.spring.apps["ssr"].open);
        assert_eq!(t.auth.tokens[0].scopes, [auth::Scope::Units]);
    }
}
