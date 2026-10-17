//! gateway-rust configuration: pools of upstream instances and the route table.
//!
//! ```toml
//! [pools.files-serve]
//! upstreams = ["http://files-serve-blue:8103", "http://files-serve-green:8103"]
//! health_path = "/readyz"
//!
//! [pools.security]
//! upstreams = "eureka:SECURITY"          # follow the Java registry during the migration
//! health_path = "/actuator/health"
//!
//! [[routes]]
//! id = "files-read"
//! prefix = "/api/files"
//! contains = ["/api/files/static/file/", "/api/files/secured/file/"]
//! methods = ["GET", "HEAD"]
//! pool = "files-serve"
//! ```
//!
//! Routes are tried in order; the first whose prefix, `contains` and methods all match wins.

use std::collections::BTreeMap;

use platform::config::{EurekaConfig, MessagesConfig, RedisConfig, SecurityConfig, ServerConfig, TelemetryConfig, UpstreamConfig};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GatewayConfig {
    pub server: ServerConfig,
    pub telemetry: TelemetryConfig,
    /// Needed for `eureka:` pools and for the security upstream when it is `eureka:SECURITY`.
    pub eureka: EurekaConfig,
    /// Listens for security's evictions of the host resolution cache (`cmn-gatewayClientAppCodeType`).
    pub redis: RedisConfig,
    /// Where host names are resolved to client and app codes.
    pub security: SecurityConfig,
    pub resolution: ResolutionConfig,
    pub proxy: ProxyConfig,
    pub pools: BTreeMap<String, PoolConfig>,
    pub routes: Vec<RouteConfig>,
    /// The gateway's own error texts: override files and the default language.
    pub messages: MessagesConfig,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig { port: 8180, ..Default::default() },
            telemetry: TelemetryConfig::default(),
            eureka: EurekaConfig::default(),
            redis: RedisConfig::default(),
            security: SecurityConfig::default(),
            resolution: ResolutionConfig::default(),
            proxy: ProxyConfig::default(),
            pools: BTreeMap::new(),
            routes: Vec::new(),
            messages: MessagesConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ResolutionConfig {
    /// How long a host's (clientCode, appCode, surface) answer is reused. Security also evicts
    /// it when a client URL changes.
    pub host_cache_seconds: u64,
    /// The longest a draft-token answer is trusted (it is also capped by the token's expiry).
    pub draft_trust_seconds: u64,
}

impl Default for ResolutionConfig {
    fn default() -> Self {
        Self { host_cache_seconds: 3600, draft_trust_seconds: 60 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProxyConfig {
    pub connect_timeout_ms: u64,
    /// Until the upstream's response headers arrive. Long, because SSE streams and slow function
    /// executions share the path; the Spring gateway allowed an hour.
    pub response_timeout_seconds: u64,
    pub pool_idle_seconds: u64,
    pub max_idle_per_host: usize,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            connect_timeout_ms: 5_000,
            response_timeout_seconds: 3_600,
            pool_idle_seconds: 90,
            max_idle_per_host: 64,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PoolConfig {
    /// Base URLs, or `eureka:<APP>`.
    pub upstreams: UpstreamConfig,
    /// Checked on every instance; 2xx means healthy. `/readyz` for Rust units,
    /// `/actuator/health` for Java services.
    pub health_path: String,
    pub health_interval_seconds: u64,
    /// Consecutive failures before an instance stops getting traffic.
    pub unhealthy_after: u32,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            upstreams: UpstreamConfig::default(),
            health_path: "/readyz".into(),
            health_interval_seconds: 5,
            unhealthy_after: 2,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct RouteConfig {
    /// Also the `route` label on metrics.
    pub id: String,
    /// Matches the path itself or anything under it (`/api/files` matches `/api/files` and
    /// `/api/files/...`). `/` matches everything.
    pub prefix: String,
    /// When set, the path must also contain one of these.
    pub contains: Vec<String>,
    /// When set, only these methods.
    pub methods: Vec<String>,
    /// Only the path itself, nothing under it (a controller mapped to exactly `/api/ui`).
    pub exact: bool,
    /// The path must also pass this classifier: `security-auth` (AuthenticationController's
    /// routes) or `security-internal` (security-internal's routes). These are the same rules
    /// the Rust units use to split their own security calls, so gateway and units never disagree.
    pub classifier: Option<String>,
    pub pool: String,
    /// Overrides `proxy.response_timeout_seconds` for this route.
    pub timeout_seconds: Option<u64>,
}
