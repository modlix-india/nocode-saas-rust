//! gateway-rust configuration: pools of upstream instances and the route table.
//!
//! ```toml
//! [pools.files-serve]
//! upstreams = ["http://files-serve-blue:8103", "http://files-serve-green:8103"]
//! health_path = "/readyz"
//!
//! [pools.security]
//! upstreams = "lighthouse:SECURITY"          # follow the Lighthouse registry
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
//!
//! Each pool also has its own outlier ejection, retry and circuit breaker settings, with the
//! defaults below; a pool overrides any of them in its own sub-tables:
//!
//! ```toml
//! [pools.core-exec.breaker]
//! open_ms = 10000
//! ```

use std::collections::BTreeMap;

use platform::config::{RegistryConfig, MessagesConfig, RedisConfig, SecurityConfig, ServerConfig, TelemetryConfig, UpstreamConfig};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GatewayConfig {
    pub server: ServerConfig,
    pub telemetry: TelemetryConfig,
    /// Needed for `lighthouse:` pools and for the security upstream when it is `lighthouse:SECURITY`.
    pub registry: RegistryConfig,
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
            registry: RegistryConfig::default(),
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
    /// Base URLs, or `lighthouse:<APP>`.
    pub upstreams: UpstreamConfig,
    /// Checked on every instance; 2xx means healthy. `/readyz` for Rust units,
    /// `/actuator/health` for Java services.
    pub health_path: String,
    pub health_interval_seconds: u64,
    /// Consecutive failures before an instance stops getting traffic.
    pub unhealthy_after: u32,
    /// How often an `lighthouse:<APP>` pool reads its instance list again. The registry client's own
    /// refresh (every 30 s) is too slow for a gateway that must follow deploys.
    pub discovery_refresh_ms: u64,
    pub outlier: OutlierConfig,
    pub retry: RetryConfig,
    pub breaker: BreakerConfig,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            upstreams: UpstreamConfig::default(),
            health_path: "/readyz".into(),
            health_interval_seconds: 5,
            unhealthy_after: 2,
            discovery_refresh_ms: 2_000,
            outlier: OutlierConfig::default(),
            retry: RetryConfig::default(),
            breaker: BreakerConfig::default(),
        }
    }
}

/// Taking an instance that keeps answering 502/503/504 out of rotation for a while. A connect
/// failure always takes an instance out until its next passing health check, whatever this says.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OutlierConfig {
    /// Consecutive gateway failures (502, 503 or 504 from the instance, a broken connection, a
    /// timeout) that eject it. 0 turns this ejection off.
    pub consecutive_5xx: u32,
    /// An ejection lasts this long times the number of times the instance has been ejected...
    pub base_ejection_ms: u64,
    /// ...but never longer than this. The instance comes back at the first passing health check
    /// after that.
    pub max_ejection_ms: u64,
    /// At most this share of the pool's instances is ejected at once; a pool of one is never
    /// ejected this way.
    pub max_ejection_percent: u32,
}

impl Default for OutlierConfig {
    fn default() -> Self {
        Self { consecutive_5xx: 5, base_ejection_ms: 10_000, max_ejection_ms: 120_000, max_ejection_percent: 50 }
    }
}

/// Retrying on another instance. A request is retried at most once.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RetryConfig {
    /// Retry a GET, HEAD, OPTIONS, PUT or DELETE without a body that was answered 502, 503 or 504.
    /// A connection that could not be opened is retried whatever this says (nothing was sent).
    pub on_5xx: bool,
    /// The pause before a retry after a 5xx, picked at random between these two.
    pub jitter_min_ms: u64,
    pub jitter_max_ms: u64,
    /// 5xx retries stay within this share of the pool's requests over the window...
    pub budget_percent: u32,
    pub budget_window_seconds: u64,
    /// ...or within this many per second, whichever allows more.
    pub budget_min_per_second: u32,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            on_5xx: true,
            jitter_min_ms: 25,
            jitter_max_ms: 50,
            budget_percent: 20,
            budget_window_seconds: 10,
            budget_min_per_second: 3,
        }
    }
}

/// The pool's circuit breaker: when most requests fail, answer 503 at once for a while instead
/// of piling more onto the service.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BreakerConfig {
    pub enabled: bool,
    /// The failure rate is measured over this many seconds, in one-second buckets.
    pub window_seconds: u64,
    /// The breaker opens only once the window holds at least this many requests...
    pub min_requests: u32,
    /// ...and at least this share of them failed (a connect failure, a timeout, a broken
    /// connection, or 502/503/504 as the final answer).
    pub failure_percent: u32,
    /// How long it stays open the first time. Then a few trial requests go through: if they all
    /// succeed it closes, if one fails it opens again for twice as long, up to `max_open_ms`.
    pub open_ms: u64,
    pub max_open_ms: u64,
    pub half_open_trials: u32,
}

impl Default for BreakerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            window_seconds: 10,
            min_requests: 20,
            failure_percent: 50,
            open_ms: 5_000,
            max_open_ms: 60_000,
            half_open_trials: 3,
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
