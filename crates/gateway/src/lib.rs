//! gateway-rust: the single entrance for API traffic behind nginx, replacing the Spring Cloud
//! Gateway, and the load balancer in front of every service.
//!
//! For each request: work out the client and app it is for (from the URL or the host), pick the
//! route, pick a healthy instance of the route's pool, and stream the request there and the
//! response back. See `proxy.rs` for exactly what the service receives.

pub mod breaker;
pub mod budget;
pub mod config;
pub mod messages;
pub mod path;
pub mod pool;
pub mod proxy;
pub mod resolve;
pub mod routes;
pub mod window;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use axum::Router;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use platform::app::Service;
use platform::cache::CacheService;
use platform::registry::Registry;
use platform::health::Health;

use crate::config::GatewayConfig;
use crate::pool::Pool;
use crate::proxy::Gateway;
use crate::resolve::Resolver;
use crate::routes::Routes;

pub const NAME: &str = "gateway-rust";

/// Loads the configuration and serves until shut down.
pub async fn run() -> Result<()> {
    let loaded = platform::config::load_async::<GatewayConfig>(NAME).await?;
    let telemetry = platform::telemetry::init(NAME, &loaded.config.telemetry)?;
    loaded.log_source(NAME);
    let cfg = loaded.config;
    platform::messages::configure(&cfg.messages)?;
    let (app, registry) = build(&cfg).await?;

    // Ready as soon as it listens: a pool with no healthy instance is that service's outage,
    // reported by `gateway_pool_healthy_instances`, and must not take the edge out of rotation.
    let health = Health::new(telemetry.metrics.clone());

    Service { name: NAME.to_string(), server: cfg.server.clone(), telemetry, health, registry, cors: false }
        .run(app)
        .await
}

/// The proxy router for a configuration, with its pools' health checks running.
pub async fn build(cfg: &GatewayConfig) -> Result<(Router, Option<Registry>)> {
    messages::register();
    let registry = if cfg.registry.register || !cfg.registry.zones.is_empty() {
        Some(Registry::new(&cfg.registry, cfg.server.port)?)
    } else {
        None
    };

    let mut pools = BTreeMap::new();
    for (name, p) in &cfg.pools {
        let pool = Pool::new(name, p, registry.as_ref())?;
        pool.spawn_background();
        pools.insert(name.clone(), pool);
    }
    let routes = Routes::build(&cfg.routes, &pools)?;

    // Security's evictions of the host cache reach us on the shared channel.
    let cache = CacheService::new(&cfg.redis.cache_prefix, &cfg.redis.eviction_channel, Some(cfg.redis.url.as_str()))?;
    let hosts = cache.family();
    cache.spawn_eviction_listener();

    let resolver = Resolver::new(
        // Host and draft resolution are security-internal routes: `internal_upstream` when set.
        // Always the security units themselves, never this gateway: the gateway asks security
        // before it can route anything, so going through itself would loop.
        platform::security::security_upstream(&cfg.security, registry.as_ref())?,
        hosts,
        cfg.resolution.draft_trust_seconds,
    )?;

    let mut connector = HttpConnector::new();
    connector.set_connect_timeout(Some(Duration::from_millis(cfg.proxy.connect_timeout_ms)));
    connector.set_nodelay(true);
    connector.enforce_http(true);
    let client = Client::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(cfg.proxy.pool_idle_seconds))
        .pool_max_idle_per_host(cfg.proxy.max_idle_per_host)
        .build(connector);

    let gateway = Arc::new(Gateway {
        routes,
        resolver,
        client,
        default_timeout: Duration::from_secs(cfg.proxy.response_timeout_seconds),
    });

    let app = Router::new().fallback(proxy::handle).with_state(gateway);
    Ok((app, registry))
}
