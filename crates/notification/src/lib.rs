//! The notification service in Rust: in-app notifications over SSE, the `notifications` queue
//! listener that sends email and in-app notifications, and user preferences. It replaces the
//! Java `notification` service (commons2, servlet) and keeps its MySQL schema.
//!
//! - HTTP: [`handlers`] (`/api/notification/...`).
//! - Queue: [`queue`] consumes `notifications.queues` and runs [`send::SendService`] per message,
//!   which reads the definitions from core ([`calls::CoreClient`]) and the recipients from
//!   security ([`calls::DirectoryClient`]), then hands out email ([`email`]) and in-app
//!   ([`inapp`]) notifications. A data notification (`kind: DATA`) skips the definitions and the
//!   database and only reaches the recipients' open streams.
//! - Streams: [`sse`] holds this process's; [`push`] reaches every instance's through Redis.

pub mod calls;
pub mod catalogue;
pub mod config;
pub mod dao;
pub mod email;
pub mod errors;
pub mod handlers;
pub mod inapp;
pub mod messages;
pub mod model;
pub mod preference;
pub mod push;
pub mod queue;
pub mod send;
pub mod spring;
pub mod sse;
pub mod template;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use platform::app::Service;
use platform::cache::CacheService;
use platform::registry::Registry;
use platform::health::Health;
use platform::security::SecurityClient;
use platform::upstream::Upstream;

use crate::calls::{CoreClient, DirectoryClient};
use crate::config::NotificationConfig;
use crate::dao::Dao;
use crate::email::EmailService;
use crate::handlers::AppState;
use crate::inapp::InAppService;
use crate::preference::PreferenceService;
use crate::push::Push;
use crate::send::SendService;
use crate::sse::Hub;

pub const NAME: &str = "notification";

/// Everything a running unit holds, built from configuration (separate from serving, so tests
/// can build one against fakes).
pub struct Built {
    pub state: Arc<AppState>,
    pub send: Arc<SendService>,
    pub hub: Arc<Hub>,
    /// Delivery to every instance's streams.
    pub push: Arc<Push>,
    pub registry: Option<Registry>,
    pub pool: sqlx::MySqlPool,
}

pub async fn build(cfg: &NotificationConfig) -> Result<Built> {
    let pool = platform::db::mysql_pool(&cfg.database).await?;
    let dao = Dao::new(pool.clone());
    let registry = if cfg.registry.register || !cfg.registry.zones.is_empty() {
        Some(Registry::new(&cfg.registry, cfg.server.port)?)
    } else {
        None
    };
    let cache = if cfg.redis.url.is_empty() {
        None
    } else {
        Some(CacheService::configured(&cfg.redis)?)
    };
    let timeout = Duration::from_secs(cfg.core.timeout_seconds.max(1));
    let directory = DirectoryClient::new(platform::security::security_upstream(&cfg.security, registry.as_ref())?, timeout)?;
    let core_up = Upstream::from_config(&cfg.core.upstream, registry.as_ref())?;
    let connections_up = if cfg.core.connections_upstream.entries().is_empty() {
        core_up.clone()
    } else {
        Upstream::from_config(&cfg.core.connections_upstream, registry.as_ref())?
    };
    let core = CoreClient::with_connections(core_up, connections_up, timeout)?;
    let hub = Hub::new(cfg.sse.buffer);
    let push = Push::new(hub.clone(), cache.clone(), &cfg.sse.push_channel);

    let in_app = InAppService { dao: dao.clone(), push: push.clone() };
    let send = Arc::new(SendService {
        core,
        directory: directory.clone(),
        email: Arc::new(EmailService { block_private_targets: cfg.email.block_private_targets, ..EmailService::new(&cfg.email.sendgrid_url)? }),
        in_app: Arc::new(InAppService { dao: dao.clone(), push: push.clone() }),
        push: push.clone(),
    });
    let state = Arc::new(AppState {
        security: SecurityClient::from_config(&cfg.security, registry.as_ref())?,
        inapp: in_app,
        prefs: PreferenceService { dao, directory, cache },
        hub: hub.clone(),
        server_port: cfg.server.port,
    });
    Ok(Built { state, send, hub, push, registry, pool })
}

/// Loads configuration, connects everything, starts the queue consumer and the heartbeat, and
/// serves until shut down.
pub async fn run() -> Result<()> {
    let loaded = platform::config::load_async::<NotificationConfig>(NAME).await?;
    catalogue::register();
    let telemetry = platform::telemetry::init(NAME, &loaded.config.telemetry)?;
    loaded.log_source(NAME);
    let cfg = loaded.config;
    let built = build(&cfg).await?;
    built.hub.spawn_heartbeat(Duration::from_secs(cfg.sse.heartbeat_seconds.max(1)));
    if built.push.spawn_listener().is_none() {
        tracing::info!("no [redis] url: notifications reach the streams open on this instance only");
    }

    let health = Health::new(telemetry.metrics.clone());
    {
        let pool = built.pool.clone();
        health.check("mysql", move || {
            let pool = pool.clone();
            async move {
                sqlx::query("SELECT 1").execute(&pool).await?;
                Ok(())
            }
        });
    }
    if cfg.mq.enabled && !cfg.notifications.names().is_empty() {
        match cfg.mq.amqp_uri() {
            Some(uri) => {
                let state = queue::ConsumerState::default();
                queue::describe_metrics();
                tokio::spawn(queue::consume_forever(built.send.clone(), uri, cfg.notifications.clone(), state.clone()));
                health.check("rabbitmq", move || {
                    let state = state.clone();
                    async move {
                        if state.connected() {
                            Ok(())
                        } else {
                            Err(anyhow::anyhow!("not consuming"))
                        }
                    }
                });
            }
            None => tracing::warn!("[mq] has no uri or host: the notifications queues are not consumed"),
        }
    }

    Service { name: NAME.to_string(), server: cfg.server.clone(), telemetry, health, registry: built.registry.clone(), cors: false }
        .run(handlers::router(built.state.clone()))
        .await
}
