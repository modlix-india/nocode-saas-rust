//! core units over one library. So far core-exec: function execution on the `kirun` crate
//! (`FunctionExecutionController`, `CoreFunctionService`) and the function and schema
//! repositories (`repositoryFind` / `repositoryFilter`), reading definitions from the `core`
//! Mongo database through the overridable store.
//!
//! - [`context`]: the request context every core function sees (task-locals);
//! - [`auth`]: the caller, from security;
//! - [`repos`]: the repositories, layered as the Java services layer them, and
//!   `DefinitionFunction`;
//! - [`functions`]: core's own KIRun functions;
//! - [`exec`] / [`handlers`]: the execution and the routes;
//! - [`gson`] / [`java_model`]: the JSON the Java code writes;
//! - [`storage`]: `AppDataService` (the storage policy layer over `crates/appdata`'s engines),
//!   the storage definitions it reads, the write validator, rows as files;
//!   [`functions::storage`] the `CoreServices.Storage.*` functions and [`data_routes`] the
//!   `AppDataController`, `InternalAppDataController` and `SpreadSheetController` routes.

pub mod auth;
pub mod authorities;
pub mod catalogue;
pub mod clients;
pub mod config;
pub mod connection_routes;
pub mod context;
pub mod cron;
pub mod data_routes;
pub mod docs;
pub mod editor;
pub mod error;
pub mod event_routes;
pub mod event_runs;
pub mod event_scheduler;
pub mod events;
pub mod events_queue;
pub mod exec;
pub mod files_calls;
pub mod functions;
pub mod gson;
pub mod handlers;
pub mod integrations;
pub mod java_model;
pub mod message_calls;
pub mod pdf;
pub mod platform_calls;
pub mod repos;
pub mod scheduler;
#[cfg(test)]
mod platform_smoke;
#[cfg(test)]
mod scheduler_parity;
pub mod security_calls;
pub mod state;
pub mod step_trace;
pub mod storage;
pub mod unmapped;

#[cfg(test)]
mod integrations_tests;
#[cfg(test)]
mod local_stack_storage_tests;
#[cfg(test)]
mod local_stack_tests;
#[cfg(test)]
pub(crate) mod testing;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use overridable::Store;
use platform::app::Service;
use platform::cache::CacheService;
use platform::eureka::Eureka;
use platform::health::Health;
use platform::security::SecurityClient;
use platform::upstream::Upstream;

use crate::auth::AuthClient;
use crate::clients::{EntityProcessor, SecurityCalls};
use crate::config::CoreConfig;
use crate::repos::app::Definitions;
use crate::repos::core_functions::CoreFunctions;
use crate::repos::remote::RemoteRepositories;
use crate::state::{AppState, Builtins, Inner};

/// Everything core-exec runs on, connected.
pub struct Exec {
    pub state: AppState,
    pub mongo: mongodb::Database,
    pub pool: sqlx::MySqlPool,
    pub cache: CacheService,
    pub eureka: Option<Eureka>,
    pub security_calls: Arc<SecurityCalls>,
}

/// Connects the databases, the caches and the other services, and builds the state.
pub async fn connect(cfg: &CoreConfig) -> Result<Exec> {
    overridable::pojo::set_java_zone_offset_seconds(cfg.core.zone_offset_seconds()?);

    let mongo = platform::db::mongo_database(&cfg.mongo).await?;
    let pool = platform::db::mysql_pool(&cfg.database).await?;

    let cache = CacheService::new(&cfg.redis.cache_prefix, &cfg.redis.eviction_channel, Some(cfg.redis.url.as_str()))?;
    let eureka = if cfg.eureka.register || !cfg.eureka.zones.is_empty() {
        Some(Eureka::new(&cfg.eureka, cfg.server.port)?)
    } else {
        None
    };
    let security_upstream = platform::security::security_upstream(&cfg.security, eureka.as_ref())?;
    let security = SecurityClient::from_config(&cfg.security, eureka.as_ref())?;
    let store = Store::new(mongo.clone(), security.clone(), &cache);
    let ep = Arc::new(EntityProcessor::new(Upstream::from_config(&cfg.entity_processor.upstream, eureka.as_ref())?)?);
    let security_calls = Arc::new(SecurityCalls::new(security_upstream.clone())?);
    let message = Arc::new(message_calls::MessageCalls::new(Upstream::from_config(&cfg.message.upstream, eureka.as_ref())?)?);
    let files = Arc::new(files_calls::FilesCalls::new(Upstream::from_config(&cfg.files.upstream, eureka.as_ref())?)?);
    let platform = Arc::new(make_platform_calls(cfg, eureka.as_ref(), &security_upstream)?);

    let definitions = Arc::new(Definitions::new(
        store,
        security.clone(),
        cache.family(),
        Duration::from_secs(cfg.core.function_timeout_seconds),
    ));
    let remote = RemoteRepositories::new(pool.clone(), cache.family(), ep);

    let kirun_schemas = Builtins::kirun_schemas();
    let core_schemas = Builtins::core_schemas();
    let mq = Arc::new(integrations::Mq::from_config(&cfg.mq));
    let defs = storage_defs(&cache, definitions.clone(), core_schemas.clone());
    let events = Arc::new(integrations::MqEvents { mq: mq.clone() });
    let appdata = Arc::new(storage_service(cfg, &cache, defs.clone(), security, kirun_schemas.clone(), events));
    let integrations = Arc::new(integrations::Integrations::new(
        cfg,
        Arc::new(integrations::StoreDocs { defs: defs.clone() }),
        security_calls.clone(),
        integrations::token_dao(cfg, pool.clone())?,
        cache.clone(),
        mq,
        Some(files.clone() as Arc<dyn integrations::FileCreate>),
    )?);
    let event_runs = Arc::new(event_runs::EventRunService::new(
        Arc::new(event_runs::MySqlEventRunDao::new(pool.clone())),
        Arc::new(scheduler::EventDefinitionService::new(definitions.store().clone(), cache.clone())),
        security_calls.clone(),
        cfg.core.event_runs.enabled,
    ));
    let deps = repos::core_functions::Deps {
        security: security_calls.clone(),
        storage: appdata.clone(),
        defs,
        mongo: mongo.clone(),
        cache: cache.clone(),
        integrations: integrations.clone(),
        message,
        files,
        scheduler: cfg.core.scheduler.clone(),
        platform,
    };
    let builtins = Builtins::with(CoreFunctions::new(&deps), kirun_schemas, core_schemas);

    let state = AppState::new(Inner {
        config: cfg.clone(),
        auth: AuthClient::new(security_upstream)?,
        definitions,
        remote,
        kirun_functions: builtins.kirun_functions,
        kirun_schemas: builtins.kirun_schemas,
        core_functions: builtins.core_functions,
        core_schemas: builtins.core_schemas,
        appdata: appdata.clone(),
        integrations: integrations.clone(),
        event_runs,
    });
    appdata.attach(&state);
    integrations.attach(&state);
    Ok(Exec { state, mongo, pool, cache, eureka, security_calls })
}

/// The services `CoreServices.Platform.*` call. An upstream the configuration cannot make
/// (an `eureka:` one without `[eureka] zones`) is kept as its error and fails only the jobs
/// that need it, with a warning now, so a unit that never runs them still starts.
fn make_platform_calls(cfg: &CoreConfig, eureka: Option<&Eureka>, security: &Upstream) -> Result<platform_calls::PlatformCalls> {
    let make = |what: &str, c: &platform::config::UpstreamConfig| {
        Upstream::from_config(c, eureka).map_err(|e| {
            tracing::warn!(service = what, error = %e, "no upstream for the platform functions");
            e.to_string()
        })
    };
    platform_calls::PlatformCalls::new(platform_calls::Upstreams {
        security: Ok(security.clone()),
        core: make("core", &cfg.core.upstream),
        entity_processor: make("entity-processor", &cfg.entity_processor.upstream),
        files: make("files", &cfg.files.upstream),
        ui: make("ui", &cfg.ui.upstream),
    })
}

/// The definitions the storage layer and the core functions read (storages, connections,
/// event definitions, templates).
pub(crate) fn storage_defs(
    cache: &CacheService,
    definitions: Arc<Definitions>,
    core_schemas: Arc<dyn repos::SchemaSource>,
) -> Arc<storage::defs::StorageDefs> {
    Arc::new(storage::defs::StorageDefs::new(definitions, core_schemas, cache.family()))
}

/// `AppDataService` over the two engines, which call back into it for storages, schemas, row
/// validation and readAuth.
pub(crate) fn storage_service(
    cfg: &CoreConfig,
    cache: &CacheService,
    defs: Arc<storage::defs::StorageDefs>,
    security: SecurityClient,
    kirun_schemas: Arc<dyn repos::SchemaSource>,
    events: Arc<dyn storage::service::EventSink>,
) -> storage::service::AppDataService {
    use appdata::engine::Hooks;
    use appdata::mongo::{MongoAppDataService, MongoEngineConfig};
    use appdata::mysql::{MySqlAppDataService, MySqlEngineConfig};

    let hooks = Hooks {
        validator: Arc::new(storage::validator::KirunWriteValidator { kirun_schemas, defs: defs.clone() }),
        schemas: Some(defs.clone()),
        storages: Some(defs.clone()),
        authority: Some(Arc::new(authorities::KirunAuthorityCheck)),
    };
    let a = &cfg.appdata;
    let retention = a.version_retention();
    let db = &cfg.database;
    let engines = appdata::selection::Engines {
        mongo: Arc::new(MongoAppDataService::new(
            MongoEngineConfig { default_uri: Some(cfg.mongo.uri.clone()), retention, skip_index_management: false },
            hooks.clone(),
            cache,
        )),
        mysql: Arc::new(MySqlAppDataService::new(
            MySqlEngineConfig {
                text_search_stemming: a.text_search_stemming,
                default_url: Some(a.mysql_url.clone().unwrap_or_else(|| {
                    format!("r2dbc:mysql://{}:{}/{}?serverTimezone=UTC", db.host, db.port, db.database)
                })),
                default_username: Some(db.username.clone()),
                default_password: Some(db.password.clone()),
                retention,
                ..Default::default()
            },
            hooks,
            cache,
        )),
    };
    storage::service::AppDataService::new(
        defs,
        security,
        storage::service::Backends::of(&engines),
        a.builder_app_codes.clone(),
        events,
    )
}

/// Starts core-exec and serves until a shutdown signal.
pub async fn run_exec() -> Result<()> {
    const NAME: &str = "core-exec";
    let cfg: CoreConfig = platform::config::load(NAME)?;
    let telemetry = platform::telemetry::init(NAME, &cfg.telemetry)?;
    if let Some(file) = platform::config::config_file(NAME) {
        tracing::info!(file = %file.display(), "configuration file");
    }
    let exec = connect(&cfg).await?;
    exec.cache.spawn_eviction_listener();

    let health = Health::new(telemetry.metrics.clone());
    let pool = exec.pool.clone();
    health.check("mysql", move || {
        let pool = pool.clone();
        async move {
            sqlx::query("SELECT 1").execute(&pool).await?;
            Ok(())
        }
    });
    let db = exec.mongo.clone();
    health.check("mongo", move || {
        let db = db.clone();
        async move {
            db.run_command(mongodb::bson::doc! {"ping": 1}).await?;
            Ok(())
        }
    });

    Service { name: NAME.to_string(), server: cfg.server.clone(), telemetry, health, eureka: exec.eureka, cors: true }
        .run(handlers::router(exec.state))
        .await
}

fn mongo_and_mysql_checks(health: &Health, mongo: &mongodb::Database, pool: Option<&sqlx::MySqlPool>) {
    if let Some(pool) = pool {
        let pool = pool.clone();
        health.check("mysql", move || {
            let pool = pool.clone();
            async move {
                sqlx::query("SELECT 1").execute(&pool).await?;
                Ok(())
            }
        });
    }
    let db = mongo.clone();
    health.check("mongo", move || {
        let db = db.clone();
        async move {
            db.run_command(mongodb::bson::doc! {"ping": 1}).await?;
            Ok(())
        }
    });
}

/// Starts core-scheduler: the EventScheduler passes, which publish what is due to the events
/// queue and never run KIRun. Serves only its health routes.
pub async fn run_scheduler() -> Result<()> {
    const NAME: &str = "core-scheduler";
    let cfg: CoreConfig = platform::config::load(NAME)?;
    let telemetry = platform::telemetry::init(NAME, &cfg.telemetry)?;
    if let Some(file) = platform::config::config_file(NAME) {
        tracing::info!(file = %file.display(), "configuration file");
    }
    overridable::pojo::set_java_zone_offset_seconds(cfg.core.zone_offset_seconds()?);
    let mongo = platform::db::mongo_database(&cfg.mongo).await?;
    let pool = platform::db::mysql_pool(&cfg.database).await?;
    let cache = CacheService::new(&cfg.redis.cache_prefix, &cfg.redis.eviction_channel, Some(cfg.redis.url.as_str()))?;
    cache.spawn_eviction_listener();
    let eureka = if cfg.eureka.register || !cfg.eureka.zones.is_empty() {
        Some(Eureka::new(&cfg.eureka, cfg.server.port)?)
    } else {
        None
    };
    let security_upstream = platform::security::security_upstream(&cfg.security, eureka.as_ref())?;
    let security = SecurityClient::from_config(&cfg.security, eureka.as_ref())?;
    let store = Store::new(mongo.clone(), security, &cache);
    let security_calls = Arc::new(SecurityCalls::new(security_upstream)?);
    let pass = Arc::new(event_scheduler_of(cfg.clone(), store, cache.clone(), security_calls, mongo.clone(), pool.clone()));
    tracing::info!(instance = pass.instance_id(), "core-scheduler instance");
    tokio::spawn(pass.run_forever());

    let health = Health::new(telemetry.metrics.clone());
    mongo_and_mysql_checks(&health, &mongo, Some(&pool));
    Service { name: NAME.to_string(), server: cfg.server.clone(), telemetry, health, eureka, cors: false }
        .run(axum::Router::new())
        .await
}

/// The EventScheduler core-scheduler runs: definitions read through `store`, raised events
/// published as `[mq]` says, its own outcomes (SKIPPED, a failed raise) in the run log.
pub fn event_scheduler_of(
    cfg: CoreConfig,
    store: Store,
    cache: CacheService,
    security_calls: Arc<SecurityCalls>,
    mongo: mongodb::Database,
    pool: sqlx::MySqlPool,
) -> event_scheduler::EventScheduler {
    let definitions = Arc::new(scheduler::EventDefinitionService::new(store, cache));
    let run_log = Arc::new(event_runs::EventRunService::new(
        Arc::new(event_runs::MySqlEventRunDao::new(pool)),
        definitions.clone(),
        security_calls.clone(),
        cfg.core.event_runs.enabled,
    ));
    let mq = Arc::new(integrations::Mq::from_config(&cfg.mq));
    let settings = cfg.core.scheduler.clone();
    let schedule_store = Arc::new(scheduler::ScheduleStore::new(mongo, settings.clone()));
    let one_offs = Arc::new(scheduler::ScheduledEventService::new(schedule_store.clone(), settings.clone()));
    event_scheduler::EventScheduler::new(definitions, security_calls, mq, schedule_store, one_offs, settings).with_run_log(run_log)
}

/// The EventsListener core-events runs, over a connected core.
pub fn events_listener_of(exec: &Exec, cfg: &CoreConfig) -> events::EventsListener {
    let s = exec.state.inner();
    let settings = cfg.core.scheduler.clone();
    let schedule_store = Arc::new(scheduler::ScheduleStore::new(exec.mongo.clone(), settings.clone()));
    let one_offs = Arc::new(scheduler::ScheduledEventService::new(schedule_store.clone(), settings));
    let completion = Arc::new(event_scheduler::RunCompletion::new(schedule_store, one_offs));
    events::EventsListener::new(Arc::new(events::StoreActions(s.definitions.store().clone())), exec.security_calls.clone())
        .with_executor(events::CALL_CORE_FUNCTION, Arc::new(events::CallCoreFunction { state: exec.state.clone() }))
        .with_executor(events::SEND_EMAIL, Arc::new(events::SendEmailTask { integrations: s.integrations.clone() }))
        .with_completion(completion)
        .with_run_log(s.event_runs.clone())
}

/// Starts core-events: consumes the events queues and runs each event's EventAction. Serves
/// only its health routes.
pub async fn run_events() -> Result<()> {
    const NAME: &str = "core-events";
    let cfg: CoreConfig = platform::config::load(NAME)?;
    let telemetry = platform::telemetry::init(NAME, &cfg.telemetry)?;
    if let Some(file) = platform::config::config_file(NAME) {
        tracing::info!(file = %file.display(), "configuration file");
    }
    let Some(uri) = cfg.mq.amqp_uri().filter(|_| cfg.mq.enabled) else {
        anyhow::bail!("core-events needs a broker: set [mq] (or MODLIX__MQ__URI)");
    };
    let exec = connect(&cfg).await?;
    exec.cache.spawn_eviction_listener();
    let listener = events_listener_of(&exec, &cfg);
    tokio::spawn(events_queue::consume_forever(Arc::new(listener), uri, cfg.mq.events_exchange.clone(), cfg.events.clone()));

    let health = Health::new(telemetry.metrics.clone());
    mongo_and_mysql_checks(&health, &exec.mongo, Some(&exec.pool));
    Service { name: NAME.to_string(), server: cfg.server.clone(), telemetry, health, eureka: exec.eureka, cors: false }
        .run(axum::Router::new())
        .await
}
