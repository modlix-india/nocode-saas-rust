//! core-editor: the Java core's editing surface on port 8111. Every core controller that is
//! not core-exec's (function execution, the repositories, the data and connection routes),
//! core-scheduler's or core-events': CRUD, drafts, fork and publish of functions, schemas,
//! storages, connections, templates, notifications, event definitions and actions,
//! workflows, actions and fillers, their version history, publish-all, transport, an app's
//! wipe, and the controllers' own routes (schedules, template previews, the index, the
//! caches, billing). The write path is the `overridable` crate's; this module plugs in the
//! core document kinds.

pub mod beans;
pub mod billing;
pub mod cache;
pub mod caller;
pub mod docs;
pub mod index;
pub mod kinds;
pub mod preview;
pub mod routes;
pub mod schedules;
pub mod storage;

#[cfg(test)]
mod local_stack;
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use axum::http::HeaderMap;
use overridable::write::router::{CallerSource, SecurityCallers};
use overridable::write::transport::TransportService;
use overridable::write::{Commons, OverridableService};
use overridable::{JMap, JValue, Store};
use platform::app::Service;
use platform::cache::CacheService;
use platform::error::{AppError, AppResult};
use platform::health::Health;
use platform::security::{ContextAuthentication, SecurityClient};

use crate::config::CoreConfig;
use crate::context::RequestContext;
use crate::editor::billing::{Billing, BillingSecurity};
use crate::editor::kinds::{core_filler, core_messages, CoreKind, CoreObject, EDITOR_AUTH_NAMES};
use crate::editor::routes::CoreEditor;
use crate::editor::schedules::ScheduleSources;
use crate::editor::storage::{DataStores, StorageOps, Triggers};
use crate::error::CoreError;
use crate::repos::SchemaSource;
use crate::storage::defs::Catalog;

pub const NAME: &str = "core-editor";

/// What the editor is built on besides the store: the data side, the definition triggers, the
/// schedule view's reads, billing's security calls.
pub struct Parts {
    pub catalog: Arc<dyn Catalog>,
    pub kirun_schemas: Arc<dyn SchemaSource>,
    pub core_schemas: Arc<dyn SchemaSource>,
    pub data: Arc<dyn DataStores>,
    pub triggers: Arc<dyn Triggers>,
    pub schedules: Arc<dyn Fn(OverridableService<CoreKind>, Commons) -> Arc<dyn ScheduleSources> + Send + Sync>,
    pub billing: Arc<dyn BillingSecurity>,
    pub redis: Option<redis::Client>,
    pub eviction_channel: String,
}

/// The editor's state on a store.
pub fn state(store: Store, cache: CacheService, callers: Arc<dyn CallerSource>, parts: Parts) -> Arc<CoreEditor> {
    let cx = Commons::new(store, cache.clone(), core_messages(), EDITOR_AUTH_NAMES);
    let ops = Arc::new(StorageOps::new(parts.catalog, parts.kirun_schemas, parts.core_schemas, parts.data.clone(), parts.triggers));
    let svc = |o: CoreObject| OverridableService::new(CoreKind::new(o, ops.clone()), cx.clone());
    let functions = svc(CoreObject::Function);
    let schemas = svc(CoreObject::Schema);
    let storages = svc(CoreObject::Storage);
    let _ = ops.storages.set(storages.clone());
    let connections = svc(CoreObject::Connection);
    let templates = svc(CoreObject::Template);
    let notifications = svc(CoreObject::Notification);
    let event_definitions = svc(CoreObject::EventDefinition);
    let event_actions = svc(CoreObject::EventAction);
    let workflows = svc(CoreObject::Workflow);
    let actions = svc(CoreObject::Action);
    let fillers = OverridableService::new(core_filler(&cache), cx.clone());
    let transport_list = CoreEditor::transport_services(&schemas, &storages, &functions, &templates, &event_definitions, &event_actions, &fillers);
    let transports = Arc::new(TransportService::new(cx.clone(), transport_list, "core", "cmodl"));
    let schedules = (parts.schedules)(event_definitions.clone(), cx.clone());
    Arc::new(CoreEditor {
        callers,
        cx,
        functions,
        schemas,
        storages,
        connections,
        templates,
        notifications,
        event_definitions,
        event_actions,
        workflows,
        actions,
        fillers,
        transports,
        storage: ops,
        data: parts.data.clone(),
        billing: Billing { security: parts.billing, data: parts.data },
        schedules,
        redis: parts.redis,
        eviction_channel: parts.eviction_channel,
    })
}

/// A core error as the editor answers it: coded as core-exec answers it; a Java text without a
/// code as Java's shape.
fn app_error(e: CoreError) -> AppError {
    if let Some(c) = e.coded_answer() {
        return AppError::from(c);
    }
    let status = e.status();
    if status.is_server_error() {
        AppError::Internal(anyhow::anyhow!(e.text()))
    } else {
        AppError::new(status, e.text())
    }
}

/// The app's data, on the engines core-exec uses.
pub struct LiveData {
    pub catalog: Arc<dyn Catalog>,
    pub mongo: Arc<appdata::mongo::MongoAppDataService>,
    pub mysql: Arc<appdata::mysql::MySqlAppDataService>,
}

impl LiveData {
    fn storage_of(e: &JMap) -> Option<appdata::model::Storage> {
        appdata::model::Storage::from_value(&crate::storage::defs::jvalue(&JValue::Object(e.clone()))).ok()
    }

    async fn conn(&self, app: &str, client: &str) -> Result<Option<appdata::model::Connection>, String> {
        self.catalog.connection("appData", app, client, "APP_DATA").await.map_err(|e| e.text())
    }

    /// `services.get(subType)`: an app on another backend has no engine.
    fn engine(&self, conn: Option<&appdata::model::Connection>) -> Result<Arc<dyn appdata::engine::AppDataEngine>, String> {
        use appdata::model::ConnectionSubType as Sub;
        match conn.map(|c| c.connection_sub_type.clone()) {
            None | Some(None) | Some(Some(Sub::Mongo)) => Ok(self.mongo.clone()),
            Some(Some(Sub::MySql)) => Ok(self.mysql.clone()),
            Some(Some(Sub::Other(o))) => Err(format!("No app data service for {o}")),
        }
    }
}

#[async_trait]
impl DataStores for LiveData {
    async fn reconcile(&self, app: &str, storage: &JMap, applied_by: &str) {
        let Some(s) = Self::storage_of(storage).filter(|s| !s.unique_name.trim().is_empty()) else { return };
        let conns = match self.catalog.all_app_data("MYSQL", app).await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(storage = s.name, app, error = %e.text(), "Could not reconcile tables");
                return;
            }
        };
        for conn in conns {
            if let Err(e) = self.mysql.reconcile(Some(&conn), app, &s, Some(applied_by)).await {
                tracing::error!(storage = s.name, app, error = %e, "Could not reconcile on a connection");
            }
        }
    }

    async fn drop_draft_storage(&self, app: &str, client: &str, storage: &JMap) -> Result<bool, String> {
        let Some(s) = Self::storage_of(storage) else { return Ok(false) };
        let conn = self.conn(app, client).await?;
        self.engine(conn.as_ref())?
            .drop_draft_storage(&crate::storage::service::ctx(), client, conn.as_ref(), &s)
            .await
            .map_err(|e| e.to_string())
    }

    async fn drop_draft_data(&self, app: &str, client: &str) -> Result<bool, String> {
        let conn = self.conn(app, client).await?;
        self.engine(conn.as_ref())?.drop_draft_database(conn.as_ref(), app, client).await.map_err(|e| e.to_string())
    }

    async fn estimated_row_count(&self, app: &str, client: &str) -> i64 {
        let conn = self.conn(app, client).await.ok().flatten();
        self.mongo.estimated_row_count(conn.as_ref(), app, client).await
    }
}

/// Definition triggers, run as core functions on core-exec's execution state.
pub struct StateTriggers(pub crate::state::AppState);

#[async_trait]
impl Triggers for StateTriggers {
    async fn run(&self, namespace: &str, name: &str, app: &str, client: &str, args: kirun::Map<serde_json::Value>) -> AppResult<()> {
        crate::exec::run(&self.0, Some(namespace), name, app, client, crate::exec::Arguments::Body(args)).await.map_err(app_error)?;
        Ok(())
    }
}

/// The caller from security, and core's request context for the requests that run functions.
pub struct StateResolver {
    pub callers: SecurityCallers,
    pub state: crate::state::AppState,
}

#[async_trait]
impl caller::Resolver for StateResolver {
    /// `JWTTokenFilter`: security's answer for the token, with the `clientCode` / `appCode`
    /// headers. A refusal is answered as security gave it: a Rust security unit's coded error
    /// with its code (`platform::security::refusal_error`), Java's with its message.
    async fn caller(&self, headers: &HeaderMap) -> AppResult<ContextAuthentication> {
        let ctx = platform::security::CallerContext::from_headers(headers, self.callers.server_port);
        match self.callers.security.context_authentication(&ctx).await {
            Ok(mut ca) => {
                ca.url_client_code = ctx.client_code;
                ca.url_app_code = ctx.app_code;
                Ok(ca)
            }
            Err(e) => Err(platform::security::refusal_error(&e).unwrap_or(AppError::Internal(e))),
        }
    }
    async fn request_context(&self, headers: &HeaderMap) -> Option<Arc<RequestContext>> {
        crate::handlers::request_context(&self.state, headers).await.ok()
    }
}

/// The schedule view's reads: the event definitions' store, security, the run log.
pub struct StateSchedules {
    pub event_definitions: OverridableService<CoreKind>,
    pub cx: Commons,
    pub security: Arc<crate::clients::SecurityCalls>,
    pub runs: Arc<crate::event_runs::EventRunService>,
}

#[async_trait]
impl ScheduleSources for StateSchedules {
    async fn copies(&self, app: &str, name: &str) -> Vec<JMap> {
        match self.cx.backend().find("eventDefinition", overridable::backend::Find::new(mongodb::bson::doc! {"name": name, "appCode": app})).await {
            Ok(docs) => docs.iter().map(|d| overridable::pojo::decode_bson(&crate::docs::EVENT_DEFINITION, d)).collect(),
            Err(e) => {
                tracing::warn!(app, name, error = %e, "event definition copies unreadable");
                Vec::new()
            }
        }
    }
    async fn writers(&self, app: &str) -> Vec<String> {
        self.security.write_access_client_codes(app).await.ok().flatten().unwrap_or_default()
    }
    async fn visible_among(&self, own: &str, app: &str, candidates: &[String]) -> Result<Vec<String>, AppError> {
        self.runs.visible_among(own, app, candidates, false).await.map_err(app_error)
    }
    async fn latest_runs(&self, app: &str, name: &str, clients: &[String]) -> HashMap<String, crate::event_runs::EventRun> {
        self.runs.latest_runs(app, name, clients).await
    }
    async fn effective_schedule(&self, app: &str, name: &str, client: &str) -> Option<crate::scheduler::EventSchedule> {
        let svc = &self.event_definitions;
        let r = svc.commons().store.read(svc.kind(), name, app, client, client, false).await.ok().flatten()?;
        r.entity.get("schedule").and_then(crate::scheduler::EventSchedule::from_j)
    }
    async fn draft(&self, ca: &ContextAuthentication, copy_id: &str) -> Option<(i64, Option<crate::scheduler::EventSchedule>)> {
        let (entity, version) = self.event_definitions.read_draft_with_version(ca, copy_id).await.ok()?;
        (version > 0).then(|| (version, entity.get("schedule").and_then(crate::scheduler::EventSchedule::from_j)))
    }
    async fn client_name(&self, client: &str) -> Option<String> {
        let v = self.security.client_by_code(client).await.ok().flatten()?;
        v.get("name").and_then(|n| n.as_str()).map(str::to_string)
    }
}

/// The concrete engines, built as core-exec builds them.
fn engines(cfg: &CoreConfig, cache: &CacheService, defs: Arc<crate::storage::defs::StorageDefs>, kirun_schemas: Arc<dyn SchemaSource>) -> (Arc<appdata::mongo::MongoAppDataService>, Arc<appdata::mysql::MySqlAppDataService>) {
    use appdata::engine::Hooks;
    use appdata::mongo::{MongoAppDataService, MongoEngineConfig};
    use appdata::mysql::{MySqlAppDataService, MySqlEngineConfig};

    let hooks = Hooks {
        validator: Arc::new(crate::storage::validator::KirunWriteValidator { kirun_schemas, defs: defs.clone() }),
        schemas: Some(defs.clone()),
        storages: Some(defs),
        authority: Some(Arc::new(crate::authorities::KirunAuthorityCheck)),
    };
    let a = &cfg.appdata;
    let retention = a.version_retention();
    let db = &cfg.database;
    let mongo = Arc::new(MongoAppDataService::new(
        MongoEngineConfig { default_uri: Some(cfg.mongo.uri.clone()), retention, skip_index_management: false },
        hooks.clone(),
        cache,
    ));
    let mysql = Arc::new(MySqlAppDataService::new(
        MySqlEngineConfig {
            text_search_stemming: a.text_search_stemming,
            default_url: Some(a.mysql_url.clone().unwrap_or_else(|| format!("r2dbc:mysql://{}:{}/{}?serverTimezone=UTC", db.host, db.port, db.database))),
            default_username: Some(db.username.clone()),
            default_password: Some(db.password.clone()),
            retention,
            ..Default::default()
        },
        hooks,
        cache,
    ));
    (mongo, mysql)
}

/// The editor on a connected core: its state, and the whole router (with the run log and the
/// event raise of step 4, so every internal route the platform jobs call is on this unit).
pub fn assemble(cfg: &CoreConfig, exec: &crate::Exec) -> Result<(Arc<CoreEditor>, axum::Router)> {
    let s = exec.state.inner();
    let store = s.definitions.store().clone();
    let security = SecurityClient::from_config(&cfg.security, exec.eureka.as_ref())?;
    let defs = crate::storage_defs(&exec.cache, s.definitions.clone(), s.core_schemas.clone());
    let (mongo, mysql) = engines(cfg, &exec.cache, defs, s.kirun_schemas.clone());
    let catalog = s.appdata.catalog().clone();
    let security_calls = exec.security_calls.clone();
    let runs = s.event_runs.clone();
    let redis = match cfg.redis.url.as_str() {
        "" => None,
        url => redis::Client::open(platform::cache::normalize_redis_url(url).as_str()).ok(),
    };
    let parts = Parts {
        catalog: catalog.clone(),
        kirun_schemas: s.kirun_schemas.clone(),
        core_schemas: s.core_schemas.clone(),
        data: Arc::new(LiveData { catalog, mongo, mysql }),
        triggers: Arc::new(StateTriggers(exec.state.clone())),
        schedules: Arc::new(move |eds, cx| Arc::new(StateSchedules { event_definitions: eds, cx, security: security_calls.clone(), runs: runs.clone() }) as Arc<dyn ScheduleSources>),
        billing: Arc::new(security.clone()),
        redis,
        eviction_channel: cfg.redis.eviction_channel.clone(),
    };
    let security_callers = SecurityCallers { security: security.clone(), server_port: cfg.server.port };
    let callers: Arc<dyn CallerSource> = Arc::new(caller::EditorCallers { inner: Arc::new(SecurityCallers { security, server_port: cfg.server.port }) });
    let st = state(store, exec.cache.clone(), callers, parts);
    let resolver: Arc<dyn caller::Resolver> = Arc::new(StateResolver { callers: security_callers, state: exec.state.clone() });
    let router = routes::with_layers(routes::router(st.clone()).merge(crate::event_routes::router().with_state(exec.state.clone())), resolver);
    Ok((st, router))
}

/// Starts core-editor and serves until a shutdown signal.
pub async fn run() -> Result<()> {
    let cfg: CoreConfig = platform::config::load(NAME)?;
    let telemetry = platform::telemetry::init(NAME, &cfg.telemetry)?;
    if let Some(file) = platform::config::config_file(NAME) {
        tracing::info!(file = %file.display(), "configuration file");
    }
    let exec = crate::connect(&cfg).await?;
    exec.cache.spawn_eviction_listener();
    let (_, router) = assemble(&cfg, &exec)?;
    let health = Health::new(telemetry.metrics.clone());
    let db = exec.mongo.clone();
    health.check("mongo", move || {
        let db = db.clone();
        async move {
            db.run_command(mongodb::bson::doc! {"ping": 1}).await?;
            Ok(())
        }
    });
    Service { name: NAME.to_string(), server: cfg.server.clone(), telemetry, health, eureka: exec.eureka, cors: true }.run(router).await
}
