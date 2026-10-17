//! `crates/connections` wired into core (its `NEEDS.md`): the six traits it takes, the RabbitMQ
//! publishing of events and notifications, and the caller every outbound call acts for.
//!
//! - [`ConnectionDocs`] / [`TemplateDocs`]: connection and template documents through the
//!   overridable store, on the caller's surface;
//! - the token store: `connections::tokens::TokenDao` over core's MySQL pool;
//! - [`AuthFunctions`]: a REST_AUTH connection's token function, run by core's executor;
//! - [`SecurityChecks`]: the notification hierarchy checks over security's internal routes;
//! - [`Downloads`]: a `CallRequest` that downloads a file stores it in files;
//! - [`Mq`]: the `events` and `notifications` publishers (`EventCreationService`,
//!   `NotificationService`); [`MqEvents`] raises the storage events (`generateEvents`).

use std::sync::{Arc, OnceLock, Weak};

use async_trait::async_trait;
use axum::http::StatusCode;
use connections::connection::{Connection, ConnectionStore};
use connections::context::Caller;
use connections::email::{EmailTemplate, TemplateStore};
use connections::error::{ConnError, ConnResult};
use connections::mq::{EventMessage, Route, EVENT_TYPE_ID, NOTIFICATION_TYPE_ID};
use connections::notification::{HierarchyChecks, NotificationRequest};
use connections::rest::auth::{AuthTokenFunction, EventResult};
use connections::rest::call::DownloadSink;
use connections::tokens::{JavaClock, TokenDao, TokenStore};
use connections::{Connections, ConnectionsConfig};
use overridable::JMap;
use platform::cache::CacheService;
use serde_json::{Map, Value};

use crate::clients::SecurityCalls;
use crate::config::{CoreConfig, MqSection};
use crate::context;
use crate::error::CoreError;
use crate::functions::support::has_user;
use crate::state::{AppState, Inner};
use crate::storage::defs::StorageDefs;

/// The caller as the Java services read it from the Reactor context.
pub fn caller() -> Caller {
    let in_kirun = context::in_kirun();
    let draft = context::is_draft();
    let Some(r) = context::request() else {
        return Caller { in_kirun, draft, ..Default::default() };
    };
    let a = &r.auth;
    let user = has_user(a);
    Caller {
        present: true,
        authenticated: a.is_authenticated(),
        user_id: user.then_some(a.ca.user.id),
        user_client_id: user.then_some(a.ca.user.client_id),
        client_code: a.client_code().map(str::to_string),
        url_client_code: a.url_client_code().map(str::to_string),
        url_app_code: a.url_app_code().map(str::to_string),
        system_client: a.ca.is_system_client(),
        authorities: a.authorities().to_vec(),
        raw: Some(a.raw.clone()),
        in_kirun,
        draft,
        debug: r.debug.clone(),
    }
}

/// A connections error as core raises it: a `GenericException` keeps its status, message and
/// code; another service's refusal its status and message (and, from a Rust unit, its code as
/// it came); anything else is an unknown error.
pub fn core_error(e: ConnError) -> CoreError {
    match e {
        ConnError::Generic { status, message, code } => CoreError::Message { status, message, cause: None, code },
        ConnError::Feign { status, message, body } => {
            let status = StatusCode::from_u16(status as u16).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            body.as_ref().and_then(|b| crate::auth::relayed(status, b)).unwrap_or_else(|| CoreError::new(status, message))
        }
        ConnError::Other { message } => CoreError::unknown(message),
    }
}

/// A core error handed to the connections library, its code with it.
pub fn conn_error(e: CoreError) -> ConnError {
    match e {
        CoreError::Message { status, message, code, .. } | CoreError::ObjectNotFound { status, message, code } => ConnError::Generic { status, message, code },
        CoreError::Unknown { debug, .. } => ConnError::other(debug),
    }
}

/// A resolved document as plain JSON.
pub fn json_of(doc: &JMap) -> ConnResult<Value> {
    serde_json::from_str(&overridable::json::map_to_compact(doc)).map_err(|e| ConnError::other(e.to_string()))
}

/// Where connection and template documents come from: the overridable store in core, a
/// stand-in in tests.
#[async_trait]
pub trait DocSource: Send + Sync {
    /// `readInternal(name, appCode, urlClientCode, clientCode)` of a connection, resolved.
    async fn connection(&self, name: &str, app_code: &str, url_client_code: &str, client_code: &str) -> Result<Option<JMap>, CoreError>;
    /// `TemplateService.read(name, appCode, clientCode)`.
    async fn template(&self, name: &str, app_code: &str, client_code: &str) -> Result<Option<JMap>, CoreError>;
}

/// The documents in core's Mongo, on the request's surface.
pub struct StoreDocs {
    pub defs: Arc<StorageDefs>,
}

#[async_trait]
impl DocSource for StoreDocs {
    async fn connection(&self, name: &str, app_code: &str, url_client_code: &str, client_code: &str) -> Result<Option<JMap>, CoreError> {
        let r = self
            .defs
            .definitions()
            .store()
            .read(&crate::docs::ConnectionDoc, name, app_code, url_client_code, client_code, context::is_draft())
            .await?;
        Ok(r.map(|r| r.entity.clone()))
    }

    async fn template(&self, name: &str, app_code: &str, client_code: &str) -> Result<Option<JMap>, CoreError> {
        self.defs.template(name, app_code, client_code).await
    }
}

/// Connection documents (`ConnectionService.readInternal`).
pub struct ConnectionDocs {
    pub source: Arc<dyn DocSource>,
}

impl ConnectionDocs {
    /// The resolved document.
    pub async fn read_jmap(&self, name: &str, app_code: &str, url_client_code: &str, client_code: &str) -> Result<Option<JMap>, CoreError> {
        self.source.connection(name, app_code, url_client_code, client_code).await
    }
}

#[async_trait]
impl ConnectionStore for ConnectionDocs {
    async fn read_internal(&self, name: &str, app_code: &str, url_client_code: &str, client_code: &str) -> ConnResult<Option<Connection>> {
        let Some(doc) = self.read_jmap(name, app_code, url_client_code, client_code).await.map_err(conn_error)? else {
            return Ok(None);
        };
        Connection::from_json(json_of(&doc)?).map(Some)
    }
}

/// Template documents (`TemplateService.read`).
pub struct TemplateDocs {
    pub source: Arc<dyn DocSource>,
}

#[async_trait]
impl TemplateStore for TemplateDocs {
    async fn read(&self, name: &str, app_code: &str, client_code: &str) -> ConnResult<Option<EmailTemplate>> {
        match self.source.template(name, app_code, client_code).await.map_err(conn_error)? {
            Some(doc) => EmailTemplate::from_json(json_of(&doc)?).map(Some),
            None => Ok(None),
        }
    }
}

/// `isUserPartOfHierarchy` / `doesClientManageClient` / `doesClientManageClientCode`: an
/// empty answer is a "no".
pub struct SecurityChecks {
    pub security: Arc<SecurityCalls>,
}

#[async_trait]
impl HierarchyChecks for SecurityChecks {
    async fn is_user_part_of_hierarchy(&self, user_id: i128, client_code: &str) -> ConnResult<bool> {
        let r = self.security.is_user_part_of_hierarchy(&user_id.to_string(), client_code).await.map_err(conn_error)?;
        Ok(r.unwrap_or(false))
    }

    async fn does_client_manage_client(&self, managing_client_id: u64, client_id: i128) -> ConnResult<bool> {
        let r = self
            .security
            .does_client_manage_client_text(&managing_client_id.to_string(), &client_id.to_string())
            .await
            .map_err(conn_error)?;
        Ok(r.unwrap_or(false))
    }

    async fn does_client_manage_client_code(&self, managing_client_code: &str, client_code: &str) -> ConnResult<bool> {
        let r = self.security.does_client_manage_client_code(managing_client_code, client_code).await.map_err(conn_error)?;
        Ok(r.unwrap_or(false))
    }
}

/// `IFeignFilesService.create`: a file stored in the files service.
#[async_trait]
pub trait FileCreate: Send + Sync {
    async fn create(
        &self,
        file_type: &str,
        client_code: &str,
        override_: bool,
        file_path: &str,
        file_name: &str,
        bytes: Vec<u8>,
    ) -> Result<Option<Map<String, Value>>, CoreError>;
}

#[async_trait]
impl FileCreate for crate::files_calls::FilesCalls {
    async fn create(
        &self,
        file_type: &str,
        client_code: &str,
        override_: bool,
        file_path: &str,
        file_name: &str,
        bytes: Vec<u8>,
    ) -> Result<Option<Map<String, Value>>, CoreError> {
        crate::files_calls::FilesCalls::create(self, file_type, client_code, override_, file_path, file_name, bytes).await
    }
}

/// Where a `CallRequest` puts a downloaded file.
pub struct Downloads {
    pub security: Arc<SecurityCalls>,
    pub files: Arc<dyn FileCreate>,
}

#[async_trait]
impl DownloadSink for Downloads {
    async fn does_client_manage_client_code(&self, managing: &str, client: &str) -> ConnResult<bool> {
        let r = self.security.does_client_manage_client_code(managing, client).await.map_err(conn_error)?;
        Ok(r.unwrap_or(false))
    }

    async fn create_file(
        &self,
        file_type: &str,
        client_code: &str,
        override_: bool,
        file_path: &str,
        file_name: &str,
        bytes: Vec<u8>,
    ) -> ConnResult<Map<String, Value>> {
        let r = self.files.create(file_type, client_code, override_, file_path, file_name, bytes).await.map_err(conn_error)?;
        Ok(r.unwrap_or_default())
    }
}

/// `coreFunctionService.execute(namespace, name, appCode, clientCode, null, null)` for a
/// REST_AUTH connection's token function.
#[derive(Default)]
pub struct AuthFunctions {
    state: OnceLock<Weak<Inner>>,
}

impl AuthFunctions {
    pub fn attach(&self, st: &AppState) {
        let _ = self.state.set(st.downgrade());
    }
}

#[async_trait]
impl AuthTokenFunction for AuthFunctions {
    async fn execute(&self, namespace: Option<&str>, name: &str, app_code: Option<&str>, client_code: Option<&str>) -> ConnResult<Option<Vec<EventResult>>> {
        let st = self.state.get().and_then(AppState::upgrade).ok_or_else(|| ConnError::other("core is not running"))?;
        let out = crate::exec::run(
            &st,
            namespace,
            name,
            app_code.unwrap_or(""),
            client_code.unwrap_or(""),
            crate::exec::Arguments::Body(kirun::Map::new()),
        )
        .await
        .map_err(conn_error)?;
        let Some(mut out) = out else { return Ok(None) };
        let mut events = Vec::new();
        while let Some(er) = out.next() {
            events.push(EventResult { name: er.get_name().to_string(), result: er.get_result().iter().map(|(k, v)| (k.clone(), v.clone())).collect() });
        }
        Ok(Some(events))
    }
}

// --- RabbitMQ ---------------------------------------------------------------------------------

/// `amqpTemplate.convertAndSend(exchange, routingKey, body)` for an already-written body.
#[async_trait]
pub trait Publish: Send + Sync {
    async fn publish(&self, exchange: &str, routing_key: &str, body: &str, type_id: &str) -> Result<(), CoreError>;
}

/// The real publisher.
pub struct Amqp(pub connections::mq::Publisher);

#[async_trait]
impl Publish for Amqp {
    async fn publish(&self, exchange: &str, routing_key: &str, body: &str, type_id: &str) -> Result<(), CoreError> {
        self.0.publish(exchange, routing_key, body.as_bytes(), type_id).await.map_err(core_error)
    }
}

/// Publishing off (`mq.enabled = false`, or no broker configured): the message is logged and
/// dropped, and the caller is told it was sent, as the Java services tell theirs once the
/// broker has it.
pub struct Dropped;

#[async_trait]
impl Publish for Dropped {
    async fn publish(&self, exchange: &str, routing_key: &str, _body: &str, type_id: &str) -> Result<(), CoreError> {
        tracing::warn!(exchange, routing_key, type_id, "message dropped: publishing is off");
        Ok(())
    }
}

/// The two exchanges core publishes to.
pub struct Mq {
    pub publisher: Arc<dyn Publish>,
    pub events: Route,
    pub notifications: Route,
}

impl Mq {
    /// From the configuration; the broker's URI is never logged.
    pub fn from_config(cfg: &MqSection) -> Self {
        let publisher: Arc<dyn Publish> = match cfg.amqp_uri().filter(|_| cfg.enabled) {
            Some(uri) => Arc::new(Amqp(connections::mq::Publisher::new(uri))),
            None => {
                tracing::info!("RabbitMQ publishing is off: events and notifications are dropped");
                Arc::new(Dropped)
            }
        };
        Self::with(publisher, cfg)
    }

    pub fn with(publisher: Arc<dyn Publish>, cfg: &MqSection) -> Self {
        Self {
            publisher,
            events: Route::new(&cfg.events_exchange, &cfg.events_routing_keys),
            notifications: Route::new(&cfg.notifications_exchange, &cfg.notifications_routing_keys),
        }
    }

    /// `EventCreationService.createEvent`.
    pub async fn create_event(&self, caller: &Caller, event: EventMessage) -> Result<bool, CoreError> {
        let (key, body) = connections::mq::prepare_event(&self.events, caller, event);
        self.publisher.publish(&self.events.exchange, &key, &body, EVENT_TYPE_ID).await?;
        Ok(true)
    }

    /// `NotificationService.processAndSendNotification`.
    pub async fn send_notification(&self, checks: &dyn HierarchyChecks, caller: &Caller, req: NotificationRequest) -> Result<Option<bool>, CoreError> {
        let Some((key, message)) = connections::notification::prepare(&self.notifications, checks, caller, req).await.map_err(core_error)? else {
            return Ok(None);
        };
        self.publisher.publish(&self.notifications.exchange, &key, &message.to_json(), NOTIFICATION_TYPE_ID).await?;
        Ok(Some(true))
    }
}

/// The storage events (`generateEvents`), on the `events` exchange.
pub struct MqEvents {
    pub mq: Arc<Mq>,
}

#[async_trait]
impl crate::storage::service::EventSink for MqEvents {
    async fn create_event(&self, app_code: &str, client_code: &str, event_name: &str, data: appdata::value::Document) -> Result<bool, CoreError> {
        let text = crate::gson::to_jackson_pretty_data(&appdata::value::Value::Object(data));
        let data: Map<String, Value> = serde_json::from_str(&text).map_err(|e| CoreError::unknown(e.to_string()))?;
        let event = EventMessage {
            event_name: Some(event_name.to_string()),
            client_code: Some(client_code.to_string()),
            app_code: Some(app_code.to_string()),
            data: Some(data),
            ..Default::default()
        };
        self.mq.create_event(&caller(), event).await
    }
}

/// Everything the integration functions and routes share.
pub struct Integrations {
    pub connections: Arc<Connections>,
    pub connection_docs: Arc<ConnectionDocs>,
    pub templates: Arc<TemplateDocs>,
    pub checks: Arc<SecurityChecks>,
    pub downloads: Option<Arc<Downloads>>,
    pub mq: Arc<Mq>,
    pub auth_functions: Arc<AuthFunctions>,
}

impl Integrations {
    pub fn new(
        cfg: &CoreConfig,
        docs: Arc<dyn DocSource>,
        security: Arc<SecurityCalls>,
        tokens: Arc<dyn TokenStore>,
        cache: CacheService,
        mq: Arc<Mq>,
        files: Option<Arc<dyn FileCreate>>,
    ) -> anyhow::Result<Self> {
        let zone = cfg.core.zone_offset_seconds()?;
        let c = &cfg.connections;
        let conn_cfg = ConnectionsConfig {
            block_private_targets: c.block_private_targets,
            java_zone_offset_seconds: zone,
            sendgrid_url: c.sendgrid_url.clone(),
            openai_base_url: c.openai_base_url.clone(),
        };
        let connection_docs = Arc::new(ConnectionDocs { source: docs.clone() });
        let auth_functions = Arc::new(AuthFunctions::default());
        let connections = Arc::new(Connections::new(conn_cfg, connection_docs.clone(), tokens, cache, auth_functions.clone()));
        Ok(Self {
            connections,
            connection_docs,
            templates: Arc::new(TemplateDocs { source: docs }),
            checks: Arc::new(SecurityChecks { security: security.clone() }),
            downloads: files.map(|files| Arc::new(Downloads { security, files })),
            mq,
            auth_functions,
        })
    }

    pub fn attach(&self, st: &AppState) {
        self.auth_functions.attach(st);
    }
}

/// `CoreTokenDAO` over core's MySQL pool, on the Java core's wall clock.
pub fn token_dao(cfg: &CoreConfig, pool: sqlx::MySqlPool) -> anyhow::Result<Arc<dyn TokenStore>> {
    Ok(Arc::new(TokenDao::new(pool, JavaClock { zone_offset_seconds: cfg.core.zone_offset_seconds()? })))
}
