//! `AppDataService`: the policy layer over the app-data engines. Which app and client an
//! operation is for, which storage and engine, the storage's authority expressions, triggers,
//! relations (created, checked, expanded, constrained on delete), events, the draft surface
//! and the builder-only operations.
//!
//! The Java chains are built with `FlatMapUtil.flatMapMonoWithNull`, so a step that completes
//! empty hands the next one a null rather than stopping it; where that decides the answer
//! (a storage that does not resolve reaching `genericOperation` as null, an engine that
//! completes empty being answered with the operation's FORBIDDEN message) it is kept here.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, OnceLock, Weak};

use appdata::engine::{AppDataEngine, Ctx};
use appdata::model::{
    AggregateQuery, Connection, DataObject, DraftCopyFilter, FilterCondition, FilterOperator, Page, Query, RelationConstraint,
    RelationType, Storage, StorageRelation,
};
use appdata::mysql::drift::{DriftRepair, Report};
use appdata::mysql::migration::TenantProgress;
use appdata::selection::{backend_for, Backend as EngineKind, Engines, CONNECTION_NAME, CONNECTION_TYPE};
use appdata::value::{Document, Value};
use appdata::AppDataError;
use async_trait::async_trait;
use axum::http::StatusCode;
use futures::future::BoxFuture;
use futures::FutureExt;
use indexmap::{IndexMap, IndexSet};
use platform::messages::JavaKey;
use platform::security::SecurityClient;

use super::defs::{not_found_or_forbidden, Catalog};
use super::values::{clone_map_object, gson_object};
use crate::authorities;
use crate::context;
use crate::error::{CoreError, CoreResult};
use crate::exec::{self, Arguments};
use crate::state::{AppState, Inner};

/// core's `messages_en.properties`, the keys the policy layer raises.
pub use crate::catalogue::keys as msg;

const MAX_CASCADE_DEPTH: usize = 8;
const MAX_EAGER_DEPTH: usize = 5;
const CASCADE_BATCH: i64 = 500;
const DATA_OBJECT_KEY: &str = "dataObject";
const EXISTING_DATA_OBJECT_KEY: &str = "existingDataObject";

tokio::task_local! {
    /// `appdata.cascade.depth`: how deep a chain of cascading deletes has gone.
    static CASCADE_DEPTH: usize;
}

fn cascade_depth() -> usize {
    CASCADE_DEPTH.try_with(|d| *d).unwrap_or(0)
}

/// `EventCreationService.createEvent`: where a `generateEvents` storage's events go.
#[async_trait]
pub trait EventSink: Send + Sync {
    async fn create_event(&self, app_code: &str, client_code: &str, event_name: &str, data: Document) -> CoreResult<bool>;
}


/// The MySQL engine's own operations, which have no Mongo counterpart.
#[async_trait]
pub trait MySqlAdmin: Send + Sync {
    /// The tenant schemas that hold the storage's table.
    async fn migration_tenants(&self, conn: &Connection, app_code: &str, storage: &Storage) -> appdata::AppDataResult<Vec<String>>;
    /// How far each of these tenants got, with its client and newest issues.
    async fn migration_status_of(&self, conn: &Connection, app_code: &str, storage: &Storage, tenants: &[String])
        -> appdata::AppDataResult<Vec<TenantProgress>>;
    async fn drift(&self, conn: &Connection, app_code: &str, storage: &Storage) -> appdata::AppDataResult<Vec<Report>>;
    async fn repair_drift(&self, conn: &Connection, app_code: &str, storage: &Storage, approved: bool)
        -> appdata::AppDataResult<Vec<DriftRepair>>;
}

#[async_trait]
impl MySqlAdmin for appdata::mysql::MySqlAppDataService {
    async fn migration_tenants(&self, conn: &Connection, app_code: &str, storage: &Storage) -> appdata::AppDataResult<Vec<String>> {
        appdata::mysql::MySqlAppDataService::migration_tenants(self, Some(conn), app_code, storage).await
    }
    async fn migration_status_of(&self, conn: &Connection, app_code: &str, storage: &Storage, tenants: &[String])
        -> appdata::AppDataResult<Vec<TenantProgress>> {
        appdata::mysql::MySqlAppDataService::migration_status_of(self, Some(conn), app_code, storage, tenants).await
    }
    async fn drift(&self, conn: &Connection, app_code: &str, storage: &Storage) -> appdata::AppDataResult<Vec<Report>> {
        appdata::mysql::MySqlAppDataService::drift(self, Some(conn), app_code, storage).await
    }
    async fn repair_drift(&self, conn: &Connection, app_code: &str, storage: &Storage, approved: bool)
        -> appdata::AppDataResult<Vec<DriftRepair>> {
        appdata::mysql::MySqlAppDataService::repair_drift(self, Some(conn), app_code, storage, approved).await
    }
}

/// The two engines `AppDataService` chooses between (`services`), and the MySQL one's own
/// operations.
#[derive(Clone)]
pub struct Backends {
    pub mongo: Arc<dyn AppDataEngine>,
    pub mysql: Arc<dyn AppDataEngine>,
    pub mysql_admin: Arc<dyn MySqlAdmin>,
}

impl Backends {
    pub fn of(engines: &Engines) -> Self {
        Self { mongo: engines.mongo.clone(), mysql: engines.mysql.clone(), mysql_admin: engines.mysql.clone() }
    }

    /// `services.get(conn == null ? MONGO : conn.getConnectionSubType())`.
    pub fn for_connection(&self, conn: Option<&Connection>) -> appdata::AppDataResult<Arc<dyn AppDataEngine>> {
        Ok(match backend_for(conn)? {
            EngineKind::Mongo => self.mongo.clone(),
            EngineKind::MySql => self.mysql.clone(),
        })
    }
}

/// `functionService.execute(namespace, name, appCode, clientCode, args, null)` for a trigger:
/// a function no repository has is skipped.
#[async_trait]
pub trait TriggerRunner: Send + Sync {
    async fn run(&self, namespace: &str, name: &str, app_code: &str, client_code: &str, args: kirun::Map<serde_json::Value>)
        -> CoreResult<()>;
}

/// Runs triggers on the execution state (held weakly: the state holds this service).
struct StateRunner(Weak<Inner>);

#[async_trait]
impl TriggerRunner for StateRunner {
    async fn run(&self, namespace: &str, name: &str, app_code: &str, client_code: &str, args: kirun::Map<serde_json::Value>)
        -> CoreResult<()> {
        let Some(state) = AppState::upgrade(&self.0) else {
            return Err(CoreError::unknown("triggers cannot run: no execution state"));
        };
        exec::run(&state, Some(namespace), name, app_code, client_code, Arguments::Body(args)).await?;
        Ok(())
    }
}

/// Where an operation's rows are: the engine and the app's appData connection.
#[derive(Clone)]
pub struct Backend {
    pub engine: Arc<dyn AppDataEngine>,
    pub conn: Option<Connection>,
}

impl Backend {
    fn conn(&self) -> Option<&Connection> {
        self.conn.as_ref()
    }
}

/// One operation's resolved app, client, backend and storage.
struct Target {
    app: String,
    client: String,
    backend: Backend,
    storage: Option<Storage>,
}

/// What a step inside `genericOperation` can end with besides a value: Java's empty Mono,
/// which `genericOperation` answers with its FORBIDDEN message.
enum Flow {
    Empty,
    Fail(CoreError),
}

impl From<CoreError> for Flow {
    fn from(e: CoreError) -> Self {
        Flow::Fail(e)
    }
}

impl From<AppDataError> for Flow {
    fn from(e: AppDataError) -> Self {
        match e {
            AppDataError::Empty => Flow::Empty,
            other => Flow::Fail(CoreError::from(other)),
        }
    }
}

type FlowResult<T> = Result<T, Flow>;

/// Which authority expression of a storage gates an operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    Create,
    Read,
    Update,
    Delete,
}

impl Gate {
    fn expression(self, s: &Storage) -> Option<&str> {
        match self {
            Gate::Create => s.create_auth.as_deref(),
            Gate::Read => s.read_auth.as_deref(),
            Gate::Update => s.update_auth.as_deref(),
            Gate::Delete => s.delete_auth.as_deref(),
        }
    }

    fn message(self) -> JavaKey {
        match self {
            Gate::Create => msg::FORBIDDEN_CREATE_STORAGE,
            Gate::Read => msg::FORBIDDEN_READ_STORAGE,
            Gate::Update => msg::FORBIDDEN_UPDATE_STORAGE,
            Gate::Delete => msg::FORBIDDEN_DELETE_STORAGE,
        }
    }
}

fn forbidden(key: JavaKey, param: &str) -> CoreError {
    CoreError::msg(StatusCode::FORBIDDEN, key, &[param])
}

/// A storage gate's refusal: it names the storage only to a signed-in caller (an anonymous one
/// is asked to sign in).
fn gate_refusal(key: JavaKey, storage: &str) -> CoreError {
    let e = forbidden(key, storage);
    if crate::catalogue::signed_in() {
        e
    } else {
        e.without_param("storage")
    }
}

/// `SecurityContextUtil.hasAuthority(expression, ca.getUser().getAuthorities())`.
fn has_authority(expression: Option<&str>) -> CoreResult<bool> {
    let auth = context::authentication();
    authorities::has_authority(expression, auth.authorities()).map_err(CoreError::from)
}

/// The engines' view of the caller and the surface.
pub fn ctx() -> Ctx {
    let auth = context::authentication();
    Ctx {
        url_client_code: auth.url_client_code().map(str::to_string),
        user_id: Some(auth.user_id()),
        authorities: auth.authorities().to_vec(),
        draft: context::is_draft(),
    }
}

pub struct AppDataService {
    defs: Arc<dyn Catalog>,
    security: SecurityClient,
    engines: Backends,
    builder_app_codes: Vec<String>,
    events: Arc<dyn EventSink>,
    /// The execution state, for triggers; set once the state that holds this service exists.
    runner: OnceLock<Arc<dyn TriggerRunner>>,
}

/// One related object a write names: created, checked, or failed.
struct RelationDataObject {
    field_name: String,
    is_new: bool,
    data: Document,
    id: Option<String>,
    exception: Option<CoreError>,
}

/// `eagerTree`: dotted paths as a tree, siblings merged.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct EagerTree(pub IndexMap<String, EagerTree>);

impl EagerTree {
    pub fn of(fields: Option<&[String]>) -> EagerTree {
        let mut root = EagerTree::default();
        for path in fields.unwrap_or_default() {
            if path.trim().is_empty() {
                continue;
            }
            let mut level = &mut root;
            for segment in path.split('.') {
                let name = segment.trim();
                if name.is_empty() {
                    break;
                }
                level = level.0.entry(name.to_string()).or_default();
            }
        }
        root
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// One relation of a page, fetched.
struct RelatedFetch {
    field: String,
    relation_type: Option<RelationType>,
    by_id: IndexMap<String, Document>,
    target: Option<Storage>,
}

/// A relation pointing at the row being deleted, and what it asks for.
#[derive(Clone)]
struct ReferencingRelation {
    child: Storage,
    field: String,
    relation: StorageRelation,
}

impl ReferencingRelation {
    fn many(&self) -> bool {
        self.relation.relation_type == Some(RelationType::ToMany)
    }

    fn constraint(&self) -> Option<RelationConstraint> {
        self.relation.delete_constraint
    }
}

/// `getElementBySchemaType` is in `files`; uploads call the engines directly.
pub struct Upload {
    pub file_type: super::files::DataFileType,
    pub bytes: Vec<u8>,
}

impl AppDataService {
    pub fn new(
        defs: Arc<dyn Catalog>,
        security: SecurityClient,
        engines: Backends,
        builder_app_codes: Vec<String>,
        events: Arc<dyn EventSink>,
    ) -> Self {
        Self { defs, security, engines, builder_app_codes, events, runner: OnceLock::new() }
    }

    /// Runs triggers with `runner` instead of the execution state (tests).
    pub fn set_trigger_runner(&self, runner: Arc<dyn TriggerRunner>) {
        let _ = self.runner.set(runner);
    }

    /// Makes triggers runnable: the state the functions run in.
    pub fn attach(&self, state: &AppState) {
        let _ = self.runner.set(Arc::new(StateRunner(state.downgrade())));
    }

    pub fn catalog(&self) -> &Arc<dyn Catalog> {
        &self.defs
    }

    // ------------------------------------------------------------------ resolution

    /// `appCode(appCode, ca)`: the argument; else the app owning the running KIRun function;
    /// else the app the request came in for.
    fn app_code(app_code: Option<&str>) -> String {
        if let Some(a) = app_code.filter(|a| !a.trim().is_empty()) {
            return a.to_string();
        }
        context::owner_app_code()
            .or_else(|| context::authentication().url_app_code().map(str::to_string))
            .unwrap_or_default()
    }

    /// `clientCode(clientCode)`: a signed-out caller gets what it sent, or its url client; a
    /// signed-in one its own client when it sent none, or one it manages or is managed by.
    async fn client_code(&self, client_code: Option<&str>) -> CoreResult<String> {
        let ca = context::authentication();
        let blank = client_code.is_none_or(|c| c.trim().is_empty());
        if !ca.is_authenticated() {
            return Ok(if blank {
                ca.url_client_code().unwrap_or_default().to_string()
            } else {
                client_code.unwrap_or_default().to_string()
            });
        }
        if blank {
            return Ok(ca.client_code().unwrap_or_default().to_string());
        }
        let cc = client_code.unwrap_or_default();
        let own = ca.client_code().unwrap_or_default();
        let manages = self.security.does_client_manage_client_code(cc, own).await.map_err(CoreError::from)?
            || self.security.does_client_manage_client_code(own, cc).await.map_err(CoreError::from)?;
        if manages {
            Ok(cc.to_string())
        } else {
            Err(forbidden(msg::FORBIDDEN_CLIENT_CODE, cc))
        }
    }

    /// `connectionService.read("appData", ac, cc, APP_DATA)` and the engine it selects.
    async fn backend(&self, app: &str, client: &str) -> CoreResult<Backend> {
        let conn = self.defs.connection(CONNECTION_NAME, app, client, CONNECTION_TYPE).await?;
        let engine = self.engines.for_connection(conn.as_ref())?;
        Ok(Backend { engine, conn })
    }

    /// `resolveStorage`: an `onlyThruKIRun` storage only inside a KIRun run or for a builder
    /// session; refused loudly (403) or, for a relation, skipped.
    async fn resolve_storage(&self, name: &str, app: &str, client: &str, refuse_loudly: bool) -> CoreResult<Option<Storage>> {
        let Some(s) = self.defs.storage(name, app, client).await? else { return Ok(None) };
        if s.only_thru_kirun != Some(true) || context::in_kirun() {
            return Ok(Some(s));
        }
        let verified = context::authentication().verified_app_code().unwrap_or_default().to_string();
        if self.builder_app_codes.iter().any(|b| *b == verified) {
            return Ok(Some(s));
        }
        if !refuse_loudly {
            return Ok(None);
        }
        Err(gate_refusal(msg::STORAGE_ONLY_THRU_KIRUN, name))
    }

    async fn storage_with_kirun_validation(&self, name: &str, app: &str, client: &str) -> CoreResult<Option<Storage>> {
        self.resolve_storage(name, app, client, true).await
    }

    async fn storage_for_relation(&self, name: &str, app: &str, client: &str) -> CoreResult<Option<Storage>> {
        self.resolve_storage(name, app, client, false).await
    }

    /// The four steps every entry point starts with.
    async fn target(&self, app_code: Option<&str>, client_code: Option<&str>, storage_name: &str) -> CoreResult<Target> {
        let app = Self::app_code(app_code);
        let client = self.client_code(client_code).await?;
        let backend = self.backend(&app, &client).await?;
        let storage = self.storage_with_kirun_validation(storage_name, &app, &client).await?;
        Ok(Target { app, client, backend, storage })
    }

    /// `genericOperation`: 404 without a storage, the gate's FORBIDDEN without the authority,
    /// and the same FORBIDDEN when the operation completes empty.
    async fn generic<'s, T, F, Fut>(&self, storage: Option<&'s Storage>, gate: Gate, op: F) -> CoreResult<T>
    where
        F: FnOnce(&'s Storage) -> Fut,
        Fut: Future<Output = FlowResult<T>>,
    {
        let Some(s) = storage else {
            return Err(CoreError::msg(StatusCode::NOT_FOUND, msg::STORAGE_NOT_FOUND, &[]));
        };
        if !has_authority(gate.expression(s))? {
            return Err(gate_refusal(gate.message(), &s.name));
        }
        match op(s).await {
            Ok(v) => Ok(v),
            // Only a MySQL update of a row that went away completes empty; Java answers it with
            // the operation's refusal, which says it plainly here.
            Err(Flow::Empty) if gate == Gate::Update => Err(forbidden(gate.message(), &s.name).with_code("CORE.STORAGE_ROW_GONE")),
            Err(Flow::Empty) => Err(gate_refusal(gate.message(), &s.name)),
            Err(Flow::Fail(e)) => Err(e),
        }
    }

    /// `hasWriteAccess(appCode, ca.getClientCode())`, an absent answer being false.
    async fn has_write_access(&self, app: &str) -> CoreResult<bool> {
        let ca = context::authentication();
        self.security
            .has_write_access(app, ca.client_code().unwrap_or_default())
            .await
            .map_err(CoreError::from)
    }

    /// `canWriteApp`: write access to the app, else FORBIDDEN_EXPLICIT_DRAFT_SURFACE.
    async fn can_write_app(&self, app: &str) -> CoreResult<()> {
        if self.has_write_access(app).await? {
            Ok(())
        } else {
            Err(forbidden(msg::FORBIDDEN_EXPLICIT_DRAFT_SURFACE, app))
        }
    }

    /// `builderOnly`: write access to the app, else FORBIDDEN_UPDATE_STORAGE.
    async fn builder_only(&self, app: &str) -> CoreResult<()> {
        if self.has_write_access(app).await? {
            Ok(())
        } else {
            Err(forbidden(msg::FORBIDDEN_UPDATE_STORAGE, app).with_code("CORE.STORAGE_BUILDER_ONLY").param("app", app))
        }
    }

    // ------------------------------------------------------------------ surface

    /// `onSurface`: with no `draft` the operation runs as is; naming a surface needs write
    /// access to the app (the url app when none is given).
    pub async fn on_surface<T, Fut>(&self, app_code: Option<&str>, draft: Option<bool>, op: Fut) -> CoreResult<T>
    where
        Fut: Future<Output = CoreResult<T>>,
    {
        let Some(draft) = draft else { return op.await };
        let ca = context::authentication();
        let app = match app_code {
            Some(a) => a.to_string(),
            None => ca.url_app_code().unwrap_or_default().to_string(),
        };
        if self.has_write_access(&app).await? {
            context::with_surface(draft, op).await
        } else {
            Err(forbidden(msg::FORBIDDEN_EXPLICIT_DRAFT_SURFACE, app_code.unwrap_or("null")))
        }
    }

    // ------------------------------------------------------------------ create

    pub fn create<'a>(
        &'a self,
        app_code: Option<&'a str>,
        client_code: Option<&'a str>,
        storage_name: &'a str,
        data: DataObject,
        eager: Option<bool>,
        eager_fields: Option<Vec<String>>,
    ) -> BoxFuture<'a, CoreResult<Document>> {
        async move {
            let t = self.target(app_code, client_code, storage_name).await?;
            let (created, sent) = self
                .generic(t.storage.as_ref(), Gate::Create, |s| async {
                    let data = self.process_relations_for_create(&t.app, &t.client, s, data, &t.backend).await?;
                    let sent = data.data.clone().unwrap_or_default();
                    let created = self.create_with_triggers(&t.client, &t.backend, s, data).await?;
                    if s.generate_events != Some(true) {
                        return Ok((created, sent));
                    }
                    Ok((self.generate_event(&t.app, &t.client, s, "Create", created, None).await?, sent))
                })
                .await?;
            let storage = t.storage.as_ref().expect("gated");
            let fields = resolve_eager_fields(storage, eager, eager_fields.as_deref());
            self.fill_created(&t.app, &t.client, storage, created, &sent, &t.backend, fields.as_deref()).await
        }
        .boxed()
    }

    pub async fn create_many(
        &self,
        app_code: Option<&str>,
        client_code: Option<&str>,
        storage_name: &str,
        data_array: Vec<DataObject>,
        eager: Option<bool>,
        eager_fields: Option<Vec<String>>,
    ) -> CoreResult<Vec<Document>> {
        let t = self.target(app_code, client_code, storage_name).await?;
        self.generic(t.storage.as_ref(), Gate::Create, |s| async {
            let fields = resolve_eager_fields(s, eager, eager_fields.as_deref());
            let mut out = Vec::with_capacity(data_array.len());
            for data in data_array {
                let data = self.process_relations_for_create(&t.app, &t.client, s, data, &t.backend).await?;
                let sent = data.data.clone().unwrap_or_default();
                let mut created = self.create_with_triggers(&t.client, &t.backend, s, data).await?;
                if s.generate_events == Some(true) {
                    let mut arr = Document::new();
                    arr.insert("dataArr".into(), Value::Array(vec![Value::Object(created)]));
                    created = self.generate_event(&t.app, &t.client, s, "Create", arr, None).await?;
                }
                out.push(self.fill_created(&t.app, &t.client, s, created, &sent, &t.backend, fields.as_deref()).await?);
            }
            Ok(out)
        })
        .await
    }

    async fn create_with_triggers(&self, client: &str, backend: &Backend, storage: &Storage, data: DataObject) -> FlowResult<Document> {
        let before = triggers_of(storage, "BEFORE_CREATE");
        let after = triggers_of(storage, "AFTER_CREATE");
        if before.is_empty() && after.is_empty() {
            return Ok(backend.engine.create(&ctx(), client, backend.conn(), storage, no_null_data(data)?).await?);
        }
        if !before.is_empty() {
            let row = data.data.clone().unwrap_or_default();
            self.execute_triggers(storage, &before, vec![(DATA_OBJECT_KEY, gson_value(&row)?)]).await?;
        }
        let created = backend.engine.create(&ctx(), client, backend.conn(), storage, no_null_data(data)?).await?;
        if !after.is_empty() {
            self.execute_triggers(storage, &after, vec![(DATA_OBJECT_KEY, gson_value(&created)?)]).await?;
        }
        Ok(created)
    }

    /// `executeTriggers`: each `namespace.name` run for the storage's own app and client,
    /// with the rows as arguments. A trigger no repository has is skipped.
    async fn execute_triggers(&self, storage: &Storage, triggers: &[String], args: Vec<(&str, serde_json::Value)>) -> CoreResult<()> {
        let Some(runner) = self.runner.get() else {
            return Err(CoreError::unknown("triggers cannot run: no execution state"));
        };
        for trigger in triggers {
            let Some(dot) = trigger.rfind('.') else {
                return Err(CoreError::unknown(format!(
                    "begin 0, end -1, length {}",
                    trigger.encode_utf16().count()
                )));
            };
            let (ns, name) = (&trigger[..dot], &trigger[dot + 1..]);
            let arguments: kirun::Map<serde_json::Value> = args.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
            runner.run(ns, name, &storage.app_code, &storage.client_code, arguments).await?;
        }
        Ok(())
    }

    /// `generateEvent`: `Storage.<name>.<operation>` raised when the app defines that event.
    async fn generate_event(
        &self,
        app: &str,
        client: &str,
        storage: &Storage,
        operation: &str,
        data: Document,
        existing: Option<Document>,
    ) -> CoreResult<Document> {
        if storage.generate_events != Some(true) {
            return Ok(data);
        }
        let event_name = format!("Storage.{}.{operation}", storage.name);
        let Some(def) = self.defs.event_definition(&event_name, app, client).await? else {
            return Ok(data);
        };
        let mut event = Document::new();
        event.insert(DATA_OBJECT_KEY.into(), Value::Object(data.clone()));
        if matches!(def.get("includeContextAuthentication"), Some(overridable::JValue::Bool(true))) {
            // `ContextAuthentication` as the event's Jackson writes it.
            let auth = connections::mq::jackson_authentication(&crate::integrations::caller());
            event.insert("authentication".into(), Value::from_json(&auth));
        }
        if let Some(e) = existing {
            event.insert(EXISTING_DATA_OBJECT_KEY.into(), Value::Object(e));
        }
        if let Some(event) = batch::defer(app, client, &event_name, event) {
            self.events.create_event(app, client, &event_name, event).await?;
        }
        Ok(data)
    }

    // ------------------------------------------------------------------ relations on write

    /// `getRelationDataObjectList` as the list of objects to check or create, by field.
    fn relation_objects(storage: &Storage, dob: &Document) -> Vec<(String, String, Document)> {
        let mut out = Vec::new();
        let Some(relations) = &storage.relations else { return out };
        for (key, relation) in relations {
            let Some(v) = dob.get(key).filter(|v| !v.is_null()) else { continue };
            for map in convert_foreign_key_values(v, relation) {
                out.push((key.clone(), relation.storage_name.clone().unwrap_or_default(), map));
            }
        }
        out
    }

    /// Runs the checks and creates in order, each failure captured on its own object.
    async fn run_relation_objects(&self, app: &str, client: &str, backend: &Backend, specs: Vec<(String, String, Document)>)
        -> Vec<RelationDataObject> {
        let mut out = Vec::with_capacity(specs.len());
        for (field, storage_name, map) in specs {
            match self.check_or_create_related_object(app, client, backend, &storage_name, &map).await {
                Ok(None) => {}
                Ok(Some((is_new, id))) => {
                    out.push(RelationDataObject { field_name: field, is_new, data: map, id: Some(id), exception: None })
                }
                Err(e) => out.push(RelationDataObject { field_name: field, is_new: false, data: map, id: None, exception: Some(e) }),
            }
        }
        out
    }

    /// `checkOrCreateRelatedObject`: an object with an `_id` must exist; one without is
    /// created. A related storage that does not resolve completes empty.
    async fn check_or_create_related_object(&self, app: &str, client: &str, backend: &Backend, storage_name: &str, map: &Document)
        -> CoreResult<Option<(bool, String)>> {
        let Some(storage) = self.storage_with_kirun_validation(storage_name, app, client).await? else {
            return Ok(None);
        };
        let id = map.get("_id").filter(|v| !v.is_null()).map(Value::java_string).filter(|s| !s.trim().is_empty());
        if let Some(id) = id {
            let exists = backend.engine.check_if_exists(&ctx(), client, backend.conn(), &storage, &id).await?;
            if exists {
                return Ok(Some((false, id)));
            }
            return Err(CoreError::msg_as(StatusCode::NOT_FOUND, msg::OBJECT_NOT_FOUND, "CORE.ROW_NOT_FOUND", &[storage_name, &id]));
        }
        let created = self
            .create(Some(app), Some(client), storage_name, DataObject::of(map.clone()), Some(false), Some(Vec::new()))
            .await?;
        let id = created.get("_id").map(Value::java_string).unwrap_or_else(|| "null".into());
        Ok(Some((true, id)))
    }

    async fn process_relations_for_create(&self, app: &str, client: &str, storage: &Storage, data: DataObject, backend: &Backend)
        -> CoreResult<DataObject> {
        if !storage.has_relations() {
            return Ok(data);
        }
        let mut dob = clone_map_object(data.data.as_ref().unwrap_or(&Document::new()));
        let specs = Self::relation_objects(storage, &dob);
        if specs.is_empty() {
            return Ok(data);
        }
        let list = self.run_relation_objects(app, client, backend, specs).await;
        if list.iter().any(|r| r.exception.is_some()) {
            return Err(self.check_and_delete_created_objects(app, client, storage, backend, list).await);
        }
        for (field, ids) in grouped(&list) {
            let relation = storage.relation(&field).expect("listed from the relations");
            if relation.relation_type == Some(RelationType::ToMany) {
                dob.insert(field, Value::Array(ids.into_iter().map(Value::String).collect()));
            } else if let Some(first) = ids.into_iter().next() {
                dob.insert(field, Value::String(first));
            }
        }
        Ok(DataObject { message: data.message, data: Some(dob) })
    }

    /// `checkAndDeleteCreatedObjects`: the objects this write created are deleted again and
    /// the first failure answered as INVALID_RELATION_DATA.
    async fn check_and_delete_created_objects(&self, app: &str, client: &str, storage: &Storage, backend: &Backend, list: Vec<RelationDataObject>)
        -> CoreError {
        let first = list.iter().find(|r| r.exception.is_some()).expect("has a failure");
        let error = CoreError::msg(
            StatusCode::BAD_REQUEST,
            msg::INVALID_RELATION_DATA,
            &[&first.field_name, &Value::Object(first.data.clone()).java_string()],
        )
        .caused_by(first.exception.as_ref().map(CoreError::text).unwrap_or_default());
        for created in list.iter().filter(|r| r.exception.is_none() && r.is_new) {
            let Some(rel) = storage.relation(&created.field_name) else { continue };
            let _ = self
                .delete_created_related_object(app, client, backend, rel.storage_name.as_deref().unwrap_or_default(), created.id.as_deref().unwrap_or_default())
                .await;
        }
        error
    }

    /// `deleteCreatedRelatedObject`: a rollback, so no version row is asked for.
    async fn delete_created_related_object(&self, app: &str, client: &str, backend: &Backend, storage_name: &str, id: &str)
        -> CoreResult<bool> {
        let Some(storage) = self.storage_with_kirun_validation(storage_name, app, client).await? else {
            return Ok(false);
        };
        Ok(backend.engine.delete(&ctx(), client, backend.conn(), &storage, id, None).await?)
    }

    // ------------------------------------------------------------------ update

    #[allow(clippy::too_many_arguments)]
    pub async fn update(
        &self,
        app_code: Option<&str>,
        client_code: Option<&str>,
        storage_name: &str,
        data: DataObject,
        override_: bool,
        eager: Option<bool>,
        eager_fields: Option<Vec<String>>,
    ) -> CoreResult<Document> {
        let t = self.target(app_code, client_code, storage_name).await?;
        let updated = self
            .generic(t.storage.as_ref(), Gate::Update, |s| async {
                let data = self.process_relations_for_update(&t.app, &t.client, &t.backend, s, data, override_).await?;
                let (updated, existing) = self.update_with_triggers(&t.app, &t.client, &t.backend, s, data, override_).await?;
                Ok(self.generate_event(&t.app, &t.client, s, "Update", updated, existing).await?)
            })
            .await?;
        let storage = t.storage.as_ref().expect("gated");
        let fields = resolve_eager_fields(storage, eager, eager_fields.as_deref());
        self.fill_one(&t.app, &t.client, storage, updated, &t.backend, fields.as_deref()).await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_many(
        &self,
        app_code: Option<&str>,
        client_code: Option<&str>,
        storage_name: &str,
        data_array: Vec<DataObject>,
        override_: bool,
        eager: Option<bool>,
        eager_fields: Option<Vec<String>>,
    ) -> CoreResult<Vec<Document>> {
        let t = self.target(app_code, client_code, storage_name).await?;
        self.generic(t.storage.as_ref(), Gate::Update, |s| async {
            let fields = resolve_eager_fields(s, eager, eager_fields.as_deref());
            let mut out = Vec::with_capacity(data_array.len());
            for data in data_array {
                let data = self.process_relations_for_update(&t.app, &t.client, &t.backend, s, data, override_).await?;
                let (updated, existing) = self.update_with_triggers(&t.app, &t.client, &t.backend, s, data, override_).await?;
                let updated = self.generate_event(&t.app, &t.client, s, "Update", updated, existing).await?;
                out.push(self.fill_one(&t.app, &t.client, s, updated, &t.backend, fields.as_deref()).await?);
            }
            Ok(out)
        })
        .await
    }

    async fn process_relations_for_update(
        &self,
        app: &str,
        client: &str,
        backend: &Backend,
        storage: &Storage,
        data: DataObject,
        override_: bool,
    ) -> CoreResult<DataObject> {
        if !storage.has_relations() {
            return Ok(data);
        }
        let mut dob = data.data.clone().unwrap_or_default();
        let specs = Self::relation_objects(storage, &dob);
        let Some(id) = dob.get("_id").filter(|v| !v.is_null()).map(Value::java_string) else {
            return Err(CoreError::unknown(
                "Cannot invoke \"Object.toString()\" because the return value of \"java.util.Map.get(Object)\" is null",
            ));
        };
        let existing = self.read(Some(app), Some(client), &storage.name, &id, Some(false), Some(Vec::new())).await?;
        let list = self.run_relation_objects(app, client, backend, specs).await;
        if list.iter().any(|r| r.exception.is_some()) {
            return Err(self.check_and_delete_created_objects(app, client, storage, backend, list).await);
        }
        let mut removals: Vec<(String, String)> = Vec::new();
        for (field, ids) in grouped(&list) {
            let in_dob = dob.contains_key(&field);
            let existing_null = existing.get(&field).is_none_or(Value::is_null);
            if (override_ && !in_dob && existing_null) || (!override_ && !in_dob) {
                continue;
            }
            let relation = storage.relation(&field).expect("listed from the relations").clone();
            if relation.update_constraint == Some(RelationConstraint::Cascade) {
                if !override_ {
                    continue;
                }
                let target = relation.storage_name.clone().unwrap_or_default();
                let mut all: IndexSet<(String, String)> = IndexSet::new();
                match existing.get(&field) {
                    Some(Value::Array(a)) => {
                        for id in a {
                            all.insert((target.clone(), id.java_string()));
                        }
                    }
                    Some(Value::String(id)) => {
                        all.insert((target.clone(), id.clone()));
                    }
                    _ => {}
                }
                match dob.get(&field) {
                    Some(Value::Array(a)) => {
                        for id in a {
                            all.shift_remove(&(target.clone(), id.java_string()));
                        }
                    }
                    Some(Value::String(id)) => {
                        all.shift_remove(&(target.clone(), id.clone()));
                    }
                    _ => {}
                }
                removals.extend(all);
            }
            if relation.relation_type == Some(RelationType::ToMany) {
                dob.insert(field, Value::Array(ids.into_iter().map(Value::String).collect()));
            } else if let Some(first) = ids.into_iter().next() {
                dob.insert(field, Value::String(first));
            }
        }
        for (storage_name, id) in removals {
            let _ = self.delete_created_related_object(app, client, backend, &storage_name, &id).await;
        }
        Ok(DataObject { message: data.message, data: Some(dob) })
    }

    async fn update_with_triggers(
        &self,
        app: &str,
        client: &str,
        backend: &Backend,
        storage: &Storage,
        data: DataObject,
        override_: bool,
    ) -> FlowResult<(Document, Option<Document>)> {
        let before = triggers_of(storage, "BEFORE_UPDATE");
        let after = triggers_of(storage, "AFTER_UPDATE");
        let events = storage.generate_events == Some(true);
        if before.is_empty() && after.is_empty() && !events {
            let updated = backend.engine.update(&ctx(), client, backend.conn(), storage, no_null_update(data)?, Some(override_)).await?;
            return Ok((updated, None));
        }
        let id = data
            .data
            .as_ref()
            .and_then(|d| d.get("_id"))
            .filter(|v| !v.is_null())
            .map(Value::java_string)
            .unwrap_or_else(|| "null".into());
        let existing = self.read(Some(app), Some(client), &storage.name, &id, Some(false), Some(Vec::new())).await?;
        if !before.is_empty() {
            let row = data.data.clone().unwrap_or_default();
            self.execute_triggers(
                storage,
                &before,
                vec![(DATA_OBJECT_KEY, gson_value(&row)?), (EXISTING_DATA_OBJECT_KEY, gson_value(&existing)?)],
            )
            .await?;
        }
        let updated = backend.engine.update(&ctx(), client, backend.conn(), storage, no_null_update(data)?, Some(override_)).await?;
        if !after.is_empty() {
            self.execute_triggers(
                storage,
                &after,
                vec![(DATA_OBJECT_KEY, gson_value(&updated)?), (EXISTING_DATA_OBJECT_KEY, gson_value(&existing)?)],
            )
            .await?;
        }
        Ok((updated, Some(existing)))
    }

    // ------------------------------------------------------------------ reads

    pub fn read<'a>(
        &'a self,
        app_code: Option<&'a str>,
        client_code: Option<&'a str>,
        storage_name: &'a str,
        id: &'a str,
        eager: Option<bool>,
        eager_fields: Option<Vec<String>>,
    ) -> BoxFuture<'a, CoreResult<Document>> {
        async move {
            let t = self.target(app_code, client_code, storage_name).await?;
            let row = self
                .generic(t.storage.as_ref(), Gate::Read, |s| async {
                    Ok(t.backend.engine.read(&ctx(), &t.client, t.backend.conn(), s, id).await?)
                })
                .await?;
            let storage = t.storage.as_ref().expect("gated");
            let fields = resolve_eager_fields(storage, eager, eager_fields.as_deref());
            self.fill_one(&t.app, &t.client, storage, row, &t.backend, fields.as_deref()).await
        }
        .boxed()
    }

    pub async fn read_page(&self, app_code: Option<&str>, client_code: Option<&str>, storage_name: &str, query: &Query)
        -> CoreResult<Page<Document>> {
        tracing::info!(app_code, client_code, storage_name, "readPage");
        let t = self.target(app_code, client_code, storage_name).await?;
        let page = self
            .generic(t.storage.as_ref(), Gate::Read, |s| async {
                Ok(t.backend.engine.read_page(&ctx(), &t.client, t.backend.conn(), s, query).await?)
            })
            .await?;
        let storage = t.storage.as_ref().expect("gated");
        if !storage.has_relations() {
            return Ok(page);
        }
        let fields = resolve_eager_fields(storage, query.eager, query.eager_fields.as_deref());
        let tree = EagerTree::of(fields.as_deref());
        let mut rows = page.content;
        self.fill_related(&t.app, &t.client, storage, &mut rows, &t.backend, &tree, 0).await?;
        let total = page.total;
        Ok(Page::of(rows, page.pageable, || total))
    }

    pub async fn aggregate(&self, app_code: Option<&str>, client_code: Option<&str>, storage_name: &str, query: &AggregateQuery)
        -> CoreResult<Page<Document>> {
        let t = self.target(app_code, client_code, storage_name).await?;
        self.generic(t.storage.as_ref(), Gate::Read, |s| async {
            Ok(t.backend.engine.aggregate(&ctx(), &t.client, t.backend.conn(), s, query).await?)
        })
        .await
    }

    pub async fn read_version(&self, app_code: Option<&str>, client_code: Option<&str>, storage_name: &str, version_id: &str)
        -> CoreResult<Document> {
        let t = self.target(app_code, client_code, storage_name).await?;
        self.generic(t.storage.as_ref(), Gate::Read, |s| async {
            Ok(t.backend.engine.read_version(&ctx(), &t.client, t.backend.conn(), s, version_id).await?)
        })
        .await
    }

    pub async fn read_page_version(
        &self,
        app_code: Option<&str>,
        client_code: Option<&str>,
        storage_name: &str,
        object_id: &str,
        query: &Query,
        include_object: Option<bool>,
    ) -> CoreResult<Page<Document>> {
        let t = self.target(app_code, client_code, storage_name).await?;
        self.generic(t.storage.as_ref(), Gate::Read, |s| async {
            Ok(t
                .backend
                .engine
                .read_page_version(&ctx(), &t.client, t.backend.conn(), s, object_id, query, include_object)
                .await?)
        })
        .await
    }

    /// `readPageAsFlux` for a download.
    pub async fn read_rows_for_download(&self, app_code: Option<&str>, client_code: Option<&str>, storage_name: &str, query: &Query)
        -> CoreResult<(Storage, Vec<Document>)> {
        let t = self.target(app_code, client_code, storage_name).await?;
        let rows = self
            .generic(t.storage.as_ref(), Gate::Read, |s| async {
                Ok(t.backend.engine.read_page_rows(&ctx(), &t.client, t.backend.conn(), s, query).await?)
            })
            .await?;
        Ok((t.storage.expect("gated"), rows))
    }

    // ------------------------------------------------------------------ fields

    /// The fields of a storage (`CoreServices.Storage.GetFields`): each property's schema in
    /// the Gson form a schema is served in. The storage resolves and is gated as a read is
    /// (the app and client defaulted the same way, `onlyThruKIRun`, `readAuth`), on the
    /// request's surface; no rows are read, so no connection or engine is picked. A top-level
    /// `ref` is followed through the schemas the write validator checks rows against (core's,
    /// then the app's as the storage's client resolves them, its own copy first); properties
    /// written beside the ref win over the referenced ones, as `getResolvedSchema` merges them.
    /// Relation fields are not part of the schema and are not added.
    pub async fn storage_fields(&self, app_code: Option<&str>, client_code: Option<&str>, storage_name: &str)
        -> CoreResult<serde_json::Map<String, serde_json::Value>> {
        let app = Self::app_code(app_code);
        let client = self.client_code(client_code).await?;
        let storage = self.storage_with_kirun_validation(storage_name, &app, &client).await?;
        let s = self.generic(storage.as_ref(), Gate::Read, |s| async move { Ok(s.clone()) }).await?;
        let raw = s
            .schema
            .as_ref()
            .and_then(|r| crate::java_model::gson_schema(&r.to_json()))
            .unwrap_or_else(|| serde_json::Value::Object(Default::default()));
        let schemas = self.defs.schema_source(&s.app_code, &s.client_code).await?;
        let resolved = follow_schema_ref(&raw, schemas.as_ref(), &s.name).await?;
        Ok(match resolved.get("properties") {
            Some(serde_json::Value::Object(p)) => p.clone(),
            _ => serde_json::Map::new(),
        })
    }

    // ------------------------------------------------------------------ eager relations

    /// [`Self::fill_one`] for a row the Mongo engine just inserted. Its relation fields still
    /// hold the stored ObjectIds (only reads turn them back into text, `updateDocWithIds`),
    /// which the engines hand over as Jackson writes an ObjectId (`timestamp`, `date`), and Java
    /// collects them with `toString()`, the hex id. That text is gone from the bean, so the ids
    /// the row was written with stand in for the lookup; a field nothing replaced keeps the
    /// bean, as Java's keeps the ObjectId.
    #[allow(clippy::too_many_arguments)]
    async fn fill_created(
        &self,
        app: &str,
        client: &str,
        storage: &Storage,
        mut row: Document,
        sent: &Document,
        backend: &Backend,
        fields: Option<&[String]>,
    ) -> CoreResult<Document> {
        let tree = EagerTree::of(fields);
        let mut kept: Vec<(String, Value, Value)> = Vec::new();
        for key in storage.relation_keys() {
            if !tree.0.contains_key(&key) {
                continue;
            }
            let (Some(stored), Some(given)) = (row.get(&key), sent.get(&key)) else { continue };
            if is_object_id_bean(stored) || stored.as_array().is_some_and(|a| a.iter().any(is_object_id_bean)) {
                kept.push((key.clone(), stored.clone(), given.clone()));
                row.insert(key, given.clone());
            }
        }
        let mut filled = self.fill_one(app, client, storage, row, backend, fields).await?;
        for (key, stored, given) in kept {
            if filled.get(&key) == Some(&given) {
                filled.insert(key, stored);
            }
        }
        Ok(filled)
    }

    async fn fill_one(&self, app: &str, client: &str, storage: &Storage, row: Document, backend: &Backend, fields: Option<&[String]>)
        -> CoreResult<Document> {
        let tree = EagerTree::of(fields);
        let mut rows = vec![row];
        self.fill_related(app, client, storage, &mut rows, backend, &tree, 0).await?;
        Ok(rows.pop().unwrap_or_default())
    }

    /// `fillRelatedObjects`: per relation, one read of every object the rows reference, the
    /// target storage gated on its own readAuth; then the next level over the objects fetched.
    #[allow(clippy::too_many_arguments)]
    fn fill_related<'a>(
        &'a self,
        app: &'a str,
        client: &'a str,
        storage: &'a Storage,
        rows: &'a mut Vec<Document>,
        backend: &'a Backend,
        tree: &'a EagerTree,
        depth: usize,
    ) -> BoxFuture<'a, CoreResult<()>> {
        async move {
            if rows.is_empty() || !storage.has_relations() || tree.is_empty() || depth >= MAX_EAGER_DEPTH {
                return Ok(());
            }
            let relations = storage.relations.as_ref().expect("has relations");
            let fields: Vec<String> = tree.0.keys().filter(|f| relations.contains_key(*f)).cloned().collect();
            for field in fields {
                let Some(mut fetched) = self.related_objects_for(app, client, storage, rows, backend, &field).await? else {
                    continue;
                };
                let nested = &tree.0[&field];
                if !nested.is_empty() && !fetched.by_id.is_empty() {
                    if let Some(target) = fetched.target.clone() {
                        let mut objects: Vec<Document> = fetched.by_id.values().cloned().collect();
                        self.fill_related(app, client, &target, &mut objects, backend, nested, depth + 1).await?;
                        for (slot, filled) in fetched.by_id.values_mut().zip(objects) {
                            *slot = filled;
                        }
                    }
                }
                apply_related(rows, &fetched.field, fetched.relation_type, &fetched.by_id);
            }
            Ok(())
        }
        .boxed()
    }

    /// `relatedObjectsFor`: `None` when the target storage is skipped (an `onlyThruKIRun`
    /// one, or one that does not resolve, with ids to fetch).
    async fn related_objects_for(&self, app: &str, client: &str, storage: &Storage, rows: &[Document], backend: &Backend, field: &str)
        -> CoreResult<Option<RelatedFetch>> {
        let relation = storage.relation(field).expect("a relation of the storage");
        let mut ids: IndexSet<String> = IndexSet::new();
        for row in rows {
            collect_ids(row.get(field), &mut ids);
        }
        let target = self.storage_for_relation(relation.storage_name.as_deref().unwrap_or_default(), app, client).await?;
        if ids.is_empty() {
            return Ok(Some(RelatedFetch {
                field: field.to_string(),
                relation_type: relation.relation_type,
                by_id: IndexMap::new(),
                target,
            }));
        }
        let Some(target) = target else { return Ok(None) };
        let condition = FilterCondition::new("_id", FilterOperator::In, None)
            .with_multi_value(ids.iter().map(|i| Value::String(i.clone())).collect());
        let mut query = Query::default().with_condition(condition);
        query.size = ids.len() as i32;
        let objects = self
            .generic(Some(&target), Gate::Read, |s| async {
                Ok(backend.engine.read_page_rows(&ctx(), client, backend.conn(), s, &query).await?)
            })
            .await?;
        let mut by_id = IndexMap::new();
        for o in objects {
            if let Some(id) = o.get("_id").filter(|v| !v.is_null()) {
                by_id.insert(id.java_string(), o);
            }
        }
        Ok(Some(RelatedFetch { field: field.to_string(), relation_type: relation.relation_type, by_id, target: Some(target) }))
    }

    // ------------------------------------------------------------------ delete

    pub fn delete<'a>(
        &'a self,
        app_code: Option<&'a str>,
        client_code: Option<&'a str>,
        storage_name: &'a str,
        id: &'a str,
        delete_version: Option<bool>,
    ) -> BoxFuture<'a, CoreResult<bool>> {
        async move {
            let t = self.target(app_code, client_code, storage_name).await?;
            self.generic(t.storage.as_ref(), Gate::Delete, |s| async {
                self.delete_related_objects(&t.app, &t.client, &t.backend, s, id, delete_version).await?;
                let (deleted, existing) = self.delete_with_triggers(&t.app, &t.client, &t.backend, s, id, delete_version).await?;
                let Some(existing) = existing else { return Ok(deleted) };
                self.generate_event(&t.app, &t.client, s, "Delete", existing, None).await?;
                Ok(deleted)
            })
            .await
        }
        .boxed()
    }

    async fn delete_with_triggers(
        &self,
        app: &str,
        client: &str,
        backend: &Backend,
        storage: &Storage,
        id: &str,
        delete_version: Option<bool>,
    ) -> FlowResult<(bool, Option<Document>)> {
        let before = triggers_of(storage, "BEFORE_DELETE");
        let after = triggers_of(storage, "AFTER_DELETE");
        let events = storage.generate_events == Some(true);
        if before.is_empty() && after.is_empty() && !events {
            let deleted = backend.engine.delete(&ctx(), client, backend.conn(), storage, id, delete_version).await?;
            return Ok((deleted, None));
        }
        let existing = self.read(Some(app), Some(client), &storage.name, id, Some(false), Some(Vec::new())).await?;
        if !before.is_empty() {
            self.execute_triggers(storage, &before, vec![(DATA_OBJECT_KEY, gson_value(&existing)?)]).await?;
        }
        let deleted = backend.engine.delete(&ctx(), client, backend.conn(), storage, id, delete_version).await?;
        if !after.is_empty() {
            self.execute_triggers(storage, &after, vec![(DATA_OBJECT_KEY, gson_value(&existing)?)]).await?;
        }
        Ok((deleted, Some(existing)))
    }

    /// `deleteRelatedObjects`: the constraints that point AT this row, before it goes.
    async fn delete_related_objects(
        &self,
        app: &str,
        client: &str,
        backend: &Backend,
        storage: &Storage,
        id: &str,
        delete_version: Option<bool>,
    ) -> CoreResult<()> {
        let names = self.defs.storages_referencing(app, &storage.name).await?;
        if names.is_empty() {
            return Ok(());
        }
        let mut relations = Vec::new();
        for name in names {
            let Some(child) = self.defs.storage(&name, app, client).await? else { continue };
            for r in declared_relations(&child, &storage.name) {
                let enforced = backend
                    .engine
                    .enforces_relation_constraint(&ctx(), client, backend.conn(), &r.child, &r.field, &r.relation)
                    .await?;
                if !enforced {
                    relations.push(r);
                }
            }
        }
        self.apply_constraints(app, client, backend, relations, id, delete_version).await
    }

    /// `applyConstraints`: every RESTRICT counted before any CASCADE deletes anything.
    async fn apply_constraints(
        &self,
        app: &str,
        client: &str,
        backend: &Backend,
        relations: Vec<ReferencingRelation>,
        id: &str,
        delete_version: Option<bool>,
    ) -> CoreResult<()> {
        if relations.is_empty() {
            return Ok(());
        }
        let mut blocking = Vec::new();
        for r in relations.iter().filter(|r| r.constraint() == Some(RelationConstraint::Restrict)) {
            let count = backend.engine.count_referencing(&ctx(), client, backend.conn(), &r.child, &r.field, r.many(), id).await?;
            if count > 0 {
                blocking.push(format!("{}.{} ({count})", r.child.name, r.field));
            }
        }
        if !blocking.is_empty() {
            return Err(CoreError::msg(
                StatusCode::BAD_REQUEST,
                msg::CANNOT_DELETE_STORAGE_WITH_RESTRICT,
                &[&format!("[{}]", blocking.join(", "))],
            )
            .param("objects", blocking.join(", ")));
        }
        let cascade: Vec<ReferencingRelation> =
            relations.into_iter().filter(|r| r.constraint() == Some(RelationConstraint::Cascade)).collect();
        self.cascades_allowed(&cascade)?;
        for r in &cascade {
            self.cascade_delete(app, client, backend, r, id, delete_version).await?;
        }
        Ok(())
    }

    /// `cascadesAllowed`: the caller may delete from every child storage a cascade reaches.
    fn cascades_allowed(&self, cascade: &[ReferencingRelation]) -> CoreResult<()> {
        let mut by_name: IndexMap<&str, &Storage> = IndexMap::new();
        for r in cascade {
            by_name.entry(r.child.name.as_str()).or_insert(&r.child);
        }
        let mut refused = Vec::new();
        for (name, child) in by_name {
            if !has_authority(child.delete_auth.as_deref())? {
                refused.push(name);
            }
        }
        if refused.is_empty() {
            Ok(())
        } else {
            Err(forbidden(msg::FORBIDDEN_DELETE_STORAGE, &refused.join(", ")).with_code("CORE.CASCADE_DELETE_FORBIDDEN").param("storages", refused.join(", ")))
        }
    }

    /// `cascadeDelete`: the referencing rows in batches, each through the ordinary delete.
    async fn cascade_delete(
        &self,
        app: &str,
        client: &str,
        backend: &Backend,
        r: &ReferencingRelation,
        id: &str,
        delete_version: Option<bool>,
    ) -> CoreResult<()> {
        loop {
            let depth = cascade_depth();
            if depth >= MAX_CASCADE_DEPTH {
                return Err(CoreError::msg_as(
                    StatusCode::BAD_REQUEST,
                    msg::CANNOT_DELETE_STORAGE_WITH_RESTRICT,
                    "CORE.CASCADE_TOO_DEEP",
                    &[&format!(
                        "[{}.{} (cascade deeper than {MAX_CASCADE_DEPTH}, the relations point at each other)]",
                        r.child.name, r.field
                    )],
                )
                .param("objects", format!("{}.{}", r.child.name, r.field)));
            }
            let ids = backend
                .engine
                .ids_referencing(&ctx(), client, backend.conn(), &r.child, &r.field, r.many(), id, CASCADE_BATCH)
                .await?;
            if ids.is_empty() {
                return Ok(());
            }
            let n = ids.len() as i64;
            CASCADE_DEPTH
                .scope(depth + 1, async {
                    for child_id in &ids {
                        self.delete(Some(app), Some(client), &r.child.name, child_id, delete_version).await?;
                    }
                    Ok::<_, CoreError>(())
                })
                .await?;
            if n < CASCADE_BATCH {
                return Ok(());
            }
        }
    }

    pub async fn delete_by_filter(
        &self,
        app_code: Option<&str>,
        client_code: Option<&str>,
        storage_name: &str,
        query: &Query,
        dev_mode: Option<bool>,
        delete_version: Option<bool>,
    ) -> CoreResult<i64> {
        let t = self.target(app_code, client_code, storage_name).await?;
        self.generic(t.storage.as_ref(), Gate::Delete, |s| async {
            Ok(t.backend.engine.delete_by_filter(&ctx(), &t.client, t.backend.conn(), s, query, dev_mode, delete_version).await?)
        })
        .await
    }

    pub async fn delete_storage(&self, app_code: Option<&str>, client_code: Option<&str>, storage_name: &str) -> CoreResult<bool> {
        let t = self.target(app_code, client_code, storage_name).await?;
        self.generic(t.storage.as_ref(), Gate::Delete, |s| async {
            Ok(t.backend.engine.delete_storage(&ctx(), &t.client, t.backend.conn(), s).await?)
        })
        .await
    }

    // ------------------------------------------------------------------ builder operations

    /// `clearAllRows`: every row, the history kept; the storage's deleteAuth or write access
    /// to the app.
    pub async fn clear_all_rows(&self, app_code: Option<&str>, client_code: Option<&str>, storage_name: &str, dry_run: Option<bool>)
        -> CoreResult<i64> {
        let t = self.target(app_code, client_code, storage_name).await?;
        let Some(s) = t.storage.as_ref() else {
            return Err(CoreError::msg(StatusCode::NOT_FOUND, msg::STORAGE_NOT_FOUND, &[]));
        };
        let allowed = has_authority(s.delete_auth.as_deref())? || self.has_write_access(&t.app).await?;
        if !allowed {
            return Err(gate_refusal(msg::FORBIDDEN_DELETE_STORAGE, &s.name));
        }
        match t.backend.engine.delete_by_filter(&ctx(), &t.client, t.backend.conn(), s, &Query::default(), dry_run, None).await {
            Ok(n) => Ok(n),
            Err(AppDataError::Empty) => Err(CoreError::unknown("the operation produced nothing")),
            Err(e) => Err(e.into()),
        }
    }

    /// `copyLiveDataToDraft`: write access to the app; zero rows is a bad request.
    pub async fn copy_live_data_to_draft(&self, app_code: Option<&str>, client_code: Option<&str>, storage_name: &str, replace: Option<bool>)
        -> CoreResult<i64> {
        let app = Self::app_code(app_code);
        let client = self.client_code(client_code).await?;
        self.can_write_app(&app).await?;
        let backend = self.backend(&app, &client).await?;
        let Some(storage) = self.storage_with_kirun_validation(storage_name, &app, &client).await? else {
            return Err(CoreError::unknown(
                "Cannot invoke \"com.fincity.saas.commons.core.document.Storage.getAppCode()\" because \"storage\" is null",
            ));
        };
        let copied = backend.engine.copy_live_to_draft(&ctx(), &client, backend.conn(), &storage, replace).await?;
        if copied < 1 {
            return Err(CoreError::msg(StatusCode::BAD_REQUEST, msg::DRAFT_COPY_SOURCE_EMPTY, &[storage_name]));
        }
        Ok(copied)
    }

    /// `clearDraftData`: every storage's draft rows for one app and tenant, by name, the
    /// storages that had any.
    pub async fn clear_draft_data(&self, app_code: Option<&str>, client_code: Option<&str>) -> CoreResult<IndexMap<String, i64>> {
        let app = Self::app_code(app_code);
        let client = self.client_code(client_code).await?;
        self.can_write_app(&app).await?;
        let backend = self.backend(&app, &client).await?;
        let storages = self.app_storages(&app, &client).await?;
        let mut out = IndexMap::new();
        for s in storages.values() {
            let n = backend.engine.clear_draft_rows(&ctx(), &client, backend.conn(), s).await?;
            if n > 0 {
                out.insert(s.name.clone(), n);
            }
        }
        Ok(out)
    }

    /// `copyAppToDraft`: the app's live rows into its draft, storage by storage, followed
    /// storages first.
    pub async fn copy_app_to_draft(&self, app_code: Option<&str>, client_code: Option<&str>, filters: IndexMap<String, DraftCopyFilter>)
        -> CoreResult<IndexMap<String, i64>> {
        let app = Self::app_code(app_code);
        let client = self.client_code(client_code).await?;
        self.can_write_app(&app).await?;
        let backend = self.backend(&app, &client).await?;
        let storages = self.app_storages(&app, &client).await?;
        let order = draft_copy_order(&storages, &filters)?;
        let followed: HashMap<String, Storage> = storages.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        let mut out = IndexMap::new();
        for s in order {
            let n = backend
                .engine
                .copy_live_to_draft_filtered(&ctx(), &client, backend.conn(), &s, filters.get(&s.name), &followed)
                .await?;
            out.insert(s.name.clone(), n);
        }
        Ok(out)
    }

    /// `appStorages`: the app's storages as this tenant resolves them, by name; one it does
    /// not resolve (404) or may not use (403) is left out.
    async fn app_storages(&self, app: &str, client: &str) -> CoreResult<IndexMap<String, Storage>> {
        let mut out = IndexMap::new();
        for name in self.defs.storage_names(app).await? {
            match self.storage_with_kirun_validation(&name, app, client).await {
                Ok(Some(s)) => {
                    out.insert(s.name.clone(), s);
                }
                Ok(None) => {}
                Err(e) if not_found_or_forbidden(&e) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    /// `migrationStatus`: readAuth; on MySQL the engine's journal and issues, one row per tenant
    /// schema of a client the caller may see (its own, and the ones it manages). Built with
    /// `flatMapMono`, so an app with no appData connection (every Mongo app), or a storage that
    /// does not resolve, completes empty (`None`): a 200 with no body.
    pub async fn migration_status(&self, app_code: Option<&str>, client_code: Option<&str>, storage_name: &str)
        -> CoreResult<Option<Vec<TenantProgress>>> {
        let app = Self::app_code(app_code);
        let client = self.client_code(client_code).await?;
        let Some(conn) = self.defs.connection(CONNECTION_NAME, &app, &client, CONNECTION_TYPE).await? else {
            return Ok(None);
        };
        let Some(storage) = self.storage_with_kirun_validation(storage_name, &app, &client).await? else {
            return Ok(None);
        };
        self.generic(Some(&storage), Gate::Read, |s| async {
            if conn.connection_sub_type == Some(appdata::model::ConnectionSubType::MySql) {
                let tenants = self.engines.mysql_admin.migration_tenants(&conn, &app, s).await?;
                let visible = self.visible_tenants(&app, tenants).await?;
                Ok(Some(self.engines.mysql_admin.migration_status_of(&conn, &app, s, &visible).await?))
            } else {
                Ok(Some(Vec::new()))
            }
        })
        .await
    }

    /// Of these tenant schemas, the ones whose client the caller may see: its own client and the
    /// clients it manages (one call to security for all of them).
    async fn visible_tenants(&self, app: &str, tenants: Vec<String>) -> CoreResult<Vec<String>> {
        let own = context::authentication().client_code().unwrap_or_default().to_string();
        let mut codes: Vec<String> = tenants.iter().map(|d| appdata::mysql::service::client_code_of(d, app)).collect();
        codes.sort();
        codes.dedup();
        codes.retain(|c| *c != own);
        let managed: std::collections::HashSet<String> =
            self.security.filter_managed_client_codes(&own, &codes).await.map_err(CoreError::from)?.into_iter().collect();
        Ok(tenants
            .into_iter()
            .filter(|d| {
                let c = appdata::mysql::service::client_code_of(d, app);
                c == own || managed.contains(&c)
            })
            .collect())
    }

    /// `drift`: write access to the app; every MySQL server the app uses.
    pub async fn drift(&self, app_code: Option<&str>, client_code: Option<&str>, storage_name: &str) -> CoreResult<Vec<Report>> {
        let app = Self::app_code(app_code);
        let client = self.client_code(client_code).await?;
        self.builder_only(&app).await?;
        let Some(storage) = self.storage_with_kirun_validation(storage_name, &app, &client).await? else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        for conn in self.defs.all_app_data("MYSQL", &app).await? {
            out.extend(self.engines.mysql_admin.drift(&conn, &app, &storage).await?);
        }
        Ok(out)
    }

    pub async fn repair_drift(&self, app_code: Option<&str>, client_code: Option<&str>, storage_name: &str, approved: bool)
        -> CoreResult<Vec<DriftRepair>> {
        let app = Self::app_code(app_code);
        let client = self.client_code(client_code).await?;
        self.builder_only(&app).await?;
        let Some(storage) = self.storage_with_kirun_validation(storage_name, &app, &client).await? else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        for conn in self.defs.all_app_data("MYSQL", &app).await? {
            out.extend(self.engines.mysql_admin.repair_drift(&conn, &app, &storage, approved).await?);
        }
        Ok(out)
    }

    // ------------------------------------------------------------------ files

    /// The schema of a storage for headers, KIRun's shape (`storageService.getSchema`).
    pub fn storage_schema(storage: &Storage) -> CoreResult<Option<kirun::json::schema::Schema>> {
        super::validator::kirun_schema(storage).map_err(CoreError::unknown)
    }

    /// `downloadTemplate(appCode, clientCode, storage, type)`: the raw codes (no resolution),
    /// the storage's createAuth.
    pub async fn template_storage(&self, app_code: &str, client_code: &str, storage_name: &str) -> CoreResult<Storage> {
        let conn = self.defs.raw_connection(CONNECTION_NAME, app_code, client_code).await?;
        self.engines.for_connection(conn.as_ref())?;
        let storage = self.storage_with_kirun_validation(storage_name, app_code, client_code).await?;
        self.generic(storage.as_ref(), Gate::Create, |s| async { Ok(s.clone()) }).await
    }

    /// `uploadData`: createAuth, the rows straight to the engine (no relations, triggers or
    /// events), in file order.
    pub async fn upload_rows(
        &self,
        app_code: Option<&str>,
        client_code: Option<&str>,
        storage_name: &str,
        rows: impl FnOnce(&Storage) -> BoxFuture<'static, CoreResult<Option<Vec<Document>>>>,
        file_type: &str,
    ) -> CoreResult<bool> {
        let t = self.target(app_code, client_code, storage_name).await?;
        self.generic(t.storage.as_ref(), Gate::Create, |s| async {
            let Some(rows) = rows(s).await? else {
                return Err(Flow::Fail(CoreError::msg(StatusCode::BAD_REQUEST, msg::NOT_ABLE_TO_READ_FILE_FORMAT, &[file_type])));
            };
            for row in rows {
                t.backend.engine.create(&ctx(), &t.client, t.backend.conn(), s, DataObject::of(row)).await?;
            }
            Ok(true)
        })
        .await
    }

    /// The schemas a storage's references resolve against besides KIRun's: core's and the
    /// app's.
    pub async fn schema_source(&self, storage: &Storage) -> CoreResult<Arc<dyn crate::repos::SchemaSource>> {
        self.defs.schema_source(&storage.app_code, &storage.client_code).await
    }
}

/// A create of no data: the engine's `gson.toJsonTree(null).getAsJsonObject()` fails.
fn no_null_data(data: DataObject) -> CoreResult<DataObject> {
    if data.data.is_none() {
        return Err(CoreError::unknown("Not a JSON Object: null"));
    }
    Ok(data)
}

/// An update of no data: the engine reads the row's `_id` from it.
fn no_null_update(data: DataObject) -> CoreResult<DataObject> {
    if data.data.is_none() {
        return Err(CoreError::unknown(
            "Cannot invoke \"java.util.Map.get(Object)\" because the return value of \"com.fincity.saas.commons.core.model.DataObject.getData()\" is null",
        ));
    }
    Ok(data)
}

/// A storage schema (Gson form) with its top-level `ref` chain followed, as
/// `SchemaRefResolver` follows it (at most [`appdata::schema_refs::MAX_DEPTH`] hops, a repeat
/// stops), and the properties written beside the ref merged over the referenced ones. A ref
/// that names no schema is refused rather than read as a storage with no fields.
async fn follow_schema_ref(
    raw: &serde_json::Value,
    schemas: &dyn crate::repos::SchemaSource,
    storage: &str,
) -> CoreResult<serde_json::Value> {
    fn reference(s: &serde_json::Value) -> Option<String> {
        s.get("ref").and_then(serde_json::Value::as_str).map(str::trim).filter(|r| !r.is_empty()).map(str::to_string)
    }
    let mut current = raw.clone();
    let mut seen = IndexSet::new();
    let mut depth = 0;
    while let Some(r) = reference(&current) {
        if depth >= appdata::schema_refs::MAX_DEPTH || !seen.insert(r.clone()) {
            break;
        }
        let Some(resolved) = schema_json_from_ref(&current, schemas, &r).await? else {
            return Err(CoreError::coded(
                StatusCode::NOT_FOUND,
                "CORE.STORAGE_SCHEMA_REF_NOT_FOUND",
                format!("Schema {r} referenced by storage {storage} not found"),
            )
            .param("schema", &r)
            .param("storage", storage));
        };
        let again = reference(&resolved).is_some() && resolved != current;
        current = resolved;
        if !again {
            break;
        }
        depth += 1;
    }
    if current == *raw {
        return Ok(current);
    }
    if let Some(serde_json::Value::Object(local)) = raw.get("properties").filter(|p| p.as_object().is_some_and(|p| !p.is_empty())) {
        let mut merged = match current.get("properties") {
            Some(serde_json::Value::Object(p)) => p.clone(),
            _ => serde_json::Map::new(),
        };
        for (k, v) in local {
            merged.insert(k.clone(), v.clone());
        }
        if let serde_json::Value::Object(c) = &mut current {
            c.insert("properties".into(), serde_json::Value::Object(merged));
        }
    }
    Ok(current)
}

/// `ReactiveSchemaUtil.getSchemaFromRef` on Gson-form JSON: `Namespace.Name` from the schemas
/// (a `#` ref is the schema itself), then a `/` path through `$defs` and properties.
async fn schema_json_from_ref(
    current: &serde_json::Value,
    schemas: &dyn crate::repos::SchemaSource,
    reference: &str,
) -> CoreResult<Option<serde_json::Value>> {
    let parts: Vec<&str> = reference.split('/').collect();
    let mut s = if reference.starts_with('#') {
        current.clone()
    } else {
        let full = parts[0];
        let Some(dot) = full.rfind('.') else { return Ok(None) };
        let (ns, name) = (&full[..dot], &full[dot + 1..]);
        if ns.is_empty() || name.is_empty() {
            return Ok(None);
        }
        match schemas.find(Some(ns), name).await? {
            Some(f) => f.json.clone(),
            None => return Ok(None),
        }
    };
    let mut i = 1;
    while i < parts.len() {
        let next = if parts[i] == "$defs" {
            i += 1;
            parts.get(i).and_then(|p| s.get("$defs")?.get(*p))
        } else {
            s.get("properties").and_then(|p| p.get(parts[i]))
        };
        let Some(next) = next.cloned() else { return Ok(None) };
        s = next;
        i += 1;
    }
    Ok(Some(s))
}

/// `gson.toJsonTree(row)`.
fn gson_value(row: &Document) -> CoreResult<serde_json::Value> {
    Ok(serde_json::Value::Object(gson_object(row)?))
}

/// An ObjectId as the engines hand it over: Jackson's bean of it.
fn is_object_id_bean(v: &Value) -> bool {
    v.as_object().is_some_and(|o| o.len() == 2 && o.contains_key("timestamp") && o.contains_key("date"))
}

fn triggers_of(storage: &Storage, kind: &str) -> Vec<String> {
    storage.triggers.as_ref().and_then(|t| t.get(kind)).cloned().unwrap_or_default()
}

/// `resolveEagerFields`: what the caller named, else every relation when it said `eager`.
pub fn resolve_eager_fields(storage: &Storage, eager: Option<bool>, eager_fields: Option<&[String]>) -> Option<Vec<String>> {
    if let Some(f) = eager_fields.filter(|f| !f.is_empty()) {
        return Some(f.to_vec());
    }
    if eager != Some(true) {
        return eager_fields.map(<[String]>::to_vec);
    }
    Some(storage.relation_keys())
}

/// `convertForeignKeyValuesToObjects`.
fn convert_foreign_key_values(v: &Value, relation: &StorageRelation) -> Vec<Document> {
    let id_map = |id: String| {
        let mut d = Document::new();
        d.insert("_id".into(), Value::String(id));
        d
    };
    if relation.relation_type == Some(RelationType::ToMany) {
        match v {
            Value::Array(a) => a
                .iter()
                .map(|e| match e {
                    Value::Object(o) => o.clone(),
                    other => id_map(other.java_string()),
                })
                .collect(),
            Value::String(ids) => java_split_commas(ids).into_iter().map(|s| id_map(s.trim().to_string())).collect(),
            _ => Vec::new(),
        }
    } else {
        match v {
            Value::Object(o) => vec![o.clone()],
            other => vec![id_map(other.java_string())],
        }
    }
}

/// `String.split(",")`: trailing empty parts dropped, an empty string is one empty part.
pub fn java_split_commas(s: &str) -> Vec<String> {
    if s.is_empty() {
        return vec![String::new()];
    }
    let mut parts: Vec<String> = s.split(',').map(str::to_string).collect();
    while parts.len() > 1 && parts.last().is_some_and(String::is_empty) {
        parts.pop();
    }
    if parts.len() == 1 && parts[0].is_empty() && !s.is_empty() {
        return Vec::new();
    }
    parts
}

/// `Collectors.groupingBy(getFieldName)`: the ids by field.
fn grouped(list: &[RelationDataObject]) -> Vec<(String, Vec<String>)> {
    let mut map: IndexMap<String, Vec<String>> = IndexMap::new();
    for r in list {
        map.entry(r.field_name.clone()).or_default().push(r.id.clone().unwrap_or_default());
    }
    map.into_iter().collect()
}

fn collect_ids(value: Option<&Value>, into: &mut IndexSet<String>) {
    match value {
        None | Some(Value::Null) => {}
        Some(Value::Array(a)) => {
            for o in a.iter().filter(|o| !o.is_null()) {
                into.insert(o.java_string());
            }
        }
        Some(v) => {
            into.insert(v.java_string());
        }
    }
}

/// `applyRelated`: each row's ids replaced by the objects, in the row's own order; an id with
/// no object dropped.
fn apply_related(rows: &mut [Document], field: &str, relation_type: Option<RelationType>, by_id: &IndexMap<String, Document>) {
    for row in rows.iter_mut() {
        let Some(value) = row.get(field).filter(|v| !v.is_null()).cloned() else { continue };
        if relation_type == Some(RelationType::ToMany) {
            let declared = match value {
                Value::Array(a) => a,
                other => vec![other],
            };
            let objects: Vec<Value> = declared
                .iter()
                .filter(|v| !v.is_null())
                .filter_map(|id| by_id.get(&id.java_string()).cloned().map(Value::Object))
                .collect();
            row.insert(field.to_string(), Value::Array(objects));
            continue;
        }
        match by_id.get(&value.java_string()) {
            None => {
                row.shift_remove(field);
            }
            Some(o) => {
                row.insert(field.to_string(), Value::Object(o.clone()));
            }
        }
    }
}

/// `declaredRelations`: the child's relations to the target that ask for something on delete.
fn declared_relations(child: &Storage, target: &str) -> Vec<ReferencingRelation> {
    let Some(relations) = &child.relations else { return Vec::new() };
    relations
        .iter()
        .filter(|(_, r)| r.storage_name.as_deref() == Some(target))
        .filter(|(_, r)| r.delete_constraint.is_some_and(|c| c != RelationConstraint::Nothing))
        .map(|(f, r)| ReferencingRelation { child: child.clone(), field: f.clone(), relation: r.clone() })
        .collect()
}

/// `draftCopyOrder`: unfiltered and condition-only storages first, then each follower after
/// the storages it follows.
pub fn draft_copy_order(storages: &IndexMap<String, Storage>, filters: &IndexMap<String, DraftCopyFilter>) -> CoreResult<Vec<Storage>> {
    let unsupported = |reason: String| CoreError::msg(StatusCode::BAD_REQUEST, msg::UNSUPPORTED_CONDITION, &[&reason]);
    for (name, f) in filters {
        if !storages.contains_key(name) {
            return Err(unsupported(format!("no storage named {name} in this app")));
        }
        if !f.has_follow() {
            continue;
        }
        for follow in f.follow.as_deref().unwrap_or_default() {
            if follow.field.trim().is_empty() || !storages.contains_key(&follow.storage) {
                return Err(unsupported(format!("{name} follows {}.{}, which is not there", follow.storage, follow.field)));
            }
        }
    }
    let mut order = Vec::new();
    let mut placed: IndexSet<String> = IndexSet::new();
    for s in storages.values() {
        if filters.get(&s.name).is_none_or(|f| !f.has_follow()) {
            order.push(s.clone());
            placed.insert(s.name.clone());
        }
    }
    let mut waiting: Vec<String> = storages.keys().filter(|n| !placed.contains(*n)).cloned().collect();
    while !waiting.is_empty() {
        let ready: Vec<String> = waiting
            .iter()
            .filter(|n| {
                filters[*n]
                    .follow
                    .as_deref()
                    .unwrap_or_default()
                    .iter()
                    .all(|f| placed.contains(&f.storage) && f.storage != **n)
            })
            .cloned()
            .collect();
        if ready.is_empty() {
            return Err(unsupported(format!("these storages follow each other: [{}]", waiting.join(", "))));
        }
        for n in &ready {
            order.push(storages[n].clone());
            placed.insert(n.clone());
        }
        waiting.retain(|n| !ready.contains(n));
    }
    Ok(order)
}

#[path = "batch.rs"]
mod batch;
pub use batch::{conflict_of, BatchConflict, BatchOp, BatchOutcome, ConflictKind, NamedOp, OnConflict, UpdateIfOutcome};

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
