//! The core document kinds on the overridable write path: what `CoreFunctionService`,
//! `CoreSchemaService`, `StorageService`, `ConnectionService`, `TemplateService`,
//! `NotificationService`, `EventDefinitionService`, `EventActionService`,
//! `WorkflowService`, `ActionService` and `CoreFillerService` add to
//! `AbstractOverridableDataService`.
//!
//! Every core object is draftable. The evictions beyond the base class's are Storage's (the
//! index and table creation caches, the schema caches, the reference index, the tables
//! rebuilt) and Schema's (the storages standing on it rebuilt); the read caches core-exec,
//! core-scheduler and core-events keep are the base class's names, which the base evicts.

use std::sync::Arc;

use async_trait::async_trait;
use axum::http::StatusCode;
use overridable::pojo::{map_field, str_field, Pojo};
use overridable::write::filler::Filler;
use overridable::write::kind::Kind;
use overridable::write::messages::{self as msg, Messages};
use overridable::write::Commons;
use overridable::{DocType, JMap, JValue};
use platform::error::{AppError, AppResult};
use platform::security::ContextAuthentication;

use crate::docs::{ConnectionDoc, EventActionDoc, EventDefinitionDoc, FunctionDoc, SchemaDoc, StorageDoc, TemplateDoc};
use crate::editor::beans::{self, T};
use crate::editor::docs::{self as edocs, ActionDoc, NotificationDoc, WorkflowDoc};
use crate::editor::storage::StorageOps;

/// core's own message ids (`CoreMessageResourceService`).
pub const STORAGE_IS_APP_LEVEL: &str = "storage_is_app_level";
pub const INVALID_STORAGE_SCHEMA: &str = "invalid_storage_schema";
pub const STORAGE_SCHEMA_ALWAYS_OBJECT: &str = "storage_schema_always_object";
pub const INVALID_COLUMN_DEFINITION: &str = "invalid_column_definition";
pub const STORAGE_SCHEMA_FIELD_ALREADY_EXISTS: &str = "storage_schema_field_already_exists";
pub const NO_STORAGE_FOUND_WITH_NAME: &str = "no_storage_found_with_name";
pub const WORKFLOW_TRIGGER_MISSING: &str = "workflow_trigger_missing";
pub const CONNECTION_REFUSED_TARGET: &str = "connection_refused_target";

/// core's `messages_en.properties`: the commons ones and the ones these services raise.
pub fn core_messages() -> Messages {
    crate::catalogue::register();
    let mut m = Messages::core();
    m.add_namespace(crate::catalogue::NS);
    for (k, v) in [
        (STORAGE_IS_APP_LEVEL, "Cannot change a storage which is app level."),
        (INVALID_STORAGE_SCHEMA, "The storage schema is not valid. $"),
        (STORAGE_SCHEMA_ALWAYS_OBJECT, "Storage schema should always be of type Object"),
        (INVALID_COLUMN_DEFINITION, "Invalid column definition. $"),
        (STORAGE_SCHEMA_FIELD_ALREADY_EXISTS, "Storage schema field $ already exists"),
        (NO_STORAGE_FOUND_WITH_NAME, "No storage found with name $"),
        (WORKFLOW_TRIGGER_MISSING, "Workflow trigger is missing"),
        (msg::OBJECT_NOT_UPDATABLE, "Cannot update this object"),
    ] {
        m.set(k, v);
    }
    m
}

/// core's `VersionService.mapAuthName`, and the three core object types it has none for: the
/// filler (guarded by the application's authorities), notifications and workflows. Java checks
/// version reads by these names in `GET /versions/{id}` only; with every version read checked
/// (see `DIFFERENCES.md`), leaving them out would hide their history from everyone.
pub const EDITOR_AUTH_NAMES: &[(&str, &str)] = &[
    ("ACTION", "Action"),
    ("CONNECTION", "Connection"),
    ("FUNCTION", "Function"),
    ("SCHEMA", "Schema"),
    ("EVENTACTION", "EventAction"),
    ("EVENTDEFINITION", "EventDefinition"),
    ("STORAGE", "Storage"),
    ("TEMPLATE", "Template"),
    ("FILLER", "Application"),
    ("NOTIFICATION", "Notification"),
    ("WORKFLOW", "Workflow"),
];

/// The core document classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreObject {
    Function,
    Schema,
    Storage,
    Connection,
    Template,
    Notification,
    EventDefinition,
    EventAction,
    Workflow,
    Action,
}

impl CoreObject {
    pub fn doc(&self) -> &'static dyn DocType {
        match self {
            CoreObject::Function => &FunctionDoc,
            CoreObject::Schema => &SchemaDoc,
            CoreObject::Storage => &StorageDoc,
            CoreObject::Connection => &ConnectionDoc,
            CoreObject::Template => &TemplateDoc,
            CoreObject::Notification => &NotificationDoc,
            CoreObject::EventDefinition => &EventDefinitionDoc,
            CoreObject::EventAction => &EventActionDoc,
            CoreObject::Workflow => &WorkflowDoc,
            CoreObject::Action => &ActionDoc,
        }
    }

    /// `extractDifference` of the class.
    fn extract(&self, this: JMap, base: &JMap) -> Option<JMap> {
        match self {
            CoreObject::Function => edocs::function(this, base),
            CoreObject::Schema => edocs::schema(this, base),
            CoreObject::Storage => edocs::storage(this, base),
            CoreObject::Connection => edocs::connection(this, base),
            CoreObject::Template => edocs::template(this, base),
            CoreObject::Notification => edocs::notification(this, base),
            CoreObject::EventDefinition => edocs::event_definition(this, base),
            CoreObject::EventAction => edocs::event_action(this, base),
            CoreObject::Workflow | CoreObject::Action => self.doc().extract_difference(this, base),
        }
    }

    /// The fields read into nested classes rather than taken as they are.
    pub fn typed_fields(&self) -> &'static [(&'static str, T)] {
        match self {
            CoreObject::Storage => &[
                ("relations", T::MapOf(&T::Bean(&beans::STORAGE_RELATION))),
                ("triggers", T::EnumMapOf(beans::TRIGGER_TYPES, &T::ListOf(&T::Str))),
                ("indexes", T::MapOf(&T::Bean(&beans::STORAGE_INDEX))),
                ("columnDefinitions", T::MapOf(&T::Bean(&beans::COLUMN_DEFINITION))),
                ("textIndexFields", T::ListOf(&T::Str)),
            ],
            CoreObject::EventDefinition => &[("schedule", T::Bean(&beans::EVENT_SCHEDULE))],
            CoreObject::EventAction => &[("tasks", T::MapOf(&T::Bean(&beans::EVENT_ACTION_TASK)))],
            CoreObject::Notification => &[
                ("notificationType", T::Enum(beans::NOTIFICATION_TYPES)),
                ("channelTemplates", T::MapOf(&T::Bean(&beans::NOTIFICATION_TEMPLATE))),
            ],
            CoreObject::Workflow => &[("trigger", T::Bean(&beans::TRIGGER_STEP))],
            CoreObject::Connection => &[
                ("connectionType", T::Enum(beans::CONNECTION_TYPES)),
                ("connectionSubType", T::Enum(beans::CONNECTION_SUB_TYPES)),
            ],
            _ => &[],
        }
    }

    /// The fields `updatableEntity` copies from the request.
    fn updatable(&self) -> &'static [&'static str] {
        match self {
            CoreObject::Template => &[
                "templateParts",
                "resources",
                "defaultLanguage",
                "templateType",
                "toExpression",
                "fromExpression",
                "languageExpression",
                "variableSchema",
                "sampleData",
                "design",
            ],
            CoreObject::Notification => &[
                "notificationType",
                "defaultLanguage",
                "languageExpression",
                "variableSchema",
                "channelTemplates",
                "channelConnections",
                "channelEnabled",
            ],
            CoreObject::EventDefinition => &["schema", "schedule"],
            CoreObject::EventAction => &["tasks"],
            CoreObject::Action => &["functionName", "functionNamespace", "properties"],
            CoreObject::Connection => &["connectionSubType", "connectionDetails", "isAppLevel", "onlyThruKIRun"],
            _ => &[],
        }
    }
}

/// One core document kind.
pub struct CoreKind {
    pub object: CoreObject,
    pub storage: Arc<StorageOps>,
}

impl CoreKind {
    pub fn new(object: CoreObject, storage: Arc<StorageOps>) -> Self {
        Self { object, storage }
    }
}

impl DocType for CoreKind {
    fn object_name(&self) -> &'static str {
        self.object.doc().object_name()
    }
    fn collection(&self) -> &'static str {
        self.object.doc().collection()
    }
    fn pojo(&self) -> &'static Pojo {
        match self.object {
            // `Boolean isAppLevel = FALSE, onlyThruKIRun = FALSE`: written, and read back, as false.
            CoreObject::Connection => &edocs::CONNECTION,
            _ => self.object.doc().pojo(),
        }
    }
    fn cache_name(&self, app_code: &str, name: &str) -> String {
        self.object.doc().cache_name(app_code, name)
    }
    fn draftable(&self) -> bool {
        true
    }
    fn apply_override(&self, this: JMap, base: &JMap) -> Option<JMap> {
        self.object.doc().apply_override(this, base)
    }
    fn extract_difference(&self, this: JMap, base: &JMap) -> Option<JMap> {
        self.object.extract(this, base)
    }
}

fn safe_value_of(v: Option<&JValue>) -> Option<String> {
    v.filter(|x| !x.is_null()).map(JValue::java_to_string)
}

fn npe(what: &str) -> AppError {
    AppError::Internal(anyhow::anyhow!("NullPointerException: {what}"))
}

/// `namespace.name` from a function's or schema's definition; `Err` for a null definition
/// (Java's `NullPointerException`).
fn definition_name(e: &JMap) -> Result<Option<String>, AppError> {
    let def = match e.get("definition") {
        Some(JValue::Object(d)) => d,
        _ => return Err(npe("definition")),
    };
    Ok(match (safe_value_of(def.get("namespace")), safe_value_of(def.get("name"))) {
        (Some(ns), Some(n)) => Some(format!("{ns}.{n}")),
        _ => None,
    })
}

/// `AbstractFunctionService.updatedFunctionName`: the same rule as a schema's. An update of a
/// client's function copy arrives as its difference from the base, without the name parts it
/// did not change.
pub fn updated_function_name(entity: &JMap, existing: &JMap) -> Option<String> {
    updated_schema_name(entity, existing)
}

/// `AbstractSchemaService.updatedSchemaName`: a derived schema's delta may leave the name
/// parts out; they are then the stored name's.
pub fn updated_schema_name(entity: &JMap, existing: &JMap) -> Option<String> {
    let def = map_field(entity, "definition");
    let name = def.and_then(|d| safe_value_of(d.get("name")));
    let namespace = def.and_then(|d| safe_value_of(d.get("namespace")));
    if let (Some(n), Some(ns)) = (&name, &namespace) {
        return Some(format!("{ns}.{n}"));
    }
    let derived = existing.get("baseClientCode").is_some_and(|b| !b.java_to_string().trim().is_empty() && !b.is_null());
    let stored = str_field(existing, "name")?;
    if !derived {
        return None;
    }
    let dot = stored.rfind('.')?;
    if dot == 0 || dot == stored.len() - 1 {
        return None;
    }
    Some(format!("{}.{}", namespace.unwrap_or_else(|| stored[..dot].to_string()), name.unwrap_or_else(|| stored[dot + 1..].to_string())))
}

/// Reads the body's nested classes as Jackson would; an unreadable one is Spring's 400.
fn normalize_typed(object: CoreObject, e: &mut JMap) -> AppResult<()> {
    for (f, t) in object.typed_fields() {
        beans::normalize(e, f, *t).map_err(|u| overridable::write::controller::spring_refusal(StatusCode::BAD_REQUEST, format!("Failed to read HTTP message: {}", u.0)))?;
    }
    if object == CoreObject::Notification && e.get("notificationType").is_none_or(JValue::is_null) {
        // `private NotificationType notificationType = NotificationType.INFO`.
        e.insert("notificationType".into(), JValue::Str("INFO".into()));
    }
    if object == CoreObject::Workflow {
        // `getStepType()`: Jackson writes it after the fields, so the version snapshots Java
        // takes carry it; kept with the trigger so the editor's snapshots do too.
        if let Some(JValue::Object(t)) = e.get_mut("trigger") {
            t.insert("stepType".into(), JValue::Str("TRIGGER".into()));
        }
        // `Map<String, WorkflowStep>` of an abstract class with no type information: Jackson
        // cannot make any step.
        // Spring answers the codec's `InvalidDefinitionException` as a server error.
        if map_field(e, "steps").is_some_and(|s| s.values().any(|v| !v.is_null())) {
            return Err(AppError::Internal(anyhow::anyhow!(
                "Cannot construct instance of `com.fincity.saas.commons.core.model.WorkflowStep` (no Creators, like default constructor, exist): abstract types either need to be mapped to concrete types, have custom deserializer, or contain additional type information"
            )));
        }
    }
    Ok(())
}

/// `OutboundUrlUtil.validateConnectionDetails`: a connection may not point inside the network.
async fn outbound_check(e: &JMap) -> AppResult<()> {
    let details = map_field(e, "connectionDetails").map(|m| match crate::editor::storage::gson_of(m) {
        serde_json::Value::Object(o) => o,
        _ => serde_json::Map::new(),
    });
    connections::outbound::validate_connection_details(details.as_ref())
        .await
        .map_err(|err| {
            let status = StatusCode::from_u16(err.status().as_u16()).unwrap_or(StatusCode::BAD_REQUEST);
            match err.code() {
                Some(c) => AppError::from(c.clone().status(status).debug(err.to_string())),
                None => AppError::new(status, err.to_string()),
            }
        })
}

#[async_trait]
impl Kind for CoreKind {
    fn access_check_name(&self) -> &'static str {
        self.object_name()
    }

    /// Storage, Schema and Workflow start their delete with `this.read(id)`.
    fn delete_reads_first(&self) -> bool {
        matches!(self.object, CoreObject::Storage | CoreObject::Schema | CoreObject::Workflow)
    }

    async fn before_create(&self, cx: &Commons, ca: &ContextAuthentication, e: &mut JMap) -> AppResult<()> {
        normalize_typed(self.object, e)?;
        match self.object {
            CoreObject::Function | CoreObject::Schema => match definition_name(e)? {
                Some(n) => {
                    e.insert("name".into(), JValue::Str(n));
                }
                None => return Err(cx.error(StatusCode::BAD_REQUEST, msg::NAME_MISSING, &[])),
            },
            CoreObject::Storage => self.storage.before_create(cx, ca, e).await?,
            CoreObject::Connection => outbound_check(e).await?,
            CoreObject::Workflow => {
                if e.get("trigger").is_none_or(JValue::is_null) {
                    return Err(cx.error(StatusCode::INTERNAL_SERVER_ERROR, WORKFLOW_TRIGGER_MISSING, &[]));
                }
            }
            _ => {}
        }
        Ok(())
    }

    async fn after_create(&self, cx: &Commons, created: &JMap) -> AppResult<()> {
        if self.object == CoreObject::Storage {
            self.storage.after_create(cx, created).await;
        }
        Ok(())
    }

    async fn before_update(&self, cx: &Commons, ca: &ContextAuthentication, e: &mut JMap) -> AppResult<()> {
        normalize_typed(self.object, e)?;
        if self.object == CoreObject::Storage {
            self.storage.before_update(cx, ca, e).await?;
        }
        Ok(())
    }

    async fn updatable_fill(&self, cx: &Commons, ca: &ContextAuthentication, existing: &mut JMap, incoming: &JMap) -> AppResult<()> {
        match self.object {
            CoreObject::Function => {
                let Some(name) = updated_function_name(incoming, existing) else {
                    return Err(cx.error(StatusCode::BAD_REQUEST, msg::NAME_MISSING, &[]));
                };
                if Some(name.as_str()) != str_field(existing, "name") {
                    return Err(cx.error(StatusCode::BAD_REQUEST, msg::NAME_CHANGE, &[]));
                }
                for f in ["executeAuth", "definition", "permission"] {
                    existing.insert(f.into(), incoming.get(f).cloned().unwrap_or_default());
                }
            }
            CoreObject::Schema => {
                let Some(name) = updated_schema_name(incoming, existing) else {
                    return Err(cx.error(StatusCode::BAD_REQUEST, msg::NAME_MISSING, &[]));
                };
                if Some(name.as_str()) != str_field(existing, "name") {
                    return Err(cx.error(StatusCode::BAD_REQUEST, msg::NAME_CHANGE, &[]));
                }
                for f in ["definition", "permission"] {
                    existing.insert(f.into(), incoming.get(f).cloned().unwrap_or_default());
                }
            }
            CoreObject::Storage => self.storage.updatable_fill(cx, ca, existing, incoming).await?,
            CoreObject::Workflow => {
                if incoming.get("trigger").is_none_or(JValue::is_null) {
                    return Err(cx.error(StatusCode::INTERNAL_SERVER_ERROR, WORKFLOW_TRIGGER_MISSING, &[]));
                }
                for f in ["startAuth", "steps"] {
                    existing.insert(f.into(), incoming.get(f).cloned().unwrap_or_default());
                }
                if incoming.get("trigger") != existing.get("trigger") {
                    existing.insert("trigger".into(), incoming.get("trigger").cloned().unwrap_or_default());
                }
            }
            CoreObject::Connection => {
                outbound_check(incoming).await?;
                for f in self.object.updatable() {
                    existing.insert(f.to_string(), incoming.get(*f).cloned().unwrap_or_default());
                }
            }
            other => {
                for f in other.updatable() {
                    existing.insert(f.to_string(), incoming.get(*f).cloned().unwrap_or_default());
                }
            }
        }
        Ok(())
    }

    async fn after_update(&self, cx: &Commons, request: &JMap, saved: &JMap) -> AppResult<()> {
        if self.object == CoreObject::Storage {
            self.storage.after_update(cx, request, saved).await?;
        }
        Ok(())
    }

    async fn before_delete(&self, _cx: &Commons, _ca: &ContextAuthentication, stored: &JMap) -> AppResult<()> {
        if self.object == CoreObject::Storage {
            self.storage.before_delete(stored).await?;
        }
        Ok(())
    }

    async fn after_delete(&self, cx: &Commons, deleted: &JMap, result: bool) -> AppResult<bool> {
        match self.object {
            CoreObject::Storage => self.storage.after_delete(cx, deleted, result).await,
            CoreObject::Schema => {
                let app = str_field(deleted, "appCode").unwrap_or("");
                let name = str_field(deleted, "name").unwrap_or("");
                self.storage.reconcile_for_schema_change(cx, app, name).await;
                Ok(result)
            }
            _ => Ok(result),
        }
    }

    async fn after_evict_recursively(&self, cx: &Commons, app: &str, client: &str, name: &str) -> AppResult<()> {
        self.after_any_eviction(cx, app, client, name).await;
        Ok(())
    }

    async fn after_evict_draft(&self, cx: &Commons, app: &str, client: &str, name: &str) -> AppResult<()> {
        self.after_any_eviction(cx, app, client, name).await;
        Ok(())
    }

    /// `ConnectionService.read(id)`: another client's connection without its details, and the
    /// credentials only for a caller who may also replace them.
    async fn after_read(&self, _cx: &Commons, ca: &ContextAuthentication, mut entity: JMap) -> AppResult<JMap> {
        if self.object != CoreObject::Connection {
            return Ok(entity);
        }
        if Some(ca.client_code()) != str_field(&entity, "clientCode") {
            entity.insert("connectionDetails".into(), JValue::Null);
            return Ok(entity);
        }
        if ca.has_authority("Authorities.Connection_UPDATE") {
            return Ok(entity);
        }
        if let Some(d) = map_field(&entity, "connectionDetails") {
            let plain = crate::editor::storage::gson_of(d);
            let stripped = match plain {
                serde_json::Value::Object(o) => connections::connection::without_secrets(&o),
                _ => serde_json::Map::new(),
            };
            let back = overridable::json::parse(serde_json::Value::Object(stripped).to_string().as_bytes()).unwrap_or_default();
            entity.insert("connectionDetails".into(), back);
        }
        Ok(entity)
    }

    fn transport_dependencies(&self, e: &JMap) -> Vec<String> {
        match self.object {
            CoreObject::Storage => StorageOps::transport_dependencies(e),
            CoreObject::Schema => overridable::write::schema_refs::collect(e.get("definition")).into_iter().collect(),
            _ => Vec::new(),
        }
    }

    fn strip_transport_dependencies(&self, e: &JMap) -> Option<JMap> {
        match self.object {
            CoreObject::Storage => StorageOps::strip_transport_dependencies(e),
            _ => None,
        }
    }
}

impl CoreKind {
    /// Storage: the reference index and the tables. Schema: the client's storage overrides,
    /// then every storage standing on the schema rebuilt.
    async fn after_any_eviction(&self, cx: &Commons, app: &str, client: &str, name: &str) {
        match self.object {
            CoreObject::Storage => self.storage.after_evict(cx, app, client, name).await,
            CoreObject::Schema => {
                let ca = crate::editor::caller::current();
                self.storage.ensure_client_overrides(cx, ca.as_ref(), app, client, name).await;
                self.storage.reconcile_for_schema_change(cx, app, name).await;
            }
            _ => {}
        }
    }
}

/// `CoreFillerService`: the library's filler with core's cache names.
pub fn core_filler(cache: &platform::cache::CacheService) -> Filler {
    Filler::core(cache)
}

#[cfg(test)]
mod tests {
    use super::*;
    use overridable::json::parse;

    fn obj(s: &str) -> JMap {
        match parse(s.as_bytes()).unwrap() {
            JValue::Object(m) => m,
            _ => panic!(),
        }
    }

    // ── AbstractSchemaServiceUpdateTest: the name rules ──

    #[test]
    fn a_base_schema_must_restate_both_name_parts() {
        let base = obj(r#"{"name":"App.Order"}"#);
        assert_eq!(updated_schema_name(&obj(r#"{"definition":{"namespace":"App","name":"Order"}}"#), &base).as_deref(), Some("App.Order"));
        assert_eq!(updated_schema_name(&obj(r#"{"definition":{"name":"Order"}}"#), &base), None);
        assert_eq!(updated_schema_name(&obj(r#"{"definition":null}"#), &base), None);
    }

    #[test]
    fn a_derived_schema_takes_the_missing_parts_from_the_stored_name() {
        let derived = obj(r#"{"name":"App.Order","baseClientCode":"SYSTEM"}"#);
        assert_eq!(updated_schema_name(&obj(r#"{"definition":{}}"#), &derived).as_deref(), Some("App.Order"));
        assert_eq!(updated_schema_name(&obj(r#"{"definition":{"name":"Other"}}"#), &derived).as_deref(), Some("App.Other"));
        assert_eq!(updated_schema_name(&obj(r#"{"definition":{"namespace":"X"}}"#), &derived).as_deref(), Some("X.Order"));
        assert_eq!(updated_schema_name(&obj(r#"{}"#), &obj(r#"{"name":"NoDot","baseClientCode":"S"}"#)), None);
        assert_eq!(updated_schema_name(&obj(r#"{}"#), &obj(r#"{"name":".x","baseClientCode":"S"}"#)), None);
        assert_eq!(updated_schema_name(&obj(r#"{}"#), &obj(r#"{"name":"x.","baseClientCode":"S"}"#)), None);
        assert_eq!(updated_schema_name(&obj(r#"{}"#), &obj(r#"{"baseClientCode":"S"}"#)), None);
    }

    #[test]
    fn body_classes_are_read_as_jackson_reads_them() {
        let mut e = obj(r#"{"tasks":{"t":{"key":"t","type":"SEND_EMAIL","x":1}}}"#);
        normalize_typed(CoreObject::EventAction, &mut e).unwrap();
        assert_eq!(e["tasks"], JValue::Object(obj(r#"{"t":{"key":"t","type":"SEND_EMAIL"}}"#)));
        let mut e = obj(r#"{"tasks":{"t":{"type":"NOPE"}}}"#);
        assert!(normalize_typed(CoreObject::EventAction, &mut e).is_err());
        let mut n = obj(r#"{}"#);
        normalize_typed(CoreObject::Notification, &mut n).unwrap();
        assert_eq!(n["notificationType"], JValue::Str("INFO".into()));
        let mut w = obj(r#"{"steps":{"a":{}}}"#);
        assert!(normalize_typed(CoreObject::Workflow, &mut w).is_err());
        let mut w = obj(r#"{"steps":{"a":null}}"#);
        assert!(normalize_typed(CoreObject::Workflow, &mut w).is_ok());
        assert_eq!(definition_name(&obj(r#"{"definition":{"namespace":"A","name":"b"}}"#)).unwrap().as_deref(), Some("A.b"));
        assert!(definition_name(&obj(r#"{}"#)).is_err());
        assert_eq!(definition_name(&obj(r#"{"definition":{"name":"b"}}"#)).unwrap(), None);
    }

    #[test]
    fn the_classes_and_their_lists() {
        for o in [
            CoreObject::Function,
            CoreObject::Schema,
            CoreObject::Storage,
            CoreObject::Connection,
            CoreObject::Template,
            CoreObject::Notification,
            CoreObject::EventDefinition,
            CoreObject::EventAction,
            CoreObject::Workflow,
            CoreObject::Action,
        ] {
            assert!(!o.doc().object_name().is_empty());
            let _ = o.typed_fields();
            let _ = o.updatable();
            assert!(o.extract(obj("{}"), &obj("{}")).is_some());
        }
        let m = core_messages();
        assert_eq!(m.template(msg::VERSION_MISMATCH), "Please reload to get the new version before making changes.");
        assert_eq!(m.template(STORAGE_SCHEMA_ALWAYS_OBJECT), "Storage schema should always be of type Object");
    }
}
