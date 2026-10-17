//! The write side of the overridable-document engine: `AbstractOverridableDataService` and
//! the commons-mongo services and controllers around it, for the Rust units that edit the
//! documents `ui` and `core` serve.
//!
//! - [`service`]: [`Commons`] (what every service of a process shares) and
//!   [`OverridableService`] (create, read by id, update, plan update, delete, access checks,
//!   evictions);
//! - [`kind`]: [`Kind`], the hooks a document kind plugs in (the Java subclass overrides);
//! - [`draft`]: drafts, fork, publish, discard; [`version`]: version history;
//! - [`list`]: the list and index reads; [`publish`]: app-wide pending and publish-all;
//! - [`transport`]: export and import; [`deletion`]: an app's wipe; [`filler`]: the filler
//!   documents;
//! - [`controller`]: request-to-reply functions for every Java route; [`router`]: axum
//!   routers built from them (not mounted here);
//! - [`condition`], [`spring`], [`persist`], [`messages`], [`schema_refs`], [`topo`]: the
//!   commons pieces they stand on.
//!
//! `WRITE_PATH.md` in the crate root has the API and the eviction table.

pub mod condition;
pub mod controller;
pub mod deletion;
pub mod draft;
pub mod filler;
pub mod kind;
pub mod list;
pub mod messages;
pub mod persist;
pub mod publish;
pub mod router;
pub mod schema_refs;
pub mod service;
pub mod spring;
pub mod topo;
pub mod transport;
pub mod version;

use async_trait::async_trait;
use platform::error::AppResult;
use platform::security::ContextAuthentication;

use crate::json::JMap;
use crate::pojo::{convert_json, to_jackson};

pub use kind::{Kind, Method};
pub use messages::Messages;
pub use service::{Commons, OverridableService};

/// An overridable service with its document kind erased, for the registries that span kinds
/// (publish-all, an app's wipe, transport).
#[async_trait]
pub trait AnyService: Send + Sync {
    /// `getObjectName()`.
    fn object_name(&self) -> &'static str;
    fn draftable(&self) -> bool;
    async fn publish(&self, ca: &ContextAuthentication, id: &str, message: Option<&str>) -> AppResult<JMap>;
    async fn delete_everything(&self, ca: &ContextAuthentication, app: &str, client: &str) -> AppResult<Option<bool>>;
    async fn read_for_transport(&self, ca: &ContextAuthentication, app: &str, client: &str, names: Option<&[String]>) -> AppResult<Vec<JMap>>;
    async fn read_to_transport(&self, ca: &ContextAuthentication, name: &str, app: &str, client: &str) -> AppResult<Option<(i64, String)>>;
    async fn create(&self, ca: &ContextAuthentication, entity: JMap) -> AppResult<JMap>;
    async fn update(&self, ca: &ContextAuthentication, entity: JMap) -> AppResult<JMap>;
    /// `makeEntity`: a transport's map as the class (Jackson `convertValue`), when the type
    /// is this service's.
    fn make_entity(&self, object_type: &str, data: &JMap) -> Option<JMap>;
    /// `makeTransportObject`'s data: the entity as Jackson maps it.
    fn to_data(&self, entity: &JMap) -> JMap;
    fn transport_dependencies(&self, entity: &JMap) -> Vec<String>;
    fn strip_transport_dependencies(&self, entity: &JMap) -> Option<JMap>;
}

#[async_trait]
impl<K: Kind> AnyService for OverridableService<K> {
    fn object_name(&self) -> &'static str {
        OverridableService::object_name(self)
    }

    fn draftable(&self) -> bool {
        self.kind().draftable()
    }

    async fn publish(&self, ca: &ContextAuthentication, id: &str, message: Option<&str>) -> AppResult<JMap> {
        OverridableService::publish(self, ca, id, message).await
    }

    async fn delete_everything(&self, ca: &ContextAuthentication, app: &str, client: &str) -> AppResult<Option<bool>> {
        OverridableService::delete_everything(self, ca, app, client).await
    }

    async fn read_for_transport(&self, ca: &ContextAuthentication, app: &str, client: &str, names: Option<&[String]>) -> AppResult<Vec<JMap>> {
        OverridableService::read_for_transport(self, ca, app, client, names).await
    }

    async fn read_to_transport(&self, ca: &ContextAuthentication, name: &str, app: &str, client: &str) -> AppResult<Option<(i64, String)>> {
        OverridableService::read_to_transport(self, ca, name, app, client).await
    }

    async fn create(&self, ca: &ContextAuthentication, entity: JMap) -> AppResult<JMap> {
        OverridableService::create(self, ca, entity).await
    }

    async fn update(&self, ca: &ContextAuthentication, entity: JMap) -> AppResult<JMap> {
        OverridableService::update(self, ca, entity).await
    }

    fn make_entity(&self, object_type: &str, data: &JMap) -> Option<JMap> {
        (object_type == OverridableService::object_name(self)).then(|| convert_json(self.kind().pojo(), data))
    }

    fn to_data(&self, entity: &JMap) -> JMap {
        to_jackson(self.kind().pojo(), entity)
    }

    fn transport_dependencies(&self, entity: &JMap) -> Vec<String> {
        self.kind().transport_dependencies(entity)
    }

    fn strip_transport_dependencies(&self, entity: &JMap) -> Option<JMap> {
        self.kind().strip_transport_dependencies(entity)
    }
}
