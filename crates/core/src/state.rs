//! What every core-exec request shares.

use std::sync::Arc;

use kirun::repository::{KIRunFunctionRepository, KIRunSchemaRepository};

use crate::auth::AuthClient;
use crate::config::CoreConfig;
use crate::repos::app::Definitions;
use crate::repos::core_functions::CoreFunctions;
use crate::repos::core_schemas::CoreSchemas;
use crate::repos::remote::RemoteRepositories;
use crate::repos::{FunctionSource, KirunFunctions, KirunSchemas, SchemaSource};

pub struct Inner {
    pub config: CoreConfig,
    pub auth: AuthClient,
    pub definitions: Arc<Definitions>,
    pub remote: RemoteRepositories,
    pub kirun_functions: Arc<dyn FunctionSource>,
    pub kirun_schemas: Arc<dyn SchemaSource>,
    pub core_functions: Arc<dyn FunctionSource>,
    pub core_schemas: Arc<dyn SchemaSource>,
    /// The storage policy layer.
    pub appdata: Arc<crate::storage::service::AppDataService>,
    /// `crates/connections` and the publishers.
    pub integrations: Arc<crate::integrations::Integrations>,
    /// The event run log (`EventRunService`).
    pub event_runs: Arc<crate::event_runs::EventRunService>,
}

#[derive(Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

impl AppState {
    pub fn new(inner: Inner) -> Self {
        Self { inner: Arc::new(inner) }
    }

    pub fn inner(&self) -> &Inner {
        &self.inner
    }

    /// A handle that does not keep the state alive (the storage service holds one for
    /// triggers, the state holds the service).
    pub fn downgrade(&self) -> std::sync::Weak<Inner> {
        Arc::downgrade(&self.inner)
    }

    pub fn upgrade(w: &std::sync::Weak<Inner>) -> Option<AppState> {
        w.upgrade().map(|inner| AppState { inner })
    }
}

/// The repositories that do not depend on the app: KIRun's and core's own.
pub struct Builtins {
    pub kirun_functions: Arc<dyn FunctionSource>,
    pub kirun_schemas: Arc<dyn SchemaSource>,
    pub core_functions: Arc<dyn FunctionSource>,
    pub core_schemas: Arc<dyn SchemaSource>,
}

impl Builtins {
    pub fn new(core_functions: CoreFunctions) -> Self {
        Self::with(core_functions, Self::kirun_schemas(), Self::core_schemas())
    }

    /// With the schema sources made beforehand (the storage layer needs them first).
    pub fn with(core_functions: CoreFunctions, kirun_schemas: Arc<dyn SchemaSource>, core_schemas: Arc<dyn SchemaSource>) -> Self {
        Self {
            kirun_functions: Arc::new(KirunFunctions(Arc::new(KIRunFunctionRepository::new()))),
            kirun_schemas,
            core_functions: Arc::new(core_functions),
            core_schemas,
        }
    }

    pub fn kirun_schemas() -> Arc<dyn SchemaSource> {
        Arc::new(KirunSchemas(Arc::new(KIRunSchemaRepository::new())))
    }

    pub fn core_schemas() -> Arc<dyn SchemaSource> {
        Arc::new(CoreSchemas::new())
    }
}
