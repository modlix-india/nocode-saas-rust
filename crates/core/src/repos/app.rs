//! An app's stored functions and schemas (`AbstractFunctionService.findFunctionRepository`,
//! `AbstractSchemaService.findSchemaRepository`), and the app's dependencies
//! (`getFunctionRepository` / `getSchemaRepository`: the app first, then every app security
//! lists as its dependency, read for the same client).
//!
//! A definition is read through the overridable store (inheritance, drafts, the base-client
//! merge, the `FunctionCache_<app>_<name>` cache), for the request's url client code (the
//! `clientCode` header, else the client asked for) and surface.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use dashmap::DashMap;
use kirun::function::Function;
use kirun::json::schema::Schema;
use mongodb::bson::{doc, Bson};
use overridable::pojo::str_field;
use overridable::{DocType, Store};
use platform::cache::LocalCaches;
use platform::security::SecurityClient;
use serde_json::Value;

use super::definition::DefinitionFunction;
use super::{FoundSchema, FunctionSource, Hybrid, SchemaSource};
use crate::context;
use crate::docs::{FunctionDoc, SchemaDoc};
use crate::error::CoreError;
use crate::java_model::gson_schema;

/// Reads definitions for apps and clients; shared by every request.
pub struct Definitions {
    store: Store,
    security: SecurityClient,
    /// `appDepList`: security's dependency lists, cached the way `FeignAuthenticationService`
    /// caches them (evicted by the Java services' messages).
    dependencies: Arc<LocalCaches<String, Arc<Vec<String>>>>,
    /// Parsed definitions by the resolved document's content id, so a cached read is not
    /// parsed again for every execution.
    functions: DashMap<String, Arc<DefinitionFunction>>,
    schemas: DashMap<String, Arc<FoundSchema>>,
    timeout: Duration,
}

const PARSED_CACHE_LIMIT: usize = 20_000;

impl Definitions {
    pub fn new(
        store: Store,
        security: SecurityClient,
        dependencies: Arc<LocalCaches<String, Arc<Vec<String>>>>,
        timeout: Duration,
    ) -> Self {
        Self { store, security, dependencies, functions: DashMap::new(), schemas: DashMap::new(), timeout }
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    /// `FeignAuthenticationService.getDependencies(appCode)`.
    pub async fn dependencies(&self, app_code: &str) -> Result<Arc<Vec<String>>, CoreError> {
        let sec = self.security.clone();
        let app = app_code.to_string();
        Ok(self
            .dependencies
            .get_or_load("appDepList", app_code.to_string(), || async move {
                Ok::<_, anyhow::Error>(Some(Arc::new(sec.app_dependencies(&app).await?)))
            })
            .await?
            .unwrap_or_default())
    }

    /// `read(name, appCode, clientCode)`: the url client code is the caller's, if any, and the
    /// client read is the one `servedClientCode` picks (a signed-in tenant's own on a shared
    /// host, Java commit e2b7d48aa).
    async fn read(&self, dt: &dyn DocType, name: &str, app_code: &str, client_code: &str) -> Result<Option<Arc<overridable::Resolved>>, CoreError> {
        let rc = context::request();
        let url_client = rc
            .as_ref()
            .and_then(|r| r.auth.url_client_code().map(str::to_string))
            .unwrap_or_else(|| client_code.to_string());
        let served = self.store.served_client_code(rc.as_ref().map(|r| &r.auth.ca), app_code, client_code).await;
        let draft = context::is_draft();
        Ok(self.store.read(dt, name, app_code, &url_client, &served, draft).await?)
    }

    pub async fn function(self: &Arc<Self>, app_code: &str, client_code: &str, name: &str) -> Result<Option<Arc<DefinitionFunction>>, CoreError> {
        let Some(r) = self.read(&FunctionDoc, name, app_code, client_code).await? else {
            return Ok(None);
        };
        if let Some(f) = self.functions.get(&r.unique_id) {
            return Ok(Some(f.clone()));
        }
        let definition = r.entity.get("definition").map(to_serde).unwrap_or(Value::Null);
        let f = Arc::new(
            DefinitionFunction::new(
                definition,
                str_field(&r.entity, "executeAuth").map(str::to_string),
                str_field(&r.entity, "appCode").map(str::to_string),
                self.timeout,
            )
            .map_err(CoreError::from)?,
        );
        if self.functions.len() > PARSED_CACHE_LIMIT {
            self.functions.clear();
        }
        self.functions.insert(r.unique_id.clone(), f.clone());
        Ok(Some(f))
    }

    pub async fn schema(self: &Arc<Self>, app_code: &str, client_code: &str, name: &str) -> Result<Option<Arc<FoundSchema>>, CoreError> {
        let Some(r) = self.read(&SchemaDoc, name, app_code, client_code).await? else {
            return Ok(None);
        };
        if let Some(s) = self.schemas.get(&r.unique_id) {
            return Ok(Some(s.clone()));
        }
        let json = r.entity.get("definition").map(to_serde).and_then(|d| gson_schema(&d)).unwrap_or(Value::Null);
        let schema = Schema::from_value(&json).map_err(CoreError::from)?.unwrap_or_default();
        let found = Arc::new(FoundSchema { schema: Arc::new(schema), json });
        if self.schemas.len() > PARSED_CACHE_LIMIT {
            self.schemas.clear();
        }
        self.schemas.insert(r.unique_id.clone(), found.clone());
        Ok(Some(found))
    }

    /// `filterInRepo`: the names in the app for every client in the inheritance order, matching
    /// `filter` as a case-insensitive regular expression; a client's copy and its base's both
    /// count.
    pub async fn filter(&self, dt: &dyn DocType, app_code: &str, client_code: &str, filter: &str) -> Result<Vec<String>, CoreError> {
        let order = self.store.inheritance_order(app_code, client_code, client_code).await?;
        let codes: Vec<Bson> = order.iter().map(|c| Bson::String(c.clone())).collect();
        let mut q = doc! {"appCode": app_code, "clientCode": {"$in": codes}};
        if !filter.trim().is_empty() {
            q.insert("name", doc! {"$regex": filter, "$options": "i"});
        }
        let docs = self.store.find_docs(dt.collection(), q).await?;
        Ok(docs.iter().filter_map(|d| d.get_str("name").ok().map(str::to_string)).collect())
    }
}

fn to_serde(v: &overridable::JValue) -> Value {
    serde_json::to_value(v).unwrap_or(Value::Null)
}

/// One app's functions for one client.
pub struct AppFunctions {
    pub defs: Arc<Definitions>,
    pub app_code: String,
    pub client_code: String,
}

#[async_trait]
impl FunctionSource for AppFunctions {
    async fn find(&self, namespace: Option<&str>, name: &str) -> Result<Option<Arc<dyn Function>>, CoreError> {
        let full = match namespace.filter(|n| !n.trim().is_empty()) {
            Some(ns) => format!("{ns}.{name}"),
            None => name.to_string(),
        };
        Ok(self
            .defs
            .function(&self.app_code, &self.client_code, &full)
            .await?
            .map(|f| f as Arc<dyn Function>))
    }

    async fn filter(&self, name: &str) -> Result<Vec<String>, CoreError> {
        self.defs.filter(&FunctionDoc, &self.app_code, &self.client_code, name).await
    }
}

/// One app's schemas for one client.
pub struct AppSchemas {
    pub defs: Arc<Definitions>,
    pub app_code: String,
    pub client_code: String,
}

#[async_trait]
impl SchemaSource for AppSchemas {
    /// `read(namespace + "." + name, ...)`: no blank check here, unlike functions.
    async fn find(&self, namespace: Option<&str>, name: &str) -> Result<Option<Arc<FoundSchema>>, CoreError> {
        let full = format!("{}.{name}", namespace.unwrap_or("null"));
        self.defs.schema(&self.app_code, &self.client_code, &full).await
    }

    async fn filter(&self, name: &str) -> Result<Vec<String>, CoreError> {
        self.defs.filter(&SchemaDoc, &self.app_code, &self.client_code, name).await
    }
}

/// `getFunctionRepository(appCode, clientCode)`: the app, then its dependencies.
pub async fn app_function_repository(defs: &Arc<Definitions>, app_code: &str, client_code: &str) -> Result<Arc<dyn FunctionSource>, CoreError> {
    let deps = defs.dependencies(app_code).await?;
    let mut sources: Vec<Arc<dyn FunctionSource>> = Vec::with_capacity(deps.len() + 1);
    for app in std::iter::once(app_code).chain(deps.iter().map(String::as_str)) {
        sources.push(Arc::new(AppFunctions { defs: defs.clone(), app_code: app.to_string(), client_code: client_code.to_string() }));
    }
    Ok(if sources.len() == 1 { sources.remove(0) } else { Arc::new(Hybrid::new(sources)) })
}

/// `getSchemaRepository(appCode, clientCode)`.
pub async fn app_schema_repository(defs: &Arc<Definitions>, app_code: &str, client_code: &str) -> Result<Arc<dyn SchemaSource>, CoreError> {
    let deps = defs.dependencies(app_code).await?;
    let mut sources: Vec<Arc<dyn SchemaSource>> = Vec::with_capacity(deps.len() + 1);
    for app in std::iter::once(app_code).chain(deps.iter().map(String::as_str)) {
        sources.push(Arc::new(AppSchemas { defs: defs.clone(), app_code: app.to_string(), client_code: client_code.to_string() }));
    }
    Ok(if sources.len() == 1 { sources.remove(0) } else { Arc::new(Hybrid::new(sources)) })
}
