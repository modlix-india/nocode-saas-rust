//! The function and schema repositories, layered as `CoreFunctionService` and
//! `CoreSchemaService` layer them: KIRun's built-ins, core's own functions and schemas, the
//! app's stored definitions (and its dependency apps'), and entity-processor's remote
//! repositories for the apps listed in `core_remote_repositories`.
//!
//! A [`FunctionSource`] / [`SchemaSource`] can fail (a Mongo read, a remote call), which
//! KIRun's `Repository` cannot say; the top-level lookups use the sources directly so those
//! failures answer as errors, and KIRun gets an adapter that logs them and reports nothing
//! found.
//!
//! Java's `ReactiveHybridRepository.find` subscribes to every repository at once and takes the
//! first that emits, so the synchronous ones (KIRun, core) always win and the asynchronous
//! ones race. [`Hybrid`] takes them in order instead, with the synchronous ones listed first.
//! `filter` concatenates without removing duplicates, as Java's `flatMap` does.

pub mod app;
pub mod core_functions;
pub mod core_schemas;
pub mod definition;
pub mod remote;

use std::sync::Arc;

use async_trait::async_trait;
use kirun::function::Function;
use kirun::json::schema::Schema;
use kirun::repository::{KIRunFunctionRepository, KIRunSchemaRepository, Repository};
use serde_json::Value;

use crate::error::CoreError;
use crate::java_model::{gson_schema, gson_signature};

/// A schema found, with the JSON of the kirun-java object it stands for (the Gson form, see
/// [`crate::java_model`]), which `repositoryFind` writes.
pub struct FoundSchema {
    pub schema: Arc<Schema>,
    pub json: Value,
}

#[async_trait]
pub trait FunctionSource: Send + Sync {
    async fn find(&self, namespace: Option<&str>, name: &str) -> Result<Option<Arc<dyn Function>>, CoreError>;
    async fn filter(&self, name: &str) -> Result<Vec<String>, CoreError>;
}

#[async_trait]
pub trait SchemaSource: Send + Sync {
    async fn find(&self, namespace: Option<&str>, name: &str) -> Result<Option<Arc<FoundSchema>>, CoreError>;
    async fn filter(&self, name: &str) -> Result<Vec<String>, CoreError>;
}

/// The signature `repositoryFind` sends for a function: a stored definition's own JSON
/// (`getOnlySignatureFromDefinition`), a remote one's as entity-processor sent it, anything
/// else from its signature.
pub fn signature_json(f: &dyn Function) -> Value {
    if let Some(any) = f.as_any() {
        if let Some(d) = any.downcast_ref::<definition::DefinitionFunction>() {
            return gson_signature(d.definition_json(), true);
        }
        if let Some(r) = any.downcast_ref::<remote::RemoteFunction>() {
            return gson_signature(r.signature_json(), false);
        }
    }
    gson_signature(&f.get_signature().to_json(), false)
}

pub struct Hybrid<S: ?Sized> {
    sources: Vec<Arc<S>>,
}

impl<S: ?Sized> Hybrid<S> {
    pub fn new(sources: Vec<Arc<S>>) -> Self {
        Self { sources }
    }
}

#[async_trait]
impl FunctionSource for Hybrid<dyn FunctionSource> {
    async fn find(&self, namespace: Option<&str>, name: &str) -> Result<Option<Arc<dyn Function>>, CoreError> {
        for s in &self.sources {
            if let Some(f) = s.find(namespace, name).await? {
                return Ok(Some(f));
            }
        }
        Ok(None)
    }

    async fn filter(&self, name: &str) -> Result<Vec<String>, CoreError> {
        let mut out = Vec::new();
        for s in &self.sources {
            out.extend(s.filter(name).await?);
        }
        Ok(out)
    }
}

#[async_trait]
impl SchemaSource for Hybrid<dyn SchemaSource> {
    async fn find(&self, namespace: Option<&str>, name: &str) -> Result<Option<Arc<FoundSchema>>, CoreError> {
        for s in &self.sources {
            if let Some(f) = s.find(namespace, name).await? {
                return Ok(Some(f));
            }
        }
        Ok(None)
    }

    async fn filter(&self, name: &str) -> Result<Vec<String>, CoreError> {
        let mut out = Vec::new();
        for s in &self.sources {
            out.extend(s.filter(name).await?);
        }
        Ok(out)
    }
}

/// KIRun's built-in functions. A missing namespace finds nothing (Java looks up `null.<name>`).
pub struct KirunFunctions(pub Arc<KIRunFunctionRepository>);

#[async_trait]
impl FunctionSource for KirunFunctions {
    async fn find(&self, namespace: Option<&str>, name: &str) -> Result<Option<Arc<dyn Function>>, CoreError> {
        let Some(ns) = namespace else { return Ok(None) };
        Ok(self.0.find(ns, name).await)
    }

    async fn filter(&self, name: &str) -> Result<Vec<String>, CoreError> {
        Ok(self.0.filter(name).await)
    }
}

/// KIRun's built-in schemas.
pub struct KirunSchemas(pub Arc<KIRunSchemaRepository>);

#[async_trait]
impl SchemaSource for KirunSchemas {
    async fn find(&self, namespace: Option<&str>, name: &str) -> Result<Option<Arc<FoundSchema>>, CoreError> {
        let Some(ns) = namespace else { return Ok(None) };
        Ok(self.0.find(ns, name).await.map(|schema| {
            let json = gson_schema(&schema.to_json()).unwrap_or(Value::Null);
            Arc::new(FoundSchema { schema, json })
        }))
    }

    async fn filter(&self, name: &str) -> Result<Vec<String>, CoreError> {
        Ok(self.0.filter(name).await)
    }
}

/// A [`FunctionSource`] as KIRun's `Repository`, for the runtime's own lookups.
pub struct FunctionRepo(pub Arc<dyn FunctionSource>);

#[async_trait]
impl Repository<dyn Function> for FunctionRepo {
    async fn find(&self, namespace: &str, name: &str) -> Option<Arc<dyn Function>> {
        match self.0.find(Some(namespace), name).await {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(namespace, name, error = %e, "function lookup failed");
                None
            }
        }
    }

    async fn filter(&self, name: &str) -> Vec<String> {
        self.0.filter(name).await.unwrap_or_default()
    }
}

/// A [`SchemaSource`] as KIRun's `Repository`.
pub struct SchemaRepo(pub Arc<dyn SchemaSource>);

#[async_trait]
impl Repository<Schema> for SchemaRepo {
    async fn find(&self, namespace: &str, name: &str) -> Option<Arc<Schema>> {
        match self.0.find(Some(namespace), name).await {
            Ok(f) => f.map(|s| s.schema.clone()),
            Err(e) => {
                tracing::warn!(namespace, name, error = %e, "schema lookup failed");
                None
            }
        }
    }

    async fn filter(&self, name: &str) -> Vec<String> {
        self.0.filter(name).await.unwrap_or_default()
    }
}

/// `filter` on a fixed list of full names: lower-case containment, as KIRun's and core's
/// repositories filter.
pub fn filter_names(names: &[String], filter: &str) -> Vec<String> {
    let f = filter.to_lowercase();
    names.iter().filter(|n| n.to_lowercase().contains(&f)).cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CoreError;
    use axum::http::StatusCode;
    use kirun::repository::KIRunSchemaRepository;

    struct Failing;

    #[async_trait]
    impl FunctionSource for Failing {
        async fn find(&self, _: Option<&str>, _: &str) -> Result<Option<Arc<dyn Function>>, CoreError> {
            Err(CoreError::new(StatusCode::BAD_GATEWAY, "down"))
        }
        async fn filter(&self, _: &str) -> Result<Vec<String>, CoreError> {
            Err(CoreError::new(StatusCode::BAD_GATEWAY, "down"))
        }
    }

    #[async_trait]
    impl SchemaSource for Failing {
        async fn find(&self, _: Option<&str>, _: &str) -> Result<Option<Arc<FoundSchema>>, CoreError> {
            Err(CoreError::new(StatusCode::BAD_GATEWAY, "down"))
        }
        async fn filter(&self, _: &str) -> Result<Vec<String>, CoreError> {
            Err(CoreError::new(StatusCode::BAD_GATEWAY, "down"))
        }
    }

    fn kirun_functions() -> Arc<dyn FunctionSource> {
        Arc::new(KirunFunctions(Arc::new(KIRunFunctionRepository::new())))
    }

    fn kirun_schemas() -> Arc<dyn SchemaSource> {
        Arc::new(KirunSchemas(Arc::new(KIRunSchemaRepository::new())))
    }

    #[tokio::test]
    async fn hybrid_takes_sources_in_order_and_keeps_every_name() {
        let h = Hybrid::<dyn FunctionSource>::new(vec![kirun_functions(), kirun_functions()]);
        assert!(h.find(Some("System.Math"), "Add").await.unwrap().is_some());
        assert!(h.find(None, "Add").await.unwrap().is_none());
        let names = h.filter("math.add").await.unwrap();
        assert_eq!(names, ["System.Math.Add", "System.Math.Add"]);
        let failing = Hybrid::<dyn FunctionSource>::new(vec![Arc::new(Failing), kirun_functions()]);
        assert_eq!(failing.find(Some("System.Math"), "Add").await.err().unwrap().status(), StatusCode::BAD_GATEWAY);
        assert!(failing.filter("").await.is_err());
        // A later failing source is not asked once an earlier one found the function.
        let late = Hybrid::<dyn FunctionSource>::new(vec![kirun_functions(), Arc::new(Failing)]);
        assert!(late.find(Some("System.Math"), "Add").await.unwrap().is_some());

        let s = Hybrid::<dyn SchemaSource>::new(vec![kirun_schemas()]);
        let any = s.find(Some("System"), "any").await.unwrap().unwrap();
        assert_eq!(any.json["name"], serde_json::json!("any"));
        assert!(s.find(Some("System"), "nothing").await.unwrap().is_none());
        assert!(s.find(None, "any").await.unwrap().is_none());
        assert!(!s.filter("system").await.unwrap().is_empty());
        let failing = Hybrid::<dyn SchemaSource>::new(vec![Arc::new(Failing)]);
        assert!(failing.find(Some("A"), "b").await.is_err());
        assert!(failing.filter("").await.is_err());
    }

    #[tokio::test]
    async fn kirun_adapters_log_failures_as_nothing_found() {
        let f = FunctionRepo(Arc::new(Failing));
        assert!(f.find("A", "b").await.is_none());
        assert!(f.filter("").await.is_empty());
        let s = SchemaRepo(Arc::new(Failing));
        assert!(s.find("A", "b").await.is_none());
        assert!(s.filter("").await.is_empty());
        let f = FunctionRepo(kirun_functions());
        assert!(f.find("System.Math", "Add").await.is_some());
        assert!(!f.filter("add").await.is_empty());
        let s = SchemaRepo(kirun_schemas());
        assert!(s.find("System", "any").await.is_some());
        assert!(!s.filter("any").await.is_empty());
    }

    #[tokio::test]
    async fn signature_json_by_kind() {
        let add = kirun_functions().find(Some("System.Math"), "Add").await.unwrap().unwrap();
        let j = signature_json(add.as_ref());
        assert_eq!(j["name"], serde_json::json!("Add"));
        assert!(j.get("steps").is_none());
        let def = definition::DefinitionFunction::new(
            serde_json::json!({"name": "f", "namespace": "N", "steps": {}}),
            None,
            None,
            std::time::Duration::from_secs(1),
        )
        .unwrap();
        let j = signature_json(&def);
        assert_eq!(j["steps"], serde_json::json!({}));
        assert_eq!(j["version"], serde_json::json!(1));
    }

    #[test]
    fn filters_names_case_insensitively() {
        let names = vec!["A.Bc".to_string(), "x.y".to_string()];
        assert_eq!(filter_names(&names, "bC"), ["A.Bc"]);
        assert_eq!(filter_names(&names, "").len(), 2);
    }
}
