//! `RemoteRepositoryService` and the entity-processor repositories
//! (`EPRemoteFunctionRepository`, `EPRemoteSchemaRepository`, `EPRemoteFunction`).
//!
//! An app listed in `core_remote_repositories` (MySQL, `core` database) also sees
//! entity-processor's functions and schemas. The list is cached per app under
//! `cacheRemoteRepositories`, which the Java core evicts when a row changes.

use std::any::Any;
use std::sync::Arc;

use async_trait::async_trait;
use axum::http::StatusCode;
use kirun::function::Function;
use kirun::json::schema::Schema;
use kirun::model::{EventResult, FunctionDefinition, FunctionOutput, FunctionSignature};
use kirun::runtime::FunctionExecutionParameters;
use kirun::Map;
use platform::cache::LocalCaches;
use serde_json::Value;
use sqlx::MySqlPool;

use super::{FoundSchema, FunctionSource, SchemaSource};
use crate::clients::{EntityProcessor, RemoteCall};
use crate::context;
use crate::error::{messages, CoreError};
use crate::gson::to_gson;
use crate::java_model::gson_schema;

pub const CACHE_REMOTE_REPOSITORIES: &str = "cacheRemoteRepositories";

pub struct RemoteRepositories {
    pool: MySqlPool,
    names: Arc<LocalCaches<String, Arc<Vec<String>>>>,
    ep: Arc<EntityProcessor>,
}

/// The function and schema repositories of one app and client, when it has remote ones.
pub struct Remote {
    pub functions: Arc<dyn FunctionSource>,
    pub schemas: Arc<dyn SchemaSource>,
}

impl RemoteRepositories {
    pub fn new(pool: MySqlPool, names: Arc<LocalCaches<String, Arc<Vec<String>>>>, ep: Arc<EntityProcessor>) -> Self {
        Self { pool, names, ep }
    }

    /// `getRemoteRepositoryNames(appCode)`: the `REPO_NAME`s of the app's rows.
    pub async fn names(&self, app_code: &str) -> Result<Arc<Vec<String>>, CoreError> {
        let pool = self.pool.clone();
        let app = app_code.to_string();
        Ok(self
            .names
            .get_or_load(CACHE_REMOTE_REPOSITORIES, app_code.to_string(), || async move {
                let rows: Vec<(String,)> =
                    sqlx::query_as("SELECT REPO_NAME FROM core_remote_repositories WHERE APP_CODE = ?")
                        .bind(&app)
                        .fetch_all(&pool)
                        .await?;
                Ok::<_, anyhow::Error>(Some(Arc::new(rows.into_iter().map(|r| r.0).collect())))
            })
            .await?
            .unwrap_or_default())
    }

    /// `getRemoteRepositories(appCode, clientCode)`. With entity-processor unconfigured (retired
    /// 2026-10-18) an app's `PROCESSOR` rows are ignored: its functions and schemas are the
    /// local ones, and a missing one is "not found" rather than a failed remote call.
    pub async fn repositories(&self, app_code: &str, client_code: &str) -> Result<Option<Remote>, CoreError> {
        if !self.ep.configured() || self.names(app_code).await?.is_empty() {
            return Ok(None);
        }
        Ok(Some(Remote {
            functions: Arc::new(RemoteFunctions::new(self.ep.clone(), app_code, client_code)),
            schemas: Arc::new(RemoteSchemas::new(self.ep.clone(), app_code, client_code)),
        }))
    }
}

pub struct RemoteFunctions {
    ep: Arc<EntityProcessor>,
    app_code: String,
    client_code: String,
}

impl RemoteFunctions {
    pub fn new(ep: Arc<EntityProcessor>, app_code: &str, client_code: &str) -> Self {
        Self { ep, app_code: app_code.to_string(), client_code: client_code.to_string() }
    }
}

#[async_trait]
impl FunctionSource for RemoteFunctions {
    async fn find(&self, namespace: Option<&str>, name: &str) -> Result<Option<Arc<dyn Function>>, CoreError> {
        let Some(text) =
            self.ep.find_function(&self.app_code, &self.client_code, namespace.unwrap_or(""), name).await?
        else {
            return Ok(None);
        };
        let json: Value = serde_json::from_str(&text).map_err(|e| CoreError::unknown(e.to_string()))?;
        let fd = FunctionDefinition::from_value(&json).map_err(CoreError::from)?;
        Ok(Some(Arc::new(RemoteFunction {
            signature: fd.get_signature().clone(),
            json,
            ep: self.ep.clone(),
            app_code: self.app_code.clone(),
            client_code: self.client_code.clone(),
        })))
    }

    async fn filter(&self, name: &str) -> Result<Vec<String>, CoreError> {
        self.ep.filter_functions(&self.app_code, &self.client_code, name).await
    }
}

pub struct RemoteSchemas {
    ep: Arc<EntityProcessor>,
    app_code: String,
    client_code: String,
}

impl RemoteSchemas {
    pub fn new(ep: Arc<EntityProcessor>, app_code: &str, client_code: &str) -> Self {
        Self { ep, app_code: app_code.to_string(), client_code: client_code.to_string() }
    }
}

#[async_trait]
impl SchemaSource for RemoteSchemas {
    async fn find(&self, namespace: Option<&str>, name: &str) -> Result<Option<Arc<FoundSchema>>, CoreError> {
        let Some(text) = self.ep.find_schema(&self.app_code, &self.client_code, namespace.unwrap_or(""), name).await?
        else {
            return Ok(None);
        };
        let raw: Value = serde_json::from_str(&text).map_err(|e| CoreError::unknown(e.to_string()))?;
        let json = gson_schema(&raw).unwrap_or(Value::Null);
        let schema = Schema::from_value(&json).map_err(CoreError::from)?.unwrap_or_default();
        Ok(Some(Arc::new(FoundSchema { schema: Arc::new(schema), json })))
    }

    async fn filter(&self, name: &str) -> Result<Vec<String>, CoreError> {
        self.ep.filter_schemas(&self.app_code, &self.client_code, name).await
    }
}

/// `EPRemoteFunction`: executed by entity-processor with the caller's token. Not an
/// `AbstractReactiveFunction`, so its arguments are sent as they are, unvalidated.
pub struct RemoteFunction {
    signature: FunctionSignature,
    json: Value,
    ep: Arc<EntityProcessor>,
    app_code: String,
    client_code: String,
}

impl RemoteFunction {
    pub fn signature_json(&self) -> &Value {
        &self.json
    }
}

#[async_trait]
impl Function for RemoteFunction {
    fn get_signature(&self) -> &FunctionSignature {
        &self.signature
    }

    async fn execute(&self, context: &mut FunctionExecutionParameters) -> kirun::Result<FunctionOutput> {
        let rc = context::request().unwrap_or_default();
        let args = context.get_arguments().cloned().unwrap_or_default();
        let body = to_gson(&Value::Object(args.into_iter().collect()));
        let full = format!("{}.{}", self.signature.get_namespace(), self.signature.get_name());
        let call = RemoteCall {
            authorization: rc.auth.access_token().unwrap_or(""),
            forwarded_host: &rc.forwarded_host,
            forwarded_port: &rc.forwarded_port,
            header_client_code: rc.auth.url_client_code().unwrap_or(""),
            header_app_code: rc.auth.url_app_code().unwrap_or(""),
            namespace: self.signature.get_namespace(),
            name: self.signature.get_name(),
            app_code: &self.app_code,
            client_code: &self.client_code,
            body,
        };
        let text = match self.ep.execute(call).await {
            Ok(Some(t)) => t,
            Ok(None) => {
                return Err(context::raise(CoreError::msg(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    messages::EMPTY_FUNCTION_RESPONSE,
                    &[&full],
                )))
            }
            Err(e) => return Err(context::raise(e)),
        };
        let list: Vec<Value> =
            serde_json::from_str(&text).map_err(|e| context::raise(CoreError::unknown(e.to_string())))?;
        let results = list
            .into_iter()
            .map(|er| {
                let name = er.get("name").and_then(Value::as_str).unwrap_or_default().to_string();
                let result: Map<Value> = match er.get("result") {
                    Some(Value::Object(m)) => m.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
                    _ => Map::new(),
                };
                EventResult::new(name, result)
            })
            .collect();
        Ok(FunctionOutput::new(results))
    }

    fn as_any(&self) -> Option<&dyn Any> {
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clients::tests::stub;
    use crate::testing::{request, user};
    use kirun::repository::{KIRunFunctionRepository, KIRunSchemaRepository};
    use platform::upstream::Upstream;
    use serde_json::json;

    fn fep() -> FunctionExecutionParameters {
        FunctionExecutionParameters::new(Arc::new(KIRunFunctionRepository::new()), Arc::new(KIRunSchemaRepository::new()))
    }

    #[tokio::test]
    async fn a_retired_entity_processor_is_no_remote_repository() {
        // No database is reached: the check comes first.
        let pool = sqlx::mysql::MySqlPoolOptions::new().connect_lazy("mysql://root@127.0.0.1:1/core").unwrap();
        let cache = platform::cache::CacheService::new("cmn", "evictionChannel", None).unwrap();
        let ep = Arc::new(EntityProcessor::new(Upstream::fixed(&[])).unwrap());
        let remote = RemoteRepositories::new(pool, cache.family(), ep);
        assert!(remote.repositories("leadzump", "SYSTEM").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn remote_functions_and_schemas() {
        let base = stub().await;
        let ep = Arc::new(EntityProcessor::new(Upstream::fixed(&[&base])).unwrap());
        let functions = RemoteFunctions::new(ep.clone(), "leadzump", "SYSTEM");
        let schemas = RemoteSchemas::new(ep.clone(), "leadzump", "SYSTEM");

        let f = functions.find(Some("EP.Campaign"), "Create").await.unwrap().unwrap();
        assert_eq!(f.get_signature().get_full_name(), "EP.Campaign.Create");
        let r = f.as_any().unwrap().downcast_ref::<RemoteFunction>().unwrap();
        assert_eq!(r.signature_json()["name"], json!("Create"));
        assert!(functions.find(None, "Nope").await.unwrap().is_none());
        assert!(functions.find(Some("EP"), "Garbage").await.is_err());
        assert_eq!(functions.filter("").await.unwrap().len(), 2);

        let s = schemas.find(Some("EP.DTO"), "Owner").await.unwrap().unwrap();
        assert_eq!(s.json["namespace"], json!("EP.DTO"));
        assert!(schemas.find(Some("EP.DTO"), "Nope").await.unwrap().is_none());
        assert!(schemas.find(None, "Garbage").await.is_err());
        assert_eq!(schemas.filter("x").await.unwrap(), ["EP.A.b", "EP.A.c"]);
    }

    #[tokio::test]
    async fn remote_execution_sends_the_arguments_and_reads_the_events() {
        let base = stub().await;
        let ep = Arc::new(EntityProcessor::new(Upstream::fixed(&[&base])).unwrap());
        let run = |name: &'static str| {
            let ep = ep.clone();
            async move {
                let f = RemoteFunction {
                    signature: FunctionSignature::new(name).set_namespace("EP.Campaign"),
                    json: Value::Null,
                    ep,
                    app_code: "leadzump".into(),
                    client_code: "SYSTEM".into(),
                };
                let mut p = fep().set_arguments(kirun::Map::from([("a".to_string(), json!(1)), ("n".to_string(), Value::Null)]));
                let r = f.execute(&mut p).await.map(|mut o| o.next());
                (r, crate::context::request().and_then(|c| c.raised.lock().clone()))
            }
        };
        let ctx = request(user(&[]), false, None);
        crate::context::with_request(ctx, async {
            let (r, _) = run("Create").await;
            let er = r.unwrap().unwrap();
            // Nulls are left out of the body, as Gson writes it.
            assert_eq!(er.get_result()["body"], json!({"a": 1}));
            let (r, raised) = run("Empty").await;
            assert_eq!(r.unwrap_err().to_string(), "The function EP.Campaign.Empty returned an empty response.");
            assert_eq!(raised.unwrap().status(), StatusCode::INTERNAL_SERVER_ERROR);
            let (r, raised) = run("Fail").await;
            assert_eq!(r.unwrap_err().to_string(), "refused");
            assert_eq!(raised.unwrap().status(), StatusCode::BAD_REQUEST);
            let (r, _) = run("Other").await;
            assert!(r.is_err());
        })
        .await;
    }
}
