//! `CoreServices.Report` (CXZ-1780): the platform report runner. Rust only, no Java counterpart.
//!
//! - `CoreServices.Report.Run(spec, catalog, scope, force, dryRun, appCode, clientCode)`: validates a
//!   report spec against the app's catalog and runs it as one storage aggregate (a page read for a
//!   list, or the catalog's function), answering `{"ok": true, "columns", "rows", ...}` or
//!   `{"ok": false, "error": {"code", "message", "path"}}` (CONTRACT section 3).
//! - `CoreServices.Report.Validate(...)`: Run with `dryRun`.
//! - `CoreServices.Report.ViewTypes()`: the "Show me" shape rules ([`shape`]) for the UI's picker.
//!
//! Run and Validate are reachable only inside a KIRun definition (an app's `reportRun` wrapper,
//! which adds the row scope), like the storages they read: a direct execute call is refused.

pub mod exec;
pub mod period;
pub mod shape;
pub mod spec;

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::sync::Arc;

use appdata::model::{AggregateQuery, Query, Sort};
use async_trait::async_trait;
use kirun::function::{validate_arguments, Function};
use kirun::json::schema::Schema;
use kirun::model::{Event, FunctionOutput, FunctionSignature, Parameter};
use kirun::repository::Repository;
use kirun::runtime::FunctionExecutionParameters;
use kirun::{Map, Value};

use self::exec::{FunctionCaller, ReportBackend, RunRequest};
use self::spec::Obj;
use crate::clients::SecurityCalls;
use crate::context;
use crate::error::CoreError;
use crate::functions::support::server_function_only;
use crate::functions::{output, CoreFunction};
use crate::storage::service::AppDataService;
use crate::storage::values::{gson_object, storage_value};

pub const NAMESPACE: &str = "CoreServices.Report";

fn p(name: &str, schema: Schema) -> (String, Parameter) {
    Parameter::of_entry(name, schema, false)
}

fn result_events() -> Map<Event> {
    Map::from([Event::output_event_map_entry(Map::from([("result".to_string(), Schema::of_any("result"))]))])
}

fn run_signature(name: &str) -> FunctionSignature {
    FunctionSignature::new(name)
        .set_namespace(NAMESPACE)
        .set_parameters(
            vec![
                p("spec", Schema::of_object("spec")),
                p("catalog", Schema::of_object("catalog")),
                p("scope", Schema::of_any("scope").set_default_value(Value::Null)),
                p("force", Schema::of_boolean("force").set_default_value(Value::Bool(false))),
                p("dryRun", Schema::of_boolean("dryRun").set_default_value(Value::Bool(false))),
                p("appCode", Schema::of_string("appCode").set_default_value(Value::String(String::new()))),
                p("clientCode", Schema::of_string("clientCode").set_default_value(Value::String(String::new()))),
            ]
            .into_iter()
            .collect(),
        )
        .set_events(result_events())
}

/// `Run` or `Validate`.
pub struct ReportFunction {
    signature: FunctionSignature,
    validate_only: bool,
    backend: Arc<dyn ReportBackend>,
}

impl ReportFunction {
    pub fn run(backend: Arc<dyn ReportBackend>) -> Self {
        Self { signature: run_signature("Run"), validate_only: false, backend }
    }

    pub fn validate(backend: Arc<dyn ReportBackend>) -> Self {
        Self { signature: run_signature("Validate"), validate_only: true, backend }
    }
}

fn flag(args: &Map<Value>, name: &str) -> bool {
    matches!(args.get(name), Some(Value::Bool(true)))
}

fn text(args: &Map<Value>, name: &str) -> Option<String> {
    args.get(name).and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string)
}

#[async_trait]
impl Function for ReportFunction {
    fn get_signature(&self) -> &FunctionSignature {
        &self.signature
    }

    async fn execute(&self, context: &mut FunctionExecutionParameters) -> kirun::Result<FunctionOutput> {
        let args = validate_arguments(
            &self.signature,
            context.get_arguments().cloned().unwrap_or_default(),
            context.get_schema_repository().as_ref(),
            context.get_statement_execution().map(|s| s.as_ref()),
        )
        .await?;
        context.set_arguments_in_place(args.clone());
        if !context::in_kirun() {
            return Err(context::raise(server_function_only(&self.signature.get_full_name())));
        }
        let caller = RepoCaller {
            functions: context.get_function_repository().clone(),
            schemas: context.get_schema_repository().clone(),
            execution_id: context.get_execution_id().to_string(),
        };
        let auth = context::authentication();
        let null = Value::Null;
        let out = exec::run(
            RunRequest {
                spec: args.get("spec").unwrap_or(&null),
                catalog: args.get("catalog").unwrap_or(&null),
                scope: args.get("scope").unwrap_or(&null),
                force: flag(&args, "force"),
                dry_run: self.validate_only || flag(&args, "dryRun"),
                app_code: text(&args, "appCode"),
                client_code: text(&args, "clientCode"),
                user_id: auth.user_id(),
                authorities: auth.authorities(),
                now: chrono::Utc::now(),
            },
            self.backend.as_ref(),
            &caller,
        )
        .await;
        Ok(output("result", out))
    }
}

/// `CoreServices.Report.ViewTypes`: the shape rules table.
pub struct ViewTypes {
    signature: FunctionSignature,
}

impl Default for ViewTypes {
    fn default() -> Self {
        Self { signature: FunctionSignature::new("ViewTypes").set_namespace(NAMESPACE).set_events(result_events()) }
    }
}

#[async_trait]
impl CoreFunction for ViewTypes {
    fn signature(&self) -> &FunctionSignature {
        &self.signature
    }

    async fn internal_execute(&self, _: &Map<Value>) -> Result<FunctionOutput, CoreError> {
        Ok(output("result", shape::rules_json()))
    }
}

/// Calls a definition through the running definition's own repositories.
struct RepoCaller {
    functions: Arc<dyn Repository<dyn Function>>,
    schemas: Arc<dyn Repository<Schema>>,
    execution_id: String,
}

#[async_trait]
impl FunctionCaller for RepoCaller {
    async fn call(&self, full_name: &str, args: Obj) -> Result<Obj, String> {
        let (ns, name) = full_name.rsplit_once('.').ok_or_else(|| format!("'{full_name}' is not Namespace.name"))?;
        let f = self.functions.find(ns, name).await.ok_or_else(|| format!("there is no function {full_name}"))?;
        let mut fep = FunctionExecutionParameters::with_execution_id(self.functions.clone(), self.schemas.clone(), self.execution_id.clone())
            .set_arguments(args.into_iter().collect());
        let mut out = f.execute(&mut fep).await.map_err(|e| e.to_string())?;
        let mut first_error = None;
        while let Some(er) = out.next() {
            let result: Obj = er.get_result().clone().into_iter().collect();
            match er.get_name() {
                "output" => return Ok(result),
                "error" if first_error.is_none() => first_error = Some(Value::Object(result).to_string()),
                _ => {}
            }
        }
        Err(first_error.map(|e| format!("{full_name} answered an error: {e}")).unwrap_or_else(|| format!("{full_name} answered no output")))
    }
}

/// The live backend: the storage policy layer (so readAuth, onlyThruKIRun and client checks all
/// apply as for `CoreServices.Storage.*`), security for user names, Redis for the cache.
pub struct LiveBackend {
    pub storage: Arc<AppDataService>,
    pub security: Arc<SecurityCalls>,
    pub cache: platform::cache::CacheService,
}

#[async_trait]
impl ReportBackend for LiveBackend {
    async fn aggregate(&self, app: Option<&str>, client: Option<&str>, storage: &str, query: &Value) -> Result<Vec<Obj>, String> {
        let q = AggregateQuery::from_value(&storage_value(query))?;
        let page = self.storage.aggregate(app, client, storage, &q).await.map_err(|e| e.text())?;
        page.content.iter().map(|r| gson_object(r).map_err(|e| e.text())).collect()
    }

    async fn read_page(&self, app: Option<&str>, client: Option<&str>, storage: &str, query: &Value) -> Result<Vec<Obj>, String> {
        let condition = query.get("condition").cloned().unwrap_or(Value::Null);
        let mut q = Query::from_value(&storage_value(&serde_json::json!({ "condition": condition })))?;
        q.page = 0;
        q.size = query.get("size").and_then(Value::as_i64).unwrap_or(10) as i32;
        q.count = Some(false);
        if let Some(Value::Array(orders)) = query.get("sort") {
            if !orders.is_empty() {
                q.sort = Sort::from_value(&storage_value(&Value::Array(orders.clone())))?;
            }
        }
        let page = self.storage.read_page(app, client, storage, &q).await.map_err(|e| e.text())?;
        page.content.iter().map(|r| gson_object(r).map_err(|e| e.text())).collect()
    }

    async fn user_names(&self, ids: &[u64]) -> Result<HashMap<u64, String>, String> {
        if ids.is_empty() {
            return Ok(HashMap::new());
        }
        let users = self.security.users_internal_batch(ids).await.map_err(|e| e.text())?.unwrap_or_default();
        Ok(users.iter().filter_map(|u| Some((user_id(u)?, display_name(u)?))).collect())
    }

    async fn cache_get(&self, key: &str) -> Option<String> {
        self.cache.get_text(key).await
    }

    async fn cache_put(&self, key: &str, value: &str, ttl_secs: u64) {
        self.cache.set_text(key, value, ttl_secs).await;
    }

    async fn claim(&self, key: &str, ttl_secs: u64) -> Option<bool> {
        self.cache.claim(key, ttl_secs).await
    }
}

fn user_id(u: &Value) -> Option<u64> {
    match u.get("id")? {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

/// "First Last", else the user name, else the email.
pub fn display_name(u: &Value) -> Option<String> {
    let s = |k: &str| u.get(k).and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("NONE")).map(str::to_string);
    let full = [s("firstName"), s("lastName")].into_iter().flatten().collect::<Vec<_>>().join(" ");
    if !full.is_empty() {
        return Some(full);
    }
    s("userName").or_else(|| s("emailId"))
}

/// The report functions, registered after every other core family.
pub fn all(storage: &Arc<AppDataService>, security: &Arc<SecurityCalls>, cache: &platform::cache::CacheService) -> Vec<Arc<dyn Function>> {
    let backend: Arc<dyn ReportBackend> = Arc::new(LiveBackend { storage: storage.clone(), security: security.clone(), cache: cache.clone() });
    vec![
        Arc::new(ReportFunction::run(backend.clone())),
        Arc::new(ReportFunction::validate(backend)),
        Arc::new(crate::functions::Core(ViewTypes::default())),
    ]
}
