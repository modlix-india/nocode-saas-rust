//! `DefinitionFunction`: a stored function definition run by a fresh `KIRuntime`.
//!
//! - `executionAuthorization` (the document's `executeAuth`) is checked by the caller before
//!   the top-level execution, as `CoreFunctionService` does;
//! - the runtime runs with the owner app code in scope (`KIRun Owner AppCode`), so a storage
//!   step inside a function shared through an app dependency defaults to the owner's storage;
//! - it gives up after the configured timeout (five minutes in Java) with
//!   `Function execution timed out : <name>. Please try again later.`;
//! - with `x-debug` the runtime records its steps, and they are written to the log afterwards
//!   (`CoreFunctionService.logExecutionLogs`);
//! - inside `step_trace::traced` (core-events) a failing step leaves a KIRun step trace.
//!
//! Called as a step of another definition it gets parameters of its own (a fresh context,
//! steps and events, the parent's value extractors minus `Arguments.`, `Steps.` and
//! `Context.`, and the execution id `<parent>_<statement>`), as kirun-java gives every
//! `IDefinitionBasedFunction`; kirun-rust only does that for its own `KIRuntime`.

use std::any::Any;
use std::time::Duration;

use async_trait::async_trait;
use axum::http::StatusCode;
use kirun::function::{validate_arguments, AbstractFunction, Function};
use kirun::model::{FunctionDefinition, FunctionOutput, FunctionSignature};
use kirun::runtime::debug::debug_collector::DebugCollector;
use kirun::runtime::{FunctionExecutionParameters, KIRuntime};
use kirun::KIRunError;
use serde_json::Value;

use crate::context::{self, RunScope};
use crate::error::CoreError;

const NOT_INHERITED: &[&str] = &["Arguments.", "Steps.", "Context."];

pub struct DefinitionFunction {
    fd: FunctionDefinition,
    /// The stored definition (after the override merge), for `repositoryFind`.
    definition: Value,
    execution_authorization: Option<String>,
    owner_app_code: Option<String>,
    timeout: Duration,
}

impl DefinitionFunction {
    pub fn new(
        definition: Value,
        execution_authorization: Option<String>,
        owner_app_code: Option<String>,
        timeout: Duration,
    ) -> Result<Self, KIRunError> {
        let fd = FunctionDefinition::from_value(&definition)?;
        Ok(Self { fd, definition, execution_authorization, owner_app_code, timeout })
    }

    pub fn execution_authorization(&self) -> Option<&str> {
        self.execution_authorization.as_deref().filter(|a| !a.trim().is_empty())
    }

    pub fn owner_app_code(&self) -> Option<&str> {
        self.owner_app_code.as_deref()
    }

    pub fn definition_json(&self) -> &Value {
        &self.definition
    }

    pub fn full_name(&self) -> String {
        self.fd.get_signature().get_full_name()
    }

    /// The parameters a nested definition runs with.
    fn own_parameters(context: &FunctionExecutionParameters, statement: &str) -> FunctionExecutionParameters {
        let inherited = context
            .get_values_map()
            .iter()
            .filter(|(_, e)| !NOT_INHERITED.contains(&e.get_prefix()))
            .map(|(k, e)| (k.clone(), e.clone()))
            .collect();
        FunctionExecutionParameters::with_execution_id(
            context.get_function_repository().clone(),
            context.get_schema_repository().clone(),
            format!("{}_{statement}", context.get_execution_id()),
        )
        .set_arguments(context.get_arguments().cloned().unwrap_or_default())
        .set_values_map(inherited)
    }

    fn log_steps(&self, execution_id: &str, errored: bool) {
        let Some(log) = DebugCollector::get_instance().get_execution(execution_id) else {
            return;
        };
        let name = self.full_name();
        for entry in DebugCollector::get_instance().get_flat_logs(&log.execution_id) {
            if errored || entry.error.is_some() {
                tracing::error!(
                    function = name,
                    step = entry.statement_name.as_deref().unwrap_or(""),
                    r#fn = entry.function_name,
                    duration_ms = entry.duration.unwrap_or(0),
                    event = entry.event_name.as_deref().unwrap_or(""),
                    error = entry.error.as_deref().unwrap_or(""),
                    "function step"
                );
            } else {
                tracing::debug!(
                    function = name,
                    step = entry.statement_name.as_deref().unwrap_or(""),
                    r#fn = entry.function_name,
                    duration_ms = entry.duration.unwrap_or(0),
                    event = entry.event_name.as_deref().unwrap_or(""),
                    result = %entry.result,
                    "function step"
                );
            }
        }
    }
}

#[async_trait]
impl Function for DefinitionFunction {
    fn get_signature(&self) -> &FunctionSignature {
        self.fd.get_signature()
    }

    async fn execute(&self, context: &mut FunctionExecutionParameters) -> kirun::Result<FunctionOutput> {
        let mut own = match context.get_statement_execution() {
            Some(se) => Self::own_parameters(context, se.get_statement().get_statement_name()),
            None => context.clone(),
        };
        let args = validate_arguments(
            self.get_signature(),
            own.get_arguments().cloned().unwrap_or_default(),
            own.get_schema_repository().as_ref(),
            context.get_statement_execution().map(|s| s.as_ref()),
        )
        .await?;
        own.set_arguments_in_place(args);

        let debug = context::request().is_some_and(|r| r.debug.is_some());
        let runtime = KIRuntime::new(self.fd.clone(), debug)?;
        // `contextWrite` merges: a definition with no owner of its own keeps the one it runs
        // under.
        let scope = RunScope {
            owner_app_code: self
                .owner_app_code
                .clone()
                .filter(|o| !o.trim().is_empty())
                .or_else(context::owner_app_code),
        };
        let execution_id = own.get_execution_id().to_string();
        let mut own = crate::step_trace::instrument(own);
        let run = crate::step_trace::in_definition(&self.fd, context::with_run(scope, AbstractFunction::internal_execute(&runtime, &mut own)));
        let result = match tokio::time::timeout(self.timeout, run).await {
            Ok(r) => r,
            Err(_) => Err(context::raise(
                CoreError::coded(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "CORE.FUNCTION_TIMED_OUT",
                    format!("Function execution timed out : {}. Please try again later.", self.full_name()),
                )
                .param("function", self.full_name()),
            )),
        };
        if debug {
            self.log_steps(&execution_id, result.is_err());
        }
        result
    }

    fn as_any(&self) -> Option<&dyn Any> {
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use kirun::repository::{KIRunFunctionRepository, KIRunSchemaRepository};
    use serde_json::json;

    fn add_definition() -> Value {
        json!({
            "name": "addOne", "namespace": "Test",
            "parameters": {"n": {"parameterName": "n", "schema": {"type": "INTEGER"}}},
            "events": {"output": {"name": "output", "parameters": {"result": {"type": "INTEGER"}}}},
            "steps": {
                "add": {"statementName": "add", "namespace": "System.Math", "name": "Add",
                        "parameterMap": {"value": {
                            "one": {"key": "one", "type": "EXPRESSION", "expression": "Arguments.n", "order": 1},
                            "two": {"key": "two", "type": "VALUE", "value": 1, "order": 2}}}},
                "out": {"statementName": "out", "namespace": "System", "name": "GenerateEvent",
                        "parameterMap": {
                            "eventName": {"e": {"key": "e", "type": "VALUE", "value": "output"}},
                            "results": {"r": {"key": "r", "type": "VALUE", "value": {"name": "result", "value": {"isExpression": true, "value": "Steps.add.output.value"}}}}}}
            }
        })
    }

    #[tokio::test]
    async fn runs_a_definition_with_the_owner_in_scope() {
        let f = DefinitionFunction::new(add_definition(), None, Some("owner".into()), Duration::from_secs(5)).unwrap();
        let mut fep = FunctionExecutionParameters::new(
            Arc::new(KIRunFunctionRepository::new()),
            Arc::new(KIRunSchemaRepository::new()),
        )
        .set_arguments(kirun::Map::from([("n".to_string(), json!(41))]));
        let mut out = f.execute(&mut fep).await.unwrap();
        let er = out.next().unwrap();
        assert_eq!(er.get_name(), "output");
        assert_eq!(er.get_result()["result"], json!(42));
    }

    /// Port of commons-mongo `DefinitionFunctionTest`: a definition calling two others, each
    /// running with its own parameters (fresh context and steps), adds up to 13.
    #[tokio::test]
    async fn nested_definitions_run_with_their_own_parameters() {
        use async_trait::async_trait;
        use kirun::hybrid_repository::HybridRepository;
        use kirun::repository::Repository;

        fn gen(name: &str, expr: &str) -> Value {
            json!({"statementName": "genOutput", "namespace": "System", "name": "GenerateEvent",
                "parameterMap": {
                    "eventName": {"one": {"key": "one", "type": "VALUE", "value": "output"}},
                    "results": {"one": {"key": "one", "type": "VALUE",
                        "value": {"name": name, "value": {"isExpression": true, "value": expr}}}}}})
        }
        fn times(name: &str, factor: u32) -> Value {
            json!({"name": name, "namespace": "Internal",
                "parameters": {"value": {"parameterName": "value", "schema": {"name": "INTEGER", "type": "INTEGER"}}},
                "events": {"output": {"name": "output", "parameters": {"result": {"name": "result", "type": "INTEGER"}}}},
                "steps": {"genOutput": gen("result", &format!("Arguments.value * {factor}"))}})
        }
        let first = json!({"name": "First", "namespace": "Internal",
            "events": {"output": {"name": "output", "parameters": {"aresult": {"name": "aresult", "type": "INTEGER"}}}},
            "steps": {
                "exSecond": {"statementName": "exSecond", "name": "Second", "namespace": "Internal",
                    "parameterMap": {"value": {"one": {"key": "one", "type": "VALUE", "value": 2}}}},
                "exThird": {"statementName": "exThird", "name": "Third", "namespace": "Internal",
                    "parameterMap": {"value": {"one": {"key": "one", "type": "VALUE", "value": 3}}}},
                "genOutput": gen("aresult", "Steps.exSecond.output.result + Steps.exThird.output.result")}});

        struct Internal {
            second: Arc<DefinitionFunction>,
            third: Arc<DefinitionFunction>,
        }
        #[async_trait]
        impl Repository<dyn Function> for Internal {
            async fn find(&self, namespace: &str, name: &str) -> Option<Arc<dyn Function>> {
                match (namespace, name) {
                    ("Internal", "Second") => Some(self.second.clone()),
                    ("Internal", "Third") => Some(self.third.clone()),
                    _ => None,
                }
            }
            async fn filter(&self, _name: &str) -> Vec<String> {
                Vec::new()
            }
        }

        let t = Duration::from_secs(5);
        let internal = Internal {
            second: Arc::new(DefinitionFunction::new(times("Second", 2), None, None, t).unwrap()),
            third: Arc::new(DefinitionFunction::new(times("Third", 3), None, None, t).unwrap()),
        };
        let repo: Arc<dyn Repository<dyn Function>> = Arc::new(HybridRepository::new(vec![
            Arc::new(KIRunFunctionRepository::new()) as Arc<dyn Repository<dyn Function>>,
            Arc::new(internal),
        ]));
        let first = DefinitionFunction::new(first, None, None, t).unwrap();
        let mut fep = FunctionExecutionParameters::with_execution_id(repo, Arc::new(KIRunSchemaRepository::new()), "Testing");
        let mut out = first.execute(&mut fep).await.unwrap();
        assert_eq!(out.next().unwrap().get_result()["aresult"], json!(13));
    }

    #[tokio::test]
    async fn times_out_like_java() {
        let def = json!({
            "name": "slow", "namespace": "Test",
            "steps": {"w": {"statementName": "w", "namespace": "System", "name": "Wait",
                            "parameterMap": {"millis": {"m": {"key": "m", "type": "VALUE", "value": 5000}}}}}
        });
        let f = DefinitionFunction::new(def, None, None, Duration::from_millis(50)).unwrap();
        let mut fep = FunctionExecutionParameters::new(
            Arc::new(KIRunFunctionRepository::new()),
            Arc::new(KIRunSchemaRepository::new()),
        );
        let err = f.execute(&mut fep).await.err().unwrap();
        assert_eq!(err.to_string(), "Function execution timed out : Test.slow. Please try again later.");
    }

    #[tokio::test]
    async fn debug_runs_log_their_steps_and_accessors() {
        let f = DefinitionFunction::new(add_definition(), Some("  ".into()), Some("owner".into()), Duration::from_secs(5)).unwrap();
        assert_eq!(f.execution_authorization(), None);
        assert_eq!(f.owner_app_code(), Some("owner"));
        assert_eq!(f.definition_json()["name"], json!("addOne"));
        let f2 = DefinitionFunction::new(add_definition(), Some("Authorities.X".into()), None, Duration::from_secs(5)).unwrap();
        assert_eq!(f2.execution_authorization(), Some("Authorities.X"));

        let ctx = crate::testing::request(crate::testing::user(&[]), false, Some("debug-1"));
        crate::context::with_request(ctx, async {
            let mut fep = FunctionExecutionParameters::new(
                Arc::new(KIRunFunctionRepository::new()),
                Arc::new(KIRunSchemaRepository::new()),
            )
            .set_arguments(kirun::Map::from([("n".to_string(), json!(1))]));
            let mut out = f.execute(&mut fep).await.unwrap();
            assert_eq!(out.next().unwrap().get_result()["result"], json!(2));

            // A step the repository cannot find fails the run; the steps are logged as errors.
            let broken = json!({"name": "broken", "namespace": "Test",
                "steps": {"x": {"statementName": "x", "namespace": "Nope", "name": "Nothing"}}});
            let b = DefinitionFunction::new(broken, None, None, Duration::from_secs(5)).unwrap();
            let mut fep = FunctionExecutionParameters::new(
                Arc::new(KIRunFunctionRepository::new()),
                Arc::new(KIRunSchemaRepository::new()),
            );
            assert!(b.execute(&mut fep).await.is_err());
        })
        .await;
    }

    #[tokio::test]
    async fn arguments_are_validated_against_the_signature() {
        let f = DefinitionFunction::new(add_definition(), None, None, Duration::from_secs(5)).unwrap();
        let mut fep = FunctionExecutionParameters::new(
            Arc::new(KIRunFunctionRepository::new()),
            Arc::new(KIRunSchemaRepository::new()),
        )
        .set_arguments(kirun::Map::from([("n".to_string(), json!("text"))]));
        assert!(f.execute(&mut fep).await.unwrap_err().to_string().contains("Test.addOne"));
        // A definition from a newer runtime is refused when it runs.
        let newer = DefinitionFunction::new(json!({"name": "v", "namespace": "T", "version": 99}), None, None, Duration::from_secs(1)).unwrap();
        let mut fep = FunctionExecutionParameters::new(
            Arc::new(KIRunFunctionRepository::new()),
            Arc::new(KIRunSchemaRepository::new()),
        );
        assert!(newer.execute(&mut fep).await.unwrap_err().to_string().contains("lower version"));
    }

}
