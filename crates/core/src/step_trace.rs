//! KIRun step traces: what kirun-java 4.9.2's `KIRuntimeStepTrace` records on a step's error (the
//! function the step is in, the step, the function the step called, and its arguments as
//! bounded, masked JSON), so `EventRunService.errorOf` / `detailOf` can name the step a failed
//! event task came out of, and a failed execution can name the step it failed in
//! (`CORE.FUNCTION_STEP_FAILED`, see `exec::run`).
//!
//! kirun-rust has no step trace, and its errors are text, so nothing can ride on the error.
//! Instead the traces are collected beside the run, only inside [`traced`]:
//!
//! - [`instrument`]: `DefinitionFunction` hands its runtime a function repository that wraps
//!   every function it finds, so each step's function runs through [`TracedStep`]. A step that
//!   fails adds its trace, after the traces of the steps that failed inside it (a nested
//!   definition's), which reads innermost first, as kirun-java collects them.
//! - [`in_definition`]: around the runtime, names the definition the steps are in, and when the
//!   runtime fails without any step having failed, looks for the step whose argument expression
//!   could not be evaluated ("before its arguments were evaluated").
//!
//! Each step runs in its own frame (a task-local scope, so steps the runtime runs together keep
//! theirs apart): a step or definition that succeeds drops what failed inside it, because that
//! error was handled and is not the one the run failed with; one that fails hands its frame up.
//! Outside [`traced`] both hooks do nothing.

use std::any::Any;
use std::future::Future;
use std::sync::{Arc, Weak};

use async_trait::async_trait;
use kirun::function::Function;
use kirun::json::schema::Schema;
use kirun::model::{Event, FunctionDefinition, FunctionOutput, FunctionSignature, ParameterReferenceType, Statement};
use kirun::repository::Repository;
use kirun::runtime::FunctionExecutionParameters;
use kirun::{Map, Value};
use overridable::java_map;
use parking_lot::Mutex;

use crate::gson::element_to_string;

/// Most traces one run collects (kirun-java: per error).
pub const MAX_TRACES: usize = 20;
pub const MAX_ARGUMENTS_LENGTH: usize = 2000;
pub const MAX_STRING_LENGTH: usize = 200;
pub const MAX_ITEMS: usize = 10;
pub const MAX_DEPTH: usize = 4;

/// The second line of a trace whose step failed while its arguments were worked out.
pub const BEFORE_ARGUMENTS: &str = "before its arguments were evaluated";

/// Where in a KIRun function an error was raised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepTrace {
    /// The function definition the step is in, namespace.name.
    pub function_name: String,
    pub statement_name: String,
    /// The function the step called, namespace.name.
    pub step_function: String,
    /// The step's arguments as bounded, masked JSON; `None` when they were never worked out.
    pub arguments: Option<String>,
}

impl StepTrace {
    /// `KIRuntimeStepTrace.getMessage()`: where, then the arguments.
    pub fn message(&self) -> String {
        match &self.arguments {
            Some(a) => format!("{}\narguments {a}", self.location()),
            None => format!("{}\n{BEFORE_ARGUMENTS}", self.location()),
        }
    }

    /// The first line: `at step <statement> (<step function>) of <function>`.
    pub fn location(&self) -> String {
        format!("at step {} ({}) of {}", self.statement_name, self.step_function, self.function_name)
    }
}

// ------------------------------------------------------------------ the arguments text

/// `String.length()`: UTF-16 code units.
pub(crate) fn len16(s: &str) -> usize {
    s.encode_utf16().count()
}

/// `s.substring(0, n)` in UTF-16 code units, stopping short of a split surrogate pair.
pub(crate) fn prefix16(s: &str, n: usize) -> &str {
    let mut units = 0;
    for (i, c) in s.char_indices() {
        if units + c.len_utf16() > n {
            return &s[..i];
        }
        units += c.len_utf16();
    }
    s
}

/// What the Java code does to a long text: the first `max - 1` units and `…`.
pub(crate) fn truncate16(s: String, max: usize) -> String {
    if len16(&s) <= max {
        return s;
    }
    format!("{}…", prefix16(&s, max - 1))
}

/// `SECRET_KEY.matcher(key.toLowerCase(Locale.ROOT)).find()`:
/// `password|passwd|secret|token|api[-_]?key|authorization|cookie|credential|private[-_]?key`.
fn is_secret_key(key: &str) -> bool {
    let k = key.to_lowercase();
    [
        "password", "passwd", "secret", "token", "apikey", "api-key", "api_key", "authorization", "cookie", "credential",
        "privatekey", "private-key", "private_key",
    ]
    .iter()
    .any(|p| k.contains(p))
}

/// `KIRuntimeStepTrace.argumentsText`: `{"key": value, ...}`, nested values bounded in depth,
/// items and string length, secret-looking keys masked, the whole at most 2000 units.
pub fn arguments_text<'a>(entries: impl IntoIterator<Item = (&'a str, &'a Value)>) -> String {
    let mut sb = String::from("{");
    for (n, (key, value)) in entries.into_iter().enumerate() {
        if n > 0 {
            sb.push_str(", ");
        }
        append_key_value(&mut sb, key, value, 1);
        if len16(&sb) > MAX_ARGUMENTS_LENGTH {
            break;
        }
    }
    sb.push('}');
    truncate16(sb, MAX_ARGUMENTS_LENGTH)
}

fn append_key_value(sb: &mut String, key: &str, value: &Value, depth: usize) {
    sb.push_str(&element_to_string(&Value::String(key.to_string())));
    sb.push_str(": ");
    if is_secret_key(key) && !value.is_null() {
        sb.push_str("\"***\"");
    } else {
        append_value(sb, value, depth);
    }
}

fn append_value(sb: &mut String, value: &Value, depth: usize) {
    match value {
        Value::String(s) if len16(s) > MAX_STRING_LENGTH => {
            let cut = format!("{}… ({} chars)", prefix16(s, MAX_STRING_LENGTH), len16(s));
            sb.push_str(&element_to_string(&Value::String(cut)));
        }
        Value::Array(a) => append_array(sb, a, depth),
        Value::Object(o) => append_object(sb, o, depth),
        other => sb.push_str(&element_to_string(other)),
    }
}

fn append_array(sb: &mut String, array: &[Value], depth: usize) {
    if depth >= MAX_DEPTH {
        sb.push_str(&format!("[… {} items]", array.len()));
        return;
    }
    sb.push('[');
    for (n, item) in array.iter().enumerate() {
        if n == MAX_ITEMS {
            sb.push_str(&format!(", … {} more", array.len() - n));
            break;
        }
        if n > 0 {
            sb.push_str(", ");
        }
        append_value(sb, item, depth + 1);
    }
    sb.push(']');
}

fn append_object(sb: &mut String, object: &serde_json::Map<String, Value>, depth: usize) {
    if depth >= MAX_DEPTH {
        sb.push_str(&format!("{{… {} keys}}", object.len()));
        return;
    }
    sb.push('{');
    for (n, (k, v)) in object.iter().enumerate() {
        if n == MAX_ITEMS * 2 {
            sb.push_str(&format!(", … {} more keys", object.len() - n));
            break;
        }
        if n > 0 {
            sb.push_str(", ");
        }
        append_key_value(sb, k, v, depth + 1);
    }
    sb.push('}');
}

/// The arguments kirun-java's runtime hands a step: the statement's parameters that have
/// references and a non-null value, in the order of the `HashMap` `Collectors.toMap` fills.
/// Taken from what the step's function holds when it fails, which for a function validated
/// against its signature is its validated arguments.
fn step_arguments<'a>(s: &Statement, args: Option<&'a Map<Value>>) -> Vec<(&'a str, &'a Value)> {
    let Some(args) = args else { return Vec::new() };
    let mut present: Vec<(&'a str, &'a Value)> = s
        .get_parameter_map()
        .iter()
        .filter(|(_, refs)| !refs.is_empty())
        .filter_map(|(k, _)| args.get_key_value(k.as_str()))
        .filter(|(_, v)| !v.is_null())
        .map(|(k, v)| (k.as_str(), v))
        .collect();
    let capacity = java_map::capacity_by_puts(present.len());
    present.sort_by_key(|(k, _)| java_map::bucket(k, capacity));
    present
}

// ------------------------------------------------------------------ collecting

/// The traces of one step, definition or run, innermost first.
#[derive(Default)]
struct Frame {
    traces: Mutex<Vec<StepTrace>>,
}

impl Frame {
    fn add(&self, more: impl IntoIterator<Item = StepTrace>) {
        let mut t = self.traces.lock();
        for trace in more {
            if t.len() >= MAX_TRACES {
                break;
            }
            t.push(trace);
        }
    }

    fn take(&self) -> Vec<StepTrace> {
        std::mem::take(&mut *self.traces.lock())
    }
}

/// One [`traced`] run: the repositories already wrapped, so a nested definition (which runs on
/// its caller's repository) does not wrap them again.
#[derive(Default)]
struct Run {
    repositories: Mutex<Vec<Weak<TracedRepository>>>,
}

tokio::task_local! {
    static RUN: Arc<Run>;
    static FRAME: Arc<Frame>;
    static DEFINITION: Arc<str>;
}

/// Runs `fut` (one event task) collecting the KIRun step traces of its failure, innermost
/// first, at most [`MAX_TRACES`]. Empty when it succeeded, failed outside a KIRun definition, or
/// failed in a way no step accounts for.
pub async fn traced<F: Future>(fut: F) -> (F::Output, Vec<StepTrace>) {
    let frame = Arc::new(Frame::default());
    let out = RUN.scope(Arc::new(Run::default()), FRAME.scope(frame.clone(), fut)).await;
    (out, frame.take())
}

/// Whether the caller runs inside [`traced`].
pub fn is_tracing() -> bool {
    FRAME.try_with(|_| ()).is_ok()
}

/// The traces collected so far in the current frame, innermost first (empty outside
/// [`traced`]); what an execution that runs inside an outer [`traced`] (an event task) reads
/// after it failed, leaving them for the outer one.
pub fn peek() -> Vec<StepTrace> {
    FRAME.try_with(|f| f.traces.lock().clone()).unwrap_or_default()
}

/// `DefinitionFunction`, before it starts its runtime: inside [`traced`], the parameters with
/// a function repository whose functions record a trace when they fail; otherwise as given.
pub fn instrument(params: FunctionExecutionParameters) -> FunctionExecutionParameters {
    let Ok(run) = RUN.try_with(Arc::clone) else { return params };
    let current = params.get_function_repository().clone();
    let address = Arc::as_ptr(&current) as *const () as usize;
    let traced = {
        let mut known = run.repositories.lock();
        known.retain(|w| w.strong_count() > 0);
        if known.iter().any(|w| w.as_ptr() as *const () as usize == address) {
            return params;
        }
        let traced = Arc::new(TracedRepository { inner: current });
        known.push(Arc::downgrade(&traced));
        traced
    };
    params.set_function_repository(traced)
}

/// `DefinitionFunction`, around its runtime: the definition's steps are traced as steps of
/// `fd`, and a failure no step accounts for is put on the step whose argument expression the
/// error names, if one does.
pub async fn in_definition<T, F>(fd: &FunctionDefinition, fut: F) -> kirun::Result<T>
where
    F: Future<Output = kirun::Result<T>>,
{
    let Ok(parent) = FRAME.try_with(Arc::clone) else { return fut.await };
    let signature = fd.get_signature();
    let name: Arc<str> = if signature.get_namespace().is_empty() {
        signature.get_name().into()
    } else {
        format!("{}.{}", signature.get_namespace(), signature.get_name()).into()
    };
    let frame = Arc::new(Frame::default());
    let result = DEFINITION.scope(name.clone(), FRAME.scope(frame.clone(), fut)).await;
    if let Err(e) = &result {
        let mut traces = frame.take();
        if traces.is_empty() {
            traces.extend(before_arguments(fd, &name, &e.to_string()));
        }
        parent.add(traces);
    }
    result
}

/// kirun-java traces a step whose argument expression throws, with no arguments. kirun-rust's
/// error is the expression's (`<expression> : <message>`, or `Expression : <expression>
/// evaluated to ...`) and names no step: the step is the first in the definition with an
/// `EXPRESSION` argument the error quotes.
fn before_arguments(fd: &FunctionDefinition, function_name: &str, error: &str) -> Option<StepTrace> {
    let quoted = normalize(error);
    let head = error.split(" : ").next().map(normalize).filter(|h| h.len() >= 3);
    for s in fd.get_steps().values() {
        let named = s.get_parameter_map().values().flat_map(|refs| refs.values()).any(|r| {
            if r.get_type() != ParameterReferenceType::Expression {
                return false;
            }
            let Some(x) = r.get_expression().map(normalize).filter(|x| !x.is_empty()) else { return false };
            quoted.contains(&x) || head.as_ref().is_some_and(|h| x.contains(h.as_str()))
        });
        if named {
            return Some(StepTrace {
                function_name: function_name.to_string(),
                statement_name: s.get_statement_name().to_string(),
                step_function: format!("{}.{}", s.get_namespace(), s.get_name()),
                arguments: None,
            });
        }
    }
    None
}

/// An expression's text without the white space and brackets kirun-rust's printed form adds
/// or drops.
fn normalize(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace() && *c != '(' && *c != ')').collect()
}

/// The repository a traced definition's runtime finds its steps' functions in.
struct TracedRepository {
    inner: Arc<dyn Repository<dyn Function>>,
}

#[async_trait]
impl Repository<dyn Function> for TracedRepository {
    async fn find(&self, namespace: &str, name: &str) -> Option<Arc<dyn Function>> {
        let inner = self.inner.find(namespace, name).await?;
        Some(Arc::new(TracedStep { inner }))
    }

    async fn filter(&self, name: &str) -> Vec<String> {
        self.inner.filter(name).await
    }
}

/// A step's function: the function itself, and a trace when it fails.
struct TracedStep {
    inner: Arc<dyn Function>,
}

impl TracedStep {
    fn trace(&self, function_name: String, context: &FunctionExecutionParameters) -> StepTrace {
        match context.get_statement_execution() {
            Some(se) => {
                let s = se.get_statement();
                StepTrace {
                    function_name,
                    statement_name: s.get_statement_name().to_string(),
                    step_function: format!("{}.{}", s.get_namespace(), s.get_name()),
                    arguments: Some(arguments_text(step_arguments(s, context.get_arguments()))),
                }
            }
            None => {
                let sig = self.inner.get_signature();
                StepTrace {
                    function_name,
                    statement_name: String::new(),
                    step_function: format!("{}.{}", sig.get_namespace(), sig.get_name()),
                    arguments: Some(arguments_text(
                        context.get_arguments().into_iter().flatten().filter(|(_, v)| !v.is_null()).map(|(k, v)| (k.as_str(), v)),
                    )),
                }
            }
        }
    }
}

#[async_trait]
impl Function for TracedStep {
    fn get_signature(&self) -> &FunctionSignature {
        self.inner.get_signature()
    }

    fn get_probable_event_signature(&self, probable_parameters: &Map<Vec<Schema>>) -> Map<Event> {
        self.inner.get_probable_event_signature(probable_parameters)
    }

    async fn execute(&self, context: &mut FunctionExecutionParameters) -> kirun::Result<FunctionOutput> {
        let Ok(parent) = FRAME.try_with(Arc::clone) else { return self.inner.execute(context).await };
        let definition = DEFINITION.try_with(|d| d.to_string()).unwrap_or_default();
        let frame = Arc::new(Frame::default());
        let result = FRAME.scope(frame.clone(), self.inner.execute(context)).await;
        if result.is_err() {
            parent.add(frame.take());
            parent.add([self.trace(definition, context)]);
        }
        result
    }

    fn as_any(&self) -> Option<&dyn Any> {
        self.inner.as_any()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use kirun::hybrid_repository::HybridRepository;
    use kirun::model::FunctionOutput;
    use kirun::repository::{KIRunFunctionRepository, KIRunSchemaRepository};
    use kirun::runtime::FunctionExecutionParameters;
    use serde_json::json;

    use crate::repos::definition::DefinitionFunction;

    /// A function that fails with `ConcurrentModificationException`, `items` (any) and
    /// `password` (a string) its parameters, like kirun-java's test `Test.Explode`.
    struct Explode {
        sig: FunctionSignature,
    }

    impl Explode {
        fn new() -> Self {
            let fd = FunctionDefinition::from_value(&json!({
                "name": "Explode", "namespace": "Test",
                "parameters": {
                    "items": {"parameterName": "items", "schema": {"name": "items"}},
                    "password": {"parameterName": "password", "schema": {"name": "password", "type": "STRING"}}
                },
                "events": {"output": {"name": "output", "parameters": {}}}
            }))
            .unwrap();
            Self { sig: fd.get_signature().clone() }
        }
    }

    #[async_trait]
    impl Function for Explode {
        fn get_signature(&self) -> &FunctionSignature {
            &self.sig
        }
        async fn execute(&self, _: &mut FunctionExecutionParameters) -> kirun::Result<FunctionOutput> {
            Err(kirun::KIRunError::runtime("java.util.ConcurrentModificationException"))
        }
    }

    struct Repo {
        defs: Vec<Arc<DefinitionFunction>>,
        explode: Arc<Explode>,
    }

    #[async_trait]
    impl Repository<dyn Function> for Repo {
        async fn find(&self, namespace: &str, name: &str) -> Option<Arc<dyn Function>> {
            if (namespace, name) == ("Test", "Explode") {
                return Some(self.explode.clone());
            }
            self.defs
                .iter()
                .find(|d| d.get_signature().get_namespace() == namespace && d.get_signature().get_name() == name)
                .map(|d| d.clone() as Arc<dyn Function>)
        }
        async fn filter(&self, _: &str) -> Vec<String> {
            Vec::new()
        }
    }

    fn definition(v: Value) -> Arc<DefinitionFunction> {
        Arc::new(DefinitionFunction::new(v, None, None, Duration::from_secs(5)).unwrap())
    }

    /// kirun-java's test definition: `Leads.syncAll` with a step `sortLeads` calling the
    /// failing function, its `items` parameter `items_ref`.
    fn sync_all(items_ref: Value) -> Value {
        json!({
            "name": "syncAll", "namespace": "Leads",
            "steps": {
                "sortLeads": {
                    "statementName": "sortLeads", "namespace": "Test", "name": "Explode",
                    "parameterMap": {
                        "items": {"one": items_ref},
                        "password": {"two": {"key": "two", "type": "VALUE", "value": "hunter2"}}
                    }
                }
            }
        })
    }

    async fn run(top: Arc<DefinitionFunction>, others: Vec<Arc<DefinitionFunction>>) -> (kirun::Result<FunctionOutput>, Vec<StepTrace>) {
        let repo: Arc<dyn Repository<dyn Function>> = Arc::new(HybridRepository::new(vec![
            Arc::new(KIRunFunctionRepository::new()) as Arc<dyn Repository<dyn Function>>,
            Arc::new(Repo { defs: others, explode: Arc::new(Explode::new()) }),
        ]));
        let mut fep = FunctionExecutionParameters::new(repo, Arc::new(KIRunSchemaRepository::new()));
        traced(async move { top.execute(&mut fep).await }).await
    }

    // Port of kirun-java `KIRuntimeStepTraceTest`.

    #[tokio::test]
    async fn the_failing_step_and_its_arguments_ride_on_the_error() {
        let (r, traces) = run(definition(sync_all(json!({"key": "one", "type": "VALUE", "value": [3, 1, 2]}))), vec![]).await;
        // The function's own error, unchanged.
        assert_eq!(r.err().unwrap().to_string(), "java.util.ConcurrentModificationException");
        assert_eq!(traces.len(), 1);
        let t = &traces[0];
        assert_eq!((t.function_name.as_str(), t.statement_name.as_str(), t.step_function.as_str()), ("Leads.syncAll", "sortLeads", "Test.Explode"));
        let a = t.arguments.as_deref().unwrap();
        assert!(a.contains("\"items\": [3, 1, 2]"), "{a}");
        assert!(a.contains("\"password\": \"***\""), "{a}");
        assert!(!a.contains("hunter2"), "{a}");
        assert!(t.message().starts_with("at step sortLeads (Test.Explode) of Leads.syncAll\narguments {"), "{}", t.message());
    }

    #[tokio::test]
    async fn an_argument_that_cannot_be_evaluated_names_the_step_without_arguments() {
        let (r, traces) = run(definition(sync_all(json!({"key": "one", "type": "EXPRESSION", "expression": "Arguments.a +"}))), vec![]).await;
        let e = r.err().unwrap().to_string();
        assert_eq!(traces.len(), 1, "{e}");
        assert_eq!(traces[0].statement_name, "sortLeads");
        assert_eq!(traces[0].arguments, None);
        assert_eq!(traces[0].message(), "at step sortLeads (Test.Explode) of Leads.syncAll\nbefore its arguments were evaluated");
    }

    #[test]
    fn arguments_are_bounded() {
        let list = Value::Array((0..50).map(Value::from).collect());
        let text = Value::String("x".repeat(500));
        let a = arguments_text([("list", &list), ("text", &text)]);
        assert!(a.contains("9, … 40 more]"), "{a}");
        assert!(a.contains("… (500 chars)"), "{a}");
    }

    #[tokio::test]
    async fn one_run_collects_at_most_twenty_traces() {
        let f = Frame::default();
        let t = StepTrace { function_name: "F".into(), statement_name: "s".into(), step_function: "N.f".into(), arguments: Some("{}".into()) };
        f.add(std::iter::repeat(t).take(30));
        assert_eq!(f.take().len(), MAX_TRACES);
    }

    // ------------------------------------------------------------------ beyond the Java tests

    #[tokio::test]
    async fn nested_definitions_read_innermost_first() {
        // Leads.sortAll's step fails; Leads.syncAll called it from its step `sort`.
        let sort_all = definition(json!({
            "name": "sortAll", "namespace": "Leads",
            "parameters": {"leads": {"parameterName": "leads", "schema": {"name": "leads", "type": "ARRAY"}}},
            "steps": {"sortLeads": {"statementName": "sortLeads", "namespace": "Test", "name": "Explode",
                "parameterMap": {"items": {"one": {"key": "one", "type": "EXPRESSION", "expression": "Arguments.leads"}},
                                 "password": {"two": {"key": "two", "type": "VALUE", "value": "hunter2"}}}}}
        }));
        let sync_all = definition(json!({
            "name": "syncAll", "namespace": "Leads",
            "steps": {"sort": {"statementName": "sort", "namespace": "Leads", "name": "sortAll",
                "parameterMap": {"leads": {"one": {"key": "one", "type": "VALUE", "value": [3, 1, 2]}}}}}
        }));
        let (r, traces) = run(sync_all, vec![sort_all]).await;
        let e = r.err().unwrap().to_string();
        let messages: Vec<String> = traces.iter().map(StepTrace::message).collect();
        assert_eq!(
            messages,
            [
                // Java's HashMap order: "password" hashes to bucket 2 of 16, "items" to 13.
                "at step sortLeads (Test.Explode) of Leads.sortAll\narguments {\"password\": \"***\", \"items\": [3, 1, 2]}",
                "at step sort (Leads.sortAll) of Leads.syncAll\narguments {\"leads\": [3, 1, 2]}",
            ],
            "{e}"
        );
    }

    /// An execution inside an outer `traced` (an event task) reads the traces after it failed
    /// and leaves them for the outer one.
    #[tokio::test]
    async fn peek_reads_without_taking() {
        assert!(peek().is_empty(), "outside traced");
        let top = definition(sync_all(json!({"key": "one", "type": "VALUE", "value": [1]})));
        let repo: Arc<dyn Repository<dyn Function>> = Arc::new(HybridRepository::new(vec![
            Arc::new(KIRunFunctionRepository::new()) as Arc<dyn Repository<dyn Function>>,
            Arc::new(Repo { defs: vec![], explode: Arc::new(Explode::new()) }),
        ]));
        let (seen, outer) = traced(async move {
            let mut fep = FunctionExecutionParameters::new(repo, Arc::new(KIRunSchemaRepository::new()));
            let _ = top.execute(&mut fep).await;
            peek()
        })
        .await;
        assert_eq!(seen.len(), 1);
        assert_eq!(seen, outer);
        assert_eq!(seen[0].location(), "at step sortLeads (Test.Explode) of Leads.syncAll");
    }

    #[tokio::test]
    async fn nothing_is_traced_when_the_run_succeeds_or_outside_traced() {
        let add = definition(json!({
            "name": "addOne", "namespace": "Test",
            "steps": {"add": {"statementName": "add", "namespace": "System.Math", "name": "Add",
                "parameterMap": {"value": {"one": {"key": "one", "type": "VALUE", "value": 1, "order": 1}}}}}
        }));
        let (r, traces) = run(add, vec![]).await;
        assert!(r.is_ok());
        assert!(traces.is_empty());

        // Outside `traced` the definition runs on the repository it was given.
        let failing = definition(sync_all(json!({"key": "one", "type": "VALUE", "value": [1]})));
        let mut fep = FunctionExecutionParameters::new(
            Arc::new(Repo { defs: vec![], explode: Arc::new(Explode::new()) }),
            Arc::new(KIRunSchemaRepository::new()),
        );
        assert!(!is_tracing());
        assert!(failing.execute(&mut fep).await.is_err());
    }

    #[tokio::test]
    async fn a_failure_no_step_accounts_for_has_no_trace() {
        // The plan refuses a step whose function does not exist: no step ran.
        let broken = definition(json!({"name": "broken", "namespace": "Test",
            "steps": {"x": {"statementName": "x", "namespace": "Nope", "name": "Nothing"}}}));
        let (r, traces) = run(broken, vec![]).await;
        assert!(r.is_err());
        assert!(traces.is_empty(), "{traces:?}");
    }

    #[test]
    fn texts_follow_gson_and_java_lengths() {
        let nested = json!({"a": {"b": {"c": {"d": {"e": 1}}}}, "list": [[[[1, 2]]]], "token": null, "apiKey": "k", "Private_Key": "p"});
        let entries: Vec<(&str, &Value)> = nested.as_object().unwrap().iter().map(|(k, v)| (k.as_str(), v)).collect();
        assert_eq!(
            arguments_text(entries),
            r#"{"a": {"b": {"c": {"d": {… 1 keys}}}}, "list": [[[[… 2 items]]]], "token": null, "apiKey": "***", "Private_Key": "***"}"#
        );
        // Strings are escaped as `JsonElement.toString()` escapes them; doubles as Java writes them.
        let v = json!({"s": "a\"b\n<", "d": 2.0, "big": 1e7});
        let entries: Vec<(&str, &Value)> = v.as_object().unwrap().iter().map(|(k, v)| (k.as_str(), v)).collect();
        assert_eq!(arguments_text(entries), r#"{"s": "a\"b\n<", "d": 2.0, "big": 1.0E7}"#);
        // Twenty keys of an object, then a count.
        let wide: serde_json::Map<String, Value> = (0..25).map(|i| (format!("k{i}"), json!(i))).collect();
        let wide = Value::Object(wide);
        let a = arguments_text([("w", &wide)]);
        assert!(a.ends_with(r#""k19": 19, … 5 more keys}}"#), "{a}");
        // The whole is cut at 2000 units with an ellipsis.
        let many: Vec<(String, Value)> = (0..40).map(|i| (format!("key{i}"), Value::String("y".repeat(150)))).collect();
        let a = arguments_text(many.iter().map(|(k, v)| (k.as_str(), v)));
        assert_eq!(len16(&a), MAX_ARGUMENTS_LENGTH);
        assert!(a.ends_with('…'));
        // Lengths are UTF-16 units: a string of 150 emoji is 300 units.
        let emoji = Value::String("😀".repeat(150));
        let a = arguments_text([("e", &emoji)]);
        assert!(a.contains("… (300 chars)"), "{a}");
        assert_eq!(truncate16("abc".into(), 3), "abc");
        assert_eq!(truncate16("abcd".into(), 3), "ab…");
    }

    #[test]
    fn top_level_arguments_follow_the_hash_map_order() {
        let s = Statement::from_value(&json!({"statementName": "s", "namespace": "N", "name": "f",
            "parameterMap": {"alpha": {"a": {"key": "a", "type": "VALUE", "value": 2}},
                             "zeta": {"a": {"key": "a", "type": "VALUE", "value": 1}},
                             "empty": {},
                             "gone": {"a": {"key": "a", "type": "VALUE", "value": 3}}}}))
        .unwrap();
        let args: Map<Value> = [("alpha", json!(2)), ("zeta", json!(1)), ("gone", Value::Null), ("extra", json!(4))]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        let keys: Vec<&str> = step_arguments(&s, Some(&args)).into_iter().map(|(k, _)| k).collect();
        // A HashMap of 16 buckets: "zeta".hashCode() lands in bucket 0, "alpha" in bucket 7.
        assert_eq!(keys, ["zeta", "alpha"]);
    }
}
