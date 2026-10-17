//! `CoreFunctionService.execute` and the parts of `FunctionExecutionController` around it:
//! the repositories for the app and client, the function, its arguments (the JSON body, or
//! the query parameters converted by the parameter schemas), the execution authorization, the
//! run, and the events up to and including `output`, written as Gson writes them.

use std::sync::Arc;

use axum::http::StatusCode;
use kirun::function::Function;
use kirun::json::schema::r#type::SchemaType;
use kirun::json::schema::schema_util::SchemaUtil;
use kirun::model::Event;
use kirun::repository::Repository;
use kirun::model::FunctionOutput;
use kirun::runtime::FunctionExecutionParameters;
use kirun::{Map, Value};

use crate::authorities::{has_authority, AuthoritiesTokenExtractor};
use crate::context;
use crate::error::{messages, CoreError};
use crate::gson::to_gson;
use crate::repos::app::{app_function_repository, app_schema_repository};
use crate::repos::definition::DefinitionFunction;
use crate::repos::{FunctionRepo, FunctionSource, Hybrid, SchemaRepo, SchemaSource};
use crate::state::AppState;
use crate::step_trace;

/// Where the arguments come from.
pub enum Arguments {
    /// The POST body's members.
    Body(Map<Value>),
    /// The GET query string, decoded, in order.
    Query(Vec<(String, String)>),
}

/// The repositories one execution uses.
pub struct Repositories {
    pub functions: Arc<dyn FunctionSource>,
    pub schemas: Arc<dyn SchemaSource>,
}

/// `functionService.getFunctionRepository` + `remoteRepositoryService.getRemoteRepositories` +
/// `schemaService.getSchemaRepository`, layered for execution: KIRun, core, the app (and its
/// dependencies), entity-processor; schemas the same way.
pub async fn repositories(st: &AppState, app_code: &str, client_code: &str) -> Result<Repositories, CoreError> {
    let s = st.inner();
    let app_functions = app_function_repository(&s.definitions, app_code, client_code).await?;
    let app_schemas = app_schema_repository(&s.definitions, app_code, client_code).await?;
    let remote = s.remote.repositories(app_code, client_code).await?;

    let mut functions: Vec<Arc<dyn FunctionSource>> =
        vec![s.kirun_functions.clone(), s.core_functions.clone(), app_functions];
    let mut schemas: Vec<Arc<dyn SchemaSource>> = vec![s.kirun_schemas.clone(), s.core_schemas.clone(), app_schemas];
    if let Some(r) = remote {
        functions.push(r.functions);
        schemas.push(r.schemas);
    }
    Ok(Repositories { functions: Arc::new(Hybrid::new(functions)), schemas: Arc::new(Hybrid::new(schemas)) })
}

/// Runs `namespace.name` for the app and client and answers with the Gson text of the events
/// up to `output`.
pub async fn execute(
    st: &AppState,
    namespace: Option<&str>,
    name: &str,
    app_code: &str,
    client_code: &str,
    arguments: Arguments,
) -> Result<String, CoreError> {
    let Some(mut output) = run(st, namespace, name, app_code, client_code, arguments).await? else {
        return Err(CoreError::msg_as(
            StatusCode::NOT_FOUND,
            messages::OBJECT_NOT_FOUND,
            "CORE.FUNCTION_NOT_FOUND",
            &["Function", &format!("{}.{name}", namespace.unwrap_or("null"))],
        ));
    };

    let mut events = Vec::new();
    while let Some(er) = output.next() {
        let is_output = er.get_name() == Event::OUTPUT;
        let result: serde_json::Map<String, Value> =
            er.get_result().iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        events.push(serde_json::json!({ "name": er.get_name(), "result": result }));
        if is_output {
            break;
        }
    }
    Ok(to_gson(&Value::Array(events)))
}

/// `CoreFunctionService.execute`: the function's output, or `None` when no repository has the
/// function (Java's chain completes empty).
pub async fn run(
    st: &AppState,
    namespace: Option<&str>,
    name: &str,
    app_code: &str,
    client_code: &str,
    arguments: Arguments,
) -> Result<Option<FunctionOutput>, CoreError> {
    let repos = repositories(st, app_code, client_code).await?;
    let Some(fun) = repos.functions.find(namespace, name).await? else {
        return Ok(None);
    };
    let schema_repo: Arc<dyn Repository<kirun::json::schema::Schema>> = Arc::new(SchemaRepo(repos.schemas.clone()));

    let args = match arguments {
        Arguments::Body(m) => m,
        Arguments::Query(q) => query_arguments(fun.as_ref(), &q, schema_repo.as_ref()).await?,
    };

    let auth = context::authentication();
    if let Some(def) = fun.as_any().and_then(|a| a.downcast_ref::<DefinitionFunction>()) {
        if let Some(required) = def.execution_authorization() {
            if !has_authority(Some(required), auth.authorities()).map_err(CoreError::from)? {
                return Err(CoreError::msg(StatusCode::FORBIDDEN, messages::FORBIDDEN_EXECUTION, &[]).param("function", def.full_name()));
            }
        }
    }

    let mut fep = FunctionExecutionParameters::new(Arc::new(FunctionRepo(repos.functions.clone())), schema_repo)
        .set_arguments(args)
        .set_values_map(AuthoritiesTokenExtractor::new(auth.authorities().to_vec()).values_map());

    let run = fun.execute(&mut fep);
    // The steps the run failed in: collected here, or, inside an event task that collects
    // them itself, read from its frame and left there.
    let (result, traces) = if step_trace::is_tracing() {
        let r = run.await;
        let traces = if r.is_err() { step_trace::peek() } else { Vec::new() };
        (r, traces)
    } else {
        step_trace::traced(run).await
    };
    match result {
        Ok(output) => Ok(Some(output)),
        Err(e) => {
            let full_name = match namespace {
                Some(ns) if !ns.is_empty() => format!("{ns}.{name}"),
                _ => name.to_string(),
            };
            Err(step_failure(context::raised_or_unknown(&e), &full_name, &traces))
        }
    }
}

/// A failed run as the caller is told about it. A refusal or a missing object a function
/// raised comes up as it is (its own code). Anything else (Java answers "Please try again"
/// with the runtime's chain in `debugMessage`, which stays there) names the innermost step that
/// failed (`CORE.FUNCTION_STEP_FAILED`), or the function when no step accounts for it
/// (`CORE.FUNCTION_FAILED`); the reason is the runtime's own (a value that does not fit, an
/// expression that fails), never the detail of a fault inside a core function.
pub fn step_failure((err, raised): (CoreError, bool), function: &str, traces: &[step_trace::StepTrace]) -> CoreError {
    let CoreError::Unknown { status, debug, code: None } = err else { return err };
    if !status.is_server_error() {
        return CoreError::Unknown { status, debug, code: None };
    }
    let reason = (!raised).then(|| plain_reason(&debug)).filter(|r| !r.is_empty());
    let mut locations: Vec<String> = traces.iter().map(step_trace::StepTrace::location).collect();
    locations.dedup();
    let detail = if locations.is_empty() { debug.clone() } else { format!("{debug}\n{}", locations.join("\n")) };
    let coded = match traces.first() {
        Some(t) => {
            let c = platform::error::Coded::new("CORE.FUNCTION_STEP_FAILED").param("function", &t.function_name).param("stepFunction", &t.step_function);
            if t.statement_name.is_empty() { c } else { c.param("step", &t.statement_name) }
        }
        None => platform::error::Coded::new("CORE.FUNCTION_FAILED").param("function", function),
    };
    let coded = match reason {
        Some(r) => coded.param("reason", r),
        None => coded,
    };
    CoreError::spring(status, debug, Some(coded.debug(detail)))
}

/// Most characters of a runtime error a message repeats.
const MAX_REASON: usize = 300;

/// The runtime's error in a line: the innermost message under the "Error while executing the
/// function ..." wrappers, without schema paths, naming the parameter whose value did not fit.
pub fn plain_reason(text: &str) -> String {
    const PREFIX: &str = "Error while executing the function ";
    let mut t = text.trim_start();
    let mut parameter: Option<&str> = None;
    while let Some(rest) = t.strip_prefix(PREFIX) {
        let end = match rest.find(" [Expected: ") {
            Some(i) => rest[i..].find("]: ").map(|j| i + j + 3),
            None => rest.find(": ").map(|j| j + 2),
        };
        let Some(end) = end else { break };
        let header = &rest[..end];
        if let Some(p) = header.find("'s parameter ") {
            parameter = header[p + "'s parameter ".len()..].split([' ', ':', ']']).next().filter(|n| !n.is_empty());
        }
        t = rest[end..].trim_start();
    }
    let mut line = t.lines().next().unwrap_or("").trim();
    // Schema validation puts the path in front of each message ("source - source - ...").
    while let Some((path, rest)) = line.split_once(" - ") {
        if path.is_empty() || path.contains(char::is_whitespace) {
            break;
        }
        line = rest.trim();
    }
    let line = without_long_values(line);
    let reason = match parameter {
        Some(p) if !line.is_empty() => format!("the value of {p} is not valid ({line})"),
        Some(p) => format!("the value of {p} is not valid"),
        None => line,
    };
    match reason.char_indices().nth(MAX_REASON) {
        Some((i, _)) => format!("{}...", &reason[..i]),
        None => reason,
    }
}

/// Values a runtime message quotes, shortened: a quoted value that is long or holds JSON reads
/// as "the value given" (the whole of it stays in `debugMessage`), and no brace is left that
/// could read as a placeholder.
fn without_long_values(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(start) = rest.find('"') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        // The closing quote: the next one not escaped by a backslash.
        let mut end = None;
        let mut escaped = false;
        for (i, c) in after.char_indices() {
            match c {
                '\\' if !escaped => escaped = true,
                '"' if !escaped => {
                    end = Some(i);
                    break;
                }
                _ => escaped = false,
            }
        }
        let Some(end) = end else {
            out.push_str(&rest[start..]);
            rest = "";
            break;
        };
        let value = &after[..end];
        if value.chars().count() > 40 || value.contains(['{', '}']) {
            out.push_str("the value given");
        } else {
            out.push('"');
            out.push_str(value);
            out.push('"');
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out.replace('{', "(").replace('}', ")")
}

/// `getRequestParamsToArguments`: each signature parameter that has query values, by its
/// schema's type (a `$ref` resolved first): arrays and objects are skipped; a STRING takes the
/// text; DOUBLE, FLOAT, LONG, INTEGER (checked in that order) parse it as Java's `valueOf`
/// does; anything else (BOOLEAN, ...) is skipped. A variable argument takes every value.
pub async fn query_arguments(
    fun: &dyn Function,
    query: &[(String, String)],
    schemas: &dyn Repository<kirun::json::schema::Schema>,
) -> Result<Map<Value>, CoreError> {
    let mut out = Map::new();
    for (key, param) in fun.get_signature().get_parameters() {
        let values: Vec<&str> = query.iter().filter(|(k, _)| k == key).map(|(_, v)| v.as_str()).collect();
        if values.is_empty() {
            continue;
        }
        let schema = param.get_schema();
        let resolved;
        let schema = match schema.get_ref().filter(|r| !r.trim().is_empty()) {
            Some(r) => {
                resolved = SchemaUtil::get_schema_from_ref(schema, Some(schemas), Some(r)).await.map_err(CoreError::from)?;
                match &resolved {
                    Some(s) => s,
                    None => continue,
                }
            }
            None => schema,
        };
        let Some(t) = schema.get_type() else {
            return Err(CoreError::unknown(
                "Cannot invoke \"com.fincity.nocode.kirun.engine.json.schema.type.Type.contains(com.fincity.nocode.kirun.engine.json.schema.type.SchemaType)\" because \"type\" is null",
            ));
        };
        if t.contains(SchemaType::Array) || t.contains(SchemaType::Object) {
            continue;
        }
        let convert: fn(&str) -> Result<Value, CoreError> = if t.contains(SchemaType::String) {
            |s| Ok(Value::String(s.to_string()))
        } else if t.contains(SchemaType::Double) {
            java_number::double_value_of
        } else if t.contains(SchemaType::Float) {
            java_number::float_value_of
        } else if t.contains(SchemaType::Long) {
            java_number::long_value_of
        } else if t.contains(SchemaType::Integer) {
            java_number::integer_value_of
        } else {
            continue;
        };
        let v = if param.is_variable_argument() {
            Value::Array(values.iter().map(|s| convert(s)).collect::<Result<_, _>>()?)
        } else {
            convert(values[0])?
        };
        out.insert(key.clone(), v);
    }
    Ok(out)
}

/// `Double.valueOf`, `Float.valueOf`, `Long.valueOf`, `Integer.valueOf` on a query value, with
/// their `NumberFormatException` messages.
pub mod java_number {
    use super::*;

    fn bad(s: &str) -> CoreError {
        CoreError::unknown(format!("For input string: \"{s}\""))
    }

    /// `FloatingDecimal.readJavaFormatString`: surrounding whitespace ignored, an optional
    /// sign, `NaN` / `Infinity`, digits with an optional point and exponent, an optional
    /// `f F d D` suffix. (Hexadecimal floating literals are not accepted here.)
    fn parse_java_double(s: &str) -> Result<f64, CoreError> {
        let t = s.trim_matches(|c: char| c <= ' ');
        if t.is_empty() {
            return Err(CoreError::unknown("empty String"));
        }
        let (sign, body) = match t.as_bytes()[0] {
            b'-' => (-1.0, &t[1..]),
            b'+' => (1.0, &t[1..]),
            _ => (1.0, t),
        };
        if body == "NaN" {
            return Ok(f64::NAN);
        }
        if body == "Infinity" {
            return Ok(sign * f64::INFINITY);
        }
        let body = body.strip_suffix(['f', 'F', 'd', 'D']).unwrap_or(body);
        let valid = !body.is_empty()
            && body.chars().all(|c| c.is_ascii_digit() || matches!(c, '.' | 'e' | 'E' | '+' | '-'))
            && body.chars().next().is_some_and(|c| c.is_ascii_digit() || c == '.')
            && body.chars().any(|c| c.is_ascii_digit());
        if !valid {
            return Err(bad(s));
        }
        body.parse::<f64>().map(|v| sign * v).map_err(|_| bad(s))
    }

    fn number(v: f64) -> Value {
        // JSON has no NaN or Infinity; Gson would write them as such only in lenient mode.
        serde_json::Number::from_f64(v).map(Value::Number).unwrap_or(Value::Null)
    }

    pub fn double_value_of(s: &str) -> Result<Value, CoreError> {
        Ok(number(parse_java_double(s)?))
    }

    /// A `Float` holds the shortest decimal that names it (`1.1f` prints `1.1`), so it is
    /// carried as that decimal.
    pub fn float_value_of(s: &str) -> Result<Value, CoreError> {
        let f = parse_java_double(s)? as f32;
        Ok(number(format!("{f}").parse::<f64>().unwrap_or(f as f64)))
    }

    fn parse_java_integer(s: &str, min: i64, max: i64) -> Result<i64, CoreError> {
        let digits = s.strip_prefix(['+', '-']).unwrap_or(s);
        if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
            return Err(bad(s));
        }
        let v: i128 = s.parse().map_err(|_| bad(s))?;
        if v < min as i128 || v > max as i128 {
            return Err(bad(s));
        }
        Ok(v as i64)
    }

    pub fn long_value_of(s: &str) -> Result<Value, CoreError> {
        Ok(Value::from(parse_java_integer(s, i64::MIN, i64::MAX)?))
    }

    pub fn integer_value_of(s: &str) -> Result<Value, CoreError> {
        Ok(Value::from(parse_java_integer(s, i32::MIN as i64, i32::MAX as i64)?))
    }
}

/// Splits `namespace.name` at the last dot (`FunctionExecutionController.splitName`). Without
/// a dot the namespace is null, which Java then fails on (`Tuples.of(null, name)`: "t1").
pub fn split_name(full: &str) -> Result<(String, String), CoreError> {
    match full.rfind('.') {
        Some(i) => Ok((full[..i].to_string(), full[i + 1..].to_string())),
        None => Err(CoreError::unknown("t1")),
    }
}

/// The query string as Spring reads it: `&`-separated pairs, each name and value
/// URL-decoded (`+` is a space).
pub fn parse_query(raw: Option<&str>) -> Vec<(String, String)> {
    let Some(raw) = raw else { return Vec::new() };
    raw.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (form_decode(k), form_decode(v))
        })
        .collect()
}

fn form_decode(s: &str) -> String {
    let plus = s.replace('+', " ");
    percent_encoding::percent_decode_str(&plus).decode_utf8_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::java_number::*;
    use super::*;
    use serde_json::json;

    #[test]
    fn java_value_of() {
        assert_eq!(double_value_of("1").unwrap(), json!(1.0));
        assert_eq!(double_value_of(" 2.5 ").unwrap(), json!(2.5));
        assert_eq!(double_value_of("1e3").unwrap(), json!(1000.0));
        assert_eq!(double_value_of("3d").unwrap(), json!(3.0));
        assert_eq!(double_value_of("abc").unwrap_err().text(), "For input string: \"abc\"");
        assert_eq!(double_value_of("").unwrap_err().text(), "empty String");
        assert_eq!(float_value_of("1.1").unwrap(), json!(1.1));
        assert_eq!(integer_value_of("42").unwrap(), json!(42));
        assert_eq!(integer_value_of("+7").unwrap(), json!(7));
        assert_eq!(integer_value_of("1.0").unwrap_err().text(), "For input string: \"1.0\"");
        assert_eq!(integer_value_of("3000000000").unwrap_err().text(), "For input string: \"3000000000\"");
        assert_eq!(long_value_of("3000000000").unwrap(), json!(3_000_000_000_i64));
        assert_eq!(integer_value_of("").unwrap_err().text(), "For input string: \"\"");
    }

    #[test]
    fn names_and_queries() {
        assert_eq!(split_name("System.Math.Add").unwrap(), ("System.Math".into(), "Add".into()));
        assert_eq!(split_name("NoDot").unwrap_err().text(), "t1");
        assert_eq!(
            parse_query(Some("value=1&value=2&s=a+b%26c&e")),
            vec![
                ("value".into(), "1".into()),
                ("value".into(), "2".into()),
                ("s".into(), "a b&c".into()),
                ("e".into(), "".into())
            ]
        );
    }

    #[tokio::test]
    async fn query_arguments_by_schema_type() {
        use kirun::repository::{KIRunFunctionRepository, KIRunSchemaRepository};
        let add = KIRunFunctionRepository::new().find("System.Math", "Add").await.unwrap();
        let q = vec![("value".to_string(), "1".to_string()), ("value".to_string(), "2".to_string())];
        let args = query_arguments(add.as_ref(), &q, &KIRunSchemaRepository::new()).await.unwrap();
        // Add's value is a variable argument of a number type that includes DOUBLE.
        assert_eq!(args["value"], json!([1.0, 2.0]));
    }

    /// A function that only has a signature, for the query conversion.
    struct Sig(kirun::model::FunctionSignature);

    #[async_trait::async_trait]
    impl Function for Sig {
        fn get_signature(&self) -> &kirun::model::FunctionSignature {
            &self.0
        }
        async fn execute(&self, _: &mut FunctionExecutionParameters) -> kirun::Result<kirun::model::FunctionOutput> {
            Ok(kirun::model::FunctionOutput::new(vec![]))
        }
    }

    #[tokio::test]
    async fn query_arguments_for_every_type() {
        use kirun::json::schema::Schema;
        use kirun::model::{FunctionSignature, Parameter};
        use kirun::repository::KIRunSchemaRepository;
        let sig = FunctionSignature::new("f").set_namespace("T").set_parameters(kirun::Map::from([
            Parameter::of_entry("s", Schema::of_string("s"), false),
            Parameter::of_entry("ss", Schema::of_string("ss"), true),
            Parameter::of_entry("d", Schema::of_double("d"), false),
            Parameter::of_entry("f", Schema::of_float("f"), false),
            Parameter::of_entry("l", Schema::of_long("l"), false),
            Parameter::of_entry("i", Schema::of_integer("i"), false),
            Parameter::of_entry("b", Schema::of_boolean("b"), false),
            Parameter::of_entry("a", Schema::of_array("a", vec![Schema::of_string("x")]), false),
            Parameter::of_entry("o", Schema::of_object("o"), false),
            Parameter::of_entry("r", Schema::of_ref("System.integer"), false),
            Parameter::of_entry("missingRef", Schema::of_ref("System.nothing"), false),
            Parameter::of_entry("absent", Schema::of_string("absent"), false),
        ]));
        let q: Vec<(String, String)> = [
            ("s", "x"), ("ss", "a"), ("ss", "b"), ("d", "1.5"), ("f", "1.1"), ("l", "9000000000"), ("i", "7"),
            ("b", "true"), ("a", "1"), ("o", "{}"), ("r", "5"), ("missingRef", "1"), ("extra", "1"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let args = query_arguments(&Sig(sig), &q, &KIRunSchemaRepository::new()).await.unwrap();
        assert_eq!(args["s"], json!("x"));
        assert_eq!(args["ss"], json!(["a", "b"]));
        assert_eq!(args["d"], json!(1.5));
        assert_eq!(args["f"], json!(1.1));
        assert_eq!(args["l"], json!(9_000_000_000_i64));
        assert_eq!(args["i"], json!(7));
        assert_eq!(args["r"], json!(5));
        for skipped in ["b", "a", "o", "absent", "extra"] {
            assert!(!args.contains_key(skipped), "{skipped}");
        }

        let untyped = FunctionSignature::new("g").set_parameters(kirun::Map::from([Parameter::of_entry(
            "u",
            Schema::new(),
            false,
        )]));
        let q = vec![("u".to_string(), "1".to_string())];
        let e = query_arguments(&Sig(untyped), &q, &KIRunSchemaRepository::new()).await.unwrap_err();
        assert!(e.text().contains("because \"type\" is null"));
        let bad = FunctionSignature::new("h").set_parameters(kirun::Map::from([Parameter::of_entry("i", Schema::of_integer("i"), true)]));
        let q = vec![("i".to_string(), "1".to_string()), ("i".to_string(), "x".to_string())];
        assert!(query_arguments(&Sig(bad), &q, &KIRunSchemaRepository::new()).await.is_err());
    }

    #[test]
    fn runtime_errors_in_a_line() {
        let chain = "Error while executing the function System.Loop.ForEachLoop's parameter source in statement 'forEachLoop' [Expected: Array<Integer | Null>]: source - source - Expected an array but found null";
        assert_eq!(plain_reason(chain), "the value of source is not valid (Expected an array but found null)");
        let nested = "Error while executing the function App.outer in statement 'call': \nError while executing the function System.Math.Add's parameter value [Expected: Double]: value - Value \"a - b\" is not of valid type(s)\nvalue - \"a\" is not a Double";
        assert_eq!(plain_reason(nested), "the value of value is not valid (Value \"a - b\" is not of valid type(s))");
        assert_eq!(plain_reason("Steps.x.output.y : Unable to evaluate"), "Steps.x.output.y : Unable to evaluate");
        assert_eq!(plain_reason("Error while executing the function X's parameter p: "), "the value of p is not valid");
        assert_eq!(plain_reason("Error while executing the function no colon"), "Error while executing the function no colon");
        let long = "x".repeat(400);
        assert_eq!(plain_reason(&long).chars().count(), MAX_REASON + 3);
        let json = r#"Error while executing the function CoreServices.Storage.ReadPage's parameter filter in statement 'read' [Expected: Object]: filter - filter - "{\"operator\":\"OR\"}" is not an Object"#;
        assert_eq!(plain_reason(json), "the value of filter is not valid (the value given is not an Object)");
        assert_eq!(without_long_values(r#"a "short" b "unclosed"#), r#"a "short" b "unclosed"#);
        assert_eq!(without_long_values("map {x} and \"q\" end"), "map (x) and \"q\" end");
    }

    #[test]
    fn failures_name_the_step_or_the_function() {
        let trace = |step: &str| step_trace::StepTrace {
            function_name: "App.list".into(),
            statement_name: step.into(),
            step_function: "CoreServices.Storage.Read".into(),
            arguments: Some("{}".into()),
        };
        let e = step_failure((CoreError::unknown("Error while executing the function A's parameter p: p - bad"), false), "App.list", &[trace("read"), trace("read")]);
        let c = e.code().unwrap();
        assert_eq!(c.code, "CORE.FUNCTION_STEP_FAILED");
        assert_eq!(c.english().message, "Step read (CoreServices.Storage.Read) in App.list failed: the value of p is not valid (bad).");
        assert_eq!(c.debug.as_deref(), Some("Error while executing the function A's parameter p: p - bad\nat step read (CoreServices.Storage.Read) of App.list"));
        // A fault a core function raised names the step, not the fault.
        let e = step_failure((CoreError::unknown("connection reset"), true), "App.list", &[trace("")]);
        assert_eq!(e.code().unwrap().english().message, "A step (CoreServices.Storage.Read) in App.list failed.");
        let e = step_failure((CoreError::unknown("boom"), false), "System.Math.Add", &[]);
        assert_eq!(e.code().unwrap().english().message, "The function System.Math.Add failed: boom.");
        // Coded errors, refusals and 4xx come up as they are.
        let refused = CoreError::coded(StatusCode::FORBIDDEN, "CORE.FORBIDDEN_EXECUTION", "x");
        assert_eq!(step_failure((refused, true), "A.b", &[]).code().unwrap().code, "CORE.FORBIDDEN_EXECUTION");
        let e = step_failure((CoreError::spring(StatusCode::BAD_REQUEST, "x", None), false), "A.b", &[]);
        assert!(e.code().is_none());
    }

    #[test]
    fn more_java_number_forms() {
        assert_eq!(double_value_of("NaN").unwrap(), Value::Null);
        assert_eq!(double_value_of("-Infinity").unwrap(), Value::Null);
        assert_eq!(double_value_of("+2").unwrap(), json!(2.0));
        assert_eq!(double_value_of(".5f").unwrap(), json!(0.5));
        assert!(double_value_of("1e").is_err());
        assert!(double_value_of("e5").is_err());
        assert!(double_value_of("0x10").is_err());
        assert!(long_value_of("1 ").is_err());
        assert!(integer_value_of("-").is_err());
        assert_eq!(parse_query(None), Vec::<(String, String)>::new());
        assert_eq!(parse_query(Some("a=%E2%9C%93&&b")), vec![("a".to_string(), "✓".to_string()), ("b".to_string(), String::new())]);
    }

}
