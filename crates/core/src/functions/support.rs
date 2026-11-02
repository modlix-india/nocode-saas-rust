//! What the security, message and schedule functions share (`SecurityFunctionSupport`,
//! `ClientRelationUtil`): ids read from arguments, the definition-only gate, and whether a
//! client is related to the caller's.

use std::sync::Arc;

use axum::http::StatusCode;
use kirun::model::{EventResult, FunctionOutput, FunctionSignature};
use kirun::{Map, Value};

use super::{java_sig, CoreFunction};
use crate::auth::Authentication;
use crate::clients::SecurityCalls;
use crate::context;
use crate::error::CoreError;
use crate::security_calls::Id;

pub const SECURITY_NAMESPACE: &str = "CoreServices.Security";
pub const CLIENT_TYPE_SYSTEM: &str = "SYS";

/// A 400 with Java's text, said plainly by `code`.
pub fn bad_request(code: &'static str, message: impl Into<String>) -> CoreError {
    CoreError::coded(StatusCode::BAD_REQUEST, code, message)
}

/// A 403 with Java's text, said plainly by `code`.
pub fn forbidden(code: &'static str, message: impl Into<String>) -> CoreError {
    CoreError::coded(StatusCode::FORBIDDEN, code, message)
}

/// `"<argument> is required"`: an argument the function cannot do without.
pub fn required_argument(argument: &str) -> CoreError {
    bad_request("CORE.ARGUMENT_REQUIRED", format!("{argument} is required")).param("argument", argument)
}

/// An argument of the wrong kind: Java's text, the argument and what it should be.
pub fn invalid_argument(argument: &str, expected: &str, message: impl Into<String>) -> CoreError {
    bad_request("CORE.ARGUMENT_INVALID", message).param("argument", argument).param("expected", expected)
}

/// A security or messaging function of core called outside a server function.
pub fn server_function_only(full_name: &str) -> CoreError {
    forbidden("CORE.SERVER_FUNCTION_ONLY", format!("{full_name} can only be called from a server function")).param("function", full_name)
}

/// `new BigDecimal(text)` for the texts an id argument can carry: an optional sign, digits,
/// an optional fraction and an optional exponent. `None` when it is not a number.
fn decimal_parts(text: &str) -> Option<(bool, String, i64)> {
    let (neg, rest) = match text.as_bytes().first()? {
        b'-' => (true, &text[1..]),
        b'+' => (false, &text[1..]),
        _ => (false, text),
    };
    let (mantissa, exp) = match rest.find(['e', 'E']) {
        Some(i) => (&rest[..i], rest[i + 1..].parse::<i64>().ok()?),
        None => (rest, 0),
    };
    let (int, frac) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    if (int.is_empty() && frac.is_empty()) || !int.bytes().all(|b| b.is_ascii_digit()) || !frac.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((neg, format!("{int}{frac}"), exp - frac.len() as i64))
}

/// `new BigDecimal(text).toBigIntegerExact()`: `None` when not a whole number.
fn exact_integer(text: &str) -> Option<(bool, String)> {
    let (neg, digits, scale) = decimal_parts(text)?;
    let digits = if scale >= 0 {
        if scale > 64 {
            return None;
        }
        format!("{digits}{}", "0".repeat(scale as usize))
    } else {
        let cut = (-scale) as usize;
        let (keep, drop) = if cut >= digits.len() { ("", digits.as_str()) } else { digits.split_at(digits.len() - cut) };
        if drop.bytes().any(|b| b != b'0') {
            return None;
        }
        keep.to_string()
    };
    let trimmed = digits.trim_start_matches('0');
    Some((neg && !trimmed.is_empty(), if trimmed.is_empty() { "0".into() } else { trimmed.into() }))
}

/// `SecurityFunctionSupport.idOf`: `None` for "not given" (absent, null, blank, 0).
pub fn id_of(name: &str, element: Option<&Value>) -> Result<Option<Id>, CoreError> {
    let text = match element {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::Number(n)) => crate::gson::number_to_java_string(n),
        Some(Value::String(s)) => s.trim().to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        Some(_) => return Err(invalid_argument(name, "a number", format!("{name} must be a number or a numeric string"))),
    };
    if text.trim().is_empty() {
        return Ok(None);
    }
    let not_an_id = || invalid_argument(name, "an id (a whole number)", format!("{name} is not an id : {text}"));
    let (neg, digits) = exact_integer(&text).ok_or_else(not_an_id)?;
    if neg {
        return Err(not_an_id());
    }
    let id: Id = digits.parse().map_err(|_| not_an_id())?;
    Ok(if id == 0 { None } else { Some(id) })
}

/// `SecurityFunctionSupport.idsOf`: in order, without repeats or blanks; one value is a
/// one-item list.
pub fn ids_of(name: &str, element: Option<&Value>) -> Result<Vec<Id>, CoreError> {
    match element {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(a)) => {
            let mut out: Vec<Id> = Vec::new();
            for each in a {
                if let Some(id) = id_of(name, Some(each))? {
                    if !out.contains(&id) {
                        out.push(id);
                    }
                }
            }
            Ok(out)
        }
        Some(other) => Ok(id_of(name, Some(other))?.into_iter().collect()),
    }
}

pub fn ids_json(ids: &[Id]) -> Value {
    Value::Array(ids.iter().map(|i| Value::from(*i)).collect())
}

/// `gson.toJsonTree(value)` of what Jackson read from another service: members whose value is
/// null are left out at every depth, nulls inside lists stay.
pub(crate) fn gson_tree(v: Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(m.into_iter().filter(|(_, v)| !v.is_null()).map(|(k, v)| (k, gson_tree(v))).collect()),
        Value::Array(a) => Value::Array(a.into_iter().map(gson_tree).collect()),
        other => other,
    }
}

/// `ca.getUser() != null`: security sent a user.
pub fn has_user(auth: &Authentication) -> bool {
    auth.raw.get("user").is_some_and(|u| !u.is_null())
}

/// `ca.getUser().getClientId()`, `None` without a user.
pub fn user_client_id(auth: &Authentication) -> Option<Id> {
    has_user(auth).then_some(auth.ca.user.client_id)
}

/// `SecurityFunctionSupport.definitionContextAuthentication`: only inside a server function.
pub fn definition_context_authentication(function_name: &str) -> Result<Arc<Authentication>, CoreError> {
    if !context::in_kirun() {
        return Err(server_function_only(&format!("{SECURITY_NAMESPACE}.{function_name}")));
    }
    match context::request() {
        Some(r) => Ok(r.auth.clone()),
        None => Err(forbidden("CORE.SECURITY_CONTEXT_MISSING", format!("{SECURITY_NAMESPACE}.{function_name} needs a security context"))
            .param("function", format!("{SECURITY_NAMESPACE}.{function_name}"))),
    }
}

/// `cv.get(DefinitionFunction.CONTEXT_KEY)` outside a definition: Reactor's error.
pub fn require_context_key() -> Result<(), CoreError> {
    if context::in_kirun() {
        Ok(())
    } else {
        Err(CoreError::unknown("Context does not contain key: KIRun Runtime"))
    }
}

fn blank(s: Option<&str>) -> bool {
    s.is_none_or(|s| s.trim().is_empty())
}

/// `ClientRelationUtil.isRelatedClient`: the same client, one the caller's client manages, or
/// its direct managing client (not SYSTEM) with write access to `app_code`.
pub async fn is_related_client(
    security: &SecurityCalls,
    caller_client_id: Option<Id>,
    target_client_id: Option<Id>,
    app_code: Option<&str>,
) -> Result<bool, CoreError> {
    let (Some(caller), Some(target)) = (caller_client_id, target_client_id) else { return Ok(false) };
    if caller == target {
        return Ok(true);
    }
    if security.does_client_manage_client(caller, target).await?.unwrap_or(false) {
        return Ok(true);
    }
    is_allowed_ancestor(security, Some(caller), Some(target), None, app_code).await
}

/// `SecurityFunctionSupport.isRelatedClient`: an error (an unknown client) is "not related".
pub async fn is_related_client_or_false(
    security: &SecurityCalls,
    caller_client_id: Option<Id>,
    target_client_id: Option<Id>,
    app_code: Option<&str>,
) -> bool {
    is_related_client(security, caller_client_id, target_client_id, app_code).await.unwrap_or(false)
}

fn client_id_of(client: &Value) -> Option<Id> {
    client.get("id").and_then(crate::security_calls::id_value)
}

/// `ClientRelationUtil.isRelatedClientCode`.
pub async fn is_related_client_code(
    security: &SecurityCalls,
    caller_client_code: Option<&str>,
    target_client_code: Option<&str>,
    app_code: Option<&str>,
) -> Result<bool, CoreError> {
    let (Some(caller), Some(target)) = (caller_client_code.filter(|s| !blank(Some(s))), target_client_code.filter(|s| !blank(Some(s))))
    else {
        return Ok(false);
    };
    if caller == target {
        return Ok(true);
    }
    if security.does_client_manage_client_code(caller, target).await?.unwrap_or(false) {
        return Ok(true);
    }
    if blank(app_code) {
        return Ok(false);
    }
    by_codes(security, caller, target, app_code).await
}

/// `Mono.zip(getClientByCode(caller), getClientByCode(target)).flatMap(isAllowedAncestor)`,
/// empty when either is unknown.
async fn by_codes(security: &SecurityCalls, caller: &str, target: &str, app_code: Option<&str>) -> Result<bool, CoreError> {
    let (c, t) = futures::try_join!(security.client_by_code(caller), security.client_by_code(target))?;
    let (Some(c), Some(t)) = (c, t) else { return Ok(false) };
    is_allowed_ancestor(security, client_id_of(&c), client_id_of(&t), Some(&t), app_code).await
}

/// `ClientRelationUtil.isSelfOrDirectManagingClientCode`: acting AS a tenant.
pub async fn is_self_or_direct_managing_client_code(
    security: &SecurityCalls,
    caller_client_code: Option<&str>,
    target_client_code: Option<&str>,
    app_code: Option<&str>,
) -> Result<bool, CoreError> {
    let (Some(caller), Some(target)) = (caller_client_code.filter(|s| !blank(Some(s))), target_client_code.filter(|s| !blank(Some(s))))
    else {
        return Ok(false);
    };
    if caller == target {
        return Ok(true);
    }
    if blank(app_code) {
        return Ok(false);
    }
    by_codes(security, caller, target, app_code).await
}

/// `ClientRelationUtil.isAllowedAncestor`: the target is the caller's client's direct managing
/// client, not SYSTEM, with write access to the app.
async fn is_allowed_ancestor(
    security: &SecurityCalls,
    caller_client_id: Option<Id>,
    target_client_id: Option<Id>,
    target: Option<&Value>,
    app_code: Option<&str>,
) -> Result<bool, CoreError> {
    let (Some(caller), Some(target_id), Some(app)) = (caller_client_id, target_client_id, app_code.filter(|a| !blank(Some(a)))) else {
        return Ok(false);
    };
    if caller == target_id {
        return Ok(false);
    }
    let chain = security.client_hierarchy(caller).await?.unwrap_or_default();
    if chain.len() < 2 || chain[1] != target_id {
        return Ok(false);
    }
    let read;
    let t = match target {
        Some(t) => t,
        None => match security.client_by_id(target_id).await? {
            Some(v) => {
                read = v;
                &read
            }
            None => return Ok(false),
        },
    };
    let code = t.get("code").and_then(Value::as_str);
    if t.get("typeCode").and_then(Value::as_str) == Some(CLIENT_TYPE_SYSTEM) || blank(code) {
        return Ok(false);
    }
    Ok(security.has_write_access(app, code.unwrap_or_default()).await?.unwrap_or(false))
}

/// A function whose signature is Java's, captured in `java_signatures.json`, and whose body
/// is `run`.
#[async_trait::async_trait]
pub trait JavaFunction: Send + Sync + 'static {
    /// The full name (`CoreServices.Security.GetClient`).
    fn full_name(&self) -> &'static str;

    async fn run(&self, args: &Map<Value>) -> Result<FunctionOutput, CoreError>;
}

/// A [`JavaFunction`] with its signature read once.
pub struct Java<F: JavaFunction> {
    signature: FunctionSignature,
    f: F,
}

impl<F: JavaFunction> Java<F> {
    pub fn new(f: F) -> Self {
        Self { signature: java_sig::signature(f.full_name()), f }
    }

    /// As a KIRun function.
    pub fn function(f: F) -> Arc<dyn kirun::function::Function> {
        Arc::new(super::Core(Self::new(f)))
    }

    pub fn inner(&self) -> &F {
        &self.f
    }
}

#[async_trait::async_trait]
impl<F: JavaFunction> CoreFunction for Java<F> {
    fn signature(&self) -> &FunctionSignature {
        &self.signature
    }

    async fn internal_execute(&self, args: &Map<Value>) -> Result<FunctionOutput, CoreError> {
        self.f.run(args).await
    }
}

/// Java's empty `Mono` from a function: on a direct execute `FunctionExecutionController`
/// answers 404 "Function with id <ns.name> not found"; inside a definition the run ends
/// without output, which also ends in that 404 for the definition being executed.
pub fn empty_result(full_name: &str) -> CoreError {
    CoreError::msg_as(StatusCode::NOT_FOUND, crate::error::messages::OBJECT_NOT_FOUND, "CORE.FUNCTION_NO_RESULT", &["Function", full_name])
}

/// `new FunctionOutput(List.of(EventResult.outputOf(map)))` for several values.
pub fn output_map<I: IntoIterator<Item = (&'static str, Value)>>(values: I) -> FunctionOutput {
    let m: Map<Value> = values.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
    FunctionOutput::new(vec![EventResult::output_of(m)])
}

/// `new FunctionOutput(List.of(EventResult.of(event, map)))`.
pub fn event_output<I: IntoIterator<Item = (&'static str, Value)>>(event: &str, values: I) -> FunctionOutput {
    let m: Map<Value> = values.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
    FunctionOutput::new(vec![EventResult::of(event, m)])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::serve;
    use axum::extract::RawQuery;
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::Router;
    use platform::upstream::Upstream;
    use serde_json::json;

    #[test]
    fn gson_tree_drops_null_members() {
        assert_eq!(gson_tree(serde_json::json!({"a": null, "b": [null, {"c": null, "d": 1}]})), serde_json::json!({"b": [null, {"d": 1}]}));
    }

    #[test]
    fn ids_as_java_reads_them() {
        let id = |v: Value| id_of("x", Some(&v));
        assert_eq!(id(json!(12)).unwrap(), Some(12));
        assert_eq!(id(json!("12")).unwrap(), Some(12));
        assert_eq!(id(json!(" 12 ")).unwrap(), Some(12));
        assert_eq!(id(json!(1.2e1)).unwrap(), Some(12));
        assert_eq!(id(json!("1.20E1")).unwrap(), Some(12));
        assert_eq!(id(json!("12.0")).unwrap(), Some(12));
        assert_eq!(id(json!(0)).unwrap(), None);
        assert_eq!(id(json!("")).unwrap(), None);
        assert_eq!(id(json!("-0")).unwrap(), None);
        assert_eq!(id(Value::Null).unwrap(), None);
        assert_eq!(id_of("x", None).unwrap(), None);
        assert_eq!(id(json!("1.5")).unwrap_err().text(), "x is not an id : 1.5");
        assert_eq!(id(json!(-3)).unwrap_err().text(), "x is not an id : -3");
        assert_eq!(id(json!("abc")).unwrap_err().text(), "x is not an id : abc");
        assert_eq!(id(json!("1e")).unwrap_err().text(), "x is not an id : 1e");
        assert_eq!(id(json!(".")).unwrap_err().text(), "x is not an id : .");
        assert_eq!(id(json!("1e99")).unwrap_err().text(), "x is not an id : 1e99");
        assert_eq!(id(json!("99999999999999999999")).unwrap_err().status(), StatusCode::BAD_REQUEST);
        assert_eq!(id(json!(true)).unwrap_err().text(), "x is not an id : true");
        assert_eq!(id(json!({})).unwrap_err().text(), "x must be a number or a numeric string");
        assert_eq!(id(json!([])).unwrap_err().text(), "x must be a number or a numeric string");

        assert_eq!(ids_of("x", Some(&json!([3, "3", 0, "", null, 4]))).unwrap(), vec![3, 4]);
        assert_eq!(ids_of("x", Some(&json!(5))).unwrap(), vec![5]);
        assert_eq!(ids_of("x", Some(&json!(0))).unwrap(), Vec::<Id>::new());
        assert_eq!(ids_of("x", None).unwrap(), Vec::<Id>::new());
        assert!(ids_of("x", Some(&json!([{}]))).is_err());
        assert_eq!(ids_json(&[1, 2]), json!([1, 2]));
    }

    async fn stub() -> String {
        fn q(r: Option<String>) -> std::collections::HashMap<String, String> {
            crate::exec::parse_query(r.as_deref()).into_iter().collect()
        }
        // Clients: 1 SYSTEM, 2 PARTNER (managed by 1, writes "app"), 3 CUST (managed by 2),
        // 4 OTHER (managed by 1, no write access).
        let router = Router::new()
            .route("/api/security/clients/internal/doesClientManageClient", get(|RawQuery(r): RawQuery| async move {
                let p = q(r);
                let pair = (p["managingClientId"].as_str(), p["clientId"].as_str());
                matches!(pair, ("1", _) | ("2", "3")).to_string()
            }))
            .route("/api/security/clients/internal/doesClientManageClientCode", get(|RawQuery(r): RawQuery| async move {
                let p = q(r);
                let pair = (p["managingClientCode"].as_str(), p["clientCode"].as_str());
                if pair.1 == "BROKEN" {
                    return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, r#"{"message":"down"}"#).into_response();
                }
                matches!(pair, ("SYSTEM", _) | ("PARTNER", "CUST")).to_string().into_response()
            }))
            .route("/api/security/clients/internal/clientHierarchy", get(|RawQuery(r): RawQuery| async move {
                match q(r)["clientId"].as_str() {
                    "3" => "[3,2,1]",
                    "2" | "4" => "[2,1]",
                    "5" => "[5,4,1]",
                    _ => "[1]",
                }
            }))
            .route("/api/security/clients/internal/getClientById", get(|RawQuery(r): RawQuery| async move {
                match q(r)["clientId"].as_str() {
                    "2" => r#"{"id":2,"code":"PARTNER","typeCode":"BUS"}"#.into_response(),
                    "4" => r#"{"id":4,"code":"OTHER","typeCode":"BUS"}"#.into_response(),
                    "1" => r#"{"id":1,"code":"SYSTEM","typeCode":"SYS"}"#.into_response(),
                    _ => axum::http::StatusCode::OK.into_response(),
                }
            }))
            .route("/api/security/clients/internal/getClientByCode", get(|RawQuery(r): RawQuery| async move {
                match q(r)["clientCode"].as_str() {
                    "PARTNER" => r#"{"id":2,"code":"PARTNER","typeCode":"BUS"}"#.into_response(),
                    "CUST" => r#"{"id":3,"code":"CUST","typeCode":"BUS"}"#.into_response(),
                    "OTHER" => r#"{"id":4,"code":"OTHER","typeCode":"BUS"}"#.into_response(),
                    "FIVE" => r#"{"id":5,"code":"FIVE","typeCode":"BUS"}"#.into_response(),
                    "NOCODE" => r#"{"id":6,"typeCode":"BUS"}"#.into_response(),
                    _ => axum::http::StatusCode::OK.into_response(),
                }
            }))
            .route("/api/security/applications/internal/hasWriteAccess", get(|RawQuery(r): RawQuery| async move {
                let p = q(r);
                (p["appCode"] == "app" && p["clientCode"] == "PARTNER").to_string()
            }));
        serve(router).await
    }

    #[tokio::test]
    async fn client_relations() {
        let base = stub().await;
        let s = SecurityCalls::new(Upstream::fixed(&[&base])).unwrap();
        // Down: own, managed at any depth.
        assert!(is_related_client(&s, Some(3), Some(3), None).await.unwrap());
        assert!(is_related_client(&s, Some(2), Some(3), None).await.unwrap());
        assert!(!is_related_client(&s, None, Some(3), None).await.unwrap());
        // Up: only the direct managing client, not SYSTEM, with write access to the app.
        assert!(is_related_client(&s, Some(3), Some(2), Some("app")).await.unwrap());
        assert!(!is_related_client(&s, Some(3), Some(2), Some("other")).await.unwrap());
        assert!(!is_related_client(&s, Some(3), Some(2), None).await.unwrap());
        assert!(!is_related_client(&s, Some(3), Some(1), Some("app")).await.unwrap());
        assert!(!is_related_client(&s, Some(2), Some(1), Some("app")).await.unwrap());
        assert!(!is_related_client(&s, Some(5), Some(4), Some("app")).await.unwrap());
        assert!(!is_related_client(&s, Some(4), Some(9), Some("app")).await.unwrap());

        assert!(is_related_client_code(&s, Some("CUST"), Some("CUST"), None).await.unwrap());
        assert!(is_related_client_code(&s, Some("PARTNER"), Some("CUST"), None).await.unwrap());
        assert!(is_related_client_code(&s, Some("CUST"), Some("PARTNER"), Some("app")).await.unwrap());
        assert!(!is_related_client_code(&s, Some("CUST"), Some("PARTNER"), Some(" ")).await.unwrap());
        assert!(!is_related_client_code(&s, Some("CUST"), Some("GHOST"), Some("app")).await.unwrap());
        assert!(!is_related_client_code(&s, Some(""), Some("CUST"), Some("app")).await.unwrap());
        assert!(is_related_client_code(&s, Some("CUST"), Some("BROKEN"), Some("app")).await.is_err());
        assert!(!is_related_client_code(&s, Some("FIVE"), Some("NOCODE"), Some("app")).await.unwrap());

        assert!(is_self_or_direct_managing_client_code(&s, Some("CUST"), Some("CUST"), None).await.unwrap());
        assert!(is_self_or_direct_managing_client_code(&s, Some("CUST"), Some("PARTNER"), Some("app")).await.unwrap());
        // Managing a client is not speaking as it.
        assert!(!is_self_or_direct_managing_client_code(&s, Some("PARTNER"), Some("CUST"), Some("app")).await.unwrap());
        assert!(!is_self_or_direct_managing_client_code(&s, Some("CUST"), Some("PARTNER"), None).await.unwrap());
        assert!(!is_self_or_direct_managing_client_code(&s, None, Some("PARTNER"), Some("app")).await.unwrap());

        let dead = SecurityCalls::new(Upstream::fixed(&["http://127.0.0.1:1"])).unwrap();
        assert!(!is_related_client_or_false(&dead, Some(1), Some(2), None).await);
        assert!(is_related_client_or_false(&s, Some(1), Some(2), None).await);
    }

    #[tokio::test]
    async fn the_definition_gate() {
        assert_eq!(definition_context_authentication("X").unwrap_err().text(), "CoreServices.Security.X can only be called from a server function");
        assert_eq!(require_context_key().unwrap_err().status(), StatusCode::INTERNAL_SERVER_ERROR);
        context::with_run(context::RunScope::default(), async {
            assert_eq!(definition_context_authentication("X").unwrap_err().text(), "CoreServices.Security.X needs a security context");
            assert!(require_context_key().is_ok());
            let ctx = crate::testing::request(crate::testing::user(&[]), false, None);
            context::with_request(ctx, async {
                let a = definition_context_authentication("X").unwrap();
                assert!(has_user(&a));
                assert_eq!(user_client_id(&a), Some(1));
            })
            .await;
        })
        .await;
        assert_eq!(user_client_id(&Authentication::default()), None);
    }
}
