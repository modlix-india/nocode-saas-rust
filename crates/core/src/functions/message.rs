//! `CoreServices.Message`: `SendWhatsapp`, `MakeCall` and the WhatsApp number administration
//! (`WhatsappNumberFunctions`), over the message service's internal routes
//! ([`crate::message_calls`]), with the tenant rule they share (`MessageTenant`).
//!
//! The internal routes trust whatever app and client they are given, so [`resolve`] and
//! [`resolve_own`] are the only check between a server function and another tenant's
//! WhatsApp number or call account. All of them run only inside a server function.

use std::sync::Arc;

use async_trait::async_trait;
use axum::http::StatusCode;
use connections::java::{hash_map_order, is_blank, to_java_string, trim};
use kirun::model::FunctionOutput;
use kirun::{Map, Value};

use super::support::{empty_result, forbidden, is_self_or_direct_managing_client_code, output_map, require_context_key, required_argument, server_function_only, Java, JavaFunction};
use super::{arg_string, output};
use crate::auth::Authentication;
use crate::clients::SecurityCalls;
use crate::context;
use crate::error::CoreError;
use crate::message_calls::MessageCalls;
use crate::repos::core_functions::Deps;

pub const NAMESPACE: &str = "CoreServices.Message";

/// The owner a call or a number linked through these functions gets: core, so its events come
/// back as the app's own core events.
pub const OWNER_SERVICE: &str = "core";

const APP_CODE: &str = "appCode";
const CLIENT_CODE: &str = "clientCode";

/// `SendWhatsapp.string(args, key)`: absent or null is null, anything else `getAsString()`.
fn string(args: &Map<Value>, key: &str) -> Result<Option<String>, CoreError> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => arg_string(args, key).map(Some),
    }
}

/// `StringUtil.safeIsBlank`.
fn blank(s: Option<&str>) -> bool {
    s.is_none_or(is_blank)
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

/// `JsonElement.getAsBoolean()` of a primitive: a boolean as is, anything else
/// `Boolean.parseBoolean(getAsString())`.
fn primitive_true(v: &Value) -> bool {
    match v {
        Value::Bool(b) => *b,
        Value::String(s) => s.eq_ignore_ascii_case("true"),
        _ => false,
    }
}

/// `JsonPrimitive.getAsInt()`: a number's `intValue()`, anything else `Integer.parseInt`.
fn primitive_int(v: &Value) -> Result<i32, CoreError> {
    let not_int = |s: String| CoreError::unknown(format!("For input string: \"{s}\""));
    match v {
        Value::Number(n) => Ok(match n.as_i64() {
            Some(i) => i as i32,
            None => n.as_f64().unwrap_or(0.0) as i32,
        }),
        Value::String(s) => s.parse::<i32>().map_err(|_| not_int(s.clone())),
        other => Err(not_int(to_java_string(other))),
    }
}

// -------------------------------------------------------------------------------------------
// MessageTenant

/// `MessageTenant.resolve`: which app and client a message function acts for, and whether the
/// caller may. The app: explicit, else the app owning the running function, else the request's,
/// and the caller's client must be able to read it (unless it is the system client). The
/// client: the caller's own, or its DIRECT managing client (not SYSTEM, with write access to
/// the app). `None` without a security context (Java's empty).
pub async fn resolve(security: &SecurityCalls, app_code: Option<&str>, client_code: Option<&str>) -> Result<Option<(String, String)>, CoreError> {
    let Some(req) = context::request() else { return Ok(None) };
    let ca = &req.auth;
    let app = app_code_of(security, app_code, ca).await?;
    let client = client_code_of(security, client_code, ca, &app).await?;
    Ok(Some((app, client)))
}

/// `MessageTenant.resolveOwn`: the same app rule, but only the caller's OWN client, for
/// administering a tenant's numbers.
pub async fn resolve_own(security: &SecurityCalls, app_code: Option<&str>, client_code: Option<&str>) -> Result<Option<(String, String)>, CoreError> {
    let Some(req) = context::request() else { return Ok(None) };
    let ca = &req.auth;
    let app = app_code_of(security, app_code, ca).await?;
    let own = ca.client_code();
    let Some(own) = own.filter(|o| !is_blank(o)) else { return Err(required_argument("clientCode")) };
    if let Some(asked) = client_code.filter(|c| !is_blank(c)) {
        if asked != own {
            return Err(forbidden("CORE.WHATSAPP_OWN_CLIENT_ONLY", format!("Only client {own} may manage its own WhatsApp numbers, not {asked}"))
                .param("own", own)
                .param("client", asked));
        }
    }
    Ok(Some((app, own.to_string())))
}

async fn app_code_of(security: &SecurityCalls, app_code: Option<&str>, ca: &Authentication) -> Result<String, CoreError> {
    let implicit = match context::owner_app_code() {
        Some(owner) => Some(owner),
        None => ca.url_app_code().map(str::to_string),
    };
    let app = if blank(app_code) { implicit } else { app_code.map(str::to_string) };
    let Some(app) = app.filter(|a| !is_blank(a)) else { return Err(required_argument("appCode")) };
    if ca.ca.is_system_client() {
        return Ok(app);
    }
    let refused = || forbidden("CORE.MESSAGE_APP_FORBIDDEN", format!("Not allowed to message for app {app}")).param("app", &app);
    let Some(own) = ca.client_code().filter(|o| !is_blank(o)) else { return Err(refused()) };
    if security.has_read_access(&app, own).await?.unwrap_or(false) {
        Ok(app)
    } else {
        Err(refused())
    }
}

async fn client_code_of(security: &SecurityCalls, client_code: Option<&str>, ca: &Authentication, app: &str) -> Result<String, CoreError> {
    let own = ca.client_code();
    let Some(target) = client_code.filter(|c| !is_blank(c) && Some(*c) != own) else {
        return match own.filter(|o| !is_blank(o)) {
            Some(o) => Ok(o.to_string()),
            None => Err(required_argument("clientCode")),
        };
    };
    if is_self_or_direct_managing_client_code(security, own, Some(target), Some(app)).await? {
        Ok(target.to_string())
    } else {
        Err(forbidden("CORE.MESSAGE_CLIENT_FORBIDDEN", format!("Not allowed to message on behalf of client {target}")).param("client", target))
    }
}

// -------------------------------------------------------------------------------------------
// SendWhatsapp

const SEND_WHATSAPP: &str = "CoreServices.Message.SendWhatsapp";

/// Sends a WhatsApp message through one of the tenant's linked numbers (a blank `sessionCode`
/// sends from the tenant's default). Output: `result` (the message service's answer) and the
/// `sessionCode` it went from.
pub struct SendWhatsapp {
    pub message: Arc<MessageCalls>,
    pub security: Arc<SecurityCalls>,
}

impl SendWhatsapp {
    /// The code asked for if it is placeable, else the tenant's default, as the message service
    /// decides; a tenant without a linked number is a 409.
    async fn session_code(&self, app_code: &str, client_code: &str, session_code: Option<String>) -> Result<String, CoreError> {
        let asked = session_code.filter(|s| !is_blank(s));
        let session = self.message.resolve_whatsapp_session(app_code, client_code, asked.as_deref()).await?;
        match session.as_ref().and_then(|s| s.get("code")).filter(|c| !c.is_null()) {
            Some(code) => Ok(to_java_string(code)),
            None => Err(CoreError::coded(StatusCode::CONFLICT, "CORE.WHATSAPP_NOT_LINKED", format!("No WhatsApp number is linked for {client_code} in {app_code}"))
                .param("client", client_code)
                .param("app", app_code)),
        }
    }
}

/// `SendWhatsapp.request`: the body the session route takes, blanks left out so it decides
/// between text and media (a `HashMap`, in its order).
pub fn send_request(args: &Map<Value>) -> Result<Value, CoreError> {
    let mut request = Map::new();
    request.insert("to".to_string(), string(args, "to")?.map(Value::String).unwrap_or(Value::Null));
    for key in ["text", "filePath", "kind", "mimeType", "fileName", "resourceType"] {
        if let Some(value) = string(args, key)?.filter(|v| !is_blank(v)) {
            request.insert(key.to_string(), Value::String(value));
        }
    }
    if args.get("voiceNote").is_some_and(|v| !v.is_null() && !v.is_object() && !v.is_array() && primitive_true(v)) {
        request.insert("voiceNote".to_string(), Value::Bool(true));
    }
    Ok(Value::Object(hash_map_order(request.into_iter().collect())))
}

#[async_trait]
impl JavaFunction for SendWhatsapp {
    fn full_name(&self) -> &'static str {
        SEND_WHATSAPP
    }

    async fn run(&self, args: &Map<Value>) -> Result<FunctionOutput, CoreError> {
        let to = string(args, "to")?;
        let text = string(args, "text")?;
        let file_path = string(args, "filePath")?;
        require_context_key()?;
        if blank(to.as_deref()) {
            return Err(required_argument("to"));
        }
        if blank(text.as_deref()) && blank(file_path.as_deref()) {
            return Err(required_argument("text or filePath"));
        }
        let tenant = resolve(&self.security, string(args, APP_CODE)?.as_deref(), string(args, CLIENT_CODE)?.as_deref()).await?;
        let Some((app, client)) = tenant else { return Err(empty_result(SEND_WHATSAPP)) };
        let session = self.session_code(&app, &client, string(args, "sessionCode")?).await?;
        let body = send_request(args)?;
        let Some(sent) = self.message.send_whatsapp_session_message(&app, &client, &session, &body).await? else {
            return Err(empty_result(SEND_WHATSAPP));
        };
        Ok(output_map([("result", gson_tree(Value::Object(sent))), ("sessionCode", Value::String(session))]))
    }
}

// -------------------------------------------------------------------------------------------
// MakeCall

const MAKE_CALL: &str = "CoreServices.Message.MakeCall";

/// Places an outbound call through the tenant's call connection, owned by core (its status
/// callbacks come back as the core event `CALL_EVENT`). Output: `call`.
pub struct MakeCall {
    pub message: Arc<MessageCalls>,
    pub security: Arc<SecurityCalls>,
}

/// `MakeCall.phone`: `{number, countryCode}`, a country code of 0 left out for the default.
fn phone(args: &Map<Value>, country_key: &str, number_key: &str) -> Result<Value, CoreError> {
    let mut phone = Map::new();
    phone.insert("number".to_string(), string(args, number_key)?.map(Value::String).unwrap_or(Value::Null));
    if let Some(country) = args.get(country_key).filter(|c| !c.is_null() && !c.is_object() && !c.is_array()) {
        let code = primitive_int(country)?;
        if code > 0 {
            phone.insert("countryCode".to_string(), Value::from(code));
        }
    }
    Ok(Value::Object(hash_map_order(phone.into_iter().collect())))
}

/// `MakeCall.request`: the message service's `CallRequest`.
pub fn call_request(args: &Map<Value>) -> Result<Value, CoreError> {
    let mut request = Map::new();
    request.insert("toNumber".to_string(), phone(args, "toCountryCode", "toNumber")?);
    if !blank(string(args, "callerId")?.as_deref()) {
        request.insert("callerId".to_string(), phone(args, "callerIdCountryCode", "callerId")?);
    }
    if let Some(name) = string(args, "connectionName")?.filter(|n| !is_blank(n)) {
        request.insert("connectionName".to_string(), Value::String(name));
    }
    Ok(Value::Object(hash_map_order(request.into_iter().collect())))
}

#[async_trait]
impl JavaFunction for MakeCall {
    fn full_name(&self) -> &'static str {
        MAKE_CALL
    }

    async fn run(&self, args: &Map<Value>) -> Result<FunctionOutput, CoreError> {
        require_context_key()?;
        if blank(string(args, "toNumber")?.as_deref()) {
            return Err(required_argument("toNumber"));
        }
        let tenant = resolve(&self.security, string(args, APP_CODE)?.as_deref(), string(args, CLIENT_CODE)?.as_deref()).await?;
        let Some((app, client)) = tenant else { return Err(empty_result(MAKE_CALL)) };
        let body = call_request(args)?;
        let Some(call) = self.message.make_call_internal(&app, &client, OWNER_SERVICE, &body).await? else {
            return Err(empty_result(MAKE_CALL));
        };
        Ok(output("call", gson_tree(Value::Object(call))))
    }
}

// -------------------------------------------------------------------------------------------
// WhatsappNumberFunctions

/// The five number functions, in `WhatsappNumberFunctions.all`'s order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumberAction {
    Link,
    List,
    PairingCode,
    Remove,
    SetDefault,
}

impl NumberAction {
    pub const ALL: [NumberAction; 5] = [Self::Link, Self::List, Self::PairingCode, Self::Remove, Self::SetDefault];

    pub fn name(self) -> &'static str {
        match self {
            Self::Link => "LinkWhatsappNumber",
            Self::List => "ListWhatsappNumbers",
            Self::PairingCode => "GetWhatsappPairingCode",
            Self::Remove => "RemoveWhatsappNumber",
            Self::SetDefault => "SetDefaultWhatsappNumber",
        }
    }

    fn full_name(self) -> &'static str {
        match self {
            Self::Link => "CoreServices.Message.LinkWhatsappNumber",
            Self::List => "CoreServices.Message.ListWhatsappNumbers",
            Self::PairingCode => "CoreServices.Message.GetWhatsappPairingCode",
            Self::Remove => "CoreServices.Message.RemoveWhatsappNumber",
            Self::SetDefault => "CoreServices.Message.SetDefaultWhatsappNumber",
        }
    }

    fn output_name(self) -> &'static str {
        match self {
            Self::Link => "session",
            Self::List => "numbers",
            Self::PairingCode => "pairing",
            Self::Remove => "removed",
            Self::SetDefault => "marked",
        }
    }

    /// Administration is own-client only; listing follows SendWhatsapp's rule.
    fn own_client_only(self) -> bool {
        self != Self::List
    }
}

/// One of `WhatsappNumberFunctions`: link a number (owned by core, so its traffic arrives as
/// the app's `WHATSAPP_INBOUND` event), list them, read the pairing code, unlink one, make one
/// the default.
pub struct WhatsappNumber {
    pub action: NumberAction,
    pub message: Arc<MessageCalls>,
    pub security: Arc<SecurityCalls>,
}

/// `Base.required`: a blank argument is a 400, otherwise it is trimmed.
fn required(args: &Map<Value>, key: &str) -> Result<String, CoreError> {
    match string(args, key)? {
        Some(v) if !is_blank(&v) => Ok(trim(&v).to_string()),
        _ => Err(required_argument(key)),
    }
}

impl WhatsappNumber {
    /// What the function does once the tenant is known; `None` is Java's empty.
    async fn act(&self, args: &Map<Value>, app: &str, client: &str) -> Result<Option<Value>, CoreError> {
        let m = &self.message;
        Ok(match self.action {
            NumberAction::Link => {
                let phone = required(args, "phoneNumber")?;
                // A LinkedHashMap: in insertion order.
                let mut body = Map::new();
                body.insert("phoneNumber".to_string(), Value::String(phone));
                if let Some(product) = string(args, "productId")?.filter(|p| !is_blank(p)) {
                    body.insert("productId".to_string(), Value::String(trim(&product).to_string()));
                }
                body.insert("ownerService".to_string(), Value::String(OWNER_SERVICE.to_string()));
                let body: serde_json::Map<String, Value> = body.into_iter().collect();
                m.create_whatsapp_session(app, client, &Value::Object(body)).await?.map(|s| gson_tree(Value::Object(s)))
            }
            NumberAction::List => Some(gson_tree(Value::Array(m.list_whatsapp_sessions(app, client).await?.unwrap_or_default()))),
            NumberAction::PairingCode => {
                let code = required(args, "sessionCode")?;
                m.get_whatsapp_session_qr(app, client, &code).await?.map(|q| gson_tree(Value::Object(q)))
            }
            NumberAction::Remove => {
                let code = required(args, "sessionCode")?;
                m.unlink_whatsapp_session(app, client, &code).await?;
                Some(Value::Bool(true))
            }
            NumberAction::SetDefault => {
                let code = required(args, "sessionCode")?;
                Some(Value::Bool(m.mark_whatsapp_session_default(app, client, &code).await?.unwrap_or(false)))
            }
        })
    }
}

#[async_trait]
impl JavaFunction for WhatsappNumber {
    fn full_name(&self) -> &'static str {
        self.action.full_name()
    }

    async fn run(&self, args: &Map<Value>) -> Result<FunctionOutput, CoreError> {
        if !context::in_kirun() {
            return Err(server_function_only(&format!("{NAMESPACE}.{}", self.action.name())));
        }
        let (app_code, client_code) = (string(args, APP_CODE)?, string(args, CLIENT_CODE)?);
        let tenant = if self.action.own_client_only() {
            resolve_own(&self.security, app_code.as_deref(), client_code.as_deref()).await?
        } else {
            resolve(&self.security, app_code.as_deref(), client_code.as_deref()).await?
        };
        let full = self.action.full_name();
        let Some((app, client)) = tenant else { return Err(empty_result(full)) };
        match self.act(args, &app, &client).await? {
            Some(out) => Ok(output(self.action.output_name(), out)),
            None => Err(empty_result(full)),
        }
    }
}

/// `makeMessageFunctions`: SendWhatsapp, MakeCall, then `WhatsappNumberFunctions.all`.
pub fn all(deps: &Deps) -> Vec<Arc<dyn kirun::function::Function>> {
    let (message, security) = (deps.message.clone(), deps.security.clone());
    let mut functions = vec![
        Java::function(SendWhatsapp { message: message.clone(), security: security.clone() }),
        Java::function(MakeCall { message: message.clone(), security: security.clone() }),
    ];
    for action in NumberAction::ALL {
        functions.push(Java::function(WhatsappNumber { action, message: message.clone(), security: security.clone() }));
    }
    functions
}

#[cfg(test)]
mod tests {
    //! Ports of commons-core `MessageFunctionsTest` and `WhatsappNumberFunctionsTest`, over a
    //! fake security service (the same small client world) and a fake message service that
    //! records every call the way the Java fakes do.

    use std::collections::{BTreeMap, HashMap, HashSet};

    use axum::extract::RawQuery;
    use axum::http::{Method, Uri};
    use axum::response::IntoResponse;
    use axum::routing::{any, get};
    use axum::Router;
    use kirun::repository::{KIRunFunctionRepository, KIRunSchemaRepository};
    use kirun::runtime::FunctionExecutionParameters;
    use parking_lot::Mutex;
    use platform::upstream::Upstream;
    use serde_json::json;

    use super::*;
    use crate::functions::CoreFunction;
    use crate::testing::{auth, request, serve};

    const APP: &str = "leadzumptwo";

    /// The fakes' shared state: who manages whom, what the message service was asked, and the
    /// session `resolve` answers (none: an empty answer).
    struct World {
        manages: Mutex<HashSet<String>>,
        calls: Mutex<Vec<String>>,
        resolved: Mutex<Option<Value>>,
        /// Routes answered with an empty 200 instead (create, qr, messages, make, list).
        empty: Mutex<HashSet<&'static str>>,
    }

    fn q(r: Option<String>) -> HashMap<String, String> {
        crate::exec::parse_query(r.as_deref()).into_iter().collect()
    }

    /// `new TreeMap<>(request).toString()`.
    fn tree(body: &str) -> String {
        let v: serde_json::Map<String, Value> = serde_json::from_str(body).unwrap();
        let sorted: BTreeMap<String, Value> = v.into_iter().collect();
        let parts: Vec<String> = sorted.into_iter().map(|(k, v)| format!("{k}={}", to_java_string(&v))).collect();
        format!("{{{}}}", parts.join(", "))
    }

    /// SYSTEM(1, SYS) above FIN(7) and OTHER(55); FIN above BP1(90); BP1 above SUB(91). FIN
    /// writes the app; SYSTEM writes every app, which must never lend it out. FIN also reads
    /// "leadzump" and "ownerapp".
    async fn security(world: Arc<World>) -> String {
        let clients: HashMap<&str, Value> = HashMap::from([
            ("SYSTEM", json!({"id": 1, "code": "SYSTEM", "typeCode": "SYS"})),
            ("FIN", json!({"id": 7, "code": "FIN", "typeCode": "BUS"})),
            ("BP1", json!({"id": 90, "code": "BP1", "typeCode": "BUS"})),
            ("OTHER", json!({"id": 55, "code": "OTHER", "typeCode": "BUS"})),
            ("SUB", json!({"id": 91, "code": "SUB", "typeCode": "BUS"})),
        ]);
        let router = Router::new()
            .route(
                "/api/security/clients/internal/doesClientManageClientCode",
                get(move |RawQuery(r): RawQuery| {
                    let w = world.clone();
                    async move {
                        let p = q(r);
                        w.manages.lock().contains(&format!("{}:{}", p["managingClientCode"], p["clientCode"])).to_string()
                    }
                }),
            )
            .route(
                "/api/security/clients/internal/getClientByCode",
                get(move |RawQuery(r): RawQuery| {
                    let c = clients.get(q(r)["clientCode"].as_str()).cloned();
                    async move { c.map(|c| c.to_string()).unwrap_or_default() }
                }),
            )
            .route(
                "/api/security/clients/internal/clientHierarchy",
                get(|RawQuery(r): RawQuery| async move {
                    match q(r)["clientId"].as_str() {
                        "7" => "[7,1]",
                        "90" => "[90,7,1]",
                        "55" => "[55,1]",
                        "91" => "[91,90,7,1]",
                        _ => "[1]",
                    }
                }),
            )
            .route(
                "/api/security/applications/internal/hasWriteAccess",
                get(|RawQuery(r): RawQuery| async move {
                    let p = q(r);
                    (p["clientCode"] == "SYSTEM" || (p["appCode"] == APP && p["clientCode"] == "FIN")).to_string()
                }),
            )
            .route(
                "/api/security/applications/internal/hasReadAccess",
                get(|RawQuery(r): RawQuery| async move {
                    let p = q(r);
                    let (a, c) = (p["appCode"].as_str(), p["clientCode"].as_str());
                    if c == "BROKEN" {
                        return (axum::http::StatusCode::BAD_GATEWAY, r#"{"message":"security down"}"#).into_response();
                    }
                    let read = (a == "leadzump" && c == "FIN")
                        || (a == "ownerapp" && c == "FIN")
                        || (a == APP && ["FIN", "BP1", "SUB", "SYSTEM"].contains(&c));
                    read.to_string().into_response()
                }),
            );
        serve(router).await
    }

    async fn message(world: Arc<World>) -> String {
        let router = Router::new().fallback(any(move |method: Method, uri: Uri, RawQuery(r): RawQuery, body: String| {
            let w = world.clone();
            async move {
                let p = q(r);
                let (app, client) = (p.get("appCode").cloned().unwrap_or_default(), p.get("clientCode").cloned().unwrap_or_default());
                let path = uri.path().to_string();
                let rest = path.strip_prefix(crate::message_calls::WHATSAPP_SESSION_PATH).map(str::to_string);
                let (name, line, answer): (&'static str, String, String) = match (method.as_str(), rest.as_deref()) {
                    ("GET", Some("/resolve")) => {
                        let session = p.get("sessionCode").cloned().unwrap_or_else(|| "null".into());
                        let answer = w.resolved.lock().clone().map(|v| v.to_string()).unwrap_or_default();
                        ("resolve", format!("resolve {app} {client} {session}"), answer)
                    }
                    ("POST", Some("")) => ("create", format!("create {app} {client} {}", tree(&body)), r#"{"code":"SESS9","sessionState":"PAIRING","bridge":null}"#.into()),
                    ("GET", Some("")) => ("list", format!("list {app} {client}"), r#"[{"code":"SESS9","phone":null},null]"#.into()),
                    ("POST", Some(s)) if s.ends_with("/messages") => {
                        let id = s.trim_start_matches('/').trim_end_matches("/messages");
                        ("send", format!("send {app} {client} {id} {}", tree(&body)), r#"{"messageId":"wamid.9","status":null}"#.into())
                    }
                    ("GET", Some(s)) if s.ends_with("/qr") => {
                        ("qr", format!("qr {app} {client} {}", s.trim_start_matches('/').trim_end_matches("/qr")), r#"{"qr":"2@abc"}"#.into())
                    }
                    ("PATCH", Some(s)) if s.ends_with("/default") => {
                        ("default", format!("default {app} {client} {}", s.trim_start_matches('/').trim_end_matches("/default")), "true".into())
                    }
                    ("DELETE", Some(s)) => ("unlink", format!("unlink {app} {client} {}", s.trim_start_matches('/')), String::new()),
                    ("POST", None) if path == "/api/message/call/exotel/internal/make" => {
                        let owner = p.get("ownerService").cloned().unwrap_or_default();
                        ("call", format!("call {app} {client} {owner} {body}"), r#"{"sid":"sid-1"}"#.into())
                    }
                    _ => return axum::http::StatusCode::NOT_FOUND.into_response(),
                };
                w.calls.lock().push(line);
                if w.empty.lock().contains(name) {
                    return axum::http::StatusCode::OK.into_response();
                }
                answer.into_response()
            }
        }));
        serve(router).await
    }

    struct Fixture {
        world: Arc<World>,
        message: Arc<MessageCalls>,
        security: Arc<SecurityCalls>,
    }

    async fn fixture() -> Fixture {
        let world = Arc::new(World {
            manages: Default::default(),
            calls: Default::default(),
            resolved: Mutex::new(Some(json!({"code": "SESS1"}))),
            empty: Default::default(),
        });
        let sec = security(world.clone()).await;
        let msg = message(world.clone()).await;
        Fixture {
            world,
            message: Arc::new(MessageCalls::new(Upstream::fixed(&[&msg])).unwrap()),
            security: Arc::new(SecurityCalls::new(Upstream::fixed(&[&sec])).unwrap()),
        }
    }

    impl Fixture {
        fn send(&self) -> Java<SendWhatsapp> {
            Java::new(SendWhatsapp { message: self.message.clone(), security: self.security.clone() })
        }

        fn call(&self) -> Java<MakeCall> {
            Java::new(MakeCall { message: self.message.clone(), security: self.security.clone() })
        }

        fn number(&self, name: &str) -> Java<WhatsappNumber> {
            let action = NumberAction::ALL.into_iter().find(|a| a.name() == name).unwrap();
            Java::new(WhatsappNumber { action, message: self.message.clone(), security: self.security.clone() })
        }

        fn calls(&self) -> Vec<String> {
            self.world.calls.lock().clone()
        }

        fn manage(&self, pair: &str) {
            self.world.manages.lock().insert(pair.to_string());
        }
    }

    fn user_of(client_code: &str) -> Authentication {
        auth(
            json!({"user": {"id": 110, "clientId": 1}, "authenticated": true, "clientCode": client_code,
                   "loggedInFromClientCode": client_code, "accessTokenExpiryAt": 1}),
            Some(client_code),
            Some(APP),
        )
    }

    fn args(kv: &[(&str, Value)]) -> Map<Value> {
        kv.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
    }

    fn s(v: &str) -> Value {
        Value::String(v.to_string())
    }

    /// `internalExecute` as the Java tests call it: inside a definition or not, as `caller`.
    async fn run<F: JavaFunction>(f: &Java<F>, a: Map<Value>, caller: &str, definition: bool) -> Result<FunctionOutput, CoreError> {
        let ctx = request(user_of(caller), false, None);
        context::with_request(ctx, async {
            if definition {
                context::with_run(context::RunScope::default(), f.internal_execute(&a)).await
            } else {
                f.internal_execute(&a).await
            }
        })
        .await
    }

    fn result(o: Result<FunctionOutput, CoreError>) -> Map<Value> {
        o.unwrap().next().unwrap().get_result().clone()
    }

    fn status(o: Result<FunctionOutput, CoreError>) -> StatusCode {
        o.err().expect("an error").status()
    }

    // ---- MessageFunctionsTest

    #[tokio::test]
    async fn sends_from_default_number() {
        let f = fixture().await;
        let r = result(run(&f.send(), args(&[("to", s("919876543210")), ("text", s("hi"))]), "FIN", true).await);
        assert_eq!(r["sessionCode"], json!("SESS1"));
        assert_eq!(r["result"], json!({"messageId": "wamid.9"}), "nulls are left out as Gson leaves them");
        assert_eq!(f.calls(), [format!("resolve {APP} FIN null"), format!("send {APP} FIN SESS1 {{text=hi, to=919876543210}}")]);
    }

    #[tokio::test]
    async fn named_number() {
        let f = fixture().await;
        run(&f.send(), args(&[("to", s("91987")), ("text", s("hi")), ("sessionCode", s("SESS7"))]), "FIN", true).await.unwrap();
        assert_eq!(f.calls()[0], format!("resolve {APP} FIN SESS7"));
    }

    #[tokio::test]
    async fn other_tenant_refused() {
        let f = fixture().await;
        let o = run(&f.send(), args(&[("to", s("91987")), ("text", s("hi")), ("clientCode", s("OTHER"))]), "FIN", true).await;
        assert_eq!(o.err().unwrap().text(), "Not allowed to message on behalf of client OTHER");
        assert!(f.calls().is_empty(), "nothing may reach the internal routes for a refused tenant");
    }

    #[tokio::test]
    async fn partner_sends_for_managing_client() {
        let f = fixture().await;
        f.manage("FIN:BP1");
        run(&f.send(), args(&[("to", s("91987")), ("text", s("hi")), ("clientCode", s("FIN"))]), "BP1", true).await.unwrap();
        assert!(f.calls()[1].starts_with(&format!("send {APP} FIN SESS1")));
    }

    #[tokio::test]
    async fn system_numbers_refused() {
        let f = fixture().await;
        f.manage("SYSTEM:FIN");
        f.manage("SYSTEM:BP1");
        f.manage("FIN:BP1");
        for caller in ["FIN", "BP1", "OTHER"] {
            let o = run(&f.send(), args(&[("to", s("91987")), ("text", s("hi")), ("clientCode", s("SYSTEM"))]), caller, true).await;
            assert_eq!(status(o), StatusCode::FORBIDDEN, "{caller}");
        }
        assert!(f.calls().is_empty(), "nothing may reach the internal routes for SYSTEM");
    }

    #[tokio::test]
    async fn system_call_account_refused() {
        let f = fixture().await;
        f.manage("SYSTEM:FIN");
        let o = run(&f.call(), args(&[("toNumber", s("9876543210")), ("clientCode", s("SYSTEM"))]), "FIN", true).await;
        assert_eq!(status(o), StatusCode::FORBIDDEN);
        assert!(f.calls().is_empty());
    }

    #[tokio::test]
    async fn partner_refused_for_another_app() {
        let f = fixture().await;
        f.manage("FIN:BP1");
        let a = args(&[("to", s("91987")), ("text", s("hi")), ("clientCode", s("FIN")), ("appCode", s("leadzump"))]);
        assert_eq!(status(run(&f.send(), a, "BP1", true).await), StatusCode::FORBIDDEN);
        assert!(f.calls().is_empty());
    }

    #[tokio::test]
    async fn unreadable_app_refused() {
        let f = fixture().await;
        let o = run(&f.send(), args(&[("to", s("91987")), ("text", s("hi")), ("appCode", s("someoneElsesApp"))]), "FIN", true).await;
        assert_eq!(o.err().unwrap().text(), "Not allowed to message for app someoneElsesApp");
        assert!(f.calls().is_empty());
    }

    #[tokio::test]
    async fn no_linked_number() {
        let f = fixture().await;
        *f.world.resolved.lock() = None;
        let o = run(&f.send(), args(&[("to", s("91987")), ("text", s("hi"))]), "FIN", true).await;
        let e = o.err().unwrap();
        assert_eq!((e.status(), e.text()), (StatusCode::CONFLICT, format!("No WhatsApp number is linked for FIN in {APP}")));
        // A session without a code is no number either.
        *f.world.resolved.lock() = Some(json!({"code": null}));
        assert_eq!(status(run(&f.send(), args(&[("to", s("91987")), ("text", s("hi"))]), "FIN", true).await), StatusCode::CONFLICT);
        // A code that is not a string is used as its Java text.
        *f.world.resolved.lock() = Some(json!({"code": 12}));
        let r = result(run(&f.send(), args(&[("to", s("91987")), ("text", s("hi"))]), "FIN", true).await);
        assert_eq!(r["sessionCode"], json!("12"));
    }

    #[tokio::test]
    async fn nothing_to_send() {
        let f = fixture().await;
        let o = run(&f.send(), args(&[("to", s("91987"))]), "FIN", true).await;
        assert_eq!(o.err().unwrap().text(), "text or filePath is required");
        let o = run(&f.send(), args(&[("text", s("hi"))]), "FIN", true).await;
        assert_eq!(o.err().unwrap().text(), "to is required");
        let o = run(&f.call(), args(&[("toNumber", s(" "))]), "FIN", true).await;
        assert_eq!(o.err().unwrap().text(), "toNumber is required");
        assert!(f.calls().is_empty());
    }

    /// Java answers nothing when the definition marker is not "true"; core only ever sets it
    /// to "true", and outside a definition Java's `cv.get` throws, which is what this keeps.
    #[tokio::test]
    async fn only_in_definition_functions() {
        let f = fixture().await;
        let e = run(&f.send(), args(&[("to", s("91987")), ("text", s("hi"))]), "FIN", false).await.err().unwrap();
        assert_eq!((e.status(), e.text()), (StatusCode::INTERNAL_SERVER_ERROR, "Context does not contain key: KIRun Runtime".to_string()));
        assert!(run(&f.call(), args(&[("toNumber", s("9876543210"))]), "FIN", false).await.is_err());
        assert!(f.calls().is_empty());
    }

    #[test]
    fn media_request_shape() {
        let a = args(&[
            ("to", s("91987")),
            ("text", s("")),
            ("filePath", s("x/y.pdf")),
            ("kind", s("document")),
            ("fileName", s("y.pdf")),
            ("voiceNote", json!(false)),
        ]);
        let request = send_request(&a).unwrap();
        assert_eq!(request, json!({"to": "91987", "filePath": "x/y.pdf", "kind": "document", "fileName": "y.pdf"}));
        assert!(request.get("text").is_none());
        // Jackson writes the HashMap in its own order.
        let keys: Vec<&String> = request.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["fileName", "kind", "filePath", "to"]);
        // A voice note, as Gson's getAsBoolean reads it.
        assert_eq!(send_request(&args(&[("to", s("1")), ("voiceNote", json!(true))])).unwrap()["voiceNote"], json!(true));
        assert_eq!(send_request(&args(&[("to", s("1")), ("voiceNote", s("TRUE"))])).unwrap()["voiceNote"], json!(true));
        assert!(send_request(&args(&[("to", s("1")), ("voiceNote", json!(1))])).unwrap().get("voiceNote").is_none());
        assert!(send_request(&args(&[("to", s("1")), ("voiceNote", json!({}))])).unwrap().get("voiceNote").is_none());
        assert_eq!(send_request(&args(&[("mimeType", s("a/b")), ("resourceType", s("secured"))])).unwrap(), json!({"to": null, "mimeType": "a/b", "resourceType": "secured"}));
        assert!(send_request(&args(&[("to", json!({}))])).is_err());
    }

    #[tokio::test]
    async fn make_call_owned_by_core() {
        let f = fixture().await;
        let a = args(&[
            ("toNumber", s("9876543210")),
            ("callerId", s("08012345678")),
            ("connectionName", s("exotel")),
            ("toCountryCode", json!(91)),
            ("callerIdCountryCode", json!(0)),
        ]);
        let r = result(run(&f.call(), a, "FIN", true).await);
        assert_eq!(r["call"]["sid"], json!("sid-1"));
        let calls = f.calls();
        assert_eq!(calls.len(), 1);
        let call = &calls[0];
        assert!(call.starts_with(&format!("call {APP} FIN core ")), "{call}");
        let body: Value = serde_json::from_str(&call[call.find('{').unwrap()..]).unwrap();
        assert_eq!(body["toNumber"], json!({"number": "9876543210", "countryCode": 91}));
        assert_eq!(body["callerId"], json!({"number": "08012345678"}), "country code 0 is left to the default");
        assert_eq!(body["connectionName"], json!("exotel"));
    }

    #[test]
    fn call_request_shapes() {
        let r = call_request(&args(&[("toNumber", s("1")), ("toCountryCode", s("44")), ("callerId", s(" "))])).unwrap();
        assert_eq!(r, json!({"toNumber": {"number": "1", "countryCode": 44}}));
        let r = call_request(&args(&[("toNumber", s("1")), ("toCountryCode", json!(4294967387_i64)), ("connectionName", s(""))])).unwrap();
        assert_eq!(r["toNumber"]["countryCode"], json!(91), "intValue wraps as Java's does");
        let r = call_request(&args(&[("toNumber", s("1")), ("toCountryCode", json!(-3)), ("callerId", s("2")), ("callerIdCountryCode", json!(7.9))])).unwrap();
        assert_eq!(r, json!({"toNumber": {"number": "1"}, "callerId": {"number": "2", "countryCode": 7}}));
        assert_eq!(call_request(&args(&[("toCountryCode", json!(null))])).unwrap(), json!({"toNumber": {"number": null}}));
        assert_eq!(call_request(&args(&[("toNumber", s("1")), ("toCountryCode", s("x"))])).unwrap_err().text(), "For input string: \"x\"");
        assert_eq!(call_request(&args(&[("toNumber", s("1")), ("toCountryCode", json!(true))])).unwrap_err().text(), "For input string: \"true\"");
    }

    #[tokio::test]
    async fn app_code_resolution() {
        let f = fixture().await;
        let ctx = request(user_of("FIN"), false, None);
        context::with_request(ctx.clone(), async {
            assert_eq!(resolve(&f.security, Some("leadzump"), Some("")).await.unwrap(), Some(("leadzump".into(), "FIN".into())));
        })
        .await;
        context::with_request(ctx, async {
            let scope = context::RunScope { owner_app_code: Some("ownerapp".into()) };
            let t = context::with_run(scope, resolve(&f.security, Some(""), None)).await.unwrap().unwrap();
            assert_eq!(t.0, "ownerapp");
        })
        .await;
        // Without a security context Java's chain is empty.
        assert_eq!(resolve(&f.security, Some("x"), None).await.unwrap(), None);
        assert_eq!(resolve_own(&f.security, Some("x"), None).await.unwrap(), None);
    }

    #[tokio::test]
    async fn request_app_without_access_refused() {
        let f = fixture().await;
        let o = run(&f.send(), args(&[("to", s("91987")), ("text", s("hi"))]), "OTHER", true).await;
        assert_eq!(status(o), StatusCode::FORBIDDEN);
        assert!(f.calls().is_empty());
    }

    #[tokio::test]
    async fn manager_cannot_speak_as_managed_client() {
        let f = fixture().await;
        f.manage("FIN:BP1");
        let o = run(&f.send(), args(&[("to", s("91987")), ("text", s("hi")), ("clientCode", s("BP1"))]), "FIN", true).await;
        assert_eq!(status(o), StatusCode::FORBIDDEN);
        assert!(f.calls().is_empty());
    }

    #[tokio::test]
    async fn grandparent_refused() {
        let f = fixture().await;
        f.manage("FIN:BP1");
        f.manage("FIN:SUB");
        f.manage("BP1:SUB");
        let o = run(&f.call(), args(&[("toNumber", s("9876543210")), ("clientCode", s("FIN"))]), "SUB", true).await;
        assert_eq!(status(o), StatusCode::FORBIDDEN);
        assert!(f.calls().is_empty());
    }

    // ---- what the Java tests leave out

    #[tokio::test]
    async fn tenant_edges() {
        let f = fixture().await;
        let sec = &f.security;
        let in_request = |a: Authentication| request(a, false, None);
        // No app anywhere.
        let no_app = auth(json!({"clientCode": "FIN"}), Some("FIN"), None);
        context::with_request(in_request(no_app), async {
            assert_eq!(resolve(sec, None, None).await.unwrap_err().text(), "appCode is required");
            assert_eq!(resolve(sec, Some(" "), None).await.unwrap_err().status(), StatusCode::BAD_REQUEST);
        })
        .await;
        // The system client may message for any app, and acts as itself.
        let system = auth(json!({"clientCode": "SYSTEM", "clientTypeCode": "SYS"}), Some("SYSTEM"), Some("anyapp"));
        context::with_request(in_request(system), async {
            assert_eq!(resolve(sec, None, Some("SYSTEM")).await.unwrap(), Some(("anyapp".into(), "SYSTEM".into())));
        })
        .await;
        // A caller without a client.
        let clientless = auth(json!({}), None, Some(APP));
        context::with_request(in_request(clientless.clone()), async {
            assert_eq!(resolve(sec, None, None).await.unwrap_err().text(), format!("Not allowed to message for app {APP}"));
            assert_eq!(resolve_own(sec, None, None).await.unwrap_err().text(), format!("Not allowed to message for app {APP}"));
        })
        .await;
        let system_clientless = auth(json!({"clientTypeCode": "SYS"}), None, Some(APP));
        context::with_request(in_request(system_clientless), async {
            assert_eq!(resolve(sec, None, None).await.unwrap_err().text(), "clientCode is required");
            assert_eq!(resolve_own(sec, None, None).await.unwrap_err().text(), "clientCode is required");
        })
        .await;
        // Security failing is the call failing.
        let broken = auth(json!({"clientCode": "BROKEN"}), Some("BROKEN"), Some(APP));
        context::with_request(in_request(broken), async {
            assert_eq!(resolve(sec, None, None).await.unwrap_err().text(), "security down");
        })
        .await;
        // Naming one's own client explicitly is the own client.
        context::with_request(in_request(user_of("FIN")), async {
            assert_eq!(resolve(sec, None, Some("FIN")).await.unwrap(), Some((APP.into(), "FIN".into())));
            assert_eq!(resolve_own(sec, None, Some("FIN")).await.unwrap(), Some((APP.into(), "FIN".into())));
            assert_eq!(
                resolve_own(sec, None, Some("BP1")).await.unwrap_err().text(),
                "Only client FIN may manage its own WhatsApp numbers, not BP1"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn empty_answers_are_java_empty() {
        let f = fixture().await;
        f.world.empty.lock().extend(["send", "call"]);
        let o = run(&f.send(), args(&[("to", s("1")), ("text", s("hi"))]), "FIN", true).await;
        assert_eq!(o.err().unwrap().text(), "Function with id CoreServices.Message.SendWhatsapp not found");
        let o = run(&f.call(), args(&[("toNumber", s("1"))]), "FIN", true).await;
        assert_eq!(o.err().unwrap().status(), StatusCode::NOT_FOUND);
        // Without a security context, inside a definition.
        let outside = context::with_run(context::RunScope::default(), f.send().internal_execute(&args(&[("to", s("1")), ("text", s("hi"))]))).await;
        assert_eq!(outside.err().unwrap().status(), StatusCode::NOT_FOUND);
        let outside = context::with_run(context::RunScope::default(), f.call().internal_execute(&args(&[("toNumber", s("1"))]))).await;
        assert_eq!(outside.err().unwrap().status(), StatusCode::NOT_FOUND);
        let outside = context::with_run(context::RunScope::default(), f.number("ListWhatsappNumbers").internal_execute(&Map::new())).await;
        assert_eq!(outside.err().unwrap().status(), StatusCode::NOT_FOUND);
    }

    // ---- WhatsappNumberFunctionsTest

    #[tokio::test]
    async fn a_number_is_linked_for_the_callers_client_and_owned_by_core() {
        let f = fixture().await;
        let r = result(run(&f.number("LinkWhatsappNumber"), args(&[("phoneNumber", s("+919876543210"))]), "FIN", true).await);
        assert_eq!(r["session"]["code"], json!("SESS9"));
        assert!(r["session"].get("bridge").is_none());
        assert_eq!(f.calls(), [format!("create {APP} FIN {{ownerService=core, phoneNumber=+919876543210}}")]);
    }

    #[tokio::test]
    async fn a_product_id_is_passed_on() {
        let f = fixture().await;
        run(&f.number("LinkWhatsappNumber"), args(&[("phoneNumber", s(" +919876543210 ")), ("productId", s(" 12 "))]), "FIN", true)
            .await
            .unwrap();
        assert_eq!(f.calls()[0], format!("create {APP} FIN {{ownerService=core, phoneNumber=+919876543210, productId=12}}"));
    }

    #[tokio::test]
    async fn administration_is_own_client_only_even_for_a_partners_managing_client() {
        let f = fixture().await;
        f.manage("FIN:BP1");
        for name in ["LinkWhatsappNumber", "GetWhatsappPairingCode", "RemoveWhatsappNumber", "SetDefaultWhatsappNumber"] {
            let a = args(&[("phoneNumber", s("+91987")), ("sessionCode", s("SESS9")), ("clientCode", s("FIN"))]);
            assert_eq!(status(run(&f.number(name), a, "BP1", true).await), StatusCode::FORBIDDEN, "{name}");
        }
        assert!(f.calls().is_empty(), "nothing may reach the internal routes for a refused tenant");
    }

    #[tokio::test]
    async fn a_partner_may_list_its_managing_clients_numbers() {
        let f = fixture().await;
        f.manage("FIN:BP1");
        let r = result(run(&f.number("ListWhatsappNumbers"), args(&[("clientCode", s("FIN"))]), "BP1", true).await);
        // Null members dropped, nulls in the list kept.
        assert_eq!(r["numbers"], json!([{"code": "SESS9"}, null]));
        assert_eq!(f.calls(), [format!("list {APP} FIN")]);
    }

    #[tokio::test]
    async fn pairing_code_and_unlink_act_on_the_named_session() {
        let f = fixture().await;
        let r = result(run(&f.number("GetWhatsappPairingCode"), args(&[("sessionCode", s("SESS9"))]), "FIN", true).await);
        assert_eq!(r["pairing"]["qr"], json!("2@abc"));
        let r = result(run(&f.number("RemoveWhatsappNumber"), args(&[("sessionCode", s("SESS9"))]), "FIN", true).await);
        assert_eq!(r["removed"], json!(true));
        assert_eq!(f.calls(), [format!("qr {APP} FIN SESS9"), format!("unlink {APP} FIN SESS9")]);
    }

    #[tokio::test]
    async fn missing_arguments_are_a_400() {
        let f = fixture().await;
        let o = run(&f.number("LinkWhatsappNumber"), Map::new(), "FIN", true).await;
        assert_eq!(o.err().unwrap().text(), "phoneNumber is required");
        let o = run(&f.number("RemoveWhatsappNumber"), args(&[("sessionCode", s(" "))]), "FIN", true).await;
        assert_eq!(status(o), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn outside_a_server_function_every_one_is_refused() {
        let f = fixture().await;
        for name in ["LinkWhatsappNumber", "ListWhatsappNumbers", "GetWhatsappPairingCode", "RemoveWhatsappNumber"] {
            let o = run(&f.number(name), args(&[("phoneNumber", s("+91987")), ("sessionCode", s("S"))]), "FIN", false).await;
            let e = o.err().unwrap();
            assert_eq!(e.status(), StatusCode::FORBIDDEN);
            assert_eq!(e.text(), format!("CoreServices.Message.{name} can only be called from a server function"));
        }
        assert!(f.calls().is_empty());
    }

    #[test]
    fn no_name_is_a_prefix_or_part_of_another() {
        let mut names: Vec<&str> = NumberAction::ALL.iter().map(|a| a.name()).collect();
        names.push("SendWhatsapp");
        names.push("MakeCall");
        for a in &names {
            for b in &names {
                assert!(a == b || !b.to_lowercase().contains(&a.to_lowercase()), "{a} is inside {b}");
            }
        }
    }

    #[tokio::test]
    async fn a_number_is_made_the_default_for_the_callers_client() {
        let f = fixture().await;
        let r = result(run(&f.number("SetDefaultWhatsappNumber"), args(&[("sessionCode", s("SESS9"))]), "FIN", true).await);
        assert_eq!(r["marked"], json!(true));
        assert_eq!(f.calls(), [format!("default {APP} FIN SESS9")]);
    }

    #[tokio::test]
    async fn empty_number_answers() {
        let f = fixture().await;
        f.world.empty.lock().extend(["create", "qr", "list", "default"]);
        let o = run(&f.number("LinkWhatsappNumber"), args(&[("phoneNumber", s("1"))]), "FIN", true).await;
        assert_eq!(o.err().unwrap().text(), "Function with id CoreServices.Message.LinkWhatsappNumber not found");
        let o = run(&f.number("GetWhatsappPairingCode"), args(&[("sessionCode", s("S"))]), "FIN", true).await;
        assert_eq!(o.err().unwrap().status(), StatusCode::NOT_FOUND);
        assert_eq!(result(run(&f.number("ListWhatsappNumbers"), Map::new(), "FIN", true).await)["numbers"], json!([]));
        assert_eq!(result(run(&f.number("SetDefaultWhatsappNumber"), args(&[("sessionCode", s("S"))]), "FIN", true).await)["marked"], json!(false));
    }

    #[test]
    fn helpers_read_arguments_as_gson_does() {
        assert_eq!(string(&args(&[("k", json!(1.5))]), "k").unwrap().as_deref(), Some("1.5"));
        assert_eq!(string(&args(&[("k", Value::Null)]), "k").unwrap(), None);
        assert!(string(&args(&[("k", json!([]))]), "k").is_err());
        assert_eq!(gson_tree(json!({"a": null, "b": [null, {"c": null, "d": 1}]})), json!({"b": [null, {"d": 1}]}));
        assert!(!primitive_true(&json!(1)));
        assert_eq!(primitive_int(&json!(5)).unwrap(), 5);
    }

    /// Through the KIRun wrapper: Java's signatures, the argument validation, and the
    /// registration order of `makeMessageFunctions`.
    #[tokio::test]
    async fn as_kirun_functions() {
        let f = fixture().await;
        let storage = crate::testing::offline_storage_service().await;
        let mut deps = crate::testing::offline_deps("http://127.0.0.1:1", storage).await;
        deps.message = f.message.clone();
        deps.security = f.security.clone();
        let all = all(&deps);
        let names: Vec<String> = all.iter().map(|x| x.get_signature().get_full_name()).collect();
        assert_eq!(
            names,
            [
                "CoreServices.Message.SendWhatsapp",
                "CoreServices.Message.MakeCall",
                "CoreServices.Message.LinkWhatsappNumber",
                "CoreServices.Message.ListWhatsappNumbers",
                "CoreServices.Message.GetWhatsappPairingCode",
                "CoreServices.Message.RemoveWhatsappNumber",
                "CoreServices.Message.SetDefaultWhatsappNumber",
            ]
        );
        let ctx = request(user_of("FIN"), false, None);
        context::with_request(ctx, async {
            context::with_run(context::RunScope::default(), async {
                let mut fep = FunctionExecutionParameters::new(Arc::new(KIRunFunctionRepository::new()), Arc::new(KIRunSchemaRepository::new()))
                    .set_arguments(args(&[("to", s("91987")), ("text", s("hi"))]));
                let mut out = all[0].execute(&mut fep).await.unwrap();
                assert_eq!(out.next().unwrap().get_result()["sessionCode"], json!("SESS1"));
                // `to` has no default: validation refuses before anything is called.
                let mut fep = FunctionExecutionParameters::new(Arc::new(KIRunFunctionRepository::new()), Arc::new(KIRunSchemaRepository::new()))
                    .set_arguments(args(&[("text", s("hi"))]));
                assert!(all[0].execute(&mut fep).await.is_err());
                // The defaults fill in: no clientCode, toCountryCode 0.
                let mut fep = FunctionExecutionParameters::new(Arc::new(KIRunFunctionRepository::new()), Arc::new(KIRunSchemaRepository::new()))
                    .set_arguments(args(&[("toNumber", s("98"))]));
                all[1].execute(&mut fep).await.unwrap();
            })
            .await;
        })
        .await;
        assert_eq!(f.calls().last().unwrap(), &format!("call {APP} FIN core {{\"toNumber\":{{\"number\":\"98\"}}}}"));
    }
}
