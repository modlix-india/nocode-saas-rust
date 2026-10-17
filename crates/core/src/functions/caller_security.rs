//! `CallerSecurityFunctions`: the `CoreServices.Security` functions that act on users and
//! clients through security's own routes, with the caller's token, forwarded host and codes
//! (`IFeignSecurityAsCaller`), so security applies its own authorities and rules. core adds
//! the scope checks first: the target client must be the caller's own or one it manages.
//!
//! A refusal from those checks is reported the way security would have refused the route
//! (`asSecurityWould`): "Access Denied" when the caller lacks the route's authorities,
//! otherwise the function's own message. A refusal from security keeps security's status and
//! message (`fromFeign`).

use std::sync::Arc;

use async_trait::async_trait;
use axum::http::StatusCode;
use kirun::function::Function;
use kirun::model::{FunctionOutput, FunctionSignature};
use kirun::{Map as KMap, Value};
use reqwest::Method;
use serde_json::{json, Map};

use super::support::{
    definition_context_authentication, forbidden, has_user, id_of, ids_of, invalid_argument, is_related_client_or_false, output_map,
    required_argument, SECURITY_NAMESPACE,
};
use super::{java_sig, Core, CoreFunction};
use crate::authorities::has_authority;
use crate::clients::SecurityCalls;
use crate::context;
use crate::error::CoreError;
use crate::security_calls::{segment, CallerHeaders, FeignFailure, Id, SecurityAsCaller, CLIENTS, CLIENT_ACTIVITIES, CLIENT_MANAGERS, USERS};

const USER_FETCH_FLAGS: [&str; 6] = ["fetchProfiles", "fetchClients", "fetchManagingClients", "fetchCreatedBy", "fetchDesignation", "fetchReportingTo"];
const ACCESS_DENIED: &str = "Access Denied";
const CLIENT_UPDATE: &str = "Authorities.Client_UPDATE";
const CANNOT_UPDATE_USER: &str = "Cannot update user for the selected client";
const USER_STATUS_REFUSED: &str = "selected user doesn't have access to change status code";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    QueryUsers,
    GetUser,
    CreateUser,
    UpdateUser,
    DeleteUser,
    SetUserStatus,
    AssignProfile,
    RemoveProfile,
    SetClientStatus,
    UpdateClient,
    DeleteClient,
    AddClientManager,
    RemoveClientManager,
    ReplaceClientManager,
    SetClientManagers,
    MigrateClientManagers,
    LogClientActivity,
    QueryClientActivities,
    GetAppProfiles,
}

/// `CallerSecurityFunctions.all` order.
pub const ALL: [Op; 19] = [
    Op::QueryUsers,
    Op::GetUser,
    Op::CreateUser,
    Op::UpdateUser,
    Op::DeleteUser,
    Op::SetUserStatus,
    Op::AssignProfile,
    Op::RemoveProfile,
    Op::SetClientStatus,
    Op::UpdateClient,
    Op::DeleteClient,
    Op::AddClientManager,
    Op::RemoveClientManager,
    Op::ReplaceClientManager,
    Op::SetClientManagers,
    Op::MigrateClientManagers,
    Op::LogClientActivity,
    Op::QueryClientActivities,
    Op::GetAppProfiles,
];

impl Op {
    pub fn name(self) -> &'static str {
        match self {
            Op::QueryUsers => "QueryUsers",
            Op::GetUser => "GetUser",
            Op::CreateUser => "CreateUser",
            Op::UpdateUser => "UpdateUser",
            Op::DeleteUser => "DeleteUser",
            Op::SetUserStatus => "SetUserStatus",
            Op::AssignProfile => "AssignProfile",
            Op::RemoveProfile => "RemoveProfile",
            Op::SetClientStatus => "SetClientStatus",
            Op::UpdateClient => "UpdateClient",
            Op::DeleteClient => "DeleteClient",
            Op::AddClientManager => "AddClientManager",
            Op::RemoveClientManager => "RemoveClientManager",
            Op::ReplaceClientManager => "ReplaceClientManager",
            Op::SetClientManagers => "SetClientManagers",
            Op::MigrateClientManagers => "MigrateClientManagers",
            Op::LogClientActivity => "LogClientActivity",
            Op::QueryClientActivities => "QueryClientActivities",
            Op::GetAppProfiles => "GetAppProfiles",
        }
    }

    fn output_name(self) -> &'static str {
        match self {
            Op::QueryUsers | Op::QueryClientActivities | Op::GetAppProfiles => "page",
            Op::GetUser | Op::CreateUser | Op::UpdateUser => "user",
            Op::DeleteUser | Op::DeleteClient => "deleted",
            Op::UpdateClient => "client",
            Op::MigrateClientManagers => "count",
            Op::LogClientActivity => "activity",
            _ => "result",
        }
    }

    /// `routeAuthorities()`: what security's route needs, checked when a scope check refuses.
    fn route_authorities(self) -> &'static [&'static str] {
        match self {
            Op::CreateUser => &["Authorities.User_CREATE"],
            Op::DeleteUser => &["Authorities.User_DELETE"],
            Op::SetUserStatus => &["Authorities.User_UPDATE"],
            Op::AssignProfile | Op::RemoveProfile => &["Authorities.User_UPDATE", "Authorities.Profile_READ"],
            Op::SetClientStatus
            | Op::UpdateClient
            | Op::AddClientManager
            | Op::RemoveClientManager
            | Op::ReplaceClientManager
            | Op::SetClientManagers
            | Op::MigrateClientManagers => &[CLIENT_UPDATE],
            Op::DeleteClient => &["Authorities.Client_DELETE"],
            _ => &[],
        }
    }
}

/// `permissionRequired(what)`: security's own `forbidden_permission` text, built by core.
fn permission_required(what: &str) -> CoreError {
    CoreError::msg(StatusCode::FORBIDDEN, crate::error::messages::FORBIDDEN_PERMISSION, &[what])
}

fn manager_refusal(operation: &str) -> CoreError {
    permission_required(&format!("Client Manager {operation}"))
}

/// What went wrong inside a function, before it is reported.
#[derive(Debug)]
enum Fail {
    Core(CoreError),
    /// `OutOfScope`: a 403 the scope checks raise (Java's text, the client refused).
    OutOfScope(String, Id),
    /// `UnknownUser`: a 404 for a user security does not know.
    UnknownUser(Id),
    /// A `FeignException` from security.
    Feign(FeignFailure),
}

impl From<CoreError> for Fail {
    fn from(e: CoreError) -> Self {
        Fail::Core(e)
    }
}

impl From<FeignFailure> for Fail {
    fn from(e: FeignFailure) -> Self {
        Fail::Feign(e)
    }
}

type R<T> = Result<T, Fail>;

/// `CallerSecurityFunctions.Caller`.
#[derive(Debug, Clone)]
pub struct Caller {
    user_id: Id,
    client_id: Id,
    headers: CallerHeaders,
    authorities: Vec<String>,
}

fn blank(s: Option<&str>) -> bool {
    s.is_none_or(|s| s.trim().is_empty())
}

/// `caller(functionName)`: only inside a server function, for a signed-in user with a token,
/// inside a request.
fn caller(name: &str) -> Result<Caller, CoreError> {
    let full = format!("{SECURITY_NAMESPACE}.{name}");
    let ca = definition_context_authentication(name)?;
    if !ca.is_authenticated() || !has_user(&ca) {
        return Err(forbidden("CORE.SIGNED_IN_USER_REQUIRED", format!("{full} needs a signed in user")).param("function", &full));
    }
    let Some(token) = ca.access_token().filter(|t| !t.trim().is_empty()) else {
        return Err(forbidden("CORE.CALLER_TOKEN_MISSING", format!("{full} has no caller token to act with")).param("function", &full));
    };
    let req = context::request();
    let host = req.as_ref().map(|r| r.forwarded_host.clone()).unwrap_or_default();
    if host.trim().is_empty() {
        return Err(forbidden(
            "CORE.CALLER_REQUEST_REQUIRED",
            format!("{full} acts only inside a caller's request; this execution (an event, a schedule or an internal call) has no request to act as"),
        )
        .param("function", &full));
    }
    let port = req.as_ref().map(|r| r.forwarded_port.clone()).unwrap_or_default();
    let client_code = if blank(ca.url_client_code()) { ca.client_code().unwrap_or("") } else { ca.url_client_code().unwrap_or("") };
    let app_code = if blank(ca.url_app_code()) { "" } else { ca.url_app_code().unwrap_or("") };
    Ok(Caller {
        user_id: ca.ca.user.id,
        client_id: ca.ca.user.client_id,
        headers: CallerHeaders {
            authorization: token.to_string(),
            forwarded_host: host,
            forwarded_port: port,
            client_code: client_code.to_string(),
            app_code: app_code.to_string(),
        },
        authorities: ca.authorities().to_vec(),
    })
}

fn cut(s: &str, n: usize) -> &str {
    match s.char_indices().nth(n) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

/// `fromFeign`: security's status (502 without one) and its message, or its text, or a
/// generic line. A coded refusal from a Rust security unit is passed on as it came.
fn from_feign(name: &str, fe: &FeignFailure) -> CoreError {
    let status = fe.status.and_then(|s| StatusCode::from_u16(s).ok()).filter(|s| s.canonical_reason().is_some()).unwrap_or(StatusCode::BAD_GATEWAY);
    if let Some(relayed) = serde_json::from_str::<Value>(fe.body.trim()).ok().and_then(|v| crate::auth::relayed(status, &v)) {
        return relayed;
    }
    let mut message: Option<String> = None;
    let mut text: Option<String> = None;
    let body = fe.body.trim();
    if !body.is_empty() {
        text = Some(body.to_string());
        if body.starts_with('{') {
            if let Ok(Value::Object(o)) = serde_json::from_str::<Value>(body) {
                match o.get("message") {
                    Some(Value::String(s)) => message = Some(s.clone()),
                    Some(Value::Number(n)) => message = Some(crate::gson::number_to_java_string(n)),
                    Some(Value::Bool(b)) => message = Some(b.to_string()),
                    _ => {}
                }
            }
            text = None;
        }
    }
    let message = match message.filter(|m| !m.trim().is_empty()) {
        Some(m) => m,
        None => match text.as_deref().filter(|t| !t.starts_with('<')) {
            Some(t) => cut(t, 500).to_string(),
            None => format!(
                "{SECURITY_NAMESPACE}.{name}: security answered {}{}",
                fe.status.filter(|s| *s >= 100).map(|s| s.to_string()).unwrap_or_else(|| "nothing".into()),
                text.as_deref().map(|t| format!(" ({})", cut(t, 200))).unwrap_or_default()
            ),
        },
    };
    CoreError::new(status, message)
}

/// `Base.parse`: Gson's lenient `JsonParser.parseString`; blank is `JsonNull`.
fn parse(body: Option<String>) -> R<Option<Value>> {
    let Some(b) = body else { return Ok(None) };
    if b.trim().is_empty() {
        return Ok(Some(Value::Null));
    }
    match serde_json::from_str::<Value>(&b) {
        Ok(v) => Ok(Some(v)),
        Err(_) if !b.trim().contains(|c: char| c.is_whitespace() || "{}[]:,\"'".contains(c)) => Ok(Some(Value::String(b.trim().to_string()))),
        Err(e) => Err(Fail::Core(CoreError::unknown(format!("com.google.gson.stream.MalformedJsonException: {e}")))),
    }
}

/// `acceptedCount`: a boolean as is, a number as "not zero", anything else true.
fn accepted_count(body: Option<String>) -> R<Value> {
    Ok(match parse(body)? {
        None => Value::Bool(true),
        Some(Value::Bool(b)) => Value::Bool(b),
        Some(Value::Number(n)) => Value::Bool(n.as_f64().is_some_and(|f| f != 0.0)),
        Some(_) => Value::Bool(true),
    })
}

fn id(args: &KMap<Value>, name: &str) -> Result<Option<Id>, CoreError> {
    id_of(name, args.get(name))
}

fn required_id(args: &KMap<Value>, name: &str) -> Result<Id, CoreError> {
    id(args, name)?.ok_or_else(|| required_argument(name))
}

fn required_object<'a>(args: &'a KMap<Value>, name: &str) -> Result<&'a Map<String, Value>, CoreError> {
    args.get(name).and_then(Value::as_object).ok_or_else(|| invalid_argument(name, "an object", format!("{name} must be an object")))
}

fn bool_arg(args: &KMap<Value>, name: &str, default: bool) -> bool {
    match args.get(name) {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s.trim().eq_ignore_ascii_case("true"),
        _ => default,
    }
}

fn string_arg(args: &KMap<Value>, name: &str) -> Option<String> {
    let s = match args.get(name)? {
        Value::String(s) => s.clone(),
        Value::Number(n) => crate::gson::number_to_java_string(n),
        Value::Bool(b) => b.to_string(),
        _ => return None,
    };
    let t = s.trim();
    (!t.is_empty()).then(|| t.to_string())
}

fn body_client_id(body: &Map<String, Value>) -> Result<Option<Id>, CoreError> {
    id_of("clientId", body.get("clientId"))
}

fn status_arg(args: &KMap<Value>) -> Result<&'static str, CoreError> {
    let s = string_arg(args, "status").unwrap_or_default().to_uppercase().replace(['_', ' '], "");
    match s.as_str() {
        "ACTIVE" => Ok("ACTIVE"),
        "INACTIVE" => Ok("INACTIVE"),
        _ => Err(invalid_argument("status", "ACTIVE or INACTIVE", "status must be ACTIVE or INACTIVE")),
    }
}

/// One `CallerSecurityFunctions` function.
pub struct CallerSecurity {
    op: Op,
    signature: FunctionSignature,
    security: Arc<SecurityCalls>,
    as_caller: Arc<SecurityAsCaller>,
}

/// The 19 functions, in Java's order.
pub fn all(security: &Arc<SecurityCalls>) -> Vec<Arc<dyn Function>> {
    let as_caller = Arc::new(SecurityAsCaller::new(security.clone()));
    ALL.iter().map(|op| Arc::new(Core(CallerSecurity::new(*op, security.clone(), as_caller.clone()))) as Arc<dyn Function>).collect()
}

impl CallerSecurity {
    pub fn new(op: Op, security: Arc<SecurityCalls>, as_caller: Arc<SecurityAsCaller>) -> Self {
        Self { op, signature: java_sig::signature(&format!("{SECURITY_NAMESPACE}.{}", op.name())), security, as_caller }
    }

    fn name(&self) -> &'static str {
        self.op.name()
    }

    async fn call(&self, c: &Caller, method: Method, path: &str, query: &[(String, String)], body: Option<&Value>) -> R<Option<String>> {
        Ok(self.as_caller.call(&c.headers, method, path, query, body).await?)
    }

    async fn call_parsed(&self, c: &Caller, method: Method, path: &str, query: &[(String, String)], body: Option<&Value>) -> R<Value> {
        Ok(parse(self.call(c, method, path, query, body).await?)?.unwrap_or(Value::Null))
    }

    /// `requireOwnOrManaged`.
    async fn require_own_or_managed(&self, c: &Caller, target: Option<Id>) -> R<()> {
        let Some(t) = target else { return Err(required_argument("clientId").into()) };
        if t == c.client_id {
            return Ok(());
        }
        self.require_managed(c, Some(t)).await
    }

    /// `requireManaged`: a client the caller's client manages (not its own).
    async fn require_managed(&self, c: &Caller, target: Option<Id>) -> R<()> {
        let Some(t) = target else { return Err(required_argument("clientId").into()) };
        if t == c.client_id {
            return Err(forbidden("CORE.OWN_CLIENT_REFUSED", format!("{SECURITY_NAMESPACE}.{} does not act on the caller's own client {t}", self.name()))
                .param("function", format!("{SECURITY_NAMESPACE}.{}", self.name()))
                .param("client", t)
                .into());
        }
        let managed = self.security.does_client_manage_client(c.client_id, t).await.ok().flatten().unwrap_or(false);
        if managed {
            Ok(())
        } else {
            Err(Fail::OutOfScope(format!("{SECURITY_NAMESPACE}.{}: client {t} is neither the caller's client nor one it manages", self.name()), t))
        }
    }

    /// `requireReadable`: the caller's client, one it manages, or the one that manages it.
    async fn require_readable(&self, c: &Caller, target: Option<Id>) -> R<()> {
        let Some(t) = target.filter(|t| *t != c.client_id) else { return Ok(()) };
        if is_related_client_or_false(&self.security, Some(c.client_id), Some(t), Some(c.headers.app_code.as_str())).await {
            Ok(())
        } else {
            Err(Fail::OutOfScope(
                format!("{SECURITY_NAMESPACE}.{}: client {t} is not the caller's client, one it manages or the client that manages it", self.name()),
                t,
            ))
        }
    }

    /// `userClientId`: a 404 (or nothing) from security is an unknown user.
    async fn user_client_id(&self, user_id: Id) -> R<Option<Id>> {
        match self.security.user_internal_raw(user_id).await {
            Ok(Some(u)) => Ok(u.get("clientId").and_then(crate::security_calls::id_value)),
            Ok(None) => Err(Fail::UnknownUser(user_id)),
            Err(fe) if fe.status == Some(404) => Err(Fail::UnknownUser(user_id)),
            Err(fe) => Err(Fail::Feign(fe)),
        }
    }

    async fn require_user_in_scope(&self, c: &Caller, user_id: Id) -> R<()> {
        if user_id == c.user_id {
            return Ok(());
        }
        let client = self.user_client_id(user_id).await?;
        self.require_own_or_managed(c, client).await
    }

    async fn require_users_in_scope(&self, c: &Caller, users: &[Id]) -> R<()> {
        for u in users {
            self.require_user_in_scope(c, *u).await?;
        }
        Ok(())
    }

    /// `asSecurityWould` for a scope refusal; `fromFeign` for security's.
    fn report(&self, args: &KMap<Value>, c: &Caller, f: Fail) -> CoreError {
        match f {
            Fail::Core(e) => e,
            Fail::Feign(fe) => from_feign(self.name(), &fe),
            scope => {
                for a in self.op.route_authorities() {
                    if !has_authority(Some(a), &c.authorities).unwrap_or(false) {
                        return forbidden("COMMON.PERMISSION_REQUIRED", ACCESS_DENIED).param("permission", a);
                    }
                }
                match scope {
                    Fail::OutOfScope(m, client) => self.security_refusal(args, m, client),
                    Fail::UnknownUser(id) => self.security_not_found(args, id),
                    _ => unreachable!("scope failures only"),
                }
            }
        }
    }

    fn security_refusal(&self, args: &KMap<Value>, message: String, client: Id) -> CoreError {
        let show = |n: &str| id(args, n).ok().flatten().map(|i| i.to_string()).unwrap_or_else(|| "null".into());
        match self.op {
            Op::CreateUser => CoreError::msg(StatusCode::FORBIDDEN, crate::error::messages::FORBIDDEN_CREATE, &["User"]),
            Op::UpdateUser | Op::DeleteUser => forbidden("CORE.USER_UPDATE_FORBIDDEN", CANNOT_UPDATE_USER),
            Op::SetUserStatus => forbidden("CORE.USER_STATUS_FORBIDDEN", USER_STATUS_REFUSED),
            Op::AssignProfile | Op::RemoveProfile => {
                forbidden("CORE.PROFILE_FORBIDDEN_FOR_USER", format!("{} profile forbidden for the {} user", show("profileId"), show("userId")))
            }
            Op::SetClientStatus => forbidden("CORE.CLIENT_STATUS_FORBIDDEN", "selected client doesn't have access to change status code"),
            Op::UpdateClient => permission_required("Client UPDATE"),
            Op::DeleteClient => permission_required("Client READ"),
            Op::AddClientManager => manager_refusal("CREATE"),
            Op::RemoveClientManager => manager_refusal("DELETE"),
            Op::ReplaceClientManager => manager_refusal("UPDATE"),
            Op::SetClientManagers => manager_refusal("SYNC"),
            Op::MigrateClientManagers => manager_refusal("MIGRATE"),
            Op::LogClientActivity => permission_required("Client Activity"),
            _ => forbidden("CORE.CLIENT_OUT_OF_SCOPE", message).param("function", format!("{SECURITY_NAMESPACE}.{}", self.name())).param("client", client),
        }
    }

    fn security_not_found(&self, args: &KMap<Value>, user_id: Id) -> CoreError {
        match self.op {
            Op::UpdateUser if bool_arg(args, "partial", true) => forbidden("CORE.USER_UPDATE_FORBIDDEN", CANNOT_UPDATE_USER),
            Op::SetUserStatus => forbidden("CORE.USER_STATUS_FORBIDDEN", USER_STATUS_REFUSED),
            Op::AddClientManager => manager_refusal("CREATE"),
            Op::RemoveClientManager => manager_refusal("DELETE"),
            Op::ReplaceClientManager => manager_refusal("UPDATE"),
            Op::SetClientManagers => manager_refusal("SYNC"),
            Op::MigrateClientManagers => manager_refusal("MIGRATE"),
            _ => CoreError::msg(StatusCode::NOT_FOUND, crate::error::messages::OBJECT_NOT_FOUND, &["User", &user_id.to_string()]),
        }
    }

    async fn act(&self, args: &KMap<Value>, c: &Caller) -> R<Value> {
        match self.op {
            Op::QueryUsers => self.query_users(args, c).await,
            Op::GetUser => {
                let user_id = required_id(args, "userId")?;
                let Some(user) = parse(self.call(c, Method::GET, &format!("{USERS}/{user_id}"), &[], None).await?)? else {
                    return Ok(Value::Null);
                };
                if user_id != c.user_id {
                    let client = match user.as_object() {
                        Some(o) => id_of("clientId", o.get("clientId"))?,
                        None => None,
                    };
                    let client = match client {
                        Some(cl) => Some(cl),
                        None => self.user_client_id(user_id).await?,
                    };
                    self.require_readable(c, client).await?;
                }
                Ok(user)
            }
            Op::CreateUser => {
                let user = required_object(args, "user")?;
                let client = body_client_id(user)?;
                self.require_own_or_managed(c, Some(client.unwrap_or(c.client_id))).await?;
                self.call_parsed(c, Method::POST, USERS, &[], Some(&Value::Object(user.clone()))).await
            }
            Op::UpdateUser => {
                let user = required_object(args, "user")?;
                let user_id = match id(args, "userId")? {
                    Some(u) => u,
                    None => id_of("user.id", user.get("id"))?.ok_or_else(|| required_argument("userId"))?,
                };
                let partial = bool_arg(args, "partial", true);
                let moves_to = body_client_id(user)?;
                let current = self.user_client_id(user_id).await?;
                self.require_own_or_managed(c, current).await?;
                if moves_to.is_some() && moves_to != current {
                    self.require_own_or_managed(c, moves_to).await?;
                }
                let method = if partial { Method::PATCH } else { Method::PUT };
                self.call_parsed(c, method, &format!("{USERS}/{user_id}"), &[], Some(&Value::Object(user.clone()))).await
            }
            Op::DeleteUser => {
                let user_id = required_id(args, "userId")?;
                self.require_user_in_scope(c, user_id).await?;
                accepted_count(self.call(c, Method::DELETE, &format!("{USERS}/{user_id}"), &[], None).await?)
            }
            Op::SetUserStatus => {
                let user_id = required_id(args, "userId")?;
                let status = status_arg(args)?;
                self.require_user_in_scope(c, user_id).await?;
                let path = if status == "ACTIVE" { "makeUserActive" } else { "makeUserInActive" };
                self.call_parsed(c, Method::PATCH, &format!("{USERS}/{path}"), &[("userId".into(), user_id.to_string())], None).await
            }
            Op::AssignProfile | Op::RemoveProfile => {
                let user_id = required_id(args, "userId")?;
                let profile_id = required_id(args, "profileId")?;
                self.require_user_in_scope(c, user_id).await?;
                let verb = if self.op == Op::AssignProfile { "assignProfile" } else { "removeProfile" };
                self.call_parsed(c, Method::GET, &format!("{USERS}/{user_id}/{verb}/{profile_id}"), &[], None).await
            }
            Op::SetClientStatus => {
                let client_id = required_id(args, "clientId")?;
                let status = status_arg(args)?;
                self.require_managed(c, Some(client_id)).await?;
                let path = if status == "ACTIVE" { "makeClientActive" } else { "makeClientInActive" };
                self.call_parsed(c, Method::GET, &format!("{CLIENTS}/{path}"), &[("clientId".into(), client_id.to_string())], None).await
            }
            Op::UpdateClient => {
                let client = required_object(args, "client")?;
                let client_id = match id(args, "clientId")? {
                    Some(i) => i,
                    None => id_of("client.id", client.get("id"))?.ok_or_else(|| required_argument("clientId"))?,
                };
                let partial = bool_arg(args, "partial", true);
                self.require_own_or_managed(c, Some(client_id)).await?;
                let method = if partial { Method::PATCH } else { Method::PUT };
                self.call_parsed(c, method, &format!("{CLIENTS}/{client_id}"), &[], Some(&Value::Object(client.clone()))).await
            }
            Op::DeleteClient => {
                let client_id = required_id(args, "clientId")?;
                self.require_managed(c, Some(client_id)).await?;
                accepted_count(self.call(c, Method::DELETE, &format!("{CLIENTS}/{client_id}"), &[], None).await?)
            }
            Op::AddClientManager | Op::RemoveClientManager => {
                let user_id = required_id(args, "userId")?;
                let client_id = required_id(args, "clientId")?;
                self.require_own_or_managed(c, Some(client_id)).await?;
                self.require_user_in_scope(c, user_id).await?;
                let method = if self.op == Op::AddClientManager { Method::POST } else { Method::DELETE };
                self.call_parsed(c, method, &format!("{CLIENT_MANAGERS}/{user_id}/{client_id}"), &[], None).await
            }
            Op::ReplaceClientManager => {
                let client_id = required_id(args, "clientId")?;
                let new_manager = required_id(args, "newManagerId")?;
                let old_manager = id(args, "oldManagerId")?;
                let mut users = vec![new_manager];
                let mut params = Vec::new();
                if let Some(o) = old_manager {
                    users.push(o);
                    params.push(("oldManagerId".to_string(), o.to_string()));
                }
                params.push(("newManagerId".to_string(), new_manager.to_string()));
                self.require_own_or_managed(c, Some(client_id)).await?;
                self.require_users_in_scope(c, &users).await?;
                self.call_parsed(c, Method::POST, &format!("{CLIENT_MANAGERS}/{client_id}"), &params, None).await
            }
            Op::SetClientManagers => {
                let client_id = required_id(args, "clientId")?;
                let managers = ids_of("managerIds", args.get("managerIds"))?;
                let body = Value::Array(managers.iter().map(|m| Value::from(*m)).collect());
                self.require_own_or_managed(c, Some(client_id)).await?;
                self.require_users_in_scope(c, &managers).await?;
                self.call_parsed(c, Method::PUT, &format!("{CLIENT_MANAGERS}/{client_id}/managers"), &[], Some(&body)).await
            }
            Op::MigrateClientManagers => {
                let from = required_id(args, "fromUserId")?;
                let to = required_id(args, "toUserId")?;
                let remove = bool_arg(args, "removeManager", true);
                self.require_users_in_scope(c, &[from, to]).await?;
                let params = [("fromUid".to_string(), from.to_string()), ("removeManager".to_string(), remove.to_string())];
                self.call_parsed(c, Method::POST, &format!("{CLIENT_MANAGERS}/migrateTo/{to}"), &params, None).await
            }
            Op::LogClientActivity => {
                let activity = required_object(args, "activity")?;
                let named = match activity.get("activityName") {
                    Some(Value::String(s)) => !s.trim().is_empty(),
                    Some(Value::Number(_)) | Some(Value::Bool(_)) => true,
                    _ => false,
                };
                if !named {
                    return Err(required_argument("Activity name").into());
                }
                let client = body_client_id(activity)?;
                self.require_own_or_managed(c, Some(client.unwrap_or(c.client_id))).await?;
                self.call_parsed(c, Method::POST, CLIENT_ACTIVITIES, &[], Some(&Value::Object(activity.clone()))).await
            }
            Op::QueryClientActivities => {
                let client_id = required_id(args, "clientId")?;
                let body = match args.get("query") {
                    Some(q @ Value::Object(_)) => q.clone(),
                    _ => json!({}),
                };
                let page = self.call_parsed(c, Method::POST, &format!("{CLIENT_ACTIVITIES}/{client_id}/query"), &[], Some(&body)).await?;
                self.require_own_or_managed(c, Some(client_id)).await?;
                Ok(page)
            }
            Op::GetAppProfiles => self.app_profiles(args, c).await,
        }
    }

    async fn query_users(&self, args: &KMap<Value>, c: &Caller) -> R<Value> {
        let mut query = match args.get("query") {
            Some(Value::Object(o)) => o.clone(),
            _ => Map::new(),
        };
        let client_id = id(args, "clientId")?;
        let mut named: Vec<Id> = Vec::new();
        if let Some(cond) = query.get("condition") {
            condition_client_ids(cond, &mut named)?;
        }
        if let Some(cid) = client_id {
            if !named.contains(&cid) {
                named.push(cid);
            }
            let cond = query.get("condition").cloned();
            query.insert("condition".into(), and_client(cond, cid));
        }
        let mut params = Vec::new();
        for f in USER_FETCH_FLAGS {
            if bool_arg(args, f, false) {
                params.push((f.to_string(), "true".to_string()));
            }
        }
        if let Some(a) = string_arg(args, "appCode") {
            params.push(("appCode".into(), a));
        }
        if let Some(a) = id(args, "appId")? {
            params.push(("appId".into(), a.to_string()));
        }
        let page = self.call_parsed(c, Method::POST, &format!("{USERS}/query"), &params, Some(&Value::Object(query))).await?;
        for n in named {
            self.require_own_or_managed(c, Some(n)).await?;
        }
        Ok(page)
    }

    async fn app_profiles(&self, args: &KMap<Value>, c: &Caller) -> R<Value> {
        let int_arg = |name: &str| -> i64 {
            match args.get(name) {
                Some(Value::Number(n)) => n.as_i64().filter(|i| i32::try_from(*i).is_ok()).or_else(|| n.as_f64().map(|f| f as i32 as i64)).unwrap_or(-1),
                Some(Value::String(s)) => s.trim().parse::<i32>().map(i64::from).unwrap_or(-1),
                _ => -1,
            }
        };
        let mut params = Vec::new();
        let page = int_arg("page");
        let size = int_arg("size");
        if page >= 0 {
            params.push(("page".to_string(), page.to_string()));
        }
        if size > 0 {
            params.push(("size".to_string(), size.to_string()));
        }
        if let Some(s) = string_arg(args, "sort") {
            params.push(("sort".to_string(), s));
        }
        let app_id = match id(args, "appId")? {
            Some(a) => a,
            None => {
                let code = string_arg(args, "appCode").unwrap_or_else(|| c.headers.app_code.clone());
                self.app_id_of(c, &code).await?
            }
        };
        self.call_parsed(c, Method::GET, &format!("/api/security/app/{app_id}/profiles"), &params, None).await
    }

    async fn app_id_of(&self, c: &Caller, app_code: &str) -> R<Id> {
        if app_code.trim().is_empty() {
            return Err(required_argument("appId or appCode").into());
        }
        let not_found =
            || Fail::Core(CoreError::coded(StatusCode::NOT_FOUND, "CORE.APP_NOT_FOUND", format!("No app found with code : {app_code}")).param("app", app_code));
        let Some(app) = parse(self.call(c, Method::GET, &format!("/api/security/applications/appCode/{}", segment(app_code)), &[], None).await?)?
        else {
            return Err(not_found());
        };
        let id = match app.as_object() {
            Some(o) => id_of("appId", o.get("id"))?,
            None => None,
        };
        id.ok_or_else(not_found)
    }
}

/// `QueryUsers.andClient`: the caller's condition AND `clientId = id`.
fn and_client(condition: Option<Value>, client_id: Id) -> Value {
    let filter = json!({"field": "clientId", "operator": "EQUALS", "value": client_id});
    match condition {
        None | Some(Value::Null) => filter,
        Some(Value::Object(o)) if o.is_empty() => filter,
        Some(c) => json!({"operator": "AND", "conditions": [c, filter]}),
    }
}

fn is_true(v: Option<&Value>) -> bool {
    match v {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s.eq_ignore_ascii_case("true"),
        _ => false,
    }
}

/// `QueryUsers.conditionClientIds`: the client ids a condition names (not negated).
fn condition_client_ids(condition: &Value, into: &mut Vec<Id>) -> Result<(), CoreError> {
    let Some(o) = condition.as_object() else { return Ok(()) };
    if let Some(Value::Array(conditions)) = o.get("conditions") {
        if is_true(o.get("negate")) {
            return Ok(());
        }
        for c in conditions {
            condition_client_ids(c, into)?;
        }
        return Ok(());
    }
    let field = match o.get("field") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => crate::gson::number_to_java_string(n),
        Some(Value::Bool(b)) => b.to_string(),
        _ => return Ok(()),
    };
    if !field.replace('_', "").eq_ignore_ascii_case("clientId") || is_true(o.get("negate")) {
        return Ok(());
    }
    if !is_true(o.get("isValueField")) {
        add_ids(o.get("value"), into)?;
    }
    if !is_true(o.get("isToValueField")) {
        add_ids(o.get("toValue"), into)?;
    }
    add_ids(o.get("multiValue"), into)
}

fn add_ids(value: Option<&Value>, into: &mut Vec<Id>) -> Result<(), CoreError> {
    match value {
        None | Some(Value::Null) => Ok(()),
        Some(Value::Array(a)) => {
            for each in a {
                add_ids(Some(each), into)?;
            }
            Ok(())
        }
        Some(Value::String(s)) if s.contains(',') => {
            for part in s.split(',') {
                add_ids(Some(&Value::String(part.trim().to_string())), into)?;
            }
            Ok(())
        }
        Some(v) => {
            if let Some(id) = id_of("clientId", Some(v))? {
                if !into.contains(&id) {
                    into.push(id);
                }
            }
            Ok(())
        }
    }
}

#[async_trait]
impl CoreFunction for CallerSecurity {
    fn signature(&self) -> &FunctionSignature {
        &self.signature
    }

    async fn internal_execute(&self, args: &KMap<Value>) -> Result<FunctionOutput, CoreError> {
        let c = caller(self.name())?;
        let out = match self.act(args, &c).await {
            Ok(v) => v,
            Err(f) => return Err(self.report(args, &c, f)),
        };
        Ok(output_map([(self.op.output_name(), out)]))
    }
}
