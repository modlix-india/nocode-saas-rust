//! `CoreServices.Security`'s functions over security's internal endpoints
//! (`makeSecurityFunctions`): `IsBeingManagedByCode`, `IsBeingManagedById`, `GetClient`,
//! `GetUserAdminEmails`, `GetOwnersEmails`, `GetUserSubOrg`, `GetManagedClientIds`,
//! `GetUsersForDistribution`, `GetUsersByIds`, `GetClientsByIds`, `GetClientUsersPage` and
//! `GetClientsDenorm`.
//!
//! Security's answers are read into Java's DTOs (`Client`, `User`, `EntityProcessorUser`,
//! `ClientDenormData`) and written back with Gson, so what a function hands out is the DTO's
//! fields in declaration order, nulls dropped, primitives defaulted.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use async_trait::async_trait;
use kirun::function::Function;
use kirun::model::FunctionOutput;
use kirun::{Map as KMap, Value};
use serde_json::{json, Map};

use super::support::{
    bad_request, definition_context_authentication, empty_result, forbidden, has_user, id_of, ids_json, ids_of,
    is_related_client_code, is_related_client_or_false, output_map, require_context_key, required_argument, user_client_id, Java,
    JavaFunction,
};
use super::arg_string;
use crate::auth::Authentication;
use crate::authorities::has_authority;
use crate::clients::SecurityCalls;
use crate::error::CoreError;
use crate::security_calls::{id_value, Id};

const OWNER_ROLE: &str = "Authorities.ROLE_Owner";
const PARTNER_MANAGER_ROLE: &str = "Authorities.ROLE_Partner_Manager";

/// The security functions, in `makeSecurityFunctions`' order.
pub fn all(security: &Arc<SecurityCalls>) -> Vec<Arc<dyn Function>> {
    let s = || security.clone();
    vec![
        Java::function(IsBeingManagedByCode(s())),
        Java::function(IsBeingManagedById(s())),
        Java::function(GetClient(s())),
        Java::function(GetUserAdminEmails(s())),
        Java::function(GetOwnersEmails(s())),
        Java::function(GetUserSubOrg(s())),
        Java::function(GetManagedClientIds(s())),
        Java::function(GetUsersForDistribution(s())),
        Java::function(GetUsersByIds(s())),
        Java::function(GetClientsByIds(s())),
        Java::function(GetClientUsersPage(s())),
        Java::function(GetClientsDenorm(s())),
    ]
}

// --- DTOs as Jackson reads them and Gson writes them -------------------------------------

#[derive(Clone, Copy)]
enum Kind {
    BigInt,
    Str,
    Int,
    Bool,
    Map,
    One(Dto),
    List(Dto),
}

#[derive(Clone, Copy)]
enum Dto {
    Client,
    User,
    Profile,
    App,
}

impl Dto {
    /// The class's fields in declaration order, with the JSON property Jackson reads each from.
    fn fields(self) -> &'static [(&'static str, &'static str, Kind)] {
        use Kind::*;
        match self {
            Dto::Client => &[
                ("id", "id", BigInt),
                ("createdBy", "createdBy", BigInt),
                ("updatedBy", "updatedBy", BigInt),
                ("code", "code", Str),
                ("name", "name", Str),
                ("typeCode", "typeCode", Str),
                ("tokenValidityMinutes", "tokenValidityMinutes", Int),
                ("localeCode", "localeCode", Str),
                ("timeZone", "timeZone", Str),
                ("statusCode", "statusCode", Str),
                ("businessType", "businessType", Str),
                ("businessSize", "businessSize", Str),
                ("industry", "industry", Str),
                ("levelType", "levelType", Str),
                ("activeUsers", "activeUsers", Int),
                ("inactiveUsers", "inactiveUsers", Int),
                ("deletedUsers", "deletedUsers", Int),
                ("lockedUsers", "lockedUsers", Int),
                ("passwordExpiredUsers", "passwordExpiredUsers", Int),
                ("owners", "owners", List(Dto::User)),
                ("managagingClient", "managagingClient", One(Dto::Client)),
                ("apps", "apps", List(Dto::App)),
                ("createdByUser", "createdByUser", One(Dto::User)),
                ("clientManagers", "clientManagers", List(Dto::User)),
            ],
            Dto::User => &[
                ("id", "id", BigInt),
                ("clientId", "clientId", BigInt),
                ("userName", "userName", Str),
                ("emailId", "emailId", Str),
                ("phoneNumber", "phoneNumber", Str),
                ("firstName", "firstName", Str),
                ("lastName", "lastName", Str),
                ("middleName", "middleName", Str),
                ("localeCode", "localeCode", Str),
                ("timeZone", "timeZone", Str),
                ("statusCode", "statusCode", Str),
                ("profiles", "profiles", List(Dto::Profile)),
                ("client", "client", One(Dto::Client)),
                ("managingClient", "managingClient", One(Dto::Client)),
                ("createdByUser", "createdByUser", One(Dto::User)),
            ],
            Dto::Profile => &[
                ("id", "id", BigInt),
                ("appId", "appId", BigInt),
                ("clientId", "clientId", BigInt),
                ("name", "name", Str),
                ("title", "title", Str),
                ("description", "description", Str),
                ("defaultProfile", "defaultProfile", Bool),
                ("rootProfileId", "rootProfileId", BigInt),
                ("arrangement", "arrangement", Map),
            ],
            Dto::App => &[
                ("id", "id", BigInt),
                ("clientId", "clientId", BigInt),
                ("appName", "appName", Str),
                ("appCode", "appCode", Str),
                ("appType", "appType", Str),
                ("appAccessType", "appAccessType", Str),
                // Lombok's `isTemplate()` makes Jackson's property `template`; Gson writes the field.
                ("isTemplate", "template", Bool),
                ("clientCode", "clientCode", Str),
                ("explicitClientId", "explicitClientId", BigInt),
                ("explicitOwnerClientCode", "explicitOwnerClientCode", Str),
                ("status", "status", Str),
            ],
        }
    }
}

/// Gson drops nulls everywhere, maps included.
fn without_nulls(v: &Value) -> Value {
    match v {
        Value::Object(o) => Value::Object(o.iter().filter(|(_, v)| !v.is_null()).map(|(k, v)| (k.clone(), without_nulls(v))).collect()),
        Value::Array(a) => Value::Array(a.iter().map(without_nulls).collect()),
        other => other.clone(),
    }
}

/// Jackson coercing a scalar into a `String`.
fn jackson_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(crate::gson::number_to_java_string(n)),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn jackson_int(v: Option<&Value>) -> i64 {
    match v {
        Some(Value::Number(n)) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)).unwrap_or(0) as i32 as i64,
        Some(Value::String(s)) => s.trim().parse::<i32>().map(i64::from).unwrap_or(0),
        _ => 0,
    }
}

/// `gson.toJsonTree(dto)` of the DTO Jackson reads from `v`.
fn dto_json(v: &Value, dto: Dto) -> Value {
    let empty = Map::new();
    let o = v.as_object().unwrap_or(&empty);
    let mut out = Map::new();
    for (field, property, kind) in dto.fields() {
        let got = o.get(*property).filter(|x| !x.is_null());
        let written = match kind {
            Kind::BigInt => got.and_then(id_value).map(Value::from),
            Kind::Str => got.and_then(jackson_string).map(Value::String),
            Kind::Int => Some(Value::from(jackson_int(got))),
            Kind::Bool => Some(Value::Bool(matches!(got, Some(Value::Bool(true))) || got.and_then(Value::as_str) == Some("true"))),
            Kind::Map => got.filter(|x| x.is_object()).map(without_nulls),
            Kind::One(d) => got.filter(|x| x.is_object()).map(|x| dto_json(x, *d)),
            Kind::List(d) => got.and_then(Value::as_array).map(|a| {
                Value::Array(a.iter().filter(|x| !x.is_null()).map(|x| dto_json(x, *d)).collect())
            }),
        };
        if let Some(w) = written {
            out.insert(field.to_string(), w);
        }
    }
    Value::Object(out)
}

/// A field of security's JSON as the DTO holds it: an id.
fn id_field(v: &Value, name: &str) -> Option<Id> {
    v.get(name).and_then(id_value)
}

fn str_field(v: &Value, name: &str) -> Option<String> {
    v.get(name).and_then(jackson_string)
}

/// `GetUsersByIds.userJson`.
pub fn user_json(u: &Value) -> Value {
    let mut o = Map::new();
    o.insert("id".into(), id_field(u, "id").map(Value::from).unwrap_or(Value::Null));
    if let Some(c) = id_field(u, "clientId") {
        o.insert("clientId".into(), Value::from(c));
    }
    for f in ["userName", "emailId", "phoneNumber", "firstName", "middleName", "lastName", "localeCode", "timeZone", "statusCode"] {
        if let Some(s) = str_field(u, f) {
            o.insert(f.into(), Value::String(s));
        }
    }
    Value::Object(o)
}

/// `GetClientsByIds.clientJson`.
fn client_json(c: &Value) -> Value {
    let mut o = Map::new();
    o.insert("id".into(), id_field(c, "id").map(Value::from).unwrap_or(Value::Null));
    for f in ["code", "name", "typeCode", "levelType", "statusCode", "businessType", "businessSize", "industry", "localeCode", "timeZone"] {
        if let Some(s) = str_field(c, f) {
            o.insert(f.into(), Value::String(s));
        }
    }
    o.insert("tokenValidityMinutes".into(), Value::from(jackson_int(c.get("tokenValidityMinutes"))));
    for f in ["createdBy", "updatedBy"] {
        if let Some(id) = id_field(c, f) {
            o.insert(f.into(), Value::from(id));
        }
    }
    Value::Object(o)
}

fn string_arg(args: &KMap<Value>, name: &str) -> Result<String, CoreError> {
    arg_string(args, name)
}

// --- IsBeingManagedByCode / IsBeingManagedById / GetClient ------------------------------

pub struct IsBeingManagedByCode(Arc<SecurityCalls>);

#[async_trait]
impl JavaFunction for IsBeingManagedByCode {
    fn full_name(&self) -> &'static str {
        "CoreServices.Security.IsBeingManagedByCode"
    }

    async fn run(&self, args: &KMap<Value>) -> Result<FunctionOutput, CoreError> {
        let client = string_arg(args, "clientCode")?;
        let managing = string_arg(args, "managingClientCode")?;
        require_context_key()?;
        match self.0.does_client_manage_client_code(&managing, &client).await? {
            Some(b) => Ok(output_map([("result", Value::Bool(b))])),
            None => Err(empty_result(self.full_name())),
        }
    }
}

pub struct IsBeingManagedById(Arc<SecurityCalls>);

/// `getAsBigInteger()` of a validated LONG argument, as its decimal text.
fn big_integer_text(args: &KMap<Value>, name: &str) -> Result<String, CoreError> {
    match args.get(name) {
        Some(Value::Number(n)) if n.is_i64() || n.is_u64() => Ok(n.to_string()),
        Some(other) => Err(CoreError::unknown(format!("For input string: \"{}\"", crate::gson::element_to_string(other)))),
        None => Err(CoreError::unknown(format!("{name} is null"))),
    }
}

#[async_trait]
impl JavaFunction for IsBeingManagedById {
    fn full_name(&self) -> &'static str {
        "CoreServices.Security.IsBeingManagedById"
    }

    async fn run(&self, args: &KMap<Value>) -> Result<FunctionOutput, CoreError> {
        let client = big_integer_text(args, "clientId")?;
        let managing = big_integer_text(args, "managingClientId")?;
        require_context_key()?;
        match self.0.does_client_manage_client_text(&managing, &client).await? {
            Some(b) => Ok(output_map([("result", Value::Bool(b))])),
            None => Err(empty_result(self.full_name())),
        }
    }
}

pub struct GetClient(Arc<SecurityCalls>);

#[async_trait]
impl JavaFunction for GetClient {
    fn full_name(&self) -> &'static str {
        "CoreServices.Security.GetClient"
    }

    async fn run(&self, args: &KMap<Value>) -> Result<FunctionOutput, CoreError> {
        let param = args.get("idOrCode").cloned().unwrap_or(Value::Null);
        if !matches!(param, Value::String(_) | Value::Number(_) | Value::Bool(_)) {
            return Err(CoreError::unknown(format!("Not a JSON Primitive: {param}")));
        }
        require_context_key()?;
        let client = match &param {
            Value::String(code) => self.0.client_by_code(code).await?,
            Value::Number(n) => {
                let id = n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)).unwrap_or(0);
                self.0.client_by_id_text(&id.to_string()).await?
            }
            // `getAsLong()` of a boolean.
            _ => return Err(CoreError::unknown(format!("For input string: \"{param}\""))),
        };
        match client {
            Some(c) => Ok(output_map([("client", dto_json(&c, Dto::Client))])),
            None => Err(empty_result(self.full_name())),
        }
    }
}

// --- GetUserAdminEmails / GetOwnersEmails --------------------------------------------------

pub struct GetUserAdminEmails(Arc<SecurityCalls>);

/// `(List<String>) result.getOrDefault("emails", List.of())` written with Gson.
fn emails_of(result: &Value) -> Value {
    match result.get("emails") {
        None => json!([]),
        Some(v) => without_nulls(v),
    }
}

#[async_trait]
impl JavaFunction for GetUserAdminEmails {
    fn full_name(&self) -> &'static str {
        "CoreServices.Security.GetUserAdminEmails"
    }

    async fn run(&self, args: &KMap<Value>) -> Result<FunctionOutput, CoreError> {
        let app = string_arg(args, "appCode")?;
        let client = string_arg(args, "clientCode")?;
        let result = self.0.user_admin_emails(&client, &app).await?.unwrap_or_else(|| json!({"emails": [], "addApp": false}));
        let add_app = match result.get("addApp") {
            None => false,
            Some(Value::Bool(b)) => *b,
            Some(Value::Null) => return Err(CoreError::unknown("Cannot invoke \"java.lang.Boolean.booleanValue()\" because \"addApp\" is null")),
            Some(other) => {
                return Err(CoreError::unknown(format!("class {} cannot be cast to class java.lang.Boolean", java_class(other))))
            }
        };
        Ok(output_map([("adminEmails", emails_of(&result)), ("addApp", Value::Bool(add_app))]))
    }
}

fn java_class(v: &Value) -> &'static str {
    match v {
        Value::String(_) => "java.lang.String",
        Value::Number(n) if n.is_f64() => "java.lang.Double",
        Value::Number(_) => "java.lang.Integer",
        Value::Array(_) => "java.util.ArrayList",
        Value::Object(_) => "java.util.LinkedHashMap",
        _ => "java.lang.Object",
    }
}

pub struct GetOwnersEmails(Arc<SecurityCalls>);

#[async_trait]
impl JavaFunction for GetOwnersEmails {
    fn full_name(&self) -> &'static str {
        "CoreServices.Security.GetOwnersEmails"
    }

    async fn run(&self, args: &KMap<Value>) -> Result<FunctionOutput, CoreError> {
        let app = string_arg(args, "appCode")?;
        let client = string_arg(args, "clientCode")?;
        let result = self.0.owner_emails(&client, &app).await?.unwrap_or_else(|| json!({"emails": []}));
        Ok(output_map([("ownerEmails", emails_of(&result))]))
    }
}

// --- GetUserSubOrg / GetManagedClientIds ----------------------------------------------------

pub struct GetUserSubOrg(Arc<SecurityCalls>);

#[async_trait]
impl JavaFunction for GetUserSubOrg {
    fn full_name(&self) -> &'static str {
        "CoreServices.Security.GetUserSubOrg"
    }

    async fn run(&self, args: &KMap<Value>) -> Result<FunctionOutput, CoreError> {
        let user_id = id_of("userId", args.get("userId"))?;
        let ca = definition_context_authentication("GetUserSubOrg")?;
        let ids = self.sub_org(&ca, user_id).await?;
        Ok(output_map([("userIds", ids_json(&ids))]))
    }
}

impl GetUserSubOrg {
    async fn sub_org(&self, ca: &Authentication, user_id: Option<Id>) -> Result<Vec<Id>, CoreError> {
        if !ca.is_authenticated() || !has_user(ca) {
            return Ok(Vec::new());
        }
        let me = ca.ca.user.id;
        let my_client = ca.ca.user.client_id;
        let app = ca.url_app_code();
        let Some(other) = user_id.filter(|u| *u != me) else {
            return Ok(self.0.user_sub_org(me, app, my_client).await?.unwrap_or_default());
        };
        let Some(user) = self.0.user_internal(other).await? else {
            return Err(bad_request("CORE.USER_NOT_FOUND", format!("No user found with id : {other}")).param("id", other));
        };
        let their_client = id_field(&user, "clientId");
        if !is_related_client_or_false(&self.0, Some(my_client), their_client, app).await {
            return Err(forbidden("CORE.USER_NOT_RELATED", format!("User {other} is not in a client related to the current user's")).param("user", other));
        }
        match their_client {
            Some(c) => Ok(self.0.user_sub_org(other, app, c).await?.unwrap_or_default()),
            None => Ok(Vec::new()),
        }
    }
}

pub struct GetManagedClientIds(Arc<SecurityCalls>);

#[async_trait]
impl JavaFunction for GetManagedClientIds {
    fn full_name(&self) -> &'static str {
        "CoreServices.Security.GetManagedClientIds"
    }

    async fn run(&self, args: &KMap<Value>) -> Result<FunctionOutput, CoreError> {
        let user_id = id_of("userId", args.get("userId"))?;
        let ca = definition_context_authentication("GetManagedClientIds")?;
        let ids = self.managed(&ca, user_id).await?;
        Ok(output_map([("clientIds", ids_json(&ids))]))
    }
}

impl GetManagedClientIds {
    async fn managed(&self, ca: &Authentication, user_id: Option<Id>) -> Result<Vec<Id>, CoreError> {
        if !ca.is_authenticated() || !has_user(ca) {
            return Ok(Vec::new());
        }
        let me = ca.ca.user.id;
        if user_id.is_some_and(|u| u != me) {
            return Err(forbidden(
                "CORE.OTHER_USER_REFUSED",
                "GetManagedClientIds answers only for the current user; security exposes no other user's roles",
            )
            .param("function", self.full_name()));
        }
        let client = ca.ca.user.client_id;
        let has = |a: &str| has_authority(Some(a), ca.authorities()).unwrap_or(false);
        if has(OWNER_ROLE) {
            return Ok(self.0.managing_client_ids(client).await?.unwrap_or_default());
        }
        if !has(PARTNER_MANAGER_ROLE) {
            return Ok(Vec::new());
        }
        let sub_org = self.0.user_sub_org(me, ca.url_app_code(), client).await?.unwrap_or_default();
        let mut managers: Vec<Id> = Vec::new();
        for id in sub_org.into_iter().chain(std::iter::once(me)) {
            if !managers.contains(&id) {
                managers.push(id);
            }
        }
        Ok(self.0.client_ids_of_managers(&managers).await?.unwrap_or_default())
    }
}

// --- GetUsersForDistribution ----------------------------------------------------------------

#[derive(Debug, Default, PartialEq)]
pub struct Distribution {
    users: Vec<i64>,
    roles: Vec<i64>,
    profiles: Vec<i64>,
    designations: Vec<i64>,
    departments: Vec<i64>,
}

fn longs(name: &str, v: Option<&Value>) -> Result<Vec<i64>, CoreError> {
    ids_of(name, v)?
        .into_iter()
        .map(|id| i64::try_from(id).map_err(|_| CoreError::unknown("BigInteger out of long range")))
        .collect()
}

impl Distribution {
    pub fn of(args: &KMap<Value>) -> Result<Self, CoreError> {
        Ok(Self {
            users: longs("userIds", args.get("userIds"))?,
            roles: longs("roleIds", args.get("roleIds"))?,
            profiles: longs("profileIds", args.get("profileIds"))?,
            designations: longs("designationIds", args.get("designationIds"))?,
            departments: longs("departmentIds", args.get("departmentIds"))?,
        })
    }

    fn is_empty(&self) -> bool {
        self.users.is_empty() && self.roles.is_empty() && self.profiles.is_empty() && self.designations.is_empty() && self.departments.is_empty()
    }

    fn matches(&self, user: &Value) -> bool {
        let long = |name: &str| user.get(name).and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok())));
        let Some(id) = long("id") else { return false };
        if self.users.contains(&id) {
            return true;
        }
        if long("roleId").is_some_and(|r| self.roles.contains(&r)) {
            return true;
        }
        if long("designationId").is_some_and(|d| self.designations.contains(&d)) {
            return true;
        }
        if long("departmentId").is_some_and(|d| self.departments.contains(&d)) {
            return true;
        }
        user.get("profileIds")
            .and_then(Value::as_array)
            .is_some_and(|p| p.iter().filter_map(Value::as_i64).any(|p| self.profiles.contains(&p)))
    }

    /// `pick`: the matching users' ids, ascending.
    pub fn pick(&self, users: &[Value]) -> Vec<Id> {
        if self.is_empty() || users.is_empty() {
            return Vec::new();
        }
        let picked: BTreeSet<i64> = users
            .iter()
            .filter(|u| self.matches(u))
            .filter_map(|u| u.get("id").and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))))
            .collect();
        picked.into_iter().map(|i| i as Id).collect()
    }
}

pub struct GetUsersForDistribution(Arc<SecurityCalls>);

#[async_trait]
impl JavaFunction for GetUsersForDistribution {
    fn full_name(&self) -> &'static str {
        "CoreServices.Security.GetUsersForDistribution"
    }

    async fn run(&self, args: &KMap<Value>) -> Result<FunctionOutput, CoreError> {
        let distribution = Distribution::of(args)?;
        let client_code = match args.get("clientCode") {
            None | Some(Value::Null) => None,
            Some(_) => Some(arg_string(args, "clientCode")?),
        };
        let ca = definition_context_authentication("GetUsersForDistribution")?;
        let target = self.target_client_code(&ca, client_code).await?;
        let users = if distribution.is_empty() {
            Vec::new()
        } else {
            self.0.users_for_entity_processor(target.as_deref(), ca.url_app_code()).await?.unwrap_or_default()
        };
        Ok(output_map([("userIds", ids_json(&distribution.pick(&users)))]))
    }
}

impl GetUsersForDistribution {
    async fn target_client_code(&self, ca: &Authentication, client_code: Option<String>) -> Result<Option<String>, CoreError> {
        let own = ca.client_code().map(str::to_string);
        let Some(cc) = client_code.filter(|c| !c.trim().is_empty() && Some(c.as_str()) != own.as_deref()) else {
            return Ok(own);
        };
        if is_related_client_code(&self.0, own.as_deref(), Some(&cc), ca.url_app_code()).await? {
            Ok(Some(cc))
        } else {
            Err(forbidden("CORE.CLIENT_NOT_RELATED", format!("Client {cc} is not related to the current user's client")).param("client", &cc))
        }
    }
}

// --- GetUsersByIds / GetClientsByIds / GetClientsDenorm ------------------------------------

pub struct GetUsersByIds(Arc<SecurityCalls>);

#[async_trait]
impl JavaFunction for GetUsersByIds {
    fn full_name(&self) -> &'static str {
        "CoreServices.Security.GetUsersByIds"
    }

    async fn run(&self, args: &KMap<Value>) -> Result<FunctionOutput, CoreError> {
        let ids = ids_of("ids", args.get("ids"))?;
        let ca = definition_context_authentication("GetUsersByIds")?;
        let users = if ids.is_empty() { Vec::new() } else { self.0.users_internal_batch(&ids).await?.unwrap_or_default() };
        let visible = self.visible(&ca, users).await;
        let mut map = Map::new();
        for u in visible.iter().filter(|u| id_field(u, "id").is_some()) {
            map.insert(id_field(u, "id").unwrap_or_default().to_string(), user_json(u));
        }
        Ok(output_map([("users", Value::Object(map))]))
    }
}

impl GetUsersByIds {
    async fn visible(&self, ca: &Authentication, users: Vec<Value>) -> Vec<Value> {
        if users.is_empty() {
            return users;
        }
        let caller = user_client_id(ca);
        let mut related: HashMap<Id, bool> = HashMap::new();
        for cid in users.iter().filter_map(|u| id_field(u, "clientId")) {
            if !related.contains_key(&cid) {
                let r = is_related_client_or_false(&self.0, caller, Some(cid), ca.url_app_code()).await;
                related.insert(cid, r);
            }
        }
        users
            .into_iter()
            .filter(|u| id_field(u, "clientId").is_some_and(|c| related.get(&c).copied().unwrap_or(false)))
            .collect()
    }
}

/// The ids of `ids` the caller may see, in order (`GetClientsByIds` / `GetClientsDenorm`).
async fn visible_client_ids(security: &SecurityCalls, ca: &Authentication, ids: &[Id]) -> Vec<Id> {
    if ids.is_empty() || !has_user(ca) {
        return Vec::new();
    }
    let caller = Some(ca.ca.user.client_id);
    let mut related: HashMap<Id, bool> = HashMap::new();
    for id in ids {
        let r = is_related_client_or_false(security, caller, Some(*id), ca.url_app_code()).await;
        related.insert(*id, r);
    }
    ids.iter().copied().filter(|id| related.get(id).copied().unwrap_or(false)).collect()
}

pub struct GetClientsByIds(Arc<SecurityCalls>);

/// `flag(e)`: a JSON primitive read with `getAsBoolean`.
fn flag(v: Option<&Value>) -> bool {
    match v {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s.eq_ignore_ascii_case("true"),
        _ => false,
    }
}

#[async_trait]
impl JavaFunction for GetClientsByIds {
    fn full_name(&self) -> &'static str {
        "CoreServices.Security.GetClientsByIds"
    }

    async fn run(&self, args: &KMap<Value>) -> Result<FunctionOutput, CoreError> {
        let ids = ids_of("ids", args.get("ids"))?;
        let owners = flag(args.get("fetchOwners"));
        let managing = flag(args.get("fetchManagingClient"));
        let managers = flag(args.get("fetchClientManagers"));
        let counts = flag(args.get("withCounts"));
        let ca = definition_context_authentication("GetClientsByIds")?;
        let visible = visible_client_ids(&self.0, &ca, &ids).await;
        let clients = if visible.is_empty() {
            Vec::new()
        } else {
            let mut params = Vec::new();
            if owners {
                params.push(("fetchOwners", "true".to_string()));
            }
            if managing {
                params.push(("fetchManagingClient", "true".to_string()));
            }
            if managers {
                params.push(("fetchClientManagers", "true".to_string()));
            }
            self.0.clients_internal_batch(&visible, &params).await?.unwrap_or_default()
        };
        Ok(output_map([("clients", clients_json(&clients, &visible, owners, managing, managers, counts))]))
    }
}

fn users_json(list: Option<&Value>) -> Value {
    Value::Array(
        list.and_then(Value::as_array)
            .map(|a| a.iter().filter(|u| id_field(u, "id").is_some()).map(user_json).collect())
            .unwrap_or_default(),
    )
}

/// `GetClientsByIds.toJson`.
fn clients_json(clients: &[Value], visible: &[Id], owners: bool, managing: bool, managers: bool, counts: bool) -> Value {
    let mut map = Map::new();
    for c in clients {
        let Some(id) = id_field(c, "id").filter(|id| visible.contains(id)) else { continue };
        let mut o = client_json(c);
        let obj = o.as_object_mut().expect("object");
        if owners {
            obj.insert("owners".into(), users_json(c.get("owners")));
        }
        if managers {
            obj.insert("clientManagers".into(), users_json(c.get("clientManagers")));
        }
        if counts {
            let n = |f: &str| jackson_int(c.get(f));
            let names = ["activeUsers", "inactiveUsers", "deletedUsers", "lockedUsers", "passwordExpiredUsers"];
            for f in names {
                obj.insert(f.into(), Value::from(n(f)));
            }
            let total: i64 = names.iter().map(|f| n(f)).sum();
            obj.insert("totalUsers".into(), Value::from(total as i32 as i64));
        }
        if managing {
            if let Some(m) = c.get("managagingClient").filter(|m| id_field(m, "id").is_some()) {
                obj.insert("managingClient".into(), client_json(m));
            }
        }
        map.insert(id.to_string(), o);
    }
    Value::Object(map)
}

pub struct GetClientsDenorm(Arc<SecurityCalls>);

#[async_trait]
impl JavaFunction for GetClientsDenorm {
    fn full_name(&self) -> &'static str {
        "CoreServices.Security.GetClientsDenorm"
    }

    async fn run(&self, args: &KMap<Value>) -> Result<FunctionOutput, CoreError> {
        let ids = ids_of("ids", args.get("ids"))?;
        let ca = definition_context_authentication("GetClientsDenorm")?;
        let visible = visible_client_ids(&self.0, &ca, &ids).await;
        let data = if visible.is_empty() { None } else { self.0.clients_denorm_full(&visible).await? };
        let mut map = Map::new();
        if let Some(data) = data {
            // Jackson keys the map by `BigInteger`: "07" and "7" are the same client.
            let by_id: HashMap<Id, &Value> = data.iter().filter_map(|(k, v)| k.trim().parse::<Id>().ok().map(|id| (id, v))).collect();
            for id in &visible {
                let Some(d) = by_id.get(id).filter(|d| !d.is_null()) else { continue };
                let mut o = Map::new();
                o.insert("clientId".into(), Value::from(*id));
                if let Some(s) = str_field(d, "clientName") {
                    o.insert("clientName".into(), Value::String(s));
                }
                if let Some(s) = str_field(d, "statusCode") {
                    o.insert("statusCode".into(), Value::String(s));
                }
                o.insert("activeUsers".into(), Value::from(jackson_int(d.get("activeUsers"))));
                for f in ["userNames", "userPhones", "clientManagerIds"] {
                    if let Some(s) = str_field(d, f) {
                        o.insert(f.into(), Value::String(s));
                    }
                }
                map.insert(id.to_string(), Value::Object(o));
            }
        }
        Ok(output_map([("denorm", Value::Object(map))]))
    }
}

// --- GetClientUsersPage ------------------------------------------------------------------------

pub struct GetClientUsersPage(Arc<SecurityCalls>);

#[derive(Debug, PartialEq)]
enum ConditionShape {
    Empty,
    NonEmpty,
}

/// `AbstractConditionDeserializer` on the given condition: which class it reads as, and
/// whether that is empty. A bad condition at the top is "Invalid condition"; one nested in a
/// complex condition fails the conversion as a whole.
fn condition_shape(v: &Value, top: bool) -> Result<Option<ConditionShape>, CoreError> {
    let Some(o) = v.as_object() else {
        return if v.is_null() { Ok(None) } else { Err(invalid_condition(top)) };
    };
    if o.is_empty() {
        return Ok(None);
    }
    if o.get("havingConditions").is_some_and(Value::is_array) {
        return Ok(Some(ConditionShape::NonEmpty));
    }
    if let Some(Value::String(op)) = o.get("operator") {
        if op == "AND" || op == "OR" {
            let conditions = match o.get("conditions") {
                None | Some(Value::Null) => Vec::new(),
                Some(Value::Array(a)) => a.clone(),
                Some(_) => return Err(CoreError::unknown("Cannot deserialize the conditions of a ComplexCondition")),
            };
            for c in &conditions {
                condition_shape(c, false)?;
            }
            return Ok(Some(if conditions.is_empty() { ConditionShape::Empty } else { ConditionShape::NonEmpty }));
        }
    }
    if o.get("aggregateFunction").is_some_and(Value::is_string) {
        return Ok(Some(ConditionShape::NonEmpty));
    }
    let has_field = matches!(o.get("field"), Some(Value::String(s)) if !s.trim().is_empty());
    let has_expr = match o.get("fieldExpr") {
        Some(Value::Object(m)) => !m.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        _ => false,
    };
    if !has_field && !has_expr {
        return Err(invalid_condition(top));
    }
    Ok(Some(ConditionShape::NonEmpty))
}

fn invalid_condition(top: bool) -> CoreError {
    if top {
        bad_request("CORE.CONDITION_INVALID", "Invalid condition")
    } else {
        CoreError::unknown("Invalid condition")
    }
}

fn int_of(v: Option<&Value>, default: i64) -> i64 {
    match v {
        Some(Value::Number(n)) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)).map(|i| i as i32 as i64).unwrap_or(default),
        Some(Value::String(s)) => s.trim().parse::<i32>().map(i64::from).unwrap_or(default),
        _ => default,
    }
}

fn order(property: &str, desc: bool) -> Value {
    json!({"direction": if desc { "DESC" } else { "ASC" }, "property": property, "ignoreCase": false, "nullHandling": "NATIVE"})
}

/// `GetClientUsersPage.sortOf`: `None` keeps `Query`'s default sort.
fn sort_of(v: Option<&Value>) -> Option<Value> {
    let arr: Vec<Value> = match v {
        None | Some(Value::Null) => return None,
        Some(Value::Array(a)) => a.clone(),
        Some(o @ Value::Object(_)) => vec![o.clone()],
        Some(_) => return None,
    };
    let orders: Vec<Value> = arr
        .iter()
        .filter_map(Value::as_object)
        .filter(|o| o.contains_key("property"))
        .map(|o| {
            let prop = o.get("property").and_then(jackson_string).unwrap_or_default();
            let desc = o.get("direction").and_then(jackson_string).is_some_and(|d| d.eq_ignore_ascii_case("desc"));
            order(&prop, desc)
        })
        .collect();
    Some(Value::Array(orders))
}

impl GetClientUsersPage {
    /// The `Query` as Jackson writes it for security.
    fn query(client_id: Id, args: &KMap<Value>) -> Result<(Value, i64, i64), CoreError> {
        let client_condition = json!({"field": "clientId", "operator": "EQUALS", "value": client_id, "negate": false});
        let given = match args.get("condition") {
            Some(c @ Value::Object(o)) if !o.is_empty() => condition_shape(c, true)?.filter(|s| *s == ConditionShape::NonEmpty).map(|_| c.clone()),
            _ => None,
        };
        let condition = match given {
            None => client_condition,
            Some(g) => json!({"operator": "AND", "conditions": [g, client_condition], "negate": false}),
        };
        let page = int_of(args.get("page"), 0).max(0);
        let size = int_of(args.get("size"), 10);
        let size = if size <= 0 { 10 } else { size };
        let sort = sort_of(args.get("sort")).unwrap_or_else(|| json!([order("updatedAt", true)]));
        let q = json!({
            "condition": condition, "subQueryConditions": null, "size": size, "page": page, "sort": sort,
            "count": true, "fields": null, "excludeFields": false, "eager": false, "eagerFields": null
        });
        Ok((q, page, size))
    }
}

#[async_trait]
impl JavaFunction for GetClientUsersPage {
    fn full_name(&self) -> &'static str {
        "CoreServices.Security.GetClientUsersPage"
    }

    async fn run(&self, args: &KMap<Value>) -> Result<FunctionOutput, CoreError> {
        let Some(client_id) = id_of("clientId", args.get("clientId"))? else {
            return Err(required_argument("clientId"));
        };
        let (query, page, size) = Self::query(client_id, args)?;
        let ca = definition_context_authentication("GetClientUsersPage")?;
        if !is_related_client_or_false(&self.0, user_client_id(&ca), Some(client_id), ca.url_app_code()).await {
            return Err(forbidden("CORE.CLIENT_NOT_RELATED", format!("Not allowed to list the users of client {client_id}")).param("client", client_id));
        }
        let Some(result) = self.0.read_user_page(&query).await? else {
            return Err(empty_result(self.full_name()));
        };
        let users = users_json(result.get("content"));
        let total = result.get("totalElements").and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64))).unwrap_or(0);
        let total_pages = (total as f64 / size as f64).ceil() as i64;
        Ok(output_map([
            ("users", users),
            ("totalElements", Value::from(total)),
            ("totalPages", Value::from(total_pages as i32 as i64)),
            ("number", Value::from(page)),
            ("size", Value::from(size)),
        ]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn args(v: Value) -> KMap<Value> {
        v.as_object().unwrap().clone().into_iter().collect()
    }

    #[test]
    fn helpers_read_values_as_jackson_and_gson_do() {
        assert_eq!(jackson_string(&json!(12)), Some("12".into()));
        assert_eq!(jackson_string(&json!(true)), Some("true".into()));
        assert_eq!(jackson_string(&json!([1])), None);
        assert_eq!(big_integer_text(&args(json!({"a": 5})), "a").unwrap(), "5");
        assert_eq!(big_integer_text(&args(json!({"a": 1.5})), "a").unwrap_err().to_string(), CoreError::unknown("For input string: \"1.5\"").to_string());
        assert!(big_integer_text(&args(json!({})), "a").unwrap_err().to_string().contains("a is null"));
        assert_eq!(emails_of(&json!({})), json!([]));
        assert_eq!(emails_of(&json!({"emails": ["a", null, {"b": null}]})), json!(["a", null, {}]));
        for (v, class) in [
            (json!("s"), "java.lang.String"),
            (json!(1.5), "java.lang.Double"),
            (json!(1), "java.lang.Integer"),
            (json!([]), "java.util.ArrayList"),
            (json!({}), "java.util.LinkedHashMap"),
            (Value::Null, "java.lang.Object"),
        ] {
            assert_eq!(java_class(&v), class);
        }
        assert!(flag(Some(&json!("TRUE"))) && flag(Some(&json!(true))) && !flag(Some(&json!(1))) && !flag(None));
        assert_eq!((int_of(Some(&json!(" 7 ")), 3), int_of(Some(&json!("x")), 3), int_of(Some(&json!([])), 3)), (7, 3, 3));
        assert_eq!(int_of(Some(&json!(4_294_967_297_i64)), 0), 1, "an int's low 32 bits");
    }

    #[test]
    fn conditions_read_as_the_deserializer_reads_them() {
        let shape = |v: Value| condition_shape(&v, true).map(|s| s.map(|s| matches!(s, ConditionShape::NonEmpty)));
        assert_eq!(shape(Value::Null).unwrap(), None);
        assert_eq!(shape(json!({})).unwrap(), None);
        assert_eq!(shape(json!({"havingConditions": []})).unwrap(), Some(true));
        assert_eq!(shape(json!({"operator": "AND"})).unwrap(), Some(false));
        assert_eq!(shape(json!({"operator": "OR", "conditions": null})).unwrap(), Some(false));
        assert_eq!(shape(json!({"operator": "AND", "conditions": [{"field": "a"}]})).unwrap(), Some(true));
        assert!(shape(json!({"operator": "AND", "conditions": {"field": "a"}})).is_err());
        assert_eq!(shape(json!({"operator": "AND", "conditions": [{}]})).unwrap(), Some(true));
        assert_eq!(shape(json!({"aggregateFunction": "COUNT"})).unwrap(), Some(true));
        assert_eq!(shape(json!({"fieldExpr": {"a": 1}})).unwrap(), Some(true));
        assert_eq!(shape(json!({"fieldExpr": [1]})).unwrap(), Some(true));
        // Bad at the top is a 400; nested in a complex condition, an unknown 500.
        assert_eq!(shape(json!({"field": " "})).unwrap_err().status(), axum::http::StatusCode::BAD_REQUEST);
        assert_eq!(shape(json!(5)).unwrap_err().status(), axum::http::StatusCode::BAD_REQUEST);
        let nested = shape(json!({"operator": "OR", "conditions": [{"fieldExpr": {}}]})).unwrap_err();
        assert_eq!(nested.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    }
}
