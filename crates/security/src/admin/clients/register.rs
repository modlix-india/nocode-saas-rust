//! `ClientRegistrationService`'s sign-up: a new client with its owner, signed in at the end.
//!
//! | Route | Who |
//! |---|---|
//! | `POST clients/register` | anyone: the client, its owner, their access and registration objects, a session |
//! | `POST clients/register/otp/verify` | anonymous only: the checks `register` runs first, and the OTP |
//! | `POST clients/socialRegister` | anyone: `register` for a verified social sign-up state |
//! | `GET clients/register/events` | anyone: `CLIENT_REGISTERED` / `USER_REGISTERED` again for a user |
//! | `POST clients/appRegister` | signed in: an existing client registered on one more app |
//!
//! Java's order of writes is kept, without a transaction: a registration that fails half way
//! leaves what it wrote (a client without its owner, say), as Java's does. The files service's
//! `internal/accesspath` goes through [`Files`]; tests point it at an in-process fake.

use std::collections::HashSet;
use std::sync::OnceLock;

use async_trait::async_trait;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use rand::Rng;
use serde_json::{json, Value};
use sqlx::Row as _;

use super::client_admin::{self, CLIENT};
use super::common::{blank, ca_has, err, object_body, prop, prop_bool, prop_str, prop_u64, reg_error, Kind};
use super::common::{FIELDS_MISSING, NO_REGISTRATION_AVAILABLE, OBJECT_NOT_FOUND, SESSION_EXPIRED, SUBDOMAIN_ALREADY_EXISTS};
use super::common::{SUBDOMAIN_SUFFIX_FORBIDDEN, USER_ALREADY_EXISTS, USER_PASSWORD_INVALID};
use super::entity::{self, Row};
use super::policies::{self, PolicyType};
use super::registration::{app_prop, consume_state, first_forwarded_host, state_expired, verify_state};
use crate::admin::users::passwords::SecretType;
use crate::admin::AdminState;
use crate::dto::{user_json, UserExtras};
use crate::errors::{AuthError, AuthResult};
use crate::events::EventMessage;
use crate::jackson::{json as json_resp, Obj};
use crate::model::{Client, ContextAuth, User};
use crate::request::RequestInfo;
use crate::signin::{AuthRequest, Minted};
use crate::web::{self, req_str, to_u64, In};
use crate::web_route;

/// `ClientRegistrationService.VALIDITY_MINUTES`: a registered client's token validity.
const VALIDITY_MINUTES: i64 = 30;
/// `DEFAULT_TIME_ZONE`: the column default, for a browser that sent none (or an unreadable one).
const DEFAULT_TIME_ZONE: &str = "Asia/Kolkata";
/// `AppRegistrationServiceV2.DEFAULT_BUSINESS_TYPE`.
const DEFAULT_BUSINESS_TYPE: &str = "COMMON";
/// `ClientDAO.CLIENT_CODE_PREFIX_LENGTH`.
const CLIENT_CODE_PREFIX_LENGTH: usize = 5;

const REG_TYPE: &str = "REGISTRATION_TYPE";
const REG_TYPE_NO_VERIFICATION: &str = "REGISTRATION_TYPE_NO_VERIFICATION";
const REG_TYPE_NO_REGISTRATION: &str = "REGISTRATION_TYPE_NO_REGISTRATION";
const URL_SUFFIX: &str = "URL_SUFFIX";

const PASS_TYPES: &[&str] = &["PASSWORD", "PIN", "OTP"];
const BODY_TYPE: &str = "com.fincity.security.model.ClientRegistrationRequest";

// ---- the request ----

/// `ClientRegistrationRequest` as Jackson reads it (unknown properties ignored).
#[derive(Debug, Clone, Default)]
pub struct RegRequest {
    pub client_name: Option<String>,
    pub locale_code: Option<String>,
    pub time_zone: Option<String>,
    pub user_id: Option<u64>,
    pub user_name: Option<String>,
    pub email_id: Option<String>,
    pub phone_number: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub middle_name: Option<String>,
    pub pass_type: Option<SecretType>,
    pub password: Option<String>,
    pub pin: Option<String>,
    pub otp: Option<String>,
    pub business_client: bool,
    pub business_type: Option<String>,
    pub business_size: Option<String>,
    pub industry: Option<String>,
    pub sub_domain: Option<String>,
    pub sub_domain_suffix: Option<String>,
    pub social_register_state: Option<String>,
    pub plan_id: Option<u64>,
    pub cycle_id: Option<u64>,
    pub manager_id: Option<u64>,
}

fn secret_type(name: &str) -> Option<SecretType> {
    match name {
        "PASSWORD" => Some(SecretType::Password),
        "PIN" => Some(SecretType::Pin),
        "OTP" => Some(SecretType::Otp),
        _ => None,
    }
}

fn non_blank(v: &Option<String>) -> Option<&str> {
    v.as_deref().filter(|s| !s.trim().is_empty())
}

impl RegRequest {
    pub fn read(b: &Value) -> AuthResult<Self> {
        let pass_type = prop(b, "passType", Kind::Enum(PASS_TYPES))?;
        Ok(Self {
            client_name: prop_str(b, "clientName")?,
            locale_code: prop_str(b, "localeCode")?,
            time_zone: prop_str(b, "timeZone")?,
            user_id: prop_u64(b, "userId")?,
            user_name: prop_str(b, "userName")?,
            email_id: prop_str(b, "emailId")?,
            phone_number: prop_str(b, "phoneNumber")?,
            first_name: prop_str(b, "firstName")?,
            last_name: prop_str(b, "lastName")?,
            middle_name: prop_str(b, "middleName")?,
            pass_type: pass_type.as_str().and_then(secret_type),
            password: prop_str(b, "password")?,
            pin: prop_str(b, "pin")?,
            otp: prop_str(b, "otp")?,
            business_client: prop_bool(b, "businessClient")?,
            business_type: prop_str(b, "businessType")?,
            business_size: prop_str(b, "businessSize")?,
            industry: prop_str(b, "industry")?,
            sub_domain: prop_str(b, "subDomain")?,
            sub_domain_suffix: prop_str(b, "subDomainSuffix")?,
            social_register_state: prop_str(b, "socialRegisterState")?,
            plan_id: prop_u64(b, "planId")?,
            cycle_id: prop_u64(b, "cycleId")?,
            manager_id: prop_u64(b, "managerId")?,
        })
    }

    /// `BasePassword.getInputPassType()`: the type given, else the first secret given.
    pub fn input_pass_type(&self) -> Option<SecretType> {
        if self.pass_type.is_some() {
            return self.pass_type;
        }
        if non_blank(&self.password).is_some() {
            Some(SecretType::Password)
        } else if non_blank(&self.pin).is_some() {
            Some(SecretType::Pin)
        } else if non_blank(&self.otp).is_some() {
            Some(SecretType::Otp)
        } else {
            None
        }
    }

    /// `BasePassword.getInputPass()`: the secret of the type given, else the first one given.
    pub fn input_pass(&self) -> Option<String> {
        match self.pass_type {
            Some(SecretType::Password) => self.password.clone(),
            Some(SecretType::Pin) => self.pin.clone(),
            Some(SecretType::Otp) => self.otp.clone(),
            None => non_blank(&self.password).or(non_blank(&self.pin)).or(non_blank(&self.otp)).map(str::to_string),
        }
    }

    /// `getIdentifier()`: the e-mail, else the phone number.
    pub fn identifier(&self) -> Option<&str> {
        non_blank(&self.email_id).or(non_blank(&self.phone_number))
    }

    /// `getValidClientName`: the client's name, else first and last names run together, else the
    /// e-mail, else the user name.
    pub fn valid_client_name(&self) -> Option<String> {
        if let Some(n) = non_blank(&self.client_name) {
            return Some(n.to_string());
        }
        if non_blank(&self.first_name).is_some() || non_blank(&self.last_name).is_some() {
            return Some(format!("{}{}", self.first_name.as_deref().unwrap_or(""), self.last_name.as_deref().unwrap_or("")));
        }
        non_blank(&self.email_id).or(non_blank(&self.user_name)).map(str::to_string)
    }
}

/// `@RequestBody ClientRegistrationRequest` as WebFlux's argument resolver reads it: a type
/// Jackson does not read is 415 (no `Content-Type` is `application/octet-stream`), except that
/// a `POST` with no type and no body is the missing body's 400; then the body's own 400s.
pub fn request_body(r: &In, post: bool) -> AuthResult<RegRequest> {
    let ct = r.info.header("content-type").map(|c| c.split(';').map(str::trim).collect::<Vec<_>>().join(";"));
    let essence = ct.as_deref().map(|c| c.split(';').next().unwrap_or("").to_ascii_lowercase());
    let json = matches!(essence.as_deref(), Some(e) if e == "application/json" || e.ends_with("+json") || e == "application/x-ndjson");
    if !json {
        if ct.is_none() && post && r.body.is_empty() {
            return Err(web::no_body());
        }
        let shown = ct.unwrap_or_else(|| "application/octet-stream".into());
        return Err(AuthError::Unknown {
            status: StatusCode::UNSUPPORTED_MEDIA_TYPE,
            cause: format!("415 UNSUPPORTED_MEDIA_TYPE \"Content type '{shown}' not supported for bodyType={BODY_TYPE}\""),
        });
    }
    RegRequest::read(&object_body(&r.body)?)
}

// ---- pure rules ----

/// `checkUsageType(usageType, levelType, isBusinessClient)`.
pub fn check_usage_type(usage: Option<&str>, level: &str, business: bool) -> AuthResult<()> {
    let owner = level == "OWNER";
    let owner_or_client = owner || level == "CLIENT";
    let refuse = |why: &str| Err(reg_error(why));
    match usage {
        Some("S") => return refuse("Not allowed for Standalone Applications"),
        Some("B") => return refuse("Not allowed for Business Applications"),
        Some("B2C") => {
            if !owner {
                return refuse("Only Applications owner can register for B2C Applications");
            }
            if business {
                return refuse("Business clients are not allowed for B2C Applications");
            }
        }
        Some("B2B") => {
            if !owner {
                return refuse("Only Applications owner can register for B2B Applications");
            }
            if !business {
                return refuse("Individual clients are not allowed for B2B Applications");
            }
        }
        Some("B2X") if !owner => return refuse("Only Applications owner can register for B2X Applications"),
        Some("B2B2B") => {
            if !owner_or_client {
                return refuse("Only Applications owner can register for B2B2B Applications");
            }
            if !business {
                return refuse("Individual clients are not allowed for B2B2B Applications");
            }
        }
        Some("B2B2C") => {
            if !owner_or_client {
                return refuse("Only Applications owner can register for B2B2C Applications");
            }
            if owner && !business {
                return refuse("Business clients are required for B2B2C Applications at owner level");
            }
            if level == "CLIENT" && business {
                return refuse("Business clients are not allowed for B2B2C Applications");
            }
        }
        Some("B2B2X") => {
            if !owner_or_client {
                return refuse("Only Applications owner can register for B2B2X Applications");
            }
            if owner && !business {
                return refuse("Business clients are required for B2B2X Applications at owner level");
            }
        }
        Some("B2X2C") => {
            if !owner_or_client {
                return refuse("Only Applications owner can register for B2X2C Applications");
            }
            if level == "CLIENT" && business {
                return refuse("Business clients are not allowed for B2X2C Applications");
            }
        }
        Some("B2X2X") if !owner_or_client => return refuse("Only Applications owner can register for B2X2X Applications"),
        _ => {}
    }
    Ok(())
}

/// The prefix `ClientDAO.getValidClientCode` numbers: the name's letters (`Character.isLetter`),
/// the first five, upper-cased.
pub fn client_code_prefix(name: &str) -> String {
    if name.trim().is_empty() {
        return name.chars().take(CLIENT_CODE_PREFIX_LENGTH).collect::<String>().to_uppercase();
    }
    let letters: String = name.chars().filter(|c| c.is_alphabetic() && (*c as u32) <= 0xFFFF).collect();
    letters.chars().take(CLIENT_CODE_PREFIX_LENGTH).collect::<String>().to_uppercase()
}

const NUMBERS: &str = "0123456789";
const UPPERCASE: &str = "BCDFGHJKLMNPQRSTVWXZ";
const LOWERCASE: &str = "bcdfghjklmnpqrstvwxz";
const SPECIAL_CHARS: &str = "!@#$";

/// `CodeUtil.generate(config)`: `length` characters, each from a set picked at random.
pub fn generate_code(length: i64, numeric: bool, upper: bool, lower: bool, special: bool) -> AuthResult<String> {
    let sets: Vec<&str> = [(numeric, NUMBERS), (upper, UPPERCASE), (lower, LOWERCASE), (special, SPECIAL_CHARS)]
        .into_iter()
        .filter(|(on, _)| *on)
        .map(|(_, s)| s)
        .collect();
    if length <= 0 {
        // `while (sb.length() != length)`: a negative length never ends in Java; nothing to make.
        return Ok(String::new());
    }
    if sets.is_empty() {
        return Err(AuthError::internal("Index 0 out of bounds for length 0"));
    }
    let mut rng = rand::thread_rng();
    Ok((0..length)
        .map(|_| {
            let set = sets[if sets.len() > 1 { rng.gen_range(0..sets.len()) } else { 0 }].as_bytes();
            set[rng.gen_range(0..set.len())] as char
        })
        .collect())
}

/// `AbstractPolicy.generate()` of the password and PIN policies.
pub fn generate_secret(t: PolicyType, policy: &Row) -> AuthResult<String> {
    let flag = |k: &str| policy.get(k).and_then(Value::as_bool).unwrap_or(false);
    let int = |k: &str, what: &str| {
        policy.get(k).and_then(Value::as_i64).ok_or_else(|| AuthError::internal(format!("Cannot invoke \"{what}.intValue()\" because \"this.{k}\" is null")))
    };
    match t {
        PolicyType::Password => generate_code(
            int("passMinLength", "java.lang.Short")?,
            flag("atleastOneDigit"),
            flag("atleastOneUppercase"),
            flag("atleastOneLowercase"),
            flag("atleastOneSpecialChar"),
        ),
        PolicyType::Pin => generate_code(int("length", "java.lang.Short")?, true, false, false, false),
        PolicyType::Otp => Err(AuthError::internal("OTP is not a registration secret")),
    }
}

fn policy_type(t: SecretType) -> PolicyType {
    match t {
        SecretType::Password => PolicyType::Password,
        SecretType::Pin => PolicyType::Pin,
        SecretType::Otp => PolicyType::Otp,
    }
}

/// `checkUrl`-less `getUrlPrefix`'s address of the request: `https://host` behind TLS, else
/// `http://host:port` (Java's `null`s included).
pub fn request_url_prefix(info: &RequestInfo) -> String {
    let host = first_forwarded_host(info);
    let scheme = info.header("X-Forwarded-Proto");
    let port = info.header("X-Forwarded-Port").unwrap_or_else(|| "null".into());
    if scheme.as_deref().is_some_and(|s| s.contains("https")) {
        format!("https://{host}")
    } else {
        format!("http://{host}:{port}")
    }
}

// ---- the files service ----

/// `IFeignFilesService.FilesAccessPath`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessPath {
    pub client_code: String,
    pub access_name: Option<String>,
    pub write_access: bool,
    pub path: Option<String>,
    pub allow_sub_path_access: bool,
    pub resource_type: Option<String>,
}

impl AccessPath {
    pub fn to_json(&self) -> Value {
        json!({
            "clientCode": self.client_code,
            "accessName": self.access_name,
            "writeAccess": self.write_access,
            "path": self.path,
            "allowSubPathAccess": self.allow_sub_path_access,
            "resourceType": self.resource_type,
        })
    }
}

/// `IFeignFilesService.createInternalAccessPath`: `POST /api/files/internal/accesspath`.
#[async_trait]
pub trait Files: Send + Sync {
    async fn create_access_path(&self, path: &AccessPath) -> AuthResult<()>;
}

/// The files service at `Admin.files`.
pub struct FilesUpstream<'a>(pub Option<&'a platform::upstream::Upstream>);

fn http() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| reqwest::Client::builder().timeout(std::time::Duration::from_secs(30)).build().unwrap_or_else(|_| reqwest::Client::new()))
}

#[async_trait]
impl Files for FilesUpstream<'_> {
    async fn create_access_path(&self, path: &AccessPath) -> AuthResult<()> {
        let Some(files) = self.0 else {
            return Err(AuthError::internal("files upstream is not configured ([files] upstream)"));
        };
        let url = format!("{}/api/files/internal/accesspath", files.base().await.map_err(AuthError::internal)?);
        let resp = http().post(&url).json(&path.to_json()).send().await.map_err(AuthError::internal)?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            // Feign's `FeignException` message.
            return Err(AuthError::internal(format!("[{}] during [POST] to [{url}] [IFeignFilesService#createInternalAccessPath(FilesAccessPath)]: [{text}]", status.as_u16())));
        }
        Ok(())
    }
}

// ---- the registration objects ----

/// A registration lookup's key (`AppRegistrationV2DAO.get*ForRegistration`).
#[derive(Debug, Clone, Copy)]
struct RegKey<'a> {
    app_id: u64,
    app_client_id: u64,
    url_client_id: u64,
    client_type: &'a str,
    level: &'a str,
    business_type: Option<&'a str>,
}

impl<'a> RegKey<'a> {
    fn of(app_id: u64, app_client_id: u64, url_client_id: u64, client: &'a Client, level: &'a str) -> Self {
        Self { app_id, app_client_id, url_client_id, client_type: client.type_code.as_deref().unwrap_or(""), level, business_type: client.business_type.as_deref() }
    }

    /// The URL client's rows when it has any, else the app owner's (`map.getOrDefault(urlClientId,
    /// map.get(appClientId))`), in the database's order.
    async fn rows(&self, s: &AdminState, table: &str, cols: &str, extra: &str) -> AuthResult<Vec<sqlx::mysql::MySqlRow>> {
        let sql = format!(
            "SELECT CLIENT_ID, {cols} FROM {table} WHERE APP_ID = ? AND CLIENT_ID IN (?, ?) AND CLIENT_TYPE = ? AND LEVEL = ? AND BUSINESS_TYPE = ?{extra}"
        );
        let rows = sqlx::query(&sql)
            .bind(self.app_id)
            .bind(self.app_client_id)
            .bind(self.url_client_id)
            .bind(self.client_type)
            .bind(self.level)
            .bind(self.business_type.unwrap_or(DEFAULT_BUSINESS_TYPE))
            .fetch_all(&s.db.pool)
            .await?;
        let of = |r: &sqlx::mysql::MySqlRow| r.try_get::<u64, _>("CLIENT_ID").ok();
        let pick = if rows.iter().any(|r| of(r) == Some(self.url_client_id)) { self.url_client_id } else { self.app_client_id };
        Ok(rows.into_iter().filter(|r| of(r) == Some(pick)).collect())
    }
}

/// `getAppIdsForRegistration` / `...ForAdditionalRegistration`: the apps to grant, the
/// registering app first (added when the rows leave it out).
async fn reg_app_ids(s: &AdminState, k: RegKey<'_>, register_only: bool) -> AuthResult<Vec<(u64, bool)>> {
    let extra = if register_only { " AND REGISTER = 1" } else { "" };
    let rows = k.rows(s, "security_app_reg_access", "ALLOW_APP_ID, WRITE_ACCESS", extra).await?;
    let mut list: Vec<(u64, bool)> = rows
        .iter()
        .map(|r| Ok((r.try_get::<u64, _>("ALLOW_APP_ID")?, r.try_get::<i8, _>("WRITE_ACCESS")? == 1)))
        .collect::<AuthResult<_>>()?;
    if list.is_empty() {
        return Ok(vec![(k.app_id, false)]);
    }
    let found = match list.iter().position(|(a, _)| *a == k.app_id) {
        Some(i) => list.remove(i),
        None => (k.app_id, false),
    };
    list.insert(0, found);
    Ok(list)
}

/// `ClientService.addClientRegistrationObjects`: the app's profile restrictions for the new
/// client.
pub async fn add_client_registration_objects(s: &AdminState, app_id: u64, app_client_id: u64, url_client_id: u64, client: &Client) -> AuthResult<bool> {
    let level = s.client_level_type(client.id(), app_id).await?;
    let k = RegKey::of(app_id, app_client_id, url_client_id, client, level);
    let mut seen = HashSet::new();
    let mut ids = Vec::new();
    for r in k.rows(s, "security_app_reg_profile_restriction", "PROFILE_ID", "").await? {
        let id: u64 = r.try_get("PROFILE_ID")?;
        if seen.insert(id) {
            ids.push(id);
        }
    }
    if ids.is_empty() {
        return Ok(true);
    }
    for id in &ids {
        sqlx::query("INSERT INTO security_profile_client_restriction (CLIENT_ID, PROFILE_ID) VALUES (?, ?)").bind(client.id()).bind(id).execute(&s.db.pool).await?;
    }
    Ok(true)
}

/// `AppService.addClientAccessAfterRegistration`: `None` for an unknown app (Java's empty).
pub async fn add_client_access_after_registration(s: &AdminState, ca: &ContextAuth, app_code: Option<&str>, url_client_id: u64, client: &Client) -> AuthResult<Option<bool>> {
    let Some(app) = app_by_code(s, app_code).await? else { return Ok(None) };
    let level = s.client_level_type(client.id(), app.id).await?;
    for (app_id, write) in reg_app_ids(s, RegKey::of(app.id, app.client_id, url_client_id, client, level), false).await? {
        super::apps::grant_registration_access(s, ca, app_id, client.id(), write).await?;
    }
    Ok(Some(true))
}

/// `addFilesAccessPath(ca, client, appCode)`: the app's file access paths for the new client,
/// made in the files service. `None` for an unknown app.
pub async fn add_files_access_path(s: &AdminState, files: &dyn Files, ca: &ContextAuth, client: &Client, app_code: Option<&str>) -> AuthResult<Option<bool>> {
    let Some(app) = app_by_code(s, app_code).await? else { return Ok(None) };
    let level = s.client_level_type(client.id(), app.id).await?;
    let k = RegKey::of(app.id, app.client_id, ca.logged_in_from_client_id.unwrap_or(0), client, level);
    let rows = k.rows(s, "security_app_reg_file_access", "ACCESS_NAME, WRITE_ACCESS, PATH, ALLOW_SUB_PATH_ACCESS, RESOURCE_TYPE", "").await?;
    for r in rows {
        let path = AccessPath {
            client_code: client.code().to_string(),
            access_name: r.try_get("ACCESS_NAME")?,
            write_access: r.try_get::<i8, _>("WRITE_ACCESS")? == 1,
            path: r.try_get("PATH")?,
            allow_sub_path_access: r.try_get::<i8, _>("ALLOW_SUB_PATH_ACCESS")? == 1,
            resource_type: r.try_get("RESOURCE_TYPE")?,
        };
        files.create_access_path(&path).await?;
    }
    Ok(Some(true))
}

/// `autoAddRegObjectsFromOtherApps(client, user)`: the file paths and the user's registration
/// objects of every app this registration also registers on (the registering app included, so
/// its own are made a second time, as Java's are). `None` for an unknown app or URL client.
async fn auto_add_reg_objects_from_other_apps(s: &AdminState, files: &dyn Files, ca: &ContextAuth, client: &Client, user: &User) -> AuthResult<Option<bool>> {
    let Some(app) = app_by_code(s, ca.url_app_code.as_deref()).await? else { return Ok(None) };
    let level = s.client_level_type(client.id(), app.id).await?;
    let Some(url_client) = client_by_code(s, ca.url_client_code.as_deref()).await? else { return Ok(None) };
    let ids = reg_app_ids(s, RegKey::of(app.id, app.client_id, url_client.id(), client, level), true).await?;
    for (app_id, _) in &ids {
        let other = s.dir().app_by_id(*app_id).await?;
        add_files_access_path(s, files, ca, client, Some(&other.app_code)).await?;
    }
    let mut added = true;
    for (app_id, _) in &ids {
        let other = s.dir().app_by_id(*app_id).await?;
        added &= s.add_registration_objects(*app_id, other.client_id, url_client.id(), client, user.id).await?;
    }
    Ok(Some(added))
}

// ---- lookups ----

async fn app_by_code(s: &AdminState, code: Option<&str>) -> AuthResult<Option<std::sync::Arc<crate::model::App>>> {
    match code {
        Some(c) => s.dir().app_by_code(c).await,
        None => Ok(None),
    }
}

async fn client_by_code(s: &AdminState, code: Option<&str>) -> AuthResult<Option<std::sync::Arc<Client>>> {
    match code {
        Some(c) => s.client_by_code(c).await,
        None => Ok(None),
    }
}

/// `ClientDAO.getValidClientCode(name)`: the prefix, else the prefix numbered one past the
/// highest number already after it.
pub async fn valid_client_code(s: &AdminState, name: &str) -> AuthResult<String> {
    let prefix = client_code_prefix(name);
    let from = (prefix.encode_utf16().count() + 1) as i64;
    let row = sqlx::query(
        "SELECT COUNT(CASE WHEN CODE = ? THEN 1 END), MAX(CASE WHEN SUBSTRING(CODE, ?) REGEXP '^[0-9]+$' THEN CAST(SUBSTRING(CODE, ?) AS SIGNED) END) \
         FROM security_client WHERE CODE LIKE CONCAT(?, '%')",
    )
    .bind(&prefix)
    .bind(from)
    .bind(from)
    .bind(&prefix)
    .fetch_one(&s.db.pool)
    .await?;
    let bare: i64 = row.try_get(0)?;
    if bare == 0 {
        return Ok(prefix);
    }
    let highest: Option<i64> = row.try_get(1)?;
    Ok(format!("{prefix}{}", highest.map_or(1, |h| h + 1)))
}

/// `checkSubDomainAvailability(subDomain, suffix, isBusinessClient)`: the full host a business
/// client asks for, `""` when it asks for none.
async fn check_subdomain(s: &AdminState, r: &RegRequest) -> AuthResult<String> {
    let Some(sub) = non_blank(&r.sub_domain).filter(|_| r.business_client) else { return Ok(String::new()) };
    let endings = &s.dir().subdomain_endings;
    let suffix = match non_blank(&r.sub_domain_suffix) {
        None => endings.first().cloned().ok_or_else(|| AuthError::internal("Index 0 out of bounds for length 0"))?,
        Some(x) if endings.iter().any(|e| e == x) => x.to_string(),
        Some(x) => return Err(err(StatusCode::FORBIDDEN, SUBDOMAIN_SUFFIX_FORBIDDEN, &[x])),
    };
    let full = format!("{sub}{}{suffix}", if suffix.starts_with('.') { "" } else { "." });
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM security_client_url WHERE URL_PATTERN = ? LIMIT 1").bind(&full).fetch_one(&s.db.pool).await?;
    let free = n == 0 && s.dir().app_by_code(sub).await?.is_none();
    if !free {
        return Err(err(StatusCode::CONFLICT, SUBDOMAIN_ALREADY_EXISTS, &[sub]));
    }
    Ok(full)
}

/// `checkDuplicateIdentity`: an individual already standing on its own, or an owner of a
/// business already holding the identity, is 409 (as is an unknown URL client).
async fn check_duplicate_identity(s: &AdminState, ca: &ContextAuth, r: &RegRequest) -> AuthResult<()> {
    let url_client = ca.url_client_code.as_deref().unwrap_or("");
    let (un, em, ph) = (r.user_name.as_deref(), r.email_id.as_deref(), r.phone_number.as_deref());
    let standing = if r.business_client {
        Some(s.check_business_client_owner_exists(url_client, un, em, ph).await?)
    } else {
        s.check_individual_client_user(url_client, un, em, ph).await?
    };
    let refused = || err(StatusCode::CONFLICT, USER_ALREADY_EXISTS, &[r.identifier().unwrap_or("null")]);
    if standing != Some(false) {
        return Err(refused());
    }
    if identity_taken_in_managing_business(s, ca, em, ph).await? {
        return Err(refused());
    }
    Ok(())
}

/// `identityTakenInManagingBusiness` (QA-0445, 2026-10-16): registering under a managing client
/// other than SYSTEM is refused when a user anywhere in that client's business (the top client
/// below SYSTEM, with every client it manages) already holds the email or phone.
async fn identity_taken_in_managing_business(s: &AdminState, ca: &ContextAuth, em: Option<&str>, ph: Option<&str>) -> AuthResult<bool> {
    let Some(managing) = ca.logged_in_from_client_id else { return Ok(false) };
    let root = s.dir().hierarchy(managing).await?.business_root_id();
    s.db.identity_exists_in_client_family(root, em, ph).await
}

/// `preRegisterCheck`: the secret against the policy, the identity, the app's usage type and
/// the subdomain. `None` where Java's chain completes empty (an unknown app or client).
async fn pre_register_check(s: &AdminState, ca: &ContextAuth, r: &mut RegRequest, app_id: u64) -> AuthResult<Option<String>> {
    if r.business_client && blank(r.business_type.as_deref()) {
        r.business_type = Some(DEFAULT_BUSINESS_TYPE.into());
    }
    let lif = ca.logged_in_from_client_id.unwrap_or(0);
    if let (Some(pass), Some(t)) = (r.input_pass().filter(|p| !p.trim().is_empty()), r.pass_type) {
        s.check_policy_for(lif, app_id, t, &pass).await?;
    }
    check_duplicate_identity(s, ca, r).await?;
    let Some(app) = app_by_code(s, ca.url_app_code.as_deref()).await? else { return Ok(None) };
    if client_by_code(s, ca.logged_in_from_client_code.as_deref()).await?.is_none() {
        return Ok(None);
    }
    let level = s.client_level_type(lif, app.id).await?;
    check_usage_type(app.app_usage_type.as_deref(), level, r.business_client)?;
    // Read and not used, as in Java.
    app_prop(s, ca, lif, Some(app.id), None, URL_SUFFIX).await?;
    Ok(Some(check_subdomain(s, r).await?))
}

/// `verifyClient`: no OTP needed when the app does not verify or the caller may create clients.
async fn verify_client(s: &AdminState, ca: &ContextAuth, reg_prop: &str, r: &RegRequest) -> AuthResult<()> {
    if reg_prop == REG_TYPE_NO_VERIFICATION || ca_has(ca, "Authorities.Client_CREATE") {
        return Ok(());
    }
    let refused = || err(StatusCode::BAD_REQUEST, USER_PASSWORD_INVALID, &["OTP", "OTP"]);
    let Some(app) = app_by_code(s, ca.url_app_code.as_deref().filter(|a| !a.trim().is_empty())).await? else { return Err(refused()) };
    let ok = s
        .auth
        .verify_target_otp(app.id, r.email_id.as_deref(), r.phone_number.as_deref(), Some(crate::otp::OtpPurpose::Registration), r.otp.as_deref())
        .await?;
    if ok {
        Ok(())
    } else {
        Err(refused())
    }
}

fn no_registration() -> AuthError {
    err(StatusCode::BAD_REQUEST, NO_REGISTRATION_AVAILABLE, &[])
}

fn reg_prop_refuses(reg_prop: &str) -> bool {
    reg_prop.trim().is_empty() || reg_prop == REG_TYPE_NO_REGISTRATION
}

/// `ClientService.createForRegistration(client, parentId)`: the client one level below its
/// parent, logged as any create is. `None` for an unknown parent.
async fn create_client(s: &AdminState, ca: &ContextAuth, mut row: Row, parent_id: u64) -> AuthResult<Option<Row>> {
    let Some(parent) = s.dir().client(parent_id).await? else { return Ok(None) };
    row.insert("levelType".into(), client_admin::child_level(parent.level_type.as_deref()).map(Value::from).unwrap_or(Value::Null));
    row.insert("createdBy".into(), Value::from(ca.user.id()));
    let id = entity::insert(&s.db, &CLIENT, &row).await?;
    let created = entity::read_by_id(&s.db, &CLIENT, id).await?;
    crate::data::audit::entity_changed(&s.db, None, crate::data::audit::object::CLIENT, crate::data::audit::action::CREATE, id, Some(id), "Client", client_admin::describe(&created).as_deref());
    Ok(Some(created))
}

/// `registerClient`: the client, its hierarchy, its manager, its registration objects and app
/// access. `None` where Java's chain completes empty.
async fn register_client(s: &AdminState, ca: &ContextAuth, r: &RegRequest, reg_prop: &str) -> AuthResult<Option<Client>> {
    if reg_prop_refuses(reg_prop) {
        return Err(no_registration());
    }
    // Java's later "Client name cannot be blank" cannot happen: a valid name is never blank.
    let Some(name) = r.valid_client_name() else { return Err(err(StatusCode::BAD_REQUEST, FIELDS_MISSING, &[])) };
    let lif = ca.logged_in_from_client_id.unwrap_or(0);
    if non_blank(&r.social_register_state).is_none() {
        verify_client(s, ca, reg_prop, r).await?;
    }
    let Some(app) = app_by_code(s, ca.url_app_code.as_deref()).await? else { return Ok(None) };
    let mut row = client_admin::initial();
    let fields = json!({
        "name": name,
        "typeCode": if r.business_client { "BUS" } else { "INDV" },
        "localeCode": r.locale_code,
        "timeZone": crate::timezone::effective(r.time_zone.as_deref(), Some(DEFAULT_TIME_ZONE)),
        "tokenValidityMinutes": VALIDITY_MINUTES,
        "businessSize": r.business_size,
        "industry": r.industry,
        "statusCode": "ACTIVE",
    });
    row.extend(fields.as_object().cloned().unwrap_or_default());
    row.insert("code".into(), Value::from(valid_client_code(s, &name).await?));
    let Some(created) = create_client(s, ca, row, lif).await? else { return Ok(None) };
    let client = client_admin::to_client(&created);
    client_admin::create_hierarchy(s, lif, client.id()).await?;
    if ca.authenticated {
        let me = ca.user.id();
        if !ca_has(ca, "Authorities.ROLE_Owner") {
            client_admin::add_client_manager(s, client.id(), me, me).await?;
        } else if let Some(manager) = r.manager_id {
            client_admin::add_client_manager(s, client.id(), manager, me).await?;
        }
    }
    add_client_registration_objects(s, app.id, app.client_id, lif, &client).await?;
    if add_client_access_after_registration(s, ca, ca.url_app_code.as_deref(), lif, &client).await?.is_none() {
        return Ok(None);
    }
    Ok(Some(client))
}

/// `registerUser`: the owner, with the secret given or one the policy makes.
async fn register_user(s: &AdminState, ca: &ContextAuth, r: &RegRequest, client: &Client, policy: &Row) -> AuthResult<Option<(User, String)>> {
    let t = r.input_pass_type();
    let pass = match t {
        Some(SecretType::Password) => Some(match non_blank(&r.password) {
            Some(p) => p.to_string(),
            None => generate_secret(PolicyType::Password, policy)?,
        }),
        Some(SecretType::Pin) => Some(match non_blank(&r.pin) {
            Some(p) => p.to_string(),
            None => generate_secret(PolicyType::Pin, policy)?,
        }),
        _ => None,
    };
    let Some(pass) = pass else { return Err(reg_error("Client password cannot be blank")) };
    let user = User {
        client_id: client.id(),
        email_id: r.email_id.clone(),
        first_name: r.first_name.clone(),
        last_name: r.last_name.clone(),
        locale_code: r.locale_code.clone(),
        user_name: r.user_name.clone(),
        phone_number: r.phone_number.clone(),
        status_code: "ACTIVE".into(),
        ..Default::default()
    };
    let Some(app) = app_by_code(s, ca.url_app_code.as_deref()).await? else { return Ok(None) };
    let url_client_id = ca.logged_in_from_client_id.unwrap_or(0);
    let created = s.create_for_registration(ca, app.id, app.client_id, url_client_id, client, user, t, Some(pass.clone())).await?;
    Ok(Some((created, pass)))
}

// ---- events and the session ----

/// `getUrlPrefix`: the app's URL for a signed-in caller's client, else the request's address.
async fn url_prefix(s: &AdminState, info: &RequestInfo, ca: &ContextAuth) -> AuthResult<String> {
    let result = request_url_prefix(info);
    if ca.authenticated {
        let url = s.app_url(ca, ca.url_app_code.as_deref(), ca.client_code.as_deref()).await?;
        if !url.trim().is_empty() {
            return Ok(url);
        }
    }
    Ok(result)
}

/// `createRegistrationEvents`: `CLIENT_REGISTERED` and `USER_REGISTERED`; false when either
/// publish fails (the registration goes on).
#[allow(clippy::too_many_arguments)]
async fn registration_events(s: &AdminState, info: &RequestInfo, ca: &ContextAuth, client: &Client, sub_domain: &str, user: &User, token: &str, password: Option<&str>) -> AuthResult<bool> {
    let prefix = url_prefix(s, info, ca).await?;
    let Some(password) = password else {
        // `Map.of` refuses a null value.
        return Err(AuthError::internal("java.lang.NullPointerException"));
    };
    let client_json = crate::dto::client_json(client, &crate::dto::ClientExtras::default());
    let base = vec![("client".to_string(), client_json.clone()), ("subDomain".to_string(), Value::from(sub_domain)), ("urlPrefix".to_string(), Value::from(prefix.clone()))];
    let mut user_data = base.clone();
    user_data.push(("user".into(), user_json(user, &UserExtras::default())));
    user_data.push(("token".into(), Value::from(token)));
    user_data.push(("passwordUsed".into(), Value::from(password)));
    let event = |name: &str, data: Vec<(String, Value)>| EventMessage {
        event_name: name.into(),
        client_code: ca.logged_in_from_client_code.clone(),
        app_code: ca.url_app_code.clone(),
        data,
        ..Default::default()
    };
    let a = s.events.publish(&event("CLIENT_REGISTERED", base)).await;
    let b = s.events.publish(&event("USER_REGISTERED", user_data)).await;
    Ok(matches!((a, b), (Ok(true), Ok(true))))
}

/// `getClientAuthenticationResponse`: the new user signed in with the secret (a cookie session
/// too); none for OTP.
async fn sign_in(s: &AdminState, info: &RequestInfo, ca: &ContextAuth, r: &RegRequest, user_id: u64, secret: Option<&str>) -> AuthResult<Option<Minted>> {
    let mut b = AuthRequest { user_id: Some(user_id), cookie: true, ..Default::default() };
    match r.input_pass_type() {
        Some(SecretType::Password) => {
            b.password = secret.map(str::to_string);
            Ok(Some(s.auth.authenticate(&b, info, ca.user.id()).await?))
        }
        Some(SecretType::Pin) => {
            b.pin = secret.map(str::to_string);
            Ok(Some(s.auth.authenticate(&b, info, ca.user.id()).await?))
        }
        // Java's social sign-in branch (no type, a social state) is never reached: `register`
        // requires a type, and the events route fails on a missing one before it gets here.
        Some(SecretType::Otp) | None => Ok(None),
    }
}

/// `RegistrationResponse(created, userId, redirectURL, authentication)`.
pub fn response_json(user_id: u64, redirect: &str, auth: Option<&Minted>) -> Value {
    Obj::new()
        .put("created", true)
        .put("userId", user_id)
        .put("redirectURL", redirect)
        .put("authentication", auth.map(|m| m.response.to_json()).unwrap_or(Value::Null))
        .build()
}

/// A registration's answer: the body and the session cookie.
#[derive(Debug)]
pub struct Registered {
    pub body: Value,
    pub cookie: Option<String>,
}

fn with_cookie(body: &Value, cookie: Option<&str>) -> Response {
    let mut resp = json_resp(body);
    if let Some(v) = cookie.and_then(|c| HeaderValue::from_str(c).ok()) {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    resp
}

/// The caller's context as `register` changes it: a signed-in caller registers from their own
/// client.
fn registering_context(ca: &ContextAuth) -> ContextAuth {
    let mut ca = ca.clone();
    if ca.authenticated {
        ca.logged_in_from_client_code = ca.client_code.clone();
        ca.logged_in_from_client_id = Some(ca.user.client_id());
    }
    ca
}

// ---- the routes' services ----

/// `register(request)`. `None` where Java's chain completes empty (200 with no body).
pub async fn register(s: &AdminState, files: &dyn Files, info: &RequestInfo, ca: &ContextAuth, mut r: RegRequest) -> AuthResult<Option<Registered>> {
    if r.pass_type.is_none() {
        return Err(reg_error("Type of password for app is required"));
    }
    let ca = registering_context(ca);
    let lif = ca.logged_in_from_client_id.unwrap_or(0);
    let t = r.input_pass_type().unwrap_or(SecretType::Password);
    // `getClientAppPolicy(clientId, appCode, type)`: empty for an unknown app.
    let Some(app) = app_by_code(s, ca.url_app_code.as_deref()).await? else { return Ok(None) };
    let policy = policies::client_app_policy(s, policy_type(t), lif, app.id).await?;
    let Some(sub_domain) = pre_register_check(s, &ca, &mut r, app.id).await? else { return Ok(None) };
    let reg_prop = app_prop(s, &ca, lif, None, ca.url_app_code.as_deref(), REG_TYPE).await?;
    let Some(client) = register_client(s, &ca, &r, &reg_prop).await? else { return Ok(None) };
    let Some((user, pass)) = register_user(s, &ca, &r, &client, &policy).await? else { return Ok(None) };
    let token = if non_blank(&r.social_register_state).is_none() && r.input_pass_type().is_some() {
        s.make_registration_token(info, &ca, &user, lif).await?.token
    } else {
        String::new()
    };
    if add_files_access_path(s, files, &ca, &client, ca.url_app_code.as_deref()).await?.is_none() {
        return Ok(None);
    }
    registration_events(s, info, &ca, &client, &sub_domain, &user, &token, Some(&pass)).await?;
    let auth = sign_in(s, info, &ca, &r, user.id, Some(&pass)).await?;
    let mut redirect = String::new();
    if !sub_domain.trim().is_empty() {
        redirect = sub_domain.clone();
        let url = json!({"appCode": ca.url_app_code, "urlPattern": sub_domain, "clientId": client.id()});
        let mut row = super::urls::initial();
        row.extend(url.as_object().cloned().unwrap_or_default());
        super::urls::create_for_registration(s, &ca, row).await?;
    }
    if auto_add_reg_objects_from_other_apps(s, files, &ca, &client, &user).await?.is_none() {
        return Ok(None);
    }
    Ok(Some(Registered { body: response_json(user.id, &redirect, auth.as_ref()), cookie: auth.and_then(|a| a.cookie) }))
}

/// `preRegisterCheckOne(request)`: the checks `register` runs, and the OTP; false where Java's
/// chain completes empty.
pub async fn pre_register_check_one(s: &AdminState, ca: &ContextAuth, mut r: RegRequest) -> AuthResult<bool> {
    if ca.authenticated {
        return Err(reg_error("Logout to register"));
    }
    let lif = ca.logged_in_from_client_id.unwrap_or(0);
    let Some(app) = app_by_code(s, ca.url_app_code.as_deref()).await? else { return Ok(false) };
    if r.input_pass_type().is_none() {
        return Err(AuthError::internal(
            "Cannot invoke \"com.fincity.security.service.policy.IPolicyService.getClientAppPolicy(org.jooq.types.ULong, org.jooq.types.ULong)\" because \"policyService\" is null",
        ));
    }
    if pre_register_check(s, ca, &mut r, app.id).await?.is_none() {
        return Ok(false);
    }
    let reg_prop = app_prop(s, ca, lif, None, ca.url_app_code.as_deref(), REG_TYPE).await?;
    if reg_prop_refuses(&reg_prop) {
        return Err(no_registration());
    }
    verify_client(s, ca, &reg_prop, &r).await?;
    Ok(true)
}

/// `registerWSocial(request)`: `register` for a state the provider verified, which is spent
/// once the registration is through.
pub async fn register_social(s: &AdminState, files: &dyn Files, info: &RequestInfo, ca: &ContextAuth, r: RegRequest) -> AuthResult<Option<Registered>> {
    let Some(state) = non_blank(&r.social_register_state).map(str::to_string) else {
        return Err(reg_error("Social register state cannot be blank for social Login."));
    };
    let token = verify_state(s, Some(&state)).await?;
    let Some(verified) = entity::str_of(&token, "username").filter(|u| !u.trim().is_empty()).map(str::to_string) else {
        return Err(reg_error("Social login was not completed"));
    };
    if Some(verified.as_str()) != r.user_name.as_deref() && Some(verified.as_str()) != r.email_id.as_deref() {
        return Err(reg_error("Username and EmailId should not be changed"));
    }
    if state_expired(&token, s.auth.clock.utc()) {
        return Err(err(StatusCode::BAD_REQUEST, SESSION_EXPIRED, &[]));
    }
    let Some(done) = register(s, files, info, ca, r).await? else { return Ok(None) };
    if let Some(st) = entity::str_of(&token, "state") {
        consume_state(s, st).await?;
    }
    Ok(Some(done))
}

/// `User.getInputPass(passType)`: the stored secret of that type (hashed, as stored).
fn stored_secret(u: &User, t: Option<SecretType>) -> AuthResult<Option<String>> {
    let blankish = |v: &Option<String>| v.as_deref().is_none_or(|s| s.trim().is_empty());
    match t {
        None => Err(AuthError::internal("Cannot invoke \"com.fincity.security.model.AuthenticationPasswordType.ordinal()\" because \"passType\" is null")),
        Some(SecretType::Password) => Ok(if !blankish(&u.password) {
            u.password.clone()
        } else if !blankish(&u.pin) {
            u.pin.clone()
        } else {
            None
        }),
        Some(SecretType::Pin) => Ok(u.pin.clone()),
        Some(SecretType::Otp) => Ok(None),
    }
}

/// `evokeRegistrationEvents(request)`: the two events again for a user, once they sign in with
/// what is stored. `None` where Java's chain completes empty.
pub async fn evoke_registration_events(s: &AdminState, info: &RequestInfo, ca: &ContextAuth, r: RegRequest) -> AuthResult<Option<bool>> {
    let t = r.input_pass_type();
    let Some(user_id) = r.user_id else { return Err(err(StatusCode::NOT_FOUND, OBJECT_NOT_FOUND, &["User", "null"])) };
    let (user, _) = s.user_for_context(ca.url_app_code.as_deref(), user_id).await?;
    let Some(client) = s.dir().client(user.client_id).await? else { return Ok(None) };
    let secret = stored_secret(&user, t)?;
    let Some(auth) = sign_in(s, info, ca, &r, user.id, secret.as_deref()).await? else { return Ok(None) };
    // `getAppUrl(client.getCode(), urlAppCode)`: Java passes the two the other way round.
    let sub_domain = s.app_url(ca, client.code.as_deref(), ca.url_app_code.as_deref()).await?;
    let token = auth.response.access_token.clone().unwrap_or_default();
    Ok(Some(registration_events(s, info, ca, &client, &sub_domain, &user, &token, secret.as_deref()).await?))
}

/// `registerApp(appCode, clientId, userId)`: an existing client, through its owner, registered
/// on one more app. 409 when the user is not an owner or the app or client is unknown.
pub async fn register_app(s: &AdminState, files: &dyn Files, ca: &ContextAuth, app_code: &str, client_id: u64, user_id: u64) -> AuthResult<bool> {
    let none = || err(StatusCode::CONFLICT, NO_REGISTRATION_AVAILABLE, &[]);
    if !s.check_if_user_is_owner(user_id).await? {
        return Err(none());
    }
    let Some(app) = s.dir().app_by_code(app_code).await? else { return Err(none()) };
    let Some(client) = s.dir().client(client_id).await? else { return Err(none()) };
    let lif = ca.logged_in_from_client_id.unwrap_or(0);
    add_client_registration_objects(s, app.id, app.client_id, lif, &client).await?;
    if add_client_access_after_registration(s, ca, Some(&app.app_code), lif, &client).await?.is_none() {
        return Err(none());
    }
    if add_files_access_path(s, files, ca, &client, Some(app_code)).await?.is_none() {
        return Err(none());
    }
    s.add_default_profiles(app.id, app.client_id, lif, &client, user_id).await?;
    s.add_default_roles(app.id, app.client_id, lif, &client, user_id).await?;
    s.add_designation(app.id, app.client_id, lif, &client, user_id).await
}

// ---- routes ----

pub fn router() -> Router<AdminState> {
    Router::new()
        .route("/api/security/clients/register", post(register_route))
        .route("/api/security/clients/register/otp/verify", post(verify_route))
        .route("/api/security/clients/socialRegister", post(social_route))
        .route("/api/security/clients/register/events", get(events_route))
        .route("/api/security/clients/appRegister", post(app_register_route))
}

fn registered(done: Option<Registered>) -> Response {
    match done {
        Some(d) => with_cookie(&d.body, d.cookie.as_deref()),
        None => web::nothing(),
    }
}

web_route!(register_route, AdminState, "/clients/register", false, |s, r, ca| {
    let body = request_body(&r, true)?;
    let files = FilesUpstream(s.files.as_ref());
    Ok(registered(register(&s, &files, &r.info, &ca, body).await?))
});

web_route!(verify_route, AdminState, "/clients/register/otp/verify", false, |s, r, ca| {
    let body = request_body(&r, true)?;
    Ok(json_resp(&Value::Bool(pre_register_check_one(&s, &ca, body).await?)))
});

web_route!(social_route, AdminState, "/clients/socialRegister", false, |s, r, ca| {
    let body = request_body(&r, true)?;
    let files = FilesUpstream(s.files.as_ref());
    Ok(registered(register_social(&s, &files, &r.info, &ca, body).await?))
});

web_route!(events_route, AdminState, "/clients/register/events", false, |s, r, ca| {
    let body = request_body(&r, false)?;
    Ok(match evoke_registration_events(&s, &r.info, &ca, body).await? {
        Some(b) => json_resp(&Value::Bool(b)),
        None => web::nothing(),
    })
});

web_route!(app_register_route, AdminState, "/clients/appRegister", true, |s, r, ca| {
    let app_code = req_str(&r.params, "appCode")?.to_string();
    let client_id = to_u64(req_str(&r.params, "clientId")?)?;
    let user_id = to_u64(req_str(&r.params, "userId")?)?;
    let files = FilesUpstream(s.files.as_ref());
    Ok(json_resp(&Value::Bool(register_app(&s, &files, &ca, &app_code, client_id, user_id).await?)))
});

#[cfg(test)]
mod tests {
    use super::*;

    fn req(v: Value) -> RegRequest {
        RegRequest::read(&v).unwrap()
    }

    #[test]
    fn reads_the_request_like_jackson() {
        let r = req(json!({"passType": "PIN", "pin": 1234, "businessClient": "true", "userId": "7", "unknown": 1}));
        assert_eq!((r.pass_type, r.pin.as_deref(), r.business_client, r.user_id), (Some(SecretType::Pin), Some("1234"), true, Some(7)));
        assert_eq!(req(json!({"passType": 2})).pass_type, Some(SecretType::Otp));
        assert!(RegRequest::read(&json!({"passType": "NOPE"})).is_err());
        assert!(RegRequest::read(&json!({"userId": "x"})).is_err());
        assert!(!req(json!({"businessClient": null})).business_client);
    }

    #[test]
    fn input_pass_and_identifier() {
        let r = req(json!({"password": "  ", "pin": "12", "otp": "9"}));
        assert_eq!((r.input_pass_type(), r.input_pass().as_deref()), (Some(SecretType::Pin), Some("12")));
        let r = req(json!({"passType": "PASSWORD", "pin": "12"}));
        assert_eq!((r.input_pass_type(), r.input_pass()), (Some(SecretType::Password), None));
        assert_eq!(req(json!({})).input_pass_type(), None);
        assert_eq!(req(json!({"emailId": " ", "phoneNumber": "+91"})).identifier(), Some("+91"));
        assert_eq!(req(json!({})).identifier(), None);
    }

    #[test]
    fn client_names() {
        assert_eq!(req(json!({"clientName": "Acme", "firstName": "A"})).valid_client_name().as_deref(), Some("Acme"));
        assert_eq!(req(json!({"firstName": "Ann", "lastName": "Lee"})).valid_client_name().as_deref(), Some("AnnLee"));
        assert_eq!(req(json!({"lastName": "Lee"})).valid_client_name().as_deref(), Some("Lee"));
        assert_eq!(req(json!({"emailId": "a@b.c", "userName": "u"})).valid_client_name().as_deref(), Some("a@b.c"));
        assert_eq!(req(json!({"userName": "u"})).valid_client_name().as_deref(), Some("u"));
        assert_eq!(req(json!({})).valid_client_name(), None);
    }

    #[test]
    fn code_prefixes() {
        assert_eq!(client_code_prefix("Kailash Traders"), "KAILA");
        assert_eq!(client_code_prefix("a1-b2"), "AB");
        assert_eq!(client_code_prefix("zz.reg@example.com"), "ZZREG");
        assert_eq!(client_code_prefix("123"), "");
    }

    #[test]
    fn usage_types() {
        assert!(check_usage_type(Some("B2C"), "OWNER", false).is_ok());
        assert!(check_usage_type(Some("B2C"), "OWNER", true).is_err());
        assert!(check_usage_type(Some("B2C"), "CLIENT", false).is_err());
        assert!(check_usage_type(Some("B2B"), "OWNER", false).is_err());
        assert!(check_usage_type(Some("B2X"), "OWNER", true).is_ok());
        assert!(check_usage_type(Some("B2X"), "CLIENT", true).is_err());
        assert!(check_usage_type(Some("B2B2C"), "CLIENT", false).is_ok());
        assert!(check_usage_type(Some("B2B2C"), "OWNER", false).is_err());
        assert!(check_usage_type(Some("B2X2X"), "CUSTOMER", false).is_err());
        assert!(check_usage_type(Some("S"), "OWNER", false).is_err());
        assert!(check_usage_type(None, "CONSUMER", true).is_ok());
        let e = check_usage_type(Some("B2B"), "OWNER", false).unwrap_err();
        assert_eq!(e.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn codes_and_secrets() {
        let c = generate_code(12, true, true, true, true).unwrap();
        assert_eq!(c.len(), 12);
        assert!(c.chars().all(|ch| NUMBERS.contains(ch) || UPPERCASE.contains(ch) || LOWERCASE.contains(ch) || SPECIAL_CHARS.contains(ch)));
        assert!(generate_code(4, true, false, false, false).unwrap().chars().all(|ch| ch.is_ascii_digit()));
        assert_eq!(generate_code(0, false, false, false, false).unwrap(), "");
        assert!(generate_code(3, false, false, false, false).is_err());
        let pin = generate_secret(PolicyType::Pin, &PolicyType::Pin.default_policy()).unwrap();
        assert_eq!(pin.len(), 4);
        let pass = generate_secret(PolicyType::Password, &PolicyType::Password.default_policy()).unwrap();
        assert_eq!(pass.len(), 12);
        assert!(generate_secret(PolicyType::Password, &PolicyType::Password.initial()).is_err());
    }

    #[test]
    fn response_and_prefix() {
        assert_eq!(response_json(7, "", None), json!({"created": true, "userId": 7}));
        assert_eq!(response_json(7, "a.b", None), json!({"created": true, "userId": 7, "redirectURL": "a.b"}));
        let mut h = axum::http::HeaderMap::new();
        h.insert("x-forwarded-host", "a.local.modlix.com".parse().unwrap());
        assert_eq!(request_url_prefix(&RequestInfo::new(h.clone(), None)), "http://a.local.modlix.com:null");
        h.insert("x-forwarded-proto", "https".parse().unwrap());
        assert_eq!(request_url_prefix(&RequestInfo::new(h, None)), "https://a.local.modlix.com");
    }

    #[test]
    fn stored_secrets() {
        let u = User { password: Some("$2a$hash".into()), pin: Some("p".into()), ..Default::default() };
        assert_eq!(stored_secret(&u, Some(SecretType::Password)).unwrap().as_deref(), Some("$2a$hash"));
        assert_eq!(stored_secret(&u, Some(SecretType::Pin)).unwrap().as_deref(), Some("p"));
        assert_eq!(stored_secret(&u, Some(SecretType::Otp)).unwrap(), None);
        assert!(stored_secret(&u, None).is_err());
    }

    #[test]
    fn every_usage_type_rule() {
        let refused = |u: &str, l: &str, b: bool| check_usage_type(Some(u), l, b).err().map(|e| e.to_string());
        for (u, l, b) in [
            ("B", "OWNER", true),
            ("B2B", "CLIENT", true),
            ("B2B2B", "CUSTOMER", true),
            ("B2B2B", "CLIENT", false),
            ("B2B2C", "CUSTOMER", false),
            ("B2B2C", "CLIENT", true),
            ("B2B2X", "CONSUMER", true),
            ("B2B2X", "OWNER", false),
            ("B2X2C", "CUSTOMER", false),
            ("B2X2C", "CLIENT", true),
        ] {
            assert!(refused(u, l, b).is_some(), "{u} {l} {b}");
        }
        for (u, l, b) in [("B2B2B", "CLIENT", true), ("B2B2X", "CLIENT", false), ("B2X2C", "OWNER", true), ("B2X2X", "CLIENT", true), ("B2B", "OWNER", true)] {
            assert!(refused(u, l, b).is_none(), "{u} {l} {b}");
        }
    }

    #[test]
    fn secret_kinds() {
        assert_eq!(secret_type("NOPE"), None);
        assert_eq!(req(json!({"password": "p"})).input_pass_type(), Some(SecretType::Password));
        assert_eq!(req(json!({"otp": "1"})).input_pass_type(), Some(SecretType::Otp));
        assert_eq!(req(json!({"passType": "PIN", "pin": "77"})).input_pass().as_deref(), Some("77"));
        assert_eq!(req(json!({"passType": "OTP", "otp": "9"})).input_pass().as_deref(), Some("9"));
        assert_eq!(client_code_prefix("  "), "  ");
        assert!(generate_secret(PolicyType::Otp, &Row::new()).is_err());
        assert_eq!(policy_type(SecretType::Pin), PolicyType::Pin);
        assert_eq!(policy_type(SecretType::Otp), PolicyType::Otp);
        let only_pin = User { pin: Some("p".into()), ..Default::default() };
        assert_eq!(stored_secret(&only_pin, Some(SecretType::Password)).unwrap().as_deref(), Some("p"));
        assert_eq!(stored_secret(&User::default(), Some(SecretType::Password)).unwrap(), None);
    }

    #[test]
    fn access_path_json() {
        let p = AccessPath { client_code: "ZZ".into(), access_name: Some("a".into()), write_access: true, path: Some("/x".into()), allow_sub_path_access: false, resource_type: Some("STATIC".into()) };
        let keys: Vec<String> = p.to_json().as_object().unwrap().keys().cloned().collect();
        assert_eq!(keys, ["clientCode", "accessName", "writeAccess", "path", "allowSubPathAccess", "resourceType"]);
    }

    #[tokio::test]
    async fn lookups_without_a_code() {
        let s = crate::admin::users::testkit::offline();
        assert!(app_by_code(&s, None).await.unwrap().is_none());
        assert!(client_by_code(&s, None).await.unwrap().is_none());
    }
}
