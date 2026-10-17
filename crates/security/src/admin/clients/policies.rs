//! `ClientPasswordPolicyController`, `ClientPinPolicyController`, `ClientOtpPolicyController`
//! (`AbstractPolicyController` over `AbstractJOOQUpdatableDataController`) and
//! `AbstractPolicyService` with its three subclasses.
//!
//! | Route (each of the three bases) | Who |
//! |---|---|
//! | `GET codes/policy` | anyone (the policy for the `clientCode` / `appCode` headers) |
//! | `GET`, `POST query`, `GET {id}` | signed in (`GET {id}`: `Application_READ`) |
//! | `POST` | `Application_CREATE` |
//! | `PUT {id}`, `PATCH {id}` | `Application_UPDATE` |
//! | `DELETE {id}` | `Application_DELETE` |
//!
//! The policy rows are read from the database each time (Java caches them per client and app in
//! `clientPasswordPolicy` / `clientPinPolicy` / `clientOtpPolicy`); every write evicts Java's
//! entry as Java does.

use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use serde_json::{json, Value};

use super::common::{err, no_content, pre_authorize, FORBIDDEN_CREATE};
use super::entity::{self, col, prim, prim_hidden, prim_write_only, write_only, Col, Entity, Row, CREATED_AT, CREATED_BY, ID, UPDATED_AT, UPDATED_BY};
use super::common::Kind;
use crate::admin::AdminState;
use crate::condition::{ColType, Table};
use crate::errors::{AuthError, AuthResult};
use crate::handlers::respond;
use crate::jackson::json as json_resp;
use crate::model::ContextAuth;
use crate::spring::Pageable;
use crate::web::{self, to_u64, In};

/// One of the three policy types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyType {
    Password,
    Pin,
    Otp,
}

const TARGET_TYPES: &[&str] = &["EMAIL", "PHONE", "BOTH"];

static OTP_COLS: [Col; 18] = [
    ID,
    CREATED_AT,
    CREATED_BY,
    UPDATED_AT,
    UPDATED_BY,
    write_only("clientId", "CLIENT_ID", Kind::U64, true),
    write_only("appId", "APP_ID", Kind::U64, true),
    col("noFailedAttempts", "NO_FAILED_ATTEMPTS", Kind::I64, true),
    write_only("userLockTime", "USER_LOCK_TIME", Kind::I64, true),
    col("targetType", "TARGET_TYPE", Kind::Enum(TARGET_TYPES), true),
    prim_write_only("isConstant", "IS_CONSTANT", Kind::Bool),
    write_only("constantValue", "CONSTANT_VALUE", Kind::Str, false),
    prim_hidden("isNumeric", "IS_NUMERIC", Kind::Bool),
    prim_hidden("isAlphanumeric", "IS_ALPHANUMERIC", Kind::Bool),
    col("length", "LENGTH", Kind::I64, true),
    prim_write_only("resendSameOtp", "RESEND_SAME_OTP", Kind::Bool),
    write_only("noResendAttempts", "NO_RESEND_ATTEMPTS", Kind::I64, true),
    col("expireInterval", "EXPIRE_INTERVAL", Kind::I64, true),
];

static PASSWORD_COLS: [Col; 21] = [
    ID,
    CREATED_AT,
    CREATED_BY,
    UPDATED_AT,
    UPDATED_BY,
    write_only("clientId", "CLIENT_ID", Kind::U64, true),
    write_only("appId", "APP_ID", Kind::U64, false),
    col("noFailedAttempts", "NO_FAILED_ATTEMPTS", Kind::I64, false),
    write_only("userLockTime", "USER_LOCK_TIME", Kind::I64, true),
    prim("atleastOneUppercase", "ATLEAST_ONE_UPPERCASE", Kind::Bool),
    prim("atleastOneLowercase", "ATLEAST_ONE_LOWERCASE", Kind::Bool),
    prim("atleastOneDigit", "ATLEAST_ONE_DIGIT", Kind::Bool),
    prim("atleastOneSpecialChar", "ATLEAST_ONE_SPECIAL_CHAR", Kind::Bool),
    prim("spacesAllowed", "SPACES_ALLOWED", Kind::Bool),
    col("regex", "REGEX", Kind::Str, false),
    // No column is named PERCENTAGE_NAME (it is PERCENTAGE_NAME_MATCH): never stored or read.
    entity::extra("percentageName", Kind::I64),
    write_only("passExpiryInDays", "PASS_EXPIRY_IN_DAYS", Kind::I64, false),
    write_only("passExpiryWarnInDays", "PASS_EXPIRY_WARN_IN_DAYS", Kind::I64, false),
    col("passMinLength", "PASS_MIN_LENGTH", Kind::I64, false),
    col("passMaxLength", "PASS_MAX_LENGTH", Kind::I64, false),
    write_only("passHistoryCount", "PASS_HISTORY_COUNT", Kind::I64, false),
];

static PIN_COLS: [Col; 14] = [
    ID,
    CREATED_AT,
    CREATED_BY,
    UPDATED_AT,
    UPDATED_BY,
    write_only("clientId", "CLIENT_ID", Kind::U64, true),
    write_only("appId", "APP_ID", Kind::U64, true),
    col("noFailedAttempts", "NO_FAILED_ATTEMPTS", Kind::I64, true),
    write_only("userLockTime", "USER_LOCK_TIME", Kind::I64, true),
    col("length", "LENGTH", Kind::I64, true),
    write_only("reLoginAfterInterval", "RE_LOGIN_AFTER_INTERVAL", Kind::I64, true),
    write_only("expiryInDays", "EXPIRY_IN_DAYS", Kind::I64, true),
    write_only("expiryWarnInDays", "EXPIRY_WARN_IN_DAYS", Kind::I64, true),
    write_only("pinHistoryCount", "PIN_HISTORY_COUNT", Kind::I64, true),
];

const COMMON_FILTER: [(&str, ColType); 9] = [
    ("ID", ColType::Num),
    ("CLIENT_ID", ColType::Num),
    ("APP_ID", ColType::Num),
    ("NO_FAILED_ATTEMPTS", ColType::Num),
    ("USER_LOCK_TIME", ColType::Num),
    ("CREATED_BY", ColType::Num),
    ("CREATED_AT", ColType::Ts),
    ("UPDATED_BY", ColType::Num),
    ("UPDATED_AT", ColType::Ts),
];

pub static OTP: std::sync::LazyLock<Entity> = std::sync::LazyLock::new(|| Entity {
    pojo: "ClientOtpPolicy",
    table: "security_client_otp_policy",
    cols: &OTP_COLS,
    setters: &[
        ("targetType", "targetType"),
        ("constant", "isConstant"),
        ("constantValue", "constantValue"),
        ("numeric", "isNumeric"),
        ("alphanumeric", "isAlphanumeric"),
        ("length", "length"),
        ("resendSameOtp", "resendSameOtp"),
        ("noResendAttempts", "noResendAttempts"),
        ("expireInterval", "expireInterval"),
    ],
    aliases: &[("constant", "isConstant"), ("numeric", "isNumeric"), ("alphanumeric", "isAlphanumeric")],
    filter: Table { name: "security_client_otp_policy", columns: leak(COMMON_FILTER.iter().copied().chain([
        ("TARGET_TYPE", ColType::Enum),
        ("IS_CONSTANT", ColType::Num),
        ("CONSTANT_VALUE", ColType::Str),
        ("IS_NUMERIC", ColType::Num),
        ("IS_ALPHANUMERIC", ColType::Num),
        ("LENGTH", ColType::Num),
        ("RESEND_SAME_OTP", ColType::Num),
        ("NO_RESEND_ATTEMPTS", ColType::Num),
        ("EXPIRE_INTERVAL", ColType::Num),
    ])) },
    client_column: Some("CLIENT_ID"),
});

pub static PASSWORD: std::sync::LazyLock<Entity> = std::sync::LazyLock::new(|| Entity {
    pojo: "ClientPasswordPolicy",
    table: "security_client_password_policy",
    cols: &PASSWORD_COLS,
    setters: &[
        ("atleastOneUppercase", "atleastOneUppercase"),
        ("atleastOneLowercase", "atleastOneLowercase"),
        ("atleastOneDigit", "atleastOneDigit"),
        ("atleastOneSpecialChar", "atleastOneSpecialChar"),
        ("spacesAllowed", "spacesAllowed"),
        ("regex", "regex"),
        ("percentageName", "percentageName"),
        ("passExpiryInDays", "passExpiryInDays"),
        ("passExpiryWarnInDays", "passExpiryWarnInDays"),
        ("passMinLength", "passMinLength"),
        ("passMaxLength", "passMaxLength"),
        ("passHistoryCount", "passHistoryCount"),
    ],
    aliases: &[],
    filter: Table { name: "security_client_password_policy", columns: leak(COMMON_FILTER.iter().copied().chain([
        ("ATLEAST_ONE_UPPERCASE", ColType::Num),
        ("ATLEAST_ONE_LOWERCASE", ColType::Num),
        ("ATLEAST_ONE_DIGIT", ColType::Num),
        ("ATLEAST_ONE_SPECIAL_CHAR", ColType::Num),
        ("SPACES_ALLOWED", ColType::Num),
        ("REGEX", ColType::Str),
        ("PERCENTAGE_NAME_MATCH", ColType::Num),
        ("PASS_EXPIRY_IN_DAYS", ColType::Num),
        ("PASS_EXPIRY_WARN_IN_DAYS", ColType::Num),
        ("PASS_MIN_LENGTH", ColType::Num),
        ("PASS_MAX_LENGTH", ColType::Num),
        ("PASS_HISTORY_COUNT", ColType::Num),
    ])) },
    client_column: Some("CLIENT_ID"),
});

pub static PIN: std::sync::LazyLock<Entity> = std::sync::LazyLock::new(|| Entity {
    pojo: "ClientPinPolicy",
    table: "security_client_pin_policy",
    cols: &PIN_COLS,
    setters: &[
        ("length", "length"),
        ("reLoginAfterInterval", "reLoginAfterInterval"),
        ("expiryInDays", "expiryInDays"),
        ("expiryWarnInDays", "expiryWarnInDays"),
        ("pinHistoryCount", "pinHistoryCount"),
    ],
    aliases: &[],
    filter: Table { name: "security_client_pin_policy", columns: leak(COMMON_FILTER.iter().copied().chain([
        ("LENGTH", ColType::Num),
        ("RE_LOGIN_AFTER_INTERVAL", ColType::Num),
        ("EXPIRY_IN_DAYS", ColType::Num),
        ("EXPIRY_WARN_IN_DAYS", ColType::Num),
        ("PIN_HISTORY_COUNT", ColType::Num),
    ])) },
    client_column: Some("CLIENT_ID"),
});

/// A table description built once at start-up and kept for the life of the process.
fn leak(it: impl Iterator<Item = (&'static str, ColType)>) -> &'static [(&'static str, ColType)] {
    Box::leak(it.collect::<Vec<_>>().into_boxed_slice())
}

fn row(pairs: Value) -> Row {
    pairs.as_object().cloned().unwrap_or_default()
}

impl PolicyType {
    pub fn entity(self) -> &'static Entity {
        match self {
            Self::Password => &PASSWORD,
            Self::Pin => &PIN,
            Self::Otp => &OTP,
        }
    }

    /// `getPolicyName()`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Password => "client password policy",
            Self::Pin => "client_pin_policy",
            Self::Otp => "client_otp_policy",
        }
    }

    /// `getPolicyCacheName()`.
    pub fn cache(self) -> &'static str {
        match self {
            Self::Password => "clientPasswordPolicy",
            Self::Pin => "clientPinPolicy",
            Self::Otp => "clientOtpPolicy",
        }
    }

    /// The DTO's field initializers.
    pub fn initial(self) -> Row {
        let mut r = row(json!({"noFailedAttempts": 3, "userLockTime": 15}));
        r.extend(match self {
            Self::Otp => row(json!({
                "targetType": "EMAIL", "isConstant": false, "isNumeric": true, "isAlphanumeric": false, "length": 4,
                "resendSameOtp": false, "noResendAttempts": 3, "expireInterval": 5
            })),
            Self::Password => row(json!({
                "atleastOneUppercase": false, "atleastOneLowercase": false, "atleastOneDigit": false,
                "atleastOneSpecialChar": false, "spacesAllowed": false
            })),
            Self::Pin => row(json!({
                "length": 4, "reLoginAfterInterval": 120, "expiryInDays": 30, "expiryWarnInDays": 25, "pinHistoryCount": 3
            })),
        });
        r
    }

    /// `getDefaultPolicy()`: id 0, client 0, app 0.
    pub fn default_policy(self) -> Row {
        let mut r = self.initial();
        if self == Self::Password {
            r.extend(row(json!({
                "atleastOneUppercase": true, "atleastOneLowercase": true, "atleastOneDigit": true,
                "atleastOneSpecialChar": true, "spacesAllowed": false, "passExpiryInDays": 10, "passExpiryWarnInDays": 8,
                "passMinLength": 12, "passMaxLength": 20, "passHistoryCount": 5
            })));
        }
        r.extend(row(json!({"id": 0, "clientId": 0, "appId": 0, "noFailedAttempts": 3, "userLockTime": 15})));
        r
    }

    /// The policy through Jackson (the OTP policy's `numeric` / `alphanumeric` are getter-only).
    pub fn to_json(self, r: &Row) -> Value {
        let getters = match self {
            Self::Otp => vec![
                ("numeric", r.get("isNumeric").cloned().unwrap_or(Value::Bool(false))),
                ("alphanumeric", r.get("isAlphanumeric").cloned().unwrap_or(Value::Bool(false))),
            ],
            _ => vec![],
        };
        self.entity().to_json(r, getters)
    }

    /// `updatableEntity`: the stored row with the request's values copied over.
    pub fn copy_updatable(self, existing: &mut Row, entity: &Row) {
        let fields: &[&str] = match self {
            Self::Otp => &[
                "targetType", "isConstant", "constantValue", "isNumeric", "isAlphanumeric", "length", "expireInterval",
                "resendSameOtp", "noResendAttempts",
            ],
            Self::Password => &[
                "atleastOneUppercase", "atleastOneLowercase", "atleastOneDigit", "atleastOneSpecialChar", "spacesAllowed",
                "regex", "percentageName", "passExpiryInDays", "passExpiryWarnInDays", "passMinLength", "passMaxLength",
                "passHistoryCount",
            ],
            Self::Pin => &["length", "reLoginAfterInterval", "expiryInDays", "expiryWarnInDays", "pinHistoryCount"],
        };
        for f in fields {
            existing.insert((*f).to_string(), entity.get(*f).cloned().unwrap_or(Value::Null));
        }
        let or = |k: &str, d: i64| entity.get(k).filter(|v| !v.is_null()).cloned().unwrap_or(Value::from(d));
        existing.insert("noFailedAttempts".into(), or("noFailedAttempts", 3));
        existing.insert("userLockTime".into(), or("userLockTime", 15));
    }

    fn base(self) -> &'static str {
        match self {
            Self::Password => "/api/security/clientPasswordPolicy",
            Self::Pin => "/api/security/clientPinPolicy",
            Self::Otp => "/api/security/clientOtpPolicy",
        }
    }
}

/// `AbstractPolicyDao.getClientAppPolicy(clientId, appId)`.
pub async fn policy_row(s: &AdminState, t: PolicyType, client_id: u64, app_id: u64) -> AuthResult<Option<Row>> {
    let e = t.entity();
    let sql = format!("SELECT {} FROM {} WHERE CLIENT_ID = ? AND APP_ID = ? LIMIT 1", e.select_list(), e.table);
    let r = sqlx::query(&sql).bind(client_id).bind(app_id).fetch_optional(&s.db.pool).await?;
    r.as_ref().map(|r| e.read_row(r)).transpose()
}

/// `AbstractPolicyService.getClientAppPolicy(clientId, appId)`: the nearest policy up the
/// hierarchy, else the type's default.
pub async fn client_app_policy(s: &AdminState, t: PolicyType, client_id: u64, app_id: u64) -> AuthResult<Row> {
    for cid in s.dir().hierarchy(client_id).await?.client_ids() {
        if let Some(r) = policy_row(s, t, cid, app_id).await? {
            return Ok(r);
        }
    }
    Ok(t.default_policy())
}

/// `getClientAppPolicy(clientCode, appCode)`: `None` for an unknown client or app.
pub async fn policy_for_codes(s: &AdminState, t: PolicyType, client_code: &str, app_code: &str) -> AuthResult<Option<Row>> {
    let Some(client) = s.client_by_code(client_code).await? else { return Ok(None) };
    let Some(app) = s.dir().app_by_code(app_code).await? else { return Ok(None) };
    Ok(Some(client_app_policy(s, t, client.id(), app.id).await?))
}

/// `canUpdatePolicy(ca, appId)`: the caller manages the app's client, its client has edit access,
/// or it is SYSTEM. An unknown app is the DAO's 404.
async fn can_update_policy(s: &AdminState, ca: &ContextAuth, app_id: Option<u64>) -> AuthResult<bool> {
    let Some(app_id) = app_id else { return Ok(false) };
    let app = s.dir().app_by_id(app_id).await?;
    let managed = s.caller_manages_client(ca, app.client_id).await?;
    let edit = super::dao::has_access_by_id(&s.db.pool, app_id, ca.logged_in_from_client_id, true).await?;
    Ok(managed || edit || ca.is_system_client())
}

fn forbidden(t: PolicyType) -> AuthError {
    err(StatusCode::FORBIDDEN, FORBIDDEN_CREATE, &[t.name()])
}

async fn evict(s: &AdminState, t: PolicyType, r: &Row) {
    let key = format!("{}:{}", fmt_id(r.get("clientId")), fmt_id(r.get("appId")));
    s.caches().service.evict_everywhere(t.cache(), &key).await;
}

/// A `ULong` as `toString()` writes it inside a cache key (`null` when absent).
fn fmt_id(v: Option<&Value>) -> String {
    match v {
        Some(Value::Number(n)) => n.to_string(),
        _ => "null".into(),
    }
}

/// `create(entity)`.
pub async fn create(s: &AdminState, ca: &ContextAuth, t: PolicyType, mut entity: Row) -> AuthResult<Row> {
    let app = match ca.url_app_code.as_deref() {
        Some(code) => s.dir().app_by_code(code).await?,
        None => None,
    };
    for (k, d) in [("noFailedAttempts", 3), ("userLockTime", 15)] {
        if entity.get(k).is_none_or(Value::is_null) {
            entity.insert(k.into(), Value::from(d));
        }
    }
    if entity.get("appId").is_none_or(Value::is_null) {
        let Some(app) = app else {
            return Err(AuthError::internal("Cannot invoke \"com.fincity.security.dto.App.getId()\" because \"app\" is null"));
        };
        entity.insert("appId".into(), Value::from(app.id));
    }
    if entity.get("clientId").is_none_or(Value::is_null) {
        entity.insert("clientId".into(), ca.logged_in_from_client_id.map(Value::from).unwrap_or(Value::Null));
    }
    let client_id = entity.get("clientId").and_then(Value::as_u64);
    let app_id = entity.get("appId").and_then(Value::as_u64);
    if let (Some(c), Some(a)) = (client_id, app_id) {
        if let Some(existing) = policy_row(s, t, c, a).await? {
            if entity::u64_of(&existing, "id").is_some_and(|id| id != 0) {
                return Err(forbidden(t));
            }
        }
    }
    if !can_update_policy(s, ca, app_id).await? {
        return Err(forbidden(t));
    }
    entity.insert("createdBy".into(), Value::Null);
    let e = t.entity();
    let id = entity::insert(&s.db, e, &entity).await?;
    let created = entity::read_by_id(&s.db, e, id).await?;
    evict(s, t, &created).await;
    crate::data::audit::activity(
        &s.db,
        entity::u64_of(&created, "clientId"),
        format!("{} Create", t.name()),
        format!("{} created for appId {}", t.name(), fmt_id(created.get("appId"))),
        None,
    );
    Ok(created)
}

/// `update(entity)`.
pub async fn update(s: &AdminState, ca: &ContextAuth, t: PolicyType, entity: &Row) -> AuthResult<Row> {
    let e = t.entity();
    let id = entity::u64_of(entity, "id").ok_or_else(|| e.not_found("null"))?;
    let stored = entity::read_by_id(&s.db, e, id).await?;
    if !can_update_policy(s, ca, entity::u64_of(&stored, "appId")).await? {
        return Err(forbidden(t));
    }
    // `canBeUpdated`: the count over the client-check joins with no restriction, so any existing row.
    let mut existing = stored.clone();
    t.copy_updatable(&mut existing, entity);
    entity::update(&s.db, e, &existing).await?;
    let updated = entity::read_by_id(&s.db, e, id).await?;
    crate::data::audit::activity(
        &s.db,
        entity::u64_of(&stored, "clientId"),
        format!("{} Update", t.name()),
        format!("{} updated for appId {}", t.name(), fmt_id(stored.get("appId"))),
        None,
    );
    evict(s, t, &stored).await;
    Ok(updated)
}

/// `update(key, fields)`: the patched row goes through `update(entity)` (which logs and evicts),
/// then this logs and evicts again, as Java does.
pub async fn patch(s: &AdminState, ca: &ContextAuth, t: PolicyType, id: u64, fields: &serde_json::Map<String, Value>) -> AuthResult<Row> {
    let e = t.entity();
    let stored = entity::read_by_id(&s.db, e, id).await?;
    if !can_update_policy(s, ca, entity::u64_of(&stored, "appId")).await? {
        return Err(forbidden(t));
    }
    let mut patched = stored.clone();
    e.patch(&mut patched, fields)?;
    let updated = update(s, ca, t, &patched).await?;
    crate::data::audit::activity(
        &s.db,
        entity::u64_of(&updated, "clientId"),
        format!("{} Update", t.name()),
        format!("{} updated for appId {}", t.name(), fmt_id(updated.get("appId"))),
        None,
    );
    evict(s, t, &updated).await;
    Ok(updated)
}

/// `delete(id)`.
pub async fn delete(s: &AdminState, ca: &ContextAuth, t: PolicyType, id: u64) -> AuthResult<u64> {
    let e = t.entity();
    let stored = entity::read_by_id(&s.db, e, id).await?;
    if !can_update_policy(s, ca, entity::u64_of(&stored, "appId")).await? {
        return Err(forbidden(t));
    }
    let n = entity::delete(&s.db, e, id).await?;
    crate::data::audit::activity(
        &s.db,
        entity::u64_of(&stored, "clientId"),
        format!("{} Delete", t.name()),
        format!("{} deleted for appId {}", t.name(), fmt_id(stored.get("appId"))),
        None,
    );
    evict(s, t, &stored).await;
    Ok(n)
}

/// `readPageFilter`: the client-check restriction, then the page.
pub async fn page(s: &AdminState, ca: &ContextAuth, t: PolicyType, pageable: &Pageable, cond: Option<&crate::condition::Cond>) -> AuthResult<Value> {
    let e = t.entity();
    let sql = cond.map(|c| crate::condition::to_sql(c, &e.filter)).transpose()?.flatten();
    let (rows, count) = entity::page(&s.db, e, crate::data::crud::client_check(ca), sql, pageable).await?;
    Ok(crate::web::page_of(rows.iter().map(|r| t.to_json(r)).collect(), pageable, count))
}

// ---- routes ----

pub fn router() -> axum::Router<AdminState> {
    let mut r = Router::new();
    for t in [PolicyType::Password, PolicyType::Pin, PolicyType::Otp] {
        r = r
            .route(&format!("{}/codes/policy", t.base()), get(move |st: State<AdminState>, req: Request| codes_policy(t, st, req)))
            .route(
                t.base(),
                get(move |st: State<AdminState>, req: Request| read_page(t, st, req))
                    .post(move |st: State<AdminState>, req: Request| create_route(t, st, req)),
            )
            .route(&format!("{}/query", t.base()), post(move |st: State<AdminState>, req: Request| query(t, st, req)))
            .route(
                &format!("{}/{{id}}", t.base()),
                get(move |st: State<AdminState>, p: Path<String>, req: Request| read(t, st, p, req))
                    .put(move |st: State<AdminState>, p: Path<String>, req: Request| put(t, st, p, req))
                    .patch(move |st: State<AdminState>, p: Path<String>, req: Request| patch_route(t, st, p, req))
                    .delete(move |st: State<AdminState>, p: Path<String>, req: Request| delete_route(t, st, p, req)),
            );
    }
    r
}

/// The route patterns for the metrics label.
fn route(t: PolicyType, suffix: &str) -> &'static str {
    match (t, suffix) {
        (PolicyType::Password, "") => "/api/security/clientPasswordPolicy",
        (PolicyType::Password, "/codes/policy") => "/api/security/clientPasswordPolicy/codes/policy",
        (PolicyType::Password, "/query") => "/api/security/clientPasswordPolicy/query",
        (PolicyType::Password, _) => "/api/security/clientPasswordPolicy/{id}",
        (PolicyType::Pin, "") => "/api/security/clientPinPolicy",
        (PolicyType::Pin, "/codes/policy") => "/api/security/clientPinPolicy/codes/policy",
        (PolicyType::Pin, "/query") => "/api/security/clientPinPolicy/query",
        (PolicyType::Pin, _) => "/api/security/clientPinPolicy/{id}",
        (PolicyType::Otp, "") => "/api/security/clientOtpPolicy",
        (PolicyType::Otp, "/codes/policy") => "/api/security/clientOtpPolicy/codes/policy",
        (PolicyType::Otp, "/query") => "/api/security/clientOtpPolicy/query",
        (PolicyType::Otp, _) => "/api/security/clientOtpPolicy/{id}",
    }
}

async fn start(s: &AdminState, req: Request, protected: bool) -> AuthResult<(In, ContextAuth)> {
    let r = web::read(req).await?;
    let ca = web::ctx(&s.auth, &r, protected).await?;
    Ok((r, ca))
}

async fn codes_policy(t: PolicyType, State(s): State<AdminState>, req: Request) -> Response {
    respond(route(t, "/codes/policy"), async {
        let (r, _) = start(&s, req, false).await?;
        // `Tuples.of(clientCode, appCode)` refuses a null element.
        let client = r.info.client_code().ok_or_else(|| AuthError::internal("t1"))?;
        let app = r.info.app_code().ok_or_else(|| AuthError::internal("t2"))?;
        Ok(match policy_for_codes(&s, t, &client, &app).await? {
            Some(p) => json_resp(&t.to_json(&p)),
            None => web::nothing(),
        })
    }.await)
}

async fn read_page(t: PolicyType, State(s): State<AdminState>, req: Request) -> Response {
    respond(route(t, ""), async {
        let (r, ca) = start(&s, req, true).await?;
        let pageable = Pageable::from_params(&r.params);
        let cond = crate::condition::from_params(&r.params.0);
        Ok(json_resp(&page(&s, &ca, t, &pageable, cond.as_ref()).await?))
    }.await)
}

async fn query(t: PolicyType, State(s): State<AdminState>, req: Request) -> Response {
    respond(route(t, "/query"), async {
        let (r, ca) = start(&s, req, true).await?;
        let (pageable, cond) = web::query_body(&r.body)?;
        Ok(json_resp(&page(&s, &ca, t, &pageable, cond.as_ref()).await?))
    }.await)
}

async fn create_route(t: PolicyType, State(s): State<AdminState>, req: Request) -> Response {
    respond(route(t, ""), async {
        let (r, ca) = start(&s, req, true).await?;
        let body = super::common::object_body(&r.body)?;
        let entity = t.entity().from_body(&body, t.initial())?;
        pre_authorize(&ca, "Authorities.Application_CREATE")?;
        Ok(json_resp(&t.to_json(&create(&s, &ca, t, entity).await?)))
    }.await)
}

async fn read(t: PolicyType, State(s): State<AdminState>, Path(id): Path<String>, req: Request) -> Response {
    respond(route(t, "/{id}"), async {
        let (_, ca) = start(&s, req, true).await?;
        let id = to_u64(&id)?;
        pre_authorize(&ca, "Authorities.Application_READ")?;
        Ok(json_resp(&t.to_json(&entity::read_by_id(&s.db, t.entity(), id).await?)))
    }.await)
}

async fn put(t: PolicyType, State(s): State<AdminState>, Path(id): Path<String>, req: Request) -> Response {
    respond(route(t, "/{id}"), async {
        let (r, ca) = start(&s, req, true).await?;
        let id = to_u64(&id)?;
        let body = super::common::object_body(&r.body)?;
        let mut entity = t.entity().from_body(&body, t.initial())?;
        entity.insert("id".into(), Value::from(id));
        pre_authorize(&ca, "Authorities.Application_UPDATE")?;
        Ok(json_resp(&t.to_json(&update(&s, &ca, t, &entity).await?)))
    }.await)
}

async fn patch_route(t: PolicyType, State(s): State<AdminState>, Path(id): Path<String>, req: Request) -> Response {
    respond(route(t, "/{id}"), async {
        let (r, ca) = start(&s, req, true).await?;
        let id = to_u64(&id)?;
        let body = super::common::object_body(&r.body)?;
        pre_authorize(&ca, "Authorities.Application_UPDATE")?;
        let fields = body.as_object().cloned().unwrap_or_default();
        Ok(json_resp(&t.to_json(&patch(&s, &ca, t, id, &fields).await?)))
    }.await)
}

async fn delete_route(t: PolicyType, State(s): State<AdminState>, Path(id): Path<String>, req: Request) -> Response {
    respond(route(t, "/{id}"), async {
        let (_, ca) = start(&s, req, true).await?;
        let id = to_u64(&id)?;
        pre_authorize(&ca, "Authorities.Application_DELETE")?;
        delete(&s, &ca, t, id).await?;
        Ok(no_content())
    }.await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jackson::pretty;

    #[test]
    fn default_policies_as_java_writes_them() {
        // GET /api/security/clientPinPolicy/codes/policy (SYSTEM, appbuilder) on 2026-10-16.
        assert_eq!(pretty(&PolicyType::Pin.to_json(&PolicyType::Pin.default_policy())), "{\n  \"id\" : 0,\n  \"noFailedAttempts\" : 3,\n  \"length\" : 4\n}");
        let otp = PolicyType::Otp.to_json(&PolicyType::Otp.default_policy());
        let keys: Vec<&str> = otp.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(keys, vec!["id", "noFailedAttempts", "targetType", "length", "expireInterval", "numeric", "alphanumeric"]);
        let pwd = PolicyType::Password.to_json(&PolicyType::Password.default_policy());
        assert_eq!(pwd["passMinLength"], 12);
        assert!(pwd.get("passHistoryCount").is_none());
        assert_eq!(PASSWORD.cols.last().unwrap().prop, "passHistoryCount");
    }

    #[test]
    fn otp_policy_order_observed_on_java() {
        // GET /api/security/clientOtpPolicy/codes/policy (SYSTEM, appbuilder) on 2026-10-16.
        let r = row(json!({"id": 10, "createdAt": 1767700854, "updatedAt": 1767700854, "noFailedAttempts": 5, "userLockTime": 30,
            "targetType": "EMAIL", "isConstant": false, "isNumeric": true, "isAlphanumeric": false, "length": 6,
            "resendSameOtp": false, "noResendAttempts": 3, "expireInterval": 5, "clientId": 1, "appId": 2}));
        let java = "{\n  \"id\" : 10,\n  \"createdAt\" : 1767700854,\n  \"updatedAt\" : 1767700854,\n  \"noFailedAttempts\" : 5,\n  \"targetType\" : \"EMAIL\",\n  \"length\" : 6,\n  \"expireInterval\" : 5,\n  \"numeric\" : true,\n  \"alphanumeric\" : false\n}";
        assert_eq!(pretty(&PolicyType::Otp.to_json(&r)), java);
    }

    #[test]
    fn bodies_and_copies() {
        let t = PolicyType::Otp;
        let e = t.entity().from_body(&json!({"numeric": false, "constant": true, "length": "8", "noFailedAttempts": null}), t.initial()).unwrap();
        assert_eq!((e["isNumeric"].clone(), e["isConstant"].clone(), e["length"].clone()), (json!(false), json!(true), json!(8)));
        assert_eq!(e["noFailedAttempts"], Value::Null);
        let mut existing = t.default_policy();
        t.copy_updatable(&mut existing, &e);
        assert_eq!((existing["noFailedAttempts"].clone(), existing["userLockTime"].clone()), (json!(3), json!(15)));
        assert_eq!(existing["isConstant"], true);
        let mut pin = PolicyType::Pin.default_policy();
        PolicyType::Pin.copy_updatable(&mut pin, &row(json!({"length": 6})));
        assert_eq!(pin["length"], 6);
        assert_eq!(pin["reLoginAfterInterval"], Value::Null);
        let mut pwd = PolicyType::Password.default_policy();
        PolicyType::Password.copy_updatable(&mut pwd, &row(json!({"regex": "x"})));
        assert_eq!(pwd["regex"], "x");
        for t in [PolicyType::Password, PolicyType::Pin, PolicyType::Otp] {
            assert!(!t.name().is_empty() && !t.cache().is_empty());
            for sfx in ["", "/codes/policy", "/query", "/{id}"] {
                assert!(route(t, sfx).starts_with(t.base()));
            }
            assert_eq!(forbidden(t).status(), StatusCode::FORBIDDEN);
        }
        assert_eq!(fmt_id(Some(&json!(4))), "4");
        assert_eq!(fmt_id(None), "null");
    }
}
