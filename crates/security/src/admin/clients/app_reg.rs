//! `AppRegistrationController` and `AppRegistrationServiceV2`: what a client registering on an
//! app is given (app access, departments, designations, file access, profile restrictions, user
//! designations, profiles and roles), one table per object type.
//!
//! | Route | Who |
//! |---|---|
//! | `POST applications/reg/{appCode}/{urlPart}` | signed in, write access to the app, a managed client |
//! | `POST applications/reg/{appCode}/{urlPart}/query` | signed in, write access to the app (SYSTEM: any client it manages) |
//! | `DELETE applications/reg/{urlPart}/{id}` | signed in, as the read by id allows |
//!
//! Each object comes back with its `app` and `client` (through the `Application_READ` and
//! `Client_READ` reads, as Java's proxied calls are) and the objects its ids name.

use std::future::Future;
use std::pin::Pin;

use axum::http::StatusCode;
use axum::routing::post;
use axum::Router;
use serde_json::{json, Value};

use crate::web::page_of;
use super::common::{bare, bool_json, err, object_body, pre_authorize, Kind, CLIENT_CODE_OR_ID_ONLY_ONE, FORBIDDEN_APP_REG_OBJECTS};
use super::entity::{self, col, extra, prim, Col, Entity, Row, CREATED_AT, CREATED_BY, ID};
use crate::admin::AdminState;
use crate::condition::{ColType, Table};
use crate::errors::{AuthError, AuthResult};
use crate::jackson::json as json_resp;
use crate::model::ContextAuth;
use crate::spring::Pageable;
use crate::web::{self, to_u64};
use crate::web_route_path2;

/// `ClientLevelType`, in declaration order (Jackson reads an index too).
pub const LEVELS: &[&str] = &["CONSUMER", "CUSTOMER", "CLIENT", "OWNER"];

/// Who resolves an id an object names (`ExtraValues.helperServiceClass`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Helper {
    App,
    /// `AppRegistrationServiceV2` itself: read with the object's own type.
    Reg,
    Profile,
    Role,
}

/// `AppRegistrationObjectType`.
pub struct RegType {
    pub url_part: &'static str,
    pub entity: Entity,
    /// (id property, object property, helper) per `ExtraValues`.
    pub extras: &'static [(&'static str, &'static str, Helper)],
    /// Whether the object property's setter accepts what the helper reads (Java looks the setter
    /// up by the filler's class: a type mismatch leaves it unset).
    pub settable: &'static [&'static str],
}

macro_rules! base_cols {
    ($($rest:expr),* $(,)?) => {
        [
            ID,
            CREATED_AT,
            CREATED_BY,
            col("clientId", "CLIENT_ID", Kind::U64, true),
            col("appId", "APP_ID", Kind::U64, true),
            col("clientType", "CLIENT_TYPE", Kind::Str, true),
            col("level", "LEVEL", Kind::Enum(LEVELS), true),
            col("businessType", "BUSINESS_TYPE", Kind::Str, true),
            extra("client", Kind::Json),
            extra("app", Kind::Json),
            $($rest),*
        ]
    };
}

const BASE_FILTER: [(&str, ColType); 8] = [
    ("ID", ColType::Num),
    ("CLIENT_ID", ColType::Num),
    ("CLIENT_TYPE", ColType::Str),
    ("APP_ID", ColType::Num),
    ("LEVEL", ColType::Enum),
    ("BUSINESS_TYPE", ColType::Str),
    ("CREATED_BY", ColType::Num),
    ("CREATED_AT", ColType::Ts),
];

const BASE_SETTERS: [(&str, &str); 7] = [
    ("clientId", "clientId"),
    ("appId", "appId"),
    ("clientType", "clientType"),
    ("level", "level"),
    ("businessType", "businessType"),
    ("client", "client"),
    ("app", "app"),
];

static ACCESS_COLS: [Col; 14] = base_cols![
    col("allowAppId", "ALLOW_APP_ID", Kind::U64, true),
    prim("writeAccess", "WRITE_ACCESS", Kind::Bool),
    prim("register", "REGISTER", Kind::Bool),
    extra("allowApp", Kind::Json),
];
static DEPARTMENT_COLS: [Col; 14] = base_cols![
    col("name", "NAME", Kind::Str, true),
    col("description", "DESCRIPTION", Kind::Str, false),
    col("parentDepartmentId", "PARENT_DEPARTMENT_ID", Kind::U64, false),
    extra("parentDepartment", Kind::Json),
];
static DESIGNATION_COLS: [Col; 18] = base_cols![
    col("name", "NAME", Kind::Str, true),
    col("description", "DESCRIPTION", Kind::Str, false),
    col("departmentId", "DEPARTMENT_ID", Kind::U64, false),
    col("parentDesignationId", "PARENT_DESIGNATION_ID", Kind::U64, false),
    col("nextDesignationId", "NEXT_DESIGNATION_ID", Kind::U64, false),
    extra("department", Kind::Json),
    extra("parentDesignation", Kind::Json),
    extra("nextDesignation", Kind::Json),
];
static FILE_COLS: [Col; 15] = base_cols![
    col("resourceType", "RESOURCE_TYPE", Kind::Str, true),
    col("accessName", "ACCESS_NAME", Kind::Str, true),
    prim("writeAccess", "WRITE_ACCESS", Kind::Bool),
    col("path", "PATH", Kind::Str, true),
    prim("allowSubPathAccess", "ALLOW_SUB_PATH_ACCESS", Kind::Bool),
];
static PROFILE_COLS: [Col; 12] = base_cols![col("profileId", "PROFILE_ID", Kind::U64, true), extra("profile", Kind::Json)];
static USER_DESIGNATION_COLS: [Col; 12] = base_cols![col("designationId", "DESIGNATION_ID", Kind::U64, true), extra("designation", Kind::Json)];
static ROLE_COLS: [Col; 12] = base_cols![col("roleId", "ROLE_ID", Kind::U64, true), extra("role", Kind::Json)];

fn leak<T: Copy>(parts: &[&[T]]) -> &'static [T] {
    Box::leak(parts.iter().flat_map(|p| p.iter().copied()).collect::<Vec<_>>().into_boxed_slice())
}

fn reg_entity(pojo: &'static str, table: &'static str, cols: &'static [Col], setters: &[(&'static str, &'static str)], filter: &[(&'static str, ColType)]) -> Entity {
    Entity {
        pojo,
        table,
        cols,
        setters: leak(&[&BASE_SETTERS, setters]),
        aliases: &[],
        filter: Table { name: table, columns: leak(&[&BASE_FILTER, filter]) },
        client_column: None,
    }
}

/// Every type, as `AppRegistrationObjectType.values()` lists them.
pub static TYPES: std::sync::LazyLock<Vec<RegType>> = std::sync::LazyLock::new(|| {
    vec![
        RegType {
            url_part: "appAccess",
            entity: reg_entity(
                "AppRegistrationAccess",
                "security_app_reg_access",
                &ACCESS_COLS,
                &[("allowAppId", "allowAppId"), ("writeAccess", "writeAccess"), ("register", "register"), ("allowApp", "allowApp")],
                &[("ALLOW_APP_ID", ColType::Num), ("WRITE_ACCESS", ColType::Num), ("REGISTER", ColType::Num)],
            ),
            extras: &[("allowAppId", "allowApp", Helper::App)],
            settable: &["allowApp"],
        },
        RegType {
            url_part: "department",
            entity: reg_entity(
                "AppRegistrationDepartment",
                "security_app_reg_department",
                &DEPARTMENT_COLS,
                &[("name", "name"), ("description", "description"), ("parentDepartmentId", "parentDepartmentId"), ("parentDepartment", "parentDepartment")],
                &[("NAME", ColType::Str), ("DESCRIPTION", ColType::Str), ("PARENT_DEPARTMENT_ID", ColType::Num)],
            ),
            extras: &[("parentDepartmentId", "parentDepartment", Helper::Reg)],
            settable: &["parentDepartment"],
        },
        RegType {
            url_part: "designation",
            entity: reg_entity(
                "AppRegistrationDesignation",
                "security_app_reg_designation",
                &DESIGNATION_COLS,
                &[
                    ("name", "name"),
                    ("description", "description"),
                    ("departmentId", "departmentId"),
                    ("parentDesignationId", "parentDesignationId"),
                    ("nextDesignationId", "nextDesignationId"),
                    ("department", "department"),
                    ("parentDesignation", "parentDesignation"),
                    ("nextDesignation", "nextDesignation"),
                ],
                &[
                    ("NAME", ColType::Str),
                    ("DESCRIPTION", ColType::Str),
                    ("DEPARTMENT_ID", ColType::Num),
                    ("PARENT_DESIGNATION_ID", ColType::Num),
                    ("NEXT_DESIGNATION_ID", ColType::Num),
                ],
            ),
            // The department is read with the designation's own type, so its setter never takes it.
            extras: &[
                ("parentDesignationId", "parentDesignation", Helper::Reg),
                ("nextDesignationId", "nextDesignation", Helper::Reg),
                ("departmentId", "department", Helper::Reg),
            ],
            settable: &["parentDesignation", "nextDesignation"],
        },
        RegType {
            url_part: "fileAccess",
            entity: reg_entity(
                "AppRegistrationFileAccess",
                "security_app_reg_file_access",
                &FILE_COLS,
                &[
                    ("resourceType", "resourceType"),
                    ("accessName", "accessName"),
                    ("writeAccess", "writeAccess"),
                    ("path", "path"),
                    ("allowSubPathAccess", "allowSubPathAccess"),
                ],
                &[
                    ("RESOURCE_TYPE", ColType::Enum),
                    ("ACCESS_NAME", ColType::Str),
                    ("WRITE_ACCESS", ColType::Num),
                    ("PATH", ColType::Str),
                    ("ALLOW_SUB_PATH_ACCESS", ColType::Num),
                ],
            ),
            extras: &[],
            settable: &[],
        },
        RegType {
            url_part: "profileRestriction",
            entity: reg_entity(
                "AppRegistrationProfileRestriction",
                "security_app_reg_profile_restriction",
                &PROFILE_COLS,
                &[("profileId", "profileId"), ("profile", "profile")],
                &[("PROFILE_ID", ColType::Num)],
            ),
            extras: &[("profileId", "profile", Helper::Profile)],
            settable: &["profile"],
        },
        RegType {
            url_part: "userDesignation",
            entity: reg_entity(
                "AppRegistrationUserDesignation",
                "security_app_reg_user_designation",
                &USER_DESIGNATION_COLS,
                &[("designationId", "designationId"), ("designation", "designation")],
                &[("DESIGNATION_ID", ColType::Num)],
            ),
            // Read with the user designation's own type: the setter never takes it.
            extras: &[("designationId", "designation", Helper::Reg)],
            settable: &[],
        },
        RegType {
            url_part: "userProfile",
            entity: reg_entity(
                "AppRegistrationUserProfile",
                "security_app_reg_user_profile",
                &PROFILE_COLS,
                &[("profileId", "profileId"), ("profile", "profile")],
                &[("PROFILE_ID", ColType::Num)],
            ),
            extras: &[("profileId", "profile", Helper::Profile)],
            settable: &["profile"],
        },
        RegType {
            url_part: "userRole",
            entity: reg_entity(
                "AppRegistrationUserRole",
                "security_app_reg_user_role_v2",
                &ROLE_COLS,
                &[("roleId", "roleId"), ("role", "role")],
                &[("ROLE_ID", ColType::Num)],
            ),
            extras: &[("roleId", "role", Helper::Role)],
            settable: &["role"],
        },
    ]
});

/// `AppRegistrationObjectType.fromUrlPart`.
pub fn reg_type(url_part: &str) -> Option<&'static RegType> {
    TYPES.iter().find(|t| t.url_part == url_part)
}

/// `AbstractAppRegistration`'s field initializers.
fn initial() -> Row {
    json!({"businessType": "COMMON", "writeAccess": false, "register": false, "allowSubPathAccess": false})
        .as_object()
        .cloned()
        .unwrap_or_default()
}

fn refused() -> AuthError {
    err(StatusCode::FORBIDDEN, FORBIDDEN_APP_REG_OBJECTS, &["App Access"])
}

/// `AppRegistrationV2DAO.getById`.
async fn by_id(s: &AdminState, t: &RegType, id: u64) -> AuthResult<Option<Row>> {
    entity::by_id(&s.db, &t.entity, id).await
}

/// `RoleV2Service.readObject`: the role row (the DAO's 404 when missing).
async fn role_json(s: &AdminState, id: u64) -> AuthResult<Value> {
    let row: Option<sqlx::mysql::MySqlRow> = sqlx::query("SELECT * FROM security_v2_role WHERE ID = ? LIMIT 1").bind(id).fetch_optional(&s.db.pool).await?;
    let Some(r) = row else { return Err(err(StatusCode::NOT_FOUND, super::common::OBJECT_NOT_FOUND, &["RoleV2", &id.to_string()])) };
    use sqlx::Row as _;
    let ts = |c: &str| -> AuthResult<Value> { Ok(crate::mysql::ts(&r, c)?.map(|t| Value::from(t.and_utc().timestamp())).unwrap_or(Value::Null)) };
    Ok(crate::jackson::Obj::new()
        .put("id", r.try_get::<u64, _>("ID")?)
        .put("createdAt", ts("CREATED_AT")?)
        .put("createdBy", crate::jackson::opt(r.try_get::<Option<u64>, _>("CREATED_BY")?))
        .put("updatedAt", ts("UPDATED_AT")?)
        .put("updatedBy", crate::jackson::opt(r.try_get::<Option<u64>, _>("UPDATED_BY")?))
        .put("clientId", r.try_get::<u64, _>("CLIENT_ID")?)
        .put("appId", crate::jackson::opt(r.try_get::<Option<u64>, _>("APP_ID")?))
        .put("name", crate::jackson::opt(r.try_get::<Option<String>, _>("NAME")?))
        .put("shortName", crate::jackson::opt(r.try_get::<Option<String>, _>("SHORT_NAME")?))
        .put("description", crate::jackson::opt(r.try_get::<Option<String>, _>("DESCRIPTION")?))
        .build())
}

/// `ProfileService.readObject`: the profile as the caller's hierarchy sees it (piece 1's
/// `ProfileDAO.read`, with its root merged).
async fn profile_json(s: &AdminState, ca: &ContextAuth, id: u64) -> AuthResult<Option<Value>> {
    Ok(Some(s.profile_read_object(ca, id).await?.to_json()))
}

/// `IAppRegistrationHelperService.hasAccessTo(id, clientId, type)`: `None` when it has no answer
/// (an object that is not there).
async fn has_access_to(s: &AdminState, t: &RegType, helper: Helper, id: u64, client_id: u64) -> AuthResult<Option<bool>> {
    match helper {
        Helper::App => Ok(Some(super::dao::has_access_by_id(&s.db.pool, id, Some(client_id), true).await?)),
        Helper::Reg => Ok(by_id(s, t, id).await?.map(|r| entity::u64_of(&r, "clientId") == Some(client_id))),
        Helper::Role => {
            let role = role_json(s, id).await?;
            let owner = role["clientId"].as_u64().unwrap_or(0);
            Ok(Some(s.is_client_being_managed_by(owner, client_id).await? || s.is_client_being_managed_by(client_id, owner).await?))
        }
        Helper::Profile => {
            let owner: Option<u64> = sqlx::query_scalar("SELECT CLIENT_ID FROM security_profile WHERE ID = ? LIMIT 1").bind(id).fetch_optional(&s.db.pool).await?;
            let Some(owner) = owner else { return Ok(None) };
            Ok(Some(s.is_client_being_managed_by(owner, client_id).await? || s.is_client_being_managed_by(client_id, owner).await?))
        }
    }
}

/// `hasAccessToInnerIds`: every id the object names must be the client's to use; `false` also
/// when none could be answered (Java's empty reduce).
async fn has_access_to_inner_ids(s: &AdminState, t: &RegType, client_id: u64, r: &Row) -> AuthResult<bool> {
    if t.extras.is_empty() {
        return Ok(true);
    }
    let mut answers = Vec::new();
    for (id_prop, _, helper) in t.extras {
        match entity::u64_of(r, id_prop) {
            None => answers.push(true),
            Some(id) => {
                if let Some(b) = has_access_to(s, t, *helper, id, client_id).await? {
                    answers.push(b);
                }
            }
        }
    }
    Ok(!answers.is_empty() && answers.iter().all(|b| *b))
}

type Filled<'a> = Pin<Box<dyn Future<Output = AuthResult<Row>> + Send + 'a>>;

/// `fillObjects`: the objects the ids name, then `app` and `client` through their proxied reads.
fn fill<'a>(s: &'a AdminState, ca: &'a ContextAuth, t: &'static RegType, mut r: Row) -> Filled<'a> {
    Box::pin(async move {
        for (id_prop, obj_prop, helper) in t.extras {
            let Some(id) = entity::u64_of(&r, id_prop) else { continue };
            let obj = match helper {
                Helper::App => Some(super::apps::json_of(&super::apps::read(s, id).await?)),
                Helper::Role => Some(role_json(s, id).await?),
                Helper::Profile => profile_json(s, ca, id).await?,
                Helper::Reg => match get_by_id(s, ca, t, id).await? {
                    Some(o) => Some(t.entity.to_json(&o, vec![])),
                    None => None,
                },
            };
            if let Some(o) = obj.filter(|_| t.settable.contains(obj_prop)) {
                r.insert((*obj_prop).to_string(), o);
            }
        }
        pre_authorize(ca, "Authorities.Application_READ")?;
        let app = super::apps::read(s, entity::u64_of(&r, "appId").unwrap_or(0)).await?;
        pre_authorize(ca, "Authorities.Client_READ")?;
        let client = super::client_admin::read(s, ca, entity::u64_of(&r, "clientId").unwrap_or(0)).await?;
        r.insert("app".into(), super::apps::json_of(&app));
        r.insert("client".into(), super::client_admin::row_json(&client));
        Ok(r)
    })
}

/// `getById(type, id)`: the object when the caller may see it (SYSTEM always).
pub async fn get_by_id(s: &AdminState, ca: &ContextAuth, t: &'static RegType, id: u64) -> AuthResult<Option<Row>> {
    let Some(r) = by_id(s, t, id).await? else { return Ok(None) };
    if !ca.is_system_client() {
        let own = ca.user.client_id();
        let app = entity::u64_of(&r, "appId").unwrap_or(0);
        if !super::dao::has_access_by_id(&s.db.pool, app, Some(own), true).await? {
            return Ok(None);
        }
        if !has_access_to_inner_ids(s, t, own, &r).await? {
            return Ok(None);
        }
        if !s.caller_manages_client(ca, entity::u64_of(&r, "clientId").unwrap_or(0)).await? {
            return Ok(None);
        }
    }
    Ok(Some(fill(s, ca, t, r).await?))
}

/// `create(type, appCode, entity)`.
pub async fn create(s: &AdminState, ca: &ContextAuth, t: &'static RegType, app_code: &str, mut entity: Row) -> AuthResult<Value> {
    let Some(app) = s.dir().app_by_code(app_code).await? else { return Err(refused()) };
    if !s.db.has_write_access(app_code, ca.client_code.as_deref().unwrap_or("")).await? {
        return Err(refused());
    }
    let own = ca.user.client_id();
    if !has_access_to_inner_ids(s, t, own, &entity).await? {
        return Err(refused());
    }
    entity.insert("appId".into(), Value::from(app.id));
    entity.insert("createdBy".into(), Value::from(ca.user.id()));
    // `LocalDateTime.now()`: the server's wall time, written as it is.
    entity.insert("createdAt".into(), Value::from(s.auth.clock.local().and_utc().timestamp()));
    match entity::u64_of(&entity, "clientId") {
        None => {
            entity.insert("clientId".into(), Value::from(own));
        }
        // A SYSTEM caller is checked too: Java's `Mono.just(true)` there is never returned.
        Some(c) => {
            if !s.caller_manages_client(ca, c).await? {
                return Err(refused());
            }
        }
    }
    let id = entity::insert(&s.db, &t.entity, &entity).await?;
    let created = by_id(s, t, id).await?.ok_or_else(|| t.entity.not_found(id))?;
    Ok(t.entity.to_json(&fill(s, ca, t, created).await?, vec![]))
}

/// The query body (`AppRegistrationQuery`).
pub struct RegQuery {
    pub client_code: Option<String>,
    pub client_id: Option<u64>,
    pub client_type: Option<String>,
    pub level: Option<String>,
    pub business_type: Option<String>,
    pub page: Option<i64>,
    pub size: Option<i64>,
}

pub fn reg_query(body: &Value) -> AuthResult<RegQuery> {
    use super::common::{prop, prop_i64, prop_str, prop_u64};
    Ok(RegQuery {
        client_code: prop_str(body, "clientCode")?,
        client_id: prop_u64(body, "clientId")?,
        client_type: prop_str(body, "clientType")?,
        level: prop(body, "level", Kind::Enum(LEVELS))?.as_str().map(str::to_string),
        business_type: prop_str(body, "businessType")?,
        page: prop_i64(body, "page")?,
        size: prop_i64(body, "size")?,
    })
}

/// `get(type, appCode, clientCode, clientId, clientType, level, businessType, pageable)`: `None`
/// for an unknown app or a caller without write access.
pub async fn page(s: &AdminState, ca: &ContextAuth, t: &'static RegType, app_code: &str, q: &RegQuery) -> AuthResult<Option<Value>> {
    let npe = |which: &str| AuthError::internal(format!("Cannot invoke \"java.lang.Integer.intValue()\" because the return value of \"com.fincity.security.model.AppRegistrationQuery.{which}()\" is null"));
    let page = q.page.ok_or_else(|| npe("getPage"))?;
    let size = q.size.ok_or_else(|| npe("getSize"))?;
    if page < 0 {
        return Err(AuthError::internal("Page index must not be less than zero"));
    }
    if size < 1 {
        return Err(AuthError::internal("Page size must not be less than one"));
    }
    let pageable = Pageable::of(page, size, vec![]);
    if q.client_code.is_some() && q.client_id.is_some() {
        return Err(err(StatusCode::BAD_REQUEST, CLIENT_CODE_OR_ID_ONLY_ONE, &[]));
    }
    let Some(app) = s.dir().app_by_code(app_code).await? else { return Ok(None) };
    if !ca.is_system_client() && !s.db.has_write_access(app_code, ca.client_code.as_deref().unwrap_or("")).await? {
        return Ok(None);
    }
    let client_id = if !ca.is_system_client() || (q.client_id.is_none() && q.client_code.is_none()) {
        ca.user.client_id()
    } else {
        let id = match &q.client_code {
            Some(code) => match s.client_by_code(code).await? {
                Some(c) => c.id(),
                None => return Ok(None),
            },
            None => q.client_id.unwrap_or(0),
        };
        if !s.caller_manages_client(ca, id).await? {
            return Ok(None);
        }
        id
    };
    let mut cond = crate::condition::Sql::text(format!("({}.APP_ID = ", t.entity.table));
    cond.push_bind(crate::condition::Bind::U64(app.id));
    cond.push_text(format!(" AND {}.CLIENT_ID = ", t.entity.table));
    cond.push_bind(crate::condition::Bind::U64(client_id));
    for (column, v) in [("CLIENT_TYPE", &q.client_type), ("LEVEL", &q.level), ("BUSINESS_TYPE", &q.business_type)] {
        if let Some(v) = v {
            cond.push_text(format!(" AND {}.{column} = ", t.entity.table));
            cond.push_bind(crate::condition::Bind::Str(v.clone()));
        }
    }
    cond.push_text(")");
    let select = |what: &str| {
        let mut qb = sqlx::QueryBuilder::<sqlx::MySql>::new(format!("SELECT {what} FROM {} WHERE ", t.entity.table));
        cond.push_to(&mut qb);
        qb
    };
    let mut q1 = select(&t.entity.select_list());
    q1.push(format!(" ORDER BY {}.CREATED_AT DESC LIMIT ", t.entity.table)).push_bind(pageable.size).push(" OFFSET ").push_bind(pageable.offset());
    let rows = q1.build().fetch_all(&s.db.pool).await?;
    let count: i64 = select("COUNT(*)").build_query_scalar().fetch_one(&s.db.pool).await?;
    let mut content = Vec::with_capacity(rows.len());
    for r in &rows {
        let row = t.entity.read_row(r)?;
        content.push(t.entity.to_json(&fill(s, ca, t, row).await?, vec![]));
    }
    if content.is_empty() {
        return Ok(Some(page_of(vec![], &pageable, 0)));
    }
    Ok(Some(page_of(content, &pageable, count)))
}

/// `delete(type, id)`: `None` when the read by id finds nothing the caller may see.
pub async fn delete_object(s: &AdminState, ca: &ContextAuth, t: &'static RegType, id: u64) -> AuthResult<Option<bool>> {
    if get_by_id(s, ca, t, id).await?.is_none() {
        return Ok(None);
    }
    Ok(Some(entity::delete(&s.db, &t.entity, id).await? > 0))
}

pub fn router() -> Router<AdminState> {
    Router::new()
        // `{appCode}/{urlPart}` (POST) and `{urlPart}/{id}` (DELETE) are one shape to the router.
        .route("/api/security/applications/reg/{first}/{second}", post(create_route).delete(delete_route))
        .route("/api/security/applications/reg/{appCode}/{urlPart}/query", post(query_route))
}

web_route_path2!(create_route, AdminState, "/applications/reg/{appCode}/{urlPart}", true, |s, r, ca, app, part| {
    let body = object_body(&r.body)?;
    let Some(t) = reg_type(&part) else { return Ok(bare(StatusCode::BAD_REQUEST)) };
    // `mapper.convertValue(map, pojoClass)`: a value that does not convert is Jackson's
    // IllegalArgumentException, a 500.
    let entity = t.entity.from_body(&body, initial()).map_err(|_| AuthError::internal("Cannot deserialize value"))?;
    Ok(json_resp(&create(&s, &ca, t, &app, entity).await?))
});

web_route_path2!(query_route, AdminState, "/applications/reg/{appCode}/{urlPart}/query", true, |s, r, ca, app, part| {
    let body = object_body(&r.body)?;
    let q = reg_query(&body)?;
    let Some(t) = reg_type(&part) else { return Ok(bare(StatusCode::BAD_REQUEST)) };
    Ok(match page(&s, &ca, t, &app, &q).await? {
        Some(v) => json_resp(&v),
        None => web::nothing(),
    })
});

web_route_path2!(delete_route, AdminState, "/applications/reg/{urlPart}/{id}", true, |s, r, ca, part, id| {
    let id = to_u64(&id)?;
    let Some(t) = reg_type(&part) else { return Ok(bare(StatusCode::BAD_REQUEST)) };
    Ok(match delete_object(&s, &ca, t, id).await? {
        Some(b) => bool_json(b),
        None => web::nothing(),
    })
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn types_and_shapes() {
        let parts: Vec<&str> = TYPES.iter().map(|t| t.url_part).collect();
        assert_eq!(parts, vec!["appAccess", "department", "designation", "fileAccess", "profileRestriction", "userDesignation", "userProfile", "userRole"]);
        assert!(reg_type("nope").is_none());
        let t = reg_type("appAccess").unwrap();
        let r = t.entity.from_body(&json!({"allowAppId": 5, "level": 2, "clientType": "BUS"}), initial()).unwrap();
        let v = t.entity.to_json(&r, vec![]);
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(keys, vec!["clientType", "level", "businessType", "allowAppId", "writeAccess", "register"]);
        assert_eq!(v["level"], "CLIENT");
        assert!(reg_type("designation").unwrap().entity.filter.columns.iter().any(|(c, _)| *c == "NEXT_DESIGNATION_ID"));
        assert!(reg_type("userDesignation").unwrap().settable.is_empty());
        assert_eq!(refused().status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn queries() {
        let q = reg_query(&json!({"clientCode": "A", "level": "OWNER", "page": 0, "size": 5})).unwrap();
        assert_eq!((q.client_code.as_deref(), q.level.as_deref(), q.page, q.size), (Some("A"), Some("OWNER"), Some(0), Some(5)));
        assert!(reg_query(&json!({"level": "X"})).is_err());
    }
}
