//! `DesignationController` / `DesignationService` and `DepartmentController` /
//! `DepartmentService`: a client's designations and departments, `Client_CREATE` or
//! `Client_UPDATE` for every route, client-check reads, names unique per client.

use std::sync::Arc;

use axum::http::StatusCode;
use axum::routing::get;
use axum::Router;
use serde_json::{Map, Value};

use super::common::{not_found, object_body, page_response, patch_error, pre_authorize, refuse, string_value, u64_value, ulong_patch_failure, Fields};
use crate::admin::{Admin, AdminState};
use crate::caches;
use crate::condition::{from_params, to_sql};
use crate::data::audit;
use crate::data::crud::{client_check, Entity};
use crate::data::org::{department, department_values, designation, designation_values, DEPARTMENT, DESIGNATION};
use crate::dto::{designation_json, Department, Designation, DesignationExtras};
use crate::errors::{AuthError, AuthResult};
use crate::jackson::json;
use crate::model::ContextAuth;
use crate::spring::{safe_bool, Pageable, Params};
use crate::web::{no_content_json, query_body, to_u64};

const ORG_AUTHORITIES: &[&str] = &["Authorities.Client_CREATE", "Authorities.Client_UPDATE"];
/// Java names its own class as the message key here: not in the bundle, so the unknown-key text.
const UNKNOWN_KEY: &str = "Designation";

/// A designation or a department: what the two services do alike.
trait OrgKind: Sized {
    const CLASS: &'static str;
    const ENTITY: &'static Entity;
    const CACHE: &'static str;
    /// The status of an update that was not allowed (Designation: 404, Department: 403).
    const UPDATE_REFUSED: StatusCode;
    fn from_row(r: &sqlx::mysql::MySqlRow) -> AuthResult<Self>;
    fn values(&self) -> Vec<(&'static str, crate::condition::Bind)>;
    fn id(&self) -> u64;
    fn client_id(&self) -> Option<u64>;
    fn name(&self) -> Option<&str>;
    fn set_name(&mut self, n: String);
    fn set_client_id(&mut self, c: u64);
    /// `AbstractUpdatableDAO.update` clears it, so the column's `ON UPDATE` sets it.
    fn clear_updated_at(&mut self);
    /// The body as the DTO.
    fn from_body(f: &Fields<'_>) -> AuthResult<Self>;
    /// `updatableEntity`: the stored row with the editable fields taken from `from`.
    fn take_editable(&mut self, from: &Self);
    /// The setters the PATCH reflection finds (the class's own fields).
    fn patch(&mut self, fields: &Map<String, Value>) -> AuthResult<()>;
    /// `checkSameClient`.
    async fn same_client(&self, s: &Admin) -> AuthResult<bool>;
}

fn patch_u64(fields: &Map<String, Value>, k: &str, slot: &mut Option<u64>) -> AuthResult<()> {
    if let Some(v) = fields.get(k) {
        *slot = u64_value(Some(v)).map_err(|_| ulong_patch_failure())?;
    }
    Ok(())
}

fn patch_str(fields: &Map<String, Value>, k: &str, slot: &mut Option<String>) -> AuthResult<()> {
    if let Some(v) = fields.get(k) {
        *slot = string_value(Some(v)).map_err(|_| patch_error(k))?;
    }
    Ok(())
}

/// A nested object property (`parentDesignation`, ...): only its conversion can fail.
fn patch_object(fields: &Map<String, Value>, k: &str) -> AuthResult<()> {
    match fields.get(k) {
        None | Some(Value::Null) | Some(Value::Object(_)) => Ok(()),
        Some(_) => Err(patch_error(k)),
    }
}

impl OrgKind for Designation {
    const CLASS: &'static str = "Designation";
    const ENTITY: &'static Entity = &DESIGNATION;
    const CACHE: &'static str = caches::DESIGNATION;
    const UPDATE_REFUSED: StatusCode = StatusCode::NOT_FOUND;

    fn from_row(r: &sqlx::mysql::MySqlRow) -> AuthResult<Self> {
        designation(r)
    }
    fn values(&self) -> Vec<(&'static str, crate::condition::Bind)> {
        designation_values(self)
    }
    fn id(&self) -> u64 {
        self.id
    }
    fn client_id(&self) -> Option<u64> {
        self.client_id
    }
    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
    fn set_name(&mut self, n: String) {
        self.name = Some(n);
    }
    fn set_client_id(&mut self, c: u64) {
        self.client_id = Some(c);
    }
    fn clear_updated_at(&mut self) {
        self.updated_at = None;
    }
    fn from_body(f: &Fields<'_>) -> AuthResult<Self> {
        Ok(Designation {
            id: f.u64("id")?.unwrap_or(0),
            client_id: f.u64("clientId")?,
            name: f.string("name")?,
            description: f.string("description")?,
            parent_designation_id: f.u64("parentDesignationId")?,
            department_id: f.u64("departmentId")?,
            next_designation_id: f.u64("nextDesignationId")?,
            profile_id: f.u64("profileId")?,
            created_by: f.u64("createdBy")?,
            created_at: f.ts("createdAt")?,
            updated_by: f.u64("updatedBy")?,
            updated_at: f.ts("updatedAt")?,
        })
    }
    fn take_editable(&mut self, from: &Self) {
        self.name = from.name.clone();
        self.description = from.description.clone();
        self.department_id = from.department_id;
        self.parent_designation_id = from.parent_designation_id;
        self.next_designation_id = from.next_designation_id;
    }
    fn patch(&mut self, fields: &Map<String, Value>) -> AuthResult<()> {
        patch_u64(fields, "clientId", &mut self.client_id)?;
        patch_str(fields, "name", &mut self.name)?;
        patch_str(fields, "description", &mut self.description)?;
        patch_u64(fields, "parentDesignationId", &mut self.parent_designation_id)?;
        patch_u64(fields, "departmentId", &mut self.department_id)?;
        patch_u64(fields, "nextDesignationId", &mut self.next_designation_id)?;
        patch_u64(fields, "profileId", &mut self.profile_id)?;
        for k in ["parentDesignation", "nextDesignation", "department"] {
            patch_object(fields, k)?;
        }
        Ok(())
    }
    async fn same_client(&self, s: &Admin) -> AuthResult<bool> {
        // Java checks the parent and next designations only when a department is given.
        if self.department_id.is_none() {
            return Ok(true);
        }
        for (table, id) in [
            ("security_designation", self.parent_designation_id),
            ("security_designation", self.next_designation_id),
            ("security_department", self.department_id),
        ] {
            if let Some(id) = id {
                if !s.db.org_in_client(table, id, self.client_id).await? {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
}

impl OrgKind for Department {
    const CLASS: &'static str = "Department";
    const ENTITY: &'static Entity = &DEPARTMENT;
    const CACHE: &'static str = caches::DEPARTMENT;
    const UPDATE_REFUSED: StatusCode = StatusCode::FORBIDDEN;

    fn from_row(r: &sqlx::mysql::MySqlRow) -> AuthResult<Self> {
        department(r)
    }
    fn values(&self) -> Vec<(&'static str, crate::condition::Bind)> {
        department_values(self)
    }
    fn id(&self) -> u64 {
        self.id
    }
    fn client_id(&self) -> Option<u64> {
        self.client_id
    }
    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
    fn set_name(&mut self, n: String) {
        self.name = Some(n);
    }
    fn set_client_id(&mut self, c: u64) {
        self.client_id = Some(c);
    }
    fn clear_updated_at(&mut self) {
        self.updated_at = None;
    }
    fn from_body(f: &Fields<'_>) -> AuthResult<Self> {
        Ok(Department {
            id: f.u64("id")?.unwrap_or(0),
            client_id: f.u64("clientId")?,
            name: f.string("name")?,
            description: f.string("description")?,
            parent_department_id: f.u64("parentDepartmentId")?,
            created_by: f.u64("createdBy")?,
            created_at: f.ts("createdAt")?,
            updated_by: f.u64("updatedBy")?,
            updated_at: f.ts("updatedAt")?,
        })
    }
    fn take_editable(&mut self, from: &Self) {
        self.name = from.name.clone();
        self.description = from.description.clone();
        self.parent_department_id = from.parent_department_id;
    }
    fn patch(&mut self, fields: &Map<String, Value>) -> AuthResult<()> {
        patch_u64(fields, "clientId", &mut self.client_id)?;
        patch_str(fields, "name", &mut self.name)?;
        patch_str(fields, "description", &mut self.description)?;
        patch_u64(fields, "parentDepartmentId", &mut self.parent_department_id)?;
        patch_object(fields, "parentDepartment")
    }
    async fn same_client(&self, s: &Admin) -> AuthResult<bool> {
        match self.parent_department_id {
            None => Ok(true),
            Some(p) => s.db.org_in_client("security_department", p, self.client_id).await,
        }
    }
}

/// The unknown-key refusal these services raise when a check comes up empty.
fn refused(status: StatusCode) -> AuthError {
    refuse(status, UNKNOWN_KEY, &[])
}

/// `checkName`: the trimmed name, 400 when blank, 409 when the client has it already.
async fn check_name<K: OrgKind>(s: &Admin, client_id: Option<u64>, name: Option<&str>, id: Option<u64>) -> AuthResult<String> {
    let trimmed = name.unwrap_or("").trim().to_string();
    if trimmed.is_empty() {
        return Err(refuse(StatusCode::BAD_REQUEST, "name_mandatory", &[K::CLASS]));
    }
    if s.db.org_name_taken(K::ENTITY.table.name, client_id, &trimmed, id).await? {
        return Err(refuse(StatusCode::CONFLICT, "name_taken", &[K::CLASS, &trimmed]));
    }
    Ok(trimmed)
}

async fn read<K: OrgKind>(s: &Admin, ca: &ContextAuth, id: u64) -> AuthResult<K> {
    pre_authorize(ca, ORG_AUTHORITIES)?;
    let row = s.db.entity_by_id(K::ENTITY, client_check(ca), id).await?;
    row.as_ref().map(K::from_row).transpose()?.ok_or_else(|| not_found(K::CLASS, id))
}

/// The row as `AbstractDAO.create` and `update` read it back (no joins).
async fn reread<K: OrgKind>(s: &Admin, id: u64) -> AuthResult<K> {
    let sql = format!("SELECT * FROM {} WHERE ID = ? LIMIT 1", K::ENTITY.table.name);
    let row = sqlx::query(&sql).bind(id).fetch_optional(&s.db.pool).await?;
    row.as_ref().map(K::from_row).transpose()?.ok_or_else(|| not_found(K::CLASS, id))
}

async fn create<K: OrgKind>(s: &Admin, ca: &ContextAuth, mut e: K) -> AuthResult<K> {
    pre_authorize(ca, ORG_AUTHORITIES)?;
    match e.client_id() {
        None => e.set_client_id(ca.user.client_id()),
        Some(c) if !ca.is_system_client() => {
            if !s.caller_manages_client(ca, c).await? {
                return Err(refused(StatusCode::FORBIDDEN));
            }
        }
        Some(_) => {}
    }
    let name = check_name::<K>(s, e.client_id(), e.name(), None).await?;
    e.set_name(name);
    if !e.same_client(s).await? {
        return Err(refused(StatusCode::FORBIDDEN));
    }
    let id = s.db.entity_insert(K::ENTITY, &e.values()).await?;
    let created = reread::<K>(s, id).await?;
    audit::activity(&s.db, created.client_id(), format!("{} Create", K::CLASS), format!("{} created: {}", K::CLASS, created.name().unwrap_or("null")), None);
    Ok(created)
}

/// `update(entity)`: checks, `updatableEntity`, the jOOQ update, the activity, the eviction.
async fn update<K: OrgKind>(s: &Admin, ca: &ContextAuth, e: K) -> AuthResult<K> {
    pre_authorize(ca, ORG_AUTHORITIES)?;
    let refused_update = || refused(K::UPDATE_REFUSED);
    if !e.same_client(s).await? || !s.db.entity_can_be_updated(K::ENTITY, client_check(ca), e.id()).await? {
        return Err(refused_update());
    }
    let mut e = e;
    let existing = read::<K>(s, ca, e.id()).await?;
    if existing.name() != e.name() {
        let name = check_name::<K>(s, existing.client_id(), e.name(), Some(e.id())).await?;
        e.set_name(name);
    }
    let mut stored = read::<K>(s, ca, e.id()).await?;
    stored.take_editable(&e);
    stored.clear_updated_at();
    s.db.entity_update(K::ENTITY, stored.id(), &stored.values()).await?;
    let updated = reread::<K>(s, stored.id()).await?;
    audit::activity(&s.db, updated.client_id(), format!("{} Update", K::CLASS), format!("{} updated: {}", K::CLASS, updated.name().unwrap_or("null")), None);
    s.caches().service.evict_everywhere(K::CACHE, &updated.id().to_string()).await;
    Ok(updated)
}

/// `update(key, fields)`: the stored row, patched through its setters, then `update(entity)`.
async fn patch<K: OrgKind>(s: &Admin, ca: &ContextAuth, id: u64, fields: &Map<String, Value>) -> AuthResult<K> {
    pre_authorize(ca, ORG_AUTHORITIES)?;
    if !s.db.entity_can_be_updated(K::ENTITY, client_check(ca), id).await? {
        return Err(refused(K::UPDATE_REFUSED));
    }
    let mut e = read::<K>(s, ca, id).await?;
    e.patch(fields)?;
    let updated = update::<K>(s, ca, e).await?;
    audit::activity(&s.db, updated.client_id(), format!("{} Update", K::CLASS), format!("{} updated: {}", K::CLASS, updated.name().unwrap_or("null")), None);
    s.caches().service.evict_everywhere(K::CACHE, &updated.id().to_string()).await;
    Ok(updated)
}

async fn delete<K: OrgKind>(s: &Admin, ca: &ContextAuth, id: u64) -> AuthResult<u64> {
    let e = read::<K>(s, ca, id).await?;
    let n = s.db.entity_delete(K::ENTITY, id).await?;
    audit::activity(&s.db, e.client_id(), format!("{} Delete", K::CLASS), format!("{} deleted: {}", K::CLASS, e.name().unwrap_or("null")), None);
    Ok(n)
}

async fn list<K: OrgKind>(s: &Admin, ca: &ContextAuth, page: &Pageable, cond: Option<&crate::condition::Cond>) -> AuthResult<(Vec<K>, i64)> {
    pre_authorize(ca, ORG_AUTHORITIES)?;
    let sql = match cond {
        Some(c) => to_sql(c, &K::ENTITY.table)?,
        None => None,
    };
    let (rows, total) = s.db.entity_page(K::ENTITY, client_check(ca), sql, page).await?;
    Ok((rows.iter().map(K::from_row).collect::<AuthResult<_>>()?, total))
}

impl Admin {
    /// `DepartmentService.readInternal`, cached by id.
    pub async fn department(&self, id: u64) -> AuthResult<Option<Arc<Department>>> {
        let db = self.db.clone();
        self.caches()
            .departments
            .get_or_load(caches::DEPARTMENT, id.to_string(), || async move { Ok::<_, AuthError>(db.department(id).await?.map(Arc::new)) })
            .await
    }

    /// `DesignationService.fillDetails` on a page.
    async fn designation_page_json(&self, items: Vec<Designation>, p: &Params) -> AuthResult<Vec<Value>> {
        let (parent, next, dept) =
            (safe_bool(p.get("fetchParentDesignation")), safe_bool(p.get("fetchNextDesignation")), safe_bool(p.get("fetchDepartment")));
        let mut out = Vec::new();
        for d in items {
            let mut x = DesignationExtras::default();
            let id_of = |v: Option<u64>| v.filter(|i| *i != 0);
            if parent {
                if let Some(i) = id_of(d.parent_designation_id) {
                    x.parent = self.designation(i).await?;
                }
            }
            if next {
                if let Some(i) = id_of(d.next_designation_id) {
                    x.next = self.designation(i).await?;
                }
            }
            if dept {
                if let Some(i) = id_of(d.department_id) {
                    x.department = self.department(i).await?;
                }
            }
            out.push(designation_json(&d, &x));
        }
        Ok(out)
    }

    /// `DepartmentService.fillDetails` on a page.
    async fn department_page_json(&self, items: Vec<Department>, p: &Params) -> AuthResult<Vec<Value>> {
        let parent = safe_bool(p.get("fetchParentDepartment"));
        let mut out = Vec::new();
        for d in items {
            let p = match d.parent_department_id.filter(|i| parent && *i != 0) {
                Some(i) => self.department(i).await?,
                None => None,
            };
            out.push(d.to_json(p.as_deref()));
        }
        Ok(out)
    }
}

fn designation_out(d: &Designation) -> Value {
    d.to_json()
}

fn department_out(d: &Department) -> Value {
    d.to_json(None)
}

macro_rules! r {
    ($name:ident, $path:expr, |$s:ident, $r:ident, $ca:ident| $body:block) => {
        $crate::web_route!($name, AdminState, $path, true, |$s, $r, $ca| $body);
    };
}

macro_rules! rp {
    ($name:ident, $path:expr, |$s:ident, $r:ident, $ca:ident, $p:ident| $body:block) => {
        $crate::web_route_path!($name, AdminState, $path, true, |$s, $r, $ca, $p| $body);
    };
}

/// `AbstractJOOQDataController.delete`: `@ResponseStatus(NO_CONTENT)`; the count is not written.
fn deleted() -> axum::response::Response {
    no_content_json()
}

// ---- designations ----

r!(designations_list, "/designations", |s, r, ca| {
    let page = Pageable::from_params(&r.params);
    let cond = from_params(&r.params.0);
    let (items, total) = list::<Designation>(&s, &ca, &page, cond.as_ref()).await?;
    Ok(page_response(s.designation_page_json(items, &r.params).await?, &page, total))
});

r!(designations_query, "/designations/query", |s, r, ca| {
    let (page, cond) = query_body(&r.body)?;
    let (items, total) = list::<Designation>(&s, &ca, &page, cond.as_ref()).await?;
    Ok(page_response(items.iter().map(designation_out).collect(), &page, total))
});

r!(designations_create, "/designations", |s, r, ca| {
    let body = object_body(&r.body)?;
    let e = Designation::from_body(&Fields(&body))?;
    Ok(json(&designation_out(&create(&s, &ca, e).await?)))
});

rp!(designation_read, "/designations/{id}", |s, r, ca, id| {
    Ok(json(&designation_out(&read::<Designation>(&s, &ca, to_u64(&id)?).await?)))
});

rp!(designation_put, "/designations/{id}", |s, r, ca, id| {
    let id = to_u64(&id)?;
    let body = object_body(&r.body)?;
    let mut e = Designation::from_body(&Fields(&body))?;
    e.id = id;
    Ok(json(&designation_out(&update(&s, &ca, e).await?)))
});

rp!(designation_patch, "/designations/{id}", |s, r, ca, id| {
    let id = to_u64(&id)?;
    let body = object_body(&r.body)?;
    Ok(json(&designation_out(&patch::<Designation>(&s, &ca, id, &body).await?)))
});

rp!(designation_delete, "/designations/{id}", |s, r, ca, id| {
    pre_authorize(&ca, ORG_AUTHORITIES)?;
    delete::<Designation>(&s, &ca, to_u64(&id)?).await?;
    Ok(deleted())
});

// ---- departments ----

r!(departments_list, "/departments", |s, r, ca| {
    let page = Pageable::from_params(&r.params);
    let cond = from_params(&r.params.0);
    let (items, total) = list::<Department>(&s, &ca, &page, cond.as_ref()).await?;
    Ok(page_response(s.department_page_json(items, &r.params).await?, &page, total))
});

r!(departments_query, "/departments/query", |s, r, ca| {
    let (page, cond) = query_body(&r.body)?;
    let (items, total) = list::<Department>(&s, &ca, &page, cond.as_ref()).await?;
    Ok(page_response(items.iter().map(department_out).collect(), &page, total))
});

r!(departments_create, "/departments", |s, r, ca| {
    let body = object_body(&r.body)?;
    let e = Department::from_body(&Fields(&body))?;
    Ok(json(&department_out(&create(&s, &ca, e).await?)))
});

rp!(department_read, "/departments/{id}", |s, r, ca, id| {
    Ok(json(&department_out(&read::<Department>(&s, &ca, to_u64(&id)?).await?)))
});

rp!(department_put, "/departments/{id}", |s, r, ca, id| {
    let id = to_u64(&id)?;
    let body = object_body(&r.body)?;
    let mut e = Department::from_body(&Fields(&body))?;
    e.id = id;
    Ok(json(&department_out(&update(&s, &ca, e).await?)))
});

rp!(department_patch, "/departments/{id}", |s, r, ca, id| {
    let id = to_u64(&id)?;
    let body = object_body(&r.body)?;
    Ok(json(&department_out(&patch::<Department>(&s, &ca, id, &body).await?)))
});

rp!(department_delete, "/departments/{id}", |s, r, ca, id| {
    pre_authorize(&ca, ORG_AUTHORITIES)?;
    delete::<Department>(&s, &ca, to_u64(&id)?).await?;
    Ok(deleted())
});

pub fn router() -> Router<AdminState> {
    Router::new()
        .route("/api/security/designations", get(designations_list).post(designations_create))
        .route("/api/security/designations/query", axum::routing::post(designations_query))
        .route(
            "/api/security/designations/{id}",
            get(designation_read).put(designation_put).patch(designation_patch).delete(designation_delete),
        )
        .route("/api/security/departments", get(departments_list).post(departments_create))
        .route("/api/security/departments/query", axum::routing::post(departments_query))
        .route(
            "/api/security/departments/{id}",
            get(department_read).put(department_put).patch(department_patch).delete(department_delete),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn bodies_and_patches() {
        let b = json!({"clientId": "28", "name": " Lead ", "departmentId": 3, "unknown": [1]});
        let d = Designation::from_body(&Fields(b.as_object().unwrap())).unwrap();
        assert_eq!((d.client_id, d.name.as_deref(), d.department_id), (Some(28), Some(" Lead "), Some(3)));
        let mut d2 = d.clone();
        d2.patch(json!({"name": "X", "id": 99, "parentDesignation": {"id": 1}}).as_object().unwrap()).unwrap();
        assert_eq!((d2.name.as_deref(), d2.id), (Some("X"), 0));
        assert_eq!(d2.clone().patch(json!({"departmentId": "x"}).as_object().unwrap()).unwrap_err().status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(d2.clone().patch(json!({"department": 5}).as_object().unwrap()).is_err());
        let mut stored = Designation { id: 4, client_id: Some(1), ..Default::default() };
        stored.take_editable(&d2);
        assert_eq!((stored.client_id, stored.name.as_deref(), stored.department_id), (Some(1), Some("X"), Some(3)));
        let dep = Department::from_body(&Fields(json!({"name": "D", "parentDepartmentId": 2}).as_object().unwrap())).unwrap();
        let mut dep2 = Department { id: 9, ..Default::default() };
        dep2.take_editable(&dep);
        assert_eq!((dep2.name.as_deref(), dep2.parent_department_id), (Some("D"), Some(2)));
        dep2.patch(json!({"parentDepartmentId": [1]}).as_object().unwrap()).unwrap();
        assert_eq!(dep2.parent_department_id, None);
        assert!(dep2.patch(json!({"parentDepartmentId": true}).as_object().unwrap()).is_err());
        assert_eq!(refused(StatusCode::FORBIDDEN).message(), "Internal Server Error (Unknown)");
        assert_eq!(designation_out(&stored)["id"], 4);
        assert!(department_out(&dep2).get("parentDepartmentId").is_none());
    }
}

#[cfg(test)]
mod live {
    use super::*;
    use crate::admin::users::testkit::{fx, sys, NONE};
    use serde_json::json;

    /// `DesignationServiceTest` / `DepartmentServiceTest`: a client's own caller, refusals across
    /// clients, and the fills.
    #[tokio::test]
    async fn own_clients_and_refusals() {
        let Some(fx) = fx().await else { return };
        let (s, c, m, i) = (&fx.s, fx.c, fx.m, fx.i);
        let run = fx.run.clone();
        let a = fx.user(c, "a").await;
        let auth = &["Authorities.Client_CREATE", "Authorities.Client_UPDATE"];
        let own = fx.as_user(&a, "ZZRUL", auth);
        // No client given: the caller's own.
        let dep = create::<Department>(s, &own, Department { name: Some(format!("zz od {run}")), ..Default::default() }).await.unwrap();
        assert_eq!(dep.client_id, Some(c));
        let des = create::<Designation>(s, &own, Designation { name: Some(format!("zz og {run}")), ..Default::default() }).await.unwrap();
        assert_eq!((des.client_id, des.department_id), (Some(c), None));
        // A client the caller does not manage.
        let e = fx.user(i, "i").await;
        let indiv = fx.as_user(&e, "ZZRUI", auth);
        let refused = create::<Designation>(s, &indiv, Designation { client_id: Some(m), name: Some("x".into()), ..Default::default() }).await;
        assert_eq!(refused.unwrap_err().status(), StatusCode::FORBIDDEN);
        // A department of another client.
        let other = create::<Department>(s, &sys(), Department { client_id: Some(m), name: Some(format!("zz md {run}")), ..Default::default() }).await.unwrap();
        let wrong = Designation { client_id: Some(c), name: Some("x".into()), department_id: Some(other.id), ..Default::default() };
        assert_eq!(create::<Designation>(s, &own, wrong).await.unwrap_err().status(), StatusCode::FORBIDDEN);
        let next = Designation { client_id: Some(c), name: Some(format!("zz on {run}")), department_id: Some(dep.id), next_designation_id: Some(des.id), ..Default::default() };
        let next = create::<Designation>(s, &own, next).await.unwrap();
        // An update naming another client's department.
        let mut moved = next.clone();
        moved.department_id = Some(other.id);
        assert_eq!(update::<Designation>(s, &own, moved).await.unwrap_err().status(), StatusCode::NOT_FOUND);
        // `DepartmentDAO` checks no client, so any caller with the authorities patches any row;
        // only a missing one is refused.
        let fields = json!({"description": "x"});
        assert_eq!(patch::<Department>(s, &indiv, other.id, fields.as_object().unwrap()).await.unwrap().description.as_deref(), Some("x"));
        assert_eq!(patch::<Department>(s, &own, NONE, fields.as_object().unwrap()).await.unwrap_err().status(), StatusCode::FORBIDDEN);
        // The list without a condition, and the page with the next designation filled in.
        let page = Pageable::from_params(&Params::default());
        let (_, total) = list::<Designation>(s, &sys(), &page, None).await.unwrap();
        assert!(total > 0);
        let (st, v) = fx.http("GET", &format!("/designations?clientId={c}&fetchNextDesignation=true&size=200"), None).await;
        assert_eq!(st, StatusCode::OK);
        let row = v["content"].as_array().unwrap().iter().find(|d| d["id"] == next.id).unwrap().clone();
        assert_eq!(row["nextDesignation"]["id"], des.id);
        fx.finish().await;
    }
}
