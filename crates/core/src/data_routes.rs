//! `AppDataController` (`/api/core/data/**`), `InternalAppDataController`
//! (`/api/core/internal/data/**`) and `SpreadSheetController` (`/api/core/spreadsheet`).
//!
//! The data and spreadsheet routes need a signed-in caller (core's filter chain does not list
//! them as open): anyone else gets a bare 401, with no `WWW-Authenticate` challenge. The
//! internal route is open, and runs as a KIRun execution would, so `onlyThruKIRun` storages
//! read there.
//!
//! What Spring resolves before the controller method runs is kept in its order: the
//! `appCode` and `clientCode` headers, then the request parameters (a boolean that is not
//! one is a 400), then the body.

use std::sync::Arc;

use appdata::model::{AggregateQuery, Condition, DataObject, FilterCondition, FilterOperator, Order, Query, Sort};
use appdata::model::condition::ComplexCondition;
use appdata::value::{Document, Value};
use axum::body::Bytes;
use axum::extract::{FromRequest, Multipart, Path, RawQuery, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::Router;
use futures::FutureExt;

use crate::context::{self, RunScope};
use crate::error::CoreError;
use crate::gson::to_jackson_pretty_data;
use crate::handlers::{finish, request_context};
use crate::state::AppState;
use crate::storage::files::{self, DataFileReader, DataFileType, DataFileWriter, ReadError};
use crate::storage::service::{msg, AppDataService};

/// `IGNORE_PARAMS`: everything else on a GET read becomes a filter on a field of that name.
const IGNORE_PARAMS: &[&str] = &["page", "size", "sort", "eager", "eagerFields", "draft"];
const INTERNAL_IGNORE_PARAMS: &[&str] = &["page", "size", "sort", "eager", "eagerFields", "count"];

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/core/data/{storage}", post(create).get(read_page_get).put(update_put_no_id).patch(update_patch_no_id).delete(delete_storage))
        .route("/api/core/data/{storage}/{id}", get(read).put(update_put).patch(update_patch).delete(delete_row))
        .route("/api/core/data/{storage}/query", post(query).get(read_query_id).put(update_put_lit).patch(update_patch_lit).delete(delete_lit))
        .route(
            "/api/core/data/{storage}/aggregate",
            post(aggregate).get(read_query_id).put(update_put_lit).patch(update_patch_lit).delete(delete_lit),
        )
        .route("/api/core/data/{storage}/rows", delete(delete_rows).get(read_query_id).put(update_put_lit).patch(update_patch_lit))
        .route(
            "/api/core/data/{storage}/copyToDraft",
            post(copy_to_draft).get(read_query_id).put(update_put_lit).patch(update_patch_lit).delete(delete_lit),
        )
        .route(
            "/api/core/data/{storage}/migrationStatus",
            get(migration_status).put(update_put_lit).patch(update_patch_lit).delete(delete_lit),
        )
        .route("/api/core/data/{storage}/drift", get(drift).put(update_put_lit).patch(update_patch_lit).delete(delete_lit))
        .route("/api/core/data/{storage}/drift/repair", post(repair_drift))
        .route("/api/core/data/download/{file_type}/{storage}", get(download_get).post(download_post))
        .route("/api/core/data/template/{storage}", get(template).put(update_put_tpl).patch(update_patch_tpl).delete(delete_tpl))
        .route("/api/core/data/upload/{storage}", post(upload).get(read_upload_id).put(update_put_up).patch(update_patch_up).delete(delete_up))
        .route("/api/core/data/{storage}/version/{id}", get(read_version))
        .route("/api/core/data/{storage}/version/{id}/query", post(find_versions))
        .route("/api/core/internal/data/{storage}", get(internal_read_page))
        .route("/api/core/spreadsheet", post(spreadsheet))
}

// ---------------------------------------------------------------------- request plumbing

/// A request parameter list as Spring reads the query string: a name with no `=` has a null
/// value, one with `=` and nothing after it an empty one.
pub fn query_params(raw: Option<&str>) -> Vec<(String, Option<String>)> {
    let Some(raw) = raw else { return Vec::new() };
    raw.split('&')
        .filter(|p| !p.is_empty() && !p.starts_with('='))
        .map(|p| match p.split_once('=') {
            Some((k, "")) => (decode(k), Some(String::new())),
            Some((k, v)) => (decode(k), Some(decode(v))),
            None => (decode(p), None),
        })
        .collect()
}

fn decode(s: &str) -> String {
    let plus = s.replace('+', " ");
    percent_encoding::percent_decode_str(&plus).decode_utf8_lossy().into_owned()
}

struct Params(Vec<(String, Option<String>)>);

impl Params {
    fn values(&self, name: &str) -> Vec<Option<String>> {
        self.0.iter().filter(|(k, _)| k == name).map(|(_, v)| v.clone()).collect()
    }

    fn first(&self, name: &str) -> Option<String> {
        self.0.iter().find(|(k, _)| k == name).and_then(|(_, v)| v.clone())
    }

    /// `@RequestParam Boolean`: Spring's conversion; empty or absent is the default.
    fn bool(&self, name: &str, default: Option<bool>) -> Result<Option<bool>, CoreError> {
        let Some(v) = self.first(name) else { return Ok(default) };
        let t = v.trim().to_ascii_lowercase();
        if t.is_empty() {
            return Ok(default);
        }
        match t.as_str() {
            "true" | "on" | "yes" | "1" => Ok(Some(true)),
            "false" | "off" | "no" | "0" => Ok(Some(false)),
            _ => Err(crate::error::spring::type_mismatch(Some(name), Some("true or false"), Some(&format!("Invalid boolean value [{v}]")))),
        }
    }

    /// `@RequestParam List<String>`: one value is split at commas, several are taken as
    /// they are.
    fn list(&self, name: &str) -> Option<Vec<String>> {
        let vals: Vec<String> = self.values(name).into_iter().flatten().collect();
        match vals.len() {
            0 => None,
            1 => Some(vals[0].split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()),
            _ => Some(vals),
        }
    }

    /// `ConditionUtil.parameterMapToMap`: the parameters not ignored, as conditions.
    fn condition(&self, ignore: &[&str]) -> Option<Condition> {
        let mut names: Vec<&str> = Vec::new();
        for (k, _) in &self.0 {
            if !ignore.contains(&k.as_str()) && !names.contains(&k.as_str()) {
                names.push(k);
            }
        }
        let conditions: Vec<Condition> = names
            .into_iter()
            .map(|name| {
                let vals = self.values(name);
                if vals.len() == 1 {
                    FilterCondition::new(name, FilterOperator::Equals, vals[0].clone().map(Value::String)).into()
                } else {
                    let joined = vals
                        .iter()
                        .map(|v| v.clone().unwrap_or_else(|| "null".into()).replace(',', "\\,"))
                        .collect::<Vec<_>>()
                        .join(",");
                    FilterCondition::new(name, FilterOperator::In, Some(Value::String(joined))).into()
                }
            })
            .collect();
        match conditions.len() {
            0 => None,
            1 => conditions.into_iter().next(),
            _ => Some(ComplexCondition::and(conditions).into()),
        }
    }

    /// The `Pageable` Spring Data resolves: `page` and `size` (20 when absent, at most 2000),
    /// and the `sort` parameters.
    fn pageable(&self) -> (i32, i32, Sort) {
        let parse = |v: Option<String>, upper: i32| -> Option<i32> {
            let v = v.filter(|s| !s.trim().is_empty())?;
            Some(match v.parse::<i32>() {
                Ok(p) if p < 0 => 0,
                Ok(p) if p > upper => upper,
                Ok(p) => p,
                Err(_) => 0,
            })
        };
        let page = parse(self.first("page"), i32::MAX).unwrap_or(0);
        let mut size = parse(self.first("size"), 2000).unwrap_or(20);
        if size < 1 {
            size = 20;
        }
        let mut orders = Vec::new();
        for part in self.values("sort").into_iter().flatten() {
            orders.extend(parse_sort(&part));
        }
        (page, size, Sort::by(orders))
    }
}

/// `SortOrderParser`: `prop[,prop...][,asc|desc][,ignorecase]`.
fn parse_sort(part: &str) -> Vec<Order> {
    let mut elements: Vec<&str> = part.split(',').collect();
    while elements.last().is_some_and(|e| e.is_empty()) {
        elements.pop();
    }
    let elements: Vec<&str> = elements.into_iter().filter(|e| e.is_empty() || !e.chars().all(|c| c == '.')).collect();
    let mut last = elements.len();
    let mut ignore_case = false;
    if last > 0 && elements[last - 1].eq_ignore_ascii_case("ignorecase") {
        ignore_case = true;
        last -= 1;
    }
    let mut desc = None;
    if last > 0 {
        let d = elements[last - 1];
        if d.eq_ignore_ascii_case("asc") {
            desc = Some(false);
        } else if d.eq_ignore_ascii_case("desc") {
            desc = Some(true);
        }
        if desc.is_some() {
            last -= 1;
        }
    }
    elements[..last]
        .iter()
        .filter(|p| !p.trim().is_empty())
        .map(|p| {
            let mut o = if desc == Some(true) { Order::desc(p) } else { Order::asc(p) };
            o.ignore_case = ignore_case;
            o
        })
        .collect()
}

fn header_value(h: &HeaderMap, name: &str) -> Option<String> {
    h.get(name).and_then(|v| v.to_str().ok()).map(str::to_string)
}

fn required(h: &HeaderMap, names: &[&str]) -> Result<Vec<String>, CoreError> {
    let mut out = Vec::new();
    for name in names {
        match header_value(h, name) {
            Some(v) => out.push(v),
            None => {
                return Err(crate::error::spring::header_missing(name))
            }
        }
    }
    Ok(out)
}

/// `ResponseEntity.ok(body)` written by the services' Jackson.
fn json(v: &Value) -> Response {
    let mut resp = (StatusCode::OK, to_jackson_pretty_data(v)).into_response();
    resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    resp
}

/// `ResponseEntity.ok()` of an empty `Mono`: 200 with no body and no content type.
fn empty_ok() -> Response {
    let mut resp = StatusCode::OK.into_response();
    resp.headers_mut().insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
    resp
}

/// Spring Security's `HttpStatusServerEntryPoint` (see [`crate::unmapped::unauthorized`]).
fn unauthorized() -> Response {
    crate::unmapped::unauthorized()
}

fn bad_body(what: &str) -> CoreError {
    crate::error::spring::body(what)
}

/// `@RequestBody`: required; what Jackson cannot read is a 400.
fn body_value(b: &Bytes) -> Result<Value, CoreError> {
    if b.is_empty() {
        return Err(bad_body("No request body"));
    }
    Value::parse_json(std::str::from_utf8(b).map_err(|_| bad_body("Failed to read HTTP message"))?)
        .map_err(|_| bad_body("Failed to read HTTP message"))
}

/// A `DataObject` body: `{"data": {...}, "message": "..."}`.
fn data_object(b: &Bytes) -> Result<DataObject, CoreError> {
    let v = body_value(b)?;
    let Value::Object(o) = v else { return Err(bad_body("Failed to read HTTP message")) };
    let data = match o.get("data") {
        None | Some(Value::Null) => None,
        Some(Value::Object(d)) => Some(d.clone()),
        Some(_) => return Err(bad_body("Failed to read HTTP message")),
    };
    let message = match o.get("message") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(other) => Some(other.java_string()),
    };
    Ok(DataObject { message, data })
}

fn query_body(b: &Bytes) -> Result<Query, CoreError> {
    Query::from_value(&body_value(b)?).map_err(|_| bad_body("Failed to read HTTP message"))
}

fn aggregate_body(b: &Bytes) -> Result<AggregateQuery, CoreError> {
    AggregateQuery::from_value(&body_value(b)?).map_err(|_| bad_body("Failed to read HTTP message"))
}

fn service(st: &AppState) -> Arc<AppDataService> {
    st.inner().appdata.clone()
}

/// Runs a data route: the caller (401 unless signed in), the two headers, then `f` inside
/// the request context.
async fn data_route<F, Fut>(st: AppState, h: HeaderMap, route: &'static str, f: F) -> Response
where
    F: FnOnce(AppState, String, String) -> Fut,
    Fut: std::future::Future<Output = Result<Response, CoreError>>,
{
    let r = async {
        let ctx = request_context(&st, &h).await?;
        if !ctx.auth.is_authenticated() {
            return Ok(unauthorized());
        }
        let codes = required(&h, &["appCode", "clientCode"])?;
        let (app, client) = (codes[0].clone(), codes[1].clone());
        context::with_request(ctx, f(st, app, client)).await
    }
    .await;
    finish(r, route)
}

fn opt(s: &str) -> Option<&str> {
    Some(s)
}

// ---------------------------------------------------------------------- rows

async fn create(State(st): State<AppState>, Path(storage): Path<String>, RawQuery(q): RawQuery, h: HeaderMap, body: Bytes) -> Response {
    data_route(st, h, "/api/core/data/{storage}", |st, app, client| async move {
        let p = Params(query_params(q.as_deref()));
        let eager = p.bool("eager", Some(false))?;
        let fields = p.list("eagerFields");
        let draft = p.bool("draft", None)?;
        let entity = data_object(&body)?;
        let svc = service(&st);
        let row = svc
            .on_surface(opt(&app), draft, svc.create(opt(&app), opt(&client), &storage, entity, eager, fields))
            .await?;
        Ok(json(&Value::Object(row)))
    })
    .await
}

#[allow(clippy::too_many_arguments)]
async fn update_route(st: AppState, h: HeaderMap, storage: String, id: Option<String>, q: Option<String>, body: Bytes, override_: bool, route: &'static str) -> Response {
    data_route(st, h, route, |st, app, client| async move {
        let p = Params(query_params(q.as_deref()));
        let eager = p.bool("eager", Some(false))?;
        let fields = p.list("eagerFields");
        let draft = p.bool("draft", None)?;
        let mut entity = data_object(&body)?;
        if let Some(id) = id {
            match entity.data.as_mut() {
                Some(d) => {
                    d.insert("_id".into(), Value::String(id));
                }
                None => {
                    return Err(CoreError::unknown(
                        "Cannot invoke \"java.util.Map.put(Object, Object)\" because the return value of \"DataObject.getData()\" is null",
                    ))
                }
            }
        }
        let svc = service(&st);
        let row = svc
            .on_surface(opt(&app), draft, svc.update(opt(&app), opt(&client), &storage, entity, override_, eager, fields))
            .await?;
        Ok(json(&Value::Object(row)))
    })
    .await
}

const ID_ROUTE: &str = "/api/core/data/{storage}/{id}";

async fn update_put(State(st): State<AppState>, Path((storage, id)): Path<(String, String)>, RawQuery(q): RawQuery, h: HeaderMap, body: Bytes) -> Response {
    update_route(st, h, storage, Some(id), q, body, true, ID_ROUTE).await
}

async fn update_patch(State(st): State<AppState>, Path((storage, id)): Path<(String, String)>, RawQuery(q): RawQuery, h: HeaderMap, body: Bytes) -> Response {
    update_route(st, h, storage, Some(id), q, body, false, ID_ROUTE).await
}

async fn update_put_no_id(State(st): State<AppState>, Path(storage): Path<String>, RawQuery(q): RawQuery, h: HeaderMap, body: Bytes) -> Response {
    update_route(st, h, storage, None, q, body, true, "/api/core/data/{storage}").await
}

async fn update_patch_no_id(State(st): State<AppState>, Path(storage): Path<String>, RawQuery(q): RawQuery, h: HeaderMap, body: Bytes) -> Response {
    update_route(st, h, storage, None, q, body, false, "/api/core/data/{storage}").await
}

async fn read_route(st: AppState, h: HeaderMap, storage: String, id: String, q: Option<String>) -> Response {
    data_route(st, h, ID_ROUTE, |st, app, client| async move {
        let p = Params(query_params(q.as_deref()));
        let eager = p.bool("eager", Some(false))?;
        let fields = p.list("eagerFields");
        let draft = p.bool("draft", None)?;
        let svc = service(&st);
        let row = svc.on_surface(opt(&app), draft, svc.read(opt(&app), opt(&client), &storage, &id, eager, fields)).await?;
        Ok(json(&Value::Object(row)))
    })
    .await
}

async fn read(State(st): State<AppState>, Path((storage, id)): Path<(String, String)>, RawQuery(q): RawQuery, h: HeaderMap) -> Response {
    read_route(st, h, storage, id, q).await
}

async fn delete_route(st: AppState, h: HeaderMap, storage: String, id: String, q: Option<String>) -> Response {
    data_route(st, h, ID_ROUTE, |st, app, client| async move {
        let p = Params(query_params(q.as_deref()));
        let draft = p.bool("draft", None)?;
        let delete_version = p.bool("deleteVersion", Some(false))?;
        let svc = service(&st);
        let deleted = svc.on_surface(opt(&app), draft, svc.delete(opt(&app), opt(&client), &storage, &id, delete_version)).await?;
        Ok(json(&Value::Bool(deleted)))
    })
    .await
}

async fn delete_row(State(st): State<AppState>, Path((storage, id)): Path<(String, String)>, RawQuery(q): RawQuery, h: HeaderMap) -> Response {
    delete_route(st, h, storage, id, q).await
}

/// The literal second segments (`query`, `rows`, ...) are ids to the methods Spring maps
/// only on `{storage}/{id}`.
fn literal(uri: &axum::http::Uri) -> String {
    uri.path().rsplit('/').next().unwrap_or_default().to_string()
}

async fn read_query_id(State(st): State<AppState>, Path(storage): Path<String>, uri: axum::http::Uri, RawQuery(q): RawQuery, h: HeaderMap) -> Response {
    read_route(st, h, storage, literal(&uri), q).await
}

async fn update_put_lit(State(st): State<AppState>, Path(storage): Path<String>, uri: axum::http::Uri, RawQuery(q): RawQuery, h: HeaderMap, body: Bytes) -> Response {
    update_route(st, h, storage, Some(literal(&uri)), q, body, true, ID_ROUTE).await
}

async fn update_patch_lit(State(st): State<AppState>, Path(storage): Path<String>, uri: axum::http::Uri, RawQuery(q): RawQuery, h: HeaderMap, body: Bytes) -> Response {
    update_route(st, h, storage, Some(literal(&uri)), q, body, false, ID_ROUTE).await
}

async fn delete_lit(State(st): State<AppState>, Path(storage): Path<String>, uri: axum::http::Uri, RawQuery(q): RawQuery, h: HeaderMap) -> Response {
    delete_route(st, h, storage, literal(&uri), q).await
}

/// `template/{x}` and `upload/{x}` read as storage `template` / `upload`, row `x`, for the
/// methods those routes do not have.
async fn update_put_tpl(State(st): State<AppState>, Path(id): Path<String>, RawQuery(q): RawQuery, h: HeaderMap, body: Bytes) -> Response {
    update_route(st, h, "template".into(), Some(id), q, body, true, ID_ROUTE).await
}

async fn update_patch_tpl(State(st): State<AppState>, Path(id): Path<String>, RawQuery(q): RawQuery, h: HeaderMap, body: Bytes) -> Response {
    update_route(st, h, "template".into(), Some(id), q, body, false, ID_ROUTE).await
}

async fn delete_tpl(State(st): State<AppState>, Path(id): Path<String>, RawQuery(q): RawQuery, h: HeaderMap) -> Response {
    delete_route(st, h, "template".into(), id, q).await
}

async fn read_upload_id(State(st): State<AppState>, Path(id): Path<String>, RawQuery(q): RawQuery, h: HeaderMap) -> Response {
    read_route(st, h, "upload".into(), id, q).await
}

async fn update_put_up(State(st): State<AppState>, Path(id): Path<String>, RawQuery(q): RawQuery, h: HeaderMap, body: Bytes) -> Response {
    update_route(st, h, "upload".into(), Some(id), q, body, true, ID_ROUTE).await
}

async fn update_patch_up(State(st): State<AppState>, Path(id): Path<String>, RawQuery(q): RawQuery, h: HeaderMap, body: Bytes) -> Response {
    update_route(st, h, "upload".into(), Some(id), q, body, false, ID_ROUTE).await
}

async fn delete_up(State(st): State<AppState>, Path(id): Path<String>, RawQuery(q): RawQuery, h: HeaderMap) -> Response {
    delete_route(st, h, "upload".into(), id, q).await
}

/// The GET read: the parameters not ignored are equality filters.
fn get_query(p: &Params, ignore: &[&str]) -> Result<Query, CoreError> {
    let count = p.bool("count", Some(true))?;
    let eager = p.bool("eager", Some(false))?;
    let (page, size, sort) = p.pageable();
    Ok(Query {
        condition: p.condition(ignore),
        exclude_fields: Some(false),
        fields: Some(Vec::new()),
        count,
        page,
        size,
        sort: Some(sort),
        eager,
        eager_fields: p.list("eagerFields"),
        ..Query::default()
    })
}

async fn read_page_get(State(st): State<AppState>, Path(storage): Path<String>, RawQuery(q): RawQuery, h: HeaderMap) -> Response {
    data_route(st, h, "/api/core/data/{storage}", |st, app, client| async move {
        let p = Params(query_params(q.as_deref()));
        let query = get_query(&p, IGNORE_PARAMS)?;
        let draft = p.bool("draft", None)?;
        let svc = service(&st);
        let page = svc.on_surface(opt(&app), draft, svc.read_page(opt(&app), opt(&client), &storage, &query)).await?;
        Ok(json(&page.to_value()))
    })
    .await
}

async fn query(State(st): State<AppState>, Path(storage): Path<String>, RawQuery(q): RawQuery, h: HeaderMap, body: Bytes) -> Response {
    data_route(st, h, "/api/core/data/{storage}/query", |st, app, client| async move {
        let p = Params(query_params(q.as_deref()));
        let draft = p.bool("draft", None)?;
        let query = query_body(&body)?;
        let svc = service(&st);
        let page = svc.on_surface(opt(&app), draft, svc.read_page(opt(&app), opt(&client), &storage, &query)).await?;
        Ok(json(&page.to_value()))
    })
    .await
}

async fn aggregate(State(st): State<AppState>, Path(storage): Path<String>, RawQuery(q): RawQuery, h: HeaderMap, body: Bytes) -> Response {
    data_route(st, h, "/api/core/data/{storage}/aggregate", |st, app, client| async move {
        let p = Params(query_params(q.as_deref()));
        let draft = p.bool("draft", None)?;
        let query = aggregate_body(&body)?;
        let svc = service(&st);
        let page = svc.on_surface(opt(&app), draft, svc.aggregate(opt(&app), opt(&client), &storage, &query)).await?;
        Ok(json(&page.to_value()))
    })
    .await
}

async fn delete_storage(State(st): State<AppState>, Path(storage): Path<String>, RawQuery(q): RawQuery, h: HeaderMap) -> Response {
    data_route(st, h, "/api/core/data/{storage}", |st, app, client| async move {
        let p = Params(query_params(q.as_deref()));
        let delete_all = p.bool("deleteAll", Some(false))?;
        let draft = p.bool("draft", None)?;
        if delete_all != Some(true) {
            return Err(CoreError::msg(StatusCode::BAD_REQUEST, msg::STORAGE_DELETE_ALL_NOT_CONFIRMED, &[&storage]));
        }
        let svc = service(&st);
        let dropped = svc.on_surface(opt(&app), draft, svc.delete_storage(opt(&app), opt(&client), &storage)).await?;
        Ok(json(&Value::Bool(dropped)))
    })
    .await
}

async fn delete_rows(State(st): State<AppState>, Path(storage): Path<String>, RawQuery(q): RawQuery, h: HeaderMap) -> Response {
    data_route(st, h, "/api/core/data/{storage}/rows", |st, app, client| async move {
        let p = Params(query_params(q.as_deref()));
        let delete_all = p.bool("deleteAll", Some(false))?;
        let dry_run = p.bool("dryRun", Some(false))?;
        let draft = p.bool("draft", None)?;
        if delete_all != Some(true) && dry_run != Some(true) {
            return Err(CoreError::msg(StatusCode::BAD_REQUEST, msg::STORAGE_DELETE_ALL_NOT_CONFIRMED, &[&storage]));
        }
        let svc = service(&st);
        let n = svc.on_surface(opt(&app), draft, svc.clear_all_rows(opt(&app), opt(&client), &storage, dry_run)).await?;
        Ok(json(&Value::Int(n)))
    })
    .await
}

async fn copy_to_draft(State(st): State<AppState>, Path(storage): Path<String>, RawQuery(q): RawQuery, h: HeaderMap) -> Response {
    data_route(st, h, "/api/core/data/{storage}/copyToDraft", |st, app, client| async move {
        let p = Params(query_params(q.as_deref()));
        let replace = p.bool("replace", Some(true))?;
        let n = service(&st).copy_live_data_to_draft(opt(&app), opt(&client), &storage, replace).await?;
        Ok(json(&Value::Int(n)))
    })
    .await
}

async fn migration_status(State(st): State<AppState>, Path(storage): Path<String>, h: HeaderMap) -> Response {
    data_route(st, h, "/api/core/data/{storage}/migrationStatus", |st, app, client| async move {
        Ok(match service(&st).migration_status(opt(&app), opt(&client), &storage).await? {
            Some(list) => json(&Value::Array(list.iter().map(tenant_progress).collect())),
            None => empty_ok(),
        })
    })
    .await
}

/// The `TenantProgress` record as Jackson writes it: its components (a null state left out),
/// then the `is` getters.
fn tenant_progress(t: &appdata::mysql::migration::TenantProgress) -> Value {
    use appdata::mysql::journal::MigrationState as S;
    let mut d = Document::new();
    d.insert("database".into(), Value::String(t.database.clone()));
    if let Some(s) = t.state {
        d.insert("state".into(), Value::from(s.name()));
    }
    d.insert("statementIndex".into(), Value::Int(t.statement_index as i64));
    d.insert("total".into(), Value::Int(t.total as i64));
    d.insert("attempt".into(), Value::Int(t.attempt as i64));
    d.insert("done".into(), Value::Bool(t.state == Some(S::Applied)));
    d.insert("untouched".into(), Value::Bool(t.state.is_none()));
    d.insert("resumable".into(), Value::Bool(matches!(t.state, Some(S::Failed) | Some(S::Running))));
    Value::Object(d)
}

async fn drift(State(st): State<AppState>, Path(storage): Path<String>, h: HeaderMap) -> Response {
    data_route(st, h, "/api/core/data/{storage}/drift", |st, app, client| async move {
        let list = service(&st).drift(opt(&app), opt(&client), &storage).await?;
        Ok(json(&Value::Array(list.iter().map(|r| r.to_value()).collect())))
    })
    .await
}

async fn repair_drift(State(st): State<AppState>, Path(storage): Path<String>, RawQuery(q): RawQuery, h: HeaderMap) -> Response {
    data_route(st, h, "/api/core/data/{storage}/drift/repair", |st, app, client| async move {
        let p = Params(query_params(q.as_deref()));
        let approve = p.bool("approve", Some(false))? == Some(true);
        let list = service(&st).repair_drift(opt(&app), opt(&client), &storage, approve).await?;
        Ok(json(&Value::Array(list.iter().map(|r| r.to_value()).collect())))
    })
    .await
}

async fn read_version(State(st): State<AppState>, Path((storage, id)): Path<(String, String)>, RawQuery(q): RawQuery, h: HeaderMap) -> Response {
    data_route(st, h, "/api/core/data/{storage}/version/{id}", |st, app, client| async move {
        let p = Params(query_params(q.as_deref()));
        let draft = p.bool("draft", None)?;
        let svc = service(&st);
        let row = svc.on_surface(opt(&app), draft, svc.read_version(opt(&app), opt(&client), &storage, &id)).await?;
        Ok(json(&Value::Object(row)))
    })
    .await
}

async fn find_versions(State(st): State<AppState>, Path((storage, id)): Path<(String, String)>, RawQuery(q): RawQuery, h: HeaderMap, body: Bytes) -> Response {
    data_route(st, h, "/api/core/data/{storage}/version/{id}/query", |st, app, client| async move {
        let p = Params(query_params(q.as_deref()));
        let draft = p.bool("draft", None)?;
        let include = p.bool("includeObject", Some(true))?;
        let query = query_body(&body)?;
        let svc = service(&st);
        let page = svc
            .on_surface(opt(&app), draft, svc.read_page_version(opt(&app), opt(&client), &storage, &id, &query, include))
            .await?;
        Ok(json(&page.to_value()))
    })
    .await
}

// ---------------------------------------------------------------------- files

fn attachment(name: &str) -> String {
    format!("attachment; filename=\"{}\"", name.replace('\\', "\\\\").replace('"', "\\\""))
}

fn file_response(bytes: Vec<u8>, mime: &str, disposition: String) -> Response {
    let len = bytes.len();
    let mut resp = (StatusCode::OK, bytes).into_response();
    let h = resp.headers_mut();
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
    if let Ok(v) = HeaderValue::from_str(mime) {
        h.insert(header::CONTENT_TYPE, v);
    }
    if let Ok(v) = HeaderValue::from_str(&disposition) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    resp
}

fn file_type_path(s: &str) -> Result<DataFileType, CoreError> {
    DataFileType::value_of(s).ok_or_else(|| crate::error::spring::type_mismatch(Some("fileType"), None, None))
}

/// `downloadData` + `writeDataToResponse`.
async fn download(svc: &AppDataService, app: &str, client: &str, storage_name: &str, query: Query, file_type: DataFileType)
    -> Result<Response, CoreError> {
    let (storage, rows) = svc.read_rows_for_download(Some(app), Some(client), storage_name, &query).await?;
    let file = format!("{}_data.{}", storage.name, file_type.name().to_lowercase());
    let fail = |e: String| CoreError::msg(StatusCode::INTERNAL_SERVER_ERROR, msg::NOT_ABLE_TO_DOWNLOAD_DATA, &[]).caused_by(e);
    let header_list = if file_type.is_nested_structure() {
        Vec::new()
    } else {
        match AppDataService::storage_schema(&storage)? {
            None => Vec::new(),
            Some(schema) => {
                let repo = schema_repo(svc, &storage).await?;
                files::headers(&schema, &repo).await.map_err(CoreError::unknown)?
            }
        }
    };
    let mut writer = DataFileWriter::new(Some(header_list.clone()), file_type, true);
    for row in rows {
        let line = if file_type.is_nested_structure() { row } else { flatten_row(&row, &header_list)? };
        writer
            .write(&line)
            .map_err(|e| CoreError::coded(StatusCode::INTERNAL_SERVER_ERROR, "CORE.NOT_ABLE_TO_OPEN_FILE_ERROR", "Unable to create file").caused_by(e))?;
    }
    let bytes = writer.finish().map_err(fail)?;
    Ok(file_response(bytes, file_type.mime_type(), attachment(&file)))
}

/// A flat file's row: each header's value from the row's Gson tree (`ObjectValueSetterExtractor`
/// on `Data.<header>`), as text, empty when absent.
fn flatten_row(row: &Document, headers: &[String]) -> Result<Document, CoreError> {
    let tree = crate::storage::values::gson_tree(&Value::Object(row.clone()))?;
    let mut out = Document::new();
    for h in headers {
        let text = match path_value(&tree, h) {
            None | Some(serde_json::Value::Null) => String::new(),
            Some(serde_json::Value::String(s)) => s.clone(),
            Some(serde_json::Value::Number(n)) => crate::gson::number_to_java_string(n),
            Some(serde_json::Value::Bool(b)) => b.to_string(),
            Some(serde_json::Value::Array(a)) if a.len() == 1 => match &a[0] {
                serde_json::Value::String(s) => s.clone(),
                other => crate::gson::element_to_string(other),
            },
            Some(serde_json::Value::Array(_)) => return Err(CoreError::unknown("java.lang.IllegalStateException")),
            Some(serde_json::Value::Object(_)) => return Err(CoreError::unknown("java.lang.UnsupportedOperationException: JsonObject")),
        };
        out.insert(h.clone(), Value::String(text));
    }
    Ok(out)
}

/// `a.b[1].c` into a JSON tree.
fn path_value<'a>(v: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut cur = v;
    for seg in path.split('.') {
        let mut parts = seg.split('[');
        let key = parts.next().unwrap_or_default();
        if !key.is_empty() {
            cur = cur.get(key)?;
        }
        for idx in parts {
            let i: usize = idx.trim_end_matches(']').trim().parse().ok()?;
            cur = cur.get(i)?;
        }
    }
    Some(cur)
}

async fn schema_repo(svc: &AppDataService, storage: &appdata::model::Storage) -> Result<crate::repos::SchemaRepo, CoreError> {
    let app = svc.schema_source(storage).await?;
    let kirun = crate::state::Builtins::kirun_schemas();
    Ok(crate::repos::SchemaRepo(Arc::new(crate::repos::Hybrid::new(vec![kirun, app]))))
}

async fn download_get(State(st): State<AppState>, Path((file_type, storage)): Path<(String, String)>, RawQuery(q): RawQuery, h: HeaderMap) -> Response {
    data_route(st, h, "/api/core/data/download/{fileType}/{storage}", |st, app, client| async move {
        let file_type = file_type_path(&file_type)?;
        let p = Params(query_params(q.as_deref()));
        let draft = p.bool("draft", None)?;
        let query = Query {
            exclude_fields: Some(false),
            fields: Some(Vec::new()),
            condition: p.condition(IGNORE_PARAMS),
            size: 1000,
            ..Query::default()
        };
        let svc = service(&st);
        svc.on_surface(opt(&app), draft, download(&svc, &app, &client, &storage, query, file_type)).await
    })
    .await
}

async fn download_post(State(st): State<AppState>, Path((file_type, storage)): Path<(String, String)>, RawQuery(q): RawQuery, h: HeaderMap, body: Bytes) -> Response {
    data_route(st, h, "/api/core/data/download/{fileType}/{storage}", |st, app, client| async move {
        let file_type = file_type_path(&file_type)?;
        let p = Params(query_params(q.as_deref()));
        let draft = p.bool("draft", None)?;
        let query = query_body(&body)?;
        let svc = service(&st);
        svc.on_surface(opt(&app), draft, download(&svc, &app, &client, &storage, query, file_type)).await
    })
    .await
}

/// `downloadTemplate`: the header row and one empty row.
async fn template(State(st): State<AppState>, Path(storage_name): Path<String>, RawQuery(q): RawQuery, h: HeaderMap) -> Response {
    data_route(st, h, "/api/core/data/template/{storage}", |st, app, client| async move {
        let p = Params(query_params(q.as_deref()));
        let file_type = match p.first("type").filter(|t| !t.is_empty()) {
            None => DataFileType::Csv,
            Some(t) => file_type_path(&t)?,
        };
        let svc = service(&st);
        let storage = svc.template_storage(&app, &client, &storage_name).await?;
        let bytes = if file_type.is_nested_structure() {
            Vec::new()
        } else {
            let Some(schema) = AppDataService::storage_schema(&storage)? else {
                return Err(CoreError::unknown(
                    "Cannot invoke \"com.fincity.nocode.kirun.engine.json.schema.Schema.getRef()\" because \"storageSchema\" is null",
                ));
            };
            let object_only = schema.r#ref.is_some()
                || schema.r#type.as_ref().is_some_and(|t| {
                    let a = t.get_allowed_schema_types();
                    a.len() == 1 && a.contains(&kirun::json::schema::r#type::SchemaType::Object)
                });
            let header_list = if object_only {
                let repo = schema_repo(&svc, &storage).await?;
                Some(files::headers(&schema, &repo).await.map_err(CoreError::unknown)?)
            } else {
                None
            };
            let mut writer = DataFileWriter::new(header_list, file_type, true);
            let fail = |_| CoreError::msg(StatusCode::INTERNAL_SERVER_ERROR, msg::TEMPLATE_GENERATION_ERROR, &[file_type.name()]);
            writer.write(&Document::new()).map_err(fail)?;
            writer.finish().map_err(fail)?
        };
        let name = format!("{storage_name}_template.{}", file_type.name().to_lowercase());
        Ok(file_response(bytes, file_type.mime_type(), attachment(&name)))
    })
    .await
}

/// `uploadData`: the part `file`, its type from `type` or the file name's extension.
async fn upload(State(st): State<AppState>, Path(storage): Path<String>, RawQuery(q): RawQuery, h: HeaderMap, req: Request) -> Response {
    data_route(st.clone(), h, "/api/core/data/upload/{storage}", |st, app, client| async move {
        let p = Params(query_params(q.as_deref()));
        let given = match p.first("type").filter(|t| !t.is_empty()) {
            None => None,
            Some(t) => Some(file_type_path(&t)?),
        };
        let draft = p.bool("draft", None)?;
        let mut multipart = Multipart::from_request(req, &st)
            .await
            .map_err(|_| bad_body("Required part 'file' is not present."))?;
        let mut file: Option<(String, Vec<u8>)> = None;
        while let Some(field) = multipart.next_field().await.map_err(|_| bad_body("Failed to read HTTP message"))? {
            if field.name() == Some("file") && file.is_none() {
                let name = field.file_name().unwrap_or_default().to_string();
                let bytes = field.bytes().await.map_err(|_| bad_body("Failed to read HTTP message"))?;
                file = Some((name, bytes.to_vec()));
            }
        }
        let Some((file_name, bytes)) = file else { return Err(bad_body("Required part 'file' is not present.")) };
        let file_type = match given {
            Some(t) => t,
            None => DataFileType::from_extension(&file_name).map_err(CoreError::unknown)?,
        };
        let svc = service(&st);
        let ok = svc.on_surface(opt(&app), draft, upload_rows(&svc, &app, &client, &storage, file_type, bytes)).await?;
        Ok(json(&Value::Bool(ok)))
    })
    .await
}

fn unreadable(file_type: DataFileType) -> CoreError {
    CoreError::coded(StatusCode::BAD_REQUEST, "CORE.UPLOAD_UNREADABLE", format!("Unable to read the uploaded {} file.", file_type.name()))
        .param("format", file_type.name())
}

async fn upload_rows(svc: &AppDataService, app: &str, client: &str, storage: &str, file_type: DataFileType, bytes: Vec<u8>)
    -> Result<bool, CoreError> {
    let schemas = svc;
    svc.upload_rows(
        Some(app),
        Some(client),
        storage,
        |s| {
            let s = s.clone();
            let repo_future = {
                let catalog = schemas.catalog().clone();
                let (app, client) = (s.app_code.clone(), s.client_code.clone());
                async move { catalog.schema_source(&app, &client).await }
            };
            async move {
                let Some(schema) = AppDataService::storage_schema(&s)? else { return Ok(None) };
                let types = if file_type.is_nested_structure() {
                    Default::default()
                } else {
                    let app_repo = repo_future.await?;
                    let repo = crate::repos::SchemaRepo(Arc::new(crate::repos::Hybrid::new(vec![
                        crate::state::Builtins::kirun_schemas(),
                        app_repo,
                    ])));
                    files::headers_schema_type(None, &schema, &repo, 0).await.map_err(CoreError::unknown)?
                };
                Ok(Some(read_rows(file_type, bytes, &types)?))
            }
            .boxed()
        },
        file_type.name(),
    )
    .await
}

/// `nestedFileToDB` / `flatFileToDB`: the whole file read before any row is written.
fn read_rows(
    file_type: DataFileType,
    bytes: Vec<u8>,
    types: &indexmap::IndexMap<Option<String>, indexmap::IndexSet<kirun::json::schema::r#type::SchemaType>>,
) -> Result<Vec<Document>, CoreError> {
    let mut reader = DataFileReader::new(bytes, file_type);
    let mut rows = Vec::new();
    if matches!(file_type, DataFileType::Json | DataFileType::Jsonl) {
        loop {
            match reader.read_object() {
                Ok(Some(o)) => rows.push(o),
                Ok(None) => break,
                Err(ReadError::Invalid) => return Err(CoreError::coded(StatusCode::BAD_REQUEST, "CORE.UPLOAD_INVALID_JSON", "Invalid JSON file")),
                Err(ReadError::Other(_)) => return Err(unreadable(file_type)),
            }
        }
        return Ok(rows);
    }
    loop {
        let row = reader.read_row().map_err(|_| unreadable(file_type))?;
        let Some(row) = row.filter(|r| !r.is_empty()) else { break };
        let headers = reader.headers().map(<[String]>::to_vec).ok_or_else(|| unreadable(file_type))?;
        let mut map = Document::new();
        for (i, cell) in row.iter().enumerate().take(headers.len()) {
            if cell.trim().is_empty() {
                continue;
            }
            let value = files::element_by_schema_type(types.get(&Some(headers[i].clone())), cell).map_err(|_| unreadable(file_type))?;
            files::set_value_in_map(&mut map, &headers[i], value).map_err(|_| unreadable(file_type))?;
        }
        rows.push(files::hash_ordered(map));
    }
    Ok(rows)
}

// ---------------------------------------------------------------------- internal and spreadsheet

/// `InternalAppDataController.readPage`: open, read only, as inside a KIRun run.
async fn internal_read_page(State(st): State<AppState>, Path(storage): Path<String>, RawQuery(q): RawQuery, h: HeaderMap) -> Response {
    let r = async {
        let ctx = request_context(&st, &h).await?;
        let codes = required(&h, &["appCode", "clientCode"])?;
        let (app, client) = (codes[0].clone(), codes[1].clone());
        let p = Params(query_params(q.as_deref()));
        let query = get_query(&p, INTERNAL_IGNORE_PARAMS)?;
        let svc = service(&st);
        context::with_request(ctx, async {
            context::with_run(RunScope { owner_app_code: None }, async {
                svc.read_page(Some(&app), Some(&client), &storage, &query).await
            })
            .await
        })
        .await
        .map(|page| json(&page.to_value()))
    }
    .await;
    finish(r, "/api/core/internal/data/{storage}")
}

/// `SpreadSheetCreateRequest`.
struct SpreadSheetRequest {
    name: Option<String>,
    data: serde_json::Value,
    headers: Option<Vec<Option<String>>>,
    file_type: DataFileType,
    downloadable: bool,
    skip_header: bool,
}

fn spreadsheet_request(b: &Bytes) -> Result<SpreadSheetRequest, CoreError> {
    if b.is_empty() {
        return Err(bad_body("No request body"));
    }
    let v: serde_json::Value = serde_json::from_slice(b).map_err(|_| bad_body("Failed to read HTTP message"))?;
    let serde_json::Value::Object(o) = v else { return Err(bad_body("Failed to read HTTP message")) };
    let bad = || bad_body("Failed to read HTTP message");
    let boolean = |k: &str, d: bool| -> Result<bool, CoreError> {
        match o.get(k) {
            None | Some(serde_json::Value::Null) => Ok(d),
            Some(serde_json::Value::Bool(b)) => Ok(*b),
            Some(serde_json::Value::String(s)) if s == "true" => Ok(true),
            Some(serde_json::Value::String(s)) if s == "false" => Ok(false),
            Some(serde_json::Value::Number(n)) => Ok(n.as_f64().unwrap_or(0.0) != 0.0),
            _ => Err(bad()),
        }
    };
    let file_type = match o.get("type") {
        None | Some(serde_json::Value::Null) => DataFileType::Csv,
        Some(serde_json::Value::String(s)) => DataFileType::value_of(s).ok_or_else(bad)?,
        _ => return Err(bad()),
    };
    let headers = match o.get("headers") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::Array(a)) => Some(
            a.iter()
                .map(|h| match h {
                    serde_json::Value::Null => None,
                    serde_json::Value::String(s) => Some(s.clone()),
                    other => Some(crate::gson::element_to_string(other)),
                })
                .collect(),
        ),
        Some(serde_json::Value::String(s)) => Some(vec![Some(s.clone())]),
        _ => return Err(bad()),
    };
    let name = match o.get("name") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(s)) => Some(s.clone()),
        Some(other) => Some(crate::gson::element_to_string(other)),
    };
    Ok(SpreadSheetRequest {
        name,
        data: o.get("data").cloned().unwrap_or(serde_json::Value::Null),
        headers,
        file_type,
        downloadable: boolean("downloadable", true)?,
        skip_header: boolean("skipHeader", false)?,
    })
}

/// `JsonElement.getAsString()` of a cell.
fn cell_string(v: &serde_json::Value) -> Result<String, CoreError> {
    match v {
        serde_json::Value::String(s) => Ok(s.clone()),
        serde_json::Value::Number(n) => Ok(crate::gson::number_to_java_string(n)),
        serde_json::Value::Bool(b) => Ok(b.to_string()),
        serde_json::Value::Array(a) if a.len() == 1 => cell_string(&a[0]),
        serde_json::Value::Null => Err(CoreError::unknown("java.lang.UnsupportedOperationException: JsonNull")),
        serde_json::Value::Array(_) => Err(CoreError::unknown("java.lang.IllegalStateException: Array must have size 1")),
        serde_json::Value::Object(_) => Err(CoreError::unknown("java.lang.UnsupportedOperationException: JsonObject")),
    }
}

/// `gson.toJsonTree(data)`: null members dropped.
fn drop_null_members(v: &serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(o) => serde_json::Value::Object(
            o.iter().filter(|(_, x)| !x.is_null()).map(|(k, x)| (k.clone(), drop_null_members(x))).collect(),
        ),
        serde_json::Value::Array(a) => serde_json::Value::Array(a.iter().map(drop_null_members).collect()),
        other => other.clone(),
    }
}

/// `SpreadSheetController.createSpreadSheet`: the bytes, the media type, the disposition.
fn spreadsheet_build(req: &mut SpreadSheetRequest) -> Result<(Vec<u8>, String, String), CoreError> {
    let data = drop_null_members(&req.data);
    let mut headers: Option<Vec<String>> = match &req.headers {
        Some(h) if !h.is_empty() => {
            if h.iter().any(Option::is_none) {
                return Err(CoreError::unknown("java.lang.NullPointerException"));
            }
            Some(h.iter().flatten().cloned().collect())
        }
        _ => None,
    };
    let mut rows: Vec<Document> = Vec::new();
    match &data {
        serde_json::Value::Array(a) if !a.is_empty() => match &a[0] {
            serde_json::Value::Array(first) => {
                let skip = usize::from(req.skip_header);
                req.skip_header = true;
                headers = Some((0..first.len()).map(|j| j.to_string()).collect());
                for e in a.iter().skip(skip) {
                    let serde_json::Value::Array(cells) = e else {
                        return Err(CoreError::unknown("java.lang.IllegalStateException: Not a JSON Array"));
                    };
                    let mut row = Document::new();
                    for (j, c) in cells.iter().enumerate() {
                        row.insert(j.to_string(), Value::String(cell_string(c)?));
                    }
                    rows.push(crate::storage::values::hash_map_order(row));
                }
            }
            serde_json::Value::Object(first) => {
                if headers.as_ref().is_none_or(Vec::is_empty) {
                    headers = Some(first.keys().cloned().collect());
                }
                for e in a {
                    let serde_json::Value::Object(o) = e else {
                        return Err(CoreError::unknown("java.lang.IllegalStateException: Not a JSON Object"));
                    };
                    let mut row = Document::new();
                    for (k, c) in o {
                        row.insert(k.clone(), Value::String(cell_string(c)?));
                    }
                    rows.push(crate::storage::values::hash_map_order(row));
                }
            }
            _ => {}
        },
        serde_json::Value::Object(o) => {
            let no_headers = headers.as_ref().is_none_or(Vec::is_empty);
            let mut h = headers.take().unwrap_or_default();
            let mut row = Document::new();
            for (k, c) in o {
                if no_headers {
                    h.push(k.clone());
                }
                row.insert(k.clone(), Value::String(cell_string(c)?));
            }
            headers = Some(h);
            rows.push(crate::storage::values::hash_map_order(row));
        }
        _ => {}
    }
    let mut writer = DataFileWriter::new(headers, req.file_type, !req.skip_header);
    for row in &rows {
        writer.write(row).map_err(CoreError::unknown)?;
    }
    let bytes = writer.finish().map_err(CoreError::unknown)?;
    let file_name = req.name.clone().unwrap_or_else(|| format!("spreadSheet.{}", req.file_type.name().to_lowercase()));
    let kind = if req.downloadable { "attachment" } else { "inline" };
    let disposition = format!("{kind}; filename=\"{}\"", file_name.replace('\\', "\\\\").replace('"', "\\\""));
    Ok((bytes, req.file_type.mime_type().to_string(), disposition))
}

async fn spreadsheet(State(st): State<AppState>, h: HeaderMap, body: Bytes) -> Response {
    let r = async {
        let ctx = request_context(&st, &h).await?;
        if !ctx.auth.is_authenticated() {
            return Ok(unauthorized());
        }
        let mut req = spreadsheet_request(&body)?;
        let (bytes, mime, disposition) = spreadsheet_build(&mut req)?;
        Ok(file_response(bytes, &mime, disposition))
    }
    .await;
    finish(r, "/api/core/spreadsheet")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(q: &str) -> Params {
        Params(query_params(Some(q)))
    }

    #[test]
    fn query_strings_as_spring_reads_them() {
        let q = query_params(Some("a=1&b=&c&d=x%20y+z&&=e"));
        assert_eq!(
            q,
            vec![
                ("a".to_string(), Some("1".to_string())),
                ("b".into(), Some(String::new())),
                ("c".into(), None),
                ("d".into(), Some("x y z".into())),
            ]
        );
        assert!(query_params(None).is_empty());
    }

    #[test]
    fn booleans_lists_and_pages() {
        let p = params("eager=yes&count=0&bad=maybe&empty=&eagerFields=a,b&many=x,y&many=z&page=-3&size=5000&sort=name,desc&sort=age");
        assert_eq!(p.bool("eager", Some(false)).unwrap(), Some(true));
        assert_eq!(p.bool("count", Some(true)).unwrap(), Some(false));
        assert_eq!(p.bool("empty", Some(true)).unwrap(), Some(true));
        assert_eq!(p.bool("missing", None).unwrap(), None);
        assert_eq!(p.bool("bad", None).unwrap_err().status(), StatusCode::BAD_REQUEST);
        assert_eq!(p.list("eagerFields").unwrap(), ["a", "b"]);
        assert_eq!(p.list("many").unwrap(), ["x,y", "z"]);
        assert_eq!(p.list("none"), None);
        let (page, size, sort) = p.pageable();
        assert_eq!((page, size), (0, 2000));
        assert_eq!(sort.orders.len(), 2);
        assert_eq!(sort.orders[0], Order::desc("name"));
        assert_eq!(sort.orders[1], Order::asc("age"));
        let (page, size, sort) = params("page=x&size=0").pageable();
        assert_eq!((page, size), (0, 20));
        assert!(sort.is_unsorted());
        assert_eq!(params("size=7&page=2").pageable().0, 2);
    }

    #[test]
    fn sort_parameters() {
        assert_eq!(parse_sort("a,b,desc"), vec![Order::desc("a"), Order::desc("b")]);
        let ic = parse_sort("a,asc,ignorecase");
        assert!(ic[0].ignore_case && ic[0].is_ascending());
        assert!(parse_sort("desc").is_empty());
        assert!(parse_sort("..,").is_empty());
        assert_eq!(parse_sort("x,,"), vec![Order::asc("x")]);
    }

    #[test]
    fn parameters_become_conditions() {
        assert!(params("page=1").condition(IGNORE_PARAMS).is_none());
        let one = params("name=x&page=1").condition(IGNORE_PARAMS).unwrap();
        let Condition::Filter(f) = one else { panic!("filter") };
        assert_eq!(f.field.as_deref(), Some("name"));
        assert_eq!(f.value, Some(Value::from("x")));
        let many = params("a=1&a=2,3&b").condition(IGNORE_PARAMS).unwrap();
        let Condition::Complex(c) = many else { panic!("complex") };
        let c: Vec<Condition> = c.conditions.unwrap().into_iter().flatten().collect();
        assert_eq!(c.len(), 2);
        let Condition::Filter(a) = &c[0] else { panic!("filter") };
        assert_eq!(a.operator, Some(FilterOperator::In));
        assert_eq!(a.value, Some(Value::from("1,2\\,3")));
        let Condition::Filter(b) = &c[1] else { panic!("filter") };
        assert_eq!(b.value, None);
        // count is a filter on the public route, a parameter on the internal one.
        assert!(params("count=false").condition(IGNORE_PARAMS).is_some());
        assert!(params("count=false").condition(INTERNAL_IGNORE_PARAMS).is_none());
    }

    #[test]
    fn bodies() {
        assert_eq!(data_object(&Bytes::new()).unwrap_err().text(), "400 BAD_REQUEST \"No request body\"");
        assert!(data_object(&Bytes::from_static(b"[1]")).is_err());
        assert!(data_object(&Bytes::from_static(b"{\"data\":5}")).is_err());
        assert!(data_object(&Bytes::from_static(b"{")).is_err());
        let d = data_object(&Bytes::from_static(b"{\"data\":{\"a\":1},\"message\":\"m\"}")).unwrap();
        assert_eq!(d.message.as_deref(), Some("m"));
        assert_eq!(d.data.unwrap()["a"], Value::Int(1));
        let d = data_object(&Bytes::from_static(b"{\"message\":3}")).unwrap();
        assert!(d.data.is_none());
        assert_eq!(d.message.as_deref(), Some("3"));
        assert!(query_body(&Bytes::from_static(b"{\"size\":\"x\"}")).is_err());
        assert_eq!(query_body(&Bytes::from_static(b"{\"size\":3}")).unwrap().size, 3);
        assert!(aggregate_body(&Bytes::from_static(b"[]")).is_err());
        assert_eq!(aggregate_body(&Bytes::from_static(b"{}")).unwrap().size, 100);
        assert_eq!(required(&HeaderMap::new(), &["appCode"]).unwrap_err().text(), "400 BAD_REQUEST \"Required header 'appCode' is not present.\"");
        assert_eq!(attachment("a\"b"), "attachment; filename=\"a\\\"b\"");
        assert!(file_type_path("csv").is_err());
    }

    #[test]
    fn flat_rows_from_paths() {
        let mut row = Document::new();
        row.insert("a".into(), Value::Object([("b".to_string(), Value::Int(1))].into_iter().collect()));
        row.insert("l".into(), Value::Array(vec![Value::from("x"), Value::Array(vec![Value::Bool(true)])]));
        row.insert("o".into(), Value::Object(Document::new()));
        let flat = flatten_row(&row, &["a.b".into(), "l[0]".into(), "l[1]".into(), "zz".into()]).unwrap();
        assert_eq!(flat["a.b"], Value::from("1"));
        assert_eq!(flat["l[0]"], Value::from("x"));
        assert_eq!(flat["l[1]"], Value::from("true"));
        assert_eq!(flat["zz"], Value::from(""));
        assert!(flatten_row(&row, &["o".into()]).is_err());
        assert!(flatten_row(&row, &["l".into()]).is_err());
    }

    fn sheet(body: serde_json::Value) -> Result<(Vec<u8>, String, String), CoreError> {
        let mut req = spreadsheet_request(&Bytes::from(body.to_string()))?;
        spreadsheet_build(&mut req)
    }

    #[test]
    fn spreadsheets() {
        let (b, mime, d) = sheet(serde_json::json!({"data": [["h1", "h2"], [1, 2.5]], "skipHeader": true})).unwrap();
        assert_eq!(String::from_utf8(b).unwrap(), "1,2.5\n");
        assert_eq!(mime, "text/csv");
        assert_eq!(d, "attachment; filename=\"spreadSheet.csv\"");
        let (b, _, _) = sheet(serde_json::json!({"data": [["a"], ["b"]]})).unwrap();
        assert_eq!(String::from_utf8(b).unwrap(), "a\nb\n");
        let (b, _, d) = sheet(serde_json::json!({"data": [{"x": 1, "y": true}], "name": "s.tsv", "type": "TSV", "downloadable": false})).unwrap();
        assert_eq!(String::from_utf8(b).unwrap(), "x\ty\n1\ttrue\n");
        assert_eq!(d, "inline; filename=\"s.tsv\"");
        let (b, _, _) = sheet(serde_json::json!({"data": {"k": "v", "n": null}, "headers": ["k"]})).unwrap();
        assert_eq!(String::from_utf8(b).unwrap(), "k\nv\n");
        let (b, _, _) = sheet(serde_json::json!({"data": {"k": "v"}})).unwrap();
        assert_eq!(String::from_utf8(b).unwrap(), "k\nv\n");
        let (b, _, _) = sheet(serde_json::json!({"data": [{"a": "1"}], "type": "JSON"})).unwrap();
        assert_eq!(String::from_utf8(b).unwrap(), "[{\"a\":\"1\"}]");
        // Nothing to write: an empty CSV, and an XLSX that fails on close as Java's does.
        assert!(sheet(serde_json::json!({"data": []})).unwrap().0.is_empty());
        assert!(sheet(serde_json::json!({"data": 5, "type": "XLSX"})).is_err());
        assert!(sheet(serde_json::json!({"data": [[null]]})).is_err());
        assert!(sheet(serde_json::json!({"data": [{"a": {"b": 1}}]})).is_err());
        assert!(sheet(serde_json::json!({"data": [[1], {"a": 1}]})).is_err());
        assert!(sheet(serde_json::json!({"data": [{"a": 1}, [1]]})).is_err());
        assert!(sheet(serde_json::json!({"data": [[1]], "headers": [null]})).is_err());
        assert!(sheet(serde_json::json!({"data": [[1]], "type": "PDF"})).is_err());
        assert!(sheet(serde_json::json!({"data": [[1]], "skipHeader": "x"})).is_err());
        assert!(sheet(serde_json::json!({"data": [[1]], "type": 3})).is_err());
        assert!(sheet(serde_json::json!({"data": [[1]], "headers": 3})).is_err());
        assert!(sheet(serde_json::json!([1])).is_err());
        assert!(spreadsheet_request(&Bytes::new()).is_err());
        let (b, _, _) = sheet(serde_json::json!({"data": [[1, [2]]], "headers": "h", "name": 7, "skipHeader": 0})).unwrap();
        assert_eq!(String::from_utf8(b).unwrap(), "1,2\n");
        assert_eq!(cell_string(&serde_json::json!([1, 2])).unwrap_err().status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn uploads_are_read_whole() {
        let mut types = indexmap::IndexMap::new();
        let mut n = indexmap::IndexSet::new();
        n.insert(kirun::json::schema::r#type::SchemaType::Integer);
        types.insert(Some("age".to_string()), n);
        let rows = read_rows(DataFileType::Csv, b"name,age,addr.city\nAnn,30,Pune\nBo\n".to_vec(), &types).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["age"], Value::Int(30));
        assert_eq!(rows[0]["addr"].as_object().unwrap()["city"], Value::from("Pune"));
        assert_eq!(rows[1]["name"], Value::from("Bo"));
        assert_eq!(read_rows(DataFileType::Csv, b"age\nabc\n".to_vec(), &types).unwrap_err().text(), "Unable to read the uploaded CSV file.");
        assert_eq!(read_rows(DataFileType::Json, b"{}".to_vec(), &types).unwrap_err().text(), "Invalid JSON file");
        assert_eq!(read_rows(DataFileType::Jsonl, b"{\"a\":}".to_vec(), &types).unwrap_err().text(), "Unable to read the uploaded JSONL file.");
        assert_eq!(read_rows(DataFileType::Jsonl, b"{\"a\":1}\n{\"b\":2}".to_vec(), &types).unwrap().len(), 2);
        assert_eq!(read_rows(DataFileType::Xlsx, b"junk".to_vec(), &types).unwrap_err().text(), "Unable to read the uploaded XLSX file.");
        assert!(read_rows(DataFileType::Csv, Vec::new(), &types).unwrap().is_empty());
    }

    // ------------------------------------------------------------ the routes, in memory

    use crate::testing::{offline_state, policy, security_stub, serve, MemoryCatalog, MemoryEngine, RecordingEvents};

    fn st(v: serde_json::Value) -> appdata::model::Storage {
        appdata::model::Storage::from_value(&Value::from_json(&v)).unwrap()
    }

    struct Http {
        base: String,
        http: reqwest::Client,
    }

    impl Http {
        async fn call(&self, method: &str, path: &str, auth: bool, body: Option<&str>, ct: Option<&str>) -> (u16, String, String, Vec<u8>) {
            let mut rb = self
                .http
                .request(reqwest::Method::from_bytes(method.as_bytes()).unwrap(), format!("{}{path}", self.base))
                .header("appCode", "app")
                .header("clientCode", "SYSTEM");
            if auth {
                rb = rb.header("Authorization", "Basic user");
            }
            if let Some(b) = body {
                rb = rb.header("content-type", ct.unwrap_or("application/json")).body(b.to_string());
            }
            let r = rb.send().await.unwrap();
            let status = r.status().as_u16();
            let headers = format!("{:?}", r.headers());
            let ctype = r.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
            let bytes = r.bytes().await.unwrap().to_vec();
            (status, ctype, headers, bytes)
        }

        async fn json(&self, method: &str, path: &str, body: Option<&str>) -> (u16, serde_json::Value) {
            let (s, _, _, b) = self.call(method, path, true, body, None).await;
            (s, serde_json::from_slice(&b).unwrap_or(serde_json::Value::Null))
        }
    }

    async fn routes() -> (Http, Arc<MemoryEngine>) {
        let base = security_stub(&[], &["app"]).await;
        let schema = serde_json::json!({"type": "OBJECT", "properties": {"name": {"type": "STRING"}, "age": {"type": "INTEGER"},
                                         "addr": {"type": "OBJECT", "properties": {"city": {"type": "STRING"}}},
                                         "tags": {"type": "ARRAY", "items": {"type": "STRING"}}}});
        let catalog = MemoryCatalog::with(vec![
            st(serde_json::json!({"name": "s", "appCode": "app", "clientCode": "SYSTEM", "schema": schema})),
            st(serde_json::json!({"name": "plain", "appCode": "app", "clientCode": "SYSTEM", "schema": {"type": ["OBJECT", "STRING"]}})),
            st(serde_json::json!({"name": "noschema", "appCode": "app", "clientCode": "SYSTEM"})),
            st(serde_json::json!({"name": "template", "appCode": "app", "clientCode": "SYSTEM"})),
            st(serde_json::json!({"name": "upload", "appCode": "app", "clientCode": "SYSTEM"})),
        ]);
        let engine = Arc::new(MemoryEngine::default());
        engine.insert("s", "r1", serde_json::from_value::<Value>(serde_json::json!({"name": "Ann", "age": 3, "addr": {"city": "Pune"}, "tags": ["a"]}))
            .unwrap()
            .as_object()
            .unwrap()
            .clone());
        engine.insert("template", "t1", Document::new());
        engine.insert("upload", "u1", Document::new());
        let svc = Arc::new(policy(catalog, engine.clone(), &base, Arc::new(RecordingEvents::default())));
        let state = offline_state(svc, &base).await;
        let url = serve(crate::handlers::router(state)).await;
        (Http { base: url, http: reqwest::Client::new() }, engine)
    }

    #[tokio::test]
    async fn rows_over_http() {
        let (c, engine) = routes().await;
        let (s, created) = c.json("POST", "/api/core/data/s", Some(r#"{"data":{"name":"Bo","age":4}}"#)).await;
        assert_eq!(s, 200, "{created}");
        let id = created["_id"].as_str().unwrap().to_string();
        assert_eq!(c.json("GET", &format!("/api/core/data/s/{id}?eager=false&eagerFields=a,b"), None).await.1["name"], "Bo");
        assert_eq!(c.json("PATCH", &format!("/api/core/data/s/{id}"), Some(r#"{"data":{"age":5}}"#)).await.1["age"], 5);
        assert_eq!(c.json("PUT", &format!("/api/core/data/s/{id}"), Some(r#"{"data":{"name":"Cy"}}"#)).await.1.get("age"), None);
        assert_eq!(c.json("PUT", "/api/core/data/s", Some(&format!(r#"{{"data":{{"_id":"{id}","name":"Di"}}}}"#))).await.1["name"], "Di");
        assert_eq!(c.json("PATCH", "/api/core/data/s", Some(&format!(r#"{{"data":{{"_id":"{id}","age":1}}}}"#))).await.1["age"], 1);
        assert_eq!(c.json("PATCH", &format!("/api/core/data/s/{id}"), Some("{}")).await.0, 500);
        let (s, page) = c.json("GET", "/api/core/data/s?size=1&sort=name,desc&name=Ann", None).await;
        assert_eq!((s, page["totalElements"].as_i64()), (200, Some(1)));
        assert_eq!(c.json("POST", "/api/core/data/s/query", Some(r#"{"size":5}"#)).await.1["numberOfElements"], 2);
        assert_eq!(c.json("POST", "/api/core/data/s/aggregate", Some("{}")).await.1["content"][0]["n"], 2);
        assert_eq!(c.json("GET", "/api/core/data/s/version/v1", None).await.0, 404);
        assert_eq!(c.json("POST", "/api/core/data/s/version/r1/query?includeObject=false", Some("{}")).await.1["totalElements"], 0);
        // The literal segments are ids for the methods Spring maps only on {storage}/{id}.
        for lit in ["rows", "query", "aggregate", "copyToDraft", "migrationStatus", "drift"] {
            let (s, _) = c.json("GET", &format!("/api/core/data/s/{lit}"), None).await;
            if lit != "migrationStatus" && lit != "drift" {
                assert_eq!(s, 404, "{lit}");
            }
            assert_eq!(c.json("PUT", &format!("/api/core/data/s/{lit}"), Some(r#"{"data":{}}"#)).await.0, 404, "{lit}");
            assert_eq!(c.json("PATCH", &format!("/api/core/data/s/{lit}"), Some(r#"{"data":{}}"#)).await.0, 404, "{lit}");
            if lit != "rows" {
                assert_eq!(c.json("DELETE", &format!("/api/core/data/s/{lit}"), None).await.0, 404, "{lit}");
            }
        }
        for (m, p) in [("GET", "/api/core/data/upload/u1"), ("PUT", "/api/core/data/upload/u1"), ("PATCH", "/api/core/data/upload/u1"),
                       ("PUT", "/api/core/data/template/t1"), ("PATCH", "/api/core/data/template/t1")] {
            let (s, _) = c.json(m, p, Some(r#"{"data":{}}"#)).await;
            assert_eq!(s, 200, "{m} {p}");
        }
        assert_eq!(c.json("DELETE", "/api/core/data/upload/u1", None).await.1, true);
        assert_eq!(c.json("DELETE", "/api/core/data/template/t1", None).await.1, true);
        assert_eq!(c.json("DELETE", &format!("/api/core/data/s/{id}?deleteVersion=true"), None).await.1, true);
        assert_eq!(c.json("DELETE", "/api/core/data/s", None).await.0, 400);
        assert_eq!(c.json("DELETE", "/api/core/data/s/rows", None).await.0, 400);
        assert_eq!(c.json("DELETE", "/api/core/data/s/rows?dryRun=true", None).await.1, 1);
        assert_eq!(c.json("POST", "/api/core/data/s/copyToDraft", None).await.1, 1);
        let (s, _, _, b) = c.call("GET", "/api/core/data/s/migrationStatus", true, None, None).await;
        assert_eq!((s, b.len()), (200, 0));
        assert_eq!(c.json("GET", "/api/core/data/s/drift", None).await.1, serde_json::json!([]));
        assert_eq!(c.json("POST", "/api/core/data/s/drift/repair?approve=true", None).await.1, serde_json::json!([]));
        assert_eq!(c.json("DELETE", "/api/core/data/s?deleteAll=true&draft=false", None).await.1, true);
        assert_eq!(engine.count("s"), 0);
        // On a named surface the operation runs there.
        assert_eq!(c.json("POST", "/api/core/data/s?draft=true", Some(r#"{"data":{"name":"d"}}"#)).await.0, 200);
        assert!(engine.calls.lock().iter().any(|c| c.contains("draft=true")));
        // The internal route answers without a caller.
        let (s, _, _, b) = c.call("GET", "/api/core/internal/data/s?count=false&size=2", false, None, None).await;
        assert_eq!(s, 200, "{}", String::from_utf8_lossy(&b));
    }

    #[tokio::test]
    async fn refusals_over_http() {
        let (c, _) = routes().await;
        let (s, _, headers, b) = c.call("POST", "/api/core/data/s/query", false, Some("{}"), None).await;
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!((s, v["code"].as_str()), (401, Some("COMMON.SIGN_IN_REQUIRED")));
        assert!(!headers.to_lowercase().contains("www-authenticate"));
        assert_eq!(c.call("POST", "/api/core/spreadsheet", false, Some("{}"), None).await.0, 401);
        let r = c.http.get(format!("{}/api/core/data/s", c.base)).header("Authorization", "Basic user").send().await.unwrap();
        assert_eq!(r.status().as_u16(), 400);
        assert_eq!(c.http.get(format!("{}/api/core/internal/data/s", c.base)).send().await.unwrap().status().as_u16(), 400);
        assert_eq!(c.json("GET", "/api/core/data/s?eager=maybe", None).await.0, 400);
        assert_eq!(c.json("POST", "/api/core/data/s", None).await.0, 400);
        assert_eq!(c.json("POST", "/api/core/data/s/query", Some("{bad")).await.0, 400);
        assert_eq!(c.json("POST", "/api/core/data/s/aggregate", Some("[]")).await.0, 400);
        assert_eq!(c.json("GET", "/api/core/data/nope/x", None).await.0, 404);
        assert_eq!(c.json("GET", "/api/core/data/download/PDF/s", None).await.0, 400);
    }

    #[tokio::test]
    async fn files_over_http() {
        let (c, engine) = routes().await;
        let (s, ct, headers, b) = c.call("GET", "/api/core/data/download/CSV/s?name=Ann", true, None, None).await;
        assert_eq!((s, ct.as_str()), (200, "text/csv"));
        assert_eq!(String::from_utf8(b).unwrap(), "age,name,tags[0],tags[1],addr.city\n3,Ann,a,,Pune\n");
        assert!(headers.contains("attachment; filename=\\\"s_data.csv\\\""), "{headers}");
        let (_, _, _, b) = c.call("POST", "/api/core/data/download/JSON/s", true, Some("{}"), None).await;
        assert!(String::from_utf8(b).unwrap().starts_with("[{\"name\":\"Ann\""));
        let (s, _, _, b) = c.call("GET", "/api/core/data/download/XLSX/s", true, None, None).await;
        assert_eq!(s, 200);
        assert_eq!(files::xlsx_rows(&b).unwrap()[1][1], "Ann");
        // No rows: an XLSX fails on close as Java's does.
        assert_eq!(c.call("GET", "/api/core/data/download/XLSX/s?name=none", true, None, None).await.0, 500);
        assert_eq!(c.call("GET", "/api/core/data/download/CSV/noschema", true, None, None).await.0, 200);

        let (s, _, _, b) = c.call("GET", "/api/core/data/template/s", true, None, None).await;
        assert_eq!((s, String::from_utf8(b).unwrap().as_str()), (200, "age,name,tags[0],tags[1],addr.city\n,,,,\n"));
        assert!(c.call("GET", "/api/core/data/template/s?type=JSON", true, None, None).await.3.is_empty());
        assert_eq!(c.call("GET", "/api/core/data/template/plain?type=CSV", true, None, None).await.0, 500);
        assert_eq!(c.call("GET", "/api/core/data/template/noschema", true, None, None).await.0, 500);

        let part = |name: &str, file: &str, content: &str| {
            format!("--b\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{file}\"\r\n\r\n{content}\r\n--b--\r\n")
        };
        let ct = Some("multipart/form-data; boundary=b");
        let (s, _, _, b) = c.call("POST", "/api/core/data/upload/s", true, Some(&part("file", "x.csv", "name,age,addr.city\nEd,7,Goa\n")), ct).await;
        assert_eq!((s, String::from_utf8_lossy(&b).to_string()), (200, "true".to_string()));
        let (s, _, _, _) = c.call("POST", "/api/core/data/upload/s?type=JSONL", true, Some(&part("file", "x", "{\"name\":\"Fi\"}")), ct).await;
        assert_eq!(s, 200);
        assert_eq!(engine.count("s"), 3);
        assert_eq!(c.call("POST", "/api/core/data/upload/s", true, Some(&part("other", "x.csv", "a")), ct).await.0, 400);
        assert_eq!(c.call("POST", "/api/core/data/upload/s", true, Some(&part("file", "x.pdf", "a")), ct).await.0, 500);
        assert_eq!(c.call("POST", "/api/core/data/upload/s", true, Some("x"), Some("text/plain")).await.0, 400);
        assert_eq!(c.call("POST", "/api/core/data/upload/noschema", true, Some(&part("file", "x.csv", "a\n1\n")), ct).await.0, 400);

        let (s, ct, _, b) = c.call("POST", "/api/core/spreadsheet", true, Some(r#"{"data":[{"a":1}],"type":"TSV"}"#), None).await;
        assert_eq!((s, ct.as_str(), String::from_utf8(b).unwrap().as_str()), (200, "text/tab-separated-values", "a\n1\n"));
        assert_eq!(c.call("POST", "/api/core/spreadsheet", true, Some("[1]"), None).await.0, 400);
    }

    // Port of commons-security `ISecurityConfigurationTest`, the cases on core's routes (the
    // event-stream and cookie ones are the message service's; `excludedPathStaysOpen` is in
    // local_stack_tests).

    async fn status_and_challenge(c: &Http, headers: &[(&str, &str)]) -> (u16, bool) {
        let mut rb = c.http.get(format!("{}/api/core/data/x", c.base)).header("appCode", "app").header("clientCode", "SYSTEM");
        for (k, v) in headers {
            rb = rb.header(*k, *v);
        }
        let r = rb.send().await.unwrap();
        (r.status().as_u16(), r.headers().contains_key("www-authenticate"))
    }

    #[tokio::test]
    async fn anonymous_request_gets_401_without_basic_challenge() {
        let (c, _) = routes().await;
        assert_eq!(status_and_challenge(&c, &[]).await, (401, false));
    }

    #[tokio::test]
    async fn document_request_gets_401_without_basic_challenge() {
        let (c, _) = routes().await;
        assert_eq!(status_and_challenge(&c, &[("Accept", "text/html")]).await, (401, false));
    }

    #[tokio::test]
    async fn wrong_basic_credentials_get_401_without_basic_challenge() {
        let (c, _) = routes().await;
        assert_eq!(status_and_challenge(&c, &[("Authorization", "Basic d3Jvbmc6d3Jvbmc=")]).await, (401, false));
    }

    #[tokio::test]
    async fn basic_credentials_in_header_still_authenticate() {
        let (c, _) = routes().await;
        // Past the filter: the storage `x` is not there, which is the controller's 404.
        assert_eq!(status_and_challenge(&c, &[("Authorization", "Basic user")]).await, (404, false));
    }
}