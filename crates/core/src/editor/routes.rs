//! core-editor's routes: the commons routers of every core document kind (CRUD, drafts, fork,
//! publish, versions, publish-all, transport) under the Java base paths, and the core
//! controllers' own routes on top (event definition schedules, template previews, a
//! notification for the services, the index, the caches, an app's wipe, billing).

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, RawQuery, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::Router;
use overridable::json::parse;
use overridable::pojo::to_jackson;
use overridable::write::controller::{self as c, error_response, int_param, spring_refusal, Reply};
use overridable::write::deletion::DeletionService;
use overridable::write::filler::Filler;
use overridable::write::publish::PublishService;
use overridable::write::router::{self as lib, on_behalf, CallerSource};
use overridable::write::spring::Params;
use overridable::write::transport::TransportService;
use overridable::write::{AnyService, Commons, OverridableService};
use overridable::{JMap, JValue};
use platform::error::{AppError, AppResult};
use platform::http::with_route;
use platform::security::ContextAuthentication;

use crate::editor::billing::Billing;
use crate::editor::caller;
use crate::editor::index::build_index;
use crate::editor::kinds::CoreKind;
use crate::editor::schedules::{self, ScheduleModel, ScheduleSources};
use crate::editor::storage::{DataStores, StorageOps};

/// Everything the routes share.
pub struct CoreEditor {
    pub callers: Arc<dyn CallerSource>,
    pub cx: Commons,
    pub functions: OverridableService<CoreKind>,
    pub schemas: OverridableService<CoreKind>,
    pub storages: OverridableService<CoreKind>,
    pub connections: OverridableService<CoreKind>,
    pub templates: OverridableService<CoreKind>,
    pub notifications: OverridableService<CoreKind>,
    pub event_definitions: OverridableService<CoreKind>,
    pub event_actions: OverridableService<CoreKind>,
    pub workflows: OverridableService<CoreKind>,
    pub actions: OverridableService<CoreKind>,
    pub fillers: OverridableService<Filler>,
    pub transports: Arc<TransportService>,
    pub storage: Arc<StorageOps>,
    pub data: Arc<dyn DataStores>,
    pub billing: Billing,
    pub schedules: Arc<dyn ScheduleSources>,
    pub redis: Option<redis::Client>,
    pub eviction_channel: String,
}

type St = Arc<CoreEditor>;

impl CoreEditor {
    fn any(s: &OverridableService<CoreKind>) -> Arc<dyn AnyService> {
        Arc::new(s.clone())
    }

    /// `CorePublishService`: storage, connection, template, notification, eventDefinition,
    /// eventAction, action, workflow, function, schema, filler.
    pub fn publish_services(&self) -> Vec<Arc<dyn AnyService>> {
        vec![
            Self::any(&self.storages),
            Self::any(&self.connections),
            Self::any(&self.templates),
            Self::any(&self.notifications),
            Self::any(&self.event_definitions),
            Self::any(&self.event_actions),
            Self::any(&self.actions),
            Self::any(&self.workflows),
            Self::any(&self.functions),
            Self::any(&self.schemas),
            Arc::new(self.fillers.clone()),
        ]
    }

    /// core's `DeletionService`: action, template, storage, function, schema, eventAction,
    /// eventDefinition, filler, connection, transport, workflow (no notification).
    pub fn deletion_services(&self) -> Vec<Arc<dyn AnyService>> {
        vec![
            Self::any(&self.actions),
            Self::any(&self.templates),
            Self::any(&self.storages),
            Self::any(&self.functions),
            Self::any(&self.schemas),
            Self::any(&self.event_actions),
            Self::any(&self.event_definitions),
            Arc::new(self.fillers.clone()),
            Self::any(&self.connections),
            Arc::new(self.transports.documents().clone()),
            Self::any(&self.workflows),
        ]
    }

    /// core's `TransportService`, in import order: schema, storage, function, template,
    /// eventDefinition, eventAction, filler (no connection, notification, action or workflow).
    pub fn transport_services(
        schemas: &OverridableService<CoreKind>,
        storages: &OverridableService<CoreKind>,
        functions: &OverridableService<CoreKind>,
        templates: &OverridableService<CoreKind>,
        event_definitions: &OverridableService<CoreKind>,
        event_actions: &OverridableService<CoreKind>,
        fillers: &OverridableService<Filler>,
    ) -> Vec<Arc<dyn AnyService>> {
        vec![
            Self::any(schemas),
            Self::any(storages),
            Self::any(functions),
            Self::any(templates),
            Self::any(event_definitions),
            Self::any(event_actions),
            Arc::new(fillers.clone()),
        ]
    }

    /// `CoreIndexService`'s sources, in order.
    fn index_sources(&self) -> [(&'static str, &OverridableService<CoreKind>); 10] {
        [
            ("storages", &self.storages),
            ("schemas", &self.schemas),
            ("functions", &self.functions),
            ("templates", &self.templates),
            ("connections", &self.connections),
            ("eventDefinitions", &self.event_definitions),
            ("eventActions", &self.event_actions),
            ("notifications", &self.notifications),
            ("workflows", &self.workflows),
            ("actions", &self.actions),
        ]
    }
}

/// The whole editor router.
pub fn router(st: St) -> Router {
    let callers = st.callers.clone();
    let publish = Arc::new(PublishService::new(st.cx.clone(), st.publish_services()));
    Router::new()
        .merge(lib::overridable_router("/api/core/functions", st.functions.clone(), callers.clone()))
        .merge(lib::overridable_router("/api/core/schemas", st.schemas.clone(), callers.clone()))
        .merge(lib::overridable_router("/api/core/storages", st.storages.clone(), callers.clone()))
        .merge(lib::overridable_router("/api/core/connections", st.connections.clone(), callers.clone()))
        .merge(lib::overridable_router("/api/core/templates", st.templates.clone(), callers.clone()))
        .merge(lib::overridable_router("/api/core/notifications", st.notifications.clone(), callers.clone()))
        .merge(lib::overridable_router("/api/core/eventDefinitions", st.event_definitions.clone(), callers.clone()))
        .merge(lib::overridable_router("/api/core/eventActions", st.event_actions.clone(), callers.clone()))
        .merge(lib::overridable_router("/api/core/workflows", st.workflows.clone(), callers.clone()))
        .merge(lib::overridable_router("/api/core/workflow/actions", st.actions.clone(), callers.clone()))
        .merge(lib::overridable_router("/api/core/filler", st.fillers.clone(), callers.clone()))
        .merge(lib::transport_router("/api/core/transports", st.transports.clone(), callers.clone()))
        .merge(lib::version_router("/api/core/versions", st.cx.versions.clone(), callers.clone()))
        .merge(lib::publish_router("/api/core/publish", publish, callers))
        .merge(own_routes(st))
}

fn own_routes(st: St) -> Router {
    Router::new()
        .route("/api/core", delete(delete_app))
        .route("/api/core/eventDefinitions/schedules", get(client_schedules))
        .route("/api/core/eventDefinitions/schedule/toCron", post(to_cron))
        .route("/api/core/eventDefinitions/schedule/fromCron", post(from_cron))
        .route("/api/core/eventDefinitions/schedule/zones", get(zones))
        .route("/api/core/templates/preview", post(template_preview))
        .route("/api/core/templates/preview/pdf", post(template_preview_pdf))
        .route("/api/core/notifications/internal/{name}", get(internal_notification))
        .route("/api/core/index", get(index))
        .route("/api/core/index/internal/{app_code}", get(internal_index))
        .route("/api/core/internal/cache", get(cache_names).delete(cache_reset_all))
        .route("/api/core/internal/cache/stats", get(cache_stats))
        .route("/api/core/internal/cache/{cache_name}", delete(cache_reset_named))
        .route("/api/core/internal/billing/meter", post(billing_meter))
        .route("/api/core/internal/billing/reconcile", post(billing_reconcile))
        .with_state(st)
}

fn respond(route: &'static str, r: AppResult<Reply>) -> Response {
    with_route(r.map(IntoResponse::into_response).unwrap_or_else(error_response), route)
}

fn json(v: JValue) -> Reply {
    Reply::json(v)
}

fn bad_request(m: &str) -> AppError {
    spring_refusal(StatusCode::BAD_REQUEST, m)
}

fn unknown(e: impl std::fmt::Display) -> AppError {
    AppError::Internal(anyhow::anyhow!("{e}"))
}

/// `@PreAuthorize("hasAuthority(...)")`: an anonymous caller is Spring Security's bare 401,
/// a signed-in one without the authority its 403 `Access Denied`.
fn pre_authorize(ca: &ContextAuthentication, authority: &str) -> Result<(), Response> {
    if !ca.authenticated {
        return Err(crate::unmapped::unauthorized());
    }
    if !ca.has_authority(authority) {
        return Err(crate::unmapped::access_denied(&[authority]));
    }
    Ok(())
}

async fn caller(st: &St, h: &HeaderMap, route: &'static str) -> Result<ContextAuthentication, Response> {
    st.callers.caller(h).await.map_err(|e| with_route(error_response(e), route))
}

/// A required `@RequestParam`.
fn required<'a>(p: &'a Params, name: &str) -> AppResult<&'a str> {
    p.first(name).ok_or_else(|| bad_request(&format!("Required query parameter '{name}' is not present.")))
}

// ── DeletionController ───────────────────────────────────────────────

/// `DELETE /api/core?deleteAppCode=`: every definition of the app, then its draft data.
async fn delete_app(State(st): State<St>, RawQuery(q): RawQuery, h: HeaderMap) -> Response {
    const R: &str = "/api/core";
    let ca = match caller(&st, &h, R).await {
        Ok(ca) => ca,
        Err(r) => return r,
    };
    let r = async {
        let ob = on_behalf(&h, &ca);
        let p = Params::from_query(q.as_deref());
        let deletion = DeletionService::new(st.cx.directory().clone(), st.deletion_services());
        let reply = c::delete_app(&deletion, &ca, ob.as_ref(), &p).await?;
        if reply.json_body().is_some() {
            if let Some(app) = p.first("deleteAppCode") {
                if let Err(e) = st.data.drop_draft_data(app, ca.client_code()).await {
                    tracing::error!(app, error = %e, "could not drop the app's draft data");
                }
            }
        }
        Ok(reply)
    }
    .await;
    respond(R, r)
}

// ── EventDefinitionController ────────────────────────────────────────

const EVENT_DEFINITION_READ: &str = "Authorities.EventDefinition_READ";

async fn client_schedules(State(st): State<St>, RawQuery(q): RawQuery, h: HeaderMap) -> Response {
    const R: &str = "/api/core/eventDefinitions/schedules";
    let ca = match caller(&st, &h, R).await {
        Ok(ca) => ca,
        Err(r) => return r,
    };
    let p = Params::from_query(q.as_deref());
    let args = (|| -> AppResult<(String, String, i64, i64)> {
        let app = required(&p, "appCode")?.to_string();
        let name = required(&p, "name")?.to_string();
        let page = int_param(&p, "page")?.unwrap_or(0).max(0);
        let size = int_param(&p, "size")?.unwrap_or(20).clamp(1, 100);
        Ok((app, name, page, size))
    })();
    let (app, name, page, size) = match args {
        Ok(a) => a,
        Err(e) => return respond(R, Err(e)),
    };
    if let Err(r) = pre_authorize(&ca, EVENT_DEFINITION_READ) {
        return with_route(r, R);
    }
    let r = schedules::client_schedules(st.schedules.as_ref(), &ca, &app, &name, p.first("timezone"), p.first("clientCode"), page, size, chrono::Utc::now())
        .await
        .map(json);
    respond(R, r)
}

fn read_body(body: &[u8]) -> AppResult<JValue> {
    if body.is_empty() {
        return Err(bad_request("Failed to read HTTP message"));
    }
    parse(body).map_err(|_| bad_request("Failed to read HTTP message"))
}

async fn to_cron(State(st): State<St>, RawQuery(q): RawQuery, h: HeaderMap, body: Bytes) -> Response {
    const R: &str = "/api/core/eventDefinitions/schedule/toCron";
    let ca = match caller(&st, &h, R).await {
        Ok(ca) => ca,
        Err(r) => return r,
    };
    let model = match read_body(&body).and_then(|v| ScheduleModel::from_json(&v).ok_or_else(|| bad_request("Failed to read HTTP message"))) {
        Ok(m) => m,
        Err(e) => return respond(R, Err(e)),
    };
    if let Err(r) = pre_authorize(&ca, EVENT_DEFINITION_READ) {
        return with_route(r, R);
    }
    let p = Params::from_query(q.as_deref());
    let r = schedules::to_cron(model, p.first("timezone"), chrono::Utc::now()).map(|pv| json(pv.to_json())).map_err(|t| unknown(t.0));
    respond(R, r)
}

async fn from_cron(State(st): State<St>, RawQuery(q): RawQuery, h: HeaderMap, body: Bytes) -> Response {
    const R: &str = "/api/core/eventDefinitions/schedule/fromCron";
    let ca = match caller(&st, &h, R).await {
        Ok(ca) => ca,
        Err(r) => return r,
    };
    // `@RequestBody Map<String, String>`: a scalar is read as its text, anything else refused.
    let m = match read_body(&body) {
        Ok(JValue::Object(m)) => m,
        Ok(_) | Err(_) => return respond(R, Err(bad_request("Failed to read HTTP message"))),
    };
    let text = |k: &str| -> Result<Option<String>, AppError> {
        match m.get(k) {
            None | Some(JValue::Null) => Ok(None),
            Some(JValue::Object(_)) | Some(JValue::Array(_)) => Err(bad_request("Failed to read HTTP message")),
            Some(v) => Ok(Some(v.java_to_string())),
        }
    };
    let (cron, zone) = match (text("cron"), text("cronZone")) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(e), _) | (_, Err(e)) => return respond(R, Err(e)),
    };
    if let Err(r) = pre_authorize(&ca, EVENT_DEFINITION_READ) {
        return with_route(r, R);
    }
    let p = Params::from_query(q.as_deref());
    let r = schedules::from_cron_preview(cron.as_deref(), zone.as_deref(), p.first("timezone"), chrono::Utc::now())
        .map(|pv| json(pv.to_json()))
        .map_err(|t| unknown(t.0));
    respond(R, r)
}

async fn zones(State(st): State<St>, h: HeaderMap) -> Response {
    const R: &str = "/api/core/eventDefinitions/schedule/zones";
    if let Err(r) = caller(&st, &h, R).await {
        return r;
    }
    respond(R, Ok(json(schedules::zones(chrono::Utc::now()))))
}

// ── TemplateController ───────────────────────────────────────────────

fn preview_request(body: &[u8]) -> AppResult<(Option<serde_json::Value>, Option<String>, Option<serde_json::Value>)> {
    let v: serde_json::Value = serde_json::from_slice(body).map_err(|_| bad_request("Failed to read HTTP message"))?;
    let o = match v {
        serde_json::Value::Object(o) => o,
        serde_json::Value::Null => return Ok((None, None, None)),
        _ => return Err(bad_request("Failed to read HTTP message")),
    };
    let template = o.get("template").filter(|t| !t.is_null()).cloned();
    if template.as_ref().is_some_and(|t| !t.is_object()) {
        return Err(bad_request("Failed to read HTTP message"));
    }
    let language = match o.get("language") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(s)) => Some(s.clone()),
        Some(serde_json::Value::Object(_)) | Some(serde_json::Value::Array(_)) => return Err(bad_request("Failed to read HTTP message")),
        Some(other) => Some(other.to_string()),
    };
    let data = o.get("data").filter(|d| !d.is_null()).cloned();
    if data.as_ref().is_some_and(|d| !d.is_object()) {
        return Err(bad_request("Failed to read HTTP message"));
    }
    Ok((template, language, data))
}

async fn template_preview(State(st): State<St>, h: HeaderMap, body: Bytes) -> Response {
    const R: &str = "/api/core/templates/preview";
    if let Err(r) = caller(&st, &h, R).await {
        return r;
    }
    let r = preview_request(&body).and_then(|(t, l, d)| {
        crate::editor::preview::render_parts(t.as_ref(), l.as_deref(), d.as_ref()).map(|m| json(JValue::Object(m))).map_err(unknown)
    });
    respond(R, r)
}

async fn template_preview_pdf(State(st): State<St>, h: HeaderMap, body: Bytes) -> Response {
    const R: &str = "/api/core/templates/preview/pdf";
    if let Err(r) = caller(&st, &h, R).await {
        return r;
    }
    let r = preview_request(&body).and_then(|(t, _, d)| {
        crate::editor::preview::render_pdf(t.as_ref(), d.as_ref())
            .map(|bytes| Reply { status: StatusCode::OK, headers: Vec::new(), body: c::ReplyBody::File { content_type: "application/pdf", bytes } })
            .map_err(unknown)
    });
    respond(R, r)
}

// ── NotificationController ───────────────────────────────────────────

/// `GET /internal/{name}?appCode&clientCode&urlClientCode`: the notification as the client
/// resolves it, no access check; an empty 200 when there is none.
async fn internal_notification(State(st): State<St>, Path(name): Path<String>, RawQuery(q): RawQuery, h: HeaderMap) -> Response {
    const R: &str = "/api/core/notifications/internal/{name}";
    if let Err(r) = caller(&st, &h, R).await {
        return r;
    }
    let r = async {
        let p = Params::from_query(q.as_deref());
        let app = required(&p, "appCode")?;
        let client = required(&p, "clientCode")?;
        let url_client = required(&p, "urlClientCode")?;
        let svc = &st.notifications;
        let found = svc.commons().store.read(svc.kind(), &name, app, url_client, client, false).await.map_err(AppError::Internal)?;
        Ok(match found {
            Some(r) => json(JValue::Object(to_jackson(svc.kind().object.doc().pojo(), &r.entity))),
            None => Reply::empty(StatusCode::OK),
        })
    }
    .await;
    respond(R, r)
}

// ── CoreIndexController ──────────────────────────────────────────────

async fn index(State(st): State<St>, RawQuery(q): RawQuery, h: HeaderMap) -> Response {
    const R: &str = "/api/core/index";
    let ca = match caller(&st, &h, R).await {
        Ok(ca) => ca,
        Err(r) => return r,
    };
    let r = async {
        let p = Params::from_query(q.as_deref());
        let app = required(&p, "appCode")?;
        let idx = build_index(&st.index_sources(), &ca, app, p.first("clientCode")).await?;
        Ok(json(JValue::Object(idx)))
    }
    .await;
    respond(R, r)
}

async fn internal_index(State(st): State<St>, Path(app): Path<String>, RawQuery(q): RawQuery, h: HeaderMap) -> Response {
    const R: &str = "/api/core/index/internal/{appCode}";
    let ca = match caller(&st, &h, R).await {
        Ok(ca) => ca,
        Err(r) => return r,
    };
    let p = Params::from_query(q.as_deref());
    let r = build_index(&st.index_sources(), &ca, &app, p.first("forClientCode")).await.map(|m| json(JValue::Object(m)));
    respond(R, r)
}

// ── CoreCacheController ──────────────────────────────────────────────

async fn cache_names(State(st): State<St>, h: HeaderMap) -> Response {
    const R: &str = "/api/core/internal/cache";
    if let Err(r) = caller(&st, &h, R).await {
        return r;
    }
    respond(R, Ok(json(crate::editor::cache::names(&st.cx.cache))))
}

async fn cache_stats(State(st): State<St>, h: HeaderMap) -> Response {
    const R: &str = "/api/core/internal/cache/stats";
    if let Err(r) = caller(&st, &h, R).await {
        return r;
    }
    respond(R, Ok(json(crate::editor::cache::stats(&st.cx.cache))))
}

async fn cache_reset_named(State(st): State<St>, Path(name): Path<String>, h: HeaderMap) -> Response {
    const R: &str = "/api/core/internal/cache/{cacheName}";
    if let Err(r) = caller(&st, &h, R).await {
        return r;
    }
    st.cx.cache.evict_all_everywhere(&name).await;
    respond(R, Ok(json(JValue::Bool(true))))
}

async fn cache_reset_all(State(st): State<St>, h: HeaderMap) -> Response {
    const R: &str = "/api/core/internal/cache";
    if let Err(r) = caller(&st, &h, R).await {
        return r;
    }
    let r = match crate::editor::cache::evict_all(&st.cx.cache, st.redis.as_ref(), &st.eviction_channel).await {
        Some(v) => json(JValue::Bool(v)),
        None => Reply::empty(StatusCode::OK),
    };
    respond(R, Ok(r))
}

// ── CoreInternalBillingController ────────────────────────────────────

async fn billing_meter(State(st): State<St>, h: HeaderMap) -> Response {
    const R: &str = "/api/core/internal/billing/meter";
    if let Err(r) = caller(&st, &h, R).await {
        return r;
    }
    respond(R, st.billing.meter().await.map(|b| json(JValue::Bool(b))).map_err(AppError::Internal))
}

async fn billing_reconcile(State(st): State<St>, RawQuery(q): RawQuery, h: HeaderMap) -> Response {
    const R: &str = "/api/core/internal/billing/reconcile";
    if let Err(r) = caller(&st, &h, R).await {
        return r;
    }
    let r = async {
        let p = Params::from_query(q.as_deref());
        let date = match p.first("date") {
            None => None,
            Some(d) => Some(chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").map_err(|_| unknown(format!("Text '{d}' could not be parsed at index 0")))?),
        };
        st.billing.reconcile(date).await.map(|b| json(JValue::Bool(b))).map_err(AppError::Internal)
    }
    .await;
    respond(R, r)
}

/// The layer resolving the caller once per request (see [`caller`]), and the one writing
/// bodies as Java core does.
pub fn with_layers(r: Router, resolver: Arc<dyn caller::Resolver>) -> Router {
    // The fallbacks sit inside the caller layer, so an anonymous caller off the permitted paths
    // gets the 401 there too; an explicit fallback also survives `Service::run`'s merge with
    // the health routes, where a layered default one is replaced by the unlayered default.
    let r = r
        .method_not_allowed_fallback(|method: axum::http::Method| async move { crate::unmapped::method_not_allowed(&method) })
        .fallback(|| async { crate::unmapped::not_found() })
        .layer(axum::middleware::from_fn(move |req, next| {
            let resolver = resolver.clone();
            async move { caller::layer(resolver, req, next).await }
        }))
        .layer(axum::middleware::from_fn(core_bodies))
        .layer(axum::middleware::from_fn(crate::error::security_headers_layer));
    crate::unmapped::without_allow_header(r)
}

/// Spring Data's `Page` as core's Jackson writes it (core's Spring version orders the
/// properties differently from ui's, which the overridable library writes).
const CORE_PAGE_ORDER: [&str; 11] =
    ["content", "pageable", "totalPages", "totalElements", "last", "sort", "numberOfElements", "first", "size", "number", "empty"];

fn core_page(m: &JMap) -> Option<JMap> {
    if !m.contains_key("pageable") || !m.keys().all(|k| CORE_PAGE_ORDER.contains(&k.as_str())) {
        return None;
    }
    let mut out = JMap::new();
    for k in CORE_PAGE_ORDER {
        if let Some(v) = m.get(k) {
            out.insert(k.into(), v.clone());
        }
    }
    (out.keys().ne(m.keys())).then_some(out)
}

/// A `Sort.Order` as core's Jackson writes it: `descending` before `ascending`.
const CORE_ORDER_KEYS: [&str; 6] = ["direction", "property", "ignoreCase", "nullHandling", "descending", "ascending"];

/// Every `Sort.Order` in the body in core's property order; `true` when one moved.
fn core_sort_orders(v: &mut JValue) -> bool {
    match v {
        JValue::Object(m) => {
            let mut changed = false;
            if m.len() == CORE_ORDER_KEYS.len() && CORE_ORDER_KEYS.iter().all(|k| m.contains_key(*k)) && m.keys().ne(CORE_ORDER_KEYS.iter().copied()) {
                let mut out = JMap::new();
                for k in CORE_ORDER_KEYS {
                    if let Some(x) = m.get(k) {
                        out.insert(k.into(), x.clone());
                    }
                }
                *m = out;
                changed = true;
            }
            for x in m.values_mut() {
                changed |= core_sort_orders(x);
            }
            changed
        }
        JValue::Array(a) => {
            let mut changed = false;
            for x in a.iter_mut() {
                changed |= core_sort_orders(x);
            }
            changed
        }
        _ => false,
    }
}

/// `TriggerWorkflowStep.getStepType()`, which Jackson writes as a property.
fn with_step_type(m: &JMap) -> Option<JMap> {
    let trigger = m.get("trigger")?.as_object()?;
    if trigger.contains_key("stepType") {
        return None;
    }
    let mut t = trigger.clone();
    t.insert("stepType".into(), JValue::Str("TRIGGER".into()));
    let mut out = m.clone();
    out.insert("trigger".into(), JValue::Object(t));
    Some(out)
}

/// core's `unknown_error_with_id` has no trailing space (ui's has one, and the platform's
/// error writer follows ui).
fn trim_unknown_error(text: &str) -> Option<String> {
    const MARK: &str = "Please try again. A server error - ";
    if !text.contains(MARK) {
        return None;
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(MARK) {
        let after = at + MARK.len();
        out.push_str(&rest[..after]);
        rest = &rest[after..];
        if let Some(q) = rest.find('"') {
            let id = &rest[..q];
            out.push_str(id.strip_suffix(' ').unwrap_or(id));
            rest = &rest[q..];
        }
    }
    out.push_str(rest);
    Some(out)
}

/// Rewrites a JSON body the way the Java core writes it: the `Page` property order, a
/// workflow's trigger step type, the unknown error's message.
pub async fn core_bodies(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let workflows = req.uri().path().starts_with("/api/core/workflows");
    let resp = next.run(req).await;
    let json = resp.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).is_some_and(|c| c.starts_with("application/json"));
    if !json {
        return resp;
    }
    let (mut parts, body) = resp.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, usize::MAX).await else {
        return Response::from_parts(parts, axum::body::Body::empty());
    };
    let text = String::from_utf8_lossy(&bytes);
    let changed = if parts.status.is_client_error() || parts.status.is_server_error() {
        trim_unknown_error(&text)
    } else {
        match parse(&bytes) {
            Ok(JValue::Object(m)) => {
                let reshaped = core_page(&m).or_else(|| if workflows { with_step_type(&m) } else { None });
                let mut v = JValue::Object(reshaped.clone().unwrap_or(m));
                let sorted = core_sort_orders(&mut v);
                (reshaped.is_some() || sorted).then(|| overridable::json::to_jackson_pretty(&v))
            }
            _ => None,
        }
    };
    match changed {
        Some(t) => {
            parts.headers.remove(header::CONTENT_LENGTH);
            Response::from_parts(parts, axum::body::Body::from(t))
        }
        None => Response::from_parts(parts, axum::body::Body::from(bytes)),
    }
}

/// A response's JSON body, for tests.
pub fn body_json(bytes: &[u8]) -> JMap {
    match parse(bytes) {
        Ok(JValue::Object(m)) => m,
        _ => JMap::new(),
    }
}
