//! The editor's routes: the commons routers of every ui document kind (CRUD, drafts, fork,
//! publish, versions, publish-all, transport, an app's wipe) under the Java base paths, and the
//! ui controllers' own routes on top: the application index and mobile apps, the page component
//! and event routes, the function step routes; and the Rust-only admin purge.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, RawQuery, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post};
use axum::Router;
use overridable::json::parse;
use overridable::pojo::{convert_json, map_field, str_field, to_jackson};
use overridable::write::controller::{bool_param, error_response, int_param, spring_refusal, Reply, DRAFT_VERSION_HEADER};
use overridable::write::deletion::DeletionService;
use overridable::write::kind::Method;
use overridable::write::messages as msg;
use overridable::write::persist::Clock;
use overridable::write::publish::PublishService;
use overridable::write::router::{self as lib, CallerSource};
use overridable::write::spring::Params;
use overridable::write::transport::TransportService;
use overridable::write::{AnyService, Commons, OverridableService};
use overridable::{java_map, JMap, JValue};
use platform::error::{AppError, AppResult};
use platform::http::with_route;
use platform::security::ContextAuthentication;

use crate::docs::{COMPONENT_DEFINITION, FUNCTION, PAGE};
use crate::editor::index::{build_index, IndexServices};
use crate::editor::kinds::{copy_then_put, java_put_order, UiEvictions, UiFiller, UiKind};
use crate::editor::mobile::{self, MobileApps, MOBILE_APP_CREATE};
use crate::editor::purge::{self, Target};
use crate::respond::with_ui_layers;

/// Everything the editor's routes share.
pub struct EditorState {
    pub callers: Arc<dyn CallerSource>,
    pub cx: Commons,
    pub ev: Arc<UiEvictions>,
    pub applications: OverridableService<UiKind>,
    pub pages: OverridableService<UiKind>,
    pub styles: OverridableService<UiKind>,
    pub themes: OverridableService<UiKind>,
    pub functions: OverridableService<UiKind>,
    pub schemas: OverridableService<UiKind>,
    pub uripaths: OverridableService<UiKind>,
    pub fillers: OverridableService<UiFiller>,
    pub transports: Arc<TransportService>,
    pub mobile: MobileApps,
    /// The admin purge's view of the `ui` Mongo database (`None`: the purge reports it cannot run).
    pub purge: Option<Arc<dyn purge::DocStore>>,
    /// Who manages whom, for the purge; `None` refuses every client purge.
    pub purge_guard: Option<Arc<dyn purge::ManagedClients>>,
}

type St = Arc<EditorState>;

impl EditorState {
    /// The publish list: application, page, style, theme, function, schema, uriPath, filler.
    pub fn publish_services(&self) -> Vec<Arc<dyn AnyService>> {
        vec![
            Arc::new(self.applications.clone()),
            Arc::new(self.pages.clone()),
            Arc::new(self.styles.clone()),
            Arc::new(self.themes.clone()),
            Arc::new(self.functions.clone()),
            Arc::new(self.schemas.clone()),
            Arc::new(self.uripaths.clone()),
            Arc::new(self.fillers.clone()),
        ]
    }

    /// The deletion list: app, page, style, theme, function, schema, filler, uriPath, transport.
    pub fn deletion_services(&self) -> Vec<Arc<dyn AnyService>> {
        vec![
            Arc::new(self.applications.clone()),
            Arc::new(self.pages.clone()),
            Arc::new(self.styles.clone()),
            Arc::new(self.themes.clone()),
            Arc::new(self.functions.clone()),
            Arc::new(self.schemas.clone()),
            Arc::new(self.fillers.clone()),
            Arc::new(self.uripaths.clone()),
            Arc::new(self.transports.documents().clone()),
        ]
    }

    /// The transport list: app, page, style, theme, function, schema, filler, uriPath.
    pub fn transport_services(applications: &OverridableService<UiKind>, rest: [&OverridableService<UiKind>; 6], fillers: &OverridableService<UiFiller>) -> Vec<Arc<dyn AnyService>> {
        let [pages, styles, themes, functions, schemas, uripaths] = rest;
        vec![
            Arc::new(applications.clone()),
            Arc::new(pages.clone()),
            Arc::new(styles.clone()),
            Arc::new(themes.clone()),
            Arc::new(functions.clone()),
            Arc::new(schemas.clone()),
            Arc::new(fillers.clone()),
            Arc::new(uripaths.clone()),
        ]
    }

    fn index_services(&self) -> IndexServices<'_> {
        IndexServices {
            applications: &self.applications,
            pages: &self.pages,
            functions: &self.functions,
            schemas: &self.schemas,
            themes: &self.themes,
            styles: &self.styles,
            uripaths: &self.uripaths,
        }
    }
}

/// The whole editor router, with the ui's filter chain around it.
pub fn router(st: St) -> Router {
    let callers = st.callers.clone();
    let publish = Arc::new(PublishService::new(st.cx.clone(), st.publish_services()));
    let deletion = Arc::new(DeletionService::new(st.cx.directory().clone(), st.deletion_services()));
    let r = Router::new()
        .merge(lib::overridable_router("/api/ui/applications", st.applications.clone(), callers.clone()))
        .merge(lib::overridable_router("/api/ui/pages", st.pages.clone(), callers.clone()))
        .merge(lib::overridable_router("/api/ui/styles", st.styles.clone(), callers.clone()))
        .merge(lib::overridable_router("/api/ui/themes", st.themes.clone(), callers.clone()))
        .merge(lib::overridable_router("/api/ui/functions", st.functions.clone(), callers.clone()))
        .merge(lib::overridable_router("/api/ui/schemas", st.schemas.clone(), callers.clone()))
        .merge(lib::overridable_router("/api/ui/uripaths", st.uripaths.clone(), callers.clone()))
        .merge(lib::overridable_router("/api/ui/filler", st.fillers.clone(), callers.clone()))
        .merge(lib::transport_router("/api/ui/transports", st.transports.clone(), callers.clone()))
        .merge(lib::version_router("/api/ui/versions", st.cx.versions.clone(), callers.clone()))
        .merge(lib::publish_router("/api/ui/publish", publish, callers.clone()))
        .merge(lib::deletion_router("/api/ui", deletion, callers))
        .merge(own_routes(st))
        .fallback(crate::handlers::universal);
    with_ui_layers(r)
}

fn own_routes(st: St) -> Router {
    Router::new()
        .route("/api/ui/applications/{id}/mobileApps", get(list_mobile_apps).post(update_mobile_app))
        .route("/api/ui/applications/{id}/mobileApps/{mobile_id}", delete(delete_mobile_app))
        .route("/api/ui/applications/apple/certificates", get(apple_certificates))
        .route("/api/ui/applications/mobileApps/next", get(next_mobile_app))
        .route("/api/ui/applications/mobileApps/status/{status_id}", post(mobile_app_status))
        .route("/api/ui/applications/{id}/index", get(app_index))
        .route("/api/ui/applications/internal/index/{app_code}", get(internal_index))
        .route("/api/ui/pages/{id}/components", get(read_components).post(add_component))
        .route("/api/ui/pages/{id}/components/{component_key}", patch(patch_component).delete(remove_component))
        .route("/api/ui/pages/{id}/events/{function_name}", get(read_event).put(put_event))
        .route("/api/ui/pages/{id}/changes", patch(patch_changes))
        .route("/api/ui/functions/{id}/steps", get(read_steps).patch(patch_steps))
        .route("/api/ui/purge/client/{code}", delete(purge_client))
        .route("/api/ui/purge/app/{code}", delete(purge_app))
        .with_state(st)
}

fn respond(route: &'static str, r: AppResult<Reply>) -> Response {
    with_route(r.map(IntoResponse::into_response).unwrap_or_else(error_response), route)
}

fn json(v: JValue) -> Reply {
    Reply::json(v)
}

/// Spring's own 400 (see `spring_refusal`).
fn bad_request(m: &str) -> AppError {
    spring_refusal(StatusCode::BAD_REQUEST, m)
}

/// `@PreAuthorize("hasAuthority(...)")`: an anonymous caller gets Spring Security's 401 (Java's
/// is bare; this one asks to sign in), a signed-in one without the authority its 403 (Java's is
/// a plain "Access Denied"; this one names the permission).
fn pre_authorize(ca: &ContextAuthentication, authority: &str) -> Result<(), Response> {
    if !ca.authenticated {
        return Err(AppError::unauthenticated().into_response());
    }
    if !ca.has_authority(authority) {
        return Err(AppError::permission_required(&[authority]).into_response());
    }
    Ok(())
}

/// The caller, or the refusal as the router answers it.
async fn caller(st: &St, h: &HeaderMap, route: &'static str) -> Result<ContextAuthentication, Response> {
    st.callers.caller(h).await.map_err(|e| with_route(error_response(e), route))
}

// ── Admin purge (Rust only) ─────────────────────────────────────────

/// `DELETE /api/ui/purge/client/{clientCode}?dryRun=`: see [`purge`].
async fn purge_client(State(st): State<St>, Path(code): Path<String>, RawQuery(q): RawQuery, h: HeaderMap) -> Response {
    purge_route(st, "/api/ui/purge/client/{clientCode}", purge::CLIENT_DELETE, Target::client(&code), q, h).await
}

/// `DELETE /api/ui/purge/app/{appCode}?dryRun=`: see [`purge`].
async fn purge_app(State(st): State<St>, Path(code): Path<String>, RawQuery(q): RawQuery, h: HeaderMap) -> Response {
    purge_route(st, "/api/ui/purge/app/{appCode}", purge::APPLICATION_DELETE, Target::app(&code), q, h).await
}

/// A signed-in caller holding `authority`; a client only by a client that manages it, an app
/// only by SYSTEM; a bad code is a 400; a dry run unless `dryRun=false`.
async fn purge_route(st: St, route: &'static str, authority: &'static str, target: Result<Target, String>, q: Option<String>, h: HeaderMap) -> Response {
    let ca = match caller(&st, &h, route).await {
        Ok(ca) => ca,
        Err(r) => return r,
    };
    if let Err(r) = pre_authorize(&ca, authority) {
        return with_route(r, route);
    }
    let target = match target {
        Ok(t) => t,
        Err(m) => return respond(route, Err(bad_request(&m))),
    };
    // A client: only a client that manages it (never itself, never SYSTEM). An app: SYSTEM only.
    let allowed = match &target {
        Target::Client(c) => {
            let guard = st.purge_guard.as_deref();
            match purge::may_purge_client(guard, ca.client_code(), c).await {
                Ok(b) => b,
                Err(e) => {
                    tracing::error!(error = %e, "purge: could not ask security who manages the client");
                    false
                }
            }
        }
        Target::App(_) => ca.is_system_client(),
    };
    if !allowed {
        let why = match &target {
            Target::Client(c) => format!("Access Denied: only a client that manages {c} may purge it"),
            Target::App(_) => "Access Denied: an app purge is for the SYSTEM client only".to_string(),
        };
        let c = platform::error::Coded::permission_required(&[authority]).debug(why);
        return with_route(platform::error::coded_response(&c), route);
    }
    let dry_run = purge::dry_run(Params::from_query(q.as_deref()).first("dryRun"));
    tracing::warn!(target = ?target, dry_run, user = ca.user.id, "admin purge");
    let report = purge::run(&st, &target, dry_run).await;
    if !report.errors.is_empty() {
        tracing::warn!(target = ?target, dry_run, errors = ?report.errors, "admin purge finished with errors");
    }
    respond(route, Ok(json(report.to_json())))
}

// ── ApplicationController ───────────────────────────────────────────

async fn list_mobile_apps(State(st): State<St>, Path(app): Path<String>, RawQuery(q): RawQuery, h: HeaderMap) -> Response {
    const R: &str = "/api/ui/applications/{appCode}/mobileApps";
    let ca = match caller(&st, &h, R).await {
        Ok(ca) => ca,
        Err(r) => return r,
    };
    if let Err(r) = pre_authorize(&ca, MOBILE_APP_CREATE) {
        return with_route(r, R);
    }
    let p = Params::from_query(q.as_deref());
    respond(R, st.mobile.list(&ca, &app, p.first("clientCode")).await.map(json))
}

async fn update_mobile_app(State(st): State<St>, Path(app): Path<String>, h: HeaderMap, body: Bytes) -> Response {
    const R: &str = "/api/ui/applications/{appCode}/mobileApps";
    let ca = match caller(&st, &h, R).await {
        Ok(ca) => ca,
        Err(r) => return r,
    };
    let r = async {
        let mut m = mobile::read_body(&body)?;
        m.insert("appCode".into(), JValue::Str(app));
        if let Err(r) = pre_authorize(&ca, MOBILE_APP_CREATE) {
            return Ok(Err(r));
        }
        Ok(Ok(match st.mobile.update(&ca, m).await? {
            Some(v) => json(v),
            None => Reply::empty(StatusCode::OK),
        }))
    }
    .await;
    match r {
        Ok(Err(resp)) => with_route(resp, R),
        Ok(Ok(reply)) => respond(R, Ok(reply)),
        Err(e) => respond(R, Err(e)),
    }
}

async fn delete_mobile_app(State(st): State<St>, Path((_app, id)): Path<(String, String)>, h: HeaderMap) -> Response {
    const R: &str = "/api/ui/applications/{appCode}/mobileApps/{id}";
    let ca = match caller(&st, &h, R).await {
        Ok(ca) => ca,
        Err(r) => return r,
    };
    if let Err(r) = pre_authorize(&ca, MOBILE_APP_CREATE) {
        return with_route(r, R);
    }
    respond(R, st.mobile.delete(&ca, &id).await.map(|b| json(JValue::Bool(b))))
}

async fn apple_certificates(State(st): State<St>, h: HeaderMap) -> Response {
    const R: &str = "/api/ui/applications/apple/certificates";
    if let Err(r) = caller(&st, &h, R).await {
        return r;
    }
    let r = match st.mobile.apple.list_certificates().await {
        Ok(list) => json(JValue::Array(list.into_iter().map(JValue::Object).collect())),
        Err(e) => {
            tracing::error!(error = %e, "Error listing certificates");
            Reply::empty(StatusCode::INTERNAL_SERVER_ERROR)
        }
    };
    respond(R, Ok(r))
}

async fn next_mobile_app(State(st): State<St>, h: HeaderMap) -> Response {
    const R: &str = "/api/ui/applications/mobileApps/next";
    let ca = match caller(&st, &h, R).await {
        Ok(ca) => ca,
        Err(r) => return r,
    };
    if let Err(r) = pre_authorize(&ca, MOBILE_APP_CREATE) {
        return with_route(r, R);
    }
    respond(
        R,
        st.mobile.next(&ca).await.map(|v| match v {
            Some(v) => json(v),
            None => Reply::empty(StatusCode::NOT_FOUND),
        }),
    )
}

async fn mobile_app_status(State(st): State<St>, Path(id): Path<String>, h: HeaderMap, body: Bytes) -> Response {
    const R: &str = "/api/ui/applications/mobileApps/status/{statusID}";
    let ca = match caller(&st, &h, R).await {
        Ok(ca) => ca,
        Err(r) => return r,
    };
    if let Err(r) = pre_authorize(&ca, MOBILE_APP_CREATE) {
        return with_route(r, R);
    }
    respond(
        R,
        st.mobile.update_status(&ca, &id, &body).await.map(|v| match v {
            Some(b) => json(JValue::Bool(b)),
            None => Reply::empty(StatusCode::OK),
        }),
    )
}

async fn app_index(State(st): State<St>, Path(app): Path<String>, RawQuery(q): RawQuery, h: HeaderMap) -> Response {
    const R: &str = "/api/ui/applications/{appCode}/index";
    let ca = match caller(&st, &h, R).await {
        Ok(ca) => ca,
        Err(r) => return r,
    };
    let r = async {
        let p = Params::from_query(q.as_deref());
        let slim = bool_param(&p, "slim", false)?;
        let idx = build_index(&st.index_services(), &ca, &app, p.first("clientCode"), !slim).await?;
        Ok(json(JValue::Object(idx)))
    }
    .await;
    respond(R, r)
}

async fn internal_index(State(st): State<St>, Path(app): Path<String>, RawQuery(q): RawQuery, h: HeaderMap) -> Response {
    const R: &str = "/api/ui/applications/internal/index/{appCode}";
    let ca = match caller(&st, &h, R).await {
        Ok(ca) => ca,
        Err(r) => return r,
    };
    let p = Params::from_query(q.as_deref());
    let r = build_index(&st.index_services(), &ca, &app, p.first("forClientCode"), false).await;
    respond(R, r.map(|m| json(JValue::Object(m))))
}

// ── PageController ──────────────────────────────────────────────────

/// `@RequestParam List<String>`: one value splits on commas, several are taken as they are.
fn list_param(p: &Params, name: &str) -> Option<Vec<String>> {
    let all = p.all(name);
    match all.len() {
        0 => None,
        1 => Some(all[0].split(',').filter(|s| !s.is_empty()).map(str::to_string).collect()),
        _ => Some(all.into_iter().map(str::to_string).collect()),
    }
}

/// `collectChildren`: the children of `parent` that are on, depth-first, once each.
fn collect_children(defs: &JMap, parent: &JMap, out: &mut Vec<(String, JValue)>, remaining: i64) {
    let Some(children) = map_field(parent, "children") else { return };
    if remaining < 0 {
        return;
    }
    for (k, on) in children {
        if *on != JValue::Bool(true) {
            continue;
        }
        let Some(child) = defs.get(k).and_then(JValue::as_object) else { continue };
        if out.iter().any(|(key, _)| key == k) {
            continue;
        }
        out.push((k.clone(), JValue::Object(child.clone())));
        if remaining > 0 {
            collect_children(defs, child, out, remaining - 1);
        }
    }
}

/// `GET /{id}/components?keys=&depth=`: the named components and their children.
pub fn components_of(page: &JMap, keys: &[String], depth: i64) -> JMap {
    let Some(defs) = map_field(page, "componentDefinition") else { return JMap::new() };
    let mut out: Vec<(String, JValue)> = Vec::new();
    for k in keys {
        let Some(comp) = defs.get(k).and_then(JValue::as_object) else { continue };
        match out.iter_mut().find(|(key, _)| key == k) {
            Some(slot) => slot.1 = JValue::Object(comp.clone()),
            None => out.push((k.clone(), JValue::Object(comp.clone()))),
        }
        if depth > 0 {
            collect_children(defs, comp, &mut out, depth - 1);
        }
    }
    out.into_iter()
        .map(|(k, v)| {
            let c = v.as_object().map(|o| JValue::Object(to_jackson(&COMPONENT_DEFINITION, o))).unwrap_or(v);
            (k, c)
        })
        .collect()
}

async fn read_components(State(st): State<St>, Path(id): Path<String>, RawQuery(q): RawQuery, h: HeaderMap) -> Response {
    const R: &str = "/api/ui/pages/{id}/components";
    let ca = match caller(&st, &h, R).await {
        Ok(ca) => ca,
        Err(r) => return r,
    };
    let r = async {
        let p = Params::from_query(q.as_deref());
        let keys = list_param(&p, "keys")
            .ok_or_else(|| bad_request("Required query parameter 'keys' is not present."))?;
        let depth = int_param(&p, "depth")?.unwrap_or(0);
        let page = st.pages.read(&ca, &id).await?;
        Ok(json(JValue::Object(components_of(&page, &keys, depth))))
    }
    .await;
    respond(R, r)
}

/// The fields of a component a patch replaces when it carries them.
const PATCHABLE: [&str; 10] = [
    "properties", "styleProperties", "children", "displayOrder", "bindingPath", "bindingPath2", "bindingPath3", "bindingPath4",
    "bindingPath5", "bindingPath6",
];

fn version_in(m: &JMap, field: &str, key: &str) -> i64 {
    map_field(m, field).and_then(|v| v.get(key)).and_then(JValue::as_i64).unwrap_or(1)
}

fn bump(m: &mut JMap, field: &str, key: &str) {
    let existing = map_field(m, field).cloned();
    let fresh = existing.is_none();
    let mut v = existing.unwrap_or_default();
    let n = v.get(key).and_then(JValue::as_i64).unwrap_or(1);
    v.insert(key.into(), JValue::Int(n + 1));
    m.insert(field.into(), JValue::Object(java_put_order(v, fresh)));
}

/// `PageService.patchOverridable`: authorize the stored page as an update, patch the merged
/// page, store only the difference from the chain below, evict.
async fn patch_overridable(st: &EditorState, ca: &ContextAuthentication, id: &str, patch: impl FnOnce(&mut JMap) -> AppResult<()>) -> AppResult<JMap> {
    let forbidden = || st.cx.error(StatusCode::FORBIDDEN, msg::FORBIDDEN_PERMISSION, &["Page"]);
    if id.trim().is_empty() {
        return Err(forbidden());
    }
    let Some((stored, raw)) = st.pages.find_raw(id).await? else { return Err(forbidden()) };
    if !st.pages.access_check(ca, Method::Update, str_field(&stored, "appCode"), str_field(&stored, "clientCode"), true).await? {
        return Err(forbidden());
    }
    let mut merged = st.pages.read(ca, id).await?;
    patch(&mut merged)?;
    let sources = st.pages.merged_sources(&merged).await?;
    let delta = st.pages.extract_override(merged.clone(), sources.as_ref())?;
    st.pages.replace(&delta, None::<&Clock>, Some(&raw)).await?;
    let (app, client, name) = (str_field(&delta, "appCode"), str_field(&delta, "clientCode"), str_field(&delta, "name"));
    st.pages.evict_recursively(app.unwrap_or("null"), client.unwrap_or("null"), name.unwrap_or("null")).await?;
    // Java's patches clear only the definition caches; the page OUI and SSR caches would keep
    // serving the page from before the patch.
    st.ev.ui_base(&st.cx, app).await;
    st.cx.evict_all(&format!("pageOUICache-{}", app.unwrap_or("null"))).await;
    Ok(delta)
}

/// Whose copy a component-level change is for (`clientCode`, `standalone`, `draft` on the page
/// component and event routes), and the request's surface for the seed read.
struct ForClient {
    target: Option<String>,
    standalone: bool,
    draft: bool,
    surface_draft: bool,
    /// `draftVersion`: the draft version the caller last saw (`X-Draft-Version` of its draft
    /// read), checked by the draft save as `PUT ?draft=true&draftVersion=` checks it.
    draft_version: Option<i64>,
}

impl ForClient {
    fn from(q: Option<&str>, h: &HeaderMap) -> AppResult<Self> {
        let p = Params::from_query(q);
        Ok(Self {
            target: p.first("clientCode").map(str::to_string).filter(|t| !t.trim().is_empty()),
            standalone: bool_param(&p, "standalone", false)?,
            draft: bool_param(&p, "draft", false)?,
            surface_draft: h.get("x-draft").and_then(|v| v.to_str().ok()).is_some_and(|v| v.eq_ignore_ascii_case("true")),
            draft_version: int_param(&p, "draftVersion")?,
        })
    }
}

/// `PageService.patchForClient`: a component-level change made FOR a client. The id names the
/// page, the target client whose copy changes: no target (and no draft) is `patchOverridable`
/// on that page; a target with its own copy has that copy patched (its draft view when
/// `draft`); a target with none gets one, seeded from the page as its base client sees it and
/// stored as a difference over that base (whole when standalone, unpublished when `draft`).
async fn patch_for_client(
    st: &EditorState,
    ca: &ContextAuthentication,
    id: &str,
    fc: &ForClient,
    patch: impl FnOnce(&mut JMap) -> AppResult<()>,
) -> AppResult<JMap> {
    Ok(patch_for_client_versioned(st, ca, id, fc, patch).await?.0)
}

/// `patch_for_client`, and the draft's version after the save when the change went to an
/// existing copy's draft (the `X-Draft-Version` the next save of that draft has to send).
async fn patch_for_client_versioned(
    st: &EditorState,
    ca: &ContextAuthentication,
    id: &str,
    fc: &ForClient,
    patch: impl FnOnce(&mut JMap) -> AppResult<()>,
) -> AppResult<(JMap, Option<i64>)> {
    if fc.target.is_none() && !fc.draft {
        return Ok((patch_overridable(st, ca, id, patch).await?, None));
    }
    let forbidden = || st.cx.error(StatusCode::FORBIDDEN, msg::FORBIDDEN_PERMISSION, &["Page"]);
    if id.trim().is_empty() {
        return Err(forbidden());
    }
    let Some(stored) = st.pages.find_by_id(id).await? else { return Err(forbidden()) };
    // The id only names the page. The caller must at least be able to READ it, as a read by
    // id requires, before its name and app are used to find or create anything; the write
    // check comes next, on the document actually written.
    if !st.pages.access_check(ca, Method::Read, str_field(&stored, "appCode"), str_field(&stored, "clientCode"), false).await? {
        return Err(forbidden());
    }
    let owner = str_field(&stored, "clientCode").unwrap_or("null").to_string();
    let target = fc.target.clone().unwrap_or_else(|| owner.clone());
    let own = if target == owner {
        Some(stored.clone())
    } else {
        st.pages.find_one(str_field(&stored, "name").unwrap_or_default(), str_field(&stored, "appCode").unwrap_or_default(), &target).await?
    };
    match own {
        None => Ok((create_for_target(st, ca, &stored, &target, fc, patch).await?, None)),
        Some(own) => {
            let own_id = str_field(&own, "id").unwrap_or_default().to_string();
            if fc.draft {
                let (view, version) = patch_draft(st, ca, &own, fc.draft_version, patch).await?;
                Ok((view, Some(version)))
            } else {
                Ok((patch_overridable(st, ca, &own_id, patch).await?, None))
            }
        }
    }
}

/// `patchDraft`: the change on the draft view of a copy the target owns, saved as its draft;
/// answers the draft view after. UPDATE on the copy itself is checked here: `save_draft` alone
/// would not refuse a caller without it, its draft target forks the page into the caller's
/// client instead, a write nobody asked for.
async fn patch_draft(
    st: &EditorState,
    ca: &ContextAuthentication,
    own: &JMap,
    expected_version: Option<i64>,
    patch: impl FnOnce(&mut JMap) -> AppResult<()>,
) -> AppResult<(JMap, i64)> {
    if !st.pages.access_check(ca, Method::Update, str_field(own, "appCode"), str_field(own, "clientCode"), true).await? {
        return Err(st.cx.error(StatusCode::FORBIDDEN, msg::FORBIDDEN_PERMISSION, &["Page"]));
    }
    let own_id = str_field(own, "id").unwrap_or_default();
    let (mut view, _) = st.pages.read_draft_with_version(ca, own_id).await?;
    patch(&mut view)?;
    st.pages.save_draft(ca, view, expected_version).await?;
    st.pages.read_draft_with_version(ca, own_id).await
}

/// `createForTarget`: the target's first copy, made by whoever may create one for it.
async fn create_for_target(
    st: &EditorState,
    ca: &ContextAuthentication,
    stored: &JMap,
    target: &str,
    fc: &ForClient,
    patch: impl FnOnce(&mut JMap) -> AppResult<()>,
) -> AppResult<JMap> {
    let forbidden = || st.cx.error(StatusCode::FORBIDDEN, msg::FORBIDDEN_PERMISSION, &["Page"]);
    let (name, app) = (str_field(stored, "name").unwrap_or("null"), str_field(stored, "appCode").unwrap_or("null"));
    if !st.pages.access_check(ca, Method::Create, Some(app), Some(target), true).await? {
        return Err(forbidden());
    }
    let base = match st.pages.base_client_code_of(app, target).await? {
        Some(b) => b,
        None => str_field(stored, "clientCode").unwrap_or("null").to_string(),
    };
    let Some(mut seed) = page_as_seen_by(st, ca, name, app, &base, fc.surface_draft).await? else { return Err(forbidden()) };
    patch(&mut seed)?;
    seed.shift_remove("id");
    seed.insert("clientCode".into(), JValue::Str(target.to_string()));
    if fc.standalone {
        seed.shift_remove("baseClientCode");
    } else {
        seed.insert("baseClientCode".into(), JValue::Str(base));
    }
    seed.insert("version".into(), JValue::Int(1));
    seed.shift_remove("published");
    let created = if fc.draft { st.pages.create_unpublished(ca, seed).await? } else { st.pages.create(ca, seed).await? };
    st.cx.evict_all(&format!("pageOUICache-{app}")).await;
    st.pages.read_internal(str_field(&created, "id").unwrap_or_default()).await?.ok_or_else(forbidden)
}

/// `readInternal(name, appCode, clientCode)` of a page, `PageService.applyChange` included: an
/// authenticated caller without the page's permission is refused, or given the app's
/// forbidden page.
fn page_as_seen_by<'a>(
    st: &'a EditorState,
    ca: &'a ContextAuthentication,
    name: &'a str,
    app: &'a str,
    client: &'a str,
    draft: bool,
) -> futures::future::BoxFuture<'a, AppResult<Option<JMap>>> {
    Box::pin(async move {
        let store = &st.cx.store;
        // The read's own steps, without the definition cache's copy: that one is cloned into
        // the class's full shape, which the difference extraction would then see as changed.
        let Some(stored) = store.read_if_exists_in_base(st.pages.kind(), name, app, client, client, draft).await? else { return Ok(None) };
        let Some(page) = store.read_drafted(st.pages.kind(), &stored, draft, client).await? else { return Ok(None) };
        let permission = str_field(&page, "permission");
        if ca.authenticated && !crate::authority::has_authority(permission, &ca.user.string_authorities) {
            let props = store
                .read(st.applications.kind(), app, app, client, client, draft)
                .await?
                .and_then(|a| map_field(&a.entity, "properties").cloned())
                .unwrap_or_default();
            let forbidden_page = props.get("forbiddenPage").filter(|v| !v.is_null()).map(JValue::java_to_string).filter(|f| !f.trim().is_empty());
            let Some(fb) = forbidden_page else {
                return Err(crate::catalogue::page_forbidden(permission));
            };
            if fb != name {
                return page_as_seen_by(st, ca, &fb, app, client, draft).await.map(|p| p.or(Some(page)));
            }
        }
        Ok(Some(page))
    })
}

fn read_json(body: &[u8]) -> AppResult<JMap> {
    match parse(body) {
        Ok(JValue::Object(m)) => Ok(m),
        _ => Err(bad_request("Failed to read HTTP message")),
    }
}

/// An `int` field of a request class: absent or null is 0.
fn int_field(m: &JMap, f: &str) -> AppResult<i64> {
    match m.get(f) {
        None | Some(JValue::Null) => Ok(0),
        Some(JValue::Int(i)) => Ok(*i as i32 as i64),
        Some(JValue::Float(x)) => Ok(*x as i32 as i64),
        Some(JValue::Str(s)) => s.trim().parse::<i32>().map(|i| i as i64).map_err(|_| bad_request("Failed to read HTTP message")),
        _ => Err(bad_request("Failed to read HTTP message")),
    }
}

/// A `String` field of a request class.
fn string_field(m: &JMap, f: &str) -> AppResult<JValue> {
    match m.get(f) {
        None | Some(JValue::Null) => Ok(JValue::Null),
        Some(JValue::Object(_)) | Some(JValue::Array(_)) => Err(bad_request("Failed to read HTTP message")),
        Some(v) => Ok(JValue::Str(v.java_to_string())),
    }
}

/// A `Map<String, Object>` field of a request class.
fn map_body_field(m: &JMap, f: &str) -> AppResult<Option<JMap>> {
    match m.get(f) {
        None | Some(JValue::Null) => Ok(None),
        Some(JValue::Object(o)) => Ok(Some(o.clone())),
        _ => Err(bad_request("Failed to read HTTP message")),
    }
}

fn page_reply(p: &JMap) -> Reply {
    json(JValue::Object(to_jackson(&PAGE, p)))
}

async fn patch_component(State(st): State<St>, Path((id, key)): Path<(String, String)>, RawQuery(q): RawQuery, h: HeaderMap, body: Bytes) -> Response {
    const R: &str = "/api/ui/pages/{id}/components/{componentKey}";
    let ca = match caller(&st, &h, R).await {
        Ok(ca) => ca,
        Err(r) => return r,
    };
    let r = async {
        let req = read_json(&body)?;
        let data = map_body_field(&req, "componentData")?;
        let expected = int_field(&req, "expectedComponentVersion")?;
        let message = string_field(&req, "message")?;
        let fc = ForClient::from(q.as_deref(), &h)?;
        let cx = st.cx.clone();
        let saved = patch_for_client(&st, &ca, &id, &fc, |page| {
            let comp = map_field(page, "componentDefinition").and_then(|d| d.get(&key)).and_then(JValue::as_object).cloned();
            let Some(mut comp) = comp else {
                return Err(cx.error(StatusCode::NOT_FOUND, msg::OBJECT_NOT_FOUND, &["Component", &key]));
            };
            if map_field(page, "componentVersions").is_some() && expected > 0 && version_in(page, "componentVersions", &key) != expected {
                return Err(cx.error(StatusCode::PRECONDITION_FAILED, msg::VERSION_MISMATCH, &[]));
            }
            // `objectMapper.convertValue(componentData, ComponentDefinition.class)`: no data is a
            // null component, which the field reads after it throw on.
            let Some(data) = data.clone() else {
                return Err(AppError::Internal(anyhow::anyhow!("NullPointerException: componentData")));
            };
            let updated = convert_json(&COMPONENT_DEFINITION, &data);
            for f in PATCHABLE {
                if let Some(v) = updated.get(f).filter(|v| !v.is_null()) {
                    comp.insert(f.into(), v.clone());
                }
            }
            if let Some(JValue::Object(defs)) = page.get_mut("componentDefinition") {
                defs.insert(key.clone(), JValue::Object(comp));
            }
            bump(page, "componentVersions", &key);
            let v = page.get("version").and_then(JValue::as_i64).unwrap_or(1);
            page.insert("version".into(), JValue::Int(v + 1));
            page.insert("message".into(), message.clone());
            Ok(())
        })
        .await?;
        Ok(page_reply(&saved))
    }
    .await;
    respond(R, r)
}

/// `POST /api/ui/pages/{id}/components` (`ComponentAddRequest`): a new component under an
/// existing parent; a key the page already has is refused (that is what the patch is for).
async fn add_component(State(st): State<St>, Path(id): Path<String>, RawQuery(q): RawQuery, h: HeaderMap, body: Bytes) -> Response {
    const R: &str = "/api/ui/pages/{id}/components";
    let ca = match caller(&st, &h, R).await {
        Ok(ca) => ca,
        Err(r) => return r,
    };
    let r = async {
        let req = read_json(&body)?;
        let key = string_field(&req, "componentKey")?;
        let data = map_body_field(&req, "componentData")?;
        let parent_key = string_field(&req, "parentKey")?;
        let message = string_field(&req, "message")?;
        let fc = ForClient::from(q.as_deref(), &h)?;
        let cx = st.cx.clone();
        let saved = patch_for_client(&st, &ca, &id, &fc, |page| {
            let key_text = key.java_to_string();
            let existing = map_field(page, "componentDefinition").cloned();
            let fresh = existing.is_none();
            let mut defs = existing.unwrap_or_default();
            if defs.contains_key(&key_text) {
                return Err(cx.error(StatusCode::CONFLICT, msg::ALREADY_EXISTS, &["Component", &key_text]));
            }
            let parent_text = parent_key.java_to_string();
            let parent = parent_key
                .as_str()
                .filter(|p| !p.trim().is_empty())
                .and_then(|p| defs.get(p))
                .and_then(JValue::as_object)
                .cloned();
            let Some(mut parent) = parent else {
                return Err(cx.error(StatusCode::NOT_FOUND, msg::OBJECT_NOT_FOUND, &["Component", &parent_text]));
            };
            // `objectMapper.convertValue(componentData, ComponentDefinition.class)`: no data is
            // a null component, and setting its key throws.
            let Some(data) = data.clone() else {
                return Err(AppError::Internal(anyhow::anyhow!("NullPointerException: componentData")));
            };
            let mut added = convert_json(&COMPONENT_DEFINITION, &data);
            added.insert("key".into(), key.clone());
            defs.insert(key_text.clone(), JValue::Object(added));
            // `new HashMap<>(children)`, then the put.
            let children = map_field(&parent, "children").cloned().unwrap_or_default();
            let added_child: JMap = [(key_text.clone(), JValue::Bool(true))].into_iter().collect();
            parent.insert("children".into(), JValue::Object(copy_then_put(children, added_child)));
            defs.insert(parent_text.clone(), JValue::Object(parent));
            page.insert("componentDefinition".into(), JValue::Object(java_put_order(defs, fresh)));

            let existing = map_field(page, "componentVersions").cloned();
            let fresh = existing.is_none();
            let mut cv = existing.unwrap_or_default();
            cv.insert(key_text, JValue::Int(1));
            let n = cv.get(&parent_text).and_then(JValue::as_i64).unwrap_or(1);
            cv.insert(parent_text, JValue::Int(n + 1));
            page.insert("componentVersions".into(), JValue::Object(java_put_order(cv, fresh)));

            let v = page.get("version").and_then(JValue::as_i64).unwrap_or(1);
            page.insert("version".into(), JValue::Int(v + 1));
            page.insert("message".into(), message.clone());
            Ok(())
        })
        .await?;
        Ok(page_reply(&saved))
    }
    .await;
    respond(R, r)
}

/// `DELETE /api/ui/pages/{id}/components/{componentKey}`: the component and everything under
/// it; the root component stays.
async fn remove_component(State(st): State<St>, Path((id, key)): Path<(String, String)>, RawQuery(q): RawQuery, h: HeaderMap) -> Response {
    const R: &str = "/api/ui/pages/{id}/components/{componentKey}";
    let ca = match caller(&st, &h, R).await {
        Ok(ca) => ca,
        Err(r) => return r,
    };
    let r = async {
        let fc = ForClient::from(q.as_deref(), &h)?;
        let message = Params::from_query(q.as_deref()).first("message").map(|m| JValue::Str(m.to_string())).unwrap_or_default();
        let cx = st.cx.clone();
        let saved = patch_for_client(&st, &ca, &id, &fc, |page| {
            let mut defs = match map_field(page, "componentDefinition") {
                Some(d) if d.contains_key(&key) => d.clone(),
                _ => return Err(cx.error(StatusCode::NOT_FOUND, msg::OBJECT_NOT_FOUND, &["Component", &key])),
            };
            if str_field(page, "rootComponent") == Some(key.as_str()) {
                return Err(crate::catalogue::error_as("UI.ROOT_COMPONENT_NOT_REMOVABLE", StatusCode::BAD_REQUEST, msg::OBJECT_NOT_UPDATABLE, &[]));
            }
            // The subtree, breadth first.
            let mut gone: Vec<String> = Vec::new();
            let mut todo = std::collections::VecDeque::from([key.clone()]);
            while let Some(k) = todo.pop_front() {
                if gone.contains(&k) {
                    continue;
                }
                if let Some(children) = defs.get(&k).and_then(JValue::as_object).and_then(|c| map_field(c, "children")) {
                    todo.extend(children.keys().cloned());
                }
                gone.push(k);
            }
            let existing = map_field(page, "componentVersions").cloned();
            let fresh = existing.is_none();
            let mut cv = existing.unwrap_or_default();
            for (k, comp) in defs.iter_mut() {
                if gone.contains(k) {
                    continue;
                }
                let JValue::Object(c) = comp else { continue };
                let Some(children) = map_field(c, "children").filter(|ch| ch.contains_key(&key)).cloned() else { continue };
                // `new HashMap<>(children)`, then the remove: the copy's table size orders it.
                let capacity = java_map::capacity_by_copy(children.len());
                let mut children = children;
                children.shift_remove(&key);
                c.insert("children".into(), JValue::Object(java_map::order(children, capacity)));
                let n = cv.get(k).and_then(JValue::as_i64).unwrap_or(1);
                cv.insert(k.clone(), JValue::Int(n + 1));
            }
            for g in &gone {
                defs.shift_remove(g);
                cv.shift_remove(g);
            }
            page.insert("componentDefinition".into(), JValue::Object(defs));
            page.insert("componentVersions".into(), JValue::Object(java_put_order(cv, fresh)));
            let v = page.get("version").and_then(JValue::as_i64).unwrap_or(1);
            page.insert("version".into(), JValue::Int(v + 1));
            page.insert("message".into(), message.clone());
            Ok(())
        })
        .await?;
        Ok(page_reply(&saved))
    }
    .await;
    respond(R, r)
}

async fn read_event(State(st): State<St>, Path((id, name)): Path<(String, String)>, h: HeaderMap) -> Response {
    const R: &str = "/api/ui/pages/{id}/events/{functionName}";
    let ca = match caller(&st, &h, R).await {
        Ok(ca) => ca,
        Err(r) => return r,
    };
    let r = async {
        let page = st.pages.read(&ca, &id).await?;
        Ok(match map_field(&page, "eventFunctions").and_then(|e| e.get(&name)) {
            Some(v) => json(v.clone()),
            None => Reply::empty(StatusCode::NOT_FOUND),
        })
    }
    .await;
    respond(R, r)
}

async fn put_event(State(st): State<St>, Path((id, name)): Path<(String, String)>, RawQuery(q): RawQuery, h: HeaderMap, body: Bytes) -> Response {
    const R: &str = "/api/ui/pages/{id}/events/{functionName}";
    let ca = match caller(&st, &h, R).await {
        Ok(ca) => ca,
        Err(r) => return r,
    };
    let r = async {
        let req = read_json(&body)?;
        let definition = map_body_field(&req, "definition")?;
        let expected = int_field(&req, "expectedEventVersion")?;
        let message = string_field(&req, "message")?;
        let fc = ForClient::from(q.as_deref(), &h)?;
        let cx = st.cx.clone();
        let saved = patch_for_client(&st, &ca, &id, &fc, |page| {
            if map_field(page, "eventFunctionVersions").is_some() && expected > 0 && version_in(page, "eventFunctionVersions", &name) != expected {
                return Err(cx.error(StatusCode::PRECONDITION_FAILED, msg::VERSION_MISMATCH, &[]));
            }
            let existing = map_field(page, "eventFunctions").cloned();
            let fresh = existing.is_none();
            let mut events = existing.unwrap_or_default();
            events.insert(name.clone(), definition.clone().map(JValue::Object).unwrap_or_default());
            page.insert("eventFunctions".into(), JValue::Object(java_put_order(events, fresh)));
            bump(page, "eventFunctionVersions", &name);
            let v = page.get("version").and_then(JValue::as_i64).unwrap_or(1);
            page.insert("version".into(), JValue::Int(v + 1));
            page.insert("message".into(), message.clone());
            Ok(())
        })
        .await?;
        Ok(page_reply(&saved))
    }
    .await;
    respond(R, r)
}

/// The top-level page fields a change set may set or clear. The rest are the document's
/// identity and bookkeeping, or the two maps it changes entry by entry.
const CHANGEABLE_FIELDS: [&str; 7] = ["device", "translations", "properties", "rootComponent", "permission", "description", "title"];

/// What `PATCH /api/ui/pages/{id}/changes` asks for: whole components and event functions by
/// key (null removes one), top-level fields (null clears one), and the versions of the entries
/// the caller read.
#[derive(Default)]
pub struct PageChanges {
    pub components: JMap,
    pub events: JMap,
    pub fields: JMap,
    pub expected_components: JMap,
    pub expected_events: JMap,
    pub message: JValue,
}

impl PageChanges {
    fn from_body(req: &JMap) -> AppResult<Self> {
        let changes = Self {
            components: map_body_field(req, "components")?.unwrap_or_default(),
            events: map_body_field(req, "eventFunctions")?.unwrap_or_default(),
            fields: map_body_field(req, "fields")?.unwrap_or_default(),
            expected_components: map_body_field(req, "expectedComponentVersions")?.unwrap_or_default(),
            expected_events: map_body_field(req, "expectedEventVersions")?.unwrap_or_default(),
            message: string_field(req, "message")?,
        };
        if let Some(f) = changes.fields.keys().find(|f| !CHANGEABLE_FIELDS.contains(&f.as_str())) {
            return Err(bad_request(&format!("Field '{f}' cannot be changed here.")));
        }
        let entries = changes.components.values().chain(changes.events.values());
        if entries.into_iter().any(|v| !matches!(v, JValue::Object(_) | JValue::Null)) {
            return Err(bad_request("Failed to read HTTP message"));
        }
        Ok(changes)
    }

    pub fn is_empty(&self) -> bool {
        self.components.is_empty() && self.events.is_empty() && self.fields.is_empty()
    }
}

fn expected_of(m: &JMap, key: &str) -> i64 {
    m.get(key).and_then(JValue::as_i64).unwrap_or(0)
}

/// Applies a change set to a page: only the named entries move, every other component, event
/// function and field stays as the page has it. A version the caller read that is no longer the
/// entry's answers 412, before anything changes.
pub fn apply_page_changes(page: &mut JMap, ch: &PageChanges) -> Result<(), &'static str> {
    for (k, _) in ch.components.iter() {
        let expected = expected_of(&ch.expected_components, k);
        if map_field(page, "componentVersions").is_some() && expected > 0 && version_in(page, "componentVersions", k) != expected {
            return Err("component");
        }
    }
    for (k, _) in ch.events.iter() {
        let expected = expected_of(&ch.expected_events, k);
        if map_field(page, "eventFunctionVersions").is_some() && expected > 0 && version_in(page, "eventFunctionVersions", k) != expected {
            return Err("event");
        }
    }
    if !ch.components.is_empty() {
        let existing = map_field(page, "componentDefinition").cloned();
        let fresh = existing.is_none();
        let mut defs = existing.unwrap_or_default();
        for (k, v) in ch.components.iter() {
            match v {
                JValue::Object(c) => {
                    let mut comp = convert_json(&COMPONENT_DEFINITION, c);
                    comp.insert("key".into(), JValue::Str(k.clone()));
                    defs.insert(k.clone(), JValue::Object(comp));
                }
                _ => {
                    defs.shift_remove(k);
                }
            }
        }
        page.insert("componentDefinition".into(), JValue::Object(java_put_order(defs, fresh)));
        for (k, v) in ch.components.iter() {
            if v.is_null() {
                if let Some(JValue::Object(cv)) = page.get_mut("componentVersions") {
                    cv.shift_remove(k);
                }
            } else {
                bump(page, "componentVersions", k);
            }
        }
    }
    if !ch.events.is_empty() {
        let existing = map_field(page, "eventFunctions").cloned();
        let fresh = existing.is_none();
        let mut events = existing.unwrap_or_default();
        for (k, v) in ch.events.iter() {
            if v.is_null() {
                events.shift_remove(k);
            } else {
                events.insert(k.clone(), v.clone());
            }
        }
        page.insert("eventFunctions".into(), JValue::Object(java_put_order(events, fresh)));
        for (k, v) in ch.events.iter() {
            if v.is_null() {
                if let Some(JValue::Object(ev)) = page.get_mut("eventFunctionVersions") {
                    ev.shift_remove(k);
                }
            } else {
                bump(page, "eventFunctionVersions", k);
            }
        }
    }
    for (f, v) in ch.fields.iter() {
        if v.is_null() {
            page.shift_remove(f);
        } else {
            page.insert(f.clone(), v.clone());
        }
    }
    let v = page.get("version").and_then(JValue::as_i64).unwrap_or(1);
    page.insert("version".into(), JValue::Int(v + 1));
    page.insert("message".into(), ch.message.clone());
    Ok(())
}

/// `PATCH /api/ui/pages/{id}/changes`: several components, event functions and top-level
/// fields of a page in one write, through the same for-a-client path as the component and
/// event routes (`clientCode`, `standalone`, `draft`, and `draftVersion` for the draft's
/// version), so a client's copy stores only what changed instead of a whole page. A draft
/// write answers the draft's new version in `X-Draft-Version`.
async fn patch_changes(State(st): State<St>, Path(id): Path<String>, RawQuery(q): RawQuery, h: HeaderMap, body: Bytes) -> Response {
    const R: &str = "/api/ui/pages/{id}/changes";
    let ca = match caller(&st, &h, R).await {
        Ok(ca) => ca,
        Err(r) => return r,
    };
    let r = async {
        let req = read_json(&body)?;
        let changes = PageChanges::from_body(&req)?;
        if changes.is_empty() {
            return Err(bad_request("No changes."));
        }
        let fc = ForClient::from(q.as_deref(), &h)?;
        let cx = st.cx.clone();
        let (saved, draft_version) = patch_for_client_versioned(&st, &ca, &id, &fc, |page| {
            apply_page_changes(page, &changes).map_err(|_| cx.error(StatusCode::PRECONDITION_FAILED, msg::VERSION_MISMATCH, &[]))
        })
        .await?;
        let reply = page_reply(&saved);
        Ok(match draft_version {
            Some(v) => reply.header(DRAFT_VERSION_HEADER, v.to_string()),
            None => reply,
        })
    }
    .await;
    respond(R, r)
}

// ── FunctionController ──────────────────────────────────────────────

async fn read_steps(State(st): State<St>, Path(id): Path<String>, RawQuery(q): RawQuery, h: HeaderMap) -> Response {
    const R: &str = "/api/ui/functions/{id}/steps";
    let ca = match caller(&st, &h, R).await {
        Ok(ca) => ca,
        Err(r) => return r,
    };
    let r = async {
        let p = Params::from_query(q.as_deref());
        let names = list_param(&p, "names").unwrap_or_default();
        let f = st.functions.read(&ca, &id).await?;
        let steps = map_field(&f, "definition").and_then(|d| d.get("steps")).and_then(JValue::as_object);
        let Some(steps) = steps else { return Ok(json(JValue::Object(JMap::new()))) };
        if names.is_empty() {
            return Ok(json(JValue::Object(steps.clone())));
        }
        let picked: JMap = names
            .iter()
            .filter_map(|n| steps.get(n).filter(|v| !v.is_null()).map(|v| (n.clone(), v.clone())))
            .collect();
        Ok(json(JValue::Object(java_map::by_puts(picked))))
    }
    .await;
    respond(R, r)
}

async fn patch_steps(State(st): State<St>, Path(id): Path<String>, h: HeaderMap, body: Bytes) -> Response {
    const R: &str = "/api/ui/functions/{id}/steps";
    let ca = match caller(&st, &h, R).await {
        Ok(ca) => ca,
        Err(r) => return r,
    };
    let r = async {
        let req = read_json(&body)?;
        let class_cast = || AppError::Internal(anyhow::anyhow!("ClassCastException"));
        let steps = match req.get("steps") {
            None => JMap::new(),
            Some(JValue::Object(m)) => m.clone(),
            Some(_) => return Err(class_cast()),
        };
        let message = match req.get("message") {
            None => JValue::Str("Step update".into()),
            Some(JValue::Str(s)) => JValue::Str(s.clone()),
            Some(JValue::Null) => JValue::Null,
            Some(_) => return Err(class_cast()),
        };
        let expected = match req.get("expectedVersion") {
            None => 0,
            Some(JValue::Int(i)) => *i as i32 as i64,
            Some(JValue::Float(x)) => *x as i32 as i64,
            Some(JValue::Null) => return Err(AppError::Internal(anyhow::anyhow!("NullPointerException"))),
            Some(_) => return Err(class_cast()),
        };
        let mut f = st.functions.read(&ca, &id).await?;
        if expected > 0 && f.get("version").and_then(JValue::as_i64) != Some(expected) {
            return Err(crate::catalogue::literal("UI.FUNCTION_VERSION_MISMATCH", StatusCode::PRECONDITION_FAILED, "Version mismatch").into());
        }
        let mut definition = map_field(&f, "definition").cloned().unwrap_or_default();
        let current = definition.get("steps").and_then(JValue::as_object).cloned().unwrap_or_default();
        definition.insert("steps".into(), JValue::Object(copy_then_put(current, steps)));
        f.insert("definition".into(), JValue::Object(definition));
        f.insert("message".into(), message);
        let updated = st.functions.update(&ca, f).await?;
        Ok(json(JValue::Object(to_jackson(&FUNCTION, &updated))))
    }
    .await;
    respond(R, r)
}
