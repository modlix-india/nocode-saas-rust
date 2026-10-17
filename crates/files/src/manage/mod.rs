//! files-manage routes: everything that is not a plain read.
//!
//! | Spring pattern | Handler |
//! |---|---|
//! | `GET/DELETE/POST /api/files/{static,secured}/**`, `.../directory/**`, `.../import/**`, `.../export/**`, `.../exports`, `.../imports`, `/static/copyToClientPage`, `/secured/createKey/**` | [`resources`] |
//! | `POST /api/files/transform/{resourceType}/**`, `/api/files/generic/*` | [`generic`] |
//! | `/api/files/internal/*` (bar the file read) | [`internal`] |
//! | `/api/files/accesspath/**`, `/api/files/retention/**` | here |
//!
//! Paths are matched from the first `/api/files/` in the URI, as the Java services resolve them,
//! and in Spring's precedence: an exact route before a `/**` one.

mod generic;
mod internal;
mod resources;

use axum::extract::Request;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use platform::error::{AppError, AppResult};
use platform::http::with_route;
use platform::security::{CallerContext, ContextAuthentication, SecurityRefused};

use crate::jackson;
use crate::paths::Kind;
use crate::spring::{Pageable, Params};
use crate::state::AppState;
use crate::upload::read_json;

/// The route a request takes, with the Spring pattern it reports.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Route {
    List(Kind),
    Delete(Kind),
    Directory(Kind),
    Upload(Kind),
    Import(Kind),
    Export(Kind),
    Exports(Kind),
    Imports(Kind),
    CopyToClientPage,
    CreateKey,
    Transform(Kind),
    GenericClient,
    GenericUser,
    GenericResize,
    GenericPopulate,
    GenericBase64,
    GenericBase64Details,
    InternalCreateKey,
    InternalUpload(Kind),
    InternalCleanup(Kind),
    InternalRetention(Kind),
    InternalBase64(Kind),
    InternalAiUploader,
    InternalAccessPath,
    BillingMeter,
    BillingReconcile,
    AccessCreate,
    AccessList,
    AccessQuery,
    AccessRead(String),
    AccessPut(String),
    AccessPatch(String),
    AccessDelete(String),
    RetentionList,
    RetentionCreate,
    RetentionUpdate(String),
    RetentionDelete(String),
    RetentionEffective,
    RetentionPreview,
    MethodNotAllowed(&'static str),
}

fn kind_of(s: &str) -> Kind {
    if s == "secured" {
        Kind::Secured
    } else {
        Kind::Static
    }
}

fn pick(kind: Kind, s: &'static str, sec: &'static str) -> &'static str {
    if kind == Kind::Secured {
        sec
    } else {
        s
    }
}

impl Route {
    fn template(&self) -> &'static str {
        use Route::*;
        match self {
            List(k) | Delete(k) | Upload(k) => pick(*k, "/api/files/static/**", "/api/files/secured/**"),
            Directory(k) => pick(*k, "/api/files/static/directory/**", "/api/files/secured/directory/**"),
            Import(k) => pick(*k, "/api/files/static/import/**", "/api/files/secured/import/**"),
            Export(k) => pick(*k, "/api/files/static/export/**", "/api/files/secured/export/**"),
            Exports(k) => pick(*k, "/api/files/static/exports", "/api/files/secured/exports"),
            Imports(k) => pick(*k, "/api/files/static/imports", "/api/files/secured/imports"),
            CopyToClientPage => "/api/files/static/copyToClientPage",
            CreateKey => "/api/files/secured/createKey/**",
            Transform(_) => "/api/files/transform/{resourceType}/**",
            GenericClient => "/api/files/generic/client",
            GenericUser => "/api/files/generic/user",
            GenericResize => "/api/files/generic/resize",
            GenericPopulate => "/api/files/generic/internal/fs/populate",
            GenericBase64 => "/api/files/generic/convertToBase64",
            GenericBase64Details => "/api/files/generic/convertToBase64WithDetails",
            InternalCreateKey => "/api/files/internal/secured/createKey",
            InternalUpload(_) => "/api/files/internal/{resourceType}",
            InternalCleanup(_) => "/api/files/internal/{resourceType}/cleanupExpired",
            InternalRetention(_) => "/api/files/internal/{resourceType}/applyRetention",
            InternalBase64(_) => "/api/files/internal/{resourceType}/convertToBase64",
            InternalAiUploader => "/api/files/internal/aiUploader",
            InternalAccessPath => "/api/files/internal/accesspath",
            BillingMeter => "/api/files/internal/billing/meter",
            BillingReconcile => "/api/files/internal/billing/reconcile",
            AccessCreate | AccessList => "/api/files/accesspath",
            AccessQuery => "/api/files/accesspath/query",
            AccessRead(_) | AccessPut(_) | AccessPatch(_) | AccessDelete(_) => "/api/files/accesspath/{id}",
            RetentionList | RetentionCreate => "/api/files/retention",
            RetentionUpdate(_) | RetentionDelete(_) => "/api/files/retention/{id}",
            RetentionEffective => "/api/files/retention/effective",
            RetentionPreview => "/api/files/retention/preview",
            MethodNotAllowed(t) => t,
        }
    }

    /// The routes Spring Security lets through without a signed-in caller.
    fn is_public(&self) -> bool {
        use Route::*;
        matches!(
            self,
            GenericPopulate
                | InternalCreateKey
                | InternalUpload(_)
                | InternalCleanup(_)
                | InternalRetention(_)
                | InternalBase64(_)
                | InternalAiUploader
                | InternalAccessPath
                | BillingMeter
                | BillingReconcile
        )
    }
}

/// `rest` is the path after the first `/api/files/`.
fn route(method: &Method, rest: &str) -> Option<Route> {
    use Route::*;
    let get = method == Method::GET || method == Method::HEAD;
    let post = method == Method::POST;

    for (name, kind) in [("static", Kind::Static), ("secured", Kind::Secured)] {
        let Some(sub) = rest.strip_prefix(name) else { continue };
        if !(sub.is_empty() || sub.starts_with('/')) {
            continue;
        }
        let under = |p: &str| sub == p || sub.starts_with(&format!("{p}/"));
        return Some(if get {
            if sub == "/exports" {
                Exports(kind)
            } else if sub == "/imports" {
                Imports(kind)
            } else if under("/export") {
                Export(kind)
            } else if kind == Kind::Secured && under("/createKey") {
                CreateKey
            } else {
                List(kind)
            }
        } else if method == Method::DELETE {
            Delete(kind)
        } else if post {
            if under("/directory") {
                Directory(kind)
            } else if under("/import") {
                Import(kind)
            } else if kind == Kind::Static && sub == "/copyToClientPage" {
                CopyToClientPage
            } else {
                Upload(kind)
            }
        } else {
            MethodNotAllowed(pick(kind, "/api/files/static/**", "/api/files/secured/**"))
        });
    }

    if let Some(t) = rest.strip_prefix("transform/") {
        let ty = t.split('/').next().unwrap_or("");
        if ty.is_empty() {
            return None;
        }
        return Some(if post { Transform(kind_of(ty)) } else { MethodNotAllowed("/api/files/transform/{resourceType}/**") });
    }

    if let Some(g) = rest.strip_prefix("generic/") {
        return match (g, post, get) {
            ("client", true, _) => Some(GenericClient),
            ("user", true, _) => Some(GenericUser),
            ("resize", true, _) => Some(GenericResize),
            ("convertToBase64", true, _) => Some(GenericBase64),
            ("convertToBase64WithDetails", true, _) => Some(GenericBase64Details),
            ("internal/fs/populate", _, true) => Some(GenericPopulate),
            _ => None,
        };
    }

    if let Some(i) = rest.strip_prefix("internal/") {
        let segs: Vec<&str> = i.split('/').collect();
        return match (segs.as_slice(), post, get) {
            (["secured", "createKey"], _, true) => Some(InternalCreateKey),
            (["accesspath"], true, _) => Some(InternalAccessPath),
            (["aiUploader"], true, _) => Some(InternalAiUploader),
            (["billing", "meter"], true, _) => Some(BillingMeter),
            (["billing", "reconcile"], true, _) => Some(BillingReconcile),
            ([t], true, _) if !t.is_empty() => Some(InternalUpload(kind_of(t))),
            ([t, "cleanupExpired"], true, _) => Some(InternalCleanup(kind_of(t))),
            ([t, "applyRetention"], true, _) => Some(InternalRetention(kind_of(t))),
            ([t, "convertToBase64"], _, true) => Some(InternalBase64(kind_of(t))),
            _ => None,
        };
    }

    if rest == "accesspath" {
        return Some(if post { AccessCreate } else if get { AccessList } else { MethodNotAllowed("/api/files/accesspath") });
    }
    if let Some(id) = rest.strip_prefix("accesspath/") {
        if id.is_empty() || id.contains('/') {
            return None;
        }
        if id == "query" && post {
            return Some(AccessQuery);
        }
        let id = id.to_string();
        return Some(match *method {
            Method::GET | Method::HEAD => AccessRead(id),
            Method::PUT => AccessPut(id),
            Method::PATCH => AccessPatch(id),
            Method::DELETE => AccessDelete(id),
            _ => MethodNotAllowed("/api/files/accesspath/{id}"),
        });
    }

    if rest == "retention" {
        return Some(if post { RetentionCreate } else if get { RetentionList } else { MethodNotAllowed("/api/files/retention") });
    }
    if let Some(sub) = rest.strip_prefix("retention/") {
        return match (sub, method.clone()) {
            ("effective", m) if m == Method::GET => Some(RetentionEffective),
            ("preview", m) if m == Method::GET => Some(RetentionPreview),
            (id, Method::PUT) if !id.is_empty() && !id.contains('/') => Some(RetentionUpdate(id.to_string())),
            (id, Method::DELETE) if !id.is_empty() && !id.contains('/') => Some(RetentionDelete(id.to_string())),
            _ => None,
        };
    }
    None
}

/// What every handler gets.
pub(crate) struct Ctx {
    pub st: AppState,
    /// The raw request path, as `getRequestURI()` returns it.
    pub uri: String,
    pub params: Params,
    /// The signed-in caller; `None` on the public routes.
    pub ca: Option<ContextAuthentication>,
}

impl Ctx {
    pub fn ca(&self) -> &ContextAuthentication {
        self.ca.as_ref().expect("route requires a caller")
    }

    /// `CommonsUtil.nonNullValue(clientCode, ca.getClientCode(), ca.getLoggedInFromClientCode())`.
    pub fn client_code(&self) -> String {
        if let Some(cc) = self.params.get("clientCode") {
            return cc.to_string();
        }
        let ca = self.ca();
        ca.client_code
            .clone()
            .or_else(|| ca.logged_in_from_client_code.clone())
            .unwrap_or_default()
    }

    pub fn user_id(&self) -> u64 {
        self.ca.as_ref().map(|c| c.user.id).unwrap_or(0)
    }
}

/// The caller as `JWTTokenFilter` sees it; anonymous or refused is Spring Security's 403 (empty
/// in Java, here saying to sign in).
async fn signed_in(st: &AppState, h: &HeaderMap) -> AppResult<ContextAuthentication> {
    let caller = CallerContext::from_headers(h, st.server_port());
    let ca = match st.security().context_authentication(&caller).await {
        Ok(ca) => ca,
        Err(e) if e.downcast_ref::<SecurityRefused>().is_some() => return Err(crate::errors::sign_in(true)),
        Err(e) => return Err(AppError::Internal(e)),
    };
    if !ca.authenticated {
        return Err(crate::errors::sign_in(false));
    }
    Ok(ca)
}

pub async fn dispatch(state: AppState, _q: std::collections::HashMap<String, String>, req: Request) -> Response {
    let uri = req.uri().path().to_string();
    let Some(at) = uri.find("/api/files/") else {
        return with_route(StatusCode::NOT_FOUND.into_response(), "unmatched");
    };
    let rest = uri[at + "/api/files/".len()..].to_string();
    let Some(r) = route(req.method(), &rest) else {
        return with_route(StatusCode::NOT_FOUND.into_response(), "unmatched");
    };
    let template = r.template();
    let result = handle(state, r, uri, req).await;
    with_route(result.unwrap_or_else(crate::errors::respond), template)
}

async fn handle(st: AppState, r: Route, uri: String, req: Request) -> AppResult<Response> {
    if let Route::MethodNotAllowed(_) = r {
        return Err(AppError::Empty(StatusCode::METHOD_NOT_ALLOWED));
    }
    let headers = req.headers().clone();
    let ca = if r.is_public() { None } else { Some(signed_in(&st, &headers).await?) };
    let params = Params::from_query(req.uri().query());
    let mut cx = Ctx { st, uri, params, ca };

    use Route::*;
    match r {
        List(k) => resources::list(&cx, k).await,
        Delete(k) => resources::delete(&cx, k).await,
        Directory(k) => resources::directory(&cx, k).await,
        Upload(k) => resources::upload(&mut cx, k, req).await,
        Import(k) => resources::import(&mut cx, k, req).await,
        Export(k) => resources::export(&cx, k).await,
        Exports(k) => resources::jobs(&cx, k, false).await,
        Imports(k) => resources::jobs(&cx, k, true).await,
        CopyToClientPage => resources::copy_to_client_page(&cx, req).await,
        CreateKey => resources::create_key(&cx).await,
        Transform(k) => generic::transform(&mut cx, k, req).await,
        GenericClient => generic::client_image(&mut cx, req).await,
        GenericUser => generic::user_image(&mut cx, req).await,
        GenericResize => generic::resize(&mut cx, req).await,
        GenericPopulate => generic::populate(&cx).await,
        GenericBase64 => generic::base64(&mut cx, req, false).await,
        GenericBase64Details => generic::base64(&mut cx, req, true).await,
        InternalCreateKey => internal::create_key(&cx).await,
        InternalUpload(k) => internal::upload(&cx, k, req).await,
        InternalCleanup(k) => internal::cleanup(&cx, k).await,
        InternalRetention(k) => internal::retention(&cx, k).await,
        InternalBase64(k) => internal::base64(&cx, k).await,
        InternalAiUploader => internal::ai_uploader(&mut cx, req).await,
        InternalAccessPath => {
            let body = read_json(req.into_body()).await?;
            Ok(jackson::json(&crate::accesspath::create_internal(&cx.st, &body).await?))
        }
        BillingMeter => Ok(jackson::json(&crate::billing::meter(&cx.st).await.map_err(AppError::Internal)?.into())),
        BillingReconcile => internal::reconcile(&cx).await,
        AccessCreate => {
            let body = read_json(req.into_body()).await?;
            Ok(jackson::json(&crate::accesspath::create(&cx.st, cx.ca(), &body).await?))
        }
        AccessList => {
            let page = Pageable::from_params(&cx.params);
            let cond = crate::condition::from_params(&cx.params.0);
            Ok(jackson::json(&crate::accesspath::page(&cx.st, cx.ca(), &page, cond).await?))
        }
        AccessQuery => {
            let body = read_json(req.into_body()).await?;
            let (page, cond) = crate::accesspath::query_from_json(&body)?;
            Ok(jackson::json(&crate::accesspath::page(&cx.st, cx.ca(), &page, cond).await?))
        }
        AccessRead(id) => Ok(jackson::json(&crate::accesspath::read(&cx.st, cx.ca(), parse_id(&id)?).await?)),
        AccessPut(id) => {
            let body = read_json(req.into_body()).await?;
            Ok(jackson::json(&crate::accesspath::put(&cx.st, cx.ca(), parse_id(&id)?, &body).await?))
        }
        AccessPatch(id) => {
            let body = read_json(req.into_body()).await?;
            Ok(jackson::json(&crate::accesspath::patch(&cx.st, cx.ca(), parse_id(&id)?, &body).await?))
        }
        AccessDelete(id) => {
            crate::accesspath::delete(&cx.st, cx.ca(), parse_id(&id)?).await?;
            Ok(jackson::no_content())
        }
        RetentionList => Ok(jackson::json(
            &crate::retention::list(&cx.st, cx.ca(), cx.params.get("appCode"), cx.params.get("clientCode")).await?,
        )),
        RetentionCreate => {
            let body = read_json(req.into_body()).await?;
            Ok(jackson::json(&crate::retention::create(&cx.st, cx.ca(), &body).await?))
        }
        RetentionUpdate(id) => {
            let body = read_json(req.into_body()).await?;
            Ok(jackson::json(&crate::retention::update(&cx.st, cx.ca(), parse_id(&id)?, &body).await?))
        }
        RetentionDelete(id) => {
            Ok(jackson::json(&crate::retention::delete(&cx.st, cx.ca(), parse_id(&id)?).await?))
        }
        RetentionEffective => Ok(jackson::json(
            &crate::retention::effective(
                &cx.st,
                cx.ca(),
                cx.params.get("appCode"),
                cx.params.get("clientCode"),
                cx.params.get("resourceType"),
            )
            .await?,
        )),
        RetentionPreview => {
            let days = opt_i64(&cx.params, "days")?;
            Ok(jackson::json(
                &crate::retention::preview(
                    &cx.st,
                    cx.ca(),
                    cx.params.get("appCode"),
                    cx.params.get("resourceType"),
                    cx.params.get("path"),
                    cx.params.get("clientCode"),
                    days,
                )
                .await?,
            ))
        }
        MethodNotAllowed(_) => Err(AppError::Empty(StatusCode::METHOD_NOT_ALLOWED)),
    }
}

/// A path id: a 400 when it is not a number (Java's binder answers with a 500).
fn parse_id(s: &str) -> AppResult<u64> {
    s.parse().map_err(|_| crate::errors::param_invalid("id", format!("Invalid id '{s}'")))
}

/// An optional numeric parameter; empty is absent, as Spring binds it.
pub(crate) fn opt_i64(p: &Params, name: &str) -> AppResult<Option<i64>> {
    match p.get(name).map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(v) => v
            .parse()
            .map(Some)
            .map_err(|_| crate::errors::param_invalid(name, format!("Invalid value '{v}' for parameter '{name}'"))),
    }
}

/// A required parameter (Java answers a missing one with a 500).
pub(crate) fn required<'a>(p: &'a Params, name: &str) -> AppResult<&'a str> {
    p.get(name).ok_or_else(|| crate::errors::param_missing(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use Route::*;

    fn r(m: Method, p: &str) -> Option<Route> {
        route(&m, p)
    }

    #[test]
    fn resource_routes_in_spring_precedence() {
        assert_eq!(r(Method::GET, "static/x/y"), Some(List(Kind::Static)));
        assert_eq!(r(Method::GET, "static"), Some(List(Kind::Static)));
        assert_eq!(r(Method::GET, "static/exports"), Some(Exports(Kind::Static)));
        assert_eq!(r(Method::GET, "static/exports/"), Some(List(Kind::Static)));
        assert_eq!(r(Method::GET, "secured/export/a"), Some(Export(Kind::Secured)));
        assert_eq!(r(Method::GET, "secured/createKey/file/CC/a.pdf"), Some(CreateKey));
        assert_eq!(r(Method::GET, "static/createKey/x"), Some(List(Kind::Static)));
        assert_eq!(r(Method::POST, "static/directory/a"), Some(Directory(Kind::Static)));
        assert_eq!(r(Method::POST, "secured/import/a"), Some(Import(Kind::Secured)));
        assert_eq!(r(Method::POST, "static/copyToClientPage"), Some(CopyToClientPage));
        assert_eq!(r(Method::POST, "secured/copyToClientPage"), Some(Upload(Kind::Secured)));
        assert_eq!(r(Method::POST, "static/a/b"), Some(Upload(Kind::Static)));
        assert_eq!(r(Method::DELETE, "static/a"), Some(Delete(Kind::Static)));
        assert_eq!(r(Method::GET, "staticx/a"), None);
    }

    #[test]
    fn other_routes() {
        assert_eq!(r(Method::POST, "transform/secured/a/b.png"), Some(Transform(Kind::Secured)));
        assert_eq!(r(Method::POST, "internal/static"), Some(InternalUpload(Kind::Static)));
        assert_eq!(r(Method::POST, "internal/accesspath"), Some(InternalAccessPath));
        assert_eq!(r(Method::POST, "internal/aiUploader"), Some(InternalAiUploader));
        assert_eq!(r(Method::POST, "internal/billing/meter"), Some(BillingMeter));
        assert_eq!(r(Method::POST, "internal/secured/cleanupExpired"), Some(InternalCleanup(Kind::Secured)));
        assert_eq!(r(Method::GET, "internal/secured/createKey"), Some(InternalCreateKey));
        assert_eq!(r(Method::GET, "internal/static/convertToBase64"), Some(InternalBase64(Kind::Static)));
        assert_eq!(r(Method::POST, "accesspath/query"), Some(AccessQuery));
        assert_eq!(r(Method::GET, "accesspath/query"), Some(AccessRead("query".into())));
        assert_eq!(r(Method::DELETE, "accesspath/7"), Some(AccessDelete("7".into())));
        assert_eq!(r(Method::GET, "accesspath/"), None);
        assert_eq!(r(Method::GET, "retention/effective"), Some(RetentionEffective));
        assert_eq!(r(Method::PUT, "retention/3"), Some(RetentionUpdate("3".into())));
        assert_eq!(r(Method::GET, "generic/internal/fs/populate"), Some(GenericPopulate));
        assert!(GenericPopulate.is_public() && !List(Kind::Static).is_public());
    }
}
