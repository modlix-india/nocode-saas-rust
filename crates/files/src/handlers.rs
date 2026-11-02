//! The routes of the files-serve unit: every way a file is read.
//!
//! | Route (the Spring pattern, also the metric `uri`) | Auth |
//! |---|---|
//! | `GET /api/files/static/file/**` | none, and no call to security either |
//! | `GET /api/files/secured/file/**` | caller must be signed in and allowed the path |
//! | `GET /api/files/secured/downloadFileByKey/{key}` | the key |
//! | `GET /api/files/internal/{resourceType}/file?filePath=` | none (nginx blocks `/internal` publicly) |
//!
//! Paths are matched anywhere in the URI, as the Java service's `indexOf` does, so a request the
//! gateway forwards with its `/<x>/<app>/<client>` prefix still resolves.

use std::collections::HashMap;

use axum::extract::{DefaultBodyLimit, Query, Request, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use platform::error::{AppError, AppResult};
use platform::http::with_route;
use platform::security::{CallerContext, SecurityRefused};

use crate::access::can_read_secured;
use crate::download::respond;
use crate::errors;
use crate::options::DownloadOptions;
use crate::paths::{has_dot_segment, legacy_key_path, make_tuple, resolve_with_client_code, Kind};
use crate::state::AppState;
use crate::Unit;


pub const ROUTE_STATIC: &str = "/api/files/static/file/**";
pub const ROUTE_SECURED: &str = "/api/files/secured/file/**";
pub const ROUTE_KEY: &str = "/api/files/secured/downloadFileByKey/{key}";
pub const ROUTE_INTERNAL: &str = "/api/files/internal/{resourceType}/file";

enum Route<'a> {
    Static,
    Secured,
    Key(&'a str),
    Internal(&'a str),
}

fn route(path: &str) -> Option<Route<'_>> {
    if path.contains("/api/files/static/file/") {
        return Some(Route::Static);
    }
    if path.contains("/api/files/secured/file/") {
        return Some(Route::Secured);
    }
    if let Some(i) = path.find("/api/files/secured/downloadFileByKey/") {
        let key = &path[i + "/api/files/secured/downloadFileByKey/".len()..];
        if !key.is_empty() && !key.contains('/') {
            return Some(Route::Key(key));
        }
    }
    if let Some(i) = path.find("/api/files/internal/") {
        let rest = &path[i + "/api/files/internal/".len()..];
        if let Some((kind, "file")) = rest.split_once('/') {
            return Some(Route::Internal(kind));
        }
    }
    None
}

/// The unit's routes. Matching is by hand rather than by axum patterns because the Java
/// controllers match `**` anywhere in the path, and one dispatcher keeps the precedence the
/// same as Spring's.
pub fn router(unit: Unit, state: AppState) -> Router {
    // files' own Spring Security header set (frameable by the apps that show its files).
    platform::http::set_header_style(platform::http::HeaderStyle::Files);
    Router::new()
        .fallback(move |s: State<AppState>, q: Query<HashMap<String, String>>, req: Request| dispatch(unit, s, q, req))
        // Uploads have no size limit, as in Java (`spring.servlet.multipart.max-file-size: -1`);
        // bodies are streamed to disk, never held in memory.
        .layer(DefaultBodyLimit::disable())
        .with_state(state)
}

async fn dispatch(unit: Unit, State(state): State<AppState>, Query(q): Query<HashMap<String, String>>, req: Request) -> Response {
    let is_read = req.method() == Method::GET || req.method() == Method::HEAD;
    let path = req.uri().path().to_string();

    let r = if is_read { route(&path) } else { None };
    let Some(r) = r else {
        if unit == Unit::Manage {
            return crate::manage::dispatch(state, q, req).await;
        }
        return with_route(StatusCode::NOT_FOUND.into_response(), "unmatched");
    };
    let headers = req.headers().clone();

    let (template, result) = match r {
        Route::Static => (ROUTE_STATIC, static_file(&state, &path, &q, &headers).await),
        Route::Secured => (ROUTE_SECURED, secured_file(&state, &path, &q, &headers).await),
        Route::Key(k) => (ROUTE_KEY, by_key(&state, k, &q, &headers).await),
        Route::Internal(kind) => (ROUTE_INTERNAL, internal_file(&state, kind, &q, &headers).await),
    };
    with_route(result.unwrap_or_else(crate::errors::respond), template)
}

async fn static_file(state: &AppState, path: &str, q: &HashMap<String, String>, h: &HeaderMap) -> AppResult<Response> {
    let options = DownloadOptions::from_query(q)?;
    let (rp, _) = resolve_with_client_code(path, Kind::Static).ok_or(AppError::Empty(StatusCode::NOT_FOUND))?;
    let detail = state
        .file_detail(Kind::Static, &rp)
        .await?
        .ok_or(AppError::Empty(StatusCode::NOT_FOUND))?;
    respond(state, Kind::Static, &rp, &detail, &options, h).await
}

async fn secured_file(state: &AppState, path: &str, q: &HashMap<String, String>, h: &HeaderMap) -> AppResult<Response> {
    let caller = CallerContext::from_headers(h, state.server_port());
    let ca = match state.security().context_authentication(&caller).await {
        Ok(ca) => ca,
        // Security turning the token down is the caller's problem, not a server fault.
        Err(e) if e.downcast_ref::<SecurityRefused>().is_some() => {
            return Err(errors::sign_in(true));
        }
        Err(e) => return Err(AppError::Internal(e)),
    };
    // `.anyRequest().authenticated()`: Spring Security's anonymous refusal (an empty 403 in Java).
    if !ca.authenticated {
        return Err(errors::sign_in(false));
    }

    let options = DownloadOptions::from_query(q)?;
    let (rp, _) = resolve_with_client_code(path, Kind::Secured).ok_or(AppError::Empty(StatusCode::NOT_FOUND))?;

    if !can_read_secured(state, &ca, &rp).await? {
        return Err(errors::status(StatusCode::FORBIDDEN, errors::FORBIDDEN_PATH, &["SECURED", &rp]));
    }

    let detail = state
        .file_detail(Kind::Secured, &rp)
        .await?
        .ok_or(AppError::Empty(StatusCode::NOT_FOUND))?;
    respond(state, Kind::Secured, &rp, &detail, &options, h).await
}

/// `downloadFileByKey`. An unknown key is a 404 `invalid_key` here; Java dereferences the
/// missing row and answers 500.
async fn by_key(state: &AppState, key: &str, q: &HashMap<String, String>, h: &HeaderMap) -> AppResult<Response> {
    let options = DownloadOptions::from_query(q)?;
    let invalid = || errors::status(StatusCode::NOT_FOUND, errors::INVALID_KEY, &[]);

    let rec = state.dao().access_key(key).await?.ok_or_else(invalid)?;
    if chrono::Utc::now() >= rec.access_till {
        return Err(invalid());
    }
    if let Some(limit) = rec.access_limit {
        if rec.accessed_count >= limit || !state.dao().increment_access_count(rec.id).await? {
            return Err(invalid());
        }
    }

    let (path, detail) = key_file(state, &rec).await?.ok_or(AppError::Empty(StatusCode::NOT_FOUND))?;
    respond(state, Kind::Secured, &path, &detail, &options, h).await
}

/// The file a key opens: the stored path as is; for a key made before CXZ-1138 (no
/// `CREATED_BY`, the path still URL encoded) that is not there, the decoded path, which is the
/// file the `createKey` URL named. A key made since holds the decoded path and is never decoded
/// again (a file named `a%20b.pdf` must not open `a b.pdf`, which the caller was not checked for).
async fn key_file(state: &AppState, rec: &crate::dao::AccessKey) -> AppResult<Option<(String, crate::dao::FileDetail)>> {
    if has_dot_segment(&rec.path) {
        return Ok(None);
    }
    if let Some(d) = state.file_detail(Kind::Secured, &rec.path).await? {
        return Ok(Some((rec.path.clone(), d)));
    }
    if rec.created_by.is_some() {
        return Ok(None);
    }
    let Some(decoded) = legacy_key_path(&rec.path) else { return Ok(None) };
    Ok(state.file_detail(Kind::Secured, &decoded).await?.map(|d| (decoded, d)))
}

/// `FilesInternalController.downloadFile`: service-to-service reads, no checks.
async fn internal_file(state: &AppState, kind: &str, q: &HashMap<String, String>, h: &HeaderMap) -> AppResult<Response> {
    let kind = if kind == "secured" { Kind::Secured } else { Kind::Static };
    let options = DownloadOptions::from_query(q)?;
    let file_path = q
        .get("filePath")
        .ok_or_else(|| errors::param_missing("filePath"))?;
    // The query value is already decoded once; Java decodes it again in makeTuple.
    let with_slash = if file_path.starts_with('/') { file_path.clone() } else { format!("/{file_path}") };
    let (rp, _) = make_tuple(&with_slash);

    let detail = state
        .file_detail(kind, &rp)
        .await?
        .ok_or(AppError::Empty(StatusCode::NOT_FOUND))?;
    if detail.is_directory {
        return Err(errors::err_as("FILES.FILE_IS_FOLDER", StatusCode::BAD_REQUEST, errors::UNKNOWN_ERROR, &[]));
    }
    respond(state, kind, &rp, &detail, &options, h).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes() {
        assert!(matches!(route("/api/files/static/file/SYSTEM/a.png"), Some(Route::Static)));
        assert!(matches!(route("/p/app/CC/api/files/secured/file/CC/a.pdf"), Some(Route::Secured)));
        assert!(matches!(route("/api/files/secured/downloadFileByKey/abc123"), Some(Route::Key("abc123"))));
        assert!(route("/api/files/secured/downloadFileByKey/").is_none());
        assert!(matches!(route("/api/files/internal/static/file"), Some(Route::Internal("static"))));
        assert!(route("/api/files/static/SYSTEM").is_none());
        assert!(route("/api/files/internal/static/cleanupExpired").is_none());
    }
}
