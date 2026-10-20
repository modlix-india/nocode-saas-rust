//! The registry REST API under `/eureka`, as the Java server answers it.
//!
//! - Bodies are XML unless `Accept` names `application/json` (py_eureka_client reads only
//!   XML; the Rust clients ask for JSON). Registrations are read as JSON, which every client in
//!   use sends.
//! - App names are upper case. Status codes are the registry protocol's: 204 for a registration, 200 or 404
//!   for the rest, 409 with our copy for a stale replicated heartbeat.
//! - The discovery GETs answer 503 while the instance is warming up; writes are always taken.
//! - As an extension, the GETs carry an ETag and answer `If-None-Match` with 304.
//! - `POST /eureka/peerreplication/batch` takes a peer's batch; `GET /v1/peer/digest` is
//!   Lighthouse's own. The dashboard and its views are in [`crate::dashboard`].

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{OriginalUri, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use lighthouse_client::replication::{ReplicationList, ReplicationListResponse};
use lighthouse_client::wire::{ApplicationEnvelope, Applications, ApplicationsEnvelope, InstanceEnvelope, InstanceInfo, Status};
use serde_json::json;

use crate::allowed::is_replication;
use crate::registry::{Origin, Renewal};
use crate::Node;

pub fn routes(node: Arc<Node>) -> Router {
    Router::new()
        .route("/eureka/apps", get(apps))
        .route("/eureka/apps/", get(apps))
        .route("/eureka/apps/delta", get(delta))
        .route("/eureka/apps/{app}", get(application).post(register))
        .route("/eureka/apps/{app}/{id}", get(instance).put(renew).delete(cancel))
        .route("/eureka/apps/{app}/{id}/status", put(status_update).delete(delete_override))
        .route("/eureka/peerreplication/batch", post(batch))
        .route("/v1/peer/digest", get(digest))
        .with_state(node)
}

type Q = Query<HashMap<String, String>>;

fn wants_json(h: &HeaderMap) -> bool {
    h.get(header::ACCEPT).and_then(|v| v.to_str().ok()).is_some_and(|a| a.contains("application/json"))
}

fn origin_of(h: &HeaderMap) -> Origin {
    if is_replication(h) {
        Origin::Peer
    } else {
        Origin::Client
    }
}

fn body(json: bool, json_body: String, xml_body: impl FnOnce() -> String) -> Response {
    if json {
        ([(header::CONTENT_TYPE, "application/json")], json_body).into_response()
    } else {
        ([(header::CONTENT_TYPE, "application/xml")], xml_body()).into_response()
    }
}

fn to_json<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_string(v).unwrap_or_default()
}

/// The JSON Spring writes for an error, without the timestamp.
fn error(status: StatusCode, uri: &OriginalUri, message: &str) -> Response {
    let mut body = json!({"status": status.as_u16(), "error": status.canonical_reason().unwrap_or(""), "path": uri.0.path()});
    if !message.is_empty() {
        body["message"] = json!(message);
    }
    (status, Json(body)).into_response()
}

fn warming(uri: &OriginalUri) -> Response {
    let mut r = error(StatusCode::SERVICE_UNAVAILABLE, uri, "warming up: syncing the registry from its peers");
    r.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from_static("5"));
    r
}

/// The ETag of a representation: this process, the registry version, the kind of body.
fn etag(node: &Node, version: u64, kind: &str) -> String {
    format!("\"{:08x}-{version}-{kind}\"", node.registry.epoch())
}

/// 304 when the caller already has `tag`, else the body with the tag.
fn tagged(h: &HeaderMap, tag: String, make: impl FnOnce() -> Response) -> Response {
    let matches = h.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()).is_some_and(|v| v.split(',').any(|t| t.trim() == tag));
    let mut r = if matches { StatusCode::NOT_MODIFIED.into_response() } else { make() };
    if let Ok(v) = HeaderValue::from_str(&tag) {
        r.headers_mut().insert(header::ETAG, v);
    }
    r
}

fn render_apps(h: &HeaderMap, apps: Applications) -> Response {
    let json = wants_json(h);
    body(json, if json { to_json(&ApplicationsEnvelope { applications: apps.clone() }) } else { String::new() }, || {
        lighthouse_client::xml::applications(&apps)
    })
}

fn render_instance(h: &HeaderMap, i: InstanceInfo) -> Response {
    let json = wants_json(h);
    body(json, if json { to_json(&InstanceEnvelope { instance: i.clone() }) } else { String::new() }, || {
        lighthouse_client::xml::instance(&i)
    })
}

async fn apps(State(n): State<Arc<Node>>, uri: OriginalUri, h: HeaderMap) -> Response {
    if !n.registry.is_ready() {
        return warming(&uri);
    }
    let (apps, version) = n.registry.applications();
    let tag = etag(&n, version, if wants_json(&h) { "j" } else { "x" });
    tagged(&h, tag, || render_apps(&h, apps))
}

async fn delta(State(n): State<Arc<Node>>, uri: OriginalUri, h: HeaderMap) -> Response {
    if !n.registry.is_ready() {
        return warming(&uri);
    }
    let (apps, version) = n.registry.delta();
    let tag = etag(&n, version, if wants_json(&h) { "dj" } else { "dx" });
    tagged(&h, tag, || render_apps(&h, apps))
}

async fn application(State(n): State<Arc<Node>>, Path(app): Path<String>, uri: OriginalUri, h: HeaderMap) -> Response {
    if !n.registry.is_ready() {
        return warming(&uri);
    }
    let (found, version) = n.registry.application(&app);
    let Some(found) = found else {
        return error(StatusCode::NOT_FOUND, &uri, "");
    };
    let json = wants_json(&h);
    let tag = etag(&n, version, &format!("{}{}", if json { "aj" } else { "ax" }, found.name));
    tagged(&h, tag, || {
        body(json, if json { to_json(&ApplicationEnvelope { application: found.clone() }) } else { String::new() }, || {
            lighthouse_client::xml::application(&found)
        })
    })
}

async fn instance(State(n): State<Arc<Node>>, Path((app, id)): Path<(String, String)>, uri: OriginalUri, h: HeaderMap) -> Response {
    if !n.registry.is_ready() && !is_replication(&h) {
        return warming(&uri);
    }
    match n.registry.instance(&app, &id) {
        Some(i) => render_instance(&h, i),
        None => error(StatusCode::NOT_FOUND, &uri, ""),
    }
}

async fn register(State(n): State<Arc<Node>>, Path(app): Path<String>, uri: OriginalUri, h: HeaderMap, raw: Bytes) -> Response {
    let app = app.to_ascii_uppercase();
    let parsed = serde_json::from_slice::<InstanceEnvelope>(&raw)
        .map(|e| e.instance)
        .or_else(|_| serde_json::from_slice::<InstanceInfo>(&raw));
    let mut info = match parsed {
        Ok(i) => i,
        Err(e) => return error(StatusCode::BAD_REQUEST, &uri, &format!("unreadable instance: {e}")),
    };
    // InstanceResource's checks, in its order.
    if info.host_name.is_empty() {
        return error(StatusCode::BAD_REQUEST, &uri, "Missing hostname");
    }
    if info.ip_addr.is_empty() {
        return error(StatusCode::BAD_REQUEST, &uri, "Missing ip address");
    }
    if info.app.is_empty() {
        info.app = app.clone();
    }
    if info.app != app {
        return error(StatusCode::BAD_REQUEST, &uri, &format!("Mismatched appName, expecting {app} but was {}", info.app));
    }
    let origin = origin_of(&h);
    if origin == Origin::Client && !n.app_allowed(&app) {
        return error(StatusCode::FORBIDDEN, &uri, &format!("{app} may not register here"));
    }
    if n.registry.register(info, origin) {
        StatusCode::NO_CONTENT.into_response()
    } else {
        error(StatusCode::CONFLICT, &uri, "cancelled recently; a newer registration is needed")
    }
}

fn dirty(q: &Q, uri: &OriginalUri) -> Result<Option<i64>, Response> {
    match q.get("lastDirtyTimestamp").map(|s| s.trim()).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(s) => s.parse().map(Some).map_err(|_| error(StatusCode::BAD_REQUEST, uri, "lastDirtyTimestamp is not a number")),
    }
}

async fn renew(State(n): State<Arc<Node>>, Path((app, id)): Path<(String, String)>, q: Q, uri: OriginalUri, h: HeaderMap) -> Response {
    let last_dirty = match dirty(&q, &uri) {
        Ok(d) => d,
        Err(r) => return r,
    };
    let overridden = q.get("overriddenstatus").or_else(|| q.get("overriddenStatus")).map(|s| Status::parse(s));
    match n.registry.renew(&app, &id, origin_of(&h), last_dirty, overridden) {
        Renewal::Renewed => StatusCode::OK.into_response(),
        Renewal::NotFound => error(StatusCode::NOT_FOUND, &uri, ""),
        Renewal::Conflict(ours) => {
            let mut r = render_instance(&h, *ours);
            *r.status_mut() = StatusCode::CONFLICT;
            r
        }
    }
}

async fn cancel(State(n): State<Arc<Node>>, Path((app, id)): Path<(String, String)>, uri: OriginalUri, h: HeaderMap) -> Response {
    if n.registry.cancel(&app, &id, origin_of(&h)) {
        StatusCode::OK.into_response()
    } else {
        error(StatusCode::NOT_FOUND, &uri, "")
    }
}

async fn status_update(State(n): State<Arc<Node>>, Path((app, id)): Path<(String, String)>, q: Q, uri: OriginalUri, h: HeaderMap) -> Response {
    let status = q.get("value").map(|v| Status::parse(v));
    let Some(status) = status.filter(|s| *s != Status::Unknown) else {
        return error(StatusCode::BAD_REQUEST, &uri, "value must be UP, DOWN, STARTING or OUT_OF_SERVICE");
    };
    let last_dirty = match dirty(&q, &uri) {
        Ok(d) => d,
        Err(r) => return r,
    };
    if n.registry.status_update(&app, &id, status, last_dirty, origin_of(&h)) {
        StatusCode::OK.into_response()
    } else {
        error(StatusCode::NOT_FOUND, &uri, "")
    }
}

async fn delete_override(State(n): State<Arc<Node>>, Path((app, id)): Path<(String, String)>, q: Q, uri: OriginalUri, h: HeaderMap) -> Response {
    let status = q.get("value").map_or(Status::Unknown, |v| Status::parse(v));
    let last_dirty = match dirty(&q, &uri) {
        Ok(d) => d,
        Err(r) => return r,
    };
    if n.registry.delete_status_override(&app, &id, status, last_dirty, origin_of(&h)) {
        StatusCode::OK.into_response()
    } else {
        error(StatusCode::NOT_FOUND, &uri, "")
    }
}

async fn batch(State(n): State<Arc<Node>>, Json(list): Json<ReplicationList>) -> Json<ReplicationListResponse> {
    let response_list = list.replication_list.into_iter().map(|item| crate::replication::apply(&n.registry, item)).collect();
    Json(ReplicationListResponse { response_list })
}

async fn digest(State(n): State<Arc<Node>>) -> Response {
    Json(n.registry.digest()).into_response()
}
