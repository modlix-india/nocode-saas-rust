//! The dashboard: the registry protocol's status page, plus managing instances.
//!
//! - `GET /` and `GET /dashboard`: one self-contained page (inline CSS and JS, nothing loaded
//!   from elsewhere). Hosts bind the port to 127.0.0.1, so it is reached through an SSH tunnel.
//! - `GET /v1/registry`: this instance, its registry and the counts by status.
//! - `GET /v1/peers`: each peer, asked now whether it answers, with how replication to it goes.
//! - `/v1/admin/apps/{APP}/{ID}[/status]`: take an instance out of service, put it back, or
//!   remove it. They run the registry's normal client writes, so they replicate to the peers
//!   like the same Lighthouse calls. They need `Authorization: Bearer <token>` where the token's
//!   SHA-256 is `admin_token_sha256`; without that setting they are refused and the page is
//!   read-only. The Lighthouse routes themselves stay open to the clients, as the registry protocol's are.
//! - `GET /v1/admin/settings`: the configuration this instance started with, as TOML (tokens
//!   included), with the file it read and the names of the `MODLIX__` variables that set values.
//!   The same admin token.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, put};
use axum::{Json, Router};
use lighthouse_client::replication::REPLICATION_HEADER;
use lighthouse_client::wire::Status;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::config::auth::{Denied, Scope};
use crate::Node;

const PAGE: &str = include_str!("dashboard.html");

/// Only what the page itself carries may run; it talks to this server alone.
const CSP: &str = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; \
                   img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

pub fn routes(node: Arc<Node>) -> Router {
    Router::new()
        .route("/", get(page))
        .route("/dashboard", get(page))
        .route("/v1/registry", get(registry_view))
        .route("/v1/peers", get(peers_view))
        .route("/v1/admin/apps/{app}/{id}/status", put(take_out).delete(put_back))
        .route("/v1/admin/apps/{app}/{id}", delete(remove))
        .route("/v1/admin/settings", get(settings_view))
        .with_state(node)
}

/// `admin_token_sha256` as bytes; `None` when it is not set.
pub fn admin_hash(hex_digest: &str) -> Result<Option<[u8; 32]>> {
    let h = hex_digest.trim();
    if h.is_empty() {
        return Ok(None);
    }
    let bytes = hex::decode(h).context("admin_token_sha256 is not hex")?;
    match <[u8; 32]>::try_from(bytes.as_slice()) {
        Ok(b) => Ok(Some(b)),
        Err(_) => bail!("admin_token_sha256 must be 64 hex characters (a SHA-256)"),
    }
}

/// The SHA-256 of a token, in hex: what goes into `admin_token_sha256`.
pub fn sha256_hex(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

async fn page() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
            (header::CONTENT_SECURITY_POLICY, CSP),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        PAGE,
    )
        .into_response()
}

async fn registry_view(State(n): State<Arc<Node>>) -> Response {
    let mut v = n.registry.operator_view();
    let p = n.registry.preservation();
    v["instance"] = json!({
        "id": n.instance_name(),
        "selfUrl": n.cfg.registry.self_url,
        "version": env!("CARGO_PKG_VERSION"),
        "startedAt": n.started_ms,
        "uptimeSeconds": n.started.elapsed().as_secs(),
        "ready": n.registry.is_ready(),
        "selfPreservationActive": p.active,
        "renewalsLastMinute": p.renewals_last_minute,
        "renewalThreshold": p.threshold,
        "peers": n.peers.len(),
    });
    v["manageable"] = json!(n.auth.has(Scope::Ops));
    Json(v).into_response()
}

/// Every peer, asked for its digest now (one second at most) as a peer would, with its
/// replication numbers. Reachable means it answered that call.
async fn peers_view(State(n): State<Arc<Node>>) -> Response {
    let now = n.registry.now_ms();
    let probes = n.peers.iter().map(|p| {
        let mut req = n.probe.get(format!("{}/v1/peer/digest", p.url)).header(REPLICATION_HEADER, "true");
        if let Some(t) = &n.client.token {
            req = req.bearer_auth(t);
        }
        async move {
            let started = tokio::time::Instant::now();
            let ok = matches!(req.send().await, Ok(r) if r.status().is_success());
            (ok, started.elapsed().as_millis() as u64)
        }
    });
    let results = futures::future::join_all(probes).await;
    let peers: Vec<_> = n
        .peers
        .iter()
        .zip(results)
        .map(|(p, (reachable, probe_ms))| {
            let s = p.stats();
            json!({
                "url": p.url,
                "reachable": reachable,
                "probeMs": probe_ms,
                "lastSuccessMs": s.last_success_ms,
                "lastSuccessAgoMs": (s.last_success_ms > 0).then(|| now - s.last_success_ms),
                "queued": p.queued(),
                "queuedByAction": p.queued_by_action(),
                "dropped": s.dropped,
                "failures": s.failures,
                "batches": s.batches,
                "healed": s.healed,
                "adopted": s.adopted,
                "lastError": s.last_error,
            })
        })
        .collect();
    Json(json!({"peers": peers})).into_response()
}

/// Lets the call through when it carries a token with the `ops` scope (the admin token is one).
fn authorize(n: &Node, h: &HeaderMap) -> Result<(), Response> {
    if !n.auth.has(Scope::Ops) {
        return Err((StatusCode::FORBIDDEN, "managing instances is off: no admin_token_sha256 is configured").into_response());
    }
    match n.auth.check(h, &[Scope::Ops]) {
        Ok(_) => Ok(()),
        Err(Denied::Unknown) => Err((StatusCode::UNAUTHORIZED, "the admin token is missing or wrong").into_response()),
        Err(Denied::Scope) => Err((StatusCode::FORBIDDEN, "this token may not manage instances").into_response()),
    }
}

fn done(found: bool, what: &str, app: &str, id: &str) -> Response {
    if found {
        tracing::info!(app, id, what, "instance managed from the dashboard");
        StatusCode::OK.into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

/// `PUT .../status?value=OUT_OF_SERVICE` (or another status): the override Lighthouse sets.
async fn take_out(
    State(n): State<Arc<Node>>,
    Path((app, id)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    if let Err(r) = authorize(&n, &h) {
        return r;
    }
    let status = q.get("value").map_or(Status::OutOfService, |v| Status::parse(v));
    if status == Status::Unknown {
        return (StatusCode::BAD_REQUEST, "value must be UP, DOWN, STARTING or OUT_OF_SERVICE").into_response();
    }
    let found = n.registry.status_update(&app, &id, status, None, crate::registry::Origin::Client);
    done(found, status.as_str(), &app, &id)
}

/// `DELETE .../status`: removes the override. Without a value the status becomes UNKNOWN and
/// the instance's next heartbeat registers it again with its real status.
async fn put_back(
    State(n): State<Arc<Node>>,
    Path((app, id)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    if let Err(r) = authorize(&n, &h) {
        return r;
    }
    let status = q.get("value").map_or(Status::Unknown, |v| Status::parse(v));
    let found = n.registry.delete_status_override(&app, &id, status, None, crate::registry::Origin::Client);
    done(found, "override removed", &app, &id)
}

/// `DELETE /v1/admin/apps/{APP}/{ID}`: the cancel a client sends. A running instance registers
/// again with its next heartbeat; a dead one is gone.
async fn remove(State(n): State<Arc<Node>>, Path((app, id)): Path<(String, String)>, h: HeaderMap) -> Response {
    if let Err(r) = authorize(&n, &h) {
        return r;
    }
    let found = n.registry.cancel(&app, &id, crate::registry::Origin::Client);
    done(found, "removed", &app, &id)
}

/// The settings as TOML, tokens included: the route is behind the admin token.
pub fn settings_text(cfg: &crate::config::LighthouseConfig) -> Result<String> {
    let v = serde_json::to_value(cfg)?;
    let t = crate::config::units::json_to_toml(&v).context("the settings are not a table")?;
    Ok(toml::to_string(&t)?)
}

async fn settings_view(State(n): State<Arc<Node>>, h: HeaderMap) -> Response {
    if let Err(r) = authorize(&n, &h) {
        return r;
    }
    let mut env: Vec<String> = std::env::vars().map(|(k, _)| k).filter(|k| k.starts_with("MODLIX__")).collect();
    env.sort();
    match settings_text(&n.cfg) {
        Ok(text) => Json(json!({
            "file": platform::config::config_file(crate::NAME).map(|p| p.display().to_string()),
            "env": env,
            "settings": text,
        }))
        .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")).into_response(),
    }
}

/// How long the dashboard waits for a peer's answer.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(1);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_hashes() {
        assert_eq!(admin_hash("").unwrap(), None);
        let h = sha256_hex("letmein");
        assert_eq!(h.len(), 64);
        assert_eq!(admin_hash(&h.to_uppercase()).unwrap().map(hex::encode), Some(h));
        assert!(admin_hash("zz").is_err());
        assert!(admin_hash("abcd").is_err());
    }

    #[test]
    fn settings_show_everything() {
        let mut cfg = crate::config::LighthouseConfig::default();
        cfg.registry.peer_token = "peer-token".into();
        cfg.auth.tokens = vec![crate::config::auth::TokenConfig { name: "units".into(), sha256: "b".repeat(64), scopes: vec![Scope::Units], units: vec![] }];
        let text = settings_text(&cfg).unwrap();
        assert!(text.contains("peer_token = \"peer-token\"") && text.contains("name = \"units\"") && text.contains("port = 8761"));
    }

    #[test]
    fn the_page_is_self_contained() {
        for external in ["http://", "https://", "<link", "src=", "@import", "url("] {
            assert!(!PAGE.contains(external), "the page must not load {external}");
        }
        for dash in ['\u{2013}', '\u{2014}'] {
            assert!(!PAGE.contains(dash));
        }
    }
}
