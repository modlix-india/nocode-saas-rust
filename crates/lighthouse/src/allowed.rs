//! Who may call the registry: source networks, and the peer token on calls between peers.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use lighthouse_client::replication::REPLICATION_HEADER;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Net {
    addr: IpAddr,
    prefix: u32,
}

impl Net {
    fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = addr.parse().with_context(|| format!("{s:?} is not an address or network"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(p) => p.parse::<u32>().ok().filter(|p| *p <= max).ok_or_else(|| anyhow!("{s:?} has a bad prefix length"))?,
            None => max,
        };
        Ok(Self { addr, prefix })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => masked(u128::from(u32::from(n)), self.prefix, 32) == masked(u128::from(u32::from(a)), self.prefix, 32),
            (IpAddr::V6(n), IpAddr::V6(a)) => masked(u128::from(n), self.prefix, 128) == masked(u128::from(a), self.prefix, 128),
            _ => false,
        }
    }
}

fn masked(v: u128, prefix: u32, bits: u32) -> u128 {
    if prefix == 0 {
        0
    } else {
        v >> (bits - prefix)
    }
}

/// The source networks allowed on the registry routes.
#[derive(Debug, Clone, Default)]
pub struct Allowed {
    nets: Arc<Vec<Net>>,
}

impl Allowed {
    pub fn parse(list: &[String]) -> Result<Self> {
        let nets = list.iter().filter(|s| !s.trim().is_empty()).map(|s| Net::parse(s)).collect::<Result<Vec<_>>>()?;
        Ok(Self { nets: Arc::new(nets) })
    }

    /// Empty allows anything. An IPv4 address seen as IPv6 (`::ffff:10.0.0.1`) counts as IPv4.
    pub fn permits(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            v4 => v4,
        };
        self.nets.is_empty() || self.nets.iter().any(|n| n.contains(ip))
    }
}

/// Refuses callers outside the allowed networks. A request without a peer address (served
/// in-process) passes.
pub async fn networks(State(allowed): State<Allowed>, req: Request, next: Next) -> Response {
    if let Some(ConnectInfo(addr)) = req.extensions().get::<ConnectInfo<SocketAddr>>() {
        if !allowed.permits(addr.ip()) {
            tracing::warn!(remote = %addr, path = req.uri().path(), "refused a caller outside the allowed networks");
            return (StatusCode::FORBIDDEN, "not an allowed network").into_response();
        }
    }
    next.run(req).await
}

/// Calls between peers carry the peer token: the batch and digest routes, and any call marked
/// as replication (which must not be replicated again, so no client may claim it).
pub async fn peer_token(State(token): State<Arc<String>>, req: Request, next: Next) -> Response {
    if token.is_empty() {
        return next.run(req).await;
    }
    let path = req.uri().path();
    let peer_call = path.starts_with("/eureka/peerreplication") || path.starts_with("/v1/peer/") || is_replication(req.headers());
    if peer_call {
        let given = req.headers().get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer "));
        if !given.is_some_and(|g| same(g.as_bytes(), token.as_bytes())) {
            return (StatusCode::UNAUTHORIZED, "peer token required").into_response();
        }
    }
    next.run(req).await
}

/// The header [`trust`] sets on a request from a trusted network (a client's own copy is
/// removed first, so no caller can claim it). [`crate::config::auth::Auth`] serves its open
/// scopes only to requests carrying it.
pub const TRUSTED_HEADER: &str = "x-lighthouse-trusted";

/// Marks requests from the trusted networks (`[allowed] trusted`: the host's own Docker network),
/// and keeps registry writes and peer calls to them: from anywhere else (the VPN, through the
/// jumphost) the registry and the dashboard are read-only, and configuration needs a token. An
/// empty list trusts every allowed caller; a request without a peer address (served
/// in-process) is trusted.
pub async fn trust(State(trusted): State<Allowed>, mut req: Request, next: Next) -> Response {
    req.headers_mut().remove(TRUSTED_HEADER);
    let inside = match req.extensions().get::<ConnectInfo<SocketAddr>>() {
        Some(ConnectInfo(addr)) => trusted.permits(addr.ip()),
        None => true,
    };
    if inside {
        req.headers_mut().insert(TRUSTED_HEADER, axum::http::HeaderValue::from_static("1"));
        return next.run(req).await;
    }
    let path = req.uri().path();
    let read = matches!(*req.method(), axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS);
    if path.starts_with("/v1/peer/") || path.starts_with("/eureka/peerreplication") || (path.starts_with("/eureka") && !read) {
        return (StatusCode::FORBIDDEN, "registry writes and peer calls are for the host's own network").into_response();
    }
    next.run(req).await
}

pub fn is_trusted(h: &axum::http::HeaderMap) -> bool {
    h.contains_key(TRUSTED_HEADER)
}

pub fn is_replication(h: &axum::http::HeaderMap) -> bool {
    h.get(REPLICATION_HEADER).and_then(|v| v.to_str().ok()).is_some_and(|v| v.eq_ignore_ascii_case("true"))
}

/// Constant-time comparison, so the token cannot be guessed from response times.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use axum::routing::any;
    use axum::Router;
    use tower::ServiceExt;

    async fn call(trusted: &[&str], from: &str, method: &str, path: &str, claim: bool) -> (StatusCode, bool) {
        let t = Allowed::parse(&trusted.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        let app = Router::new()
            .route("/{*rest}", any(|h: axum::http::HeaderMap| async move { if is_trusted(&h) { "trusted" } else { "outside" } }))
            .layer(axum::middleware::from_fn_with_state(t, trust));
        let mut req = HttpRequest::builder().method(method).uri(path).body(Body::empty()).unwrap();
        if claim {
            req.headers_mut().insert(TRUSTED_HEADER, "1".parse().unwrap());
        }
        req.extensions_mut().insert(ConnectInfo::<SocketAddr>(format!("{from}:5555").parse().unwrap()));
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        (status, body.as_ref() == b"trusted")
    }

    #[tokio::test]
    async fn only_the_trusted_network_reads_configuration_and_writes_the_registry() {
        let docker = ["172.21.0.0/16"];
        assert_eq!(call(&docker, "172.21.0.5", "GET", "/v1/units/multi/config", false).await, (StatusCode::OK, true));
        assert_eq!(call(&docker, "172.21.0.5", "POST", "/eureka/apps/MULTI", false).await, (StatusCode::OK, true));
        // The VPN, through the jumphost: reads only, never trusted, whatever it claims.
        assert_eq!(call(&docker, "172.16.0.107", "GET", "/v1/units/multi/config", true).await, (StatusCode::OK, false));
        assert_eq!(call(&docker, "172.16.0.107", "GET", "/eureka/apps", false).await, (StatusCode::OK, false));
        assert_eq!(call(&docker, "172.16.0.107", "DELETE", "/eureka/apps/MULTI/x", false).await.0, StatusCode::FORBIDDEN);
        assert_eq!(call(&docker, "172.16.0.107", "POST", "/eureka/peerreplication/batch", false).await.0, StatusCode::FORBIDDEN);
        assert_eq!(call(&docker, "172.16.0.107", "GET", "/v1/peer/snapshot", false).await.0, StatusCode::FORBIDDEN);
        assert_eq!(call(&docker, "172.16.0.107", "PUT", "/v1/admin/apps/MULTI/x/status", false).await, (StatusCode::OK, false), "admin actions go on to their token check");
        // No list: every allowed caller is trusted (the local stack).
        assert_eq!(call(&[], "10.8.0.10", "POST", "/eureka/apps/MULTI", false).await, (StatusCode::OK, true));
    }

    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn networks_and_addresses() {
        let a = Allowed::parse(&["10.0.0.0/8".into(), "192.168.1.7".into(), " ".into(), "fc00::/7".into(), "0.0.0.0/0".into()]).unwrap();
        assert!(a.permits(ip("8.8.8.8")), "0.0.0.0/0 allows any IPv4");
        let a = Allowed::parse(&["10.0.0.0/8".into(), "192.168.1.7".into(), "fc00::/7".into()]).unwrap();
        assert!(a.permits(ip("10.200.3.4")));
        assert!(a.permits(ip("::ffff:10.1.1.1")), "IPv4 seen through IPv6");
        assert!(a.permits(ip("192.168.1.7")));
        assert!(!a.permits(ip("192.168.1.8")));
        assert!(a.permits(ip("fd12::1")));
        assert!(!a.permits(ip("2001:db8::1")));
        assert!(!a.permits(ip("8.8.8.8")));
        assert!(Allowed::parse(&[]).unwrap().permits(ip("8.8.8.8")), "empty allows any");
        assert!(Allowed::default().permits(ip("1.2.3.4")));
        for bad in ["nope", "10.0.0.0/33", "::/129", "10.0.0.0/x"] {
            assert!(Allowed::parse(&[bad.to_string()]).is_err(), "{bad}");
        }
        assert!(same(b"abc", b"abc") && !same(b"abc", b"abd") && !same(b"ab", b"abc"));
    }
}
