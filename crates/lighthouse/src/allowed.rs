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

pub fn is_replication(h: &axum::http::HeaderMap) -> bool {
    h.get(REPLICATION_HEADER).and_then(|v| v.to_str().ok()).is_some_and(|v| v.eq_ignore_ascii_case("true"))
}

/// Constant-time comparison, so the token cannot be guessed from response times.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
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
