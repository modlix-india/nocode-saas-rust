//! What the Java service reads off a `ServerHttpRequest`: headers by name (first value, as
//! sent), the `Authorization` cookie, the URI's host and port, and the remote address.

use std::net::{IpAddr, SocketAddr};

use axum::http::{header, HeaderMap};

use crate::useragent::UserAgentInfo;

#[derive(Debug, Clone, Default)]
pub struct RequestInfo {
    pub headers: HeaderMap,
    /// `request.getURI().getHost()`: the `Host` header without its port.
    pub uri_host: String,
    /// `request.getURI().getPort()`: `-1` when the `Host` header names none.
    pub uri_port: i32,
    pub remote: Option<SocketAddr>,
}

impl RequestInfo {
    pub fn new(headers: HeaderMap, remote: Option<SocketAddr>) -> Self {
        let host = headers.get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("localhost").to_string();
        let (uri_host, uri_port) = split_host(&host);
        Self { headers, uri_host, uri_port, remote }
    }

    /// `headers.getFirst(name)`: the first value as sent, `None` when absent.
    pub fn header(&self, name: &str) -> Option<String> {
        self.headers.get(name).map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
    }

    pub fn client_code(&self) -> Option<String> {
        self.header("clientCode")
    }

    pub fn app_code(&self) -> Option<String> {
        self.header("appCode")
    }

    /// The `Authorization` cookie's value, if one was sent.
    pub fn auth_cookie(&self) -> Option<String> {
        self.headers.get_all(header::COOKIE).iter().find_map(|v| {
            v.to_str().ok()?.split(';').find_map(|pair| {
                let (k, v) = pair.trim().split_once('=')?;
                (k.trim() == "Authorization").then(|| v.trim().to_string())
            })
        })
    }

    /// `ServerHttpRequestUtil.extractBasicNBearerToken`: the header (or, when it is blank, the
    /// cookie), trimmed, with a `Bearer ` / `Basic ` prefix taken off in any case. `""` when
    /// there is none.
    pub fn basic_or_bearer(&self) -> (bool, String) {
        let mut raw = self.header(header::AUTHORIZATION.as_str());
        if raw.as_deref().map(|s| s.trim().is_empty()).unwrap_or(true) {
            if let Some(c) = self.auth_cookie() {
                raw = Some(c);
            }
        }
        let Some(raw) = raw else { return (false, String::new()) };
        let t = raw.trim();
        let lower = t.to_ascii_lowercase();
        if lower.starts_with("bearer ") {
            (false, t[7..].to_string())
        } else if lower.starts_with("basic ") {
            (true, t[6..].to_string())
        } else {
            (false, t.to_string())
        }
    }

    /// The host the token origin check and token minting use: `X-Forwarded-Host`, else the URI's.
    pub fn forwarded_host(&self) -> String {
        self.header("X-Forwarded-Host").unwrap_or_else(|| self.uri_host.clone())
    }

    /// `X-Forwarded-Port`, else the URI's port as `"" + port` (`-1` when none).
    pub fn forwarded_port(&self) -> String {
        self.header("X-Forwarded-Port").unwrap_or_else(|| self.uri_port.to_string())
    }

    /// `getRemoteAddressFrom`: `X-Real-IP`, else the peer's address.
    pub fn real_ip(&self) -> Option<String> {
        self.header("X-Real-IP").or_else(|| self.remote.map(|a| java_host_address(a.ip())))
    }

    /// `request.getRemoteAddress().getHostString()` (refreshToken records this one).
    pub fn remote_host(&self) -> Option<String> {
        self.remote.map(|a| java_host_address(a.ip()))
    }

    pub fn user_agent(&self) -> UserAgentInfo {
        UserAgentInfo::parse(self.header(header::USER_AGENT.as_str()).as_deref())
    }

    /// The scheme, host and port `ClientService.getClientBy(request)` resolves a client from.
    pub fn client_resolution_parts(&self) -> (String, String, String) {
        let scheme = self.header("X-Forwarded-Proto").unwrap_or_else(|| "http".into());
        let host = self.header("X-Forwarded-Host").unwrap_or_else(|| self.uri_host.clone());
        let host = host.split(':').next().unwrap_or("").to_string();
        let port = self.header("X-Forwarded-Port").unwrap_or_else(|| self.uri_port.to_string());
        (scheme, host, port)
    }
}

fn split_host(host: &str) -> (String, i32) {
    if let Some(rest) = host.strip_prefix('[') {
        // An IPv6 literal: `[::1]:8080`.
        let (h, after) = rest.split_once(']').unwrap_or((rest, ""));
        let port = after.strip_prefix(':').and_then(|p| p.parse().ok()).unwrap_or(-1);
        return (format!("[{h}]"), port);
    }
    match host.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(-1)),
        None => (host.to_string(), -1),
    }
}

/// `InetAddress.getHostAddress()`: IPv6 written in full, without `::` compression.
pub fn java_host_address(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => v6.segments().iter().map(|s| format!("{s:x}")).collect::<Vec<_>>().join(":"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn info(pairs: &[(&'static str, &'static str)]) -> RequestInfo {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(*k, HeaderValue::from_static(v));
        }
        RequestInfo::new(h, Some("127.0.0.1:5000".parse().unwrap()))
    }

    #[test]
    fn tokens_from_header_or_cookie() {
        assert_eq!(info(&[("authorization", "Bearer abc ")]).basic_or_bearer(), (false, "abc".into()));
        assert_eq!(info(&[("authorization", "bAsIc dXM6cA==")]).basic_or_bearer(), (true, "dXM6cA==".into()));
        assert_eq!(info(&[("authorization", "raw")]).basic_or_bearer(), (false, "raw".into()));
        assert_eq!(info(&[("authorization", " "), ("cookie", "a=1; Authorization=ck")]).basic_or_bearer(), (false, "ck".into()));
        assert_eq!(info(&[]).basic_or_bearer(), (false, String::new()));
        assert_eq!(info(&[("authorization", "  ")]).basic_or_bearer(), (false, String::new()));
    }

    #[test]
    fn host_port_and_addresses() {
        let i = info(&[("host", "localhost:8001")]);
        assert_eq!((i.uri_host.as_str(), i.uri_port), ("localhost", 8001));
        assert_eq!((i.forwarded_host(), i.forwarded_port()), ("localhost".into(), "8001".into()));
        let i = info(&[("host", "apps.local"), ("x-forwarded-host", "a.b, c.d"), ("x-forwarded-port", "443, 80")]);
        assert_eq!(i.uri_port, -1);
        assert_eq!((i.forwarded_host(), i.forwarded_port()), ("a.b, c.d".into(), "443, 80".into()));
        assert_eq!(i.client_resolution_parts(), ("http".into(), "a.b, c.d".into(), "443, 80".into()));
        let i = info(&[("host", "x:1"), ("x-forwarded-host", "h.local:8080"), ("x-forwarded-proto", "https")]);
        assert_eq!(i.client_resolution_parts(), ("https".into(), "h.local".into(), "1".into()));
        assert_eq!(info(&[("x-real-ip", "10.0.0.9")]).real_ip().as_deref(), Some("10.0.0.9"));
        assert_eq!(info(&[]).real_ip().as_deref(), Some("127.0.0.1"));
        assert_eq!(info(&[]).remote_host().as_deref(), Some("127.0.0.1"));
        assert_eq!(java_host_address("::1".parse().unwrap()), "0:0:0:0:0:0:0:1");
        assert_eq!(java_host_address("::ffff:10.1.2.3".parse().unwrap()), "10.1.2.3");
        let i = info(&[("host", "[::1]:9000")]);
        assert_eq!((i.uri_host.as_str(), i.uri_port), ("[::1]", 9000));
        let i = RequestInfo::new(HeaderMap::new(), None);
        assert_eq!((i.uri_host.as_str(), i.real_ip()), ("localhost", None));
        assert_eq!(info(&[("user-agent", "curl/8")]).user_agent().device_type.as_deref(), Some("BOT"));
        assert_eq!(info(&[("clientcode", "SYSTEM"), ("appcode", "x")]).client_code().as_deref(), Some("SYSTEM"));
        assert_eq!(info(&[("appcode", "x")]).app_code().as_deref(), Some("x"));
    }
}
