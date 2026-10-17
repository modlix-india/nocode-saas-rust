//! Forwarding a request to an instance of the route's pool, and its response back.
//!
//! What reaches the service is what Spring Cloud Gateway sent, measured on the local stack:
//! - `Host` is the instance's own `host:port`;
//! - `X-Forwarded-For`, `-Proto`, `-Host` and `-Port` get this hop appended after a comma
//!   (`https,http`, `foo.com,localhost:8080`), and `Forwarded` is added;
//! - `appCode` / `clientCode` are filled in when the caller sent none;
//! - `x-draft` is removed, and set only when the host grants the draft surface for the very
//!   app and client the request is for;
//! - the path is the one after the codes prefix, without a trailing `/`; the query is untouched.
//!
//! Bodies stream both ways with no buffering, so uploads, downloads and server-sent events pass
//! through at the pace the two ends set.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use platform::error::{AppError, Coded};
use platform::http::with_route;

use crate::path::split;
use crate::pool::Member;
use crate::resolve::{codes_match, Resolver};
use crate::routes::{Route, Routes};

pub type HttpClient = Client<HttpConnector, Body>;

pub struct Gateway {
    pub routes: Routes,
    pub resolver: Resolver,
    pub client: HttpClient,
    pub default_timeout: Duration,
}

/// Headers that describe one connection, never forwarded (RFC 9110 7.6.1).
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

fn strip_hop_by_hop(h: &mut HeaderMap) {
    let named: Vec<HeaderName> = h
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|n| HeaderName::from_bytes(n.trim().as_bytes()).ok())
        .collect();
    for n in named {
        h.remove(n);
    }
    for n in HOP_BY_HOP {
        h.remove(*n);
    }
}

fn header_str<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

/// `InetAddress.getHostAddress()`: IPv6 as eight uncompressed groups, IPv4 dotted.
pub fn java_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => v6.segments().iter().map(|s| format!("{s:x}")).collect::<Vec<_>>().join(":"),
        },
    }
}

/// `scheme`, `host` (no port) and `port` as `GatewayFilter.getSchemeHostPort` reads them: the
/// forwarded headers when present (raw, commas and all), else the request's own; a missing port
/// is `-1`, as `URI.getPort()` reports it.
pub fn scheme_host_port(h: &HeaderMap) -> (String, String, String) {
    let host_header = header_str(h, "host").unwrap_or("");
    let scheme = header_str(h, "x-forwarded-proto").unwrap_or("http").to_string();
    let mut host = header_str(h, "x-forwarded-host")
        .map(str::to_string)
        .unwrap_or_else(|| host_header.to_string());
    let port = header_str(h, "x-forwarded-port").map(str::to_string).unwrap_or_else(|| {
        host_header
            .rsplit_once(':')
            .filter(|(_, p)| p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty())
            .map(|(_, p)| p.to_string())
            .unwrap_or_else(|| "-1".to_string())
    });
    if let Some(i) = host.find(':') {
        host.truncate(i);
    }
    (scheme, host, port)
}

fn append(h: &mut HeaderMap, name: &'static str, value: &str) {
    let v = match header_str(h, name) {
        Some(existing) if !existing.is_empty() => format!("{existing},{value}"),
        _ => value.to_string(),
    };
    if let Ok(v) = HeaderValue::from_str(&v) {
        h.insert(name, v);
    }
}

fn quote_if_needed(v: &str) -> String {
    if v.contains(':') || v.contains('[') || v.contains(' ') {
        format!("\"{v}\"")
    } else {
        v.to_string()
    }
}

/// `XForwardedHeadersFilter` + `ForwardedHeadersFilter`, as measured.
pub fn add_forwarding_headers(h: &mut HeaderMap, client: SocketAddr) {
    let ip = java_ip(client.ip());
    let original_host = header_str(h, "host").unwrap_or("").to_string();
    let port = original_host
        .rsplit_once(':')
        .filter(|(_, p)| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
        .map(|(_, p)| p.to_string())
        .unwrap_or_else(|| "80".to_string());

    let for_value = match client.ip() {
        IpAddr::V6(_) => format!("[{ip}]:{}", client.port()),
        IpAddr::V4(_) => format!("{ip}:{}", client.port()),
    };
    let forwarded = format!(
        "proto=http;host={};for={}",
        quote_if_needed(&original_host),
        quote_if_needed(&for_value)
    );
    append(h, "forwarded", &forwarded);
    append(h, "x-forwarded-for", &ip);
    append(h, "x-forwarded-proto", "http");
    append(h, "x-forwarded-port", &port);
    if !original_host.is_empty() {
        append(h, "x-forwarded-host", &original_host);
    }
}

fn wants_event_stream(path: &str, h: &HeaderMap) -> bool {
    path.contains("/api/ai/")
        || h.get_all(header::ACCEPT)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .any(|v| v.contains("text/event-stream"))
}

/// One of the gateway's own errors (`GW.*`): the plain text for people, the technical detail
/// (pool, upstream, cause) in `debugMessage`.
fn error(code: &'static str, debug: String, route: &'static str) -> Response {
    with_route(AppError::from(Coded::new(code).debug(debug)).into_response(), route)
}

pub async fn handle(
    State(gw): State<Arc<Gateway>>,
    ConnectInfo(client): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    let (parts, body) = req.into_parts();

    // The Spring gateway has no CORS configuration, so it refuses every preflight itself (an
    // empty 403) before any service sees it, even same-origin ones: behind nginx the scheme of
    // the request never matches the https Origin. Kept: passing preflights through would let
    // ui's permissive CORS answer and open cross-origin calls that are refused today.
    if parts.method == Method::OPTIONS
        && parts.headers.contains_key(header::ORIGIN)
        && parts.headers.contains_key(header::ACCESS_CONTROL_REQUEST_METHOD)
    {
        let mut r = Response::new(Body::empty());
        *r.status_mut() = StatusCode::FORBIDDEN;
        for v in ["Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers"] {
            r.headers_mut().append(header::VARY, HeaderValue::from_static(v));
        }
        r.headers_mut().insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
        return with_route(r, "cors-preflight");
    }

    let path = parts.uri.path().to_string();
    let query = parts.uri.query().map(str::to_string);
    let split = split(&path);

    let Some(route) = gw.routes.find(&split.forward, &parts.method) else {
        return error("GW.NO_ROUTE", format!("No route for {} {path}", parts.method), "unmatched");
    };

    let (scheme, host, port) = scheme_host_port(&parts.headers);
    let supplied_client = header_str(&parts.headers, "clientcode").map(str::to_string);
    let supplied_app = header_str(&parts.headers, "appcode").map(str::to_string);
    let resolved = match gw
        .resolver
        .resolve(&scheme, &host, &port, split.codes_part, supplied_client.as_deref(), supplied_app.as_deref())
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(host, error = %e, "host resolution failed");
            return error("GW.HOST_UNRESOLVED", format!("Unable to resolve the application for the host {host}: {e}"), route.id);
        }
    };

    let mut headers = parts.headers.clone();
    let blank = |v: &Option<String>| v.as_deref().map(str::trim).unwrap_or("").is_empty();
    if blank(&supplied_app) {
        if let Ok(v) = HeaderValue::from_str(&resolved.app_code) {
            headers.insert("appcode", v);
        }
    }
    if blank(&supplied_client) {
        if let Ok(v) = HeaderValue::from_str(&resolved.client_code) {
            headers.insert("clientcode", v);
        }
    }
    headers.remove("x-draft");
    if resolved.draft
        && codes_match(supplied_app.as_deref(), &resolved.app_code, supplied_client.as_deref(), &resolved.client_code)
    {
        headers.insert("x-draft", HeaderValue::from_static("true"));
    }
    strip_hop_by_hop(&mut headers);
    add_forwarding_headers(&mut headers, client);
    platform::telemetry::inject_trace_headers(&mut headers);

    let sse = wants_event_stream(&split.forward, &parts.headers);
    let timeout = route.timeout.unwrap_or(gw.default_timeout);
    let path_and_query = match &query {
        Some(q) => format!("{}?{q}", split.forward),
        None => split.forward.clone(),
    };

    // A request without a body can go to a second instance if the first refuses the
    // connection; one with a body has already been handed over and cannot.
    let replayable = matches!(parts.method, Method::GET | Method::HEAD | Method::OPTIONS | Method::DELETE)
        && header_str(&parts.headers, "content-length").is_none_or(|l| l == "0")
        && !parts.headers.contains_key(header::TRANSFER_ENCODING);

    let pool = &route.pool;
    let Some(first) = pool.pick(None) else {
        return error("GW.SERVICE_STARTING", format!("No instance of {} is available", pool.name), route.id);
    };

    let mut body = Some(body);
    let mut member = first;
    let mut attempt = 0;
    loop {
        attempt += 1;
        let this_body = if replayable { Body::empty() } else { body.take().unwrap_or_else(Body::empty) };
        let result = send(&gw.client, &parts.method, &headers, &member, &path_and_query, this_body, timeout).await;
        match result {
            Ok(resp) => return finish(resp, sse, route),
            Err(SendError::Connect(e)) => {
                pool.eject(&member);
                tracing::warn!(pool = pool.name, upstream = member.base, error = %e, attempt, "upstream connect failed");
                if replayable && attempt < 2 {
                    if let Some(next) = pool.pick(Some(&member.base)) {
                        if next.base != member.base {
                            member = next;
                            continue;
                        }
                    }
                }
                return error("GW.SERVICE_UNAVAILABLE", format!("{} is unavailable: {e}", pool.name), route.id);
            }
            Err(SendError::Timeout) => {
                return error("GW.SERVICE_TIMEOUT", format!("{} did not answer in {}s", pool.name, timeout.as_secs()), route.id);
            }
            Err(SendError::Other(e)) => {
                tracing::warn!(pool = pool.name, upstream = member.base, error = %e, "upstream request failed");
                return error("GW.SERVICE_FAILED", format!("{} failed to answer: {e}", pool.name), route.id);
            }
        }
    }
}

enum SendError {
    Connect(String),
    Timeout,
    Other(String),
}

async fn send(
    client: &HttpClient,
    method: &Method,
    headers: &HeaderMap,
    member: &Member,
    path_and_query: &str,
    body: Body,
    timeout: Duration,
) -> Result<hyper::Response<hyper::body::Incoming>, SendError> {
    let uri: Uri = format!("{}{}", member.base, path_and_query)
        .parse()
        .map_err(|e| SendError::Other(format!("bad upstream uri: {e}")))?;
    let mut req = hyper::Request::builder()
        .method(method.clone())
        .uri(uri)
        .body(body)
        .map_err(|e| SendError::Other(e.to_string()))?;
    *req.headers_mut() = headers.clone();
    if let Ok(v) = HeaderValue::from_str(&member.authority) {
        req.headers_mut().insert(header::HOST, v);
    }
    match tokio::time::timeout(timeout, client.request(req)).await {
        Err(_) => Err(SendError::Timeout),
        Ok(Ok(resp)) => Ok(resp),
        Ok(Err(e)) => {
            if e.is_connect() {
                Err(SendError::Connect(e.to_string()))
            } else {
                Err(SendError::Other(e.to_string()))
            }
        }
    }
}

fn finish(resp: hyper::Response<hyper::body::Incoming>, sse: bool, route: &Route) -> Response {
    let (mut parts, body) = resp.into_parts();
    strip_hop_by_hop(&mut parts.headers);
    let is_stream = header_str(&parts.headers, "content-type").is_some_and(|c| c.contains("text/event-stream"));
    if sse && is_stream {
        // `SSELoggingFilter`: nothing between here and the browser may buffer the stream.
        parts.headers.remove(header::CONTENT_LENGTH);
        parts.headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache, no-store, must-revalidate"));
        parts.headers.insert("x-accel-buffering", HeaderValue::from_static("no"));
        // A body of known length gets its Content-Length put back by axum; as a plain stream it
        // goes out chunked, event by event.
        let stream = http_body_util::BodyExt::into_data_stream(body);
        return with_route(Response::from_parts(parts, Body::from_stream(stream)), route.id);
    }
    with_route(Response::from_parts(parts, Body::new(body)), route.id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hm(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(*k, HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn forwarding_headers_match_spring() {
        // As observed through the Spring gateway with a Host and no forwarded headers.
        let mut h = hm(&[("host", "leadzump.local.modlix.com"), ("x-forwarded-proto", "https")]);
        add_forwarding_headers(&mut h, "[::1]:56232".parse().unwrap());
        assert_eq!(h["x-forwarded-proto"], "https,http");
        assert_eq!(h["x-forwarded-host"], "leadzump.local.modlix.com");
        assert_eq!(h["x-forwarded-port"], "80");
        assert_eq!(h["x-forwarded-for"], "0:0:0:0:0:0:0:1");
        assert_eq!(h["forwarded"], "proto=http;host=leadzump.local.modlix.com;for=\"[0:0:0:0:0:0:0:1]:56232\"");

        // And with caller-supplied forwarded headers and a Host with a port.
        let mut h = hm(&[
            ("host", "localhost:8080"),
            ("x-forwarded-host", "foo.com"),
            ("x-forwarded-port", "443"),
            ("x-forwarded-for", "9.9.9.9"),
        ]);
        add_forwarding_headers(&mut h, "127.0.0.1:5000".parse().unwrap());
        assert_eq!(h["x-forwarded-host"], "foo.com,localhost:8080");
        assert_eq!(h["x-forwarded-port"], "443,8080");
        assert_eq!(h["x-forwarded-for"], "9.9.9.9,127.0.0.1");
        assert_eq!(h["forwarded"], "proto=http;host=\"localhost:8080\";for=\"127.0.0.1:5000\"");
    }

    #[test]
    fn scheme_host_port_like_gateway_filter() {
        let h = hm(&[("host", "leadzump.ai"), ("x-forwarded-proto", "https")]);
        assert_eq!(scheme_host_port(&h), ("https".into(), "leadzump.ai".into(), "-1".into()));
        let h = hm(&[("host", "localhost:8080")]);
        assert_eq!(scheme_host_port(&h), ("http".into(), "localhost".into(), "8080".into()));
        let h = hm(&[("host", "x"), ("x-forwarded-host", "a.com:9"), ("x-forwarded-port", "443")]);
        assert_eq!(scheme_host_port(&h), ("http".into(), "a.com".into(), "443".into()));
    }

    #[test]
    fn hop_by_hop_and_connection_named_headers_go() {
        let mut h = hm(&[("connection", "keep-alive, x-secret"), ("x-secret", "1"), ("keep-alive", "5"), ("x-keep", "1")]);
        strip_hop_by_hop(&mut h);
        assert!(h.get("x-secret").is_none() && h.get("keep-alive").is_none() && h.get("connection").is_none());
        assert_eq!(h["x-keep"], "1");
    }

    #[test]
    fn ipv4_mapped_reads_as_ipv4() {
        assert_eq!(java_ip("::ffff:10.0.0.1".parse().unwrap()), "10.0.0.1");
    }
}
