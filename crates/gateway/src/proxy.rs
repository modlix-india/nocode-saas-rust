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
//! Rust only: a route may rewrite its prefix and name fixed codes (`RouteConfig::rewrite`,
//! `app_code`, `client_code`, `anonymous`). Such a request goes out for those codes whatever
//! its host and headers say, without a host lookup, and without `Authorization` when anonymous;
//! the forwarded headers are added as for any other request.
//!
//! Bodies stream both ways with no buffering, so uploads, downloads and server-sent events pass
//! through at the pace the two ends set.
//!
//! A unit calling another unit's internal path through the gateway (`resolve::is_internal_call`)
//! gets none of the above but the `Host`: its codes, `x-draft` and forwarded headers arrive as
//! the caller sent them, as if it had called the unit directly.
//!
//! Each request goes through its pool's circuit breaker and is retried at most once, on another
//! instance: after a connection that could not be opened (nothing was sent, so any request
//! without a body), or after a 502/503/504 answer to a GET, HEAD, OPTIONS, PUT or DELETE
//! without a body, within the pool's retry budget. A timeout is never retried, nor is anything
//! that was sent with a body.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, HttpBody};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use platform::error::{AppError, Coded};
use platform::http::with_route;

use crate::config::RetryConfig;
use crate::path::{split, SplitPath};
use crate::pool::{Member, Pool};
use crate::resolve::{codes_match, is_internal_call, Resolver};
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

    // Lighthouse's Lighthouse API is never served from outside (Kiran, 2026-10-19). No pool may point
    // at Lighthouse either (`pool::is_lighthouse`), so its other paths fall through to the ui.
    if parts.uri.path() == "/eureka" || parts.uri.path().starts_with("/eureka/") {
        return error("COMMON.NOT_FOUND", "the registry's API is not served through the gateway".into(), "registry-blocked");
    }

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

    let headers = match upstream_headers(&gw, &parts.headers, &split, client, route).await {
        Ok(h) => h,
        Err(resp) => return resp,
    };

    let forward_path = route.forward_path(&split.forward);
    let sse = wants_event_stream(&forward_path, &parts.headers);
    let timeout = route.timeout.unwrap_or(gw.default_timeout);
    let path_and_query = match &query {
        Some(q) => format!("{forward_path}?{q}"),
        None => forward_path.into_owned(),
    };
    // Only a request without a body can be sent a second time: a body is streamed to the first
    // instance as it arrives and is gone once handed over. The body itself says whether it has
    // anything (HTTP/2 needs no Content-Length).
    let bodiless = body.is_end_stream() || body.size_hint().exact() == Some(0);

    let req = Outgoing { method: &parts.method, headers: &headers, path_and_query: &path_and_query, timeout, sse, bodiless };
    forward(&gw, route, &req, body).await
}

/// What reaches the instance: the caller's headers with the codes, `x-draft` and forwarded
/// headers settled as the module notes say, or the answer to give when the host cannot be
/// resolved.
async fn upstream_headers(
    gw: &Gateway,
    incoming: &HeaderMap,
    split: &SplitPath<'_>,
    client: SocketAddr,
    route: &Route,
) -> Result<HeaderMap, Response> {
    let supplied_client = header_str(incoming, "clientcode");
    let supplied_app = header_str(incoming, "appcode");
    let mut headers = incoming.clone();
    if let Some((app_code, client_code)) = &route.codes {
        // Rust only: a route served by one app on every host. Its codes win over the caller's
        // and the host is not resolved; everything else is as for any other request.
        for (name, value) in [("appcode", app_code), ("clientcode", client_code)] {
            if let Ok(v) = HeaderValue::from_str(value) {
                headers.insert(name, v);
            }
        }
        headers.remove("x-draft");
        if route.anonymous {
            headers.remove(header::AUTHORIZATION);
        }
        strip_hop_by_hop(&mut headers);
        add_forwarding_headers(&mut headers, client);
        platform::telemetry::inject_trace_headers(&mut headers);
        return Ok(headers);
    }
    if route.anonymous {
        headers.remove(header::AUTHORIZATION);
    }
    if is_internal_call(&split.forward, supplied_client, supplied_app) {
        strip_hop_by_hop(&mut headers);
        platform::telemetry::inject_trace_headers(&mut headers);
        return Ok(headers);
    }

    let (scheme, host, port) = scheme_host_port(incoming);
    let resolved = match gw.resolver.resolve(&scheme, &host, &port, split.codes_part, split.codes_unverified, supplied_client, supplied_app).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(host, error = %e, "host resolution failed");
            return Err(error(
                "GW.HOST_UNRESOLVED",
                format!("Unable to resolve the application for the host {host}: {e}"),
                route.id,
            ));
        }
    };

    let blank = |v: Option<&str>| v.map(str::trim).unwrap_or("").is_empty();
    if blank(supplied_app) {
        if let Ok(v) = HeaderValue::from_str(&resolved.app_code) {
            headers.insert("appcode", v);
        }
    }
    if blank(supplied_client) {
        if let Ok(v) = HeaderValue::from_str(&resolved.client_code) {
            headers.insert("clientcode", v);
        }
    }
    headers.remove("x-draft");
    if resolved.draft && codes_match(supplied_app, &resolved.app_code, supplied_client, &resolved.client_code) {
        headers.insert("x-draft", HeaderValue::from_static("true"));
    }
    strip_hop_by_hop(&mut headers);
    add_forwarding_headers(&mut headers, client);
    platform::telemetry::inject_trace_headers(&mut headers);
    Ok(headers)
}

/// The request as it goes to an instance.
struct Outgoing<'a> {
    method: &'a Method,
    headers: &'a HeaderMap,
    path_and_query: &'a str,
    timeout: Duration,
    sse: bool,
    bodiless: bool,
}

/// 502, 503 and 504: the instance, or something in front of it, could not serve the request.
fn is_gateway_failure(status: StatusCode) -> bool {
    matches!(status, StatusCode::BAD_GATEWAY | StatusCode::SERVICE_UNAVAILABLE | StatusCode::GATEWAY_TIMEOUT)
}

/// Another instance than `member` to retry on, if the pool has one.
fn other_member(pool: &Pool, member: &Member) -> Option<Arc<Member>> {
    pool.pick(Some(&member.base)).filter(|next| next.base != member.base)
}

fn jitter(cfg: &RetryConfig) -> Duration {
    use rand::Rng;
    let (lo, hi) = (cfg.jitter_min_ms.min(cfg.jitter_max_ms), cfg.jitter_max_ms.max(cfg.jitter_min_ms));
    Duration::from_millis(rand::thread_rng().gen_range(lo..=hi))
}

fn count_retry(pool: &Pool, reason: &'static str) {
    metrics::counter!("gateway_retries_total", "pool" => pool.name.clone(), "reason" => reason).increment(1);
}

/// Sends the request to the route's pool through its circuit breaker, retrying at most once on
/// another instance (see the module notes for when).
async fn forward(gw: &Gateway, route: &Route, req: &Outgoing<'_>, body: Body) -> Response {
    let pool = &route.pool;
    let Some(first) = pool.pick(None) else {
        return error("GW.SERVICE_STARTING", format!("No instance of {} is available", pool.name), route.id);
    };
    let permit = match pool.breaker.admit() {
        Ok(p) => p,
        Err(wait) => {
            metrics::counter!("gateway_pool_breaker_rejections_total", "pool" => pool.name.clone()).increment(1);
            let when = if wait.is_zero() {
                "its trial requests are under way".to_string()
            } else {
                format!("trial requests start in {} ms", wait.as_millis())
            };
            // Quiet: one line per rejected request would flood the log during an outage; the
            // breaker logs when it opens and closes.
            let coded = Coded::new("GW.SERVICE_UNAVAILABLE")
                .debug(format!("{} is failing: its circuit breaker is open, {when}", pool.name));
            return with_route(platform::error::coded_response_quiet(&coded), route.id);
        }
    };
    pool.budget.record_request();

    let retry_on_5xx = pool.config().retry.on_5xx
        && req.bodiless
        && matches!(*req.method, Method::GET | Method::HEAD | Method::OPTIONS | Method::PUT | Method::DELETE);
    let mut body = Some(body);
    let mut member = first;
    let mut retried = false;
    // A 5xx answer kept while its retry runs: the caller gets it if the retry gets nothing.
    let mut held: Option<hyper::Response<hyper::body::Incoming>> = None;
    loop {
        let this_body = if req.bodiless { Body::empty() } else { body.take().unwrap_or_else(Body::empty) };
        match send(&gw.client, req.method, req.headers, &member, req.path_and_query, this_body, req.timeout).await {
            Ok(resp) => {
                let failed = is_gateway_failure(resp.status());
                if !failed {
                    pool.passed(&member);
                } else {
                    pool.failed(&member);
                    if retry_on_5xx && !retried {
                        if let Some(next) = other_member(pool, &member) {
                            if pool.budget.try_retry() {
                                tracing::debug!(pool = pool.name, upstream = member.base, status = resp.status().as_u16(), "retrying on another instance");
                                count_retry(pool, "5xx");
                                retried = true;
                                held = Some(resp);
                                member = next;
                                tokio::time::sleep(jitter(&pool.config().retry)).await;
                                continue;
                            }
                        }
                    }
                }
                pool.breaker.record(permit, !failed);
                return finish(resp, req.sse, route);
            }
            Err(SendError::Connect(e)) => {
                pool.eject(&member);
                tracing::warn!(pool = pool.name, upstream = member.base, error = %e, "upstream connect failed");
                if req.bodiless && !retried {
                    if let Some(next) = other_member(pool, &member) {
                        count_retry(pool, "connect");
                        retried = true;
                        member = next;
                        continue;
                    }
                }
                pool.breaker.record(permit, false);
                if let Some(resp) = held {
                    return finish(resp, req.sse, route);
                }
                return error("GW.SERVICE_UNAVAILABLE", format!("{} is unavailable: {e}", pool.name), route.id);
            }
            Err(SendError::Timeout) => {
                pool.failed(&member);
                pool.breaker.record(permit, false);
                if let Some(resp) = held {
                    return finish(resp, req.sse, route);
                }
                return error(
                    "GW.SERVICE_TIMEOUT",
                    format!("{} did not answer in {}s", pool.name, req.timeout.as_secs()),
                    route.id,
                );
            }
            Err(SendError::Other(e)) => {
                pool.failed(&member);
                tracing::warn!(pool = pool.name, upstream = member.base, error = %e, "upstream request failed");
                pool.breaker.record(permit, false);
                if let Some(resp) = held {
                    return finish(resp, req.sse, route);
                }
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
