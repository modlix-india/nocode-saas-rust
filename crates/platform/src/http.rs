//! HTTP behaviour every service shares: the request observation layer, CORS, and the
//! response headers browsers and callers already depend on from the Java services.

use std::time::Instant;

use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use tracing::Instrument;

/// Which Spring Security header set this process writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderStyle {
    /// The reactive services (core, ui, security, multi, ...): Spring Security's defaults,
    /// `X-Frame-Options: DENY` and `Referrer-Policy: no-referrer`, no CSP.
    Reactive,
    /// files: `X-Frame-Options: SAMEORIGIN` and `Content-Security-Policy: frame-ancestors 'self'`,
    /// no `Referrer-Policy`, so its files can be framed by the apps that show them.
    Files,
}

static HEADER_STYLE: std::sync::OnceLock<HeaderStyle> = std::sync::OnceLock::new();

/// Picks this process's header set; call once at startup, before serving. Unset means
/// [`HeaderStyle::Reactive`].
pub fn set_header_style(style: HeaderStyle) {
    let _ = HEADER_STYLE.set(style);
}

pub fn header_style() -> HeaderStyle {
    HEADER_STYLE.get().copied().unwrap_or(HeaderStyle::Reactive)
}

/// The headers Spring Security writes on responses it gets to finish: errors, 304s, and
/// anything not streamed. `no_cache` adds the cache-busting trio it adds when the controller
/// set no cache header of its own.
pub fn spring_security_headers(h: &mut HeaderMap, no_cache: bool) {
    write_security_headers(h, no_cache, header_style());
}

fn write_security_headers(h: &mut HeaderMap, no_cache: bool, style: HeaderStyle) {
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    h.insert("x-xss-protection", HeaderValue::from_static("0"));
    if no_cache {
        h.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-cache, no-store, max-age=0, must-revalidate"),
        );
        h.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
        h.insert(header::EXPIRES, HeaderValue::from_static("0"));
    }
    match style {
        HeaderStyle::Files => {
            h.insert("x-frame-options", HeaderValue::from_static("SAMEORIGIN"));
            h.insert("content-security-policy", HeaderValue::from_static("frame-ancestors 'self'"));
        }
        HeaderStyle::Reactive => {
            h.insert("x-frame-options", HeaderValue::from_static("DENY"));
            h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
        }
    }
}

/// Spring's `CorsFilter` with `ISecurityConfiguration.corsConfigurationSource` (any origin,
/// method and header). Unlike a generic CORS layer it answers only cross-origin requests:
/// `Access-Control-Allow-Origin` appears when the request carries an `Origin` that differs from
/// its own host, and the three `Vary` headers appear on every response.
pub async fn spring_cors(req: Request, next: Next) -> Response {
    let origin = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let host = req
        .headers()
        .get("x-forwarded-host")
        .or_else(|| req.headers().get(header::HOST))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let cross_origin = origin.as_deref().is_some_and(|o| {
        let without_scheme = o.split_once("://").map(|(_, rest)| rest).unwrap_or(o);
        !without_scheme.eq_ignore_ascii_case(&host)
    });

    let preflight = cross_origin
        && req.method() == Method::OPTIONS
        && req.headers().contains_key(header::ACCESS_CONTROL_REQUEST_METHOD);

    let mut resp = if preflight {
        let mut r = Response::new(Body::empty());
        let h = r.headers_mut();
        if let Some(m) = req.headers().get(header::ACCESS_CONTROL_REQUEST_METHOD) {
            h.insert(header::ACCESS_CONTROL_ALLOW_METHODS, m.clone());
        }
        if let Some(rh) = req.headers().get(header::ACCESS_CONTROL_REQUEST_HEADERS) {
            h.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, rh.clone());
        }
        h.insert(header::ACCESS_CONTROL_MAX_AGE, HeaderValue::from_static("1800"));
        r
    } else {
        next.run(req).await
    };

    let h = resp.headers_mut();
    for v in ["Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers"] {
        h.append(header::VARY, HeaderValue::from_static(v));
    }
    if cross_origin {
        h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    }
    resp
}

/// The Spring MVC handler pattern a response came from, for the `uri` metric label. Handlers
/// attach it so Rust and Java instances of a route land in the same Prometheus series.
#[derive(Clone, Copy, Debug)]
pub struct RouteTemplate(pub &'static str);

pub fn with_route(mut resp: Response, route: &'static str) -> Response {
    resp.extensions_mut().insert(RouteTemplate(route));
    resp
}

/// One layer for every request: a tracing span (continuing the caller's trace and carrying the
/// `x-debug` tag the Java services use), and the request duration histogram labelled by the
/// route template the handler reported (`unmatched` when none did, so scanners cannot blow up
/// the label set).
pub async fn observe(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let debug_tag = req
        .headers()
        .get("x-debug")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let span = tracing::info_span!(
        "http.request",
        otel.kind = "server",
        method = %method,
        path = %req.uri().path(),
        x_debug = %debug_tag,
        trace_id = tracing::field::Empty,
        route = tracing::field::Empty,
        status = tracing::field::Empty,
    );
    let trace_id = crate::telemetry::continue_trace(&span, req.headers());
    if !trace_id.is_empty() {
        span.record("trace_id", trace_id.as_str());
    }

    let start = Instant::now();
    let resp = next.run(req).instrument(span.clone()).await;
    let elapsed = start.elapsed().as_secs_f64();

    let route = resp
        .extensions()
        .get::<RouteTemplate>()
        .map(|r| r.0)
        .unwrap_or("unmatched");
    let status = resp.status().as_u16();
    span.record("route", route);
    span.record("status", status);

    metrics::histogram!(
        crate::telemetry::HTTP_DURATION,
        "method" => method.to_string(),
        "route" => route,
        "status" => status.to_string(),
    )
    .record(elapsed);

    if status >= 500 {
        tracing::warn!(parent: &span, status, elapsed_ms = elapsed * 1000.0, "request failed");
    } else {
        tracing::debug!(parent: &span, status, elapsed_ms = elapsed * 1000.0, "request done");
    }
    resp
}

/// A response with only Spring Security's headers, for 304s.
pub fn not_modified() -> Response {
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::NOT_MODIFIED;
    let h = resp.headers_mut();
    h.insert(HeaderName::from_static("x-cache"), HeaderValue::from_static("HIT"));
    spring_security_headers(h, false);
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_sets() {
        let mut h = HeaderMap::new();
        write_security_headers(&mut h, true, HeaderStyle::Reactive);
        assert_eq!(h["x-frame-options"], "DENY");
        assert_eq!(h["referrer-policy"], "no-referrer");
        assert_eq!(h[header::PRAGMA], "no-cache");
        assert!(h.get("content-security-policy").is_none());

        let mut h = HeaderMap::new();
        write_security_headers(&mut h, false, HeaderStyle::Files);
        assert_eq!(h["x-frame-options"], "SAMEORIGIN");
        assert_eq!(h["content-security-policy"], "frame-ancestors 'self'");
        assert!(h.get("referrer-policy").is_none());
        assert!(h.get(header::CACHE_CONTROL).is_none());
        assert_eq!(header_style(), HeaderStyle::Reactive, "unset is reactive");
    }
}
