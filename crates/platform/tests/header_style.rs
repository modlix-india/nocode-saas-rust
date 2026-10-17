//! The files header set. Its own test binary: the header style is chosen once per process, and
//! the other tests rely on the default.

use axum::http::{header, HeaderMap, StatusCode};
use platform::http::{header_style, not_modified, set_header_style, spring_security_headers, HeaderStyle};

#[test]
fn files_header_set_is_chosen_once() {
    assert_eq!(header_style(), HeaderStyle::Reactive, "unset is reactive");
    set_header_style(HeaderStyle::Files);
    set_header_style(HeaderStyle::Reactive);
    assert_eq!(header_style(), HeaderStyle::Files, "the first choice holds");

    let mut h = HeaderMap::new();
    spring_security_headers(&mut h, true);
    assert_eq!(h["x-frame-options"], "SAMEORIGIN");
    assert_eq!(h["content-security-policy"], "frame-ancestors 'self'");
    assert!(h.get("referrer-policy").is_none());
    assert_eq!(h[header::CACHE_CONTROL], "no-cache, no-store, max-age=0, must-revalidate");
    assert_eq!(h["x-content-type-options"], "nosniff");

    let r = not_modified();
    assert_eq!(r.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(r.headers()["x-frame-options"], "SAMEORIGIN", "304s carry the files set too");
    assert!(r.headers().get(header::CACHE_CONTROL).is_none());
}
