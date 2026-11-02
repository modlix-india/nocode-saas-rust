//! How the gateway reads a request path: what to forward, and which client and app the URL
//! names, if any. Reproduces `GatewayFilter.filter` and `getCodesFromURL`, with one difference
//! (DIFFERENCES.md): codes in front of `/api/` with no `/page/` before it are kept as a
//! candidate, which counts only when it names a real app and client (`resolve`).

/// The path to forward and the "codes part" in front of it.
#[derive(Debug, PartialEq, Eq)]
pub struct SplitPath<'a> {
    /// Everything before `/api/`, `/manifest/` or `/page/`; empty when nothing comes before.
    pub codes_part: &'a str,
    /// The codes part stands in front of `/api/` with no `/page/` before the `/api/`: Java never
    /// read it, and it counts only when it names an app and a client that has access to it.
    /// Relative URLs put any junk there (`/x/y/api/ui/application`).
    pub codes_unverified: bool,
    /// The forwarded path: from `/api/` (or `/manifest/`, `/page/`) on, trimmed, without a
    /// trailing `/` unless it is just `/`.
    pub forward: String,
}

/// `/api/` wins; the codes in front of it are sure when a `/page/` comes before the `/api/`, and
/// only a candidate otherwise. Failing `/api/`, `/manifest/` and then `/page/` cut the path and
/// their prefix is the codes.
pub fn split(path: &str) -> SplitPath<'_> {
    let (codes_part, codes_unverified, modified) = if let Some(api) = path.find("/api/") {
        let page_at = path.find("/page/").filter(|p| *p <= api);
        if page_at == Some(0) {
            // Rust only: `/page/<name>/<id>/api/...` is a page with path parts calling a relative
            // `api/...` on the app's own host. Nothing in front of `/page/` names an app or a
            // client, so the host decides (the codes part would otherwise read `/page/<name>` as
            // app `page`, client `<name>`: "unknown client" on every call of such a page).
            ("", false, &path[api..])
        } else {
            (&path[..api], page_at.is_none(), &path[api..])
        }
    } else if let Some(m) = path.find("/manifest/") {
        (&path[..m], false, &path[m..])
    } else if let Some(p) = path.find("/page/") {
        (&path[..p], false, &path[p..])
    } else {
        ("", false, path)
    };

    let trimmed = modified.trim();
    let forward = if trimmed.len() != 1 && trimmed.ends_with('/') {
        trimmed[..trimmed.len() - 1].to_string()
    } else {
        trimmed.to_string()
    };
    SplitPath { codes_part, codes_unverified, forward }
}

/// `getCodesFromURL`: `/<appCode>/<clientCode>` (more segments allowed after) to
/// `(clientCode, appCode)`. Nothing for an empty or `/` codes part, or fewer than two segments.
pub fn codes_from_url(codes_part: &str) -> Option<(String, String)> {
    if codes_part.trim().is_empty() || codes_part == "/" {
        return None;
    }
    let parts: Vec<&str> = codes_part.split('/').collect();
    if parts.len() > 2 {
        Some((parts[2].to_string(), parts[1].to_string()))
    } else {
        None
    }
}

/// Codes worth asking security about: app and client codes are letters, digits, `_` and `-`
/// (at most 64), so anything else in front of `/api/` is a relative URL's junk and resolves by
/// host without a lookup.
pub fn plausible_codes(client_code: &str, app_code: &str) -> bool {
    let ok = |s: &str| !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    ok(client_code) && ok(app_code)
}

/// The first label of a host name.
pub fn first_label(host: &str) -> &str {
    host.split('.').next().unwrap_or("")
}

/// A `t-<32 lowercase hex>` first label: an editing session's draft grant.
pub fn is_draft_token_label(host: &str) -> bool {
    let l = first_label(host);
    l.len() == 34
        && l.starts_with("t-")
        && l[2..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(p: &str) -> (String, String) {
        let r = split(p);
        (r.codes_part.to_string(), r.forward)
    }

    fn unverified(p: &str) -> bool {
        split(p).codes_unverified
    }

    #[test]
    fn codes_in_front_of_api_are_only_a_candidate() {
        assert_eq!(s("/api/files/static/file/a.png"), ("".into(), "/api/files/static/file/a.png".into()));
        assert_eq!(s("/api/ui/application/"), ("".into(), "/api/ui/application".into()));
        assert_eq!(s("/leadzump/FIN/api/webhooks/whatsapp"), ("/leadzump/FIN".into(), "/api/webhooks/whatsapp".into()));
        assert!(unverified("/leadzump/FIN/api/webhooks/whatsapp"));
        // A `/page/` after the `/api/` is part of the forwarded path, not a marker.
        assert_eq!(s("/leadzump/SYSTEM/api/ui/page/home"), ("/leadzump/SYSTEM".into(), "/api/ui/page/home".into()));
        assert!(unverified("/leadzump/SYSTEM/api/ui/page/home"));
        // Junk and one segment: still a candidate, which codes_from_url or the lookup turns down.
        assert_eq!(s("/x/y/api/ui/application"), ("/x/y".into(), "/api/ui/application".into()));
        assert!(unverified("/x/y/api/ui/application"));
        assert_eq!(s("/assets/api/x"), ("/assets".into(), "/api/x".into()));
        assert_eq!(codes_from_url("/assets"), None);
        assert!(unverified("/api/x"), "an empty candidate names nothing");
        assert_eq!(codes_from_url(split("/api/x").codes_part), None);
    }

    #[test]
    fn page_before_api_keeps_codes() {
        // Java cuts the codes part at `/api/`, so it keeps `/page`; the codes still read as
        // (SYSTEM, leadzump) because only the first two segments count.
        assert_eq!(s("/leadzump/SYSTEM/page/api/x"), ("/leadzump/SYSTEM/page".into(), "/api/x".into()));
        assert!(!unverified("/leadzump/SYSTEM/page/api/x"));
        assert_eq!(codes_from_url("/leadzump/SYSTEM/page"), Some(("SYSTEM".into(), "leadzump".into())));
    }

    #[test]
    fn a_page_with_path_parts_on_the_apps_own_host_resolves_by_host() {
        assert_eq!(s("/page/booking/01ABC/api/core/function/execute/CxZump/caseGet"), ("".into(), "/api/core/function/execute/CxZump/caseGet".into()));
        assert!(!unverified("/page/booking/01ABC/api/core/function/execute/CxZump/caseGet"));
        assert_eq!(codes_from_url(split("/page/booking/01ABC/api/x").codes_part), None);
        // Codes in front of `/page/` still count.
        assert_eq!(s("/cxzump/SASIC/page/booking/01ABC/api/x"), ("/cxzump/SASIC/page/booking/01ABC".into(), "/api/x".into()));
        assert_eq!(codes_from_url("/cxzump/SASIC/page/booking/01ABC"), Some(("SASIC".into(), "cxzump".into())));
    }

    #[test]
    fn page_and_manifest_paths() {
        assert_eq!(s("/leadzump/FIN/page/home"), ("/leadzump/FIN".into(), "/page/home".into()));
        assert!(!unverified("/leadzump/FIN/page/home"));
        assert_eq!(s("/leadzump/FIN/manifest/manifest.json"), ("/leadzump/FIN".into(), "/manifest/manifest.json".into()));
        assert!(!unverified("/leadzump/FIN/manifest/manifest.json"));
        assert_eq!(s("/"), ("".into(), "/".into()));
        assert_eq!(s("/hello/"), ("".into(), "/hello".into()));
        assert!(!unverified("/hello"));
    }

    #[test]
    fn plausible() {
        assert!(plausible_codes("FIN", "leadzump"));
        assert!(plausible_codes("KIRAN_54-a", "app2"));
        assert!(!plausible_codes("", "leadzump"));
        assert!(!plausible_codes("FIN", ""));
        assert!(!plausible_codes("a.b", "leadzump"));
        assert!(!plausible_codes("FIN", "static%20x"));
        assert!(!plausible_codes(&"A".repeat(65), "leadzump"));
    }

    #[test]
    fn codes() {
        assert_eq!(codes_from_url("/leadzump/FIN"), Some(("FIN".into(), "leadzump".into())));
        assert_eq!(codes_from_url("/leadzump"), None);
        assert_eq!(codes_from_url("/"), None);
        assert_eq!(codes_from_url(""), None);
        assert_eq!(codes_from_url("/a/b/c"), Some(("b".into(), "a".into())));
    }

    #[test]
    fn draft_labels() {
        assert!(is_draft_token_label("t-0123456789abcdef0123456789abcdef.apps.modlix.com"));
        assert!(!is_draft_token_label("t-0123456789ABCDEF0123456789abcdef.apps.modlix.com"));
        assert!(!is_draft_token_label("tea.modlix.com"));
        assert!(!is_draft_token_label("t-123.modlix.com"));
    }
}
