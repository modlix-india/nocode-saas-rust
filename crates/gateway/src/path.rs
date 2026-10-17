//! How the gateway reads a request path: what to forward, and which client and app the URL
//! names, if any. Reproduces `GatewayFilter.filter` and `getCodesFromURL`.

/// The path to forward and the "codes part" in front of it.
#[derive(Debug, PartialEq, Eq)]
pub struct SplitPath<'a> {
    /// Everything before `/api/`, `/manifest/` or `/page/`, when it names codes; else empty.
    pub codes_part: &'a str,
    /// The forwarded path: from `/api/` (or `/manifest/`, `/page/`) on, trimmed, without a
    /// trailing `/` unless it is just `/`.
    pub forward: String,
}

/// `/api/` wins; the codes in front of it count only when a `/page/` comes before the `/api/`.
/// Failing `/api/`, `/manifest/` and then `/page/` cut the path and their prefix is the codes.
pub fn split(path: &str) -> SplitPath<'_> {
    let (codes_part, modified) = if let Some(api) = path.find("/api/") {
        let page = path.find("/page/");
        let codes = match page {
            Some(p) if p <= api => &path[..api],
            _ => "",
        };
        (codes, &path[api..])
    } else if let Some(m) = path.find("/manifest/") {
        (&path[..m], &path[m..])
    } else if let Some(p) = path.find("/page/") {
        (&path[..p], &path[p..])
    } else {
        ("", path)
    };

    let trimmed = modified.trim();
    let forward = if trimmed.len() != 1 && trimmed.ends_with('/') {
        trimmed[..trimmed.len() - 1].to_string()
    } else {
        trimmed.to_string()
    };
    SplitPath { codes_part, forward }
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

    #[test]
    fn api_paths_never_take_codes() {
        assert_eq!(s("/api/files/static/file/a.png"), ("".into(), "/api/files/static/file/a.png".into()));
        assert_eq!(s("/leadzump/SYSTEM/api/ui/page/home"), ("".into(), "/api/ui/page/home".into()));
        assert_eq!(s("/api/ui/application/"), ("".into(), "/api/ui/application".into()));
    }

    #[test]
    fn page_before_api_keeps_codes() {
        // Java cuts the codes part at `/api/`, so it keeps `/page`; the codes still read as
        // (SYSTEM, leadzump) because only the first two segments count.
        assert_eq!(s("/leadzump/SYSTEM/page/api/x"), ("/leadzump/SYSTEM/page".into(), "/api/x".into()));
        assert_eq!(codes_from_url("/leadzump/SYSTEM/page"), Some(("SYSTEM".into(), "leadzump".into())));
    }

    #[test]
    fn page_and_manifest_paths() {
        assert_eq!(s("/leadzump/FIN/page/home"), ("/leadzump/FIN".into(), "/page/home".into()));
        assert_eq!(s("/leadzump/FIN/manifest/manifest.json"), ("/leadzump/FIN".into(), "/manifest/manifest.json".into()));
        assert_eq!(s("/"), ("".into(), "/".into()));
        assert_eq!(s("/hello/"), ("".into(), "/hello".into()));
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
