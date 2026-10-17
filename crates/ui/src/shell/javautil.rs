//! Small Java behaviours the shell's answers depend on: `java.net.URI`'s idea of an absolute
//! http(s) address, `UniversalController`'s JS string literal and redirect rules, the SSO
//! beacon host, and `ObjectWithUniqueID`'s MD5 id.

use md5::{Digest, Md5};

/// What `java.net.URI` makes of an absolute http(s) address: the scheme as written, the host
/// (lower or upper case as written) and the port (-1 when absent).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaUri {
    pub scheme: String,
    pub host: String,
    pub port: i32,
}

const UNRESERVED_MARKS: &str = "-_.!~*'()";
const RESERVED: &str = ";/?:@&=+$,[]";

/// `URI.create` refuses these anywhere outside an escape: spaces, controls and RFC 2396's
/// "unwise" and delimiter characters.
fn legal_char(c: char) -> bool {
    if c.is_ascii_alphanumeric() || UNRESERVED_MARKS.contains(c) || RESERVED.contains(c) || c == '%' || c == '#' {
        return true;
    }
    // Java's "other" category: non-ASCII characters that are not controls or spaces.
    !c.is_ascii() && !c.is_control() && !c.is_whitespace()
}

fn valid_escapes(s: &str) -> bool {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if i + 2 >= b.len() + 0 && i + 2 > b.len() - 1 + 1 {
                return false;
            }
            if i + 2 >= b.len() || !b[i + 1].is_ascii_hexdigit() || !b[i + 2].is_ascii_hexdigit() {
                return false;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    true
}

/// RFC 2396 `hostname`: dot-separated labels of letters, digits and inner hyphens, the last of
/// which starts with a letter, an optional trailing dot; or an IPv4 address.
fn server_host(h: &str) -> bool {
    if h.is_empty() {
        return false;
    }
    let ipv4 = h.split('.').count() == 4 && h.split('.').all(|p| !p.is_empty() && p.len() <= 3 && p.chars().all(|c| c.is_ascii_digit()));
    if ipv4 {
        return true;
    }
    let trimmed = h.strip_suffix('.').unwrap_or(h);
    let labels: Vec<&str> = trimmed.split('.').collect();
    let label_ok = |l: &&str| {
        !l.is_empty()
            && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    };
    labels.iter().all(label_ok) && labels.last().is_some_and(|l| l.chars().next().is_some_and(|c| c.is_ascii_alphabetic()))
}

/// `UniversalController.absoluteHttpUri`: an absolute `http`/`https` address with a host, as
/// `java.net.URI` parses it, or `None`.
pub fn absolute_http_uri(value: Option<&str>) -> Option<JavaUri> {
    let v = value?;
    if v.trim().is_empty() {
        return None;
    }
    if !v.chars().all(legal_char) || !valid_escapes(v) || v.matches('#').count() > 1 {
        return None;
    }
    let colon = v.find(':')?;
    let scheme = &v[..colon];
    let mut sc = scheme.chars();
    if !sc.next().is_some_and(|c| c.is_ascii_alphabetic()) || !sc.all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c)) {
        return None;
    }
    if !(scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")) {
        return None;
    }
    let rest = &v[colon + 1..];
    let after = rest.strip_prefix("//")?;
    let end = after.find(['/', '?', '#']).unwrap_or(after.len());
    let authority = &after[..end];
    // The user information ends at the last '@' Java's parser can take; the host follows.
    let host_port = match authority.rfind('@') {
        Some(i) => &authority[i + 1..],
        None => authority,
    };
    let (host, port) = if let Some(stripped) = host_port.strip_prefix('[') {
        let close = stripped.find(']')?;
        let host = &host_port[..close + 2];
        let tail = &stripped[close + 1..];
        let port = match tail.strip_prefix(':') {
            Some(p) if p.is_empty() => -1,
            Some(p) => p.parse::<i32>().ok()?,
            None if tail.is_empty() => -1,
            None => return None,
        };
        (host.to_string(), port)
    } else {
        match host_port.rsplit_once(':') {
            Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => {
                (h.to_string(), if p.is_empty() { -1 } else { p.parse::<i32>().unwrap_or(-1) })
            }
            Some(_) => return None,
            None => (host_port.to_string(), -1),
        }
    };
    // A registry-based authority (one that is not a host name) leaves getHost() null.
    if !(host.starts_with('[') || server_host(&host)) {
        return None;
    }
    Some(JavaUri { scheme: scheme.to_string(), host, port })
}

/// `UniversalController.jsString`: a single-quoted JS literal that cannot close itself, the
/// script element, or the line.
pub fn js_string(s: Option<&str>) -> String {
    let Some(s) = s else {
        return "''".into();
    };
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        match c {
            '\'' => out.push_str("\\'"),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c => out.push(c),
        }
    }
    out.push('\'');
    out
}

/// `UniversalController.decideRedirectWithoutLookup`: the destination, or `None` when only a
/// host lookup can say.
pub fn decide_redirect_without_lookup(redirect_url: Option<&str>, own_host: &str) -> Option<String> {
    let Some(r) = redirect_url.filter(|r| !r.trim().is_empty()) else {
        return Some("/".into());
    };
    if let Some(rest) = r.strip_prefix('/') {
        return Some(if rest.starts_with('/') || rest.starts_with('\\') { "/".into() } else { r.to_string() });
    }
    let Some(uri) = absolute_http_uri(Some(r)) else {
        return Some("/".into());
    };
    if uri.host.eq_ignore_ascii_case(own_host) {
        return Some(r.to_string());
    }
    None
}

/// `UniversalController.clientFacingHost`: the first `X-Forwarded-Host` hop without its port,
/// else the request's own host.
pub fn client_facing_host(forwarded_host: Option<&str>, request_host: &str) -> String {
    match forwarded_host.filter(|h| !h.trim().is_empty()) {
        None => request_host.to_string(),
        Some(raw) => {
            let first = raw.split(',').next().unwrap_or("").trim();
            first.split(':').next().unwrap_or("").to_string()
        }
    }
}

/// `IndexHTMLService.deriveBeaconHost`: the authzump host for an environment's
/// `security.appCodeSuffix`.
pub fn derive_beacon_host(app_code_suffix: Option<&str>) -> String {
    let Some(s) = app_code_suffix.filter(|s| !s.trim().is_empty()) else {
        return "authzump.ai".into();
    };
    let trimmed = s.strip_prefix('.').unwrap_or(s);
    let env = trimmed.split('.').next().unwrap_or("");
    if env.trim().is_empty() {
        return "authzump.ai".into();
    }
    if env == "local" {
        format!("authzump.{env}.modlix.com")
    } else {
        format!("{env}.authzump.ai")
    }
}

/// `ObjectWithUniqueID.getUniqueId()` with no id set: the MD5 of the content as a
/// `BigInteger` in hex (leading zeros dropped), in double quotes.
pub fn md5_unique_id(content: &str) -> String {
    let digest = Md5::digest(content.as_bytes());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    let trimmed = hex.trim_start_matches('0');
    format!("\"{}\"", if trimmed.is_empty() { "0" } else { trimmed })
}

/// `IndexHTMLService.escapeHtml`: the five replacements, `&` first.
pub fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    // The Java ui `BeaconHostTest`.
    #[test]
    fn deployed_environments_live_on_the_ai_domain() {
        assert_eq!(derive_beacon_host(Some("")), "authzump.ai");
        assert_eq!(derive_beacon_host(None), "authzump.ai");
        assert_eq!(derive_beacon_host(Some(".dev")), "dev.authzump.ai");
        assert_eq!(derive_beacon_host(Some(".stage")), "stage.authzump.ai");
        assert_eq!(derive_beacon_host(Some("dev")), "dev.authzump.ai");
    }

    #[test]
    fn local_lives_on_modlix_com_because_that_is_what_dnsmasq_wildcards() {
        assert_eq!(derive_beacon_host(Some(".local")), "authzump.local.modlix.com");
        assert_eq!(derive_beacon_host(Some("local")), "authzump.local.modlix.com");
    }

    #[test]
    fn only_the_first_suffix_segment_names_the_environment() {
        assert_eq!(derive_beacon_host(Some(".dev.something")), "dev.authzump.ai");
        assert_eq!(derive_beacon_host(Some(".local.something")), "authzump.local.modlix.com");
        assert_eq!(derive_beacon_host(Some(".")), "authzump.ai");
    }

    // The Java ui `HasssoBounceTest`.
    #[test]
    fn accepts_absolute_http_addresses() {
        let u = absolute_http_uri(Some("https://leadzump.ai/deals?x=1")).unwrap();
        assert_eq!(u.host, "leadzump.ai");
        assert_eq!(u.scheme, "https");
        assert!(absolute_http_uri(Some("http://leadzump.local.modlix.com:8002/")).is_some());
        assert!(absolute_http_uri(Some("HTTPS://leadzump.ai/")).is_some());
    }

    #[test]
    fn refuses_anything_that_is_not_a_place_to_send_a_session() {
        assert!(absolute_http_uri(None).is_none());
        assert!(absolute_http_uri(Some("")).is_none());
        assert!(absolute_http_uri(Some("   ")).is_none());
        assert!(absolute_http_uri(Some("/deals")).is_none());
        assert!(absolute_http_uri(Some("//leadzump.ai/deals")).is_none());
        assert!(absolute_http_uri(Some("javascript:alert(1)")).is_none());
        assert!(absolute_http_uri(Some("data:text/html,x")).is_none());
        assert!(absolute_http_uri(Some("https://exa mple.com/")).is_none());
    }

    #[test]
    fn userinfo_cannot_spoof_the_host_that_gets_checked() {
        let u = absolute_http_uri(Some("https://leadzump.ai@evil.example/steal")).unwrap();
        assert_eq!(u.host, "evil.example");
    }

    #[test]
    fn port_is_carried_through_for_the_resolver_and_absent_when_default() {
        assert_eq!(absolute_http_uri(Some("http://x.local.modlix.com:8002/a")).unwrap().port, 8002);
        assert_eq!(absolute_http_uri(Some("https://leadzump.ai/a")).unwrap().port, -1);
    }

    #[test]
    fn java_uri_edges() {
        assert!(absolute_http_uri(Some("https://my_host/")).is_none(), "registry-based: no host");
        assert!(absolute_http_uri(Some("https://1.2.3.4:80/")).is_some());
        assert_eq!(absolute_http_uri(Some("https://[::1]:8080/")).unwrap().port, 8080);
        assert_eq!(absolute_http_uri(Some("https://[::1]/")).unwrap().port, -1);
        assert!(absolute_http_uri(Some("https://[::1]x/")).is_none());
        assert!(absolute_http_uri(Some("https://[::1")).is_none());
        assert!(absolute_http_uri(Some("https://host:/")).is_some());
        assert!(absolute_http_uri(Some("https://host:8x/")).is_none());
        assert!(absolute_http_uri(Some("https://example.com./a")).is_some());
        assert!(absolute_http_uri(Some("https://-bad.com/")).is_none());
        assert!(absolute_http_uri(Some("https://example.123/")).is_none(), "the top label starts with a letter");
        assert!(absolute_http_uri(Some("https://a%2/")).is_none(), "a broken escape");
        assert!(absolute_http_uri(Some("https://a.com/%41")).is_some());
        assert!(absolute_http_uri(Some("https://a.com/#x#y")).is_none());
        assert!(absolute_http_uri(Some("https://a.com/ü")).is_some(), "Java's other characters");
        assert!(absolute_http_uri(Some("1https://a.com/")).is_none());
        assert!(absolute_http_uri(Some("noscheme")).is_none());
        assert!(absolute_http_uri(Some("ftp://a.com/")).is_none());
        assert!(absolute_http_uri(Some("https:/a.com")).is_none());
        assert!(absolute_http_uri(Some("https://")).is_none());
    }

    // The Java ui `SsoRedirectGuardTest`.
    const OWN_HOST: &str = "sitezump.ai";

    fn guard(r: Option<&str>) -> Option<String> {
        decide_redirect_without_lookup(r, OWN_HOST)
    }

    #[test]
    fn escapes_a_quote_so_it_cannot_close_the_js_string_literal() {
        assert_eq!(js_string(Some("'+alert(1)+'")), "'\\'+alert(1)+\\''");
        assert_eq!(js_string(Some("</script>")), "'\\u003c/script\\u003e'");
        assert_eq!(js_string(None), "''");
        assert_eq!(js_string(Some("a\\b\nc\rd&e\u{2028}\u{2029}")), "'a\\\\b\\nc\\rd\\u0026e\\u2028\\u2029'");
    }

    #[test]
    fn keeps_same_origin_destinations() {
        assert_eq!(guard(Some("/")).as_deref(), Some("/"));
        assert_eq!(guard(Some("/dashboard?tab=1")).as_deref(), Some("/dashboard?tab=1"));
        assert_eq!(guard(Some("https://sitezump.ai/deals")).as_deref(), Some("https://sitezump.ai/deals"));
        assert_eq!(guard(Some("https://sitezump.ai")).as_deref(), Some("https://sitezump.ai"));
        assert_eq!(guard(Some("https://SITEZUMP.AI/x")).as_deref(), Some("https://SITEZUMP.AI/x"));
    }

    #[test]
    fn defers_other_origins_to_the_host_lookup_rather_than_guessing() {
        assert_eq!(guard(Some("https://evil.example/steal")), None);
        assert_eq!(guard(Some("https://sitezump.ai@evil.example/steal")), None);
    }

    #[test]
    fn rejects_anything_that_is_not_an_address_at_all() {
        assert_eq!(guard(Some("//evil.example/steal")).as_deref(), Some("/"));
        assert_eq!(guard(Some("/\\evil.example/steal")).as_deref(), Some("/"));
        assert_eq!(guard(Some("javascript:alert(1)")).as_deref(), Some("/"));
        assert_eq!(guard(Some("")).as_deref(), Some("/"));
        assert_eq!(guard(None).as_deref(), Some("/"));
    }

    #[test]
    fn takes_the_client_facing_host_from_the_first_forwarded_hop_without_its_port() {
        assert_eq!(client_facing_host(Some("sitezump.ai:443, internal-lb"), OWN_HOST), "sitezump.ai");
        assert_eq!(client_facing_host(Some("sitezump.ai"), OWN_HOST), "sitezump.ai");
        assert_eq!(client_facing_host(None, OWN_HOST), OWN_HOST);
    }

    #[test]
    fn md5_ids_drop_leading_zeros_like_big_integer() {
        // Values the Java ui sent on 2026-10-15.
        assert_eq!(md5_unique_id(""), "\"d41d8cd98f00b204e9800998ecf8427e\"");
        assert_eq!(md5_unique_id("Coming soon..."), "\"20c0cfafdfe0b514bedd6af52e0231f\"");
        assert_eq!(escape_html("a&<>\"'"), "a&amp;&lt;&gt;&quot;&#39;");
    }
}
