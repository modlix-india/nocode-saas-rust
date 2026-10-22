//! `OutboundUrlUtil`: the one gate for every URL a connection hands the platform to call.
//!
//! Ported rule for rule. [`validate_connection_details`] runs at save time over a whole
//! `connectionDetails` map and refuses the obvious cases without resolving names;
//! [`validate_resolved`] is the call-time boundary and resolves the host, which catches DNS
//! rebinding and URLs that only exist at call time (a connection without `baseUrl` takes the
//! URL verbatim from the KIRun step). Both use Java's own reading of the URL (`java.net.URI`
//! and `InetAddress` literal parsing, in [`crate::java`]), because the refusal depends on
//! exactly which host the parser finds.
//!
//! What Rust adds on top is in [`guard_target`] (see DIFFERENCES.md): the host the HTTP client
//! will really connect to (the `url` crate's reading of the URL) is checked too, and resolved
//! IPv4-mapped IPv6 answers are judged as the IPv4 address they carry.

use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;

use http::StatusCode;
use serde_json::{Map, Value};

use crate::error::{ConnError, ConnResult};
use crate::java::inet::{classify, JavaInet, Literal};
use crate::java::{self, uri};

const ALLOWED_SCHEMES: [&str; 2] = ["http", "https"];
const DATABASE_SCHEMES: [&str; 2] = ["mongodb", "mongodb+srv"];
const BLOCKED_NAMES: [&str; 7] =
    ["localhost", "ip6-localhost", "ip6-loopback", "metadata.google.internal", "metadata.goog", "instance-data", "metadata"];
const BLOCKED_SUFFIXES: [&str; 5] = [".localhost", ".local", ".internal", ".home.arpa", ".oraclevcn.com"];
const DANGEROUS_SCHEMES: [&str; 12] =
    ["file", "ftp", "ftps", "sftp", "tftp", "gopher", "jar", "netdoc", "dict", "ldap", "ldaps", "classpath"];

fn is_scheme_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '+' || c == '.' || c == '-'
}

/// `^[a-zA-Z][a-zA-Z0-9+.\-]*://.*` (DOTALL).
fn with_authority(s: &str) -> bool {
    let mut chars = s.char_indices();
    match chars.next() {
        Some((_, c)) if c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    let end = s.char_indices().skip(1).find(|(_, c)| !is_scheme_char(*c)).map(|(i, _)| i).unwrap_or(s.len());
    s[end..].starts_with("://")
}

/// `^([a-zA-Z][a-zA-Z0-9+.\-]+):(?!//).*` (DOTALL): the scheme of a URL with no authority.
fn scheme_only(s: &str) -> Option<&str> {
    let colon = s.find(':')?;
    let scheme = &s[..colon];
    let mut cs = scheme.chars();
    let first = cs.next()?;
    if !first.is_ascii_alphabetic() || scheme.len() < 2 || !cs.all(is_scheme_char) {
        return None;
    }
    if s[colon + 1..].starts_with("//") {
        return None;
    }
    Some(scheme)
}

fn is_java_line_terminator(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{0085}' | '\u{2028}' | '\u{2029}')
}

/// `^(\[.*\]|[0-9.]+|0[xX][0-9a-fA-F.]+|[0-9a-fA-F:.]*:[0-9a-fA-F:.]*)$`: an address literal,
/// which `InetAddress.getByName` parses without touching DNS.
pub fn numeric_host(h: &str) -> bool {
    if h.len() >= 2 && h.starts_with('[') && h.ends_with(']') && !h[1..h.len() - 1].chars().any(is_java_line_terminator) {
        return true;
    }
    if !h.is_empty() && h.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return true;
    }
    if h.len() > 2
        && h.starts_with('0')
        && (h.as_bytes()[1] == b'x' || h.as_bytes()[1] == b'X')
        && h[2..].chars().all(|c| c.is_ascii_hexdigit() || c == '.')
    {
        return true;
    }
    h.contains(':') && h.chars().all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
}

fn is_host_key(key: &str) -> bool {
    let k = key.to_lowercase();
    let last = match k.rfind('.') {
        Some(dot) => &k[dot + 1..],
        None => &k[..],
    };
    last == "host" || last == "hostname"
}

/// Validates every URL and every host-bearing key in a `connectionDetails` map, at any depth.
pub async fn validate_connection_details(details: Option<&Map<String, Value>>) -> ConnResult<()> {
    let Some(details) = details else { return Ok(()) };
    if details.is_empty() {
        return Ok(());
    }
    let mut stack: Vec<(String, &Value)> = Vec::new();
    for (k, v) in details.iter().rev() {
        stack.push((k.clone(), v));
    }
    // Depth first, in map order, as the Java walk visits them: the first refusal wins.
    while let Some((path, value)) = stack.pop() {
        match value {
            Value::Object(m) => {
                for (k, v) in m.iter().rev() {
                    let p = if path.is_empty() { k.clone() } else { format!("{path}.{k}") };
                    stack.push((p, v));
                }
            }
            Value::Array(a) => {
                for (i, v) in a.iter().enumerate().rev() {
                    stack.push((format!("{path}[{i}]"), v));
                }
            }
            Value::String(s) => validate_value(&path, s).await?,
            _ => {}
        }
    }
    Ok(())
}

/// True when the details would be refused, for callers that filter rather than fail.
pub async fn is_usable(details: Option<&Map<String, Value>>) -> bool {
    validate_connection_details(details).await.is_ok()
}

async fn validate_value(key: &str, value: &str) -> ConnResult<()> {
    if java::is_blank(value) {
        return Ok(());
    }
    let trimmed = java::trim(value);
    if with_authority(trimmed) {
        return validate_url(Some(key), trimmed).await;
    }
    if let Some(scheme) = scheme_only(trimmed) {
        let lower = scheme.to_lowercase();
        if DANGEROUS_SCHEMES.contains(&lower.as_str()) {
            return Err(refuse(
                Some(key),
                trimmed,
                &format!("the '{lower}' scheme is not a web address the platform will fetch"),
            ));
        }
    }
    if is_host_key(key) {
        check_host(Some(key), trimmed, trimmed).await?;
    }
    Ok(())
}

/// Validates one absolute URL with the save-time rules.
pub async fn validate_url(key: Option<&str>, url: &str) -> ConnResult<()> {
    let parsed = match uri::parse(java::trim(url)) {
        Ok(u) => u,
        Err(_) => return Err(refuse(key, url, "it is not a valid web address")),
    };
    let scheme = parsed.scheme.as_deref().unwrap_or("").to_lowercase();

    if DATABASE_SCHEMES.contains(&scheme.as_str()) {
        return check_database_authority(key, url).await;
    }

    if !ALLOWED_SCHEMES.contains(&scheme.as_str()) {
        let tail = if scheme.is_empty() { String::new() } else { format!(", not '{scheme}'") };
        return Err(refuse(key, url, &format!("only http and https addresses can be called{tail}")));
    }

    let host = match parsed.host {
        Some(h) if !java::is_blank(&h) => h,
        _ => return Err(refuse(key, url, "the address has no readable host name")),
    };
    check_host(key, url, &host).await
}

/// The call-time check, exactly as Java: the save-time rules (re-worded for a call), then what
/// the host resolves to right now. Every answer has to be public.
pub async fn validate_resolved(url: &str) -> ConnResult<()> {
    if let Err(e) = validate_url(None, url).await {
        return Err(refuse_call(url, &strip(e.message())));
    }

    let host = match uri::parse(java::trim(url)) {
        Ok(u) => normalize_host(u.host.as_deref()),
        Err(_) => return Err(refuse_call(url, "it is not a valid web address")),
    };

    if numeric_host(&host) {
        return Ok(());
    }

    let addresses = match get_all_by_name(&host).await {
        Ok(a) => a,
        Err(()) => return Err(refuse_call(url, &format!("'{host}' does not resolve to any address"))),
    };
    for address in addresses {
        if is_private_address(&address) {
            return Err(refuse_call(
                url,
                &format!("'{host}' resolves to {}, which is a private or internal address", address.host_address()),
            ));
        }
    }
    Ok(())
}

/// [`validate_resolved`], then the same rules over the host the HTTP client will connect to.
///
/// Java's guard and Java's HTTP client both read the URL with `java.net.URI`, so they cannot
/// disagree about the host. Here the HTTP client reads it with the `url` crate, which accepts
/// and rewrites things `java.net.URI` does not; checking its host as well closes any gap
/// between the two readings.
pub async fn guard_target(url: &str) -> ConnResult<()> {
    validate_resolved(url).await?;
    let Ok(parsed) = reqwest::Url::parse(java::trim(url)) else {
        // The client cannot call it either; the call fails on its own.
        return Ok(());
    };
    match parsed.host() {
        Some(url_host) => {
            let name = match url_host {
                url::Host::Domain(d) => d.to_string(),
                url::Host::Ipv4(a) => a.to_string(),
                url::Host::Ipv6(a) => a.to_string(),
            };
            check_client_host(url, &name, url_host_ip(&url_host)).await
        }
        None => Err(refuse_call(url, "the address has no readable host name")),
    }
}

fn url_host_ip(h: &url::Host<&str>) -> Option<IpAddr> {
    match h {
        url::Host::Ipv4(a) => Some(IpAddr::V4(*a)),
        url::Host::Ipv6(a) => Some(IpAddr::V6(*a)),
        url::Host::Domain(_) => None,
    }
}

async fn check_client_host(url: &str, name: &str, ip: Option<IpAddr>) -> ConnResult<()> {
    if let Some(ip) = ip {
        let a = canonical(JavaInet::from_ip(ip));
        if is_private_address(&a) {
            return Err(refuse_call(url, &format!("'{name}' is a private or internal address")));
        }
        return Ok(());
    }
    let host = normalize_host(Some(name));
    if BLOCKED_NAMES.contains(&host.as_str()) {
        return Err(refuse_call(url, &format!("'{host}' is this server, not an outside address")));
    }
    if BLOCKED_SUFFIXES.iter().any(|s| host.ends_with(s)) {
        return Err(refuse_call(url, &format!("'{host}' is an internal address")));
    }
    let addresses = resolve(&host).await.map_err(|_| refuse_call(url, &format!("'{host}' does not resolve to any address")))?;
    for a in addresses {
        let a = canonical(a);
        if is_private_address(&a) {
            return Err(refuse_call(
                url,
                &format!("'{host}' resolves to {}, which is a private or internal address", a.host_address()),
            ));
        }
    }
    Ok(())
}

/// The same rules for a server no URL names (an SMTP host): the blocked names and suffixes,
/// then every address the host resolves to (`target` only names it in the refusal). The
/// addresses are returned so the connection goes to exactly the ones judged, with no second
/// lookup to rebind.
pub async fn guard_host(target: &str, host: &str) -> ConnResult<Vec<IpAddr>> {
    let name = normalize_host(Some(host));
    if name.is_empty() {
        return Err(refuse_call(target, "the address has no readable host name"));
    }
    if let Ok(ip) = name.parse::<IpAddr>() {
        if is_private_address(&canonical(JavaInet::from_ip(ip))) {
            return Err(refuse_call(target, &format!("'{name}' is a private or internal address")));
        }
        return Ok(vec![ip]);
    }
    if BLOCKED_NAMES.contains(&name.as_str()) {
        return Err(refuse_call(target, &format!("'{name}' is this server, not an outside address")));
    }
    if BLOCKED_SUFFIXES.iter().any(|s| name.ends_with(s)) {
        return Err(refuse_call(target, &format!("'{name}' is an internal address")));
    }
    let addresses = resolve(&name).await.map_err(|_| refuse_call(target, &format!("'{name}' does not resolve to any address")))?;
    for a in &addresses {
        let a = canonical(*a);
        if is_private_address(&a) {
            return Err(refuse_call(
                target,
                &format!("'{name}' resolves to {}, which is a private or internal address", a.host_address()),
            ));
        }
    }
    Ok(addresses.iter().map(JavaInet::ip).collect())
}

/// An IPv4-mapped IPv6 address judged as the IPv4 address it carries.
pub fn canonical(a: JavaInet) -> JavaInet {
    match a {
        JavaInet::V6(b) if b[..10].iter().all(|x| *x == 0) && b[10] == 0xff && b[11] == 0xff => {
            JavaInet::V4([b[12], b[13], b[14], b[15]])
        }
        other => other,
    }
}

fn normalize_host(raw: Option<&str>) -> String {
    let Some(raw) = raw else { return String::new() };
    let mut host = java::trim(raw).to_lowercase();
    if host.starts_with('[') && host.ends_with(']') && host.len() >= 2 {
        host = host[1..host.len() - 1].to_string();
    }
    while host.ends_with('.') {
        host.pop();
    }
    host
}

async fn check_database_authority(key: Option<&str>, url: &str) -> ConnResult<()> {
    let trimmed = java::trim(url);
    // `rest.indexOf("://") + 3`: a missing "://" starts at index 2, as Java does.
    let start = match trimmed.find("://") {
        Some(i) => i + 3,
        None => 2,
    };
    let rest = trimmed.get(start..).unwrap_or("");
    let end = ['/', '?', '#'].iter().filter_map(|c| rest.find(*c)).min().unwrap_or(rest.len());
    let mut authority = &rest[..end];
    if let Some(at) = authority.rfind('@') {
        authority = &authority[at + 1..];
    }
    if java::is_blank(authority) {
        return Err(refuse(key, url, "the address has no readable host name"));
    }
    for member in java_split_comma(authority) {
        let mut host = java::trim(member);
        if host.is_empty() {
            return Err(refuse(key, url, "the address has no readable host name"));
        }
        if host.starts_with('[') {
            match host.find(']') {
                Some(close) => host = &host[..close + 1],
                None => return Err(refuse(key, url, "the address has no readable host name")),
            }
        } else if let Some(colon) = host.find(':') {
            host = &host[..colon];
        }
        if java::is_blank(host) {
            return Err(refuse(key, url, "the address has no readable host name"));
        }
        check_host(key, url, host).await?;
    }
    Ok(())
}

/// `String.split(",")`: trailing empty strings are dropped.
fn java_split_comma(s: &str) -> Vec<&str> {
    let mut parts: Vec<&str> = s.split(',').collect();
    while parts.last().is_some_and(|p| p.is_empty()) {
        parts.pop();
    }
    parts
}

async fn check_host(key: Option<&str>, original: &str, raw_host: &str) -> ConnResult<()> {
    let host = normalize_host(Some(raw_host));
    if host.is_empty() {
        return Err(refuse(key, original, "the address has no readable host name"));
    }
    if BLOCKED_NAMES.contains(&host.as_str()) {
        return Err(refuse(key, original, &format!("'{host}' is this server, not an outside address")));
    }
    if BLOCKED_SUFFIXES.iter().any(|s| host.ends_with(s)) {
        return Err(refuse(key, original, &format!("'{host}' is an internal address")));
    }
    if !numeric_host(&host) {
        return Ok(());
    }
    let address = match get_by_name(&host).await {
        Ok(a) => a,
        Err(()) => return Err(refuse(key, original, &format!("'{host}' is not a usable address"))),
    };
    if is_private_address(&address) {
        return Err(refuse(key, original, &format!("'{host}' is a private or internal address")));
    }
    Ok(())
}

/// Every range that is not a public internet destination, as `OutboundUrlUtil.isPrivateAddress`.
pub fn is_private_address(a: &JavaInet) -> bool {
    if a.is_loopback() || a.is_any_local() || a.is_link_local() || a.is_site_local() || a.is_multicast() {
        return true;
    }
    match a {
        JavaInet::V4(b) => {
            let (first, second) = (b[0], b[1]);
            if first == 0 {
                return true;
            }
            if first == 100 && (64..=127).contains(&second) {
                return true;
            }
            if first == 192 && second == 0 && b[2] == 0 {
                return true;
            }
            first == 198 && (second == 18 || second == 19)
        }
        JavaInet::V6(b) => (b[0] & 0xFE) == 0xFC,
    }
}

/// `InetAddress.getByName`: the first of [`get_all_by_name`].
async fn get_by_name(host: &str) -> Result<JavaInet, ()> {
    get_all_by_name(host).await?.into_iter().next().ok_or(())
}

/// `InetAddress.getAllByName`: a literal is parsed, anything else goes to the system resolver
/// (IPv4 answers first, as Java orders them by default).
pub async fn get_all_by_name(host: &str) -> Result<Vec<JavaInet>, ()> {
    match classify(host) {
        Literal::Address(a) => Ok(vec![a]),
        Literal::Unknown(_) => Err(()),
        Literal::Resolve(name) => resolve(&name).await,
    }
}

/// A stand-in for the system resolver: a host's answers, or `None` when it does not resolve.
pub type Resolver = Arc<dyn Fn(&str) -> Option<Vec<IpAddr>> + Send + Sync>;

tokio::task_local! {
    static RESOLVER: Resolver;
}

/// Runs `fut` with names resolved by `resolver` instead of the system (for tests: a DNS answer
/// can then be chosen, rebinding included, without a network).
pub async fn with_resolver<F: Future>(resolver: Resolver, fut: F) -> F::Output {
    RESOLVER.scope(resolver, fut).await
}

/// Every address a name resolves to: the [`with_resolver`] override, or the system resolver.
pub async fn lookup(name: &str) -> Result<Vec<IpAddr>, ()> {
    if let Ok(answer) = RESOLVER.try_with(|r| r(name)) {
        return answer.filter(|a| !a.is_empty()).ok_or(());
    }
    let answers = tokio::net::lookup_host((name, 0)).await.map_err(|_| ())?;
    Ok(answers.map(|a| a.ip()).collect())
}

async fn resolve(name: &str) -> Result<Vec<JavaInet>, ()> {
    let answers = lookup(name).await?;
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for a in answers {
        let inet = JavaInet::from_ip(a);
        if !v4.contains(&inet) && !v6.contains(&inet) {
            match inet {
                JavaInet::V4(_) => v4.push(inet),
                JavaInet::V6(_) => v6.push(inet),
            }
        }
    }
    v4.extend(v6);
    if v4.is_empty() {
        return Err(());
    }
    Ok(v4)
}

/// The reason out of a save-time refusal, without its saving-specific framing.
fn strip(message: &str) -> String {
    let why = match message.find("\": ") {
        Some(i) => &message[i + 3..],
        None => message,
    };
    match why.find(". A connection may only") {
        Some(stop) => why[..stop].to_string(),
        None => why.to_string(),
    }
}

fn refuse_call(url: &str, why: &str) -> ConnError {
    ConnError::coded(
        StatusCode::BAD_REQUEST,
        "CORE.PRIVATE_TARGET_REFUSED",
        format!("Refusing to call \"{url}\": {why}. Only addresses reachable from the public internet can be called."),
    )
    .param("url", url)
    .param("reason", why)
}

fn refuse(key: Option<&str>, value: &str, why: &str) -> ConnError {
    let where_ = match key {
        Some(k) if !java::is_blank(k) => format!("'{k}'"),
        _ => "A connection address".to_string(),
    };
    let refused = ConnError::coded(
        StatusCode::BAD_REQUEST,
        "CORE.CONNECTION_TARGET_REFUSED",
        format!(
            "{where_} cannot be saved as \"{value}\": {why}. A connection may only point at an address reachable from the public internet."
        ),
    )
    .param("value", value)
    .param("reason", why);
    match key {
        Some(k) if !java::is_blank(k) => refused.param("field", k),
        _ => refused,
    }
}
