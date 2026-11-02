//! A URI path's `whitelist` and `blacklist` (per path definition, so per method): the network
//! addresses that may, or may not, call the route. Java stored both and never read them; this is
//! Rust only (DIFFERENCES.md).
//!
//! An entry is an IPv4 or IPv6 address or a CIDR range (`203.0.113.0/24`, `2001:db8::/32`). A list
//! is a JSON array of such strings, or one string; a string may hold several entries separated by
//! commas or spaces. A blank entry is nothing; an entry that does not read (or is not a string) is
//! logged and never matches, and the rest of the list still counts.
//!
//! The caller's address is `X-Real-IP`: every app server block of the load balancer's nginx sets
//! it to `$remote_addr` (overwriting whatever the visitor sent), and `$remote_addr` is the
//! visitor's own address (behind Cloudflare, through the `real_ip` module trusting only
//! Cloudflare's ranges). `X-Forwarded-For` is not that: nginx passes on what the visitor wrote in
//! it and the gateway only appends its own hop. Without `X-Real-IP` (a request that did not come
//! through nginx, as on a local stack), the address the gateway saw: the last `X-Forwarded-For`
//! entry, which the gateway appends; failing that, the connection's peer.

use std::net::IpAddr;

use axum::http::{HeaderMap, StatusCode};
use overridable::{JMap, JValue};
use platform::error::AppError;

/// One entry of a list: an address and how many leading bits must match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    addr: IpAddr,
    prefix: u8,
}

/// An IPv4 address written as IPv6 (`::ffff:10.0.0.1`) is that IPv4 address.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

/// An address as written in a list or a header: plain, or IPv6 in brackets.
fn parse_ip(s: &str) -> Option<IpAddr> {
    let s = s.trim();
    let s = s.strip_prefix('[').and_then(|r| r.strip_suffix(']')).unwrap_or(s);
    s.parse::<IpAddr>().ok().map(canonical)
}

impl Range {
    /// `None` when the entry is not an address or a CIDR range.
    pub fn parse(entry: &str) -> Option<Range> {
        let entry = entry.trim();
        let Some((addr, bits)) = entry.split_once('/') else {
            let addr = parse_ip(entry)?;
            let prefix = if addr.is_ipv4() { 32 } else { 128 };
            return Some(Range { addr, prefix });
        };
        if bits.is_empty() || bits.len() > 3 || !bits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let prefix: u8 = bits.parse().ok()?;
        // A range keeps the family it is written in: `::ffff:10.0.0.0/104` is an IPv6 range.
        let addr = addr.trim().parse::<IpAddr>().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return None;
        }
        Some(Range { addr, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => masked_eq(u32::from(net) as u128, u32::from(ip) as u128, self.prefix, 32),
            (IpAddr::V6(net), IpAddr::V6(ip)) => masked_eq(u128::from(net), u128::from(ip), self.prefix, 128),
            (IpAddr::V6(net), IpAddr::V4(ip)) => masked_eq(u128::from(net), u128::from(ip.to_ipv6_mapped()), self.prefix, 128),
            (IpAddr::V4(_), IpAddr::V6(_)) => false,
        }
    }
}

/// The first `prefix` of `width` bits of `a` and `b` agree.
fn masked_eq(a: u128, b: u128, prefix: u8, width: u32) -> bool {
    if prefix == 0 {
        return true;
    }
    let shift = width - prefix as u32;
    (a >> shift) == (b >> shift)
}

/// A list as stored: its ranges, and whether it named anything at all (an entry that does not
/// read still makes a whitelist non-empty, so a broken whitelist lets nobody in).
#[derive(Debug, Default, PartialEq)]
pub struct List {
    pub ranges: Vec<Range>,
    pub named: bool,
}

impl List {
    /// Reads a stored list; `what` names it in the log (`/api/x GET whitelist`).
    pub fn read(v: Option<&JValue>, what: &str) -> List {
        let mut list = List::default();
        match v {
            None | Some(JValue::Null) => {}
            Some(JValue::Str(s)) => list.add(s, what),
            Some(JValue::Array(items)) => {
                for item in items {
                    match item {
                        JValue::Null => {}
                        JValue::Str(s) => list.add(s, what),
                        other => {
                            list.named = true;
                            tracing::warn!(list = what, entry = %other.java_to_string(), "not an IP address or CIDR range, skipped");
                        }
                    }
                }
            }
            Some(other) => {
                list.named = true;
                tracing::warn!(list = what, value = %other.java_to_string(), "not a list of IP addresses, nobody matches it");
            }
        }
        list
    }

    /// The entries of one string, separated by commas or spaces.
    fn add(&mut self, s: &str, what: &str) {
        for entry in s.split(|c: char| c == ',' || c.is_whitespace()).filter(|e| !e.is_empty()) {
            self.named = true;
            match Range::parse(entry) {
                Some(r) => self.ranges.push(r),
                None => tracing::warn!(list = what, entry, "not an IP address or CIDR range, skipped"),
            }
        }
    }

    fn matches(&self, ip: Option<IpAddr>) -> bool {
        ip.is_some_and(|ip| self.ranges.iter().any(|r| r.contains(ip)))
    }
}

/// The caller's address (see the module notes); `None` when no source gives one that reads.
pub fn caller_ip(h: &HeaderMap, peer: Option<IpAddr>) -> Option<IpAddr> {
    if let Some(real) = h.get("x-real-ip") {
        return real.to_str().ok().and_then(parse_ip);
    }
    let last_forwarded = h
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .last();
    match last_forwarded {
        Some(v) => parse_ip(v),
        None => peer.map(canonical),
    }
}

/// Why a caller is refused.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    Blocked,
    NotAllowed,
}

/// The rule: a blacklist match refuses; a whitelist that names anything requires a match.
pub fn decide(whitelist: &List, blacklist: &List, ip: Option<IpAddr>) -> Result<(), Refusal> {
    if blacklist.matches(ip) {
        return Err(Refusal::Blocked);
    }
    if whitelist.named && !whitelist.matches(ip) {
        return Err(Refusal::NotAllowed);
    }
    Ok(())
}

/// The path definition's lists against the caller: `Ok` to run the route, else the 403.
pub fn check(def: &JMap, route: &str, method: &str, ip: Option<IpAddr>) -> Result<(), AppError> {
    let white = List::read(def.get("whitelist"), &format!("{route} {method} whitelist"));
    let black = List::read(def.get("blacklist"), &format!("{route} {method} blacklist"));
    let shown = ip.map(|i| i.to_string()).unwrap_or_default();
    let (code, java_text) = match decide(&white, &black, ip) {
        Ok(()) => return Ok(()),
        Err(Refusal::Blocked) => ("UI.URI_PATH_ADDRESS_BLOCKED", format!("Address {shown} is on the blacklist of {route} {method}")),
        Err(Refusal::NotAllowed) => {
            ("UI.URI_PATH_ADDRESS_NOT_ALLOWED", format!("Address {shown} is not on the whitelist of {route} {method}"))
        }
    };
    let mut c = crate::catalogue::literal(code, StatusCode::FORBIDDEN, java_text);
    if !shown.is_empty() {
        c = c.param("address", shown);
    }
    Err(c.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn ip(s: &str) -> IpAddr {
        parse_ip(s).unwrap_or_else(|| panic!("{s} should read"))
    }

    fn r(s: &str) -> Range {
        Range::parse(s).unwrap_or_else(|| panic!("{s} should read"))
    }

    fn list(v: serde_json::Value) -> List {
        let j = overridable::json::parse(v.to_string().as_bytes()).unwrap();
        List::read(Some(&j), "test")
    }

    #[test]
    fn single_addresses() {
        assert!(r("10.1.2.3").contains(ip("10.1.2.3")));
        assert!(!r("10.1.2.3").contains(ip("10.1.2.4")));
        assert!(r(" 2001:db8::1 ").contains(ip("2001:db8:0:0:0:0:0:1")), "Java's long form is the same address");
        assert!(r("[2001:db8::1]").contains(ip("2001:db8::1")));
        assert!(!r("2001:db8::1").contains(ip("2001:db8::2")));
        // An IPv4 address written as IPv6 is the IPv4 address, both ways.
        assert!(r("::ffff:10.0.0.1").contains(ip("10.0.0.1")));
        assert!(r("10.0.0.1").contains(ip("::ffff:10.0.0.1")));
        assert!(!r("10.0.0.1").contains(ip("2001:db8::1")));
    }

    #[test]
    fn cidr_edges() {
        let net = r("192.168.10.0/24");
        assert!(net.contains(ip("192.168.10.0")) && net.contains(ip("192.168.10.255")));
        assert!(!net.contains(ip("192.168.11.0")) && !net.contains(ip("192.168.9.255")));
        assert!(r("0.0.0.0/0").contains(ip("8.8.8.8")));
        assert!(!r("0.0.0.0/0").contains(ip("2001:db8::1")), "an IPv4 range never holds an IPv6 address");
        assert!(r("10.0.0.7/32").contains(ip("10.0.0.7")) && !r("10.0.0.7/32").contains(ip("10.0.0.6")));
        assert!(r("10.0.0.5/8").contains(ip("10.200.0.1")), "host bits in the network are ignored");
        assert!(r("172.16.0.0/12").contains(ip("172.31.255.255")) && !r("172.16.0.0/12").contains(ip("172.32.0.0")));
        let v6 = r("2001:db8::/32");
        assert!(v6.contains(ip("2001:db8:ffff::1")) && !v6.contains(ip("2001:db9::1")));
        assert!(r("::/0").contains(ip("2001:db8::1")) && r("::/0").contains(ip("10.0.0.1")));
        assert!(r("::1/128").contains(ip("0:0:0:0:0:0:0:1")) && !r("::1/128").contains(ip("::2")));
        assert!(r("::ffff:10.0.0.0/104").contains(ip("10.9.9.9")), "an IPv4 range written as IPv6");
        assert!(!r("::ffff:10.0.0.0/104").contains(ip("11.0.0.1")));
    }

    #[test]
    fn entries_that_do_not_read() {
        for bad in ["", "10.0.0", "10.0.0.256", "10.0.0.0/33", "2001:db8::/129", "10.0.0.0/", "10.0.0.0/+8", "10.0.0.0/1234", "host.example", "/8", "10.0.0.0/8/9"] {
            assert_eq!(Range::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn lists() {
        assert_eq!(List::read(None, "t"), List::default());
        assert_eq!(list(serde_json::json!(null)), List::default());
        assert_eq!(list(serde_json::json!([])), List::default());
        assert_eq!(list(serde_json::json!(["", "  ", null])), List::default(), "blank entries are nothing");
        let l = list(serde_json::json!("10.0.0.1, 10.0.1.0/24 2001:db8::1"));
        assert_eq!((l.ranges.len(), l.named), (3, true));
        let l = list(serde_json::json!(["10.0.0.1", "nonsense", 5, "10.0.2.0/24"]));
        assert_eq!((l.ranges.len(), l.named), (2, true), "bad entries are skipped, the rest count");
        let l = list(serde_json::json!(["nonsense"]));
        assert_eq!((l.ranges.len(), l.named), (0, true));
        let l = list(serde_json::json!({"a": "10.0.0.1"}));
        assert_eq!((l.ranges.len(), l.named), (0, true), "not a list: names something, matches nothing");
    }

    #[test]
    fn rules() {
        let none = List::default();
        let office = list(serde_json::json!(["203.0.113.0/24", "2001:db8::/32"]));
        let bad = list(serde_json::json!(["203.0.113.66"]));
        let a = Some(ip("203.0.113.5"));
        assert_eq!(decide(&none, &none, a), Ok(()));
        assert_eq!(decide(&none, &none, None), Ok(()));
        assert_eq!(decide(&office, &none, a), Ok(()));
        assert_eq!(decide(&office, &none, Some(ip("2001:db8::9"))), Ok(()));
        assert_eq!(decide(&office, &none, Some(ip("198.51.100.1"))), Err(Refusal::NotAllowed));
        assert_eq!(decide(&office, &none, None), Err(Refusal::NotAllowed), "an unknown caller is not on a whitelist");
        assert_eq!(decide(&none, &bad, None), Ok(()), "nor on a blacklist");
        assert_eq!(decide(&office, &bad, Some(ip("203.0.113.66"))), Err(Refusal::Blocked), "the blacklist wins");
        assert_eq!(decide(&none, &bad, Some(ip("203.0.113.67"))), Ok(()));
        let broken = list(serde_json::json!(["nonsense"]));
        assert_eq!(decide(&broken, &none, a), Err(Refusal::NotAllowed), "a whitelist that reads as nothing lets nobody in");
        assert_eq!(decide(&none, &broken, a), Ok(()));
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(), HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn the_callers_address() {
        let peer = Some(ip("127.0.0.1"));
        // nginx's X-Real-IP wins over a forwarded chain the visitor can write into.
        assert_eq!(caller_ip(&headers(&[("x-real-ip", "203.0.113.9"), ("x-forwarded-for", "1.1.1.1, 10.0.0.2")]), peer), Some(ip("203.0.113.9")));
        assert_eq!(caller_ip(&headers(&[("x-real-ip", "2001:db8::5")]), peer), Some(ip("2001:db8::5")));
        assert_eq!(caller_ip(&headers(&[("x-real-ip", "garbage"), ("x-forwarded-for", "10.0.0.2")]), peer), None, "a broken X-Real-IP is not replaced");
        // Without nginx: the gateway's hop, the last forwarded entry.
        assert_eq!(caller_ip(&headers(&[("x-forwarded-for", "6.6.6.6, 10.0.0.2")]), peer), Some(ip("10.0.0.2")));
        assert_eq!(caller_ip(&headers(&[("x-forwarded-for", "6.6.6.6"), ("x-forwarded-for", "0:0:0:0:0:0:0:1")]), peer), Some(ip("::1")));
        assert_eq!(caller_ip(&headers(&[("x-forwarded-for", " , ")]), peer), Some(ip("127.0.0.1")));
        assert_eq!(caller_ip(&HeaderMap::new(), Some(ip("::ffff:10.1.1.1"))), Some(ip("10.1.1.1")));
        assert_eq!(caller_ip(&HeaderMap::new(), None), None);
    }

    #[test]
    fn refusals_are_coded() {
        let def = |w: serde_json::Value, b: serde_json::Value| match overridable::json::parse(serde_json::json!({"whitelist": w, "blacklist": b}).to_string().as_bytes()).unwrap() {
            JValue::Object(m) => m,
            _ => unreachable!(),
        };
        assert!(check(&def(serde_json::json!(null), serde_json::json!(null)), "/api/x", "GET", None).is_ok());
        let code = |e: AppError| match e {
            AppError::Coded(c) => (c.code.to_string(), c.status, c.params.clone()),
            other => panic!("{other:?}"),
        };
        let blocked = check(&def(serde_json::json!(null), serde_json::json!(["10.0.0.0/8"])), "/api/x", "POST", Some(ip("10.2.3.4"))).unwrap_err();
        let (c, s, p) = code(blocked);
        assert_eq!((c.as_str(), s), ("UI.URI_PATH_ADDRESS_BLOCKED", Some(StatusCode::FORBIDDEN)));
        assert_eq!(p, vec![("address".to_string(), "10.2.3.4".to_string())]);
        let (c, _, p) = code(check(&def(serde_json::json!("10.0.0.1"), serde_json::json!(null)), "/api/x", "GET", None).unwrap_err());
        assert_eq!((c.as_str(), p.is_empty()), ("UI.URI_PATH_ADDRESS_NOT_ALLOWED", true));
    }
}
