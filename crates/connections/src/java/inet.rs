//! `InetAddress.getAllByName` as JDK 21 runs it on a host string: the literal forms it parses
//! itself (`sun.net.util.IPAddressUtil`), the ambiguous IPv4 spellings it refuses
//! (`jdk.net.allowAmbiguousIPAddressLiterals` is false by default), and the system resolver for
//! everything else. Plus the `Inet4Address` / `Inet6Address` classification methods the guard
//! asks.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// An address as Java holds it: an IPv4-mapped IPv6 literal is an `Inet4Address`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JavaInet {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl JavaInet {
    pub fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => JavaInet::V4(v4.octets()),
            IpAddr::V6(v6) => JavaInet::V6(v6.octets()),
        }
    }

    pub fn ip(&self) -> IpAddr {
        match self {
            JavaInet::V4(b) => IpAddr::V4(Ipv4Addr::from(*b)),
            JavaInet::V6(b) => IpAddr::V6(Ipv6Addr::from(*b)),
        }
    }

    pub fn is_loopback(&self) -> bool {
        match self {
            JavaInet::V4(b) => b[0] == 127,
            JavaInet::V6(b) => b[..15].iter().all(|x| *x == 0) && b[15] == 1,
        }
    }

    pub fn is_any_local(&self) -> bool {
        match self {
            JavaInet::V4(b) => b.iter().all(|x| *x == 0),
            JavaInet::V6(b) => b.iter().all(|x| *x == 0),
        }
    }

    pub fn is_link_local(&self) -> bool {
        match self {
            JavaInet::V4(b) => b[0] == 169 && b[1] == 254,
            JavaInet::V6(b) => b[0] == 0xfe && (b[1] & 0xc0) == 0x80,
        }
    }

    pub fn is_site_local(&self) -> bool {
        match self {
            JavaInet::V4(b) => b[0] == 10 || (b[0] == 172 && (b[1] & 0xF0) == 16) || (b[0] == 192 && b[1] == 168),
            JavaInet::V6(b) => b[0] == 0xfe && (b[1] & 0xc0) == 0xc0,
        }
    }

    pub fn is_multicast(&self) -> bool {
        match self {
            JavaInet::V4(b) => (b[0] & 0xf0) == 0xe0,
            JavaInet::V6(b) => b[0] == 0xff,
        }
    }

    /// `getHostAddress()`: dotted quad, or eight lower-case hex groups without compression.
    pub fn host_address(&self) -> String {
        match self {
            JavaInet::V4(b) => format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]),
            JavaInet::V6(b) => (0..8)
                .map(|i| format!("{:x}", u16::from_be_bytes([b[2 * i], b[2 * i + 1]])))
                .collect::<Vec<_>>()
                .join(":"),
        }
    }
}

/// What `getAllByName` does with a host before any lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Literal {
    /// Parsed as an address literal.
    Address(JavaInet),
    /// Not a literal: the system resolver decides.
    Resolve(String),
    /// `UnknownHostException` without a lookup.
    Unknown(String),
}

/// The literal half of `InetAddress.getAllByName(host)`.
pub fn classify(host: &str) -> Literal {
    let units: Vec<u16> = host.encode_utf16().collect();
    if units.is_empty() {
        // Java answers the loopback address for an empty host.
        return Literal::Address(JavaInet::V4([127, 0, 0, 1]));
    }
    if units.contains(&0) {
        return Literal::Unknown("NUL character not allowed in hostname".into());
    }

    let mut h: Vec<u16> = units;
    let mut ipv6_expected = false;
    if h[0] == b'[' as u16 {
        if h.len() > 2 && h[h.len() - 1] == b']' as u16 {
            h = h[1..h.len() - 1].to_vec();
            ipv6_expected = true;
        } else {
            return Literal::Unknown(format!("{}: invalid IPv6 address literal", String::from_utf16_lossy(&h)));
        }
    }
    let hs = String::from_utf16_lossy(&h);

    if hex_digit(h[0]).is_some() || h[0] == b':' as u16 {
        let mut addr: Option<Vec<u8>> = None;
        let mut has_zone = false;
        let mut ifname: Option<String> = None;
        if !ipv6_expected {
            match validate_numeric_format_v4(&h) {
                Err(()) => return Literal::Unknown(hs),
                Ok(a) => addr = a.map(|a| a.to_vec()),
            }
        }
        if addr.is_none() {
            if let Some(pos) = h.iter().position(|c| *c == b'%' as u16) {
                if check_numeric_zone(&h).is_some() {
                    has_zone = true;
                } else {
                    has_zone = true;
                    ifname = Some(String::from_utf16_lossy(&h[pos + 1..]));
                }
            }
            addr = text_to_numeric_format_v6(&h);
            if addr.is_none() && (h.contains(&(b':' as u16)) || ipv6_expected) {
                let shown = if ipv6_expected { format!("[{hs}]") } else { hs.clone() };
                return Literal::Unknown(format!("{shown}: invalid IPv6 address literal"));
            }
        }
        if let Some(a) = addr {
            if a.len() == 4 {
                if has_zone {
                    return Literal::Unknown(format!("{hs}: invalid IPv4-mapped address"));
                }
                return Literal::Address(JavaInet::V4([a[0], a[1], a[2], a[3]]));
            }
            let mut b = [0u8; 16];
            b.copy_from_slice(&a);
            let inet = JavaInet::V6(b);
            if let Some(name) = ifname {
                // Java binds the address to the named interface. The guard does not look up
                // this machine's interfaces: an interface-scoped literal is answered as Java
                // answers a scope naming no interface here (see DIFFERENCES.md).
                let _ = inet;
                return Literal::Unknown(format!("no such interface {name}"));
            }
            return Literal::Address(inet);
        }
    } else if ipv6_expected {
        return Literal::Unknown(format!("[{hs}]: invalid IPv6 address literal"));
    }
    Literal::Resolve(hs)
}

/// `IPAddressUtil.digit(c, 16)` with ambiguous literals disallowed: ASCII hex only.
fn hex_digit(c: u16) -> Option<u32> {
    parse_ascii_digit(c, 16)
}

fn parse_ascii_digit(c: u16, radix: u32) -> Option<u32> {
    if radix == 16 {
        return parse_ascii_hex_digit(c);
    }
    let v = (c as i32) - ('0' as i32);
    if v < 0 || v >= radix as i32 {
        None
    } else {
        Some(v as u32)
    }
}

fn parse_ascii_hex_digit(c: u16) -> Option<u32> {
    let lower = match char::from_u32(c as u32) {
        Some(ch) => {
            let mut l = ch.to_lowercase();
            match (l.next(), l.next()) {
                (Some(x), None) => x as u32,
                _ => c as u32,
            }
        }
        None => c as u32,
    };
    if (b'a' as u32..=b'f' as u32).contains(&lower) {
        return Some(lower - b'a' as u32 + 10);
    }
    if lower > u16::MAX as u32 {
        return None;
    }
    parse_ascii_digit(lower as u16, 10)
}

/// `textToNumericFormatV4`: `a.b.c.d`, `a.b.c`, `a.b` and `a`, decimal only.
pub fn text_to_numeric_format_v4(src: &[u16]) -> Option<[u8; 4]> {
    let mut res = [0u8; 4];
    let mut tmp: i64 = 0;
    let mut curr = 0usize;
    let mut new_octet = true;
    let len = src.len();
    if len == 0 || len > 15 {
        return None;
    }
    for &c in src {
        if c == b'.' as u16 {
            if new_octet || !(0..=0xff).contains(&tmp) || curr == 3 {
                return None;
            }
            res[curr] = (tmp & 0xff) as u8;
            curr += 1;
            tmp = 0;
            new_octet = true;
        } else {
            let d = parse_ascii_digit(c, 10)?;
            tmp = tmp * 10 + d as i64;
            new_octet = false;
        }
    }
    if new_octet || tmp < 0 || tmp >= (1i64 << ((4 - curr) * 8)) {
        return None;
    }
    // The switch falls through from the current byte to the last.
    if curr == 0 {
        res[0] = ((tmp >> 24) & 0xff) as u8;
    }
    if curr <= 1 {
        res[1] = ((tmp >> 16) & 0xff) as u8;
    }
    if curr <= 2 {
        res[2] = ((tmp >> 8) & 0xff) as u8;
    }
    res[3] = (tmp & 0xff) as u8;
    Some(res)
}

/// `validateNumericFormatV4`: `Err` is the `IllegalArgumentException` for a literal a BSD
/// `inet_aton` would read (hex, octal) but Java refuses as ambiguous.
pub fn validate_numeric_format_v4(src: &[u16]) -> Result<Option<[u8; 4]>, ()> {
    let parsed = text_to_numeric_format_v4(src);
    if parsed.is_none() && is_bsd_parsable_v4(src) {
        return Err(());
    }
    Ok(parsed)
}

const CANT_PARSE_IN_RADIX: i64 = -1;
const TERMINAL_PARSE_ERROR: i64 = -2;

pub fn is_bsd_parsable_v4(input: &[u16]) -> bool {
    let Some(&first) = input.first() else { return false };
    if parse_ascii_digit(first, 10).is_none() {
        return false;
    }
    let last = input[input.len() - 1];
    if last == b'.' as u16 || parse_ascii_hex_digit(last).is_none() {
        return false;
    }
    let mut pos = 0usize;
    let mut field_number = 0;
    while pos < input.len() {
        let mut field_value = -1i64;
        for radix in [16u32, 8, 10] {
            field_value = parse_v4_field_bsd(radix, input, &mut pos, field_number);
            if field_value >= 0 {
                field_number += 1;
                break;
            } else if field_value == TERMINAL_PARSE_ERROR {
                return false;
            }
        }
        if field_value < 0 {
            return false;
        }
    }
    true
}

fn parse_v4_field_bsd(radix: u32, buf: &[u16], pos: &mut usize, field_number: i32) -> i64 {
    let initial = *pos;
    let mut val: i64 = 0;
    let mut digits = 0;
    if !check_prefix(buf, pos, radix) {
        val = CANT_PARSE_IN_RADIX;
    }
    let mut dot_seen = false;
    while *pos < buf.len() && val != CANT_PARSE_IN_RADIX && !dot_seen {
        let c = buf[*pos];
        *pos += 1;
        if c == b'.' as u16 {
            dot_seen = true;
            if field_number == 3 {
                return TERMINAL_PARSE_ERROR;
            }
            if digits == 0 {
                return TERMINAL_PARSE_ERROR;
            }
            if val > 255 {
                return TERMINAL_PARSE_ERROR;
            }
        } else {
            match parse_ascii_digit(c, radix) {
                Some(dv) => {
                    digits += 1;
                    val = val.wrapping_mul(radix as i64).wrapping_add(dv as i64);
                }
                None => return TERMINAL_PARSE_ERROR,
            }
        }
    }
    if val == CANT_PARSE_IN_RADIX {
        *pos = initial;
    } else if !dot_seen {
        let max = (1i64 << ((4 - field_number) * 8)) - 1;
        if val > max {
            return TERMINAL_PARSE_ERROR;
        }
    }
    val
}

fn check_prefix(buf: &[u16], pos: &mut usize, radix: u32) -> bool {
    match radix {
        8 => {
            if buf.len() - *pos < 2 {
                return false;
            }
            let first = buf[*pos];
            let second = buf[*pos + 1];
            let octal = first == b'0' as u16 && second != b'.' as u16;
            if octal {
                *pos += 1;
            } else {
                // Java consumed both characters; the caller resets on false.
                *pos += 2;
            }
            octal
        }
        10 => *pos < buf.len(),
        _ => {
            if buf.len() - *pos < 2 {
                return false;
            }
            let first = buf[*pos];
            let second = buf[*pos + 1];
            *pos += 2;
            first == b'0' as u16 && (second == b'x' as u16 || second == b'X' as u16)
        }
    }
}

fn check_numeric_zone(s: &[u16]) -> Option<i32> {
    let percent = s.iter().position(|c| *c == b'%' as u16)?;
    let multmax = i32::MAX / 10;
    let mut zone: i32 = 0;
    for &c in &s[percent + 1..] {
        let d = parse_ascii_digit(c, 10)? as i32;
        if zone > multmax {
            return None;
        }
        zone = zone.wrapping_mul(10).wrapping_add(d);
        if zone < 0 {
            return None;
        }
    }
    Some(zone)
}

/// `textToNumericFormatV6`, including the conversion of an IPv4-mapped address to 4 bytes.
pub fn text_to_numeric_format_v6(src: &[u16]) -> Option<Vec<u8>> {
    if src.len() < 2 {
        return None;
    }
    let mut srcb_length = src.len();
    let pc = src.iter().position(|c| *c == b'%' as u16);
    if pc == Some(srcb_length - 1) {
        return None;
    }
    if let Some(pc) = pc {
        srcb_length = pc;
    }
    let mut dst = [0u8; 16];
    let mut colonp: i32 = -1;
    let mut i = 0usize;
    let mut j = 0usize;
    if src[i] == b':' as u16 {
        i += 1;
        if src[i] != b':' as u16 {
            return None;
        }
    }
    let mut curtok = i;
    let mut saw_xdigit = false;
    let mut val: u32 = 0;
    while i < srcb_length {
        let ch = src[i];
        i += 1;
        if let Some(chval) = hex_digit(ch) {
            val <<= 4;
            val |= chval;
            if val > 0xffff {
                return None;
            }
            saw_xdigit = true;
            continue;
        }
        if ch == b':' as u16 {
            curtok = i;
            if !saw_xdigit {
                if colonp != -1 {
                    return None;
                }
                colonp = j as i32;
                continue;
            } else if i == srcb_length {
                return None;
            }
            if j + 2 > 16 {
                return None;
            }
            dst[j] = ((val >> 8) & 0xff) as u8;
            dst[j + 1] = (val & 0xff) as u8;
            j += 2;
            saw_xdigit = false;
            val = 0;
            continue;
        }
        if ch == b'.' as u16 && j + 4 <= 16 {
            let ia4 = &src[curtok..srcb_length];
            let dots = ia4.iter().filter(|c| **c == b'.' as u16).count();
            if dots != 3 {
                return None;
            }
            let v4 = text_to_numeric_format_v4(ia4)?;
            dst[j..j + 4].copy_from_slice(&v4);
            j += 4;
            saw_xdigit = false;
            break;
        }
        return None;
    }
    if saw_xdigit {
        if j + 2 > 16 {
            return None;
        }
        dst[j] = ((val >> 8) & 0xff) as u8;
        dst[j + 1] = (val & 0xff) as u8;
        j += 2;
    }
    if colonp != -1 {
        let colonp = colonp as usize;
        let n = j - colonp;
        if j == 16 {
            return None;
        }
        for k in 1..=n {
            dst[16 - k] = dst[colonp + n - k];
            dst[colonp + n - k] = 0;
        }
        j = 16;
    }
    if j != 16 {
        return None;
    }
    if dst[..10].iter().all(|b| *b == 0) && dst[10] == 0xff && dst[11] == 0xff {
        return Some(dst[12..16].to_vec());
    }
    Some(dst.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lit(s: &str) -> Literal {
        classify(s)
    }

    #[test]
    fn ipv4_forms() {
        assert_eq!(lit("127.0.0.1"), Literal::Address(JavaInet::V4([127, 0, 0, 1])));
        assert_eq!(lit("127.1"), Literal::Address(JavaInet::V4([127, 0, 0, 1])));
        assert_eq!(lit("2130706433"), Literal::Address(JavaInet::V4([127, 0, 0, 1])));
        assert_eq!(lit("10.1.65535"), Literal::Address(JavaInet::V4([10, 1, 255, 255])));
        // Leading zeros are read as decimal by JDK 21.
        assert_eq!(lit("0127.0.0.1"), Literal::Address(JavaInet::V4([127, 0, 0, 1])));
        // Hex is what a BSD parser would read: refused as ambiguous.
        assert!(matches!(lit("0x7f000001"), Literal::Unknown(_)));
        assert!(matches!(lit("0x7f.1"), Literal::Unknown(_)));
        // Too many parts is not ambiguous, only not a literal.
        assert!(matches!(lit("1.2.3.4.5"), Literal::Resolve(_)));
    }

    #[test]
    fn ipv6_forms() {
        assert_eq!(lit("::1"), Literal::Address(JavaInet::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])));
        assert_eq!(lit("::ffff:127.0.0.1"), Literal::Address(JavaInet::V4([127, 0, 0, 1])));
        assert_eq!(lit("[::1]"), lit("::1"));
        assert!(matches!(lit("fe80::zz"), Literal::Unknown(_)));
        assert!(matches!(lit("example.com"), Literal::Resolve(_)));
        assert_eq!(JavaInet::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]).host_address(), "0:0:0:0:0:0:0:1");
    }
}
