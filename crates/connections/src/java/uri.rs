//! `new java.net.URI(String)` as JDK 21 parses it (the JDK the Java core runs on): the RFC 2396
//! parser with Java's deviations (empty authority before a path, RFC 2732 IPv6 literals, the
//! registry-based fallback when an authority does not parse as `[userinfo@]host[:port]`).
//!
//! The outbound guard decides on what this parser says the host is, so it is ported line for
//! line rather than approximated with the `url` crate, which follows WHATWG and reads many
//! strings differently (it accepts backslashes, folds full-width digits, re-encodes, and finds
//! a host where Java finds none).
//!
//! The input is handled as UTF-16 code units, as `String.charAt` sees it.

/// What a successful parse found. Only the parts the guard reads are kept.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JavaUri {
    pub scheme: Option<String>,
    /// `getHost()`: `None` for an opaque URI, an empty or registry-based authority. An IPv6
    /// literal keeps its brackets, as Java returns it.
    pub host: Option<String>,
    pub port: i32,
}

/// `URISyntaxException`, with the reason and index Java reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UriSyntaxError {
    pub reason: String,
    pub index: i32,
}

const fn low_mask_range(first: u8, last: u8) -> u64 {
    let mut m = 0u64;
    let mut c = first;
    while c <= last {
        if c < 64 {
            m |= 1u64 << c;
        }
        c += 1;
    }
    m
}

const fn high_mask_range(first: u8, last: u8) -> u64 {
    let mut m = 0u64;
    let mut c = first;
    while c <= last {
        if c >= 64 && c < 128 {
            m |= 1u64 << (c - 64);
        }
        c += 1;
    }
    m
}

const fn low_mask(chars: &[u8]) -> u64 {
    let mut m = 0u64;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c < 64 {
            m |= 1u64 << c;
        }
        i += 1;
    }
    m
}

const fn high_mask(chars: &[u8]) -> u64 {
    let mut m = 0u64;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c >= 64 && c < 128 {
            m |= 1u64 << (c - 64);
        }
        i += 1;
    }
    m
}

const L_DIGIT: u64 = low_mask_range(b'0', b'9');
const H_DIGIT: u64 = 0;
const H_UPALPHA: u64 = high_mask_range(b'A', b'Z');
const H_LOWALPHA: u64 = high_mask_range(b'a', b'z');
const L_ALPHA: u64 = 0;
const H_ALPHA: u64 = H_LOWALPHA | H_UPALPHA;
const L_ALPHANUM: u64 = L_DIGIT | L_ALPHA;
const H_ALPHANUM: u64 = H_DIGIT | H_ALPHA;
const L_HEX: u64 = L_DIGIT;
const H_HEX: u64 = high_mask_range(b'A', b'F') | high_mask_range(b'a', b'f');
const L_MARK: u64 = low_mask(b"-_.!~*'()");
const H_MARK: u64 = high_mask(b"-_.!~*'()");
const L_UNRESERVED: u64 = L_ALPHANUM | L_MARK;
const H_UNRESERVED: u64 = H_ALPHANUM | H_MARK;
const L_RESERVED: u64 = low_mask(b";/?:@&=+$,[]");
const H_RESERVED: u64 = high_mask(b";/?:@&=+$,[]");
/// Bit 0 (the NUL slot, which never matches a character) flags "escapes allowed".
const L_ESCAPED: u64 = 1;
const H_ESCAPED: u64 = 0;
const L_URIC: u64 = L_RESERVED | L_UNRESERVED | L_ESCAPED;
const H_URIC: u64 = H_RESERVED | H_UNRESERVED | H_ESCAPED;
const L_PCHAR: u64 = L_UNRESERVED | L_ESCAPED | low_mask(b":@&=+$,");
const H_PCHAR: u64 = H_UNRESERVED | H_ESCAPED | high_mask(b":@&=+$,");
const L_PATH: u64 = L_PCHAR | low_mask(b";/");
const H_PATH: u64 = H_PCHAR;
const L_DASH: u64 = low_mask(b"-");
const H_DASH: u64 = 0;
const L_DOT: u64 = low_mask(b".");
const H_DOT: u64 = 0;
const L_USERINFO: u64 = L_UNRESERVED | L_ESCAPED | low_mask(b";:&=+$,");
const H_USERINFO: u64 = H_UNRESERVED | H_ESCAPED;
const L_REG_NAME: u64 = L_UNRESERVED | L_ESCAPED | low_mask(b"$,;:@&=+");
const H_REG_NAME: u64 = H_UNRESERVED | H_ESCAPED | high_mask(b"$,;:@&=+");
const L_SERVER: u64 = L_USERINFO | L_ALPHANUM | L_DASH | low_mask(b".:@[]");
const H_SERVER: u64 = H_USERINFO | H_ALPHANUM | H_DASH | high_mask(b".:@[]");
const L_SERVER_PERCENT: u64 = L_SERVER | low_mask(b"%");
const H_SERVER_PERCENT: u64 = H_SERVER;
const L_SCHEME: u64 = L_ALPHA | L_DIGIT | low_mask(b"+-.");
const H_SCHEME: u64 = H_ALPHA | H_DIGIT;
const L_SCOPE_ID: u64 = L_ALPHANUM | low_mask(b"_.");
const H_SCOPE_ID: u64 = H_ALPHANUM | high_mask(b"_.");

fn matches(c: u16, low: u64, high: u64) -> bool {
    if c == 0 {
        return false;
    }
    if c < 64 {
        return (1u64 << c) & low != 0;
    }
    if c < 128 {
        return (1u64 << (c - 64)) & high != 0;
    }
    false
}

/// `Character.isSpaceChar` for a UTF-16 unit above 128: the Zs, Zl and Zp characters.
fn is_space_char(c: u16) -> bool {
    matches!(c, 0x00A0 | 0x1680 | 0x2000..=0x200A | 0x2028 | 0x2029 | 0x202F | 0x205F | 0x3000)
}

/// `Character.isISOControl`.
fn is_iso_control(c: u16) -> bool {
    c <= 0x1F || (0x7F..=0x9F).contains(&c)
}

/// Parses `s` as `new URI(s)` does.
pub fn parse(s: &str) -> Result<JavaUri, UriSyntaxError> {
    parse_with(s, false)
}

/// The parse the multi-argument constructors run on the string they build: the authority
/// must be a server.
pub fn parse_with(s: &str, require_server_authority: bool) -> Result<JavaUri, UriSyntaxError> {
    let mut p = Parser {
        input: s.encode_utf16().collect(),
        require_server_authority,
        scheme: None,
        host: None,
        port: -1,
        ipv6_byte_count: 0,
    };
    p.parse()?;
    Ok(JavaUri { scheme: p.scheme, host: p.host, port: p.port })
}

struct Parser {
    input: Vec<u16>,
    require_server_authority: bool,
    scheme: Option<String>,
    host: Option<String>,
    port: i32,
    ipv6_byte_count: i32,
}

type R<T> = Result<T, UriSyntaxError>;

impl Parser {
    fn fail<T>(&self, reason: &str, p: i32) -> R<T> {
        Err(UriSyntaxError { reason: reason.to_string(), index: p })
    }

    fn fail_expecting<T>(&self, expected: &str, p: i32) -> R<T> {
        self.fail(&format!("Expected {expected}"), p)
    }

    fn ch(&self, i: i32) -> u16 {
        self.input[i as usize]
    }

    fn substring(&self, start: i32, end: i32) -> String {
        String::from_utf16_lossy(&self.input[start as usize..end as usize])
    }

    fn at(&self, start: i32, end: i32, c: u16) -> bool {
        start < end && self.ch(start) == c
    }

    fn at_str(&self, start: i32, end: i32, s: &str) -> bool {
        let s: Vec<u16> = s.encode_utf16().collect();
        let sn = s.len() as i32;
        if sn > end - start {
            return false;
        }
        (0..sn).all(|i| self.ch(start + i) == s[i as usize])
    }

    fn scan_char(&self, start: i32, end: i32, c: u16) -> i32 {
        if start < end && self.ch(start) == c {
            start + 1
        } else {
            start
        }
    }

    fn scan_err_stop(&self, start: i32, end: i32, err: &str, stop: &str) -> i32 {
        let mut p = start;
        while p < end {
            let c = self.ch(p);
            if contains(err, c) {
                return -1;
            }
            if contains(stop, c) {
                break;
            }
            p += 1;
        }
        p
    }

    fn scan_stop(&self, start: i32, end: i32, stop: &str) -> i32 {
        let mut p = start;
        while p < end {
            if contains(stop, self.ch(p)) {
                break;
            }
            p += 1;
        }
        p
    }

    fn scan_escape(&self, start: i32, n: i32, first: u16) -> R<i32> {
        let p = start;
        let c = first;
        if c == b'%' as u16 {
            if p + 3 <= n && matches(self.ch(p + 1), L_HEX, H_HEX) && matches(self.ch(p + 2), L_HEX, H_HEX) {
                return Ok(p + 3);
            }
            return self.fail("Malformed escape pair", p);
        } else if c > 128 && !is_space_char(c) && !is_iso_control(c) {
            return Ok(p + 1);
        }
        Ok(p)
    }

    fn scan_mask(&self, start: i32, n: i32, low: u64, high: u64) -> R<i32> {
        let mut p = start;
        while p < n {
            let c = self.ch(p);
            if matches(c, low, high) {
                p += 1;
                continue;
            }
            if low & L_ESCAPED != 0 {
                let q = self.scan_escape(p, n, c)?;
                if q > p {
                    p = q;
                    continue;
                }
            }
            break;
        }
        Ok(p)
    }

    fn check_chars(&self, start: i32, end: i32, low: u64, high: u64, what: &str) -> R<()> {
        let p = self.scan_mask(start, end, low, high)?;
        if p < end {
            return self.fail(&format!("Illegal character in {what}"), p);
        }
        Ok(())
    }

    fn check_char(&self, p: i32, low: u64, high: u64, what: &str) -> R<()> {
        self.check_chars(p, p + 1, low, high, what)
    }

    fn parse(&mut self) -> R<()> {
        let n = self.input.len() as i32;
        let mut p = self.scan_err_stop(0, n, "/?#", ":");
        if p >= 0 && self.at(p, n, b':' as u16) {
            if p == 0 {
                return self.fail_expecting("scheme name", 0);
            }
            self.check_char(0, L_ALPHA, H_ALPHA, "scheme name")?;
            self.check_chars(1, p, L_SCHEME, H_SCHEME, "scheme name")?;
            self.scheme = Some(self.substring(0, p));
            p += 1;
            if self.at(p, n, b'/' as u16) {
                p = self.parse_hierarchical(p, n)?;
            } else {
                let q = self.scan_stop(p, n, "#");
                if q <= p {
                    return self.fail_expecting("scheme-specific part", p);
                }
                self.check_chars(p, q, L_URIC, H_URIC, "opaque part")?;
                p = q;
            }
        } else {
            p = self.parse_hierarchical(0, n)?;
        }
        if self.at(p, n, b'#' as u16) {
            self.check_chars(p + 1, n, L_URIC, H_URIC, "fragment")?;
            p = n;
        }
        if p < n {
            return self.fail("end of URI", p);
        }
        Ok(())
    }

    fn parse_hierarchical(&mut self, start: i32, n: i32) -> R<i32> {
        let mut p = start;
        if self.at(p, n, b'/' as u16) && self.at(p + 1, n, b'/' as u16) {
            p += 2;
            let q = self.scan_stop(p, n, "/?#");
            if q > p {
                p = self.parse_authority(p, q)?;
            } else if q < n {
                // An empty authority before a path, query or fragment is allowed.
            } else {
                return self.fail_expecting("authority", p);
            }
        }
        let q = self.scan_stop(p, n, "?#");
        self.check_chars(p, q, L_PATH, H_PATH, "path")?;
        p = q;
        if self.at(p, n, b'?' as u16) {
            p += 1;
            let q = self.scan_stop(p, n, "#");
            self.check_chars(p, q, L_URIC, H_URIC, "query")?;
            p = q;
        }
        Ok(p)
    }

    fn parse_authority(&mut self, start: i32, n: i32) -> R<i32> {
        let p = start;
        let mut q = p;
        let mut ex: Option<UriSyntaxError> = None;

        let server_chars = if self.scan_stop(p, n, "]") > p {
            self.scan_mask(p, n, L_SERVER_PERCENT, H_SERVER_PERCENT)? == n
        } else {
            self.scan_mask(p, n, L_SERVER, H_SERVER)? == n
        };
        let qreg = self.scan_mask(p, n, L_REG_NAME, H_REG_NAME)?;
        let reg_chars = qreg == n;

        if reg_chars && !server_chars {
            return Ok(n);
        }

        let skip_parse_exception = !self.require_server_authority && reg_chars;

        if server_chars {
            match self.parse_server(p, n, skip_parse_exception) {
                Ok(r) => {
                    q = r;
                    if q < n {
                        if skip_parse_exception {
                            self.host = None;
                            self.port = -1;
                            q = p;
                        } else {
                            return self.fail_expecting("end of authority", q);
                        }
                    }
                }
                Err(x) => {
                    self.host = None;
                    self.port = -1;
                    if self.require_server_authority {
                        return Err(x);
                    }
                    ex = Some(x);
                    q = p;
                }
            }
        }

        if q < n {
            if reg_chars {
                // Registry-based authority.
            } else if let Some(ex) = ex {
                return Err(ex);
            } else {
                return self.fail("Illegal character in authority", if server_chars { q } else { qreg });
            }
        }
        Ok(n)
    }

    fn parse_server(&mut self, start: i32, n: i32, skip_parse_exception: bool) -> R<i32> {
        let mut p = start;
        let q = self.scan_err_stop(p, n, "/?#", "@");
        if q >= p && self.at(q, n, b'@' as u16) {
            self.check_chars(p, q, L_USERINFO, H_USERINFO, "user info")?;
            p = q + 1;
        }

        if self.at(p, n, b'[' as u16) {
            p += 1;
            let q = self.scan_err_stop(p, n, "/?#", "]");
            if q > p && self.at(q, n, b']' as u16) {
                let r = self.scan_stop(p, q, "%");
                if r > p {
                    self.parse_ipv6_reference(p, r)?;
                    if r + 1 == q {
                        return self.fail("scope id expected", -1);
                    }
                    self.check_chars(r + 1, q, L_SCOPE_ID, H_SCOPE_ID, "scope id")?;
                } else {
                    self.parse_ipv6_reference(p, q)?;
                }
                self.host = Some(self.substring(p - 1, q + 1));
                p = q + 1;
            } else {
                return self.fail_expecting("closing bracket for IPv6 address", q);
            }
        } else {
            let mut q = self.parse_ipv4_address(p, n);
            if q <= p {
                q = self.parse_hostname(p, n, skip_parse_exception)?;
            }
            p = q;
        }

        if self.at(p, n, b':' as u16) {
            p += 1;
            let q = self.scan_stop(p, n, "/");
            if q > p {
                self.check_chars(p, q, L_DIGIT, H_DIGIT, "port number")?;
                match self.substring(p, q).parse::<i32>() {
                    Ok(v) => self.port = v,
                    Err(_) => return self.fail("Malformed port number", p),
                }
                p = q;
            }
        } else if p < n && skip_parse_exception {
            return Ok(p);
        }
        if p < n {
            return self.fail_expecting("port number", p);
        }
        Ok(p)
    }

    /// Decimal digits whose value fits in a byte. `Integer.parseInt` of a run too long for an
    /// `int` throws `NumberFormatException`, which `parseIPv4Address` turns into "not IPv4".
    fn scan_byte(&self, start: i32, n: i32) -> R<Result<i32, ()>> {
        let p = start;
        let q = self.scan_mask(p, n, L_DIGIT, H_DIGIT)?;
        if q <= p {
            return Ok(Ok(q));
        }
        match self.substring(p, q).parse::<i32>() {
            Ok(v) if v > 255 => Ok(Ok(p)),
            Ok(_) => Ok(Ok(q)),
            Err(_) => Ok(Err(())),
        }
    }

    /// `scanIPv4Address`. `Ok(Err(()))` is the `NumberFormatException` escape.
    fn scan_ipv4_address(&self, start: i32, n: i32, strict: bool) -> R<Result<i32, ()>> {
        let mut p = start;
        let m = self.scan_mask(p, n, L_DIGIT | L_DOT, H_DIGIT | H_DOT)?;
        if m <= p || (strict && m != n) {
            return Ok(Ok(-1));
        }
        let mut q;
        macro_rules! byte {
            () => {
                match self.scan_byte(p, m)? {
                    Ok(v) => v,
                    Err(()) => return Ok(Err(())),
                }
            };
        }
        loop {
            q = byte!();
            if q <= p {
                break;
            }
            p = q;
            q = self.scan_char(p, m, b'.' as u16);
            if q <= p {
                break;
            }
            p = q;
            q = byte!();
            if q <= p {
                break;
            }
            p = q;
            q = self.scan_char(p, m, b'.' as u16);
            if q <= p {
                break;
            }
            p = q;
            q = byte!();
            if q <= p {
                break;
            }
            p = q;
            q = self.scan_char(p, m, b'.' as u16);
            if q <= p {
                break;
            }
            p = q;
            q = byte!();
            if q <= p {
                break;
            }
            if q < m {
                break;
            }
            return Ok(Ok(q));
        }
        self.fail("Malformed IPv4 address", q)
    }

    fn take_ipv4_address(&self, start: i32, n: i32, expected: &str) -> R<i32> {
        let p = match self.scan_ipv4_address(start, n, true)? {
            Ok(p) => p,
            // A NumberFormatException escapes the URI constructor as itself; the guard treats
            // every failure to construct the URI alike.
            Err(()) => return self.fail("NumberFormatException", start),
        };
        if p <= start {
            return self.fail_expecting(expected, start);
        }
        Ok(p)
    }

    fn parse_ipv4_address(&mut self, start: i32, n: i32) -> i32 {
        let mut p = match self.scan_ipv4_address(start, n, false) {
            Ok(Ok(p)) => p,
            _ => return -1,
        };
        if p > start && p < n && self.ch(p) != b':' as u16 {
            p = -1;
        }
        if p > start {
            self.host = Some(self.substring(start, p));
        }
        p
    }

    fn parse_hostname(&mut self, start: i32, n: i32, skip_parse_exception: bool) -> R<i32> {
        let mut p = start;
        let mut l = -1;
        loop {
            let q = self.scan_mask(p, n, L_ALPHANUM, H_ALPHANUM)?;
            if q <= p {
                break;
            }
            l = p;
            p = q;
            let q = self.scan_mask(p, n, L_ALPHANUM | L_DASH, H_ALPHANUM | H_DASH)?;
            if q > p {
                if self.ch(q - 1) == b'-' as u16 {
                    return self.fail("Illegal character in hostname", q - 1);
                }
                p = q;
            }
            let q = self.scan_char(p, n, b'.' as u16);
            if q <= p {
                break;
            }
            p = q;
            if p >= n {
                break;
            }
        }
        if p < n && !self.at(p, n, b':' as u16) {
            if skip_parse_exception {
                return Ok(p);
            }
            return self.fail("Illegal character in hostname", p);
        }
        if l < 0 {
            return self.fail_expecting("hostname", start);
        }
        if l > start && !matches(self.ch(l), L_ALPHA, H_ALPHA) {
            return self.fail("Illegal character in hostname", l);
        }
        self.host = Some(self.substring(start, p));
        Ok(p)
    }

    fn parse_ipv6_reference(&mut self, start: i32, n: i32) -> R<i32> {
        let mut p = start;
        let mut compressed_zeros = false;
        let q = self.scan_hex_seq(p, n)?;
        if q > p {
            p = q;
            if self.at_str(p, n, "::") {
                compressed_zeros = true;
                p = self.scan_hex_post(p + 2, n)?;
            } else if self.at(p, n, b':' as u16) {
                p = self.take_ipv4_address(p + 1, n, "IPv4 address")?;
                self.ipv6_byte_count += 4;
            }
        } else if self.at_str(p, n, "::") {
            compressed_zeros = true;
            p = self.scan_hex_post(p + 2, n)?;
        }
        if p < n {
            return self.fail("Malformed IPv6 address", start);
        }
        if self.ipv6_byte_count > 16 {
            return self.fail("IPv6 address too long", start);
        }
        if !compressed_zeros && self.ipv6_byte_count < 16 {
            return self.fail("IPv6 address too short", start);
        }
        if compressed_zeros && self.ipv6_byte_count == 16 {
            return self.fail("Malformed IPv6 address", start);
        }
        Ok(p)
    }

    fn scan_hex_post(&mut self, start: i32, n: i32) -> R<i32> {
        let mut p = start;
        if p == n {
            return Ok(p);
        }
        let q = self.scan_hex_seq(p, n)?;
        if q > p {
            p = q;
            if self.at(p, n, b':' as u16) {
                p += 1;
                p = self.take_ipv4_address(p, n, "hex digits or IPv4 address")?;
                self.ipv6_byte_count += 4;
            }
        } else {
            p = self.take_ipv4_address(p, n, "hex digits or IPv4 address")?;
            self.ipv6_byte_count += 4;
        }
        Ok(p)
    }

    fn scan_hex_seq(&mut self, start: i32, n: i32) -> R<i32> {
        let mut p = start;
        let q = self.scan_mask(p, n, L_HEX, H_HEX)?;
        if q <= p {
            return Ok(-1);
        }
        if self.at(q, n, b'.' as u16) {
            return Ok(-1);
        }
        if q > p + 4 {
            return self.fail("IPv6 hexadecimal digit sequence too long", p);
        }
        self.ipv6_byte_count += 2;
        p = q;
        while p < n {
            if !self.at(p, n, b':' as u16) {
                break;
            }
            if self.at(p + 1, n, b':' as u16) {
                break;
            }
            p += 1;
            let q = self.scan_mask(p, n, L_HEX, H_HEX)?;
            if q <= p {
                return self.fail_expecting("digits for an IPv6 address", p);
            }
            if self.at(q, n, b'.' as u16) {
                p -= 1;
                break;
            }
            if q > p + 4 {
                return self.fail("IPv6 hexadecimal digit sequence too long", p);
            }
            self.ipv6_byte_count += 2;
            p = q;
        }
        Ok(p)
    }
}

/// Which characters a component of the multi-argument constructors may hold unquoted.
#[derive(Debug, Clone, Copy)]
pub enum QuoteComponent {
    UserInfo,
    Path,
    Uric,
}

/// `URI.quote`: every ASCII character outside the component's set is escaped (including `%`,
/// so an already-escaped value is escaped again), non-ASCII spaces and controls are escaped as
/// UTF-8, other non-ASCII characters stay.
pub fn quote(s: &str, component: QuoteComponent) -> String {
    let (low, high) = match component {
        QuoteComponent::UserInfo => (L_USERINFO, H_USERINFO),
        QuoteComponent::Path => (L_PATH, H_PATH),
        QuoteComponent::Uric => (L_URIC, H_URIC),
    };
    let allow_non_ascii = low & L_ESCAPED != 0;
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        let c = ch as u32;
        if c < 0x80 {
            if !matches(c as u16, low, high) {
                out.push_str(&format!("%{:02X}", c));
            } else {
                out.push(ch);
            }
        } else if allow_non_ascii && (c <= 0xFFFF && (is_space_char(c as u16) || is_iso_control(c as u16))) {
            let mut buf = [0u8; 4];
            for b in ch.encode_utf8(&mut buf).bytes() {
                out.push_str(&format!("%{:02X}", b));
            }
        } else {
            out.push(ch);
        }
    }
    out
}

fn contains(set: &str, c: u16) -> bool {
    set.encode_utf16().any(|x| x == c)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The precomputed constants in `java.net.URI`, so a typo in a character list shows up.
    #[test]
    fn masks_equal_the_jdk_constants() {
        assert_eq!(L_DIGIT, 0x3FF000000000000);
        assert_eq!(H_UPALPHA, 0x7FFFFFE);
        assert_eq!(H_LOWALPHA, 0x7FFFFFE00000000);
        assert_eq!(H_HEX, 0x7E0000007E);
        assert_eq!(L_MARK, 0x678200000000);
        assert_eq!(H_MARK, 0x4000000080000000);
        assert_eq!(L_RESERVED, 0xAC00985000000000);
        assert_eq!(H_RESERVED, 0x28000001);
        assert_eq!(L_PCHAR & !(L_UNRESERVED | L_ESCAPED), 0x2400185000000000);
        assert_eq!(L_PATH & !L_PCHAR, 0x800800000000000);
        assert_eq!(L_DASH, 0x200000000000);
        assert_eq!(L_DOT, 0x400000000000);
        assert_eq!(L_SCHEME & !(L_ALPHA | L_DIGIT), 0x680000000000);
        assert_eq!(H_SCOPE_ID & !H_ALPHANUM, 0x80000000);
        assert_eq!(L_SERVER_PERCENT & !L_SERVER, 0x2000000000);
        // The same helpers, run (not const-evaluated).
        let (lo, hi) = (std::hint::black_box(b'0'), std::hint::black_box(b'9'));
        assert_eq!(low_mask_range(lo, hi), L_DIGIT);
        assert_eq!(high_mask_range(std::hint::black_box(b'A'), std::hint::black_box(b'Z')), H_UPALPHA);
        assert_eq!(low_mask(std::hint::black_box(b";/")), L_PATH & !L_PCHAR);
        assert_eq!(high_mask(std::hint::black_box(b"-_.!~*'()")), H_MARK);
        assert_eq!(high_mask_range(std::hint::black_box(0), std::hint::black_box(10)), 0);
        assert_eq!(low_mask(std::hint::black_box(b"\x7f")), 0);
    }

    #[test]
    fn quoting_non_ascii() {
        assert_eq!(quote("a b\u{a0}c\u{e9}", QuoteComponent::Uric), "a%20b%C2%A0c\u{e9}");
        assert_eq!(quote("u:p@x", QuoteComponent::UserInfo), "u:p%40x");
        assert_eq!(quote("/a b", QuoteComponent::Path), "/a%20b");
    }

    fn host(s: &str) -> Option<String> {
        parse(s).unwrap().host
    }

    #[test]
    fn hosts() {
        assert_eq!(host("http://example.com/x"), Some("example.com".into()));
        assert_eq!(host("http://user:pw@example.com:8080/x"), Some("example.com".into()));
        assert_eq!(host("http://[::1]/x"), Some("[::1]".into()));
        // A short dotted number is neither an IPv4 address nor a hostname to java.net.URI.
        assert_eq!(host("http://127.1/x"), None);
        assert_eq!(host("http://10.0.0.5:8080/x"), Some("10.0.0.5".into()));
        // Underscores make the authority registry-based: no host.
        assert_eq!(host("http://my_host.example.com/x"), None);
        assert_eq!(host("file:///etc/passwd"), None);
        assert_eq!(parse("mailto:a@b").unwrap().scheme, Some("mailto".into()));
    }

    #[test]
    fn syntax_errors() {
        assert!(parse("http://example.com/x/{id}").is_err());
        assert!(parse("http://example.com/a b").is_err());
        assert!(parse("http://exa mple.com/").is_err());
        assert!(parse("http://example.com\\@127.0.0.1/").is_err());
        assert!(parse("://x").is_err());
        assert!(parse("http://[::1/").is_err());
    }
}
