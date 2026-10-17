//! How Spring 6.2 turns a REST connection's URL into the URI WebClient calls:
//! `CustomUriBuilderFactory(url, encodingMode)` (a `DefaultUriBuilderFactory` over
//! `UriComponentsBuilder.fromUriString`, the RFC parser), `queryParam` for every query
//! parameter, `build(pathParameters)` (URI template expansion), then `URI.create`.
//!
//! The encoding mode decides what is percent-encoded where, and template variables (`{name}`)
//! can appear in any part of the URL, so this is a port of the pieces of `RfcUriParser`,
//! `UriComponentsBuilder` and `HierarchicalUriComponents` that path takes, not an
//! approximation with a generic URL library.

use std::collections::HashMap;

use crate::error::ConnError;
use crate::java;

/// `WebClientEncodingModes`, the value of a connection's `encodingMode` detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebClientEncodingMode {
    ManualValuesEncoded,
    ValuesOnly,
    TemplateAndValues,
    UriComponent,
    None,
}

impl WebClientEncodingMode {
    /// `WebClientEncodingModes.valueOf(name)`; Java fails with this message for anything else.
    pub fn value_of(name: &str) -> Result<Self, ConnError> {
        Ok(match name {
            "MANUAL_VALUES_ENCODED" => Self::ManualValuesEncoded,
            "VALUES_ONLY" => Self::ValuesOnly,
            "TEMPLATE_AND_VALUES" => Self::TemplateAndValues,
            "URI_COMPONENT" => Self::UriComponent,
            "NONE" => Self::None,
            _ => {
                return Err(ConnError::other(format!(
                    "No enum constant com.fincity.saas.commons.webclient.WebClientEncodingModes.{name}"
                )))
            }
        })
    }

    fn spring_mode(self) -> EncodingMode {
        match self {
            Self::TemplateAndValues => EncodingMode::TemplateAndValues,
            Self::UriComponent => EncodingMode::UriComponent,
            Self::ValuesOnly => EncodingMode::ValuesOnly,
            Self::ManualValuesEncoded | Self::None => EncodingMode::None,
        }
    }
}

/// `DefaultUriBuilderFactory.EncodingMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EncodingMode {
    TemplateAndValues,
    ValuesOnly,
    UriComponent,
    None,
}

/// Builds the URI string WebClient sends for `url` with the given query and path parameters,
/// as `BasicRestService` does. Errors carry the Java exception's message.
pub fn build_request_uri(
    url: &str,
    mode: WebClientEncodingMode,
    query_parameters: &[(String, String)],
    path_parameters: &HashMap<String, String>,
) -> Result<String, ConnError> {
    let spring = mode.spring_mode();
    let base = Builder::from_uri_string(url)?;

    // DefaultUriBuilder(""): a clone of the base.
    let mut b = base.clone();
    if spring == EncodingMode::TemplateAndValues {
        b.encode_template = true;
    }
    if spring == EncodingMode::UriComponent {
        // parsePathIfNecessary: the path is re-added segment by segment, so each is encoded
        // as a segment.
        let (path, segments) = match b.build_components(false) {
            Components::Hier(h) => (h.path.get_path(), h.path.get_path_segments()),
            Components::Opaque { .. } => (String::new(), Vec::new()),
        };
        b.replace_path(None);
        b.path_segments(&segments);
        if path.ends_with('/') {
            b.add_path("/");
        }
    }

    for (k, v) in query_parameters {
        let value = if mode == WebClientEncodingMode::ManualValuesEncoded { url_encode_form(v) } else { v.clone() };
        b.query_param(k, Some(value));
    }

    let vars: HashMap<String, String> = if spring == EncodingMode::ValuesOnly {
        path_parameters.iter().map(|(k, v)| (k.clone(), encode_uri_component(v, Type::Uri))).collect()
    } else {
        path_parameters.clone()
    };

    let built = b.build_components(spring == EncodingMode::TemplateAndValues);
    let mut expanded = built.expand(&vars)?;
    if spring == EncodingMode::UriComponent {
        expanded = expanded.encode();
    }
    let s = expanded.to_uri_string();
    // URI.create(...)
    if let Err(e) = java::uri::parse(&s) {
        return Err(ConnError::other(uri_syntax_message(&e, &s)));
    }
    Ok(s)
}

/// `UriComponentsBuilder.fromUriString(url)`, a `queryParam` per pair, then
/// `build().toUri()`: the raw components put through the multi-argument `URI` constructor,
/// which quotes what is illegal in each (and every `%`).
pub fn build_to_uri(url: &str, query: &[(String, String)]) -> Result<String, ConnError> {
    let mut b = Builder::from_uri_string(url)?;
    for (k, v) in query {
        b.query_param(k, Some(v.clone()));
    }
    match b.build_components(false) {
        Components::Opaque { scheme, ssp, fragment } => {
            let mut out = String::new();
            if let Some(s) = scheme {
                out.push_str(&s);
                out.push(':');
            }
            out.push_str(&java::uri::quote(&ssp, java::uri::QuoteComponent::Uric));
            if let Some(f) = fragment {
                out.push('#');
                out.push_str(&java::uri::quote(&f, java::uri::QuoteComponent::Uric));
            }
            Ok(out)
        }
        Components::Hier(h) => {
            let mut path = h.path.get_path();
            let port: i32 = match &h.port {
                None => -1,
                Some(p) if p.contains('{') => {
                    return Err(ConnError::other(format!(
                        "The port contains a URI variable but has not been expanded yet: {p}"
                    )))
                }
                Some(p) => p.parse().map_err(|_| ConnError::other(format!("The port must be an integer: {p}")))?,
            };
            if !path.is_empty() && !path.starts_with('/') && (h.scheme.is_some() || h.user_info.is_some() || h.host.is_some() || port != -1) {
                path = format!("/{path}");
            }
            let mut s = String::new();
            if let Some(sc) = &h.scheme {
                s.push_str(sc);
                s.push(':');
            }
            if let Some(host) = &h.host {
                s.push_str("//");
                if let Some(u) = &h.user_info {
                    s.push_str(&java::uri::quote(u, java::uri::QuoteComponent::UserInfo));
                    s.push('@');
                }
                let brackets = host.contains(':') && !host.starts_with('[') && !host.ends_with(']');
                if brackets {
                    s.push('[');
                }
                s.push_str(host);
                if brackets {
                    s.push(']');
                }
                if port != -1 {
                    s.push_str(&format!(":{port}"));
                }
            }
            s.push_str(&java::uri::quote(&path, java::uri::QuoteComponent::Path));
            if let Some(q) = h.get_query() {
                s.push('?');
                s.push_str(&java::uri::quote(&q, java::uri::QuoteComponent::Uric));
            }
            if let Some(f) = &h.fragment {
                s.push('#');
                s.push_str(&java::uri::quote(f, java::uri::QuoteComponent::Uric));
            }
            if h.scheme.is_some() && !path.is_empty() && !path.starts_with('/') {
                return Err(ConnError::other(format!("Could not create URI object: Relative path in absolute URI: {s}")));
            }
            if let Err(e) = java::uri::parse_with(&s, true) {
                return Err(ConnError::other(format!("Could not create URI object: {}", uri_syntax_message(&e, &s))));
            }
            Ok(s)
        }
    }
}

/// `UriComponentsBuilder.fromUriString(url)`, a `queryParam` per pair, then
/// `build().toUriString()`: no encoding at all.
pub fn build_to_uri_string(url: &str, query: &[(String, String)]) -> Result<String, ConnError> {
    let mut b = Builder::from_uri_string(url)?;
    for (k, v) in query {
        b.query_param(k, Some(v.clone()));
    }
    Ok(match b.build_components(false) {
        Components::Hier(h) => h.to_uri_string(),
        other => other.to_uri_string(),
    })
}

/// `URISyntaxException.getMessage()`: `reason at index N: input`.
pub fn uri_syntax_message(e: &java::uri::UriSyntaxError, input: &str) -> String {
    if e.index > -1 {
        format!("{} at index {}: {}", e.reason, e.index, input)
    } else {
        format!("{}: {}", e.reason, input)
    }
}

/// `URLEncoder.encode(value, UTF_8)`: form encoding, space as `+`, `*-._` and alphanumerics
/// kept.
pub fn url_encode_form(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match *b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'*' => out.push(*b as char),
            b' ' => out.push('+'),
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------
// HierarchicalUriComponents.Type

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Type {
    Scheme,
    UserInfo,
    HostIpv4,
    HostIpv6,
    Path,
    PathSegment,
    QueryParam,
    Fragment,
    Uri,
}

fn is_alpha(c: u8) -> bool {
    c.is_ascii_alphabetic()
}
fn is_digit(c: u8) -> bool {
    c.is_ascii_digit()
}
fn is_sub_delimiter(c: u8) -> bool {
    matches!(c, b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'=')
}
fn is_unreserved(c: u8) -> bool {
    is_alpha(c) || is_digit(c) || matches!(c, b'-' | b'.' | b'_' | b'~')
}
fn is_unreserved_or_sub_delimiter(c: u8) -> bool {
    c < 128 && (is_unreserved(c) || is_sub_delimiter(c))
}
fn is_pchar(c: u8) -> bool {
    is_unreserved_or_sub_delimiter(c) || c == b':' || c == b'@'
}

impl Type {
    /// `isAllowed(int c)` for a byte: Java passes a signed byte, so every non-ASCII byte is
    /// negative and never allowed.
    fn is_allowed(self, c: u8) -> bool {
        if c >= 128 {
            return false;
        }
        match self {
            Type::Scheme => is_alpha(c) || is_digit(c) || matches!(c, b'+' | b'-' | b'.'),
            Type::UserInfo => is_unreserved_or_sub_delimiter(c) || c == b':',
            Type::HostIpv4 => is_unreserved_or_sub_delimiter(c),
            Type::HostIpv6 => is_unreserved_or_sub_delimiter(c) || matches!(c, b'[' | b']' | b':'),
            Type::Path => is_pchar(c) || c == b'/',
            Type::PathSegment => is_pchar(c),
            Type::QueryParam => c != b'=' && c != b'&' && (is_pchar(c) || c == b'/' || c == b'?'),
            Type::Fragment => is_pchar(c) || c == b'/' || c == b'?',
            Type::Uri => is_unreserved(c),
        }
    }
}

/// `HierarchicalUriComponents.encodeUriComponent(source, UTF_8, type)`.
pub(crate) fn encode_uri_component(source: &str, t: Type) -> String {
    if source.is_empty() {
        return String::new();
    }
    let bytes = source.as_bytes();
    if bytes.iter().all(|b| t.is_allowed(*b)) {
        return source.to_string();
    }
    let mut out = String::with_capacity(bytes.len() * 3);
    for &b in bytes {
        if t.is_allowed(b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------
// RfcUriParser

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Start,
    HostOrPath,
    SchemeOrPath,
    Host,
    Ipv6,
    Port,
    Path,
    Query,
    Fragment,
    Wildcard,
}

#[derive(Debug, Default, Clone)]
struct UriRecord {
    scheme: Option<String>,
    is_opaque: bool,
    user: Option<String>,
    host: Option<String>,
    port: Option<String>,
    path: Option<String>,
    query: Option<String>,
    fragment: Option<String>,
}

struct RfcParser {
    uri: Vec<u16>,
    rec: UriRecord,
    state: State,
    index: i64,
    component_index: i64,
    remaining_percent: i32,
    in_utf16: bool,
    in_password: bool,
    open_curly: i32,
}

fn bad(msg: &str) -> ConnError {
    ConnError::other(msg.to_string())
}

fn is_hex(c: u16) -> bool {
    matches!(c, 0x30..=0x39 | 0x41..=0x46 | 0x61..=0x66)
}

impl RfcParser {
    fn parse(uri: &str) -> Result<UriRecord, ConnError> {
        let mut p = RfcParser {
            uri: uri.encode_utf16().collect(),
            rec: UriRecord::default(),
            state: State::Start,
            index: 0,
            component_index: 0,
            remaining_percent: 0,
            in_utf16: false,
            in_password: false,
            open_curly: 0,
        };
        while p.has_next() {
            let c = p.char_at_index();
            let i = p.index;
            p.handle_next(c, i)?;
            p.index += 1;
        }
        p.handle_end()?;
        Ok(p.rec)
    }

    fn has_next(&self) -> bool {
        self.index < self.uri.len() as i64
    }

    fn char_at_index(&self) -> u16 {
        self.uri[self.index as usize]
    }

    fn advance_to(&mut self, s: State) {
        self.state = s;
        self.open_curly = 0;
    }

    fn advance_to_at(&mut self, s: State, component_index: i64) {
        self.component_index = component_index;
        self.advance_to(s);
    }

    fn capture(&self) -> String {
        let (a, b) = (self.component_index.max(0) as usize, self.index.max(0) as usize);
        if a >= b {
            return String::new();
        }
        String::from_utf16_lossy(&self.uri[a..b])
    }

    fn capture_scheme(&mut self) {
        let s = self.capture();
        self.rec.scheme = Some(if s.contains('{') { s } else { s.to_lowercase() });
    }

    fn capture_user(&mut self) {
        self.in_password = false;
        self.rec.user = Some(self.capture());
    }

    fn capture_host(&mut self) -> Result<(), ConnError> {
        if !(self.remaining_percent == 0 && !self.in_password) {
            return Err(bad("Bad authority"));
        }
        self.rec.host = Some(self.capture());
        Ok(())
    }

    fn capture_host_if_not_empty(&mut self) -> Result<(), ConnError> {
        if self.index > self.component_index {
            self.capture_host()?;
        }
        Ok(())
    }

    fn capture_port(&mut self) -> Result<(), ConnError> {
        if self.open_curly != 0 {
            return Err(bad("Bad authority"));
        }
        self.rec.port = Some(self.capture());
        Ok(())
    }

    fn capture_path(&mut self) {
        self.rec.path = Some(self.capture());
    }

    fn capture_query(&mut self) {
        self.rec.query = Some(self.capture());
    }

    fn capture_fragment_if_not_empty(&mut self) {
        if self.index > self.component_index + 1 {
            self.rec.fragment = Some(self.capture());
        }
    }

    fn mark_percent_encoding(&mut self) -> Result<(), ConnError> {
        if self.remaining_percent != 0 {
            return Err(bad("Bad encoding"));
        }
        self.remaining_percent = 2;
        self.in_utf16 = false;
        Ok(())
    }

    fn count_down_percent_in_host(&mut self, c: u16) -> Result<bool, ConnError> {
        if self.remaining_percent == 0 {
            return Ok(false);
        }
        self.remaining_percent -= 1;
        if !is_hex(c) {
            return Err(bad("Bad authority"));
        }
        Ok(true)
    }

    fn count_down_percent_in_path(&mut self, c: u16) -> Result<bool, ConnError> {
        if self.remaining_percent == 0 {
            return Ok(false);
        }
        if self.remaining_percent == 2 && c == b'u' as u16 && !self.in_utf16 {
            self.in_utf16 = true;
            self.remaining_percent = 4;
            return Ok(true);
        }
        self.remaining_percent -= 1;
        if !is_hex(c) {
            return Err(bad("Bad path"));
        }
        self.in_utf16 &= self.remaining_percent > 0;
        Ok(true)
    }

    fn process_curly(&mut self, c: u16) -> bool {
        if c == b'{' as u16 {
            self.open_curly += 1;
            return true;
        } else if c == b'}' as u16 {
            if self.open_curly > 0 {
                self.open_curly -= 1;
                return true;
            }
            return false;
        }
        self.open_curly > 0
    }

    fn resolve_if_opaque(&mut self) {
        let has_slash = !self.uri[(self.index + 1).min(self.uri.len() as i64) as usize..]
            .iter()
            .any(|c| *c == b'/' as u16);
        let hierarchical = matches!(self.rec.scheme.as_deref(), Some("ftp" | "file" | "http" | "https" | "ws" | "wss"));
        self.rec.is_opaque = has_slash && !hierarchical;
    }

    fn handle_next(&mut self, c: u16, i: i64) -> Result<(), ConnError> {
        let ch = |b: u8| b as u16;
        match self.state {
            State::Start => {
                if c == ch(b'/') {
                    self.advance_to_at(State::HostOrPath, i);
                } else if c == ch(b';') || c == ch(b'.') {
                    self.advance_to_at(State::Path, i);
                } else if c == ch(b'%') {
                    self.mark_percent_encoding()?;
                    self.advance_to_at(State::Path, i);
                } else if c == ch(b'?') {
                    self.advance_to_at(State::Query, i + 1);
                } else if c == ch(b'#') {
                    self.advance_to_at(State::Fragment, i + 1);
                } else if c == ch(b'*') {
                    self.advance_to(State::Wildcard);
                } else if self.rec.scheme.is_some() {
                    self.resolve_if_opaque();
                    self.advance_to_at(State::Path, i);
                } else {
                    self.advance_to_at(State::SchemeOrPath, i);
                }
            }
            State::HostOrPath => {
                if c == ch(b'/') {
                    self.component_index = i;
                    self.capture_host()?;
                    self.advance_to_at(State::Host, i + 1);
                } else if [b'%', b'@', b';', b'?', b'#', b'.'].iter().any(|b| c == ch(*b)) {
                    self.index = i - 1;
                    self.advance_to(State::Path);
                } else {
                    self.advance_to(State::Path);
                }
            }
            State::SchemeOrPath => {
                if c == ch(b':') {
                    self.capture_scheme();
                    self.advance_to(State::Start);
                } else if c == ch(b'/') || c == ch(b';') {
                    self.advance_to(State::Path);
                } else if c == ch(b'%') {
                    self.mark_percent_encoding()?;
                    self.advance_to(State::Path);
                } else if c == ch(b'?') {
                    self.capture_path();
                    self.advance_to_at(State::Query, i + 1);
                } else if c == ch(b'#') {
                    self.capture_path();
                    self.advance_to(State::Fragment);
                }
            }
            State::Host => {
                if c == ch(b'/') {
                    self.capture_host()?;
                    self.advance_to_at(State::Path, i);
                } else if c == ch(b':') {
                    self.capture_host_if_not_empty()?;
                    self.advance_to_at(State::Port, i + 1);
                } else if c == ch(b'?') {
                    self.capture_host_if_not_empty()?;
                    self.advance_to_at(State::Query, i + 1);
                } else if c == ch(b'#') {
                    self.capture_host_if_not_empty()?;
                    self.advance_to_at(State::Fragment, i + 1);
                } else if c == ch(b'@') {
                    self.capture_user();
                    self.component_index = i + 1;
                } else if c == ch(b'[') {
                    if self.index != self.component_index {
                        return Err(bad("Bad authority"));
                    }
                    self.advance_to(State::Ipv6);
                } else if c == ch(b'%') {
                    self.mark_percent_encoding()?;
                } else {
                    let allowed = self.process_curly(c)
                        || self.count_down_percent_in_host(c)?
                        || (c < 128 && is_unreserved_or_sub_delimiter(c as u8));
                    if !allowed {
                        return Err(bad("Bad authority"));
                    }
                }
            }
            State::Ipv6 => {
                if c == ch(b']') {
                    let i = i + 1;
                    self.index = i;
                    self.capture_host()?;
                    if self.has_next() {
                        if self.char_at_index() == ch(b':') {
                            self.advance_to_at(State::Port, i + 1);
                        } else {
                            self.advance_to_at(State::Path, i);
                        }
                    }
                } else if c == ch(b':') {
                } else if !is_hex(c) {
                    return Err(bad("Bad authority"));
                }
            }
            State::Port => {
                if c == ch(b'@') {
                    if self.rec.user.is_some() {
                        return Err(bad("Bad authority"));
                    }
                    // switchPortForFullPassword
                    let host = self.rec.host.clone().unwrap_or_else(|| "null".into());
                    self.rec.user = Some(format!("{host}:{}", self.capture()));
                    self.advance_to_at(State::Host, i + 1);
                } else if c == ch(b'/') {
                    self.capture_port()?;
                    self.advance_to_at(State::Path, i);
                } else if c == ch(b'?') || c == ch(b'#') {
                    self.capture_port()?;
                    self.advance_to_at(if c == ch(b'?') { State::Query } else { State::Fragment }, i + 1);
                } else if !java_is_digit(c) {
                    if self.process_curly(c) {
                        return Ok(());
                    } else if (c < 128 && is_unreserved_or_sub_delimiter(c as u8)) || c == ch(b'%') {
                        // switchPortForPassword
                        self.in_password = true;
                        if let Some(host) = self.rec.host.take() {
                            self.component_index = self.component_index - host.encode_utf16().count() as i64 - 1;
                        }
                        self.advance_to(State::Host);
                        return Ok(());
                    }
                    return Err(bad("Bad authority"));
                }
            }
            State::Path => {
                if !self.count_down_percent_in_path(c)? {
                    if c == ch(b'?') {
                        if !self.rec.is_opaque {
                            self.capture_path();
                            self.advance_to_at(State::Query, i + 1);
                        }
                    } else if c == ch(b'#') {
                        self.capture_path();
                        self.advance_to_at(State::Fragment, i + 1);
                    } else if c == ch(b'%') {
                        self.mark_percent_encoding()?;
                    }
                }
            }
            State::Query => {
                if c == ch(b'#') {
                    self.capture_query();
                    self.advance_to_at(State::Fragment, i + 1);
                }
            }
            State::Fragment => {}
            State::Wildcard => return Err(bad("Bad character '*'")),
        }
        Ok(())
    }

    fn handle_end(&mut self) -> Result<(), ConnError> {
        match self.state {
            State::Start | State::HostOrPath | State::SchemeOrPath | State::Path | State::Wildcard => self.capture_path(),
            State::Host => self.capture_host_if_not_empty()?,
            State::Ipv6 => {
                if self.rec.host.is_none() {
                    return Err(bad("Bad authority"));
                }
            }
            State::Port => self.capture_port()?,
            State::Query => self.capture_query(),
            State::Fragment => self.capture_fragment_if_not_empty(),
        }
        Ok(())
    }
}

/// `Character.isDigit(char)`: Unicode decimal digits, not only ASCII.
fn java_is_digit(c: u16) -> bool {
    char::from_u32(c as u32).is_some_and(|ch| ch.is_numeric() && ch.to_digit(10).is_some() || is_unicode_nd(ch))
}

fn is_unicode_nd(ch: char) -> bool {
    // The Nd blocks reachable from a BMP char beyond ASCII; enough for a port number check.
    let c = ch as u32;
    const RANGES: &[(u32, u32)] = &[
        (0x0660, 0x0669),
        (0x06F0, 0x06F9),
        (0x07C0, 0x07C9),
        (0x0966, 0x096F),
        (0x09E6, 0x09EF),
        (0x0A66, 0x0A6F),
        (0x0AE6, 0x0AEF),
        (0x0B66, 0x0B6F),
        (0x0BE6, 0x0BEF),
        (0x0C66, 0x0C6F),
        (0x0CE6, 0x0CEF),
        (0x0D66, 0x0D6F),
        (0x0E50, 0x0E59),
        (0x0ED0, 0x0ED9),
        (0x0F20, 0x0F29),
        (0x1040, 0x1049),
        (0x17E0, 0x17E9),
        (0x1810, 0x1819),
        (0xFF10, 0xFF19),
    ];
    RANGES.iter().any(|(a, b)| (*a..=*b).contains(&c))
}

// ---------------------------------------------------------------------------------------------
// UriComponentsBuilder

#[derive(Debug, Clone)]
enum PathBuilder {
    Full(String),
    Segments(Vec<String>),
}

#[derive(Debug, Clone, Default)]
struct Builder {
    scheme: Option<String>,
    ssp: Option<String>,
    user_info: Option<String>,
    host: Option<String>,
    port: Option<String>,
    path_builders: Vec<PathBuilder>,
    query_params: Vec<(String, Vec<Option<String>>)>,
    fragment: Option<String>,
    encode_template: bool,
}

/// `StringUtils.hasText`.
fn has_text(s: &str) -> bool {
    s.chars().any(|c| !java::is_whitespace(c))
}

impl Builder {
    fn from_uri_string(uri: &str) -> Result<Self, ConnError> {
        let mut b = Builder::default();
        if uri.is_empty() {
            return Ok(b);
        }
        let rec = RfcParser::parse(uri)?;
        b.scheme = rec.scheme.clone();
        if rec.is_opaque {
            if let Some(p) = rec.path {
                b.ssp = Some(p);
                b.reset_hierarchical();
            }
        } else {
            b.user_info = rec.user;
            b.ssp = None;
            b.host = rec.host.clone();
            b.port = rec.port.clone();
            if let Some(p) = rec.path {
                b.add_path(&p);
            }
            b.query(rec.query.as_deref());
        }
        b.fragment(rec.fragment);
        Ok(b)
    }

    fn reset_hierarchical(&mut self) {
        self.user_info = None;
        self.host = None;
        self.port = None;
        self.path_builders.clear();
        self.query_params.clear();
    }

    fn fragment(&mut self, f: Option<String>) {
        self.fragment = f;
    }

    fn add_path(&mut self, path: &str) {
        if !has_text(path) {
            return;
        }
        let mut path = path.to_string();
        let last_is_segments = matches!(self.path_builders.last(), Some(PathBuilder::Segments(_)));
        if last_is_segments && !path.starts_with('/') {
            path = format!("/{path}");
        }
        match self.path_builders.last_mut() {
            Some(PathBuilder::Full(s)) => s.push_str(&path),
            _ => self.path_builders.push(PathBuilder::Full(path)),
        }
        self.ssp = None;
    }

    fn path_segments(&mut self, segments: &[String]) {
        if segments.is_empty() {
            return;
        }
        if !matches!(self.path_builders.last(), Some(PathBuilder::Segments(_))) {
            if let Some(PathBuilder::Full(s)) = self.path_builders.last_mut() {
                if s.ends_with('/') {
                    s.pop();
                }
            }
            self.path_builders.push(PathBuilder::Segments(Vec::new()));
        }
        if let Some(PathBuilder::Segments(v)) = self.path_builders.last_mut() {
            v.extend(segments.iter().filter(|s| has_text(s)).cloned());
        }
        self.ssp = None;
    }

    fn replace_path(&mut self, path: Option<&str>) {
        self.path_builders.clear();
        if let Some(p) = path {
            self.add_path(p);
        }
        self.ssp = None;
    }

    /// `query(String)` with `QUERY_PARAM_PATTERN = ([^&=]+)(=?)([^&]+)?`.
    fn query(&mut self, query: Option<&str>) {
        let Some(q) = query else {
            self.query_params.clear();
            return;
        };
        let chars: Vec<char> = q.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            if chars[i] == '&' || chars[i] == '=' {
                i += 1;
                continue;
            }
            let start = i;
            while i < chars.len() && chars[i] != '&' && chars[i] != '=' {
                i += 1;
            }
            let name: String = chars[start..i].iter().collect();
            let mut eq = false;
            if i < chars.len() && chars[i] == '=' {
                eq = true;
                i += 1;
            }
            let vstart = i;
            while i < chars.len() && chars[i] != '&' {
                i += 1;
            }
            let value = if i > vstart {
                Some(chars[vstart..i].iter().collect::<String>())
            } else if eq {
                Some(String::new())
            } else {
                None
            };
            self.query_param(&name, value);
        }
        self.ssp = None;
    }

    fn query_param(&mut self, name: &str, value: Option<String>) {
        match self.query_params.iter_mut().find(|(k, _)| k == name) {
            Some((_, values)) => values.push(value),
            None => self.query_params.push((name.to_string(), vec![value])),
        }
        self.ssp = None;
    }

    fn build_path(&self) -> PathComponent {
        let mut comps: Vec<PathComponent> = Vec::new();
        for pb in &self.path_builders {
            match pb {
                PathBuilder::Full(s) => {
                    if !s.is_empty() {
                        comps.push(PathComponent::Full(sanitize_path(s)));
                    }
                }
                PathBuilder::Segments(v) => {
                    if !v.is_empty() {
                        comps.push(PathComponent::Segments(v.clone()));
                    }
                }
            }
        }
        match comps.len() {
            0 => PathComponent::Null,
            1 => comps.remove(0),
            _ => PathComponent::Composite(comps),
        }
    }

    /// `build()` (with `encodeTemplate` when set).
    fn build_components(&self, encode_template: bool) -> Components {
        if let Some(ssp) = &self.ssp {
            return Components::Opaque { scheme: self.scheme.clone(), ssp: ssp.clone(), fragment: self.fragment.clone() };
        }
        let h = Hier {
            scheme: self.scheme.clone(),
            fragment: self.fragment.clone(),
            user_info: self.user_info.clone(),
            host: self.host.clone(),
            port: self.port.clone(),
            path: self.build_path(),
            query_params: self.query_params.clone(),
            variable_encoder: false,
            encoded: false,
        };
        Components::Hier(if encode_template && self.encode_template { h.encode_template() } else { h })
    }
}

/// `FullPathComponentBuilder.getSanitizedPath`: every `//` collapsed to `/`.
fn sanitize_path(path: &str) -> String {
    let mut s: Vec<char> = path.chars().collect();
    let mut i = 0;
    while i + 1 < s.len() {
        if s[i] == '/' && s[i + 1] == '/' {
            s.remove(i);
        } else {
            i += 1;
        }
    }
    s.into_iter().collect()
}

// ---------------------------------------------------------------------------------------------
// HierarchicalUriComponents

#[derive(Debug, Clone)]
enum PathComponent {
    Null,
    Full(String),
    Segments(Vec<String>),
    Composite(Vec<PathComponent>),
}

impl PathComponent {
    fn get_path(&self) -> String {
        match self {
            PathComponent::Null => String::new(),
            PathComponent::Full(p) => p.clone(),
            PathComponent::Segments(v) => format!("/{}", v.join("/")),
            PathComponent::Composite(c) => c.iter().map(|p| p.get_path()).collect(),
        }
    }

    fn get_path_segments(&self) -> Vec<String> {
        match self {
            PathComponent::Null => Vec::new(),
            // StringUtils.tokenizeToStringArray(path, "/"): trimmed, empty tokens dropped.
            PathComponent::Full(p) => p
                .split('/')
                .map(|t| t.trim_matches(|c: char| java::is_whitespace(c)).to_string())
                .filter(|t| !t.is_empty())
                .collect(),
            PathComponent::Segments(v) => v.clone(),
            PathComponent::Composite(c) => c.iter().flat_map(|p| p.get_path_segments()).collect(),
        }
    }

    fn map(&self, f: &mut dyn FnMut(&str, Type) -> Result<String, ConnError>) -> Result<PathComponent, ConnError> {
        Ok(match self {
            PathComponent::Null => PathComponent::Null,
            PathComponent::Full(p) => PathComponent::Full(f(p, Type::Path)?),
            PathComponent::Segments(v) => {
                PathComponent::Segments(v.iter().map(|s| f(s, Type::PathSegment)).collect::<Result<_, _>>()?)
            }
            PathComponent::Composite(c) => PathComponent::Composite(c.iter().map(|p| p.map(f)).collect::<Result<_, _>>()?),
        })
    }
}

#[derive(Debug, Clone)]
struct Hier {
    scheme: Option<String>,
    fragment: Option<String>,
    user_info: Option<String>,
    host: Option<String>,
    port: Option<String>,
    path: PathComponent,
    query_params: Vec<(String, Vec<Option<String>>)>,
    /// `variableEncoder` is set (by `encodeTemplate`): expanded values are strictly encoded.
    variable_encoder: bool,
    encoded: bool,
}

#[derive(Debug, Clone)]
enum Components {
    Hier(Hier),
    Opaque { scheme: Option<String>, ssp: String, fragment: Option<String> },
}

impl Hier {
    fn host_type(&self) -> Type {
        if self.host.as_deref().is_some_and(|h| h.starts_with('[')) {
            Type::HostIpv6
        } else {
            Type::HostIpv4
        }
    }

    fn encode_template(&self) -> Hier {
        let mut enc = |s: &str, t: Type| -> Result<String, ConnError> { Ok(template_encode(s, t)) };
        Hier {
            scheme: self.scheme.as_deref().map(|s| template_encode(s, Type::Scheme)),
            fragment: self.fragment.as_deref().map(|s| template_encode(s, Type::Fragment)),
            user_info: self.user_info.as_deref().map(|s| template_encode(s, Type::UserInfo)),
            host: self.host.as_deref().map(|s| template_encode(s, self.host_type())),
            port: self.port.clone(),
            path: self.path.map(&mut enc).unwrap_or(PathComponent::Null),
            query_params: self
                .query_params
                .iter()
                .map(|(k, vs)| {
                    (
                        template_encode(k, Type::QueryParam),
                        vs.iter().map(|v| v.as_deref().map(|v| template_encode(v, Type::QueryParam))).collect(),
                    )
                })
                .collect(),
            variable_encoder: true,
            encoded: true,
        }
    }

    /// `encode(UTF_8)` after expansion (URI_COMPONENT mode).
    fn encode(&self) -> Hier {
        if self.encoded {
            return self.clone();
        }
        let mut enc = |s: &str, t: Type| -> Result<String, ConnError> { Ok(encode_uri_component(s, t)) };
        Hier {
            scheme: self.scheme.as_deref().map(|s| encode_uri_component(s, Type::Scheme)),
            fragment: self.fragment.as_deref().map(|s| encode_uri_component(s, Type::Fragment)),
            user_info: self.user_info.as_deref().map(|s| encode_uri_component(s, Type::UserInfo)),
            host: self.host.as_deref().map(|s| encode_uri_component(s, self.host_type())),
            port: self.port.clone(),
            path: self.path.map(&mut enc).unwrap_or(PathComponent::Null),
            query_params: self
                .query_params
                .iter()
                .map(|(k, vs)| {
                    (
                        encode_uri_component(k, Type::QueryParam),
                        vs.iter().map(|v| v.as_deref().map(|v| encode_uri_component(v, Type::QueryParam))).collect(),
                    )
                })
                .collect(),
            variable_encoder: false,
            encoded: true,
        }
    }

    fn get_query(&self) -> Option<String> {
        if self.query_params.is_empty() {
            return None;
        }
        let mut q = String::new();
        for (name, values) in &self.query_params {
            if values.is_empty() {
                if !q.is_empty() {
                    q.push('&');
                }
                q.push_str(name);
            } else {
                for v in values {
                    if !q.is_empty() {
                        q.push('&');
                    }
                    q.push_str(name);
                    if let Some(v) = v {
                        q.push('=');
                        q.push_str(v);
                    }
                }
            }
        }
        Some(q)
    }

    fn to_uri_string(&self) -> String {
        let mut out = String::new();
        if let Some(s) = &self.scheme {
            out.push_str(s);
            out.push(':');
        }
        if self.user_info.is_some() || self.host.is_some() {
            out.push_str("//");
            if let Some(u) = &self.user_info {
                out.push_str(u);
                out.push('@');
            }
            if let Some(h) = &self.host {
                out.push_str(h);
            }
            if let Some(p) = &self.port {
                if has_text(p) && p != "-1" {
                    out.push(':');
                    out.push_str(p);
                }
            }
        }
        let path = self.path.get_path();
        if !path.is_empty() {
            if !out.is_empty() && !path.starts_with('/') {
                out.push('/');
            }
            out.push_str(&path);
        }
        if let Some(q) = self.get_query() {
            out.push('?');
            out.push_str(&q);
        }
        if let Some(f) = &self.fragment {
            out.push('#');
            out.push_str(f);
        }
        out
    }
}

impl Components {
    fn expand(&self, vars: &HashMap<String, String>) -> Result<Components, ConnError> {
        match self {
            Components::Opaque { scheme, ssp, fragment } => Ok(Components::Opaque {
                scheme: expand_component(scheme.as_deref(), vars, false)?,
                ssp: expand_component(Some(ssp), vars, false)?.unwrap_or_default(),
                fragment: expand_component(fragment.as_deref(), vars, false)?,
            }),
            Components::Hier(h) => {
                let enc = h.variable_encoder;
                let scheme = expand_component(h.scheme.as_deref(), vars, enc)?;
                let user_info = expand_component(h.user_info.as_deref(), vars, enc)?;
                let host = expand_component(h.host.as_deref(), vars, enc)?;
                let port = expand_component(h.port.as_deref(), vars, enc)?;
                let mut ex = |s: &str, _t: Type| -> Result<String, ConnError> {
                    Ok(expand_component(Some(s), vars, enc)?.unwrap_or_default())
                };
                let path = h.path.map(&mut ex)?;
                let mut query_params = Vec::new();
                for (k, vs) in &h.query_params {
                    let name = expand_component(Some(k), vars, enc)?.unwrap_or_default();
                    let mut values = Vec::new();
                    for v in vs {
                        values.push(expand_component(v.as_deref(), vars, enc)?);
                    }
                    // result.put(name, values): a later key expanding to the same name
                    // replaces the earlier list in place.
                    match query_params.iter_mut().find(|(n, _): &&mut (String, Vec<Option<String>>)| *n == name) {
                        Some((_, existing)) => *existing = values,
                        None => query_params.push((name, values)),
                    }
                }
                let fragment = expand_component(h.fragment.as_deref(), vars, enc)?;
                Ok(Components::Hier(Hier {
                    scheme,
                    fragment,
                    user_info,
                    host,
                    port,
                    path,
                    query_params,
                    variable_encoder: h.variable_encoder,
                    encoded: h.encoded,
                }))
            }
        }
    }

    fn encode(self) -> Components {
        match self {
            Components::Hier(h) => Components::Hier(h.encode()),
            other => other,
        }
    }

    fn to_uri_string(&self) -> String {
        match self {
            Components::Hier(h) => h.to_uri_string(),
            Components::Opaque { scheme, ssp, fragment } => {
                let mut out = String::new();
                if let Some(s) = scheme {
                    out.push_str(s);
                    out.push(':');
                }
                out.push_str(ssp);
                if let Some(f) = fragment {
                    out.push('#');
                    out.push_str(f);
                }
                out
            }
        }
    }
}

/// `UriTemplateEncoder.apply`: literal parts encoded for the component, `{variables}` kept.
fn template_encode(source: &str, t: Type) -> String {
    if is_uri_variable(source) {
        return source.to_string();
    }
    if !source.contains('{') {
        return encode_uri_component(source, t);
    }
    let mut level = 0;
    let mut literal = String::new();
    let mut variable = String::new();
    let mut output = String::new();
    let mut with_name_and_regex = false;
    for c in source.chars() {
        if c == ':' && level == 1 {
            with_name_and_regex = true;
        }
        if c == '{' {
            level += 1;
            if level == 1 {
                output.push_str(&encode_uri_component(&literal, t));
                literal.clear();
                with_name_and_regex = false;
            }
        }
        if c == '}' && level > 0 {
            level -= 1;
            variable.push('}');
            if level == 0 {
                let encode = !is_uri_variable(&variable);
                output.push_str(&if encode { encode_uri_component(&variable, t) } else { variable.clone() });
                variable.clear();
                with_name_and_regex = false;
            } else if !with_name_and_regex {
                output.push_str(&encode_uri_component(&variable, t));
                variable.clear();
                with_name_and_regex = false;
                level = 0;
            }
        } else if level > 0 {
            variable.push(c);
        } else {
            literal.push(c);
        }
    }
    if level > 0 {
        literal.push_str(&variable);
    }
    output.push_str(&encode_uri_component(&literal, t));
    output
}

fn is_uri_variable(source: &str) -> bool {
    let chars: Vec<char> = source.chars().collect();
    if chars.len() < 2 || chars[0] != '{' || chars[chars.len() - 1] != '}' {
        return false;
    }
    let mut has_text = false;
    for (i, c) in chars.iter().enumerate().take(chars.len() - 1).skip(1) {
        if *c == ':' && i > 1 {
            return true;
        }
        if *c == '{' || *c == '}' {
            return false;
        }
        has_text = has_text || !java::is_whitespace(*c);
    }
    has_text
}

/// `UriComponents.expandUriComponent` with a `MapTemplateVariables`.
fn expand_component(source: Option<&str>, vars: &HashMap<String, String>, encode: bool) -> Result<Option<String>, ConnError> {
    let Some(source) = source else { return Ok(None) };
    if !source.contains('{') {
        return Ok(Some(source.to_string()));
    }
    let source = if source.contains(':') { sanitize_source(source) } else { source.to_string() };
    let chars: Vec<char> = source.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    let mut last = 0;
    while i < chars.len() {
        if chars[i] != '{' {
            i += 1;
            continue;
        }
        // \{([^/]+?)\}: the shortest group of at least one non-'/' char followed by '}'.
        let mut k = i + 2;
        let mut found = None;
        while k < chars.len() {
            if chars[k - 1] == '/' {
                break;
            }
            if chars[k] == '}' {
                found = Some(k);
                break;
            }
            k += 1;
        }
        match found {
            Some(end) => {
                let group: String = chars[i + 1..end].iter().collect();
                let name = match group.find(':') {
                    Some(c) => group[..c].to_string(),
                    None => group.clone(),
                };
                let Some(value) = vars.get(&name) else {
                    return Err(ConnError::other(format!("Map has no value for '{name}'")));
                };
                out.extend(chars[last..i].iter());
                out.push_str(&if encode { encode_uri_component(value, Type::Uri) } else { value.clone() });
                i = end + 1;
                last = i;
            }
            None => i += 1,
        }
    }
    out.extend(chars[last..].iter());
    Ok(Some(out))
}

fn sanitize_source(source: &str) -> String {
    let mut level = 0;
    let mut out = String::new();
    for c in source.chars() {
        if c == '{' {
            level += 1;
        }
        if c == '}' {
            level -= 1;
        }
        if level > 1 || (level == 1 && c == '}') {
            continue;
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(url: &str, mode: WebClientEncodingMode, q: &[(&str, &str)], p: &[(&str, &str)]) -> String {
        let q: Vec<(String, String)> = q.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect();
        let p: HashMap<String, String> = p.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect();
        match build_request_uri(url, mode, &q, &p) {
            Ok(s) => s,
            Err(e) => format!("ERR {}", e.message()),
        }
    }

    use WebClientEncodingMode::*;

    #[test]
    fn template_and_values() {
        assert_eq!(
            build("https://api.example.com/v1/users/{id}", TemplateAndValues, &[("q", "a b&c")], &[("id", "x/y z")]),
            "https://api.example.com/v1/users/x%2Fy%20z?q=a%20b%26c"
        );
        assert_eq!(build("https://h.com/a/{id}", TemplateAndValues, &[], &[]), "ERR Map has no value for 'id'");
        assert_eq!(build("https://h.com//a//b", TemplateAndValues, &[], &[]), "https://h.com/a/b");
    }

    #[test]
    fn other_modes() {
        assert_eq!(build("https://h.com/a", ManualValuesEncoded, &[("q", "a b+c")], &[]), "https://h.com/a?q=a+b%2Bc");
        assert_eq!(build("https://h.com/{id}", ValuesOnly, &[], &[("id", "a b")]), "https://h.com/a%20b");
        assert_eq!(build("https://h.com/{id}/x", UriComponent, &[("q", "a b")], &[("id", "a/b")]), "https://h.com/a%2Fb/x?q=a%20b");
        assert!(build("https://h.com/a", None, &[("q", "a b")], &[]).starts_with("ERR Illegal character in query at index"));
    }

    #[test]
    fn to_uri_quotes_each_component() {
        let q = |a: &str, b: &str| (a.to_string(), b.to_string());
        assert_eq!(
            build_to_uri("https://www.facebook.com/v21.0/dialog/oauth", &[q("scope", "a b,c"), q("redirect_uri", "https://x.com/cb?y=1"), q("p", "50%")]).unwrap(),
            "https://www.facebook.com/v21.0/dialog/oauth?scope=a%20b,c&redirect_uri=https://x.com/cb?y=1&p=50%25"
        );
        assert_eq!(build_to_uri_string("https://app.com/page", &[q("META_API", "success")]).unwrap(), "https://app.com/page?META_API=success");
    }

    #[test]
    fn parser_errors() {
        assert_eq!(build("https://h^st.com/", TemplateAndValues, &[], &[]), "ERR Bad authority");
        assert_eq!(build("https://h.com/%zz", TemplateAndValues, &[], &[]), "ERR Bad path");
    }
}
