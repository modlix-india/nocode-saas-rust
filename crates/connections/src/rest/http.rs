//! The HTTP exchange a REST connection makes, as Reactor Netty (WebClient's default client)
//! makes it: HTTP/1.1, no redirects followed, no proxy, gzip asked for and gzip or deflate
//! decoded, a 30 second connect timeout, and the response headers as the server sent them,
//! original case and order included (`toSingleValueMap()` of Netty's headers is what a KIRun
//! step reads).
//!
//! hyper parses the response but folds header names to lower case, so the connection's reads
//! are tapped and the names are taken from the raw response head.
//!
//! Every connection is resolved here, and with private targets blocked an address that is not
//! public is never connected to: the guard's DNS answer and the connection's cannot differ.

use std::io::{self, Read as _};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderName, HeaderValue, Method, Request};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::error::{ConnError, ConnResult};
use crate::java::inet::JavaInet;
use crate::outbound;

/// What Reactor Netty sends as its user agent (spring-boot 3.4.1's reactor-netty 1.2.1), kept
/// so the services on the other end see the same client they see today.
pub const USER_AGENT: &str = "ReactorNetty/1.2.1";

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const HEAD_CAPTURE_LIMIT: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct HttpClient {
    /// `core.rest.blockPrivateTargets`: refuse to connect to anything that is not public.
    pub block_private_targets: bool,
}

#[derive(Debug, Clone)]
pub struct OutboundRequest {
    pub method: String,
    /// The absolute URI string WebClient would send.
    pub uri: String,
    /// Header lines in order, repeated names allowed.
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct OutboundResponse {
    pub status: u16,
    /// Header lines as received (original case, wire order, repeats kept), adjusted as
    /// Netty's decompressor adjusts them for a gzip or deflate body.
    pub headers: Vec<(String, String)>,
    pub body: hyper::body::Incoming,
    /// The content coding the body arrived in, when it is one the client undoes.
    decode: Option<Coding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Coding {
    Gzip,
    Deflate,
}

impl OutboundResponse {
    /// First value of a header, matched case-insensitively (`HttpHeaders.getFirst`).
    pub fn first(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// `toSingleValueMap()`: each name with its first value. Netty's headers are
    /// case-insensitive, so a name repeated in another case folds into the first spelling.
    pub fn single_value_map(&self) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = Vec::new();
        for (k, v) in &self.headers {
            if !out.iter().any(|(e, _)| e.eq_ignore_ascii_case(k)) {
                out.push((k.clone(), v.clone()));
            }
        }
        out
    }

    /// Reads (and decompresses) the body, failing as WebClient's in-memory limit does.
    pub async fn read_body(self, limit: usize) -> ConnResult<Vec<u8>> {
        let mut body = self.body;
        let mut out = Vec::new();
        let too_big = || ConnError::other(format!("Exceeded limit on max bytes to buffer : {limit}"));
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|e| ConnError::other(e.to_string()))?;
            if let Ok(data) = frame.into_data() {
                if out.len() + data.len() > limit {
                    return Err(too_big());
                }
                out.extend_from_slice(&data);
            }
        }
        let Some(coding) = self.decode else { return Ok(out) };
        if out.is_empty() {
            return Ok(out);
        }
        let mut decoded = Vec::new();
        let read = match coding {
            Coding::Gzip => {
                let mut d = flate2::read::MultiGzDecoder::new(&out[..]).take(limit as u64 + 1);
                d.read_to_end(&mut decoded)
            }
            Coding::Deflate => {
                let mut d = flate2::read::ZlibDecoder::new(&out[..]).take(limit as u64 + 1);
                match d.read_to_end(&mut decoded) {
                    Ok(n) => Ok(n),
                    Err(_) => {
                        // Netty accepts raw deflate as well as zlib-wrapped.
                        decoded.clear();
                        let mut raw = flate2::read::DeflateDecoder::new(&out[..]).take(limit as u64 + 1);
                        raw.read_to_end(&mut decoded)
                    }
                }
            }
        };
        read.map_err(|e| ConnError::other(e.to_string()))?;
        if decoded.len() > limit {
            return Err(too_big());
        }
        Ok(decoded)
    }
}

impl HttpClient {
    pub async fn send(&self, req: OutboundRequest) -> ConnResult<OutboundResponse> {
        let url = reqwest::Url::parse(&req.uri).map_err(|e| ConnError::other(format!("{e}: {}", req.uri)))?;
        let scheme = url.scheme().to_string();
        let https = match scheme.as_str() {
            "http" => false,
            "https" => true,
            other => return Err(ConnError::other(format!("Unsupported scheme '{other}' in {}", req.uri))),
        };
        let host = match url.host() {
            Some(url::Host::Domain(d)) => d.to_string(),
            Some(url::Host::Ipv4(a)) => a.to_string(),
            Some(url::Host::Ipv6(a)) => a.to_string(),
            None => return Err(ConnError::other(format!("Host is not specified: {}", req.uri))),
        };
        let port = url.port_or_known_default().unwrap_or(if https { 443 } else { 80 });

        let addrs = self.resolve(&req.uri, &url, &host, port).await?;
        let tcp = connect_any(&host, port, &addrs).await?;
        let _ = tcp.set_nodelay(true);

        let captured = Arc::new(Mutex::new(Vec::<u8>::new()));
        let path_and_query = raw_path_and_query(&req.uri);

        let request = build_request(&req, &url, &host, &path_and_query)?;

        let response = if https {
            let tls = tls_connect(&host, tcp).await?;
            exchange(Tap::new(tls, captured.clone()), request).await?
        } else {
            exchange(Tap::new(tcp, captured.clone()), request).await?
        };

        let status = response.status().as_u16();
        let mut headers = original_headers(&captured.lock(), status).unwrap_or_else(|| {
            response
                .headers()
                .iter()
                .map(|(k, v)| (k.as_str().to_string(), latin1(v.as_bytes())))
                .collect()
        });
        let decode = undo_content_coding(&mut headers);
        Ok(OutboundResponse { status, headers, body: response.into_body(), decode })
    }

    async fn resolve(&self, uri: &str, url: &reqwest::Url, host: &str, port: u16) -> ConnResult<Vec<SocketAddr>> {
        let addrs: Vec<SocketAddr> = match url.host() {
            Some(url::Host::Ipv4(a)) => vec![SocketAddr::new(a.into(), port)],
            Some(url::Host::Ipv6(a)) => vec![SocketAddr::new(a.into(), port)],
            _ => outbound::lookup(host)
                .await
                .map_err(|_| ConnError::other(format!("Failed to resolve '{host}'")))?
                .into_iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect(),
        };
        if addrs.is_empty() {
            return Err(ConnError::other(format!("Failed to resolve '{host}'")));
        }
        if !self.block_private_targets {
            return Ok(addrs);
        }
        let public: Vec<SocketAddr> = addrs
            .iter()
            .copied()
            .filter(|a| !outbound::is_private_address(&outbound::canonical(JavaInet::from_ip(a.ip()))))
            .collect();
        if public.len() != addrs.len() {
            // An answer the guard did not see (rebinding between the check and the connect).
            let private = addrs.iter().find(|a| !public.contains(a)).map(|a| a.ip().to_string()).unwrap_or_default();
            return Err(ConnError::coded(
                http::StatusCode::BAD_REQUEST,
                "CORE.PRIVATE_TARGET_REFUSED",
                format!(
                    "Refusing to call \"{uri}\": '{host}' resolves to {private}, which is a private or internal address. Only addresses reachable from the public internet can be called."
                ),
            )
            .param("url", uri.to_string())
            .param("reason", format!("'{host}' resolves to {private}, which is a private or internal address")));
        }
        Ok(public)
    }
}

/// What a JSON body is decoded into: `bodyToMono(Map)` or `bodyToMono(JsonNode)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonTarget {
    Map,
    JsonNode,
}

impl JsonTarget {
    fn java_type(&self) -> &'static str {
        match self {
            JsonTarget::Map => "java.util.Map<java.lang.String, java.lang.Object>",
            JsonTarget::JsonNode => "com.fasterxml.jackson.databind.JsonNode",
        }
    }
}

/// `webClient.method(m).uri(uri).retrieve().bodyToMono(target)`: a 4xx/5xx is an error, the
/// body must be JSON (Jackson's decoder), and an empty body is no value.
pub async fn retrieve_json(client: &HttpClient, method: &str, uri: &str, target: JsonTarget) -> ConnResult<Option<serde_json::Value>> {
    let headers = Vec::new();
    let body = if method == "POST" { Some(Vec::new()) } else { None };
    let response = client.send(OutboundRequest { method: method.into(), uri: uri.into(), headers, body }).await?;
    let status = response.status;
    if status >= 400 {
        let reason = http::StatusCode::from_u16(status).ok().and_then(|s| s.canonical_reason()).unwrap_or("");
        return Err(ConnError::other(format!("{status} {reason} from {method} {uri}")));
    }
    let content_type = response.first("Content-Type").map(str::to_string);
    let bytes = response.read_body(256 * 1024).await?;
    if bytes.is_empty() {
        return Ok(None);
    }
    let ct = content_type.as_deref().map(crate::rest::media_type::MediaType::parse).transpose()?;
    let json_ok = ct.as_ref().is_some_and(|ct| crate::rest::media_type::jackson_can_encode(Some(ct)));
    if !json_ok {
        let shown = content_type.unwrap_or_else(|| "application/octet-stream".into());
        return Err(ConnError::other(format!("Content type '{shown}' not supported for bodyType={}", target.java_type())));
    }
    let v: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| ConnError::other(format!("JSON decoding error: {e}")))?;
    if target == JsonTarget::Map && !v.is_object() {
        return Err(ConnError::other(format!(
            "JSON decoding error: Cannot deserialize value of type `java.util.LinkedHashMap<java.lang.String,java.lang.Object>` from {}",
            match v { serde_json::Value::Array(_) => "Array value", serde_json::Value::String(_) => "String value", _ => "value" }
        )));
    }
    Ok(Some(v))
}

/// The request target exactly as the URI string has it (WebClient sends the URI's raw path
/// and query, without normalising dot segments), with non-ASCII characters UTF-8 encoded.
fn raw_path_and_query(uri: &str) -> String {
    let after_scheme = match uri.find("://") {
        Some(i) => &uri[i + 3..],
        None => uri,
    };
    let rest = match after_scheme.find(['/', '?', '#']) {
        Some(i) => &after_scheme[i..],
        None => "",
    };
    let rest = match rest.find('#') {
        Some(i) => &rest[..i],
        None => rest,
    };
    let mut target = String::with_capacity(rest.len() + 1);
    if !rest.starts_with('/') {
        target.push('/');
    }
    for ch in rest.chars() {
        if ch.is_ascii() {
            target.push(ch);
        } else {
            let mut buf = [0u8; 4];
            for b in ch.encode_utf8(&mut buf).bytes() {
                target.push_str(&format!("%{b:02X}"));
            }
        }
    }
    target
}

/// Reactor Netty asks for gzip and decompresses: a gzip or deflate body is decoded, and the
/// headers then read as Netty leaves them (no `Content-Encoding`, no `Content-Length`,
/// `transfer-encoding: chunked`).
fn undo_content_coding(headers: &mut Vec<(String, String)>) -> Option<Coding> {
    let coding = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-encoding"))
        .map(|(_, v)| v.trim().to_ascii_lowercase())?;
    let decode = match coding.as_str() {
        "gzip" | "x-gzip" => Coding::Gzip,
        "deflate" | "x-deflate" => Coding::Deflate,
        _ => return None,
    };
    headers.retain(|(k, _)| !k.eq_ignore_ascii_case("content-encoding") && !k.eq_ignore_ascii_case("content-length"));
    headers.retain(|(k, _)| !k.eq_ignore_ascii_case("transfer-encoding"));
    headers.push(("transfer-encoding".into(), "chunked".into()));
    Some(decode)
}

async fn connect_any(host: &str, port: u16, addrs: &[SocketAddr]) -> ConnResult<TcpStream> {
    let mut last: Option<io::Error> = None;
    for a in addrs {
        match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(a)).await {
            Ok(Ok(s)) => return Ok(s),
            Ok(Err(e)) => last = Some(e),
            Err(_) => {
                return Err(ConnError::other(format!(
                    "connection timed out after {} ms: {host}/{}:{port}",
                    CONNECT_TIMEOUT.as_millis(),
                    a.ip()
                )))
            }
        }
    }
    let e = last.unwrap_or_else(|| io::Error::other("no address"));
    let ip = addrs.first().map(|a| a.ip().to_string()).unwrap_or_default();
    // `InetSocketAddress.toString()`: `host/ip:port`, with no host part for an address literal.
    let shown_host = if host.parse::<std::net::IpAddr>().is_ok() { "" } else { host };
    Err(ConnError::other(match e.kind() {
        io::ErrorKind::ConnectionRefused => format!("Connection refused: {shown_host}/{ip}:{port}"),
        _ => format!("{e}: {shown_host}/{ip}:{port}"),
    }))
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
            let builder = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions();
            let mut config = match builder {
                Ok(b) => b.with_root_certificates(roots).with_no_client_auth(),
                // The ring provider always supports the default versions.
                Err(_) => rustls::ClientConfig::builder()
                    .with_root_certificates(rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() })
                    .with_no_client_auth(),
            };
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            Arc::new(config)
        })
        .clone()
}

async fn tls_connect(host: &str, tcp: TcpStream) -> ConnResult<tokio_rustls::client::TlsStream<TcpStream>> {
    let name = rustls::pki_types::ServerName::try_from(host.trim_start_matches('[').trim_end_matches(']').to_string())
        .map_err(|e| ConnError::other(format!("Invalid host name {host}: {e}")))?;
    let connector = tokio_rustls::TlsConnector::from(tls_config());
    // Reactor Netty's default handshake timeout.
    match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, connector.connect(name, tcp)).await {
        Ok(r) => r.map_err(|e| ConnError::other(e.to_string())),
        Err(_) => Err(ConnError::other(format!("handshake timed out after {}ms", TLS_HANDSHAKE_TIMEOUT.as_millis()))),
    }
}

/// The request as Reactor Netty writes it: its defaults first (`accept-encoding: gzip`,
/// `user-agent`, `host`, `accept`), then the request's headers, then the framing
/// (`content-length`, `0` when there is no body; chunked for multipart).
fn build_request(req: &OutboundRequest, url: &reqwest::Url, host: &str, path_and_query: &str) -> ConnResult<Request<Full<Bytes>>> {
    let method = Method::from_bytes(req.method.as_bytes())
        .map_err(|_| ConnError::other(format!("Invalid HTTP method: {}", req.method)))?;
    let mut builder = Request::builder().method(method).uri(path_and_query);
    let headers = builder.headers_mut().ok_or_else(|| ConnError::other("Invalid request"))?;
    let given = |name: &str| req.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(name));

    if !given("accept-encoding") {
        headers.insert(http::header::ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
    }
    if !given("user-agent") {
        headers.insert(http::header::USER_AGENT, HeaderValue::from_static(USER_AGENT));
    }
    if !given("host") {
        let host_header = match url.port() {
            Some(p) => format!("{}:{p}", url.host_str().unwrap_or(host)),
            None => url.host_str().unwrap_or(host).to_string(),
        };
        let value = HeaderValue::from_str(&host_header).map_err(|_| ConnError::other("Invalid host"))?;
        headers.insert(http::header::HOST, value);
    }
    if !given("accept") {
        headers.insert(http::header::ACCEPT, HeaderValue::from_static("*/*"));
    }
    let multipart = req.headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("content-type") && v.trim_start().to_ascii_lowercase().starts_with("multipart/")
    });
    for (k, v) in &req.headers {
        if multipart && k.eq_ignore_ascii_case("content-type") {
            headers.insert(http::header::TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        }
        let name = HeaderName::from_bytes(k.as_bytes()).map_err(|_| ConnError::other(format!("Invalid header name: {k}")))?;
        let value = HeaderValue::from_str(v).map_err(|_| ConnError::other(format!("Invalid header value for {k}")))?;
        headers.append(name, value);
    }
    if !multipart && !given("content-length") && !given("transfer-encoding") {
        let len = req.body.as_ref().map(Vec::len).unwrap_or(0);
        headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from(len));
    }
    let body = Full::new(Bytes::from(req.body.clone().unwrap_or_default()));
    builder.body(body).map_err(|e| ConnError::other(e.to_string()))
}

async fn exchange<S>(io: Tap<S>, request: Request<Full<Bytes>>) -> ConnResult<http::Response<hyper::body::Incoming>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
        .handshake(TokioIo::new(io))
        .await
        .map_err(|e| ConnError::other(e.to_string()))?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!(error = %e, "outbound connection closed with an error");
        }
    });
    sender.send_request(request).await.map_err(|e| ConnError::other(e.to_string()))
}

/// The header lines of the final (non-1xx) response head in the captured bytes.
fn original_headers(raw: &[u8], status: u16) -> Option<Vec<(String, String)>> {
    let mut rest = raw;
    loop {
        let end = find(rest, b"\r\n\r\n")?;
        let head = &rest[..end];
        rest = &rest[end + 4..];
        let mut lines = head.split(|b| *b == b'\n').map(|l| l.strip_suffix(b"\r").unwrap_or(l));
        let status_line = lines.next()?;
        let code: u16 = std::str::from_utf8(status_line).ok()?.split_whitespace().nth(1)?.parse().ok()?;
        if (100..200).contains(&code) && code != 101 && code != status {
            continue;
        }
        let mut out = Vec::new();
        for line in lines {
            let colon = line.iter().position(|b| *b == b':')?;
            let name = latin1(&line[..colon]);
            let value = latin1(&line[colon + 1..]);
            out.push((name.trim().to_string(), value.trim_matches(|c| c == ' ' || c == '\t').to_string()));
        }
        return Some(out);
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Netty reads header bytes as ISO-8859-1.
fn latin1(b: &[u8]) -> String {
    b.iter().map(|c| *c as char).collect()
}

/// Records the first bytes read from a connection, which hold the raw response head.
struct Tap<S> {
    inner: S,
    captured: Arc<Mutex<Vec<u8>>>,
}

impl<S> Tap<S> {
    fn new(inner: S, captured: Arc<Mutex<Vec<u8>>>) -> Self {
        Self { inner, captured }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Tap<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &res {
            let new = &buf.filled()[before..];
            let mut c = self.captured.lock();
            if c.len() < HEAD_CAPTURE_LIMIT {
                let take = new.len().min(HEAD_CAPTURE_LIMIT - c.len());
                c.extend_from_slice(&new[..take]);
            }
        }
        res
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Tap<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_targets() {
        assert_eq!(raw_path_and_query("https://h.com/a/../b?x=1#f"), "/a/../b?x=1");
        assert_eq!(raw_path_and_query("https://h.com?x"), "/?x");
        assert_eq!(raw_path_and_query("https://h.com"), "/");
        assert_eq!(raw_path_and_query("http://h.com/caf\u{e9}"), "/caf%C3%A9");
    }

    #[test]
    fn gzip_headers_as_netty_leaves_them() {
        let mut h = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Content-Encoding".to_string(), "gzip".to_string()),
            ("Content-Length".to_string(), "20".to_string()),
        ];
        assert_eq!(undo_content_coding(&mut h), Some(Coding::Gzip));
        assert_eq!(h, vec![("Content-Type".to_string(), "application/json".to_string()), ("transfer-encoding".to_string(), "chunked".to_string())]);
    }

    #[test]
    fn original_case_of_the_final_head() {
        let raw = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Total-Count:  3\r\nset-cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n{\"a\":1}";
        let h = original_headers(raw, 200).unwrap();
        assert_eq!(
            h,
            vec![
                ("Content-Type".into(), "application/json".into()),
                ("X-Total-Count".into(), "3".into()),
                ("set-cookie".into(), "a=1".into()),
                ("Set-Cookie".into(), "b=2".into()),
            ]
        );
    }
}
