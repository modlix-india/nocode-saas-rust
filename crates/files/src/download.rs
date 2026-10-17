//! `makeMatchesStartDownload`, `sendFile` and `RangeDownloadUtil.serveResource`: everything
//! between "this file may be read" and the bytes on the wire.

use std::io::SeekFrom;
use std::path::PathBuf;

use axum::body::{Body, Bytes};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::Response;
use chrono::{DateTime, Duration, Utc};
use futures::stream::{self, StreamExt};
use platform::error::{AppError, AppResult};
use platform::http::{not_modified, spring_security_headers};
use platform::java::string_hash_code;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_util::io::ReaderStream;

use crate::dao::FileDetail;
use crate::image_ops;
use crate::options::DownloadOptions;
use crate::paths::{download_name, Kind};
use crate::state::AppState;

const BOUNDARY: &str = "MULTIPART_BYTERANGES";
/// `RangeDownloadUtil`'s response buffer. A body larger than this commits the response while
/// it is being written, and only then does Spring Security get to add its headers; a body that
/// fits is sent without them. Reproduced, because those headers decide whether a file may be
/// framed by another origin.
const SERVLET_BUFFER: u64 = 20 * 1024;
const CHUNK: usize = 64 * 1024;

/// `"<name.hashCode()>-<lastModified>-<options hash>"`, quotes included.
pub fn etag(detail: &FileDetail, options: &DownloadOptions) -> String {
    format!(
        "\"{}-{}-{}\"",
        string_hash_code(&detail.name),
        detail.last_modified,
        options.etag_code()
    )
}

fn http_date(t: DateTime<Utc>) -> String {
    t.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

fn header_str<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

/// `ifModifiedSinceSeconds`: the header as epoch seconds, if it is a readable HTTP date.
fn if_modified_since(h: &HeaderMap) -> Option<i64> {
    let v = header_str(h, "if-modified-since")?;
    DateTime::parse_from_rfc2822(v.trim())
        .ok()
        .map(|d| d.timestamp())
}

/// The whole download decision: 304, or the file (possibly transformed, possibly a range).
pub async fn respond(
    state: &AppState,
    kind: Kind,
    path: &str,
    detail: &FileDetail,
    options: &DownloadOptions,
    req: &HeaderMap,
) -> AppResult<Response> {
    let tag = etag(detail, options);

    if !options.no_cache {
        if if_modified_since(req) == Some(detail.last_modified) {
            return Ok(not_modified());
        }
        // Java reads a request `ETag` header first, then the first `If-None-Match`.
        let sent = header_str(req, "etag").or_else(|| header_str(req, "if-none-match"));
        if sent == Some(tag.as_str()) {
            return Ok(not_modified());
        }
    }

    send_file(state, kind, path, detail, options, &tag, req).await
}

async fn send_file(
    state: &AppState,
    kind: Kind,
    path: &str,
    detail: &FileDetail,
    options: &DownloadOptions,
    tag: &str,
    req: &HeaderMap,
) -> AppResult<Response> {
    let file_name = download_name(path);
    let shown_name = options.name.clone().unwrap_or_else(|| file_name.clone());

    let mut h = HeaderMap::new();
    h.insert(HeaderName::from_static("x-cache"), HeaderValue::from_static("MISS"));
    let last_modified = DateTime::<Utc>::from_timestamp(detail.last_modified, 0).unwrap_or_default();
    h.insert(header::LAST_MODIFIED, HeaderValue::from_str(&http_date(last_modified)).unwrap());
    h.insert(
        header::ETAG,
        HeaderValue::from_str(tag).map_err(|e| anyhow::anyhow!("etag header: {e}"))?,
    );
    if !options.no_cache && kind == Kind::Static {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=3600"));
    }
    h.insert(header::CONTENT_DISPOSITION, content_disposition(options.download, &shown_name));
    let mime = mime_guess::from_path(&file_name)
        .first_raw()
        .unwrap_or("application/octet-stream");
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(mime));

    let store = state.store(kind);
    let local = store
        .get_as_file(path, detail.last_modified, options.no_cache)
        .await
        .map_err(AppError::Internal)?;

    if options.has_no_modification() {
        let len = tokio::fs::metadata(&local).await.map_err(anyhow::Error::from)?.len();
        return serve_ranges(h, req, Source::File(local), len, mime).await;
    }

    let bytes = tokio::fs::read(&local).await.map_err(anyhow::Error::from)?;
    let opts = options.clone();
    let name = file_name.clone();
    let out = tokio::task::spawn_blocking(move || image_ops::transform(&opts, &name, &bytes))
        .await
        .map_err(anyhow::Error::from)?;
    let len = out.len() as u64;
    serve_ranges(h, req, Source::Memory(Bytes::from(out)), len, mime).await
}

/// `ContentDisposition.inline()/attachment().filename(name)`: quoted, with `"` and `\` escaped.
/// For a name outside ASCII, an RFC 5987 `filename*` is added; Tomcat instead writes such a
/// name as Latin-1 bytes and turns anything beyond Latin-1 into `?`.
pub(crate) fn content_disposition(attachment: bool, name: &str) -> HeaderValue {
    let kind = if attachment { "attachment" } else { "inline" };
    let ascii: String = name
        .chars()
        .map(|c| if c.is_ascii() && !c.is_ascii_control() { c } else { '_' })
        .collect();
    let quoted = ascii.replace('\\', "\\\\").replace('"', "\\\"");
    let mut v = format!("{kind}; filename=\"{quoted}\"");
    if !name.is_ascii() {
        let encoded =
            percent_encoding::utf8_percent_encode(name, percent_encoding::NON_ALPHANUMERIC).to_string();
        v.push_str(&format!("; filename*=UTF-8''{encoded}"));
    }
    HeaderValue::from_str(&v).unwrap_or_else(|_| HeaderValue::from_static("inline"))
}

enum Source {
    File(PathBuf),
    Memory(Bytes),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ByteRange {
    start: u64,
    end: u64,
}

impl ByteRange {
    fn len(&self) -> u64 {
        self.end + 1 - self.start
    }
}

enum RangeRequest {
    Full,
    Ranges(Vec<ByteRange>),
    Unsatisfiable,
}

/// The `Range` header as `RangeDownloadUtil` reads it: `bytes=a-b,c-d`, open ends allowed,
/// a suffix `-n` meaning the last `n` bytes, ends clamped to the file.
fn parse_range(header: Option<&str>, len: u64) -> RangeRequest {
    let Some(h) = header else { return RangeRequest::Full };
    let Some(spec) = h.strip_prefix("bytes=") else { return RangeRequest::Unsatisfiable };
    let len = len as i128;
    let mut out = Vec::new();
    for part in spec.split(',') {
        let Some((a, b)) = part.split_once('-') else { return RangeRequest::Unsatisfiable };
        if !a.chars().all(|c| c.is_ascii_digit()) || !b.chars().all(|c| c.is_ascii_digit()) {
            return RangeRequest::Unsatisfiable;
        }
        let num = |s: &str| -> Option<i128> { if s.is_empty() { Some(-1) } else { s.parse().ok() } };
        let (Some(mut start), Some(mut end)) = (num(a), num(b)) else {
            return RangeRequest::Unsatisfiable;
        };
        if start == -1 {
            start = len - end;
            end = len - 1;
        } else if end == -1 || end > len - 1 {
            end = len - 1;
        }
        if start < 0 {
            start = 0;
        }
        if start > end {
            return RangeRequest::Unsatisfiable;
        }
        out.push(ByteRange { start: start as u64, end: end as u64 });
    }
    RangeRequest::Ranges(out)
}

async fn serve_ranges(
    mut h: HeaderMap,
    req: &HeaderMap,
    source: Source,
    len: u64,
    mime: &'static str,
) -> AppResult<Response> {
    let ranges = match parse_range(header_str(req, "range"), len) {
        RangeRequest::Unsatisfiable => {
            // Java's sendError(416) is swallowed by its own security filter and arrives as a 403.
            let mut resp = Response::new(Body::empty());
            *resp.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;
            let rh = resp.headers_mut();
            rh.insert(header::CONTENT_RANGE, HeaderValue::from_str(&format!("bytes */{len}")).unwrap());
            spring_security_headers(rh, true);
            return Ok(resp);
        }
        RangeRequest::Full => None,
        RangeRequest::Ranges(r) => Some(r),
    };

    h.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    let expires = Utc::now() + Duration::milliseconds(604_800_000);
    h.insert(header::EXPIRES, HeaderValue::from_str(&http_date(expires)).unwrap());

    let (status, body) = match ranges.as_deref() {
        None => {
            // A full download still carries Content-Range, as the Java service sends it.
            h.insert(
                header::CONTENT_RANGE,
                HeaderValue::from_str(&format!("bytes 0-{}/{len}", len as i64 - 1)).unwrap(),
            );
            h.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
            (StatusCode::OK, body_for(&source, 0, len).await?)
        }
        Some([one]) => {
            h.insert(
                header::CONTENT_RANGE,
                HeaderValue::from_str(&format!("bytes {}-{}/{len}", one.start, one.end)).unwrap(),
            );
            h.insert(header::CONTENT_LENGTH, HeaderValue::from(one.len()));
            (StatusCode::PARTIAL_CONTENT, body_for(&source, one.start, one.len()).await?)
        }
        Some(many) => {
            h.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_str(&format!("multipart/byteranges; boundary={BOUNDARY}")).unwrap(),
            );
            (StatusCode::PARTIAL_CONTENT, multipart_body(&source, many.to_vec(), len, mime))
        }
    };

    let sent_length = h
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if sent_length.is_none_or(|l| l > SERVLET_BUFFER) {
        spring_security_headers(&mut h, false);
    }

    let mut resp = Response::new(body);
    *resp.status_mut() = status;
    resp.headers_mut().extend(h);
    Ok(resp)
}

async fn body_for(source: &Source, start: u64, count: u64) -> AppResult<Body> {
    Ok(match source {
        Source::Memory(b) => {
            let s = start.min(b.len() as u64) as usize;
            let e = (start + count).min(b.len() as u64) as usize;
            Body::from(b.slice(s..e))
        }
        Source::File(p) => {
            let mut f = tokio::fs::File::open(p).await.map_err(anyhow::Error::from)?;
            if start > 0 {
                f.seek(SeekFrom::Start(start)).await.map_err(anyhow::Error::from)?;
            }
            Body::from_stream(ReaderStream::with_capacity(f.take(count), CHUNK))
        }
    })
}

/// A correct `multipart/byteranges` body. The Java one has no blank line between a part's
/// headers and its bytes, and every range after the first comes out empty because it reads
/// on from where the previous range stopped.
fn multipart_body(source: &Source, ranges: Vec<ByteRange>, len: u64, mime: &'static str) -> Body {
    let source = match source {
        Source::File(p) => Source::File(p.clone()),
        Source::Memory(b) => Source::Memory(b.clone()),
    };
    let source = std::sync::Arc::new(source);
    let parts = stream::iter(ranges).then(move |r| {
        let source = source.clone();
        async move {
            let head = Bytes::from(format!(
                "\r\n--{BOUNDARY}\r\nContent-Type: {mime}\r\nContent-Range: bytes {}-{}/{len}\r\n\r\n",
                r.start, r.end
            ));
            let data: Bytes = match &*source {
                Source::Memory(b) => {
                    let s = r.start.min(b.len() as u64) as usize;
                    let e = (r.end + 1).min(b.len() as u64) as usize;
                    b.slice(s..e)
                }
                Source::File(p) => {
                    let mut buf = Vec::with_capacity(r.len() as usize);
                    if let Ok(mut f) = tokio::fs::File::open(p).await {
                        if f.seek(SeekFrom::Start(r.start)).await.is_ok() {
                            let _ = f.take(r.len()).read_to_end(&mut buf).await;
                        }
                    }
                    Bytes::from(buf)
                }
            };
            stream::iter(vec![Ok::<_, std::io::Error>(head), Ok(data)])
        }
    });
    let tail = stream::once(async { Ok::<_, std::io::Error>(Bytes::from(format!("\r\n--{BOUNDARY}--\r\n"))) });
    Body::from_stream(parts.flatten().chain(tail))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ranges(h: &str, len: u64) -> Vec<(u64, u64)> {
        match parse_range(Some(h), len) {
            RangeRequest::Ranges(r) => r.into_iter().map(|r| (r.start, r.end)).collect(),
            _ => vec![],
        }
    }

    #[test]
    fn parses_ranges_like_java() {
        assert_eq!(ranges("bytes=0-99", 1213), vec![(0, 99)]);
        assert_eq!(ranges("bytes=100-", 1213), vec![(100, 1212)]);
        assert_eq!(ranges("bytes=-100", 1213), vec![(1113, 1212)]);
        assert_eq!(ranges("bytes=0-99999", 1213), vec![(0, 1212)]);
        assert_eq!(ranges("bytes=0-1,4-5", 1213), vec![(0, 1), (4, 5)]);
        assert!(ranges("bytes=5-2", 1213).is_empty());
        assert!(ranges("items=0-1", 1213).is_empty());
        assert!(ranges("bytes=a-1", 1213).is_empty());
    }

    #[test]
    fn etag_matches_the_live_java_value() {
        let detail = FileDetail {
            id: 1,
            name: "loopzump-32-v1.png".into(),
            is_directory: false,
            size: 1213,
            created: 1_791_655_035,
            last_modified: 1_791_655_035,
        };
        let opts = DownloadOptions::default();
        assert_eq!(
            etag(&detail, &opts),
            "\"-220649959-1791655035-a4d9da2831316f5021400cee04db02e1ca31413da29b52f2f7b7af51b4bd6809\""
        );
    }

    #[test]
    fn content_disposition_escapes() {
        assert_eq!(content_disposition(false, "a\"b.png"), "inline; filename=\"a\\\"b.png\"");
        assert_eq!(content_disposition(true, "x.pdf"), "attachment; filename=\"x.pdf\"");
        let v = content_disposition(false, "été.png");
        assert_eq!(v, "inline; filename=\"_t_.png\"; filename*=UTF-8''%C3%A9t%C3%A9%2Epng");
    }


    #[test]
    fn ranges_past_the_edges() {
        assert!(matches!(parse_range(None, 10), RangeRequest::Full));
        // A start before the file is the file's start; a number too large to read is refused.
        assert_eq!(ranges("bytes=-5000", 11), vec![(0, 10)]);
        assert!(ranges("bytes=99999999999999999999999999999999999999999-", 11).is_empty());
        assert_eq!(ByteRange { start: 2, end: 4 }.len(), 3);
    }

    /// `LastModifiedHeaderTest`: `Last-Modified` carries the real date (epoch seconds are not
    /// milliseconds), and `If-Modified-Since` reads back as epoch seconds; absent or unreadable
    /// is no date (Java's -1).
    #[test]
    fn last_modified_header_test() {
        let written = DateTime::<Utc>::from_timestamp(1_791_131_678, 0).unwrap();
        assert_eq!(http_date(written), "Sun, 04 Oct 2026 16:34:38 GMT");
        let mut h = HeaderMap::new();
        assert_eq!(if_modified_since(&h), None);
        h.insert("if-modified-since", HeaderValue::from_static("Sun, 04 Oct 2026 16:34:38 GMT"));
        assert_eq!(if_modified_since(&h), Some(1_791_131_678));
        h.insert("if-modified-since", HeaderValue::from_static("not a date"));
        assert_eq!(if_modified_since(&h), None);
    }

    #[tokio::test]
    async fn multipart_of_a_file_that_went_away() {
        let gone = std::env::temp_dir().join(format!("files-gone-{:x}", rand::random::<u64>()));
        let body = multipart_body(&Source::File(gone), vec![ByteRange { start: 0, end: 1 }], 2, "text/plain");
        let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        assert_eq!(
            &bytes[..],
            b"\r\n--MULTIPART_BYTERANGES\r\nContent-Type: text/plain\r\nContent-Range: bytes 0-1/2\r\n\r\n\r\n--MULTIPART_BYTERANGES--\r\n"
        );
        let mem = multipart_body(&Source::Memory(Bytes::from_static(b"abc")), vec![ByteRange { start: 1, end: 9 }], 3, "text/plain");
        let bytes = axum::body::to_bytes(mem, usize::MAX).await.unwrap();
        assert!(bytes.windows(6).any(|w| w == b"\r\n\r\nbc"));
        let body = body_for(&Source::Memory(Bytes::from_static(b"abc")), 5, 2).await.unwrap();
        assert!(axum::body::to_bytes(body, usize::MAX).await.unwrap().is_empty());
    }
}
