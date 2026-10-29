//! files-serve: every way a file is read, against the in-process S3 and security services. Row
//! lookups come from the `fsGetDetail` cache (seeded as a first read would leave it), so no
//! database is needed; where one would be, the dead pool turns it into a 500.

mod common;

use axum::http::{Method, StatusCode};
use common::*;
use files::paths::Kind;
use files::Unit;

/// 2026-10-04T16:34:38Z, the instant of `LastModifiedHeaderTest`.
const WRITTEN: i64 = 1_791_131_678;
const WRITTEN_HTTP: &str = "Sun, 04 Oct 2026 16:34:38 GMT";

async fn with_text_file(unit: Unit) -> Harness {
    let h = Harness::new(unit).await;
    h.seed_detail(Kind::Static, "SYSTEM", "docs/hello.txt", file(7, "hello.txt", 11, WRITTEN)).await;
    h.put_object(Kind::Static, "SYSTEM/docs/hello.txt", b"hello world");
    h
}

fn assert_files_headers(r: &Resp) {
    assert_eq!(r.header("x-frame-options"), Some("SAMEORIGIN"));
    assert_eq!(r.header("content-security-policy"), Some("frame-ancestors 'self'"));
    assert_eq!(r.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(r.header("referrer-policy"), None);
}

#[tokio::test]
async fn static_file_with_the_java_headers() {
    let h = with_text_file(Unit::Serve).await;
    let r = h.get("/api/files/static/file/SYSTEM/docs/hello.txt", None).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.route, Some("/api/files/static/file/**"));
    assert_eq!(&r.body[..], b"hello world");
    assert_eq!(r.header("x-cache"), Some("MISS"));
    assert_eq!(r.header("last-modified"), Some(WRITTEN_HTTP));
    assert_eq!(r.header("cache-control"), Some("public, max-age=3600"));
    assert_eq!(r.header("content-disposition"), Some("inline; filename=\"hello.txt\""));
    assert_eq!(r.header("content-type"), Some("text/plain"));
    assert_eq!(r.header("accept-ranges"), Some("bytes"));
    assert_eq!(r.header("content-range"), Some("bytes 0-10/11"));
    assert_eq!(r.header("content-length"), Some("11"));
    assert!(r.header("expires").is_some_and(|e| e.ends_with("GMT")));
    assert!(r.header("etag").is_some_and(|e| e.starts_with('"') && e.contains(&format!("-{WRITTEN}-"))));
    // Fits Tomcat's buffer: Spring Security never gets to add its headers.
    assert_eq!(r.header("x-frame-options"), None);

    // The second read is served from this instance's disk copy.
    let again = h.get("/api/files/static/file/SYSTEM/docs/hello.txt", None).await;
    assert_eq!(&again.body[..], b"hello world");
    assert_eq!(h.s3_calls("GET test-static/SYSTEM/docs/hello.txt"), 1);

    // noCache always goes to the bucket and asks nobody to cache the answer.
    let fresh = h.get("/api/files/static/file/SYSTEM/docs/hello.txt?noCache=true", None).await;
    assert_eq!(fresh.status, StatusCode::OK);
    assert_eq!(fresh.header("cache-control"), None);
    assert_eq!(h.s3_calls("GET test-static/SYSTEM/docs/hello.txt"), 2);
}

/// `LastModifiedHeaderTest`: the header is the real date, and `If-Modified-Since` is read as an
/// HTTP date in seconds; an unreadable one is ignored.
#[tokio::test]
async fn if_modified_since_and_etags_answer_304() {
    let h = with_text_file(Unit::Serve).await;
    let uri = "/api/files/static/file/SYSTEM/docs/hello.txt";
    let first = h.get(uri, None).await;
    let etag = first.header("etag").unwrap().to_string();

    let r = h.get_with(uri, None, &[("if-modified-since", WRITTEN_HTTP)]).await;
    assert_eq!(r.status, StatusCode::NOT_MODIFIED);
    assert_eq!(r.header("x-cache"), Some("HIT"));
    assert!(r.body.is_empty());
    assert_files_headers(&r);

    let r = h.get_with(uri, None, &[("if-modified-since", "not a date")]).await;
    assert_eq!(r.status, StatusCode::OK);
    let r = h.get_with(uri, None, &[("if-modified-since", "Sun, 04 Oct 2026 16:34:39 GMT")]).await;
    assert_eq!(r.status, StatusCode::OK);

    assert_eq!(h.get_with(uri, None, &[("if-none-match", &etag)]).await.status, StatusCode::NOT_MODIFIED);
    // Java reads a request `ETag` header before `If-None-Match`.
    assert_eq!(h.get_with(uri, None, &[("etag", &etag)]).await.status, StatusCode::NOT_MODIFIED);
    assert_eq!(h.get_with(uri, None, &[("etag", "\"x\""), ("if-none-match", &etag)]).await.status, StatusCode::OK);
    // A different option set is a different ETag.
    assert_eq!(h.get_with(&format!("{uri}?width=5"), None, &[("if-none-match", &etag)]).await.status, StatusCode::OK);
    // noCache ignores both.
    let r = h.get_with(&format!("{uri}?noCache=true"), None, &[("if-none-match", &etag), ("if-modified-since", WRITTEN_HTTP)]).await;
    assert_eq!(r.status, StatusCode::OK);
}

#[tokio::test]
async fn download_name_and_disposition() {
    let h = with_text_file(Unit::Serve).await;
    let r = h.get("/api/files/static/file/SYSTEM/docs/hello.txt?download=true&name=report%20final.txt", None).await;
    assert_eq!(r.header("content-disposition"), Some("attachment; filename=\"report final.txt\""));
    let r = h.get("/api/files/static/file/SYSTEM/docs/hello.txt?name=%C3%A9t%C3%A9.txt", None).await;
    assert_eq!(
        r.header("content-disposition"),
        Some("inline; filename=\"_t_.txt\"; filename*=UTF-8''%C3%A9t%C3%A9%2Etxt")
    );
    // A trailing slash names the file by the segment before it.
    let r = h.get("/api/files/static/file/SYSTEM/docs/hello.txt/", None).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.header("content-disposition"), Some("inline; filename=\"hello.txt\""));
}

#[tokio::test]
async fn byte_ranges() {
    let h = with_text_file(Unit::Serve).await;
    let uri = "/api/files/static/file/SYSTEM/docs/hello.txt";

    let r = h.get_with(uri, None, &[("range", "bytes=0-3")]).await;
    assert_eq!(r.status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(r.header("content-range"), Some("bytes 0-3/11"));
    assert_eq!(r.header("content-length"), Some("4"));
    assert_eq!(&r.body[..], b"hell");

    let r = h.get_with(uri, None, &[("range", "bytes=6-")]).await;
    assert_eq!(&r.body[..], b"world");
    let r = h.get_with(uri, None, &[("range", "bytes=-3")]).await;
    assert_eq!(&r.body[..], b"rld");

    let r = h.get_with(uri, None, &[("range", "bytes=0-1,6-7")]).await;
    assert_eq!(r.status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(r.header("content-type"), Some("multipart/byteranges; boundary=MULTIPART_BYTERANGES"));
    assert_eq!(
        r.text(),
        "\r\n--MULTIPART_BYTERANGES\r\nContent-Type: text/plain\r\nContent-Range: bytes 0-1/11\r\n\r\nhe\
         \r\n--MULTIPART_BYTERANGES\r\nContent-Type: text/plain\r\nContent-Range: bytes 6-7/11\r\n\r\nwo\
         \r\n--MULTIPART_BYTERANGES--\r\n"
    );
    // No length on a multipart answer: Spring Security's headers are added.
    assert_files_headers(&r);

    for bad in ["bytes=5-2", "items=0-1", "bytes=a-1", "bytes=1"] {
        let r = h.get_with(uri, None, &[("range", bad)]).await;
        assert_eq!(r.status, StatusCode::RANGE_NOT_SATISFIABLE, "{bad}");
        assert_eq!(r.header("content-range"), Some("bytes */11"));
        assert_files_headers(&r);
    }
}

#[tokio::test]
async fn a_body_past_the_servlet_buffer_gets_the_security_headers() {
    let h = Harness::new(Unit::Serve).await;
    let big = vec![b'x'; 30 * 1024];
    h.seed_detail(Kind::Static, "SYSTEM", "big.bin", file(9, "big.bin", big.len() as u64, WRITTEN)).await;
    h.put_object(Kind::Static, "SYSTEM/big.bin", &big);
    let r = h.get("/api/files/static/file/SYSTEM/big.bin", None).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body.len(), big.len());
    assert_eq!(r.header("content-type"), Some("application/octet-stream"));
    assert_eq!(r.header("cache-control"), Some("public, max-age=3600"));
    assert_files_headers(&r);
}

#[tokio::test]
async fn transformed_images_and_their_ranges() {
    let h = Harness::new(Unit::Serve).await;
    h.seed_detail(Kind::Static, "SYSTEM", "img/logo.png", file(3, "logo.png", 100, WRITTEN)).await;
    h.put_object(Kind::Static, "SYSTEM/img/logo.png", &png(40, 20));
    let uri = "/api/files/static/file/SYSTEM/img/logo.png";

    let r = h.get(&format!("{uri}?width=10"), None).await;
    assert_eq!(r.status, StatusCode::OK);
    let img = image::load_from_memory(&r.body).unwrap();
    assert_eq!((img.width(), img.height()), (10, 5));
    assert_eq!(r.header("content-type"), Some("image/png"));

    let len = r.body.len();
    let r = h.get_with(&format!("{uri}?width=10"), None, &[("range", "bytes=0-3")]).await;
    assert_eq!(r.status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(&r.body[..], b"\x89PNG");
    assert_eq!(r.header("content-range"), Some(format!("bytes 0-3/{len}").as_str()));
    let r = h.get_with(&format!("{uri}?width=10"), None, &[("range", "bytes=1-3,5-5")]).await;
    assert!(r.text().contains("Content-Range: bytes 1-3/"));
    assert!(r.body.windows(3).any(|w| w == b"PNG"));

    // Unknown option values are refused before anything is read.
    for q in ["fit=bogus", "gravity=up", "format=tiff", "width=x", "noCache=maybe", "download=perhaps"] {
        let r = h.get(&format!("{uri}?{q}"), None).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{q}");
        assert!(r.message().starts_with("Invalid value"), "{q}");
    }
}

#[tokio::test]
async fn missing_objects_and_unreadable_rows_are_server_errors() {
    let h = Harness::new(Unit::Serve).await;
    h.seed_detail(Kind::Static, "SYSTEM", "gone.txt", file(1, "gone.txt", 3, WRITTEN)).await;
    let r = h.get("/api/files/static/file/SYSTEM/gone.txt", None).await;
    assert_eq!((r.status, r.code()), (StatusCode::INTERNAL_SERVER_ERROR, "COMMON.INTERNAL_ERROR".to_string()));
    assert!(r.plain().starts_with("Something went wrong on our side. Error id "), "{}", r.plain());
    assert_files_headers(&r);

    // No cached row: the lookup reaches the database, which is down here.
    let r = h.get("/api/files/static/file/SYSTEM/nowhere.txt", None).await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);

    // A client's root is a folder with no object behind it.
    let r = h.get("/api/files/static/file/SYSTEM", None).await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
}

/// The router sets files' own Spring Security header set: SAMEORIGIN and `frame-ancestors
/// 'self'` (what Java files sends), never the reactive services' DENY and no-referrer.
#[tokio::test]
async fn error_responses_carry_the_files_header_set() {
    let h = Harness::new(Unit::Serve).await;
    // Spring Security's refusal (empty in Java), asking to sign in.
    let r = h.get("/api/files/secured/file/SYSTEM/a.pdf", None).await;
    assert_eq!((r.status, r.code()), (StatusCode::FORBIDDEN, "COMMON.SIGN_IN_REQUIRED".to_string()));
    assert_files_headers(&r);
    assert_eq!(r.header("cache-control"), Some("no-cache, no-store, max-age=0, must-revalidate"));
    assert_eq!(r.header("pragma"), Some("no-cache"));
    assert_eq!(r.header("expires"), Some("0"));
    assert_eq!(r.header("x-xss-protection"), Some("0"));
    assert_eq!(r.header("content-type"), Some("application/json"));

    // A message error.
    let r = h.get("/api/files/secured/file/SYSTEM/_withInClient/a.pdf", Some("clia")).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.header("content-type"), Some("application/json"));
    assert_files_headers(&r);
    assert_eq!(platform::http::header_style(), platform::http::HeaderStyle::Files);
}

#[tokio::test]
async fn secured_reads_need_a_caller() {
    let h = Harness::new(Unit::Serve).await;
    let uri = "/api/files/secured/file/SYSTEM/_withInClient/a.pdf";
    for (token, code) in [(None, "COMMON.SIGN_IN_REQUIRED"), (Some("anon"), "COMMON.SIGN_IN_REQUIRED"), (Some("refuse"), "COMMON.SIGNED_OUT"), (Some("nobody"), "COMMON.SIGN_IN_REQUIRED")] {
        let r = h.get(uri, token).await;
        assert_eq!((r.status, r.code()), (StatusCode::FORBIDDEN, code.to_string()), "{token:?}");
        assert_eq!(r.route, Some("/api/files/secured/file/**"));
    }
    // Security answering nonsense is a fault, not a refusal.
    assert_eq!(h.get(uri, Some("garbage")).await.status, StatusCode::INTERNAL_SERVER_ERROR);
    // The Authorization cookie works too.
    h.seed_detail(Kind::Secured, "SYSTEM", "_withInClient/a.pdf", file(4, "a.pdf", 3, WRITTEN)).await;
    h.put_object(Kind::Secured, "SYSTEM/_withInClient/a.pdf", b"pdf");
    let r = h.get_with(uri, None, &[("cookie", "x=1; Authorization=sys")]).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(&r.body[..], b"pdf");
    assert_eq!(r.header("content-type"), Some("application/pdf"));
    // Secured files are never marked publicly cacheable.
    assert_eq!(r.header("cache-control"), None);
    // A bad option is checked after the caller.
    assert_eq!(h.get(&format!("{uri}?fit=no"), Some("sys")).await.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn secured_special_folders() {
    let h = Harness::new(Unit::Serve).await;
    for (cc, rest) in [
        ("CLIA", "_withInClient/x.txt"),
        ("CLIA", "_withInSubClient/x.txt"),
        ("CLIA", "_allSubClients/x.txt"),
        ("SYSTEM", "_userImages/142.png"),
        ("CLIA", "_userImages/1.png"),
    ] {
        h.seed_detail(Kind::Secured, cc, rest, file(5, "x", 1, WRITTEN)).await;
        h.put_object(Kind::Secured, &format!("{cc}/{rest}"), b"x");
    }
    let read = |token: &'static str, path: &'static str| {
        let h = &h;
        async move { h.get(&format!("/api/files/secured/file/{path}"), Some(token)).await.status }
    };
    assert_eq!(read("clia", "CLIA/_withInClient/x.txt").await, StatusCode::OK);
    assert_eq!(read("child", "CLIA/_withInClient/x.txt").await, StatusCode::FORBIDDEN);
    // CLIA manages CHILD: the child reads its parent's sub client folder; the owner does not.
    assert_eq!(read("child", "CLIA/_withInSubClient/x.txt").await, StatusCode::OK);
    assert_eq!(read("clia", "CLIA/_withInSubClient/x.txt").await, StatusCode::FORBIDDEN);
    assert_eq!(read("child", "CLIA/_allSubClients/x.txt").await, StatusCode::OK);
    assert_eq!(read("clia", "CLIA/_allSubClients/x.txt").await, StatusCode::OK);
    h.sec.token("stranger", ca(900, 99, "STRANGER", false, &[]));
    assert_eq!(read("stranger", "CLIA/_allSubClients/x.txt").await, StatusCode::FORBIDDEN);
    // Anyone signed in reads the system user images.
    assert_eq!(read("child", "SYSTEM/_userImages/142.png").await, StatusCode::OK);
    // `_userImages` of any other client is an ordinary folder: CHILD does not manage CLIA.
    let r = h.get("/api/files/secured/file/CLIA/_userImages/1.png", Some("child")).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.message(), "Permission to SECURED resource in the path CLIA/_userImages/1.png is forbidden");
    // A managed client's ordinary path goes to the path rules, in the database (down here).
    assert_eq!(read("clia", "CHILD/docs/a.txt").await, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(read("sys", "CLIA/docs/a.txt").await, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn keys_need_the_database() {
    let h = Harness::new(Unit::Serve).await;
    let r = h.get("/api/files/secured/downloadFileByKey/abc123", None).await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(r.route, Some("/api/files/secured/downloadFileByKey/{key}"));
    assert_eq!(h.get("/api/files/secured/downloadFileByKey/abc?width=q", None).await.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn internal_reads() {
    let h = with_text_file(Unit::Serve).await;
    let r = h.get("/api/files/internal/static/file?filePath=SYSTEM/docs/hello.txt", None).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.route, Some("/api/files/internal/{resourceType}/file"));
    assert_eq!(&r.body[..], b"hello world");
    let r = h.get("/api/files/internal/static/file?filePath=%2FSYSTEM%2Fdocs%2Fhello.txt", None).await;
    assert_eq!(r.status, StatusCode::OK);

    let r = h.get("/api/files/internal/static/file", None).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.message(), "Required parameter 'filePath' is not present.");
    // The client's root is a folder.
    let r = h.get("/api/files/internal/static/file?filePath=SYSTEM", None).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.message(), "Internal Server Error (Unknown)");
    assert_eq!(h.get("/api/files/internal/static/file?filePath=SYSTEM/x&width=a", None).await.status, StatusCode::BAD_REQUEST);

    h.seed_detail(Kind::Secured, "SYSTEM", "s.txt", file(2, "s.txt", 1, WRITTEN)).await;
    h.put_object(Kind::Secured, "SYSTEM/s.txt", b"s");
    let r = h.get("/api/files/internal/secured/file?filePath=SYSTEM/s.txt", None).await;
    assert_eq!((r.status, &r.body[..]), (StatusCode::OK, &b"s"[..]));
}

#[tokio::test]
async fn reads_through_a_gateway_prefix_and_unmatched_paths() {
    let h = with_text_file(Unit::Serve).await;
    let r = h.get("/x/app/SYSTEM/api/files/static/file/SYSTEM/docs/hello.txt", None).await;
    assert_eq!(r.status, StatusCode::OK);

    // files-serve answers nothing but reads.
    for (m, uri) in [
        (Method::POST, "/api/files/static/file/SYSTEM/docs/hello.txt"),
        (Method::GET, "/api/files/static/SYSTEM"),
        (Method::GET, "/somewhere/else"),
    ] {
        let r = h.call(m.clone(), uri, None).await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{m} {uri}");
        assert_eq!(r.route, Some("unmatched"));
    }
    // HEAD reads like GET.
    assert_eq!(h.call(Method::HEAD, "/api/files/static/file/SYSTEM/docs/hello.txt", None).await.status, StatusCode::OK);
}

#[tokio::test]
async fn files_manage_answers_the_read_routes_too() {
    let h = with_text_file(Unit::Manage).await;
    let r = h.get("/api/files/static/file/SYSTEM/docs/hello.txt", None).await;
    assert_eq!((r.status, &r.body[..]), (StatusCode::OK, &b"hello world"[..]));
}

/// CXZ-1138: a secured file read directly under every special name, in a nested folder with
/// spaces, by the service's own spelling (`+` for a space) and by `encodeURIComponent`'s (`%20`).
/// A literal `+` in a name reads only as `%2B`; a bare `+` is a space.
#[tokio::test]
async fn special_names_read_directly_in_both_spellings() {
    let h = Harness::new(Unit::Serve).await;
    let folder = "_withInClient/My Docs (2)/sub, folder";
    for (i, name) in special_names().iter().enumerate() {
        let rest = format!("{folder}/{name}");
        h.seed_detail(Kind::Secured, "CLIA", &rest, file(100 + i as u64, name, 3, WRITTEN)).await;
        h.put_object(Kind::Secured, &format!("CLIA/{rest}"), format!("#{i}").as_bytes());
        for spelled in [java_path(&rest), component_path(&rest)] {
            let r = h.get(&format!("/api/files/secured/file/CLIA/{spelled}"), Some("clia")).await;
            assert_eq!((r.status, String::from_utf8_lossy(&r.body).to_string()), (StatusCode::OK, format!("#{i}")), "{name:?} as {spelled}");
            let d = r.header("content-disposition").unwrap_or("").to_string();
            assert!(d.starts_with("inline; filename=\""), "{name:?}: {d}");
            if !name.is_ascii() {
                assert!(d.contains("filename*=UTF-8''"), "{name:?}: {d}");
            }
        }
        // The same path through the gateway prefix.
        let r = h.get(&format!("/x/app/CLIA/api/files/secured/file/CLIA/{}", java_path(&rest)), Some("clia")).await;
        assert_eq!(r.status, StatusCode::OK, "{name:?} behind a prefix");
    }
    // `plus+sign.pdf` sent with a bare `+` is `plus sign.pdf`, which is not there.
    let r = h.get(&format!("/api/files/secured/file/CLIA/{}/plus+sign.pdf", java_path(folder)), Some("clia")).await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR, "not seeded: the tree walk reaches the (dead) database");
    // A raw `?` starts the query, an encoded one is part of the name.
    let r = h.get(&format!("/api/files/secured/file/CLIA/{}/what%3F.pdf?download=true", java_path(folder)), Some("clia")).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.header("content-disposition").unwrap().starts_with("attachment; filename=\"what?.pdf\""));
}

/// Static files resolve the same way, with no caller.
#[tokio::test]
async fn special_names_read_directly_from_static() {
    let h = Harness::new(Unit::Serve).await;
    for (i, name) in special_names().iter().enumerate() {
        let rest = format!("My Site/{name}");
        h.seed_detail(Kind::Static, "CLIA", &rest, file(300 + i as u64, name, 2, WRITTEN)).await;
        h.put_object(Kind::Static, &format!("CLIA/{rest}"), b"ok");
        for spelled in [java_path(&rest), component_path(&rest)] {
            let r = h.get(&format!("/api/files/static/file/CLIA/{spelled}"), None).await;
            assert_eq!(r.status, StatusCode::OK, "{name:?} as {spelled}");
        }
    }
}
