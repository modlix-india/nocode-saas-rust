//! files-manage without a database: routing, the caller checks, every refusal and binding error
//! that comes before a query, and the routes that need only the bucket, security and the caches
//! (resize, base64, internal base64, uploads of a file that already exists, retention reads from
//! cached rows). Anything that reaches the database gets the dead pool's 500; the gated
//! `live_mysql` tests cover those paths for real.

mod common;

use axum::http::{Method, StatusCode};
use common::*;
use files::paths::Kind;
use files::retention::PolicyRow;
use files::Unit;
use serde_json::{json, Value};

async fn manage() -> Harness {
    Harness::new(Unit::Manage).await
}

// ---------------------------------------------------------------------------------------------
// Routing and callers
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn every_route_reports_its_spring_pattern() {
    let h = manage().await;
    let cases: &[(Method, &str, &str)] = &[
        (Method::GET, "/api/files/static/a", "/api/files/static/**"),
        (Method::GET, "/api/files/secured/a", "/api/files/secured/**"),
        (Method::DELETE, "/api/files/static/a", "/api/files/static/**"),
        (Method::POST, "/api/files/secured/directory/a", "/api/files/secured/directory/**"),
        (Method::POST, "/api/files/static/directory/a", "/api/files/static/directory/**"),
        (Method::POST, "/api/files/static/a", "/api/files/static/**"),
        (Method::POST, "/api/files/static/import/a", "/api/files/static/import/**"),
        (Method::POST, "/api/files/secured/import/a", "/api/files/secured/import/**"),
        (Method::GET, "/api/files/static/export/a", "/api/files/static/export/**"),
        (Method::GET, "/api/files/secured/export/a", "/api/files/secured/export/**"),
        (Method::GET, "/api/files/static/exports", "/api/files/static/exports"),
        (Method::GET, "/api/files/secured/exports", "/api/files/secured/exports"),
        (Method::GET, "/api/files/static/imports", "/api/files/static/imports"),
        (Method::GET, "/api/files/secured/imports", "/api/files/secured/imports"),
        (Method::POST, "/api/files/static/copyToClientPage", "/api/files/static/copyToClientPage"),
        (Method::GET, "/api/files/secured/createKey/file/SYSTEM/a", "/api/files/secured/createKey/**"),
        (Method::POST, "/api/files/transform/static/a", "/api/files/transform/{resourceType}/**"),
        (Method::POST, "/api/files/generic/client", "/api/files/generic/client"),
        (Method::POST, "/api/files/generic/user", "/api/files/generic/user"),
        (Method::POST, "/api/files/generic/resize", "/api/files/generic/resize"),
        (Method::POST, "/api/files/generic/convertToBase64", "/api/files/generic/convertToBase64"),
        (Method::POST, "/api/files/generic/convertToBase64WithDetails", "/api/files/generic/convertToBase64WithDetails"),
        (Method::GET, "/api/files/generic/internal/fs/populate?resourceType=none", "/api/files/generic/internal/fs/populate"),
        (Method::GET, "/api/files/internal/secured/createKey", "/api/files/internal/secured/createKey"),
        (Method::POST, "/api/files/internal/static", "/api/files/internal/{resourceType}"),
        (Method::POST, "/api/files/internal/static/cleanupExpired", "/api/files/internal/{resourceType}/cleanupExpired"),
        (Method::POST, "/api/files/internal/secured/applyRetention", "/api/files/internal/{resourceType}/applyRetention"),
        (Method::GET, "/api/files/internal/static/convertToBase64", "/api/files/internal/{resourceType}/convertToBase64"),
        (Method::POST, "/api/files/internal/aiUploader", "/api/files/internal/aiUploader"),
        (Method::POST, "/api/files/internal/accesspath", "/api/files/internal/accesspath"),
        (Method::POST, "/api/files/internal/billing/meter", "/api/files/internal/billing/meter"),
        (Method::POST, "/api/files/internal/billing/reconcile?date=x", "/api/files/internal/billing/reconcile"),
        (Method::POST, "/api/files/accesspath", "/api/files/accesspath"),
        (Method::GET, "/api/files/accesspath", "/api/files/accesspath"),
        (Method::POST, "/api/files/accesspath/query", "/api/files/accesspath/query"),
        (Method::GET, "/api/files/accesspath/1", "/api/files/accesspath/{id}"),
        (Method::PUT, "/api/files/accesspath/1", "/api/files/accesspath/{id}"),
        (Method::PATCH, "/api/files/accesspath/1", "/api/files/accesspath/{id}"),
        (Method::DELETE, "/api/files/accesspath/1", "/api/files/accesspath/{id}"),
        (Method::GET, "/api/files/retention", "/api/files/retention"),
        (Method::POST, "/api/files/retention", "/api/files/retention"),
        (Method::PUT, "/api/files/retention/1", "/api/files/retention/{id}"),
        (Method::DELETE, "/api/files/retention/1", "/api/files/retention/{id}"),
        (Method::GET, "/api/files/retention/effective", "/api/files/retention/effective"),
        (Method::GET, "/api/files/retention/preview", "/api/files/retention/preview"),
    ];
    for (m, uri, template) in cases {
        let r = h.call(m.clone(), uri, Some("child")).await;
        assert_eq!(r.route, Some(*template), "{m} {uri}");
    }
}

#[tokio::test]
async fn unknown_paths_and_methods() {
    let h = manage().await;
    for (m, uri) in [
        (Method::GET, "/elsewhere"),
        (Method::GET, "/api/files/nothing"),
        (Method::GET, "/api/files/staticx/a"),
        (Method::POST, "/api/files/transform/"),
        (Method::GET, "/api/files/generic/other"),
        (Method::GET, "/api/files/generic/client"),
        (Method::POST, "/api/files/internal/a/b/c"),
        (Method::GET, "/api/files/internal/static"),
        (Method::GET, "/api/files/accesspath/a/b"),
        (Method::PATCH, "/api/files/retention/1"),
        (Method::GET, "/api/files/retention/a/b"),
    ] {
        let r = h.call(m.clone(), uri, Some("sys")).await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{m} {uri}");
        assert_eq!(r.route, Some("unmatched"), "{m} {uri}");
    }
    for (m, uri, template) in [
        (Method::PUT, "/api/files/static/a", "/api/files/static/**"),
        (Method::PATCH, "/api/files/secured/a", "/api/files/secured/**"),
        (Method::GET, "/api/files/transform/static/a", "/api/files/transform/{resourceType}/**"),
        (Method::DELETE, "/api/files/accesspath", "/api/files/accesspath"),
        (Method::POST, "/api/files/accesspath/5", "/api/files/accesspath/{id}"),
        (Method::PUT, "/api/files/retention", "/api/files/retention"),
    ] {
        let r = h.call(m.clone(), uri, Some("sys")).await;
        assert_eq!(r.status, StatusCode::METHOD_NOT_ALLOWED, "{m} {uri}");
        assert!(r.body.is_empty());
        assert_eq!(r.route, Some(template));
    }
}

#[tokio::test]
async fn signed_in_routes_refuse_like_spring_security() {
    let h = manage().await;
    // Spring Security's empty 403, said plainly: sign in, or signed out when a credential was refused.
    for (token, code) in [(None, "COMMON.SIGN_IN_REQUIRED"), (Some("anon"), "COMMON.SIGN_IN_REQUIRED"), (Some("refuse"), "COMMON.SIGNED_OUT")] {
        let r = h.get("/api/files/static/x", token).await;
        assert_eq!((r.status, r.code()), (StatusCode::FORBIDDEN, code.to_string()), "{token:?}");
    }
    let garbage = h.get("/api/files/static/x", Some("garbage")).await;
    assert_eq!((garbage.status, garbage.code()), (StatusCode::INTERNAL_SERVER_ERROR, "COMMON.INTERNAL_ERROR".to_string()));
    assert!(garbage.plain().contains(garbage.json()["exceptionId"].as_str().unwrap()));
    // The internal routes never ask security.
    let before = h.sec.calls_to("securityContextAuthentication");
    h.call(Method::POST, "/api/files/internal/billing/meter", None).await;
    assert_eq!(h.sec.calls_to("securityContextAuthentication"), before);
}

// ---------------------------------------------------------------------------------------------
// Resources: listing, delete, folders, uploads, zips, jobs, copy, keys
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn listing_refusals_and_the_cached_first_page() {
    let h = manage().await;
    let r = h.get("/api/files/static/a?fileType=IMAGES,BOGUS", Some("sys")).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.message(), "Invalid value 'BOGUS' for parameter 'fileType'");

    let r = h.get("/api/files/static/a?clientCode=NOPE", Some("sys")).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.message(), "Permission to STATIC resource in the path a is forbidden");
    let r = h.get("/api/files/secured/a?clientCode=STRANGER", Some("clia")).await;
    assert_eq!(r.message(), "Permission to SECURED resource in the path a is forbidden");
    // Static: the sub client folders a managing client shares.
    assert_eq!(h.get("/api/files/static/?clientCode=STRANGER", Some("clia")).await.status, StatusCode::FORBIDDEN);
    assert_eq!(h.get("/api/files/static/_withInSubClient?clientCode=STRANGER", Some("clia")).await.status, StatusCode::FORBIDDEN);
    assert_eq!(h.get("/api/files/static/other/x?clientCode=STRANGER", Some("clia")).await.status, StatusCode::FORBIDDEN);
    assert_eq!(h.get("/api/files/static/_allSubClients?clientCode=STRANGER", Some("clia")).await.status, StatusCode::FORBIDDEN);

    // CHILD lists its manager's `_allSubClients`; the plain first page comes from the cache.
    h.state
        .inner()
        .lists
        .insert(
            "fsPathList-STATIC-CLIA",
            "_allSubClients".to_string(),
            files::fs::FilesPage { content: vec![file(0, "b b.png", 4, 9), folder(0, "sub")], total: 2 },
        )
        .await;
    let r = h.get("/api/files/static/_allSubClients?clientCode=CLIA&size=200", Some("child")).await;
    assert_eq!(r.status, StatusCode::OK);
    let v = r.json();
    assert_eq!(v["totalElements"], 2);
    assert_eq!(v["content"][0]["url"], "api/files/static/file/CLIA/_allSubClients/b+b.png");
    assert_eq!(v["content"][0]["filePath"], "/_allSubClients/b b.png");
    assert_eq!(v["content"][1]["url"], "api/files/static/_allSubClients/sub");
    assert!(v["content"][0].get("id").is_none());
    // A sibling of the manager is not shared with.
    let r = h.get("/api/files/static/_withInSubClient?clientCode=CLIA&size=200", Some("clia")).await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR, "own client: the path rules are read");
    // Anything but the plain first page reads the database.
    let r = h.get("/api/files/static/_allSubClients?clientCode=CLIA&size=200&filter=b", Some("child")).await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn writes_to_a_client_the_caller_cannot_write() {
    let h = manage().await;
    for (m, uri) in [
        (Method::DELETE, "/api/files/static/a.txt?clientCode=NOPE"),
        (Method::POST, "/api/files/static/directory/a?clientCode=NOPE"),
        (Method::POST, "/api/files/secured/directory/a?clientCode=STRANGER"),
        (Method::POST, "/api/files/static/a?clientCode=NOPE"),
    ] {
        let r = h.call(m.clone(), uri, Some("clia")).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{m} {uri}");
        assert!(r.message().starts_with("Permission to "), "{m} {uri}");
    }
    // The system client writes only to clients security knows.
    h.sec.world.lock().unwrap().valid.retain(|c| c != "STRANGER");
    let r = h.call(Method::POST, "/api/files/static/directory/a?clientCode=STRANGER", Some("sys")).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    // Managed and allowed so far: the path rules are in the database.
    let r = h.call(Method::DELETE, "/api/files/static/a.txt?clientCode=CHILD", Some("clia")).await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
    let r = h.call(Method::DELETE, "/api/files/static/a.txt", Some("sys")).await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
}

/// The system client's mobile uploader writes into `_withInClient` without a path rule, so
/// these uploads need no database while the target exists in the cache.
#[tokio::test]
async fn uploads_into_with_in_client() {
    let h = manage().await;
    let uri = "/api/files/static/_withInClient/docs";

    let r = h.form(uri, Some("sys"), &[FormPart::Text("name", "x")]).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.message(), "file is/are missing");
    // Not multipart at all reads as an empty form.
    let r = h.raw(Method::POST, uri, Some("sys"), "plain").await;
    assert_eq!(r.message(), "file is/are missing");
    let r = h
        .send(
            Harness::request(Method::POST, uri, Some("sys"))
                .header("content-type", "multipart/form-data")
                .body(axum::body::Body::from("x"))
                .unwrap(),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "multipart without a boundary");

    // An existing file with override=false answers the existing row.
    let exists = |rest: &str| (format!("fsPathExists-STATIC-SYSTEM"), rest.to_string());
    let (n, k) = exists("_withInClient/docs/report.txt");
    h.state.inner().exists.insert(&n, k, true).await;
    h.seed_detail(Kind::Static, "SYSTEM", "_withInClient/docs/report.txt", file(31, "report.txt", 5, 1_791_000_000)).await;
    let r = h
        .form(
            uri,
            Some("sys"),
            &[
                FormPart::Text("override", "false"),
                FormPart::Text("name", "report"),
                FormPart::File("file", "a.txt", "text/plain", b"hello".to_vec()),
                FormPart::File("file", "second.txt", "text/plain", b"ignored".to_vec()),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    let v = r.json();
    assert_eq!(v["id"], 31);
    assert_eq!(v["filePath"], "/_withInClient/docs/report.txt");
    assert_eq!(v["url"], "api/files/static/file/SYSTEM/_withInClient/docs/report.txt");
    assert!(h.object(Kind::Static, "SYSTEM/_withInClient/docs/report.txt").is_none(), "nothing written");

    // A name that is no name is refused before the object is written.
    let (n, k) = exists("_withInClient/docs/undefined");
    h.state.inner().exists.insert(&n, k, false).await;
    let r = h.form(uri, Some("sys"), &[FormPart::File("file", "undefined", "text/plain", b"x".to_vec())]).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(r.message().starts_with("'undefined' is not a usable name."), "{}", r.message());
    assert_eq!(h.s3_calls("PUT"), 0);

    // A new file: the object is written, then the row (the database is down here).
    let (n, k) = exists("_withInClient/docs/new.txt");
    h.state.inner().exists.insert(&n, k, false).await;
    let r = h.form(uri, Some("sys"), &[FormPart::File("file", "new.txt", "text/plain", b"new".to_vec())]).await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
    let o = h.object(Kind::Static, "SYSTEM/_withInClient/docs/new.txt").unwrap();
    assert_eq!(o.bytes, b"new");
    assert_eq!(o.content_type.as_deref(), Some("text/plain"));
    assert_eq!(o.disposition.as_deref(), Some("inline"));
}

#[tokio::test]
async fn zip_import_refusals() {
    let h = manage().await;
    let uri = "/api/files/static/import/_withInClient/z";
    let r = h.form(uri, Some("sys"), &[FormPart::Text("override", "true")]).await;
    assert_eq!((r.status, r.message().as_str()), (StatusCode::BAD_REQUEST, "Unable to read uploaded zip file"));
    let r = h.form(uri, Some("sys"), &[FormPart::File("file", "a.txt", "text/plain", b"x".to_vec())]).await;
    assert_eq!(r.message(), "Unable to read uploaded zip file");
    let r = h.form("/api/files/static/import/x?clientCode=NOPE", Some("sys"), &[FormPart::File("file", "a.ZIP", "application/zip", b"x".to_vec())]).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    // Allowed: the job row needs the database.
    let r = h.form(uri, Some("sys"), &[FormPart::File("file", "a.zip", "application/zip", b"PK".to_vec())]).await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn export_and_job_listings_reach_the_database() {
    let h = manage().await;
    assert_eq!(h.get("/api/files/static/export/a?clientCode=NOPE", Some("sys")).await.status, StatusCode::FORBIDDEN);
    assert_eq!(h.get("/api/files/static/export/a", Some("sys")).await.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(h.get("/api/files/static/exports?clientCode=CLIA", Some("sys")).await.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(h.get("/api/files/secured/imports", Some("sys")).await.status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn copy_to_client_page_refusals() {
    let h = manage().await;
    let uri = "/api/files/static/copyToClientPage";
    let r = h.json(Method::POST, uri, Some("sys"), &json!([])).await;
    assert_eq!((r.status, r.message().as_str()), (StatusCode::BAD_REQUEST, "Required parameter 'pageName' is not present."));
    let r = h.json(Method::POST, &format!("{uri}?pageName=home"), Some("sys"), &json!({"a": 1})).await;
    assert_eq!(r.message(), "A list of file URLs is required");
    let r = h.raw(Method::POST, &format!("{uri}?pageName=home"), Some("sys"), "{nope").await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(r.message().starts_with("Invalid JSON"));
    let r = h.json(Method::POST, &format!("{uri}?pageName=home&clientCode=NOPE"), Some("sys"), &json!([])).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.message(), "Permission to STATIC resource in the path sitezump/home is forbidden");
}

#[tokio::test]
async fn create_key_checks_before_the_insert() {
    let h = manage().await;
    let base = "/api/files/secured/createKey/file/SYSTEM/_withInClient/a.pdf";
    for (q, message) in [
        ("timeSpan=5", "Time unit is not provided for selected resource"),
        ("accessLimit=2", "Time Span is not provided for selected resource"),
        ("timeSpan=5&timeUnit=Hours", "Invalid value 'Hours' for parameter 'timeUnit'"),
        ("timeSpan=x&timeUnit=HOURS", "Invalid value 'x' for parameter 'timeSpan'"),
        ("timeSpan=1&timeUnit=HOURS&accessLimit=-1", "Invalid value '-1' for parameter 'accessLimit'"),
        ("timeSpan=1&timeUnit=FOREVER", "Unsupported time span: 1 Forever"),
        ("timeSpan=1&timeUnit=ERAS", "Unsupported time span: 1 Eras"),
        // The most negative span in months used to overflow its negation (a panic in a debug build).
        ("timeSpan=-9223372036854775808&timeUnit=MONTHS", "Unsupported time span: -9223372036854775808 Months"),
    ] {
        let r = h.get(&format!("{base}?{q}"), Some("sys")).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{q}");
        assert_eq!(r.message(), message, "{q}");
    }
    let r = h.get(base, Some("clia")).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.message(), "Permission to SECURED resource in the path SYSTEM/_withInClient/a.pdf is forbidden");
    let r = h.get("/api/files/secured/createKey", Some("sys")).await;
    assert_eq!(r.message(), "Permission to SECURED resource in the path  is forbidden");
    // Allowed and valid: the key row needs the database.
    let r = h.get(&format!("{base}?timeSpan=2&timeUnit=HOURS&accessLimit=3"), Some("sys")).await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
}

// ---------------------------------------------------------------------------------------------
// Generic: transforms, pictures, resize, base64, populate
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn transform_refusals() {
    let h = manage().await;
    let uri = "/api/files/transform/static/_withInClient/pics";
    let r = h.json(Method::POST, uri, Some("sys"), &json!({})).await;
    assert_eq!(r.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert!(r.body.is_empty());
    let r = h.form(uri, Some("sys"), &[FormPart::Text("width", "10")]).await;
    assert_eq!(r.message(), "fileName is/are missing");
    let r = h.form(uri, Some("sys"), &[FormPart::Text("fileName", "o.png")]).await;
    assert_eq!(r.message(), "path is/are missing");
    let r = h.form(uri, Some("sys"), &[FormPart::Text("fileName", "o.png"), FormPart::Text("path", "/elsewhere/a.png")]).await;
    assert_eq!(r.message(), "path is/are missing");
    let r = h.form(uri, Some("sys"), &[FormPart::Text("fileName", "o.png"), FormPart::Text("path", "api/files/static/file/")]).await;
    assert_eq!(r.message(), "path is/are missing");
    let r = h.form(uri, Some("sys"), &[FormPart::Text("width", "wide"), FormPart::File("file", "a.png", "image/png", png(4, 4))]).await;
    assert_eq!((r.status, r.message().as_str()), (StatusCode::BAD_REQUEST, "Invalid value 'wide' for 'width'"));
    let r = h.form("/api/files/transform/static/x?clientCode=STRANGER", Some("clia"), &[FormPart::File("file", "a.png", "image/png", png(4, 4))]).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = h.form(uri, Some("sys"), &[FormPart::File("file", "a.png", "image/png", b"not an image".to_vec())]).await;
    assert_eq!((r.status, r.message().as_str()), (StatusCode::INTERNAL_SERVER_ERROR, "Unable to find the reader for the image."));
}

#[tokio::test]
async fn transform_an_upload_and_a_stored_image() {
    let h = manage().await;
    let exists = |rest: &str| ("fsPathExists-STATIC-SYSTEM".to_string(), rest.to_string());
    // The target exists and override is off: the existing row is the answer.
    let (n, k) = exists("_withInClient/pics/out.png");
    h.state.inner().exists.insert(&n, k, true).await;
    h.seed_detail(Kind::Static, "SYSTEM", "_withInClient/pics/out.png", file(40, "out.png", 9, 1_791_000_000)).await;
    let r = h
        .form(
            "/api/files/transform/static/_withInClient/pics",
            Some("sys"),
            &[
                FormPart::Text("fileName", "out.png"),
                FormPart::Text("width", "2"),
                FormPart::Text("rotation", "90"),
                FormPart::File("file", "in.png", "image/png", png(8, 4)),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let v = r.json();
    assert_eq!(v["id"], 40);
    assert_eq!(v["url"], "api/files/static/file/SYSTEM/_withInClient/pics/out.png");

    // From a stored image, named by the file part's name when there is no fileName.
    h.put_object(Kind::Static, "SYSTEM/_withInClient/src.jpg", &{
        let img = image::DynamicImage::ImageRgb8(image::RgbImage::from_pixel(6, 6, image::Rgb([1, 2, 3])));
        let mut out = std::io::Cursor::new(Vec::new());
        img.write_to(&mut out, image::ImageFormat::Jpeg).unwrap();
        out.into_inner()
    });
    let (n, k) = exists("_withInClient/copy.jpg");
    h.state.inner().exists.insert(&n, k, true).await;
    h.seed_detail(Kind::Static, "SYSTEM", "_withInClient/copy.jpg", file(41, "copy.jpg", 9, 1)).await;
    let r = h
        .form(
            "/api/files/transform/static/ignored",
            Some("sys"),
            &[
                FormPart::Text("fileName", "copy.jpg"),
                FormPart::Text("path", "api/files/static/file/SYSTEM/_withInClient/src.jpg"),
                FormPart::Text("flipHorizontal", "true"),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(r.json()["id"], 41);

    // A stored image that is not in the bucket.
    let r = h
        .form(
            "/api/files/transform/static/ignored",
            Some("sys"),
            &[FormPart::Text("fileName", "c.png"), FormPart::Text("path", "api/files/static/file/SYSTEM/_withInClient/none.png")],
        )
        .await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);

    // Overwriting writes the object, then needs the database for the row.
    let (n, k) = exists("_withInClient/pics/photo.PNG");
    h.state.inner().exists.insert(&n, k, true).await;
    let r = h
        .form(
            "/api/files/transform/static/_withInClient/pics",
            Some("sys"),
            &[FormPart::Text("override", "true"), FormPart::File("file", "photo.PNG", "image/png", png(3, 3))],
        )
        .await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(h.object(Kind::Static, "SYSTEM/_withInClient/pics/photo.PNG").is_some());
}

/// `ImageUploadNamingAndAccessTest`, the refusals: they come before anything is written.
#[tokio::test]
async fn picture_refusals() {
    let h = manage().await;
    let pic = || FormPart::File("file", "photo.png", "image/png", png(4, 4));

    // A client logo needs Client_UPDATE.
    let r = h.form("/api/files/generic/client", Some("clia"), &[pic()]).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.message(), "Permission/Role Authorities.Client_UPDATE is required to use this operation ");
    h.sec.token("cliaAdmin", ca(501, 10, "CLIA", false, &["Authorities.Client_UPDATE", "Authorities.User_UPDATE"]));
    let r = h.form("/api/files/generic/client", Some("cliaAdmin"), &[]).await;
    assert_eq!(r.message(), "file is/are missing");
    // Of a client the caller does not manage.
    let r = h.form("/api/files/generic/client", Some("cliaAdmin"), &[FormPart::Text("clientId", "1"), pic()]).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.message(), "Permission to STATIC resource in the path User Images is forbidden");
    let r = h.form("/api/files/generic/client", Some("cliaAdmin"), &[FormPart::Text("clientId", "x"), pic()]).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    // A caller with no client code of its own.
    let mut nameless = ca(502, 10, "CLIA", false, &["Authorities.Client_UPDATE"]);
    nameless["clientCode"] = Value::Null;
    h.sec.token("nameless", nameless);
    let r = h.form("/api/files/generic/client", Some("nameless"), &[pic()]).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(h.s3_calls("PUT"), 0);

    // Someone else's photo without User_UPDATE.
    let r = h.form("/api/files/generic/user", Some("clia"), &[FormPart::Text("userId", "600"), pic()]).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.message(), "Permission to SECURED resource in the path User Images is forbidden");
    // With it, of a user whose client the caller does not manage.
    let r = h.form("/api/files/generic/user", Some("cliaAdmin"), &[FormPart::Text("userId", "142"), pic()]).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    // Of a user security does not know.
    let r = h.form("/api/files/generic/user", Some("cliaAdmin"), &[FormPart::Text("userId", "7777"), pic()]).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = h.form("/api/files/generic/user", Some("cliaAdmin"), &[FormPart::Text("userId", "600")]).await;
    assert_eq!(r.message(), "file is/are missing");
    assert_eq!(h.s3_calls("PUT"), 0);

    // Allowed: the picture is written by id, then the row needs the database.
    h.state.inner().exists.insert("fsPathExists-SECURED-SYSTEM", "_userImages/600.png".to_string(), true).await;
    h.state.inner().exists.insert("fsPathExists-STATIC-SYSTEM", "_clientImages/11.png".to_string(), true).await;
    let r = h.form("/api/files/generic/user", Some("cliaAdmin"), &[FormPart::Text("userId", "600"), pic()]).await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(h.object(Kind::Secured, "SYSTEM/_userImages/600.png").is_some());
    let r = h.form("/api/files/generic/client", Some("cliaAdmin"), &[FormPart::Text("clientId", "11"), pic()]).await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(h.object(Kind::Static, "SYSTEM/_clientImages/11.png").is_some());
}

#[tokio::test]
async fn resize_answers_the_image() {
    let h = manage().await;
    let r = h
        .form(
            "/api/files/generic/resize",
            Some("child"),
            &[FormPart::Text("width", "4"), FormPart::File("file", "a.png", "image/png", png(8, 8))],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.header("content-type"), Some("image/png"));
    assert_eq!(r.header("content-disposition"), Some("inline; filename=\"a.png\""));
    assert_eq!(r.header("x-frame-options"), Some("SAMEORIGIN"));
    let img = image::load_from_memory(&r.body).unwrap();
    assert_eq!((img.width(), img.height()), (4, 4));

    let r = h.form("/api/files/generic/resize", Some("child"), &[FormPart::File("file", "a.JPG", "image/jpeg", png(8, 8))]).await;
    assert_eq!(r.header("content-type"), Some("image/jpeg"));
    assert_eq!(image::guess_format(&r.body).unwrap(), image::ImageFormat::Jpeg);

    let r = h.form("/api/files/generic/resize", Some("child"), &[FormPart::File("file", "a.gif", "image/gif", png(8, 8))]).await;
    assert_eq!((r.status, r.message().as_str()), (StatusCode::BAD_REQUEST, "Unsupported image type 'gif'"));
    let r = h.form("/api/files/generic/resize", Some("child"), &[]).await;
    assert_eq!(r.message(), "file is/are missing");
    let r = h.form("/api/files/generic/resize", Some("child"), &[FormPart::Text("height", "h")]).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn base64_conversions() {
    let h = manage().await;
    let r = h.form("/api/files/generic/convertToBase64", Some("child"), &[FormPart::File("file", "a.txt", "text/plain", b"hello".to_vec())]).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.text(), "aGVsbG8=");
    assert_eq!(r.header("content-type"), Some("text/plain;charset=UTF-8"));
    let r = h
        .form("/api/files/generic/convertToBase64WithDetails", Some("child"), &[FormPart::File("file", "a.txt", "text/plain", b"hello".to_vec())])
        .await;
    assert_eq!(r.json(), json!({"fileName": "a.txt", "contentType": "text/plain", "size": 5, "base64Content": "aGVsbG8="}));
    let r = h.form("/api/files/generic/convertToBase64", Some("child"), &[FormPart::File("file", "e.txt", "text/plain", vec![])]).await;
    assert_eq!((r.status, r.message().as_str()), (StatusCode::BAD_REQUEST, "File is required and cannot be empty"));
    let r = h.form("/api/files/generic/convertToBase64", Some("child"), &[]).await;
    assert_eq!(r.message(), "file is/are missing");
}

#[tokio::test]
async fn populate_answers_at_once() {
    let h = manage().await;
    let r = h.get("/api/files/generic/internal/fs/populate?clientCode=SYSTEM&folderPath=x&resourceType=static", None).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.text(), "FileSystem populated");
    // The rebuild runs in the background and fails on the database here; the answer is the same.
    let r = h.get("/api/files/generic/internal/fs/populate", None).await;
    assert_eq!(r.text(), "FileSystem populated");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}

// ---------------------------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn internal_binding_errors() {
    let h = manage().await;
    for (m, uri, message) in [
        (Method::GET, "/api/files/internal/secured/createKey", "Required parameter 'filePath' is not present."),
        (Method::POST, "/api/files/internal/static?fileName=a", "Required parameter 'clientCode' is not present."),
        (Method::POST, "/api/files/internal/static?clientCode=A", "Required parameter 'fileName' is not present."),
        (Method::POST, "/api/files/internal/static?clientCode=A&fileName=a&override=perhaps", "Invalid value 'perhaps' for parameter 'override'"),
        (Method::POST, "/api/files/internal/static?clientCode=A&fileName=a&expiresAfterMinutes=-5", "Invalid value '-5' for parameter 'expiresAfterMinutes'"),
        (Method::POST, "/api/files/internal/static?clientCode=A&fileName=a&expiresAfterMinutes=x", "Invalid value 'x' for parameter 'expiresAfterMinutes'"),
        (Method::POST, "/api/files/internal/static/cleanupExpired?limit=lots", "Invalid value 'lots' for parameter 'limit'"),
        (Method::POST, "/api/files/internal/secured/applyRetention?limit=1.5", "Invalid value '1.5' for parameter 'limit'"),
        (Method::GET, "/api/files/internal/static/convertToBase64?url=x", "Required parameter 'clientCode' is not present."),
        (Method::GET, "/api/files/internal/static/convertToBase64?clientCode=SYSTEM", "Required parameter 'url' is not present."),
        (Method::POST, "/api/files/internal/aiUploader", "Required parameter 'clientCode' is not present."),
        (Method::POST, "/api/files/internal/aiUploader?clientCode=CLIA", "file is/are missing"),
        (Method::POST, "/api/files/internal/billing/reconcile?date=2026-13-01", "Invalid date '2026-13-01'"),
    ] {
        let r = h.call(m.clone(), uri, None).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{m} {uri}");
        assert_eq!(r.message(), message, "{m} {uri}");
    }
    // Valid: these read or write rows.
    for (m, uri) in [
        (Method::GET, "/api/files/internal/secured/createKey?filePath=SYSTEM/a.pdf"),
        (Method::POST, "/api/files/internal/static/cleanupExpired"),
        (Method::POST, "/api/files/internal/secured/applyRetention?limit=3"),
    ] {
        assert_eq!(h.call(m.clone(), uri, None).await.status, StatusCode::INTERNAL_SERVER_ERROR, "{m} {uri}");
    }
    // A limit of zero sweeps nothing and reads nothing.
    let r = h.call(Method::POST, "/api/files/internal/static/applyRetention?limit=0", None).await;
    assert_eq!((r.status, r.text().as_str()), (StatusCode::OK, "[ ]"));
}

#[tokio::test]
async fn internal_raw_upload_of_an_existing_file() {
    let h = manage().await;
    h.state.inner().exists.insert("fsPathExists-SECURED-CLIA", "in/a.bin".to_string(), true).await;
    h.seed_detail(Kind::Secured, "CLIA", "in/a.bin", file(77, "a.bin", 3, 1)).await;
    let r = h.raw(Method::POST, "/api/files/internal/secured?clientCode=CLIA&fileName=a.bin&filePath=in&expiresAfterMinutes=10", None, "abc").await;
    assert_eq!(r.status, StatusCode::OK);
    let v = r.json();
    assert_eq!(v["id"], 77);
    assert_eq!(v["url"], "api/files/secured/file/CLIA/in/a.bin");
    // Overwriting writes the object first (a chunked body works), then the row.
    let body = axum::body::Body::from_stream(futures::stream::iter(vec![Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"ab")), Ok(bytes::Bytes::from_static(b"cd"))]));
    let r = h.raw(Method::POST, "/api/files/internal/secured?clientCode=CLIA&fileName=a.bin&filePath=in&override=yes", None, body).await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(h.object(Kind::Secured, "CLIA/in/a.bin").unwrap().bytes, b"abcd");
    // No filePath: the client's root.
    h.state.inner().exists.insert("fsPathExists-STATIC-CLIA", "/r.txt".to_string(), true).await;
    h.seed_detail(Kind::Static, "CLIA", "/r.txt", file(78, "r.txt", 1, 1)).await;
    let r = h.raw(Method::POST, "/api/files/internal/static?clientCode=CLIA&fileName=r.txt", None, "x").await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(r.json()["filePath"], "/r.txt");
}

#[tokio::test]
async fn internal_base64_of_a_managed_clients_file() {
    let h = manage().await;
    h.seed_detail(Kind::Static, "CHILD", "docs/hello.txt", file(8, "hello.txt", 5, 1)).await;
    h.put_object(Kind::Static, "CHILD/docs/hello.txt", b"hello");
    let base = "/api/files/internal/static/convertToBase64?clientCode=CLIA&url=";
    let r = h.get(&format!("{base}/api/files/static/file/CHILD/docs/hello.txt"), None).await;
    assert_eq!((r.status, r.text().as_str()), (StatusCode::OK, "aGVsbG8="));
    let r = h.get(&format!("{base}/api/files/static/file/CHILD/docs/hello.txt&metadataRequired=true"), None).await;
    assert_eq!(r.text(), "data:text/plain;name:hello.txt;base64,aGVsbG8=");
    let r = h.get(&format!("{base}x&metadataRequired=sure"), None).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);

    for url in ["/elsewhere/a.txt", "/api/files/static/file/", "/api/files/static/file/%2520/a"] {
        let r = h.get(&format!("{base}{url}"), None).await;
        assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR, "{url}");
        assert_eq!(r.message(), "File cannot be converted to base64", "{url}");
    }
    // CHILD does not manage CLIA.
    let r = h.get("/api/files/internal/static/convertToBase64?clientCode=CHILD&url=/api/files/static/file/CLIA/a.txt", None).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.message(), "Permission to STATIC resource in the path CLIA/a.txt is forbidden");
    // A folder.
    h.seed_detail(Kind::Static, "CLIA", "docs", folder(9, "docs")).await;
    let r = h.get(&format!("{base}/api/files/static/file/CLIA/docs"), None).await;
    assert_eq!((r.status, r.message().as_str()), (StatusCode::BAD_REQUEST, "Unable to convert $ to $"));
    // The client's own root is a folder too; an unknown file reaches the database.
    assert_eq!(h.get(&format!("{base}/api/files/static/file/CLIA"), None).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(h.get(&format!("{base}/api/files/static/file/CLIA/none.txt"), None).await.status, StatusCode::INTERNAL_SERVER_ERROR);
    // In the bucket's listing but gone from it.
    h.seed_detail(Kind::Static, "CLIA", "gone.txt", file(10, "gone.txt", 1, 1)).await;
    assert_eq!(h.get(&format!("{base}/api/files/static/file/CLIA/gone.txt"), None).await.status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn ai_uploader_keeps_an_existing_file() {
    let h = manage().await;
    h.state.inner().exists.insert("fsPathExists-STATIC-SYSTEM", "aiGen/CLIA/pic.png".to_string(), true).await;
    h.seed_detail(Kind::Static, "SYSTEM", "aiGen/CLIA/pic.png", file(90, "pic.png", 1, 1)).await;
    let r = h.form("/api/files/internal/aiUploader", None, &[FormPart::Text("clientCode", "CLIA"), FormPart::File("file", "pic.png", "image/png", png(2, 2))]).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.text(), "/api/files/static/file/SYSTEM/aiGen/CLIA/pic.png");
    assert_eq!(h.s3_calls("PUT"), 0);
}

#[tokio::test]
async fn billing_without_rows() {
    let h = manage().await;
    let r = h.call(Method::POST, "/api/files/internal/billing/meter", None).await;
    assert_eq!((r.status, r.text().as_str()), (StatusCode::OK, "true"));
    // A client to bill: its bytes are in the database (down here), which is logged and skipped.
    h.sec.world.lock().unwrap().instructions =
        json!([{"configClientId": 1, "billedClientId": 10, "appId": 2, "billedClientCode": "CLIA"}]);
    let r = h.call(Method::POST, "/api/files/internal/billing/reconcile?date=2026-06-15", None).await;
    assert_eq!(r.text(), "true");
    let r = h.call(Method::POST, "/api/files/internal/billing/reconcile", None).await;
    assert_eq!(r.text(), "true");
    assert!(h.sec.charges.lock().unwrap().is_empty());
    // Security answering something else than a list.
    h.sec.world.lock().unwrap().instructions = json!({"not": "a list"});
    assert_eq!(h.call(Method::POST, "/api/files/internal/billing/meter", None).await.text(), "true");
}

// ---------------------------------------------------------------------------------------------
// Access paths
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn access_path_bodies_and_callers() {
    let h = manage().await;
    let uri = "/api/files/accesspath";
    for (body, status, message) in [
        (json!({"path": "a"}), StatusCode::BAD_REQUEST, "Access can be given to a user, permission, or a role "),
        (json!({"userId": 5}), StatusCode::BAD_REQUEST, "Resource Type is/are missing"),
        (json!({"userId": "x", "resourceType": "STATIC"}), StatusCode::BAD_REQUEST, "userId field cannot be read"),
        (json!({"userId": 1, "resourceType": "OTHER"}), StatusCode::BAD_REQUEST, "resourceType field cannot be read"),
        (json!({"accessName": [1], "resourceType": "STATIC"}), StatusCode::BAD_REQUEST, "accessName field cannot be read"),
        (json!({"accessName": "A", "writeAccess": "maybe", "resourceType": "STATIC"}), StatusCode::BAD_REQUEST, "writeAccess field cannot be read"),
        (json!([1]), StatusCode::BAD_REQUEST, "Invalid body"),
        (json!({"accessName": "A", "resourceType": "SECURED"}), StatusCode::FORBIDDEN, "Permission/Role Authorities.SECURED_Files_PATH is required to use this operation "),
    ] {
        let r = h.json(Method::POST, uri, Some("child"), &body).await;
        assert_eq!(r.status, status, "{body}");
        assert_eq!(r.message(), message, "{body}");
    }
    // Allowed: the rule is written to the database.
    let r = h.json(Method::POST, uri, Some("clia"), &json!({"accessName": "A", "resourceType": "STATIC", "path": " /x "})).await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
    // Internal: no checks, but a client code.
    let r = h.json(Method::POST, "/api/files/internal/accesspath", None, &json!({"userId": 1, "resourceType": "STATIC"})).await;
    assert_eq!(r.message(), "clientCode is/are missing");
    let r = h.json(Method::POST, "/api/files/internal/accesspath", None, &json!({"userId": 1, "resourceType": "STATIC", "clientCode": "A"})).await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
    // Ids are numbers.
    for m in [Method::GET, Method::PUT, Method::PATCH, Method::DELETE] {
        let r = h.json(m.clone(), "/api/files/accesspath/abc", Some("clia"), &json!({})).await;
        assert_eq!((r.status, r.message().as_str()), (StatusCode::BAD_REQUEST, "Invalid id 'abc'"), "{m}");
        let r = h.json(m.clone(), "/api/files/accesspath/5", Some("clia"), &json!({})).await;
        assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR, "{m}");
    }
    let r = h.json(Method::PATCH, "/api/files/accesspath/5", Some("clia"), &json!([])).await;
    assert_eq!((r.status, r.message().as_str()), (StatusCode::BAD_REQUEST, "Invalid body"));
}

#[tokio::test]
async fn access_path_pages_check_the_callers_authorities() {
    let h = manage().await;
    let mut away = ca(503, 10, "CLIA", false, &["Authorities.STATIC_Files_PATH"]);
    away["loggedInFromClientId"] = json!(11);
    h.sec.token("away", away);
    h.sec.token("staticOnly", ca(504, 10, "CLIA", false, &["Authorities.STATIC_Files_PATH"]));
    h.sec.token("securedOnly", ca(505, 10, "CLIA", false, &["Authorities.SECURED_Files_PATH"]));

    let r = h.get("/api/files/accesspath", Some("away")).await;
    assert_eq!((r.status, r.message().as_str()), (StatusCode::FORBIDDEN, "Permission/Role  is required to use this operation "));
    let r = h.get("/api/files/accesspath", Some("child")).await;
    assert_eq!(r.message(), "Permission/Role STATIC Files PATH / SECURED Files PATH is required to use this operation ");
    let r = h.get("/api/files/accesspath?resourceType=SECURED", Some("staticOnly")).await;
    assert_eq!(r.message(), "Permission/Role SECURED Files PATH is required to use this operation ");
    let r = h.get("/api/files/accesspath?resourceType=STATIC", Some("securedOnly")).await;
    assert_eq!(r.message(), "Permission/Role STATIC Files PATH is required to use this operation ");
    // A filter value that does not convert is the caller's mistake.
    let r = h.get("/api/files/accesspath?id=abc", Some("staticOnly")).await;
    assert_eq!((r.status, r.message().as_str()), (StatusCode::BAD_REQUEST, "'abc' is not a number"));
    for token in ["staticOnly", "securedOnly", "sys"] {
        assert_eq!(h.get("/api/files/accesspath?page=1", Some(token)).await.status, StatusCode::INTERNAL_SERVER_ERROR);
    }
    let r = h.json(Method::POST, "/api/files/accesspath/query", Some("sys"), &json!({"size": 0})).await;
    assert_eq!((r.status, r.message().as_str()), (StatusCode::BAD_REQUEST, "Page size must not be less than one"));
    let r = h.json(Method::POST, "/api/files/accesspath/query", Some("sys"), &json!({"condition": {"value": 1}})).await;
    assert_eq!(r.message(), "Invalid condition");
    let r = h.json(Method::POST, "/api/files/accesspath/query", Some("sys"), &json!({"page": "x"})).await;
    assert_eq!(r.message(), "Invalid page");
    let r = h.json(Method::POST, "/api/files/accesspath/query", Some("sys"), &json!({"sort": {"direction": "UP", "property": "id"}})).await;
    assert_eq!(r.message(), "Invalid direction 'UP'");
    let r = h.json(Method::POST, "/api/files/accesspath/query", Some("sys"), &json!({"sort": [{"direction": "DESC"}]})).await;
    assert_eq!(r.message(), "Sort order without a property");
    let r = h
        .json(Method::POST, "/api/files/accesspath/query", Some("sys"), &json!({"sort": null, "condition": {"field": "path", "operator": "LIKE"}}))
        .await;
    assert_eq!(r.message(), "LIKE needs a value");
    let r = h
        .json(Method::POST, "/api/files/accesspath/query", Some("sys"), &json!({"sort": "x", "condition": {"field": "path", "value": "a"}}))
        .await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
}

// ---------------------------------------------------------------------------------------------
// Retention
// ---------------------------------------------------------------------------------------------

fn policy(id: u64, path: &str, cc: &str, level: &str, applies: &str, days: Option<u32>) -> PolicyRow {
    PolicyRow {
        id,
        app_code: "app".into(),
        client_code: cc.into(),
        resource_type: "SECURED".into(),
        path: path.into(),
        retention_days: days,
        applies_to: applies.into(),
        level: level.into(),
        created_by: None,
        created_at: None,
        updated_by: None,
        updated_at: None,
    }
}

async fn retention_harness() -> Harness {
    let h = manage().await;
    {
        let mut w = h.sec.world.lock().unwrap();
        w.clients.insert("OWNER".into(), 20);
        w.clients.insert("OTHER".into(), 30);
        w.clients.insert("CHILD2".into(), 31);
        w.manages.push(("OTHER".into(), "CHILD2".into()));
        w.apps.insert("app".into(), json!(20));
        w.hierarchy.insert("OTHER".into(), vec!["OTHER".into(), "SYSTEM".into()]);
        w.hierarchy.insert("CHILD2".into(), vec!["OTHER".into(), "SYSTEM".into()]);
    }
    h.sec.token("owner", ca(21, 20, "OWNER", false, &["Authorities.Files_RETENTION"]));
    h.sec.token("ownerReader", ca(22, 20, "OWNER", false, &["Authorities.Logged_IN"]));
    h.sec.token("other", ca(31, 30, "OTHER", false, &["Authorities.Files_RETENTION"]));
    h
}

/// `FilesRetentionServiceTest.missingRetentionAuthorityIsRefused`, and the other refusals that
/// come before the database.
#[tokio::test]
async fn retention_writes_need_the_authority_and_a_valid_body() {
    let h = retention_harness().await;
    let row = json!({"appCode": "app", "resourceType": "SECURED", "level": "APP", "path": "/whatsapp/incoming/", "retentionDays": 30});
    let r = h.json(Method::POST, "/api/files/retention", Some("ownerReader"), &row).await;
    assert_eq!((r.status, r.message().as_str()), (StatusCode::FORBIDDEN, "Permission/Role Authorities.Files_RETENTION is required to use this operation "));
    let r = h.get("/api/files/retention/preview?appCode=app&resourceType=SECURED&path=whatsapp/incoming&days=30", Some("ownerReader")).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    for m in [Method::PUT, Method::DELETE] {
        assert_eq!(h.json(m, "/api/files/retention/5", Some("ownerReader"), &json!({})).await.status, StatusCode::FORBIDDEN);
    }

    for (body, message) in [
        (Value::Null, "body is/are missing"),
        (json!({"resourceType": "SECURED", "level": "APP"}), "appCode is/are missing"),
        (json!({"appCode": " ", "resourceType": "SECURED", "level": "APP"}), "appCode is/are missing"),
        (json!({"appCode": "app", "level": "APP"}), "resourceType is/are missing"),
        (json!({"appCode": "app", "resourceType": "BOTH", "level": "APP"}), "Invalid resourceType: \"BOTH\""),
        (json!({"appCode": "app", "resourceType": "SECURED"}), "level is/are missing"),
        (json!({"appCode": "app", "resourceType": "SECURED", "level": "APP", "appliesTo": "ALL"}), "Invalid appliesTo: \"ALL\""),
        (json!({"appCode": "app", "resourceType": "SECURED", "level": "APP", "path": "a/../b"}), "Invalid path: a/../b"),
        (json!({"appCode": "app", "resourceType": "SECURED", "level": "APP", "retentionDays": 0}), "Invalid retentionDays: 0"),
        (json!({"appCode": "app", "resourceType": "SECURED", "level": "APP", "retentionDays": "x"}), "Invalid retentionDays"),
        (json!({"appCode": "app", "resourceType": "SECURED", "level": "APP", "retentionDays": 1.5}), "Invalid retentionDays"),
        (json!({"appCode": "app", "resourceType": "SECURED", "level": "APP", "retentionDays": true}), "Invalid retentionDays"),
    ] {
        let r = h.json(Method::POST, "/api/files/retention", Some("owner"), &body).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(r.message(), message, "{body}");
    }

    // APP rows: only the app's owner; an unknown (or unreadable) app is a 404.
    let r = h.json(Method::POST, "/api/files/retention", Some("other"), &row).await;
    assert_eq!((r.status, r.message().as_str()), (StatusCode::FORBIDDEN, "Permission/Role owner of the app app is required to use this operation "));
    for app in ["nope", "boom"] {
        let mut b = row.clone();
        b["appCode"] = json!(app);
        let r = h.json(Method::POST, "/api/files/retention", Some("owner"), &b).await;
        assert_eq!((r.status, r.message()), (StatusCode::NOT_FOUND, format!("App with id {app} not found")));
    }
    // CLIENT rows: the caller's client or one it manages.
    let client_row = json!({"appCode": "app", "resourceType": "SECURED", "level": "CLIENT", "path": "whatsapp/incoming", "retentionDays": "10", "clientCode": "STRANGER"});
    let r = h.json(Method::POST, "/api/files/retention", Some("other"), &client_row).await;
    assert_eq!((r.status, r.message().as_str()), (StatusCode::FORBIDDEN, "Permission/Role manager of the client STRANGER is required to use this operation "));
    let r = h.json(Method::POST, "/api/files/retention", Some("other"), &json!({"appCode": "app", "resourceType": "SECURED", "level": "CLIENT", "clientCode": "NOBODY"})).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    // Allowed so far: the registered prefix is checked in the database.
    let mut managed = client_row.clone();
    managed["clientCode"] = json!("CHILD2");
    assert_eq!(h.json(Method::POST, "/api/files/retention", Some("other"), &managed).await.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(h.json(Method::POST, "/api/files/retention", Some("owner"), &row).await.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(h.json(Method::PUT, "/api/files/retention/5", Some("owner"), &json!({"retentionDays": 3})).await.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(h.call(Method::DELETE, "/api/files/retention/5", Some("owner")).await.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(h.call(Method::DELETE, "/api/files/retention/x", Some("owner")).await.status, StatusCode::BAD_REQUEST);
}

/// `FilesRetentionServiceTest.readingWhatAppliesNeedsOnlyASignedInUserWithAccessToTheClient`,
/// with the app's rows already cached.
#[tokio::test]
async fn effective_retention_from_cached_rows() {
    let h = retention_harness().await;
    let rows = vec![
        policy(1, "whatsapp/incoming", "OWNER", "APP", "SELF", Some(30)),
        policy(2, "whatsapp/incoming", "OTHER", "CLIENT", "SELF", Some(7)),
        policy(3, "whatsapp/incoming", "OTHER", "CLIENT", "MANAGED", None),
        policy(4, "docs", "OWNER", "APP", "SELF", None),
    ];
    let inner = h.state.inner();
    inner.retention_rows.insert("filesRetentionPolicies", "app:SECURED".to_string(), rows).await;
    inner.retention_rows.insert("filesRetentionPolicies", "app:STATIC".to_string(), vec![]).await;

    let r = h.get("/api/files/retention/effective?appCode=app&resourceType=secured", Some("other")).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(
        r.json(),
        json!([
            {"appCode": "app", "clientCode": "OTHER", "resourceType": "SECURED", "path": "whatsapp/incoming", "days": 7,
             "keepForever": false, "source": "OWN", "appPolicyId": 1, "appDays": 30, "ownPolicyId": 2, "ownDays": 7,
             "managedPolicyId": 3},
            {"appCode": "app", "clientCode": "OTHER", "resourceType": "SECURED", "path": "docs", "keepForever": true,
             "source": "APP", "appPolicyId": 4}
        ])
    );
    // A managed client: its manager's MANAGED row (keep forever) applies; both types by default.
    let r = h.get("/api/files/retention/effective?appCode=app&clientCode=CHILD2", Some("other")).await;
    let v = r.json();
    assert_eq!(v[0]["clientCode"], "CHILD2");
    assert_eq!(v[0]["source"], "MANAGER:OTHER");
    assert_eq!(v[0]["keepForever"], true);
    // Reading needs no retention authority, only access to the client.
    h.sec.world.lock().unwrap().hierarchy.insert("OWNER".into(), vec!["SYSTEM".into()]);
    let r = h.get("/api/files/retention/effective?appCode=app", Some("ownerReader")).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.json()[0]["source"], "APP");
    let r = h.get("/api/files/retention/effective?appCode=app&clientCode=STRANGER", Some("ownerReader")).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);

    let r = h.get("/api/files/retention/effective", Some("other")).await;
    assert_eq!((r.status, r.message().as_str()), (StatusCode::BAD_REQUEST, "appCode is/are missing"));
    let r = h.get("/api/files/retention/effective?appCode=app&resourceType=both", Some("other")).await;
    assert_eq!(r.message(), "Invalid resourceType: both");
    // A client security does not know, or cannot answer for.
    h.sec.world.lock().unwrap().clients.insert("BOOM".into(), 40);
    h.sec.world.lock().unwrap().manages.push(("OTHER".into(), "BOOM".into()));
    h.sec.world.lock().unwrap().manages.push(("OTHER".into(), "LOST".into()));
    h.sec.world.lock().unwrap().clients.insert("LOST".into(), 41);
    let r = h.get("/api/files/retention/effective?appCode=app&clientCode=LOST", Some("other")).await;
    assert_eq!((r.status, r.message().as_str()), (StatusCode::NOT_FOUND, "Unknown client LOST"));
    let r = h.get("/api/files/retention/effective?appCode=app&clientCode=BOOM", Some("other")).await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
    // Listing reads every row of the app from the database.
    assert_eq!(h.get("/api/files/retention?appCode=app", Some("other")).await.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(h.get("/api/files/retention", Some("other")).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(h.get("/api/files/retention?appCode=app&clientCode=STRANGER", Some("other")).await.status, StatusCode::FORBIDDEN);
}

/// `FilesRetentionServiceTest.previewWithoutAFolderFindsNothingAndKeepForeverReadsNothing`, the
/// half that needs no folder lookup.
#[tokio::test]
async fn preview_from_cached_rows() {
    let h = retention_harness().await;
    let rows = vec![policy(1, "whatsapp/incoming", "OWNER", "APP", "SELF", None), policy(5, "docs", "OWNER", "APP", "SELF", Some(9))];
    h.state.inner().retention_rows.insert("filesRetentionPolicies", "app:SECURED".to_string(), rows).await;
    let base = "/api/files/retention/preview?appCode=app&resourceType=secured";

    let r = h.get(&format!("{base}&path=whatsapp/incoming/sub"), Some("other")).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(
        r.json(),
        json!({"appCode": "app", "clientCode": "OTHER", "resourceType": "SECURED", "path": "whatsapp/incoming/sub",
               "source": "APP", "count": 0, "totalBytes": 0})
    );
    // No registered prefix covers the path.
    let r = h.get(&format!("{base}&path=other"), Some("other")).await;
    assert_eq!(r.json(), json!({"appCode": "app", "clientCode": "OTHER", "resourceType": "SECURED", "path": "other", "count": 0, "totalBytes": 0}));

    for (q, status, message) in [
        ("&days=0", StatusCode::BAD_REQUEST, "Invalid retentionDays: 0"),
        ("&days=x", StatusCode::BAD_REQUEST, "Invalid value 'x' for parameter 'days'"),
        ("&path=..", StatusCode::BAD_REQUEST, "Invalid path: .."),
        ("&clientCode=STRANGER", StatusCode::FORBIDDEN, "Permission/Role manager of the client STRANGER is required to use this operation "),
    ] {
        let r = h.get(&format!("{base}{q}"), Some("other")).await;
        assert_eq!((r.status, r.message().as_str()), (status, message), "{q}");
    }
    let r = h.get("/api/files/retention/preview?resourceType=secured", Some("other")).await;
    assert_eq!(r.message(), "appCode is/are missing");
    let r = h.get("/api/files/retention/preview?appCode=app", Some("other")).await;
    assert_eq!(r.message(), "Invalid resourceType: null");
    // A number of days, or a covering prefix with days, looks for the folder in the database.
    assert_eq!(h.get(&format!("{base}&days=5"), Some("other")).await.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(h.get(&format!("{base}&path=docs/a"), Some("other")).await.status, StatusCode::INTERNAL_SERVER_ERROR);
}
