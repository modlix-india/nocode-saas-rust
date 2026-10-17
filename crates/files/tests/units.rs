//! The library's pieces called directly, over the in-process bucket and security service (no
//! database: where one would be reached, these tests would fail, which is the point of several).

mod common;

use axum::http::{Method, StatusCode};
use common::*;
use files::access::{can_read_secured, has_read_access, has_write_access, is_client_being_managed, sub_client_list_access};
use files::fs::{Fs, TempDir};
use files::fsdao::ExpiredFile;
use files::paths::Kind;
use files::Unit;
use platform::security::ContextAuthentication;
use serde_json::json;

fn signed_in(code: &str) -> ContextAuthentication {
    serde_json::from_value(ca(1, 1, code, false, &[])).unwrap()
}

const LONG_CODE: &str = "AVERYLONGCLIENTCODE01";

/// `SecuredFirstFolderAccessTest`: the first folder after the client code decides special
/// access, whatever the length of the client code. The database here refuses every query, so a
/// pass can only come from the special folder (Java mocks the path rules to refuse).
#[tokio::test]
async fn secured_first_folder_access_test() {
    let h = Harness::new(Unit::Serve).await;
    let st = &h.state;
    // withInClientIsFoundForALongClientCode
    assert!(can_read_secured(st, &signed_in(LONG_CODE), &format!("{LONG_CODE}/_withInClient/report.pdf")).await.unwrap());
    // withInClientIsFoundBeneathASubFolder
    assert!(can_read_secured(st, &signed_in(LONG_CODE), &format!("{LONG_CODE}/_withInClient/2026/report.pdf")).await.unwrap());
    // withInClientStillRefusesAnotherClient
    assert!(!can_read_secured(st, &signed_in("OTHERCL1"), &format!("{LONG_CODE}/_withInClient/report.pdf")).await.unwrap());
    // shortClientCodeStillWorks
    assert!(can_read_secured(st, &signed_in("CLIENT01"), "CLIENT01/_withInClient/2026/report.pdf").await.unwrap());
}

#[tokio::test]
async fn access_checks_that_stop_before_the_rules() {
    let h = Harness::new(Unit::Manage).await;
    let st = &h.state;
    let child: ContextAuthentication = serde_json::from_value(ca(600, 11, "CHILD", false, &[])).unwrap();
    // A bare client code: the client's root, which CHILD does not manage.
    assert!(!can_read_secured(st, &child, "CLIA").await.unwrap());
    assert!(!has_read_access(st, &child, "x/", "CLIA", Kind::Static).await.unwrap());
    assert!(!has_read_access(st, &child, "x", "NOPE", Kind::Secured).await.unwrap());
    assert!(!has_write_access(st, &child, "x", "CLIA", Kind::Static).await.unwrap());
    assert!(!has_write_access(st, &child, "x", "NOPE", Kind::Static).await.unwrap());
    assert!(!sub_client_list_access(st, &child, "  ", "CLIA").await.unwrap());
    assert!(sub_client_list_access(st, &child, "/_withInSubClient/a", "CLIA").await.unwrap());
    assert!(!sub_client_list_access(st, &child, "_withInSubClient", "CHILD").await.unwrap());
    assert!(is_client_being_managed(st, "CLIA", "CLIA").await.unwrap());
    assert!(is_client_being_managed(st, "CLIA", "CHILD").await.unwrap());
    assert!(!is_client_being_managed(st, "CHILD", "CLIA").await.unwrap());
}

#[tokio::test]
async fn file_system_pieces_without_rows() {
    let h = Harness::new(Unit::Manage).await;
    let fs = Fs::new(&h.state, Kind::Static);
    assert!(fs.exists("CLIA", "").await.unwrap());
    assert!(fs.exists("CLIA", "/").await.unwrap());

    // A bare client code: no object key with a folder, no row.
    h.put_object(Kind::Static, "CLIA", b"x");
    assert!(!fs.delete("CLIA").await.unwrap());
    assert!(h.object(Kind::Static, "CLIA").is_none());

    // Files of the other type are never removed from this bucket.
    h.put_object(Kind::Secured, "CLIA/a.txt", b"a");
    let other = ExpiredFile { id: 1, client_code: "CLIA".into(), kind: Kind::Secured, path: "/a.txt".into() };
    assert!(fs.delete_files(vec![other]).await.is_empty());
    assert!(h.object(Kind::Secured, "CLIA/a.txt").is_some());
    assert_eq!(h.s3_calls("DELETE test-secured"), 0);
    // A file whose object cannot be removed stays, row and all (no database call is made).
    let stuck = ExpiredFile { id: 2, client_code: "CLIA".into(), kind: Kind::Static, path: "/s3fail.txt".into() };
    assert!(fs.delete_files(vec![stuck]).await.is_empty());

    // A folder as a zip: entries relative to it, folder markers left out.
    for (k, b) in [("CLIA/site/a.txt", "a"), ("CLIA/site/", ""), ("CLIA/site/sub/", ""), ("CLIA/site/sub/b.txt", "b"), ("CLIA/sitemap.txt", "m")] {
        h.put_object(Kind::Static, k, b.as_bytes());
    }
    let dir = TempDir::new(&h.state, "units").unwrap();
    let zip = fs.directory_archive("/CLIA/site", &dir).await.unwrap();
    let mut archive = zip::ZipArchive::new(std::fs::File::open(&zip).unwrap()).unwrap();
    let mut names: Vec<String> = (0..archive.len()).map(|i| archive.by_index(i).unwrap().name().to_string()).collect();
    names.sort();
    assert_eq!(names, vec!["a.txt", "sub/b.txt"]);
    // An object that cannot be read fails the archive.
    h.put_object(Kind::Static, "CLIA/bad/s3fail.txt", b"x");
    let dir2 = TempDir::new(&h.state, "units").unwrap();
    assert!(fs.directory_archive("CLIA/bad/", &dir2).await.is_err());
    let fetched = fs.fetch("CLIA/site/a.txt", &dir).await.unwrap();
    assert_eq!(std::fs::read(fetched).unwrap(), b"a");
    let path = dir.path.clone();
    drop(dir);
    assert!(!path.exists(), "a temp dir goes with its handle");
    assert_eq!(files::fs::mime_of("x.html"), "text/html");
}

#[tokio::test]
async fn the_store_and_its_disk_copies() {
    let h = Harness::new(Unit::Serve).await;
    let store = h.state.store(Kind::Static);

    h.put_object(Kind::Static, "CLIA/v/f.txt", b"one");
    let first = store.get_as_file("CLIA/v/f.txt", 1, false).await.unwrap();
    assert_eq!(std::fs::read(&first).unwrap(), b"one");
    // A new version replaces the old copy.
    h.put_object(Kind::Static, "CLIA/v/f.txt", b"two");
    let second = store.get_as_file("CLIA/v/f.txt", 2, false).await.unwrap();
    assert_eq!(std::fs::read(&second).unwrap(), b"two");
    assert!(!first.exists());
    // The same version is served from disk, unless forced.
    h.put_object(Kind::Static, "CLIA/v/f.txt", b"three");
    assert_eq!(std::fs::read(store.get_as_file("CLIA/v/f.txt", 2, false).await.unwrap()).unwrap(), b"two");
    assert_eq!(std::fs::read(store.get_as_file("CLIA/v/f.txt", 2, true).await.unwrap()).unwrap(), b"three");

    // Dropping one object's copies leaves its neighbours.
    h.put_object(Kind::Static, "CLIA/v/g.txt", b"g");
    let g = store.get_as_file("CLIA/v/g.txt", 5, false).await.unwrap();
    store.drop_local_copies("CLIA//v/f.txt").await;
    assert!(!second.exists() && g.exists());
    for key in ["CLIA/v/", "nofolder", "CLIA/none/x.txt"] {
        store.drop_local_copies(key).await;
    }
    assert!(g.exists());

    // Failures: no folder in the key, nothing in the bucket (and no part file left behind).
    assert!(store.get_as_file("nofolder", 1, false).await.is_err());
    assert!(store.get_as_file("CLIA/v/missing.txt", 1, false).await.is_err());
    let leftovers = std::fs::read_dir(g.parent().unwrap()).unwrap().filter(|e| e.as_ref().unwrap().file_name().to_string_lossy().starts_with('.')).count();
    assert_eq!(leftovers, 0);

    // Writes and listings.
    let local = h.dir.join("raw.bin");
    std::fs::write(&local, b"raw").unwrap();
    store.put_file("CLIA/raw.bin", &local, 3, None, "inline").await.unwrap();
    assert_eq!(h.object(Kind::Static, "CLIA/raw.bin").unwrap().bytes, b"raw");
    assert!(store.put_file("CLIA/x.bin", &h.dir.join("absent"), 1, None, "inline").await.is_err());
    assert!(store.put_file("CLIA/s3fail.bin", &local, 3, Some("text/plain"), "inline").await.is_err());
    assert!(store.delete_object("CLIA/s3fail").await.is_err());
    assert!(store.list_objects("s3fail/").await.is_err());
    let all = store.list_objects("").await.unwrap();
    assert_eq!(all.len(), 3);
    assert!(all.contains(&("CLIA/raw.bin".to_string(), 3)));
    assert_eq!(files::store::collapse_slashes("//a"), "/a");
}

#[tokio::test]
async fn app_owners_as_security_sends_them() {
    let h = Harness::new(Unit::Manage).await;
    {
        let mut w = h.sec.world.lock().unwrap();
        w.apps.insert("strapp".into(), json!("20"));
        w.apps.insert("ownerless".into(), serde_json::Value::Null);
        w.clients.insert("OWNER".into(), 20);
    }
    h.sec.token("owner", ca(21, 20, "OWNER", false, &["Authorities.Files_RETENTION"]));
    let body = |app: &str| json!({"appCode": app, "resourceType": "STATIC", "level": "APP", "retentionDays": 3});
    // An owner sent as a string still owns the app: the next step reads the database.
    let r = h.json(Method::POST, "/api/files/retention", Some("owner"), &body("strapp")).await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
    let r = h.json(Method::POST, "/api/files/retention", Some("owner"), &body("ownerless")).await;
    assert_eq!((r.status, r.message().as_str()), (StatusCode::FORBIDDEN, "Permission/Role owner of the app ownerless is required to use this operation "));
    // A caller with no client id owns nothing.
    h.sec.token("clientless", ca(22, 0, "OWNER", false, &["Authorities.Files_RETENTION"]));
    h.sec.world.lock().unwrap().apps.insert("zero".into(), json!(0));
    let r = h.json(Method::POST, "/api/files/retention", Some("clientless"), &body("zero")).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
}
