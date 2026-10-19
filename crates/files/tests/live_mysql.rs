//! files against a real MySQL: each test makes a scratch database (`files_rusttest_*`, the
//! tables' DDL read from the local `files` schema, which is never written) and drops it again.
//! The bucket and security are the in-process fakes.
//!
//! Gated: `#[ignore]`, and runs only with `FILES_TEST_MYSQL=1` and `MODLIX__DATABASE__PASSWORD`:
//!
//! ```text
//! eval "$(tools/local-env.py)"
//! FILES_TEST_MYSQL=1 cargo test -p files --test live_mysql -- --ignored
//! ```

mod common;

use axum::http::{Method, StatusCode};
use common::*;
use files::dao::Dao;
use files::paths::Kind;
use files::Unit;
use serde_json::{json, Value};
use sqlx::{MySqlPool, Row};

async fn exec(pool: &MySqlPool, sql: &str) {
    sqlx::query(sql).execute(pool).await.unwrap_or_else(|e| panic!("{sql}: {e}"));
}

async fn scalar_i64(pool: &MySqlPool, sql: &str) -> i64 {
    sqlx::query(sql).fetch_one(pool).await.unwrap().try_get::<i64, _>(0).unwrap()
}

/// Moves a row's last write `days` days (and `hours` hours) into the past.
async fn age(pool: &MySqlPool, id: u64, days: i64, hours: i64) {
    sqlx::query("UPDATE files_file_system SET UPDATED_AT = UTC_TIMESTAMP() - INTERVAL ? DAY - INTERVAL ? HOUR WHERE ID = ?")
        .bind(days)
        .bind(hours)
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
}

async fn file_row(dao: &Dao, kind: Kind, cc: &str, path: &str, size: u64, expires: Option<u32>) -> u64 {
    let name = path.rsplit('/').next().unwrap();
    dao.create_or_update_file(kind, cc, path, Some(name), size, false, expires).await.unwrap().unwrap().id
}

// ---------------------------------------------------------------------------------------------
// FileSystemDaoOverwriteTest
// ---------------------------------------------------------------------------------------------

/// Overwriting stores the new size, takes `UPDATED_AT` from the database clock, and touches
/// only the row of that client and file system type.
#[tokio::test]
#[ignore = "needs the local MySQL (FILES_TEST_MYSQL=1, MODLIX__DATABASE__PASSWORD)"]
async fn overwrite_updates_size_and_time_of_that_row_only() {
    with_scratch(|pool| async move {
        let dao = Dao::new(pool.clone());
        let id = file_row(&dao, Kind::Secured, "SYSTEM", "_userImages/142.png", 156, None).await;
        let static_twin = file_row(&dao, Kind::Static, "SYSTEM", "_userImages/142.png", 156, None).await;
        let other_client = file_row(&dao, Kind::Secured, "CLIA", "_userImages/142.png", 156, None).await;
        for i in [id, static_twin, other_client] {
            age(&pool, i, 1, 0).await;
        }

        let fd = dao
            .create_or_update_file(Kind::Secured, "SYSTEM", "_userImages/142.png", Some("142.png"), 110, true, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fd.id, id);
        assert_eq!(fd.size, 110, "the response carries the size just written");
        let now = scalar_i64(&pool, "SELECT CAST(UNIX_TIMESTAMP() AS SIGNED)").await;
        assert!((now - fd.last_modified).abs() <= 5, "UPDATED_AT is the database's now");

        for other in [static_twin, other_client] {
            let r = sqlx::query("SELECT SIZE, CAST(UNIX_TIMESTAMP(UPDATED_AT) AS SIGNED) AS T FROM files_file_system WHERE ID = ?")
                .bind(other)
                .fetch_one(&pool)
                .await
                .unwrap();
            assert_eq!(r.get::<Option<u64>, _>("SIZE"), Some(156));
            assert!(now - r.get::<i64, _>("T") > 80_000);
        }
    })
    .await;
}

/// A stale "exists" must not leave the uploaded object without a row.
#[tokio::test]
#[ignore = "needs the local MySQL (FILES_TEST_MYSQL=1, MODLIX__DATABASE__PASSWORD)"]
async fn an_overwrite_that_matches_no_row_inserts_one() {
    with_scratch(|pool| async move {
        let dao = Dao::new(pool.clone());
        let fd = dao
            .create_or_update_file(Kind::Secured, "SYSTEM", "_userImages/142.png", Some("142.png"), 110, true, Some(5))
            .await
            .unwrap()
            .unwrap();
        assert_eq!((fd.name.as_str(), fd.size, fd.is_directory), ("142.png", 110, false));
        assert_eq!(scalar_i64(&pool, "SELECT COUNT(*) FROM files_file_system WHERE FILE_TYPE = 'FILE'").await, 1);
        assert_eq!(
            scalar_i64(&pool, "SELECT CAST(EXPIRES_AFTER_MINUTES AS SIGNED) FROM files_file_system WHERE FILE_TYPE = 'FILE'").await,
            5
        );
        // A name given without a folder is the whole path's last segment.
        let fd = dao.create_or_update_file(Kind::Static, "SYSTEM", "top.txt", Some("other.txt"), 1, false, None).await.unwrap().unwrap();
        assert_eq!(fd.name, "top.txt");
        let refused = dao.create_or_update_file(Kind::Static, "SYSTEM", "a/null", None, 1, false, None).await;
        assert!(refused.is_err());
    })
    .await;
}

/// The driver hands back the true instant: sessions are UTC.
#[tokio::test]
#[ignore = "needs the local MySQL (FILES_TEST_MYSQL=1, MODLIX__DATABASE__PASSWORD)"]
async fn stored_times_are_the_true_instant() {
    with_scratch(|pool| async move {
        let dao = Dao::new(pool.clone());
        let id = file_row(&dao, Kind::Static, "SYSTEM", "t.txt", 1, None).await;
        sqlx::query("UPDATE files_file_system SET CREATED_AT = '2026-10-04 16:31:14', UPDATED_AT = '2026-10-04 16:34:38' WHERE ID = ?")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
        let fd = dao.file_detail(Kind::Static, "SYSTEM", &["t.txt"]).await.unwrap().unwrap();
        assert_eq!(fd.last_modified, 1_791_131_678);
        assert_eq!(fd.created, 1_791_131_474);
    })
    .await;
}

// ---------------------------------------------------------------------------------------------
// FileSystemDaoRetentionTest
// ---------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs the local MySQL (FILES_TEST_MYSQL=1, MODLIX__DATABASE__PASSWORD)"]
async fn read_expired_is_scoped_to_the_file_system_type() {
    with_scratch(|pool| async move {
        let dao = Dao::new(pool.clone());
        let secured = file_row(&dao, Kind::Secured, "C1", "tmp/a/s.txt", 1, Some(1)).await;
        let stat = file_row(&dao, Kind::Static, "C1", "tmp/a/s.txt", 1, Some(1)).await;
        let fresh = file_row(&dao, Kind::Secured, "C1", "tmp/fresh.txt", 1, Some(600)).await;
        let forever = file_row(&dao, Kind::Secured, "C1", "tmp/keep.txt", 1, None).await;
        for id in [secured, stat, fresh, forever] {
            age(&pool, id, 0, 2).await;
        }
        let expired = dao.read_expired(Kind::Secured, 50).await.unwrap();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].id, secured);
        assert_eq!(expired[0].client_code, "C1");
        assert_eq!(expired[0].kind, Kind::Secured);
        assert_eq!(expired[0].path, "/tmp/a/s.txt");
        assert_eq!(dao.read_expired(Kind::Static, 50).await.unwrap()[0].id, stat);
        assert!(dao.read_expired(Kind::Static, 0).await.unwrap().is_empty());
    })
    .await;
}

/// Only files without their own lifetime, older than the policy, inside one client's folder and
/// outside the excluded (nested prefix) folders.
#[tokio::test]
#[ignore = "needs the local MySQL (FILES_TEST_MYSQL=1, MODLIX__DATABASE__PASSWORD)"]
async fn retention_selection_skips_own_lifetimes_and_stays_in_the_client() {
    with_scratch(|pool| async move {
        let dao = Dao::new(pool.clone());
        let old = file_row(&dao, Kind::Static, "C1", "app/whatsapp/incoming/sub/a.jpg", 10, None).await;
        let own_lifetime = file_row(&dao, Kind::Static, "C1", "app/whatsapp/incoming/b.jpg", 20, Some(60 * 24 * 365)).await;
        let recent = file_row(&dao, Kind::Static, "C1", "app/whatsapp/incoming/new.jpg", 30, None).await;
        let nested1 = file_row(&dao, Kind::Static, "C1", "app/whatsapp/incoming/x1/n.jpg", 40, None).await;
        let nested2 = file_row(&dao, Kind::Static, "C1", "app/whatsapp/incoming/x2/n.jpg", 50, None).await;
        let other_client = file_row(&dao, Kind::Static, "C2", "app/whatsapp/incoming/sub/a.jpg", 60, None).await;
        let other_type = file_row(&dao, Kind::Secured, "C1", "app/whatsapp/incoming/sub/z.jpg", 70, None).await;
        for id in [old, own_lifetime, nested1, nested2, other_client, other_type] {
            age(&pool, id, 40, 0).await;
        }
        let _ = recent;
        let root = dao.read_root_folder_id(Kind::Static, "C1", "app").await.unwrap().unwrap();
        let segs = |p: &str| p.split('/').map(str::to_string).collect::<Vec<_>>();
        let folder = dao.read_sub_folder_id(Kind::Static, "C1", root, &segs("whatsapp/incoming")).await.unwrap().unwrap();
        let x1 = dao.read_sub_folder_id(Kind::Static, "C1", root, &segs("whatsapp/incoming/x1")).await.unwrap().unwrap();
        let x2 = dao.read_sub_folder_id(Kind::Static, "C1", root, &segs("whatsapp/incoming/x2")).await.unwrap().unwrap();
        // A file is not a folder, and a missing segment is nothing.
        assert_eq!(dao.read_sub_folder_id(Kind::Static, "C1", root, &segs("whatsapp/incoming/new.jpg")).await.unwrap(), None);
        assert_eq!(dao.read_sub_folder_id(Kind::Static, "C1", root, &segs("nope/deeper")).await.unwrap(), None);
        assert_eq!(dao.read_root_folder_id(Kind::Static, "C3", "app").await.unwrap(), None);

        let files = dao
            .read_retention_expired(Kind::Static, "C1", folder, "/app/whatsapp/incoming", &[x1, x2], 30, 25)
            .await
            .unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].id, old);
        assert_eq!(files[0].path, "/app/whatsapp/incoming/sub/a.jpg");
        assert_eq!((files[0].client_code.as_str(), files[0].kind), ("C1", Kind::Static));
        assert_eq!(dao.count_retention_expired(Kind::Static, "C1", folder, &[x1, x2], 30).await.unwrap(), (1, 10));
        // Without the exclusions the nested folders' files are in, oldest first.
        let all = dao.read_retention_expired(Kind::Static, "C1", folder, "/f", &[], 30, 25).await.unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(dao.count_retention_expired(Kind::Static, "C1", folder, &[], 30).await.unwrap(), (3, 100));
        // A limit of zero reads nothing.
        assert!(dao.read_retention_expired(Kind::Static, "C1", folder, "/f", &[], 30, 0).await.unwrap().is_empty());
        // The app root folders, one per client.
        let roots = dao.read_app_root_folders(Kind::Static, "app").await.unwrap();
        assert_eq!(roots.iter().map(|(c, _)| c.as_str()).collect::<Vec<_>>(), vec!["C1", "C2"]);
    })
    .await;
}

// ---------------------------------------------------------------------------------------------
// The service over a real database
// ---------------------------------------------------------------------------------------------

async fn service(pool: MySqlPool) -> Harness {
    Harness::with_pool(Unit::Manage, pool).await
}

/// Access rules through the internal route (no checks there).
async fn rule(h: &Harness, body: Value) -> Value {
    let r = h.json(Method::POST, "/api/files/internal/accesspath", None, &body).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    r.json()
}

/// Everyone signed in (`Logged_IN`) may write anywhere in CLIA, static and secured.
async fn clia_writable(h: &Harness) {
    for t in ["STATIC", "SECURED"] {
        rule(h, json!({"clientCode": "CLIA", "accessName": "Authorities.Logged_IN", "resourceType": t, "path": "", "writeAccess": true, "allowSubPathAccess": true})).await;
    }
}

fn names(page: &Value) -> Vec<String> {
    page["content"].as_array().map(|a| a.iter().map(|e| e["name"].as_str().unwrap_or("").to_string()).collect()).unwrap_or_default()
}

#[tokio::test]
#[ignore = "needs the local MySQL (FILES_TEST_MYSQL=1, MODLIX__DATABASE__PASSWORD)"]
async fn folders_uploads_listings_downloads_and_deletes() {
    with_scratch(|pool| async move {
        let h = service(pool.clone()).await;
        clia_writable(&h).await;

        let r = h.call(Method::POST, "/api/files/static/directory/docs/2026", Some("clia")).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.text());
        let dir = r.json();
        assert_eq!((dir["name"].as_str(), dir["directory"].as_bool()), (Some("2026"), Some(true)));
        // Again: nothing new, the same folder.
        let again = h.call(Method::POST, "/api/files/static/directory/docs/2026", Some("clia")).await.json();
        assert_eq!(again["id"], dir["id"]);
        assert_eq!(scalar_i64(&pool, "SELECT COUNT(*) FROM files_file_system WHERE FILE_TYPE = 'DIRECTORY'").await, 2);
        // A folder that is no name.
        let r = h.call(Method::POST, "/api/files/static/directory/docs/undefined", Some("clia")).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST);

        let upload = |name: &'static str, body: &'static [u8], extra: Vec<FormPart<'static>>| {
            let h = &h;
            async move {
                let mut parts = extra;
                parts.push(FormPart::File("file", name, "text/plain", body.to_vec()));
                h.form("/api/files/static/docs/2026", Some("clia"), &parts).await
            }
        };
        let r = upload("a.txt", b"first", vec![]).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.text());
        let a = r.json();
        assert_eq!(a["filePath"], "/docs/2026/a.txt");
        assert_eq!(a["url"], "api/files/static/file/CLIA/docs/2026/a.txt");
        assert_eq!(a["size"], 5);
        assert_eq!(h.object(Kind::Static, "CLIA/docs/2026/a.txt").unwrap().bytes, b"first");
        let r = upload("a.txt", b"x", vec![FormPart::Text("name", "report")]).await;
        assert_eq!(r.json()["name"], "report.txt");
        // Static overwrites by default; the row keeps its id and takes the new size.
        let r = upload("a.txt", b"second!", vec![]).await;
        assert_eq!((r.json()["id"].clone(), r.json()["size"].clone()), (a["id"].clone(), json!(7)));
        // Unless told not to: the existing row is the answer and nothing is written.
        let r = upload("a.txt", b"third", vec![FormPart::Text("override", "false")]).await;
        assert_eq!(r.json()["size"], 7);
        assert_eq!(h.object(Kind::Static, "CLIA/docs/2026/a.txt").unwrap().bytes, b"second!");

        // Listing.
        let list = |q: &'static str| {
            let h = &h;
            async move {
                let r = h.get(&format!("/api/files/static/docs/2026{q}"), Some("clia")).await;
                assert_eq!(r.status, StatusCode::OK, "{q}: {}", r.text());
                r.json()
            }
        };
        let page = list("").await;
        assert_eq!(names(&page), vec!["a.txt", "report.txt"]);
        assert_eq!(page["totalElements"], 2);
        assert_eq!(page["content"][0]["url"], "api/files/static/file/CLIA/docs/2026/a.txt");
        assert_eq!(names(&list("?size=200").await), vec!["a.txt", "report.txt"]);
        assert_eq!(names(&list("?size=200").await), vec!["a.txt", "report.txt"], "the cached first page");
        assert_eq!(names(&list("?sort=name,desc").await), vec!["report.txt", "a.txt"]);
        assert_eq!(names(&list("?sort=size&sort=lastModified,desc&sort=created&sort=type").await), vec!["report.txt", "a.txt"]);
        assert_eq!(names(&list("?filter=rep").await), vec!["report.txt"]);
        assert_eq!(names(&list("?fileType=DOCUMENTS").await).len(), 2);
        assert!(names(&list("?fileType=IMAGES,VIDEOS,ARCHIVE").await).is_empty());
        let paged = list("?size=1&page=1").await;
        assert_eq!((names(&paged), paged["totalElements"].clone()), (vec!["report.txt".to_string()], json!(2)));
        let r = h.get("/api/files/static/docs?fileType=DIRECTORIES,FILES", Some("clia")).await.json();
        assert_eq!(names(&r), vec!["2026"]);
        assert_eq!(r["content"][0]["url"], "api/files/static/docs/2026");
        assert_eq!(names(&h.get("/api/files/static", Some("clia")).await.json()), vec!["docs"]);
        assert_eq!(h.get("/api/files/static/nothing/here", Some("clia")).await.json()["totalElements"], 0);

        // Read through files-serve's route, with the row from the database.
        let r = h.get("/api/files/static/file/CLIA/docs/2026/a.txt", None).await;
        assert_eq!((r.status, &r.body[..]), (StatusCode::OK, &b"second!"[..]));
        assert_eq!(h.get("/api/files/static/file/CLIA/docs/2026/none.txt", None).await.status, StatusCode::NOT_FOUND);
        assert_eq!(h.get("/api/files/static/file/CLIA/docs/2027/a.txt", None).await.status, StatusCode::NOT_FOUND);

        // Delete a file, then the folder with what is left under it.
        let r = h.call(Method::DELETE, "/api/files/static/docs/2026/a.txt", Some("clia")).await;
        assert_eq!(r.text(), "true");
        assert!(h.object(Kind::Static, "CLIA/docs/2026/a.txt").is_none());
        assert_eq!(h.get("/api/files/static/file/CLIA/docs/2026/a.txt", None).await.status, StatusCode::NOT_FOUND);
        assert_eq!(h.call(Method::DELETE, "/api/files/static/docs", Some("clia")).await.text(), "true");
        assert_eq!(scalar_i64(&pool, "SELECT COUNT(*) FROM files_file_system").await, 0);
        // The folder's objects stay in the bucket, as in Java.
        assert!(h.object(Kind::Static, "CLIA/docs/2026/report.txt").is_some());
        assert_eq!(h.call(Method::DELETE, "/api/files/static/docs", Some("clia")).await.text(), "false");

        // Secured does not overwrite unless asked.
        let up = |body: &'static [u8], over: Option<&'static str>| {
            let h = &h;
            async move {
                let mut parts = vec![FormPart::File("file", "s.pdf", "application/pdf", body.to_vec())];
                if let Some(o) = over {
                    parts.push(FormPart::Text("override", o));
                }
                h.form("/api/files/secured/vault", Some("clia"), &parts).await.json()
            }
        };
        assert_eq!(up(b"one", None).await["size"], 3);
        assert_eq!(up(b"three", None).await["size"], 3);
        assert_eq!(up(b"three", Some("true")).await["size"], 5);
    })
    .await;
}

#[tokio::test]
#[ignore = "needs the local MySQL (FILES_TEST_MYSQL=1, MODLIX__DATABASE__PASSWORD)"]
async fn path_rules_decide_reads_and_writes() {
    with_scratch(|pool| async move {
        let h = service(pool.clone()).await;
        // CHILD has no static rules: a managing caller reads everything there.
        assert_eq!(h.get("/api/files/static/x?clientCode=CHILD", Some("clia")).await.status, StatusCode::OK);
        // But writes need a rule.
        assert_eq!(h.call(Method::POST, "/api/files/static/directory/x?clientCode=CHILD", Some("clia")).await.status, StatusCode::FORBIDDEN);
        rule(&h, json!({"clientCode": "CHILD", "userId": 500, "resourceType": "STATIC", "path": "pub", "allowSubPathAccess": true})).await;
        assert_eq!(h.get("/api/files/static/pub/a?clientCode=CHILD", Some("clia")).await.status, StatusCode::OK);
        assert_eq!(h.get("/api/files/static/x?clientCode=CHILD", Some("clia")).await.status, StatusCode::FORBIDDEN);
        // Read only: no writing.
        assert_eq!(h.call(Method::POST, "/api/files/static/directory/pub/b?clientCode=CHILD", Some("clia")).await.status, StatusCode::FORBIDDEN);

        // Secured paths start with `/`; sub paths only when the rule allows them.
        rule(&h, json!({"clientCode": "CLIA", "userId": 500, "resourceType": "SECURED", "path": "/reports", "allowSubPathAccess": true})).await;
        rule(&h, json!({"clientCode": "CLIA", "accessName": "Authorities.SECURED_Files_PATH", "resourceType": "SECURED", "path": "/exact.pdf", "allowSubPathAccess": false})).await;
        for p in ["reports/q1.pdf", "exact.pdf", "exact.pdf.bak", "other.pdf"] {
            h.seed_detail(Kind::Secured, "CLIA", p, file(1, p, 1, 1)).await;
            h.put_object(Kind::Secured, &format!("CLIA/{p}"), b"x");
        }
        let read = |token: &'static str, p: &'static str| {
            let h = &h;
            async move { h.get(&format!("/api/files/secured/file/CLIA/{p}"), Some(token)).await.status }
        };
        assert_eq!(read("clia", "reports/q1.pdf").await, StatusCode::OK);
        assert_eq!(read("clia", "exact.pdf").await, StatusCode::OK);
        assert_eq!(read("clia", "exact.pdf.bak").await, StatusCode::FORBIDDEN);
        assert_eq!(read("clia", "other.pdf").await, StatusCode::FORBIDDEN);
        // The system user manages CLIA but has no rule of its own there.
        assert_eq!(read("sys", "reports/q1.pdf").await, StatusCode::FORBIDDEN);
        // CHILD does not manage CLIA.
        assert_eq!(read("child", "reports/q1.pdf").await, StatusCode::FORBIDDEN);
        // Listing secured follows the same rules, without the static fallback.
        assert_eq!(h.get("/api/files/secured/x?clientCode=CHILD", Some("clia")).await.status, StatusCode::FORBIDDEN);

        // Exports check read access.
        assert_eq!(h.get("/api/files/secured/export/other?clientCode=CLIA", Some("clia")).await.status, StatusCode::FORBIDDEN);
    })
    .await;
}

#[tokio::test]
#[ignore = "needs the local MySQL (FILES_TEST_MYSQL=1, MODLIX__DATABASE__PASSWORD)"]
async fn secured_keys() {
    with_scratch(|pool| async move {
        let h = service(pool.clone()).await;
        clia_writable(&h).await;
        rule(&h, json!({"clientCode": "CLIA", "userId": 500, "resourceType": "SECURED", "path": "/reports", "allowSubPathAccess": true})).await;
        let r = h.form("/api/files/secured/reports", Some("clia"), &[FormPart::File("file", "q1.pdf", "application/pdf", b"%PDF".to_vec())]).await;
        assert_eq!(r.status, StatusCode::OK);

        let r = h.get("/api/files/secured/createKey/file/CLIA/reports/q1.pdf?timeSpan=1&timeUnit=HOURS&accessLimit=2", Some("clia")).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.text());
        assert_eq!(r.header("content-type"), Some("text/plain;charset=UTF-8"));
        let link = r.text();
        let key = link.strip_prefix("api/files/secured/downloadFileByKey/").unwrap().to_string();
        assert!((12..=13).contains(&key.len()));
        let till = scalar_i64(&pool, "SELECT CAST(UNIX_TIMESTAMP(ACCESS_TILL) - UNIX_TIMESTAMP() AS SIGNED) FROM files_secured_access_keys").await;
        // MySQL rounds the fractional second of the bound instant.
        assert!((3590..=3601).contains(&till), "{till}");

        let by_key = format!("/api/files/secured/downloadFileByKey/{key}");
        for _ in 0..2 {
            let r = h.get(&by_key, None).await;
            assert_eq!((r.status, &r.body[..]), (StatusCode::OK, &b"%PDF"[..]));
        }
        let r = h.get(&by_key, None).await;
        assert_eq!((r.status, r.message().as_str()), (StatusCode::NOT_FOUND, "Cannot be accessed with the given key or access limit reached"));
        assert_eq!(h.get("/api/files/secured/downloadFileByKey/unknownkey1", None).await.status, StatusCode::NOT_FOUND);

        // Without a time: the default (365 days), no limit.
        let link = h.get("/api/files/secured/createKey/file/CLIA/reports/q1.pdf", Some("clia")).await.text();
        let open = format!("/{link}");
        for _ in 0..3 {
            assert_eq!(h.get(&open, None).await.status, StatusCode::OK);
        }
        let days = scalar_i64(&pool, "SELECT CAST(MAX(DATEDIFF(ACCESS_TILL, UTC_TIMESTAMP())) AS SIGNED) FROM files_secured_access_keys").await;
        assert!((364..=366).contains(&days));
        // Expired.
        exec(&pool, "UPDATE files_secured_access_keys SET ACCESS_TILL = UTC_TIMESTAMP() - INTERVAL 1 MINUTE").await;
        assert_eq!(h.get(&open, None).await.status, StatusCode::NOT_FOUND);

        // Internal: any path, cut at `?`; a key for a file that is not there finds nothing.
        let r = h.get("/api/files/internal/secured/createKey?filePath=CLIA%2Fnone.pdf%3Fx%3D1", None).await;
        let link = r.text();
        assert_eq!(scalar_i64(&pool, "SELECT COUNT(*) FROM files_secured_access_keys WHERE PATH = 'CLIA/none.pdf'").await, 1);
        let r = h.get(&format!("/{link}"), None).await;
        assert_eq!((r.status, r.body.is_empty()), (StatusCode::NOT_FOUND, true));
    })
    .await;
}

fn zip_of(entries: &[(&str, Option<&[u8]>)]) -> Vec<u8> {
    use std::io::Write;
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default();
    for (name, data) in entries {
        match data {
            None => w.add_directory(*name, opts).unwrap(),
            Some(d) => {
                w.start_file(*name, opts).unwrap();
                w.write_all(d).unwrap();
            }
        }
    }
    w.finish().unwrap().into_inner()
}

async fn job(h: &Harness, kind: &str, imports: bool, id: &Value) -> Value {
    let list = if imports { "imports" } else { "exports" };
    let mut last = Value::Null;
    for _ in 0..200 {
        let page = h.get(&format!("/api/files/{kind}/{list}?clientCode=CLIA"), Some("clia")).await.json();
        if let Some(j) = page["content"].as_array().and_then(|a| a.iter().find(|j| j["id"] == *id)) {
            last = j.clone();
            if j["status"] != "PENDING" {
                return last;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("job {id} still pending: {last}");
}

#[tokio::test]
#[ignore = "needs the local MySQL (FILES_TEST_MYSQL=1, MODLIX__DATABASE__PASSWORD)"]
async fn zip_import_and_export() {
    with_scratch(|pool| async move {
        let h = service(pool.clone()).await;
        clia_writable(&h).await;
        let zip = zip_of(&[
            ("index.html", Some(b"<html/>")),
            ("css/", None),
            ("css/site.css", Some(b"body{}")),
            ("img/logo.png", Some(b"png")),
            ("../evil.txt", Some(b"no")),
        ]);
        let r = h.form("/api/files/static/import/site", Some("clia"), &[FormPart::File("file", "site.zip", "application/zip", zip.clone())]).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.text());
        let id = r.json();
        let done = job(&h, "static", true, &id).await;
        assert_eq!(done["status"], "DONE", "{done}");
        assert_eq!((done["type"].as_str(), done["resourceType"].as_str(), done["path"].as_str()), (Some("UPLOAD"), Some("STATIC"), Some("site")));
        let o = h.object(Kind::Static, "CLIA/site/index.html").unwrap();
        assert_eq!((o.bytes.as_slice(), o.content_type.as_deref()), (&b"<html/>"[..], Some("text/html")));
        assert!(h.object(Kind::Static, "CLIA/site/css/site.css").is_some());
        assert!(h.object(Kind::Static, "CLIA/site/img/logo.png").is_some());
        assert!(!h.s3.objects.lock().unwrap().keys().any(|k| k.contains("evil")));
        let listed = h.get("/api/files/static/site?clientCode=CLIA", Some("clia")).await.json();
        assert_eq!(names(&listed), vec!["css", "img", "index.html"]);

        // Again without override: what is there stays.
        h.put_object(Kind::Static, "CLIA/site/index.html", b"changed");
        let r = h.form("/api/files/static/import/site", Some("clia"), &[FormPart::Text("override", "false"), FormPart::File("file", "site.zip", "application/zip", zip.clone())]).await;
        assert_eq!(job(&h, "static", true, &r.json()).await["status"], "DONE");
        assert_eq!(h.object(Kind::Static, "CLIA/site/index.html").unwrap().bytes, b"changed");
        // With it, the rows are updated in place.
        let r = h.form("/api/files/static/import/site", Some("clia"), &[FormPart::File("file", "site.zip", "application/zip", zip.clone())]).await;
        assert_eq!(job(&h, "static", true, &r.json()).await["status"], "DONE");
        assert_eq!(h.object(Kind::Static, "CLIA/site/index.html").unwrap().bytes, b"<html/>");
        assert_eq!(scalar_i64(&pool, "SELECT COUNT(*) FROM files_file_system WHERE NAME = 'index.html'").await, 1);

        // Into the client's root.
        let r = h.form("/api/files/secured/import", Some("clia"), &[FormPart::File("file", "root.ZIP", "application/zip", zip_of(&[("top.txt", Some(b"t")), ("d/e.txt", Some(b"e"))]))]).await;
        assert_eq!(job(&h, "secured", true, &r.json()).await["status"], "DONE");
        assert!(h.object(Kind::Secured, "CLIA/top.txt").is_some());
        assert!(h.object(Kind::Secured, "CLIA/d/e.txt").is_some());

        // A zip that is not one: the job records why.
        let r = h.form("/api/files/static/import/bad", Some("clia"), &[FormPart::File("file", "bad.zip", "application/zip", b"not a zip".to_vec())]).await;
        let failed = job(&h, "static", true, &r.json()).await;
        assert_eq!(failed["status"], "ERROR");
        assert!(failed["exception"].as_str().unwrap().contains("Unable to read zip file"), "{failed}");
        // A file whose upload fails.
        let r = h.form("/api/files/static/import/broken", Some("clia"), &[FormPart::File("file", "b.zip", "application/zip", zip_of(&[("s3fail.txt", Some(b"x")), ("fine.txt", Some(b"y"))]))]).await;
        let failed = job(&h, "static", true, &r.json()).await;
        assert_eq!(failed["status"], "ERROR");
        assert!(failed["exception"].as_str().unwrap().contains("uploading broken/s3fail.txt"), "{failed}");
        assert!(h.object(Kind::Static, "CLIA/broken/fine.txt").is_some(), "every file is tried");
        // A name in the zip that is no name fails the folders.
        let r = h.form("/api/files/static/import/n", Some("clia"), &[FormPart::File("file", "n.zip", "application/zip", zip_of(&[("undefined/a.txt", Some(b"x"))]))]).await;
        let failed = job(&h, "static", true, &r.json()).await;
        assert_eq!(failed["status"], "ERROR");
        assert!(failed["exception"].as_str().unwrap().contains("not a usable name"), "{failed}");

        // Export the imported folder.
        let r = h.get("/api/files/static/export/site", Some("clia")).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.text());
        let done = job(&h, "static", false, &r.json()).await;
        assert_eq!(done["status"], "DONE", "{done}");
        let cdn = done["cdnUrl"].as_str().unwrap().to_string();
        assert!(cdn.starts_with("_downloads/") && cdn.ends_with(".zip") && cdn.len() == "_downloads/".len() + 22 + 4, "{cdn}");
        let o = h.object(Kind::Static, &format!("CLIA/{cdn}")).unwrap();
        assert_eq!(o.disposition.as_deref(), Some("attachment; filename=\"site.zip\""));
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(o.bytes)).unwrap();
        let mut entries: Vec<String> = (0..archive.len()).map(|i| archive.by_index(i).unwrap().name().to_string()).collect();
        entries.sort();
        assert_eq!(entries, vec!["css/site.css", "img/logo.png", "index.html"]);
        // Exporting a folder the bucket refuses to list.
        let r = h.get("/api/files/static/export/s3fail", Some("clia")).await;
        assert_eq!(job(&h, "static", false, &r.json()).await["status"], "ERROR");
        // Jobs of others are not listed.
        let page = h.get("/api/files/static/exports?clientCode=CLIA", Some("sys")).await.json();
        assert!(page.get("content").is_none());
    })
    .await;
}

#[tokio::test]
#[ignore = "needs the local MySQL (FILES_TEST_MYSQL=1, MODLIX__DATABASE__PASSWORD)"]
async fn ai_images_copied_to_a_client_page() {
    with_scratch(|pool| async move {
        let h = service(pool.clone()).await;
        clia_writable(&h).await;
        let r = h.form("/api/files/internal/aiUploader", None, &[FormPart::Text("clientCode", "CLIA"), FormPart::File("file", "pic one.png", "image/png", png(2, 2))]).await;
        assert_eq!(r.text(), "/api/files/static/file/SYSTEM/aiGen/CLIA/pic one.png");

        let uri = "/api/files/static/copyToClientPage?pageName=home";
        let r = h.json(Method::POST, uri, Some("clia"), &json!(["/api/files/static/file/SYSTEM/aiGen/CLIA/pic%20one.png", 7])).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.text());
        let v = r.json();
        assert_eq!(v.as_array().unwrap().len(), 1);
        assert_eq!(v[0]["url"], "api/files/static/file/CLIA/sitezump/home/pic+one.png");
        assert_eq!(h.object(Kind::Static, "CLIA/sitezump/home/pic one.png").unwrap().bytes, png(2, 2));

        // A source with no row, or a row with nothing in the bucket: Java's unknown error.
        for url in ["/api/files/static/file/SYSTEM/aiGen/CLIA/none.png", "/api/files/static/file/SYSTEM/aiGen/CLIA/gone.png"] {
            if url.ends_with("gone.png") {
                Dao::new(pool.clone()).create_or_update_file(Kind::Static, "SYSTEM", "aiGen/CLIA/gone.png", Some("gone.png"), 1, false, None).await.unwrap();
            }
            let r = h.json(Method::POST, uri, Some("clia"), &json!([url])).await;
            assert_eq!((r.status, r.message().as_str()), (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error (Unknown)"), "{url}");
        }
    })
    .await;
}

#[tokio::test]
#[ignore = "needs the local MySQL (FILES_TEST_MYSQL=1, MODLIX__DATABASE__PASSWORD)"]
async fn internal_uploads_with_a_lifetime_and_the_cleanup() {
    with_scratch(|pool| async move {
        let h = service(pool.clone()).await;
        let r = h.raw(Method::POST, "/api/files/internal/static?clientCode=CLIA&fileName=t.txt&filePath=tmp&expiresAfterMinutes=1", None, "temp").await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.text());
        let id = r.json()["id"].as_u64().unwrap();
        let r = h.raw(Method::POST, "/api/files/internal/secured?clientCode=CLIA&fileName=s.txt&filePath=tmp&expiresAfterMinutes=1", None, "s").await;
        let secured = r.json()["id"].as_u64().unwrap();
        // A row whose object the bucket refuses to delete.
        let dao = Dao::new(pool.clone());
        let stuck = file_row(&dao, Kind::Static, "CLIA", "tmp/s3fail.txt", 1, Some(1)).await;
        for i in [id, secured, stuck] {
            age(&pool, i, 0, 2).await;
        }

        let r = h.call(Method::POST, "/api/files/internal/static/cleanupExpired?limit=10", None).await;
        assert_eq!(r.text(), "1");
        assert!(h.object(Kind::Static, "CLIA/tmp/t.txt").is_none());
        assert!(h.object(Kind::Secured, "CLIA/tmp/s.txt").is_some(), "the other type is left alone");
        assert_eq!(scalar_i64(&pool, &format!("SELECT COUNT(*) FROM files_file_system WHERE ID IN ({secured}, {stuck})")).await, 2);
        assert_eq!(h.call(Method::POST, "/api/files/internal/secured/cleanupExpired", None).await.text(), "1");
        assert_eq!(h.call(Method::POST, "/api/files/internal/static/cleanupExpired", None).await.text(), "0");
    })
    .await;
}

#[tokio::test]
#[ignore = "needs the local MySQL (FILES_TEST_MYSQL=1, MODLIX__DATABASE__PASSWORD)"]
async fn populate_rebuilds_the_rows_from_the_bucket() {
    with_scratch(|pool| async move {
        let h = service(pool.clone()).await;
        for (k, b) in [("CLIA/pa.txt", "1"), ("CLIA/pd/pe/pf.txt", "22"), ("CHILD/x.txt", "333"), ("js/lib.js", "4"), ("NOFOLDER", "5")] {
            h.put_object(Kind::Static, k, b.as_bytes());
        }
        let count = |sql: String| {
            let pool = pool.clone();
            async move { scalar_i64(&pool, &sql).await }
        };
        let files_of = |cc: &'static str| format!("SELECT COUNT(*) FROM files_file_system WHERE CODE = '{cc}' AND FILE_TYPE = 'FILE'");

        let r = h.get("/api/files/generic/internal/fs/populate?clientCode=CLIA&resourceType=static", None).await;
        assert_eq!(r.text(), "FileSystem populated");
        eventually("CLIA's rows", || async { count(files_of("CLIA")).await == 2 }).await;
        let fd = Dao::new(pool.clone()).detail_of(Kind::Static, "CLIA", "pd/pe/pf.txt").await.unwrap().unwrap();
        assert_eq!(fd.size, 2);
        assert_eq!(count(files_of("CHILD")).await, 0);

        // One folder of a client.
        h.put_object(Kind::Static, "CLIA/pd/pe/pg.txt", b"g");
        h.get("/api/files/generic/internal/fs/populate?clientCode=CLIA&folderPath=pd&resourceType=STATIC", None).await;
        eventually("the new file", || async { count(files_of("CLIA")).await == 3 }).await;

        // Everything, both types.
        h.get("/api/files/generic/internal/fs/populate", None).await;
        eventually("every client", || async { count(files_of("CHILD")).await == 1 && count(files_of("CLIA")).await == 3 }).await;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    })
    .await;
}

/// `ImageUploadNamingAndAccessTest`: which id names the picture, who may write someone else's,
/// and that replacing a picture drops this instance's disk copy of the old one.
#[tokio::test]
#[ignore = "needs the local MySQL (FILES_TEST_MYSQL=1, MODLIX__DATABASE__PASSWORD)"]
async fn pictures_are_named_by_id() {
    with_scratch(|pool| async move {
        let h = service(pool.clone()).await;
        h.sec.token("cliaAdmin", ca(501, 10, "CLIA", false, &["Authorities.Client_UPDATE", "Authorities.User_UPDATE"]));
        let pic = |w: u32| FormPart::File("file", "photo.png", "image/png", png(w, w));
        let checks = |h: &Harness| (h.sec.calls_to("isUserClientManageClient"), h.sec.calls_to("getClientById"), h.sec.calls_to("/users/internal/"));

        // Own logo, no client id: named after the caller's client, nothing asked of security.
        let before = checks(&h);
        let r = h.form("/api/files/generic/client", Some("cliaAdmin"), &[FormPart::Text("width", "4"), FormPart::Text("height", "4"), pic(4)]).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.text());
        assert_eq!(r.json()["name"], "10.png");
        assert_eq!(r.json()["url"], "api/files/static/file/SYSTEM/_clientImages/10.png");
        assert_eq!(checks(&h), before);
        // A managed client's logo: named after that client.
        let r = h.form("/api/files/generic/client", Some("cliaAdmin"), &[FormPart::Text("clientId", "11"), pic(4)]).await;
        assert_eq!(r.json()["name"], "11.png");

        // Own photo, with or without one's own id: no check.
        let before = checks(&h);
        let r = h.form("/api/files/generic/user", Some("clia"), &[pic(4)]).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.text());
        assert_eq!(r.json()["name"], "500.png");
        assert_eq!(r.json()["url"], "api/files/secured/file/SYSTEM/_userImages/500.png");
        let r = h.form("/api/files/generic/user", Some("clia"), &[FormPart::Text("userId", "500"), pic(4)]).await;
        assert_eq!(r.json()["name"], "500.png");
        assert_eq!(checks(&h), before);
        // Someone else's: (appCode, caller id, caller client, target client), not the other way.
        let r = h.form("/api/files/generic/user", Some("cliaAdmin"), &[FormPart::Text("userId", "600"), pic(4)]).await;
        assert_eq!(r.json()["name"], "600.png");
        let call = h.sec.calls.lock().unwrap().iter().rev().find(|c| c.contains("isUserClientManageClient")).cloned().unwrap();
        assert!(call.contains("userId=501") && call.contains("userClientId=10") && call.contains("targetClientId=11"), "{call}");

        // Overwriting drops the disk copy: the next read is the new picture.
        let first = h.get("/api/files/static/file/SYSTEM/_clientImages/10.png", None).await;
        assert_eq!(image::load_from_memory(&first.body).unwrap().width(), 4);
        let r = h.form("/api/files/generic/client", Some("cliaAdmin"), &[pic(6)]).await;
        assert_eq!(r.status, StatusCode::OK);
        let second = h.get("/api/files/static/file/SYSTEM/_clientImages/10.png", None).await;
        assert_eq!(image::load_from_memory(&second.body).unwrap().width(), 6);

        // An edited upload under a path rule, named by `fileName`.
        clia_writable(&h).await;
        let r = h
            .form(
                "/api/files/transform/static/pics",
                Some("clia"),
                &[FormPart::Text("fileName", "out.png"), FormPart::Text("cropAreaX", "0"), FormPart::Text("cropAreaY", "0"), FormPart::Text("cropAreaWidth", "2"), FormPart::Text("cropAreaHeight", "2"), pic(8)],
            )
            .await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.text());
        assert_eq!(r.json()["url"], "api/files/static/file/CLIA/pics/out.png");
        let stored = h.object(Kind::Static, "CLIA/pics/out.png").unwrap();
        assert_eq!(image::load_from_memory(&stored.bytes).unwrap().width(), 2);
        // A secured transform of that stored image's copy, by path.
        h.put_object(Kind::Secured, "CLIA/pics/in.png", &png(4, 4));
        let r = h
            .form("/api/files/transform/secured/x", Some("clia"), &[FormPart::Text("fileName", "flipped.png"), FormPart::Text("flipVertical", "1"), FormPart::Text("path", "/api/files/secured/file/CLIA/pics/in.png")])
            .await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.text());
        assert_eq!(r.json()["url"], "api/files/secured/file/CLIA/pics/flipped.png");
    })
    .await;
}

// ---------------------------------------------------------------------------------------------
// Access paths (the generic data controller)
// ---------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs the local MySQL (FILES_TEST_MYSQL=1, MODLIX__DATABASE__PASSWORD)"]
async fn access_paths_through_the_data_controller() {
    with_scratch(|pool| async move {
        let h = service(pool.clone()).await;
        let create = |body: Value| {
            let h = &h;
            async move {
                let r = h.json(Method::POST, "/api/files/accesspath", Some("clia"), &body).await;
                assert_eq!(r.status, StatusCode::OK, "{body}: {}", r.text());
                r.json()
            }
        };
        let a = create(json!({"accessName": "Authorities.X", "userId": 9, "resourceType": "STATIC", "path": " /a/ "})).await;
        assert_eq!(a["clientCode"], "CLIA");
        assert_eq!(a["accessName"], "Authorities.X");
        assert!(a.get("userId").is_none(), "an access name wins over a user");
        assert_eq!((a["writeAccess"].clone(), a["allowSubPathAccess"].clone(), a["path"].clone()), (json!(false), json!(false), json!("/a/")));
        assert!(a["createdAt"].as_i64().is_some() && a["updatedAt"].as_i64().is_some());
        // The same rule again is reused, gaining what the new one asks for.
        let again = create(json!({"accessName": "Authorities.X", "resourceType": "STATIC", "path": "/a/", "writeAccess": true})).await;
        assert_eq!((again["id"].clone(), again["writeAccess"].clone()), (a["id"].clone(), json!(true)));
        let same = create(json!({"accessName": "Authorities.X", "resourceType": "STATIC", "path": "/a/", "writeAccess": true})).await;
        assert_eq!(same, again);
        let sub = create(json!({"accessName": "Authorities.X", "resourceType": "STATIC", "path": "/a/", "allowSubPathAccess": "true"})).await;
        assert_eq!((sub["writeAccess"].clone(), sub["allowSubPathAccess"].clone()), (json!(true), json!(true)));
        let u = create(json!({"userId": "600", "resourceType": "SECURED", "writeAccess": 1})).await;
        assert_eq!((u["userId"].clone(), u["path"].clone()), (json!(600), json!("/")));
        let id = a["id"].as_u64().unwrap();
        let uid = u["id"].as_u64().unwrap();

        let r = h.get(&format!("/api/files/accesspath/{id}"), Some("clia")).await;
        assert_eq!(r.json()["id"], id);

        // Pages of the caller's own client's rules.
        let page = h.get("/api/files/accesspath", Some("clia")).await.json();
        assert_eq!(page["totalElements"], 2);
        let page = h.get("/api/files/accesspath?resourceType=STATIC&path=/a/&path=/", Some("clia")).await.json();
        assert_eq!(page["totalElements"], 1);
        let page = h.get("/api/files/accesspath?sort=id,desc&size=1&page=1", Some("clia")).await.json();
        assert_eq!((page["content"][0]["id"].clone(), page["totalElements"].clone()), (json!(id), json!(2)));
        let page = h
            .json(
                Method::POST,
                "/api/files/accesspath/query",
                Some("clia"),
                &json!({"condition": {"operator": "AND", "conditions": [{"field": "accessName", "operator": "STRING_LOOSE_EQUAL", "value": "X"}]}, "size": 5, "sort": [{"property": "id", "direction": "DESC"}]}),
            )
            .await
            .json();
        assert_eq!(page["content"].as_array().unwrap().len(), 1);
        assert_eq!(page["pageable"]["pageSize"], 5);
        let page = h.json(Method::POST, "/api/files/accesspath/query", Some("clia"), &json!({})).await.json();
        assert_eq!(page["sort"][0]["property"], "updatedAt");
        assert_eq!(page["totalElements"], 2);
        h.sec.token("staticOnly", ca(504, 10, "CLIA", false, &["Authorities.STATIC_Files_PATH"]));
        h.sec.token("securedOnly", ca(505, 10, "CLIA", false, &["Authorities.SECURED_Files_PATH"]));
        assert_eq!(h.get("/api/files/accesspath", Some("staticOnly")).await.json()["content"][0]["id"], id);
        assert_eq!(h.get("/api/files/accesspath", Some("securedOnly")).await.json()["content"][0]["id"], uid);
        assert!(h.get("/api/files/accesspath", Some("sys")).await.json().get("content").is_none());

        // PUT: who it is for, write, sub paths and path.
        let put = |body: Value| {
            let h = &h;
            async move { h.json(Method::PUT, &format!("/api/files/accesspath/{id}"), Some("clia"), &body).await }
        };
        let r = put(json!({"accessName": "Authorities.Y", "allowSubPathAccess": true, "path": ""})).await;
        let v = r.json();
        assert_eq!((v["accessName"].clone(), v["path"].clone(), v["writeAccess"].clone(), v["allowSubPathAccess"].clone()), (json!("Authorities.Y"), json!("/"), json!(false), json!(true)));
        let r = put(json!({"accessName": "A", "userId": 1})).await;
        assert_eq!((r.status, r.message().as_str()), (StatusCode::BAD_REQUEST, "Access can be given to a user, permission, or a role "));
        let v = put(json!({"userId": 7})).await.json();
        assert_eq!((v["userId"].clone(), v.get("accessName").is_none()), (json!(7), true));

        // PATCH: the row with the given fields changed.
        let patch = |body: Value| {
            let h = &h;
            async move { h.json(Method::PATCH, &format!("/api/files/accesspath/{id}"), Some("clia"), &body).await }
        };
        let v = patch(json!({"writeAccess": true, "path": "/p", "id": 99, "clientCode": "X"})).await.json();
        assert_eq!((v["id"].clone(), v["writeAccess"].clone(), v["path"].clone(), v["clientCode"].clone(), v["userId"].clone()), (json!(id), json!(true), json!("/p"), json!("CLIA"), json!(7)));
        let v = patch(json!({"accessName": "Authorities.Z", "userId": null, "allowSubPathAccess": false})).await.json();
        assert_eq!((v["accessName"].clone(), v.get("userId").is_none(), v["allowSubPathAccess"].clone()), (json!("Authorities.Z"), true, json!(false)));
        assert_eq!(patch(json!({"userId": 3})).await.status, StatusCode::BAD_REQUEST, "both a user and an access name");
        for (field, value) in [("writeAccess", json!("maybe")), ("userId", json!("x")), ("accessName", json!([1])), ("path", json!({})), ("allowSubPathAccess", json!("q"))] {
            let r = patch(json!({field: value})).await;
            assert_eq!(r.status, StatusCode::BAD_REQUEST, "{field}");
            assert_eq!(r.message(), format!("{field} field cannot be updated, it might not be available or unmodifiable"));
        }

        // Somebody else's rules.
        let stranger = rule(&h, json!({"clientCode": "STRANGER", "userId": 1, "resourceType": "STATIC"})).await;
        assert_eq!(stranger["path"], json!(null).as_str().map_or(Value::Null, |_| Value::Null));
        let mut away = ca(503, 10, "CLIA", false, &["Authorities.STATIC_Files_PATH"]);
        away["loggedInFromClientId"] = json!(11);
        h.sec.token("away", away);
        let r = h.get(&format!("/api/files/accesspath/{}", stranger["id"]), Some("away")).await;
        assert_eq!((r.status, r.message().as_str()), (StatusCode::FORBIDDEN, "Permission/Role Authorities.STATIC_Files_PATH is required to use this operation "));
        assert_eq!(h.get(&format!("/api/files/accesspath/{id}"), Some("away")).await.status, StatusCode::OK, "own client, logged in elsewhere");
        let nope = rule(&h, json!({"clientCode": "NOPE", "userId": 1, "resourceType": "SECURED"})).await;
        assert_eq!(h.get(&format!("/api/files/accesspath/{}", nope["id"]), Some("sys")).await.status, StatusCode::FORBIDDEN);
        assert_eq!(h.get(&format!("/api/files/accesspath/{id}"), Some("child")).await.status, StatusCode::FORBIDDEN);

        // Delete: 204 with the JSON type of the value the handler returned.
        let r = h.call(Method::DELETE, &format!("/api/files/accesspath/{id}"), Some("clia")).await;
        assert_eq!((r.status, r.body.is_empty(), r.header("content-type")), (StatusCode::NO_CONTENT, true, Some("application/json")));
        let r = h.get(&format!("/api/files/accesspath/{id}"), Some("clia")).await;
        assert_eq!((r.status, r.message()), (StatusCode::NOT_FOUND, format!("FilesAccessPath with id {id} not found")));
        assert_eq!(h.call(Method::DELETE, &format!("/api/files/accesspath/{id}"), Some("clia")).await.status, StatusCode::NOT_FOUND);
    })
    .await;
}

// ---------------------------------------------------------------------------------------------
// Retention (FilesRetentionServiceTest)
// ---------------------------------------------------------------------------------------------

fn retention_world(h: &Harness) {
    {
        let mut w = h.sec.world.lock().unwrap();
        for (c, id) in [("OWNER", 20), ("OTHER", 30), ("CHILD2", 31), ("C1", 41), ("C2", 42), ("C3", 43), ("KEEP", 44), ("GONE", 45), ("BOOM", 46)] {
            w.clients.insert(c.into(), id);
            w.manages.push(("SYSTEM".into(), c.into()));
        }
        w.manages.push(("OTHER".into(), "CHILD2".into()));
        w.apps.insert("app".into(), json!(20));
        for (c, chain) in [
            ("OTHER", vec!["OTHER", "SYSTEM"]),
            ("CHILD2", vec!["CHILD2", "OTHER", "SYSTEM"]),
            ("OWNER", vec!["OWNER", "SYSTEM"]),
            ("C1", vec!["C1", "SYSTEM"]),
            ("C2", vec!["C2"]),
            ("C3", vec!["SYSTEM"]),
            ("KEEP", vec!["KEEP", "SYSTEM"]),
        ] {
            w.hierarchy.insert(c.into(), chain.into_iter().map(String::from).collect());
        }
    }
    h.sec.token("owner", ca(21, 20, "OWNER", false, &["Authorities.Files_RETENTION"]));
    h.sec.token("other", ca(31, 30, "OTHER", false, &["Authorities.Files_RETENTION"]));
}

async fn policy(h: &Harness, token: &str, body: Value) -> Value {
    let r = h.json(Method::POST, "/api/files/retention", Some(token), &body).await;
    assert_eq!(r.status, StatusCode::OK, "{body}: {}", r.text());
    r.json()
}

#[tokio::test]
#[ignore = "needs the local MySQL (FILES_TEST_MYSQL=1, MODLIX__DATABASE__PASSWORD)"]
async fn retention_policies_who_may_write_what() {
    with_scratch(|pool| async move {
        let h = service(pool.clone()).await;
        retention_world(&h);
        let client_row = json!({"appCode": "app", "resourceType": "SECURED", "level": "CLIENT", "path": "whatsapp/incoming", "retentionDays": 10});

        // clientRowWithoutAnAppRowIsRefused
        let r = h.json(Method::POST, "/api/files/retention", Some("other"), &client_row).await;
        assert_eq!((r.status, r.message().as_str()), (StatusCode::BAD_REQUEST, "Path 'whatsapp/incoming' is not a registered retention prefix of app app for SECURED files"));

        // appRowByTheOwnerIsCreatedNormalised
        let app = policy(&h, "owner", json!({"appCode": " app ", "clientCode": "SOMEONE", "resourceType": "SECURED", "path": "/whatsapp/incoming/", "retentionDays": 30, "level": "APP", "appliesTo": "MANAGED"})).await;
        assert_eq!(
            (app["clientCode"].clone(), app["path"].clone(), app["appliesTo"].clone(), app["level"].clone(), app["appCode"].clone(), app["createdBy"].clone(), app["retentionDays"].clone()),
            (json!("OWNER"), json!("whatsapp/incoming"), json!("SELF"), json!("APP"), json!("app"), json!(21), json!(30))
        );
        // zeroDaysAndDuplicatesAreRefused
        let r = h.json(Method::POST, "/api/files/retention", Some("owner"), &json!({"appCode": "app", "resourceType": "SECURED", "path": "whatsapp/incoming", "retentionDays": 30, "level": "APP"})).await;
        assert_eq!((r.status, r.message().as_str()), (StatusCode::CONFLICT, "Retention policy app/whatsapp/incoming already exists"));

        // clientRowOnARegisteredPrefixIsCreatedForTheCaller
        let own = policy(&h, "other", client_row.clone()).await;
        assert_eq!((own["clientCode"].clone(), own["appliesTo"].clone()), (json!("OTHER"), json!("SELF")));
        // clientRowForAManagedClientIsAllowed
        let mut managed = client_row.clone();
        managed["clientCode"] = json!("CHILD2");
        managed["appliesTo"] = json!("MANAGED");
        managed["retentionDays"] = Value::Null;
        let child = policy(&h, "other", managed).await;
        assert_eq!((child["clientCode"].clone(), child["appliesTo"].clone(), child.get("retentionDays").is_none()), (json!("CHILD2"), json!("MANAGED"), true));

        // Listing: the app's rows and the client's own.
        let list = h.get("/api/files/retention?appCode=app", Some("other")).await.json();
        assert_eq!(list.as_array().unwrap().iter().map(|r| r["id"].clone()).collect::<Vec<_>>(), vec![app["id"].clone(), own["id"].clone()]);
        let list = h.get("/api/files/retention?appCode=app&clientCode=CHILD2", Some("other")).await.json();
        assert_eq!(list.as_array().unwrap().len(), 2);
        let eff = h.get("/api/files/retention/effective?appCode=app&resourceType=SECURED", Some("other")).await.json();
        assert_eq!((eff[0]["days"].clone(), eff[0]["source"].clone()), (json!(10), json!("OWN")));

        // updatingAnAppRowByANonOwnerIsRefused
        let app_id = app["id"].as_u64().unwrap();
        let r = h.json(Method::PUT, &format!("/api/files/retention/{app_id}"), Some("other"), &json!({"retentionDays": 1})).await;
        assert_eq!((r.status, r.message().as_str()), (StatusCode::FORBIDDEN, "Permission/Role owner of the app app is required to use this operation "));
        let r = h.json(Method::PUT, &format!("/api/files/retention/{app_id}"), Some("owner"), &json!({"retentionDays": 14, "path": "ignored"})).await;
        assert_eq!((r.json()["retentionDays"].clone(), r.json()["path"].clone(), r.json()["updatedBy"].clone()), (json!(14), json!("whatsapp/incoming"), json!(21)));
        let own_id = own["id"].as_u64().unwrap();
        let r = h.raw(Method::PUT, &format!("/api/files/retention/{own_id}"), Some("other"), "").await;
        assert!(r.json().get("retentionDays").is_none(), "an empty body is keep forever");
        let r = h.json(Method::PUT, &format!("/api/files/retention/{own_id}"), Some("other"), &json!({"retentionDays": -2})).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST);
        let r = h.json(Method::PUT, "/api/files/retention/999", Some("owner"), &json!({})).await;
        assert_eq!((r.status, r.message().as_str()), (StatusCode::NOT_FOUND, "Retention policy with id 999 not found"));
        // A write clears the cached rows: the effective answer follows.
        let eff = h.get("/api/files/retention/effective?appCode=app&resourceType=SECURED", Some("other")).await.json();
        assert_eq!((eff[0]["keepForever"].clone(), eff[0]["appDays"].clone()), (json!(true), json!(14)));
        // A client row of a client the caller does not manage.
        let r = h.call(Method::DELETE, &format!("/api/files/retention/{}", child["id"]), Some("owner")).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN);

        // deletingAnAppRowRemovesItsClientRows
        assert_eq!(h.call(Method::DELETE, &format!("/api/files/retention/{app_id}"), Some("other")).await.status, StatusCode::FORBIDDEN);
        let r = h.call(Method::DELETE, &format!("/api/files/retention/{app_id}"), Some("owner")).await;
        assert_eq!(r.text(), "true");
        assert_eq!(scalar_i64(&pool, "SELECT COUNT(*) FROM files_retention_policy").await, 0);
        assert_eq!(h.call(Method::DELETE, &format!("/api/files/retention/{app_id}"), Some("owner")).await.status, StatusCode::NOT_FOUND);

        // A client deletes its own row.
        policy(&h, "owner", json!({"appCode": "app", "resourceType": "STATIC", "level": "APP", "retentionDays": 3})).await;
        let row = policy(&h, "other", json!({"appCode": "app", "resourceType": "STATIC", "level": "CLIENT", "path": "/", "retentionDays": 2})).await;
        assert_eq!(row["path"], json!(null).as_str().map_or(Value::Null, |_| Value::Null), "the whole app is the empty path, left out");
        assert_eq!(h.call(Method::DELETE, &format!("/api/files/retention/{}", row["id"]), Some("other")).await.text(), "true");
        assert_eq!(scalar_i64(&pool, "SELECT COUNT(*) FROM files_retention_policy").await, 1);
    })
    .await;
}

/// The tree every sweep test uses: secured files under `<client>/app/...`, aged in days.
async fn aged_files(h: &Harness, pool: &MySqlPool, files: &[(&str, &str, i64)]) -> Vec<u64> {
    let dao = Dao::new(pool.clone());
    let mut ids = vec![];
    for (cc, path, days) in files {
        let id = file_row(&dao, Kind::Secured, cc, path, 10, None).await;
        age(pool, id, *days, 0).await;
        h.put_object(Kind::Secured, &format!("{cc}/{path}"), b"0123456789");
        ids.push(id);
    }
    ids
}

/// `sweepUsesEachClientsResolvedDaysSkipsKeepForeverAndExcludesNestedPrefixes` and
/// `sweepSkipsAClientThatKeepsForeverAndAClientWithoutHierarchy`.
#[tokio::test]
#[ignore = "needs the local MySQL (FILES_TEST_MYSQL=1, MODLIX__DATABASE__PASSWORD)"]
async fn retention_sweep_resolves_per_client() {
    with_scratch(|pool| async move {
        let h = service(pool.clone()).await;
        retention_world(&h);
        for (path, days) in [("", json!(30)), ("whatsapp/incoming", json!(7)), ("whatsapp/avatars", Value::Null)] {
            policy(&h, "owner", json!({"appCode": "app", "resourceType": "SECURED", "level": "APP", "path": path, "retentionDays": days})).await;
        }
        exec(&pool, "INSERT INTO files_retention_policy (APP_CODE, CLIENT_CODE, RESOURCE_TYPE, PATH, RETENTION_DAYS, APPLIES_TO, LEVEL) VALUES ('app', 'KEEP', 'SECURED', 'whatsapp/incoming', NULL, 'SELF', 'CLIENT')").await;
        aged_files(
            &h,
            &pool,
            &[
                ("C1", "app/docs/a.pdf", 40),
                ("C1", "app/whatsapp/incoming/b.jpg", 10),
                ("C1", "app/whatsapp/incoming/fresh.jpg", 1),
                ("C1", "app/whatsapp/avatars/c.png", 400),
                ("KEEP", "app/whatsapp/incoming/k.jpg", 10),
                ("KEEP", "app/x.pdf", 5),
                ("GONE", "app/g.pdf", 400),
                ("BOOM", "app/b.pdf", 400),
                ("C3", "app/other.txt", 1),
            ],
        )
        .await;

        let r = h.call(Method::POST, "/api/files/internal/secured/applyRetention", None).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.text());
        assert_eq!(
            r.json(),
            json!([{"clientCode": "C1", "appCode": "app", "resourceType": "SECURED", "paths": ["/app/docs/a.pdf", "/app/whatsapp/incoming/b.jpg"]}])
        );
        assert!(h.object(Kind::Secured, "C1/app/docs/a.pdf").is_none());
        for kept in ["C1/app/whatsapp/avatars/c.png", "C1/app/whatsapp/incoming/fresh.jpg", "KEEP/app/whatsapp/incoming/k.jpg", "GONE/app/g.pdf", "BOOM/app/b.pdf"] {
            assert!(h.object(Kind::Secured, kept).is_some(), "{kept}");
        }
        // Nothing of the static type is registered.
        assert_eq!(h.call(Method::POST, "/api/files/internal/static/applyRetention", None).await.text(), "[ ]");
        // Nothing left to remove.
        assert_eq!(h.call(Method::POST, "/api/files/internal/secured/applyRetention", None).await.text(), "[ ]");

        // Previews (sys manages every client here).
        let preview = |q: &'static str| {
            let h = &h;
            async move {
                let r = h.get(&format!("/api/files/retention/preview?appCode=app&resourceType=SECURED{q}"), Some("sys")).await;
                assert_eq!(r.status, StatusCode::OK, "{q}: {}", r.text());
                r.json()
            }
        };
        let p = preview("&clientCode=KEEP&days=2").await;
        assert_eq!((p["count"].clone(), p["totalBytes"].clone(), p["samplePaths"].clone(), p["source"].clone()), (json!(1), json!(10), json!(["/app/x.pdf"]), json!("PREVIEW")));
        let p = preview("&clientCode=KEEP&path=whatsapp/incoming&days=2").await;
        assert_eq!(p["samplePaths"], json!(["/app/whatsapp/incoming/k.jpg"]));
        let p = preview("&clientCode=C1&path=whatsapp/avatars/").await;
        assert_eq!((p["count"].clone(), p.get("days").is_none()), (json!(0), true), "keep forever reads nothing");
        let p = preview("&clientCode=C1&path=whatsapp/incoming/sub").await;
        assert_eq!((p["days"].clone(), p["source"].clone(), p["count"].clone()), (json!(7), json!("APP"), json!(0)), "no such folder");
        let p = preview("&clientCode=C2&days=5").await;
        assert_eq!((p["days"].clone(), p["count"].clone()), (json!(5), json!(0)), "no app folder at all");
        let p = preview("&clientCode=C3&path=x").await;
        assert_eq!(p["days"], 30);
    })
    .await;
}

/// `sweepStopsAtTheLimitAndOnlyReportsWhatWasRemoved`.
#[tokio::test]
#[ignore = "needs the local MySQL (FILES_TEST_MYSQL=1, MODLIX__DATABASE__PASSWORD)"]
async fn retention_sweep_stops_at_the_limit() {
    with_scratch(|pool| async move {
        let h = service(pool.clone()).await;
        retention_world(&h);
        h.sec.world.lock().unwrap().hierarchy.insert("C2".into(), vec!["C2".into()]);
        policy(&h, "owner", json!({"appCode": "app", "resourceType": "SECURED", "level": "APP", "path": "whatsapp/incoming", "retentionDays": 7})).await;
        let ids = aged_files(
            &h,
            &pool,
            &[
                ("C1", "app/whatsapp/incoming/s3fail-1.jpg", 30),
                ("C1", "app/whatsapp/incoming/2.jpg", 20),
                ("C1", "app/whatsapp/incoming/3.jpg", 15),
                ("C2", "app/whatsapp/incoming/4.jpg", 30),
            ],
        )
        .await;
        let r = h.call(Method::POST, "/api/files/internal/secured/applyRetention?limit=2", None).await;
        // The first file could not be removed; only the second is reported.
        assert_eq!(r.json(), json!([{"clientCode": "C1", "appCode": "app", "resourceType": "SECURED", "paths": ["/app/whatsapp/incoming/2.jpg"]}]));
        assert_eq!(scalar_i64(&pool, &format!("SELECT COUNT(*) FROM files_file_system WHERE ID IN ({}, {}, {})", ids[0], ids[2], ids[3])).await, 3);
    })
    .await;
}

// ---------------------------------------------------------------------------------------------
// FilesBillingMeteringServiceTest
// ---------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs the local MySQL (FILES_TEST_MYSQL=1, MODLIX__DATABASE__PASSWORD)"]
async fn billing_meters_stored_gigabytes() {
    with_scratch(|pool| async move {
        let h = service(pool.clone()).await;
        let dao = Dao::new(pool.clone());
        const FIVE_GB: u64 = 5 * 1024 * 1024 * 1024;
        file_row(&dao, Kind::Static, "MMMM", "a.bin", FIVE_GB - 1000, None).await;
        file_row(&dao, Kind::Secured, "MMMM", "b.bin", 1000, None).await;
        file_row(&dao, Kind::Static, "TINY", "t.bin", 100, None).await;
        let instr = |code: &str, billed: u64| json!({"configClientCode": "CCCC", "configClientId": 10, "appCode": "appbuilder", "appId": 2, "billedClientCode": code, "billedClientId": billed});
        h.sec.world.lock().unwrap().instructions = json!([instr("MMMM", 20), instr("ZERO", 21), instr("TINY", 22), instr("FAIL", 13)]);
        file_row(&dao, Kind::Static, "FAIL", "f.bin", FIVE_GB, None).await;

        // windowPostsOneChargeWithBytesConvertedToGb
        assert_eq!(h.call(Method::POST, "/api/files/internal/billing/meter", None).await.text(), "true");
        {
            let charges = h.sec.charges.lock().unwrap();
            assert_eq!(charges.len(), 1, "zero bytes, a rounding to zero and a refused charge post nothing");
            let v: Value = serde_json::from_str(&charges[0]).unwrap();
            assert_eq!(v.as_array().unwrap().len(), 1);
            assert_eq!((v[0]["actionKey"].clone(), v[0]["billedClientId"].clone(), v[0]["configClientId"].clone(), v[0]["appId"].clone()), (json!("files.gb"), json!(20), json!(10), json!(2)));
            assert!(charges[0].contains("\"quantity\":5.000000"));
        }
        // reconcilePostsAllNinetySixWindows
        assert_eq!(h.call(Method::POST, "/api/files/internal/billing/reconcile?date=2026-06-15", None).await.text(), "true");
        let charges = h.sec.charges.lock().unwrap();
        let v: Value = serde_json::from_str(&charges[1]).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 96);
        assert_eq!(v[0]["date"], 1_781_481_600);
        assert_eq!(v[95]["windowIndex"], 95);
    })
    .await;
}

/// The corners of the tree walk and the path rules.
#[tokio::test]
#[ignore = "needs the local MySQL (FILES_TEST_MYSQL=1, MODLIX__DATABASE__PASSWORD)"]
async fn dao_corners() {
    with_scratch(|pool| async move {
        let dao = Dao::new(pool.clone());
        // Empty segments are skipped when folders are made.
        let id = dao.get_folder_id(Kind::Static, "C1", "a//b/").await.unwrap().unwrap();
        assert_eq!(dao.get_id(Kind::Static, "C1", "a/b").await.unwrap(), Some(id));
        // A name that exists, but not under the parent the path walks through.
        file_row(&dao, Kind::Static, "C1", "x.txt", 1, None).await;
        assert!(dao.get_id(Kind::Static, "C1", "a/x.txt").await.unwrap().is_none());
        assert!(dao.detail_of(Kind::Static, "C1", "a/b/c").await.unwrap().is_none());
        // A parent that is not there ends the walk.
        assert_eq!(dao.full_path(Some(9_999_999), "n.txt").await.unwrap(), "/n.txt");
        assert_eq!(dao.full_path(None, "n.txt").await.unwrap(), "/n.txt");
        // Two root folders named like the app: the client is listed once.
        exec(&pool, "INSERT INTO files_file_system (TYPE, CODE, NAME, FILE_TYPE) VALUES ('STATIC', 'C1', 'app', 'DIRECTORY'), ('STATIC', 'C1', 'app', 'DIRECTORY')").await;
        assert_eq!(dao.read_app_root_folders(Kind::Static, "app").await.unwrap().len(), 1);
        // No authorities: only the user's own rules count.
        exec(&pool, "INSERT INTO files_access_path (CLIENT_CODE, USER_ID, RESOURCE_TYPE, PATH, WRITE_ACCESS, ALLOW_SUB_PATH_ACCESS) VALUES ('C1', 5, 'SECURED', '/s', 1, 1), ('C1', 5, 'STATIC', 'p', 1, 1)").await;
        assert!(dao.has_secured_path_read_access("/s/a", 5, "C1", &[]).await.unwrap());
        assert!(!dao.has_secured_path_read_access("/s/a", 6, "C1", &[]).await.unwrap());
        assert!(dao.has_path_access(Kind::Static, "p/q", 5, "C1", &[], true).await.unwrap());
        assert!(!dao.has_path_access(Kind::Static, "z", 5, "C1", &[], false).await.unwrap());
        assert!(dao.has_path_access(Kind::Static, "z", 5, "C2", &[], false).await.unwrap(), "no static rules: all readable");
        assert!(!dao.has_path_access(Kind::Secured, "/z", 5, "C2", &[], false).await.unwrap());
        // Folders made in one go, parents first, reusing what exists.
        let ids = dao.create_folders(Kind::Static, "C1", &["a/b".to_string(), "a/c/d".to_string()]).await.unwrap();
        assert_eq!(ids["a/b"], id);
        assert!(dao.create_folders(Kind::Static, "C1", &["a/null".to_string()]).await.is_err());
        assert!(dao.create_folder(Kind::Static, "C1", "a/..").await.is_err());
        assert_eq!(dao.sum_bytes_by_client("C1").await.unwrap(), 1);
        assert_eq!(dao.clear_file_system(Kind::Secured, None, None).await.unwrap(), 0);
        dao.insert_discovered(Kind::Static, &[]).await.unwrap();
        // A key to nothing.
        assert!(dao.access_key("none").await.unwrap().is_none());
        assert!(!dao.increment_access_count(12345).await.unwrap());
    })
    .await;
}

/// The cached "exists" said yes but the row is gone: the existing-file answer is an empty 200.
#[tokio::test]
#[ignore = "needs the local MySQL (FILES_TEST_MYSQL=1, MODLIX__DATABASE__PASSWORD)"]
async fn a_stale_exists_answers_an_empty_200() {
    with_scratch(|pool| async move {
        let h = service(pool.clone()).await;
        clia_writable(&h).await;
        let exists = &h.state.inner().exists;
        exists.insert("fsPathExists-STATIC-CLIA", "d/a.txt".to_string(), true).await;
        let r = h.form("/api/files/static/d", Some("clia"), &[FormPart::Text("override", "no"), FormPart::File("file", "a.txt", "text/plain", b"a".to_vec())]).await;
        assert_eq!((r.status, r.body.is_empty(), r.header("content-type")), (StatusCode::OK, true, None));
        exists.insert("fsPathExists-SECURED-CLIA", "in/b.bin".to_string(), true).await;
        let r = h.raw(Method::POST, "/api/files/internal/secured?clientCode=CLIA&fileName=b.bin&filePath=in", None, "b").await;
        assert_eq!((r.status, r.text().as_str()), (StatusCode::OK, ""));
        exists.insert("fsPathExists-STATIC-CLIA", "pics/o.png".to_string(), true).await;
        let r = h.form("/api/files/transform/static/pics", Some("clia"), &[FormPart::Text("fileName", "o.png"), FormPart::File("file", "i.png", "image/png", png(2, 2))]).await;
        assert_eq!((r.status, r.text().as_str()), (StatusCode::OK, ""));
        // And a folder that cannot be made answers its refusal.
        let r = h.call(Method::POST, "/api/files/static/directory/ok/..", Some("clia")).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST);
    })
    .await;
}
