//! Where snapshots come from: a directory read again on every poll, and a fake GitHub API (the
//! sha by ETag, a 304 when nothing moved, the tarball through a redirect); a commit that does not
//! render is not served; the last good snapshot kept on disk and taken at start; a peer's
//! snapshot when the source fails.

mod common;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get as route_get;
use axum::Router;
use common::*;
use lighthouse::config::source::Snapshot;
use serde_json::Value;

#[derive(Clone, Default)]
struct GitHub {
    head: Arc<Mutex<String>>,
    tarballs: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    not_modified: Arc<AtomicU32>,
    downloads: Arc<AtomicU32>,
    failing: Arc<Mutex<bool>>,
}

/// A gzipped tar of `files` under GitHub's top directory.
fn tarball(sha: &str, files: &BTreeMap<String, String>) -> Vec<u8> {
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    {
        let mut t = tar::Builder::new(&mut gz);
        let extra = ("scripts/dev/x.sh".to_string(), "echo".to_string());
        for (path, text) in files.iter().chain(std::iter::once((&extra.0, &extra.1))) {
            let mut h = tar::Header::new_gnu();
            h.set_size(text.len() as u64);
            h.set_mode(0o644);
            h.set_entry_type(tar::EntryType::Regular);
            h.set_cksum();
            t.append_data(&mut h, format!("o-r-{}/{path}", &sha[..7]), text.as_bytes()).unwrap();
        }
        t.finish().unwrap();
    }
    gz.finish().unwrap()
}

impl GitHub {
    fn publish(&self, sha: &str, files: &BTreeMap<String, String>) {
        self.tarballs.lock().unwrap().insert(sha.to_string(), tarball(sha, files));
        *self.head.lock().unwrap() = sha.to_string();
    }
}

async fn commits(State(g): State<GitHub>, Path(label): Path<String>, h: HeaderMap) -> Response {
    if *g.failing.lock().unwrap() {
        return StatusCode::BAD_GATEWAY.into_response();
    }
    assert_eq!(h["authorization"], "Bearer gh-token");
    assert_eq!(h["accept"], "application/vnd.github.sha");
    if label != "master" {
        return StatusCode::NOT_FOUND.into_response();
    }
    let sha = g.head.lock().unwrap().clone();
    let etag = format!("\"etag-{sha}\"");
    if h.get("if-none-match").and_then(|v| v.to_str().ok()) == Some(etag.as_str()) {
        g.not_modified.fetch_add(1, Ordering::SeqCst);
        return StatusCode::NOT_MODIFIED.into_response();
    }
    ([("etag", etag)], sha).into_response()
}

async fn fake_github(g: GitHub) -> String {
    let app = Router::new()
        .route("/repos/o/r/commits/{label}", route_get(commits))
        .route("/repos/o/r/tarball/{sha}", route_get(|Path(sha): Path<String>| async move { Redirect::temporary(&format!("/codeload/{sha}")) }))
        .route(
            "/codeload/{sha}",
            route_get(|State(g): State<GitHub>, Path(sha): Path<String>| async move {
                g.downloads.fetch_add(1, Ordering::SeqCst);
                match g.tarballs.lock().unwrap().get(&sha) {
                    Some(b) => b.clone().into_response(),
                    None => StatusCode::NOT_FOUND.into_response(),
                }
            }),
        )
        .with_state(g);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    url
}

fn fixture_files() -> BTreeMap<String, String> {
    Snapshot::from_dir(&fixture(), "master").unwrap().files
}

const SHA1: &str = "1111111111111111111111111111111111111111";
const SHA2: &str = "2222222222222222222222222222222222222222";
const SHA3: &str = "3333333333333333333333333333333333333333";

async fn github_node(api: &str, peers: &[String], snapshot_dir: Option<&std::path::Path>) -> TestNode {
    let (l, url) = bind().await;
    let mut c = config_server(&url, peers, "github:o/r", "dev");
    c.config.github_api = api.to_string();
    c.config.github_token = "gh-token".into();
    if let Some(d) = snapshot_dir {
        c.config.snapshot_dir = d.display().to_string();
    }
    c.config.spring.apps.insert("security".into(), lighthouse::config::spring::AppRule { open: true, ..Default::default() });
    TestNode::start(l, c)
}

async fn served_sha(n: &TestNode) -> Option<String> {
    n.node.config.as_ref().unwrap().served().map(|s| s.snapshot.sha.clone())
}

async fn version(n: &TestNode, unit: &str) -> String {
    get(format!("{}/v1/units/{unit}/version", n.url), Some(UNITS_TOKEN)).await.text().await.unwrap()
}

#[tokio::test]
async fn github_by_etag_and_tarball() {
    let g = GitHub::default();
    g.publish(SHA1, &fixture_files());
    let api = fake_github(g.clone()).await;
    let dir = std::env::temp_dir().join(format!("lighthouse-kept-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let n = github_node(&api, &[], Some(&dir)).await;
    assert!(eventually(Duration::from_secs(5), || async { served_sha(&n).await.as_deref() == Some(SHA1) }).await);
    let cs = n.node.config.clone().unwrap();
    assert_eq!(cs.served().unwrap().from, "github");
    assert!(cs.served().unwrap().snapshot.file("scripts/dev/x.sh").is_none(), "only the files the server reads");
    assert_eq!(g.downloads.load(Ordering::SeqCst), 1);

    // Nothing moved: a 304, nothing downloaded.
    assert!(!cs.poll_once().await);
    assert_eq!(g.not_modified.load(Ordering::SeqCst), 1);
    assert_eq!(g.downloads.load(Ordering::SeqCst), 1);

    // Asked in full (no ETag), GitHub answers the same sha: nothing to do either.
    cs.source.forget_etag();
    assert!(!cs.poll_once().await);
    assert_eq!(g.downloads.load(Ordering::SeqCst), 1);

    // The Spring endpoint names sources after the repository and answers its label.
    let env: Value = get(format!("{}/security/ocidev", n.url), None).await.json().await.unwrap();
    assert_eq!(env["label"], "master");
    assert_eq!(env["version"], SHA1);
    assert_eq!(env["propertySources"][0]["name"], "https://github.com/o/r.git/security-ocidev.yml");
    assert_eq!(env["propertySources"][3]["name"], "https://github.com/o/r.git/application.yml (document #1)");
    let view: Value = get(format!("{}/v1/config", n.url), None).await.json().await.unwrap();
    assert_eq!((view["source"]["kind"].as_str(), view["source"]["where"].as_str()), (Some("github"), Some("o/r")));
    assert_eq!(view["snapshot"]["from"], "github");

    // A new commit: a new snapshot, and multi's version moves (its restart part).
    let before = version(&n, "multi").await;
    let mut files = fixture_files();
    let multi = files["rust/multi.toml"].replace("port = 8110", "port = 8115");
    files.insert("rust/multi.toml".into(), multi);
    g.publish(SHA2, &files);
    assert!(cs.poll_once().await);
    let after = version(&n, "multi").await;
    assert_ne!(before.split('.').next(), after.split('.').next());

    // A commit that does not render is not served: the last good one stays.
    let mut broken = files.clone();
    broken.insert("rust/units.toml".into(), "not = [a manifest".into());
    g.publish(SHA3, &broken);
    assert!(!cs.poll_once().await);
    assert_eq!(served_sha(&n).await.as_deref(), Some(SHA2));
    assert!(cs.status().last_error.unwrap().contains("is not served"));
    // GitHub's head stays that commit (a 304 now): the error stays shown.
    assert!(!cs.poll_once().await);
    assert!(cs.status().last_error.unwrap().contains("is not served"));
    let view: Value = get(format!("{}/v1/config", n.url), None).await.json().await.unwrap();
    assert_eq!(view["rejectedCommit"], SHA3);

    // The last good snapshot was kept, readable by Lighthouse only.
    let kept = Snapshot::load(&dir).unwrap().unwrap();
    assert_eq!(kept.sha, SHA2);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(dir.join("snapshot.tar.gz")).unwrap().permissions().mode() & 0o777, 0o600);
    }

    // A restart while GitHub fails serves the kept snapshot.
    *g.failing.lock().unwrap() = true;
    n.kill();
    let again = github_node(&api, &[], Some(&dir)).await;
    assert_eq!(served_sha(&again).await.as_deref(), Some(SHA2));
    assert_eq!(again.node.config.as_ref().unwrap().served().unwrap().from, "disk");
    assert!(eventually(Duration::from_secs(5), || async {
        again.node.config.as_ref().unwrap().status().last_error.is_some_and(|e| e.contains("502"))
    })
    .await);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn a_peer_snapshot_when_the_source_fails() {
    let g = GitHub::default();
    g.publish(SHA1, &fixture_files());
    let api = fake_github(g.clone()).await;
    let a = github_node(&api, &[], None).await;
    assert!(eventually(Duration::from_secs(5), || async { served_sha(&a).await.is_some() }).await);

    let down = GitHub::default();
    *down.failing.lock().unwrap() = true;
    let down_api = fake_github(down).await;
    let b = github_node(&down_api, &[a.url.clone()], None).await;
    assert!(eventually(Duration::from_secs(5), || async { served_sha(&b).await.as_deref() == Some(SHA1) }).await);
    assert_eq!(b.node.config.as_ref().unwrap().served().unwrap().from, "peer");
    assert_eq!(version(&a, "multi").await, version(&b, "multi").await, "the same snapshot, the same versions");

    // A peer that does not have one, or a wrong token, gives nothing.
    let lonely = github_node(&down_api, &["http://127.0.0.1:1".into()], None).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(served_sha(&lonely).await, None);
    assert!(!lonely.node.config.as_ref().unwrap().from_peers().await);
}

#[tokio::test]
async fn a_directory_is_read_again() {
    let dir = fixture_copy("rescan");
    let (l, url) = bind().await;
    let n = TestNode::start(l, config_server(&url, &[], &format!("dir:{}", dir.display()), "dev"));
    assert!(eventually(Duration::from_secs(5), || async { served_sha(&n).await.is_some() }).await);
    let cs = n.node.config.clone().unwrap();
    assert_eq!(cs.served().unwrap().from, "dir");
    assert!(!cs.poll_once().await, "the same files");
    let before = version(&n, "multi").await;

    // A live key changes: only the live part of multi's version moves.
    let path = dir.join("rust/multi.toml");
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, text.replace("log_level = \"info\"", "log_level = \"debug\"")).unwrap();
    assert!(cs.poll_once().await);
    let after = version(&n, "multi").await;
    assert_eq!(before.split('.').next(), after.split('.').next());
    assert_ne!(before, after);
    assert_eq!(version(&n, "core-exec").await.len(), before.len());

    // A YAML the units read breaks: the last good snapshot stays.
    std::fs::write(dir.join("application.yml"), "a: [1\n").unwrap();
    assert!(!cs.poll_once().await);
    assert_eq!(version(&n, "multi").await, after);
    let view: Value = get(format!("{url}/v1/config"), None).await.json().await.unwrap();
    assert!(view["lastError"].as_str().unwrap().contains("application.yml"), "{view}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn github_answers_that_are_not_a_commit() {
    let g = GitHub::default();
    g.publish(SHA1, &fixture_files());
    *g.head.lock().unwrap() = "not-a-sha".into();
    let api = fake_github(g.clone()).await;
    let n = github_node(&api, &[], None).await;
    let cs = n.node.config.clone().unwrap();
    assert!(eventually(Duration::from_secs(5), || async { cs.status().last_error.is_some_and(|e| e.contains("not a sha")) }).await);
    // A sha without a tarball.
    *g.head.lock().unwrap() = SHA2.into();
    assert!(!cs.poll_once().await);
    assert!(cs.status().last_error.unwrap().contains("404"));
    // A first snapshot that does not render is served all the same (nothing better exists),
    // and the units answer why.
    let mut broken = fixture_files();
    broken.remove("rust/units.toml");
    g.publish(SHA3, &broken);
    assert!(cs.poll_once().await);
    let r = get(format!("{}/v1/units/multi/config", n.url), Some(UNITS_TOKEN)).await;
    assert_eq!(r.status(), 500);
    assert!(r.text().await.unwrap().contains("rust/units.toml is missing"));
    assert_eq!(get(format!("{}/v1/env/ai", n.url), Some(AI_TOKEN)).await.status(), 500);
}
