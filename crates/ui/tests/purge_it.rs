//! The admin purge's ui half in process, on the in-memory store: who may run it, which codes
//! it refuses, the dry run default, what a client's and an app's purge delete, and the caches
//! a real purge evicts.

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::Router;
use mongodb::bson::doc;
use overridable::backend::{FakeDirectory, MemBackend};
use overridable::write::router::CallerSource;
use overridable::Store;
use platform::cache::{CacheService, LocalCaches};
use platform::error::AppResult;
use platform::security::{ContextAuthentication, ContextUser};
use tower::ServiceExt;
use ui::editor::config::EditorConfig;
use ui::editor::purge::BackendDocs;

const SYSTEM: &str = "SYSTEM";
const PURGERS: &str = "Authorities.Client_DELETE,Authorities.Application_DELETE";
const COLLECTIONS: [&str; 5] = ["application", "page", "version", "uri_path", "system.views"];

/// `x-test-client` signs in as that client (SYSTEM is of type SYS) with `x-test-auth`'s
/// authorities; no header is the anonymous caller.
struct Callers;

#[async_trait]
impl CallerSource for Callers {
    async fn caller(&self, h: &HeaderMap) -> AppResult<ContextAuthentication> {
        let get = |n: &str| h.get(n).and_then(|v| v.to_str().ok()).map(str::to_string);
        let Some(client) = get("x-test-client") else {
            return Ok(ContextAuthentication { client_code: Some(SYSTEM.into()), ..Default::default() });
        };
        let auths = get("x-test-auth").unwrap_or_default().split(',').filter(|s| !s.is_empty()).map(str::to_string).collect();
        Ok(ContextAuthentication {
            user: ContextUser { id: 7, client_id: 1, user_name: Some("purger".into()), string_authorities: auths },
            authenticated: true,
            logged_in_from_client_id: 1,
            logged_in_from_client_code: Some(client.clone()),
            client_type_code: Some(if client == SYSTEM { "SYS" } else { "BUS" }.to_string()),
            client_code: Some(client.clone()),
            client_level_type: None,
            access_token: Some("t".into()),
            url_client_code: Some(client),
            url_app_code: Some("appbuilder".into()),
        })
    }
}

/// Who manages whom for the purge: SYSTEM every other client, LZCLA only ZZ10.
struct Managed;

#[async_trait]
impl ui::editor::purge::ManagedClients for Managed {
    async fn manages(&self, managing: &str, client: &str) -> anyhow::Result<bool> {
        Ok((managing == SYSTEM && client != SYSTEM) || (managing == "LZCLA" && client == "ZZ10"))
    }
}

struct Env {
    mem: Arc<MemBackend>,
    router: Router,
    st: Arc<ui::editor::routes::EditorState>,
    probe: Arc<LocalCaches<String, u32>>,
}

fn env() -> Env {
    let mem = Arc::new(MemBackend::new());
    let dir = Arc::new(FakeDirectory::new());
    dir.chain(&[SYSTEM]);
    let cache = CacheService::new("cmn", "evictionChannel", None).unwrap();
    let store = Store::with_parts(mem.clone(), dir, &cache).unwrap();
    let mut st = ui::editor::state(store, cache.clone(), Arc::new(Callers), &EditorConfig::default(), reqwest::Client::new());
    let s = Arc::get_mut(&mut st).unwrap();
    s.purge = Some(Arc::new(BackendDocs { name: "ui".into(), backend: mem.clone(), collections: COLLECTIONS.iter().map(|c| c.to_string()).collect() }));
    s.purge_guard = Some(Arc::new(Managed));
    let router = ui::editor::routes::router(st.clone());
    for (coll, d) in [
        ("application", doc! {"name": "zapp", "appCode": "zapp", "clientCode": "ZZ1"}),
        ("application", doc! {"name": "zapp2", "appCode": "zapp2", "clientCode": "ZZ10"}),
        ("page", doc! {"name": "home", "appCode": "zapp", "clientCode": "ZZ1"}),
        ("page", doc! {"name": "home", "appCode": "zapp", "clientCode": "ZZ10"}),
        ("page", doc! {"name": "about", "appCode": "zapp2", "clientCode": "ZZ1"}),
        ("version", doc! {"objectName": "home", "objectAppCode": "zapp", "clientCode": "ZZ10"}),
        ("uri_path", doc! {"name": "u", "appCode": "zapp2", "clientCode": "ZZ10"}),
    ] {
        mem.put_raw(coll, d);
    }
    Env { mem, router, st, probe: cache.family() }
}

impl Env {
    async fn purge(&self, client: Option<&str>, auth: &str, uri: &str) -> (StatusCode, String) {
        let mut req = Request::builder().method("DELETE").uri(uri).header("x-test-auth", auth);
        if let Some(c) = client {
            req = req.header("x-test-client", c);
        }
        let resp = self.router.clone().oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        // The report compact (the editor writes it pretty, as Jackson); anything else as sent.
        match overridable::json::parse(&body) {
            Ok(v) if status == StatusCode::OK => (status, overridable::json::to_compact(&v)),
            _ => (status, String::from_utf8_lossy(&body).into_owned()),
        }
    }

    fn count(&self, coll: &str) -> usize {
        self.mem.all(coll).len()
    }

    fn total(&self) -> usize {
        COLLECTIONS.iter().map(|c| self.count(c)).sum()
    }
}

#[tokio::test]
async fn only_a_managing_client_with_the_authority_may_purge_a_client() {
    let e = env();
    let (s, b) = e.purge(None, PURGERS, "/api/ui/purge/client/ZZ1?dryRun=false").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "{b}");
    let (s, b) = e.purge(Some(SYSTEM), "Authorities.Application_DELETE", "/api/ui/purge/client/ZZ1?dryRun=false").await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{b}");
    let (s, b) = e.purge(Some(SYSTEM), "Authorities.Client_DELETE", "/api/ui/purge/app/zapp?dryRun=false").await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{b}");
    // LZCLA does not manage ZZ1, and ZZ1 never purges itself.
    for caller in ["LZCLA", "ZZ1"] {
        let (s, b) = e.purge(Some(caller), PURGERS, "/api/ui/purge/client/ZZ1?dryRun=false").await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{caller}: {b}");
        assert!(b.contains("only a client that manages ZZ1"), "{b}");
    }
    let (s, b) = e.purge(Some("LZCLA"), PURGERS, "/api/ui/purge/app/zapp?dryRun=false").await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{b}");
    assert!(b.contains("SYSTEM client only"), "{b}");
    assert_eq!(e.total(), 7, "a refused purge deleted documents");
    // LZCLA manages ZZ10: its dry run answers.
    let (s, b) = e.purge(Some("LZCLA"), PURGERS, "/api/ui/purge/client/ZZ10").await;
    assert_eq!(s, StatusCode::OK, "{b}");
}

#[tokio::test]
async fn bad_codes_and_system_are_refused() {
    let e = env();
    for uri in ["/api/ui/purge/client/SYSTEM", "/api/ui/purge/client/ZZ_1", "/api/ui/purge/client/Z.Z", "/api/ui/purge/app/z-app", "/api/ui/purge/app/_"] {
        let (s, b) = e.purge(Some(SYSTEM), PURGERS, &format!("{uri}?dryRun=false")).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{uri}: {b}");
    }
    assert_eq!(e.total(), 7);
}

#[tokio::test]
async fn a_dry_run_unless_asked_then_the_clients_documents_go() {
    let e = env();
    let expected = r#""mongo":{"ui.application":1,"ui.page":2},"mysql":{},"dropped":[],"errors":[]}"#;
    for uri in ["/api/ui/purge/client/ZZ1", "/api/ui/purge/client/ZZ1?dryRun=true"] {
        let (s, b) = e.purge(Some(SYSTEM), PURGERS, uri).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b, format!(r#"{{"dryRun":true,{expected}"#));
    }
    assert_eq!(e.total(), 7, "a dry run deleted documents");

    let home = e.st.pages.cache_name("zapp", "home", false);
    let index = "ApplicationCache_zapp_indexNewCache_zapp".to_string();
    for c in [&home, &index] {
        e.probe.insert(c, "k".into(), 1).await;
    }
    let (s, b) = e.purge(Some(SYSTEM), PURGERS, "/api/ui/purge/client/ZZ1?dryRun=false").await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b, format!(r#"{{"dryRun":false,{expected}"#));
    assert_eq!((e.count("application"), e.count("page"), e.count("version"), e.count("uri_path")), (1, 1, 1, 1));
    assert!(e.mem.all("page").iter().all(|d| d.get_str("clientCode") == Ok("ZZ10")));
    for c in [&home, &index] {
        assert!(e.probe.get(c, &"k".to_string()).await.is_none(), "{c} outlived the purge");
    }
}

#[tokio::test]
async fn an_app_purge_reaches_every_client() {
    let e = env();
    let (s, b) = e.purge(Some(SYSTEM), PURGERS, "/api/ui/purge/app/zapp?dryRun=false").await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b, r#"{"dryRun":false,"mongo":{"ui.application":1,"ui.page":2,"ui.version":1},"mysql":{},"dropped":[],"errors":[]}"#);
    assert_eq!((e.count("application"), e.count("page"), e.count("version"), e.count("uri_path")), (1, 1, 0, 1));
    assert!(e.mem.all("page").iter().all(|d| d.get_str("appCode") == Ok("zapp2")));
}

#[tokio::test]
async fn a_failing_collection_is_reported_and_the_rest_goes_on() {
    let e = env();
    e.mem.fail("page", true);
    let (s, b) = e.purge(Some(SYSTEM), PURGERS, "/api/ui/purge/client/ZZ1?dryRun=false").await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert!(b.contains(r#""errors":["ui.page: "#), "{b}");
    assert_eq!(e.count("application"), 1);
}
