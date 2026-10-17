//! The overridable read path against a real MongoDB: the read halves of the Java ui's
//! `OverrideChainIntegrationTest`, `DraftSurfaceIntegrationTest`,
//! `DraftReconciliationIntegrationTest` and `DraftPublishIntegrationTest`, with the documents
//! those tests create through the Java services seeded directly.
//!
//! Gated: `#[ignore]`, and `OVERRIDABLE_TEST_MONGO=1`. Every test works in its own scratch
//! database on the local MongoDB (`overridable_rusttest_<epoch>_<rand>`, see `scratch`), dropped
//! at the end even when an assertion fails, and security is a fake on a local port. Run with
//! `OVERRIDABLE_TEST_MONGO=1 cargo test -p overridable -- --include-ignored`.

mod scratch;

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use mongodb::bson::{doc, oid::ObjectId, Bson, DateTime, Document};
use mongodb::Database;
use overridable::difference::apply_map;
use overridable::pojo::{map_field, set_opt_map, CloneRule, Field, Kind, Pojo, OVERRIDABLE_BASE};
use overridable::{DocType, JMap, JValue, Store};
use platform::cache::CacheService;
use platform::security::SecurityClient;
use platform::upstream::Upstream;

const APP: &str = "testapp";

/// A page-like document: identity plus a `properties` map merged key by key.
struct Doc;
const DOC: Pojo = Pojo {
    name: "Doc",
    parts: &[OVERRIDABLE_BASE, &[Field::new("properties", Kind::MapObject, CloneRule::MapObject)]],
};
impl DocType for Doc {
    fn object_name(&self) -> &'static str {
        "Page"
    }
    fn collection(&self) -> &'static str {
        "page"
    }
    fn pojo(&self) -> &'static Pojo {
        &DOC
    }
    fn apply_override(&self, mut this: JMap, base: &JMap) -> Option<JMap> {
        let p = apply_map(map_field(&this, "properties"), map_field(base, "properties"));
        set_opt_map(&mut this, "properties", p);
        Some(this)
    }
}

/// A class whose merge comes back empty (`AbstractFiller` with nothing on either side).
struct Empty;
impl DocType for Empty {
    fn object_name(&self) -> &'static str {
        "Filler"
    }
    fn collection(&self) -> &'static str {
        "filler"
    }
    fn pojo(&self) -> &'static Pojo {
        &DOC
    }
    fn draftable(&self) -> bool {
        false
    }
    fn apply_override(&self, _this: JMap, _base: &JMap) -> Option<JMap> {
        None
    }
}

#[derive(Default)]
struct FakeSecurity {
    chains: Mutex<HashMap<String, Vec<String>>>,
    calls: AtomicUsize,
}

async fn inheritance(State(f): State<Arc<FakeSecurity>>, Query(q): Query<HashMap<String, String>>) -> Json<Vec<String>> {
    f.calls.fetch_add(1, Ordering::SeqCst);
    let client = q.get("clientCode").cloned().unwrap_or_default();
    let chain = f.chains.lock().unwrap().get(&client).cloned().unwrap_or_else(|| vec![client.clone()]);
    Json(chain)
}

/// `getAppExplicitInfoByCode`: every app is SYSTEM's.
async fn explicit_app(axum::extract::Path(code): axum::extract::Path<String>) -> Json<serde_json::Value> {
    Json(serde_json::json!({"appCode": code, "clientCode": "SYSTEM", "appAccessType": "ANY"}))
}

/// `getClientHierarchyCodes`: the inheritance chain set for the client, nearest first.
async fn hierarchy(State(f): State<Arc<FakeSecurity>>, Query(q): Query<HashMap<String, String>>) -> Json<Vec<String>> {
    let client = q.get("clientCode").cloned().unwrap_or_default();
    let chain = f.chains.lock().unwrap().get(&client).cloned().unwrap_or_else(|| vec![client.clone()]);
    Json(chain.into_iter().rev().collect())
}

struct Env {
    db: Database,
    store: Store,
    cache: CacheService,
    fake: Arc<FakeSecurity>,
    /// Drops the database when the test ends, however it ends.
    _scratch: scratch::Scratch,
}

async fn env() -> Option<Env> {
    let scratch = scratch::Scratch::new().await?;
    let db = scratch.db.clone();
    let fake = Arc::new(FakeSecurity::default());
    let app = Router::new()
        .route("/api/security/applications/internal/appInheritance", get(inheritance))
        .route("/api/security/applications/internal/explicitInfo/{code}", get(explicit_app))
        .route("/api/security/clients/internal/clientHierarchyCodes", get(hierarchy))
        .with_state(fake.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await });
    let security = SecurityClient::new(Upstream::fixed(&[&format!("http://{addr}")]), 0).unwrap();
    let cache = CacheService::new("cmn", "evictionChannel", None).unwrap();
    let store = Store::new(db.clone(), security, &cache);
    Some(Env { db, store, cache, fake, _scratch: scratch })
}

impl Env {
    fn chain(&self, client: &str, chain: &[&str]) {
        self.fake
            .chains
            .lock()
            .unwrap()
            .insert(client.to_string(), chain.iter().map(|s| s.to_string()).collect());
    }

    async fn insert(&self, coll: &str, d: Document) -> String {
        let id = ObjectId::new();
        let mut d = d;
        d.insert("_id", id);
        self.db.collection::<Document>(coll).insert_one(d).await.unwrap();
        id.to_hex()
    }

    async fn page(&self, client: &str, base: Option<&str>, props: Document, published: Option<bool>, version: i32) -> String {
        let mut d = doc! {"name": "home", "appCode": APP, "clientCode": client, "version": version, "properties": props,
            "createdAt": DateTime::from_millis(1_700_000_000_000)};
        if let Some(b) = base {
            d.insert("baseClientCode", b);
        }
        if let Some(p) = published {
            d.insert("published", p);
        }
        self.insert("page", d).await
    }

    async fn draft(&self, client: &str, object_id: &str, content: Document, base_version: i32) {
        self.insert(
            "draft",
            doc! {"objectType": "PAGE", "objectAppCode": APP, "objectName": "home", "clientCode": client,
            "objectId": object_id, "content": content, "baseVersion": base_version, "version": 1},
        )
        .await;
    }

    async fn read(&self, client: &str, draft: bool) -> Option<JMap> {
        self.store
            .read(&Doc, "home", APP, client, client, draft)
            .await
            .unwrap()
            .map(|r| r.entity.clone())
    }

    /// The end of a test; the scratch database goes with `self`.
    async fn done(self) {}
}

fn prop<'a>(m: &'a JMap, k: &str) -> Option<&'a JValue> {
    map_field(m, "properties").and_then(|p| p.get(k))
}

fn s(v: &str) -> JValue {
    JValue::Str(v.to_string())
}

// OverrideChainIntegrationTest (reads)

#[tokio::test]
#[ignore = "needs the local MongoDB (OVERRIDABLE_TEST_MONGO=1)"]
async fn reads_own_content() {
    let Some(e) = env().await else { return };
    e.page("SYSTEM", None, doc! {"title": "Base", "k": 1_i32}, None, 1).await;
    let got = e.read("SYSTEM", false).await.unwrap();
    assert_eq!(prop(&got, "title"), Some(&s("Base")));
    assert_eq!(got["createdAt"], JValue::Int(1_700_000_000));
    e.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (OVERRIDABLE_TEST_MONGO=1)"]
async fn read_merges_child_over_base() {
    let Some(e) = env().await else { return };
    e.chain("CHILD", &["SYSTEM", "CHILD"]);
    e.page("SYSTEM", None, doc! {"title": "Base", "keep": "base"}, None, 1).await;
    e.page("CHILD", Some("SYSTEM"), doc! {"title": "Child"}, None, 1).await;
    let got = e.read("CHILD", false).await.unwrap();
    assert_eq!(prop(&got, "title"), Some(&s("Child")));
    assert_eq!(prop(&got, "keep"), Some(&s("base")));
    assert_eq!(got["clientCode"], s("CHILD"));
    e.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (OVERRIDABLE_TEST_MONGO=1)"]
async fn read_merges_all_three_levels() {
    let Some(e) = env().await else { return };
    e.chain("LEAF", &["SYSTEM", "MID", "LEAF"]);
    e.page("SYSTEM", None, doc! {"a": "base", "b": "base", "c": "base"}, None, 1).await;
    e.page("MID", Some("SYSTEM"), doc! {"b": "mid", "c": "mid"}, None, 1).await;
    e.page("LEAF", Some("MID"), doc! {"c": "leaf"}, None, 1).await;
    let got = e.read("LEAF", false).await.unwrap();
    assert_eq!(prop(&got, "a"), Some(&s("base")));
    assert_eq!(prop(&got, "b"), Some(&s("mid")));
    assert_eq!(prop(&got, "c"), Some(&s("leaf")));
    e.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (OVERRIDABLE_TEST_MONGO=1)"]
async fn read_does_not_mutate_stored_leaf() {
    let Some(e) = env().await else { return };
    e.chain("LEAF", &["SYSTEM", "MID", "LEAF"]);
    e.page("SYSTEM", None, doc! {"a": "base"}, None, 1).await;
    e.page("MID", Some("SYSTEM"), doc! {"b": "mid"}, None, 1).await;
    let leaf = e.page("LEAF", Some("MID"), doc! {"c": "leaf"}, None, 1).await;
    e.read("LEAF", false).await.unwrap();
    let stored = e.store.find_by_id(&Doc, &leaf).await.unwrap().unwrap();
    assert_eq!(map_field(&stored, "properties").unwrap().len(), 1, "the stored leaf is still a delta");
    e.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (OVERRIDABLE_TEST_MONGO=1)"]
async fn read_merges_all_four_levels() {
    let Some(e) = env().await else { return };
    e.chain("L2", &["SYSTEM", "MID", "LEAF", "L2"]);
    e.page("SYSTEM", None, doc! {"a": 1_i32, "b": 1_i32, "c": 1_i32, "d": 1_i32}, None, 1).await;
    e.page("MID", Some("SYSTEM"), doc! {"b": 2_i32}, None, 1).await;
    e.page("LEAF", Some("MID"), doc! {"c": 3_i32}, None, 1).await;
    e.page("L2", Some("LEAF"), doc! {"d": 4_i32, "a": null}, None, 1).await;
    let got = e.read("L2", false).await.unwrap();
    assert_eq!(prop(&got, "a"), None, "a null in the override deletes");
    assert_eq!(prop(&got, "b"), Some(&JValue::Int(2)));
    assert_eq!(prop(&got, "c"), Some(&JValue::Int(3)));
    assert_eq!(prop(&got, "d"), Some(&JValue::Int(4)));
    e.done().await;
}

// DraftSurfaceIntegrationTest / DraftPublishIntegrationTest (reads)

#[tokio::test]
#[ignore = "needs the local MongoDB (OVERRIDABLE_TEST_MONGO=1)"]
async fn serves_draft_only_on_draft_surface() {
    let Some(e) = env().await else { return };
    let id = e.page("SYSTEM", None, doc! {"title": "Live"}, None, 1).await;
    e.draft("SYSTEM", &id, doc! {"name": "home", "properties": {"title": "Draft"}}, 1).await;
    assert_eq!(prop(&e.read("SYSTEM", false).await.unwrap(), "title"), Some(&s("Live")), "invisible to the runtime read");
    assert_eq!(prop(&e.read("SYSTEM", true).await.unwrap(), "title"), Some(&s("Draft")));
    e.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (OVERRIDABLE_TEST_MONGO=1)"]
async fn falls_back_to_live() {
    let Some(e) = env().await else { return };
    e.page("SYSTEM", None, doc! {"title": "Live"}, None, 1).await;
    assert_eq!(prop(&e.read("SYSTEM", true).await.unwrap(), "title"), Some(&s("Live")));
    e.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (OVERRIDABLE_TEST_MONGO=1)"]
async fn shows_unpublished() {
    let Some(e) = env().await else { return };
    e.page("SYSTEM", None, doc! {"title": "New"}, Some(false), 1).await;
    assert!(e.read("SYSTEM", false).await.is_none(), "the live surface hides never-published objects");
    assert_eq!(prop(&e.read("SYSTEM", true).await.unwrap(), "title"), Some(&s("New")));
    e.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (OVERRIDABLE_TEST_MONGO=1)"]
async fn an_unpublished_override_falls_back_to_the_published_base() {
    let Some(e) = env().await else { return };
    e.chain("CHILD", &["SYSTEM", "CHILD"]);
    e.page("SYSTEM", None, doc! {"title": "Base"}, None, 1).await;
    e.page("CHILD", Some("SYSTEM"), doc! {"title": "Fork"}, Some(false), 1).await;
    let live = e.read("CHILD", false).await.unwrap();
    assert_eq!(prop(&live, "title"), Some(&s("Base")));
    assert_eq!(live["clientCode"], s("SYSTEM"));
    assert_eq!(prop(&e.read("CHILD", true).await.unwrap(), "title"), Some(&s("Fork")));
    e.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (OVERRIDABLE_TEST_MONGO=1)"]
async fn base_draft_not_served_to_derived() {
    let Some(e) = env().await else { return };
    e.chain("CHILD", &["SYSTEM", "CHILD"]);
    let id = e.page("SYSTEM", None, doc! {"title": "Live"}, None, 1).await;
    e.draft("SYSTEM", &id, doc! {"properties": {"title": "Base draft"}}, 1).await;
    assert_eq!(prop(&e.read("CHILD", true).await.unwrap(), "title"), Some(&s("Live")));
    // base_sees_own_draft
    assert_eq!(prop(&e.read("SYSTEM", true).await.unwrap(), "title"), Some(&s("Base draft")));
    e.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (OVERRIDABLE_TEST_MONGO=1)"]
async fn derived_sees_own_draft() {
    let Some(e) = env().await else { return };
    e.chain("CHILD", &["SYSTEM", "CHILD"]);
    e.page("SYSTEM", None, doc! {"title": "Base"}, None, 1).await;
    let child = e.page("CHILD", Some("SYSTEM"), doc! {"title": "Child"}, None, 1).await;
    e.draft("CHILD", &child, doc! {"properties": {"title": "Child draft"}}, 1).await;
    assert_eq!(prop(&e.read("CHILD", true).await.unwrap(), "title"), Some(&s("Child draft")));
    assert_eq!(prop(&e.read("CHILD", false).await.unwrap(), "title"), Some(&s("Child")));
    e.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (OVERRIDABLE_TEST_MONGO=1)"]
async fn mid_draft_not_served_to_leaf() {
    let Some(e) = env().await else { return };
    e.chain("LEAF", &["SYSTEM", "MID", "LEAF"]);
    e.page("SYSTEM", None, doc! {"title": "Base"}, None, 1).await;
    let mid = e.page("MID", Some("SYSTEM"), doc! {"title": "Mid"}, None, 1).await;
    e.draft("MID", &mid, doc! {"properties": {"title": "Mid draft"}}, 1).await;
    assert_eq!(prop(&e.read("LEAF", true).await.unwrap(), "title"), Some(&s("Mid")));
    e.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (OVERRIDABLE_TEST_MONGO=1)"]
async fn neither_surface_poisons_the_others_cache() {
    let Some(e) = env().await else { return };
    let id = e.page("SYSTEM", None, doc! {"title": "Live"}, None, 1).await;
    e.draft("SYSTEM", &id, doc! {"properties": {"title": "Draft"}}, 1).await;
    // draft_does_not_poison_live_cache
    assert_eq!(prop(&e.read("SYSTEM", true).await.unwrap(), "title"), Some(&s("Draft")));
    assert_eq!(prop(&e.read("SYSTEM", false).await.unwrap(), "title"), Some(&s("Live")));
    // live_does_not_poison_draft_cache
    assert_eq!(prop(&e.read("SYSTEM", true).await.unwrap(), "title"), Some(&s("Draft")));
    e.done().await;
}

// DraftReconciliationIntegrationTest (the draft surface half)

async fn snapshot(e: &Env, version: i32, object: Document) {
    e.insert(
        "version",
        doc! {"objectType": "PAGE", "objectAppCode": APP, "objectName": "home", "clientCode": "SYSTEM",
        "versionNumber": version, "object": object, "createdAt": DateTime::now()},
    )
    .await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (OVERRIDABLE_TEST_MONGO=1)"]
async fn draft_surface_carries_live_changes_in() {
    let Some(e) = env().await else { return };
    // Live moved to v2 (title added) after the draft was taken at v1 (which changed theme).
    let id = e.page("SYSTEM", None, doc! {"theme": "light", "title": "Web Smith", "gone": null}, None, 2).await;
    snapshot(&e, 1, doc! {"properties": {"theme": "light", "gone": "x"}}).await;
    e.draft("SYSTEM", &id, doc! {"name": "evil", "appCode": "other", "properties": {"theme": "dark", "gone": "x"}}, 1).await;
    let got = e.read("SYSTEM", true).await.unwrap();
    assert_eq!(prop(&got, "theme"), Some(&s("dark")), "the draft's own edit");
    assert_eq!(prop(&got, "title"), Some(&s("Web Smith")), "the live change made after the draft");
    assert_eq!(prop(&got, "gone"), None, "a key the live document deleted stays deleted");
    // identity_is_not_mergeable
    assert_eq!(got["name"], s("home"));
    assert_eq!(got["appCode"], s(APP));
    assert_eq!(got["version"], JValue::Int(2), "stamped with the live version");
    // live_surface_is_unaffected
    assert_eq!(prop(&e.read("SYSTEM", false).await.unwrap(), "theme"), Some(&s("light")));
    e.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (OVERRIDABLE_TEST_MONGO=1)"]
async fn real_conflict_keeps_the_draft() {
    let Some(e) = env().await else { return };
    let id = e.page("SYSTEM", None, doc! {"title": "Live title"}, None, 2).await;
    snapshot(&e, 1, doc! {"properties": {"title": "Old"}}).await;
    e.draft("SYSTEM", &id, doc! {"properties": {"title": "Draft title"}}, 1).await;
    assert_eq!(prop(&e.read("SYSTEM", true).await.unwrap(), "title"), Some(&s("Draft title")));
    e.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (OVERRIDABLE_TEST_MONGO=1)"]
async fn no_base_snapshot_serves_the_draft_unmerged() {
    let Some(e) = env().await else { return };
    let id = e.page("SYSTEM", None, doc! {"title": "Live", "extra": 1_i32}, None, 3).await;
    e.draft("SYSTEM", &id, doc! {"properties": {"title": "Draft"}}, 1).await;
    let got = e.read("SYSTEM", true).await.unwrap();
    assert_eq!(prop(&got, "title"), Some(&s("Draft")));
    assert_eq!(prop(&got, "extra"), None, "nothing to merge from, so nothing pulled in");
    assert_eq!(got["version"], JValue::Int(1), "still claims the frozen base");
    e.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (OVERRIDABLE_TEST_MONGO=1)"]
async fn merges_from_the_frozen_base() {
    let Some(e) = env().await else { return };
    let id = e.page("SYSTEM", None, doc! {"a": "live", "b": "v3"}, None, 3).await;
    snapshot(&e, 1, doc! {"properties": {"a": "v1", "b": "v1"}}).await;
    snapshot(&e, 2, doc! {"properties": {"a": "v2", "b": "v2"}}).await;
    e.draft("SYSTEM", &id, doc! {"properties": {"a": "v1", "b": "draft"}}, 1).await;
    let got = e.read("SYSTEM", true).await.unwrap();
    assert_eq!(prop(&got, "a"), Some(&s("live")), "untouched by the draft since v1: live wins");
    assert_eq!(prop(&got, "b"), Some(&s("draft")));
    e.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (OVERRIDABLE_TEST_MONGO=1)"]
async fn reconciles_across_an_override_chain() {
    let Some(e) = env().await else { return };
    e.chain("CHILD", &["SYSTEM", "CHILD"]);
    e.page("SYSTEM", None, doc! {"base": "b", "title": "Base"}, None, 1).await;
    let child = e.page("CHILD", Some("SYSTEM"), doc! {"title": "Child"}, None, 2).await;
    e.insert(
        "version",
        doc! {"objectType": "PAGE", "objectAppCode": APP, "objectName": "home", "clientCode": "CHILD",
        "versionNumber": 1_i32, "object": {"properties": {"base": "b", "title": "Child"}}, "createdAt": DateTime::now()},
    )
    .await;
    e.draft("CHILD", &child, doc! {"properties": {"base": "b", "title": "Child draft"}}, 1).await;
    let got = e.read("CHILD", true).await.unwrap();
    assert_eq!(prop(&got, "title"), Some(&s("Child draft")));
    assert_eq!(prop(&got, "base"), Some(&s("b")), "the applied form, inherited value included");
    e.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (OVERRIDABLE_TEST_MONGO=1)"]
async fn a_draft_with_no_content_still_reads() {
    let Some(e) = env().await else { return };
    let id = e.page("SYSTEM", None, doc! {"title": "Live"}, None, 1).await;
    e.insert(
        "draft",
        doc! {"objectType": "PAGE", "objectAppCode": APP, "objectName": "home", "clientCode": "SYSTEM", "objectId": &id},
    )
    .await;
    let got = e.read("SYSTEM", true).await.unwrap();
    assert_eq!(got["name"], s("home"));
    e.done().await;
}

// The store's own machinery

#[tokio::test]
#[ignore = "needs the local MongoDB (OVERRIDABLE_TEST_MONGO=1)"]
async fn definitions_and_inheritance_are_cached_until_evicted() {
    let Some(e) = env().await else { return };
    let id = e.page("SYSTEM", None, doc! {"title": "One"}, None, 1).await;
    let first = e.store.read(&Doc, "home", APP, "SYSTEM", "SYSTEM", false).await.unwrap().unwrap();
    e.db
        .collection::<Document>("page")
        .update_one(doc! {"_id": ObjectId::parse_str(&id).unwrap()}, doc! {"$set": {"properties.title": "Two"}})
        .await
        .unwrap();
    let cached = e.store.read(&Doc, "home", APP, "SYSTEM", "SYSTEM", false).await.unwrap().unwrap();
    assert_eq!(cached.unique_id, first.unique_id, "served from the definition cache");
    assert_eq!(e.fake.calls.load(Ordering::SeqCst), 1, "inheritance asked once");
    // A Java save publishes cmn-PageCache_testapp_home:*; the local half of that is this.
    e.cache.evict_all_everywhere("PageCache_testapp_home").await;
    let fresh = e.store.read(&Doc, "home", APP, "SYSTEM", "SYSTEM", false).await.unwrap().unwrap();
    assert_eq!(prop(&fresh.entity, "title"), Some(&s("Two")));
    assert_ne!(fresh.unique_id, first.unique_id);
    assert!(e.store.read(&Doc, "nosuch", APP, "SYSTEM", "SYSTEM", false).await.unwrap().is_none());
    e.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (OVERRIDABLE_TEST_MONGO=1)"]
async fn odd_chains_and_ids() {
    let Some(e) = env().await else { return };
    // A cycle in baseClientCode stops at the bound instead of spinning.
    e.chain("A", &["B", "A"]);
    e.page("A", Some("B"), doc! {"a": 1_i32}, None, 1).await;
    e.page("B", Some("A"), doc! {"b": 1_i32}, None, 1).await;
    let got = e.read("A", false).await.unwrap();
    assert_eq!(prop(&got, "a"), Some(&JValue::Int(1)));
    // A base that does not exist, with no copy above it either, ends the chain.
    e.chain("ORPHAN", &["ORPHAN"]);
    let orphan = e.page("ORPHAN", Some("NOBODY"), doc! {"o": 1_i32}, None, 1).await;
    assert!(e.store.read_merged_by_id(&Doc, &orphan).await.unwrap().is_some());
    // A base client without a copy is walked past to the copy its own base has: NOBODY is
    // managed by nobody, so the app owner's.
    e.page("SYSTEM", None, doc! {"root": 1_i32}, None, 1).await;
    let walked = e.store.read_merged_by_id(&Doc, &orphan).await.unwrap().unwrap();
    assert_eq!((prop(&walked, "o"), prop(&walked, "root")), (Some(&JValue::Int(1)), Some(&JValue::Int(1))));
    // String ids and unknown ids.
    e.db
        .collection::<Document>("page")
        .insert_one(doc! {"_id": "plain-id", "name": "x", "appCode": APP, "clientCode": "SYSTEM"})
        .await
        .unwrap();
    assert!(e.store.find_by_id(&Doc, "plain-id").await.unwrap().is_some());
    assert!(e.store.read_merged_by_id(&Doc, "63bd2d154d18a31536e81fa5").await.unwrap().is_none());
    // A class whose merge is empty: the merged sources vanish, the document stands alone.
    e.insert("filler", doc! {"name": "f", "appCode": APP, "clientCode": "SYSTEM", "properties": {"x": 1_i32}}).await;
    let child = e.insert("filler", doc! {"name": "f", "appCode": APP, "clientCode": "C", "baseClientCode": "SYSTEM"}).await;
    e.insert("filler", doc! {"name": "f", "appCode": APP, "clientCode": "D", "baseClientCode": "C"}).await;
    assert!(e.store.read_merged_by_id(&Empty, &child).await.unwrap().is_none());
    e.chain("D", &["SYSTEM", "C", "D"]);
    assert!(e.store.read(&Empty, "f", APP, "D", "D", true).await.unwrap().is_some(), "Java applies nothing and serves D alone");
    // Duplicates for one client: the first in natural order wins, as in Java.
    let docs = e.store.find_docs("page", doc! {"name": "home"}).await.unwrap();
    assert!(docs.len() >= 3);
    assert!(matches!(docs[0].get("_id"), Some(Bson::ObjectId(_))));
    e.done().await;
}
