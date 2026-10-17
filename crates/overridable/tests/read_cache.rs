//! The commons `AbstractOverridableReadCacheTest` (nocode-saas, uncommitted on 2026-10-15): a
//! cache hit in `read(name, appCode, urlClientCode, clientCode, draft)` touches no repository
//! method. Java's hit used to re-read the document and its ancestors and throw the read away;
//! `Store::read` loads only on a miss, which these tests pin down.

mod common;

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use common::*;
use mongodb::bson::{Bson, Document};
use overridable::backend::{Backend, FakeDirectory, Find, MemBackend};
use overridable::write::persist::to_document;
use overridable::{JValue, Store};
use platform::cache::CacheService;

const NAME: &str = "nightly";

/// The in-memory backend, recording every call the store makes.
struct Counting {
    inner: Arc<MemBackend>,
    calls: Mutex<Vec<String>>,
}

impl Counting {
    fn note(&self, what: &str, collection: &str) {
        self.calls.lock().unwrap().push(format!("{what} {collection}"));
    }
    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.calls.lock().unwrap())
    }
}

#[async_trait]
impl Backend for Counting {
    async fn find(&self, collection: &str, query: Find) -> anyhow::Result<Vec<Document>> {
        self.note("find", collection);
        self.inner.find(collection, query).await
    }
    async fn find_one(&self, collection: &str, filter: Document, sort: Option<Document>) -> anyhow::Result<Option<Document>> {
        self.note("find_one", collection);
        self.inner.find_one(collection, filter, sort).await
    }
    async fn count(&self, collection: &str, filter: Document) -> anyhow::Result<u64> {
        self.note("count", collection);
        self.inner.count(collection, filter).await
    }
    async fn insert(&self, collection: &str, doc: Document) -> anyhow::Result<Bson> {
        self.note("insert", collection);
        self.inner.insert(collection, doc).await
    }
    async fn replace(&self, collection: &str, id: Bson, doc: Document) -> anyhow::Result<()> {
        self.note("replace", collection);
        self.inner.replace(collection, id, doc).await
    }
    async fn delete_one(&self, collection: &str, filter: Document) -> anyhow::Result<u64> {
        self.note("delete_one", collection);
        self.inner.delete_one(collection, filter).await
    }
    async fn delete_many(&self, collection: &str, filter: Document) -> anyhow::Result<u64> {
        self.note("delete_many", collection);
        self.inner.delete_many(collection, filter).await
    }
    async fn update_many(&self, collection: &str, filter: Document, set: Document) -> anyhow::Result<u64> {
        self.note("update_many", collection);
        self.inner.update_many(collection, filter, set).await
    }
}

struct Fixture {
    db: Arc<Counting>,
    store: Store,
    kind: PageKind,
}

fn fixture(chain: &[&str]) -> Fixture {
    let mem = Arc::new(MemBackend::new());
    let dir = Arc::new(FakeDirectory::new());
    dir.chain(chain);
    let db = Arc::new(Counting { inner: mem, calls: Mutex::new(Vec::new()) });
    let cache = CacheService::new("cmn", "evictionChannel", None).unwrap();
    let store = Store::with_parts(db.clone(), dir, &cache).unwrap();
    Fixture { db, store, kind: PageKind::default() }
}

impl Fixture {
    fn add(&self, client: &str, base: Option<&str>, properties: &str) {
        let base = base.map(|b| format!(r#","baseClientCode":"{b}""#)).unwrap_or_default();
        let m = obj(&format!(r#"{{"name":"{NAME}","appCode":"{APP}","clientCode":"{client}","version":1{base},"properties":{properties}}}"#));
        self.db.inner.put_raw("page", to_document(&PAGE, &m, None, &[]));
    }

    async fn read(&self, client: &str, draft: bool) -> Option<JValue> {
        self.store
            .read(&self.kind, NAME, APP, client, client, draft)
            .await
            .unwrap()
            .map(|r| r.entity.get("properties").cloned().unwrap_or_default())
    }
}

#[tokio::test]
async fn a_cache_hit_reads_nothing_from_the_database() {
    let f = fixture(&[SYSTEM]);
    f.add(SYSTEM, None, r#"{"cron":"0 0 * * * *"}"#);
    let first = f.read(SYSTEM, false).await;
    assert!(!f.db.take().is_empty(), "the first read goes to the database");
    let second = f.read(SYSTEM, false).await;
    assert_eq!(f.db.take(), Vec::<String>::new());
    assert_eq!(first, second);
}

#[tokio::test]
async fn a_merged_override_is_served_from_the_cache_without_reading_its_ancestors() {
    let f = fixture(&[SYSTEM, "FIN"]);
    f.add(SYSTEM, None, r#"{"cron":"0 0 * * * *","timezone":"UTC"}"#);
    f.add("FIN", Some(SYSTEM), r#"{"timezone":"Asia/Kolkata"}"#);
    let first = f.read("FIN", false).await;
    let calls = f.db.take();
    assert!(calls.len() > 1, "the first read walks to the ancestor: {calls:?}");
    let props = first.as_ref().and_then(JValue::as_object).unwrap();
    assert_eq!((props.get("cron"), props.get("timezone")), (Some(&JValue::from("0 0 * * * *")), Some(&JValue::from("Asia/Kolkata"))));
    let second = f.read("FIN", false).await;
    assert_eq!(f.db.take(), Vec::<String>::new());
    assert_eq!(first, second);
}

#[tokio::test]
async fn another_client_is_still_a_miss() {
    let f = fixture(&[SYSTEM]);
    f.add(SYSTEM, None, r#"{"cron":"0 0 * * * *"}"#);
    f.read("FIN", false).await;
    f.db.take();
    f.read("AKASH", false).await;
    assert!(!f.db.take().is_empty(), "a different client is a different key");
}

#[tokio::test]
async fn live_and_draft_do_not_share_an_entry() {
    let f = fixture(&[SYSTEM]);
    f.add(SYSTEM, None, r#"{"cron":"0 0 * * * *"}"#);
    f.read(SYSTEM, false).await;
    f.db.take();
    f.read(SYSTEM, true).await;
    assert!(!f.db.take().is_empty(), "the draft surface has its own cache");
}
