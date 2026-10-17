//! `readOrder` / `managingChain` and `baseDocument` / `baseClientCodeOf` of
//! `AbstractOverridableDataService` (nocode-saas commit 3cf6ebc54): a client's reads
//! and its own copy's merge both go through the level above it, its managing client, whether or
//! not that level has a copy. Hierarchy as in Java's `PageClientPatchIntegrationTest`: SYSTEM owns
//! the app, MID is managed by SYSTEM, LEAF by MID.

mod common;

use std::sync::Arc;

use common::*;
use overridable::backend::{ExplicitApp, FakeDirectory, MemBackend};
use overridable::write::persist::to_document;
use overridable::{JValue, Store};
use platform::cache::CacheService;

const NAME: &str = "clientPatchPage";
const MID: &str = "LZMID";
const LEAF: &str = "LZLEAF";

struct Fixture {
    mem: Arc<MemBackend>,
    dir: Arc<FakeDirectory>,
    store: Store,
    kind: PageKind,
}

fn fixture() -> Fixture {
    let mem = Arc::new(MemBackend::new());
    let dir = Arc::new(FakeDirectory::new());
    dir.hierarchy(MID, &[MID, SYSTEM]);
    dir.hierarchy(LEAF, &[LEAF, MID, SYSTEM]);
    let cache = CacheService::new("cmn", "evictionChannel", None).unwrap();
    let store = Store::with_parts(mem.clone(), dir.clone(), &cache).unwrap();
    Fixture { mem, dir, store, kind: PageKind::default() }
}

impl Fixture {
    fn add(&self, client: &str, base: Option<&str>, properties: &str) -> String {
        let base = base.map(|b| format!(r#","baseClientCode":"{b}""#)).unwrap_or_default();
        let m = obj(&format!(r#"{{"name":"{NAME}","appCode":"{APP}","clientCode":"{client}","version":1{base},"properties":{properties}}}"#));
        let id = self.mem.put_raw("page", to_document(&PAGE, &m, None, &[]));
        overridable::bson_conv::to_java_string(&id).java_to_string()
    }

    async fn read(&self, url: &str, client: &str) -> Option<JValue> {
        self.store.read(&self.kind, NAME, APP, url, client, false).await.unwrap().map(|r| r.entity.get("properties").cloned().unwrap_or_default())
    }
}

fn title(v: &Option<JValue>) -> Option<&str> {
    v.as_ref().and_then(JValue::as_object).and_then(|p| p.get("title")).and_then(JValue::as_str)
}

#[tokio::test]
async fn the_read_order_adds_the_managing_chain_below_the_client() {
    let f = fixture();
    // App inheritance on LEAF's own URL skips MID.
    f.dir.chain(&[SYSTEM, LEAF]);
    assert_eq!(*f.store.read_order(APP, LEAF, LEAF).await.unwrap(), vec![SYSTEM, MID, LEAF]);
    // Already there: nothing is added twice.
    f.dir.chain(&[SYSTEM, MID, LEAF]);
    assert_eq!(*f.store.read_order(APP, "X", LEAF).await.unwrap(), vec![SYSTEM, MID, LEAF]);
    // The owner has no managing chain.
    f.dir.chain(&[SYSTEM]);
    assert_eq!(*f.store.read_order(APP, SYSTEM, SYSTEM).await.unwrap(), vec![SYSTEM]);
}

#[tokio::test]
async fn a_client_without_a_copy_is_served_its_managing_clients_customization() {
    let f = fixture();
    f.add(SYSTEM, None, r#"{"title":"base"}"#);
    f.add(MID, Some(SYSTEM), r#"{"title":"MID's"}"#);
    // LEAF on its own URL: app inheritance alone is [SYSTEM, LEAF].
    f.dir.chain(&[SYSTEM, LEAF]);
    assert_eq!(title(&f.read(LEAF, LEAF).await), Some("MID's"));
}

#[tokio::test]
async fn a_failed_hierarchy_lookup_keeps_the_inheritance_order() {
    let f = fixture();
    f.dir.chain(&[SYSTEM, LEAF]);
    f.dir.set(|a| {
        a.apps.insert(APP.into(), None);
    });
    assert_eq!(*f.store.read_order(APP, LEAF, LEAF).await.unwrap(), vec![SYSTEM, LEAF], "an unknown app has no managing chain");
}

#[tokio::test]
async fn a_copy_merges_past_a_level_with_no_copy_of_its_own() {
    let f = fixture();
    f.dir.chain(&[SYSTEM, MID, LEAF]);
    f.add(SYSTEM, None, r#"{"title":"base","subtitle":"s"}"#);
    let leaf = f.add(LEAF, Some(MID), r#"{"title":"LEAF's"}"#);
    let merged = f.store.read_merged_by_id(&f.kind, &leaf).await.unwrap().unwrap();
    let props = merged.get("properties").and_then(JValue::as_object).unwrap();
    assert_eq!((props.get("title"), props.get("subtitle")), (Some(&JValue::from("LEAF's")), Some(&JValue::from("s"))));
}

#[tokio::test]
async fn the_base_client_rule() {
    let f = fixture();
    assert_eq!(f.store.base_client_code_of(APP, LEAF).await.unwrap().as_deref(), Some(MID));
    assert_eq!(f.store.base_client_code_of(APP, MID).await.unwrap().as_deref(), Some(SYSTEM));
    assert_eq!(f.store.base_client_code_of(APP, SYSTEM).await.unwrap(), None);
    // An app owned by MID: a client managed by SYSTEM directly stands on MID.
    f.dir.set(|a| {
        a.apps.insert(
            "midapp".into(),
            Some(ExplicitApp { app_access_type: Some("ANY".into()), client_code: Some(MID.into()), explicit_owner_client_code: None }),
        );
    });
    f.dir.hierarchy("OTHER", &["OTHER", SYSTEM]);
    assert_eq!(f.store.base_client_code_of("midapp", "OTHER").await.unwrap().as_deref(), Some(MID));
    assert_eq!(f.store.base_client_code_of("midapp", MID).await.unwrap(), None);
}
