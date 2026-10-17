//! The in-memory harness the write-path tests share: the Java integration tests'
//! `AbstractIntegrationTest` (permissive security, `setInheritance`, `authFor`, `insertRaw`),
//! on [`MemBackend`] and [`FakeDirectory`], with a page-like and a storage-like kind.
#![allow(dead_code)]

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use mongodb::bson::Document;
use overridable::backend::{FakeDirectory, MemBackend};
use overridable::difference::{apply_map, extract_map};
use overridable::json::parse;
use overridable::pojo::{map_field, set_opt_map, str_field, CloneRule, Field, Kind as K, Pojo, OVERRIDABLE_BASE};
use overridable::write::kind::{Kind, Method};
use overridable::write::persist::to_document;
use overridable::write::version::UI_AUTH_NAMES;
use overridable::write::{Commons, Messages, OverridableService};
use overridable::{DocType, JMap, JValue, Store};
use platform::cache::{CacheService, LocalCaches};
use platform::error::AppResult;
use platform::security::{ContextAuthentication, ContextUser};

pub const SYSTEM: &str = "SYSTEM";
pub const APP: &str = "testapp";

pub const PAGE: Pojo = Pojo {
    name: "Page",
    parts: &[
        OVERRIDABLE_BASE,
        &[Field::new("rootComponent", K::Str, CloneRule::Copy), Field::new("properties", K::MapObject, CloneRule::MapObject)],
    ],
};

/// A page as far as the override machinery sees one: `properties` merged key by key,
/// `rootComponent` inherited when unset. Records the hooks it is called with.
#[derive(Default)]
pub struct PageKind {
    pub log: Arc<Mutex<Vec<String>>>,
}

impl PageKind {
    pub fn calls(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }

    fn note(&self, s: String) {
        self.log.lock().unwrap().push(s);
    }
}

impl DocType for PageKind {
    fn object_name(&self) -> &'static str {
        "Page"
    }
    fn collection(&self) -> &'static str {
        "page"
    }
    fn pojo(&self) -> &'static Pojo {
        &PAGE
    }
    fn apply_override(&self, mut this: JMap, base: &JMap) -> Option<JMap> {
        let p = apply_map(map_field(&this, "properties"), map_field(base, "properties"));
        set_opt_map(&mut this, "properties", p);
        if this.get("rootComponent").is_none_or(JValue::is_null) {
            this.insert("rootComponent".into(), base.get("rootComponent").cloned().unwrap_or_default());
        }
        Some(this)
    }
    fn extract_difference(&self, mut this: JMap, base: &JMap) -> Option<JMap> {
        let p = extract_map(map_field(&this, "properties"), map_field(base, "properties"));
        this.insert("properties".into(), JValue::Object(p));
        if this.get("rootComponent").is_some() && this.get("rootComponent") == base.get("rootComponent") {
            this.insert("rootComponent".into(), JValue::Null);
        }
        Some(this)
    }
}

#[async_trait]
impl Kind for PageKind {
    fn delete_reads_first(&self) -> bool {
        true
    }
    async fn after_create(&self, _cx: &Commons, created: &JMap) -> AppResult<()> {
        self.note(format!("after_create {}", str_field(created, "name").unwrap_or("")));
        Ok(())
    }
    async fn after_update(&self, cx: &Commons, request: &JMap, saved: &JMap) -> AppResult<()> {
        // The ui base class: the OUI caches of the app, keyed on the body's app code.
        cx.evict_all(&format!("pageOUICache-{}", str_field(request, "appCode").unwrap_or("null"))).await;
        self.note(format!("after_update {}", str_field(saved, "name").unwrap_or("")));
        Ok(())
    }
    async fn after_delete(&self, _cx: &Commons, deleted: &JMap, result: bool) -> AppResult<bool> {
        self.note(format!("after_delete {}", str_field(deleted, "name").unwrap_or("")));
        Ok(result)
    }
    async fn after_evict_recursively(&self, _cx: &Commons, app: &str, client: &str, name: &str) -> AppResult<()> {
        self.note(format!("evict_recursively {app} {client} {name}"));
        Ok(())
    }
    async fn after_evict_draft(&self, _cx: &Commons, app: &str, client: &str, name: &str) -> AppResult<()> {
        self.note(format!("evict_draft {app} {client} {name}"));
        Ok(())
    }
    async fn after_delete_everything(&self, _cx: &Commons, app: &str, client: &str) -> AppResult<()> {
        self.note(format!("delete_everything {app} {client}"));
        Ok(())
    }
}

pub const STORAGE: Pojo = Pojo {
    name: "Storage",
    parts: &[
        OVERRIDABLE_BASE,
        &[
            Field::new("uniqueName", K::Str, CloneRule::Copy),
            Field::new("schema", K::MapObject, CloneRule::MapObject),
            Field::new("indexes", K::MapObject, CloneRule::MapObject),
            Field::new("relations", K::MapObject, CloneRule::MapObject),
        ],
    ],
};

/// A storage as far as the override machinery sees one, with every hook left at its default.
pub struct StorageKind;

impl DocType for StorageKind {
    fn object_name(&self) -> &'static str {
        "Storage"
    }
    fn collection(&self) -> &'static str {
        "storage"
    }
    fn pojo(&self) -> &'static Pojo {
        &STORAGE
    }
    fn apply_override(&self, mut this: JMap, base: &JMap) -> Option<JMap> {
        for f in ["schema", "indexes", "relations"] {
            let m = apply_map(map_field(&this, f), map_field(base, f));
            set_opt_map(&mut this, f, m);
        }
        Some(this)
    }
    fn extract_difference(&self, mut this: JMap, base: &JMap) -> Option<JMap> {
        for f in ["schema", "indexes", "relations"] {
            let m = extract_map(map_field(&this, f), map_field(base, f));
            this.insert(f.into(), JValue::Object(m));
        }
        Some(this)
    }
}

impl Kind for StorageKind {
    fn transport_dependencies(&self, entity: &JMap) -> Vec<String> {
        map_field(entity, "relations")
            .map(|r| r.values().filter_map(|v| v.as_object().and_then(|o| str_field(o, "storageName")).map(str::to_string)).collect())
            .unwrap_or_default()
    }
    fn strip_transport_dependencies(&self, entity: &JMap) -> Option<JMap> {
        let mut e = entity.clone();
        e.insert("relations".into(), JValue::Null);
        Some(e)
    }
}

/// A kind whose access check is replaced (`PersonalizationService`), that is not
/// versionable, and that refuses another user's row before the version check.
pub struct PrefKind;

impl DocType for PrefKind {
    fn object_name(&self) -> &'static str {
        "Personalization"
    }
    fn collection(&self) -> &'static str {
        "personalization"
    }
    fn pojo(&self) -> &'static Pojo {
        &PAGE
    }
    fn draftable(&self) -> bool {
        false
    }
    fn apply_override(&self, this: JMap, _base: &JMap) -> Option<JMap> {
        Some(this)
    }
}

#[async_trait]
impl Kind for PrefKind {
    fn versionable(&self) -> bool {
        false
    }
    fn snapshot_is_override(&self) -> bool {
        false
    }
    async fn access_override(&self, _ca: &ContextAuthentication, _method: Method) -> Option<bool> {
        Some(true)
    }
    async fn updatable_precheck(&self, cx: &Commons, ca: &ContextAuthentication, existing: &JMap, _incoming: &JMap) -> AppResult<()> {
        if str_field(existing, "createdBy") != Some(&ca.user.id.to_string()) {
            return Err(cx.error(axum::http::StatusCode::FORBIDDEN, "cannot_change_pref", &[]));
        }
        Ok(())
    }
    async fn before_delete(&self, cx: &Commons, ca: &ContextAuthentication, stored: &JMap) -> AppResult<()> {
        self.updatable_precheck(cx, ca, stored, stored).await
    }
}

pub struct Env {
    pub mem: Arc<MemBackend>,
    pub dir: Arc<FakeDirectory>,
    pub cache: CacheService,
    pub cx: Commons,
    pub pages: OverridableService<PageKind>,
    pub log: Arc<Mutex<Vec<String>>>,
    pub probe: Arc<LocalCaches<String, u32>>,
}

/// The harness with `stubPermissiveSecurity`: chain `[SYSTEM]`, read, write and manage all
/// allowed, an `ANY` app owned by SYSTEM.
pub fn env() -> Env {
    env_with(Messages::ui())
}

pub fn env_with(messages: Messages) -> Env {
    let mem = Arc::new(MemBackend::new());
    let dir = Arc::new(FakeDirectory::new());
    dir.chain(&[SYSTEM]);
    let cache = CacheService::new("cmn", "evictionChannel", None).unwrap();
    let store = Store::with_parts(mem.clone(), dir.clone(), &cache).unwrap();
    let cx = Commons::new(store, cache.clone(), messages, UI_AUTH_NAMES);
    let kind = PageKind::default();
    let log = kind.log.clone();
    let pages = OverridableService::new(kind, cx.clone());
    let probe = cache.family();
    Env { mem, dir, cache, cx, pages, log, probe }
}

impl Env {
    pub fn calls(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }

    /// Puts an entry under a cache name, to see whether a write evicts it.
    pub async fn warm(&self, cache_name: &str, key: &str) {
        self.probe.insert(cache_name, key.to_string(), 1).await;
    }

    pub async fn is_warm(&self, cache_name: &str, key: &str) -> bool {
        self.probe.get(cache_name, &key.to_string()).await.is_some()
    }

    pub fn storages(&self) -> OverridableService<StorageKind> {
        OverridableService::new(StorageKind, self.cx.clone())
    }

    /// `insertRaw`: the stored (delta) form, no Version row.
    pub fn insert_raw(&self, pojo: &Pojo, collection: &str, json: &str) -> String {
        let m = obj(json);
        let d: Document = to_document(pojo, &m, None, &[]);
        let id = self.mem.put_raw(collection, d);
        overridable::bson_conv::to_java_string(&id).java_to_string()
    }

    pub fn page(&self, json: &str) -> String {
        self.insert_raw(&PAGE, "page", json)
    }

    pub fn raw(&self, collection: &str) -> Vec<Document> {
        self.mem.all(collection)
    }

    pub fn raw_page(&self, id: &str) -> JMap {
        let d = self
            .raw("page")
            .into_iter()
            .find(|d| overridable::bson_conv::to_java_string(d.get("_id").unwrap()).java_to_string() == id)
            .expect("stored page");
        overridable::pojo::decode_bson(&PAGE, &d)
    }

    pub fn count(&self, collection: &str) -> usize {
        self.raw(collection).len()
    }
}

pub fn obj(s: &str) -> JMap {
    match parse(s.as_bytes()).unwrap() {
        JValue::Object(m) => m,
        other => panic!("not an object: {other:?}"),
    }
}

/// `authFor(clientCode, authorities...)`.
pub fn auth_for(client: &str, authorities: &[String]) -> ContextAuthentication {
    ContextAuthentication {
        user: ContextUser { id: 1, client_id: 1, user_name: Some(format!("test-{client}")), string_authorities: authorities.to_vec() },
        authenticated: true,
        logged_in_from_client_id: 1,
        logged_in_from_client_code: Some(client.to_string()),
        client_type_code: Some(if client == SYSTEM { "SYS" } else { "BUS" }.to_string()),
        client_code: Some(client.to_string()),
        client_level_type: None,
        access_token: Some("test-token".into()),
        url_client_code: Some(client.to_string()),
        url_app_code: Some(APP.to_string()),
    }
}

/// `allAuthoritiesFor(obj)`.
pub fn all_for(object: &str) -> Vec<String> {
    ["CREATE", "READ", "UPDATE", "DELETE"].iter().map(|m| format!("Authorities.{object}_{m}")).collect()
}

pub fn system() -> ContextAuthentication {
    auth_for(SYSTEM, &all_for("Page"))
}

pub fn anonymous() -> ContextAuthentication {
    ContextAuthentication { client_code: Some(SYSTEM.into()), ..Default::default() }
}

pub fn prop<'a>(e: &'a JMap, k: &str) -> Option<&'a JValue> {
    map_field(e, "properties").and_then(|p| p.get(k))
}

pub fn prop_str<'a>(e: &'a JMap, k: &str) -> Option<&'a str> {
    prop(e, k).and_then(JValue::as_str)
}

/// A raw page of `client` with a title and a root component.
pub fn page_json(name: &str, client: &str, title: &str, root: &str, extra: &str) -> String {
    format!(r#"{{"name":"{name}","appCode":"{APP}","clientCode":"{client}","version":1,"rootComponent":"{root}","properties":{{"title":"{title}"{extra}}}}}"#)
}
