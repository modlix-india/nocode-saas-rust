//! In-process fakes for tests: [`MemBackend`] holds collections in memory and runs the same
//! filter documents a database would; [`FakeDirectory`] answers the security calls from
//! tables, the way the Java integration tests stub `FeignAuthenticationService` and
//! `InheritanceService`.
//!
//! Public so the crates that mount these services can test against them too.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

use anyhow::{bail, Result};
use async_trait::async_trait;
use mongodb::bson::{doc, oid::ObjectId, Bson, Document};
use platform::security::OnBehalfOf;

use super::matcher::{bson_eq, matches, project, sort};
use super::{Backend, Directory, DuplicateKey, ExplicitApp, Find};

#[derive(Default)]
struct Collections {
    docs: HashMap<String, Vec<Document>>,
    unique: HashMap<String, Vec<Vec<String>>>,
    failing: HashSet<String>,
}

/// Collections in memory.
#[derive(Default)]
pub struct MemBackend {
    inner: Mutex<Collections>,
}

impl MemBackend {
    /// An empty store with the unique index the Java `Draft` document declares
    /// (`objectAppCode, objectType, objectName, clientCode`).
    pub fn new() -> Self {
        let m = Self::default();
        m.unique_index("draft", &["objectAppCode", "objectType", "objectName", "clientCode"]);
        m
    }

    fn lock(&self) -> MutexGuard<'_, Collections> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Declares a unique index: inserts and saves that would repeat its fields fail with
    /// [`DuplicateKey`].
    pub fn unique_index(&self, collection: &str, fields: &[&str]) {
        self.lock()
            .unique
            .entry(collection.to_string())
            .or_default()
            .push(fields.iter().map(|f| f.to_string()).collect());
    }

    /// Makes every operation on `collection` fail (or work again), for error paths.
    pub fn fail(&self, collection: &str, failing: bool) {
        let mut g = self.lock();
        if failing {
            g.failing.insert(collection.to_string());
        } else {
            g.failing.remove(collection);
        }
    }

    /// Every document of a collection, as stored (the tests' `findAllRaw`).
    pub fn all(&self, collection: &str) -> Vec<Document> {
        self.lock().docs.get(collection).cloned().unwrap_or_default()
    }

    /// Stores a document as given, no checks (the tests' `insertRaw`). Answers its `_id`.
    pub fn put_raw(&self, collection: &str, mut doc: Document) -> Bson {
        let id = match doc.get("_id") {
            Some(id) => id.clone(),
            None => {
                let id = Bson::ObjectId(ObjectId::new());
                let mut with_id = doc! {"_id": id.clone()};
                with_id.extend(doc);
                doc = with_id;
                id
            }
        };
        let mut g = self.lock();
        let list = g.docs.entry(collection.to_string()).or_default();
        list.retain(|d| d.get("_id").is_none_or(|x| !bson_eq(x, &id)));
        list.push(doc);
        id
    }

    fn check(g: &Collections, collection: &str) -> Result<()> {
        if g.failing.contains(collection) {
            bail!("{collection} is failing on purpose");
        }
        Ok(())
    }

    fn violates_unique(g: &Collections, collection: &str, doc: &Document) -> bool {
        let Some(indexes) = g.unique.get(collection) else { return false };
        let Some(list) = g.docs.get(collection) else { return false };
        let id = doc.get("_id");
        indexes.iter().any(|fields| {
            list.iter().any(|other| {
                other.get("_id").zip(id).is_none_or(|(a, b)| !bson_eq(a, b))
                    && fields.iter().all(|f| {
                        let a = other.get(f).unwrap_or(&Bson::Null);
                        let b = doc.get(f).unwrap_or(&Bson::Null);
                        bson_eq(a, b)
                    })
            })
        })
    }

    fn matching(g: &Collections, collection: &str, filter: &Document) -> Result<Vec<Document>> {
        let mut out = Vec::new();
        for d in g.docs.get(collection).map(Vec::as_slice).unwrap_or_default() {
            if matches(d, filter)? {
                out.push(d.clone());
            }
        }
        Ok(out)
    }
}

#[async_trait]
impl Backend for MemBackend {
    async fn find(&self, collection: &str, query: Find) -> Result<Vec<Document>> {
        let g = self.lock();
        Self::check(&g, collection)?;
        let mut found = Self::matching(&g, collection, &query.filter)?;
        if let Some(s) = &query.sort {
            sort(&mut found, s);
        }
        let skipped = found.into_iter().skip(query.skip as usize);
        let limited: Vec<Document> = match query.limit {
            Some(n) if n > 0 => skipped.take(n as usize).collect(),
            _ => skipped.collect(),
        };
        Ok(match &query.projection {
            Some(p) => limited.iter().map(|d| project(d, p)).collect(),
            None => limited,
        })
    }

    async fn count(&self, collection: &str, filter: Document) -> Result<u64> {
        let g = self.lock();
        Self::check(&g, collection)?;
        Ok(Self::matching(&g, collection, &filter)?.len() as u64)
    }

    async fn insert(&self, collection: &str, mut doc: Document) -> Result<Bson> {
        let mut g = self.lock();
        Self::check(&g, collection)?;
        if !doc.contains_key("_id") {
            let mut with_id = doc! {"_id": ObjectId::new()};
            with_id.extend(doc);
            doc = with_id;
        }
        let id = doc.get("_id").cloned().unwrap_or(Bson::Null);
        let exists = g
            .docs
            .get(collection)
            .is_some_and(|l| l.iter().any(|d| d.get("_id").is_some_and(|x| bson_eq(x, &id))));
        if exists || Self::violates_unique(&g, collection, &doc) {
            return Err(DuplicateKey { collection: collection.to_string() }.into());
        }
        g.docs.entry(collection.to_string()).or_default().push(doc);
        Ok(id)
    }

    async fn replace(&self, collection: &str, id: Bson, mut doc: Document) -> Result<()> {
        let mut g = self.lock();
        Self::check(&g, collection)?;
        if !doc.contains_key("_id") {
            let mut with_id = doc! {"_id": id.clone()};
            with_id.extend(doc);
            doc = with_id;
        }
        if Self::violates_unique(&g, collection, &doc) {
            return Err(DuplicateKey { collection: collection.to_string() }.into());
        }
        let list = g.docs.entry(collection.to_string()).or_default();
        match list.iter_mut().find(|d| d.get("_id").is_some_and(|x| bson_eq(x, &id))) {
            Some(slot) => *slot = doc,
            None => list.push(doc),
        }
        Ok(())
    }

    async fn delete_one(&self, collection: &str, filter: Document) -> Result<u64> {
        let mut g = self.lock();
        Self::check(&g, collection)?;
        let Some(list) = g.docs.get(collection) else { return Ok(0) };
        let mut at = None;
        for (i, d) in list.iter().enumerate() {
            if matches(d, &filter)? {
                at = Some(i);
                break;
            }
        }
        Ok(match at {
            Some(i) => {
                g.docs.entry(collection.to_string()).or_default().remove(i);
                1
            }
            None => 0,
        })
    }

    async fn delete_many(&self, collection: &str, filter: Document) -> Result<u64> {
        let mut g = self.lock();
        Self::check(&g, collection)?;
        let Some(list) = g.docs.get(collection) else { return Ok(0) };
        let mut keep = Vec::with_capacity(list.len());
        let mut removed = 0;
        for d in list {
            if matches(d, &filter)? {
                removed += 1;
            } else {
                keep.push(d.clone());
            }
        }
        g.docs.insert(collection.to_string(), keep);
        Ok(removed)
    }

    async fn update_many(&self, collection: &str, filter: Document, set: Document) -> Result<u64> {
        let mut g = self.lock();
        Self::check(&g, collection)?;
        let Some(list) = g.docs.get(collection) else { return Ok(0) };
        let mut updated = list.clone();
        let mut n = 0;
        for d in updated.iter_mut() {
            if matches(d, &filter)? {
                for (k, v) in &set {
                    d.insert(k.clone(), v.clone());
                }
                n += 1;
            }
        }
        g.docs.insert(collection.to_string(), updated);
        Ok(n)
    }
}

/// The answers [`FakeDirectory`] gives. Defaults are the Java tests' `stubPermissiveSecurity`:
/// read and write access everywhere, every client managed, an app of type `ANY` owned by
/// `SYSTEM`, and each client's chain being just itself.
#[derive(Debug, Clone)]
pub struct FakeAnswers {
    /// The inheritance order for every call, whatever the arguments (the tests' `setInheritance`).
    pub chain: Option<Vec<String>>,
    /// Per requesting client, taking precedence over `chain`.
    pub chains: HashMap<String, Vec<String>>,
    pub read_access: bool,
    pub write_access: bool,
    /// `(appCode, clientCode)` exceptions to `read_access` / `write_access`.
    pub read_by: HashMap<(String, String), bool>,
    pub write_by: HashMap<(String, String), bool>,
    pub manages_all: bool,
    /// `(managing, client)` pairs managed even when `manages_all` is off.
    pub managed: HashSet<(String, String)>,
    /// Managing clients that manage everyone even when `manages_all` is off.
    pub managers: HashSet<String>,
    pub app: Option<ExplicitApp>,
    pub apps: HashMap<String, Option<ExplicitApp>>,
    pub delete_access: bool,
    pub base_client: Option<(String, bool)>,
    /// `getClientHierarchyCodes` per client; an unknown client answers empty.
    pub hierarchies: HashMap<String, Vec<String>>,
    /// Makes every call fail, for error paths.
    pub failing: bool,
}

impl Default for FakeAnswers {
    fn default() -> Self {
        Self {
            chain: None,
            chains: HashMap::new(),
            read_access: true,
            write_access: true,
            read_by: HashMap::new(),
            write_by: HashMap::new(),
            manages_all: true,
            managed: HashSet::new(),
            managers: HashSet::new(),
            app: Some(ExplicitApp { app_access_type: Some("ANY".into()), client_code: Some("SYSTEM".into()), explicit_owner_client_code: None }),
            apps: HashMap::new(),
            delete_access: true,
            base_client: None,
            hierarchies: HashMap::new(),
            failing: false,
        }
    }
}

/// Security answered from [`FakeAnswers`], counting the inheritance calls.
#[derive(Default)]
pub struct FakeDirectory {
    answers: Mutex<FakeAnswers>,
    pub inheritance_calls: AtomicUsize,
}

impl FakeDirectory {
    pub fn new() -> Self {
        Self::default()
    }

    /// Changes the answers.
    pub fn set(&self, f: impl FnOnce(&mut FakeAnswers)) {
        f(&mut self.answers.lock().unwrap_or_else(|p| p.into_inner()));
    }

    fn get(&self) -> Result<FakeAnswers> {
        let a = self.answers.lock().unwrap_or_else(|p| p.into_inner()).clone();
        if a.failing {
            bail!("security is failing on purpose");
        }
        Ok(a)
    }

    /// The inheritance order for every caller (`setInheritance`).
    pub fn chain(&self, chain: &[&str]) {
        self.set(|a| a.chain = Some(chain.iter().map(|s| s.to_string()).collect()));
    }

    /// `stubHierarchy(client, codes...)`: the client's `getClientHierarchyCodes`.
    pub fn hierarchy(&self, client: &str, codes: &[&str]) {
        self.set(|a| {
            a.hierarchies.insert(client.to_string(), codes.iter().map(|s| s.to_string()).collect());
        });
    }

    /// `isolateTenants()`: nobody manages anybody.
    pub fn isolate_tenants(&self) {
        self.set(|a| a.manages_all = false);
    }
}

#[async_trait]
impl Directory for FakeDirectory {
    async fn app_inheritance(&self, _app_code: &str, _url_client_code: &str, client_code: &str) -> Result<Vec<String>> {
        self.inheritance_calls.fetch_add(1, Ordering::SeqCst);
        let a = self.get()?;
        Ok(a.chains
            .get(client_code)
            .cloned()
            .or(a.chain)
            .unwrap_or_else(|| vec![client_code.to_string()]))
    }

    async fn has_read_access(&self, app_code: &str, client_code: &str) -> Result<bool> {
        let a = self.get()?;
        Ok(*a.read_by.get(&(app_code.to_string(), client_code.to_string())).unwrap_or(&a.read_access))
    }

    async fn has_write_access(&self, app_code: &str, client_code: &str) -> Result<bool> {
        let a = self.get()?;
        Ok(*a.write_by.get(&(app_code.to_string(), client_code.to_string())).unwrap_or(&a.write_access))
    }

    async fn does_client_manage_client_code(&self, managing: &str, client: &str) -> Result<bool> {
        let a = self.get()?;
        Ok(a.manages_all || a.managers.contains(managing) || a.managed.contains(&(managing.to_string(), client.to_string())))
    }

    async fn app_explicit_info(&self, app_code: &str) -> Result<Option<ExplicitApp>> {
        let a = self.get()?;
        Ok(a.apps.get(app_code).cloned().unwrap_or(a.app))
    }

    async fn has_delete_access(&self, _caller: &OnBehalfOf, _app: &str, _client: &str) -> Result<bool> {
        Ok(self.get()?.delete_access)
    }

    async fn find_base_client_code_for_override(&self, _caller: &OnBehalfOf, _app: &str) -> Result<Option<(String, bool)>> {
        Ok(self.get()?.base_client)
    }

    async fn client_hierarchy_codes(&self, client_code: &str) -> Result<Vec<String>> {
        Ok(self.get()?.hierarchies.get(client_code).cloned().unwrap_or_default())
    }
}
