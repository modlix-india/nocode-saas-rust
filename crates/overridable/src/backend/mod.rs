//! Where the overridable documents live and who decides access to them, as two small traits,
//! so the same read and write paths run against MongoDB and security in production and against
//! in-process fakes in tests.
//!
//! - [`Backend`]: the handful of collection operations Spring Data's repositories and
//!   `ReactiveMongoTemplate` perform for these services (find, count, insert, save, delete,
//!   update many). [`mongo::MongoBackend`] runs them on a database; [`memory::MemBackend`]
//!   keeps the collections in memory and evaluates the same filter documents.
//! - [`Directory`]: the security calls the Java services make through
//!   `FeignAuthenticationService` / `IFeignSecurityService`. [`directory::RemoteDirectory`] calls
//!   security (with the Java cache names); [`memory::FakeDirectory`] answers from tables.

pub mod directory;
pub mod matcher;
pub mod memory;
pub mod mongo;

use anyhow::Result;
use async_trait::async_trait;
use mongodb::bson::{Bson, Document};
use platform::security::OnBehalfOf;

pub use directory::{ExplicitApp, RemoteDirectory};
pub use memory::{FakeDirectory, MemBackend};
pub use mongo::MongoBackend;

/// A query: filter, and optionally sort, projection, skip and limit.
#[derive(Debug, Clone, Default)]
pub struct Find {
    pub filter: Document,
    pub sort: Option<Document>,
    pub projection: Option<Document>,
    pub skip: u64,
    pub limit: Option<i64>,
}

impl Find {
    pub fn new(filter: Document) -> Self {
        Self { filter, ..Default::default() }
    }

    pub fn sort(mut self, sort: Document) -> Self {
        self.sort = (!sort.is_empty()).then_some(sort);
        self
    }

    pub fn projection(mut self, projection: Document) -> Self {
        self.projection = Some(projection);
        self
    }

    pub fn skip(mut self, skip: u64) -> Self {
        self.skip = skip;
        self
    }

    pub fn limit(mut self, limit: i64) -> Self {
        self.limit = Some(limit);
        self
    }
}

/// A write refused by a unique index (Mongo error 11000), Spring's `DuplicateKeyException`.
#[derive(Debug, thiserror::Error)]
#[error("duplicate key in {collection}")]
pub struct DuplicateKey {
    pub collection: String,
}

/// Whether an error is (or wraps) a unique-index refusal.
pub fn is_duplicate_key(e: &anyhow::Error) -> bool {
    e.chain().any(|c| c.is::<DuplicateKey>())
}

/// The collection operations the services perform.
#[async_trait]
pub trait Backend: Send + Sync + 'static {
    async fn find(&self, collection: &str, query: Find) -> Result<Vec<Document>>;

    async fn find_one(&self, collection: &str, filter: Document, sort: Option<Document>) -> Result<Option<Document>> {
        let mut q = Find::new(filter).limit(1);
        q.sort = sort;
        Ok(self.find(collection, q).await?.into_iter().next())
    }

    async fn count(&self, collection: &str, filter: Document) -> Result<u64>;

    /// Inserts `doc`, giving it an ObjectId `_id` when it has none, and answers the `_id`.
    async fn insert(&self, collection: &str, doc: Document) -> Result<Bson>;

    /// Spring Data `save` of a document that has an id: replaces it, or inserts it when no
    /// document has that id.
    async fn replace(&self, collection: &str, id: Bson, doc: Document) -> Result<()>;

    async fn delete_one(&self, collection: &str, filter: Document) -> Result<u64>;

    async fn delete_many(&self, collection: &str, filter: Document) -> Result<u64>;

    /// `updateMulti(query, Update.update(field, value))`: `$set` on every match.
    async fn update_many(&self, collection: &str, filter: Document, set: Document) -> Result<u64>;
}

/// The security calls the services make.
#[async_trait]
pub trait Directory: Send + Sync + 'static {
    /// `appInheritance`: the client codes an app resolves through, root first. Uncached here;
    /// the store caches it as `inheritanceOrder`.
    async fn app_inheritance(&self, app_code: &str, url_client_code: &str, client_code: &str) -> Result<Vec<String>>;
    async fn has_read_access(&self, app_code: &str, client_code: &str) -> Result<bool>;
    async fn has_write_access(&self, app_code: &str, client_code: &str) -> Result<bool>;
    async fn does_client_manage_client_code(&self, managing_client_code: &str, client_code: &str) -> Result<bool>;
    /// `getAppExplicitInfoByCode`: `None` for an unknown app (Feign's empty Mono).
    async fn app_explicit_info(&self, app_code: &str) -> Result<Option<ExplicitApp>>;
    async fn has_delete_access(&self, caller: &OnBehalfOf, delete_app_code: &str, delete_client_code: &str) -> Result<bool>;
    async fn find_base_client_code_for_override(&self, caller: &OnBehalfOf, application_code: &str) -> Result<Option<(String, bool)>>;
    /// `getClientHierarchyCodes`: the client, then its managing clients nearest first; empty
    /// for an unknown code.
    async fn client_hierarchy_codes(&self, client_code: &str) -> Result<Vec<String>>;
}
