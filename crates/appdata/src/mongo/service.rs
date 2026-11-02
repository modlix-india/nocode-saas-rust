//! `MongoAppDataService`: app data in `<CLIENT>_<app>` (and `<CLIENT>_<app>_draft`), one
//! collection per storage named by its uniqueName, history in `<uniqueName>_version`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, Bson, DateTime, Document as BsonDocument};
use mongodb::options::IndexOptions;
use mongodb::{Client, Collection, IndexModel};
use platform::cache::{CacheService, LocalCaches};
use tokio::sync::Mutex;

use super::aggregate;
use super::bson_util::{self, document_to_value, parse_object_id};
use super::codec;
use super::filter::filter;
use crate::aggregate_validator;
use crate::difference;
use crate::engine::{AppDataEngine, Ctx, Hooks, CACHE_SUFFIX_FOR_INDEX_CREATION, DRAFT_DB_SUFFIX};
use crate::error::{AppDataError, AppDataResult};
use crate::model::{
    AggregateQuery, ComplexCondition, Condition, Connection, DataObject, Direction, DraftCopyFilter, FilterCondition,
    FilterOperator, Page, Pageable, Query, Storage, StorageIndex,
};
use crate::retention::VersionRetention;
use crate::schema_refs::storage_schema;
use crate::value::{Document, Value};

const BACKEND: &str = "Mongo";
const ID: &str = "_id";
const OBJECT: &str = "object";
const OBJECT_ID: &str = "objectId";
const CREATED_AT: &str = "createdAt";
const CREATED_BY: &str = "createdBy";
const MESSAGE: &str = "message";
const OPERATION: &str = "operation";
const TEXT_INDEX_NAME: &str = "_textIndex";
const DUPLICATE_ID_INDEX: &str = "index: _id_";
/// The per-database collection that holds named counters (`Storage.NextSequence`).
const SEQUENCE_COLLECTION: &str = "_mlx_sequence";
const AGGREGATE_MAX_SECONDS: u64 = 30;
const VERSION_PURGE_BATCH: usize = 1000;
const COPY_BATCH_SIZE: usize = 500;

#[derive(Debug, Clone, Default)]
pub struct MongoEngineConfig {
    /// The core service's own Mongo, used when an app has no appData connection.
    pub default_uri: Option<String>,
    /// The installation-wide history retention (`core.appdata.versionRetention`).
    pub retention: VersionRetention,
    /// Leave every collection's indexes as they are. Off in service; on for read-only
    /// tooling (the parity run) that must not change a real tenant.
    pub skip_index_management: bool,
}

pub struct MongoAppDataService {
    config: MongoEngineConfig,
    hooks: Hooks,
    default_client: Mutex<Option<Client>>,
    clients: Mutex<HashMap<String, Client>>,
    index_cache: Arc<LocalCaches<String, bool>>,
}

/// The draft surface is its own database, not its own collection names.
pub fn database_name(client_code: &str, app_code: &str, draft: bool) -> String {
    format!("{client_code}_{app_code}{}", if draft { DRAFT_DB_SUFFIX } else { "" })
}

fn version_name(unique_name: &str) -> String {
    format!("{unique_name}_version")
}

fn is_duplicate_key(e: &mongodb::error::Error) -> Option<String> {
    use mongodb::error::{ErrorKind, WriteFailure};
    match e.kind.as_ref() {
        ErrorKind::Write(WriteFailure::WriteError(w)) if matches!(w.code, 11000 | 11001 | 12582) => Some(w.message.clone()),
        _ => None,
    }
}

fn is_namespace_not_found(e: &mongodb::error::Error) -> bool {
    use mongodb::error::ErrorKind;
    matches!(e.kind.as_ref(), ErrorKind::Command(c) if c.code == 26)
}

impl MongoAppDataService {
    pub fn new(config: MongoEngineConfig, hooks: Hooks, cache: &CacheService) -> MongoAppDataService {
        MongoAppDataService {
            config,
            hooks,
            default_client: Mutex::new(None),
            clients: Mutex::new(HashMap::new()),
            index_cache: cache.family::<String, bool>(),
        }
    }

    /// Drop a cached client, as the Java service does on a connection-channel message.
    pub async fn evict_connection(&self, connection_id: &str) {
        self.clients.lock().await.remove(&format!("Connection : {connection_id}"));
    }

    async fn client(&self, conn: Option<&Connection>) -> AppDataResult<Client> {
        let Some(conn) = conn else {
            let mut guard = self.default_client.lock().await;
            if let Some(c) = guard.as_ref() {
                return Ok(c.clone());
            }
            let uri = self
                .config
                .default_uri
                .clone()
                .filter(|u| !u.trim().is_empty())
                .ok_or_else(|| AppDataError::connection_details_missing("url"))?;
            let c = Client::with_uri_str(&uri).await?;
            *guard = Some(c.clone());
            return Ok(c);
        };
        let key = format!("Connection : {}", conn.id);
        let mut clients = self.clients.lock().await;
        if let Some(c) = clients.get(&key) {
            return Ok(c.clone());
        }
        let url = conn
            .detail("url")
            .map(Value::java_string)
            .filter(|u| !u.trim().is_empty() && u != "null")
            .ok_or_else(|| AppDataError::connection_details_missing("url"))?;
        let c = Client::with_uri_str(&url).await?;
        clients.insert(key, c.clone());
        Ok(c)
    }

    /// The storage's collection on the caller's surface, with its indexes brought into line
    /// once per (storage, app, client, surface).
    async fn collection(&self, cx: &Ctx, client_code: &str, conn: Option<&Connection>, storage: &Storage)
        -> AppDataResult<Collection<BsonDocument>> {
        let tenant = cx.tenant(client_code, storage);
        let client = self.client(conn).await?;
        let coll = client
            .database(&database_name(&tenant, &storage.app_code, cx.draft))
            .collection::<BsonDocument>(&storage.unique_name);

        let cache_name = format!("{}{CACHE_SUFFIX_FOR_INDEX_CREATION}", storage.unique_name);
        let key = format!("{}{}{}", storage.app_code, tenant, if cx.draft { DRAFT_DB_SUFFIX } else { "" });
        if self.config.skip_index_management {
            return Ok(coll);
        }
        self.index_cache
            .get_or_load(&cache_name, key, || async {
                manage_indexes(&coll, storage.indexes.as_ref(), storage.text_index_fields.as_ref()).await?;
                Ok::<_, AppDataError>(Some(true))
            })
            .await?;
        Ok(coll)
    }

    async fn version_collection(&self, cx: &Ctx, client_code: &str, conn: Option<&Connection>, storage: &Storage)
        -> AppDataResult<Collection<BsonDocument>> {
        let tenant = cx.tenant(client_code, storage);
        let client = self.client(conn).await?;
        Ok(client
            .database(&database_name(&tenant, &storage.app_code, cx.draft))
            .collection::<BsonDocument>(&version_name(&storage.unique_name)))
    }

    /// One history row. Nothing for a storage that keeps no history.
    async fn add_version(
        &self,
        cx: &Ctx,
        client_code: &str,
        conn: Option<&Connection>,
        storage: &Storage,
        message: Option<&str>,
        object_id: &str,
        document: &mut BsonDocument,
        operation: &str,
    ) -> AppDataResult<()> {
        if !storage.keeps_history() {
            return Ok(());
        }
        let mut version = BsonDocument::new();
        version.insert(OBJECT_ID, object_id);
        version.insert(MESSAGE, message.map(Bson::from).unwrap_or(Bson::Null));
        version.insert(CREATED_AT, DateTime::now());
        version.insert(OPERATION, operation);
        if let Some(user) = cx.user_id {
            version.insert(CREATED_BY, Bson::Int64(user as i64));
        }
        document.remove(ID);
        if storage.versioned() {
            version.insert(OBJECT, document.clone());
        }
        let versions = self.version_collection(cx, client_code, conn, storage).await?;
        versions.insert_one(version).await?;
        // Housekeeping: a failed trim never fails the write it follows.
        let _ = trim_versions(&versions, VersionRetention::for_storage(storage, self.config.retention), object_id).await;
        Ok(())
    }

    async fn record_delete(
        &self,
        cx: &Ctx,
        client_code: &str,
        conn: Option<&Connection>,
        storage: &Storage,
        doc: Option<BsonDocument>,
        id: &str,
        delete_version: Option<bool>,
    ) -> AppDataResult<()> {
        let (Some(delete_version), Some(mut doc)) = (delete_version, doc) else { return Ok(()) };
        if !storage.keeps_history() {
            return Ok(());
        }
        if delete_version {
            let versions = self.version_collection(cx, client_code, conn, storage).await?;
            versions.delete_many(doc! { OBJECT_ID: id }).await?;
            return Ok(());
        }
        self.add_version(cx, client_code, conn, storage, None, id, &mut doc, "DELETE").await
    }

    async fn record_bulk_delete(
        &self,
        cx: &Ctx,
        client_code: &str,
        conn: Option<&Connection>,
        storage: &Storage,
        coll: &Collection<BsonDocument>,
        filter: &BsonDocument,
        delete_version: Option<bool>,
    ) -> AppDataResult<()> {
        let Some(delete_version) = delete_version else { return Ok(()) };
        if !storage.keeps_history() {
            return Ok(());
        }
        if delete_version {
            let versions = self.version_collection(cx, client_code, conn, storage).await?;
            let mut cursor = coll.find(filter.clone()).projection(doc! { ID: 1 }).await?;
            let mut batch = Vec::new();
            while let Some(d) = cursor.try_next().await? {
                batch.push(Bson::String(object_id_of(&d)?.to_hex()));
                if batch.len() == VERSION_PURGE_BATCH {
                    versions.delete_many(doc! { OBJECT_ID: { "$in": std::mem::take(&mut batch) } }).await?;
                }
            }
            if !batch.is_empty() {
                versions.delete_many(doc! { OBJECT_ID: { "$in": batch } }).await?;
            }
            return Ok(());
        }
        let mut cursor = coll.find(filter.clone()).await?;
        while let Some(mut d) = cursor.try_next().await? {
            let oid = object_id_of(&d)?.to_hex();
            self.add_version(cx, client_code, conn, storage, None, &oid, &mut d, "DELETE").await?;
        }
        Ok(())
    }

    /// `applyQueryOnElements`: a find, or an aggregation when fields are projected.
    async fn query_elements(
        &self,
        coll: &Collection<BsonDocument>,
        query: &Query,
        filter: BsonDocument,
        page: &Pageable,
    ) -> AppDataResult<Vec<BsonDocument>> {
        let sort = aggregate::sort_doc(&page.sort);
        match query.fields.as_ref().filter(|f| !f.is_empty()) {
            None => {
                let mut find = coll.find(filter).skip(page.offset() as i32 as u64).limit(page.page_size());
                if let Some(s) = sort {
                    find = find.sort(s);
                }
                Ok(find.await?.try_collect().await?)
            }
            Some(fields) => {
                let mut pipeline = vec![doc! { "$match": filter }];
                if let Some(s) = sort {
                    pipeline.push(doc! { "$sort": s });
                }
                let flag = if query.excludes() { 0 } else { 1 };
                let mut projection = BsonDocument::new();
                for f in fields {
                    projection.insert(f.clone(), flag);
                }
                pipeline.push(doc! { "$project": projection });
                pipeline.push(doc! { "$skip": page.offset() as i32 });
                pipeline.push(doc! { "$limit": page.size });
                Ok(coll.aggregate(pipeline).await?.try_collect().await?)
            }
        }
    }

    /// Mongo's backend knows no second collection, so joins and subqueries are refused
    /// rather than answered without the filter they carry.
    fn refuse_if_unsupported(query: &Query) -> AppDataResult<()> {
        if query.has_joins() {
            return Err(AppDataError::unsupported_on_backend("joins", BACKEND));
        }
        if query.has_sub_queries() {
            return Err(AppDataError::unsupported_on_backend("subqueries", BACKEND));
        }
        Ok(())
    }

    /// `estimatedRowCount`: rows across both surfaces of an app for one client, for
    /// metering. A missing database counts as zero.
    pub async fn estimated_row_count(&self, conn: Option<&Connection>, app_code: &str, client_code: &str) -> i64 {
        if app_code.trim().is_empty() || client_code.trim().is_empty() {
            return 0;
        }
        let Ok(client) = self.client(conn).await else { return 0 };
        let mut total = 0;
        for draft in [false, true] {
            let db = client.database(&database_name(client_code, app_code, draft));
            let Ok(names) = db.list_collection_names().await else { continue };
            for name in names {
                if name.ends_with("_version") || name.starts_with("system.") {
                    continue;
                }
                total += db.collection::<BsonDocument>(&name).estimated_document_count().await.unwrap_or(0) as i64;
            }
        }
        total
    }

    async fn draft_copy_filter(
        &self,
        cx: &Ctx,
        client_code: &str,
        conn: Option<&Connection>,
        storage: &Storage,
        filter_spec: Option<&DraftCopyFilter>,
        followed: &HashMap<String, Storage>,
    ) -> AppDataResult<BsonDocument> {
        let Some(f) = filter_spec else { return Ok(BsonDocument::new()) };
        let base = filter(storage, f.condition.as_ref())?;
        if !f.has_follow() {
            return Ok(base);
        }
        let draft = cx.on_draft(true);
        let mut each = Vec::new();
        let mut filled = Vec::new();
        for follow in f.follow.iter().flatten() {
            let target = followed
                .get(&follow.storage)
                .ok_or_else(|| AppDataError::internal(format!("NullPointerException: storage {}", follow.storage)))?;
            let reference = self.collection(&draft, client_code, conn, target).await?;
            let values = reference.distinct(follow.ref_field_or_default(), BsonDocument::new()).await?;
            each.push(Bson::Document(doc! { "$or": [ { &follow.field: Bson::Null }, { &follow.field: { "$in": values } } ] }));
            filled.push(Bson::Document(doc! { &follow.field: { "$ne": Bson::Null } }));
        }
        Ok(doc! { "$and": [ base, { "$and": each }, { "$or": filled } ] })
    }

    async fn copy_into(
        &self,
        live: &Collection<BsonDocument>,
        draft: &Collection<BsonDocument>,
        filter: BsonDocument,
    ) -> AppDataResult<i64> {
        let mut cursor = live.find(filter).batch_size(COPY_BATCH_SIZE as u32).await?;
        let mut copied = 0i64;
        while let Some(d) = cursor.try_next().await? {
            let id = d.get(ID).cloned().unwrap_or(Bson::Null);
            draft.replace_one(doc! { ID: id }, d).upsert(true).await?;
            copied += 1;
        }
        Ok(copied)
    }
}

fn object_id_of(d: &BsonDocument) -> AppDataResult<ObjectId> {
    match d.get(ID) {
        Some(Bson::ObjectId(o)) => Ok(*o),
        _ => Err(AppDataError::internal("ClassCastException: _id is not an ObjectId")),
    }
}

/// Keep one row's history inside its retention: older than the cutoff goes, and so does
/// everything older than the Nth newest.
async fn trim_versions(versions: &Collection<BsonDocument>, retention: VersionRetention, object_id: &str) -> AppDataResult<()> {
    if retention.keeps_everything() {
        return Ok(());
    }
    if retention.trims_by_age() {
        let cutoff = DateTime::from_millis(retention.cutoff_epoch_millis());
        versions
            .delete_many(doc! { "$and": [ { OBJECT_ID: object_id }, { CREATED_AT: { "$lt": cutoff } } ] })
            .await?;
    }
    if retention.trims_by_count() {
        let oldest_kept = versions
            .find(doc! { OBJECT_ID: object_id })
            .sort(doc! { CREATED_AT: -1 })
            .skip((retention.count - 1) as u64)
            .limit(1)
            .await?
            .try_next()
            .await?;
        if let Some(kept) = oldest_kept {
            let at = kept.get(CREATED_AT).cloned().unwrap_or(Bson::Null);
            versions
                .delete_many(doc! { "$and": [ { OBJECT_ID: object_id }, { CREATED_AT: { "$lt": at } } ] })
                .await?;
        }
    }
    Ok(())
}

/// `manageIndexes`: drop what the definition no longer names, create what it does.
async fn manage_indexes(
    coll: &Collection<BsonDocument>,
    indexes: Option<&indexmap::IndexMap<String, StorageIndex>>,
    text_fields: Option<&Vec<String>>,
) -> AppDataResult<()> {
    let no_text = text_fields.is_none_or(|t| t.is_empty());
    let no_indexes = indexes.is_none_or(|i| i.is_empty());

    let existing: Vec<IndexModel> = match coll.list_indexes().await {
        Ok(cursor) => cursor.try_collect().await?,
        Err(e) if is_namespace_not_found(&e) => Vec::new(),
        Err(e) => return Err(e.into()),
    };
    for index in existing {
        let Some(name) = index.options.as_ref().and_then(|o| o.name.clone()) else { continue };
        let drop = if name == "_id_" {
            false
        } else if name == TEXT_INDEX_NAME {
            no_text
        } else {
            no_indexes || !indexes.is_some_and(|i| i.contains_key(&name))
        };
        if drop {
            coll.drop_index(&name).await?;
        }
    }

    if let Some(indexes) = indexes {
        for (name, index) in indexes {
            if index.fields.is_empty() {
                continue;
            }
            let mut keys = BsonDocument::new();
            for f in &index.fields {
                let dir = if f.direction == Some(Direction::Desc) { -1 } else { 1 };
                keys.insert(f.field_name.clone().unwrap_or_default(), dir);
            }
            let options = IndexOptions::builder().name(name.clone()).unique(index.unique).build();
            coll.create_index(IndexModel::builder().keys(keys).options(options).build()).await?;
        }
    }

    if let Some(fields) = text_fields.filter(|t| !t.is_empty()) {
        let mut keys = BsonDocument::new();
        for f in fields {
            keys.insert(f.clone(), "text");
        }
        let options = IndexOptions::builder().name(TEXT_INDEX_NAME.to_string()).build();
        coll.create_index(IndexModel::builder().keys(keys).options(options).build()).await?;
    }
    Ok(())
}

/// `convertBisonIds`: `_id` (and on a version row `objectId`) as hex at the end, the codec's
/// readable forms, relation ids as hex.
fn convert_ids(storage: &Storage, mut doc: BsonDocument, is_version: bool) -> Document {
    move_hex_to_end(&mut doc, ID);
    if !is_version {
        codec::decode(&mut doc);
    } else {
        move_hex_to_end(&mut doc, OBJECT_ID);
        if let Some(Bson::DateTime(dt)) = doc.get(CREATED_AT).cloned() {
            doc.remove(CREATED_AT);
            doc.insert(CREATED_AT, Bson::Int64(dt.timestamp_millis().div_euclid(1000)));
        }
    }
    relation_ids_to_hex(storage, &mut doc);
    document_to_value(&doc)
}

fn move_hex_to_end(doc: &mut BsonDocument, key: &str) {
    if let Some(Bson::ObjectId(oid)) = doc.get(key).cloned() {
        doc.remove(key);
        doc.insert(key, oid.to_hex());
    }
}

/// `updateDocWithIds`. A storage that declares no relations has nothing to convert (the
/// Java read path hands the engine an empty map there, never a null).
fn relation_ids_to_hex(storage: &Storage, doc: &mut BsonDocument) {
    let Some(relations) = &storage.relations else { return };
    for key in relations.keys() {
        let Some(v) = doc.get(key).cloned() else { continue };
        match v {
            Bson::ObjectId(o) => {
                doc.insert(key.clone(), o.to_hex());
            }
            Bson::Array(list) => {
                let out: Vec<Bson> = list
                    .into_iter()
                    .filter(|o| !matches!(o, Bson::Null))
                    .map(|o| match o {
                        Bson::ObjectId(x) => Bson::String(x.to_hex()),
                        Bson::String(s) => Bson::String(s),
                        other => Bson::String(java_bson_to_string(&other)),
                    })
                    .collect();
                doc.insert(key.clone(), Bson::Array(out));
            }
            _ => {}
        }
    }
}

/// `Object.toString()` of what the driver decodes a BSON value into.
fn java_bson_to_string(b: &Bson) -> String {
    match b {
        Bson::Int32(i) => i.to_string(),
        Bson::Int64(i) => i.to_string(),
        Bson::Double(d) => crate::value::java_double(*d),
        Bson::Boolean(x) => x.to_string(),
        other => bson_util::to_value(other).java_string(),
    }
}

/// `takeGivenId`: a hex `_id` in the data is kept for the insert, anything else dropped.
fn take_given_id(data: &mut Document) -> Option<ObjectId> {
    let id = data.shift_remove(ID)?;
    match id {
        Value::String(s) if !s.trim().is_empty() => parse_object_id(&s),
        Value::Null => None,
        other => parse_object_id(&other.java_string()),
    }
}

fn relation_keys(storage: &Storage) -> Vec<String> {
    storage.relation_keys()
}

#[async_trait]
impl AppDataEngine for MongoAppDataService {
    fn backend(&self) -> &'static str {
        BACKEND
    }

    async fn create(&self, cx: &Ctx, client_code: &str, conn: Option<&Connection>, storage: &Storage, data: DataObject)
        -> AppDataResult<Document> {
        let mut row = data.data.clone().unwrap_or_default();
        let given_id = take_given_id(&mut row);

        let coll = self.collection(cx, client_code, conn, storage).await?;
        let schema = storage_schema(storage);
        let validated = self.hooks.validator.validate(&row, storage, schema.as_ref()).await?;

        let mut document = bson_util::from_validated(&relation_keys(storage), &validated)?;
        codec::encode(&mut document, storage.column_definitions.as_ref());
        if let Some(id) = given_id {
            document.insert(ID, id);
        }

        let result = match coll.insert_one(&document).await {
            Ok(r) => r,
            Err(e) => {
                if let (Some(id), Some(message)) = (given_id, is_duplicate_key(&e)) {
                    if message.contains(DUPLICATE_ID_INDEX) {
                        return Err(AppDataError::storage_object_id_exists(&id.to_hex(), &storage.name));
                    }
                }
                // Another unique index: a 409 naming the storage (`CORE.DUPLICATE_KEY`).
                return Err(AppDataError::from(e).in_storage(&storage.name));
            }
        };
        let inserted = match result.inserted_id {
            Bson::ObjectId(o) => Some(o),
            _ => given_id,
        };
        let id_filter = match inserted {
            Some(o) => Bson::ObjectId(o),
            None => result.inserted_id.clone(),
        };

        let mut doc = coll
            .find_one(doc! { ID: id_filter })
            .await?
            .ok_or_else(|| AppDataError::internal("NullPointerException: the created row could not be read back"))?;

        let hex = inserted.map(|o| o.to_hex()).unwrap_or_else(|| bson_util::to_value(&result.inserted_id).java_string());
        self.add_version(cx, client_code, conn, storage, data.message.as_deref(), &hex, &mut doc, "CREATE").await?;

        if let Some(o) = inserted {
            doc.insert(ID, o.to_hex());
        }
        // Handed back as stored: no codec decode and no relation conversion, as in Java.
        Ok(document_to_value(&doc))
    }

    async fn update(
        &self,
        cx: &Ctx,
        client_code: &str,
        conn: Option<&Connection>,
        storage: &Storage,
        data: DataObject,
        override_: Option<bool>,
    ) -> AppDataResult<Document> {
        let mut row = data.data.clone().unwrap_or_default();
        // StringUtil.safeValueOf: a missing id is null, and the message says so.
        let key = match row.get(ID) {
            None | Some(Value::Null) => "null".to_string(),
            Some(v) => v.java_string(),
        };
        let blank = matches!(row.get(ID), None | Some(Value::Null)) || key.trim().is_empty();
        let Some(object_id) = parse_object_id(&key).filter(|_| !blank) else {
            return Err(AppDataError::object_not_found_to_update(&storage.name, &key));
        };

        let coll = self.collection(cx, client_code, conn, storage).await?;
        let schema = storage_schema(storage);

        row.shift_remove(ID);
        let to_write = if override_ == Some(true) {
            row
        } else {
            let mut existing = coll
                .find_one(doc! { ID: object_id })
                .await?
                .ok_or_else(|| AppDataError::object_not_found_to_update(&storage.name, &key))?;
            existing.remove(ID);
            let existing = convert_ids(storage, existing, false);
            difference::apply(&row, &existing)
        };

        let validated = self.hooks.validator.validate(&to_write, storage, schema.as_ref()).await?;
        let mut document = bson_util::from_validated(&relation_keys(storage), &validated)?;
        codec::encode(&mut document, storage.column_definitions.as_ref());
        coll.replace_one(doc! { ID: object_id }, document).await.map_err(|e| AppDataError::from(e).in_storage(&storage.name))?;

        let mut doc = coll
            .find_one(doc! { ID: object_id })
            .await?
            .ok_or_else(|| AppDataError::object_not_found_to_update(&storage.name, &key))?;

        self.add_version(cx, client_code, conn, storage, data.message.as_deref(), &object_id.to_hex(), &mut doc, "UPDATE")
            .await?;

        doc.insert(ID, key);
        relation_ids_to_hex(storage, &mut doc);
        Ok(document_to_value(&doc))
    }

    async fn read(&self, cx: &Ctx, client_code: &str, conn: Option<&Connection>, storage: &Storage, id: &str)
        -> AppDataResult<Document> {
        let Some(oid) = parse_object_id(id) else {
            return Err(AppDataError::object_not_found(&storage.name, id));
        };
        let coll = self.collection(cx, client_code, conn, storage).await?;
        match coll.find_one(doc! { ID: oid }).await? {
            Some(d) => Ok(convert_ids(storage, d, false)),
            None => Err(AppDataError::object_not_found(&storage.name, id)),
        }
    }

    /// `$inc` on the counter's document is atomic on any deployment, standalone included. The
    /// first call inserts `start`; two first calls racing meet on the `_id` and the loser
    /// increments instead.
    async fn next_sequence(
        &self,
        cx: &Ctx,
        client_code: &str,
        conn: Option<&Connection>,
        storage: &Storage,
        key: &str,
        start: i64,
    ) -> AppDataResult<i64> {
        use mongodb::options::ReturnDocument;
        let tenant = cx.tenant(client_code, storage);
        let coll = self
            .client(conn)
            .await?
            .database(&database_name(&tenant, &storage.app_code, cx.draft))
            .collection::<BsonDocument>(SEQUENCE_COLLECTION);
        let name = format!("{}:{key}", storage.unique_name);
        for _ in 0..3 {
            let bumped = coll
                .find_one_and_update(doc! { ID: &name }, doc! { "$inc": { "value": 1_i64 } })
                .return_document(ReturnDocument::After)
                .await?;
            if let Some(d) = bumped {
                return match d.get("value") {
                    Some(Bson::Int64(v)) => Ok(*v),
                    Some(Bson::Int32(v)) => Ok(i64::from(*v)),
                    Some(Bson::Double(v)) => Ok(*v as i64),
                    _ => Err(AppDataError::internal(format!("sequence {name} holds no number"))),
                };
            }
            match coll.insert_one(doc! { ID: &name, "value": start }).await {
                Ok(_) => return Ok(start),
                Err(e) if is_duplicate_key(&e).is_some() => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Err(AppDataError::internal(format!("sequence {name}: could not be read or created")))
    }

    async fn read_page(&self, cx: &Ctx, client_code: &str, conn: Option<&Connection>, storage: &Storage, query: &Query)
        -> AppDataResult<Page<Document>> {
        Self::refuse_if_unsupported(query)?;
        let page = query.pageable()?;
        let coll = self.collection(cx, client_code, conn, storage).await?;
        let condition = filter(storage, query.condition.as_ref())?;
        let rows: Vec<Document> = self
            .query_elements(&coll, query, condition.clone(), &page)
            .await?
            .into_iter()
            .map(|d| convert_ids(storage, d, false))
            .collect();
        let total = if query.counts() {
            coll.count_documents(condition).await? as i64
        } else {
            page.offset() + rows.len() as i64
        };
        Ok(Page::of(rows, page, || total))
    }

    async fn read_page_rows(&self, cx: &Ctx, client_code: &str, conn: Option<&Connection>, storage: &Storage, query: &Query)
        -> AppDataResult<Vec<Document>> {
        Self::refuse_if_unsupported(query)?;
        let page = query.pageable()?;
        let coll = self.collection(cx, client_code, conn, storage).await?;
        let condition = filter(storage, query.condition.as_ref())?;
        Ok(self
            .query_elements(&coll, query, condition, &page)
            .await?
            .into_iter()
            .map(|d| convert_ids(storage, d, false))
            .collect())
    }

    async fn aggregate(
        &self,
        cx: &Ctx,
        client_code: &str,
        conn: Option<&Connection>,
        storage: &Storage,
        query: &AggregateQuery,
    ) -> AppDataResult<Page<Document>> {
        if query.has_joins() {
            return Err(AppDataError::unsupported_on_backend("joins", BACKEND));
        }
        if query.has_sub_queries() {
            return Err(AppDataError::unsupported_on_backend("subqueries", BACKEND));
        }
        let page = query.pageable()?;
        let coll = self.collection(cx, client_code, conn, storage).await?;

        if let Some(reason) = aggregate_validator::check(query) {
            return Err(AppDataError::invalid_aggregation(&reason));
        }
        if let Some(reason) = aggregate::bucket_encoding_problem(query) {
            return Err(AppDataError::invalid_aggregation(&reason));
        }
        if let Some(reason) = aggregate::schema_problem(&storage.name, storage_schema(storage).as_ref(), query) {
            return Err(AppDataError::invalid_aggregation(&reason));
        }
        for g in query.group_by.iter().flatten() {
            if g.bucket.is_none() || g.encoding != Some(crate::model::DateEncoding::EpochSeconds) {
                continue;
            }
            let field = g.field.clone().unwrap_or_default();
            let first = coll
                .find_one(doc! { &field: { "$exists": true } })
                .projection(doc! { &field: 1 })
                .await?;
            let n = match first.as_ref().and_then(|d| d.get(&field)) {
                Some(Bson::Int32(i)) => Some(*i as i64),
                Some(Bson::Int64(i)) => Some(*i),
                Some(Bson::Double(d)) => Some(*d as i64),
                _ => None,
            };
            if let Some(n) = n.filter(|n| n.unsigned_abs() > aggregate::EPOCH_SECONDS_SANITY_CEILING as u64) {
                return Err(AppDataError::invalid_aggregation(&format!(
                    "field '{field}' is declared EPOCH_SECONDS but holds {n}, which is milliseconds; bucketing it as seconds would be wrong by a factor of 1000"
                )));
            }
        }

        let match_doc = filter(storage, query.condition.as_ref())?;
        let having_doc = match &query.having {
            None => None,
            Some(h) => Some(filter(storage, Some(h))?),
        };

        let mut shared = vec![doc! { "$match": match_doc }, aggregate::group_stage(query), aggregate::project_stage(query)];
        if let Some(h) = having_doc {
            shared.push(doc! { "$match": h });
        }
        let mut paging = Vec::new();
        if let Some(s) = aggregate::sort_doc(&page.sort) {
            paging.push(doc! { "$sort": s });
        }
        paging.push(doc! { "$skip": page.offset() as i32 });
        paging.push(doc! { "$limit": page.size });

        let run = |pipeline: Vec<BsonDocument>| {
            coll.aggregate(pipeline).allow_disk_use(true).max_time(Duration::from_secs(AGGREGATE_MAX_SECONDS))
        };

        if !query.counts() {
            let mut pipeline = shared;
            pipeline.extend(paging);
            let rows: Vec<BsonDocument> = run(pipeline).await?.try_collect().await?;
            let rows: Vec<Document> = rows.iter().map(document_to_value).collect();
            let total = page.offset() + rows.len() as i64;
            return Ok(Page::of(rows, page, || total));
        }

        let mut pipeline = shared;
        pipeline.push(doc! { "$facet": { "rows": paging, "total": [ { "$count": "value" } ] } });
        let facet = run(pipeline).await?.try_next().await?;
        let Some(facet) = facet else { return Ok(Page::of(Vec::new(), page, || 0)) };
        let rows: Vec<Document> = match facet.get("rows") {
            Some(Bson::Array(a)) => a.iter().filter_map(|d| d.as_document()).map(document_to_value).collect(),
            _ => Vec::new(),
        };
        let total = match facet.get("total") {
            Some(Bson::Array(a)) => match a.first().and_then(|d| d.as_document()).and_then(|d| d.get("value")) {
                Some(Bson::Int32(i)) => *i as i64,
                Some(Bson::Int64(i)) => *i,
                Some(Bson::Double(d)) => *d as i64,
                _ => 0,
            },
            _ => 0,
        };
        Ok(Page::of(rows, page, || total))
    }

    async fn delete(
        &self,
        cx: &Ctx,
        client_code: &str,
        conn: Option<&Connection>,
        storage: &Storage,
        id: &str,
        delete_version: Option<bool>,
    ) -> AppDataResult<bool> {
        let Some(oid) = parse_object_id(id) else {
            return Err(AppDataError::object_not_found(&storage.name, id));
        };
        let coll = self.collection(cx, client_code, conn, storage).await?;
        let Some(doc) = coll.find_one(doc! { ID: oid }).await? else {
            return Err(AppDataError::object_not_found(&storage.name, id));
        };
        self.record_delete(cx, client_code, conn, storage, Some(doc), id, delete_version).await?;
        match coll.find_one_and_delete(doc! { ID: oid }).await? {
            Some(_) => Ok(true),
            None => Err(AppDataError::object_not_found(&storage.name, id)),
        }
    }

    async fn delete_by_filter(
        &self,
        cx: &Ctx,
        client_code: &str,
        conn: Option<&Connection>,
        storage: &Storage,
        query: &Query,
        dev_mode: Option<bool>,
        delete_version: Option<bool>,
    ) -> AppDataResult<i64> {
        Self::refuse_if_unsupported(query)?;
        let coll = self.collection(cx, client_code, conn, storage).await?;
        let condition = filter(storage, query.condition.as_ref())?;
        if dev_mode == Some(true) {
            return Ok(coll.count_documents(condition).await? as i64);
        }
        self.record_bulk_delete(cx, client_code, conn, storage, &coll, &condition, delete_version).await?;
        Ok(coll.delete_many(condition).await?.deleted_count as i64)
    }

    async fn read_version(&self, cx: &Ctx, client_code: &str, conn: Option<&Connection>, storage: &Storage, version_id: &str)
        -> AppDataResult<Document> {
        let Some(oid) = parse_object_id(version_id) else {
            return Err(AppDataError::version_not_found(&storage.name, version_id));
        };
        let versions = self.version_collection(cx, client_code, conn, storage).await?;
        match versions.find_one(doc! { ID: oid }).await? {
            Some(d) => Ok(convert_ids(storage, d, true)),
            None => Err(AppDataError::generic_not_found(&storage.name, version_id)),
        }
    }

    async fn read_page_version(
        &self,
        cx: &Ctx,
        client_code: &str,
        conn: Option<&Connection>,
        storage: &Storage,
        object_id: &str,
        query: &Query,
        include_object: Option<bool>,
    ) -> AppDataResult<Page<Document>> {
        let effective = if include_object == Some(false) && query.fields.as_ref().is_none_or(|f| f.is_empty()) {
            Query {
                condition: query.condition.clone(),
                page: query.page,
                size: query.size,
                sort: query.sort.clone(),
                count: query.count,
                fields: Some(vec![OBJECT.to_string()]),
                exclude_fields: Some(true),
                ..Query::default()
            }
        } else {
            query.clone()
        };
        let page = effective.pageable()?;

        let by_object = Condition::Filter(FilterCondition::new(OBJECT_ID, FilterOperator::Equals, Some(Value::from(object_id))));
        let condition = match &effective.condition {
            None => by_object,
            Some(c) => Condition::Complex(ComplexCondition::and(vec![by_object, c.clone()])),
        };

        let versions = self.version_collection(cx, client_code, conn, storage).await?;
        let bson_filter = filter(storage, Some(&condition))?;
        let rows: Vec<Document> = self
            .query_elements(&versions, &effective, bson_filter.clone(), &page)
            .await?
            .into_iter()
            .map(|d| convert_ids(storage, d, true))
            .collect();
        let total = if effective.counts() {
            versions.count_documents(bson_filter).await? as i64
        } else {
            page.offset() + rows.len() as i64
        };
        Ok(Page::of(rows, page, || total))
    }

    async fn check_if_exists(&self, cx: &Ctx, client_code: &str, conn: Option<&Connection>, storage: &Storage, id: &str)
        -> AppDataResult<bool> {
        let Some(oid) = parse_object_id(id) else { return Ok(false) };
        let coll = self.collection(cx, client_code, conn, storage).await?;
        Ok(coll.count_documents(doc! { ID: oid }).await? > 0)
    }

    async fn count_referencing(
        &self,
        cx: &Ctx,
        client_code: &str,
        conn: Option<&Connection>,
        child: &Storage,
        field: &str,
        _many: bool,
        id: &str,
    ) -> AppDataResult<i64> {
        let Some(oid) = parse_object_id(id) else { return Ok(0) };
        let coll = self.collection(cx, client_code, conn, child).await?;
        Ok(coll.count_documents(doc! { field: oid }).await? as i64)
    }

    async fn ids_referencing(
        &self,
        cx: &Ctx,
        client_code: &str,
        conn: Option<&Connection>,
        child: &Storage,
        field: &str,
        _many: bool,
        id: &str,
        limit: i64,
    ) -> AppDataResult<Vec<String>> {
        let Some(oid) = parse_object_id(id) else { return Ok(Vec::new()) };
        let coll = self.collection(cx, client_code, conn, child).await?;
        let docs: Vec<BsonDocument> =
            coll.find(doc! { field: oid }).projection(doc! { ID: 1 }).limit(limit).await?.try_collect().await?;
        docs.iter().map(|d| object_id_of(d).map(|o| o.to_hex())).collect()
    }

    async fn delete_storage(&self, cx: &Ctx, client_code: &str, conn: Option<&Connection>, storage: &Storage)
        -> AppDataResult<bool> {
        let coll = self.collection(cx, client_code, conn, storage).await?;
        coll.drop().await?;
        if storage.keeps_history() {
            self.version_collection(cx, client_code, conn, storage).await?.drop().await?;
        }
        Ok(true)
    }

    async fn drop_draft_storage(&self, cx: &Ctx, client_code: &str, conn: Option<&Connection>, storage: &Storage)
        -> AppDataResult<bool> {
        let Ok(client) = self.client(conn).await else { return Ok(false) };
        let db = client.database(&database_name(&cx.tenant(client_code, storage), &storage.app_code, true));
        let dropped = async {
            db.collection::<BsonDocument>(&storage.unique_name).drop().await?;
            db.collection::<BsonDocument>(&version_name(&storage.unique_name)).drop().await
        }
        .await;
        Ok(dropped.is_ok())
    }

    async fn drop_draft_database(&self, conn: Option<&Connection>, app_code: &str, client_code: &str) -> AppDataResult<bool> {
        if app_code.trim().is_empty() || client_code.trim().is_empty() {
            return Ok(false);
        }
        let Ok(client) = self.client(conn).await else { return Ok(false) };
        Ok(client.database(&database_name(client_code, app_code, true)).drop().await.is_ok())
    }

    async fn database_names(&self, conn: Option<&Connection>) -> AppDataResult<Vec<String>> {
        Ok(self.client(conn).await?.list_database_names().await?)
    }

    async fn database_rows(&self, conn: Option<&Connection>, name: &str) -> AppDataResult<i64> {
        let stats = self.client(conn).await?.database(name).run_command(doc! {"dbStats": 1}).await?;
        Ok(match stats.get("objects") {
            Some(Bson::Int32(n)) => i64::from(*n),
            Some(Bson::Int64(n)) => *n,
            Some(Bson::Double(n)) => *n as i64,
            _ => 0,
        })
    }

    async fn drop_database(&self, conn: Option<&Connection>, name: &str) -> AppDataResult<bool> {
        if !crate::engine::is_tenant_database_name(name) {
            return Err(AppDataError::internal(format!("IllegalArgumentException: not a tenant database: {name}")));
        }
        self.client(conn).await?.database(name).drop().await?;
        Ok(true)
    }

    async fn copy_live_to_draft(
        &self,
        cx: &Ctx,
        client_code: &str,
        conn: Option<&Connection>,
        storage: &Storage,
        replace: Option<bool>,
    ) -> AppDataResult<i64> {
        let live = self.collection(&cx.on_draft(false), client_code, conn, storage).await?;
        let draft = self.collection(&cx.on_draft(true), client_code, conn, storage).await?;
        let live_count = live.count_documents(BsonDocument::new()).await?;
        if live_count > 0 && replace == Some(true) {
            draft.delete_many(BsonDocument::new()).await?;
        }
        if live_count < 1 {
            return Ok(0);
        }
        self.copy_into(&live, &draft, BsonDocument::new()).await
    }

    async fn clear_draft_rows(&self, cx: &Ctx, client_code: &str, conn: Option<&Connection>, storage: &Storage)
        -> AppDataResult<i64> {
        let draft_cx = cx.on_draft(true);
        let draft = self.collection(&draft_cx, client_code, conn, storage).await?;
        let deleted = draft.delete_many(BsonDocument::new()).await?.deleted_count as i64;
        let versions = self.version_collection(&draft_cx, client_code, conn, storage).await?;
        versions.delete_many(BsonDocument::new()).await?;
        Ok(deleted)
    }

    async fn copy_live_to_draft_filtered(
        &self,
        cx: &Ctx,
        client_code: &str,
        conn: Option<&Connection>,
        storage: &Storage,
        filter_spec: Option<&DraftCopyFilter>,
        followed: &HashMap<String, Storage>,
    ) -> AppDataResult<i64> {
        let live = self.collection(&cx.on_draft(false), client_code, conn, storage).await?;
        let draft = self.collection(&cx.on_draft(true), client_code, conn, storage).await?;
        let where_ = self.draft_copy_filter(cx, client_code, conn, storage, filter_spec, followed).await?;
        draft.delete_many(BsonDocument::new()).await?;
        self.copy_into(&live, &draft, where_).await
    }
}
