//! [`Backend`] on a MongoDB database, doing what Spring Data does for the Java services.

use anyhow::Result;
use async_trait::async_trait;
use futures::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, Bson, Document};
use mongodb::error::{ErrorKind, WriteFailure};
use mongodb::options::FindOptions;
use mongodb::Database;

use super::{Backend, DuplicateKey, Find};

#[derive(Clone)]
pub struct MongoBackend {
    db: Database,
}

impl MongoBackend {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    pub fn db(&self) -> &Database {
        &self.db
    }
}

/// Mongo's duplicate key error, as Spring raises `DuplicateKeyException` for it.
fn map_write_error(collection: &str, e: mongodb::error::Error) -> anyhow::Error {
    let duplicate = match e.kind.as_ref() {
        ErrorKind::Write(WriteFailure::WriteError(w)) => w.code == 11000,
        ErrorKind::Command(c) => c.code == 11000,
        _ => false,
    };
    if duplicate {
        anyhow::Error::new(DuplicateKey { collection: collection.to_string() })
    } else {
        e.into()
    }
}

#[async_trait]
impl Backend for MongoBackend {
    async fn find(&self, collection: &str, query: Find) -> Result<Vec<Document>> {
        let opts = FindOptions::builder()
            .sort(query.sort)
            .projection(query.projection)
            .skip((query.skip > 0).then_some(query.skip))
            .limit(query.limit)
            .build();
        let cursor = self.db.collection::<Document>(collection).find(query.filter).with_options(opts).await?;
        Ok(cursor.try_collect().await?)
    }

    async fn count(&self, collection: &str, filter: Document) -> Result<u64> {
        Ok(self.db.collection::<Document>(collection).count_documents(filter).await?)
    }

    async fn insert(&self, collection: &str, mut doc: Document) -> Result<Bson> {
        if !doc.contains_key("_id") {
            let mut with_id = doc! {"_id": ObjectId::new()};
            with_id.extend(doc);
            doc = with_id;
        }
        let r = self
            .db
            .collection::<Document>(collection)
            .insert_one(doc)
            .await
            .map_err(|e| map_write_error(collection, e))?;
        Ok(r.inserted_id)
    }

    async fn replace(&self, collection: &str, id: Bson, doc: Document) -> Result<()> {
        self.db
            .collection::<Document>(collection)
            .replace_one(doc! {"_id": id}, doc)
            .upsert(true)
            .await
            .map_err(|e| map_write_error(collection, e))?;
        Ok(())
    }

    async fn delete_one(&self, collection: &str, filter: Document) -> Result<u64> {
        Ok(self.db.collection::<Document>(collection).delete_one(filter).await?.deleted_count)
    }

    async fn delete_many(&self, collection: &str, filter: Document) -> Result<u64> {
        Ok(self.db.collection::<Document>(collection).delete_many(filter).await?.deleted_count)
    }

    async fn update_many(&self, collection: &str, filter: Document, set: Document) -> Result<u64> {
        Ok(self
            .db
            .collection::<Document>(collection)
            .update_many(filter, doc! {"$set": set})
            .await?
            .modified_count)
    }
}
