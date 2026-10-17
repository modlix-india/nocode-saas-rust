//! The Mongo backend, Java's default when an app has no appData connection.

pub mod aggregate;
pub mod bson_util;
pub mod codec;
pub mod decimal128;
pub mod filter;
pub mod service;

pub use service::{database_name, MongoAppDataService, MongoEngineConfig};
