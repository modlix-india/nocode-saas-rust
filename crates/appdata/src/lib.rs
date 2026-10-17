//! The app-data storage engines of the Java `core` service: where a storage's rows live,
//! on Mongo (`MongoAppDataService`) or MySQL (`MySQLAppDataService`), behind one trait
//! ([`engine::AppDataEngine`], Java's `IAppDataService`).
//!
//! The policy layer of `AppDataService` (auth gates, triggers, relations, validation) is not
//! here; it calls these engines. What is here is everything below it: filters, paging,
//! aggregates, versions, the draft surface, and on MySQL the DDL, the migration journal and
//! the drift report.

pub mod aggregate_validator;
pub mod catalogue;
pub mod difference;
pub mod engine;
pub mod error;
pub mod field_names;
pub mod java_time;
pub mod lookup;
pub mod model;
pub mod mongo;
pub mod mysql;
pub mod retention;
pub mod schema_refs;
pub mod selection;
pub mod ulid;
pub mod value;

pub use engine::{AppDataEngine, Ctx, Hooks};
pub use error::{AppDataError, AppDataResult};
pub use value::{Document, Value};
