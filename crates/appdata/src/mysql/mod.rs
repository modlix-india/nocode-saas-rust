//! The MySQL backend: one schema per `<CLIENT>_<app>`, a sibling `_draft` schema, and the
//! storage's uniqueName as the table on both surfaces.

pub mod aggregate_builder;
pub mod column;
pub mod column_names;
pub mod db;
pub mod drift;
pub mod field_resolver;
pub mod filter_builder;
pub mod foreign_keys;
pub mod indexes;
pub mod inspector;
pub mod join_planner;
pub mod journal;
pub mod migration;
pub mod migration_planner;
pub mod porter_stemmer;
pub mod service;
pub mod sql;
pub mod subquery_planner;
pub mod table_planner;
pub mod type_mapper;
pub mod value_codec;
pub mod version_table;

pub use service::{MySqlAppDataService, MySqlEngineConfig};
