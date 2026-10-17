//! The overridable-document read path of the Java `commons-mongo` services (`ui`, `core`),
//! for Rust units that serve the same documents.
//!
//! - [`json`]: a JSON value that keeps key order and integer/double, and the Jackson and Gson
//!   writers the Java services answer with;
//! - [`java_map`]: the key order of a `java.util.HashMap`;
//! - [`difference`]: `DifferenceApplicator` / `DifferenceExtractor`;
//! - [`three_way`]: `ThreeWayMerge`, for drafts;
//! - [`pojo`]: the Java document classes as field lists (decode, clone, write);
//! - [`store`]: inheritance, candidate fetch, published and draft selection, the merge down
//!   the `baseClientCode` chain, and the per-client definition cache under the Java names;
//! - [`catalogue`]: the library's error messages (codes `DEF.*`).

pub mod backend;
pub mod bson_conv;
pub mod catalogue;
pub mod difference;
pub mod java_map;
pub mod json;
pub mod pojo;
pub mod store;
pub mod three_way;
pub mod write;

pub use json::{JMap, JValue};
pub use store::{DocType, Resolved, Store};
