//! Storages: the policy layer over the app-data engines (`AppDataService`), the definitions
//! it reads, the write validator the engines call, and storage rows as files.

pub mod defs;
pub mod files;
pub mod service;
pub mod validator;
pub mod values;

#[cfg(test)]
mod integration_ports;
