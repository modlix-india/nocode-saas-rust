//! The part of `AppDataService` that only picks the engine: an app's APP_DATA connection
//! named "appData" decides it, and no connection means Mongo.
//!
//! Which database the rows land in follows from the engine: Mongo uses the default client
//! (or the connection's own url) and `<CLIENT>_<app>`; MySQL uses the connection's server
//! (or the platform's own, for `useDefaultConnection`) and the schema `<CLIENT>_<app>`;
//! both add `_draft` on the draft surface.

use std::sync::Arc;

use crate::engine::AppDataEngine;
use crate::error::{AppDataError, AppDataResult};
use crate::model::{Connection, ConnectionSubType};
use crate::mongo::MongoAppDataService;
use crate::mysql::MySqlAppDataService;

/// The connection name and type `AppDataService` reads.
pub const CONNECTION_NAME: &str = "appData";
pub const CONNECTION_TYPE: &str = "APP_DATA";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Mongo,
    MySql,
}

/// `services.get(conn == null ? MONGO : conn.getConnectionSubType())`. A connection whose
/// subtype is not an app-data backend selects nothing; Java then fails with a
/// NullPointerException, a 500, and so does this.
pub fn backend_for(conn: Option<&Connection>) -> AppDataResult<Backend> {
    match conn {
        None => Ok(Backend::Mongo),
        Some(c) => match &c.connection_sub_type {
            Some(ConnectionSubType::Mongo) => Ok(Backend::Mongo),
            Some(ConnectionSubType::MySql) => Ok(Backend::MySql),
            other => Err(AppDataError::internal(format!(
                "NullPointerException: no app data service for connection subtype {other:?}"
            ))),
        },
    }
}

/// The database (Mongo) or schema (MySQL) a client's rows of an app live in.
pub fn database(client_code: &str, app_code: &str, draft: bool) -> String {
    format!("{client_code}_{app_code}{}", if draft { crate::engine::DRAFT_DB_SUFFIX } else { "" })
}

/// Both engines, and the choice between them.
#[derive(Clone)]
pub struct Engines {
    pub mongo: Arc<MongoAppDataService>,
    pub mysql: Arc<MySqlAppDataService>,
}

impl Engines {
    pub fn for_connection(&self, conn: Option<&Connection>) -> AppDataResult<Arc<dyn AppDataEngine>> {
        Ok(match backend_for(conn)? {
            Backend::Mongo => self.mongo.clone(),
            Backend::MySql => self.mysql.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(sub: Option<ConnectionSubType>) -> Connection {
        Connection { id: "c".into(), connection_sub_type: sub, ..Default::default() }
    }

    #[test]
    fn picks_the_backend() {
        assert_eq!(backend_for(None).unwrap(), Backend::Mongo);
        assert_eq!(backend_for(Some(&conn(Some(ConnectionSubType::Mongo)))).unwrap(), Backend::Mongo);
        assert_eq!(backend_for(Some(&conn(Some(ConnectionSubType::MySql)))).unwrap(), Backend::MySql);
        assert!(backend_for(Some(&conn(Some(ConnectionSubType::Other("SMTP".into()))))).is_err());
        assert!(backend_for(Some(&conn(None))).is_err());
        assert_eq!(database("SYSTEM", "appa", false), "SYSTEM_appa");
        assert_eq!(database("SYSTEM", "appa", true), "SYSTEM_appa_draft");
    }
}
