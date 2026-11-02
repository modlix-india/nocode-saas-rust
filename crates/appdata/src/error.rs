//! The errors the engines raise, with the status and message text the Java engines use.
//!
//! The messages come from `core/src/main/resources/messages_en.properties`, filled in the
//! way `CoreMessageResourceService.throwMessage` fills them. The kind is kept alongside the
//! text because callers act on it: the KIRun storage functions catch a missing object
//! (`StorageObjectNotFoundException`) and nothing else.

use http::StatusCode;
use platform::error::{AppError, Coded};
use platform::messages::JavaKey;

pub type AppDataResult<T> = Result<T, AppDataError>;

/// Which Java exception the error stands for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// `GenericException`.
    Generic,
    /// `StorageObjectNotFoundException`, which the KIRun storage functions catch.
    ObjectNotFound,
}

#[derive(Debug, thiserror::Error)]
pub enum AppDataError {
    /// Java's status and text, and the code (`CORE.*`, from core's catalogue) that says it
    /// plainly.
    #[error("{status}: {message}")]
    Message { status: StatusCode, message: String, kind: ErrorKind, code: Option<Box<Coded>> },

    /// The Java engine completed EMPTY rather than with a value (a PUT to a row that is not
    /// there, on MySQL). `AppDataService.genericOperation` answers that with the
    /// operation's own FORBIDDEN message, which only the caller knows.
    #[error("the operation produced nothing")]
    Empty,

    /// Anything the Java code would let escape as a 500: a driver error, a refused
    /// statement nobody translated.
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl AppDataError {
    /// `throwMessage(status, KEY, values...)`: Java's text and the code standing for the key.
    pub fn new(status: StatusCode, key: JavaKey, params: &[&str]) -> Self {
        Self::keyed(status, key, params, ErrorKind::Generic)
    }

    fn keyed(status: StatusCode, key: JavaKey, params: &[&str], kind: ErrorKind) -> Self {
        crate::catalogue::register();
        AppDataError::Message { status, message: key.text(params), kind, code: Some(Box::new(key.coded("CORE", params))) }
    }

    /// The key's Java text said by a more specific `code`, its values named by that code.
    fn keyed_as(status: StatusCode, key: JavaKey, code: &'static str, params: &[&str], kind: ErrorKind) -> Self {
        crate::catalogue::register();
        AppDataError::Message { status, message: key.text(params), kind, code: Some(Box::new(key.coded_as(code, params))) }
    }

    /// The same Java text said by a more specific code; the values stay.
    pub fn with_code(self, code: &'static str) -> Self {
        match self {
            AppDataError::Message { status, message, kind, code: old } => {
                let c = match old {
                    Some(old) => Coded { code: code.into(), ..*old },
                    None => Coded::new(code),
                };
                AppDataError::Message { status, message, kind, code: Some(Box::new(c)) }
            }
            other => other,
        }
    }

    /// Sets a value of the message.
    pub fn param(self, name: &str, value: impl ToString) -> Self {
        match self {
            AppDataError::Message { status, message, kind, code } => {
                AppDataError::Message { status, message, kind, code: code.map(|c| Box::new(c.param(name, value))) }
            }
            other => other,
        }
    }

    /// The code the error answers with, when it has one.
    pub fn code(&self) -> Option<&Coded> {
        match self {
            AppDataError::Message { code, .. } => code.as_deref(),
            _ => None,
        }
    }

    pub fn status(&self) -> StatusCode {
        match self {
            AppDataError::Message { status, .. } => *status,
            AppDataError::Empty => StatusCode::FORBIDDEN,
            AppDataError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn message(&self) -> String {
        match self {
            AppDataError::Message { message, .. } => message.clone(),
            AppDataError::Empty => String::new(),
            AppDataError::Internal(e) => e.to_string(),
        }
    }

    pub fn kind(&self) -> ErrorKind {
        match self {
            AppDataError::Message { kind, .. } => *kind,
            _ => ErrorKind::Generic,
        }
    }

    pub fn is_object_not_found(&self) -> bool {
        self.kind() == ErrorKind::ObjectNotFound
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        AppDataError::Internal(anyhow::anyhow!(msg.into()))
    }

    // ---- the messages the engines raise, one constructor each

    /// `object_not_found` for a version of a row (a version id that is not one), as
    /// `StorageObjectNotFoundException` (404).
    pub fn version_not_found(storage: &str, id: &str) -> Self {
        Self::keyed_as(StatusCode::NOT_FOUND, msg::OBJECT_NOT_FOUND, "CORE.VERSION_NOT_FOUND", &[storage, id], ErrorKind::ObjectNotFound)
    }

    /// `object_not_found` for a row, as `StorageObjectNotFoundException` (404).
    pub fn object_not_found(storage: &str, id: &str) -> Self {
        Self::keyed_as(StatusCode::NOT_FOUND, msg::OBJECT_NOT_FOUND, "CORE.ROW_NOT_FOUND", &[storage, id], ErrorKind::ObjectNotFound)
    }

    /// `object_not_found` as a plain `GenericException` (404), which is what reading a
    /// missing VERSION raises on both backends.
    pub fn generic_not_found(storage: &str, id: &str) -> Self {
        Self::keyed_as(StatusCode::NOT_FOUND, msg::OBJECT_NOT_FOUND, "CORE.VERSION_NOT_FOUND", &[storage, id], ErrorKind::Generic)
    }

    pub fn object_not_found_to_update(storage: &str, id: &str) -> Self {
        Self::keyed(StatusCode::NOT_FOUND, msg::OBJECT_NOT_FOUND_TO_UPDATE, &[storage, id], ErrorKind::ObjectNotFound)
    }

    pub fn unsupported_condition(what: &str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, msg::UNSUPPORTED_CONDITION, &[what])
    }

    pub fn unsupported_on_backend(what: &str, backend: &str) -> Self {
        Self::new(StatusCode::NOT_IMPLEMENTED, msg::UNSUPPORTED_ON_BACKEND, &[what, backend])
    }

    pub fn invalid_aggregation(reason: &str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, msg::INVALID_AGGREGATION, &[reason])
    }

    pub fn invalid_join(reason: &str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, msg::INVALID_JOIN, &[reason])
    }

    /// `connection_details_missing` naming the setting the data connection lacks (`url`).
    pub fn connection_details_missing(what: &str) -> Self {
        Self::keyed_as(StatusCode::NOT_FOUND, msg::CONNECTION_DETAILS_MISSING, "CORE.DATA_CONNECTION_INCOMPLETE", &[what], ErrorKind::Generic)
    }

    pub fn connection_not_available(backend: &str) -> Self {
        Self::new(StatusCode::NOT_FOUND, msg::CONNECTION_NOT_AVAILABLE, &[backend])
    }

    /// A write refused by a unique index (409, `CORE.DUPLICATE_KEY`, Rust only). The text names
    /// the index, never the value (it can be a person's e-mail); the engine that knows the
    /// storage adds it with [`AppDataError::in_storage`].
    pub fn duplicate_key(index: &str) -> Self {
        crate::catalogue::register();
        let index = index.trim();
        let mut c = Coded::new(DUPLICATE_KEY);
        if !index.is_empty() {
            c = c.param("index", index);
        }
        let message = if index.is_empty() { "Duplicate entry for a unique key".to_string() } else { format!("Duplicate entry for key '{index}'") };
        AppDataError::Message { status: StatusCode::CONFLICT, message, kind: ErrorKind::Generic, code: Some(Box::new(c)) }
    }

    /// Names the storage on a duplicate key (its text and its `storage` value); any other error
    /// is returned as it is.
    pub fn in_storage(self, storage: &str) -> Self {
        match self {
            AppDataError::Message { status, message, kind, code: Some(c) } if c.code == DUPLICATE_KEY => {
                let message = if message.contains(" in storage ") { message } else { format!("{message} in storage {storage}") };
                AppDataError::Message { status, message, kind, code: Some(Box::new(c.param("storage", storage))) }
            }
            other => other,
        }
    }

    /// Whether a unique index refused the write.
    pub fn is_duplicate_key(&self) -> bool {
        self.code().is_some_and(|c| c.code == DUPLICATE_KEY)
    }

    pub fn storage_object_id_exists(id: &str, storage: &str) -> Self {
        Self::new(StatusCode::CONFLICT, msg::STORAGE_OBJECT_ID_EXISTS, &[id, storage])
    }

    pub fn row_id_required(column: &str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, msg::ROW_ID_REQUIRED, &[column])
    }

    pub fn field_cannot_be_null(fields: &str, storage: &str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, msg::FIELD_CANNOT_BE_NULL, &[fields, storage])
    }

    /// `cannot_delete_storage_with_restrict`, whose one parameter Java passes as a List,
    /// so it renders with the brackets of `List.toString()` (the message names the storage
    /// without them).
    pub fn cannot_delete_with_restrict(storage: &str) -> Self {
        let param = format!("[{storage} (other rows still reference this one)]");
        Self::new(StatusCode::BAD_REQUEST, msg::CANNOT_DELETE_STORAGE_WITH_RESTRICT, &[&param]).param("objects", storage)
    }

    pub fn forbidden_read_storage(storage: &str) -> Self {
        Self::new(StatusCode::FORBIDDEN, msg::FORBIDDEN_READ_STORAGE, &[storage])
    }

    /// What Spring's `PageRequest.of` throws for a bad page or size.
    pub fn illegal_argument(message: &str) -> Self {
        AppDataError::Internal(anyhow::anyhow!("IllegalArgumentException: {message}"))
    }
}

/// The engines' errors as a unit answers them: coded with Java's text in `debugMessage`.
impl From<AppDataError> for AppError {
    fn from(e: AppDataError) -> Self {
        match e {
            AppDataError::Message { status, message, code: Some(c), .. } => {
                let prefix = c.debug.as_deref().and_then(|d| d.find("] ").map(|i| d[..i + 2].to_string())).unwrap_or_default();
                AppError::Coded(Box::new(c.status(status).debug(format!("{prefix}{message}"))))
            }
            AppDataError::Message { status, message, code: None, .. } => AppError::new(status, message),
            AppDataError::Empty => AppError::Empty(StatusCode::FORBIDDEN),
            AppDataError::Internal(e) => AppError::Internal(e),
        }
    }
}

/// A MySQL duplicate key (error 1062, or 1586 when the key is named, SQLSTATE 23000) becomes
/// [`AppDataError::duplicate_key`], a 409 a KIRun function can tell apart (Java let the R2DBC
/// `DataIntegrityViolationException` escape as a 500). Every other driver error stays internal.
impl From<sqlx::Error> for AppDataError {
    fn from(e: sqlx::Error) -> Self {
        if let Some(d) = e.as_database_error() {
            let number = d.try_downcast_ref::<sqlx::mysql::MySqlDatabaseError>().map(|m| m.number());
            if let Some(index) = mysql_duplicate_key(number, d.code().as_deref(), d.message()) {
                return AppDataError::duplicate_key(&index);
            }
        }
        AppDataError::Internal(anyhow::Error::new(e))
    }
}

/// Mongo's E11000 (codes 11000, 11001, 12582, Spring's `DuplicateKeyException`) becomes
/// [`AppDataError::duplicate_key`], as on MySQL.
impl From<mongodb::error::Error> for AppDataError {
    fn from(e: mongodb::error::Error) -> Self {
        if let Some(index) = mongo_error_duplicate_key(&e) {
            return AppDataError::duplicate_key(&index);
        }
        AppDataError::Internal(anyhow::Error::new(e))
    }
}

/// The code of a duplicate key, on both backends.
pub const DUPLICATE_KEY: &str = "CORE.DUPLICATE_KEY";

/// The unique index a MySQL error names when it is a duplicate key: error 1062 (or 1586), or
/// SQLSTATE 23000 with MySQL's "Duplicate entry '<value>' for key '<index>'" text. MySQL 8.0.19
/// and later write the key as `<table>.<index>`; the table is dropped. Empty when the text
/// names no key. `None` for every other error (a foreign key or a NOT NULL refusal is 23000 too).
pub fn mysql_duplicate_key(number: Option<u16>, sql_state: Option<&str>, message: &str) -> Option<String> {
    let duplicate = matches!(number, Some(1062 | 1586)) || (number.is_none() && sql_state == Some("23000") && message.starts_with("Duplicate entry"));
    if !duplicate {
        return None;
    }
    let key = message.rfind(" for key '").map(|i| &message[i + " for key '".len()..]).unwrap_or("");
    let key = key.strip_suffix('\'').unwrap_or(key);
    Some(key.rsplit('.').next().unwrap_or(key).to_string())
}

/// The unique index a Mongo write error names when it is a duplicate key (codes 11000, 11001,
/// 12582): "E11000 duplicate key error collection: <db>.<coll> index: <index> dup key: {...}".
/// Empty when the text names no index.
pub fn mongo_duplicate_key(code: i32, message: &str) -> Option<String> {
    if !matches!(code, 11000 | 11001 | 12582) {
        return None;
    }
    let index = message.find(" index: ").map(|i| &message[i + " index: ".len()..]).unwrap_or("");
    Some(index.split_whitespace().next().unwrap_or("").to_string())
}

/// The duplicate key a Mongo driver error carries: a single write's, a command's, or the first
/// failed insert of an `insert_many`.
fn mongo_error_duplicate_key(e: &mongodb::error::Error) -> Option<String> {
    use mongodb::error::{ErrorKind, WriteFailure};
    match e.kind.as_ref() {
        ErrorKind::Write(WriteFailure::WriteError(w)) => mongo_duplicate_key(w.code, &w.message),
        ErrorKind::Command(c) => mongo_duplicate_key(c.code, &c.message),
        ErrorKind::InsertMany(m) => m.write_errors.iter().flatten().find_map(|w| mongo_duplicate_key(w.code, &w.message)),
        _ => None,
    }
}

/// The message keys the engines raise, with their templates verbatim from core's
/// `messages_en.properties`.
pub mod msg {
    use platform::messages::JavaKey;

    pub const OBJECT_NOT_FOUND: JavaKey = JavaKey::new("object_not_found", "$ with id $ not found");
    pub const OBJECT_NOT_FOUND_TO_UPDATE: JavaKey = JavaKey::new("object_not_found_to_update", "$ with id $ not found to update");
    pub const CONNECTION_DETAILS_MISSING: JavaKey = JavaKey::new("connection_details_missing", "Connection details missing $");
    pub const FORBIDDEN_READ_STORAGE: JavaKey = JavaKey::new("forbidden_read_storage", "Unable to read data from storage $");
    pub const CANNOT_DELETE_STORAGE_WITH_RESTRICT: JavaKey = JavaKey::new("cannot_delete_storage_with_restrict", "Following objects exists and cannot be deleted: $");
    pub const STORAGE_OBJECT_ID_EXISTS: JavaKey = JavaKey::new("storage_object_id_exists", "A row with _id $ already exists in $. Remove the _id from the data to store it as a new row, or update the existing row instead.");
    pub const CONNECTION_NOT_AVAILABLE: JavaKey = JavaKey::new("connection_not_available", "Connection $ not available");
    pub const INVALID_AGGREGATION: JavaKey = JavaKey::new("invalid_aggregation", "Invalid aggregation request: $");
    pub const INVALID_JOIN: JavaKey = JavaKey::new("invalid_join", "Invalid join request: $");
    pub const UNSUPPORTED_CONDITION: JavaKey = JavaKey::new("unsupported_condition", "$ is not a condition this data filter supports.");
    pub const UNSUPPORTED_ON_BACKEND: JavaKey = JavaKey::new("unsupported_on_backend", "$ is not supported on the $ storage backend yet.");
    pub const ROW_ID_REQUIRED: JavaKey = JavaKey::new("row_id_required", "$ is required to update a row.");
    pub const FIELD_CANNOT_BE_NULL: JavaKey = JavaKey::new("field_cannot_be_null", "$ cannot be null in $: the field is required.");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each engine error carries Java's text and the code that says it plainly, its values
    /// named.
    #[test]
    fn engine_errors_are_coded() {
        let e = AppDataError::object_not_found("leads", "7");
        assert!(e.is_object_not_found());
        assert_eq!(e.message(), "leads with id 7 not found");
        let c = e.code().unwrap();
        assert_eq!(c.code, "CORE.ROW_NOT_FOUND");
        assert_eq!(c.params, vec![("storage".to_string(), "leads".to_string()), ("id".to_string(), "7".to_string())]);
        assert_eq!(c.english().message, "We couldn't find the row 7 in leads.");
        assert_eq!(c.debug.as_deref(), Some("[object_not_found] leads with id 7 not found"));

        for (e, code, status) in [
            (AppDataError::generic_not_found("leads", "v1"), "CORE.VERSION_NOT_FOUND", StatusCode::NOT_FOUND),
            (AppDataError::version_not_found("leads", "v1"), "CORE.VERSION_NOT_FOUND", StatusCode::NOT_FOUND),
            (AppDataError::object_not_found_to_update("leads", "7"), "CORE.OBJECT_NOT_FOUND_TO_UPDATE", StatusCode::NOT_FOUND),
            (AppDataError::unsupported_condition("x"), "CORE.UNSUPPORTED_CONDITION", StatusCode::BAD_REQUEST),
            (AppDataError::unsupported_on_backend("joins", "Mongo"), "CORE.UNSUPPORTED_ON_BACKEND", StatusCode::NOT_IMPLEMENTED),
            (AppDataError::invalid_aggregation("r"), "CORE.INVALID_AGGREGATION", StatusCode::BAD_REQUEST),
            (AppDataError::invalid_join("r"), "CORE.INVALID_JOIN", StatusCode::BAD_REQUEST),
            (AppDataError::connection_details_missing("url"), "CORE.DATA_CONNECTION_INCOMPLETE", StatusCode::NOT_FOUND),
            (AppDataError::connection_not_available("MySQL"), "CORE.CONNECTION_NOT_AVAILABLE", StatusCode::NOT_FOUND),
            (AppDataError::storage_object_id_exists("1", "leads"), "CORE.STORAGE_OBJECT_ID_EXISTS", StatusCode::CONFLICT),
            (AppDataError::row_id_required("_id"), "CORE.ROW_ID_REQUIRED", StatusCode::BAD_REQUEST),
            (AppDataError::field_cannot_be_null("name", "leads"), "CORE.FIELD_CANNOT_BE_NULL", StatusCode::BAD_REQUEST),
            (AppDataError::cannot_delete_with_restrict("leads"), "CORE.CANNOT_DELETE_STORAGE_WITH_RESTRICT", StatusCode::BAD_REQUEST),
            (AppDataError::forbidden_read_storage("leads"), "CORE.FORBIDDEN_READ_STORAGE", StatusCode::FORBIDDEN),
        ] {
            assert_eq!((e.code().map(|c| c.code.to_string()).as_deref(), e.status()), (Some(code), status), "{e}");
        }
        assert_eq!(AppDataError::connection_details_missing("url").code().unwrap().english().message, "The app's data connection is missing a setting: url.");
        assert_eq!(
            AppDataError::cannot_delete_with_restrict("leads").code().unwrap().english().message,
            "This row can't be deleted: other rows still refer to it (leads)."
        );
        assert!(AppDataError::Empty.code().is_none());
        assert_eq!(AppDataError::Empty.with_code("X").status(), StatusCode::FORBIDDEN);
        assert!(AppDataError::internal("x").param("a", 1).code().is_none());
    }

    /// MySQL's 1062 and Mongo's E11000 name the index; the value never reaches the text.
    #[test]
    fn duplicate_keys_are_recognised_on_both_backends() {
        // MySQL 8.0.19+ names the key `<table>.<index>`; older servers the index alone.
        let m8 = "Duplicate entry 'P1|2026-10-23T10:00|1' for key 'cxCallBooking.claimKey_unique'";
        assert_eq!(mysql_duplicate_key(Some(1062), Some("23000"), m8).as_deref(), Some("claimKey_unique"));
        assert_eq!(mysql_duplicate_key(Some(1062), Some("23000"), "Duplicate entry 'x' for key 'claimKey_unique'").as_deref(), Some("claimKey_unique"));
        assert_eq!(mysql_duplicate_key(Some(1062), Some("23000"), "Duplicate entry '7' for key 'PRIMARY'").as_deref(), Some("PRIMARY"));
        // A value holding the same words does not confuse the key.
        let tricky = "Duplicate entry 'a for key 'b' for key 't.uk_x'";
        assert_eq!(mysql_duplicate_key(Some(1062), None, tricky).as_deref(), Some("uk_x"));
        // Without the server's number, the state and the text decide.
        assert_eq!(mysql_duplicate_key(None, Some("23000"), m8).as_deref(), Some("claimKey_unique"));
        // Other integrity refusals share SQLSTATE 23000 and stay what they were.
        assert_eq!(mysql_duplicate_key(Some(1451), Some("23000"), "Cannot delete or update a parent row: a foreign key constraint fails"), None);
        assert_eq!(mysql_duplicate_key(Some(1048), Some("23000"), "Column 'name' cannot be null"), None);
        assert_eq!(mysql_duplicate_key(None, Some("42S02"), "Table 'x.y' doesn't exist"), None);
        assert_eq!(mysql_duplicate_key(Some(1062), Some("23000"), "Duplicate entry").as_deref(), Some(""));

        let e11000 = "E11000 duplicate key error collection: app_SYSTEM.cxCase index: claimKey_unique dup key: { claimKey: \"p|a@b.c\" }";
        assert_eq!(mongo_duplicate_key(11000, e11000).as_deref(), Some("claimKey_unique"));
        assert_eq!(mongo_duplicate_key(11001, "E11001 duplicate key on update index: email_1 dup key").as_deref(), Some("email_1"));
        assert_eq!(mongo_duplicate_key(12582, "duplicate key insert for unique index of capped collection").as_deref(), Some(""));
        assert_eq!(mongo_duplicate_key(26, "ns not found"), None);

        let e = AppDataError::duplicate_key("claimKey_unique");
        assert!(e.is_duplicate_key());
        assert_eq!(e.status(), StatusCode::CONFLICT);
        assert_eq!(e.message(), "Duplicate entry for key 'claimKey_unique'");
        assert_eq!(e.code().unwrap().english().message, "That is already taken (claimKey_unique).");
        let e = e.in_storage("cxCase");
        assert_eq!(e.message(), "Duplicate entry for key 'claimKey_unique' in storage cxCase");
        assert_eq!(
            e.code().unwrap().params,
            vec![("index".to_string(), "claimKey_unique".to_string()), ("storage".to_string(), "cxCase".to_string())]
        );
        assert_eq!(e.code().unwrap().english().action.as_deref(), Some("Choose another value, or change the row that already holds it in cxCase."));
        // Naming the storage twice keeps one mention; other errors pass through.
        assert_eq!(e.in_storage("cxCase").message(), "Duplicate entry for key 'claimKey_unique' in storage cxCase");
        assert!(!AppDataError::object_not_found("s", "1").in_storage("s").is_duplicate_key());
        let blank = AppDataError::duplicate_key(" ");
        assert_eq!(blank.code().unwrap().english().message, "That is already taken.");
        assert!(blank.code().unwrap().params.is_empty());
        // A plain driver error that is not a database error stays internal.
        assert!(matches!(AppDataError::from(sqlx::Error::RowNotFound), AppDataError::Internal(_)));
    }

    #[test]
    fn codes_change_and_reach_the_edge() {
        let e = AppDataError::forbidden_read_storage("leads").with_code("CORE.STORAGE_ROW_GONE").param("storage", "orders");
        assert_eq!(e.code().unwrap().code, "CORE.STORAGE_ROW_GONE");
        let AppError::Coded(c) = AppError::from(e) else { panic!("coded") };
        assert_eq!(c.status, Some(StatusCode::FORBIDDEN));
        assert_eq!(c.debug.as_deref(), Some("[forbidden_read_storage] Unable to read data from storage leads"));
        let plain = AppDataError::Message { status: StatusCode::CONFLICT, message: "m".into(), kind: ErrorKind::Generic, code: None };
        assert!(matches!(plain.with_code("CORE.ROW_NOT_FOUND"), AppDataError::Message { code: Some(_), .. }));
        let plain = AppDataError::Message { status: StatusCode::CONFLICT, message: "m".into(), kind: ErrorKind::Generic, code: None };
        assert!(matches!(AppError::from(plain), AppError::Message { .. }));
        assert!(matches!(AppError::from(AppDataError::Empty), AppError::Empty(StatusCode::FORBIDDEN)));
        assert!(matches!(AppError::from(AppDataError::internal("x")), AppError::Internal(_)));
        assert!(AppDataError::illegal_argument("page").message().starts_with("IllegalArgumentException"));
    }
}
