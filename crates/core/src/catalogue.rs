//! The core service's message catalogue (`messages/en.toml`, codes `CORE.*`), shared by the
//! libraries core runs (appdata, connections register the same file): every key of the Java
//! core bundle and every literal refusal, in plain words with a next step. Java's text stays the
//! parity reference and goes to `debugMessage`.

use std::sync::Once;

use platform::messages::JavaKey;

/// The English texts, compiled in.
pub const EN: &str = include_str!("../messages/en.toml");

/// The namespace of core's codes.
pub const NS: &str = "CORE";

/// Adds the catalogue to the process (once; every coded error calls it, so tests need no
/// setup). appdata and connections register the same file under the same name.
pub fn register() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| platform::messages::register("core", "en", EN));
}

/// Whether the caller is signed in: a refusal names the object only for a signed-in caller.
pub fn signed_in() -> bool {
    crate::context::authentication().is_authenticated()
}

/// core's `messages_en.properties`, every key, verbatim.
pub mod keys {
    use platform::messages::JavaKey;

    pub const OBJECT_NOT_FOUND: JavaKey = JavaKey::new("object_not_found", "$ with id $ not found");
    pub const OBJECT_NOT_FOUND_TO_UPDATE: JavaKey = JavaKey::new("object_not_found_to_update", "$ with id $ not found to update");
    pub const FORBIDDEN_CREATE: JavaKey = JavaKey::new("forbidden_create", "Cannot create $ for the selected client");
    pub const FORBIDDEN_PERMISSION: JavaKey = JavaKey::new("forbidden_permission", "Permission/Role $ is required to use this operation");
    pub const UNABLE_TO_DELETE: JavaKey = JavaKey::new("unable_to_delete", "Unable to delete $ with id $");
    pub const OBJECT_NOT_UPDATABLE: JavaKey = JavaKey::new("object_not_updatable", "Cannot update this object");
    pub const USER_CREDENTIALS_MISMATCHED: JavaKey = JavaKey::new("user_credentials_mismatched", "User credentials mismatch");
    pub const UNKNOWN_ERROR: JavaKey = JavaKey::new("unknown_error", "Internal Server Error (Unknown)");
    pub const UNKNOWN_ERROR_WITH_ID: JavaKey = JavaKey::new("unknown_error_with_id", "Please try again. A server error - $");
    pub const UNKONWN_ERROR_INSERT: JavaKey = JavaKey::new("unkonwn_error_insert", "Unknown error occurred while inserting into db");
    pub const VALUEOF_METHOD_NOT_FOUND: JavaKey = JavaKey::new("valueof_method_not_found", "Could not find the valueOf method");
    pub const UNABLE_TO_CONVERT: JavaKey = JavaKey::new("unable_to_convert", "Unable to convert $ to $");
    pub const TOKEN_EXPIRED: JavaKey = JavaKey::new("token_expired", "Authorization token expired. Please re-login.");
    pub const UNKNOWN_TOKEN: JavaKey = JavaKey::new("unknown_token", "Unknown token");
    pub const ALREADY_EXISTS: JavaKey = JavaKey::new("already_exists", "$ $ already exists");
    pub const VERSION_MISMATCH: JavaKey = JavaKey::new("version_mismatch", "Please reload to get the new version before making changes.");
    pub const CANNOT_CHANGE_PREF: JavaKey = JavaKey::new("cannot_change_pref", "Cannot change preference.");
    pub const UNABLE_TO_CREATE_OBJECT: JavaKey = JavaKey::new("unable_to_create_object", "Unable to create object $");
    pub const APPLICATION_NAME_REQUIRED: JavaKey = JavaKey::new("application_name_required", "Application name required for searching");
    pub const FORBIDDEN_APP_ACCESS: JavaKey = JavaKey::new("forbidden_app_access", "Forbidden access to the application with code $");
    pub const STORAGE_NOT_FOUND: JavaKey = JavaKey::new("storage_not_found", "Storage not found");
    pub const CONNECTION_DETAILS_MISSING: JavaKey = JavaKey::new("connection_details_missing", "Connection details missing $");
    pub const FORBIDDEN_CREATE_STORAGE: JavaKey = JavaKey::new("forbidden_create_storage", "Unable to add data to storage $");
    pub const FORBIDDEN_UPDATE_STORAGE: JavaKey = JavaKey::new("forbidden_update_storage", "Unable to update data in storage $");
    pub const FORBIDDEN_READ_STORAGE: JavaKey = JavaKey::new("forbidden_read_storage", "Unable to read data from storage $");
    pub const FORBIDDEN_DELETE_STORAGE: JavaKey = JavaKey::new("forbidden_delete_storage", "Unable to delete data from storage $");
    pub const SCHEMA_VALIDATION_ERROR: JavaKey = JavaKey::new("schema_validation_error", "Validation Error");
    pub const WORKFLOW_TRIGGER_MISSING: JavaKey = JavaKey::new("workflow_trigger_missing", "Workflow trigger is missing");
    pub const NAME_MISSING: JavaKey = JavaKey::new("name_missing", "Namespace or name missing");
    pub const NAME_CHANGE: JavaKey = JavaKey::new("name_change", "Namespace or name cannot be changed");
    pub const FORBIDDEN_EXECUTION: JavaKey = JavaKey::new("forbidden_execution", "Authorization $ is required to execute the function");
    pub const INTERNAL_ERROR_RECURSION: JavaKey = JavaKey::new("internal_error_recursion", "Some error occurred while reading $ resource as it is going recursive");
    pub const TEMPLATE_GENERATION_ERROR: JavaKey = JavaKey::new("template_generation_error", "For the selected $ format template cannot be generated");
    pub const NOT_ABLE_TO_OPEN_FILE_ERROR: JavaKey = JavaKey::new("not_able_to_open_file_error", "Not able to open file for writing");
    pub const NOT_ABLE_TO_READ_FILE_FORMAT: JavaKey = JavaKey::new("not_able_to_read_file_format", "Not able to read file with given $ format");
    pub const FILE_FORMAT_INVALID: JavaKey = JavaKey::new("file_format_invalid", "The given file format $ is invalid.");
    pub const BULK_UPLOAD_MESSAGE: JavaKey = JavaKey::new("bulk_upload_message", "This record was uploaded from bulk service from the file type $");
    pub const NOT_ABLE_TO_READ_FROM_FILE: JavaKey = JavaKey::new("not_able_to_read_from_file", "Error while reading data from file");
    pub const CANNOT_BE_UPDATED: JavaKey = JavaKey::new("cannot_be_updated", "Cannot update this object");
    pub const TEMPLATE_DETAILS_MISSING: JavaKey = JavaKey::new("template_details_missing", "Template details missing : $");
    pub const TEMPLATE_CONVERT_ERROR: JavaKey = JavaKey::new("template_convert_error", "Unable to convert template $ to $");
    pub const FS_STREAM_ERROR: JavaKey = JavaKey::new("fs_stream_error", "Unable to create url reading fs stream.");
    pub const UNABLE_TO_FETCH_INTERNAL_RESOURCE: JavaKey = JavaKey::new("unable_to_fetch_internal_resource", "Unable to fetch internal resource.");
    pub const UNABLE_TO_FETCH_EXTERNAL_RESOURCE: JavaKey = JavaKey::new("unable_to_fetch_external_resource", "Unable to fetch external resource.");
    pub const STORAGE_IS_APP_LEVEL: JavaKey = JavaKey::new("storage_is_app_level", "Cannot change a storage which is app level.");
    pub const NOT_ABLE_TO_DOWNLOAD_DATA: JavaKey = JavaKey::new("not_able_to_download_data", "Not able to download data from the selected storage");
    pub const ONLY_SCHEMA_OBJECT_TYPE: JavaKey = JavaKey::new("only_schema_object_type", "Only schema of type object is required to access the storage");
    pub const NO_STORAGE_FOUND_WITH_NAME: JavaKey = JavaKey::new("no_storage_found_with_name", "No storage found with name $");
    pub const STORAGE_SCHEMA_ALWAYS_OBJECT: JavaKey = JavaKey::new("storage_schema_always_object", "Storage schema should always be of type Object");
    pub const STORAGE_SCHEMA_FIELD_ALREADY_EXISTS: JavaKey = JavaKey::new("storage_schema_field_already_exists", "Storage schema field $ already exists");
    pub const INVALID_COLUMN_DEFINITION: JavaKey = JavaKey::new("invalid_column_definition", "Invalid column definition. $");
    pub const INVALID_STORAGE_SCHEMA: JavaKey = JavaKey::new("invalid_storage_schema", "The storage schema is not valid. $");
    pub const STORAGE_RELATION_DATA_TYPE_MISMATCH: JavaKey = JavaKey::new("storage_relation_data_type_mismatch", "Storage relation $ data type has to be a string or object, given $");
    pub const STORAGE_RELATION_OBJECT_CREATION_ERROR: JavaKey = JavaKey::new("storage_relation_object_creation_error", "Error while creating relation object");
    pub const INVALID_RELATION_DATA: JavaKey = JavaKey::new("invalid_relation_data", "Invalid relation data in the field $ with data $");
    pub const CANNOT_DELETE_STORAGE_WITH_RESTRICT: JavaKey = JavaKey::new("cannot_delete_storage_with_restrict", "Following objects exists and cannot be deleted: $");
    pub const STORAGE_DELETE_ALL_NOT_CONFIRMED: JavaKey = JavaKey::new("storage_delete_all_not_confirmed", "Deleting every row of $ needs deleteAll=true. If you meant to delete one row, the row id is missing from the URL.");
    pub const STORAGE_OBJECT_ID_EXISTS: JavaKey = JavaKey::new("storage_object_id_exists", "A row with _id $ already exists in $. Remove the _id from the data to store it as a new row, or update the existing row instead.");
    pub const FORBIDDEN_EXPLICIT_DRAFT_SURFACE: JavaKey = JavaKey::new("forbidden_explicit_draft_surface", "Naming the data surface needs write access to the application $. Without it, a data call reads and writes whichever surface its hostname resolves to.");
    pub const DRAFT_COPY_SOURCE_EMPTY: JavaKey = JavaKey::new("draft_copy_source_empty", "Storage $ has no live rows to copy into the draft surface.");
    pub const STORAGE_ONLY_THRU_KIRUN: JavaKey = JavaKey::new("storage_only_thru_kirun", "Storage $ is marked onlyThruKIRun, so its rows are reachable only through a KIRun function or from a builder application.");
    pub const TRANSPORT_ERROR: JavaKey = JavaKey::new("transport_error", "Error while $ transport : $");
    pub const CONNECTION_NOT_AVAILABLE: JavaKey = JavaKey::new("connection_not_available", "Connection $ not available");
    pub const UNABLE_TO_EXECUTE: JavaKey = JavaKey::new("unable_to_execute", "Unable to execute function $.$ with parameters $");
    pub const UNABLE_AI_CONNECTION: JavaKey = JavaKey::new("unable_ai_connection", "Unable to connect to AI connection $");
    pub const EMPTY_AI_RESPONSE: JavaKey = JavaKey::new("empty_ai_response", "Empty response received");
    pub const EMPTY_FUNCTION_RESPONSE: JavaKey = JavaKey::new("empty_function_response", "The function $ returned an empty response.");
    pub const FORBIDDEN_FORK_NOT_OVERRIDABLE: JavaKey = JavaKey::new("forbidden_fork_not_overridable", "$ $ cannot be overridden, so it cannot be edited by a client that does not own it");
    pub const INVALID_AGGREGATION: JavaKey = JavaKey::new("invalid_aggregation", "Invalid aggregation request: $");
    pub const INVALID_JOIN: JavaKey = JavaKey::new("invalid_join", "Invalid join request: $");
    pub const FORBIDDEN_CLIENT_CODE: JavaKey = JavaKey::new("forbidden_client_code", "$ is not a client you can act for.");
    pub const UNSUPPORTED_CONDITION: JavaKey = JavaKey::new("unsupported_condition", "$ is not a condition this data filter supports.");
    pub const UNSUPPORTED_ON_BACKEND: JavaKey = JavaKey::new("unsupported_on_backend", "$ is not supported on the $ storage backend yet.");
    pub const ROW_ID_REQUIRED: JavaKey = JavaKey::new("row_id_required", "$ is required to update a row.");
    pub const FIELD_CANNOT_BE_NULL: JavaKey = JavaKey::new("field_cannot_be_null", "$ cannot be null in $: the field is required.");
    pub const MAIL_SEND_ERROR: JavaKey = JavaKey::new("mail_send_error", "Unable to send the email: $");
    pub const NOT_ABLE_TO_CREATE_TOKEN: JavaKey = JavaKey::new("not_able_to_create_token", "Not able to create a token for the connection $: $");
    pub const CANNOT_DELETE_TOKEN_WITH_CLIENT_CODE: JavaKey = JavaKey::new("cannot_delete_token_with_client_code", "No active token found to revoke for connection $");
    pub const INVALID_USER_FOR_CLIENT: JavaKey = JavaKey::new("invalid_user_for_client", "Invalid user $ for the given client $.");

    /// Every key, in the bundle's order.
    pub const ALL: [JavaKey; 79] = [
        OBJECT_NOT_FOUND,
        OBJECT_NOT_FOUND_TO_UPDATE,
        FORBIDDEN_CREATE,
        FORBIDDEN_PERMISSION,
        UNABLE_TO_DELETE,
        OBJECT_NOT_UPDATABLE,
        USER_CREDENTIALS_MISMATCHED,
        UNKNOWN_ERROR,
        UNKNOWN_ERROR_WITH_ID,
        UNKONWN_ERROR_INSERT,
        VALUEOF_METHOD_NOT_FOUND,
        UNABLE_TO_CONVERT,
        TOKEN_EXPIRED,
        UNKNOWN_TOKEN,
        ALREADY_EXISTS,
        VERSION_MISMATCH,
        CANNOT_CHANGE_PREF,
        UNABLE_TO_CREATE_OBJECT,
        APPLICATION_NAME_REQUIRED,
        FORBIDDEN_APP_ACCESS,
        STORAGE_NOT_FOUND,
        CONNECTION_DETAILS_MISSING,
        FORBIDDEN_CREATE_STORAGE,
        FORBIDDEN_UPDATE_STORAGE,
        FORBIDDEN_READ_STORAGE,
        FORBIDDEN_DELETE_STORAGE,
        SCHEMA_VALIDATION_ERROR,
        WORKFLOW_TRIGGER_MISSING,
        NAME_MISSING,
        NAME_CHANGE,
        FORBIDDEN_EXECUTION,
        INTERNAL_ERROR_RECURSION,
        TEMPLATE_GENERATION_ERROR,
        NOT_ABLE_TO_OPEN_FILE_ERROR,
        NOT_ABLE_TO_READ_FILE_FORMAT,
        FILE_FORMAT_INVALID,
        BULK_UPLOAD_MESSAGE,
        NOT_ABLE_TO_READ_FROM_FILE,
        CANNOT_BE_UPDATED,
        TEMPLATE_DETAILS_MISSING,
        TEMPLATE_CONVERT_ERROR,
        FS_STREAM_ERROR,
        UNABLE_TO_FETCH_INTERNAL_RESOURCE,
        UNABLE_TO_FETCH_EXTERNAL_RESOURCE,
        STORAGE_IS_APP_LEVEL,
        NOT_ABLE_TO_DOWNLOAD_DATA,
        ONLY_SCHEMA_OBJECT_TYPE,
        NO_STORAGE_FOUND_WITH_NAME,
        STORAGE_SCHEMA_ALWAYS_OBJECT,
        STORAGE_SCHEMA_FIELD_ALREADY_EXISTS,
        INVALID_COLUMN_DEFINITION,
        INVALID_STORAGE_SCHEMA,
        STORAGE_RELATION_DATA_TYPE_MISMATCH,
        STORAGE_RELATION_OBJECT_CREATION_ERROR,
        INVALID_RELATION_DATA,
        CANNOT_DELETE_STORAGE_WITH_RESTRICT,
        STORAGE_DELETE_ALL_NOT_CONFIRMED,
        STORAGE_OBJECT_ID_EXISTS,
        FORBIDDEN_EXPLICIT_DRAFT_SURFACE,
        DRAFT_COPY_SOURCE_EMPTY,
        STORAGE_ONLY_THRU_KIRUN,
        TRANSPORT_ERROR,
        CONNECTION_NOT_AVAILABLE,
        UNABLE_TO_EXECUTE,
        UNABLE_AI_CONNECTION,
        EMPTY_AI_RESPONSE,
        EMPTY_FUNCTION_RESPONSE,
        FORBIDDEN_FORK_NOT_OVERRIDABLE,
        INVALID_AGGREGATION,
        INVALID_JOIN,
        FORBIDDEN_CLIENT_CODE,
        UNSUPPORTED_CONDITION,
        UNSUPPORTED_ON_BACKEND,
        ROW_ID_REQUIRED,
        FIELD_CANNOT_BE_NULL,
        MAIL_SEND_ERROR,
        NOT_ABLE_TO_CREATE_TOKEN,
        CANNOT_DELETE_TOKEN_WITH_CLIENT_CODE,
        INVALID_USER_FOR_CLIENT,
    ];
}

/// The code standing for a Java key (`object_not_found` reads `CORE.OBJECT_NOT_FOUND`).
pub fn code_for_key(key: &JavaKey) -> String {
    register();
    platform::messages::global().code_for_java(NS, key.key).map(str::to_string).unwrap_or_else(|| format!("{NS}.{}", key.key.to_ascii_uppercase()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use platform::messages::Catalogue;

    fn catalogue() -> Catalogue {
        let mut c = Catalogue::default();
        c.add_builtin("platform", "en", platform::messages::PLATFORM_EN).unwrap();
        c.add_builtin("core", "en", EN).unwrap();
        c
    }

    #[test]
    fn catalogue_is_complete() {
        platform::messages::check_catalogue(&catalogue(), NS);
    }

    /// Every key of the Java bundle has its own code, named after it; the copy here is Java's
    /// (checked against the bundle when the Java tree is next to this one).
    #[test]
    fn every_java_key_has_a_code() {
        let c = catalogue();
        for k in keys::ALL {
            let code = format!("CORE.{}", k.key.to_ascii_uppercase());
            assert_eq!(c.code_for_java(NS, k.key), Some(code.as_str()), "{}", k.key);
            assert_eq!(code_for_key(&k), code);
        }
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../nocode-saas/core/src/main/resources/messages_en.properties");
        if let Ok(bundle) = std::fs::read_to_string(path) {
            let java: Vec<(&str, &str)> = bundle.lines().filter_map(|l| l.split_once('=')).collect();
            assert_eq!(java.len(), keys::ALL.len());
            for (k, (jk, jv)) in keys::ALL.iter().zip(java) {
                assert_eq!((k.key, k.template), (jk, jv));
            }
        }
        assert_eq!(code_for_key(&JavaKey::new("no_such_key", "x")), "CORE.NO_SUCH_KEY");
    }

    /// Each code reads well with all its values and with none.
    #[test]
    fn texts_render() {
        let c = catalogue();
        let en = vec!["en".to_string()];
        let p = |pairs: &[(&str, &str)]| pairs.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect::<Vec<_>>();
        let r = c.render("CORE.FUNCTION_STEP_FAILED", &p(&[("step", "read"), ("stepFunction", "CoreServices.Storage.Read"), ("function", "App.list"), ("reason", "no such row")]), &en, "E");
        assert_eq!(r.message, "Step read (CoreServices.Storage.Read) in App.list failed: no such row.");
        let r = c.render("CORE.FORBIDDEN_READ_STORAGE", &p(&[("storage", "leads")]), &en, "E");
        assert_eq!(r.message, "You can't view the data in leads: your account does not have the permission this storage needs for reading.");
        assert_eq!(c.render("CORE.FORBIDDEN_READ_STORAGE", &[], &en, "E").action.as_deref(), Some("Sign in and try again."));
        let r = c.render("CORE.ROW_NOT_FOUND", &p(&[("storage", "leads"), ("id", "65f")]), &en, "E");
        assert_eq!(r.message, "We couldn't find the row 65f in leads.");
        let r = c.render("CORE.KEY_TOO_SHORT", &p(&[("use", "signing"), ("bits", "128"), ("algorithm", "HS256")]), &en, "E");
        assert_eq!(r.message, "The signing key is too short for the HS256 algorithm: it has 128 bits.");
        for code in c.codes().into_iter().filter(|c| c.starts_with("CORE.")) {
            let r = c.render(code, &[], &en, "E");
            assert!(!r.message.contains('{') && !r.message.contains("  ") && !r.message.is_empty(), "{code}: {}", r.message);
            assert!(!r.message.contains('\u{2014}') && !r.message.contains('\u{2013}'), "{code}: no dashes");
        }
    }
}
