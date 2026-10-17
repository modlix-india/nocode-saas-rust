//! The error messages of `AbstractMongoMessageResourceService`, as each service's
//! `messages_en.properties` words them, and the coded errors that say them plainly.
//!
//! A refusal answers with a code from the message catalogue: `DEF.*` ([`crate::catalogue`]) for
//! the keys the ui and core bundles share, then a unit's own namespace ([`Messages::add_namespace`])
//! for its own keys. The body carries the plain text and the next step; `debugMessage` carries
//! Java's text as `[key] text`, which stays the parity reference. ui and core word some keys
//! differently (trailing spaces in ui, a full stop in core's `version_mismatch`), and callers
//! that record failures compare these strings ([`error_message`]), so each service keeps its own
//! table. A key no namespace has a code for answers Java's text as it is.

use std::collections::HashMap;

use axum::http::StatusCode;
use platform::error::{format_message, AppError, Coded};
use platform::messages::render::name_positional;
use platform::security::ContextAuthentication;

pub const OBJECT_NOT_FOUND: &str = "object_not_found";
pub const OBJECT_NOT_FOUND_TO_UPDATE: &str = "object_not_found_to_update";
pub const FORBIDDEN_CREATE: &str = "forbidden_create";
pub const FORBIDDEN_PERMISSION: &str = "forbidden_permission";
pub const UNABLE_TO_DELETE: &str = "unable_to_delete";
pub const OBJECT_NOT_UPDATABLE: &str = "object_not_updatable";
pub const UNKNOWN_ERROR: &str = "unknown_error";
pub const ALREADY_EXISTS: &str = "already_exists";
pub const VERSION_MISMATCH: &str = "version_mismatch";
pub const FORBIDDEN_FORK_NOT_OVERRIDABLE: &str = "forbidden_fork_not_overridable";
pub const UNABLE_TO_CREATE_OBJECT: &str = "unable_to_create_object";
pub const FORBIDDEN_APP_ACCESS: &str = "forbidden_app_access";
pub const NAME_MISSING: &str = "name_missing";
pub const NAME_CHANGE: &str = "name_change";
pub const CANNOT_BE_UPDATED: &str = "cannot_be_updated";
pub const TRANSPORT_ERROR: &str = "transport_error";
pub const FORBIDDEN_EXECUTION: &str = "forbidden_execution";

/// The code an anonymous caller gets instead of a refusal that names what it asked for.
pub const SIGN_IN_REQUIRED: &str = "DEF.SIGN_IN_REQUIRED";

/// One service's message templates (`$` placeholders, KIRun formatting), and the catalogue
/// namespaces its keys are coded in.
#[derive(Debug, Clone)]
pub struct Messages {
    templates: HashMap<String, String>,
    namespaces: Vec<&'static str>,
}

/// ui's bundle for the keys it shares with core: commons-mongo's message service and the
/// commons one under it.
const UI: &[(&str, &str)] = &[
    (OBJECT_NOT_FOUND, "$ with id $ not found"),
    (OBJECT_NOT_FOUND_TO_UPDATE, "$ with id $ not found to update"),
    (FORBIDDEN_CREATE, "Cannot create $ for the selected client"),
    (FORBIDDEN_PERMISSION, "Permission/Role $ is required to use this operation "),
    (UNABLE_TO_DELETE, "Unable to delete $ with id $ "),
    (OBJECT_NOT_UPDATABLE, "Cannot update this object"),
    ("user_credentials_mismatched", "User credentials mismatch"),
    (UNKNOWN_ERROR, "Internal Server Error (Unknown)"),
    ("unknown_error_with_id", "Please try again. A server error - $ "),
    ("unkonwn_error_insert", "Unknown error occurred while inserting into db"),
    ("valueof_method_not_found", "Could not find the valueOf method"),
    ("unable_to_convert", "Unable to convert $ to $"),
    ("token_expired", "Authorization token expired, Please re-login"),
    ("unknown_token", "Unknown token"),
    (ALREADY_EXISTS, "$ $ already exists"),
    (VERSION_MISMATCH, "Please reload to get the new version before making changes"),
    ("cannot_change_pref", "Cannot change preference."),
    (UNABLE_TO_CREATE_OBJECT, "Unable to create object $"),
    ("application_name_required", "Application name required for searching"),
    (FORBIDDEN_APP_ACCESS, "Forbidden access to the application with code $"),
    (NAME_MISSING, "Namespace or name missing"),
    (NAME_CHANGE, "Namespace or name cannot be changed"),
    (FORBIDDEN_EXECUTION, "Authorization $ is required"),
    ("internal_error_recursion", "Some error occurred while reading $ resource as it is going recursive"),
    (CANNOT_BE_UPDATED, "Cannot update this object"),
    (TRANSPORT_ERROR, "Error while $ transport : $"),
    (FORBIDDEN_FORK_NOT_OVERRIDABLE, "$ $ cannot be overridden, so it cannot be edited by a client that does not own it"),
];

impl Messages {
    /// ui's `messages_en.properties`.
    pub fn ui() -> Self {
        Self::from_pairs(UI)
    }

    /// core's: no trailing spaces, a full stop on `version_mismatch`, its own `token_expired`
    /// and `forbidden_execution`.
    pub fn core() -> Self {
        let mut m = Self::from_pairs(UI);
        m.set(FORBIDDEN_PERMISSION, "Permission/Role $ is required to use this operation");
        m.set(UNABLE_TO_DELETE, "Unable to delete $ with id $");
        m.set(VERSION_MISMATCH, "Please reload to get the new version before making changes.");
        m.set("unknown_error_with_id", "Please try again. A server error - $");
        m.set("token_expired", "Authorization token expired. Please re-login.");
        m.set(FORBIDDEN_EXECUTION, "Authorization $ is required to execute the function");
        m
    }

    pub fn from_pairs(pairs: &[(&str, &str)]) -> Self {
        Self { templates: pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(), namespaces: vec![crate::catalogue::NS] }
    }

    /// Adds or replaces a template (a service's own messages).
    pub fn set(&mut self, id: &str, template: &str) {
        self.templates.insert(id.to_string(), template.to_string());
    }

    /// Codes a unit's own keys in its own namespace (`UI`, `CORE`), tried after `DEF`. The unit
    /// registers that catalogue itself.
    pub fn add_namespace(&mut self, ns: &'static str) {
        if !self.namespaces.contains(&ns) {
            self.namespaces.push(ns);
        }
    }

    /// Codes the keys in exactly these namespaces, in this order (a unit's own messages that are
    /// not definition errors).
    pub fn set_namespaces(&mut self, namespaces: &[&'static str]) {
        self.namespaces = namespaces.to_vec();
    }

    /// The keys this bundle has, sorted.
    pub fn keys(&self) -> Vec<String> {
        let mut k: Vec<String> = self.templates.keys().cloned().collect();
        k.sort();
        k
    }

    /// The template, or `unknown_error`'s for an id the bundle lacks, as Java's `getMessage`.
    pub fn template(&self, id: &str) -> &str {
        self.templates
            .get(id)
            .or_else(|| self.templates.get(UNKNOWN_ERROR))
            .map(String::as_str)
            .unwrap_or("Internal Server Error (Unknown)")
    }

    /// Java's text for `id` with `params`.
    pub fn java_text(&self, id: &str, params: &[&str]) -> String {
        format_message(self.template(id), params)
    }

    /// The code standing for `id`: the first namespace that has one.
    pub fn code_for(&self, id: &str) -> Option<String> {
        crate::catalogue::register();
        let cat = platform::messages::global();
        self.namespaces.iter().find_map(|ns| cat.code_for_java(ns, id).map(str::to_string))
    }

    /// `throwMessage(status, id, params...)`: the coded error for the key, or Java's text when
    /// no namespace codes it.
    pub fn error(&self, status: StatusCode, id: &str, params: &[&str]) -> AppError {
        match self.code_for(id) {
            Some(code) => self.error_as(&code, status, id, params),
            None => AppError::msg(status, self.template(id), params),
        }
    }

    /// The same Java text said by a more specific code. Java's values are named by the code's
    /// params in order; a missing value (Java's `null`) is left out.
    pub fn error_as(&self, code: &str, status: StatusCode, id: &str, params: &[&str]) -> AppError {
        crate::catalogue::register();
        let values: Vec<&str> = params.iter().map(|p| if *p == "null" { "" } else { *p }).collect();
        let named = name_positional(&platform::messages::global(), code, &values);
        let mut c = Coded::new(code.to_string());
        c.params = named.into_iter().filter(|(_, v)| !v.trim().is_empty()).collect();
        c.status(status).debug(format!("[{id}] {}", self.java_text(id, params))).into()
    }

    /// A refusal that names what was refused: an anonymous caller is only asked to sign in
    /// (same status, same Java text in `debugMessage`).
    pub fn refusal(&self, ca: &ContextAuthentication, status: StatusCode, id: &str, params: &[&str]) -> AppError {
        if ca.authenticated {
            self.error(status, id, params)
        } else {
            self.error_as(SIGN_IN_REQUIRED, status, id, params)
        }
    }
}

/// A refusal Java raises with a literal text (no bundle key), said by `code`; the text goes to
/// `debugMessage`.
pub fn literal(code: &'static str, status: StatusCode, java_text: impl Into<String>) -> Coded {
    crate::catalogue::register();
    Coded::new(code).status(status).debug(java_text)
}

/// Sets a value of a coded error's message (a name Java does not pass); other errors as they are.
pub fn with_param(e: AppError, name: &str, value: impl ToString) -> AppError {
    match e {
        AppError::Coded(c) => AppError::Coded(Box::new(c.param(name, value))),
        other => other,
    }
}

/// The message of an error as Java's `Throwable.getMessage()` gives it to a caller that
/// reports failures (publishAll's `error`): Java's text, also for a coded error (its
/// `debugMessage`, without the key).
pub fn error_message(e: &AppError) -> String {
    match e {
        AppError::Message { message, .. } => message.clone(),
        AppError::Empty(s) => s.to_string(),
        AppError::Internal(e) => e.to_string(),
        AppError::Coded(c) => match c.debug.as_deref() {
            Some(d) => java_part(d).unwrap_or(d).to_string(),
            None => e.english_message(),
        },
    }
}

/// `[key] text` is Java's text under its key.
fn java_part(debug: &str) -> Option<&str> {
    let rest = debug.strip_prefix('[')?;
    rest.find("] ").map(|i| &rest[i + 2..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;

    async fn body(e: AppError) -> serde_json::Value {
        let r = e.into_response();
        serde_json::from_slice(&axum::body::to_bytes(r.into_body(), 100_000).await.unwrap()).unwrap()
    }

    #[test]
    fn ui_and_core_differ_where_the_bundles_do() {
        let ui = Messages::ui();
        let core = Messages::core();
        assert_eq!(ui.template(FORBIDDEN_PERMISSION), "Permission/Role $ is required to use this operation ");
        assert_eq!(core.template(FORBIDDEN_PERMISSION), "Permission/Role $ is required to use this operation");
        assert!(core.template(VERSION_MISMATCH).ends_with('.'));
        assert_eq!(ui.template("nope"), "Internal Server Error (Unknown)");
        let e = ui.error(StatusCode::NOT_FOUND, OBJECT_NOT_FOUND, &["Page", "x1"]);
        assert_eq!(e.status(), StatusCode::NOT_FOUND);
        assert_eq!(error_message(&e), "Page with id x1 not found");
        assert_eq!(error_message(&AppError::Empty(StatusCode::FORBIDDEN)), "403 Forbidden");
        assert_eq!(error_message(&AppError::Internal(anyhow::anyhow!("boom"))), "boom");
        assert_eq!(error_message(&AppError::new(StatusCode::CONFLICT, "Taken")), "Taken");
        let empty = Messages::from_pairs(&[]);
        assert_eq!(empty.template("x"), "Internal Server Error (Unknown)");
        assert_eq!(ui.keys().len(), 27);
    }

    #[tokio::test]
    async fn refusals_are_coded_with_javas_text_for_support() {
        let ui = Messages::ui();
        let v = body(ui.error(StatusCode::NOT_FOUND, OBJECT_NOT_FOUND, &["URIPath", "x1"])).await;
        assert_eq!(v["code"], "DEF.OBJECT_NOT_FOUND");
        assert_eq!(v["message"], "We couldn't find the URI path with id x1.");
        assert_eq!(v["debugMessage"], "[object_not_found] URIPath with id x1 not found");
        assert_eq!(v["params"], serde_json::json!({"what": "URI path", "id": "x1"}));

        // Java's null is left out of the message, kept in Java's text.
        let v = body(ui.error(StatusCode::FORBIDDEN, FORBIDDEN_FORK_NOT_OVERRIDABLE, &["Page", "null"])).await;
        assert_eq!(v["message"], "This item can't be customised, so only the organisation that owns it can edit it.");
        assert_eq!(v["debugMessage"], "[forbidden_fork_not_overridable] Page null cannot be overridden, so it cannot be edited by a client that does not own it");

        // A more specific code keeps the key's Java text.
        let e = ui.error_as("DEF.DRAFT_NOT_SUPPORTED", StatusCode::METHOD_NOT_ALLOWED, OBJECT_NOT_FOUND, &["Draft", "Transport"]);
        assert_eq!(error_message(&e), "Draft with id Transport not found");
        let v = body(e).await;
        assert_eq!((v["code"].as_str(), v["message"].as_str()), (Some("DEF.DRAFT_NOT_SUPPORTED"), Some("Drafts are not available for this kind of item (transport).")));

        // A key nothing codes keeps Java's text as the message.
        let mut m = Messages::ui();
        m.set("own_key", "Own $");
        assert_eq!(m.code_for("own_key"), None);
        let v = body(m.error(StatusCode::BAD_REQUEST, "own_key", &["x"])).await;
        assert_eq!(v["message"], "Own x");
        assert!(v.get("code").is_none());

        // A unit's namespace codes its own keys after DEF.
        platform::messages::register("overridable-test", "en", "[ZDEFT.OWN_KEY]\nstatus = 400\ntext = \"Own.\"\njava = \"own_key\"\n[ZDEFT.OBJECT_NOT_FOUND]\nstatus = 404\ntext = \"No.\"\njava = \"object_not_found\"");
        m.add_namespace("ZDEFT");
        m.add_namespace("ZDEFT");
        assert_eq!(m.code_for("own_key").as_deref(), Some("ZDEFT.OWN_KEY"));
        assert_eq!(m.code_for(OBJECT_NOT_FOUND).as_deref(), Some("DEF.OBJECT_NOT_FOUND"), "DEF first");
        m.set_namespaces(&["ZDEFT"]);
        assert_eq!(m.code_for(OBJECT_NOT_FOUND).as_deref(), Some("ZDEFT.OBJECT_NOT_FOUND"));
    }

    #[tokio::test]
    async fn anonymous_callers_are_asked_to_sign_in() {
        let ui = Messages::ui();
        let anon = ContextAuthentication::default();
        let v = body(ui.refusal(&anon, StatusCode::FORBIDDEN, FORBIDDEN_PERMISSION, &["Page"])).await;
        assert_eq!((v["code"].as_str(), v["message"].as_str()), (Some("DEF.SIGN_IN_REQUIRED"), Some("Please sign in to continue.")));
        assert_eq!(v["debugMessage"], "[forbidden_permission] Permission/Role Page is required to use this operation ");
        let signed_in = ContextAuthentication { authenticated: true, ..Default::default() };
        let v = body(ui.refusal(&signed_in, StatusCode::FORBIDDEN, FORBIDDEN_PERMISSION, &["Page"])).await;
        assert_eq!(v["code"], "DEF.FORBIDDEN_PERMISSION");
        assert_eq!(v["message"], "You don't have permission to do this with the page.");
    }

    #[tokio::test]
    async fn values_can_be_added() {
        let ui = Messages::ui();
        let v = body(with_param(ui.error(StatusCode::NOT_MODIFIED, CANNOT_BE_UPDATED, &[]), "what", "Transport")).await;
        assert_eq!(v["message"], "This transport can't be changed once it is made.");
        assert!(matches!(with_param(AppError::Empty(StatusCode::OK), "a", 1), AppError::Empty(_)));
        assert_eq!(java_part("no key"), None);
        let c: AppError = literal("DEF.CONDITION_INVALID", StatusCode::BAD_REQUEST, "Invalid condition").into();
        assert_eq!(error_message(&c), "Invalid condition");
        assert_eq!(c.status(), StatusCode::BAD_REQUEST);
        let c: AppError = Coded::new("DEF.NAME_MISSING").into();
        assert_eq!(error_message(&c), "The name or the namespace is missing.");
    }
}
