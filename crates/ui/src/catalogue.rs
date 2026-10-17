//! The ui service's message catalogue (`messages/en.toml`, codes `UI.*`): every key of the Java
//! ui bundle and every other refusal the ui units make, in plain words with a next step. Java's
//! text stays the reference for parity and goes to `debugMessage` (`[key] text`).
//!
//! The keys ui shares with core belong to the definition library: the editor's [`messages`]
//! codes them `DEF.*` first and its own keys `UI.*`; the runtime units' own refusals
//! ([`error`]) are `UI.*` only.

use std::sync::{LazyLock, Once};

use axum::http::StatusCode;
use overridable::write::messages::Messages;
use platform::error::{AppError, Coded};

/// The English texts, compiled in.
pub const EN: &str = include_str!("../messages/en.toml");

/// The namespace of this service's codes.
pub const NS: &str = "UI";

pub const APP_NAME_MISMATCH: &str = "app_name_mismatch";
pub const URI_STRING_NULL: &str = "uri_path_string_null";
pub const URI_PATTERN_PATH_MISMATCH: &str = "uri_pattern_path_mismatch";
pub const URI_INVALID_TYPE: &str = "uri_invalid_type";
pub const URI_INVALID_METHOD: &str = "uri_invalid_method";
pub const MULTIPLE_GEN_STATUS: &str = "multiple_gen_status";
pub const INTERNAL_ONLY: &str = "internal_only";
pub const MOBILE_APP_BAD_REQUEST: &str = "mobile_app_bad_request";
pub const MOBILE_APP_UNABLE_TO_GEN_KEYSTORE: &str = "mobile_app_unable_to_gen_keystore";
pub const ANALYTICS_NOT_CONFIGURED: &str = "analytics_not_configured";
pub const ANALYTICS_CODES_REQUIRED: &str = "analytics_codes_required";
pub const ANALYTICS_LOGIN_REQUIRED: &str = "analytics_login_required";
pub const ANALYTICS_NO_WRITE_ACCESS: &str = "analytics_no_write_access";
pub const ANALYTICS_CLIENT_NOT_MANAGED: &str = "analytics_client_not_managed";
pub const ANALYTICS_NOT_ENABLED: &str = "analytics_not_enabled";
pub const ANALYTICS_UNKNOWN_TIMEZONE: &str = "analytics_unknown_timezone";

/// The ui bundle's own keys (the shared ones are [`Messages::ui`]'s).
const UI_ONLY: &[(&str, &str)] = &[
    (APP_NAME_MISMATCH, "Application name should match with appCode and should not contain any special characters "),
    (URI_STRING_NULL, "Path string missing"),
    (URI_PATTERN_PATH_MISMATCH, "Pattern: $ doesn't match with the given path: $."),
    (URI_INVALID_TYPE, "Selected Invalid UriPath for given definitions."),
    (URI_INVALID_METHOD, "Invalid method: Only GET, POST, PUT, PATCH and DELETE are supported."),
    (MULTIPLE_GEN_STATUS, "Multiple generation status for $ $ $ combination."),
    (INTERNAL_ONLY, "Cannot be used by clients other than SYSTEM Client."),
    (MOBILE_APP_BAD_REQUEST, "App Details are wrong with the mobile apps request"),
    (MOBILE_APP_UNABLE_TO_GEN_KEYSTORE, "Error occurred when generating the keystore."),
    (ANALYTICS_NOT_CONFIGURED, "Analytics is not configured on this server."),
    (ANALYTICS_CODES_REQUIRED, "appCode and clientCode are required."),
    (ANALYTICS_LOGIN_REQUIRED, "Sign in to read this application's analytics."),
    (ANALYTICS_NO_WRITE_ACCESS, "You do not have write access to this application."),
    (ANALYTICS_CLIENT_NOT_MANAGED, "Your client does not manage the requested client code."),
    (ANALYTICS_NOT_ENABLED, "Analytics is not enabled for this application."),
    (ANALYTICS_UNKNOWN_TIMEZONE, "$ is not a known IANA time zone."),
];

/// Adds the catalogue to the process (once; every error path calls it, so tests need no setup).
pub fn register() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| platform::messages::register("ui", "en", EN));
}

/// The whole ui bundle (`messages_en.properties`), coded `DEF.*` first, then `UI.*`: what the
/// editor's definition services raise with.
pub fn messages() -> Messages {
    register();
    let mut m = Messages::ui();
    for (k, v) in UI_ONLY {
        m.set(k, v);
    }
    m.add_namespace(NS);
    m
}

/// The whole bundle coded `UI.*` only: the runtime units' own refusals.
static OWN: LazyLock<Messages> = LazyLock::new(|| {
    let mut m = messages();
    m.set_namespaces(&[NS]);
    m
});

/// `throwMessage(status, key, params...)` for the ui units' own refusals: the `UI.*` code with
/// Java's text in `debugMessage`.
pub fn error(status: StatusCode, key: &str, params: &[&str]) -> AppError {
    OWN.error(status, key, params)
}

/// The same Java text said by a more specific code.
pub fn error_as(code: &str, status: StatusCode, key: &str, params: &[&str]) -> AppError {
    register();
    OWN.error_as(code, status, key, params)
}

/// A refusal Java raises with a literal text (no bundle key), said by `code`; the text goes to
/// `debugMessage`.
pub fn literal(code: &'static str, status: StatusCode, java_text: impl Into<String>) -> Coded {
    register();
    Coded::new(code).status(status).debug(java_text)
}

/// [`error_as`] with the message's values given by name, where Java's would not read well.
pub fn error_named(code: &'static str, status: StatusCode, key: &str, java_params: &[&str], named: Vec<(String, String)>) -> AppError {
    register();
    let mut c = Coded::new(code).status(status).debug(format!("[{key}] {}", OWN.java_text(key, java_params)));
    c.params = named;
    c.into()
}

/// A page whose permission a signed-in caller lacks (`FORBIDDEN_PERMISSION` naming the page's
/// permission expression): the permission is named when it is a plain one.
pub fn page_forbidden(permission: Option<&str>) -> AppError {
    let named = permission_param(permission).map(|p| vec![("permission".to_string(), p)]).unwrap_or_default();
    error_named("UI.PAGE_PERMISSION_REQUIRED", StatusCode::FORBIDDEN, "forbidden_permission", &[permission.unwrap_or("null")], named)
}

/// A URI path route whose permission the caller lacks (`FORBIDDEN_EXECUTION`); an anonymous
/// caller is only asked to sign in.
pub fn execution_forbidden(authenticated: bool, permission: &str) -> AppError {
    if !authenticated {
        return error_named("UI.SIGN_IN_REQUIRED", StatusCode::FORBIDDEN, "forbidden_execution", &[permission], Vec::new());
    }
    let named = permission_param(Some(permission)).map(|p| vec![("permission".to_string(), p)]).unwrap_or_default();
    error_named("UI.FORBIDDEN_EXECUTION", StatusCode::FORBIDDEN, "forbidden_execution", &[permission], named)
}

/// A permission expression as a message can name it: one authority, or several any one of which
/// would do (`A or B`), comma separated. `None` for anything more involved (`and`, `not`,
/// parentheses), which the message then leaves out.
pub fn permission_param(expression: Option<&str>) -> Option<String> {
    let parts: Vec<&str> = expression?.split(" or ").map(str::trim).collect();
    let simple = |p: &&str| {
        p.strip_prefix("Authorities.").is_some_and(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.'))
    };
    parts.iter().all(simple).then(|| parts.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;
    use platform::messages::Catalogue;

    fn catalogue() -> Catalogue {
        let mut c = Catalogue::default();
        c.add_builtin("platform", "en", platform::messages::PLATFORM_EN).unwrap();
        c.add_builtin("ui", "en", EN).unwrap();
        c
    }

    #[test]
    fn catalogue_is_complete() {
        platform::messages::check_catalogue(&catalogue(), NS);
    }

    /// Every key of the Java ui bundle has its own code, named after it.
    #[test]
    fn every_java_key_has_a_code() {
        let c = catalogue();
        let keys = messages().keys();
        assert_eq!(keys.len(), 43, "{keys:?}");
        for k in keys {
            let code = format!("UI.{}", k.to_ascii_uppercase());
            assert_eq!(c.code_for_java(NS, &k), Some(code.as_str()), "{k}");
        }
    }

    /// Each code reads well with all its values and with none.
    #[test]
    fn texts_render() {
        let c = catalogue();
        let en = vec!["en".to_string()];
        let p = |pairs: &[(&str, &str)]| pairs.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect::<Vec<_>>();
        let r = c.render("UI.PAGE_PERMISSION_REQUIRED", &p(&[("permission", "Authorities.Page_READ,Authorities.ROLE_Owner")]), &en, "E");
        assert_eq!(r.message, "You can't open this page: your account does not have the View pages permission or the Owner role.");
        let r = c.render("UI.ANALYTICS_UNKNOWN_TIMEZONE", &p(&[("zone", "Mars/Olympus")]), &en, "E");
        assert_eq!(r.message, "Mars/Olympus is not a time zone we know.");
        for code in c.codes().into_iter().filter(|c| c.starts_with("UI.")) {
            let r = c.render(code, &[], &en, "E");
            assert!(!r.message.contains('{') && !r.message.contains("  ") && !r.message.is_empty(), "{code}: {}", r.message);
            let meta = c.meta(code).unwrap();
            assert!(!meta.java.is_empty() || !meta.java_text.is_empty(), "{code} names no Java text");
            assert!(meta.when.is_some() && meta.audience.is_some(), "{code}");
        }
    }

    async fn body(e: AppError) -> serde_json::Value {
        let r = e.into_response();
        serde_json::from_slice(&axum::body::to_bytes(r.into_body(), 100_000).await.unwrap()).unwrap()
    }

    #[tokio::test]
    async fn the_editor_codes_definitions_first_and_the_runtime_its_own() {
        let m = messages();
        assert_eq!(m.code_for("object_not_found").as_deref(), Some("DEF.OBJECT_NOT_FOUND"));
        assert_eq!(m.code_for(URI_INVALID_TYPE).as_deref(), Some("UI.URI_INVALID_TYPE"));
        let v = body(error(StatusCode::PRECONDITION_FAILED, "version_mismatch", &[])).await;
        assert_eq!(v["code"], "UI.VERSION_MISMATCH");
        assert_eq!(v["debugMessage"], "[version_mismatch] Please reload to get the new version before making changes");
        let v = body(error_as("UI.SIGN_IN_REQUIRED", StatusCode::FORBIDDEN, "forbidden_execution", &["Authorities.Logged_IN"])).await;
        assert_eq!((v["message"].as_str(), v["debugMessage"].as_str()), (Some("Please sign in to continue."), Some("[forbidden_execution] Authorization Authorities.Logged_IN is required")));
        let v = body(literal("UI.PERSONALIZATION_NOT_OBJECT", StatusCode::BAD_REQUEST, "Personalization must be an object").into()).await;
        assert_eq!(v["debugMessage"], "Personalization must be an object");
    }

    #[tokio::test]
    async fn page_and_route_permissions() {
        let v = body(page_forbidden(Some("Authorities.Page_READ"))).await;
        assert_eq!(v["code"], "UI.PAGE_PERMISSION_REQUIRED");
        assert_eq!(v["message"], "You can't open this page: your account does not have the View pages permission.");
        assert_eq!(v["debugMessage"], "[forbidden_permission] Permission/Role Authorities.Page_READ is required to use this operation ");
        let v = body(page_forbidden(Some("Authorities.A and Authorities.B"))).await;
        assert_eq!(v["message"], "You can't open this page: your account does not have the permission it needs.");
        let v = body(page_forbidden(None)).await;
        assert_eq!(v["debugMessage"], "[forbidden_permission] Permission/Role null is required to use this operation ");
        let v = body(execution_forbidden(true, "Authorities.Logged_IN")).await;
        assert_eq!(v["message"], "You can't use this address: your account does not have the Signed in permission.");
        let v = body(execution_forbidden(false, "Authorities.Logged_IN")).await;
        assert_eq!((v["code"].as_str(), v["debugMessage"].as_str()), (Some("UI.SIGN_IN_REQUIRED"), Some("[forbidden_execution] Authorization Authorities.Logged_IN is required")));
    }

    #[test]
    fn permissions_named_when_simple() {
        assert_eq!(permission_param(Some("Authorities.Page_READ")).as_deref(), Some("Authorities.Page_READ"));
        assert_eq!(permission_param(Some("Authorities.A_READ or Authorities.ROLE_Owner")).as_deref(), Some("Authorities.A_READ,Authorities.ROLE_Owner"));
        assert_eq!(permission_param(Some("Authorities.A and Authorities.B")), None);
        assert_eq!(permission_param(Some("not Authorities.A")), None);
        assert_eq!(permission_param(Some("Authorization.Logged_IN")), None);
        assert_eq!(permission_param(Some("Authorities.")), None);
        assert_eq!(permission_param(None), None);
    }
}
