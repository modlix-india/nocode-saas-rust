//! The service's messages (`messages_en.properties`) as coded errors, and the bridge from
//! `anyhow` to the HTTP edge: code deep in a write can refuse with an `AppError` wrapped in
//! `anyhow`, and the handler turns it back into that status and message.
//!
//! Every refusal answers with a code from the catalogue (`messages/en.toml`, codes `FILES.*`, and
//! the platform's `COMMON.*`): the plain text and the next step, with Java's text in
//! `debugMessage` (`[key] text` for a bundle key), which stays the parity reference.

use std::sync::Once;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use platform::error::{format_message, AppError, Coded};
use platform::messages::render::name_positional;

/// The English texts, compiled in.
pub const EN: &str = include_str!("../messages/en.toml");

/// The namespace of this service's codes.
pub const NS: &str = "FILES";

pub const OBJECT_NOT_FOUND: &str = "object_not_found";
pub const ALREADY_EXISTS: &str = "already_exists";
pub const UNABLE_TO_CONVERT: &str = "unable_to_convert";
pub const UNKNOWN_ERROR: &str = "unknown_error";
pub const FORBIDDEN_PERMISSION: &str = "forbidden_permission";
pub const FORBIDDEN_PATH: &str = "forbidden_path";
pub const ACCESS_ONLY_TO_ONE: &str = "access_only_to_one";
pub const TIME_UNIT_ERROR: &str = "time_unit_error";
pub const TIME_SPAN_ERROR: &str = "time_span_error";
pub const SECURED_KEY_CREATION_ERROR: &str = "secured_key_creation_error";
pub const UNABLE_TO_READ_UP_FILE: &str = "unable_to_read_up_file";
pub const MISSING_FIELD: &str = "missing_field";
pub const IMAGE_TRANSFORM_ERROR: &str = "image_transform_error";
pub const INVALID_KEY: &str = "invalid_key";
pub const UNABLE_TO_UPLOAD_ZIP_FILE: &str = "unable_to_upload_zip_file";
pub const FILE_CANNOT_BE_CONVERTED: &str = "file_cannot_be_converted";
pub const RETENTION_PREFIX_NOT_REGISTERED: &str = "retention_prefix_not_registered";
pub const INVALID_FIELD: &str = "invalid_field";

/// The Java bundle, every key.
pub const JAVA: &[(&str, &str)] = &[
    (OBJECT_NOT_FOUND, "$ with id $ not found"),
    ("object_not_found_to_update", "$ with id $ not found to update"),
    ("forbidden_create", "Cannot create $ for the selected client"),
    (FORBIDDEN_PERMISSION, "Permission/Role $ is required to use this operation "),
    ("unable_to_delete", "Unable to delete $ with id $ "),
    ("object_not_updatable", "Cannot update this object"),
    ("user_credentials_mismatched", "User credentials mismatch"),
    (UNKNOWN_ERROR, "Internal Server Error (Unknown)"),
    ("unknown_error_with_id", "Please try again. A server error - $ "),
    ("unkonwn_error_insert", "Unknown error occurred while inserting into db"),
    ("valueof_method_not_found", "Could not find the valueOf method"),
    (UNABLE_TO_CONVERT, "Unable to convert $ to $"),
    ("token_expired", "Authorization token expired. Please re-login."),
    ("unknown_token", "Unknown token"),
    (ALREADY_EXISTS, "$ $ already exists"),
    ("forbidden_resource", "Permission to $ the $ resources is forbidden"),
    (FORBIDDEN_PATH, "Permission to $ resource in the path $ is forbidden"),
    (ACCESS_ONLY_TO_ONE, "Access can be given to a user, permission, or a role "),
    ("not_a_directory", "Path '$' is not a directory to list"),
    ("unable_to_del_file", "Unable to delete file/folder $"),
    ("path_not_found", "Location '$' is not found"),
    (TIME_UNIT_ERROR, "Time unit is not provided for selected resource"),
    (TIME_SPAN_ERROR, "Time Span is not provided for selected resource"),
    (SECURED_KEY_CREATION_ERROR, "Secured key cannot be created"),
    (UNABLE_TO_READ_UP_FILE, "Unable to read uploaded zip file"),
    ("unable_create_download_file", "Unable to create a zip file of the directory"),
    ("wrong_file_type", "Selected file type doesn't exist"),
    (MISSING_FIELD, "$ is/are missing"),
    ("image_file_required", "Uploaded file should be of image type"),
    (IMAGE_TRANSFORM_ERROR, "Selected image cannot be edited"),
    ("unable_to_copy_the_image_file", "Unable to copy the image file"),
    (INVALID_KEY, "Cannot be accessed with the given key or access limit reached"),
    (UNABLE_TO_UPLOAD_ZIP_FILE, "Unable to upload the zip file"),
    (FILE_CANNOT_BE_CONVERTED, "File cannot be converted to base64"),
    (RETENTION_PREFIX_NOT_REGISTERED, "Path '$' is not a registered retention prefix of app $ for $ files"),
    (INVALID_FIELD, "Invalid $: $"),
];

/// Adds the catalogue to the process (once; every error path calls it, so tests need no setup).
pub fn register() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| platform::messages::register("files", "en", EN));
}

/// The bundle's template for `key` (`unknown_error`'s for a key it lacks, as Java's `getMessage`).
pub fn template(key: &str) -> &'static str {
    JAVA.iter().find(|(k, _)| *k == key).or_else(|| JAVA.iter().find(|(k, _)| *k == UNKNOWN_ERROR)).map(|(_, t)| *t).unwrap_or("")
}

/// `throwMessage(status, key, params...)`: the code standing for the key, Java's text in
/// `debugMessage`.
pub fn status(status: StatusCode, key: &str, params: &[&str]) -> AppError {
    register();
    let code = platform::messages::global().code_for_java(NS, key).unwrap_or("FILES.UNKNOWN_ERROR").to_string();
    err_as(&code, status, key, params)
}

/// The same Java text said by a more specific code; Java's values are named by the code's params
/// in order (Java's `null` left out).
pub fn err_as(code: &str, status: StatusCode, key: &str, params: &[&str]) -> AppError {
    register();
    let values: Vec<&str> = params.iter().map(|p| if *p == "null" { "" } else { *p }).collect();
    let named = name_positional(&platform::messages::global(), code, &values);
    err_named(code, status, key, params, named)
}

/// [`err_as`] with the message's values given by name, where Java's would not read well.
pub fn err_named(code: &str, status: StatusCode, key: &str, params: &[&str], named: Vec<(String, String)>) -> AppError {
    register();
    let mut c = Coded::new(code.to_string()).status(status).debug(format!("[{key}] {}", format_message(template(key), params)));
    c.params = named.into_iter().filter(|(_, v)| !v.trim().is_empty()).collect();
    c.into()
}

/// A refusal Java raises with a literal text (no bundle key), said by `code`; the text goes to
/// `debugMessage`.
pub fn literal(code: &'static str, status: StatusCode, java_text: impl Into<String>) -> Coded {
    register();
    Coded::new(code).status(status).debug(java_text)
}

/// A query or path parameter whose value does not convert (Java's catch-all 500 says "Please try
/// again"); `text` is the detail for support.
pub fn param_invalid(name: &str, text: impl Into<String>) -> AppError {
    platform::error::input::param_invalid(name, None).status(StatusCode::BAD_REQUEST).debug(text).into()
}

/// A required query parameter that was not sent.
pub fn param_missing(name: &str) -> AppError {
    platform::error::input::param_missing(name)
        .status(StatusCode::BAD_REQUEST)
        .debug(format!("Required parameter '{name}' is not present."))
        .into()
}

/// A request body that cannot be read; `text` is the reader's detail for support.
pub fn body_unreadable(text: impl Into<String>) -> AppError {
    platform::error::input::body_unreadable(None).status(StatusCode::BAD_REQUEST).debug(text).into()
}

/// Spring Security's empty 403, said plainly: "signed out" when security turned a credential
/// down, "please sign in" when there was none.
pub fn sign_in(credential_refused: bool) -> AppError {
    let code = if credential_refused { "COMMON.SIGNED_OUT" } else { "COMMON.SIGN_IN_REQUIRED" };
    let why = if credential_refused { "security refused the credential" } else { "not signed in" };
    Coded::new(code).status(StatusCode::FORBIDDEN).debug(format!("Spring Security's empty 403: {why}")).into()
}

/// The text Java would give for this error (`getMessage`), for the records that keep one (a
/// background job's failure).
pub fn java_message(e: &AppError) -> String {
    match e {
        AppError::Message { message, .. } => message.clone(),
        AppError::Coded(c) => match c.debug.as_deref() {
            Some(d) => d.strip_prefix('[').and_then(|r| r.split_once("] ")).map(|(_, t)| t).unwrap_or(d).to_string(),
            None => e.english_message(),
        },
        other => other.english_message(),
    }
}

/// An error as the files units answer it: an unexpected failure is `COMMON.INTERNAL_ERROR` (the
/// cause for support), everything else as the platform renders it.
pub fn respond(e: AppError) -> Response {
    match e {
        AppError::Internal(cause) => platform::error::coded_response(&Coded::new("COMMON.INTERNAL_ERROR").debug(format!("{cause:#}"))),
        other => other.into_response(),
    }
}

/// An `AppError` raised inside `anyhow` code comes back out as itself; anything else is a 500.
pub fn into_app(e: anyhow::Error) -> AppError {
    match e.downcast::<AppError>() {
        Ok(a) => a,
        Err(e) => AppError::Internal(e),
    }
}

pub trait OrApp<T> {
    fn app(self) -> Result<T, AppError>;
}

impl<T> OrApp<T> for anyhow::Result<T> {
    fn app(self) -> Result<T, AppError> {
        self.map_err(into_app)
    }
}

pub fn forbidden_path(kind: crate::paths::Kind, path: &str) -> AppError {
    status(StatusCode::FORBIDDEN, FORBIDDEN_PATH, &[kind.db_name(), path])
}

pub fn missing(field: &str) -> AppError {
    status(StatusCode::BAD_REQUEST, MISSING_FIELD, &[field])
}

/// `FileNameUtil.validate`: the one gate for every name that becomes a row.
pub fn validate_name(name: &str) -> Result<(), AppError> {
    let refuse = |code: &'static str, text: String, name: Option<&str>| -> AppError {
        let c = literal(code, StatusCode::BAD_REQUEST, text);
        match name {
            Some(n) => c.param("name", n).into(),
            None => c.into(),
        }
    };
    if name.trim().is_empty() {
        return Err(refuse("FILES.NAME_BLANK", "A file or folder name cannot be blank.".into(), None));
    }
    let trimmed = name.trim();
    if trimmed == "." || trimmed == ".." {
        return Err(refuse("FILES.NAME_RESERVED", format!("'{trimmed}' is not a usable file or folder name."), Some(trimmed)));
    }
    let lower = trimmed.to_lowercase();
    if matches!(lower.as_str(), "undefined" | "null" | "nan" | "[object object]" | "[object undefined]") {
        return Err(refuse(
            "FILES.NAME_EMPTY_VALUE",
            format!(
                "'{trimmed}' is not a usable name. It is what an empty value looks like once it has been put into a URL, so the caller most likely sent a path with a missing part in it."
            ),
            Some(trimmed),
        ));
    }
    if trimmed.chars().any(|c| c == '/' || c == '\\' || (c as u32) < 0x20 || c as u32 == 0x7F) {
        return Err(refuse("FILES.NAME_SEPARATOR", "A file or folder name cannot contain a path separator or a control character.".into(), None));
    }
    Ok(())
}

/// `validate_name` for `anyhow` code.
pub fn check_name(name: &str) -> anyhow::Result<()> {
    validate_name(name).map_err(anyhow::Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use platform::messages::Catalogue;

    fn catalogue() -> Catalogue {
        let mut c = Catalogue::default();
        c.add_builtin("platform", "en", platform::messages::PLATFORM_EN).unwrap();
        c.add_builtin("files", "en", EN).unwrap();
        c
    }

    #[test]
    fn catalogue_is_complete() {
        platform::messages::check_catalogue(&catalogue(), NS);
    }

    /// Every key of the Java bundle has its own code, named after it.
    #[test]
    fn every_java_key_has_a_code() {
        let c = catalogue();
        assert_eq!(JAVA.len(), 36);
        for (k, _) in JAVA {
            let code = format!("FILES.{}", k.to_ascii_uppercase());
            assert_eq!(c.code_for_java(NS, k), Some(code.as_str()), "{k}");
        }
        assert_eq!(template("nope"), "Internal Server Error (Unknown)");
    }

    /// Each code reads well with all its values and with none.
    #[test]
    fn texts_render() {
        let c = catalogue();
        let en = vec!["en".to_string()];
        let p = |pairs: &[(&str, &str)]| pairs.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect::<Vec<_>>();
        let r = c.render("FILES.OBJECT_NOT_FOUND", &p(&[("what", "FilesAccessPath"), ("id", "9")]), &en, "E");
        assert_eq!(r.message, "We couldn't find the file access rule with id 9.");
        let r = c.render("FILES.FORBIDDEN_PERMISSION", &p(&[("permission", "STATIC Files PATH")]), &en, "E");
        assert_eq!(r.message, "You can't do this: your account does not have the Use static file paths permission.");
        for code in c.codes().into_iter().filter(|c| c.starts_with("FILES.")) {
            let r = c.render(code, &[], &en, "E");
            assert!(!r.message.contains('{') && !r.message.contains("  ") && !r.message.is_empty(), "{code}: {}", r.message);
            let meta = c.meta(code).unwrap();
            assert!(!meta.java.is_empty() || !meta.java_text.is_empty(), "{code} names no Java text");
            assert!(meta.when.is_some() && meta.audience.is_some(), "{code}");
        }
    }

    async fn body(r: Response) -> (StatusCode, serde_json::Value) {
        let s = r.status();
        (s, serde_json::from_slice(&axum::body::to_bytes(r.into_body(), 100_000).await.unwrap()).unwrap())
    }

    #[tokio::test]
    async fn refusals_are_coded_with_javas_text_for_support() {
        let (s, v) = body(forbidden_path(crate::paths::Kind::Secured, "FIN/a.pdf").into_response()).await;
        assert_eq!((s, v["code"].as_str()), (StatusCode::FORBIDDEN, Some("FILES.FORBIDDEN_PATH")));
        assert_eq!(v["message"], "You don't have access to FIN/a.pdf.");
        assert_eq!(v["debugMessage"], "[forbidden_path] Permission to SECURED resource in the path FIN/a.pdf is forbidden");
        let (_, v) = body(status(StatusCode::BAD_REQUEST, "no_such_key", &[]).into_response()).await;
        assert_eq!((v["code"].as_str(), v["debugMessage"].as_str()), (Some("FILES.UNKNOWN_ERROR"), Some("[no_such_key] Internal Server Error (Unknown)")));
        let (_, v) = body(err_as("FILES.APP_NOT_FOUND", StatusCode::NOT_FOUND, OBJECT_NOT_FOUND, &["App", "null"]).into_response()).await;
        assert_eq!(v["message"], "We couldn't find the app.", "Java's null is left out");
        let (s, v) = body(param_missing("filePath").into_response()).await;
        assert_eq!((s, v["code"].as_str(), v["debugMessage"].as_str()), (StatusCode::BAD_REQUEST, Some("COMMON.PARAM_MISSING"), Some("Required parameter 'filePath' is not present.")));
        let (s, v) = body(param_invalid("width", "Invalid value 'x' for parameter 'width'").into_response()).await;
        assert_eq!((s, v["message"].as_str()), (StatusCode::BAD_REQUEST, Some("The value of the width parameter is not valid.")));
        let (_, v) = body(body_unreadable("Invalid JSON: eof").into_response()).await;
        assert_eq!(v["code"], "COMMON.BODY_UNREADABLE");
        for (refused, code) in [(true, "COMMON.SIGNED_OUT"), (false, "COMMON.SIGN_IN_REQUIRED")] {
            let (s, v) = body(sign_in(refused).into_response()).await;
            assert_eq!((s, v["code"].as_str()), (StatusCode::FORBIDDEN, Some(code)));
        }
        let (s, v) = body(respond(AppError::Internal(anyhow::anyhow!("bucket down")))).await;
        assert_eq!((s, v["code"].as_str(), v["debugMessage"].as_str()), (StatusCode::INTERNAL_SERVER_ERROR, Some("COMMON.INTERNAL_ERROR"), Some("bucket down")));
        assert_eq!(respond(AppError::Empty(StatusCode::NOT_FOUND)).status(), StatusCode::NOT_FOUND);
        assert_eq!(java_message(&AppError::new(StatusCode::CONFLICT, "Taken")), "Taken");
        assert_eq!(java_message(&AppError::Internal(anyhow::anyhow!("x"))), "x");
        assert_eq!(java_message(&Coded::new("FILES.FILE_EMPTY").into()), "The uploaded file is empty.");
        assert_eq!(java_message(&literal("FILES.FILE_EMPTY", StatusCode::BAD_REQUEST, "File is required and cannot be empty").into()), "File is required and cannot be empty");
    }

    #[test]
    fn names_like_file_name_util() {
        assert!(validate_name("a.png").is_ok());
        assert!(validate_name("Null").is_err());
        assert!(validate_name(" ").is_err());
        assert!(validate_name("..").is_err());
        assert!(validate_name("a\\b").is_err());
        assert!(validate_name("a\u{7f}").is_err());
        let e = validate_name("undefined").unwrap_err();
        assert_eq!(e.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn app_errors_survive_anyhow() {
        let e: anyhow::Error = forbidden_path(crate::paths::Kind::Static, "a/b").into();
        let a = into_app(e);
        assert_eq!(a.status(), StatusCode::FORBIDDEN);
        assert_eq!(into_app(anyhow::anyhow!("x")).status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// `FileNameUtilTest`, every case but `null` (a Rust `&str` cannot be null).
    #[test]
    fn file_name_util_test() {
        // StringifiedNothing: refused, whatever the case.
        for name in ["undefined", "UNDEFINED", "Undefined", "null", "NaN", "[object Object]", "[object object]", "[object undefined]"] {
            let e = validate_name(name).unwrap_err();
            assert_eq!(e.status(), StatusCode::BAD_REQUEST, "{name}");
        }
        assert_eq!(
            java_message(&validate_name(" undefined ").unwrap_err()),
            "'undefined' is not a usable name. It is what an empty value looks like once it has been put into a URL, so the caller most likely sent a path with a missing part in it."
        );
        // A name that merely contains one is fine.
        assert!(validate_name("undefined-behaviour.pdf").is_ok());
        assert!(validate_name("nullable").is_ok());
        // Malformed: blank (spaces, a tab), the traversal segments, separators, control characters.
        for name in ["", "   ", "\t"] {
            assert_eq!(java_message(&validate_name(name).unwrap_err()), "A file or folder name cannot be blank.", "{name:?}");
        }
        for name in [".", ".."] {
            assert_eq!(java_message(&validate_name(name).unwrap_err()), format!("'{name}' is not a usable file or folder name."));
        }
        for name in ["a/b", "a\\b", "a\u{1}b"] {
            assert_eq!(
                java_message(&validate_name(name).unwrap_err()),
                "A file or folder name cannot contain a path separator or a control character.",
                "{name:?}"
            );
        }
        // Names people really use.
        for name in [
            "docsScreens",
            "Pan.pdf",
            "calculator images",
            "video_test-1",
            "Adzump text updated themes.xlsx",
            "Group 1707479488.svg",
            "699d4dc399e3a015be13c8f4",
            "CityVille4_1225_68.pdf",
            "..leading-dots.png",
            "a",
        ] {
            assert!(validate_name(name).is_ok(), "{name}");
        }
        // `isUsable`: the answer without the error.
        assert!(check_name("undefined").is_err());
        assert!(check_name("real.png").is_ok());
        assert_eq!(java_message(&missing("file")), "file is/are missing");
        assert_eq!(java_message(&status(StatusCode::CONFLICT, ALREADY_EXISTS, &["A", "b"])), "A b already exists");
        let r: anyhow::Result<()> = Err(anyhow::Error::from(missing("x")));
        assert_eq!(r.app().unwrap_err().status(), StatusCode::BAD_REQUEST);
    }
}
