//! Rust only (HRMS): `CoreServices.File.CreateSecuredKey` and `SaveSecuredFile`, a secured file of
//! the caller's own client opened or written by a server function, which decides who may (scope and
//! visibility) before it acts. The files service's own path rules are not consulted: an employee
//! with no secured files path can still open a document the function hands a key for.
//!
//! What keeps them narrow:
//! - only inside a server function, for a signed-in user (an anonymous page, a webhook or an event
//!   without a user is refused);
//! - the client is the signed-in user's own (`<clientCode>/...`), never one an argument names;
//! - the path must be under the folder of the app that owns the running function (`hrms/` for an
//!   HRMS function), so a function of one app never reaches another app's files;
//! - a key lasts at most a day (`minutes`, 10 by default) and may be limited to a number of opens.

use std::sync::Arc;

use async_trait::async_trait;
use axum::http::StatusCode;
use kirun::model::FunctionOutput;
use kirun::{Map, Value};

use super::support::{forbidden, gson_tree, has_user, invalid_argument, output_map, required_argument, server_function_only, Java, JavaFunction};
use crate::context;
use crate::error::CoreError;
use crate::files_calls::FilesCalls;

const CREATE_SECURED_KEY: &str = "CoreServices.File.CreateSecuredKey";
const SAVE_SECURED_FILE: &str = "CoreServices.File.SaveSecuredFile";

/// The marker of a secured file's URL (`/api/files/secured/file/<clientCode>/<path>`).
const SECURED_FILE_MARKER: &str = "api/files/secured/file/";
/// A key's lifetime when `minutes` is not given, and the longest one.
pub const KEY_MINUTES_DEFAULT: i64 = 10;
pub const KEY_MINUTES_MAX: i64 = 1440;
/// The largest file `SaveSecuredFile` writes (decoded bytes).
pub const SAVE_MAX_BYTES: usize = 50 * 1024 * 1024;

/// Who is calling: the signed-in user, their client's code and the app whose folder they may use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileCaller {
    pub user_id: u64,
    pub client_code: String,
    pub app_code: String,
}

/// Only inside a server function, for a signed-in user with a client, with an owning app.
fn file_caller(full: &str) -> Result<FileCaller, CoreError> {
    if !context::in_kirun() {
        return Err(server_function_only(full));
    }
    let Some(req) = context::request() else {
        return Err(forbidden("CORE.SECURITY_CONTEXT_MISSING", format!("{full} needs a security context")).param("function", full));
    };
    let ca = &req.auth;
    let client_code = ca.client_code().map(str::trim).unwrap_or("");
    if !ca.is_authenticated() || !has_user(ca) || client_code.is_empty() {
        return Err(forbidden("CORE.SIGNED_IN_USER_REQUIRED", format!("{full} needs a signed in user")).param("function", full));
    }
    let app_code = context::owner_app_code()
        .filter(|a| !a.trim().is_empty())
        .or_else(|| ca.url_app_code().map(str::to_string).filter(|a| !a.trim().is_empty()))
        .ok_or_else(|| outside(full, "", "<app>/"))?;
    Ok(FileCaller { user_id: ca.user_id(), client_code: client_code.to_string(), app_code: app_code.trim().to_string() })
}

fn outside(full: &str, path: &str, prefix: &str) -> CoreError {
    forbidden("CORE.FILE_PATH_OUTSIDE_APP", format!("{full}: the path '{path}' is not under '{prefix}' of the caller's client"))
        .param("function", full)
        .param("path", path)
        .param("prefix", prefix)
}

/// `java.net.URLDecoder` over a URL path, as the files service reads it: `+` is a space.
fn url_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(&s.replace('+', " ")).decode_utf8_lossy().into_owned()
}

/// The path inside the caller's client that `path` names, under `<app>/` (or the app folder itself
/// when `folder` is true). `path` may be relative to the client (`hrms/employees/7/a.pdf`), start
/// with the client's code (`ACME/hrms/...`), or be the file's URL as the files service hands it out
/// (`/api/files/secured/file/ACME/hrms/...`, decoded as that service decodes it). Anything naming
/// another client, stepping out of a folder (`.`, `..`), with an empty segment, a backslash or a
/// control character, or outside the app's folder is `None`.
pub fn app_relative_path(path: &str, client_code: &str, app_code: &str, folder: bool) -> Option<String> {
    let t = path.trim();
    let (decoded, from_url) = match t.find(SECURED_FILE_MARKER) {
        Some(i) => (url_decode(t[i + SECURED_FILE_MARKER.len()..].split('?').next().unwrap_or("")), true),
        None => (t.to_string(), false),
    };
    let mut p = decoded.trim_start_matches('/').trim_end_matches('/').to_string();
    if from_url {
        // A file URL always starts with the client's code.
        p = p.strip_prefix(client_code)?.strip_prefix('/')?.to_string();
    } else if let Some(rest) = p.strip_prefix(client_code).and_then(|r| r.strip_prefix('/')) {
        if rest == app_code || rest.starts_with(&format!("{app_code}/")) {
            p = rest.to_string();
        }
    }
    if p.is_empty() || p.contains('\\') || p.chars().any(char::is_control) {
        return None;
    }
    if p.split('/').any(|s| s.is_empty() || s == "." || s == "..") {
        return None;
    }
    let under = p.starts_with(&format!("{app_code}/"));
    (under || (folder && p == app_code)).then_some(p)
}

/// A whole number argument (a number or a numeric string), `default` when absent or null.
fn int_arg(args: &Map<Value>, name: &str, default: i64) -> Result<i64, CoreError> {
    match args.get(name) {
        None | Some(Value::Null) => Ok(default),
        Some(Value::Number(n)) => n.as_i64().or_else(|| n.as_f64().filter(|f| f.fract() == 0.0).map(|f| f as i64)).ok_or_else(|| invalid_argument(name, "a whole number", format!("{name} must be a whole number"))),
        Some(Value::String(s)) if s.trim().is_empty() => Ok(default),
        Some(Value::String(s)) => s.trim().parse::<i64>().map_err(|_| invalid_argument(name, "a whole number", format!("{name} must be a whole number"))),
        Some(_) => Err(invalid_argument(name, "a whole number", format!("{name} must be a whole number"))),
    }
}

fn text_arg(args: &Map<Value>, name: &str) -> Option<String> {
    match args.get(name) {
        Some(Value::String(s)) if !s.trim().is_empty() => Some(s.trim().to_string()),
        _ => None,
    }
}

/// The bytes of a base64 text: plain, or a `data:` URL (`data:<type>[;name:<name>];base64,<data>`,
/// the form `FileToBase64` and pages hand out). White space is ignored; URL-safe letters too.
pub fn decode_base64(text: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    let data = match text.find(";base64,") {
        Some(i) if text.trim_start().starts_with("data:") => &text[i + ";base64,".len()..],
        _ => text,
    };
    let clean: String = data.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.is_empty() {
        return None;
    }
    let e = &base64::engine::general_purpose::STANDARD;
    e.decode(&clean)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(clean.trim_end_matches('=')))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(&clean))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(clean.trim_end_matches('=')))
        .ok()
}

/// A file name the files service stores as one name: no folder separators, nothing that steps out.
fn valid_file_name(name: &str) -> bool {
    !name.is_empty()
        && name.chars().count() <= 255
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\\')
        && !name.chars().any(char::is_control)
}

// -------------------------------------------------------------------------------------------
// CreateSecuredKey

/// `CoreServices.File.CreateSecuredKey(path, minutes, accessLimit)`: a short-lived download key for
/// a secured file of the caller's own client under the owning app's folder. `minutes` 1 to 1440
/// (10 when not given), `accessLimit` the most opens (0 or absent: no limit). The file is not
/// checked for: a key for a missing file opens nothing.
///
/// Output: `key`, and `url` (`/api/files/secured/downloadFileByKey/<key>`, to open as it is).
pub struct CreateSecuredKey {
    pub files: Arc<FilesCalls>,
}

#[async_trait]
impl JavaFunction for CreateSecuredKey {
    fn full_name(&self) -> &'static str {
        CREATE_SECURED_KEY
    }

    async fn run(&self, args: &Map<Value>) -> Result<FunctionOutput, CoreError> {
        let c = file_caller(CREATE_SECURED_KEY)?;
        let path = text_arg(args, "path").ok_or_else(|| required_argument("path"))?;
        let prefix = format!("{}/", c.app_code);
        let rel = app_relative_path(&path, &c.client_code, &c.app_code, false).ok_or_else(|| outside(CREATE_SECURED_KEY, &path, &prefix))?;
        let minutes = int_arg(args, "minutes", KEY_MINUTES_DEFAULT)?;
        let minutes = if minutes == 0 { KEY_MINUTES_DEFAULT } else { minutes };
        if !(1..=KEY_MINUTES_MAX).contains(&minutes) {
            return Err(invalid_argument("minutes", "1 to 1440", format!("minutes must be 1 to {KEY_MINUTES_MAX}")));
        }
        let limit = match int_arg(args, "accessLimit", 0)? {
            0 => None,
            l if l > 0 => Some(l as u64),
            _ => return Err(invalid_argument("accessLimit", "0 or more", "accessLimit must be 0 (no limit) or more")),
        };
        let storage = format!("{}/{rel}", c.client_code);
        let answer = self.files.create_timed_key(&storage, minutes, limit, Some(c.user_id)).await?.unwrap_or_default();
        let url_path = answer.trim().trim_start_matches('/').to_string();
        let key = url_path.rsplit('/').next().unwrap_or("").to_string();
        if key.is_empty() {
            return Err(CoreError::coded(StatusCode::BAD_GATEWAY, "CORE.FILES_NO_ANSWER", format!("{CREATE_SECURED_KEY}: the files service made no key")).param("function", CREATE_SECURED_KEY));
        }
        Ok(output_map([("key", Value::String(key)), ("url", Value::String(format!("/{url_path}")))]))
    }
}

// -------------------------------------------------------------------------------------------
// SaveSecuredFile

/// `CoreServices.File.SaveSecuredFile(path, fileName, base64, override)`: `base64` (plain or a
/// `data:` URL, at most 50 MB decoded) written as `<path>/<fileName>` among the secured files of
/// the caller's own client, `path` being the owning app's folder or one under it. Without
/// `override` an existing file is kept and its details answered.
///
/// Output: `file`, the files service's details of the file (`name`, `url`, `size`, ...).
pub struct SaveSecuredFile {
    pub files: Arc<FilesCalls>,
}

#[async_trait]
impl JavaFunction for SaveSecuredFile {
    fn full_name(&self) -> &'static str {
        SAVE_SECURED_FILE
    }

    async fn run(&self, args: &Map<Value>) -> Result<FunctionOutput, CoreError> {
        let c = file_caller(SAVE_SECURED_FILE)?;
        let path = text_arg(args, "path").ok_or_else(|| required_argument("path"))?;
        let prefix = format!("{}/", c.app_code);
        let rel = app_relative_path(&path, &c.client_code, &c.app_code, true).ok_or_else(|| outside(SAVE_SECURED_FILE, &path, &prefix))?;
        let name = text_arg(args, "fileName").ok_or_else(|| required_argument("fileName"))?;
        if !valid_file_name(&name) {
            return Err(invalid_argument("fileName", "a file name", "fileName must be one file name, without folders"));
        }
        let data = match args.get("base64") {
            Some(Value::String(s)) if !s.trim().is_empty() => s,
            _ => return Err(required_argument("base64")),
        };
        if data.len() > SAVE_MAX_BYTES / 3 * 4 + 1024 {
            return Err(invalid_argument("base64", "at most 50 MB", "the file is larger than 50 MB"));
        }
        let bytes = decode_base64(data).ok_or_else(|| invalid_argument("base64", "base64 text", "base64 is not base64 text"))?;
        if bytes.len() > SAVE_MAX_BYTES {
            return Err(invalid_argument("base64", "at most 50 MB", "the file is larger than 50 MB"));
        }
        let overwrite = matches!(args.get("override"), Some(Value::Bool(true))) || matches!(args.get("override"), Some(Value::String(s)) if s.eq_ignore_ascii_case("true"));
        let details = self.files.create("secured", &c.client_code, overwrite, &format!("/{rel}"), &name, bytes).await?;
        let Some(details) = details else {
            return Err(CoreError::coded(StatusCode::BAD_GATEWAY, "CORE.FILES_NO_ANSWER", format!("{SAVE_SECURED_FILE}: the files service wrote nothing")).param("function", SAVE_SECURED_FILE));
        };
        Ok(output_map([("file", gson_tree(Value::Object(details)))]))
    }
}

/// The two functions, after `file::all`'s.
pub fn all(files: &Arc<FilesCalls>) -> Vec<Arc<dyn kirun::function::Function>> {
    vec![Java::function(CreateSecuredKey { files: files.clone() }), Java::function(SaveSecuredFile { files: files.clone() })]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_stay_in_the_callers_app_folder() {
        let p = |s: &str| app_relative_path(s, "ACME", "hrms", false);
        assert_eq!(p("hrms/employees/7/a.pdf").as_deref(), Some("hrms/employees/7/a.pdf"));
        assert_eq!(p("/hrms/employees/7/a.pdf").as_deref(), Some("hrms/employees/7/a.pdf"));
        assert_eq!(p("ACME/hrms/a.pdf").as_deref(), Some("hrms/a.pdf"));
        assert_eq!(p("/api/files/secured/file/ACME/hrms/My+Doc%2B1.pdf").as_deref(), Some("hrms/My Doc+1.pdf"));
        assert_eq!(p("https://x.modlix.com/api/files/secured/file/ACME/hrms/a.pdf?download=true").as_deref(), Some("hrms/a.pdf"));
        // Another client, another app, the app folder itself, stepping out, odd segments.
        assert_eq!(p("/api/files/secured/file/OTHER/hrms/a.pdf"), None);
        assert_eq!(p("OTHER/hrms/a.pdf"), None);
        assert_eq!(p("leadzump/a.pdf"), None);
        assert_eq!(p("hrmsx/a.pdf"), None);
        assert_eq!(p("hrms"), None);
        assert_eq!(p("hrms/../leadzump/a.pdf"), None);
        assert_eq!(p("hrms/./a.pdf"), None);
        assert_eq!(p("hrms//a.pdf"), None);
        assert_eq!(p("hrms\\a.pdf"), None);
        assert_eq!(p("/api/files/secured/file/ACME/hrms/%2E%2E/x.pdf"), None);
        assert_eq!(p(""), None);
        // A folder may be the app's own.
        assert_eq!(app_relative_path("hrms", "ACME", "hrms", true).as_deref(), Some("hrms"));
        assert_eq!(app_relative_path("hrms/employees/7/", "ACME", "hrms", true).as_deref(), Some("hrms/employees/7"));
        assert_eq!(app_relative_path("ACME", "ACME", "hrms", true), None);
    }

    #[test]
    fn base64_plain_or_data_url() {
        assert_eq!(decode_base64("aGVsbG8=").as_deref(), Some(&b"hello"[..]));
        assert_eq!(decode_base64("aGVsbG8").as_deref(), Some(&b"hello"[..]));
        assert_eq!(decode_base64("data:text/plain;name:a.txt;base64,aGVs\nbG8=").as_deref(), Some(&b"hello"[..]));
        assert_eq!(decode_base64("data:application/pdf;base64,aGVsbG8=").as_deref(), Some(&b"hello"[..]));
        assert_eq!(decode_base64("-_8=").as_deref(), Some(&[0xfb, 0xff][..]));
        assert!(decode_base64("not base64!").is_none());
        assert!(decode_base64("  ").is_none());
    }

    #[test]
    fn file_names_are_one_name() {
        assert!(valid_file_name("offer letter.pdf"));
        for bad in ["", ".", "..", "a/b.pdf", "a\\b.pdf", "a\nb"] {
            assert!(!valid_file_name(bad), "{bad}");
        }
    }

    #[tokio::test]
    async fn refused_outside_a_server_function_or_without_a_user() {
        let files = Arc::new(FilesCalls::new(platform::upstream::Upstream::fixed(&["http://127.0.0.1:1"])).unwrap());
        let key = Java::new(CreateSecuredKey { files: files.clone() });
        let args: Map<Value> = [("path".to_string(), Value::from("hrms/a.pdf"))].into_iter().collect();
        use crate::functions::CoreFunction;
        let e = key.internal_execute(&args).await.unwrap_err();
        assert_eq!(e.status(), StatusCode::FORBIDDEN);
        assert!(e.text().contains("can only be called from a server function"), "{}", e.text());
        // Inside a definition but anonymous: refused before any call.
        let anon = Arc::new(context::RequestContext::default());
        let e = context::with_request(anon, context::with_run(context::RunScope { owner_app_code: Some("hrms".into()) }, key.internal_execute(&args)))
            .await
            .unwrap_err();
        assert_eq!(e.status(), StatusCode::FORBIDDEN);
        assert!(e.text().contains("needs a signed in user"), "{}", e.text());
        let save = Java::new(SaveSecuredFile { files });
        let e = context::with_request(Arc::new(context::RequestContext::default()), context::with_run(context::RunScope::default(), save.internal_execute(&args)))
            .await
            .unwrap_err();
        assert!(e.text().contains("needs a signed in user"), "{}", e.text());
    }

    #[tokio::test]
    async fn keys_and_uploads_for_the_signed_in_users_client() {
        use axum::extract::RawQuery;
        use axum::routing::{get, post};
        use parking_lot::Mutex;
        let seen: Arc<Mutex<Vec<String>>> = Default::default();
        let (a, b) = (seen.clone(), seen.clone());
        let router = axum::Router::new()
            .route(
                "/api/files/internal/secured/createTimedKey",
                get(move |RawQuery(q): RawQuery| {
                    let a = a.clone();
                    async move {
                        a.lock().push(q.unwrap_or_default());
                        "api/files/secured/downloadFileByKey/k3y"
                    }
                }),
            )
            .route(
                "/api/files/internal/secured",
                post(move |RawQuery(q): RawQuery, body: axum::body::Bytes| {
                    let b = b.clone();
                    async move {
                        b.lock().push(format!("{}|{}", q.unwrap_or_default(), String::from_utf8_lossy(&body)));
                        axum::Json(serde_json::json!({"name": "a.txt", "url": "/api/files/secured/file/SYSTEM/hrms/x/a.txt"}))
                    }
                }),
            );
        let base = crate::testing::serve(router).await;
        let files = Arc::new(FilesCalls::new(platform::upstream::Upstream::fixed(&[&base])).unwrap());
        let run = |f: Java<CreateSecuredKey>, args: Map<Value>| async move {
            use crate::functions::CoreFunction;
            let req = crate::testing::request(crate::testing::user(&[]), false, None);
            context::with_request(req, context::with_run(context::RunScope { owner_app_code: Some("hrms".into()) }, async move { f.internal_execute(&args).await })).await
        };
        let args = |pairs: &[(&str, Value)]| -> Map<Value> { pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect() };
        let out = run(Java::new(CreateSecuredKey { files: files.clone() }), args(&[("path", Value::from("hrms/employees/7/a b.pdf")), ("accessLimit", Value::from(2))]))
            .await
            .unwrap()
            .next()
            .unwrap();
        assert_eq!(out.get_result().get("key"), Some(&Value::from("k3y")));
        assert_eq!(out.get_result().get("url"), Some(&Value::from("/api/files/secured/downloadFileByKey/k3y")));
        let q = seen.lock()[0].clone();
        assert!(q.contains("filePath=SYSTEM%2Fhrms%2Femployees%2F7%2Fa+b.pdf") || q.contains("filePath=SYSTEM%2Fhrms%2Femployees%2F7%2Fa%20b.pdf"), "{q}");
        assert!(q.contains("minutes=10") && q.contains("accessLimit=2") && q.contains("createdBy=142"), "{q}");
        // Another app's folder and a long key are refused before any call.
        let e = run(Java::new(CreateSecuredKey { files: files.clone() }), args(&[("path", Value::from("leadzump/a.pdf"))])).await.unwrap_err();
        assert_eq!(e.status(), StatusCode::FORBIDDEN);
        let e = run(Java::new(CreateSecuredKey { files: files.clone() }), args(&[("path", Value::from("hrms/a.pdf")), ("minutes", Value::from(1441))])).await.unwrap_err();
        assert_eq!(e.status(), StatusCode::BAD_REQUEST);
        assert_eq!(seen.lock().len(), 1);

        use crate::functions::CoreFunction;
        let save = Java::new(SaveSecuredFile { files });
        let a = args(&[("path", Value::from("hrms/x")), ("fileName", Value::from("a.txt")), ("base64", Value::from("data:text/plain;base64,aGVsbG8="))]);
        let req = crate::testing::request(crate::testing::user(&[]), false, None);
        let out = context::with_request(req, context::with_run(context::RunScope { owner_app_code: Some("hrms".into()) }, save.internal_execute(&a))).await.unwrap().next().unwrap();
        assert_eq!(out.get_result()["file"]["name"], Value::from("a.txt"));
        let sent = seen.lock()[1].clone();
        assert!(sent.starts_with("clientCode=SYSTEM&override=false&filePath=%2Fhrms%2Fx&fileName=a.txt|hello"), "{sent}");
    }
}
