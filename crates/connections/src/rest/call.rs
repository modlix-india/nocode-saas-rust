//! `CallRequest` (`CoreServices.REST.GetRequest`, `PostRequest`, `PutRequest`, `PatchRequest`,
//! `DeleteRequest`, `CallRequest`): what a REST call hands back to KIRun.
//!
//! - A response with a status from 400 to 600 raises `error` with the response
//!   (`data`, `headers`, `statusCode`) and then `output` with `{}` data and headers and the same
//!   status.
//! - A failure without a response (refused target, timeout, unreadable URL) raises the same
//!   pair with status 500 (or a Feign error's own status) and the message as `data`.
//! - Otherwise `output` with the response, after storing it as a file when asked to.

use std::collections::HashMap;

use async_trait::async_trait;
use serde_json::{Map, Value};

use super::media_type::MediaType;
use super::{do_call, RestData, RestRequest, RestResponse};
use crate::context::Caller;
use crate::error::{ConnError, ConnResult};
use crate::java::{self, json};
use crate::Connections;

pub const NAMESPACE: &str = "CoreServices.REST";
pub const EVENT_OUTPUT: &str = "output";
pub const EVENT_ERROR: &str = "error";
/// The status of a failure that had no response to take one from.
pub const NO_RESPONSE_STATUS: i32 = 500;
/// Held only by core's internal webhook run (`crates/core/src/events.rs`).
pub const WEBHOOK_AUTHORITY: &str = "Authorities._Webhook";
/// Held only by core's anonymous event run (`crates/core/src/events.rs`).
pub const EVENT_RUNNER_AUTHORITY: &str = "Authorities._Event_Runner";
/// The files a webhook or event run downloads are always secured: nobody signed in asked for
/// them, and recordings and media must not become public by URL.
pub const RUN_FILE_TYPE: &str = "secured";

/// One event the function raises.
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    pub name: &'static str,
    pub result: Map<String, Value>,
}

/// The step's arguments, after KIRun has applied the signature's defaults.
#[derive(Debug, Clone, Default)]
pub struct CallArgs {
    pub connection_name: String,
    pub url: String,
    pub app_code: String,
    pub client_code: String,
    pub headers: Map<String, Value>,
    pub query_params: Map<String, Value>,
    pub path_params: Map<String, Value>,
    pub ignore_connection_headers: bool,
    pub timeout: i32,
    /// The function's own method, or the `methodName` argument for `CallRequest`.
    pub method: String,
    /// `None` when the function has no `payload` parameter or the step left it unset.
    pub payload: Option<Value>,
    pub download_as_a_file: bool,
    pub file_name: String,
    pub file_location: String,
    pub file_client_code: String,
    pub file_type: String,
    pub file_override: bool,
}

/// What the files service and security give the download path (`IFeignFilesService.create`,
/// `doesClientManageClientCode`), provided by the core crate.
#[async_trait]
pub trait DownloadSink: Send + Sync {
    async fn does_client_manage_client_code(&self, managing: &str, client: &str) -> ConnResult<bool>;
    /// `POST /api/files/internal/{fileType}` with the bytes; the stored file's details.
    async fn create_file(
        &self,
        file_type: &str,
        client_code: &str,
        override_: bool,
        file_path: &str,
        file_name: &str,
        bytes: Vec<u8>,
    ) -> ConnResult<Map<String, Value>>;
}

/// `JsonElement.getAsString()` on an argument map value.
fn arg_string(v: &Value) -> ConnResult<String> {
    match v {
        Value::String(s) => Ok(s.clone()),
        Value::Bool(b) => Ok(b.to_string()),
        Value::Number(_) => Ok(json::gson_element(v)),
        Value::Array(a) if a.len() == 1 => arg_string(&a[0]),
        Value::Null => Err(ConnError::other("JsonNull")),
        Value::Object(_) => Err(ConnError::other("JsonObject")),
        Value::Array(a) => Err(ConnError::other(format!("Array must have size 1, but has size {}", a.len()))),
    }
}

/// Builds the `RestRequest` `CallRequest.internalExecute` builds. An argument that is not a
/// string fails here, before the call (Java throws it out of `internalExecute`).
pub fn rest_request(args: &CallArgs) -> ConnResult<RestRequest> {
    let mut headers: Vec<(String, Vec<String>)> = Vec::new();
    for (k, v) in &args.headers {
        let v = arg_string(v)?;
        match headers.iter_mut().find(|(n, _)| n == k) {
            Some((_, vs)) => vs.push(v),
            None => headers.push((k.clone(), vec![v])),
        }
    }
    let mut path = HashMap::new();
    for (k, v) in &args.path_params {
        path.insert(k.clone(), arg_string(v)?);
    }
    // A `HashMap`: the query goes out in Java's hash order.
    let mut query = Map::new();
    for (k, v) in &args.query_params {
        query.insert(k.clone(), Value::String(arg_string(v)?));
    }
    let query: Vec<(String, String)> = java::hash_map_order(query)
        .into_iter()
        .map(|(k, v)| (k, v.as_str().unwrap_or_default().to_string()))
        .collect();
    Ok(RestRequest {
        url: args.url.clone(),
        headers: if headers.is_empty() { None } else { Some(headers) },
        path_parameters: path,
        query_parameters: if query.is_empty() { None } else { Some(query) },
        timeout: args.timeout,
        method: args.method.clone(),
        payload: args.payload.clone(),
        ignore_default_headers: args.ignore_connection_headers,
    })
}

fn event_map(data: Value, headers: Value, status: i32) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("data".into(), data);
    m.insert("headers".into(), headers);
    m.insert("statusCode".into(), Value::from(status));
    m
}

/// `processOutput`.
pub fn output_events(r: &RestResponse) -> Vec<Event> {
    vec![Event { name: EVENT_OUTPUT, result: event_map(r.data.to_gson_tree(), r.headers_json(), r.status) }]
}

/// `makeErrorResponseFunctionOutput`.
pub fn error_response_events(r: &RestResponse) -> Vec<Event> {
    vec![
        Event { name: EVENT_ERROR, result: event_map(r.data.to_gson_tree(), r.headers_json(), r.status) },
        Event { name: EVENT_OUTPUT, result: event_map(Value::Object(Map::new()), Value::Object(Map::new()), r.status) },
    ]
}

/// `makeExceptionResponseFunctionOutput`.
pub fn exception_events(e: &ConnError) -> Vec<Event> {
    let (status, data) = match e {
        ConnError::Feign { status, body, message } if *status >= 100 => {
            (*status, body.clone().unwrap_or_else(|| Value::String(message.clone())))
        }
        other => (NO_RESPONSE_STATUS, Value::String(other.message().to_string())),
    };
    vec![
        Event { name: EVENT_ERROR, result: event_map(data, Value::Object(Map::new()), status) },
        Event { name: EVENT_OUTPUT, result: event_map(Value::Object(Map::new()), Value::Object(Map::new()), status) },
    ]
}

/// Runs the call for a step. `Err` is an argument problem that fails the step itself;
/// `Ok(None)` is Java's empty output (a download by a caller [`Downloader::of`] refuses).
pub async fn call(
    svc: &Connections,
    caller: &Caller,
    args: &CallArgs,
    downloads: Option<&dyn DownloadSink>,
) -> ConnResult<Option<Vec<Event>>> {
    let request = rest_request(args)?;
    let result = do_call(
        svc,
        caller,
        Some(&args.app_code),
        Some(&args.client_code),
        &args.connection_name,
        request,
        args.download_as_a_file,
    )
    .await;
    let response = match result {
        Ok(r) => r,
        Err(e) => return Ok(Some(exception_events(&e))),
    };
    if response.status >= 400 && response.status <= 600 {
        return Ok(Some(error_response_events(&response)));
    }
    if !args.download_as_a_file {
        return Ok(Some(output_events(&response)));
    }
    match process_download(caller, args, response, downloads).await {
        Ok(Some(r)) => Ok(Some(output_events(&r))),
        Ok(None) => Ok(None),
        Err(e) => Ok(Some(exception_events(&e))),
    }
}

/// Who stores a downloaded file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Downloader {
    /// A signed-in caller (Java): the file goes to their client, or to `fileClientCode` when the
    /// URL's client manages it, as the `fileType` the step asks for.
    User,
    /// A webhook or event run (Rust only): anonymous, but acting for the run's own client, so a
    /// provider's recording or media can be stored. The file goes to that client, or to
    /// `fileClientCode` when the run's client manages it, always as [`RUN_FILE_TYPE`].
    Run,
}

impl Downloader {
    /// Java stores a download only for a signed-in caller; core's webhook and event runs
    /// (`Authorities._Webhook`, `Authorities._Event_Runner`) may as well. A browser's anonymous
    /// caller holds neither, so it still gets nothing.
    pub fn of(caller: &Caller) -> Option<Self> {
        if !caller.present {
            None
        } else if caller.authenticated {
            Some(Self::User)
        } else if caller.has_authority(WEBHOOK_AUTHORITY) || caller.has_authority(EVENT_RUNNER_AUTHORITY) {
            Some(Self::Run)
        } else {
            None
        }
    }

    /// The client whose management of `fileClientCode` is checked.
    fn managing(self, caller: &Caller) -> &str {
        match self {
            Self::User => caller.url_client_code.as_deref().unwrap_or(""),
            Self::Run => caller.client_code(),
        }
    }

    fn file_type(self, asked: &str) -> &str {
        match self {
            Self::User => asked,
            Self::Run => RUN_FILE_TYPE,
        }
    }
}

async fn process_download(
    caller: &Caller,
    args: &CallArgs,
    mut response: RestResponse,
    downloads: Option<&dyn DownloadSink>,
) -> ConnResult<Option<RestResponse>> {
    let Some(who) = Downloader::of(caller) else {
        return Ok(None);
    };
    let ca_client = caller.client_code.clone().unwrap_or_default();
    let client = if java::is_blank(&args.file_client_code) || ca_client == args.file_client_code {
        ca_client.clone()
    } else {
        let sink = downloads.ok_or_else(|| ConnError::other("No files service"))?;
        let managing = who.managing(caller);
        if sink.does_client_manage_client_code(managing, &args.file_client_code).await? {
            args.file_client_code.clone()
        } else {
            String::new()
        }
    };
    if java::is_blank(&client) {
        return Err(ConnError::other("Client code is invalid"));
    }
    let RestData::Binary(bytes) = &response.data else {
        return Err(ConnError::other("Data is not a file"));
    };
    let name = resolve_file_name(&response, &args.url, &args.file_name, &short_uuid())?;
    let sink = downloads.ok_or_else(|| ConnError::other("No files service"))?;
    let file = sink
        .create_file(who.file_type(&args.file_type), &client, args.file_override, &args.file_location, &name, bytes.clone())
        .await?;
    response.data = RestData::Json(Value::Object(file));
    Ok(Some(response))
}

/// `resolveFileName`: the given name (or `file<shortUUID>`), with the extension taken from the
/// response's `Content-Type` subtype, else from the URL after its first dot, else from the
/// `Content-Disposition` file name.
pub fn resolve_file_name(r: &RestResponse, url: &str, file_name: &str, unique: &str) -> ConnResult<String> {
    let empty = java::is_blank(file_name);
    let mut final_name = if empty { format!("file{unique}") } else { file_name.to_string() };
    let without_ext = if empty {
        final_name.clone()
    } else if final_name.contains('.') {
        final_name[..final_name.rfind('.').unwrap_or(final_name.len())].to_string()
    } else {
        final_name.clone()
    };

    // Header names ignore case, as Spring's HttpHeaders did: providers send `content-type` too.
    let header = |name: &str| r.headers.as_ref().and_then(|h| h.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone()));

    if let Some(ct) = header("Content-Type").filter(|v| !java::is_blank(v)) {
        let ext = MediaType::parse(&ct)?.subtype;
        return Ok(format!("{without_ext}.{ext}"));
    }

    if let Some(dot) = url.find('.') {
        let end = url.find('?').unwrap_or(url.len());
        let ext = url.get(dot + 1..end).ok_or_else(|| {
            ConnError::other(format!("begin {}, end {end}, length {}", dot + 1, url.len()))
        })?;
        return Ok(format!("{without_ext}.{ext}"));
    }

    let cd = header("Content-Disposition").or_else(|| header("content-disposition"));
    if let Some(cd) = cd.filter(|v| !java::is_blank(v)) {
        if let Some(cd_name) = parse_content_disposition_file_name(&cd).filter(|n| !java::is_blank(n) && n.contains('.')) {
            let ext = &cd_name[cd_name.rfind('.').map(|i| i + 1).unwrap_or(0)..];
            final_name = if empty { cd_name.clone() } else { format!("{without_ext}.{ext}") };
            return Ok(final_name);
        }
    }
    Ok(final_name)
}

/// `parseContentDispositionForFileName`.
pub fn parse_content_disposition_file_name(cd: &str) -> Option<String> {
    let index = cd.find("filename")? + "filename".len();
    let rest = &cd[index..];
    match rest.chars().next() {
        Some('=') => {
            let after = &rest[1..];
            if let Some(quoted) = after.strip_prefix('"') {
                let end = quoted.find('"').unwrap_or(quoted.len());
                Some(quoted[..end].to_string())
            } else {
                let end = after.find(';').unwrap_or(after.len());
                Some(after[..end].to_string())
            }
        }
        Some('*') => {
            // filename*=charset'lang'value
            let after = rest.get(2..)?;
            let first = after.find('\'')?;
            let rest2 = &after[first + 1..];
            let second = rest2.find('\'')?;
            Some(percent_encoding::percent_decode_str(&rest2[second + 1..].replace('+', " ")).decode_utf8_lossy().into_owned())
        }
        _ => None,
    }
}

/// `UniqueUtil.shortUUID()`: a random UUID's 128 bits (as a signed number) in base 62,
/// left-padded with `0` to 22 characters.
pub fn short_uuid() -> String {
    const BASE: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut num = i128::from_be_bytes(*uuid::Uuid::new_v4().as_bytes());
    let mut out = Vec::new();
    while num != 0 {
        out.push(BASE[num.rem_euclid(62) as usize]);
        num /= 62;
    }
    out.reverse();
    let s = String::from_utf8(out).unwrap_or_default();
    format!("{s:0>22}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// CallRequestErrorOutputTest.
    #[test]
    fn http_error_carries_the_real_status_on_both_events() {
        let r = RestResponse { data: RestData::Text("missing".into()), headers: Some(vec![]), status: 404 };
        let events = error_response_events(&r);
        assert_eq!(events[0].name, "error");
        assert_eq!(events[1].name, "output");
        for e in &events {
            assert_eq!(e.result["statusCode"], json!(404));
        }
        assert_eq!(events[0].result["data"], json!("missing"));
        assert_eq!(events[1].result["data"], json!({}));
    }

    #[test]
    fn exception_without_response_reports_500() {
        let events = exception_events(&ConnError::other("slow"));
        assert_eq!(events[0].result["statusCode"], json!(500));
        assert_eq!(events[1].result["statusCode"], json!(500));
        assert_eq!(events[0].result["data"], json!("slow"));
        assert_eq!(events[0].result["headers"], json!({}));
    }

    #[test]
    fn feign_exception_reports_its_own_status() {
        let events = exception_events(&ConnError::Feign { status: 403, message: "Forbidden".into(), body: None });
        assert_eq!(events[0].result["statusCode"], json!(403));
        assert_eq!(events[1].result["statusCode"], json!(403));
    }

    #[test]
    fn made_up_responses_have_null_headers() {
        let r = RestResponse::message(http::StatusCode::INTERNAL_SERVER_ERROR, "Connection Not found");
        let e = error_response_events(&r);
        assert_eq!(e[0].result["headers"], Value::Null);
        assert_eq!(e[0].result["data"], json!("Connection Not found"));
    }

    #[test]
    fn request_from_arguments() {
        let args = CallArgs {
            headers: json!({"X-A": "1", "n": 2}).as_object().unwrap().clone(),
            query_params: json!({"notFoundPage": "b", "defaultPage": "a"}).as_object().unwrap().clone(),
            method: "GET".into(),
            ..Default::default()
        };
        let r = rest_request(&args).unwrap();
        assert_eq!(r.headers.unwrap(), vec![("X-A".to_string(), vec!["1".to_string()]), ("n".to_string(), vec!["2".to_string()])]);
        assert_eq!(r.query_parameters.unwrap(), vec![("defaultPage".to_string(), "a".to_string()), ("notFoundPage".to_string(), "b".to_string())]);
        let bad = CallArgs { headers: json!({"x": {}}).as_object().unwrap().clone(), ..Default::default() };
        assert!(rest_request(&bad).is_err());
    }

    fn run_caller(authenticated: bool, authorities: &[&str]) -> Caller {
        Caller {
            present: true,
            authenticated,
            client_code: Some("FIN".into()),
            url_client_code: Some("URLC".into()),
            authorities: authorities.iter().map(|a| a.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn who_may_store_a_download() {
        assert_eq!(Downloader::of(&run_caller(true, &[])), Some(Downloader::User));
        assert_eq!(Downloader::of(&run_caller(false, &["Authorities._Anonymous", WEBHOOK_AUTHORITY])), Some(Downloader::Run));
        assert_eq!(Downloader::of(&run_caller(false, &["Authorities._Anonymous", EVENT_RUNNER_AUTHORITY])), Some(Downloader::Run));
        assert_eq!(Downloader::of(&run_caller(false, &["Authorities._Anonymous"])), None, "a browser's anonymous caller");
        assert_eq!(Downloader::of(&Caller { authorities: vec![WEBHOOK_AUTHORITY.into()], ..Default::default() }), None, "no context at all");
        assert_eq!(Downloader::User.file_type("static"), "static");
        assert_eq!(Downloader::Run.file_type("static"), "secured");
        let c = run_caller(false, &[]);
        assert_eq!(Downloader::User.managing(&c), "URLC");
        assert_eq!(Downloader::Run.managing(&c), "FIN");
    }

    /// Records each managing question and each stored file; manages only `managed`.
    #[derive(Default)]
    struct Sink {
        managed: Vec<(&'static str, &'static str)>,
        asked: parking_lot::Mutex<Vec<(String, String)>>,
        stored: parking_lot::Mutex<Vec<(String, String, String)>>,
    }

    #[async_trait]
    impl DownloadSink for Sink {
        async fn does_client_manage_client_code(&self, managing: &str, client: &str) -> ConnResult<bool> {
            self.asked.lock().push((managing.into(), client.into()));
            Ok(self.managed.iter().any(|(m, c)| *m == managing && *c == client))
        }
        async fn create_file(&self, ty: &str, cc: &str, _: bool, path: &str, name: &str, _: Vec<u8>) -> ConnResult<Map<String, Value>> {
            self.stored.lock().push((ty.into(), cc.into(), format!("{path}{name}")));
            Ok(json!({"name": name}).as_object().unwrap().clone())
        }
    }

    fn recording() -> RestResponse {
        RestResponse {
            data: RestData::Binary(b"ID3".to_vec()),
            headers: Some(vec![("Content-Type".into(), "audio/mpeg".into())]),
            status: 200,
        }
    }

    fn download_args(file_client_code: &str) -> CallArgs {
        CallArgs {
            download_as_a_file: true,
            file_name: "rec".into(),
            file_location: "/calls/".into(),
            file_type: "static".into(),
            file_client_code: file_client_code.into(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn webhook_and_event_runs_store_secured_files_for_their_client() {
        for authority in [WEBHOOK_AUTHORITY, EVENT_RUNNER_AUTHORITY] {
            let sink = Sink::default();
            let c = run_caller(false, &["Authorities._Anonymous", authority]);
            let out = process_download(&c, &download_args(""), recording(), Some(&sink)).await.unwrap().unwrap();
            assert_eq!(out.data, RestData::Json(json!({"name": "rec.mpeg"})));
            assert_eq!(sink.stored.lock()[0], ("secured".to_string(), "FIN".to_string(), "/calls/rec.mpeg".to_string()));
            // Its own code named outright is no foreign client.
            process_download(&c, &download_args("FIN"), recording(), Some(&sink)).await.unwrap().unwrap();
            assert!(sink.asked.lock().is_empty());
        }
    }

    #[tokio::test]
    async fn a_run_stores_for_another_client_only_when_its_client_manages_it() {
        let c = run_caller(false, &[WEBHOOK_AUTHORITY]);
        let sink = Sink { managed: vec![("FIN", "CHILD")], ..Default::default() };
        process_download(&c, &download_args("CHILD"), recording(), Some(&sink)).await.unwrap().unwrap();
        assert_eq!(sink.stored.lock()[0].1, "CHILD");
        let err = process_download(&c, &download_args("OTHER"), recording(), Some(&sink)).await.unwrap_err();
        assert_eq!(err.message(), "Client code is invalid");
        // The run's client is asked, never the URL client a signed-in caller is checked by.
        assert_eq!(*sink.asked.lock(), vec![("FIN".to_string(), "CHILD".to_string()), ("FIN".to_string(), "OTHER".to_string())]);
        assert_eq!(sink.stored.lock().len(), 1);
    }

    #[tokio::test]
    async fn signed_in_callers_keep_the_java_rules_and_anonymous_ones_get_nothing() {
        let sink = Sink { managed: vec![("URLC", "CHILD")], ..Default::default() };
        let user = run_caller(true, &[]);
        process_download(&user, &download_args("CHILD"), recording(), Some(&sink)).await.unwrap().unwrap();
        assert_eq!(sink.stored.lock()[0], ("static".to_string(), "CHILD".to_string(), "/calls/rec.mpeg".to_string()));
        assert_eq!(sink.asked.lock()[0].0, "URLC");

        let anon = run_caller(false, &["Authorities._Anonymous"]);
        assert!(process_download(&anon, &download_args(""), recording(), Some(&sink)).await.unwrap().is_none());
        assert_eq!(sink.stored.lock().len(), 1);
    }

    #[test]
    fn file_names() {
        let with = |h: Vec<(&str, &str)>| RestResponse {
            data: RestData::Binary(vec![]),
            headers: Some(h.into_iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()),
            status: 200,
        };
        assert_eq!(resolve_file_name(&with(vec![("Content-Type", "application/pdf")]), "u", "report.x", "U").unwrap(), "report.pdf");
        // Header names ignore case: a provider's `content-type` names the extension too.
        assert_eq!(resolve_file_name(&with(vec![("content-type", "application/pdf")]), "https://h.com/a", "", "U").unwrap(), "fileU.pdf");
        assert_eq!(resolve_file_name(&with(vec![("CONTENT-TYPE", "audio/mpeg")]), "https://h.com/rec", "call1", "U").unwrap(), "call1.mpeg");
        assert_eq!(
            resolve_file_name(&with(vec![("content-disposition", "attachment; filename=\"r.csv\"")]), "nodot", "", "U").unwrap(),
            "r.csv"
        );
        assert_eq!(parse_content_disposition_file_name("attachment; filename*=UTF-8''na%C3%AFve.txt").unwrap(), "naïve.txt");
        assert_eq!(short_uuid().len(), 22);
    }
}
