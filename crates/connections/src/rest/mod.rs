//! REST connections: `RestService` (dispatch by sub type), `BasicRestService` (the call
//! itself), `OAuth2RestService` and `RestAuthService` (a token, then the basic call), and
//! `CallRequest`'s reading of the result.

pub mod auth;
pub mod basic;
pub mod body;
pub mod call;
pub mod http;
pub mod media_type;
pub mod oauth2;
pub mod spring_uri;

use std::collections::HashMap;

use ::http::StatusCode;
use serde_json::Value;

use crate::connection::{self, ConnectionSubType, ConnectionType};
use crate::context::Caller;
use crate::error::ConnResult;
use crate::java::json;
use crate::rest::call::{EVENT_RUNNER_AUTHORITY, WEBHOOK_AUTHORITY};
use crate::Connections;

/// `RestRequest`.
#[derive(Debug, Clone)]
pub struct RestRequest {
    pub url: String,
    /// A `MultiValueMap`: names as given, values in order. `None` when the step set none.
    pub headers: Option<Vec<(String, Vec<String>)>>,
    pub path_parameters: HashMap<String, String>,
    /// In the order Java iterates them (`CallRequest` builds a `HashMap`).
    pub query_parameters: Option<Vec<(String, String)>>,
    /// Seconds; `CallRequest` passes the step's value (0 means the connection's or 300).
    pub timeout: i32,
    pub method: String,
    /// `None` is Java's `null` (no payload argument); `Some(Value::Null)` is a JSON null.
    pub payload: Option<Value>,
    pub ignore_default_headers: bool,
}

impl Default for RestRequest {
    fn default() -> Self {
        Self {
            url: String::new(),
            headers: None,
            path_parameters: HashMap::new(),
            query_parameters: None,
            timeout: 300,
            method: "GET".into(),
            payload: None,
            ignore_default_headers: false,
        }
    }
}

impl RestRequest {
    /// `MultiValueMap.add`: appends to the exactly-named entry, or adds one.
    pub fn add_header(&mut self, name: &str, value: &str) {
        let headers = self.headers.get_or_insert_with(Vec::new);
        match headers.iter_mut().find(|(k, _)| k == name) {
            Some((_, v)) => v.push(value.to_string()),
            None => headers.push((name.to_string(), vec![value.to_string()])),
        }
    }
}

/// What `RestResponse.data` holds.
#[derive(Debug, Clone, PartialEq)]
pub enum RestData {
    None,
    /// A text body, or one of the messages the services put in `data`.
    Text(String),
    /// A JSON body as Gson read it (numbers inside maps and lists are doubles).
    Json(Value),
    /// A binary body (`byte[]`).
    Binary(Vec<u8>),
}

impl RestData {
    /// `gson.toJsonTree(data)`: a `byte[]` is an array of signed byte values, and null map
    /// members disappear.
    pub fn to_gson_tree(&self) -> Value {
        match self {
            RestData::None => Value::Null,
            RestData::Text(s) => Value::String(s.clone()),
            RestData::Json(v) => json::gson_tree(v.clone()),
            RestData::Binary(b) => Value::Array(b.iter().map(|x| Value::from(*x as i8)).collect()),
        }
    }
}

/// `RestResponse`.
#[derive(Debug, Clone, PartialEq)]
pub struct RestResponse {
    pub data: RestData,
    /// `toSingleValueMap()` of the response headers; `None` on the responses the services
    /// make up themselves.
    pub headers: Option<Vec<(String, String)>>,
    pub status: i32,
}

impl RestResponse {
    pub fn message(status: StatusCode, text: impl Into<String>) -> Self {
        Self { data: RestData::Text(text.into()), headers: None, status: status.as_u16() as i32 }
    }

    pub fn headers_json(&self) -> Value {
        match &self.headers {
            None => Value::Null,
            Some(h) => Value::Object(h.iter().map(|(k, v)| (k.clone(), Value::String(v.clone()))).collect()),
        }
    }
}

/// `RestService.doCall`: resolves the codes, reads the REST connection the caller may use, and
/// calls it through its sub type's service. A missing connection is a 500 "Connection Not
/// found" response, not an error.
pub async fn do_call(
    svc: &Connections,
    caller: &Caller,
    app_code: Option<&str>,
    client_code: Option<&str>,
    connection_name: &str,
    request: RestRequest,
    file_download: bool,
) -> ConnResult<RestResponse> {
    let (app, client) = caller.resolve_app_and_client(app_code, client_code);
    let not_found = || RestResponse::message(StatusCode::INTERNAL_SERVER_ERROR, "Connection Not found");
    let (Some(app), Some(client)) = (app, client) else { return Ok(not_found()) };

    let Some(conn) =
        connection::read(svc.store.as_ref(), caller, connection_name, &app, &client, ConnectionType::RestApi).await?
    else {
        return Ok(not_found());
    };

    let response = match conn.connection_sub_type {
        Some(ConnectionSubType::RestApiBasic) => basic::call(svc, &conn, request, file_download).await?,
        Some(ConnectionSubType::RestApiOAuth2) => {
            let token_client = token_client(svc, caller, &client).await?;
            oauth2::call_with_token_client(svc, caller, token_client.as_deref(), &conn, request, file_download).await?
        }
        Some(ConnectionSubType::RestApiAuth) => auth::call(svc, caller, &conn, request, file_download).await?,
        // `Mono.just(services.get(subType))` with no service for the sub type: Reactor's
        // null check fails with this message.
        _ => return Err(crate::error::ConnError::other("value")),
    };
    // A call that reached a connection but completed empty says so, rather than blaming the
    // lookup.
    Ok(response.unwrap_or_else(|| {
        RestResponse::message(StatusCode::INTERNAL_SERVER_ERROR, format!("No response from connection {connection_name}"))
    }))
}

/// The client whose OAuth2 token a REST step uses (LZT-2106). Java always used the caller's own
/// client, so a SYSTEM run (an anonymous webhook, a scheduled `_Event_Runner` intake) naming
/// FIN's connection looked up SYSTEM's token and failed. Here the step's client is used instead
/// when every one of these holds; otherwise the caller's own client, exactly as before:
/// - the step names a client other than the caller's;
/// - the step runs inside a stored KIRun definition (`in_kirun`), never a direct HTTP execution
///   of `CoreServices.REST.*`, whose arguments the HTTP caller chooses;
/// - the caller is signed in, or is a webhook or event run (`_Webhook`, `_Event_Runner`), never
///   a browser's anonymous visitor (the same callers [`call::Downloader::of`] accepts);
/// - the caller's client is SYSTEM, or manages the step's client in security's hierarchy.
pub async fn token_client(svc: &Connections, caller: &Caller, step_client: &str) -> ConnResult<Option<String>> {
    let own = caller.client_code.clone();
    let Some(own_code) = own.as_deref() else { return Ok(own) };
    if !caller.present || own_code == step_client || crate::java::is_blank(step_client) || !caller.in_kirun {
        return Ok(own);
    }
    let acts_as_itself = caller.authenticated || caller.has_authority(WEBHOOK_AUTHORITY) || caller.has_authority(EVENT_RUNNER_AUTHORITY);
    if !acts_as_itself {
        return Ok(own);
    }
    if caller.system_client {
        return Ok(Some(step_client.to_string()));
    }
    match svc.hierarchy.as_deref() {
        Some(h) if h.does_client_manage_client_code(own_code, step_client).await? => Ok(Some(step_client.to_string())),
        _ => Ok(own),
    }
}
