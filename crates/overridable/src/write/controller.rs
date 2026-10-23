//! The commons-mongo controllers (`AbstractOverridableDataController`, its Mongo and
//! updatable bases, `AbstractVersionController`, `AbstractPublishController`,
//! `AbstractTransportController`) as functions from a parsed request to a [`Reply`]: what the
//! route answers, status, headers and body, written the way the Java services write it
//! (Jackson, indented, `NON_EMPTY`). The HTTP layer only extracts the caller, the path, the
//! query and the body; [`crate::write::router`] does that with axum.

use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use platform::error::{coded_response, input, AppError, AppResult, Coded};
use platform::http::spring_security_headers;
use platform::security::{ContextAuthentication, OnBehalfOf};

use crate::json::{parse, to_jackson_pretty, JMap, JValue};
use crate::pojo::{convert_json, to_jackson};
use crate::write::condition::Query;
use crate::write::deletion::DeletionService;
use crate::write::draft::DRAFT;
use crate::write::kind::Kind;
use crate::write::messages as msg;
use crate::write::publish::PublishService;
use crate::write::service::OverridableService;
use crate::write::spring::{Pageable, Params};
use crate::write::transport::{TransportRequest, TransportService};
use crate::write::version::VersionStore;

/// `AbstractOverridableDataController.DRAFT_VERSION_HEADER`.
pub const DRAFT_VERSION_HEADER: &str = "X-Draft-Version";

#[derive(Debug, Clone, PartialEq)]
pub enum ReplyBody {
    /// No body (`ResponseEntity.badRequest().build()`, or an empty Mono's 200).
    Empty,
    Json(JValue),
    File { content_type: &'static str, bytes: Vec<u8> },
}

/// What a route answers.
#[derive(Debug, Clone, PartialEq)]
pub struct Reply {
    pub status: StatusCode,
    pub headers: Vec<(String, String)>,
    pub body: ReplyBody,
}

impl Reply {
    pub fn json(v: JValue) -> Self {
        Self { status: StatusCode::OK, headers: Vec::new(), body: ReplyBody::Json(v) }
    }

    pub fn empty(status: StatusCode) -> Self {
        Self { status, headers: Vec::new(), body: ReplyBody::Empty }
    }

    pub fn header(mut self, name: &str, value: String) -> Self {
        self.headers.push((name.to_string(), value));
        self
    }

    /// The JSON body, if any.
    pub fn json_body(&self) -> Option<&JValue> {
        match &self.body {
            ReplyBody::Json(v) => Some(v),
            _ => None,
        }
    }
}

impl IntoResponse for Reply {
    fn into_response(self) -> Response {
        let mut h = HeaderMap::new();
        spring_security_headers(&mut h, true);
        for (k, v) in &self.headers {
            if let (Ok(name), Ok(value)) = (header::HeaderName::try_from(k.as_str()), HeaderValue::from_str(v)) {
                h.insert(name, value);
            }
        }
        let bytes = match self.body {
            ReplyBody::Empty => Vec::new(),
            ReplyBody::Json(v) => {
                h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
                to_jackson_pretty(&v).into_bytes()
            }
            ReplyBody::File { content_type, bytes } => {
                h.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
                bytes
            }
        };
        // Not `(status, headers, Vec<u8>)`: axum would add `application/octet-stream` to a body
        // Java sends without any content type (the empty replies).
        let mut resp = Response::new(axum::body::Body::from(bytes));
        *resp.status_mut() = self.status;
        *resp.headers_mut() = h;
        resp
    }
}

/// A refusal Spring makes before the controller method runs: an unreadable body, a missing or
/// unconvertible parameter, a missing header or part. Java's `ControllerAdvice` answers these
/// `ResponseStatusException`s with their status, the generic "Please try again" message with an
/// exception id, and Spring's text (`400 BAD_REQUEST "..."`) as the debug message. Carried as
/// an `AppError::Internal`; [`error_response`] renders it (the routers use it) with the code
/// that names what was wrong, Spring's text staying in `debugMessage`.
#[derive(Debug)]
pub struct SpringRefusal {
    pub status: StatusCode,
    pub reason: String,
    /// The code when the refusal knows more than its text says (the parameter's name).
    pub code: Option<Coded>,
}

impl std::fmt::Display for SpringRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = self.status.canonical_reason().unwrap_or("").to_ascii_uppercase().replace(' ', "_");
        write!(f, "{} {} \"{}\"", self.status.as_u16(), name, self.reason)
    }
}

impl std::error::Error for SpringRefusal {}

pub fn spring_refusal(status: StatusCode, reason: impl Into<String>) -> AppError {
    AppError::Internal(anyhow::Error::new(SpringRefusal { status, reason: reason.into(), code: None }))
}

/// [`spring_refusal`] said by `code` (which names the parameter Spring's text leaves out).
pub fn spring_refusal_coded(status: StatusCode, reason: impl Into<String>, code: Coded) -> AppError {
    AppError::Internal(anyhow::Error::new(SpringRefusal { status, reason: reason.into(), code: Some(code) }))
}

/// The code that says what Spring refused, from its text: the header, parameter or part named
/// when the text names it.
pub fn spring_code(status: StatusCode, reason: &str) -> Coded {
    crate::catalogue::register();
    let quoted = |prefix: &str| reason.strip_prefix(prefix).and_then(|r| r.split('\'').next()).filter(|n| !n.trim().is_empty());
    let code = if let Some(h) = quoted("Required header '") {
        input::header_missing(h)
    } else if reason.starts_with("Required header") || reason.starts_with("Missing request header") {
        Coded::new("COMMON.HEADER_MISSING")
    } else if let Some(p) = quoted("Required query parameter '").or_else(|| quoted("Required parameter '")) {
        input::param_missing(p)
    } else if let Some(p) = quoted("Required part '").or_else(|| quoted("Required request part '")) {
        input::field_missing(p)
    } else if reason.starts_with("No request body") {
        input::body_missing()
    } else if reason.starts_with("Failed to read HTTP message") {
        input::body_unreadable(None)
    } else if reason.starts_with("Type mismatch") {
        Coded::new("COMMON.PARAM_INVALID")
    } else {
        match status {
            StatusCode::METHOD_NOT_ALLOWED => Coded::new("COMMON.METHOD_NOT_ALLOWED"),
            StatusCode::PAYLOAD_TOO_LARGE => Coded::new("COMMON.PAYLOAD_TOO_LARGE"),
            StatusCode::UNSUPPORTED_MEDIA_TYPE => Coded::new("COMMON.BODY_NOT_JSON"),
            s if s.is_server_error() => Coded::new("COMMON.INTERNAL_ERROR"),
            _ => Coded::new("COMMON.BAD_REQUEST"),
        }
    };
    code.status(status)
}

/// An error as the Java services write it, coded: a [`SpringRefusal`] names what was wrong
/// (Spring's text in `debugMessage`), any other unexpected failure is `COMMON.INTERNAL_ERROR`
/// with the cause for support, and the rest as the platform renders an `AppError`.
pub fn error_response(e: AppError) -> Response {
    match e {
        AppError::Internal(err) => match err.downcast_ref::<SpringRefusal>() {
            Some(r) => {
                let code = r.code.clone().unwrap_or_else(|| spring_code(r.status, &r.reason));
                coded_response(&code.status(r.status).debug(r.to_string()))
            }
            None => coded_response(&Coded::new("COMMON.INTERNAL_ERROR").debug(format!("{err:#}"))),
        },
        other => other.into_response(),
    }
}

fn bad_request(message: &str) -> AppError {
    spring_refusal(StatusCode::BAD_REQUEST, message)
}

/// Spring's "Type mismatch." for the query parameter `name`, which a person reads as `expected`.
fn type_mismatch(name: &str, expected: &str) -> AppError {
    spring_refusal_coded(StatusCode::BAD_REQUEST, "Type mismatch.", input::param_invalid(name, Some(expected)))
}

/// A request body read into the class (`@RequestBody D`).
pub fn read_entity(pojo: &'static crate::pojo::Pojo, body: &[u8]) -> AppResult<JMap> {
    match parse(body) {
        Ok(JValue::Object(m)) => Ok(convert_json(pojo, &m)),
        _ => Err(bad_request("Failed to read HTTP message")),
    }
}

/// A `boolean` request parameter as Spring converts it; `default` when absent.
pub fn bool_param(params: &Params, name: &str, default: bool) -> AppResult<bool> {
    match params.first(name).map(|v| v.trim().to_ascii_lowercase()) {
        None => Ok(default),
        Some(v) if matches!(v.as_str(), "true" | "on" | "yes" | "1") => Ok(true),
        Some(v) if matches!(v.as_str(), "false" | "off" | "no" | "0") => Ok(false),
        Some(_) => Err(type_mismatch(name, "true or false")),
    }
}

/// An `Integer`/`int` request parameter; `None` when absent.
pub fn int_param(params: &Params, name: &str) -> AppResult<Option<i64>> {
    match params.first(name) {
        None => Ok(None),
        Some(v) => v
            .trim()
            .parse::<i32>()
            .map(|n| Some(n as i64))
            .map_err(|_| type_mismatch(name, "a whole number")),
    }
}

/// A document as a route answers it: what the kind holds back from replies held back.
fn entity_json<K: Kind>(svc: &OverridableService<K>, e: &JMap) -> JValue {
    JValue::Object(to_jackson(svc.kind().pojo(), &svc.kind().redact(e.clone())))
}

/// A draft row as a route answers it: its content as [`entity_json`] holds it back.
fn draft_json<K: Kind>(svc: &OverridableService<K>, mut draft: JMap) -> JValue {
    if let Some(JValue::Object(c)) = draft.get_mut("content") {
        *c = svc.kind().redact(std::mem::take(c));
    }
    JValue::Object(to_jackson(&DRAFT, &draft))
}

// ── AbstractOverridableDataController ────────────────────────────────

/// `POST` (and `POST ?draft=`): create, or create never-published.
pub async fn post<K: Kind>(svc: &OverridableService<K>, ca: &ContextAuthentication, params: &Params, body: &[u8]) -> AppResult<Reply> {
    let entity = read_entity(svc.kind().pojo(), body)?;
    let created = if params.contains("draft") && bool_param(params, "draft", false)? {
        svc.create_unpublished(ca, entity).await?
    } else {
        svc.create(ca, entity).await?
    };
    Ok(Reply::json(entity_json(svc, &created)))
}

/// `GET /{id}` (and `?draft=`): the object, or the editor's draft with `X-Draft-Version`.
pub async fn get_one<K: Kind>(svc: &OverridableService<K>, ca: &ContextAuthentication, id: &str, params: &Params) -> AppResult<Reply> {
    if params.contains("draft") && bool_param(params, "draft", false)? {
        let (entity, version) = svc.read_draft_with_version(ca, id).await?;
        return Ok(Reply::json(entity_json(svc, &entity)).header(DRAFT_VERSION_HEADER, version.to_string()));
    }
    Ok(Reply::json(entity_json(svc, &svc.read(ca, id).await?)))
}

/// `PUT /{id}` (and `?draft=true[&draftVersion=n]`): update live, or save a draft.
pub async fn put<K: Kind>(svc: &OverridableService<K>, ca: &ContextAuthentication, id: &str, params: &Params, body: &[u8]) -> AppResult<Reply> {
    let mut entity = read_entity(svc.kind().pojo(), body)?;
    entity.insert("id".into(), JValue::Str(id.to_string()));
    if params.contains("draft") {
        if !bool_param(params, "draft", false)? {
            return Ok(Reply::empty(StatusCode::BAD_REQUEST));
        }
        let draft = svc.save_draft(ca, entity, int_param(params, "draftVersion")?).await?;
        return Ok(Reply::json(draft_json(svc, draft)));
    }
    Ok(Reply::json(entity_json(svc, &svc.update(ca, entity).await?)))
}

/// `DELETE /{id}`.
pub async fn delete<K: Kind>(svc: &OverridableService<K>, ca: &ContextAuthentication, id: &str) -> AppResult<Reply> {
    Ok(Reply::json(JValue::Bool(svc.delete(ca, id).await?)))
}

/// `GET` (the list): `readPageFilterLRO`.
pub async fn list<K: Kind>(svc: &OverridableService<K>, ca: &ContextAuthentication, params: &Params) -> AppResult<Reply> {
    let eager = bool_param(params, "eager", false)?;
    let client_only = bool_param(params, "clientOnly", false)?;
    let pageable = Pageable::from_params(params);
    let mut page = svc.read_page_filter_lro(ca, eager, client_only, &pageable, params).await?;
    for row in &mut page.content {
        if let Some(JValue::Object(d)) = row.get_mut("data") {
            *d = svc.kind().redact(std::mem::take(d));
        }
    }
    Ok(Reply::json(page.to_json(&pageable)))
}

/// `GET /nomap2` and `POST /nomap2`: the plain filter routes the overridable controller turns
/// off.
pub fn nomap2() -> Reply {
    Reply::empty(StatusCode::BAD_REQUEST)
}

/// `PATCH /{id}/blueprint`: the whole plan, an empty object clears it, no body is null.
pub async fn patch_blueprint<K: Kind>(svc: &OverridableService<K>, ca: &ContextAuthentication, id: &str, body: &[u8]) -> AppResult<Reply> {
    let blueprint = if body.iter().all(u8::is_ascii_whitespace) {
        None
    } else {
        match parse(body) {
            Ok(JValue::Object(m)) => Some(m),
            Ok(JValue::Null) => None,
            _ => return Err(bad_request("Failed to read HTTP message")),
        }
    };
    Ok(Reply::json(entity_json(svc, &svc.update_blueprint(ca, id, blueprint).await?)))
}

/// `GET /createForClient/{id}/{clientCode}`: an empty 200 for an unknown id.
pub async fn create_for_client<K: Kind>(svc: &OverridableService<K>, ca: &ContextAuthentication, id: &str, client: &str) -> AppResult<Reply> {
    Ok(match svc.create_for_client(ca, id, client).await? {
        Some(e) => Reply::json(entity_json(svc, &e)),
        None => Reply::empty(StatusCode::OK),
    })
}

/// `POST /{id}/fork`.
pub async fn fork<K: Kind>(svc: &OverridableService<K>, ca: &ContextAuthentication, id: &str) -> AppResult<Reply> {
    Ok(Reply::json(entity_json(svc, &svc.fork_for_caller(ca, id).await?)))
}

/// `POST /{id}/publish?message=`.
pub async fn publish<K: Kind>(svc: &OverridableService<K>, ca: &ContextAuthentication, id: &str, params: &Params) -> AppResult<Reply> {
    Ok(Reply::json(entity_json(svc, &svc.publish(ca, id, params.first("message")).await?)))
}

/// `DELETE /{id}/draft`.
pub async fn discard_draft<K: Kind>(svc: &OverridableService<K>, ca: &ContextAuthentication, id: &str) -> AppResult<Reply> {
    Ok(Reply::json(JValue::Bool(svc.discard_draft(ca, id).await?)))
}

// ── AbstractVersionController ────────────────────────────────────────

/// `GET /{id}`: an empty 200 when the row is missing or not the caller's to read.
pub async fn version_read(versions: &VersionStore, ca: &ContextAuthentication, id: &str) -> AppResult<Reply> {
    Ok(match versions.read(ca, id).await? {
        Some(v) => Reply::json(JValue::Object(to_jackson(&crate::write::version::VERSION, &v))),
        None => Reply::empty(StatusCode::OK),
    })
}

/// `POST /{id}/query`.
pub async fn version_query(versions: &VersionStore, ca: &ContextAuthentication, id: &str, body: &[u8]) -> AppResult<Reply> {
    let q = parse(body).map_err(|_| bad_request("Failed to read HTTP message"))?;
    Ok(Reply::json(versions.read_page_per_object_id(ca, id, &Query::from_json(&q)?).await?))
}

// ── AbstractPublishController ────────────────────────────────────────

/// `GET /app/{appCode}/pending?clientCode=`.
pub async fn publish_pending(p: &PublishService, ca: &ContextAuthentication, app: &str, params: &Params) -> AppResult<Reply> {
    Ok(Reply::json(JValue::Object(p.pending(ca, app, params.first("clientCode")).await?)))
}

/// `POST /app/{appCode}?clientCode=`.
pub async fn publish_app(p: &PublishService, ca: &ContextAuthentication, app: &str, params: &Params) -> AppResult<Reply> {
    Ok(Reply::json(JValue::Object(p.publish_all(ca, app, params.first("clientCode")).await?)))
}

// ── DeletionController ───────────────────────────────────────────────

/// `DELETE ?deleteAppCode=`: needs the forwarded host, port, `clientCode` and `appCode`
/// headers (400 without them, as Spring answers a missing `@RequestHeader`).
pub async fn delete_app(d: &DeletionService, ca: &ContextAuthentication, on_behalf: Option<&OnBehalfOf>, params: &Params) -> AppResult<Reply> {
    let on_behalf = on_behalf.ok_or_else(|| bad_request("Required header is not present"))?;
    let app = params.first("deleteAppCode").ok_or_else(|| bad_request("Required query parameter 'deleteAppCode' is not present."))?;
    Ok(match d.delete_everything(ca, on_behalf, app).await? {
        Some(v) => Reply::json(JValue::Bool(v)),
        None => Reply::empty(StatusCode::OK),
    })
}

// ── AbstractTransportController ──────────────────────────────────────

/// `POST` on transports: refused, a transport is uploaded through `createAndApply`.
pub fn transport_post(t: &TransportService) -> AppError {
    t.documents().commons().messages.error_as(
        "DEF.TRANSPORT_UPLOAD_REQUIRED",
        StatusCode::FORBIDDEN,
        msg::TRANSPORT_ERROR,
        &["Creating", "You need to upload a transport file using /createAndApply"],
    )
}

/// `POST /makeTransport` and `/internal/makeTransport`.
pub async fn make_transport(t: &TransportService, ca: &ContextAuthentication, internal: bool, body: &[u8]) -> AppResult<Reply> {
    let req = TransportRequest::from_json(&parse(body).map_err(|_| bad_request("Failed to read HTTP message"))?)?;
    let file = t.make_transport(ca, internal, &req).await?;
    let mut reply = Reply { status: StatusCode::OK, headers: Vec::new(), body: ReplyBody::File { content_type: file.content_type, bytes: file.bytes } };
    if let Some(d) = file.content_disposition {
        reply = reply.header("Content-Disposition", d);
    }
    Ok(reply)
}

/// `GET /applyTransport/{id}`.
pub async fn apply_transport(t: &TransportService, ca: &ContextAuthentication, on_behalf: &OnBehalfOf, id: &str) -> AppResult<Reply> {
    Ok(Reply::json(JValue::Bool(t.apply_transport(ca, on_behalf, id, None, false).await?)))
}

/// `GET /applyTransportCode/{code}`.
pub async fn apply_transport_code(t: &TransportService, ca: &ContextAuthentication, on_behalf: &OnBehalfOf, code: &str) -> AppResult<Reply> {
    Ok(Reply::json(JValue::Bool(t.apply_transport_with_code(ca, on_behalf, code).await?)))
}

/// `POST /internal/cleanupOlderThan?retentionDays=90&limit=200`.
pub async fn cleanup_older_than(t: &TransportService, params: &Params) -> AppResult<Reply> {
    let days = int_param(params, "retentionDays")?.unwrap_or(90);
    let limit = int_param(params, "limit")?.unwrap_or(200);
    Ok(Reply::json(JValue::Object(t.cleanup_older_than(days, limit).await?)))
}

/// `GET /transportTypes`.
pub fn transport_types(t: &TransportService) -> Reply {
    Reply::json(JValue::Array(t.transport_types().into_iter().map(|n| JValue::Str(n.to_string())).collect()))
}

/// `POST /createAndApply` (the file part) and `/internal/createAndApply` (the raw body with
/// `fileName`): `isForBaseApp`, `applicationCode` and `isJson` from the query.
pub async fn create_and_apply(t: &TransportService, ca: &ContextAuthentication, on_behalf: &OnBehalfOf, params: &Params, file_name: &str, bytes: &[u8]) -> AppResult<Reply> {
    let for_base = bool_param(params, "isForBaseApp", false)?;
    let is_json = bool_param(params, "isJson", false)?;
    let transport = t
        .create_and_apply(ca, on_behalf, file_name, bytes, is_json, params.first("applicationCode"), for_base)
        .await?;
    Ok(Reply::json(JValue::Object(to_jackson(&crate::write::transport::TRANSPORT, &transport))))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn body(r: Response) -> (StatusCode, serde_json::Value) {
        let status = r.status();
        (status, serde_json::from_slice(&axum::body::to_bytes(r.into_body(), 100_000).await.unwrap()).unwrap())
    }

    /// Spring's refusals answer with the code that names what was wrong; Spring's text stays the
    /// debug message.
    #[tokio::test]
    async fn spring_refusals_are_coded() {
        for (status, reason, code, field) in [
            (400, "Required header 'appCode' is not present.", "COMMON.HEADER_MISSING", Some(("field", "appCode"))),
            (400, "Required header is not present", "COMMON.HEADER_MISSING", None),
            (400, "Required query parameter 'keys' is not present.", "COMMON.PARAM_MISSING", Some(("field", "keys"))),
            (400, "Required parameter 'filePath' is not present.", "COMMON.PARAM_MISSING", Some(("field", "filePath"))),
            (400, "Required part 'file' is not present.", "COMMON.FIELD_MISSING", Some(("field", "file"))),
            (400, "No request body", "COMMON.BODY_MISSING", None),
            (400, "Failed to read HTTP message", "COMMON.BODY_UNREADABLE", None),
            (400, "Type mismatch.", "COMMON.PARAM_INVALID", None),
            (405, "Request method 'PUT' is not supported", "COMMON.METHOD_NOT_ALLOWED", None),
            (413, "Too large", "COMMON.PAYLOAD_TOO_LARGE", None),
            (415, "Content type 'text/plain' not supported", "COMMON.BODY_NOT_JSON", None),
            (500, "boom", "COMMON.INTERNAL_ERROR", None),
            (400, "Something else", "COMMON.BAD_REQUEST", None),
        ] {
            let status = StatusCode::from_u16(status).unwrap();
            let c = spring_code(status, reason);
            assert_eq!((c.code.as_ref(), c.resolved_status()), (code, status), "{reason}");
            if let Some((k, v)) = field {
                assert!(c.params.contains(&(k.to_string(), v.to_string())), "{reason}: {:?}", c.params);
            }
        }
        let (status, v) = body(error_response(spring_refusal(StatusCode::BAD_REQUEST, "Required header 'clientCode' is not present."))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(v["code"], "COMMON.HEADER_MISSING");
        assert_eq!(v["message"], "The request is missing the clientCode header.");
        assert_eq!(v["debugMessage"], "400 BAD_REQUEST \"Required header 'clientCode' is not present.\"");
        let (_, v) = body(error_response(bool_param(&Params::from_query(Some("draft=maybe")), "draft", false).unwrap_err())).await;
        assert_eq!(v["message"], "The value of the draft parameter is not valid: it should be true or false.");
        let (_, v) = body(error_response(int_param(&Params::from_query(Some("limit=x")), "limit").unwrap_err())).await;
        assert_eq!(v["params"]["expected"], "a whole number");
    }

    #[tokio::test]
    async fn unexpected_failures_name_the_error_id() {
        let (status, v) = body(error_response(AppError::Internal(anyhow::anyhow!("mongo is down")))).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(v["code"], "COMMON.INTERNAL_ERROR");
        assert!(v["message"].as_str().unwrap().contains(v["exceptionId"].as_str().unwrap()));
        assert_eq!(v["debugMessage"], "mongo is down");
        let (status, v) = body(error_response(AppError::new(StatusCode::CONFLICT, "Taken"))).await;
        assert_eq!((status, v["message"].as_str()), (StatusCode::CONFLICT, Some("Taken")));
    }
}
