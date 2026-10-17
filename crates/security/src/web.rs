//! Request parsing and response shapes the security controllers share (security-internal and
//! security-admin): Spring's `@RequestParam` conversions (with the JOOQ controllers' `ULong`
//! binder), `@RequestBody` readers for the common bodies, `ResponseEntity` shapes, and the
//! [`web_route!`] / [`web_route_path!`] macros that give every handler the caller's context first,
//! as `JWTTokenFilter` does.

use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::Response;
use chrono::NaiveDate;
use serde_json::Value;

use crate::condition::{parse as parse_condition, Cond};
use crate::decimal::Dec;
use crate::errors::{AuthError, AuthResult};
use platform::error::{input, Coded};
use crate::handlers::{body, caller, split};
use crate::jackson::{empty, json};
use crate::model::ContextAuth;
use crate::request::RequestInfo;
use crate::service::Auth;
use crate::spring::{Order, Pageable, Params};

/// A handler with the caller's context: `web_route!(name, StateType, "/path/under/api/security",
/// protected, |state, request, context| { ... })`. The state must reach an `auth: Arc<Auth>`
/// field (directly or through `Deref`). `protected` routes refuse an anonymous caller with a
/// bare 401, as Spring Security does outside the permit list.
#[macro_export]
macro_rules! web_route {
    ($name:ident, $state:ty, $path:expr, $protected:expr, |$s:ident, $r:ident, $ca:ident| $body:block) => {
        async fn $name(
            axum::extract::State($s): axum::extract::State<$state>,
            req: axum::extract::Request,
        ) -> axum::response::Response {
            $crate::handlers::respond(
                concat!("/api/security", $path),
                async {
                    let $r = $crate::web::read(req).await?;
                    #[allow(unused_variables)]
                    let $ca = $crate::web::ctx(&$s.auth, &$r, $protected).await?;
                    $body
                }
                .await,
            )
        }
    };
}

/// [`web_route!`] with one path variable, handed to the body as a `String`.
#[macro_export]
macro_rules! web_route_path {
    ($name:ident, $state:ty, $path:expr, $protected:expr, |$s:ident, $r:ident, $ca:ident, $p:ident| $body:block) => {
        async fn $name(
            axum::extract::State($s): axum::extract::State<$state>,
            axum::extract::Path($p): axum::extract::Path<String>,
            req: axum::extract::Request,
        ) -> axum::response::Response {
            $crate::handlers::respond(
                concat!("/api/security", $path),
                async {
                    let $r = $crate::web::read(req).await?;
                    #[allow(unused_variables)]
                    let $ca = $crate::web::ctx(&$s.auth, &$r, $protected).await?;
                    $body
                }
                .await,
            )
        }
    };
}

/// [`web_route!`] with two path variables.
#[macro_export]
macro_rules! web_route_path2 {
    ($name:ident, $state:ty, $path:expr, $protected:expr, |$s:ident, $r:ident, $ca:ident, $p:ident, $q:ident| $body:block) => {
        async fn $name(
            axum::extract::State($s): axum::extract::State<$state>,
            axum::extract::Path(($p, $q)): axum::extract::Path<(String, String)>,
            req: axum::extract::Request,
        ) -> axum::response::Response {
            $crate::handlers::respond(
                concat!("/api/security", $path),
                async {
                    let $r = $crate::web::read(req).await?;
                    #[allow(unused_variables)]
                    let $ca = $crate::web::ctx(&$s.auth, &$r, $protected).await?;
                    $body
                }
                .await,
            )
        }
    };
}

/// The method-not-allowed answer every security router uses.
pub async fn method_not_allowed(method: axum::http::Method) -> Response {
    use axum::response::IntoResponse;
    let cause = format!("405 METHOD_NOT_ALLOWED \"Request method '{method}' is not supported.\"");
    AuthError::input(StatusCode::METHOD_NOT_ALLOWED, cause, Coded::new("COMMON.METHOD_NOT_ALLOWED").param("method", method)).into_response()
}

/// A request as the controllers read it.
pub struct In {
    pub info: RequestInfo,
    pub params: Params,
    pub body: Vec<u8>,
}

pub async fn read(req: Request) -> AuthResult<In> {
    let params = Params::from_query(req.uri().query());
    let (info, body) = split(req).await?;
    Ok(In { info, params, body })
}

/// The caller's context; `protected` paths refuse an anonymous one.
pub async fn ctx(auth: &Auth, r: &In, protected: bool) -> AuthResult<ContextAuth> {
    caller(auth, &r.info, protected).await
}

/// Spring's 400 for a request it could not use; Java's text is the unknown error, the cause its
/// `debugMessage`.
pub fn bad_request(cause: impl Into<String>) -> AuthError {
    AuthError::input(StatusCode::BAD_REQUEST, cause, Coded::new("COMMON.BAD_REQUEST"))
}

/// A `@RequestBody` that was not sent.
pub fn no_body() -> AuthError {
    AuthError::input(StatusCode::BAD_REQUEST, "400 BAD_REQUEST \"No request body\"", input::body_missing())
}

/// A parameter that does not convert; callers that know which one add `field`.
pub fn type_mismatch() -> AuthError {
    AuthError::input(StatusCode::BAD_REQUEST, "400 BAD_REQUEST \"Type mismatch.\"", input::param_invalid("", None))
}

pub fn missing(name: &str) -> AuthError {
    let cause = format!("400 BAD_REQUEST \"Required query parameter '{name}' is not present.\"");
    AuthError::input(StatusCode::BAD_REQUEST, cause, input::param_missing(name))
}

/// A required `@RequestParam String`.
pub fn req_str<'a>(p: &'a Params, name: &str) -> AuthResult<&'a str> {
    p.get(name).ok_or_else(|| missing(name))
}

/// A `ULong` as the controllers' `@InitBinder` converts it (`ULong.valueOf(text)`, a
/// `BigInteger` in range): an optional sign, digits, nothing else; "Type mismatch." otherwise.
pub fn to_u64(v: &str) -> AuthResult<u64> {
    let (negative, digits) = match v.as_bytes().first() {
        Some(b'+') => (false, &v[1..]),
        Some(b'-') => (true, &v[1..]),
        _ => (false, v),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(type_mismatch());
    }
    let n: u64 = digits.parse().map_err(|_| type_mismatch())?;
    if negative && n != 0 {
        return Err(type_mismatch());
    }
    Ok(n)
}

/// A required `@RequestParam ULong`.
pub fn req_u64(p: &Params, name: &str) -> AuthResult<u64> {
    to_u64(req_str(p, name)?).map_err(|e| e.with_param("field", name))
}

/// A `ULong` parameter without `@RequestParam`: optional, `None` when absent.
pub fn opt_u64(p: &Params, name: &str) -> AuthResult<Option<u64>> {
    p.get(name).map(to_u64).transpose().map_err(|e| e.with_param("field", name))
}

/// A required `@RequestParam List<ULong>`: repeated values each convert; a single value may be
/// empty (no ids) but not a comma list (observed: Java answers "Type mismatch.").
pub fn req_u64_list(p: &Params, name: &str) -> AuthResult<Vec<u64>> {
    let values = p.all(name);
    match values.as_slice() {
        [] => Err(missing(name)),
        [one] if one.is_empty() => Ok(vec![]),
        [one] if one.contains(',') => Err(type_mismatch().with_param("field", name).with_param("expected", "one id per parameter, repeated")),
        many => many.iter().map(|v| to_u64(v)).collect::<AuthResult<_>>().map_err(|e| e.with_param("field", name)),
    }
}

/// `ResponseEntity.ok(string)`: `text/plain`, the text as is.
pub fn text(s: &str) -> Response {
    let mut resp = Response::new(Body::from(s.to_string()));
    resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain;charset=UTF-8"));
    resp
}

/// `@ResponseStatus(NO_CONTENT)` on a `Mono<Integer>` (the JOOQ controllers' delete): 204 with
/// the JSON content type and no body.
pub fn no_content_json() -> Response {
    let mut resp = empty(StatusCode::NO_CONTENT);
    resp.headers_mut().remove(header::CONTENT_LENGTH);
    resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    resp
}

/// `new PageImpl<>(content, pageable, total)` as the security service's Jackson writes it: its
/// property order (observed 2026-10-16; the files service's differs), `NON_EMPTY` (no `content`
/// key on an empty page), and `PageImpl`'s own total correction. Java picks the order of a page's
/// getters per JVM run (`getDeclaredMethods`), so a restart can flip it; the parity tools treat a
/// page's own key order as expected and compare its items in order.
pub fn page_json(content: Vec<Value>, pageable: &Pageable, total: i64) -> Value {
    let len = content.len() as i64;
    let total = if len != 0 && pageable.offset() + pageable.size > total { pageable.offset() + len } else { total };
    let total_pages = if pageable.size == 0 { 1 } else { (total + pageable.size - 1) / pageable.size };
    let has_next = pageable.page + 1 < total_pages;
    crate::jackson::Obj::new()
        .put("content", Value::Array(content))
        .put("pageable", pageable.json())
        .put("totalPages", total_pages)
        .put("totalElements", total)
        .put("last", !has_next)
        .put_always("sort", crate::spring::sort_json(&pageable.sort))
        .put("first", pageable.page == 0)
        .put("numberOfElements", len)
        .put("size", pageable.size)
        .put("number", pageable.page)
        .put("empty", len == 0)
        .build()
}

/// `PageableExecutionUtils.getPage(content, pageable, () -> count)`: the total told from the
/// page when it can be, else the count.
pub fn page_of(content: Vec<Value>, pageable: &Pageable, count: i64) -> Value {
    let total = crate::spring::known_total(content.len(), pageable).unwrap_or(count);
    page_json(content, pageable, total)
}

/// An empty `Mono<ResponseEntity>`: 200 with no body.
pub fn nothing() -> Response {
    empty(StatusCode::OK)
}

pub fn ids_json(ids: &[u64]) -> Response {
    json(&Value::from(ids.to_vec()))
}

/// A `List<BigInteger>` body.
pub fn id_list_body(bytes: &[u8]) -> AuthResult<Vec<u64>> {
    let raw: Vec<Value> = body(bytes)?;
    raw.iter()
        .map(|v| match v {
            Value::Number(n) if n.is_u64() => Ok(n.as_u64().unwrap_or(0)),
            Value::Number(n) if n.is_i64() => Err(AuthError::internal("BigInteger out of range of ULong")),
            Value::String(s) if !s.trim().is_empty() => s.trim().parse::<u64>().map_err(|_| unreadable()),
            Value::Null => Err(AuthError::internal("Cannot invoke \"java.math.BigInteger.signum()\" because \"value\" is null")),
            _ => Err(unreadable()),
        })
        .collect()
}

/// A `List<String>` body (Jackson coerces scalars to text).
pub fn string_list_body(bytes: &[u8]) -> AuthResult<Vec<String>> {
    let raw: Vec<Value> = body(bytes)?;
    raw.iter()
        .map(|v| match v {
            Value::String(s) => Ok(s.clone()),
            Value::Number(n) => Ok(n.to_string()),
            Value::Bool(b) => Ok(b.to_string()),
            _ => Err(unreadable()),
        })
        .collect()
}

pub fn unreadable() -> AuthError {
    AuthError::input(StatusCode::BAD_REQUEST, "400 BAD_REQUEST \"Failed to read HTTP message\"", input::body_unreadable(None))
}

/// [`unreadable`] for one field of the body: Java's answer, the field named.
pub fn unreadable_field(field: &str) -> AuthError {
    AuthError::input(StatusCode::BAD_REQUEST, "400 BAD_REQUEST \"Failed to read HTTP message\"", input::field_invalid(field, None))
}

pub fn opt_text(v: Option<&Value>) -> AuthResult<Option<String>> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(Value::Number(n)) => Ok(Some(n.to_string())),
        Some(Value::Bool(b)) => Ok(Some(b.to_string())),
        Some(_) => Err(unreadable()),
    }
}

pub fn opt_i64(v: Option<&Value>) -> AuthResult<Option<i64>> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n.as_i64().map(Some).ok_or_else(unreadable),
        Some(Value::String(s)) if s.trim().is_empty() => Ok(None),
        Some(Value::String(s)) => s.trim().parse().map(Some).map_err(|_| unreadable()),
        Some(_) => Err(unreadable()),
    }
}

pub fn opt_u64_json(v: Option<&Value>) -> AuthResult<Option<u64>> {
    match opt_i64(v)? {
        Some(n) if n < 0 => Err(unreadable()),
        other => Ok(other.map(|n| n as u64)),
    }
}


/// `Query`: page, size, sort (default `updatedAt` DESC) and the condition.
pub fn query_body(bytes: &[u8]) -> AuthResult<(Pageable, Option<Cond>)> {
    let v: Value = body(bytes)?;
    let int = |k: &str, default: i64| -> AuthResult<i64> {
        match v.get(k) {
            None | Some(Value::Null) => Ok(default),
            Some(x) => x.as_i64().ok_or_else(unreadable),
        }
    };
    let page = int("page", 0)?;
    let size = int("size", 10)?;
    if page < 0 {
        return Err(AuthError::internal("Page index must not be less than zero"));
    }
    if size < 1 {
        return Err(AuthError::internal("Page size must not be less than one"));
    }
    let order = |o: &Value| -> AuthResult<Order> {
        let property = o.get("property").and_then(Value::as_str).ok_or_else(unreadable)?;
        let ascending = match o.get("direction").and_then(Value::as_str) {
            None | Some("ASC") => true,
            Some("DESC") => false,
            Some(_) => return Err(unreadable()),
        };
        Ok(Order { property: property.to_string(), ascending, ignore_case: false })
    };
    let sort = match v.get("sort") {
        None => vec![Order::new("updatedAt", false)],
        Some(Value::Array(items)) => items.iter().map(order).collect::<AuthResult<_>>()?,
        Some(o @ Value::Object(_)) => vec![order(o)?],
        Some(_) => vec![],
    };
    let cond = match v.get("condition") {
        None => None,
        // The condition's deserializer throws inside Jackson: Spring reports an unreadable body.
        Some(c) => parse_condition(c).map_err(|_| unreadable())?,
    };
    Ok((Pageable::of(page, size, sort), cond))
}

/// A `LocalDate` as `CommonsSerializationModule` reads it: epoch seconds, the UTC date.
pub fn epoch_date(v: Option<&Value>) -> AuthResult<Option<NaiveDate>> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => {
            let secs = n.as_i64().ok_or_else(unreadable)?;
            Ok(chrono::DateTime::from_timestamp(secs, 0).map(|t| t.date_naive()))
        }
        Some(_) => Err(unreadable()),
    }
}

pub fn dec_json(v: Option<&Value>) -> AuthResult<Option<Dec>> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(x) => Dec::from_json(x).map(Some).ok_or_else(unreadable),
    }
}



