//! What this piece's controllers share: `@PreAuthorize`, reading request bodies the way the
//! service's Jackson reads the DTOs (unknown properties ignored, `ULong`s from numbers or text),
//! the reflective PATCH of `AbstractJOOQUpdatableDataService`, and the `Page` answer.

use axum::http::StatusCode;
use axum::response::Response;
use chrono::NaiveDateTime;
use serde_json::{Map, Value};

use crate::errors::{AuthError, AuthResult};
use crate::jackson::json;
use crate::model::ContextAuth;
use crate::spring::Pageable;
use crate::web::{unreadable, unreadable_field};

/// `hasAuthority` / `hasAnyAuthority`: plain membership of the caller's authorities.
pub fn has_any(ca: &ContextAuth, authorities: &[&str]) -> bool {
    let mine = ca.user.string_authorities.as_deref().unwrap_or_default();
    authorities.iter().any(|a| mine.iter().any(|m| m == a))
}

/// `@PreAuthorize("hasAnyAuthority(...)")`: a 403 "Access Denied" otherwise.
pub fn pre_authorize(ca: &ContextAuth, authorities: &[&str]) -> AuthResult<()> {
    if has_any(ca, authorities) {
        Ok(())
    } else {
        Err(AuthError::denied(ca, authorities))
    }
}

/// `@PreAuthorize("hasAuthority('A') and hasAuthority('B')")`.
pub fn pre_authorize_all(ca: &ContextAuth, authorities: &[&str]) -> AuthResult<()> {
    let missing: Vec<&str> = authorities.iter().copied().filter(|a| !has_any(ca, &[a])).collect();
    if missing.is_empty() {
        Ok(())
    } else {
        // Every one is needed: the refusal names the first one missing.
        Err(AuthError::denied(ca, &missing[..1]))
    }
}

/// `throwMessage(status, key, params)`.
pub fn refuse(status: StatusCode, key: &str, params: &[&str]) -> AuthError {
    AuthError::msg(status, key, params)
}

/// `getRecordById`'s 404: `"<Class> with id <id> not found"`.
pub fn not_found(class: &str, id: impl std::fmt::Display) -> AuthError {
    AuthError::msg(StatusCode::NOT_FOUND, "object_not_found", &[class, &id.to_string()])
}

/// A JSON object body (`@RequestBody D`), or Spring's 400.
pub fn object_body(bytes: &[u8]) -> AuthResult<Map<String, Value>> {
    match crate::handlers::body::<Value>(bytes)? {
        Value::Object(m) => Ok(m),
        _ => Err(unreadable()),
    }
}

/// Jackson's readers for the DTO properties: a wrong shape fails the whole body (400).
pub struct Fields<'a>(pub &'a Map<String, Value>);

impl Fields<'_> {
    pub fn has(&self, k: &str) -> bool {
        self.0.contains_key(k)
    }

    /// `ULong` (`UNumberDeserializer`): a number, numeric text, or an object's `id`.
    pub fn u64(&self, k: &str) -> AuthResult<Option<u64>> {
        u64_value(self.0.get(k)).map_err(|_| unreadable_field(k))
    }

    /// `String`: scalars as their text.
    pub fn string(&self, k: &str) -> AuthResult<Option<String>> {
        string_value(self.0.get(k)).map_err(|_| unreadable_field(k))
    }

    /// `boolean`: true, false, "true", "false", numbers (0 is false); null and absent are false.
    pub fn bool(&self, k: &str) -> AuthResult<bool> {
        bool_value(self.0.get(k)).map_err(|_| unreadable_field(k))
    }

    /// `Short` / `Integer` / `Long`.
    pub fn i64(&self, k: &str) -> AuthResult<Option<i64>> {
        i64_value(self.0.get(k)).map_err(|_| unreadable_field(k))
    }

    /// `LocalDateTime` as `CommonsSerializationModule` reads it: epoch seconds, UTC wall time.
    pub fn ts(&self, k: &str) -> AuthResult<Option<NaiveDateTime>> {
        ts_value(self.0.get(k)).map_err(|_| unreadable_field(k))
    }
}

/// `UNumberDeserializer`: an object gives its `id`, a scalar its text, anything else null; the
/// text goes through `ULong.valueOf` (`Long.parseLong` digits, no minus sign, in range).
pub fn u64_value(v: Option<&Value>) -> Result<Option<u64>, ()> {
    let text = match v {
        None | Some(Value::Null) | Some(Value::Array(_)) => return Ok(None),
        Some(Value::Object(o)) => return u64_value(o.get("id")),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Bool(b)) => b.to_string(),
    };
    let digits = text.strip_prefix('+').unwrap_or(&text);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(());
    }
    digits.parse().map(Some).map_err(|_| ())
}

/// What a failed `ULong` conversion in the reflective PATCH answers: the deserializer's message
/// service is null in that mapper, so its exception is a `NullPointerException` (500).
pub fn ulong_patch_failure() -> AuthError {
    AuthError::internal(
        "Cannot invoke \"com.fincity.saas.commons.configuration.service.AbstractMessageService.getDefaultLocaleMessage(String, Object[])\" because \"this.msgResource\" is null",
    )
}

pub fn string_value(v: Option<&Value>) -> Result<Option<String>, ()> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(Value::Number(n)) => Ok(Some(n.to_string())),
        Some(Value::Bool(b)) => Ok(Some(b.to_string())),
        Some(_) => Err(()),
    }
}

pub fn bool_value(v: Option<&Value>) -> Result<bool, ()> {
    match v {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(Value::Number(n)) => Ok(n.as_f64().unwrap_or(0.0) != 0.0),
        Some(Value::String(s)) if s.eq_ignore_ascii_case("true") => Ok(true),
        Some(Value::String(s)) if s.eq_ignore_ascii_case("false") || s.is_empty() => Ok(false),
        Some(_) => Err(()),
    }
}

pub fn i64_value(v: Option<&Value>) -> Result<Option<i64>, ()> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)).map(Some).ok_or(()),
        Some(Value::String(s)) if s.trim().is_empty() => Ok(None),
        Some(Value::String(s)) => s.trim().parse().map(Some).map_err(|_| ()),
        Some(_) => Err(()),
    }
}

pub fn ts_value(v: Option<&Value>) -> Result<Option<NaiveDateTime>, ()> {
    match i64_value(v)? {
        None => Ok(None),
        Some(s) => chrono::DateTime::from_timestamp(s, 0).map(|t| Some(t.naive_utc())).ok_or(()),
    }
}

/// The PATCH of `AbstractJOOQUpdatableDataService.update(key, fields)`: each field goes through
/// its setter, converted by Jackson; a value that does not convert is this 400.
pub fn patch_error(field: &str) -> AuthError {
    AuthError::literal(StatusCode::BAD_REQUEST, "SEC.FIELD_NOT_UPDATABLE", format!("{field} field cannot be updated, it might not be available or unmodifiable"))
        .with_param("field", field)
}

/// A `Page` answer (`PageableExecutionUtils.getPage`).
pub fn page_response(content: Vec<Value>, page: &Pageable, total: i64) -> Response {
    json(&crate::web::page_of(content, page, total))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn jackson_readers() {
        let m = json!({"a": "12", "b": 7, "c": {"id": 3}, "d": "x", "e": true, "f": "true", "g": 0, "h": [1], "i": -1, "j": "+4", "k": 2.0, "t": 1700000000});
        let f = Fields(m.as_object().unwrap());
        assert_eq!((f.u64("a").unwrap(), f.u64("b").unwrap(), f.u64("c").unwrap(), f.u64("zz").unwrap()), (Some(12), Some(7), Some(3), None));
        assert!(f.u64("d").is_err() && f.u64("i").is_err() && f.u64("k").is_err() && f.u64("e").is_err());
        assert_eq!((f.u64("j").unwrap(), f.u64("h").unwrap()), (Some(4), None));
        assert_eq!(u64_value(Some(&json!({"x": 1}))), Ok(None));
        assert_eq!(ulong_patch_failure().status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!((f.string("b").unwrap(), f.string("e").unwrap()), (Some("7".into()), Some("true".into())));
        assert!(f.string("h").is_err());
        assert!(f.bool("e").unwrap() && f.bool("f").unwrap() && !f.bool("g").unwrap() && !f.bool("zz").unwrap());
        assert!(f.bool("d").is_err());
        assert_eq!(f.i64("a").unwrap(), Some(12));
        assert!(f.i64("d").is_err());
        assert_eq!(f.ts("t").unwrap().unwrap().to_string(), "2023-11-14 22:13:20");
        assert!(f.has("a") && !f.has("zz"));
        assert!(object_body(b"[1]").is_err() && object_body(b"{}").is_ok());
        assert_eq!(patch_error("x").message(), "x field cannot be updated, it might not be available or unmodifiable");
        let mut ca = ContextAuth::default();
        assert!(matches!(pre_authorize(&ca, &["A"]), Err(AuthError::AccessDenied { .. })));
        ca.user.string_authorities = Some(vec!["A".into()]);
        assert!(pre_authorize(&ca, &["B", "A"]).is_ok());
        assert!(pre_authorize_all(&ca, &["A"]).is_ok() && pre_authorize_all(&ca, &["A", "B"]).is_err());
        assert_eq!(not_found("Designation", 5).message(), "Designation with id 5 not found");
        assert_eq!(refuse(StatusCode::CONFLICT, "name_taken", &["Designation", "X"]).message(), "Designation \"X\" already exists");
    }
}
