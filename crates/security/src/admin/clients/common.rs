//! What every controller of this piece shares: the messages it raises (`SecurityMessageResourceService`
//! keys), `@PreAuthorize`, the `Page` shape Java security writes, Jackson's coercions for request
//! bodies, and the cache names the services evict.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::Response;
use serde_json::Value;

use crate::errors::{AuthError, AuthResult};
use crate::expr::has_authority;
use crate::jackson::json;
use crate::model::ContextAuth;

// ---- message keys (messages_en.properties) ----

pub const OBJECT_NOT_FOUND: &str = "object_not_found";
pub const OBJECT_NOT_FOUND_TO_UPDATE: &str = "object_not_found_to_update";
pub const FORBIDDEN_CREATE: &str = "forbidden_create";
pub const FORBIDDEN_PERMISSION: &str = "forbidden_permission";
pub const APP_CODE_NO_SPL_CHAR: &str = "app_code_no_spl_char";
pub const CLIENT_REGISTRATION_ERROR: &str = "client_registration_error";
pub const USER_ALREADY_EXISTS: &str = "user_already_exists";
pub const USER_PASSWORD_INVALID: &str = "user_password_invalid";
/// Referenced as `request_existing`; the bundle spells it `request_exisiting`, so Java reads it
/// as the unknown-key message.
pub const REQUEST_EXISTING: &str = "request_existing";
pub const BAD_CERT_REQUEST: &str = "bad_cert_request";
pub const MISMATCH_DOMAINS: &str = "mismatch_domains";
pub const ERROR_KEY_CSR: &str = "error_key_csr";
pub const LETS_ENCRYPT_CREDENTIALS: &str = "lets_encrypt_credentials";
pub const LETS_ENCRYPT_ISSUE: &str = "lets_encrypt_issue";
pub const TRIGGER_FAILED: &str = "trigger_failed";
pub const ONLY_SYS_USER_CERTS: &str = "only_sys_user_certs";
pub const MANDATORY_APP_ID_CODE: &str = "mandatory_app_id_code";
pub const MANDATORY_APP_ID_NAME: &str = "mandatory_app_id_name";
pub const NO_REGISTRATION_AVAILABLE: &str = "no_registration_available";
pub const FIELDS_MISSING: &str = "fields_missing";
pub const MANDATORY_APP_CODE: &str = "mandatory_app_code";
pub const CLIENT_CODE_OR_ID_ONLY_ONE: &str = "client_code_or_id_only_one";
pub const FORBIDDEN_APP_REG_OBJECTS: &str = "forbidden_app_reg_objects";
pub const SUBDOMAIN_ALREADY_EXISTS: &str = "subdomain_already_exists";
pub const URL_IS_APP_SUBDOMAIN: &str = "url_is_app_subdomain";
pub const APP_SUBDOMAIN_TAKEN: &str = "app_subdomain_taken";
pub const APP_DEPENDENCY_SAME_APP_CODE: &str = "app_dependency_same_app_code";
pub const ACTIVE_INACTIVE_ERROR: &str = "active_inactive_error";
/// Missing from the bundle: Java reads it as the unknown-key message.
pub const SESSION_EXPIRED: &str = "session_expired";
/// Missing from the bundle as well.
pub const UNSUPPORTED_PLATFORM: &str = "unsupported_platform";
pub const CRT_KEY_ISSUE: &str = "crt_key_issue";
pub const SUBDOMAIN_SUFFIX_FORBIDDEN: &str = "subdomain_suffix_forbidden";
pub const FORBIDDEN_WRITE_APPLICATION_ACCESS: &str = "forbidden_write_application_access";
pub const NAME_MANDATORY: &str = "name_mandatory";
pub const INACTIVE_CLIENT: &str = "inactive_client";
pub const LENGTH_ERROR: &str = "length_error";
pub const PASSWORD_USER_ERROR: &str = "password_used_error";
pub const CAPITAL_LETTERS_MISSING: &str = "capital_letters_missing";
pub const SMALL_LETTERS_MISSING: &str = "small_letters_missing";
pub const NUMBERS_MISSING: &str = "numbers_missing";
pub const SPECIAL_CHARACTERS_MISSING: &str = "special_characters_missing";
pub const SPACES_MISSING: &str = "spaces_missing";
pub const REGEX_MISMATCH: &str = "regex_mismatch";
pub const MIN_LENGTH_ERROR: &str = "min_length_error";
pub const MAX_LENGTH_ERROR: &str = "max_length_error";

/// `AbstractMessageService.FIELD_NOT_AVAILABLE`, appended to a field name (not a bundle key).
pub const FIELD_NOT_AVAILABLE: &str = " field cannot be updated, it might not be available or unmodifiable";

/// `throwMessage(msg -> new GenericException(status, msg), key, params...)`.
pub fn err(status: StatusCode, key: &str, params: &[&str]) -> AuthError {
    AuthError::msg(status, key, params)
}

/// The `regError(...)` of the registration service: 400 `client_registration_error`.
pub fn reg_error(reason: &str) -> AuthError {
    err(StatusCode::BAD_REQUEST, CLIENT_REGISTRATION_ERROR, &[reason])
}

// ---- @PreAuthorize ----

/// `@PreAuthorize("hasAuthority('<authority>')")`: an anonymous caller never gets here (the
/// paths are protected), a signed-in one without it is refused as Spring Security refuses.
pub fn pre_authorize(ca: &ContextAuth, authority: &str) -> AuthResult<()> {
    if !ca.authenticated {
        return Err(AuthError::Unauthenticated);
    }
    if has_authority(Some(authority), &authorities(ca)) {
        Ok(())
    } else {
        Err(AuthError::denied(ca, &[authority]))
    }
}

/// `ContextAuthentication.getAuthorities()` as strings.
pub fn authorities(ca: &ContextAuth) -> Vec<String> {
    ca.user.string_authorities.clone().unwrap_or_default()
}

/// `SecurityContextUtil.hasAuthority(authority, ca.getAuthorities())`.
pub fn ca_has(ca: &ContextAuth, authority: &str) -> bool {
    has_authority(Some(authority), &authorities(ca))
}

// ---- responses ----

/// `@ResponseStatus(NO_CONTENT)` on a `Mono<Integer>`: 204, the JSON type, no body.
pub fn no_content() -> Response {
    let mut resp = crate::jackson::empty(StatusCode::NO_CONTENT);
    resp.headers_mut().remove(header::CONTENT_LENGTH);
    resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    resp
}

/// `ResponseEntity.notFound().build()` / `badRequest().build()`: the status, no body.
pub fn bare(status: StatusCode) -> Response {
    crate::jackson::empty(status)
}

/// `ResponseEntity.ok(Boolean)`.
pub fn bool_json(b: bool) -> Response {
    json(&Value::Bool(b))
}

/// `Page.empty()` (unpaged): Jackson cannot write `Unpaged.getOffset()`, so Java answers 500.
pub fn unpaged_empty_page() -> AuthError {
    AuthError::internal("JSON encoding error: (was java.lang.UnsupportedOperationException)")
}

// ---- Jackson coercions ----

/// The Java type a property is read into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `ULong` (also `BigInteger` ids).
    U64,
    /// `Long`, `Integer`, `Short` (and their primitives).
    I64,
    Bool,
    Str,
    /// `LocalDateTime`: epoch seconds.
    Ts,
    /// An enum, by constant name.
    Enum(&'static [&'static str]),
    /// A `Map<String, Object>` / JSON column, as given.
    Json,
}

/// Why a value could not be read.
#[derive(Debug, PartialEq, Eq)]
pub struct Unreadable;

/// Jackson reading `v` into the property's type (`MapperFeature.ALLOW_COERCION_OF_SCALARS`, the
/// Spring Boot defaults): text and numbers convert both ways, `"true"`/`"false"` and 0/1 are
/// booleans, an empty string is null for the wrapper types, an enum is its constant's name (or
/// index).
pub fn coerce(kind: Kind, v: &Value) -> Result<Value, Unreadable> {
    if v.is_null() {
        return Ok(Value::Null);
    }
    match kind {
        Kind::Str => match v {
            Value::String(_) => Ok(v.clone()),
            Value::Number(n) => Ok(Value::String(n.to_string())),
            Value::Bool(b) => Ok(Value::String(b.to_string())),
            _ => Err(Unreadable),
        },
        Kind::U64 | Kind::I64 | Kind::Ts => {
            let n: i128 = match v {
                Value::Number(n) => {
                    if let Some(i) = n.as_i64() {
                        i as i128
                    } else if let Some(u) = n.as_u64() {
                        u as i128
                    } else if kind == Kind::Ts {
                        return Err(Unreadable);
                    } else {
                        n.as_f64().map(|f| f.trunc() as i128).ok_or(Unreadable)?
                    }
                }
                Value::String(s) if kind != Kind::Ts => {
                    let t = s.trim();
                    if t.is_empty() {
                        return Ok(Value::Null);
                    }
                    t.parse::<i128>().map_err(|_| Unreadable)?
                }
                _ => return Err(Unreadable),
            };
            if kind == Kind::U64 {
                if n < 0 || n > u64::MAX as i128 {
                    return Err(Unreadable);
                }
                return Ok(Value::from(n as u64));
            }
            i64::try_from(n).map(Value::from).map_err(|_| Unreadable)
        }
        Kind::Bool => match v {
            Value::Bool(_) => Ok(v.clone()),
            Value::Number(n) => Ok(Value::Bool(n.as_i64().unwrap_or(1) != 0)),
            Value::String(s) if s.trim().is_empty() => Ok(Value::Null),
            Value::String(s) if s.eq_ignore_ascii_case("true") => Ok(Value::Bool(true)),
            Value::String(s) if s.eq_ignore_ascii_case("false") => Ok(Value::Bool(false)),
            _ => Err(Unreadable),
        },
        Kind::Enum(names) => match v {
            Value::String(s) if s.is_empty() => Ok(Value::Null),
            Value::String(s) if names.contains(&s.as_str()) => Ok(v.clone()),
            Value::Number(n) => {
                let i = n.as_u64().ok_or(Unreadable)? as usize;
                names.get(i).map(|s| Value::from(*s)).ok_or(Unreadable)
            }
            _ => Err(Unreadable),
        },
        Kind::Json => Ok(v.clone()),
    }
}

/// Reads one property of a request body.
pub fn prop(body: &Value, name: &str, kind: Kind) -> AuthResult<Value> {
    match body.get(name) {
        None => Ok(Value::Null),
        Some(v) => coerce(kind, v).map_err(|_| crate::web::unreadable()),
    }
}

pub fn prop_str(body: &Value, name: &str) -> AuthResult<Option<String>> {
    Ok(prop(body, name, Kind::Str)?.as_str().map(str::to_string))
}

pub fn prop_u64(body: &Value, name: &str) -> AuthResult<Option<u64>> {
    Ok(prop(body, name, Kind::U64)?.as_u64())
}

pub fn prop_i64(body: &Value, name: &str) -> AuthResult<Option<i64>> {
    Ok(prop(body, name, Kind::I64)?.as_i64())
}

/// A primitive `boolean`: absent or null is false.
pub fn prop_bool(body: &Value, name: &str) -> AuthResult<bool> {
    Ok(prop(body, name, Kind::Bool)?.as_bool().unwrap_or(false))
}

/// A request body that must be a JSON object (any other JSON is unreadable as a bean).
pub fn object_body(bytes: &[u8]) -> AuthResult<Value> {
    let v: Value = crate::handlers::body(bytes)?;
    match v {
        Value::Object(_) => Ok(v),
        _ => Err(crate::web::unreadable()),
    }
}

/// `StringUtil.safeIsBlank`.
pub fn blank(s: Option<&str>) -> bool {
    s.is_none_or(|s| s.trim().is_empty())
}

// ---- cache names (Java's) ----

pub mod cache {
    pub const CLIENT_CODE: &str = "clientCodeId";
    pub const CLIENT_ID: &str = "clientId";
    pub const CLIENT_URI: &str = "uri";
    pub const CLIENT_URL: &str = "clientUrl";
    pub const CLIENT_HIERARCHY: &str = "clientHierarchy";
    pub const GATEWAY_URL_CLIENT_APP_CODE: &str = "gatewayClientAppCodeType";
    pub const CERTIFICATE: &str = "certificateCache";
    pub const CERTIFICATE_LAST_UPDATED: &str = "certificatesLastUpdatedCache";
    pub const APP_READ_ACCESS: &str = "appReadAccess";
    pub const APP_WRITE_ACCESS: &str = "appWriteAccess";
    pub const APP_INHERITANCE: &str = "appInheritance";
    pub const APP_BY_CODE: &str = "byAppCode";
    pub const APP_BY_ID: &str = "byAppId";
    pub const APP_DEPENDENCIES: &str = "appDependencies";
    pub const APP_DEP_LIST: &str = "appDepList";
    pub const APP_STATUS: &str = "appStatus";
    pub const INTEGRATION_PLATFORM: &str = "integrationPlatform";
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn messages_and_unknown_keys() {
        assert_eq!(err(StatusCode::FORBIDDEN, FORBIDDEN_CREATE, &["Application"]).message(), "Cannot create Application for the selected client");
        assert_eq!(err(StatusCode::CONFLICT, REQUEST_EXISTING, &[]).message(), "Internal Server Error (Unknown)");
        assert_eq!(err(StatusCode::BAD_REQUEST, UNSUPPORTED_PLATFORM, &[]).message(), "Internal Server Error (Unknown)");
        assert_eq!(reg_error("Feature not supported").message(), "Client Registration Error : Feature not supported");
        assert_eq!(err(StatusCode::BAD_REQUEST, SESSION_EXPIRED, &[]).message(), "Internal Server Error (Unknown)");
        for k in [
            OBJECT_NOT_FOUND, OBJECT_NOT_FOUND_TO_UPDATE, FORBIDDEN_PERMISSION, APP_CODE_NO_SPL_CHAR, USER_ALREADY_EXISTS,
            USER_PASSWORD_INVALID, BAD_CERT_REQUEST, MISMATCH_DOMAINS, ERROR_KEY_CSR, LETS_ENCRYPT_CREDENTIALS,
            LETS_ENCRYPT_ISSUE, TRIGGER_FAILED, ONLY_SYS_USER_CERTS, MANDATORY_APP_ID_CODE, MANDATORY_APP_ID_NAME,
            NO_REGISTRATION_AVAILABLE, FIELDS_MISSING, MANDATORY_APP_CODE, CLIENT_CODE_OR_ID_ONLY_ONE,
            FORBIDDEN_APP_REG_OBJECTS, SUBDOMAIN_ALREADY_EXISTS, URL_IS_APP_SUBDOMAIN, APP_SUBDOMAIN_TAKEN,
            APP_DEPENDENCY_SAME_APP_CODE, ACTIVE_INACTIVE_ERROR, CRT_KEY_ISSUE, SUBDOMAIN_SUFFIX_FORBIDDEN,
            FORBIDDEN_WRITE_APPLICATION_ACCESS, NAME_MANDATORY, INACTIVE_CLIENT, LENGTH_ERROR, PASSWORD_USER_ERROR,
            CAPITAL_LETTERS_MISSING, SMALL_LETTERS_MISSING, NUMBERS_MISSING, SPECIAL_CHARACTERS_MISSING, SPACES_MISSING,
            REGEX_MISMATCH, MIN_LENGTH_ERROR, MAX_LENGTH_ERROR, CLIENT_REGISTRATION_ERROR,
        ] {
            assert_ne!(crate::messages::template(k), "Internal Server Error (Unknown)", "{k}");
        }
    }

    #[test]
    fn pre_authorize_like_spring_security() {
        let mut ca = ContextAuth { authenticated: true, ..Default::default() };
        ca.user.string_authorities = Some(vec!["Authorities.Client_READ".into()]);
        assert!(pre_authorize(&ca, "Authorities.Client_READ").is_ok());
        assert!(matches!(pre_authorize(&ca, "Authorities.Client_UPDATE"), Err(AuthError::AccessDenied { .. })));
        assert!(ca_has(&ca, "Authorities.Client_READ"));
        assert!(!ca_has(&ca, "Authorities.ROLE_Owner"));
        ca.authenticated = false;
        assert!(matches!(pre_authorize(&ca, "Authorities.Client_READ"), Err(AuthError::Unauthenticated)));
    }

    #[test]
    fn coercions_like_jackson() {
        assert_eq!(coerce(Kind::Str, &json!(5)), Ok(json!("5")));
        assert_eq!(coerce(Kind::Str, &json!(true)), Ok(json!("true")));
        assert!(coerce(Kind::Str, &json!({})).is_err());
        assert_eq!(coerce(Kind::U64, &json!("12")), Ok(json!(12)));
        assert_eq!(coerce(Kind::U64, &json!(" ")), Ok(Value::Null));
        assert!(coerce(Kind::U64, &json!(-1)).is_err());
        assert!(coerce(Kind::U64, &json!("x")).is_err());
        assert_eq!(coerce(Kind::I64, &json!(2.7)), Ok(json!(2)));
        assert_eq!(coerce(Kind::I64, &json!(-3)), Ok(json!(-3)));
        assert!(coerce(Kind::Ts, &json!("1")).is_err());
        assert!(coerce(Kind::Ts, &json!(1.5)).is_err());
        assert_eq!(coerce(Kind::Ts, &json!(1700000000)), Ok(json!(1700000000)));
        assert_eq!(coerce(Kind::Bool, &json!("TRUE")), Ok(json!(true)));
        assert_eq!(coerce(Kind::Bool, &json!(0)), Ok(json!(false)));
        assert_eq!(coerce(Kind::Bool, &json!("")), Ok(Value::Null));
        assert!(coerce(Kind::Bool, &json!("yes")).is_err());
        assert!(coerce(Kind::Bool, &json!([])).is_err());
        const E: &[&str] = &["A", "B"];
        assert_eq!(coerce(Kind::Enum(E), &json!("B")), Ok(json!("B")));
        assert_eq!(coerce(Kind::Enum(E), &json!(1)), Ok(json!("B")));
        assert_eq!(coerce(Kind::Enum(E), &json!("")), Ok(Value::Null));
        assert!(coerce(Kind::Enum(E), &json!("C")).is_err());
        assert!(coerce(Kind::Enum(E), &json!(5)).is_err());
        assert_eq!(coerce(Kind::Json, &json!({"a": 1})), Ok(json!({"a": 1})));
        assert_eq!(coerce(Kind::Str, &Value::Null), Ok(Value::Null));
        let b = json!({"a": "1", "b": "x", "c": "true"});
        assert_eq!(prop_u64(&b, "a").unwrap(), Some(1));
        assert!(prop_u64(&b, "b").is_err());
        assert!(prop_bool(&b, "c").unwrap());
        assert!(!prop_bool(&b, "z").unwrap());
        assert_eq!(prop_i64(&b, "a").unwrap(), Some(1));
        assert_eq!(prop_str(&b, "b").unwrap().as_deref(), Some("x"));
        assert!(object_body(b"[1]").is_err());
        assert!(object_body(b"{}").is_ok());
        assert!(blank(None) && blank(Some(" ")) && !blank(Some("a")));
    }

    #[test]
    fn unpaged_page_cannot_be_written() {
        assert_eq!(unpaged_empty_page().status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn bare_responses() {
        let r = no_content();
        assert_eq!(r.status(), StatusCode::NO_CONTENT);
        assert_eq!(r.headers()[header::CONTENT_TYPE], "application/json");
        assert_eq!(bare(StatusCode::NOT_FOUND).status(), StatusCode::NOT_FOUND);
        let b = axum::body::to_bytes(bool_json(true).into_body(), 10).await.unwrap();
        assert_eq!(&b[..], b"true");
    }
}
