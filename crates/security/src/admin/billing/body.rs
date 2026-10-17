//! Request bodies as the security service's `ObjectMapper` reads them into the billing DTOs and
//! records, and `AbstractJOOQUpdatableDataService.update(id, map)`'s per-field conversion.
//!
//! Jackson's coercions, as configured there: unknown properties are ignored; a `ULong` goes
//! through `UNumberDeserializer` (`ULong.valueOf(text)`, or the `id` of an object); a
//! `BigDecimal` reads a number or a numeric string (`""` is null); a `String` takes any
//! scalar's text; an `Integer` truncates a float and parses a numeric string; an enum takes its
//! name or its ordinal; a `LocalDateTime` takes epoch seconds. Anything else is Spring's
//! "Failed to read HTTP message" 400.

use serde_json::{Map, Value};

use crate::data::billing_admin::{Kind, Rec, Schema, Val};
use crate::decimal::Dec;
use crate::errors::{AuthError, AuthResult};
use crate::handlers::body;
use crate::web::unreadable;

/// `AbstractMessageService.FIELD_NOT_AVAILABLE`.
pub const FIELD_NOT_AVAILABLE: &str = " field cannot be updated, it might not be available or unmodifiable";

/// `ULong.valueOf(text)`: `new BigInteger(text)` in range.
pub fn ulong_text(s: &str) -> Option<u64> {
    let (neg, digits) = match s.as_bytes().first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: u64 = digits.parse().ok()?;
    (!neg || n == 0).then_some(n)
}

/// `UNumberDeserializer<ULong>`.
pub fn ulong(v: &Value) -> Result<Option<u64>, ()> {
    match v {
        Value::Null => Ok(None),
        Value::Number(n) => ulong_text(&n.to_string()).map(Some).ok_or(()),
        Value::String(s) => ulong_text(s).map(Some).ok_or(()),
        Value::Object(m) => match m.get("id") {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) => ulong_text(s).map(Some).ok_or(()),
            Some(Value::Number(n)) => ulong_text(&n.to_string()).map(Some).ok_or(()),
            Some(_) => Ok(None),
        },
        _ => Err(()),
    }
}

/// Jackson's `BigDecimal`.
pub fn decimal(v: &Value) -> Result<Option<Dec>, ()> {
    match v {
        Value::Null => Ok(None),
        Value::Number(n) => Dec::parse(&n.to_string()).map(Some).ok_or(()),
        Value::String(s) if s.trim().is_empty() => Ok(None),
        Value::String(s) => Dec::parse(s.trim()).map(Some).ok_or(()),
        _ => Err(()),
    }
}

/// Jackson's `String`: any scalar as its text.
pub fn text(v: &Value) -> Result<Option<String>, ()> {
    match v {
        Value::Null => Ok(None),
        Value::String(s) => Ok(Some(s.clone())),
        Value::Number(n) => Ok(Some(n.to_string())),
        Value::Bool(b) => Ok(Some(b.to_string())),
        _ => Err(()),
    }
}

fn integer(v: &Value, min: i64, max: i64) -> Result<Option<i64>, ()> {
    let n = match v {
        Value::Null => return Ok(None),
        Value::Number(n) => match n.as_i64() {
            Some(i) => i,
            None => n.as_f64().filter(|f| f.is_finite()).map(|f| f.trunc() as i64).ok_or(())?,
        },
        Value::String(s) if s.trim().is_empty() => return Ok(None),
        Value::String(s) => s.trim().parse::<i64>().map_err(|_| ())?,
        _ => return Err(()),
    };
    if n < min || n > max {
        return Err(());
    }
    Ok(Some(n))
}

/// One value read into a property of the given Java type.
pub fn coerce(kind: Kind, v: &Value) -> Result<Val, ()> {
    let val = match kind {
        Kind::Id => ulong(v)?.map(Val::Id),
        Kind::Dec => decimal(v)?.map(Val::Dec),
        Kind::Str => text(v)?.map(Val::Str),
        Kind::Enum(names) => match v {
            Value::Null => None,
            Value::String(s) if names.contains(&s.as_str()) => Some(Val::Str(s.clone())),
            Value::Number(n) => {
                let i = n.as_u64().ok_or(())? as usize;
                Some(Val::Str(names.get(i).ok_or(())?.to_string()))
            }
            _ => return Err(()),
        },
        Kind::Int => integer(v, i32::MIN.into(), i32::MAX.into())?.map(Val::Int),
        Kind::Small => integer(v, i16::MIN.into(), i16::MAX.into())?.map(Val::Int),
        Kind::Byte => integer(v, i8::MIN.into(), i8::MAX.into())?.map(Val::Int),
        Kind::Json => match v {
            Value::Null => None,
            Value::Object(_) => Some(Val::Json(v.clone())),
            _ => return Err(()),
        },
        Kind::Ts | Kind::Date => match v {
            Value::Null => None,
            Value::Number(n) => {
                let secs = n.as_i64().or_else(|| n.as_f64().map(|f| f.trunc() as i64)).ok_or(())?;
                let t = chrono::DateTime::from_timestamp(secs, 0).ok_or(())?.naive_utc();
                Some(if kind == Kind::Ts { Val::Ts(t) } else { Val::Date(t.date()) })
            }
            _ => return Err(()),
        },
    };
    Ok(val.unwrap_or(Val::Null))
}

/// `@RequestBody Dto`: the JSON object's known properties, coerced.
pub fn dto(schema: &'static Schema, bytes: &[u8]) -> AuthResult<Rec> {
    let v: Value = body(bytes)?;
    let Value::Object(m) = v else { return Err(unreadable()) };
    let mut rec = Rec::new(schema);
    for c in schema.cols {
        if let Some(x) = m.get(c.prop) {
            rec.set(c.prop, coerce(c.kind, x).map_err(|_| unreadable())?);
        }
    }
    Ok(rec)
}

/// `@RequestBody Map<String, Object>`.
pub fn object(bytes: &[u8]) -> AuthResult<Map<String, Value>> {
    match body::<Value>(bytes)? {
        Value::Object(m) => Ok(m),
        _ => Err(unreadable()),
    }
}

/// `update(key, fields)`'s reflection: each key names a setter of the DTO's own class
/// (`"set" + capitalised key`; the base DTO's setters are not its declared methods, so `id`
/// and the audit fields are ignored, as is any key without a setter), and the value goes
/// through `convertValue`, whose failure is a 400 naming the field.
pub fn patch(target: &mut Rec, fields: &Map<String, Value>) -> AuthResult<()> {
    const BASE: [&str; 5] = ["id", "createdAt", "createdBy", "updatedAt", "updatedBy"];
    for (field, value) in fields {
        let mut chars = field.chars();
        let Some(first) = chars.next() else {
            return Err(AuthError::internal("begin 0, end 1, length 0"));
        };
        let setter = format!("{}{}", first.to_uppercase(), chars.as_str());
        let Some(c) = target.schema.cols.iter().find(|c| !BASE.contains(&c.prop) && capitalised(c.prop) == setter) else {
            continue;
        };
        let v = coerce(c.kind, value)
            .map_err(|_| {
                AuthError::literal(axum::http::StatusCode::BAD_REQUEST, "SEC.FIELD_NOT_UPDATABLE", format!("{field}{FIELD_NOT_AVAILABLE}")).with_param("field", field)
            })?;
        target.set(c.prop, v);
    }
    Ok(())
}

fn capitalised(prop: &str) -> String {
    let mut chars = prop.chars();
    chars.next().map(|f| format!("{}{}", f.to_uppercase(), chars.as_str())).unwrap_or_default()
}

/// A field of a record body (`PurchaseRequest`, `RepayRequest`, `WalletCreditRequest`).
pub fn field<T>(m: &Map<String, Value>, name: &str, read: fn(&Value) -> Result<Option<T>, ()>) -> AuthResult<Option<T>> {
    match m.get(name) {
        None => Ok(None),
        Some(v) => read(v).map_err(|_| unreadable()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::billing_admin::{BUNDLE, CONFIG};
    use serde_json::json;

    #[test]
    fn ulongs_like_unumber_deserializer() {
        assert_eq!(ulong(&json!(5)), Ok(Some(5)));
        assert_eq!(ulong(&json!("7")), Ok(Some(7)));
        assert_eq!(ulong(&json!("+7")), Ok(Some(7)));
        assert_eq!(ulong(&json!("-0")), Ok(Some(0)));
        assert_eq!(ulong(&json!({"id": "9", "x": 1})), Ok(Some(9)));
        assert_eq!(ulong(&json!({"id": 9})), Ok(Some(9)));
        assert_eq!(ulong(&json!({"x": 1})), Ok(None));
        assert_eq!(ulong(&json!({"id": true})), Ok(None));
        assert_eq!(ulong(&json!({"id": "x"})), Err(()));
        assert_eq!(ulong(&json!({"id": -1})), Err(()));
        assert_eq!(ulong(&json!(null)), Ok(None));
        assert_eq!(ulong(&json!(-1)), Err(()));
        assert_eq!(ulong(&json!(1.5)), Err(()));
        assert_eq!(ulong(&json!(" 5")), Err(()));
        assert_eq!(ulong(&json!(true)), Err(()));
        assert_eq!(ulong(&json!("99999999999999999999")), Err(()));
    }

    #[test]
    fn scalars_coerce_like_jackson() {
        assert_eq!(decimal(&json!(" 1.50 ")).unwrap().unwrap().to_string(), "1.50");
        assert_eq!(decimal(&json!("")), Ok(None));
        assert_eq!(decimal(&json!(12)).unwrap().unwrap().to_string(), "12");
        assert!(decimal(&json!("x")).is_err() && decimal(&json!(true)).is_err());
        assert_eq!(text(&json!(5)), Ok(Some("5".into())));
        assert_eq!(text(&json!(false)), Ok(Some("false".into())));
        assert!(text(&json!([])).is_err());
        assert_eq!(coerce(Kind::Int, &json!(5.9)), Ok(Val::Int(5)));
        assert_eq!(coerce(Kind::Int, &json!(" 6 ")), Ok(Val::Int(6)));
        assert_eq!(coerce(Kind::Int, &json!("")), Ok(Val::Null));
        assert!(coerce(Kind::Int, &json!(true)).is_err());
        assert!(coerce(Kind::Int, &json!("x")).is_err());
        assert!(coerce(Kind::Small, &json!(40000)).is_err());
        assert!(coerce(Kind::Byte, &json!(200)).is_err());
        let e = Kind::Enum(&["FIXED", "CUSTOM"]);
        assert_eq!(coerce(e, &json!("CUSTOM")), Ok(Val::Str("CUSTOM".into())));
        assert_eq!(coerce(e, &json!(1)), Ok(Val::Str("CUSTOM".into())));
        assert!(coerce(e, &json!(2)).is_err() && coerce(e, &json!("fixed")).is_err() && coerce(e, &json!(-1)).is_err());
        assert_eq!(coerce(e, &json!(null)), Ok(Val::Null));
        assert!(coerce(Kind::Json, &json!([1])).is_err());
        assert_eq!(coerce(Kind::Json, &json!({"a": 1})), Ok(Val::Json(json!({"a": 1}))));
        assert_eq!(coerce(Kind::Json, &json!(null)), Ok(Val::Null));
        let t = coerce(Kind::Ts, &json!(1792108800)).unwrap();
        assert_eq!(t, Val::Ts(chrono::NaiveDate::from_ymd_opt(2026, 10, 16).unwrap().and_hms_opt(0, 0, 0).unwrap()));
        assert_eq!(coerce(Kind::Date, &json!(1792108800.7)), Ok(Val::Date(chrono::NaiveDate::from_ymd_opt(2026, 10, 16).unwrap())));
        assert!(coerce(Kind::Ts, &json!("2026-10-16")).is_err());
        assert_eq!(coerce(Kind::Ts, &json!(null)), Ok(Val::Null));
    }

    #[test]
    fn dto_bodies() {
        let r = dto(&BUNDLE, br#"{"id": 3, "label": "Starter", "tokens": 1000, "bundleType": "FIXED", "nope": [1], "displayOrder": "2"}"#).unwrap();
        assert_eq!((r.id(), r.str("label"), r.int("displayOrder")), (Some(3), Some("Starter"), Some(2)));
        let e = dto(&BUNDLE, br#"{"bundleType": "OTHER"}"#).unwrap_err();
        assert_eq!(e.to_string(), "400 Bad Request: 400 BAD_REQUEST \"Failed to read HTTP message\"");
        assert!(dto(&BUNDLE, b"[1]").is_err());
        assert!(dto(&BUNDLE, b"").is_err());
        assert!(object(b"[]").is_err());
        assert_eq!(object(br#"{"a": 1}"#).unwrap().len(), 1);
    }

    #[test]
    fn patches_through_declared_setters() {
        let mut r = Rec::new(&CONFIG);
        let m = object(br#"{"Status": "INACTIVE", "id": 9, "createdBy": 4, "zzz": 1, "lowBalanceThreshold": 5.5, "paymentGatewayConfig": null}"#).unwrap();
        patch(&mut r, &m).unwrap();
        assert_eq!((r.str("status"), r.id(), r.u64("createdBy")), (Some("INACTIVE"), None, None));
        assert_eq!(r.dec("lowBalanceThreshold").unwrap().to_string(), "5.5");
        let bad = object(br#"{"gstPercentage": "abc"}"#).unwrap();
        let e = patch(&mut r, &bad).unwrap_err();
        assert_eq!(e.message(), "gstPercentage field cannot be updated, it might not be available or unmodifiable");
        assert_eq!(e.status(), axum::http::StatusCode::BAD_REQUEST);
        let empty = object(br#"{"": 1}"#).unwrap();
        assert_eq!(patch(&mut r, &empty).unwrap_err().status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn record_fields() {
        let m = object(br#"{"bundleId": "4", "tokens": "x"}"#).unwrap();
        assert_eq!(field(&m, "bundleId", ulong).unwrap(), Some(4));
        assert_eq!(field(&m, "clientId", ulong).unwrap(), None);
        assert!(field(&m, "tokens", decimal).is_err());
        assert_eq!(capitalised(""), "");
    }
}
