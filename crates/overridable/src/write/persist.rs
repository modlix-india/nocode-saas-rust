//! A document as Spring Data writes it, and the clock it stamps with.
//!
//! - `_id` first, an ObjectId when the id is 24 hex digits (Spring converts such strings);
//! - then the class's own fields, then its superclasses' (`AbstractOverridableDTO`, then
//!   `updatedAt`/`updatedBy`, then `createdAt`/`createdBy`), each in declaration order;
//! - null fields left out; `int` fields always written;
//! - map keys with a dot stored with `__d-o-t__`;
//! - `LocalDateTime` stored as a `Date` of the UTC wall time read as JVM local time.
//!
//! A date keeps its milliseconds: the entity holds epoch seconds (what the JSON shows), so a
//! date that was read from the stored document or stamped by this write's clock is written
//! back from those, and only a date a caller supplied is written from its seconds.

use mongodb::bson::{oid::ObjectId, Bson, DateTime, Document};

use crate::bson_conv::{from_j, map_to_doc};
use crate::json::{JMap, JValue};
use crate::pojo::{epoch_seconds_of, stored_millis_for_utc_now, to_jackson, Field, Kind, Pojo};

/// The time of one write, as `LocalDateTime.now(ZoneId.of("UTC"))`.
#[derive(Debug, Clone, Copy)]
pub struct Clock {
    /// Milliseconds since the epoch, UTC.
    pub ms: i64,
}

impl Clock {
    pub fn now() -> Self {
        Self { ms: chrono::Utc::now().timestamp_millis() }
    }

    /// The epoch seconds a response shows for this time.
    pub fn secs(&self) -> i64 {
        self.ms.div_euclid(1000)
    }

    pub fn value(&self) -> JValue {
        JValue::Int(self.secs())
    }

    /// The `Date` Spring Data stores for it.
    pub fn stored(&self) -> Bson {
        Bson::DateTime(DateTime::from_millis(stored_millis_for_utc_now(self.ms)))
    }
}

/// `_id` as Spring Data stores a `String` id.
pub fn id_bson(id: &str) -> Bson {
    match ObjectId::parse_str(id) {
        Ok(oid) => Bson::ObjectId(oid),
        Err(_) => Bson::String(id.to_string()),
    }
}

const TRAILING: &[&str] = &["updatedAt", "updatedBy", "createdAt", "createdBy"];

/// The fields in the order Spring Data writes them.
fn spring_order(pojo: &Pojo) -> Vec<&'static Field> {
    let mut out = Vec::new();
    for part in pojo.parts.iter().rev() {
        out.extend(part.iter().filter(|f| f.name != "id" && !TRAILING.contains(&f.name)));
    }
    for name in TRAILING {
        out.extend(pojo.fields().filter(|f| f.name == *name));
    }
    out
}

fn date_bson(secs: i64, field: &str, clock: Option<&Clock>, priors: &[&Document]) -> Bson {
    if let Some(c) = clock.filter(|c| c.secs() == secs) {
        return c.stored();
    }
    for p in priors {
        if let Some(Bson::DateTime(d)) = p.get(field) {
            if epoch_seconds_of(d.timestamp_millis()) == secs {
                return Bson::DateTime(*d);
            }
        }
    }
    Bson::DateTime(DateTime::from_millis(stored_millis_for_utc_now(secs * 1000)))
}

fn field_bson(f: &Field, v: &JValue, clock: Option<&Clock>, priors: &[&Document]) -> Option<Bson> {
    match (f.kind, v) {
        (Kind::PrimInt(d), JValue::Null) => Some(Bson::Int32(d as i32)),
        (Kind::PrimBool, JValue::Null) => Some(Bson::Boolean(false)),
        (_, JValue::Null) => None,
        (Kind::DateTime, JValue::Int(secs)) => Some(date_bson(*secs, f.name, clock, priors)),
        (Kind::DateTime, _) => None,
        (Kind::MapPojo(p), JValue::Object(m)) => {
            let mut d = Document::new();
            for (k, x) in m {
                let inner = match x {
                    JValue::Object(o) => Bson::Document(to_document(p, o, None, &[])),
                    other => from_j(other),
                };
                d.insert(crate::bson_conv::escape_key(k), inner);
            }
            Some(Bson::Document(d))
        }
        (_, JValue::Object(m)) => Some(Bson::Document(map_to_doc(m))),
        (_, other) => Some(from_j(other)),
    }
}

/// `entity` as Spring Data stores it. `priors` are stored documents whose dates may be the
/// same instants (kept to the millisecond); `clock` is this write's time.
pub fn to_document(pojo: &Pojo, entity: &JMap, clock: Option<&Clock>, priors: &[&Document]) -> Document {
    let mut d = Document::new();
    if let Some(id) = entity.get("id").and_then(JValue::as_str) {
        d.insert("_id", id_bson(id));
    }
    for f in spring_order(pojo) {
        let v = entity.get(f.name).unwrap_or(&JValue::Null);
        if let Some(b) = field_bson(f, v, clock, priors) {
            d.insert(f.name, b);
        }
    }
    d
}

/// `objectMapper.convertValue(entity, Map.class)` stored in Mongo: what a Version snapshot's
/// `object` and a draft's `content` hold. Jackson's `NON_EMPTY` map of the class, with the
/// dates as epoch seconds in `Long`s.
pub fn jackson_document(pojo: &Pojo, entity: &JMap) -> Document {
    let m = to_jackson(pojo, entity);
    let mut d = Document::new();
    for (k, v) in &m {
        let is_date = pojo.fields().any(|f| f.name == k && matches!(f.kind, Kind::DateTime));
        let b = match v {
            JValue::Int(i) if is_date => Bson::Int64(*i),
            other => from_j(other),
        };
        d.insert(crate::bson_conv::escape_key(k), b);
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::parse;
    use crate::pojo::{CloneRule, OVERRIDABLE_BASE};

    const CHILD: Pojo = Pojo { name: "Child", parts: &[&[Field::new("k", Kind::Str, CloneRule::Copy), Field::new("at", Kind::DateTime, CloneRule::Copy)]] };
    const DOC: Pojo = Pojo {
        name: "Doc",
        parts: &[
            OVERRIDABLE_BASE,
            &[
                Field::new("rootComponent", Kind::Str, CloneRule::Copy),
                Field::new("properties", Kind::MapObject, CloneRule::MapObject),
                Field::new("kids", Kind::MapPojo(&CHILD), CloneRule::MapObject),
                Field::new("flag", Kind::PrimBool, CloneRule::Copy),
            ],
        ],
    };

    fn obj(s: &str) -> JMap {
        match parse(s.as_bytes()).unwrap() {
            JValue::Object(m) => m,
            _ => panic!(),
        }
    }

    #[test]
    fn written_in_spring_order_without_nulls() {
        let e = obj(r#"{"id":"63bee0aa4d18a31536e81fa9","name":"home","clientCode":"SYSTEM","appCode":"a","version":3,
            "rootComponent":"r","properties":{"a.b":1},"kids":{"x":{"k":"v"},"y":5},"createdAt":100,"updatedBy":"7"}"#);
        let d = to_document(&DOC, &e, None, &[]);
        let keys: Vec<&str> = d.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            ["_id", "rootComponent", "properties", "kids", "flag", "name", "clientCode", "appCode", "version", "updatedBy", "createdAt"]
        );
        assert!(matches!(d.get("_id"), Some(Bson::ObjectId(_))));
        assert!(d.get_document("properties").unwrap().contains_key("a__d-o-t__b"));
        assert_eq!(d.get_document("kids").unwrap().get("y"), Some(&Bson::Int32(5)));
        assert_eq!(d.get("flag"), Some(&Bson::Boolean(false)));
        assert_eq!(d.get("createdAt"), Some(&Bson::DateTime(DateTime::from_millis(100_000))));
        let no_id = to_document(&DOC, &obj(r#"{"id":"not-hex","version":null}"#), None, &[]);
        assert_eq!(no_id.get("_id"), Some(&Bson::String("not-hex".into())));
        assert_eq!(no_id.get("version"), Some(&Bson::Int32(1)), "an int field is always written");
        assert!(to_document(&DOC, &obj(r#"{"createdAt":"x"}"#), None, &[]).get("createdAt").is_none());
    }

    #[test]
    fn dates_keep_their_milliseconds() {
        let clock = Clock { ms: 1_700_000_000_123 };
        assert_eq!(clock.secs(), 1_700_000_000);
        assert_eq!(clock.value(), JValue::Int(1_700_000_000));
        let prior = mongodb::bson::doc! {"createdAt": DateTime::from_millis(1_600_000_000_456)};
        let e = obj(r#"{"createdAt":1600000000,"updatedAt":1700000000}"#);
        let d = to_document(&DOC, &e, Some(&clock), &[&prior]);
        assert_eq!(d.get("createdAt"), Some(&Bson::DateTime(DateTime::from_millis(1_600_000_000_456))));
        assert_eq!(d.get("updatedAt"), Some(&Bson::DateTime(DateTime::from_millis(1_700_000_000_123))));
        assert_eq!(clock.stored(), Bson::DateTime(DateTime::from_millis(1_700_000_000_123)));
        assert!(Clock::now().ms > 1_700_000_000_000);
    }

    #[test]
    fn jackson_maps_hold_dates_as_longs() {
        let e = obj(r#"{"id":"x","createdAt":5,"name":"n","version":2,"properties":{},"kids":{"a":{"k":"v","at":3}}}"#);
        let d = jackson_document(&DOC, &e);
        assert_eq!(d.get("createdAt"), Some(&Bson::Int64(5)));
        assert_eq!(d.get("version"), Some(&Bson::Int32(2)));
        assert!(!d.contains_key("properties"), "empty maps are left out");
        assert_eq!(d.keys().next().map(String::as_str), Some("id"));
        assert_eq!(id_bson("63bee0aa4d18a31536e81fa9"), Bson::ObjectId(ObjectId::parse_str("63bee0aa4d18a31536e81fa9").unwrap()));
    }
}
