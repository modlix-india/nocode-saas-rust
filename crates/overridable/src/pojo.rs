//! The Java document classes, described as field lists, and the four things the Java side does
//! with them that show in a response:
//!
//! - **decode**: Spring Data reading a Mongo document into the class (unknown fields dropped,
//!   scalars converted to the field's type, `int` fields defaulted);
//! - **convert**: Jackson `convertValue` of a map into the class (draft content);
//! - **clone**: the copy constructor every read goes through (`CloneUtil`: a null map becomes
//!   an empty one, null values are dropped, and every map is rebuilt as a `HashMap`, which is
//!   what fixes the key order of the response);
//! - **write**: Jackson with `NON_EMPTY` on properties (null, empty string, map or list left
//!   out; primitives always written) and `ALWAYS` on map contents.
//!
//! A document is held as a [`JMap`] with every field of its class present, in Jackson's order
//! (superclass fields first, then declaration order).

use std::sync::atomic::{AtomicI32, Ordering};

use mongodb::bson::{Bson, Document};

use crate::bson_conv::{self, to_java_string};
use crate::java_map;
use crate::json::{JMap, JValue};

#[derive(Clone, Copy, Debug)]
pub enum Kind {
    /// `String`.
    Str,
    /// `Integer`.
    BoxInt,
    /// `int`, with its initial value.
    PrimInt(i64),
    /// `boolean`.
    PrimBool,
    /// `Boolean`.
    BoxBool,
    /// `LocalDateTime`, written as epoch seconds (`CommonsSerializationModule`).
    DateTime,
    /// `Object`.
    Object,
    /// `Map<String, Object>`.
    MapObject,
    /// `Map<String, String>`.
    MapString,
    /// `Map<String, Map<String, String>>`.
    MapMapString,
    /// `Map<String, Boolean>`.
    MapBool,
    /// `Map<String, Integer>`.
    MapInt,
    /// `Map<String, SomeClass>`.
    MapPojo(&'static Pojo),
}

/// What the class's copy constructor does with a field.
#[derive(Clone, Copy, Debug)]
pub enum CloneRule {
    /// Assigned as is (scalars).
    Copy,
    /// `CloneUtil.cloneMapObject`: null becomes `{}`, null values dropped, values cloned
    /// recursively, rebuilt as a `HashMap` by puts.
    MapObject,
    /// `CloneUtil.cloneMapStringMap`: the same two levels deep, inner values not cloned.
    MapStringMap,
    /// `new HashMap<>(map)`: null stays null, null values kept.
    NewHashMap,
    /// Not copied: the clone has the field's initial value.
    Skip,
}

#[derive(Debug)]
pub struct Field {
    pub name: &'static str,
    pub kind: Kind,
    pub clone: CloneRule,
    /// `@JsonProperty(access = READ_ONLY)`: written, never read from JSON.
    pub read_only: bool,
}

impl Field {
    pub const fn new(name: &'static str, kind: Kind, clone: CloneRule) -> Self {
        Self { name, kind, clone, read_only: false }
    }

    pub const fn read_only(mut self) -> Self {
        self.read_only = true;
        self
    }
}

/// A Java class: its fields, superclass parts first.
#[derive(Debug)]
pub struct Pojo {
    pub name: &'static str,
    pub parts: &'static [&'static [Field]],
}

impl Pojo {
    pub fn fields(&self) -> impl Iterator<Item = &'static Field> {
        self.parts.iter().flat_map(|p| p.iter())
    }
}

/// `AbstractDTO`, `AbstractUpdatableDTO` and `AbstractOverridableDTO`.
pub const OVERRIDABLE_BASE: &[Field] = &[
    Field::new("id", Kind::Str, CloneRule::Copy),
    Field::new("createdAt", Kind::DateTime, CloneRule::Copy),
    Field::new("createdBy", Kind::Str, CloneRule::Copy),
    Field::new("updatedAt", Kind::DateTime, CloneRule::Copy),
    Field::new("updatedBy", Kind::Str, CloneRule::Copy),
    Field::new("name", Kind::Str, CloneRule::Copy),
    Field::new("message", Kind::Str, CloneRule::Copy),
    Field::new("clientCode", Kind::Str, CloneRule::Copy),
    Field::new("permission", Kind::Str, CloneRule::Copy),
    Field::new("appCode", Kind::Str, CloneRule::Copy),
    Field::new("baseClientCode", Kind::Str, CloneRule::Copy),
    Field::new("notOverridable", Kind::BoxBool, CloneRule::Copy),
    Field::new("description", Kind::Str, CloneRule::Copy),
    Field::new("title", Kind::Str, CloneRule::Copy),
    Field::new("published", Kind::BoxBool, CloneRule::Copy).read_only(),
    Field::new("blueprint", Kind::MapObject, CloneRule::MapObject),
    Field::new("version", Kind::PrimInt(1), CloneRule::Copy),
];

/// The offset the Java services' JVM runs at. Spring Data turns a stored `Date` into a
/// `LocalDateTime` in the JVM's zone and the serializer then reads that wall time as UTC, so
/// the epoch seconds on the wire are shifted by this offset (zero when the JVM runs in UTC).
static JAVA_ZONE_OFFSET_SECONDS: AtomicI32 = AtomicI32::new(0);

pub fn set_java_zone_offset_seconds(secs: i32) {
    JAVA_ZONE_OFFSET_SECONDS.store(secs, Ordering::Relaxed);
}

pub fn java_zone_offset_seconds() -> i32 {
    JAVA_ZONE_OFFSET_SECONDS.load(Ordering::Relaxed)
}

/// `LocalDateTime.toEpochSecond(UTC)` of a stored date read in the JVM's zone.
pub fn epoch_seconds_of(ms: i64) -> i64 {
    (ms + java_zone_offset_seconds() as i64 * 1000).div_euclid(1000)
}

/// The `Date` Spring Data stores for `LocalDateTime.now(UTC)`: the UTC wall time taken as JVM
/// local time.
pub fn stored_millis_for_utc_now(now_ms: i64) -> i64 {
    now_ms - java_zone_offset_seconds() as i64 * 1000
}

fn default_of(kind: Kind) -> JValue {
    match kind {
        Kind::PrimInt(d) => JValue::Int(d),
        Kind::PrimBool => JValue::Bool(false),
        _ => JValue::Null,
    }
}

fn bson_int(b: &Bson) -> Option<i64> {
    match b {
        Bson::Int32(i) => Some(*i as i64),
        // Long.intValue() wraps, like the Java conversion.
        Bson::Int64(i) => Some(*i as i32 as i64),
        Bson::Double(d) => Some(*d as i32 as i64),
        Bson::String(s) => s.trim().parse::<i32>().ok().map(|x| x as i64),
        _ => None,
    }
}

fn decode_field(kind: Kind, b: &Bson) -> JValue {
    match kind {
        Kind::Str => to_java_string(b),
        Kind::BoxInt | Kind::PrimInt(_) => bson_int(b).map(JValue::Int).unwrap_or_else(|| default_of(kind)),
        Kind::PrimBool | Kind::BoxBool => match b {
            Bson::Boolean(v) => JValue::Bool(*v),
            Bson::String(s) if s.eq_ignore_ascii_case("true") => JValue::Bool(true),
            Bson::String(s) if s.eq_ignore_ascii_case("false") => JValue::Bool(false),
            _ => default_of(kind),
        },
        Kind::DateTime => match b {
            Bson::DateTime(dt) => JValue::Int(epoch_seconds_of(dt.timestamp_millis())),
            _ => JValue::Null,
        },
        Kind::Object | Kind::MapObject => match b {
            Bson::Document(_) | Bson::Null => bson_conv::to_j(b),
            other if matches!(kind, Kind::Object) => bson_conv::to_j(other),
            _ => JValue::Null,
        },
        Kind::MapString => map_of(b, to_java_string),
        Kind::MapMapString => map_of(b, |v| map_of(v, to_java_string)),
        Kind::MapBool => map_of(b, |v| decode_field(Kind::BoxBool, v)),
        Kind::MapInt => map_of(b, |v| decode_field(Kind::BoxInt, v)),
        Kind::MapPojo(p) => map_of(b, |v| match v {
            Bson::Document(d) => JValue::Object(decode_bson(p, d)),
            _ => JValue::Null,
        }),
    }
}

fn map_of(b: &Bson, f: impl Fn(&Bson) -> JValue) -> JValue {
    match b {
        Bson::Document(d) => JValue::Object(d.iter().map(|(k, v)| (bson_conv::unescape_key(k), f(v))).collect()),
        _ => JValue::Null,
    }
}

/// Spring Data reading `doc` into the class.
pub fn decode_bson(pojo: &Pojo, doc: &Document) -> JMap {
    let mut out = JMap::new();
    for f in pojo.fields() {
        let mongo_name = if f.name == "id" { "_id" } else { f.name };
        let v = match doc.get(mongo_name) {
            Some(b) => decode_field(f.kind, b),
            None => default_of(f.kind),
        };
        out.insert(f.name.to_string(), v);
    }
    out
}

fn json_int(v: &JValue) -> Option<i64> {
    match v {
        JValue::Int(i) => Some(*i as i32 as i64),
        JValue::Float(f) => Some(*f as i32 as i64),
        JValue::Str(s) => s.trim().parse::<i32>().ok().map(|x| x as i64),
        _ => None,
    }
}

fn convert_field(kind: Kind, v: &JValue) -> JValue {
    match kind {
        Kind::Str => match v {
            JValue::Str(_) | JValue::Null => v.clone(),
            JValue::Object(_) | JValue::Array(_) => JValue::Null,
            other => JValue::Str(other.java_to_string()),
        },
        Kind::BoxInt | Kind::PrimInt(_) => json_int(v).map(JValue::Int).unwrap_or_else(|| default_of(kind)),
        Kind::PrimBool | Kind::BoxBool => match v {
            JValue::Bool(_) => v.clone(),
            _ => default_of(kind),
        },
        // The custom deserializer: epoch seconds.
        Kind::DateTime => match v {
            JValue::Int(_) => v.clone(),
            JValue::Float(f) => JValue::Int(*f as i64),
            _ => JValue::Null,
        },
        Kind::Object => v.clone(),
        Kind::MapObject => match v {
            JValue::Object(_) => v.clone(),
            _ => JValue::Null,
        },
        Kind::MapString | Kind::MapMapString | Kind::MapBool | Kind::MapInt => match v {
            JValue::Object(m) => {
                let inner = match kind {
                    Kind::MapString => Kind::Str,
                    Kind::MapMapString => Kind::MapString,
                    Kind::MapBool => Kind::BoxBool,
                    _ => Kind::BoxInt,
                };
                JValue::Object(m.iter().map(|(k, x)| (k.clone(), convert_field(inner, x))).collect())
            }
            _ => JValue::Null,
        },
        Kind::MapPojo(p) => match v {
            JValue::Object(m) => JValue::Object(
                m.iter()
                    .map(|(k, x)| {
                        let c = match x {
                            JValue::Object(o) => JValue::Object(convert_json(p, o)),
                            _ => JValue::Null,
                        };
                        (k.clone(), c)
                    })
                    .collect(),
            ),
            _ => JValue::Null,
        },
    }
}

/// Jackson `convertValue(map, Class)`: unknown keys dropped (Spring Boot turns off
/// `FAIL_ON_UNKNOWN_PROPERTIES`), read-only fields ignored.
pub fn convert_json(pojo: &Pojo, m: &JMap) -> JMap {
    let mut out = JMap::new();
    for f in pojo.fields() {
        let v = match m.get(f.name) {
            Some(v) if !f.read_only => convert_field(f.kind, v),
            _ => default_of(f.kind),
        };
        out.insert(f.name.to_string(), v);
    }
    out
}

/// `CloneUtil.cloneObject` on an untyped value.
pub fn clone_value(v: &JValue) -> JValue {
    match v {
        JValue::Object(m) => JValue::Object(clone_map_object(m)),
        JValue::Array(a) => JValue::Array(a.iter().filter(|x| !x.is_null()).map(clone_value).collect()),
        other => other.clone(),
    }
}

/// `CloneUtil.cloneMapObject` on an untyped map.
pub fn clone_map_object(m: &JMap) -> JMap {
    java_map::by_puts(
        m.iter()
            .filter(|(_, v)| !v.is_null())
            .map(|(k, v)| (k.clone(), clone_value(v)))
            .collect(),
    )
}

fn clone_field(f: &Field, v: &JValue) -> JValue {
    match f.clone {
        CloneRule::Copy => v.clone(),
        CloneRule::Skip => default_of(f.kind),
        CloneRule::NewHashMap => match v {
            JValue::Object(m) => JValue::Object(java_map::by_copy(m.clone())),
            _ => JValue::Null,
        },
        CloneRule::MapStringMap => {
            let m = match v {
                JValue::Object(m) => m,
                _ => return JValue::Object(JMap::new()),
            };
            JValue::Object(java_map::by_puts(
                m.iter()
                    .filter_map(|(k, inner)| match inner {
                        JValue::Null => None,
                        JValue::Object(im) => Some((
                            k.clone(),
                            JValue::Object(java_map::by_puts(
                                im.iter().filter(|(_, x)| !x.is_null()).map(|(a, b)| (a.clone(), b.clone())).collect(),
                            )),
                        )),
                        other => Some((k.clone(), other.clone())),
                    })
                    .collect(),
            ))
        }
        CloneRule::MapObject => {
            let m = match v {
                JValue::Object(m) => m,
                _ => return JValue::Object(JMap::new()),
            };
            match f.kind {
                Kind::MapPojo(p) => JValue::Object(java_map::by_puts(
                    m.iter()
                        .filter_map(|(k, x)| match x {
                            JValue::Object(o) => Some((k.clone(), JValue::Object(clone_pojo(p, o)))),
                            JValue::Null => None,
                            other => Some((k.clone(), other.clone())),
                        })
                        .collect(),
                )),
                _ => JValue::Object(clone_map_object(m)),
            }
        }
    }
}

/// The class's copy constructor.
pub fn clone_pojo(pojo: &Pojo, m: &JMap) -> JMap {
    let mut out = JMap::new();
    for f in pojo.fields() {
        let v = m.get(f.name).unwrap_or(&JValue::Null);
        out.insert(f.name.to_string(), clone_field(f, v));
    }
    out
}

fn always_written(kind: Kind) -> bool {
    matches!(kind, Kind::PrimInt(_) | Kind::PrimBool)
}

/// Jackson writing the class with `NON_EMPTY` property inclusion.
pub fn to_jackson(pojo: &Pojo, m: &JMap) -> JMap {
    let mut out = JMap::new();
    for f in pojo.fields() {
        let v = m.get(f.name).unwrap_or(&JValue::Null);
        if !always_written(f.kind) && v.is_jackson_empty() {
            continue;
        }
        let w = match (f.kind, v) {
            (Kind::MapPojo(p), JValue::Object(entries)) => JValue::Object(
                entries
                    .iter()
                    .map(|(k, x)| {
                        let y = match x {
                            JValue::Object(o) => JValue::Object(to_jackson(p, o)),
                            other => other.clone(),
                        };
                        (k.clone(), y)
                    })
                    .collect(),
            ),
            _ => v.clone(),
        };
        out.insert(f.name.to_string(), w);
    }
    out
}

/// A field's map, if it holds one.
pub fn map_field<'a>(m: &'a JMap, name: &str) -> Option<&'a JMap> {
    m.get(name).and_then(JValue::as_object)
}

pub fn str_field<'a>(m: &'a JMap, name: &str) -> Option<&'a str> {
    m.get(name).and_then(JValue::as_str)
}

pub fn set_opt_map(m: &mut JMap, name: &str, v: Option<JMap>) {
    m.insert(name.to_string(), v.map(JValue::Object).unwrap_or(JValue::Null));
}

#[cfg(test)]
mod tests {
    use super::*;
    use mongodb::bson::doc;

    const CHILD: Pojo = Pojo {
        name: "Child",
        parts: &[&[
            Field::new("key", Kind::Str, CloneRule::Copy),
            Field::new("override", Kind::PrimBool, CloneRule::Copy),
            Field::new("children", Kind::MapBool, CloneRule::MapObject),
        ]],
    };
    const DOC: Pojo = Pojo {
        name: "Doc",
        parts: &[
            OVERRIDABLE_BASE,
            &[
                Field::new("properties", Kind::MapObject, CloneRule::MapObject),
                Field::new("kids", Kind::MapPojo(&CHILD), CloneRule::MapObject),
                Field::new("versions", Kind::MapInt, CloneRule::NewHashMap),
            ],
        ],
    };

    #[test]
    fn decode_clone_write() {
        let d = doc! {
            "_id": mongodb::bson::oid::ObjectId::parse_str("63bd2d154d18a31536e81fa5").unwrap(),
            "name": "x", "version": 3_i32, "junk": 1,
            "createdAt": mongodb::bson::DateTime::from_millis(1_673_342_229_657),
            "properties": {"a": null, "b": "", "c": {"d": null, "e": 1.0}},
            "kids": {"k1": {"key": "k1", "children": {"z": true, "q": null}, "extra": 1}},
            "versions": {"k1": 2_i32},
        };
        let m = decode_bson(&DOC, &d);
        assert_eq!(m["id"], JValue::Str("63bd2d154d18a31536e81fa5".into()));
        assert!(matches!(m["createdAt"], JValue::Int(_)));
        assert!(!m.contains_key("junk"));
        assert_eq!(m["version"], JValue::Int(3));

        let c = clone_pojo(&DOC, &m);
        let w = JValue::Object(to_jackson(&DOC, &c));
        let created = m["createdAt"].as_i64().unwrap().to_string();
        let text = crate::json::to_compact(&w).replace(&created, "CREATED");
        assert_eq!(
            text,
            r#"{"id":"63bd2d154d18a31536e81fa5","createdAt":CREATED,"name":"x","version":3,"properties":{"b":"","c":{"e":1.0}},"kids":{"k1":{"key":"k1","override":false,"children":{"z":true}}},"versions":{"k1":2}}"#
        );
    }

    const ALL: Pojo = Pojo {
        name: "All",
        parts: &[&[
            Field::new("s", Kind::Str, CloneRule::Copy),
            Field::new("bi", Kind::BoxInt, CloneRule::Copy),
            Field::new("pi", Kind::PrimInt(9), CloneRule::Copy),
            Field::new("pb", Kind::PrimBool, CloneRule::Copy),
            Field::new("bb", Kind::BoxBool, CloneRule::Copy),
            Field::new("dt", Kind::DateTime, CloneRule::Copy),
            Field::new("o", Kind::Object, CloneRule::Copy),
            Field::new("mo", Kind::MapObject, CloneRule::MapObject),
            Field::new("ms", Kind::MapString, CloneRule::MapObject),
            Field::new("mms", Kind::MapMapString, CloneRule::MapStringMap),
            Field::new("mb", Kind::MapBool, CloneRule::MapObject),
            Field::new("mi", Kind::MapInt, CloneRule::NewHashMap),
            Field::new("mp", Kind::MapPojo(&CHILD), CloneRule::MapObject),
            Field::new("skip", Kind::Str, CloneRule::Skip),
            Field::new("ro", Kind::BoxBool, CloneRule::Copy).read_only(),
        ]],
    };

    #[test]
    fn decode_converts_like_spring_data() {
        let d = doc! {
            "s": 5_i32, "bi": 3_000_000_000_i64, "pi": "12", "pb": "TRUE", "bb": "false",
            "dt": "not a date", "o": 1.5, "mo": "not a map",
            "ms": {"a": 1_i32, "b": null, "c": true}, "mms": {"x": {"y": 2.5}, "z": 1_i32},
            "mb": {"t": true, "s": "true", "n": 1_i32}, "mi": {"a": 1.9, "b": "x"},
            "mp": {"k": {"key": "k"}, "bad": 1_i32}, "skip": "kept on read",
        };
        let m = decode_bson(&ALL, &d);
        assert_eq!(m["s"], JValue::Str("5".into()));
        assert_eq!(m["bi"], JValue::Int(3_000_000_000_i64 as i32 as i64));
        assert_eq!(m["pi"], JValue::Int(12));
        assert_eq!(m["pb"], JValue::Bool(true));
        assert_eq!(m["bb"], JValue::Bool(false));
        assert_eq!(m["dt"], JValue::Null);
        assert_eq!(m["o"], JValue::Float(1.5));
        assert_eq!(m["mo"], JValue::Null);
        assert_eq!(m["ms"].as_object().unwrap()["a"], JValue::Str("1".into()));
        assert_eq!(m["ms"].as_object().unwrap()["c"], JValue::Str("true".into()));
        assert_eq!(m["mms"].as_object().unwrap()["x"].as_object().unwrap()["y"], JValue::Str("2.5".into()));
        assert_eq!(m["mms"].as_object().unwrap()["z"], JValue::Null);
        assert_eq!(m["mb"].as_object().unwrap()["s"], JValue::Bool(true));
        assert_eq!(m["mb"].as_object().unwrap()["n"], JValue::Null);
        assert_eq!(m["mi"].as_object().unwrap()["a"], JValue::Int(1));
        assert_eq!(m["mi"].as_object().unwrap()["b"], JValue::Null);
        assert_eq!(m["mp"].as_object().unwrap()["bad"], JValue::Null);
        assert_eq!(m["skip"], JValue::Str("kept on read".into()));
        // Absent fields take their initial values.
        let empty = decode_bson(&ALL, &doc! {"pi": "x", "pb": 1_i32});
        assert_eq!(empty["pi"], JValue::Int(9));
        assert_eq!(empty["pb"], JValue::Bool(false));
        assert_eq!(empty["s"], JValue::Null);
    }

    #[test]
    fn convert_reads_json_like_jackson() {
        let src = crate::json::parse(
            br#"{"s":1.5,"bi":"7","pi":2.9,"pb":"yes","bb":true,"dt":1673362029.5,"o":[1],
            "mo":{"a":1},"ms":{"a":1,"b":{"x":1}},"mms":{"x":{"y":true}},"mb":{"a":true,"b":"t"},
            "mi":{"a":"3","b":1.2},"mp":{"k":{"key":"k","override":true,"junk":1},"n":null},
            "ro":true,"junk":1}"#,
        )
        .unwrap();
        let JValue::Object(src) = src else { panic!() };
        let m = convert_json(&ALL, &src);
        assert_eq!(m["s"], JValue::Str("1.5".into()));
        assert_eq!(m["bi"], JValue::Int(7));
        assert_eq!(m["pi"], JValue::Int(2));
        assert_eq!(m["pb"], JValue::Bool(false));
        assert_eq!(m["bb"], JValue::Bool(true));
        assert_eq!(m["dt"], JValue::Int(1_673_362_029));
        assert_eq!(m["o"], JValue::Array(vec![JValue::Int(1)]));
        assert_eq!(m["ms"].as_object().unwrap()["b"], JValue::Null);
        assert_eq!(m["mms"].as_object().unwrap()["x"].as_object().unwrap()["y"], JValue::Str("true".into()));
        assert_eq!(m["mb"].as_object().unwrap()["b"], JValue::Null);
        assert_eq!(m["mi"].as_object().unwrap()["a"], JValue::Int(3));
        assert_eq!(m["mi"].as_object().unwrap()["b"], JValue::Int(1));
        assert_eq!(m["mp"].as_object().unwrap()["k"].as_object().unwrap()["override"], JValue::Bool(true));
        assert!(!m["mp"].as_object().unwrap()["k"].as_object().unwrap().contains_key("junk"));
        assert_eq!(m["ro"], JValue::Null, "read-only fields are never read");
        assert!(!m.contains_key("junk"));
        let odd = crate::json::parse(br#"{"s":{"a":1},"dt":"x","mo":[1],"ms":[1],"mp":"x","pi":"q"}"#).unwrap();
        let JValue::Object(odd) = odd else { panic!() };
        let m = convert_json(&ALL, &odd);
        assert_eq!(m["s"], JValue::Null);
        assert_eq!(m["dt"], JValue::Null);
        assert_eq!(m["mo"], JValue::Null);
        assert_eq!(m["ms"], JValue::Null);
        assert_eq!(m["mp"], JValue::Null);
        assert_eq!(m["pi"], JValue::Int(9));
    }

    #[test]
    fn clone_follows_each_copy_constructor_rule() {
        let src = crate::json::parse(
            br#"{"s":"a","skip":"gone","mo":{"x":null,"y":[1,null,{"z":null}]},
            "mms":{"a":{"b":"c","d":null},"n":null,"s":"v"},"mi":{"a":null,"b":1},
            "mp":{"k":{"key":"k"},"n":null,"x":5}}"#,
        )
        .unwrap();
        let JValue::Object(src) = src else { panic!() };
        let c = clone_pojo(&ALL, &src);
        assert_eq!(c["skip"], JValue::Null);
        assert_eq!(c["mo"], crate::json::parse(br#"{"y":[1,{}]}"#).unwrap());
        assert_eq!(c["mms"], crate::json::parse(br#"{"a":{"b":"c"},"s":"v"}"#).unwrap());
        assert_eq!(c["mi"], crate::json::parse(br#"{"a":null,"b":1}"#).unwrap());
        assert!(c["mp"].as_object().unwrap().contains_key("x"));
        assert!(!c["mp"].as_object().unwrap().contains_key("n"));
        assert_eq!(c["ms"], JValue::Object(JMap::new()), "a null map becomes empty");
        assert_eq!(c["mb"], JValue::Object(JMap::new()));
        // A null NewHashMap stays null; a null string map becomes empty.
        let c2 = clone_pojo(&ALL, &JMap::new());
        assert_eq!(c2["mi"], JValue::Null);
        assert_eq!(c2["mms"], JValue::Object(JMap::new()));
        assert_eq!(c2["mp"], JValue::Object(JMap::new()));
        // Jackson leaves out what is empty, keeps primitives, writes nested classes as classes.
        let w = to_jackson(&ALL, &c);
        assert!(!w.contains_key("ms"));
        assert!(w.contains_key("pi"));
        assert_eq!(w["mp"].as_object().unwrap()["x"], JValue::Int(5));
    }

    #[test]
    fn small_helpers() {
        let mut m = JMap::new();
        m.insert("a".into(), JValue::Str("x".into()));
        m.insert("b".into(), JValue::Object(JMap::new()));
        assert_eq!(str_field(&m, "a"), Some("x"));
        assert_eq!(str_field(&m, "b"), None);
        assert!(map_field(&m, "b").is_some());
        assert!(map_field(&m, "a").is_none());
        set_opt_map(&mut m, "c", None);
        assert_eq!(m["c"], JValue::Null);
        set_opt_map(&mut m, "c", Some(JMap::new()));
        assert!(m["c"].as_object().is_some());
        assert_eq!(ALL.fields().count(), 15);
        assert!(Field::new("x", Kind::Str, CloneRule::Copy).read_only().read_only);
    }

    /// Every use of the process-wide offset in one test, so tests running in parallel never see
    /// another's value.
    #[test]
    fn the_jvm_zone_offset_shifts_both_ways() {
        set_java_zone_offset_seconds(19_800);
        assert_eq!(java_zone_offset_seconds(), 19_800);
        assert_eq!(epoch_seconds_of(1_673_342_229_657), 1_673_362_029);
        assert_eq!(stored_millis_for_utc_now(1_000_000), 1_000_000 - 19_800_000);
        let d = doc! {"createdAt": mongodb::bson::DateTime::from_millis(1_673_342_229_657)};
        assert_eq!(decode_bson(&DOC, &d)["createdAt"], JValue::Int(1_673_362_029));
        set_java_zone_offset_seconds(0);
        assert_eq!(epoch_seconds_of(-1), -1, "floors before the epoch");
        assert_eq!(stored_millis_for_utc_now(5), 5);
    }

}
