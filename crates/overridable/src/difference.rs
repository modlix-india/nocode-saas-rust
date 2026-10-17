//! `DifferenceApplicator` and `DifferenceExtractor` from commons, on [`JValue`].
//!
//! An override document stores only what differs from its base. Applying it walks both maps:
//! a key only one side has is taken from that side, a key whose override value is null is a
//! deletion, nested maps merge recursively, and anything else (strings, numbers, lists) is
//! replaced whole by the override. Typed values that are not plain maps in Java (a page's
//! `ComponentDefinition`s, which implement `IDifferentiable`) merge through a callback, since
//! in JSON they are objects like any other.
//!
//! `None` stands for Java's empty `Mono` (no value: the key is dropped, the field left null);
//! `Some(JValue::Null)` is an explicit null.
//!
//! The KIRun model branches (`FunctionDefinition`, `Statement`, ...) and Gson `JsonElement`s are
//! not ported: the ui documents hold function definitions as plain maps, so those branches are
//! never reached on this read path.

use crate::java_map;
use crate::json::{JMap, JValue};

/// What to do with a key both maps have, given the override's value (non-null) and the base's.
pub type ElementApply<'a> = &'a dyn Fn(&JValue, Option<&JValue>) -> Option<JValue>;

/// `DifferenceApplicator.apply(Object override, Object base)` for untyped values.
pub fn apply_value(override_: Option<&JValue>, base: Option<&JValue>) -> Option<JValue> {
    let o = match override_ {
        None | Some(JValue::Null) => return None,
        Some(o) => o,
    };
    match (o, base) {
        (JValue::Object(om), Some(JValue::Object(bm))) => apply_map(Some(om), Some(bm)).map(JValue::Object),
        _ => Some(o.clone()),
    }
}

fn untyped(o: &JValue, b: Option<&JValue>) -> Option<JValue> {
    apply_value(Some(o), b)
}

/// `DifferenceApplicator.apply(Map override, Map base)`.
pub fn apply_map(override_: Option<&JMap>, base: Option<&JMap>) -> Option<JMap> {
    apply_map_inner(override_, base, &untyped, &maps_deferred)
}

/// Whether merging two values both present (override first) finishes later than the keys taken
/// whole, i.e. whether Java's merge of them runs on its scheduler.
pub type Deferred<'a> = &'a dyn Fn(&JValue, &JValue) -> bool;

/// Java's map merge goes to a scheduler only when both maps have entries.
pub fn maps_deferred(o: &JValue, b: &JValue) -> bool {
    matches!((o, b), (JValue::Object(x), JValue::Object(y)) if !x.is_empty() && !y.is_empty())
}

/// The same, with `element` deciding keys present on both sides (the `IDifferentiable` case).
/// Every typed merge with a base is taken to finish late; [`apply_map_with_deferral`] says
/// which do.
pub fn apply_map_with(override_: Option<&JMap>, base: Option<&JMap>, element: ElementApply) -> Option<JMap> {
    apply_map_inner(override_, base, element, &|_, _| true)
}

/// [`apply_map_with`], with `deferred` saying which of the typed merges finish late.
pub fn apply_map_with_deferral(
    override_: Option<&JMap>,
    base: Option<&JMap>,
    element: ElementApply,
    deferred: Deferred,
) -> Option<JMap> {
    apply_map_inner(override_, base, element, deferred)
}

fn apply_map_inner(override_: Option<&JMap>, base: Option<&JMap>, element: ElementApply, deferred: Deferred) -> Option<JMap> {
    let o = match override_ {
        Some(o) if !o.is_empty() => o,
        _ => return base.cloned(),
    };
    let b = match base {
        Some(b) if !b.is_empty() => b,
        _ => return Some(o.clone()),
    };

    // Base keys first, then the override's own: the order Flux.concat(...).distinct() visits.
    // Java merges each key in a flatMap on a scheduler: a key settled on the spot (taken from
    // one side, or replaced whole) lands in the map at once, while a key whose two values are
    // merged lands when that merge finishes, after the others. Only keys sharing a HashMap
    // bucket can tell the difference; the settled-first order is followed here.
    let mut settled = JMap::new();
    let mut merged = JMap::new();
    let keys = b.keys().chain(o.keys().filter(|k| !b.contains_key(*k)));
    for key in keys {
        let ov = o.get(key);
        let bv = b.get(key);
        if ov.is_none() && bv.is_some_and(|v| !v.is_null()) {
            settled.insert(key.clone(), bv.cloned().unwrap_or_default());
        } else if bv.is_none() && ov.is_some_and(|v| !v.is_null()) {
            settled.insert(key.clone(), ov.cloned().unwrap_or_default());
        } else if let Some(v) = ov.filter(|v| !v.is_null()) {
            let base_value = bv.filter(|x| !x.is_null());
            let late = base_value.is_some_and(|b| deferred(v, b));
            if let Some(r) = element(v, base_value) {
                if late {
                    merged.insert(key.clone(), r);
                } else {
                    settled.insert(key.clone(), r);
                }
            }
        }
    }
    settled.extend(merged);
    // collectMap builds a HashMap.
    Some(java_map::by_puts(settled))
}

/// `DifferenceApplicator.applyMapBoolean`: per key the override's value when it has the key,
/// else the base's; a key whose value comes out null leaves the map.
pub fn apply_map_boolean(override_: Option<&JMap>, base: Option<&JMap>) -> Option<JMap> {
    let o = match override_ {
        Some(o) if !o.is_empty() => o,
        _ => return base.cloned(),
    };
    let b = match base {
        Some(b) if !b.is_empty() => b,
        _ => return Some(o.clone()),
    };
    // A null in the override is a key that client removed (the extractor writes one for every
    // base key the client no longer has), so it leaves the merged map.
    let mut out = JMap::new();
    for key in b.keys().chain(o.keys().filter(|k| !b.contains_key(*k))) {
        let v = if o.contains_key(key) { o.get(key) } else { b.get(key) };
        if let Some(v) = v.filter(|v| !v.is_null()) {
            out.insert(key.clone(), v.clone());
        }
    }
    Some(java_map::by_puts(out))
}

/// `DifferenceExtractor.extract(Object incoming, Object existing)`: `None` for no difference,
/// `Some(Null)` for a deletion (Java's `JsonNull.INSTANCE`, stored as a null value).
pub fn extract_value(incoming: Option<&JValue>, existing: Option<&JValue>) -> Option<JValue> {
    let existing = existing.filter(|v| !v.is_null());
    let incoming = incoming.filter(|v| !v.is_null());
    match (incoming, existing) {
        (None, None) => None,
        (Some(i), None) => Some(i.clone()),
        (None, Some(_)) => Some(JValue::Null),
        (Some(i), Some(e)) => {
            if i == e {
                return None;
            }
            match (i, e) {
                (JValue::Object(im), JValue::Object(em)) => Some(JValue::Object(extract_map(Some(im), Some(em)))),
                _ => Some(i.clone()),
            }
        }
    }
}

/// What to do with a key both maps have in the extractor: `incoming` and `existing` are both
/// non-null and not equal (the `IDifferentiable` case, `existing.extractDifference(incoming)`).
pub type ElementExtract<'a> = &'a dyn Fn(&JValue, &JValue) -> Option<JValue>;

fn untyped_extract(incoming: &JValue, existing: &JValue) -> Option<JValue> {
    extract_value(Some(incoming), Some(existing))
}

/// `DifferenceExtractor.extract(Map incoming, Map existing)`.
pub fn extract_map(incoming: Option<&JMap>, existing: Option<&JMap>) -> JMap {
    extract_map_with(incoming, existing, &untyped_extract)
}

/// The same, with `element` extracting the difference of typed values present on both sides.
pub fn extract_map_with(incoming: Option<&JMap>, existing: Option<&JMap>, element: ElementExtract) -> JMap {
    let e = match existing {
        Some(e) if !e.is_empty() => e,
        _ => {
            return match incoming {
                Some(i) if !i.is_empty() => i.clone(),
                _ => JMap::new(),
            }
        }
    };
    let i = match incoming {
        Some(i) if !i.is_empty() => i,
        _ => return java_map::by_puts(e.keys().map(|k| (k.clone(), JValue::Null)).collect()),
    };
    // Java collects the keys with a `flatMap` on `boundedElastic`: a difference known at once (a
    // key on one side only, a scalar or a list) is put as the keys are walked, while two objects
    // are compared on another thread and put when that finishes. The puts' order decides the
    // iteration order of keys sharing a bucket, so the objects go in after the rest.
    let mut out = JMap::new();
    let mut later: Vec<(String, JValue)> = Vec::new();
    for key in e.keys().chain(i.keys().filter(|k| !e.contains_key(*k))) {
        let iv = i.get(key).filter(|v| !v.is_null());
        let ev = e.get(key).filter(|v| !v.is_null());
        match (iv, ev) {
            (Some(x), Some(y)) if x != y => {
                if let Some(d) = element(x, y) {
                    if matches!((x, y), (JValue::Object(_), JValue::Object(_))) {
                        later.push((key.clone(), d));
                    } else {
                        out.insert(key.clone(), d);
                    }
                }
            }
            _ => {
                if let Some(d) = extract_value(iv, ev) {
                    out.insert(key.clone(), d);
                }
            }
        }
    }
    out.extend(later);
    java_map::by_puts(out)
}

/// `DifferenceExtractor.extractMapBoolean`.
pub fn extract_map_boolean(incoming: Option<&JMap>, existing: Option<&JMap>) -> JMap {
    let e = match existing {
        Some(e) if !e.is_empty() => e,
        _ => {
            return match incoming {
                Some(i) if !i.is_empty() => i.clone(),
                _ => JMap::new(),
            }
        }
    };
    let i = match incoming {
        Some(i) if !i.is_empty() => i,
        _ => return java_map::by_puts(e.keys().map(|k| (k.clone(), JValue::Null)).collect()),
    };
    let mut out = JMap::new();
    for key in e.keys().chain(i.keys().filter(|k| !e.contains_key(*k))) {
        let iv = i.get(key).cloned().unwrap_or(JValue::Null);
        let ev = e.get(key).cloned().unwrap_or(JValue::Null);
        if iv != ev {
            out.insert(key.clone(), iv);
        }
    }
    java_map::by_puts(out)
}

#[cfg(test)]
mod tests {
    //! The commons `DifferenceExtractorTest` and `DifferenceApplicatorTest`, case for case.
    use super::*;
    use crate::json::parse;

    fn obj(s: &str) -> JMap {
        match parse(s.as_bytes()).unwrap() {
            JValue::Object(m) => m,
            _ => panic!("not an object"),
        }
    }

    #[test]
    fn test_extract_object_object() {
        let base = obj(r#"{"a":20,"b":30,"c":{"k":1,"i":2},"d":{"k":1,"i":2},"e":{"k":1,"i":2}}"#);
        let inc = obj(r#"{"a":20,"c":{"k":1,"i":2},"d":{"k":2},"f":{"k":2,"i":3}}"#);
        let expected = obj(r#"{"b":null,"d":{"i":null,"k":2},"e":null,"f":{"k":2,"i":3}}"#);
        assert_eq!(extract_map(Some(&inc), Some(&base)), expected);
    }

    #[test]
    fn test_extract_map1() {
        let incoming = obj(r#"{"check":"what1","checkMap1":{"x":2,"y":{"a":3}}}"#);
        let base = obj(r#"{"check":"what1","checkMap":{"x":2,"y":{"a":3}}}"#);
        let expected = obj(r#"{"checkMap":null,"checkMap1":{"x":2,"y":{"a":3}}}"#);
        assert_eq!(extract_map(Some(&incoming), Some(&base)), expected);
    }

    #[test]
    fn test_extract_map2() {
        let incoming = obj(r#"{"check":"what","checkMap":{"x":12,"y":{"a":12}}}"#);
        let base = obj(r#"{"check":"what","checkMap":{"x":2,"y":{"a":3}}}"#);
        let expected = obj(r#"{"checkMap":{"x":12,"y":{"a":12}}}"#);
        assert_eq!(extract_map(Some(&incoming), Some(&base)), expected);
    }

    #[test]
    fn test_extract_same() {
        let incoming = obj(r#"{"check":"what","checkMap":{"x":12,"y":{"a":12}}}"#);
        let base = obj(r#"{"check":"what","checkMap":{"x":12,"y":{"a":12}}}"#);
        assert_eq!(extract_map(Some(&incoming), Some(&base)), JMap::new());
    }

    #[test]
    fn test_map_boolean() {
        let inc = obj(r#"{"a":true,"b":false,"c":null,"d":null}"#);
        let existing = obj(r#"{"a":true,"b":true,"c":true,"d":null}"#);
        let expected = obj(r#"{"b":false,"c":null}"#);
        assert_eq!(extract_map_boolean(Some(&inc), Some(&existing)), expected);
    }

    #[test]
    fn test_apply() {
        let base = obj(r#"{"a1":"b1","a2":"b2","a3":"b3"}"#);
        let ovr = obj(r#"{"a1":"c1","a2":null}"#);
        let expected = obj(r#"{"a1":"c1","a3":"b3"}"#);
        assert_eq!(apply_map(Some(&ovr), Some(&base)), Some(expected));
    }

    // Beyond the Java tests: the edges the read path relies on.

    #[test]
    fn apply_edges() {
        let base = obj(r#"{"m":{"x":1,"y":2},"l":[1,2],"s":"a"}"#);
        // Nested maps merge, lists and scalars are replaced whole.
        let ovr = obj(r#"{"m":{"y":3,"z":4},"l":[9],"n":"new"}"#);
        let got = apply_map(Some(&ovr), Some(&base)).unwrap();
        assert_eq!(got, obj(r#"{"m":{"x":1,"y":3,"z":4},"l":[9],"s":"a","n":"new"}"#));
        // An empty override is the base itself; an empty base the override itself.
        assert_eq!(apply_map(Some(&JMap::new()), Some(&base)), Some(base.clone()));
        assert_eq!(apply_map(Some(&ovr), None), Some(ovr.clone()));
        assert_eq!(apply_map(None, None), None);
        // A null override value deletes; a key whose base value is null and the override lacks
        // goes away too.
        let base2 = obj(r#"{"a":null,"b":1}"#);
        let ovr2 = obj(r#"{"b":null,"c":2}"#);
        assert_eq!(apply_map(Some(&ovr2), Some(&base2)).unwrap(), obj(r#"{"c":2}"#));
        // A map that empties out stays as an empty map.
        let base3 = obj(r#"{"a":{"x":1}}"#);
        let ovr3 = obj(r#"{"a":{"x":null}}"#);
        assert_eq!(apply_map(Some(&ovr3), Some(&base3)).unwrap(), obj(r#"{"a":{}}"#));
    }

    #[test]
    fn objects_compared_are_put_after_the_rest() {
        // `root` and `extra` share a bucket: Java puts the new key while the two objects are
        // still being compared, so `extra` iterates first.
        assert_eq!(java_map::bucket("root", 16), java_map::bucket("extra", 16));
        let base = obj(r#"{"root":{"children":{"a":true}},"txt":{"x":1}}"#);
        let inc = obj(r#"{"root":{"children":{"a":true,"extra":true}},"txt":{"x":1},"extra":{"key":"extra"}}"#);
        let got = extract_map(Some(&inc), Some(&base));
        assert_eq!(got.keys().map(String::as_str).collect::<Vec<_>>(), ["extra", "root"]);
    }

    #[test]
    fn apply_map_boolean_drops_removed_keys() {
        // DifferenceApplicatorTest.testApplyMapBooleanDropsRemovedKeys
        let base = obj(r#"{"txt":true,"btn":true}"#);
        let ovr = obj(r#"{"txt":null,"extra":true}"#);
        assert_eq!(apply_map_boolean(Some(&ovr), Some(&base)).unwrap(), obj(r#"{"btn":true,"extra":true}"#));
        let ovr = obj(r#"{"b":null,"c":false}"#);
        assert_eq!(apply_map_boolean(Some(&ovr), Some(&obj(r#"{"a":true,"b":true}"#))).unwrap(), obj(r#"{"a":true,"c":false}"#));
    }

    #[test]
    fn merged_maps_iterate_like_a_hashmap() {
        let base = obj(r#"{"defaultPage":1,"notFoundPage":1,"links":1}"#);
        let ovr = obj(r#"{"styles":1,"themes":1,"fontPacks":1}"#);
        let got = apply_map(Some(&ovr), Some(&base)).unwrap();
        let keys: Vec<&str> = got.keys().map(String::as_str).collect();
        assert_eq!(keys, ["fontPacks", "themes", "defaultPage", "links", "styles", "notFoundPage"]);
    }

    #[test]
    fn extract_value_cases() {
        let a = JValue::Str("a".into());
        let b = JValue::Str("b".into());
        assert_eq!(extract_value(None, None), None);
        assert_eq!(extract_value(Some(&a), None), Some(a.clone()));
        assert_eq!(extract_value(None, Some(&a)), Some(JValue::Null));
        assert_eq!(extract_value(Some(&a), Some(&a)), None);
        assert_eq!(extract_value(Some(&b), Some(&a)), Some(b.clone()));
        let m1 = JValue::Object(obj(r#"{"x":1}"#));
        let m2 = JValue::Object(obj(r#"{"x":2}"#));
        assert_eq!(extract_value(Some(&m2), Some(&m1)), Some(JValue::Object(obj(r#"{"x":2}"#))));
    }

    #[test]
    fn extract_map_edges() {
        assert_eq!(extract_map(None, None), JMap::new());
        let a = obj(r#"{"a":1}"#);
        assert_eq!(extract_map(Some(&a), None), a);
        assert_eq!(extract_map(None, Some(&a)), obj(r#"{"a":null}"#));
        assert_eq!(extract_map_boolean(None, None), JMap::new());
        let t = obj(r#"{"t":true}"#);
        assert_eq!(extract_map_boolean(Some(&t), None), t);
        assert_eq!(extract_map_boolean(None, Some(&t)), obj(r#"{"t":null}"#));
        // A typed element sees both values when they differ.
        let got = extract_map_with(Some(&obj(r#"{"k":{"v":2}}"#)), Some(&obj(r#"{"k":{"v":1}}"#)), &|i, _e| {
            Some(JValue::Object(i.as_object().cloned().unwrap_or_default()))
        });
        assert_eq!(got, obj(r#"{"k":{"v":2}}"#));
    }

    #[test]
    fn apply_edges_more() {
        assert_eq!(apply_map_boolean(None, None), None);
        let t = obj(r#"{"t":true}"#);
        assert_eq!(apply_map_boolean(Some(&t), None), Some(t.clone()));
        assert_eq!(apply_map_boolean(None, Some(&t)), Some(t.clone()));
        assert_eq!(apply_value(None, None), None);
        assert_eq!(apply_value(Some(&JValue::Null), None), None);
        let s = JValue::Str("s".into());
        let m = JValue::Object(obj(r#"{"a":1}"#));
        assert_eq!(apply_value(Some(&m), Some(&s)), Some(m.clone()));
        assert!(maps_deferred(&m, &m));
        assert!(!maps_deferred(&m, &JValue::Object(JMap::new())));
        assert!(!maps_deferred(&s, &m));
        // The three-argument form defers every typed merge.
        let got = apply_map_with(Some(&obj(r#"{"k":{"a":1}}"#)), Some(&obj(r#"{"k":{"b":2}}"#)), &|o, _b| Some(o.clone()));
        assert_eq!(got, Some(obj(r#"{"k":{"a":1}}"#)));
        let got = apply_map_with_deferral(Some(&obj(r#"{"k":{"a":1}}"#)), Some(&obj(r#"{"k":{"b":2}}"#)), &|_o, _b| None, &|_, _| false);
        assert_eq!(got, Some(JMap::new()));
    }

}
