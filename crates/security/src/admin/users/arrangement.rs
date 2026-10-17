//! A profile's `arrangement` (`Map<String, Object>` in Java) and what the profile service does
//! with it: `DifferenceApplicator` / `DifferenceExtractor` from commons, and the walks of
//! `fillProfileArrangements`, `cleanProfileArrangement` and `getRoleIdsFromArrangements`.
//!
//! The order of a written map is Java's: a map read from the JSON column is a `LinkedHashMap`
//! (insertion order, which is MySQL's key order), while a map the applicator builds is a
//! `HashMap` (`collectMap`), iterated in hash order. [`JMap::hash`] tells the two apart so that a
//! key added later (`putIfAbsent("assignable", true)`) lands where Java puts it.

use serde_json::{Map, Number, Value};

use crate::errors::{AuthError, AuthResult};
use crate::javamap::hash_map_order_str;

/// A value inside an arrangement.
#[derive(Debug, Clone, PartialEq)]
pub enum JV {
    Null,
    Bool(bool),
    Number(Number),
    String(String),
    Array(Vec<JV>),
    Map(JMap),
    /// A Java object Jackson writes on its own terms (the `role` a read adds).
    Pojo(Value),
}

/// A `Map<String, Object>`: its entries in insertion order, and whether it is a `HashMap`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct JMap {
    pub hash: bool,
    pub entries: Vec<(String, JV)>,
}

impl JV {
    pub fn from_value(v: &Value) -> JV {
        match v {
            Value::Null => JV::Null,
            Value::Bool(b) => JV::Bool(*b),
            Value::Number(n) => JV::Number(n.clone()),
            Value::String(s) => JV::String(s.clone()),
            Value::Array(a) => JV::Array(a.iter().map(JV::from_value).collect()),
            Value::Object(m) => JV::Map(JMap::from_map(m)),
        }
    }

    /// The value as Jackson writes it (map entries are written, nulls included).
    pub fn to_value(&self) -> Value {
        match self {
            JV::Null => Value::Null,
            JV::Bool(b) => Value::Bool(*b),
            JV::Number(n) => Value::Number(n.clone()),
            JV::String(s) => Value::String(s.clone()),
            JV::Array(a) => Value::Array(a.iter().map(JV::to_value).collect()),
            JV::Map(m) => Value::Object(m.to_map()),
            JV::Pojo(v) => v.clone(),
        }
    }

    fn is_null(&self) -> bool {
        matches!(self, JV::Null)
    }

    /// `Object.toString()` of a JSON value as Jackson read it.
    fn java_string(&self) -> String {
        match self {
            JV::String(s) => s.clone(),
            JV::Number(n) => {
                if n.is_f64() {
                    // Double.toString: 14.0, 1.0E10.
                    let f = n.as_f64().unwrap_or(0.0);
                    if f.fract() == 0.0 && f.abs() < 1e7 {
                        format!("{f:.1}")
                    } else {
                        f.to_string()
                    }
                } else {
                    n.to_string()
                }
            }
            JV::Bool(b) => b.to_string(),
            other => other.to_value().to_string(),
        }
    }

    /// The Java class a value is, for a `ClassCastException`'s text.
    fn java_class(&self) -> &'static str {
        match self {
            JV::String(_) => "java.lang.String",
            JV::Bool(_) => "java.lang.Boolean",
            JV::Number(n) if n.is_f64() => "java.lang.Double",
            JV::Number(n) if n.as_i64().is_some_and(|v| i32::try_from(v).is_ok()) => "java.lang.Integer",
            JV::Number(_) => "java.lang.Long",
            JV::Array(_) => "java.util.ArrayList",
            _ => "java.lang.Object",
        }
    }
}

impl JMap {
    pub fn from_map(m: &Map<String, Value>) -> JMap {
        JMap { hash: false, entries: m.iter().map(|(k, v)| (k.clone(), JV::from_value(v))).collect() }
    }

    pub fn to_map(&self) -> Map<String, Value> {
        let mut out = Map::new();
        if self.hash {
            for k in hash_map_order_str(self.entries.iter().map(|(k, _)| k.as_str())) {
                if let Some(v) = self.get(k) {
                    out.insert(k.to_string(), v.to_value());
                }
            }
        } else {
            for (k, v) in &self.entries {
                out.insert(k.clone(), v.to_value());
            }
        }
        out
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn contains(&self, k: &str) -> bool {
        self.entries.iter().any(|(e, _)| e == k)
    }

    pub fn get(&self, k: &str) -> Option<&JV> {
        self.entries.iter().find(|(e, _)| e == k).map(|(_, v)| v)
    }

    fn get_mut(&mut self, k: &str) -> Option<&mut JV> {
        self.entries.iter_mut().find(|(e, _)| e == k).map(|(_, v)| v)
    }

    /// `get(k)` as Java sees it: a JSON null is null.
    fn value(&self, k: &str) -> Option<&JV> {
        self.get(k).filter(|v| !v.is_null())
    }

    /// `put`: a present key keeps its place.
    pub fn put(&mut self, k: &str, v: JV) {
        match self.get_mut(k) {
            Some(slot) => *slot = v,
            None => self.entries.push((k.to_string(), v)),
        }
    }

    /// `putIfAbsent`: also replaces a null.
    pub fn put_if_absent(&mut self, k: &str, v: JV) {
        if self.value(k).is_none() {
            self.put(k, v);
        }
    }

    pub fn remove(&mut self, k: &str) {
        self.entries.retain(|(e, _)| e != k);
    }

    fn keys_with<'a>(&'a self, other: &'a JMap) -> Vec<&'a str> {
        let mut keys: Vec<&str> = Vec::new();
        for (k, _) in self.entries.iter().chain(other.entries.iter()) {
            if !keys.contains(&k.as_str()) {
                keys.push(k);
            }
        }
        keys
    }

    /// `Map.equals`: the same keys with equal values, in any order.
    fn java_equals(&self, other: &JMap) -> bool {
        self.entries.len() == other.entries.len() && self.entries.iter().all(|(k, v)| other.get(k).is_some_and(|o| java_equals(v, o)))
    }
}

fn java_equals(a: &JV, b: &JV) -> bool {
    match (a, b) {
        (JV::Map(x), JV::Map(y)) => x.java_equals(y),
        (JV::Array(x), JV::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(p, q)| java_equals(p, q)),
        _ => a == b,
    }
}

/// `DifferenceApplicator.apply(Map override, Map base)`; `None` is an empty `Mono`.
pub fn apply_map(override_: Option<&JMap>, base: Option<&JMap>) -> Option<JMap> {
    let Some(o) = override_.filter(|m| !m.is_empty()) else { return base.cloned() };
    let Some(b) = base.filter(|m| !m.is_empty()) else { return Some(o.clone()) };
    let mut out = JMap { hash: true, entries: vec![] };
    for k in b.keys_with(o) {
        if !o.contains(k) && b.value(k).is_some() {
            out.put(k, b.get(k).cloned().unwrap_or(JV::Null));
        } else if !b.contains(k) && o.value(k).is_some() {
            out.put(k, o.get(k).cloned().unwrap_or(JV::Null));
        } else if let Some(v) = apply_value(o.value(k), b.value(k)) {
            out.put(k, v);
        }
    }
    if out.is_empty() {
        out.hash = false;
    }
    Some(out)
}

/// `DifferenceApplicator.apply(Object, Object)` for map values.
fn apply_value(override_: Option<&JV>, base: Option<&JV>) -> Option<JV> {
    let o = override_?;
    match (o, base) {
        (JV::Map(om), Some(JV::Map(bm))) => apply_map(Some(om), Some(bm)).map(JV::Map),
        _ => Some(o.clone()),
    }
}

/// `DifferenceExtractor.extract(Map incoming, Map existing)`.
pub fn extract_map(incoming: Option<&JMap>, existing: Option<&JMap>) -> JMap {
    let Some(ex) = existing.filter(|m| !m.is_empty()) else {
        return incoming.filter(|m| !m.is_empty()).cloned().unwrap_or_default();
    };
    let Some(inc) = incoming.filter(|m| !m.is_empty()) else {
        return JMap { hash: true, entries: ex.entries.iter().map(|(k, _)| (k.clone(), JV::Null)).collect() };
    };
    let mut out = JMap { hash: true, entries: vec![] };
    for k in ex.keys_with(inc) {
        if let Some(v) = extract_value(inc.value(k), ex.value(k)) {
            out.put(k, v);
        }
    }
    if out.is_empty() {
        out.hash = false;
    }
    out
}

fn extract_value(incoming: Option<&JV>, existing: Option<&JV>) -> Option<JV> {
    let Some(ex) = existing else { return incoming.cloned() };
    let Some(inc) = incoming else { return Some(JV::Null) };
    if java_equals(ex, inc) {
        return None;
    }
    match (ex, inc) {
        (JV::Map(e), JV::Map(i)) => Some(JV::Map(extract_map(Some(i), Some(e)))),
        _ => Some(inc.clone()),
    }
}

/// `ULong.valueOf(value.toString())`.
fn role_id_of(v: &JV) -> AuthResult<u64> {
    let text = v.java_string();
    let digits = text.strip_prefix('+').unwrap_or(&text);
    if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
        if let Ok(n) = digits.parse() {
            return Ok(n);
        }
    }
    Err(AuthError::internal(format!("For input string: \"{text}\"")))
}

/// A path to a map inside an arrangement: the top-level key, then `subArrangements` keys.
type Path = Vec<String>;

fn at<'a>(arr: &'a mut JMap, path: &[String]) -> Option<&'a mut JV> {
    let (first, rest) = path.split_first()?;
    let mut cur = arr.get_mut(first)?;
    for k in rest {
        let JV::Map(m) = cur else { return None };
        let JV::Map(sub) = m.get_mut("subArrangements")? else { return None };
        cur = sub.get_mut(k)?;
    }
    Some(cur)
}

/// The breadth-first queue both walks build: the top-level map values, then every value of each
/// queued map's `subArrangements` map. A queued value that is not a map is Java's
/// `ClassCastException`. `visit` runs on each queued map in turn, after its children are queued.
fn walk(arr: &mut JMap, mut visit: impl FnMut(&Path, &mut JMap)) -> AuthResult<Vec<Path>> {
    let mut queue: Vec<Path> = arr.entries.iter().filter(|(_, v)| matches!(v, JV::Map(_))).map(|(k, _)| vec![k.clone()]).collect();
    let mut i = 0;
    while i < queue.len() {
        let path = queue[i].clone();
        let node = at(arr, &path).ok_or_else(|| AuthError::internal("arrangement path"))?;
        let JV::Map(m) = node else {
            return Err(AuthError::internal(format!(
                "class {} cannot be cast to class java.util.Map ({} and java.util.Map are in module java.base of loader 'bootstrap')",
                node.java_class(),
                node.java_class()
            )));
        };
        if let Some(JV::Map(sub)) = m.get("subArrangements") {
            for (k, _) in &sub.entries {
                let mut p = path.clone();
                p.push(k.clone());
                queue.push(p);
            }
        }
        visit(&path, m);
        i += 1;
    }
    Ok(queue)
}

/// The queued maps that name a role, with that role's id.
fn role_paths(arr: &mut JMap, queue: &[Path]) -> AuthResult<Vec<(u64, Path)>> {
    let mut out = Vec::new();
    for p in queue {
        if let Some(JV::Map(m)) = at(arr, p) {
            if let Some(r) = m.value("roleId") {
                out.push((role_id_of(r)?, p.clone()));
            }
        }
    }
    Ok(out)
}

/// What a role contributes to its arrangement line.
#[derive(Debug, Clone, Default)]
pub struct RoleFacts {
    pub json: Value,
    pub name: Option<String>,
    pub short_name: Option<String>,
    pub description: Option<String>,
}

fn str_or_null(s: &Option<String>) -> JV {
    s.clone().map(JV::String).unwrap_or(JV::Null)
}

fn null_role() -> AuthError {
    AuthError::internal("Cannot invoke \"com.fincity.security.dto.RoleV2.getName()\" because \"role\" is null")
}

/// `fillProfileArrangements`, first half: every line gets `assignable` (true unless set), and
/// the role ids the lines name are returned (`Collectors.toMap`, so a repeated id fails).
pub fn fill_prepare(arr: &mut JMap) -> AuthResult<Vec<(u64, Path)>> {
    let queue = walk(arr, |_, m| m.put_if_absent("assignable", JV::Bool(true)))?;
    let index = role_paths(arr, &queue)?;
    for (i, (id, _)) in index.iter().enumerate() {
        if index[..i].iter().any(|(other, _)| other == id) {
            return Err(AuthError::internal(format!("Duplicate key {id} (attempted merging values)")));
        }
    }
    Ok(index)
}

/// `fillProfileArrangements`, second half: each line gets its `role` and, where it has none,
/// the role's names and description.
pub fn fill_apply(arr: &mut JMap, index: &[(u64, Path)], role: impl Fn(u64) -> Option<RoleFacts>) -> AuthResult<()> {
    for (id, path) in index {
        let facts = role(*id).ok_or_else(null_role)?;
        if let Some(JV::Map(m)) = at(arr, path) {
            m.put("role", JV::Pojo(facts.json.clone()));
            m.put_if_absent("name", str_or_null(&facts.name));
            m.put_if_absent("shortName", str_or_null(&facts.short_name));
            m.put_if_absent("description", str_or_null(&facts.description));
        }
    }
    Ok(())
}

/// The role ids `cleanProfileArrangement` looks up (`groupingBy`: a repeated id is fine).
pub fn clean_prepare(arr: &mut JMap) -> AuthResult<Vec<(u64, Path)>> {
    let queue = walk(arr, |_, _| {})?;
    role_paths(arr, &queue)
}

/// `cleanProfileArrangement`: a line keeps only what differs from its role.
pub fn clean_apply(arr: &mut JMap, index: &[(u64, Path)], role: impl Fn(u64) -> Option<RoleFacts>) -> AuthResult<()> {
    for (id, path) in index {
        let facts = role(*id).ok_or_else(null_role)?;
        if let Some(JV::Map(m)) = at(arr, path) {
            m.remove("role");
            for (k, v) in [("name", &facts.name), ("shortName", &facts.short_name), ("description", &facts.description)] {
                let same = match (m.value(k), v) {
                    (None, None) => true,
                    (Some(JV::String(a)), Some(b)) => a == b,
                    _ => false,
                };
                if same {
                    m.remove(k);
                }
            }
        }
    }
    Ok(())
}

/// `getRoleIdsFromArrangements`: the roles of assignable lines, depth first.
pub fn role_ids(arr: Option<&JMap>) -> AuthResult<Vec<u64>> {
    let mut out = Vec::new();
    if let Some(a) = arr {
        collect_role_ids(a, &mut out)?;
    }
    Ok(out)
}

fn collect_role_ids(arr: &JMap, out: &mut Vec<u64>) -> AuthResult<()> {
    for (_, v) in &arr.entries {
        let JV::Map(m) = v else { continue };
        if let Some(r) = m.value("roleId") {
            if m.get("assignable") != Some(&JV::Bool(false)) {
                out.push(role_id_of(r)?);
            }
        }
        if let Some(JV::Map(sub)) = m.get("subArrangements") {
            collect_role_ids(sub, out)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn jm(v: Value) -> JMap {
        if let JV::Map(m) = JV::from_value(&v) { m } else { JMap::default() }
    }

    #[test]
    fn values_texts_and_casts() {
        let v = json!([1, {"a": [true, null]}]);
        assert_eq!(JV::from_value(&v).to_value(), v);
        let num = |f: f64| JV::Number(serde_json::Number::from_f64(f).unwrap());
        assert_eq!(num(14.0).java_string(), "14.0");
        assert_eq!(num(1e10).java_string(), "10000000000");
        assert_eq!(JV::Bool(true).java_string(), "true");
        assert_eq!(JV::Array(vec![JV::Null]).java_string(), "[null]");
        // A `subArrangements` value that is no map is Java's ClassCastException, named by its class.
        for (v, class) in [
            (json!("x"), "java.lang.String"),
            (json!(true), "java.lang.Boolean"),
            (json!(1.5), "java.lang.Double"),
            (json!(7), "java.lang.Integer"),
            (json!(10_000_000_000u64), "java.lang.Long"),
            (json!([1]), "java.util.ArrayList"),
            (json!(null), "java.lang.Object"),
        ] {
            let mut a = jm(json!({"k": {"subArrangements": {"s": v}}}));
            let e = fill_prepare(&mut a).unwrap_err();
            assert!(e.to_string().contains(&format!("class {class} cannot be cast")), "{e}");
        }
        // `put` keeps a present key's place.
        let mut m = jm(json!({"a": 1, "b": 2}));
        m.put("a", JV::Bool(false));
        assert_eq!(m.to_map().keys().collect::<Vec<_>>(), ["a", "b"]);
        assert!(java_equals(&JV::Array(vec![JV::Bool(true)]), &JV::Array(vec![JV::Bool(true)])));
        assert!(!java_equals(&JV::Array(vec![JV::Bool(true)]), &JV::Array(vec![])));
        // Every key of the override null: nothing left, a plain map.
        let out = apply_map(Some(&jm(json!({"a": null}))), Some(&jm(json!({"a": null})))).unwrap();
        assert!(out.is_empty() && !out.hash);
        // Role ids: a JSON value's text, digits only.
        assert_eq!(role_id_of(&JV::String("+12".into())).unwrap(), 12);
        assert!(role_id_of(&JV::String("1a".into())).is_err());
        assert!(role_id_of(&JV::String("".into())).is_err());
        assert!(role_id_of(&JV::String("99999999999999999999999".into())).is_err());
        let ids = role_ids(Some(&jm(json!({"x": 5, "k": {"roleId": "3", "subArrangements": {"y": "z", "s": {"roleId": 4, "assignable": false}}}})))).unwrap();
        assert_eq!(ids, vec![3]);
        assert_eq!(role_ids(None).unwrap(), Vec::<u64>::new());
    }

    #[test]
    fn applies_and_extracts_like_commons() {
        let base = jm(json!({"a": {"x": 1, "y": 2}, "b": 1, "c": null}));
        let over = jm(json!({"a": {"y": 3, "z": null}, "d": 4, "b": null}));
        let merged = apply_map(Some(&over), Some(&base)).unwrap();
        assert!(merged.hash);
        let v = Value::Object(merged.to_map());
        assert_eq!(v, json!({"a": {"x": 1, "y": 3}, "d": 4}));
        assert_eq!(apply_map(None, Some(&base)), Some(base.clone()));
        assert_eq!(apply_map(Some(&JMap::default()), None), None);
        let diff = extract_map(Some(&jm(json!({"a": {"x": 1, "y": 5}, "b": 1}))), Some(&base));
        assert_eq!(Value::Object(diff.to_map()), json!({"a": {"y": 5}}));
        let all_gone = extract_map(None, Some(&base));
        assert!(all_gone.entries.iter().all(|(_, v)| v.is_null()) && all_gone.entries.len() == 3);
        assert!(extract_map(Some(&base), Some(&base)).is_empty());
        assert_eq!(extract_map(Some(&base), None), base);
    }

    #[test]
    fn walks_lines() {
        let mut arr = jm(json!({"k1": {"roleId": 14, "subArrangements": {"s1": {"roleId": "110", "assignable": false}}}, "k2": 5}));
        let index = fill_prepare(&mut arr).unwrap();
        assert_eq!(index.iter().map(|(id, _)| *id).collect::<Vec<_>>(), vec![14, 110]);
        let facts = |id: u64| Some(RoleFacts { json: json!({"id": id}), name: Some(format!("R{id}")), short_name: None, description: None });
        fill_apply(&mut arr, &index, facts).unwrap();
        let v = Value::Object(arr.to_map());
        assert_eq!(v["k1"]["assignable"], true);
        assert_eq!(v["k1"]["subArrangements"]["s1"]["assignable"], false);
        assert_eq!(v["k1"]["name"], "R14");
        assert!(v["k1"]["shortName"].is_null() && v["k1"].as_object().unwrap().contains_key("shortName"));
        let keys: Vec<&String> = v["k1"].as_object().unwrap().keys().collect();
        assert_eq!(keys, vec!["roleId", "subArrangements", "assignable", "role", "name", "shortName", "description"]);
        assert!(fill_apply(&mut arr, &index, |_| None).is_err());
        let ids = clean_prepare(&mut arr).unwrap();
        clean_apply(&mut arr, &ids, facts).unwrap();
        let v = Value::Object(arr.to_map());
        assert!(v["k1"].get("role").is_none() && v["k1"].get("name").is_none() && v["k1"].get("shortName").is_none());
        assert_eq!(role_ids(Some(&arr)).unwrap(), vec![14]);
        let mut dup = jm(json!({"a": {"roleId": 1}, "b": {"roleId": 1}}));
        assert!(fill_prepare(&mut dup).is_err());
        assert_eq!(clean_prepare(&mut dup).unwrap().len(), 2);
        let mut bad = jm(json!({"a": {"subArrangements": {"x": "str"}}}));
        assert!(fill_prepare(&mut bad).unwrap_err().to_string().contains("java.lang.String cannot be cast"));
        assert!(role_ids(Some(&jm(json!({"a": {"roleId": 1.0}})))).unwrap_err().to_string().contains("\"1.0\""));
    }
}
