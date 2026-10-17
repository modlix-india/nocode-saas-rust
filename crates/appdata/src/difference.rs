//! `DifferenceApplicator.apply(Map, Map)`, which the Mongo backend uses to apply a PATCH to
//! the stored row, with the key order of the `HashMap` it collects into.
//!
//! The merged map's order is what the validator, and then the stored document, receive,
//! so a row patched through the Java backend comes back with its keys in Java `HashMap`
//! order. That order is deterministic (bucket by the spread String hash, insertion order
//! within a bucket), so it is reproduced here rather than approximated.

use platform::java::string_hash_code;

use crate::value::{Document, Value};

/// Merge `patch` over `base`: a key the patch sends replaces the stored one, a key sent as
/// null is removed, two maps merge recursively, everything else is kept.
pub fn apply(patch: &Document, base: &Document) -> Document {
    if patch.is_empty() {
        return base.clone();
    }
    if base.is_empty() {
        return patch.clone();
    }

    let mut merged: Vec<(String, Value)> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for key in base.keys().chain(patch.keys()) {
        if !seen.insert(key.clone()) {
            continue;
        }
        let in_patch = patch.get(key);
        let in_base = base.get(key);
        let value = match (in_patch, in_base) {
            (None, Some(b)) if !b.is_null() => Some(b.clone()),
            (Some(p), None) if !p.is_null() => Some(p.clone()),
            (p, b) => apply_value(p, b),
        };
        if let Some(v) = value {
            merged.push((key.clone(), v));
        }
    }
    java_hash_map_order(merged)
}

/// `apply(Object override, Object base)`: null drops the key, two maps merge, otherwise
/// the override wins.
fn apply_value(patch: Option<&Value>, base: Option<&Value>) -> Option<Value> {
    match (patch, base) {
        (None, _) | (Some(Value::Null), _) => None,
        (Some(Value::Object(p)), Some(Value::Object(b))) => Some(Value::Object(apply(p, b))),
        (Some(p), _) => Some(p.clone()),
    }
}

/// The iteration order of a `java.util.HashMap` the entries were put into in this order.
pub fn java_hash_map_order(entries: Vec<(String, Value)>) -> Document {
    let mut capacity: usize = 16;
    while entries.len() > capacity * 3 / 4 {
        capacity *= 2;
    }
    let mask = (capacity - 1) as u32;
    let mut indexed: Vec<(u32, usize, String, Value)> = entries
        .into_iter()
        .enumerate()
        .map(|(i, (k, v))| {
            let h = string_hash_code(&k) as u32;
            ((h ^ (h >> 16)) & mask, i, k, v)
        })
        .collect();
    indexed.sort_by_key(|(bucket, order, _, _)| (*bucket, *order));
    indexed.into_iter().map(|(_, _, k, v)| (k, v)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(s: &str) -> Document {
        match Value::parse_json(s).unwrap() {
            Value::Object(o) => o,
            _ => unreachable!(),
        }
    }

    #[test]
    fn patches_merge() {
        let out = apply(&doc(r#"{"b":2,"c":null,"n":{"y":1}}"#), &doc(r#"{"a":1,"c":3,"n":{"x":0}}"#));
        assert_eq!(out.get("a"), Some(&Value::Int(1)));
        assert_eq!(out.get("b"), Some(&Value::Int(2)));
        assert!(!out.contains_key("c"));
        assert_eq!(out["n"].as_object().unwrap().len(), 2);
    }

    #[test]
    fn hash_map_order_matches_java() {
        // new HashMap<>() with put("name"), put("amount"), put("phone"), put("tags") iterates
        // as [amount, phone, name, tags] on a JVM.
        let entries: Vec<(String, Value)> =
            ["name", "amount", "phone", "tags"].iter().map(|k| (k.to_string(), Value::Null)).collect();
        let keys: Vec<String> = java_hash_map_order(entries).keys().cloned().collect();
        assert_eq!(keys, vec!["amount", "phone", "name", "tags"]);

        // Fourteen keys resize the table to 32; also taken from a JVM.
        let names = ["title", "body", "_id", "status", "createdAt", "owner", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8"];
        let entries: Vec<(String, Value)> = names.iter().map(|k| (k.to_string(), Value::Null)).collect();
        let keys: Vec<String> = java_hash_map_order(entries).keys().cloned().collect();
        assert_eq!(
            keys,
            vec!["owner", "x8", "title", "body", "createdAt", "x1", "x2", "_id", "x3", "x4", "x5", "x6", "status", "x7"]
        );
    }
}
