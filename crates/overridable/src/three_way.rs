//! commons-mongo `ThreeWayMerge`: replays a draft's edits (base -> draft) onto the live
//! document (base -> live). The draft surface serves a draft through this, so it shows what a
//! publish would produce.
//!
//! Where only one side moved, that side wins; where both moved to different values the draft
//! wins and the dotted path is reported. Lists are whole values. Keys in `ignored_root_keys`
//! are skipped at the root only.

use std::collections::HashSet;

use crate::json::{JMap, JValue};

pub struct Merged {
    pub merged: JMap,
    pub conflicts: Vec<String>,
}

impl Merged {
    pub fn is_clean(&self) -> bool {
        self.conflicts.is_empty()
    }
}

/// A key's value on one side, or that the side does not have the key.
#[derive(Clone, Copy, PartialEq)]
enum Side<'a> {
    Missing,
    Value(&'a JValue),
}

fn side<'a>(m: &'a JMap, key: &str) -> Side<'a> {
    m.get(key).map(Side::Value).unwrap_or(Side::Missing)
}

pub fn merge(base: Option<&JMap>, live: Option<&JMap>, draft: Option<&JMap>, ignored_root_keys: &HashSet<&str>) -> Merged {
    let empty = JMap::new();
    let mut conflicts = Vec::new();
    let merged = merge_maps(
        base.unwrap_or(&empty),
        live.unwrap_or(&empty),
        draft.unwrap_or(&empty),
        "",
        ignored_root_keys,
        &mut conflicts,
    );
    Merged { merged, conflicts }
}

fn merge_maps(
    base: &JMap,
    live: &JMap,
    draft: &JMap,
    path: &str,
    ignored: &HashSet<&str>,
    conflicts: &mut Vec<String>,
) -> JMap {
    // Live first, then what the draft adds, then what only the base had (a LinkedHashSet).
    let mut keys: Vec<&String> = live.keys().collect();
    for k in draft.keys().chain(base.keys()) {
        if !keys.contains(&k) {
            keys.push(k);
        }
    }
    let mut out = JMap::new();
    for key in keys {
        if path.is_empty() && ignored.contains(key.as_str()) {
            continue;
        }
        let child = if path.is_empty() { key.clone() } else { format!("{path}.{key}") };
        if let Some(v) = merge_value(side(base, key), side(live, key), side(draft, key), &child, ignored, conflicts) {
            out.insert(key.clone(), v);
        }
    }
    out
}

fn merge_value(
    base: Side,
    live: Side,
    draft: Side,
    path: &str,
    ignored: &HashSet<&str>,
    conflicts: &mut Vec<String>,
) -> Option<JValue> {
    let owned = |s: Side| match s {
        Side::Missing => None,
        Side::Value(v) => Some(v.clone()),
    };
    if draft == base {
        return owned(live);
    }
    if live == base {
        return owned(draft);
    }
    if live == draft {
        return owned(draft);
    }
    if let (Side::Value(JValue::Object(l)), Side::Value(JValue::Object(d))) = (live, draft) {
        let empty = JMap::new();
        let b = match base {
            Side::Value(JValue::Object(b)) => b,
            _ => &empty,
        };
        return Some(JValue::Object(merge_maps(b, l, d, path, ignored, conflicts)));
    }
    conflicts.push(path.to_string());
    owned(draft)
}

#[cfg(test)]
mod tests {
    //! The commons-mongo `ThreeWayMergeTest`, case for case.
    use super::*;
    use crate::json::parse;

    fn m(s: &str) -> JMap {
        match parse(s.as_bytes()).unwrap() {
            JValue::Object(m) => m,
            _ => panic!(),
        }
    }

    fn run(b: &str, l: &str, d: &str) -> Merged {
        merge(Some(&m(b)), Some(&m(l)), Some(&m(d)), &HashSet::new())
    }

    #[test]
    fn live_only_change_survives() {
        let r = run(r#"{"a":1,"b":2}"#, r#"{"a":1,"b":99}"#, r#"{"a":7,"b":2}"#);
        assert_eq!(r.merged, m(r#"{"a":7,"b":99}"#));
        assert!(r.is_clean());
    }

    #[test]
    fn draft_only_change_survives() {
        let r = run(r#"{"a":1}"#, r#"{"a":1}"#, r#"{"a":2}"#);
        assert_eq!(r.merged, m(r#"{"a":2}"#));
        assert!(r.is_clean());
    }

    #[test]
    fn identical_change_is_not_a_conflict() {
        let r = run(r#"{"a":1}"#, r#"{"a":2}"#, r#"{"a":2}"#);
        assert_eq!(r.merged, m(r#"{"a":2}"#));
        assert!(r.is_clean());
    }

    #[test]
    fn real_conflict_keeps_the_draft() {
        let r = run(r#"{"a":1}"#, r#"{"a":2}"#, r#"{"a":3}"#);
        assert_eq!(r.merged, m(r#"{"a":3}"#));
        assert_eq!(r.conflicts, vec!["a"]);
    }

    #[test]
    fn live_addition_is_carried_in() {
        let r = run(r#"{"a":1}"#, r#"{"a":1,"title":"Web Smith"}"#, r#"{"a":1}"#);
        assert_eq!(r.merged, m(r#"{"a":1,"title":"Web Smith"}"#));
        assert!(r.is_clean());
    }

    #[test]
    fn live_deletion_is_honoured() {
        let r = run(r#"{"a":1,"gone":2}"#, r#"{"a":1}"#, r#"{"a":1,"gone":2}"#);
        assert_eq!(r.merged, m(r#"{"a":1}"#));
        assert!(r.is_clean());
    }

    #[test]
    fn draft_deletion_is_honoured() {
        let r = run(r#"{"a":1,"gone":2}"#, r#"{"a":1,"gone":2}"#, r#"{"a":1}"#);
        assert_eq!(r.merged, m(r#"{"a":1}"#));
        assert!(r.is_clean());
    }

    #[test]
    fn explicit_null_is_not_a_deletion() {
        let r = run(r#"{"a":1}"#, r#"{"a":1,"n":null}"#, r#"{"a":1}"#);
        assert!(r.merged.contains_key("n"));
        assert!(r.is_clean());
    }

    #[test]
    fn disjoint_subtree_edits_both_survive() {
        let r = run(
            r#"{"properties":{"theme":"light"}}"#,
            r#"{"properties":{"theme":"light","title":"Web Smith"}}"#,
            r#"{"properties":{"theme":"light","fontPacks":{"dm":"DM_SANS"}}}"#,
        );
        assert_eq!(r.merged, m(r#"{"properties":{"theme":"light","title":"Web Smith","fontPacks":{"dm":"DM_SANS"}}}"#));
        assert!(r.is_clean());
    }

    #[test]
    fn independent_additions_union() {
        let r = run(r#"{"p":{}}"#, r#"{"p":{"links":{"a":1}}}"#, r#"{"p":{"fonts":{"b":2}}}"#);
        assert_eq!(r.merged, m(r#"{"p":{"links":{"a":1},"fonts":{"b":2}}}"#));
        assert!(r.is_clean());
    }

    #[test]
    fn conflict_path_is_dotted() {
        let r = run(r#"{"p":{"t":"a"}}"#, r#"{"p":{"t":"b"}}"#, r#"{"p":{"t":"c"}}"#);
        assert_eq!(r.conflicts, vec!["p.t"]);
        assert_eq!(r.merged, m(r#"{"p":{"t":"c"}}"#));
    }

    #[test]
    fn conflict_is_confined() {
        let r = run(r#"{"p":{"t":"a","u":1}}"#, r#"{"p":{"t":"b","u":1,"v":9}}"#, r#"{"p":{"t":"c","u":2}}"#);
        assert_eq!(r.merged, m(r#"{"p":{"t":"c","u":2,"v":9}}"#));
        assert_eq!(r.conflicts, vec!["p.t"]);
    }

    #[test]
    fn lists_are_atomic() {
        let r = run(r#"{"languages":["en"]}"#, r#"{"languages":["en","fr"]}"#, r#"{"languages":["en","de"]}"#);
        assert_eq!(r.merged, m(r#"{"languages":["en","de"]}"#));
        assert_eq!(r.conflicts, vec!["languages"]);
    }

    #[test]
    fn one_sided_list_change() {
        let r = run(r#"{"languages":["en"]}"#, r#"{"languages":["en","fr"]}"#, r#"{"languages":["en"]}"#);
        assert_eq!(r.merged, m(r#"{"languages":["en","fr"]}"#));
        assert!(r.is_clean());
    }

    #[test]
    fn ignored_keys_are_root_only() {
        let ignored: HashSet<&str> = ["version"].into_iter().collect();
        let r = merge(
            Some(&m(r#"{"version":1,"p":{"version":"1.2.0"}}"#)),
            Some(&m(r#"{"version":3,"p":{"version":"1.2.0"}}"#)),
            Some(&m(r#"{"version":1,"p":{"version":"1.3.0"}}"#)),
            &ignored,
        );
        assert!(!r.merged.contains_key("version"));
        assert_eq!(r.merged["p"].as_object().unwrap()["version"], JValue::Str("1.3.0".into()));
    }

    #[test]
    fn nulls_are_tolerated() {
        let r = merge(None, Some(&m(r#"{"a":1}"#)), None, &HashSet::new());
        assert_eq!(r.merged, m(r#"{"a":1}"#));
        assert!(r.is_clean());
    }
}
