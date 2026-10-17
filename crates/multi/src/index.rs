//! `ObjectIndexService`: every object an application is made of, across ui and core, as one
//! flat list. Backs the builder's object tree and its search box (the same call with a filter).
//!
//! Each half arrives already resolved by its service (one row per name, the client's override
//! chosen over the owner's base). A half that did not answer arrives as an empty map; the
//! `services` entry says which halves answered, so a degraded tree does not look like an app
//! with no objects.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Map, Value};

/// The ui index's buckets and the type each row gets. Anything else a service returns is
/// ignored: a new type must be named here deliberately.
const UI_TYPES: &[(&str, &str)] = &[
    ("pages", "page"),
    ("styles", "style"),
    ("themes", "theme"),
    ("functions", "function"),
    ("schemas", "schema"),
    ("uripaths", "uripath"),
];

const CORE_TYPES: &[(&str, &str)] = &[
    ("storages", "storage"),
    ("schemas", "schema"),
    ("functions", "function"),
    ("templates", "template"),
    ("connections", "connection"),
    ("eventDefinitions", "eventDefinition"),
    ("eventActions", "eventAction"),
    ("notifications", "notification"),
    ("workflows", "workflow"),
    ("actions", "action"),
];

/// `type=page,storage` to a set; blank means every type.
pub fn parse_types(t: Option<&str>) -> BTreeSet<String> {
    t.unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

fn s(row: &Map<String, Value>, key: &str) -> String {
    match row.get(key) {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(v)) => v.clone(),
        Some(other) => other.to_string(),
    }
}

fn label(item: &Map<String, Value>) -> String {
    let title = s(item, "title");
    if !title.trim().is_empty() {
        return title.trim().to_string();
    }
    s(item, "name")
}

fn flatten(index: &Map<String, Value>, service: &str, types: &[(&str, &str)]) -> Vec<Map<String, Value>> {
    let mut out = Vec::new();
    for (bucket, ty) in types {
        let Some(Value::Array(items)) = index.get(*bucket) else { continue };
        for item in items {
            let Value::Object(item) = item else { continue };
            let mut row = Map::new();
            row.insert("service".into(), json!(service));
            row.insert("type".into(), json!(ty));
            row.insert("name".into(), item.get("name").cloned().unwrap_or(Value::Null));
            row.insert("title".into(), item.get("title").cloned().unwrap_or(Value::Null));
            row.insert("label".into(), json!(label(item)));
            row.insert("id".into(), item.get("id").cloned().unwrap_or(Value::Null));
            row.insert("version".into(), item.get("version").cloned().unwrap_or(Value::Null));
            row.insert("clientCode".into(), item.get("clientCode").cloned().unwrap_or(Value::Null));
            out.push(row);
        }
    }
    out
}

/// `String.compareToIgnoreCase`: char by char, each folded to upper then lower case.
pub fn compare_ignore_case(a: &str, b: &str) -> Ordering {
    let fold = |c: char| {
        let u = c.to_uppercase().next().unwrap_or(c);
        u.to_lowercase().next().unwrap_or(u)
    };
    let (mut x, mut y) = (a.chars(), b.chars());
    loop {
        match (x.next(), y.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(c1), Some(c2)) => {
                let (f1, f2) = (fold(c1), fold(c2));
                if f1 != f2 {
                    return f1.cmp(&f2);
                }
            }
        }
    }
}

/// The whole index: `uiIndex` / `coreIndex` are the services' answers (empty when they failed).
pub fn build(
    app_code: &str,
    requested_client_code: Option<&str>,
    ui_index: &Map<String, Value>,
    core_index: &Map<String, Value>,
    query: Option<&str>,
    types: &BTreeSet<String>,
) -> Value {
    let mut objects = flatten(ui_index, "ui", UI_TYPES);
    objects.extend(flatten(core_index, "core", CORE_TYPES));

    let needle = query.unwrap_or("").trim().to_lowercase();
    if !needle.is_empty() || !types.is_empty() {
        objects.retain(|row| {
            (types.is_empty() || types.contains(&s(row, "type")))
                && (needle.is_empty() || s(row, "name").to_lowercase().contains(&needle))
        });
    }
    // Stable, like Java's List.sort: ties keep ui before core and each service's own order.
    objects.sort_by(|a, b| s(a, "type").cmp(&s(b, "type")).then_with(|| compare_ignore_case(&s(a, "name"), &s(b, "name"))));

    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut by_service: BTreeMap<String, u64> = BTreeMap::new();
    for row in &objects {
        *counts.entry(s(row, "type")).or_default() += 1;
        *by_service.entry(format!("{}_{}", s(row, "service"), s(row, "type"))).or_default() += 1;
    }

    let client_code = {
        let from_ui = s(ui_index, "clientCode");
        let from_core = s(core_index, "clientCode");
        if !from_ui.is_empty() {
            json!(from_ui)
        } else if !from_core.is_empty() {
            json!(from_core)
        } else {
            requested_client_code.map(|c| json!(c)).unwrap_or(Value::Null)
        }
    };

    let mut result = Map::new();
    result.insert("appCode".into(), json!(app_code));
    result.insert("clientCode".into(), client_code);
    result.insert("count".into(), json!(objects.len()));
    result.insert("counts".into(), json!(counts));
    result.insert("countsByServiceType".into(), json!(by_service));
    result.insert("services".into(), json!({"ui": !ui_index.is_empty(), "core": !core_index.is_empty()}));
    result.insert("objects".into(), Value::Array(objects.into_iter().map(Value::Object).collect()));
    Value::Object(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    fn sample() -> (Map<String, Value>, Map<String, Value>) {
        let ui = m(json!({
            "clientCode": "SYSTEM",
            "pages": [{"name": "home", "title": "Home", "id": "p1", "version": 2, "clientCode": "SYSTEM"},
                      {"name": "Leads", "id": "p2", "version": 1, "clientCode": "SYSTEM"}],
            "functions": [{"name": "Common.go", "id": "f1", "version": 1, "clientCode": "SYSTEM"}],
            "unknownBucket": [{"name": "x"}]
        }));
        let core = m(json!({
            "clientCode": "SYSTEM",
            "functions": [{"name": "common.go", "title": "  ", "id": "f2", "version": 3, "clientCode": "SYSTEM"}],
            "storages": [{"name": "lead", "id": "s1", "version": 1, "clientCode": "SYSTEM"}]
        }));
        (ui, core)
    }

    #[test]
    fn flattens_sorts_and_counts_like_java() {
        let (ui, core) = sample();
        let v = build("app", None, &ui, &core, None, &BTreeSet::new());
        assert_eq!(v["count"], 5);
        assert_eq!(v["counts"], json!({"function": 2, "page": 2, "storage": 1}));
        assert_eq!(v["countsByServiceType"], json!({"core_function": 1, "core_storage": 1, "ui_function": 1, "ui_page": 2}));
        let names: Vec<(String, String)> = v["objects"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| (o["service"].as_str().unwrap().to_string(), o["name"].as_str().unwrap().to_string()))
            .collect();
        // Same type, names equal ignoring case: ui stays before core (stable sort).
        assert_eq!(
            names,
            vec![
                ("ui".into(), "Common.go".into()),
                ("core".into(), "common.go".into()),
                ("ui".into(), "home".into()),
                ("ui".into(), "Leads".into()),
                ("core".into(), "lead".into()),
            ]
        );
        assert_eq!(v["objects"][2]["label"], "Home");
        assert_eq!(v["objects"][1]["label"], "common.go", "blank title falls back to the name");
        assert_eq!(v["objects"][3]["title"], Value::Null);
        assert_eq!(v["services"], json!({"ui": true, "core": true}));
        assert_eq!(v["clientCode"], "SYSTEM");
    }

    #[test]
    fn filters_by_query_and_type() {
        let (ui, core) = sample();
        let v = build("app", None, &ui, &core, Some(" LEA "), &parse_types(Some("page, storage")));
        assert_eq!(v["count"], 2);
        assert_eq!(v["counts"], json!({"page": 1, "storage": 1}));
    }

    #[test]
    fn degraded_half_and_client_fallback() {
        let (ui, _) = sample();
        let v = build("app", Some("FIN"), &Map::new(), &Map::new(), None, &BTreeSet::new());
        assert_eq!(v["clientCode"], "FIN");
        assert_eq!(v["services"], json!({"ui": false, "core": false}));
        assert_eq!(v["count"], 0);
        let v = build("app", None, &ui, &Map::new(), None, &BTreeSet::new());
        assert_eq!(v["services"], json!({"ui": true, "core": false}));
        let v = build("app", None, &Map::new(), &Map::new(), None, &BTreeSet::new());
        assert_eq!(v["clientCode"], Value::Null);
    }

    #[test]
    fn ignore_case_order() {
        assert_eq!(compare_ignore_case("abc", "ABD"), Ordering::Less);
        assert_eq!(compare_ignore_case("Abc", "abc"), Ordering::Equal);
        assert_eq!(compare_ignore_case("ab", "abc"), Ordering::Less);
        assert_eq!(parse_types(Some(" , page,,storage ")), ["page", "storage"].iter().map(|s| s.to_string()).collect());
        assert!(parse_types(None).is_empty());
    }
}
