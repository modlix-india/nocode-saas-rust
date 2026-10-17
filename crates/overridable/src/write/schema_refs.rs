//! commons-mongo `SchemaRefs`: the schema documents a raw KIRun schema definition refers to,
//! and the documents that would change if one did. Schemas use it for their transport order,
//! storages for which tables to rebuild.

use std::collections::{HashMap, VecDeque};

use indexmap::IndexSet;

use crate::json::JValue;

/// Every other schema `definition` refers to, in the order the walk meets them. A reference is
/// a plain `ref` string anywhere in the tree (never `$ref`); the walk is blind to the shape
/// because `items` and the `additional*` fields are stored in several union forms.
pub fn collect(definition: Option<&JValue>) -> IndexSet<String> {
    let mut refs = IndexSet::new();
    if let Some(d) = definition {
        collect_into(d, &mut refs);
    }
    refs
}

fn collect_into(node: &JValue, refs: &mut IndexSet<String>) {
    match node {
        JValue::Object(m) => {
            for (k, v) in m {
                match (k.as_str(), v) {
                    ("ref", JValue::Str(r)) => add_schema_names(r, refs),
                    _ => collect_into(v, refs),
                }
            }
        }
        JValue::Array(a) => a.iter().for_each(|v| collect_into(v, refs)),
        _ => {}
    }
}

/// The document names a ref could point at: the part before the first `/`, then each prefix
/// that still has a dot (`Model.UserSegment._id` names `Model.UserSegment._id` and
/// `Model.UserSegment`). `#` refs are internal and name nothing.
fn add_schema_names(r: &str, refs: &mut IndexSet<String>) {
    if r.trim().is_empty() || r.starts_with('#') {
        return;
    }
    let mut name = r.split('/').next().unwrap_or_default().to_string();
    while let Some(dot) = name.rfind('.') {
        refs.insert(name.clone());
        name.truncate(dot);
    }
}

/// Every document that would change if `target` changed, `target` included: reverse
/// reachability over `refs_by_document`, safe on cycles.
pub fn referencing_closure(refs_by_document: &HashMap<String, IndexSet<String>>, target: &str) -> IndexSet<String> {
    let mut referenced_by: HashMap<&str, IndexSet<&str>> = HashMap::new();
    for (name, refs) in refs_by_document {
        for r in refs {
            referenced_by.entry(r.as_str()).or_default().insert(name.as_str());
        }
    }
    let mut closure = IndexSet::new();
    let mut pending = VecDeque::new();
    closure.insert(target.to_string());
    pending.push_back(target.to_string());
    while let Some(next) = pending.pop_front() {
        for parent in referenced_by.get(next.as_str()).into_iter().flatten() {
            if closure.insert(parent.to_string()) {
                pending.push_back(parent.to_string());
            }
        }
    }
    closure
}

#[cfg(test)]
mod tests {
    //! commons-mongo `SchemaRefsTest`, case for case, and `AbstractSchemaServiceDependencyTest`.
    use super::*;
    use crate::json::parse;

    fn refs(s: &str) -> Vec<String> {
        collect(Some(&parse(s.as_bytes()).unwrap())).into_iter().collect()
    }

    #[test]
    fn collecting() {
        assert_eq!(refs(r#"{"ref":"App.Customer"}"#), ["App.Customer"]);
        assert_eq!(refs(r#"{"type":"OBJECT","properties":{"c":{"ref":"App.City"}}}"#), ["App.City"]);
        assert_eq!(refs(r#"{"type":"ARRAY","items":{"ref":"App.Line"}}"#), ["App.Line"]);
        assert_eq!(refs(r#"{"items":[{"ref":"App.A"},{"ref":"App.B"}]}"#), ["App.A", "App.B"]);
        assert_eq!(refs(r#"{"ref":"App.Customer/properties/name"}"#), ["App.Customer"]);
        let dotted = refs(r#"{"ref":"Model.UserSegment._id"}"#);
        assert!(dotted.contains(&"Model.UserSegment._id".to_string()) && dotted.contains(&"Model.UserSegment".to_string()));
        assert!(!dotted.contains(&"Model".to_string()));
        assert!(refs(r##"{"ref":"#/$defs/Inner"}"##).is_empty());
        assert!(refs(r#"{"type":"STRING"}"#).is_empty());
        assert!(collect(None).is_empty());
    }

    #[test]
    fn dependency_cases() {
        assert_eq!(refs(r#"{"ref":"Model.FilterCondition"}"#), ["Model.FilterCondition"]);
        assert_eq!(
            refs(r#"{"properties":{"a":{"ref":"Model.Address"},"s":{"ref":"EnumModel.EmploymentStatus"}}}"#),
            ["Model.Address", "EnumModel.EmploymentStatus"]
        );
        let all = refs(
            r#"{"anyOf":[{"ref":"Model.A"}],"allOf":[{"ref":"Model.B"}],"oneOf":[{"ref":"Model.C"}],"not":{"ref":"Model.D"},
            "contains":{"ref":"Model.E"},"propertyNames":{"ref":"Model.F"},"patternProperties":{"x":{"ref":"Model.G"}},
            "$defs":{"d":{"ref":"Model.H"}},"items":{"singleSchema":{"ref":"Model.I"}},"additionalItems":{"schemaValue":{"ref":"Model.J"}},
            "additionalProperties":{"ref":"Model.K"},"properties":{"deep":{"items":[{"ref":"Model.L"}]},"flag":{"additionalProperties":true}}}"#,
        );
        let expected: Vec<String> = "ABCDEFGHIJKL".chars().map(|c| format!("Model.{c}")).collect();
        let mut sorted = all.clone();
        sorted.sort();
        assert_eq!(sorted, expected);
        assert_eq!(refs(r#"{"ref":"Model.User/properties/name"}"#), ["Model.User"]);
        assert_eq!(refs(r#"{"ref":"rim.Projects.Project"}"#), ["rim.Projects.Project", "rim.Projects"]);
        for internal in [r##"{"ref":"#/$defs/inner"}"##, r##"{"ref":"#/properties/name"}"##, r#"{"ref":""}"#, r#"{"ref":"Something"}"#] {
            assert!(refs(internal).is_empty(), "{internal}");
        }
        assert_eq!(refs(r#"{"ref":{"ref":"App.X"}}"#), ["App.X"], "a ref that is not a string is walked");
    }

    fn graph(edges: &[(&str, &[&str])]) -> HashMap<String, IndexSet<String>> {
        edges.iter().map(|(k, v)| (k.to_string(), v.iter().map(|s| s.to_string()).collect())).collect()
    }

    fn closure(edges: &[(&str, &[&str])], target: &str) -> Vec<String> {
        let mut v: Vec<String> = referencing_closure(&graph(edges), target).into_iter().collect();
        v[1..].sort();
        v
    }

    #[test]
    fn closures() {
        assert_eq!(closure(&[], "App.Money"), ["App.Money"]);
        assert_eq!(closure(&[("App.Order", &["App.Money"])], "App.Money"), ["App.Money", "App.Order"]);
        assert_eq!(
            closure(&[("App.Order", &["App.Money"]), ("App.Invoice", &["App.Order"])], "App.Money"),
            ["App.Money", "App.Invoice", "App.Order"]
        );
        assert!(!closure(&[("App.Order", &["App.Money"]), ("App.Page", &["App.Widget"])], "App.Money").contains(&"App.Page".to_string()));
        assert_eq!(closure(&[("App.Node", &["App.Node"])], "App.Node"), ["App.Node"]);
        assert_eq!(closure(&[("App.A", &["App.B"]), ("App.B", &["App.A"])], "App.A"), ["App.A", "App.B"]);
    }
}
