//! The signatures of core's functions ported in step 3, as the Java core declares them.
//!
//! `java_signatures.json` holds each function's signature exactly as Java's `repositoryFind`
//! writes it (Gson over kirun-java's `FunctionSignature`), keyed by full name. The Java classes
//! build these with `Map.of`, nested schemas, enums and defaults; keeping them as data, read
//! back into kirun's model, makes `repositoryFind` and the argument validation the same as
//! Java's by construction. A test checks every one reads back to what Java answers.

use std::collections::HashMap;
use std::sync::LazyLock;

use kirun::json::schema::Schema;
use kirun::model::{Event, FunctionSignature, Parameter};
use kirun::Map;
use serde_json::Value;

static SIGNATURES: LazyLock<HashMap<String, Value>> = LazyLock::new(|| {
    let all: serde_json::Map<String, Value> =
        serde_json::from_str(include_str!("java_signatures.json")).expect("java_signatures.json");
    all.into_iter().collect()
});

/// The Java JSON of `full_name`'s signature.
pub fn json(full_name: &str) -> &'static Value {
    SIGNATURES.get(full_name).unwrap_or_else(|| panic!("no Java signature for {full_name}"))
}

/// `full_name`'s signature in kirun's model.
pub fn signature(full_name: &str) -> FunctionSignature {
    from_json(json(full_name)).unwrap_or_else(|e| panic!("signature {full_name}: {e}"))
}

/// A Gson-written `FunctionSignature` read into kirun's model.
pub fn from_json(v: &Value) -> Result<FunctionSignature, String> {
    let mut params: Map<Parameter> = Map::new();
    if let Some(p) = v["parameters"].as_object() {
        for (k, pv) in p {
            params.insert(k.clone(), Parameter::from_value(pv).map_err(|e| e.to_string())?);
        }
    }
    let mut events: Map<Event> = Map::new();
    if let Some(e) = v["events"].as_object() {
        for (k, ev) in e {
            events.insert(k.clone(), Event::from_value(ev).map_err(|e| e.to_string())?);
        }
    }
    let mut sig = FunctionSignature::new(v["name"].as_str().unwrap_or_default()).set_parameters(params).set_events(events);
    if let Some(ns) = v["namespace"].as_str() {
        sig = sig.set_namespace(ns);
    }
    Ok(sig)
}

/// Every full name with a captured signature.
pub fn names() -> Vec<&'static str> {
    let mut n: Vec<&'static str> = SIGNATURES.keys().map(String::as_str).collect();
    n.sort();
    n
}

/// A schema of the Java signature's event `event`, parameter `name` (for tests and wrappers).
pub fn event_schema(full_name: &str, event: &str, name: &str) -> Option<Schema> {
    signature(full_name).get_events().get(event).and_then(|e| e.get_parameters().get(name).cloned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::java_model::gson_signature;

    /// JSON compared with schema `type` lists as sets (Java writes a `HashSet`).
    fn canon(v: &Value, key: Option<&str>) -> Value {
        match v {
            Value::Object(o) => {
                let mut keys: Vec<&String> = o.keys().collect();
                keys.sort();
                Value::Object(keys.into_iter().map(|k| (k.clone(), canon(&o[k], Some(k)))).collect())
            }
            Value::Array(a) if key == Some("type") => {
                let mut s: Vec<String> = a.iter().map(|x| x.to_string()).collect();
                s.sort();
                Value::Array(s.into_iter().map(Value::String).collect())
            }
            Value::Array(a) => Value::Array(a.iter().map(|x| canon(x, None)).collect()),
            other => other.clone(),
        }
    }

    #[test]
    fn every_signature_reads_back_to_what_java_answers() {
        assert_eq!(names().len(), 53);
        for name in names() {
            let back = gson_signature(&signature(name).to_json(), false);
            assert_eq!(canon(&back, None), canon(json(name), None), "{name}");
        }
    }

    #[test]
    fn bad_json_is_refused() {
        assert!(from_json(&serde_json::json!({"name": "x", "parameters": {"p": {"schema": null}}})).is_err());
        assert!(from_json(&serde_json::json!({"name": "x", "events": {"output": {"parameters": {"p": null}}}})).is_err());
        assert!(event_schema("CoreServices.AI.Chat", "nope", "x").is_none());
    }
}
