//! What kirun-java's `Schema`, `FunctionSignature` and `FunctionDefinition` look like on the
//! wire, for the `repositoryFind` routes.
//!
//! Java never serializes a stored definition as it is: it reads it into the kirun-java class
//! with Gson (`gson.fromJson(gson.toJsonTree(definition), Schema.class)`) and writes that
//! object back, with Gson for functions and with Jackson for schemas. The read drops unknown
//! fields, fills the field defaults (`namespace` `_`, `version` 1, `variableArgument` false,
//! `type` `EXPRESSION`) and runs the custom adapters (`Type`, `ArraySchemaType`,
//! `AdditionalType`); the write follows the class's field order.
//!
//! [`gson_schema`] and [`gson_signature`] do the Gson read and write in one step, on JSON:
//! the result is what Gson writes (before nulls are dropped, which [`crate::gson`] does).
//! [`jackson_schema`] turns that into what Jackson writes for the same object: the adapters
//! are absent there, so `items` and the additional types appear as beans, and the two getters
//! without a field (`title`, `fullName`) are added.

use serde_json::{Map, Value};

const TEMPORARY: &str = "_";

const STRING_FORMATS: &[&str] = &["DATETIME", "TIME", "DATE", "EMAIL", "REGEX", "DECIMAL", "ID"];

const SCHEMA_TYPES: &[&str] = &["INTEGER", "LONG", "FLOAT", "DOUBLE", "STRING", "OBJECT", "ARRAY", "BOOLEAN", "NULL"];

fn str_of(v: &Value) -> Option<Value> {
    match v {
        Value::String(_) => Some(v.clone()),
        // Gson reads a number or a boolean into a String field as its text.
        Value::Number(n) => Some(Value::String(crate::gson::number_to_java_string(n))),
        Value::Bool(b) => Some(Value::String(b.to_string())),
        _ => None,
    }
}

fn int_of(v: &Value) -> Option<Value> {
    match v {
        Value::Number(n) => n
            .as_i64()
            .or_else(|| n.as_f64().filter(|f| f.fract() == 0.0).map(|f| f as i64))
            .map(Value::from),
        Value::String(s) => s.trim().parse::<i64>().ok().map(Value::from),
        _ => None,
    }
}

fn bool_of(v: &Value) -> Option<Value> {
    match v {
        Value::Bool(_) => Some(v.clone()),
        Value::String(s) if s.eq_ignore_ascii_case("true") => Some(Value::Bool(true)),
        Value::String(s) if s.eq_ignore_ascii_case("false") => Some(Value::Bool(false)),
        _ => None,
    }
}

/// `SchemaTypeAdapter.read`: a string is a `SingleType`, an array a `MultipleType` (a set).
fn type_of(v: &Value) -> Option<Value> {
    let one = |s: &str| {
        let up = s.to_ascii_uppercase();
        let up = if up == "NUMBER" { "DOUBLE".to_string() } else { up };
        SCHEMA_TYPES.contains(&up.as_str()).then_some(up)
    };
    match v {
        Value::String(s) => one(s).map(Value::String),
        Value::Array(a) => {
            let mut out: Vec<Value> = Vec::new();
            for t in a.iter().filter_map(Value::as_str).filter_map(one) {
                let t = Value::String(t);
                if !out.contains(&t) {
                    out.push(t);
                }
            }
            Some(Value::Array(out))
        }
        _ => None,
    }
}

fn schemas_of(v: &Value) -> Option<Value> {
    v.as_array().map(|a| Value::Array(a.iter().map(|s| gson_schema(s).unwrap_or(Value::Null)).collect()))
}

fn schema_map_of(v: &Value) -> Option<Value> {
    v.as_object().map(|m| {
        Value::Object(m.iter().map(|(k, s)| (k.clone(), gson_schema(s).unwrap_or(Value::Null))).collect())
    })
}

/// `AdditionalTypeAdapter.read` then `write`: a boolean, or a schema.
fn additional_of(v: &Value) -> Option<Value> {
    match v {
        Value::Bool(_) => Some(v.clone()),
        Value::Object(m) => {
            if let Some(b) = m.get("booleanValue") {
                bool_of(b)
            } else if let Some(s) = m.get("schemaValue") {
                gson_schema(s)
            } else {
                gson_schema(v)
            }
        }
        _ => None,
    }
}

/// `ArraySchemaTypeAdapter.read` then `write`: one schema written as itself, a tuple as an
/// array of schemas.
fn items_of(v: &Value) -> Option<Value> {
    match v {
        Value::Array(_) => schemas_of(v),
        Value::Object(m) => {
            if let Some(s) = m.get("singleSchema") {
                gson_schema(s)
            } else if let Some(t) = m.get("tupleSchema") {
                schemas_of(t)
            } else {
                gson_schema(v)
            }
        }
        _ => None,
    }
}

/// A `Map<String, Object>` read by Gson's `ObjectTypeAdapter`: every number becomes a
/// `Double`.
fn object_map_of(v: &Value) -> Option<Value> {
    fn doubles(v: &Value) -> Value {
        match v {
            Value::Number(n) => serde_json::Number::from_f64(n.as_f64().unwrap_or(0.0))
                .map(Value::Number)
                .unwrap_or(Value::Null),
            Value::Array(a) => Value::Array(a.iter().map(doubles).collect()),
            Value::Object(m) => Value::Object(m.iter().map(|(k, x)| (k.clone(), doubles(x))).collect()),
            other => other.clone(),
        }
    }
    v.as_object().map(|_| doubles(v))
}

fn string_map_of(v: &Value) -> Option<Value> {
    v.as_object()
        .map(|m| Value::Object(m.iter().map(|(k, x)| (k.clone(), str_of(x).unwrap_or(Value::Null))).collect()))
}

fn details_of(v: &Value) -> Option<Value> {
    let m = v.as_object()?;
    let mut out = Map::new();
    put(&mut out, m, "preferredComponent", str_of);
    put(&mut out, m, "validationMessages", string_map_of);
    put(&mut out, m, "properties", object_map_of);
    put(&mut out, m, "styleProperties", object_map_of);
    put(&mut out, m, "order", int_of);
    put(&mut out, m, "label", str_of);
    Some(Value::Object(out))
}

fn put(out: &mut Map<String, Value>, m: &Map<String, Value>, key: &str, f: impl Fn(&Value) -> Option<Value>) {
    if let Some(v) = m.get(key).filter(|v| !v.is_null()).and_then(f) {
        out.insert(key.to_string(), v);
    }
}

fn put_as_is(out: &mut Map<String, Value>, m: &Map<String, Value>, key: &str) {
    if let Some(v) = m.get(key).filter(|v| !v.is_null()) {
        out.insert(key.to_string(), v.clone());
    }
}

/// kirun-java `Schema` read and written by Gson. `None` when `v` is not an object.
pub fn gson_schema(v: &Value) -> Option<Value> {
    let m = v.as_object()?;
    let mut out = Map::new();
    match m.get("namespace") {
        None => {
            out.insert("namespace".into(), Value::String(TEMPORARY.into()));
        }
        Some(ns) => {
            if let Some(s) = str_of(ns) {
                out.insert("namespace".into(), s);
            }
        }
    }
    put(&mut out, m, "name", str_of);
    out.insert(
        "version".into(),
        m.get("version").and_then(int_of).unwrap_or(Value::from(1)),
    );
    put(&mut out, m, "ref", str_of);
    put(&mut out, m, "type", type_of);
    put(&mut out, m, "anyOf", schemas_of);
    put(&mut out, m, "allOf", schemas_of);
    put(&mut out, m, "oneOf", schemas_of);
    put(&mut out, m, "not", gson_schema);
    put(&mut out, m, "description", str_of);
    put_as_is(&mut out, m, "examples");
    put_as_is(&mut out, m, "defaultValue");
    put(&mut out, m, "comment", str_of);
    put_as_is(&mut out, m, "enums");
    put_as_is(&mut out, m, "constant");
    put(&mut out, m, "pattern", str_of);
    put(&mut out, m, "format", |f| {
        f.as_str().filter(|s| STRING_FORMATS.contains(s)).map(|s| Value::String(s.into()))
    });
    put(&mut out, m, "minLength", int_of);
    put(&mut out, m, "maxLength", int_of);
    put(&mut out, m, "multipleOf", int_of);
    for k in ["minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"] {
        put(&mut out, m, k, |x| x.is_number().then(|| x.clone()));
    }
    put(&mut out, m, "properties", schema_map_of);
    put(&mut out, m, "additionalProperties", additional_of);
    put(&mut out, m, "required", |r| {
        r.as_array().map(|a| Value::Array(a.iter().map(|x| str_of(x).unwrap_or(Value::Null)).collect()))
    });
    put(&mut out, m, "propertyNames", gson_schema);
    put(&mut out, m, "minProperties", int_of);
    put(&mut out, m, "maxProperties", int_of);
    put(&mut out, m, "patternProperties", schema_map_of);
    put(&mut out, m, "items", items_of);
    put(&mut out, m, "contains", gson_schema);
    for k in ["minContains", "maxContains", "minItems", "maxItems"] {
        put(&mut out, m, k, int_of);
    }
    put(&mut out, m, "uniqueItems", bool_of);
    put(&mut out, m, "additionalItems", additional_of);
    put(&mut out, m, "$defs", schema_map_of);
    put(&mut out, m, "permission", str_of);
    put(&mut out, m, "details", details_of);
    put(&mut out, m, "viewDetails", details_of);
    Some(Value::Object(out))
}

fn parameter_of(v: &Value) -> Option<Value> {
    let m = v.as_object()?;
    let mut out = Map::new();
    put(&mut out, m, "schema", gson_schema);
    put(&mut out, m, "parameterName", |p| str_of(p).filter(|s| s.as_str() != Some("")));
    out.insert(
        "variableArgument".into(),
        m.get("variableArgument").and_then(bool_of).unwrap_or(Value::Bool(false)),
    );
    match m.get("type") {
        None => {
            out.insert("type".into(), Value::String("EXPRESSION".into()));
        }
        Some(t) => {
            if let Some(t) = t.as_str().filter(|t| *t == "EXPRESSION" || *t == "CONSTANT") {
                out.insert("type".into(), Value::String(t.into()));
            }
        }
    }
    Some(Value::Object(out))
}

fn event_of(v: &Value) -> Option<Value> {
    let m = v.as_object()?;
    let mut out = Map::new();
    put(&mut out, m, "name", str_of);
    put(&mut out, m, "parameters", schema_map_of);
    Some(Value::Object(out))
}

/// kirun-java `FunctionSignature` (or, with `definition`, the `FunctionDefinition` that
/// `getOnlySignatureFromDefinition` makes: `steps` and `stepGroups` emptied) read and written
/// by Gson.
pub fn gson_signature(v: &Value, definition: bool) -> Value {
    let empty = Map::new();
    let m = v.as_object().unwrap_or(&empty);
    let mut out = Map::new();
    if definition {
        out.insert("version".into(), m.get("version").and_then(int_of).unwrap_or(Value::from(1)));
        out.insert("steps".into(), Value::Object(Map::new()));
        out.insert("stepGroups".into(), Value::Object(Map::new()));
    }
    put(&mut out, m, "namespace", str_of);
    put(&mut out, m, "name", str_of);
    for (key, f) in [("parameters", parameter_of as fn(&Value) -> Option<Value>), ("events", event_of)] {
        match m.get(key) {
            // The field's initial value, `Map.of()`.
            None => {
                out.insert(key.into(), Value::Object(Map::new()));
            }
            Some(Value::Object(entries)) => {
                out.insert(
                    key.into(),
                    Value::Object(entries.iter().map(|(k, x)| (k.clone(), f(x).unwrap_or(Value::Null))).collect()),
                );
            }
            Some(_) => {}
        }
    }
    put(&mut out, m, "description", str_of);
    put(&mut out, m, "documentation", str_of);
    put(&mut out, m, "metadata", object_map_of);
    Value::Object(out)
}

fn jackson_additional(v: &Value) -> Value {
    match v {
        Value::Bool(b) => serde_json::json!({ "booleanValue": b }),
        other => serde_json::json!({ "schemaValue": jackson_schema(other) }),
    }
}

/// The Gson form of a schema (from [`gson_schema`]) as Jackson writes the same object, with
/// nulls left out (`NON_NULL`).
pub fn jackson_schema(g: &Value) -> Value {
    let Some(m) = g.as_object() else {
        return g.clone();
    };
    let mut out = Map::new();
    for (k, v) in m {
        let w = match k.as_str() {
            "anyOf" | "allOf" | "oneOf" => match v {
                Value::Array(a) => Value::Array(a.iter().map(jackson_schema).collect()),
                other => other.clone(),
            },
            "not" | "propertyNames" | "contains" => jackson_schema(v),
            "properties" | "patternProperties" | "$defs" => match v {
                Value::Object(p) => Value::Object(p.iter().map(|(n, s)| (n.clone(), jackson_schema(s))).collect()),
                other => other.clone(),
            },
            "items" => match v {
                Value::Array(a) => serde_json::json!({
                    "tupleSchema": a.iter().map(jackson_schema).collect::<Vec<_>>(),
                    "singleType": false,
                }),
                other => serde_json::json!({ "singleSchema": jackson_schema(other), "singleType": true }),
            },
            "additionalProperties" | "additionalItems" => jackson_additional(v),
            _ => v.clone(),
        };
        out.insert(k.clone(), w);
    }
    let ns = m.get("namespace").and_then(Value::as_str);
    let name = m.get("name").and_then(Value::as_str);
    // getTitle() and getFullName(): Java string concatenation writes a null as "null".
    let title = match ns {
        None | Some(TEMPORARY) => name.map(str::to_string),
        Some(ns) => Some(format!("{ns}.{}", name.unwrap_or("null"))),
    };
    if let Some(t) = title {
        out.insert("title".into(), Value::String(t));
    }
    out.insert(
        "fullName".into(),
        Value::String(format!("{}.{}", ns.unwrap_or("null"), name.unwrap_or("null"))),
    );
    Value::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn schema_defaults_and_adapters() {
        // Stored as markauto's Model.Conditions; Java (Jackson) served the expected value below.
        let stored = json!({"name":"Conditions","namespace":"Model","type":"OBJECT","properties":{"conditions":{"type":"ARRAY","items":{"singleSchema":{"anyOf":[{"ref":"Model.FilterCondition"},{"ref":"Model.ComplexCondition"}]}}}}});
        let j = jackson_schema(&gson_schema(&stored).unwrap());
        let expected = json!({
          "namespace" : "Model", "name" : "Conditions", "version" : 1, "type" : "OBJECT",
          "properties" : {"conditions" : {
              "namespace" : "_", "version" : 1, "type" : "ARRAY",
              "items" : {
                "singleSchema" : {"namespace" : "_", "version" : 1,
                  "anyOf" : [
                    {"namespace" : "_", "version" : 1, "ref" : "Model.FilterCondition", "fullName" : "_.null"},
                    {"namespace" : "_", "version" : 1, "ref" : "Model.ComplexCondition", "fullName" : "_.null"}],
                  "fullName" : "_.null"},
                "singleType" : true},
              "fullName" : "_.null"}},
          "title" : "Model.Conditions", "fullName" : "Model.Conditions"});
        assert_eq!(j, expected);
    }

    #[test]
    fn gson_items_and_types() {
        let s = gson_schema(&json!({"type": ["integer"], "items": {"type": "number"}})).unwrap();
        assert_eq!(s, json!({"namespace":"_","version":1,"type":["INTEGER"],"items":{"namespace":"_","version":1,"type":"DOUBLE"}}));
    }

    #[test]
    fn definition_signature() {
        // Test.fibonacci on appbuilder: what Java's repositoryFind sent.
        let def = json!({"name":"fibonacci","namespace":"Test","parameters":{"n":{"parameterName":"n","schema":{"type":["INTEGER"]}}},
            "events":{"output":{"name":"output","parameters":{"result":{"type":["ARRAY"],"items":{"type":["INTEGER"]}}}}},
            "steps":{"a":{}}});
        let g = gson_signature(&def, true);
        assert_eq!(crate::gson::to_gson(&g),
            r#"{"version":1,"steps":{},"stepGroups":{},"namespace":"Test","name":"fibonacci","parameters":{"n":{"schema":{"namespace":"_","version":1,"type":["INTEGER"]},"parameterName":"n","variableArgument":false,"type":"EXPRESSION"}},"events":{"output":{"name":"output","parameters":{"result":{"namespace":"_","version":1,"type":["ARRAY"],"items":{"namespace":"_","version":1,"type":["INTEGER"]}}}}}}"#);
    }

    #[test]
    fn every_schema_field_in_java_order() {
        let stored: Value = serde_json::from_str(
            r#"{
            "name": "All", "namespace": "N", "version": "2", "ref": 5, "type": ["number", "string", "STRING", "bogus"],
            "anyOf": [{"type": "INTEGER"}, 3], "allOf": [{"type": "LONG"}], "oneOf": [{"type": "BOOLEAN"}],
            "not": {"type": "NULL"}, "description": true, "examples": [1, "x"], "defaultValue": {"a": null},
            "comment": "c", "enums": ["A"], "constant": 1, "pattern": "^a", "format": "EMAIL",
            "minLength": 1.0, "maxLength": "9", "multipleOf": 2, "minimum": 0, "maximum": 1.5,
            "exclusiveMinimum": "x", "exclusiveMaximum": 9,
            "properties": {"p": {"type": "STRING"}},
            "additionalProperties": {"booleanValue": "true"},
            "required": ["p", 7], "propertyNames": {"pattern": "^k"}, "minProperties": 1, "maxProperties": 2,
            "patternProperties": {"^x": {"type": "INTEGER"}},
            "items": [{"type": "INTEGER"}, {"type": "STRING"}], "contains": {"type": "INTEGER"},
            "minContains": 1, "maxContains": 2, "minItems": 0, "maxItems": 5, "uniqueItems": "false",
            "additionalItems": {"schemaValue": {"type": "STRING"}},
            "$defs": {"d": {"type": "OBJECT"}}, "permission": "P",
            "details": {"preferredComponent": "x", "validationMessages": {"a": 1}, "properties": {"n": 1},
                        "styleProperties": {"s": [2]}, "order": 3, "label": "L", "junk": 1},
            "viewDetails": {"label": "V"},
            "junk": 1
        }"#,
        )
        .unwrap();
        let g = gson_schema(&stored).unwrap();
        let keys: Vec<&str> = g.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "namespace", "name", "version", "ref", "type", "anyOf", "allOf", "oneOf", "not", "description",
                "examples", "defaultValue", "comment", "enums", "constant", "pattern", "format", "minLength",
                "maxLength", "multipleOf", "minimum", "maximum", "exclusiveMaximum", "properties",
                "additionalProperties", "required", "propertyNames", "minProperties", "maxProperties",
                "patternProperties", "items", "contains", "minContains", "maxContains", "minItems", "maxItems",
                "uniqueItems", "additionalItems", "$defs", "permission", "details", "viewDetails"
            ]
        );
        assert_eq!(g["version"], json!(2));
        assert_eq!(g["ref"], json!("5"));
        assert_eq!(g["type"], json!(["DOUBLE", "STRING"]));
        assert_eq!(g["anyOf"][1], Value::Null);
        assert_eq!(g["description"], json!("true"));
        assert_eq!(g["minLength"], json!(1));
        assert_eq!(g["maxLength"], json!(9));
        assert_eq!(g["additionalProperties"], json!(true));
        assert_eq!(g["required"], json!(["p", "7"]));
        assert_eq!(g["uniqueItems"], json!(false));
        assert_eq!(g["additionalItems"]["type"], json!("STRING"));
        assert_eq!(g["details"]["validationMessages"], json!({"a": "1"}));
        assert_eq!(g["details"]["properties"], json!({"n": 1.0}));
        assert!(g["details"].get("junk").is_none());

        // Jackson writes the adapters' types as beans and adds title / fullName.
        let j = jackson_schema(&g);
        assert_eq!(j["items"]["singleType"], json!(false));
        assert_eq!(j["items"]["tupleSchema"].as_array().unwrap().len(), 2);
        assert_eq!(j["additionalProperties"], json!({"booleanValue": true}));
        assert_eq!(j["additionalItems"]["schemaValue"]["fullName"], json!("_.null"));
        assert_eq!(j["not"]["fullName"], json!("_.null"));
        assert_eq!(j["anyOf"][0]["fullName"], json!("_.null"));
        assert_eq!(j["patternProperties"]["^x"]["fullName"], json!("_.null"));
        assert_eq!(j["title"], json!("N.All"));
        assert_eq!(jackson_schema(&json!(3)), json!(3));
    }

    #[test]
    fn adapter_shapes() {
        // A bare schema in `additionalProperties`, `items.tupleSchema`, a namespace null.
        let g = gson_schema(&json!({"namespace": null, "additionalProperties": {"type": "STRING"},
            "items": {"tupleSchema": [{"type": "STRING"}]}, "additionalItems": false, "format": "WEEKDAY",
            "type": 7})).unwrap();
        assert!(g.get("namespace").is_none());
        assert!(g.get("format").is_none());
        assert!(g.get("type").is_none());
        assert_eq!(g["additionalProperties"]["type"], json!("STRING"));
        assert_eq!(g["items"].as_array().unwrap().len(), 1);
        let j = jackson_schema(&g);
        assert_eq!(j["additionalItems"], json!({"booleanValue": false}));
        assert_eq!(j["fullName"], json!("null.null"));
        assert!(j.get("title").is_none());
        assert_eq!(jackson_schema(&json!({"namespace": "_", "name": "n"}))["title"], json!("n"));
        assert!(gson_schema(&json!("x")).is_none());
        assert!(gson_schema(&json!({"items": 5})).unwrap().get("items").is_none());
        assert!(gson_schema(&json!({"additionalProperties": 5})).unwrap().get("additionalProperties").is_none());
        assert!(gson_schema(&json!({"properties": 5})).unwrap().get("properties").is_none());
    }

    #[test]
    fn signature_fields() {
        let sig = gson_signature(
            &json!({"namespace": "A", "name": 3, "description": "d", "documentation": "doc", "metadata": {"m": [1]},
                    "parameters": {"p": {"parameterName": "", "variableArgument": "true", "type": "CONSTANT"},
                                   "q": {"type": "OTHER"}, "r": 1},
                    "events": "x"}),
            false,
        );
        assert_eq!(sig["name"], json!("3"));
        assert_eq!(sig["metadata"], json!({"m": [1.0]}));
        assert_eq!(sig["parameters"]["p"], json!({"variableArgument": true, "type": "CONSTANT"}));
        assert_eq!(sig["parameters"]["q"], json!({"variableArgument": false}));
        assert_eq!(sig["parameters"]["r"], Value::Null);
        assert!(sig.get("events").is_none());
        let empty = gson_signature(&json!(null), false);
        assert_eq!(empty, json!({"parameters": {}, "events": {}}));
        assert_eq!(gson_signature(&json!({"version": 3}), true)["version"], json!(3));
    }

}
