//! The KIRun model classes as the Java ui reads them with Gson and writes them back.
//!
//! `repositoryFind` does not return a stored definition as stored: it parses it into KIRun's
//! `FunctionDefinition` (or `Schema`) with Gson and serializes that object, which drops unknown
//! fields, fills defaults (`version: 1`, a schema's `namespace: "_"`, `override: false`, ...),
//! converts types (positions are `Float`), and orders fields as Gson does (subclass fields
//! first, then each superclass's, in declaration order). Functions go out through Gson again;
//! schemas through Jackson (`NON_EMPTY`, plus the computed `title` and `fullName`).

use overridable::json::{java_double, JMap, JValue};

#[derive(Clone, Copy, Debug)]
pub enum G {
    Str,
    /// `int` with its initial value.
    PrimInt(i64),
    BoxInt,
    BoxLong,
    /// `boolean` with its initial value.
    PrimBool(bool),
    BoxBool,
    /// `Float`.
    Float32,
    /// `Number`: Gson keeps the number's text (`LazilyParsedNumber`).
    Number,
    /// `JsonElement`: taken as is.
    Element,
    /// `Object`: Gson's `ObjectTypeAdapter`, which reads every number as a `Double`.
    Any,
    Enum(&'static [&'static str]),
    Class(&'static Class),
    MapOf(&'static G),
    ListOf(&'static G),
    /// A schema's `type` (`SchemaTypeAdapter`).
    SchemaType,
    /// `AdditionalType` (`AdditionalTypeAdapter`).
    Additional,
    /// `ArraySchemaType` (`ArraySchemaTypeAdapter`).
    ArrayItems,
}

#[derive(Debug)]
pub struct Field {
    pub name: &'static str,
    pub kind: G,
    /// A non-primitive field's initializer (`parameters = Map.of()`, `namespace = "_"`).
    pub init: Option<Init>,
}

#[derive(Clone, Copy, Debug)]
pub enum Init {
    EmptyMap,
    Str(&'static str),
}

const fn f(name: &'static str, kind: G) -> Field {
    Field { name, kind, init: None }
}

const fn fi(name: &'static str, kind: G, init: Init) -> Field {
    Field { name, kind, init: Some(init) }
}

#[derive(Debug)]
pub struct Class {
    pub name: &'static str,
    /// Gson order: the class's own fields, then its superclass's.
    pub fields: &'static [Field],
    /// Jackson's computed properties, written after the fields.
    pub jackson_getters: &'static [&'static str],
}

const PARAMETER_REFERENCE_TYPE: &[&str] = &["VALUE", "EXPRESSION"];
const PARAMETER_TYPE: &[&str] = &["CONSTANT", "EXPRESSION"];
const STRING_FORMAT: &[&str] = &["DATETIME", "TIME", "DATE", "EMAIL", "REGEX", "DECIMAL", "ID"];
const SCHEMA_TYPES: &[&str] = &["INTEGER", "LONG", "FLOAT", "DOUBLE", "STRING", "OBJECT", "ARRAY", "BOOLEAN", "NULL"];

static STR: G = G::Str;
static BOOL: G = G::BoxBool;
static SCHEMA_REF: G = G::Class(&SCHEMA);

pub static SCHEMA_DETAILS: Class = Class {
    name: "SchemaDetails",
    fields: &[
        f("preferredComponent", G::Str),
        f("validationMessages", G::MapOf(&STR)),
        f("properties", G::MapOf(&G::Any)),
        f("styleProperties", G::MapOf(&G::Any)),
        f("order", G::BoxInt),
        f("label", G::Str),
    ],
    jackson_getters: &[],
};

pub static SCHEMA: Class = Class {
    name: "Schema",
    fields: &[
        fi("namespace", G::Str, Init::Str("_")),
        f("name", G::Str),
        f("version", G::PrimInt(1)),
        f("ref", G::Str),
        f("type", G::SchemaType),
        f("anyOf", G::ListOf(&SCHEMA_REF)),
        f("allOf", G::ListOf(&SCHEMA_REF)),
        f("oneOf", G::ListOf(&SCHEMA_REF)),
        f("not", G::Class(&SCHEMA)),
        f("description", G::Str),
        f("examples", G::ListOf(&G::Element)),
        f("defaultValue", G::Element),
        f("comment", G::Str),
        f("enums", G::ListOf(&G::Element)),
        f("constant", G::Element),
        f("pattern", G::Str),
        f("format", G::Enum(STRING_FORMAT)),
        f("minLength", G::BoxInt),
        f("maxLength", G::BoxInt),
        f("multipleOf", G::BoxLong),
        f("minimum", G::Number),
        f("maximum", G::Number),
        f("exclusiveMinimum", G::Number),
        f("exclusiveMaximum", G::Number),
        f("properties", G::MapOf(&SCHEMA_REF)),
        f("additionalProperties", G::Additional),
        f("required", G::ListOf(&STR)),
        f("propertyNames", G::Class(&SCHEMA)),
        f("minProperties", G::BoxInt),
        f("maxProperties", G::BoxInt),
        f("patternProperties", G::MapOf(&SCHEMA_REF)),
        f("items", G::ArrayItems),
        f("contains", G::Class(&SCHEMA)),
        f("minContains", G::BoxInt),
        f("maxContains", G::BoxInt),
        f("minItems", G::BoxInt),
        f("maxItems", G::BoxInt),
        f("uniqueItems", G::BoxBool),
        f("additionalItems", G::Additional),
        f("$defs", G::MapOf(&SCHEMA_REF)),
        f("permission", G::Str),
        f("details", G::Class(&SCHEMA_DETAILS)),
        f("viewDetails", G::Class(&SCHEMA_DETAILS)),
    ],
    jackson_getters: &["title", "fullName"],
};

pub static POSITION: Class = Class {
    name: "Position",
    fields: &[f("left", G::Float32), f("top", G::Float32)],
    jackson_getters: &[],
};

pub static PARAMETER_REFERENCE: Class = Class {
    name: "ParameterReference",
    fields: &[
        f("key", G::Str),
        f("type", G::Enum(PARAMETER_REFERENCE_TYPE)),
        f("value", G::Element),
        f("expression", G::Str),
        f("order", G::PrimInt(0)),
    ],
    jackson_getters: &[],
};

static PARAMETER_REFERENCE_REF: G = G::Class(&PARAMETER_REFERENCE);
static PARAMETER_REFERENCES: G = G::MapOf(&PARAMETER_REFERENCE_REF);

pub static STATEMENT: Class = Class {
    name: "Statement",
    fields: &[
        f("statementName", G::Str),
        f("namespace", G::Str),
        f("name", G::Str),
        f("parameterMap", G::MapOf(&PARAMETER_REFERENCES)),
        f("dependentStatements", G::MapOf(&BOOL)),
        f("executeIftrue", G::MapOf(&BOOL)),
        // AbstractStatement
        f("comment", G::Str),
        f("description", G::Str),
        f("position", G::Class(&POSITION)),
        f("override", G::PrimBool(false)),
    ],
    jackson_getters: &[],
};

pub static STATEMENT_GROUP: Class = Class {
    name: "StatementGroup",
    fields: &[
        f("statementGroupName", G::Str),
        f("statements", G::MapOf(&BOOL)),
        f("comment", G::Str),
        f("description", G::Str),
        f("position", G::Class(&POSITION)),
        f("override", G::PrimBool(false)),
    ],
    jackson_getters: &[],
};

pub static PARAMETER: Class = Class {
    name: "Parameter",
    fields: &[
        f("schema", G::Class(&SCHEMA)),
        f("parameterName", G::Str),
        f("variableArgument", G::PrimBool(false)),
        fi("type", G::Enum(PARAMETER_TYPE), Init::Str("EXPRESSION")),
    ],
    jackson_getters: &[],
};

pub static EVENT: Class = Class {
    name: "Event",
    fields: &[f("name", G::Str), f("parameters", G::MapOf(&SCHEMA_REF))],
    jackson_getters: &[],
};

static STATEMENT_REF: G = G::Class(&STATEMENT);
static STATEMENT_GROUP_REF: G = G::Class(&STATEMENT_GROUP);
static PARAMETER_REF: G = G::Class(&PARAMETER);
static EVENT_REF: G = G::Class(&EVENT);

pub static FUNCTION_DEFINITION: Class = Class {
    name: "FunctionDefinition",
    fields: &[
        f("version", G::PrimInt(1)),
        f("steps", G::MapOf(&STATEMENT_REF)),
        f("stepGroups", G::MapOf(&STATEMENT_GROUP_REF)),
        // FunctionSignature
        f("namespace", G::Str),
        f("name", G::Str),
        fi("parameters", G::MapOf(&PARAMETER_REF), Init::EmptyMap),
        fi("events", G::MapOf(&EVENT_REF), Init::EmptyMap),
        f("description", G::Str),
        f("documentation", G::Str),
        f("metadata", G::MapOf(&G::Any)),
    ],
    jackson_getters: &[],
};

/// What Gson cannot read (it throws, and the request fails with a 500).
#[derive(Debug)]
pub struct GsonError(pub String);

type R<T> = Result<T, GsonError>;

fn err<T>(what: &str, v: &JValue) -> R<T> {
    Err(GsonError(format!("Gson cannot read {what} from {}", v.java_to_string())))
}

/// `JsonPrimitive.getAsString()`.
fn as_string(v: &JValue) -> Option<String> {
    match v {
        JValue::Str(s) => Some(s.clone()),
        JValue::Int(i) => Some(i.to_string()),
        JValue::Float(x) => Some(java_double(*x)),
        JValue::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn read_value(kind: G, v: &JValue) -> R<JValue> {
    if v.is_null() {
        return Ok(JValue::Null);
    }
    Ok(match kind {
        G::Str => match as_string(v) {
            Some(s) => JValue::Str(s),
            None => return err("a String", v),
        },
        G::PrimInt(_) | G::BoxInt => match v {
            JValue::Int(i) => JValue::Int(*i as i32 as i64),
            JValue::Float(x) => JValue::Int(*x as i32 as i64),
            JValue::Str(s) => match s.trim().parse::<i32>() {
                Ok(i) => JValue::Int(i as i64),
                Err(_) => return err("an int", v),
            },
            _ => return err("an int", v),
        },
        G::BoxLong => match v {
            JValue::Int(i) => JValue::Int(*i),
            JValue::Float(x) => JValue::Int(*x as i64),
            JValue::Str(s) => match s.trim().parse::<i64>() {
                Ok(i) => JValue::Int(i),
                Err(_) => return err("a long", v),
            },
            _ => return err("a long", v),
        },
        G::PrimBool(_) | G::BoxBool => match v {
            JValue::Bool(b) => JValue::Bool(*b),
            JValue::Str(s) => JValue::Bool(s.eq_ignore_ascii_case("true")),
            _ => return err("a boolean", v),
        },
        G::Float32 => match v {
            JValue::Int(i) => JValue::Float(*i as f32 as f64),
            JValue::Float(x) => JValue::Float(*x as f32 as f64),
            JValue::Str(s) => match s.trim().parse::<f32>() {
                Ok(x) => JValue::Float(x as f64),
                Err(_) => return err("a float", v),
            },
            _ => return err("a float", v),
        },
        G::Number => match v {
            JValue::Int(_) | JValue::Float(_) => v.clone(),
            JValue::Str(s) => match s.trim().parse::<f64>() {
                Ok(_) => JValue::Str(s.clone()),
                Err(_) => return err("a number", v),
            },
            _ => return err("a number", v),
        },
        G::Element => v.clone(),
        G::Any => any(v),
        G::Enum(names) => match v {
            JValue::Str(s) if names.contains(&s.as_str()) => JValue::Str(s.clone()),
            JValue::Object(_) | JValue::Array(_) => return err("an enum", v),
            // Gson's enum adapter answers null for a name it does not know.
            _ => JValue::Null,
        },
        G::Class(c) => match v {
            JValue::Object(m) => JValue::Object(read_class(c, m)?),
            _ => return err(c.name, v),
        },
        G::MapOf(inner) => match v {
            JValue::Object(m) => {
                let mut out = JMap::new();
                for (k, x) in m {
                    out.insert(k.clone(), read_value(*inner, x)?);
                }
                JValue::Object(out)
            }
            _ => return err("a map", v),
        },
        G::ListOf(inner) => match v {
            JValue::Array(a) => JValue::Array(a.iter().map(|x| read_value(*inner, x)).collect::<R<Vec<_>>>()?),
            _ => return err("a list", v),
        },
        G::SchemaType => schema_type(v)?,
        G::Additional => match v {
            JValue::Bool(b) => JValue::Bool(*b),
            JValue::Object(m) => {
                if let Some(b) = m.get("booleanValue") {
                    match b {
                        JValue::Bool(x) => JValue::Bool(*x),
                        JValue::Str(s) => JValue::Bool(s.eq_ignore_ascii_case("true")),
                        _ => return err("an AdditionalType", v),
                    }
                } else if let Some(JValue::Object(s)) = m.get("schemaValue") {
                    JValue::Object(read_class(&SCHEMA, s)?)
                } else {
                    JValue::Object(read_class(&SCHEMA, m)?)
                }
            }
            _ => return err("an AdditionalType", v),
        },
        G::ArrayItems => match v {
            JValue::Array(a) => JValue::Array(tuple(a)?),
            JValue::Object(m) => match (m.get("singleSchema"), m.get("tupleSchema")) {
                (Some(JValue::Object(s)), _) => JValue::Object(read_class(&SCHEMA, s)?),
                (None, Some(JValue::Array(a))) => JValue::Array(tuple(a)?),
                _ => JValue::Object(read_class(&SCHEMA, m)?),
            },
            _ => return err("an ArraySchemaType", v),
        },
    })
}

fn tuple(a: &[JValue]) -> R<Vec<JValue>> {
    a.iter()
        .map(|x| match x {
            JValue::Object(m) => Ok(JValue::Object(read_class(&SCHEMA, m)?)),
            JValue::Null => Ok(JValue::Null),
            other => err("a Schema", other),
        })
        .collect()
}

/// `ObjectTypeAdapter`: numbers become doubles.
fn any(v: &JValue) -> JValue {
    match v {
        JValue::Int(i) => JValue::Float(*i as f64),
        JValue::Array(a) => JValue::Array(a.iter().map(any).collect()),
        JValue::Object(m) => JValue::Object(m.iter().map(|(k, x)| (k.clone(), any(x))).collect()),
        other => other.clone(),
    }
}

/// `SchemaTypeAdapter.read`: a name (`NUMBER` meaning `DOUBLE`) or a list of them.
fn schema_type(v: &JValue) -> R<JValue> {
    let one = |s: &str| -> R<String> {
        let t = s.to_uppercase();
        let t = if t == "NUMBER" { "DOUBLE".to_string() } else { t };
        if SCHEMA_TYPES.contains(&t.as_str()) {
            Ok(t)
        } else {
            Err(GsonError(format!("No enum constant SchemaType.{t}")))
        }
    };
    match v {
        JValue::Str(s) => Ok(JValue::Str(one(s)?)),
        JValue::Array(a) => {
            let mut out: Vec<JValue> = Vec::new();
            for x in a {
                let s = as_string(x).ok_or_else(|| GsonError("a schema type that is not a string".into()))?;
                let t = JValue::Str(one(&s)?);
                if !out.contains(&t) {
                    out.push(t);
                }
            }
            Ok(JValue::Array(out))
        }
        other => err("a schema type", other),
    }
}

/// `Gson.fromJson(tree, Class)`: every field of the class, in Gson order, `Null` when unset.
pub fn read_class(c: &Class, m: &JMap) -> R<JMap> {
    let mut out = JMap::new();
    for fld in c.fields {
        let v = match m.get(fld.name) {
            Some(x) if x.is_null() && matches!(fld.kind, G::PrimInt(_) | G::PrimBool(_)) => default_of(fld),
            Some(x) => read_value(fld.kind, x)?,
            None => default_of(fld),
        };
        out.insert(fld.name.to_string(), v);
    }
    Ok(out)
}

fn default_of(fld: &Field) -> JValue {
    match (fld.kind, fld.init) {
        (G::PrimInt(d), _) => JValue::Int(d),
        (G::PrimBool(b), _) => JValue::Bool(b),
        (_, Some(Init::EmptyMap)) => JValue::Object(JMap::new()),
        (_, Some(Init::Str(s))) => JValue::Str(s.to_string()),
        _ => JValue::Null,
    }
}

/// `Float.toString(f)`.
pub fn java_float(x: f32) -> String {
    if x.is_nan() {
        return "NaN".into();
    }
    if x.is_infinite() {
        return if x > 0.0 { "Infinity".into() } else { "-Infinity".into() };
    }
    if x == 0.0 {
        return if x.is_sign_negative() { "-0.0".into() } else { "0.0".into() };
    }
    // Rust's shortest f32 digits, laid out by the shared Java rules for Double/Float.
    let shortest: f64 = format!("{x:?}").parse().unwrap_or(x as f64);
    java_double(shortest)
}

/// Gson writing an object of class `c` (nulls left out).
pub fn write_gson(c: &Class, m: &JMap, out: &mut String) {
    out.push('{');
    let mut first = true;
    for fld in c.fields {
        let v = m.get(fld.name).unwrap_or(&JValue::Null);
        if v.is_null() {
            continue;
        }
        if !first {
            out.push(',');
        }
        first = false;
        gson_str(fld.name, out);
        out.push(':');
        write_gson_value(fld.kind, v, out);
    }
    out.push('}');
}

fn gson_str(s: &str, out: &mut String) {
    let quoted = overridable::json::to_gson(&JValue::Str(s.to_string()));
    out.push_str(&quoted);
}

pub fn write_gson_value(kind: G, v: &JValue, out: &mut String) {
    match (kind, v) {
        (_, JValue::Null) => out.push_str("null"),
        (G::Float32, JValue::Float(x)) => out.push_str(&java_float(*x as f32)),
        (G::Class(c), JValue::Object(m)) => write_gson(c, m, out),
        (G::MapOf(inner), JValue::Object(m)) => {
            out.push('{');
            let mut first = true;
            for (k, x) in m {
                if x.is_null() {
                    continue;
                }
                if !first {
                    out.push(',');
                }
                first = false;
                gson_str(k, out);
                out.push(':');
                write_gson_value(*inner, x, out);
            }
            out.push('}');
        }
        (G::ListOf(inner), JValue::Array(a)) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_gson_value(*inner, x, out);
            }
            out.push(']');
        }
        (G::Additional | G::ArrayItems, JValue::Object(m)) => write_gson(&SCHEMA, m, out),
        (G::ArrayItems, JValue::Array(a)) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_gson_value(G::Class(&SCHEMA), x, out);
            }
            out.push(']');
        }
        (G::Number, JValue::Str(s)) => out.push_str(s),
        (_, other) => out.push_str(&overridable::json::to_gson(other)),
    }
}

/// Jackson writing a KIRun `Schema` (`NON_EMPTY`), as `SchemaController` answers. A
/// `JsonElement` (`enums`, `defaultValue`, `examples`, `constant`) cannot be written by
/// Jackson at all; Java fails the request then, and so does this.
pub fn schema_to_jackson(m: &JMap) -> R<JValue> {
    let mut out = JMap::new();
    for fld in SCHEMA.fields {
        let v = m.get(fld.name).unwrap_or(&JValue::Null);
        let present_in_source = !v.is_null();
        if matches!(fld.kind, G::Element) && present_in_source {
            return Err(GsonError(format!("Jackson cannot serialize the JsonElement in {}", fld.name)));
        }
        if let G::ListOf(G::Element) = fld.kind {
            if let JValue::Array(a) = v {
                if !a.is_empty() {
                    return Err(GsonError(format!("Jackson cannot serialize the JsonElements in {}", fld.name)));
                }
            }
        }
        if !matches!(fld.kind, G::PrimInt(_) | G::PrimBool(_)) && v.is_jackson_empty() {
            continue;
        }
        out.insert(fld.name.to_string(), jackson_value(fld.kind, v)?);
    }
    let ns = m.get("namespace").and_then(JValue::as_str);
    let name = m.get("name").and_then(JValue::as_str);
    let title = match ns {
        None | Some("_") => name.map(str::to_string),
        Some(n) => Some(format!("{n}.{}", name.unwrap_or("null"))),
    };
    if let Some(t) = title.filter(|t| !t.is_empty()) {
        out.insert("title".into(), JValue::Str(t));
    }
    out.insert(
        "fullName".into(),
        JValue::Str(format!("{}.{}", ns.unwrap_or("null"), name.unwrap_or("null"))),
    );
    Ok(JValue::Object(out))
}

fn jackson_value(kind: G, v: &JValue) -> R<JValue> {
    Ok(match (kind, v) {
        (G::Class(c), JValue::Object(m)) if std::ptr::eq(c, &SCHEMA) => schema_to_jackson(m)?,
        (G::Class(c), JValue::Object(m)) => {
            let mut out = JMap::new();
            for fld in c.fields {
                let x = m.get(fld.name).unwrap_or(&JValue::Null);
                if !matches!(fld.kind, G::PrimInt(_) | G::PrimBool(_)) && x.is_jackson_empty() {
                    continue;
                }
                out.insert(fld.name.to_string(), jackson_value(fld.kind, x)?);
            }
            JValue::Object(out)
        }
        (G::MapOf(inner), JValue::Object(m)) => {
            let mut out = JMap::new();
            for (k, x) in m {
                out.insert(k.clone(), jackson_value(*inner, x)?);
            }
            JValue::Object(out)
        }
        (G::ListOf(inner), JValue::Array(a)) => {
            JValue::Array(a.iter().map(|x| jackson_value(*inner, x)).collect::<R<Vec<_>>>()?)
        }
        // AdditionalType and ArraySchemaType have no Jackson serializer: written as beans.
        (G::Additional, JValue::Bool(b)) => JValue::Object([("booleanValue".to_string(), JValue::Bool(*b))].into_iter().collect()),
        (G::Additional, JValue::Object(m)) => {
            JValue::Object([("schemaValue".to_string(), schema_to_jackson(m)?)].into_iter().collect())
        }
        (G::ArrayItems, JValue::Object(m)) => JValue::Object(
            [("singleSchema".to_string(), schema_to_jackson(m)?), ("singleType".to_string(), JValue::Bool(true))]
                .into_iter()
                .collect(),
        ),
        (G::ArrayItems, JValue::Array(a)) => {
            let schemas = a
                .iter()
                .map(|x| match x {
                    JValue::Object(m) => schema_to_jackson(m),
                    other => Ok(other.clone()),
                })
                .collect::<R<Vec<_>>>()?;
            JValue::Object(
                [("tupleSchema".to_string(), JValue::Array(schemas)), ("singleType".to_string(), JValue::Bool(false))]
                    .into_iter()
                    .collect(),
            )
        }
        (G::Number, JValue::Str(s)) => s.parse::<i64>().map(JValue::Int).unwrap_or_else(|_| {
            s.parse::<f64>().map(JValue::Float).unwrap_or(JValue::Str(s.clone()))
        }),
        (G::Float32, JValue::Float(x)) => JValue::Float(*x),
        (_, other) => other.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use overridable::json::parse;

    fn obj(s: &str) -> JMap {
        match parse(s.as_bytes()).unwrap() {
            JValue::Object(m) => m,
            _ => panic!(),
        }
    }

    #[test]
    fn function_definition_round_trip_matches_the_java_output() {
        // TestUI.testNumber as stored (one step), and what the Java ui answered for it.
        let stored = obj(
            r#"{"name":"testNumber","namespace":"TestUI","steps":{"if":{"statementName":"if","namespace":"System","name":"If",
            "position":{"left":148.0,"top":135.0},"parameterMap":{"condition":{"3jzK":{"key":"3jzK","type":"EXPRESSION","expression":"(Arguments.a % 2) = 1","order":1}}}}},
            "parameters":{"a":{"parameterName":"a","schema":{"type":["INTEGER"]}}},
            "events":{"output":{"name":"output","parameters":{"returnValue":{"type":["INTEGER"]}}}},"junk":1}"#,
        );
        let fd = read_class(&FUNCTION_DEFINITION, &stored).unwrap();
        let mut out = String::new();
        write_gson(&FUNCTION_DEFINITION, &fd, &mut out);
        let expected = concat!(
            r#"{"version":1,"steps":{"if":{"statementName":"if","namespace":"System","name":"If","parameterMap":{"condition":{"3jzK":{"key":"3jzK","type":"EXPRESSION","expression":"(Arguments.a % 2) "#,
            "\\u003d",
            r#" 1","order":1}}},"position":{"left":148.0,"top":135.0},"override":false}},"namespace":"TestUI","name":"testNumber","parameters":{"a":{"schema":{"namespace":"_","version":1,"type":["INTEGER"]},"parameterName":"a","variableArgument":false,"type":"EXPRESSION"}},"events":{"output":{"name":"output","parameters":{"returnValue":{"namespace":"_","version":1,"type":["INTEGER"]}}}}}"#
        );
        assert_eq!(out, expected);
    }

    #[test]
    fn floats_print_like_java() {
        assert_eq!(java_float(507.0), "507.0");
        assert_eq!(java_float(55.5), "55.5");
        assert_eq!(java_float(123.456), "123.456");
        assert_eq!(java_float(0.1), "0.1");
        assert_eq!(java_float(1.0e7), "1.0E7");
    }

    #[test]
    fn schema_as_jackson_writes_it() {
        let stored = obj(r#"{"name":"UserRecord","namespace":"TestUI","type":["OBJECT"],"properties":{"phone":{"type":"STRING"}}}"#);
        let s = read_class(&SCHEMA, &stored).unwrap();
        let j = schema_to_jackson(&s).unwrap();
        assert_eq!(
            overridable::json::to_compact(&j),
            r#"{"namespace":"TestUI","name":"UserRecord","version":1,"type":["OBJECT"],"properties":{"phone":{"namespace":"_","version":1,"type":"STRING","fullName":"_.null"}},"title":"TestUI.UserRecord","fullName":"TestUI.UserRecord"}"#
        );
        let with_enum = obj(r#"{"name":"T","namespace":"S","enums":["A"]}"#);
        assert!(schema_to_jackson(&read_class(&SCHEMA, &with_enum).unwrap()).is_err());
    }

    fn read(kind: G, json: &[u8]) -> R<JValue> {
        read_value(kind, &parse(json).unwrap())
    }

    #[test]
    fn gson_reads_scalars_like_java() {
        assert_eq!(read(G::Str, b"1.5").unwrap(), JValue::Str("1.5".into()));
        assert_eq!(read(G::Str, b"true").unwrap(), JValue::Str("true".into()));
        assert!(read(G::Str, b"{}").is_err());
        assert_eq!(read(G::BoxInt, b"2.9").unwrap(), JValue::Int(2));
        assert_eq!(read(G::BoxInt, br#""7""#).unwrap(), JValue::Int(7));
        assert!(read(G::BoxInt, br#""x""#).is_err());
        assert!(read(G::BoxInt, b"true").is_err());
        assert_eq!(read(G::BoxLong, b"3000000000").unwrap(), JValue::Int(3_000_000_000));
        assert_eq!(read(G::BoxLong, b"2.5").unwrap(), JValue::Int(2));
        assert_eq!(read(G::BoxLong, br#""9""#).unwrap(), JValue::Int(9));
        assert!(read(G::BoxLong, br#""x""#).is_err());
        assert!(read(G::BoxLong, b"[]").is_err());
        assert_eq!(read(G::BoxBool, br#""TRUE""#).unwrap(), JValue::Bool(true));
        assert!(read(G::BoxBool, b"1").is_err());
        assert_eq!(read(G::Float32, b"3").unwrap(), JValue::Float(3.0));
        assert_eq!(read(G::Float32, br#""1.5""#).unwrap(), JValue::Float(1.5));
        assert!(read(G::Float32, br#""x""#).is_err());
        assert!(read(G::Float32, b"{}").is_err());
        assert_eq!(read(G::Number, br#""5.50""#).unwrap(), JValue::Str("5.50".into()));
        assert!(read(G::Number, br#""x""#).is_err());
        assert!(read(G::Number, b"true").is_err());
        assert_eq!(read(G::Any, br#"{"a":[1]}"#).unwrap(), parse(br#"{"a":[1.0]}"#).unwrap());
        assert_eq!(read(G::Enum(PARAMETER_TYPE), br#""CONSTANT""#).unwrap(), JValue::Str("CONSTANT".into()));
        assert_eq!(read(G::Enum(PARAMETER_TYPE), br#""constant""#).unwrap(), JValue::Null);
        assert_eq!(read(G::Enum(PARAMETER_TYPE), b"1").unwrap(), JValue::Null);
        assert!(read(G::Enum(PARAMETER_TYPE), b"{}").is_err());
        assert!(read(G::Class(&POSITION), b"1").is_err());
        assert!(read(G::MapOf(&STR), b"1").is_err());
        assert!(read(G::MapOf(&STR), br#"{"a":{}}"#).is_err());
        assert!(read(G::ListOf(&STR), b"1").is_err());
        assert!(read(G::ListOf(&STR), b"[{}]").is_err());
        assert_eq!(read(G::Str, b"null").unwrap(), JValue::Null);
    }

    #[test]
    fn schema_types_and_adapters() {
        assert_eq!(read(G::SchemaType, br#""number""#).unwrap(), JValue::Str("DOUBLE".into()));
        assert_eq!(read(G::SchemaType, br#"["STRING","string","NULL"]"#).unwrap(), parse(br#"["STRING","NULL"]"#).unwrap());
        assert!(read(G::SchemaType, br#""nope""#).is_err());
        assert!(read(G::SchemaType, b"[{}]").is_err());
        assert!(read(G::SchemaType, b"1").is_err());
        assert_eq!(read(G::Additional, b"true").unwrap(), JValue::Bool(true));
        assert_eq!(read(G::Additional, br#"{"booleanValue":false}"#).unwrap(), JValue::Bool(false));
        assert_eq!(read(G::Additional, br#"{"booleanValue":"true"}"#).unwrap(), JValue::Bool(true));
        assert!(read(G::Additional, br#"{"booleanValue":1}"#).is_err());
        assert!(read(G::Additional, br#"{"schemaValue":{"type":"STRING"}}"#).unwrap().as_object().is_some());
        assert!(read(G::Additional, br#"{"type":"STRING"}"#).unwrap().as_object().is_some());
        assert!(read(G::Additional, b"1").is_err());
        assert!(read(G::ArrayItems, br#"[{"type":"STRING"},null]"#).unwrap().as_object().is_none());
        assert!(read(G::ArrayItems, b"[1]").is_err());
        assert!(read(G::ArrayItems, br#"{"singleSchema":{"type":"STRING"}}"#).unwrap().as_object().is_some());
        assert!(matches!(read(G::ArrayItems, br#"{"tupleSchema":[{"type":"STRING"}]}"#).unwrap(), JValue::Array(_)));
        assert!(read(G::ArrayItems, br#"{"type":"STRING"}"#).unwrap().as_object().is_some());
        assert!(read(G::ArrayItems, b"true").is_err());
        let s = read_class(&SCHEMA, &obj(r#"{"version":null,"name":"n"}"#)).unwrap();
        assert_eq!(s["version"], JValue::Int(1), "a null primitive keeps its initial value");
        assert_eq!(s["namespace"], JValue::Str("_".into()));
    }

    #[test]
    fn gson_writes_every_shape() {
        let schema = obj(
            r#"{"name":"S","type":"OBJECT","additionalProperties":{"type":"STRING"},"items":[{"type":"STRING"}],
            "minimum":"5.0","maximum":3,"enums":["A",null],"properties":{"a":null,"b":{"type":"STRING"}},
            "required":["a"],"details":{"order":1}}"#,
        );
        let s = read_class(&SCHEMA, &schema).unwrap();
        let mut out = String::new();
        write_gson(&SCHEMA, &s, &mut out);
        assert!(out.contains(r#""additionalProperties":{"namespace":"_","version":1,"type":"STRING"}"#), "{out}");
        assert!(out.contains(r#""items":[{"namespace":"_","version":1,"type":"STRING"}]"#), "{out}");
        assert!(out.contains(r#""minimum":5.0"#), "{out}");
        assert!(out.contains(r#""enums":["A",null]"#), "{out}");
        assert!(out.contains(r#""properties":{"b":"#), "a null map value is left out: {out}");
        let single = read_class(&SCHEMA, &obj(r#"{"items":{"type":"STRING"},"additionalProperties":false}"#)).unwrap();
        let mut out = String::new();
        write_gson(&SCHEMA, &single, &mut out);
        assert!(out.contains(r#""items":{"namespace":"_","version":1,"type":"STRING"}"#), "{out}");
        assert!(out.contains(r#""additionalProperties":false"#), "{out}");
        let mut n = String::new();
        write_gson_value(G::Str, &JValue::Null, &mut n);
        assert_eq!(n, "null");
    }

    #[test]
    fn jackson_writes_schema_shapes() {
        let s = read_class(
            &SCHEMA,
            &obj(r#"{"name":"S","namespace":"N","additionalProperties":true,"additionalItems":{"type":"STRING"},
            "items":[{"type":"STRING"},null],"minimum":"7","maximum":"2.5","details":{"label":"L","order":2},
            "anyOf":[{"type":"STRING"}],"multipleOf":3,"uniqueItems":true}"#),
        )
        .unwrap();
        let j = schema_to_jackson(&s).unwrap();
        let m = j.as_object().unwrap();
        assert_eq!(m["additionalProperties"], parse(br#"{"booleanValue":true}"#).unwrap());
        assert!(m["additionalItems"].as_object().unwrap().contains_key("schemaValue"));
        assert_eq!(m["items"].as_object().unwrap()["singleType"], JValue::Bool(false));
        assert_eq!(m["minimum"], JValue::Int(7));
        assert_eq!(m["maximum"], JValue::Float(2.5));
        assert_eq!(m["details"], parse(br#"{"order":2,"label":"L"}"#).unwrap());
        assert_eq!(m["title"], JValue::Str("N.S".into()));
        let single = read_class(&SCHEMA, &obj(r#"{"items":{"type":"STRING"},"name":"x"}"#)).unwrap();
        let j = schema_to_jackson(&single).unwrap();
        assert_eq!(j.as_object().unwrap()["items"].as_object().unwrap()["singleType"], JValue::Bool(true));
        assert_eq!(j.as_object().unwrap()["title"], JValue::Str("x".into()));
        let nameless = schema_to_jackson(&read_class(&SCHEMA, &JMap::new()).unwrap()).unwrap();
        assert!(!nameless.as_object().unwrap().contains_key("title"));
        assert_eq!(nameless.as_object().unwrap()["fullName"], JValue::Str("_.null".into()));
        let with_default = read_class(&SCHEMA, &obj(r#"{"defaultValue":1}"#)).unwrap();
        assert!(schema_to_jackson(&with_default).is_err());
        let s = read_class(&SCHEMA, &obj(r#"{"exclusiveMaximum":"abc"}"#));
        assert!(s.is_err());
        assert!(format!("{:?}", GsonError("x".into())).contains('x'));
        assert_eq!(java_float(f32::NAN), "NaN");
        assert_eq!(java_float(f32::INFINITY), "Infinity");
        assert_eq!(java_float(f32::NEG_INFINITY), "-Infinity");
        assert_eq!(java_float(0.0), "0.0");
        assert_eq!(java_float(-0.0), "-0.0");
        assert_eq!(java_float(-2.5), "-2.5");
    }

}
