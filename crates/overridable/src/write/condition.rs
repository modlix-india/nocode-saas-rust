//! commons' `AbstractCondition` (`FilterCondition`, `ComplexCondition`), read from JSON as
//! `AbstractConditionDeserializer` reads it, and turned into the Mongo query document
//! `AbstractMongoDataService.filter` builds through Spring's `Criteria`.
//!
//! The documents are Spring's, quirks included: `IS_NULL` and `BETWEEN` reuse one `Criteria`
//! for both halves of an `$or`, so they produce the condition twice over (and a negated
//! `BETWEEN` asks for `< from` and `> to` at once, which matches nothing); `LIKE` and
//! `STRING_LOOSE_EQUAL` are both an unanchored regular expression.

use axum::http::StatusCode;
use mongodb::bson::{doc, Bson, Document, Regex};
use platform::error::AppError;

use crate::bson_conv::from_j;
use crate::json::{JMap, JValue};
use crate::write::messages as msg;
use crate::write::spring::{Order, Sort};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operator {
    Equals,
    LessThan,
    GreaterThan,
    LessThanEqual,
    GreaterThanEqual,
    IsTrue,
    IsFalse,
    IsNull,
    Between,
    In,
    Like,
    StringLooseEqual,
    Match,
    MatchAll,
    TextSearch,
}

impl Operator {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "EQUALS" => Self::Equals,
            "LESS_THAN" => Self::LessThan,
            "GREATER_THAN" => Self::GreaterThan,
            "LESS_THAN_EQUAL" => Self::LessThanEqual,
            "GREATER_THAN_EQUAL" => Self::GreaterThanEqual,
            "IS_TRUE" => Self::IsTrue,
            "IS_FALSE" => Self::IsFalse,
            "IS_NULL" => Self::IsNull,
            "BETWEEN" => Self::Between,
            "IN" => Self::In,
            "LIKE" => Self::Like,
            "STRING_LOOSE_EQUAL" => Self::StringLooseEqual,
            "MATCH" => Self::Match,
            "MATCH_ALL" => Self::MatchAll,
            "TEXT_SEARCH" => Self::TextSearch,
            _ => return None,
        })
    }
}

/// `FieldExpression`: a computed value compared through `$expr`.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldExpression {
    /// `CONCAT`, `UPPER`, `LOWER`, `TRIM` or `COALESCE`.
    pub function: String,
    pub fields: Vec<String>,
    pub separator: Option<String>,
}

impl FieldExpression {
    pub fn is_valid(&self) -> bool {
        if self.fields.is_empty() {
            return false;
        }
        match self.function.as_str() {
            "UPPER" | "LOWER" | "TRIM" => self.fields.len() == 1,
            "CONCAT" | "COALESCE" => self.fields.len() >= 2,
            _ => false,
        }
    }

    fn to_mongo(&self) -> Bson {
        let f = |i: usize| Bson::String(format!("${}", self.fields[i]));
        match self.function.as_str() {
            "CONCAT" => {
                let mut args = Vec::new();
                for i in 0..self.fields.len() {
                    if let Some(sep) = self.separator.as_deref().filter(|s| i > 0 && !s.is_empty()) {
                        args.push(Bson::String(sep.to_string()));
                    }
                    args.push(f(i));
                }
                Bson::Document(doc! {"$concat": args})
            }
            "UPPER" => Bson::Document(doc! {"$toUpper": f(0)}),
            "LOWER" => Bson::Document(doc! {"$toLower": f(0)}),
            "TRIM" => Bson::Document(doc! {"$trim": {"input": f(0)}}),
            _ => nested_if_null(&(0..self.fields.len()).map(f).collect::<Vec<_>>()),
        }
    }
}

fn nested_if_null(args: &[Bson]) -> Bson {
    match args {
        [one] => one.clone(),
        [a, b] => Bson::Document(doc! {"$ifNull": [a.clone(), b.clone()]}),
        [first, rest @ ..] => Bson::Document(doc! {"$ifNull": [first.clone(), nested_if_null(rest)]}),
        [] => Bson::Null,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct FilterCondition {
    pub field: Option<String>,
    pub field_expr: Option<FieldExpression>,
    pub operator: Operator,
    pub value: Option<JValue>,
    pub to_value: Option<JValue>,
    pub multi_value: Option<Vec<JValue>>,
    pub negate: bool,
}

impl FilterCondition {
    pub fn new(field: &str, operator: Operator, value: JValue) -> Self {
        Self { field: Some(field.to_string()), field_expr: None, operator, value: Some(value), to_value: None, multi_value: None, negate: false }
    }

    pub fn multi(field: &str, values: Vec<JValue>) -> Self {
        Self { multi_value: Some(values), value: None, ..Self::new(field, Operator::In, JValue::Null) }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Condition {
    Filter(FilterCondition),
    Complex { and: bool, conditions: Vec<Option<Condition>>, negate: bool },
    /// `GroupCondition` / `HavingCondition`: SQL-only, refused by the Mongo services.
    Unsupported(&'static str),
}

impl Condition {
    pub fn and(conditions: Vec<Condition>) -> Self {
        Condition::Complex { and: true, conditions: conditions.into_iter().map(Some).collect(), negate: false }
    }

    /// `AbstractConditionDeserializer`.
    pub fn from_json(v: &JValue) -> Result<Option<Condition>, AppError> {
        let m = match v {
            JValue::Object(m) if !m.is_empty() => m,
            _ => return Ok(None),
        };
        if matches!(m.get("havingConditions"), Some(JValue::Array(_))) {
            return Ok(Some(Condition::Unsupported("GroupCondition")));
        }
        if let Some(JValue::Str(op)) = m.get("operator") {
            if op == "AND" || op == "OR" {
                let conditions = match m.get("conditions") {
                    Some(JValue::Array(a)) => a.iter().map(Condition::from_json).collect::<Result<_, _>>()?,
                    _ => Vec::new(),
                };
                return Ok(Some(Condition::Complex { and: op == "AND", conditions, negate: bool_of(m, "negate") }));
            }
        }
        if matches!(m.get("aggregateFunction"), Some(JValue::Str(_))) {
            return Ok(Some(Condition::Unsupported("HavingCondition")));
        }
        let field = m.get("field").and_then(JValue::as_str).filter(|s| !s.trim().is_empty());
        let field_expr = m.get("fieldExpr").and_then(JValue::as_object).filter(|o| !o.is_empty());
        if field.is_none() && field_expr.is_none() {
            return Err(msg::literal("DEF.CONDITION_INVALID", StatusCode::BAD_REQUEST, "Invalid condition").into());
        }
        let operator = match m.get("operator") {
            None | Some(JValue::Null) => Operator::Equals,
            Some(JValue::Str(s)) => Operator::parse(s).ok_or_else(|| unknown_operator(Some(s)))?,
            Some(_) => return Err(unknown_operator(None)),
        };
        let field_expr = field_expr.map(|o| FieldExpression {
            function: o.get("function").and_then(JValue::as_str).unwrap_or_default().to_string(),
            fields: match o.get("fields") {
                Some(JValue::Array(a)) => a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect(),
                _ => Vec::new(),
            },
            separator: o.get("separator").and_then(JValue::as_str).map(str::to_string),
        });
        let present = |k: &str| m.get(k).filter(|x| !x.is_null()).cloned();
        Ok(Some(Condition::Filter(FilterCondition {
            field: field.map(str::to_string),
            field_expr,
            operator,
            value: present("value"),
            to_value: present("toValue"),
            multi_value: match m.get("multiValue") {
                Some(JValue::Array(a)) => Some(a.clone()),
                _ => None,
            },
            negate: bool_of(m, "negate"),
        })))
    }

    /// `AbstractMongoDataService.filter`: the query document (`{}` matches everything).
    pub fn to_mongo(c: Option<&Condition>) -> Result<Document, AppError> {
        Ok(match c {
            None => Document::new(),
            Some(Condition::Filter(fc)) => filter_to_mongo(fc).unwrap_or_default(),
            Some(Condition::Complex { and, conditions, negate }) => {
                if conditions.is_empty() {
                    return Ok(Document::new());
                }
                let docs: Vec<Bson> = conditions
                    .iter()
                    .map(|c| Condition::to_mongo(c.as_ref()).map(Bson::Document))
                    .collect::<Result<_, _>>()?;
                let key = if *and != *negate { "$and" } else { "$or" };
                doc! {key: docs}
            }
            Some(Condition::Unsupported(kind)) => {
                return Err(AppError::Internal(anyhow::anyhow!("{kind} cannot be used to filter a Mongo collection")))
            }
        })
    }
}

fn bool_of(m: &JMap, k: &str) -> bool {
    matches!(m.get(k), Some(JValue::Bool(true)))
}

/// Java's "Unknown operator ..." for a filter operator it does not have.
fn unknown_operator(op: Option<&str>) -> AppError {
    let text = op.map(|o| format!("Unknown operator {o}")).unwrap_or_else(|| "Unknown operator".to_string());
    let c = msg::literal("DEF.CONDITION_OPERATOR_UNKNOWN", StatusCode::BAD_REQUEST, text);
    match op {
        Some(o) => c.param("operator", o).into(),
        None => c.into(),
    }
}

/// A sort the request cannot be ordered by; the reader's text (Java's) in `debugMessage`.
fn bad_sort(text: &str) -> AppError {
    msg::literal("DEF.SORT_INVALID", StatusCode::BAD_REQUEST, text).into()
}

/// `Criteria.getSingleCriteriaObject` for one field: the `is` value alone, or the operators
/// with the `is` value folded in as `$eq` (or `$regex` for a pattern).
fn single(field: &str, mut criteria: Document, is_value: Option<Bson>) -> Document {
    match is_value {
        Some(v) if criteria.is_empty() => doc! {field: v},
        Some(v) => {
            let key = if matches!(v, Bson::RegularExpression(_)) { "$regex" } else { "$eq" };
            criteria.insert(key, v);
            doc! {field: criteria}
        }
        None => doc! {field: criteria},
    }
}

/// A criteria that names itself twice inside its own `$or`/`$and`, as `crit.orOperator(crit, crit)`
/// renders once the chain is merged.
fn self_chained(field: &str, criteria: Document, is_value: Option<Bson>, op: &str) -> Document {
    let one = single(field, criteria, is_value);
    let mut out = one.clone();
    out.insert(op, vec![Bson::Document(one.clone()), Bson::Document(one)]);
    out
}

fn regex(pattern: String, options: &str) -> Bson {
    Bson::RegularExpression(Regex { pattern, options: options.to_string() })
}

/// `filterConditionFilter`: `None` where Java's is an empty Mono (the condition is dropped).
fn filter_to_mongo(fc: &FilterCondition) -> Option<Document> {
    if let Some(expr) = fc.field_expr.as_ref().filter(|e| e.is_valid()) {
        return expr_to_mongo(&expr.to_mongo(), fc);
    }
    let field = fc.field.as_deref()?;
    let neg = fc.negate;
    let value = fc.value.as_ref().map(from_j);
    match fc.operator {
        Operator::IsTrue | Operator::IsFalse => return Some(doc! {field: !neg}),
        Operator::IsNull => {
            return Some(if neg {
                doc! {field: {"$ne": Bson::Null}}
            } else {
                self_chained(field, doc! {"$exists": false}, Some(Bson::Null), "$or")
            })
        }
        Operator::In => {
            let list = multi_field_value(fc.value.as_ref(), fc.multi_value.as_deref())?;
            return Some(doc! {field: {if neg { "$nin" } else { "$in" }: list}});
        }
        _ => {}
    }
    let value = value?;
    if fc.operator == Operator::Between {
        let to = fc.to_value.as_ref().map(from_j).unwrap_or(Bson::Null);
        return Some(if neg {
            self_chained(field, doc! {"$lt": value, "$gt": to}, None, "$and")
        } else {
            self_chained(field, doc! {"$gte": value, "$lte": to}, None, "$or")
        });
    }
    let text = fc.value.as_ref().map(JValue::java_to_string).unwrap_or_default();
    let op = |pos: &str, negated: &str| doc! {field: {if neg { negated } else { pos }: value.clone()}};
    Some(match fc.operator {
        Operator::Equals if neg => doc! {field: {"$ne": value.clone()}},
        Operator::Equals => doc! {field: value.clone()},
        Operator::GreaterThan => op("$gt", "$lte"),
        Operator::GreaterThanEqual => op("$gte", "$lt"),
        Operator::LessThan => op("$lt", "$gte"),
        Operator::LessThanEqual => op("$lte", "$gt"),
        Operator::Like | Operator::StringLooseEqual if neg => doc! {field: {"$not": regex(text, "")}},
        Operator::Like | Operator::StringLooseEqual => doc! {field: regex(text, "")},
        _ => return None,
    })
}

/// `buildMongoExprCondition`.
fn expr_to_mongo(computed: &Bson, fc: &FilterCondition) -> Option<Document> {
    let neg = fc.negate;
    let expr = |d: Document| doc! {"$expr": d};
    let eq = |v: Bson| expr(doc! {if neg { "$ne" } else { "$eq" }: [computed.clone(), v]});
    match fc.operator {
        Operator::IsNull => return Some(eq(Bson::Null)),
        Operator::IsTrue => return Some(eq(Bson::Boolean(true))),
        Operator::IsFalse => return Some(eq(Bson::Boolean(false))),
        Operator::In => {
            let list = multi_field_value(fc.value.as_ref(), fc.multi_value.as_deref())?;
            let d = doc! {"$in": [computed.clone(), list]};
            return Some(expr(if neg { doc! {"$not": d} } else { d }));
        }
        _ => {}
    }
    let value = from_j(fc.value.as_ref()?);
    if fc.operator == Operator::Between {
        if let Some(to) = fc.to_value.as_ref() {
            let d = doc! {"$and": [{"$gte": [computed.clone(), value]}, {"$lte": [computed.clone(), from_j(to)]}]};
            return Some(expr(if neg { doc! {"$not": d} } else { d }));
        }
    }
    if matches!(fc.operator, Operator::Like | Operator::StringLooseEqual) {
        let pattern = fc.value.as_ref().map(JValue::java_to_string).unwrap_or_default();
        let d = doc! {"$regexMatch": {"input": computed.clone(), "regex": pattern, "options": "i"}};
        return Some(expr(if neg { doc! {"$not": d} } else { d }));
    }
    let op = match fc.operator {
        Operator::Equals => if neg { "$ne" } else { "$eq" },
        Operator::GreaterThan => if neg { "$lte" } else { "$gt" },
        Operator::GreaterThanEqual => if neg { "$lt" } else { "$gte" },
        Operator::LessThan => if neg { "$gte" } else { "$lt" },
        Operator::LessThanEqual => if neg { "$gt" } else { "$lte" },
        _ => return None,
    };
    Some(expr(doc! {op: [computed.clone(), value]}))
}

/// `multiFieldValue`: the multi-value list, or the value split at commas not preceded by a
/// backslash. Java keeps the backslash, and an empty piece neither counts nor moves the start,
/// so it is folded into the next one; both kept. `None` (no list at all) drops the condition.
pub fn multi_field_value(value: Option<&JValue>, values: Option<&[JValue]>) -> Option<Vec<Bson>> {
    if let Some(vs) = values.filter(|v| !v.is_empty()) {
        return Some(vs.iter().map(from_j).collect());
    }
    let v = value?;
    let s = v.java_to_string();
    let s = s.trim();
    let chars: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut from = 0;
    for i in 0..chars.len() {
        if chars[i] != ',' || (i != 0 && chars[i - 1] == '\\') {
            continue;
        }
        let piece: String = chars[from..i].iter().collect::<String>().trim().to_string();
        if piece.is_empty() {
            continue;
        }
        out.push(Bson::String(piece));
        from = i + 1;
    }
    let rest: String = chars[from..].iter().collect();
    if !rest.trim().is_empty() {
        out.push(Bson::String(rest));
    }
    Some(out)
}

/// commons `Query`: the body of the version history route.
#[derive(Debug, Clone, PartialEq)]
pub struct Query {
    pub condition: Option<Condition>,
    pub size: i64,
    pub page: i64,
    pub sort: Sort,
    pub fields: Option<Vec<String>>,
    pub exclude_fields: bool,
}

impl Query {
    /// `Query.DEFAULT_SORT`.
    pub fn default_sort() -> Sort {
        Sort::by(vec![Order::desc("updatedAt")])
    }

    pub fn from_json(v: &JValue) -> Result<Self, AppError> {
        let m = v.as_object().cloned().unwrap_or_default();
        let int = |k: &str, d: i64| match m.get(k) {
            Some(JValue::Int(i)) => *i as i32 as i64,
            Some(JValue::Float(f)) => *f as i32 as i64,
            _ => d,
        };
        let sort = match m.get("sort") {
            None => Self::default_sort(),
            Some(s) => Sort::from_json(s).map_err(|e| bad_sort(&e))?.unwrap_or_else(Self::default_sort),
        };
        Ok(Self {
            condition: match m.get("condition") {
                Some(c) => Condition::from_json(c)?,
                None => None,
            },
            size: int("size", 10),
            page: int("page", 0),
            sort,
            fields: match m.get("fields") {
                Some(JValue::Array(a)) => Some(a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()),
                _ => None,
            },
            exclude_fields: matches!(m.get("excludeFields"), Some(JValue::Bool(true))),
        })
    }

    /// `AbstractCondition.isEmpty` of the condition (a filter is never empty, a complex one is
    /// when it has no conditions).
    pub fn condition_is_empty(&self) -> bool {
        match &self.condition {
            None => true,
            Some(Condition::Complex { conditions, .. }) => conditions.is_empty(),
            Some(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::parse;

    fn cond(s: &str) -> Option<Condition> {
        Condition::from_json(&parse(s.as_bytes()).unwrap()).unwrap()
    }

    fn mongo(s: &str) -> Document {
        Condition::to_mongo(cond(s).as_ref()).unwrap()
    }

    #[test]
    fn deserializer_picks_the_class() {
        assert_eq!(cond("{}"), None);
        assert_eq!(cond("null"), None);
        assert!(matches!(cond(r#"{"havingConditions":[]}"#), Some(Condition::Unsupported("GroupCondition"))));
        assert!(matches!(cond(r#"{"aggregateFunction":"SUM"}"#), Some(Condition::Unsupported("HavingCondition"))));
        assert!(matches!(cond(r#"{"operator":"OR","conditions":[{"field":"a","value":1}]}"#), Some(Condition::Complex { and: false, .. })));
        assert!(matches!(cond(r#"{"field":"a","operator":"IN","multiValue":[1]}"#), Some(Condition::Filter(_))));
        let code = |s: &[u8]| match Condition::from_json(&parse(s).unwrap()).unwrap_err() {
            AppError::Coded(c) => (c.code.to_string(), c.params.clone(), crate::write::messages::error_message(&AppError::Coded(c))),
            other => panic!("{other:?}"),
        };
        assert_eq!(code(br#"{"value":1}"#), ("DEF.CONDITION_INVALID".into(), vec![], "Invalid condition".into()));
        assert_eq!(
            code(br#"{"field":"a","operator":"NOPE"}"#),
            ("DEF.CONDITION_OPERATOR_UNKNOWN".into(), vec![("operator".into(), "NOPE".into())], "Unknown operator NOPE".into())
        );
        assert_eq!(code(br#"{"field":"a","operator":1}"#), ("DEF.CONDITION_OPERATOR_UNKNOWN".into(), vec![], "Unknown operator".into()));
        let sort = Query::from_json(&parse(br#"{"sort":[{"property":"a","direction":"UP"}]}"#).unwrap()).unwrap_err();
        assert!(matches!(&sort, AppError::Coded(c) if c.code == "DEF.SORT_INVALID"), "{sort:?}");
        assert_eq!(sort.status(), StatusCode::BAD_REQUEST);
        assert!(Condition::to_mongo(cond(r#"{"havingConditions":[]}"#).as_ref()).is_err());
        for op in ["LESS_THAN", "GREATER_THAN", "LESS_THAN_EQUAL", "GREATER_THAN_EQUAL", "IS_TRUE", "IS_FALSE", "IS_NULL", "BETWEEN", "LIKE", "STRING_LOOSE_EQUAL", "MATCH", "MATCH_ALL", "TEXT_SEARCH", "EQUALS", "IN"] {
            assert!(Operator::parse(op).is_some());
        }
    }

    #[test]
    fn criteria_as_spring_renders_them() {
        assert_eq!(mongo(r#"{"field":"a","value":"x"}"#), doc! {"a": "x"});
        assert_eq!(mongo(r#"{"field":"a","value":"x","negate":true}"#), doc! {"a": {"$ne": "x"}});
        assert_eq!(mongo(r#"{"field":"a","operator":"IS_TRUE"}"#), doc! {"a": true});
        assert_eq!(mongo(r#"{"field":"a","operator":"IS_FALSE","negate":true}"#), doc! {"a": false});
        assert_eq!(mongo(r#"{"field":"a","operator":"IS_NULL","negate":true}"#), doc! {"a": {"$ne": null}});
        let one = doc! {"a": {"$exists": false, "$eq": null}};
        let mut is_null = one.clone();
        is_null.insert("$or", vec![Bson::Document(one.clone()), Bson::Document(one)]);
        assert_eq!(mongo(r#"{"field":"a","operator":"IS_NULL"}"#), is_null);
        assert_eq!(mongo(r#"{"field":"a","operator":"IN","value":"x,y\\,z, ,w"}"#), doc! {"a": {"$in": ["x", "y\\,z", " ,w"]}});
        assert_eq!(mongo(r#"{"field":"a","operator":"IN","multiValue":[1,2],"negate":true}"#), doc! {"a": {"$nin": [1, 2]}});
        assert_eq!(mongo(r#"{"field":"a","operator":"IN"}"#), doc! {}, "no values drops the condition");
        assert_eq!(mongo(r#"{"field":"a","operator":"GREATER_THAN"}"#), doc! {}, "no value drops the condition");
        let b = doc! {"a": {"$gte": 1, "$lte": 5}};
        let mut between = b.clone();
        between.insert("$or", vec![Bson::Document(b.clone()), Bson::Document(b)]);
        assert_eq!(mongo(r#"{"field":"a","operator":"BETWEEN","value":1,"toValue":5}"#), between);
        let nb = doc! {"a": {"$lt": 1, "$gt": 5}};
        let mut not_between = nb.clone();
        not_between.insert("$and", vec![Bson::Document(nb.clone()), Bson::Document(nb)]);
        assert_eq!(mongo(r#"{"field":"a","operator":"BETWEEN","value":1,"toValue":5,"negate":true}"#), not_between);
        for (op, pos, neg) in [("GREATER_THAN", "$gt", "$lte"), ("GREATER_THAN_EQUAL", "$gte", "$lt"), ("LESS_THAN", "$lt", "$gte"), ("LESS_THAN_EQUAL", "$lte", "$gt")] {
            assert_eq!(mongo(&format!(r#"{{"field":"a","operator":"{op}","value":3}}"#)), doc! {"a": {pos: 3}});
            assert_eq!(mongo(&format!(r#"{{"field":"a","operator":"{op}","value":3,"negate":true}}"#)), doc! {"a": {neg: 3}});
        }
        assert_eq!(mongo(r#"{"field":"a","operator":"LIKE","value":"x"}"#), doc! {"a": regex("x".into(), "")});
        assert_eq!(mongo(r#"{"field":"a","operator":"STRING_LOOSE_EQUAL","value":1,"negate":true}"#), doc! {"a": {"$not": regex("1".into(), "")}});
        assert_eq!(mongo(r#"{"field":"a","operator":"MATCH","value":1}"#), doc! {});
        assert_eq!(single("f", doc! {"$gt": 1}, Some(regex("p".into(), ""))), doc! {"f": {"$gt": 1, "$regex": regex("p".into(), "")}});
    }

    #[test]
    fn complex_conditions() {
        assert_eq!(
            mongo(r#"{"operator":"AND","conditions":[{"field":"a","value":1},{"field":"b","operator":"MATCH","value":1},null]}"#),
            doc! {"$and": [{"a": 1}, {}, {}]}
        );
        assert_eq!(mongo(r#"{"operator":"OR","conditions":[{"field":"a","value":1}],"negate":true}"#), doc! {"$and": [{"a": 1}]});
        assert_eq!(mongo(r#"{"operator":"AND","conditions":[{"field":"a","value":1}],"negate":true}"#), doc! {"$or": [{"a": 1}]});
        assert_eq!(mongo(r#"{"operator":"AND"}"#), doc! {});
        assert_eq!(Condition::to_mongo(None).unwrap(), doc! {});
        let and = Condition::and(vec![Condition::Filter(FilterCondition::new("x", Operator::Equals, JValue::Int(1)))]);
        assert_eq!(Condition::to_mongo(Some(&and)).unwrap(), doc! {"$and": [{"x": 1}]});
        let m = FilterCondition::multi("y", vec![JValue::Str("a".into())]);
        assert_eq!(Condition::to_mongo(Some(&Condition::Filter(m))).unwrap(), doc! {"y": {"$in": ["a"]}});
    }

    #[test]
    fn field_expressions() {
        let base = r#""fieldExpr":{"function":"CONCAT","fields":["a","b"],"separator":" "}"#;
        let concat = Bson::Document(doc! {"$concat": ["$a", " ", "$b"]});
        assert_eq!(mongo(&format!(r#"{{{base},"value":"x y"}}"#)), doc! {"$expr": {"$eq": [concat.clone(), "x y"]}});
        assert_eq!(mongo(&format!(r#"{{{base},"value":"x","negate":true}}"#)), doc! {"$expr": {"$ne": [concat.clone(), "x"]}});
        assert_eq!(mongo(&format!(r#"{{{base},"operator":"IS_NULL"}}"#)), doc! {"$expr": {"$eq": [concat.clone(), null]}});
        assert_eq!(mongo(&format!(r#"{{{base},"operator":"IS_TRUE"}}"#)), doc! {"$expr": {"$eq": [concat.clone(), true]}});
        assert_eq!(mongo(&format!(r#"{{{base},"operator":"IS_FALSE","negate":true}}"#)), doc! {"$expr": {"$ne": [concat.clone(), false]}});
        assert_eq!(mongo(&format!(r#"{{{base},"operator":"IN","value":"p,q"}}"#)), doc! {"$expr": {"$in": [concat.clone(), ["p", "q"]]}});
        assert_eq!(mongo(&format!(r#"{{{base},"operator":"IN","value":"p","negate":true}}"#)), doc! {"$expr": {"$not": {"$in": [concat.clone(), ["p"]]}}});
        assert_eq!(mongo(&format!(r#"{{{base},"operator":"IN"}}"#)), doc! {});
        assert_eq!(mongo(&format!(r#"{{{base},"operator":"GREATER_THAN"}}"#)), doc! {});
        let between = doc! {"$and": [{"$gte": [concat.clone(), 1]}, {"$lte": [concat.clone(), 2]}]};
        assert_eq!(mongo(&format!(r#"{{{base},"operator":"BETWEEN","value":1,"toValue":2}}"#)), doc! {"$expr": between.clone()});
        assert_eq!(mongo(&format!(r#"{{{base},"operator":"BETWEEN","value":1,"toValue":2,"negate":true}}"#)), doc! {"$expr": {"$not": between}});
        assert_eq!(mongo(&format!(r#"{{{base},"operator":"BETWEEN","value":1}}"#)), doc! {}, "between without an end is no operator");
        let rm = doc! {"$regexMatch": {"input": concat.clone(), "regex": "x", "options": "i"}};
        assert_eq!(mongo(&format!(r#"{{{base},"operator":"LIKE","value":"x"}}"#)), doc! {"$expr": rm.clone()});
        assert_eq!(mongo(&format!(r#"{{{base},"operator":"STRING_LOOSE_EQUAL","value":"x","negate":true}}"#)), doc! {"$expr": {"$not": rm}});
        for (op, pos, neg) in [("GREATER_THAN", "$gt", "$lte"), ("GREATER_THAN_EQUAL", "$gte", "$lt"), ("LESS_THAN", "$lt", "$gte"), ("LESS_THAN_EQUAL", "$lte", "$gt")] {
            assert_eq!(mongo(&format!(r#"{{{base},"operator":"{op}","value":3}}"#)), doc! {"$expr": {pos: [concat.clone(), 3]}});
            assert_eq!(mongo(&format!(r#"{{{base},"operator":"{op}","value":3,"negate":true}}"#)), doc! {"$expr": {neg: [concat.clone(), 3]}});
        }
        let up = r#"{"fieldExpr":{"function":"UPPER","fields":["a"]},"value":"X"}"#;
        assert_eq!(mongo(up), doc! {"$expr": {"$eq": [{"$toUpper": "$a"}, "X"]}});
        let low = r#"{"fieldExpr":{"function":"LOWER","fields":["a"]},"value":"x"}"#;
        assert_eq!(mongo(low), doc! {"$expr": {"$eq": [{"$toLower": "$a"}, "x"]}});
        let trim = r#"{"fieldExpr":{"function":"TRIM","fields":["a"]},"value":"x"}"#;
        assert_eq!(mongo(trim), doc! {"$expr": {"$eq": [{"$trim": {"input": "$a"}}, "x"]}});
        let co = r#"{"fieldExpr":{"function":"COALESCE","fields":["a","b","c"]},"value":"x"}"#;
        assert_eq!(mongo(co), doc! {"$expr": {"$eq": [{"$ifNull": ["$a", {"$ifNull": ["$b", "$c"]}]}, "x"]}});
        let co2 = r#"{"fieldExpr":{"function":"COALESCE","fields":["a","b"]},"value":"x"}"#;
        assert_eq!(mongo(co2), doc! {"$expr": {"$eq": [{"$ifNull": ["$a", "$b"]}, "x"]}});
        assert_eq!(mongo(r#"{"fieldExpr":{"function":"UPPER","fields":["a","b"]},"field":"z","value":1}"#), doc! {"z": 1}, "an invalid expression falls back to the field");
        assert!(!FieldExpression { function: "X".into(), fields: vec!["a".into()], separator: None }.is_valid());
        assert!(!FieldExpression { function: "UPPER".into(), fields: vec![], separator: None }.is_valid());
        assert_eq!(nested_if_null(&[]), Bson::Null);
        assert_eq!(expr_to_mongo(&Bson::Null, &FilterCondition::new("a", Operator::Match, JValue::Int(1))), None);
    }

    #[test]
    fn splitting_like_multi_field_value() {
        let split = |s: &str| multi_field_value(Some(&JValue::Str(s.into())), None).unwrap();
        assert_eq!(split("a,b"), vec![Bson::String("a".into()), Bson::String("b".into())]);
        assert_eq!(split(",a"), vec![Bson::String(",a".into())], "an empty first piece is folded into the next");
        assert_eq!(split("a,"), vec![Bson::String("a".into())]);
        assert_eq!(split(""), Vec::<Bson>::new());
        assert_eq!(multi_field_value(None, Some(&[])), None);
        assert_eq!(multi_field_value(Some(&JValue::Int(5)), Some(&[])).unwrap(), vec![Bson::String("5".into())]);
    }

    #[test]
    fn queries() {
        let q = Query::from_json(&parse(br#"{"page":2,"size":5.0,"fields":["a"],"excludeFields":true,"condition":{"field":"x","value":1}}"#).unwrap()).unwrap();
        assert_eq!((q.page, q.size, q.exclude_fields), (2, 5, true));
        assert_eq!(q.sort, Query::default_sort());
        assert!(!q.condition_is_empty());
        let q = Query::from_json(&parse(br#"{"sort":{"property":"a"},"condition":{"operator":"AND","conditions":[]}}"#).unwrap()).unwrap();
        assert_eq!(q.sort, Sort::by(vec![Order::asc("a")]));
        assert!(q.condition_is_empty());
        let q = Query::from_json(&parse(br#"{"sort":null}"#).unwrap()).unwrap();
        assert_eq!((q.page, q.size), (0, 10));
        assert_eq!(q.sort, Query::default_sort());
        assert!(q.condition_is_empty());
        assert!(Query::from_json(&parse(br#"{"sort":{"direction":"X","property":"a"}}"#).unwrap()).is_err());
        assert!(Query::from_json(&JValue::Null).unwrap().fields.is_none());
    }
}
