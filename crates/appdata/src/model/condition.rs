//! The platform's filter vocabulary, `com.fincity.saas.commons.model.condition`.
//!
//! Read the way `AbstractConditionDeserializer` reads it, which decides the condition's
//! class from which keys the JSON has rather than from a type tag: `havingConditions`
//! makes a group, an `operator` of AND or OR a complex condition, an `aggregateFunction`
//! a having condition, and a `field` (or a `fieldExpr`) a filter condition. Anything else
//! that is not empty is refused with "Invalid condition".

use std::fmt;

use serde::{Deserialize, Deserializer};

use crate::value::{Document, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FilterOperator {
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

impl FilterOperator {
    pub const ALL: [FilterOperator; 15] = [
        FilterOperator::Equals,
        FilterOperator::LessThan,
        FilterOperator::GreaterThan,
        FilterOperator::LessThanEqual,
        FilterOperator::GreaterThanEqual,
        FilterOperator::IsTrue,
        FilterOperator::IsFalse,
        FilterOperator::IsNull,
        FilterOperator::Between,
        FilterOperator::In,
        FilterOperator::Like,
        FilterOperator::StringLooseEqual,
        FilterOperator::Match,
        FilterOperator::MatchAll,
        FilterOperator::TextSearch,
    ];

    pub fn name(&self) -> &'static str {
        match self {
            FilterOperator::Equals => "EQUALS",
            FilterOperator::LessThan => "LESS_THAN",
            FilterOperator::GreaterThan => "GREATER_THAN",
            FilterOperator::LessThanEqual => "LESS_THAN_EQUAL",
            FilterOperator::GreaterThanEqual => "GREATER_THAN_EQUAL",
            FilterOperator::IsTrue => "IS_TRUE",
            FilterOperator::IsFalse => "IS_FALSE",
            FilterOperator::IsNull => "IS_NULL",
            FilterOperator::Between => "BETWEEN",
            FilterOperator::In => "IN",
            FilterOperator::Like => "LIKE",
            FilterOperator::StringLooseEqual => "STRING_LOOSE_EQUAL",
            FilterOperator::Match => "MATCH",
            FilterOperator::MatchAll => "MATCH_ALL",
            FilterOperator::TextSearch => "TEXT_SEARCH",
        }
    }

    pub fn from_name(s: &str) -> Option<FilterOperator> {
        FilterOperator::ALL.into_iter().find(|o| o.name() == s)
    }
}

impl fmt::Display for FilterOperator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComplexOperator {
    And,
    Or,
}

impl ComplexOperator {
    pub fn from_name(s: &str) -> Option<ComplexOperator> {
        match s {
            "AND" => Some(ComplexOperator::And),
            "OR" => Some(ComplexOperator::Or),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AggregateFunction {
    Max,
    Min,
    Sum,
    Avg,
    Count,
    CountDistinct,
}

impl AggregateFunction {
    pub fn name(&self) -> &'static str {
        match self {
            AggregateFunction::Max => "MAX",
            AggregateFunction::Min => "MIN",
            AggregateFunction::Sum => "SUM",
            AggregateFunction::Avg => "AVG",
            AggregateFunction::Count => "COUNT",
            AggregateFunction::CountDistinct => "COUNT_DISTINCT",
        }
    }

    pub fn from_name(s: &str) -> Option<AggregateFunction> {
        [
            AggregateFunction::Max,
            AggregateFunction::Min,
            AggregateFunction::Sum,
            AggregateFunction::Avg,
            AggregateFunction::Count,
            AggregateFunction::CountDistinct,
        ]
        .into_iter()
        .find(|f| f.name() == s)
    }
}

impl fmt::Display for AggregateFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct FieldExpression {
    pub function: Option<String>,
    pub fields: Option<Vec<String>>,
    pub separator: Option<String>,
}

impl FieldExpression {
    pub fn is_valid(&self) -> bool {
        let (Some(f), Some(fields)) = (&self.function, &self.fields) else { return false };
        if fields.is_empty() {
            return false;
        }
        match f.as_str() {
            "UPPER" | "LOWER" | "TRIM" => fields.len() == 1,
            "CONCAT" | "COALESCE" => fields.len() >= 2,
            _ => false,
        }
    }
}

/// `FilterCondition`. `None` stands for a Java null throughout: a JSON null and an absent
/// key are the same thing to the bean.
#[derive(Debug, Clone, PartialEq)]
pub struct FilterCondition {
    pub negate: bool,
    pub field: Option<String>,
    pub field_expr: Option<FieldExpression>,
    /// EQUALS unless the JSON says otherwise; an explicit null stays null.
    pub operator: Option<FilterOperator>,
    pub value: Option<Value>,
    pub to_value: Option<Value>,
    pub multi_value: Option<Vec<Value>>,
    pub value_field: bool,
    pub to_value_field: bool,
    pub match_operator: Option<FilterOperator>,
}

impl Default for FilterCondition {
    fn default() -> Self {
        FilterCondition {
            negate: false,
            field: None,
            field_expr: None,
            operator: Some(FilterOperator::Equals),
            value: None,
            to_value: None,
            multi_value: None,
            value_field: false,
            to_value_field: false,
            match_operator: Some(FilterOperator::Equals),
        }
    }
}

impl FilterCondition {
    pub fn new(field: &str, operator: FilterOperator, value: impl Into<Option<Value>>) -> Self {
        FilterCondition {
            field: Some(field.to_string()),
            operator: Some(operator),
            value: value.into(),
            ..Default::default()
        }
    }

    pub fn eq(field: &str, value: impl Into<Value>) -> Self {
        Self::new(field, FilterOperator::Equals, Some(value.into()))
    }

    pub fn negated(mut self) -> Self {
        self.negate = true;
        self
    }

    pub fn with_to_value(mut self, v: impl Into<Value>) -> Self {
        self.to_value = Some(v.into());
        self
    }

    pub fn with_multi_value(mut self, v: Vec<Value>) -> Self {
        self.multi_value = Some(v);
        self
    }

    pub fn with_match_operator(mut self, op: FilterOperator) -> Self {
        self.match_operator = Some(op);
        self
    }

    pub fn with_value_field(mut self) -> Self {
        self.value_field = true;
        self
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ComplexCondition {
    pub negate: bool,
    pub operator: Option<ComplexOperator>,
    /// An element is `None` where the JSON held an empty object, which the deserializer
    /// turns into null.
    pub conditions: Option<Vec<Option<Condition>>>,
    pub group_condition: Option<GroupCondition>,
}

impl ComplexCondition {
    pub fn and(conditions: Vec<Condition>) -> Self {
        ComplexCondition {
            negate: false,
            operator: Some(ComplexOperator::And),
            conditions: Some(conditions.into_iter().map(Some).collect()),
            group_condition: None,
        }
    }

    pub fn or(conditions: Vec<Condition>) -> Self {
        ComplexCondition {
            negate: false,
            operator: Some(ComplexOperator::Or),
            conditions: Some(conditions.into_iter().map(Some).collect()),
            group_condition: None,
        }
    }

    pub fn negated(mut self) -> Self {
        self.negate = true;
        self
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct HavingCondition {
    pub negate: bool,
    pub aggregate_function: Option<AggregateFunction>,
    pub condition: Option<FilterCondition>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GroupCondition {
    pub negate: bool,
    pub operator: Option<ComplexOperator>,
    pub fields: Vec<String>,
    pub having_conditions: Vec<HavingCondition>,
}

/// `AbstractCondition`.
#[derive(Debug, Clone, PartialEq)]
pub enum Condition {
    Filter(FilterCondition),
    Complex(ComplexCondition),
    Having(HavingCondition),
    Group(GroupCondition),
}

impl From<FilterCondition> for Condition {
    fn from(f: FilterCondition) -> Self {
        Condition::Filter(f)
    }
}

impl From<ComplexCondition> for Condition {
    fn from(c: ComplexCondition) -> Self {
        Condition::Complex(c)
    }
}

impl Condition {
    pub fn negate(&self) -> bool {
        match self {
            Condition::Filter(f) => f.negate,
            Condition::Complex(c) => c.negate,
            Condition::Having(h) => h.negate,
            Condition::Group(g) => g.negate,
        }
    }

    /// The Java class's simple name, which is what the refusals quote.
    pub fn class_name(&self) -> &'static str {
        match self {
            Condition::Filter(_) => "FilterCondition",
            Condition::Complex(_) => "ComplexCondition",
            Condition::Having(_) => "HavingCondition",
            Condition::Group(_) => "GroupCondition",
        }
    }

    /// Whether `AbstractConditionDeserializer` refuses `v` itself ("Invalid condition"), not a
    /// condition nested in it: Java lets that refusal through as its own `GenericException`
    /// (400), where Jackson wraps one raised deeper.
    pub fn refused_at_top(v: &Value) -> bool {
        let obj = match v {
            Value::Null => return false,
            Value::Object(o) => o,
            _ => return true,
        };
        if obj.is_empty() || matches!(obj.get("havingConditions"), Some(Value::Array(_))) {
            return false;
        }
        if let Some(Value::String(op)) = obj.get("operator") {
            if ComplexOperator::from_name(op).is_some() {
                return false;
            }
        }
        let has_field_expr = match obj.get("fieldExpr") {
            Some(Value::Object(o)) => !o.is_empty(),
            Some(Value::Array(a)) => !a.is_empty(),
            _ => false,
        };
        !(matches!(obj.get("aggregateFunction"), Some(Value::String(_))) || matches!(obj.get("field"), Some(Value::String(_))) || has_field_expr)
    }

    /// `AbstractConditionDeserializer.deserialize`. `Ok(None)` for an empty object.
    pub fn from_value(v: &Value) -> Result<Option<Condition>, String> {
        let obj = match v {
            Value::Null => return Ok(None),
            Value::Object(o) => o,
            _ => return Err("Invalid condition".into()),
        };
        if obj.is_empty() {
            return Ok(None);
        }

        if let Some(Value::Array(_)) = obj.get("havingConditions") {
            return group_from(obj).map(|g| Some(Condition::Group(g)));
        }

        if let Some(Value::String(op)) = obj.get("operator") {
            if ComplexOperator::from_name(op).is_some() {
                return complex_from(obj).map(|c| Some(Condition::Complex(c)));
            }
        }

        if let Some(Value::String(_)) = obj.get("aggregateFunction") {
            return having_from(obj).map(|h| Some(Condition::Having(h)));
        }

        let has_field = matches!(obj.get("field"), Some(Value::String(_)));
        let has_field_expr = match obj.get("fieldExpr") {
            Some(Value::Object(o)) => !o.is_empty(),
            Some(Value::Array(a)) => !a.is_empty(),
            _ => false,
        };

        if !has_field && !has_field_expr {
            return Err("Invalid condition".into());
        }

        filter_from(obj).map(|f| Some(Condition::Filter(f)))
    }
}

impl<'de> Deserialize<'de> for Condition {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Condition, D::Error> {
        let v = Value::deserialize(d)?;
        match Condition::from_value(&v).map_err(serde::de::Error::custom)? {
            Some(c) => Ok(c),
            None => Err(serde::de::Error::custom("empty condition")),
        }
    }
}

/// An optional condition field, where `{}` and `null` both mean "none".
pub fn condition_opt(v: Option<&Value>) -> Result<Option<Condition>, String> {
    match v {
        None => Ok(None),
        Some(v) => Condition::from_value(v),
    }
}

fn bool_of(v: Option<&Value>) -> Result<bool, String> {
    match v {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(Value::String(s)) if s == "true" => Ok(true),
        Some(Value::String(s)) if s == "false" || s.is_empty() => Ok(false),
        Some(Value::Int(i)) => Ok(*i != 0),
        Some(other) => Err(format!("cannot read {} as a boolean", other.to_java_json())),
    }
}

fn string_of(v: Option<&Value>) -> Result<Option<String>, String> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(Value::Int(i)) => Ok(Some(i.to_string())),
        Some(Value::Double(_)) | Some(Value::Decimal(_)) | Some(Value::Bool(_)) => {
            Ok(Some(v.map(Value::java_string).unwrap_or_default()))
        }
        Some(other) => Err(format!("cannot read {} as a string", other.to_java_json())),
    }
}

fn operator_of(v: Option<&Value>, default: FilterOperator) -> Result<Option<FilterOperator>, String> {
    match v {
        None => Ok(Some(default)),
        Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.is_empty() => Ok(None),
        Some(Value::String(s)) => FilterOperator::from_name(s)
            .map(Some)
            .ok_or_else(|| format!("'{s}' is not one of the FilterConditionOperator values")),
        Some(other) => Err(format!("cannot read {} as an operator", other.to_java_json())),
    }
}

/// A Java value: JSON null and absent are both null.
fn object_of(v: Option<&Value>) -> Option<Value> {
    match v {
        None | Some(Value::Null) => None,
        Some(v) => Some(v.clone()),
    }
}

pub(crate) fn filter_from(obj: &Document) -> Result<FilterCondition, String> {
    let multi_value = match obj.get("multiValue") {
        None | Some(Value::Null) => None,
        Some(Value::Array(a)) => Some(a.clone()),
        Some(other) => return Err(format!("multiValue must be a list, not {}", other.to_java_json())),
    };

    let field_expr = match obj.get("fieldExpr") {
        Some(Value::Object(o)) => Some(FieldExpression {
            function: string_of(o.get("function"))?,
            fields: match o.get("fields") {
                Some(Value::Array(a)) => Some(a.iter().map(Value::java_string).collect()),
                _ => None,
            },
            separator: string_of(o.get("separator"))?,
        }),
        _ => None,
    };

    Ok(FilterCondition {
        negate: bool_of(obj.get("negate"))?,
        field: string_of(obj.get("field"))?,
        field_expr,
        operator: operator_of(obj.get("operator"), FilterOperator::Equals)?,
        value: object_of(obj.get("value")),
        to_value: object_of(obj.get("toValue")),
        multi_value,
        // Jackson names the Lombok `isValueField` property `valueField`; the Gson path the
        // KIRun functions take reads the field name. Both reach the engines.
        value_field: bool_of(obj.get("valueField").or(obj.get("isValueField")))?,
        to_value_field: bool_of(obj.get("toValueField").or(obj.get("isToValueField")))?,
        match_operator: operator_of(obj.get("matchOperator"), FilterOperator::Equals)?,
    })
}

fn complex_from(obj: &Document) -> Result<ComplexCondition, String> {
    let operator = match obj.get("operator") {
        Some(Value::String(s)) => ComplexOperator::from_name(s),
        _ => None,
    };
    let conditions = match obj.get("conditions") {
        None | Some(Value::Null) => None,
        Some(Value::Array(a)) => {
            let mut out = Vec::with_capacity(a.len());
            for c in a {
                out.push(Condition::from_value(c)?);
            }
            Some(out)
        }
        Some(other) => return Err(format!("conditions must be a list, not {}", other.to_java_json())),
    };
    let group_condition = match obj.get("groupCondition") {
        Some(Value::Object(o)) if !o.is_empty() => Some(group_from(o)?),
        _ => None,
    };
    Ok(ComplexCondition { negate: bool_of(obj.get("negate"))?, operator, conditions, group_condition })
}

fn having_from(obj: &Document) -> Result<HavingCondition, String> {
    let aggregate_function = match obj.get("aggregateFunction") {
        None => Some(AggregateFunction::Max),
        Some(Value::Null) => None,
        Some(Value::String(s)) => Some(
            AggregateFunction::from_name(s)
                .ok_or_else(|| format!("'{s}' is not one of the AggregateFunction values"))?,
        ),
        Some(other) => return Err(format!("cannot read {} as a function", other.to_java_json())),
    };
    let condition = match obj.get("condition") {
        Some(Value::Object(o)) => Some(filter_from(o)?),
        _ => None,
    };
    Ok(HavingCondition { negate: bool_of(obj.get("negate"))?, aggregate_function, condition })
}

fn group_from(obj: &Document) -> Result<GroupCondition, String> {
    let fields = match obj.get("fields") {
        Some(Value::Array(a)) => a.iter().map(Value::java_string).collect(),
        _ => Vec::new(),
    };
    let mut having_conditions = Vec::new();
    if let Some(Value::Array(a)) = obj.get("havingConditions") {
        for h in a {
            if let Value::Object(o) = h {
                having_conditions.push(having_from(o)?);
            }
        }
    }
    let operator = match obj.get("operator") {
        Some(Value::String(s)) => ComplexOperator::from_name(s),
        None => Some(ComplexOperator::And),
        _ => None,
    };
    Ok(GroupCondition { negate: bool_of(obj.get("negate"))?, operator, fields, having_conditions })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<Option<Condition>, String> {
        Condition::from_value(&Value::parse_json(s).unwrap())
    }

    #[test]
    fn picks_the_class_from_the_keys() {
        assert!(matches!(parse(r#"{"field":"a","value":1}"#), Ok(Some(Condition::Filter(_)))));
        assert!(matches!(parse(r#"{"operator":"AND","conditions":[]}"#), Ok(Some(Condition::Complex(_)))));
        assert!(matches!(
            parse(r#"{"aggregateFunction":"SUM","condition":{"field":"a"}}"#),
            Ok(Some(Condition::Having(_)))
        ));
        assert!(matches!(parse(r#"{"havingConditions":[]}"#), Ok(Some(Condition::Group(_)))));
        assert!(matches!(parse("{}"), Ok(None)));
        assert_eq!(parse(r#"{"value":1}"#), Err("Invalid condition".into()));
        let v = |s: &str| Value::from_json(&serde_json::from_str(s).unwrap());
        assert!(Condition::refused_at_top(&v(r#"{"value":1}"#)));
        assert!(Condition::refused_at_top(&v("5")));
        for ok in [r#"{}"#, "null", r#"{"field":"a"}"#, r#"{"operator":"OR","conditions":[{"value":1}]}"#, r#"{"havingConditions":[]}"#,
            r#"{"aggregateFunction":"SUM"}"#, r#"{"fieldExpr":{"a":1}}"#] {
            assert!(!Condition::refused_at_top(&v(ok)), "{ok}");
        }
    }

    #[test]
    fn a_filter_operator_that_is_not_complex_is_a_filter() {
        let c = parse(r#"{"field":"a","operator":"IN","value":"x,y"}"#).unwrap().unwrap();
        let Condition::Filter(f) = c else { panic!() };
        assert_eq!(f.operator, Some(FilterOperator::In));
        assert_eq!(f.match_operator, Some(FilterOperator::Equals));
    }

    #[test]
    fn empty_objects_inside_a_group_are_nulls() {
        let c = parse(r#"{"operator":"OR","conditions":[{},{"field":"a"}]}"#).unwrap().unwrap();
        let Condition::Complex(cc) = c else { panic!() };
        let list = cc.conditions.unwrap();
        assert!(list[0].is_none());
        assert!(list[1].is_some());
    }
}
