//! `MySQLFilterBuilder`: the platform's condition vocabulary translated into SQL.
//!
//! Mirrors the Mongo backend operator for operator, negation included. An operator that
//! cannot be expressed is an error rather than a dropped clause, because a dropped clause
//! means "every row". The one clause dropped is a read's condition given no value at all
//! ([`build_for_read`]), because Mongo drops that one too.

use indexmap::IndexSet;

use super::field_resolver::FieldResolver;
use super::porter_stemmer;
use super::sql::{string_literal, Bind, Cond, FieldOps, Sql};
use crate::model::{ComplexCondition, ComplexOperator, Condition, FilterCondition, FilterOperator};
use crate::value::Value;

/// `UnsupportedFilterException`, split by what it means to the caller.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FilterError {
    /// The backend cannot express it (501).
    #[error("{0}")]
    Unsupported(String),
    /// The condition itself is wrong (400).
    #[error("{0}")]
    Malformed(String),
    /// A value the driver cannot bind, which Java lets escape as a 500.
    #[error("{0}")]
    Unbindable(String),
}

impl FilterError {
    pub fn detail(&self) -> &str {
        match self {
            FilterError::Unsupported(d) | FilterError::Malformed(d) | FilterError::Unbindable(d) => d,
        }
    }

    pub fn is_malformed(&self) -> bool {
        matches!(self, FilterError::Malformed(_))
    }
}

pub type FilterResult<T> = Result<T, FilterError>;

fn malformed<T>(detail: impl Into<String>) -> FilterResult<T> {
    Err(FilterError::Malformed(detail.into()))
}

/// The value a comparison binds. Lists and maps have no binding, as in Java, where the
/// statement then fails as a server error.
pub fn bind_of(v: &Value) -> FilterResult<Bind> {
    Ok(match v {
        Value::Null => Bind::Null,
        Value::Bool(b) => Bind::Bool(*b),
        Value::Int(i) => Bind::Int(*i),
        Value::Double(d) => Bind::Double(*d),
        Value::Decimal(d) => Bind::Decimal(d.clone()),
        Value::String(s) => Bind::Text(s.clone()),
        Value::LocalDateTime(_) | Value::LocalDate(_) | Value::LocalTime(_) | Value::Date(_) => {
            Bind::Text(v.java_string())
        }
        Value::Array(_) | Value::Object(_) => {
            return Err(FilterError::Unbindable(format!(
                "Cannot encode value of type '{}'",
                if matches!(v, Value::Array(_)) { "class java.util.ArrayList" } else { "class java.util.LinkedHashMap" }
            )))
        }
    })
}

fn param(v: &Value) -> FilterResult<Sql> {
    Ok(Sql::param(bind_of(v)?))
}

/// For a delete: a condition with no value is refused, because dropping it would remove
/// rows nobody named.
pub fn build(condition: Option<&Condition>, resolver: &FieldResolver) -> FilterResult<Cond> {
    build_with(condition, resolver, false)
}

/// For a read: a condition given no value drops out, as it does on Mongo.
pub fn build_for_read(condition: Option<&Condition>, resolver: &FieldResolver) -> FilterResult<Cond> {
    build_with(condition, resolver, true)
}

/// `build(condition, jsonColumns)`.
pub fn build_json(condition: Option<&Condition>, json_columns: IndexSet<String>) -> FilterResult<Cond> {
    build(condition, &FieldResolver::of(json_columns))
}

fn build_with(condition: Option<&Condition>, resolver: &FieldResolver, skip_empty: bool) -> FilterResult<Cond> {
    match condition {
        None => Ok(Cond::None),
        Some(Condition::Complex(cc)) => complex(cc, resolver, skip_empty),
        Some(Condition::Filter(fc)) => {
            if skip_empty && is_empty(fc) {
                Ok(Cond::None)
            } else {
                filter(fc, resolver)
            }
        }
        Some(other) => Err(FilterError::Unsupported(format!(
            "{} is not a condition this backend supports",
            other.class_name()
        ))),
    }
}

/// Exactly the conditions Mongo drops: no value to compare with.
pub fn is_empty(fc: &FilterCondition) -> bool {
    let Some(op) = fc.operator else { return false };
    let no_multi = fc.multi_value.as_ref().is_none_or(|m| m.is_empty());
    match op {
        FilterOperator::IsNull | FilterOperator::IsTrue | FilterOperator::IsFalse => false,
        FilterOperator::In | FilterOperator::MatchAll => fc.value.is_none() && no_multi,
        _ => fc.value.is_none(),
    }
}

/// Java's `String.split("\\.")`: trailing empty strings removed.
pub(crate) fn split_dots(s: &str) -> Vec<&str> {
    let mut parts: Vec<&str> = s.split('.').collect();
    while parts.len() > 1 && parts.last() == Some(&"") {
        parts.pop();
    }
    if parts.len() == 1 && parts[0].is_empty() && !s.is_empty() {
        parts.clear();
    }
    parts
}

fn path_segment_ok(seg: &str) -> bool {
    !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'$' | b'[' | b']'))
}

fn path_expr(whole: &str, path: &str) -> FilterResult<String> {
    let mut expr = String::from("$");
    for seg in split_dots(path) {
        if !path_segment_ok(seg) {
            return malformed(format!("'{whole}' is not a usable JSON path"));
        }
        expr.push('.');
        expr.push_str(seg);
    }
    Ok(expr)
}

/// A path into a JSON column, unquoted so it compares as text. The path is inlined, so it
/// is validated rather than trusted.
pub fn json_path(column: &Sql, whole: &str, path: &str) -> FilterResult<Sql> {
    let expr = path_expr(whole, path)?;
    Ok(Sql::template("json_unquote(json_extract({0}, {1}))", &[column.clone(), Sql::raw(string_literal(&expr))]))
}

/// De Morgan, as Mongo does it: a negated group negates each child and flips the
/// operator.
fn complex(cc: &ComplexCondition, resolver: &FieldResolver, skip_empty: bool) -> FilterResult<Cond> {
    let Some(conditions) = cc.conditions.as_ref().filter(|c| !c.is_empty()) else { return Ok(Cond::None) };

    let mut parts = Vec::new();
    for c in conditions {
        if skip_empty {
            if let Some(Condition::Filter(fc)) = c {
                if is_empty(fc) {
                    continue;
                }
            }
        }
        let built = build_with(c.as_ref(), resolver, skip_empty)?;
        parts.push(if cc.negate { built.not() } else { built });
    }

    if parts.is_empty() {
        return Ok(Cond::None);
    }

    let mut and = cc.operator == Some(ComplexOperator::And);
    if cc.negate {
        and = !and;
    }

    Ok(if and { Cond::and(parts) } else { Cond::or(parts) })
}

fn filter(fc: &FilterCondition, resolver: &FieldResolver) -> FilterResult<Cond> {
    let Some(op) = fc.operator else { return malformed("a filter condition has no operator") };

    match op {
        FilterOperator::TextSearch => return text_search(fc, resolver),
        FilterOperator::Match => return match_one(fc, resolver),
        FilterOperator::MatchAll => return match_all(fc, resolver),
        _ => {}
    }

    let Some(field) = fc.field.as_ref().filter(|f| !f.trim().is_empty()) else {
        return malformed("a filter condition has no field");
    };

    let column = resolver.resolve(field)?;
    let c = positive(fc, op, field, &column, resolver)?;
    Ok(if fc.negate { c.not() } else { c })
}

fn text_search(fc: &FilterCondition, resolver: &FieldResolver) -> FilterResult<Cond> {
    let columns = resolver.text_columns();
    if columns.is_empty() {
        return Err(FilterError::Unsupported(
            "TEXT_SEARCH needs the storage to declare textIndexFields, and this one declares none".into(),
        ));
    }

    let raw = match &fc.value {
        Some(v) if !v.java_string().trim().is_empty() => v.java_string(),
        _ => return Err(FilterError::Unsupported("TEXT_SEARCH was given nothing to search for".into())),
    };

    let cols: Vec<Sql> = columns.iter().map(|c| resolver.qualified(c)).collect();
    let mut sql = Sql::raw("MATCH(").then_sql(&Sql::join(&cols, ", "));

    if !resolver.stemming() {
        sql.push(") AGAINST (");
        sql.push_param(Bind::Text(raw));
        sql.push(" IN NATURAL LANGUAGE MODE)");
        let plain = Cond::Plain(sql);
        return Ok(if fc.negate { plain.not() } else { plain });
    }

    let prefixes = porter_stemmer::search_prefixes(&raw);
    if prefixes.is_empty() {
        return Ok(if fc.negate { Cond::True } else { Cond::False });
    }

    let against: Vec<String> = prefixes.iter().map(|p| format!("{p}*")).collect();
    sql.push(") AGAINST (");
    sql.push_param(Bind::Text(against.join(" ")));
    sql.push(" IN BOOLEAN MODE)");
    let c = Cond::Plain(sql);
    Ok(if fc.negate { c.not() } else { c })
}

fn require<'a>(v: Option<&'a Value>, message: &str) -> FilterResult<&'a Value> {
    match v {
        Some(v) => Ok(v),
        None => malformed(message),
    }
}

/// Mongo's `$elemMatch`: at least one element of the array satisfies the match operator.
fn match_one(fc: &FilterCondition, resolver: &FieldResolver) -> FilterResult<Cond> {
    let array = array_field(fc.field.as_deref(), resolver)?;
    let op = fc.match_operator.unwrap_or(FilterOperator::Equals);
    let value = require(fc.value.as_ref(), "MATCH needs a value")?;

    let c = match op {
        FilterOperator::Equals => json_contains(&array, &json_literal(value)),
        FilterOperator::Like => json_search(&array, &value.java_string()),
        FilterOperator::StringLooseEqual => json_search(&array, &format!("%{}%", value.java_string())),
        FilterOperator::GreaterThan
        | FilterOperator::GreaterThanEqual
        | FilterOperator::LessThan
        | FilterOperator::LessThanEqual => element_compare(&array, op, value)?,
        other => {
            return Err(FilterError::Unsupported(format!(
                "MATCH cannot use a match operator of {other} on this backend"
            )))
        }
    };

    Ok(if fc.negate { c.not() } else { c })
}

/// Mongo's `$all`: every supplied value is in the array, as one JSON_CONTAINS.
fn match_all(fc: &FilterCondition, resolver: &FieldResolver) -> FilterResult<Cond> {
    let array = array_field(fc.field.as_deref(), resolver)?;

    let values: Vec<Value> = match (&fc.multi_value, &fc.value) {
        (Some(m), _) if !m.is_empty() => m.clone(),
        (_, Some(v)) => vec![v.clone()],
        _ => Vec::new(),
    };
    if values.is_empty() {
        return malformed("MATCH_ALL needs either multiValue or a value");
    }

    let literals: Vec<String> = values.iter().map(json_literal).collect();
    let c = json_contains(&array, &format!("[{}]", literals.join(",")));
    Ok(if fc.negate { c.not() } else { c })
}

/// The array itself, as JSON: not unquoted, which would hand the JSON functions a string.
fn array_field(name: Option<&str>, resolver: &FieldResolver) -> FilterResult<Sql> {
    let Some(name) = name.filter(|n| !n.trim().is_empty()) else {
        return malformed("a filter condition has no field");
    };

    let Some(dot) = name.find('.').filter(|d| *d > 0 && *d != name.len() - 1) else {
        return resolver.resolve(name);
    };

    let head = &name[..dot];
    if !resolver.is_json_column(head) {
        return malformed(format!("'{name}' is not an array on this storage, so it cannot be matched inside"));
    }

    let expr = path_expr(name, &name[dot + 1..])?;
    Ok(Sql::template("json_extract({0}, {1})", &[resolver.resolve(head)?, Sql::raw(string_literal(&expr))]))
}

fn json_contains(array: &Sql, candidate: &str) -> Cond {
    Cond::Plain(Sql::template(
        "json_contains({0}, cast({1} as json))",
        &[array.clone(), Sql::param(Bind::Text(candidate.to_string()))],
    ))
}

fn json_search(array: &Sql, pattern: &str) -> Cond {
    Cond::Plain(Sql::template(
        "json_search({0}, 'one', {1}) is not null",
        &[array.clone(), Sql::param(Bind::Text(pattern.to_string()))],
    ))
}

fn element_compare(array: &Sql, op: FilterOperator, value: &Value) -> FilterResult<Cond> {
    let column_type = if value.is_number() { "decimal(38,10)" } else { "char(1024)" };
    let comparison = match op {
        FilterOperator::GreaterThan => ">",
        FilterOperator::GreaterThanEqual => ">=",
        FilterOperator::LessThan => "<",
        _ => "<=",
    };
    // Counted rather than EXISTS: on MySQL 8.4 an EXISTS over a JSON_TABLE of an outer
    // column silently matches nothing.
    let template = format!(
        "(select count(*) from json_table({{0}}, '$[*]' columns (v {column_type} path '$')) as jt where jt.v {comparison} {{1}}) > 0"
    );
    Ok(Cond::Plain(Sql::template(&template, &[array.clone(), param(value)?])))
}

/// A value as a JSON literal: numbers and booleans as they print, anything else quoted.
fn json_literal(value: &Value) -> String {
    match value {
        Value::Int(_) | Value::Double(_) | Value::Decimal(_) | Value::Bool(_) => value.java_string(),
        other => {
            let mut out = String::from("\"");
            for ch in other.java_string().chars() {
                match ch {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                    c => out.push(c),
                }
            }
            out.push('"');
            out
        }
    }
}

fn positive(
    fc: &FilterCondition,
    op: FilterOperator,
    field_name: &str,
    field: &Sql,
    resolver: &FieldResolver,
) -> FilterResult<Cond> {
    match op {
        FilterOperator::IsTrue => return Ok(field.is_true()),
        FilterOperator::IsFalse => return Ok(field.is_false()),
        FilterOperator::IsNull => return Ok(field.is_null()),
        FilterOperator::In => {
            let values = multi_value(fc, field_name)?;
            let mut binds = Vec::with_capacity(values.len());
            for v in &values {
                binds.push(param(v)?);
            }
            return Ok(field.in_list(binds));
        }
        FilterOperator::Between => {
            let low = require(fc.value.as_ref(), &format!("BETWEEN on '{field_name}' without a value"))?;
            let high = require(fc.to_value.as_ref(), &format!("BETWEEN on '{field_name}' without a toValue"))?;
            return Ok(field.between(param(low)?, param(high)?));
        }
        FilterOperator::Like => {
            let v = require(fc.value.as_ref(), "LIKE needs a value")?;
            return Ok(field.like(Sql::param(Bind::Text(v.java_string()))));
        }
        FilterOperator::StringLooseEqual => {
            let v = require(fc.value.as_ref(), "STRING_LOOSE_EQUAL needs a value")?;
            return Ok(field.like(Sql::param(Bind::Text(format!("%{}%", v.java_string())))));
        }
        _ => {}
    }

    let value = require(fc.value.as_ref(), &format!("{op} needs a value"))?;

    let right = if fc.value_field { resolver.resolve(&value.java_string())? } else { param(value)? };

    Ok(match op {
        FilterOperator::Equals => field.cmp("=", right),
        FilterOperator::GreaterThan => field.cmp(">", right),
        FilterOperator::GreaterThanEqual => field.cmp(">=", right),
        FilterOperator::LessThan => field.cmp("<", right),
        FilterOperator::LessThanEqual => field.cmp("<=", right),
        other => return Err(FilterError::Unsupported(format!("{other} is not supported on this backend"))),
    })
}

/// An explicit multiValue, or a comma separated single value.
fn multi_value(fc: &FilterCondition, field: &str) -> FilterResult<Vec<Value>> {
    if let Some(m) = fc.multi_value.as_ref().filter(|m| !m.is_empty()) {
        return Ok(m.clone());
    }
    let Some(v) = &fc.value else {
        return malformed(format!("IN on '{field}' needs either multiValue or a comma separated value"));
    };
    let parts: Vec<Value> = v
        .java_string()
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(|p| Value::String(p.to_string()))
        .collect();
    if parts.is_empty() {
        return malformed(format!("IN on '{field}' was given an empty list"));
    }
    Ok(parts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ComplexCondition, HavingCondition};

    fn fc(field: Option<&str>, op: FilterOperator, value: Option<Value>) -> FilterCondition {
        FilterCondition { field: field.map(str::to_string), operator: Some(op), value, ..Default::default() }
    }

    fn f(field: &str, op: FilterOperator, value: impl Into<Value>) -> FilterCondition {
        fc(Some(field), op, Some(value.into()))
    }

    fn sql(c: impl Into<Condition>) -> FilterResult<String> {
        Ok(build(Some(&c.into()), &FieldResolver::of(IndexSet::new()))?.inlined())
    }

    fn read(c: impl Into<Condition>) -> FilterResult<String> {
        Ok(build_for_read(Some(&c.into()), &FieldResolver::of(IndexSet::new()))?.inlined())
    }

    fn text_sql(term: &str, stemming: bool) -> String {
        let resolver = FieldResolver::of(IndexSet::new())
            .with_text_columns(["title", "body"].iter().map(|s| s.to_string()).collect())
            .with_stemming(stemming);
        build(Some(&f("title", FilterOperator::TextSearch, term).into()), &resolver).unwrap().inlined()
    }

    fn and(cs: Vec<FilterCondition>) -> ComplexCondition {
        ComplexCondition::and(cs.into_iter().map(Condition::from).collect())
    }

    fn or(cs: Vec<FilterCondition>) -> ComplexCondition {
        ComplexCondition::or(cs.into_iter().map(Condition::from).collect())
    }

    use FilterOperator::*;

    #[test]
    fn comparisons() {
        assert_eq!(sql(f("region", Equals, "North")).unwrap(), "`region` = 'North'");
        assert_eq!(sql(f("n", GreaterThan, 5)).unwrap(), "`n` > 5");
        assert_eq!(sql(f("n", GreaterThanEqual, 5)).unwrap(), "`n` >= 5");
        assert_eq!(sql(f("n", LessThan, 5)).unwrap(), "`n` < 5");
        assert_eq!(sql(f("n", LessThanEqual, 5)).unwrap(), "`n` <= 5");
        assert_eq!(sql(f("a", Equals, "b").with_value_field()).unwrap(), "`a` = `b`");
    }

    #[test]
    fn predicates() {
        assert_eq!(sql(fc(Some("a"), IsNull, None)).unwrap(), "`a` is null");
        assert!(sql(fc(Some("a"), IsTrue, None)).unwrap().contains("`a`"));
        assert!(sql(fc(Some("a"), IsFalse, None)).unwrap().contains("`a`"));
        for op in [IsNull, IsTrue, IsFalse] {
            assert!(!sql(fc(Some("a"), op, None)).unwrap().is_empty());
        }
    }

    #[test]
    fn in_lists() {
        let c = fc(Some("s"), In, None).with_multi_value(vec!["A".into(), "B".into()]);
        assert_eq!(sql(c).unwrap(), "`s` in ('A', 'B')");
        assert_eq!(sql(f("s", In, "A,B,C")).unwrap(), "`s` in ('A', 'B', 'C')");
        assert_eq!(sql(f("s", In, " A , B ")).unwrap(), "`s` in ('A', 'B')");
        assert!(sql(f("s", In, " , ")).is_err());
        assert!(sql(fc(Some("s"), In, None)).is_err());
    }

    #[test]
    fn strings_and_ranges() {
        assert_eq!(sql(f("a", Like, "x%")).unwrap(), "`a` like 'x%'");
        assert_eq!(sql(f("a", StringLooseEqual, "x")).unwrap(), "`a` like '%x%'");
        assert_eq!(sql(f("n", Between, 1).with_to_value(10)).unwrap(), "`n` between 1 and 10");
        assert!(sql(f("n", Between, 1)).is_err());
    }

    #[test]
    fn negation() {
        assert_eq!(sql(f("a", Equals, 1).negated()).unwrap(), "not (`a` = 1)");
        assert_eq!(
            sql(and(vec![f("a", Equals, 1), f("b", Equals, 2)]).negated()).unwrap(),
            "(not (`a` = 1) or not (`b` = 2))"
        );
        assert_eq!(
            sql(or(vec![f("a", Equals, 1), f("b", Equals, 2)]).negated()).unwrap(),
            "(not (`a` = 1) and not (`b` = 2))"
        );
    }

    #[test]
    fn grouping() {
        assert_eq!(sql(and(vec![f("a", Equals, 1), f("b", Equals, 2)])).unwrap(), "(`a` = 1 and `b` = 2)");
        assert_eq!(sql(or(vec![f("a", Equals, 1), f("b", Equals, 2)])).unwrap(), "(`a` = 1 or `b` = 2)");
        let inner = or(vec![f("b", Equals, 2), f("c", Equals, 3)]);
        let outer = ComplexCondition::and(vec![f("a", Equals, 1).into(), inner.into()]);
        assert_eq!(sql(outer).unwrap(), "(`a` = 1 and (`b` = 2 or `c` = 3))");
        assert_eq!(sql(and(vec![])).unwrap(), "true");
        assert_eq!(build(None, &FieldResolver::of(IndexSet::new())).unwrap().inlined(), "true");
    }

    #[test]
    fn unsupported() {
        let e = sql(f("a", TextSearch, "x")).unwrap_err();
        assert!(e.detail().contains("textIndexFields"));
        assert!(!e.is_malformed());
        let e = sql(f("a", Match, "x").with_match_operator(In)).unwrap_err();
        assert!(e.detail().contains("IN"));
        assert!(!e.is_malformed());
        assert!(sql(fc(Some("a"), MatchAll, None)).is_err());
        let having = Condition::Having(HavingCondition { negate: false, aggregate_function: None, condition: None });
        assert!(build(Some(&having), &FieldResolver::of(IndexSet::new())).is_err());
        assert!(sql(fc(None, Equals, Some(1.into()))).unwrap_err().is_malformed());
        assert!(sql(fc(Some("  "), Equals, Some(1.into()))).is_err());
        let mut c = fc(Some("a"), Equals, None);
        c.operator = None;
        assert!(sql(c).is_err());
        assert!(sql(fc(Some("a"), Equals, None)).is_err());
    }

    #[test]
    fn malformed_vs_unsupported() {
        let e = sql(f("a", Between, 1)).unwrap_err();
        assert!(e.is_malformed());
        assert!(e.detail().contains("toValue") && e.detail().contains("'a'"), "{}", e.detail());
        assert!(sql(f("a", In, " , , ")).unwrap_err().is_malformed());
    }

    #[test]
    fn stemming() {
        let s = text_sql("guides", true);
        assert!(s.contains("IN BOOLEAN MODE") && s.contains("guid*"), "{s}");
        let s = text_sql("southern regions", true);
        assert!(s.contains("southern*") && s.contains("region*") && !s.contains('+'), "{s}");
        let s = text_sql("C++ (best) ~thing", true);
        assert!(!s.contains("++") && !s.contains('~') && !s.contains("(best)"), "{s}");
        let s = text_sql("quarterly", true);
        assert!(s.contains("quarterl*") && !s.contains("quarterli*"), "{s}");
        let s = text_sql("+++ ---", true);
        assert!(!s.contains("AGAINST"), "{s}");
        let s = text_sql("guides", false);
        assert!(s.contains("IN NATURAL LANGUAGE MODE") && s.contains("guides") && !s.contains("guid*"), "{s}");
        assert_eq!(
            text_sql("guides", true),
            "(MATCH(`title`, `body`) AGAINST ('guid*' IN BOOLEAN MODE))"
        );
    }

    #[test]
    fn reads_skip_empty() {
        assert_eq!(read(and(vec![f("a", Equals, 1), fc(Some("b"), Equals, None)])).unwrap(), "`a` = 1");
        for op in [
            Equals, GreaterThan, GreaterThanEqual, LessThan, LessThanEqual, Like, StringLooseEqual, Between, In, Match,
            MatchAll, TextSearch,
        ] {
            assert_eq!(read(fc(Some("a"), op, None)).unwrap(), "true", "{op}");
        }
        assert_eq!(read(and(vec![f("a", Equals, 1), fc(Some("b"), Equals, None).negated()])).unwrap(), "`a` = 1");
        assert_eq!(read(and(vec![f("a", Equals, 1), fc(Some("b"), Equals, None)]).negated()).unwrap(), "not (`a` = 1)");
        assert_eq!(read(and(vec![fc(Some("a"), Equals, None), fc(Some("b"), In, None)])).unwrap(), "true");
        assert_eq!(read(fc(Some("a"), IsNull, None)).unwrap(), "`a` is null");
        assert!(read(fc(Some("a"), IsTrue, None)).unwrap().contains("`a`"));
        assert_eq!(read(fc(Some("s"), In, None).with_multi_value(vec!["A".into()])).unwrap(), "`s` in ('A')");
        assert!(read(f("s", In, " , ")).is_err());
        assert!(read(f("n", Between, 1)).is_err());
        assert!(read(fc(None, Equals, Some(1.into()))).is_err());
        assert_eq!(read(f("a", Equals, "")).unwrap(), "`a` = ''");
        assert!(sql(and(vec![f("a", Equals, 1), fc(Some("b"), Equals, None)])).is_err());
    }

    #[test]
    fn lists_and_maps_do_not_bind() {
        let e = sql(f("a", Equals, Value::Array(vec!["x".into()]))).unwrap_err();
        assert!(matches!(e, FilterError::Unbindable(_)));
    }
}
