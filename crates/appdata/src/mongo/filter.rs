//! `MongoAppDataService.filter`: a condition as a Mongo query document, built the way the
//! Java driver's `Filters` builds it, so the server sees the same document from both.
//!
//! A filter given no value drops out (an empty document), as it does in Java. `_id` and
//! relation fields compare as ObjectIds. A dollar in a field name or a value's keys is
//! refused, because there it would be an operator rather than data.

use mongodb::bson::{doc, oid::ObjectId, Bson, Document as BsonDocument, Regex};

use super::bson_util::filter_value;
use crate::error::{AppDataError, AppDataResult};
use crate::field_names;
use crate::model::{ComplexCondition, ComplexOperator, Condition, FilterCondition, FilterOperator, Storage};
use crate::value::Value;

/// `filter(storage, condition)`: `{}` for no condition.
pub fn filter(storage: &Storage, condition: Option<&Condition>) -> AppDataResult<BsonDocument> {
    let built = match condition {
        None => return Ok(BsonDocument::new()),
        Some(Condition::Complex(cc)) => complex(storage, cc)?,
        Some(Condition::Filter(fc)) => filter_condition(storage, fc)?,
        Some(other) => return Err(AppDataError::unsupported_condition(other.class_name())),
    };
    Ok(built.unwrap_or_default())
}

fn complex(storage: &Storage, cc: &ComplexCondition) -> AppDataResult<Option<BsonDocument>> {
    let Some(conditions) = cc.conditions.as_ref().filter(|c| !c.is_empty()) else { return Ok(None) };

    let mut parts = Vec::with_capacity(conditions.len());
    for c in conditions {
        let e = filter(storage, c.as_ref())?;
        parts.push(Bson::Document(if cc.negate { not(e) } else { e }));
    }

    let and = cc.operator == Some(ComplexOperator::And);
    let key = match (and, cc.negate) {
        (true, false) | (false, true) => "$and",
        _ => "$or",
    };
    Ok(Some(doc! { key: parts }))
}

/// `Filters.not`, as driver 5 encodes its NotFilter.
pub fn not(filter: BsonDocument) -> BsonDocument {
    if filter.len() == 1 {
        let (k, v) = filter.into_iter().next().unwrap_or_default();
        return create_not(k, v);
    }
    let values: Vec<Bson> = filter.into_iter().map(|(k, v)| Bson::Document(doc! { k: v })).collect();
    create_not("$and".into(), Bson::Array(values))
}

fn create_not(field: String, value: Bson) -> BsonDocument {
    if field.starts_with('$') {
        return doc! { "$not": { field: value } };
    }
    let operator = match &value {
        Bson::Document(d) => d.keys().any(|k| k.starts_with('$')),
        Bson::RegularExpression(_) => true,
        _ => false,
    };
    if operator {
        doc! { field: { "$not": value } }
    } else {
        doc! { field: { "$not": { "$eq": value } } }
    }
}

fn op(field: &str, operator: &str, value: Bson) -> BsonDocument {
    doc! { field: { operator: value } }
}

fn object_id(v: &Value) -> AppDataResult<Bson> {
    let text = v.java_string();
    ObjectId::parse_str(&text)
        .map(Bson::ObjectId)
        .map_err(|_| AppDataError::internal(format!("IllegalArgumentException: invalid hexadecimal representation of an ObjectId: [{text}]")))
}

/// `Pattern.quote`.
pub fn pattern_quote(s: &str) -> String {
    if !s.contains("\\E") {
        return format!("\\Q{s}\\E");
    }
    let mut out = String::from("\\Q");
    let mut current = 0;
    while let Some(i) = s[current..].find("\\E") {
        let index = current + i;
        out.push_str(&s[current..index]);
        out.push_str("\\E\\\\E\\Q");
        current = index + 2;
    }
    out.push_str(&s[current..]);
    out.push_str("\\E");
    out
}

fn regex(field: &str, pattern: String, options: &str) -> BsonDocument {
    doc! { field: Bson::RegularExpression(Regex { pattern, options: options.to_string() }) }
}

fn match_operator(op: Option<FilterOperator>) -> AppDataResult<&'static str> {
    let Some(op) = op else {
        // Map.of(...).get(null) throws in Java.
        return Err(AppDataError::internal("NullPointerException: matchOperator"));
    };
    Ok(match op {
        FilterOperator::Equals => "$eq",
        FilterOperator::GreaterThan => "$gt",
        FilterOperator::GreaterThanEqual => "$gte",
        FilterOperator::LessThan => "$lt",
        FilterOperator::LessThanEqual => "$lte",
        FilterOperator::Like | FilterOperator::StringLooseEqual => "$regex",
        _ => "$eq",
    })
}

fn filter_condition(storage: &Storage, fc: &FilterCondition) -> AppDataResult<Option<BsonDocument>> {
    let operator = fc.operator;

    if operator == Some(FilterOperator::TextSearch) {
        let Some(v) = &fc.value else { return Ok(None) };
        return Ok(Some(doc! { "$text": { "$search": v.java_string() } }));
    }

    let Some(field) = fc.field.as_deref() else { return Ok(None) };

    if !field_names::safe_query_path(field) {
        return Err(AppDataError::unsupported_condition(&format!("a field named {field}")));
    }

    if !field_names::safe_filter_value(fc.value.as_ref())
        || !field_names::safe_filter_value(fc.to_value.as_ref())
        || !field_names::safe_filter_values(fc.multi_value.as_ref())
    {
        return Err(AppDataError::unsupported_condition(&format!("an operator in the value of {field}")));
    }

    if matches!(operator, Some(FilterOperator::IsFalse) | Some(FilterOperator::IsTrue)) {
        let b = if fc.negate { operator == Some(FilterOperator::IsFalse) } else { operator == Some(FilterOperator::IsTrue) };
        return Ok(Some(doc! { field: b }));
    }

    if operator == Some(FilterOperator::IsNull) {
        return Ok(Some(if fc.negate {
            op(field, "$ne", Bson::Null)
        } else {
            doc! { "$or": [ { field: Bson::Null }, { field: { "$exists": false } } ] }
        }));
    }

    let is_id = field == "_id" || storage.relation(field).is_some();
    let value: Option<Bson> = match &fc.value {
        None => None,
        Some(v) if is_id && operator != Some(FilterOperator::In) => Some(object_id(v)?),
        Some(v) => Some(filter_value(v)),
    };

    if operator == Some(FilterOperator::In) {
        let no_multi = fc.multi_value.as_ref().is_none_or(|m| m.is_empty());
        if fc.value.is_none() && no_multi {
            return Ok(None);
        }
        let items = multi_field_value(is_id, fc.value.as_ref(), fc.multi_value.as_ref())?;
        if items.is_empty() {
            return Err(AppDataError::unsupported_condition(&format!("IN on '{field}' was given an empty list")));
        }
        return Ok(Some(op(field, if fc.negate { "$nin" } else { "$in" }, Bson::Array(items))));
    }

    if operator == Some(FilterOperator::Match) {
        let Some(v) = value else { return Ok(None) };
        let m = match_operator(fc.match_operator)?;
        return Ok(Some(doc! { field: { "$elemMatch": { m: v } } }));
    }

    if operator == Some(FilterOperator::MatchAll) {
        let no_multi = fc.multi_value.as_ref().is_none_or(|m| m.is_empty());
        if value.is_none() && no_multi {
            return Ok(None);
        }
        let all = match value {
            Some(v) => Bson::Array(vec![v]),
            None => Bson::Array(fc.multi_value.iter().flatten().map(filter_value).collect()),
        };
        return Ok(Some(op(field, "$all", all)));
    }

    let Some(value) = value else { return Ok(None) };

    if operator == Some(FilterOperator::Between) {
        let Some(to) = &fc.to_value else {
            return Err(AppDataError::unsupported_condition(&format!("BETWEEN on '{field}' without a toValue")));
        };
        let to_value = if is_id { object_id(to)? } else { filter_value(to) };
        let (lower, upper) = if fc.negate {
            (op(field, "$lt", value), op(field, "$gt", to_value))
        } else {
            (op(field, "$gte", value), op(field, "$lte", to_value))
        };
        let key = if fc.negate { "$or" } else { "$and" };
        return Ok(Some(doc! { key: [lower, upper] }));
    }

    // Java switches on the operator here, and a null one throws: a 500.
    let Some(_) = operator else {
        return Err(AppDataError::internal("NullPointerException: the filter condition has no operator"));
    };

    let comparison = match operator {
        Some(FilterOperator::Equals) => Some(if fc.negate { "$ne" } else { "" }),
        Some(FilterOperator::GreaterThan) => Some(if fc.negate { "$lte" } else { "$gt" }),
        Some(FilterOperator::GreaterThanEqual) => Some(if fc.negate { "$lt" } else { "$gte" }),
        Some(FilterOperator::LessThan) => Some(if fc.negate { "$gte" } else { "$lt" }),
        Some(FilterOperator::LessThanEqual) => Some(if fc.negate { "$gt" } else { "$lte" }),
        _ => None,
    };
    if let Some(c) = comparison {
        return Ok(Some(if c.is_empty() { doc! { field: value } } else { op(field, c, value) }));
    }

    let raw = fc.value.as_ref().map(Value::java_string).unwrap_or_default();
    match operator {
        Some(FilterOperator::Like) => {
            let f = regex(field, raw, "");
            Ok(Some(if fc.negate { not(f) } else { f }))
        }
        Some(FilterOperator::StringLooseEqual) => {
            let f = regex(field, pattern_quote(&raw), "i");
            Ok(Some(if fc.negate { not(f) } else { f }))
        }
        _ => Ok(None),
    }
}

/// `multiFieldValue`: an explicit list, or a comma separated value where `\,` is a comma.
fn multi_field_value(convert_id: bool, value: Option<&Value>, values: Option<&Vec<Value>>) -> AppDataResult<Vec<Bson>> {
    if let Some(vs) = values.filter(|v| !v.is_empty()) {
        return vs.iter().map(|v| if convert_id { object_id(v) } else { Ok(filter_value(v)) }).collect();
    }
    let Some(v) = value else { return Ok(Vec::new()) };

    let text = v.java_string();
    let text = text.trim();
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut from = 0;
    for i in 0..chars.len() {
        if chars[i] != ',' {
            continue;
        }
        if i != 0 && chars[i - 1] == '\\' {
            continue;
        }
        add_item(&mut out, &chars[from..i].iter().collect::<String>(), convert_id)?;
        from = i + 1;
    }
    add_item(&mut out, &chars[from..].iter().collect::<String>(), convert_id)?;
    Ok(out)
}

fn add_item(out: &mut Vec<Bson>, raw: &str, convert_id: bool) -> AppDataResult<()> {
    let s = raw.trim();
    if s.is_empty() {
        return Ok(());
    }
    let s = s.replace("\\,", ",");
    out.push(if convert_id { object_id(&Value::String(s))? } else { Bson::String(s) });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn storage() -> Storage {
        let mut rel = indexmap::IndexMap::new();
        rel.insert("owner".to_string(), crate::model::StorageRelation::to_one("people"));
        Storage { name: "s".into(), relations: Some(rel), ..Default::default() }
    }

    fn json(c: impl Into<Condition>) -> String {
        Bson::Document(filter(&storage(), Some(&c.into())).unwrap()).into_relaxed_extjson().to_string()
    }

    #[test]
    fn shapes() {
        use FilterOperator::*;
        assert_eq!(json(FilterCondition::eq("a", 1)), r#"{"a":1}"#);
        assert_eq!(json(FilterCondition::eq("a", 1).negated()), r#"{"a":{"$ne":1}}"#);
        assert_eq!(
            json(FilterCondition::new("a", Between, Some(1.into())).with_to_value(5)),
            r#"{"$and":[{"a":{"$gte":1}},{"a":{"$lte":5}}]}"#
        );
        assert_eq!(json(FilterCondition::new("a", In, Some("x, y\\,z ,".into()))), r#"{"a":{"$in":["x","y,z"]}}"#);
        assert_eq!(
            json(FilterCondition::new("a", IsNull, None)),
            r#"{"$or":[{"a":null},{"a":{"$exists":false}}]}"#
        );
        assert_eq!(
            json(FilterCondition::new("a", StringLooseEqual, Some("+91".into())).negated()),
            r#"{"a":{"$not":{"$regularExpression":{"pattern":"\\Q+91\\E","options":"i"}}}}"#
        );
        assert_eq!(
            json(FilterCondition::eq("owner", "6ac7d4a11a578c042996bca5")),
            r#"{"owner":{"$oid":"6ac7d4a11a578c042996bca5"}}"#
        );
        let and = ComplexCondition::and(vec![FilterCondition::eq("a", 1).into(), FilterCondition::eq("b", 2).into()]).negated();
        assert_eq!(json(and), r#"{"$or":[{"a":{"$not":{"$eq":1}}},{"b":{"$not":{"$eq":2}}}]}"#);
        assert_eq!(json(FilterCondition::new("a", Equals, None)), "{}");
        assert_eq!(pattern_quote("a\\Eb"), "\\Qa\\E\\\\E\\Qb\\E");
    }

    #[test]
    fn refusals() {
        let s = storage();
        let e = filter(&s, Some(&FilterCondition::eq("$where", 1).into())).unwrap_err();
        assert_eq!(e.status(), http::StatusCode::BAD_REQUEST);
        assert!(e.message().contains("a field named $where"));
        let v = Value::parse_json(r#"{"$gt":0}"#).unwrap();
        assert!(filter(&s, Some(&FilterCondition::eq("price", v).into())).is_err());
        let empty_in = FilterCondition::new("a", FilterOperator::In, Some(" , ".into()));
        assert!(filter(&s, Some(&empty_in.into())).unwrap_err().message().contains("empty list"));
        let between = FilterCondition::new("a", FilterOperator::Between, Some(1.into()));
        assert!(filter(&s, Some(&between.into())).unwrap_err().message().contains("without a toValue"));
    }
}
