//! `AggregateQueryValidator`: the rules an aggregate request meets before either backend
//! builds a query from it. Field names become pipeline paths and column references,
//! aliases become output keys, so this is the injection gate, shared so the two backends
//! cannot drift apart.

use indexmap::IndexSet;

use crate::model::{AggregateFunction, AggregateQuery, Aggregation, Condition, GroupByField};

/// `[A-Za-z_][A-Za-z0-9_]*`, matched whole.
pub fn alias_ok(alias: &str) -> bool {
    let b = alias.as_bytes();
    !b.is_empty()
        && (b[0].is_ascii_alphabetic() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
}

pub const ALIAS_PATTERN: &str = "[A-Za-z_][A-Za-z0-9_]*";

/// The reason this request is not usable, or None when it is.
pub fn check(query: &AggregateQuery) -> Option<String> {
    let Some(aggregations) = query.aggregations.as_ref().filter(|a| !a.is_empty()) else {
        return Some("at least one aggregation is required".into());
    };

    if matches!(query.having, Some(Condition::Having(_))) {
        return Some(
            "having must be a plain condition over the aliases; HavingCondition carries its own aggregate and is not supported here"
                .into(),
        );
    }

    let mut aliases = IndexSet::new();

    if let Some(groups) = &query.group_by {
        for g in groups {
            if let Some(err) = check_group_by(g, &mut aliases) {
                return Some(err);
            }
        }
    }

    for a in aggregations {
        if let Some(err) = check_aggregation(a, &mut aliases) {
            return Some(err);
        }
    }

    if let Some(sort) = &query.sort {
        for o in &sort.orders {
            if !aliases.contains(&o.property) {
                let list: Vec<&str> = aliases.iter().map(String::as_str).collect();
                return Some(format!(
                    "cannot sort on '{}'; sort is only possible on a group key or measure alias [{}]",
                    o.property,
                    list.join(", ")
                ));
            }
        }
    }

    None
}

/// Every alias this query produces.
pub fn aliases(query: &AggregateQuery) -> IndexSet<String> {
    let mut out = IndexSet::new();
    for g in query.group_by.iter().flatten() {
        if let Some(a) = g.resolved_alias() {
            out.insert(a);
        }
    }
    for a in query.aggregations.iter().flatten() {
        if let Some(a) = a.resolved_alias() {
            out.insert(a);
        }
    }
    out
}

fn check_group_by(g: &GroupByField, aliases: &mut IndexSet<String>) -> Option<String> {
    let Some(field) = g.field.as_ref().filter(|f| !f.trim().is_empty()) else {
        return Some("a groupBy entry has no field".into());
    };
    if field.contains('$') {
        return Some(format!("field '{field}' may not contain '$'"));
    }

    let alias = g.resolved_alias().unwrap_or_default();
    if !alias_ok(&alias) {
        return Some(format!("alias '{alias}' must match {ALIAS_PATTERN}"));
    }
    if !aliases.insert(alias.clone()) {
        return Some(format!("duplicate alias '{alias}'"));
    }

    if g.bucket.is_none() {
        if g.encoding.is_some() {
            return Some(format!("encoding is only meaningful with a bucket, on field '{field}'"));
        }
        return None;
    }

    if !zone_id_ok(&g.resolved_timezone()) {
        return Some(format!(
            "'{}' is not a known IANA timezone",
            g.timezone.clone().unwrap_or_else(|| "null".into())
        ));
    }

    None
}

fn check_aggregation(a: &Aggregation, aliases: &mut IndexSet<String>) -> Option<String> {
    let Some(f) = a.function else { return Some("an aggregation has no function".into()) };

    if f != AggregateFunction::Count && a.field.as_ref().is_none_or(|f| f.trim().is_empty()) {
        return Some(format!("{f} needs a field"));
    }

    if let Some(field) = a.field.as_ref().filter(|f| f.contains('$')) {
        return Some(format!("field '{field}' may not contain '$'"));
    }

    let alias = a.resolved_alias();
    let Some(alias) = alias.filter(|a| alias_ok(a)) else {
        return Some(format!(
            "alias '{}' must match {ALIAS_PATTERN}",
            a.resolved_alias().unwrap_or_else(|| "null".into())
        ));
    };
    if !aliases.insert(alias.clone()) {
        return Some(format!("duplicate alias '{alias}'"));
    }

    None
}

/// Whether `ZoneId.of(id)` accepts this: an offset, UTC / GMT / UT with or without one, or
/// a region in the tz database.
pub fn zone_id_ok(id: &str) -> bool {
    if id == "Z" {
        return true;
    }
    if id.starts_with('+') || id.starts_with('-') {
        return offset_ok(id);
    }
    for prefix in ["UTC", "GMT", "UT"] {
        if id == prefix {
            return true;
        }
        if let Some(rest) = id.strip_prefix(prefix) {
            if rest.starts_with('+') || rest.starts_with('-') {
                return offset_ok(rest);
            }
        }
    }
    let shape_ok = id.len() >= 2
        && id.as_bytes()[0].is_ascii_alphabetic()
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b"~/._+-".contains(&b));
    shape_ok && id.parse::<chrono_tz::Tz>().is_ok()
}

/// `ZoneOffset.of`: ±h, ±hh, ±hh:mm, ±hhmm, ±hh:mm:ss, ±hhmmss, within ±18:00.
fn offset_ok(s: &str) -> bool {
    let body = &s[1..];
    let num = |t: &str| -> Option<u32> {
        if t.bytes().all(|b| b.is_ascii_digit()) && !t.is_empty() {
            t.parse().ok()
        } else {
            None
        }
    };
    let (h, m, sec) = match body.len() {
        1 | 2 => (num(body), Some(0), Some(0)),
        4 => (num(&body[..2]), num(&body[2..]), Some(0)),
        5 if &body[2..3] == ":" => (num(&body[..2]), num(&body[3..]), Some(0)),
        6 => (num(&body[..2]), num(&body[2..4]), num(&body[4..])),
        8 if &body[2..3] == ":" && &body[5..6] == ":" => (num(&body[..2]), num(&body[3..5]), num(&body[6..])),
        _ => return false,
    };
    match (h, m, sec) {
        (Some(h), Some(m), Some(s)) => h <= 18 && m <= 59 && s <= 59 && (h < 18 || (m == 0 && s == 0)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DateBucketUnit, Order, Sort};

    fn q(groups: Vec<GroupByField>, aggs: Vec<Aggregation>) -> AggregateQuery {
        AggregateQuery { group_by: Some(groups), aggregations: Some(aggs), ..Default::default() }
    }

    #[test]
    fn rules() {
        assert!(check(&AggregateQuery::default()).unwrap().contains("at least one aggregation"));
        let count = Aggregation::new(AggregateFunction::Count, None);
        assert!(check(&q(vec![GroupByField::new("region")], vec![count.clone()])).is_none());
        assert!(check(&q(vec![], vec![Aggregation::new(AggregateFunction::Sum, None)])).unwrap().contains("needs a field"));
        assert!(check(&q(vec![GroupByField::new("$x")], vec![count.clone()])).unwrap().contains("'$'"));
        let mut g = GroupByField::new("a");
        g.alias = Some("bad alias".into());
        assert!(check(&q(vec![g], vec![count.clone()])).unwrap().contains("must match"));
        let mut g = GroupByField::new("a");
        g.encoding = Some(crate::model::DateEncoding::EpochSeconds);
        assert!(check(&q(vec![g], vec![count.clone()])).unwrap().contains("only meaningful with a bucket"));
        let mut g = GroupByField::new("a");
        g.bucket = Some(DateBucketUnit::Day);
        g.timezone = Some("Mars/Olympus".into());
        assert!(check(&q(vec![g], vec![count.clone()])).unwrap().contains("not a known IANA timezone"));
        let mut sorted = q(vec![GroupByField::new("region")], vec![count.clone()]);
        sorted.sort = Some(Sort::by(vec![Order::desc("amount")]));
        assert!(check(&sorted).unwrap().contains("cannot sort on 'amount'"));
        let dup = q(vec![GroupByField::new("count")], vec![count]);
        assert!(check(&dup).unwrap().contains("duplicate alias 'count'"));
    }

    #[test]
    fn zones() {
        for z in ["UTC", "Z", "Asia/Kolkata", "+05:30", "-08", "GMT+2", "UTC-05:00", "America/New_York", "EST"] {
            assert!(zone_id_ok(z), "{z}");
        }
        for z in ["Mars/Olympus", "+19:00", "asia/kolkata", "", "UTC+", "+5:30"] {
            assert!(!zone_id_ok(z), "{z}");
        }
    }
}
