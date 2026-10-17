//! `MySQLAggregateBuilder`: an `AggregateQuery` as SQL. Validation is NOT done here; the
//! validator has already refused anything whose names are not identifiers.

use indexmap::IndexSet;

use super::field_resolver::FieldResolver;
use super::filter_builder::FilterResult;
use super::sql::{Cond, Select, Sql};
use crate::model::{AggregateFunction, AggregateQuery, Aggregation, DateBucketUnit, DateEncoding, GroupByField, Pageable, Sort};

/// The datetime zero point as a literal, so no session time zone can move it.
const EPOCH: &str = "TIMESTAMP('1970-01-01 00:00:00')";

/// The grouped SELECT, without paging.
pub fn grouped(table: &Sql, query: &AggregateQuery, where_: Cond, resolver: &FieldResolver) -> FilterResult<Select> {
    let mut select = Vec::new();
    let mut group_by = Vec::new();

    for g in query.group_by.iter().flatten() {
        let key = group_key(g, resolver)?;
        select.push(key.alias(&g.resolved_alias().unwrap_or_default()));
        group_by.push(key);
    }

    for a in query.aggregations.iter().flatten() {
        select.push(measure(a, resolver)?.alias(&a.resolved_alias().unwrap_or_default()));
    }

    Ok(Select { fields: select, from: table.clone(), where_: Some(where_), group_by, ..Default::default() })
}

/// The full query: grouped, filtered after grouping, sorted and paged.
pub fn page(
    table: &Sql,
    query: &AggregateQuery,
    where_: Cond,
    having: Option<Cond>,
    pageable: &Pageable,
    resolver: &FieldResolver,
) -> FilterResult<Select> {
    let mut s = grouped(table, query, where_, resolver)?;
    s.having = having;
    s.order_by = order(&pageable.sort);
    s.limit = Some((pageable.page_size(), pageable.offset()));
    Ok(s)
}

/// How many groups there are: the grouped query wrapped and counted, HAVING kept.
pub fn count(
    table: &Sql,
    query: &AggregateQuery,
    where_: Cond,
    having: Option<Cond>,
    resolver: &FieldResolver,
) -> FilterResult<Select> {
    let mut inner = grouped(table, query, where_, resolver)?;
    inner.having = having;
    Ok(Select::count(inner.as_table("grouped")))
}

/// Sort on the output aliases.
pub fn order(sort: &Sort) -> Vec<Sql> {
    sort.orders
        .iter()
        .map(|o| {
            let f = Sql::name(&[&o.property]);
            if o.is_ascending() {
                f.asc()
            } else {
                f.desc()
            }
        })
        .collect()
}

/// One measure. No CAST on SUM and AVG: jOOQ's double cast is DECIMAL(10,0) on MySQL.
pub fn measure(a: &Aggregation, resolver: &FieldResolver) -> FilterResult<Sql> {
    let Some(field) = a.field.as_ref().filter(|f| !f.trim().is_empty()) else {
        return Ok(Sql::raw("count(*)"));
    };
    let f = resolver.resolve(field)?;
    let wrap = |name: &str| Sql::raw(format!("{name}(")).then_sql(&f).then(")");
    Ok(match a.function.unwrap_or(AggregateFunction::Count) {
        AggregateFunction::Count => wrap("count"),
        AggregateFunction::CountDistinct => Sql::raw("count(distinct ").then_sql(&f).then(")"),
        AggregateFunction::Sum => wrap("sum"),
        AggregateFunction::Avg => wrap("avg"),
        AggregateFunction::Min => wrap("min"),
        AggregateFunction::Max => wrap("max"),
    })
}

/// The group key: the raw value, or a truncated date.
pub fn group_key(g: &GroupByField, resolver: &FieldResolver) -> FilterResult<Sql> {
    let raw = resolver.resolve(g.field.as_deref().unwrap_or(""))?;

    let Some(bucket) = g.bucket else { return Ok(raw) };

    let utc = match g.encoding {
        None => "{0}".to_string(),
        Some(e) => format!("{EPOCH} + INTERVAL FLOOR({{0}} * {} / 1000) SECOND", e.to_millis()),
    };

    let zone = g.resolved_timezone();
    let shifted = zone != "UTC";

    let local = if shifted { format!("CONVERT_TZ({utc}, '+00:00', '{zone}')") } else { utc };
    let truncated = truncate(bucket, &local);
    let back_to_utc = if shifted { format!("CONVERT_TZ({truncated}, '{zone}', '+00:00')") } else { truncated };

    let Some(encoding) = g.encoding else { return Ok(Sql::template(&back_to_utc, &[raw])) };

    let seconds = format!("TIMESTAMPDIFF(SECOND, {EPOCH}, {back_to_utc})");
    let value = if encoding == DateEncoding::EpochMillis { format!("({seconds}) * 1000") } else { seconds };
    Ok(Sql::template(&value, &[raw]))
}

/// Truncate a datetime expression to a boundary, as arithmetic that yields a datetime.
pub fn truncate(unit: DateBucketUnit, d: &str) -> String {
    match unit {
        DateBucketUnit::Year => format!("MAKEDATE(YEAR({d}), 1)"),
        DateBucketUnit::Quarter => format!("MAKEDATE(YEAR({d}), 1) + INTERVAL (QUARTER({d}) - 1) QUARTER"),
        DateBucketUnit::Month => format!("DATE_SUB(DATE({d}), INTERVAL DAYOFMONTH({d}) - 1 DAY)"),
        DateBucketUnit::Week => format!("DATE_SUB(DATE({d}), INTERVAL DAYOFWEEK({d}) - 1 DAY)"),
        DateBucketUnit::IsoWeek => format!("DATE_SUB(DATE({d}), INTERVAL WEEKDAY({d}) DAY)"),
        DateBucketUnit::Day => format!("DATE({d})"),
        DateBucketUnit::Hour => format!("DATE_ADD(DATE({d}), INTERVAL HOUR({d}) HOUR)"),
    }
}

/// Does this server know the named zone?
pub fn zone_check(zone: &str) -> String {
    format!("SELECT CONVERT_TZ({EPOCH}, '+00:00', '{zone}') IS NOT NULL")
}

/// Named zones used by this query, UTC excluded.
pub fn named_zones(query: &AggregateQuery) -> IndexSet<String> {
    let mut out = IndexSet::new();
    for g in query.group_by.iter().flatten() {
        if g.bucket.is_some() && g.resolved_timezone() != "UTC" {
            out.insert(g.resolved_timezone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Condition, FilterCondition, Order};
    use crate::mysql::filter_builder;

    fn table() -> Sql {
        Sql::name(&["db", "orders"])
    }

    fn q(groups: Option<Vec<GroupByField>>, aggs: Vec<Aggregation>) -> AggregateQuery {
        AggregateQuery { group_by: groups, aggregations: Some(aggs), ..Default::default() }
    }

    fn agg(f: AggregateFunction, field: Option<&str>, alias: &str) -> Aggregation {
        Aggregation::new(f, field).with_alias(alias)
    }

    fn sql(query: &AggregateQuery) -> String {
        grouped(&table(), query, Cond::None, &FieldResolver::of(IndexSet::new())).unwrap().to_sql().inlined()
    }

    fn bucket(field: &str, unit: DateBucketUnit) -> GroupByField {
        GroupByField { bucket: Some(unit), ..GroupByField::new(field) }
    }

    use AggregateFunction::*;

    #[test]
    fn measures() {
        assert!(sql(&q(None, vec![agg(Count, None, "n")])).contains("count(*)"));
        let s = sql(&q(None, vec![agg(Count, Some("amount"), "n")]));
        assert!(s.contains("count(`amount`)"), "{s}");
        let s = sql(&q(None, vec![agg(Sum, Some("amount"), "total"), agg(Avg, Some("amount"), "mean")]));
        assert!(s.contains("sum(`amount`)") && s.contains("avg(`amount`)") && !s.to_lowercase().contains("cast("), "{s}");
        assert!(s.contains("total"));
        assert!(sql(&q(None, vec![agg(Min, Some("code"), "lowest")])).contains("min(`code`)"));
        let s = sql(&q(None, vec![agg(CountDistinct, Some("ticketId"), "deals")]));
        assert!(s.contains("count(distinct `ticketId`)") && s.contains("`deals`"), "{s}");
        let s = sql(&q(None, vec![agg(Sum, Some("amount"), "total"), agg(Count, None, "n")]));
        assert!(s.contains("`total`") && s.contains("`n`"));
        assert_eq!(s, "select sum(`amount`) as `total`, count(*) as `n` from `db`.`orders`");
    }

    #[test]
    fn group_keys() {
        let s = sql(&q(Some(vec![GroupByField::new("region")]), vec![agg(Count, None, "n")]));
        assert!(s.contains("group by `region`"), "{s}");
        let mut g = GroupByField::new("region");
        g.alias = Some("r".into());
        let s = sql(&q(Some(vec![g]), vec![agg(Count, None, "n")]));
        assert!(s.contains("group by `region`") && !s.contains("group by `r`"), "{s}");
        let s = sql(&q(Some(vec![bucket("createdAt", DateBucketUnit::Month)]), vec![agg(Count, None, "n")]));
        assert!(!s.contains("1970-01-01") && s.contains("DAYOFMONTH"), "{s}");
        let mut e = bucket("ts", DateBucketUnit::Day);
        e.encoding = Some(DateEncoding::EpochSeconds);
        let s = sql(&q(Some(vec![e]), vec![agg(Count, None, "n")]));
        assert!(s.contains("1970-01-01") && s.contains("* 1000 / 1000") && s.contains("TIMESTAMPDIFF(SECOND"), "{s}");
        let mut m = bucket("ts", DateBucketUnit::Day);
        m.encoding = Some(DateEncoding::EpochMillis);
        assert!(sql(&q(Some(vec![m]), vec![agg(Count, None, "n")])).contains(") * 1000"));
        let s = sql(&q(Some(vec![bucket("createdAt", DateBucketUnit::Day)]), vec![agg(Count, None, "n")]));
        assert!(!s.contains("CONVERT_TZ"), "{s}");
        let mut z = bucket("createdAt", DateBucketUnit::Day);
        z.timezone = Some("Asia/Kolkata".into());
        let s = sql(&q(Some(vec![z]), vec![agg(Count, None, "n")]));
        assert!(s.contains("'+00:00', 'Asia/Kolkata'") && s.contains("'Asia/Kolkata', '+00:00'"), "{s}");
        for unit in [
            DateBucketUnit::Year,
            DateBucketUnit::Quarter,
            DateBucketUnit::Month,
            DateBucketUnit::Week,
            DateBucketUnit::IsoWeek,
            DateBucketUnit::Day,
            DateBucketUnit::Hour,
        ] {
            assert!(!truncate(unit, "d").contains("DATE_FORMAT"));
        }
        assert!(truncate(DateBucketUnit::Week, "d").contains("DAYOFWEEK"));
        assert_eq!(truncate(DateBucketUnit::IsoWeek, "d"), "DATE_SUB(DATE(d), INTERVAL WEEKDAY(d) DAY)");
        let mut w = bucket("createdAt", DateBucketUnit::IsoWeek);
        w.alias = Some("wk".into());
        w.timezone = Some("Asia/Kolkata".into());
        let s = sql(&q(Some(vec![w]), vec![agg(Count, None, "n")]));
        assert!(s.contains("WEEKDAY(CONVERT_TZ(") && s.contains("'Asia/Kolkata', '+00:00'"), "{s}");
        let mut city = GroupByField::new("address.city");
        city.alias = Some("city".into());
        let s = grouped(
            &table(),
            &q(Some(vec![city]), vec![agg(Count, None, "n")]),
            Cond::None,
            &FieldResolver::of(["address".to_string()].into_iter().collect()),
        )
        .unwrap()
        .to_sql()
        .inlined();
        assert!(s.contains("json_extract"), "{s}");
    }

    #[test]
    fn shape() {
        assert!(!sql(&q(None, vec![agg(Sum, Some("amount"), "total")])).contains("group by"));
        let mut query = q(Some(vec![GroupByField::new("region")]), vec![agg(Sum, Some("amount"), "total")]);
        query.having = Some(Condition::Filter(FilterCondition::eq("total", 100)));
        let having = filter_builder::build_json(query.having.as_ref(), IndexSet::new()).unwrap();
        let r = FieldResolver::of(IndexSet::new());
        let s = page(&table(), &query, Cond::None, Some(having.clone()), &query.pageable().unwrap(), &r)
            .unwrap()
            .to_sql()
            .inlined();
        assert!(s.contains("having") && s.contains("`total`"), "{s}");
        let c = count(&table(), &query, Cond::None, Some(having), &r).unwrap().to_sql().inlined();
        assert!(c.contains("having") && c.contains("grouped") && c.contains("group by"), "{c}");

        let mut sorted = q(Some(vec![GroupByField::new("region")]), vec![agg(Sum, Some("amount"), "total")]);
        sorted.sort = Some(Sort::by(vec![Order::desc("total")]));
        let s = page(&table(), &sorted, Cond::None, None, &sorted.pageable().unwrap(), &r).unwrap().to_sql().inlined();
        assert!(s.contains("order by `total` desc"), "{s}");

        let mut paged = q(Some(vec![GroupByField::new("region")]), vec![agg(Count, None, "n")]);
        paged.size = 5000;
        paged.page = 2;
        let s = page(&table(), &paged, Cond::None, None, &paged.pageable().unwrap(), &r).unwrap().to_sql().inlined();
        assert!(s.contains(&format!("limit {}", AggregateQuery::MAX_SIZE)), "{s}");

        let mut a = bucket("a", DateBucketUnit::Day);
        a.timezone = Some("Asia/Kolkata".into());
        let zones = named_zones(&q(Some(vec![a, bucket("b", DateBucketUnit::Day)]), vec![agg(Count, None, "n")]));
        assert_eq!(zones.into_iter().collect::<Vec<_>>(), vec!["Asia/Kolkata".to_string()]);
    }
}
