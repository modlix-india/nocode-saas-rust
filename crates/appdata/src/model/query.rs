//! `Query`, `AggregateQuery` and the Spring `Sort` / `Pageable` they carry.
//!
//! Field defaults follow the Java beans: a query with no `size` reads 10 rows, with no
//! `sort` sorts on `updatedAt DESC` (which most storages do not have, and which both
//! backends therefore drop), and with no `count` counts.

use serde::{Deserialize, Deserializer};

use super::condition::{condition_opt, AggregateFunction, Condition};
use crate::error::{AppDataError, AppDataResult};
use crate::value::{Document, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Asc,
    Desc,
}

impl Direction {
    pub fn name(&self) -> &'static str {
        match self {
            Direction::Asc => "ASC",
            Direction::Desc => "DESC",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NullHandling {
    Native,
    NullsFirst,
    NullsLast,
}

impl NullHandling {
    pub fn name(&self) -> &'static str {
        match self {
            NullHandling::Native => "NATIVE",
            NullHandling::NullsFirst => "NULLS_FIRST",
            NullHandling::NullsLast => "NULLS_LAST",
        }
    }
}

/// `Sort.Order`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Order {
    pub direction: Direction,
    pub property: String,
    pub ignore_case: bool,
    pub null_handling: NullHandling,
}

impl Order {
    pub fn asc(property: &str) -> Order {
        Order { direction: Direction::Asc, property: property.into(), ignore_case: false, null_handling: NullHandling::Native }
    }

    pub fn desc(property: &str) -> Order {
        Order { direction: Direction::Desc, property: property.into(), ignore_case: false, null_handling: NullHandling::Native }
    }

    pub fn is_ascending(&self) -> bool {
        self.direction == Direction::Asc
    }

    /// The JSON Spring Data's `SortJsonComponent` writes for one order.
    pub fn to_value(&self) -> Value {
        let mut d = Document::new();
        d.insert("direction".into(), Value::from(self.direction.name()));
        d.insert("property".into(), Value::from(self.property.as_str()));
        d.insert("ignoreCase".into(), Value::Bool(self.ignore_case));
        d.insert("nullHandling".into(), Value::from(self.null_handling.name()));
        d.insert("ascending".into(), Value::Bool(self.is_ascending()));
        d.insert("descending".into(), Value::Bool(!self.is_ascending()));
        Value::Object(d)
    }
}

/// `org.springframework.data.domain.Sort`: an ordered list of orders, unsorted when empty.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Sort {
    pub orders: Vec<Order>,
}

impl Sort {
    pub fn unsorted() -> Sort {
        Sort { orders: Vec::new() }
    }

    pub fn by(orders: Vec<Order>) -> Sort {
        Sort { orders }
    }

    /// `Query.DEFAULT_SORT`.
    pub fn default_query_sort() -> Sort {
        Sort::by(vec![Order::desc("updatedAt")])
    }

    pub fn is_sorted(&self) -> bool {
        !self.orders.is_empty()
    }

    pub fn is_unsorted(&self) -> bool {
        self.orders.is_empty()
    }

    pub fn to_value(&self) -> Value {
        Value::Array(self.orders.iter().map(Order::to_value).collect())
    }

    /// `SortSerializationModule.SortDeserializer`: one order object or an array of them.
    pub fn from_value(v: &Value) -> Result<Option<Sort>, String> {
        match v {
            Value::Null => Ok(None),
            Value::Object(o) => Ok(Some(Sort::by(vec![order_from(o)?]))),
            Value::Array(a) => {
                let mut orders = Vec::new();
                for e in a {
                    match e {
                        Value::Object(o) => orders.push(order_from(o)?),
                        other => return Err(format!("not a sort order: {}", other.to_java_json())),
                    }
                }
                Ok(Some(Sort::by(orders)))
            }
            _ => Ok(None),
        }
    }
}

fn order_from(o: &Document) -> Result<Order, String> {
    let direction = match o.get("direction") {
        None => Direction::Asc,
        Some(Value::String(s)) if s == "ASC" => Direction::Asc,
        Some(Value::String(s)) if s == "DESC" => Direction::Desc,
        Some(other) => return Err(format!("not a sort direction: {}", other.to_java_json())),
    };
    let null_handling = match o.get("nullHandling") {
        None => NullHandling::Native,
        Some(Value::String(s)) if s == "NATIVE" => NullHandling::Native,
        Some(Value::String(s)) if s == "NULLS_FIRST" => NullHandling::NullsFirst,
        Some(Value::String(s)) if s == "NULLS_LAST" => NullHandling::NullsLast,
        Some(other) => return Err(format!("not a null handling: {}", other.to_java_json())),
    };
    let property = match o.get("property") {
        Some(Value::String(s)) => s.clone(),
        _ => return Err("a sort order needs a property".into()),
    };
    // Spring's Order refuses a blank property.
    if property.trim().is_empty() {
        return Err("Property must not be null or empty".into());
    }
    // `jsonNode.get("ignoreCase").textValue()` is null for a JSON boolean, so only the
    // STRING "true" turns it on. Reproduced.
    let ignore_case = matches!(o.get("ignoreCase"), Some(Value::String(s)) if s.eq_ignore_ascii_case("true"));
    Ok(Order { direction, property, ignore_case, null_handling })
}

/// `PageRequest`.
#[derive(Debug, Clone, PartialEq)]
pub struct Pageable {
    pub page: i32,
    pub size: i32,
    pub sort: Sort,
}

impl Pageable {
    /// `PageRequest.of(page, size, sort)`, with its two refusals.
    pub fn of(page: i32, size: i32, sort: Sort) -> AppDataResult<Pageable> {
        if page < 0 {
            return Err(AppDataError::illegal_argument("Page index must not be less than zero"));
        }
        if size < 1 {
            return Err(AppDataError::illegal_argument("Page size must not be less than one"));
        }
        Ok(Pageable { page, size, sort })
    }

    pub fn offset(&self) -> i64 {
        self.page as i64 * self.size as i64
    }

    pub fn page_size(&self) -> i64 {
        self.size as i64
    }

    pub fn to_value(&self) -> Value {
        let mut d = Document::new();
        d.insert("pageNumber".into(), Value::Int(self.page as i64));
        d.insert("pageSize".into(), Value::Int(self.size as i64));
        d.insert("sort".into(), self.sort.to_value());
        d.insert("offset".into(), Value::Int(self.offset()));
        d.insert("paged".into(), Value::Bool(true));
        d.insert("unpaged".into(), Value::Bool(false));
        Value::Object(d)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinType {
    Left,
    Inner,
}

/// `StorageJoin`: a relation of the queried storage, joined.
#[derive(Debug, Clone, PartialEq)]
pub struct StorageJoin {
    pub relation: Option<String>,
    pub alias: Option<String>,
    /// LEFT unless the JSON says otherwise; an explicit null stays null.
    pub join_type: Option<JoinType>,
}

impl StorageJoin {
    pub fn new(relation: &str) -> StorageJoin {
        StorageJoin { relation: Some(relation.into()), alias: None, join_type: Some(JoinType::Left) }
    }

    pub fn resolved_alias(&self) -> Option<String> {
        match &self.alias {
            Some(a) if !a.trim().is_empty() => Some(a.clone()),
            _ => self.relation.clone(),
        }
    }
}

/// `Aggregation`: one measure.
#[derive(Debug, Clone, PartialEq)]
pub struct Aggregation {
    pub function: Option<AggregateFunction>,
    pub field: Option<String>,
    pub alias: Option<String>,
}

impl Aggregation {
    pub fn new(function: AggregateFunction, field: Option<&str>) -> Aggregation {
        Aggregation { function: Some(function), field: field.map(str::to_string), alias: None }
    }

    pub fn with_alias(mut self, alias: &str) -> Aggregation {
        self.alias = Some(alias.into());
        self
    }

    pub fn resolved_alias(&self) -> Option<String> {
        if let Some(a) = &self.alias {
            if !a.trim().is_empty() {
                return Some(a.clone());
            }
        }
        let f = self.function?;
        let name = f.name().to_lowercase();
        Some(match &self.field {
            Some(field) if !field.trim().is_empty() => format!("{name}_{}", field.replace('.', "_")),
            _ => name,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DateBucketUnit {
    Year,
    Quarter,
    Month,
    Week,
    IsoWeek,
    Day,
    Hour,
}

impl DateBucketUnit {
    pub fn name(&self) -> &'static str {
        match self {
            DateBucketUnit::Year => "YEAR",
            DateBucketUnit::Quarter => "QUARTER",
            DateBucketUnit::Month => "MONTH",
            DateBucketUnit::Week => "WEEK",
            DateBucketUnit::IsoWeek => "ISO_WEEK",
            DateBucketUnit::Day => "DAY",
            DateBucketUnit::Hour => "HOUR",
        }
    }

    pub fn mongo_unit(&self) -> &'static str {
        match self {
            DateBucketUnit::Year => "year",
            DateBucketUnit::Quarter => "quarter",
            DateBucketUnit::Month => "month",
            DateBucketUnit::Week | DateBucketUnit::IsoWeek => "week",
            DateBucketUnit::Day => "day",
            DateBucketUnit::Hour => "hour",
        }
    }

    fn from_name(s: &str) -> Option<DateBucketUnit> {
        [
            DateBucketUnit::Year,
            DateBucketUnit::Quarter,
            DateBucketUnit::Month,
            DateBucketUnit::Week,
            DateBucketUnit::IsoWeek,
            DateBucketUnit::Day,
            DateBucketUnit::Hour,
        ]
        .into_iter()
        .find(|u| u.name() == s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DateEncoding {
    EpochSeconds,
    EpochMillis,
}

impl DateEncoding {
    pub fn to_millis(&self) -> i64 {
        match self {
            DateEncoding::EpochSeconds => 1000,
            DateEncoding::EpochMillis => 1,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            DateEncoding::EpochSeconds => "EPOCH_SECONDS",
            DateEncoding::EpochMillis => "EPOCH_MILLIS",
        }
    }
}

/// `GroupByField`.
#[derive(Debug, Clone, PartialEq)]
pub struct GroupByField {
    pub field: Option<String>,
    pub alias: Option<String>,
    pub bucket: Option<DateBucketUnit>,
    pub encoding: Option<DateEncoding>,
    pub timezone: Option<String>,
}

impl GroupByField {
    pub fn new(field: &str) -> GroupByField {
        GroupByField { field: Some(field.into()), alias: None, bucket: None, encoding: None, timezone: None }
    }

    pub fn resolved_alias(&self) -> Option<String> {
        if let Some(a) = &self.alias {
            if !a.trim().is_empty() {
                return Some(a.clone());
            }
        }
        self.field.as_ref().map(|f| f.replace('.', "_"))
    }

    pub fn resolved_timezone(&self) -> String {
        match &self.timezone {
            Some(t) if !t.trim().is_empty() => t.clone(),
            _ => "UTC".into(),
        }
    }
}

/// `StorageSubQuery`: a grouped read of a storage's children.
#[derive(Debug, Clone, PartialEq)]
pub struct StorageSubQuery {
    pub storage: Option<String>,
    pub relation: Option<String>,
    pub alias: Option<String>,
    pub condition: Option<Condition>,
    pub aggregations: Option<Vec<Aggregation>>,
    pub having: Option<Condition>,
    /// TRUE unless the JSON says otherwise.
    pub required: Option<bool>,
}

impl StorageSubQuery {
    pub fn resolved_alias(&self) -> Option<String> {
        match &self.alias {
            Some(a) if !a.trim().is_empty() => Some(a.clone()),
            _ => self.storage.clone(),
        }
    }
}

/// `com.fincity.saas.commons.model.Query`.
#[derive(Debug, Clone, PartialEq)]
pub struct Query {
    pub condition: Option<Condition>,
    pub joins: Option<Vec<StorageJoin>>,
    pub sub_queries: Option<Vec<StorageSubQuery>>,
    pub size: i32,
    pub page: i32,
    /// `None` only when the JSON sent `"sort": null`, which Spring refuses.
    pub sort: Option<Sort>,
    pub count: Option<bool>,
    pub fields: Option<Vec<String>>,
    pub exclude_fields: Option<bool>,
    pub eager: Option<bool>,
    pub eager_fields: Option<Vec<String>>,
}

impl Default for Query {
    fn default() -> Self {
        Query {
            condition: None,
            joins: None,
            sub_queries: None,
            size: 10,
            page: 0,
            sort: Some(Sort::default_query_sort()),
            count: Some(true),
            fields: None,
            exclude_fields: Some(false),
            eager: Some(false),
            eager_fields: None,
        }
    }
}

impl Query {
    pub fn with_condition(mut self, c: impl Into<Condition>) -> Self {
        self.condition = Some(c.into());
        self
    }

    pub fn with_sort(mut self, s: Sort) -> Self {
        self.sort = Some(s);
        self
    }

    pub fn with_page(mut self, page: i32, size: i32) -> Self {
        self.page = page;
        self.size = size;
        self
    }

    pub fn pageable(&self) -> AppDataResult<Pageable> {
        let sort = self
            .sort
            .clone()
            .ok_or_else(|| AppDataError::illegal_argument("Sort must not be null"))?;
        Pageable::of(self.page, self.size, sort)
    }

    pub fn counts(&self) -> bool {
        self.count == Some(true)
    }

    pub fn excludes(&self) -> bool {
        self.exclude_fields == Some(true)
    }

    pub fn has_joins(&self) -> bool {
        self.joins.as_ref().is_some_and(|j| !j.is_empty())
    }

    pub fn has_sub_queries(&self) -> bool {
        self.sub_queries.as_ref().is_some_and(|j| !j.is_empty())
    }

    pub fn from_value(v: &Value) -> Result<Query, String> {
        let Value::Object(o) = v else { return Err("a query must be an object".into()) };
        let mut q = Query::default();
        if let Some(c) = o.get("condition") {
            q.condition = condition_opt(Some(c))?;
        }
        if let Some(j) = o.get("joins") {
            q.joins = joins_from(j)?;
        }
        if let Some(s) = o.get("subQueries") {
            q.sub_queries = sub_queries_from(s)?;
        }
        if let Some(v) = o.get("size") {
            q.size = int_of(v, "size")?;
        }
        if let Some(v) = o.get("page") {
            q.page = int_of(v, "page")?;
        }
        if let Some(v) = o.get("sort") {
            q.sort = Sort::from_value(v)?;
        }
        if let Some(v) = o.get("count") {
            q.count = opt_bool(v);
        }
        if let Some(v) = o.get("fields") {
            q.fields = strings_of(v);
        }
        if let Some(v) = o.get("excludeFields") {
            q.exclude_fields = opt_bool(v);
        }
        if let Some(v) = o.get("eager") {
            q.eager = opt_bool(v);
        }
        if let Some(v) = o.get("eagerFields") {
            q.eager_fields = strings_of(v);
        }
        Ok(q)
    }
}

impl<'de> Deserialize<'de> for Query {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Query, D::Error> {
        let v = Value::deserialize(d)?;
        Query::from_value(&v).map_err(serde::de::Error::custom)
    }
}

/// `com.fincity.saas.commons.model.AggregateQuery`.
#[derive(Debug, Clone, PartialEq)]
pub struct AggregateQuery {
    pub condition: Option<Condition>,
    pub joins: Option<Vec<StorageJoin>>,
    pub sub_queries: Option<Vec<StorageSubQuery>>,
    pub group_by: Option<Vec<GroupByField>>,
    pub aggregations: Option<Vec<Aggregation>>,
    pub having: Option<Condition>,
    pub sort: Option<Sort>,
    pub size: i32,
    pub page: i32,
    pub count: Option<bool>,
}

impl Default for AggregateQuery {
    fn default() -> Self {
        AggregateQuery {
            condition: None,
            joins: None,
            sub_queries: None,
            group_by: None,
            aggregations: None,
            having: None,
            sort: None,
            size: 100,
            page: 0,
            count: Some(false),
        }
    }
}

impl AggregateQuery {
    pub const MAX_SIZE: i32 = 1000;

    /// Clamped to 1..=1000, and unsorted when no sort is given.
    pub fn pageable(&self) -> AppDataResult<Pageable> {
        let effective = (if self.size < 1 { 1 } else { self.size }).min(Self::MAX_SIZE);
        let sort = match &self.sort {
            Some(s) if s.is_sorted() => s.clone(),
            _ => Sort::unsorted(),
        };
        Pageable::of(self.page, effective, sort)
    }

    pub fn counts(&self) -> bool {
        self.count == Some(true)
    }

    pub fn has_joins(&self) -> bool {
        self.joins.as_ref().is_some_and(|j| !j.is_empty())
    }

    pub fn has_sub_queries(&self) -> bool {
        self.sub_queries.as_ref().is_some_and(|j| !j.is_empty())
    }

    pub fn from_value(v: &Value) -> Result<AggregateQuery, String> {
        let Value::Object(o) = v else { return Err("an aggregate query must be an object".into()) };
        let mut q = AggregateQuery::default();
        if let Some(c) = o.get("condition") {
            q.condition = condition_opt(Some(c))?;
        }
        if let Some(j) = o.get("joins") {
            q.joins = joins_from(j)?;
        }
        if let Some(s) = o.get("subQueries") {
            q.sub_queries = sub_queries_from(s)?;
        }
        if let Some(Value::Array(a)) = o.get("groupBy") {
            let mut out = Vec::new();
            for g in a {
                if let Value::Object(g) = g {
                    out.push(group_by_from(g)?);
                }
            }
            q.group_by = Some(out);
        }
        if let Some(a) = o.get("aggregations") {
            q.aggregations = aggregations_from(a)?;
        }
        if let Some(h) = o.get("having") {
            q.having = condition_opt(Some(h))?;
        }
        if let Some(v) = o.get("sort") {
            q.sort = Sort::from_value(v)?;
        }
        if let Some(v) = o.get("size") {
            q.size = int_of(v, "size")?;
        }
        if let Some(v) = o.get("page") {
            q.page = int_of(v, "page")?;
        }
        if let Some(v) = o.get("count") {
            q.count = opt_bool(v);
        }
        Ok(q)
    }
}

impl<'de> Deserialize<'de> for AggregateQuery {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<AggregateQuery, D::Error> {
        let v = Value::deserialize(d)?;
        AggregateQuery::from_value(&v).map_err(serde::de::Error::custom)
    }
}

fn int_of(v: &Value, name: &str) -> Result<i32, String> {
    match v {
        Value::Int(i) => i32::try_from(*i).map_err(|_| format!("{name} out of range")),
        Value::String(s) => s.trim().parse().map_err(|_| format!("{name} is not a number")),
        Value::Double(d) if d.fract() == 0.0 => Ok(*d as i32),
        Value::Null => Ok(0),
        other => Err(format!("{name} is not a number: {}", other.to_java_json())),
    }
}

fn opt_bool(v: &Value) -> Option<bool> {
    match v {
        Value::Bool(b) => Some(*b),
        Value::String(s) if s == "true" => Some(true),
        Value::String(s) if s == "false" => Some(false),
        _ => None,
    }
}

fn strings_of(v: &Value) -> Option<Vec<String>> {
    match v {
        Value::Array(a) => Some(a.iter().map(Value::java_string).collect()),
        _ => None,
    }
}

fn opt_string(v: Option<&Value>) -> Option<String> {
    match v {
        None | Some(Value::Null) => None,
        Some(v) => Some(v.java_string()),
    }
}

fn joins_from(v: &Value) -> Result<Option<Vec<StorageJoin>>, String> {
    let Value::Array(a) = v else { return Ok(None) };
    let mut out = Vec::new();
    for j in a {
        let Value::Object(o) = j else { continue };
        let join_type = match o.get("type") {
            None => Some(JoinType::Left),
            Some(Value::String(s)) if s == "LEFT" => Some(JoinType::Left),
            Some(Value::String(s)) if s == "INNER" => Some(JoinType::Inner),
            Some(Value::Null) => None,
            Some(other) => return Err(format!("not a join type: {}", other.to_java_json())),
        };
        out.push(StorageJoin {
            relation: opt_string(o.get("relation")),
            alias: opt_string(o.get("alias")),
            join_type,
        });
    }
    Ok(Some(out))
}

fn aggregations_from(v: &Value) -> Result<Option<Vec<Aggregation>>, String> {
    let Value::Array(a) = v else { return Ok(None) };
    let mut out = Vec::new();
    for e in a {
        let Value::Object(o) = e else { continue };
        let function = match o.get("function") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(
                AggregateFunction::from_name(s)
                    .ok_or_else(|| format!("'{s}' is not one of the AggregateFunction values"))?,
            ),
            Some(other) => return Err(format!("not a function: {}", other.to_java_json())),
        };
        out.push(Aggregation { function, field: opt_string(o.get("field")), alias: opt_string(o.get("alias")) });
    }
    Ok(Some(out))
}

fn group_by_from(o: &Document) -> Result<GroupByField, String> {
    let bucket = match o.get("bucket") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => {
            Some(DateBucketUnit::from_name(s).ok_or_else(|| format!("'{s}' is not a DateBucketUnit"))?)
        }
        Some(other) => return Err(format!("not a bucket: {}", other.to_java_json())),
    };
    let encoding = match o.get("encoding") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if s == "EPOCH_SECONDS" => Some(DateEncoding::EpochSeconds),
        Some(Value::String(s)) if s == "EPOCH_MILLIS" => Some(DateEncoding::EpochMillis),
        Some(other) => return Err(format!("not a DateEncoding: {}", other.to_java_json())),
    };
    Ok(GroupByField {
        field: opt_string(o.get("field")),
        alias: opt_string(o.get("alias")),
        bucket,
        encoding,
        timezone: opt_string(o.get("timezone")),
    })
}

fn sub_queries_from(v: &Value) -> Result<Option<Vec<StorageSubQuery>>, String> {
    let Value::Array(a) = v else { return Ok(None) };
    let mut out = Vec::new();
    for e in a {
        let Value::Object(o) = e else { continue };
        out.push(StorageSubQuery {
            storage: opt_string(o.get("storage")),
            relation: opt_string(o.get("relation")),
            alias: opt_string(o.get("alias")),
            condition: condition_opt(o.get("condition"))?,
            aggregations: match o.get("aggregations") {
                Some(a) => aggregations_from(a)?,
                None => None,
            },
            having: condition_opt(o.get("having"))?,
            required: match o.get("required") {
                None => Some(true),
                Some(v) => opt_bool(v),
            },
        });
    }
    Ok(Some(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_bean() {
        let q = Query::from_value(&Value::parse_json("{}").unwrap()).unwrap();
        assert_eq!(q.size, 10);
        assert_eq!(q.sort, Some(Sort::default_query_sort()));
        assert!(q.counts());
        let a = AggregateQuery::from_value(&Value::parse_json(r#"{"size":5000}"#).unwrap()).unwrap();
        assert_eq!(a.pageable().unwrap().size, 1000);
        assert!(a.pageable().unwrap().sort.is_unsorted());
    }

    #[test]
    fn sort_reads_one_order_or_many() {
        let s = Sort::from_value(&Value::parse_json(r#"{"property":"a"}"#).unwrap()).unwrap().unwrap();
        assert_eq!(s.orders[0].direction, Direction::Asc);
        let s = Sort::from_value(&Value::parse_json(r#"[{"property":"a","direction":"DESC"},{"property":"b"}]"#).unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(s.orders.len(), 2);
    }

    #[test]
    fn resolved_aliases() {
        assert_eq!(Aggregation::new(AggregateFunction::Sum, Some("a.b")).resolved_alias().unwrap(), "sum_a_b");
        assert_eq!(Aggregation::new(AggregateFunction::Count, None).resolved_alias().unwrap(), "count");
        assert_eq!(GroupByField::new("a.b").resolved_alias().unwrap(), "a_b");
    }
}
