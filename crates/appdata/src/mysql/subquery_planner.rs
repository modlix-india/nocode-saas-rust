//! `MySQLSubQueryPlanner` and `SubQueryTable`: a grouped read of a storage's children,
//! as a derived table with one row per parent.

use indexmap::{IndexMap, IndexSet};

use super::aggregate_builder;
use super::field_resolver::FieldResolver;
use super::filter_builder::FilterResult;
use super::sql::{Cond, FieldOps, Select, Sql};
use crate::aggregate_validator::{alias_ok, ALIAS_PATTERN};
use crate::model::{AggregateFunction, Condition, RelationType, Storage, StorageSubQuery};

pub const DEFAULT_MEASURE: &str = "count";
pub const KEY: &str = "__parent";
pub const MAX_SUBQUERIES: usize = 3;

#[derive(Debug, Clone, PartialEq)]
pub struct SubQueryTable {
    pub alias: String,
    /// The grouped SELECT, already aliased.
    pub derived: Sql,
    pub key_column: String,
    pub parent_field: String,
    pub measures: IndexSet<String>,
    /// INNER, so a parent with no children drops.
    pub required: bool,
}

impl SubQueryTable {
    pub fn on(&self, parent_alias: &str) -> Sql {
        Sql::name(&[parent_alias, &self.parent_field]).equal(Sql::name(&[&self.alias, &self.key_column])).to_sql()
    }

    pub fn measure(&self, name: &str) -> Sql {
        Sql::name(&[&self.alias, name])
    }

    pub fn output_key(&self, measure: &str) -> String {
        format!("{}.{}", self.alias, measure)
    }
}

/// Why this subquery list cannot be used, or None. `children` is the resolved child
/// storage for each entry, in order.
pub fn check(
    parent: &Storage,
    sub_queries: Option<&Vec<StorageSubQuery>>,
    children: &[Option<Storage>],
    taken_aliases: &IndexSet<String>,
    parent_columns: &IndexSet<String>,
) -> Option<String> {
    let sub_queries = sub_queries.filter(|s| !s.is_empty())?;

    if sub_queries.len() > MAX_SUBQUERIES {
        return Some(format!("a query may carry at most {MAX_SUBQUERIES} subqueries"));
    }

    let mut aliases = taken_aliases.clone();

    for (i, sq) in sub_queries.iter().enumerate() {
        let Some(storage) = sq.storage.as_ref().filter(|s| !s.trim().is_empty()) else {
            return Some("a subquery names no storage".into());
        };
        let Some(relation_name) = sq.relation.as_ref().filter(|r| !r.trim().is_empty()) else {
            return Some(format!("subquery on '{storage}' names no relation back to {}", parent.name));
        };

        let Some(child) = children.get(i).and_then(|c| c.as_ref()) else {
            return Some(format!("subquery storage '{storage}' does not resolve for this client"));
        };

        let Some(relation) = child.relation(relation_name) else {
            return Some(format!("storage '{storage}' has no relation '{relation_name}'"));
        };

        if relation.storage_name.as_deref() != Some(parent.name.as_str()) {
            return Some(format!(
                "relation '{relation_name}' on '{storage}' points at '{}', not at {}",
                relation.storage_name.clone().unwrap_or_else(|| "null".into()),
                parent.name
            ));
        }

        if relation.relation_type != Some(RelationType::ToOne) {
            return Some(format!(
                "relation '{relation_name}' on '{storage}' is {}; the child must hold a single id for its parent, which is what a to-one is",
                relation.relation_type.map(|t| t.name()).unwrap_or("null")
            ));
        }

        if matches!(sq.having, Some(Condition::Having(_))) {
            return Some("a subquery's having must be a plain condition over its measure aliases".into());
        }

        let alias = sq.resolved_alias();
        let Some(alias) = alias.filter(|a| alias_ok(a)) else {
            return Some(format!(
                "subquery alias '{}' must match {ALIAS_PATTERN}",
                sq.resolved_alias().unwrap_or_else(|| "null".into())
            ));
        };

        if !aliases.insert(alias.clone()) {
            return Some(format!("duplicate alias '{alias}'"));
        }

        if parent_columns.contains(&alias) {
            return Some(format!("subquery alias '{alias}' is also a column of {}", parent.name));
        }

        if let Some(err) = check_measures(sq, &alias) {
            return Some(err);
        }
    }

    None
}

fn check_measures(sq: &StorageSubQuery, alias: &str) -> Option<String> {
    let aggs = sq.aggregations.as_ref().filter(|a| !a.is_empty())?;
    let mut measures = IndexSet::new();

    for a in aggs {
        let Some(f) = a.function else {
            return Some(format!("a measure of subquery '{alias}' has no function"));
        };
        if f != AggregateFunction::Count && a.field.as_ref().is_none_or(|x| x.trim().is_empty()) {
            return Some(format!("{f} in subquery '{alias}' needs a field"));
        }
        if let Some(field) = a.field.as_ref().filter(|x| x.contains('$')) {
            return Some(format!("field '{field}' may not contain '$'"));
        }
        let name = a.resolved_alias();
        let Some(name) = name.filter(|n| alias_ok(n)) else {
            return Some(format!(
                "measure alias '{}' must match {ALIAS_PATTERN}",
                a.resolved_alias().unwrap_or_else(|| "null".into())
            ));
        };
        if !measures.insert(name.clone()) {
            return Some(format!("duplicate measure '{name}' in subquery '{alias}'"));
        }
    }

    None
}

/// The measures this subquery exposes.
pub fn measures(sq: &StorageSubQuery) -> IndexSet<String> {
    let mut out = IndexSet::new();
    match sq.aggregations.as_ref().filter(|a| !a.is_empty()) {
        None => {
            out.insert(DEFAULT_MEASURE.to_string());
        }
        Some(aggs) => {
            for a in aggs {
                if let Some(alias) = a.resolved_alias() {
                    out.insert(alias);
                }
            }
        }
    }
    out
}

/// The grouped child query, keyed on the relation column, its HAVING inside.
pub fn derived(
    child_table: &Sql,
    sq: &StorageSubQuery,
    relation_column: &str,
    where_: Option<Cond>,
    having: Option<Cond>,
    child_json_columns: IndexSet<String>,
) -> FilterResult<Sql> {
    let resolver = FieldResolver::of(child_json_columns);
    let key = Sql::name(&[relation_column]);

    let mut select = vec![key.alias(KEY)];
    match sq.aggregations.as_ref().filter(|a| !a.is_empty()) {
        None => select.push(Sql::raw("count(*)").alias(DEFAULT_MEASURE)),
        Some(aggs) => {
            for a in aggs {
                select.push(aggregate_builder::measure(a, &resolver)?.alias(&a.resolved_alias().unwrap_or_default()));
            }
        }
    }

    let filter = match where_ {
        None => key.is_not_null(),
        Some(w) => w.and_also(key.is_not_null()),
    };

    let grouped = Select {
        fields: select,
        from: child_table.clone(),
        where_: Some(filter),
        group_by: vec![key],
        having,
        ..Default::default()
    };

    Ok(grouped.as_table(&sq.resolved_alias().unwrap_or_default()))
}

/// Hang the derived tables off the parent.
pub fn attach(from: Sql, parent_alias: &str, sub_queries: &[SubQueryTable]) -> Sql {
    let mut table = from;
    for sq in sub_queries {
        let kind = if sq.required { " join " } else { " left outer join " };
        table = table.then(kind).then_sql(&sq.derived).then(" on ").then_sql(&sq.on(parent_alias));
    }
    table
}

/// Every measure, prefixed.
pub fn selection(sub_queries: &[SubQueryTable]) -> Vec<Sql> {
    let mut fields = Vec::new();
    for sq in sub_queries {
        for m in &sq.measures {
            fields.push(sq.measure(m).alias(&sq.output_key(m)));
        }
    }
    fields
}

pub fn by_alias(sub_queries: &[SubQueryTable]) -> IndexMap<String, SubQueryTable> {
    sub_queries.iter().map(|s| (s.alias.clone(), s.clone())).collect()
}
