//! `MySQLSubQueryPlanner` and `SubQueryTable`: a grouped read of a storage's children,
//! as a derived table with one row per parent.

use indexmap::{IndexMap, IndexSet};

use super::aggregate_builder;
use super::field_resolver::FieldResolver;
use super::filter_builder::FilterResult;
use super::sql::{quote, Cond, FieldOps, Select, Sql};
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
    /// The same measures as one correlated subquery each, or None when a HAVING makes
    /// that a different answer.
    pub correlated: Option<Correlated>,
}

/// The pieces of the grouped read, kept apart so each measure can be read per parent row.
#[derive(Debug, Clone, PartialEq)]
pub struct Correlated {
    /// The child table under the subquery's own alias.
    pub from: Sql,
    /// The relation column, qualified by that alias.
    pub key: Sql,
    pub where_: Option<Cond>,
    pub measures: Vec<(String, Sql)>,
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

    /// Whether `sql` reads one of this subquery's measures.
    pub fn referenced_by(&self, sql: &Sql) -> bool {
        sql.render().0.contains(&format!("{}.", quote(&self.alias)))
    }

    /// A LEFT subquery has one row per parent at most, so leaving it out changes no count.
    pub fn countless(&self, condition: &Sql) -> bool {
        !self.required && !self.referenced_by(condition)
    }

    /// A LEFT subquery that neither filters nor sorts can be read for the page's rows
    /// alone, instead of grouping every child row before the page is cut.
    pub fn per_row(&self, condition: &Sql, order: &[Sql]) -> bool {
        self.countless(condition) && self.correlated.is_some() && !order.iter().any(|o| self.referenced_by(o))
    }

    /// Each measure as `(select <measure> from <child> where <key> = <parent> ...) as alias.measure`.
    /// `having count(*) > 0` keeps "no children" a null, as the LEFT join gives it, also for a count.
    pub fn per_row_selection(&self, parent_alias: &str) -> Vec<Sql> {
        let Some(c) = &self.correlated else { return Vec::new() };
        let link = c.key.equal(Sql::name(&[parent_alias, &self.parent_field]));
        let filter = match &c.where_ {
            None => link,
            Some(w) => w.clone().and_also(link),
        };
        c.measures
            .iter()
            .map(|(name, measure)| {
                Sql::raw("(")
                    .then_sql(&Select::fields(vec![measure.clone()], c.from.clone()).filter(filter.clone()).to_sql())
                    .then(" having count(*) > 0)")
                    .alias(&self.output_key(name))
            })
            .collect()
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

/// The grouped child query, keyed on the relation column, its HAVING inside, and the same
/// read split for per-row use (None with a HAVING).
pub fn derived(
    child_table: &Sql,
    sq: &StorageSubQuery,
    relation_column: &str,
    where_: Option<Cond>,
    having: Option<Cond>,
    child_json_columns: IndexSet<String>,
) -> FilterResult<(Sql, Option<Correlated>)> {
    let resolver = FieldResolver::of(child_json_columns);
    let key = Sql::name(&[relation_column]);
    let alias = sq.resolved_alias().unwrap_or_default();

    let mut measures = Vec::new();
    match sq.aggregations.as_ref().filter(|a| !a.is_empty()) {
        None => measures.push((DEFAULT_MEASURE.to_string(), Sql::raw("count(*)"))),
        Some(aggs) => {
            for a in aggs {
                measures.push((a.resolved_alias().unwrap_or_default(), aggregate_builder::measure(a, &resolver)?));
            }
        }
    }

    let correlated = having.is_none().then(|| Correlated {
        from: child_table.clone().then(" as ").then(&quote(&alias)),
        key: Sql::name(&[&alias, relation_column]),
        where_: where_.clone(),
        measures: measures.clone(),
    });

    let mut select = vec![key.alias(KEY)];
    select.extend(measures.iter().map(|(name, m)| m.alias(name)));

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

    Ok((grouped.as_table(&alias), correlated))
}

/// Hang the derived tables off the parent.
pub fn attach<'a>(from: Sql, parent_alias: &str, sub_queries: impl IntoIterator<Item = &'a SubQueryTable>) -> Sql {
    let mut table = from;
    for sq in sub_queries {
        let kind = if sq.required { " join " } else { " left outer join " };
        table = table.then(kind).then_sql(&sq.derived).then(" on ").then_sql(&sq.on(parent_alias));
    }
    table
}

/// Every measure, prefixed.
pub fn selection<'a>(sub_queries: impl IntoIterator<Item = &'a SubQueryTable>) -> Vec<Sql> {
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
