//! `MySQLFieldResolver`: a field name in a query turned into the SQL that reads it.
//!
//! `amount` is a parent column, `address.city` a path into a JSON column, `customer.region`
//! a column on a joined table and `orders.count` a measure from a subquery. Decided by
//! precedence; aliases are refused at validation when they collide with a column, so a
//! head can never be two things.

use indexmap::{IndexMap, IndexSet};

use super::column_names;
use super::filter_builder::{json_path, FilterError};
use super::join_planner::JoinedTable;
use super::sql::Sql;
use super::subquery_planner::SubQueryTable;

#[derive(Debug, Clone, Default)]
pub struct FieldResolver {
    parent_alias: Option<String>,
    json_columns: IndexSet<String>,
    joins: IndexMap<String, JoinedTable>,
    sub_queries: IndexMap<String, SubQueryTable>,
    text_columns: IndexSet<String>,
    stemming: bool,
}

impl FieldResolver {
    /// No joins, so no table qualifier: the SQL is what it always was.
    pub fn of(json_columns: IndexSet<String>) -> FieldResolver {
        FieldResolver { json_columns, stemming: true, ..Default::default() }
    }

    pub fn joined(
        parent_alias: &str,
        json_columns: IndexSet<String>,
        joins: IndexMap<String, JoinedTable>,
        sub_queries: IndexMap<String, SubQueryTable>,
    ) -> FieldResolver {
        FieldResolver {
            parent_alias: Some(parent_alias.to_string()),
            json_columns,
            joins,
            sub_queries,
            text_columns: IndexSet::new(),
            stemming: true,
        }
    }

    pub fn with_text_columns(mut self, text_columns: IndexSet<String>) -> FieldResolver {
        self.text_columns = text_columns;
        self
    }

    pub fn with_stemming(mut self, stemming: bool) -> FieldResolver {
        self.stemming = stemming;
        self
    }

    pub fn text_columns(&self) -> &IndexSet<String> {
        &self.text_columns
    }

    pub fn stemming(&self) -> bool {
        self.stemming
    }

    pub fn is_json_column(&self, column: &str) -> bool {
        self.json_columns.contains(&column_names::column(column))
    }

    pub fn qualified(&self, column: &str) -> Sql {
        match &self.parent_alias {
            None => Sql::name(&[column]),
            Some(p) => Sql::name(&[p, column]),
        }
    }

    pub fn has_joins(&self) -> bool {
        !self.joins.is_empty() || !self.sub_queries.is_empty()
    }

    pub fn joins(&self) -> &IndexMap<String, JoinedTable> {
        &self.joins
    }

    pub fn resolve(&self, name: &str) -> Result<Sql, FilterError> {
        let Some(dot) = name.find('.').filter(|d| *d > 0 && *d != name.len() - 1) else {
            return Ok(self.parent_column(name));
        };

        let head = &name[..dot];
        let tail = &name[dot + 1..];

        if let Some(join) = self.joins.get(head) {
            return self.joined_field(join, tail);
        }

        if let Some(sub) = self.sub_queries.get(head) {
            return Ok(sub.measure(tail));
        }

        if self.is_json_column(head) {
            return json_path(&self.parent_column(head), name, tail);
        }

        Ok(self.parent_column(name))
    }

    fn joined_field(&self, join: &JoinedTable, tail: &str) -> Result<Sql, FilterError> {
        let Some(dot) = tail.find('.').filter(|d| *d > 0 && *d != tail.len() - 1) else {
            return Ok(join.column(tail));
        };
        let column = &tail[..dot];
        if join.json_columns.contains(&column_names::column(column)) {
            return json_path(&join.column(column), tail, &tail[dot + 1..]);
        }
        Ok(join.column(tail))
    }

    fn parent_column(&self, name: &str) -> Sql {
        let column = column_names::column(name);
        self.qualified(&column)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::JoinType;
    use crate::mysql::join_planner::PARENT;

    fn customers() -> JoinedTable {
        let mut types = IndexMap::new();
        types.insert("_id".to_string(), "CHAR(26)".to_string());
        types.insert("region".to_string(), "VARCHAR(20)".to_string());
        types.insert("profile".to_string(), "JSON".to_string());
        JoinedTable::new(
            "customer",
            Sql::name(&["CL_app", "customers"]),
            "customer",
            "_id",
            JoinType::Left,
            types,
            ["profile".to_string()].into_iter().collect(),
            IndexSet::new(),
        )
    }

    fn joined() -> FieldResolver {
        let mut joins = IndexMap::new();
        joins.insert("customer".to_string(), customers());
        FieldResolver::joined(PARENT, ["address".to_string()].into_iter().collect(), joins, IndexMap::new())
    }

    fn sql(r: &FieldResolver, name: &str) -> String {
        format!("select {}", r.resolve(name).unwrap().inlined())
    }

    #[test]
    fn qualification() {
        let r = FieldResolver::of(["address".to_string()].into_iter().collect());
        assert_eq!(sql(&r, "amount"), "select `amount`");
        assert!(sql(&joined(), "amount").contains("`p`.`amount`"));
        assert!(sql(&joined(), "_id").contains("`p`.`_id`"));
    }

    #[test]
    fn precedence() {
        let s = sql(&joined(), "customer.region");
        assert!(s.contains("`customer`.`region`") && !s.contains("json_extract"), "{s}");
        let s = sql(&joined(), "address.city");
        assert!(s.contains("json_extract") && s.contains("`p`.`address`") && s.contains("$.city"), "{s}");
        let s = sql(&joined(), "customer.profile.tier");
        assert!(s.contains("json_extract") && s.contains("`customer`.`profile`") && s.contains("$.tier"), "{s}");
        assert!(sql(&joined(), "customer.odd.name").contains("`customer`.`odd.name`"));
        assert!(sql(&joined(), "some.thing").contains("`p`.`some.thing`"));
        assert!(sql(&joined(), "customer.").contains("`p`.`customer.`"));
        assert!(sql(&joined(), "customer").contains("`p`.`customer`"));
    }

    #[test]
    fn junk_paths_are_refused() {
        assert!(joined().resolve("address.c'ty").is_err());
        assert!(joined().resolve("customer.profile.t'er").is_err());
        assert!(!FieldResolver::of(IndexSet::new()).has_joins());
        assert!(joined().has_joins());
    }

    #[test]
    fn field_names_read_columns() {
        let r = FieldResolver::of(["Bank_Details".to_string()].into_iter().collect());
        assert_eq!(sql(&r, "IFSC Code"), "select `IFSC_Code`");
        assert!(sql(&r, "Bank Details.city").contains("`Bank_Details`"));
    }
}
