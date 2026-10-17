//! `MySQLJoinPlanner` and `JoinedTable`: a join list checked, and the SQL around it.

use indexmap::{IndexMap, IndexSet};

use crate::aggregate_validator::alias_ok;
use super::column_names;
use super::sql::{quote, FieldOps, Sql};
use super::subquery_planner::SubQueryTable;
use crate::model::{JoinType, RelationType, Storage, StorageJoin};
use crate::value::{Document, Value};

/// The parent's table alias once there is anything to tell it apart from.
pub const PARENT: &str = "p";

/// At most this many joins in one query.
pub const MAX_JOINS: usize = 5;

/// One relation resolved into something SQL can use, for one tenant.
#[derive(Debug, Clone, PartialEq)]
pub struct JoinedTable {
    pub alias: String,
    /// The target table, qualified with the tenant database.
    pub table: Sql,
    pub parent_field: String,
    pub target_field: String,
    pub join_type: JoinType,
    /// The target's columns and their MySQL types.
    pub column_types: IndexMap<String, String>,
    pub json_columns: IndexSet<String>,
    pub date_columns: IndexSet<String>,
    /// Column to field, for the target's columns whose names differ from their field.
    pub field_names: IndexMap<String, String>,
    pub boolean_columns: IndexSet<String>,
}

impl JoinedTable {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        alias: &str,
        table: Sql,
        parent_field: &str,
        target_field: &str,
        join_type: JoinType,
        column_types: IndexMap<String, String>,
        json_columns: IndexSet<String>,
        date_columns: IndexSet<String>,
    ) -> JoinedTable {
        JoinedTable {
            alias: alias.to_string(),
            table,
            parent_field: parent_field.to_string(),
            target_field: target_field.to_string(),
            join_type,
            column_types,
            json_columns,
            date_columns,
            field_names: IndexMap::new(),
            boolean_columns: IndexSet::new(),
        }
    }

    pub fn columns(&self) -> impl Iterator<Item = &String> {
        self.column_types.keys()
    }

    /// The equality that defines the join.
    pub fn on(&self, parent_alias: &str) -> Sql {
        let c = Sql::name(&[parent_alias, &self.parent_field]).equal(Sql::name(&[&self.alias, &self.target_field]));
        c.to_sql()
    }

    /// Takes a field or a column; a field is read through its column.
    pub fn column(&self, name: &str) -> Sql {
        Sql::name(&[&self.alias, &column_names::column(name)])
    }

    /// The prefix joined columns come back under, because both sides have an `_id`.
    pub fn output_key(&self, column: &str) -> String {
        format!("{}.{}", self.alias, column)
    }
}

/// Why this join list cannot be used, or None.
pub fn check(
    storage: &Storage,
    joins: Option<&Vec<StorageJoin>>,
    parent_columns: &IndexSet<String>,
    parent_json_columns: &IndexSet<String>,
) -> Option<String> {
    let joins = joins.filter(|j| !j.is_empty())?;

    if joins.len() > MAX_JOINS {
        return Some(format!("a query may join at most {MAX_JOINS} relations"));
    }

    let empty = IndexMap::new();
    let relations = storage.relations.as_ref().unwrap_or(&empty);
    let mut aliases = IndexSet::new();

    for join in joins {
        let Some(relation_name) = join.relation.as_ref().filter(|r| !r.trim().is_empty()) else {
            return Some("a join names no relation".into());
        };

        let Some(relation) = relations.get(relation_name) else {
            return Some(format!("storage {} has no relation '{}'", storage.name, relation_name));
        };

        if relation.relation_type != Some(RelationType::ToOne) {
            return Some(format!(
                "relation '{}' is {}. A to-many relation stores a list of ids in one column, so joining through it cannot use an index and would scan the parent for every row. Read it eagerly instead, or model it as its own storage.",
                relation_name,
                relation.relation_type.map(|t| t.name()).unwrap_or("null")
            ));
        }

        let alias = join.resolved_alias();
        let Some(alias) = alias.filter(|a| alias_ok(a)) else {
            return Some(format!(
                "join alias '{}' must match [A-Za-z_][A-Za-z0-9_]*",
                join.resolved_alias().unwrap_or_else(|| "null".into())
            ));
        };

        if !aliases.insert(alias.clone()) {
            return Some(format!("duplicate join alias '{alias}'"));
        }

        if parent_json_columns.contains(&alias) {
            return Some(format!(
                "join alias '{alias}' is a JSON column of {}; a path into it would be spelled the same way",
                storage.name
            ));
        }

        if &alias != relation_name && parent_columns.contains(&alias) {
            return Some(format!(
                "join alias '{alias}' is also a column of {}; give the join a different alias",
                storage.name
            ));
        }
    }

    None
}

/// The FROM clause: the parent aliased, each join hung off it.
pub fn from(parent: &Sql, joins: &[JoinedTable]) -> Sql {
    let mut table = parent.clone().then(" as ").then(&quote(PARENT));
    for join in joins {
        let kind = if join.join_type == JoinType::Inner { " join " } else { " left outer join " };
        table = table
            .then(kind)
            .then_sql(&join.table)
            .then(" as ")
            .then(&quote(&join.alias))
            .then(" on ")
            .then_sql(&join.on(PARENT));
    }
    table
}

/// Every column the caller gets back, the joined ones prefixed.
pub fn selection(parent_columns: &IndexSet<String>, joins: &[JoinedTable]) -> Vec<Sql> {
    let mut fields: Vec<Sql> = parent_columns.iter().map(|c| Sql::name(&[PARENT, c])).collect();
    for join in joins {
        for c in join.columns() {
            fields.push(join.column(c).alias(&join.output_key(c)));
        }
    }
    fields
}

/// Fold the prefixed columns back into an object per join (dropped when the LEFT join
/// matched nothing) and per subquery (kept, a null count meaning "none").
pub fn nest(flat: Document, joins: &[JoinedTable], sub_queries: &[SubQueryTable]) -> Document {
    if joins.is_empty() && sub_queries.is_empty() {
        return flat;
    }

    let mut out = Document::new();
    let mut nested: IndexMap<String, Document> = IndexMap::new();

    for (k, v) in flat {
        match k.find('.').filter(|d| *d > 0) {
            None => {
                out.insert(k, v);
            }
            Some(dot) => {
                nested.entry(k[..dot].to_string()).or_default().insert(k[dot + 1..].to_string(), v);
            }
        }
    }

    for join in joins {
        let Some(side) = nested.get(&join.alias) else { continue };
        let matched = side.values().any(|v| !v.is_null());
        if matched {
            out.insert(join.alias.clone(), Value::Object(column_names::to_fields(side.clone(), &join.field_names)));
        } else {
            out.shift_remove(&join.alias);
        }
    }

    for sq in sub_queries {
        let Some(side) = nested.get(&sq.alias) else { continue };
        out.insert(sq.alias.clone(), Value::Object(side.clone()));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{StorageRelation, StorageJoin};

    fn storage_with(relations: Vec<(&str, StorageRelation)>) -> Storage {
        Storage {
            name: "orders".into(),
            relations: Some(relations.into_iter().map(|(k, v)| (k.to_string(), v)).collect()),
            ..Default::default()
        }
    }

    fn to_one(t: &str) -> StorageRelation {
        StorageRelation::to_one(t).with_field_name("_id")
    }

    fn parent_columns() -> IndexSet<String> {
        ["_id", "amount", "customer"].iter().map(|s| s.to_string()).collect()
    }

    fn join(relation: &str, alias: Option<&str>) -> StorageJoin {
        StorageJoin { relation: Some(relation.into()), alias: alias.map(str::to_string), join_type: Some(JoinType::Left) }
    }

    fn joined(alias: &str, t: JoinType, columns: &[&str]) -> JoinedTable {
        let mut types = IndexMap::new();
        types.insert("_id".to_string(), "CHAR(26)".to_string());
        for c in columns {
            types.insert(c.to_string(), "VARCHAR(40)".to_string());
        }
        JoinedTable::new(alias, Sql::name(&["CL_app", "customers"]), "customer", "_id", t, types, IndexSet::new(), IndexSet::new())
    }

    fn none() -> IndexSet<String> {
        IndexSet::new()
    }

    #[test]
    fn validation() {
        assert!(check(&storage_with(vec![]), None, &parent_columns(), &none()).is_none());
        assert!(check(&storage_with(vec![]), Some(&vec![]), &parent_columns(), &none()).is_none());
        let s = storage_with(vec![("customer", to_one("customers"))]);
        assert!(check(&s, Some(&vec![join("customer", None)]), &parent_columns(), &none()).is_none());
        let err = check(&s, Some(&vec![join("supplier", None)]), &parent_columns(), &none()).unwrap();
        assert!(err.contains("no relation 'supplier'"), "{err}");
        let m = storage_with(vec![("tags", StorageRelation::to_many("tagList").with_field_name("_id"))]);
        let err = check(&m, Some(&vec![join("tags", None)]), &parent_columns(), &none()).unwrap();
        assert!(err.contains("cannot use an index"), "{err}");
        for alias in ["has space", "has-dash", "1leading", "has$dollar"] {
            assert!(check(&s, Some(&vec![join("customer", Some(alias))]), &parent_columns(), &none()).is_some(), "{alias}");
        }
        let two = storage_with(vec![("customer", to_one("customers")), ("payer", to_one("customers"))]);
        let err = check(&two, Some(&vec![join("customer", Some("c")), join("payer", Some("c"))]), &parent_columns(), &none()).unwrap();
        assert!(err.contains("duplicate join alias"), "{err}");
        let err = check(&s, Some(&vec![join("customer", Some("amount"))]), &parent_columns(), &none()).unwrap();
        assert!(err.contains("is also a column"), "{err}");
        let mut cols = parent_columns();
        cols.insert("address".into());
        let json: IndexSet<String> = ["address".to_string()].into_iter().collect();
        let err = check(&s, Some(&vec![join("customer", Some("address"))]), &cols, &json).unwrap();
        assert!(err.contains("JSON column"), "{err}");
        assert!(check(&s, Some(&vec![join("customer", Some("a")), join("customer", Some("b"))]), &parent_columns(), &none()).is_none());
        let mut many = Vec::new();
        let mut rels = Vec::new();
        for i in 0..=MAX_JOINS {
            rels.push((format!("r{i}"), to_one("customers")));
            many.push(join(&format!("r{i}"), Some(&format!("a{i}"))));
        }
        let st = Storage { name: "orders".into(), relations: Some(rels.into_iter().collect()), ..Default::default() };
        assert!(check(&st, Some(&many), &parent_columns(), &none()).is_some());
        assert_eq!(join("customer", None).resolved_alias().unwrap(), "customer");
        assert_eq!(join("customer", Some("c")).resolved_alias().unwrap(), "c");
    }

    fn from_sql(joins: &[JoinedTable]) -> String {
        format!("select * from {}", from(&Sql::name(&["CL_app", "orders"]), joins).inlined())
    }

    #[test]
    fn generated_sql() {
        let s = from_sql(&[joined("c", JoinType::Left, &["region"])]);
        assert!(s.contains("left outer join"), "{s}");
        assert!(s.contains("`CL_app`.`customers` as `c`"), "{s}");
        assert!(s.contains("`p`.`customer` = `c`.`_id`"), "{s}");
        assert!(s.contains("as `p`"));
        let s = from_sql(&[joined("c", JoinType::Inner, &["region"])]);
        assert!(s.contains("join `CL_app`.`customers` as `c`") && !s.contains("left outer join"), "{s}");
        let s = from_sql(&[joined("a", JoinType::Left, &["x"]), joined("b", JoinType::Inner, &["y"])]);
        assert!(s.contains("as `a`") && s.contains("as `b`"), "{s}");
        let cols: IndexSet<String> = ["_id", "amount"].iter().map(|s| s.to_string()).collect();
        let fields = selection(&cols, &[joined("c", JoinType::Left, &["region"])]);
        let s = Sql::join(&fields, ", ").inlined();
        assert!(s.contains("`p`.`_id`") && s.contains("`c`.`_id` as `c._id`") && s.contains("`c`.`region` as `c.region`"), "{s}");
    }

    #[test]
    fn nesting() {
        let mut flat = Document::new();
        flat.insert("_id".into(), Value::from("1"));
        flat.insert("amount".into(), Value::Int(10));
        flat.insert("c._id".into(), Value::from("9"));
        flat.insert("c.region".into(), Value::from("north"));
        flat.insert("c".into(), Value::from("9"));
        let out = nest(flat, &[joined("c", JoinType::Left, &["region"])], &[]);
        assert_eq!(out["_id"], Value::from("1"));
        assert_eq!(out["c"].as_object().unwrap()["region"], Value::from("north"));

        let mut flat = Document::new();
        flat.insert("_id".into(), Value::from("1"));
        flat.insert("c._id".into(), Value::Null);
        flat.insert("c.region".into(), Value::Null);
        flat.insert("c".into(), Value::from("9"));
        let out = nest(flat, &[joined("c", JoinType::Left, &["region"])], &[]);
        assert!(!out.contains_key("c"));

        let mut flat = Document::new();
        flat.insert("_id".into(), Value::from("1"));
        assert_eq!(nest(flat.clone(), &[], &[]), flat);

        let mut j = joined("pay", JoinType::Left, &[]);
        j.column_types.insert("IFSC_Code".into(), "VARCHAR(20)".into());
        j.field_names.insert("IFSC_Code".into(), "IFSC Code".into());
        let mut flat = Document::new();
        flat.insert("_id".into(), Value::from("parent"));
        flat.insert("pay._id".into(), Value::from("child"));
        flat.insert("pay.IFSC_Code".into(), Value::from("HDFC0000001"));
        let out = nest(flat, &[j.clone()], &[]);
        assert_eq!(out["pay"].as_object().unwrap()["IFSC Code"], Value::from("HDFC0000001"));
        assert_eq!(format!("select {}", j.column("IFSC Code").inlined()), "select `pay`.`IFSC_Code`");
    }
}
