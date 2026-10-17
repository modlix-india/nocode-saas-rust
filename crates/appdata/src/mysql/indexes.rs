//! `MySQLIndexes`: the indexes a storage's table should have, and the statements that
//! get it there. The declared set is authoritative, as on Mongo; the primary key and an
//! index backing a foreign key are never dropped.

use indexmap::{IndexMap, IndexSet};

use crate::field_names;
use crate::model::{Direction, RelationType, Storage, StorageIndex};

pub const RELATION_PREFIX: &str = "rel_";
pub const FULLTEXT_NAME: &str = "ft_all";
const MAX_NAME: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Index {
    pub name: String,
    pub columns: Vec<String>,
    /// One per column, or empty when every column is ascending (a FULLTEXT index).
    pub directions: Vec<Direction>,
    pub unique: bool,
    pub full_text: bool,
}

impl Index {
    pub fn ddl(&self, db: &str, table: &str) -> String {
        let mut sb = String::from("CREATE ");
        if self.full_text {
            sb.push_str("FULLTEXT ");
        } else if self.unique {
            sb.push_str("UNIQUE ");
        }
        sb.push_str(&format!("INDEX `{}` ON `{db}`.`{table}` (", self.name));
        for (i, c) in self.columns.iter().enumerate() {
            if i > 0 {
                sb.push_str(", ");
            }
            sb.push('`');
            sb.push_str(c);
            sb.push('`');
            if !self.full_text {
                if let Some(d) = self.directions.get(i) {
                    sb.push_str(if *d == Direction::Desc { " DESC" } else { " ASC" });
                }
            }
        }
        sb.push(')');
        sb
    }

    /// The same index whatever its name.
    pub fn same_as(&self, other: &Index) -> bool {
        self.columns == other.columns
            && self.unique == other.unique
            && self.full_text == other.full_text
            && self.directions == other.directions
    }
}

/// What the definition asks for, filtered to fields that exist.
pub fn desired(storage: &Storage, columns: &IndexSet<String>) -> Vec<Index> {
    let mut out = Vec::new();

    if let Some(indexes) = &storage.indexes {
        for (name, index) in indexes {
            if let Some(i) = declared(name, index, columns) {
                out.push(i);
            }
        }
    }

    if let Some(t) = full_text(storage.text_index_fields.as_ref(), columns) {
        out.push(t);
    }

    let rel = relation_indexes(storage, columns, &out);
    out.extend(rel);
    out
}

fn declared(name: &str, index: &StorageIndex, columns: &IndexSet<String>) -> Option<Index> {
    if index.fields.is_empty() {
        return None;
    }
    if !field_names::valid(name) || name.len() > MAX_NAME {
        return None;
    }
    let mut cols = Vec::new();
    let mut directions = Vec::new();
    for f in &index.fields {
        let column = field_names::column(f.field_name.as_deref()?);
        if !columns.contains(&column) {
            return None;
        }
        cols.push(column);
        directions.push(f.direction.unwrap_or(Direction::Asc));
    }
    Some(Index { name: name.to_string(), columns: cols, directions, unique: index.unique, full_text: false })
}

fn full_text(fields: Option<&Vec<String>>, columns: &IndexSet<String>) -> Option<Index> {
    let fields = fields.filter(|f| !f.is_empty())?;
    let cols: Vec<String> = fields.iter().map(|f| field_names::column(f)).filter(|c| columns.contains(c)).collect();
    if cols.is_empty() {
        return None;
    }
    Some(Index { name: FULLTEXT_NAME.into(), columns: cols, directions: Vec::new(), unique: false, full_text: true })
}

fn relation_indexes(storage: &Storage, columns: &IndexSet<String>, already: &[Index]) -> Vec<Index> {
    let mut out = Vec::new();
    let Some(relations) = &storage.relations else { return out };

    let mut covered: IndexSet<String> = already.iter().filter_map(|i| i.columns.first().cloned()).collect();

    for (field, relation) in relations {
        if relation.relation_type != Some(RelationType::ToOne) {
            continue;
        }
        if !columns.contains(field) || covered.contains(field) {
            continue;
        }
        if !field_names::valid(field) {
            continue;
        }
        out.push(Index {
            name: relation_index_name(field),
            columns: vec![field.clone()],
            directions: vec![Direction::Asc],
            unique: false,
            full_text: false,
        });
        covered.insert(field.clone());
    }
    out
}

pub fn relation_index_name(field: &str) -> String {
    let name = format!("{RELATION_PREFIX}{field}");
    if name.len() <= MAX_NAME {
        name
    } else {
        name[..MAX_NAME].to_string()
    }
}

/// The query that reads what MySQL reports, grouped by the caller into [`Index`]es.
pub fn existing_sql(db: &str, table: &str) -> String {
    format!(
        "SELECT INDEX_NAME, COLUMN_NAME, NON_UNIQUE, INDEX_TYPE, COLLATION, SEQ_IN_INDEX FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = '{db}' AND TABLE_NAME = '{table}' ORDER BY INDEX_NAME, SEQ_IN_INDEX"
    )
}

/// One row of [`existing_sql`]: name, column, non_unique, index_type, collation.
pub type StatisticsRow = (String, String, i64, String, Option<String>);

/// The rows grouped into indexes, as `MySQLIndexes.existing` groups them.
pub fn from_statistics(rows: Vec<StatisticsRow>) -> Vec<Index> {
    let mut grouped: IndexMap<String, Vec<StatisticsRow>> = IndexMap::new();
    for r in rows {
        grouped.entry(r.0.clone()).or_default().push(r);
    }
    grouped
        .into_iter()
        .map(|(name, parts)| {
            let mut cols = Vec::new();
            let mut directions = Vec::new();
            let mut unique = false;
            let mut full_text = false;
            for p in &parts {
                cols.push(p.1.clone());
                unique = p.2 == 0;
                full_text = p.3.eq_ignore_ascii_case("FULLTEXT");
                directions.push(if p.4.as_deref() == Some("D") { Direction::Desc } else { Direction::Asc });
            }
            Index { name, columns: cols, directions: if full_text { Vec::new() } else { directions }, unique, full_text }
        })
        .collect()
}

/// What turns `existing` into `desired`: drops first, then adds.
pub fn sync(db: &str, table: &str, existing: &[Index], desired: &[Index], foreign_key_columns: &IndexSet<String>) -> Vec<String> {
    let have: IndexMap<&str, &Index> = existing.iter().map(|i| (i.name.as_str(), i)).collect();
    let want: IndexMap<&str, &Index> = desired.iter().map(|i| (i.name.as_str(), i)).collect();

    let mut drops = Vec::new();
    let mut adds = Vec::new();

    for (name, index) in &have {
        if name.eq_ignore_ascii_case("PRIMARY") {
            continue;
        }
        if index.columns.first().is_some_and(|c| foreign_key_columns.contains(c)) {
            continue;
        }
        match want.get(name) {
            Some(target) if index.same_as(target) => {}
            _ => drops.push(format!("DROP INDEX `{name}` ON `{db}`.`{table}`")),
        }
    }

    for (name, index) in &want {
        match have.get(name) {
            Some(current) if current.same_as(index) => {}
            _ => adds.push(index.ddl(db, table)),
        }
    }

    drops.extend(adds);
    drops
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{StorageIndexField, StorageRelation};

    fn index(unique: bool, fields: &[&str]) -> StorageIndex {
        StorageIndex {
            unique,
            fields: fields
                .iter()
                .map(|f| StorageIndexField { field_name: Some(f.to_string()), direction: Some(Direction::Asc) })
                .collect(),
        }
    }

    fn storage(indexes: Vec<(&str, StorageIndex)>, text: Option<Vec<&str>>) -> Storage {
        Storage {
            name: "orders".into(),
            app_code: "testapp".into(),
            client_code: "SYSTEM".into(),
            version: 1,
            unique_name: "testapp_orders".into(),
            indexes: if indexes.is_empty() { None } else { Some(indexes.into_iter().map(|(k, v)| (k.to_string(), v)).collect()) },
            text_index_fields: text.map(|t| t.iter().map(|s| s.to_string()).collect()),
            ..Default::default()
        }
    }

    fn cols() -> IndexSet<String> {
        ["ref", "amount", "note", "customer"].iter().map(|s| s.to_string()).collect()
    }

    fn none() -> IndexSet<String> {
        IndexSet::new()
    }

    #[test]
    fn desired_indexes() {
        let out = desired(&storage(vec![("byRef", index(false, &["ref"]))], None), &cols());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "byRef");
        assert_eq!(out[0].columns, vec!["ref"]);
        assert!(!out[0].unique);

        let compound = StorageIndex {
            unique: false,
            fields: vec![
                StorageIndexField { field_name: Some("ref".into()), direction: Some(Direction::Asc) },
                StorageIndexField { field_name: Some("amount".into()), direction: Some(Direction::Desc) },
            ],
        };
        let out = desired(&storage(vec![("byRefAmount", compound)], None), &cols());
        assert_eq!(out[0].columns, vec!["ref", "amount"]);
        let ddl = out[0].ddl("db", "testapp_orders");
        assert!(ddl.contains("`ref` ASC") && ddl.contains("`amount` DESC"), "{ddl}");

        assert!(desired(&storage(vec![("bySku", index(true, &["ref"]))], None), &cols())[0].unique);

        let out = desired(&storage(vec![], Some(vec!["ref", "note"])), &cols());
        assert_eq!(out.len(), 1);
        assert!(out[0].full_text);
        assert_eq!(out[0].columns, vec!["ref", "note"]);
        assert!(out[0].ddl("db", "testapp_orders").contains("FULLTEXT"));

        assert!(desired(&storage(vec![("byGhost", index(false, &["nosuchfield"]))], None), &cols()).is_empty());

        let mut s = storage(vec![], None);
        let mut rel = IndexMap::new();
        rel.insert("customer".to_string(), StorageRelation::to_one("customers"));
        rel.insert("labels".to_string(), StorageRelation::to_many("tags"));
        s.relations = Some(rel);
        let c: IndexSet<String> = ["ref", "customer", "labels"].iter().map(|s| s.to_string()).collect();
        let names: Vec<String> = desired(&s, &c).into_iter().map(|i| i.name).collect();
        assert_eq!(names.len(), 1);
        assert!(names[0].contains("customer"));
    }

    #[test]
    fn statements() {
        let want = desired(&storage(vec![("byRef", index(false, &["ref"]))], None), &cols());
        assert!(sync("db", "testapp_orders", &want, &want, &none()).is_empty());
        let sql = sync("db", "testapp_orders", &want, &[], &none());
        assert_eq!(sql.len(), 1);
        assert!(sql[0].starts_with("DROP INDEX"));
        let uniq = desired(&storage(vec![("byRef", index(true, &["ref"]))], None), &cols());
        let sql = sync("db", "testapp_orders", &want, &uniq, &none());
        assert_eq!(sql.len(), 2);
        assert!(sql[0].starts_with("DROP INDEX") && sql[1].contains("UNIQUE"));
        let primary = Index { name: "PRIMARY".into(), columns: vec!["_id".into()], directions: vec![], unique: true, full_text: false };
        assert!(sync("db", "testapp_orders", &[primary], &[], &none()).is_empty());
        let backing = Index {
            name: "fk_testapp_orders_customer".into(),
            columns: vec!["customer".into()],
            directions: vec![],
            unique: false,
            full_text: false,
        };
        let fk: IndexSet<String> = ["customer".to_string()].into_iter().collect();
        assert!(sync("db", "testapp_orders", &[backing], &[], &fk).is_empty());
    }
}
