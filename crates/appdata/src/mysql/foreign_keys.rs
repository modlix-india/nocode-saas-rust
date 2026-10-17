//! `MySQLForeignKeys`: real foreign keys for the relations MySQL can enforce. TO_MANY (a
//! JSON array), a relation to anything but `_id`, and NOTHING never become one, and a
//! CASCADE stays in the service when the child owes triggers, events or history on delete.

use indexmap::IndexMap;

use super::type_mapper::ID_COLUMN;
use crate::model::{RelationConstraint, RelationType, Storage, StorageRelation};

const MAX_NAME: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForeignKey {
    pub name: String,
    pub column: String,
    pub target_table: String,
    pub on_delete: String,
    pub on_update: String,
}

impl ForeignKey {
    pub fn add_clause(&self) -> String {
        format!(
            "ADD CONSTRAINT `{}` FOREIGN KEY (`{}`) REFERENCES `{}` (`{ID_COLUMN}`) ON DELETE {} ON UPDATE {}",
            self.name, self.column, self.target_table, self.on_delete, self.on_update
        )
    }

    pub fn same_as(&self, other: &ForeignKey) -> bool {
        self.column == other.column
            && self.target_table.eq_ignore_ascii_case(&other.target_table)
            && self.on_delete.eq_ignore_ascii_case(&other.on_delete)
            && self.on_update.eq_ignore_ascii_case(&other.on_update)
    }
}

/// Whether the database can enforce this relation at all.
pub fn enforceable(relation: Option<&StorageRelation>) -> bool {
    let Some(r) = relation else { return false };
    if r.relation_type != Some(RelationType::ToOne) {
        return false;
    }
    if let Some(f) = r.field_name.as_ref().filter(|f| !f.trim().is_empty()) {
        if f != ID_COLUMN {
            return false;
        }
    }
    action(r.delete_constraint).is_some()
}

/// The same, with what a cascade can take away: rows deleted inside MySQL get no trigger,
/// event or version row.
pub fn enforceable_for(child: Option<&Storage>, relation: Option<&StorageRelation>) -> bool {
    if !enforceable(relation) {
        return false;
    }
    if relation.and_then(|r| r.delete_constraint) != Some(RelationConstraint::Cascade) {
        return true;
    }
    !owes_anything_on_delete(child)
}

pub fn owes_anything_on_delete(child: Option<&Storage>) -> bool {
    let Some(child) = child else { return true };
    if child.generate_events == Some(true) || child.audited() || child.versioned() {
        return true;
    }
    let Some(triggers) = &child.triggers else { return false };
    ["BEFORE_DELETE", "AFTER_DELETE"].iter().any(|t| triggers.get(*t).is_some_and(|f| !f.is_empty()))
}

/// The SQL action for a constraint; NOTHING is not NO ACTION, it is no key.
pub fn action(c: Option<RelationConstraint>) -> Option<&'static str> {
    match c? {
        RelationConstraint::Cascade => Some("CASCADE"),
        RelationConstraint::Restrict => Some("RESTRICT"),
        RelationConstraint::Nothing => None,
    }
}

/// Always RESTRICT: the referenced `_id` is never rewritten.
pub fn on_update() -> &'static str {
    "RESTRICT"
}

/// The keys this table should have, given relations already filtered to enforceable ones
/// and the target table each resolves to.
pub fn desired(
    table: &str,
    relations: &IndexMap<String, StorageRelation>,
    target_table_by_field: &IndexMap<String, String>,
) -> Vec<ForeignKey> {
    let mut out = Vec::new();
    for (field, relation) in relations {
        if !enforceable(Some(relation)) {
            continue;
        }
        let Some(target) = target_table_by_field.get(field) else { continue };
        out.push(ForeignKey {
            name: name(table, field),
            column: field.clone(),
            target_table: target.clone(),
            on_delete: action(relation.delete_constraint).unwrap_or("RESTRICT").to_string(),
            on_update: on_update().to_string(),
        });
    }
    out
}

/// Deterministic, trimmed from the table end to fit 64 characters.
pub fn name(table: &str, column: &str) -> String {
    let suffix = format!("_{column}");
    let room = MAX_NAME as isize - 3 - suffix.len() as isize;
    let head = if room <= 0 {
        ""
    } else if table.len() <= room as usize {
        table
    } else {
        &table[..room as usize]
    };
    format!("fk_{head}{suffix}")
}

/// The keys MySQL reports on a table.
pub fn existing_sql(db: &str, table: &str) -> String {
    format!(
        "SELECT k.CONSTRAINT_NAME, k.COLUMN_NAME, k.REFERENCED_TABLE_NAME, r.DELETE_RULE, r.UPDATE_RULE FROM information_schema.KEY_COLUMN_USAGE k JOIN information_schema.REFERENTIAL_CONSTRAINTS r ON r.CONSTRAINT_SCHEMA = k.CONSTRAINT_SCHEMA AND r.CONSTRAINT_NAME = k.CONSTRAINT_NAME WHERE k.TABLE_SCHEMA = '{db}' AND k.TABLE_NAME = '{table}' AND k.REFERENCED_TABLE_NAME IS NOT NULL ORDER BY k.CONSTRAINT_NAME"
    )
}

/// Drops first, then adds.
pub fn sync(db: &str, table: &str, existing: &[ForeignKey], desired: &[ForeignKey]) -> Vec<String> {
    let have: IndexMap<&str, &ForeignKey> = existing.iter().map(|k| (k.name.as_str(), k)).collect();
    let want: IndexMap<&str, &ForeignKey> = desired.iter().map(|k| (k.name.as_str(), k)).collect();
    let mut drops = Vec::new();
    let mut adds = Vec::new();
    for (name, fk) in &have {
        match want.get(name) {
            Some(target) if fk.same_as(target) => {}
            _ => drops.push(format!("ALTER TABLE `{db}`.`{table}` DROP FOREIGN KEY `{name}`")),
        }
    }
    for (name, fk) in &want {
        match have.get(name) {
            Some(current) if current.same_as(fk) => {}
            _ => adds.push(format!("ALTER TABLE `{db}`.`{table}` {}", fk.add_clause())),
        }
    }
    drops.extend(adds);
    drops
}

/// Rows that would make this key impossible to add.
pub fn orphan_count(db: &str, table: &str, fk: &ForeignKey) -> String {
    format!(
        "SELECT COUNT(*) FROM `{db}`.`{table}` c WHERE c.`{col}` IS NOT NULL AND NOT EXISTS (SELECT 1 FROM `{db}`.`{target}` p WHERE p.`{ID_COLUMN}` = c.`{col}`)",
        col = fk.column,
        target = fk.target_table
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relation(t: RelationType, on_delete: Option<RelationConstraint>) -> StorageRelation {
        StorageRelation {
            storage_name: Some("customers".into()),
            relation_type: Some(t),
            field_name: Some("_id".into()),
            delete_constraint: on_delete,
            ..Default::default()
        }
    }

    use RelationConstraint::*;
    use RelationType::*;

    #[test]
    fn which_qualify() {
        assert!(enforceable(Some(&relation(ToOne, Some(Restrict)))));
        assert!(enforceable(Some(&relation(ToOne, Some(Cascade)))));
        assert!(!enforceable(Some(&relation(ToOne, Some(Nothing)))));
        assert!(!enforceable(Some(&relation(ToOne, None))));
        assert!(!enforceable(Some(&relation(ToMany, Some(Restrict)))));
        assert!(!enforceable(Some(&relation(ToOne, Some(Restrict)).with_field_name("externalRef"))));
        let r = relation(ToOne, Some(Cascade));
        let plain = Storage::default();
        let versioned = Storage { is_versioned: Some(true), ..Default::default() };
        assert!(enforceable_for(Some(&plain), Some(&r)));
        assert!(!enforceable_for(Some(&versioned), Some(&r)));
        assert!(enforceable_for(Some(&versioned), Some(&relation(ToOne, Some(Restrict)))));
        let mut triggers = IndexMap::new();
        triggers.insert("AFTER_DELETE".to_string(), vec!["notifyWarehouse".to_string()]);
        let triggered = Storage { triggers: Some(triggers), ..Default::default() };
        assert!(!enforceable_for(Some(&triggered), Some(&r)));
        let mut blank = relation(ToOne, Some(Cascade));
        blank.field_name = None;
        assert!(enforceable(Some(&blank)));
        let audited = Storage { is_audited: Some(true), is_versioned: Some(false), ..Default::default() };
        assert!(owes_anything_on_delete(Some(&audited)));
        assert!(!enforceable_for(Some(&audited), Some(&r)));
        assert!(enforceable_for(Some(&audited), Some(&relation(ToOne, Some(Restrict)))));
        let neither = Storage { is_audited: Some(false), is_versioned: Some(false), ..Default::default() };
        assert!(!owes_anything_on_delete(Some(&neither)));
    }

    fn want(c: RelationConstraint) -> Vec<ForeignKey> {
        let mut relations = IndexMap::new();
        relations.insert("customer".to_string(), relation(ToOne, Some(c)));
        let mut targets = IndexMap::new();
        targets.insert("customer".to_string(), "app_customers".to_string());
        desired("app_orders", &relations, &targets)
    }

    #[test]
    fn statements() {
        let sql = want(Cascade)[0].add_clause();
        assert!(sql.contains("FOREIGN KEY (`customer`) REFERENCES `app_customers` (`_id`)") && sql.contains("ON DELETE CASCADE"));
        assert!(sql.contains("ON UPDATE RESTRICT"));
        assert!(sync("db", "app_orders", &want(Restrict), &want(Restrict)).is_empty());
        let s = sync("db", "app_orders", &want(Restrict), &want(Cascade));
        assert_eq!(s.len(), 2);
        assert!(s[0].contains("DROP FOREIGN KEY") && s[1].contains("ADD CONSTRAINT"));
        let s = sync("db", "app_orders", &want(Restrict), &[]);
        assert_eq!(s.len(), 1);
        assert!(s[0].contains("DROP FOREIGN KEY"));
        let n = name(&"a".repeat(120), "customer");
        assert!(n.len() <= 64 && n.ends_with("_customer"), "{n}");
        let o = orphan_count("db", "app_orders", &want(Restrict)[0]);
        assert!(o.contains("NOT EXISTS") && o.contains("IS NOT NULL"));
        let mut relations = IndexMap::new();
        relations.insert("customer".to_string(), relation(ToOne, Some(Cascade)));
        assert!(desired("app_orders", &relations, &IndexMap::new()).is_empty());
    }
}
