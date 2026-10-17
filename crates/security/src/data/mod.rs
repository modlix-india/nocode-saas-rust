//! The security DAOs the units share beyond authentication: the SQL each Java DAO method
//! renders, over the same pool. Reads that Java caches go through [`crate::directory`] or the
//! unit's service, never straight here.

pub mod apps;
pub mod audit;
pub mod billing;
pub mod billing_admin;
pub mod clients;
pub mod crud;
pub mod filters;
pub mod misc;
pub mod org;
pub mod profiles;
pub mod roles;
pub mod users;
pub mod users_admin;

use sqlx::mysql::MySqlPool;
use sqlx::{MySql, QueryBuilder};

/// The `security` schema.
#[derive(Clone)]
pub struct Db {
    pub pool: MySqlPool,
}

impl Db {
    pub fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }
}

/// `col IN (?, ...)`, or jOOQ's rendering of an empty `IN`: `1 = 0`.
pub fn push_in_u64(qb: &mut QueryBuilder<'_, MySql>, col: &str, ids: &[u64]) {
    if ids.is_empty() {
        qb.push("1 = 0");
        return;
    }
    qb.push(col).push(" IN (");
    let mut sep = qb.separated(", ");
    for id in ids {
        sep.push_bind(*id);
    }
    qb.push(")");
}

/// The same for text values.
pub fn push_in_str(qb: &mut QueryBuilder<'_, MySql>, col: &str, values: &[String]) {
    if values.is_empty() {
        qb.push("1 = 0");
        return;
    }
    qb.push(col).push(" IN (");
    let mut sep = qb.separated(", ");
    for v in values {
        sep.push_bind(v.clone());
    }
    qb.push(")");
}

/// `ClientHierarchyDAO.getManageClientCondition(clientId)` as SQL text (the id is a number).
pub fn manage_client_condition(client_id: u64) -> String {
    format!(
        "(security_client_hierarchy.CLIENT_ID = {client_id} OR security_client_hierarchy.MANAGE_CLIENT_LEVEL_0 = {client_id} \
         OR security_client_hierarchy.MANAGE_CLIENT_LEVEL_1 = {client_id} OR security_client_hierarchy.MANAGE_CLIENT_LEVEL_2 = {client_id} \
         OR security_client_hierarchy.MANAGE_CLIENT_LEVEL_3 = {client_id})"
    )
}

/// Several distinct ids in first-seen order (`Flux.distinct()`).
pub fn distinct(ids: impl IntoIterator<Item = u64>) -> Vec<u64> {
    let mut seen = std::collections::HashSet::new();
    ids.into_iter().filter(|i| seen.insert(*i)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_lists_and_conditions() {
        let mut qb = QueryBuilder::<MySql>::new("SELECT 1 WHERE ");
        push_in_u64(&mut qb, "ID", &[1, 2]);
        qb.push(" AND ");
        push_in_u64(&mut qb, "ID", &[]);
        qb.push(" AND ");
        push_in_str(&mut qb, "CODE", &["A".into()]);
        qb.push(" AND ");
        push_in_str(&mut qb, "CODE", &[]);
        assert_eq!(qb.sql(), "SELECT 1 WHERE ID IN (?, ?) AND 1 = 0 AND CODE IN (?) AND 1 = 0");
        assert!(manage_client_condition(7).contains("MANAGE_CLIENT_LEVEL_3 = 7"));
        assert_eq!(distinct([3, 1, 3, 2, 1]), vec![3, 1, 2]);
    }
}
