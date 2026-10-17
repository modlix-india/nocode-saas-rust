//! The generic SQL of `AbstractDAO`, `AbstractUpdatableDAO` and the client-check DAOs
//! (`AbstractClientCheckDAO`, `AbstractUpdatableClientCheckDAO` through `ClientCheckDAOHelper`),
//! for the admin entities that use them as they are (designations, departments, roles, ...).
//!
//! - A non-SYSTEM caller's reads select `DISTINCT` rows joined to the row's client, its
//!   hierarchy and its client managers; a page counts `DISTINCT` ids.
//! - Lists add the client filter: the caller's managed clients, and for a non-Owner only those
//!   the caller is a registered manager of (`applyClientFilter`). A read by id (and
//!   `canBeUpdated`) has the joins but not the filter, as `getRecordById` has.
//! - Writes are jOOQ's `Record.from(pojo)`: a null value of a NOT NULL column is left out (the
//!   database default applies), any other value is written, null included; an update never
//!   touches `CREATED_BY` / `CREATED_AT`.

use sqlx::mysql::MySqlRow;
use sqlx::{MySql, QueryBuilder, Row};

use super::{manage_client_condition, Db};
use crate::condition::{order_by, Bind, Sql, Table};
use crate::errors::{AuthError, AuthResult};
use crate::expr::has_authority;
use crate::model::ContextAuth;
use crate::spring::Pageable;

/// A table as the generic DAOs see it.
pub struct Entity {
    pub table: Table,
    /// The client id column of a client-check DAO; `None` for a plain DAO.
    pub client_column: Option<&'static str>,
    /// NOT NULL columns: left out of an insert or update when the value is null.
    pub not_null: &'static [&'static str],
}

/// `ClientCheckDAOHelper`'s view of the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientCheck {
    /// A SYSTEM client caller: no joins, no filter.
    All,
    /// Anyone else.
    Managed { client_id: u64, user_id: u64, owner: bool },
    /// `applyOwnAndManagedClientFilter` (invites, access requests): the caller's own client, or a
    /// client it manages that the caller is a registered manager of (any of them with Owner or
    /// Client_Manager).
    OwnOrManaged { client_id: u64, user_id: u64, managing: bool },
}

pub fn client_check(ca: &ContextAuth) -> ClientCheck {
    if ca.is_system_client() {
        return ClientCheck::All;
    }
    let authorities = ca.user.string_authorities.clone().unwrap_or_default();
    ClientCheck::Managed {
        client_id: ca.user.client_id(),
        user_id: ca.user.id(),
        owner: has_authority(Some("Authorities.ROLE_Owner"), &authorities),
    }
}

/// The own-or-managed scope of the caller (`ClientCheckDAOHelper.applyOwnAndManagedClientFilter`).
pub fn own_or_managed(ca: &ContextAuth) -> ClientCheck {
    if ca.is_system_client() {
        return ClientCheck::All;
    }
    let authorities = ca.user.string_authorities.clone().unwrap_or_default();
    ClientCheck::OwnOrManaged {
        client_id: ca.user.client_id(),
        user_id: ca.user.id(),
        managing: has_authority(Some("Authorities.ROLE_Owner or Authorities.ROLE_Client_Manager"), &authorities),
    }
}

/// `applyClientFilter`'s condition, or `None` for SYSTEM.
pub fn client_filter(scope: ClientCheck) -> Option<Sql> {
    match scope {
        ClientCheck::All => None,
        ClientCheck::OwnOrManaged { .. } => None,
        ClientCheck::Managed { client_id, user_id, owner } => Some(Sql::text(if owner {
            format!("({} AND 1 = 1)", manage_client_condition(client_id))
        } else {
            format!("({} AND security_client_manager.MANAGER_ID = {user_id})", manage_client_condition(client_id))
        })),
    }
}

/// Appends a bound value.
pub fn push_bind(qb: &mut QueryBuilder<'_, MySql>, b: &Bind) {
    let mut s = Sql::default();
    s.push_bind(b.clone());
    s.push_to(qb);
}

impl Entity {
    fn columns(&self) -> String {
        self.table.columns.iter().map(|(c, _)| self.table.qualified(c)).collect::<Vec<_>>().join(", ")
    }

    /// (`SELECT` list, `FROM` clause, count expression) for the caller.
    fn shape(&self, scope: ClientCheck) -> (String, String, String) {
        let t = self.table.name;
        match (self.client_column, scope) {
            (Some(col), ClientCheck::Managed { .. } | ClientCheck::OwnOrManaged { .. }) => (
                format!("DISTINCT {}", self.columns()),
                format!(
                    " FROM {t} LEFT JOIN security_client ON security_client.ID = {t}.{col} \
                     LEFT JOIN security_client_hierarchy ON security_client_hierarchy.CLIENT_ID = security_client.ID \
                     LEFT JOIN security_client_manager ON security_client_manager.CLIENT_ID = {t}.{col}"
                ),
                format!("COUNT(DISTINCT {t}.ID)"),
            ),
            _ => (self.columns(), format!(" FROM {t}"), "COUNT(*)".to_string()),
        }
    }

    /// The caller's condition with the client filter of a client-check DAO.
    fn scoped(&self, scope: ClientCheck, cond: Option<Sql>) -> Option<Sql> {
        let Some(col) = self.client_column else { return cond };
        if let ClientCheck::OwnOrManaged { client_id, user_id, managing } = scope {
            let manager = if managing { "1 = 1".to_string() } else { format!("security_client_manager.MANAGER_ID = {user_id}") };
            let filter = Sql::text(format!(
                "({t}.{col} = {client_id} OR ({} AND {manager}))",
                manage_client_condition(client_id),
                t = self.table.name
            ));
            return Sql::and(cond, Some(filter));
        }
        Sql::and(cond, client_filter(scope))
    }
}

impl Db {
    /// `readPageFilter`: the rows of the page and the total.
    pub async fn entity_page(&self, e: &Entity, scope: ClientCheck, cond: Option<Sql>, page: &Pageable) -> AuthResult<(Vec<MySqlRow>, i64)> {
        let (select, from, count) = e.shape(scope);
        let cond = e.scoped(scope, cond);
        let build = |what: &str| {
            let mut qb: QueryBuilder<MySql> = QueryBuilder::new(format!("SELECT {what}{from}"));
            if let Some(c) = &cond {
                qb.push(" WHERE ");
                c.push_to(&mut qb);
            }
            qb
        };
        let mut qb = build(&select);
        qb.push(order_by(&page.sort, &e.table));
        qb.push(" LIMIT ").push_bind(page.size).push(" OFFSET ").push_bind(page.offset());
        let rows = qb.build().fetch_all(&self.pool).await?;
        let total: i64 = build(&count).build().fetch_one(&self.pool).await?.try_get(0)?;
        Ok((rows, total))
    }

    /// `readAll`.
    pub async fn entity_all(&self, e: &Entity, scope: ClientCheck, cond: Option<Sql>) -> AuthResult<Vec<MySqlRow>> {
        let (select, from, _) = e.shape(scope);
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new(format!("SELECT {select}{from}"));
        if let Some(c) = e.scoped(scope, cond) {
            qb.push(" WHERE ");
            c.push_to(&mut qb);
        }
        Ok(qb.build().fetch_all(&self.pool).await?)
    }

    /// `getRecordById`: the joins without the client filter.
    pub async fn entity_by_id(&self, e: &Entity, scope: ClientCheck, id: u64) -> AuthResult<Option<MySqlRow>> {
        let (select, from, _) = e.shape(scope);
        let sql = format!("SELECT {select}{from} WHERE {}.ID = ? LIMIT 1", e.table.name);
        Ok(sqlx::query(&sql).bind(id).fetch_optional(&self.pool).await?)
    }

    /// `canBeUpdated`: the count query by id (the joins, no filter) is exactly one.
    pub async fn entity_can_be_updated(&self, e: &Entity, scope: ClientCheck, id: u64) -> AuthResult<bool> {
        let (_, from, count) = e.shape(scope);
        let sql = format!("SELECT {count}{from} WHERE {}.ID = ?", e.table.name);
        let n: i64 = sqlx::query(&sql).bind(id).fetch_one(&self.pool).await?.try_get(0)?;
        Ok(n == 1)
    }

    /// `AbstractDAO.create`: the new id.
    pub async fn entity_insert(&self, e: &Entity, values: &[(&str, Bind)]) -> AuthResult<u64> {
        let kept: Vec<&(&str, Bind)> = values.iter().filter(|(c, v)| !(*v == Bind::Null && e.not_null.contains(c))).collect();
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new(format!("INSERT INTO {} (", e.table.name));
        qb.push(kept.iter().map(|(c, _)| *c).collect::<Vec<_>>().join(", "));
        qb.push(") VALUES (");
        for (i, (_, v)) in kept.iter().enumerate() {
            if i > 0 {
                qb.push(", ");
            }
            push_bind(&mut qb, v);
        }
        qb.push(")");
        match qb.build().execute(&self.pool).await {
            Ok(r) => Ok(r.last_insert_id()),
            // jOOQ's DataAccessException: the statement it rendered, then the server's message.
            Err(sqlx::Error::Database(db)) => {
                let cols = kept.iter().map(|(c, _)| format!("`{c}`")).collect::<Vec<_>>().join(", ");
                let marks = vec!["?"; kept.len()].join(", ");
                Err(AuthError::internal(format!(
                    "SQL [insert into `security`.`{}` ({cols}) values ({marks})]; {}",
                    e.table.name,
                    db.message()
                )))
            }
            Err(other) => Err(other.into()),
        }
    }

    /// `AbstractUpdatableDAO.update(entity)`.
    pub async fn entity_update(&self, e: &Entity, id: u64, values: &[(&str, Bind)]) -> AuthResult<u64> {
        let kept: Vec<&(&str, Bind)> = values
            .iter()
            .filter(|(c, v)| *c != "CREATED_BY" && *c != "CREATED_AT" && !(*v == Bind::Null && e.not_null.contains(c)))
            .collect();
        if kept.is_empty() {
            return Ok(0);
        }
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new(format!("UPDATE {} SET ", e.table.name));
        for (i, (c, v)) in kept.iter().enumerate() {
            if i > 0 {
                qb.push(", ");
            }
            qb.push(format!("{c} = "));
            push_bind(&mut qb, v);
        }
        qb.push(" WHERE ID = ").push_bind(id);
        Ok(qb.build().execute(&self.pool).await?.rows_affected())
    }

    /// `AbstractDAO.delete`.
    pub async fn entity_delete(&self, e: &Entity, id: u64) -> AuthResult<u64> {
        let sql = format!("DELETE FROM {} WHERE ID = ?", e.table.name);
        Ok(sqlx::query(&sql).bind(id).execute(&self.pool).await?.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::condition::ColType;

    const E: Entity = Entity {
        table: Table { name: "security_designation", columns: &[("ID", ColType::Num), ("CLIENT_ID", ColType::Num), ("NAME", ColType::Str)] },
        client_column: Some("CLIENT_ID"),
        not_null: &["CLIENT_ID", "NAME"],
    };

    #[test]
    fn caller_shapes() {
        let (s, f, c) = E.shape(ClientCheck::All);
        assert_eq!((s.as_str(), f.as_str(), c.as_str()), ("security_designation.ID, security_designation.CLIENT_ID, security_designation.NAME", " FROM security_designation", "COUNT(*)"));
        let m = ClientCheck::Managed { client_id: 28, user_id: 8, owner: false };
        let (s, f, c) = E.shape(m);
        assert!(s.starts_with("DISTINCT ") && f.contains("LEFT JOIN security_client_manager") && c == "COUNT(DISTINCT security_designation.ID)");
        let filter = client_filter(m).unwrap();
        let text: String = filter.parts.iter().map(|p| match p { crate::condition::Part::Text(t) => t.clone(), _ => String::new() }).collect();
        assert!(text.ends_with("AND security_client_manager.MANAGER_ID = 8)"));
        assert!(client_filter(ClientCheck::Managed { client_id: 28, user_id: 8, owner: true }).is_some());
        assert!(client_filter(ClientCheck::All).is_none());
        assert!(E.scoped(ClientCheck::All, None).is_none());
        let plain = Entity { client_column: None, ..E };
        assert!(plain.scoped(m, None).is_none());
        let mut ca = ContextAuth { client_type_code: Some("SYS".into()), ..Default::default() };
        assert_eq!(client_check(&ca), ClientCheck::All);
        ca.client_type_code = Some("BUS".into());
        ca.user.string_authorities = Some(vec!["Authorities.ROLE_Owner".into()]);
        assert!(matches!(client_check(&ca), ClientCheck::Managed { owner: true, .. }));
    }
}

#[cfg(test)]
mod scope_tests {
    use super::*;
    use crate::condition::ColType;

    const E: Entity = Entity {
        table: Table { name: "security_user_invite", columns: &[("ID", ColType::Num), ("CLIENT_ID", ColType::Num)] },
        client_column: Some("CLIENT_ID"),
        not_null: &["CLIENT_ID"],
    };

    fn text(s: &Sql) -> String {
        s.parts.iter().map(|p| match p { crate::condition::Part::Text(t) => t.clone(), _ => String::new() }).collect()
    }

    #[test]
    fn own_or_managed_callers() {
        let mut ca = ContextAuth { client_type_code: Some("SYS".into()), ..Default::default() };
        assert_eq!(own_or_managed(&ca), ClientCheck::All);
        ca.client_type_code = Some("BUS".into());
        ca.user.id = Some(8);
        ca.user.client_id = Some(28);
        assert_eq!(own_or_managed(&ca), ClientCheck::OwnOrManaged { client_id: 28, user_id: 8, managing: false });
        ca.user.string_authorities = Some(vec!["Authorities.ROLE_Client_Manager".into()]);
        let scope = own_or_managed(&ca);
        assert_eq!(scope, ClientCheck::OwnOrManaged { client_id: 28, user_id: 8, managing: true });
        assert!(client_filter(scope).is_none());
        assert!(text(&E.scoped(scope, None).unwrap()).contains("1 = 1"));
        let plain = ClientCheck::OwnOrManaged { client_id: 28, user_id: 8, managing: false };
        assert!(text(&E.scoped(plain, None).unwrap()).contains("security_client_manager.MANAGER_ID = 8"));
        let (select, from, _) = E.shape(plain);
        assert!(select.starts_with("DISTINCT") && from.contains("security_client_hierarchy"));
    }

    /// An update with nothing left to write touches no database.
    #[tokio::test]
    async fn nothing_to_update() {
        let s = crate::admin::users::testkit::offline();
        assert_eq!(s.db.entity_update(&E, 1, &[("CREATED_BY", Bind::U64(1))]).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn all_rows_of_a_scope() {
        let Some(fx) = crate::admin::users::testkit::fx().await else { return };
        let invite = Entity { table: Table { name: "security_user_invite", columns: &[("ID", ColType::Num), ("CLIENT_ID", ColType::Num)] }, ..E };
        let cond = Sql::text(format!("security_user_invite.CLIENT_ID = {}", fx.c));
        fx.s.db.entity_all(&invite, ClientCheck::All, Some(cond.clone())).await.unwrap();
        let scope = ClientCheck::Managed { client_id: fx.c, user_id: 0, owner: true };
        fx.s.db.entity_all(&invite, scope, Some(cond)).await.unwrap();
        fx.s.db.entity_all(&invite, ClientCheck::OwnOrManaged { client_id: fx.c, user_id: 0, managing: false }, None).await.unwrap();
        fx.finish().await;
    }
}
