//! `DesignationDAO` and `DepartmentDAO`: client-check tables of a client's organisation.

use sqlx::mysql::MySqlRow;
use sqlx::Row;

use super::crud::Entity;
use super::Db;
use crate::condition::{Bind, ColType, Table};
use crate::dto::{Department, Designation};
use crate::errors::AuthResult;
use crate::mysql::ts;

use ColType::{Num, Str, Ts};

pub const DESIGNATION: Entity = Entity {
    table: Table {
        name: "security_designation",
        columns: &[
            ("ID", Num),
            ("CLIENT_ID", Num),
            ("NAME", Str),
            ("DESCRIPTION", Str),
            ("DEPARTMENT_ID", Num),
            ("PARENT_DESIGNATION_ID", Num),
            ("NEXT_DESIGNATION_ID", Num),
            ("PROFILE_ID", Num),
            ("CREATED_BY", Num),
            ("CREATED_AT", Ts),
            ("UPDATED_BY", Num),
            ("UPDATED_AT", Ts),
        ],
    },
    client_column: Some("CLIENT_ID"),
    not_null: &["ID", "CLIENT_ID", "NAME", "CREATED_AT", "UPDATED_AT"],
};

pub const DEPARTMENT: Entity = Entity {
    table: Table {
        name: "security_department",
        columns: &[
            ("ID", Num),
            ("CLIENT_ID", Num),
            ("NAME", Str),
            ("DESCRIPTION", Str),
            ("PARENT_DEPARTMENT_ID", Num),
            ("CREATED_BY", Num),
            ("CREATED_AT", Ts),
            ("UPDATED_BY", Num),
            ("UPDATED_AT", Ts),
        ],
    },
    client_column: Some("CLIENT_ID"),
    not_null: &["ID", "CLIENT_ID", "NAME", "CREATED_AT", "UPDATED_AT"],
};

pub fn designation(r: &MySqlRow) -> AuthResult<Designation> {
    Ok(Designation {
        id: r.try_get("ID")?,
        client_id: r.try_get("CLIENT_ID")?,
        name: r.try_get("NAME")?,
        description: r.try_get("DESCRIPTION")?,
        parent_designation_id: r.try_get("PARENT_DESIGNATION_ID")?,
        department_id: r.try_get("DEPARTMENT_ID")?,
        next_designation_id: r.try_get("NEXT_DESIGNATION_ID")?,
        profile_id: r.try_get("PROFILE_ID")?,
        created_by: r.try_get("CREATED_BY")?,
        created_at: ts(r, "CREATED_AT")?,
        updated_by: r.try_get("UPDATED_BY")?,
        updated_at: ts(r, "UPDATED_AT")?,
    })
}

pub fn department(r: &MySqlRow) -> AuthResult<Department> {
    Ok(Department {
        id: r.try_get("ID")?,
        client_id: r.try_get("CLIENT_ID")?,
        name: r.try_get("NAME")?,
        description: r.try_get("DESCRIPTION")?,
        parent_department_id: r.try_get("PARENT_DEPARTMENT_ID")?,
        created_by: r.try_get("CREATED_BY")?,
        created_at: ts(r, "CREATED_AT")?,
        updated_by: r.try_get("UPDATED_BY")?,
        updated_at: ts(r, "UPDATED_AT")?,
    })
}

fn n(v: Option<u64>) -> Bind {
    v.map(Bind::U64).unwrap_or(Bind::Null)
}

fn s(v: &Option<String>) -> Bind {
    v.clone().map(Bind::Str).unwrap_or(Bind::Null)
}

fn t(v: Option<chrono::NaiveDateTime>) -> Bind {
    v.map(|t| Bind::Ts(t.and_utc())).unwrap_or(Bind::Null)
}

/// The record jOOQ makes from a `Designation` (every column).
pub fn designation_values(d: &Designation) -> Vec<(&'static str, Bind)> {
    vec![
        ("CLIENT_ID", n(d.client_id)),
        ("NAME", s(&d.name)),
        ("DESCRIPTION", s(&d.description)),
        ("DEPARTMENT_ID", n(d.department_id)),
        ("PARENT_DESIGNATION_ID", n(d.parent_designation_id)),
        ("NEXT_DESIGNATION_ID", n(d.next_designation_id)),
        ("PROFILE_ID", n(d.profile_id)),
        ("CREATED_BY", n(d.created_by)),
        ("CREATED_AT", t(d.created_at)),
        ("UPDATED_BY", n(d.updated_by)),
        ("UPDATED_AT", t(d.updated_at)),
    ]
}

pub fn department_values(d: &Department) -> Vec<(&'static str, Bind)> {
    vec![
        ("CLIENT_ID", n(d.client_id)),
        ("NAME", s(&d.name)),
        ("DESCRIPTION", s(&d.description)),
        ("PARENT_DEPARTMENT_ID", n(d.parent_department_id)),
        ("CREATED_BY", n(d.created_by)),
        ("CREATED_AT", t(d.created_at)),
        ("UPDATED_BY", n(d.updated_by)),
        ("UPDATED_AT", t(d.updated_at)),
    ]
}

impl Db {
    /// `isNameTaken`: another row of the client with this name (the column's collation compares).
    pub async fn org_name_taken(&self, table: &str, client_id: Option<u64>, name: &str, exclude: Option<u64>) -> AuthResult<bool> {
        let mut sql = format!("SELECT COUNT(*) FROM {table} WHERE CLIENT_ID <=> ? AND NAME = ?");
        if exclude.is_some() {
            sql.push_str(" AND ID <> ?");
        }
        let mut q = sqlx::query_scalar::<_, i64>(&sql).bind(client_id).bind(name);
        if let Some(e) = exclude {
            q = q.bind(e);
        }
        Ok(q.fetch_one(&self.pool).await? > 0)
    }

    /// One row with this id in this client (`checkSameClient` / `canAssignDesignation`).
    pub async fn org_in_client(&self, table: &str, id: u64, client_id: Option<u64>) -> AuthResult<bool> {
        let sql = format!("SELECT COUNT(*) FROM {table} WHERE ID = ? AND CLIENT_ID <=> ?");
        Ok(sqlx::query_scalar::<_, i64>(&sql).bind(id).bind(client_id).fetch_one(&self.pool).await? == 1)
    }

    /// `DepartmentDAO.readInternal`.
    pub async fn department(&self, id: u64) -> AuthResult<Option<Department>> {
        let row = sqlx::query("SELECT * FROM security_department WHERE ID = ? LIMIT 1").bind(id).fetch_optional(&self.pool).await?;
        row.as_ref().map(department).transpose()
    }
}
