//! Reads of the `files` schema the serving routes need: the file tree, access paths and
//! secured access keys. Same SQL meaning as the jOOQ in `FileSystemDao`, `FilesAccessPathDao`
//! and `FilesSecuredAccessKeyDao`.

use std::collections::HashMap;
use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::mysql::MySqlPool;
use sqlx::{FromRow, QueryBuilder, Row};

use crate::paths::Kind;

/// `FileDetail` as `FileSystemDao.getFileDetail` fills it.
#[derive(Debug, Clone)]
pub struct FileDetail {
    /// 0 for a client's root, which has no row.
    pub id: u64,
    pub name: String,
    pub is_directory: bool,
    pub size: u64,
    /// Epoch seconds, as Java's `FileDetail.createdDate` holds it.
    pub created: i64,
    /// Epoch seconds, as Java's `FileDetail.lastModifiedTime` holds it.
    pub last_modified: i64,
}

impl FileDetail {
    /// `new FileDetail().setFileName("").setDirectory(true)`: a client's root.
    pub fn root() -> Self {
        Self { id: 0, name: String::new(), is_directory: true, size: 0, created: 0, last_modified: 0 }
    }
}

#[derive(FromRow, Clone)]
pub(crate) struct FileRow {
    #[sqlx(rename = "ID")]
    pub id: u64,
    #[sqlx(rename = "NAME")]
    pub name: String,
    #[sqlx(rename = "FILE_TYPE")]
    pub file_type: String,
    #[sqlx(rename = "SIZE")]
    pub size: Option<u64>,
    #[sqlx(rename = "PARENT_ID")]
    pub parent_id: Option<u64>,
    #[sqlx(rename = "CREATED_AT")]
    pub created_at: Option<DateTime<Utc>>,
    #[sqlx(rename = "UPDATED_AT")]
    pub updated_at: Option<DateTime<Utc>>,
}

impl FileRow {
    pub fn detail(&self) -> FileDetail {
        FileDetail {
            id: self.id,
            name: self.name.clone(),
            is_directory: self.file_type == "DIRECTORY",
            size: self.size.unwrap_or(0),
            created: self.created_at.map(|t| t.timestamp()).unwrap_or(0),
            last_modified: self.updated_at.map(|t| t.timestamp()).unwrap_or(0),
        }
    }
}

/// The columns every read of `files_file_system` takes.
pub(crate) const FILE_COLUMNS: &str =
    "ID, NAME, CAST(FILE_TYPE AS CHAR) AS FILE_TYPE, SIZE, PARENT_ID, CREATED_AT, UPDATED_AT";

#[derive(Debug, Clone)]
pub struct AccessKey {
    pub id: u64,
    pub path: String,
    pub access_till: DateTime<Utc>,
    pub access_limit: Option<u64>,
    pub accessed_count: u64,
}

#[derive(Clone)]
pub struct Dao {
    pool: MySqlPool,
}

impl Dao {
    pub fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &MySqlPool {
        &self.pool
    }

    /// `FileSystemDao.getFileDetail`: walks the tree from the client root by name.
    ///
    /// One query fetches every row of the client whose name is one of the path's segments; the
    /// walk then follows parent ids in memory. Name matching is exact here although the column's
    /// collation is case-insensitive, because the Java walk matches in a `HashMap`.
    pub async fn file_detail(&self, kind: Kind, client_code: &str, parts: &[&str]) -> Result<Option<FileDetail>> {
        Ok(self.file_record(kind, client_code, parts).await?.map(|r| r.detail()))
    }

    /// `FileSystemDao.getFileRecord`: the row at `parts`, walking from the client's root.
    pub(crate) async fn file_record(&self, kind: Kind, client_code: &str, parts: &[&str]) -> Result<Option<FileRow>> {
        if parts.is_empty() {
            return Ok(None);
        }
        let mut qb = QueryBuilder::new(format!("SELECT {FILE_COLUMNS} FROM files_file_system WHERE CODE = "));
        qb.push_bind(client_code);
        qb.push(" AND TYPE = ");
        qb.push_bind(kind.db_name());
        qb.push(" AND NAME IN (");
        let mut sep = qb.separated(", ");
        for p in parts {
            sep.push_bind(*p);
        }
        qb.push(")");

        let rows: Vec<FileRow> = qb.build_query_as().fetch_all(&self.pool).await?;
        if rows.is_empty() || parts.len() > rows.len() {
            return Ok(None);
        }

        let mut by_name: HashMap<&str, Vec<&FileRow>> = HashMap::new();
        for r in &rows {
            by_name.entry(r.name.as_str()).or_default().push(r);
        }

        let mut parent: Option<u64> = None;
        let mut found: Option<&FileRow> = None;
        for part in parts {
            let Some(candidates) = by_name.get(part) else { return Ok(None) };
            // Java returns on the first candidate whose parent matches, without trying others.
            let Some(rec) = candidates.iter().find(|r| r.parent_id == parent) else {
                return Ok(None);
            };
            parent = Some(rec.id);
            found = Some(rec);
        }

        Ok(found.cloned())
    }

    /// `FilesSecuredAccessKeyDao.getAccessByKey`.
    pub async fn access_key(&self, key: &str) -> Result<Option<AccessKey>> {
        let row = sqlx::query(
            "SELECT ID, PATH, ACCESS_TILL, ACCESS_LIMIT, ACCESSED_COUNT \
             FROM files_secured_access_keys WHERE ACCESS_KEY = ? LIMIT 1",
        )
        .bind(key)
        .fetch_optional(&self.pool)
        .await?;
        Ok(match row {
            None => None,
            Some(r) => Some(AccessKey {
                id: r.try_get("ID")?,
                path: r.try_get("PATH")?,
                access_till: r.try_get("ACCESS_TILL")?,
                access_limit: r.try_get("ACCESS_LIMIT")?,
                accessed_count: r.try_get("ACCESSED_COUNT")?,
            }),
        })
    }

    /// `incrementAccessCount`: only while under the limit, so two racing downloads cannot both
    /// take the last use.
    pub async fn increment_access_count(&self, id: u64) -> Result<bool> {
        let r = sqlx::query(
            "UPDATE files_secured_access_keys SET ACCESSED_COUNT = ACCESSED_COUNT + 1 \
             WHERE ID = ? AND ACCESSED_COUNT <= ACCESS_LIMIT",
        )
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() > 0)
    }

    /// `FilesAccessPathDao.hasPathReadAccess` / `hasPathWriteAccess`: a rule for this user or one
    /// of their authorities that covers `path` (and, to write, grants writing). A static read
    /// with no covering rule is allowed when the client has no static rules at all.
    pub async fn has_path_access(
        &self,
        kind: Kind,
        path: &str,
        user_id: u64,
        client_code: &str,
        authorities: &[String],
        write: bool,
    ) -> Result<bool> {
        let mut qb = QueryBuilder::new("SELECT COUNT(*) AS C FROM files_access_path WHERE CLIENT_CODE = ");
        qb.push_bind(client_code);
        qb.push(" AND RESOURCE_TYPE = ");
        qb.push_bind(kind.db_name());
        qb.push(" AND (USER_ID = ");
        qb.push_bind(user_id);
        if authorities.is_empty() {
            qb.push(" OR 1 = 0");
        } else {
            qb.push(" OR ACCESS_NAME IN (");
            let mut sep = qb.separated(", ");
            for a in authorities {
                sep.push_bind(a.as_str());
            }
            qb.push(")");
        }
        qb.push(") AND CONCAT(");
        qb.push_bind(path);
        qb.push(") LIKE IF(ALLOW_SUB_PATH_ACCESS <> 0, CONCAT(PATH, '%'), PATH)");
        if write {
            qb.push(" AND WRITE_ACCESS = 1");
        }
        let count: i64 = qb.build().fetch_one(&self.pool).await?.try_get("C")?;
        if count != 0 || write || kind == Kind::Secured {
            return Ok(count != 0);
        }
        let any: i64 = sqlx::query(
            "SELECT COUNT(*) AS C FROM files_access_path WHERE CLIENT_CODE = ? AND RESOURCE_TYPE = ?",
        )
        .bind(client_code)
        .bind(kind.db_name())
        .fetch_one(&self.pool)
        .await?
        .try_get("C")?;
        Ok(any == 0)
    }

    /// `FilesAccessPathDao.hasPathReadAccess` for SECURED: a path rule for this user or one of
    /// their authorities that covers `path` (exactly, or as a prefix when sub paths are allowed).
    pub async fn has_secured_path_read_access(
        &self,
        path: &str,
        user_id: u64,
        client_code: &str,
        authorities: &[String],
    ) -> Result<bool> {
        let mut qb = QueryBuilder::new("SELECT COUNT(*) AS C FROM files_access_path WHERE CLIENT_CODE = ");
        qb.push_bind(client_code);
        qb.push(" AND RESOURCE_TYPE = 'SECURED' AND (USER_ID = ");
        qb.push_bind(user_id);
        if authorities.is_empty() {
            // jOOQ renders an empty IN as false.
            qb.push(" OR 1 = 0");
        } else {
            qb.push(" OR ACCESS_NAME IN (");
            let mut sep = qb.separated(", ");
            for a in authorities {
                sep.push_bind(a.as_str());
            }
            qb.push(")");
        }
        qb.push(") AND ");
        qb.push_bind(path);
        qb.push(" LIKE IF(ALLOW_SUB_PATH_ACCESS <> 0, CONCAT(PATH, '%'), PATH) LIMIT 1");

        let row = qb.build().fetch_one(&self.pool).await?;
        let count: i64 = row.try_get("C")?;
        Ok(count != 0)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn row(created: Option<DateTime<Utc>>, updated: Option<DateTime<Utc>>) -> FileRow {
        FileRow { id: 1, name: "n".into(), file_type: "FILE".into(), size: None, parent_id: None, created_at: created, updated_at: updated }
    }

    /// `FileSystemDaoOverwriteTest.storedTimesAreReadInTheJvmZoneTheDriverConvertedThemTo`: the
    /// instant comes back as written (sessions are UTC), and a missing time is 0.
    #[test]
    fn epoch_seconds_of_stored_times() {
        let written = DateTime::parse_from_rfc3339("2026-10-04T16:34:38Z").unwrap().with_timezone(&Utc);
        let d = row(Some(written), Some(written)).detail();
        assert_eq!((d.created, d.last_modified), (1_791_131_678, 1_791_131_678));
        let d = row(None, None).detail();
        assert_eq!((d.created, d.last_modified, d.size, d.is_directory), (0, 0, 0, false));
    }
}
