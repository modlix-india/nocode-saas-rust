//! The write side of `FileSystemDao`: folders, files, listings, deletes, the lifetime cleanup
//! and the retention reads. Same SQL meaning as the jOOQ; the file tree is one row per name with
//! a parent id, so every path is resolved by walking it.

use std::collections::HashMap;

use anyhow::Result;
use sqlx::{QueryBuilder, Row};

use crate::condition::{Bind, Part, Sql};
use crate::dao::{Dao, FileDetail, FileRow, FILE_COLUMNS};
use crate::errors::check_name;
use crate::paths::{path_parts, Kind};
use crate::spring::Pageable;

/// `FileType`: the listing filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Archive,
    Documents,
    Images,
    Videos,
    Directories,
    Files,
}

impl FileType {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.trim() {
            "ARCHIVE" => Self::Archive,
            "DOCUMENTS" => Self::Documents,
            "IMAGES" => Self::Images,
            "VIDEOS" => Self::Videos,
            "DIRECTORIES" => Self::Directories,
            "FILES" => Self::Files,
            _ => return None,
        })
    }

    fn extensions(self) -> &'static [&'static str] {
        match self {
            Self::Archive => &["zip", "rar", "7z", "tar", "gz", "iso", "dmg"],
            Self::Documents => &[
                "doc", "docx", "html", "htm", "odt", "pdf", "ods", "ppt", "pptx", "xls", "xlsx", "xlsm", "xlt", "txt",
            ],
            Self::Images => &[
                "jpg", "jpeg", "jpe", "jif", "jfif", "jfi", "png", "gif", "webp", "tiff", "tif", "raw", "arw", "cr2",
                "nrw", "k25", "bmp", "dib", "heif", "heic", "ind", "indd", "indt", "jp2", "j2k", "jpf", "jpx", "jpm",
                "mj2", "svg", "svgz", "avif", "apng", "ico",
            ],
            Self::Videos => &[
                "webm", "mpg", "mp2", "mpeg", "mpe", "mpv", "ogg", "mp4", "m4p", "m4v", "avi", "wmv", "mov", "qt",
                "flv", "swf",
            ],
            Self::Directories | Self::Files => &[],
        }
    }
}

/// One file the cleanup may remove: `FileSystemDao.ExpiredFile`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiredFile {
    pub id: u64,
    pub client_code: String,
    pub kind: Kind,
    /// `/<path within the client>`.
    pub path: String,
}

/// One listing page before it is shaped: `FilesPage`.
#[derive(Debug, Clone)]
pub struct ListPage {
    pub content: Vec<FileDetail>,
    pub total: i64,
}

fn parent_condition(qb: &mut QueryBuilder<'_, sqlx::MySql>, parent: Option<u64>) {
    match parent {
        None => {
            qb.push("PARENT_ID IS NULL");
        }
        Some(id) => {
            qb.push("PARENT_ID = ");
            qb.push_bind(id);
        }
    }
}

/// `splitPathParts` of `path`, as owned strings.
fn parts_of(path: &str) -> Vec<String> {
    path_parts(path).into_iter().map(str::to_string).collect()
}

impl Dao {
    /// `getId(type, clientCode, path)`: the row at `path`, file or folder.
    pub async fn get_id(&self, kind: Kind, cc: &str, path: &str) -> Result<Option<u64>> {
        if path.trim().is_empty() {
            return Ok(None);
        }
        let parts = parts_of(path);
        let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
        Ok(self.file_record(kind, cc, &refs).await?.map(|r| r.id))
    }

    /// `getFileDetail(type, clientCode, path)` straight from the database.
    pub async fn detail_of(&self, kind: Kind, cc: &str, path: &str) -> Result<Option<FileDetail>> {
        let parts = parts_of(path);
        let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
        self.file_detail(kind, cc, &refs).await
    }

    /// `getId(type, clientCode, folderId, path)`: the row named like the last segment of `path`
    /// directly in `folder`.
    pub async fn get_id_in_folder(&self, kind: Kind, cc: &str, folder: Option<u64>, path: &str) -> Result<Option<u64>> {
        let name = path.rsplit('/').next().unwrap_or(path);
        let mut qb = QueryBuilder::new("SELECT ID FROM files_file_system WHERE TYPE = ");
        qb.push_bind(kind.db_name());
        qb.push(" AND ");
        parent_condition(&mut qb, folder);
        qb.push(" AND NAME = ");
        qb.push_bind(name);
        qb.push(" AND CODE = ");
        qb.push_bind(cc);
        qb.push(" LIMIT 1");
        Ok(qb.build().fetch_optional(self.pool()).await?.map(|r| r.get::<u64, _>("ID")))
    }

    async fn insert_folder(&self, kind: Kind, cc: &str, parent: Option<u64>, name: &str) -> Result<u64> {
        let r = sqlx::query(
            "INSERT INTO files_file_system (CODE, PARENT_ID, FILE_TYPE, NAME, TYPE) VALUES (?, ?, 'DIRECTORY', ?, ?)",
        )
        .bind(cc)
        .bind(parent)
        .bind(name)
        .bind(kind.db_name())
        .execute(self.pool())
        .await?;
        Ok(r.last_insert_id())
    }

    /// `getFolderId`: the folder at `path`, creating every missing folder on the way. Whatever
    /// row holds a name is used as the parent, file or folder, as in Java.
    pub async fn get_folder_id(&self, kind: Kind, cc: &str, path: &str) -> Result<Option<u64>> {
        if path.trim().is_empty() {
            return Ok(None);
        }
        let mut cumulative: Vec<String> = Vec::new();
        for part in path.split('/') {
            if part.trim().is_empty() {
                continue;
            }
            let next = match cumulative.last() {
                None => part.to_string(),
                Some(last) => format!("{last}/{part}"),
            };
            cumulative.push(next);
        }
        let mut folder = None;
        for p in cumulative {
            folder = Some(match self.get_id(kind, cc, &p).await? {
                Some(id) => id,
                None => {
                    let name = p.rsplit('/').next().unwrap_or(&p);
                    check_name(name)?;
                    self.insert_folder(kind, cc, folder, name).await?
                }
            });
        }
        Ok(folder)
    }

    /// `FileSystemDao.createFolder`: one folder, its parents found or made.
    pub async fn create_folder(&self, kind: Kind, cc: &str, path: &str) -> Result<u64> {
        let rp = path.strip_prefix('/').unwrap_or(path);
        let (parent_path, name) = match rp.rfind('/') {
            None => (None, rp),
            Some(i) => (Some(&rp[..i]), &rp[i + 1..]),
        };
        check_name(name)?;
        let parent = match parent_path {
            None => None,
            Some(pp) => self.get_folder_id(kind, cc, pp).await?,
        };
        self.insert_folder(kind, cc, parent, name).await
    }

    /// `createOrUpdateFile`: the row for a file just written to the bucket.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_or_update_file(
        &self,
        kind: Kind,
        cc: &str,
        path: &str,
        file_name: Option<&str>,
        len: u64,
        exists: bool,
        expires_after_minutes: Option<u32>,
    ) -> Result<Option<FileDetail>> {
        let index = path.rfind('/');
        let parent_path = index.map(|i| &path[..i]).unwrap_or("");
        let (path, name) = match (file_name.filter(|f| !f.trim().is_empty()), index) {
            (Some(f), Some(_)) => (format!("{parent_path}/{f}"), f.to_string()),
            _ => (path.to_string(), path[index.map(|i| i + 1).unwrap_or(0)..].to_string()),
        };
        check_name(&name)?;
        let parent = self.get_folder_id(kind, cc, parent_path).await?;

        let mut done = false;
        if exists {
            let mut qb = QueryBuilder::new("UPDATE files_file_system SET UPDATED_AT = CURRENT_TIMESTAMP, SIZE = ");
            qb.push_bind(len);
            qb.push(", EXPIRES_AFTER_MINUTES = ");
            qb.push_bind(expires_after_minutes);
            qb.push(" WHERE ");
            parent_condition(&mut qb, parent);
            qb.push(" AND NAME = ");
            qb.push_bind(&name);
            qb.push(" AND CODE = ");
            qb.push_bind(cc);
            qb.push(" AND TYPE = ");
            qb.push_bind(kind.db_name());
            qb.push(" AND FILE_TYPE = 'FILE'");
            done = qb.build().execute(self.pool()).await?.rows_affected() > 0;
        }
        // Also reached when the caller believed the file existed but no row matched.
        if !done {
            done = sqlx::query(
                "INSERT INTO files_file_system (CODE, PARENT_ID, FILE_TYPE, NAME, SIZE, EXPIRES_AFTER_MINUTES, TYPE) \
                 VALUES (?, ?, 'FILE', ?, ?, ?, ?)",
            )
            .bind(cc)
            .bind(parent)
            .bind(&name)
            .bind(len)
            .bind(expires_after_minutes)
            .bind(kind.db_name())
            .execute(self.pool())
            .await?
            .rows_affected()
                > 0;
        }
        if !done {
            return Ok(None);
        }
        self.detail_of(kind, cc, &path).await
    }

    /// `createOrUpdateFileForZipUpload`: by id when the row is known, else a new row.
    #[allow(clippy::too_many_arguments)]
    pub async fn zip_upsert(
        &self,
        existing: Option<u64>,
        kind: Kind,
        cc: &str,
        folder: Option<u64>,
        path: &str,
        file_name: &str,
        len: u64,
    ) -> Result<bool> {
        let index = path.rfind('/');
        let name = if !file_name.trim().is_empty() && index.is_some() {
            file_name.to_string()
        } else {
            path[index.map(|i| i + 1).unwrap_or(0)..].to_string()
        };
        let r = match existing {
            Some(id) => {
                sqlx::query("UPDATE files_file_system SET UPDATED_AT = CURRENT_TIMESTAMP, SIZE = ? WHERE ID = ?")
                    .bind(len)
                    .bind(id)
                    .execute(self.pool())
                    .await?
            }
            None => {
                sqlx::query(
                    "INSERT INTO files_file_system (CODE, PARENT_ID, FILE_TYPE, NAME, SIZE, TYPE) VALUES (?, ?, 'FILE', ?, ?, ?)",
                )
                .bind(cc)
                .bind(folder)
                .bind(&name)
                .bind(len)
                .bind(kind.db_name())
                .execute(self.pool())
                .await?
            }
        };
        Ok(r.rows_affected() > 0)
    }

    /// `deleteFile`: the row at `path` (and, by the foreign key, everything under it).
    pub async fn delete_file(&self, kind: Kind, cc: &str, path: &str) -> Result<bool> {
        let Some(id) = self.get_id(kind, cc, path).await? else { return Ok(false) };
        self.delete_by_id(id).await
    }

    pub async fn delete_by_id(&self, id: u64) -> Result<bool> {
        let r = sqlx::query("DELETE FROM files_file_system WHERE ID = ?").bind(id).execute(self.pool()).await?;
        Ok(r.rows_affected() > 0)
    }

    /// `createFolders`: every folder of every path, made once, parents first. Returns the id of
    /// each requested path.
    pub async fn create_folders(&self, kind: Kind, cc: &str, paths: &[String]) -> Result<HashMap<String, u64>> {
        // path -> (name, parent path)
        let mut nodes: HashMap<String, (String, Option<String>)> = HashMap::new();
        for path in paths {
            let mut acc = String::new();
            for part in java_split(path, '/') {
                let parent = (!acc.is_empty()).then(|| acc.clone());
                if !acc.is_empty() {
                    acc.push('/');
                }
                acc.push_str(&part);
                check_name(&part)?;
                nodes.entry(acc.clone()).or_insert((part.clone(), parent));
            }
        }
        let depth = |p: &str, nodes: &HashMap<String, (String, Option<String>)>| {
            let mut d = 0;
            let mut cur = nodes.get(p).and_then(|n| n.1.clone());
            while let Some(c) = cur {
                d += 1;
                cur = nodes.get(&c).and_then(|n| n.1.clone());
            }
            d
        };
        let mut order: Vec<String> = nodes.keys().cloned().collect();
        order.sort_by(|a, b| depth(a, &nodes).cmp(&depth(b, &nodes)).then_with(|| a.cmp(b)));

        let mut ids: HashMap<String, u64> = HashMap::new();
        for p in order {
            let (name, parent_path) = nodes[&p].clone();
            let parent = parent_path.as_ref().and_then(|pp| ids.get(pp).copied());
            let mut qb = QueryBuilder::new("SELECT ID FROM files_file_system WHERE CODE = ");
            qb.push_bind(cc);
            qb.push(" AND NAME = ");
            qb.push_bind(&name);
            qb.push(" AND TYPE = ");
            qb.push_bind(kind.db_name());
            qb.push(" AND ");
            parent_condition(&mut qb, parent);
            qb.push(" AND FILE_TYPE = 'DIRECTORY' LIMIT 1");
            let found = qb.build().fetch_optional(self.pool()).await?.map(|r| r.get::<u64, _>("ID"));
            let id = match found {
                Some(id) => id,
                None => self.insert_folder(kind, cc, parent, &name).await?,
            };
            ids.insert(p, id);
        }
        Ok(paths.iter().filter_map(|p| ids.get(p).map(|id| (p.clone(), *id))).collect())
    }

    /// `FileSystemDao.list`: the children of the folder at `path` (the client root when blank).
    pub async fn list(
        &self,
        kind: Kind,
        cc: &str,
        path: &str,
        file_types: &[FileType],
        filter: Option<&str>,
        page: &Pageable,
    ) -> Result<ListPage> {
        let folder = self.get_id(kind, cc, path).await?;
        if folder.is_none() && !path.trim().is_empty() {
            return Ok(ListPage { content: vec![], total: 0 });
        }

        let mut cond = Sql::default();
        cond.parts.push(Part::Text("CODE = ".into()));
        cond.parts.push(Part::Bind(Bind::Str(cc.to_string())));
        match folder {
            None => cond.parts.push(Part::Text(" AND PARENT_ID IS NULL".into())),
            Some(id) => {
                cond.parts.push(Part::Text(" AND PARENT_ID = ".into()));
                cond.parts.push(Part::Bind(Bind::U64(id)));
            }
        }
        cond.parts.push(Part::Text(" AND TYPE = ".into()));
        cond.parts.push(Part::Bind(Bind::Str(kind.db_name().into())));
        if let Some(f) = filter.filter(|f| !f.trim().is_empty()) {
            cond.parts.push(Part::Text(" AND NAME LIKE ".into()));
            cond.parts.push(Part::Bind(Bind::Str(format!("%{f}%"))));
        }
        if !file_types.is_empty() {
            cond.parts.push(Part::Text(" AND (".into()));
            for (i, ft) in file_types.iter().enumerate() {
                if i > 0 {
                    cond.parts.push(Part::Text(" OR ".into()));
                }
                match ft {
                    FileType::Directories => cond.parts.push(Part::Text("FILE_TYPE = 'DIRECTORY'".into())),
                    FileType::Files => cond.parts.push(Part::Text("FILE_TYPE = 'FILE'".into())),
                    other => {
                        cond.parts.push(Part::Text("(".into()));
                        for (j, e) in other.extensions().iter().enumerate() {
                            if j > 0 {
                                cond.parts.push(Part::Text(" OR ".into()));
                            }
                            cond.parts.push(Part::Text("NAME LIKE ".into()));
                            cond.parts.push(Part::Bind(Bind::Str(format!("%.{e}"))));
                        }
                        cond.parts.push(Part::Text(")".into()));
                    }
                }
            }
            cond.parts.push(Part::Text(")".into()));
        }

        let mut qb = QueryBuilder::new(format!("SELECT {FILE_COLUMNS} FROM files_file_system WHERE "));
        cond.push_to(&mut qb);
        qb.push(list_order(page));
        qb.push(" LIMIT ");
        qb.push_bind(page.size);
        qb.push(" OFFSET ");
        qb.push_bind(page.offset());
        let rows: Vec<FileRow> = qb.build_query_as().fetch_all(self.pool()).await?;

        let mut cq = QueryBuilder::new("SELECT COUNT(*) AS C FROM files_file_system WHERE ");
        cond.push_to(&mut cq);
        let total: i64 = cq.build().fetch_one(self.pool()).await?.try_get("C")?;

        Ok(ListPage { content: rows.iter().map(FileRow::detail).collect(), total })
    }

    /// `readExpired`: files of `kind` whose own lifetime has run out, oldest first.
    pub async fn read_expired(&self, kind: Kind, limit: i64) -> Result<Vec<ExpiredFile>> {
        let rows = sqlx::query(
            "SELECT ID, CODE, NAME, PARENT_ID FROM files_file_system WHERE TYPE = ? \
             AND EXPIRES_AFTER_MINUTES IS NOT NULL AND FILE_TYPE = 'FILE' \
             AND CURRENT_TIMESTAMP > TIMESTAMPADD(MINUTE, CAST(EXPIRES_AFTER_MINUTES AS SIGNED), UPDATED_AT) \
             ORDER BY UPDATED_AT ASC LIMIT ?",
        )
        .bind(kind.db_name())
        .bind(limit)
        .fetch_all(self.pool())
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let name: String = r.try_get("NAME")?;
            let parent: Option<u64> = r.try_get("PARENT_ID")?;
            out.push(ExpiredFile {
                id: r.try_get("ID")?,
                client_code: r.try_get("CODE")?,
                kind,
                path: self.full_path(parent, &name).await?,
            });
        }
        Ok(out)
    }

    /// `fullPath`: `/a/b/name`, walking parents (at most 64, in case of a cycle).
    pub async fn full_path(&self, parent: Option<u64>, name: &str) -> Result<String> {
        let mut path = name.to_string();
        let mut current = parent;
        for _ in 0..64 {
            let Some(id) = current else { break };
            let Some(r) = sqlx::query("SELECT NAME, PARENT_ID FROM files_file_system WHERE ID = ?")
                .bind(id)
                .fetch_optional(self.pool())
                .await?
            else {
                break;
            };
            let n: String = r.try_get("NAME")?;
            path = format!("{n}/{path}");
            current = r.try_get("PARENT_ID")?;
        }
        Ok(format!("/{path}"))
    }

    /// `sumBytesByClient`: stored bytes of a client, static and secured.
    pub async fn sum_bytes_by_client(&self, cc: &str) -> Result<i64> {
        let r = sqlx::query(
            "SELECT CAST(COALESCE(SUM(SIZE), 0) AS SIGNED) AS S FROM files_file_system WHERE CODE = ? AND FILE_TYPE = 'FILE'",
        )
        .bind(cc)
        .fetch_one(self.pool())
        .await?;
        Ok(r.try_get("S")?)
    }

    /// `clearFileSystem`: the rows a reconcile replaces.
    pub async fn clear_file_system(&self, kind: Kind, cc: Option<&str>, folder: Option<u64>) -> Result<u64> {
        let mut qb = QueryBuilder::new("DELETE FROM files_file_system WHERE TYPE = ");
        qb.push_bind(kind.db_name());
        if let Some(cc) = cc {
            qb.push(" AND CODE = ");
            qb.push_bind(cc);
        }
        if let Some(f) = folder {
            qb.push(" AND PARENT_ID = ");
            qb.push_bind(f);
        }
        Ok(qb.build().execute(self.pool()).await?.rows_affected())
    }

    /// `batchInsert` of discovered files: (client, parent, name, size).
    pub async fn insert_discovered(&self, kind: Kind, rows: &[(String, Option<u64>, String, i64)]) -> Result<()> {
        for chunk in rows.chunks(100) {
            let mut qb = QueryBuilder::new("INSERT INTO files_file_system (TYPE, CODE, NAME, FILE_TYPE, SIZE, PARENT_ID) ");
            qb.push_values(chunk, |mut b, (cc, parent, name, size)| {
                b.push_bind(kind.db_name())
                    .push_bind(cc.as_str())
                    .push_bind(name.as_str())
                    .push_bind("FILE")
                    .push_bind(*size)
                    .push_bind(*parent);
            });
            qb.build().execute(self.pool()).await?;
        }
        Ok(())
    }

    /// `readAppRootFolders`: clients with an `<appCode>` folder at their root, with its id.
    pub async fn read_app_root_folders(&self, kind: Kind, app_code: &str) -> Result<Vec<(String, u64)>> {
        let rows = sqlx::query(
            "SELECT CODE, ID FROM files_file_system WHERE TYPE = ? AND FILE_TYPE = 'DIRECTORY' \
             AND PARENT_ID IS NULL AND NAME = ? ORDER BY CODE ASC",
        )
        .bind(kind.db_name())
        .bind(app_code)
        .fetch_all(self.pool())
        .await?;
        let mut out: Vec<(String, u64)> = Vec::new();
        for r in rows {
            let cc: String = r.try_get("CODE")?;
            if !out.iter().any(|(c, _)| *c == cc) {
                out.push((cc, r.try_get("ID")?));
            }
        }
        Ok(out)
    }

    /// `readRootFolderId`.
    pub async fn read_root_folder_id(&self, kind: Kind, cc: &str, name: &str) -> Result<Option<u64>> {
        Ok(sqlx::query(
            "SELECT ID FROM files_file_system WHERE TYPE = ? AND CODE = ? AND PARENT_ID IS NULL AND NAME = ? \
             AND FILE_TYPE = 'DIRECTORY' LIMIT 1",
        )
        .bind(kind.db_name())
        .bind(cc)
        .bind(name)
        .fetch_optional(self.pool())
        .await?
        .map(|r| r.get::<u64, _>("ID")))
    }

    /// `readSubFolderId`: read only, never creates.
    pub async fn read_sub_folder_id(&self, kind: Kind, cc: &str, folder: u64, segments: &[String]) -> Result<Option<u64>> {
        let mut current = Some(folder);
        for seg in segments {
            let Some(id) = current else { return Ok(None) };
            current = sqlx::query(
                "SELECT ID FROM files_file_system WHERE TYPE = ? AND CODE = ? AND PARENT_ID = ? AND NAME = ? \
                 AND FILE_TYPE = 'DIRECTORY' LIMIT 1",
            )
            .bind(kind.db_name())
            .bind(cc)
            .bind(id)
            .bind(seg)
            .fetch_optional(self.pool())
            .await?
            .map(|r| r.get::<u64, _>("ID"));
        }
        Ok(current)
    }

    fn retention_tree(qb: &mut QueryBuilder<'_, sqlx::MySql>, kind: Kind, cc: &str, folder: u64, excluded: &[u64]) {
        qb.push(
            "WITH RECURSIVE retention_tree (ID, FILE_TYPE, REL_PATH, SIZE, UPDATED_AT, EXPIRES_AFTER_MINUTES) AS (\
             SELECT f.ID, f.FILE_TYPE, CAST('' AS CHAR(4096) CHARACTER SET utf8mb4) COLLATE utf8mb4_unicode_ci, \
             f.SIZE, f.UPDATED_AT, f.EXPIRES_AFTER_MINUTES FROM files_file_system f WHERE f.ID = ",
        );
        qb.push_bind(folder);
        qb.push(" AND f.CODE = ");
        qb.push_bind(cc.to_string());
        qb.push(" AND f.TYPE = ");
        qb.push_bind(kind.db_name());
        qb.push(
            " UNION ALL SELECT c.ID, c.FILE_TYPE, CONCAT(t.REL_PATH, '/', c.NAME), c.SIZE, c.UPDATED_AT, \
             c.EXPIRES_AFTER_MINUTES FROM files_file_system c JOIN retention_tree t ON c.PARENT_ID = t.ID \
             WHERE t.FILE_TYPE = 'DIRECTORY' AND c.CODE = ",
        );
        qb.push_bind(cc.to_string());
        qb.push(" AND c.TYPE = ");
        qb.push_bind(kind.db_name());
        if !excluded.is_empty() {
            qb.push(" AND c.ID NOT IN (");
            let mut sep = qb.separated(", ");
            for id in excluded {
                sep.push_bind(*id);
            }
            qb.push(")");
        }
        qb.push(")");
    }

    const RETENTION_ELIGIBLE: &'static str = " FROM retention_tree WHERE FILE_TYPE = 'FILE' \
        AND EXPIRES_AFTER_MINUTES IS NULL AND UPDATED_AT < DATE_SUB(CURRENT_TIMESTAMP, INTERVAL ";

    /// `readRetentionExpired`: files a policy of `days` would remove under `folder`, oldest first.
    #[allow(clippy::too_many_arguments)]
    pub async fn read_retention_expired(
        &self,
        kind: Kind,
        cc: &str,
        folder: u64,
        folder_path: &str,
        excluded: &[u64],
        days: i64,
        limit: i64,
    ) -> Result<Vec<ExpiredFile>> {
        if limit <= 0 {
            return Ok(vec![]);
        }
        let mut qb = Self::retention_expired_query(kind, cc, folder, excluded, days, limit);
        let rows = qb.build().fetch_all(self.pool()).await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let rel: String = r.try_get("REL_PATH")?;
            out.push(ExpiredFile {
                id: r.try_get("ID")?,
                client_code: cc.to_string(),
                kind,
                path: format!("{folder_path}{rel}"),
            });
        }
        Ok(out)
    }

    /// The statement `read_retention_expired` runs: the tree below `folder`, the eligible files,
    /// oldest first, at most `limit`.
    fn retention_expired_query(
        kind: Kind,
        cc: &str,
        folder: u64,
        excluded: &[u64],
        days: i64,
        limit: i64,
    ) -> QueryBuilder<'static, sqlx::MySql> {
        let mut qb = QueryBuilder::new("");
        Self::retention_tree(&mut qb, kind, cc, folder, excluded);
        qb.push(" SELECT ID, REL_PATH");
        qb.push(Self::RETENTION_ELIGIBLE);
        qb.push_bind(days);
        qb.push(" DAY) ORDER BY UPDATED_AT ASC, ID ASC LIMIT ");
        qb.push_bind(limit);
        qb
    }

    /// `countRetentionExpired`: (count, bytes) of what that would remove without a limit.
    pub async fn count_retention_expired(
        &self,
        kind: Kind,
        cc: &str,
        folder: u64,
        excluded: &[u64],
        days: i64,
    ) -> Result<(i64, i64)> {
        let mut qb = QueryBuilder::new("");
        Self::retention_tree(&mut qb, kind, cc, folder, excluded);
        qb.push(" SELECT COUNT(*) AS N, CAST(COALESCE(SUM(SIZE), 0) AS SIGNED) AS B");
        qb.push(Self::RETENTION_ELIGIBLE);
        qb.push_bind(days);
        qb.push(" DAY)");
        let r = qb.build().fetch_one(self.pool()).await?;
        Ok((r.try_get("N")?, r.try_get("B")?))
    }
}

/// `ORDER BY` of a listing: folders first then by name, or the requested sortable fields.
fn list_order(page: &Pageable) -> String {
    if !page.is_sorted() {
        // Qualified: a bare FILE_TYPE would name the select's CHAR alias and sort the enum as text.
        return " ORDER BY files_file_system.FILE_TYPE DESC, files_file_system.NAME ASC".into();
    }
    let cols: Vec<String> = page
        .sort
        .iter()
        .filter_map(|o| {
            let col = match o.property.to_uppercase().as_str() {
                "TYPE" => "FILE_TYPE",
                "NAME" => "NAME",
                "SIZE" => "SIZE",
                "LASTMODIFIED" => "UPDATED_AT",
                "CREATED" => "CREATED_AT",
                _ => return None,
            };
            Some(format!("files_file_system.{col} {}", if o.ascending { "ASC" } else { "DESC" }))
        })
        .collect();
    if cols.is_empty() {
        String::new()
    } else {
        format!(" ORDER BY {}", cols.join(", "))
    }
}

/// `String.split(char)`: trailing empty pieces dropped, leading and inner ones kept.
pub fn java_split(s: &str, sep: char) -> Vec<String> {
    let mut parts: Vec<String> = s.split(sep).map(str::to_string).collect();
    while parts.len() > 1 && parts.last().is_some_and(String::is_empty) {
        parts.pop();
    }
    if parts.len() == 1 && parts[0].is_empty() && !s.is_empty() {
        parts.clear();
    }
    parts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spring::Order;

    #[test]
    fn java_split_semantics() {
        assert_eq!(java_split("a//b/", '/'), vec!["a", "", "b"]);
        assert_eq!(java_split("/a", '/'), vec!["", "a"]);
        assert_eq!(java_split("", '/'), vec![""]);
        assert!(java_split("//", '/').is_empty());
    }

    #[test]
    fn listing_order() {
        assert_eq!(
            list_order(&Pageable::of(0, 20, vec![])),
            " ORDER BY files_file_system.FILE_TYPE DESC, files_file_system.NAME ASC"
        );
        assert_eq!(
            list_order(&Pageable::of(0, 20, vec![Order::new("lastModified", false), Order::new("bogus", true)])),
            " ORDER BY files_file_system.UPDATED_AT DESC"
        );
        assert_eq!(list_order(&Pageable::of(0, 20, vec![Order::new("bogus", true)])), "");
    }

    #[test]
    fn file_types() {
        assert_eq!(FileType::parse("IMAGES"), Some(FileType::Images));
        assert_eq!(FileType::parse("images"), None);
        assert!(FileType::Images.extensions().contains(&"webp"));
    }


    #[test]
    fn every_file_type() {
        for (s, t) in [
            ("ARCHIVE", FileType::Archive),
            ("DOCUMENTS", FileType::Documents),
            ("VIDEOS", FileType::Videos),
            (" DIRECTORIES ", FileType::Directories),
            ("FILES", FileType::Files),
        ] {
            assert_eq!(FileType::parse(s), Some(t));
        }
        assert!(FileType::Directories.extensions().is_empty() && FileType::Files.extensions().is_empty());
        assert!(FileType::Archive.extensions().contains(&"zip") && FileType::Videos.extensions().contains(&"mp4"));
        assert!(FileType::Documents.extensions().contains(&"pdf"));
    }

    /// `FileSystemDaoRetentionTest.retentionSelectionSkipsFilesWithTheirOwnLifetimeAndStaysInTheClient`,
    /// the statement half (the gated `live_mysql` test runs it): files without their own lifetime,
    /// every step held to the client and type, the nested folders left out, in Java's bind order
    /// (folder, client, type, client, type, excluded..., days, limit).
    #[test]
    fn retention_statement_like_java() {
        use sqlx::{Arguments, Execute};
        let mut qb = Dao::retention_expired_query(Kind::Static, "C1", 100, &[101, 102], 30, 25);
        let sql = qb.sql().to_string();
        assert!(sql.starts_with("WITH RECURSIVE retention_tree"), "{sql}");
        assert!(sql.contains("f.ID = ? AND f.CODE = ? AND f.TYPE = ?"), "{sql}");
        assert!(sql.contains("EXPIRES_AFTER_MINUTES IS NULL"), "{sql}");
        assert!(sql.contains("FILE_TYPE = 'FILE'"), "{sql}");
        assert!(sql.contains("c.CODE = ? AND c.TYPE = ?"), "{sql}");
        assert!(sql.contains("c.ID NOT IN (?, ?)"), "{sql}");
        assert!(sql.contains("INTERVAL ? DAY"), "{sql}");
        assert!(sql.ends_with("ORDER BY UPDATED_AT ASC, ID ASC LIMIT ?"), "{sql}");
        let mut q = qb.build();
        assert_eq!(q.take_arguments().unwrap().unwrap().len(), 9);
        let none = Dao::retention_expired_query(Kind::Secured, "C1", 1, &[], 30, 5);
        assert!(!none.sql().contains("NOT IN"));
    }

    /// `FileSystemDaoRetentionTest.retentionSelectionWithZeroLimitReadsNothing`: no statement at
    /// all (the pool here cannot reach any server).
    #[tokio::test]
    async fn retention_selection_with_zero_limit_reads_nothing() {
        let pool = sqlx::mysql::MySqlPoolOptions::new().connect_lazy("mysql://nobody@127.0.0.1:1/none").unwrap();
        let dao = Dao::new(pool);
        assert!(dao.read_retention_expired(Kind::Static, "C1", 1, "/app", &[], 30, 0).await.unwrap().is_empty());
        assert!(dao.get_id(Kind::Static, "C1", " ").await.unwrap().is_none());
        assert!(dao.get_folder_id(Kind::Static, "C1", "").await.unwrap().is_none());
        assert!(dao.file_detail(Kind::Static, "C1", &[]).await.unwrap().is_none());
    }
}
