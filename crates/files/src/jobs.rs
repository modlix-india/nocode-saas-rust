//! Zip import and export: the `files_upload_download` rows that track them and the background
//! work, on tokio tasks instead of Java's virtual-thread pool.
//!
//! One deliberate difference from Java: a job's row says DONE only once every file is written
//! and the caches are evicted, and says ERROR (with the message) when the job fails. Java marks
//! an import DONE as soon as the per-file uploads are queued, and leaves a failed job PENDING
//! for ever.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use std::future::Future;
use std::pin::Pin;
use platform::error::AppError;
use serde_json::Value;
use sqlx::{FromRow, QueryBuilder};

use crate::condition::{ColType, Table};
use crate::errors::UNABLE_TO_UPLOAD_ZIP_FILE;
use crate::fs::{Fs, TempDir};
use crate::jackson::Obj;
use crate::paths::Kind;
use crate::spring::Pageable;
use crate::state::AppState;

pub const TABLE: Table = Table {
    name: "files_upload_download",
    columns: &[
        ("ID", ColType::Num),
        ("TYPE", ColType::Enum),
        ("RESOURCE_TYPE", ColType::Enum),
        ("CLIENT_CODE", ColType::Str),
        ("PATH", ColType::Str),
        ("CDN_URL", ColType::Str),
        ("STATUS", ColType::Enum),
        ("EXCEPTION", ColType::Str),
        ("CREATED_BY", ColType::Num),
        ("CREATED_AT", ColType::Ts),
        ("UPDATED_BY", ColType::Num),
        ("UPDATED_AT", ColType::Ts),
    ],
};

const COLUMNS: &str = "ID, CAST(TYPE AS CHAR) AS TYPE, CAST(RESOURCE_TYPE AS CHAR) AS RESOURCE_TYPE, CLIENT_CODE, \
    PATH, CDN_URL, CAST(STATUS AS CHAR) AS STATUS, EXCEPTION, CREATED_BY, CREATED_AT, UPDATED_BY, UPDATED_AT";

/// `FilesUploadDownloadDTO`.
#[derive(Debug, Clone, FromRow)]
pub struct JobRow {
    #[sqlx(rename = "ID")]
    pub id: u64,
    #[sqlx(rename = "TYPE")]
    pub kind: String,
    #[sqlx(rename = "RESOURCE_TYPE")]
    pub resource_type: String,
    #[sqlx(rename = "CLIENT_CODE")]
    pub client_code: String,
    #[sqlx(rename = "PATH")]
    pub path: String,
    #[sqlx(rename = "CDN_URL")]
    pub cdn_url: Option<String>,
    #[sqlx(rename = "STATUS")]
    pub status: String,
    #[sqlx(rename = "EXCEPTION")]
    pub exception: Option<String>,
    #[sqlx(rename = "CREATED_BY")]
    pub created_by: Option<u64>,
    #[sqlx(rename = "CREATED_AT")]
    pub created_at: Option<DateTime<Utc>>,
    #[sqlx(rename = "UPDATED_BY")]
    pub updated_by: Option<u64>,
    #[sqlx(rename = "UPDATED_AT")]
    pub updated_at: Option<DateTime<Utc>>,
}

fn opt<T: Into<Value>>(v: Option<T>) -> Value {
    v.map(Into::into).unwrap_or(Value::Null)
}

impl JobRow {
    pub fn json(&self) -> Value {
        Obj::new()
            .put("id", self.id)
            .put("createdAt", opt(self.created_at.map(|t| t.timestamp())))
            .put("createdBy", opt(self.created_by))
            .put("updatedAt", opt(self.updated_at.map(|t| t.timestamp())))
            .put("updatedBy", opt(self.updated_by))
            .put("type", self.kind.as_str())
            .put("resourceType", self.resource_type.as_str())
            .put("clientCode", self.client_code.as_str())
            .put("path", self.path.as_str())
            .put("cdnUrl", opt(self.cdn_url.clone()))
            .put("status", self.status.as_str())
            .put("exception", opt(self.exception.clone()))
            .build()
    }
}

/// `FilesUploadDownloadService.create`: a PENDING row, created by the caller.
pub async fn create_row(
    st: &AppState,
    upload: bool,
    kind: Kind,
    cc: &str,
    path: &str,
    cdn_url: Option<&str>,
    user: u64,
) -> Result<u64> {
    let r = sqlx::query(
        "INSERT INTO files_upload_download (TYPE, RESOURCE_TYPE, CLIENT_CODE, PATH, CDN_URL, CREATED_BY) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(if upload { "UPLOAD" } else { "DOWNLOAD" })
    .bind(kind.db_name())
    .bind(cc)
    .bind(path)
    .bind(cdn_url)
    .bind((user != 0).then_some(user))
    .execute(st.dao().pool())
    .await?;
    Ok(r.last_insert_id())
}

async fn mark(st: &AppState, id: u64, error: Option<String>) {
    let r = match &error {
        None => sqlx::query("UPDATE files_upload_download SET STATUS = 'DONE' WHERE ID = ?").bind(id).execute(st.dao().pool()).await,
        Some(e) => {
            sqlx::query("UPDATE files_upload_download SET STATUS = 'ERROR', EXCEPTION = ? WHERE ID = ?")
                .bind(e)
                .bind(id)
                .execute(st.dao().pool())
                .await
        }
    };
    if let Err(e) = r {
        tracing::error!(id, error = %e, "could not record the job status");
    }
}

/// `listExportsImports`: the caller's own jobs of one kind for a client.
pub async fn list(st: &AppState, upload: bool, kind: Kind, cc: &str, user: u64, page: &Pageable) -> Result<Value> {
    let push_where = |qb: &mut QueryBuilder<'_, sqlx::MySql>| {
        qb.push(" WHERE CLIENT_CODE = ");
        qb.push_bind(cc.to_string());
        qb.push(" AND TYPE = ");
        qb.push_bind(if upload { "UPLOAD" } else { "DOWNLOAD" });
        qb.push(" AND RESOURCE_TYPE = ");
        qb.push_bind(kind.db_name());
        qb.push(" AND CREATED_BY = ");
        qb.push_bind(user);
    };
    let mut cq = QueryBuilder::new("SELECT COUNT(*) AS C FROM files_upload_download");
    push_where(&mut cq);
    let total: i64 = sqlx::Row::try_get(&cq.build().fetch_one(st.dao().pool()).await?, "C")?;

    let mut qb = QueryBuilder::new(format!("SELECT {COLUMNS} FROM files_upload_download"));
    push_where(&mut qb);
    qb.push(crate::condition::order_by(&page.sort, &TABLE));
    qb.push(" LIMIT ");
    qb.push_bind(page.size);
    qb.push(" OFFSET ");
    qb.push_bind(page.offset());
    let rows: Vec<JobRow> = qb.build_query_as().fetch_all(st.dao().pool()).await?;
    let content: Vec<Value> = rows.iter().map(JobRow::json).collect();
    let total = crate::spring::known_total(content.len(), page).unwrap_or(total);
    Ok(crate::spring::page_json(content, page, total))
}

/// Runs a job in the background and records how it ended.
fn spawn_job<F>(st: AppState, id: u64, what: &'static str, job: F)
where
    F: std::future::Future<Output = Result<()>> + Send + 'static,
{
    tokio::spawn(async move {
        match job.await {
            Ok(()) => mark(&st, id, None).await,
            Err(e) => {
                tracing::error!(id, job = what, error = %format!("{e:#}"), "files job failed");
                let msg = match e.downcast_ref::<AppError>() {
                    Some(a @ (AppError::Message { .. } | AppError::Coded(_))) => crate::errors::java_message(a),
                    _ => format!("{e:#}"),
                };
                mark(&st, id, Some(msg)).await;
            }
        }
    });
}

/// `createFromZipFile`: the zip is already in `dir`; extraction and upload run in the background.
#[allow(clippy::too_many_arguments)]
pub fn start_import(st: AppState, id: u64, kind: Kind, cc: String, rp: String, zip: PathBuf, dir: TempDir, overwrite: bool) {
    let st2 = st.clone();
    spawn_job(st, id, "import", async move {
        let res = import(&st2, kind, &cc, &rp, &zip, &dir.path, overwrite).await;
        Fs::new(&st2, kind).evict(&cc).await;
        drop(dir);
        res
    });
}

async fn import(st: &AppState, kind: Kind, cc: &str, rp: &str, zip: &Path, dir: &Path, overwrite: bool) -> Result<()> {
    let is_root = rp.trim().is_empty();
    let (z, out) = (zip.to_path_buf(), dir.join("x"));
    let extracted = tokio::task::spawn_blocking(move || {
        std::fs::create_dir_all(&out)?;
        crate::zipio::extract(&z, &out)
    })
    .await??;

    let mut folders = Vec::new();
    if !is_root {
        folders.push(rp.to_string());
    }
    for f in &extracted.folders {
        folders.push(if is_root { f.clone() } else { format!("{rp}/{f}") });
    }
    let folder_ids = st.dao().create_folders(kind, cc, &folders).await?;

    let mut uploads = Vec::new();
    for (entry, local) in &extracted.files {
        let parent = entry.rfind('/').map(|i| &entry[..i]).unwrap_or("");
        let folder_path = if is_root {
            parent.to_string()
        } else if parent.trim().is_empty() {
            rp.to_string()
        } else {
            format!("{rp}/{parent}")
        };
        let folder = folder_ids.get(&folder_path).copied();
        if !folder_path.is_empty() && folder.is_none() {
            return Err(anyhow::Error::from(crate::errors::status(StatusCode::BAD_REQUEST, UNABLE_TO_UPLOAD_ZIP_FILE, &[])));
        }
        let path = if folder_path.is_empty() { entry.clone() } else { format!("{rp}/{entry}") };
        uploads.push((folder, path, local.clone()));
    }

    let mut results: Vec<Result<()>> = Vec::with_capacity(uploads.len());
    for chunk in uploads.chunks(8) {
        let futs: Vec<Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>> = chunk
            .iter()
            .map(|(folder, path, local)| {
                Box::pin(upload_one(st, kind, cc, *folder, path, local, overwrite))
                    as Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>
            })
            .collect();
        results.extend(futures::future::join_all(futs).await);
    }
    // Every file is tried; the first failure is what the row records.
    results.into_iter().collect::<Result<Vec<()>>>()?;
    Ok(())
}

async fn upload_one(
    st: &AppState,
    kind: Kind,
    cc: &str,
    folder: Option<u64>,
    path: &str,
    local: &Path,
    overwrite: bool,
) -> Result<()> {
    Fs::new(st, kind)
        .zip_upload_file(cc, folder, path, local, overwrite)
        .await
        .with_context(|| format!("uploading {path}"))
}

/// `asyncExportFolder`: zips the folder and stores it at the row's `cdnUrl` in the background.
pub fn start_export(st: AppState, id: u64, kind: Kind, cc: String, rp: String, cdn_url: String) {
    let st2 = st.clone();
    spawn_job(st, id, "export", async move {
        let fs = Fs::new(&st2, kind);
        let dir = TempDir::new(&st2, "export")?;
        let archive = fs.directory_archive(&format!("{cc}/{rp}"), &dir).await?;
        let name = rp.rsplit('/').next().unwrap_or("");
        let (cdn_path, cdn_file) = cdn_url.rsplit_once('/').unwrap_or(("", cdn_url.as_str()));
        let len = tokio::fs::metadata(&archive).await?.len();
        fs.create_from_file(
            &cc,
            cdn_path,
            Some(cdn_file),
            &archive,
            len,
            true,
            &format!("attachment; filename=\"{name}.zip\""),
            None,
        )
        .await?;
        fs.evict(&cc).await;
        Ok(())
    });
}
