//! `FileSystemService` for the writes: one per file system type, over the bucket, the tree rows
//! and the three per-client caches every write evicts everywhere (`fsPathExists`,
//! `fsGetDetail`, `fsPathList`, under the configured prefix).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use futures::stream::{self, TryStreamExt};

use crate::dao::FileDetail;
use crate::errors::{check_name, err_as, UNKNOWN_ERROR};
use crate::fsdao::{ExpiredFile, FileType, ListPage};
use crate::paths::Kind;
use crate::spring::Pageable;
use crate::state::AppState;
use crate::store::collapse_slashes;

pub type FilesPage = ListPage;

/// A file in the work directory, removed when dropped.
pub struct TempFile {
    pub path: PathBuf,
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// A folder in the work directory, removed with everything in it when dropped.
pub struct TempDir {
    pub path: PathBuf,
}

impl TempDir {
    pub fn new(state: &AppState, label: &str) -> Result<Self> {
        let suffix: u64 = rand::random();
        let path = state.work_dir().join(format!("{label}-{suffix:x}"));
        std::fs::create_dir_all(&path).with_context(|| format!("creating {}", path.display()))?;
        Ok(Self { path })
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// The MIME type a write stores with the object: by file name, else octet-stream.
pub fn mime_of(name: &str) -> &'static str {
    mime_guess::from_path(name).first_raw().unwrap_or("application/octet-stream")
}

pub struct Fs<'a> {
    pub st: &'a AppState,
    pub kind: Kind,
}

impl<'a> Fs<'a> {
    pub fn new(st: &'a AppState, kind: Kind) -> Self {
        Self { st, kind }
    }

    fn cache_names(&self, cc: &str) -> [String; 3] {
        let t = self.kind.db_name();
        [
            format!("fsPathExists-{t}-{cc}"),
            format!("fsGetDetail-{t}-{cc}"),
            format!("fsPathList-{t}-{cc}"),
        ]
    }

    /// `evictCache(clientCode)`: here, on every other Rust instance and on every Java instance.
    pub async fn evict(&self, cc: &str) {
        for name in self.cache_names(cc) {
            self.st.cache().evict_all_everywhere(&name).await;
        }
    }

    /// `exists(clientCode, path)`, cached (a `false` too) until the client's next write.
    pub async fn exists(&self, cc: &str, path: &str) -> Result<bool> {
        if path.trim().is_empty() || path == "/" {
            return Ok(true);
        }
        let name = format!("fsPathExists-{}-{cc}", self.kind.db_name());
        let dao = self.st.dao().clone();
        let (kind, cc_owned, p) = (self.kind, cc.to_string(), path.to_string());
        Ok(self
            .st
            .inner()
            .exists
            .get_or_load(&name, path.to_string(), || async move {
                Ok::<_, anyhow::Error>(Some(dao.get_id(kind, &cc_owned, &p).await?.is_some()))
            })
            .await?
            .unwrap_or(false))
    }

    pub async fn detail(&self, cc: &str, path: &str) -> Result<Option<FileDetail>> {
        self.st.client_file_detail(self.kind, cc, path).await
    }

    /// `FileSystemService.list`: the plain first page (no filters, unsorted, 200) is cached.
    pub async fn list(
        &self,
        cc: &str,
        path: &str,
        types: &[FileType],
        filter: Option<&str>,
        page: &Pageable,
    ) -> Result<ListPage> {
        let plain = types.is_empty()
            && filter.is_none_or(|f| f.trim().is_empty())
            && !page.is_sorted()
            && page.page == 0
            && page.size == 200;
        if !plain {
            return self.st.dao().list(self.kind, cc, path, types, filter, page).await;
        }
        let name = format!("fsPathList-{}-{cc}", self.kind.db_name());
        let dao = self.st.dao().clone();
        let (kind, cc_owned, p, pg) = (self.kind, cc.to_string(), path.to_string(), page.clone());
        Ok(self
            .st
            .inner()
            .lists
            .get_or_load(&name, path.to_string(), || async move {
                Ok::<_, anyhow::Error>(Some(dao.list(kind, &cc_owned, &p, &[], None, &pg).await?))
            })
            .await?
            .unwrap_or(ListPage { content: vec![], total: 0 }))
    }

    /// `createFileFromInputStream` with the bytes already in a local file.
    ///
    /// The name is checked before the object is written (Java writes the object first and then
    /// refuses the name, leaving an object no row points at), and the caches are evicted after
    /// the row is written, so nobody caches the state in between.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_from_file(
        &self,
        cc: &str,
        path: &str,
        file_name: Option<&str>,
        src: &Path,
        len: u64,
        overwrite: bool,
        disposition: &str,
        expires_after_minutes: Option<u32>,
    ) -> Result<Option<FileDetail>> {
        let file_path = match file_name {
            None => path.to_string(),
            Some(f) => format!("{path}/{f}"),
        };
        let file_path = collapse_slashes(&file_path);
        let exists = self.exists(cc, &file_path).await?;
        if exists && !overwrite {
            return self.detail(cc, &file_path).await;
        }

        let index = file_path.rfind('/');
        let name = match (file_name.filter(|f| !f.trim().is_empty()), index) {
            (Some(f), Some(_)) => f.to_string(),
            _ => file_path[index.map(|i| i + 1).unwrap_or(0)..].to_string(),
        };
        check_name(&name)?;

        let key = if file_path.starts_with('/') { format!("{cc}{file_path}") } else { format!("{cc}/{file_path}") };
        let store = self.st.store(self.kind);
        store.put_file(&key, src, len, Some(mime_of(&file_path)), disposition).await?;
        store.drop_local_copies(&key).await;
        let detail = self
            .st
            .dao()
            .create_or_update_file(self.kind, cc, &file_path, file_name, len, exists && overwrite, expires_after_minutes)
            .await;
        self.evict(cc).await;
        detail
    }

    /// `deleteFile(<clientCode>/<path>)`: the object at that key, then the row (and the rows
    /// under it). The caller evicts.
    pub async fn delete(&self, full: &str) -> Result<bool> {
        let (cc, rest) = match full.find('/') {
            Some(i) => (&full[..i], &full[i + 1..]),
            None => (full, ""),
        };
        let key = collapse_slashes(full);
        let store = self.st.store(self.kind);
        store.delete_object(&key).await?;
        store.drop_local_copies(&key).await;
        self.st.dao().delete_file(self.kind, cc, rest).await
    }

    /// `FileSystemService.createFolder`: every missing folder of `path`, then the last one's
    /// detail. The caller evicts.
    pub async fn create_folder(&self, cc: &str, path: &str) -> Result<Option<FileDetail>> {
        let rp = path.strip_prefix('/').unwrap_or(path);
        let mut acc = String::new();
        let mut prefixes = Vec::new();
        for (i, part) in crate::fsdao::java_split(rp, '/').iter().enumerate() {
            if i > 0 {
                acc.push('/');
            }
            acc.push_str(part);
            prefixes.push(acc.clone());
        }
        let dao = self.st.dao();
        for p in prefixes {
            if dao.get_id(self.kind, cc, &p).await?.is_some() {
                continue;
            }
            dao.create_folder(self.kind, cc, &p).await?;
        }
        dao.detail_of(self.kind, cc, path).await
    }

    /// The object at `key` in a file of its own (`getAsFile(key, true)` for one-off reads).
    pub async fn fetch(&self, key: &str, dir: &TempDir) -> Result<PathBuf> {
        let name = key.rsplit('/').next().filter(|n| !n.is_empty()).unwrap_or("file");
        let suffix: u64 = rand::random();
        let target = dir.path.join(format!("{suffix:x}-{name}"));
        self.st.store(self.kind).download_to(key, &target).await?;
        Ok(target)
    }

    /// `copyFile`: a file of one client's tree written into another's (overwriting).
    pub async fn copy_file(
        &self,
        src_cc: &str,
        src_path: &str,
        dest_cc: &str,
        dest_path: &str,
        file_name: &str,
    ) -> Result<Option<FileDetail>> {
        let src_file = format!("{}/{file_name}", src_path.strip_prefix('/').unwrap_or(src_path));
        // Java reports a missing source as its catch-all `unknown_error`, a 500.
        let unknown = || anyhow::Error::from(err_as("FILES.COPY_SOURCE_MISSING", axum::http::StatusCode::INTERNAL_SERVER_ERROR, UNKNOWN_ERROR, &[]));
        match self.detail(src_cc, &src_file).await? {
            Some(d) if !d.is_directory => {}
            _ => return Err(unknown()),
        }
        let key = format!("{src_cc}/{src_file}");
        let dir = TempDir::new(self.st, "copy")?;
        let local = self.fetch(&key, &dir).await.map_err(|_| unknown())?;
        let len = tokio::fs::metadata(&local).await?.len();
        self.create_from_file(dest_cc, dest_path, Some(file_name), &local, len, true, "inline", None)
            .await
    }

    /// `createFileForZipUpload`: one extracted file, unless it exists and may not be replaced.
    pub async fn zip_upload_file(&self, cc: &str, folder: Option<u64>, path: &str, file: &Path, overwrite: bool) -> Result<()> {
        let dao = self.st.dao();
        let existing = dao.get_id_in_folder(self.kind, cc, folder, path).await?;
        if existing.is_some() && !overwrite {
            return Ok(());
        }
        let key = format!("{cc}/{path}").replace("//", "/");
        let len = tokio::fs::metadata(file).await?.len();
        let store = self.st.store(self.kind);
        store.put_file(&key, file, len, Some(mime_of(path)), "inline").await?;
        store.drop_local_copies(&key).await;
        let file_name = file.file_name().and_then(|n| n.to_str()).unwrap_or("");
        dao.zip_upsert(existing, self.kind, cc, folder, path, file_name, len).await?;
        Ok(())
    }

    /// `deleteFiles`: object first, row second, eviction after each; a failure is logged and the
    /// pass goes on. Files of the other type are refused, never deleted from this bucket.
    pub async fn delete_files(&self, files: Vec<ExpiredFile>) -> Vec<ExpiredFile> {
        let mut removed = Vec::new();
        for f in files {
            if f.kind != self.kind {
                tracing::error!(kind = ?f.kind, path = f.path, "refusing to remove a file of the other type");
                continue;
            }
            let key = format!("{}{}", f.client_code, f.path).replace("//", "/");
            let res: Result<()> = async {
                let store = self.st.store(self.kind);
                store.delete_object(&key).await?;
                store.drop_local_copies(&key).await;
                self.st.dao().delete_by_id(f.id).await?;
                Ok(())
            }
            .await;
            match res {
                Ok(()) => {
                    self.evict(&f.client_code).await;
                    removed.push(f);
                }
                Err(e) => tracing::error!(key, error = %e, "could not remove the expired file"),
            }
        }
        removed
    }

    /// `deleteExpired`: files whose own lifetime has run out, at most `limit`.
    pub async fn delete_expired(&self, limit: i64) -> Result<usize> {
        let files = self.st.dao().read_expired(self.kind, limit).await?;
        let removed = self.delete_files(files).await;
        if !removed.is_empty() {
            tracing::info!(count = removed.len(), kind = self.kind.db_name(), "removed expired files");
        }
        Ok(removed.len())
    }

    /// `getDirectoryAsArchive`: every object under `<clientCode>/<path>/` in one zip, entries
    /// relative to that folder.
    pub async fn directory_archive(&self, fp: &str, dir: &TempDir) -> Result<PathBuf> {
        let mut prefix = if fp.ends_with('/') { fp.to_string() } else { format!("{fp}/") };
        if let Some(p) = prefix.strip_prefix('/') {
            prefix = p.to_string();
        }
        let staging = dir.path.join("staging");
        tokio::fs::create_dir_all(&staging).await?;
        let objects = self.st.store(self.kind).list_objects(&prefix).await?;
        let jobs: Vec<(String, PathBuf)> = objects
            .into_iter()
            .filter_map(|(key, _)| {
                let rel = key.get(prefix.len()..)?.trim_start_matches('/').to_string();
                if rel.is_empty() || rel.ends_with('/') {
                    return None;
                }
                let target = safe_join(&staging, &rel)?;
                Some((key, target))
            })
            .collect();
        let store = self.st.store(self.kind).clone();
        stream::iter(jobs.into_iter().map(Ok::<_, anyhow::Error>))
            .try_for_each_concurrent(8, |(key, target)| {
                let store = store.clone();
                async move {
                    if let Some(parent) = target.parent() {
                        tokio::fs::create_dir_all(parent).await?;
                    }
                    store.download_to(&key, &target).await
                }
            })
            .await?;

        let zip_path = dir.path.join("directory.zip");
        let (zp, sp) = (zip_path.clone(), staging.clone());
        tokio::task::spawn_blocking(move || crate::zipio::zip_folder(&sp, &zp)).await??;
        Ok(zip_path)
    }

    /// `populateFileSystem`: rebuilds the rows of a client (or of every client) from the bucket.
    pub async fn populate(&self, cc: Option<&str>, folder_path: Option<&str>) -> Result<()> {
        let dao = self.st.dao();
        let folder = match (cc, folder_path) {
            (Some(cc), Some(fp)) => dao.get_id(self.kind, cc, fp).await?,
            _ => None,
        };
        dao.clear_file_system(self.kind, cc, folder).await?;
        let prefix = match cc {
            None => String::new(),
            Some(cc) => match (folder, folder_path) {
                (Some(_), Some(fp)) => format!("{cc}/{fp}/"),
                _ => format!("{cc}/"),
            },
        };
        let mut folder_ids: HashMap<String, Option<u64>> = HashMap::new();
        if let (Some(id), Some(fp)) = (folder, folder_path) {
            folder_ids.insert(fp.to_string(), Some(id));
        }
        let mut clients: Vec<String> = Vec::new();
        let mut rows = Vec::new();
        for (key, size) in self.st.store(self.kind).list_objects(&prefix).await? {
            if key.starts_with("js") || key.starts_with('/') {
                continue;
            }
            let Some(i) = key.rfind('/') else { continue };
            let (folder_key, name) = (&key[..i], &key[i + 1..]);
            let first = folder_key.find('/');
            let client = match first {
                None => folder_key.to_string(),
                Some(j) => key[..j].to_string(),
            };
            if !folder_ids.contains_key(folder_key) {
                let id = match first {
                    None => None,
                    Some(j) => dao.get_folder_id(self.kind, &client, &folder_key[j + 1..]).await?,
                };
                folder_ids.insert(folder_key.to_string(), id);
            }
            if !clients.contains(&client) {
                clients.push(client.clone());
            }
            rows.push((client, folder_ids[folder_key], name.to_string(), size));
        }
        dao.insert_discovered(self.kind, &rows).await?;
        for c in clients {
            self.evict(&c).await;
        }
        Ok(())
    }
}

/// `base/rel` for a relative path with no `..`, root or prefix components.
pub fn safe_join(base: &Path, rel: &str) -> Option<PathBuf> {
    let mut out = base.to_path_buf();
    for part in rel.split('/') {
        match part {
            "" | "." => continue,
            ".." => return None,
            p if p.contains('\\') || p.contains(':') && cfg!(windows) => return None,
            p => out.push(p),
        }
    }
    (out != base).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_join_refuses_escapes() {
        let b = Path::new("/tmp/x");
        assert_eq!(safe_join(b, "a/b.txt"), Some(PathBuf::from("/tmp/x/a/b.txt")));
        assert_eq!(safe_join(b, "../e"), None);
        assert_eq!(safe_join(b, "a/../../e"), None);
        assert_eq!(safe_join(b, ""), None);
    }

    #[test]
    fn mime_by_name() {
        assert_eq!(mime_of("a/b.png"), "image/png");
        assert_eq!(mime_of("noext"), "application/octet-stream");
    }
}
