use std::path::{Path, PathBuf};
use std::sync::Arc;

use platform::cache::{CacheService, LocalCaches};
use platform::security::SecurityClient;

use crate::config::FilesConfig;

use crate::dao::{Dao, FileDetail};
use crate::fs::FilesPage;
use crate::paths::{path_parts, split_client_code, Kind};
use crate::retention::PolicyRow;
use crate::store::Store;

#[derive(Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

pub struct Inner {
    pub dao: Dao,
    pub static_store: Store,
    pub secured_store: Store,
    pub details: Arc<LocalCaches<String, FileDetail>>,
    /// `fsPathExists-<TYPE>-<clientCode>`.
    pub exists: Arc<LocalCaches<String, bool>>,
    /// `fsPathList-<TYPE>-<clientCode>`.
    pub lists: Arc<LocalCaches<String, FilesPage>>,
    /// `filesRetentionPolicies` and `filesRetentionHierarchy`.
    pub retention_rows: Arc<LocalCaches<String, Vec<PolicyRow>>>,
    pub hierarchies: Arc<LocalCaches<String, Vec<String>>>,
    /// For evictions this unit causes (writes), published to every instance, Java included.
    pub cache: CacheService,
    pub security: SecurityClient,
    pub server_port: u16,
    pub config: FilesConfig,
    /// Scratch space for uploads, zips and transforms; each user gets its own subfolder.
    pub work_dir: PathBuf,
}

impl AppState {
    pub fn new(inner: Inner) -> Self {
        Self { inner: Arc::new(inner) }
    }

    pub fn inner(&self) -> &Inner {
        &self.inner
    }

    pub fn config(&self) -> &FilesConfig {
        &self.inner.config
    }

    pub fn cache(&self) -> &CacheService {
        &self.inner.cache
    }

    pub fn dao(&self) -> &Dao {
        &self.inner.dao
    }

    pub fn security(&self) -> &SecurityClient {
        &self.inner.security
    }

    pub fn server_port(&self) -> u16 {
        self.inner.server_port
    }

    pub fn work_dir(&self) -> &Path {
        &self.inner.work_dir
    }

    pub fn store(&self, kind: Kind) -> &Store {
        match kind {
            Kind::Static => &self.inner.static_store,
            Kind::Secured => &self.inner.secured_store,
        }
    }

    /// `FileSystemService.getFileDetail(path)`: `<clientCode>/<rest>`, cached per client in
    /// `fsGetDetail-<TYPE>-<clientCode>` (the cache the Java writes evict), keyed by `<rest>`.
    pub async fn file_detail(&self, kind: Kind, full_path: &str) -> anyhow::Result<Option<FileDetail>> {
        let (client_code, rest) = split_client_code(full_path);
        self.client_file_detail(kind, client_code, rest).await
    }

    /// `FileSystemService.getFileDetail(clientCode, path)`.
    pub async fn client_file_detail(
        &self,
        kind: Kind,
        client_code: &str,
        rest: &str,
    ) -> anyhow::Result<Option<FileDetail>> {
        if rest.trim().is_empty() {
            // The client's root: a directory with no row.
            return Ok(Some(FileDetail::root()));
        }
        let cache_name = format!("fsGetDetail-{}-{}", kind.db_name(), client_code);
        let dao = self.inner.dao.clone();
        let cc = client_code.to_string();
        let rest_owned = rest.to_string();
        self.inner
            .details
            .get_or_load(&cache_name, rest.to_string(), || async move {
                dao.file_detail(kind, &cc, &path_parts(&rest_owned)).await
            })
            .await
    }
}
