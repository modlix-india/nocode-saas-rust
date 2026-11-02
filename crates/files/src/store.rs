//! The object store (Cloudflare R2 over the S3 API) and this instance's disk copy of what it has
//! served.
//!
//! The Java service keeps a downloaded copy at `<tmp>/sha256(<parent>)/<name>` and drops it only
//! when a write happens on the same instance, so after an overwrite every other instance keeps
//! serving the old bytes until it restarts. Here the copy's name carries the row's
//! `UPDATED_AT`: a write changes that, the change reaches every instance through the
//! `fsGetDetail` eviction, and the next read finds no copy for the new version and fetches it.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use aws_sdk_s3::config::{Credentials, Region, RequestChecksumCalculation};
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client;
use platform::java::sha256_hex;
use rand::Rng;
use tokio::io::AsyncWriteExt;

#[derive(Clone)]
pub struct Store {
    s3: Client,
    bucket: String,
    temp_root: PathBuf,
}

/// `FilesConfiguration.s3Client`: path-style, region `auto`, static keys.
pub fn s3_client(endpoint: &str, access_key: &str, secret_key: &str) -> Client {
    let creds = Credentials::new(access_key, secret_key, None, None, "files-config");
    let conf = aws_sdk_s3::Config::builder()
        .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
        .endpoint_url(endpoint)
        .region(Region::new("auto"))
        .credentials_provider(creds)
        .force_path_style(true)
        // As the Java client (`checksumValidationEnabled(false)`): no flexible checksums
        // unless an operation requires one.
        .request_checksum_calculation(RequestChecksumCalculation::WhenRequired)
        .build();
    Client::from_conf(conf)
}

impl Store {
    pub fn new(s3: Client, bucket: String, temp_base: &Path) -> Result<Self> {
        let temp_root = temp_base.join(format!("download-{bucket}"));
        std::fs::create_dir_all(&temp_root)
            .with_context(|| format!("creating {}", temp_root.display()))?;
        Ok(Self { s3, bucket, temp_root })
    }

    /// Where the copy of `key` at `version` lives. `key` is `<clientCode>/<path>`.
    fn local_path(&self, key: &str, version: i64) -> Result<PathBuf> {
        let key = collapse_slashes(key);
        let key = key.strip_prefix('/').unwrap_or(&key);
        let (parent, name) = key
            .rsplit_once('/')
            .ok_or_else(|| anyhow!("object key without a folder: {key}"))?;
        Ok(self
            .temp_root
            .join(sha256_hex(parent))
            .join(format!("{version}-{name}")))
    }

    /// `FileSystemService.getAsFile`: a local file with the object's bytes, downloaded unless a
    /// copy of this version is already here. `force` always downloads (`noCache`).
    pub async fn get_as_file(&self, key: &str, version: i64, force: bool) -> Result<PathBuf> {
        let target = self.local_path(key, version)?;
        if !force && tokio::fs::try_exists(&target).await.unwrap_or(false) {
            return Ok(target);
        }
        let dir = target.parent().expect("local path has a parent");
        tokio::fs::create_dir_all(dir).await?;

        // Each download writes its own part file and renames it into place, so concurrent
        // misses on one object never hand anyone a half-written file.
        let suffix: u64 = rand::thread_rng().gen();
        let part = dir.join(format!(
            ".{}.{suffix:x}.part",
            target.file_name().and_then(|n| n.to_str()).unwrap_or("f")
        ));

        let result = self.download_to(key, &part).await;
        if let Err(e) = result {
            let _ = tokio::fs::remove_file(&part).await;
            return Err(e);
        }
        tokio::fs::rename(&part, &target).await?;
        self.drop_older_versions(&target).await;
        Ok(target)
    }

    /// Downloads `key` to `dest` (a one-off copy, outside the versioned layout).
    pub async fn download_to(&self, key: &str, part: &Path) -> Result<()> {
        let key = collapse_slashes(key);
        let key = key.strip_prefix('/').unwrap_or(&key).to_string();
        let obj = self
            .s3
            .get_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
            .with_context(|| format!("get {}/{key}", self.bucket))?;
        let mut body = obj.body.into_async_read();
        let mut file = tokio::fs::File::create(part).await?;
        tokio::io::copy(&mut body, &mut file).await?;
        file.flush().await?;
        Ok(())
    }

    /// Removes copies of the same object at other versions, so the disk holds one per object.
    async fn drop_older_versions(&self, current: &Path) {
        let (Some(dir), Some(name)) = (current.parent(), current.file_name().and_then(|n| n.to_str())) else {
            return;
        };
        let Some((_, base)) = name.split_once('-') else { return };
        let Ok(mut entries) = tokio::fs::read_dir(dir).await else { return };
        while let Ok(Some(e)) = entries.next_entry().await {
            let n = e.file_name();
            let Some(n) = n.to_str() else { continue };
            if n != name && !n.starts_with('.') && n.split_once('-').map(|(_, b)| b) == Some(base) {
                let _ = tokio::fs::remove_file(e.path()).await;
            }
        }
    }
}

impl Store {
    /// `putObject` from a local file. `content_type` `None` sends none (the zip import's way).
    pub async fn put_file(
        &self,
        key: &str,
        file: &Path,
        len: u64,
        content_type: Option<&str>,
        disposition: &str,
    ) -> Result<()> {
        let body = ByteStream::from_path(file)
            .await
            .with_context(|| format!("reading {}", file.display()))?;
        let mut req = self
            .s3
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .content_length(len as i64)
            .content_disposition(disposition)
            .body(body);
        if let Some(ct) = content_type {
            req = req.content_type(ct);
        }
        req.send().await.with_context(|| format!("put {}/{key}", self.bucket))?;
        Ok(())
    }

    /// `deleteObject`; a missing key is not an error (S3 semantics).
    pub async fn delete_object(&self, key: &str) -> Result<()> {
        self.s3
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .with_context(|| format!("delete {}/{key}", self.bucket))?;
        Ok(())
    }

    /// Every object under `prefix`: (key, size).
    pub async fn list_objects(&self, prefix: &str) -> Result<Vec<(String, i64)>> {
        let mut out = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let mut req = self.s3.list_objects_v2().bucket(&self.bucket);
            if !prefix.is_empty() {
                req = req.prefix(prefix);
            }
            if let Some(t) = &token {
                req = req.continuation_token(t);
            }
            let page = req.send().await.with_context(|| format!("list {}/{prefix}", self.bucket))?;
            for o in page.contents() {
                if let Some(k) = o.key() {
                    out.push((k.to_string(), o.size().unwrap_or(0)));
                }
            }
            match page.next_continuation_token() {
                Some(t) if page.is_truncated().unwrap_or(false) => token = Some(t.to_string()),
                _ => break,
            }
        }
        Ok(out)
    }

    /// `evictDownloadCopy`: drops this instance's copies of `key`, every version of them, so the
    /// next read here fetches what was just written. Other instances drop theirs when the
    /// `fsGetDetail` eviction gives them a new version to look for.
    pub async fn drop_local_copies(&self, key: &str) {
        let key = collapse_slashes(key);
        let key = key.strip_prefix('/').unwrap_or(&key);
        let Some((parent, name)) = key.rsplit_once('/') else { return };
        if name.is_empty() {
            return;
        }
        let dir = self.temp_root.join(sha256_hex(parent));
        let Ok(mut entries) = tokio::fs::read_dir(&dir).await else { return };
        while let Ok(Some(e)) = entries.next_entry().await {
            let n = e.file_name();
            let Some(n) = n.to_str() else { continue };
            if let Some((version, rest)) = n.split_once('-') {
                if rest == name && !version.is_empty() && version.chars().all(|c| c.is_ascii_digit() || c == '-') {
                    let _ = tokio::fs::remove_file(e.path()).await;
                }
            }
        }
    }
}

/// Whether `e` says the object is not in the bucket (S3 `NoSuchKey`): a file row whose bytes are
/// gone, such as one that came over with a database copy. The download answers 404 for it rather
/// than 500, and the file browser shows an icon instead of breaking (local, 2026-10-22).
pub fn is_missing_object(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        let text = c.to_string();
        text.contains("NoSuchKey") || text.contains("The specified key does not exist")
    })
}

pub fn collapse_slashes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev = '\0';
    for c in s.chars() {
        if !(c == '/' && prev == '/') {
            out.push(c);
        }
        prev = c;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collapses() {
        assert_eq!(collapse_slashes("a//b///c/"), "a/b/c/");
    }

    #[test]
    fn a_missing_object_is_told_apart_from_other_failures() {
        let missing = anyhow::anyhow!("service error: NoSuchKey: The specified key does not exist.")
            .context("get local-secured/FIN/shriram.jpg");
        assert!(is_missing_object(&missing));
        assert!(!is_missing_object(&anyhow::anyhow!("connection refused").context("get local-secured/x")));
    }

    #[tokio::test]
    async fn local_path_is_hashed_parent_and_versioned_name() {
        let s3 = s3_client("http://localhost:1", "k", "s");
        let tmp = std::env::temp_dir().join("files-store-test");
        let store = Store::new(s3, "local-static".into(), &tmp).unwrap();
        let p = store.local_path("SYSTEM//a/b.png", 42).unwrap();
        assert!(p.ends_with(format!("{}/42-b.png", sha256_hex("SYSTEM/a"))));
    }
}
