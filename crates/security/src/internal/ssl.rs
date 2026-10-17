//! `SSLCertificateService.getAllCertificates` / `getLastUpdated`, both cached under one key.

use std::sync::Arc;

use super::Internal;
use crate::caches;
use crate::data::misc::CertificateConfig;
use crate::errors::{AuthError, AuthResult};

impl Internal {
    /// Every URL's current certificate (`certificateCache`).
    pub async fn certificates(&self) -> AuthResult<Arc<Vec<CertificateConfig>>> {
        let db = self.db.clone();
        let v = self
            .caches()
            .certificates
            .get_or_load(caches::CERTIFICATES, caches::CERTIFICATES_KEY.to_string(), || async move {
                Ok::<_, AuthError>(Some(Arc::new(db.certificates().await?)))
            })
            .await?;
        Ok(v.unwrap_or_default())
    }

    /// The ETag of the certificate list (`certificatesLastUpdatedCache`).
    pub async fn certificates_last_updated(&self) -> AuthResult<Arc<String>> {
        let db = self.db.clone();
        let v = self
            .caches()
            .strings
            .get_or_load(caches::CERTIFICATES_LAST_UPDATED, caches::CERTIFICATES_LAST_UPDATED_KEY.to_string(), || async move {
                Ok::<_, AuthError>(Some(Arc::new(db.certificates_last_updated().await?)))
            })
            .await?;
        Ok(v.unwrap_or_default())
    }
}
