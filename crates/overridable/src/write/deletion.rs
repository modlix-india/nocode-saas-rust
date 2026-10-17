//! `AbstractDeletionService`: wiping one app for the caller's client across every service,
//! once security says the caller may delete it.

use std::sync::Arc;

use futures::future::join_all;
use platform::error::AppResult;
use platform::security::{ContextAuthentication, OnBehalfOf};

use crate::backend::Directory;
use crate::write::AnyService;

pub struct DeletionService {
    directory: Arc<dyn Directory>,
    services: Vec<Arc<dyn AnyService>>,
}

impl DeletionService {
    pub fn new(directory: Arc<dyn Directory>, services: Vec<Arc<dyn AnyService>>) -> Self {
        Self { directory, services }
    }

    /// `deleteEverything`: `None` when security refuses (or no service had anything to do,
    /// Java's empty Mono), else `Some(true)`. The services run concurrently, as Java's
    /// `flatMap` runs them.
    pub async fn delete_everything(&self, ca: &ContextAuthentication, on_behalf: &OnBehalfOf, app_code: &str) -> AppResult<Option<bool>> {
        if !self.directory.has_delete_access(on_behalf, app_code, ca.client_code()).await? {
            return Ok(None);
        }
        let results = join_all(self.services.iter().map(|s| s.delete_everything(ca, app_code, ca.client_code()))).await;
        let mut any = false;
        for r in results {
            any |= r?.is_some();
        }
        Ok(any.then_some(true))
    }
}
