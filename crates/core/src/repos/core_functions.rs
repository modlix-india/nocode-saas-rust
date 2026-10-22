//! `CoreFunctionRepository`: core's own functions by full name.
//!
//! Only the families ported so far are registered (see `NEEDS.md` / the port map for the
//! rest); a stored definition that calls one that is not here fails as an unknown function.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use kirun::function::Function;

use super::{filter_names, FunctionSource};
use crate::clients::SecurityCalls;
use crate::error::CoreError;
use crate::functions::crypto::{SignatureValidator, Signer};
use crate::functions::hash::HashData;
use crate::functions::security::GetAppUrl;
use crate::functions::securitycontext::{GetAuthentication, GetUser, HasAuthority};
use crate::functions::Core;
use crate::storage::service::AppDataService;

/// What core's functions are built over.
pub struct Deps {
    pub security: Arc<SecurityCalls>,
    pub storage: Arc<AppDataService>,
    /// The definitions read through the overridable store (storages, connections, event
    /// definitions, templates).
    pub defs: Arc<crate::storage::defs::StorageDefs>,
    /// core's own Mongo database.
    pub mongo: mongodb::Database,
    pub cache: platform::cache::CacheService,
    /// The connections library and the publishers.
    pub integrations: Arc<crate::integrations::Integrations>,
    /// The files service (`IFeignFilesService`).
    pub files: Arc<crate::files_calls::FilesCalls>,
    /// `core.scheduler.*`, for the one-off functions.
    pub scheduler: crate::scheduler::EventSchedulerSettings,
    /// The internal routes `CoreServices.Platform.*` call (the retired worker's Feign clients).
    pub platform: Arc<crate::platform_calls::PlatformCalls>,
}

pub struct CoreFunctions {
    map: HashMap<String, Arc<dyn Function>>,
    names: Vec<String>,
}

impl CoreFunctions {
    pub fn new(deps: &Deps) -> Self {
        // `makeStorageFunctions` runs first in the Java constructor.
        let mut functions: Vec<Arc<dyn Function>> = crate::functions::storage::all(&deps.storage);
        functions.extend(crate::functions::integration_fns::rest(&deps.integrations));
        functions.extend::<Vec<Arc<dyn Function>>>(vec![
            Arc::new(Core(HasAuthority::new())),
            Arc::new(Core(GetAuthentication::new())),
            Arc::new(Core(GetUser::new())),
            Arc::new(Core(GetAppUrl::new(deps.security.clone()))),
        ]);
        functions.extend(crate::functions::security_fns::all(&deps.security));
        functions.extend(crate::functions::caller_security::all(&deps.security));
        functions.extend(crate::functions::integration_fns::email(&deps.integrations, &deps.files));
        functions.extend(crate::functions::integration_fns::create_event(&deps.integrations, deps.storage.catalog()));
        functions.extend(crate::functions::schedule::all(deps));
        functions.extend(crate::functions::file::all(deps));
        functions.extend::<Vec<Arc<dyn Function>>>(vec![
            Arc::new(Core(Signer::new())),
            Arc::new(Core(SignatureValidator::new())),
            Arc::new(Core(HashData::new())),
        ]);
        functions.extend(crate::functions::integration_fns::notification(&deps.integrations));
        functions.extend(crate::functions::integration_fns::ai(&deps.integrations));
        // Retired: each fails at once (the message service is gone).
        functions.extend(crate::functions::message::all());
        // Rust only (no Java counterpart): the platform app's jobs, guarded, after every
        // family Java has.
        functions.extend(crate::functions::platform::all(&deps.platform));
        let mut map = HashMap::new();
        let mut names = Vec::new();
        for f in functions {
            let full = f.get_signature().get_full_name();
            // `putIfAbsent`: the first registration of a name wins.
            if !map.contains_key(&full) {
                names.push(full.clone());
                map.insert(full, f);
            }
        }
        Self { map, names }
    }

    pub fn names(&self) -> &[String] {
        &self.names
    }
}

#[async_trait]
impl FunctionSource for CoreFunctions {
    /// `repoMap.get(namespace + "." + name)`: a null namespace reads as `null`.
    async fn find(&self, namespace: Option<&str>, name: &str) -> Result<Option<Arc<dyn Function>>, CoreError> {
        Ok(self.map.get(&format!("{}.{name}", namespace.unwrap_or("null"))).cloned())
    }

    async fn filter(&self, name: &str) -> Result<Vec<String>, CoreError> {
        Ok(filter_names(&self.names, name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_ported_functions_by_full_name() {
        let storage = crate::testing::offline_storage_service().await;
        let deps = crate::testing::offline_deps("http://127.0.0.1:1", storage).await;
        let core = CoreFunctions::new(&deps);
        assert_eq!(core.names().len(), 81);
        assert_eq!(core.names()[0], "CoreServices.Storage.ClearDraft");
        // The platform family comes last, after the 72 Java has, SendDataNotification and
        // Storage.GetFields.
        assert_eq!(
            core.names()[74..],
            [
                "CoreServices.Platform.RenewCertificates",
                "CoreServices.Platform.CleanupTokens",
                "CoreServices.Platform.Meter",
                "CoreServices.Platform.ReconcileBilling",
                "CoreServices.Platform.CleanupExpiredFiles",
                "CoreServices.Platform.CleanupTransports",
                "CoreServices.Platform.CleanupEventRuns",
            ]
        );
        assert!(core.names()[..74].iter().all(|n| !n.starts_with("CoreServices.Platform.")));
        let notification: Vec<&String> = core.names().iter().filter(|n| n.starts_with("CoreServices.Notification.")).collect();
        assert_eq!(notification, ["CoreServices.Notification.SendNotification", "CoreServices.Notification.SendDataNotification"]);
        assert_eq!(core.filter("SendDataNotification").await.unwrap(), ["CoreServices.Notification.SendDataNotification"]);
        assert_eq!(core.names().iter().filter(|n| n.starts_with("CoreServices.Message.")).count(), 7, "retired, still registered");
        for full in [
            "CoreServices.SecurityContext.HasAuthority",
            "CoreServices.SecurityContext.GetAuthentication",
            "CoreServices.SecurityContext.GetUser",
            "CoreServices.Security.GetAppUrl",
            "CoreServices.Crypto.Signer",
            "CoreServices.Crypto.SignatureValidator",
            "CoreServices.Hash.HashData",
            "CoreServices.Storage.Create",
            "CoreServices.Storage.CreateMany",
            "CoreServices.Storage.Read",
            "CoreServices.Storage.ReadPage",
            "CoreServices.Storage.Update",
            "CoreServices.Storage.UpdateMany",
            "CoreServices.Storage.Delete",
            "CoreServices.Storage.DeleteByFilter",
            "CoreServices.Storage.Aggregate",
            "CoreServices.Storage.GetVersionDetails",
            "CoreServices.Storage.ClearDraft",
            "CoreServices.Storage.CopyToDraft",
            "CoreServices.Storage.GetFields",
            "CoreServices.Notification.SendDataNotification",
        ] {
            let (ns, name) = full.rsplit_once('.').unwrap();
            assert!(core.find(Some(ns), name).await.unwrap().is_some(), "{full}");
        }
        assert!(core.find(None, "HashData").await.unwrap().is_none());
        assert_eq!(core.filter("CRYPTO").await.unwrap().len(), 2);
    }
}
