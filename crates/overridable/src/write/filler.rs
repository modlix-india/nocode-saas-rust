//! The filler documents: `AbstractFiller` (a `definition` and `values` map, merged key by key)
//! and `AbstractFillerService` (named after its app, read through a per-app cache
//! `<Cache>_<app>_<app>_FILLER_READ` that is evicted on every write). ui's `UIFiller` and
//! core's `CoreFiller` are this class with different cache names; both check the
//! `Application` authorities.

use std::sync::Arc;

use async_trait::async_trait;
use platform::cache::{CacheService, LocalCaches};
use platform::error::AppResult;
use platform::security::ContextAuthentication;

use crate::difference::{apply_map, extract_map};
use crate::json::{JMap, JValue};
use crate::pojo::{map_field, set_opt_map, str_field, CloneRule as C, Field, Kind as K, Pojo, OVERRIDABLE_BASE};
use crate::store::{DocType, Resolved};
use crate::write::kind::Kind;
use crate::write::service::{jstr, Commons, OverridableService};

/// `AbstractFiller`.
pub const FILLER: Pojo = Pojo {
    name: "Filler",
    parts: &[OVERRIDABLE_BASE, &[Field::new("definition", K::MapObject, C::MapObject), Field::new("values", K::MapObject, C::MapObject)]],
};

const FILLER_READ: &str = "_FILLER_READ";

/// A filler kind: `Filler::ui` (`UIFillerCache_...`) or `Filler::core` (`FillerCache_...`).
pub struct Filler {
    cache_prefix: &'static str,
    reads: Arc<LocalCaches<String, Option<Arc<Resolved>>>>,
}

impl Filler {
    pub fn ui(cache: &CacheService) -> Self {
        Self { cache_prefix: "UI", reads: cache.family() }
    }

    pub fn core(cache: &CacheService) -> Self {
        Self { cache_prefix: "", reads: cache.family() }
    }

    /// The per-app read cache: `<getCacheName(app, app)>_FILLER_READ`.
    pub fn read_cache_name(&self, app: &str) -> String {
        self.cache_name(app, app) + FILLER_READ
    }

    /// `AbstractFillerService.read(name, appCode, clientCode)`: the app's filler for the
    /// client it serves (`servedClientCode`), cached per served client even when there is
    /// none: on a shared host the host's entry must not answer for a signed-in tenant. The
    /// draft surface has its own key (Java shares one; see `DIFFERENCES.md`).
    pub async fn read(&self, svc: &OverridableService<Filler>, ca: &ContextAuthentication, app: &str, client: &str, draft: bool) -> AppResult<Option<Arc<Resolved>>> {
        let served = svc.commons().store.served_client_code(Some(ca), app, client).await;
        let key = if draft { format!("{served}:draft") } else { served.clone() };
        let (svc, ca, a, c) = (svc.clone(), ca.clone(), app.to_string(), served);
        let v = self
            .reads
            .get_or_load(&self.read_cache_name(app), key, || async move {
                Ok::<_, platform::error::AppError>(Some(svc.read_resolved(&ca, &a, &a, &c, draft).await?))
            })
            .await?;
        Ok(v.flatten())
    }

    async fn evict_reads(&self, cx: &Commons, app: Option<&str>) {
        cx.evict_all(&self.read_cache_name(jstr(app))).await;
    }
}

impl DocType for Filler {
    fn object_name(&self) -> &'static str {
        "Filler"
    }

    fn collection(&self) -> &'static str {
        "filler"
    }

    fn pojo(&self) -> &'static Pojo {
        &FILLER
    }

    fn cache_name(&self, app_code: &str, name: &str) -> String {
        format!("{}FillerCache_{app_code}_{name}", self.cache_prefix)
    }

    /// Empty when either map merges to nothing, as Java's `flatMapMono` is.
    fn apply_override(&self, mut this: JMap, base: &JMap) -> Option<JMap> {
        let d = apply_map(map_field(&this, "definition"), map_field(base, "definition"))?;
        let v = apply_map(map_field(&this, "values"), map_field(base, "values"))?;
        set_opt_map(&mut this, "definition", Some(d));
        set_opt_map(&mut this, "values", Some(v));
        Some(this)
    }

    fn extract_difference(&self, mut this: JMap, base: &JMap) -> Option<JMap> {
        let d = extract_map(map_field(&this, "definition"), map_field(base, "definition"));
        let v = extract_map(map_field(&this, "values"), map_field(base, "values"));
        this.insert("definition".into(), JValue::Object(d));
        this.insert("values".into(), JValue::Object(v));
        Some(this)
    }
}

#[async_trait]
impl Kind for Filler {
    fn access_check_name(&self) -> &'static str {
        "Application"
    }

    fn delete_reads_first(&self) -> bool {
        true
    }

    /// A filler is named after its app.
    async fn before_create(&self, _cx: &Commons, _ca: &ContextAuthentication, entity: &mut JMap) -> AppResult<()> {
        let app = entity.get("appCode").cloned().unwrap_or_default();
        entity.insert("name".into(), app);
        Ok(())
    }

    async fn after_create(&self, cx: &Commons, created: &JMap) -> AppResult<()> {
        self.evict_reads(cx, str_field(created, "appCode")).await;
        Ok(())
    }

    async fn updatable_fill(&self, _cx: &Commons, _ca: &ContextAuthentication, existing: &mut JMap, incoming: &JMap) -> AppResult<()> {
        for f in ["definition", "values", "permission"] {
            existing.insert(f.into(), incoming.get(f).cloned().unwrap_or_default());
        }
        Ok(())
    }

    /// Keyed on the stored app (Java takes the body's; see `DIFFERENCES.md`).
    async fn after_update(&self, cx: &Commons, _request: &JMap, saved: &JMap) -> AppResult<()> {
        self.evict_reads(cx, str_field(saved, "appCode")).await;
        Ok(())
    }

    async fn after_delete(&self, cx: &Commons, deleted: &JMap, result: bool) -> AppResult<bool> {
        self.evict_reads(cx, str_field(deleted, "appCode")).await;
        Ok(result)
    }

    /// The draft surface's read is cached here too, so a draft save clears it.
    async fn after_evict_draft(&self, cx: &Commons, app: &str, _client: &str, _name: &str) -> AppResult<()> {
        self.evict_reads(cx, Some(app)).await;
        Ok(())
    }
}
