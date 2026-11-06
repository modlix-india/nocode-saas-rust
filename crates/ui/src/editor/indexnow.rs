//! IndexNow on publish (Rust only, PLAT-1550): when a page's live definition changes (a publish,
//! or a save straight to the live copy), one ping names the page's public addresses on the
//! app's address for the page's client, so Bing (whose index feeds Copilot and part of ChatGPT
//! search) and the other IndexNow engines fetch them again.
//!
//! - The address is security's app URL for the page's app and client (the client's URL
//!   property, else its newest live URL), else the app's `og.canonicalBase`. None: no ping.
//! - Signed in pages, `noindex` pages, the app's utility pages and apps with search crawlers
//!   turned off are never pinged.
//! - The key is `crate::aeo::indexnow_key`; ui-shell serves it at `/indexnow.txt` on every host
//!   of the app, and each ping names that file as `keyLocation`.
//! - `[aeo] indexnow_enabled = false` (the default, and local) sends nothing and logs the body
//!   that would have been sent.
//!
//! The ping runs after the write has answered and never fails it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use overridable::pojo::{map_field, str_field};
use overridable::{JMap, Store};
use platform::upstream::Upstream;

use crate::aeo::{self, AeoConfig, AppInfo, PageInfo};
use crate::docs::ApplicationDoc;

/// The security route that answers an app's address for a client.
const APP_URL_ROUTE: &str = "/api/security/clienturls/internal/applications/property/url";

pub struct IndexNow {
    cfg: AeoConfig,
    http: reqwest::Client,
    security: Upstream,
    /// When each page (`app/client/name`) was last pinged.
    recent: Mutex<HashMap<String, Instant>>,
}

impl std::fmt::Debug for IndexNow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IndexNow").field("enabled", &self.cfg.indexnow_enabled).field("endpoint", &self.cfg.indexnow_endpoint).finish()
    }
}

impl IndexNow {
    pub fn new(cfg: AeoConfig, http: reqwest::Client, security: Upstream) -> Self {
        Self { cfg, http, security, recent: Mutex::new(HashMap::new()) }
    }

    /// Pings for `page` (the live definition just written) in the background.
    pub fn page_written(self: &Arc<Self>, store: &Store, page: &JMap) {
        let (this, store, page) = (self.clone(), store.clone(), page.clone());
        tokio::spawn(async move {
            if let Err(e) = this.ping_page(&store, &page).await {
                tracing::warn!(error = %format!("{e:#}"), page = str_field(&page, "name").unwrap_or(""), "IndexNow ping failed");
            }
        });
    }

    /// Whether the page was pinged too recently to ping again; records this ping otherwise.
    fn too_soon(&self, key: &str) -> bool {
        let min = Duration::from_secs(self.cfg.indexnow_min_interval_seconds);
        let now = Instant::now();
        let mut recent = self.recent.lock().unwrap_or_else(|p| p.into_inner());
        recent.retain(|_, t| now.duration_since(*t) < min);
        if recent.contains_key(key) {
            return true;
        }
        recent.insert(key.to_string(), now);
        false
    }

    async fn ping_page(&self, store: &Store, page: &JMap) -> anyhow::Result<()> {
        let (Some(app), Some(client)) = (str_field(page, "appCode"), str_field(page, "clientCode")) else { return Ok(()) };
        let info = PageInfo::of(page);
        let props = store
            .read(&ApplicationDoc, app, app, client, client, false)
            .await?
            .and_then(|r| map_field(&r.entity, "properties").cloned())
            .unwrap_or_default();
        let app_info = AppInfo::of(&props);
        if !info.listed(&app_info) || !app_info.visibility().allow_search_bots {
            tracing::debug!(app, page = info.name, "IndexNow: the page is not public, no ping");
            return Ok(());
        }
        let Some(base) = self.app_address(app, client).await?.or_else(|| app_info.canonical_base.clone()) else {
            tracing::info!(app, client, page = info.name, "IndexNow: the app has no address for the client, no ping");
            return Ok(());
        };
        if self.too_soon(&format!("{app}/{client}/{}", info.name)) {
            tracing::debug!(app, page = info.name, "IndexNow: pinged recently, skipped");
            return Ok(());
        }
        let urls: Vec<String> = info.paths(&app_info).iter().map(|p| format!("{base}{p}")).collect();
        let body = aeo::indexnow_body(&base, &aeo::indexnow_key(&self.cfg.indexnow_key_salt, app), &urls);
        if !self.cfg.indexnow_enabled {
            tracing::info!(endpoint = self.cfg.indexnow_endpoint, body = %body, "IndexNow ping not sent ([aeo] indexnow_enabled is off)");
            return Ok(());
        }
        let resp = self
            .http
            .post(&self.cfg.indexnow_endpoint)
            .header(reqwest::header::CONTENT_TYPE, "application/json; charset=utf-8")
            .timeout(Duration::from_secs(20))
            .body(body.to_string())
            .send()
            .await?;
        let status = resp.status();
        if status.is_success() {
            tracing::info!(status = status.as_u16(), body = %body, "IndexNow ping sent");
        } else {
            let text = resp.text().await.unwrap_or_default();
            tracing::warn!(status = status.as_u16(), answer = text, body = %body, "IndexNow ping refused");
        }
        Ok(())
    }

    /// Security's address of the app for the client (`https://host`), `None` when it has none.
    async fn app_address(&self, app: &str, client: &str) -> anyhow::Result<Option<String>> {
        let resp = self
            .security
            .send(APP_URL_ROUTE, |base| {
                self.http
                    .get(format!("{base}{APP_URL_ROUTE}"))
                    .query(&[("appCode", app), ("clientCode", client)])
                    .timeout(Duration::from_secs(20))
            })
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!("security answered {} for the app's address", resp.status());
        }
        let text = resp.text().await?;
        let url = text.trim().trim_end_matches('/');
        Ok(url.starts_with("http").then(|| url.to_string()))
    }
}
