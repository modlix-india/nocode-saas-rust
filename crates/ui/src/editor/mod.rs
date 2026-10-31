//! ui-editor: the Java ui's editing surface on port 8107. Every controller that is neither the
//! engine's nor the shell's: CRUD, drafts, fork and publish of applications, pages, styles,
//! themes, functions, schemas, URI paths and fillers, their version history, publish-all,
//! transport, an app's wipe, the controllers' own routes (the application index and mobile
//! apps, page components and events, function steps), and the Rust-only admin purge. The write path is the `overridable`
//! crate's; this module plugs in the ui document kinds.

pub mod apple;
pub mod config;
pub mod firebase;
pub mod index;
pub mod jks;
pub mod kinds;
pub mod mobile;
pub mod purge;
pub mod routes;

use std::sync::Arc;

use anyhow::Result;
use overridable::write::router::{CallerSource, SecurityCallers};
use overridable::write::transport::TransportService;
use overridable::write::{Commons, OverridableService};
use platform::app::Service;
use platform::cache::CacheService;
use platform::registry::Registry;
use platform::health::Health;
use platform::security::SecurityClient;

use crate::editor::apple::Apple;
use crate::editor::firebase::Firebase;
use crate::editor::config::EditorConfig;
use crate::editor::kinds::{ui_messages, UiEvictions, UiFiller, UiKind, UiObject, EDITOR_AUTH_NAMES};
use crate::editor::mobile::MobileApps;
use crate::editor::routes::EditorState;

pub const NAME: &str = "ui-editor";

/// The editor's state on a store, with every ui kind's service.
pub fn state(store: overridable::Store, cache: CacheService, callers: Arc<dyn CallerSource>, cfg: &EditorConfig, http: reqwest::Client) -> Arc<EditorState> {
    let cx = Commons::new(store, cache.clone(), ui_messages(), EDITOR_AUTH_NAMES);
    let ev = Arc::new(UiEvictions { ssr_channel: cfg.editor.ssr_channel.clone() });
    let svc = |o: UiObject| OverridableService::new(UiKind::new(o, ev.clone()), cx.clone());
    let applications = svc(UiObject::Application);
    let pages = svc(UiObject::Page);
    let styles = svc(UiObject::Style);
    let themes = svc(UiObject::Theme);
    let functions = svc(UiObject::Function);
    let schemas = svc(UiObject::Schema);
    let uripaths = svc(UiObject::UriPath);
    let fillers = OverridableService::new(UiFiller(overridable::write::filler::Filler::ui(&cache)), cx.clone());
    let transport_list = EditorState::transport_services(&applications, [&pages, &styles, &themes, &functions, &schemas, &uripaths], &fillers);
    let transports = Arc::new(TransportService::new(cx.clone(), transport_list, "ui", "umodl"));
    let mobile = MobileApps {
        backend: cx.backend().clone(),
        directory: cx.directory().clone(),
        messages: cx.messages.clone(),
        apple: Apple::new(cfg.editor.clone(), http.clone()),
        firebase: Firebase::new(&cfg.editor, http),
        app_code_suffix: cfg.editor.app_code_suffix.clone(),
        key_bits: 2048,
    };
    Arc::new(EditorState { callers, cx, ev, applications, pages, styles, themes, functions, schemas, uripaths, fillers, transports, mobile, purge: None, purge_guard: None })
}

/// Loads configuration, connects everything, and serves until shut down.
pub async fn run() -> Result<()> {
    let loaded = platform::config::load_async::<EditorConfig>(NAME).await?;
    let telemetry = platform::telemetry::init(NAME, &loaded.config.telemetry)?;
    loaded.log_source(NAME);
    let cfg = loaded.config;
    overridable::pojo::set_java_zone_offset_seconds(cfg.ui.zone_offset_seconds()?);

    let db = platform::db::mongo_database(&cfg.mongo).await?;
    let cache = CacheService::configured(&cfg.redis)?;
    let registry = if cfg.registry.register || !cfg.registry.zones.is_empty() {
        Some(Registry::new(&cfg.registry, cfg.server.port)?)
    } else {
        None
    };
    let security = SecurityClient::from_config(&cfg.security, registry.as_ref())?;
    let store = overridable::Store::new(db.clone(), security.clone(), &cache);
    let health = Health::new(telemetry.metrics.clone());
    {
        let db = db.clone();
        health.check("mongo", move || {
            let db = db.clone();
            async move {
                db.run_command(mongodb::bson::doc! {"ping": 1}).await?;
                Ok(())
            }
        });
    }
    let guard: Arc<dyn purge::ManagedClients> = Arc::new(security.clone());
    let callers: Arc<dyn CallerSource> = Arc::new(SecurityCallers { security, server_port: cfg.server.port });
    let mut st = state(store, cache.clone(), callers, &cfg, reqwest::Client::new());
    if let Some(s) = Arc::get_mut(&mut st) {
        s.purge = Some(Arc::new(db.clone()));
        s.purge_guard = Some(guard);
    }
    cache.spawn_eviction_listener();

    // CORS is answered inside the router, under the security headers, as the Java ui does.
    Service { name: NAME.to_string(), server: cfg.server.clone(), telemetry, health, registry, cors: false }
        .run(routes::router(st))
        .await
}
