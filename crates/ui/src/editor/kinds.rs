//! The ui document kinds on the overridable write path: what `ApplicationService`,
//! `PageService`, `StyleService`, `StyleThemeService`, `UIFunctionService`, `UISchemaService`,
//! `URIPathService` and `UIFillerService` add to `AbstractOverridableDataService`.
//!
//! The evictions are Java's (`AbstractUIOverridableDataService`'s OUI and SSR caches, the
//! application's index, manifest and properties caches, the URI pattern cache), plus a few Java
//! leaves out that only make caches fresher (see `DIFFERENCES.md`): the stored app as well as
//! the body's on update, the same caches on create, and every client's cached copy on delete.

use std::sync::Arc;

use async_trait::async_trait;
use axum::http::StatusCode;
use overridable::pojo::{map_field, str_field, Pojo};
use overridable::write::filler::Filler;
use overridable::write::kind::Kind;
use overridable::write::messages::{self as msg, Messages};
use overridable::write::Commons;
use overridable::{DocType, JMap, JValue};
use platform::error::{AppError, AppResult};
use platform::security::ContextAuthentication;

use crate::docs::{ApplicationDoc, FunctionDoc, PageDoc, SchemaDoc, StyleDoc, ThemeDoc};
use crate::shell::paths::PathPattern;
use crate::shell::uripath::UriPathDoc;
use crate::ssr;

/// The ui's own message ids (`UIMessageResourceService`).
pub use crate::catalogue::{
    APP_NAME_MISMATCH, INTERNAL_ONLY, MOBILE_APP_BAD_REQUEST, MOBILE_APP_UNABLE_TO_GEN_KEYSTORE, URI_INVALID_METHOD, URI_INVALID_TYPE,
    URI_PATTERN_PATH_MISMATCH, URI_STRING_NULL,
};

/// ui's `messages_en.properties`: the commons ones and the ui's own, coded `DEF.*` then `UI.*`.
pub fn ui_messages() -> Messages {
    crate::catalogue::messages()
}

/// `VersionService.mapAuthName`'s names, and the two ui object types it has none for: URI paths
/// and fillers, which are guarded by the application's authorities. Java checks version reads
/// by these names in `GET /versions/{id}` only; with every version read checked (see
/// `DIFFERENCES.md`), leaving them out would hide a URI path's or a filler's history from
/// everyone.
pub const EDITOR_AUTH_NAMES: &[(&str, &str)] = &[
    ("APPLICATION", "Application"),
    ("PAGE", "Page"),
    ("PERSONALIZATION", "Personalization"),
    ("STYLE", "Style"),
    ("THEME", "Theme"),
    ("FUNCTION", "Function"),
    ("SCHEMA", "Schema"),
    ("URIPATH", "Application"),
    ("FILLER", "Application"),
];

/// `EngineService`'s response caches, cleared whole per app.
pub const APPLICATION_OUI: &str = "applicationOUICache";
pub const PAGE_OUI: &str = "pageOUICache";
pub const STYLE_OUI: &str = "styleOUICache";
pub const THEME_OUI: &str = "themeOUICache";

/// The ui document classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiObject {
    Application,
    Page,
    Style,
    Theme,
    Function,
    Schema,
    UriPath,
}

impl UiObject {
    fn doc(&self) -> &'static dyn DocType {
        match self {
            UiObject::Application => &ApplicationDoc,
            UiObject::Page => &PageDoc,
            UiObject::Style => &StyleDoc,
            UiObject::Theme => &ThemeDoc,
            UiObject::Function => &FunctionDoc,
            UiObject::Schema => &SchemaDoc,
            UiObject::UriPath => &UriPathDoc,
        }
    }

    /// Whether the class extends `AbstractUIOverridableDataService` (the OUI and SSR caches).
    fn is_ui(&self) -> bool {
        matches!(self, UiObject::Application | UiObject::Page | UiObject::Style | UiObject::Theme)
    }

    /// The OUI caches a write clears besides the application's and the page's.
    fn own_oui(&self) -> &'static [&'static str] {
        match self {
            UiObject::Page => &[PAGE_OUI],
            UiObject::Style => &[STYLE_OUI],
            UiObject::Theme => &[THEME_OUI, STYLE_OUI],
            _ => &[],
        }
    }
}

/// The SSR channel and anything else every kind of one process shares.
#[derive(Debug, Clone)]
pub struct UiEvictions {
    pub ssr_channel: String,
}

impl UiEvictions {
    /// `ssrCacheEvictionService.evictByAppCode`: `false` without an app or Redis.
    pub async fn ssr(&self, cx: &Commons, app: Option<&str>) -> bool {
        match ssr::app_message(app) {
            Some(m) => cx.publish(&self.ssr_channel, &m).await,
            None => false,
        }
    }

    async fn oui(&self, cx: &Commons, app: &str, names: &[&str]) {
        for n in names {
            cx.evict_all(&format!("{n}-{app}")).await;
        }
    }

    /// `AbstractUIOverridableDataService`'s three: the application and page OUI caches and the
    /// SSR invalidation.
    pub async fn ui_base(&self, cx: &Commons, app: Option<&str>) -> bool {
        let a = app.unwrap_or("null");
        self.oui(cx, a, &[APPLICATION_OUI, PAGE_OUI]).await;
        self.ssr(cx, app).await
    }

    /// `ApplicationService.evictAll`: the index page, the manifest, the properties (both
    /// surfaces), the application OUI cache and the SSR invalidation.
    pub async fn app_caches(&self, cx: &Commons, app: &str) -> bool {
        for c in ["indexNewCache", "manifestCache", "cacheProperties"] {
            cx.evict_all(&format!("ApplicationCache_{app}_{c}_{app}")).await;
        }
        cx.evict_all(&format!("ApplicationCache_{app}_cacheProperties_{app}_DRAFT")).await;
        cx.evict_all(&format!("{APPLICATION_OUI}-{app}")).await;
        self.ssr(cx, Some(app)).await
    }

    /// `URIPatternCache`, keyed `<app>-<client>`.
    pub async fn uri_patterns(&self, cx: &Commons, app: Option<&str>, client: Option<&str>) {
        cx.evict("URIPatternCache", &format!("{}-{}", app.unwrap_or("null"), client.unwrap_or("null"))).await;
    }
}

/// One ui document kind.
pub struct UiKind {
    pub object: UiObject,
    pub ev: Arc<UiEvictions>,
}

impl UiKind {
    pub fn new(object: UiObject, ev: Arc<UiEvictions>) -> Self {
        Self { object, ev }
    }

    /// The UI classes' evictions on a write of `app`, and the class's own OUI caches.
    async fn ui_write(&self, cx: &Commons, app: Option<&str>) -> bool {
        let r = self.ev.ui_base(cx, app).await;
        self.ev.oui(cx, app.unwrap_or("null"), self.object.own_oui()).await;
        r
    }

    /// Every client's cached copy of the object, both surfaces (Java's delete clears only the
    /// deleting client's key).
    async fn all_copies(&self, cx: &Commons, e: &JMap) {
        let (app, name) = (str_field(e, "appCode").unwrap_or("null"), str_field(e, "name").unwrap_or("null"));
        let c = self.cache_name(app, name);
        cx.evict_all(&c).await;
        cx.evict_all(&format!("{c}_DRAFT")).await;
    }
}

impl DocType for UiKind {
    fn object_name(&self) -> &'static str {
        self.object.doc().object_name()
    }
    fn collection(&self) -> &'static str {
        self.object.doc().collection()
    }
    fn pojo(&self) -> &'static Pojo {
        self.object.doc().pojo()
    }
    fn cache_name(&self, app_code: &str, name: &str) -> String {
        self.object.doc().cache_name(app_code, name)
    }
    fn draftable(&self) -> bool {
        true
    }
    fn apply_override(&self, this: JMap, base: &JMap) -> Option<JMap> {
        self.object.doc().apply_override(this, base)
    }
    fn extract_difference(&self, this: JMap, base: &JMap) -> Option<JMap> {
        self.object.doc().extract_difference(this, base)
    }
}

fn blank(v: Option<&JValue>) -> bool {
    match v {
        None | Some(JValue::Null) => true,
        Some(x) => x.java_to_string().trim().is_empty(),
    }
}

/// `StringUtil.safeValueOf`: the value's string, `None` for null.
fn safe_value_of(v: Option<&JValue>) -> Option<String> {
    v.filter(|x| !x.is_null()).map(JValue::java_to_string)
}

/// `StringUtil.onlyAlphabetAllowed`.
pub fn only_alphabet(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_alphabetic())
}

/// `namespace.name` from a function's or schema's definition; `None` when either is missing.
fn definition_name(e: &JMap) -> Result<Option<String>, ()> {
    let def = match e.get("definition") {
        Some(JValue::Object(d)) => d,
        // `entity.getDefinition().get(...)` on a null definition.
        _ => return Err(()),
    };
    match (safe_value_of(def.get("namespace")), safe_value_of(def.get("name"))) {
        (Some(ns), Some(n)) => Ok(Some(format!("{ns}.{n}"))),
        _ => Ok(None),
    }
}

fn npe(what: &str) -> AppError {
    AppError::Internal(anyhow::anyhow!("NullPointerException: {what}"))
}

/// `AbstractFunctionService.updatedFunctionName`: the same rule as a schema's. An update of a
/// client's function copy arrives as its difference from the base, without the name parts it
/// did not change.
pub fn updated_function_name(entity: &JMap, existing: &JMap) -> Option<String> {
    updated_schema_name(entity, existing)
}

/// `AbstractSchemaService.updatedSchemaName`: the name an update gives the schema. A derived
/// schema's delta may leave out the name parts; they are then the stored name's.
pub fn updated_schema_name(entity: &JMap, existing: &JMap) -> Option<String> {
    let def = map_field(entity, "definition");
    let name = def.and_then(|d| safe_value_of(d.get("name")));
    let namespace = def.and_then(|d| safe_value_of(d.get("namespace")));
    if let (Some(n), Some(ns)) = (&name, &namespace) {
        return Some(format!("{ns}.{n}"));
    }
    let stored = str_field(existing, "name")?;
    if blank(existing.get("baseClientCode")) {
        return None;
    }
    let dot = stored.rfind('.')?;
    if dot == 0 || dot == stored.len() - 1 {
        return None;
    }
    Some(format!("{}.{}", namespace.unwrap_or_else(|| stored[..dot].to_string()), name.unwrap_or_else(|| stored[dot + 1..].to_string())))
}

/// `PathDefinition.isValidType`.
fn valid_type(def: &JValue) -> bool {
    let Some(d) = def.as_object() else { return false };
    let has = |f: &str| d.get(f).is_some_and(|v| !v.is_null());
    match str_field(d, "uriType") {
        Some("KIRUN_FUNCTION") => has("kiRunFxDefinition") && !has("redirectionDefinition"),
        Some("REDIRECTION") => has("redirectionDefinition") && !has("kiRunFxDefinition"),
        _ => false,
    }
}

const ALLOWED_METHODS: [&str; 5] = ["GET", "POST", "PUT", "PATCH", "DELETE"];

/// `URIPathService.validateURIPath`.
pub fn validate_uri_path(cx: &Commons, e: &JMap) -> AppResult<()> {
    let name = str_field(e, "name").unwrap_or("");
    if let Some(path) = str_field(e, "pathString").filter(|p| !p.trim().is_empty()) {
        let pattern = PathPattern::parse(name).map_err(|p| AppError::Internal(anyhow::anyhow!("PatternParseException: {}", p.0)))?;
        if pattern.match_and_extract(path).is_none() {
            return Err(cx.error(StatusCode::BAD_REQUEST, URI_PATTERN_PATH_MISMATCH, &[]));
        }
    }
    let defs = map_field(e, "pathDefinitions").ok_or_else(|| npe("pathDefinitions"))?;
    if defs.values().any(|d| !valid_type(d)) {
        return Err(cx.error(StatusCode::BAD_REQUEST, URI_INVALID_TYPE, &[]));
    }
    if !defs.keys().any(|k| ALLOWED_METHODS.contains(&k.as_str())) {
        return Err(cx.error(StatusCode::BAD_REQUEST, URI_INVALID_METHOD, &[]));
    }
    if name.trim().is_empty() {
        return Err(cx.error(StatusCode::BAD_REQUEST, msg::NAME_MISSING, &[]));
    }
    Ok(())
}

/// `URIPathService.setPathDefinitions`: a redirection gets an (empty) redirection definition
/// and no function; anything else loses its redirection.
fn set_path_definitions(e: &mut JMap) -> AppResult<()> {
    let Some(JValue::Object(defs)) = e.get_mut("pathDefinitions") else { return Err(npe("pathDefinitions")) };
    for d in defs.values_mut() {
        let Some(d) = d.as_object_mut() else { continue };
        if str_field(d, "uriType") == Some("REDIRECTION") {
            if d.get("redirectionDefinition").is_none_or(JValue::is_null) {
                d.insert("redirectionDefinition".into(), JValue::Object(JMap::new()));
            }
            d.insert("kiRunFxDefinition".into(), JValue::Null);
        } else {
            d.insert("redirectionDefinition".into(), JValue::Null);
        }
    }
    Ok(())
}

/// Copies the named fields from `incoming` onto `existing` (a setter with what came, null
/// included).
fn copy(existing: &mut JMap, incoming: &JMap, fields: &[&str]) {
    for f in fields {
        existing.insert(f.to_string(), incoming.get(*f).cloned().unwrap_or_default());
    }
}

/// `map.put` on a map Java either read from Mongo (a `LinkedHashMap`: entries keep their places,
/// new ones go last) or made fresh with `new HashMap<>()` (`made_fresh`: hash order).
pub fn java_put_order(m: JMap, made_fresh: bool) -> JMap {
    if made_fresh {
        overridable::java_map::by_puts(m)
    } else {
        m
    }
}

/// `new HashMap<>(existing)` and then `putAll(added)`: Java's iteration order, which depends on
/// the table size that history leaves (a copy is sized for its source, and grows as keys are
/// added), not only on the keys.
pub fn copy_then_put(existing: JMap, added: JMap) -> JMap {
    let mut cap = if existing.is_empty() { 0 } else { overridable::java_map::capacity_by_copy(existing.len()) };
    let mut m = existing;
    for (k, v) in added {
        let new = !m.contains_key(&k);
        m.insert(k, v);
        if new {
            if cap == 0 {
                cap = 16;
            }
            if m.len() * 4 > cap * 3 {
                cap *= 2;
            }
        }
    }
    if cap == 0 {
        return m;
    }
    overridable::java_map::order(m, cap)
}

/// `PageService.incrementAllComponentVersions`: every component and event function of the
/// page counts one more edit.
pub fn increment_all_component_versions(page: &mut JMap) {
    for (defs, versions) in [("componentDefinition", "componentVersions"), ("eventFunctions", "eventFunctionVersions")] {
        let keys: Vec<String> = map_field(page, defs).map(|m| m.keys().cloned().collect()).unwrap_or_default();
        let existing = map_field(page, versions).cloned();
        let fresh = existing.is_none();
        let mut v = existing.unwrap_or_default();
        for k in keys {
            let n = v.get(&k).and_then(JValue::as_i64).unwrap_or(0);
            v.insert(k, JValue::Int(n + 1));
        }
        page.insert(versions.into(), JValue::Object(java_put_order(v, fresh)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(m: &JMap) -> Vec<&str> {
        m.keys().map(String::as_str).collect()
    }

    #[test]
    fn a_copied_map_orders_by_the_table_its_history_leaves() {
        let one: JMap = [("one".to_string(), JValue::Int(1))].into_iter().collect();
        let two: JMap = [("two".to_string(), JValue::Int(2))].into_iter().collect();
        // A copy of one entry has a table of 2; the second key grows it to 4.
        assert_eq!(keys(&copy_then_put(one.clone(), two.clone())), vec!["two", "one"]);
        // Fresh puts use the default table of 16.
        let mut both = one.clone();
        both.extend(two.clone());
        assert_eq!(keys(&overridable::java_map::by_puts(both)), vec!["one", "two"]);
        assert_eq!(keys(&copy_then_put(JMap::new(), two.clone())), vec!["two"]);
        assert_eq!(keys(&copy_then_put(one.clone(), JMap::new())), vec!["one"]);
        assert!(copy_then_put(JMap::new(), JMap::new()).is_empty());
        assert_eq!(keys(&java_put_order(one, false)), vec!["one"]);
    }
}

#[async_trait]
impl Kind for UiKind {
    fn access_check_name(&self) -> &'static str {
        match self.object {
            UiObject::UriPath => "Application",
            _ => self.object_name(),
        }
    }

    /// Application, Page, Style, Theme and URIPath start their delete with `this.read(id)`.
    fn delete_reads_first(&self) -> bool {
        !matches!(self.object, UiObject::Function | UiObject::Schema)
    }

    async fn before_create(&self, cx: &Commons, _ca: &ContextAuthentication, e: &mut JMap) -> AppResult<()> {
        match self.object {
            UiObject::Application => {
                let (name, app) = (str_field(e, "name").unwrap_or(""), str_field(e, "appCode").unwrap_or(""));
                if name.trim().is_empty() || app.trim().is_empty() || name != app || !only_alphabet(app) {
                    return Err(cx.error(StatusCode::BAD_REQUEST, APP_NAME_MISMATCH, &[]));
                }
            }
            UiObject::Function | UiObject::Schema => match definition_name(e) {
                Ok(Some(n)) => {
                    e.insert("name".into(), JValue::Str(n));
                }
                Ok(None) => return Err(cx.error(StatusCode::BAD_REQUEST, msg::NAME_MISSING, &[])),
                Err(()) => return Err(npe("definition")),
            },
            UiObject::UriPath => {
                if blank(e.get("name")) {
                    if blank(e.get("shortCode")) {
                        e.insert("shortCode".into(), JValue::Str(overridable::write::transport::short_uuid()));
                    }
                    let short = e.get("shortCode").map(JValue::java_to_string).unwrap_or_default();
                    e.insert("name".into(), JValue::Str(format!("/{short}")));
                }
                if blank(e.get("name")) || blank(e.get("pathString")) {
                    return Err(cx.error(StatusCode::BAD_REQUEST, URI_STRING_NULL, &[]));
                }
                set_path_definitions(e)?;
                validate_uri_path(cx, e)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// The UI classes' caches (Java's create clears none of them) and the URI pattern list.
    async fn after_create(&self, cx: &Commons, created: &JMap) -> AppResult<()> {
        let app = str_field(created, "appCode");
        if self.object.is_ui() {
            self.ui_write(cx, app).await;
        }
        match self.object {
            UiObject::Application => {
                self.ev.app_caches(cx, app.unwrap_or("null")).await;
            }
            UiObject::UriPath => self.ev.uri_patterns(cx, app, str_field(created, "clientCode")).await,
            _ => {}
        }
        Ok(())
    }

    async fn before_update(&self, cx: &Commons, _ca: &ContextAuthentication, e: &mut JMap) -> AppResult<()> {
        if self.object == UiObject::UriPath {
            validate_uri_path(cx, e)?;
        }
        Ok(())
    }

    async fn updatable_fill(&self, cx: &Commons, _ca: &ContextAuthentication, existing: &mut JMap, incoming: &JMap) -> AppResult<()> {
        match self.object {
            UiObject::Application => copy(existing, incoming, &["properties", "translations", "languages", "message", "defaultLanguage"]),
            UiObject::Page => {
                copy(existing, incoming, &["device", "translations", "properties", "eventFunctions", "rootComponent", "componentDefinition"]);
                increment_all_component_versions(existing);
            }
            UiObject::Style => copy(existing, incoming, &["styleString"]),
            UiObject::Theme => copy(existing, incoming, &["variables"]),
            UiObject::Function => {
                let Some(name) = updated_function_name(incoming, existing) else {
                    return Err(cx.error(StatusCode::BAD_REQUEST, msg::NAME_MISSING, &[]));
                };
                if Some(name.as_str()) != str_field(existing, "name") {
                    return Err(cx.error(StatusCode::BAD_REQUEST, msg::NAME_CHANGE, &[]));
                }
                copy(existing, incoming, &["executeAuth", "definition", "permission"]);
            }
            UiObject::Schema => {
                let Some(name) = updated_schema_name(incoming, existing) else {
                    return Err(cx.error(StatusCode::BAD_REQUEST, msg::NAME_MISSING, &[]));
                };
                if Some(name.as_str()) != str_field(existing, "name") {
                    return Err(cx.error(StatusCode::BAD_REQUEST, msg::NAME_CHANGE, &[]));
                }
                copy(existing, incoming, &["definition", "permission"]);
            }
            // `webhook` is Rust only (DIFFERENCES.md): an update sets it as it sets the definitions.
            UiObject::UriPath => copy(existing, incoming, &["pathString", "pathDefinitions", "webhook"]),
        }
        Ok(())
    }

    /// Java keys the UI caches on the body's app code; the stored one is cleared as well.
    async fn after_update(&self, cx: &Commons, request: &JMap, saved: &JMap) -> AppResult<()> {
        let (body_app, app) = (str_field(request, "appCode"), str_field(saved, "appCode"));
        if self.object.is_ui() {
            self.ui_write(cx, body_app).await;
            if app != body_app {
                self.ui_write(cx, app).await;
            }
        }
        match self.object {
            UiObject::Application => {
                self.ev.app_caches(cx, app.unwrap_or("null")).await;
            }
            UiObject::UriPath => self.ev.uri_patterns(cx, app, str_field(saved, "clientCode")).await,
            _ => {}
        }
        Ok(())
    }

    /// Page, Style and Theme answer the SSR publish's result; the others the delete's.
    async fn after_delete(&self, cx: &Commons, deleted: &JMap, result: bool) -> AppResult<bool> {
        let app = str_field(deleted, "appCode");
        self.all_copies(cx, deleted).await;
        let answer = match self.object {
            UiObject::Application => {
                self.ev.ui_base(cx, app).await;
                self.ev.app_caches(cx, app.unwrap_or("null")).await;
                result
            }
            UiObject::Page | UiObject::Style | UiObject::Theme => {
                self.ev.ui_base(cx, app).await;
                self.ev.oui(cx, app.unwrap_or("null"), self.object.own_oui()).await;
                self.ev.ssr(cx, app).await
            }
            UiObject::UriPath => {
                self.ev.uri_patterns(cx, app, str_field(deleted, "clientCode")).await;
                result
            }
            UiObject::Function | UiObject::Schema => result,
        };
        Ok(answer)
    }

    async fn after_evict_draft(&self, cx: &Commons, app: &str, client: &str, _name: &str) -> AppResult<()> {
        if self.object.is_ui() {
            self.ui_write(cx, Some(app)).await;
        }
        match self.object {
            UiObject::Application => {
                self.ev.app_caches(cx, app).await;
            }
            UiObject::UriPath => self.ev.uri_patterns(cx, Some(app), Some(client)).await,
            _ => {}
        }
        Ok(())
    }

    async fn after_delete_everything(&self, cx: &Commons, app: &str, _client: &str) -> AppResult<()> {
        if self.object == UiObject::Application {
            self.ev.app_caches(cx, app).await;
        }
        Ok(())
    }
}

/// `UIFillerService`: the library's filler, with every client's cached copy cleared on delete.
pub struct UiFiller(pub Filler);

impl DocType for UiFiller {
    fn object_name(&self) -> &'static str {
        self.0.object_name()
    }
    fn collection(&self) -> &'static str {
        self.0.collection()
    }
    fn pojo(&self) -> &'static Pojo {
        self.0.pojo()
    }
    fn cache_name(&self, app_code: &str, name: &str) -> String {
        self.0.cache_name(app_code, name)
    }
    fn draftable(&self) -> bool {
        true
    }
    fn apply_override(&self, this: JMap, base: &JMap) -> Option<JMap> {
        self.0.apply_override(this, base)
    }
    fn extract_difference(&self, this: JMap, base: &JMap) -> Option<JMap> {
        self.0.extract_difference(this, base)
    }
}

#[async_trait]
impl Kind for UiFiller {
    fn access_check_name(&self) -> &'static str {
        self.0.access_check_name()
    }
    fn delete_reads_first(&self) -> bool {
        self.0.delete_reads_first()
    }
    async fn before_create(&self, cx: &Commons, ca: &ContextAuthentication, e: &mut JMap) -> AppResult<()> {
        self.0.before_create(cx, ca, e).await
    }
    async fn after_create(&self, cx: &Commons, created: &JMap) -> AppResult<()> {
        self.0.after_create(cx, created).await
    }
    async fn updatable_fill(&self, cx: &Commons, ca: &ContextAuthentication, existing: &mut JMap, incoming: &JMap) -> AppResult<()> {
        self.0.updatable_fill(cx, ca, existing, incoming).await
    }
    async fn after_update(&self, cx: &Commons, request: &JMap, saved: &JMap) -> AppResult<()> {
        self.0.after_update(cx, request, saved).await
    }
    async fn after_delete(&self, cx: &Commons, deleted: &JMap, result: bool) -> AppResult<bool> {
        let (app, name) = (str_field(deleted, "appCode").unwrap_or("null"), str_field(deleted, "name").unwrap_or("null"));
        let c = self.cache_name(app, name);
        cx.evict_all(&c).await;
        cx.evict_all(&format!("{c}_DRAFT")).await;
        self.0.after_delete(cx, deleted, result).await
    }
    async fn after_evict_draft(&self, cx: &Commons, app: &str, client: &str, name: &str) -> AppResult<()> {
        self.0.after_evict_draft(cx, app, client, name).await
    }
}
