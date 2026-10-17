//! `EngineService` and what it calls: `PageService.read` (protected page to login page,
//! unknown page to the not-found page, forbidden page), `ApplicationService.applyChange`
//! (shell, consent and filler inlined), `readProperties`, theme resolution and the style sheet.
//!
//! The engine caches of the Java service (`pageOUICache-<app>` and friends) are keyed by the
//! ETag the client sends and only save recomputing a response; they are not ported. Every
//! response here is computed from the definition caches, and the 304 decision is the same
//! substring test against the same ids, which is what the Java caches return while nothing
//! has changed.

use std::sync::Arc;

use axum::response::Response;
use futures::future::BoxFuture;
use overridable::java_map;
use overridable::pojo::{map_field, str_field, to_jackson};
use overridable::store::resolve;
use overridable::{DocType, JMap, JValue, Resolved};
use platform::error::{AppError, AppResult};

use crate::authority::has_authority;
use crate::docs::{ApplicationDoc, FillerDoc, FunctionDoc, PageDoc, StyleDoc, ThemeDoc, APPLICATION, FUNCTION, PAGE};
use crate::respond::{build, empty_ok, not_found, EngineBody, Caching};
use crate::state::{AppState, Caller};


/// `StringUtil.safeIsBlank(Object)`.
fn blank(v: Option<&JValue>) -> bool {
    match v {
        None | Some(JValue::Null) => true,
        Some(x) => x.java_to_string().trim().is_empty(),
    }
}

/// `EngineService.draftUid`: the `d-` marker for the draft surface, idempotent both ways.
pub fn draft_uid(unique_id: &str, draft: bool) -> String {
    if unique_id.is_empty() {
        return unique_id.to_string();
    }
    let bare = unique_id.strip_prefix("d-").unwrap_or(unique_id);
    if draft {
        format!("d-{bare}")
    } else {
        bare.to_string()
    }
}

/// `EngineService.uniqueIdPrefix`: the page ETag's login and surface dimensions.
pub fn unique_id_prefix(authenticated: bool, draft: bool) -> String {
    format!("{}{}", if draft { "d" } else { "" }, if authenticated { "lg-" } else { "nlg-" })
}

fn strip_weak(etag: &str) -> &str {
    etag.strip_prefix("W/").unwrap_or(etag)
}

/// `Integer.valueOf(String)`.
fn java_int(s: &str) -> Option<i32> {
    let t = s.strip_prefix('+').unwrap_or(s);
    if t.is_empty() || t == "-" {
        return None;
    }
    let digits = t.strip_prefix('-').unwrap_or(t);
    if !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    t.parse::<i32>().ok()
}

/// Values of a map property sorted by their `order` (`MapWithOrderComparator`, a stable sort;
/// an `order` that is not an integer string fails the request as it does in Java).
fn sorted_by_order(m: &JMap) -> AppResult<Vec<JMap>> {
    let mut entries: Vec<JMap> = m.values().filter_map(|v| v.as_object().cloned()).collect();
    if entries.len() < 2 {
        return Ok(entries);
    }
    let mut keyed = Vec::with_capacity(entries.len());
    for e in entries.drain(..) {
        let raw = e.get("order").map(JValue::java_to_string).unwrap_or_else(|| "0".into());
        let k = java_int(&raw)
            .ok_or_else(|| AppError::Internal(anyhow::anyhow!("NumberFormatException: For input string: \"{raw}\"")))?;
        keyed.push((k, e));
    }
    keyed.sort_by_key(|(k, _)| *k);
    Ok(keyed.into_iter().map(|(_, e)| e).collect())
}

/// The application after `ApplicationService.applyChange`, with its id.
pub struct AppRead {
    pub entity: JMap,
    pub unique_id: String,
}

struct ResolvedTheme {
    entry: Option<JMap>,
    unique_id: String,
    variables: Option<JValue>,
}

pub struct Engine<'a> {
    pub st: &'a AppState,
    pub caller: &'a Caller,
}

impl<'a> Engine<'a> {
    pub fn new(st: &'a AppState, caller: &'a Caller) -> Self {
        Self { st, caller }
    }

    fn draft(&self) -> bool {
        self.caller.draft
    }

    /// `EngineService.servedClient` (`AbstractOverridableDataService.servedClientCode`, Java
    /// commit e2b7d48aa): the client whose copies a request is served. On a shared host that is
    /// a signed-in tenant's own client, and every read and cache key below uses it, never the
    /// host's, or the host's copy would answer for the tenant.
    pub async fn served(&self, app: &str, cc: &str) -> String {
        self.st.store().served_client_code(Some(&self.caller.ca), app, cc).await
    }

    /// `AbstractOverridableDataService.read(name, appCode, clientCode)` without the class's
    /// `applyChange`, for the client it serves ([`Self::served`]; asking again with a client
    /// already served is a no-op).
    pub async fn read_def(&self, dt: &dyn DocType, name: &str, app: &str, cc: &str) -> AppResult<Option<Arc<Resolved>>> {
        let served = self.served(app, cc).await;
        Ok(self
            .st
            .store()
            .read(dt, name, app, self.caller.url_client_code(cc), &served, self.draft())
            .await?)
    }

    /// `ApplicationService.readProperties`: the merged app definition's `properties`, per
    /// client and surface, `{}` when there is no app.
    pub async fn read_properties(&self, app: &str, cc: &str) -> AppResult<Arc<JMap>> {
        let mut cache = format!("ApplicationCache_{app}_cacheProperties_{app}");
        if self.draft() {
            cache.push_str("_DRAFT");
        }
        let store = self.st.store();
        let url_cc = self.caller.url_client_code(cc);
        let draft = self.draft();
        let v = self
            .st
            .inner()
            .properties
            .get_or_load(&cache, cc.to_string(), || async move {
                let Some(stored) = store
                    .read_if_exists_in_base(&ApplicationDoc, app, app, url_cc, cc, draft)
                    .await?
                else {
                    return Ok::<_, anyhow::Error>(None);
                };
                let Some(merged) = store.read_drafted(&ApplicationDoc, &stored, draft, cc).await? else {
                    return Ok(None);
                };
                let cloned = resolve(&APPLICATION, &merged);
                Ok(Some(Arc::new(map_field(&cloned.entity, "properties").cloned().unwrap_or_default())))
            })
            .await?;
        Ok(v.unwrap_or_default())
    }

    /// `readInternal` + `PageService.applyChange`: an authenticated caller without the page's
    /// permission gets the forbidden page, or a 403 when the app names none.
    pub fn page_base_read<'b>(&'b self, name: &'b str, app: &'b str, cc: &'b str) -> BoxFuture<'b, AppResult<Option<Arc<Resolved>>>> {
        Box::pin(async move {
            let Some(page) = self.read_def(&PageDoc, name, app, cc).await? else {
                return Ok(None);
            };
            let props = self.read_properties(app, cc).await?;
            let permission = str_field(&page.entity, "permission");
            if self.caller.authenticated() && !has_authority(permission, self.caller.authorities()) {
                if blank(props.get("forbiddenPage")) {
                    return Err(crate::catalogue::page_forbidden(permission));
                }
                let fb = props.get("forbiddenPage").map(JValue::java_to_string).unwrap_or_default();
                if fb != name {
                    let other = self.page_base_read(&fb, app, cc).await?;
                    return Ok(Some(other.unwrap_or(page)));
                }
            }
            Ok(Some(page))
        })
    }

    /// `PageService.read(name, appCode, clientCode)`, for the client it serves.
    pub async fn page_read(&self, name: &str, app: &str, cc: &str) -> AppResult<Option<Arc<Resolved>>> {
        let served = self.served(app, cc).await;
        let cc = served.as_str();
        let found = match self.page_base_read(name, app, cc).await? {
            None => None,
            Some(pg) => {
                let protected = !blank(pg.entity.get("permission"));
                if !protected || self.caller.authenticated() {
                    Some(pg)
                } else {
                    let props = self.read_properties(app, cc).await?;
                    if blank(props.get("loginPage")) {
                        Some(pg)
                    } else {
                        let login = props.get("loginPage").map(JValue::java_to_string).unwrap_or_default();
                        self.page_base_read(&login, app, cc).await?
                    }
                }
            }
        };
        if found.is_some() {
            return Ok(found);
        }
        let props = self.read_properties(app, cc).await?;
        if blank(props.get("notFoundPage")) {
            return Ok(None);
        }
        let nf = props.get("notFoundPage").map(JValue::java_to_string).unwrap_or_default();
        self.page_base_read(&nf, app, cc).await
    }

    /// `UIFillerService.read`: cached per client including "there is none".
    ///
    /// Java names this cache without the surface, so a draft read and a live read share an
    /// entry; here the draft surface keys its own (see DIFFERENCES.md).
    async fn filler_read(&self, app: &str, cc: &str) -> AppResult<Option<Arc<Resolved>>> {
        let cache = format!("UIFillerCache_{app}_{app}_FILLER_READ");
        let key = if self.draft() { format!("{cc}:draft") } else { cc.to_string() };
        let v = self
            .st
            .inner()
            .fillers
            .get_or_load(&cache, key, || async {
                let r = self.read_def(&FillerDoc, app, app, cc).await.map_err(|e| anyhow::anyhow!("{e}"))?;
                Ok::<_, anyhow::Error>(Some(Arc::new(r)))
            })
            .await?;
        Ok(v.and_then(|x| (*x).clone()))
    }

    /// `appService.read(appCode, appCode, clientCode)`: `readInternal` +
    /// `ApplicationService.applyChange`, for the client it serves (the shell, filler and
    /// consent reads included).
    pub async fn app_read(&self, app: &str, cc: &str) -> AppResult<Option<AppRead>> {
        let served = self.served(app, cc).await;
        let cc = served.as_str();
        let Some(r) = self.read_def(&ApplicationDoc, app, app, cc).await? else {
            return Ok(None);
        };
        let mut entity = r.entity.clone();
        let doc_app = str_field(&entity, "appCode").unwrap_or(app).to_string();
        let permission = entity.get("permission").filter(|v| !v.is_null()).and_then(JValue::as_str);
        let show_shell = permission.is_none() || has_authority(permission, self.caller.authorities());
        let props = map_field(&entity, "properties").cloned().unwrap_or_default();

        let shell = match props.get("shellPage").filter(|v| !v.is_null()) {
            None => None,
            Some(sp) => {
                let mut page_name = sp.clone();
                if !show_shell {
                    if let Some(fb) = props.get("forbiddenPage").filter(|v| !v.is_null()) {
                        page_name = fb.clone();
                    }
                }
                self.page_read(&page_name.java_to_string(), &doc_app, cc).await?
            }
        };
        let filler = self.filler_read(&doc_app, cc).await?;
        let consent = match props.get("consentPage").filter(|v| !v.is_null()) {
            None => None,
            Some(c) => self.page_read(&c.java_to_string(), &doc_app, cc).await?,
        };

        let size_before = props.len();
        let mut p = props;
        p.shift_remove("mobileApps");
        p.shift_remove("manifest");
        let mut uid = r.unique_id.clone();
        if let Some(f) = &filler {
            uid.push_str(&f.unique_id);
            p.insert("fillerValues".into(), f.entity.get("values").cloned().unwrap_or(JValue::Null));
        }
        if let Some(c) = &consent {
            uid.push_str(&c.unique_id);
            p.insert("consentPageDefinition".into(), JValue::Object(to_jackson(&PAGE, &c.entity)));
        }
        if let Some(s) = &shell {
            uid.push_str(&s.unique_id);
            p.insert("shellPageDefinition".into(), JValue::Object(to_jackson(&PAGE, &s.entity)));
        }
        // The puts above land in the HashMap the clone made, which grows if they overflow it.
        let cap = java_map::capacity_by_puts(size_before.max(p.len()));
        let p = java_map::order(p, cap);
        entity.insert("properties".into(), JValue::Object(p));
        Ok(Some(AppRead { entity, unique_id: uid }))
    }

    /// `EngineService.readApplicationForResponse`: the plan stripped (`withoutPlan`, a copy that
    /// rebuilds `properties`), `urlClientCode` set, the draft marker on the id. The definition is
    /// the served client's; `urlClientCode` stays the host's (`cc`), which the browser sends back.
    async fn application_for_response(&self, app: &str, cc: &str, served: &str) -> AppResult<Option<(JValue, String)>> {
        let Some(a) = self.app_read(app, served).await? else {
            return Ok(None);
        };
        let mut e = a.entity;
        let props = map_field(&e, "properties").cloned().unwrap_or_default();
        let props: JMap = props.into_iter().filter(|(_, v)| !v.is_null()).collect();
        e.insert("properties".into(), JValue::Object(java_map::by_puts(props)));
        e.insert("blueprint".into(), JValue::Null);
        e.insert("urlClientCode".into(), JValue::Str(cc.to_string()));
        Ok(Some((JValue::Object(to_jackson(&APPLICATION, &e)), draft_uid(&a.unique_id, self.draft()))))
    }

    /// `GET /api/ui/application`.
    pub async fn application(&self, app: &str, cc: &str, etag: Option<&str>) -> AppResult<Response> {
        if self.st.app_status(app).await?.as_deref().map(String::as_str) != Some("ACTIVE") {
            return Ok(empty_ok());
        }
        let caching = Caching::pick(self.draft(), Caching::Revalidate);
        let served = self.served(app, cc).await;
        let Some((body, uid)) = self.application_for_response(app, cc, &served).await? else {
            return Ok(not_found());
        };
        let compare = match etag {
            None => None,
            Some(e) if e.is_empty() => Some(e.to_string()),
            Some(e) => Some(draft_uid(strip_weak(e), self.draft())),
        };
        Ok(build(&uid, compare.as_deref(), caching, || EngineBody::Json(body)))
    }

    /// `GET /api/ui/page/{pageName}`.
    pub async fn page(&self, name: &str, app: &str, cc: &str, etag: Option<&str>) -> AppResult<Response> {
        let caching = Caching::pick(self.draft(), Caching::Revalidate);
        let prefix = unique_id_prefix(self.caller.authenticated(), self.draft());
        let served = self.served(app, cc).await;
        let Some(page) = self.page_read(name, app, &served).await? else {
            return Ok(not_found());
        };
        let body = || {
            let mut e = page.entity.clone();
            e.insert("blueprint".into(), JValue::Null);
            EngineBody::Json(JValue::Object(to_jackson(&PAGE, &e)))
        };
        match etag {
            Some(e) if !e.is_empty() => {
                let uid = strip_weak(e);
                let rest = uid.find('-').map(|i| &uid[i + 1..]).unwrap_or(uid);
                let n_uid = format!("{prefix}{rest}");
                // A miss in the Java eTag branch answers with the page's own id, unprefixed.
                Ok(build_against(&page.unique_id, &n_uid, caching, body))
            }
            _ => Ok(build(&format!("{prefix}{}", page.unique_id), etag, caching, body)),
        }
    }

    async fn resolve_theme(&self, app: &JMap, app_code: &str, cc: &str, requested: Option<&str>) -> AppResult<ResolvedTheme> {
        for e in theme_candidates(app, requested)? {
            let name = e.get("name").map(JValue::java_to_string).unwrap_or_default();
            if let Some(t) = self.read_def(&ThemeDoc, &name, app_code, cc).await? {
                return Ok(ResolvedTheme {
                    entry: Some(e),
                    unique_id: t.unique_id.clone(),
                    variables: t.entity.get("variables").cloned(),
                });
            }
        }
        Ok(ResolvedTheme { entry: None, unique_id: String::new(), variables: None })
    }

    /// `EngineService.internalReadStyle`.
    async fn internal_style(&self, app_code: &str, cc: &str, theme: Option<&str>) -> AppResult<Option<(String, String)>> {
        let Some(app) = self.app_read(app_code, cc).await? else {
            return Ok(None);
        };
        let resolved = self.resolve_theme(&app.entity, app_code, cc, theme).await?;
        let names = style_names(&app.entity, resolved.entry.as_ref())?;
        let tail = format!("{}{}", resolved.unique_id, app.unique_id);
        let mut styles = Vec::new();
        for n in &names {
            if let Some(s) = self.read_def(&StyleDoc, n, app_code, cc).await? {
                styles.push(s);
            }
        }
        if styles.is_empty() {
            return Ok(Some((String::new(), tail)));
        }
        let css: Vec<String> = styles
            .iter()
            .map(|s| s.entity.get("styleString").map(JValue::java_to_string).unwrap_or_else(|| "null".into()))
            .collect();
        let mut uid: String = styles.iter().map(|s| s.unique_id.as_str()).collect();
        uid.push_str(&tail);
        Ok(Some((css.join("\n"), uid)))
    }

    /// `GET /api/ui/style`.
    pub async fn style(&self, app: &str, cc: &str, theme: Option<&str>, etag: Option<&str>) -> AppResult<Response> {
        let caching = Caching::pick(self.draft(), Caching::MaxAge(self.st.config().ui.resource_cache_age));
        let served = self.served(app, cc).await;
        let Some((css, uid)) = self.internal_style(app, &served, theme).await? else {
            return Ok(not_found());
        };
        Ok(match etag {
            Some(e) if !e.is_empty() => {
                let client = draft_uid(strip_weak(e), self.draft());
                build_against(&uid, &client, caching, || EngineBody::Css(css))
            }
            _ => build(&draft_uid(&uid, self.draft()), etag, caching, || EngineBody::Css(css)),
        })
    }

    /// `GET /api/ui/theme`.
    pub async fn theme(&self, app: &str, cc: &str, theme: Option<&str>, etag: Option<&str>) -> AppResult<Response> {
        let caching = Caching::pick(self.draft(), Caching::MaxAge(self.st.config().ui.resource_cache_age));
        let served = self.served(app, cc).await;
        let Some(a) = self.app_read(app, &served).await? else {
            return Ok(not_found());
        };
        let resolved = self.resolve_theme(&a.entity, app, &served, theme).await?;
        let uid = format!("{}{}", resolved.unique_id, a.unique_id);
        let vars = match resolved.variables {
            Some(JValue::Object(m)) => JValue::Object(m),
            _ => JValue::Object(JMap::new()),
        };
        Ok(match etag {
            Some(e) if !e.is_empty() => {
                let client = draft_uid(strip_weak(e), self.draft());
                build_against(&uid, &client, caching, || EngineBody::Json(vars))
            }
            _ => build(&draft_uid(&uid, self.draft()), etag, caching, || EngineBody::Json(vars)),
        })
    }

    /// `GET /api/ui/function/{namespace}/{name}`: `functionService.read`, which serves the
    /// signed-in tenant's copy on a shared host like every overridable read.
    pub async fn function(&self, ns: &str, name: &str, app: &str, cc: &str, etag: Option<&str>) -> AppResult<Response> {
        let caching = Caching::pick(self.draft(), Caching::MaxAge(self.st.config().ui.resource_cache_age));
        let served = self.served(app, cc).await;
        let Some(f) = self.read_def(&FunctionDoc, &format!("{ns}.{name}"), app, &served).await? else {
            return Ok(not_found());
        };
        Ok(build(&f.unique_id, etag, caching, || EngineBody::Json(JValue::Object(to_jackson(&FUNCTION, &f.entity)))))
    }
}

/// `build` with the client's (normalized) tag compared against the object's id.
fn build_against(unique_id: &str, client: &str, caching: Caching, body: impl FnOnce() -> EngineBody) -> Response {
    build(unique_id, Some(client), caching, body)
}

fn props_of(app: &JMap) -> Option<&JMap> {
    map_field(app, "properties").filter(|p| !p.is_empty())
}

/// `EngineService.themeCandidates`: the requested theme if listed, then the rest in order;
/// `pageOnly` themes only when asked for by name.
fn theme_candidates(app: &JMap, requested: Option<&str>) -> AppResult<Vec<JMap>> {
    let listed: Vec<JMap> = match props_of(app).and_then(|p| map_field(p, "themes")).filter(|t| !t.is_empty()) {
        None => Vec::new(),
        Some(themes) => {
            let named: JMap = themes
                .iter()
                .filter(|(_, v)| v.as_object().is_some_and(|e| !blank(e.get("name"))))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            sorted_by_order(&named)?
        }
    };
    let visitor: Vec<JMap> = listed
        .iter()
        .filter(|e| e.get("pageOnly") != Some(&JValue::Bool(true)))
        .cloned()
        .collect();
    let ordered = if visitor.is_empty() { listed.clone() } else { visitor };
    let requested = match requested.filter(|r| !r.trim().is_empty()) {
        Some(r) if !ordered.is_empty() => r,
        _ => return Ok(ordered),
    };
    let name_is = |e: &JMap, r: &str| e.get("name").map(JValue::java_to_string).as_deref() == Some(r);
    let preferred: Vec<JMap> = listed.iter().filter(|e| name_is(e, requested)).cloned().collect();
    if preferred.is_empty() {
        return Ok(ordered);
    }
    let mut out = preferred;
    out.extend(ordered.into_iter().filter(|e| !name_is(e, requested)));
    Ok(out)
}

/// `EngineService.styleNames`: the app's styles in order, then the theme's own style.
fn style_names(app: &JMap, theme: Option<&JMap>) -> AppResult<Vec<String>> {
    let Some(props) = props_of(app) else {
        return Ok(Vec::new());
    };
    let mut names: Vec<String> = match map_field(props, "styles").filter(|s| !s.is_empty()) {
        None => Vec::new(),
        Some(styles) => sorted_by_order(styles)?
            .iter()
            .filter_map(|e| e.get("name").filter(|v| !v.is_null()).map(JValue::java_to_string))
            .collect(),
    };
    if let Some(t) = theme {
        if let Some(s) = t.get("style").filter(|v| !v.is_null()) {
            let s = s.java_to_string();
            if !s.trim().is_empty() {
                names.push(s);
            }
        }
    }
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;
    use overridable::json::parse;

    fn obj(s: &str) -> JMap {
        match parse(s.as_bytes()).unwrap() {
            JValue::Object(m) => m,
            _ => panic!(),
        }
    }

    #[test]
    fn draft_uid_is_reversible_and_idempotent() {
        assert_eq!(draft_uid("abc", true), "d-abc");
        assert_eq!(draft_uid("d-abc", true), "d-abc");
        assert_eq!(draft_uid("d-abc", false), "abc");
        assert_eq!(draft_uid("dabc", false), "dabc");
        assert_eq!(draft_uid("", true), "");
        assert_eq!(unique_id_prefix(true, false), "lg-");
        assert_eq!(unique_id_prefix(false, true), "dnlg-");
    }

    #[test]
    fn theme_candidates_follow_the_java_rules() {
        let app = obj(
            r#"{"properties":{"themes":{
                "a":{"name":"dark","order":2},
                "b":{"name":"light","order":1},
                "c":{"name":"promo","pageOnly":true,"order":0},
                "d":{"name":"  "}}}}"#,
        );
        let names = |v: Vec<JMap>| v.iter().map(|e| e["name"].java_to_string()).collect::<Vec<_>>();
        assert_eq!(names(theme_candidates(&app, None).unwrap()), ["light", "dark"]);
        assert_eq!(names(theme_candidates(&app, Some("dark")).unwrap()), ["dark", "light"]);
        assert_eq!(names(theme_candidates(&app, Some("promo")).unwrap()), ["promo", "light", "dark"]);
        assert_eq!(names(theme_candidates(&app, Some("gone")).unwrap()), ["light", "dark"]);
    }

    #[test]
    fn a_non_integer_order_fails_like_java() {
        let app = obj(r#"{"properties":{"themes":{"a":{"name":"x","order":1.0},"b":{"name":"y"}}}}"#);
        assert!(theme_candidates(&app, None).is_err());
        // One entry is never compared, so Java never parses its order.
        let app = obj(r#"{"properties":{"themes":{"a":{"name":"x","order":1.0}}}}"#);
        assert_eq!(theme_candidates(&app, None).unwrap().len(), 1);
    }

    #[test]
    fn style_names_take_the_theme_style_last() {
        let app = obj(r#"{"properties":{"styles":{"s1":{"name":"two","order":2},"s2":{"name":"one","order":1}}}}"#);
        let theme = obj(r#"{"name":"dark","style":"darkstyle"}"#);
        assert_eq!(style_names(&app, Some(&theme)).unwrap(), ["one", "two", "darkstyle"]);
        let empty = obj(r#"{"properties":{}}"#);
        assert!(style_names(&empty, Some(&theme)).unwrap().is_empty());
    }

    // The Java ui `ThemeCandidatesTest`.
    fn with_classic() -> JMap {
        obj(r#"{"properties":{"themes":{
            "t0":{"name":"monoLight","order":1},
            "t1":{"name":"monoDark","order":2},
            "t2":{"name":"classic","order":0,"pageOnly":true}}}}"#)
    }

    fn names(v: Vec<JMap>) -> Vec<String> {
        v.iter().map(|e| e["name"].java_to_string()).collect()
    }

    #[test]
    fn a_page_only_theme_is_never_the_default_even_with_the_lowest_order() {
        assert_eq!(names(theme_candidates(&with_classic(), None).unwrap()), ["monoLight", "monoDark"]);
    }

    #[test]
    fn a_page_only_theme_is_served_when_asked_for_by_name() {
        assert_eq!(names(theme_candidates(&with_classic(), Some("classic")).unwrap()), ["classic", "monoLight", "monoDark"]);
    }

    #[test]
    fn an_unlisted_request_falls_back_to_the_visitor_themes() {
        assert_eq!(names(theme_candidates(&with_classic(), Some("gone")).unwrap()), ["monoLight", "monoDark"]);
    }

    #[test]
    fn an_app_listing_only_page_only_themes_is_still_themed() {
        let app = obj(r#"{"properties":{"themes":{"t0":{"name":"classic","order":0,"pageOnly":true}}}}"#);
        assert_eq!(names(theme_candidates(&app, None).unwrap()), ["classic"]);
    }

    #[test]
    fn helpers() {
        assert_eq!(java_int("12"), Some(12));
        assert_eq!(java_int("+3"), Some(3));
        assert_eq!(java_int("-4"), Some(-4));
        assert_eq!(java_int(""), None);
        assert_eq!(java_int("-"), None);
        assert_eq!(java_int("1.0"), None);
        assert_eq!(java_int("99999999999"), None);
        assert!(blank(None));
        assert!(blank(Some(&JValue::Null)));
        assert!(blank(Some(&JValue::Str("  ".into()))));
        assert!(!blank(Some(&JValue::Int(0))));
        assert_eq!(strip_weak("W/abc"), "abc");
        assert_eq!(strip_weak("abc"), "abc");
        // No properties, no themes map, an empty themes map, a theme that is not a map.
        assert!(theme_candidates(&obj("{}"), None).unwrap().is_empty());
        assert!(theme_candidates(&obj(r#"{"properties":{"a":1}}"#), Some("x")).unwrap().is_empty());
        assert!(theme_candidates(&obj(r#"{"properties":{"themes":{}}}"#), None).unwrap().is_empty());
        assert!(theme_candidates(&obj(r#"{"properties":{"themes":{"a":"x","b":{"name":"n"}}}}"#), None).unwrap().len() == 1);
        // A style named by a number, styles without a name, a theme style that is blank.
        let app = obj(r#"{"properties":{"styles":{"a":{"name":5,"order":"1"},"b":{"order":"2"}}}}"#);
        assert_eq!(style_names(&app, Some(&obj(r#"{"style":" "}"#))).unwrap(), ["5"]);
        assert_eq!(style_names(&app, Some(&obj(r#"{"style":null}"#))).unwrap(), ["5"]);
        assert_eq!(style_names(&app, None).unwrap(), ["5"]);
        let bad = obj(r#"{"properties":{"styles":{"a":{"name":"x","order":"one"},"b":{"name":"y"}}}}"#);
        assert!(style_names(&bad, None).is_err());
        let ordered = sorted_by_order(&obj(r#"{"a":{"order":"2"},"b":{"order":1},"c":{},"d":"skip"}"#)).unwrap();
        assert_eq!(ordered.len(), 3);
        assert!(ordered[0].get("order").is_none());
    }

}
