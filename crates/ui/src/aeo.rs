//! Discovery files for answer engines and search crawlers (Rust only; PLAT-1547, PLAT-1549,
//! PLAT-1550, SZ-930): what `/robots.txt`, `/sitemap.xml`, `/llms.txt` and `/indexnow.txt`
//! say for an app, and the IndexNow key and ping body. ui-shell serves the files
//! (`crate::shell::discovery`); ui-editor pings IndexNow when a page is published
//! (`crate::editor::indexnow`). Everything here is pure: the callers read the definitions.
//!
//! The app's switches live in `properties.aiVisibility`
//! (`{allowSearchBots, allowTrainingBots, llmsTxt}`, each `true` unless set to `false`), and
//! an app may replace a generated file with its own text in `properties.seoFiles`
//! (`{robotsTxt, llmsTxt}`, strings). A page with a `permission` is a signed in page: it is never
//! listed, and nothing in robots.txt names it.

use chrono::DateTime;
use mongodb::bson::{doc, Document};
use overridable::pojo::{map_field, str_field};
use overridable::{JMap, JValue};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// AI search and answer crawlers, and the classic search engines' own: `allowSearchBots`.
pub const SEARCH_BOTS: &[&str] = &[
    "OAI-SearchBot",
    "ChatGPT-User",
    "PerplexityBot",
    "Perplexity-User",
    "Claude-SearchBot",
    "Claude-User",
    "bingbot",
    "Googlebot",
    "Applebot",
];

/// Crawlers that collect text to train models: `allowTrainingBots`.
pub const TRAINING_BOTS: &[&str] = &[
    "GPTBot",
    "ClaudeBot",
    "Google-Extended",
    "Applebot-Extended",
    "CCBot",
    "meta-externalagent",
    "Bytespider",
];

/// The cache the shell keeps the generated files in, one per app: every write of the app, a
/// page or a URI path clears it (`crate::editor::kinds::UiEvictions`).
pub const CACHE_PREFIX: &str = "aeoFilesCache";

pub fn cache_name(app: &str) -> String {
    format!("{CACHE_PREFIX}-{app}")
}

/// The fixed path of the IndexNow key file; every ping names it as `keyLocation`.
pub const INDEXNOW_KEY_PATH: &str = "/indexnow.txt";

/// The most URLs one sitemap or llms.txt lists (the sitemap protocol allows 50,000).
pub const MAX_URLS: usize = 5000;

/// `[aeo]` in the ui-shell and ui-editor configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AeoConfig {
    /// ui-editor: send the IndexNow ping on publish. Off (the default) logs what would be sent.
    pub indexnow_enabled: bool,
    /// ui-editor: where the ping goes (the shared endpoint passes it on to Bing, Yandex and the
    /// others).
    pub indexnow_endpoint: String,
    /// Both units: mixed into every app's key, so the keys can all be changed at once. The two
    /// units must agree, or the key file will not match the pings.
    pub indexnow_key_salt: String,
    /// ui-editor: a page pinged less than this many seconds ago is not pinged again (an editor
    /// saving every few seconds would otherwise ping on each save).
    pub indexnow_min_interval_seconds: u64,
}

impl Default for AeoConfig {
    fn default() -> Self {
        Self {
            indexnow_enabled: false,
            indexnow_endpoint: "https://api.indexnow.org/indexnow".into(),
            indexnow_key_salt: "modlix-indexnow".into(),
            indexnow_min_interval_seconds: 600,
        }
    }
}

/// An app's IndexNow key: 32 hex characters derived from the app code and the salt, so neither
/// unit stores anything and every host of the app serves the same key. The key is public by
/// design (the key file proves the host's owner chose to ping); it is no credential.
pub fn indexnow_key(salt: &str, app: &str) -> String {
    let digest = Sha256::digest(format!("{salt}:{app}").as_bytes());
    digest.iter().take(16).map(|b| format!("{b:02x}")).collect()
}

/// `properties.aiVisibility`, each switch on unless it is `false`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AiVisibility {
    pub allow_search_bots: bool,
    pub allow_training_bots: bool,
    pub llms_txt: bool,
}

impl AiVisibility {
    pub fn of(props: &JMap) -> Self {
        let m = map_field(props, "aiVisibility");
        let on = |k: &str| match m.and_then(|m| m.get(k)) {
            Some(JValue::Bool(b)) => *b,
            Some(JValue::Str(s)) => !s.trim().eq_ignore_ascii_case("false"),
            _ => true,
        };
        Self { allow_search_bots: on("allowSearchBots"), allow_training_bots: on("allowTrainingBots"), llms_txt: on("llmsTxt") }
    }
}

/// A value as written, or the `value` of a component property (`{"value": ...}`); a property
/// bound to an expression (`location` only) has no static value.
fn static_value(v: &JValue) -> Option<&JValue> {
    match v {
        JValue::Object(m) if m.contains_key("value") || m.contains_key("location") => m.get("value").filter(|v| !v.is_null()),
        JValue::Null => None,
        other => Some(other),
    }
}

fn text(v: Option<&JValue>) -> Option<String> {
    match v.and_then(static_value)? {
        JValue::Str(s) if !s.trim().is_empty() => Some(s.trim().to_string()),
        _ => None,
    }
}

/// What the files need of the app's `properties`.
#[derive(Debug, Clone, Default)]
pub struct AppInfo {
    pub title: Option<String>,
    pub description: Option<String>,
    pub default_page: Option<String>,
    /// Pages that are never listed: the login, not found, forbidden, shell and consent pages.
    pub utility_pages: Vec<String>,
    pub visibility: Option<AiVisibility>,
    pub robots_override: Option<String>,
    pub llms_override: Option<String>,
    /// `og.canonicalBase`, the address IndexNow falls back to when security knows none.
    pub canonical_base: Option<String>,
}

impl AppInfo {
    pub fn of(props: &JMap) -> Self {
        let og = map_field(props, "og");
        let og_text = |k: &str| og.and_then(|o| text(o.get(k)));
        let files = map_field(props, "seoFiles");
        let file = |k: &str| match files.and_then(|f| f.get(k)) {
            Some(JValue::Str(s)) if !s.trim().is_empty() => Some(s.clone()),
            _ => None,
        };
        let utility_pages = ["loginPage", "notFoundPage", "forbiddenPage", "shellPage", "consentPage"]
            .iter()
            .filter_map(|k| text(props.get(*k)))
            .collect();
        Self {
            title: text(props.get("title")).or_else(|| og_text("siteName")).or_else(|| og_text("title")),
            description: text(props.get("description")).or_else(|| og_text("description")),
            default_page: text(props.get("defaultPage")),
            utility_pages,
            visibility: Some(AiVisibility::of(props)),
            robots_override: file("robotsTxt"),
            llms_override: file("llmsTxt"),
            canonical_base: og_text("canonicalBase").map(|b| b.trim_end_matches('/').to_string()),
        }
    }

    pub fn visibility(&self) -> AiVisibility {
        self.visibility.unwrap_or(AiVisibility { allow_search_bots: true, allow_training_bots: true, llms_txt: true })
    }
}

/// What the files need of a page definition (merged over its client chain).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PageInfo {
    pub name: String,
    pub title: Option<String>,
    pub description: Option<String>,
    /// `updatedAt`, epoch seconds.
    pub updated: Option<i64>,
    /// The page has a `permission`: only signed in users see it.
    pub signed_in: bool,
    /// `seo.robots` says `noindex`.
    pub noindex: bool,
    /// The slugs of `seo.paths` when it is a static map (`{"<slug>": {...}}`, PLAT-1546's
    /// proposal); a path source (`{"uri": ...}`) lists nothing.
    pub slugs: Vec<String>,
}

impl PageInfo {
    pub fn of(page: &JMap) -> Self {
        let props = map_field(page, "properties");
        let seo = props.and_then(|p| map_field(p, "seo"));
        let title = props
            .and_then(|p| p.get("title"))
            .and_then(|t| match t {
                JValue::Object(m) if !m.contains_key("value") => text(m.get("name")),
                other => text(Some(other)),
            })
            .or_else(|| text(page.get("title")));
        let robots = seo.and_then(|s| text(s.get("robots"))).unwrap_or_default();
        let slugs = match seo.and_then(|s| s.get("paths")).and_then(static_value) {
            Some(JValue::Object(m)) if !m.get("uri").is_some_and(|u| matches!(u, JValue::Str(_))) => {
                m.keys().map(|k| k.trim_matches('/').to_string()).filter(|k| !k.is_empty()).collect()
            }
            _ => Vec::new(),
        };
        Self {
            name: str_field(page, "name").unwrap_or_default().to_string(),
            title,
            description: seo.and_then(|s| text(s.get("description"))),
            updated: match page.get("updatedAt") {
                Some(JValue::Int(s)) => Some(*s),
                Some(JValue::Float(f)) => Some(*f as i64),
                _ => None,
            },
            signed_in: str_field(page, "permission").is_some_and(|p| !p.trim().is_empty()),
            noindex: robots.to_ascii_lowercase().contains("noindex"),
            slugs,
        }
    }

    /// Whether the page may be named in the sitemap, llms.txt and an IndexNow ping.
    pub fn listed(&self, app: &AppInfo) -> bool {
        !self.name.trim().is_empty() && !self.signed_in && !self.noindex && !app.utility_pages.contains(&self.name)
    }

    /// The page's own path (`/` for the app's default page) and its slugs' paths.
    pub fn paths(&self, app: &AppInfo) -> Vec<String> {
        let own = if app.default_page.as_deref() == Some(self.name.as_str()) { "/".to_string() } else { format!("/{}", segment(&self.name)) };
        let mut out = vec![own];
        for s in &self.slugs {
            let encoded: Vec<String> = s.split('/').filter(|p| !p.is_empty()).map(segment).collect();
            out.push(format!("/{}/{}", segment(&self.name), encoded.join("/")));
        }
        out
    }
}

/// Characters a path segment keeps as they are (RFC 3986 unreserved).
const SEGMENT: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'.').remove(b'_').remove(b'~');

fn segment(s: &str) -> String {
    utf8_percent_encode(s, SEGMENT).to_string()
}

/// The fields of a page the files read, for a projected query.
pub fn page_projection() -> Document {
    doc! {"name": 1, "appCode": 1, "clientCode": 1, "permission": 1, "title": 1, "updatedAt": 1, "published": 1,
        "properties.title": 1, "properties.seo": 1}
}

/// The fields of a URI path the sitemap reads.
pub fn uri_path_projection() -> Document {
    doc! {"name": 1, "clientCode": 1, "permission": 1, "published": 1, "pathDefinitions.GET": 1}
}

/// `overlay(base, top)`: `top`'s values over `base`'s, maps merged key by key, a null in `top`
/// taking nothing away (a client copy stores only what it changes).
fn overlay(base: &mut JMap, top: JMap) {
    for (k, v) in top {
        match (base.get_mut(&k), v) {
            (_, JValue::Null) => {}
            (Some(JValue::Object(b)), JValue::Object(t)) => overlay(b, t),
            (_, v) => {
                base.insert(k, v);
            }
        }
    }
}

/// One definition per name from the copies of every client in `order` (base first), each
/// client's copy laid over the ones below it; `updatedAt` is the newest copy's.
pub fn merge_copies(mut rows: Vec<JMap>, order: &[String]) -> Vec<JMap> {
    let rank = |m: &JMap| str_field(m, "clientCode").and_then(|c| order.iter().position(|o| o == c)).unwrap_or(usize::MAX);
    rows.sort_by_key(rank);
    let mut out: Vec<JMap> = Vec::new();
    for row in rows {
        let name = str_field(&row, "name").unwrap_or_default().to_string();
        match out.iter_mut().find(|m| str_field(m, "name") == Some(name.as_str())) {
            Some(merged) => {
                let newest = match (merged.get("updatedAt"), row.get("updatedAt")) {
                    (Some(JValue::Int(a)), Some(JValue::Int(b))) => Some(JValue::Int(*a.max(b))),
                    _ => None,
                };
                overlay(merged, row);
                if let Some(n) = newest {
                    merged.insert("updatedAt".into(), n);
                }
            }
            None => out.push(row),
        }
    }
    out
}

/// A URI path that is a clean address for a public page: a literal path (no wildcard or
/// variable) whose GET redirects to a relative address naming the page. Answers the path and
/// the page's name (empty for the app's default page).
pub fn uri_path_alias(uri_path: &JMap) -> Option<(String, String)> {
    let name = str_field(uri_path, "name")?.trim();
    if !name.starts_with('/') || name.contains(['*', '{', '}', '?', ' ']) {
        return None;
    }
    if str_field(uri_path, "permission").is_some_and(|p| !p.trim().is_empty()) {
        return None;
    }
    let get = map_field(uri_path, "pathDefinitions").and_then(|d| map_field(d, "GET"))?;
    if str_field(get, "uriType") != Some("REDIRECTION") {
        return None;
    }
    let target = map_field(get, "redirectionDefinition").and_then(|r| str_field(r, "targetUrl"))?.trim();
    if !target.starts_with('/') || target.starts_with("//") {
        return None;
    }
    let path = target.split(['?', '#']).next().unwrap_or("");
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    let page = match parts.iter().position(|p| *p == "page") {
        Some(i) => parts.get(i + 1).copied().unwrap_or(""),
        None => parts.first().copied().unwrap_or(""),
    };
    Some((name.to_string(), page.to_string()))
}

/// One sitemap entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub path: String,
    pub lastmod: Option<i64>,
}

/// The sitemap's entries: every listed page's paths, then the URI path aliases of listed pages;
/// the home page first, the rest by path, each path once, at most [`MAX_URLS`].
pub fn entries(app: &AppInfo, pages: &[PageInfo], aliases: &[(String, String)]) -> Vec<Entry> {
    let mut out: Vec<Entry> = Vec::new();
    let listed: Vec<&PageInfo> = pages.iter().filter(|p| p.listed(app)).collect();
    for p in &listed {
        for path in p.paths(app) {
            out.push(Entry { path, lastmod: p.updated });
        }
    }
    for (path, page) in aliases {
        let target = if page.is_empty() { app.default_page.as_deref().unwrap_or("") } else { page.as_str() };
        if let Some(p) = listed.iter().find(|p| p.name == target) {
            out.push(Entry { path: path.clone(), lastmod: p.updated });
        }
    }
    out.sort_by(|a, b| (a.path != "/", &a.path).cmp(&(b.path != "/", &b.path)));
    out.dedup_by(|a, b| a.path == b.path);
    out.truncate(MAX_URLS);
    out
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

/// W3C datetime in UTC.
pub fn w3c(epoch_seconds: i64) -> Option<String> {
    DateTime::from_timestamp(epoch_seconds, 0).map(|d| d.format("%Y-%m-%dT%H:%M:%S+00:00").to_string())
}

/// `base` is the scheme and host the request came to (`https://site.example`).
pub fn sitemap_xml(base: &str, entries: &[Entry]) -> String {
    let base = base.trim_end_matches('/');
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n");
    for e in entries {
        out.push_str("  <url>\n    <loc>");
        out.push_str(&xml_escape(&format!("{base}{}", e.path)));
        out.push_str("</loc>\n");
        if let Some(t) = e.lastmod.and_then(w3c) {
            out.push_str("    <lastmod>");
            out.push_str(&t);
            out.push_str("</lastmod>\n");
        }
        out.push_str("  </url>\n");
    }
    out.push_str("</urlset>\n");
    out
}

fn bot_group(out: &mut String, bots: &[&str], what: &str) {
    out.push_str(&format!("\n# {what}\n"));
    for b in bots {
        out.push_str(&format!("User-agent: {b}\n"));
    }
    out.push_str("Disallow: /\n");
}

/// The generated robots.txt: everyone may crawl everything (the page shell fetches its pages
/// and styles from `/api/`, so a crawler that renders needs it), the bots the switches turn off
/// may crawl nothing, and the sitemap is named. An app's own text replaces all of it. A draft
/// (preview) host is closed to every crawler.
pub fn robots_txt(base: &str, app: &AppInfo, draft: bool) -> String {
    if draft {
        return "# A preview host: not for crawlers.\nUser-agent: *\nDisallow: /\n".into();
    }
    if let Some(own) = &app.robots_override {
        let mut s = own.clone();
        if !s.ends_with('\n') {
            s.push('\n');
        }
        return s;
    }
    let v = app.visibility();
    let base = base.trim_end_matches('/');
    let mut out = String::from("User-agent: *\nAllow: /\n");
    if !v.allow_search_bots {
        bot_group(&mut out, SEARCH_BOTS, "Search and AI answer crawlers are turned off for this site.");
    }
    if !v.allow_training_bots {
        bot_group(&mut out, TRAINING_BOTS, "AI training crawlers are turned off for this site.");
    }
    out.push_str(&format!("\nSitemap: {base}/sitemap.xml\n"));
    out
}

fn one_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn md_link_text(s: &str) -> String {
    one_line(s).replace('[', "\\[").replace(']', "\\]")
}

/// The generated llms.txt (llmstxt.org): the app's name and description, then a link per
/// listed page with its title and description. `None` when the app turned it off. An app's own
/// text replaces the generated one.
pub fn llms_txt(base: &str, app: &AppInfo, pages: &[PageInfo]) -> Option<String> {
    if !app.visibility().llms_txt {
        return None;
    }
    if let Some(own) = &app.llms_override {
        return Some(own.clone());
    }
    let base = base.trim_end_matches('/');
    let host = base.split("://").nth(1).unwrap_or(base);
    let mut out = format!("# {}\n", one_line(app.title.as_deref().unwrap_or(host)));
    if let Some(d) = &app.description {
        out.push_str(&format!("\n> {}\n", one_line(d)));
    }
    let mut listed: Vec<(String, &PageInfo)> = pages
        .iter()
        .filter(|p| p.listed(app))
        .filter_map(|p| p.paths(app).into_iter().next().map(|path| (path, p)))
        .collect();
    listed.sort_by(|a, b| (a.0 != "/", &a.0).cmp(&(b.0 != "/", &b.0)));
    listed.truncate(MAX_URLS);
    if !listed.is_empty() {
        out.push_str("\n## Pages\n\n");
        for (path, p) in listed {
            let title = md_link_text(p.title.as_deref().unwrap_or(&p.name));
            out.push_str(&format!("- [{title}]({base}{path})"));
            if let Some(d) = &p.description {
                out.push_str(&format!(": {}", one_line(d)));
            }
            out.push('\n');
        }
    }
    Some(out)
}

/// The IndexNow ping for `urls` on `base`'s host (`https://www.indexnow.org/documentation`).
pub fn indexnow_body(base: &str, key: &str, urls: &[String]) -> serde_json::Value {
    let base = base.trim_end_matches('/');
    let host = base.split("://").nth(1).unwrap_or(base).split('/').next().unwrap_or("");
    serde_json::json!({
        "host": host,
        "key": key,
        "keyLocation": format!("{base}{INDEXNOW_KEY_PATH}"),
        "urlList": urls,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn j(v: serde_json::Value) -> JMap {
        match overridable::json::parse(v.to_string().as_bytes()).unwrap() {
            JValue::Object(m) => m,
            _ => panic!("not an object"),
        }
    }

    fn app(v: serde_json::Value) -> AppInfo {
        AppInfo::of(&j(v))
    }

    #[test]
    fn switches_default_on() {
        assert_eq!(AiVisibility::of(&JMap::new()), AiVisibility { allow_search_bots: true, allow_training_bots: true, llms_txt: true });
        let v = AiVisibility::of(&j(serde_json::json!({"aiVisibility": {"allowTrainingBots": false, "llmsTxt": "false", "allowSearchBots": null}})));
        assert_eq!(v, AiVisibility { allow_search_bots: true, allow_training_bots: false, llms_txt: false });
    }

    #[test]
    fn robots_by_switches() {
        let r = robots_txt("https://a.example/", &app(serde_json::json!({})), false);
        assert_eq!(r, "User-agent: *\nAllow: /\n\nSitemap: https://a.example/sitemap.xml\n");
        let r = robots_txt("https://a.example", &app(serde_json::json!({"aiVisibility": {"allowTrainingBots": false}})), false);
        for b in TRAINING_BOTS {
            assert!(r.contains(&format!("User-agent: {b}\n")), "{r}");
        }
        assert!(!r.contains("GPTBot\nUser-agent: OAI-SearchBot"));
        assert!(!r.contains("Googlebot"), "search bots stay allowed: {r}");
        assert_eq!(r.matches("Disallow: /\n").count(), 1);
        let r = robots_txt("https://a.example", &app(serde_json::json!({"aiVisibility": {"allowSearchBots": false, "allowTrainingBots": false}})), false);
        assert_eq!(r.matches("Disallow: /\n").count(), 2);
        assert!(r.contains("User-agent: Googlebot\n"));
        assert!(robots_txt("https://a.example", &AppInfo::default(), true).contains("User-agent: *\nDisallow: /\n"));
        let own = app(serde_json::json!({"seoFiles": {"robotsTxt": "User-agent: *\nDisallow: /x"}}));
        assert_eq!(robots_txt("https://a.example", &own, false), "User-agent: *\nDisallow: /x\n");
    }

    fn page(v: serde_json::Value) -> PageInfo {
        PageInfo::of(&j(v))
    }

    #[test]
    fn page_values() {
        let p = page(serde_json::json!({"name": "about", "updatedAt": 1_700_000_000, "permission": " ",
            "properties": {"title": {"name": {"value": "About us"}}, "seo": {"description": {"value": "Who we are"}, "robots": {"value": "index"}}}}));
        assert_eq!(p.title.as_deref(), Some("About us"));
        assert_eq!(p.description.as_deref(), Some("Who we are"));
        assert_eq!(p.updated, Some(1_700_000_000));
        assert!(!p.signed_in && !p.noindex);
        let p = page(serde_json::json!({"name": "x", "title": "Plain", "permission": "Authorities.Logged_IN",
            "properties": {"title": {"name": {"location": {"expression": "Store.t"}}}, "seo": {"robots": {"value": "NoIndex, follow"}}}}));
        assert_eq!(p.title.as_deref(), Some("Plain"));
        assert!(p.signed_in && p.noindex);
        assert_eq!(page(serde_json::json!({"name": "g", "properties": {"title": "Grouped"}})).title.as_deref(), Some("Grouped"));
        let p = page(serde_json::json!({"name": "blog", "properties": {"seo": {"paths": {"value": {"first post": {}, "/b/c/": {}}}}}}));
        assert_eq!(p.slugs, vec!["first post", "b/c"]);
        let a = app(serde_json::json!({"defaultPage": "home"}));
        assert_eq!(p.paths(&a), vec!["/blog", "/blog/first%20post", "/blog/b/c"]);
        assert!(page(serde_json::json!({"name": "s", "properties": {"seo": {"paths": {"uri": "/api/x"}}}})).slugs.is_empty());
    }

    #[test]
    fn sitemap_lists_public_pages_only() {
        let a = app(serde_json::json!({"defaultPage": "home", "loginPage": "login"}));
        let pages = vec![
            page(serde_json::json!({"name": "home", "updatedAt": 0})),
            page(serde_json::json!({"name": "pricing & plans", "updatedAt": 1_762_400_000})),
            page(serde_json::json!({"name": "admin", "permission": "Authorities.ROLE_Owner"})),
            page(serde_json::json!({"name": "login"})),
            page(serde_json::json!({"name": "hidden", "properties": {"seo": {"robots": "noindex"}}})),
        ];
        let aliases = vec![("/plans".to_string(), "pricing & plans".to_string()), ("/secret".to_string(), "admin".to_string())];
        let e = entries(&a, &pages, &aliases);
        let paths: Vec<&str> = e.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, vec!["/", "/plans", "/pricing%20%26%20plans"]);
        let xml = sitemap_xml("https://s.example", &e);
        assert!(xml.contains("<loc>https://s.example/</loc>\n    <lastmod>1970-01-01T00:00:00+00:00</lastmod>"), "{xml}");
        assert!(xml.contains("<loc>https://s.example/pricing%20%26%20plans</loc>\n    <lastmod>2025-11-06T03:33:20+00:00</lastmod>"), "{xml}");
        assert!(!xml.contains("admin") && !xml.contains("login") && !xml.contains("hidden"));
    }

    #[test]
    fn aliases_of_uri_paths() {
        let u = |name: &str, def: serde_json::Value| j(serde_json::json!({"name": name, "pathDefinitions": {"GET": def}}));
        let redirect = |t: &str| serde_json::json!({"uriType": "REDIRECTION", "redirectionDefinition": {"targetUrl": t}});
        assert_eq!(uri_path_alias(&u("/plans", redirect("/pricing?x=1"))), Some(("/plans".into(), "pricing".into())));
        assert_eq!(uri_path_alias(&u("/p", redirect("/app/SYSTEM/page/about"))), Some(("/p".into(), "about".into())));
        assert_eq!(uri_path_alias(&u("/start", redirect("/"))), Some(("/start".into(), "".into())));
        assert_eq!(uri_path_alias(&u("/blog/**", redirect("/blog"))), None);
        assert_eq!(uri_path_alias(&u("/x", redirect("https://elsewhere/"))), None);
        assert_eq!(uri_path_alias(&u("/x", serde_json::json!({"uriType": "KIRUN_FUNCTION"}))), None);
    }

    #[test]
    fn merged_copies() {
        let order = vec!["SYSTEM".to_string(), "FIN".to_string()];
        let rows = vec![
            j(serde_json::json!({"name": "a", "clientCode": "FIN", "updatedAt": 5, "properties": {"seo": {"description": {"value": "mine"}}}})),
            j(serde_json::json!({"name": "a", "clientCode": "SYSTEM", "updatedAt": 9, "permission": null,
                "properties": {"title": "T", "seo": {"description": {"value": "base"}, "robots": {"value": "index"}}}})),
            j(serde_json::json!({"name": "b", "clientCode": "SYSTEM", "permission": "P"})),
        ];
        let m = merge_copies(rows, &order);
        assert_eq!(m.len(), 2);
        let a = PageInfo::of(&m[0]);
        assert_eq!((a.title.as_deref(), a.description.as_deref(), a.updated), (Some("T"), Some("mine"), Some(9)));
        assert!(PageInfo::of(&m[1]).signed_in);
    }

    #[test]
    fn llms_text() {
        let a = app(serde_json::json!({"title": "Site", "og": {"description": "What  we\ndo"}, "defaultPage": "home"}));
        let pages = vec![
            page(serde_json::json!({"name": "home", "properties": {"title": "Home [main]"}})),
            page(serde_json::json!({"name": "faq", "properties": {"seo": {"description": "Answers"}}})),
            page(serde_json::json!({"name": "admin", "permission": "P"})),
        ];
        let t = llms_txt("https://s.example", &a, &pages).unwrap();
        assert_eq!(t, "# Site\n\n> What we do\n\n## Pages\n\n- [Home \\[main\\]](https://s.example/)\n- [faq](https://s.example/faq): Answers\n");
        let off = app(serde_json::json!({"aiVisibility": {"llmsTxt": false}, "seoFiles": {"llmsTxt": "# own"}}));
        assert_eq!(llms_txt("https://s.example", &off, &pages), None);
        let own = app(serde_json::json!({"seoFiles": {"llmsTxt": "# own"}}));
        assert_eq!(llms_txt("https://s.example", &own, &pages).as_deref(), Some("# own"));
        assert_eq!(llms_txt("https://s.example", &AppInfo::default(), &[]).as_deref(), Some("# s.example\n"));
    }

    #[test]
    fn keys_and_pings() {
        let k = indexnow_key("modlix-indexnow", "sitezump");
        assert_eq!(k.len(), 32);
        assert!(k.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(k, indexnow_key("modlix-indexnow", "sitezump"));
        assert_ne!(k, indexnow_key("modlix-indexnow", "other"));
        assert_ne!(k, indexnow_key("rotated", "sitezump"));
        let b = indexnow_body("https://s.example/", &k, &["https://s.example/".into()]);
        assert_eq!(b["host"], "s.example");
        assert_eq!(b["keyLocation"], "https://s.example/indexnow.txt");
        assert_eq!(b["urlList"][0], "https://s.example/");
    }
}
