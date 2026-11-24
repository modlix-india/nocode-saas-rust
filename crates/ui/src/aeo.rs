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
//!
//! Which public pages the sitemap and llms.txt list (`decide`): the app's own choice per page in
//! `properties.sitemap.pages` (`{"<page>": true|false}`) first; otherwise the home page, a page
//! with an `seo.description`, the target of a URI path alias, and a page linked from one of those
//! (or from a page the app chose to list). Everything else (a screen nobody links to from the
//! public site, a test page) stays out. A page whose `seo.paths` names a `list` source also lists
//! every path that source answers (`parse_list`).

use std::collections::{HashMap, HashSet};

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
    /// The home page is never one of them, even when it is also the login page.
    pub utility_pages: Vec<String>,
    /// `properties.sitemap.pages`: `true` lists the page, `false` keeps it out, missing decides
    /// by itself (`decide`).
    pub sitemap_pages: HashMap<String, bool>,
    pub visibility: Option<AiVisibility>,
    pub robots_override: Option<String>,
    pub llms_override: Option<String>,
    /// `og.canonicalBase`, the address IndexNow falls back to when security knows none.
    pub canonical_base: Option<String>,
    /// `shellPage`: its links only mark a page `Reason::ShellOnly`.
    pub shell_page: Option<String>,
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
        let default_page = text(props.get("defaultPage"));
        let utility_pages = ["loginPage", "notFoundPage", "forbiddenPage", "shellPage", "consentPage"]
            .iter()
            .filter_map(|k| text(props.get(*k)))
            .filter(|p| default_page.as_deref() != Some(p.as_str()))
            .collect();
        let sitemap_pages = map_field(props, "sitemap")
            .and_then(|m| m.get("pages"))
            .and_then(static_value)
            .and_then(|v| match v {
                JValue::Object(m) => Some(m),
                _ => None,
            })
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| {
                        let on = match static_value(v)? {
                            JValue::Bool(b) => *b,
                            JValue::Str(s) if s.trim().eq_ignore_ascii_case("true") => true,
                            JValue::Str(s) if s.trim().eq_ignore_ascii_case("false") => false,
                            _ => return None,
                        };
                        Some((k.clone(), on))
                    })
                    .collect()
            })
            .unwrap_or_default();
        Self {
            title: text(props.get("title")).or_else(|| og_text("siteName")).or_else(|| og_text("title")),
            description: text(props.get("description")).or_else(|| og_text("description")),
            default_page,
            utility_pages,
            sitemap_pages,
            visibility: Some(AiVisibility::of(props)),
            robots_override: file("robotsTxt"),
            llms_override: file("llmsTxt"),
            canonical_base: og_text("canonicalBase").map(|b| b.trim_end_matches('/').to_string()),
            shell_page: text(props.get("shellPage")),
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
    /// proposal); a path source (`{"uri": ...}`) lists nothing by itself.
    pub slugs: Vec<String>,
    /// `seo.paths.list` of a path source: an `/api/` address answering every path of the page
    /// (`parse_list`).
    pub list_source: Option<String>,
    /// The page names this page's components and events may link to (`link_names`), unfiltered:
    /// `decide` keeps the ones that are pages.
    pub links: Vec<String>,
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
        let paths = seo.and_then(|s| s.get("paths")).and_then(static_value);
        let source = matches!(paths, Some(JValue::Object(m)) if m.get("uri").is_some_and(|u| matches!(u, JValue::Str(_))));
        let slugs = match paths {
            Some(JValue::Object(m)) if !source => m.keys().map(|k| k.trim_matches('/').to_string()).filter(|k| !k.is_empty()).collect(),
            _ => Vec::new(),
        };
        let list_source = match paths {
            Some(JValue::Object(m)) if source => match m.get("list") {
                Some(JValue::Str(l)) if l.trim().starts_with("/api/") && !l.contains("://") => Some(l.trim().to_string()),
                _ => None,
            },
            _ => None,
        };
        let mut links = Vec::new();
        for k in ["componentDefinition", "eventFunctions"] {
            if let Some(v) = page.get(k) {
                link_names(v, false, &mut links);
            }
        }
        links.sort();
        links.dedup();
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
            list_source,
            links,
        }
    }

    /// Why the page can never be listed, whatever the app chose: `None` for a public page.
    fn barred(&self, app: &AppInfo) -> Option<Reason> {
        if self.signed_in {
            Some(Reason::SignedIn)
        } else if self.noindex {
            Some(Reason::NoIndex)
        } else if app.utility_pages.contains(&self.name) {
            Some(Reason::Utility)
        } else {
            None
        }
    }

    /// Whether the page may be named in an IndexNow ping: public, and not kept out of the
    /// sitemap by the app's choice. (Whether it is linked is the sitemap's question, `decide`.)
    pub fn eligible(&self, app: &AppInfo) -> bool {
        !self.name.trim().is_empty() && self.barred(app).is_none() && app.sitemap_pages.get(&self.name) != Some(&false)
    }

    /// The page's own path (`/` for the app's default page) and its slugs' paths.
    pub fn paths(&self, app: &AppInfo) -> Vec<String> {
        let own = if app.default_page.as_deref() == Some(self.name.as_str()) { "/".to_string() } else { format!("/{}", segment(&self.name)) };
        let mut out = vec![own];
        for s in &self.slugs {
            out.push(self.slug_path(s));
        }
        out
    }

    /// `/<page>/<slug>`, each segment encoded.
    pub fn slug_path(&self, slug: &str) -> String {
        let encoded: Vec<String> = slug.split('/').filter(|p| !p.is_empty()).map(segment).collect();
        format!("/{}/{}", segment(&self.name), encoded.join("/"))
    }
}

/// Why a page is in the sitemap or not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// The app's default page.
    Home,
    /// `properties.sitemap.pages.<page>` is `true`.
    Included,
    /// The page has an `seo.description`.
    Described,
    /// A URI path is a short address for the page.
    Alias,
    /// A page listed for one of the reasons above links to it (`Decision::linked_from`).
    Linked,
    /// `properties.sitemap.pages.<page>` is `false`.
    Excluded,
    /// The page has a `permission`.
    SignedIn,
    /// `seo.robots` says `noindex`.
    NoIndex,
    /// The login, not found, forbidden, shell or consent page.
    Utility,
    /// Not listed: only the app's shell page (its header and footer) links to it. The shell of an
    /// app is often the signed in frame, so its links do not list a page; a panel suggests
    /// listing it by hand (`Decision::linked_from` is the shell).
    ShellOnly,
    /// None of the reasons to list it.
    NotLinked,
}

impl Reason {
    pub fn code(self) -> &'static str {
        match self {
            Reason::Home => "home",
            Reason::Included => "included",
            Reason::Described => "described",
            Reason::Alias => "alias",
            Reason::Linked => "linked",
            Reason::Excluded => "excluded",
            Reason::SignedIn => "signedIn",
            Reason::NoIndex => "noindex",
            Reason::Utility => "utility",
            Reason::ShellOnly => "shellOnly",
            Reason::NotLinked => "notLinked",
        }
    }
}

/// Whether one page is listed, and why; in the order of the pages given to `decide`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub name: String,
    pub listed: bool,
    pub reason: Reason,
    /// For `Reason::Linked`: the listed page that links to it.
    pub linked_from: Option<String>,
    /// The app's choice: `properties.sitemap.pages.<page>`.
    pub setting: Option<bool>,
}

/// Which pages the sitemap and llms.txt list. A page that can never be listed (signed in,
/// `noindex`, a utility page) is not, whatever the app chose; then the app's choice; then the
/// home page, a described page and an alias target are listed on their own, and so is a page one
/// of those links to. A URL driven page (`seo.paths` with a `list` or static slugs) is listed
/// when any listed page links to it, so a blog's posts follow its index page.
pub fn decide(app: &AppInfo, pages: &[PageInfo], aliases: &[(String, String)]) -> Vec<Decision> {
    let home = app.default_page.as_deref().unwrap_or("");
    let alias_targets: HashSet<&str> = aliases.iter().map(|(_, pg)| if pg.is_empty() { home } else { pg.as_str() }).collect();
    let mut out: Vec<Decision> = pages
        .iter()
        .map(|p| {
            let setting = app.sitemap_pages.get(&p.name).copied();
            let (listed, reason) = match p.barred(app) {
                Some(r) => (false, r),
                None if p.name.trim().is_empty() => (false, Reason::NotLinked),
                None if setting == Some(false) => (false, Reason::Excluded),
                None if p.name == home => (true, Reason::Home),
                None if setting == Some(true) => (true, Reason::Included),
                None if p.description.is_some() => (true, Reason::Described),
                None if alias_targets.contains(p.name.as_str()) => (true, Reason::Alias),
                None => (false, Reason::NotLinked),
            };
            Decision { name: p.name.clone(), listed, reason, linked_from: None, setting }
        })
        .collect();
    let by_name: HashMap<&str, usize> = pages.iter().enumerate().map(|(i, p)| (p.name.as_str(), i)).collect();
    let link = |out: &mut Vec<Decision>, from: usize, url_driven_only: bool| {
        for l in &pages[from].links {
            let Some(&j) = by_name.get(l.as_str()) else { continue };
            let url_driven = pages[j].list_source.is_some() || !pages[j].slugs.is_empty();
            if j != from && out[j].reason == Reason::NotLinked && !pages[j].name.trim().is_empty() && (url_driven || !url_driven_only) {
                out[j].listed = true;
                out[j].reason = Reason::Linked;
                out[j].linked_from = Some(pages[from].name.clone());
            }
        }
    };
    // The home page first, so a page it links to names it.
    let mut roots: Vec<usize> = (0..out.len()).filter(|&i| out[i].listed).collect();
    roots.sort_by_key(|&i| out[i].reason != Reason::Home);
    for &r in &roots {
        link(&mut out, r, false);
    }
    let linked: Vec<usize> = (0..out.len()).filter(|&i| out[i].reason == Reason::Linked).collect();
    for r in linked {
        link(&mut out, r, true);
    }
    if let Some(&sh) = app.shell_page.as_deref().and_then(|n| by_name.get(n)) {
        for l in &pages[sh].links {
            if let Some(&j) = by_name.get(l.as_str()) {
                if out[j].reason == Reason::NotLinked && !pages[j].name.trim().is_empty() {
                    out[j].reason = Reason::ShellOnly;
                    out[j].linked_from = Some(pages[sh].name.clone());
                }
            }
        }
    }
    out
}

/// Keys whose value is somewhere to go: a component's `linkPath`, a Navigate step's `linkPath`
/// or `pageName`, an `href` or `url`.
fn link_key(k: &str) -> bool {
    let k = k.to_ascii_lowercase();
    k.contains("linkpath") || k == "pagename" || k == "href" || k == "url"
}

/// The names a page definition may link to (see `names_in`); a value under a link key may be a
/// bare name.
fn link_names(v: &JValue, link: bool, out: &mut Vec<String>) {
    match v {
        JValue::Str(s) => names_in(s, link, out),
        JValue::Array(a) => a.iter().for_each(|x| link_names(x, link, out)),
        JValue::Object(m) => m.iter().for_each(|(k, x)| link_names(x, link || link_key(k), out)),
        _ => {}
    }
}

/// The page names a text may link to: the whole text under a link key (`pricing`, `/pricing`,
/// `/page/pricing`, `https://host/pricing?x`), and every `/<name>` that starts the text or follows
/// a quote, a bracket, `=`, `>` or a space (a link in markdown or HTML, a path in an expression).
fn names_in(s: &str, link: bool, out: &mut Vec<String>) {
    if s.len() > 200_000 {
        return;
    }
    if link {
        out.extend(first_segment(s.trim()));
    }
    let b = s.as_bytes();
    for (i, c) in b.iter().enumerate() {
        let starts = i == 0 || matches!(b[i - 1], b'"' | b'\'' | b'(' | b'=' | b' ' | b'\n' | b'>' | b'`');
        if *c == b'/' && starts && b.get(i + 1) != Some(&b'/') {
            out.extend(first_segment(&s[i..]));
        }
    }
}

/// The page a path names: its first segment, or the one after `page` (`/app/SYSTEM/page/x`).
fn first_segment(s: &str) -> Option<String> {
    let s = match s.find("://") {
        Some(i) => {
            let rest = &s[i + 3..];
            &rest[rest.find('/').unwrap_or(rest.len())..]
        }
        None => s,
    };
    let path = s.split(['?', '#', '"', '\'', ')', ' ', '\n', '<', '`']).next().unwrap_or("");
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    let name = match parts.iter().position(|p| *p == "page") {
        Some(i) => parts.get(i + 1).copied(),
        None => parts.first().copied(),
    }?;
    (name.len() <= 200 && name.chars().all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.' | '~'))).then(|| name.to_string())
}

/// The paths a page's `seo.paths.list` source answered: an array of slugs, or of
/// `{path | slug, lastmod | updatedAt | modifiedAt}` objects (epoch seconds or milliseconds, or
/// an RFC 3339 / `YYYY-MM-DD` date), or an object holding that array under `paths`, `content`,
/// `items` or `data`. A slug may repeat the page's own name in front (`/blogPost/x`). At most
/// [`MAX_URLS`].
pub fn parse_list(body: &JValue, page: &str) -> Vec<(String, Option<i64>)> {
    let items = match body {
        JValue::Array(a) => Some(a),
        JValue::Object(m) => ["paths", "content", "items", "data"].iter().find_map(|k| match m.get(*k) {
            Some(JValue::Array(a)) => Some(a),
            _ => None,
        }),
        _ => None,
    };
    let Some(items) = items else { return Vec::new() };
    let stamp = |v: Option<&JValue>| -> Option<i64> {
        match v? {
            JValue::Int(n) => Some(if *n > 100_000_000_000 { n / 1000 } else { *n }),
            JValue::Float(f) => Some(if *f > 1e11 { (*f / 1000.0) as i64 } else { *f as i64 }),
            JValue::Str(s) => DateTime::parse_from_rfc3339(s.trim())
                .map(|d| d.timestamp())
                .ok()
                .or_else(|| chrono::NaiveDate::parse_from_str(s.trim(), "%Y-%m-%d").ok().and_then(|d| d.and_hms_opt(0, 0, 0)).map(|d| d.and_utc().timestamp())),
            _ => None,
        }
    };
    let prefix = format!("{page}/");
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for it in items {
        let (slug, lastmod) = match it {
            JValue::Str(s) => (s.as_str(), None),
            JValue::Object(m) => match m.get("path").or_else(|| m.get("slug")) {
                Some(JValue::Str(s)) => (s.as_str(), stamp(m.get("lastmod").or_else(|| m.get("updatedAt")).or_else(|| m.get("modifiedAt")))),
                _ => continue,
            },
            _ => continue,
        };
        let slug = slug.trim().trim_matches('/');
        let slug = slug.strip_prefix(&prefix).unwrap_or(slug).trim_matches('/');
        if slug.is_empty() || slug.len() > 300 || !seen.insert(slug.to_string()) {
            continue;
        }
        out.push((slug.to_string(), lastmod));
        if out.len() >= MAX_URLS {
            break;
        }
    }
    out
}

/// Characters a path segment keeps as they are (RFC 3986 unreserved).
const SEGMENT: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'.').remove(b'_').remove(b'~');

fn segment(s: &str) -> String {
    utf8_percent_encode(s, SEGMENT).to_string()
}

/// The fields of a page the files read, for a projected query.
pub fn page_projection() -> Document {
    doc! {"name": 1, "appCode": 1, "clientCode": 1, "permission": 1, "title": 1, "updatedAt": 1, "published": 1,
        "properties.title": 1, "properties.seo": 1, "componentDefinition": 1, "eventFunctions": 1}
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

/// The sitemap's entries: every listed page's paths (a page with a `list` source: the paths it
/// answered, in `sourced` by page name, instead of its bare address), then the URI path aliases
/// of listed pages; the home page first, the rest by path, each path once, at most [`MAX_URLS`].
pub fn entries(app: &AppInfo, pages: &[PageInfo], aliases: &[(String, String)], sourced: &HashMap<String, Vec<(String, Option<i64>)>>) -> Vec<Entry> {
    let mut out: Vec<Entry> = Vec::new();
    let decisions = decide(app, pages, aliases);
    let listed: Vec<&PageInfo> = pages.iter().zip(&decisions).filter(|(_, d)| d.listed).map(|(p, _)| p).collect();
    for p in &listed {
        let bare = p.list_source.is_none() || app.default_page.as_deref() == Some(p.name.as_str());
        for (i, path) in p.paths(app).into_iter().enumerate() {
            if i > 0 || bare {
                out.push(Entry { path, lastmod: p.updated });
            }
        }
        for (slug, lastmod) in sourced.get(&p.name).map(Vec::as_slice).unwrap_or_default() {
            out.push(Entry { path: p.slug_path(slug), lastmod: lastmod.or(p.updated) });
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
    let decisions = decide(app, pages, &[]);
    let mut listed: Vec<(String, &PageInfo)> = pages
        .iter()
        .zip(&decisions)
        .filter(|(p, d)| d.listed && p.list_source.is_none())
        .filter_map(|(p, _)| p.paths(app).into_iter().next().map(|path| (path, p)))
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
        let e = entries(&a, &pages, &aliases, &HashMap::new());
        let paths: Vec<&str> = e.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, vec!["/", "/plans", "/pricing%20%26%20plans"]);
        let xml = sitemap_xml("https://s.example", &e);
        assert!(xml.contains("<loc>https://s.example/</loc>\n    <lastmod>1970-01-01T00:00:00+00:00</lastmod>"), "{xml}");
        assert!(xml.contains("<loc>https://s.example/pricing%20%26%20plans</loc>\n    <lastmod>2025-11-06T03:33:20+00:00</lastmod>"), "{xml}");
        assert!(!xml.contains("admin") && !xml.contains("login") && !xml.contains("hidden"));
    }

    fn decided(a: &AppInfo, pages: &[PageInfo]) -> Vec<(String, bool, &'static str, Option<String>)> {
        decide(a, pages, &[]).into_iter().map(|d| (d.name, d.listed, d.reason.code(), d.linked_from)).collect()
    }

    #[test]
    fn home_is_listed_even_as_the_login_page() {
        let a = app(serde_json::json!({"defaultPage": "home", "loginPage": "home", "notFoundPage": "nf"}));
        assert_eq!(a.utility_pages, vec!["nf".to_string()]);
        let e = entries(&a, &[page(serde_json::json!({"name": "home"}))], &[], &HashMap::new());
        assert_eq!(e.iter().map(|e| e.path.as_str()).collect::<Vec<_>>(), vec!["/"]);
    }

    #[test]
    fn links_choices_and_screens() {
        let a = app(serde_json::json!({"defaultPage": "home", "loginPage": "signIn", "shellPage": "shell",
            "sitemap": {"pages": {"legal": true, "ad": false, "secret": true, "forgot": "true"}}}));
        let pages = vec![
            page(serde_json::json!({"name": "home", "componentDefinition": {
                "b1": {"properties": {"linkPath": {"value": "/pricing"}}},
                "t1": {"properties": {"text": {"value": "See [our story](/about) or <a href=\"/page/team\">the team</a>"}}},
                "b2": {"properties": {"linkPath": {"value": "signIn"}}},
                "b3": {"properties": {"linkPath": {"value": "ad"}}}},
                "eventFunctions": {"go": {"steps": {"n": {"name": "Navigate", "parameterMap": {"linkPath": {"x": {"value": "blog"}}}}}}}})),
            page(serde_json::json!({"name": "pricing"})),
            page(serde_json::json!({"name": "about", "componentDefinition": {"l": {"properties": {"linkPath": {"value": "/careers"}}}}})),
            page(serde_json::json!({"name": "team"})),
            page(serde_json::json!({"name": "careers"})),
            page(serde_json::json!({"name": "signIn", "componentDefinition": {"l": {"properties": {"linkPath": {"value": "/forgot"}}}}})),
            page(serde_json::json!({"name": "forgot"})),
            page(serde_json::json!({"name": "ad"})),
            page(serde_json::json!({"name": "legal"})),
            page(serde_json::json!({"name": "secret", "permission": "Authorities.Logged_IN"})),
            page(serde_json::json!({"name": "dealSettings"})),
            page(serde_json::json!({"name": "shell", "componentDefinition": {"f": {"properties": {"linkPath": {"value": "/privacy"}}}}})),
            page(serde_json::json!({"name": "privacy"})),
            page(serde_json::json!({"name": "blog", "properties": {"seo": {"description": "Posts"}},
                "componentDefinition": {"c": {"properties": {"linkPath": {"location": {"expression": "'/blogPost/' + Parent.slug"}}}}}})),
            page(serde_json::json!({"name": "blogPost", "properties": {"seo": {"paths": {"value": {"uri": "/api/open/blog/post/{path}", "list": "/api/open/blog/posts"}}}}})),
        ];
        let d = decided(&a, &pages);
        let get = |n: &str| d.iter().find(|r| r.0 == n).cloned().unwrap();
        assert_eq!(get("home"), ("home".into(), true, "home", None));
        assert_eq!(get("pricing"), ("pricing".into(), true, "linked", Some("home".into())));
        assert_eq!(get("about"), ("about".into(), true, "linked", Some("home".into())));
        assert_eq!(get("team"), ("team".into(), true, "linked", Some("home".into())));
        // One step only: a page linked from a merely linked page is not listed.
        assert_eq!(get("careers").2, "notLinked");
        assert_eq!(get("signIn").2, "utility");
        assert_eq!(get("forgot"), ("forgot".into(), true, "included", None));
        assert_eq!(get("ad").2, "excluded");
        assert_eq!(get("legal").2, "included");
        assert_eq!(get("secret").2, "signedIn");
        assert_eq!(get("dealSettings").2, "notLinked");
        assert_eq!(get("privacy"), ("privacy".into(), false, "shellOnly", Some("shell".into())));
        assert_eq!(get("blog"), ("blog".into(), true, "described", None));
        assert_eq!(get("blogPost"), ("blogPost".into(), true, "linked", Some("blog".into())));

        let mut sourced = HashMap::new();
        sourced.insert("blogPost".to_string(), vec![("first post".to_string(), Some(1_762_400_000)), ("b".to_string(), None)]);
        let e = entries(&a, &pages, &[], &sourced);
        let paths: Vec<&str> = e.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, vec!["/", "/about", "/blog", "/blogPost/b", "/blogPost/first%20post", "/forgot", "/legal", "/pricing", "/team"]);
        assert!(pages[14].eligible(&a) && !pages[7].eligible(&a) && !pages[9].eligible(&a));
    }

    #[test]
    fn list_sources_answer_paths() {
        let v = |x: serde_json::Value| overridable::json::parse(x.to_string().as_bytes()).unwrap();
        assert_eq!(parse_list(&v(serde_json::json!(["a", "/b/", "a", "", "blogPost/c"])), "blogPost"),
            vec![("a".into(), None), ("b".into(), None), ("c".into(), None)]);
        assert_eq!(
            parse_list(&v(serde_json::json!({"content": [{"slug": "x", "updatedAt": 1_762_400_000_000_i64}, {"path": "y", "lastmod": "2025-11-06"},
                {"path": "z", "modifiedAt": "2025-11-06T03:33:20Z"}, {"title": "no path"}]})), "p"),
            vec![("x".into(), Some(1_762_400_000)), ("y".into(), Some(1_762_387_200)), ("z".into(), Some(1_762_400_000))]
        );
        assert!(parse_list(&v(serde_json::json!({"nothing": 1})), "p").is_empty());
        let p = page(serde_json::json!({"name": "s", "properties": {"seo": {"paths": {"uri": "/api/x/{path}", "list": "https://evil/x"}}}}));
        assert_eq!(p.list_source, None);
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
