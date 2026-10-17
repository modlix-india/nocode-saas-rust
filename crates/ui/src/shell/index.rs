//! `IndexHTMLService`: the HTML document every page of an app loads first, built from the
//! application's `properties` (title, links, scripts, metas, Open Graph, fonts, icons, code
//! parts, loader, analytics beacon, CSP) and the webpack entry points.

use overridable::{JMap, JValue};

use crate::shell::config::ShellSection;
use crate::shell::javautil::{derive_beacon_host, escape_html, md5_unique_id};

const LINK_FIELDS: [&str; 9] = ["crossorigin", "href", "hreflang", "media", "referrerpolicy", "rel", "sizes", "title", "type"];
const SCRIPT_FIELDS: [&str; 8] = ["async", "type", "crossorigin", "defer", "integrity", "nomodule", "referrerpolicy", "src"];
const META_FIELDS: [&str; 5] = ["charset", "name", "http-equiv", "property", "content"];
const PROPERTY: &str = "property";
const THEME_COOKIE_PREFIX: &str = "mlxTheme_";
const APP_STYLE_LINK_ID: &str = "mlxAppStyle";

pub const CACHE_NAME_INDEX: &str = "indexNewCache";

fn icon_pack(name: &str) -> Option<&'static str> {
    Some(match name {
        "FREE_FONT_AWESOME_ALL" => "<link href=\"https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.7.2/css/all.min.css\" rel=\"stylesheet\" />",
        "MATERIAL_SYMBOLS_OUTLINED" => "<link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@20..48,100..700,0..1,-50..200\" rel=\"stylesheet\" /><link href=\"https://cdn.jsdelivr.net/gh/fincity-india/nocode-ui-icon-packs@master/dist/fonts/MATERIAL_SYMBOLS/font.css\" rel=\"stylesheet\" />",
        "MATERIAL_SYMBOLS_ROUNDED" => "<link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Rounded:opsz,wght,FILL,GRAD@20..48,100..700,0..1,-50..200\" rel=\"stylesheet\" /><link href=\"https://cdn.jsdelivr.net/gh/fincity-india/nocode-ui-icon-packs@master/dist/fonts/MATERIAL_SYMBOLS/font.css\" rel=\"stylesheet\" />",
        "MATERIAL_SYMBOLS_SHARP" => "<link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Sharp:opsz,wght,FILL,GRAD@20..48,100..700,0..1,-50..200\" rel=\"stylesheet\" /><link href=\"https://cdn.jsdelivr.net/gh/fincity-india/nocode-ui-icon-packs@master/dist/fonts/MATERIAL_SYMBOLS/font.css\" rel=\"stylesheet\" />",
        "MATERIAL_ICONS_FILLED" => "<link href=\"https://fonts.googleapis.com/css2?family=Material+Icons\" rel=\"stylesheet\" /><link href=\"https://cdn.jsdelivr.net/gh/fincity-india/nocode-ui-icon-packs@master/dist/fonts/MATERIAL_ICONS/font.css\" rel=\"stylesheet\" />",
        "MATERIAL_ICONS_OUTLINED" => "<link href=\"https://fonts.googleapis.com/css2?family=Material+Icons+Outlined\" rel=\"stylesheet\" /><link href=\"https://cdn.jsdelivr.net/gh/fincity-india/nocode-ui-icon-packs@master/dist/fonts/MATERIAL_ICONS/font.css\" rel=\"stylesheet\" />",
        "MATERIAL_ICONS_ROUNDED" => "<link href=\"https://fonts.googleapis.com/css2?family=Material+Icons+Round\" rel=\"stylesheet\" /><link href=\"https://cdn.jsdelivr.net/gh/fincity-india/nocode-ui-icon-packs@master/dist/fonts/MATERIAL_ICONS/font.css\" rel=\"stylesheet\" />",
        "MATERIAL_ICONS_SHARP" => "<link href=\"https://fonts.googleapis.com/css2?family=Material+Icons+Sharp\" rel=\"stylesheet\" /><link href=\"https://cdn.jsdelivr.net/gh/fincity-india/nocode-ui-icon-packs@master/dist/fonts/MATERIAL_ICONS/font.css\" rel=\"stylesheet\" />",
        "MATERIAL_ICONS_TWO_TONE" => "<link href=\"https://fonts.googleapis.com/css2?family=Material+Icons+Two+Tone\" rel=\"stylesheet\" /><link href=\"https://cdn.jsdelivr.net/gh/fincity-india/nocode-ui-icon-packs@master/dist/fonts/MATERIAL_ICONS/font.css\" rel=\"stylesheet\" />",
        _ => return None,
    })
}

const DEFAULT_LOADER: &str = "<style>\n\t._initloaderContainer {\n\t\twidth: 100vw;\n\t\theight: 100vh;\n\t\tdisplay: flex;\n\t\tjustify-content: center;\n\t\talign-items: center;\n\t\tposition: fixed;\n\t\tleft:0;\n\t\ttop:0;\n\t}\n\t._initloader {\n\t\t\twidth: 2vmax;\n\t\t\theight: 2vmax;\n\t\t\tborder: 0.5vmin solid rgb(224, 224, 224);\n\t\t\tborder-top: 0.5vmin solid rgb(173, 173, 173);\n\t\t\tborder-radius: 50%;\n\t\t\tanimation: _loaderspin 3s linear infinite;\n\t\t}\n\t\t@keyframes _loaderspin {\n\t\t\t0% {\n\t\t\ttransform: rotate(0deg);\n\t\t\t}\n\t\t\t100% {\n\t\t\ttransform: rotate(360deg);\n\t\t\t}\n\t\t}\n</style>\n<div class=\"_initloaderContainer\"><div class=\"_initloader\"></div></div>";

/// A rendered index page: the document, its id (`ObjectWithUniqueID`'s MD5) and its own
/// headers (the app's CSP).
#[derive(Debug, Clone, PartialEq)]
pub struct IndexPage {
    pub html: String,
    pub unique_id: String,
    pub headers: Vec<(String, String)>,
}

/// What the index refuses to render (a non-integer `order`, as Java's comparator throws).
#[derive(Debug, PartialEq)]
pub struct IndexError(pub String);

/// `StringUtil.safeIsBlank(Object)`.
fn blank(v: Option<&JValue>) -> bool {
    match v {
        None | Some(JValue::Null) => true,
        Some(x) => x.java_to_string().trim().is_empty(),
    }
}

/// `Integer.valueOf(String)`.
fn java_int(s: &str) -> Option<i32> {
    let t = s.strip_prefix('+').unwrap_or(s);
    let digits = t.strip_prefix('-').unwrap_or(t);
    if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    t.parse::<i32>().ok()
}

/// Values of a map property cast to maps and sorted by `order` (`MapWithOrderComparator`, a
/// stable sort).
fn sorted_maps<'a>(values: impl Iterator<Item = &'a JMap>) -> Result<Vec<&'a JMap>, IndexError> {
    let mut keyed = Vec::new();
    for e in values {
        let raw = e.get("order").map(JValue::java_to_string).unwrap_or_else(|| "0".into());
        let k = java_int(&raw).ok_or_else(|| IndexError(format!("For input string: \"{raw}\"")))?;
        keyed.push((k, e));
    }
    if keyed.len() > 1 {
        keyed.sort_by_key(|(k, _)| *k);
    }
    Ok(keyed.into_iter().map(|(_, e)| e).collect())
}

/// A map's values that are maps (Java casts each, and a list of these never holds anything
/// else in practice).
fn map_values(m: Option<&JValue>) -> Vec<&JMap> {
    match m {
        Some(JValue::Object(o)) => o.values().filter_map(JValue::as_object).collect(),
        _ => Vec::new(),
    }
}

fn code_parts(props: &JMap) -> Result<[String; 4], IndexError> {
    let mut out: [String; 4] = Default::default();
    let parts: Vec<&JMap> = map_values(props.get("codeParts")).into_iter().filter(|m| !m.is_empty()).collect();
    for e in sorted_maps(parts.into_iter())? {
        if blank(e.get("part")) || blank(e.get("place")) {
            continue;
        }
        let idx = match e.get("place").map(JValue::java_to_string).as_deref() {
            Some("AFTER_HEAD") => 0,
            Some("BEFORE_HEAD") => 1,
            Some("AFTER_BODY") => 2,
            Some("BEFORE_BODY") => 3,
            _ => continue,
        };
        out[idx].push_str(&e.get("part").map(JValue::java_to_string).unwrap_or_default());
    }
    Ok(out)
}

fn tag_string(tag: &str, attributes: &JMap, fields: &[&str]) -> String {
    let mut s = format!("<{tag}");
    for attr in fields {
        if let Some(v) = attributes.get(*attr) {
            let text = if v.is_null() { String::new() } else { v.java_to_string() };
            s.push_str(&format!(" {attr}=\"{}\"", escape_html(&text)));
        }
    }
    s.push_str("/> \n");
    s
}

fn tag_type(out: &mut String, props: &JMap, key: &str, tag: &str, fields: &[&str], already_said: &[String]) -> Result<(), IndexError> {
    let values = map_values(props.get(key));
    for e in sorted_maps(values.into_iter())? {
        let property = e.get(PROPERTY).filter(|v| !v.is_null()).map(JValue::java_to_string).unwrap_or_default();
        if already_said.contains(&property) {
            continue;
        }
        out.push_str(&tag_string(tag, e, fields));
    }
    Ok(())
}

/// First non-blank candidate, trimmed.
fn first_of(candidates: &[Option<&JValue>]) -> String {
    for c in candidates.iter().flatten() {
        if c.is_null() {
            continue;
        }
        let v = c.java_to_string();
        let t = v.trim();
        if !t.is_empty() {
            return t.to_string();
        }
    }
    String::new()
}

fn append_meta(out: &mut String, emitted: &mut Vec<String>, attribute: &str, property: &str, value: &str) {
    if value.trim().is_empty() || emitted.iter().any(|e| e == property) {
        return;
    }
    emitted.push(property.to_string());
    out.push_str(&format!("<meta {attribute}=\"{property}\" content=\"{}\"/> \n", escape_html(value)));
}

fn absolutise(value: &str, canonical_base: &str) -> String {
    let v = value.trim();
    if v.is_empty() {
        return String::new();
    }
    let lower = v.to_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") || v.starts_with("//") {
        return v.to_string();
    }
    if canonical_base.is_empty() {
        return String::new();
    }
    format!("{canonical_base}/{}", v.trim_start_matches('/'))
}

fn open_graph(og: Option<&JValue>, app_title: &JValue, emitted: &mut Vec<String>) -> String {
    let Some(og) = og.and_then(JValue::as_object).filter(|o| !o.is_empty()) else { return String::new() };
    let empty = JMap::new();
    let image = og.get("image").and_then(JValue::as_object).unwrap_or(&empty);
    let canonical = og
        .get("canonicalBase")
        .filter(|v| !v.is_null())
        .map(JValue::java_to_string)
        .unwrap_or_default();
    let canonical = canonical.trim().trim_end_matches('/').to_string();
    let title = first_of(&[og.get("title"), Some(app_title)]);
    let image_url = absolutise(
        &image.get("url").filter(|v| !v.is_null()).map(JValue::java_to_string).unwrap_or_default(),
        &canonical,
    );
    let description = first_of(&[og.get("description")]);
    if title.is_empty() && image_url.is_empty() && description.is_empty() {
        return String::new();
    }
    let website = JValue::from("website");
    let mut s = String::new();
    append_meta(&mut s, emitted, PROPERTY, "og:title", &title);
    append_meta(&mut s, emitted, PROPERTY, "og:type", &first_of(&[og.get("type"), Some(&website)]));
    if !image_url.is_empty() {
        append_meta(&mut s, emitted, PROPERTY, "og:image", &image_url);
        if image_url.starts_with("https://") {
            append_meta(&mut s, emitted, PROPERTY, "og:image:secure_url", &image_url);
        }
        append_meta(&mut s, emitted, PROPERTY, "og:image:alt", &first_of(&[image.get("alt")]));
        append_meta(&mut s, emitted, PROPERTY, "og:image:type", &first_of(&[image.get("type")]));
        append_meta(&mut s, emitted, PROPERTY, "og:image:width", &first_of(&[image.get("width")]));
        append_meta(&mut s, emitted, PROPERTY, "og:image:height", &first_of(&[image.get("height")]));
    }
    append_meta(&mut s, emitted, PROPERTY, "og:url", &canonical);
    append_meta(&mut s, emitted, PROPERTY, "og:description", &description);
    append_meta(&mut s, emitted, PROPERTY, "og:site_name", &first_of(&[og.get("siteName"), Some(app_title)]));
    append_meta(&mut s, emitted, PROPERTY, "og:locale", &first_of(&[og.get("locale")]));
    if let Some(JValue::Array(alts)) = og.get("localeAlternate") {
        if !alts.is_empty() {
            emitted.push("og:locale:alternate".into());
            for alt in alts {
                let v = first_of(&[Some(alt)]);
                if !v.is_empty() {
                    s.push_str(&format!("<meta property=\"og:locale:alternate\" content=\"{}\"/> \n", escape_html(&v)));
                }
            }
        }
    }
    append_meta(&mut s, emitted, PROPERTY, "og:determiner", &first_of(&[og.get("determiner")]));
    let twitter = og.get("twitter").and_then(JValue::as_object).unwrap_or(&empty);
    let card = JValue::from(if image_url.is_empty() { "summary" } else { "summary_large_image" });
    append_meta(&mut s, emitted, "name", "twitter:card", &first_of(&[twitter.get("card"), Some(&card)]));
    append_meta(&mut s, emitted, "name", "twitter:site", &first_of(&[twitter.get("site")]));
    append_meta(&mut s, emitted, "name", "twitter:creator", &first_of(&[twitter.get("creator")]));
    append_meta(&mut s, emitted, PROPERTY, "fb:app_id", &first_of(&[og.get("fbAppId")]));
    s
}

fn packs(m: Option<&JValue>, icons: bool) -> String {
    let Some(JValue::Object(o)) = m else { return String::new() };
    let parts: Vec<String> = o
        .values()
        .map(|e| {
            let Some(mso) = e.as_object() else { return String::new() };
            if let Some(code) = mso.get("code").filter(|v| !v.is_null()) {
                return code.java_to_string();
            }
            if icons {
                if let Some(p) = mso.get("name").filter(|v| !v.is_null()).and_then(|n| icon_pack(&n.java_to_string())) {
                    return p.to_string();
                }
            }
            String::new()
        })
        .filter(|s| !s.trim().is_empty())
        .collect();
    parts.join("\n")
}

fn bool_attr(v: Option<&JValue>, default: bool) -> bool {
    match v {
        None | Some(JValue::Null) => default,
        Some(JValue::Bool(false)) => false,
        Some(_) => true,
    }
}

fn analytics_snippet(props: &JMap, ingestion_host: &str) -> String {
    if ingestion_host.trim().is_empty() {
        return String::new();
    }
    let Some(JValue::Object(a)) = props.get("analytics") else { return String::new() };
    if a.get("enabled") != Some(&JValue::Bool(true)) {
        return String::new();
    }
    let host = ingestion_host.strip_suffix('/').unwrap_or(ingestion_host);
    let heatmaps = match a.get("heatmaps") {
        Some(JValue::Object(h)) => h.get("enabled"),
        _ => None,
    };
    format!(
        "<script>window.mlx=window.mlx||function(){{(window.mlx.q=window.mlx.q||[]).push(arguments)}};</script><script async src=\"{host}/a.js\" data-autocapture=\"{}\" data-pageviews=\"{}\" data-pageleaves=\"{}\" data-scroll=\"{}\" data-heatmaps=\"{}\" data-consent=\"required\"></script>",
        bool_attr(a.get("autocapture"), true),
        bool_attr(a.get("capturePageviews"), true),
        bool_attr(a.get("capturePageleaves"), true),
        bool_attr(a.get("captureScroll"), true),
        bool_attr(heatmaps, false),
    )
}

/// `defaultSrc` to `default-src`, as the Java loop does it.
fn kebab(key: &str) -> String {
    let mut s = String::with_capacity(key.len() + 4);
    for c in key.chars() {
        if c.is_uppercase() {
            s.push('-');
            s.push(c.to_lowercase().next().unwrap_or(c));
        } else {
            s.push(c);
        }
    }
    s
}

fn csp(m: Option<&JValue>, cdn: &str) -> Option<String> {
    let Some(JValue::Object(o)) = m else { return None };
    if o.is_empty() {
        return None;
    }
    let mut s = String::new();
    for (k, v) in o {
        let mut value = if v.is_null() { String::new() } else { v.java_to_string() };
        if !cdn.trim().is_empty() {
            value = if value.trim().is_empty() { cdn.to_string() } else { format!("{value} {cdn}") };
        }
        if !value.trim().is_empty() {
            s.push_str(&format!("{} {value};", kebab(k)));
        }
    }
    Some(s)
}

fn csp_headers(props: &JMap, cdn: &str) -> Vec<(String, String)> {
    if props.is_empty() {
        return Vec::new();
    }
    let mut h = Vec::new();
    if let Some(v) = csp(props.get("csp"), cdn) {
        h.push(("Content-Security-Policy".to_string(), v));
    }
    if let Some(v) = csp(props.get("cspReport"), cdn) {
        h.push(("Content-Security-Policy-Report-Only".to_string(), v));
    }
    h
}

/// `IndexHTMLService.indexHtml`. `app` is the application after `applyChange`, `None` when the
/// app does not exist (the page is then titled `Error`).
pub fn index_html(
    app: Option<&JMap>,
    app_code: &str,
    client_code: &str,
    draft: bool,
    cfg: &ShellSection,
    entrypoints: &[String],
) -> Result<IndexPage, IndexError> {
    // `new Application(app)`: the copy constructor clones the properties.
    let props: JMap = app
        .and_then(|a| a.get("properties"))
        .and_then(JValue::as_object)
        .map(overridable::pojo::clone_map_object)
        .unwrap_or_default();
    let parts = code_parts(&props)?;
    let mut s = String::with_capacity(8192);
    s.push_str("<!DOCTYPE html><html lang=\"en\"");
    if draft {
        s.push_str(" data-draft=\"true\"");
    }
    s.push_str("><head>");
    s.push_str(&parts[0]);
    s.push_str("<meta charset=\"utf-8\" /><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" /><title>");
    let title = match props.get("title") {
        Some(t) if !t.is_null() => t.clone(),
        _ => match app {
            None => JValue::from("Error"),
            Some(a) => a.get("appCode").cloned().unwrap_or(JValue::Null),
        },
    };
    s.push_str(&title.java_to_string());
    s.push_str("</title>");
    tag_type(&mut s, &props, "links", "link", &LINK_FIELDS, &[])?;
    tag_type(&mut s, &props, "scripts", "script", &SCRIPT_FIELDS, &[])?;
    let mut said: Vec<String> = Vec::new();
    s.push_str(&open_graph(props.get("og"), &title, &mut said));
    tag_type(&mut s, &props, "metas", "meta", &META_FIELDS, &said)?;
    if matches!(props.get("manifest"), Some(JValue::Object(m)) if !m.is_empty()) {
        s.push_str(&format!("<link rel=\"manifest\" href=\"{app_code}/{client_code}/manifest/manifest.json\" />"));
    }
    s.push_str(&packs(props.get("fontPacks"), false));
    s.push_str(&packs(props.get("iconPacks"), true));
    s.push_str(&analytics_snippet(&props, &cfg.analytics_ingestion_host));
    s.push_str(&parts[1]);
    s.push_str("</head><body>");
    s.push_str(&parts[2]);
    s.push_str("<div id=\"app\">");
    match props.get("loader") {
        Some(l) => s.push_str(&l.java_to_string()),
        None => s.push_str(DEFAULT_LOADER),
    }
    s.push_str("</div>");
    s.push_str(&format!("<link rel=\"stylesheet\" id=\"{APP_STYLE_LINK_ID}\" />"));
    s.push_str("<script>");
    s.push_str(&format!("window.__mlxAppCode='{app_code}';"));
    s.push_str(&format!(
        "(function(){{var m=document.cookie.match(/(?:^|;\\s*){THEME_COOKIE_PREFIX}{app_code}=([^;]*)/);document.getElementById('{APP_STYLE_LINK_ID}').setAttribute('href','/{app_code}/{client_code}/page/api/ui/style'+(m?'?theme='+m[1]:''));}})();"
    ));
    let cdn = cfg.cdn_host_name.as_str();
    if !cdn.trim().is_empty() {
        s.push_str(&format!("window.cdnPrefix='{cdn}';"));
        s.push_str(&format!("window.cdnStripAPIPrefix='{}';", cfg.cdn_strip_api_prefix));
        s.push_str(&format!("window.cdnReplacePlus={};", cfg.cdn_replace_plus));
        s.push_str(&format!("window.cdnResizeOptionsType='{}';", cfg.cdn_resize_options_type));
    }
    s.push_str(&format!("window.domainAppCode='{app_code}';"));
    s.push_str(&format!("window.domainClientCode='{client_code}';"));
    let beacon = derive_beacon_host(Some(&cfg.app_code_suffix));
    s.push_str(&format!("window.__SOCIAL_LOGIN_HOST__='{beacon}';"));
    if props.get("sso3") == Some(&JValue::Bool(true)) {
        s.push_str(&format!("window.__SSO_BEACON_HOST__='{beacon}';"));
    }
    s.push_str("</script>");
    let prefix = if cdn.trim().is_empty() { "/js/dist/".to_string() } else { format!("https://{cdn}/js/dist/") };
    for script in entrypoints {
        s.push_str(&format!("<script src=\"{prefix}{script}\"></script>"));
    }
    s.push_str(&parts[3]);
    s.push_str("</body></html>");
    let headers = csp_headers(&props, cdn);
    let unique_id = md5_unique_id(&s);
    Ok(IndexPage { html: s, unique_id, headers })
}

/// The entry points of an `asset-manifest.json` (`entrypoints.index`), `None` when it has none.
pub fn entrypoints_of(manifest: &[u8]) -> Option<Vec<String>> {
    let v: serde_json::Value = serde_json::from_slice(manifest).ok()?;
    let list = v.get("entrypoints")?.get("index")?.as_array()?;
    Some(list.iter().map(|e| e.as_str().map(str::to_string).unwrap_or_else(|| e.to_string())).collect())
}

/// The legacy bundles, when no manifest could be read.
pub fn fallback_entrypoints() -> Vec<String> {
    vec!["vendors.js".into(), "index.js".into()]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> ShellSection {
        ShellSection {
            cdn_host_name: "cdn-local.modlix.com".into(),
            cdn_replace_plus: true,
            app_code_suffix: ".local".into(),
            analytics_ingestion_host: "https://engine.local.modlix.com/".into(),
            ..Default::default()
        }
    }

    fn app(props: serde_json::Value) -> JMap {
        let v = serde_json::json!({"appCode": "demo", "properties": props});
        match overridable::json::parse(v.to_string().as_bytes()).unwrap() {
            JValue::Object(o) => o,
            _ => unreachable!(),
        }
    }

    #[test]
    fn a_missing_app_renders_the_error_page() {
        let p = index_html(None, "x", "SYSTEM", false, &ShellSection::default(), &fallback_entrypoints()).unwrap();
        assert!(p.html.starts_with("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\" />"));
        assert!(p.html.contains("<title>Error</title>"));
        assert!(p.html.contains("window.__SOCIAL_LOGIN_HOST__='authzump.ai';"));
        assert!(!p.html.contains("cdnPrefix"));
        assert!(p.html.ends_with("<script src=\"/js/dist/vendors.js\"></script><script src=\"/js/dist/index.js\"></script></body></html>"));
        assert!(p.headers.is_empty());
        assert_eq!(p.unique_id, md5_unique_id(&p.html));
    }

    #[test]
    fn renders_the_application_properties() {
        let a = app(serde_json::json!({
            "title": "Demo & Co",
            "codeParts": {
                "a": {"order": 2, "place": "BEFORE_BODY", "part": "<i>end</i>"},
                "b": {"order": 1, "place": "AFTER_HEAD", "part": "<i>top</i>"},
                "c": {"place": "BEFORE_HEAD", "part": "<i>bh</i>"},
                "d": {"place": "AFTER_BODY", "part": "<i>ab</i>"},
                "e": {"place": "NOWHERE", "part": "x"},
                "f": {"place": "AFTER_HEAD", "part": " "},
                "g": {}
            },
            "links": {"l1": {"rel": "icon", "href": "/f.png?a=1&b=\"2\"", "order": 1, "x": "ignored"}},
            "scripts": {"s1": {"src": "https://x/y.js", "async": true}},
            "og": {
                "title": " OG title ", "description": "d", "canonicalBase": "https://demo.example/",
                "image": {"url": "/img.png", "alt": "alt", "width": 1200},
                "localeAlternate": ["en_GB", " ", "fr_FR"], "locale": "en_US",
                "twitter": {"site": "@demo"}, "fbAppId": 42, "siteName": "Site", "determiner": "the"
            },
            "metas": {
                "m1": {"property": "og:title", "content": "dropped"},
                "m2": {"name": "description", "content": "It's <ok>"},
                "m3": {"property": "og:locale:alternate", "content": "dropped too"}
            },
            "fontPacks": {"f1": {"code": "<link font/>"}, "f2": {"code": ""}, "f3": "x"},
            "iconPacks": {"i1": {"name": "FREE_FONT_AWESOME_ALL"}, "i2": {"name": "UNKNOWN"}, "i3": {"code": "<link own/>", "name": "MATERIAL_ICONS_SHARP"}},
            "analytics": {"enabled": true, "captureScroll": false, "heatmaps": {"enabled": true}},
            "loader": "<p>loading</p>",
            "sso3": true,
            "manifest": {"name": "m"},
            "csp": {"defaultSrc": "'self'", "imgSrc": "", "fontSrc": null},
            "cspReport": {}
        }));
        let p = index_html(Some(&a), "demo", "SYSTEM", true, &cfg(), &["a.js".to_string()]).unwrap();
        let h = &p.html;
        assert!(h.starts_with("<!DOCTYPE html><html lang=\"en\" data-draft=\"true\"><head><i>top</i><meta charset"));
        assert!(h.contains("<title>Demo & Co</title><link href=\"/f.png?a=1&amp;b=&quot;2&quot;\" rel=\"icon\"/> \n<script async=\"true\" src=\"https://x/y.js\"/> \n"));
        assert!(h.contains("<meta property=\"og:title\" content=\"OG title\"/> \n<meta property=\"og:type\" content=\"website\"/> \n<meta property=\"og:image\" content=\"https://demo.example/img.png\"/> \n<meta property=\"og:image:secure_url\" content=\"https://demo.example/img.png\"/> \n<meta property=\"og:image:alt\" content=\"alt\"/> \n<meta property=\"og:image:width\" content=\"1200\"/> \n<meta property=\"og:url\" content=\"https://demo.example\"/> \n"));
        assert!(h.contains("<meta property=\"og:locale:alternate\" content=\"en_GB\"/> \n<meta property=\"og:locale:alternate\" content=\"fr_FR\"/> \n<meta property=\"og:determiner\" content=\"the\"/> \n<meta name=\"twitter:card\" content=\"summary_large_image\"/> \n<meta name=\"twitter:site\" content=\"@demo\"/> \n<meta property=\"fb:app_id\" content=\"42\"/> \n"));
        assert!(h.contains("<meta name=\"description\" content=\"It&#39;s &lt;ok&gt;\"/> \n"));
        assert!(!h.contains("dropped"));
        assert!(h.contains("<link rel=\"manifest\" href=\"demo/SYSTEM/manifest/manifest.json\" />"));
        assert!(h.contains("<link font/>"));
        assert!(h.contains("<link href=\"https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.7.2/css/all.min.css\" rel=\"stylesheet\" />\n<link own/>") || h.contains("<link own/>\n<link href=\"https://cdnjs"));
        assert!(h.contains("<script async src=\"https://engine.local.modlix.com/a.js\" data-autocapture=\"true\" data-pageviews=\"true\" data-pageleaves=\"true\" data-scroll=\"false\" data-heatmaps=\"true\" data-consent=\"required\"></script><i>bh</i></head><body><i>ab</i><div id=\"app\"><p>loading</p></div>"));
        assert!(h.contains("window.cdnPrefix='cdn-local.modlix.com';window.cdnStripAPIPrefix='true';window.cdnReplacePlus=true;window.cdnResizeOptionsType='none';window.domainAppCode='demo';window.domainClientCode='SYSTEM';window.__SOCIAL_LOGIN_HOST__='authzump.local.modlix.com';window.__SSO_BEACON_HOST__='authzump.local.modlix.com';</script>"));
        assert!(h.ends_with("<script src=\"https://cdn-local.modlix.com/js/dist/a.js\"></script><i>end</i></body></html>"));
        assert_eq!(p.headers.len(), 1, "an empty report policy is no header");
        assert_eq!(p.headers[0].0, "Content-Security-Policy");
        let header = &p.headers[0].1;
        assert!(header.contains("default-src 'self' cdn-local.modlix.com;") && header.contains("img-src cdn-local.modlix.com;"));
    }

    #[test]
    fn edges_of_the_properties() {
        let bad = app(serde_json::json!({"links": {"a": {"order": "x"}, "b": {}}}));
        assert_eq!(
            index_html(Some(&bad), "demo", "S", false, &cfg(), &[]).unwrap_err(),
            IndexError("For input string: \"x\"".into())
        );
        let none = app(serde_json::json!({"og": {"image": {"url": "/rel.png"}}, "analytics": {"enabled": false}}));
        let p = index_html(Some(&none), "demo", "S", false, &ShellSection::default(), &[]).unwrap();
        assert!(p.html.contains("<title>demo</title>"));
        assert!(p.html.contains("<meta property=\"og:title\" content=\"demo\"/> \n<meta property=\"og:type\" content=\"website\"/> \n<meta property=\"og:site_name\" content=\"demo\"/> \n<meta name=\"twitter:card\" content=\"summary\"/> \n"));
        assert!(!p.html.contains("a.js"));
        let empty_og = app(serde_json::json!({"og": {"type": "x"}, "title": " "}));
        let p = index_html(Some(&empty_og), "demo", "S", false, &cfg(), &[]).unwrap();
        assert!(!p.html.contains("og:type"), "a card with nothing in it is not emitted");
        assert!(p.html.contains("<title> </title>"));
        let http_img = app(serde_json::json!({"og": {"image": {"url": "http://x/i.png"}}}));
        let p = index_html(Some(&http_img), "d", "S", false, &cfg(), &[]).unwrap();
        assert!(p.html.contains("og:image\" content=\"http://x/i.png\"") && !p.html.contains("secure_url"));
        let no_cdn = app(serde_json::json!({"csp": {"scriptSrc": " "}, "cspReport": {"styleSrc": "'self'"}}));
        let p = index_html(Some(&no_cdn), "d", "S", false, &ShellSection::default(), &[]).unwrap();
        assert_eq!(
            p.headers,
            vec![
                ("Content-Security-Policy".to_string(), String::new()),
                ("Content-Security-Policy-Report-Only".to_string(), "style-src 'self';".to_string())
            ]
        );
        assert_eq!(kebab("frameAncestorsX"), "frame-ancestors-x");
        assert_eq!(java_int("+7"), Some(7));
        assert_eq!(java_int("-"), None);
        assert_eq!(first_of(&[None, Some(&JValue::Null), Some(&JValue::from("  ")), Some(&JValue::Int(3))]), "3");
        assert_eq!(absolutise(" ", "https://b"), "");
        assert_eq!(absolutise("//cdn/x", ""), "//cdn/x");
        assert_eq!(absolutise("x", ""), "");
        assert!(!bool_attr(Some(&JValue::Bool(false)), true));
        assert!(bool_attr(Some(&JValue::from("no")), false));
        assert_eq!(packs(Some(&JValue::from("x")), true), "");
        assert_eq!(analytics_snippet(&app(serde_json::json!({}))["properties"].as_object().unwrap().clone(), "h"), "");
        let t = tag_string("meta", &JMap::from_iter([("name".to_string(), JValue::Null)]), &META_FIELDS);
        assert_eq!(t, "<meta name=\"\"/> \n");
        let parts = code_parts(&JMap::from_iter([("codeParts".to_string(), JValue::from("x"))])).unwrap();
        assert!(parts.iter().all(String::is_empty));
    }

    #[test]
    fn reads_the_asset_manifest() {
        let m = br#"{"files":{},"entrypoints":{"index":["a.js","b.js",3]}}"#;
        assert_eq!(entrypoints_of(m), Some(vec!["a.js".into(), "b.js".into(), "3".into()]));
        assert_eq!(entrypoints_of(br#"{"entrypoints":{}}"#), None);
        assert_eq!(entrypoints_of(b"nope"), None);
        assert_eq!(fallback_entrypoints(), vec!["vendors.js".to_string(), "index.js".to_string()]);
    }
}
