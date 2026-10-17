//! `UIIndexService`: every application, page, function, schema, theme, style and URI path a
//! client sees in an app, as one map of name / title / id / version / client rows, with each
//! page's component and event versions unless the caller asks for the slim form.

use overridable::write::list::LroPage;
use overridable::write::OverridableService;
use overridable::{java_map, JMap, JValue};
use platform::error::AppResult;
use platform::security::ContextAuthentication;

use crate::editor::kinds::UiKind;

/// The services the index reads, in the order Java zips them.
pub struct IndexServices<'a> {
    pub applications: &'a OverridableService<UiKind>,
    pub pages: &'a OverridableService<UiKind>,
    pub functions: &'a OverridableService<UiKind>,
    pub schemas: &'a OverridableService<UiKind>,
    pub themes: &'a OverridableService<UiKind>,
    pub styles: &'a OverridableService<UiKind>,
    pub uripaths: &'a OverridableService<UiKind>,
}

/// `summarize`: one `HashMap` row per list row.
fn summarize(page: &LroPage) -> Vec<JMap> {
    page.content
        .iter()
        .map(|lro| {
            let mut m = JMap::new();
            for k in ["name", "title", "id", "version", "clientCode"] {
                m.insert(k.into(), lro.get(k).cloned().unwrap_or_default());
            }
            java_map::by_puts(m)
        })
        .collect()
}

fn rows(v: Vec<JMap>) -> JValue {
    JValue::Array(v.into_iter().map(JValue::Object).collect())
}

/// `buildIndex(appCode, clientCode, includeComponentVersions)`.
pub async fn build_index(s: &IndexServices<'_>, ca: &ContextAuthentication, app: &str, client: Option<&str>, include_versions: bool) -> AppResult<JMap> {
    let c = client.filter(|c| !c.trim().is_empty());
    let applications = s.applications.read_index_lro(ca, app, c).await?;
    let pages = s.pages.read_index_lro(ca, app, c).await?;
    let functions = s.functions.read_index_lro(ca, app, c).await?;
    let schemas = s.schemas.read_index_lro(ca, app, c).await?;
    let themes = s.themes.read_index_lro(ca, app, c).await?;
    let styles = s.styles.read_index_lro(ca, app, c).await?;
    let uripaths = s.uripaths.read_index_lro(ca, app, c).await?;

    let mut page_rows = summarize(&pages);
    if include_versions {
        for item in page_rows.iter_mut() {
            let id = item.get("id").map(JValue::java_to_string).unwrap_or_default();
            let pg = s.pages.read(ca, &id).await?;
            let mut added = false;
            for f in ["componentVersions", "eventFunctionVersions"] {
                if let Some(v) = pg.get(f).filter(|v| !v.is_null()) {
                    item.insert(f.into(), v.clone());
                    added = true;
                }
            }
            if added {
                *item = java_map::by_puts(std::mem::take(item));
            }
        }
    }
    // Which client's view this is: the one asked for, or the caller's own.
    let resolved = match client.filter(|c| !c.trim().is_empty()) {
        Some(c) => c.to_string(),
        None => ca.client_code().to_string(),
    };
    let mut result = JMap::new();
    result.insert("appCode".into(), JValue::Str(app.into()));
    result.insert("clientCode".into(), JValue::Str(resolved));
    result.insert("applications".into(), rows(summarize(&applications)));
    result.insert("pages".into(), rows(page_rows));
    result.insert("functions".into(), rows(summarize(&functions)));
    result.insert("schemas".into(), rows(summarize(&schemas)));
    result.insert("themes".into(), rows(summarize(&themes)));
    result.insert("styles".into(), rows(summarize(&styles)));
    result.insert("uripaths".into(), rows(summarize(&uripaths)));
    Ok(java_map::by_puts(result))
}
