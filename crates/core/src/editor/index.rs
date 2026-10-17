//! `CoreIndexService`: every core object an application owns, as name / title / id / version /
//! client rows per type, the override chain resolved to one row per name.

use overridable::write::list::LroPage;
use overridable::write::OverridableService;
use overridable::{java_map, JMap, JValue};
use platform::error::AppResult;
use platform::security::ContextAuthentication;

use crate::editor::kinds::CoreKind;

/// One row per object of the page, as a `HashMap`.
fn summarize(page: &LroPage) -> JValue {
    JValue::Array(
        page.content
            .iter()
            .map(|lro| {
                let mut m = JMap::new();
                for k in ["name", "title", "id", "version", "clientCode"] {
                    m.insert(k.into(), lro.get(k).cloned().unwrap_or_default());
                }
                JValue::Object(java_map::by_puts(m))
            })
            .collect(),
    )
}

/// `buildIndex(appCode, clientCode)`: the types in their declared order, after the app and the
/// client the index is of (the one asked for, or the caller's own).
pub async fn build_index(sources: &[(&str, &OverridableService<CoreKind>)], ca: &ContextAuthentication, app: &str, client: Option<&str>) -> AppResult<JMap> {
    let c = client.filter(|c| !c.trim().is_empty());
    let mut result = JMap::new();
    result.insert("appCode".into(), JValue::Str(app.into()));
    result.insert("clientCode".into(), JValue::Str(c.map(str::to_string).unwrap_or_else(|| ca.client_code().to_string())));
    for (key, svc) in sources {
        let page = svc.read_index_lro(ca, app, c).await?;
        result.insert(key.to_string(), summarize(&page));
    }
    Ok(result)
}
