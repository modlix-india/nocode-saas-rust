//! `SSRCacheEvictionService`: the message the SSR renderers listen for on
//! `ssr:cache:invalidation`, as the Java ui's `ObjectMapper` writes it.

use overridable::json::{to_jackson_pretty, JMap, JValue};

/// The channel the SSR renderers subscribe to.
pub const SSR_CHANNEL: &str = "ssr:cache:invalidation";

/// `publishInvalidation`'s message: `evictAll`, or an app (and client, page), and the time.
/// A `HashMap`, so the keys come out in its order.
pub fn ssr_message(app: Option<&str>, client: Option<&str>, page: Option<&str>, evict_all: bool, now_millis: i64) -> String {
    let mut m = JMap::new();
    if evict_all {
        m.insert("evictAll".into(), JValue::Bool(true));
    } else if let Some(a) = app {
        m.insert("appCode".into(), JValue::Str(a.into()));
    }
    if let Some(c) = client.filter(|c| !c.trim().is_empty()) {
        m.insert("clientCode".into(), JValue::Str(c.into()));
    }
    if let Some(p) = page.filter(|p| !p.trim().is_empty()) {
        m.insert("pageName".into(), JValue::Str(p.into()));
    }
    m.insert("timestamp".into(), JValue::Int(now_millis));
    to_jackson_pretty(&JValue::Object(overridable::java_map::by_puts(m)))
}

/// `evictByAppCode`'s message, or `None` when there is no app (Java skips the publish and
/// answers `false`).
pub fn app_message(app: Option<&str>) -> Option<String> {
    let app = app.filter(|a| !a.trim().is_empty())?;
    Some(ssr_message(Some(app), None, None, false, chrono::Utc::now().timestamp_millis()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_as_java_writes_them() {
        assert_eq!(ssr_message(None, None, None, true, 5), "{\n  \"evictAll\" : true,\n  \"timestamp\" : 5\n}");
        let m = ssr_message(Some("app"), Some("C"), Some("home"), false, 7);
        for part in ["\"appCode\" : \"app\"", "\"clientCode\" : \"C\"", "\"pageName\" : \"home\"", "\"timestamp\" : 7"] {
            assert!(m.contains(part), "{m}");
        }
        assert_eq!(ssr_message(None, Some(" "), None, false, 1), "{\n  \"timestamp\" : 1\n}");
        assert!(app_message(Some("x")).unwrap().contains("\"appCode\" : \"x\""));
        assert_eq!(app_message(Some(" ")), None);
        assert_eq!(app_message(None), None);
    }
}
