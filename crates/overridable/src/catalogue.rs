//! The definition library's message catalogue (`messages/en.toml`, codes `DEF.*`): every key of
//! the commons-mongo message service ([`crate::write::messages`]) and every other refusal the
//! library makes, in plain words with a next step. Java's text stays the reference for parity and
//! goes to `debugMessage`.

use std::sync::Once;

/// The English texts, compiled in.
pub const EN: &str = include_str!("../messages/en.toml");

/// The namespace of this library's codes.
pub const NS: &str = "DEF";

/// Adds the catalogue to the process (once; every error path calls it, so tests need no setup).
pub fn register() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| platform::messages::register("overridable", "en", EN));
}

#[cfg(test)]
mod tests {
    use super::*;
    use platform::messages::Catalogue;

    fn catalogue() -> Catalogue {
        let mut c = Catalogue::default();
        c.add_builtin("platform", "en", platform::messages::PLATFORM_EN).unwrap();
        c.add_builtin("overridable", "en", EN).unwrap();
        c
    }

    #[test]
    fn catalogue_is_complete() {
        platform::messages::check_catalogue(&catalogue(), NS);
    }

    /// Every key the ui and core bundles share (the commons-mongo message service) has its own
    /// code, named after it.
    #[test]
    fn every_java_key_has_a_code() {
        let c = catalogue();
        let keys = crate::write::messages::Messages::ui().keys();
        assert_eq!(keys.len(), 27, "{keys:?}");
        for k in keys {
            let code = format!("DEF.{}", k.to_ascii_uppercase());
            assert_eq!(c.code_for_java(NS, &k), Some(code.as_str()), "{k}");
        }
        for (key, code) in [("object_not_found", "DEF.DRAFT_NOT_SUPPORTED"), ("transport_error", "DEF.TRANSPORT_UPLOAD_REQUIRED")] {
            assert!(c.meta(code).unwrap().java.iter().any(|j| j == key), "{code}");
        }
    }

    /// Each code reads well with all its values and with none.
    #[test]
    fn texts_render() {
        let c = catalogue();
        let en = vec!["en".to_string()];
        let p = |pairs: &[(&str, &str)]| pairs.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect::<Vec<_>>();
        let r = c.render("DEF.OBJECT_NOT_FOUND", &p(&[("what", "URIPath"), ("id", "7")]), &en, "E");
        assert_eq!(r.message, "We couldn't find the URI path with id 7.");
        let r = c.render("DEF.ALREADY_EXISTS", &p(&[("what", "Application"), ("name", "crm")]), &en, "E");
        assert_eq!(r.message, "The name crm is already used by another app.");
        let r = c.render("DEF.DRAFT_NOT_SUPPORTED", &p(&[("draft", "Draft"), ("what", "Personalization")]), &en, "E");
        assert_eq!(r.message, "Drafts are not available for this kind of item (personalization).");
        let r = c.render("DEF.FORBIDDEN_FORK_NOT_OVERRIDABLE", &p(&[("what", "Page"), ("name", "home")]), &en, "E");
        assert_eq!(r.message, "The page home can't be customised, so only the organisation that owns it can edit it.");
        for code in c.codes().into_iter().filter(|c| c.starts_with("DEF.")) {
            let r = c.render(code, &[], &en, "E");
            assert!(!r.message.contains('{') && !r.message.contains("  ") && !r.message.is_empty(), "{code}: {}", r.message);
            let meta = c.meta(code).unwrap();
            assert!(!meta.java.is_empty() || !meta.java_text.is_empty(), "{code} names no Java text");
            assert!(meta.when.is_some() && meta.audience.is_some(), "{code}");
        }
    }
}
