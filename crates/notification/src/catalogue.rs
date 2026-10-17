//! notification's message catalogue (`messages/en.toml`, codes `NOTIF.*`): the three keys of the
//! Java bundle ([`crate::messages`]) and the refusals the service raises itself, in plain words
//! with a next step. The Java text stays the reference for parity and goes to `debugMessage`.

use std::sync::Once;

/// The English texts, compiled in.
pub const EN: &str = include_str!("../messages/en.toml");

/// The namespace of this service's codes.
pub const NS: &str = "NOTIF";

/// Adds the catalogue to the process (once; every error path calls it, so tests need no setup).
pub fn register() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| platform::messages::register("notification", "en", EN));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::{template, NOTIFICATION_TYPE_NOT_FOUND, UNKNOWN_ERROR, UNKNOWN_ERROR_WITH_ID};
    use platform::messages::Catalogue;

    fn catalogue() -> Catalogue {
        let mut c = Catalogue::default();
        c.add_builtin("platform", "en", platform::messages::PLATFORM_EN).unwrap();
        c.add_builtin("notification", "en", EN).unwrap();
        c
    }

    #[test]
    fn catalogue_is_complete() {
        platform::messages::check_catalogue(&catalogue(), NS);
    }

    /// Every key of the Java bundle has its own code, named after it.
    #[test]
    fn every_java_key_has_a_code() {
        let c = catalogue();
        for k in [UNKNOWN_ERROR, NOTIFICATION_TYPE_NOT_FOUND, UNKNOWN_ERROR_WITH_ID] {
            assert_ne!(template(k), "", "{k} is in the bundle");
            let code = format!("NOTIF.{}", k.to_ascii_uppercase());
            assert_eq!(c.code_for_java(NS, k), Some(code.as_str()), "{k}");
        }
        let forbidden = c.meta("NOTIF.USER_PREFERENCE_FORBIDDEN").unwrap();
        assert_eq!(forbidden.java_text, vec!["User don't have access to this user Id : $"]);
    }

    /// Each code reads well with all its values and with none.
    #[test]
    fn texts_render() {
        let c = catalogue();
        let en = vec!["en".to_string()];
        let r = c.render("NOTIF.USER_PREFERENCE_FORBIDDEN", &[("id".to_string(), "7".to_string())], &en, "E");
        assert_eq!(r.message, "You can't manage this user's notification preferences: you don't manage their account.");
        assert_eq!(r.action.as_deref(), Some("Change your own preferences instead, or ask an owner of the user's organisation."));
        for code in c.codes().into_iter().filter(|c| c.starts_with("NOTIF.")) {
            let r = c.render(code, &[], &en, "E");
            assert!(!r.message.contains('{') && !r.message.contains("  ") && !r.message.is_empty(), "{code}: {}", r.message);
            for t in [Some(r.message.as_str()), r.action.as_deref()].into_iter().flatten() {
                assert!(!t.contains('\u{2013}') && !t.contains('\u{2014}'), "{code}: no dashes in {t}");
            }
        }
    }
}
