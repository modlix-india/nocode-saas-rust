//! The security service's message catalogue (`messages/en.toml`, codes `SEC.*`): every key of
//! the Java bundle ([`crate::messages`]) and every other refusal, in plain words with a next
//! step. The Java text stays the reference for parity and goes to `debugMessage`.

use std::sync::Once;

/// The English texts, compiled in.
pub const EN: &str = include_str!("../messages/en.toml");

/// The namespace of this service's codes.
pub const NS: &str = "SEC";

/// Adds the catalogue to the process (once; every error path calls it, so tests need no setup).
pub fn register() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| platform::messages::register("security", "en", EN));
}

/// The code standing for a Java bundle key (`object_not_found` reads `SEC.OBJECT_NOT_FOUND`), or
/// `SEC.UNKNOWN_ERROR` for a key nothing claims.
pub fn code_for_key(key: &str) -> String {
    register();
    platform::messages::global().code_for_java(NS, key).unwrap_or("SEC.UNKNOWN_ERROR").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use platform::messages::Catalogue;

    fn catalogue() -> Catalogue {
        let mut c = Catalogue::default();
        c.add_builtin("platform", "en", platform::messages::PLATFORM_EN).unwrap();
        c.add_builtin("security", "en", EN).unwrap();
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
        let bundle = include_str!("messages.rs");
        let keys: Vec<&str> = bundle
            .lines()
            .filter_map(|l| l.trim().strip_prefix('"').and_then(|r| r.split_once("\" => r#\"")).map(|(k, _)| k))
            .collect();
        assert_eq!(keys.len(), 124);
        for k in keys {
            let code = format!("SEC.{}", k.to_ascii_uppercase());
            assert_eq!(c.code_for_java(NS, k), Some(code.as_str()), "{k}");
        }
        for extra in ["social_login_failed", "session_expired", "unsupported_platform", "request_existing", "Designation", "User", "$ cannot be updated"] {
            assert!(c.code_for_java(NS, extra).is_some(), "{extra}");
        }
        assert_eq!(code_for_key("no_such_key"), "SEC.UNKNOWN_ERROR");
        assert_eq!(code_for_key("object_not_found"), "SEC.OBJECT_NOT_FOUND");
    }

    /// Each code reads well with all its values and with none.
    #[test]
    fn texts_render() {
        let c = catalogue();
        let en = vec!["en".to_string()];
        let p = |pairs: &[(&str, &str)]| pairs.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect::<Vec<_>>();
        let r = c.render("SEC.OBJECT_NOT_FOUND", &p(&[("what", "ClientUrl"), ("id", "7")]), &en, "E");
        assert_eq!(r.message, "We couldn't find the client address with id 7.");
        let r = c.render("SEC.USER_PASSWORD_INVALID_ATTEMPTS", &p(&[("what", "Password"), ("left", "2")]), &en, "E");
        assert_eq!(r.message, "The password is not correct. Attempts left before your account is locked: 2.");
        let r = c.render("SEC.USER_ACCOUNT_BLOCKED_LIMIT", &p(&[("minutes", "15")]), &en, "E");
        assert_eq!(r.message, "Your account is locked after too many wrong attempts.");
        assert_eq!(r.action.as_deref(), Some("Try again in 15 minutes, or reset your password."));
        let r = c.render("SEC.FORBIDDEN_PERMISSION", &p(&[("permission", "User READ")]), &en, "E");
        assert_eq!(r.message, "You can't do this: your account does not have the View users permission.");
        let r = c.render("SEC.NAME_TAKEN", &p(&[("what", "Designation"), ("name", "Sales")]), &en, "E");
        assert_eq!(r.message, "A designation named Sales already exists.");
        for code in c.codes().into_iter().filter(|c| c.starts_with("SEC.")) {
            let r = c.render(code, &[], &en, "E");
            assert!(!r.message.contains('{') && !r.message.contains("  ") && !r.message.is_empty(), "{code}: {}", r.message);
        }
    }
}
