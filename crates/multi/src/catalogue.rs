//! multi's message catalogue (`messages/en.toml`, codes `MULTI.*`): every key of the Java bundle
//! and every refusal multi raises itself, in plain words with a next step. The Java text stays
//! the reference for parity and goes to `debugMessage`.

use std::sync::Once;

/// The English texts, compiled in.
pub const EN: &str = include_str!("../messages/en.toml");

/// The namespace of this service's codes.
pub const NS: &str = "MULTI";

/// Adds the catalogue to the process (once; every error path calls it, so tests need no setup).
pub fn register() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| platform::messages::register("multi", "en", EN));
}

#[cfg(test)]
mod tests {
    use super::*;
    use platform::messages::Catalogue;

    /// Java multi's `messages_en.properties`, key for key (2026-10-17).
    const JAVA_BUNDLE: &str = "object_not_found=$ with id $ not found
object_not_found_to_update=$ with id $ not found to update
forbidden_create=Cannot create $ for the selected client
forbidden_permission=Permission/Role $ is required to use this operation
unable_to_delete=Unable to delete $ with id $
object_not_updatable=Cannot update this object
user_credentials_mismatched=User credentials mismatch
unknown_error=Internal Server Error (Unknown)
unknown_error_with_id=Please try again. A server error - $
unkonwn_error_insert=Unknown error occurred while inserting into db
valueof_method_not_found=Could not find the valueOf method
unable_to_convert=Unable to convert $ to $
token_expired=Authorization token expired. Please re-login.
unknown_token=Unknown token
already_exists=$ $ already exists
multi_transport_error=Error while creating/updating application";

    fn catalogue() -> Catalogue {
        let mut c = Catalogue::default();
        c.add_builtin("platform", "en", platform::messages::PLATFORM_EN).unwrap();
        c.add_builtin("multi", "en", EN).unwrap();
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
        let keys: Vec<&str> = JAVA_BUNDLE.lines().filter_map(|l| l.split_once('=').map(|(k, _)| k)).collect();
        assert_eq!(keys.len(), 16);
        for k in keys {
            let code = format!("MULTI.{}", k.to_ascii_uppercase());
            assert_eq!(c.code_for_java(NS, k), Some(code.as_str()), "{k}");
        }
        let raised = ["MULTI.TRANSPORT_EXPORT_FORBIDDEN", "MULTI.APP_CREATE_FORBIDDEN", "MULTI.ENCODED_MODL_INVALID", "MULTI.DEFINITION_UNREADABLE"];
        for code in raised {
            assert!(!c.meta(code).unwrap().java.is_empty(), "{code} names the Java key it stands for");
        }
    }

    /// Each code reads well with all its values and with none.
    #[test]
    fn texts_render() {
        let c = catalogue();
        let en = vec!["en".to_string()];
        let p = |pairs: &[(&str, &str)]| pairs.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect::<Vec<_>>();
        let r = c.render("MULTI.APP_CREATE_FORBIDDEN", &[], &en, "E");
        assert_eq!(r.message, "You can't create apps: your account does not have the Create applications permission.");
        assert_eq!(r.action.as_deref(), Some("Ask an owner of your organisation to give you the Create applications permission."));
        let r = c.render("MULTI.SERVICE_UNAVAILABLE", &p(&[("service", "core")]), &en, "E1");
        assert_eq!(r.message, "The core service is not answering right now. Try again in a few seconds.");
        assert_eq!(r.action.as_deref(), Some("If it keeps happening, give support the error id E1."));
        let r = c.render("MULTI.SERVICE_UNAVAILABLE", &[], &en, "E1");
        assert_eq!(r.message, "A service this needs is not answering right now. Try again in a few seconds.");
        let r = c.render("MULTI.DEFINITION_URL_FAILED", &p(&[("status", "404")]), &en, "E");
        assert_eq!(r.message, "We couldn't download the app definition from its address: the address answered with status 404.");
        let r = c.render("MULTI.HEADER_MISSING", &p(&[("header", "X-Forwarded-Port")]), &en, "E");
        assert_eq!(r.message, "The request is missing the X-Forwarded-Port header.");
        for code in c.codes().into_iter().filter(|c| c.starts_with("MULTI.")) {
            let r = c.render(code, &[], &en, "E");
            assert!(!r.message.contains('{') && !r.message.contains("  ") && !r.message.is_empty(), "{code}: {}", r.message);
            for t in [Some(r.message.as_str()), r.action.as_deref()].into_iter().flatten() {
                assert!(!t.contains('\u{2013}') && !t.contains('\u{2014}'), "{code}: no dashes in {t}");
            }
        }
    }
}
