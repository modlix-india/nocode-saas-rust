//! Clear error messages: stable codes, texts per language, and layers of customisation.
//!
//! Every message has a code (`SEC.APP_ACCESS_FORBIDDEN`, namespaced per service), an HTTP
//! status, the values it names (`{app}`, `{permission}`...), and per language a `text` (what
//! happened, on what, why) and an optional `action` (what to do next). Codes and English texts
//! are compiled into each crate (`messages/en.toml`); another language is another file
//! (`messages/pt.toml`) registered the same way.
//!
//! Which text a request gets, highest first, for each language of the request in turn
//! ([`locale::chain`]):
//! 1. the client's (or client's app's) own text, from the [`OverrideSource`] (none yet; see
//!    `messages/OVERRIDES.md` for the planned store);
//! 2. the service's override files: `[messages] override_dir`, one `<locale>.toml` each;
//! 3. the built-in texts.
//!
//! A code with no text anywhere reads as [`render::FALLBACK_CODE`], never as an empty message.

pub mod catalogue;
pub mod java;
pub mod labels;
pub mod locale;
pub mod render;
pub mod scope;
pub mod template;

use std::sync::{LazyLock, RwLock, RwLockReadGuard};

use anyhow::{Context, Result};

pub use catalogue::{Catalogue, Meta, ParamKind, ParamSpec, Texts};
pub use java::JavaKey;
pub use render::Rendered;
pub use scope::{layer, layer_with, note_caller, set_override_source, CallerHint, NoOverrides, OverrideKey, OverrideSource, RequestScope};

use crate::config::MessagesConfig;

/// The platform's own codes (`COMMON.*`) and the label tables (`PERMISSION.*`, `ENTITY.*`).
pub const PLATFORM_EN: &str = include_str!("../../messages/en.toml");

static GLOBAL: LazyLock<RwLock<Catalogue>> = LazyLock::new(|| {
    let mut c = Catalogue::default();
    if let Err(e) = c.add_builtin("platform", "en", PLATFORM_EN) {
        tracing::error!(error = format!("{e:#}"), "platform message catalogue");
    }
    RwLock::new(c)
});

/// The process's catalogue.
pub fn global() -> RwLockReadGuard<'static, Catalogue> {
    GLOBAL.read().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn global_mut(f: impl FnOnce(&mut Catalogue) -> Result<usize>) -> Result<usize> {
    let mut c = GLOBAL.write().unwrap_or_else(|poisoned| poisoned.into_inner());
    f(&mut c)
}

/// Adds a crate's compiled-in catalogue for `locale` (once; later calls are no-ops). A file
/// that does not parse is logged and skipped: the crate's tests catch it before it ships.
pub fn register(source: &str, locale: &str, toml: &str) {
    if let Err(e) = global_mut(|c| c.add_builtin(source, locale, toml)) {
        tracing::error!(source, locale, error = format!("{e:#}"), "message catalogue not loaded");
    }
}

/// Applies `[messages]`: the service's override files and its default language.
pub fn configure(cfg: &MessagesConfig) -> Result<usize> {
    global_mut(|c| {
        c.set_default_locale(Some(cfg.default_locale.as_str()).filter(|s| !s.trim().is_empty()));
        if cfg.override_dir.trim().is_empty() {
            return Ok(0);
        }
        let n = c
            .load_override_dir(std::path::Path::new(&cfg.override_dir))
            .with_context(|| format!("[messages] override_dir {}", cfg.override_dir))?;
        tracing::info!(dir = cfg.override_dir, texts = n, "message overrides");
        Ok(n)
    })
}

/// The current request's languages, best first (just the defaults outside a request).
pub fn current_chain() -> Vec<String> {
    let default = global().default_locale().map(str::to_string);
    match scope::current() {
        Some(s) => s.chain(default.as_deref()),
        None => locale::chain(&locale::LocaleSources { default: default.as_deref(), ..Default::default() }),
    }
}

/// `code` with `params`, in the current request's language.
pub fn render(code: &str, params: &[(String, String)], error_id: &str) -> Rendered {
    let chain = current_chain();
    global().render(code, params, &chain, error_id)
}

/// The current request's `Accept-Language`, best first (`pt-BR, pt`), to pass on to another
/// unit whose errors this one relays; `None` outside a request or when it sent none.
pub fn current_accept_language() -> Option<String> {
    scope::current().map(|s| s.accept_language.join(", ")).filter(|l| !l.is_empty())
}

/// The current caller as the scope knows it (default outside a request).
pub fn current_caller() -> CallerHint {
    scope::current().map(|s| s.caller()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every built-in platform text renders to a sentence with no values at all, so no message
    /// can show an empty hole; every placeholder is declared.
    #[test]
    fn platform_catalogue_is_complete() {
        let mut c = Catalogue::default();
        c.add_builtin("platform", "en", PLATFORM_EN).unwrap();
        check_catalogue(&c, "COMMON");
        for code in ["COMMON.ERROR", "COMMON.SIGNED_OUT", "COMMON.SIGN_IN_REQUIRED", "COMMON.PERMISSION_REQUIRED",
            "COMMON.INTERNAL_ERROR", "WORD.OR", "PERMISSION._ROLE", "PERMISSION.Page_UPDATE"] {
            assert!(c.has(code), "{code}");
        }
    }

    /// The checks every crate runs on its own catalogue (see [`check_catalogue`]).
    #[test]
    fn checks_catch_problems() {
        let mut c = Catalogue::default();
        c.add_builtin("t", "en", "[X.A]\nstatus = 400\ntext = \"Missing {field}.\"").unwrap();
        let problems = catalogue_problems(&c, "X");
        assert!(problems.iter().any(|p| p.contains("prints nothing")), "{problems:?}");
        assert!(problems.iter().any(|p| p.contains("not declared")), "{problems:?}");
        let mut c = Catalogue::default();
        c.add_builtin("t", "en", "[X.A]\ntext = \"A\"").unwrap();
        assert!(catalogue_problems(&c, "X").iter().any(|p| p.contains("no status")));
        // An action without a text, a code only another language has, a text that renders empty.
        let mut c = Catalogue::default();
        c.add_builtin("t", "en", "[X.A]\nstatus = 400\naction = \"Do it.\"\n[X.E]\nstatus = 400\ntext = \"[{x}]\"\nparams = [\"x\"]").unwrap();
        c.add_builtin("t", "pt", "[X.P]\ntext = \"So em pt.\"").unwrap();
        let problems = catalogue_problems(&c, "X");
        assert!(problems.iter().any(|p| p == "X.A: no English text"), "{problems:?}");
        assert!(problems.iter().any(|p| p.starts_with("X.E: renders empty")), "{problems:?}");
    }

    #[test]
    fn global_registration_and_configuration() {
        register("platform-test", "en", "[ZTEST.ONE]\nstatus = 418\ntext = \"Teapot.\"");
        register("platform-test-bad", "en", "[ZTEST");
        assert!(global().has("ZTEST.ONE"));
        assert_eq!(render("ZTEST.ONE", &[], "E").message, "Teapot.");
        assert_eq!(current_chain().last().map(String::as_str), Some("en"));
        assert_eq!(current_caller(), CallerHint::default());

        let dir = std::env::temp_dir().join(format!("platform-msg-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("en.toml"), "[ZTEST.ONE]\ntext = \"Short and stout.\"").unwrap();
        let cfg = MessagesConfig { override_dir: dir.display().to_string(), default_locale: String::new() };
        assert_eq!(configure(&cfg).unwrap(), 1);
        assert_eq!(render("ZTEST.ONE", &[], "E").message, "Short and stout.");
        std::fs::write(dir.join("en.toml"), "[ZTEST").unwrap();
        assert!(configure(&cfg).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(configure(&MessagesConfig::default()).unwrap(), 0);
    }
}

/// What is wrong with a namespace's built-in English texts: codes without a status or text,
/// placeholders that are not declared params, and placeholders that would print nothing when
/// their value is unknown (a message must read well without any value).
pub fn catalogue_problems(c: &Catalogue, namespace: &str) -> Vec<String> {
    let prefix = format!("{namespace}.");
    let mut problems = Vec::new();
    for code in c.codes().into_iter().filter(|c| c.starts_with(&prefix)) {
        let meta = c.meta(code).cloned().unwrap_or_default();
        if meta.status.is_none() {
            problems.push(format!("{code}: no status"));
        }
        let Some(texts) = c.builtin_texts("en", code) else {
            problems.push(format!("{code}: no English text"));
            continue;
        };
        let Some(text) = &texts.text else {
            problems.push(format!("{code}: no English text"));
            continue;
        };
        for t in [Some(text), texts.action.as_ref()].into_iter().flatten() {
            for name in t.placeholders() {
                if name != render::ERROR_ID && !meta.params.iter().any(|p| p.name == name) {
                    problems.push(format!("{code}: placeholder {{{name}}} is not declared in params"));
                }
            }
            for name in t.bare_placeholders() {
                if name != render::ERROR_ID {
                    problems.push(format!("{code}: {{{name}}} prints nothing without a value; give it a default or an optional segment"));
                }
            }
            if t.render(&|_| None).is_empty() {
                problems.push(format!("{code}: renders empty without values"));
            }
        }
    }
    problems
}

/// Panics with every problem in a namespace's catalogue (for crate tests).
pub fn check_catalogue(c: &Catalogue, namespace: &str) {
    let problems = catalogue_problems(c, namespace);
    assert!(problems.is_empty(), "catalogue {namespace}:\n{}", problems.join("\n"));
}
