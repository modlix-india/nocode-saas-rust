//! A Java bundle message as a Rust unit raises it: the key and its English template (Java's
//! text, which stays the parity reference and goes to `debugMessage`), and the catalogue code
//! that says it in plain words.

use crate::error::{format_message, Coded};

/// One key of a Java `messages_en.properties`, with its template (`$` for each value).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JavaKey {
    pub key: &'static str,
    pub template: &'static str,
}

impl JavaKey {
    pub const fn new(key: &'static str, template: &'static str) -> Self {
        Self { key, template }
    }

    /// Java's English text with the values, as `throwMessage` formats it.
    pub fn text(&self, values: &[&str]) -> String {
        format_message(self.template, values)
    }

    /// The code standing for the key in namespace `ns` (`<NS>.<KEY>` unless the catalogue names
    /// another), its values named by the code's params (a value Java prints as `null` is left
    /// out), and `[key] text` as the `debugMessage`.
    pub fn coded(&self, ns: &str, values: &[&str]) -> Coded {
        let code = super::global().code_for_java(ns, self.key).map(str::to_string).unwrap_or_else(|| format!("{ns}.{}", self.key.to_ascii_uppercase()));
        self.coded_as(code, values)
    }

    /// The same Java text said by a more specific `code` (one that names a case of the key):
    /// the values are named by that code's params.
    pub fn coded_as(&self, code: impl Into<String>, values: &[&str]) -> Coded {
        let code = code.into();
        let shown: Vec<&str> = values.iter().map(|v| if *v == "null" { "" } else { *v }).collect();
        let params = super::render::name_positional(&super::global(), &code, &shown).into_iter().filter(|(_, v)| !v.trim().is_empty()).collect();
        let mut c = Coded::new(code).debug(format!("[{}] {}", self.key, self.text(values)));
        c.params = params;
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coded_from_a_key() {
        super::super::register("java-key-test", "en", "[JK.THING_GONE]\nstatus = 404\nparams = [\"what\", \"id\"]\ntext = \"Gone[ {what}].\"\njava = \"thing_gone\"\n[JK.OTHER]\ntext = \"Other.\"\njava = \"shared\"");
        let k = JavaKey::new("thing_gone", "$ with id $ is gone");
        assert_eq!(k.text(&["Page", "7"]), "Page with id 7 is gone");
        let c = k.coded("JK", &["Page", "null"]);
        assert_eq!(c.code, "JK.THING_GONE");
        assert_eq!(c.params, vec![("what".to_string(), "Page".to_string())]);
        assert_eq!(c.debug.as_deref(), Some("[thing_gone] Page with id null is gone"));
        assert_eq!(JavaKey::new("shared", "x").coded("JK", &[]).code, "JK.OTHER");
        let c = k.coded_as("JK.OTHER", &["Page"]);
        assert_eq!((c.code.as_ref(), c.params.len()), ("JK.OTHER", 0));
        let c = JavaKey::new("not_in_any_catalogue", "x $").coded("JK", &["1"]);
        assert_eq!((c.code.as_ref(), c.params.len()), ("JK.NOT_IN_ANY_CATALOGUE", 0));
    }
}
