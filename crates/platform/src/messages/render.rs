//! Turning a code and its values into the text a person reads, in the best language the
//! catalogue has for the request.

use super::catalogue::{Catalogue, ParamKind, Texts};
use super::template::Template;

/// The code used when the one asked for is not in the catalogue: a generic text, never an
/// empty one.
pub const FALLBACK_CODE: &str = "COMMON.ERROR";
/// The last resort, if even [`FALLBACK_CODE`] has no text.
pub const LAST_RESORT: &str = "Your request could not be completed.";
/// A placeholder every template may use: the error id of this response.
pub const ERROR_ID: &str = "errorId";

/// A message ready to send.
#[derive(Debug, Clone, PartialEq)]
pub struct Rendered {
    pub code: String,
    pub message: String,
    pub action: Option<String>,
    /// The values as they appear in the message (labels, not authority names).
    pub params: Vec<(String, String)>,
    /// The language of `message`.
    pub locale: String,
}

impl Catalogue {
    /// The text and action for `code` in the first language of `chain` that has a text.
    /// `top` (from a client or app override) sits above every other layer for its locale.
    pub fn render(&self, code: &str, params: &[(String, String)], chain: &[String], error_id: &str) -> Rendered {
        self.render_with(code, params, chain, error_id, None)
    }

    pub fn render_with(
        &self,
        code: &str,
        params: &[(String, String)],
        chain: &[String],
        error_id: &str,
        top: Option<(&str, &Texts)>,
    ) -> Rendered {
        let known = self.has(code) || top.is_some();
        let lookup_code = if known { code } else { FALLBACK_CODE };
        let shown = self.shown_params(lookup_code, params, chain);
        let value = |k: &str| -> Option<String> {
            if k == ERROR_ID {
                return Some(error_id.to_string());
            }
            shown.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone())
        };

        let mut chosen: Option<(String, Option<&Template>, Option<&Template>)> = None;
        for locale in chain {
            let top_here = top.filter(|(l, _)| *l == locale.as_str()).map(|(_, t)| t);
            let mut layers: Vec<&Texts> = top_here.into_iter().collect();
            layers.extend(self.layers(locale, lookup_code).into_iter().flatten());
            let text = layers.iter().find_map(|t| t.text.as_ref());
            if let Some(text) = text {
                let action = layers.iter().find_map(|t| t.action.as_ref());
                chosen = Some((locale.clone(), Some(text), action));
                break;
            }
        }
        let (locale, text, action) = match chosen {
            Some(c) => c,
            None => ("en".to_string(), None, None),
        };
        let message = text.map(|t| t.render(&value)).filter(|m| !m.is_empty()).unwrap_or_else(|| LAST_RESORT.to_string());
        let action = action.map(|t| t.render(&value)).filter(|a| !a.is_empty());
        Rendered { code: code.to_string(), message, action, params: shown, locale }
    }

    /// The values with their kinds applied, in the order the code declares them, then any
    /// others given. Blank values are left out.
    fn shown_params(&self, code: &str, params: &[(String, String)], chain: &[String]) -> Vec<(String, String)> {
        let specs = self.meta(code).map(|m| m.params.clone()).unwrap_or_default();
        let kind = |name: &str| specs.iter().find(|s| s.name == name).map(|s| s.kind).unwrap_or(ParamKind::Plain);
        let mut ordered: Vec<&(String, String)> = Vec::new();
        for s in &specs {
            ordered.extend(params.iter().filter(|(n, _)| *n == s.name));
        }
        ordered.extend(params.iter().filter(|(n, _)| !specs.iter().any(|s| s.name == *n)));
        ordered
            .into_iter()
            .filter(|(_, v)| !v.trim().is_empty())
            .map(|(n, v)| {
                let shown = match kind(n) {
                    ParamKind::Plain => v.clone(),
                    ParamKind::Authority => self.authority_labels(v, chain),
                    ParamKind::Entity => self.entity_label(v, chain),
                };
                (n.clone(), shown)
            })
            .collect()
    }

    /// The plain text of a label code (`PERMISSION.Page_UPDATE`), with `name` filled in.
    pub(crate) fn label(&self, code: &str, name: &str, chain: &[String]) -> Option<String> {
        chain.iter().find_map(|locale| {
            let t = self.layers(locale, code).into_iter().flatten().find_map(|t| t.text.as_ref())?;
            let s = t.render(&|k| (k == "name").then(|| name.to_string()));
            (!s.is_empty()).then_some(s)
        })
    }
}

/// Positional values (Java's `$`s) named by the code's params, in order. Values beyond the
/// declared names are dropped; missing ones are simply absent.
pub fn name_positional(cat: &Catalogue, code: &str, values: &[&str]) -> Vec<(String, String)> {
    let Some(meta) = cat.meta(code) else { return Vec::new() };
    meta.params.iter().zip(values).map(|(s, v)| (s.name.clone(), v.to_string())).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cat() -> Catalogue {
        let mut c = Catalogue::default();
        c.add_builtin(
            "t",
            "en",
            r#"
            [COMMON.ERROR]
            text = "Generic."
            [T.ONE]
            params = ["what:entity", "id"]
            text = "No {what|thing}[ {id}]."
            action = "Ref {errorId}."
            [T.PERM]
            params = ["permission:authority"]
            text = "You need {permission|a permission}."
            [T.EMPTY]
            text = "[{x}]"
            [PERMISSION.Page_UPDATE]
            text = "Edit pages"
            "#,
        )
        .unwrap();
        c.add_builtin("t", "pt", "[T.ONE]\ntext = \"Nenhum {what}.\"").unwrap();
        c
    }

    fn en() -> Vec<String> {
        vec!["en".into()]
    }

    fn p(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()
    }

    #[test]
    fn renders_in_the_first_language_with_a_text() {
        let c = cat();
        let r = c.render("T.ONE", &p(&[("id", "7"), ("what", "ClientUrl")]), &en(), "E1");
        assert_eq!(r.message, "No client URL 7.");
        assert_eq!(r.action.as_deref(), Some("Ref E1."));
        assert_eq!(r.params, p(&[("what", "client URL"), ("id", "7")]), "declared order, labels applied");
        assert_eq!(r.locale, "en");

        let chain = vec!["pt-BR".to_string(), "pt".to_string(), "en".to_string()];
        let r = c.render("T.ONE", &p(&[("what", "App")]), &chain, "E1");
        assert_eq!(r.message, "Nenhum app.");
        assert_eq!(r.locale, "pt");
        assert_eq!(r.action.as_deref(), None, "the action comes with the text's language");
    }

    #[test]
    fn unknown_codes_and_empty_texts_fall_back() {
        let c = cat();
        let r = c.render("T.NOPE", &p(&[("extra", "x")]), &en(), "E1");
        assert_eq!((r.code.as_str(), r.message.as_str()), ("T.NOPE", "Generic."));
        assert_eq!(r.params, p(&[("extra", "x")]));
        assert_eq!(c.render("T.EMPTY", &[], &en(), "E").message, LAST_RESORT);
        assert_eq!(Catalogue::default().render("X", &[], &en(), "E").message, LAST_RESORT);
        assert_eq!(c.render("T.ONE", &[], &["fr".to_string()], "E").locale, "en", "no language at all reads as en");
    }

    #[test]
    fn a_top_layer_wins_for_its_language() {
        let c = cat();
        let top = Texts::from_strings(Some("Custom[ {what}]."), None).unwrap();
        let r = c.render_with("T.ONE", &p(&[("what", "App")]), &en(), "E", Some(("en", &top)));
        assert_eq!(r.message, "Custom app.");
        assert_eq!(r.action.as_deref(), Some("Ref E."), "the built-in action stays");
        let r = c.render_with("T.ONE", &[], &en(), "E", Some(("fr", &top)));
        assert_eq!(r.message, "No thing.");
        let r = c.render_with("T.CUSTOM_ONLY", &[], &en(), "E", Some(("en", &top)));
        assert_eq!(r.message, "Custom.");
    }

    #[test]
    fn blank_values_are_left_out() {
        let c = cat();
        let r = c.render("T.ONE", &p(&[("what", " "), ("id", "")]), &en(), "E");
        assert_eq!(r.message, "No thing.");
        assert!(r.params.is_empty());
    }

    #[test]
    fn positional_values_are_named() {
        let c = cat();
        assert_eq!(name_positional(&c, "T.ONE", &["App", "7", "extra"]), p(&[("what", "App"), ("id", "7")]));
        assert_eq!(name_positional(&c, "T.ONE", &["App"]), p(&[("what", "App")]));
        assert!(name_positional(&c, "T.NOPE", &["x"]).is_empty());
    }

    #[test]
    fn labels() {
        let c = cat();
        assert_eq!(c.label("PERMISSION.Page_UPDATE", "", &en()).as_deref(), Some("Edit pages"));
        assert_eq!(c.label("PERMISSION.Nope", "", &en()), None);
        let r = c.render("T.PERM", &p(&[("permission", "Authorities.Page_UPDATE")]), &en(), "E");
        assert_eq!(r.message, "You need Edit pages.");
    }
}
