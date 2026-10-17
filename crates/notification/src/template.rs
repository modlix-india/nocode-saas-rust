//! `AbstractTemplateService`: the language a notification renders in and its template parts,
//! through the FreeMarker subset in `connections::template` (the same FreeMarker configuration
//! as core's: 2.3.32, `RETHROW_HANDLER`).
//!
//! Every failure here aborts the whole notification in Java (the exception leaves the send
//! service and is logged by the listener), so they are errors, not empty results.

use std::collections::HashMap;

use anyhow::{anyhow, Result};
use connections::java::is_blank;
use serde_json::{Map, Value};

use crate::messages::{self, MAIL_SEND_ERROR};
use crate::model::{CoreNotification, NotificationTemplate};

/// `processFreeMarker(name, template, data)`: a failure is `GenericException(500, message)`.
pub fn process(name: &str, source: Option<&str>, data: &Map<String, Value>) -> Result<String> {
    connections::template::process(name, source, data).map_err(|e| anyhow!(e.message().to_string()))
}

/// `StringUtil.safeIsBlank`.
fn safe_is_blank(s: Option<&str>) -> bool {
    s.is_none_or(is_blank)
}

/// `getLanguage`: the default language (or `""`) when there is no expression; otherwise the
/// rendered expression, or the default language (possibly null) when it renders blank.
pub fn language(n: &CoreNotification, data: &Map<String, Value>) -> Result<Option<String>> {
    if safe_is_blank(n.language_expression.as_deref()) {
        return Ok(Some(if safe_is_blank(n.default_language.as_deref()) {
            String::new()
        } else {
            n.default_language.clone().unwrap_or_default()
        }));
    }
    let lang = process("language", n.language_expression.as_deref(), data)?;
    Ok(if is_blank(&lang) { n.default_language.clone() } else { Some(lang) })
}

/// `getProcessedTemplate`: every part of the language's set rendered; the set is `en` when the
/// language is blank, and the first set (in the order core sent them) when the language has none.
pub fn processed_template(
    language: Option<&str>,
    template: Option<&NotificationTemplate>,
    data: &Map<String, Value>,
) -> Result<HashMap<String, String>> {
    let template = template.ok_or_else(|| anyhow!("Cannot invoke \"getTemplateParts()\" because \"template\" is null"))?;
    let parts = match template.template_parts.as_ref() {
        Some(p) if !p.is_empty() => p,
        // msgService.throwMessage(MAIL_SEND_ERROR, "No template parts found"); the bundle has
        // no such entry, so the message is unknown_error's.
        _ => return Err(anyhow!(messages::message(MAIL_SEND_ERROR, &["No template parts found"]))),
    };
    let language = language.ok_or_else(|| anyhow!("Cannot invoke \"String.isBlank()\" because \"language\" is null"))?;
    let key = if is_blank(language) { "en" } else { language };
    let set = parts
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v)
        .filter(|v| v.is_some())
        .unwrap_or(&parts[0].1);
    let set = set.as_ref().ok_or_else(|| anyhow!("Cannot invoke \"java.util.Map.entrySet()\" because \"temp\" is null"))?;
    let mut out = HashMap::new();
    for (name, source) in set {
        out.insert(name.clone(), process("templatePart", source.as_deref(), data)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn notification(v: Value) -> CoreNotification {
        CoreNotification::from_json(&v).unwrap()
    }

    fn data() -> Map<String, Value> {
        json!({"who": "Ann", "n": 3, "lang": "fr", "blank": " "}).as_object().unwrap().clone()
    }

    #[test]
    fn language_rules() {
        assert_eq!(language(&notification(json!({})), &data()).unwrap().as_deref(), Some(""));
        assert_eq!(language(&notification(json!({"defaultLanguage": "de"})), &data()).unwrap().as_deref(), Some("de"));
        assert_eq!(language(&notification(json!({"defaultLanguage": " "})), &data()).unwrap().as_deref(), Some(""));
        let expr = notification(json!({"languageExpression": "${lang}", "defaultLanguage": "de"}));
        assert_eq!(language(&expr, &data()).unwrap().as_deref(), Some("fr"));
        let blank = notification(json!({"languageExpression": "${blank}", "defaultLanguage": "de"}));
        assert_eq!(language(&blank, &data()).unwrap().as_deref(), Some("de"));
        let blank_no_default = notification(json!({"languageExpression": "${blank}"}));
        assert_eq!(language(&blank_no_default, &data()).unwrap(), None);
        let missing = notification(json!({"languageExpression": "${nope}"}));
        assert!(language(&missing, &data()).is_err());
    }

    #[test]
    fn template_parts_rules() {
        let n = notification(json!({"channelTemplates": {"inapp": {"templateParts": {
            "fr": {"title": "Bonjour ${who}"},
            "en": {"title": "Hello ${who}", "description": "${n} new"}
        }}}}));
        let t = n.channel("inapp");
        let en = processed_template(Some(""), t, &data()).unwrap();
        assert_eq!(en["title"], "Hello Ann");
        assert_eq!(en["description"], "3 new");
        assert_eq!(processed_template(Some("fr"), t, &data()).unwrap()["title"], "Bonjour Ann");
        // A language without a set takes the first set core sent.
        assert_eq!(processed_template(Some("de"), t, &data()).unwrap()["title"], "Bonjour Ann");
        assert!(processed_template(None, t, &data()).unwrap_err().to_string().contains("language"));
        assert!(processed_template(Some("en"), None, &data()).is_err());

        let none = notification(json!({"channelTemplates": {"inapp": {"templateParts": {}}}}));
        let e = processed_template(Some("en"), none.channel("inapp"), &data()).unwrap_err();
        assert_eq!(e.to_string(), "Internal Server Error (Unknown)");
        let absent = notification(json!({"channelTemplates": {"inapp": {}}}));
        assert!(processed_template(Some("en"), absent.channel("inapp"), &data()).is_err());

        let null_set = notification(json!({"channelTemplates": {"inapp": {"templateParts": {"en": null}}}}));
        assert!(processed_template(Some("en"), null_set.channel("inapp"), &data()).unwrap_err().to_string().contains("temp"));
        let null_first = notification(json!({"channelTemplates": {"inapp": {"templateParts": {"fr": null, "en": {"t": "x"}}}}}));
        assert_eq!(processed_template(Some("en"), null_first.channel("inapp"), &data()).unwrap()["t"], "x");
        assert!(processed_template(Some("de"), null_first.channel("inapp"), &data()).is_err());

        let null_part = notification(json!({"channelTemplates": {"inapp": {"templateParts": {"en": {"t": null}}}}}));
        assert!(processed_template(Some("en"), null_part.channel("inapp"), &data()).is_err());
        let broken = notification(json!({"channelTemplates": {"inapp": {"templateParts": {"en": {"t": "${missing}"}}}}}));
        assert!(processed_template(Some("en"), broken.channel("inapp"), &data()).is_err());
        assert!(process("x", Some("<#if>"), &data()).is_err());
    }
}
