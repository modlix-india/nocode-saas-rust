//! `TemplatePreviewService`: an unsaved template rendered for the editor, leniently (an
//! undefined `${var}` renders as nothing rather than failing the preview), as its parts or as
//! the PDF of its `body` part.

use overridable::{java_map, JMap, JValue};
use serde_json::{Map, Value};

/// The part map of the language the preview is for: the one asked for, else the template's
/// default, else `en`; the first part map when the template has none for it.
fn parts_for<'a>(template: &'a Value, language: Option<&str>) -> Option<&'a Map<String, Value>> {
    let parts = template.get("templateParts")?.as_object().filter(|p| !p.is_empty())?;
    let lang = match language.filter(|l| !l.trim().is_empty()) {
        Some(l) => l.to_string(),
        None => match template.get("defaultLanguage").and_then(Value::as_str).filter(|d| !d.trim().is_empty()) {
            Some(d) => d.to_string(),
            None => "en".into(),
        },
    };
    parts.get(&lang).or_else(|| parts.values().next()).and_then(Value::as_object)
}

/// The data a preview renders against: the request's when it has any, else the template's
/// `sampleData`.
fn data_for(template: &Value, data: Option<&Value>) -> Map<String, Value> {
    if let Some(d) = data.and_then(Value::as_object).filter(|d| !d.is_empty()) {
        return d.clone();
    }
    template.get("sampleData").and_then(Value::as_object).cloned().unwrap_or_default()
}

/// `renderParts(template, language, data)`: each part rendered, in a `HashMap`. A syntax
/// error fails the preview.
pub fn render_parts(template: Option<&Value>, language: Option<&str>, data: Option<&Value>) -> Result<JMap, String> {
    let Some(template) = template.filter(|t| t.is_object()) else { return Ok(JMap::new()) };
    let Some(parts) = parts_for(template, language) else { return Ok(JMap::new()) };
    let model = data_for(template, data);
    let mut out = JMap::new();
    for (k, v) in parts {
        let source = match v {
            Value::String(s) => s.clone(),
            Value::Null => String::new(),
            other => other.to_string(),
        };
        let text = connections::template::process_lenient("templatePart", Some(&source), &model).map_err(|e| e.message().to_string())?;
        out.insert(k.clone(), JValue::Str(text));
    }
    Ok(java_map::by_puts(out))
}

/// `renderPdf(template, data)`: the `body` part (default language) as a PDF.
pub fn render_pdf(template: Option<&Value>, data: Option<&Value>) -> Result<Vec<u8>, String> {
    let parts = render_parts(template, Some(""), data)?;
    let body = parts.get("body").and_then(JValue::as_str).unwrap_or("").to_string();
    Ok(crate::pdf::html_to_pdf(&body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parts_render_leniently_in_the_chosen_language() {
        let t = json!({"templateParts": {"en": {"subject": "Hi ${name}", "body": "<p>${missing}x</p>"}, "fr": {"subject": "Salut ${name}"}},
            "defaultLanguage": "fr", "sampleData": {"name": "Ann"}});
        let p = render_parts(Some(&t), None, None).unwrap();
        assert_eq!(p.get("subject"), Some(&JValue::Str("Salut Ann".into())));
        let p = render_parts(Some(&t), Some("en"), Some(&json!({"name": "Bo"}))).unwrap();
        assert_eq!(p.get("subject"), Some(&JValue::Str("Hi Bo".into())));
        assert_eq!(p.get("body"), Some(&JValue::Str("<p>x</p>".into())));
        let p = render_parts(Some(&t), Some("de"), Some(&json!({}))).unwrap();
        assert_eq!(p.get("subject"), Some(&JValue::Str("Hi Ann".into())), "the first part map, sample data");
        assert!(render_parts(None, None, None).unwrap().is_empty());
        assert!(render_parts(Some(&json!({"templateParts": {}})), None, None).unwrap().is_empty());
        let t = json!({"templateParts": {"en": {"a": null, "b": 3}}});
        let p = render_parts(Some(&t), None, None).unwrap();
        assert_eq!((p.get("a"), p.get("b")), (Some(&JValue::Str(String::new())), Some(&JValue::Str("3".into()))));
        assert!(render_parts(Some(&json!({"templateParts": {"en": {"a": "${"}}})), None, None).is_err());
        let pdf = render_pdf(Some(&json!({"templateParts": {"en": {"body": "<p>Hello</p>"}}})), None).unwrap();
        assert!(pdf.starts_with(b"%PDF"));
    }
}
