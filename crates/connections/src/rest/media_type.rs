//! Spring's `MediaType`: what `HttpHeaders.getContentType()` parses, `isCompatibleWith`, and
//! the `toString()` a codec writes back into the `Content-Type` header.

use crate::error::ConnError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaType {
    /// Lower case, as `MimeType` stores it.
    pub type_: String,
    pub subtype: String,
    /// In the order given, names and values as given.
    pub params: Vec<(String, String)>,
}

const TOKEN_SEPARATORS: &str = "()<>@,;:\\\"/[]?={} \t";

fn check_token(token: &str, whole: &str) -> Result<(), ConnError> {
    for c in token.chars() {
        let code = c as u32;
        if code <= 31 || code >= 127 || TOKEN_SEPARATORS.contains(c) {
            return Err(invalid(whole, &format!("Invalid token character '{c}' in token \"{token}\"")));
        }
    }
    Ok(())
}

fn invalid(whole: &str, why: &str) -> ConnError {
    ConnError::other(format!("Invalid mime type \"{whole}\": {why}"))
}

/// Splits on `;` outside double quotes.
fn split_params(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for c in s.chars() {
        if escaped {
            cur.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' if quoted => {
                escaped = true;
                cur.push(c);
            }
            '"' => {
                quoted = !quoted;
                cur.push(c);
            }
            ';' if !quoted => {
                out.push(std::mem::take(&mut cur));
            }
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out
}

impl MediaType {
    pub fn new(type_: &str, subtype: &str) -> Self {
        Self { type_: type_.to_string(), subtype: subtype.to_string(), params: Vec::new() }
    }

    /// `MediaType.parseMediaType`.
    pub fn parse(value: &str) -> Result<Self, ConnError> {
        if value.is_empty() {
            return Err(invalid(value, "'mimeType' must not be empty"));
        }
        let parts = split_params(value);
        let mut full = parts[0].trim().to_string();
        if full == "*" {
            full = "*/*".into();
        }
        let Some(slash) = full.find('/') else {
            return Err(invalid(value, "does not contain '/'"));
        };
        if slash == full.len() - 1 {
            return Err(invalid(value, "does not contain subtype after '/'"));
        }
        let type_ = full[..slash].trim().to_lowercase();
        let subtype = full[slash + 1..].trim().to_lowercase();
        if type_ == "*" && subtype != "*" {
            return Err(invalid(value, "wildcard type is legal only in '*/*' (all mime types)"));
        }
        check_token(&type_, value)?;
        check_token(&subtype, value)?;
        let mut params = Vec::new();
        for p in parts.iter().skip(1) {
            let p = p.trim();
            if let Some(eq) = p.find('=') {
                let k = p[..eq].trim().to_string();
                let v = p[eq + 1..].trim().to_string();
                if !params.iter().any(|(e, _): &(String, String)| e.eq_ignore_ascii_case(&k)) {
                    params.push((k, v));
                }
            }
        }
        Ok(Self { type_, subtype, params })
    }

    pub fn is_wildcard_type(&self) -> bool {
        self.type_ == "*"
    }

    pub fn is_wildcard_subtype(&self) -> bool {
        self.subtype == "*" || self.subtype.starts_with("*+")
    }

    fn suffix(&self) -> Option<&str> {
        self.subtype.rfind('+').filter(|i| *i + 1 < self.subtype.len()).map(|i| &self.subtype[i + 1..])
    }

    /// `MimeType.isCompatibleWith`.
    pub fn is_compatible_with(&self, other: &MediaType) -> bool {
        if self.is_wildcard_type() || other.is_wildcard_type() {
            return true;
        }
        if self.type_ == other.type_ {
            if self.subtype == other.subtype {
                return true;
            }
            if self.is_wildcard_subtype() || other.is_wildcard_subtype() {
                let this_suffix = self.suffix();
                let other_suffix = other.suffix();
                if self.subtype == "*" || other.subtype == "*" {
                    return true;
                } else if self.is_wildcard_subtype() && this_suffix.is_some() {
                    return this_suffix == Some(other.subtype.as_str()) || this_suffix == other_suffix;
                } else if other.is_wildcard_subtype() && other_suffix.is_some() {
                    return Some(self.subtype.as_str()) == other_suffix || other_suffix == this_suffix;
                }
            }
        }
        false
    }

    pub fn param(&self, name: &str) -> Option<&str> {
        self.params.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// The charset parameter, unquoted.
    pub fn charset(&self) -> Option<String> {
        self.param("charset").map(|c| c.trim_matches('"').to_string())
    }

    /// `MimeType.toString()`: `type/subtype;name=value...`.
    pub fn to_header(&self) -> String {
        let mut s = format!("{}/{}", self.type_, self.subtype);
        for (k, v) in &self.params {
            s.push(';');
            s.push_str(k);
            s.push('=');
            s.push_str(v);
        }
        s
    }
}

pub fn application_json() -> MediaType {
    MediaType::new("application", "json")
}

pub fn multipart_form_data() -> MediaType {
    MediaType::new("multipart", "form-data")
}

pub fn application_form_urlencoded() -> MediaType {
    MediaType::new("application", "x-www-form-urlencoded")
}

/// What `Jackson2JsonEncoder` writes: `application/json`, `application/*+json`,
/// `application/x-ndjson`.
pub fn jackson_can_encode(content_type: Option<&MediaType>) -> bool {
    let Some(ct) = content_type else { return true };
    [application_json(), MediaType::new("application", "*+json"), MediaType::new("application", "x-ndjson")]
        .iter()
        .any(|m| m.is_compatible_with(ct))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_compares() {
        let j = MediaType::parse("Application/JSON; charset=UTF-8").unwrap();
        assert_eq!(j.to_header(), "application/json;charset=UTF-8");
        assert!(j.is_compatible_with(&application_json()));
        let api = MediaType::parse("application/vnd.api+json").unwrap();
        assert!(!api.is_compatible_with(&application_json()));
        assert!(jackson_can_encode(Some(&api)));
        assert!(!jackson_can_encode(Some(&MediaType::parse("text/plain").unwrap())));
        assert!(MediaType::parse("multipart/form-data; boundary=x").unwrap().is_compatible_with(&multipart_form_data()));
        assert_eq!(MediaType::parse("json").unwrap_err().message(), "Invalid mime type \"json\": does not contain '/'");
    }

    #[test]
    fn parse_edges() {
        assert!(MediaType::parse("").is_err());
        assert_eq!(MediaType::parse("*").unwrap().to_header(), "*/*");
        assert!(MediaType::parse("text/").is_err());
        assert!(MediaType::parse("*/json").is_err());
        assert!(MediaType::parse("te xt/plain").is_err());
        let q = MediaType::parse(r#"text/plain; name="a;b\"c"; charset="utf-8"; flag; charset=x"#).unwrap();
        assert_eq!(q.param("name"), Some(r#""a;b\"c""#));
        assert_eq!(q.charset().as_deref(), Some("utf-8"));
        assert_eq!(q.params.len(), 2);
    }

    #[test]
    fn compatibility() {
        let p = |s: &str| MediaType::parse(s).unwrap();
        assert!(p("*/*").is_compatible_with(&p("text/plain")));
        assert!(p("text/plain").is_compatible_with(&p("*/*")));
        assert!(p("application/*").is_compatible_with(&p("application/xml")));
        assert!(p("application/*+json").is_compatible_with(&p("application/vnd.api+json")));
        assert!(p("application/*+json").is_compatible_with(&p("application/json")));
        assert!(!p("application/*+xml").is_compatible_with(&p("application/json")));
        assert!(p("application/json").is_compatible_with(&p("application/*+json")));
        assert!(p("application/vnd.a+json").is_compatible_with(&p("application/*+json")));
        assert!(!p("text/plain").is_compatible_with(&p("application/plain")));
        assert!(!p("application/x").is_compatible_with(&p("application/y")));
        assert!(jackson_can_encode(None));
        assert_eq!(multipart_form_data().to_header(), "multipart/form-data");
    }
}
