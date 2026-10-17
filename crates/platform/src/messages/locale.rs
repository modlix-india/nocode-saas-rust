//! Which languages a request is answered in, best first.
//!
//! The order: the request's `Accept-Language` (by its q-values), then the signed-in user's
//! locale, then their client's, then the service default, then English. Each locale brings its
//! less specific forms right after it (`pt-BR`, then `pt`), so a catalogue only needs the
//! languages it really has. Java's `en_US` style is read as `en-US`.

/// `en_us`, `EN-us` and `en-US` all read as `en-US`; `zh-hant-tw` as `zh-Hant-TW`.
pub fn normalize(tag: &str) -> Option<String> {
    let tag = tag.trim().replace('_', "-");
    let mut parts = tag.split('-').filter(|p| !p.is_empty());
    let lang = parts.next()?;
    if !lang.chars().all(|c| c.is_ascii_alphabetic()) || lang.len() > 8 {
        return None;
    }
    let mut out = lang.to_ascii_lowercase();
    for p in parts {
        if !p.chars().all(|c| c.is_ascii_alphanumeric()) {
            return None;
        }
        out.push('-');
        match p.len() {
            2 if p.chars().all(|c| c.is_ascii_alphabetic()) => out.push_str(&p.to_ascii_uppercase()),
            4 if p.chars().all(|c| c.is_ascii_alphabetic()) => {
                out.push_str(&p[..1].to_ascii_uppercase());
                out.push_str(&p[1..].to_ascii_lowercase());
            }
            _ => out.push_str(p),
        }
    }
    Some(out)
}

/// `Accept-Language`, best first: entries with `q=0` and `*` are dropped, equal weights keep
/// their order.
pub fn parse_accept_language(header: &str) -> Vec<String> {
    let mut weighted: Vec<(f32, usize, String)> = header
        .split(',')
        .enumerate()
        .filter_map(|(i, part)| {
            let mut bits = part.split(';');
            let tag = bits.next()?.trim();
            if tag == "*" {
                return None;
            }
            let q = bits
                .filter_map(|b| b.trim().strip_prefix("q="))
                .find_map(|q| q.trim().parse::<f32>().ok())
                .unwrap_or(1.0);
            (q > 0.0).then(|| normalize(tag).map(|t| (q, i, t)))?
        })
        .collect();
    weighted.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal).then(a.1.cmp(&b.1)));
    weighted.into_iter().map(|(_, _, t)| t).collect()
}

/// `pt-BR` then `pt`; `zh-Hant-TW`, `zh-Hant`, `zh`.
pub fn expand(tag: &str) -> Vec<String> {
    let mut out = vec![tag.to_string()];
    let mut t = tag;
    while let Some(i) = t.rfind('-') {
        t = &t[..i];
        out.push(t.to_string());
    }
    out
}

/// Where the languages of one request come from.
#[derive(Debug, Clone, Default)]
pub struct LocaleSources<'a> {
    pub accept_language: &'a [String],
    pub user: Option<&'a str>,
    pub client: Option<&'a str>,
    pub default: Option<&'a str>,
}

/// The languages to try, best first, each once, always ending with English.
pub fn chain(src: &LocaleSources<'_>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |tag: &str| {
        if let Some(t) = normalize(tag) {
            for e in expand(&t) {
                if !out.contains(&e) {
                    out.push(e);
                }
            }
        }
    };
    for t in src.accept_language {
        push(t);
    }
    for t in [src.user, src.client, src.default, Some("en")].into_iter().flatten() {
        push(t);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_tags() {
        assert_eq!(normalize("en_US").as_deref(), Some("en-US"));
        assert_eq!(normalize(" PT-br ").as_deref(), Some("pt-BR"));
        assert_eq!(normalize("zh-hant-tw").as_deref(), Some("zh-Hant-TW"));
        assert_eq!(normalize("es-419").as_deref(), Some("es-419"));
        assert_eq!(normalize("en").as_deref(), Some("en"));
        assert_eq!(normalize(""), None);
        assert_eq!(normalize("e1"), None);
        assert_eq!(normalize("en-U$"), None);
        assert_eq!(normalize("abcdefghi"), None);
    }

    #[test]
    fn accept_language_by_weight() {
        assert_eq!(parse_accept_language("pt-BR,pt;q=0.9,en;q=0.8"), vec!["pt-BR", "pt", "en"]);
        assert_eq!(parse_accept_language("en;q=0.5, fr ,de;q=0.7"), vec!["fr", "de", "en"]);
        assert_eq!(parse_accept_language("*, de;q=0, it;q=x"), vec!["it"]);
        assert!(parse_accept_language("").is_empty());
        assert_eq!(parse_accept_language("a, b"), vec!["a", "b"], "equal weights keep their order");
    }

    #[test]
    fn expands_to_less_specific() {
        assert_eq!(expand("pt-BR"), vec!["pt-BR", "pt"]);
        assert_eq!(expand("zh-Hant-TW"), vec!["zh-Hant-TW", "zh-Hant", "zh"]);
        assert_eq!(expand("en"), vec!["en"]);
    }

    #[test]
    fn chain_order() {
        let accept = parse_accept_language("pt-BR,en;q=0.5");
        let c = chain(&LocaleSources { accept_language: &accept, user: Some("fr_FR"), client: Some("de"), default: None });
        assert_eq!(c, vec!["pt-BR", "pt", "en", "fr-FR", "fr", "de"]);
        let c = chain(&LocaleSources { user: Some("pt_BR"), ..Default::default() });
        assert_eq!(c, vec!["pt-BR", "pt", "en"]);
        assert_eq!(chain(&LocaleSources::default()), vec!["en"]);
        let c = chain(&LocaleSources { client: Some("??"), default: Some("hi"), ..Default::default() });
        assert_eq!(c, vec!["hi", "en"]);
    }
}
