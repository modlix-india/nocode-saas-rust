//! The two Spring path matchers the URI path routes use: `AntPathMatcher.match` to find the
//! route (its `name` is an Ant pattern), and `PathPattern.matchAndExtract` to read the route's
//! `pathString` variables (`/api/x/{code}`).

use std::collections::HashMap;

use percent_encoding::percent_decode_str;
use regex::Regex;

/// `AntPathMatcher` tokenising: split on `/`, empty tokens dropped, nothing trimmed.
fn tokenize(s: &str) -> Vec<&str> {
    s.split('/').filter(|t| !t.is_empty()).collect()
}

/// `AntPathStringMatcher`: one path segment against one pattern segment (`*`, `?`, `{name}`,
/// `{name:regex}`), whole-segment and case-sensitive.
fn match_segment(pattern: &str, s: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains(['*', '?', '{']) {
        return pattern == s;
    }
    let mut re = String::from("^");
    let mut literal = String::new();
    let flush = |literal: &mut String, re: &mut String| {
        if !literal.is_empty() {
            re.push_str(&regex::escape(literal));
            literal.clear();
        }
    };
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '*' => {
                flush(&mut literal, &mut re);
                re.push_str(".*");
            }
            '?' => {
                flush(&mut literal, &mut re);
                re.push('.');
            }
            '{' => {
                // A variable runs to its matching close brace (a regex may nest braces).
                let mut depth = 0;
                let mut j = i;
                while j < chars.len() {
                    match chars[j] {
                        '{' => depth += 1,
                        '}' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                    j += 1;
                }
                let inner: String = chars[i + 1..j.min(chars.len())].iter().collect();
                flush(&mut literal, &mut re);
                match inner.split_once(':') {
                    Some((_, custom)) => {
                        re.push('(');
                        re.push_str(custom);
                        re.push(')');
                    }
                    None => re.push_str("(.*)"),
                }
                i = j;
            }
            c => literal.push(c),
        }
        i += 1;
    }
    flush(&mut literal, &mut re);
    re.push('$');
    Regex::new(&re).is_ok_and(|r| r.is_match(s))
}

/// `AntPathMatcher.match(pattern, path)` (full match).
pub fn ant_match(pattern: &str, path: &str) -> bool {
    if path.starts_with('/') != pattern.starts_with('/') {
        return false;
    }
    let patt = tokenize(pattern);
    let dirs = tokenize(path);
    let (mut ps, mut pe) = (0usize as isize, patt.len() as isize - 1);
    let (mut ds, mut de) = (0usize as isize, dirs.len() as isize - 1);

    while ps <= pe && ds <= de {
        let p = patt[ps as usize];
        if p == "**" {
            break;
        }
        if !match_segment(p, dirs[ds as usize]) {
            return false;
        }
        ps += 1;
        ds += 1;
    }
    if ds > de {
        if ps > pe {
            return pattern.ends_with('/') == path.ends_with('/');
        }
        if ps == pe && patt[ps as usize] == "*" && path.ends_with('/') {
            return true;
        }
        return (ps..=pe).all(|i| patt[i as usize] == "**");
    } else if ps > pe {
        return false;
    }

    while ps <= pe && ds <= de {
        let p = patt[pe as usize];
        if p == "**" {
            break;
        }
        if !match_segment(p, dirs[de as usize]) {
            return false;
        }
        if pe == patt.len() as isize - 1 && pattern.ends_with('/') != path.ends_with('/') {
            return false;
        }
        pe -= 1;
        de -= 1;
    }
    if ds > de {
        return (ps..=pe).all(|i| patt[i as usize] == "**");
    }

    while ps != pe && ds <= de {
        let mut tmp = -1isize;
        for i in (ps + 1)..=pe {
            if patt[i as usize] == "**" {
                tmp = i;
                break;
            }
        }
        if tmp == ps + 1 {
            ps += 1;
            continue;
        }
        let pat_len = tmp - ps - 1;
        let str_len = de - ds + 1;
        let mut found = -1isize;
        'outer: for i in 0..=(str_len - pat_len) {
            for j in 0..pat_len {
                if !match_segment(patt[(ps + j + 1) as usize], dirs[(ds + i + j) as usize]) {
                    continue 'outer;
                }
            }
            found = ds + i;
            break;
        }
        if found == -1 {
            return false;
        }
        ps = tmp;
        ds = found + pat_len;
    }
    (ps..=pe).all(|i| patt[i as usize] == "**")
}

/// One element of a parsed path (`PathContainer.parsePath`).
#[derive(Debug, PartialEq)]
enum PathTok {
    Sep,
    /// A segment's `valueToMatch`: decoded, matrix parameters (`;a=b`) removed.
    Seg(String),
}

/// `DefaultPathContainer.parsePath`: separators kept one by one, empty segments dropped.
fn parse_path(path: &str) -> Vec<PathTok> {
    let mut out = Vec::new();
    let mut rest = path;
    if let Some(r) = rest.strip_prefix('/') {
        out.push(PathTok::Sep);
        rest = r;
    }
    if path.is_empty() {
        return out;
    }
    loop {
        let (seg, next) = match rest.find('/') {
            Some(i) => (&rest[..i], Some(&rest[i + 1..])),
            None => (rest, None),
        };
        if !seg.is_empty() {
            let value = seg.split(';').next().unwrap_or("");
            out.push(PathTok::Seg(decode(value)));
        }
        match next {
            Some(r) => {
                out.push(PathTok::Sep);
                rest = r;
            }
            None => break,
        }
    }
    out
}

/// One element of a Spring `PathPattern`.
#[derive(Debug)]
enum Element {
    Sep,
    Literal(String),
    /// `*`: one segment (an empty one only at the end of the pattern).
    Wildcard,
    /// `{name}` or `{name:regex}` alone in its segment.
    Capture(String, Option<Regex>),
    /// A segment mixing literals, `*`, `?` and variables.
    Regex(Regex, Vec<String>),
    /// `**` at the end: the rest of the path, its leading separator included.
    Rest,
    /// `{*name}` at the end: the same, captured.
    CaptureRest(String),
}

/// A parsed `PathPattern` (`PathPatternParser.defaultInstance`: no optional trailing separator,
/// case sensitive).
#[derive(Debug)]
pub struct PathPattern {
    elements: Vec<Element>,
}

/// What `PathPatternParser` refuses (`PatternParseException`).
#[derive(Debug, PartialEq, Eq)]
pub struct PatternError(pub String);

impl PathPattern {
    pub fn parse(pattern: &str) -> Result<PathPattern, PatternError> {
        let err = |m: &str| PatternError(format!("{m}: {pattern}"));
        let mut elements: Vec<Element> = Vec::new();
        let mut names: Vec<String> = Vec::new();
        let add_name = |n: &str, names: &mut Vec<String>| -> Result<(), PatternError> {
            if names.iter().any(|x| x == n) {
                return Err(err("Path variable used more than once"));
            }
            names.push(n.to_string());
            Ok(())
        };
        let parts: Vec<&str> = pattern.split('/').collect();
        for (i, seg) in parts.iter().enumerate() {
            if i > 0 {
                elements.push(Element::Sep);
            }
            if seg.is_empty() {
                continue;
            }
            if matches!(elements.last(), Some(Element::Rest | Element::CaptureRest(_))) {
                return Err(err("No more pattern data allowed after {*...} or ** pattern element"));
            }
            let last = i == parts.len() - 1;
            if *seg == "**" || (seg.starts_with("{*") && seg.ends_with('}')) {
                if !last {
                    return Err(err("No more pattern data allowed after {*...} or ** pattern element"));
                }
                // It takes the separator before it with it.
                if matches!(elements.last(), Some(Element::Sep)) {
                    elements.pop();
                }
                if *seg == "**" {
                    elements.push(Element::Rest);
                } else {
                    let name = &seg[2..seg.len() - 1];
                    add_name(name, &mut names)?;
                    elements.push(Element::CaptureRest(name.to_string()));
                }
            } else if *seg == "*" {
                elements.push(Element::Wildcard);
            } else if seg.starts_with('{') && seg.ends_with('}') && whole_variable(seg) {
                let inner = &seg[1..seg.len() - 1];
                let (name, re) = match inner.split_once(':') {
                    Some((n, r)) => (n, Some(Regex::new(&format!("^(?:{r})$")).map_err(|_| err("Bad regex"))?)),
                    None => (inner, None),
                };
                add_name(name, &mut names)?;
                elements.push(Element::Capture(name.to_string(), re));
            } else if seg.contains(['{', '*', '?']) {
                let (re, vars) = segment_regex(seg).ok_or_else(|| err("Missing closing brace"))?;
                for v in &vars {
                    add_name(v, &mut names)?;
                }
                elements.push(Element::Regex(re, vars));
            } else {
                elements.push(Element::Literal(seg.to_string()));
            }
        }
        Ok(PathPattern { elements })
    }

    /// `matchAndExtract`: the decoded variables when the whole path matches.
    pub fn match_and_extract(&self, path: &str) -> Option<HashMap<String, String>> {
        let toks = parse_path(path);
        let mut vars = HashMap::new();
        let mut pi = 0;
        let n = self.elements.len();
        for (ei, e) in self.elements.iter().enumerate() {
            let tok = toks.get(pi);
            match e {
                Element::Rest | Element::CaptureRest(_) => {
                    if pi < toks.len() && toks[pi] != PathTok::Sep {
                        return None;
                    }
                    if let Element::CaptureRest(name) = e {
                        let rest: String = toks[pi..]
                            .iter()
                            .map(|t| match t {
                                PathTok::Sep => "/",
                                PathTok::Seg(s) => s.as_str(),
                            })
                            .collect();
                        vars.insert(name.clone(), rest);
                    }
                    return Some(vars);
                }
                Element::Sep => {
                    if tok != Some(&PathTok::Sep) {
                        return None;
                    }
                }
                Element::Wildcard => match tok {
                    Some(PathTok::Seg(s)) => {
                        if s.is_empty() && ei + 1 < n {
                            return None;
                        }
                    }
                    Some(PathTok::Sep) => return None,
                    // Only a last `*` matches nothing at all.
                    None => return (ei + 1 == n).then_some(vars),
                },
                Element::Literal(l) => match tok {
                    Some(PathTok::Seg(s)) if s == l => {}
                    _ => return None,
                },
                Element::Capture(name, re) => match tok {
                    Some(PathTok::Seg(s)) if !s.is_empty() && re.as_ref().is_none_or(|r| r.is_match(s)) => {
                        vars.insert(name.clone(), s.clone());
                    }
                    _ => return None,
                },
                Element::Regex(re, names) => {
                    let Some(PathTok::Seg(s)) = tok else { return None };
                    let caps = re.captures(s)?;
                    for (k, name) in names.iter().enumerate() {
                        if let Some(m) = caps.get(k + 1) {
                            vars.insert(name.clone(), m.as_str().to_string());
                        }
                    }
                }
            }
            pi += 1;
        }
        (pi == toks.len()).then_some(vars)
    }
}

/// `{name}` or `{name:regex}` spanning the whole segment (and not `{a}{b}`).
fn whole_variable(seg: &str) -> bool {
    let mut depth = 0;
    for (i, c) in seg.char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 && i != seg.len() - 1 {
                    return false;
                }
            }
            _ => {}
        }
    }
    depth == 0
}

/// A segment with variables as a regex and the variable names in order.
fn segment_regex(seg: &str) -> Option<(Regex, Vec<String>)> {
    let mut re = String::from("^");
    let mut names = Vec::new();
    let chars: Vec<char> = seg.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '{' => {
                let mut depth = 0;
                let mut j = i;
                while j < chars.len() {
                    match chars[j] {
                        '{' => depth += 1,
                        '}' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                    j += 1;
                }
                if j >= chars.len() {
                    return None;
                }
                let inner: String = chars[i + 1..j].iter().collect();
                match inner.split_once(':') {
                    Some((n, custom)) => {
                        names.push(n.to_string());
                        re.push('(');
                        re.push_str(custom);
                        re.push(')');
                    }
                    None => {
                        names.push(inner);
                        re.push_str("(.*)");
                    }
                }
                i = j;
            }
            '*' => re.push_str(".*"),
            '?' => re.push('.'),
            c => re.push_str(&regex::escape(&c.to_string())),
        }
        i += 1;
    }
    re.push('$');
    Some((Regex::new(&re).ok()?, names))
}

fn decode(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().to_string()
}

#[cfg(test)]
mod tests {
    //! Expectations recorded from Spring 6.2.1 (`AntPathMatcher.match`,
    //! `PathPatternParser.defaultInstance.parse(p).matchAndExtract(PathContainer.parsePath(x))`).
    use super::*;

    #[test]
    fn ant_patterns_like_spring() {
        let cases: &[(&str, &str, bool)] = &[
            ("/hello/*/*/C/B", "/hello/x/y/C/B", true),
            ("/hello/*/*/C/B", "/hello/x/C/B", false),
            ("/api/open/tickets/req/website/**", "/api/open/tickets/req/website/P1/x", true),
            ("/api/open/tickets/req/website/**", "/api/open/tickets/req/website", true),
            ("/api/open/tickets/req/website/**", "/api/open/tickets/req/website/", true),
            ("/api/exotel/call", "/api/exotel/call", true),
            ("/api/exotel/call", "/api/exotel/call/", false),
            ("api/transactions/x", "/api/transactions/x", false),
            ("api/transactions/x", "api/transactions/x", true),
            ("/a/**/b", "/a/x/y/b", true),
            ("/a/**/b", "/a/b", true),
            ("/a/**/b/**/c", "/a/x/b/y/z/c", true),
            ("/a/**/b/**/c", "/a/x/c", false),
            ("/a/**/**/c", "/a/x/c", true),
            ("/a/{id}/c", "/a/42/c", true),
            (r#"/a/{id:\d+}"#, "/a/42", true),
            (r#"/a/{id:\d+}"#, "/a/x", false),
            ("/a/f?o", "/a/foo", true),
            ("/a/*.json", "/a/x.json", true),
            ("/a/*.json", "/a/x.xml", false),
            ("/a/*", "/a/", true),
            ("/a/b", "/a", false),
            ("/a", "/a/b", false),
            ("/**", "/anything/at/all", true),
            ("/a/**/x/y", "/a/b/x", false),
            ("/a/**/x/y", "/a/b/x/y", true),
            ("/a/**/z", "/a/b/c", false),
            ("/a/**/b/**/c", "/a/q/c", false),
            ("/a/**", "/a/", true),
            ("/", "/", true),
            ("/a//b", "/a/b", true),
            ("/a/b", "/a//b", true),
            ("/A/b", "/a/b", false),
            ("/a/*b*c", "/a/xbyc", true),
            ("/a/{x}-{y}", "/a/1-2", true),
            ("/a/**/", "/a/b/", true),
            ("/a/**/", "/a/b", true),
            ("/a/x/", "/a/x", false),
            ("/a/x", "/a/x/", false),
            ("/a/*/", "/a/b/", true),
            ("/a/*/", "/a/b", false),
            ("", "/", false),
            ("/", "", false),
            ("**", "/a/b", false),
            (r#"/a/{x:[a-z]+}{y:\d+}"#, "/a/abc12", true),
            ("/a/%20", "/a/%20", true),
            ("/a/ b", "/a/ b", true),
            ("/a/b/**/c/**", "/a/b/c", true),
            ("/**/c", "/c", true),
            ("/**/c", "/x/y/c", true),
            ("/a/*/**", "/a", false),
            ("/a/*/**", "/a/b", true),
        ];
        for (pattern, path, expected) in cases {
            assert_eq!(ant_match(pattern, path), *expected, "{pattern} vs {path}");
        }
    }

    /// `None` for no match, else the variables as `k=v` pairs sorted by name.
    fn extract(pattern: &str, path: &str) -> Option<String> {
        let vars = PathPattern::parse(pattern).ok()?.match_and_extract(path)?;
        let mut v: Vec<String> = vars.into_iter().map(|(k, v)| format!("{k}={v}")).collect();
        v.sort();
        Some(format!("{{{}}}", v.join(", ")))
    }

    #[test]
    fn path_patterns_like_spring() {
        let cases: &[(&str, &str, &str)] = &[
            ("/hello/{a}/{b}/C/B", "/hello/x%20y/2/C/B", "{a=x y, b=2}"),
            ("/hello/{a}/{b}/C/B", "/hello/x/C/B", "NOMATCH"),
            ("/hello/{a}/{b}/C/B", "/hello/x/y/C/B/", "NOMATCH"),
            ("/api/open/tickets/req/website/{code}", "/api/open/tickets/req/website/P123", "{code=P123}"),
            (r#"/a/{id:\d+}.json"#, "/a/7.json", "{id=7}"),
            ("/a/**", "/a/b/c", "{}"),
            ("/a/{*rest}", "/a/b/c", "{rest=/b/c}"),
            ("/a/{*rest}", "/a", "{rest=}"),
            ("/a/*/f?", "/a/q/fo", "{}"),
            ("/a/", "/a/", "{}"),
            ("/a/", "/a", "NOMATCH"),
            ("/a", "/a/b", "NOMATCH"),
            ("/a/b", "/a", "NOMATCH"),
            ("/api/open/tickets/req/website", "/api/open/tickets/req/website/P1", "NOMATCH"),
            ("/a/{x}", "/a/%E2%82%AC", "{x=€}"),
            ("/a/{x}", "/a/a+b", "{x=a+b}"),
            ("/a/{x}", "/a/a;b=c", "{x=a}"),
            ("/a/{x}-{y}", "/a/1-2", "{x=1, y=2}"),
            ("/a/{x}", "/a//", "NOMATCH"),
            ("/a//{x}", "/a//b", "{x=b}"),
            ("/a/{x}", "/a/b/", "NOMATCH"),
            ("api/x/{y}", "/api/x/1", "NOMATCH"),
            ("/api/x/{y}", "api/x/1", "NOMATCH"),
            ("/transactions/webhook/virtualAccount", "/transactions/webhook/virtualAccount", "{}"),
            ("/a/{x}", "/A/b", "NOMATCH"),
            ("/a/**", "/a", "{}"),
            ("/a/**", "/a/", "{}"),
            ("/a/*", "/a/", "{}"),
            ("/a/*", "/a", "NOMATCH"),
            ("/a/*", "/a/b", "{}"),
            ("/a/{x}", "/a/", "NOMATCH"),
            ("/a/{*r}", "/a/", "{r=/}"),
            ("/a/{*r}", "/a/b%20c/d;x=1", "{r=/b c/d}"),
            ("/**", "/", "{}"),
            ("/**", "", "{}"),
            ("/{*r}", "/", "{r=/}"),
            ("/a/b*", "/a/b", "{}"),
            ("/a/b*", "/a/bcd", "{}"),
            ("/a/?", "/a/b", "{}"),
            ("/a/?", "/a/bc", "NOMATCH"),
            ("/a/{x:[0-9]+}", "/a/12", "{x=12}"),
            ("/a/{x:[0-9]+}", "/a/1x", "NOMATCH"),
            ("/a/x{y}z", "/a/x1z", "{y=1}"),
            ("/a/x{y}z", "/a/xz", "{y=}"),
            ("/a/{x}", "/a/%2F", "{x=/}"),
            ("/", "/", "{}"),
            ("/", "", "NOMATCH"),
            ("", "/", "NOMATCH"),
            ("", "", "{}"),
            ("/a/b", "/a/b;x=1", "{}"),
        ];
        for (pattern, path, expected) in cases {
            let got = extract(pattern, path).unwrap_or_else(|| "NOMATCH".into());
            assert_eq!(&got, expected, "{pattern} vs {path}");
        }
    }

    #[test]
    fn refuses_patterns_spring_refuses() {
        for bad in ["/a/**/b", "/a/{*r}/b", "/a/{x", "/a/{x}/{x}", "/a/x{y", "/a/{x:(}"] {
            assert!(PathPattern::parse(bad).is_err(), "{bad}");
        }
        assert!(PathPattern::parse("/a/{x}{y}").is_ok());
    }
}
