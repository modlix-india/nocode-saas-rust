//! Message templates: named placeholders with defaults, and optional segments, so a message
//! never shows an empty hole when a value is unknown.
//!
//! - `{app}`: the value of `app`.
//! - `{app|this app}`: the value, or the default text when there is none.
//! - `[ in {app}]`: kept only when every placeholder directly inside has a value.
//! - `[the {permission} permission|this permission]`: the part before `|` when its placeholders
//!   all have values, else the part after it.
//! - `\{`, `\}`, `\[`, `\]`, `\|` and `\\` stand for the character itself.
//!
//! A blank value counts as no value. Runs of spaces left by a dropped part are collapsed.

#[derive(Debug, Clone, PartialEq)]
enum Node {
    Text(String),
    Var { name: String, default: Option<String> },
    Optional { body: Vec<Node>, otherwise: Vec<Node> },
}

/// A parsed template.
#[derive(Debug, Clone, PartialEq)]
pub struct Template {
    nodes: Vec<Node>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TemplateError {
    #[error("'{{' at {0} is never closed")]
    UnclosedPlaceholder(usize),
    #[error("a placeholder at {0} has no name")]
    EmptyName(usize),
    #[error("'[' is never closed")]
    UnclosedOptional,
    #[error("']' at {0} closes nothing")]
    StrayClose(usize),
}

enum End {
    Eof,
    Close,
    Pipe,
}

struct Parser {
    chars: Vec<char>,
    pos: usize,
}

impl Parser {
    fn next(&mut self) -> Option<char> {
        let c = self.chars.get(self.pos).copied();
        self.pos += 1;
        c
    }

    /// Nodes up to the end of input, or (inside a segment) up to its `]` or, when `pipe_ends`,
    /// its first `|`.
    fn nodes(&mut self, depth: usize, pipe_ends: bool) -> Result<(Vec<Node>, End), TemplateError> {
        let mut out = Vec::new();
        let mut text = String::new();
        let flush = |text: &mut String, out: &mut Vec<Node>| {
            if !text.is_empty() {
                out.push(Node::Text(std::mem::take(text)));
            }
        };
        while let Some(c) = self.next() {
            match c {
                '\\' => text.push(self.next().unwrap_or('\\')),
                '{' => {
                    flush(&mut text, &mut out);
                    out.push(self.placeholder()?);
                }
                '[' => {
                    flush(&mut text, &mut out);
                    out.push(self.optional(depth)?);
                }
                ']' if depth > 0 => {
                    flush(&mut text, &mut out);
                    return Ok((out, End::Close));
                }
                ']' => return Err(TemplateError::StrayClose(self.pos - 1)),
                '|' if pipe_ends => {
                    flush(&mut text, &mut out);
                    return Ok((out, End::Pipe));
                }
                c => text.push(c),
            }
        }
        flush(&mut text, &mut out);
        if depth > 0 {
            Err(TemplateError::UnclosedOptional)
        } else {
            Ok((out, End::Eof))
        }
    }

    fn placeholder(&mut self) -> Result<Node, TemplateError> {
        let start = self.pos - 1;
        let mut name = String::new();
        let mut default: Option<String> = None;
        loop {
            let Some(c) = self.next() else { return Err(TemplateError::UnclosedPlaceholder(start)) };
            let c = match c {
                '}' => break,
                '|' if default.is_none() => {
                    default = Some(String::new());
                    continue;
                }
                '\\' => self.next().ok_or(TemplateError::UnclosedPlaceholder(start))?,
                c => c,
            };
            match default.as_mut() {
                Some(d) => d.push(c),
                None => name.push(c),
            }
        }
        let name = name.trim().to_string();
        if name.is_empty() {
            return Err(TemplateError::EmptyName(start));
        }
        Ok(Node::Var { name, default })
    }

    fn optional(&mut self, depth: usize) -> Result<Node, TemplateError> {
        let (body, end) = self.nodes(depth + 1, true)?;
        let otherwise = match end {
            End::Pipe => self.nodes(depth + 1, false)?.0,
            End::Close | End::Eof => Vec::new(),
        };
        Ok(Node::Optional { body, otherwise })
    }
}

fn present(v: Option<String>) -> Option<String> {
    v.filter(|s| !s.trim().is_empty())
}

impl Template {
    pub fn parse(src: &str) -> Result<Self, TemplateError> {
        let mut p = Parser { chars: src.chars().collect(), pos: 0 };
        Ok(Self { nodes: p.nodes(0, false)?.0 })
    }

    /// The text with each placeholder filled from `value`.
    pub fn render(&self, value: &dyn Fn(&str) -> Option<String>) -> String {
        let mut out = String::new();
        render_nodes(&self.nodes, value, &mut out);
        tidy(&out)
    }

    /// Every placeholder name, first use first.
    pub fn placeholders(&self) -> Vec<String> {
        let mut names = Vec::new();
        collect(&self.nodes, &mut names);
        names
    }

    /// Placeholders that print nothing when they have no value: outside every optional segment
    /// and without a default. A built-in message must have none (see the catalogue tests).
    pub fn bare_placeholders(&self) -> Vec<String> {
        self.nodes
            .iter()
            .filter_map(|n| match n {
                Node::Var { name, default: None } => Some(name.clone()),
                _ => None,
            })
            .collect()
    }
}

fn collect(nodes: &[Node], names: &mut Vec<String>) {
    for n in nodes {
        match n {
            Node::Text(_) => {}
            Node::Var { name, .. } => {
                if !names.contains(name) {
                    names.push(name.clone());
                }
            }
            Node::Optional { body, otherwise } => {
                collect(body, names);
                collect(otherwise, names);
            }
        }
    }
}

fn render_nodes(nodes: &[Node], value: &dyn Fn(&str) -> Option<String>, out: &mut String) {
    for n in nodes {
        match n {
            Node::Text(t) => out.push_str(t),
            Node::Var { name, default } => match present(value(name)) {
                Some(v) => out.push_str(&v),
                None => out.push_str(default.as_deref().unwrap_or("")),
            },
            Node::Optional { body, otherwise } => {
                let complete = body.iter().all(|n| match n {
                    Node::Var { name, .. } => present(value(name)).is_some(),
                    _ => true,
                });
                render_nodes(if complete { body } else { otherwise }, value, out);
            }
        }
    }
}

/// Collapses runs of spaces (a dropped segment can leave two) and trims the ends.
fn tidy(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last_space = false;
    for c in s.chars() {
        if c == ' ' {
            if !last_space {
                out.push(' ');
            }
            last_space = true;
        } else {
            out.push(c);
            last_space = false;
        }
    }
    out.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(t: &str, vals: &[(&str, &str)]) -> String {
        let t = Template::parse(t).unwrap();
        t.render(&|k| vals.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string()))
    }

    #[test]
    fn placeholders_and_defaults() {
        assert_eq!(r("You can't open {app}.", &[("app", "LeadZump")]), "You can't open LeadZump.");
        assert_eq!(r("You can't open {app|this app}.", &[]), "You can't open this app.");
        assert_eq!(r("You can't open {app|this app}.", &[("app", "  ")]), "You can't open this app.");
        assert_eq!(r("{a}{b}", &[("a", "x"), ("b", "y")]), "xy");
        assert_eq!(r("Hi { name }", &[("name", "Kiran")]), "Hi Kiran");
    }

    #[test]
    fn optional_segments_and_alternatives() {
        let t = "You can't do this[ in {app}].";
        assert_eq!(r(t, &[("app", "CRM")]), "You can't do this in CRM.");
        assert_eq!(r(t, &[]), "You can't do this.");
        let t = "Ask for [the {permission} permission|this permission].";
        assert_eq!(r(t, &[("permission", "Edit pages")]), "Ask for the Edit pages permission.");
        assert_eq!(r(t, &[]), "Ask for this permission.");
        // A nested segment decides for itself; the outer one only looks at its own placeholders.
        let t = "[{a} [and {b}]|none]";
        assert_eq!(r(t, &[("a", "x")]), "x");
        assert_eq!(r(t, &[("a", "x"), ("b", "y")]), "x and y");
        assert_eq!(r(t, &[("b", "y")]), "none");
        // A default inside a segment does not make the segment complete.
        assert_eq!(r("A[ {x|y}]", &[]), "A");
    }

    #[test]
    fn escapes_and_pipes() {
        assert_eq!(r(r"Use \{braces\} and \[brackets\] \| \\", &[]), r"Use {braces} and [brackets] | \");
        assert_eq!(r("a | b", &[]), "a | b");
        assert_eq!(r(r"{x|a\}b}", &[]), "a}b");
        assert_eq!(r(r"[{x}|a \| b]", &[]), "a | b");
        assert_eq!(r("trailing \\", &[]), "trailing \\");
    }

    #[test]
    fn spaces_are_tidied() {
        assert_eq!(r("  A  [{x} ] B ", &[]), "A B");
    }

    #[test]
    fn names_and_bare_placeholders() {
        let t = Template::parse("{a} {b|x} [{c} {a}|{d}]").unwrap();
        assert_eq!(t.placeholders(), vec!["a", "b", "c", "d"]);
        assert_eq!(t.bare_placeholders(), vec!["a"]);
    }

    #[test]
    fn malformed_templates() {
        assert_eq!(Template::parse("a {b").unwrap_err(), TemplateError::UnclosedPlaceholder(2));
        assert_eq!(Template::parse("a {b\\").unwrap_err(), TemplateError::UnclosedPlaceholder(2));
        assert_eq!(Template::parse("{ }").unwrap_err(), TemplateError::EmptyName(0));
        assert_eq!(Template::parse("[a").unwrap_err(), TemplateError::UnclosedOptional);
        assert_eq!(Template::parse("[a|b").unwrap_err(), TemplateError::UnclosedOptional);
        assert_eq!(Template::parse("a]").unwrap_err(), TemplateError::StrayClose(1));
        assert!(TemplateError::UnclosedOptional.to_string().contains("never closed"));
    }
}
