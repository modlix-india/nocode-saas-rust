//! The FreeMarker the email templates are written in (`AbstractTemplateService.processFreeMarker`:
//! FreeMarker 2.3.32, `RETHROW_HANDLER`, the default object wrapper, BigDecimal arithmetic, the
//! `number` number format).
//!
//! Not the whole language: the parts the stored templates use (census of every local template,
//! 2026-10-15), each ported from FreeMarker's own sources so the output is the same character for
//! character, white-space stripping included:
//!
//! - `${...}` interpolation; `<#if>` / `<#elseif>` / `<#else>`; `<#list x as y>` with `<#sep>`
//!   and an `<#else>` for an empty list; `<#-- comments -->`.
//! - Literals, variables, `.name`, `[key]`, `!` and `??` (with FreeMarker's rule that only a
//!   parenthesised expression may be missing at any depth), `!`, `&&`, `||`, `==` / `=` / `!=`,
//!   `<` `<=` `>` `>=` (and `lt` `lte` `gt` `gte`, `&lt;` `&gt;`), `+` (sum or concatenation),
//!   `-` `*` `/` `%`.
//! - Built-ins: `has_content`, `number`, `replace`, `length`, `then`, `string` (numbers with a
//!   Java `DecimalFormat` pattern, booleans), `is_number` and the other `is_*`, `matches`, the
//!   loop variable ones (`index`, `counter`, `has_next`, `is_last`, `is_first`, `item_parity`),
//!   `size`, `trim`, `upper_case`, `lower_case`, `cap_first`, `uncap_first`, `contains`,
//!   `starts_with`, `ends_with`, `c`, `round`, `floor`, `ceiling`, `abs`, `int`.
//!
//! Anything else (macros, `<#assign>`, `<@...>`, other built-ins) fails to render with a message
//! naming it, rather than rendering something Java would not. Error messages are not FreeMarker's.

use std::cmp::Ordering;

use serde_json::{Map, Value};

use crate::error::ConnError;
use crate::java::json;

fn err(msg: impl Into<String>) -> ConnError {
    ConnError::other(msg.into())
}

/// `processFreeMarker(name, template, data)`.
///
/// Plain `${number}` uses the `number` format of the JVM's default locale; for `en`, `en_US`
/// and `en_IN` alike Java's `DecimalFormat` writes `#,##0.###` (it has no secondary grouping, so
/// even `en_IN` groups by three), which is what this writes.
pub fn process(name: &str, source: Option<&str>, data: &Map<String, Value>) -> Result<String, ConnError> {
    process_with(name, source, data, false)
}

/// `process` with FreeMarker's `IGNORE_HANDLER` (`TemplatePreviewService`): an element that
/// fails to render (an undefined `${var}`, an `#if` on a missing value) writes nothing more
/// and the rest of the template goes on; what it had written before failing stays. A syntax
/// error still fails the whole template.
pub fn process_lenient(name: &str, source: Option<&str>, data: &Map<String, Value>) -> Result<String, ConnError> {
    process_with(name, source, data, true)
}

fn process_with(name: &str, source: Option<&str>, data: &Map<String, Value>, lenient: bool) -> Result<String, ConnError> {
    let Some(source) = source else {
        return Err(err("Cannot invoke \"String.length()\" because \"s\" is null"));
    };
    let template = parse(source).map_err(|e| err(format!("Syntax error in template \"{name}\": {e}")))?;
    let mut out = String::with_capacity(source.len());
    let mut env = Env { data, loops: Vec::new(), lenient };
    env.render(&template, template.root, &mut out)
        .map_err(|e| err(format!("Error rendering template \"{name}\": {e}")))?;
    Ok(out)
}

// =============================================================================================
// Tree

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Pos {
    line: i64,
    col: i64,
}

#[derive(Debug, Clone)]
enum Kind {
    Mixed,
    Text(Vec<char>),
    Dollar(Expr),
    IfBlock,
    /// `None` for `#else`.
    Cond(Option<Expr>),
    /// `<#list>` with its `#else` (the body is the first child, the else the second).
    ListElse,
    List { seq: Expr, var: String },
    ListElseBody,
    Sep,
    Comment,
}

#[derive(Debug, Clone)]
struct Node {
    kind: Kind,
    children: Vec<usize>,
    parent: Option<usize>,
    begin: Pos,
    end: Pos,
}

#[derive(Debug)]
pub struct Template {
    nodes: Vec<Node>,
    root: usize,
}

impl Template {
    fn add(&mut self, kind: Kind, begin: Pos, end: Pos) -> usize {
        self.nodes.push(Node { kind, children: Vec::new(), parent: None, begin, end });
        self.nodes.len() - 1
    }

    fn set_children(&mut self, id: usize, children: Vec<usize>) {
        for &c in &children {
            self.nodes[c].parent = Some(id);
        }
        self.nodes[id].children = children;
    }

    fn index_in_parent(&self, id: usize) -> Option<(usize, usize)> {
        let p = self.nodes[id].parent?;
        let i = self.nodes[p].children.iter().position(|c| *c == id)?;
        Some((p, i))
    }

    fn previous_sibling(&self, id: usize) -> Option<usize> {
        let (p, i) = self.index_in_parent(id)?;
        if i > 0 {
            Some(self.nodes[p].children[i - 1])
        } else {
            None
        }
    }

    fn next_sibling(&self, id: usize) -> Option<usize> {
        let (p, i) = self.index_in_parent(id)?;
        self.nodes[p].children.get(i + 1).copied()
    }

    fn first_leaf(&self, mut id: usize) -> usize {
        while let Some(&c) = self.nodes[id].children.first() {
            id = c;
        }
        id
    }

    fn last_leaf(&self, mut id: usize) -> usize {
        while let Some(&c) = self.nodes[id].children.last() {
            id = c;
        }
        id
    }

    fn next_terminal(&self, id: usize) -> Option<usize> {
        match self.next_sibling(id) {
            Some(n) => Some(self.first_leaf(n)),
            None => self.nodes[id].parent.and_then(|p| self.next_terminal(p)),
        }
    }

    fn prev_terminal(&self, id: usize) -> Option<usize> {
        match self.previous_sibling(id) {
            Some(n) => Some(self.last_leaf(n)),
            None => self.nodes[id].parent.and_then(|p| self.prev_terminal(p)),
        }
    }

    fn is_top_level_text_if_parent_is(&self, parent: Option<usize>) -> bool {
        match parent {
            None => true,
            Some(p) => self.nodes[p].parent.is_none() && matches!(self.nodes[p].kind, Kind::Mixed),
        }
    }

    fn non_outputting(&self, id: Option<usize>) -> bool {
        id.is_some_and(|i| matches!(self.nodes[i].kind, Kind::Comment))
    }

    fn is_ignorable(&self, id: usize) -> bool {
        let Kind::Text(text) = &self.nodes[id].kind else { return false };
        if text.is_empty() {
            return true;
        }
        if !trimmable(text, 0, text.len()) {
            return false;
        }
        let top = self.is_top_level_text_if_parent_is(self.nodes[id].parent);
        let prev = self.previous_sibling(id);
        let next = self.next_sibling(id);
        ((prev.is_none() && top) || self.non_outputting(prev)) && ((next.is_none() && top) || self.non_outputting(next))
    }

    fn heeds_opening_whitespace(&self, id: usize) -> bool {
        match &self.nodes[id].kind {
            Kind::Dollar(_) => true,
            Kind::Text(text) => {
                if self.is_ignorable(id) {
                    return false;
                }
                for &c in text.iter().rev() {
                    if c == '\n' || c == '\r' {
                        return false;
                    }
                    if !java_whitespace(c) {
                        return true;
                    }
                }
                true
            }
            _ => false,
        }
    }

    fn heeds_trailing_whitespace(&self, id: usize) -> bool {
        match &self.nodes[id].kind {
            Kind::Dollar(_) => true,
            Kind::Text(text) => {
                if self.is_ignorable(id) {
                    return false;
                }
                for &c in text.iter() {
                    if c == '\n' || c == '\r' {
                        return false;
                    }
                    if !java_whitespace(c) {
                        return true;
                    }
                }
                true
            }
            _ => false,
        }
    }

    /// `TextBlock.postParseCleanup` (no `#t` / `#lt` / `#rt` in these templates).
    fn clean_text(&mut self, id: usize) {
        let Kind::Text(text) = &self.nodes[id].kind else { return };
        if text.is_empty() {
            return;
        }
        let text = text.clone();
        let parent = self.nodes[id].parent;
        if self.is_top_level_text_if_parent_is(parent) && self.previous_sibling(id).is_none() {
            return;
        }
        let trailing = self.trailing_chars_to_strip(id, &text);
        let opening = self.opening_chars_to_strip(id, &text);
        if opening == 0 && trailing == 0 {
            return;
        }
        let new_text: Vec<char> = text[opening..text.len() - trailing].to_vec();
        let node = &mut self.nodes[id];
        node.kind = Kind::Text(new_text);
        if opening > 0 {
            node.begin.line += 1;
            node.begin.col = 1;
        }
        if trailing > 0 {
            node.end.col = 0;
        }
    }

    fn opening_chars_to_strip(&self, id: usize, text: &[char]) -> usize {
        let first_nl = text.iter().position(|c| *c == '\r' || *c == '\n');
        if first_nl.is_none() && self.nodes[id].begin.col != 1 {
            return 0;
        }
        let mut nl = first_nl.map(|i| i as i64).unwrap_or(-1) + 1;
        let nlu = nl as usize;
        if text.len() > nlu && nlu > 0 && text[nlu - 1] == '\r' && text[nlu] == '\n' {
            nl += 1;
        }
        let nlu = nl as usize;
        if !trimmable(text, 0, nlu) {
            return 0;
        }
        let begin_line = self.nodes[id].begin.line;
        let mut e = self.prev_terminal(id);
        while let Some(el) = e {
            if self.nodes[el].end.line != begin_line {
                break;
            }
            if self.heeds_opening_whitespace(el) {
                return 0;
            }
            e = self.prev_terminal(el);
        }
        nlu
    }

    fn trailing_chars_to_strip(&self, id: usize, text: &[char]) -> usize {
        let last_nl = text.iter().rposition(|c| *c == '\r' || *c == '\n');
        if last_nl.is_none() && self.nodes[id].begin.col != 1 {
            return 0;
        }
        let from = last_nl.map(|i| i + 1).unwrap_or(0);
        if !trimmable(text, from, text.len()) {
            return 0;
        }
        let end_line = self.nodes[id].end.line;
        let mut e = self.next_terminal(id);
        while let Some(el) = e {
            if self.nodes[el].begin.line != end_line {
                break;
            }
            if self.heeds_trailing_whitespace(el) {
                return 0;
            }
            e = self.next_terminal(el);
        }
        text.len() - from
    }

    /// `postParseCleanup(stripWhitespace = true)`: returns the node that takes this one's place.
    fn cleanup(&mut self, id: usize) -> usize {
        match self.nodes[id].kind {
            Kind::Text(_) => {
                self.clean_text(id);
                id
            }
            Kind::IfBlock if self.nodes[id].children.len() == 1 => {
                let c = self.nodes[id].children[0];
                self.nodes[c].end = self.nodes[id].end;
                self.cleanup(c)
            }
            Kind::Mixed => {
                self.cleanup_children(id);
                if self.nodes[id].children.len() == 1 {
                    self.nodes[id].children[0]
                } else {
                    id
                }
            }
            _ => {
                self.cleanup_children(id);
                id
            }
        }
    }

    fn cleanup_children(&mut self, id: usize) {
        let count = self.nodes[id].children.len();
        for i in 0..count {
            let child = self.nodes[id].children[i];
            let replaced = self.cleanup(child);
            self.nodes[id].children[i] = replaced;
            self.nodes[replaced].parent = Some(id);
        }
        let mut i = 0;
        while i < self.nodes[id].children.len() {
            let c = self.nodes[id].children[i];
            if self.is_ignorable(c) {
                self.nodes[id].children.remove(i);
            } else {
                i += 1;
            }
        }
    }
}

/// `StringUtil.isTrimmableToEmpty`: every char at or below U+0020.
fn trimmable(text: &[char], start: usize, end: usize) -> bool {
    text[start..end].iter().all(|c| (*c as u32) <= 0x20)
}

fn java_whitespace(c: char) -> bool {
    crate::java::is_whitespace(c)
}

// =============================================================================================
// Parsing

struct Parser {
    src: Vec<char>,
    i: usize,
    line: i64,
    col: i64,
    t: Template,
}

#[derive(Debug, PartialEq)]
enum Stop {
    Eof,
    /// An end or middle tag: its name (`/if`, `elseif`, `else`, `/list`, `sep`, `/sep`).
    Tag(String),
}

impl Parser {
    fn pos(&self) -> Pos {
        Pos { line: self.line, col: self.col }
    }

    fn at(&self, s: &str) -> bool {
        let mut j = self.i;
        for c in s.chars() {
            if self.src.get(j) != Some(&c) {
                return false;
            }
            j += 1;
        }
        true
    }

    fn peek(&self) -> Option<char> {
        self.src.get(self.i).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = *self.src.get(self.i)?;
        self.i += 1;
        if c == '\n' {
            self.line += 1;
            self.col = 1;
        } else if c == '\r' {
            if self.src.get(self.i) != Some(&'\n') {
                self.line += 1;
                self.col = 1;
            } else {
                self.col += 1;
            }
        } else {
            self.col += 1;
        }
        Some(c)
    }

    /// The position of the char just consumed (JavaCC's token end: the last char's own spot).
    fn bump_end(&mut self) -> Pos {
        let p = self.pos();
        self.bump();
        p
    }

    fn tag_name_after(&self, prefix_len: usize) -> String {
        let mut j = self.i + prefix_len;
        let mut name = String::new();
        while let Some(c) = self.src.get(j) {
            if c.is_ascii_alphanumeric() || *c == '_' {
                name.push(*c);
                j += 1;
            } else {
                break;
            }
        }
        name
    }

    /// Parses content until EOF or a tag that belongs to an enclosing directive.
    fn content(&mut self) -> Result<(Vec<usize>, Stop), String> {
        let mut children = Vec::new();
        let mut text: Vec<char> = Vec::new();
        let mut text_begin = Pos::default();
        let mut text_end = Pos::default();
        macro_rules! flush {
            () => {
                if !text.is_empty() {
                    let id = self.t.add(Kind::Text(std::mem::take(&mut text)), text_begin, text_end);
                    children.push(id);
                }
            };
        }
        loop {
            if self.i >= self.src.len() {
                flush!();
                return Ok((children, Stop::Eof));
            }
            if self.at("${") {
                flush!();
                children.push(self.interpolation(false)?);
                continue;
            }
            if self.at("#{") {
                flush!();
                children.push(self.interpolation(true)?);
                continue;
            }
            if self.at("<#--") {
                flush!();
                children.push(self.comment()?);
                continue;
            }
            if self.at("<@") || self.at("</@") {
                return Err(format!("user-defined directives (<@...>) are not supported (line {})", self.line));
            }
            if self.at("<#") || self.at("</#") {
                let closing = self.at("</#");
                let name = self.tag_name_after(if closing { 3 } else { 2 });
                if !name.is_empty() {
                    flush!();
                    match (closing, name.as_str()) {
                        (false, "if") => children.push(self.if_block()?),
                        (false, "list") => children.push(self.list_block()?),
                        (false, "elseif") | (false, "else") | (false, "sep") => return Ok((children, Stop::Tag(name))),
                        (true, "if") | (true, "list") | (true, "sep") => return Ok((children, Stop::Tag(format!("/{name}")))),
                        (_, other) => {
                            return Err(format!("the directive #{other} is not supported (line {})", self.line));
                        }
                    }
                    continue;
                }
            }
            if text.is_empty() {
                text_begin = self.pos();
            }
            text_end = self.pos();
            if let Some(c) = self.bump() {
                text.push(c);
            }
        }
    }

    fn comment(&mut self) -> Result<usize, String> {
        let begin = self.pos();
        while self.i < self.src.len() && !self.at("-->") {
            self.bump();
        }
        if !self.at("-->") {
            return Err("unclosed comment".into());
        }
        self.bump();
        self.bump();
        let end = self.bump_end();
        Ok(self.t.add(Kind::Comment, begin, end))
    }

    /// `${...}`, or the legacy numerical `#{...}` (written in the computer format).
    fn interpolation(&mut self, numerical: bool) -> Result<usize, String> {
        let begin = self.pos();
        self.bump();
        self.bump();
        let expr = {
            let mut ep = ExprParser { p: self, in_directive: false, depth: 0 };
            let e = ep.expression()?;
            ep.skip_ws();
            e
        };
        if self.peek() != Some('}') {
            return Err(format!("expected '}}' to close the interpolation on line {}", self.line));
        }
        let end = self.bump_end();
        let expr = if numerical { Expr::BuiltIn(Box::new(expr), "c".into(), None) } else { expr };
        Ok(self.t.add(Kind::Dollar(expr), begin, end))
    }

    /// Consumes `>` ending a directive's start tag; its position.
    fn directive_end(&mut self) -> Result<Pos, String> {
        self.skip_ws();
        if self.peek() == Some('>') {
            return Ok(self.bump_end());
        }
        Err(format!("expected '>' on line {}", self.line))
    }

    /// `>` or `/>` (`#else`, `#sep`).
    fn loose_directive_end(&mut self) -> Result<Pos, String> {
        self.skip_ws();
        if self.at("/>") {
            self.bump();
            return Ok(self.bump_end());
        }
        if self.peek() == Some('>') {
            return Ok(self.bump_end());
        }
        Err(format!("expected '>' on line {}", self.line))
    }

    fn skip_ws(&mut self) {
        while self.peek().is_some_and(|c| c.is_whitespace()) {
            self.bump();
        }
    }

    /// Consumes `</#name` + optional blanks + `>`; its end position.
    fn end_tag(&mut self, name: &str) -> Result<Pos, String> {
        let tag = format!("</#{name}");
        if !self.at(&tag) {
            return Err(format!("expected </#{name}> on line {}", self.line));
        }
        for _ in 0..tag.chars().count() {
            self.bump();
        }
        self.skip_ws();
        if self.peek() != Some('>') {
            return Err(format!("expected '>' after </#{name} on line {}", self.line));
        }
        Ok(self.bump_end())
    }

    fn directive_expr(&mut self) -> Result<Expr, String> {
        let mut ep = ExprParser { p: self, in_directive: true, depth: 0 };
        ep.expression()
    }

    fn cond_location(&self, tag_begin: Pos, tag_end: Pos, children: &[usize]) -> (Pos, Pos) {
        match children.last() {
            Some(&last) => (tag_begin, self.t.nodes[last].end),
            None => (tag_begin, tag_end),
        }
    }

    fn if_block(&mut self) -> Result<usize, String> {
        let start = self.pos();
        for _ in 0.."<#if".len() {
            self.bump();
        }
        let cond = self.directive_expr()?;
        let tag_end = self.directive_end()?;
        let (children, mut stop) = self.content()?;
        let (b, e) = self.cond_location(start, tag_end, &children);
        let first = self.t.add(Kind::Cond(Some(cond)), b, e);
        self.t.set_children(first, children);
        let mut blocks = vec![first];
        loop {
            match stop {
                Stop::Tag(ref t) if t == "elseif" => {
                    let tb = self.pos();
                    for _ in 0.."<#elseif".len() {
                        self.bump();
                    }
                    let cond = self.directive_expr()?;
                    let te = self.directive_end()?;
                    let (children, s) = self.content()?;
                    let (b, e) = self.cond_location(tb, te, &children);
                    let id = self.t.add(Kind::Cond(Some(cond)), b, e);
                    self.t.set_children(id, children);
                    blocks.push(id);
                    stop = s;
                }
                Stop::Tag(ref t) if t == "else" => {
                    let tb = self.pos();
                    for _ in 0.."<#else".len() {
                        self.bump();
                    }
                    let te = self.loose_directive_end()?;
                    let (children, s) = self.content()?;
                    let (b, e) = self.cond_location(tb, te, &children);
                    let id = self.t.add(Kind::Cond(None), b, e);
                    self.t.set_children(id, children);
                    blocks.push(id);
                    stop = s;
                    if stop != Stop::Tag("/if".into()) {
                        return Err(format!("expected </#if> after #else on line {}", self.line));
                    }
                }
                Stop::Tag(ref t) if t == "/if" => {
                    let end = self.end_tag("if")?;
                    let id = self.t.add(Kind::IfBlock, start, end);
                    self.t.set_children(id, blocks);
                    return Ok(id);
                }
                _ => return Err(format!("unclosed #if starting on line {}", start.line)),
            }
        }
    }

    fn list_block(&mut self) -> Result<usize, String> {
        let start = self.pos();
        for _ in 0.."<#list".len() {
            self.bump();
        }
        let seq = self.directive_expr()?;
        self.skip_ws();
        if !self.at("as") {
            return Err(format!("only `<#list x as y>` is supported (line {})", self.line));
        }
        self.bump();
        self.bump();
        self.skip_ws();
        let mut var = String::new();
        while let Some(c) = self.peek() {
            if c.is_alphanumeric() || c == '_' || c == '$' {
                var.push(c);
                self.bump();
            } else {
                break;
            }
        }
        if var.is_empty() {
            return Err(format!("expected a loop variable name on line {}", self.line));
        }
        self.directive_end()?;
        let (mut children, mut stop) = self.content()?;
        if stop == Stop::Tag("sep".into()) {
            let sep_start = self.pos();
            for _ in 0.."<#sep".len() {
                self.bump();
            }
            let sep_tag_end = self.loose_directive_end()?;
            let (sep_children, s) = self.content()?;
            let (b, e) = match s {
                Stop::Tag(ref t) if t == "/sep" => {
                    let end = self.end_tag("sep")?;
                    (sep_start, end)
                }
                _ => self.cond_location(sep_start, sep_tag_end, &sep_children),
            };
            let sep = self.t.add(Kind::Sep, b, e);
            self.t.set_children(sep, sep_children);
            children.push(sep);
            stop = if matches!(s, Stop::Tag(ref t) if t == "/sep") { self.content().map(|(more, s2)| {
                children.extend(more);
                s2
            })? } else { s };
        }
        let mut else_body = None;
        if stop == Stop::Tag("else".into()) {
            let tb = self.pos();
            for _ in 0.."<#else".len() {
                self.bump();
            }
            let te = self.loose_directive_end()?;
            let (else_children, s) = self.content()?;
            let (b, e) = self.cond_location(tb, te, &else_children);
            let id = self.t.add(Kind::ListElseBody, b, e);
            self.t.set_children(id, else_children);
            else_body = Some(id);
            stop = s;
        }
        if stop != Stop::Tag("/list".into()) {
            return Err(format!("unclosed #list starting on line {}", start.line));
        }
        let end = self.end_tag("list")?;
        let list = self.t.add(Kind::List { seq, var }, start, end);
        self.t.set_children(list, children);
        match else_body {
            None => Ok(list),
            Some(eb) => {
                let c = self.t.add(Kind::ListElse, start, end);
                self.t.set_children(c, vec![list, eb]);
                Ok(c)
            }
        }
    }
}

pub fn parse(source: &str) -> Result<Template, String> {
    let mut p = Parser {
        src: source.chars().collect(),
        i: 0,
        line: 1,
        col: 1,
        t: Template { nodes: Vec::new(), root: 0 },
    };
    let (children, stop) = p.content()?;
    if let Stop::Tag(t) = stop {
        return Err(format!("unexpected <#{t}> on line {}", p.line));
    }
    let root = match children.len() {
        0 => p.t.add(Kind::Text(Vec::new()), Pos::default(), Pos::default()),
        1 => children[0],
        _ => {
            let begin = p.t.nodes[children[0]].begin;
            let end = p.t.nodes[*children.last().unwrap_or(&children[0])].end;
            let id = p.t.add(Kind::Mixed, begin, end);
            p.t.set_children(id, children);
            id
        }
    };
    let mut t = p.t;
    t.nodes[root].parent = None;
    let root = t.cleanup(root);
    t.root = root;
    Ok(t)
}

// =============================================================================================
// Expressions

#[derive(Debug, Clone)]
enum Expr {
    Str(String),
    Num(Num),
    Bool(bool),
    Ident(String),
    Paren(Box<Expr>),
    ListLit(Vec<Expr>),
    Dot(Box<Expr>, String),
    Key(Box<Expr>, Box<Expr>),
    BuiltIn(Box<Expr>, String, Option<Vec<Expr>>),
    Default(Box<Expr>, Option<Box<Expr>>),
    Exists(Box<Expr>),
    Not(Box<Expr>),
    Neg(Box<Expr>, bool),
    Arith(Box<Expr>, char, Box<Expr>),
    Add(Box<Expr>, Box<Expr>),
    Cmp(Box<Expr>, &'static str, Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Str(String),
    Num(String),
    Ident(String),
    Op(&'static str),
    /// `>` closing a directive, or `}` closing an interpolation.
    End,
    Eof,
}

struct ExprParser<'p> {
    p: &'p mut Parser,
    in_directive: bool,
    /// Parenthesis / bracket nesting: a `>` inside it is "greater than".
    depth: i32,
}

impl ExprParser<'_> {
    fn skip_ws(&mut self) {
        loop {
            while self.p.peek().is_some_and(|c| c.is_whitespace()) {
                self.p.bump();
            }
            // Comments inside expressions: <#-- --> and [#-- --] are rare; not handled.
            break;
        }
    }

    /// Reads the next token without consuming it (returns it and its char length).
    fn peek_tok(&mut self) -> Result<(Tok, usize), String> {
        self.skip_ws();
        let s = &self.p.src[self.p.i..];
        let starts = |pat: &str| {
            let pc: Vec<char> = pat.chars().collect();
            s.len() >= pc.len() && s[..pc.len()] == pc[..]
        };
        let Some(&c) = s.first() else { return Ok((Tok::Eof, 0)) };
        if c == '"' || c == '\'' {
            let mut j = 1;
            let mut out = String::new();
            while j < s.len() && s[j] != c {
                if s[j] == '\\' && j + 1 < s.len() {
                    j += 1;
                    match s[j] {
                        'n' => out.push('\n'),
                        't' => out.push('\t'),
                        'r' => out.push('\r'),
                        'b' => out.push('\u{8}'),
                        'f' => out.push('\u{c}'),
                        'l' => out.push('<'),
                        'g' => out.push('>'),
                        'a' => out.push('&'),
                        'x' => {
                            let mut hex = String::new();
                            while hex.len() < 4 && j + 1 < s.len() && s[j + 1].is_ascii_hexdigit() {
                                j += 1;
                                hex.push(s[j]);
                            }
                            out.push(char::from_u32(u32::from_str_radix(&hex, 16).unwrap_or(0)).unwrap_or('\u{fffd}'));
                        }
                        other => out.push(other),
                    }
                } else {
                    if s[j] == '$' && s.get(j + 1) == Some(&'{') {
                        return Err("interpolation inside string literals is not supported".into());
                    }
                    out.push(s[j]);
                }
                j += 1;
            }
            if j >= s.len() {
                return Err("unterminated string literal".into());
            }
            return Ok((Tok::Str(out), j + 1));
        }
        if c == 'r' && matches!(s.get(1), Some('"') | Some('\'')) {
            let q = s[1];
            let mut j = 2;
            while j < s.len() && s[j] != q {
                j += 1;
            }
            if j >= s.len() {
                return Err("unterminated raw string literal".into());
            }
            return Ok((Tok::Str(s[2..j].iter().collect()), j + 1));
        }
        if c.is_ascii_digit() {
            let mut j = 0;
            while j < s.len() && s[j].is_ascii_digit() {
                j += 1;
            }
            if j + 1 < s.len() && s[j] == '.' && s[j + 1].is_ascii_digit() {
                j += 1;
                while j < s.len() && s[j].is_ascii_digit() {
                    j += 1;
                }
            }
            return Ok((Tok::Num(s[..j].iter().collect()), j));
        }
        if c.is_alphabetic() || c == '_' || c == '$' || c == '@' {
            let mut j = 0;
            while j < s.len() && (s[j].is_alphanumeric() || s[j] == '_' || s[j] == '$' || s[j] == '@') {
                j += 1;
            }
            let word: String = s[..j].iter().collect();
            return Ok((
                match word.as_str() {
                    "gt" => Tok::Op(">"),
                    "gte" => Tok::Op(">="),
                    "lt" => Tok::Op("<"),
                    "lte" => Tok::Op("<="),
                    _ => Tok::Ident(word),
                },
                j,
            ));
        }
        for (pat, op) in [
            ("&amp;&amp;", "&&"),
            ("&gt;=", ">="),
            ("&lt;=", "<="),
            ("&gt;", ">"),
            ("&lt;", "<"),
            ("&&", "&&"),
            ("||", "||"),
            ("==", "=="),
            ("!=", "!="),
            ("<=", "<="),
            ("??", "??"),
            ("..", ".."),
        ] {
            if starts(pat) {
                return Ok((Tok::Op(op), pat.chars().count()));
            }
        }
        if c == '>' {
            if self.in_directive && self.depth == 0 {
                return Ok((Tok::End, 0));
            }
            if starts(">=") {
                return Ok((Tok::Op(">="), 2));
            }
            return Ok((Tok::Op(">"), 1));
        }
        if c == '/' && s.get(1) == Some(&'>') && self.in_directive && self.depth == 0 {
            return Ok((Tok::End, 0));
        }
        if c == '}' && !self.in_directive && self.depth == 0 {
            return Ok((Tok::End, 0));
        }
        let op = match c {
            '=' => "=",
            '<' => "<",
            '!' => "!",
            '?' => "?",
            '+' => "+",
            '-' => "-",
            '*' => "*",
            '/' => "/",
            '%' => "%",
            '(' => "(",
            ')' => ")",
            '[' => "[",
            ']' => "]",
            ',' => ",",
            '.' => ".",
            '{' => "{",
            '}' => "}",
            ':' => ":",
            other => return Err(format!("unexpected character '{other}' in an expression on line {}", self.p.line)),
        };
        Ok((Tok::Op(op), 1))
    }

    fn next_tok(&mut self) -> Result<Tok, String> {
        let (t, n) = self.peek_tok()?;
        for _ in 0..n {
            self.p.bump();
        }
        if let Tok::Op(o) = t {
            match o {
                "(" | "[" => self.depth += 1,
                ")" | "]" => self.depth -= 1,
                _ => {}
            }
        }
        Ok(t)
    }

    fn expect(&mut self, op: &'static str) -> Result<(), String> {
        match self.next_tok()? {
            Tok::Op(o) if o == op => Ok(()),
            other => Err(format!("expected '{op}' but found {other:?} on line {}", self.p.line)),
        }
    }

    fn peek_op(&mut self) -> Result<Option<&'static str>, String> {
        Ok(match self.peek_tok()?.0 {
            Tok::Op(o) => Some(o),
            _ => None,
        })
    }

    fn expression(&mut self) -> Result<Expr, String> {
        let mut lhs = self.and_expr()?;
        while self.peek_op()? == Some("||") {
            self.next_tok()?;
            let rhs = self.and_expr()?;
            lhs = Expr::Or(Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn and_expr(&mut self) -> Result<Expr, String> {
        let mut lhs = self.equality()?;
        while self.peek_op()? == Some("&&") {
            self.next_tok()?;
            let rhs = self.equality()?;
            lhs = Expr::And(Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn equality(&mut self) -> Result<Expr, String> {
        let lhs = self.relational()?;
        if let Some(op) = self.peek_op()? {
            if matches!(op, "==" | "=" | "!=") {
                self.next_tok()?;
                let rhs = self.relational()?;
                let op = if op == "!=" { "!=" } else { "==" };
                return Ok(Expr::Cmp(Box::new(lhs), op, Box::new(rhs)));
            }
        }
        Ok(lhs)
    }

    fn relational(&mut self) -> Result<Expr, String> {
        let lhs = self.range()?;
        if let Some(op) = self.peek_op()? {
            if matches!(op, "<" | "<=" | ">" | ">=") {
                self.next_tok()?;
                let rhs = self.range()?;
                return Ok(Expr::Cmp(Box::new(lhs), op, Box::new(rhs)));
            }
        }
        Ok(lhs)
    }

    fn range(&mut self) -> Result<Expr, String> {
        let lhs = self.additive()?;
        if self.peek_op()? == Some("..") {
            return Err("ranges are not supported".into());
        }
        Ok(lhs)
    }

    fn additive(&mut self) -> Result<Expr, String> {
        let mut lhs = self.multiplicative()?;
        loop {
            match self.peek_op()? {
                Some("+") => {
                    self.next_tok()?;
                    let rhs = self.multiplicative()?;
                    lhs = Expr::Add(Box::new(lhs), Box::new(rhs));
                }
                Some("-") => {
                    self.next_tok()?;
                    let rhs = self.multiplicative()?;
                    lhs = Expr::Arith(Box::new(lhs), '-', Box::new(rhs));
                }
                _ => return Ok(lhs),
            }
        }
    }

    fn multiplicative(&mut self) -> Result<Expr, String> {
        let mut lhs = self.unary()?;
        loop {
            let op = match self.peek_op()? {
                Some("*") => '*',
                Some("/") => '/',
                Some("%") => '%',
                _ => return Ok(lhs),
            };
            self.next_tok()?;
            let rhs = self.unary()?;
            lhs = Expr::Arith(Box::new(lhs), op, Box::new(rhs));
        }
    }

    fn unary(&mut self) -> Result<Expr, String> {
        match self.peek_op()? {
            Some("!") => {
                let mut nots = 0;
                while self.peek_op()? == Some("!") {
                    self.next_tok()?;
                    nots += 1;
                }
                let mut e = self.primary()?;
                for _ in 0..nots {
                    e = Expr::Not(Box::new(e));
                }
                Ok(e)
            }
            Some("-") | Some("+") => {
                let minus = self.next_tok()? == Tok::Op("-");
                let e = self.primary()?;
                Ok(Expr::Neg(Box::new(e), minus))
            }
            _ => self.primary(),
        }
    }

    /// Whether the next token can start an expression (`DefaultTo`'s lookahead for a right side).
    fn starts_expression(&mut self) -> Result<bool, String> {
        Ok(match self.peek_tok()?.0 {
            Tok::Str(_) | Tok::Num(_) | Tok::Ident(_) => true,
            Tok::Op(o) => matches!(o, "(" | "[" | "{" | "!" | "+" | "-"),
            _ => false,
        })
    }

    fn primary(&mut self) -> Result<Expr, String> {
        let mut e = self.atomic()?;
        loop {
            match self.peek_op()? {
                Some(".") => {
                    self.next_tok()?;
                    match self.next_tok()? {
                        Tok::Ident(name) => e = Expr::Dot(Box::new(e), name),
                        other => return Err(format!("expected a name after '.', found {other:?}")),
                    }
                }
                Some("[") => {
                    self.next_tok()?;
                    let key = self.expression()?;
                    self.expect("]")?;
                    e = Expr::Key(Box::new(e), Box::new(key));
                }
                Some("?") => {
                    self.next_tok()?;
                    let name = match self.next_tok()? {
                        Tok::Ident(n) => n,
                        other => return Err(format!("expected a built-in name after '?', found {other:?}")),
                    };
                    let args = if self.peek_op()? == Some("(") {
                        self.next_tok()?;
                        let mut args = Vec::new();
                        if self.peek_op()? != Some(")") {
                            loop {
                                args.push(self.expression()?);
                                if self.peek_op()? == Some(",") {
                                    self.next_tok()?;
                                    continue;
                                }
                                break;
                            }
                        }
                        self.expect(")")?;
                        Some(args)
                    } else {
                        None
                    };
                    e = Expr::BuiltIn(Box::new(e), name, args);
                }
                Some("??") => {
                    self.next_tok()?;
                    e = Expr::Exists(Box::new(e));
                }
                Some("!") => {
                    self.next_tok()?;
                    let rhs = if self.starts_expression()? { Some(Box::new(self.expression()?)) } else { None };
                    e = Expr::Default(Box::new(e), rhs);
                }
                Some("(") => return Err("method calls are not supported".into()),
                _ => return Ok(e),
            }
        }
    }

    fn atomic(&mut self) -> Result<Expr, String> {
        match self.next_tok()? {
            Tok::Str(s) => Ok(Expr::Str(s)),
            Tok::Num(n) => Ok(Expr::Num(Num::Dec(Dec::parse(&n).ok_or("bad number literal")?))),
            Tok::Ident(w) if w == "true" => Ok(Expr::Bool(true)),
            Tok::Ident(w) if w == "false" => Ok(Expr::Bool(false)),
            Tok::Ident(w) => Ok(Expr::Ident(w)),
            Tok::Op("(") => {
                let e = self.expression()?;
                self.expect(")")?;
                Ok(Expr::Paren(Box::new(e)))
            }
            Tok::Op("[") => {
                let mut items = Vec::new();
                if self.peek_op()? != Some("]") {
                    loop {
                        items.push(self.expression()?);
                        if self.peek_op()? == Some(",") {
                            self.next_tok()?;
                            continue;
                        }
                        break;
                    }
                }
                self.expect("]")?;
                Ok(Expr::ListLit(items))
            }
            other => Err(format!("unexpected {other:?} in an expression on line {}", self.p.line)),
        }
    }
}

// =============================================================================================
// Numbers

/// A `BigDecimal`: `m * 10^-s`.
#[derive(Debug, Clone, Copy)]
struct Dec {
    m: i128,
    s: u32,
}

fn pow10(n: u32) -> Option<i128> {
    10i128.checked_pow(n)
}

impl Dec {
    fn from_i64(v: i64) -> Self {
        Dec { m: v as i128, s: 0 }
    }

    /// `new BigDecimal(String)`.
    fn parse(text: &str) -> Option<Dec> {
        let t = text.trim_start_matches('+');
        let (neg, t) = match t.strip_prefix('-') {
            Some(r) => (true, r),
            None => (false, t),
        };
        let (mant, exp) = match t.find(['e', 'E']) {
            Some(i) => (&t[..i], t[i + 1..].trim_start_matches('+').parse::<i32>().ok()?),
            None => (t, 0),
        };
        let (int, frac) = match mant.split_once('.') {
            Some((a, b)) => (a, b),
            None => (mant, ""),
        };
        if int.is_empty() && frac.is_empty() {
            return None;
        }
        if !int.chars().chain(frac.chars()).all(|c| c.is_ascii_digit()) {
            return None;
        }
        let digits = format!("{int}{frac}");
        let mut m: i128 = if digits.is_empty() { 0 } else { digits.parse().ok()? };
        let mut s = frac.len() as i64 - exp as i64;
        if s < 0 {
            m = m.checked_mul(pow10((-s) as u32)?)?;
            s = 0;
        }
        Some(Dec { m: if neg { -m } else { m }, s: s as u32 })
    }

    /// `new BigDecimal(Double.toString(d))`.
    fn from_f64(d: f64) -> Option<Dec> {
        Dec::parse(&format!("{d:e}"))
    }

    fn align(a: Dec, b: Dec) -> Option<(i128, i128, u32)> {
        let s = a.s.max(b.s);
        Some((a.m.checked_mul(pow10(s - a.s)?)?, b.m.checked_mul(pow10(s - b.s)?)?, s))
    }

    fn cmp(a: Dec, b: Dec) -> Option<Ordering> {
        let (x, y, _) = Dec::align(a, b)?;
        Some(x.cmp(&y))
    }

    fn add(a: Dec, b: Dec) -> Option<Dec> {
        let (x, y, s) = Dec::align(a, b)?;
        Some(Dec { m: x.checked_add(y)?, s })
    }

    fn sub(a: Dec, b: Dec) -> Option<Dec> {
        let (x, y, s) = Dec::align(a, b)?;
        Some(Dec { m: x.checked_sub(y)?, s })
    }

    fn mul(a: Dec, b: Dec) -> Option<Dec> {
        let mut r = Dec { m: a.m.checked_mul(b.m)?, s: a.s + b.s };
        if r.s > 100 {
            r = r.rescale_half_up(100)?;
        }
        Some(r)
    }

    /// `left.divide(right, max(scale1, scale2, 12), HALF_UP)`.
    fn div(a: Dec, b: Dec) -> Option<Dec> {
        if b.m == 0 {
            return None;
        }
        let scale = a.s.max(b.s).max(12);
        // a / b = (a.m / 10^a.s) / (b.m / 10^b.s); result.m = a.m * 10^(scale - a.s + b.s) / b.m
        let num = a.m.checked_mul(pow10(scale - a.s + b.s)?)?;
        let q = num / b.m;
        let r = num % b.m;
        let mut m = q;
        if r != 0 && (r.unsigned_abs() * 2) >= b.m.unsigned_abs() {
            m += if (num < 0) != (b.m < 0) { -1 } else { 1 };
        }
        Some(Dec { m, s: scale })
    }

    fn rescale_half_up(self, s: u32) -> Option<Dec> {
        if s >= self.s {
            return Some(Dec { m: self.m.checked_mul(pow10(s - self.s)?)?, s });
        }
        let d = pow10(self.s - s)?;
        let q = self.m / d;
        let r = self.m % d;
        let m = if r.unsigned_abs() * 2 >= d.unsigned_abs() { q + self.m.signum() } else { q };
        Some(Dec { m, s })
    }

    fn signum(self) -> i32 {
        self.m.signum() as i32
    }

    fn to_i64(self) -> i64 {
        let d = 10i128.pow(self.s.min(38));
        (self.m / d) as i64
    }

    /// Decimal digits (no sign) and the position of the decimal point within them.
    fn digits(self) -> (bool, String, i64) {
        let neg = self.m < 0;
        let ds = self.m.unsigned_abs().to_string();
        (neg, ds.clone(), ds.len() as i64 - self.s as i64)
    }
}

#[derive(Debug, Clone, Copy)]
enum Num {
    Int(i64),
    Double(f64),
    Dec(Dec),
}

impl Num {
    fn dec(self) -> Option<Dec> {
        match self {
            Num::Int(i) => Some(Dec::from_i64(i)),
            Num::Double(d) => Dec::from_f64(d),
            Num::Dec(d) => Some(d),
        }
    }

    fn signum(self) -> i32 {
        match self {
            Num::Int(i) => i.signum() as i32,
            Num::Double(d) => {
                if d > 0.0 {
                    1
                } else if d < 0.0 {
                    -1
                } else {
                    0
                }
            }
            Num::Dec(d) => d.signum(),
        }
    }

    /// `BigDecimalEngine.compareNumbers`.
    fn compare(a: Num, b: Num) -> Result<Ordering, String> {
        let (sa, sb) = (a.signum(), b.signum());
        if sa != sb {
            return Ok(sa.cmp(&sb));
        }
        if sa == 0 {
            return Ok(Ordering::Equal);
        }
        match (a, b) {
            (Num::Int(x), Num::Int(y)) => Ok(x.cmp(&y)),
            (Num::Double(x), Num::Double(y)) => Ok(x.partial_cmp(&y).unwrap_or(Ordering::Equal)),
            _ => {
                let (x, y) = (a.dec().ok_or("not a finite number")?, b.dec().ok_or("not a finite number")?);
                Dec::cmp(x, y).ok_or_else(|| "number too large".to_string())
            }
        }
    }

    fn arith(a: Num, op: char, b: Num) -> Result<Num, String> {
        if op == '%' {
            let (l, r) = (a.long_value(), b.long_value());
            if r == 0 {
                return Err("division by zero".into());
            }
            return Ok(Num::Int(l % r));
        }
        let (x, y) = (a.dec().ok_or("not a finite number")?, b.dec().ok_or("not a finite number")?);
        let r = match op {
            '+' => Dec::add(x, y),
            '-' => Dec::sub(x, y),
            '*' => Dec::mul(x, y),
            '/' => {
                if y.m == 0 {
                    return Err("division by zero".into());
                }
                Dec::div(x, y)
            }
            _ => None,
        };
        r.map(Num::Dec).ok_or_else(|| "arithmetic overflow".to_string())
    }

    fn long_value(self) -> i64 {
        match self {
            Num::Int(i) => i,
            Num::Double(d) => d as i64,
            Num::Dec(d) => d.to_i64(),
        }
    }
}

/// A Java `DecimalFormat` (the subset the templates use) with `HALF_EVEN` rounding.
#[derive(Debug, Clone)]
struct NumberFormat {
    prefix: String,
    suffix: String,
    /// The negative subpattern's prefix and suffix, when the pattern has one.
    negative: Option<(String, String)>,
    min_int: usize,
    min_frac: usize,
    max_frac: usize,
    grouping: Option<usize>,
    percent: bool,
    half_up: bool,
}

impl NumberFormat {
    fn number() -> Self {
        NumberFormat {
            prefix: String::new(),
            suffix: String::new(),
            negative: None,
            min_int: 1,
            min_frac: 0,
            max_frac: 3,
            grouping: Some(3),
            percent: false,
            half_up: false,
        }
    }

    /// A Java `DecimalFormat` pattern, with FreeMarker's `;;` options (`roundingMode`).
    fn parse(pattern: &str) -> Result<Self, String> {
        let (patterns, options) = match pattern.split_once(";;") {
            Some((a, b)) => (a, Some(b)),
            None => (pattern, None),
        };
        let mut half_up = false;
        for opt in options.unwrap_or("").split([' ', ',']).filter(|o| !o.is_empty()) {
            match opt.split_once('=') {
                Some(("roundingMode", "halfUp")) => half_up = true,
                Some(("roundingMode", "halfEven")) => half_up = false,
                _ => return Err(format!("unsupported number format option {opt}")),
            }
        }
        let (main, negative) = match patterns.split_once(';') {
            Some((a, b)) => (a, Some(b)),
            None => (patterns, None),
        };
        let (prefix, body, suffix) = split_affixes(main);
        if body.is_empty() || main.contains('E') {
            return Err(format!("unsupported number format \"{pattern}\""));
        }
        let int_part = body.split('.').next().unwrap_or("").to_string();
        // DecimalFormat.applyPattern's digit counts.
        let (mut left, mut zeros, mut right) = (0usize, 0usize, 0usize);
        let mut decimal_pos: Option<usize> = None;
        for c in body.chars() {
            match c {
                '#' if zeros > 0 => right += 1,
                '#' => left += 1,
                '0' if right > 0 => return Err(format!("Unexpected '0' in pattern \"{pattern}\"")),
                '0' => zeros += 1,
                '.' => decimal_pos = Some(left + zeros + right),
                _ => {}
            }
        }
        if zeros == 0 && left > 0 {
            if let Some(dp) = decimal_pos {
                // "#.##" reads as "0.##", ".##" as ".0#".
                let n = if dp == 0 { 1 } else { dp };
                right = left - n;
                left = n - 1;
                zeros = 1;
            }
        }
        let total = left + zeros + right;
        let effective = decimal_pos.unwrap_or(total);
        let min_int = effective - left;
        let max_frac = decimal_pos.map(|dp| total - dp).unwrap_or(0);
        let min_frac = decimal_pos.map(|dp| (left + zeros).saturating_sub(dp)).unwrap_or(0);
        // DecimalFormat keeps one grouping size: the digits after the last ','.
        let grouping = int_part.rfind(',').map(|last| int_part[last + 1..].chars().filter(|c| *c == '#' || *c == '0').count());
        let percent = prefix.contains('%') || suffix.contains('%');
        let negative = negative.map(|n| {
            let (p, _, s) = split_affixes(n);
            (p, s)
        });
        Ok(NumberFormat {
            prefix,
            suffix,
            negative,
            min_int,
            min_frac,
            max_frac,
            grouping: grouping.filter(|p| *p > 0),
            percent,
            half_up,
        })
    }

    fn format(&self, n: Num) -> String {
        let (neg, digits, point, exact_tie) = match n {
            Num::Int(i) => {
                let (neg, d, p) = Dec::from_i64(i).digits();
                (neg, d, p, None)
            }
            Num::Dec(d) => {
                let (neg, d, p) = d.digits();
                (neg, d, p, None)
            }
            Num::Double(d) => {
                if d.is_nan() {
                    return "NaN".into();
                }
                if d.is_infinite() {
                    return if d > 0.0 { "∞".into() } else { "-∞".into() };
                }
                let dec = Dec::from_f64(d).unwrap_or(Dec { m: 0, s: 0 });
                let (_, ds, p) = dec.digits();
                (d.is_sign_negative(), ds, p, Some(d))
            }
        };
        let (mut digits, mut point) = (digits, point);
        if self.percent {
            point += 2;
        }
        // Round to max_frac fraction digits.
        let keep = point + self.max_frac as i64;
        let mut int_digits: Vec<u8>;
        if keep < digits.len() as i64 {
            let keep_u = keep.max(0) as usize;
            let (head, tail) = if keep < 0 { ("", digits.as_str()) } else { digits.split_at(keep_u) };
            let first_dropped = if keep < 0 { 0 } else { tail.as_bytes()[0] - b'0' };
            let rest_nonzero = if keep < 0 { tail.bytes().any(|b| b != b'0') } else { tail[1..].bytes().any(|b| b != b'0') };
            let mut kept: Vec<u8> = head.bytes().map(|b| b - b'0').collect();
            let last_kept_odd = kept.last().is_some_and(|d| d % 2 == 1);
            let round_up = if keep < 0 {
                false
            } else if first_dropped > 5 || (first_dropped == 5 && rest_nonzero) {
                true
            } else if first_dropped == 5 {
                // A tie in these digits. A double's exact value decides it.
                match exact_tie.and_then(|d| exact_vs_tie(d, &digits, point, keep_u)) {
                    Some(Ordering::Greater) => true,
                    Some(Ordering::Less) => false,
                    _ => self.half_up || last_kept_odd,
                }
            } else {
                false
            };
            if round_up {
                let mut i = kept.len();
                loop {
                    if i == 0 {
                        kept.insert(0, 1);
                        point += 1;
                        break;
                    }
                    i -= 1;
                    if kept[i] == 9 {
                        kept[i] = 0;
                    } else {
                        kept[i] += 1;
                        break;
                    }
                }
            }
            int_digits = kept;
            digits = int_digits.iter().map(|d| (d + b'0') as char).collect();
        }
        int_digits = digits.bytes().map(|b| b - b'0').collect();
        // Split into integer and fraction digits.
        let mut int_part: Vec<u8> = Vec::new();
        let mut frac_part: Vec<u8> = Vec::new();
        for (i, d) in int_digits.iter().enumerate() {
            if (i as i64) < point {
                int_part.push(*d);
            } else {
                frac_part.push(*d);
            }
        }
        if point < 0 {
            let mut f = vec![0u8; (-point) as usize];
            f.extend(frac_part);
            frac_part = f;
        } else if (int_part.len() as i64) < point {
            int_part.extend(std::iter::repeat_n(0, (point - int_part.len() as i64) as usize));
        }
        while frac_part.len() > self.min_frac && frac_part.last() == Some(&0) {
            frac_part.pop();
        }
        while frac_part.len() < self.min_frac {
            frac_part.push(0);
        }
        while int_part.len() > 1 && int_part[0] == 0 {
            int_part.remove(0);
        }
        if int_part == [0] && self.min_int == 0 {
            int_part.clear();
        }
        while int_part.len() < self.min_int {
            int_part.insert(0, 0);
        }
        // A negative value that rounds to zero still prints its sign ("-0"), as DecimalFormat.
        let mut out = String::new();
        let suffix = match (&self.negative, neg) {
            (Some((p, s)), true) => {
                out.push_str(p);
                s.clone()
            }
            (None, true) => {
                out.push('-');
                out.push_str(&self.prefix);
                self.suffix.clone()
            }
            _ => {
                out.push_str(&self.prefix);
                self.suffix.clone()
            }
        };
        let int_str: String = int_part.iter().map(|d| (d + b'0') as char).collect();
        match self.grouping {
            Some(size) if int_str.len() > size => {
                let first = int_str.len() % size;
                let mut groups: Vec<&str> = Vec::new();
                if first > 0 {
                    groups.push(&int_str[..first]);
                }
                let mut i = first;
                while i < int_str.len() {
                    groups.push(&int_str[i..i + size]);
                    i += size;
                }
                out.push_str(&groups.join(","));
            }
            _ => out.push_str(&int_str),
        }
        if int_str.is_empty() && frac_part.is_empty() {
            out.push('0');
        }
        if !frac_part.is_empty() {
            out.push('.');
            for d in frac_part {
                out.push((d + b'0') as char);
            }
        }
        out.push_str(&suffix);
        out
    }
}

/// A subpattern's literal prefix (quotes removed), its digit pattern, and its literal suffix.
fn split_affixes(pattern: &str) -> (String, String, String) {
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    let prefix = affix(&chars, &mut i, true);
    let start = i;
    while i < chars.len() && matches!(chars[i], '#' | '0' | ',' | '.') {
        i += 1;
    }
    let body: String = chars[start..i].iter().collect();
    let suffix = affix(&chars, &mut i, false);
    (prefix, body, suffix)
}

/// Literal text of a pattern from `i`: quoted runs as written, `''` as one quote. A prefix
/// stops at the first digit pattern character outside quotes.
fn affix(chars: &[char], i: &mut usize, stop_at_digits: bool) -> String {
    let mut out = String::new();
    let mut quoted = false;
    while *i < chars.len() {
        let c = chars[*i];
        if c == '\'' {
            if chars.get(*i + 1) == Some(&'\'') {
                out.push('\'');
                *i += 2;
                continue;
            }
            quoted = !quoted;
            *i += 1;
            continue;
        }
        if !quoted && stop_at_digits && matches!(c, '#' | '0' | ',' | '.') {
            break;
        }
        out.push(c);
        *i += 1;
    }
    out
}

/// How a double's exact binary value compares with the tie that its shortest digits show at
/// `keep` (Java's `DecimalFormat` decides a `HALF_EVEN` tie on the exact value).
fn exact_vs_tie(d: f64, digits: &str, point: i64, keep: usize) -> Option<Ordering> {
    let d = d.abs();
    // The tie value as a decimal: digits[..keep] then 5, times 10^(point - keep - 1).
    let tie_digits = format!("{}5", &digits[..keep]);
    let tie: u128 = tie_digits.parse().ok()?;
    let e10 = point - keep as i64 - 1;
    let bits = d.to_bits();
    let exp = ((bits >> 52) & 0x7ff) as i64;
    let mant = if exp == 0 { (bits & ((1 << 52) - 1)) << 1 } else { (bits & ((1 << 52) - 1)) | (1 << 52) } as u128;
    let e2 = if exp == 0 { -1074 } else { exp - 1075 };
    // Compare mant * 2^e2 with tie * 10^e10.
    let (mut lhs, mut rhs) = (mant, tie);
    if e2 >= 0 {
        lhs = lhs.checked_mul(1u128.checked_shl(e2 as u32)?)?;
    } else {
        rhs = rhs.checked_mul(1u128.checked_shl((-e2) as u32)?)?;
    }
    if e10 >= 0 {
        rhs = rhs.checked_mul(10u128.checked_pow(e10 as u32)?)?;
    } else {
        lhs = lhs.checked_mul(10u128.checked_pow((-e10) as u32)?)?;
    }
    Some(lhs.cmp(&rhs))
}

// =============================================================================================
// Evaluation

#[derive(Debug, Clone)]
enum Val<'a> {
    Str(String),
    Num(Num),
    Bool(bool),
    Seq(Vec<Val<'a>>),
    Hash(&'a Map<String, Value>),
    /// The value of `x!` with no default: an empty string, sequence and hash at once.
    Empty,
}

impl<'a> Val<'a> {
    fn from_json(v: &'a Value) -> Option<Val<'a>> {
        Some(match v {
            Value::Null => return None,
            Value::Bool(b) => Val::Bool(*b),
            Value::Number(n) => Val::Num(match n.as_i64() {
                Some(i) => Num::Int(i),
                None => Num::Double(n.as_f64().unwrap_or(0.0)),
            }),
            Value::String(s) => Val::Str(s.clone()),
            Value::Array(a) => Val::Seq(a.iter().map(|x| Val::from_json(x).unwrap_or(Val::Empty)).collect()),
            Value::Object(m) => Val::Hash(m),
        })
    }

    fn type_name(&self) -> &'static str {
        match self {
            Val::Str(_) => "string",
            Val::Num(_) => "number",
            Val::Bool(_) => "boolean",
            Val::Seq(_) => "sequence",
            Val::Hash(_) => "hash",
            Val::Empty => "string",
        }
    }
}

struct LoopVar<'a> {
    name: String,
    value: Option<Val<'a>>,
    index: usize,
    len: usize,
}

struct Env<'a> {
    data: &'a Map<String, Value>,
    loops: Vec<LoopVar<'a>>,
    /// `IGNORE_HANDLER`: a failing element is skipped rather than failing the template.
    lenient: bool,
}

type R<T> = Result<T, String>;

fn missing(e: &Expr) -> String {
    format!("The following has evaluated to null or missing: {}", describe(e))
}

fn describe(e: &Expr) -> String {
    match e {
        Expr::Ident(n) => n.clone(),
        Expr::Dot(t, n) => format!("{}.{n}", describe(t)),
        Expr::Paren(i) => format!("({})", describe(i)),
        Expr::BuiltIn(t, n, _) => format!("{}?{n}", describe(t)),
        Expr::Key(t, _) => format!("{}[...]", describe(t)),
        _ => "an expression".into(),
    }
}

impl<'a> Env<'a> {
    fn render(&mut self, t: &Template, id: usize, out: &mut String) -> R<()> {
        if self.lenient {
            // FreeMarker visits each element under the handler: a failure ends that element
            // only.
            let _ = self.render_node(t, id, out);
            return Ok(());
        }
        self.render_node(t, id, out)
    }

    fn render_node(&mut self, t: &Template, id: usize, out: &mut String) -> R<()> {
        let node = &t.nodes[id];
        match &node.kind {
            Kind::Text(text) => out.extend(text.iter()),
            Kind::Comment => {}
            Kind::Mixed | Kind::Sep | Kind::ListElseBody | Kind::Cond(None) => {
                for &c in &node.children {
                    self.render(t, c, out)?;
                }
            }
            // An #if with no #elseif / #else: the cleanup put the conditional block in its place.
            Kind::Cond(Some(e)) => {
                if self.eval_bool(e)? {
                    for &c in &node.children {
                        self.render(t, c, out)?;
                    }
                }
            }
            Kind::Dollar(e) => {
                let v = self.eval(e)?.ok_or_else(|| missing(e))?;
                out.push_str(&self.to_text(&v, e)?);
            }
            Kind::IfBlock => {
                for &c in &node.children {
                    let Kind::Cond(cond) = &t.nodes[c].kind else { continue };
                    let take = match cond {
                        None => true,
                        Some(e) => self.eval_bool(e)?,
                    };
                    if take {
                        for &child in &t.nodes[c].children {
                            self.render(t, child, out)?;
                        }
                        return Ok(());
                    }
                }
            }
            Kind::ListElse => {
                let list = node.children[0];
                if !self.render_list(t, list, out)? {
                    if let Some(&eb) = node.children.get(1) {
                        self.render(t, eb, out)?;
                    }
                }
            }
            Kind::List { .. } => {
                self.render_list(t, id, out)?;
            }
        }
        Ok(())
    }

    /// Renders a `#list`; false when the sequence was empty.
    fn render_list(&mut self, t: &Template, id: usize, out: &mut String) -> R<bool> {
        let Kind::List { seq, var } = &t.nodes[id].kind else { return Ok(false) };
        let v = self.eval(seq)?.ok_or_else(|| missing(seq))?;
        let items: Vec<Option<Val<'a>>> = match v {
            Val::Seq(items) => items.into_iter().map(|i| if matches!(i, Val::Empty) { None } else { Some(i) }).collect(),
            Val::Empty => Vec::new(),
            Val::Hash(_) => return Err("listing a hash needs `as k, v`, which is not supported".into()),
            other => return Err(format!("Expected a sequence, but this has evaluated to a {}", other.type_name())),
        };
        let len = items.len();
        for (index, value) in items.into_iter().enumerate() {
            self.loops.push(LoopVar { name: var.clone(), value, index, len });
            for &c in &t.nodes[id].children {
                if matches!(t.nodes[c].kind, Kind::Sep) && index + 1 >= len {
                    continue;
                }
                let r = self.render(t, c, out);
                if r.is_err() {
                    self.loops.pop();
                    return r.map(|_| false);
                }
            }
            self.loops.pop();
        }
        Ok(len > 0)
    }

    fn lookup(&self, name: &str) -> Option<Val<'a>> {
        for l in self.loops.iter().rev() {
            if l.name == name {
                return l.value.clone();
            }
            // The legacy `x_index` / `x_has_next` loop variables.
            if let Some(base) = name.strip_suffix("_index") {
                if base == l.name {
                    return Some(Val::Num(Num::Int(l.index as i64)));
                }
            }
            if let Some(base) = name.strip_suffix("_has_next") {
                if base == l.name {
                    return Some(Val::Bool(l.index + 1 < l.len));
                }
            }
        }
        self.data.get(name).and_then(Val::from_json)
    }

    fn loop_var(&self, e: &Expr) -> R<&LoopVar<'a>> {
        if let Expr::Ident(name) = e {
            if let Some(l) = self.loops.iter().rev().find(|l| &l.name == name) {
                return Ok(l);
            }
        }
        Err(format!("{} is not a loop variable", describe(e)))
    }

    fn eval_bool(&mut self, e: &Expr) -> R<bool> {
        match self.eval(e)? {
            Some(Val::Bool(b)) => Ok(b),
            Some(other) => Err(format!("Expected a boolean, but this has evaluated to a {}: {}", other.type_name(), describe(e))),
            None => Err(missing(e)),
        }
    }

    fn number_format(&self) -> NumberFormat {
        NumberFormat::number()
    }

    /// What `${...}` writes, and what string built-ins and `+` turn a value into.
    fn to_text(&self, v: &Val<'a>, e: &Expr) -> R<String> {
        match v {
            Val::Str(s) => Ok(s.clone()),
            Val::Num(n) => Ok(self.number_format().format(*n)),
            Val::Empty => Ok(String::new()),
            Val::Bool(_) => Err(format!(
                "Can't convert boolean to string automatically, because the \"boolean_format\" setting was \"true,false\": {}",
                describe(e)
            )),
            other => Err(format!("Expected a string or something automatically convertible to string, but this has evaluated to a {}: {}", other.type_name(), describe(e))),
        }
    }

    /// Evaluates allowing a missing value at any depth, as FreeMarker does for a parenthesised
    /// operand of `!`, `??` and `?has_content`.
    fn eval_maybe_missing(&mut self, target: &Expr) -> R<Option<Val<'a>>> {
        match target {
            Expr::Paren(inner) => Ok(self.eval(inner).unwrap_or(None)),
            other => self.eval(other),
        }
    }

    fn eval(&mut self, e: &Expr) -> R<Option<Val<'a>>> {
        Ok(Some(match e {
            Expr::Str(s) => Val::Str(s.clone()),
            Expr::Num(n) => Val::Num(*n),
            Expr::Bool(b) => Val::Bool(*b),
            Expr::Ident(name) => return Ok(self.lookup(name)),
            Expr::Paren(inner) => return self.eval(inner),
            Expr::ListLit(items) => {
                let mut out = Vec::new();
                for i in items {
                    out.push(self.eval(i)?.ok_or_else(|| missing(i))?);
                }
                Val::Seq(out)
            }
            Expr::Dot(target, key) => match self.eval(target)? {
                Some(Val::Hash(m)) => return Ok(m.get(key).and_then(Val::from_json)),
                Some(Val::Empty) => return Ok(None),
                Some(other) => return Err(format!("Expected a hash, but this has evaluated to a {}: {}", other.type_name(), describe(target))),
                None => return Err(missing(target)),
            },
            Expr::Key(target, key) => {
                let t = self.eval(target)?.ok_or_else(|| missing(target))?;
                let k = self.eval(key)?.ok_or_else(|| missing(key))?;
                return match (t, k) {
                    (Val::Hash(m), Val::Str(s)) => Ok(m.get(&s).and_then(Val::from_json)),
                    (Val::Seq(items), Val::Num(n)) => {
                        let i = n.long_value();
                        if i < 0 || i as usize >= items.len() {
                            return Err(format!("index {i} out of bounds"));
                        }
                        Ok(match &items[i as usize] {
                            Val::Empty => None,
                            other => Some(other.clone()),
                        })
                    }
                    (t, k) => Err(format!("can't index a {} with a {}", t.type_name(), k.type_name())),
                };
            }
            Expr::Default(lhs, rhs) => {
                let left = self.eval_maybe_missing(lhs)?;
                if let Some(v) = left {
                    return Ok(Some(v));
                }
                match rhs {
                    None => Val::Empty,
                    Some(r) => return self.eval(r),
                }
            }
            Expr::Exists(target) => Val::Bool(self.eval_maybe_missing(target)?.is_some()),
            Expr::Not(inner) => Val::Bool(!self.eval_bool(inner)?),
            Expr::Neg(inner, minus) => match self.eval(inner)?.ok_or_else(|| missing(inner))? {
                Val::Num(n) => {
                    if *minus {
                        Val::Num(Num::arith(Num::Int(0), '-', n)?)
                    } else {
                        Val::Num(n)
                    }
                }
                other => return Err(format!("Expected a number, but this has evaluated to a {}", other.type_name())),
            },
            Expr::Arith(l, op, r) => {
                let a = self.num(l)?;
                let b = self.num(r)?;
                Val::Num(Num::arith(a, *op, b)?)
            }
            Expr::Add(l, r) => {
                let a = self.eval(l)?.ok_or_else(|| missing(l))?;
                let b = self.eval(r)?.ok_or_else(|| missing(r))?;
                match (&a, &b) {
                    (Val::Num(x), Val::Num(y)) => Val::Num(Num::arith(*x, '+', *y)?),
                    (Val::Seq(x), Val::Seq(y)) => Val::Seq(x.iter().chain(y.iter()).cloned().collect()),
                    _ => Val::Str(format!("{}{}", self.to_text(&a, l)?, self.to_text(&b, r)?)),
                }
            }
            Expr::Cmp(l, op, r) => {
                let a = self.eval(l)?.ok_or_else(|| missing(l))?;
                let b = self.eval(r)?.ok_or_else(|| missing(r))?;
                Val::Bool(self.compare(&a, op, &b)?)
            }
            Expr::And(l, r) => Val::Bool(self.eval_bool(l)? && self.eval_bool(r)?),
            Expr::Or(l, r) => Val::Bool(self.eval_bool(l)? || self.eval_bool(r)?),
            Expr::BuiltIn(target, name, args) => return self.builtin(target, name, args.as_deref()),
        }))
    }

    fn num(&mut self, e: &Expr) -> R<Num> {
        match self.eval(e)?.ok_or_else(|| missing(e))? {
            Val::Num(n) => Ok(n),
            other => Err(format!("Expected a number, but this has evaluated to a {}: {}", other.type_name(), describe(e))),
        }
    }

    fn compare(&self, a: &Val<'a>, op: &str, b: &Val<'a>) -> R<bool> {
        let ord = match (a, b) {
            (Val::Num(x), Val::Num(y)) => Num::compare(*x, *y)?,
            (Val::Str(x), Val::Str(y)) => {
                if op == "==" || op == "!=" {
                    if x == y {
                        Ordering::Equal
                    } else {
                        Ordering::Less
                    }
                } else {
                    x.cmp(y)
                }
            }
            (Val::Empty, Val::Str(y)) | (Val::Str(y), Val::Empty) => {
                if y.is_empty() {
                    Ordering::Equal
                } else {
                    Ordering::Less
                }
            }
            (Val::Bool(x), Val::Bool(y)) if op == "==" || op == "!=" => {
                if x == y {
                    Ordering::Equal
                } else {
                    Ordering::Less
                }
            }
            (x, y) => {
                return Err(format!(
                    "Can't compare values of these types. Allowed comparisons are between two numbers, two strings, two dates, or two booleans. Left hand operand is a {}, right hand operand is a {}",
                    x.type_name(),
                    y.type_name()
                ))
            }
        };
        Ok(match op {
            "==" => ord == Ordering::Equal,
            "!=" => ord != Ordering::Equal,
            "<" => ord == Ordering::Less,
            "<=" => ord != Ordering::Greater,
            ">" => ord == Ordering::Greater,
            ">=" => ord != Ordering::Less,
            _ => false,
        })
    }

    fn string_target(&mut self, target: &Expr) -> R<String> {
        let v = self.eval(target)?.ok_or_else(|| missing(target))?;
        self.to_text(&v, target)
    }

    fn arg(&mut self, args: Option<&[Expr]>, i: usize, name: &str) -> R<Val<'a>> {
        let a = args.and_then(|a| a.get(i)).ok_or_else(|| format!("?{name} needs an argument"))?;
        self.eval(a)?.ok_or_else(|| missing(a))
    }

    fn arg_str(&mut self, args: Option<&[Expr]>, i: usize, name: &str) -> R<String> {
        match self.arg(args, i, name)? {
            Val::Str(s) => Ok(s),
            other => Err(format!("?{name} argument must be a string, not a {}", other.type_name())),
        }
    }

    fn builtin(&mut self, target: &Expr, name: &str, args: Option<&[Expr]>) -> R<Option<Val<'a>>> {
        let v = match name {
            "has_content" => {
                let v = self.eval_maybe_missing(target)?;
                Val::Bool(match v {
                    None | Some(Val::Empty) => false,
                    Some(Val::Str(s)) => !s.is_empty(),
                    Some(Val::Seq(s)) => !s.is_empty(),
                    Some(Val::Hash(m)) => !m.is_empty(),
                    Some(_) => true,
                })
            }
            "index" => Val::Num(Num::Int(self.loop_var(target)?.index as i64)),
            "counter" => Val::Num(Num::Int(self.loop_var(target)?.index as i64 + 1)),
            "has_next" => {
                let l = self.loop_var(target)?;
                Val::Bool(l.index + 1 < l.len)
            }
            "is_last" => {
                let l = self.loop_var(target)?;
                Val::Bool(l.index + 1 >= l.len)
            }
            "is_first" => Val::Bool(self.loop_var(target)?.index == 0),
            "item_parity" => Val::Str(if self.loop_var(target)?.index % 2 == 0 { "odd" } else { "even" }.into()),
            "is_number" | "is_string" | "is_boolean" | "is_sequence" | "is_hash" => {
                let v = self.eval(target)?.ok_or_else(|| missing(target))?;
                Val::Bool(match name {
                    "is_number" => matches!(v, Val::Num(_)),
                    "is_string" => matches!(v, Val::Str(_) | Val::Empty),
                    "is_boolean" => matches!(v, Val::Bool(_)),
                    "is_sequence" => matches!(v, Val::Seq(_) | Val::Empty),
                    _ => matches!(v, Val::Hash(_) | Val::Empty),
                })
            }
            "then" => {
                let cond = self.eval_bool(target)?;
                let a = args.ok_or("?then needs two arguments")?;
                if a.len() != 2 {
                    return Err("?then needs two arguments".into());
                }
                return self.eval(if cond { &a[0] } else { &a[1] });
            }
            // A string built-in: a number is first written with the number format ("1,234"),
            // then parsed back.
            "number" => Val::Num(to_number(&self.string_target(target)?)?),
            "string" => {
                let v = self.eval(target)?.ok_or_else(|| missing(target))?;
                match (v, args) {
                    (Val::Num(n), None) => Val::Str(self.number_format().format(n)),
                    (Val::Num(n), Some(_)) => {
                        let pattern = self.arg_str(args, 0, "string")?;
                        Val::Str(NumberFormat::parse(&pattern)?.format(n))
                    }
                    (Val::Bool(b), Some(a)) if a.len() == 2 => {
                        let i = if b { 0 } else { 1 };
                        Val::Str(self.arg_str(args, i, "string")?)
                    }
                    (Val::Bool(b), None) => Val::Str(b.to_string()),
                    (Val::Str(s), None) => Val::Str(s),
                    (Val::Empty, None) => Val::Str(String::new()),
                    (v, _) => return Err(format!("?string is not supported here for a {}", v.type_name())),
                }
            }
            "c" => match self.eval(target)?.ok_or_else(|| missing(target))? {
                Val::Num(Num::Int(i)) => Val::Str(i.to_string()),
                Val::Num(n) => {
                    let f = NumberFormat { grouping: None, max_frac: 16, ..NumberFormat::number() };
                    Val::Str(f.format(n))
                }
                Val::Bool(b) => Val::Str(b.to_string()),
                // The JavaScript-or-JSON c_format quotes strings.
                Val::Str(s) => Val::Str(json::jackson(&Value::String(s))),
                other => return Err(format!("?c is not supported for a {}", other.type_name())),
            },
            "size" => match self.eval(target)?.ok_or_else(|| missing(target))? {
                Val::Seq(s) => Val::Num(Num::Int(s.len() as i64)),
                Val::Hash(m) => Val::Num(Num::Int(m.len() as i64)),
                Val::Empty => Val::Num(Num::Int(0)),
                other => return Err(format!("?size is not supported for a {}", other.type_name())),
            },
            "length" => Val::Num(Num::Int(self.string_target(target)?.encode_utf16().count() as i64)),
            "replace" => {
                let s = self.string_target(target)?;
                let from = self.arg_str(args, 0, "replace")?;
                let to = self.arg_str(args, 1, "replace")?;
                let flags = if args.is_some_and(|a| a.len() > 2) { self.arg_str(args, 2, "replace")? } else { String::new() };
                // Flags other than r, i and f do not change the replacement.
                if flags.is_empty() {
                    Val::Str(if from.is_empty() { java_replace_empty(&s, &to) } else { s.replace(&from, &to) })
                } else {
                    let pattern = if flags.contains('r') { from.clone() } else { regex::escape(&from) };
                    let re = regex::RegexBuilder::new(&pattern)
                        .case_insensitive(flags.contains('i'))
                        .build()
                        .map_err(|e| format!("bad regular expression: {e}"))?;
                    let out = match (flags.contains('r'), flags.contains('f')) {
                        // Java's replacement syntax ($1) reads the same in the regex crate.
                        (true, true) => re.replace(&s, to.as_str()).into_owned(),
                        (true, false) => re.replace_all(&s, to.as_str()).into_owned(),
                        (false, true) => re.replace(&s, regex::NoExpand(&to)).into_owned(),
                        (false, false) => re.replace_all(&s, regex::NoExpand(&to)).into_owned(),
                    };
                    Val::Str(out)
                }
            }
            "matches" => {
                let s = self.string_target(target)?;
                let pattern = self.arg_str(args, 0, "matches")?;
                let re = regex::Regex::new(&format!("^(?:{pattern})$")).map_err(|e| format!("bad regular expression: {e}"))?;
                Val::Bool(re.is_match(&s))
            }
            "contains" | "starts_with" | "ends_with" => {
                let s = self.string_target(target)?;
                let a = self.arg_str(args, 0, name)?;
                Val::Bool(match name {
                    "contains" => s.contains(&a),
                    "starts_with" => s.starts_with(&a),
                    _ => s.ends_with(&a),
                })
            }
            "trim" => Val::Str(crate::java::trim(&self.string_target(target)?).to_string()),
            "upper_case" => Val::Str(self.string_target(target)?.to_uppercase()),
            "lower_case" => Val::Str(self.string_target(target)?.to_lowercase()),
            "cap_first" | "uncap_first" => {
                let s = self.string_target(target)?;
                let idx = s.find(|c: char| !c.is_whitespace());
                Val::Str(match idx {
                    Some(i) => {
                        let mut chars = s[i..].chars();
                        let first = chars.next().map(|c| if name == "cap_first" { c.to_uppercase().collect::<String>() } else { c.to_lowercase().collect() }).unwrap_or_default();
                        format!("{}{first}{}", &s[..i], chars.as_str())
                    }
                    None => s,
                })
            }
            "abs" | "round" | "floor" | "ceiling" | "int" => {
                let n = self.num(target)?;
                let d = n.dec().ok_or("not a finite number")?;
                Val::Num(match name {
                    "abs" => {
                        if n.signum() < 0 {
                            Num::arith(Num::Int(0), '-', n)?
                        } else {
                            n
                        }
                    }
                    "int" => Num::Int(n.long_value()),
                    "round" => Num::Dec(Dec::add(d, Dec { m: 5, s: 1 }).map(|x| floor(x)).ok_or("overflow")?),
                    "floor" => Num::Dec(floor(d)),
                    _ => Num::Dec(Dec::sub(Dec { m: 0, s: 0 }, floor(Dec { m: -d.m, s: d.s })).ok_or("overflow")?),
                })
            }
            other => return Err(format!("the built-in ?{other} is not supported")),
        };
        Ok(Some(v))
    }
}

fn floor(d: Dec) -> Dec {
    let p = 10i128.pow(d.s.min(38));
    let q = d.m.div_euclid(p);
    Dec { m: q, s: 0 }
}

/// `String.replace("", x)` (FreeMarker's literal replace): the replacement between every char.
fn java_replace_empty(s: &str, to: &str) -> String {
    let mut out = String::from(to);
    for c in s.chars() {
        out.push(c);
        out.push_str(to);
    }
    out
}

/// `BigDecimalEngine.toNumber(String)`.
fn to_number(s: &str) -> R<Num> {
    match s {
        "INF" | "Infinity" => return Ok(Num::Double(f64::INFINITY)),
        "-INF" | "-Infinity" => return Ok(Num::Double(f64::NEG_INFINITY)),
        "NaN" => return Ok(Num::Double(f64::NAN)),
        _ => {}
    }
    Dec::parse(s).map(Num::Dec).ok_or_else(|| format!("Can't convert this string to number: \"{s}\""))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn render(src: &str, data: Value) -> String {
        match process("t", Some(src), data.as_object().unwrap()) {
            Ok(s) => s,
            Err(e) => format!("ERR {}", e.message()),
        }
    }

    #[test]
    fn interpolation_and_numbers() {
        assert_eq!(render("Hi ${name}!", json!({"name": "Ann"})), "Hi Ann!");
        assert_eq!(render("${n}", json!({"n": 1234567})), "1,234,567");
        assert_eq!(render("${n}", json!({"n": 1234.5678})), "1,234.568");
        assert_eq!(render("${n}", json!({"n": 2.5})), "2.5");
        assert_eq!(render("${n?string(\",##0.00\")}", json!({"n": 1234.5})), "1,234.50");
        assert_eq!(render("${(a + b)}", json!({"a": 0.1, "b": 0.2})), "0.3");
        assert_eq!(render("${x!}|${x!\"d\"}", json!({})), "|d");
        assert!(render("${missing}", json!({})).starts_with("ERR"));
    }

    #[test]
    fn whitespace_stripping() {
        let src = "Hello\n<#if show>\n  World\n</#if>\nBye";
        assert_eq!(render(src, json!({"show": true})), "Hello\n  World\nBye");
        assert_eq!(render(src, json!({"show": false})), "Hello\nBye");
    }

    #[test]
    fn lists_and_sep() {
        assert_eq!(render("<#list xs as x>${x?index}:${x}<#sep>, </#list>", json!({"xs": ["a", "b"]})), "0:a, 1:b");
        assert_eq!(render("<#list xs as x>${x}<#else>none</#list>", json!({"xs": []})), "none");
    }

    #[test]
    fn existence_rules() {
        assert_eq!(render("${(a.b)!\"d\"}", json!({})), "d");
        assert!(render("${a.b!\"d\"}", json!({})).starts_with("ERR"));
        assert_eq!(render("<#if a?? && a?has_content>y<#else>n</#if>", json!({"a": ""})), "n");
        assert_eq!(render("${(n?replace(\",\", \"\"))?number + 1}", json!({"n": 1234})), "1,235");
        // ?number writes a number out first, grouping and all.
        assert!(render("${n?number}", json!({"n": 1234})).starts_with("ERR"));
        assert_eq!(render("${n?number}", json!({"n": 12.5})), "12.5");
    }

    #[test]
    fn lenient_rendering_skips_what_fails() {
        let lenient = |src: &str, data: Value| process_lenient("t", Some(src), data.as_object().unwrap()).unwrap();
        assert_eq!(lenient("Hi ${name}, ${missing}!", json!({"name": "Ann"})), "Hi Ann, !");
        assert_eq!(lenient("<#if nope>a<#else>b</#if>-c", json!({})), "-c");
        assert_eq!(lenient("<#list xs as x>[${x.y}]</#list>", json!({"xs": [1, 2]})), "[][]");
        assert!(process_lenient("t", Some("${"), json!({}).as_object().unwrap()).is_err(), "a syntax error still fails");
    }
}
