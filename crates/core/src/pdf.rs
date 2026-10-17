//! The HTML-to-PDF step of `CoreServices.File.TemplateToPdf` (`PdfConversionService`).
//!
//! Java renders the template's HTML with openhtmltopdf (a CSS 2.1 layout engine with images,
//! SVG and embedded fonts). Rust has nothing comparable without heavy dependencies, so this is
//! a small, self-contained text renderer that keeps what a document says and its reading
//! structure, not its exact look:
//!
//! - the HTML is read leniently (as a browser would: unclosed tags, implied ends of `p`, `li`,
//!   `td`, `tr`, raw `script`/`style`/`title`, comments, character references);
//! - block elements become paragraphs with the browser's default margins, `br` a line break,
//!   `hr` a rule, headings larger and bold, `b`/`strong`/`th` bold, `i`/`em` italic,
//!   `code`/`pre` monospaced (`pre` keeps its spaces and lines), list items get a bullet or
//!   their number, list and quote content is indented, table cells sit side by side;
//! - `text-align` (or `align`, `center`) aligns a block, `display:none` hides one, and
//!   `page-break-before/after: always` (or `break-before/after: page`) breaks the page;
//! - text is set in the standard Helvetica (and Courier) fonts in `WinAnsiEncoding`, wrapped
//!   to an A4 page with 36pt margins, over as many pages as it needs; a character the encoding
//!   cannot show is written as `?`.
//!
//! Images, SVG, colours, CSS boxes and fonts other than the standard ones are not drawn.

use std::fmt::Write as _;

pub const PAGE_WIDTH: f32 = 595.28;
pub const PAGE_HEIGHT: f32 = 841.89;
const MARGIN: f32 = 36.0;
const BASE_SIZE: f32 = 12.0;
const LINE_HEIGHT: f32 = 1.2;
/// The space between two table cells.
const CELL_GAP: f32 = 18.0;
/// The indent of a list, a quote and a definition (40px).
const INDENT: f32 = 30.0;

/// HTML (a template's processed body) as an A4 PDF.
pub fn html_to_pdf(html: &str) -> Vec<u8> {
    let doc = parse(html);
    let pages = paginate(&doc.blocks);
    write_pdf(&pages, doc.title.as_deref())
}

// =============================================================================================
// Fonts

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Style {
    bold: bool,
    italic: bool,
    mono: bool,
}

const FONTS: [&str; 5] = ["Helvetica", "Helvetica-Bold", "Helvetica-Oblique", "Helvetica-BoldOblique", "Courier"];

impl Style {
    /// The index in [`FONTS`].
    fn font(self) -> usize {
        if self.mono {
            4
        } else {
            usize::from(self.bold) + 2 * usize::from(self.italic)
        }
    }
}

/// Helvetica's advance widths (1/1000 em) for `WinAnsiEncoding` codes 32 to 255; the oblique
/// face has the same.
#[rustfmt::skip]
const HELVETICA: [u16; 224] = [
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278,
    556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556,
    1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778,
    667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556,
    333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556,
    556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584, 350,
    556, 350, 222, 556, 333, 1000, 556, 556, 333, 1000, 667, 333, 1000, 350, 611, 350,
    350, 222, 222, 333, 333, 350, 556, 1000, 333, 1000, 500, 333, 944, 350, 500, 667,
    278, 333, 556, 556, 556, 556, 260, 556, 333, 737, 370, 556, 584, 333, 737, 333,
    400, 584, 333, 333, 333, 556, 537, 278, 333, 333, 365, 556, 834, 834, 834, 611,
    667, 667, 667, 667, 667, 667, 1000, 722, 667, 667, 667, 667, 278, 278, 278, 278,
    722, 722, 778, 778, 778, 778, 778, 584, 778, 722, 722, 722, 722, 667, 667, 611,
    556, 556, 556, 556, 556, 556, 889, 500, 556, 556, 556, 556, 278, 278, 278, 278,
    556, 556, 556, 556, 556, 556, 556, 584, 611, 556, 556, 556, 556, 500, 556, 500,
];

/// Helvetica-Bold's (and Helvetica-BoldOblique's) advance widths, as [`HELVETICA`].
#[rustfmt::skip]
const HELVETICA_BOLD: [u16; 224] = [
    278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278,
    556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 333, 333, 584, 584, 584, 611,
    975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778,
    667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584, 556,
    333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611,
    611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584, 350,
    556, 350, 278, 556, 500, 1000, 556, 556, 333, 1000, 667, 333, 1000, 350, 611, 350,
    350, 278, 278, 500, 500, 350, 556, 1000, 333, 1000, 556, 333, 944, 350, 500, 667,
    278, 333, 556, 556, 556, 556, 280, 556, 333, 737, 370, 556, 584, 333, 737, 333,
    400, 584, 333, 333, 333, 611, 556, 278, 333, 333, 365, 556, 834, 834, 834, 611,
    722, 722, 722, 722, 722, 722, 1000, 722, 667, 667, 667, 667, 278, 278, 278, 278,
    722, 722, 778, 778, 778, 778, 778, 584, 778, 722, 722, 722, 722, 667, 667, 611,
    556, 556, 556, 556, 556, 556, 889, 556, 556, 556, 556, 556, 278, 278, 278, 278,
    611, 611, 611, 611, 611, 611, 611, 584, 611, 611, 611, 611, 611, 556, 611, 556,
];

fn char_width(b: u8, style: Style) -> f32 {
    if style.mono {
        return 600.0;
    }
    let table = if style.bold { &HELVETICA_BOLD } else { &HELVETICA };
    f32::from(table[usize::from(b.max(32)) - 32])
}

fn text_width(text: &[u8], style: Style, size: f32) -> f32 {
    text.iter().map(|b| char_width(*b, style)).sum::<f32>() * size / 1000.0
}

/// `WinAnsiEncoding`'s 0x80-0x9F block, by Unicode code point.
const WIN_ANSI_HIGH: [(char, u8); 27] = [
    ('\u{20AC}', 0x80),
    ('\u{201A}', 0x82),
    ('\u{0192}', 0x83),
    ('\u{201E}', 0x84),
    ('\u{2026}', 0x85),
    ('\u{2020}', 0x86),
    ('\u{2021}', 0x87),
    ('\u{02C6}', 0x88),
    ('\u{2030}', 0x89),
    ('\u{0160}', 0x8A),
    ('\u{2039}', 0x8B),
    ('\u{0152}', 0x8C),
    ('\u{017D}', 0x8E),
    ('\u{2018}', 0x91),
    ('\u{2019}', 0x92),
    ('\u{201C}', 0x93),
    ('\u{201D}', 0x94),
    ('\u{2022}', 0x95),
    ('\u{2013}', 0x96),
    ('\u{2014}', 0x97),
    ('\u{02DC}', 0x98),
    ('\u{2122}', 0x99),
    ('\u{0161}', 0x9A),
    ('\u{203A}', 0x9B),
    ('\u{0153}', 0x9C),
    ('\u{017E}', 0x9E),
    ('\u{0178}', 0x9F),
];

/// A character in `WinAnsiEncoding`: `None` to leave it out (zero-width and control
/// characters), `?` for one the encoding has no glyph for.
fn win_ansi(c: char) -> Option<u8> {
    match c {
        ' '..='~' | '\u{A0}'..='\u{FF}' => Some(c as u8),
        '\u{2000}'..='\u{200A}' | '\u{202F}' | '\u{205F}' | '\u{3000}' => Some(b' '),
        '\u{2010}' | '\u{2011}' | '\u{2012}' | '\u{2212}' => Some(b'-'),
        '\u{200B}'..='\u{200F}' | '\u{2060}' | '\u{FEFF}' | '\0'..='\u{1F}' | '\u{7F}'..='\u{9F}' => None,
        _ => Some(WIN_ANSI_HIGH.iter().find(|(u, _)| *u == c).map_or(b'?', |(_, b)| *b)),
    }
}

/// A code point of a numeric character reference: HTML reads 0x80-0x9F as Windows-1252.
fn reference_char(n: u32) -> char {
    if (0x80..=0x9F).contains(&n) {
        if let Some((c, _)) = WIN_ANSI_HIGH.iter().find(|(_, b)| u32::from(*b) == n) {
            return *c;
        }
    }
    match char::from_u32(n) {
        Some(c) if n != 0 => c,
        _ => '\u{FFFD}',
    }
}

// =============================================================================================
// HTML

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Align {
    #[default]
    Left,
    Center,
    Right,
}

/// What a paragraph is made of.
#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Word(Vec<u8>, Style),
    Space(Style),
    Gap(f32),
    Break,
}

#[derive(Debug, Clone, PartialEq)]
enum Block {
    Para { toks: Vec<Tok>, size: f32, left: f32, right: f32, align: Align, before: f32, pre: bool },
    Rule { before: f32, left: f32, right: f32 },
    PageBreak,
}

#[derive(Debug, Default)]
struct Doc {
    blocks: Vec<Block>,
    title: Option<String>,
}

/// Elements whose content is not shown.
const HIDDEN: &[&str] = &[
    "head", "script", "style", "title", "template", "noscript", "svg", "math", "iframe", "object", "canvas", "video", "audio", "map",
    "datalist", "select",
];

/// Elements whose content is text up to their end tag.
const RAW_TEXT: &[&str] = &["script", "style", "title", "textarea", "xmp"];

const VOID: &[&str] = &[
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr", "basefont", "frame",
    "keygen",
];

const BLOCKS: &[&str] = &[
    "address", "article", "aside", "blockquote", "body", "caption", "center", "dd", "details", "dialog", "dir", "div", "dl", "dt",
    "fieldset", "figcaption", "figure", "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "header", "hgroup", "html", "legend", "li",
    "listing", "main", "menu", "nav", "ol", "p", "pre", "section", "summary", "table", "tbody", "tfoot", "thead", "tr", "ul", "xmp",
    "textarea",
];

fn is_block(name: &str) -> bool {
    BLOCKS.contains(&name)
}

fn heading_size(name: &str) -> Option<f32> {
    Some(match name {
        "h1" => 24.0,
        "h2" => 18.0,
        "h3" => 14.0,
        "h4" => 12.0,
        "h5" => 10.0,
        "h6" => 8.0,
        _ => return None,
    })
}

#[derive(Debug)]
struct Open {
    name: String,
    align: Option<Align>,
    hidden: bool,
    break_after: bool,
    /// An `ol`'s next number; `Some(0)` marks a `ul`/`menu`/`dir` (bullets).
    counter: Option<i64>,
}

#[derive(Default)]
struct Builder {
    doc: Doc,
    toks: Vec<Tok>,
    stack: Vec<Open>,
    /// The collapsed margin waiting above the next paragraph.
    gap: f32,
    /// A list item's marker, waiting for the item's first word.
    marker: Option<String>,
}

/// The `style` attribute's declarations, lower-cased and without spaces.
fn declarations(style: &str) -> Vec<(String, String)> {
    style
        .split(';')
        .filter_map(|d| d.split_once(':'))
        .map(|(k, v)| {
            let clean = |s: &str| s.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_ascii_lowercase();
            (clean(k), clean(v).trim_end_matches("!important").to_string())
        })
        .collect()
}

fn align_of(value: &str) -> Option<Align> {
    match value.trim().to_ascii_lowercase().as_str() {
        "center" | "-webkit-center" | "middle" => Some(Align::Center),
        "right" | "end" => Some(Align::Right),
        "left" | "start" | "justify" => Some(Align::Left),
        _ => None,
    }
}

impl Builder {
    fn names(&self) -> impl DoubleEndedIterator<Item = &str> {
        self.stack.iter().map(|o| o.name.as_str())
    }

    fn hidden(&self) -> bool {
        self.stack.iter().any(|o| o.hidden || HIDDEN.contains(&o.name.as_str()))
    }

    fn pre(&self) -> bool {
        self.names().any(|n| matches!(n, "pre" | "textarea" | "xmp" | "listing"))
    }

    fn style(&self) -> Style {
        let mut s = Style::default();
        for n in self.names() {
            match n {
                "b" | "strong" | "th" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => s.bold = true,
                "i" | "em" | "cite" | "var" | "dfn" | "address" => s.italic = true,
                "code" | "kbd" | "samp" | "tt" | "pre" | "textarea" | "xmp" | "listing" => s.mono = true,
                _ => {}
            }
        }
        s
    }

    fn size(&self) -> f32 {
        self.names().rev().find_map(heading_size).unwrap_or(BASE_SIZE)
    }

    fn indents(&self) -> (f32, f32) {
        let (mut left, mut right) = (0.0, 0.0);
        for n in self.names() {
            match n {
                "ul" | "ol" | "menu" | "dir" | "dd" => left += INDENT,
                "blockquote" => {
                    left += INDENT;
                    right += INDENT;
                }
                _ => {}
            }
        }
        (left, right)
    }

    fn align(&self) -> Align {
        self.stack.iter().rev().find_map(|o| o.align).unwrap_or_default()
    }

    /// The default vertical margin of a block (top and bottom alike).
    fn margin(&self, name: &str, index: usize) -> f32 {
        let nested_list = self.stack[..index].iter().any(|o| matches!(o.name.as_str(), "ul" | "ol" | "menu" | "dir" | "dl"));
        match name {
            "p" | "blockquote" | "pre" | "figure" | "xmp" | "listing" => BASE_SIZE,
            "ul" | "ol" | "menu" | "dir" | "dl" if !nested_list => BASE_SIZE,
            "h1" => 0.67 * 24.0,
            "h2" => 0.83 * 18.0,
            "h3" => 14.0,
            "h4" => 1.33 * 12.0,
            "h5" => 1.67 * 10.0,
            "h6" => 2.33 * 8.0,
            _ => 0.0,
        }
    }

    fn push_word(&mut self, word: &str, style: Style) {
        if let Some(marker) = self.marker.take() {
            self.toks.push(Tok::Word(marker.chars().filter_map(win_ansi).collect(), Style::default()));
            self.toks.push(Tok::Space(Style::default()));
        }
        let bytes: Vec<u8> = word.chars().filter_map(win_ansi).collect();
        if !bytes.is_empty() {
            self.toks.push(Tok::Word(bytes, style));
        }
    }

    fn text(&mut self, text: &str) {
        if self.hidden() || text.is_empty() {
            return;
        }
        let style = self.style();
        if self.pre() {
            let mut word = String::new();
            for c in text.chars() {
                match c {
                    ' ' | '\t' | '\n' => {
                        if !word.is_empty() {
                            self.push_word(&std::mem::take(&mut word), style);
                        }
                        match c {
                            '\n' => self.toks.push(Tok::Break),
                            '\t' => self.toks.extend(std::iter::repeat_n(Tok::Space(style), 4)),
                            _ => self.toks.push(Tok::Space(style)),
                        }
                    }
                    '\r' => {}
                    _ => word.push(c),
                }
            }
            if !word.is_empty() {
                self.push_word(&word, style);
            }
            return;
        }
        for (i, part) in text.split([' ', '\t', '\n', '\r', '\u{0C}']).enumerate() {
            if i > 0 && matches!(self.toks.last(), Some(Tok::Word(..))) {
                self.toks.push(Tok::Space(style));
            }
            if !part.is_empty() {
                self.push_word(part, style);
            }
        }
    }

    /// Ends the paragraph being built.
    fn flush(&mut self) {
        let mut toks = std::mem::take(&mut self.toks);
        while matches!(toks.last(), Some(Tok::Space(_) | Tok::Gap(_))) {
            toks.pop();
        }
        if !toks.iter().any(|t| matches!(t, Tok::Word(..) | Tok::Break)) {
            return;
        }
        let (left, right) = self.indents();
        let before = std::mem::take(&mut self.gap);
        self.doc.blocks.push(Block::Para { toks, size: self.size(), left, right, align: self.align(), before, pre: self.pre() });
    }

    fn page_break(&mut self) {
        self.flush();
        self.gap = 0.0;
        self.doc.blocks.push(Block::PageBreak);
    }

    /// The innermost open element among `names`, if it is one of `closing`.
    fn innermost(&self, names: &[&str], closing: &[&str]) -> Option<String> {
        self.names().rev().find(|n| names.contains(n)).filter(|n| closing.contains(n)).map(str::to_string)
    }

    fn start(&mut self, name: &str, attrs: &[(String, String)]) {
        let attr = |k: &str| attrs.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        let decls = declarations(attr("style").unwrap_or(""));
        let decl = |k: &str| decls.iter().rev().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        let hidden = decl("display") == Some("none") || attr("hidden").is_some();
        let breaks = |a: &str, b: &str| decl(a) == Some("always") || decl(b) == Some("page");

        match name {
            "br" => {
                if !self.hidden() {
                    self.toks.push(Tok::Break);
                }
                return;
            }
            "hr" => {
                if !self.hidden() && !hidden {
                    self.flush();
                    let before = std::mem::take(&mut self.gap).max(6.0);
                    let (left, right) = self.indents();
                    self.doc.blocks.push(Block::Rule { before, left, right });
                    self.gap = 6.0;
                }
                return;
            }
            _ if VOID.contains(&name) => return,
            _ => {}
        }

        // The ends HTML implies.
        let implied = match name {
            "li" => self.innermost(&["li", "ul", "ol", "menu", "dir"], &["li"]),
            "dt" | "dd" => self.innermost(&["dt", "dd", "dl"], &["dt", "dd"]),
            "td" | "th" => self.innermost(&["td", "th", "tr", "table"], &["td", "th"]),
            "tr" => self.innermost(&["tr", "table"], &["tr"]),
            "tbody" | "thead" | "tfoot" => self.innermost(&["tbody", "thead", "tfoot", "table"], &["tbody", "thead", "tfoot"]),
            _ => None,
        };
        if let Some(n) = implied {
            self.end(&n);
        }
        if is_block(name) && self.names().next_back() == Some("p") {
            self.end("p");
        }

        let mut align = attr("align").and_then(align_of).or_else(|| decl("text-align").and_then(align_of));
        if name == "center" {
            align = align.or(Some(Align::Center));
        }
        let counter = match name {
            "ol" => Some(attr("start").and_then(|s| s.trim().parse::<i64>().ok()).unwrap_or(1)),
            "ul" | "menu" | "dir" => Some(0),
            _ => None,
        };
        let open = Open { name: name.to_string(), align, hidden, break_after: breaks("page-break-after", "break-after"), counter };

        if is_block(name) {
            self.flush();
            if breaks("page-break-before", "break-before") && !self.hidden() {
                self.page_break();
            }
            let margin = self.margin(name, self.stack.len());
            self.gap = self.gap.max(margin);
            if name == "li" {
                self.marker = Some(match self.stack.iter_mut().rev().find_map(|o| o.counter.as_mut()) {
                    Some(n) if *n != 0 => {
                        let m = format!("{n}.");
                        *n += 1;
                        m
                    }
                    _ => "\u{2022}".to_string(),
                });
            }
        } else if matches!(name, "td" | "th") && self.toks.iter().any(|t| matches!(t, Tok::Word(..))) {
            self.toks.push(Tok::Gap(CELL_GAP));
        }
        self.stack.push(open);
    }

    fn end(&mut self, name: &str) {
        // `</br>` is read as `<br>`.
        if name == "br" {
            self.start("br", &[]);
            return;
        }
        let Some(at) = self.stack.iter().rposition(|o| o.name == name) else { return };
        while self.stack.len() > at {
            let i = self.stack.len() - 1;
            let n = self.stack[i].name.clone();
            if is_block(&n) {
                self.flush();
                let margin = self.margin(&n, i);
                self.gap = self.gap.max(margin);
                if n == "li" {
                    self.marker = None;
                }
            }
            if self.stack[i].break_after && !self.hidden() {
                self.page_break();
            }
            self.stack.pop();
        }
    }
}

/// HTML's named character references this reader knows (the common ones).
const ENTITIES: &[(&str, &str)] = &[
    ("amp", "&"), ("lt", "<"), ("gt", ">"), ("quot", "\""), ("apos", "'"), ("nbsp", "\u{A0}"), ("copy", "\u{A9}"), ("reg", "\u{AE}"),
    ("trade", "\u{2122}"), ("hellip", "\u{2026}"), ("mdash", "\u{2014}"), ("ndash", "\u{2013}"), ("lsquo", "\u{2018}"),
    ("rsquo", "\u{2019}"), ("ldquo", "\u{201C}"), ("rdquo", "\u{201D}"), ("sbquo", "\u{201A}"), ("bdquo", "\u{201E}"),
    ("bull", "\u{2022}"), ("middot", "\u{B7}"), ("euro", "\u{20AC}"), ("pound", "\u{A3}"), ("yen", "\u{A5}"), ("cent", "\u{A2}"),
    ("curren", "\u{A4}"), ("sect", "\u{A7}"), ("para", "\u{B6}"), ("deg", "\u{B0}"), ("plusmn", "\u{B1}"), ("times", "\u{D7}"),
    ("divide", "\u{F7}"), ("frac12", "\u{BD}"), ("frac14", "\u{BC}"), ("frac34", "\u{BE}"), ("sup1", "\u{B9}"), ("sup2", "\u{B2}"),
    ("sup3", "\u{B3}"), ("laquo", "\u{AB}"), ("raquo", "\u{BB}"), ("lsaquo", "\u{2039}"), ("rsaquo", "\u{203A}"),
    ("iexcl", "\u{A1}"), ("iquest", "\u{BF}"), ("dagger", "\u{2020}"), ("Dagger", "\u{2021}"), ("permil", "\u{2030}"),
    ("shy", "\u{AD}"), ("ensp", "\u{2002}"), ("emsp", "\u{2003}"), ("thinsp", "\u{2009}"), ("zwnj", "\u{200C}"), ("zwj", "\u{200D}"),
    ("micro", "\u{B5}"), ("ordf", "\u{AA}"), ("ordm", "\u{BA}"), ("not", "\u{AC}"), ("macr", "\u{AF}"), ("acute", "\u{B4}"),
    ("cedil", "\u{B8}"), ("uml", "\u{A8}"), ("brvbar", "\u{A6}"), ("szlig", "\u{DF}"), ("rarr", "\u{2192}"), ("larr", "\u{2190}"),
    ("Agrave", "\u{C0}"), ("Aacute", "\u{C1}"), ("Acirc", "\u{C2}"), ("Atilde", "\u{C3}"), ("Auml", "\u{C4}"), ("Aring", "\u{C5}"),
    ("AElig", "\u{C6}"), ("Ccedil", "\u{C7}"), ("Egrave", "\u{C8}"), ("Eacute", "\u{C9}"), ("Ecirc", "\u{CA}"), ("Euml", "\u{CB}"),
    ("Igrave", "\u{CC}"), ("Iacute", "\u{CD}"), ("Icirc", "\u{CE}"), ("Iuml", "\u{CF}"), ("ETH", "\u{D0}"), ("Ntilde", "\u{D1}"),
    ("Ograve", "\u{D2}"), ("Oacute", "\u{D3}"), ("Ocirc", "\u{D4}"), ("Otilde", "\u{D5}"), ("Ouml", "\u{D6}"), ("Oslash", "\u{D8}"),
    ("Ugrave", "\u{D9}"), ("Uacute", "\u{DA}"), ("Ucirc", "\u{DB}"), ("Uuml", "\u{DC}"), ("Yacute", "\u{DD}"), ("THORN", "\u{DE}"),
    ("agrave", "\u{E0}"), ("aacute", "\u{E1}"), ("acirc", "\u{E2}"), ("atilde", "\u{E3}"), ("auml", "\u{E4}"), ("aring", "\u{E5}"),
    ("aelig", "\u{E6}"), ("ccedil", "\u{E7}"), ("egrave", "\u{E8}"), ("eacute", "\u{E9}"), ("ecirc", "\u{EA}"), ("euml", "\u{EB}"),
    ("igrave", "\u{EC}"), ("iacute", "\u{ED}"), ("icirc", "\u{EE}"), ("iuml", "\u{EF}"), ("eth", "\u{F0}"), ("ntilde", "\u{F1}"),
    ("ograve", "\u{F2}"), ("oacute", "\u{F3}"), ("ocirc", "\u{F4}"), ("otilde", "\u{F5}"), ("ouml", "\u{F6}"), ("oslash", "\u{F8}"),
    ("ugrave", "\u{F9}"), ("uacute", "\u{FA}"), ("ucirc", "\u{FB}"), ("uuml", "\u{FC}"), ("yacute", "\u{FD}"), ("thorn", "\u{FE}"),
    ("yuml", "\u{FF}"), ("OElig", "\u{152}"), ("oelig", "\u{153}"), ("Scaron", "\u{160}"), ("scaron", "\u{161}"), ("Yuml", "\u{178}"),
    ("fnof", "\u{192}"), ("circ", "\u{2C6}"), ("tilde", "\u{2DC}"),
];

/// The references HTML also reads without the `;`.
const LEGACY: &[&str] = &["amp", "lt", "gt", "quot", "nbsp", "copy", "reg"];

/// Character references resolved.
fn decode(text: &str) -> String {
    if !text.contains('&') {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        let after = &rest[1..];
        if let Some(num) = after.strip_prefix('#') {
            let (hex, digits) = match num.strip_prefix(['x', 'X']) {
                Some(h) => (true, h),
                None => (false, num),
            };
            let len = digits.bytes().take_while(|b| if hex { b.is_ascii_hexdigit() } else { b.is_ascii_digit() }).count();
            if len > 0 {
                let n = u32::from_str_radix(&digits[..len], if hex { 16 } else { 10 }).unwrap_or(u32::MAX);
                out.push(reference_char(n));
                let used = 1 + (num.len() - digits.len()) + len;
                rest = &after[used..];
                rest = rest.strip_prefix(';').unwrap_or(rest);
                continue;
            }
        } else {
            let len = after.bytes().take(32).take_while(u8::is_ascii_alphanumeric).count();
            let name = &after[..len];
            if let Some((_, value)) = ENTITIES.iter().find(|(n, _)| *n == name) {
                if after[len..].starts_with(';') {
                    out.push_str(value);
                    rest = &after[len + 1..];
                    continue;
                }
            }
            // `&copy2`: a reference HTML reads without its `;` matches as a prefix.
            if let Some(legacy) = LEGACY.iter().find(|l| name.starts_with(**l)) {
                let value = ENTITIES.iter().find(|(n, _)| n == legacy).map_or("", |(_, v)| *v);
                out.push_str(value);
                rest = &after[legacy.len()..];
                continue;
            }
        }
        out.push('&');
        rest = after;
    }
    out.push_str(rest);
    out
}

/// Reads a start tag from `s` (just after `<`): its name, attributes and length up to and
/// including `>`. `None` when the tag never ends.
fn read_tag(s: &str) -> Option<(String, Vec<(String, String)>, usize)> {
    let b = s.as_bytes();
    let mut i = b.iter().take_while(|c| c.is_ascii_alphanumeric() || **c == b'-' || **c == b':' || **c == b'_').count();
    let name = s[..i].to_ascii_lowercase();
    let mut attrs = Vec::new();
    loop {
        while i < b.len() && (b[i].is_ascii_whitespace() || b[i] == b'/') {
            i += 1;
        }
        if i >= b.len() {
            return None;
        }
        if b[i] == b'>' {
            return Some((name, attrs, i + 1));
        }
        let start = i;
        while i < b.len() && !b[i].is_ascii_whitespace() && !matches!(b[i], b'=' | b'>' | b'/') {
            i += 1;
        }
        let key = s[start..i].to_ascii_lowercase();
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        let mut value = String::new();
        if i < b.len() && b[i] == b'=' {
            i += 1;
            while i < b.len() && b[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < b.len() && (b[i] == b'"' || b[i] == b'\'') {
                let q = b[i];
                let end = b[i + 1..].iter().position(|c| *c == q).map(|p| i + 1 + p)?;
                value = decode(&s[i + 1..end]);
                i = end + 1;
            } else {
                let v = i;
                while i < b.len() && !b[i].is_ascii_whitespace() && b[i] != b'>' {
                    i += 1;
                }
                value = decode(&s[v..i]);
            }
        }
        attrs.push((key, value));
    }
}

fn parse(html: &str) -> Doc {
    let lower = html.to_ascii_lowercase();
    let mut b = Builder::default();
    let mut i = 0;
    while i < html.len() {
        let rest = &html[i..];
        let Some(lt) = rest.find('<') else {
            b.text(&decode(rest));
            break;
        };
        if lt > 0 {
            b.text(&decode(&rest[..lt]));
            i += lt;
            continue;
        }
        let next = rest.as_bytes().get(1).copied().unwrap_or(b' ');
        if rest.starts_with("<!--") {
            i += rest[4..].find("-->").map_or(rest.len(), |e| e + 7);
        } else if next == b'!' || next == b'?' {
            i += rest.find('>').map_or(rest.len(), |e| e + 1);
        } else if next == b'/' && rest.as_bytes().get(2).is_some_and(u8::is_ascii_alphabetic) {
            let Some(gt) = rest.find('>') else { break };
            let name: String = rest[2..gt]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | ':' | '_'))
                .collect::<String>()
                .to_ascii_lowercase();
            b.end(&name);
            i += gt + 1;
        } else if next.is_ascii_alphabetic() {
            let Some((name, attrs, len)) = read_tag(&rest[1..]) else { break };
            i += 1 + len;
            b.start(&name, &attrs);
            // A newline right after these start tags is not content.
            if matches!(name.as_str(), "pre" | "listing" | "textarea") {
                let skip = if html[i..].starts_with("\r\n") { 2 } else { usize::from(html[i..].starts_with('\n')) };
                i += skip;
            }
            if RAW_TEXT.contains(&name.as_str()) {
                let close = format!("</{name}");
                let end = lower[i..].find(&close).map_or(html.len(), |e| i + e);
                let content = &html[i..end];
                match name.as_str() {
                    "title" if b.doc.title.is_none() => b.doc.title = Some(decode(content).split_whitespace().collect::<Vec<_>>().join(" ")),
                    "textarea" => b.text(&decode(content)),
                    "xmp" => b.text(content),
                    _ => {}
                }
                i = end;
            }
        } else {
            b.text("<");
            i += 1;
        }
    }
    while let Some(o) = b.stack.last() {
        let name = o.name.clone();
        b.end(&name);
    }
    b.flush();
    b.doc
}

// =============================================================================================
// Layout

#[derive(Debug, Default, Clone, PartialEq)]
struct Line {
    /// x from the line's start, the text, its style.
    items: Vec<(f32, Vec<u8>, Style)>,
    width: f32,
}

/// The longest start of `word` that fits `room` (at least one character).
fn fit(word: &[u8], style: Style, size: f32, room: f32) -> usize {
    let mut w = 0.0;
    for (i, c) in word.iter().enumerate() {
        w += char_width(*c, style) * size / 1000.0;
        if w > room {
            return i.max(1);
        }
    }
    word.len()
}

/// A paragraph's words broken into lines `max` wide: at spaces, a word wider than a line
/// broken where it overflows; leading spaces dropped except at the start of a `pre` line.
fn lines(toks: &[Tok], size: f32, max: f32, pre: bool) -> Vec<Line> {
    let mut out = Vec::new();
    let mut cur = Line::default();
    // The space waiting before the next word, and whether it is one plain space of a style
    // (the next word can then join the previous text).
    let mut pending = 0.0f32;
    let mut simple: Option<Style> = None;
    let mut spaces = 0;
    let mut line_start = true;
    for t in toks {
        match t {
            Tok::Space(st) => {
                pending += char_width(b' ', *st) * size / 1000.0;
                spaces += 1;
                simple = if spaces == 1 { Some(*st) } else { None };
            }
            Tok::Gap(g) => {
                pending += g;
                spaces += 2;
                simple = None;
            }
            Tok::Break => {
                out.push(std::mem::take(&mut cur));
                (pending, simple, spaces, line_start) = (0.0, None, 0, true);
            }
            Tok::Word(w, st) => {
                let mut word = &w[..];
                while !word.is_empty() {
                    let lead = if !cur.items.is_empty() || (pre && line_start) { pending } else { 0.0 };
                    let ww = text_width(word, *st, size);
                    if !cur.items.is_empty() && cur.width + lead + ww > max {
                        out.push(std::mem::take(&mut cur));
                        (pending, simple, spaces, line_start) = (0.0, None, 0, false);
                        continue;
                    }
                    let n = if lead + ww > max { fit(word, *st, size, max - lead) } else { word.len() };
                    let (part, rest) = word.split_at(n);
                    let x = cur.width + lead;
                    match cur.items.last_mut() {
                        Some((_, text, last)) if *last == *st && simple == Some(*st) => {
                            text.push(b' ');
                            text.extend_from_slice(part);
                        }
                        _ => cur.items.push((x, part.to_vec(), *st)),
                    }
                    cur.width = x + text_width(part, *st, size);
                    (pending, simple, spaces) = (0.0, None, 0);
                    word = rest;
                    if !word.is_empty() {
                        out.push(std::mem::take(&mut cur));
                        line_start = false;
                    }
                }
            }
        }
    }
    if !cur.items.is_empty() {
        out.push(cur);
    }
    out
}

/// A number as a PDF operand: at most two decimals, no trailing zeros.
fn num(f: f32) -> String {
    let s = format!("{f:.2}");
    let s = s.trim_end_matches('0').trim_end_matches('.');
    if s == "-0" { "0".into() } else { s.to_string() }
}

/// A PDF literal string of `WinAnsiEncoding` bytes.
fn literal(text: &[u8]) -> String {
    let mut s = String::with_capacity(text.len() + 2);
    s.push('(');
    for &b in text {
        match b {
            b'(' | b')' | b'\\' => {
                s.push('\\');
                s.push(b as char);
            }
            0x20..=0x7E => s.push(b as char),
            _ => {
                let _ = write!(s, "\\{b:03o}");
            }
        }
    }
    s.push(')');
    s
}

/// The blocks set on pages: each page's content stream.
fn paginate(blocks: &[Block]) -> Vec<String> {
    let top = PAGE_HEIGHT - MARGIN;
    let mut pages = vec![String::new()];
    let mut y = top;
    let mut fresh = true;
    // A page break waits for content, so a break at the end adds no empty page.
    let mut broken = false;
    let new_page = |pages: &mut Vec<String>, y: &mut f32, fresh: &mut bool| {
        pages.push(String::new());
        *y = top;
        *fresh = true;
    };
    for block in blocks {
        if broken && !matches!(block, Block::PageBreak) {
            new_page(&mut pages, &mut y, &mut fresh);
            broken = false;
        }
        match block {
            Block::Para { toks, size, left, right, align, before, pre } => {
                let max = (PAGE_WIDTH - 2.0 * MARGIN - left - right).max(36.0);
                let lh = size * LINE_HEIGHT;
                if !fresh {
                    y -= before;
                }
                for line in lines(toks, *size, max, *pre) {
                    if y - lh < MARGIN && !fresh {
                        new_page(&mut pages, &mut y, &mut fresh);
                    }
                    let baseline = y - (lh - size) / 2.0 - size * 0.8;
                    let shift = match align {
                        Align::Left => 0.0,
                        Align::Center => ((max - line.width) / 2.0).max(0.0),
                        Align::Right => (max - line.width).max(0.0),
                    };
                    let page = pages.last_mut().expect("a page");
                    for (x, text, st) in &line.items {
                        let _ = writeln!(
                            page,
                            "BT /F{} {} Tf {} {} Td {} Tj ET",
                            st.font() + 1,
                            num(*size),
                            num(MARGIN + left + shift + x),
                            num(baseline),
                            literal(text)
                        );
                    }
                    y -= lh;
                    fresh = false;
                }
            }
            Block::Rule { before, left, right } => {
                if !fresh {
                    y -= before;
                }
                if y - 6.0 < MARGIN && !fresh {
                    new_page(&mut pages, &mut y, &mut fresh);
                }
                let at = y - 3.0;
                let page = pages.last_mut().expect("a page");
                let _ = writeln!(
                    page,
                    "q 0.6 G 0.75 w {} {} m {} {} l S Q",
                    num(MARGIN + left),
                    num(at),
                    num(PAGE_WIDTH - MARGIN - right),
                    num(at)
                );
                y -= 6.0;
                fresh = false;
            }
            Block::PageBreak => broken = !fresh,
        }
    }
    pages
}

// =============================================================================================
// PDF

/// A PDF text string: UTF-16BE with its byte order mark, in hex.
fn text_string(s: &str) -> String {
    let mut out = String::from("<FEFF");
    for u in s.encode_utf16() {
        let _ = write!(out, "{u:04X}");
    }
    out.push('>');
    out
}

/// The document: catalog, page tree, the five standard fonts, the information dictionary, then
/// each page and its content stream, with the cross-reference table.
fn write_pdf(pages: &[String], title: Option<&str>) -> Vec<u8> {
    let mut objects: Vec<Vec<u8>> = Vec::new();
    let first_page = 3 + FONTS.len() + 1;
    let kids: Vec<String> = (0..pages.len()).map(|i| format!("{} 0 R", first_page + 2 * i)).collect();
    objects.push(b"<< /Type /Catalog /Pages 2 0 R >>".to_vec());
    objects.push(format!("<< /Type /Pages /Kids [{}] /Count {} >>", kids.join(" "), pages.len()).into_bytes());
    for font in FONTS {
        objects.push(format!("<< /Type /Font /Subtype /Type1 /BaseFont /{font} /Encoding /WinAnsiEncoding >>").into_bytes());
    }
    let mut info = String::from("<< /Producer (Modlix core)");
    if let Some(t) = title.filter(|t| !t.is_empty()) {
        let _ = write!(info, " /Title {}", text_string(t));
    }
    info.push_str(" >>");
    objects.push(info.into_bytes());
    let fonts: Vec<String> = (0..FONTS.len()).map(|i| format!("/F{} {} 0 R", i + 1, i + 3)).collect();
    for (i, content) in pages.iter().enumerate() {
        objects.push(
            format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {} {}] /Resources << /Font << {} >> >> /Contents {} 0 R >>",
                num(PAGE_WIDTH),
                num(PAGE_HEIGHT),
                fonts.join(" "),
                first_page + 2 * i + 1
            )
            .into_bytes(),
        );
        let mut stream = format!("<< /Length {} >>\nstream\n", content.len()).into_bytes();
        stream.extend_from_slice(content.as_bytes());
        stream.extend_from_slice(b"\nendstream");
        objects.push(stream);
    }

    let mut out: Vec<u8> = b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n".to_vec();
    let mut offsets = Vec::with_capacity(objects.len());
    for (i, body) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    }
    let xref = out.len();
    let mut table = format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1);
    for o in offsets {
        let _ = write!(table, "{o:010} 00000 n \n");
    }
    let _ = write!(
        table,
        "trailer\n<< /Size {} /Root 1 0 R /Info {} 0 R >>\nstartxref\n{xref}\n%%EOF\n",
        objects.len() + 1,
        3 + FONTS.len()
    );
    out.extend_from_slice(table.as_bytes());
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The text a PDF shows, page by page: each `Tj` string, lines joined by `\n` when the
    /// baseline changes, items on one line by a space.
    pub(crate) fn pdf_text(pdf: &[u8]) -> Vec<String> {
        let s = String::from_utf8_lossy(pdf).into_owned();
        let mut pages = Vec::new();
        for chunk in s.split(">>\nstream\n").skip(1) {
            let content = chunk.split("\nendstream").next().unwrap();
            let mut text = String::new();
            let mut last_y: Option<String> = None;
            for line in content.lines().filter(|l| l.starts_with("BT ")) {
                let parts: Vec<&str> = line.split(' ').collect();
                let y = parts[5].to_string();
                let open = line.find(" Td (").unwrap() + 4;
                let close = line.rfind(") Tj").unwrap();
                let raw = &line[open + 1..close];
                let mut t = String::new();
                let mut chars = raw.chars().peekable();
                while let Some(c) = chars.next() {
                    if c == '\\' {
                        let n = chars.next().unwrap();
                        if n.is_ascii_digit() {
                            let oct: String = std::iter::once(n).chain((0..2).map(|_| chars.next().unwrap())).collect();
                            t.push(u8::from_str_radix(&oct, 8).unwrap() as char);
                        } else {
                            t.push(n);
                        }
                    } else {
                        t.push(c);
                    }
                }
                match &last_y {
                    Some(prev) if *prev == y => text.push(' '),
                    Some(_) => text.push('\n'),
                    None => {}
                }
                text.push_str(&t);
                last_y = Some(y);
            }
            pages.push(text);
        }
        pages
    }

    /// The cross-reference table points at every object, `startxref` at the table, and the
    /// page tree counts the pages.
    pub(crate) fn assert_valid(pdf: &[u8]) -> usize {
        assert!(pdf.starts_with(b"%PDF-1.4\n"));
        assert!(pdf.ends_with(b"%%EOF\n"));
        let s = String::from_utf8_lossy(pdf).into_owned();
        let start: usize = s.rsplit("startxref\n").next().unwrap().lines().next().unwrap().parse().unwrap();
        assert!(pdf[start..].starts_with(b"xref\n"));
        let table = String::from_utf8_lossy(&pdf[start..]).into_owned();
        let mut rows = table.lines().skip(1);
        let count: usize = rows.next().unwrap().split(' ').nth(1).unwrap().parse().unwrap();
        let entries: Vec<&str> = rows.take(count).collect();
        assert_eq!(entries[0], "0000000000 65535 f ");
        for (n, e) in entries.iter().enumerate().skip(1) {
            assert_eq!(e.len(), 19, "{e}");
            let off: usize = e[..10].parse().unwrap();
            assert!(pdf[off..].starts_with(format!("{n} 0 obj\n").as_bytes()), "object {n}");
        }
        for (n, body) in s.split(" 0 obj\n").enumerate().skip(1) {
            if let Some(len) = body.strip_prefix("<< /Length ") {
                let len: usize = len.split(' ').next().unwrap().parse().unwrap();
                let data = body.split_once("stream\n").unwrap().1;
                assert_eq!(&data.as_bytes()[len..len + 10], b"\nendstream", "stream of object {n}");
            }
        }
        let pages = s.matches("/Type /Page ").count();
        assert!(s.contains(&format!("/Count {pages} >>")));
        assert!(s.contains("/MediaBox [0 0 595.28 841.89]"));
        pages
    }

    fn paras(html: &str) -> Vec<Block> {
        parse(html).blocks
    }

    fn words(b: &Block) -> String {
        let Block::Para { toks, .. } = b else { return "<rule>".into() };
        toks.iter()
            .map(|t| match t {
                Tok::Word(w, _) => w.iter().map(|b| char::from(*b)).collect::<String>(),
                Tok::Space(_) => " ".into(),
                Tok::Gap(_) => " | ".into(),
                Tok::Break => "\n".into(),
            })
            .collect()
    }

    #[test]
    fn a_document_becomes_paragraphs() {
        let html = r#"<!DOCTYPE html><html><head><title> The  Invoice </title><style>p { color: red } </style>
            <script>if (a < b) { document.write("<p>no</p>") }</script></head>
            <body><h1>Invoice &#35;42</h1><!-- a comment <p>hidden</p> -->
            <p>Dear   <b>Customer</b>,<br>thank&nbsp;you.</p><p>
            Total: <strong>&euro;10</strong> &amp; more</p><div style="display: none">secret</div>
            <?php echo 1 ?><p hidden>gone</p></body></html>"#;
        let doc = parse(html);
        assert_eq!(doc.title.as_deref(), Some("The Invoice"));
        let texts: Vec<String> = doc.blocks.iter().map(words).collect();
        assert_eq!(texts, ["Invoice #42", "Dear Customer,\nthank\u{A0}you.", "Total: \u{80}10 & more"]);
        let Block::Para { size, toks, before, .. } = &doc.blocks[0] else { panic!() };
        assert_eq!(*size, 24.0);
        assert!(matches!(&toks[0], Tok::Word(_, Style { bold: true, .. })));
        assert_eq!(*before, 0.67 * 24.0);
        let Block::Para { toks, before, .. } = &doc.blocks[1] else { panic!() };
        assert_eq!(*before, 0.67 * 24.0, "margins collapse to the larger");
        assert!(toks.iter().any(|t| matches!(t, Tok::Word(w, Style { bold: true, .. }) if w == b"Customer")));
    }

    #[test]
    fn lists_tables_quotes_and_rules() {
        let html = "<ul><li>one<li>two<ul><li>deep</ul></ul><ol start=3><li><p>three</p></li><li>four</ol>\
                    <table><tr><th>A<th>B</tr><tr><td>1</td><td></td><td>2</table>\
                    <blockquote>quoted</blockquote><hr><dl><dt>term<dd>meaning</dl><center>mid</center>";
        let blocks = paras(html);
        let texts: Vec<String> = blocks.iter().map(words).collect();
        assert_eq!(
            texts,
            ["\u{95} one", "\u{95} two", "\u{95} deep", "3. three", "4. four", "A | B", "1 |  | 2", "quoted", "<rule>", "term", "meaning", "mid"]
        );
        let indent = |i: usize| match &blocks[i] {
            Block::Para { left, right, .. } => (*left, *right),
            Block::Rule { left, right, .. } => (*left, *right),
            Block::PageBreak => panic!(),
        };
        assert_eq!(indent(0), (30.0, 0.0));
        assert_eq!(indent(2), (60.0, 0.0));
        assert_eq!(indent(7), (30.0, 30.0));
        assert_eq!(indent(10), (30.0, 0.0));
        assert!(matches!(&blocks[11], Block::Para { align: Align::Center, .. }));
        assert!(matches!(&blocks[5], Block::Para { toks, .. } if matches!(&toks[0], Tok::Word(_, Style { bold: true, .. }))));
    }

    #[test]
    fn pre_code_alignment_and_breaks() {
        let html = "<pre>  a  b\n\tc\r\n</pre><p>x <code>y()</code></p>\
                    <p align=right>r</p><div style='text-align:center; page-break-after: always'>c</div>\
                    <p style=\"break-before:page\">next</p><textarea>t &lt;1</textarea><xmp><b>raw</b></xmp>";
        let blocks = paras(html);
        let Block::Para { toks, pre: true, .. } = &blocks[0] else { panic!("{:?}", blocks[0]) };
        assert_eq!(words(&blocks[0]), "  a  b\n    c\n");
        assert!(matches!(&toks[2], Tok::Word(_, Style { mono: true, .. })));
        assert!(matches!(&blocks[1], Block::Para { toks, .. } if matches!(&toks[2], Tok::Word(w, Style { mono: true, .. }) if w == b"y()")));
        assert!(matches!(&blocks[2], Block::Para { align: Align::Right, .. }));
        assert!(matches!(&blocks[3], Block::Para { align: Align::Center, .. }));
        assert_eq!(blocks[4], Block::PageBreak);
        assert_eq!(blocks[5], Block::PageBreak);
        assert_eq!(words(&blocks[6]), "next");
        assert_eq!(words(&blocks[7]), "t <1");
        assert_eq!(words(&blocks[8]), "<b>raw</b>");
        // The newline after a `pre` or `textarea` start tag is not content; `</br>` is a break.
        assert_eq!(paras("<pre>\na</pre><pre>\r\nb</pre><textarea>\nc</textarea>x</br>y").iter().map(words).collect::<Vec<_>>(), ["a", "b", "c", "x\ny"]);
    }

    #[test]
    fn lenient_reading() {
        assert_eq!(paras("a < b and c<5 & d").iter().map(words).collect::<Vec<_>>(), ["a < b and c<5 & d"]);
        assert_eq!(paras("x</div></p>y").iter().map(words).collect::<Vec<_>>(), ["xy"]);
        assert_eq!(paras("<p>one<p>two<div>three</div>").iter().map(words).collect::<Vec<_>>(), ["one", "two", "three"]);
        assert_eq!(paras("<p>unterminated <b").iter().map(words).collect::<Vec<_>>(), ["unterminated"]);
        assert_eq!(paras("<p>end</").iter().map(words).collect::<Vec<_>>(), ["end</"]);
        assert_eq!(paras("<p title='a>b' data-x=\"q\" checked>v</p>").iter().map(words).collect::<Vec<_>>(), ["v"]);
        assert_eq!(paras("<img src=x.png alt=pic><br/>").iter().map(words).collect::<Vec<_>>(), ["\n"]);
        assert_eq!(paras("<style>never closed").len(), 0);
        assert_eq!(paras("<p><span>&#x1F600; &#128512; &#150; &#0; &bogus; &amp &copy2 &#; &#xZ;</span></p>").iter().map(words).collect::<Vec<_>>(), [
            "? ? \u{96} ? &bogus; & \u{A9}2 &#; &#xZ;"
        ]);
        assert_eq!(paras("<p>\u{200B}zero\u{2009}thin \u{2212}1 \u{4E2D}</p>").iter().map(words).collect::<Vec<_>>(), ["zero thin -1 ?"]);
        // A list item's marker waits for its text; an empty item shows nothing.
        assert_eq!(paras("<ul><li></li><li>x</li></ul>").iter().map(words).collect::<Vec<_>>(), ["\u{95} x"]);
        assert_eq!(paras("<table><tbody><tr><td>a<tbody><tr><td>b</table>").iter().map(words).collect::<Vec<_>>(), ["a", "b"]);
        assert_eq!(paras("<hr style='display:none'><div hidden><br><hr></div>").len(), 0);
        assert_eq!(decode("&lt;&gt"), "<>");
        assert_eq!(reference_char(0x81), '\u{81}');
        assert_eq!(declarations("COLOR : Red ; text-align:CENTER !important"), [("color".to_string(), "red".to_string()), ("text-align".into(), "center".into())]);
        assert_eq!(align_of("weird"), None);
        assert_eq!(align_of("left"), Some(Align::Left));
        assert_eq!(paras("<table><tr><td>a<tr><td>b</table>x</p").iter().map(words).collect::<Vec<_>>(), ["a", "b", "x"]);
    }

    #[test]
    fn headings_and_inline_styles() {
        let blocks = paras("<h3>c</h3><h4>d</h4><h5>e</h5><h6>f</h6><p><em>i</em><address>a</address></p>");
        let sizes: Vec<(f32, f32)> = blocks
            .iter()
            .map(|b| match b {
                Block::Para { size, before, .. } => (*size, *before),
                _ => panic!(),
            })
            .collect();
        assert_eq!(sizes, [(14.0, 14.0), (12.0, 1.33 * 12.0), (10.0, 1.67 * 10.0), (8.0, 2.33 * 8.0), (12.0, 2.33 * 8.0), (12.0, 12.0)]);
        assert!(matches!(&blocks[4], Block::Para { toks, .. } if matches!(&toks[0], Tok::Word(_, Style { italic: true, bold: false, .. }))));
        assert!(matches!(&blocks[5], Block::Para { toks, .. } if matches!(&toks[0], Tok::Word(_, Style { italic: true, .. }))));
    }

    #[test]
    fn words_wrap_and_long_words_break() {
        let toks: Vec<Tok> = (0..40)
            .flat_map(|i| [Tok::Word(format!("word{i}").into_bytes(), Style::default()), Tok::Space(Style::default())])
            .collect();
        let ls = lines(&toks, 12.0, 200.0, false);
        assert!(ls.len() > 5);
        for l in &ls {
            assert!(l.width <= 200.0, "{}", l.width);
            assert_eq!(l.items.len(), 1, "plain spaces join one run");
        }
        let long = vec![Tok::Word(vec![b'W'; 100], Style { bold: true, ..Default::default() })];
        let ls = lines(&long, 12.0, 100.0, false);
        assert!(ls.len() > 5);
        assert!(ls.iter().all(|l| l.width <= 100.0));
        assert_eq!(ls.iter().map(|l| l.items[0].1.len()).sum::<usize>(), 100);
        // Leading spaces of a pre line are kept; a narrow room still takes one character.
        let ls = lines(&[Tok::Space(Style::default()), Tok::Word(b"ab".to_vec(), Style::default())], 12.0, 100.0, true);
        assert!(ls[0].items[0].0 > 0.0);
        assert_eq!(fit(b"abc", Style::default(), 12.0, 0.1), 1);
        // A gap separates runs; a break makes an empty line.
        let ls = lines(&[Tok::Word(b"a".to_vec(), Style::default()), Tok::Gap(18.0), Tok::Word(b"b".to_vec(), Style::default()), Tok::Break, Tok::Break], 12.0, 100.0, false);
        assert_eq!(ls.len(), 2);
        assert_eq!(ls[0].items.len(), 2);
        assert!(ls[1].items.is_empty());
    }

    #[test]
    fn a_valid_a4_pdf_over_pages() {
        let mut html = String::from("<title>Report \u{2013} \u{4E2D}</title><h2 style='text-align:right'>Report (draft) \\ 1</h2>");
        for i in 0..120 {
            html.push_str(&format!("<p>Paragraph {i}: the quick brown fox jumps over the lazy dog, caf\u{E9} na\u{EF}ve.</p>"));
        }
        html.push_str("<hr><p style='text-align:center'>end</p>");
        let pdf = html_to_pdf(&html);
        let pages = assert_valid(&pdf);
        assert!(pages >= 3, "{pages}");
        let text = pdf_text(&pdf);
        assert_eq!(text.len(), pages);
        assert!(text[0].starts_with("Report (draft) \\ 1\nParagraph 0: the quick brown fox"));
        assert!(text[0].contains("caf\u{E9} na\u{EF}ve."));
        assert!(text.last().unwrap().ends_with("end"));
        let s = String::from_utf8_lossy(&pdf);
        assert!(s.contains("/Title <FEFF005200650070006F007200740020201300204E2D>"));
        assert!(s.contains("/BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding"));
        assert!(s.contains(" l S Q"));
        // Nothing to show is still one page.
        let empty = html_to_pdf("<html><body><!-- --></body></html>");
        assert_eq!(assert_valid(&empty), 1);
        assert!(!String::from_utf8_lossy(&empty).contains("/Title"));
        // Page breaks, and a rule at the foot of a full page.
        let broken = html_to_pdf("<p>a</p><div style='page-break-before:always'>b</div><p style='page-break-after:always'>c</p>");
        assert_eq!(pdf_text(&broken), ["a", "b\nc"]);
        let broken = html_to_pdf("<p style='page-break-after:always'>c</p><p style='page-break-before:always'>d</p>");
        assert_eq!(pdf_text(&broken), ["c", "d"]);
        // 53 lines fill a page: the rule goes to the next.
        let mut full = "<br>".repeat(53);
        full.push_str("<hr>x");
        assert_eq!(assert_valid(&html_to_pdf(&full)), 2);
    }

    #[test]
    fn operands_and_strings() {
        assert_eq!(num(1.0), "1");
        assert_eq!(num(-0.001), "0");
        assert_eq!(num(12.345), "12.35");
        assert_eq!(literal(&[b'(', b'a', b')', b'\\', 0x80, 0x0A]), "(\\(a\\)\\\\\\200\\012)");
        assert_eq!(text_string("A"), "<FEFF0041>");
        assert_eq!(win_ansi('\u{20AC}'), Some(0x80));
        assert_eq!(win_ansi('\u{9}'), None);
        assert_eq!(char_width(b'W', Style { mono: true, ..Default::default() }), 600.0);
        assert_eq!(char_width(0x10, Style::default()), 278.0);
        assert_eq!(Style { bold: true, italic: true, mono: false }.font(), 3);
    }
}
