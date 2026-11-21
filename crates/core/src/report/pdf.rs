//! `CoreServices.Report.Pdf(document)` (CXZ-1780 P1b, CONTRACT 8.2): a dashboard or widget the
//! caller already has on screen, as a print friendly PDF.
//!
//! `document = {"title", "subtitle", "generatedAt", "locale", "items": [{"name", "subtitle",
//! "image": "data:image/png;base64,...", "columns": [...], "rows": [...]}]}`; at most 24 items,
//! 200 rows an item, 8 MB in all. The HTML is built here (plain, theme neutral, every text
//! escaped, images only PNG data URLs) and rendered by the pdf-render sidecar through
//! [`crate::pdf_render::render`], as `CoreServices.File.TemplateToPdf` renders; never a third
//! party. Nothing is read from or written to any storage or the files service: the data is the
//! caller's own screen, so there is no scope check, and the app's wrapper (`<App>.reportPdf`)
//! decides who may export (the function is reachable only inside a KIRun definition).
//!
//! Output `result`: `{"ok": true, "fileName": "Sales dashboard 2026-11-21.pdf", "contentType":
//! "application/pdf", "size": <bytes>, "sha256": "<hex>", "data": "data:application/pdf;base64,..."}`
//! (the UI turns `data` into a Blob and downloads it as `fileName`), or `{"ok": false, "error":
//! {"code", "message", "path"}}` with TOO_MANY, TOO_LARGE, BAD_KIND or PDF_FAILED.

use async_trait::async_trait;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde_json::{json, Value};

use super::spec::{Obj, ReportError, R};

pub const MAX_ITEMS: usize = 24;
pub const MAX_ROWS: usize = 200;
pub const MAX_COLUMNS: usize = 40;
/// The whole document as JSON.
pub const MAX_BYTES: usize = 8 * 1024 * 1024;
const PNG_PREFIX: &str = "data:image/png;base64,";
const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";

/// Where the HTML becomes a PDF (the sidecar live, a fake in tests).
#[async_trait]
pub trait HtmlToPdf: Send + Sync {
    async fn render(&self, html: String) -> Result<Vec<u8>, String>;
}

/// The process's renderer: the pdf-render sidecar from `[pdf] upstream`, as TemplateToPdf uses.
pub struct LiveRenderer;

#[async_trait]
impl HtmlToPdf for LiveRenderer {
    async fn render(&self, html: String) -> Result<Vec<u8>, String> {
        crate::pdf_render::render(html).await
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Column {
    pub key: String,
    pub label: String,
    pub format: Option<String>,
    pub currency: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Item {
    pub name: String,
    pub subtitle: Option<String>,
    /// The base64 of a PNG (checked), without the data URL prefix.
    pub image: Option<String>,
    pub columns: Vec<Column>,
    /// One text per column.
    pub rows: Vec<Vec<Cell>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Cell {
    pub text: String,
    pub number: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Document {
    pub title: String,
    pub subtitle: Option<String>,
    pub generated_at: Option<String>,
    pub locale: Option<String>,
    pub items: Vec<Item>,
}

fn err<T>(code: &'static str, path: impl Into<String>, message: impl Into<String>) -> R<T> {
    Err(ReportError::new(code, path, message))
}

fn keys(o: &Obj, known: &[&str], path: &str) -> R<()> {
    match o.keys().find(|k| !known.contains(&k.as_str())) {
        Some(k) => err("BAD_KIND", format!("{path}.{k}"), format!("'{k}' is not something {path} takes ({}).", known.join(", "))),
        None => Ok(()),
    }
}

fn text(o: &Obj, k: &str, path: &str) -> R<Option<String>> {
    match o.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.trim().is_empty() => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.trim().to_string())),
        Some(_) => err("BAD_KIND", format!("{path}.{k}"), format!("{path}.{k} must be a text.")),
    }
}

/// Validates the document and reads it into what the HTML shows.
pub fn parse(doc: &Value) -> R<Document> {
    let Value::Object(o) = doc else { return err("BAD_KIND", "document", "The document must be an object.") };
    let size = doc.to_string().len();
    if size > MAX_BYTES {
        return err("TOO_LARGE", "document", format!("The document is {:.1} MB; at most 8 MB can be printed.", size as f64 / 1_048_576.0));
    }
    keys(o, &["title", "subtitle", "generatedAt", "locale", "items"], "document")?;
    let items_in = match o.get("items") {
        None | Some(Value::Null) => &[][..],
        Some(Value::Array(a)) => a.as_slice(),
        Some(_) => return err("BAD_KIND", "document.items", "document.items must be a list."),
    };
    if items_in.len() > MAX_ITEMS {
        return err("TOO_MANY", "document.items", format!("A PDF takes at most {MAX_ITEMS} items; this one has {}.", items_in.len()));
    }
    let locale = text(o, "locale", "document")?;
    let indian = locale.as_deref().is_some_and(|l| l.to_ascii_uppercase().ends_with("-IN"));
    let mut items = Vec::new();
    for (i, it) in items_in.iter().enumerate() {
        items.push(parse_item(it, &format!("document.items[{i}]"), indian)?);
    }
    Ok(Document {
        title: text(o, "title", "document")?.unwrap_or_else(|| "Report".into()),
        subtitle: text(o, "subtitle", "document")?,
        generated_at: text(o, "generatedAt", "document")?,
        locale,
        items,
    })
}

fn parse_item(v: &Value, path: &str, indian: bool) -> R<Item> {
    let Value::Object(o) = v else { return err("BAD_KIND", path, format!("{path} must be an object.")) };
    keys(o, &["name", "subtitle", "image", "columns", "rows"], path)?;
    let image = match text(o, "image", path)? {
        None => None,
        Some(url) => {
            let Some(b64) = url.strip_prefix(PNG_PREFIX) else {
                return err("BAD_KIND", format!("{path}.image"), "An image must be a PNG data URL (data:image/png;base64,...).");
            };
            let ok = base64::engine::general_purpose::STANDARD.decode(b64.as_bytes()).is_ok_and(|b| b.starts_with(PNG_MAGIC));
            if !ok {
                return err("BAD_KIND", format!("{path}.image"), "The image is not a PNG.");
            }
            Some(b64.to_string())
        }
    };
    let columns_in = match o.get("columns") {
        None | Some(Value::Null) => &[][..],
        Some(Value::Array(a)) => a.as_slice(),
        Some(_) => return err("BAD_KIND", format!("{path}.columns"), format!("{path}.columns must be a list.")),
    };
    // A column is a key (its own label) or a Run output column: hidden ones are left out, and
    // keys other than key / label / format / currency / hidden are ignored.
    let mut columns = Vec::new();
    for (j, c) in columns_in.iter().enumerate() {
        let cp = format!("{path}.columns[{j}]");
        match c {
            Value::String(k) if !k.trim().is_empty() => columns.push(Column { key: k.clone(), label: k.clone(), format: None, currency: None }),
            Value::Object(co) => {
                if matches!(co.get("hidden"), Some(Value::Bool(true))) {
                    continue;
                }
                let key = match co.get("key") {
                    Some(Value::String(k)) => k.clone(),
                    None | Some(Value::Null) => String::new(),
                    Some(_) => return err("BAD_KIND", format!("{cp}.key"), format!("{cp}.key must be a text.")),
                };
                let label = text(co, "label", &cp)?.unwrap_or_else(|| key.clone());
                columns.push(Column { key, label, format: text(co, "format", &cp)?, currency: text(co, "currency", &cp)? });
            }
            _ => return err("BAD_KIND", cp.clone(), format!("{cp} must be a column key or an object with key and label.")),
        }
    }
    if columns.len() > MAX_COLUMNS {
        return err("TOO_MANY", format!("{path}.columns"), format!("A table in the PDF takes at most {MAX_COLUMNS} columns."));
    }
    let rows_in = match o.get("rows") {
        None | Some(Value::Null) => &[][..],
        Some(Value::Array(a)) => a.as_slice(),
        Some(_) => return err("BAD_KIND", format!("{path}.rows"), format!("{path}.rows must be a list.")),
    };
    if rows_in.len() > MAX_ROWS {
        return err("TOO_MANY", format!("{path}.rows"), format!("A table in the PDF takes at most {MAX_ROWS} rows; this one has {}.", rows_in.len()));
    }
    if !rows_in.is_empty() && columns.is_empty() {
        return err("BAD_KIND", format!("{path}.columns"), "Rows need columns (their labels head the table).");
    }
    let mut rows = Vec::new();
    for (j, r) in rows_in.iter().enumerate() {
        let cells: Vec<Cell> = match r {
            // A row object: the value by column key, its `<key>_label` when it has one.
            Value::Object(ro) => columns
                .iter()
                .map(|c| match ro.get(&format!("{}_label", c.key)).filter(|v| !v.is_null()) {
                    Some(l) => cell(l, &Column { format: None, ..c.clone() }, indian),
                    None => cell(ro.get(&c.key).unwrap_or(&Value::Null), c, indian),
                })
                .collect(),
            // A row list: values by position.
            Value::Array(a) => columns.iter().enumerate().map(|(k, c)| cell(a.get(k).unwrap_or(&Value::Null), c, indian)).collect(),
            _ => return err("BAD_KIND", format!("{path}.rows[{j}]"), format!("{path}.rows[{j}] must be an object or a list.")),
        };
        rows.push(cells);
    }
    Ok(Item { name: text(o, "name", path)?.unwrap_or_default(), subtitle: text(o, "subtitle", path)?, image, columns, rows })
}

/// A value as the table shows it; `indian` groups digits as the en-IN locale does (12,34,567).
fn cell(v: &Value, c: &Column, indian: bool) -> Cell {
    match v {
        Value::Null => Cell { text: String::new(), number: false },
        Value::Bool(b) => Cell { text: if *b { "Yes" } else { "No" }.into(), number: false },
        Value::String(s) => Cell { text: s.clone(), number: false },
        Value::Number(n) => {
            let x = n.as_f64().unwrap_or(0.0);
            let text = match c.format.as_deref() {
                Some("PERCENT") => format!("{}%", group(x, 1, indian)),
                Some("MONEY") => match &c.currency {
                    Some(cur) => format!("{cur} {}", group(x, 2, indian)),
                    None => group(x, 2, indian),
                },
                _ => group(x, 2, indian),
            };
            Cell { text, number: true }
        }
        other => Cell { text: other.to_string(), number: false },
    }
}

/// `x` with at most `decimals` decimals (trailing zeros dropped) and digit group separators:
/// thousands (1,234,567), or the last three then pairs (12,34,567) when `indian`.
pub fn group(x: f64, decimals: usize, indian: bool) -> String {
    if !x.is_finite() {
        return String::new();
    }
    let s = format!("{:.*}", decimals, x.abs());
    let (int, frac) = s.split_once('.').unwrap_or((&s, ""));
    let frac = frac.trim_end_matches('0');
    let mut out = String::new();
    for (i, ch) in int.chars().enumerate() {
        let left = int.len() - i;
        let cut = if indian { left == 3 || (left > 3 && (left - 3) % 2 == 0) } else { left % 3 == 0 };
        if i > 0 && cut {
            out.push(',');
        }
        out.push(ch);
    }
    let sign = if x < 0.0 && (int != "0" || !frac.is_empty()) { "-" } else { "" };
    if frac.is_empty() {
        format!("{sign}{out}")
    } else {
        format!("{sign}{out}.{frac}")
    }
}

/// HTML text: `& < > " '` escaped.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c if c.is_control() && c != '\n' && c != '\t' => {}
            c => out.push(c),
        }
    }
    out
}

/// "21 Nov 2026, 17:42 (UTC+05:30)" for an RFC 3339 time; any other text as given; now (UTC)
/// when none.
fn generated_on(given: Option<&str>, now: DateTime<Utc>) -> String {
    match given {
        Some(g) => match DateTime::parse_from_rfc3339(g) {
            Ok(t) => {
                let off = t.offset().local_minus_utc();
                let zone = if off == 0 {
                    "UTC".to_string()
                } else {
                    format!("UTC{}{:02}:{:02}", if off < 0 { '-' } else { '+' }, off.abs() / 3600, (off.abs() % 3600) / 60)
                };
                format!("{} ({zone})", t.format("%-d %b %Y, %H:%M"))
            }
            Err(_) => g.to_string(),
        },
        None => format!("{} (UTC)", now.format("%-d %b %Y, %H:%M")),
    }
}

const STYLE: &str = "@page { size: A4; margin: 14mm 12mm 16mm 12mm; \
@bottom-right { content: \"Page \" counter(page) \" of \" counter(pages); font-size: 8pt; color: #666; } }\
body { font-family: 'DejaVu Sans', Arial, Helvetica, sans-serif; font-size: 9pt; color: #111; margin: 0; }\
h1 { font-size: 17pt; margin: 0 0 1mm 0; font-weight: 600; }\
.doc-sub { color: #444; font-size: 10pt; margin: 0 0 1mm 0; }\
.generated { color: #777; font-size: 8pt; margin: 0 0 6mm 0; }\
.item { margin: 0 0 8mm 0; }\
.item-head { break-inside: avoid; break-after: avoid; }\
h2 { font-size: 12pt; margin: 0 0 1mm 0; font-weight: 600; }\
.item-sub { color: #555; font-size: 8.5pt; margin: 0 0 2mm 0; }\
.chart { text-align: center; margin: 1mm 0 3mm 0; break-inside: avoid; }\
.chart img { max-width: 100%; max-height: 115mm; }\
table { width: 100%; border-collapse: collapse; }\
thead { display: table-header-group; }\
tr { break-inside: avoid; }\
th { text-align: left; font-weight: 600; background: #f2f2f2; border-bottom: 1px solid #bbb; padding: 3px 5px; }\
td { border-bottom: 1px solid #e3e3e3; padding: 3px 5px; vertical-align: top; }\
.num { text-align: right; white-space: nowrap; }";

/// The print friendly HTML of a validated document.
pub fn html(doc: &Document, now: DateTime<Utc>) -> String {
    let lang = doc.locale.as_deref().filter(|l| l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')).unwrap_or("en");
    let mut h = String::new();
    h.push_str(&format!(
        "<!DOCTYPE html><html lang=\"{}\"><head><meta charset=\"utf-8\"><title>{}</title><style>{STYLE}</style></head><body>",
        escape(lang),
        escape(&doc.title)
    ));
    h.push_str(&format!("<h1>{}</h1>", escape(&doc.title)));
    if let Some(s) = &doc.subtitle {
        h.push_str(&format!("<div class=\"doc-sub\">{}</div>", escape(s)));
    }
    h.push_str(&format!("<div class=\"generated\">Generated on {}</div>", escape(&generated_on(doc.generated_at.as_deref(), now))));
    for it in &doc.items {
        h.push_str("<section class=\"item\"><div class=\"item-head\">");
        if !it.name.is_empty() {
            h.push_str(&format!("<h2>{}</h2>", escape(&it.name)));
        }
        if let Some(s) = &it.subtitle {
            h.push_str(&format!("<div class=\"item-sub\">{}</div>", escape(s)));
        }
        h.push_str("</div>");
        if let Some(b64) = &it.image {
            // The base64 alphabet has no quote or angle bracket; checked as a PNG in `parse`.
            h.push_str(&format!("<div class=\"chart\"><img alt=\"{}\" src=\"{PNG_PREFIX}{}\"></div>", escape(&it.name), escape(b64)));
        }
        if !it.columns.is_empty() {
            h.push_str("<table><thead><tr>");
            let numeric: Vec<bool> = (0..it.columns.len()).map(|k| !it.rows.is_empty() && it.rows.iter().all(|r| r[k].number || r[k].text.is_empty())).collect();
            for (k, c) in it.columns.iter().enumerate() {
                let class = if numeric[k] { " class=\"num\"" } else { "" };
                h.push_str(&format!("<th{class}>{}</th>", escape(&c.label)));
            }
            h.push_str("</tr></thead><tbody>");
            for r in &it.rows {
                h.push_str("<tr>");
                for (k, c) in r.iter().enumerate() {
                    let class = if numeric[k] || c.number { " class=\"num\"" } else { "" };
                    h.push_str(&format!("<td{class}>{}</td>", escape(&c.text)));
                }
                h.push_str("</tr>");
            }
            h.push_str("</tbody></table>");
        }
        h.push_str("</section>");
    }
    h.push_str("</body></html>");
    h
}

/// "Sales dashboard 2026-11-21.pdf": the title (letters, digits, spaces, `-` and `_`) and the date
/// it was generated on.
pub fn file_name(doc: &Document, now: DateTime<Utc>) -> String {
    let mut name: String = doc.title.chars().map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { ' ' }).collect();
    name = name.split_whitespace().collect::<Vec<_>>().join(" ");
    let name: String = name.chars().take(80).collect();
    let name = if name.trim().is_empty() { "Report".to_string() } else { name.trim().to_string() };
    let date = doc
        .generated_at
        .as_deref()
        .and_then(|g| DateTime::parse_from_rfc3339(g).ok())
        .map(|t| t.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| now.format("%Y-%m-%d").to_string());
    format!("{name} {date}.pdf")
}

/// Validates, builds the HTML and renders it. Never fails: a refusal is the output.
pub async fn make(document: &Value, now: DateTime<Utc>, renderer: &dyn HtmlToPdf) -> Value {
    let doc = match parse(document) {
        Ok(d) => d,
        Err(e) => return e.to_json(),
    };
    let html = html(&doc, now);
    match renderer.render(html).await {
        Ok(pdf) if pdf.starts_with(b"%PDF") => {
            use sha2::Digest;
            json!({
                "ok": true,
                "fileName": file_name(&doc, now),
                "contentType": "application/pdf",
                "size": pdf.len(),
                "sha256": hex::encode(sha2::Sha256::digest(&pdf)),
                "data": format!("data:application/pdf;base64,{}", base64::engine::general_purpose::STANDARD.encode(&pdf)),
            })
        }
        Ok(_) => ReportError::new("PDF_FAILED", "document", "The PDF could not be made: the renderer answered something else.").to_json(),
        Err(why) => ReportError::new("PDF_FAILED", "document", format!("The PDF could not be made: {why}")).to_json(),
    }
}
