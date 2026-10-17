//! Storage rows as files and back: `DataFileType`, `DataFileWriter` and `DataFileReader`
//! (commons `util` / `file`), the header list a storage's schema gives
//! (`AppDataService.getHeaders`), and the conversion of a flat file's text cells
//! (`getElementBySchemaType`, `MapUtil.setValueInMap`).
//!
//! The writers produce what the Java ones do byte for byte, except XLSX, which is the same
//! zip entries with the same contents (a zip's compressed bytes and timestamps differ by
//! implementation).

use std::io::{Cursor, Read, Write};

use appdata::value::{Document, Value};
use futures::future::BoxFuture;
use futures::FutureExt;
use indexmap::{IndexMap, IndexSet};
use kirun::json::schema::r#type::SchemaType;
use kirun::json::schema::schema_util::SchemaUtil;
use kirun::json::schema::Schema;
use kirun::repository::Repository;

use super::values::{gson_tree, hash_map_order, plain_gson_map};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataFileType {
    Csv,
    Xls,
    Xlsx,
    Tsv,
    Json,
    Jsonl,
}

impl DataFileType {
    pub const ALL: [DataFileType; 6] =
        [DataFileType::Csv, DataFileType::Xls, DataFileType::Xlsx, DataFileType::Tsv, DataFileType::Json, DataFileType::Jsonl];

    pub fn name(self) -> &'static str {
        match self {
            DataFileType::Csv => "CSV",
            DataFileType::Xls => "XLS",
            DataFileType::Xlsx => "XLSX",
            DataFileType::Tsv => "TSV",
            DataFileType::Json => "JSON",
            DataFileType::Jsonl => "JSONL",
        }
    }

    /// `DataFileType.valueOf`: the exact constant name.
    pub fn value_of(s: &str) -> Option<DataFileType> {
        Self::ALL.into_iter().find(|t| t.name() == s)
    }

    pub fn mime_type(self) -> &'static str {
        match self {
            DataFileType::Csv => "text/csv",
            DataFileType::Xls => "application/x-excel",
            DataFileType::Xlsx => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            DataFileType::Tsv => "text/tab-separated-values",
            DataFileType::Json => "application/json",
            DataFileType::Jsonl => "application/x-jsonlines",
        }
    }

    pub fn is_nested_structure(self) -> bool {
        matches!(self, DataFileType::Json | DataFileType::Jsonl)
    }

    /// `getFileTypeFromExtension`: what follows the last dot, upper-cased.
    pub fn from_extension(file_name: &str) -> Result<DataFileType, String> {
        let ext = match file_name.rfind('.') {
            Some(i) => &file_name[i + 1..],
            None => file_name,
        };
        let upper = ext.to_uppercase();
        Self::value_of(&upper)
            .ok_or_else(|| format!("No enum constant com.fincity.saas.commons.util.DataFileType.{upper}"))
    }
}

// ---------------------------------------------------------------------- writer

const XLS_START: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<?mso-application progid="Excel.Sheet"?>
<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet" xmlns:o="urn:schemas-microsoft-com:office:office"
xmlns:x="urn:schemas-microsoft-com:office:excel" xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet" xmlns:html="http://www.w3.org/TR/REC-html40">
<Worksheet ss:Name="Sheet1">
<Table>"#;

const XLSX_PARTS: &[(&str, &str)] = &[
    ("[Content_Types].xml", "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/xl/sharedStrings.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml\"/><Override PartName=\"/xl/styles.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml\"/><Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml\"/><Override PartName=\"/xl/worksheets/sheet1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/><Override PartName=\"/docProps/core.xml\" ContentType=\"application/vnd.openxmlformats-package.core-properties+xml\"/><Override PartName=\"/docProps/app.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.extended-properties+xml\"/></Types>"),
    ("_rels/.rels", "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId3\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties\" Target=\"docProps/app.xml\"/><Relationship Id=\"rId2\" Type=\"http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties\" Target=\"docProps/core.xml\"/><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"xl/workbook.xml\"/></Relationships>"),
    ("docProps/app.xml", "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Properties xmlns=\"http://schemas.openxmlformats.org/officeDocument/2006/extended-properties\"><Application>Prime Unilog Platform</Application><AppVersion>1.0</AppVersion></Properties>"),
    ("docProps/core.xml", "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?><cp:coreProperties xmlns:cp=\"http://schemas.openxmlformats.org/package/2006/metadata/core-properties\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:dcterms=\"http://purl.org/dc/terms/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"><dcterms:created xsi:type=\"dcterms:W3CDTF\">2018-08-25T07:28:42.72846Z</dcterms:created><dc:creator>Prime Unilog Platform</dc:creator></cp:coreProperties>"),
    ("xl/_rels/workbook.xml.rels", "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Target=\"sharedStrings.xml\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings\"/><Relationship Id=\"rId2\" Target=\"styles.xml\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles\"/><Relationship Id=\"rId3\" Target=\"worksheets/sheet1.xml\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\"/></Relationships>"),
    ("xl/sharedStrings.xml", "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><sst xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" count=\"0\" uniqueCount=\"0\"></sst>"),
    ("xl/styles.xml", "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><styleSheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" xmlns:mc=\"http://schemas.openxmlformats.org/markup-compatibility/2006\" mc:Ignorable=\"x14ac x16r2 xr\" xmlns:x14ac=\"http://schemas.microsoft.com/office/spreadsheetml/2009/9/ac\" xmlns:x16r2=\"http://schemas.microsoft.com/office/spreadsheetml/2015/02/main\" xmlns:xr=\"http://schemas.microsoft.com/office/spreadsheetml/2014/revision\"><fonts count=\"1\" x14ac:knownFonts=\"1\"><font><sz val=\"11\"/><color rgb=\"FF000000\"/><name val=\"Calibri\"/></font></fonts><fills count=\"2\"><fill><patternFill patternType=\"none\"/></fill><fill><patternFill patternType=\"gray125\"/></fill></fills><borders count=\"1\"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count=\"1\"><xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"0\"/></cellStyleXfs><cellXfs count=\"1\"><xf numFmtId=\"49\" fontId=\"0\" fillId=\"0\" borderId=\"0\" xfId=\"0\" applyNumberFormat=\"1\"/></cellXfs><cellStyles count=\"1\"><cellStyle name=\"Normal\" xfId=\"0\" builtinId=\"0\"/></cellStyles><dxfs count=\"0\"/><tableStyles count=\"0\" defaultTableStyle=\"TableStyleMedium2\" defaultPivotStyle=\"PivotStyleLight16\"/><extLst><ext uri=\"{EB79DEF2-80B8-43e5-95BD-54CBDDF9020C}\" xmlns:x14=\"http://schemas.microsoft.com/office/spreadsheetml/2009/9/main\"><x14:slicerStyles defaultSlicerStyle=\"SlicerStyleLight1\"/></ext><ext uri=\"{9260A510-F301-46a8-8635-F512D64BE5F5}\" xmlns:x15=\"http://schemas.microsoft.com/office/spreadsheetml/2010/11/main\"><x15:timelineStyles defaultTimelineStyle=\"TimeSlicerStyleLight1\"/></ext></extLst></styleSheet>"),
    ("xl/workbook.xml", "<?xml version=\"1.0\" encoding=\"UTF-8\"?><workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"><workbookPr date1904=\"false\"/><bookViews><workbookView activeTab=\"0\"/></bookViews><sheets><sheet name=\"Sheet1\" r:id=\"rId3\" sheetId=\"1\"/></sheets></workbook>"),
];

const XLSX_SHEET_START: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><dimension ref=\"A1\"/><sheetViews><sheetView workbookViewId=\"0\"/></sheetViews><sheetFormatPr defaultRowHeight=\"15.0\"/><sheetData>";
const XLSX_SHEET_END: &str = "</sheetData><pageMargins bottom=\"0.75\" footer=\"0.3\" header=\"0.3\" left=\"0.7\" right=\"0.7\" top=\"0.75\"/></worksheet>";

/// `DataFileWriter` over an in-memory stream.
pub struct DataFileWriter {
    header: Option<Vec<String>>,
    file_type: DataFileType,
    write_header: bool,
    header_written: bool,
    first_line: bool,
    out: Vec<u8>,
    zip: Option<zip::ZipWriter<Cursor<Vec<u8>>>>,
}

fn io(e: impl std::fmt::Display) -> String {
    e.to_string()
}

impl DataFileWriter {
    pub fn new(header: Option<Vec<String>>, file_type: DataFileType, write_header: bool) -> Self {
        Self { header, file_type, write_header, header_written: false, first_line: true, out: Vec::new(), zip: None }
    }

    fn null_header() -> String {
        "Cannot invoke \"java.util.List.stream()\" because \"this.header\" is null".into()
    }

    /// One row; values written are `toString()` of the row's values (flat files) or the
    /// row as JSON (nested files).
    pub fn write(&mut self, row: &Document) -> Result<(), String> {
        if self.file_type == DataFileType::Xlsx && self.zip.is_none() {
            self.zip = Some(zip::ZipWriter::new(Cursor::new(Vec::new())));
        }
        if !self.header_written {
            self.write_starting_of_file()?;
            if self.write_header && !self.file_type.is_nested_structure() {
                let header = self.header.clone().ok_or_else(Self::null_header)?;
                self.write_line(&header)?;
            }
            self.header_written = true;
        }
        if !self.file_type.is_nested_structure() {
            let header = self.header.clone().ok_or_else(Self::null_header)?;
            let line: Vec<String> = header.iter().map(|h| row.get(h).map(Value::java_string).unwrap_or_default()).collect();
            self.write_line(&line)?;
        } else {
            if !self.first_line {
                self.out.extend_from_slice(if self.file_type == DataFileType::Json { b",\n" } else { b"\n" });
            }
            let tree = gson_tree(&Value::Object(row.clone())).map_err(|e| e.text())?;
            self.out.extend_from_slice(crate::gson::to_gson(&tree).as_bytes());
        }
        self.first_line = false;
        Ok(())
    }

    fn write_starting_of_file(&mut self) -> Result<(), String> {
        match self.file_type {
            DataFileType::Xls => {
                self.out.extend_from_slice(XLS_START.as_bytes());
                let n = self.header.as_ref().ok_or_else(|| {
                    "Cannot invoke \"java.util.List.size()\" because \"this.header\" is null".to_string()
                })?;
                for i in 1..=n.len() {
                    self.out
                        .extend_from_slice(format!("<Column ss:Index=\"{i}\" ss:AutoFitWidth=\"0\" ss:Width=\"110\"/>").as_bytes());
                }
            }
            DataFileType::Xlsx => {
                let zip = self.zip.as_mut().expect("created");
                let opts = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
                for (name, content) in XLSX_PARTS {
                    zip.start_file(*name, opts).map_err(io)?;
                    zip.write_all(content.as_bytes()).map_err(io)?;
                }
                zip.start_file("xl/worksheets/sheet1.xml", opts).map_err(io)?;
                zip.write_all(XLSX_SHEET_START.as_bytes()).map_err(io)?;
            }
            DataFileType::Json => self.out.push(b'['),
            _ => {}
        }
        Ok(())
    }

    fn write_line(&mut self, line: &[String]) -> Result<(), String> {
        let joined = |sep: &str, prefix: &str, suffix: &str| format!("{prefix}{}{suffix}", line.join(sep));
        match self.file_type {
            DataFileType::Csv => {
                let cols: Vec<String> = line.iter().map(|e| single_column_convert(e, ',')).collect();
                self.out.extend_from_slice(format!("{}\n", cols.join(",")).as_bytes());
            }
            DataFileType::Tsv => {
                let cols: Vec<String> = line.iter().map(|e| single_column_convert(e, '\t')).collect();
                self.out.extend_from_slice(format!("{}\n", cols.join("\t")).as_bytes());
            }
            DataFileType::Xls => {
                let s = joined(
                    "</Data></Cell><Cell><Data ss:Type=\"String\">",
                    "<Row><Cell><Data ss:Type=\"String\">",
                    "</Data></Cell></Row>",
                );
                self.out.extend_from_slice(s.as_bytes());
            }
            DataFileType::Xlsx => {
                let s = joined(
                    "</t></is></c><c t=\"inlineStr\"><is><t>",
                    "<row><c t=\"inlineStr\"><is><t>",
                    "</t></is></c></row>",
                );
                self.zip.as_mut().expect("created").write_all(s.as_bytes()).map_err(io)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// `close()`: the file's tail. An XLSX nothing was written to fails as Java's does (its
    /// zip stream is only made by the first write).
    pub fn finish(mut self) -> Result<Vec<u8>, String> {
        match self.file_type {
            DataFileType::Xls => self.out.extend_from_slice(b"</Table>\n</Worksheet>\n</Workbook>"),
            DataFileType::Xlsx => {
                let Some(mut zip) = self.zip.take() else {
                    return Err("Cannot invoke \"java.util.zip.ZipOutputStream.write(byte[])\" because \"this.zos\" is null".into());
                };
                zip.write_all(XLSX_SHEET_END.as_bytes()).map_err(io)?;
                return Ok(zip.finish().map_err(io)?.into_inner());
            }
            DataFileType::Json => self.out.push(b']'),
            _ => {}
        }
        Ok(self.out)
    }
}

/// `singleColumnConvert`: quoted (inner quotes doubled) when it holds a quote, the
/// delimiter, or a line break.
pub fn single_column_convert(e: &str, delim: char) -> String {
    let has_quotes = e.contains('"');
    let s = if has_quotes { e.replace('"', "\"\"") } else { e.to_string() };
    if has_quotes || e.contains(delim) || e.contains('\n') || e.contains('\r') {
        format!("\"{s}\"")
    } else {
        s
    }
}

// ---------------------------------------------------------------------- reader

/// `DataFileReader` over the uploaded bytes.
pub struct DataFileReader {
    file_type: DataFileType,
    chars: Vec<char>,
    pos: usize,
    headers: Option<Vec<String>>,
    current_row: usize,
    sheet: Option<std::vec::IntoIter<Vec<String>>>,
    bytes: Vec<u8>,
}

impl DataFileReader {
    pub fn new(bytes: Vec<u8>, file_type: DataFileType) -> Self {
        Self { file_type, chars: Vec::new(), pos: 0, headers: Some(Vec::new()), current_row: 0, sheet: None, bytes }
    }

    pub fn headers(&self) -> Option<&[String]> {
        self.headers.as_deref()
    }

    fn read_header_row(&mut self) {
        if self.file_type.is_nested_structure() || matches!(self.file_type, DataFileType::Csv | DataFileType::Tsv) {
            self.chars = String::from_utf8_lossy(&self.bytes).chars().collect();
            if matches!(self.file_type, DataFileType::Csv | DataFileType::Tsv) {
                self.headers = self.read_line_csv_tsv();
            }
        } else {
            // A file the streaming reader cannot open leaves no sheet; the next read fails.
            if let Ok(rows) = xlsx_rows(&self.bytes) {
                let mut it = rows.into_iter();
                self.headers = Some(it.next().unwrap_or_default());
                self.sheet = Some(it);
            }
            self.current_row += 1;
        }
    }

    /// `readRow`: the next row of a flat file, `None` at the end.
    pub fn read_row(&mut self) -> Result<Option<Vec<String>>, String> {
        if self.current_row == 0 && !self.file_type.is_nested_structure() {
            self.read_header_row();
        }
        if self.file_type.is_nested_structure() {
            return Ok(None);
        }
        if matches!(self.file_type, DataFileType::Csv | DataFileType::Tsv) {
            let row = self.read_line_csv_tsv();
            self.current_row += 1;
            return Ok(row);
        }
        let Some(sheet) = self.sheet.as_mut() else {
            return Err("Cannot invoke \"java.util.Iterator.hasNext()\" because \"this.sheet\" is null".into());
        };
        match sheet.next() {
            Some(r) => {
                self.current_row += 1;
                Ok(Some(r))
            }
            None => Ok(None),
        }
    }

    fn read_char(&mut self) -> Option<char> {
        let c = self.chars.get(self.pos).copied();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }

    /// `readObject`: the next object of a JSON array or a JSONL file.
    pub fn read_object(&mut self) -> Result<Option<Document>, ReadError> {
        if !self.file_type.is_nested_structure() {
            return Ok(None);
        }
        if self.current_row == 0 {
            self.read_header_row();
        }
        if self.current_row == 0 && self.file_type == DataFileType::Json && self.read_char() != Some('[') {
            return Err(ReadError::Invalid);
        }
        let mut c;
        loop {
            c = self.read_char();
            match c {
                None => return Ok(None),
                Some('{') => break,
                _ => {}
            }
        }
        let mut count = 1;
        let mut in_quotes = false;
        let mut escaped = false;
        let mut s = String::from('{');
        while count != 0 {
            let Some(ch) = self.read_char() else { return Err(ReadError::Invalid) };
            s.push(ch);
            if escaped {
                escaped = false;
            } else if in_quotes && ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_quotes = !in_quotes;
            } else if !in_quotes {
                if ch == '{' {
                    count += 1;
                } else if ch == '}' {
                    count -= 1;
                }
            }
        }
        self.current_row += 1;
        plain_gson_map(&s).map(Some).map_err(ReadError::Other)
    }

    /// `readLineFromReaderForCSVTSV`, quirks included: a line ends at an unquoted `\n`, and
    /// the last character of a line is kept whatever it is.
    fn read_line_csv_tsv(&mut self) -> Option<Vec<String>> {
        let mut line: Vec<char> = Vec::new();
        let mut in_quotes = false;
        while let Some(ch) = self.read_char() {
            if ch == '"' {
                in_quotes = !in_quotes;
            }
            if !in_quotes && ch == '\n' {
                break;
            }
            line.push(ch);
        }
        let length = line.len();
        if length == 0 {
            return None;
        }
        let delim = if self.file_type == DataFileType::Csv { ',' } else { '\t' };
        let mut list = Vec::new();
        let mut sb = String::new();
        let mut within = false;
        let mut i = 0;
        while i + 1 < length {
            let ch = line[i];
            if ch == delim && !within {
                list.push(remove_line_feeds(&sb));
                sb.clear();
            } else if ch == '"' {
                let mut j = i;
                while line[j] == '"' && j + 1 < length {
                    j += 1;
                }
                if (j - i) % 2 == 1 {
                    within = !within;
                }
                if j - i != 1 {
                    for _ in 0..((j - i) / 2) {
                        sb.push('"');
                    }
                    i = j - 1;
                }
            } else {
                sb.push(ch);
            }
            i += 1;
        }
        if line[i] != '\n' {
            sb.push(line[i]);
        }
        if !sb.is_empty() {
            list.push(remove_line_feeds(&sb));
        }
        (!list.is_empty()).then_some(list)
    }
}

#[derive(Debug, PartialEq)]
pub enum ReadError {
    /// `GenericException(BAD_REQUEST, "Invalid JSON file")`, which goes out as it is.
    Invalid,
    /// Anything else, answered as an unreadable file.
    Other(String),
}

/// `StringUtil.removeLineFeedOrNewLineChars`: trailing `\r` and `\n` removed.
fn remove_line_feeds(s: &str) -> String {
    s.trim_end_matches(['\r', '\n']).to_string()
}

// ---------------------------------------------------------------------- XLSX reading

fn zip_text(archive: &mut zip::ZipArchive<Cursor<&[u8]>>, name: &str) -> Option<String> {
    let mut f = archive.by_name(name).ok()?;
    let mut s = String::new();
    f.read_to_string(&mut s).ok()?;
    Some(s)
}

fn attr(e: &quick_xml::events::BytesStart, name: &[u8]) -> Option<String> {
    e.attributes()
        .flatten()
        .find(|a| a.key.local_name().as_ref() == name)
        .and_then(|a| a.unescape_value().ok().map(|v| v.into_owned()))
}

/// The first sheet's rows, each cell's text as the streaming reader's `getStringCellValue`
/// gives it (a date-formatted number as `yyyy-MM-dd`), blank cells empty, up to the row's last
/// cell.
pub fn xlsx_rows(bytes: &[u8]) -> Result<Vec<Vec<String>>, String> {
    use quick_xml::events::Event;
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).map_err(io)?;

    let shared = zip_text(&mut archive, "xl/sharedStrings.xml").map(|x| shared_strings(&x)).unwrap_or_default();
    let date_styles = zip_text(&mut archive, "xl/styles.xml").map(|x| date_styles(&x)).unwrap_or_default();
    let sheet_path = first_sheet_path(&mut archive).unwrap_or_else(|| "xl/worksheets/sheet1.xml".into());
    let sheet = zip_text(&mut archive, &sheet_path).ok_or("no sheet")?;

    let mut reader = quick_xml::Reader::from_str(&sheet);
    let mut rows = Vec::new();
    let mut cells: std::collections::BTreeMap<usize, String> = std::collections::BTreeMap::new();
    let mut in_row = false;
    let mut cell: Option<(usize, Option<String>, Option<usize>)> = None;
    let mut next_col = 0usize;
    let mut text = String::new();
    let mut in_value = false;
    let mut value = String::new();
    let mut has_value = false;
    loop {
        match reader.read_event().map_err(io)? {
            Event::Start(e) if e.local_name().as_ref() == b"row" => {
                in_row = true;
                cells.clear();
                next_col = 0;
            }
            Event::Empty(e) if e.local_name().as_ref() == b"row" => rows.push(Vec::new()),
            Event::Start(e) if e.local_name().as_ref() == b"c" && in_row => {
                let col = attr(&e, b"r").map(|r| column_index(&r)).unwrap_or(next_col);
                next_col = col + 1;
                cell = Some((col, attr(&e, b"t"), attr(&e, b"s").and_then(|s| s.parse().ok())));
                value.clear();
                text.clear();
                has_value = false;
            }
            Event::Empty(e) if e.local_name().as_ref() == b"c" && in_row => {
                let col = attr(&e, b"r").map(|r| column_index(&r)).unwrap_or(next_col);
                next_col = col + 1;
                cells.entry(col).or_default();
            }
            Event::Start(e) if matches!(e.local_name().as_ref(), b"v" | b"t") && cell.is_some() => {
                in_value = true;
                if e.local_name().as_ref() == b"t" {
                    text.clear();
                }
            }
            Event::Text(t) if in_value => {
                let s = t.decode().map_err(io)?;
                let s = quick_xml::escape::unescape(&s).map_err(io)?;
                value.push_str(&s);
                has_value = true;
            }
            Event::End(e) if matches!(e.local_name().as_ref(), b"v" | b"t") => in_value = false,
            Event::End(e) if e.local_name().as_ref() == b"c" => {
                if let Some((col, t, style)) = cell.take() {
                    let shown = if !has_value {
                        String::new()
                    } else {
                        cell_text(t.as_deref(), style, &value, &shared, &date_styles)
                    };
                    cells.insert(col, shown);
                }
            }
            Event::End(e) if e.local_name().as_ref() == b"row" => {
                in_row = false;
                let last = cells.keys().next_back().map(|c| c + 1).unwrap_or(0);
                rows.push((0..last).map(|c| cells.get(&c).cloned().unwrap_or_default()).collect());
            }
            Event::Eof => break,
            _ => {}
        }
    }
    Ok(rows)
}

fn first_sheet_path(archive: &mut zip::ZipArchive<Cursor<&[u8]>>) -> Option<String> {
    use quick_xml::events::Event;
    let wb = zip_text(archive, "xl/workbook.xml")?;
    let mut r = quick_xml::Reader::from_str(&wb);
    let mut rid = None;
    loop {
        match r.read_event().ok()? {
            Event::Start(e) | Event::Empty(e) if e.local_name().as_ref() == b"sheet" => {
                rid = attr(&e, b"id");
                break;
            }
            Event::Eof => break,
            _ => {}
        }
    }
    let rid = rid?;
    let rels = zip_text(archive, "xl/_rels/workbook.xml.rels")?;
    let mut r = quick_xml::Reader::from_str(&rels);
    loop {
        match r.read_event().ok()? {
            Event::Start(e) | Event::Empty(e) if e.local_name().as_ref() == b"Relationship" => {
                if attr(&e, b"Id").as_deref() == Some(rid.as_str()) {
                    let target = attr(&e, b"Target")?;
                    let t = target.trim_start_matches('/');
                    return Some(if t.starts_with("xl/") { t.to_string() } else { format!("xl/{t}") });
                }
            }
            Event::Eof => return None,
            _ => {}
        }
    }
}

fn shared_strings(xml: &str) -> Vec<String> {
    use quick_xml::events::Event;
    let mut r = quick_xml::Reader::from_str(xml);
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_si = false;
    let mut in_t = false;
    let mut in_phonetic = false;
    loop {
        match r.read_event() {
            Ok(Event::Start(e)) => match e.local_name().as_ref() {
                b"si" => {
                    in_si = true;
                    cur.clear();
                }
                b"rPh" => in_phonetic = true,
                b"t" if in_si && !in_phonetic => in_t = true,
                _ => {}
            },
            Ok(Event::Text(t)) if in_t => {
                let d = t.decode().unwrap_or_default();
                cur.push_str(&quick_xml::escape::unescape(&d).unwrap_or_default());
            }
            Ok(Event::End(e)) => match e.local_name().as_ref() {
                b"si" => {
                    in_si = false;
                    out.push(std::mem::take(&mut cur));
                }
                b"rPh" => in_phonetic = false,
                b"t" => in_t = false,
                _ => {}
            },
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }
    out
}

/// The cell styles (`cellXfs` index) whose number format is a date (POI `DateUtil`).
fn date_styles(xml: &str) -> IndexSet<usize> {
    use quick_xml::events::Event;
    let mut r = quick_xml::Reader::from_str(xml);
    let mut custom: IndexMap<u32, String> = IndexMap::new();
    let mut xfs: Vec<u32> = Vec::new();
    let mut in_xfs = false;
    loop {
        match r.read_event() {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => match e.local_name().as_ref() {
                b"numFmt" => {
                    if let (Some(id), Some(code)) = (attr(&e, b"numFmtId").and_then(|i| i.parse().ok()), attr(&e, b"formatCode")) {
                        custom.insert(id, code);
                    }
                }
                b"cellXfs" => in_xfs = true,
                b"xf" if in_xfs => xfs.push(attr(&e, b"numFmtId").and_then(|i| i.parse().ok()).unwrap_or(0)),
                _ => {}
            },
            Ok(Event::End(e)) if e.local_name().as_ref() == b"cellXfs" => in_xfs = false,
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }
    xfs.iter()
        .enumerate()
        .filter(|(_, id)| is_date_format(**id, custom.get(*id).map(String::as_str)))
        .map(|(i, _)| i)
        .collect()
}

/// `DateUtil.isADateFormat`: the built-in date formats, or a code with date letters outside
/// quotes and brackets.
fn is_date_format(id: u32, code: Option<&str>) -> bool {
    if matches!(id, 14..=22 | 45..=47) {
        return true;
    }
    let Some(code) = code else { return false };
    let mut out = String::new();
    let mut in_quote = false;
    let mut in_bracket = false;
    for c in code.chars() {
        match c {
            '"' => in_quote = !in_quote,
            '[' if !in_quote => in_bracket = true,
            ']' if !in_quote => in_bracket = false,
            c if !in_quote && !in_bracket => out.push(c),
            _ => {}
        }
    }
    let lower = out.to_lowercase();
    lower.chars().any(|c| matches!(c, 'y' | 'm' | 'd' | 'h' | 's'))
        && !lower.contains("general")
        && !lower.chars().any(|c| matches!(c, '0' | '#'))
}

/// A cell column from its reference (`C7` is 2).
fn column_index(r: &str) -> usize {
    let mut n = 0usize;
    for c in r.chars().take_while(char::is_ascii_alphabetic) {
        n = n * 26 + (c.to_ascii_uppercase() as usize - 'A' as usize + 1);
    }
    n.saturating_sub(1)
}

fn cell_text(t: Option<&str>, style: Option<usize>, raw: &str, shared: &[String], dates: &IndexSet<usize>) -> String {
    match t {
        Some("s") => raw.trim().parse::<usize>().ok().and_then(|i| shared.get(i).cloned()).unwrap_or_default(),
        Some("inlineStr") | Some("str") | Some("e") => raw.to_string(),
        Some("b") => if raw.trim() == "1" { "TRUE" } else { "FALSE" }.to_string(),
        _ => {
            let Ok(n) = raw.trim().parse::<f64>() else { return raw.to_string() };
            if style.is_some_and(|s| dates.contains(&s)) {
                return excel_date(n);
            }
            general_number(n)
        }
    }
}

/// An Excel serial day (1900 system) as `yyyy-MM-dd`.
fn excel_date(serial: f64) -> String {
    let days = serial.floor() as i64;
    let base = chrono::NaiveDate::from_ymd_opt(1899, 12, 30).expect("date");
    // Serial 60 is the 1900-02-29 that never was; earlier serials sit one day later.
    let d = if days < 61 { base + chrono::Duration::days(days + 1) } else { base + chrono::Duration::days(days) };
    d.format("%Y-%m-%d").to_string()
}

/// POI's "General" for a number: whole numbers without a fraction, others to at most ten
/// decimals without trailing zeros.
fn general_number(n: f64) -> String {
    if n.fract() == 0.0 && n.abs() < 1e15 {
        return format!("{}", n as i64);
    }
    let s = format!("{n:.10}");
    s.trim_end_matches('0').trim_end_matches('.').to_string()
}

// ---------------------------------------------------------------------- headers

/// `getHeadersSchemaType`: the leaf paths a flat file of the storage has, with their types;
/// objects two levels deep, arrays as their first two elements (`a[0]`, `a[1]`).
pub fn headers_schema_type<'a>(
    prefix: Option<String>,
    schema: &'a Schema,
    repo: &'a dyn Repository<Schema>,
    level: usize,
) -> BoxFuture<'a, Result<IndexMap<Option<String>, IndexSet<SchemaType>>, String>> {
    async move {
        let resolved = match &schema.r#ref {
            None => schema.clone(),
            Some(r) => match SchemaUtil::get_schema_from_ref(schema, Some(repo), Some(r)).await.map_err(|e| e.to_string())? {
                Some(s) => s,
                None => return Ok(IndexMap::new()),
            },
        };
        let Some(t) = resolved.r#type.as_ref() else {
            return Err("Cannot invoke \"com.fincity.nocode.kirun.engine.json.schema.type.Type.contains(...)\" because the return value of \"getType()\" is null".into());
        };
        if t.contains(SchemaType::Object) {
            let mut out = IndexMap::new();
            if level >= 2 {
                return Ok(out);
            }
            let Some(props) = &resolved.properties else { return Ok(out) };
            for (k, v) in props {
                let name = match &prefix {
                    None => k.clone(),
                    Some(p) => format!("{p}.{k}"),
                };
                out.extend(headers_schema_type(Some(name), v, repo, level + 1).await?);
            }
            return Ok(out);
        }
        if t.contains(SchemaType::Array) {
            let mut out = IndexMap::new();
            if level > 2 {
                return Ok(out);
            }
            let Some(items) = &resolved.items else { return Ok(out) };
            let name = |i: usize| match &prefix {
                None => format!("[{i}]"),
                Some(p) => format!("{p}[{i}]"),
            };
            if let Some(single) = &items.single_schema {
                for i in 0..2 {
                    out.extend(headers_schema_type(Some(name(i)), single, repo, level + 1).await?);
                }
            } else if let Some(tuple) = &items.tuple_schema {
                for (i, s) in tuple.iter().enumerate() {
                    out.extend(headers_schema_type(Some(name(i)), s, repo, level + 1).await?);
                }
            }
            return Ok(out);
        }
        let mut out = IndexMap::new();
        out.insert(prefix, t.get_allowed_schema_types());
        Ok(out)
    }
    .boxed()
}

/// `getHeaders`: the paths, fewest dots first, then case-insensitively.
pub async fn headers(schema: &Schema, repo: &dyn Repository<Schema>) -> Result<Vec<String>, String> {
    let map = headers_schema_type(None, schema, repo, 0).await?;
    let mut keys: Vec<String> = map.into_keys().map(|k| k.unwrap_or_else(|| "null".into())).collect();
    keys.sort_by(|a, b| {
        let (ca, cb) = (a.matches('.').count(), b.matches('.').count());
        if ca == cb {
            compare_ignore_case(a, b)
        } else {
            ca.cmp(&cb)
        }
    });
    Ok(keys)
}

/// `String.compareToIgnoreCase`.
fn compare_ignore_case(a: &str, b: &str) -> std::cmp::Ordering {
    let fold = |c: char| c.to_uppercase().next().unwrap_or(c).to_lowercase().next().unwrap_or(c);
    let mut x = a.chars().map(fold);
    let mut y = b.chars().map(fold);
    loop {
        match (x.next(), y.next()) {
            (None, None) => return std::cmp::Ordering::Equal,
            (None, Some(_)) => return std::cmp::Ordering::Less,
            (Some(_), None) => return std::cmp::Ordering::Greater,
            (Some(p), Some(q)) if p != q => return p.cmp(&q),
            _ => {}
        }
    }
}

/// `getElementBySchemaType`: a blank or `null` cell is nothing; a STRING column keeps the
/// text, a BOOLEAN one takes `true` / `false`, anything else is read as a number.
pub fn element_by_schema_type(types: Option<&IndexSet<SchemaType>>, value: &str) -> Result<Option<Value>, String> {
    if value.trim().is_empty() || value.eq_ignore_ascii_case("null") {
        return Ok(None);
    }
    let Some(types) = types else { return Ok(Some(Value::String(value.to_string()))) };
    if types.contains(&SchemaType::String) {
        return Ok(Some(Value::String(value.to_string())));
    }
    if types.contains(&SchemaType::Boolean) {
        if value.eq_ignore_ascii_case("true") {
            return Ok(Some(Value::Bool(true)));
        }
        if value.eq_ignore_ascii_case("false") {
            return Ok(Some(Value::Bool(false)));
        }
    }
    primitive_number(value).map(Some)
}

/// `PrimitiveUtil.findPrimitiveNumberType(new JsonPrimitive(text))`: no dot, a long (through
/// `BigDecimal` when it is not a plain integer); a dot, a float when a float holds it.
fn primitive_number(text: &str) -> Result<Value, String> {
    let fail = || format!("Unable to convert {text} to a number.");
    if !text.contains('.') {
        if let Ok(l) = text.parse::<i64>() {
            return Ok(Value::Int(l));
        }
        let d = appdata::value::Decimal::parse(text.trim()).ok_or_else(fail)?;
        return Ok(Value::Int(d.long_value()));
    }
    let d: f64 = text.trim().parse().map_err(|_| fail())?;
    let f = d as f32;
    if d == 0.0 || (f != 0.0 && f.is_finite()) {
        return Ok(Value::Double(appdata::value::float_as_double(f)));
    }
    Ok(Value::Double(d))
}

/// One step of a `MapUtil.setValueInMap` path.
#[derive(Clone)]
enum Step {
    Key(String),
    Index(usize),
}

fn walk<'a>(root: &'a mut Document, path: &[Step]) -> Result<&'a mut Value, String> {
    let cast = || "class java.lang.Object cannot be cast to the container the path needs".to_string();
    let Some((Step::Key(first), rest)) = path.split_first() else { return Err(cast()) };
    let mut cur = root.get_mut(first).ok_or_else(cast)?;
    for s in rest {
        cur = match (s, cur) {
            (Step::Key(k), Value::Object(o)) => o.get_mut(k).ok_or_else(cast)?,
            (Step::Index(i), Value::Array(a)) => a.get_mut(*i).ok_or_else(cast)?,
            _ => return Err(cast()),
        };
    }
    Ok(cur)
}

fn container<'a>(root: &'a mut Document, path: &[Step]) -> Result<&'a mut Document, String> {
    if path.is_empty() {
        return Ok(root);
    }
    match walk(root, path)? {
        Value::Object(o) => Ok(o),
        _ => Err("class java.util.ArrayList cannot be cast to class java.util.Map".into()),
    }
}

fn index_of(part: &str) -> Result<usize, String> {
    let t = part.replace(']', " ");
    let t = t.trim();
    t.parse::<i32>()
        .map_err(|_| format!("For input string: \"{t}\""))
        .and_then(|i| usize::try_from(i).map_err(|_| format!("Index {i} out of bounds")))
}

/// `String.split(regex)`: trailing empty parts removed.
fn java_split(s: &str, sep: char) -> Vec<String> {
    let mut parts: Vec<String> = s.split(sep).map(str::to_string).collect();
    while parts.len() > 1 && parts.last().is_some_and(String::is_empty) {
        parts.pop();
    }
    if parts.len() == 1 && parts[0].is_empty() && !s.is_empty() {
        parts.clear();
    }
    parts
}

/// `MapUtil.setValueInMap`: `a.b[1].c` builds the maps and lists on the way; an existing
/// plain key keeps its first value; the element a dotted index path lands on is replaced by a
/// new map each time.
pub fn set_value_in_map(map: &mut Document, key: &str, value: Option<Value>) -> Result<(), String> {
    let Some(value) = value else { return Ok(()) };
    if key.trim().is_empty() {
        return Ok(());
    }
    let parts = java_split(key, '.');
    if parts.is_empty() {
        return Err("Index 0 out of bounds for length 0".into());
    }
    let mut path: Vec<Step> = Vec::new();
    let n = parts.len();
    for (i, part) in parts.iter().enumerate().take(n - 1) {
        let arr = java_split(part, '[');
        let head = arr.first().cloned().unwrap_or_default();
        let cur = container(map, &path)?;
        if !cur.contains_key(&head) {
            cur.insert(head.clone(), if arr.len() == 1 { Value::Object(Document::new()) } else { Value::Array(Vec::new()) });
        }
        path.push(Step::Key(head));
        if arr.len() == 1 {
            if !matches!(walk(map, &path)?, Value::Object(_)) {
                return Err("cannot be cast to class java.util.Map".into());
            }
            continue;
        }
        for (j, a) in arr.iter().enumerate().skip(1) {
            let index = index_of(a)?;
            let Value::Array(list) = walk(map, &path)? else {
                return Err("cannot be cast to class java.util.List".into());
            };
            if index >= list.len() {
                let missing = index - list.len();
                for _ in 0..=missing {
                    list.push(if j + 1 == arr.len() && i + 1 == n - 1 { Value::Null } else { Value::Array(Vec::new()) });
                }
            }
            if j + 1 == arr.len() {
                list[index] = Value::Object(Document::new());
            }
            path.push(Step::Index(index));
        }
    }
    let last = &parts[n - 1];
    let arr = java_split(last, '[');
    let head = arr.first().cloned().unwrap_or_default();
    let cur = container(map, &path)?;
    if !cur.contains_key(&head) {
        cur.insert(head.clone(), if arr.len() == 1 { value.clone() } else { Value::Array(Vec::new()) });
    }
    if arr.len() == 1 {
        return Ok(());
    }
    path.push(Step::Key(head));
    for (j, a) in arr.iter().enumerate().skip(1) {
        let index = index_of(a)?;
        let Value::Array(list) = walk(map, &path)? else {
            return Err("cannot be cast to class java.util.List".into());
        };
        if index >= list.len() {
            let missing = index - list.len();
            for _ in 0..=missing {
                list.push(Value::Array(Vec::new()));
            }
        }
        if j + 1 == arr.len() {
            list[index] = value;
            return Ok(());
        }
        path.push(Step::Index(index));
    }
    Ok(())
}

/// Every map of a row built by puts into `HashMap`s, iterated as Java iterates them.
pub fn hash_ordered(doc: Document) -> Document {
    let inner: Document = doc.into_iter().map(|(k, v)| (k, hash_ordered_value(v))).collect();
    hash_map_order(inner)
}

fn hash_ordered_value(v: Value) -> Value {
    match v {
        Value::Object(o) => Value::Object(hash_ordered(o)),
        Value::Array(a) => Value::Array(a.into_iter().map(hash_ordered_value).collect()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(pairs: &[(&str, Value)]) -> Document {
        pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
    }

    fn h(v: &[&str]) -> Option<Vec<String>> {
        Some(v.iter().map(|s| s.to_string()).collect())
    }

    #[test]
    fn file_types() {
        assert_eq!(DataFileType::from_extension("a.b.csv").unwrap(), DataFileType::Csv);
        assert_eq!(DataFileType::from_extension("x.JsonL").unwrap(), DataFileType::Jsonl);
        assert!(DataFileType::from_extension("x.pdf").unwrap_err().contains("DataFileType.PDF"));
        assert_eq!(DataFileType::from_extension("csv").unwrap(), DataFileType::Csv);
        assert!(DataFileType::Json.is_nested_structure() && !DataFileType::Xlsx.is_nested_structure());
        for t in DataFileType::ALL {
            assert_eq!(DataFileType::value_of(t.name()), Some(t));
            assert!(!t.mime_type().is_empty());
        }
        assert_eq!(DataFileType::value_of("csv"), None);
    }

    #[test]
    fn csv_and_tsv_quote_what_needs_it() {
        let mut w = DataFileWriter::new(h(&["a", "b"]), DataFileType::Csv, true);
        w.write(&doc(&[("a", Value::from("x,y")), ("b", Value::Int(3))])).unwrap();
        w.write(&doc(&[("a", Value::from("say \"hi\""))])).unwrap();
        assert_eq!(String::from_utf8(w.finish().unwrap()).unwrap(), "a,b\n\"x,y\",3\n\"say \"\"hi\"\"\",\n");

        let mut w = DataFileWriter::new(h(&["a"]), DataFileType::Tsv, false);
        w.write(&doc(&[("a", Value::from("t\tu"))])).unwrap();
        w.write(&doc(&[("a", Value::from("line\r"))])).unwrap();
        assert_eq!(String::from_utf8(w.finish().unwrap()).unwrap(), "\"t\tu\"\n\"line\r\"\n");

        // Nothing written: an empty file, no header.
        assert!(DataFileWriter::new(h(&["a"]), DataFileType::Csv, true).finish().unwrap().is_empty());
        // A template's one empty row.
        let mut w = DataFileWriter::new(h(&["a", "b"]), DataFileType::Csv, true);
        w.write(&Document::new()).unwrap();
        assert_eq!(String::from_utf8(w.finish().unwrap()).unwrap(), "a,b\n,\n");
        // No header list: Java's NullPointerException.
        let mut w = DataFileWriter::new(None, DataFileType::Csv, true);
        assert!(w.write(&Document::new()).unwrap_err().contains("this.header"));
    }

    #[test]
    fn xls_json_and_jsonl() {
        let mut w = DataFileWriter::new(h(&["a"]), DataFileType::Xls, true);
        w.write(&doc(&[("a", Value::from("v"))])).unwrap();
        let s = String::from_utf8(w.finish().unwrap()).unwrap();
        assert!(s.starts_with("<?xml version=\"1.0\""));
        assert!(s.contains("<Column ss:Index=\"1\" ss:AutoFitWidth=\"0\" ss:Width=\"110\"/>"));
        assert!(s.contains("<Row><Cell><Data ss:Type=\"String\">a</Data></Cell></Row><Row><Cell><Data ss:Type=\"String\">v</Data></Cell></Row>"));
        assert!(s.ends_with("</Table>\n</Worksheet>\n</Workbook>"));
        let mut w = DataFileWriter::new(None, DataFileType::Xls, true);
        assert!(w.write(&Document::new()).is_err());

        let mut w = DataFileWriter::new(None, DataFileType::Json, true);
        w.write(&doc(&[("a", Value::Int(1)), ("n", Value::Null)])).unwrap();
        w.write(&doc(&[("b", Value::from("<"))])).unwrap();
        assert_eq!(String::from_utf8(w.finish().unwrap()).unwrap(), "[{\"a\":1},\n{\"b\":\"\\u003c\"}]");
        assert_eq!(DataFileWriter::new(None, DataFileType::Json, true).finish().unwrap(), b"]");

        let mut w = DataFileWriter::new(None, DataFileType::Jsonl, true);
        w.write(&doc(&[("a", Value::Int(1))])).unwrap();
        w.write(&doc(&[("a", Value::Int(2))])).unwrap();
        assert_eq!(String::from_utf8(w.finish().unwrap()).unwrap(), "{\"a\":1}\n{\"a\":2}");
        let mut w = DataFileWriter::new(None, DataFileType::Json, true);
        assert!(w.write(&doc(&[("d", Value::Double(f64::INFINITY))])).is_err());
    }

    #[test]
    fn xlsx_round_trips_through_the_reader() {
        let mut w = DataFileWriter::new(h(&["name", "age"]), DataFileType::Xlsx, true);
        w.write(&doc(&[("name", Value::from("Ann")), ("age", Value::Int(30))])).unwrap();
        let bytes = w.finish().unwrap();
        let mut archive = zip::ZipArchive::new(Cursor::new(bytes.as_slice())).unwrap();
        let names: Vec<String> = archive.file_names().map(str::to_string).collect();
        assert_eq!(names.len(), 9);
        let sheet = zip_text(&mut archive, "xl/worksheets/sheet1.xml").unwrap();
        assert!(sheet.ends_with(XLSX_SHEET_END));
        assert_eq!(xlsx_rows(&bytes).unwrap(), vec![vec!["name", "age"], vec!["Ann", "30"]]);

        let mut r = DataFileReader::new(bytes, DataFileType::Xlsx);
        assert_eq!(r.read_row().unwrap(), Some(vec!["Ann".to_string(), "30".to_string()]));
        assert_eq!(r.headers().unwrap(), ["name", "age"]);
        assert_eq!(r.read_row().unwrap(), None);

        // An XLSX nothing was written to fails on close.
        assert!(DataFileWriter::new(h(&["a"]), DataFileType::Xlsx, true).finish().is_err());
        // Not a zip: no sheet, and the first row read fails.
        let mut r = DataFileReader::new(b"not a zip".to_vec(), DataFileType::Xls);
        assert!(r.read_row().is_err());
    }

    #[test]
    fn xlsx_cells_as_the_streaming_reader_shows_them() {
        let shared = vec!["s0".to_string(), "s1".to_string()];
        let mut dates = IndexSet::new();
        dates.insert(1);
        assert_eq!(cell_text(Some("s"), None, "1", &shared, &dates), "s1");
        assert_eq!(cell_text(Some("s"), None, "9", &shared, &dates), "");
        assert_eq!(cell_text(Some("b"), None, "1", &shared, &dates), "TRUE");
        assert_eq!(cell_text(Some("b"), None, "0", &shared, &dates), "FALSE");
        assert_eq!(cell_text(None, None, "2.50", &shared, &dates), "2.5");
        assert_eq!(cell_text(None, None, "abc", &shared, &dates), "abc");
        assert_eq!(cell_text(None, Some(1), "45000", &shared, &dates), "2023-03-15");
        assert_eq!(excel_date(1.0), "1900-01-01");
        assert_eq!(general_number(1e20), "100000000000000000000");
        assert_eq!(column_index("C7"), 2);
        assert_eq!(column_index("AA1"), 26);
        assert!(is_date_format(14, None));
        assert!(is_date_format(164, Some("dd/mm/yyyy")));
        assert!(!is_date_format(164, Some("0.00")));
        assert!(!is_date_format(164, Some("\"day\" 0")));
        assert!(!is_date_format(2, None));
        let styles = r#"<styleSheet><numFmts><numFmt numFmtId="164" formatCode="yyyy-mm-dd"/></numFmts><cellXfs count="3"><xf numFmtId="0"/><xf numFmtId="164"/><xf numFmtId="14"/></cellXfs></styleSheet>"#;
        assert_eq!(date_styles(styles).into_iter().collect::<Vec<_>>(), [1, 2]);
        let sst = r#"<sst><si><t>a</t></si><si><r><t>b</t></r><r><t>c</t></r><rPh><t>x</t></rPh></si></sst>"#;
        assert_eq!(shared_strings(sst), ["a", "bc"]);
    }

    #[test]
    fn xlsx_from_another_writer() {
        let sheet = r#"<worksheet><sheetData><row r="1"><c r="A1" t="s"><v>0</v></c><c r="C1" t="inlineStr"><is><t>z</t></is></c></row><row r="2"><c r="B2" s="1"><v>45000</v></c><c r="C2"/></row><row r="3"/></sheetData></worksheet>"#;
        let mut buf = Cursor::new(Vec::new());
        {
            let mut z = zip::ZipWriter::new(&mut buf);
            let o = zip::write::SimpleFileOptions::default();
            z.start_file("xl/workbook.xml", o).unwrap();
            z.write_all(br#"<workbook xmlns:r="r"><sheets><sheet name="S" sheetId="1" r:id="rId9"/></sheets></workbook>"#).unwrap();
            z.start_file("xl/_rels/workbook.xml.rels", o).unwrap();
            z.write_all(br#"<Relationships><Relationship Id="rId9" Target="worksheets/data.xml"/></Relationships>"#).unwrap();
            z.start_file("xl/worksheets/data.xml", o).unwrap();
            z.write_all(sheet.as_bytes()).unwrap();
            z.start_file("xl/sharedStrings.xml", o).unwrap();
            z.write_all(br#"<sst><si><t>head</t></si></sst>"#).unwrap();
            z.start_file("xl/styles.xml", o).unwrap();
            z.write_all(br#"<styleSheet><cellXfs><xf numFmtId="0"/><xf numFmtId="14"/></cellXfs></styleSheet>"#).unwrap();
            z.finish().unwrap();
        }
        let rows = xlsx_rows(&buf.into_inner()).unwrap();
        assert_eq!(rows[0], ["head", "", "z"]);
        assert_eq!(rows[1], ["", "2023-03-15", ""]);
        assert!(rows[2].is_empty());
    }

    #[test]
    fn csv_lines_are_read_with_the_java_quirks() {
        let mut r = DataFileReader::new(b"a,b,c\n1,\"x,y\",z\r\n\"q\"\"q\",2,\"last\"\n,\n".to_vec(), DataFileType::Csv);
        assert_eq!(r.read_row().unwrap(), Some(vec!["1".to_string(), "x,y".into(), "z".into()]));
        assert_eq!(r.headers().unwrap(), ["a", "b", "c"]);
        // The closing quote of the last cell is kept, as Java keeps the line's last character.
        assert_eq!(r.read_row().unwrap(), Some(vec!["q\"q".to_string(), "2".into(), "last\"".into()]));
        assert_eq!(r.read_row().unwrap(), Some(vec![",".to_string()]));
        assert_eq!(r.read_row().unwrap(), None);

        let mut r = DataFileReader::new(b"a\tb\nx\ty".to_vec(), DataFileType::Tsv);
        assert_eq!(r.read_row().unwrap(), Some(vec!["x".to_string(), "y".into()]));
        let mut r = DataFileReader::new(Vec::new(), DataFileType::Csv);
        assert_eq!(r.read_row().unwrap(), None);
        assert!(r.headers().is_none());
        assert_eq!(r.read_object().unwrap(), None);
    }

    #[test]
    fn json_objects_are_cut_out_of_the_stream() {
        let mut r = DataFileReader::new(br#"[{"a":1,"s":"}{\"x"},{"b":{"c":2}}]"#.to_vec(), DataFileType::Json);
        let first = r.read_object().unwrap().unwrap();
        assert_eq!(first["a"], Value::Double(1.0));
        assert_eq!(first["s"], Value::from("}{\"x"));
        assert_eq!(r.read_object().unwrap().unwrap()["b"].as_object().unwrap()["c"], Value::Double(2.0));
        assert_eq!(r.read_object().unwrap(), None);
        assert_eq!(r.read_row().unwrap(), None);

        assert_eq!(DataFileReader::new(b"{}".to_vec(), DataFileType::Json).read_object(), Err(ReadError::Invalid));
        assert_eq!(DataFileReader::new(Vec::new(), DataFileType::Json).read_object(), Err(ReadError::Invalid));
        assert_eq!(DataFileReader::new(b"[{\"a\":1".to_vec(), DataFileType::Json).read_object(), Err(ReadError::Invalid));
        let mut r = DataFileReader::new(b"{\"a\":1}\n{\"a\":}".to_vec(), DataFileType::Jsonl);
        assert!(r.read_object().unwrap().is_some());
        assert!(matches!(r.read_object(), Err(ReadError::Other(_))));
    }

    #[test]
    fn cells_by_schema_type() {
        let mut s = IndexSet::new();
        s.insert(SchemaType::String);
        assert_eq!(element_by_schema_type(Some(&s), "12").unwrap(), Some(Value::from("12")));
        assert_eq!(element_by_schema_type(Some(&s), "NULL").unwrap(), None);
        assert_eq!(element_by_schema_type(None, "x").unwrap(), Some(Value::from("x")));
        assert_eq!(element_by_schema_type(None, "  ").unwrap(), None);
        let mut b = IndexSet::new();
        b.insert(SchemaType::Boolean);
        assert_eq!(element_by_schema_type(Some(&b), "TRUE").unwrap(), Some(Value::Bool(true)));
        assert_eq!(element_by_schema_type(Some(&b), "false").unwrap(), Some(Value::Bool(false)));
        assert_eq!(element_by_schema_type(Some(&b), "1").unwrap(), Some(Value::Int(1)));
        let mut n = IndexSet::new();
        n.insert(SchemaType::Integer);
        assert_eq!(element_by_schema_type(Some(&n), "42").unwrap(), Some(Value::Int(42)));
        assert_eq!(element_by_schema_type(Some(&n), "1e3").unwrap(), Some(Value::Int(1000)));
        assert_eq!(element_by_schema_type(Some(&n), "1.1").unwrap(), Some(Value::Double(1.1)));
        assert_eq!(element_by_schema_type(Some(&n), "0.0").unwrap(), Some(Value::Double(0.0)));
        assert_eq!(element_by_schema_type(Some(&n), "1.0e-50").unwrap(), Some(Value::Double(1.0e-50)));
        assert!(element_by_schema_type(Some(&n), "abc").unwrap_err().contains("Unable to convert abc"));
        assert!(element_by_schema_type(Some(&n), "a.b").is_err());
    }

    #[test]
    fn values_land_on_their_paths() {
        let mut m = Document::new();
        set_value_in_map(&mut m, "name", Some(Value::from("a"))).unwrap();
        set_value_in_map(&mut m, "name", Some(Value::from("b"))).unwrap();
        set_value_in_map(&mut m, "addr.city", Some(Value::from("c"))).unwrap();
        set_value_in_map(&mut m, "addr.zip", Some(Value::from("z"))).unwrap();
        set_value_in_map(&mut m, "tags[1]", Some(Value::from("t1"))).unwrap();
        set_value_in_map(&mut m, "tags[0]", Some(Value::from("t0"))).unwrap();
        set_value_in_map(&mut m, "items[0].x", Some(Value::Int(1))).unwrap();
        set_value_in_map(&mut m, "skip", None).unwrap();
        set_value_in_map(&mut m, " ", Some(Value::Int(1))).unwrap();
        assert_eq!(m["name"], Value::from("a"));
        assert_eq!(m["addr"], Value::Object(doc(&[("city", Value::from("c")), ("zip", Value::from("z"))])));
        assert_eq!(m["tags"], Value::Array(vec![Value::from("t0"), Value::from("t1")]));
        assert_eq!(m["items"], Value::Array(vec![Value::Object(doc(&[("x", Value::Int(1))]))]));
        assert!(!m.contains_key("skip"));
        // A path through a leaf, and a bad index, fail as Java's casts and parses do.
        assert!(set_value_in_map(&mut m, "name.x", Some(Value::Int(1))).is_err());
        assert!(set_value_in_map(&mut m, "tags[x]", Some(Value::Int(1))).is_err());
        assert!(set_value_in_map(&mut m, "addr[0]", Some(Value::Int(1))).is_err());
        assert!(set_value_in_map(&mut m, "q[-1]", Some(Value::Int(1))).is_err());
        // Java puts the list before parsing the bad index, so `q` is there.
        let ordered = hash_ordered(m);
        assert_eq!(ordered.len(), 5);
    }

    #[test]
    fn header_order_and_case() {
        let mut v = vec!["b.x", "A", "a.b.c", "c", "B"];
        v.sort_by(|a, b| {
            let (ca, cb) = (a.matches('.').count(), b.matches('.').count());
            if ca == cb {
                compare_ignore_case(a, b)
            } else {
                ca.cmp(&cb)
            }
        });
        assert_eq!(v, ["A", "B", "c", "b.x", "a.b.c"]);
        assert_eq!(compare_ignore_case("ab", "a"), std::cmp::Ordering::Greater);
        assert_eq!(compare_ignore_case("a", "AB"), std::cmp::Ordering::Less);
    }

    // Port of commons `DataFileReaderTest`.

    fn read_all(content: &str, t: DataFileType) -> Result<Vec<Document>, ReadError> {
        let mut r = DataFileReader::new(content.as_bytes().to_vec(), t);
        let mut out = Vec::new();
        while let Some(o) = r.read_object()? {
            out.push(o);
        }
        Ok(out)
    }

    #[test]
    fn reads_every_object_from_a_json_array() {
        let o = read_all("[{\"a\":1},{\"a\":2},{\"a\":3}]", DataFileType::Json).unwrap();
        assert_eq!(o.len(), 3);
        assert_eq!(o[0]["a"], Value::Double(1.0));
        assert_eq!(o[2]["a"], Value::Double(3.0));
    }

    #[test]
    fn keeps_escaped_quotes_and_braces_inside_strings() {
        let body = "a \\\" quote, a { brace and a } brace";
        let o = read_all(&format!("[{{\"body\":\"{body}\",\"n\":1}},{{\"body\":\"second\",\"n\":2}}]"), DataFileType::Json).unwrap();
        assert_eq!(o.len(), 2);
        assert_eq!(o[0]["body"], Value::from("a \" quote, a { brace and a } brace"));
        assert_eq!(o[1]["body"], Value::from("second"));
    }

    #[test]
    fn reads_nested_objects_whole_and_not_at_the_first_inner_brace() {
        let o = read_all("[{\"outer\":{\"inner\":{\"deep\":\"v\"}},\"n\":1}]", DataFileType::Json).unwrap();
        assert_eq!(o.len(), 1);
        assert_eq!(o[0]["n"], Value::Double(1.0));
    }

    #[test]
    fn reads_json_lines_one_object_per_line() {
        let o = read_all("{\"a\":1}\n{\"a\":2, \"b\":\"has a \\\" and a { in it\"}\n", DataFileType::Jsonl).unwrap();
        assert_eq!(o.len(), 2);
        assert_eq!(o[1]["b"], Value::from("has a \" and a { in it"));
    }

    #[test]
    fn fails_on_a_truncated_object_instead_of_spinning() {
        assert_eq!(read_all("[{\"a\":1},{\"a\":", DataFileType::Json).unwrap_err(), ReadError::Invalid);
    }

    #[test]
    fn fails_on_a_truncated_object_with_an_unclosed_string() {
        assert_eq!(read_all("[{\"a\":\"unterminated", DataFileType::Json).unwrap_err(), ReadError::Invalid);
    }

    #[test]
    fn ends_quietly_on_an_empty_json_array() {
        assert!(read_all("[]", DataFileType::Json).unwrap().is_empty());
    }

    #[test]
    fn reads_nothing_from_a_flat_type_as_an_object() {
        let mut r = DataFileReader::new(b"a,b\n1,2\n".to_vec(), DataFileType::Csv);
        assert_eq!(r.read_object().unwrap(), None);
    }
}