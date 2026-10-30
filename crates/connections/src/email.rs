//! Email: `EmailService` (pick the MAIL connection and the template), `AbstractEmailService`
//! (recipients, sender, language and the rendered parts), `SMTPService` and `SendGridService`,
//! and what `CoreServices.Email.SendEmail` reports.
//!
//! Attachments are Rust only (Java's `SendEmail` sends none): stored files or inline content,
//! sent as `multipart/mixed` by SMTP and as `attachments` to SendGrid. So are `SendEmail`'s
//! `cc` and `bcc` copies.

use std::net::SocketAddr;
use std::time::Duration;

use async_trait::async_trait;
use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine;
use http::StatusCode;
use lettre::message::header::ContentType;
use lettre::message::{Attachment, Mailbox, MultiPart, SinglePart};
use percent_encoding::percent_decode_str;
use lettre::transport::smtp::client::{AsyncSmtpConnection, TlsParameters};
use lettre::transport::smtp::commands::{Data, Mail, Rcpt, Rset};
use lettre::transport::smtp::extension::ClientId;
use lettre::Address;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::connection::{self, Connection, ConnectionStore, ConnectionSubType, ConnectionType};
use crate::context::Caller;
use crate::error::{messages, ConnError, ConnResult};
use crate::java::{self, json};
use crate::outbound;
use crate::rest::http::{HttpClient, OutboundRequest};
use crate::template;

/// A `template` document (the fields email uses).
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EmailTemplate {
    #[serde(default)]
    pub name: Option<String>,
    /// Language, then part name (`subject`, `body`, ...), then the FreeMarker source.
    #[serde(default)]
    pub template_parts: Option<Map<String, Value>>,
    #[serde(default)]
    pub default_language: Option<String>,
    #[serde(default)]
    pub template_type: Option<String>,
    #[serde(default)]
    pub to_expression: Option<String>,
    #[serde(default)]
    pub from_expression: Option<String>,
    #[serde(default)]
    pub language_expression: Option<String>,
}

impl EmailTemplate {
    pub fn from_json(v: Value) -> ConnResult<Self> {
        serde_json::from_value(v).map_err(|e| ConnError::other(format!("Unable to read the template: {e}")))
    }
}

/// `TemplateService.read(name, appCode, clientCode)`, provided by the core crate over
/// `crates/overridable` (the caller's URL client decides inheritance, as for connections).
#[async_trait]
pub trait TemplateStore: Send + Sync {
    async fn read(&self, name: &str, app_code: &str, client_code: &str) -> ConnResult<Option<EmailTemplate>>;
}

/// `ProcessedEmailDetails`, and the attachments read for it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProcessedEmail {
    pub to: Vec<String>,
    /// Copies, none already in `to`; `bcc` holds none of `cc` either.
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub from: String,
    pub subject: String,
    pub body: String,
    pub attachments: Vec<EmailAttachment>,
}

fn mail_error(reason: &str) -> ConnError {
    ConnError::msg(StatusCode::INTERNAL_SERVER_ERROR, messages::MAIL_SEND_ERROR, &[reason])
}

/// `SendEmail.givenAddresses`: the step's `address` values, blanks and nulls dropped, trimmed.
pub fn given_addresses(address: Option<&Value>) -> Vec<String> {
    let Some(Value::Array(a)) = address else { return Vec::new() };
    a.iter()
        .filter(|v| !v.is_null())
        .map(|v| java::trim(&java::to_java_string(v)).to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// `getToAddresses`: the given addresses (blanks dropped, trimmed), then the template's
/// `toExpression` rendered and split on `;`. None at all is an error.
pub fn to_addresses(given: &[String], tmpl: &EmailTemplate, data: &Map<String, Value>) -> ConnResult<Vec<String>> {
    let mut out: Vec<String> = given.iter().filter(|a| !java::is_blank(a)).map(|a| java::trim(a).to_string()).collect();
    if let Some(expr) = tmpl.to_expression.as_deref().filter(|e| !java::is_blank(e)) {
        let rendered = template::process("toExpression", Some(expr), data)?;
        for a in rendered.split(';') {
            if !java::is_blank(a) {
                out.push(java::trim(a).to_string());
            }
        }
    }
    if out.is_empty() {
        return Err(mail_error("No Send Addresses Found."));
    }
    Ok(out)
}

/// `getFromAddress`: the template's `fromExpression`, else the connection's `fromAddress`.
pub fn from_address(conn: &Connection, tmpl: &EmailTemplate, data: &Map<String, Value>) -> ConnResult<String> {
    match tmpl.from_expression.as_deref().filter(|e| !java::is_blank(e)) {
        Some(expr) => template::process("fromExpression", Some(expr), data),
        None => Ok(conn.detail("fromAddress").map(java::to_java_string).unwrap_or_default()),
    }
}

/// The language when neither the expression nor the template's default gives one.
pub const DEFAULT_LANGUAGE: &str = "en";

/// `getLanguage`: the rendered `languageExpression`, else the template's default language,
/// else [`DEFAULT_LANGUAGE`]. (Java failed on a default language without an expression, and
/// had no language at all when the expression rendered blank without a default.)
pub fn language(tmpl: &EmailTemplate, data: &Map<String, Value>) -> ConnResult<Option<String>> {
    if let Some(expr) = tmpl.language_expression.as_deref().filter(|e| !java::is_blank(e)) {
        let rendered = template::process("language", Some(expr), data)?;
        if !java::is_blank(&rendered) {
            return Ok(Some(java::trim(&rendered).to_string()));
        }
    }
    let default = tmpl.default_language.as_deref().map(java::trim).filter(|d| !d.is_empty());
    Ok(Some(default.unwrap_or(DEFAULT_LANGUAGE).to_string()))
}

/// `getProcessedTemplate`: every part of the language's set rendered (`en` when the language
/// is blank; the set named in another case, so `EN` finds `en`; else the first set).
pub fn processed_parts(language: Option<&str>, tmpl: &EmailTemplate, data: &Map<String, Value>) -> ConnResult<Map<String, Value>> {
    let parts = tmpl.template_parts.clone().unwrap_or_default();
    // CloneUtil copies the document's maps into HashMaps, nulls dropped.
    let parts: Map<String, Value> = java::hash_map_order(parts.into_iter().filter(|(_, v)| !v.is_null()).collect());
    if parts.is_empty() {
        return Err(mail_error("No template parts found"));
    }
    let Some(language) = language else {
        return Err(ConnError::other("Cannot invoke \"String.isBlank()\" because \"language\" is null"));
    };
    let key = if java::is_blank(language) { DEFAULT_LANGUAGE } else { language };
    let set = parts
        .get(key)
        .or_else(|| parts.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)).map(|(_, v)| v))
        .or_else(|| parts.values().next())
        .cloned()
        .unwrap_or(Value::Null);
    let mut out = Map::new();
    if let Value::Object(set) = set {
        for (name, src) in set {
            if src.is_null() {
                continue;
            }
            let text = template::process("templatePart", src.as_str(), data)?;
            out.insert(name, Value::String(text));
        }
    }
    Ok(out)
}

/// `getProcessedEmailDetails`.
pub fn processed_email(
    conn: &Connection,
    given: &[String],
    tmpl: &EmailTemplate,
    data: &Map<String, Value>,
) -> ConnResult<ProcessedEmail> {
    let to = to_addresses(given, tmpl, data)?;
    let from = from_address(conn, tmpl, data)?;
    let lang = language(tmpl, data)?;
    let parts = processed_parts(lang.as_deref(), tmpl, data)?;
    let part = |k: &str| parts.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    Ok(ProcessedEmail { to, from, subject: part("subject"), body: part("body"), ..Default::default() })
}

// ---------------------------------------------------------------------------------------------
// Copies

/// The copies of one send (Rust only): `cc` shown to every recipient, `bcc` to none.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Copies {
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
}

impl Copies {
    /// `SendEmail`'s `cc` and `bcc`, each read by [`copy_addresses`].
    pub fn from_args(cc: Option<&Value>, bcc: Option<&Value>) -> ConnResult<Self> {
        Ok(Copies { cc: copy_addresses(cc)?, bcc: copy_addresses(bcc)? })
    }

    /// Without the addresses already in `to`, and `bcc` without those in `cc`, ignoring case:
    /// SendGrid refuses an address that appears twice in one personalization.
    pub fn without(&self, to: &[String]) -> Copies {
        let seen = |list: &[String], a: &str| list.iter().any(|t| t.trim().eq_ignore_ascii_case(a));
        let cc: Vec<String> = self.cc.iter().filter(|a| !seen(to, a)).cloned().collect();
        let bcc = self.bcc.iter().filter(|a| !seen(to, a) && !seen(&cc, a)).cloned().collect();
        Copies { cc, bcc }
    }
}

fn bad_address(shown: &str) -> ConnError {
    ConnError::coded(StatusCode::BAD_REQUEST, "CORE.MAIL_ADDRESS_INVALID", format!("Unable to send the email: Not an email address: {shown}"))
        .param("address", shown)
}

/// `SendEmail`'s `cc` or `bcc`: a string of addresses separated by `,` or `;`, or an array of
/// such strings. Blanks are dropped, each address is trimmed and kept once (ignoring case).
/// A value that is not an email address refuses the whole send (400), so nothing goes to part
/// of the list.
pub fn copy_addresses(arg: Option<&Value>) -> ConnResult<Vec<String>> {
    let items: &[Value] = match arg {
        None | Some(Value::Null) => &[],
        Some(Value::Array(a)) => a,
        Some(v) => std::slice::from_ref(v),
    };
    let mut out: Vec<String> = Vec::new();
    for item in items {
        let text = match item {
            Value::Null => continue,
            Value::String(s) => s,
            other => return Err(bad_address(&other.to_string())),
        };
        for a in text.split([',', ';']).map(java::trim).filter(|a| !a.is_empty()) {
            if a.parse::<Address>().is_err() {
                return Err(bad_address(a));
            }
            if !out.iter().any(|o| o.eq_ignore_ascii_case(a)) {
                out.push(a.to_string());
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// Attachments

/// The most one mail carries in attachments, decoded. SendGrid takes 30 MB a message, with the
/// attachments in base64 (a third larger).
pub const MAX_ATTACHMENT_BYTES: usize = 20 * 1024 * 1024;

const STATIC_FILE: &str = "api/files/static/file/";
const SECURED_FILE: &str = "api/files/secured/file/";

/// One attachment, read and decoded.
#[derive(Debug, Clone, PartialEq)]
pub struct EmailAttachment {
    pub name: String,
    pub content_type: String,
    pub bytes: Vec<u8>,
}

/// An attachment as `SendEmail`'s `attachments` names it.
#[derive(Debug, Clone, PartialEq)]
pub enum AttachmentSource {
    /// A stored file, by its files URL (`/api/files/{static|secured}/file/<client>/<path>`).
    File { url: String, secured: bool, name: Option<String>, content_type: Option<String> },
    /// The content itself: base64, or a `data:` URL.
    Inline { content: String, name: Option<String>, content_type: Option<String> },
}

/// Reads a stored file for an attachment: the files service's `convertToBase64` with its
/// metadata (`data:<type>;name:<name>;base64,...`), `None` when it answers nothing.
#[async_trait]
pub trait AttachmentFiles: Send + Sync {
    async fn read_base64(&self, url: &str, secured: bool) -> ConnResult<Option<String>>;
}

/// The attachments of one send, and the files service the stored ones are read through
/// (`None` where there is none to ask).
#[derive(Default)]
pub struct Attachments<'a> {
    pub sources: Vec<AttachmentSource>,
    pub files: Option<&'a dyn AttachmentFiles>,
}

fn non_blank(o: &Map<String, Value>, key: &str) -> Option<String> {
    o.get(key).and_then(Value::as_str).map(java::trim).filter(|s| !s.is_empty()).map(str::to_string)
}

fn file_source(url: String, name: Option<String>, content_type: Option<String>) -> ConnResult<AttachmentSource> {
    let secured = if url.contains(SECURED_FILE) {
        true
    } else if url.contains(STATIC_FILE) {
        false
    } else {
        return Err(mail_error(&format!("Attachment is not a stored file: {url}")));
    };
    Ok(AttachmentSource::File { url, secured, name, content_type })
}

/// `SendEmail`'s `attachments`: each a files URL, a `data:` URL, or an object with `url` or
/// `content` and optionally `name` and `contentType` (so a files `FileDetail` goes as it is).
/// Nulls and blanks are dropped.
pub fn attachment_sources(arg: Option<&Value>) -> ConnResult<Vec<AttachmentSource>> {
    let items: &[Value] = match arg {
        None | Some(Value::Null) => &[],
        Some(Value::Array(a)) => a,
        Some(v) => std::slice::from_ref(v),
    };
    let mut out = Vec::new();
    for item in items {
        match item {
            Value::Null => {}
            Value::String(s) => {
                let s = java::trim(s);
                if s.is_empty() {
                    continue;
                }
                if s.starts_with("data:") {
                    out.push(AttachmentSource::Inline { content: s.to_string(), name: None, content_type: None });
                } else {
                    out.push(file_source(s.to_string(), None, None)?);
                }
            }
            Value::Object(o) => {
                let name = non_blank(o, "name");
                let content_type = non_blank(o, "contentType");
                if let Some(content) = non_blank(o, "content") {
                    out.push(AttachmentSource::Inline { content, name, content_type });
                } else if let Some(url) = non_blank(o, "url") {
                    out.push(file_source(url, name, content_type)?);
                } else {
                    return Err(mail_error("An attachment needs a url or content"));
                }
            }
            other => return Err(mail_error(&format!("An attachment is a file url or an object, not {other}"))),
        }
    }
    Ok(out)
}

/// What a `data:` URL or plain base64 holds.
struct Decoded {
    content_type: Option<String>,
    name: Option<String>,
    bytes: Vec<u8>,
}

/// Base64 with or without its padding.
const BASE64: GeneralPurpose =
    GeneralPurpose::new(&alphabet::STANDARD, GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent));

fn too_large() -> ConnError {
    mail_error(&format!("Attachments are over {} MB in all", MAX_ATTACHMENT_BYTES / (1024 * 1024)))
}

fn decode_content(content: &str) -> ConnResult<Decoded> {
    let bad = || mail_error("An attachment's content is not base64");
    let (meta, data, base64) = match content.strip_prefix("data:") {
        None => ("", content, true),
        Some(rest) => match rest.find(";base64,") {
            Some(i) => (&rest[..i], &rest[i + ";base64,".len()..], true),
            None => match rest.split_once(',') {
                Some((m, d)) => (m, d, false),
                None => return Err(bad()),
            },
        },
    };
    // `<type>;name:<name>` as the files service writes it, `<type>;name=<encoded>` as browsers do.
    let (head, name) = match (meta.find(";name:"), meta.find(";name=")) {
        (Some(i), _) => (&meta[..i], Some(meta[i + 6..].to_string())),
        (None, Some(i)) => (&meta[..i], Some(percent_decode_str(&meta[i + 6..]).decode_utf8_lossy().into_owned())),
        (None, None) => (meta, None),
    };
    let content_type = head.split(';').next().map(str::trim).filter(|t| !t.is_empty()).map(str::to_string);
    let bytes = if base64 {
        if data.len() / 4 * 3 > MAX_ATTACHMENT_BYTES + 3 {
            return Err(too_large());
        }
        let clean: Vec<u8> = data.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        BASE64.decode(clean).map_err(|_| bad())?
    } else {
        percent_decode_str(data).collect()
    };
    Ok(Decoded { content_type, name: name.filter(|n| !java::is_blank(n)), bytes })
}

/// The last name of a files URL, decoded.
fn url_file_name(url: &str) -> Option<String> {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    path.rsplit('/').find(|s| !s.is_empty()).map(|s| percent_decode_str(s).decode_utf8_lossy().into_owned())
}

/// A name that is safe in a header: no control characters, quotes or path separators.
fn clean_name(name: &str) -> String {
    let n: String = name.chars().map(|c| if c.is_control() || matches!(c, '"' | '/' | '\\') { '_' } else { c }).collect();
    n.trim().to_string()
}

/// The name given, else the one the content names, else the URL's; the type given, else the
/// content's, else the name's. Without a name it is `attachment`, with the type's extension.
fn attachment_of(decoded: Decoded, name: Option<String>, content_type: Option<String>, url: Option<&str>) -> EmailAttachment {
    let given = name.or(decoded.name).or_else(|| url.and_then(url_file_name)).map(|n| clean_name(&n)).filter(|n| !n.is_empty());
    let content_type = [content_type, decoded.content_type].into_iter().flatten().find(|t| ContentType::parse(t).is_ok());
    let name = given.clone().unwrap_or_else(|| {
        let ext = content_type.as_deref().and_then(mime_guess::get_mime_extensions_str).and_then(|e| e.first());
        ext.map(|e| format!("attachment.{e}")).unwrap_or_else(|| "attachment".into())
    });
    let content_type = content_type.unwrap_or_else(|| mime_guess::from_path(&name).first_or_octet_stream().to_string());
    EmailAttachment { name, content_type, bytes: decoded.bytes }
}

/// Every attachment read and decoded, in order. A stored file the files service does not
/// answer, or more than [`MAX_ATTACHMENT_BYTES`] in all, fails the send.
pub async fn read_attachments(attachments: &Attachments<'_>) -> ConnResult<Vec<EmailAttachment>> {
    let mut out = Vec::with_capacity(attachments.sources.len());
    let mut total = 0usize;
    for source in &attachments.sources {
        let a = match source {
            AttachmentSource::Inline { content, name, content_type } => {
                attachment_of(decode_content(content)?, name.clone(), content_type.clone(), None)
            }
            AttachmentSource::File { url, secured, name, content_type } => {
                let files = attachments.files.ok_or_else(|| mail_error("Stored files cannot be attached here"))?;
                let Some(content) = files.read_base64(url, *secured).await?.filter(|c| !c.is_empty()) else {
                    return Err(mail_error(&format!("Attachment not found: {url}")));
                };
                attachment_of(decode_content(&content)?, name.clone(), content_type.clone(), Some(url))
            }
        };
        total += a.bytes.len();
        if total > MAX_ATTACHMENT_BYTES {
            return Err(too_large());
        }
        out.push(a);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// SMTP

/// The JavaMail session properties the SMTP service honours, read from `mailProps`.
#[derive(Debug, Clone, PartialEq)]
pub struct SmtpProps {
    pub host: String,
    pub port: u16,
    pub auth: bool,
    pub starttls: bool,
    pub starttls_required: bool,
    pub ssl: bool,
    /// `mail.smtp.ssl.trust`: `*` or the host names whose certificates are accepted unchecked.
    pub trust: Option<String>,
    pub send_partial: bool,
    pub connect_timeout: Option<Duration>,
    pub timeout: Option<Duration>,
    pub envelope_from: Option<String>,
    pub local_host: Option<String>,
}

/// `PropUtil.getBooleanProperty`: a `Boolean`, or a string equal to `true` ignoring case.
fn prop_bool(props: &Map<String, Value>, key: &str) -> bool {
    match props.get(key) {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s.eq_ignore_ascii_case("true"),
        _ => false,
    }
}

/// `Properties.getProperty`: only string values count.
fn prop_str(props: &Map<String, Value>, key: &str) -> Option<String> {
    props.get(key).and_then(Value::as_str).map(str::to_string)
}

fn prop_int(props: &Map<String, Value>, key: &str) -> Option<i64> {
    match props.get(key) {
        Some(Value::Number(n)) => n.as_i64(),
        Some(Value::String(s)) => s.trim().parse().ok(),
        _ => None,
    }
}

/// The connect and read timeouts when `mailProps` set none (JavaMail waits forever).
pub const DEFAULT_SMTP_TIMEOUT: Duration = Duration::from_secs(60);

/// How much longer than the read timeout the message itself may take to go out: one second
/// for every 100 KiB (20 MB of attachments get about three and a half minutes more).
const MESSAGE_BYTES_PER_SECOND: usize = 100 * 1024;

impl SmtpProps {
    pub fn from_props(props: &Map<String, Value>) -> Self {
        let ms = |k: &str| {
            let set = prop_int(props, k).filter(|v| *v > 0).map(|v| Duration::from_millis(v as u64));
            Some(set.unwrap_or(DEFAULT_SMTP_TIMEOUT))
        };
        SmtpProps {
            host: prop_str(props, "mail.smtp.host").or_else(|| prop_str(props, "mail.host")).unwrap_or_else(|| "localhost".into()),
            port: prop_int(props, "mail.smtp.port").and_then(|p| u16::try_from(p).ok()).unwrap_or(25),
            auth: prop_bool(props, "mail.smtp.auth"),
            starttls: prop_bool(props, "mail.smtp.starttls.enable"),
            starttls_required: prop_bool(props, "mail.smtp.starttls.required"),
            ssl: prop_bool(props, "mail.smtp.ssl.enable"),
            trust: prop_str(props, "mail.smtp.ssl.trust"),
            send_partial: prop_bool(props, "mail.smtp.sendpartial"),
            connect_timeout: ms("mail.smtp.connectiontimeout"),
            timeout: ms("mail.smtp.timeout"),
            envelope_from: prop_str(props, "mail.smtp.from"),
            local_host: prop_str(props, "mail.smtp.localhost"),
        }
    }

    fn trusts(&self) -> bool {
        self.trust.as_deref().is_some_and(|t| t.trim() == "*" || t.split_whitespace().any(|h| h == self.host))
    }

    fn tls(&self) -> ConnResult<TlsParameters> {
        TlsParameters::builder(self.host.clone())
            .dangerous_accept_invalid_certs(self.trusts())
            .build_rustls()
            .map_err(|e| ConnError::other(e.to_string()))
    }
}

/// How the SMTP server answered one recipient, as JavaMail sorts it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RcptOutcome {
    Valid,
    /// 4xx: valid, but not sent to.
    ValidUnsent,
    Invalid,
}

/// `SMTPTransport.rcptTo`'s reading of a reply code.
pub fn classify_rcpt(code: u16) -> RcptOutcome {
    match code {
        250 | 251 => RcptOutcome::Valid,
        550 | 553 | 503 | 551 | 501 => RcptOutcome::Invalid,
        552 | 450 | 451 | 452 => RcptOutcome::ValidUnsent,
        400..=499 => RcptOutcome::ValidUnsent,
        // 5xx and anything unexpected (OCI answers a suppressed address with 254).
        _ => RcptOutcome::Invalid,
    }
}

fn smtp_code(e: &lettre::transport::smtp::Error) -> Option<u16> {
    e.status().and_then(|c| c.to_string().parse().ok())
}

/// The message JavaMail builds: `From`, `To`, `Cc`, `Subject`, an HTML body. With attachments
/// it is `multipart/mixed`: the HTML body, then each attachment. The `bcc` mailboxes are only
/// recipients of the envelope: lettre leaves the `Bcc` header out of the message.
fn build_message(
    from: &Mailbox,
    to: &[Mailbox],
    copies: (&[Mailbox], &[Mailbox]),
    subject: &str,
    body: &str,
    attachments: &[EmailAttachment],
) -> ConnResult<Vec<u8>> {
    let mut b = lettre::Message::builder().from(from.clone());
    for t in to {
        b = b.to(t.clone());
    }
    for c in copies.0 {
        b = b.cc(c.clone());
    }
    for c in copies.1 {
        b = b.bcc(c.clone());
    }
    let b = b.subject(subject);
    let m = if attachments.is_empty() {
        b.header(ContentType::TEXT_HTML).body(body.to_string())
    } else {
        let mut parts = MultiPart::mixed().singlepart(SinglePart::html(body.to_string()));
        for a in attachments {
            let ct = ContentType::parse(&a.content_type)
                .or_else(|_| ContentType::parse("application/octet-stream"))
                .map_err(|e| ConnError::other(e.to_string()))?;
            parts = parts.singlepart(Attachment::new(a.name.clone()).body(a.bytes.clone(), ct));
        }
        b.multipart(parts)
    }
    .map_err(|e| ConnError::other(e.to_string()))?;
    Ok(m.formatted())
}

/// `SMTPService.sendMail`: true when the server took the message for at least one recipient
/// (`SendFailedException.getValidSentAddresses()`), false when it refused the recipients, an
/// error when the connection itself fails. With `block_private_targets` the SMTP host must
/// resolve only to public addresses, as a REST connection's must (`CORE.PRIVATE_TARGET_REFUSED`).
pub async fn smtp_send(conn: &Connection, details: &ProcessedEmail, block_private_targets: bool) -> ConnResult<bool> {
    let Some(cd) = conn.details() else {
        return Err(mail_error("Connection details are missing"));
    };
    let props = match cd.get("mailProps") {
        Some(Value::Object(m)) if !m.is_empty() => m.clone(),
        _ => return Err(mail_error("Connection Properties with 'mail.' are missing")),
    };
    if java::safe_is_blank(cd.get("username")) || java::safe_is_blank(cd.get("password")) {
        return Err(mail_error("Connection username/password is missing"));
    }
    let user = java::to_java_string(&cd["username"]);
    let password = java::to_java_string(&cd["password"]);
    let props = SmtpProps::from_props(&props);

    let from: Mailbox = details.from.parse().map_err(|e: lettre::address::AddressError| mail_error(&e.to_string()))?;
    let to: Vec<Mailbox> = details
        .to
        .iter()
        .filter_map(|a| match a.parse::<Mailbox>() {
            Ok(m) => Some(m),
            Err(e) => {
                tracing::error!("Error while adding : {a} {e}");
                None
            }
        })
        .collect();
    if to.is_empty() {
        tracing::warn!("Recipients refused : No recipient addresses");
        return Ok(false);
    }
    // Checked when the step's arguments were read; a copy that still does not parse is dropped
    // as a `to` address is.
    let mailboxes = |list: &[String]| -> Vec<Mailbox> { list.iter().filter_map(|a| a.parse::<Mailbox>().ok()).collect() };
    let (cc, bcc) = (mailboxes(&details.cc), mailboxes(&details.bcc));
    let targets = if block_private_targets {
        let found = outbound::guard_host(&format!("smtp://{}:{}", props.host, props.port), &props.host).await?;
        Some(found.into_iter().map(|ip| SocketAddr::new(ip, props.port)).collect::<Vec<_>>())
    } else {
        None
    };
    let message = build_message(&from, &to, (&cc, &bcc), &details.subject, &details.body, &details.attachments)?;
    // One message, so each copy goes once whatever the number of `to` addresses.
    let copies: Vec<Mailbox> = cc.into_iter().chain(bcc).collect();
    match deliver(&props, targets.as_deref(), &user, &password, &from, &to, &copies, &message).await {
        Ok(sent) => Ok(sent),
        Err(e) => {
            tracing::error!("Error while sending : {}", e.message());
            Err(mail_error(e.message()))
        }
    }
}

/// `mail.smtp.timeout`, JavaMail's socket read timeout, applied to each exchange with the
/// server (a command and its reply).
async fn timed<T>(limit: Option<Duration>, f: impl std::future::Future<Output = T>) -> ConnResult<T> {
    match limit {
        None => Ok(f.await),
        Some(d) => tokio::time::timeout(d, f).await.map_err(|_| ConnError::other("Read timed out")),
    }
}

/// `targets`: the addresses the guard checked, connected to instead of the host's name.
/// `copies` (the CC and BCC mailboxes) are recipients too, but one the server refuses is only
/// logged: whether the mail goes out is decided by the `to` addresses alone.
#[allow(clippy::too_many_arguments)]
async fn deliver(
    props: &SmtpProps,
    targets: Option<&[SocketAddr]>,
    user: &str,
    password: &str,
    from: &Mailbox,
    to: &[Mailbox],
    copies: &[Mailbox],
    message: &[u8],
) -> ConnResult<bool> {
    let net = |e: lettre::transport::smtp::Error| ConnError::other(e.to_string());
    let hello = ClientId::Domain(props.local_host.clone().unwrap_or_else(|| "localhost".into()));
    let tls = if props.ssl { Some(props.tls()?) } else { None };
    let shown_timeout = props.connect_timeout.map(|d| d.as_millis() as i64).unwrap_or(-1);
    let connected = match targets {
        Some(addrs) => timed(props.timeout, AsyncSmtpConnection::connect_tokio1(addrs, props.connect_timeout, &hello, tls, None)).await?,
        None => {
            let server = (props.host.as_str(), props.port);
            timed(props.timeout, AsyncSmtpConnection::connect_tokio1(server, props.connect_timeout, &hello, tls, None)).await?
        }
    };
    let mut c = connected.map_err(|e| {
        ConnError::other(format!("Couldn't connect to host, port: {}, {}; timeout {shown_timeout}; {e}", props.host, props.port))
    })?;
    let t = props.timeout;
    if !props.ssl && props.starttls {
        if c.can_starttls() {
            timed(t, c.starttls(props.tls()?, &hello)).await?.map_err(net)?;
        } else if props.starttls_required {
            return Err(ConnError::other("STARTTLS is required but host does not support STARTTLS"));
        }
    }
    if props.auth {
        let creds = lettre::transport::smtp::authentication::Credentials::new(user.into(), password.into());
        let mechanisms = [
            lettre::transport::smtp::authentication::Mechanism::Plain,
            lettre::transport::smtp::authentication::Mechanism::Login,
        ];
        timed(t, c.auth(&mechanisms, &creds)).await?.map_err(net)?;
    }
    let sender: Address = match &props.envelope_from {
        Some(f) => f.parse().map_err(|e: lettre::address::AddressError| ConnError::other(e.to_string()))?,
        None => from.email.clone(),
    };
    timed(t, c.command(Mail::new(Some(sender), vec![]))).await?.map_err(net)?;

    let mut valid = 0usize;
    let mut failed = false;
    for (i, rcpt) in to.iter().chain(copies).enumerate() {
        let code = match timed(t, c.command(Rcpt::new(rcpt.email.clone(), vec![]))).await? {
            Ok(r) => r.code().to_string().parse().unwrap_or(0),
            Err(e) => match smtp_code(&e) {
                Some(code) => code,
                None => return Err(net(e)),
            },
        };
        let valid_rcpt = classify_rcpt(code) == RcptOutcome::Valid;
        if i >= to.len() {
            if !valid_rcpt {
                tracing::warn!("Copy recipient refused : {} {code}", rcpt.email);
            }
        } else if valid_rcpt {
            valid += 1;
        } else {
            failed = true;
        }
    }
    if valid == 0 || (failed && !props.send_partial) {
        let _ = timed(t, c.command(Rset)).await;
        let _ = timed(t, c.quit()).await;
        tracing::warn!("Recipients refused : Invalid Addresses");
        return Ok(false);
    }
    timed(t, c.command(Data)).await?.map_err(net)?;
    let sending = t.map(|d| d + Duration::from_secs((message.len() / MESSAGE_BYTES_PER_SECOND) as u64));
    timed(sending, c.message(message)).await?.map_err(net)?;
    let _ = timed(t, c.quit()).await;
    Ok(true)
}

// ---------------------------------------------------------------------------------------------
// SendGrid

/// `getSendGridBody`, with `cc` and `bcc` in the personalization and `attachments` (base64)
/// when there are any.
pub fn sendgrid_body(details: &ProcessedEmail) -> Value {
    let emails = |list: &[String]| list.iter().map(|e| json!({"email": e})).collect::<Vec<_>>();
    let mut personalization = json!({"to": emails(&details.to)});
    if !details.cc.is_empty() {
        personalization["cc"] = emails(&details.cc).into();
    }
    if !details.bcc.is_empty() {
        personalization["bcc"] = emails(&details.bcc).into();
    }
    let mut body = json!({
        "personalizations": [personalization],
        "from": {"email": details.from},
        "subject": details.subject,
        "content": [{"type": "text/html", "value": details.body}],
    });
    if !details.attachments.is_empty() {
        body["attachments"] = details
            .attachments
            .iter()
            .map(|a| {
                json!({
                    "content": base64::engine::general_purpose::STANDARD.encode(&a.bytes),
                    "type": a.content_type,
                    "filename": a.name,
                    "disposition": "attachment",
                })
            })
            .collect();
    }
    body
}

/// `SendGridService.sendMail`: posts to SendGrid; a refusal is an error carrying the response
/// body. A 2xx is sent (see DIFFERENCES.md for the empty 202 Java mishandles).
pub async fn sendgrid_send(http: &HttpClient, url: &str, conn: &Connection, details: &ProcessedEmail) -> ConnResult<bool> {
    let Some(api_key) = conn.detail("apiKey").filter(|v| !java::safe_is_blank(Some(v))).map(java::to_java_string) else {
        return Err(mail_error("SENDGRID api key is not found"));
    };
    let body = json::jackson(&sendgrid_body(details)).into_bytes();
    let response = http
        .send(OutboundRequest {
            method: "POST".into(),
            uri: url.into(),
            headers: vec![("Authorization".into(), format!("Bearer {api_key}")), ("Content-Type".into(), "application/json".into())],
            body: Some(body),
        })
        .await?;
    let status = response.status;
    let text = String::from_utf8_lossy(&response.read_body(16 * 1024 * 1024).await?).into_owned();
    if status >= 400 {
        tracing::error!("Error while sending it to send grid : {text}");
        return Err(mail_error(&format!("Error with body : {text}")));
    }
    Ok(true)
}

// ---------------------------------------------------------------------------------------------
// EmailService / SendEmail

/// Where SendGrid mail goes (the fixed Java URL unless configured otherwise for a test).
pub struct EmailContext<'a> {
    pub connections: &'a dyn ConnectionStore,
    pub templates: &'a dyn TemplateStore,
    pub http: &'a HttpClient,
    pub sendgrid_url: &'a str,
    /// `core.rest.blockPrivateTargets`, which SMTP hosts follow too.
    pub block_private_targets: bool,
}

/// `EmailService.sendEmail(appCode, clientCode, addresses, templateName, connectionName, data)`.
/// `None` is Java's empty result (no security context to resolve blank codes from).
#[allow(clippy::too_many_arguments)]
pub async fn send_email(
    ctx: &EmailContext<'_>,
    caller: &Caller,
    app_code: Option<&str>,
    client_code: Option<&str>,
    addresses: &[String],
    template_name: &str,
    connection_name: Option<&str>,
    data: &Map<String, Value>,
) -> ConnResult<Option<bool>> {
    let none = Attachments::default();
    send_email_attaching(ctx, caller, app_code, client_code, addresses, &none, &Copies::default(), template_name, connection_name, data).await
}

/// [`send_email`] with attachments, read once the connection and the template are found and
/// the template is rendered, and copies, less the `to` addresses the template gives.
#[allow(clippy::too_many_arguments)]
pub async fn send_email_attaching(
    ctx: &EmailContext<'_>,
    caller: &Caller,
    app_code: Option<&str>,
    client_code: Option<&str>,
    addresses: &[String],
    attachments: &Attachments<'_>,
    copies: &Copies,
    template_name: &str,
    connection_name: Option<&str>,
    data: &Map<String, Value>,
) -> ConnResult<Option<bool>> {
    let (Some(app), Some(client)) = caller.resolve_app_and_client(app_code, client_code) else { return Ok(None) };
    let name = connection_name.unwrap_or("");
    let Some(conn) = connection::read(ctx.connections, caller, name, &app, &client, ConnectionType::Mail).await? else {
        return Err(ConnError::msg(StatusCode::NOT_FOUND, messages::CONNECTION_DETAILS_MISSING, &[connection_name.unwrap_or("null")]));
    };
    let sub = conn.connection_sub_type;
    if !matches!(sub, Some(ConnectionSubType::SendGrid) | Some(ConnectionSubType::Smtp)) {
        let shown = sub.map(|s| s.name()).unwrap_or("null");
        return Err(ConnError::msg_as(StatusCode::NOT_FOUND, messages::CONNECTION_DETAILS_MISSING, "CORE.MAIL_CONNECTION_UNSUPPORTED", &[shown]));
    }
    let Some(tmpl) = ctx.templates.read(template_name, &app, &client).await? else {
        return Err(ConnError::msg(StatusCode::NOT_FOUND, messages::TEMPLATE_DETAILS_MISSING, &[template_name]));
    };
    if sub == Some(ConnectionSubType::SendGrid)
        && conn.details().is_none_or(|d| java::safe_is_blank(d.get("apiKey")))
    {
        return Err(mail_error("SENDGRID api key is not found"));
    }
    if sub == Some(ConnectionSubType::Smtp) {
        // The SMTP service checks its connection before rendering anything.
        let cd = conn.details().ok_or_else(|| mail_error("Connection details are missing"))?;
        if !matches!(cd.get("mailProps"), Some(Value::Object(m)) if !m.is_empty()) {
            return Err(mail_error("Connection Properties with 'mail.' are missing"));
        }
        if java::safe_is_blank(cd.get("username")) || java::safe_is_blank(cd.get("password")) {
            return Err(mail_error("Connection username/password is missing"));
        }
    }
    let mut details = processed_email(&conn, addresses, &tmpl, data)?;
    let copies = copies.without(&details.to);
    (details.cc, details.bcc) = (copies.cc, copies.bcc);
    details.attachments = read_attachments(attachments).await?;
    let sent = match sub {
        Some(ConnectionSubType::SendGrid) => sendgrid_send(ctx.http, ctx.sendgrid_url, &conn, &details).await?,
        _ => smtp_send(&conn, &details, ctx.block_private_targets).await?,
    };
    Ok(Some(sent))
}

/// `SendEmail.internalExecute`: `false` outside a KIRun runtime; otherwise the blank codes
/// come from the caller and the result is whether the mail went out. `None` is no output.
#[allow(clippy::too_many_arguments)]
pub async fn send_email_function(
    ctx: &EmailContext<'_>,
    caller: &Caller,
    app_code: &str,
    client_code: &str,
    connection_name: Option<&str>,
    template_name: &str,
    address: Option<&Value>,
    data: &Map<String, Value>,
    attachments: &Attachments<'_>,
    copies: &Copies,
) -> ConnResult<Option<bool>> {
    if !caller.in_kirun {
        return Ok(Some(false));
    }
    let addresses = given_addresses(address);
    let data = java::hash_map_order_deep(Value::Object(data.clone()));
    let data = data.as_object().cloned().unwrap_or_default();
    let (to, a, c) = (&addresses, attachments, copies);
    if caller.present {
        let app = if java::trim(app_code).is_empty() { caller.url_app_code.clone() } else { Some(app_code.to_string()) };
        let client = if java::trim(client_code).is_empty() { caller.client_code.clone() } else { Some(client_code.to_string()) };
        if let Some(sent) =
            send_email_attaching(ctx, caller, app.as_deref(), client.as_deref(), to, a, c, template_name, connection_name, &data).await?
        {
            return Ok(Some(sent));
        }
    }
    send_email_attaching(ctx, caller, Some(app_code), Some(client_code), to, a, c, template_name, connection_name, &data).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpl(to: Option<&str>) -> EmailTemplate {
        EmailTemplate { to_expression: to.map(str::to_string), ..Default::default() }
    }

    fn data() -> Map<String, Value> {
        json!({"email": "c@x.com"}).as_object().unwrap().clone()
    }

    /// EmailToAddressesTest.
    #[test]
    fn to_addresses_like_java() {
        assert_eq!(to_addresses(&[String::new()], &tmpl(Some("${email}")), &data()).unwrap(), vec!["c@x.com"]);
        assert_eq!(
            to_addresses(&["a@x.com".into(), " ".into()], &tmpl(Some("${email}; d@x.com")), &data()).unwrap(),
            vec!["a@x.com", "c@x.com", "d@x.com"]
        );
        let e = to_addresses(&[String::new()], &tmpl(None), &data()).unwrap_err();
        assert_eq!(e.message(), "Unable to send the email: No Send Addresses Found.");
        assert_eq!(e.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(to_addresses(&["a@x.com".into()], &tmpl(Some("")), &data()).unwrap(), vec!["a@x.com"]);
    }

    /// SendEmailAddressesTest.
    #[test]
    fn given_addresses_like_java() {
        assert!(given_addresses(Some(&json!([""]))).is_empty());
        assert_eq!(given_addresses(Some(&json!(["", " a@x.com ", null, "   ", "b@x.com"]))), vec!["a@x.com", "b@x.com"]);
        assert!(given_addresses(None).is_empty());
        assert!(given_addresses(Some(&Value::Null)).is_empty());
    }

    #[test]
    fn rcpt_codes_as_javamail_sorts_them() {
        assert_eq!(classify_rcpt(250), RcptOutcome::Valid);
        assert_eq!(classify_rcpt(251), RcptOutcome::Valid);
        assert_eq!(classify_rcpt(550), RcptOutcome::Invalid);
        assert_eq!(classify_rcpt(254), RcptOutcome::Invalid);
        assert_eq!(classify_rcpt(452), RcptOutcome::ValidUnsent);
        assert_eq!(classify_rcpt(421), RcptOutcome::ValidUnsent);
        assert_eq!(classify_rcpt(599), RcptOutcome::Invalid);
    }

    #[test]
    fn smtp_props_from_mail_props() {
        let p = SmtpProps::from_props(
            json!({"mail.smtp.host": "smtp.example.com", "mail.smtp.port": "587", "mail.smtp.auth": "true",
                   "mail.smtp.starttls.enable": true, "mail.smtp.ssl.trust": "*", "mail.smtp.timeout": 5000})
            .as_object()
            .unwrap(),
        );
        assert_eq!((p.host.as_str(), p.port, p.auth, p.starttls, p.ssl), ("smtp.example.com", 587, true, true, false));
        assert!(p.trusts());
        assert_eq!(p.timeout, Some(Duration::from_secs(5)));
        assert_eq!(p.connect_timeout, Some(DEFAULT_SMTP_TIMEOUT));
        let d = SmtpProps::from_props(&Map::new());
        assert_eq!((d.host.as_str(), d.port, d.auth), ("localhost", 25, false));
        assert_eq!((d.timeout, d.connect_timeout), (Some(Duration::from_secs(60)), Some(Duration::from_secs(60))));
        // Zero or negative is not a timeout JavaMail honours either: the default.
        let z = SmtpProps::from_props(json!({"mail.smtp.timeout": 0, "mail.smtp.connectiontimeout": "-5"}).as_object().unwrap());
        assert_eq!((z.timeout, z.connect_timeout), (Some(DEFAULT_SMTP_TIMEOUT), Some(DEFAULT_SMTP_TIMEOUT)));
        // A non-string host is not a property JavaMail reads.
        assert_eq!(SmtpProps::from_props(json!({"mail.smtp.host": 5}).as_object().unwrap()).host, "localhost");
    }

    #[test]
    fn sendgrid_body_shape() {
        let mut d = ProcessedEmail { to: vec!["a@x.com".into()], from: "f@x.com".into(), subject: "S".into(), body: "<p>B</p>".into(), ..Default::default() };
        assert_eq!(
            json::jackson(&sendgrid_body(&d)),
            r#"{"personalizations":[{"to":[{"email":"a@x.com"}]}],"from":{"email":"f@x.com"},"subject":"S","content":[{"type":"text/html","value":"<p>B</p>"}]}"#
        );
        d.attachments = vec![EmailAttachment { name: "a.txt".into(), content_type: "text/plain".into(), bytes: b"hi".to_vec() }];
        assert_eq!(
            sendgrid_body(&d)["attachments"],
            json!([{"content": "aGk=", "type": "text/plain", "filename": "a.txt", "disposition": "attachment"}])
        );
    }

    #[test]
    fn attachment_sources_from_the_argument() {
        let s = attachment_sources(Some(&json!([
            null,
            "  ",
            "/api/files/secured/file/C1/inv/a%20b.pdf",
            "data:text/plain;base64,aGk=",
            {"url": "https://h/api/files/static/file/C1/x.png", "name": "logo.png", "directory": false},
            {"content": "aGk", "name": "n.txt", "contentType": "text/plain"}
        ])))
        .unwrap();
        assert_eq!(
            s,
            vec![
                AttachmentSource::File { url: "/api/files/secured/file/C1/inv/a%20b.pdf".into(), secured: true, name: None, content_type: None },
                AttachmentSource::Inline { content: "data:text/plain;base64,aGk=".into(), name: None, content_type: None },
                AttachmentSource::File {
                    url: "https://h/api/files/static/file/C1/x.png".into(),
                    secured: false,
                    name: Some("logo.png".into()),
                    content_type: None
                },
                AttachmentSource::Inline { content: "aGk".into(), name: Some("n.txt".into()), content_type: Some("text/plain".into()) },
            ]
        );
        assert!(attachment_sources(None).unwrap().is_empty());
        let e = attachment_sources(Some(&json!(["https://evil.example/x.pdf"]))).unwrap_err();
        assert_eq!(e.message(), "Unable to send the email: Attachment is not a stored file: https://evil.example/x.pdf");
        assert!(attachment_sources(Some(&json!([{"name": "x"}]))).is_err());
        assert!(attachment_sources(Some(&json!([5]))).is_err());
    }

    #[test]
    fn attachment_names_and_types() {
        // The files service's data URL: its type and name.
        let a = attachment_of(decode_content("data:application/pdf;name:Invoice, May.pdf;base64,aGk=").unwrap(), None, None, None);
        assert_eq!((a.name.as_str(), a.content_type.as_str(), a.bytes.as_slice()), ("Invoice, May.pdf", "application/pdf", &b"hi"[..]));
        // A browser's data URL, a name given, the URL's name, and the type from the name.
        let a = attachment_of(decode_content("data:text/csv;name=r%C3%A9sum%C3%A9.csv;base64,aGk=").unwrap(), None, None, None);
        assert_eq!(a.name, "résumé.csv");
        let a = attachment_of(decode_content("aGk").unwrap(), None, None, Some("/api/files/static/file/C1/q/a%20b.png?x=1"));
        assert_eq!((a.name.as_str(), a.content_type.as_str()), ("a b.png", "image/png"));
        let a = attachment_of(decode_content("aGk=").unwrap(), Some("x\r\n/y\".pdf".into()), Some("not a type".into()), None);
        assert_eq!((a.name.as_str(), a.content_type.as_str()), ("x___y_.pdf", "application/pdf"));
        // Nothing names it: `attachment`, with the type's extension when there is one.
        assert_eq!(attachment_of(decode_content("data:application/pdf;base64,aGk=").unwrap(), None, None, None).name, "attachment.pdf");
        assert_eq!(attachment_of(decode_content("aGk=").unwrap(), None, None, None).content_type, "application/octet-stream");
        // A text data URL, and content that is not base64.
        assert_eq!(decode_content("data:text/plain,a%20b").unwrap().bytes, b"a b");
        assert_eq!(decode_content("not base64!").err().unwrap().message(), "Unable to send the email: An attachment's content is not base64");
    }

    #[test]
    fn message_with_attachments_is_multipart() {
        let from: Mailbox = "f@x.com".parse().unwrap();
        let to: Vec<Mailbox> = vec!["a@x.com".parse().unwrap()];
        let a = EmailAttachment { name: "r.pdf".into(), content_type: "application/pdf".into(), bytes: vec![0, 1, 2, 255] };
        let m = String::from_utf8(build_message(&from, &to, (&[], &[]), "S", "<p>B</p>", &[a]).unwrap()).unwrap();
        assert!(m.contains("Content-Type: multipart/mixed"), "{m}");
        assert!(m.contains("Content-Type: text/html"), "{m}");
        assert!(m.contains("Content-Disposition: attachment; filename=\"r.pdf\""), "{m}");
        assert!(m.contains("Content-Type: application/pdf"), "{m}");
        assert!(m.contains("AAEC/w=="), "{m}");
        let plain = String::from_utf8(build_message(&from, &to, (&[], &[]), "S", "<p>B</p>", &[]).unwrap()).unwrap();
        assert!(!plain.contains("multipart"), "{plain}");
    }
}
