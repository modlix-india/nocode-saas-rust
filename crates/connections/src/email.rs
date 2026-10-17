//! Email: `EmailService` (pick the MAIL connection and the template), `AbstractEmailService`
//! (recipients, sender, language and the rendered parts), `SMTPService` and `SendGridService`,
//! and what `CoreServices.Email.SendEmail` reports.

use std::time::Duration;

use async_trait::async_trait;
use http::StatusCode;
use lettre::message::header::ContentType;
use lettre::message::Mailbox;
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

/// `ProcessedEmailDetails`.
#[derive(Debug, Clone, PartialEq)]
pub struct ProcessedEmail {
    pub to: Vec<String>,
    pub from: String,
    pub subject: String,
    pub body: String,
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

/// `getLanguage`: the rendered `languageExpression`, the default language when that renders
/// blank, `""` when neither is set. A default language without an expression fails, as in Java
/// (the expression is rendered while null).
pub fn language(tmpl: &EmailTemplate, data: &Map<String, Value>) -> ConnResult<Option<String>> {
    let expr_blank = tmpl.language_expression.as_deref().is_none_or(java::is_blank);
    let default_blank = tmpl.default_language.as_deref().is_none_or(java::is_blank);
    if expr_blank && default_blank {
        return Ok(Some(String::new()));
    }
    let rendered = template::process("language", tmpl.language_expression.as_deref(), data)?;
    if java::is_blank(&rendered) {
        Ok(tmpl.default_language.clone())
    } else {
        Ok(Some(rendered))
    }
}

/// `getProcessedTemplate`: every part of the language's set rendered (`en` when the language
/// is blank, the first set when the language has none).
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
    let key = if java::is_blank(language) { "en" } else { language };
    let set = match parts.get(key) {
        Some(v) => v.clone(),
        None => parts.values().next().cloned().unwrap_or(Value::Null),
    };
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
    Ok(ProcessedEmail { to, from, subject: part("subject"), body: part("body") })
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

impl SmtpProps {
    pub fn from_props(props: &Map<String, Value>) -> Self {
        let ms = |k: &str| prop_int(props, k).filter(|v| *v > 0).map(|v| Duration::from_millis(v as u64));
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

/// The message JavaMail builds: `From`, `To`, `Subject`, an HTML body.
fn build_message(from: &Mailbox, to: &[Mailbox], subject: &str, body: &str) -> ConnResult<Vec<u8>> {
    let mut b = lettre::Message::builder().from(from.clone());
    for t in to {
        b = b.to(t.clone());
    }
    let m = b
        .subject(subject)
        .header(ContentType::TEXT_HTML)
        .body(body.to_string())
        .map_err(|e| ConnError::other(e.to_string()))?;
    Ok(m.formatted())
}

/// `SMTPService.sendMail`: true when the server took the message for at least one recipient
/// (`SendFailedException.getValidSentAddresses()`), false when it refused the recipients, an
/// error when the connection itself fails.
pub async fn smtp_send(conn: &Connection, details: &ProcessedEmail) -> ConnResult<bool> {
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
    let message = build_message(&from, &to, &details.subject, &details.body)?;
    match deliver(&props, &user, &password, &from, &to, &message).await {
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

async fn deliver(props: &SmtpProps, user: &str, password: &str, from: &Mailbox, to: &[Mailbox], message: &[u8]) -> ConnResult<bool> {
    let net = |e: lettre::transport::smtp::Error| ConnError::other(e.to_string());
    let hello = ClientId::Domain(props.local_host.clone().unwrap_or_else(|| "localhost".into()));
    let tls = if props.ssl { Some(props.tls()?) } else { None };
    let shown_timeout = props.connect_timeout.map(|d| d.as_millis() as i64).unwrap_or(-1);
    let connect = AsyncSmtpConnection::connect_tokio1((props.host.as_str(), props.port), props.connect_timeout, &hello, tls, None);
    let mut c = timed(props.timeout, connect).await?.map_err(|e| {
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
    for to in to {
        let code = match timed(t, c.command(Rcpt::new(to.email.clone(), vec![]))).await? {
            Ok(r) => r.code().to_string().parse().unwrap_or(0),
            Err(e) => match smtp_code(&e) {
                Some(code) => code,
                None => return Err(net(e)),
            },
        };
        match classify_rcpt(code) {
            RcptOutcome::Valid => valid += 1,
            _ => failed = true,
        }
    }
    if valid == 0 || (failed && !props.send_partial) {
        let _ = timed(t, c.command(Rset)).await;
        let _ = timed(t, c.quit()).await;
        tracing::warn!("Recipients refused : Invalid Addresses");
        return Ok(false);
    }
    timed(t, c.command(Data)).await?.map_err(net)?;
    timed(t, c.message(message)).await?.map_err(net)?;
    let _ = timed(t, c.quit()).await;
    Ok(true)
}

// ---------------------------------------------------------------------------------------------
// SendGrid

/// `getSendGridBody`.
pub fn sendgrid_body(details: &ProcessedEmail) -> Value {
    json!({
        "personalizations": [{"to": details.to.iter().map(|e| json!({"email": e})).collect::<Vec<_>>()}],
        "from": {"email": details.from},
        "subject": details.subject,
        "content": [{"type": "text/html", "value": details.body}],
    })
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
}

/// `EmailService.sendEmail(appCode, clientCode, addresses, templateName, connectionName, data)`.
/// `None` is Java's empty result (no security context to resolve blank codes from).
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
    let details = processed_email(&conn, addresses, &tmpl, data)?;
    let sent = match sub {
        Some(ConnectionSubType::SendGrid) => sendgrid_send(ctx.http, ctx.sendgrid_url, &conn, &details).await?,
        _ => smtp_send(&conn, &details).await?,
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
) -> ConnResult<Option<bool>> {
    if !caller.in_kirun {
        return Ok(Some(false));
    }
    let addresses = given_addresses(address);
    let data = java::hash_map_order_deep(Value::Object(data.clone()));
    let data = data.as_object().cloned().unwrap_or_default();
    if caller.present {
        let app = if java::trim(app_code).is_empty() { caller.url_app_code.clone() } else { Some(app_code.to_string()) };
        let client = if java::trim(client_code).is_empty() { caller.client_code.clone() } else { Some(client_code.to_string()) };
        if let Some(sent) =
            send_email(ctx, caller, app.as_deref(), client.as_deref(), &addresses, template_name, connection_name, &data).await?
        {
            return Ok(Some(sent));
        }
    }
    send_email(ctx, caller, Some(app_code), Some(client_code), &addresses, template_name, connection_name, &data).await
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
        let d = SmtpProps::from_props(&Map::new());
        assert_eq!((d.host.as_str(), d.port, d.auth), ("localhost", 25, false));
        // A non-string host is not a property JavaMail reads.
        assert_eq!(SmtpProps::from_props(json!({"mail.smtp.host": 5}).as_object().unwrap()).host, "localhost");
    }

    #[test]
    fn sendgrid_body_shape() {
        let d = ProcessedEmail { to: vec!["a@x.com".into()], from: "f@x.com".into(), subject: "S".into(), body: "<p>B</p>".into() };
        assert_eq!(
            json::jackson(&sendgrid_body(&d)),
            r#"{"personalizations":[{"to":[{"email":"a@x.com"}]}],"from":{"email":"f@x.com"},"subject":"S","content":[{"type":"text/html","value":"<p>B</p>"}]}"#
        );
    }
}
