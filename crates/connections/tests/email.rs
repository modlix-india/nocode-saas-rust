//! Email end to end against local fakes: an SMTP stub (the Java `SMTPServiceTest`'s, ported)
//! and a stand-in SendGrid endpoint. No real mail provider is contacted.

use std::sync::Arc;

use async_trait::async_trait;
use connections::connection::{Connection, ConnectionStore};
use connections::context::Caller;
use connections::email::{self, EmailContext, EmailTemplate, ProcessedEmail, TemplateStore};
use connections::error::ConnResult;
use connections::rest::http::HttpClient;
use parking_lot::Mutex;
use serde_json::{json, Map, Value};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

/// One connection at a time; RCPT replies come from the map, everything else is accepted.
/// `rcpts` is every envelope recipient asked for, `accepted` every message taken.
struct StubSmtp {
    port: u16,
    accepted: Arc<Mutex<Vec<String>>>,
    rcpts: Arc<Mutex<Vec<String>>>,
}

impl StubSmtp {
    async fn start(rcpt_replies: Vec<(&'static str, &'static str)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(Mutex::new(Vec::new()));
        let acc = accepted.clone();
        let rcpts = Arc::new(Mutex::new(Vec::new()));
        let asked = rcpts.clone();
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else { return };
                let (r, mut w) = sock.into_split();
                let mut lines = BufReader::new(r).lines();
                w.write_all(b"220 stub ready\r\n").await.unwrap();
                while let Ok(Some(line)) = lines.next_line().await {
                    let cmd = line.to_uppercase();
                    let reply = if cmd.starts_with("EHLO") || cmd.starts_with("HELO") {
                        "250 stub".to_string()
                    } else if cmd.starts_with("RCPT") {
                        let addr = &line[line.find('<').unwrap() + 1..line.find('>').unwrap()];
                        asked.lock().push(addr.to_string());
                        rcpt_replies.iter().find(|(a, _)| *a == addr).map(|(_, r)| r.to_string()).unwrap_or_else(|| "250 ok".into())
                    } else if cmd.starts_with("DATA") {
                        w.write_all(b"354 go ahead\r\n").await.unwrap();
                        let mut msg = String::new();
                        while let Ok(Some(l)) = lines.next_line().await {
                            if l == "." {
                                break;
                            }
                            msg.push_str(&l);
                            msg.push('\n');
                        }
                        acc.lock().push(msg);
                        "250 queued".into()
                    } else if cmd.starts_with("QUIT") {
                        w.write_all(b"221 bye\r\n").await.unwrap();
                        break;
                    } else {
                        "250 ok".into()
                    };
                    w.write_all(format!("{reply}\r\n").as_bytes()).await.unwrap();
                }
            }
        });
        StubSmtp { port, accepted, rcpts }
    }
}

const SUPPRESSED: &str = "254 4.7.1 -  gone@example.com is suppressed for sender ocid1.emailsender";

fn smtp_connection(port: u16, extra: Value) -> Connection {
    let mut props = json!({"mail.smtp.host": "127.0.0.1", "mail.smtp.port": port.to_string()});
    for (k, v) in extra.as_object().unwrap() {
        props[k] = v.clone();
    }
    Connection::from_json(json!({
        "name": "mail", "appCode": "app", "clientCode": "SYSTEM", "isAppLevel": true,
        "connectionType": "MAIL", "connectionSubType": "SMTP",
        "connectionDetails": {"mailProps": props, "username": "user", "password": "secret", "fromAddress": "noreply@example.com"}
    }))
    .unwrap()
}

fn details(to: &[&str]) -> ProcessedEmail {
    ProcessedEmail {
        to: to.iter().map(|s| s.to_string()).collect(),
        from: "noreply@example.com".into(),
        subject: "Welcome".into(),
        body: "<p>Hi</p>".into(),
        ..Default::default()
    }
}

#[tokio::test]
async fn suppressed_recipient_is_not_sent_instead_of_an_error() {
    let s = StubSmtp::start(vec![("gone@example.com", SUPPRESSED)]).await;
    assert!(!email::smtp_send(&smtp_connection(s.port, json!({})), &details(&["gone@example.com"]), false).await.unwrap());
}

#[tokio::test]
async fn permanently_rejected_recipient_is_not_sent() {
    let s = StubSmtp::start(vec![("gone@example.com", "550 5.1.1 no such user")]).await;
    assert!(!email::smtp_send(&smtp_connection(s.port, json!({})), &details(&["gone@example.com"]), false).await.unwrap());
}

#[tokio::test]
async fn partial_send_counts_as_sent() {
    let s = StubSmtp::start(vec![("gone@example.com", "550 5.1.1 no such user")]).await;
    let conn = smtp_connection(s.port, json!({"mail.smtp.sendpartial": "true"}));
    assert!(email::smtp_send(&conn, &details(&["ok@example.com", "gone@example.com"]), false).await.unwrap());
    assert_eq!(s.accepted.lock().len(), 1);
}

#[tokio::test]
async fn without_sendpartial_one_refusal_sends_nothing() {
    let s = StubSmtp::start(vec![("gone@example.com", "550 5.1.1 no such user")]).await;
    let conn = smtp_connection(s.port, json!({}));
    assert!(!email::smtp_send(&conn, &details(&["ok@example.com", "gone@example.com"]), false).await.unwrap());
    assert!(s.accepted.lock().is_empty());
}

#[tokio::test]
async fn accepted_recipient_is_sent() {
    let s = StubSmtp::start(vec![]).await;
    assert!(email::smtp_send(&smtp_connection(s.port, json!({})), &details(&["ok@example.com"]), false).await.unwrap());
    let msgs = s.accepted.lock().clone();
    assert_eq!(msgs.len(), 1);
    assert!(msgs[0].contains("Subject: Welcome"));
    assert!(msgs[0].contains("Content-Type: text/html"));
    assert!(msgs[0].contains("<p>Hi</p>"));
}

#[tokio::test]
async fn connection_checks_and_failures() {
    let mut c = smtp_connection(1, json!({}));
    c.connection_details.as_mut().unwrap().remove("password");
    let e = email::smtp_send(&c, &details(&["a@x.com"]), false).await.unwrap_err();
    assert_eq!(e.message(), "Unable to send the email: Connection username/password is missing");
    let mut c = smtp_connection(1, json!({}));
    c.connection_details.as_mut().unwrap()["mailProps"] = json!({});
    let e = email::smtp_send(&c, &details(&["a@x.com"]), false).await.unwrap_err();
    assert_eq!(e.message(), "Unable to send the email: Connection Properties with 'mail.' are missing");
    let mut c = smtp_connection(1, json!({}));
    c.connection_details = None;
    assert_eq!(
        email::smtp_send(&c, &details(&["a@x.com"]), false).await.unwrap_err().message(),
        "Unable to send the email: Connection details are missing"
    );
    // Nothing listening: the connection failure is the error.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let e = email::smtp_send(&smtp_connection(closed, json!({})), &details(&["a@x.com"]), false).await.unwrap_err();
    assert!(e.message().starts_with("Unable to send the email: Couldn't connect to host"), "{}", e.message());
    // No usable recipient: not sent, nothing attempted.
    assert!(!email::smtp_send(&smtp_connection(closed, json!({})), &details(&["not an address"]), false).await.unwrap());
    // A sender that is not an address.
    let mut d = details(&["a@x.com"]);
    d.from = String::new();
    assert!(email::smtp_send(&smtp_connection(closed, json!({})), &d, false).await.is_err());
}

#[tokio::test]
async fn read_timeout_from_mail_smtp_timeout() {
    // Greets, then never answers EHLO.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else { return };
            tokio::spawn(async move {
                sock.write_all(b"220 slow\r\n").await.unwrap();
                let mut buf = [0u8; 256];
                while let Ok(n) = sock.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                }
            });
        }
    });
    let conn = smtp_connection(port, json!({"mail.smtp.timeout": 200, "mail.smtp.connectiontimeout": "1500"}));
    let started = std::time::Instant::now();
    let e = email::smtp_send(&conn, &details(&["a@x.com"]), false).await.unwrap_err();
    assert_eq!(e.message(), "Unable to send the email: Read timed out");
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    // A connection that fails shows the connect timeout it had.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let e = email::smtp_send(&smtp_connection(closed, json!({"mail.smtp.connectiontimeout": 1500})), &details(&["a@x.com"]), false)
        .await
        .unwrap_err();
    assert!(e.message().contains("; timeout 1500; "), "{}", e.message());
}

// --- EmailService over in-memory stores

struct Store(Vec<Connection>);
#[async_trait]
impl ConnectionStore for Store {
    async fn read_internal(&self, name: &str, _: &str, _: &str, _: &str) -> ConnResult<Option<Connection>> {
        Ok(self.0.iter().find(|c| c.name() == name).cloned())
    }
}

struct Templates(Vec<EmailTemplate>);
#[async_trait]
impl TemplateStore for Templates {
    async fn read(&self, name: &str, _: &str, _: &str) -> ConnResult<Option<EmailTemplate>> {
        Ok(self.0.iter().find(|t| t.name.as_deref() == Some(name)).cloned())
    }
}

fn welcome() -> EmailTemplate {
    EmailTemplate::from_json(json!({
        "name": "welcome",
        "toExpression": "${email}",
        "languageExpression": "${lang!\"\"}",
        "defaultLanguage": "en",
        "templateParts": {
            "en": {"subject": "Hello ${name}", "body": "<p>Hi ${name},</p>\n<#if vip>\n<b>VIP</b>\n</#if>\n"},
            "fr": {"subject": "Bonjour ${name}", "body": "<p>Salut</p>"}
        }
    }))
    .unwrap()
}

fn caller() -> Caller {
    Caller {
        present: true,
        authenticated: true,
        client_code: Some("SYSTEM".into()),
        url_client_code: Some("SYSTEM".into()),
        url_app_code: Some("app".into()),
        in_kirun: true,
        ..Default::default()
    }
}

fn data(v: Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

#[tokio::test]
async fn send_email_renders_the_template_and_sends_by_smtp() {
    let s = StubSmtp::start(vec![]).await;
    let store = Store(vec![smtp_connection(s.port, json!({}))]);
    let templates = Templates(vec![welcome()]);
    let http = HttpClient { block_private_targets: false };
    let ctx = EmailContext { connections: &store, templates: &templates, http: &http, sendgrid_url: "http://127.0.0.1:1", block_private_targets: false };
    let d = data(json!({"email": "ann@example.com", "name": "Ann", "vip": true, "lang": "fr"}));
    let sent = email::send_email_function(&ctx, &caller(), "", "", Some("mail"), "welcome", Some(&json!([""])), &d, &Default::default(), &Default::default()).await.unwrap();
    assert_eq!(sent, Some(true));
    let msg = s.accepted.lock()[0].clone();
    assert!(msg.contains("Subject: Bonjour Ann"), "{msg}");
    assert!(msg.contains("To: ann@example.com"), "{msg}");

    // Outside a KIRun runtime the function reports not sent.
    let mut outside = caller();
    outside.in_kirun = false;
    assert_eq!(email::send_email_function(&ctx, &outside, "", "", Some("mail"), "welcome", None, &d, &Default::default(), &Default::default()).await.unwrap(), Some(false));

    // The rendered parts.
    let tmpl = welcome();
    let conn = smtp_connection(s.port, json!({}));
    let p = email::processed_email(&conn, &[], &tmpl, &data(json!({"email": "a@x.com", "name": "Bo", "vip": true}))).unwrap();
    assert_eq!(p.subject, "Hello Bo");
    assert_eq!(p.body, "<p>Hi Bo,</p>\n<b>VIP</b>\n");
    assert_eq!(p.from, "noreply@example.com");
}

#[tokio::test]
async fn send_email_refusals() {
    let store = Store(vec![
        Connection::from_json(json!({"name": "fax", "clientCode": "SYSTEM", "connectionType": "MAIL", "connectionSubType": "OFFICE365", "connectionDetails": {"a": 1}})).unwrap(),
        Connection::from_json(json!({"name": "sg", "clientCode": "SYSTEM", "connectionType": "MAIL", "connectionSubType": "SENDGRID", "connectionDetails": {"x": 1}})).unwrap(),
        smtp_connection(1, json!({})),
    ]);
    let templates = Templates(vec![welcome()]);
    let http = HttpClient { block_private_targets: false };
    let ctx = EmailContext { connections: &store, templates: &templates, http: &http, sendgrid_url: "http://127.0.0.1:1", block_private_targets: false };
    let d = data(json!({"email": "a@x.com", "name": "A", "vip": false}));
    let c = caller();
    let e = email::send_email(&ctx, &c, None, None, &[], "welcome", Some("nope"), &d).await.unwrap_err();
    assert_eq!(e.message(), "Connection details missing nope");
    assert_eq!(e.status(), http::StatusCode::NOT_FOUND);
    let e = email::send_email(&ctx, &c, None, None, &[], "welcome", Some("fax"), &d).await.unwrap_err();
    assert_eq!(e.message(), "Connection details missing OFFICE365");
    let e = email::send_email(&ctx, &c, None, None, &[], "missing", Some("mail"), &d).await.unwrap_err();
    assert_eq!(e.message(), "Template details missing : missing");
    let e = email::send_email(&ctx, &c, None, None, &[], "welcome", Some("sg"), &d).await.unwrap_err();
    assert_eq!(e.message(), "Unable to send the email: SENDGRID api key is not found");
    // No caller to resolve blank codes from: no output.
    let none = Caller { in_kirun: true, ..Default::default() };
    assert_eq!(email::send_email_function(&ctx, &none, "", "", Some("mail"), "welcome", None, &d, &Default::default(), &Default::default()).await.unwrap(), None);
}

/// A stand-in SendGrid: records the request, answers 202 with no body, or 400 with one.
async fn fake_sendgrid(status: u16) -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let log = Arc::new(Mutex::new(Vec::new()));
    let l2 = log.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else { return };
            let mut buf = vec![0u8; 65536];
            let mut data = Vec::new();
            loop {
                let n = sock.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                data.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&data);
                if let Some(i) = text.find("\r\n\r\n") {
                    let len: usize = text
                        .lines()
                        .find(|l| l.to_lowercase().starts_with("content-length"))
                        .and_then(|l| l.split(':').nth(1))
                        .and_then(|v| v.trim().parse().ok())
                        .unwrap_or(0);
                    if data.len() >= i + 4 + len {
                        break;
                    }
                }
            }
            l2.lock().push(String::from_utf8_lossy(&data).into_owned());
            let resp = if status == 202 {
                "HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
            } else {
                let body = r#"{"errors":[{"message":"bad"}]}"#;
                format!("HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
            };
            let _ = sock.write_all(resp.as_bytes()).await;
        }
    });
    (port, log)
}

#[tokio::test]
async fn sendgrid_posts_the_java_body() {
    let (port, log) = fake_sendgrid(202).await;
    let conn = Connection::from_json(json!({"name": "sg", "connectionType": "MAIL", "connectionSubType": "SENDGRID", "connectionDetails": {"apiKey": "SG.key"}})).unwrap();
    let http = HttpClient { block_private_targets: false };
    let url = format!("http://127.0.0.1:{port}/v3/mail/send");
    assert!(email::sendgrid_send(&http, &url, &conn, &details(&["a@x.com"])).await.unwrap());
    let req = log.lock()[0].clone();
    assert!(req.starts_with("POST /v3/mail/send HTTP/1.1"));
    assert!(req.contains("authorization: Bearer SG.key"));
    assert!(req.ends_with(r#"{"personalizations":[{"to":[{"email":"a@x.com"}]}],"from":{"email":"noreply@example.com"},"subject":"Welcome","content":[{"type":"text/html","value":"<p>Hi</p>"}]}"#));

    let (port, _) = fake_sendgrid(400).await;
    let url = format!("http://127.0.0.1:{port}/v3/mail/send");
    let e = email::sendgrid_send(&http, &url, &conn, &details(&["a@x.com"])).await.unwrap_err();
    assert_eq!(e.message(), r#"Unable to send the email: Error with body : {"errors":[{"message":"bad"}]}"#);

    let no_key = Connection::from_json(json!({"name": "sg", "connectionDetails": {"apiKey": " "}})).unwrap();
    assert!(email::sendgrid_send(&http, &url, &no_key, &details(&["a@x.com"])).await.is_err());
}

#[test]
fn language_and_parts() {
    let d = data(json!({}));
    // Neither expression nor default: "en" and the "en" parts.
    let t = EmailTemplate::from_json(json!({"templateParts": {"de": {"subject": "Hallo"}, "en": {"subject": "Hello"}}})).unwrap();
    assert_eq!(email::language(&t, &d).unwrap().as_deref(), Some("en"));
    assert_eq!(email::processed_parts(Some(""), &t, &d).unwrap()["subject"], "Hello");
    // A language without parts falls back to the first set in Java's map order.
    let first = email::processed_parts(Some("fr"), &t, &d).unwrap();
    assert!(first["subject"] == "Hello" || first["subject"] == "Hallo");
    // A default language without an expression is the language; nothing at all is `en`.
    let t2 = EmailTemplate::from_json(json!({"defaultLanguage": "fr", "templateParts": {"en": {}}})).unwrap();
    assert_eq!(email::language(&t2, &d).unwrap().as_deref(), Some("fr"));
    assert_eq!(email::language(&EmailTemplate::default(), &d).unwrap().as_deref(), Some("en"));
    // An expression that renders blank takes the default, and without one `en` (Java: null).
    let t4 = EmailTemplate::from_json(json!({"languageExpression": "${lang!\"\"}", "defaultLanguage": "de"})).unwrap();
    assert_eq!(email::language(&t4, &d).unwrap().as_deref(), Some("de"));
    assert_eq!(email::language(&t4, &data(json!({"lang": " fr "}))).unwrap().as_deref(), Some("fr"));
    let t5 = EmailTemplate::from_json(json!({"languageExpression": "${lang!\"\"}"})).unwrap();
    assert_eq!(email::language(&t5, &d).unwrap().as_deref(), Some("en"));
    // The set is found whatever its case.
    let upper = EmailTemplate::from_json(json!({"templateParts": {"de": {"subject": "Hallo"}, "EN": {"subject": "Hello"}}})).unwrap();
    assert_eq!(email::processed_parts(Some("en"), &upper, &d).unwrap()["subject"], "Hello");
    assert_eq!(email::processed_parts(Some("DE"), &upper, &d).unwrap()["subject"], "Hallo");
    // No parts at all.
    let t3 = EmailTemplate::default();
    assert_eq!(email::processed_parts(Some("en"), &t3, &d).unwrap_err().message(), "Unable to send the email: No template parts found");
    assert!(email::processed_parts(None, &t, &d).is_err());
    // A from expression wins over the connection's address.
    let tf = EmailTemplate::from_json(json!({"fromExpression": "${f}"})).unwrap();
    let conn = Connection::default();
    assert_eq!(email::from_address(&conn, &tf, &data(json!({"f": "x@y.com"}))).unwrap(), "x@y.com");
    assert_eq!(email::from_address(&conn, &EmailTemplate::default(), &d).unwrap(), "");
}

// --- Attachments

/// A files service that answers `data:` URLs for the paths it holds, recording each read.
struct Files {
    held: Vec<(&'static str, &'static str)>,
    reads: Mutex<Vec<(String, bool)>>,
}

#[async_trait]
impl email::AttachmentFiles for Files {
    async fn read_base64(&self, url: &str, secured: bool) -> ConnResult<Option<String>> {
        self.reads.lock().push((url.to_string(), secured));
        Ok(self.held.iter().find(|(u, _)| *u == url).map(|(_, b64)| b64.to_string()))
    }
}

const INVOICE: &str = "/api/files/secured/file/SYSTEM/invoices/May.pdf";

fn files() -> Files {
    Files { held: vec![(INVOICE, "data:application/pdf;name:May.pdf;base64,JVBERi0x")], reads: Mutex::new(Vec::new()) }
}

#[tokio::test]
async fn smtp_sends_stored_and_inline_attachments() {
    let s = StubSmtp::start(vec![]).await;
    let store = Store(vec![smtp_connection(s.port, json!({}))]);
    let templates = Templates(vec![welcome()]);
    let http = HttpClient { block_private_targets: false };
    let ctx = EmailContext { connections: &store, templates: &templates, http: &http, sendgrid_url: "http://127.0.0.1:1", block_private_targets: false };
    let f = files();
    let sources = email::attachment_sources(Some(&json!([INVOICE, {"content": "aGVsbG8=", "name": "notes.txt"}]))).unwrap();
    let attachments = email::Attachments { sources, files: Some(&f) };
    let d = data(json!({"email": "ann@example.com", "name": "Ann", "vip": false}));
    let sent = email::send_email_function(&ctx, &caller(), "", "", Some("mail"), "welcome", None, &d, &attachments, &Default::default()).await.unwrap();
    assert_eq!(sent, Some(true));
    assert_eq!(f.reads.lock().clone(), vec![(INVOICE.to_string(), true)]);
    let msg = s.accepted.lock()[0].clone();
    assert!(msg.contains("Content-Type: multipart/mixed"), "{msg}");
    assert!(msg.contains("<p>Hi Ann,</p>"), "{msg}");
    assert!(msg.contains("filename=\"May.pdf\""), "{msg}");
    assert!(msg.contains("Content-Type: application/pdf"), "{msg}");
    // lettre writes ASCII content as 7bit, anything else in base64.
    assert!(msg.contains("\n%PDF-1\n"), "{msg}");
    assert!(msg.contains("filename=\"notes.txt\""), "{msg}");
    assert!(msg.contains("Content-Type: text/plain"), "{msg}");
}

#[tokio::test]
async fn attachment_failures_send_nothing() {
    let s = StubSmtp::start(vec![]).await;
    let store = Store(vec![smtp_connection(s.port, json!({}))]);
    let templates = Templates(vec![welcome()]);
    let http = HttpClient { block_private_targets: false };
    let ctx = EmailContext { connections: &store, templates: &templates, http: &http, sendgrid_url: "http://127.0.0.1:1", block_private_targets: false };
    let d = data(json!({"email": "ann@example.com", "name": "Ann", "vip": false}));
    let f = files();
    let send = |sources: Value, files: Option<&'static Files>| {
        let ctx = &ctx;
        let d = &d;
        async move {
            let a = email::Attachments { sources: email::attachment_sources(Some(&sources)).unwrap(), files: files.map(|f| f as _) };
            email::send_email_function(ctx, &caller(), "", "", Some("mail"), "welcome", None, d, &a, &Default::default()).await
        }
    };
    let f: &'static Files = Box::leak(Box::new(f));
    let e = send(json!(["/api/files/static/file/SYSTEM/gone.pdf"]), Some(f)).await.unwrap_err();
    assert_eq!(e.message(), "Unable to send the email: Attachment not found: /api/files/static/file/SYSTEM/gone.pdf");
    let e = send(json!([INVOICE]), None).await.unwrap_err();
    assert_eq!(e.message(), "Unable to send the email: Stored files cannot be attached here");
    let big = "A".repeat(email::MAX_ATTACHMENT_BYTES / 3 * 4 + 8);
    let e = send(json!([{"content": big, "name": "big.bin"}]), Some(f)).await.unwrap_err();
    assert_eq!(e.message(), "Unable to send the email: Attachments are over 20 MB in all");
    // A missing template is still the first refusal: nothing is read for it.
    f.reads.lock().clear();
    let a = email::Attachments { sources: email::attachment_sources(Some(&json!([INVOICE]))).unwrap(), files: Some(f) };
    assert!(email::send_email_function(&ctx, &caller(), "", "", Some("mail"), "nope", None, &d, &a, &Default::default()).await.is_err());
    assert!(f.reads.lock().is_empty());
    assert!(s.accepted.lock().is_empty());
}

#[tokio::test]
async fn sendgrid_sends_attachments_in_base64() {
    let (port, log) = fake_sendgrid(202).await;
    let conn = Connection::from_json(json!({"name": "sg", "connectionType": "MAIL", "connectionSubType": "SENDGRID", "connectionDetails": {"apiKey": "SG.key"}})).unwrap();
    let http = HttpClient { block_private_targets: false };
    let url = format!("http://127.0.0.1:{port}/v3/mail/send");
    let mut d = details(&["a@x.com"]);
    d.attachments = vec![email::EmailAttachment { name: "May.pdf".into(), content_type: "application/pdf".into(), bytes: b"%PDF-1".to_vec() }];
    assert!(email::sendgrid_send(&http, &url, &conn, &d).await.unwrap());
    let req = log.lock()[0].clone();
    assert!(
        req.ends_with(r#""content":[{"type":"text/html","value":"<p>Hi</p>"}],"attachments":[{"content":"JVBERi0x","type":"application/pdf","filename":"May.pdf","disposition":"attachment"}]}"#),
        "{req}"
    );
}

// --- The private-target guard

#[tokio::test]
async fn smtp_to_a_private_host_is_refused() {
    let s = StubSmtp::start(vec![]).await;
    let e = email::smtp_send(&smtp_connection(s.port, json!({})), &details(&["a@x.com"]), true).await.unwrap_err();
    assert_eq!(e.code().map(|c| c.code.as_ref()), Some("CORE.PRIVATE_TARGET_REFUSED"));
    assert_eq!(
        e.message(),
        format!("Refusing to call \"smtp://127.0.0.1:{}\": '127.0.0.1' is a private or internal address. Only addresses reachable from the public internet can be called.", s.port)
    );
    assert!(s.accepted.lock().is_empty());
    // Through EmailService: the guard follows the context's flag.
    let store = Store(vec![smtp_connection(s.port, json!({}))]);
    let templates = Templates(vec![welcome()]);
    let http = HttpClient { block_private_targets: false };
    let ctx = EmailContext { connections: &store, templates: &templates, http: &http, sendgrid_url: "http://127.0.0.1:1", block_private_targets: true };
    let d = data(json!({"email": "ann@example.com", "name": "Ann", "vip": false}));
    let e = email::send_email(&ctx, &caller(), None, None, &[], "welcome", Some("mail"), &d).await.unwrap_err();
    assert_eq!(e.code().map(|c| c.code.as_ref()), Some("CORE.PRIVATE_TARGET_REFUSED"));
    assert!(s.accepted.lock().is_empty());
}

#[tokio::test]
async fn smtp_guard_rules() {
    use connections::outbound::{guard_host, with_resolver, Resolver};
    let resolver: Resolver = Arc::new(|name: &str| match name {
        "smtp.public.example" => Some(vec!["93.184.216.34".parse().unwrap()]),
        "rebound.example" => Some(vec!["93.184.216.34".parse().unwrap(), "10.0.0.5".parse().unwrap()]),
        "mapped.example" => Some(vec!["::ffff:127.0.0.1".parse().unwrap()]),
        _ => None,
    });
    with_resolver(resolver, async {
        assert_eq!(guard_host("smtp://smtp.public.example:587", "SMTP.Public.Example.").await.unwrap(), vec!["93.184.216.34".parse::<std::net::IpAddr>().unwrap()]);
        assert_eq!(guard_host("t", "8.8.8.8").await.unwrap().len(), 1);
        for (host, why) in [
            ("rebound.example", "'rebound.example' resolves to 10.0.0.5, which is a private or internal address"),
            ("mapped.example", "'mapped.example' resolves to 127.0.0.1, which is a private or internal address"),
            ("localhost", "'localhost' is this server, not an outside address"),
            ("metadata.google.internal", "'metadata.google.internal' is this server, not an outside address"),
            ("mail.corp.internal", "'mail.corp.internal' is an internal address"),
            ("169.254.169.254", "'169.254.169.254' is a private or internal address"),
            ("[::1]", "'::1' is a private or internal address"),
            ("nowhere.example", "'nowhere.example' does not resolve to any address"),
            (" ", "the address has no readable host name"),
        ] {
            let e = guard_host("t", host).await.unwrap_err();
            assert_eq!(e.message(), format!("Refusing to call \"t\": {why}. Only addresses reachable from the public internet can be called."), "{host}");
        }
    })
    .await;
}

// --- CC and BCC

#[test]
fn copy_addresses_from_the_argument() {
    let a = email::copy_addresses(Some(&json!(" ops@example.com; Sales@example.com,,sales@EXAMPLE.com ,"))).unwrap();
    assert_eq!(a, vec!["ops@example.com", "Sales@example.com"]);
    let a = email::copy_addresses(Some(&json!(["a@x.com, b@x.com", null, "", "A@x.com"]))).unwrap();
    assert_eq!(a, vec!["a@x.com", "b@x.com"]);
    assert!(email::copy_addresses(None).unwrap().is_empty());
    assert!(email::copy_addresses(Some(&Value::Null)).unwrap().is_empty());
    assert!(email::copy_addresses(Some(&json!(" , "))).unwrap().is_empty());
    // One bad address refuses the whole list, naming it.
    let e = email::copy_addresses(Some(&json!("ok@x.com, not an address"))).unwrap_err();
    assert_eq!(e.status(), http::StatusCode::BAD_REQUEST);
    assert_eq!(e.message(), "Unable to send the email: Not an email address: not an address");
    let code = e.code().unwrap();
    assert_eq!(code.code.as_ref(), "CORE.MAIL_ADDRESS_INVALID");
    assert_eq!(code.params, vec![("address".to_string(), "not an address".to_string())]);
    assert_eq!(email::copy_addresses(Some(&json!([5]))).unwrap_err().message(), "Unable to send the email: Not an email address: 5");
    // Copies already in `to` go, and a BCC already in CC.
    let c = email::Copies::from_args(Some(&json!("ann@example.com, ops@x.com")), Some(&json!("OPS@x.com; audit@x.com; ANN@example.com"))).unwrap();
    let c = c.without(&["Ann@Example.com".to_string()]);
    assert_eq!((c.cc, c.bcc), (vec!["ops@x.com".to_string()], vec!["audit@x.com".to_string()]));
}

#[tokio::test]
async fn smtp_sends_one_copy_with_cc_in_the_headers_and_bcc_only_in_the_envelope() {
    let s = StubSmtp::start(vec![]).await;
    let store = Store(vec![smtp_connection(s.port, json!({}))]);
    let templates = Templates(vec![welcome()]);
    let http = HttpClient { block_private_targets: false };
    let ctx = EmailContext { connections: &store, templates: &templates, http: &http, sendgrid_url: "http://127.0.0.1:1", block_private_targets: false };
    let d = data(json!({"email": "ann@example.com", "name": "Ann", "vip": false}));
    // Two `to` addresses (given and the template's), a CC also in `to`, a BCC also in CC.
    let copies = email::Copies::from_args(Some(&json!("ops@example.com, ANN@example.com")), Some(&json!(["audit@example.com", "ops@example.com"]))).unwrap();
    let to = json!(["bob@example.com"]);
    let sent = email::send_email_function(&ctx, &caller(), "", "", Some("mail"), "welcome", Some(&to), &d, &Default::default(), &copies).await.unwrap();
    assert_eq!(sent, Some(true));
    let msgs = s.accepted.lock().clone();
    assert_eq!(msgs.len(), 1);
    assert_eq!(s.rcpts.lock().clone(), vec!["bob@example.com", "ann@example.com", "ops@example.com", "audit@example.com"]);
    assert!(msgs[0].contains("To: bob@example.com, ann@example.com"), "{}", msgs[0]);
    assert!(msgs[0].contains("Cc: ops@example.com"), "{}", msgs[0]);
    assert!(!msgs[0].to_lowercase().contains("bcc"), "{}", msgs[0]);
    assert!(!msgs[0].contains("audit@example.com"), "{}", msgs[0]);
}

#[tokio::test]
async fn smtp_copy_refused_still_sends_to_the_customer() {
    let s = StubSmtp::start(vec![("gone@example.com", SUPPRESSED)]).await;
    let mut d = details(&["ok@example.com"]);
    d.cc = vec!["gone@example.com".into()];
    d.bcc = vec!["audit@example.com".into()];
    assert!(email::smtp_send(&smtp_connection(s.port, json!({})), &d, false).await.unwrap());
    assert_eq!(s.accepted.lock().len(), 1);
    assert_eq!(s.rcpts.lock().clone(), vec!["ok@example.com", "gone@example.com", "audit@example.com"]);
    // The `to` refused: nothing goes to the copies either.
    let s = StubSmtp::start(vec![("gone@example.com", SUPPRESSED)]).await;
    let mut d = details(&["gone@example.com"]);
    d.cc = vec!["ops@example.com".into()];
    assert!(!email::smtp_send(&smtp_connection(s.port, json!({})), &d, false).await.unwrap());
    assert!(s.accepted.lock().is_empty());
}

#[tokio::test]
async fn sendgrid_posts_cc_and_bcc_in_the_personalization() {
    let (port, log) = fake_sendgrid(202).await;
    let sg = Connection::from_json(json!({"name": "sg", "clientCode": "SYSTEM", "connectionType": "MAIL", "connectionSubType": "SENDGRID", "connectionDetails": {"apiKey": "SG.key"}})).unwrap();
    let store = Store(vec![sg]);
    let templates = Templates(vec![welcome()]);
    let http = HttpClient { block_private_targets: false };
    let url = format!("http://127.0.0.1:{port}/v3/mail/send");
    let ctx = EmailContext { connections: &store, templates: &templates, http: &http, sendgrid_url: &url, block_private_targets: false };
    let d = data(json!({"email": "ann@example.com", "name": "Ann", "vip": false}));
    let copies = email::Copies::from_args(Some(&json!("ops@example.com; ann@example.com")), Some(&json!("audit@example.com, Ops@example.com"))).unwrap();
    let sent = email::send_email_function(&ctx, &caller(), "", "", Some("sg"), "welcome", None, &d, &Default::default(), &copies).await.unwrap();
    assert_eq!(sent, Some(true));
    let req = log.lock()[0].clone();
    assert!(
        req.contains(r#"{"personalizations":[{"to":[{"email":"ann@example.com"}],"cc":[{"email":"ops@example.com"}],"bcc":[{"email":"audit@example.com"}]}],"#),
        "{req}"
    );
    // No copies: no cc or bcc keys at all.
    let sent = email::send_email_function(&ctx, &caller(), "", "", Some("sg"), "welcome", None, &d, &Default::default(), &Default::default()).await.unwrap();
    assert_eq!(sent, Some(true));
    let req = log.lock()[1].clone();
    assert!(req.contains(r#"{"personalizations":[{"to":[{"email":"ann@example.com"}]}],"#), "{req}");
}
