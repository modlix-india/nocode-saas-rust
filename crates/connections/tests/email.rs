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
struct StubSmtp {
    port: u16,
    accepted: Arc<Mutex<Vec<String>>>,
}

impl StubSmtp {
    async fn start(rcpt_replies: Vec<(&'static str, &'static str)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(Mutex::new(Vec::new()));
        let acc = accepted.clone();
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
        StubSmtp { port, accepted }
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
    }
}

#[tokio::test]
async fn suppressed_recipient_is_not_sent_instead_of_an_error() {
    let s = StubSmtp::start(vec![("gone@example.com", SUPPRESSED)]).await;
    assert!(!email::smtp_send(&smtp_connection(s.port, json!({})), &details(&["gone@example.com"])).await.unwrap());
}

#[tokio::test]
async fn permanently_rejected_recipient_is_not_sent() {
    let s = StubSmtp::start(vec![("gone@example.com", "550 5.1.1 no such user")]).await;
    assert!(!email::smtp_send(&smtp_connection(s.port, json!({})), &details(&["gone@example.com"])).await.unwrap());
}

#[tokio::test]
async fn partial_send_counts_as_sent() {
    let s = StubSmtp::start(vec![("gone@example.com", "550 5.1.1 no such user")]).await;
    let conn = smtp_connection(s.port, json!({"mail.smtp.sendpartial": "true"}));
    assert!(email::smtp_send(&conn, &details(&["ok@example.com", "gone@example.com"])).await.unwrap());
    assert_eq!(s.accepted.lock().len(), 1);
}

#[tokio::test]
async fn without_sendpartial_one_refusal_sends_nothing() {
    let s = StubSmtp::start(vec![("gone@example.com", "550 5.1.1 no such user")]).await;
    let conn = smtp_connection(s.port, json!({}));
    assert!(!email::smtp_send(&conn, &details(&["ok@example.com", "gone@example.com"])).await.unwrap());
    assert!(s.accepted.lock().is_empty());
}

#[tokio::test]
async fn accepted_recipient_is_sent() {
    let s = StubSmtp::start(vec![]).await;
    assert!(email::smtp_send(&smtp_connection(s.port, json!({})), &details(&["ok@example.com"])).await.unwrap());
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
    let e = email::smtp_send(&c, &details(&["a@x.com"])).await.unwrap_err();
    assert_eq!(e.message(), "Unable to send the email: Connection username/password is missing");
    let mut c = smtp_connection(1, json!({}));
    c.connection_details.as_mut().unwrap()["mailProps"] = json!({});
    let e = email::smtp_send(&c, &details(&["a@x.com"])).await.unwrap_err();
    assert_eq!(e.message(), "Unable to send the email: Connection Properties with 'mail.' are missing");
    let mut c = smtp_connection(1, json!({}));
    c.connection_details = None;
    assert_eq!(
        email::smtp_send(&c, &details(&["a@x.com"])).await.unwrap_err().message(),
        "Unable to send the email: Connection details are missing"
    );
    // Nothing listening: the connection failure is the error.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let e = email::smtp_send(&smtp_connection(closed, json!({})), &details(&["a@x.com"])).await.unwrap_err();
    assert!(e.message().starts_with("Unable to send the email: Couldn't connect to host"), "{}", e.message());
    // No usable recipient: not sent, nothing attempted.
    assert!(!email::smtp_send(&smtp_connection(closed, json!({})), &details(&["not an address"])).await.unwrap());
    // A sender that is not an address.
    let mut d = details(&["a@x.com"]);
    d.from = String::new();
    assert!(email::smtp_send(&smtp_connection(closed, json!({})), &d).await.is_err());
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
    let e = email::smtp_send(&conn, &details(&["a@x.com"])).await.unwrap_err();
    assert_eq!(e.message(), "Unable to send the email: Read timed out");
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    // A connection that fails shows the connect timeout it had.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let e = email::smtp_send(&smtp_connection(closed, json!({"mail.smtp.connectiontimeout": 1500})), &details(&["a@x.com"]))
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
    let ctx = EmailContext { connections: &store, templates: &templates, http: &http, sendgrid_url: "http://127.0.0.1:1" };
    let d = data(json!({"email": "ann@example.com", "name": "Ann", "vip": true, "lang": "fr"}));
    let sent = email::send_email_function(&ctx, &caller(), "", "", Some("mail"), "welcome", Some(&json!([""])), &d).await.unwrap();
    assert_eq!(sent, Some(true));
    let msg = s.accepted.lock()[0].clone();
    assert!(msg.contains("Subject: Bonjour Ann"), "{msg}");
    assert!(msg.contains("To: ann@example.com"), "{msg}");

    // Outside a KIRun runtime the function reports not sent.
    let mut outside = caller();
    outside.in_kirun = false;
    assert_eq!(email::send_email_function(&ctx, &outside, "", "", Some("mail"), "welcome", None, &d).await.unwrap(), Some(false));

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
    let ctx = EmailContext { connections: &store, templates: &templates, http: &http, sendgrid_url: "http://127.0.0.1:1" };
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
    assert_eq!(email::send_email_function(&ctx, &none, "", "", Some("mail"), "welcome", None, &d).await.unwrap(), None);
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
    // Neither expression nor default: "" and the "en" parts.
    let t = EmailTemplate::from_json(json!({"templateParts": {"de": {"subject": "Hallo"}, "en": {"subject": "Hello"}}})).unwrap();
    assert_eq!(email::language(&t, &d).unwrap(), Some(String::new()));
    assert_eq!(email::processed_parts(Some(""), &t, &d).unwrap()["subject"], "Hello");
    // A language without parts falls back to the first set in Java's map order.
    let first = email::processed_parts(Some("fr"), &t, &d).unwrap();
    assert!(first["subject"] == "Hello" || first["subject"] == "Hallo");
    // A default language without an expression fails, as in Java.
    let t2 = EmailTemplate::from_json(json!({"defaultLanguage": "en", "templateParts": {"en": {}}})).unwrap();
    assert!(email::language(&t2, &d).is_err());
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
