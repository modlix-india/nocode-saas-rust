//! The notification service's own SMTP and SendGrid rules, against an SMTP stub and a stand-in
//! SendGrid endpoint. No real mail provider is contacted.

mod common;

use common::{Answer, Fake, StubSmtp};
use notification::email::{EmailService, EmailSink};
use notification::model::{CoreNotification, MailConnection, NotificationUser};
use serde_json::{json, Map, Value};

fn user(email: Option<&str>) -> NotificationUser {
    NotificationUser { id: Some(142), client_id: Some(1), email_id: email.map(str::to_string) }
}

fn notification(parts: Value) -> CoreNotification {
    CoreNotification::from_json(&json!({"name": "n", "channelTemplates": {"email": {"templateParts": {"en": parts}}}})).unwrap()
}

fn welcome() -> CoreNotification {
    notification(json!({"subject": "Hi ${who}", "body": "<p>Welcome ${who}</p>"}))
}

fn payload() -> Map<String, Value> {
    json!({"who": "Ann"}).as_object().unwrap().clone()
}

fn smtp(port: u16, extra: Value) -> MailConnection {
    let mut details = json!({
        "mailProps": {"mail.smtp.host": "127.0.0.1", "mail.smtp.port": port.to_string(), "mail.smtp.auth": "true"},
        "username": "u", "password": "p", "fromAddress": "noreply@modlix.test"
    });
    for (k, v) in extra.as_object().unwrap() {
        if v.is_null() {
            details.as_object_mut().unwrap().remove(k);
        } else {
            details[k] = v.clone();
        }
    }
    MailConnection { connection_sub_type: Some("SMTP".into()), connection_details: Some(details.as_object().unwrap().clone()) }
}

fn service(sendgrid: &str) -> EmailService {
    EmailService::new(sendgrid).unwrap()
}

#[tokio::test]
async fn smtp_sends_one_mail_per_recipient() {
    let s = StubSmtp::start(vec![]).await;
    let svc = service("http://127.0.0.1:1");
    assert!(svc.send_email(&user(Some("ann@x.test")), &smtp(s.port, json!({})), &welcome(), &payload()).await.unwrap());
    let msgs = s.messages.lock().clone();
    assert_eq!(msgs.len(), 1);
    assert!(msgs[0].contains("Subject: Hi Ann"), "{}", msgs[0]);
    assert!(msgs[0].contains("<p>Welcome Ann</p>"));
    assert!(msgs[0].contains("To: ann@x.test"));
    assert!(msgs[0].contains("From: noreply@modlix.test"));
    assert_eq!(*s.recipients.lock(), ["ann@x.test"]);
}

#[tokio::test]
async fn smtp_answers_false_before_sending_anything() {
    let s = StubSmtp::start(vec![]).await;
    let svc = service("http://127.0.0.1:1");
    let w = welcome();
    let p = payload();
    for email in [None, Some(""), Some("  "), Some("NONE"), Some("none"), Some("no-at-sign")] {
        assert!(!svc.smtp(&user(email), &smtp(s.port, json!({})), &w, &p).await.unwrap(), "{email:?}");
    }
    let u = user(Some("ann@x.test"));
    for extra in [
        json!({"mailProps": null}),
        json!({"mailProps": {}}),
        json!({"username": null}),
        json!({"password": " "}),
        json!({"fromAddress": null}),
        json!({"fromAddress": ""}),
    ] {
        assert!(!svc.smtp(&u, &smtp(s.port, extra.clone()), &w, &p).await.unwrap(), "{extra}");
    }
    let none = MailConnection { connection_sub_type: Some("SMTP".into()), connection_details: None };
    assert!(!svc.smtp(&u, &none, &w, &p).await.unwrap());
    let empty = MailConnection { connection_sub_type: Some("SMTP".into()), connection_details: Some(Map::new()) };
    assert!(!svc.smtp(&u, &empty, &w, &p).await.unwrap());
    // An email template whose parts render to nothing.
    let nothing = CoreNotification::from_json(&json!({"channelTemplates": {"email": {"templateParts": {"en": {}}}}})).unwrap();
    assert!(!svc.smtp(&u, &smtp(s.port, json!({})), &nothing, &p).await.unwrap());
    assert!(s.messages.lock().is_empty());
}

#[tokio::test]
async fn smtp_failures() {
    let s = StubSmtp::start(vec![("gone@x.test", "550 5.1.1 no such user")]).await;
    let svc = service("http://127.0.0.1:1");
    let p = payload();
    // mailProps that is not a map: Java's ClassCastException.
    assert!(svc.smtp(&user(Some("a@x.test")), &smtp(s.port, json!({"mailProps": "x"})), &welcome(), &p).await.is_err());
    // A template that fails to render.
    let broken = notification(json!({"subject": "${missing}", "body": "b"}));
    assert!(svc.smtp(&user(Some("a@x.test")), &smtp(s.port, json!({})), &broken, &p).await.is_err());
    // No body: JavaMail fails writing the message.
    let no_body = notification(json!({"subject": "s"}));
    assert!(svc.smtp(&user(Some("a@x.test")), &smtp(s.port, json!({})), &no_body, &p).await.is_err());
    // A refused recipient or an unreachable server is logged; the answer is still true.
    assert!(svc.smtp(&user(Some("gone@x.test")), &smtp(s.port, json!({})), &welcome(), &p).await.unwrap());
    assert!(svc.smtp(&user(Some("a@x.test")), &smtp(1, json!({})), &welcome(), &p).await.unwrap());
    assert!(s.messages.lock().is_empty());
    // A subject-less template sends with an empty subject.
    assert!(svc.smtp(&user(Some("a@x.test")), &smtp(s.port, json!({})), &notification(json!({"body": "b"})), &p).await.unwrap());
    assert_eq!(s.messages.lock().len(), 1);
}

#[tokio::test]
async fn sendgrid_posts_the_java_body() {
    let (sg, base) = Fake::start().await;
    sg.answer("POST", "/v3/mail/send", Answer::status(202, ""));
    let svc = service(&format!("{base}/v3/mail/send"));
    let mail = MailConnection {
        connection_sub_type: Some("SENDGRID".into()),
        connection_details: Some(json!({"apiKey": "SG.test", "fromAddress": "noreply@modlix.test"}).as_object().unwrap().clone()),
    };
    // SendGrid's usual empty 202: `.body(String.class)` is null, so false.
    assert!(!svc.send_email(&user(Some("ann@x.test")), &mail, &welcome(), &payload()).await.unwrap());
    let call = sg.calls_to("/v3/mail/send")[0].clone();
    assert_eq!(call.header("authorization").as_deref(), Some("Bearer SG.test"));
    assert_eq!(call.header("content-type").as_deref(), Some("application/json"));
    assert_eq!(
        call.json(),
        json!({"personalizations": [{"to": [{"email": "ann@x.test"}]}], "from": {"email": "noreply@modlix.test"},
               "subject": "Hi Ann", "content": [{"type": "text/html", "value": "<p>Welcome Ann</p>"}]})
    );
    sg.answer("POST", "/v3/mail/send", Answer::status(200, "ok"));
    assert!(svc.send_email(&user(Some("ann@x.test")), &mail, &welcome(), &payload()).await.unwrap());
    // A refusal fails the notification.
    sg.answer("POST", "/v3/mail/send", Answer::error(401, "bad key"));
    assert!(svc.send_email(&user(Some("ann@x.test")), &mail, &welcome(), &payload()).await.is_err());
    // SendGrid checks no address: a recipient without one fails (Map.of refuses null).
    assert!(svc.send_email(&user(None), &mail, &welcome(), &payload()).await.is_err());
    // ... as does a template without a subject or a body.
    assert!(svc.sendgrid(&user(Some("a@x.test")), &mail, &notification(json!({"body": "b"})), &payload()).await.is_err());
    assert!(svc.sendgrid(&user(Some("a@x.test")), &mail, &notification(json!({"subject": "s"})), &payload()).await.is_err());
}

#[tokio::test]
async fn sendgrid_answers_false_before_posting() {
    let (sg, base) = Fake::start().await;
    let svc = service(&format!("{base}/v3/mail/send"));
    let with = |d: Value| MailConnection { connection_sub_type: Some("SENDGRID".into()), connection_details: d.as_object().cloned() };
    let u = user(Some("a@x.test"));
    for d in [Value::Null, json!({}), json!({"apiKey": " ", "fromAddress": "f@x"}), json!({"apiKey": "k"}), json!({"apiKey": "k", "fromAddress": ""})] {
        assert!(!svc.sendgrid(&u, &with(d.clone()), &welcome(), &payload()).await.unwrap(), "{d}");
    }
    let nothing = CoreNotification::from_json(&json!({"channelTemplates": {"email": {"templateParts": {"en": {}}}}})).unwrap();
    assert!(!svc.sendgrid(&u, &with(json!({"apiKey": "k", "fromAddress": "f@x"})), &nothing, &payload()).await.unwrap());
    assert!(sg.calls.lock().is_empty());
    // An unreachable endpoint is an error.
    let dead = service("http://127.0.0.1:1/v3/mail/send");
    assert!(dead.sendgrid(&u, &with(json!({"apiKey": "k", "fromAddress": "f@x"})), &welcome(), &payload()).await.is_err());
}

#[tokio::test]
async fn unknown_sub_types_have_no_service() {
    let svc = service("http://127.0.0.1:1");
    let u = user(Some("a@x.test"));
    for sub in [None, Some("OFFICE365")] {
        let m = MailConnection { connection_sub_type: sub.map(str::to_string), connection_details: None };
        assert!(svc.send_email(&u, &m, &welcome(), &payload()).await.is_err());
    }
}
