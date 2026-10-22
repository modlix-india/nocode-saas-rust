//! Smaller behaviours across the crate: enum names, Java string forms, JSON escapes, body
//! encodings, file names, timeouts, SMTP options and the notification publish.

mod common;

use std::sync::Arc;

use async_trait::async_trait;
use common::{caller, server, service, Canned, Functions, MemTokens};
use connections::connection::{Connection, ConnectionSubType, ConnectionType};
use connections::context::Caller;
use connections::error::{ConnError, ConnResult};
use connections::java::{self, json};
use connections::mq::{jackson_authentication, Publisher, Route};
use connections::notification::{process_and_send, HierarchyChecks, NotificationRequest};
use connections::rest::basic::{self, apply_connection_details};
use connections::rest::body;
use connections::rest::call::{parse_content_disposition_file_name, resolve_file_name, rest_request, CallArgs};
use connections::rest::{RestData, RestRequest, RestResponse};
use serde_json::{json, Map, Value};

#[test]
fn enum_names() {
    use ConnectionSubType::*;
    for (s, n) in [
        (Mongo, "MONGO"),
        (MySql, "MYSQL"),
        (Office365, "OFFICE365"),
        (SendGrid, "SENDGRID"),
        (WhatsApp, "WHATSAPP"),
        (RestApiOAuth2, "REST_API_OAUTH2"),
        (RestApiBasic, "REST_API_BASIC"),
        (RestApiAuth, "REST_API_AUTH"),
        (Smtp, "SMTP"),
        (Exotel, "EXOTEL"),
        (OpenAi, "OPENAI"),
        (Gemini, "GEMINI"),
        (Claude, "CLAUDE"),
        (Grok, "GROK"),
        (DeepSeek, "DEEP_SEEK"),
    ] {
        assert_eq!(s.name(), n);
        assert_eq!(serde_json::to_value(s).unwrap(), json!(n));
    }
    use ConnectionType::*;
    for (t, n, sub) in [
        (AppData, "APP_DATA", Some(Mongo)),
        (Mail, "MAIL", Some(Smtp)),
        (RestApi, "REST_API", Some(RestApiAuth)),
        (Notification, "NOTIFICATION", None),
        (Text, "TEXT", Some(WhatsApp)),
        (Call, "CALL", Some(Exotel)),
        (Ai, "AI", Some(Grok)),
    ] {
        assert_eq!(t.name(), n);
        assert_eq!(ConnectionType::value_of(n), Some(t));
        if let Some(sub) = sub {
            assert!(t.has_sub_type(sub));
            assert!(!t.has_sub_type(Office365));
        }
    }
}

#[test]
fn java_string_forms() {
    assert_eq!(java::to_java_string(&json!(null)), "null");
    assert_eq!(java::to_java_string(&json!(u64::MAX)), "18446744073709551615");
    assert_eq!(java::to_java_string(&json!(1.5)), "1.5");
    assert_eq!(java::to_java_string(&json!([1, "a", true])), "[1, a, true]");
    assert_eq!(java::to_java_string(&json!({"a": 1, "b": {"c": null}})), "{a=1, b={c=null}}");
    assert_eq!(java::java_double(f64::NAN), "NaN");
    assert_eq!(java::java_double(f64::INFINITY), "Infinity");
    assert_eq!(java::java_double(f64::NEG_INFINITY), "-Infinity");
    assert_eq!(java::java_double(-0.0), "-0.0");
    assert_eq!(java::java_double(0.0), "0.0");
    assert_eq!(java::java_double(-2.5), "-2.5");
    assert_eq!(java::java_double(1.2345e-9), "1.2345E-9");
    assert_eq!(java::java_double(1e21), "1.0E21");
    assert!(java::safe_is_blank(None));
    assert!(java::safe_is_blank(Some(&json!(" "))));
    assert!(!java::safe_is_blank(Some(&json!(0))));
}

#[test]
fn json_escapes() {
    let s = json!("\u{8}\t\u{c}\n\r\\\u{2028}\u{2029}\u{1}");
    assert_eq!(json::jackson(&s), "\"\\b\\t\\f\\n\\r\\\\\u{2028}\u{2029}\\u0001\"");
    assert_eq!(json::gson_element(&s), "\"\\b\\t\\f\\n\\r\\\\\\u2028\\u2029\\u0001\"");
    assert_eq!(json::gson_element(&json!([true, false, null, u64::MAX])), "[true,false,null,18446744073709551615]");
    assert_eq!(json::jackson(&json!(u64::MAX)), "18446744073709551615");
    assert_eq!(json::numbers_as_doubles(json!(u64::MAX)), json!(18446744073709551615.0));
    assert!(json::jackson_non_empty(&json!(0)));
    assert!(!json::jackson_non_empty(&json!([])));
}

#[test]
fn multipart_values_as_gson_reads_them() {
    let parts = body::multipart_parts(&json!({"b": true, "one": [["x"]], "n": 2})).unwrap();
    assert_eq!(parts.len(), 3);
    assert_eq!(body::multipart_parts(&json!({"n": null})).unwrap_err().message(), "JsonNull");
    assert_eq!(body::multipart_parts(&json!({"a": [[1, 2]]})).unwrap_err().message(), "Array must have size 1, but has size 2");
    assert!(body::multipart_parts(&json!([1])).unwrap().is_empty());
    assert!(body::form_body(&json!("x")).is_empty());
    // A data: value that is not a file part stays text; bad base64 is a 400.
    let p = body::multipart_parts(&json!({"d": "data:text/plain;name:a.txt"})).unwrap();
    assert!(matches!(&p[0], body::Part::Text { .. }));
    let p = body::multipart_parts(&json!({"d": "data:x;y;z"})).unwrap();
    assert!(matches!(&p[0], body::Part::Text { .. }));
    let e = body::multipart_parts(&json!({"d": "data:text/plain;name:a.txt;base64,!!!"})).unwrap_err();
    assert_eq!((e.status(), e.message()), (http::StatusCode::BAD_REQUEST, "Not a base64 encoded string"));
    let (b, ct) = body::multipart_body(
        &[body::Part::File { name: "f".into(), content_type: "text/plain".into(), filename: "a.txt".into(), bytes: b"hi".to_vec() }],
        &connections::rest::media_type::MediaType::parse("multipart/form-data; boundary=old; charset=UTF-8").unwrap(),
        "B",
    );
    // Spring rebuilds the parameters in a HashMap: boundary hashes first.
    assert_eq!(ct, "multipart/form-data;boundary=B;charset=UTF-8");
    assert!(String::from_utf8(b).unwrap().contains("Content-Type: text/plain\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\""));
    let bnd = body::boundary();
    assert!((30..=40).contains(&bnd.len()));
}

#[test]
fn call_arguments_and_file_names() {
    let args = CallArgs {
        headers: json!({"b": true, "n": null}).as_object().unwrap().clone(),
        ..Default::default()
    };
    assert_eq!(rest_request(&args).unwrap_err().message(), "JsonNull");
    let args = CallArgs { headers: json!({"b": true, "a": ["x"]}).as_object().unwrap().clone(), ..Default::default() };
    let r = rest_request(&args).unwrap();
    assert_eq!(r.headers.unwrap()[0], ("b".to_string(), vec!["true".to_string()]));
    let resp = |h: Vec<(&str, &str)>| RestResponse {
        data: RestData::Binary(vec![]),
        headers: Some(h.into_iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()),
        status: 200,
    };
    // The extension after the URL's first dot, up to the query.
    assert_eq!(resolve_file_name(&resp(vec![]), "https://h.com/f.pdf?x=1", "doc", "U").unwrap(), "doc.com/f.pdf");
    assert_eq!(resolve_file_name(&resp(vec![]), "noext", "plain", "U").unwrap(), "plain");
    assert_eq!(
        resolve_file_name(&resp(vec![("Content-Disposition", "attachment; filename=r.csv; size=1")]), "noext", "mine", "U").unwrap(),
        "mine.csv"
    );
    assert_eq!(resolve_file_name(&resp(vec![("Content-Disposition", "inline")]), "noext", "", "U").unwrap(), "fileU");
    assert!(resolve_file_name(&resp(vec![]), "a?b.c", "x", "U").is_err());
    assert_eq!(parse_content_disposition_file_name("attachment"), None);
    assert_eq!(parse_content_disposition_file_name("attachment; filename=plain.txt").as_deref(), Some("plain.txt"));
    assert_eq!(parse_content_disposition_file_name("attachment; filenamex"), None);
}

#[test]
fn connection_details_edges() {
    let conn = |d: Value| Connection::from_json(json!({"name": "c", "connectionDetails": d})).unwrap();
    let e = apply_connection_details(&conn(json!({"baseUrl": null})), "x", false, 0).unwrap_err();
    assert!(e.message().contains("java.util.Map.get(Object)"));
    let a = apply_connection_details(&conn(json!({"userName": null, "password": "p"})), "x", false, 0).unwrap().unwrap();
    assert_eq!(a.headers.first("authorization"), Some("Basic bnVsbDpw"));
    for (v, class) in [(json!(true), "Boolean"), (json!([1]), "ArrayList"), (json!({}), "LinkedHashMap"), (json!(1.5), "Double")] {
        let e = apply_connection_details(&conn(json!({"userName": v, "password": "p"})), "x", false, 0).unwrap_err();
        assert!(e.message().contains(class), "{}", e.message());
    }
    // A timeout that is not an int is ignored.
    let a = apply_connection_details(&conn(json!({"timeout": 2.5})), "x", false, 0).unwrap().unwrap();
    assert_eq!(a.timeout, std::time::Duration::from_secs(300));
    assert_eq!(basic::process_json_response("null").unwrap(), RestData::None);
}

#[tokio::test]
async fn rest_timeouts_and_broken_bodies() {
    let (port, _) = server(vec![Canned { delay_ms: 1500, ..Canned::json(200, "{}") }]).await;
    let svc = service(
        vec![Connection::from_json(json!({"name": "slow", "clientCode": "SYSTEM", "connectionType": "REST_API",
            "connectionSubType": "REST_API_BASIC", "connectionDetails": {"baseUrl": format!("http://127.0.0.1:{port}")}})).unwrap()],
        Arc::new(MemTokens::default()),
        Functions::answering(None),
    );
    let conn = svc.store.read_internal("slow", "a", "c", "c").await.unwrap().unwrap();
    let r = basic::call(&svc, &conn, RestRequest { url: "/x".into(), timeout: 1, ..Default::default() }, false).await.unwrap().unwrap();
    assert_eq!(r.status, 500);
    assert_eq!(
        r.data,
        RestData::Text("Error occurred: Did not observe any item or terminal signal within 1000ms in 'defaultIfEmpty' (and no fallback has been configured)".into())
    );
    // A body cut short.
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cut = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut s, _) = l.accept().await.unwrap();
        let mut b = [0u8; 4096];
        let _ = s.read(&mut b).await;
        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 100\r\n\r\nshort").await;
    });
    let conn = Connection::from_json(json!({"name": "c", "connectionDetails": {"baseUrl": format!("http://127.0.0.1:{cut}")}})).unwrap();
    let r = basic::call(&svc, &conn, RestRequest { url: "/x".into(), ..Default::default() }, false).await.unwrap().unwrap();
    assert_eq!(r.status, 500);
    assert!(matches!(r.data, RestData::Text(ref t) if t.starts_with("Error occurred:")));
    // Blocked private target.
    let guarded = connections::Connections::new(
        connections::ConnectionsConfig::default(),
        Arc::new(common::Store(vec![])),
        Arc::new(MemTokens::default()),
        platform::cache::CacheService::new("cmn", "evictionChannel", None).unwrap(),
        Functions::answering(None),
    );
    let e = basic::call(&guarded, &conn, RestRequest { url: "/x".into(), ..Default::default() }, false).await.unwrap_err();
    assert!(e.message().starts_with("Refusing to call"));
}

struct Yes;
#[async_trait]
impl HierarchyChecks for Yes {
    async fn is_user_part_of_hierarchy(&self, _: i128, _: &str) -> ConnResult<bool> {
        Ok(true)
    }
    async fn does_client_manage_client(&self, _: u64, _: i128) -> ConnResult<bool> {
        Ok(true)
    }
    async fn does_client_manage_client_code(&self, _: &str, _: &str) -> ConnResult<bool> {
        Ok(true)
    }
}

#[tokio::test]
async fn notification_publish_without_a_broker() {
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let p = Publisher::new(format!("amqp://guest:guest@127.0.0.1:{closed}/%2f"));
    let req = NotificationRequest { target_type: "User Id".into(), target_id: Some(1), ..Default::default() };
    assert!(process_and_send(&p, &Route::notifications(), &Yes, &caller(), req.clone()).await.is_err());
    assert_eq!(process_and_send(&p, &Route::notifications(), &Yes, &Default::default(), req).await.unwrap(), None);
}

#[test]
fn context_errors_and_authentication_json() {
    let c = Caller { authorities: vec!["Authorities.X".into()], ..Default::default() };
    assert!(c.has_authority("Authorities.X") && !c.has_authority("Y"));
    assert_eq!(c.client_code(), "");
    assert_eq!(ConnError::Feign { status: 403, message: "m".into(), body: None }.status(), http::StatusCode::FORBIDDEN);
    assert_eq!(ConnError::other("x").status(), http::StatusCode::INTERNAL_SERVER_ERROR);
    let mut raw = Map::new();
    raw.insert("user".into(), json!({"id": "142", "createdAt": 1.9, "stringAuthorities": []}));
    raw.insert("loggedInFromClientId".into(), json!("x"));
    let a = jackson_authentication(&Caller { raw: Some(raw), url_app_code: Some("app".into()), ..Default::default() });
    assert_eq!(a["user"]["id"], json!(142));
    assert_eq!(a["user"]["createdAt"], json!(1));
    assert!(a.get("loggedInFromClientId").is_none());
    assert_eq!(a["urlAppCode"], "app");
    let mut r = RestRequest::default();
    r.add_header("A", "1");
    r.add_header("A", "2");
    assert_eq!(r.headers.unwrap(), vec![("A".to_string(), vec!["1".to_string(), "2".to_string()])]);
}

#[tokio::test]
async fn smtp_options() {
    use connections::email::{self, ProcessedEmail};
    // A server that offers AUTH and no STARTTLS.
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let seen = Arc::new(parking_lot::Mutex::new(Vec::<String>::new()));
    let s2 = seen.clone();
    tokio::spawn(async move {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        loop {
            let Ok((sock, _)) = l.accept().await else { return };
            let (r, mut w) = sock.into_split();
            let mut lines = BufReader::new(r).lines();
            let _ = w.write_all(b"220 hi\r\n").await;
            while let Ok(Some(line)) = lines.next_line().await {
                s2.lock().push(line.clone());
                let up = line.to_uppercase();
                let reply: &[u8] = if up.starts_with("EHLO") {
                    b"250-stub\r\n250 AUTH PLAIN LOGIN\r\n"
                } else if up.starts_with("AUTH") {
                    b"235 ok\r\n"
                } else if up.starts_with("DATA") {
                    let _ = w.write_all(b"354 go\r\n").await;
                    while let Ok(Some(l)) = lines.next_line().await {
                        if l == "." {
                            break;
                        }
                    }
                    b"250 queued\r\n"
                } else if up.starts_with("QUIT") {
                    let _ = w.write_all(b"221 bye\r\n").await;
                    break;
                } else {
                    b"250 ok\r\n"
                };
                let _ = w.write_all(reply).await;
            }
        }
    });
    let conn = |props: Value| {
        let mut p = json!({"mail.smtp.host": "127.0.0.1", "mail.smtp.port": port});
        for (k, v) in props.as_object().unwrap() {
            p[k] = v.clone();
        }
        Connection::from_json(json!({"name": "m", "connectionDetails": {"mailProps": p, "username": "u", "password": "pw"}})).unwrap()
    };
    let d = ProcessedEmail { to: vec!["a@x.com".into()], from: "f@x.com".into(), subject: "s".into(), body: "b".into(), ..Default::default() };
    let sent = email::smtp_send(&conn(json!({"mail.smtp.auth": "true", "mail.smtp.starttls.enable": "true", "mail.smtp.from": "bounce@x.com"})), &d, false).await.unwrap();
    assert!(sent);
    let lines = seen.lock().clone();
    assert!(lines.iter().any(|l| l.starts_with("AUTH PLAIN")));
    assert!(lines.iter().any(|l| l.contains("MAIL FROM:<bounce@x.com>")));
    let e = email::smtp_send(&conn(json!({"mail.smtp.starttls.enable": true, "mail.smtp.starttls.required": "true"})), &d, false).await.unwrap_err();
    assert!(e.message().contains("STARTTLS is required"));
    assert!(email::smtp_send(&conn(json!({"mail.smtp.ssl.enable": "true", "mail.smtp.connectiontimeout": "2000"})), &d, false).await.is_err());
    assert!(email::smtp_send(&conn(json!({"mail.smtp.from": "not an address"})), &d, false).await.is_err());
}

#[tokio::test]
async fn send_email_paths() {
    use connections::email::{self, EmailContext, EmailTemplate, TemplateStore};
    struct T;
    #[async_trait]
    impl TemplateStore for T {
        async fn read(&self, _: &str, _: &str, _: &str) -> ConnResult<Option<EmailTemplate>> {
            Ok(Some(EmailTemplate::from_json(json!({"templateParts": {"en": {"subject": "S", "body": "B", "nul": null}}})).unwrap()))
        }
    }
    let (port, log) = server(vec![Canned { status: 202, headers: vec![], body: vec![], delay_ms: 0 }]).await;
    let store = common::Store(vec![
        Connection::from_json(json!({"name": "sg", "clientCode": "SYSTEM", "connectionType": "MAIL", "connectionSubType": "SENDGRID", "connectionDetails": {"apiKey": "k", "fromAddress": "f@x.com"}})).unwrap(),
        Connection::from_json(json!({"name": "s1", "clientCode": "SYSTEM", "connectionType": "MAIL", "connectionSubType": "SMTP"})).unwrap(),
        Connection::from_json(json!({"name": "s2", "clientCode": "SYSTEM", "connectionType": "MAIL", "connectionSubType": "SMTP", "connectionDetails": {"mailProps": {}}})).unwrap(),
        Connection::from_json(json!({"name": "s3", "clientCode": "SYSTEM", "connectionType": "MAIL", "connectionSubType": "SMTP", "connectionDetails": {"mailProps": {"a": 1}}})).unwrap(),
    ]);
    let http = connections::rest::http::HttpClient { block_private_targets: false };
    let url = format!("http://127.0.0.1:{port}/v3/mail/send");
    let ctx = EmailContext { connections: &store, templates: &T, http: &http, sendgrid_url: &url, block_private_targets: false };
    let c = caller();
    let d = Map::new();
    let to = vec!["a@x.com".to_string()];
    assert_eq!(email::send_email(&ctx, &c, None, None, &to, "t", Some("sg"), &d).await.unwrap(), Some(true));
    assert!(log.lock()[0].contains("\"value\":\"B\""));
    for (name, msg) in [
        ("s1", "Unable to send the email: Connection details are missing"),
        ("s2", "Unable to send the email: Connection Properties with 'mail.' are missing"),
        ("s3", "Unable to send the email: Connection username/password is missing"),
    ] {
        assert_eq!(email::send_email(&ctx, &c, None, None, &to, "t", Some(name), &d).await.unwrap_err().message(), msg);
    }
    assert_eq!(email::send_email(&ctx, &c, None, None, &to, "t", None, &d).await.unwrap_err().message(), "Connection details missing null");
    // SendEmail with explicit codes and no caller: the second, raw-codes attempt is the one that runs.
    let anon = Caller { in_kirun: true, ..Default::default() };
    assert_eq!(email::send_email_function(&ctx, &anon, "app", "SYSTEM", Some("sg"), "t", None, &json!({"x": 1}).as_object().unwrap().clone(), &Default::default()).await.unwrap_err().message(), "Unable to send the email: No Send Addresses Found.");
}

#[test]
fn readable_tokens_and_store_types() {
    let _ = service(vec![], Arc::new(MemTokens::default()), Functions::answering(None));
    let v = serde_json::to_value(Connection::default()).unwrap();
    assert!(v.get("connectionType").is_some());
}
