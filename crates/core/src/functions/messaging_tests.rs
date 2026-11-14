//! `CoreServices.Messaging.SendSms` against connections and templates in memory and a fake SMS
//! provider. Nothing leaves the machine.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::Router;
use kirun::function::Function;
use overridable::{JMap, JValue};
use parking_lot::Mutex;
use platform::upstream::Upstream;
use serde_json::{json, Value};

use super::messaging::{all, dlt_text, international, needs_unicode, sms_parts, Limits, COMPANY_PER_HOUR, PHONE_PER_HOUR};
use super::security_world::{anonymous, find, run, user, World};
use crate::clients::SecurityCalls;
use crate::integrations::{Integrations, Mq};
use crate::integrations_tests::{MemoryDocs, MemoryTokens, Recording};

type Seen = Arc<Mutex<Vec<(String, String, String)>>>;

struct Setup {
    fns: Vec<Arc<dyn Function>>,
    docs: Arc<MemoryDocs>,
    seen: Seen,
    target: String,
}

fn jmap(v: Value) -> JMap {
    match overridable::json::parse(v.to_string().as_bytes()).unwrap() {
        JValue::Object(m) => m,
        _ => panic!("not an object"),
    }
}

async fn setup() -> Setup {
    let world = World::new();
    let security_base = world.serve().await;
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let (s1, s2) = (seen.clone(), seen.clone());
    let provider = Router::new()
        .route("/sms/send", post(move |h: HeaderMap, body: String| {
            let s = s1.clone();
            async move {
                let auth = h.get("authorization").or(h.get("authkey")).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                s.lock().push((auth, body, String::new()));
                axum::Json(json!({"type": "success", "id": "m1"}))
            }
        }))
        .route("/sms/get", get(move |q: axum::extract::RawQuery| {
            let s = s2.clone();
            async move {
                s.lock().push((String::new(), String::new(), q.0.unwrap_or_default()));
                "success | 919845012345 | 3365"
            }
        }))
        .route("/sms/refuse200", post(|| async { axum::Json(json!({"type": "error", "message": "Invalid DLT template"})) }))
        .route("/sms/down", post(|| async { (axum::http::StatusCode::UNAUTHORIZED, "bad key") }));
    let target = crate::testing::serve(provider).await;
    let docs = Arc::new(MemoryDocs::default());
    let mut cfg = crate::config::CoreConfig::default();
    cfg.connections.block_private_targets = false;
    let mq = Arc::new(Mq::with(Arc::new(Recording::default()), &cfg.mq));
    let cache = platform::cache::CacheService::new("cmn", "evictionChannel", None).unwrap();
    let security = Arc::new(SecurityCalls::new(Upstream::fixed(&[&security_base])).unwrap());
    let integrations =
        Arc::new(Integrations::new(&cfg, docs.clone(), security, Arc::new(MemoryTokens::default()), cache, mq, None).unwrap());
    Setup { fns: all(&integrations), docs, seen, target }
}

const BODY: &str = "Dear ${name}, please sign the ${doc} for booking ${caseNumber}: ${link} - ${company}";

impl Setup {
    fn connection(&self, sms: Value) {
        let details = json!({"baseUrl": self.target, "credentials": {"apiKey": "tenant-key", "accountSid": "AC1", "authToken": "tok"}, "sms": sms});
        self.docs.connections.lock().insert(
            "cxSms".into(),
            jmap(json!({"name": "cxSms", "appCode": "leadzumptwo", "clientCode": "SYSTEM", "connectionType": "REST_API",
                        "connectionSubType": "REST_API_BASIC", "connectionDetails": details})),
        );
    }

    fn json_provider(&self, path: &str) {
        self.connection(json!({
            "provider": "CUSTOM", "senderId": "CONNID", "dltEntityId": "1101000000000001",
            "url": path, "headers": {"Content-Type": "application/json", "authkey": "{apiKey}"},
            "payload": {"to": "{phoneDigits}", "from": "{senderId}", "text": "{message}", "te": "{dltTemplateId}", "pe": "{dltEntityId}", "u": "{unicode}"},
            "errorWhen": {"field": "type", "equals": "error"},
        }));
    }

    fn template(&self, name: &str, body: &str, sms: Value) {
        self.docs.templates.lock().insert(
            name.into(),
            jmap(json!({"name": name, "appCode": "leadzumptwo", "clientCode": "SYSTEM", "templateType": "sms",
                        "templateParts": {"en": {"body": body}}, "design": {"sms": sms}})),
        );
    }

    fn active(&self) {
        self.template("cxSmsSignLink", BODY, json!({"status": "ACTIVE", "dltTemplateId": "1107000000000042", "senderId": "BLDRCO", "registeredText": dlt_text(BODY)}));
    }
}

fn vars() -> Value {
    json!({"name": "Asha", "doc": "booking form", "caseNumber": "CX-1", "link": "https://fin.example/signForm/s1", "company": "Fincity Homes"})
}

async fn send(s: &Setup, args: Value) -> serde_json::Map<String, Value> {
    run(find(&s.fns, "SendSms").as_ref(), args, user(110, 7, "FIN", &[]), true, true).await.unwrap()
}

fn args(phone: &str) -> Value {
    json!({"connectionName": "cxSms", "phone": phone, "templateName": "cxSmsSignLink", "vars": vars()})
}

#[tokio::test]
async fn signature_and_only_in_a_server_function() {
    let s = setup().await;
    let f = find(&s.fns, "SendSms");
    assert_eq!(f.get_signature().get_full_name(), "CoreServices.Messaging.SendSms");
    for p in ["appCode", "clientCode", "connectionName", "phone", "templateName", "vars"] {
        assert!(f.get_signature().get_parameters().contains_key(p), "{p}");
    }
    assert!(run(f.as_ref(), args("+919845012345"), user(110, 7, "FIN", &[]), false, true).await.is_err());
    assert!(s.seen.lock().is_empty());
}

#[tokio::test]
async fn sends_the_active_template_through_the_companys_provider() {
    let s = setup().await;
    s.json_provider("/sms/send");
    s.active();
    let r = send(&s, args("+91 98450-12345")).await;
    assert_eq!((r["sent"].clone(), r["reason"].as_str(), r["target"].as_str()), (json!(true), Some(""), Some("+919845012345")));
    let text = "Dear Asha, please sign the booking form for booking CX-1: https://fin.example/signForm/s1 - Fincity Homes";
    assert_eq!(r["text"], text);
    assert_eq!((r["characters"].as_u64(), r["parts"].as_u64()), (Some(text.len() as u64), Some(1)));
    let seen = s.seen.lock().clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, "tenant-key", "the secret from the credentials block");
    let body: Value = serde_json::from_str(&seen[0].1).unwrap();
    assert_eq!(body, json!({"to": "919845012345", "from": "BLDRCO", "text": text, "te": "1107000000000042", "pe": "1101000000000001", "u": "0"}));
    // Signed out (the outbox drain) works the same.
    let r = run(find(&s.fns, "SendSms").as_ref(), args("+919845012345"), anonymous(7, "FIN"), true, true).await.unwrap();
    assert_eq!(r["sent"], json!(true));
}

#[tokio::test]
async fn query_string_providers_and_basic_auth() {
    let s = setup().await;
    s.connection(json!({"url": "/sms/get", "method": "GET", "senderId": "CONNID",
                        "queryParams": {"send_to": "{phoneDigits}", "msg": "{message}", "mask": "{senderId}", "auth": "{basicAuth}"}}));
    s.template("cxSmsSignLink", "Hi ${name}", json!({"status": "active"}));
    let r = send(&s, args("+6581234567")).await;
    assert_eq!(r["sent"], json!(true), "{r:?}");
    let q = s.seen.lock()[0].2.clone();
    assert!(q.contains("send_to=6581234567"), "{q}");
    assert!(q.contains("mask=CONNID"), "the connection's sender when the template has none: {q}");
    assert!(q.contains("msg=Hi%20Asha") || q.contains("msg=Hi+Asha"), "{q}");
    assert!(q.contains("auth=QUMxOnRvaw"), "base64 of AC1:tok: {q}");
}

#[tokio::test]
async fn an_account_and_a_key_make_basic_auth() {
    let s = setup().await;
    let details = json!({"baseUrl": s.target, "credentials": {"key": "tok"},
                         "sms": {"account": "AC9", "url": "/sms/get", "method": "GET",
                                 "queryParams": {"a": "{basicAuth}", "who": "{account}", "t": "{msgType}"}}});
    s.docs.connections.lock().insert(
        "cxSms".into(),
        jmap(json!({"name": "cxSms", "appCode": "leadzumptwo", "clientCode": "SYSTEM", "connectionType": "REST_API",
                    "connectionSubType": "REST_API_BASIC", "connectionDetails": details})),
    );
    s.template("cxSmsSignLink", "नमस्ते ${name}", json!({"status": "ACTIVE"}));
    assert_eq!(send(&s, args("+6581234567")).await["sent"], json!(true));
    let q = s.seen.lock()[0].2.clone();
    assert!(q.contains("a=QUM5OnRvaw"), "base64 of AC9:tok: {q}");
    assert!(q.contains("who=AC9") && q.contains("t=UNICODE_TEXT"), "{q}");
}

#[tokio::test]
async fn refusals_are_answers() {
    let s = setup().await;
    // No provider.
    let r = send(&s, args("+919845012345")).await;
    assert_eq!((r["sent"].clone(), r["reason"].as_str()), (json!(false), Some("NO_SMS")));
    let r = send(&s, json!({"phone": "+919845012345", "templateName": "cxSmsSignLink"})).await;
    assert_eq!(r["reason"], "NO_SMS");
    s.connection(json!({"enabled": false, "url": "/sms/send"}));
    assert_eq!(send(&s, args("+919845012345")).await["reason"], "NO_SMS");
    s.json_provider("/sms/send");
    // A bad number.
    for bad in ["9845012345", "+91 98", "+91abc12345678", ""] {
        assert_eq!(send(&s, args(bad)).await["reason"], "INVALID", "{bad}");
    }
    // No template, not an SMS template, not active.
    assert_eq!(send(&s, args("+919845012345")).await["reason"], "NOT_ACTIVE");
    s.docs.templates.lock().insert("cxSmsSignLink".into(), jmap(json!({"name": "cxSmsSignLink", "templateType": "email", "templateParts": {"en": {"body": "x"}}})));
    assert_eq!(send(&s, args("+919845012345")).await["reason"], "NOT_ACTIVE");
    for status in ["DRAFT", "WAITING"] {
        s.template("cxSmsSignLink", BODY, json!({"status": status, "dltTemplateId": "1107"}));
        assert_eq!(send(&s, args("+919845012345")).await["reason"], "NOT_ACTIVE", "{status}");
    }
    // +91 needs a DLT id, and the registered text.
    s.template("cxSmsSignLink", BODY, json!({"status": "ACTIVE"}));
    let r = send(&s, args("+919845012345")).await;
    assert_eq!(r["reason"], "NOT_ACTIVE");
    assert!(r["message"].as_str().unwrap().contains("DLT"));
    assert_eq!(send(&s, args("+6581234567")).await["sent"], json!(true), "elsewhere no DLT id is needed");
    s.template("cxSmsSignLink", &format!("{BODY}!"), json!({"status": "ACTIVE", "dltTemplateId": "1107", "registeredText": dlt_text(BODY)}));
    let r = send(&s, args("+919845012345")).await;
    assert_eq!(r["reason"], "NOT_ACTIVE");
    assert!(r["message"].as_str().unwrap().contains("changed after"));
    let before = s.seen.lock().len();
    // The provider refuses: by its status, or by a 200 whose reply says error.
    s.active();
    s.json_provider("/sms/down");
    let r = send(&s, args("+919845012345")).await;
    assert_eq!((r["sent"].clone(), r["reason"].as_str()), (json!(false), Some("SEND_FAILED")));
    assert!(r["message"].as_str().unwrap().contains("401"), "{r:?}");
    assert!(r["text"].as_str().unwrap().starts_with("Dear Asha"), "the text it tried is kept for the history");
    s.json_provider("/sms/refuse200");
    let r = send(&s, args("+919845012345")).await;
    assert_eq!(r["reason"], "SEND_FAILED");
    assert!(r["message"].as_str().unwrap().contains("Invalid DLT template"), "{r:?}");
    assert_eq!(s.seen.lock().len(), before, "nothing reached the recording route");
}

#[tokio::test]
async fn the_limit_per_number() {
    let s = setup().await;
    s.json_provider("/sms/send");
    s.active();
    for _ in 0..PHONE_PER_HOUR {
        assert_eq!(send(&s, args("+919845012345")).await["sent"], json!(true));
    }
    let r = send(&s, args("+919845012345")).await;
    assert_eq!((r["sent"].clone(), r["reason"].as_str()), (json!(false), Some("LIMIT")));
    assert_eq!(send(&s, args("+919845012346")).await["sent"], json!(true), "another number is fine");
}

#[test]
fn limits_turn_with_the_hour() {
    let l = Limits::default();
    let t0 = Instant::now();
    for i in 0..COMPANY_PER_HOUR {
        assert!(l.take("FIN", &format!("+9198450{i:05}"), t0));
    }
    assert!(!l.take("FIN", "+919999999999", t0), "the company's hour is full");
    assert!(l.take("OTHER", "+919999999999", t0), "another company has its own");
    assert!(l.take("FIN", "+919999999999", t0 + Duration::from_secs(3601)));
}

#[test]
fn numbers_texts_and_parts() {
    assert_eq!(international("+91 98450 12345").as_deref(), Some("+919845012345"));
    assert_eq!(international("0091-98450-12345").as_deref(), Some("+919845012345"));
    assert_eq!(international("(+65) 8123.4567").as_deref(), Some("+6581234567"));
    for bad in ["9845012345", "+0123456789", "+1234", "+91 98450 1234x", "+1234567890123456"] {
        assert!(international(bad).is_none(), "{bad}");
    }
    assert_eq!(dlt_text(BODY), "Dear {#var#}, please sign the {#var#} for booking {#var#}: {#url#} - {#var#}");
    assert_eq!(dlt_text("Pay ${(case.amount)!0} by ${dueOn} at ${payUrl}"), "Pay {#var#} by {#var#} at {#url#}");
    assert_eq!(dlt_text("no fields, {braces} and $ alone"), "no fields, {braces} and $ alone");
    assert_eq!(dlt_text("broken ${x"), "broken ${x");
    assert!(!needs_unicode("Plain text: 100% ok @ 5 {x} [y] €"));
    assert!(needs_unicode("नमस्ते"));
    assert!(needs_unicode("smart “quotes”"));
    assert_eq!(sms_parts(&"a".repeat(160)), (160, 1));
    assert_eq!(sms_parts(&"a".repeat(161)), (161, 2));
    assert_eq!(sms_parts(&"a".repeat(307)), (307, 3));
    assert_eq!(sms_parts("[]"), (4, 1), "extension characters count two");
    assert_eq!(sms_parts(&"न".repeat(70)), (70, 1));
    assert_eq!(sms_parts(&"न".repeat(71)), (71, 2));
}
