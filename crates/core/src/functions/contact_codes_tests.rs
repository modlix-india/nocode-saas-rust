//! `CoreServices.Security.SendContactCode` / `VerifyContactCode` against a stand-in
//! security-internal ([`World`]), connections in memory, a recording publisher and a fake SMS
//! provider. Nothing leaves the machine.

use std::sync::Arc;

use axum::http::HeaderMap;
use axum::routing::post;
use axum::Router;
use kirun::function::Function;
use overridable::{JMap, JValue};
use parking_lot::Mutex;
use platform::upstream::Upstream;
use serde_json::{json, Value};

use super::contact_codes::{all, fill, sms_call};
use super::security_world::{anonymous, find, run, user, World};
use crate::clients::SecurityCalls;
use crate::integrations::{Integrations, Mq};
use crate::integrations_tests::{MemoryDocs, MemoryTokens, Recording};

const ISSUE: &str = "/api/security/internal/contactCodes";
const VERIFY: &str = "/api/security/internal/contactCodes/verify";

struct Setup {
    fns: Vec<Arc<dyn Function>>,
    world: Arc<World>,
    docs: Arc<MemoryDocs>,
    published: Arc<Recording>,
    sms_seen: Arc<Mutex<Vec<(String, String)>>>,
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
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s1 = seen.clone();
    let provider = Router::new()
        .route("/sms/send", post(move |h: HeaderMap, body: String| {
            let s = s1.clone();
            async move {
                s.lock().push((h.get("x-api-key").and_then(|v| v.to_str().ok()).unwrap_or("").to_string(), body));
                axum::Json(json!({"status": "queued"}))
            }
        }))
        .route("/sms/down", post(|| async { (axum::http::StatusCode::SERVICE_UNAVAILABLE, "down") }));
    let target = crate::testing::serve(provider).await;
    let docs = Arc::new(MemoryDocs::default());
    let published = Arc::new(Recording::default());
    let mut cfg = crate::config::CoreConfig::default();
    cfg.connections.block_private_targets = false;
    let mq = Arc::new(Mq::with(published.clone(), &cfg.mq));
    let cache = platform::cache::CacheService::new("cmn", "evictionChannel", None).unwrap();
    let security = Arc::new(SecurityCalls::new(Upstream::fixed(&[&security_base])).unwrap());
    let integrations =
        Arc::new(Integrations::new(&cfg, docs.clone(), security.clone(), Arc::new(MemoryTokens::default()), cache, mq, None).unwrap());
    Setup { fns: all(&security, &integrations), world, docs, published, sms_seen: seen, target }
}

impl Setup {
    fn sms_connection(&self, name: &str, path: &str, with_sms: bool) {
        let mut details = json!({"baseUrl": self.target, "defaultHeaders": {"x-api-key": "tenant-key"}});
        if with_sms {
            details["sms"] = json!({
                "url": path,
                "headers": {"Content-Type": "application/json"},
                "payload": {"to": "{phoneDigits}", "from": "BLDR", "text": "{message}"},
            });
        }
        self.docs.connections.lock().insert(
            name.to_string(),
            jmap(json!({"name": name, "appCode": "leadzumptwo", "clientCode": "SYSTEM", "connectionType": "REST_API",
                        "connectionSubType": "REST_API_BASIC", "connectionDetails": details})),
        );
    }

    fn body(&self, path: &str) -> Value {
        serde_json::from_str(&self.world.last(path).body).unwrap()
    }
}

#[tokio::test]
async fn signatures() {
    let s = setup().await;
    let send = find(&s.fns, "SendContactCode");
    let sig = send.get_signature();
    assert_eq!(sig.get_full_name(), "CoreServices.Security.SendContactCode");
    let params: Vec<&String> = sig.get_parameters().keys().collect();
    for p in ["emailId", "phoneNumber", "smsConnection"] {
        assert!(params.iter().any(|x| x.as_str() == p), "{p}");
    }
    assert_eq!(find(&s.fns, "VerifyContactCode").get_signature().get_full_name(), "CoreServices.Security.VerifyContactCode");
}

#[tokio::test]
async fn only_in_a_server_function_and_only_signed_in() {
    let s = setup().await;
    let send = find(&s.fns, "SendContactCode");
    let outside = run(send.as_ref(), json!({"emailId": "a@x.io"}), user(110, 7, "FIN", &[]), false, true).await;
    assert!(outside.is_err(), "not callable outside a definition");
    let anon = run(send.as_ref(), json!({"emailId": "a@x.io"}), anonymous(7, "FIN"), true, true).await.unwrap();
    assert_eq!((anon["sent"].clone(), anon["reason"].as_str()), (json!(false), Some("SIGN_IN")));
    let verify = find(&s.fns, "VerifyContactCode");
    let anon = run(verify.as_ref(), json!({"emailId": "a@x.io", "code": "1"}), anonymous(7, "FIN"), true, true).await.unwrap();
    assert_eq!((anon["verified"].clone(), anon["reason"].as_str()), (json!(false), Some("SIGN_IN")));
    assert_eq!(s.world.count("/api/security/internal/contactCodes"), 0, "security is not asked");
}

#[tokio::test]
async fn an_email_code_goes_out_as_the_apps_otp_event() {
    let s = setup().await;
    s.world.answer(
        "POST",
        ISSUE,
        200,
        r#"{"ok":true,"channel":"EMAIL","target":"asha@example.com","expireMinutes":10,"resendAfterSeconds":30,"appName":"CXZump","sent":false,"code":"482913"}"#,
    );
    let send = find(&s.fns, "SendContactCode");
    let r = run(send.as_ref(), json!({"emailId": " Asha@Example.com "}), user(110, 7, "FIN", &[]), true, true).await.unwrap();
    assert_eq!(r["sent"], json!(true));
    assert_eq!((r["channel"].as_str(), r["target"].as_str(), r["expireMinutes"].as_i64(), r["resendAfterSeconds"].as_i64()), (Some("EMAIL"), Some("asha@example.com"), Some(10), Some(30)));
    assert!(r.get("code").is_none(), "the code never reaches the definition");
    assert!(!r.values().any(|v| v.as_str() == Some("482913")));
    let asked = s.body(ISSUE);
    assert_eq!(
        (asked["appCode"].as_str(), asked["clientCode"].as_str(), asked["userId"].as_u64(), asked["delivery"].as_str(), asked["emailId"].as_str()),
        (Some("leadzumptwo"), Some("SYSTEM"), Some(110), Some("RETURN"), Some("Asha@Example.com"))
    );
    let sent = s.published.sent.lock().clone();
    assert_eq!(sent.len(), 1);
    let ev = &sent[0].2;
    assert_eq!((ev["eventName"].as_str(), ev["appCode"].as_str(), ev["clientCode"].as_str()), (Some("USER_OTP_GENERATE"), Some("leadzumptwo"), Some("SYSTEM")));
    assert_eq!(ev["data"], json!({"appName": "CXZump", "email": "asha@example.com", "otp": "482913", "otpPurpose": "VERIFICATION", "expireInterval": 10}));
}

#[tokio::test]
async fn refusals_are_answers() {
    let s = setup().await;
    let send = find(&s.fns, "SendContactCode");
    s.world.answer("POST", ISSUE, 200, r#"{"ok":false,"reason":"WAIT","message":"A code was just sent. You can ask for another in 12 seconds.","channel":"EMAIL","target":"a@x.io","retryAfterSeconds":12}"#);
    let r = run(send.as_ref(), json!({"emailId": "a@x.io"}), user(110, 7, "FIN", &[]), true, true).await.unwrap();
    assert_eq!((r["sent"].clone(), r["reason"].as_str(), r["retryAfterSeconds"].as_i64()), (json!(false), Some("WAIT"), Some(12)));
    assert!(r["message"].as_str().unwrap().contains("12 seconds"));
    assert_eq!(r["expireMinutes"], json!(0), "every key is there");
    assert!(s.published.sent.lock().is_empty());
    s.world.answer("POST", ISSUE, 200, r#"{"ok":false,"reason":"LIMIT","message":"Too many"}"#);
    let r = run(send.as_ref(), json!({"emailId": "a@x.io"}), user(110, 7, "FIN", &[]), true, true).await.unwrap();
    assert_eq!(r["reason"], "LIMIT");
    s.world.answer("POST", ISSUE, 500, r#"{"message":"down"}"#);
    assert!(run(send.as_ref(), json!({"emailId": "a@x.io"}), user(110, 7, "FIN", &[]), true, true).await.is_err(), "a broken security is an error");
}

#[tokio::test]
async fn a_phone_without_the_institutions_connection_uses_the_platform_sms() {
    let s = setup().await;
    s.world.answer("POST", ISSUE, 200, r#"{"ok":true,"channel":"PHONE","target":"+919845012345","expireMinutes":10,"resendAfterSeconds":30,"appName":"CXZump","sent":true}"#);
    let send = find(&s.fns, "SendContactCode");
    for conn in ["", "cxSms"] {
        let r = run(send.as_ref(), json!({"phoneNumber": "+91 98450 12345", "smsConnection": conn}), user(110, 7, "FIN", &[]), true, true).await.unwrap();
        assert_eq!((r["sent"].clone(), r["channel"].as_str()), (json!(true), Some("PHONE")));
        assert_eq!(s.body(ISSUE)["delivery"], "PLATFORM_SMS", "no connection named {conn:?}");
    }
    s.world.answer("POST", ISSUE, 200, r#"{"ok":false,"reason":"NO_SMS","message":"We cannot send a text message to this number yet."}"#);
    let r = run(send.as_ref(), json!({"phoneNumber": "+65 8123 4567"}), user(110, 7, "FIN", &[]), true, true).await.unwrap();
    assert_eq!(r["reason"], "NO_SMS");
    assert!(s.sms_seen.lock().is_empty() && s.published.sent.lock().is_empty());
}

#[tokio::test]
async fn a_phone_code_goes_through_the_institutions_sms_connection() {
    let s = setup().await;
    s.sms_connection("cxSms", "/sms/send", true);
    s.world.answer("POST", ISSUE, 200, r#"{"ok":true,"channel":"PHONE","target":"+6581234567","expireMinutes":5,"resendAfterSeconds":30,"appName":"CXZump","sent":false,"code":"774411"}"#);
    let send = find(&s.fns, "SendContactCode");
    let r = run(send.as_ref(), json!({"phoneNumber": "+65 8123 4567", "smsConnection": "cxSms"}), user(110, 7, "FIN", &[]), true, true).await.unwrap();
    assert_eq!((r["sent"].clone(), r["target"].as_str()), (json!(true), Some("+6581234567")));
    assert_eq!(s.body(ISSUE)["delivery"], "RETURN");
    let seen = s.sms_seen.lock().clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, "tenant-key", "the connection's own headers go with it");
    let body: Value = serde_json::from_str(&seen[0].1).unwrap();
    assert_eq!(body["to"], "6581234567");
    assert_eq!(body["from"], "BLDR");
    assert_eq!(body["text"], "774411 is your CXZump verification code. It works for 5 minutes. Do not share it.");
    assert!(s.published.sent.lock().is_empty(), "no e-mail event for a phone");
    assert!(!r.values().any(|v| v.as_str() == Some("774411")));

    // The provider refuses: not sent, said plainly.
    s.sms_connection("cxSms", "/sms/down", true);
    let r = run(send.as_ref(), json!({"phoneNumber": "+65 8123 4567", "smsConnection": "cxSms"}), user(110, 7, "FIN", &[]), true, true).await.unwrap();
    assert_eq!((r["sent"].clone(), r["reason"].as_str(), r["target"].as_str()), (json!(false), Some("SEND_FAILED"), Some("+6581234567")));

    // A connection with no sms settings cannot send, and security is not asked for a code.
    s.sms_connection("cxSms", "/sms/send", false);
    let before = s.world.count(ISSUE);
    let r = run(send.as_ref(), json!({"phoneNumber": "+65 8123 4567", "smsConnection": "cxSms"}), user(110, 7, "FIN", &[]), true, true).await.unwrap();
    assert_eq!(r["reason"], "SEND_FAILED");
    assert_eq!(s.world.count(ISSUE), before);
}

#[tokio::test]
async fn verify_passes_the_callers_scope_and_answers() {
    let s = setup().await;
    let verify = find(&s.fns, "VerifyContactCode");
    s.world.answer("POST", VERIFY, 200, r#"{"ok":true,"channel":"EMAIL","target":"asha@example.com"}"#);
    let r = run(verify.as_ref(), json!({"emailId": "Asha@example.com", "code": " 482913 "}), user(110, 7, "FIN", &[]), true, true).await.unwrap();
    assert_eq!((r["verified"].clone(), r["target"].as_str(), r["reason"].as_str()), (json!(true), Some("asha@example.com"), Some("")));
    let asked = s.body(VERIFY);
    assert_eq!((asked["userId"].as_u64(), asked["appCode"].as_str(), asked["clientCode"].as_str(), asked["code"].as_str()), (Some(110), Some("leadzumptwo"), Some("SYSTEM"), Some("482913")));
    s.world.answer("POST", VERIFY, 200, r#"{"ok":false,"reason":"WRONG_CODE","message":"That code is not right.","triesLeft":3}"#);
    let r = run(verify.as_ref(), json!({"phoneNumber": "+919845012345", "code": "1"}), user(110, 7, "FIN", &[]), true, true).await.unwrap();
    assert_eq!((r["verified"].clone(), r["reason"].as_str(), r["triesLeft"].as_i64()), (json!(false), Some("WRONG_CODE"), Some(3)));
    // `ok` must be exactly true.
    s.world.answer("POST", VERIFY, 200, r#"{"ok":"true","target":"x"}"#);
    let r = run(verify.as_ref(), json!({"emailId": "a@x.io", "code": "1"}), user(110, 7, "FIN", &[]), true, true).await.unwrap();
    assert_eq!(r["verified"], json!(false));
}

#[test]
fn placeholders() {
    let vars = [("phone", "+919845012345".to_string()), ("code", "12".to_string())];
    assert_eq!(fill(&json!({"a": ["{phone}", 3, {"b": "x{code}y{code}"}], "c": "{nope}"}), &vars), json!({"a": ["+919845012345", 3, {"b": "x12y12"}], "c": "{nope}"}));
    let sms = json!({"url": "/send/{phoneDigits}", "method": "get", "queryParams": {"msg": "{message}"}, "message": "Code {code}"});
    let req = sms_call("cxSms", "a", "B", sms.as_object().unwrap(), &[("phoneDigits", "9198".into()), ("code", "55".into())]);
    assert_eq!((req.url.as_str(), req.method.as_str(), req.query_params["msg"].as_str()), ("/send/9198", "GET", Some("Code 55")));
    assert!(req.payload.is_none());
}
