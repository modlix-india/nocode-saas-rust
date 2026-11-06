//! `CoreServices.Connection.VerifySignature` (Rust only): checks a webhook's HMAC signature with
//! a secret that is stored in a connection, so the secret never enters KIRun scope (LZT-2267).
//!
//! `CoreServices.Crypto.SignatureValidator` takes the key as a literal argument, so an app that
//! verifies a provider's webhook had to keep a second copy of the provider's secret somewhere a
//! function can read it. Here the function names a connection and the path of the secret inside
//! its `connectionDetails` (for a Meta app: `tokenDetails.queryParams.client_secret`, the app
//! secret that is both the OAuth `client_secret` and the `X-Hub-Signature-256` key). Core reads
//! the connection the way the code that opens connections does, computes the HMAC itself and
//! answers only:
//!
//! - `isValid`: the signature matches the data;
//! - `configured`: the connection was found and holds a usable secret at that path;
//! - `reason`: `VALID`, `INVALID_SIGNATURE`, `BAD_SIGNATURE_FORMAT`, `NO_CONNECTION`,
//!   `NO_SECRET` (nothing, or not text, at the path) or `WEAK_SECRET` (shorter than the
//!   digest, which HMAC verification refuses).
//!
//! What keeps it from becoming a way to read credentials:
//! - nothing of the secret comes back, not even its length;
//! - it runs only inside a server function (never a direct HTTP execution of the function);
//! - the connection is read by `connections::connection::read`, the same rules as a REST step:
//!   the client's own connection or an app level one, `onlyThruKIRun` honoured;
//! - only for the running definition's own app (or the URL's app): `appCode` naming another
//!   app is refused, so one app's functions cannot probe another app's connections;
//! - there is no signing counterpart on purpose: a function that could sign with a stored
//!   secret could forge the provider's webhooks.

use std::sync::Arc;

use async_trait::async_trait;
use connections::connection::{self, ConnectionType};
use kirun::json::schema::Schema;
use kirun::model::{Event, FunctionOutput, FunctionSignature, Parameter};
use kirun::{Map, Value};

use super::crypto::{constant_time_eq, encode_charset, HmacAlgo, StringEncoder};
use super::support::{forbidden, server_function_only};
use super::{arg, CoreFunction};
use crate::context;
use crate::error::CoreError;
use crate::integrations::{caller, Integrations};

const NAMESPACE: &str = "CoreServices.Connection";
const NAME: &str = "VerifySignature";

pub fn all(integrations: &Arc<Integrations>) -> Vec<Arc<dyn kirun::function::Function>> {
    vec![Arc::new(super::Core(VerifySignature::new(integrations.clone())))]
}

fn text(name: &str, default: Option<&str>) -> (String, Parameter) {
    let mut s = Schema::of_string(name);
    if let Some(d) = default {
        s = s.set_default_value(Value::from(d));
    }
    Parameter::of_entry(name, s, false)
}

fn text_arg(args: &Map<Value>, name: &str) -> String {
    match args.get(name) {
        Some(Value::String(s)) => s.trim().to_string(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

/// The value at a dotted path inside a connection's details (`a.b.c`).
fn at_path<'a>(details: &'a serde_json::Map<String, Value>, path: &str) -> Option<&'a Value> {
    let mut parts = path.split('.').filter(|p| !p.is_empty());
    let mut cur = details.get(parts.next()?)?;
    for p in parts {
        cur = cur.as_object()?.get(p)?;
    }
    Some(cur)
}

/// The answer: never anything of the secret.
fn answer(is_valid: bool, configured: bool, reason: &str) -> FunctionOutput {
    let mut m = Map::new();
    m.insert("isValid".to_string(), Value::Bool(is_valid));
    m.insert("configured".to_string(), Value::Bool(configured));
    m.insert("reason".to_string(), Value::from(reason));
    FunctionOutput::new(vec![kirun::model::EventResult::output_of(m)])
}

pub struct VerifySignature {
    signature: FunctionSignature,
    integrations: Arc<Integrations>,
}

impl VerifySignature {
    pub fn new(integrations: Arc<Integrations>) -> Self {
        let alg = Schema::of_string("alg")
            .set_enums(["HmacSHA1", "HmacSHA256", "HmacSHA384", "HmacSHA512"].map(Value::from).to_vec())
            .set_default_value(Value::from("HmacSHA256"));
        let charset = Schema::of_string("charset")
            .set_enums(["US-ASCII", "ISO-8859-1", "UTF-8", "UTF-16BE", "UTF-16LE", "UTF-16"].map(Value::from).to_vec())
            .set_default_value(Value::from("UTF-8"));
        let encoder = Schema::of_string("signatureEncoder")
            .set_enums(vec![Value::from("base64"), Value::from("Hex")])
            .set_default_value(Value::from("Hex"));
        let output = Map::from([Event::output_event_map_entry(Map::from([
            ("isValid".to_string(), Schema::of_boolean("isValid")),
            ("configured".to_string(), Schema::of_boolean("configured")),
            ("reason".to_string(), Schema::of_string("reason")),
        ]))]);
        Self {
            signature: FunctionSignature::new(NAME)
                .set_namespace(NAMESPACE)
                .set_parameters(Map::from([
                    text("connectionName", None),
                    text("secretPath", None),
                    text("connectionType", Some("REST_API")),
                    text("appCode", Some("")),
                    text("clientCode", Some("")),
                    Parameter::of_entry("alg", alg, false),
                    Parameter::of_entry("charset", charset, false),
                    Parameter::of_entry("data", Schema::of_any_not_null("data"), false),
                    text("signature", Some("")),
                    Parameter::of_entry("signatureEncoder", encoder, false),
                ]))
                .set_events(output),
            integrations,
        }
    }
}

#[async_trait]
impl CoreFunction for VerifySignature {
    fn signature(&self) -> &FunctionSignature {
        &self.signature
    }

    async fn internal_execute(&self, args: &Map<Value>) -> Result<FunctionOutput, CoreError> {
        let full = format!("{NAMESPACE}.{NAME}");
        if !context::in_kirun() {
            return Err(server_function_only(&full));
        }
        let c = caller();
        // The running definition's app, else the URL's: the only app whose connections it reads.
        let own_app = context::owner_app_code().or_else(|| c.url_app_code.clone()).unwrap_or_default();
        let asked_app = text_arg(args, "appCode");
        if !asked_app.is_empty() && asked_app != own_app {
            return Err(forbidden("CORE.CONNECTION_OTHER_APP", format!("{full} reads only the connections of its own app ({own_app})"))
                .param("function", full.as_str()));
        }
        let app = if asked_app.is_empty() { own_app } else { asked_app };
        let (Some(app), Some(client)) = c.resolve_app_and_client(Some(&app), Some(&text_arg(args, "clientCode"))) else {
            return Ok(answer(false, false, "NO_CONNECTION"));
        };
        let name = text_arg(args, "connectionName");
        let path = text_arg(args, "secretPath");
        let wanted = ConnectionType::value_of(&text_arg(args, "connectionType")).unwrap_or(ConnectionType::RestApi);
        if name.is_empty() || app.is_empty() || client.is_empty() {
            return Ok(answer(false, false, "NO_CONNECTION"));
        }
        let conn = match connection::read(self.integrations.connections.store.as_ref(), &c, &name, &app, &client, wanted).await {
            Ok(Some(conn)) => conn,
            Ok(None) => return Ok(answer(false, false, "NO_CONNECTION")),
            Err(e) => {
                tracing::warn!(connection = name.as_str(), app = app.as_str(), client = client.as_str(), error = %e.message(), "VerifySignature: connection not read");
                return Ok(answer(false, false, "NO_CONNECTION"));
            }
        };
        let secret = match conn.details().and_then(|d| at_path(d, &path)) {
            Some(Value::String(s)) if !s.is_empty() => s.clone(),
            _ => return Ok(answer(false, false, "NO_SECRET")),
        };
        let Some(algo) = HmacAlgo::by_jca_name(&text_arg(args, "alg")) else {
            return Err(CoreError::unknown("alg"));
        };
        let charset = text_arg(args, "charset");
        let key = encode_charset(&secret, &charset)?;
        if algo.check_key(&key, false).is_err() {
            return Ok(answer(false, false, "WEAK_SECRET"));
        }
        let data = match arg(args, "data") {
            Value::String(s) => s.clone(),
            Value::Null => return Ok(answer(false, true, "INVALID_SIGNATURE")),
            other => crate::gson::element_to_string(other),
        };
        let encoder = StringEncoder::by_name(&text_arg(args, "signatureEncoder")).unwrap_or(StringEncoder::Hex);
        let given = match encoder.decode(&text_arg(args, "signature")) {
            Ok(g) if !g.is_empty() => g,
            _ => return Ok(answer(false, true, "BAD_SIGNATURE_FORMAT")),
        };
        let signed = algo.sign(&key, &encode_charset(&data, &charset)?);
        if constant_time_eq(&signed, &given) {
            Ok(answer(true, true, "VALID"))
        } else {
            Ok(answer(false, true, "INVALID_SIGNATURE"))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use kirun::function::Function;
    use overridable::{JMap, JValue};
    use serde_json::{json, Value};

    use super::all;
    use crate::functions::crypto::{HmacAlgo, StringEncoder};
    use crate::functions::security_world::{anonymous, run, user};
    use crate::integrations::{Integrations, Mq};
    use crate::integrations_tests::{MemoryDocs, MemoryTokens, Recording};

    const SECRET: &str = "0123456789abcdef0123456789abcdef";
    const BODY: &str = r#"{"object":"whatsapp_business_account","entry":[{"id":"1"}]}"#;
    const PATH: &str = "tokenDetails.queryParams.client_secret";

    fn jmap(v: Value) -> JMap {
        match overridable::json::parse(v.to_string().as_bytes()).unwrap() {
            JValue::Object(m) => m,
            _ => panic!("not an object"),
        }
    }

    fn setup(secret: Option<&str>, only_thru_kirun: bool) -> (Arc<dyn Function>, Arc<MemoryDocs>) {
        let docs = Arc::new(MemoryDocs::default());
        let mut token = json!({"url": "https://graph.example/oauth/access_token", "queryParams": {"client_id": "1099"}});
        if let Some(s) = secret {
            token["queryParams"]["client_secret"] = json!(s);
        }
        docs.connections.lock().insert(
            "meta_Connection".into(),
            jmap(json!({"name": "meta_Connection", "appCode": "leadzumptwo", "clientCode": "SYSTEM", "isAppLevel": true,
                        "onlyThruKIRun": only_thru_kirun, "connectionType": "REST_API", "connectionSubType": "REST_API_OAUTH2",
                        "connectionDetails": {"tokenDetails": token}})),
        );
        let cfg = crate::config::CoreConfig::default();
        let mq = Arc::new(Mq::with(Arc::new(Recording::default()), &cfg.mq));
        let cache = platform::cache::CacheService::new("cmn", "evictionChannel", None).unwrap();
        let security = Arc::new(crate::clients::SecurityCalls::new(platform::upstream::Upstream::fixed(&["http://127.0.0.1:1"])).unwrap());
        let integrations =
            Arc::new(Integrations::new(&cfg, docs.clone(), security, Arc::new(MemoryTokens::default()), cache, mq, None).unwrap());
        (all(&integrations).remove(0), docs)
    }

    fn hex_sig(secret: &str, body: &str) -> String {
        StringEncoder::Hex.encode(&HmacAlgo::Hs256.sign(secret.as_bytes(), body.as_bytes()))
    }

    fn args(sig: &str) -> Value {
        json!({"connectionName": "meta_Connection", "secretPath": PATH, "clientCode": "FIN", "alg": "HmacSHA256",
               "data": BODY, "signature": sig, "signatureEncoder": "Hex"})
    }

    #[tokio::test]
    async fn signature_and_name() {
        let (f, _) = setup(Some(SECRET), false);
        let sig = f.get_signature();
        assert_eq!(sig.get_full_name(), "CoreServices.Connection.VerifySignature");
        for p in ["connectionName", "secretPath", "data", "signature", "alg", "signatureEncoder", "appCode", "clientCode"] {
            assert!(sig.get_parameters().contains_key(p), "{p}");
        }
        assert!(!sig.get_parameters().contains_key("secretKey"), "no literal secret");
    }

    #[tokio::test]
    async fn a_webhook_checked_against_the_stored_secret() {
        let (f, _) = setup(Some(SECRET), true);
        let ok = run(f.as_ref(), args(&hex_sig(SECRET, BODY)), anonymous(7, "FIN"), true, true).await.unwrap();
        assert_eq!((ok["isValid"].clone(), ok["configured"].clone(), ok["reason"].as_str()), (json!(true), json!(true), Some("VALID")));
        // Only the three answers come back: nothing of the secret.
        assert_eq!(ok.len(), 3);
        assert!(!serde_json::to_string(&ok).unwrap().contains(SECRET));

        let other = hex_sig("ffffffffffffffffffffffffffffffff", BODY);
        let bad = run(f.as_ref(), args(&other), anonymous(7, "FIN"), true, true).await.unwrap();
        assert_eq!((bad["isValid"].clone(), bad["configured"].clone(), bad["reason"].as_str()), (json!(false), json!(true), Some("INVALID_SIGNATURE")));

        let mut changed = args(&hex_sig(SECRET, BODY));
        changed["data"] = json!(BODY.replace("\"1\"", "\"2\""));
        let r = run(f.as_ref(), changed, anonymous(7, "FIN"), true, true).await.unwrap();
        assert_eq!(r["reason"], "INVALID_SIGNATURE");

        let r = run(f.as_ref(), args("not-hex"), anonymous(7, "FIN"), true, true).await.unwrap();
        assert_eq!((r["isValid"].clone(), r["reason"].as_str()), (json!(false), Some("BAD_SIGNATURE_FORMAT")));
        let r = run(f.as_ref(), args(""), anonymous(7, "FIN"), true, true).await.unwrap();
        assert_eq!(r["reason"], "BAD_SIGNATURE_FORMAT");
    }

    #[tokio::test]
    async fn not_configured_is_an_answer_not_an_error() {
        let (f, _) = setup(None, false);
        let r = run(f.as_ref(), args(&hex_sig(SECRET, BODY)), anonymous(7, "FIN"), true, true).await.unwrap();
        assert_eq!((r["isValid"].clone(), r["configured"].clone(), r["reason"].as_str()), (json!(false), json!(false), Some("NO_SECRET")));

        let (f, _) = setup(Some("short"), false);
        let r = run(f.as_ref(), args(&hex_sig("short", BODY)), anonymous(7, "FIN"), true, true).await.unwrap();
        assert_eq!((r["configured"].clone(), r["reason"].as_str()), (json!(false), Some("WEAK_SECRET")));
        assert!(!serde_json::to_string(&r).unwrap().contains("bits"), "the secret's size is not told");

        let (f2, _) = setup(Some(SECRET), false);
        let mut a = args(&hex_sig(SECRET, BODY));
        a["connectionName"] = json!("noSuchConnection");
        let r = run(f2.as_ref(), a, anonymous(7, "FIN"), true, true).await.unwrap();
        assert_eq!((r["configured"].clone(), r["reason"].as_str()), (json!(false), Some("NO_CONNECTION")));

        let mut a = args(&hex_sig(SECRET, BODY));
        a["secretPath"] = json!("tokenDetails.queryParams");
        let r = run(f2.as_ref(), a, anonymous(7, "FIN"), true, true).await.unwrap();
        assert_eq!(r["reason"], "NO_SECRET", "an object at the path is no secret");
    }

    #[tokio::test]
    async fn only_inside_a_server_function_and_only_for_its_own_app() {
        let (f, _) = setup(Some(SECRET), false);
        let outside = run(f.as_ref(), args(&hex_sig(SECRET, BODY)), user(110, 7, "FIN", &[]), false, true).await;
        let e = outside.unwrap_err();
        assert_eq!(e.code().map(|c| c.code.to_string()).as_deref(), Some("CORE.SERVER_FUNCTION_ONLY"));

        let mut a = args(&hex_sig(SECRET, BODY));
        a["appCode"] = json!("someotherapp");
        let e = run(f.as_ref(), a, anonymous(7, "FIN"), true, true).await.unwrap_err();
        assert_eq!(e.code().map(|c| c.code.to_string()).as_deref(), Some("CORE.CONNECTION_OTHER_APP"));

        let mut a = args(&hex_sig(SECRET, BODY));
        a["appCode"] = json!("leadzumptwo");
        let r = run(f.as_ref(), a, anonymous(7, "FIN"), true, true).await.unwrap();
        assert_eq!(r["reason"], "VALID", "its own app named explicitly is fine");
    }
}
