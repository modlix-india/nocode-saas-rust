//! `CoreServices.Security.SendContactCode` and `CoreServices.Security.VerifyContactCode` (Rust
//! only): a server function proves that the signed-in user owns an e-mail address or a phone
//! number before it trusts it (a KYC contact, a profile change).
//!
//! Both run only inside a server function, for a signed-in caller, for the URL's app and client
//! (the institution whose site the user is on). Security keeps the codes (hashed, in
//! `security_otp` under its own purpose) and the limits: one code per target every 30 seconds,
//! five an hour per user, five wrong tries per code, each code good once and only until it
//! expires (the app's OTP policy). See `crates/security/src/internal/contact.rs`.
//!
//! Delivery:
//! - an e-mail address: the app's `USER_OTP_GENERATE` event (purpose `VERIFICATION`), the same
//!   e-mail the app sends for its sign-in codes;
//! - a phone number, when `smsConnection` names a REST connection of the URL's client that has an
//!   `sms` block in its details: through that connection (the institution's own provider and
//!   sender, any country);
//! - otherwise the platform's 2Factor account, for Indian (+91) numbers only.
//!
//! The `sms` block of a connection's details (every string may hold `{phone}`, `{phoneDigits}`,
//! `{code}`, `{minutes}`, `{appName}` and `{message}`):
//!
//! ```json
//! "sms": {"method": "POST", "url": "/messages", "headers": {"Content-Type": "application/json"},
//!         "queryParams": {}, "payload": {"to": "{phone}", "text": "{message}"},
//!         "message": "{code} is your {appName} verification code. It works for {minutes} minutes."}
//! ```
//!
//! Expected refusals are answers, not errors: `sent` / `verified` is false and `reason` says why
//! (`SIGN_IN`, `INVALID`, `WAIT`, `LIMIT`, `NO_SMS`, `SEND_FAILED`; `WRONG_CODE`, `EXPIRED`,
//! `NO_CODE`, `TOO_MANY_TRIES`), with `message` in plain words. The code never comes back.

use std::sync::Arc;

use async_trait::async_trait;
use connections::connection::{self, ConnectionType};
use connections::mq::EventMessage;
use connections::rest::call::{self, CallArgs, EVENT_ERROR};
use kirun::json::schema::Schema;
use kirun::model::{Event, FunctionOutput, FunctionSignature, Parameter};
use kirun::{Map, Value};
use serde_json::{json, Map as JMap};

use super::support::{definition_context_authentication, has_user};
use super::{CoreFunction, Core};
use crate::clients::SecurityCalls;
use crate::error::CoreError;
use crate::integrations::{caller, core_error, Integrations};

const NAMESPACE: &str = "CoreServices.Security";
/// The event security's sign-in codes use; the app's action mails its template.
pub const OTP_EVENT: &str = "USER_OTP_GENERATE";
const DEFAULT_MESSAGE: &str = "{code} is your {appName} verification code. It works for {minutes} minutes. Do not share it.";
const SMS_TIMEOUT_MS: i32 = 15000;

pub fn all(security: &Arc<SecurityCalls>, integrations: &Arc<Integrations>) -> Vec<Arc<dyn kirun::function::Function>> {
    vec![
        Arc::new(Core(SendContactCode::new(security.clone(), integrations.clone()))),
        Arc::new(Core(VerifyContactCode::new(security.clone()))),
    ]
}

fn text_param(name: &str) -> (String, Parameter) {
    Parameter::of_entry(name, Schema::of_string(name).set_default_value(Value::String(String::new())), false)
}

fn arg(args: &Map<Value>, name: &str) -> String {
    match args.get(name) {
        Some(Value::String(s)) => s.trim().to_string(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

/// The caller's user and the URL's app and client, or the refusal to answer with.
fn scope(function: &str) -> Result<Result<(u64, String, String), JMap<String, Value>>, CoreError> {
    let auth = definition_context_authentication(function)?;
    let (app, client) = (auth.url_app_code().unwrap_or_default().to_string(), auth.url_client_code().unwrap_or_default().to_string());
    if !auth.is_authenticated() || !has_user(&auth) || auth.ca.user.id == 0 {
        return Ok(Err(refusal("SIGN_IN", "Please sign in to verify an e-mail address or a phone number.")));
    }
    if app.is_empty() || client.is_empty() {
        return Ok(Err(refusal("INVALID", "This page has no app or organisation to send the code for.")));
    }
    Ok(Ok((auth.ca.user.id, app, client)))
}

fn refusal(reason: &str, message: &str) -> JMap<String, Value> {
    let mut m = JMap::new();
    m.insert("reason".into(), Value::from(reason));
    m.insert("message".into(), Value::from(message));
    m
}

/// Every output key, defaulted, then `answer`'s values over them (the code is never copied).
fn shaped(keys: &[(&str, Value)], ok_key: &str, ok: bool, answer: &JMap<String, Value>) -> FunctionOutput {
    let mut m: Map<Value> = keys.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
    m.insert(ok_key.to_string(), Value::Bool(ok));
    for (k, _) in keys {
        if let Some(v) = answer.get(*k).filter(|v| !v.is_null()) {
            m.insert(k.to_string(), v.clone());
        }
    }
    m.insert(ok_key.to_string(), Value::Bool(ok));
    FunctionOutput::new(vec![kirun::model::EventResult::output_of(m)])
}

/// `{placeholder}`s of every string in `v`.
pub fn fill(v: &Value, vars: &[(&str, String)]) -> Value {
    match v {
        Value::String(s) => {
            let mut out = s.clone();
            for (k, val) in vars {
                out = out.replace(&format!("{{{k}}}"), val);
            }
            Value::String(out)
        }
        Value::Array(a) => Value::Array(a.iter().map(|x| fill(x, vars)).collect()),
        Value::Object(o) => Value::Object(o.iter().map(|(k, x)| (k.clone(), fill(x, vars))).collect()),
        other => other.clone(),
    }
}

/// The `sms` block's request for one code.
pub fn sms_call(connection_name: &str, app: &str, client: &str, sms: &JMap<String, Value>, vars: &[(&str, String)]) -> CallArgs {
    let message = fill(sms.get("message").filter(|m| m.as_str().is_some_and(|s| !s.trim().is_empty())).unwrap_or(&Value::from(DEFAULT_MESSAGE)), vars);
    let mut all: Vec<(&str, String)> = vars.to_vec();
    all.push(("message", message.as_str().unwrap_or_default().to_string()));
    let obj = |k: &str| match sms.get(k) {
        Some(Value::Object(o)) => match fill(&Value::Object(o.clone()), &all) {
            Value::Object(o) => o,
            _ => JMap::new(),
        },
        _ => JMap::new(),
    };
    let text = |k: &str, d: &str| sms.get(k).and_then(Value::as_str).filter(|s| !s.trim().is_empty()).unwrap_or(d).to_string();
    CallArgs {
        connection_name: connection_name.to_string(),
        url: fill(&Value::from(text("url", "")), &all).as_str().unwrap_or_default().to_string(),
        app_code: app.to_string(),
        client_code: client.to_string(),
        headers: obj("headers"),
        query_params: obj("queryParams"),
        path_params: JMap::new(),
        ignore_connection_headers: false,
        timeout: SMS_TIMEOUT_MS,
        method: text("method", "POST").to_uppercase(),
        payload: sms.get("payload").map(|p| fill(p, &all)),
        ..Default::default()
    }
}

// --- SendContactCode ------------------------------------------------------------------------------

pub struct SendContactCode {
    signature: FunctionSignature,
    security: Arc<SecurityCalls>,
    integrations: Arc<Integrations>,
}

const SEND_KEYS: [&str; 8] = ["sent", "reason", "message", "channel", "target", "expireMinutes", "resendAfterSeconds", "retryAfterSeconds"];

impl SendContactCode {
    pub fn new(security: Arc<SecurityCalls>, integrations: Arc<Integrations>) -> Self {
        Self {
            signature: FunctionSignature::new("SendContactCode")
                .set_namespace(NAMESPACE)
                .set_parameters(Map::from([text_param("emailId"), text_param("phoneNumber"), text_param("smsConnection")]))
                .set_events(Map::from([Event::output_event_map_entry(Map::from([
                    ("sent".to_string(), Schema::of_boolean("sent")),
                    ("reason".to_string(), Schema::of_string("reason")),
                    ("message".to_string(), Schema::of_string("message")),
                    ("channel".to_string(), Schema::of_string("channel")),
                    ("target".to_string(), Schema::of_string("target")),
                    ("expireMinutes".to_string(), Schema::of_integer("expireMinutes")),
                    ("resendAfterSeconds".to_string(), Schema::of_integer("resendAfterSeconds")),
                    ("retryAfterSeconds".to_string(), Schema::of_integer("retryAfterSeconds")),
                ]))])),
            security,
            integrations,
        }
    }

    fn out(ok: bool, answer: &JMap<String, Value>) -> FunctionOutput {
        let defaults: Vec<(&str, Value)> = SEND_KEYS
            .iter()
            .map(|k| (*k, if k.ends_with("Minutes") || k.ends_with("Seconds") { Value::from(0) } else if *k == "sent" { Value::Bool(false) } else { Value::from("") }))
            .collect();
        shaped(&defaults, "sent", ok, answer)
    }

    /// The URL client's SMS connection and its `sms` block; `Err` when the connection exists
    /// but cannot send.
    async fn sms_connection(&self, name: &str, app: &str, client: &str) -> Result<Option<JMap<String, Value>>, ()> {
        if name.is_empty() {
            return Ok(None);
        }
        let c = caller();
        let conn = match connection::read(self.integrations.connections.store.as_ref(), &c, name, app, client, ConnectionType::RestApi).await {
            Ok(Some(conn)) => conn,
            Ok(None) => return Ok(None),
            Err(e) => {
                tracing::warn!(connection = name, error = %e.message(), "SMS connection not read");
                return Ok(None);
            }
        };
        match conn.connection_details.as_ref().and_then(|d| d.get("sms")) {
            Some(Value::Object(sms)) => Ok(Some(sms.clone())),
            _ => Err(()),
        }
    }
}

#[async_trait]
impl CoreFunction for SendContactCode {
    fn signature(&self) -> &FunctionSignature {
        &self.signature
    }

    async fn internal_execute(&self, args: &Map<Value>) -> Result<FunctionOutput, CoreError> {
        let (user_id, app, client) = match scope("SendContactCode")? {
            Ok(s) => s,
            Err(r) => return Ok(Self::out(false, &r)),
        };
        let (email, phone) = (arg(args, "emailId"), arg(args, "phoneNumber"));
        let connection_name = arg(args, "smsConnection");
        let sms = if !phone.is_empty() && email.is_empty() {
            match self.sms_connection(&connection_name, &app, &client).await {
                Ok(s) => s,
                Err(()) => {
                    return Ok(Self::out(false, &refusal("SEND_FAILED", "The organisation's SMS connection has no sms settings, so no text message can be sent.")));
                }
            }
        } else {
            None
        };
        let platform_sms = !phone.is_empty() && email.is_empty() && sms.is_none();
        let body = json!({
            "appCode": app, "clientCode": client, "userId": user_id,
            "emailId": email, "phoneNumber": phone,
            "delivery": if platform_sms { "PLATFORM_SMS" } else { "RETURN" },
        });
        let Some(Value::Object(answer)) = self.security.contact_code(false, &body).await? else {
            return Err(CoreError::unknown("security gave no answer for the contact code"));
        };
        if answer.get("ok") != Some(&Value::Bool(true)) {
            return Ok(Self::out(false, &answer));
        }
        if platform_sms {
            return Ok(Self::out(true, &answer));
        }
        let code = answer.get("code").and_then(Value::as_str).unwrap_or_default().to_string();
        let minutes = answer.get("expireMinutes").and_then(Value::as_i64).unwrap_or(0);
        let app_name = answer.get("appName").and_then(Value::as_str).filter(|n| !n.is_empty()).unwrap_or(&app).to_string();
        let target = answer.get("target").and_then(Value::as_str).unwrap_or_default().to_string();
        let c = caller();
        let sent = if let Some(sms) = sms {
            let vars = [
                ("phone", target.clone()),
                ("phoneDigits", target.trim_start_matches('+').to_string()),
                ("code", code),
                ("minutes", minutes.to_string()),
                ("appName", app_name),
            ];
            let req = sms_call(&connection_name, &app, &client, &sms, &vars);
            let events = call::call(&self.integrations.connections, &c, &req, None).await.map_err(core_error)?;
            let failed = events.as_ref().is_none_or(|ev| ev.iter().any(|e| e.name == EVENT_ERROR));
            if failed {
                let status = events.as_ref().and_then(|ev| ev.iter().find(|e| e.name == EVENT_ERROR)).and_then(|e| e.result.get("statusCode").cloned());
                tracing::warn!(connection = connection_name.as_str(), status = ?status, "contact code SMS refused by the connection");
            }
            !failed
        } else {
            let mut data = JMap::new();
            data.insert("appName".into(), Value::from(app_name));
            data.insert("email".into(), Value::from(target));
            data.insert("otp".into(), Value::from(code));
            data.insert("otpPurpose".into(), Value::from("VERIFICATION"));
            data.insert("expireInterval".into(), Value::from(minutes));
            let event = EventMessage {
                event_name: Some(OTP_EVENT.into()),
                client_code: Some(client.clone()),
                app_code: Some(app.clone()),
                data: Some(data),
                ..Default::default()
            };
            self.integrations.mq.create_event(&c, event).await?
        };
        if !sent {
            let mut r = refusal("SEND_FAILED", "We could not send the code. Please try again in a few minutes.");
            r.insert("channel".into(), answer.get("channel").cloned().unwrap_or(Value::Null));
            r.insert("target".into(), answer.get("target").cloned().unwrap_or(Value::Null));
            return Ok(Self::out(false, &r));
        }
        Ok(Self::out(true, &answer))
    }
}

// --- VerifyContactCode ----------------------------------------------------------------------------

pub struct VerifyContactCode {
    signature: FunctionSignature,
    security: Arc<SecurityCalls>,
}

impl VerifyContactCode {
    pub fn new(security: Arc<SecurityCalls>) -> Self {
        Self {
            signature: FunctionSignature::new("VerifyContactCode")
                .set_namespace(NAMESPACE)
                .set_parameters(Map::from([text_param("emailId"), text_param("phoneNumber"), text_param("code")]))
                .set_events(Map::from([Event::output_event_map_entry(Map::from([
                    ("verified".to_string(), Schema::of_boolean("verified")),
                    ("reason".to_string(), Schema::of_string("reason")),
                    ("message".to_string(), Schema::of_string("message")),
                    ("channel".to_string(), Schema::of_string("channel")),
                    ("target".to_string(), Schema::of_string("target")),
                    ("triesLeft".to_string(), Schema::of_integer("triesLeft")),
                ]))])),
            security,
        }
    }

    fn out(ok: bool, answer: &JMap<String, Value>) -> FunctionOutput {
        let defaults = [
            ("verified", Value::Bool(false)),
            ("reason", Value::from("")),
            ("message", Value::from("")),
            ("channel", Value::from("")),
            ("target", Value::from("")),
            ("triesLeft", Value::from(0)),
        ];
        shaped(&defaults, "verified", ok, answer)
    }
}

#[async_trait]
impl CoreFunction for VerifyContactCode {
    fn signature(&self) -> &FunctionSignature {
        &self.signature
    }

    async fn internal_execute(&self, args: &Map<Value>) -> Result<FunctionOutput, CoreError> {
        let (user_id, app, client) = match scope("VerifyContactCode")? {
            Ok(s) => s,
            Err(r) => return Ok(Self::out(false, &r)),
        };
        let body = json!({
            "appCode": app, "clientCode": client, "userId": user_id,
            "emailId": arg(args, "emailId"), "phoneNumber": arg(args, "phoneNumber"), "code": arg(args, "code"),
        });
        let Some(Value::Object(answer)) = self.security.contact_code(true, &body).await? else {
            return Err(CoreError::unknown("security gave no answer for the contact code"));
        };
        let ok = answer.get("ok") == Some(&Value::Bool(true));
        Ok(Self::out(ok, &answer))
    }
}
