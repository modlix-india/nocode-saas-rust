//! `CoreServices.Messaging.SendSms` (Rust only): a server function sends one text message
//! through the company's own SMS provider, from one of the company's SMS templates. Never free
//! text: the words come only from a core template of `templateType` `sms`, so only text the
//! company has registered (India: on the DLT portal) goes out.
//!
//! - The provider is a REST connection of the company with an `sms` block in its details, the
//!   same block `SendContactCode` uses ([`super::contact_codes::sms_call`]). Its strings may
//!   hold `{phone}`, `{phoneDigits}`, `{message}`, `{senderId}`, `{dltTemplateId}`,
//!   `{dltEntityId}`, `{unicode}` (`1` / `0`), `{encoding}` (`unicode` / `text`), `{msgType}`
//!   (`UNICODE_TEXT` / `TEXT`), `{templateName}`, `{account}` (`sms.account`: a user id or account
//!   SID, not secret) and every text in the details' `credentials` block by its own name (`{key}`,
//!   `{apiKey}`, `{authToken}`, ...; the block is secret, so core never reads it back), plus
//!   `{basicAuth}` (base64 of `account:<key, authToken, password or apiKey>`, else
//!   `accountSid:authToken`, else `username:password`).
//!   `sms.enabled: false` switches the provider off; `sms.senderId` / `sms.dltEntityId` are the
//!   company's defaults; `sms.errorWhen {field, equals}` names a reply field that says the
//!   provider refused it although the status is 2xx (MSG91 and Gupshup answer 200 with an error).
//! - The template (`TemplateService.read(name, app, client)`: the company's copy, else the one it
//!   inherits) holds the text in `templateParts.<language>.body` (FreeMarker, the same merge
//!   fields as mail templates) and an `sms` block in its `design` map (core keeps only the
//!   template's known fields; `design` is free): `status` (`DRAFT`, `WAITING`, `ACTIVE`),
//!   `dltTemplateId`, `senderId`, `language`, `registeredText` (the DLT text at registration).
//!   It sends only when `ACTIVE`; to an Indian number (+91) only with a DLT template id, and
//!   only while the text still matches `registeredText` when one is kept (the operator rejects
//!   any other text).
//! - At most [`COMPANY_PER_HOUR`] messages an hour per company and [`PHONE_PER_HOUR`] to one
//!   number per company, per core instance.
//!
//! Expected refusals are answers, not errors: `sent` false and `reason` says why: `INVALID`
//! (no company, no number or a number without its country code), `NO_SMS` (no provider set up
//! or switched off), `NOT_ACTIVE` (no such SMS template, or not active, or no DLT id for +91, or
//! changed after registration), `LIMIT`, `SEND_FAILED` (the provider refused or could not be
//! reached), with `message` in plain words. Outside a server function the call fails.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::Engine as _;
use connections::connection::{self, ConnectionType};
use connections::rest::call::{self, EVENT_ERROR};
use kirun::json::schema::Schema;
use kirun::model::{Event, EventResult, FunctionOutput, FunctionSignature, Parameter};
use kirun::{Map, Value};
use parking_lot::Mutex;
use serde_json::Map as JMap;

use super::contact_codes::sms_call;
use super::support::server_function_only;
use super::{CoreFunction, Core};
use crate::context;
use crate::error::CoreError;
use crate::integrations::{caller, json_of, Integrations};

const NAMESPACE: &str = "CoreServices.Messaging";
pub const COMPANY_PER_HOUR: usize = 300;
pub const PHONE_PER_HOUR: usize = 10;
const HOUR: Duration = Duration::from_secs(3600);
const REPLY_TEXT_MAX: usize = 200;

pub fn all(integrations: &Arc<Integrations>) -> Vec<Arc<dyn kirun::function::Function>> {
    vec![Arc::new(Core(SendSms::new(integrations.clone())))]
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

/// `+` and digits of a phone number written with spaces, dashes, dots or brackets; `00` is
/// read as `+`. `None` without a country code or with too few or too many digits.
pub fn international(phone: &str) -> Option<String> {
    let kept: String = phone.chars().filter(|c| !matches!(c, ' ' | '-' | '.' | '(' | ')' | '\u{a0}')).collect();
    let digits = if let Some(d) = kept.strip_prefix('+') {
        d.to_string()
    } else if let Some(d) = kept.strip_prefix("00") {
        d.to_string()
    } else {
        return None;
    };
    if digits.len() < 8 || digits.len() > 15 || !digits.chars().all(|c| c.is_ascii_digit()) || digits.starts_with('0') {
        return None;
    }
    Some(format!("+{digits}"))
}

/// The text as it is registered on India's DLT portal: every `${...}` merge field becomes a
/// variable, `{#url#}` for a field named like a link (`link`, `url`), else `{#var#}`.
pub fn dlt_text(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut rest = body;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        // The matching `}` (a merge field may hold `{...}` itself, e.g. a default `!{}`).
        let mut depth = 1usize;
        let mut end = None;
        for (i, ch) in after.char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(end) = end else {
            out.push_str(&rest[start..]);
            return out;
        };
        let field = after[..end].to_ascii_lowercase();
        out.push_str(if field.contains("link") || field.contains("url") { "{#url#}" } else { "{#var#}" });
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

/// Whether a text needs Unicode (UCS-2) messages: anything outside the GSM 7-bit alphabet.
pub fn needs_unicode(text: &str) -> bool {
    const GSM: &str = "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà";
    const GSM_EXT: &str = "^{}\\[~]|€\x0c";
    text.chars().any(|c| !GSM.contains(c) && !GSM_EXT.contains(c))
}

/// Characters as the operator counts them and how many SMS parts the text takes: 160 a single
/// plain message (153 a part when split; `^{}\[~]|€` count two), 70 with Unicode (67 a part).
pub fn sms_parts(text: &str) -> (usize, usize) {
    if needs_unicode(text) {
        let n = text.encode_utf16().count();
        (n, if n <= 70 { 1 } else { n.div_ceil(67) })
    } else {
        let n: usize = text.chars().map(|c| if "^{}\\[~]|€\x0c".contains(c) { 2 } else { 1 }).sum();
        (n, if n <= 160 { 1 } else { n.div_ceil(153) })
    }
}

fn refusal(reason: &str, message: impl Into<String>) -> JMap<String, Value> {
    let mut m = JMap::new();
    m.insert("reason".into(), Value::from(reason));
    m.insert("message".into(), Value::from(message.into()));
    m
}

const OUT_KEYS: [&str; 7] = ["sent", "reason", "message", "target", "text", "characters", "parts"];

fn out(sent: bool, answer: &JMap<String, Value>) -> FunctionOutput {
    let mut m: Map<Value> = Map::new();
    for k in OUT_KEYS {
        let default = match k {
            "sent" => Value::Bool(false),
            "characters" | "parts" => Value::from(0),
            _ => Value::from(""),
        };
        m.insert(k.to_string(), answer.get(k).filter(|v| !v.is_null()).cloned().unwrap_or(default));
    }
    m.insert("sent".into(), Value::Bool(sent));
    FunctionOutput::new(vec![EventResult::output_of(m)])
}

/// Sends in the last hour, per company and per company and number.
#[derive(Default)]
pub struct Limits {
    seen: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl Limits {
    /// Counts one send for `client` to `phone` unless either is over its limit.
    pub fn take(&self, client: &str, phone: &str, now: Instant) -> bool {
        let mut seen = self.seen.lock();
        let keys = [(format!("c:{client}"), COMPANY_PER_HOUR), (format!("p:{client}:{phone}"), PHONE_PER_HOUR)];
        for (k, limit) in &keys {
            let q = seen.entry(k.clone()).or_default();
            while q.front().is_some_and(|t| now.duration_since(*t) >= HOUR) {
                q.pop_front();
            }
            if q.len() >= *limit {
                return false;
            }
        }
        for (k, _) in keys {
            seen.entry(k).or_default().push_back(now);
        }
        // Forget numbers not texted for an hour.
        seen.retain(|_, q| q.back().is_some_and(|t| now.duration_since(*t) < HOUR));
        true
    }
}

pub struct SendSms {
    signature: FunctionSignature,
    integrations: Arc<Integrations>,
    limits: Limits,
}

impl SendSms {
    pub fn new(integrations: Arc<Integrations>) -> Self {
        Self {
            signature: FunctionSignature::new("SendSms")
                .set_namespace(NAMESPACE)
                .set_parameters(Map::from([
                    text_param("appCode"),
                    text_param("clientCode"),
                    text_param("connectionName"),
                    text_param("phone"),
                    text_param("templateName"),
                    Parameter::of_entry("vars", Schema::of_object("vars").set_default_value(Value::Object(JMap::new())), false),
                ]))
                .set_events(Map::from([Event::output_event_map_entry(Map::from([
                    ("sent".to_string(), Schema::of_boolean("sent")),
                    ("reason".to_string(), Schema::of_string("reason")),
                    ("message".to_string(), Schema::of_string("message")),
                    ("target".to_string(), Schema::of_string("target")),
                    ("text".to_string(), Schema::of_string("text")),
                    ("characters".to_string(), Schema::of_integer("characters")),
                    ("parts".to_string(), Schema::of_integer("parts")),
                ]))])),
            integrations,
            limits: Limits::default(),
        }
    }

    /// The template as plain JSON, `None` when there is none (or it cannot be read).
    async fn template(&self, name: &str, app: &str, client: &str) -> Option<Value> {
        match self.integrations.templates.source.template(name, app, client).await {
            Ok(Some(doc)) => json_of(&doc).ok(),
            Ok(None) => None,
            Err(e) => {
                tracing::warn!(template = name, error = %e, "SMS template not read");
                None
            }
        }
    }
}

fn s<'a>(v: Option<&'a Value>) -> &'a str {
    v.and_then(Value::as_str).map(str::trim).unwrap_or("")
}

/// The text part of the template for `language` (else `en`, else the first set).
fn body_of(tmpl: &Value, language: &str) -> String {
    let Some(parts) = tmpl.get("templateParts").and_then(Value::as_object) else { return String::new() };
    let set = parts
        .get(language)
        .or_else(|| parts.iter().find(|(k, _)| k.eq_ignore_ascii_case(language)).map(|(_, v)| v))
        .or_else(|| parts.get("en"))
        .or_else(|| parts.values().next());
    s(set.and_then(|p| p.get("body"))).to_string()
}

/// The reply says the provider refused it: `errorWhen {field, equals}` matched (a dotted path).
fn reply_refused(sms: &JMap<String, Value>, reply: Option<&Value>) -> bool {
    let Some(rule) = sms.get("errorWhen").and_then(Value::as_object) else { return false };
    let field = s(rule.get("field"));
    let Some(equals) = rule.get("equals") else { return false };
    if field.is_empty() {
        return false;
    }
    let mut v = match reply {
        Some(Value::String(t)) => match serde_json::from_str::<Value>(t) {
            Ok(parsed) => parsed,
            Err(_) => return false,
        },
        Some(v) => v.clone(),
        None => return false,
    };
    for part in field.split('.') {
        match v.get(part) {
            Some(next) => v = next.clone(),
            None => return false,
        }
    }
    match (&v, equals) {
        (Value::String(a), Value::String(b)) => a.eq_ignore_ascii_case(b),
        (a, b) => a == b,
    }
}

fn short_reply(v: Option<&Value>) -> String {
    let text = match v {
        Some(Value::String(t)) => t.clone(),
        Some(Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    };
    let t: String = text.chars().filter(|c| !c.is_control()).take(REPLY_TEXT_MAX).collect();
    t.trim().to_string()
}

#[async_trait]
impl CoreFunction for SendSms {
    fn signature(&self) -> &FunctionSignature {
        &self.signature
    }

    async fn internal_execute(&self, args: &Map<Value>) -> Result<FunctionOutput, CoreError> {
        if !context::in_kirun() {
            return Err(server_function_only(&format!("{NAMESPACE}.SendSms")));
        }
        let c = caller();
        let pick = |given: String, url: Option<&String>| if given.is_empty() { url.cloned().unwrap_or_default() } else { given };
        let app = pick(arg(args, "appCode"), c.url_app_code.as_ref());
        let client = pick(arg(args, "clientCode"), c.url_client_code.as_ref());
        if app.is_empty() || client.is_empty() {
            return Ok(out(false, &refusal("INVALID", "There is no app or company to send the text message for.")));
        }
        let Some(phone) = international(&arg(args, "phone")) else {
            return Ok(out(false, &refusal("INVALID", "The phone number needs its country code, like +91 98450 12345.")));
        };
        let mut base = refusal("", "");
        base.insert("target".into(), Value::from(phone.as_str()));
        fn refused(base: &JMap<String, Value>, reason: &str, message: String) -> Result<FunctionOutput, CoreError> {
            let mut r = base.clone();
            r.extend(refusal(reason, message));
            Ok(out(false, &r))
        }

        // The company's provider.
        let connection_name = arg(args, "connectionName");
        let no_sms = "Text messages are not set up for this company.".to_string();
        if connection_name.is_empty() {
            return refused(&base, "NO_SMS", no_sms);
        }
        let conn = match connection::read(self.integrations.connections.store.as_ref(), &c, &connection_name, &app, &client, ConnectionType::RestApi).await {
            Ok(Some(conn)) => conn,
            Ok(None) => return refused(&base, "NO_SMS", no_sms),
            Err(e) => {
                tracing::warn!(connection = connection_name.as_str(), error = %e.message(), "SMS connection not read");
                return refused(&base, "NO_SMS", no_sms);
            }
        };
        let details = conn.connection_details.clone().unwrap_or_default();
        let Some(Value::Object(sms)) = details.get("sms").cloned() else {
            return refused(&base, "NO_SMS", no_sms);
        };
        if sms.get("enabled") == Some(&Value::Bool(false)) {
            return refused(&base, "NO_SMS", "Text messages are switched off for this company.".into());
        }

        // The template: active, registered, unchanged.
        let template_name = arg(args, "templateName");
        let tmpl = if template_name.is_empty() { None } else { self.template(&template_name, &app, &client).await };
        let Some(tmpl) = tmpl.filter(|t| s(t.get("templateType")).eq_ignore_ascii_case("sms")) else {
            return refused(&base, "NOT_ACTIVE", format!("There is no text message template named {template_name}."));
        };
        // core keeps a template's own settings in its `design` map; `sms` at the top is read too.
        let meta = tmpl.get("design").and_then(|d| d.get("sms")).or_else(|| tmpl.get("sms")).cloned().unwrap_or(Value::Object(JMap::new()));
        if !s(meta.get("status")).eq_ignore_ascii_case("ACTIVE") {
            return refused(&base, "NOT_ACTIVE", "This text message template is not active yet.".into());
        }
        let language = {
            let l = s(meta.get("language"));
            if l.is_empty() { s(tmpl.get("defaultLanguage")).to_string() } else { l.to_string() }
        };
        let body = body_of(&tmpl, if language.is_empty() { "en" } else { &language });
        if body.is_empty() {
            return refused(&base, "NOT_ACTIVE", "This text message template has no text.".into());
        }
        let dlt_template_id = s(meta.get("dltTemplateId")).to_string();
        let registered = s(meta.get("registeredText"));
        if phone.starts_with("+91") {
            if dlt_template_id.is_empty() {
                return refused(&base, "NOT_ACTIVE", "An Indian number needs the template's DLT template id first.".into());
            }
            if !registered.is_empty() && registered != dlt_text(&body).trim() {
                return refused(&base, "NOT_ACTIVE", "The text was changed after it was registered on DLT. Register the new text first.".into());
            }
        }

        // The words.
        let data = match args.get("vars") {
            Some(Value::Object(m)) => m.clone(),
            _ => JMap::new(),
        };
        let text = match connections::template::process(&template_name, Some(&body), &data) {
            Ok(t) => t.trim().to_string(),
            Err(e) => return refused(&base, "NOT_ACTIVE", format!("The text message could not be filled in: {}", e.message())),
        };
        if text.is_empty() {
            return refused(&base, "NOT_ACTIVE", "The text message came out empty.".into());
        }
        let (characters, parts) = sms_parts(&text);
        base.insert("text".into(), Value::from(text.as_str()));
        base.insert("characters".into(), Value::from(characters));
        base.insert("parts".into(), Value::from(parts));

        if !self.limits.take(&client, &phone, Instant::now()) {
            return refused(&base, "LIMIT", "Too many text messages in the last hour. Please try again later.".into());
        }

        // The provider's request.
        let unicode = needs_unicode(&text);
        let sender = {
            let t = s(meta.get("senderId"));
            if t.is_empty() { s(sms.get("senderId")).to_string() } else { t.to_string() }
        };
        let mut vars: Vec<(String, String)> = Vec::new();
        let account = s(sms.get("account")).to_string();
        if let Some(Value::Object(creds)) = details.get("credentials") {
            for (k, v) in creds {
                if let Some(t) = v.as_str() {
                    vars.push((k.clone(), t.to_string()));
                }
            }
            let text = |k: &str| creds.get(k).and_then(Value::as_str).filter(|t| !t.is_empty());
            let pair = |a: Option<&str>, b: Option<&str>| match (a, b) {
                (Some(x), Some(y)) if !x.is_empty() && !y.is_empty() => Some(format!("{x}:{y}")),
                _ => None,
            };
            let secret = text("key").or(text("authToken")).or(text("password")).or(text("apiKey"));
            let basic = pair(Some(account.as_str()), secret)
                .or_else(|| pair(text("accountSid"), text("authToken")))
                .or_else(|| pair(text("username"), text("password")));
            if let Some(p) = basic {
                vars.push(("basicAuth".into(), base64::engine::general_purpose::STANDARD.encode(p)));
            }
        }
        vars.push(("account".into(), account));
        vars.extend([
            ("phone".to_string(), phone.clone()),
            ("phoneDigits".to_string(), phone.trim_start_matches('+').to_string()),
            ("senderId".to_string(), sender),
            ("dltTemplateId".to_string(), dlt_template_id),
            ("dltEntityId".to_string(), s(sms.get("dltEntityId")).to_string()),
            ("unicode".to_string(), if unicode { "1" } else { "0" }.to_string()),
            ("encoding".to_string(), if unicode { "unicode" } else { "text" }.to_string()),
            ("msgType".to_string(), if unicode { "UNICODE_TEXT" } else { "TEXT" }.to_string()),
            ("templateName".to_string(), template_name.clone()),
            // Last, so nothing is replaced inside the message's own words.
            ("smsText".to_string(), text.clone()),
        ]);
        let mut block = sms.clone();
        block.insert("message".into(), Value::from("{smsText}"));
        let refs: Vec<(&str, String)> = vars.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
        let req = sms_call(&connection_name, &app, &client, &block, &refs);
        let events = match call::call(&self.integrations.connections, &c, &req, None).await {
            Ok(ev) => ev,
            Err(e) => {
                tracing::warn!(connection = connection_name.as_str(), error = %e.message(), "SMS not sent");
                return refused(&base, "SEND_FAILED", "The text message provider could not be reached. Please check the provider settings.".into());
            }
        };
        let failed = events.as_ref().and_then(|ev| ev.iter().find(|e| e.name == EVENT_ERROR));
        if let Some(e) = failed {
            let status = e.result.get("statusCode").and_then(Value::as_i64).unwrap_or(0);
            let reply = short_reply(e.result.get("data"));
            tracing::warn!(connection = connection_name.as_str(), status, "SMS refused by the provider");
            let mut m = format!("The text message provider refused the message (status {status})");
            if !reply.is_empty() {
                m.push_str(&format!(": {reply}"));
            }
            return refused(&base, "SEND_FAILED", m);
        }
        let reply = events.as_ref().and_then(|ev| ev.first()).and_then(|e| e.result.get("data")).cloned();
        if events.is_none() || reply_refused(&sms, reply.as_ref()) {
            let r = short_reply(reply.as_ref());
            return refused(&base, "SEND_FAILED", if r.is_empty() { "The text message provider refused the message.".into() } else { format!("The text message provider refused the message: {r}") });
        }
        let mut ok = base.clone();
        ok.insert("reason".into(), Value::from(""));
        ok.insert("message".into(), Value::from(format!("Text message sent to {phone}.")));
        Ok(out(true, &ok))
    }
}
