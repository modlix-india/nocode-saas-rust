//! Rust only: `CoreServices.Billing`, what an app's own functions use to bill what it sells.
//!
//! - `RecordUsage(meterKey, quantity, figures, reference)`: one use of a meter of the app's
//!   billing config (a lead created, a booking made). Security charges the client's wallet or
//!   keeps the use for the monthly invoice; past a plan's hard cap nothing is recorded and
//!   `overLimit` is true (the app keeps the record and shows it after an upgrade).
//! - `ReverseUsage(meterKey, reference)`: the use undone (a booking cancelled) within the meter's
//!   refund window.
//! - `Allowed(meterKey, model, count)`: may the client do it now (a plan's cap, a suspended
//!   wallet, a model the plan does not include). `count` is the app's own current count, for a
//!   cap on a storage's rows (one project, one ad account), which security cannot count.
//!
//! The client billed is the signed-in user's, or for an anonymous caller (a public form) the
//! URL's; the app is the URL's. Neither is a parameter, so a function cannot bill someone else.

use std::sync::Arc;

use async_trait::async_trait;
use kirun::function::Function;
use kirun::model::FunctionOutput;
use kirun::{Map as KMap, Value};
use serde_json::json;

use super::arg_string;
use super::support::{definition_context_authentication, output_map, required_argument, Java, JavaFunction};
use crate::auth::Authentication;
use crate::clients::SecurityCalls;
use crate::error::CoreError;

pub fn all(security: &Arc<SecurityCalls>) -> Vec<Arc<dyn Function>> {
    vec![
        Java::function(RecordUsage(security.clone())),
        Java::function(ReverseUsage(security.clone())),
        Java::function(Allowed(security.clone())),
    ]
}

fn optional(args: &KMap<Value>, name: &str) -> Result<Option<String>, CoreError> {
    match args.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => Ok(Some(arg_string(args, name)?.trim().to_string()).filter(|s| !s.is_empty())),
    }
}

/// The (app, client) a function bills: the URL's app; the signed-in user's client, else the URL's.
pub fn billed(ca: &Authentication) -> Option<(String, String)> {
    let app = ca.url_app_code()?.to_string();
    let client = if ca.is_authenticated() { ca.client_code().or(ca.url_client_code()) } else { ca.url_client_code() };
    Some((app, client?.to_string()))
}

fn meter_key(args: &KMap<Value>) -> Result<String, CoreError> {
    optional(args, "meterKey")?.ok_or_else(|| required_argument("meterKey"))
}

fn as_bool(v: &serde_json::Value, k: &str) -> Value {
    Value::Bool(v.get(k).and_then(serde_json::Value::as_bool).unwrap_or(false))
}

pub struct RecordUsage(Arc<SecurityCalls>);

#[async_trait]
impl JavaFunction for RecordUsage {
    fn full_name(&self) -> &'static str {
        "CoreServices.Billing.RecordUsage"
    }

    async fn run(&self, args: &KMap<Value>) -> Result<FunctionOutput, CoreError> {
        let key = meter_key(args)?;
        let ca = definition_context_authentication("RecordUsage")?;
        let Some((app, client)) = billed(&ca) else {
            return Ok(output_map([("recorded", Value::Bool(false)), ("overLimit", Value::Bool(false)), ("charged", Value::from(0))]));
        };
        let figures = match args.get("figures") {
            Some(Value::Object(m)) => Value::Object(m.clone()),
            _ => json!({}),
        };
        let mut body = json!({"clientCode": client, "appCode": app, "meterKey": key, "figures": figures, "reference": optional(args, "reference")?});
        if let Some(q) = args.get("quantity").filter(|q| !q.is_null()) {
            body["quantity"] = q.clone();
        }
        let r = self.0.billing_record(&body).await?.unwrap_or_else(|| json!({}));
        Ok(output_map([
            ("recorded", as_bool(&r, "recorded")),
            ("overLimit", as_bool(&r, "overLimit")),
            ("charged", r.get("charged").cloned().unwrap_or(Value::from(0))),
            ("suspended", as_bool(&r, "suspended")),
        ]))
    }
}

pub struct ReverseUsage(Arc<SecurityCalls>);

#[async_trait]
impl JavaFunction for ReverseUsage {
    fn full_name(&self) -> &'static str {
        "CoreServices.Billing.ReverseUsage"
    }

    async fn run(&self, args: &KMap<Value>) -> Result<FunctionOutput, CoreError> {
        let key = meter_key(args)?;
        let reference = optional(args, "reference")?.ok_or_else(|| required_argument("reference"))?;
        let ca = definition_context_authentication("ReverseUsage")?;
        let Some((app, client)) = billed(&ca) else {
            return Ok(output_map([("reversed", Value::Bool(false)), ("reason", Value::from("no app or client"))]));
        };
        let body = json!({"clientCode": client, "appCode": app, "meterKey": key, "reference": reference});
        let r = self.0.billing_reverse(&body).await?.unwrap_or_else(|| json!({}));
        Ok(output_map([("reversed", as_bool(&r, "reversed")), ("reason", r.get("reason").cloned().unwrap_or(Value::Null))]))
    }
}

pub struct Allowed(Arc<SecurityCalls>);

#[async_trait]
impl JavaFunction for Allowed {
    fn full_name(&self) -> &'static str {
        "CoreServices.Billing.Allowed"
    }

    async fn run(&self, args: &KMap<Value>) -> Result<FunctionOutput, CoreError> {
        let key = optional(args, "meterKey")?;
        let model = optional(args, "model")?;
        let count = match args.get("count") {
            // -1 (the default) is "not given".
            Some(Value::Number(n)) if n.as_f64().is_some_and(|f| f >= 0.0) => Some(n.to_string()),
            _ => None,
        };
        let ca = definition_context_authentication("Allowed")?;
        let Some((app, client)) = billed(&ca) else {
            return Ok(output_map([("allowed", Value::Bool(true)), ("reason", Value::Null)]));
        };
        let r = self.0.billing_allowed(&app, &client, key.as_deref(), model.as_deref(), count).await?.unwrap_or_else(|| json!({"allowed": true}));
        let allowed = r.get("allowed").and_then(serde_json::Value::as_bool).unwrap_or(true);
        Ok(output_map([("allowed", Value::Bool(allowed)), ("reason", r.get("reason").cloned().unwrap_or(Value::Null))]))
    }
}
