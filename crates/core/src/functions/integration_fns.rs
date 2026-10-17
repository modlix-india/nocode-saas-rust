//! The core functions over `crates/connections` and the publishers: `CoreServices.REST.*`
//! (`CallRequest` and its five method-fixed forms), `CoreServices.Email.SendEmail`,
//! `CoreServices.AI.Chat`, `CoreServices.Notification.SendNotification` and
//! `CoreServices.Event.CreateEvent`.
//!
//! Each reads its arguments as the Java class does, then hands the work to the library with
//! the caller from the request context. Like the Java classes, all but the REST ones ask
//! `ContextView.get(DefinitionFunction.CONTEXT_KEY)`, which fails outside a definition.

use std::sync::Arc;

use async_trait::async_trait;
use connections::ai::{chat_function, ChatOutcome};
use connections::email::{send_email_function, EmailContext};
use connections::mq::{jackson_authentication, EventMessage};
use connections::notification::NotificationRequest;
use connections::rest::call::{self, CallArgs};
use kirun::function::Function;
use kirun::model::{EventResult, FunctionOutput};
use kirun::{Map as KMap, Value};
use serde_json::Map;

use super::arg_string;
use super::support::{empty_result, output_map, require_context_key, Java, JavaFunction};
use crate::error::CoreError;
use crate::integrations::{caller, core_error, Integrations};
use crate::storage::defs::Catalog;

/// `makeRESTFunctions`, `makeEmailFunctions` and `makeCreateEventFunction`'s functions, and the
/// notification and AI ones, each list in Java's order.
pub fn rest(integrations: &Arc<Integrations>) -> Vec<Arc<dyn Function>> {
    [
        ("CoreServices.REST.GetRequest", "GET"),
        ("CoreServices.REST.PostRequest", "POST"),
        ("CoreServices.REST.PutRequest", "PUT"),
        ("CoreServices.REST.PatchRequest", "PATCH"),
        ("CoreServices.REST.DeleteRequest", "DELETE"),
        ("CoreServices.REST.CallRequest", ""),
    ]
    .into_iter()
    .map(|(full, method)| Java::function(CallRequest { full, method, integrations: integrations.clone() }))
    .collect()
}

pub fn email(integrations: &Arc<Integrations>) -> Vec<Arc<dyn Function>> {
    vec![Java::function(SendEmail(integrations.clone()))]
}

pub fn create_event(integrations: &Arc<Integrations>, defs: &Arc<dyn Catalog>) -> Vec<Arc<dyn Function>> {
    vec![Java::function(CreateEvent { integrations: integrations.clone(), defs: defs.clone() })]
}

pub fn notification(integrations: &Arc<Integrations>) -> Vec<Arc<dyn Function>> {
    vec![Java::function(SendNotification(integrations.clone()))]
}

pub fn ai(integrations: &Arc<Integrations>) -> Vec<Arc<dyn Function>> {
    vec![Java::function(Chat(integrations.clone()))]
}

fn object(args: &KMap<Value>, name: &str) -> Result<Map<String, Value>, CoreError> {
    match args.get(name) {
        Some(Value::Object(o)) => Ok(o.clone()),
        Some(other) => Err(CoreError::unknown(format!("Not a JSON Object: {}", crate::gson::element_to_string(other)))),
        None => Err(CoreError::unknown(format!(
            "Cannot invoke \"com.google.gson.JsonElement.getAsJsonObject()\" because the return value of \"java.util.Map.get(Object)\" is null ({name})"
        ))),
    }
}

/// `getAsInt()` / `getAsBoolean()` of a validated argument.
fn int(args: &KMap<Value>, name: &str) -> Result<i32, CoreError> {
    match args.get(name) {
        Some(Value::Number(n)) => Ok(n.as_i64().map(|i| i as i32).or_else(|| n.as_f64().map(|f| f as i32)).unwrap_or(0)),
        Some(Value::String(s)) => s.trim().parse().map_err(|_| CoreError::unknown(format!("For input string: \"{s}\""))),
        _ => Err(CoreError::unknown(format!("{name} is not a number"))),
    }
}

fn boolean(args: &KMap<Value>, name: &str) -> bool {
    match args.get(name) {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s.eq_ignore_ascii_case("true"),
        _ => false,
    }
}

// --- CoreServices.REST -------------------------------------------------------------------------

pub struct CallRequest {
    full: &'static str,
    /// Empty for `CallRequest`, which takes the method as an argument.
    method: &'static str,
    integrations: Arc<Integrations>,
}

#[async_trait]
impl JavaFunction for CallRequest {
    fn full_name(&self) -> &'static str {
        self.full
    }

    async fn run(&self, args: &KMap<Value>) -> Result<FunctionOutput, CoreError> {
        let app_code = arg_string(args, "appCode")?;
        let payload = args.get("payload").cloned();
        let client_code = arg_string(args, "clientCode")?;
        let url = arg_string(args, "url")?;
        let method = if self.method.is_empty() { arg_string(args, "methodName")? } else { self.method.to_string() };
        let connection_name = arg_string(args, "connectionName")?;
        let timeout = int(args, "timeout")?;
        let download = boolean(args, "downloadAsAFile");
        let headers = object(args, "headers")?;
        let path_params = object(args, "pathParams")?;
        let query_params = object(args, "queryParams")?;
        let ignore = boolean(args, "ignoreConnectionHeaders");
        let file = |n: &str| if download { arg_string(args, n) } else { Ok(String::new()) };
        let call_args = CallArgs {
            connection_name,
            url,
            app_code,
            client_code,
            headers,
            query_params,
            path_params,
            ignore_connection_headers: ignore,
            timeout,
            method,
            payload,
            download_as_a_file: download,
            file_name: file("fileName")?,
            file_location: file("fileLocation")?,
            file_client_code: file("fileClientCode")?,
            file_type: file("fileType")?,
            file_override: download && boolean(args, "fileOverride"),
        };
        let downloads = self.integrations.downloads.as_deref().map(|d| d as &dyn call::DownloadSink);
        let events = call::call(&self.integrations.connections, &caller(), &call_args, downloads).await.map_err(core_error)?;
        match events {
            Some(events) => Ok(FunctionOutput::new(
                events.into_iter().map(|e| EventResult::of(e.name, e.result.into_iter().collect())).collect(),
            )),
            None => Err(empty_result(self.full)),
        }
    }
}

// --- CoreServices.Email.SendEmail ----------------------------------------------------------------

pub struct SendEmail(Arc<Integrations>);

#[async_trait]
impl JavaFunction for SendEmail {
    fn full_name(&self) -> &'static str {
        "CoreServices.Email.SendEmail"
    }

    async fn run(&self, args: &KMap<Value>) -> Result<FunctionOutput, CoreError> {
        let app_code = arg_string(args, "appCode")?;
        let client_code = arg_string(args, "clientCode")?;
        let connection_name = arg_string(args, "connectionName")?;
        let template_name = arg_string(args, "templateName")?;
        let data = object(args, "templateData")?;
        require_context_key()?;
        let i = &self.0;
        let ctx = EmailContext {
            connections: i.connection_docs.as_ref(),
            templates: i.templates.as_ref(),
            http: &i.connections.provider_http,
            sendgrid_url: &i.connections.config.sendgrid_url,
        };
        let sent = send_email_function(&ctx, &caller(), &app_code, &client_code, Some(&connection_name), &template_name, args.get("address"), &data)
            .await
            .map_err(core_error)?;
        match sent {
            Some(b) => Ok(output_map([("sent", Value::Bool(b))])),
            None => Err(empty_result(self.full_name())),
        }
    }
}

// --- CoreServices.AI.Chat --------------------------------------------------------------------------

pub struct Chat(Arc<Integrations>);

#[async_trait]
impl JavaFunction for Chat {
    fn full_name(&self) -> &'static str {
        "CoreServices.AI.Chat"
    }

    async fn run(&self, args: &KMap<Value>) -> Result<FunctionOutput, CoreError> {
        let app_code = arg_string(args, "appCode")?;
        let client_code = arg_string(args, "clientCode")?;
        let connection_name = arg_string(args, "connectionName")?;
        let prompt = arg_string(args, "prompt")?;
        require_context_key()?;
        let c = &self.0.connections;
        let outcome = chat_function(
            self.0.connection_docs.as_ref(),
            &c.provider_http,
            &c.config.openai_base_url,
            &caller(),
            &app_code,
            &client_code,
            &connection_name,
            &prompt,
        )
        .await;
        match outcome {
            ChatOutcome::Response(v) => Ok(output_map([("response", v)])),
            ChatOutcome::Failed(message) => {
                let mut error = KMap::new();
                error.insert("error".to_string(), Value::String(message));
                let mut out = KMap::new();
                out.insert("response".to_string(), Value::String(String::new()));
                Ok(FunctionOutput::new(vec![EventResult::of("error", error), EventResult::output_of(out)]))
            }
            ChatOutcome::NoOutput => Err(empty_result(self.full_name())),
        }
    }
}

// --- CoreServices.Notification.SendNotification --------------------------------------------------

pub struct SendNotification(Arc<Integrations>);

/// `getAsBigInteger()`.
fn big_integer(args: &KMap<Value>, name: &str) -> Result<i128, CoreError> {
    match args.get(name) {
        Some(Value::Number(n)) => n
            .as_i64()
            .map(i128::from)
            .or_else(|| n.as_u64().map(i128::from))
            .ok_or_else(|| CoreError::unknown(format!("For input string: \"{}\"", crate::gson::number_to_java_string(n)))),
        Some(Value::String(s)) => s.trim().parse().map_err(|_| CoreError::unknown(format!("For input string: \"{s}\""))),
        _ => Err(CoreError::unknown(format!("{name} is not a number"))),
    }
}

fn non_empty(s: String) -> Option<String> {
    (!s.is_empty()).then_some(s)
}

#[async_trait]
impl JavaFunction for SendNotification {
    fn full_name(&self) -> &'static str {
        "CoreServices.Notification.SendNotification"
    }

    async fn run(&self, args: &KMap<Value>) -> Result<FunctionOutput, CoreError> {
        let app_code = arg_string(args, "appCode")?;
        let client_code = arg_string(args, "clientCode")?;
        let target_id = big_integer(args, "targetId")?;
        let target_code = arg_string(args, "targetCode")?;
        let target_type = arg_string(args, "targetType")?;
        let connection_name = arg_string(args, "connectionName")?;
        let filter_authorization = arg_string(args, "filterAuthorization")?;
        let notification_name = arg_string(args, "notificationName")?;
        let notification_category = arg_string(args, "notificationCategory")?;
        let payload = object(args, "payload")?;
        require_context_key()?;
        let req = NotificationRequest {
            app_code: non_empty(app_code),
            client_code: non_empty(client_code),
            connection_name: Some(connection_name),
            target_id: Some(target_id),
            target_code: non_empty(target_code),
            target_type,
            filter_authorization: non_empty(filter_authorization),
            notification_name: Some(notification_name),
            notification_category: Some(notification_category),
            payload: Some(payload),
        };
        let sent = self.0.mq.send_notification(self.0.checks.as_ref(), &caller(), req).await?;
        Ok(output_map([("sent", Value::Bool(sent.unwrap_or(false)))]))
    }
}

// --- CoreServices.Event.CreateEvent ----------------------------------------------------------------

pub struct CreateEvent {
    integrations: Arc<Integrations>,
    defs: Arc<dyn Catalog>,
}

#[async_trait]
impl JavaFunction for CreateEvent {
    fn full_name(&self) -> &'static str {
        "CoreServices.Event.CreateEvent"
    }

    async fn run(&self, args: &KMap<Value>) -> Result<FunctionOutput, CoreError> {
        let app_code = arg_string(args, "appCode")?;
        let client_code = arg_string(args, "clientCode")?;
        let event_name = arg_string(args, "eventName")?;
        let data = object(args, "eventData")?;
        require_context_key()?;
        let not_sent = || Ok(output_map([("created", Value::Bool(false))]));
        let c = caller();
        if !c.present {
            return not_sent();
        }
        let in_app = if app_code.trim().is_empty() { c.url_app_code.clone() } else { Some(app_code.clone()) };
        let in_client = if client_code.trim().is_empty() { c.client_code.clone() } else { Some(client_code.clone()) };
        let definition = self
            .defs
            .event_definition(&event_name, in_app.as_deref().unwrap_or(""), in_client.as_deref().unwrap_or(""))
            .await?;
        if definition.is_none() {
            return not_sent();
        }
        let event = EventMessage {
            event_name: Some(event_name),
            client_code: Some(client_code),
            app_code: Some(app_code),
            data: Some(data),
            authentication: Some(jackson_authentication(&c)),
            ..Default::default()
        };
        let sent = self.integrations.mq.create_event(&c, event).await?;
        Ok(output_map([("created", Value::Bool(sent))]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn args(v: Value) -> KMap<Value> {
        v.as_object().unwrap().clone().into_iter().collect()
    }

    #[test]
    fn arguments_read_as_gson_reads_them() {
        let a = args(json!({"o": {"x": 1}, "s": "h", "n": 7, "f": 2.9, "t": " 12 ", "bad": "x", "arr": [1], "yes": "True", "big": 18446744073709551615_u64}));
        assert_eq!(object(&a, "o").unwrap(), json!({"x": 1}).as_object().unwrap().clone());
        assert!(object(&a, "s").unwrap_err().to_string().contains("Not a JSON Object: \"h\""));
        assert!(object(&a, "none").unwrap_err().to_string().contains("is null (none)"));
        assert_eq!((int(&a, "n").unwrap(), int(&a, "f").unwrap(), int(&a, "t").unwrap()), (7, 2, 12));
        assert!(int(&a, "bad").unwrap_err().to_string().contains("For input string: \"x\""));
        assert!(int(&a, "arr").unwrap_err().to_string().contains("arr is not a number"));
        assert!(boolean(&a, "yes") && !boolean(&a, "n") && !boolean(&a, "none"));
        assert_eq!(big_integer(&a, "big").unwrap(), 18446744073709551615_i128);
        assert_eq!(big_integer(&a, "t").unwrap(), 12);
        assert!(big_integer(&a, "f").unwrap_err().to_string().contains("For input string: \"2.9\""));
        assert!(big_integer(&a, "bad").is_err() && big_integer(&a, "arr").is_err());
    }
}
