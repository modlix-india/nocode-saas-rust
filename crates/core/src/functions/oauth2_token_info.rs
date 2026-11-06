//! `CoreServices.REST.OAuth2TokenInfo` (Rust only, LZT-2270): what the provider says about the
//! stored token of an authorization-code OAuth2 connection (for Meta: `debug_token`, whose
//! `granular_scopes[].target_ids` name the WhatsApp Business Accounts a customer shared through
//! Embedded Signup). The token and the app's credentials stay in core; see
//! `connections::rest::token_info` for the endpoint rules.
//!
//! Like `CoreServices.Connection.VerifySignature`, it runs only inside a server function and
//! only for the running definition's own app. The client is chosen as a REST step's is, so a
//! function reads the token of the client it names only when it may act for that client.
//!
//! Events, as a REST step raises them: `output` `{data, statusCode}`; on a failure `error`
//! `{data, statusCode}` first (the provider's error body, or a plain message), then `output`.

use std::sync::Arc;

use async_trait::async_trait;
use connections::rest::token_info;
use kirun::json::schema::Schema;
use kirun::model::{Event, EventResult, FunctionOutput, FunctionSignature, Parameter};
use kirun::{Map, Value};

use super::support::{empty_result, forbidden, server_function_only};
use super::CoreFunction;
use crate::context;
use crate::error::CoreError;
use crate::integrations::{caller, core_error, Integrations};

const NAMESPACE: &str = "CoreServices.REST";

pub fn all(integrations: &Arc<Integrations>) -> Vec<Arc<dyn kirun::function::Function>> {
    vec![Arc::new(super::Core(OAuth2TokenInfo::new(integrations.clone())))]
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

fn event_schema() -> Map<Schema> {
    Map::from([
        ("data".to_string(), Schema::of_any("data")),
        ("statusCode".to_string(), Schema::of_integer("statusCode")),
    ])
}

pub struct OAuth2TokenInfo {
    signature: FunctionSignature,
    integrations: Arc<Integrations>,
}

/// `connectionName`, optional `appCode` and `clientCode`; `output` and `error` with `{data, statusCode}`.
pub fn token_info_signature() -> FunctionSignature {
    FunctionSignature::new(token_info::FUNCTION_NAME)
        .set_namespace(NAMESPACE)
        .set_parameters(Map::from([text("connectionName", None), text("appCode", Some("")), text("clientCode", Some(""))]))
        .set_events(Map::from([Event::output_event_map_entry(event_schema()), Event::event_map_entry(Event::ERROR, event_schema())]))
}

impl OAuth2TokenInfo {
    pub fn new(integrations: Arc<Integrations>) -> Self {
        Self { signature: token_info_signature(), integrations }
    }
}

#[async_trait]
impl CoreFunction for OAuth2TokenInfo {
    fn signature(&self) -> &FunctionSignature {
        &self.signature
    }

    async fn internal_execute(&self, args: &Map<Value>) -> Result<FunctionOutput, CoreError> {
        let full = format!("{NAMESPACE}.{}", token_info::FUNCTION_NAME);
        if !context::in_kirun() {
            return Err(server_function_only(&full));
        }
        let c = caller();
        let own_app = context::owner_app_code().or_else(|| c.url_app_code.clone()).unwrap_or_default();
        let asked_app = text_arg(args, "appCode");
        if !asked_app.is_empty() && asked_app != own_app {
            return Err(forbidden("CORE.CONNECTION_OTHER_APP", format!("{full} reads only the connections of its own app ({own_app})"))
                .param("function", full.as_str()));
        }
        let app = if asked_app.is_empty() { own_app } else { asked_app };
        let client = text_arg(args, "clientCode");
        let name = text_arg(args, "connectionName");
        let events = token_info::token_info(
            &self.integrations.connections,
            &c,
            Some(app.as_str()).filter(|a| !a.is_empty()),
            Some(client.as_str()).filter(|a| !a.is_empty()),
            &name,
        )
        .await
        .map_err(core_error)?;
        match events {
            Some(events) => Ok(FunctionOutput::new(
                events.into_iter().map(|e| EventResult::of(e.name, e.result.into_iter().collect())).collect(),
            )),
            None => Err(empty_result(&full)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_names_and_events() {
        let sig = token_info_signature();
        assert_eq!(sig.get_full_name(), "CoreServices.REST.OAuth2TokenInfo");
        assert!(sig.get_events().contains_key("output") && sig.get_events().contains_key("error"));
        assert!(sig.get_parameters().contains_key("connectionName"));
    }
}
