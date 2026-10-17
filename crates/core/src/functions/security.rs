//! `CoreServices.Security.GetAppUrl`. (The rest of the `CoreServices.Security` family calls
//! security on the caller's behalf and comes with the caller-security port.)

use std::sync::Arc;

use async_trait::async_trait;
use kirun::json::schema::Schema;
use kirun::model::{Event, FunctionOutput, FunctionSignature, Parameter};
use kirun::{Map, Value};

use super::{arg_string, output, CoreFunction};
use crate::clients::SecurityCalls;
use crate::error::CoreError;

pub struct GetAppUrl {
    signature: FunctionSignature,
    security: Arc<SecurityCalls>,
}

impl GetAppUrl {
    pub fn new(security: Arc<SecurityCalls>) -> Self {
        Self {
            signature: FunctionSignature::new("GetAppUrl")
                .set_namespace("CoreServices.Security")
                .set_parameters(Map::from([
                    Parameter::of_entry("appCode", Schema::of_string("appCode"), false),
                    Parameter::of_entry(
                        "clientCode",
                        Schema::of_string("clientCode").set_default_value(Value::String(String::new())),
                        false,
                    ),
                ]))
                .set_events(Map::from([Event::output_event_map_entry(Map::from([(
                    "result".to_string(),
                    Schema::of_string("result"),
                )]))])),
            security,
        }
    }
}

#[async_trait]
impl CoreFunction for GetAppUrl {
    fn signature(&self) -> &FunctionSignature {
        &self.signature
    }

    /// `ClientUrlService.getAppUrl(appCode, clientCode).defaultIfEmpty("")`.
    async fn internal_execute(&self, args: &Map<Value>) -> Result<FunctionOutput, CoreError> {
        let app_code = arg_string(args, "appCode")?;
        let client_code = arg_string(args, "clientCode")?;
        let url = self.security.app_url(&app_code, &client_code).await?;
        Ok(output("result", Value::String(url.unwrap_or_default())))
    }
}
