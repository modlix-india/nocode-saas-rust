//! `CoreServices.SecurityContext`: `HasAuthority`, `GetAuthentication`, `GetUser`.

use async_trait::async_trait;
use kirun::json::schema::Schema;
use kirun::model::{Event, FunctionOutput, FunctionSignature, Parameter};
use kirun::{Map, Value};

use super::{arg_string, output, CoreFunction};
use crate::authorities::has_authority;
use crate::context;
use crate::error::CoreError;
use crate::repos::core_schemas::{CONTEXT_AUTHENTICATION, CONTEXT_USER, SECURITY_CONTEXT};

const NAMESPACE: &str = "CoreServices.SecurityContext";

fn event(name: &str, schema: Schema) -> Map<Event> {
    Map::from([Event::output_event_map_entry(Map::from([(name.to_string(), schema)]))])
}

pub struct HasAuthority {
    signature: FunctionSignature,
}

impl HasAuthority {
    pub fn new() -> Self {
        Self {
            signature: FunctionSignature::new("HasAuthority")
                .set_namespace(NAMESPACE)
                .set_parameters(Map::from([Parameter::of_entry("authority", Schema::of_string("authority"), false)]))
                .set_events(event("result", Schema::of_boolean("result"))),
        }
    }
}

impl Default for HasAuthority {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CoreFunction for HasAuthority {
    fn signature(&self) -> &FunctionSignature {
        &self.signature
    }

    /// `SecurityContextUtil.hasAuthority(authority)` over the caller's authorities.
    async fn internal_execute(&self, args: &Map<Value>) -> Result<FunctionOutput, CoreError> {
        let authority = arg_string(args, "authority")?;
        let auth = context::authentication();
        let result = has_authority(Some(&authority), auth.authorities()).map_err(CoreError::from)?;
        Ok(output("result", Value::Bool(result)))
    }
}

pub struct GetAuthentication {
    signature: FunctionSignature,
}

impl GetAuthentication {
    pub fn new() -> Self {
        Self {
            signature: FunctionSignature::new("GetAuthentication").set_namespace(NAMESPACE).set_events(event(
                "auth",
                Schema::of_ref(&format!("{SECURITY_CONTEXT}.{CONTEXT_AUTHENTICATION}")),
            )),
        }
    }
}

impl Default for GetAuthentication {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CoreFunction for GetAuthentication {
    fn signature(&self) -> &FunctionSignature {
        &self.signature
    }

    /// The `ContextAuthentication` as Gson writes it, without `accessToken` and
    /// `accessTokenExpiryAt`.
    async fn internal_execute(&self, _args: &Map<Value>) -> Result<FunctionOutput, CoreError> {
        Ok(output("auth", context::authentication().authentication_json()))
    }
}

pub struct GetUser {
    signature: FunctionSignature,
}

impl GetUser {
    pub fn new() -> Self {
        Self {
            signature: FunctionSignature::new("GetUser")
                .set_namespace(NAMESPACE)
                .set_events(event("user", Schema::of_ref(&format!("{SECURITY_CONTEXT}.{CONTEXT_USER}")))),
        }
    }
}

impl Default for GetUser {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CoreFunction for GetUser {
    fn signature(&self) -> &FunctionSignature {
        &self.signature
    }

    async fn internal_execute(&self, _args: &Map<Value>) -> Result<FunctionOutput, CoreError> {
        Ok(output("user", context::authentication().user_json()))
    }
}
