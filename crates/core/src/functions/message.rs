//! `CoreServices.Message`: `SendWhatsapp`, `MakeCall` and the WhatsApp number administration
//! (`WhatsappNumberFunctions`). They called the message service, which is retired: apps now
//! message and call through their own server functions and REST connections to the provider.
//!
//! Stored definitions still name them (on the local stack, 2026-10-22: eight leadzumptwo server
//! functions), so each stays registered under its Java signature, and so stays visible to
//! `repositoryFind`, but fails at once with `CORE.MESSAGE_SERVICE_RETIRED`, whatever its
//! arguments, calling nothing.

use std::sync::Arc;

use async_trait::async_trait;
use axum::http::StatusCode;
use kirun::function::Function;
use kirun::model::{FunctionOutput, FunctionSignature};
use kirun::runtime::FunctionExecutionParameters;

use super::java_sig;
use crate::context;
use crate::error::CoreError;

pub const NAMESPACE: &str = "CoreServices.Message";

/// `makeMessageFunctions`' names, in its order: SendWhatsapp, MakeCall, then
/// `WhatsappNumberFunctions.all`.
pub const NAMES: [&str; 7] = [
    "CoreServices.Message.SendWhatsapp",
    "CoreServices.Message.MakeCall",
    "CoreServices.Message.LinkWhatsappNumber",
    "CoreServices.Message.ListWhatsappNumbers",
    "CoreServices.Message.GetWhatsappPairingCode",
    "CoreServices.Message.RemoveWhatsappNumber",
    "CoreServices.Message.SetDefaultWhatsappNumber",
];

/// What every one of them answers.
pub fn retired(full_name: &str) -> CoreError {
    CoreError::coded(StatusCode::GONE, "CORE.MESSAGE_SERVICE_RETIRED", format!("{full_name} called the message service, which has been retired"))
        .param("function", full_name)
}

/// One retired function: Java's signature, no work. It answers before the arguments are
/// validated, so a definition learns why it fails rather than which argument it missed.
pub struct Retired {
    full_name: &'static str,
    signature: FunctionSignature,
}

impl Retired {
    pub fn new(full_name: &'static str) -> Self {
        Self { full_name, signature: java_sig::signature(full_name) }
    }
}

#[async_trait]
impl Function for Retired {
    fn get_signature(&self) -> &FunctionSignature {
        &self.signature
    }

    async fn execute(&self, _context: &mut FunctionExecutionParameters) -> kirun::Result<FunctionOutput> {
        Err(context::raise(retired(self.full_name)))
    }
}

/// The seven, in `makeMessageFunctions`' order.
pub fn all() -> Vec<Arc<dyn Function>> {
    NAMES.into_iter().map(|n| Arc::new(Retired::new(n)) as Arc<dyn Function>).collect()
}

#[cfg(test)]
mod tests {
    use kirun::repository::{KIRunFunctionRepository, KIRunSchemaRepository};
    use serde_json::json;

    use super::*;
    use crate::testing::{request, user};

    #[tokio::test]
    async fn every_one_fails_at_once_with_one_code() {
        let all = all();
        let names: Vec<String> = all.iter().map(|f| f.get_signature().get_full_name()).collect();
        assert_eq!(names, NAMES);
        let ctx = request(user(&["Authorities.Logged_IN"]), false, None);
        context::with_request(ctx, async {
            for (f, name) in all.iter().zip(NAMES) {
                // With arguments, and without the ones the signature requires.
                for args in [json!({"to": "91987", "text": "hi", "toNumber": "98", "phoneNumber": "1", "sessionCode": "S"}), json!({})] {
                    let mut fep = FunctionExecutionParameters::new(Arc::new(KIRunFunctionRepository::new()), Arc::new(KIRunSchemaRepository::new()))
                        .set_arguments(args.as_object().unwrap().clone().into_iter().collect());
                    let e = f.execute(&mut fep).await.unwrap_err();
                    assert_eq!(e.to_string(), format!("{name} called the message service, which has been retired"));
                    let raised = context::request().and_then(|r| r.raised.lock().take()).unwrap();
                    assert_eq!(raised.status(), StatusCode::GONE);
                    assert_eq!(raised.code().map(|c| c.code.to_string()).as_deref(), Some("CORE.MESSAGE_SERVICE_RETIRED"));
                }
            }
        })
        .await;
        // Outside a request there is nothing to raise into; the error still says why.
        let e = retired(NAMES[0]);
        assert_eq!(e.status(), StatusCode::GONE);
        assert!(NAMES.iter().all(|n| n.starts_with(NAMESPACE)));
    }
}
