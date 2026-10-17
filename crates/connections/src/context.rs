//! What the Java services read from the Reactor context while a connection is used: the
//! caller's `ContextAuthentication`, whether a KIRun runtime is running
//! (`DefinitionFunction.CONTEXT_KEY`), the draft surface and `x-debug`. The core crate fills
//! this from its request context.

use serde_json::{Map, Value};

#[derive(Debug, Clone, Default)]
pub struct Caller {
    /// `ContextAuthentication` was found at all. Anonymous callers still have one.
    pub present: bool,
    pub authenticated: bool,
    /// `ca.getUser().getId()`.
    pub user_id: Option<u64>,
    /// `ca.getUser().getClientId()`.
    pub user_client_id: Option<u64>,
    /// `ca.getClientCode()`: the client the user belongs to.
    pub client_code: Option<String>,
    /// `ca.getUrlClientCode()`, from the `clientCode` header.
    pub url_client_code: Option<String>,
    /// `ca.getUrlAppCode()`, from the `appCode` header.
    pub url_app_code: Option<String>,
    /// `clientTypeCode == "SYS"`.
    pub system_client: bool,
    pub authorities: Vec<String>,
    /// Security's `ContextAuthentication` answer as received, for the messages that carry it.
    pub raw: Option<Map<String, Value>>,
    /// A KIRun runtime is running this call (`DefinitionFunction.CONTEXT_KEY` is `"true"`).
    pub in_kirun: bool,
    /// The request is on the app's draft surface (`LogUtil.DRAFT_KEY`).
    pub draft: bool,
    /// The `x-debug` value (`LogUtil.DEBUG_KEY`), when the request has one.
    pub debug: Option<String>,
}

impl Caller {
    /// `SecurityContextUtil.resolveAppAndClientCode`: the given codes when both are set,
    /// otherwise the blank ones from the caller (`urlAppCode`, the user's `clientCode`).
    pub fn resolve_app_and_client(&self, app_code: Option<&str>, client_code: Option<&str>) -> (Option<String>, Option<String>) {
        let blank = |s: Option<&str>| s.is_none_or(crate::java::is_blank);
        if !blank(app_code) && !blank(client_code) {
            return (app_code.map(str::to_string), client_code.map(str::to_string));
        }
        if !self.present {
            // No security context: the Java Mono is empty and nothing downstream runs.
            return (None, None);
        }
        (
            if blank(app_code) { self.url_app_code.clone() } else { app_code.map(str::to_string) },
            if blank(client_code) { self.client_code.clone() } else { client_code.map(str::to_string) },
        )
    }

    pub fn client_code(&self) -> &str {
        self.client_code.as_deref().unwrap_or("")
    }

    pub fn has_authority(&self, authority: &str) -> bool {
        self.authorities.iter().any(|a| a == authority)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_blank_codes_from_the_caller() {
        let c = Caller {
            present: true,
            url_app_code: Some("leadzump".into()),
            client_code: Some("FIN".into()),
            ..Default::default()
        };
        assert_eq!(c.resolve_app_and_client(Some("a"), Some("B")), (Some("a".into()), Some("B".into())));
        assert_eq!(c.resolve_app_and_client(Some(" "), None), (Some("leadzump".into()), Some("FIN".into())));
        assert_eq!(c.resolve_app_and_client(Some("x"), Some("")), (Some("x".into()), Some("FIN".into())));
    }
}
