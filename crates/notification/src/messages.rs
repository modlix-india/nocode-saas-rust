//! notification's message bundle (`messages_en.properties`) and `NotificationMessageResourceService`.
//!
//! The bundle has three entries. The ids the service names but the bundle lacks
//! (`mail_send_error`, `template_data_not_found`, ...) resolve to `unknown_error`, as
//! `AbstractMessageService.getMessage` falls back.

use platform::error::format_message;

pub const UNKNOWN_ERROR: &str = "unknown_error";
pub const NOTIFICATION_TYPE_NOT_FOUND: &str = "notification_type_not_found";
pub const UNKNOWN_ERROR_WITH_ID: &str = "unknown_error_with_id";

pub const FORBIDDEN_CREATE: &str = "forbidden_create";
pub const FORBIDDEN_UPDATE: &str = "forbidden_update";
pub const TEMPLATE_DATA_NOT_FOUND: &str = "template_data_not_found";
pub const CONNECTION_DETAILS_MISSING: &str = "connection_details_missing";
pub const MAIL_SEND_ERROR: &str = "mail_send_error";

/// `messages_en.properties`, entry for entry (the last value keeps its trailing space).
const BUNDLE: [(&str, &str); 3] = [
    (UNKNOWN_ERROR, "Internal Server Error (Unknown)"),
    (NOTIFICATION_TYPE_NOT_FOUND, "Provide a notification type to continue."),
    (UNKNOWN_ERROR_WITH_ID, "Please try again. A server error - $ "),
];

/// `getMessage(messageId)`: the entry, or `unknown_error`'s when the bundle has none.
pub fn template(id: &str) -> &'static str {
    BUNDLE
        .iter()
        .find(|(k, _)| *k == id)
        .or_else(|| BUNDLE.iter().find(|(k, _)| *k == UNKNOWN_ERROR))
        .map(|(_, v)| *v)
        .unwrap_or("")
}

/// `getMessage(messageId, params...)`: the entry formatted with KIRun's `StringFormatter`.
pub fn message(id: &str, params: &[&str]) -> String {
    format_message(template(id), params)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_and_fallback() {
        assert_eq!(message(UNKNOWN_ERROR_WITH_ID, &["2026-10-16-1a"]), "Please try again. A server error - 2026-10-16-1a ");
        assert_eq!(message(NOTIFICATION_TYPE_NOT_FOUND, &[]), "Provide a notification type to continue.");
        // AbstractTemplateService throws mail_send_error, which the bundle does not have.
        assert_eq!(message(MAIL_SEND_ERROR, &["No template parts found"]), "Internal Server Error (Unknown)");
        for id in [FORBIDDEN_CREATE, FORBIDDEN_UPDATE, TEMPLATE_DATA_NOT_FOUND, CONNECTION_DETAILS_MISSING] {
            assert_eq!(template(id), "Internal Server Error (Unknown)");
        }
    }
}
