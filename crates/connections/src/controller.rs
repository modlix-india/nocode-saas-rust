//! `ConnectionController`'s own routes, as functions the core crate mounts under
//! `/api/core/connections`. Each says what Java answers so the route can answer the same:
//!
//! | Route | Java answer |
//! |---|---|
//! | `POST /oauth/evoke?connectionName=` | 200 `text/plain` consent URL; 200 empty when the connection is not visible |
//! | `GET /oauth/callback?code=&state=` | 302 to the connection's `pagePath` (see [`CallbackOutcome`]) |
//! | `GET /oauth/revoke?connectionName=` | 200 `true` |
//! | `GET /internal/oauth2/token/{connectionName}` (`appCode`, `clientCode` headers) | 200 `text/plain` token, or empty |
//! | `GET /internal/notification/{name}?appCode=&clientCode=&urlClientCode=` | 200 JSON [`NotificationConnectionDetails`], or empty |
//! | `GET /internal/{name}?appCode=&clientCode=&urlClientCode=&connectionType=` | 200 JSON connection, or empty |
//!
//! An unknown `connectionType` is Spring's 400 for an unconvertible request parameter.

use http::StatusCode;

use crate::connection::{self, Connection, ConnectionType, NotificationConnectionDetails};
use crate::context::Caller;
use crate::error::{ConnError, ConnResult};
pub use crate::rest::oauth2::CallbackOutcome;
use crate::rest::oauth2::{self, CONSENT_CALLBACK_URI};
use crate::Connections;

pub async fn evoke_oauth(svc: &Connections, caller: &Caller, connection_name: &str, forwarded_host: Option<&str>) -> ConnResult<Option<String>> {
    oauth2::evoke_consent(svc, caller, connection_name, forwarded_host).await
}

pub async fn oauth_callback(
    svc: &Connections,
    caller: &Caller,
    code: Option<&str>,
    state: Option<&str>,
    forwarded_host: Option<&str>,
) -> ConnResult<CallbackOutcome> {
    oauth2::oauth2_callback(svc, caller, code, state, forwarded_host, CONSENT_CALLBACK_URI).await
}

pub async fn revoke_token(svc: &Connections, caller: &Caller, connection_name: &str) -> ConnResult<bool> {
    oauth2::revoke_connection_token(svc, caller, connection_name).await
}

pub async fn oauth2_token(
    svc: &Connections,
    caller: &Caller,
    connection_name: &str,
    app_code_header: Option<&str>,
    client_code_header: Option<&str>,
) -> ConnResult<Option<String>> {
    oauth2::access_token_for(svc, caller, app_code_header, client_code_header, connection_name).await
}

pub async fn notification_connections(
    svc: &Connections,
    name: &str,
    app_code: &str,
    client_code: &str,
    url_client_code: &str,
) -> ConnResult<Option<NotificationConnectionDetails>> {
    connection::notification_connections(svc.store.as_ref(), name, app_code, url_client_code, client_code).await
}

pub async fn internal_connection(
    svc: &Connections,
    name: &str,
    app_code: &str,
    client_code: &str,
    url_client_code: &str,
    connection_type: &str,
) -> ConnResult<Option<Connection>> {
    let Some(wanted) = ConnectionType::value_of(connection_type) else {
        return Err(ConnError::coded(
            StatusCode::BAD_REQUEST,
            "CORE.CONNECTION_TYPE_INVALID",
            format!("Failed to convert value of type 'java.lang.String' to required type 'com.fincity.saas.commons.core.enums.ConnectionType'; Failed to convert from type [java.lang.String] to type [@org.springframework.web.bind.annotation.RequestParam com.fincity.saas.commons.core.enums.ConnectionType] for value [{connection_type}]"),
        ));
    };
    connection::connection_of_type(svc.store.as_ref(), name, app_code, url_client_code, client_code, wanted).await
}
