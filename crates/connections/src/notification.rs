//! `NotificationService.processAndSendNotification`: checks that the caller may notify the
//! target, then publishes a `NotificationQueObject` on the `notifications` exchange for the
//! notification service to render and deliver.
//!
//! A data notification (Rust only, [`prepare_data`]) goes the same way after the same checks:
//! the message carries `kind: DATA`, an event name, any JSON and an expiry, and the
//! notification service pushes it to the recipients' open streams without storing it.

use async_trait::async_trait;
use http::StatusCode;
use serde_json::{Map, Value};

use crate::context::Caller;
use crate::error::{ConnError, ConnResult};
use crate::mq::{NotificationMessage, Publisher, Route, KIND_DATA, NOTIFICATION_TYPE_ID};

pub const USER_ID: &str = "User Id";
pub const CLIENT_ID: &str = "Client Id";
pub const CLIENT_CODE: &str = "Client Code";

/// The security service's hierarchy checks (`IFeignSecurityService`), provided by the core
/// crate.
#[async_trait]
pub trait HierarchyChecks: Send + Sync {
    /// `isUserPartOfHierarchy(userId, clientCode)`.
    async fn is_user_part_of_hierarchy(&self, user_id: i128, client_code: &str) -> ConnResult<bool>;
    /// `doesClientManageClient(managingClientId, clientId)`.
    async fn does_client_manage_client(&self, managing_client_id: u64, client_id: i128) -> ConnResult<bool>;
    /// `doesClientManageClientCode(managingClientCode, clientCode)`.
    async fn does_client_manage_client_code(&self, managing_client_code: &str, client_code: &str) -> ConnResult<bool>;
}

/// The arguments of `processAndSendNotification`.
#[derive(Debug, Clone, Default)]
pub struct NotificationRequest {
    pub app_code: Option<String>,
    pub client_code: Option<String>,
    pub connection_name: Option<String>,
    /// A `BigInteger`; `SendNotification` defaults it to 0.
    pub target_id: Option<i128>,
    pub target_code: Option<String>,
    pub target_type: String,
    pub filter_authorization: Option<String>,
    pub notification_name: Option<String>,
    pub notification_category: Option<String>,
    pub payload: Option<Map<String, Value>>,
}

/// `Some(true)` once published; `None` where Java completes empty (no caller, a target the
/// caller may not reach, an unknown target type). `SendNotification` reports `None` as `false`.
pub async fn process_and_send(
    publisher: &Publisher,
    route: &Route,
    checks: &dyn HierarchyChecks,
    caller: &Caller,
    req: NotificationRequest,
) -> ConnResult<Option<bool>> {
    let Some((key, message)) = prepare(route, checks, caller, req).await? else { return Ok(None) };
    publisher.publish(&route.exchange, &key, message.to_json().as_bytes(), NOTIFICATION_TYPE_ID).await?;
    Ok(Some(true))
}

/// Everything before the publish: the access check, the routing key and the message. `None`
/// where Java completes empty.
pub async fn prepare(
    route: &Route,
    checks: &dyn HierarchyChecks,
    caller: &Caller,
    req: NotificationRequest,
) -> ConnResult<Option<(String, NotificationMessage)>> {
    if !caller.present {
        return Ok(None);
    }
    let (app, _client) = caller.resolve_app_and_client(req.app_code.as_deref(), req.client_code.as_deref());

    let target_id = || req.target_id.unwrap_or(0);
    let has_access = match req.target_type.as_str() {
        USER_ID => {
            if target_id() <= 0 && !caller.system_client {
                return Ok(None);
            }
            caller.system_client || checks.is_user_part_of_hierarchy(target_id(), caller.client_code()).await?
        }
        CLIENT_ID => {
            if target_id() <= 0 && !caller.system_client {
                return Ok(None);
            }
            caller.system_client
                || checks.does_client_manage_client(caller.user_client_id.unwrap_or(0), target_id()).await?
        }
        CLIENT_CODE => {
            if req.target_code.as_deref().is_none_or(str::is_empty) && !caller.system_client {
                return Ok(None);
            }
            caller.system_client
                || checks
                    .does_client_manage_client_code(caller.client_code(), req.target_code.as_deref().unwrap_or(""))
                    .await?
        }
        other => {
            tracing::error!(target_type = other, "Invalid target type for notification processing");
            return Ok(None);
        }
    };
    if !has_access {
        return Ok(None);
    }

    let key = route.next_key().to_string();
    let message = NotificationMessage {
        app_code: app,
        // Java sets the resolved client code and then overwrites it with the URL client code.
        client_code: caller.url_client_code.clone(),
        url_client_code: caller.url_client_code.clone(),
        triggered_user_id: caller.user_id,
        target_id: req.target_id.map(|t| Value::from(t as i64)),
        target_type: Some(req.target_type.clone()),
        target_code: req.target_code.clone(),
        filter_authorization: req.filter_authorization.clone(),
        notification_name: req.notification_name.clone(),
        notification_category: req.notification_category.clone(),
        connection_name: req.connection_name.clone(),
        x_debug: caller.debug.clone(),
        draft: caller.draft,
        payload: req.payload.clone(),
        ..Default::default()
    };
    Ok(Some((key, message)))
}

/// The longest event name a data notification may carry.
pub const EVENT_NAME_MAX: usize = 64;
/// The most a data notification's data may weigh, serialised.
pub const DATA_MAX_BYTES: usize = 64 * 1024;
/// The event names the stream itself uses.
pub const RESERVED_EVENT_NAMES: [&str; 2] = ["init", "notification"];

/// The arguments of `SendDataNotification`.
#[derive(Debug, Clone, Default)]
pub struct DataNotificationRequest {
    pub app_code: Option<String>,
    pub client_code: Option<String>,
    pub target_id: Option<i128>,
    pub target_code: Option<String>,
    pub target_type: String,
    pub filter_authorization: Option<String>,
    pub event_name: String,
    pub data: Value,
    /// How long the push is worth delivering.
    pub ttl_seconds: i64,
}

/// An event name is 1 to 64 letters, digits, `_`, `.` or `-`, and not one the stream uses
/// itself (`init`, `notification`, in any case).
pub fn check_event_name(name: &str) -> ConnResult<()> {
    let shape = !name.is_empty()
        && name.len() <= EVENT_NAME_MAX
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
    if !shape {
        return Err(ConnError::coded(
            StatusCode::BAD_REQUEST,
            "CORE.DATA_NOTIFICATION_EVENT_INVALID",
            format!("Event name '{name}' must be 1 to {EVENT_NAME_MAX} letters, digits, '_', '.' or '-'"),
        )
        .param("event", name.to_string()));
    }
    if RESERVED_EVENT_NAMES.iter().any(|r| r.eq_ignore_ascii_case(name)) {
        return Err(ConnError::coded(StatusCode::BAD_REQUEST, "CORE.DATA_NOTIFICATION_EVENT_RESERVED", format!("Event name '{name}' is reserved"))
            .param("event", name.to_string()));
    }
    Ok(())
}

/// The data, serialised, must fit in [`DATA_MAX_BYTES`].
pub fn check_data_size(data: &Value) -> ConnResult<()> {
    let size = serde_json::to_vec(data).map(|v| v.len()).unwrap_or(usize::MAX);
    if size > DATA_MAX_BYTES {
        return Err(ConnError::coded(
            StatusCode::BAD_REQUEST,
            "CORE.DATA_NOTIFICATION_TOO_LARGE",
            format!("Data notification data is {size} bytes, more than the {DATA_MAX_BYTES} allowed"),
        )
        .param("size", size.to_string())
        .param("limit", DATA_MAX_BYTES.to_string()));
    }
    Ok(())
}

/// The event name and data are checked first; then the caller and target exactly as
/// [`prepare`] checks them (`None` where a notification would not be sent); then the message,
/// marked `DATA`, expiring `ttl_seconds` after `now_millis`.
pub async fn prepare_data(
    route: &Route,
    checks: &dyn HierarchyChecks,
    caller: &Caller,
    req: DataNotificationRequest,
    now_millis: i64,
) -> ConnResult<Option<(String, NotificationMessage)>> {
    check_event_name(&req.event_name)?;
    check_data_size(&req.data)?;
    let base = NotificationRequest {
        app_code: req.app_code,
        client_code: req.client_code,
        target_id: req.target_id,
        target_code: req.target_code,
        target_type: req.target_type,
        filter_authorization: req.filter_authorization,
        ..Default::default()
    };
    let Some((key, mut message)) = prepare(route, checks, caller, base).await? else { return Ok(None) };
    message.kind = Some(KIND_DATA.to_string());
    message.event_name = Some(req.event_name);
    message.data = Some(req.data);
    message.expires_at = Some(now_millis.saturating_add(req.ttl_seconds.saturating_mul(1000)));
    Ok(Some((key, message)))
}
