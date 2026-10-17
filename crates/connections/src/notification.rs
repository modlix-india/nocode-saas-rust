//! `NotificationService.processAndSendNotification`: checks that the caller may notify the
//! target, then publishes a `NotificationQueObject` on the `notifications` exchange for the
//! notification service to render and deliver.

use async_trait::async_trait;
use serde_json::{Map, Value};

use crate::context::Caller;
use crate::error::ConnResult;
use crate::mq::{NotificationMessage, Publisher, Route, NOTIFICATION_TYPE_ID};

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
