//! `NotificationSendService.sendNotification`: one queue message, end to end.
//!
//! 1. The notification connection and the notification definition from core, on the surface
//!    the message was raised on (`x-draft: true` only for a draft message).
//! 2. The channels: email when the connection names a MAIL connection and the notification has
//!    an `email` template; in-app when the connection allows it and there is an `inapp`
//!    template. Neither: nothing is sent.
//! 3. The recipients from security's real user directory (never the draft surface).
//! 4. Email to each recipient, then in-app to all of them.
//!
//! A missing definition or no recipients ends the run quietly (logged). Anything that fails
//! ends it with an error, which the listener logs; the message is acked either way. User
//! preferences play no part: Java reads none when sending.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use serde_json::{Map, Value};

use crate::calls::{CoreClient, DefinitionRead, DirectoryClient};
use crate::email::{EmailSink, EMAIL_TEMPLATE_NAME};
use crate::inapp::{InAppSink, INAPP_TEMPLATE_NAME};
use crate::model::{CoreNotification, NotificationConnection, NotificationUser, QueueMessage, UsersListRequest};

pub const USER_ID: &str = "User Id";
pub const CLIENT_ID: &str = "Client Id";
pub const CLIENT_CODE: &str = "Client Code";

/// How a message ended, for the log and the tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    NoConnection,
    NoNotification,
    NoChannel,
    NoUsers,
    /// Mails attempted (each `false` or `true` as the email service answered), and whether the
    /// in-app channel ran.
    Sent { emails: usize, in_app: bool },
}

pub struct SendService {
    pub core: CoreClient,
    pub directory: DirectoryClient,
    pub email: Arc<dyn EmailSink>,
    pub in_app: Arc<dyn InAppSink>,
}

impl SendService {
    pub async fn send(&self, qob: &QueueMessage) -> Result<Outcome> {
        // Definition lookups follow the surface the notification was raised on; recipient
        // resolution below deliberately does not.
        let draft = qob.draft.then_some("true");
        let read = DefinitionRead {
            name: qob.connection_name.as_deref(),
            app_code: qob.app_code.as_deref(),
            client_code: qob.client_code.as_deref(),
            url_client_code: qob.url_client_code.as_deref(),
            draft,
            debug: qob.x_debug.as_deref(),
        };
        let Some(conn) = self.core.notification_connection(read).await? else {
            tracing::error!("Notification connection not found: {}", qob.connection_name.as_deref().unwrap_or("null"));
            return Ok(Outcome::NoConnection);
        };
        let conn = NotificationConnection::from_json(&conn).map_err(|e| anyhow!(e.0))?;

        let read = DefinitionRead { name: qob.notification_name.as_deref(), ..read };
        let Some(notification) = self.core.notification(read).await? else {
            tracing::error!("Notification not found: {}", qob.notification_name.as_deref().unwrap_or("null"));
            return Ok(Outcome::NoNotification);
        };
        let notification = CoreNotification::from_json(&notification).map_err(|e| anyhow!(e.0))?;

        let has = |channel: &str| {
            notification
                .has_channel(channel)
                .ok_or_else(|| anyhow!("Cannot invoke \"java.util.Map.containsKey(Object)\" because the channel templates are null"))
        };
        let is_email = conn.mail.is_some() && has(EMAIL_TEMPLATE_NAME)?;
        let is_in_app = conn.in_app && has(INAPP_TEMPLATE_NAME)?;
        if !is_email && !is_in_app {
            tracing::error!("Notification channel and templates are not found: {}, {conn:?}, {notification:?}", qob.describe());
            return Ok(Outcome::NoChannel);
        }

        let target_type = qob
            .target_type
            .as_deref()
            .ok_or_else(|| anyhow!("Cannot invoke \"String.equals(Object)\" because the target type is null"))?;
        let target_long = || {
            qob.target_id
                .map(|t| t as i64)
                .ok_or_else(|| anyhow!("Cannot invoke \"java.math.BigInteger.longValue()\" because the target id is null"))
        };
        let mut request = UsersListRequest { app_code: qob.app_code.clone(), ..Default::default() };
        match target_type {
            USER_ID => request.user_ids = Some(vec![target_long()?]),
            CLIENT_ID => request.client_id = Some(target_long()?),
            CLIENT_CODE => request.client_code = qob.target_code.clone(),
            _ => {}
        }
        let users = self
            .directory
            .users_for_notification(&request, qob.x_debug.as_deref())
            .await?
            .ok_or_else(|| anyhow!("Cannot invoke \"java.util.List.isEmpty()\" because \"users\" is null"))?;
        let users: Vec<NotificationUser> = match users {
            Value::Array(a) => a.iter().map(NotificationUser::from_json).collect::<Result<_, _>>().map_err(|e| anyhow!(e.0))?,
            _ => return Err(anyhow!("Error while extracting response for type [java.util.List<NotificationUser>]")),
        };
        if users.is_empty() {
            tracing::error!("Users not found: {}", qob.describe());
            return Ok(Outcome::NoUsers);
        }

        let empty = Map::new();
        let payload = qob.payload.as_ref().unwrap_or(&empty);
        let mut emails = 0;
        if is_email {
            let mail = conn.mail.as_ref().expect("checked above");
            for user in &users {
                self.email.send_email(user, mail, &notification, payload).await?;
                emails += 1;
            }
        }
        if !is_in_app {
            return Ok(Outcome::Sent { emails, in_app: false });
        }
        self.in_app
            .send_in_app(&users, &notification, qob.app_code.as_deref(), qob.notification_category.as_deref(), payload)
            .await?;
        Ok(Outcome::Sent { emails, in_app: true })
    }
}
