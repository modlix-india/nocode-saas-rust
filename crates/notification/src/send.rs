//! `NotificationSendService.sendNotification`: one queue message, end to end.
//!
//! 1. The notification connection and the notification definition from core, on the surface
//!    the message was raised on (`x-draft: true` only for a draft message).
//! 2. The channels: email when the connection names a MAIL connection and the notification has
//!    an `email` template; in-app when the connection allows it and there is an `inapp`
//!    template. Neither: nothing is sent.
//! 3. The recipients from security's real user directory (never the draft surface), only those
//!    holding `filterAuthorization` when the message names one (Rust only).
//! 4. Each recipient's choices for the app ([`crate::choices`], Rust only: Java read none):
//!    per channel and the message's category, else the definition's `channelEnabled` default.
//! 5. Email to each recipient who wants it, then in-app to all who want it.
//!
//! A missing definition or no recipients ends the run quietly (logged). Anything that fails
//! ends it with an error, which the listener logs; the message is acked either way.
//!
//! A data notification (`kind: DATA`, Rust only) skips steps 1, 2 and 4: once it is found not
//! expired, the recipients come from the same security call, and one frame, `event:<eventName>` with
//! `{"event","data","id","sentAt"}`, goes to their open streams. Nothing is stored, and it is
//! never retried: a user who is not online misses it.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use serde_json::{json, Map, Value};

use crate::calls::{CoreClient, DefinitionRead, DirectoryClient};
use crate::choices::{wants, PreferenceSource};
use crate::email::{EmailSink, EMAIL_TEMPLATE_NAME};
use crate::inapp::{InAppSink, INAPP_TEMPLATE_NAME};
use crate::model::{CoreNotification, NotificationConnection, NotificationUser, QueueMessage, UsersListRequest};
use crate::push::Push;
use crate::sse::{event_frame, key};

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
    /// A data notification handed to the open streams of this many recipients.
    Pushed { users: usize },
    /// A data notification that arrived after its `expiresAt`: dropped.
    Expired,
}

pub struct SendService {
    pub core: CoreClient,
    pub directory: DirectoryClient,
    pub email: Arc<dyn EmailSink>,
    pub in_app: Arc<dyn InAppSink>,
    /// Where data notifications go.
    pub push: Arc<Push>,
    /// The recipients' choices; `None` sends to everyone as Java did (tests).
    pub prefs: Option<Arc<dyn PreferenceSource>>,
}

/// Now, in epoch milliseconds.
fn now_millis() -> i128 {
    i128::from(chrono::Utc::now().timestamp_millis())
}

/// A data notification's frame: `event:<eventName>` with `{"event","data","id","sentAt"}`.
pub fn data_frame(event_name: &str, data: &Value, id: &str, sent_at: i128) -> bytes::Bytes {
    let body = json!({"event": event_name, "data": data, "id": id, "sentAt": sent_at as i64});
    event_frame(event_name, &body.to_string(), id, 5000)
}

impl SendService {
    pub async fn send(&self, qob: &QueueMessage) -> Result<Outcome> {
        if qob.is_data() {
            return self.send_data(qob, now_millis()).await;
        }
        if let Some(kind) = &qob.kind {
            return Err(anyhow!("Unknown notification kind: {kind}"));
        }
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

        let users = self.recipients(qob).await?;
        if users.is_empty() {
            tracing::error!("Users not found: {}", qob.describe());
            return Ok(Outcome::NoUsers);
        }

        let prefs = self.choices(qob, &users).await?;
        let category = qob.notification_category.as_deref();
        let wanting = |channel: &str| -> Vec<NotificationUser> {
            users
                .iter()
                .filter(|u| wants(u.id.and_then(|id| prefs.get(&(id as u64))), channel, category, &notification))
                .cloned()
                .collect()
        };

        let empty = Map::new();
        let payload = qob.payload.as_ref().unwrap_or(&empty);
        let mut emails = 0;
        if is_email {
            let mail = conn.mail.as_ref().expect("checked above");
            for user in &wanting(EMAIL_TEMPLATE_NAME) {
                self.email.send_email(user, mail, &notification, payload).await?;
                emails += 1;
            }
        }
        let in_app_users = if is_in_app { wanting(INAPP_TEMPLATE_NAME) } else { Vec::new() };
        if in_app_users.is_empty() {
            return Ok(Outcome::Sent { emails, in_app: false });
        }
        self.in_app.send_in_app(&in_app_users, &notification, qob.app_code.as_deref(), category, payload).await?;
        Ok(Outcome::Sent { emails, in_app: true })
    }

    /// The recipients' preference maps in the message's app; none without a source or an app.
    async fn choices(&self, qob: &QueueMessage, users: &[NotificationUser]) -> Result<HashMap<u64, Map<String, Value>>> {
        let (Some(source), Some(app)) = (&self.prefs, qob.app_code.as_deref().filter(|a| !a.is_empty())) else {
            return Ok(HashMap::new());
        };
        let ids: Vec<u64> = users.iter().filter_map(|u| u.id).filter(|id| *id >= 0).map(|id| id as u64).collect();
        source.preferences(app, &ids).await
    }

    /// The recipients from security's user directory, as Java's `UsersListRequest` per target
    /// type asks for them, narrowed to the users holding the message's `filterAuthorization`
    /// when it has one (Rust only: Java's stored notifications ignored it, DIFFERENCES N15).
    async fn recipients(&self, qob: &QueueMessage) -> Result<Vec<NotificationUser>> {
        let target_type = qob
            .target_type
            .as_deref()
            .ok_or_else(|| anyhow!("Cannot invoke \"String.equals(Object)\" because the target type is null"))?;
        let target_long = || {
            qob.target_id
                .map(|t| t as i64)
                .ok_or_else(|| anyhow!("Cannot invoke \"java.math.BigInteger.longValue()\" because the target id is null"))
        };
        let mut request = UsersListRequest {
            app_code: qob.app_code.clone(),
            filter_authorization: qob.filter_authorization.clone(),
            ..Default::default()
        };
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
        match users {
            Value::Array(a) => a.iter().map(NotificationUser::from_json).collect::<Result<_, _>>().map_err(|e| anyhow!(e.0)),
            _ => Err(anyhow!("Error while extracting response for type [java.util.List<NotificationUser>]")),
        }
    }

    /// A data notification at `now` (epoch milliseconds): no connection, definition, template
    /// or row; the recipients' open streams only.
    pub async fn send_data(&self, qob: &QueueMessage, now: i128) -> Result<Outcome> {
        if qob.expires_at.is_some_and(|e| e < now) {
            tracing::debug!("Data notification expired before delivery: {}", qob.describe());
            return Ok(Outcome::Expired);
        }
        let event = qob.event_name.as_deref().filter(|e| !e.is_empty()).ok_or_else(|| anyhow!("A data notification without an event name"))?;
        let app = qob.app_code.as_deref().filter(|a| !a.is_empty()).ok_or_else(|| anyhow!("A data notification without an app code"))?;
        let users = self.recipients(qob).await?;
        let mut keys: Vec<String> = Vec::with_capacity(users.len());
        for id in users.iter().filter_map(|u| u.id) {
            let k = key(id, app);
            if !keys.contains(&k) {
                keys.push(k);
            }
        }
        if keys.is_empty() {
            tracing::debug!("Data notification has no recipients: {}", qob.describe());
            return Ok(Outcome::NoUsers);
        }
        let id = uuid::Uuid::new_v4().to_string();
        let frame = data_frame(event, qob.data.as_ref().unwrap_or(&Value::Null), &id, now);
        self.push.deliver(&keys, &frame).await;
        Ok(Outcome::Pushed { users: keys.len() })
    }
}
