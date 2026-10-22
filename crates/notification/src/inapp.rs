//! `InAppNotificationService`: stores in-app notifications, pushes them to the recipients'
//! open streams, and answers the count and list reads.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use connections::java::json::jackson_pretty;
use serde_json::{Map, Value};

use crate::dao::{Dao, InAppFilter, InAppRow, NewInApp};
use crate::model::{CoreNotification, NotificationUser};
use crate::push::Push;
use crate::spring::{page_json, Pageable};
use crate::sse::{event_frame, key};
use crate::template::{language, processed_template};

pub const INAPP_TEMPLATE_NAME: &str = "inapp";

/// Where the send service hands in-app notifications (the Java test mocks this service).
#[async_trait]
pub trait InAppSink: Send + Sync {
    async fn send_in_app(
        &self,
        users: &[NotificationUser],
        notification: &CoreNotification,
        app_code: Option<&str>,
        category: Option<&str>,
        payload: &Map<String, Value>,
    ) -> Result<()>;
}

/// `NotificationEventRecord` as the services' `ObjectMapper` writes it (`INDENT_OUTPUT`,
/// `NON_EMPTY`): what an open stream receives as the `notification` event's data.
pub fn event_json(r: &InAppRow) -> String {
    let mut m = Map::new();
    m.insert("id".into(), Value::from(r.id));
    m.insert("userId".into(), Value::from(r.user_id));
    for (k, v) in [
        ("appCode", Some(&r.app_code)),
        ("notificationName", Some(&r.notification_name)),
        ("title", Some(&r.title)),
        ("message", Some(&r.message)),
        ("mimeUrl", r.mime_url.as_ref()),
        ("notificationType", Some(&r.notification_type)),
    ] {
        if let Some(v) = v.filter(|v| !v.is_empty()) {
            m.insert(k.into(), Value::from(v.clone()));
        }
    }
    jackson_pretty(&Value::Object(m))
}

/// `NotificationInApp` as the list writes it. Its `type` is never filled: jOOQ maps
/// `NOTIFICATION_TYPE` to a `notificationType` property the class does not have, so Java always
/// leaves it out, and so does this.
pub fn list_item_json(r: &InAppRow) -> Value {
    let mut m = Map::new();
    m.insert("id".into(), Value::from(r.id));
    if !r.title.is_empty() {
        m.insert("title".into(), Value::from(r.title.clone()));
    }
    if !r.message.is_empty() {
        m.insert("message".into(), Value::from(r.message.clone()));
    }
    m.insert("createdAt".into(), Value::from(r.created_at));
    if let Some(t) = r.read_at {
        m.insert("readAt".into(), Value::from(t));
    }
    for (k, v) in [("mimeUrl", r.mime_url.as_ref()), ("notificationCategory", Some(&r.notification_category)), ("url", r.url.as_ref())] {
        if let Some(v) = v.filter(|v| !v.is_empty()) {
            m.insert(k.into(), Value::from(v.clone()));
        }
    }
    Value::Object(m)
}

fn not_blank(s: Option<&str>) -> Option<&str> {
    s.filter(|v| !connections::java::is_blank(v))
}

pub struct InAppService {
    pub dao: Dao,
    /// To the recipients' open streams, on every instance ([`Push`]).
    pub push: Arc<Push>,
}

impl InAppService {
    /// `checkForNewNotifications`: 0 for a blank app code.
    pub async fn check_for_new(&self, app_code: Option<&str>, notification_type: Option<&str>, user_id: u64) -> Result<i64> {
        let Some(app_code) = app_code.filter(|a| !connections::java::is_blank(a)) else { return Ok(0) };
        let notification_type = not_blank(notification_type);
        self.dao.count_unread(&InAppFilter { app_code, user_id, notification_type, category: None }).await
    }

    /// `readNotifications`: one page, newest first; the rows returned are then marked read
    /// (the page still shows them as they were before).
    pub async fn read(
        &self,
        app_code: Option<&str>,
        notification_type: Option<&str>,
        category: Option<&str>,
        pageable: &Pageable,
        user_id: u64,
    ) -> Result<Value> {
        let Some(app_code) = app_code.filter(|a| !connections::java::is_blank(a)) else {
            return Ok(page_json(Vec::new(), pageable));
        };
        let filter = InAppFilter { app_code, user_id, notification_type: not_blank(notification_type), category: not_blank(category) };
        let rows = self.dao.page(&filter, pageable.size, pageable.offset()).await?;
        if !rows.is_empty() {
            let ids: Vec<u64> = rows.iter().map(|r| r.id).collect();
            self.dao.mark_read(&ids).await?;
        }
        Ok(page_json(rows.iter().map(list_item_json).collect(), pageable))
    }
}

#[async_trait]
impl InAppSink for InAppService {
    /// `sendInApp`: renders the `inapp` template once, stores a row per recipient, then sends
    /// each stored row to that recipient's open streams for the app, on whichever instance they
    /// are open (Java reached only the consuming instance's).
    async fn send_in_app(
        &self,
        users: &[NotificationUser],
        notification: &CoreNotification,
        app_code: Option<&str>,
        category: Option<&str>,
        payload: &Map<String, Value>,
    ) -> Result<()> {
        let lang = language(notification, payload)?;
        let template = processed_template(lang.as_deref(), notification.channel(INAPP_TEMPLATE_NAME), payload)?;
        if template.is_empty() {
            return Ok(());
        }
        let category = category.filter(|c| !c.is_empty()).unwrap_or("Default");
        let notification_type = notification
            .notification_type
            .as_deref()
            .ok_or_else(|| anyhow!("Cannot invoke \"NotificationType.name()\" because the notification type is null"))?;
        let app = app_code.ok_or_else(|| anyhow!("Column 'APP_CODE' cannot be null"))?;

        let mut stored = Vec::with_capacity(users.len());
        for u in users {
            let id = u.id.ok_or_else(|| anyhow!("Cannot invoke \"java.lang.Long.longValue()\" because the user id is null"))?;
            let user_id = u64::try_from(id).map_err(|_| anyhow!("Value is out of range : {id}"))?;
            stored.push(
                self.dao
                    .insert_inapp(&NewInApp {
                        user_id,
                        app_code: app,
                        notification_name: notification.name.as_deref(),
                        notification_type,
                        notification_category: category,
                        title: template.get("title").map(String::as_str),
                        message: template.get("description").map(String::as_str),
                        mime_url: template.get("image").map(String::as_str),
                        url: template.get("url").map(String::as_str),
                    })
                    .await?,
            );
        }

        for row in &stored {
            let k = key(row.user_id, app);
            let frame = event_frame("notification", &event_json(row), &uuid::Uuid::new_v4().to_string(), 5000);
            self.push.deliver(&[k], &frame).await;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row() -> InAppRow {
        InAppRow {
            id: 5686,
            user_id: 142,
            app_code: "monkbars".into(),
            notification_name: "rsNotifParity".into(),
            title: "H\u{e9}llo Ann".into(),
            message: "Line one\nline \"two\" 3".into(),
            mime_url: Some("api/files/x.svg".into()),
            notification_type: "ALERT".into(),
            notification_category: "Parity".into(),
            url: Some("/page/Ann".into()),
            read_at: None,
            created_at: 1792121644,
        }
    }

    /// The event Java sent on 2026-10-16 for the same row.
    #[test]
    fn event_json_as_java_writes_it() {
        assert_eq!(
            event_json(&row()),
            "{\n  \"id\" : 5686,\n  \"userId\" : 142,\n  \"appCode\" : \"monkbars\",\n  \"notificationName\" : \"rsNotifParity\",\n  \"title\" : \"H\u{e9}llo Ann\",\n  \"message\" : \"Line one\\nline \\\"two\\\" 3\",\n  \"mimeUrl\" : \"api/files/x.svg\",\n  \"notificationType\" : \"ALERT\"\n}"
        );
        let bare = InAppRow { mime_url: None, title: String::new(), ..row() };
        let j = event_json(&bare);
        assert!(!j.contains("mimeUrl") && !j.contains("title"));
    }

    /// The list item Java sent on 2026-10-16 for the same row.
    #[test]
    fn list_item_as_java_writes_it() {
        assert_eq!(
            list_item_json(&row()),
            serde_json::json!({"id": 5686, "title": "H\u{e9}llo Ann", "message": "Line one\nline \"two\" 3", "createdAt": 1792121644,
                "mimeUrl": "api/files/x.svg", "notificationCategory": "Parity", "url": "/page/Ann"})
        );
        let read = InAppRow { read_at: Some(1792121700), url: None, mime_url: Some(String::new()), message: String::new(), title: String::new(), ..row() };
        let v = list_item_json(&read);
        assert_eq!(v["readAt"], 1792121700);
        assert!(v.get("url").is_none() && v.get("mimeUrl").is_none() && v.get("message").is_none() && v.get("title").is_none());
        let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["id", "createdAt", "readAt", "notificationCategory"]);
    }
}
