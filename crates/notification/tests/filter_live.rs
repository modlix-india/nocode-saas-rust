//! A normal (bell) notification with `filterAuthorization`, against the local security-internal
//! (`users/internal/notification`, read only) and a `RUSTTEST_notif_*` scratch schema (gated:
//! `NOTIFICATION_LOCAL_STACK=1`, from `eval "$(tools/local-env.py)"`). Core's definitions are a
//! fake; the message goes through the listener's `handle` as core publishes it, never through
//! the real `notifications` queues. DIFFERENCES N15.

mod common;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use common::{local_stack, with_scratch, Answer, Fake, CONN_PATH, NOTIF_PATH};
use notification::calls::{CoreClient, DirectoryClient};
use notification::dao::Dao;
use notification::email::EmailSink;
use notification::inapp::InAppService;
use notification::model::{CoreNotification, MailConnection, NotificationUser};
use notification::push::Push;
use notification::queue::{handle, Settle};
use notification::send::{Outcome, SendService};
use notification::sse::Hub;
use parking_lot::Mutex;
use platform::upstream::Upstream;
use serde_json::{json, Map, Value};

/// security-internal, as `config/notification.toml` names it on the local stack.
const SECURITY_INTERNAL: &str = "http://localhost:8112";

/// Records who would be mailed; sends nothing.
#[derive(Default)]
struct Mails(Mutex<Vec<Option<i64>>>);

#[async_trait]
impl EmailSink for Mails {
    async fn send_email(&self, user: &NotificationUser, _: &MailConnection, _: &CoreNotification, _: &Map<String, Value>) -> Result<bool> {
        self.0.lock().push(user.id);
        Ok(true)
    }
}

#[tokio::test]
#[ignore = "needs the local MySQL and security-internal: NOTIFICATION_LOCAL_STACK=1"]
async fn a_filtered_notification_reaches_only_the_users_holding_the_authority() {
    if !local_stack() {
        return;
    }
    with_scratch(|pool, _| async move {
        let (core, core_base) = Fake::start().await;
        core.answer("GET", CONN_PATH, Answer::json(json!({"inApp": true, "mail": {"connectionSubType": "SMTP"}})));
        core.answer(
            "GET",
            NOTIF_PATH,
            Answer::json(json!({"name": "hello", "notificationType": "INFO",
                "channelTemplates": {"inapp": {"templateParts": {"en": {"title": "Hi", "description": "d"}}}, "email": {}}})),
        );
        let t = Duration::from_secs(5);
        let mails = Arc::new(Mails::default());
        let push = Push::local(Hub::new(16));
        let service = SendService {
            core: CoreClient::new(Upstream::fixed(&[&core_base]), t).unwrap(),
            directory: DirectoryClient::new(Upstream::fixed(&[SECURITY_INTERNAL]), t).unwrap(),
            email: mails.clone(),
            in_app: Arc::new(InAppService { dao: Dao::new(pool.clone()), push: push.clone() }),
            push,
        };
        let message = |filter: &str| {
            json!({"appCode": "appbuilder", "clientCode": "SYSTEM", "urlClientCode": "SYSTEM", "targetType": "User Id",
                "targetId": 142, "filterAuthorization": filter, "notificationName": "hello", "connectionName": "c", "draft": false})
            .to_string()
        };
        let rows = || async {
            let r: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM notification_inapp").fetch_one(&pool).await.unwrap();
            r.0
        };

        // The SYSTEM user 142 is signed in to appbuilder: a filter it meets keeps it.
        let settled = handle(&service, Some("application/json"), message("Authorities.Logged_IN").as_bytes()).await;
        assert_eq!(settled, Settle::Ack(Some(Outcome::Sent { emails: 1, in_app: true })));
        assert_eq!(*mails.0.lock(), vec![Some(142)]);
        assert_eq!(rows().await, 1);

        // A filter nobody meets: no mail, no bell row.
        let settled = handle(&service, Some("application/json"), message("Authorities.RS_Test_Nobody_Holds_This").as_bytes()).await;
        assert_eq!(settled, Settle::Ack(Some(Outcome::NoUsers)));
        assert_eq!(mails.0.lock().len(), 1);
        assert_eq!(rows().await, 1);
    })
    .await;
}
