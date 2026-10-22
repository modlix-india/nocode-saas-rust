//! `NotificationSendService` against fakes of core and security, with recording email and
//! in-app sinks (as the Java test mocks those two services).

mod common;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use common::{Answer, Fake, CONN_PATH, NOTIF_PATH, USERS_PATH};
use notification::calls::{CoreClient, DirectoryClient};
use notification::email::EmailSink;
use notification::inapp::InAppSink;
use notification::model::{CoreNotification, MailConnection, NotificationUser, QueueMessage};
use notification::push::Push;
use notification::send::{Outcome, SendService};
use notification::sse::Hub;
use parking_lot::Mutex;
use platform::upstream::Upstream;
use serde_json::{json, Map, Value};

#[derive(Default)]
struct Sinks {
    emails: Mutex<Vec<(Option<i64>, Option<String>)>>,
    in_app: Mutex<Vec<(usize, Option<String>, Option<String>, Value)>>,
    fail_email: Mutex<bool>,
}

#[async_trait]
impl EmailSink for Sinks {
    async fn send_email(&self, user: &NotificationUser, mail: &MailConnection, _: &CoreNotification, _: &Map<String, Value>) -> Result<bool> {
        if *self.fail_email.lock() {
            anyhow::bail!("SendGrid refused");
        }
        self.emails.lock().push((user.id, mail.connection_sub_type.clone()));
        Ok(true)
    }
}

#[async_trait]
impl InAppSink for Sinks {
    async fn send_in_app(
        &self,
        users: &[NotificationUser],
        _: &CoreNotification,
        app_code: Option<&str>,
        category: Option<&str>,
        payload: &Map<String, Value>,
    ) -> Result<()> {
        self.in_app.lock().push((users.len(), app_code.map(str::to_string), category.map(str::to_string), Value::Object(payload.clone())));
        Ok(())
    }
}

struct Rig {
    core: Arc<Fake>,
    core_base: String,
    security: Arc<Fake>,
    sinks: Arc<Sinks>,
    service: SendService,
}

async fn rig() -> Rig {
    let (core, core_base) = Fake::start().await;
    let (security, sec_base) = Fake::start().await;
    let sinks = Arc::new(Sinks::default());
    let t = Duration::from_secs(5);
    let service = SendService {
        core: CoreClient::new(Upstream::fixed(&[&core_base]), t).unwrap(),
        directory: DirectoryClient::new(Upstream::fixed(&[&sec_base]), t).unwrap(),
        email: sinks.clone(),
        in_app: sinks.clone(),
        push: Push::local(Hub::new(8)),
    };
    // Only the in-app channel: which channel fires is not what the draft tests are about.
    core.answer("GET", CONN_PATH, Answer::json(json!({"inApp": true})));
    core.answer("GET", NOTIF_PATH, Answer::json(json!({"name": "testNotification", "channelTemplates": {"inapp": {}}})));
    security.answer("POST", USERS_PATH, Answer::json(json!([{}])));
    Rig { core, core_base, security, sinks, service }
}

/// `NotificationDraftHeaderTest.message(draft)`.
fn message(draft: bool) -> QueueMessage {
    QueueMessage {
        app_code: Some("testapp".into()),
        client_code: Some("SYSTEM".into()),
        url_client_code: Some("SYSTEM".into()),
        target_type: Some("User Id".into()),
        target_id: Some(1),
        notification_name: Some("testNotification".into()),
        notification_category: Some("SYSTEM".into()),
        connection_name: Some("appNotification".into()),
        draft,
        ..Default::default()
    }
}

// ----------------------------------------------------------- NotificationDraftHeaderTest

/// "a draft message resolves both definitions on the draft surface"
#[tokio::test]
async fn draft_message_asks_core_for_drafts() {
    let r = rig().await;
    r.service.send(&message(true)).await.unwrap();
    let conn = r.core.calls_to(CONN_PATH);
    let notif = r.core.calls_to(NOTIF_PATH);
    assert_eq!(conn[0].header("x-draft").as_deref(), Some("true"), "the connection was resolved from the live surface");
    assert_eq!(notif[0].header("x-draft").as_deref(), Some("true"), "the notification definition was resolved from the live surface");
}

/// "a live message sends no header at all": not `false`, absent.
#[tokio::test]
async fn live_message_sends_no_header() {
    let r = rig().await;
    r.service.send(&message(false)).await.unwrap();
    assert!(r.core.calls_to(CONN_PATH)[0].headers.get("x-draft").is_none(), "a live notification must not carry the draft header");
    assert!(r.core.calls_to(NOTIF_PATH)[0].headers.get("x-draft").is_none(), "a live notification must not carry the draft header");
}

/// "recipients come from the real user directory on both surfaces"
#[tokio::test]
async fn recipients_ignore_the_marker() {
    let r = rig().await;
    r.service.send(&message(true)).await.unwrap();
    let users = r.security.calls_to(USERS_PATH);
    assert_eq!(users.len(), 1);
    let req = users[0].json();
    assert!(req.as_object().unwrap().keys().all(|k| !k.to_lowercase().contains("draft")), "UsersListRequest grew a draft dimension");
    assert_eq!(req["appCode"], "testapp");
}

/// "only the core definition lookups declare the header": every security call of a draft run
/// goes out without it.
#[tokio::test]
async fn only_core_lookups_carry_the_header() {
    let r = rig().await;
    r.service.send(&message(true)).await.unwrap();
    let core_calls = r.core.calls.lock().clone();
    assert_eq!(core_calls.iter().filter(|c| c.header("x-draft").is_some()).count(), 2);
    assert!(r.security.calls.lock().iter().all(|c| c.header("x-draft").is_none()));
}

// ------------------------------------------------------------------------------- flows

#[tokio::test]
async fn definition_reads_carry_the_message_codes() {
    let r = rig().await;
    let mut m = message(false);
    m.x_debug = Some("dbg-9".into());
    m.connection_name = Some("conn name".into());
    r.service.send(&m).await.unwrap();
    let c = &r.core.calls_to(CONN_PATH)[0];
    assert_eq!(c.path, "/api/core/connections/internal/notification/conn%20name");
    assert_eq!(c.query, "appCode=testapp&clientCode=SYSTEM&urlClientCode=SYSTEM");
    assert_eq!(c.header("x-debug").as_deref(), Some("dbg-9"));
    let n = &r.core.calls_to(NOTIF_PATH)[0];
    assert_eq!(n.path, "/api/core/notifications/internal/testNotification");
    assert_eq!(r.security.calls_to(USERS_PATH)[0].header("x-debug").as_deref(), Some("dbg-9"));
    assert_eq!(*r.sinks.in_app.lock(), vec![(1, Some("testapp".into()), Some("SYSTEM".into()), json!({}))]);

    // Unset codes are left out of the query.
    let mut m = message(false);
    m.client_code = None;
    m.url_client_code = None;
    r.core.clear();
    r.service.send(&m).await.unwrap();
    assert_eq!(r.core.calls_to(CONN_PATH)[0].query, "appCode=testapp");
}

#[tokio::test]
async fn missing_definitions_end_quietly() {
    let r = rig().await;
    r.core.answer("GET", CONN_PATH, Answer::empty());
    assert_eq!(r.service.send(&message(false)).await.unwrap(), Outcome::NoConnection);
    assert!(r.core.calls_to(NOTIF_PATH).is_empty());

    r.core.answer("GET", CONN_PATH, Answer::json(json!({"inApp": true})));
    r.core.answer("GET", NOTIF_PATH, Answer::empty());
    assert_eq!(r.service.send(&message(false)).await.unwrap(), Outcome::NoNotification);
    assert!(r.security.calls_to(USERS_PATH).is_empty());
}

#[tokio::test]
async fn failures_of_the_calls_are_errors() {
    let r = rig().await;
    r.core.answer("GET", CONN_PATH, Answer::error(500, "boom"));
    assert!(r.service.send(&message(false)).await.is_err());
    r.core.answer("GET", CONN_PATH, Answer::status(200, "not json"));
    assert!(r.service.send(&message(false)).await.is_err());
    r.core.answer("GET", CONN_PATH, Answer::json(json!({"inApp": true, "mail": 3})));
    assert!(r.service.send(&message(false)).await.is_err());
    r.core.answer("GET", CONN_PATH, Answer::json(json!({"inApp": true})));
    r.core.answer("GET", NOTIF_PATH, Answer::json(json!({"notificationType": "NOPE"})));
    assert!(r.service.send(&message(false)).await.is_err());
    r.core.answer("GET", NOTIF_PATH, Answer::json(json!({"channelTemplates": {"inapp": {}}})));
    r.security.answer("POST", USERS_PATH, Answer::error(500, "down"));
    assert!(r.service.send(&message(false)).await.is_err());
    // An empty answer is a null list, which Java dereferences.
    r.security.answer("POST", USERS_PATH, Answer::empty());
    assert!(r.service.send(&message(false)).await.unwrap_err().to_string().contains("users"));
    r.security.answer("POST", USERS_PATH, Answer::json(json!({"id": 1})));
    assert!(r.service.send(&message(false)).await.is_err());
    r.security.answer("POST", USERS_PATH, Answer::json(json!([{"id": "x"}])));
    assert!(r.service.send(&message(false)).await.is_err());
    // An unreachable core.
    let dead = SendService {
        core: CoreClient::new(Upstream::fixed(&["http://127.0.0.1:1"]), Duration::from_secs(1)).unwrap(),
        ..r.service
    };
    assert!(dead.send(&message(false)).await.is_err());
}

#[tokio::test]
async fn channels_are_chosen_from_connection_and_templates() {
    let r = rig().await;
    // A mail connection but only an in-app template: in-app only.
    r.core.answer("GET", CONN_PATH, Answer::json(json!({"inApp": true, "mail": {"connectionSubType": "SMTP"}})));
    assert_eq!(r.service.send(&message(false)).await.unwrap(), Outcome::Sent { emails: 0, in_app: true });

    // Both templates, both channels; every recipient gets mail, then in-app runs once.
    r.core.answer("GET", NOTIF_PATH, Answer::json(json!({"channelTemplates": {"inapp": {}, "email": {}}})));
    r.security.answer("POST", USERS_PATH, Answer::json(json!([{"id": 1}, {"id": 2, "emailId": "b@x.com"}])));
    assert_eq!(r.service.send(&message(false)).await.unwrap(), Outcome::Sent { emails: 2, in_app: true });
    assert_eq!(*r.sinks.emails.lock(), vec![(Some(1), Some("SMTP".into())), (Some(2), Some("SMTP".into()))]);

    // The connection does not allow in-app: email only.
    r.core.answer("GET", CONN_PATH, Answer::json(json!({"inApp": false, "mail": {"connectionSubType": "SENDGRID"}})));
    assert_eq!(r.service.send(&message(false)).await.unwrap(), Outcome::Sent { emails: 2, in_app: false });

    // No mail connection and no in-app: nothing to send, and no recipients asked for.
    r.security.clear();
    r.core.answer("GET", CONN_PATH, Answer::json(json!({"inApp": false})));
    assert_eq!(r.service.send(&message(false)).await.unwrap(), Outcome::NoChannel);
    assert!(r.security.calls_to(USERS_PATH).is_empty());

    // In-app allowed but no in-app template (only email), and no mail connection.
    r.core.answer("GET", CONN_PATH, Answer::json(json!({"inApp": true})));
    r.core.answer("GET", NOTIF_PATH, Answer::json(json!({"channelTemplates": {"email": {}}})));
    assert_eq!(r.service.send(&message(false)).await.unwrap(), Outcome::NoChannel);

    // Channel templates missing altogether: Java dereferences them.
    r.core.answer("GET", NOTIF_PATH, Answer::json(json!({"name": "n"})));
    assert!(r.service.send(&message(false)).await.is_err());
    // ... but not when neither channel needs them.
    r.core.answer("GET", CONN_PATH, Answer::json(json!({"inApp": false})));
    assert_eq!(r.service.send(&message(false)).await.unwrap(), Outcome::NoChannel);
}

#[tokio::test]
async fn a_failed_mail_stops_the_rest() {
    let r = rig().await;
    r.core.answer("GET", CONN_PATH, Answer::json(json!({"inApp": true, "mail": {"connectionSubType": "SENDGRID"}})));
    r.core.answer("GET", NOTIF_PATH, Answer::json(json!({"channelTemplates": {"inapp": {}, "email": {}}})));
    *r.sinks.fail_email.lock() = true;
    assert!(r.service.send(&message(false)).await.is_err());
    assert!(r.sinks.in_app.lock().is_empty(), "in-app never ran");
}

#[tokio::test]
async fn targets_become_the_users_request() {
    let r = rig().await;
    let request = |m: QueueMessage| {
        let r = &r;
        async move {
            r.security.clear();
            let out = r.service.send(&m).await;
            (out, r.security.calls_to(USERS_PATH).first().map(|c| c.json()))
        }
    };
    let (_, req) = request(QueueMessage { target_id: Some(142), ..message(false) }).await;
    assert_eq!(req.unwrap(), json!({"userIds": [142], "appCode": "testapp"}));
    let (_, req) = request(QueueMessage { target_type: Some("Client Id".into()), target_id: Some(4), ..message(false) }).await;
    assert_eq!(req.unwrap(), json!({"clientId": 4, "appCode": "testapp"}));
    let (_, req) = request(QueueMessage { target_type: Some("Client Code".into()), target_code: Some("FIN".into()), ..message(false) }).await;
    assert_eq!(req.unwrap(), json!({"clientCode": "FIN", "appCode": "testapp"}));
    let (_, req) = request(QueueMessage { target_type: Some("Anyone".into()), ..message(false) }).await;
    assert_eq!(req.unwrap(), json!({"appCode": "testapp"}), "an unknown target narrows nothing");

    let (out, req) = request(QueueMessage { target_type: None, ..message(false) }).await;
    assert!(out.is_err() && req.is_none(), "a null target type");
    let (out, req) = request(QueueMessage { target_id: None, ..message(false) }).await;
    assert!(out.is_err() && req.is_none(), "a null user id");
    let (out, _) = request(QueueMessage { target_type: Some("Client Id".into()), target_id: None, ..message(false) }).await;
    assert!(out.is_err(), "a null client id");

    r.security.answer("POST", USERS_PATH, Answer::json(json!([])));
    let (out, _) = request(message(false)).await;
    assert_eq!(out.unwrap(), Outcome::NoUsers);
}

/// A normal (bell and email) notification asks security only for the users holding its
/// `filterAuthorization` (DIFFERENCES N15), and both channels go to exactly those users.
#[tokio::test]
async fn the_authority_filter_narrows_a_normal_notification() {
    let r = rig().await;
    r.core.answer("GET", CONN_PATH, Answer::json(json!({"inApp": true, "mail": {"connectionSubType": "SMTP"}})));
    r.core.answer("GET", NOTIF_PATH, Answer::json(json!({"channelTemplates": {"inapp": {}, "email": {}}})));
    // Security answers the users that meet the filter: one of the client's users.
    r.security.answer("POST", USERS_PATH, Answer::json(json!([{"id": 7}])));
    let m = QueueMessage {
        target_type: Some("Client Id".into()),
        target_id: Some(3),
        filter_authorization: Some("Authorities.Calls".into()),
        ..message(false)
    };
    assert_eq!(r.service.send(&m).await.unwrap(), Outcome::Sent { emails: 1, in_app: true });
    let asked = r.security.calls_to(USERS_PATH);
    assert_eq!(asked[0].json(), json!({"clientId": 3, "appCode": "testapp", "filterAuthorization": "Authorities.Calls"}));
    assert_eq!(*r.sinks.emails.lock(), vec![(Some(7), Some("SMTP".into()))]);
    assert_eq!(r.sinks.in_app.lock()[0].0, 1, "the in-app rows are for the filtered users only");

    // A blank filter is no filter.
    r.security.clear();
    r.service.send(&QueueMessage { filter_authorization: Some("  ".into()), ..m.clone() }).await.unwrap();
    assert_eq!(r.security.calls_to(USERS_PATH)[0].json(), json!({"clientId": 3, "appCode": "testapp"}));

    // Nobody meets it: nothing more is sent.
    r.security.answer("POST", USERS_PATH, Answer::json(json!([])));
    let (emails, in_app) = (r.sinks.emails.lock().len(), r.sinks.in_app.lock().len());
    assert_eq!(r.service.send(&m).await.unwrap(), Outcome::NoUsers);
    assert_eq!((r.sinks.emails.lock().len(), r.sinks.in_app.lock().len()), (emails, in_app));
}

#[tokio::test]
async fn the_connection_read_can_have_its_own_upstream() {
    let r = rig().await;
    // core-exec answers the connection read, core-editor (the rig's core fake) the definition.
    let (exec, exec_base) = Fake::start().await;
    exec.answer("GET", CONN_PATH, Answer::json(json!({"inApp": true})));
    let svc = SendService {
        core: CoreClient::with_connections(Upstream::fixed(&[&r.core_base]), Upstream::fixed(&[&exec_base]), Duration::from_secs(5)).unwrap(),
        ..r.service
    };
    svc.send(&message(false)).await.unwrap();
    assert_eq!(exec.calls_to(CONN_PATH).len(), 1);
    assert!(exec.calls_to(NOTIF_PATH).is_empty());
    assert!(r.core.calls_to(CONN_PATH).is_empty());
    assert_eq!(r.core.calls_to(NOTIF_PATH).len(), 1);
}

#[tokio::test]
async fn payload_reaches_the_sinks() {
    let r = rig().await;
    let m = QueueMessage { payload: Some(json!({"who": "Ann"}).as_object().unwrap().clone()), notification_category: None, ..message(false) };
    r.service.send(&m).await.unwrap();
    assert_eq!(r.sinks.in_app.lock()[0], (1, Some("testapp".into()), None, json!({"who": "Ann"})));
}

// ----------------------------------------------------------------- data notifications

/// A data notification for the users of client 3 holding `Authorities.Calls`.
fn data_message(expires_at: Option<i128>) -> QueueMessage {
    QueueMessage {
        app_code: Some("leadzumptwo".into()),
        client_code: Some("FIN".into()),
        target_type: Some("Client Id".into()),
        target_id: Some(3),
        filter_authorization: Some("Authorities.Calls".into()),
        kind: Some("DATA".into()),
        event_name: Some("incomingCall".into()),
        data: Some(json!({"from": "+9180", "lead": {"id": 9}})),
        expires_at,
        ..Default::default()
    }
}

#[tokio::test]
async fn a_data_notification_reaches_the_open_streams_and_nothing_else() {
    use futures::StreamExt;
    let r = rig().await;
    let hub = Hub::new(8);
    let service = SendService { push: Push::local(hub.clone()), ..r.service };
    r.security.answer("POST", USERS_PATH, Answer::json(json!([{"id": 142, "clientId": 3}, {"id": 143, "clientId": 3}, {"id": 142, "clientId": 3}, {"clientId": 3}])));
    let mut a = hub.subscribe("142-leadzumptwo".into());
    let mut b = hub.subscribe("143-leadzumptwo".into());
    let mut other_app = hub.subscribe("142-leadzump".into());
    for s in [&mut a, &mut b, &mut other_app] {
        let _ = s.next().await;
    }
    let now = 1_792_634_021_000;
    let outcome = service.send_data(&data_message(Some(now + 60_000)), now).await.unwrap();
    assert_eq!(outcome, Outcome::Pushed { users: 2 }, "each user once");

    let frame = String::from_utf8(a.next().await.unwrap().unwrap().to_vec()).unwrap();
    assert!(frame.starts_with("event:incomingCall\ndata:{\"event\":\"incomingCall\",\"data\":{\"from\":\"+9180\",\"lead\":{\"id\":9}},\"id\":\""), "{frame}");
    let data_line = frame.lines().nth(1).unwrap().strip_prefix("data:").unwrap();
    let body: Value = serde_json::from_str(data_line).unwrap();
    assert_eq!(body["sentAt"], json!(now as i64));
    assert_eq!(frame.lines().nth(2).unwrap(), format!("id:{}", body["id"].as_str().unwrap()));
    assert!(frame.ends_with("\nretry:5000\n\n"));
    assert_eq!(String::from_utf8(b.next().await.unwrap().unwrap().to_vec()).unwrap(), frame);
    assert!(tokio::time::timeout(Duration::from_millis(50), other_app.next()).await.is_err(), "another app's stream hears nothing");

    // No definition was read, nothing went to email or in-app; recipients were asked for with
    // the authority filter.
    assert!(r.core.calls.lock().is_empty());
    assert!(r.sinks.emails.lock().is_empty() && r.sinks.in_app.lock().is_empty());
    let asked = r.security.calls_to(USERS_PATH);
    assert_eq!(asked[0].json(), json!({"clientId": 3, "appCode": "leadzumptwo", "filterAuthorization": "Authorities.Calls"}));

    // Through `send`, as the queue runs it: the clock is the real one.
    let far = i128::from(chrono::Utc::now().timestamp_millis()) + 60_000;
    assert_eq!(service.send(&data_message(Some(far))).await.unwrap(), Outcome::Pushed { users: 2 });
    assert_eq!(service.send(&data_message(None)).await.unwrap(), Outcome::Pushed { users: 2 }, "no expiry: delivered");
}

#[tokio::test]
async fn data_notifications_that_end_early() {
    let r = rig().await;
    let service = SendService { push: Push::local(Hub::new(8)), ..r.service };
    let now = 1_792_634_021_000;
    // Expired: dropped before anyone is asked.
    assert_eq!(service.send_data(&data_message(Some(now - 1)), now).await.unwrap(), Outcome::Expired);
    assert!(r.security.calls_to(USERS_PATH).is_empty());
    // Nobody to tell.
    r.security.answer("POST", USERS_PATH, Answer::json(json!([])));
    assert_eq!(service.send_data(&data_message(Some(now)), now).await.unwrap(), Outcome::NoUsers);
    r.security.answer("POST", USERS_PATH, Answer::json(json!([{"clientId": 3}])));
    assert_eq!(service.send_data(&data_message(None), now).await.unwrap(), Outcome::NoUsers, "users without ids");
    // Unusable messages fail (and are acked by the listener).
    let no_event = QueueMessage { event_name: None, ..data_message(None) };
    assert!(service.send_data(&no_event, now).await.unwrap_err().to_string().contains("event name"));
    let no_app = QueueMessage { app_code: Some(String::new()), ..data_message(None) };
    assert!(service.send_data(&no_app, now).await.unwrap_err().to_string().contains("app code"));
    r.security.answer("POST", USERS_PATH, Answer::json(json!({"not": "a list"})));
    assert!(service.send_data(&data_message(None), now).await.is_err());
    let unknown = QueueMessage { kind: Some("LATER".into()), ..data_message(None) };
    assert!(service.send(&unknown).await.unwrap_err().to_string().contains("Unknown notification kind: LATER"));
    assert!(r.core.calls.lock().is_empty());
}
