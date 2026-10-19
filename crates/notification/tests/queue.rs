//! The listener: how each delivery is settled, and (gated) a round trip through scratch
//! exchanges and queues of the local broker, deleted afterwards. Never the real
//! `notifications` exchange or queues.

mod common;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use common::{local_stack, Answer, Fake, CONN_PATH, NOTIF_PATH, USERS_PATH};
use lapin::options::{BasicPublishOptions, ExchangeDeleteOptions, QueueDeclareOptions, QueueDeleteOptions};
use lapin::types::{FieldTable, ShortString};
use lapin::{BasicProperties, Connection, ConnectionProperties};
use notification::calls::{CoreClient, DirectoryClient};
use notification::config::QueueSection;
use notification::email::EmailSink;
use notification::inapp::InAppSink;
use notification::model::{CoreNotification, MailConnection, NotificationUser};
use notification::queue::{consume_forever, handle, ConsumerState, Settle};
use notification::send::{Outcome, SendService};
use parking_lot::Mutex;
use platform::upstream::Upstream;
use serde_json::{json, Map, Value};

#[derive(Default)]
struct Seen(Mutex<Vec<String>>);

#[async_trait]
impl InAppSink for Seen {
    async fn send_in_app(&self, _: &[NotificationUser], n: &CoreNotification, _: Option<&str>, _: Option<&str>, p: &Map<String, Value>) -> Result<()> {
        self.0.lock().push(format!("{}:{}", n.name.clone().unwrap_or_default(), p.get("i").cloned().unwrap_or(Value::Null)));
        Ok(())
    }
}

#[async_trait]
impl EmailSink for Seen {
    async fn send_email(&self, _: &NotificationUser, _: &MailConnection, _: &CoreNotification, _: &Map<String, Value>) -> Result<bool> {
        Ok(true)
    }
}

async fn service() -> (Arc<SendService>, Arc<Fake>, Arc<Seen>) {
    let (fake, base) = Fake::start().await;
    fake.answer("GET", CONN_PATH, Answer::json(json!({"inApp": true})));
    fake.answer("GET", NOTIF_PATH, Answer::json(json!({"name": "n", "channelTemplates": {"inapp": {}}})));
    fake.answer("POST", USERS_PATH, Answer::json(json!([{"id": 142}])));
    let seen = Arc::new(Seen::default());
    let t = Duration::from_secs(5);
    let s = SendService {
        core: CoreClient::new(Upstream::fixed(&[&base]), t).unwrap(),
        directory: DirectoryClient::new(Upstream::fixed(&[&base]), t).unwrap(),
        email: seen.clone(),
        in_app: seen.clone(),
    };
    (Arc::new(s), fake, seen)
}

const BODY: &[u8] = br#"{"appCode":"app","clientCode":"SYSTEM","urlClientCode":"SYSTEM","targetType":"User Id","targetId":142,"notificationName":"n","connectionName":"c","draft":false,"payload":{"i":1}}"#;

#[tokio::test]
async fn deliveries_are_settled_as_spring_settles_them() {
    let (s, fake, seen) = service().await;
    assert_eq!(handle(&s, Some("application/json"), BODY).await, Settle::Ack(Some(Outcome::Sent { emails: 0, in_app: true })));
    assert_eq!(*seen.0.lock(), ["n:1"]);
    // Unreadable, or not declared as JSON: rejected for good.
    assert_eq!(handle(&s, Some("application/json"), b"not json").await, Settle::Drop);
    assert_eq!(handle(&s, Some("application/json"), br#"{"targetId":"x"}"#).await, Settle::Drop);
    assert_eq!(handle(&s, Some("text/plain"), BODY).await, Settle::Drop);
    // No content type is read as JSON.
    assert!(matches!(handle(&s, None, BODY).await, Settle::Ack(Some(_))));
    // A failing send is acked too: the listener only logs it.
    fake.answer("GET", CONN_PATH, Answer::error(500, "core down"));
    assert_eq!(handle(&s, Some("application/json"), BODY).await, Settle::Ack(None));
    // A quiet end (no connection) is a normal ack.
    fake.answer("GET", CONN_PATH, Answer::empty());
    assert_eq!(handle(&s, Some("application/json"), BODY).await, Settle::Ack(Some(Outcome::NoConnection)));
}

#[test]
fn deliveries_are_counted() {
    use notification::queue::{CONSUMED, FAILED, SENT};
    let ((), text) = platform::meter::capture_async(async {
        let (s, fake, _) = service().await;
        handle(&s, Some("application/json"), BODY).await;
        handle(&s, Some("application/json"), b"not json").await;
        handle(&s, Some("text/plain"), BODY).await;
        fake.answer("GET", CONN_PATH, Answer::error(500, "core down"));
        handle(&s, Some("application/json"), BODY).await;
        fake.answer("GET", CONN_PATH, Answer::empty());
        handle(&s, Some("application/json"), BODY).await;
    });
    let n = |name: &str, labels: &[(&str, &str)]| platform::meter::sample(&text, name, labels);
    assert_eq!(n(CONSUMED, &[]), Some(5.0));
    assert_eq!(n(SENT, &[("channel", "in_app")]), Some(1.0));
    assert_eq!(n(FAILED, &[("reason", "unreadable")]), Some(2.0));
    assert_eq!(n(FAILED, &[("reason", "error")]), Some(1.0));
    assert_eq!(n(FAILED, &[("reason", "no_connection")]), Some(1.0));
    // The calls to core and security are timed by the service their paths name.
    assert!(n("http_client_request_duration_seconds_count", &[("target", "core"), ("status", "200")]).is_some(), "{text}");
}

async fn message_count(ch: &lapin::Channel, q: &str) -> u32 {
    ch.queue_declare(ShortString::from(q), QueueDeclareOptions { passive: true, ..Default::default() }, FieldTable::default())
        .await
        .unwrap()
        .message_count()
}

#[tokio::test]
#[ignore = "needs the local RabbitMQ: NOTIFICATION_LOCAL_STACK=1"]
async fn messages_published_to_the_queues_are_sent_and_acked() {
    if !local_stack() {
        return;
    }
    let uri = std::env::var("MODLIX__MQ__URI").ok().filter(|u| !u.is_empty()).unwrap_or_else(|| "amqp://guest:guest@localhost:5672/%2f".into());
    let tag = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let exchange = format!("rs_scratch_notif_x_{tag}");
    let queues: Vec<String> = (1..=2).map(|i| format!("rs_scratch_notif{i}_{tag}")).collect();
    assert!(queues.iter().all(|q| q.starts_with("rs_scratch_")));
    let settings = QueueSection { queues: queues.join(","), prefetch: 4, declare: true, exchange: exchange.clone() };
    let (s, _, seen) = service().await;
    let state = ConsumerState::default();
    let consumer = tokio::spawn(consume_forever(s, uri.clone(), settings, state.clone()));
    for _ in 0..100 {
        if state.connected() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(state.connected(), "the consumer did not start");

    let conn = Connection::connect(&uri, ConnectionProperties::default()).await.unwrap();
    let ch = conn.create_channel().await.unwrap();
    let props = connections::mq::message_properties(connections::mq::NOTIFICATION_TYPE_ID);
    for i in 0..4 {
        let body = String::from_utf8_lossy(BODY).replace(r#""i":1"#, &format!(r#""i":{i}"#));
        ch.basic_publish(
            ShortString::from(exchange.as_str()),
            ShortString::from(queues[i % 2].as_str()),
            BasicPublishOptions::default(),
            body.as_bytes(),
            props.clone(),
        )
        .await
        .unwrap();
    }
    // Unreadable bodies are rejected, not requeued.
    ch.basic_publish(ShortString::from(exchange.as_str()), ShortString::from(queues[0].as_str()), BasicPublishOptions::default(), b"not json", props.clone())
        .await
        .unwrap();
    ch.basic_publish(
        ShortString::from(exchange.as_str()),
        ShortString::from(queues[1].as_str()),
        BasicPublishOptions::default(),
        BODY,
        BasicProperties::default().with_content_type(ShortString::from("text/plain")),
    )
    .await
    .unwrap();
    for _ in 0..100 {
        if seen.0.lock().len() == 4 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let left: Vec<u32> = futures::future::join_all(queues.iter().map(|q| message_count(&ch, q))).await;
    consumer.abort();
    for q in &queues {
        ch.queue_delete(ShortString::from(q.as_str()), QueueDeleteOptions::default()).await.unwrap();
    }
    ch.exchange_delete(ShortString::from(exchange.as_str()), ExchangeDeleteOptions::default()).await.unwrap();
    let mut names = seen.0.lock().clone();
    names.sort();
    assert_eq!(names, ["n:0", "n:1", "n:2", "n:3"]);
    assert_eq!(left, [0, 0], "every delivery was acked or dropped");
}

#[tokio::test]
#[ignore = "needs the local RabbitMQ: NOTIFICATION_LOCAL_STACK=1"]
async fn an_unreachable_broker_is_retried() {
    if !local_stack() {
        return;
    }
    let (s, _, _) = service().await;
    let state = ConsumerState::default();
    let task = tokio::spawn(consume_forever(s, "amqp://guest:guest@127.0.0.1:1/%2f".into(), QueueSection::default(), state.clone()));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!state.connected());
    task.abort();
}
