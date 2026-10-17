//! Publishing through the local RabbitMQ, on a scratch exchange and queue this test creates and
//! deletes (never the real `events` / `notifications` exchanges, whose Java consumers would act
//! on the messages).
//!
//! `MODLIX_TEST_AMQP_URI=amqp://user:pass@localhost:5672/%2f cargo test -p connections --test rabbitmq_live -- --ignored`

use async_trait::async_trait;
use connections::context::Caller;
use connections::error::ConnResult;
use connections::mq::{create_event, EventMessage, Publisher, Route};
use connections::notification::{process_and_send, HierarchyChecks, NotificationRequest};
use futures::StreamExt;
use lapin::options::{
    BasicAckOptions, BasicConsumeOptions, ExchangeDeclareOptions, ExchangeDeleteOptions, QueueBindOptions, QueueDeclareOptions,
    QueueDeleteOptions,
};
use lapin::types::{AMQPValue, FieldTable, ShortString};
use lapin::{Connection, ConnectionProperties, ExchangeKind};
use serde_json::{json, Value};

struct Deny;
#[async_trait]
impl HierarchyChecks for Deny {
    async fn is_user_part_of_hierarchy(&self, _: i128, _: &str) -> ConnResult<bool> {
        Ok(false)
    }
    async fn does_client_manage_client(&self, _: u64, _: i128) -> ConnResult<bool> {
        Ok(false)
    }
    async fn does_client_manage_client_code(&self, _: &str, _: &str) -> ConnResult<bool> {
        Ok(false)
    }
}

#[tokio::test]
#[ignore]
async fn publishes_java_shaped_messages_round_robin() {
    let uri = std::env::var("MODLIX_TEST_AMQP_URI").expect("MODLIX_TEST_AMQP_URI");
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let exchange = format!("rust-connections-scratch-{suffix}");
    let queue = format!("rust-connections-scratch-q-{suffix}");

    let admin = Connection::connect(&uri, ConnectionProperties::default()).await.unwrap();
    let ch = admin.create_channel().await.unwrap();
    ch.exchange_declare(
        ShortString::from(exchange.as_str()),
        ExchangeKind::Direct,
        ExchangeDeclareOptions { auto_delete: true, ..Default::default() },
        FieldTable::default(),
    )
    .await
    .unwrap();
    ch.queue_declare(
        ShortString::from(queue.as_str()),
        QueueDeclareOptions { exclusive: true, auto_delete: true, ..Default::default() },
        FieldTable::default(),
    )
    .await
    .unwrap();
    for key in ["scratch1", "scratch2", "scratch3"] {
        ch.queue_bind(
            ShortString::from(queue.as_str()),
            ShortString::from(exchange.as_str()),
            ShortString::from(key),
            QueueBindOptions::default(),
            FieldTable::default(),
        )
        .await
        .unwrap();
    }

    let publisher = Publisher::new(uri.clone());
    let events = Route::new(&exchange, "scratch1,scratch2,scratch3");
    let caller = Caller { present: true, authenticated: true, draft: true, debug: Some("dbg-7".into()), ..Default::default() };
    let mut sent = Vec::new();
    for i in 0..3 {
        let e = EventMessage {
            event_name: Some(format!("SCRATCH_{i}")),
            client_code: Some("SYSTEM".into()),
            app_code: Some("appbuilder".into()),
            data: Some(json!({"n": i}).as_object().unwrap().clone()),
            ..Default::default()
        };
        assert!(create_event(&publisher, &events, &caller, e.clone()).await.unwrap());
        let mut expected = e;
        expected.draft = true;
        expected.x_debug = Some("dbg-7".into());
        sent.push(expected.to_json());
    }
    // A system caller may notify anyone; the message goes on the same scratch route.
    let system = Caller {
        present: true,
        system_client: true,
        user_id: Some(142),
        client_code: Some("SYSTEM".into()),
        url_client_code: Some("SYSTEM".into()),
        url_app_code: Some("appbuilder".into()),
        ..Default::default()
    };
    let n = process_and_send(
        &publisher,
        &events,
        &Deny,
        &system,
        NotificationRequest { target_id: Some(7), target_type: "User Id".into(), notification_name: Some("hello".into()), ..Default::default() },
    )
    .await
    .unwrap();
    assert_eq!(n, Some(true));

    let mut consumer = ch
        .basic_consume(
            ShortString::from(queue.as_str()),
            ShortString::from("rust-connections-test"),
            BasicConsumeOptions::default(),
            FieldTable::default(),
        )
        .await
        .unwrap();
    let mut got = Vec::new();
    for _ in 0..4 {
        let d = tokio::time::timeout(std::time::Duration::from_secs(10), consumer.next()).await.unwrap().unwrap().unwrap();
        d.ack(BasicAckOptions::default()).await.unwrap();
        got.push(d);
    }

    let keys: Vec<String> = got.iter().map(|d| d.routing_key.to_string()).collect();
    assert_eq!(keys, ["scratch2", "scratch3", "scratch1", "scratch2"]);
    for (d, body) in got.iter().zip(&sent) {
        assert_eq!(String::from_utf8(d.data.clone()).unwrap(), *body);
    }
    let p = &got[0].properties;
    assert_eq!(p.content_type().as_ref().map(|s| s.to_string()).as_deref(), Some("application/json"));
    assert_eq!(p.content_encoding().as_ref().map(|s| s.to_string()).as_deref(), Some("UTF-8"));
    assert_eq!(*p.delivery_mode(), Some(2));
    assert_eq!(*p.priority(), Some(0));
    let type_id = p.headers().as_ref().unwrap().inner().get("__TypeId__").cloned();
    assert_eq!(type_id, Some(AMQPValue::LongString("com.fincity.saas.commons.mq.events.EventQueObject".into())));
    let note: Value = serde_json::from_slice(&got[3].data).unwrap();
    assert_eq!(note["notificationName"], "hello");
    assert_eq!(note["clientCode"], "SYSTEM");
    assert_eq!(note["triggeredUserId"], 142);
    let note_type = got[3].properties.headers().as_ref().unwrap().inner().get("__TypeId__").cloned();
    assert_eq!(note_type, Some(AMQPValue::LongString("com.fincity.saas.commons.mq.notifications.NotificationQueObject".into())));

    ch.queue_delete(ShortString::from(queue.as_str()), QueueDeleteOptions::default()).await.unwrap();
    ch.exchange_delete(ShortString::from(exchange.as_str()), ExchangeDeleteOptions::default()).await.unwrap();
    println!("published 4 messages on {exchange}, read them back from {queue}, deleted both");
}
