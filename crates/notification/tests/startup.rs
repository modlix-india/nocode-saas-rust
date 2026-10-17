//! The binary's startup path, end to end (gated: `NOTIFICATION_LOCAL_STACK=1`): configuration
//! from the environment, a scratch schema, scratch queues on the local broker, fakes of
//! security and core; a message published to the scratch exchange reaches a stream opened over
//! real HTTP. The schema, queues and exchange are removed afterwards.

mod common;

use std::time::Duration;

use common::{context, local_stack, with_scratch, Answer, Fake, AUTH_PATH, CONN_PATH, NOTIF_PATH, USERS_PATH};
use lapin::options::{BasicPublishOptions, ExchangeDeleteOptions, QueueDeleteOptions};
use lapin::types::ShortString;
use lapin::{Connection, ConnectionProperties};
use serde_json::json;

#[tokio::test]
#[ignore = "needs the local MySQL and RabbitMQ: NOTIFICATION_LOCAL_STACK=1"]
async fn starts_consumes_and_streams() {
    if !local_stack() {
        return;
    }
    with_scratch(|_pool, schema| async move {
        let (fake, base) = Fake::start().await;
        fake.answer("GET", AUTH_PATH, Answer::json(context(true)));
        fake.answer("GET", CONN_PATH, Answer::json(json!({"inApp": true})));
        fake.answer(
            "GET",
            NOTIF_PATH,
            Answer::json(json!({"name": "hello", "notificationType": "INFO",
                "channelTemplates": {"inapp": {"templateParts": {"en": {"title": "Hi ${who}", "description": "d"}}}}})),
        );
        fake.answer("POST", USERS_PATH, Answer::json(json!([{"id": 142, "clientId": 1, "emailId": "a@x.test"}])));

        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let uri = std::env::var("MODLIX__MQ__URI").ok().filter(|u| !u.is_empty()).unwrap_or_else(|| "amqp://guest:guest@localhost:5672/%2f".into());
        let tag = &uuid::Uuid::new_v4().simple().to_string()[..8];
        let exchange = format!("rs_scratch_notif_x_{tag}");
        let queue = format!("rs_scratch_notif_{tag}");
        for (k, v) in [
            ("CONFIG_FILE", "/nonexistent/notification.toml".to_string()),
            ("MODLIX__SERVER__PORT", port.to_string()),
            ("MODLIX__SERVER__SHUTDOWN_GRACE_SECONDS", "0".into()),
            ("MODLIX__TELEMETRY__LOG_LEVEL", "warn".into()),
            ("MODLIX__DATABASE__HOST", "127.0.0.1".into()),
            ("MODLIX__DATABASE__DATABASE", schema.clone()),
            ("MODLIX__DATABASE__MAX_CONNECTIONS", "2".into()),
            ("MODLIX__SECURITY__UPSTREAM", base.clone()),
            ("MODLIX__CORE__UPSTREAM", base.clone()),
            ("MODLIX__CORE__CONNECTIONS_UPSTREAM", base.clone()),
            ("MODLIX__MQ__URI", uri.clone()),
            ("MODLIX__NOTIFICATIONS__QUEUES", queue.clone()),
            ("MODLIX__NOTIFICATIONS__EXCHANGE", exchange.clone()),
            ("MODLIX__NOTIFICATIONS__DECLARE", "true".into()),
            ("MODLIX__SSE__HEARTBEAT_SECONDS", "1".into()),
        ] {
            std::env::set_var(k, v);
        }
        let task = tokio::spawn(notification::run());
        let http = reqwest::Client::new();
        let mut ready = false;
        for _ in 0..200 {
            if let Ok(r) = http.get(format!("http://127.0.0.1:{port}/readyz")).send().await {
                if r.status().is_success() {
                    ready = true;
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(ready, "notification did not become ready (mysql and the consumer)");

        let stream = http
            .get(format!("http://127.0.0.1:{port}/api/notification/subscribe?appCode=rsapp"))
            .header("authorization", "Bearer t")
            .send()
            .await
            .unwrap();
        assert_eq!(stream.headers()["content-type"], "text/event-stream;charset=UTF-8");
        let mut body = stream;
        let init = body.chunk().await.unwrap().unwrap();
        assert!(init.starts_with(b"event:init"));

        let conn = Connection::connect(&uri, ConnectionProperties::default()).await.unwrap();
        let ch = conn.create_channel().await.unwrap();
        let msg = json!({"appCode": "rsapp", "clientCode": "SYSTEM", "urlClientCode": "SYSTEM", "targetType": "User Id",
            "targetId": 142, "notificationName": "hello", "connectionName": "c", "draft": false, "payload": {"who": "Ann"}});
        ch.basic_publish(
            ShortString::from(exchange.as_str()),
            ShortString::from(queue.as_str()),
            BasicPublishOptions::default(),
            msg.to_string().as_bytes(),
            connections::mq::message_properties(connections::mq::NOTIFICATION_TYPE_ID),
        )
        .await
        .unwrap();

        let mut got = String::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while !got.contains("event:notification") && tokio::time::Instant::now() < deadline {
            if let Ok(Ok(Some(chunk))) = tokio::time::timeout(Duration::from_secs(2), body.chunk()).await {
                got.push_str(&String::from_utf8_lossy(&chunk));
            }
        }
        assert!(got.contains("event:notification\ndata:{\n"), "{got}");
        assert!(got.contains("data:  \"title\" : \"Hi Ann\",\n"), "{got}");
        assert!(got.contains("data:  \"notificationType\" : \"INFO\"\n"), "{got}");
        // The 1 s keepalive.
        let mut keepalive = got.contains(":keepalive");
        for _ in 0..3 {
            if keepalive {
                break;
            }
            if let Ok(Ok(Some(chunk))) = tokio::time::timeout(Duration::from_secs(2), body.chunk()).await {
                keepalive = String::from_utf8_lossy(&chunk).contains(":keepalive");
            }
        }
        assert!(keepalive, "no keepalive");
        // The count route over the same server.
        let n = http
            .get(format!("http://127.0.0.1:{port}/api/notification/new?appCode=rsapp"))
            .header("authorization", "Bearer t")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert_eq!(n, "1");

        drop(body);
        task.abort();
        ch.queue_delete(ShortString::from(queue.as_str()), QueueDeleteOptions::default()).await.unwrap();
        ch.exchange_delete(ShortString::from(exchange.as_str()), ExchangeDeleteOptions::default()).await.unwrap();
        let defaults = notification::config::NotificationConfig::default();
        assert_eq!(defaults.server.port, 8114);
    })
    .await;
}
