//! The queue side of core-events: `@RabbitListener(queues = events.mq.queues)` with
//! `directMessageListener` (auto ack after the listener's Mono completes, one consumer per
//! queue). Each delivery is read as Jackson reads an `EventQueObject` and handed to
//! [`EventsListener::run`]; it is acked when the run ends, rejected without requeue when it
//! cannot be read (Spring's fatal conversion error), and nacked with requeue when the run
//! fails before its action could run (Spring's default for a listener error).
//!
//! Java's prefetch is unbounded; here `events.prefetch` bounds the deliveries in flight on the
//! channel, and so the runs in progress.

use std::sync::Arc;

use futures::StreamExt;
use lapin::options::{
    BasicAckOptions, BasicConsumeOptions, BasicNackOptions, BasicQosOptions, ExchangeDeclareOptions, QueueBindOptions,
    QueueDeclareOptions,
};
use lapin::types::{FieldTable, ShortString};
use lapin::{Connection, ConnectionProperties, ExchangeKind};

use crate::config::EventsSection;
use crate::events::{parse_event, EventsListener};

/// The queues `events.queues` names, trimmed, empty names left out.
pub fn queue_names(settings: &EventsSection) -> Vec<String> {
    settings.queues.split(',').map(str::trim).filter(|q| !q.is_empty()).map(str::to_string).collect()
}

/// Deliveries taken off the queues.
pub const CONSUMED: &str = "core_events_consumed_total";
/// Deliveries acked.
pub const ACKED: &str = "core_events_acked_total";
/// Deliveries nacked, `requeue` true (the run failed) or false (unreadable, dropped).
pub const NACKED: &str = "core_events_nacked_total";
/// What went wrong, by `reason`: `unreadable`, `run` (requeued), `settle` (the ack or nack
/// itself failed).
pub const FAILED: &str = "core_events_failed_total";

/// The descriptions of the counters above, for `/metrics`.
pub fn describe_metrics() {
    metrics::describe_counter!(CONSUMED, metrics::Unit::Count, "Deliveries core-events took off the events queues.");
    metrics::describe_counter!(ACKED, metrics::Unit::Count, "Deliveries core-events acked.");
    metrics::describe_counter!(NACKED, metrics::Unit::Count, "Deliveries core-events nacked, by requeue.");
    metrics::describe_counter!(FAILED, metrics::Unit::Count, "Deliveries core-events could not read or run, or could not settle, by reason.");
}

/// What to do with a delivery once its run is over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Settle {
    Ack,
    /// Rejected for good: the message cannot be read.
    Drop,
    /// Back on the queue: the run failed before its action could run.
    Requeue,
}

/// Runs one delivery's body through the listener.
pub async fn handle(listener: &EventsListener, body: &[u8]) -> Settle {
    metrics::counter!(CONSUMED).increment(1);
    let qob = match parse_event(body) {
        Ok(q) => q,
        Err(e) => {
            metrics::counter!(FAILED, "reason" => "unreadable").increment(1);
            tracing::error!("Event dropped: {e}");
            return Settle::Drop;
        }
    };
    match listener.run(&qob).await {
        Ok(_) => Settle::Ack,
        Err(e) => {
            metrics::counter!(FAILED, "reason" => "run").increment(1);
            tracing::warn!(
                "Event {}.{} for {} failed and goes back on the queue: {e}",
                qob.app_code.as_deref().unwrap_or("null"),
                qob.event_name.as_deref().unwrap_or("null"),
                qob.client_code.as_deref().unwrap_or("null")
            );
            Settle::Requeue
        }
    }
}

/// Consumes until the connection drops; then reconnects, forever.
pub async fn consume_forever(listener: Arc<EventsListener>, uri: String, exchange: String, settings: EventsSection) {
    loop {
        match consume(listener.clone(), &uri, &exchange, &settings).await {
            Ok(()) => tracing::warn!("The events consumer stopped; reconnecting"),
            Err(e) => tracing::error!("The events consumer failed: {e}; reconnecting"),
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

async fn consume(listener: Arc<EventsListener>, uri: &str, exchange: &str, settings: &EventsSection) -> Result<(), lapin::Error> {
    let conn = Connection::connect(uri, ConnectionProperties::default()).await?;
    let ch = conn.create_channel().await?;
    ch.basic_qos(settings.prefetch.max(1), BasicQosOptions::default()).await?;
    let queues = queue_names(settings);
    if settings.declare {
        let durable = ExchangeDeclareOptions { durable: true, ..Default::default() };
        ch.exchange_declare(ShortString::from(exchange), ExchangeKind::Direct, durable, FieldTable::default()).await?;
        for q in &queues {
            let opts = QueueDeclareOptions { durable: true, ..Default::default() };
            ch.queue_declare(ShortString::from(q.as_str()), opts, FieldTable::default()).await?;
            ch.queue_bind(
                ShortString::from(q.as_str()),
                ShortString::from(exchange),
                ShortString::from(q.as_str()),
                QueueBindOptions::default(),
                FieldTable::default(),
            )
            .await?;
        }
    }
    let mut streams = Vec::new();
    for q in &queues {
        let tag = format!("core-events-{q}-{}", &uuid::Uuid::new_v4().to_string()[..8]);
        let consumer = ch
            .basic_consume(ShortString::from(q.as_str()), ShortString::from(tag), BasicConsumeOptions::default(), FieldTable::default())
            .await?;
        streams.push(consumer);
    }
    tracing::info!(queues = ?queues, prefetch = settings.prefetch, "core-events is consuming");
    let mut all = futures::stream::select_all(streams);
    while let Some(delivery) = all.next().await {
        let delivery = delivery?;
        let listener = listener.clone();
        tokio::spawn(async move {
            let settle = handle(&listener, &delivery.data).await;
            let done = match settle {
                Settle::Ack => delivery.acker.ack(BasicAckOptions::default()).await,
                Settle::Drop => delivery.acker.nack(BasicNackOptions { requeue: false, ..Default::default() }).await,
                Settle::Requeue => delivery.acker.nack(BasicNackOptions { requeue: true, ..Default::default() }).await,
            };
            settled(settle, done.is_ok());
            if let Err(e) = done {
                tracing::warn!("Could not settle a delivery: {e}");
            }
        });
    }
    Ok(())
}

/// Counts how a delivery was settled, once the broker took the ack or nack (`ok`).
pub fn settled(settle: Settle, ok: bool) {
    if !ok {
        metrics::counter!(FAILED, "reason" => "settle").increment(1);
        return;
    }
    match settle {
        Settle::Ack => metrics::counter!(ACKED).increment(1),
        Settle::Drop => metrics::counter!(NACKED, "requeue" => "false").increment(1),
        Settle::Requeue => metrics::counter!(NACKED, "requeue" => "true").increment(1),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use lapin::options::{ExchangeDeleteOptions, QueueDeleteOptions};
    use overridable::{JMap, JValue};
    use parking_lot::Mutex;
    use serde_json::Value;

    use super::*;
    use crate::error::CoreError;
    use crate::events::{ActionTask, ClientLookup, EventActions, TaskExecutor, TaskResult, CALL_CORE_FUNCTION};

    struct OneAction(Result<(), String>);

    #[async_trait]
    impl EventActions for OneAction {
        async fn read(&self, name: &str, _: &str, _: &str, _: bool) -> Result<Option<JMap>, CoreError> {
            if let Err(e) = &self.0 {
                return Err(CoreError::unknown(e.clone()));
            }
            let mut task = JMap::new();
            task.insert("type".into(), JValue::Str(CALL_CORE_FUNCTION.into()));
            let mut tasks = JMap::new();
            tasks.insert(name.to_string(), JValue::Object(task));
            let mut a = JMap::new();
            a.insert("tasks".into(), JValue::Object(tasks));
            Ok(Some(a))
        }
    }

    struct Client;

    #[async_trait]
    impl ClientLookup for Client {
        async fn client_by_code(&self, code: &str) -> Result<Option<Value>, CoreError> {
            Ok(Some(serde_json::json!({"id": 1, "code": code})))
        }
    }

    #[derive(Default)]
    struct Seen(Mutex<Vec<String>>);

    #[async_trait]
    impl TaskExecutor for Seen {
        async fn execute(&self, _task: &ActionTask, qob: &connections::mq::EventMessage) -> TaskResult {
            self.0.lock().push(qob.event_name.clone().unwrap_or_default());
            TaskResult::from(Ok(Some(true)))
        }
    }

    fn listener(read: Result<(), String>, seen: Arc<Seen>) -> EventsListener {
        EventsListener::new(Arc::new(OneAction(read)), Arc::new(Client)).with_executor(CALL_CORE_FUNCTION, seen)
    }

    #[tokio::test]
    async fn deliveries_are_settled_as_spring_settles_them() {
        let seen = Arc::new(Seen::default());
        let ok = listener(Ok(()), seen.clone());
        let body = br#"{"eventName":"E","appCode":"app","clientCode":"FIN","draft":false}"#;
        assert_eq!(handle(&ok, body).await, Settle::Ack);
        assert_eq!(*seen.0.lock(), ["E"]);
        assert_eq!(handle(&ok, b"not json").await, Settle::Drop);
        let failing = listener(Err("mongo unreachable".into()), seen);
        assert_eq!(handle(&failing, body).await, Settle::Requeue);
        let s = EventsSection { queues: " a, ,b ".into(), ..Default::default() };
        assert_eq!(queue_names(&s), ["a", "b"]);
    }

    #[test]
    fn deliveries_are_counted() {
        let ((), text) = platform::meter::capture_async(async {
            let ok = listener(Ok(()), Arc::new(Seen::default()));
            let body = br#"{"eventName":"E","appCode":"app","clientCode":"FIN","draft":false}"#;
            settled(handle(&ok, body).await, true);
            settled(handle(&ok, b"not json").await, true);
            let failing = listener(Err("mongo unreachable".into()), Arc::new(Seen::default()));
            settled(handle(&failing, body).await, true);
            settled(Settle::Ack, false);
            describe_metrics();
        });
        let n = |name: &str, labels: &[(&str, &str)]| platform::meter::sample(&text, name, labels);
        assert_eq!(n(CONSUMED, &[]), Some(3.0));
        assert_eq!(n(ACKED, &[]), Some(1.0));
        assert_eq!(n(NACKED, &[("requeue", "false")]), Some(1.0));
        assert_eq!(n(NACKED, &[("requeue", "true")]), Some(1.0));
        for reason in ["unreadable", "run", "settle"] {
            assert_eq!(n(FAILED, &[("reason", reason)]), Some(1.0), "{reason}");
        }
        assert!(text.contains(&format!("# HELP {CONSUMED}")));
    }

    /// A round trip through a scratch exchange and scratch queues of the local broker, deleted
    /// afterwards: never the real `events` exchange or queues.
    #[tokio::test]
    #[ignore = "needs the local stack: CORE_LOCAL_STACK=1 and config/local.toml"]
    async fn events_published_to_the_queues_are_run_and_acked() {
        if !crate::testing::local_stack() {
            return;
        }
        let uri = std::env::var("MODLIX__MQ__URI").ok().filter(|u| !u.is_empty()).unwrap_or_else(|| "amqp://guest:guest@localhost:5672/%2f".into());
        let tag = &uuid::Uuid::new_v4().to_string()[..8];
        let exchange = format!("rs_scratch_events_{tag}");
        let queues: Vec<String> = (1..=2).map(|i| format!("rs_scratch_events{i}_{tag}")).collect();
        let settings = EventsSection { queues: queues.join(","), prefetch: 4, declare: true };
        let seen = Arc::new(Seen::default());
        let consumer = tokio::spawn(consume_forever(Arc::new(listener(Ok(()), seen.clone())), uri.clone(), exchange.clone(), settings));
        let publisher = connections::mq::Publisher::new(uri.clone());
        // The consumer declares the exchange and queues; publish once they exist.
        let mut sent = 0;
        for _ in 0..50 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            if sent < 4 {
                let body = format!(r#"{{"eventName":"E{sent}","appCode":"app","clientCode":"FIN","draft":false}}"#);
                if publisher.publish(&exchange, &queues[sent % 2], body.as_bytes(), connections::mq::EVENT_TYPE_ID).await.is_ok() {
                    sent += 1;
                }
            }
            if sent == 4 && seen.0.lock().len() == 4 {
                break;
            }
        }
        // A message that cannot be read is rejected for good, not requeued.
        publisher.publish(&exchange, &queues[0], b"not json", connections::mq::EVENT_TYPE_ID).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        consumer.abort();
        let conn = lapin::Connection::connect(&uri, lapin::ConnectionProperties::default()).await.unwrap();
        let ch = conn.create_channel().await.unwrap();
        let mut left = 0;
        for q in &queues {
            left += ch.queue_delete(ShortString::from(q.as_str()), QueueDeleteOptions::default()).await.unwrap();
        }
        ch.exchange_delete(ShortString::from(exchange.as_str()), ExchangeDeleteOptions::default()).await.unwrap();
        let mut names = seen.0.lock().clone();
        names.sort();
        assert_eq!(names, ["E0", "E1", "E2", "E3"]);
        assert_eq!(left, 0, "every delivery was acked, the unreadable one dropped");
    }
}
