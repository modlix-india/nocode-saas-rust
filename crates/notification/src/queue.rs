//! `NotificationsQueListener`: `@RabbitListener(queues = notifications.mq.queues)` with
//! `directMessageListener` (one consumer per queue, auto ack) and the services' JSON converter.
//!
//! Each queue is worked one message at a time, as Java's single consumer per queue does. A
//! message is acked once its run ends, whether the send succeeded or failed (the listener
//! catches every exception and only logs it); a body that cannot be read into a
//! `NotificationQueObject` is rejected without requeue (Spring's fatal conversion error).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use futures::StreamExt;
use lapin::message::Delivery;
use lapin::options::{
    BasicAckOptions, BasicConsumeOptions, BasicNackOptions, BasicQosOptions, ExchangeDeclareOptions, QueueBindOptions,
    QueueDeclareOptions,
};
use lapin::types::{FieldTable, ShortString};
use lapin::{Connection, ConnectionProperties, ExchangeKind};
use tracing::Instrument;

use crate::config::QueueSection;
use crate::model::QueueMessage;
use crate::send::{Outcome, SendService};

/// What happens to a delivery once its run is over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Settle {
    Ack(Option<Outcome>),
    /// Rejected for good: the message cannot be read.
    Drop,
}

/// `Jackson2JsonMessageConverter.fromMessage`: a body is read as JSON when its content type
/// mentions `json`, or when it has none or the default `application/octet-stream`.
pub fn readable_content_type(content_type: Option<&str>) -> bool {
    match content_type {
        None => true,
        Some(ct) => ct == "application/octet-stream" || ct.contains("json"),
    }
}

/// One delivery through the listener.
pub async fn handle(service: &SendService, content_type: Option<&str>, body: &[u8]) -> Settle {
    if !readable_content_type(content_type) {
        tracing::error!("Notification dropped: content type {} is not JSON", content_type.unwrap_or("null"));
        return Settle::Drop;
    }
    let qob = match QueueMessage::parse(body) {
        Ok(q) => q,
        Err(e) => {
            tracing::error!("Notification dropped: {e}");
            return Settle::Drop;
        }
    };
    let span = tracing::info_span!("notification.receive", x_debug = qob.x_debug.as_deref().unwrap_or(""));
    async {
        let tag = qob.x_debug.as_deref().unwrap_or("null");
        tracing::info!("{tag} - Received notification message: {}", qob.describe());
        match service.send(&qob).await {
            Ok(outcome) => {
                tracing::info!("{tag} - Sent notification message: {}", qob.describe());
                Settle::Ack(Some(outcome))
            }
            Err(e) => {
                tracing::error!("Failed to send notification : {} : {e:#}", qob.describe());
                Settle::Ack(None)
            }
        }
    }
    .instrument(span)
    .await
}

/// Whether the consumer currently holds its broker connection (a readiness check).
#[derive(Clone, Default)]
pub struct ConsumerState(Arc<AtomicBool>);

impl ConsumerState {
    pub fn connected(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }

    fn set(&self, v: bool) {
        self.0.store(v, Ordering::Relaxed);
    }
}

/// Consumes until the connection drops, then reconnects, for the life of the process.
pub async fn consume_forever(service: Arc<SendService>, uri: String, settings: QueueSection, state: ConsumerState) {
    loop {
        match consume(service.clone(), &uri, &settings, &state).await {
            Ok(()) => tracing::warn!("The notifications consumer stopped; reconnecting"),
            Err(e) => tracing::error!("The notifications consumer failed: {e}; reconnecting"),
        }
        state.set(false);
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

async fn settle(delivery: &Delivery, s: &Settle) {
    let done = match s {
        Settle::Ack(_) => delivery.acker.ack(BasicAckOptions::default()).await,
        Settle::Drop => delivery.acker.nack(BasicNackOptions { requeue: false, ..Default::default() }).await,
    };
    if let Err(e) = done {
        tracing::warn!("Could not settle a delivery: {e}");
    }
}

async fn consume(service: Arc<SendService>, uri: &str, settings: &QueueSection, state: &ConsumerState) -> Result<(), lapin::Error> {
    let conn = Connection::connect(uri, ConnectionProperties::default()).await?;
    let queues = settings.names();
    let mut workers: Vec<tokio::task::JoinHandle<Result<(), lapin::Error>>> = Vec::new();
    for q in &queues {
        // A channel per queue, so one slow notification holds up only its own queue.
        let ch = conn.create_channel().await?;
        ch.basic_qos(settings.prefetch.max(1), BasicQosOptions::default()).await?;
        if settings.declare {
            ch.exchange_declare(
                ShortString::from(settings.exchange.as_str()),
                ExchangeKind::Direct,
                ExchangeDeclareOptions::default(),
                FieldTable::default(),
            )
            .await?;
            ch.queue_declare(ShortString::from(q.as_str()), QueueDeclareOptions::default(), FieldTable::default()).await?;
            ch.queue_bind(
                ShortString::from(q.as_str()),
                ShortString::from(settings.exchange.as_str()),
                ShortString::from(q.as_str()),
                QueueBindOptions::default(),
                FieldTable::default(),
            )
            .await?;
        }
        let tag = format!("notification-{q}-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
        let mut consumer = ch
            .basic_consume(ShortString::from(q.as_str()), ShortString::from(tag), BasicConsumeOptions::default(), FieldTable::default())
            .await?;
        let service = service.clone();
        workers.push(tokio::spawn(async move {
            while let Some(delivery) = consumer.next().await {
                let delivery = delivery?;
                let ct = delivery.properties.content_type().as_ref().map(|c| c.to_string());
                let s = service.clone();
                let body = delivery.data.clone();
                // A panic in a run is acked like any failure, rather than redelivered forever.
                let outcome = tokio::spawn(async move { handle(&s, ct.as_deref(), &body).await })
                    .await
                    .unwrap_or_else(|e| {
                        tracing::error!("Failed to send notification : {e}");
                        Settle::Ack(None)
                    });
                settle(&delivery, &outcome).await;
            }
            Ok::<(), lapin::Error>(())
        }));
    }
    if workers.is_empty() {
        futures::future::pending::<()>().await;
    }
    state.set(true);
    tracing::info!(queues = ?queues, prefetch = settings.prefetch, "notification is consuming");
    // The first worker to end (a closed channel or connection) ends this round.
    let (first, _, rest) = futures::future::select_all(workers).await;
    for w in rest {
        w.abort();
    }
    match first {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("A queue worker stopped: {e}");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_types_the_converter_reads() {
        assert!(readable_content_type(None));
        assert!(readable_content_type(Some("application/json")));
        assert!(readable_content_type(Some("application/octet-stream")));
        assert!(readable_content_type(Some("text/json")));
        assert!(!readable_content_type(Some("text/plain")));
        let s = ConsumerState::default();
        assert!(!s.connected());
        s.set(true);
        assert!(s.connected());
    }
}
