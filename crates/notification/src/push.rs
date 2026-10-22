//! Delivery to the open streams of every instance (DIFFERENCES.md N1).
//!
//! The streams live in each process's [`Hub`]. With Redis configured, the instance that
//! consumed a notification publishes `{"keys": [...], "frame": "..."}` on the push channel
//! (`[sse] push_channel`, `notificationPush`), and every instance, this one included, hands the
//! frame to its own streams when it hears it: the publisher never also delivers locally, so a
//! stream gets each frame once. Without Redis, or when a publish fails, the frame goes to this
//! instance's streams only, as before.
//!
//! A message published while an instance is not subscribed is lost for its streams: an in-app
//! notification is still in the list and the count, and a data notification was never meant
//! for anyone offline.

use std::sync::Arc;

use bytes::Bytes;
use platform::cache::{CacheService, Heard};
use serde_json::{json, Value};

use crate::sse::Hub;

/// Frames handed out, by `via`: `redis` (published for every instance) or `local` (this
/// instance's streams only).
pub const PUSHED: &str = "notification_push_total";

pub struct Push {
    hub: Arc<Hub>,
    /// The Redis connection and channel, when frames go through Redis.
    redis: Option<(CacheService, String)>,
}

impl Push {
    /// Delivery to this instance's streams only.
    pub fn local(hub: Arc<Hub>) -> Arc<Self> {
        Arc::new(Self { hub, redis: None })
    }

    /// Through Redis on `channel` when `cache` is given, else local.
    pub fn new(hub: Arc<Hub>, cache: Option<CacheService>, channel: &str) -> Arc<Self> {
        Arc::new(Self { hub, redis: cache.map(|c| (c, channel.to_string())) })
    }

    /// Whether frames go through Redis.
    pub fn fans_out(&self) -> bool {
        self.redis.is_some()
    }

    /// The message published for `keys` and `frame`.
    pub fn message(keys: &[String], frame: &Bytes) -> String {
        json!({"keys": keys, "frame": String::from_utf8_lossy(frame)}).to_string()
    }

    /// Hands `frame` to the streams of `keys`, on every instance when Redis is configured.
    pub async fn deliver(&self, keys: &[String], frame: &Bytes) {
        if keys.is_empty() {
            return;
        }
        if let Some((cache, channel)) = &self.redis {
            if cache.publish(channel, &Self::message(keys, frame)).await {
                metrics::counter!(PUSHED, "via" => "redis").increment(1);
                return;
            }
            tracing::warn!(channel, "push not published: delivering to this instance's streams only");
        }
        metrics::counter!(PUSHED, "via" => "local").increment(1);
        self.to_streams(keys, frame);
    }

    fn to_streams(&self, keys: &[String], frame: &Bytes) -> usize {
        keys.iter().map(|k| self.hub.send(k, frame)).sum()
    }

    /// A message heard on the push channel, handed to this instance's streams. The number of
    /// streams reached; a message that is not a push is ignored.
    pub fn heard(&self, payload: &str) -> usize {
        let Ok(v) = serde_json::from_str::<Value>(payload) else {
            tracing::warn!("ignoring a push that is not JSON");
            return 0;
        };
        let (Some(keys), Some(frame)) = (v.get("keys").and_then(Value::as_array), v.get("frame").and_then(Value::as_str)) else {
            tracing::warn!("ignoring a push without keys or frame");
            return 0;
        };
        let keys: Vec<String> = keys.iter().filter_map(Value::as_str).map(str::to_string).collect();
        self.to_streams(&keys, &Bytes::from(frame.to_string()))
    }

    /// Listens on the push channel for the life of the process (with Redis only).
    pub fn spawn_listener(self: &Arc<Self>) -> Option<tokio::task::JoinHandle<()>> {
        let (cache, channel) = self.redis.as_ref()?;
        let this = self.clone();
        cache.spawn_listener(channel, move |heard| {
            let this = this.clone();
            Box::pin(async move {
                if let Heard::Message(payload) = heard {
                    this.heard(&payload);
                }
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sse::key;
    use futures::StreamExt;

    #[tokio::test]
    async fn local_delivery_and_what_is_heard() {
        let hub = Hub::new(8);
        let push = Push::local(hub.clone());
        assert!(!push.fans_out());
        assert!(push.spawn_listener().is_none());
        let mut a = hub.subscribe(key(1, "app"));
        let mut b = hub.subscribe(key(2, "app"));
        let _ = (a.next().await, b.next().await);
        push.deliver(&[key(1, "app"), key(2, "app"), key(3, "app")], &Bytes::from_static(b"event:x\n\n")).await;
        assert_eq!(a.next().await.unwrap().unwrap(), Bytes::from_static(b"event:x\n\n"));
        assert_eq!(b.next().await.unwrap().unwrap(), Bytes::from_static(b"event:x\n\n"));
        push.deliver(&[], &Bytes::from_static(b"never")).await;

        let message = Push::message(&[key(1, "app")], &Bytes::from_static(b"event:y\ndata:{\"a\":1}\n\n"));
        assert_eq!(serde_json::from_str::<Value>(&message).unwrap(), json!({"keys": ["1-app"], "frame": "event:y\ndata:{\"a\":1}\n\n"}));
        assert_eq!(push.heard(&message), 1);
        assert_eq!(a.next().await.unwrap().unwrap(), Bytes::from_static(b"event:y\ndata:{\"a\":1}\n\n"));
        assert_eq!(push.heard("not json"), 0);
        assert_eq!(push.heard(r#"{"keys":["1-app"]}"#), 0);
        assert_eq!(push.heard(r#"{"frame":"x"}"#), 0);
        assert_eq!(push.heard(r#"{"keys":[7,"2-app"],"frame":"z"}"#), 1, "a key that is not text is skipped");
    }

    #[tokio::test]
    async fn a_failed_publish_delivers_locally() {
        let hub = Hub::new(8);
        let cache = CacheService::new("x", "evictionChannel", Some("redis://127.0.0.1:1")).unwrap();
        let push = Push::new(hub.clone(), Some(cache), "notificationPush");
        assert!(push.fans_out());
        let listener = push.spawn_listener().unwrap();
        let mut a = hub.subscribe(key(1, "app"));
        let _ = a.next().await;
        push.deliver(&[key(1, "app")], &Bytes::from_static(b"f")).await;
        assert_eq!(a.next().await.unwrap().unwrap(), Bytes::from_static(b"f"));
        listener.abort();
        assert!(!Push::new(hub, None, "c").fans_out());
    }
}
