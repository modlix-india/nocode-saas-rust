//! The open in-app streams (`InAppNotificationService.userEmitters`): one list of streams per
//! `"<userId>-<appCode>"`, the frames Spring's `SseEmitter` writes, and the 15 s keepalive.
//!
//! Like Java's map this lives in the process: a notification consumed by one instance reaches
//! only the streams open on that instance (see DIFFERENCES.md for the limitation and the
//! proposed fan-out).

use std::collections::HashMap;
use std::convert::Infallible;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use futures::Stream;
use parking_lot::Mutex;
use tokio::sync::mpsc;

/// `SseEmitter.event().name(name).data(data).id(id).reconnectTime(retry)` as Spring writes it:
/// no space after the colons, a multi-line `data` split into `data:` lines, a blank line last.
pub fn event_frame(name: &str, data: &str, id: &str, retry_ms: u64) -> Bytes {
    Bytes::from(format!("event:{name}\ndata:{}\nid:{id}\nretry:{retry_ms}\n\n", data.replace('\n', "\ndata:")))
}

/// `SseEmitter.event().comment(text)`.
pub fn comment_frame(text: &str) -> Bytes {
    Bytes::from(format!(":{text}\n\n"))
}

/// The first event of every stream.
pub fn init_frame() -> Bytes {
    event_frame("init", "connected", &uuid::Uuid::new_v4().to_string(), 5000)
}

/// The key Java files a stream under.
pub fn key(user_id: impl std::fmt::Display, app_code: &str) -> String {
    format!("{user_id}-{app_code}")
}

struct Subscriber {
    id: u64,
    tx: mpsc::Sender<Bytes>,
}

pub struct Hub {
    streams: Mutex<HashMap<String, Vec<Subscriber>>>,
    next: AtomicU64,
    buffer: usize,
}

impl Hub {
    pub fn new(buffer: usize) -> Arc<Self> {
        Arc::new(Self { streams: Mutex::new(HashMap::new()), next: AtomicU64::new(1), buffer: buffer.max(2) })
    }

    /// Opens a stream under `key`, starting with the `init` event.
    pub fn subscribe(self: &Arc<Self>, key: String) -> Subscription {
        let (tx, rx) = mpsc::channel(self.buffer);
        let _ = tx.try_send(init_frame());
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        self.streams.lock().entry(key.clone()).or_default().push(Subscriber { id, tx });
        Subscription { rx, hub: self.clone(), key, id }
    }

    fn remove(&self, key: &str, id: u64) {
        let mut streams = self.streams.lock();
        if let Some(list) = streams.get_mut(key) {
            list.retain(|s| s.id != id);
            if list.is_empty() {
                streams.remove(key);
            }
        }
    }

    /// Sends `frame` to every stream of `key`; a stream that is gone (or too far behind) is
    /// dropped, as a failed send removes Java's emitter. The number reached.
    pub fn send(&self, key: &str, frame: &Bytes) -> usize {
        let mut streams = self.streams.lock();
        let Some(list) = streams.get_mut(key) else { return 0 };
        list.retain(|s| s.tx.try_send(frame.clone()).is_ok());
        let n = list.len();
        if n == 0 {
            streams.remove(key);
        }
        n
    }

    /// `heartbeat()`: the keepalive comment to every open stream. The number reached.
    pub fn heartbeat(&self) -> usize {
        let frame = comment_frame("keepalive");
        let mut streams = self.streams.lock();
        let mut reached = 0;
        streams.retain(|_, list| {
            list.retain(|s| s.tx.try_send(frame.clone()).is_ok());
            reached += list.len();
            !list.is_empty()
        });
        reached
    }

    /// `@Scheduled(fixedRate = 15000)`: one timer for every stream, as in Java.
    pub fn spawn_heartbeat(self: &Arc<Self>, period: Duration) -> tokio::task::JoinHandle<()> {
        let hub = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(period);
            tick.tick().await;
            loop {
                tick.tick().await;
                hub.heartbeat();
            }
        })
    }

    /// Open streams, for the gauge and tests.
    pub fn open_streams(&self) -> usize {
        self.streams.lock().values().map(Vec::len).sum()
    }
}

/// One open stream; dropping it (the client went away) removes it from the hub.
pub struct Subscription {
    rx: mpsc::Receiver<Bytes>,
    hub: Arc<Hub>,
    key: String,
    id: u64,
}

impl Stream for Subscription {
    type Item = Result<Bytes, Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx).map(|o| o.map(Ok))
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.hub.remove(&self.key, self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    #[test]
    fn frames_as_spring_writes_them() {
        // Captured from Java notification on 2026-10-16.
        let data = "{\n  \"id\" : 5686,\n  \"title\" : \"H\u{e9}llo Ann\"\n}";
        assert_eq!(
            event_frame("notification", data, "e863bf18", 5000),
            "event:notification\ndata:{\ndata:  \"id\" : 5686,\ndata:  \"title\" : \"H\u{e9}llo Ann\"\ndata:}\nid:e863bf18\nretry:5000\n\n"
        );
        assert_eq!(comment_frame("keepalive"), ":keepalive\n\n");
        let init = String::from_utf8(init_frame().to_vec()).unwrap();
        assert!(init.starts_with("event:init\ndata:connected\nid:") && init.ends_with("\nretry:5000\n\n"));
        assert_eq!(key(142u64, "monkbars"), "142-monkbars");
    }

    #[tokio::test]
    async fn streams_receive_and_leave() {
        let hub = Hub::new(4);
        let mut a = hub.subscribe(key(1, "app"));
        let mut b = hub.subscribe(key(1, "app"));
        let c = hub.subscribe(key(2, "app"));
        assert_eq!(hub.open_streams(), 3);
        for s in [&mut a, &mut b] {
            let first = s.next().await.unwrap().unwrap();
            assert!(first.starts_with(b"event:init"));
        }
        assert_eq!(hub.send(&key(1, "app"), &Bytes::from_static(b"x")), 2);
        assert_eq!(hub.send(&key(9, "app"), &Bytes::from_static(b"x")), 0);
        assert_eq!(a.next().await.unwrap().unwrap(), Bytes::from_static(b"x"));
        drop(b);
        assert_eq!(hub.open_streams(), 2);
        assert_eq!(hub.heartbeat(), 2);
        assert_eq!(a.next().await.unwrap().unwrap(), comment_frame("keepalive"));
        drop(c);
        drop(a);
        assert_eq!(hub.open_streams(), 0);
        assert_eq!(hub.heartbeat(), 0);
    }

    #[tokio::test]
    async fn a_stream_that_stops_reading_is_dropped() {
        let hub = Hub::new(2);
        let s = hub.subscribe(key(1, "a"));
        // init fills one slot; one more fits, the next send finds it full.
        assert_eq!(hub.send(&key(1, "a"), &Bytes::from_static(b"1")), 1);
        assert_eq!(hub.send(&key(1, "a"), &Bytes::from_static(b"2")), 0);
        assert_eq!(hub.open_streams(), 0);
        let s2 = hub.subscribe(key(3, "a"));
        assert_eq!(hub.heartbeat(), 1);
        assert_eq!(hub.heartbeat(), 0, "the init and one keepalive fill it");
        drop(s);
        drop(s2);
    }

    #[tokio::test(start_paused = true)]
    async fn heartbeat_timer() {
        let hub = Hub::new(8);
        let mut s = hub.subscribe(key(1, "a"));
        let _ = s.next().await;
        let task = hub.spawn_heartbeat(Duration::from_secs(15));
        tokio::time::sleep(Duration::from_secs(16)).await;
        assert_eq!(s.next().await.unwrap().unwrap(), comment_frame("keepalive"));
        task.abort();
    }
}
