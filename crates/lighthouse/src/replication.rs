//! Peer replication, as Eureka's `PeerEurekaNodes` does it, in batches.
//!
//! - Every change made for a client is queued for each peer. A queue holds at most
//!   `replication_queue_limit` items; when it is full a heartbeat goes first (the next one
//!   carries the same news), and only when none is left the oldest item.
//! - A worker per peer sends the queue as `POST /eureka/peerreplication/batch` every
//!   `replication_flush_ms`, or at once when `replication_batch` items wait. A batch the peer
//!   did not take (unreachable, 5xx) goes back to the front of the queue and is retried with a
//!   growing pause, up to 5 seconds.
//! - Each item's answer heals the peer: 404 to a heartbeat or status update sends our whole
//!   copy as a registration; 409 carries the peer's newer copy, which we adopt.
//! - What a peer sends is applied with `Origin::Peer` and never sent on.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};
use lighthouse_client::replication::{
    Action, ReplicationInstance, ReplicationInstanceResponse, ReplicationList, ReplicationListResponse, REPLICATION_HEADER,
};
use lighthouse_client::wire::{InstanceInfo, Status};
use parking_lot::Mutex;
use serde::Serialize;
use tokio::sync::Notify;

use crate::registry::{Origin, Registry, Renewal};

const MIN_BACKOFF: Duration = Duration::from_millis(200);
const MAX_BACKOFF: Duration = Duration::from_secs(5);

/// One peer: its queue and how sending to it went.
pub struct Peer {
    /// The peer's origin, `http://host:port`.
    pub url: String,
    queue: Mutex<VecDeque<ReplicationInstance>>,
    full: Notify,
    limit: usize,
    batch: usize,
    stats: Mutex<PeerStats>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerStats {
    pub batches: u64,
    pub items: u64,
    pub failures: u64,
    pub dropped: u64,
    pub healed: u64,
    pub adopted: u64,
    pub last_error: Option<String>,
    pub last_success_ms: i64,
}

impl Peer {
    pub fn new(url: &str, limit: usize, batch: usize) -> Self {
        Self {
            url: lighthouse_client::origin(url),
            queue: Mutex::new(VecDeque::new()),
            full: Notify::new(),
            limit: limit.max(1),
            batch: batch.max(1),
            stats: Mutex::new(PeerStats::default()),
        }
    }

    pub fn queued(&self) -> usize {
        self.queue.lock().len()
    }

    pub fn stats(&self) -> PeerStats {
        self.stats.lock().clone()
    }

    /// How many items of each kind wait for this peer.
    pub fn queued_by_action(&self) -> BTreeMap<&'static str, usize> {
        let mut out = BTreeMap::new();
        for i in self.queue.lock().iter() {
            *out.entry(action_label(i.action)).or_default() += 1;
        }
        out
    }

    fn dropped(&self, action: Action) {
        self.stats.lock().dropped += 1;
        metrics::counter!("lighthouse_replication_dropped_total", "peer" => self.url.clone(), "action" => action_label(action))
            .increment(1);
    }

    /// Room for one more item, by dropping a heartbeat (the oldest), or the oldest item when the
    /// incoming one is not a heartbeat. False when the incoming item is the one to drop.
    fn make_room(&self, q: &mut VecDeque<ReplicationInstance>, incoming: Action) -> bool {
        if q.len() < self.limit {
            return true;
        }
        if let Some(pos) = q.iter().position(|i| i.action == Action::Heartbeat) {
            q.remove(pos);
            self.dropped(Action::Heartbeat);
            return true;
        }
        if incoming == Action::Heartbeat {
            self.dropped(Action::Heartbeat);
            return false;
        }
        if let Some(old) = q.pop_front() {
            self.dropped(old.action);
        }
        true
    }

    /// Queues a change for this peer.
    pub fn push(&self, item: ReplicationInstance) {
        let mut q = self.queue.lock();
        if !self.make_room(&mut q, item.action) {
            return;
        }
        q.push_back(item);
        let full = q.len() >= self.batch;
        drop(q);
        if full {
            self.full.notify_one();
        }
    }

    /// Puts items back at the front, in their order, for the next attempt. On overflow the
    /// requeued (older) items lose to what is already queued, heartbeats first.
    fn requeue(&self, items: Vec<ReplicationInstance>) {
        let mut q = self.queue.lock();
        for item in items.into_iter().rev() {
            if q.len() >= self.limit && item.action != Action::Heartbeat && q.iter().all(|i| i.action != Action::Heartbeat) {
                self.dropped(item.action);
                continue;
            }
            if self.make_room(&mut q, item.action) {
                q.push_front(item);
            }
        }
    }

    fn take(&self) -> Vec<ReplicationInstance> {
        let mut q = self.queue.lock();
        let n = q.len().min(self.batch);
        q.drain(..n).collect()
    }
}

fn action_label(a: Action) -> &'static str {
    match a {
        Action::Heartbeat => "heartbeat",
        Action::Register => "register",
        Action::Cancel => "cancel",
        Action::StatusUpdate => "status_update",
        Action::DeleteStatusOverride => "delete_status_override",
    }
}

/// A registration of `info` for a peer, as the registry queues it.
fn register_item(info: InstanceInfo) -> ReplicationInstance {
    ReplicationInstance {
        app_name: info.app.clone(),
        id: info.instance_id.clone(),
        last_dirty_timestamp: Some(info.last_dirty_timestamp),
        overridden_status: Some(info.overridden_status),
        status: Some(info.status),
        instance_info: Some(info),
        action: Action::Register,
    }
}

/// Sends `peer`'s queue until the task is aborted.
pub async fn run(peer: Arc<Peer>, registry: Arc<Registry>, http: reqwest::Client, token: Option<String>, flush: Duration) {
    let mut backoff = Duration::ZERO;
    loop {
        if backoff.is_zero() {
            tokio::select! {
                _ = tokio::time::sleep(flush) => {}
                _ = peer.full.notified() => {}
            }
        } else {
            tokio::time::sleep(backoff).await;
        }
        loop {
            let items = peer.take();
            if items.is_empty() {
                break;
            }
            match send(&http, &peer.url, token.as_deref(), &items).await {
                Ok(answers) => {
                    backoff = Duration::ZERO;
                    {
                        let mut s = peer.stats.lock();
                        s.batches += 1;
                        s.items += items.len() as u64;
                        s.last_success_ms = registry.now_ms();
                    }
                    metrics::counter!("lighthouse_replication_batches_total", "peer" => peer.url.clone(), "result" => "ok").increment(1);
                    settle(&peer, &registry, items, answers);
                }
                Err(e) => {
                    {
                        let mut s = peer.stats.lock();
                        s.failures += 1;
                        s.last_error = Some(e.to_string());
                    }
                    metrics::counter!("lighthouse_replication_batches_total", "peer" => peer.url.clone(), "result" => "failed").increment(1);
                    tracing::debug!(peer = peer.url, error = %e, "replication batch failed, will retry");
                    peer.requeue(items);
                    backoff = (backoff * 2).clamp(MIN_BACKOFF, MAX_BACKOFF);
                    break;
                }
            }
        }
        metrics::gauge!("lighthouse_replication_queue", "peer" => peer.url.clone()).set(peer.queued() as f64);
    }
}

async fn send(http: &reqwest::Client, url: &str, token: Option<&str>, items: &[ReplicationInstance]) -> Result<ReplicationListResponse> {
    let body = ReplicationList { replication_list: items.to_vec() };
    let mut req = http.post(format!("{url}/eureka/peerreplication/batch")).header(REPLICATION_HEADER, "true").json(&body);
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    let resp = req.send().await?;
    if !resp.status().is_success() {
        bail!("{url}: batch answered {}", resp.status());
    }
    Ok(resp.json().await?)
}

/// Acts on the peer's answer to each item.
fn settle(peer: &Peer, registry: &Registry, items: Vec<ReplicationInstance>, answers: ReplicationListResponse) {
    for (item, answer) in items.into_iter().zip(answers.response_list) {
        match (item.action, answer.status_code) {
            (_, 200..=299) => {}
            (Action::Heartbeat | Action::StatusUpdate, 404) => {
                if let Some(info) = registry.instance(&item.app_name, &item.id) {
                    tracing::info!(peer = peer.url, app = item.app_name, id = item.id, "peer misses an instance, sending it");
                    peer.stats.lock().healed += 1;
                    peer.requeue(vec![register_item(info)]);
                }
            }
            (_, 409) => {
                if let Some(theirs) = answer.response_entity {
                    tracing::info!(peer = peer.url, app = item.app_name, id = item.id, "peer has a newer copy, adopting it");
                    peer.stats.lock().adopted += 1;
                    registry.adopt(theirs);
                }
            }
            (action, code) => {
                tracing::debug!(peer = peer.url, app = item.app_name, id = item.id, ?action, code, "peer refused a replicated item");
            }
        }
    }
}

/// Applies one item a peer sent, with `Origin::Peer`, and answers what the single call would.
pub fn apply(registry: &Registry, item: ReplicationInstance) -> ReplicationInstanceResponse {
    let code = |status_code: u16| ReplicationInstanceResponse { status_code, response_entity: None };
    let found = |ok: bool| code(if ok { 200 } else { 404 });
    let (app, id, dirty) = (item.app_name.as_str(), item.id.as_str(), item.last_dirty_timestamp);
    match item.action {
        Action::Register => match item.instance_info {
            Some(info) => code(if registry.register(info, Origin::Peer) { 200 } else { 409 }),
            None => code(400),
        },
        Action::Heartbeat => match registry.renew(app, id, Origin::Peer, dirty, item.overridden_status) {
            Renewal::Renewed => code(200),
            Renewal::NotFound => code(404),
            Renewal::Conflict(ours) => ReplicationInstanceResponse { status_code: 409, response_entity: Some(*ours) },
        },
        Action::Cancel => found(registry.cancel(app, id, Origin::Peer)),
        Action::StatusUpdate => match item.status {
            Some(s) => found(registry.status_update(app, id, s, dirty, Origin::Peer)),
            None => code(400),
        },
        Action::DeleteStatusOverride => {
            found(registry.delete_status_override(app, id, item.status.unwrap_or(Status::Unknown), dirty, Origin::Peer))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::Tuning;

    fn item(action: Action, id: &str) -> ReplicationInstance {
        ReplicationInstance {
            app_name: "A".into(),
            id: id.into(),
            last_dirty_timestamp: None,
            overridden_status: None,
            status: None,
            instance_info: None,
            action,
        }
    }

    fn actions(p: &Peer) -> Vec<(Action, String)> {
        p.queue.lock().iter().map(|i| (i.action, i.id.clone())).collect()
    }

    #[test]
    fn a_full_queue_drops_heartbeats_first() {
        let p = Peer::new("http://p:8761/eureka/", 3, 2);
        assert_eq!(p.url, "http://p:8761");
        p.push(item(Action::Register, "r1"));
        p.push(item(Action::Heartbeat, "h1"));
        p.push(item(Action::Register, "r2"));
        // Full: the heartbeat goes to make room.
        p.push(item(Action::Cancel, "c1"));
        assert_eq!(actions(&p).iter().map(|a| a.1.as_str()).collect::<Vec<_>>(), ["r1", "r2", "c1"]);
        // Full of non-heartbeats: an incoming heartbeat is dropped...
        p.push(item(Action::Heartbeat, "h2"));
        assert_eq!(p.queued(), 3);
        // ...and anything else pushes the oldest out.
        p.push(item(Action::Register, "r3"));
        assert_eq!(actions(&p).iter().map(|a| a.1.as_str()).collect::<Vec<_>>(), ["r2", "c1", "r3"]);
        assert_eq!(p.stats().dropped, 3);
        assert_eq!(p.queued_by_action().into_iter().collect::<Vec<_>>(), [("cancel", 1), ("register", 2)]);

        // Taking honours the batch size; requeued items go back in front, in order.
        let first = p.take();
        assert_eq!(first.len(), 2);
        p.requeue(first);
        assert_eq!(actions(&p).iter().map(|a| a.1.as_str()).collect::<Vec<_>>(), ["r2", "c1", "r3"]);
        // A requeued item that does not fit loses to the newer ones.
        let q = Peer::new("http://q", 2, 10);
        q.push(item(Action::Register, "new1"));
        q.push(item(Action::Heartbeat, "hb"));
        q.requeue(vec![item(Action::Register, "old1"), item(Action::Register, "old2")]);
        assert_eq!(actions(&q).iter().map(|a| a.1.as_str()).collect::<Vec<_>>(), ["old2", "new1"]);
        q.requeue(vec![item(Action::Heartbeat, "oldhb")]);
        assert_eq!(q.queued(), 2, "a heartbeat does not push a registration out");
    }

    #[tokio::test]
    async fn applies_what_peers_send() {
        let r = Registry::new(Tuning::default(), vec![]);
        let mut info = crate::registry::tests_support::inst("A", "i", 10);
        info.status = Status::Up;
        let mut reg = item(Action::Register, "i");
        reg.instance_info = Some(info.clone());
        assert_eq!(apply(&r, reg.clone()).status_code, 200);
        assert_eq!(apply(&r, item(Action::Register, "i")).status_code, 400, "a registration needs the instance");
        let mut hb = item(Action::Heartbeat, "i");
        hb.last_dirty_timestamp = Some(10);
        assert_eq!(apply(&r, hb.clone()).status_code, 200);
        hb.last_dirty_timestamp = Some(9);
        let c = apply(&r, hb.clone());
        assert_eq!((c.status_code, c.response_entity.map(|e| e.last_dirty_timestamp)), (409, Some(10)));
        hb.last_dirty_timestamp = Some(11);
        assert_eq!(apply(&r, hb).status_code, 404);
        assert_eq!(apply(&r, item(Action::StatusUpdate, "i")).status_code, 400, "a status update needs the status");
        let mut su = item(Action::StatusUpdate, "i");
        su.status = Some(Status::OutOfService);
        assert_eq!(apply(&r, su).status_code, 200);
        assert_eq!(r.instance("A", "i").unwrap().status, Status::OutOfService);
        assert_eq!(apply(&r, item(Action::DeleteStatusOverride, "i")).status_code, 200);
        assert_eq!(r.instance("A", "i").unwrap().status, Status::Unknown);
        assert_eq!(apply(&r, item(Action::Cancel, "i")).status_code, 200);
        assert_eq!(apply(&r, item(Action::Cancel, "i")).status_code, 404);
        assert_eq!(apply(&r, reg).status_code, 409, "the tombstone refuses the late copy");
        for a in [Action::Heartbeat, Action::Register, Action::Cancel, Action::StatusUpdate, Action::DeleteStatusOverride] {
            assert!(!action_label(a).is_empty());
        }
    }
}
