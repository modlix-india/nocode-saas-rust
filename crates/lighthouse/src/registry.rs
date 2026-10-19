//! The registry, with Eureka's rules (`AbstractInstanceRegistry`, `PeerAwareInstanceRegistryImpl`
//! and the `InstanceResource` checks), so every Eureka client sees the behaviour it was built for.
//!
//! - **Status.** A registration's status goes through Eureka's override rules: an instance
//!   reporting DOWN or STARTING wins; else an OUT_OF_SERVICE (or other) override set through
//!   `/status` wins; else, for a client's own call, an existing UP or OUT_OF_SERVICE is kept.
//! - **Dirty timestamps.** A registration older than the copy held is ignored in favour of the
//!   copy. A heartbeat carrying a newer `lastDirtyTimestamp` answers 404 (register again); a
//!   replicated heartbeat carrying an older one answers 409 with the newer copy.
//! - **Leases** are each instance's own (`durationInSecs`), renewed by heartbeats.
//! - **Self-preservation**: no eviction while the renewals of the last minute are below
//!   `sum(60 / renewalIntervalInSecs) x renewal_percent_threshold`, as when a network problem
//!   rather than the instances stops the heartbeats. At most `1 - threshold` of the registry is
//!   evicted per tick, the most overdue first.
//! - **Delta**: every change of the last 180 seconds, the latest state of each instance once.
//! - **Tombstones** (an extension): an instance cancelled in the last 2 minutes refuses
//!   replicated registrations that are not newer than it, so a late Register from a peer cannot
//!   bring it back. Its own client registering again always wins.
//!
//! Every change made for a client is queued for each peer, under the registry lock so the
//! peers see changes in the order they happened. Changes received from a peer are never sent on.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use lighthouse_client::replication::{Action, Digest, DigestEntry, ReplicationInstance};
use lighthouse_client::wire::{reconcile_hashcode, ActionType, Application, Applications, InstanceInfo, LeaseInfo, Status};
use parking_lot::Mutex;
use serde::Serialize;
use serde_json::{json, Value};

use crate::replication::Peer;

/// Who made a call: an instance (or operator) itself, or a peer repeating it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Client,
    Peer,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Renewal {
    Renewed,
    /// Unknown here, or the caller's copy is newer: the caller should register.
    NotFound,
    /// A peer's copy is older than ours: here is ours.
    Conflict(Box<InstanceInfo>),
}

#[derive(Debug, Clone)]
pub struct Tuning {
    pub renewal_percent_threshold: f64,
    pub self_preservation: bool,
    pub delta_retention_ms: i64,
    pub tombstone_ms: i64,
}

impl Default for Tuning {
    fn default() -> Self {
        Self { renewal_percent_threshold: 0.85, self_preservation: true, delta_retention_ms: 180_000, tombstone_ms: 120_000 }
    }
}

/// Wall-clock milliseconds that follow tokio's clock, so leases and self-preservation can be
/// tested with `tokio::time::pause`.
struct Clock {
    start: tokio::time::Instant,
    start_ms: i64,
}

impl Clock {
    fn new() -> Self {
        Self { start: tokio::time::Instant::now(), start_ms: lighthouse_client::now_millis() }
    }

    fn now_ms(&self) -> i64 {
        self.start_ms + self.start.elapsed().as_millis() as i64
    }
}

/// The self-preservation numbers, also exported as gauges.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Preservation {
    pub renewals_last_minute: u64,
    pub expected_per_minute: f64,
    pub threshold: f64,
    pub active: bool,
}

struct Lease {
    info: InstanceInfo,
    registered_ms: i64,
    last_renewal_ms: i64,
    service_up_ms: i64,
}

impl Lease {
    fn duration_ms(&self) -> i64 {
        i64::from(self.info.lease_info.duration_in_secs.max(1)) * 1000
    }

    fn renewals_per_minute(&self) -> f64 {
        60.0 / f64::from(self.info.lease_info.renewal_interval_in_secs.max(1))
    }

    /// The instance as served, with the lease's timestamps.
    fn view(&self, eviction_ms: i64) -> InstanceInfo {
        let mut i = self.info.clone();
        i.lease_info = LeaseInfo {
            renewal_interval_in_secs: self.info.lease_info.renewal_interval_in_secs,
            duration_in_secs: self.info.lease_info.duration_in_secs,
            registration_timestamp: self.registered_ms,
            last_renewal_timestamp: self.last_renewal_ms,
            eviction_timestamp: eviction_ms,
            service_up_timestamp: self.service_up_ms,
        };
        i
    }
}

struct Tombstone {
    until_ms: i64,
    last_dirty: i64,
}

/// Renewals per second over the last minute.
struct Window {
    buckets: Vec<(i64, u64)>,
}

impl Window {
    fn new() -> Self {
        Self { buckets: vec![(i64::MIN, 0); 60] }
    }

    fn add(&mut self, now_ms: i64) {
        let sec = now_ms.div_euclid(1000);
        let b = &mut self.buckets[sec.rem_euclid(60) as usize];
        if b.0 != sec {
            *b = (sec, 0);
        }
        b.1 += 1;
    }

    fn count(&self, now_ms: i64) -> u64 {
        let sec = now_ms.div_euclid(1000);
        self.buckets.iter().filter(|(s, _)| *s > sec - 60 && *s <= sec).map(|(_, n)| n).sum()
    }
}

struct State {
    apps: BTreeMap<String, BTreeMap<String, Lease>>,
    /// Status overrides by instance id, as Eureka keys them.
    overrides: HashMap<String, Status>,
    recent: VecDeque<(i64, InstanceInfo)>,
    tombstones: HashMap<(String, String), Tombstone>,
    renewals: Window,
    /// Bumped on every visible change: the delta's version and the ETags.
    version: u64,
}

impl State {
    fn lease_mut(&mut self, app: &str, id: &str) -> Option<&mut Lease> {
        self.apps.get_mut(app).and_then(|m| m.get_mut(id))
    }

    fn lease(&self, app: &str, id: &str) -> Option<&Lease> {
        self.apps.get(app).and_then(|m| m.get(id))
    }

    fn changed(&mut self, now: i64, retention_ms: i64, view: InstanceInfo) {
        self.recent.push_back((now, view));
        self.prune_recent(now, retention_ms);
        self.version += 1;
    }

    fn prune_recent(&mut self, now: i64, retention_ms: i64) {
        while self.recent.front().is_some_and(|(t, _)| now - t > retention_ms) {
            self.recent.pop_front();
        }
    }

    /// Takes an instance out; `None` when it was not there.
    fn remove(&mut self, app: &str, id: &str, now: i64, retention_ms: i64) -> Option<InstanceInfo> {
        let m = self.apps.get_mut(app)?;
        let lease = m.remove(id)?;
        if m.is_empty() {
            self.apps.remove(app);
        }
        self.overrides.remove(id);
        let mut v = lease.view(now);
        v.action_type = Some(ActionType::Deleted);
        v.last_updated_timestamp = now;
        self.changed(now, retention_ms, v.clone());
        Some(v)
    }

    fn leases(&self) -> impl Iterator<Item = &Lease> {
        self.apps.values().flat_map(|m| m.values())
    }

    fn size(&self) -> usize {
        self.apps.values().map(BTreeMap::len).sum()
    }

    fn hashcode(&self) -> String {
        reconcile_hashcode(self.leases().map(|l| l.info.status))
    }

    fn preservation(&self, now: i64, t: &Tuning) -> Preservation {
        let expected: f64 = self.leases().map(Lease::renewals_per_minute).sum();
        let threshold = expected * t.renewal_percent_threshold;
        let renewals = self.renewals.count(now);
        let active = t.self_preservation && threshold > 0.0 && (renewals as f64) < threshold;
        Preservation { renewals_last_minute: renewals, expected_per_minute: expected, threshold, active }
    }
}

/// Eureka's `FirstMatchWinsCompositeRule(DownOrStartingRule, OverrideExistsRule,
/// LeaseExistsRule)`, then the instance's own status.
fn status_rules(incoming: Status, id: &str, existing: Option<Status>, overrides: &HashMap<String, Status>, origin: Origin) -> Status {
    if incoming != Status::Up && incoming != Status::OutOfService {
        return incoming;
    }
    if let Some(o) = overrides.get(id) {
        return *o;
    }
    if origin == Origin::Client {
        if let Some(e @ (Status::Up | Status::OutOfService)) = existing {
            return e;
        }
    }
    incoming
}

pub struct Registry {
    state: Mutex<State>,
    clock: Clock,
    tuning: Tuning,
    peers: Vec<Arc<Peer>>,
    ready: AtomicBool,
    epoch: u32,
}

impl Registry {
    pub fn new(tuning: Tuning, peers: Vec<Arc<Peer>>) -> Self {
        Self {
            state: Mutex::new(State {
                apps: BTreeMap::new(),
                overrides: HashMap::new(),
                recent: VecDeque::new(),
                tombstones: HashMap::new(),
                renewals: Window::new(),
                version: 1,
            }),
            clock: Clock::new(),
            tuning,
            peers,
            ready: AtomicBool::new(false),
            epoch: rand::random(),
        }
    }

    pub fn now_ms(&self) -> i64 {
        self.clock.now_ms()
    }

    /// Whether the startup sync is over. Until then discovery answers 503 and nothing is evicted.
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }

    pub fn set_ready(&self) {
        self.ready.store(true, Ordering::SeqCst);
    }

    /// Changes with every process, so an ETag from another instance never matches.
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    pub fn tuning(&self) -> &Tuning {
        &self.tuning
    }

    fn replicate(&self, action: Action, view: &InstanceInfo, overridden: Option<Status>) {
        if self.peers.is_empty() {
            return;
        }
        let item = ReplicationInstance {
            app_name: view.app.clone(),
            id: view.instance_id.clone(),
            last_dirty_timestamp: Some(view.last_dirty_timestamp),
            overridden_status: Some(overridden.unwrap_or(view.overridden_status)),
            status: Some(view.status),
            instance_info: (action == Action::Register).then(|| view.clone()),
            action,
        };
        for p in &self.peers {
            p.push(item.clone());
        }
    }

    /// `POST /apps/{APP}`. False when a tombstone refused a peer's late registration.
    pub fn register(&self, info: InstanceInfo, origin: Origin) -> bool {
        self.put(info, origin, None)
    }

    /// Takes a peer's full copy (startup sync, digest repair, a 409): like a replicated
    /// registration, but keeping the peer's lease timestamps, so an instance that stopped
    /// renewing on the peer expires here on the same schedule.
    pub fn adopt(&self, info: InstanceInfo) -> bool {
        let lease = info.lease_info;
        self.put(info, Origin::Peer, Some(lease))
    }

    fn put(&self, mut r: InstanceInfo, origin: Origin, peer_lease: Option<LeaseInfo>) -> bool {
        let now = self.now_ms();
        r.app = r.app.to_ascii_uppercase();
        if r.instance_id.is_empty() {
            r.instance_id = r.host_name.clone();
        }
        let (app, id) = (r.app.clone(), r.instance_id.clone());
        let mut st = self.state.lock();
        let key = (app.clone(), id.clone());
        match origin {
            Origin::Client => {
                st.tombstones.remove(&key);
            }
            Origin::Peer => {
                if st.tombstones.get(&key).is_some_and(|t| t.until_ms > now && r.last_dirty_timestamp <= t.last_dirty) {
                    metrics::counter!("lighthouse_tombstone_refusals_total").increment(1);
                    tracing::info!(app, id, "refused a late replicated registration of a cancelled instance");
                    return false;
                }
            }
        }
        let existing = st.lease(&app, &id);
        let existing_status = existing.map(|l| l.info.status);
        let existing_service_up = existing.map(|l| l.service_up_ms);
        if let Some(e) = existing {
            // Eureka keeps its own copy when it is newer than the registration.
            if e.info.last_dirty_timestamp > r.last_dirty_timestamp {
                r = e.info.clone();
            }
        }
        if r.overridden_status != Status::Unknown && (peer_lease.is_some() || !st.overrides.contains_key(&id)) {
            st.overrides.insert(id.clone(), r.overridden_status);
        }
        if let Some(o) = st.overrides.get(&id) {
            r.overridden_status = *o;
        }
        r.status = status_rules(r.status, &id, existing_status, &st.overrides, origin);
        let from_peer = |pick: fn(&LeaseInfo) -> i64| peer_lease.as_ref().map(pick).filter(|t| *t > 0).map(|t| t.min(now));
        let registered_ms = from_peer(|l| l.registration_timestamp).unwrap_or(now);
        let last_renewal_ms = from_peer(|l| l.last_renewal_timestamp).unwrap_or(now);
        let mut service_up_ms = existing_service_up.or_else(|| from_peer(|l| l.service_up_timestamp)).unwrap_or(0);
        if r.status == Status::Up && service_up_ms == 0 {
            service_up_ms = now;
        }
        r.action_type = Some(ActionType::Added);
        r.last_updated_timestamp = now;
        let lease = Lease { info: r, registered_ms, last_renewal_ms, service_up_ms };
        let view = lease.view(0);
        st.apps.entry(app).or_default().insert(id, lease);
        st.changed(now, self.tuning.delta_retention_ms, view.clone());
        metrics::counter!("lighthouse_registrations_total", "origin" => origin_label(origin)).increment(1);
        if origin == Origin::Client {
            self.replicate(Action::Register, &view, None);
        }
        true
    }

    /// `PUT /apps/{APP}/{ID}`: Eureka's `renew` followed by `validateDirtyTimestamp`.
    pub fn renew(&self, app: &str, id: &str, origin: Origin, last_dirty: Option<i64>, overridden: Option<Status>) -> Renewal {
        let now = self.now_ms();
        let app = app.to_ascii_uppercase();
        let mut st = self.state.lock();
        let override_now = st.overrides.get(id).copied();
        let Some(lease) = st.lease_mut(&app, id) else {
            metrics::counter!("lighthouse_renewals_total", "result" => "not_found").increment(1);
            return Renewal::NotFound;
        };
        let current = lease.info.status;
        let status = if current != Status::Up && current != Status::OutOfService { current } else { override_now.unwrap_or(current) };
        if status == Status::Unknown {
            // A deleted override left the status unknown: Eureka asks for a new registration.
            return Renewal::NotFound;
        }
        lease.last_renewal_ms = now;
        let changed = (status != current).then(|| {
            lease.info.status = status;
            lease.info.action_type = Some(ActionType::Modified);
            lease.info.last_updated_timestamp = now;
            lease.view(0)
        });
        let view = lease.view(0);
        let ours = lease.info.last_dirty_timestamp;
        st.renewals.add(now);
        if let Some(v) = changed {
            st.changed(now, self.tuning.delta_retention_ms, v);
        }
        if origin == Origin::Client {
            self.replicate(Action::Heartbeat, &view, override_now);
        }
        let result = match last_dirty {
            Some(d) if d > ours => {
                if let Some(o) = overridden.filter(|o| origin == Origin::Peer && *o != Status::Unknown) {
                    st.overrides.insert(id.to_string(), o);
                }
                Renewal::NotFound
            }
            Some(d) if d < ours && origin == Origin::Peer => Renewal::Conflict(Box::new(view)),
            _ => Renewal::Renewed,
        };
        let label = match result {
            Renewal::Renewed => "renewed",
            Renewal::NotFound => "newer_elsewhere",
            Renewal::Conflict(_) => "conflict",
        };
        metrics::counter!("lighthouse_renewals_total", "result" => label).increment(1);
        result
    }

    /// `DELETE /apps/{APP}/{ID}`. Leaves a tombstone.
    pub fn cancel(&self, app: &str, id: &str, origin: Origin) -> bool {
        let now = self.now_ms();
        let app = app.to_ascii_uppercase();
        let mut st = self.state.lock();
        let Some(view) = st.remove(&app, id, now, self.tuning.delta_retention_ms) else {
            return false;
        };
        st.tombstones.insert(
            (app, id.to_string()),
            Tombstone { until_ms: now + self.tuning.tombstone_ms, last_dirty: view.last_dirty_timestamp },
        );
        metrics::counter!("lighthouse_cancels_total", "origin" => origin_label(origin)).increment(1);
        if origin == Origin::Client {
            self.replicate(Action::Cancel, &view, None);
        }
        true
    }

    /// `PUT /apps/{APP}/{ID}/status?value=`: sets an override (OUT_OF_SERVICE to drain).
    pub fn status_update(&self, app: &str, id: &str, status: Status, last_dirty: Option<i64>, origin: Origin) -> bool {
        let now = self.now_ms();
        let app = app.to_ascii_uppercase();
        let mut st = self.state.lock();
        let Some(lease) = st.lease_mut(&app, id) else {
            return false;
        };
        lease.last_renewal_ms = now;
        let changed = (lease.info.status != status).then(|| {
            if status == Status::Up && lease.service_up_ms == 0 {
                lease.service_up_ms = now;
            }
            lease.info.overridden_status = status;
            lease.info.status = status;
            if let Some(d) = last_dirty.filter(|d| *d > lease.info.last_dirty_timestamp) {
                lease.info.last_dirty_timestamp = d;
            }
            lease.info.action_type = Some(ActionType::Modified);
            lease.info.last_updated_timestamp = now;
            lease.view(0)
        });
        let view = lease.view(0);
        if let Some(v) = changed {
            st.overrides.insert(id.to_string(), status);
            st.changed(now, self.tuning.delta_retention_ms, v);
        }
        if origin == Origin::Client {
            self.replicate(Action::StatusUpdate, &view, Some(status));
        }
        true
    }

    /// `DELETE /apps/{APP}/{ID}/status?value=`: removes the override and sets `status`
    /// (UNKNOWN when no value is given, which makes the next heartbeat ask for a registration).
    pub fn delete_status_override(&self, app: &str, id: &str, status: Status, last_dirty: Option<i64>, origin: Origin) -> bool {
        let now = self.now_ms();
        let app = app.to_ascii_uppercase();
        let mut st = self.state.lock();
        let had = st.overrides.contains_key(id);
        let Some(lease) = st.lease_mut(&app, id) else {
            return false;
        };
        lease.last_renewal_ms = now;
        let changed = had.then(|| {
            lease.info.overridden_status = Status::Unknown;
            lease.info.status = status;
            if let Some(d) = last_dirty.filter(|d| *d > lease.info.last_dirty_timestamp) {
                lease.info.last_dirty_timestamp = d;
            }
            lease.info.action_type = Some(ActionType::Modified);
            lease.info.last_updated_timestamp = now;
            lease.view(0)
        });
        let view = lease.view(0);
        if let Some(v) = changed {
            st.overrides.remove(id);
            st.changed(now, self.tuning.delta_retention_ms, v);
        }
        if origin == Origin::Client {
            self.replicate(Action::DeleteStatusOverride, &view, Some(Status::Unknown));
        }
        true
    }

    /// The whole registry and the version it was read at (for the ETag).
    pub fn applications(&self) -> (Applications, u64) {
        let st = self.state.lock();
        let applications = st
            .apps
            .iter()
            .map(|(name, m)| Application { name: name.clone(), instances: m.values().map(|l| l.view(0)).collect() })
            .collect();
        (Applications { versions_delta: "1".into(), apps_hashcode: st.hashcode(), applications }, st.version)
    }

    /// The changes of the retention window, each instance once in its latest state, grouped by
    /// app in the order they first appear; the hash code is the whole registry's.
    pub fn delta(&self) -> (Applications, u64) {
        let now = self.now_ms();
        let mut st = self.state.lock();
        st.prune_recent(now, self.tuning.delta_retention_ms);
        let mut latest: Vec<&InstanceInfo> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for (_, i) in st.recent.iter().rev() {
            if seen.insert((i.app.as_str(), i.instance_id.as_str())) {
                latest.push(i);
            }
        }
        latest.reverse();
        let mut applications: Vec<Application> = Vec::new();
        for i in latest {
            match applications.iter_mut().find(|a| a.name == i.app) {
                Some(a) => a.instances.push(i.clone()),
                None => applications.push(Application { name: i.app.clone(), instances: vec![i.clone()] }),
            }
        }
        let version = st.version;
        (Applications { versions_delta: version.to_string(), apps_hashcode: st.hashcode(), applications }, version)
    }

    /// One app, `None` when it has no instance.
    pub fn application(&self, app: &str) -> (Option<Application>, u64) {
        let st = self.state.lock();
        let name = app.to_ascii_uppercase();
        let app = st.apps.get(&name).map(|m| Application { name: name.clone(), instances: m.values().map(|l| l.view(0)).collect() });
        (app, st.version)
    }

    pub fn instance(&self, app: &str, id: &str) -> Option<InstanceInfo> {
        self.state.lock().lease(&app.to_ascii_uppercase(), id).map(|l| l.view(0))
    }

    pub fn digest(&self) -> Digest {
        let st = self.state.lock();
        Digest {
            instances: st
                .leases()
                .map(|l| DigestEntry {
                    app: l.info.app.clone(),
                    id: l.info.instance_id.clone(),
                    status: l.info.status,
                    last_dirty_timestamp: l.info.last_dirty_timestamp,
                })
                .collect(),
        }
    }

    /// Whether a peer's digest entry is something to fetch: missing here (and not cancelled
    /// here since), or newer than our copy.
    pub fn wants(&self, e: &DigestEntry) -> bool {
        let now = self.now_ms();
        let st = self.state.lock();
        let app = e.app.to_ascii_uppercase();
        match st.lease(&app, &e.id) {
            Some(l) => l.info.last_dirty_timestamp < e.last_dirty_timestamp,
            None => !st
                .tombstones
                .get(&(app, e.id.clone()))
                .is_some_and(|t| t.until_ms > now && e.last_dirty_timestamp <= t.last_dirty),
        }
    }

    pub fn version(&self) -> u64 {
        self.state.lock().version
    }

    pub fn preservation(&self) -> Preservation {
        self.state.lock().preservation(self.now_ms(), &self.tuning)
    }

    /// One eviction pass: drops expired tombstones, then (unless self-preservation holds)
    /// evicts expired leases, the most overdue first, at most `1 - threshold` of the registry.
    /// Evictions are not replicated: each instance evicts on its own leases.
    pub fn evict(&self) -> usize {
        let now = self.now_ms();
        let mut st = self.state.lock();
        st.tombstones.retain(|_, t| t.until_ms > now);
        let p = st.preservation(now, &self.tuning);
        let size = st.size();
        metrics::gauge!("lighthouse_self_preservation").set(if p.active { 1.0 } else { 0.0 });
        metrics::gauge!("lighthouse_renewals_last_minute").set(p.renewals_last_minute as f64);
        metrics::gauge!("lighthouse_renewal_threshold").set(p.threshold);
        metrics::gauge!("lighthouse_instances").set(size as f64);
        if p.active {
            return 0;
        }
        let mut expired: Vec<(i64, String, String)> = st
            .leases()
            .filter(|l| now - l.last_renewal_ms > l.duration_ms())
            .map(|l| (now - l.last_renewal_ms - l.duration_ms(), l.info.app.clone(), l.info.instance_id.clone()))
            .collect();
        let keep = (size as f64 * self.tuning.renewal_percent_threshold.clamp(0.0, 1.0)).floor() as usize;
        expired.sort_by(|a, b| b.0.cmp(&a.0));
        expired.truncate(size - keep.min(size));
        for (overdue, app, id) in &expired {
            st.remove(app, id, now, self.tuning.delta_retention_ms);
            tracing::warn!(app, id, overdue_ms = overdue, "evicted an instance whose lease expired");
        }
        metrics::counter!("lighthouse_evictions_total").increment(expired.len() as u64);
        expired.len()
    }

    /// For `/v1/registry`: everything an operator wants to see at a glance.
    pub fn operator_view(&self) -> Value {
        let now = self.now_ms();
        let st = self.state.lock();
        let apps: Vec<Value> = st
            .apps
            .iter()
            .map(|(name, m)| {
                let instances: Vec<Value> = m
                    .values()
                    .map(|l| {
                        json!({
                            "id": l.info.instance_id,
                            "status": l.info.status,
                            "overriddenStatus": l.info.overridden_status,
                            "hostName": l.info.host_name,
                            "ipAddr": l.info.ip_addr,
                            "port": l.info.port.port,
                            "url": l.info.base_url(),
                            "healthCheckUrl": l.info.health_check_url,
                            "lastRenewalAgoMs": now - l.last_renewal_ms,
                            "leaseSeconds": l.info.lease_info.duration_in_secs,
                            "renewalSeconds": l.info.lease_info.renewal_interval_in_secs,
                            "registeredAt": l.registered_ms,
                            "lastDirtyTimestamp": l.info.last_dirty_timestamp,
                            "metadata": l.info.metadata.0,
                        })
                    })
                    .collect();
                json!({"name": name, "instances": instances})
            })
            .collect();
        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        for l in st.leases() {
            *counts.entry(l.info.status.as_str()).or_default() += 1;
        }
        json!({
            "ready": self.is_ready(),
            "registryVersion": st.version,
            "instances": st.size(),
            "counts": counts,
            "appsHashcode": st.hashcode(),
            "selfPreservation": st.preservation(now, &self.tuning),
            "tombstones": st.tombstones.values().filter(|t| t.until_ms > now).count(),
            "apps": apps,
        })
    }
}

fn origin_label(o: Origin) -> &'static str {
    match o {
        Origin::Client => "client",
        Origin::Peer => "peer",
    }
}

#[cfg(test)]
pub(crate) mod tests_support {
    use lighthouse_client::wire::{InstanceInfo, LeaseInfo, PortInfo};

    /// An UP instance with a 10/30 second lease.
    pub(crate) fn inst(app: &str, id: &str, dirty: i64) -> InstanceInfo {
        InstanceInfo {
            instance_id: id.into(),
            host_name: "h".into(),
            app: app.into(),
            ip_addr: "10.0.0.1".into(),
            port: PortInfo { port: 8000, enabled: true },
            lease_info: LeaseInfo { renewal_interval_in_secs: 10, duration_in_secs: 30, ..LeaseInfo::default() },
            last_dirty_timestamp: dirty,
            ..InstanceInfo::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::inst;
    use super::*;
    use std::time::Duration;

    fn reg() -> Registry {
        Registry::new(Tuning::default(), vec![])
    }

    fn status(r: &Registry, app: &str, id: &str) -> Status {
        r.instance(app, id).unwrap().status
    }

    #[tokio::test]
    async fn override_rules() {
        let r = reg();
        assert!(r.register(inst("files", "a", 10), Origin::Client));
        assert_eq!(status(&r, "FILES", "a"), Status::Up);
        assert_eq!(r.instance("files", "a").unwrap().app, "FILES", "upper case");

        // OUT_OF_SERVICE through /status is an override: it survives heartbeats and a client's
        // own UP registration.
        assert!(r.status_update("FILES", "a", Status::OutOfService, Some(11), Origin::Client));
        assert_eq!(r.instance("FILES", "a").unwrap().last_dirty_timestamp, 11);
        assert_eq!(r.renew("FILES", "a", Origin::Client, None, None), Renewal::Renewed);
        assert_eq!(status(&r, "FILES", "a"), Status::OutOfService);
        r.register(inst("FILES", "a", 12), Origin::Client);
        assert_eq!(status(&r, "FILES", "a"), Status::OutOfService);
        assert_eq!(r.instance("FILES", "a").unwrap().overridden_status, Status::OutOfService);
        // An instance reporting DOWN wins over the override.
        let mut down = inst("FILES", "a", 13);
        down.status = Status::Down;
        r.register(down, Origin::Client);
        assert_eq!(status(&r, "FILES", "a"), Status::Down);
        // A heartbeat of a DOWN instance keeps it DOWN.
        assert_eq!(r.renew("FILES", "a", Origin::Client, None, None), Renewal::Renewed);
        assert_eq!(status(&r, "FILES", "a"), Status::Down);

        // Deleting the override with a value sets that status.
        assert!(r.delete_status_override("FILES", "a", Status::Up, Some(14), Origin::Client));
        assert_eq!(status(&r, "FILES", "a"), Status::Up);
        assert_eq!(r.instance("FILES", "a").unwrap().last_dirty_timestamp, 14);
        // Deleting it without one leaves UNKNOWN: the next heartbeat asks for a registration.
        r.status_update("FILES", "a", Status::OutOfService, None, Origin::Client);
        r.delete_status_override("FILES", "a", Status::Unknown, None, Origin::Client);
        assert_eq!(status(&r, "FILES", "a"), Status::Unknown);
        assert_eq!(r.renew("FILES", "a", Origin::Client, None, None), Renewal::NotFound);
        // No override to delete: nothing changes.
        let v = r.version();
        assert!(r.delete_status_override("FILES", "a", Status::Up, None, Origin::Client));
        assert_eq!(r.version(), v);

        // A client re-registering UP over an existing UP or OUT_OF_SERVICE keeps it; a peer's
        // copy is taken as it is.
        r.register(inst("FILES", "a", 20), Origin::Client);
        assert_eq!(status(&r, "FILES", "a"), Status::Up);
        let mut oos = inst("FILES", "b", 1);
        oos.status = Status::OutOfService;
        r.register(oos, Origin::Peer);
        assert_eq!(status(&r, "FILES", "b"), Status::OutOfService);
        r.register(inst("FILES", "b", 2), Origin::Client);
        assert_eq!(status(&r, "FILES", "b"), Status::OutOfService, "LeaseExistsRule");
        r.register(inst("FILES", "b", 3), Origin::Peer);
        assert_eq!(status(&r, "FILES", "b"), Status::Up);

        // A registration carrying an override transfers it (the peer's startup state).
        let mut carried = inst("FILES", "c", 1);
        carried.overridden_status = Status::OutOfService;
        r.register(carried, Origin::Peer);
        assert_eq!(status(&r, "FILES", "c"), Status::OutOfService);

        // Unknown instances.
        assert!(!r.status_update("FILES", "zz", Status::Up, None, Origin::Client));
        assert!(!r.delete_status_override("FILES", "zz", Status::Up, None, Origin::Client));
        assert!(!r.cancel("FILES", "zz", Origin::Client));
        assert_eq!(r.renew("NOPE", "zz", Origin::Client, None, None), Renewal::NotFound);
        // A status update to the same status changes nothing.
        let v = r.version();
        assert!(r.status_update("FILES", "c", Status::OutOfService, None, Origin::Client));
        assert_eq!(r.version(), v);
        // UP through /status marks the service up.
        let mut starting = inst("FILES", "d", 1);
        starting.status = Status::Starting;
        r.register(starting, Origin::Client);
        assert_eq!(r.instance("FILES", "d").unwrap().lease_info.service_up_timestamp, 0);
        r.status_update("FILES", "d", Status::Up, None, Origin::Client);
        assert!(r.instance("FILES", "d").unwrap().lease_info.service_up_timestamp > 0);
    }

    #[tokio::test]
    async fn dirty_timestamps() {
        let r = reg();
        r.register(inst("A", "i", 100), Origin::Client);
        // An older registration does not replace the newer copy.
        let mut old = inst("A", "i", 50);
        old.ip_addr = "9.9.9.9".into();
        r.register(old, Origin::Client);
        assert_eq!(r.instance("A", "i").unwrap().ip_addr, "10.0.0.1");
        assert_eq!(r.instance("A", "i").unwrap().last_dirty_timestamp, 100);

        assert_eq!(r.renew("A", "i", Origin::Client, Some(100), None), Renewal::Renewed);
        // The caller is newer: register again.
        assert_eq!(r.renew("A", "i", Origin::Client, Some(101), None), Renewal::NotFound);
        // A client with an older copy is answered 200; a peer gets ours.
        assert_eq!(r.renew("A", "i", Origin::Client, Some(99), None), Renewal::Renewed);
        let Renewal::Conflict(ours) = r.renew("A", "i", Origin::Peer, Some(99), None) else { panic!() };
        assert_eq!(ours.last_dirty_timestamp, 100);
        // A newer peer's override is stored for when its copy arrives.
        assert_eq!(r.renew("A", "i", Origin::Peer, Some(101), Some(Status::OutOfService)), Renewal::NotFound);
        r.register(inst("A", "i", 101), Origin::Peer);
        assert_eq!(status(&r, "A", "i"), Status::OutOfService);
        // Before its copy arrives, the stored override already applies at the next heartbeat.
        r.register(inst("A", "j", 1), Origin::Client);
        assert_eq!(r.renew("A", "j", Origin::Peer, Some(2), Some(Status::OutOfService)), Renewal::NotFound);
        assert_eq!(status(&r, "A", "j"), Status::Up);
        let v = r.version();
        assert_eq!(r.renew("A", "j", Origin::Client, None, None), Renewal::Renewed);
        assert_eq!(status(&r, "A", "j"), Status::OutOfService);
        assert_eq!(r.version(), v + 1, "a visible change");
    }

    #[tokio::test(start_paused = true)]
    async fn leases_expire_on_their_own_duration() {
        let r = Registry::new(Tuning { self_preservation: false, ..Tuning::default() }, vec![]);
        r.register(inst("A", "short", 1), Origin::Client);
        let mut long = inst("A", "long", 1);
        long.lease_info = LeaseInfo { renewal_interval_in_secs: 30, duration_in_secs: 90, ..LeaseInfo::default() };
        r.register(long, Origin::Client);
        tokio::time::advance(Duration::from_secs(29)).await;
        assert_eq!(r.evict(), 0);
        tokio::time::advance(Duration::from_secs(2)).await;
        assert_eq!(r.evict(), 1);
        assert!(r.instance("A", "short").is_none() && r.instance("A", "long").is_some());
        // Renewing keeps a lease alive.
        for _ in 0..4 {
            tokio::time::advance(Duration::from_secs(30)).await;
            assert_eq!(r.renew("A", "long", Origin::Client, None, None), Renewal::Renewed);
            assert_eq!(r.evict(), 0);
        }
        tokio::time::advance(Duration::from_secs(91)).await;
        assert_eq!(r.evict(), 1);
        assert!(r.application("A").0.is_none(), "an app without instances is gone");
    }

    #[tokio::test(start_paused = true)]
    async fn self_preservation_holds_when_heartbeats_stop() {
        let r = reg();
        for i in 0..10 {
            r.register(inst("A", &format!("i{i}"), 1), Origin::Client);
        }
        // The first minute has no renewals yet: preserved.
        assert!(r.preservation().active);
        let beat = |n: usize| {
            for i in 0..n {
                r.renew("A", &format!("i{i}"), Origin::Client, None, None);
            }
        };
        for _ in 0..7 {
            tokio::time::advance(Duration::from_secs(10)).await;
            beat(10);
        }
        let p = r.preservation();
        assert_eq!((p.expected_per_minute, p.renewals_last_minute, p.active), (60.0, 60, false));
        assert!((p.threshold - 51.0).abs() < 1e-9);

        // Half the heartbeats stop: renewals fall under the threshold, nothing is evicted.
        for _ in 0..7 {
            tokio::time::advance(Duration::from_secs(10)).await;
            beat(5);
            assert_eq!(r.evict(), 0);
        }
        assert!(r.preservation().active);
        assert_eq!(r.applications().0.applications[0].instances.len(), 10);

        // One instance of ten stops: eviction goes on, at most 15% per pass.
        let r = reg();
        for i in 0..10 {
            r.register(inst("A", &format!("i{i}"), 1), Origin::Client);
        }
        for _ in 0..10 {
            tokio::time::advance(Duration::from_secs(10)).await;
            beat_with(&r, 9);
        }
        assert!(!r.preservation().active);
        assert_eq!(r.evict(), 1);
        assert!(r.instance("A", "i9").is_none());
    }

    fn beat_with(r: &Registry, n: usize) {
        for i in 0..n {
            r.renew("A", &format!("i{i}"), Origin::Client, None, None);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn eviction_takes_at_most_the_unprotected_share() {
        let r = Registry::new(Tuning { self_preservation: false, ..Tuning::default() }, vec![]);
        for i in 0..10 {
            r.register(inst("A", &format!("i{i}"), 1), Origin::Client);
        }
        tokio::time::advance(Duration::from_secs(31)).await;
        // Most overdue first: all equal here; two per pass (10 - floor(8.5)).
        assert_eq!(r.evict(), 2);
        assert_eq!(r.evict(), 2);
        let r = Registry::new(Tuning { self_preservation: false, ..Tuning::default() }, vec![]);
        r.register(inst("A", "only", 1), Origin::Client);
        tokio::time::advance(Duration::from_secs(31)).await;
        assert_eq!(r.evict(), 1, "a single instance can always go");
    }

    #[test]
    fn renewal_window() {
        let mut w = Window::new();
        w.add(1_000);
        w.add(1_500);
        w.add(30_000);
        assert_eq!(w.count(30_000), 3);
        assert_eq!(w.count(60_999), 3);
        assert_eq!(w.count(61_000), 1, "the second at 1s fell out of the minute");
        assert_eq!(w.count(91_000), 0);
        w.add(61_000);
        assert_eq!(w.count(61_000), 2, "a reused bucket starts again");
    }

    #[tokio::test]
    async fn hashcode_versions_and_delta_window() {
        let r = reg();
        let (empty, v1) = r.applications();
        assert_eq!((empty.apps_hashcode.as_str(), empty.versions_delta.as_str(), v1), ("", "1", 1));
        r.register(inst("B", "b1", 1), Origin::Client);
        r.register(inst("A", "a1", 1), Origin::Client);
        r.register(inst("A", "a2", 1), Origin::Client);
        r.status_update("A", "a2", Status::OutOfService, None, Origin::Client);
        let (apps, v) = r.applications();
        assert_eq!(apps.apps_hashcode, "OUT_OF_SERVICE_1_UP_2_");
        assert_eq!(apps.applications.iter().map(|a| a.name.as_str()).collect::<Vec<_>>(), ["A", "B"], "sorted");
        assert_eq!(v, 5);

        // The delta: each instance once, latest state, apps in first-appearance order.
        r.cancel("B", "b1", Origin::Client);
        let (delta, dv) = r.delta();
        assert_eq!(dv, 6);
        assert_eq!(delta.versions_delta, "6");
        assert_eq!(delta.apps_hashcode, "OUT_OF_SERVICE_1_UP_1_", "the full registry's");
        let names: Vec<&str> = delta.applications.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["A", "B"]);
        let a2 = delta.applications[0].instances.iter().find(|i| i.instance_id == "a2").unwrap();
        assert_eq!((a2.status, a2.action_type), (Status::OutOfService, Some(ActionType::Modified)));
        let b1 = &delta.applications[1].instances[0];
        assert_eq!(b1.action_type, Some(ActionType::Deleted));
        assert!(b1.lease_info.eviction_timestamp > 0);
        assert_eq!(r.application("a").0.unwrap().instances.len(), 2);
        assert_eq!(r.application("b").1, 6);
        assert_eq!(r.digest().instances.len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn the_delta_forgets_after_its_window() {
        let r = reg();
        r.register(inst("A", "a1", 1), Origin::Client);
        tokio::time::advance(Duration::from_secs(179)).await;
        assert_eq!(r.delta().0.applications.len(), 1);
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(r.delta().0.applications.is_empty());
        assert_eq!(r.applications().0.applications.len(), 1, "the registry keeps it");
    }

    #[tokio::test(start_paused = true)]
    async fn tombstones_stop_late_registrations() {
        let r = reg();
        r.register(inst("A", "i", 10), Origin::Client);
        assert!(r.cancel("A", "i", Origin::Client));
        assert!(!r.register(inst("A", "i", 10), Origin::Peer), "a late copy of what was cancelled");
        assert!(!r.adopt(inst("A", "i", 9)));
        let e = |d| DigestEntry { app: "a".into(), id: "i".into(), status: Status::Up, last_dirty_timestamp: d };
        assert!(!r.wants(&e(10)));
        assert!(r.wants(&e(11)), "a newer registration happened elsewhere");
        assert!(r.instance("A", "i").is_none());
        // Its own client registering again wins, and clears the tombstone.
        assert!(r.register(inst("A", "i", 10), Origin::Client));
        assert!(r.cancel("A", "i", Origin::Peer));
        // The tombstone lapses after two minutes.
        tokio::time::advance(Duration::from_secs(121)).await;
        r.evict();
        assert!(r.register(inst("A", "i", 10), Origin::Peer));
        assert!(!r.wants(&e(10)));
        assert!(r.wants(&e(11)));
        assert_eq!(r.operator_view()["tombstones"], 0);
    }

    #[tokio::test(start_paused = true)]
    async fn adoption_keeps_the_peers_lease() {
        let r = Registry::new(Tuning { self_preservation: false, ..Tuning::default() }, vec![]);
        let now = r.now_ms();
        let mut i = inst("A", "i", 5);
        i.lease_info.registration_timestamp = now - 100_000;
        i.lease_info.last_renewal_timestamp = now - 25_000;
        i.lease_info.service_up_timestamp = now - 90_000;
        i.overridden_status = Status::OutOfService;
        assert!(r.adopt(i));
        let got = r.instance("A", "i").unwrap();
        assert_eq!(got.lease_info.registration_timestamp, now - 100_000);
        assert_eq!(got.lease_info.service_up_timestamp, now - 90_000);
        assert_eq!(got.status, Status::OutOfService);
        tokio::time::advance(Duration::from_secs(6)).await;
        assert_eq!(r.evict(), 1, "expired on the peer's schedule");

        // A timestamp from a peer's clock ahead of ours is capped at now.
        let mut ahead = inst("A", "j", 5);
        ahead.lease_info.last_renewal_timestamp = r.now_ms() + 1_000_000;
        r.adopt(ahead);
        assert!(r.instance("A", "j").unwrap().lease_info.last_renewal_timestamp <= r.now_ms());
        // An instance without an id takes its host name.
        let mut anon = inst("A", "", 1);
        anon.host_name = "host-x".into();
        r.register(anon, Origin::Client);
        assert!(r.instance("A", "host-x").is_some());
        let view = r.operator_view();
        assert_eq!(view["instances"], 2);
        assert_eq!(view["counts"], json!({"UP": 2}));
        assert_eq!(view["apps"][0]["instances"][0]["leaseSeconds"], 30);
        assert!(!r.is_ready());
        r.set_ready();
        assert!(r.is_ready());
        assert_eq!(r.tuning().tombstone_ms, 120_000);
        let _ = r.epoch();
    }
}
