//! In-process caches kept consistent with the Java services' cache evictions.
//!
//! The Java `CacheService` keeps a Caffeine L1 per cache name and a Redis hash L2 named
//! `<prefix>-<cacheName>`, and on every eviction publishes `<prefix>-<cacheName>:<key>` (or
//! `:*` for the whole cache) on the Redis channel `evictionChannel`. Every instance listens and
//! drops its L1 copy.
//!
//! The L2 values are Java-serialized objects (`redis.codec: object` in every environment), which
//! Rust cannot read, so a Rust service keeps only an L1 and never reads or writes the hashes.
//! What it does share is the eviction channel, in both directions:
//! - it listens, so a Java write (an upload, a delete) evicts the Rust copies too;
//! - when it writes, it publishes the same messages and deletes the Java L2 hash, so the Java
//!   instances reload rather than serve what Rust just replaced.
//!
//! If the subscription drops, every local cache is cleared on reconnect: evictions published
//! while disconnected were missed, and a cold cache is correct where a stale one is not.

use std::future::Future;
use std::hash::Hash;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use futures::future::BoxFuture;
use futures::StreamExt;
use moka::future::Cache;

/// The Java services write `redis://<password>@host`: Lettuce reads a lone user-info as the
/// password, redis-rs as a user name, which then never authenticates (and an unauthenticated
/// SUBSCRIBE fails without an error reaching the caller). A lone user-info becomes `:<password>`.
pub fn normalize_redis_url(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else { return url.to_string() };
    let Some((userinfo, host)) = rest.rsplit_once('@') else { return url.to_string() };
    if userinfo.contains(':') {
        return url.to_string();
    }
    format!("{scheme}://:{userinfo}@{host}")
}

/// Local cache lookups by `cache` and `result` (`hit`, `miss`): Micrometer's name for Caffeine's
/// counters, so Java and Rust instances of a cache can share a panel.
pub const CACHE_GETS: &str = "cache_gets_total";
/// Local cache entries dropped for size or age, by `cache`.
pub const CACHE_EVICTIONS: &str = "cache_evictions_total";

/// The `cache` label for a cache name without its prefix. Most Java cache names carry the app,
/// client, profile or storage they hold (`UIFunctionCache_<app>_<name>`, `profileAuthsById_42`,
/// `<storage>_table_creation`), so the label keeps only the fixed part and the series stay
/// bounded: the fixed tail when the name ends with one, else the leading letters.
pub fn cache_label(name: &str) -> String {
    const TAILS: [&str; 3] = ["_index_creation", "_table_creation", "_foreign_keys"];
    if let Some(tail) = TAILS.iter().find(|t| name.ends_with(*t)) {
        return tail[1..].to_string();
    }
    let head: String = name.chars().take_while(char::is_ascii_alphabetic).take(64).collect();
    if head.is_empty() {
        "other".into()
    } else {
        head
    }
}

/// One cache's counters, as Caffeine's `stats()` reports them: lookups that found a value,
/// lookups that did not, and entries dropped for size or age (not explicit evictions).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CacheStats {
    pub entries: u64,
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
}

/// Something that holds named caches and can drop entries by the names the Java side uses.
pub trait Evictable: Send + Sync {
    fn evict<'a>(&'a self, full_cache_name: &'a str, key: &'a str) -> BoxFuture<'a, ()>;
    fn clear_all(&self);
    /// The full names of the caches this family holds now, with their entry counts.
    fn cache_names(&self) -> Vec<(String, u64)> {
        Vec::new()
    }
    /// The full names of the caches with their counters.
    fn cache_stats(&self) -> Vec<(String, CacheStats)> {
        self.cache_names()
            .into_iter()
            .map(|(n, entries)| (n, CacheStats { entries, ..Default::default() }))
            .collect()
    }
    /// What the family holds against its budget, for the metrics.
    fn usage(&self) -> FamilyUsage {
        FamilyUsage::default()
    }
}

#[derive(Clone)]
pub struct CacheService {
    inner: Arc<Inner>,
}

struct Inner {
    prefix: String,
    channel: String,
    redis: Option<redis::Client>,
    families: std::sync::RwLock<Vec<Arc<dyn Evictable>>>,
    ttl: Duration,
    budget_bytes: u64,
    max_entries: u64,
}

/// A weighed family's budget when the caller sets none (`[redis] cache_budget_mb`'s default).
const DEFAULT_BUDGET_BYTES: u64 = 128 * 1024 * 1024;
/// Any other family's entry limit when the caller sets none (`[redis] cache_max_entries`).
const DEFAULT_MAX_ENTRIES: u64 = 20_000;

/// What bounds a family: estimated bytes when its values are weighed
/// ([`CacheService::family_weighed`]), entries otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    Bytes(u64),
    Entries(u64),
}

impl Default for Limit {
    fn default() -> Self {
        Limit::Entries(0)
    }
}

impl Limit {
    /// The `unit` label of the family gauges.
    pub fn unit(&self) -> &'static str {
        match self {
            Limit::Bytes(_) => "bytes",
            Limit::Entries(_) => "entries",
        }
    }

    pub fn value(&self) -> u64 {
        match self {
            Limit::Bytes(n) | Limit::Entries(n) => *n,
        }
    }
}

/// Entries and estimated bytes held, by family and cache label.
pub const CACHE_SIZE: &str = "cache_size";
pub const CACHE_BYTES: &str = "cache_bytes";
/// What a family holds and its limit, by `family` and `unit` (`bytes` or `entries`, see [`Limit`]).
pub const CACHE_FAMILY_USED: &str = "cache_family_used";
pub const CACHE_FAMILY_LIMIT: &str = "cache_family_limit";

impl CacheService {
    /// `prefix` is the Java services' effective `redis.cache.prefix` (`cmn` everywhere): it must
    /// be the one the Java instances use, or their evictions will not be recognised.
    pub fn new(prefix: &str, channel: &str, redis_url: Option<&str>) -> anyhow::Result<Self> {
        Self::build(prefix, channel, redis_url, Duration::from_secs(60 * 60), DEFAULT_BUDGET_BYTES, DEFAULT_MAX_ENTRIES)
    }

    /// The unit's cache service from its `[redis]` section, with its families' sizes reported
    /// on every `/metrics` scrape.
    pub fn configured(cfg: &crate::config::RedisConfig) -> anyhow::Result<Self> {
        let svc = Self::build(
            &cfg.cache_prefix,
            &cfg.eviction_channel,
            Some(cfg.url.as_str()),
            Duration::from_secs(cfg.cache_ttl_secs.max(1)),
            cfg.cache_budget_mb.max(1) * 1024 * 1024,
            cfg.cache_max_entries.max(1),
        )?;
        let mut configured = CONFIGURED.lock().unwrap_or_else(|e| e.into_inner());
        if configured.is_empty() {
            crate::meter::on_scrape(|| {
                let live: Vec<CacheService> = CONFIGURED
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .iter()
                    .filter_map(|w| w.upgrade().map(|inner| CacheService { inner }))
                    .collect();
                report(live.iter().flat_map(CacheService::usage));
            });
        }
        configured.retain(|w| w.strong_count() > 0);
        configured.push(Arc::downgrade(&svc.inner));
        Ok(svc)
    }

    fn build(prefix: &str, channel: &str, redis_url: Option<&str>, ttl: Duration, budget_bytes: u64, max_entries: u64) -> anyhow::Result<Self> {
        let redis = match redis_url.filter(|u| !u.is_empty()) {
            Some(url) => Some(redis::Client::open(normalize_redis_url(url).as_str())?),
            None => None,
        };
        Ok(Self {
            inner: Arc::new(Inner {
                prefix: prefix.to_string(),
                channel: channel.to_string(),
                redis,
                families: std::sync::RwLock::new(Vec::new()),
                // Caffeine's expire-after-write in AbstractBaseConfiguration.
                ttl,
                budget_bytes,
                max_entries,
            }),
        })
    }

    pub fn full_name(&self, cache_name: &str) -> String {
        format!("{}-{}", self.inner.prefix, cache_name)
    }

    /// A weighed family's budget in bytes, any other family's entry limit, and how long a value
    /// lives.
    pub fn limits(&self) -> (u64, u64, Duration) {
        (self.inner.budget_bytes, self.inner.max_entries, self.inner.ttl)
    }

    /// A family of caches holding `V`, addressed by cache name. Registered for eviction.
    /// Bounded by entries (`[redis] cache_max_entries` for the whole family, where Java allows
    /// 10,000 per name): for small values, whose real size cannot be seen behind an `Arc`.
    /// Large values (definitions, pages, files) use [`Self::family_weighed`].
    pub fn family<K, V>(&self) -> Arc<LocalCaches<K, V>>
    where
        K: Hash + Eq + Send + Sync + Clone + From<String> + 'static,
        V: Clone + Send + Sync + 'static,
    {
        self.register(LocalCaches::new(&self.inner.prefix, self.inner.ttl, Limit::Entries(self.inner.max_entries), |_| std::mem::size_of::<V>()))
    }

    /// A family bounded by estimated size (`[redis] cache_budget_mb`), `weigh` estimating each
    /// value's bytes, inline and heap.
    pub fn family_weighed<K, V>(&self, weigh: fn(&V) -> usize) -> Arc<LocalCaches<K, V>>
    where
        K: Hash + Eq + Send + Sync + Clone + From<String> + 'static,
        V: Clone + Send + Sync + 'static,
    {
        self.register(LocalCaches::new(&self.inner.prefix, self.inner.ttl, Limit::Bytes(self.inner.budget_bytes), weigh))
    }

    fn register<K, V>(&self, family: LocalCaches<K, V>) -> Arc<LocalCaches<K, V>>
    where
        K: Hash + Eq + Send + Sync + Clone + From<String> + 'static,
        V: Clone + Send + Sync + 'static,
    {
        let f = Arc::new(family);
        self.inner
            .families
            .write()
            .expect("cache registry poisoned")
            .push(f.clone() as Arc<dyn Evictable>);
        f
    }

    /// Every family's usage now.
    pub fn usage(&self) -> Vec<FamilyUsage> {
        let families: Vec<Arc<dyn Evictable>> =
            self.inner.families.read().expect("cache registry poisoned").clone();
        families.iter().map(|f| f.usage()).collect()
    }

    #[cfg(test)]
    fn report(&self) {
        report(self.usage());
    }
}

/// The services built by [`CacheService::configured`] in this process, reported together.
static CONFIGURED: std::sync::Mutex<Vec<std::sync::Weak<Inner>>> = std::sync::Mutex::new(Vec::new());

/// Sets the cache gauges. Two families of one value type share a `family` label, so everything
/// is summed per label first.
fn report(usage: impl IntoIterator<Item = FamilyUsage>) {
    let mut by_family: std::collections::BTreeMap<(String, &'static str), (u64, u64)> = Default::default();
    let mut by_label: std::collections::BTreeMap<(String, String), (u64, u64)> = Default::default();
    for u in usage {
        let f = by_family.entry((u.family.clone(), u.limit.unit())).or_default();
        f.0 += u.used;
        f.1 += u.limit.value();
        for (label, entries, bytes) in u.by_label {
            let l = by_label.entry((u.family.clone(), label)).or_default();
            l.0 += entries;
            l.1 += bytes;
        }
    }
    for ((family, unit), (used, limit)) in by_family {
        metrics::gauge!(CACHE_FAMILY_USED, "family" => family.clone(), "unit" => unit).set(used as f64);
        metrics::gauge!(CACHE_FAMILY_LIMIT, "family" => family, "unit" => unit).set(limit as f64);
    }
    for ((family, cache), (entries, bytes)) in by_label {
        metrics::gauge!(CACHE_SIZE, "family" => family.clone(), "cache" => cache.clone()).set(entries as f64);
        metrics::gauge!(CACHE_BYTES, "family" => family, "cache" => cache).set(bytes as f64);
    }
}

impl CacheService {
    async fn dispatch(&self, message: &str) {
        let Some(colon) = message.find(':') else { return };
        let (name, key) = (&message[..colon], &message[colon + 1..]);
        tracing::debug!(cache = name, key, "eviction");
        let families: Vec<Arc<dyn Evictable>> =
            self.inner.families.read().expect("cache registry poisoned").clone();
        for f in families {
            f.evict(name, key).await;
        }
    }

    /// Drops every local entry of every family, as Java's `evictAllCaches` does when it has no
    /// Redis.
    pub fn clear_local(&self) {
        self.clear_everything();
    }

    /// The caches held locally, without the prefix, and their entry counts (Java's
    /// `getCacheNames` / `getCacheStats` read its Caffeine L1 the same way).
    pub fn local_cache_names(&self) -> Vec<(String, u64)> {
        let strip = format!("{}-", self.inner.prefix);
        let families: Vec<Arc<dyn Evictable>> =
            self.inner.families.read().expect("cache registry poisoned").clone();
        families
            .iter()
            .flat_map(|f| f.cache_names())
            .map(|(n, c)| (n.strip_prefix(&strip).unwrap_or(&n).to_string(), c))
            .collect()
    }

    /// [`Self::local_cache_names`] with each cache's counters (Java's `getCacheStats`).
    pub fn local_cache_stats(&self) -> Vec<(String, CacheStats)> {
        let strip = format!("{}-", self.inner.prefix);
        let families: Vec<Arc<dyn Evictable>> =
            self.inner.families.read().expect("cache registry poisoned").clone();
        families
            .iter()
            .flat_map(|f| f.cache_stats())
            .map(|(n, c)| (n.strip_prefix(&strip).unwrap_or(&n).to_string(), c))
            .collect()
    }

    /// The service's `redis.cache.prefix`.
    pub fn prefix(&self) -> &str {
        &self.inner.prefix
    }

    fn clear_everything(&self) {
        for f in self.inner.families.read().expect("cache registry poisoned").iter() {
            f.clear_all();
        }
    }

    /// Evicts a whole cache here and everywhere: the same as Java `CacheService.evictAll`.
    pub async fn evict_all_everywhere(&self, cache_name: &str) {
        let full = self.full_name(cache_name);
        self.dispatch(&format!("{full}:*")).await;
        if let Some(client) = &self.inner.redis {
            match client.get_multiplexed_async_connection().await {
                Ok(mut conn) => {
                    let published: redis::RedisResult<i64> = redis::cmd("PUBLISH")
                        .arg(&self.inner.channel)
                        .arg(format!("{full}:*"))
                        .query_async(&mut conn)
                        .await;
                    let deleted: redis::RedisResult<i64> =
                        redis::cmd("DEL").arg(&full).query_async(&mut conn).await;
                    if let Err(e) = published.and(deleted) {
                        crate::meter::redis_error("command");
                        tracing::warn!(cache = full, error = %e, "eviction not propagated");
                    }
                }
                Err(e) => {
                    crate::meter::redis_error("connect");
                    tracing::warn!(cache = full, error = %e, "redis unavailable for eviction");
                }
            }
        }
    }

    /// Java `CacheService.evictAllCaches`: every `<prefix>-*` hash in Redis is announced on the
    /// eviction channel (each instance, this one included, drops its copies when it hears) and
    /// deleted. The local copies are dropped here first. `None` when Redis holds no cache (Java's
    /// empty `Mono`), `Some(false)` when Redis cannot be reached, `Some(true)` without Redis.
    pub async fn evict_all_caches(&self) -> Option<bool> {
        self.clear_everything();
        let Some(client) = &self.inner.redis else { return Some(true) };
        let mut conn = match client.get_multiplexed_async_connection().await {
            Ok(c) => c,
            Err(e) => {
                crate::meter::redis_error("connect");
                tracing::warn!(error = %e, "redis unavailable for evictAllCaches");
                return Some(false);
            }
        };
        let keys: Vec<String> =
            match redis::cmd("KEYS").arg(format!("{}-*", self.inner.prefix)).query_async(&mut conn).await {
                Ok(k) => k,
                Err(e) => {
                    crate::meter::redis_error("command");
                    tracing::warn!(error = %e, "KEYS failed");
                    return Some(false);
                }
            };
        if keys.is_empty() {
            return None;
        }
        for k in keys {
            let published: redis::RedisResult<i64> =
                redis::cmd("PUBLISH").arg(&self.inner.channel).arg(format!("{k}:*")).query_async(&mut conn).await;
            let deleted: redis::RedisResult<i64> = redis::cmd("DEL").arg(&k).query_async(&mut conn).await;
            if let Err(e) = published.and(deleted) {
                crate::meter::redis_error("command");
                tracing::warn!(cache = k, error = %e, "eviction not propagated");
            }
        }
        Some(true)
    }

    /// Evicts one key here and everywhere: the same as Java `CacheService.evict(name, key)`,
    /// which publishes `<prefix>-<name>:<key>` and deletes the key from the Redis hash.
    pub async fn evict_everywhere(&self, cache_name: &str, key: &str) {
        let full = self.full_name(cache_name);
        let message = format!("{full}:{key}");
        self.dispatch(&message).await;
        if let Some(client) = &self.inner.redis {
            match client.get_multiplexed_async_connection().await {
                Ok(mut conn) => {
                    let published: redis::RedisResult<i64> =
                        redis::cmd("PUBLISH").arg(&self.inner.channel).arg(&message).query_async(&mut conn).await;
                    let deleted: redis::RedisResult<i64> =
                        redis::cmd("HDEL").arg(&full).arg(key).query_async(&mut conn).await;
                    if let Err(e) = published.and(deleted) {
                        crate::meter::redis_error("command");
                        tracing::warn!(cache = full, key, error = %e, "eviction not propagated");
                    }
                }
                Err(e) => {
                    crate::meter::redis_error("connect");
                    tracing::warn!(cache = full, error = %e, "redis unavailable for eviction");
                }
            }
        }
    }

    /// Publishes `message` on any Redis channel, for the invalidations that are not cache
    /// evictions (the ui's `ssr:cache:invalidation`). `false` when there is no Redis or the
    /// publish failed, as the Java publishers answer.
    pub async fn publish(&self, channel: &str, message: &str) -> bool {
        let Some(client) = &self.inner.redis else { return false };
        match client.get_multiplexed_async_connection().await {
            Ok(mut conn) => {
                let r: redis::RedisResult<i64> = redis::cmd("PUBLISH").arg(channel).arg(message).query_async(&mut conn).await;
                match r {
                    Ok(_) => true,
                    Err(e) => {
                        crate::meter::redis_error("command");
                        tracing::warn!(channel, error = %e, "publish failed");
                        false
                    }
                }
            }
            Err(e) => {
                crate::meter::redis_error("connect");
                tracing::warn!(channel, error = %e, "redis unavailable for publish");
                false
            }
        }
    }

    /// redis-rs 0.27 answers a SUBSCRIBE that Redis refused (`NOAUTH` when the URL carries no
    /// password the server wants) with `Ok`, which would leave the listener reporting itself
    /// subscribed while receiving nothing. A PING on an ordinary connection does report the
    /// refusal, so it goes first, and a refusal is retried like any failed subscribe.
    async fn check_access(client: &redis::Client) -> redis::RedisResult<()> {
        let mut conn = client.get_multiplexed_async_connection().await?;
        redis::cmd("PING").query_async::<String>(&mut conn).await.map(|_| ())
    }

    /// Listens on the eviction channel for the life of the process.
    pub fn spawn_eviction_listener(&self) -> Option<tokio::task::JoinHandle<()>> {
        let this = self.clone();
        let channel = self.inner.channel.clone();
        self.spawn_listener(&channel, move |heard| {
            let this = this.clone();
            Box::pin(async move { this.eviction_heard(heard).await })
        })
    }

    /// What the eviction listener does with what it hears.
    async fn eviction_heard(&self, heard: Heard) {
        match heard {
            // Anything published while we were away was missed.
            Heard::Resubscribed => self.clear_everything(),
            Heard::Subscribed => {}
            Heard::Message(payload) => self.dispatch(&payload).await,
        }
    }

    /// Listens on any Redis channel for the life of the process: `handler` hears each
    /// (re)subscription and every message. A dropped subscription is retried every 5 s.
    /// `None` without Redis.
    pub fn spawn_listener<F>(&self, channel: &str, handler: F) -> Option<tokio::task::JoinHandle<()>>
    where
        F: Fn(Heard) -> BoxFuture<'static, ()> + Send + Sync + 'static,
    {
        let client = self.inner.redis.clone()?;
        let channel = channel.to_string();
        Some(tokio::spawn(async move {
            let mut first = true;
            loop {
                match client.get_async_pubsub().await {
                    Ok(mut pubsub) => {
                        let subscribed = match Self::check_access(&client).await {
                            Ok(()) => pubsub.subscribe(&channel).await,
                            Err(e) => Err(e),
                        };
                        if let Err(e) = subscribed {
                            crate::meter::redis_error("subscribe");
                            tracing::warn!(channel, error = %e, "channel subscribe failed");
                        } else {
                            handler(if first { Heard::Subscribed } else { Heard::Resubscribed }).await;
                            first = false;
                            tracing::info!(channel, "listening");
                            let mut stream = pubsub.on_message();
                            while let Some(msg) = stream.next().await {
                                if let Ok(payload) = msg.get_payload::<String>() {
                                    handler(Heard::Message(payload)).await;
                                }
                            }
                            crate::meter::redis_error("subscribe");
                            tracing::warn!(channel, "channel closed, reconnecting");
                        }
                    }
                    Err(e) => {
                        crate::meter::redis_error("connect");
                        tracing::warn!(channel, error = %e, "redis unreachable for the channel");
                    }
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }))
    }
}

/// What a [`CacheService::spawn_listener`] handler hears.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Heard {
    /// The first subscription succeeded.
    Subscribed,
    /// Subscribed again after the subscription dropped: messages published meanwhile were missed.
    Resubscribed,
    /// A message's payload.
    Message(String),
}

/// Estimated bytes Moka keeps per entry besides the key and the value: its node, its places in
/// the access-order and write-order queues, and its share of the frequency sketch.
const ENTRY_OVERHEAD: usize = 128;

/// Caches of one value type: one Moka cache for the whole family, keyed by the full Java cache
/// name and the key, holding at most the family's [`Limit`].
///
/// Java keeps one Caffeine cache per NAME, capped at 10,000 entries. Names carry the app, page
/// or client (`PageCache_<app>_<page>`), so there the total grows with every page served. Here
/// the family's total is bounded by estimated size, and evictions by name still work: a `:*`
/// eviction is an invalidation predicate on the name, and Moka never returns an entry a
/// predicate matches, even before its maintenance has removed it.
pub struct LocalCaches<K, V> {
    prefix: String,
    /// The value type, without module paths: the `family` label of the family's metrics.
    family: String,
    cache: Cache<(String, K), V>,
    /// Every full cache name this family has loaded or stored a value under, with its counters.
    /// A name is listed from then on, as Java lists a Caffeine cache once it exists.
    names: Arc<DashMap<String, Arc<Counters>>>,
    limit: Limit,
    weigh: fn(&V) -> usize,
}

#[derive(Default)]
struct Counters {
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
    /// Entries and estimated bytes held under the name: added on insert, taken off when Moka
    /// reports the entry gone for any reason (replaced, invalidated, expired, over budget).
    entries: AtomicI64,
    bytes: AtomicI64,
}

/// What one family holds now, for the metrics.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FamilyUsage {
    pub family: String,
    pub limit: Limit,
    /// Held now, in the limit's unit.
    pub used: u64,
    /// By cache label ([`cache_label`]): entries and estimated bytes.
    pub by_label: Vec<(String, u64, u64)>,
}

/// Estimated bytes of a list of strings, inline and heap, for [`CacheService::family_weighed`].
pub fn strings_bytes(v: &[String]) -> usize {
    std::mem::size_of_val(v) + v.iter().map(String::capacity).sum::<usize>()
}

/// `alloc::sync::Arc<overridable::store::Resolved>` -> `Arc<Resolved>`.
fn short_type_name(full: &str) -> String {
    let mut out = String::with_capacity(full.len());
    let mut segment = String::new();
    for c in full.chars() {
        if c.is_alphanumeric() || c == '_' || c == ':' {
            segment.push(c);
        } else {
            out.push_str(segment.rsplit("::").next().unwrap_or(""));
            segment.clear();
            out.push(c);
        }
    }
    out.push_str(segment.rsplit("::").next().unwrap_or(""));
    out
}

impl<K, V> LocalCaches<K, V>
where
    K: Hash + Eq + Send + Sync + Clone + From<String> + 'static,
    V: Clone + Send + Sync + 'static,
{
    fn new(prefix: &str, ttl: Duration, limit: Limit, weigh: fn(&V) -> usize) -> Self {
        let names: Arc<DashMap<String, Arc<Counters>>> = Arc::default();
        let gone = names.clone();
        let strip = format!("{prefix}-");
        let entry_bytes = move |name: &str, v: &V| ENTRY_OVERHEAD + std::mem::size_of::<(String, K)>() + name.len() + weigh(v);
        let cache = Cache::builder()
            .max_capacity(limit.value())
            .weigher(move |k: &(String, K), v: &V| match limit {
                Limit::Entries(_) => 1,
                Limit::Bytes(_) => u32::try_from(entry_bytes(&k.0, v)).unwrap_or(u32::MAX),
            })
            .time_to_live(ttl)
            .support_invalidation_closures()
            .eviction_listener(move |k: Arc<(String, K)>, v: V, cause| {
                if let Some(c) = gone.get(&k.0) {
                    c.entries.fetch_sub(1, Ordering::Relaxed);
                    c.bytes.fetch_sub(entry_bytes(&k.0, &v) as i64, Ordering::Relaxed);
                    if matches!(cause, moka::notification::RemovalCause::Expired | moka::notification::RemovalCause::Size) {
                        c.evictions.fetch_add(1, Ordering::Relaxed);
                    }
                }
                if matches!(cause, moka::notification::RemovalCause::Expired | moka::notification::RemovalCause::Size) {
                    let name = k.0.strip_prefix(&strip).unwrap_or(&k.0);
                    metrics::counter!(CACHE_EVICTIONS, "cache" => cache_label(name)).increment(1);
                }
            })
            .build();
        Self {
            prefix: prefix.to_string(),
            family: short_type_name(std::any::type_name::<V>()),
            cache,
            names,
            limit,
            weigh,
        }
    }

    fn full_name(&self, cache_name: &str) -> String {
        format!("{}-{}", self.prefix, cache_name)
    }

    async fn store(&self, full: String, key: K, value: V) {
        let c = self.counters(&full);
        c.entries.fetch_add(1, Ordering::Relaxed);
        let bytes = ENTRY_OVERHEAD + std::mem::size_of::<(String, K)>() + full.len() + (self.weigh)(&value);
        c.bytes.fetch_add(bytes as i64, Ordering::Relaxed);
        self.cache.insert((full, key), value).await;
    }

    fn counters(&self, full: &str) -> Arc<Counters> {
        if let Some(c) = self.names.get(full) {
            return c.clone();
        }
        self.names.entry(full.to_string()).or_default().clone()
    }

    fn count(&self, full: &str, hit: bool) {
        let c = self.counters(full);
        if hit {
            c.hits.fetch_add(1, Ordering::Relaxed);
        } else {
            c.misses.fetch_add(1, Ordering::Relaxed);
        }
        let name = full.strip_prefix(&self.prefix).and_then(|n| n.strip_prefix('-')).unwrap_or(full);
        metrics::counter!(CACHE_GETS, "cache" => cache_label(name), "result" => if hit { "hit" } else { "miss" }).increment(1);
    }

    /// Java `cacheValueOrGet`: the cached value, or the loader's; a `None` from the loader is
    /// not cached, so a missing row is looked up again next time.
    pub async fn get_or_load<F, Fut, E>(&self, cache_name: &str, key: K, load: F) -> Result<Option<V>, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Option<V>, E>>,
    {
        let full = self.full_name(cache_name);
        let k = (full, key);
        if let Some(v) = self.cache.get(&k).await {
            self.count(&k.0, true);
            return Ok(Some(v));
        }
        self.count(&k.0, false);
        let v = load().await?;
        if let Some(v) = &v {
            let (full, key) = k;
            self.store(full, key, v.clone()).await;
        }
        Ok(v)
    }

    /// Java `cacheService.get(name, key)`, L1 only: the cached value, if any.
    pub async fn get(&self, cache_name: &str, key: &K) -> Option<V> {
        let full = self.full_name(cache_name);
        if !self.names.contains_key(&full) {
            return None;
        }
        let k = (full, key.clone());
        let v = self.cache.get(&k).await;
        self.count(&k.0, v.is_some());
        v
    }

    /// Java `cacheService.put(name, value, key)`, L1 only. For values that are decided after the
    /// lookup (a token that turns out to be one-time must not be cached), where
    /// [`Self::get_or_load`] does not fit.
    pub async fn insert(&self, cache_name: &str, key: K, value: V) {
        self.store(self.full_name(cache_name), key, value).await;
    }

    /// Runs Moka's pending maintenance (expiry, budget evictions, removal notifications) now
    /// rather than on a later read or write.
    pub async fn run_pending_tasks(&self) {
        self.cache.run_pending_tasks().await;
    }
}

impl<K, V> Evictable for LocalCaches<K, V>
where
    K: Hash + Eq + Send + Sync + Clone + From<String> + 'static,
    V: Clone + Send + Sync + 'static,
{
    fn evict<'a>(&'a self, full_cache_name: &'a str, key: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if !self.names.contains_key(full_cache_name) {
                return;
            }
            if key == "*" {
                let name = full_cache_name.to_string();
                if let Err(e) = self.cache.invalidate_entries_if(move |k, _| k.0 == name) {
                    // Only possible without support_invalidation_closures, which new() sets.
                    tracing::error!(cache = full_cache_name, error = %e, "cache not cleared; clearing the whole family");
                    self.cache.invalidate_all();
                }
            } else {
                self.cache.invalidate(&(full_cache_name.to_string(), K::from(key.to_string()))).await;
            }
        })
    }

    fn clear_all(&self) {
        self.cache.invalidate_all();
    }

    fn cache_names(&self) -> Vec<(String, u64)> {
        self.names.iter().map(|c| (c.key().clone(), c.entries.load(Ordering::Relaxed).max(0) as u64)).collect()
    }

    fn cache_stats(&self) -> Vec<(String, CacheStats)> {
        self.names
            .iter()
            .map(|c| {
                let stats = CacheStats {
                    entries: c.entries.load(Ordering::Relaxed).max(0) as u64,
                    hits: c.hits.load(Ordering::Relaxed),
                    misses: c.misses.load(Ordering::Relaxed),
                    evictions: c.evictions.load(Ordering::Relaxed),
                };
                (c.key().clone(), stats)
            })
            .collect()
    }

    fn usage(&self) -> FamilyUsage {
        let strip = format!("{}-", self.prefix);
        let mut by_label: std::collections::BTreeMap<String, (u64, u64)> = Default::default();
        for c in self.names.iter() {
            let name = c.key().strip_prefix(&strip).unwrap_or(c.key());
            let e = by_label.entry(cache_label(name)).or_default();
            e.0 += c.entries.load(Ordering::Relaxed).max(0) as u64;
            e.1 += c.bytes.load(Ordering::Relaxed).max(0) as u64;
        }
        FamilyUsage {
            family: self.family.clone(),
            limit: self.limit,
            used: self.cache.weighted_size(),
            by_label: by_label.into_iter().map(|(l, (e, b))| (l, e, b)).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_keep_the_fixed_part_of_a_name() {
        assert_eq!(cache_label("UIFunctionCache_app_name"), "UIFunctionCache");
        assert_eq!(cache_label("profileAuthsById_42"), "profileAuthsById");
        assert_eq!(cache_label("fsGetDetail-STATIC-SYSTEM"), "fsGetDetail");
        assert_eq!(cache_label("st42ab_table_creation"), "table_creation");
        assert_eq!(cache_label("leads_index_creation"), "index_creation");
        assert_eq!(cache_label("leads_foreign_keys"), "foreign_keys");
        assert_eq!(cache_label("42"), "other");
        assert_eq!(cache_label(&"a".repeat(100)).len(), 64);
    }

    #[test]
    fn lookups_evictions_and_redis_failures_are_counted() {
        let ((), text) = crate::meter::capture_async(async {
            let svc = CacheService::new("cmn", "evictionChannel", Some("redis://127.0.0.1:1")).unwrap();
            let fam = svc.family::<String, u32>();
            for name in ["UIFunctionCache_a_x", "UIFunctionCache_b_y"] {
                fam.get_or_load(name, "k".into(), || async { Ok::<_, ()>(Some(1)) }).await.unwrap();
            }
            fam.get_or_load("UIFunctionCache_a_x", "k".into(), || async { Ok::<_, ()>(Some(2)) }).await.unwrap();
            svc.evict_everywhere("UIFunctionCache_a_x", "k").await;
            svc.evict_all_everywhere("UIFunctionCache_a_x").await;
            assert!(!svc.publish("ch", "m").await);

            // Room for about two entries.
            let small: LocalCaches<String, u32> = LocalCaches::new("cmn", Duration::from_secs(60), Limit::Entries(2), |_| 4);
            for i in 0..10u32 {
                small.insert("pageCache_app", i.to_string(), i).await;
            }
            small.run_pending_tasks().await;
        });
        let gets = |result: &str| crate::meter::sample(&text, CACHE_GETS, &[("cache", "UIFunctionCache"), ("result", result)]);
        assert_eq!((gets("hit"), gets("miss")), (Some(1.0), Some(2.0)));
        assert!(crate::meter::sample(&text, CACHE_EVICTIONS, &[("cache", "pageCache")]).is_some_and(|n| n >= 1.0), "{text}");
        assert_eq!(crate::meter::sample(&text, crate::meter::REDIS_ERRORS, &[("operation", "connect")]), Some(3.0));
    }

    #[tokio::test]
    async fn evict_all_caches_without_and_with_an_unreachable_redis() {
        let svc = CacheService::new("cmn", "evictionChannel", None).unwrap();
        let fam = svc.family::<String, u32>();
        fam.insert("a", "k".into(), 1).await;
        assert_eq!(svc.evict_all_caches().await, Some(true));
        assert!(fam.get("a", &"k".to_string()).await.is_none());
        let bad = CacheService::new("cmn", "evictionChannel", Some("redis://127.0.0.1:1")).unwrap();
        assert_eq!(bad.evict_all_caches().await, Some(false));
    }

    #[tokio::test]
    async fn evict_all_by_java_message() {
        let svc = CacheService::new("fil", "evictionChannel", None).unwrap();
        let fam = svc.family::<String, u32>();
        let name = "fsGetDetail-STATIC-SYSTEM";

        let v = fam
            .get_or_load(name, "a/b".to_string(), || async { Ok::<_, ()>(Some(7)) })
            .await
            .unwrap();
        assert_eq!(v, Some(7));

        // Served from cache now: the loader would say 8.
        let v = fam
            .get_or_load(name, "a/b".to_string(), || async { Ok::<_, ()>(Some(8)) })
            .await
            .unwrap();
        assert_eq!(v, Some(7));

        svc.dispatch("fil-fsGetDetail-STATIC-SYSTEM:*").await;
        let v = fam
            .get_or_load(name, "a/b".to_string(), || async { Ok::<_, ()>(Some(9)) })
            .await
            .unwrap();
        assert_eq!(v, Some(9));
    }

    #[tokio::test]
    async fn evicts_one_key_everywhere() {
        let svc = CacheService::new("cmn", "evictionChannel", None).unwrap();
        let fam = svc.family::<String, u32>();
        for k in ["a", "b"] {
            fam.get_or_load("RestOAuthToken", k.to_string(), || async { Ok::<_, ()>(Some(1)) }).await.unwrap();
        }
        svc.evict_everywhere("RestOAuthToken", "a").await;
        let a = fam.get_or_load("RestOAuthToken", "a".to_string(), || async { Ok::<_, ()>(Some(2)) }).await.unwrap();
        let b = fam.get_or_load("RestOAuthToken", "b".to_string(), || async { Ok::<_, ()>(Some(2)) }).await.unwrap();
        assert_eq!((a, b), (Some(2), Some(1)));
    }

    #[tokio::test]
    async fn get_and_insert_take_part_in_evictions() {
        let svc = CacheService::new("cmn", "evictionChannel", None).unwrap();
        let fam = svc.family::<String, u32>();
        assert_eq!(fam.get("tokenCache", &"t".to_string()).await, None);
        fam.insert("tokenCache", "t".to_string(), 5).await;
        assert_eq!(fam.get("tokenCache", &"t".to_string()).await, Some(5));
        svc.dispatch("cmn-tokenCache:t").await;
        assert_eq!(fam.get("tokenCache", &"t".to_string()).await, None);
    }

    #[tokio::test]
    async fn counts_hits_and_misses() {
        let svc = CacheService::new("cmn", "evictionChannel", None).unwrap();
        let fam = svc.family::<String, u32>();
        fam.get_or_load("c", "k".to_string(), || async { Ok::<_, ()>(Some(1)) }).await.unwrap();
        fam.get_or_load("c", "k".to_string(), || async { Ok::<_, ()>(Some(2)) }).await.unwrap();
        assert_eq!(fam.get("c", &"x".to_string()).await, None);
        assert_eq!(fam.get("none", &"x".to_string()).await, None, "an unknown cache is not created by a lookup");
        let stats = svc.local_cache_stats();
        assert_eq!(stats, vec![("c".to_string(), CacheStats { entries: stats[0].1.entries, hits: 1, misses: 2, evictions: 0 })]);
        struct Bare;
        impl Evictable for Bare {
            fn evict<'a>(&'a self, _: &'a str, _: &'a str) -> BoxFuture<'a, ()> {
                Box::pin(async {})
            }
            fn clear_all(&self) {}
        }
        assert!(Bare.cache_stats().is_empty());
    }

    #[tokio::test]
    async fn none_is_not_cached() {
        let svc = CacheService::new("fil", "evictionChannel", None).unwrap();
        let fam = svc.family::<String, u32>();
        let v = fam
            .get_or_load("c", "k".to_string(), || async { Ok::<_, ()>(None) })
            .await
            .unwrap();
        assert_eq!(v, None);
        let v = fam
            .get_or_load("c", "k".to_string(), || async { Ok::<_, ()>(Some(1)) })
            .await
            .unwrap();
        assert_eq!(v, Some(1));
    }

    #[test]
    fn redis_url_password_only() {
        assert_eq!(normalize_redis_url("redis://Kiran%40123@localhost:6379"), "redis://:Kiran%40123@localhost:6379");
        assert_eq!(normalize_redis_url("rediss://u:p@h:6379/0"), "rediss://u:p@h:6379/0");
        assert_eq!(normalize_redis_url("redis://localhost:6379"), "redis://localhost:6379");
    }

    #[tokio::test]
    async fn unreachable_redis_only_logs() {
        let svc = CacheService::new("x", "evictionChannel", Some("redis://127.0.0.1:1")).unwrap();
        assert!(!svc.publish("ssr:cache:invalidation", "{}").await, "no redis to publish on");
        assert!(!CacheService::new("x", "c", None).unwrap().publish("c", "m").await);
        let fam = svc.family::<String, u32>();
        fam.insert("c", "k".into(), 1).await;
        svc.evict_everywhere("c", "k").await;
        assert!(fam.get("c", &"k".to_string()).await.is_none(), "the local copy goes even when redis is down");
        fam.insert("c", "k".into(), 1).await;
        svc.evict_all_everywhere("c").await;
        assert!(fam.get("c", &"k".to_string()).await.is_none());
        let listener = svc.spawn_eviction_listener().unwrap();
        let other = svc.spawn_listener("notificationPush", |_| Box::pin(async {})).unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        listener.abort();
        other.abort();
        assert!(CacheService::new("x", "c", None).unwrap().spawn_listener("c", |_| Box::pin(async {})).is_none());

        // What the eviction listener does with what it hears.
        fam.insert("c", "k".into(), 1).await;
        svc.eviction_heard(Heard::Subscribed).await;
        assert!(fam.get("c", &"k".to_string()).await.is_some(), "the first subscription keeps the caches");
        svc.eviction_heard(Heard::Message("x-c:k".into())).await;
        assert!(fam.get("c", &"k".to_string()).await.is_none(), "a message evicts");
        fam.insert("c", "k".into(), 1).await;
        svc.eviction_heard(Heard::Resubscribed).await;
        assert!(fam.get("c", &"k".to_string()).await.is_none(), "a resubscription clears everything");

        fam.insert("c", "k".into(), 1).await;
        fam.insert("d", "k".into(), 1).await;
        svc.clear_everything();
        assert!(fam.get("c", &"k".to_string()).await.is_none());
        assert!(fam.get("d", &"k".to_string()).await.is_none());
        assert_eq!(svc.full_name("c"), "x-c");
    }

    #[tokio::test]
    async fn other_prefix_is_ignored() {
        let svc = CacheService::new("fil", "evictionChannel", None).unwrap();
        let fam = svc.family::<String, u32>();
        fam.get_or_load("c", "k".to_string(), || async { Ok::<_, ()>(Some(1)) })
            .await
            .unwrap();
        svc.dispatch("cor-c:*").await;
        let v = fam
            .get_or_load("c", "k".to_string(), || async { Ok::<_, ()>(Some(2)) })
            .await
            .unwrap();
        assert_eq!(v, Some(1));
    }

    #[tokio::test]
    async fn the_family_stays_within_its_budget_across_names() {
        // 100 names of 10 KB pages each against a 200 KB budget: Java's per-name cap would
        // have kept all of them.
        let svc = CacheService::build("cmn", "evictionChannel", None, Duration::from_secs(60), 200 * 1024, 10).unwrap();
        let fam = svc.family_weighed::<String, Arc<String>>(|v| v.len());
        for i in 0..100 {
            fam.insert(&format!("PageCache_app_p{i}"), "CLIENT".into(), Arc::new("x".repeat(10 * 1024))).await;
        }
        fam.run_pending_tasks().await;
        let u = &svc.usage()[0];
        assert_eq!(u.family, "Arc<String>");
        assert_eq!(u.limit, Limit::Bytes(200 * 1024));
        assert!(u.used <= 200 * 1024, "{u:?}");
        let (entries, bytes) = u.by_label.iter().fold((0, 0), |a, (_, e, b)| (a.0 + e, a.1 + b));
        assert!((1..=20).contains(&entries), "{u:?}");
        assert_eq!(bytes, u.used, "the per-name accounting matches Moka's weighted size");
    }

    #[tokio::test]
    async fn a_name_eviction_leaves_the_other_names() {
        let svc = CacheService::new("cmn", "evictionChannel", None).unwrap();
        let fam = svc.family::<String, u32>();
        fam.insert("PageCache_a_x", "c1".into(), 1).await;
        fam.insert("PageCache_a_x", "c2".into(), 2).await;
        fam.insert("PageCache_a_y", "c1".into(), 3).await;
        svc.dispatch("cmn-PageCache_a_x:*").await;
        assert_eq!(fam.get("PageCache_a_x", &"c1".to_string()).await, None, "gone before maintenance runs");
        assert_eq!(fam.get("PageCache_a_x", &"c2".to_string()).await, None);
        assert_eq!(fam.get("PageCache_a_y", &"c1".to_string()).await, Some(3));
        fam.run_pending_tasks().await;
        let names: std::collections::HashMap<String, u64> = svc.local_cache_names().into_iter().collect();
        assert_eq!(names.get("PageCache_a_x"), Some(&0), "still listed, as an emptied Caffeine cache is");
        assert_eq!(names.get("PageCache_a_y"), Some(&1));
        // A value loaded after the eviction is kept.
        fam.insert("PageCache_a_x", "c1".into(), 4).await;
        assert_eq!(fam.get("PageCache_a_x", &"c1".to_string()).await, Some(4));
    }

    #[tokio::test]
    async fn replacing_and_clearing_return_the_accounting_to_zero() {
        let svc = CacheService::new("cmn", "evictionChannel", None).unwrap();
        let fam = svc.family_weighed::<String, Arc<String>>(|v| v.len());
        fam.insert("c", "k".into(), Arc::new("a".repeat(1000))).await;
        fam.insert("c", "k".into(), Arc::new("b".repeat(5000))).await;
        fam.run_pending_tasks().await;
        let u = &svc.usage()[0];
        assert_eq!((u.by_label[0].1, u.by_label[0].2), (1, u.used), "{u:?}");
        svc.clear_local();
        fam.run_pending_tasks().await;
        let u = &svc.usage()[0];
        assert_eq!((u.used, u.by_label[0].1, u.by_label[0].2), (0, 0, 0), "{u:?}");
    }

    #[tokio::test]
    async fn an_unweighed_family_is_bounded_by_entries() {
        let svc = CacheService::build("cmn", "evictionChannel", None, Duration::from_secs(60), 1 << 30, 50).unwrap();
        let fam = svc.family::<String, Arc<String>>();
        for i in 0..500 {
            fam.insert(&format!("profileAuthsById_{i}"), "k".into(), Arc::new("x".repeat(4096))).await;
        }
        fam.run_pending_tasks().await;
        let u = &svc.usage()[0];
        assert_eq!(u.limit, Limit::Entries(50));
        assert!(u.used <= 50, "{u:?}");
        assert_eq!(u.by_label.iter().map(|l| l.1).sum::<u64>(), u.used);
    }

    #[test]
    fn family_names_drop_module_paths() {
        assert_eq!(short_type_name("alloc::sync::Arc<overridable::store::Resolved>"), "Arc<Resolved>");
        assert_eq!(short_type_name("core::option::Option<alloc::sync::Arc<a::B>>"), "Option<Arc<B>>");
        assert_eq!(short_type_name("(alloc::string::String, u32)"), "(String, u32)");
        assert_eq!(short_type_name("bool"), "bool");
    }

    #[test]
    fn the_gauges_are_set_per_family_and_label() {
        let ((), text) = crate::meter::capture_async(async {
            let svc = CacheService::new("cmn", "evictionChannel", None).unwrap();
            let fam = svc.family_weighed::<String, Arc<String>>(|v| v.len());
            fam.insert("PageCache_app_home", "C".into(), Arc::new("x".repeat(100))).await;
            fam.run_pending_tasks().await;
            svc.report();
        });
        let s = |name: &str, labels: &[(&str, &str)]| crate::meter::sample(&text, name, labels);
        assert_eq!(s(CACHE_SIZE, &[("family", "Arc<String>"), ("cache", "PageCache")]), Some(1.0), "{text}");
        assert!(s(CACHE_BYTES, &[("family", "Arc<String>"), ("cache", "PageCache")]).is_some_and(|b| b >= 100.0));
        let fam = |unit| [("family", "Arc<String>"), ("unit", unit)];
        assert_eq!(s(CACHE_FAMILY_LIMIT, &fam("bytes")), Some(DEFAULT_BUDGET_BYTES as f64));
        assert!(s(CACHE_FAMILY_USED, &fam("bytes")).is_some_and(|b| b >= 100.0));
    }
}

#[cfg(test)]
mod live {
    use super::*;

    /// `MODLIX__REDIS__URL=... cargo test -p platform -- --ignored live_eviction_round_trip`.
    #[tokio::test]
    #[ignore]
    async fn live_eviction_round_trip() {
        let Ok(url) = std::env::var("MODLIX__REDIS__URL") else { return };
        let svc = CacheService::new("rusttest", "evictionChannel", Some(&url)).unwrap();
        let fam = svc.family::<String, u32>();
        svc.spawn_eviction_listener().unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;

        let other = CacheService::new("rusttest", "evictionChannel", Some(&url)).unwrap();
        for (cache, key) in [("c1", "k"), ("c2", "k")] {
            fam.insert(cache, key.to_string(), 1).await;
        }
        other.evict_everywhere("c1", "k").await;
        other.evict_all_everywhere("c2").await;
        for _ in 0..50 {
            if fam.get("c1", &"k".to_string()).await.is_none() && fam.get("c2", &"k".to_string()).await.is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(fam.get("c1", &"k".to_string()).await.is_none(), "a published key eviction arrived");
        assert!(fam.get("c2", &"k".to_string()).await.is_none(), "a published evict-all arrived");

        // evictAllCaches over this test's prefix only: a hash is found, announced and dropped.
        let client = redis::Client::open(normalize_redis_url(&url).as_str()).unwrap();
        let mut conn = client.get_multiplexed_async_connection().await.unwrap();
        let _: i64 = redis::cmd("HSET").arg("rusttest-c3").arg("k").arg("v").query_async(&mut conn).await.unwrap();
        assert_eq!(other.evict_all_caches().await, Some(true));
        let left: i64 = redis::cmd("EXISTS").arg("rusttest-c3").query_async(&mut conn).await.unwrap();
        assert_eq!(left, 0);
        assert_eq!(other.evict_all_caches().await, None);

        // Without redis, the same calls only act locally.
        let local = CacheService::new("rusttest", "evictionChannel", None).unwrap();
        assert!(local.spawn_eviction_listener().is_none());
        let lf = local.family::<String, u32>();
        lf.insert("c", "k".into(), 1).await;
        local.evict_everywhere("c", "k").await;
        assert!(lf.get("c", &"k".to_string()).await.is_none());
        lf.insert("c", "k".into(), 1).await;
        local.evict_all_everywhere("c").await;
        assert!(lf.get("c", &"k".to_string()).await.is_none());
    }

    /// `MODLIX__REDIS__URL=... cargo test -p platform -- --ignored live_listener_round_trip`: two
    /// services on one channel each hear what either publishes.
    #[tokio::test]
    #[ignore]
    async fn live_listener_round_trip() {
        let Ok(url) = std::env::var("MODLIX__REDIS__URL") else { return };
        let channel = format!("rusttest-listener-{}", std::process::id());
        let heard = Arc::new(std::sync::Mutex::new(Vec::<(usize, Heard)>::new()));
        let mut tasks = Vec::new();
        let services: Vec<CacheService> = (0..2).map(|_| CacheService::new("rusttest", "evictionChannel", Some(&url)).unwrap()).collect();
        for (i, svc) in services.iter().enumerate() {
            let heard = heard.clone();
            tasks.push(
                svc.spawn_listener(&channel, move |h| {
                    let heard = heard.clone();
                    Box::pin(async move { heard.lock().unwrap().push((i, h)) })
                })
                .unwrap(),
            );
        }
        for _ in 0..100 {
            if heard.lock().unwrap().iter().filter(|(_, h)| *h == Heard::Subscribed).count() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(services[1].publish(&channel, "hello").await);
        for _ in 0..100 {
            if heard.lock().unwrap().iter().filter(|(_, h)| *h == Heard::Message("hello".into())).count() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        for t in tasks {
            t.abort();
        }
        let got = heard.lock().unwrap().clone();
        for i in 0..2 {
            assert!(got.contains(&(i, Heard::Subscribed)), "{got:?}");
            assert!(got.contains(&(i, Heard::Message("hello".into()))), "{got:?}");
        }
    }

    /// Against a real Redis: `MODLIX__REDIS__URL=... cargo test -p platform -- --ignored live_pubsub`.
    #[tokio::test]
    #[ignore]
    async fn live_pubsub() {
        let url = std::env::var("MODLIX__REDIS__URL").expect("MODLIX__REDIS__URL");
        let client = redis::Client::open(normalize_redis_url(&url).as_str()).unwrap();
        let mut pubsub = client.get_async_pubsub().await.unwrap();
        pubsub.subscribe("evictionChannel").await.unwrap();
        eprintln!("subscribed");
        let mut conn = client.get_multiplexed_async_connection().await.unwrap();
        let n: i64 = redis::cmd("PUBLISH").arg("evictionChannel").arg("cmn-live-test:*").query_async(&mut conn).await.unwrap();
        eprintln!("published to {n} subscribers");
        let mut stream = pubsub.on_message();
        let msg = tokio::time::timeout(Duration::from_secs(5), stream.next()).await;
        eprintln!("received: {:?}", msg.map(|m| m.map(|m| m.get_payload::<String>())));
    }
}
