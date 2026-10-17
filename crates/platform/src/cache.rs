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
use std::sync::atomic::{AtomicU64, Ordering};
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
    max_entries_per_cache: u64,
}

impl CacheService {
    /// `prefix` is the Java services' effective `redis.cache.prefix` (`cmn` everywhere): it must
    /// be the one the Java instances use, or their evictions will not be recognised.
    pub fn new(prefix: &str, channel: &str, redis_url: Option<&str>) -> anyhow::Result<Self> {
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
                ttl: Duration::from_secs(60 * 60),
                max_entries_per_cache: 10_000,
            }),
        })
    }

    pub fn full_name(&self, cache_name: &str) -> String {
        format!("{}-{}", self.inner.prefix, cache_name)
    }

    /// A family of caches holding `V`, addressed by cache name. Registered for eviction.
    pub fn family<K, V>(&self) -> Arc<LocalCaches<K, V>>
    where
        K: Hash + Eq + Send + Sync + Clone + From<String> + 'static,
        V: Clone + Send + Sync + 'static,
    {
        let f = Arc::new(LocalCaches {
            prefix: self.inner.prefix.clone(),
            caches: DashMap::new(),
            counters: DashMap::new(),
            ttl: self.inner.ttl,
            max_entries: self.inner.max_entries_per_cache,
        });
        self.inner
            .families
            .write()
            .expect("cache registry poisoned")
            .push(f.clone() as Arc<dyn Evictable>);
        f
    }

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
                        tracing::warn!(cache = full, error = %e, "eviction not propagated");
                    }
                }
                Err(e) => tracing::warn!(cache = full, error = %e, "redis unavailable for eviction"),
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
                tracing::warn!(error = %e, "redis unavailable for evictAllCaches");
                return Some(false);
            }
        };
        let keys: Vec<String> =
            match redis::cmd("KEYS").arg(format!("{}-*", self.inner.prefix)).query_async(&mut conn).await {
                Ok(k) => k,
                Err(e) => {
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
                        tracing::warn!(cache = full, key, error = %e, "eviction not propagated");
                    }
                }
                Err(e) => tracing::warn!(cache = full, error = %e, "redis unavailable for eviction"),
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
                        tracing::warn!(channel, error = %e, "publish failed");
                        false
                    }
                }
            }
            Err(e) => {
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
        let client = self.inner.redis.clone()?;
        let this = self.clone();
        Some(tokio::spawn(async move {
            let mut first = true;
            loop {
                match client.get_async_pubsub().await {
                    Ok(mut pubsub) => {
                        let subscribed = match Self::check_access(&client).await {
                            Ok(()) => pubsub.subscribe(&this.inner.channel).await,
                            Err(e) => Err(e),
                        };
                        if let Err(e) = subscribed {
                            tracing::warn!(error = %e, "eviction channel subscribe failed");
                        } else {
                            if !first {
                                // Anything published while we were away was missed.
                                this.clear_everything();
                            }
                            first = false;
                            tracing::info!(channel = this.inner.channel, "listening for cache evictions");
                            let mut stream = pubsub.on_message();
                            while let Some(msg) = stream.next().await {
                                if let Ok(payload) = msg.get_payload::<String>() {
                                    this.dispatch(&payload).await;
                                }
                            }
                            tracing::warn!("eviction channel closed, reconnecting");
                        }
                    }
                    Err(e) => tracing::warn!(error = %e, "redis unreachable for evictions"),
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }))
    }
}

/// Caches of one value type, one Moka cache per Java cache name.
pub struct LocalCaches<K, V> {
    prefix: String,
    caches: DashMap<String, Cache<K, V>>,
    counters: DashMap<String, Arc<Counters>>,
    ttl: Duration,
    max_entries: u64,
}

#[derive(Default)]
struct Counters {
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
}

impl<K, V> LocalCaches<K, V>
where
    K: Hash + Eq + Send + Sync + Clone + From<String> + 'static,
    V: Clone + Send + Sync + 'static,
{
    fn cache(&self, cache_name: &str) -> Cache<K, V> {
        let full = format!("{}-{}", self.prefix, cache_name);
        let counters = self.counters(&full);
        self.caches
            .entry(full)
            .or_insert_with(|| {
                Cache::builder()
                    .max_capacity(self.max_entries)
                    .time_to_live(self.ttl)
                    .eviction_listener(move |_k, _v, cause| {
                        if matches!(cause, moka::notification::RemovalCause::Expired | moka::notification::RemovalCause::Size) {
                            counters.evictions.fetch_add(1, Ordering::Relaxed);
                        }
                    })
                    .build()
            })
            .clone()
    }

    fn counters(&self, full: &str) -> Arc<Counters> {
        self.counters.entry(full.to_string()).or_default().clone()
    }

    fn count(&self, full: &str, hit: bool) {
        let c = self.counters(full);
        if hit {
            c.hits.fetch_add(1, Ordering::Relaxed);
        } else {
            c.misses.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Java `cacheValueOrGet`: the cached value, or the loader's; a `None` from the loader is
    /// not cached, so a missing row is looked up again next time.
    pub async fn get_or_load<F, Fut, E>(&self, cache_name: &str, key: K, load: F) -> Result<Option<V>, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Option<V>, E>>,
    {
        let cache = self.cache(cache_name);
        let full = format!("{}-{}", self.prefix, cache_name);
        if let Some(v) = cache.get(&key).await {
            self.count(&full, true);
            return Ok(Some(v));
        }
        self.count(&full, false);
        let v = load().await?;
        if let Some(v) = &v {
            cache.insert(key, v.clone()).await;
        }
        Ok(v)
    }

    /// Java `cacheService.get(name, key)`, L1 only: the cached value, if any.
    pub async fn get(&self, cache_name: &str, key: &K) -> Option<V> {
        let full = format!("{}-{}", self.prefix, cache_name);
        let cache = self.caches.get(&full).map(|c| c.clone())?;
        let v = cache.get(key).await;
        self.count(&full, v.is_some());
        v
    }

    /// Java `cacheService.put(name, value, key)`, L1 only. For values that are decided after the
    /// lookup (a token that turns out to be one-time must not be cached), where
    /// [`Self::get_or_load`] does not fit.
    pub async fn insert(&self, cache_name: &str, key: K, value: V) {
        self.cache(cache_name).insert(key, value).await;
    }
}

impl<K, V> Evictable for LocalCaches<K, V>
where
    K: Hash + Eq + Send + Sync + Clone + From<String> + 'static,
    V: Clone + Send + Sync + 'static,
{
    fn evict<'a>(&'a self, full_cache_name: &'a str, key: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let Some(cache) = self.caches.get(full_cache_name).map(|c| c.clone()) else {
                return;
            };
            if key == "*" {
                cache.invalidate_all();
            } else {
                cache.invalidate(&K::from(key.to_string())).await;
            }
        })
    }

    fn clear_all(&self) {
        for c in self.caches.iter() {
            c.invalidate_all();
        }
    }

    fn cache_names(&self) -> Vec<(String, u64)> {
        self.caches.iter().map(|c| (c.key().clone(), c.value().entry_count())).collect()
    }

    fn cache_stats(&self) -> Vec<(String, CacheStats)> {
        self.caches
            .iter()
            .map(|c| {
                let k = self.counters(c.key());
                let stats = CacheStats {
                    entries: c.value().entry_count(),
                    hits: k.hits.load(Ordering::Relaxed),
                    misses: k.misses.load(Ordering::Relaxed),
                    evictions: k.evictions.load(Ordering::Relaxed),
                };
                (c.key().clone(), stats)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        tokio::time::sleep(Duration::from_millis(100)).await;
        listener.abort();

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
