//! `CoreCacheController` (`AbstractCacheController` under `api/core/`): this instance's cache
//! names and counters, and the evictions an operator can ask for.

use overridable::{JMap, JValue};
use platform::cache::CacheService;

/// `GET internal/cache`: the names of the caches this instance holds.
pub fn names(cache: &CacheService) -> JValue {
    JValue::Array(cache.local_cache_names().into_iter().map(|(n, _)| JValue::Str(n)).collect())
}

/// `GET internal/cache/stats`: Caffeine's counters per cache (no weigher: `-1` bytes).
pub fn stats(cache: &CacheService) -> JValue {
    let mut out = JMap::new();
    for (name, s) in cache.local_cache_stats() {
        let requests = s.hits + s.misses;
        let mut one = JMap::new();
        one.insert("entries".into(), JValue::Int(s.entries as i64));
        one.insert("weightedBytes".into(), JValue::Int(-1));
        one.insert("hitCount".into(), JValue::Int(s.hits as i64));
        one.insert("missCount".into(), JValue::Int(s.misses as i64));
        one.insert("hitRate".into(), JValue::Float(if requests == 0 { 1.0 } else { s.hits as f64 / requests as f64 }));
        one.insert("evictionCount".into(), JValue::Int(s.evictions as i64));
        out.insert(name, JValue::Object(one));
    }
    JValue::Object(out)
}

/// `CacheService.evictAllCaches`: every `<prefix>-*` hash in Redis is announced and dropped
/// (each instance drops its copies when it hears); `None` (an empty Mono) when Redis holds none.
pub async fn evict_all(cache: &CacheService, redis: Option<&redis::Client>, channel: &str) -> Option<bool> {
    cache.clear_local();
    let client = redis?;
    let mut conn = match client.get_multiplexed_async_connection().await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "redis unavailable for evictAllCaches");
            return Some(false);
        }
    };
    let keys: Vec<String> = match redis::cmd("KEYS").arg(format!("{}-*", cache.prefix())).query_async(&mut conn).await {
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
        let published: redis::RedisResult<i64> = redis::cmd("PUBLISH").arg(channel).arg(format!("{k}:*")).query_async(&mut conn).await;
        let deleted: redis::RedisResult<i64> = redis::cmd("DEL").arg(&k).query_async(&mut conn).await;
        if let Err(e) = published.and(deleted) {
            tracing::warn!(cache = k, error = %e, "eviction not propagated");
        }
    }
    Some(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn names_and_stats_of_this_instance() {
        let cache = CacheService::new("cmn", "evictionChannel", None).unwrap();
        let fam: std::sync::Arc<platform::cache::LocalCaches<String, u32>> = cache.family();
        fam.insert("FunctionCache_a_b", "SYSTEM".into(), 1).await;
        let _ = fam.get("FunctionCache_a_b", &"SYSTEM".to_string()).await;
        let n = names(&cache);
        assert!(matches!(&n, JValue::Array(a) if a.contains(&JValue::Str("FunctionCache_a_b".into()))));
        let s = stats(&cache);
        assert!(s.as_object().unwrap().contains_key("FunctionCache_a_b"));
        assert_eq!(evict_all(&cache, None, "evictionChannel").await, None);
        assert!(fam.get("FunctionCache_a_b", &"SYSTEM".to_string()).await.is_none());
        let bad = redis::Client::open("redis://127.0.0.1:1").unwrap();
        assert_eq!(evict_all(&cache, Some(&bad), "evictionChannel").await, Some(false));
    }
}
