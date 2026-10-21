//! `CacheService` beyond the unit tests in `cache.rs`: listing, clearing and counting the local
//! caches, and the Redis side (publish, propagated evictions, the eviction listener's failures
//! and reconnects) against a scripted fake Redis, plus a gated round trip on the local Redis.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::StreamExt;
use platform::cache::{normalize_redis_url, CacheService};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

#[tokio::test]
async fn lists_and_clears_local_caches() {
    let svc = CacheService::new("cmn", "evictionChannel", None).unwrap();
    assert_eq!(svc.prefix(), "cmn");
    let numbers = svc.family::<String, u32>();
    let texts = svc.family::<String, String>();
    numbers.insert("pageCache", "p".into(), 1).await;
    numbers.insert("appCache", "a".into(), 2).await;
    texts.insert("themeCache", "t".into(), "v".into()).await;

    let mut names: Vec<String> = svc.local_cache_names().into_iter().map(|(n, _)| n).collect();
    names.sort();
    assert_eq!(names, ["appCache", "pageCache", "themeCache"], "every family, without the prefix");

    svc.clear_local();
    assert!(numbers.get("pageCache", &"p".to_string()).await.is_none());
    assert!(numbers.get("appCache", &"a".to_string()).await.is_none());
    assert!(texts.get("themeCache", &"t".to_string()).await.is_none());
    assert_eq!(svc.local_cache_names().len(), 3, "cleared caches are still known");
}

#[tokio::test]
async fn counts_size_evictions() {
    let svc = CacheService::new("cmn", "evictionChannel", None).unwrap();
    let fam = svc.family::<String, u32>();
    // A family of small values holds 20,000 entries across all its names (`[redis]
    // cache_max_entries`; Java's Caffeine allows 10,000 per name); the ones beyond are dropped
    // for size, which is what the eviction counter counts.
    for i in 0..20_500u32 {
        fam.insert("big", i.to_string(), i).await;
    }
    let mut stats = svc.local_cache_stats();
    for _ in 0..200 {
        if stats[0].1.evictions > 0 {
            break;
        }
        // Reads drive Moka's housekeeping, which is when size evictions happen.
        fam.get("big", &"0".to_string()).await;
        tokio::time::sleep(Duration::from_millis(10)).await;
        stats = svc.local_cache_stats();
    }
    assert_eq!(stats.len(), 1);
    assert_eq!(stats[0].0, "big");
    assert!(stats[0].1.evictions > 0, "{stats:?}");
    // Entries are counted off as Moka's maintenance reports them gone, so finish it first.
    fam.run_pending_tasks().await;
    let stats = svc.local_cache_stats();
    assert!(stats[0].1.entries <= 20_000, "{stats:?}");
}

/// A Redis that speaks just enough RESP2 for `CacheService`. It records every command. For
/// `refuse_for` after it starts it answers PING and SUBSCRIBE with `NOAUTH`, as a Redis that
/// wants a password does, and it answers PUBLISH / DEL / HDEL that way when `refuse_writes`.
/// Otherwise it confirms each SUBSCRIBE, sends the scripted messages, and hangs up after them
/// when `hang_up` says so for that subscription.
struct FakeRedis {
    url: String,
    commands: Mutex<Vec<Vec<String>>>,
    started: std::time::Instant,
    refuse_for: Duration,
    subscribes: AtomicUsize,
    refuse_writes: bool,
    hang_up: fn(usize) -> bool,
    messages: Vec<Vec<u8>>,
}

const NOAUTH: &[u8] = b"-NOAUTH Authentication required.\r\n";

impl FakeRedis {
    async fn start(refuse_for: Duration, refuse_writes: bool, hang_up: fn(usize) -> bool, messages: Vec<Vec<u8>>) -> Arc<Self> {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fake = Arc::new(Self {
            url: format!("redis://{}", l.local_addr().unwrap()),
            commands: Mutex::new(Vec::new()),
            started: std::time::Instant::now(),
            refuse_for,
            subscribes: AtomicUsize::new(0),
            refuse_writes,
            hang_up,
            messages,
        });
        let f = fake.clone();
        tokio::spawn(async move {
            while let Ok((sock, _)) = l.accept().await {
                tokio::spawn(f.clone().serve(sock));
            }
        });
        fake
    }

    fn seen(&self, name: &str) -> Vec<Vec<String>> {
        self.commands.lock().unwrap().iter().filter(|c| c[0].eq_ignore_ascii_case(name)).cloned().collect()
    }

    async fn serve(self: Arc<Self>, sock: TcpStream) {
        let (r, mut w) = sock.into_split();
        let mut r = BufReader::new(r);
        while let Some(cmd) = read_command(&mut r).await {
            let text: Vec<String> = cmd.iter().map(|p| String::from_utf8_lossy(p).to_string()).collect();
            self.commands.lock().unwrap().push(text.clone());
            let refusing = self.started.elapsed() < self.refuse_for;
            let reply: Vec<u8> = match text[0].to_ascii_uppercase().as_str() {
                "PING" | "SUBSCRIBE" if refusing => NOAUTH.to_vec(),
                "SUBSCRIBE" => {
                    let hang_up = (self.hang_up)(self.subscribes.fetch_add(1, Ordering::SeqCst));
                    // ["subscribe", channel, channels now subscribed], then the messages.
                    let mut out = b"*3\r\n".to_vec();
                    out.extend(bulk(b"subscribe"));
                    out.extend(bulk(&cmd[1]));
                    out.extend_from_slice(b":1\r\n");
                    for m in &self.messages {
                        out.extend_from_slice(b"*3\r\n");
                        for part in [&b"message"[..], &cmd[1], m] {
                            out.extend(bulk(part));
                        }
                    }
                    if w.write_all(&out).await.is_err() || hang_up {
                        return;
                    }
                    continue;
                }
                "PING" => b"+PONG\r\n".to_vec(),
                "PUBLISH" | "DEL" | "HDEL" if self.refuse_writes => NOAUTH.to_vec(),
                "PUBLISH" | "DEL" | "HDEL" => b":0\r\n".to_vec(),
                _ => b"+OK\r\n".to_vec(),
            };
            if w.write_all(&reply).await.is_err() {
                return;
            }
        }
    }
}

/// One RESP bulk string.
fn bulk(p: &[u8]) -> Vec<u8> {
    let mut out = format!("${}\r\n", p.len()).into_bytes();
    out.extend_from_slice(p);
    out.extend_from_slice(b"\r\n");
    out
}

async fn read_command<R: AsyncBufReadExt + Unpin>(r: &mut R) -> Option<Vec<Vec<u8>>> {
    let mut line = String::new();
    r.read_line(&mut line).await.ok()?;
    let n: usize = line.trim().strip_prefix('*')?.parse().ok()?;
    let mut parts = Vec::with_capacity(n);
    for _ in 0..n {
        line.clear();
        r.read_line(&mut line).await.ok()?;
        let len: usize = line.trim().strip_prefix('$')?.parse().ok()?;
        let mut buf = vec![0; len + 2];
        r.read_exact(&mut buf).await.ok()?;
        buf.truncate(len);
        parts.push(buf);
    }
    Some(parts)
}

async fn wait_for(what: &str, mut done: impl FnMut() -> bool, timeout: Duration) {
    let start = tokio::time::Instant::now();
    while !done() {
        assert!(start.elapsed() < timeout, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn evictions_and_publishes_reach_redis_as_java_sends_them() {
    let fake = FakeRedis::start(Duration::ZERO, false, |_| false, vec![]).await;
    let svc = CacheService::new("cmn", "evictionChannel", Some(&fake.url)).unwrap();
    let fam = svc.family::<String, u32>();
    fam.insert("pageCache", "k".into(), 1).await;
    fam.insert("pageCache", "other".into(), 1).await;

    svc.evict_everywhere("pageCache", "k").await;
    assert!(fam.get("pageCache", &"k".to_string()).await.is_none());
    assert_eq!(fam.get("pageCache", &"other".to_string()).await, Some(1), "only the one key");
    svc.evict_all_everywhere("pageCache").await;
    assert!(fam.get("pageCache", &"other".to_string()).await.is_none());
    assert!(svc.publish("ssr:cache:invalidation", r#"{"appCode":"a"}"#).await);

    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    assert_eq!(
        fake.seen("PUBLISH"),
        [
            s(&["PUBLISH", "evictionChannel", "cmn-pageCache:k"]),
            s(&["PUBLISH", "evictionChannel", "cmn-pageCache:*"]),
            s(&["PUBLISH", "ssr:cache:invalidation", r#"{"appCode":"a"}"#]),
        ]
    );
    assert_eq!(fake.seen("HDEL"), [s(&["HDEL", "cmn-pageCache", "k"])], "the key leaves the Java L2 hash");
    assert_eq!(fake.seen("DEL"), [s(&["DEL", "cmn-pageCache"])], "the whole L2 hash goes");
}

#[tokio::test]
async fn refused_redis_writes_only_log() {
    let fake = FakeRedis::start(Duration::ZERO, true, |_| false, vec![]).await;
    let svc = CacheService::new("cmn", "evictionChannel", Some(&fake.url)).unwrap();
    let fam = svc.family::<String, u32>();
    fam.insert("c", "k".into(), 1).await;
    svc.evict_everywhere("c", "k").await;
    assert!(fam.get("c", &"k".to_string()).await.is_none(), "the local copy goes even when Redis refuses");
    fam.insert("c", "k".into(), 1).await;
    svc.evict_all_everywhere("c").await;
    assert!(fam.get("c", &"k".to_string()).await.is_none());
    assert!(!svc.publish("ssr:cache:invalidation", "{}").await, "a refused publish is false");
    assert_eq!((fake.seen("PUBLISH").len(), fake.seen("HDEL").len(), fake.seen("DEL").len()), (3, 1, 1));
}

/// `true` once `fam` no longer holds `cache`/`key`, polling for up to `secs`.
async fn gone(fam: &platform::cache::LocalCaches<String, u32>, cache: &str, key: &str, secs: u64) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(secs) {
        if fam.get(cache, &key.to_string()).await.is_none() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

#[tokio::test]
async fn a_refused_listener_retries_instead_of_listening_to_nothing() {
    // Redis refuses the first attempt, as it does when it wants a password the URL does not
    // carry. redis-rs reports a refused SUBSCRIBE as a success, which would leave the listener
    // waiting on a subscription that does not exist.
    let fake = FakeRedis::start(Duration::from_secs(1), false, |_| false, vec![b"cmn-c:k".to_vec()]).await;
    let svc = CacheService::new("cmn", "evictionChannel", Some(&fake.url)).unwrap();
    let fam = svc.family::<String, u32>();
    fam.insert("c", "k".into(), 1).await;
    let listener = svc.spawn_eviction_listener().unwrap();

    let attempted = || !fake.seen("PING").is_empty() || !fake.seen("SUBSCRIBE").is_empty();
    wait_for("the first attempt", attempted, Duration::from_secs(5)).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(fam.get("c", &"k".to_string()).await, Some(1), "nothing heard while refused");
    assert!(!listener.is_finished());

    // The retry, after the refusal ends, subscribes and hears evictions.
    assert!(gone(&fam, "c", "k", 10).await, "subscribed on the retry");
    assert_eq!(fake.subscribes.load(Ordering::SeqCst), 1);
    listener.abort();
}

#[tokio::test]
async fn listener_skips_bad_payloads_and_clears_after_a_reconnect() {
    // The first subscription delivers a payload that is not UTF-8 and then an eviction, and
    // hangs up; the second stays.
    let fake = FakeRedis::start(Duration::ZERO, false, |n| n == 0, vec![vec![0xff, 0xfe], b"cmn-c:k".to_vec()]).await;
    let svc = CacheService::new("cmn", "evictionChannel", Some(&fake.url)).unwrap();
    let fam = svc.family::<String, u32>();
    fam.insert("c", "k".into(), 1).await;
    fam.insert("d", "k".into(), 1).await;
    let listener = svc.spawn_eviction_listener().unwrap();

    assert!(gone(&fam, "c", "k", 5).await, "the eviction after the bad payload arrived");
    assert_eq!(fam.get("d", &"k".to_string()).await, Some(1), "only the evicted key, until the reconnect");

    // Evictions published while disconnected were missed: everything local goes on reconnect.
    assert!(gone(&fam, "d", "k", 10).await, "cleared on reconnect");
    assert_eq!(fake.subscribes.load(Ordering::SeqCst), 2);
    assert!(!listener.is_finished());
    listener.abort();
}

/// The local Redis, on a key prefix and channel nothing else uses:
/// `PLATFORM_LOCAL_STACK=1 MODLIX__REDIS__URL=... cargo test -p platform --test cache_service -- --ignored`.
#[tokio::test]
#[ignore]
async fn live_publish_and_evict_on_the_local_redis() {
    if std::env::var("PLATFORM_LOCAL_STACK").is_err() {
        return;
    }
    let Ok(url) = std::env::var("MODLIX__REDIS__URL") else { return };
    let prefix = format!("rustcovtest{}", std::process::id());
    let channel = format!("{prefix}-evictions");
    let (c1, c2) = (format!("{prefix}-c1"), format!("{prefix}-c2"));

    let client = redis::Client::open(normalize_redis_url(&url).as_str()).unwrap();
    let mut conn = client.get_multiplexed_async_connection().await.unwrap();
    // The Java L2 hashes, as `<prefix>-<cacheName>` with one field per key.
    for (hash, field) in [(&c1, "k"), (&c1, "keep"), (&c2, "k")] {
        let _: i64 = redis::cmd("HSET").arg(hash).arg(field).arg("1").query_async(&mut conn).await.unwrap();
    }
    let mut sub = client.get_async_pubsub().await.unwrap();
    sub.subscribe(&channel).await.unwrap();

    let svc = CacheService::new(&prefix, &channel, Some(&url)).unwrap();
    let published = svc.publish(&channel, "hello").await;
    svc.evict_everywhere("c1", "k").await;
    svc.evict_all_everywhere("c2").await;

    let mut received = Vec::new();
    {
        let mut stream = sub.on_message();
        while received.len() < 3 {
            match tokio::time::timeout(Duration::from_secs(5), stream.next()).await {
                Ok(Some(m)) => received.push(m.get_payload::<String>().unwrap()),
                _ => break,
            }
        }
    }
    let k_left: i64 = redis::cmd("HEXISTS").arg(&c1).arg("k").query_async(&mut conn).await.unwrap();
    let keep_left: i64 = redis::cmd("HEXISTS").arg(&c1).arg("keep").query_async(&mut conn).await.unwrap();
    let c2_left: i64 = redis::cmd("EXISTS").arg(&c2).query_async(&mut conn).await.unwrap();

    // Clean up before asserting, so a failure leaves nothing behind.
    let _: i64 = redis::cmd("DEL").arg(&c1).arg(&c2).query_async(&mut conn).await.unwrap();
    let left: i64 = redis::cmd("EXISTS").arg(&c1).arg(&c2).query_async(&mut conn).await.unwrap();
    assert_eq!(left, 0);

    assert!(published, "a publish on the local Redis succeeds");
    assert_eq!(received, ["hello".to_string(), format!("{c1}:k"), format!("{c2}:*")]);
    assert_eq!((k_left, keep_left, c2_left), (0, 1, 0), "one field out of c1's hash, all of c2's");
}
