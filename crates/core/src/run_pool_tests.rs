use super::*;

use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use axum::routing::get;
use axum::Router;
use futures::FutureExt;
use kirun::function::Function;
use kirun::repository::{KIRunFunctionRepository, KIRunSchemaRepository, Repository};
use kirun::runtime::FunctionExecutionParameters;
use serde_json::Value;

/// Answers `/readyz` must give while runs are busy.
const READY_WITHIN: Duration = Duration::from_millis(500);
/// How long each busy run computes.
const BUSY_FOR: Duration = Duration::from_millis(2500);

/// A KIRun run that computes for `BUSY_FOR` without ever waiting: `System.Array.Sort` of
/// 20,000 numbers again and again. Its futures are always ready, so it holds its thread until
/// it is done, as the AdZump syncs did on dev.
async fn busy_kirun_run() -> usize {
    let functions: Arc<dyn Repository<dyn Function>> = Arc::new(KIRunFunctionRepository::new());
    let schemas: Arc<dyn Repository<kirun::json::schema::Schema>> = Arc::new(KIRunSchemaRepository::new());
    let sort = functions.find("System.Array", "Sort").await.expect("System.Array.Sort");
    let mut seed = 7u64;
    let source: Vec<Value> = (0..20_000)
        .map(|_| {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            Value::from(seed >> 33)
        })
        .collect();
    let until = Instant::now() + BUSY_FOR;
    let mut sorts = 0;
    while Instant::now() < until {
        let mut args = kirun::Map::new();
        args.insert("source".to_string(), Value::Array(source.clone()));
        let mut fep = FunctionExecutionParameters::new(functions.clone(), schemas.clone()).set_arguments(args);
        sort.execute(&mut fep).await.expect("sorted");
        sorts += 1;
    }
    sorts
}

/// The health routes and `/busy` (a busy run, on `pool` when there is one), served on the
/// test's runtime; its port.
async fn serve(pool: Option<RunPool>) -> u16 {
    let health = Health::new(metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder().handle());
    health.check("ok", || async { Ok(()) });
    let mut busy = Router::new().route("/busy", get(|| async { busy_kirun_run().await.to_string() }));
    if let Some(pool) = pool {
        busy = busy.route_layer(axum::middleware::from_fn_with_state(pool, offload));
    }
    let app = busy.merge(health.routes());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    port
}

/// A GET from a thread of its own (the test's runtime may be the one that is busy): the status
/// line's code and how long the answer took.
fn get_from_thread(port: u16, path: &'static str) -> std::thread::JoinHandle<(u16, Duration)> {
    std::thread::spawn(move || {
        let started = Instant::now();
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        write!(s, "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
        let mut buf = [0u8; 12];
        let code = match s.read_exact(&mut buf) {
            Ok(()) => std::str::from_utf8(&buf[9..12]).ok().and_then(|c| c.parse().ok()).unwrap_or(0),
            Err(_) => 0,
        };
        (code, started.elapsed())
    })
}

/// The cause, as on dev: runs on the server's own runtime, one per worker, and `/readyz`
/// waits until one of them is done.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn busy_runs_on_the_server_runtime_hold_readyz_back() {
    let port = serve(None).await;
    let runs: Vec<_> = (0..2).map(|_| tokio::spawn(busy_kirun_run())).collect();
    // A thread's sleep: the runtime's timers are as stuck as everything else on it.
    std::thread::sleep(Duration::from_millis(100));
    let (code, took) = get_from_thread(port, "/readyz").join().unwrap();
    assert_eq!(code, 200);
    assert!(took >= Duration::from_secs(1), "readyz answered in {took:?} with every worker busy");
    for r in runs {
        assert!(r.await.unwrap() > 0);
    }
}

/// The fix: the same runs (twice as many as the pool has threads, and two busy requests through
/// the execute layer) on the run pool, and `/readyz` answers at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn readyz_answers_while_runs_keep_every_pool_thread_busy() {
    let pool = RunPool::new("test-runs", 2).unwrap();
    let port = serve(Some(pool.clone())).await;
    let runs: Vec<_> = (0..4).map(|_| pool.spawn(busy_kirun_run())).collect();
    let requests: Vec<_> = (0..2).map(|_| get_from_thread(port, "/busy")).collect();
    std::thread::sleep(Duration::from_millis(200));
    for _ in 0..5 {
        let (code, took) = get_from_thread(port, "/readyz").join().unwrap();
        assert_eq!(code, 200);
        assert!(took < READY_WITHIN, "readyz answered in {took:?} while the run pool was busy");
        std::thread::sleep(Duration::from_millis(100));
    }
    for r in requests {
        let (code, took) = r.join().unwrap();
        assert_eq!(code, 200, "a request run on the pool is answered");
        assert!(took >= BUSY_FOR);
    }
    for r in runs {
        assert!(r.await.unwrap() > 0);
    }
}

#[tokio::test]
async fn a_run_keeps_the_message_scope_and_its_panic_and_is_stopped_when_dropped() {
    use platform::messages::scope::{current, with_scope, RequestScope};
    let pool = RunPool::new("test-runs", 1).unwrap();

    let mut h = axum::http::HeaderMap::new();
    h.insert("accept-language", "fr".parse().unwrap());
    let seen = with_scope(RequestScope::from_headers(&h), {
        let pool = pool.clone();
        async move { pool.run(async { current().map(|s| s.accept_language.clone()) }).await }
    })
    .await;
    assert_eq!(seen.unwrap_or_default().first().map(String::as_str), Some("fr"), "the run sees the request's scope");
    assert!(pool.run(async { current().is_none() }).await, "and none outside a request");

    let panicked = std::panic::AssertUnwindSafe(pool.run(async { panic!("boom") })).catch_unwind().await;
    let payload = panicked.expect_err("the run's panic comes out of run");
    assert_eq!(payload.downcast_ref::<&str>(), Some(&"boom"));

    let finished = Arc::new(AtomicBool::new(false));
    let f = finished.clone();
    let run = pool.run(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        f.store(true, Ordering::SeqCst);
    });
    assert!(tokio::time::timeout(Duration::from_millis(50), run).await.is_err());
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!finished.load(Ordering::SeqCst), "a dropped run is stopped, as a dropped request is");

    // The last clone stops the runtime, from inside an async context too.
    drop(pool);
}

#[test]
fn sizes_and_the_prefetch_cap() {
    let d = RunsSection::default();
    assert_eq!((d.dedicated, d.threads), (true, 0));
    assert_eq!(d.exec_threads(), cpus());
    assert_eq!(d.events_threads(16), cpus().max(16), "a thread for every delivery in flight");
    assert_eq!(d.events_threads(0), cpus());
    let four = RunsSection { dedicated: true, threads: 4 };
    assert_eq!((four.exec_threads(), four.events_threads(16)), (4, 4));

    let events = EventsSection::default();
    assert_eq!(events.prefetch, 16);
    assert_eq!(events_settings(&events, 32).prefetch, 16, "under the threads: kept");
    assert_eq!(events_settings(&events, 4).prefetch, 4, "over them: lowered");
    assert_eq!(events_settings(&events, 0).prefetch, 1);
    assert_eq!(events_settings(&events, 4).queues, events.queues);

    let c: CoreConfig = toml::from_str("[runs]\ndedicated = false\nthreads = 3").unwrap();
    assert_eq!(c.runs, RunsSection { dedicated: false, threads: 3 });
    assert!(events_pool(&c).unwrap().is_none() && exec_pool(&c).unwrap().is_none(), "off: no pool");
    let c: CoreConfig = toml::from_str("").unwrap();
    assert_eq!(c.runs, RunsSection::default());
}

/// Readiness keeps its own connections: with every connection of the runs' pool taken (and
/// its one connection driven by a runtime that is gone), `/readyz` still reaches MySQL and
/// Mongo. Local stack: `CORE_LOCAL_STACK=1`, `eval "$(tools/local-env.py)"`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs the local stack: CORE_LOCAL_STACK=1 and config/local.toml"]
async fn readiness_answers_with_the_shared_pool_exhausted() {
    if !crate::testing::local_stack() {
        return;
    }
    let mut cfg = CoreConfig::default();
    cfg.database.host = "127.0.0.1".into();
    cfg.database.port = 3306;
    cfg.database.username = "root".into();
    cfg.database.password = std::env::var("MODLIX__DATABASE__PASSWORD").expect("MODLIX__DATABASE__PASSWORD");
    cfg.mongo.uri = "mongodb://127.0.0.1:27017".into();

    let opts = sqlx::mysql::MySqlConnectOptions::new()
        .host("127.0.0.1")
        .port(3306)
        .username("root")
        .password(&cfg.database.password)
        .database("core");
    let shared = sqlx::mysql::MySqlPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(300))
        .connect_with(opts)
        .await
        .unwrap();
    let held = shared.acquire().await.unwrap();
    assert!(sqlx::query("SELECT 1").execute(&shared).await.is_err(), "the shared pool is exhausted");

    let health = Health::new(metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder().handle());
    readiness_checks(&health, &cfg).await.unwrap();
    for _ in 0..3 {
        let started = Instant::now();
        assert!(health.ready().await, "ready over its own connections");
        assert!(started.elapsed() < READY_WITHIN, "{:?}", started.elapsed());
    }
    drop(held);
}
