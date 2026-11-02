//! Outlier ejection, retries, the retry budget, the circuit breaker and registry pools, end to
//! end against fake upstreams that refuse, answer 5xx or hang.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::{to_bytes, Body, Bytes};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use gateway::config::{BreakerConfig, GatewayConfig, OutlierConfig, PoolConfig, RouteConfig};
use platform::config::UpstreamConfig;
use serde_json::{json, Value};
use tower::ServiceExt;

/// An upstream whose answers the test sets.
struct Fake {
    name: String,
    hits: AtomicUsize,
    /// What every request but `/health` is answered with...
    status: AtomicU16,
    /// ...except the first this many, answered 502.
    first_502s: AtomicUsize,
    delay_ms: AtomicU64,
    healthy: AtomicBool,
}

type F = Arc<Fake>;

async fn answer(State(f): State<F>, req: Request) -> Response {
    let method = req.method().to_string();
    let body = to_bytes(req.into_body(), usize::MAX).await.unwrap_or_default();
    let n = f.hits.fetch_add(1, Ordering::SeqCst) + 1;
    let delay = f.delay_ms.load(Ordering::SeqCst);
    if delay > 0 {
        tokio::time::sleep(Duration::from_millis(delay)).await;
    }
    let status = if n <= f.first_502s.load(Ordering::SeqCst) {
        StatusCode::BAD_GATEWAY
    } else {
        StatusCode::from_u16(f.status.load(Ordering::SeqCst)).unwrap()
    };
    (status, Json(json!({"from": f.name, "method": method, "body": String::from_utf8_lossy(&body)}))).into_response()
}

async fn fake(name: &str, status: u16) -> (String, F) {
    let f = Arc::new(Fake {
        name: name.into(),
        hits: AtomicUsize::new(0),
        status: AtomicU16::new(status),
        first_502s: AtomicUsize::new(0),
        delay_ms: AtomicU64::new(0),
        healthy: AtomicBool::new(true),
    });
    let app = Router::new()
        .route(
            "/health",
            get(|State(f): State<F>| async move {
                if f.healthy.load(Ordering::SeqCst) { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE }
            }),
        )
        .route(
            "/api/security/clients/internal/getClientNAppCodeNType",
            get(|| async { Json(json!(["SYSTEM", "nothing", "LIVE"])) }),
        )
        .fallback(answer)
        .with_state(f.clone());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (base, f)
}

fn hits(f: &F) -> usize {
    f.hits.load(Ordering::SeqCst)
}

fn pool(urls: &[&str]) -> PoolConfig {
    PoolConfig {
        upstreams: UpstreamConfig::Many(urls.iter().map(|s| s.to_string()).collect()),
        health_path: "/health".into(),
        health_interval_seconds: 3600,
        ..Default::default()
    }
}

fn no_breaker() -> BreakerConfig {
    BreakerConfig { enabled: false, ..Default::default() }
}

/// A gateway with one route per pool, `/api/<pool>`, and security answered by `security`.
async fn gateway(security: &str, pools: Vec<(&str, PoolConfig)>) -> Router {
    gateway_with(security, pools, |_| {}).await
}

async fn gateway_with(security: &str, pools: Vec<(&str, PoolConfig)>, edit: impl FnOnce(&mut GatewayConfig)) -> Router {
    let mut cfg = GatewayConfig::default();
    cfg.security.upstream = UpstreamConfig::One(security.into());
    for (name, p) in pools {
        cfg.routes.push(RouteConfig {
            id: name.into(),
            prefix: format!("/api/{name}"),
            pool: name.into(),
            ..Default::default()
        });
        cfg.pools.insert(name.into(), p);
    }
    edit(&mut cfg);
    gateway::build(&cfg).await.unwrap().0
}

fn req(method: &str, uri: &str, body: &str) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri).header("host", "h.example");
    if !body.is_empty() {
        b = b.header("content-length", body.len().to_string());
    }
    let mut r = b.body(Body::from(body.to_string())).unwrap();
    let addr: SocketAddr = "127.0.0.1:50000".parse().unwrap();
    r.extensions_mut().insert(ConnectInfo(addr));
    r
}

async fn call(app: &Router, r: Request<Body>) -> (StatusCode, Bytes) {
    let resp = app.clone().oneshot(r).await.unwrap();
    let s = resp.status();
    (s, to_bytes(resp.into_body(), usize::MAX).await.unwrap())
}

async fn get_(app: &Router, uri: &str) -> (StatusCode, Value) {
    let (s, b) = call(app, req("GET", uri, "")).await;
    (s, serde_json::from_slice(&b).unwrap_or(Value::Null))
}

/// GETs until `f` has had `n` requests in all.
async fn until_hits(app: &Router, uri: &str, f: &F, n: usize) {
    for _ in 0..200 {
        if hits(f) >= n {
            return;
        }
        get_(app, uri).await;
    }
    panic!("{} never reached {n} requests", f.name);
}

/// Whether `f` gets any of a few GETs.
async fn in_rotation(app: &Router, uri: &str, f: &F) -> bool {
    let before = hits(f);
    for _ in 0..6 {
        get_(app, uri).await;
    }
    hits(f) > before
}

async fn sleep_until(t: Instant) {
    tokio::time::sleep(t.saturating_duration_since(Instant::now())).await;
}

#[tokio::test]
async fn outlier_ejection_grows_and_is_capped() {
    let (bad_base, bad) = fake("bad", 503).await;
    let (good_base, good) = fake("good", 200).await;
    let mut p = pool(&[&bad_base, &good_base]);
    p.breaker = no_breaker();
    p.outlier = OutlierConfig { base_ejection_ms: 500, max_ejection_ms: 1_200, ..Default::default() };
    let app = gateway(&good_base, vec![("ej", p)]).await;
    let ms = Duration::from_millis;

    // Ejected at its fifth 503 in a row, for 500 ms.
    until_hits(&app, "/api/ej", &bad, 5).await;
    let t1 = Instant::now();
    assert!(!in_rotation(&app, "/api/ej", &bad).await, "ejected");
    sleep_until(t1 + ms(300)).await;
    assert!(!in_rotation(&app, "/api/ej", &bad).await, "still within 500 ms");
    sleep_until(t1 + ms(750)).await;
    assert!(in_rotation(&app, "/api/ej", &bad).await, "back after 500 ms and a passing check");

    // The second ejection lasts 1 s: still out when the first was long over.
    until_hits(&app, "/api/ej", &bad, 10).await;
    let t2 = Instant::now();
    sleep_until(t2 + ms(750)).await;
    assert!(!in_rotation(&app, "/api/ej", &bad).await, "2 x 500 ms");
    sleep_until(t2 + ms(1_250)).await;
    assert!(in_rotation(&app, "/api/ej", &bad).await);

    // The third would be 1.5 s: capped at 1.2 s.
    until_hits(&app, "/api/ej", &bad, 15).await;
    let t3 = Instant::now();
    sleep_until(t3 + ms(1_000)).await;
    assert!(!in_rotation(&app, "/api/ej", &bad).await);
    sleep_until(t3 + ms(1_400)).await;
    assert!(in_rotation(&app, "/api/ej", &bad).await, "back at 1.2 s, not 1.5 s");
    assert!(hits(&good) > 0);
}

#[tokio::test]
async fn at_most_half_a_pool_is_ejected() {
    let (b1_base, b1) = fake("b1", 503).await;
    let (b2_base, b2) = fake("b2", 503).await;
    let (b3_base, b3) = fake("b3", 503).await;
    let (g_base, g) = fake("g", 200).await;
    let mut p = pool(&[&b1_base, &b2_base, &b3_base, &g_base]);
    p.breaker = no_breaker();
    let app = gateway(&g_base, vec![("cap", p)]).await;
    for _ in 0..40 {
        get_(&app, "/api/cap").await;
    }
    let before: Vec<usize> = [&b1, &b2, &b3, &g].iter().map(|f| hits(f)).collect();
    for _ in 0..20 {
        get_(&app, "/api/cap").await;
    }
    let got: Vec<bool> = [&b1, &b2, &b3, &g].iter().zip(&before).map(|(f, b)| hits(f) > *b).collect();
    assert_eq!(got[..3].iter().filter(|x| **x).count(), 1, "two of the three failing instances are out, not three: {got:?}");
    assert!(got[3]);
}

#[tokio::test]
async fn five_502s_are_retried_away_then_ejected() {
    let (flaky_base, flaky) = fake("flaky", 200).await;
    flaky.first_502s.store(5, Ordering::SeqCst);
    let (good_base, good) = fake("good", 200).await;
    let mut p = pool(&[&flaky_base, &good_base]);
    // Every 502 retried, whatever the budget would allow at this low a rate.
    p.retry.budget_percent = 100;
    let app = gateway(&good_base, vec![("f", p)]).await;
    for _ in 0..30 {
        let (s, v) = get_(&app, "/api/f").await;
        assert_eq!((s, v["from"].as_str()), (StatusCode::OK, Some("good")), "each 502 retried on the good instance");
    }
    assert_eq!(hits(&flaky), 5, "out after its fifth 502 (ejected for 10 s)");
    assert_eq!(hits(&good), 30);
}

#[tokio::test]
async fn what_is_retried_and_what_never_is() {
    let (a_base, a) = fake("a", 503).await;
    let (b_base, b) = fake("b", 503).await;
    let (hang_base, hang) = fake("hang", 200).await;
    hang.delay_ms.store(5_000, Ordering::SeqCst);
    let (good_base, good) = fake("good", 200).await;
    let quiet = |urls: &[&str]| {
        let mut p = pool(urls);
        p.breaker = no_breaker();
        p.outlier.consecutive_5xx = 0;
        p.retry.budget_percent = 100;
        p
    };
    let app = gateway_with(
        &good_base,
        vec![
            ("two", quiet(&[&a_base, &b_base])),
            ("slow", quiet(&[&hang_base, &good_base])),
            ("refused", quiet(&["http://127.0.0.1:1", &good_base])),
            ("refusedpost", quiet(&["http://127.0.0.1:1", &good_base])),
            ("refusedbody", quiet(&["http://127.0.0.1:1", &good_base])),
        ],
        |cfg| {
            for r in &mut cfg.routes {
                if r.id == "slow" {
                    r.timeout_seconds = Some(1);
                }
            }
        },
    )
    .await;
    let total = || hits(&a) + hits(&b);

    let cases: [(&str, &str, usize); 8] = [
        ("POST", "abc", 1),
        ("POST", "", 1),
        ("PATCH", "", 1),
        ("PUT", "abc", 1),
        ("PUT", "", 2),
        ("GET", "", 2),
        ("DELETE", "", 2),
        ("HEAD", "", 2),
    ];
    for (method, body, sent) in cases {
        let before = total();
        let (s, b) = call(&app, req(method, "/api/two/x", body)).await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{method}: the service's own 503 comes back");
        if method != "HEAD" {
            assert!(serde_json::from_slice::<Value>(&b).unwrap().get("from").is_some(), "{method}: not a gateway error");
        }
        assert_eq!(total() - before, sent, "{method} with body {body:?}");
    }

    // A timeout is never retried, even for a GET: the first pick of the pool is the hanging one.
    let (s, b) = call(&app, req("GET", "/api/slow", "")).await;
    assert_eq!(s, StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(serde_json::from_slice::<Value>(&b).unwrap()["code"], "GW.SERVICE_TIMEOUT");
    assert_eq!((hits(&hang), hits(&good)), (1, 0));

    // A refused connection sent nothing: a GET or a POST without a body moves on to the next
    // instance; a POST with a body cannot (the body went with the failed attempt).
    let (s, v) = get_(&app, "/api/refused").await;
    assert_eq!((s, v["from"].as_str()), (StatusCode::OK, Some("good")));
    let (s, b) = call(&app, req("POST", "/api/refusedpost", "")).await;
    assert_eq!(s, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
    assert_eq!(hits(&good), 2);
    let (s, b) = call(&app, req("POST", "/api/refusedbody", "abc")).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(serde_json::from_slice::<Value>(&b).unwrap()["code"], "GW.SERVICE_UNAVAILABLE");
    assert_eq!(hits(&good), 2);
}

#[tokio::test]
async fn a_retry_that_fails_outright_returns_the_first_answer() {
    // The 503 instance answers first; the retry finds the other one refusing.
    let (a_base, a) = fake("a", 503).await;
    let refusing = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        drop(l);
        base
    };
    let mut p = pool(&[&a_base, &refusing]);
    p.breaker = no_breaker();
    let app = gateway(&a_base, vec![("r", p)]).await;
    let (s, v) = get_(&app, "/api/r").await;
    assert_eq!((s, v["from"].as_str()), (StatusCode::SERVICE_UNAVAILABLE, Some("a")));
    assert_eq!(hits(&a), 1);
}

#[tokio::test]
async fn the_retry_budget_holds_under_a_storm() {
    let (a_base, a) = fake("a", 503).await;
    let (b_base, b) = fake("b", 503).await;
    let mut p = pool(&[&a_base, &b_base]);
    p.breaker = no_breaker();
    p.outlier.consecutive_5xx = 0;
    let app = gateway(&a_base, vec![("storm", p)]).await;
    // Warm the host cache so the storm itself is only GETs to the pool.
    get_(&app, "/api/storm").await;
    let warm = hits(&a) + hits(&b);

    let n = 300;
    let started = Instant::now();
    let tasks: Vec<_> = (0..n)
        .map(|_| {
            let app = app.clone();
            tokio::spawn(async move { call(&app, req("GET", "/api/storm", "")).await.0 })
        })
        .collect();
    for t in tasks {
        assert_eq!(t.await.unwrap(), StatusCode::SERVICE_UNAVAILABLE);
    }
    let seconds = started.elapsed().as_secs() as usize + 1;
    let retries = hits(&a) + hits(&b) - warm - n;
    // 20% of the storm, plus the 3 a second the floor allows in each second it spanned.
    assert!(retries >= 3, "some were retried: {retries}");
    assert!(retries <= (n + 1) / 5 + 3 * (seconds + 1), "{retries} retries for {n} requests in {seconds}s");
}

#[tokio::test]
async fn the_breaker_opens_half_opens_and_closes() {
    let (u_base, u) = fake("u", 503).await;
    let mut p = pool(&[&u_base]);
    p.breaker = BreakerConfig { open_ms: 400, max_open_ms: 1_600, ..Default::default() };
    let app = gateway(&u_base, vec![("brk", p)]).await;
    let refused = |v: &Value| v["code"] == "GW.SERVICE_UNAVAILABLE";

    // Closed: 19 failures are under the minimum of 20 requests; the 20th opens it.
    for _ in 0..20 {
        let (s, v) = get_(&app, "/api/brk").await;
        assert_eq!((s, v["from"].as_str()), (StatusCode::SERVICE_UNAVAILABLE, Some("u")));
    }
    assert_eq!(hits(&u), 20);

    // Open: answered at once, nothing reaches the service.
    let (s, v) = get_(&app, "/api/brk").await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    assert!(refused(&v), "{v}");
    assert_eq!(v["message"], "The service is not answering right now. Try again in a few seconds.");
    assert!(v["debugMessage"].as_str().unwrap().contains("circuit breaker is open"));
    assert_eq!(hits(&u), 20);

    // Half-open after 400 ms: three trials at a time, the rest still refused.
    tokio::time::sleep(Duration::from_millis(450)).await;
    u.status.store(200, Ordering::SeqCst);
    u.delay_ms.store(300, Ordering::SeqCst);
    let tasks: Vec<_> = (0..5)
        .map(|_| {
            let app = app.clone();
            tokio::spawn(async move { get_(&app, "/api/brk").await })
        })
        .collect();
    let mut answers = Vec::new();
    for t in tasks {
        answers.push(t.await.unwrap());
    }
    assert_eq!(answers.iter().filter(|(s, _)| *s == StatusCode::OK).count(), 3);
    assert_eq!(answers.iter().filter(|(_, v)| refused(v)).count(), 2);
    assert_eq!(hits(&u), 23);

    // The three trials passed: closed again.
    u.delay_ms.store(0, Ordering::SeqCst);
    for _ in 0..10 {
        assert_eq!(get_(&app, "/api/brk").await.0, StatusCode::OK);
    }

    // Open again; a failed trial doubles the open time to 800 ms.
    u.status.store(503, Ordering::SeqCst);
    for _ in 0..20 {
        get_(&app, "/api/brk").await;
    }
    assert!(refused(&get_(&app, "/api/brk").await.1));
    tokio::time::sleep(Duration::from_millis(450)).await;
    let (_, v) = get_(&app, "/api/brk").await;
    assert_eq!(v["from"], "u", "the trial reached the service, and failed");
    let reopened = Instant::now();
    sleep_until(reopened + Duration::from_millis(500)).await;
    assert!(refused(&get_(&app, "/api/brk").await.1), "open for 800 ms now, not 400");
    sleep_until(reopened + Duration::from_millis(900)).await;
    u.status.store(200, Ordering::SeqCst);
    for _ in 0..3 {
        assert_eq!(get_(&app, "/api/brk").await.0, StatusCode::OK);
    }
    for _ in 0..5 {
        assert_eq!(get_(&app, "/api/brk").await.0, StatusCode::OK, "closed");
    }
}

type Listing = Arc<parking_lot::RwLock<Vec<String>>>;

/// A registry answering `GET /eureka/apps/{app}` with the listed `ip:port`s, all UP.
async fn registry(listing: Listing) -> String {
    let app = Router::new()
        .route(
            "/eureka/apps/{app}",
            get(|State(l): State<Listing>| async move {
                let inst: Vec<Value> = l
                    .read()
                    .iter()
                    .map(|a| {
                        let (ip, port) = a.split_once(':').unwrap();
                        json!({"ipAddr": ip, "port": {"$": port.parse::<u16>().unwrap()}, "status": "UP"})
                    })
                    .collect();
                Json(json!({"application": {"instance": inst}}))
            }),
        )
        .with_state(listing);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let zone = format!("http://{}/eureka/", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    zone
}

#[tokio::test]
async fn a_registry_pool_follows_membership_within_its_refresh() {
    let (one_base, _) = fake("one", 200).await;
    let (two_base, _) = fake("two", 200).await;
    let addr = |b: &str| b.trim_start_matches("http://").to_string();
    let listing: Listing = Arc::new(parking_lot::RwLock::new(vec![addr(&one_base)]));
    let zone = registry(listing.clone()).await;
    let p = PoolConfig { upstreams: UpstreamConfig::One("lighthouse:REG".into()), health_path: "/health".into(), ..Default::default() };
    assert_eq!(p.discovery_refresh_ms, 2_000, "the default");
    let app = gateway_with(&one_base, vec![("reg", p)], |cfg| cfg.registry.zones = vec![zone]).await;

    let mut first = None;
    for _ in 0..50 {
        let (s, v) = get_(&app, "/api/reg").await;
        if s == StatusCode::OK {
            first = v["from"].as_str().map(str::to_string);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(first.as_deref(), Some("one"));

    *listing.write() = vec![addr(&two_base)];
    let changed = Instant::now();
    loop {
        let (_, v) = get_(&app, "/api/reg").await;
        if v["from"] == "two" {
            break;
        }
        assert!(changed.elapsed() < Duration::from_millis(2_600), "not followed within the 2 s refresh");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn internal_calls_pass_through_as_if_direct() {
    // An echo of the headers the instance receives; security is down, so any resolution fails.
    let echo = Router::new().fallback(|req: Request| async move {
        let h: serde_json::Map<String, Value> = req
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), Value::String(v.to_str().unwrap_or("").into())))
            .collect();
        Json(Value::Object(h))
    });
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, echo).await.unwrap() });
    let app = gateway("http://127.0.0.1:1", vec![("core", pool(&[&base]))]).await;

    let internal = |path: &str, codes: bool| {
        let mut b = Request::builder()
            .uri(path)
            .header("host", "gateway-1:8080")
            .header("x-forwarded-host", "leadzump.ai")
            .header("x-forwarded-port", "443")
            .header("x-draft", "true");
        if codes {
            b = b.header("clientcode", "FIN").header("appcode", "leadzump");
        }
        let mut r = b.body(Body::empty()).unwrap();
        r.extensions_mut().insert(ConnectInfo("10.0.0.5:4000".parse::<SocketAddr>().unwrap()));
        r
    };
    let (s, b) = call(&app, internal("/api/core/internal/data", true)).await;
    assert_eq!(s, StatusCode::OK, "no host resolution, so no security call");
    let h: Value = serde_json::from_slice(&b).unwrap();
    assert_eq!((h["clientcode"].as_str(), h["appcode"].as_str()), (Some("FIN"), Some("leadzump")));
    assert_eq!(h["x-draft"], "true", "the caller's draft marker travels the hop");
    assert_eq!((h["x-forwarded-host"].as_str(), h["x-forwarded-port"].as_str()), (Some("leadzump.ai"), Some("443")));
    assert!(h.get("forwarded").is_none() && h.get("x-forwarded-for").is_none());
    assert!(h["host"].as_str().unwrap().starts_with("127.0.0.1:"));

    // Without both codes, or on a public path, it is browser traffic: resolution runs (and fails
    // here, security being down).
    let (s, _) = call(&app, internal("/api/core/internal/data", false)).await;
    assert_eq!(s, StatusCode::BAD_GATEWAY);
    let (s, _) = call(&app, internal("/api/core/function/x", true)).await;
    assert_eq!(s, StatusCode::BAD_GATEWAY);
}
