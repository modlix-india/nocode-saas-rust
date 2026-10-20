//! The service runner end to end: telemetry (logs, metrics, OTLP traces), the shared layers,
//! health and readiness, error bodies, Lighthouse registration and a SIGTERM shutdown.
//! One test: telemetry and signal handlers are process-wide.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post, put};
use axum::Router;
use platform::app::{probe, Service};
use platform::config::{RegistryConfig, ServerConfig, TelemetryConfig};
use platform::error::AppError;
use platform::registry::Registry;
use platform::health::Health;
use platform::http::{not_modified, with_route};

#[derive(Default)]
struct Seen(Mutex<Vec<String>>);

async fn collector_and_registry() -> (String, Arc<Seen>) {
    let seen = Arc::new(Seen::default());
    let app = Router::new()
        .route(
            "/v1/traces",
            post(|State(s): State<Arc<Seen>>, body: axum::body::Bytes| async move {
                s.0.lock().unwrap().push(format!("traces {}", body.len()));
                StatusCode::OK
            }),
        )
        .route(
            "/eureka/apps/{app}",
            post(|State(s): State<Arc<Seen>>| async move {
                s.0.lock().unwrap().push("register".into());
                StatusCode::NO_CONTENT
            }),
        )
        .route(
            "/eureka/apps/{app}/{id}",
            put(|| async { StatusCode::OK }).delete(|State(s): State<Arc<Seen>>| async move {
                s.0.lock().unwrap().push("deregister".into());
                StatusCode::OK
            }),
        )
        .with_state(seen.clone());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (base, seen)
}

#[tokio::test(flavor = "multi_thread")]
async fn serves_observes_and_shuts_down() {
    let (side, seen) = collector_and_registry().await;
    let telemetry = platform::telemetry::init(
        "runner-test",
        &TelemetryConfig {
            log_format: "json".into(),
            log_level: "info".into(),
            otlp_endpoint: side.clone(),
            trace_sample_ratio: 1.0,
            environment: "test".into(),
            instance: "i1".into(),
        },
    )
    .unwrap();

    let health = Health::new(telemetry.metrics.clone());
    health.check("ok", || async { Ok(()) });
    let flip = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let f2 = flip.clone();
    health.check("flip", move || {
        let ok = f2.load(std::sync::atomic::Ordering::SeqCst);
        async move { if ok { Ok(()) } else { anyhow::bail!("down") } }
    });

    let app = Router::new()
        .route("/ok", get(|| async { with_route("fine".into_response(), "/ok") }))
        .route("/bad", get(|| async { AppError::msg(StatusCode::BAD_REQUEST, "bad $", &["thing"]).into_response() }))
        .route("/boom", get(|| async { AppError::new(StatusCode::BAD_GATEWAY, "upstream").into_response() }))
        .route("/empty", get(|| async { AppError::Empty(StatusCode::NOT_FOUND).into_response() }))
        .route("/internal", get(|| async { AppError::Internal(anyhow::anyhow!("secret detail")).into_response() }))
        .route("/same", get(|| async { not_modified() }))
        .route(
            "/trace",
            get(|| async {
                let mut h = axum::http::HeaderMap::new();
                platform::telemetry::inject_trace_headers(&mut h);
                h.get("traceparent").map(|v| v.to_str().unwrap().to_string()).unwrap_or_default()
            }),
        );

    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let registry = Registry::new(
        &RegistryConfig {
            register: true,
            register_as: "runner".into(),
            zones: vec![format!("{side}/eureka/")],
            instance_ip: "127.0.0.1".into(),
        },
        port,
    )
    .unwrap();
    let service = Service {
        name: "runner-test".into(),
        server: ServerConfig { port, shutdown_grace_seconds: 0 },
        telemetry,
        health,
        registry: Some(registry),
        cors: true,
    };
    let task = tokio::spawn(service.run(app));

    let base = format!("http://127.0.0.1:{port}");
    let http = reqwest::Client::new();
    for _ in 0..100 {
        if http.get(format!("{base}/healthz")).send().await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(tokio::task::spawn_blocking(move || probe(port)).await.unwrap(), "the healthcheck probe sees it ready");

    // Routes and error bodies.
    assert_eq!(http.get(format!("{base}/ok")).send().await.unwrap().text().await.unwrap(), "fine");
    let r = http.get(format!("{base}/bad")).send().await.unwrap();
    assert_eq!(r.status(), 400);
    assert_eq!(r.headers()["x-frame-options"], "DENY", "reactive services' header set by default");
    assert_eq!(r.headers()["referrer-policy"], "no-referrer");
    assert!(r.headers().get("content-security-policy").is_none());
    let v: serde_json::Value = r.json().await.unwrap();
    assert_eq!(v["message"], "bad thing");
    assert_eq!(v["stackTrace"], "");
    assert_eq!(http.get(format!("{base}/boom")).send().await.unwrap().status(), 502);
    let r = http.get(format!("{base}/empty")).send().await.unwrap();
    assert_eq!((r.status().as_u16(), r.headers()["content-length"].to_str().unwrap()), (404, "0"));
    let v: serde_json::Value = http.get(format!("{base}/internal")).send().await.unwrap().json().await.unwrap();
    // A real fault is coded; its cause is in debugMessage, as Java shows it (Kiran, 2026-10-17).
    assert_eq!((v["code"].as_str(), v["debugMessage"].as_str()), (Some("COMMON.INTERNAL_ERROR"), Some("secret detail")));
    let r = http.get(format!("{base}/same")).send().await.unwrap();
    assert_eq!((r.status().as_u16(), r.headers()["x-cache"].to_str().unwrap()), (304, "HIT"));

    // Tracing: an incoming traceparent is continued.
    let tp = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
    let out = http.get(format!("{base}/trace")).header("traceparent", tp).send().await.unwrap().text().await.unwrap();
    assert!(out.starts_with("00-0af7651916cd43dd8448eb211c80319c-"), "{out}");

    // CORS.
    let r = http.get(format!("{base}/ok")).header("origin", "https://other.example").send().await.unwrap();
    assert_eq!(r.headers()["access-control-allow-origin"], "*");
    assert_eq!(r.headers().get_all("vary").iter().count(), 3);
    let r = http.get(format!("{base}/ok")).header("origin", format!("http://127.0.0.1:{port}")).send().await.unwrap();
    assert!(r.headers().get("access-control-allow-origin").is_none(), "same origin is not CORS");
    let r = http
        .request(reqwest::Method::OPTIONS, format!("{base}/ok"))
        .header("origin", "https://other.example")
        .header("access-control-request-method", "PUT")
        .header("access-control-request-headers", "x-a")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["access-control-allow-methods"], "PUT");
    assert_eq!(r.headers()["access-control-allow-headers"], "x-a");
    assert_eq!(r.headers()["access-control-max-age"], "1800");

    // Metrics by route; unmatched paths share one label.
    http.get(format!("{base}/nowhere")).send().await.unwrap();
    let m = http.get(format!("{base}/metrics")).send().await.unwrap().text().await.unwrap();
    assert!(m.contains("route=\"/ok\""));
    assert!(m.contains("route=\"unmatched\""));
    assert!(m.contains("service=\"runner-test\""));
    // The process, the runtime and the build, read at the scrape.
    use platform::meter::sample;
    for name in ["process_resident_memory_bytes", "process_start_time_seconds", "process_cpu_seconds_total", "tokio_runtime_workers", "tokio_runtime_alive_tasks"] {
        assert!(sample(&m, name, &[("service", "runner-test")]).is_some(), "{name} in {m}");
    }
    assert_eq!(sample(&m, "build_info", &[("service", "runner-test"), ("instance", "i1")]), Some(1.0));
    assert!(m.contains("# HELP http_server_request_duration_seconds"));

    // Readiness reflects its checks.
    assert_eq!(http.get(format!("{base}/readyz")).send().await.unwrap().status(), 200);
    flip.store(false, std::sync::atomic::Ordering::SeqCst);
    let r = http.get(format!("{base}/readyz")).send().await.unwrap();
    assert_eq!(r.status(), 503);
    let v: serde_json::Value = r.json().await.unwrap();
    assert_eq!(v["checks"]["flip"], "failed: down");
    assert_eq!(v["checks"]["ok"], "ok");

    // SIGTERM: drain, leave Lighthouse, stop.
    assert!(seen.0.lock().unwrap().contains(&"register".to_string()));
    std::process::Command::new("kill").args(["-TERM", &std::process::id().to_string()]).status().unwrap();
    tokio::time::timeout(Duration::from_secs(20), task).await.expect("stopped in time").unwrap().unwrap();
    assert!(seen.0.lock().unwrap().contains(&"deregister".to_string()));
    assert!(seen.0.lock().unwrap().iter().any(|s| s.starts_with("traces")), "spans flushed on shutdown");
    assert!(!tokio::task::spawn_blocking(move || probe(port)).await.unwrap());
}
