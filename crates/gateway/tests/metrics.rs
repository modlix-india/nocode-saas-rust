//! The resilience metrics on `/metrics`, from a gateway started with `gateway::run` and per-pool
//! overrides in its TOML file.

use std::time::Duration;

use axum::http::StatusCode;
use axum::routing::get;

async fn serve(app: axum::Router) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    base
}

/// The value of the series `name` whose labels include all of `labels` (the exporter adds its
/// own global labels too).
fn value(text: &str, name: &str, labels: &[(&str, &str)]) -> Option<f64> {
    text.lines().find_map(|l| {
        let (series, v) = l.rsplit_once(' ')?;
        let rest = series.strip_prefix(name)?.strip_prefix('{')?;
        labels.iter().all(|(k, val)| rest.contains(&format!("{k}=\"{val}\""))).then(|| v.parse().ok())?
    })
}

#[tokio::test]
async fn resilience_metrics_are_exported() {
    let good = serve(
        axum::Router::new()
            .route(
                "/api/security/clients/internal/getClientNAppCodeNType",
                get(|| async { axum::Json(serde_json::json!(["SYSTEM", "app", "LIVE"])) }),
            )
            .route("/readyz", get(|| async { "ok" }))
            .fallback(|| async { "ok" }),
    )
    .await;
    let failing = serve(axum::Router::new().route("/readyz", get(|| async { "ok" })).fallback(|| async { StatusCode::SERVICE_UNAVAILABLE })).await;
    let failing2 = serve(axum::Router::new().route("/readyz", get(|| async { "ok" })).fallback(|| async { StatusCode::SERVICE_UNAVAILABLE })).await;

    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let dir = std::env::temp_dir().join(format!("gw-metrics-{port}"));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("gateway-rust.toml");
    std::fs::write(
        &file,
        format!(
            r#"[server]
port = {port}
[telemetry]
log_level = "warn"
[security]
upstream = "{good}"

# A refused first instance: one connect retry.
[pools.flaky]
upstreams = ["http://127.0.0.1:1", "{good}"]

# Breaks after two failures and stays open.
[pools.brk]
upstreams = ["{failing}"]
[pools.brk.breaker]
min_requests = 2
open_ms = 60000

# No budget at all: every 5xx retry is refused.
[pools.storm]
upstreams = ["{failing}", "{failing2}"]
[pools.storm.retry]
budget_percent = 0
budget_min_per_second = 0
[pools.storm.breaker]
enabled = false

[[routes]]
id = "flaky"
prefix = "/api/flaky"
pool = "flaky"
[[routes]]
id = "brk"
prefix = "/api/brk"
pool = "brk"
[[routes]]
id = "storm"
prefix = "/api/storm"
pool = "storm"
"#
        ),
    )
    .unwrap();
    std::env::set_var("CONFIG_FILE", &file);
    let task = tokio::spawn(gateway::run());
    let gw = format!("http://127.0.0.1:{port}");
    let mut up = false;
    for _ in 0..100 {
        if reqwest::get(format!("{gw}/healthz")).await.is_ok() {
            up = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(up);

    assert_eq!(reqwest::get(format!("{gw}/api/flaky")).await.unwrap().status(), 200);
    for _ in 0..2 {
        assert_eq!(reqwest::get(format!("{gw}/api/brk")).await.unwrap().status(), 503);
    }
    let r = reqwest::get(format!("{gw}/api/brk")).await.unwrap();
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["code"], "GW.SERVICE_UNAVAILABLE");
    assert_eq!(reqwest::get(format!("{gw}/api/storm")).await.unwrap().status(), 503);

    let text = reqwest::get(format!("{gw}/metrics")).await.unwrap().text().await.unwrap();
    let v = |name: &str, labels: &[(&str, &str)]| {
        value(&text, name, labels).unwrap_or_else(|| panic!("{name} {labels:?} missing from /metrics"))
    };
    let flaky = [("pool", "flaky"), ("reason", "connect")];
    assert_eq!(v("gateway_retries_total", &flaky), 1.0);
    assert_eq!(v("gateway_pool_ejections_total", &flaky), 1.0);
    assert_eq!(v("gateway_pool_breaker_state", &[("pool", "brk")]), 2.0, "open");
    assert_eq!(v("gateway_pool_breaker_state", &[("pool", "flaky")]), 0.0, "closed");
    assert_eq!(v("gateway_pool_breaker_rejections_total", &[("pool", "brk")]), 1.0);
    assert_eq!(v("gateway_retry_budget_exhausted_total", &[("pool", "storm")]), 1.0);
    assert_eq!(v("gateway_retries_total", &[("pool", "storm"), ("reason", "5xx")]), 0.0);
    assert_eq!(v("gateway_pool_ejected_instances", &[("pool", "storm")]), 0.0);
    assert_eq!(v("gateway_pool_ejections_total", &[("pool", "storm"), ("reason", "5xx")]), 0.0);
    assert!(value(&text, "gateway_retries_total", &[("pool", "nope")]).is_none());
    task.abort();
    let _ = std::fs::remove_dir_all(dir);
}
