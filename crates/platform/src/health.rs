//! `/healthz`, `/readyz` and `/metrics`.
//!
//! - `/healthz`: the process is alive. No dependency is checked, so a database outage never
//!   gets every instance restarted at once.
//! - `/readyz`: this instance should get traffic. Runs every registered check (database, redis,
//!   ...) with a short timeout, and fails as soon as shutdown begins so a load balancer drains
//!   the instance before it stops.
//! - `/metrics`: Prometheus text, the scrape-time gauges read first ([`crate::meter::collect`]).

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use metrics_exporter_prometheus::PrometheusHandle;
use serde_json::{json, Map, Value};

type Check = Arc<dyn Fn() -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>> + Send + Sync>;

#[derive(Clone)]
pub struct Health {
    inner: Arc<Inner>,
}

struct Inner {
    checks: std::sync::RwLock<Vec<(String, Check)>>,
    draining: AtomicBool,
    metrics: PrometheusHandle,
}

impl Health {
    pub fn new(metrics: PrometheusHandle) -> Self {
        Self {
            inner: Arc::new(Inner {
                checks: std::sync::RwLock::new(Vec::new()),
                draining: AtomicBool::new(false),
                metrics,
            }),
        }
    }

    /// Adds a readiness check.
    pub fn check<F, Fut>(&self, name: &str, f: F)
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        let f = Arc::new(f);
        let check: Check = Arc::new(move || {
            let f = f.clone();
            Box::pin(async move { f().await })
        });
        self.inner
            .checks
            .write()
            .expect("health checks poisoned")
            .push((name.to_string(), check));
    }

    /// From now on `/readyz` fails, so load balancers stop sending new requests.
    pub fn start_draining(&self) {
        self.inner.draining.store(true, Ordering::SeqCst);
    }

    pub fn is_draining(&self) -> bool {
        self.inner.draining.load(Ordering::SeqCst)
    }

    /// What `/readyz` answers, for callers in this process (the Lighthouse registration waits
    /// for it): not draining, and every check passing within its 2 seconds.
    pub async fn ready(&self) -> bool {
        !self.is_draining() && self.run_checks().await.0
    }

    /// Runs every check; whether all passed, and each one's outcome.
    async fn run_checks(&self) -> (bool, Map<String, Value>) {
        let checks: Vec<(String, Check)> = self.inner.checks.read().expect("health checks poisoned").clone();
        let mut details = Map::new();
        let mut ok = true;
        for (name, check) in checks {
            let result = tokio::time::timeout(Duration::from_secs(2), check()).await;
            let v = match result {
                Ok(Ok(())) => json!("ok"),
                Ok(Err(e)) => {
                    ok = false;
                    json!(format!("failed: {e}"))
                }
                Err(_) => {
                    ok = false;
                    json!("timed out")
                }
            };
            details.insert(name, v);
        }
        (ok, details)
    }

    pub fn routes(&self) -> Router {
        async fn healthz() -> impl IntoResponse {
            (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], r#"{"status":"ok"}"#)
        }

        async fn readyz(State(h): State<Health>) -> impl IntoResponse {
            if h.is_draining() {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    [(header::CONTENT_TYPE, "application/json")],
                    r#"{"status":"draining"}"#.to_string(),
                );
            }
            let (ok, details) = h.run_checks().await;
            let body = json!({"status": if ok { "ok" } else { "unavailable" }, "checks": Value::Object(details)});
            (
                if ok { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE },
                [(header::CONTENT_TYPE, "application/json")],
                body.to_string(),
            )
        }

        async fn metrics(State(h): State<Health>) -> impl IntoResponse {
            crate::meter::collect();
            (
                [(header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
                h.inner.metrics.render(),
            )
        }

        Router::new()
            .route("/healthz", get(healthz))
            .route("/readyz", get(readyz))
            .route("/metrics", get(metrics))
            .with_state(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use tower::ServiceExt;

    #[tokio::test]
    async fn slow_checks_time_out_and_draining_fails_readiness() {
        let handle = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder().handle();
        let h = Health::new(handle);
        h.check("slow", || async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            Ok(())
        });
        let app = h.routes();
        let resp = app.clone().oneshot(Request::get("/readyz").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains("timed out"));

        h.start_draining();
        let resp = app.clone().oneshot(Request::get("/readyz").body(Body::empty()).unwrap()).await.unwrap();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], br#"{"status":"draining"}"#);
        let resp = app.oneshot(Request::get("/healthz").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "alive while draining");
    }

    #[tokio::test]
    async fn ready_follows_the_checks_and_draining() {
        let handle = || metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder().handle();
        let h = Health::new(handle());
        assert!(h.ready().await, "no checks: ready");
        h.check("ok", || async { Ok(()) });
        assert!(h.ready().await);
        h.check("down", || async { anyhow::bail!("database unreachable") });
        assert!(!h.ready().await);
        let h = Health::new(handle());
        h.start_draining();
        assert!(h.is_draining() && !h.ready().await);
    }
}
