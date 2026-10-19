//! Running a service: the shared layers, the health endpoints, and an orderly shutdown.
//!
//! With a Lighthouse registration ([`Service::run_with`]), once the listener is bound a task
//! waits for the first passing readiness check (the same checks as `/readyz`) and only then
//! registers the instance UP; it keeps renewing, and reports DOWN after three failed checks.
//!
//! Shutdown order on SIGTERM / Ctrl-C:
//! 1. `/readyz` starts failing, so the gateway's health checks take this instance out;
//! 2. the Eureka registration (if any) is withdrawn, for Java callers; the Lighthouse one (if
//!    any) goes OUT_OF_SERVICE, so the gateway drains the instance;
//! 3. requests keep being served for `shutdown_grace_seconds`;
//! 4. the instance is deleted from every Lighthouse;
//! 5. the listener closes, in-flight requests finish, spans are flushed.

use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Result;
use axum::middleware;
use axum::Router;
use lighthouse_client::Registration;
use tokio::sync::watch;

use crate::config::ServerConfig;
use crate::eureka::Eureka;
use crate::health::Health;
use crate::http::{observe, spring_cors};
use crate::telemetry::Telemetry;

pub struct Service {
    pub name: String,
    pub server: ServerConfig,
    pub telemetry: Telemetry,
    pub health: Health,
    /// Registered under `[eureka] register_as` when `[eureka] register` is on.
    pub eureka: Option<Eureka>,
    /// Answer CORS like the Java services (`*`). Off for the gateway, which passes preflights
    /// through to the service that owns the path.
    pub cors: bool,
}

impl Service {
    /// Serves `app` (plus `/healthz`, `/readyz`, `/metrics`) until a shutdown signal.
    pub async fn run(self, app: Router) -> Result<()> {
        self.run_with(app, None).await
    }

    /// Like [`Service::run`], and registered in Lighthouse through `registration` while ready
    /// (see the module documentation). Its grace period is `shutdown_grace_seconds` and its
    /// readiness check is this service's `/readyz` checks.
    pub async fn run_with(self, app: Router, registration: Option<Registration>) -> Result<()> {
        self.serve(app, registration, crate::shutdown_signal()).await
    }

    async fn serve<S>(self, app: Router, registration: Option<Registration>, signal: S) -> Result<()>
    where
        S: Future<Output = ()> + Send + 'static,
    {
        // The message scope sits inside CORS and observation, around every handler, so a coded
        // error anywhere is written in the request's language.
        let mut app = app.merge(self.health.routes()).layer(middleware::from_fn(crate::messages::layer));
        if self.cors {
            app = app.layer(middleware::from_fn(spring_cors));
        }
        let app = app.layer(middleware::from_fn(observe));

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let eureka = self
            .eureka
            .as_ref()
            .filter(|e| e.me().is_some())
            .map(|e| e.spawn_lifecycle(shutdown_rx.clone()));

        let addr = SocketAddr::from(([0, 0, 0, 0], self.server.port));
        let listener = tokio::net::TcpListener::bind(addr).await?;
        tracing::info!(%addr, "listening");

        let health = self.health.clone();
        let grace = Duration::from_secs(self.server.shutdown_grace_seconds);
        // Bound: the registration can now wait for readiness and register.
        let lighthouse = registration.map(|r| {
            let h = self.health.clone();
            r.grace(grace)
                .with_check(move || {
                    let h = h.clone();
                    async move { h.ready().await }
                })
                .spawn(shutdown_rx)
        });
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
            .with_graceful_shutdown(async move {
                signal.await;
                tracing::info!("shutting down: draining");
                let draining_since = tokio::time::Instant::now();
                health.start_draining();
                let _ = shutdown_tx.send(true);
                if let Some(e) = eureka {
                    let _ = e.await;
                }
                // Lighthouse: OUT_OF_SERVICE, the grace period, then the DELETE.
                if let Some(l) = lighthouse {
                    let _ = l.await;
                }
                tokio::time::sleep(grace.saturating_sub(draining_since.elapsed())).await;
            })
            .await?;

        self.telemetry.shutdown();
        Ok(())
    }
}

/// `<binary> healthcheck [port]`: for container health checks in images without curl. Asks this
/// machine's `/readyz` and exits 0 when ready, 1 otherwise. Call first thing in `main`; it
/// returns only when the process was not started as a health check.
pub fn healthcheck_if_asked(default_port: u16) {
    let env_port = std::env::var("MODLIX__SERVER__PORT").ok();
    if let Some(port) = healthcheck_port(std::env::args().skip(1), env_port.as_deref(), default_port) {
        std::process::exit(if probe(port) { 0 } else { 1 });
    }
}

/// The port to probe when the arguments ask for a health check: the argument after
/// `healthcheck`, else the configured port, else the default. `None` for a normal start.
pub fn healthcheck_port(mut args: impl Iterator<Item = String>, env_port: Option<&str>, default_port: u16) -> Option<u16> {
    if args.next().as_deref() != Some("healthcheck") {
        return None;
    }
    Some(
        args.next()
            .and_then(|p| p.parse().ok())
            .or_else(|| env_port.and_then(|p| p.parse().ok()))
            .unwrap_or(default_port),
    )
}

/// Whether `127.0.0.1:<port>/readyz` answers 200 (what `healthcheck` exits on).
pub fn probe(port: u16) -> bool {
    use std::io::{Read, Write};
    let Ok(mut s) = std::net::TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_secs(2),
    ) else {
        return false;
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
    if s
        .write_all(b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut buf = [0u8; 16];
    matches!(s.read(&mut buf), Ok(n) if n >= 12 && &buf[9..12] == b"200")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> impl Iterator<Item = String> {
        a.iter().map(|s| s.to_string()).collect::<Vec<_>>().into_iter()
    }

    #[test]
    fn healthcheck_arguments() {
        assert_eq!(healthcheck_port(args(&[]), None, 1), None);
        assert_eq!(healthcheck_port(args(&["serve"]), None, 1), None);
        assert_eq!(healthcheck_port(args(&["healthcheck"]), None, 1), Some(1));
        assert_eq!(healthcheck_port(args(&["healthcheck"]), Some("9"), 1), Some(9));
        assert_eq!(healthcheck_port(args(&["healthcheck", "7"]), Some("9"), 1), Some(7));
        assert_eq!(healthcheck_port(args(&["healthcheck", "x"]), Some("y"), 1), Some(1));
        // The test binary is not started as a health check: this returns.
        healthcheck_if_asked(1);
    }

    /// The Lighthouse hook: nothing is registered before readiness passes; shutdown drains,
    /// goes OUT_OF_SERVICE, waits the grace period, then deletes. The only test in this binary
    /// that sets up telemetry (its metrics recorder is process-wide).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn registers_in_lighthouse_once_ready_and_leaves_in_order() {
        use std::collections::HashMap;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Mutex};
        use std::time::Instant;

        use axum::extract::{Query, State};
        use axum::http::StatusCode;
        use axum::routing::{post, put};

        use crate::config::{ServerConfig, TelemetryConfig};
        use crate::health::Health;

        type Calls = Arc<Mutex<Vec<(String, Instant)>>>;
        fn log(c: &Calls, what: String) -> StatusCode {
            c.lock().unwrap().push((what, Instant::now()));
            StatusCode::OK
        }
        let calls: Calls = Arc::default();
        let fake = Router::new()
            .route(
                "/eureka/apps/{app}",
                post(|State(c): State<Calls>, body: String| async move {
                    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
                    log(&c, format!("register {}", v["instance"]["status"].as_str().unwrap()));
                    StatusCode::NO_CONTENT
                }),
            )
            .route(
                "/eureka/apps/{app}/{id}",
                put(|State(c): State<Calls>| async move { log(&c, "heartbeat".into()) })
                    .delete(|State(c): State<Calls>| async move { log(&c, "delete".into()) }),
            )
            .route(
                "/eureka/apps/{app}/{id}/status",
                put(|State(c): State<Calls>, Query(q): Query<HashMap<String, String>>| async move {
                    log(&c, format!("status {}", q["value"]))
                }),
            )
            .with_state(calls.clone());
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let lighthouse = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, fake).await.unwrap() });
        let names = |c: &Calls| c.lock().unwrap().iter().map(|(n, _)| n.clone()).collect::<Vec<_>>();

        let telemetry = crate::telemetry::init("app-test", &TelemetryConfig::default()).unwrap();
        let health = Health::new(telemetry.metrics.clone());
        let ready = Arc::new(AtomicBool::new(false));
        let r2 = ready.clone();
        health.check("flip", move || {
            let ok = r2.load(Ordering::SeqCst);
            async move {
                if ok {
                    Ok(())
                } else {
                    anyhow::bail!("not yet")
                }
            }
        });
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let service = Service {
            name: "app-test".into(),
            server: ServerConfig { port, shutdown_grace_seconds: 1 },
            telemetry,
            health,
            eureka: None,
            cors: false,
        };
        let registration = lighthouse_client::registration("app-test", port, "/readyz")
            .servers([lighthouse.as_str()])
            .ip("127.0.0.1")
            .lease(Duration::from_millis(50), Duration::from_secs(1))
            .ready_poll(Duration::from_millis(20));
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(service.serve(Router::new(), Some(registration), async move {
            let _ = stopped.await;
        }));

        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(names(&calls).is_empty(), "nothing before the first readiness pass");
        ready.store(true, Ordering::SeqCst);
        for _ in 0..200 {
            if names(&calls).iter().any(|n| n == "heartbeat") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(names(&calls)[0], "register UP");
        assert!(names(&calls).iter().any(|n| n == "heartbeat"));

        stop.send(()).unwrap();
        for _ in 0..200 {
            if names(&calls).iter().any(|n| n == "status OUT_OF_SERVICE") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let http = reqwest::Client::new();
        let r = http.get(format!("http://127.0.0.1:{port}/readyz")).send().await.unwrap();
        assert_eq!(r.status(), 503, "draining, still serving during the grace period");
        tokio::time::timeout(Duration::from_secs(10), task).await.unwrap().unwrap().unwrap();
        let c = calls.lock().unwrap().clone();
        let n = c.len();
        assert_eq!((c[n - 2].0.as_str(), c[n - 1].0.as_str()), ("status OUT_OF_SERVICE", "delete"));
        assert!(c[n - 1].1 - c[n - 2].1 >= Duration::from_millis(900), "the grace period sits between them");
    }

    #[test]
    fn probe_of_a_closed_port_or_a_non_200() {
        assert!(!probe(1));
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            if let Ok((mut s, _)) = l.accept() {
                let mut b = [0u8; 256];
                let _ = s.read(&mut b);
                let _ = s.write_all(b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\n\r\n");
            }
        });
        assert!(!probe(port));
    }
}
