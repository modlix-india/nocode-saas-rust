//! Running a service: the shared layers, the health endpoints, and an orderly shutdown.
//!
//! Shutdown order on SIGTERM / Ctrl-C:
//! 1. `/readyz` starts failing, so the gateway's health checks take this instance out;
//! 2. the Eureka registration (if any) is withdrawn, for Java callers;
//! 3. requests keep being served for `shutdown_grace_seconds`;
//! 4. the listener closes, in-flight requests finish, spans are flushed.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Result;
use axum::middleware;
use axum::Router;
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
        // The message scope sits inside CORS and observation, around every handler, so a coded
        // error anywhere is written in the request's language.
        let mut app = app.merge(self.health.routes()).layer(middleware::from_fn(crate::messages::layer));
        if self.cors {
            app = app.layer(middleware::from_fn(spring_cors));
        }
        let app = app.layer(middleware::from_fn(observe));

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let registration = self
            .eureka
            .as_ref()
            .filter(|e| e.me().is_some())
            .map(|e| e.spawn_lifecycle(shutdown_rx));

        let addr = SocketAddr::from(([0, 0, 0, 0], self.server.port));
        let listener = tokio::net::TcpListener::bind(addr).await?;
        tracing::info!(%addr, service = self.name, "listening");

        let health = self.health.clone();
        let grace = Duration::from_secs(self.server.shutdown_grace_seconds);
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
            .with_graceful_shutdown(async move {
                crate::shutdown_signal().await;
                tracing::info!("shutting down: draining");
                health.start_draining();
                let _ = shutdown_tx.send(true);
                if let Some(r) = registration {
                    let _ = r.await;
                }
                tokio::time::sleep(grace).await;
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
