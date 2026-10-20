//! What every Modlix Rust service shares: configuration, telemetry, health, the HTTP behaviour
//! callers depend on, the caller's identity from security, cache eviction, and the few
//! compatibility pieces (Lighthouse, Java hashing) the migration window needs.

pub mod app;
pub mod cache;
pub mod config;
pub mod crypto;
pub mod db;
pub mod error;
pub mod registry;
pub mod health;
pub mod http;
pub mod java;
pub mod messages;
pub mod meter;
pub mod security;
pub mod telemetry;
pub mod upstream;

/// A future that resolves on SIGINT or SIGTERM (what `docker stop` sends).
pub async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {}
        _ = term => {}
    }
}
