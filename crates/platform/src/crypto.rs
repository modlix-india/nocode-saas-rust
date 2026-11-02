//! The process-wide rustls crypto provider.
//!
//! The dependency graph enables both of rustls's providers: `ring` (redis, hyper and tokio-rustls)
//! and `aws-lc-rs` (lapin's AMQP over TLS). With both present rustls cannot choose one on its own,
//! and the first TLS client built without an explicit provider panics ("Could not automatically
//! determine the process-level CryptoProvider"). On dev that killed every request that published
//! to RabbitMQ over TLS, a schema save among them; locally RabbitMQ publishing is off, so nothing
//! showed. Every unit installs `ring` before it builds any client.

use std::sync::Once;

static INSTALL: Once = Once::new();

/// Installs `ring` as the process-wide provider, once. Safe to call from every entry point.
pub fn install() {
    INSTALL.call_once(|| {
        // An error means a provider is already installed, which is all this needs.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_client_config_builds_after_install() {
        super::install();
        super::install();
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
        let _ = rustls::ClientConfig::builder().with_root_certificates(rustls::RootCertStore::empty()).with_no_client_auth();
    }
}
