//! What a client URL's hosting reaches outside the unit: the certificate authority and the key
//! and CSR maker of the SSL routes (`ssl.rs`), and Cloudflare for LIVE client URLs (`urls.rs`).
//! security-admin builds it once at startup from its configuration ([`Hosting::from_config`]) and
//! every request shares it, so there is one ACME account connection and one Cloudflare client per
//! process.
//!
//! - `[letsencrypt] credentials` empty: [`Unavailable`], and the routes that would reach the
//!   authority answer 500 `lets_encrypt_credentials` before changing anything.
//! - `[cloudflare] api_token` or `zone_id` empty: an unconfigured [`CustomHostnames`] that
//!   calls nothing.

use std::sync::Arc;

use super::acme::LetsEncrypt;
use super::cloudflare::CustomHostnames;
use super::csr::RsaCsr;
use super::ssl::{Acme, CertCrypto, Ssl, Unavailable};
use crate::config::AuthConfig;

pub struct Hosting {
    pub acme: Arc<dyn Acme>,
    pub crypto: Arc<dyn CertCrypto>,
    pub cloudflare: CustomHostnames,
}

/// No authority, no Cloudflare: what a unit without either section runs with.
impl Default for Hosting {
    fn default() -> Self {
        Self { acme: Arc::new(Unavailable), crypto: Arc::new(RsaCsr), cloudflare: CustomHostnames::unconfigured() }
    }
}

impl Hosting {
    /// From the unit's `[letsencrypt]` and `[cloudflare]` sections. Nothing is contacted here; an
    /// error only for credentials that cannot be read.
    pub fn from_config(cfg: &AuthConfig) -> anyhow::Result<Self> {
        let acme: Arc<dyn Acme> = match LetsEncrypt::from_config(&cfg.letsencrypt)? {
            Some(le) => {
                tracing::info!(directory = le.directory(), "certificates are ordered from this ACME directory");
                Arc::new(le)
            }
            None => {
                tracing::info!("no [letsencrypt] credentials: certificate requests answer lets_encrypt_credentials");
                Arc::new(Unavailable)
            }
        };
        let cloudflare = CustomHostnames::from_config(&cfg.cloudflare);
        if !cloudflare.is_configured() {
            tracing::info!("no [cloudflare] api_token and zone_id: LIVE client URLs are not registered as custom hostnames");
        }
        Ok(Self { acme, crypto: Arc::new(RsaCsr), cloudflare })
    }

    /// What the SSL routes run with.
    pub fn ssl(&self) -> Ssl<'_> {
        Ssl { acme: &*self.acme, crypto: &*self.crypto }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_from_the_settings_or_not() {
        let off = Hosting::from_config(&AuthConfig::default()).unwrap();
        assert!(!off.ssl().acme.configured());
        assert!(!off.cloudflare.is_configured());
        assert!(!Hosting::default().ssl().acme.configured() && !Hosting::default().cloudflare.is_configured());

        let mut cfg = AuthConfig::default();
        let (_, der) = instant_acme::Key::generate_pkcs8().unwrap();
        use base64::Engine;
        let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(der.secret_pkcs8_der());
        cfg.letsencrypt.credentials = serde_json::json!({"id": "https://acme.invalid/acct/1", "key_pkcs8": key}).to_string();
        cfg.cloudflare.api_token = "t".into();
        assert!(!Hosting::from_config(&cfg).unwrap().cloudflare.is_configured(), "a token without a zone is off");
        cfg.cloudflare.zone_id = "z".into();
        cfg.cloudflare.own_domains = vec!["ours.example".into()];
        let on = Hosting::from_config(&cfg).unwrap();
        assert!(on.ssl().acme.configured());
        assert!(on.cloudflare.is_configured());
        assert!(on.cloudflare.is_own_domain("a.ours.example") && !on.cloudflare.is_own_domain("modlix.com"));
        // A real key and CSR whatever the authority.
        assert!(on.ssl().crypto.key_and_csr(&["a.example".into()], None).is_some());

        cfg.letsencrypt.credentials = "{".into();
        assert!(Hosting::from_config(&cfg).is_err());
    }
}
