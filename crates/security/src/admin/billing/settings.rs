//! The `[billing]` section of security-admin's configuration, read beside the unit's own
//! (`crate::config::AuthConfig` ignores the section; this reads only it):
//!
//! ```toml
//! [billing]
//! # Answer `POST wallets/{walletId}/adjust` (an owner's credit or debit of a managed client's
//! # wallet). Off by default: Java cannot convert the id, so the route only ever answers
//! # "Type mismatch.", and this unit answers the same.
//! serve_wallet_adjust = false
//! # Where the Razorpay calls of a purchase go. Razorpay's own API by default; the local stack
//! # points it at a closed port so no local run can reach Razorpay.
//! razorpay_base_url = "https://api.razorpay.com/v1"
//! ```
//!
//! Both can also come from `MODLIX__BILLING__SERVE_WALLET_ADJUST` and
//! `MODLIX__BILLING__RAZORPAY_BASE_URL`.

use serde::{Deserialize, Serialize};

use super::service::RAZORPAY_BASE_URL;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BillingSettings {
    /// Serve `wallets/{walletId}/adjust`; off answers as Java does ("Type mismatch.").
    pub serve_wallet_adjust: bool,
    /// The Razorpay API base, without a trailing `/`.
    pub razorpay_base_url: String,
}

impl Default for BillingSettings {
    fn default() -> Self {
        Self { serve_wallet_adjust: false, razorpay_base_url: RAZORPAY_BASE_URL.to_string() }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct File {
    billing: BillingSettings,
}

impl BillingSettings {
    /// The section from `config/<service>.toml` and the environment; the defaults when it is
    /// absent. A section that does not read is logged and the safe defaults are used.
    pub fn load(service: &str) -> Self {
        match platform::config::load::<File>(service) {
            Ok(f) => f.billing.normalised(),
            Err(e) => {
                tracing::error!(error = %e, "the [billing] configuration does not read; using its defaults");
                Self::default()
            }
        }
    }

    fn normalised(mut self) -> Self {
        let trimmed = self.razorpay_base_url.trim().trim_end_matches('/');
        self.razorpay_base_url = if trimmed.is_empty() { RAZORPAY_BASE_URL.to_string() } else { trimmed.to_string() };
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_off_and_razorpay() {
        let s = BillingSettings::default();
        assert!(!s.serve_wallet_adjust);
        assert_eq!(s.razorpay_base_url, "https://api.razorpay.com/v1");
        let s = BillingSettings { razorpay_base_url: " http://127.0.0.1:9/stub/ ".into(), serve_wallet_adjust: true }.normalised();
        assert_eq!(s.razorpay_base_url, "http://127.0.0.1:9/stub");
        assert_eq!(BillingSettings { razorpay_base_url: " ".into(), ..Default::default() }.normalised().razorpay_base_url, RAZORPAY_BASE_URL);
    }

    #[test]
    fn loads_the_section_and_the_environment() {
        figment::Jail::expect_with(|jail| {
            jail.create_dir("config")?;
            jail.create_file("config/billing-test.toml", "[server]\nport = 1\n[billing]\nserve_wallet_adjust = true\n")?;
            jail.set_env("MODLIX__BILLING__RAZORPAY_BASE_URL", "http://127.0.0.1:9");
            let s = BillingSettings::load("billing-test");
            assert_eq!(s, BillingSettings { serve_wallet_adjust: true, razorpay_base_url: "http://127.0.0.1:9".into() });
            jail.set_env("MODLIX__BILLING__SERVE_WALLET_ADJUST", "not-a-bool");
            assert_eq!(BillingSettings::load("billing-test"), BillingSettings::default());
            Ok(())
        });
        assert_eq!(BillingSettings::load("no-such-unit"), BillingSettings::default());
    }
}
