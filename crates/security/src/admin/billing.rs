//! Billing: billing bundles, billing configs, billing profile, bundle purchase (with the Razorpay
//! webhook), invoices, wallets (piece 3 of security-admin, see SPLIT.md).
//!
//! - [`configs`]: `AppBillingConfigService`, `AppBillingBundleService`;
//! - [`invoices`]: `InvoiceService`, `BillingProfileService`;
//! - [`purchase`]: `BundlePurchaseService`, `RazorpayPaymentService` (quote, order, webhook);
//! - [`wallets`]: `WalletService`'s owner views, credits and adjustments;
//! - [`service`]: the [`service::Billing`] context they share and the calls that leave the
//!   process; [`body`]: Jackson's reading of the request bodies; [`money`]: `BigDecimal`;
//!   [`settings`]: the `[billing]` configuration section.
//!
//! The tables are `crate::data::billing_admin`; the debits and the gates security-internal
//! serves stay in `crate::internal::billing`.

pub mod body;
pub mod configs;
pub mod invoices;
pub mod money;
pub mod purchase;
mod routes;
pub mod service;
pub mod settings;
pub mod wallets;

use axum::Router;

use super::AdminState;

/// This piece's routes, with the `[billing]` section of security-admin's configuration;
/// [`super::router`] merges them.
pub fn router() -> Router<AdminState> {
    router_with(settings::BillingSettings::load(super::NAME))
}

/// The routes with the given settings.
pub fn router_with(settings: settings::BillingSettings) -> Router<AdminState> {
    routes::router(std::sync::Arc::new(settings))
}
