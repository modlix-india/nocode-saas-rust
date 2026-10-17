//! Clients, apps and hosting: `ClientController`, `AppController` and app CRUD, `AppRegistrationController` and the
//! registration integrations, `ClientUrlController`, `SSLCertificateController`, the client policy
//! controllers, `ClientActivityController`, `TransportController`.
//!
//! The services are free functions over [`AdminState`] in the submodules; the DTOs this piece
//! reads and writes whole are described once each as an [`entity::Entity`] (jOOQ's record and
//! POJO round trip, Jackson's property order).

pub mod activities;
pub mod app_reg;
pub mod app_routes;
pub mod apps;
pub mod client_admin;
pub mod cloudflare;
pub mod common;
pub mod dao;
pub mod entity;
pub mod integrations;
#[cfg(test)]
mod live_tests;
pub mod policies;
pub mod register;
pub mod registration;
pub mod ssl;
#[cfg(test)]
pub mod testlive;
pub mod urls;
pub mod x509;

use axum::Router;

use super::AdminState;

/// This piece's routes; [`super::router`] merges them.
pub fn router() -> Router<AdminState> {
    Router::new().merge(policies::router()).merge(activities::router()).merge(client_admin::router()).merge(urls::router())
        .merge(app_routes::router())
        .merge(app_reg::router())
        .merge(integrations::router())
        .merge(ssl::router())
        .merge(registration::router())
        .merge(register::router())
}
