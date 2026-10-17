//! Users and organisation: `UserController`, `ProfileController`, `RoleV2Controller`, `DesignationController`,
//! `DepartmentController`, `ClientManagerController`, `OtpController`, `AuthorityExpressionController`.

use axum::Router;

use super::AdminState;

pub mod accounts;
pub mod arrangement;
pub mod authority;
pub mod common;
pub mod invites;
pub mod managers;
pub mod org;
pub mod otp;
pub mod passwords;
pub mod profiles;
pub mod registration;
pub mod roles;
#[cfg(test)]
pub(crate) mod testkit;

/// This piece's routes; [`super::router`] merges them.
pub fn router() -> Router<AdminState> {
    Router::new().merge(accounts::router()).merge(org::router()).merge(managers::router()).merge(invites::router()).merge(authority::router()).merge(otp::router()).merge(passwords::router()).merge(roles::router()).merge(profiles::router())
}
