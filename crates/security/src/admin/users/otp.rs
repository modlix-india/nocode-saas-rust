//! `OtpController`: OTPs sent to an e-mail or a phone (no user), for the URL's client and app,
//! and their verification. Both routes are open to anonymous callers.

use std::sync::Arc;

use axum::routing::post;
use axum::Router;
use serde_json::{Map, Value};

use super::common::{object_body, Fields};
use crate::admin::{Admin, AdminState};
use crate::errors::AuthResult;
use crate::jackson::json;
use crate::model::{App, Client, ContextAuth};
use crate::otp::{OtpPurpose, OtpRequest};
use crate::web::unreadable;

/// `OtpGenerationRequest` / `OtpVerificationRequest` as Jackson reads them.
#[derive(Debug, Clone, Default)]
pub struct OtpBody {
    pub email_id: Option<String>,
    pub phone_number: Option<String>,
    pub purpose: Option<OtpPurpose>,
    pub resend: bool,
    pub otp: Option<String>,
}

impl OtpBody {
    pub fn read(m: &Map<String, Value>) -> AuthResult<Self> {
        let f = Fields(m);
        Ok(OtpBody {
            email_id: f.string("emailId")?,
            phone_number: f.string("phoneNumber")?,
            purpose: match m.get("purpose") {
                None => None,
                Some(v) => OtpPurpose::from_json(v).map_err(|_| unreadable())?,
            },
            resend: f.bool("resend")?,
            otp: f.string("otp")?,
        })
    }

    /// `OtpVerificationRequest.isNotValid`.
    pub fn not_valid(&self) -> bool {
        let blank = |s: &Option<String>| s.as_deref().is_none_or(|v| v.trim().is_empty());
        (blank(&self.otp) && self.purpose.is_none()) || (blank(&self.email_id) && blank(&self.phone_number))
    }
}

fn blank_to_none(s: &Option<String>) -> Option<String> {
    s.clone().filter(|v| !v.trim().is_empty())
}

impl Admin {
    /// `OtpService.getClientAppInheritance(urlClientCode, urlAppCode)`: the URL's client and app
    /// when the app reaches that client; `None` when either is unknown.
    pub async fn url_client_app(&self, ca: &ContextAuth) -> AuthResult<Option<(Arc<Client>, Arc<App>, bool)>> {
        let Some(code) = ca.url_client_code.as_deref() else { return Ok(None) };
        let Some(client) = self.dir().client_by_code(code).await? else { return Ok(None) };
        let Some(app_code) = ca.url_app_code.as_deref() else { return Ok(None) };
        let Some(app) = self.dir().app_by_code(app_code).await? else { return Ok(None) };
        let inherits = match self.app_inheritance(app_code, code, code).await? {
            Some(list) => list.iter().any(|c| c == code),
            None => return Ok(None),
        };
        Ok(Some((client, app, inherits)))
    }

    /// `OtpService.generateOtp`.
    pub async fn generate_otp(&self, ca: &ContextAuth, body: &OtpBody, ip: Option<String>, x_debug: Option<String>) -> AuthResult<bool> {
        let Some((client, app, true)) = self.url_client_app(ca).await? else { return Ok(false) };
        let req = OtpRequest {
            client_id: client.id(),
            client_code: client.code.clone(),
            app_id: app.id,
            app_code: app.app_code.clone(),
            app_name: app.app_name.clone(),
            user_id: ca.authenticated.then(|| ca.user.id()),
            email_id: blank_to_none(&body.email_id),
            phone_number: blank_to_none(&body.phone_number),
            ip_address: ip,
            resend: body.resend,
            x_debug,
            purpose: body.purpose,
            with_user: false,
        };
        self.auth.generate_otp_internal(&req).await
    }

    /// `OtpService.verifyOtp(request)`.
    pub async fn verify_otp_request(&self, ca: &ContextAuth, body: &OtpBody) -> AuthResult<bool> {
        if body.not_valid() {
            return Ok(false);
        }
        let Some((_, app, true)) = self.url_client_app(ca).await? else { return Ok(false) };
        self.auth
            .verify_target_otp(app.id, body.email_id.as_deref(), body.phone_number.as_deref(), body.purpose, body.otp.as_deref())
            .await
    }
}

crate::web_route!(generate, AdminState, "/otp/generate", false, |s, r, ca| {
    let body = OtpBody::read(&object_body(&r.body)?)?;
    Ok(json(&Value::Bool(s.generate_otp(&ca, &body, r.info.remote_host(), r.info.header("x-debug")).await?)))
});

crate::web_route!(verify, AdminState, "/otp/verify", false, |s, r, ca| {
    let body = OtpBody::read(&object_body(&r.body)?)?;
    Ok(json(&Value::Bool(s.verify_otp_request(&ca, &body).await?)))
});

pub fn router() -> Router<AdminState> {
    Router::new().route("/api/security/otp/generate", post(generate)).route("/api/security/otp/verify", post(verify))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn bodies() {
        let b = OtpBody::read(json!({"emailId": "a@b.c", "purpose": "PASSWORD_RESET", "resend": "true", "otp": 1234}).as_object().unwrap()).unwrap();
        assert_eq!((b.purpose, b.resend, b.otp.as_deref()), (Some(OtpPurpose::PasswordReset), true, Some("1234")));
        assert_eq!(OtpBody::read(json!({"purpose": 1}).as_object().unwrap()).unwrap().purpose, Some(OtpPurpose::Login));
        assert!(OtpBody::read(json!({"purpose": "login"}).as_object().unwrap()).is_err());
        assert!(OtpBody::read(json!({"purpose": 9}).as_object().unwrap()).is_err());
        assert!(OtpBody { email_id: Some("a".into()), ..Default::default() }.not_valid());
        assert!(!OtpBody { email_id: Some("a".into()), otp: Some("1".into()), ..Default::default() }.not_valid());
        assert!(OtpBody { otp: Some("1".into()), purpose: Some(OtpPurpose::Login), phone_number: Some(" ".into()), ..Default::default() }.not_valid());
        assert_eq!(blank_to_none(&Some("  ".into())), None);
    }
}
