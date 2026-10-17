//! Ported from security `OtpServiceTest` (the sign-in half: `generateOtpInternal`,
//! `verifyOtpInternal` with a user) and `OneTimeTokenServiceTest`. The e-mail/phone-only
//! `verifyOtpInternal` belongs to `OtpController`, which stays in Java.

mod common;

use std::sync::Arc;

use common::*;
use security::otp::OtpRequest;
use security::store::{NewOneTimeToken, Store};

fn request(user: Option<u64>, email: Option<&str>) -> OtpRequest {
    OtpRequest {
        client_id: 2,
        client_code: Some("BUS".into()),
        app_id: 2,
        app_code: "crm".into(),
        app_name: Some("crm app".into()),
        user_id: user,
        email_id: email.map(str::to_string),
        phone_number: None,
        ip_address: Some("10.0.0.1".into()),
        resend: false,
        x_debug: None,
        purpose: Some(security::otp::OtpPurpose::Login),
        with_user: user.is_some(),
    }
}

#[tokio::test]
async fn generate_otp_internal_valid_user_sends_message_and_publishes_event() {
    let h = harness();
    assert!(h.auth.generate_otp_internal(&request(Some(11), Some("m@example.com"))).await.unwrap());
    let e = h.events.events.lock().unwrap()[0].clone();
    let keys: Vec<&str> = e.data.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(keys, vec!["appName", "email", "otp", "otpPurpose", "expireInterval"]);
    assert_eq!(e.data[3].1, "LOGIN");
    assert_eq!(e.data[4].1, 5);
    assert_eq!(h.store.called("insert_otp"), 1);
}

#[tokio::test]
async fn generate_otp_internal_no_email_returns_false() {
    let h = harness();
    assert!(!h.auth.generate_otp_internal(&request(Some(11), None)).await.unwrap());
    assert!(!h.auth.generate_otp_internal(&request(Some(11), Some(" "))).await.unwrap());
    assert_eq!(h.store.called("insert_otp"), 0);
}

#[tokio::test]
async fn generate_otp_internal_unknown_app_returns_false() {
    let h = harness();
    let r = OtpRequest { app_code: "nope".into(), ..request(Some(11), Some("m@example.com")) };
    assert!(!h.auth.generate_otp_internal(&r).await.unwrap());
}

#[tokio::test]
async fn generate_otp_internal_resend_with_user_increases_resend_attempt() {
    let h = harness();
    let r = OtpRequest { resend: true, ..request(Some(11), Some("m@example.com")) };
    assert!(h.auth.generate_otp_internal(&r).await.unwrap());
    assert_eq!(h.store.called("increase_resend_attempts"), 1);
    // Without a user there is nobody to count against.
    let r = OtpRequest { resend: true, ..request(None, Some("m@example.com")) };
    assert!(h.auth.generate_otp_internal(&r).await.unwrap());
    assert_eq!(h.store.called("increase_resend_attempts"), 1);
}

#[tokio::test]
async fn generate_otp_internal_event_failure_is_an_error() {
    let mut h = harness();
    let events = Arc::new(RecordingEvents { fail: true, ..Default::default() });
    let auth = Arc::get_mut(&mut h.auth).unwrap();
    auth.events = events;
    assert!(h.auth.generate_otp_internal(&request(Some(11), Some("m@example.com"))).await.is_err());
}

#[tokio::test]
async fn verify_otp_internal_with_user_finds_by_user_id_and_rejects_wrong_ones() {
    let h = harness();
    assert!(h.auth.generate_otp_internal(&request(Some(11), Some("m@example.com"))).await.unwrap());
    let otp = h.events.events.lock().unwrap()[0].data[2].1.as_str().unwrap().to_string();
    assert!(!h.auth.verify_otp(Some("crm"), 11, "0000x").await.unwrap(), "wrong code");
    assert!(!h.auth.verify_otp(Some(""), 11, &otp).await.unwrap(), "blank app code");
    assert!(h.auth.verify_otp(Some("crm"), 11, &otp).await.unwrap());
    assert!(!h.auth.verify_otp(Some("crm"), 11, &otp).await.unwrap(), "deleted once used");
}

#[tokio::test]
async fn verify_otp_expired_otp_returns_false() {
    let later = security::clock::Clock::fixed(clock().instant() + chrono::Duration::minutes(6), 19_800);
    let h = harness();
    assert!(h.auth.generate_otp_internal(&request(Some(11), Some("m@example.com"))).await.unwrap());
    let otp = h.events.events.lock().unwrap()[0].data[2].1.as_str().unwrap().to_string();
    let h2 = harness_with(seed(), later, settings());
    h2.store.with(|d| d.otps = h.store.with(|o| o.otps.clone()));
    assert!(!h2.auth.verify_otp(Some("crm"), 11, &otp).await.unwrap());
}

#[tokio::test]
async fn one_time_token_create_generates_uuid_token_without_dashes() {
    // OneTimeTokenServiceTest.create_GeneratesUUIDToken / create_TokenHasNoDashes
    let a = security::signin::random_uuid_hex();
    let b = security::signin::random_uuid_hex();
    assert_ne!(a, b);
    assert_eq!(a.len(), 32);
    assert!(!a.contains('-'));
    assert!(matches!(&a[16..17], "8" | "9" | "a" | "b"), "the RFC 4122 variant");
}

#[tokio::test]
async fn get_one_time_token_reads_and_deletes_and_unknown_is_empty() {
    let h = harness();
    h.store.insert_one_time_token(&NewOneTimeToken { user_id: 142, token: "abc".into(), ..Default::default() }).await.unwrap();
    let row = h.store.redeem_one_time_token("abc", 5).await.unwrap().unwrap();
    assert_eq!((row.user_id, row.auth_mode.as_deref(), row.remember_me), (142, Some("BEARER"), false));
    assert!(h.store.redeem_one_time_token("abc", 5).await.unwrap().is_none());
    assert!(h.store.redeem_one_time_token("never", 5).await.unwrap().is_none());
}
