//! Ported from security `AuthenticationServiceTest` (Mockito DAOs there, the in-memory store
//! here) and the service-level scenarios of `AuthenticationIntegrationTest`. Test names keep the
//! Java ones, in snake case, grouped as the Java `@Nested` classes are.

mod common;

use std::sync::Arc;

use axum::http::{HeaderValue, StatusCode};
use common::*;
use security::caches;
use security::errors::AuthError;
use security::jwt;
use security::model::{ContextAuth, PassType, Policy};
use security::signin::AuthRequest;
use security::store::StateRow;

fn pw(name: &str, password: &str) -> AuthRequest {
    AuthRequest { user_name: Some(name.into()), password: Some(password.into()), ..Default::default() }
}

fn status(e: &AuthError) -> StatusCode {
    e.status()
}

async fn sign_in(h: &Harness, r: &security::request::RequestInfo, body: &AuthRequest) -> String {
    h.auth.authenticate(body, r, 0).await.unwrap().response.access_token.unwrap()
}

mod revoke_tests {
    use super::*;

    #[tokio::test]
    async fn revoke_null_token_returns_1() {
        let h = harness();
        h.auth.revoke(false, &sys_req("appbuilder"), &ContextAuth::default()).await.unwrap();
        assert_eq!(h.store.called("tokens_by_part"), 0);
    }

    #[tokio::test]
    async fn revoke_bearer_token_evicts_cache_and_deletes_from_db() {
        let h = harness();
        let r = sys_req("appbuilder");
        let token = sign_in(&h, &r, &pw("kirangrandhi", "Pass@1234")).await;
        let signed = with_bearer(&r, &token);
        let ca = h.auth.context(&signed).await.unwrap();
        assert!(ca.authenticated);
        assert!(h.auth.dir.caches.tokens.get(caches::TOKEN, &token).await.is_some());
        h.auth.revoke(false, &signed, &ca).await.unwrap();
        assert!(h.auth.dir.caches.tokens.get(caches::TOKEN, &token).await.is_none());
        assert!(h.store.with(|d| d.tokens.is_empty()));
        assert!(!h.auth.context(&signed).await.unwrap().authenticated);
    }

    #[tokio::test]
    async fn revoke_basic_auth_prefix_strips_prefix() {
        let h = harness();
        let r = req(&[("authorization", "Basic  abc ")]);
        h.auth.revoke(false, &r, &ContextAuth::default()).await.unwrap();
        assert_eq!(h.store.called("tokens_by_part"), 1);
    }

    #[tokio::test]
    async fn revoke_sso_logout_true_calls_sso_revoke() {
        let h = harness();
        let r = sys_req("appbuilder");
        let a = sign_in(&h, &r, &pw("kirangrandhi", "Pass@1234")).await;
        let _b = sign_in(&h, &r, &pw("kirangrandhi", "Pass@1234")).await;
        let signed = with_bearer(&r, &a);
        let ca = h.auth.context(&signed).await.unwrap();
        h.auth.revoke(true, &signed, &ca).await.unwrap();
        assert!(h.store.with(|d| d.tokens.iter().all(|t| t.user_id != 142)));
        assert_eq!(h.store.called("delete_tokens_of_user"), 1);
    }

    #[tokio::test]
    async fn revoke_cookie_token_extracts_from_cookie() {
        let h = harness();
        let r = sys_req("appbuilder");
        let token = sign_in(&h, &r, &pw("kirangrandhi", "Pass@1234")).await;
        let mut c = r.clone();
        c.headers.insert("cookie", HeaderValue::from_str(&format!("x=1; Authorization={token}")).unwrap());
        h.auth.revoke(false, &c, &ContextAuth::default()).await.unwrap();
        assert!(h.store.with(|d| d.tokens.is_empty()));
    }

    #[tokio::test]
    async fn revoke_matching_token_in_db_deletes_token_and_non_matching_is_kept() {
        let h = harness();
        let r = sys_req("appbuilder");
        let token = sign_in(&h, &r, &pw("kirangrandhi", "Pass@1234")).await;
        // Same indexed tail, different token: PART_TOKEN is case-insensitive in MySQL.
        let twin = format!("X{}", &token[1..]);
        h.store.with(|d| {
            let mut t = d.tokens[0].clone();
            t.id = 77;
            t.token = twin.clone();
            d.tokens.push(t);
        });
        h.auth.revoke(false, &with_bearer(&r, &token), &ContextAuth::default()).await.unwrap();
        assert_eq!(h.store.with(|d| d.tokens.iter().map(|t| t.id).collect::<Vec<_>>()), vec![77]);
    }

    #[tokio::test]
    async fn revoke_deletes_every_row_with_the_token_lower_case_bearer_prefix() {
        let h = harness();
        let r = sys_req("appbuilder");
        let token = sign_in(&h, &r, &pw("kirangrandhi", "Pass@1234")).await;
        h.store.with(|d| {
            let mut t = d.tokens[0].clone();
            t.id = 78;
            d.tokens.push(t);
        });
        let mut lower = r.clone();
        lower.headers.insert("authorization", HeaderValue::from_str(&format!("bearer {token}")).unwrap());
        h.auth.revoke(false, &lower, &ContextAuth::default()).await.unwrap();
        assert!(h.store.with(|d| d.tokens.is_empty()));
    }

    #[tokio::test]
    async fn revoke_sso_logout_with_no_tokens_completes() {
        let h = harness();
        h.auth.revoke(true, &req(&[("authorization", "Bearer x")]), &ContextAuth::default()).await.unwrap();
        assert_eq!(h.store.called("delete_tokens_of_user"), 1);
    }

    #[tokio::test]
    async fn revoke_store_failure_is_an_error() {
        let h = harness();
        h.store.with(|d| d.fail.insert("tokens_by_part"));
        let e = h.auth.revoke(false, &req(&[("authorization", "Bearer x")]), &ContextAuth::default()).await.unwrap_err();
        assert_eq!(status(&e), StatusCode::INTERNAL_SERVER_ERROR);
    }
}

mod authenticate_tests {
    use super::*;

    #[tokio::test]
    async fn authenticate_null_password_type_throws_bad_request() {
        let h = harness();
        let e = h.auth.authenticate(&AuthRequest { user_name: Some("x".into()), ..Default::default() }, &sys_req("appbuilder"), 0).await.unwrap_err();
        assert_eq!((status(&e), e.message()), (StatusCode::BAD_REQUEST, "Internal Server Error (Unknown)".to_string()));
    }

    #[tokio::test]
    async fn authenticate_happy_path_password_returns_token_response() {
        let h = harness();
        let m = h.auth.authenticate(&pw("kirangrandhi", "Pass@1234"), &sys_req("appbuilder"), 0).await.unwrap();
        let r = &m.response;
        assert_eq!(r.verified_app_code.as_deref(), Some("appbuilder"));
        assert_eq!((r.logged_in_client_code.as_deref(), r.logged_in_client_id), (Some("SYSTEM"), Some(1)));
        assert_eq!((r.managed_client_id, r.managed_client_code.clone()), (None, None));
        assert_eq!(r.client.code(), "SYSTEM");
        assert_eq!(
            r.user.string_authorities.clone().unwrap(),
            vec![
                "Authorities.ROLE_Owner",
                "Authorities.ROLE_Page_Manager",
                "Authorities.ROLE_Page_READ",
                "Authorities.Page_READ",
                "Authorities.APPBUILDER.PROFILE_Appbuilder_Owner",
                "Authorities.Logged_IN"
            ]
        );
        // SYSTEM's tokens last 60 minutes; the expiry is the UTC wall time.
        assert_eq!(r.access_token_expiry_at, Some(clock().instant().timestamp() + 3600));
        let c = jwt::parse(KEY, r.access_token.as_deref().unwrap(), clock().millis()).unwrap();
        assert_eq!((c.user_id, c.host_name.as_deref(), c.port.as_deref()), (142, Some("apps.local"), Some("443")));
        assert_eq!((c.logged_in_client_id, c.app_code.as_deref(), c.one_time), (1, Some("appbuilder"), false));
        assert!(m.cookie.is_none());
        let row = h.store.with(|d| d.tokens[0].clone());
        assert_eq!((row.user_id, row.created_by, row.ip.as_deref()), (142, Some(0), Some("10.1.2.3")));
        assert_eq!(row.part.len(), 50);
        settle().await;
        assert!(h.store.with(|d| d.sox.iter().any(|s| s == &(142, "LOGIN".into(), "Successful".into()))));
    }

    #[tokio::test]
    async fn authenticate_business_client_has_its_managing_client() {
        let h = harness();
        let m = h.auth.authenticate(&pw("member", "memberpw"), &bus_req("crm"), 0).await.unwrap();
        assert_eq!((m.response.managed_client_id, m.response.managed_client_code.as_deref()), (Some(1), Some("SYSTEM")));
        assert_eq!(m.response.access_token_expiry_at, Some(clock().instant().timestamp() + 1800));
        // No profile assigned in crm: the app's default profile applies.
        assert_eq!(
            m.response.user.string_authorities.unwrap(),
            vec!["Authorities.CRM.ROLE_Lead_Viewer", "Authorities.CRM.Lead_READ", "Authorities.CRM.PROFILE_Crm_Member", "Authorities.Logged_IN"]
        );
    }

    #[tokio::test]
    async fn authenticate_invalid_password_increases_failed_attempt() {
        let h = harness();
        let e = h.auth.authenticate(&pw("member", "nope"), &bus_req("crm"), 0).await.unwrap_err();
        assert_eq!((status(&e), e.message()), (StatusCode::FORBIDDEN, "Wrong Password, 2 attempt remaining.".to_string()));
        assert_eq!(h.store.user(11).no_failed_attempt, Some(1));
        settle().await;
        assert!(h.store.with(|d| d.sox.iter().any(|s| s.1 == "UPDATE")));
    }

    #[tokio::test]
    async fn authenticate_wrong_password_three_times_then_locked() {
        // AuthenticationIntegrationTest.authenticate_MultipleFailedAttempts_LocksAccount.
        let h = harness();
        for left in ["2", "1", "0"] {
            let e = h.auth.authenticate(&pw("member", "nope"), &bus_req("crm"), 0).await.unwrap_err();
            assert_eq!(e.message(), format!("Wrong Password, {left} attempt remaining."));
        }
        let e = h.auth.authenticate(&pw("member", "nope"), &bus_req("crm"), 0).await.unwrap_err();
        assert_eq!(e.message(), "Your account is blocked. Please contact support.");
        let u = h.store.user(11);
        assert_eq!(u.status_code, "LOCKED");
        assert_eq!(u.locked_until, Some(dt("2026-10-15 07:45:00")), "local wall time + the policy's 15 minutes");
        assert_eq!(u.locked_due_to.as_deref(), Some("Password"));
        // Even the right password is refused while locked, with the minutes left.
        let e = h.auth.authenticate(&pw("member", "memberpw"), &bus_req("crm"), 0).await.unwrap_err();
        assert_eq!(e.message(), "Wrong Password limit reached. Try after 15 minutes.");
    }

    #[tokio::test]
    async fn authenticate_exceed_max_failed_attempts_locks_user() {
        let h = harness();
        h.store.with(|d| d.users.iter_mut().find(|u| u.id == 11).unwrap().no_failed_attempt = Some(3));
        let e = h.auth.authenticate(&pw("member", "nope"), &bus_req("crm"), 0).await.unwrap_err();
        assert_eq!(status(&e), StatusCode::FORBIDDEN);
        assert_eq!(h.store.called("lock_user"), 1);
        settle().await;
        assert!(h.store.with(|d| d.sox.iter().any(|s| s.2 == "Failed password attempts are more than the configuration")));
    }

    #[tokio::test]
    async fn authenticate_uses_the_clients_own_policy() {
        let h = harness();
        h.store.with(|d| d.policies.push((PassType::Password, 2, 2, Policy { no_failed_attempts: Some(5), user_lock_time: Some(30), otp: None })));
        let e = h.auth.authenticate(&pw("member", "nope"), &bus_req("crm"), 0).await.unwrap_err();
        assert_eq!(e.message(), "Wrong Password, 4 attempt remaining.");
    }

    #[tokio::test]
    async fn authenticate_policy_without_limits_is_javas_null_pointer() {
        let h = harness();
        h.store.with(|d| d.policies.push((PassType::Password, 2, 2, Policy { no_failed_attempts: None, user_lock_time: None, otp: None })));
        let e = h.auth.authenticate(&pw("member", "nope"), &bus_req("crm"), 0).await.unwrap_err();
        assert_eq!(status(&e), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(h.store.user(11).no_failed_attempt, Some(1), "the attempt is counted before the failure");
        h.store.with(|d| {
            d.policies[0].1 = 2;
            d.policies[0].3 = Policy { no_failed_attempts: Some(1), user_lock_time: None, otp: None };
        });
        h.auth.dir.caches.policies.get("clientPasswordPolicy", &"2:2".to_string()).await;
        h.cache.evict_all_everywhere("clientPasswordPolicy").await;
        let e = h.auth.authenticate(&pw("member", "nope"), &bus_req("crm"), 0).await.unwrap_err();
        assert_eq!(status(&e), StatusCode::INTERNAL_SERVER_ERROR, "no lock time to lock with");
    }

    #[tokio::test]
    async fn authenticate_locked_user_throws_forbidden() {
        let h = harness();
        let e = h.auth.authenticate(&pw("locked", "lockedpw"), &bus_req("crm"), 0).await.unwrap_err();
        assert_eq!((status(&e), e.message()), (StatusCode::FORBIDDEN, "Wrong Password limit reached. Try after 15 minutes.".to_string()));
    }

    #[tokio::test]
    async fn authenticate_locked_user_without_until_is_javas_null_pointer() {
        let h = harness();
        h.store.with(|d| d.users.iter_mut().find(|u| u.id == 13).unwrap().locked_until = None);
        let e = h.auth.authenticate(&pw("locked", "lockedpw"), &bus_req("crm"), 0).await.unwrap_err();
        assert_eq!(status(&e), StatusCode::INTERNAL_SERVER_ERROR);
        h.store.with(|d| {
            let u = d.users.iter_mut().find(|u| u.id == 13).unwrap();
            u.locked_until = Some(dt("2026-10-15 07:31:00"));
            u.locked_due_to = None;
        });
        let e = h.auth.authenticate(&pw("locked", "lockedpw"), &bus_req("crm"), 0).await.unwrap_err();
        assert_eq!(e.message(), "Wrong null limit reached. Try after 1 minutes.");
    }

    #[tokio::test]
    async fn authenticate_locked_user_lock_expired_unlocks_and_authenticates() {
        let h = harness();
        h.store.with(|d| d.users.iter_mut().find(|u| u.id == 13).unwrap().locked_until = Some(dt("2026-10-15 07:00:00")));
        let m = h.auth.authenticate(&pw("locked", "lockedpw"), &bus_req("crm"), 0).await.unwrap();
        assert!(m.response.access_token.is_some());
        assert_eq!(h.store.called("unlock_user"), 1);
        assert_eq!(h.store.user(13).status_code, "ACTIVE");
    }

    #[tokio::test]
    async fn authenticate_lock_expired_but_unlock_refused_is_blocked() {
        let h = harness();
        h.store.with(|d| {
            let u = d.users.iter_mut().find(|u| u.id == 13).unwrap();
            u.locked_until = Some(dt("2026-10-15 07:00:00"));
        });
        // A row the unlock cannot touch (gone between the read and the update).
        let user = h.store.user(13);
        h.store.with(|d| d.users.retain(|u| u.id != 13));
        let e = h.auth.check_user_status(&user).await.unwrap_err();
        assert_eq!(e.message(), "Your account is blocked. Please contact support.");
    }

    #[tokio::test]
    async fn authenticate_inactive_user_throws_forbidden() {
        let h = harness();
        let e = h.auth.authenticate(&pw("inactive", "x"), &bus_req("crm"), 0).await.unwrap_err();
        assert_eq!((status(&e), e.message()), (StatusCode::FORBIDDEN, "Your account is blocked. Please contact support.".to_string()));
    }

    #[tokio::test]
    async fn authenticate_password_expired_user_throws_forbidden() {
        let h = harness();
        let e = h.auth.authenticate(&pw("expired", "x"), &bus_req("crm"), 0).await.unwrap_err();
        assert_eq!(e.message(), "Your account null is expired. Please reset it now.");
        h.store.with(|d| d.users.iter_mut().find(|u| u.id == 14).unwrap().locked_due_to = Some("Password".into()));
        let e = h.auth.authenticate(&pw("expired", "x"), &bus_req("crm"), 0).await.unwrap_err();
        assert_eq!(e.message(), "Your account Password is expired. Please reset it now.");
    }

    #[tokio::test]
    async fn authenticate_deleted_user_throws_forbidden() {
        let h = harness();
        let e = h.auth.authenticate(&pw("deleted", "x"), &bus_req("crm"), 0).await.unwrap_err();
        assert_eq!((status(&e), e.message()), (StatusCode::FORBIDDEN, "No registration available for the selected client on this application.".to_string()));
    }

    #[tokio::test]
    async fn authenticate_user_not_found_falls_back_to_authenticate_for_having_app() {
        let h = harness();
        // Not an app the owner's client can reach: signed in to the one they hold a profile in.
        let m = h.auth.authenticate(&pw("owner", "secret"), &bus_req("unknownapp"), 0).await.unwrap();
        assert_eq!(m.response.verified_app_code.as_deref(), Some("crm"));
    }

    #[tokio::test]
    async fn authenticate_resets_failed_attempt_on_success() {
        let h = harness();
        h.store.with(|d| d.users.iter_mut().find(|u| u.id == 11).unwrap().no_failed_attempt = Some(2));
        h.auth.authenticate(&pw("member", "memberpw"), &bus_req("crm"), 0).await.unwrap();
        assert_eq!(h.store.user(11).no_failed_attempt, Some(0));
    }

    #[tokio::test]
    async fn authenticate_by_user_id_and_caller_recorded() {
        let h = harness();
        let body = AuthRequest { user_id: Some(142), password: Some("Pass@1234".into()), ..Default::default() };
        h.auth.authenticate(&body, &sys_req("appbuilder"), 99).await.unwrap();
        assert_eq!(h.store.with(|d| d.tokens[0].created_by), Some(99));
    }

    #[tokio::test]
    async fn authenticate_inactive_client_is_bad_request() {
        let h = harness();
        h.store.with(|d| d.clients.iter_mut().find(|c| c.id == Some(1)).unwrap().status_code = Some("INACTIVE".into()));
        let e = h.auth.authenticate(&pw("member", "memberpw"), &bus_req("crm"), 0).await.unwrap_err();
        assert_eq!((status(&e), e.message()), (StatusCode::BAD_REQUEST, "The requested client is inactive. Please contact admin.".to_string()));
    }

    #[tokio::test]
    async fn authenticate_without_client_code_has_no_registration() {
        let h = harness();
        let e = h.auth.authenticate(&pw("member", "memberpw"), &req(&[("appCode", "crm")]), 0).await.unwrap_err();
        assert_eq!(status(&e), StatusCode::FORBIDDEN);
    }
}

mod pin_authentication_tests {
    use super::*;

    fn pin(name: &str, p: &str) -> AuthRequest {
        AuthRequest { user_name: Some(name.into()), pin: Some(p.into()), ..Default::default() }
    }

    #[tokio::test]
    async fn authenticate_valid_pin_returns_token_response() {
        let h = harness();
        let m = h.auth.authenticate(&pin("owner", "1234"), &bus_req("crm"), 0).await.unwrap();
        assert!(m.response.access_token.is_some());
        assert_eq!(h.store.user(10).no_pin_failed_attempt, Some(0));
    }

    #[tokio::test]
    async fn authenticate_invalid_pin_increases_failed_attempt() {
        let h = harness();
        let e = h.auth.authenticate(&pin("owner", "0000"), &bus_req("crm"), 0).await.unwrap_err();
        assert_eq!(e.message(), "Wrong PIN, 2 attempt remaining.");
        assert_eq!(h.store.user(10).no_pin_failed_attempt, Some(1));
        assert_eq!(h.store.user(10).no_failed_attempt, Some(0));
    }

    #[tokio::test]
    async fn authenticate_pin_max_failed_attempts_locks_user() {
        let h = harness();
        h.store.with(|d| d.users.iter_mut().find(|u| u.id == 10).unwrap().no_pin_failed_attempt = Some(3));
        h.auth.authenticate(&pin("owner", "0000"), &bus_req("crm"), 0).await.unwrap_err();
        assert_eq!(h.store.user(10).locked_due_to.as_deref(), Some("PIN"));
    }

    #[tokio::test]
    async fn authenticate_unhashed_pin_uses_string_comparison() {
        let h = harness();
        h.store.with(|d| {
            let u = d.users.iter_mut().find(|u| u.id == 11).unwrap();
            u.pin = Some("4444".into());
            u.pin_hashed = false;
        });
        assert!(h.auth.authenticate(&pin("member", "4444"), &bus_req("crm"), 0).await.is_ok());
    }
}

mod otp_authentication_tests {
    use super::*;
    use security::store::NewOtp;

    fn otp(name: &str, code: &str) -> AuthRequest {
        AuthRequest { user_name: Some(name.into()), otp: Some(code.into()), ..Default::default() }
    }

    fn give_otp(h: &Harness, user: u64, code: &str, expires: &str) {
        h.store.with(|d| {
            d.otps.push(FakeOtp {
                id: 500,
                otp: NewOtp {
                    app_id: 2,
                    user_id: Some(user),
                    email_id: None,
                    phone_number: None,
                    purpose: "LOGIN".into(),
                    target_type: "EMAIL".into(),
                    unique_code: bcrypt::hash(code, 4).unwrap(),
                    expires_at: dt(expires),
                    ip_address: None,
                    created_at: dt("2026-10-15 07:29:00"),
                },
                legs: 0,
            })
        });
    }

    #[tokio::test]
    async fn authenticate_valid_otp_returns_token_and_resets_attempts() {
        let h = harness();
        give_otp(&h, 11, "4321", "2026-10-15 07:35:00");
        h.store.with(|d| d.users.iter_mut().find(|u| u.id == 11).unwrap().no_otp_failed_attempt = Some(1));
        h.auth.authenticate(&otp("member", "4321"), &bus_req("crm"), 0).await.unwrap();
        assert_eq!(h.store.user(11).no_otp_failed_attempt, Some(0));
        assert_eq!(h.store.called("reset_resend_attempts"), 1);
        assert!(h.store.with(|d| d.otps.is_empty()), "a login OTP is deleted once used");
    }

    #[tokio::test]
    async fn authenticate_invalid_otp_increases_otp_failed_attempts() {
        let h = harness();
        give_otp(&h, 11, "4321", "2026-10-15 07:35:00");
        let e = h.auth.authenticate(&otp("member", "1111"), &bus_req("crm"), 0).await.unwrap_err();
        assert_eq!(e.message(), "Wrong OTP, 2 attempt remaining.");
        assert_eq!(h.store.user(11).no_otp_failed_attempt, Some(1));
    }

    #[tokio::test]
    async fn authenticate_expired_otp_is_wrong() {
        let h = harness();
        give_otp(&h, 11, "4321", "2026-10-15 07:00:00");
        assert!(h.auth.authenticate(&otp("member", "4321"), &bus_req("crm"), 0).await.is_err());
    }

    #[tokio::test]
    async fn authenticate_otp_max_failed_attempts_locks_user() {
        let h = harness();
        h.store.with(|d| d.users.iter_mut().find(|u| u.id == 11).unwrap().no_otp_failed_attempt = Some(3));
        h.auth.authenticate(&otp("member", "1111"), &bus_req("crm"), 0).await.unwrap_err();
        assert_eq!(h.store.user(11).locked_due_to.as_deref(), Some("OTP"));
    }

    #[tokio::test]
    async fn otp_with_two_verify_legs_counts_instead_of_deleting() {
        let h = harness();
        give_otp(&h, 11, "4321", "2026-10-15 07:35:00");
        h.store.with(|d| d.otps[0].legs = 1);
        assert!(h.auth.verify_otp(Some("crm"), 11, "4321").await.unwrap());
        assert_eq!(h.store.with(|d| d.otps[0].legs), 2);
        assert!(!h.auth.verify_otp(Some(" "), 11, "4321").await.unwrap());
        assert!(!h.auth.verify_otp(None, 11, "4321").await.unwrap());
        assert!(!h.auth.verify_otp(Some("nope"), 11, "4321").await.unwrap());
        assert!(!h.auth.verify_otp(Some("crm"), 10, "4321").await.unwrap());
    }
}

mod authenticate_token_options_tests {
    use super::*;

    #[tokio::test]
    async fn authenticate_remember_me_uses_extended_expiry() {
        let h = harness();
        let body = AuthRequest { remember_me: true, ..pw("kirangrandhi", "Pass@1234") };
        let m = h.auth.authenticate(&body, &sys_req("appbuilder"), 0).await.unwrap();
        assert_eq!(m.response.access_token_expiry_at, Some(clock().instant().timestamp() + 525_600 * 60));
        assert!(h.auth.is_remember_me_token(m.response.access_token.as_deref()));
    }

    #[tokio::test]
    async fn authenticate_cookie_flag_adds_cookie_to_response() {
        let h = harness();
        let body = AuthRequest { cookie: true, ..pw("kirangrandhi", "Pass@1234") };
        let m = h.auth.authenticate(&body, &sys_req("appbuilder"), 0).await.unwrap();
        let token = m.response.access_token.unwrap();
        assert_eq!(m.cookie.unwrap(), format!("Authorization={token}; Max-Age=3600; Expires=Thu, 15 Oct 2026 03:00:00 GMT; Path=/"));
    }

    #[tokio::test]
    async fn authenticate_sso_token_flag_creates_one_time_token() {
        let h = harness();
        let body = AuthRequest { sso_token: true, ..pw("kirangrandhi", "Pass@1234") };
        let m = h.auth.authenticate(&body, &sys_req("appbuilder"), 0).await.unwrap();
        let sso = m.response.sso_token.unwrap();
        assert_eq!(sso.len(), 32);
        assert!(sso.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(&sso[12..13], "4", "a version 4 UUID");
        assert_eq!(h.store.with(|d| d.otts[0].row.remember_me), Some(false));
    }

    #[tokio::test]
    async fn authenticate_unhashed_password_uses_string_comparison() {
        let h = harness();
        assert!(h.auth.authenticate(&pw("kirangrandhi", "Pass@1234"), &sys_req("appbuilder"), 0).await.is_ok());
        assert!(h.auth.authenticate(&pw("kirangrandhi", "pass@1234"), &sys_req("appbuilder"), 0).await.is_err());
    }

    #[tokio::test]
    async fn authenticate_zero_token_validity_uses_default_expiry() {
        let mut d = seed();
        d.users.push(user(20, 3, "consumer", "pw"));
        let h = harness_with(d, clock(), settings());
        let r = req(&[("clientCode", "CUST"), ("appCode", "appbuilder"), ("X-Forwarded-Host", "c.local")]);
        h.store.with(|d| d.app_access.push((3, 1)));
        let m = h.auth.authenticate(&pw("consumer", "pw"), &r, 0).await.unwrap();
        assert_eq!(m.response.access_token_expiry_at, Some(clock().instant().timestamp() + 30 * 60));
        assert_eq!(m.response.managed_client_code.as_deref(), Some("BUS"));
        let c = jwt::parse(KEY, &m.response.access_token.unwrap(), clock().millis()).unwrap();
        assert_eq!(c.port.as_deref(), Some("8080"), "no X-Forwarded-Port: the Host header's port");
    }

    #[tokio::test]
    async fn authenticate_email_identifier_resolves_correctly() {
        let h = harness();
        assert!(h.auth.authenticate(&pw("kirangrandhi@example.com", "Pass@1234"), &sys_req("appbuilder"), 0).await.is_ok());
        let body = AuthRequest { identifier_type: Some("PHONE_NUMBER".into()), ..pw("kirangrandhi@example.com", "Pass@1234") };
        assert!(h.auth.authenticate(&body, &sys_req("appbuilder"), 0).await.is_err());
    }

    #[tokio::test]
    async fn authenticate_no_profile_falls_through() {
        let h = harness();
        h.store.with(|d| d.profile_users.retain(|(_, u)| *u != 142));
        let m = h.auth.authenticate(&pw("kirangrandhi", "Pass@1234"), &sys_req("appbuilder"), 0).await.unwrap();
        assert_eq!(m.response.user.string_authorities.unwrap(), vec!["Authorities.Logged_IN"]);
    }

    #[tokio::test]
    async fn multiple_authentications_generate_unique_tokens() {
        let h = harness();
        let a = sign_in(&h, &sys_req("appbuilder"), &pw("kirangrandhi", "Pass@1234")).await;
        let b = sign_in(&h, &sys_req("appbuilder"), &pw("kirangrandhi", "Pass@1234")).await;
        assert_ne!(a, b);
        assert_eq!(h.store.with(|d| d.tokens.len()), 2);
    }
}

mod authenticate_user_for_having_app_tests {
    use super::*;

    #[tokio::test]
    async fn authenticate_user_for_having_app_no_app_throws_forbidden() {
        let h = harness();
        let e = h.auth.authenticate(&pw("member", "memberpw"), &bus_req("unknownapp"), 0).await.unwrap_err();
        assert_eq!(e.message(), "No registration available for the selected client on this application.");
    }

    #[tokio::test]
    async fn authenticate_user_for_having_app_user_not_found_throws_forbidden() {
        let h = harness();
        let e = h.auth.authenticate(&pw("nobody", "x"), &bus_req("crm"), 0).await.unwrap_err();
        assert_eq!(status(&e), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn authenticate_user_for_having_app_app_not_found_by_id_is_not_found() {
        let h = harness();
        h.store.with(|d| {
            d.profiles.push(FakeProfile { id: 9, client_id: 2, name: None, app_id: 99, root: None, default: false });
            d.profile_users.insert(0, (9, 11));
        });
        let e = h.auth.authenticate(&pw("member", "memberpw"), &bus_req("unknownapp"), 0).await.unwrap_err();
        assert_eq!((status(&e), e.message()), (StatusCode::NOT_FOUND, "App with id 99 not found".to_string()));
    }

    #[tokio::test]
    async fn authenticate_user_for_having_app_inner_miss_is_a_refusal_not_a_loop() {
        let h = harness();
        // member's only profile is in appbuilder, which their client cannot reach without access.
        h.store.with(|d| {
            d.app_access.clear();
            d.profile_users.push((1, 11));
        });
        let e = h.auth.authenticate(&pw("member", "memberpw"), &bus_req("unknownapp"), 0).await.unwrap_err();
        assert_eq!(e.message(), "User credentials mismatch");
    }

    #[tokio::test]
    async fn authenticate_user_for_having_app_with_social_state_goes_social() {
        let h = harness();
        let body = AuthRequest { social_register_state: Some("s".into()), ..pw("owner", "x") };
        let e = h.auth.authenticate(&body, &bus_req("unknownapp"), 0).await.unwrap_err();
        // The social leg looks the state up and fails on one nobody minted ("Invalid state").
        assert_eq!(status(&e), StatusCode::INTERNAL_SERVER_ERROR);
    }
}

mod authenticate_w_social_tests {
    use super::*;

    fn social(name: &str, state: &str) -> AuthRequest {
        AuthRequest { user_name: Some(name.into()), social_register_state: Some(state.into()), ..Default::default() }
    }

    fn state(h: &Harness, s: &str, username: Option<&str>, updated: &str) {
        h.store.with(|d| {
            d.states.push(StateRow {
                state: s.into(),
                username: username.map(str::to_string),
                created_at: Some(dt("2026-10-15 01:00:00")),
                updated_at: Some(dt(updated)),
            })
        });
    }

    #[tokio::test]
    async fn authenticate_w_social_blank_state_throws_bad_request() {
        let h = harness();
        let e = h.auth.authenticate_social(&social("owner@example.com", " "), &bus_req("crm"), 0).await.unwrap_err();
        assert_eq!((status(&e), e.message()), (StatusCode::BAD_REQUEST, "Internal Server Error (Unknown)".to_string()));
    }

    #[tokio::test]
    async fn authenticate_w_social_verified_user_signs_in_and_spends_the_state() {
        let h = harness();
        state(&h, "st1", Some("owner@example.com"), "2026-10-15 01:55:00");
        let m = h.auth.authenticate_social(&social("owner@example.com", "st1"), &bus_req("crm"), 0).await.unwrap();
        assert_eq!(m.response.user.id, Some(10));
        assert!(h.store.with(|d| d.states.is_empty()));
        // The state is spent: the same arrival cannot buy a second session.
        let e = h.auth.authenticate_social(&social("owner@example.com", "st1"), &bus_req("crm"), 0).await.unwrap_err();
        assert_eq!(status(&e), StatusCode::INTERNAL_SERVER_ERROR, "Invalid state");
    }

    #[tokio::test]
    async fn authenticate_w_social_username_not_the_verified_one_forbidden_without_recursing() {
        let h = harness();
        state(&h, "st", Some("someone@else.com"), "2026-10-15 01:55:00");
        let e = h.auth.authenticate_social(&social("owner@example.com", "st"), &bus_req("crm"), 0).await.unwrap_err();
        assert_eq!((status(&e), e.message()), (StatusCode::FORBIDDEN, "Internal Server Error (Unknown)".to_string()));
    }

    #[tokio::test]
    async fn authenticate_w_social_state_never_completed_forbidden() {
        let h = harness();
        state(&h, "st", None, "2026-10-15 01:55:00");
        let e = h.auth.authenticate_social(&social("owner@example.com", "st"), &bus_req("crm"), 0).await.unwrap_err();
        assert_eq!(status(&e), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn authenticate_w_social_state_too_old_forbidden() {
        let h = harness();
        state(&h, "st", Some("owner@example.com"), "2026-10-15 01:49:00");
        let e = h.auth.authenticate_social(&social("owner@example.com", "st"), &bus_req("crm"), 0).await.unwrap_err();
        assert_eq!(status(&e), StatusCode::FORBIDDEN);
        assert!(h.store.with(|d| d.states.len() == 1), "a refused state is not spent");
    }

    #[tokio::test]
    async fn authenticate_w_social_user_not_on_this_app_forbidden() {
        let h = harness();
        // Nobody under BUS by this e-mail.
        state(&h, "st", Some("stranger@example.com"), "2026-10-15 01:55:00");
        let e = h.auth.authenticate_social(&social("stranger@example.com", "st"), &bus_req("crm"), 0).await.unwrap_err();
        assert_eq!((status(&e), e.message()), (StatusCode::FORBIDDEN, "User credentials mismatch".to_string()));
    }

    #[tokio::test]
    async fn authenticate_w_social_duplicate_identity_with_owner_signs_in_as_the_owner() {
        let h = harness();
        h.store.with(|d| {
            for u in d.users.iter_mut().filter(|u| u.id == 11) {
                u.email_id = Some("owner@example.com".into());
            }
        });
        state(&h, "st", Some("owner@example.com"), "2026-10-15 01:55:00");
        let m = h.auth.authenticate_social(&social("owner@example.com", "st"), &bus_req("crm"), 0).await.unwrap();
        assert_eq!(m.response.user.id, Some(10));
    }

    #[tokio::test]
    async fn authenticate_w_social_duplicate_identity_prefers_owner_with_app_profile() {
        let h = harness();
        h.store.with(|d| {
            let mut twin = d.users.iter().find(|u| u.id == 10).unwrap().clone();
            twin.id = 9;
            twin.user_name = Some("twin".into());
            d.users.push(twin);
            d.profile_users.push((1, 9));
        });
        state(&h, "st", Some("owner@example.com"), "2026-10-15 01:55:00");
        let m = h.auth.authenticate_social(&social("owner@example.com", "st"), &bus_req("crm"), 0).await.unwrap();
        assert_eq!(m.response.user.id, Some(10), "9 is an owner too, but only 10 has a crm profile");
        // With no app to judge by, the earliest owner wins.
        state(&h, "st2", Some("owner@example.com"), "2026-10-15 01:55:00");
        let r = bus_req("crm");
        let picked = h.auth.authenticate_social(&social("owner@example.com", "st2"), &r, 0).await.unwrap();
        assert_eq!(picked.response.user.id, Some(10));
    }

    #[tokio::test]
    async fn authenticate_w_social_duplicate_identity_no_owner_forbidden() {
        let h = harness();
        h.store.with(|d| {
            for u in d.users.iter_mut().filter(|u| u.id == 11 || u.id == 13) {
                u.email_id = Some("same@example.com".into());
                u.status_code = "ACTIVE".into();
            }
        });
        state(&h, "st", Some("same@example.com"), "2026-10-15 01:55:00");
        let e = h.auth.authenticate_social(&social("same@example.com", "st"), &bus_req("crm"), 0).await.unwrap_err();
        assert_eq!((status(&e), e.message()), (StatusCode::FORBIDDEN, "User credentials mismatch".to_string()));
    }

    #[tokio::test]
    async fn authenticate_w_social_owner_without_access_to_this_app_conflict() {
        let h = harness();
        // owner@example.com owns a client under BUS but BUS has no access to this app.
        h.store.with(|d| d.apps.push(app(9, 1, "private")));
        state(&h, "st", Some("owner@example.com"), "2026-10-15 01:55:00");
        let e = h.auth.authenticate_social(&social("owner@example.com", "st"), &bus_req("private"), 0).await.unwrap_err();
        assert_eq!(status(&e), StatusCode::CONFLICT);
        assert!(e.message().starts_with("This account already belongs to an organisation."));
    }

    #[tokio::test]
    async fn authenticate_w_social_unverified_state_does_not_disclose_that_the_identity_exists() {
        let h = harness();
        h.store.with(|d| d.apps.push(app(9, 1, "private")));
        let e = h.auth.authenticate_social(&social("owner@example.com", "never-minted"), &bus_req("private"), 0).await.unwrap_err();
        assert_eq!(status(&e), StatusCode::FORBIDDEN);
        state(&h, "st", Some("owner@example.com"), "2026-10-15 01:00:00");
        let e = h.auth.authenticate_social(&social("owner@example.com", "st"), &bus_req("private"), 0).await.unwrap_err();
        assert_eq!(status(&e), StatusCode::FORBIDDEN, "a stale state is not evidence either");
        h.store.with(|d| d.fail.insert("state_by_value"));
        let e = h.auth.authenticate_social(&social("owner@example.com", "st"), &bus_req("private"), 0).await.unwrap_err();
        assert_eq!(status(&e), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn authenticate_w_social_member_who_owns_nothing_is_told_to_register() {
        let h = harness();
        h.store.with(|d| d.apps.push(app(9, 1, "private")));
        state(&h, "st", Some("member@example.com"), "2026-10-15 01:55:00");
        let e = h.auth.authenticate_social(&social("member@example.com", "st"), &bus_req("private"), 0).await.unwrap_err();
        assert_eq!((status(&e), e.message()), (StatusCode::FORBIDDEN, "User credentials mismatch".to_string()));
    }

    #[tokio::test]
    async fn state_expiry_uses_the_verification_time() {
        let s = StateRow { state: "s".into(), username: None, created_at: Some(dt("2026-10-15 01:00:00")), updated_at: None };
        assert!(security::signin::is_state_expired(&s, dt("2026-10-15 02:00:00")));
        assert!(!security::signin::is_state_expired(&s, dt("2026-10-15 01:05:00")));
        let none = StateRow { created_at: None, ..s };
        assert!(security::signin::is_state_expired(&none, dt("2026-10-15 01:05:00")));
    }
}

mod get_authentication_tests {
    use super::*;
    use security::request::RequestInfo;

    #[tokio::test]
    async fn get_authentication_blank_token_returns_anonymous() {
        let h = harness();
        let ca = h.auth.context(&req(&[("clientCode", "BUS"), ("appCode", "crm")])).await.unwrap();
        assert!(!ca.authenticated);
        assert_eq!(ca.user.user_name.as_deref(), Some("_Anonymous"));
        assert_eq!((ca.client_code.as_deref(), ca.client_type_code.as_deref()), (Some("BUS"), Some("BUS")));
        assert_eq!((ca.url_client_code.as_deref(), ca.url_app_code.as_deref()), (Some("BUS"), Some("crm")));
        // LocalDateTime.now() of a JVM 5h30 east, written as if it were UTC.
        assert_eq!(ca.user.created_at, Some(dt("2026-10-15 07:30:00").and_utc().timestamp()));
        assert_eq!(ca.access_token_expiry_at, Some(security::jackson::LOCAL_DATE_TIME_MAX_EPOCH));
    }

    #[tokio::test]
    async fn get_authentication_expired_token_returns_anonymous() {
        let h = harness();
        let token = sign_in(&h, &sys_req("appbuilder"), &pw("kirangrandhi", "Pass@1234")).await;
        let later = harness_with(seed(), security::clock::Clock::fixed(clock().instant() + chrono::Duration::hours(2), 19_800), settings());
        later.store.with(|d| d.tokens = h.store.with(|o| o.tokens.clone()));
        assert!(!later.auth.context(&with_bearer(&sys_req("appbuilder"), &token)).await.unwrap().authenticated);
    }

    #[tokio::test]
    async fn get_authentication_null_token_and_malformed_jwt_return_anonymous() {
        let h = harness();
        for t in ["Bearer ", "Bearer not.a.jwt", "Bearer x"] {
            let r = req(&[("clientCode", "SYSTEM"), ("authorization", t)]);
            assert!(!h.auth.context(&r).await.unwrap().authenticated);
        }
    }

    #[tokio::test]
    async fn get_authentication_unknown_client_code_throws_unauthorized() {
        let h = harness();
        let e = h.auth.context(&req(&[("clientCode", "NOPE")])).await.unwrap_err();
        assert_eq!((status(&e), e.message()), (StatusCode::UNAUTHORIZED, "Unknown client information requested".to_string()));
        let e = h.auth.context(&req(&[("clientCode", "")])).await.unwrap_err();
        assert_eq!(status(&e), StatusCode::UNAUTHORIZED, "an empty clientCode header is still a code");
    }

    #[tokio::test]
    async fn context_authentication_with_valid_token_returns_context() {
        let h = harness();
        let token = sign_in(&h, &bus_req("crm"), &pw("owner", "secret")).await;
        let ca = h.auth.context(&with_bearer(&bus_req("crm"), &token)).await.unwrap();
        assert!(ca.authenticated);
        assert_eq!(ca.user.time_zone.as_deref(), Some("Europe/London"), "the user's own zone wins");
        assert_eq!((ca.client_type_code.as_deref(), ca.client_level_type.as_deref(), ca.client_code.as_deref()), (Some("BUS"), Some("CLIENT"), Some("BUS")));
        assert_eq!(ca.verified_app_code.as_deref(), Some("crm"));
        assert_eq!(ca.user.string_authorities.as_ref().unwrap().last().map(String::as_str), Some("Authorities.Logged_IN"));
        let row_used = h.store.with(|d| d.tokens[0].last_used);
        assert_eq!(row_used, Some(dt("2026-10-15 07:30:00")), "LAST_USED_AT is the local wall time");
        // The second call is answered from the token cache.
        h.auth.context(&with_bearer(&bus_req("crm"), &token)).await.unwrap();
        assert_eq!(h.store.called("tokens_by_part"), 1);
        // A user without a zone of their own takes the client's.
        let t2 = sign_in(&h, &sys_req("appbuilder"), &pw("kirangrandhi", "Pass@1234")).await;
        let ca = h.auth.context(&with_bearer(&sys_req("appbuilder"), &t2)).await.unwrap();
        assert_eq!(ca.user.time_zone.as_deref(), Some("Asia/Kolkata"));
    }

    #[tokio::test]
    async fn context_with_token_from_another_host_is_anonymous() {
        let h = harness();
        let token = sign_in(&h, &sys_req("appbuilder"), &pw("kirangrandhi", "Pass@1234")).await;
        let other = req(&[("clientCode", "SYSTEM"), ("X-Forwarded-Host", "evil.example"), ("authorization", &format!("Bearer {token}"))]);
        assert!(!h.auth.context(&other).await.unwrap().authenticated);
        // A host that contains the issuing host is accepted (Java's `contains`).
        let sub = req(&[("clientCode", "SYSTEM"), ("X-Forwarded-Host", "x.apps.local"), ("authorization", &format!("Bearer {token}"))]);
        assert!(h.auth.context(&sub).await.unwrap().authenticated);
    }

    #[tokio::test]
    async fn context_of_a_blocked_user_with_a_valid_token_is_refused() {
        let h = harness();
        let token = sign_in(&h, &bus_req("crm"), &pw("member", "memberpw")).await;
        let r = with_bearer(&bus_req("crm"), &token);
        assert!(h.auth.context(&r).await.unwrap().authenticated);
        h.store.with(|d| d.users.iter_mut().find(|u| u.id == 11).unwrap().status_code = "INACTIVE".into());
        // Java's admin change evicts `user:<id>`; the eviction reaches this cache.
        h.cache.evict_everywhere(caches::USER, "11").await;
        let e = h.auth.context(&r).await.unwrap_err();
        assert_eq!(status(&e), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn context_of_a_token_whose_user_is_gone_is_anonymous() {
        let h = harness();
        let token = sign_in(&h, &bus_req("crm"), &pw("member", "memberpw")).await;
        h.store.with(|d| d.users.retain(|u| u.id != 11));
        assert!(!h.auth.context(&with_bearer(&bus_req("crm"), &token)).await.unwrap().authenticated);
    }

    #[tokio::test]
    async fn context_of_a_token_whose_client_type_is_gone_is_anonymous() {
        let h = harness();
        let token = sign_in(&h, &bus_req("crm"), &pw("member", "memberpw")).await;
        let r = with_bearer(&bus_req("crm"), &token);
        h.store.with(|d| d.fail.insert("client_type_code_level"));
        assert!(!h.auth.context(&r).await.unwrap().authenticated);
        h.store.with(|d| {
            d.fail.clear();
            d.clients.retain(|c| c.id != Some(2));
        });
        let anon = h.auth.context(&with_bearer(&req(&[("clientCode", "SYSTEM")]), &token)).await.unwrap();
        assert!(!anon.authenticated);
    }

    #[tokio::test]
    async fn one_time_token_claim_deletes_the_row_and_is_not_cached() {
        let h = harness();
        let claims = jwt::Claims {
            user_id: 142,
            host_name: Some("apps.local".into()),
            port: Some("443".into()),
            logged_in_client_id: 1,
            logged_in_client_code: Some("SYSTEM".into()),
            app_code: Some("appbuilder".into()),
            one_time: true,
        };
        let made = jwt::make(KEY, &claims, clock().instant().timestamp(), 5);
        h.store.with(|d| {
            d.tokens.push(FakeToken {
                id: 1,
                user_id: 142,
                token: made.token.clone(),
                part: security::context::part_token(&made.token).into(),
                expires_at: dt("2026-10-15 02:05:00"),
                last_used: None,
                created_by: None,
                ip: None,
            })
        });
        let r = with_bearer(&sys_req("appbuilder"), &made.token);
        assert!(h.auth.context(&r).await.unwrap().authenticated);
        assert!(h.store.with(|d| d.tokens.is_empty()));
        assert!(!h.auth.context(&r).await.unwrap().authenticated);
    }

    #[tokio::test]
    async fn context_store_failure_while_reading_the_token_is_anonymous() {
        let h = harness();
        let token = sign_in(&h, &sys_req("appbuilder"), &pw("kirangrandhi", "Pass@1234")).await;
        h.store.with(|d| d.fail.insert("update_last_used"));
        assert!(!h.auth.context(&with_bearer(&sys_req("appbuilder"), &token)).await.unwrap().authenticated);
    }

    #[tokio::test]
    async fn token_without_host_claim_is_anonymous() {
        let h = harness();
        let claims = jwt::Claims { user_id: 142, host_name: None, port: None, logged_in_client_id: 1, logged_in_client_code: None, app_code: None, one_time: false };
        let made = jwt::make(KEY, &claims, clock().instant().timestamp(), 5);
        assert!(!h.auth.context(&with_bearer(&sys_req("appbuilder"), &made.token)).await.unwrap().authenticated);
    }

    #[tokio::test]
    async fn token_without_app_code_takes_the_request_app() {
        let h = harness();
        let claims = jwt::Claims {
            user_id: 142,
            host_name: Some("apps.local".into()),
            port: None,
            logged_in_client_id: 1,
            logged_in_client_code: Some("SYSTEM".into()),
            app_code: None,
            one_time: false,
        };
        let made = jwt::make(KEY, &claims, clock().instant().timestamp(), 5);
        h.store.with(|d| {
            d.tokens.push(FakeToken {
                id: 3,
                user_id: 142,
                token: made.token.clone(),
                part: security::context::part_token(&made.token).into(),
                expires_at: dt("2026-10-15 02:05:00"),
                last_used: None,
                created_by: None,
                ip: None,
            })
        });
        let ca = h.auth.context(&with_bearer(&sys_req("appbuilder"), &made.token)).await.unwrap();
        assert_eq!(ca.verified_app_code.as_deref(), Some("appbuilder"));
    }

    fn basic(user_pass: &str, client: &str, app: &str) -> RequestInfo {
        use base64::Engine;
        let b = base64::engine::general_purpose::STANDARD.encode(user_pass);
        req(&[("clientCode", client), ("appCode", app), ("authorization", &format!("Basic {b}"))])
    }

    #[tokio::test]
    async fn basic_by_user_id_and_by_name() {
        let h = harness();
        let ca = h.auth.context(&basic("142:Pass@1234", "SYSTEM", "appbuilder")).await.unwrap();
        assert!(ca.authenticated);
        assert!(ca.access_token.as_deref().unwrap().starts_with("Basic "));
        assert_eq!(ca.access_token_expiry, Some(dt("2027-10-15 07:30:00")), "LocalDateTime.now().plusYears(1)");
        assert_eq!(ca.verified_app_code.as_deref(), Some("appbuilder"));
        assert!(h.auth.context(&basic("kirangrandhi:Pass@1234", "SYSTEM", "appbuilder")).await.unwrap().authenticated);
        assert!(h.auth.context(&basic("kirangrandhi@example.com:Pass@1234", "SYSTEM", "appbuilder")).await.unwrap().authenticated);
        // An all-digit name that is not an id is tried as a name.
        h.store.with(|d| d.users.iter_mut().find(|u| u.id == 11).unwrap().user_name = Some("4242".into()));
        assert!(h.auth.context(&basic("4242:memberpw", "BUS", "crm")).await.unwrap().authenticated);
    }

    #[tokio::test]
    async fn basic_wrong_password_is_anonymous_and_counts() {
        let h = harness();
        let ca = h.auth.context(&basic("11:wrong", "BUS", "crm")).await.unwrap();
        assert!(!ca.authenticated);
        assert_eq!(h.store.user(11).no_failed_attempt, Some(1));
    }

    #[tokio::test]
    async fn basic_rejections_are_anonymous() {
        let h = harness();
        for r in [
            basic("nobody:x", "BUS", "crm"),
            basic("11:memberpw", "BUS", "unknownapp"),
            basic("no-colon", "BUS", "crm"),
            basic("12:x", "BUS", "crm"),
            req(&[("clientCode", "BUS"), ("authorization", "Basic !!!")]),
        ] {
            assert!(!h.auth.context(&r).await.unwrap().authenticated);
        }
        let mut r = basic("11:memberpw", "BUS", "crm");
        r.headers.remove("clientcode");
        // No clientCode header: the host decides the client, and Basic finds nobody.
        assert!(!h.auth.context(&r).await.unwrap().authenticated);
    }

    #[tokio::test]
    async fn basic_user_client_check_needs_a_client_code() {
        let h = harness();
        let found = h.auth.find_user(Some("member"), None, Some("BUS"), Some("crm"), security::store::IdentifierType::UserName, false).await.unwrap().unwrap();
        assert!(security::context::check_user_and_client(&found, Some("BUS")));
        assert!(!security::context::check_user_and_client(&found, None));
        assert!(security::context::check_user_and_client(&found, Some("OTHER")), "same client either way");
        assert_eq!(security::context::basic_user_id("142"), Some(142));
        assert_eq!(security::context::basic_user_id("12345678901234567890"), None);
        assert_eq!(security::context::basic_user_id("a1"), None);
        assert_eq!(security::context::lock_minutes_left(5, 50), 15);
    }

    #[tokio::test]
    async fn anonymous_by_host() {
        let mut d = seed();
        d.url_patterns = vec![security::model::UrlPattern::new("2".into(), Some("BUS".into()), Some("bus.example.com".into()), Some("crm".into()))];
        let h = harness_with(d, clock(), settings());
        let ca = h.auth.context(&req(&[("X-Forwarded-Host", "bus.example.com:443")])).await.unwrap();
        assert_eq!(ca.client_code.as_deref(), Some("BUS"));
        let ca = h.auth.context(&req(&[("host", "elsewhere.local")])).await.unwrap();
        assert_eq!(ca.client_code.as_deref(), Some("SYSTEM"), "no pattern: SYSTEM");
        // An app's platform subdomain resolves through the app, and Java then fails on the
        // pattern's empty identifier: a 500, kept.
        let e = h.auth.context(&req(&[("X-Forwarded-Host", "crm.local.modlix.com")])).await.unwrap_err();
        assert_eq!((status(&e), e.to_string()), (StatusCode::INTERNAL_SERVER_ERROR, "500 Internal Server Error: Empty input string".into()));
        assert_eq!(h.auth.dir.subdomain_app_code("a.b.local.modlix.com"), None);
        assert_eq!(h.auth.dir.subdomain_app_code(".local.modlix.com"), None);
        assert_eq!(h.auth.dir.subdomain_app_code("nothing.example"), None);
        // An unknown or archived app's subdomain is just no pattern.
        assert_eq!(h.auth.context(&req(&[("X-Forwarded-Host", "nope.local.modlix.com")])).await.unwrap().client_code.as_deref(), Some("SYSTEM"));
        h.store.with(|d| d.apps.iter_mut().find(|a| a.app_code == "authzump").unwrap().status = Some("ARCHIVED".into()));
        assert!(h.auth.context(&req(&[("X-Forwarded-Host", "authzump.local.modlix.com")])).await.is_ok());
        // A pattern whose identifier is not a number fails the same way.
        let mut d = seed();
        d.url_patterns = vec![security::model::UrlPattern::new("x".into(), None, Some("odd.example".into()), None)];
        let h = harness_with(d, clock(), settings());
        assert!(h.auth.context(&req(&[("X-Forwarded-Host", "odd.example")])).await.is_err());
    }

    #[tokio::test]
    async fn authorities_with_user_roles_and_hierarchy() {
        let h = harness();
        h.store.with(|d| {
            d.user_roles.push((11, 2));
            d.user_roles.push((11, 3));
        });
        let a = h.auth.dir.user_authorities(Some("crm"), 2, 11).await.unwrap();
        assert_eq!(
            a,
            vec![
                "Authorities.CRM.ROLE_Lead_Viewer",
                "Authorities.CRM.Lead_READ",
                "Authorities.ROLE_Page_Manager",
                "Authorities.ROLE_Page_READ",
                "Authorities.Page_READ",
                "Authorities.CRM.ROLE_Lead_Viewer",
                "Authorities.CRM.Lead_READ",
                "Authorities.CRM.PROFILE_Crm_Member",
                "Authorities.Logged_IN"
            ]
        );
        // A client without a hierarchy row is Java's 500.
        let e = h.auth.dir.user_authorities(Some("crm"), 77, 11).await.unwrap_err();
        assert_eq!(e.message(), "No client hierarchy found for client id: 77");
        // "nothing" asks for every app's profiles.
        let all = h.auth.dir.profile_authorities(Some("nothing"), 2, 10).await.unwrap();
        assert!(all.contains(&"Authorities.APPBUILDER.PROFILE_Appbuilder_Owner".to_string()));
        assert!(all.contains(&"Authorities.CRM.PROFILE_Crm_Owner".to_string()));
    }

    #[tokio::test]
    async fn child_profile_overrides_drop_the_role() {
        let h = harness();
        h.store.with(|d| {
            d.profiles.push(FakeProfile { id: 5, client_id: 2, name: Some("Crm Owner Override".into()), app_id: 2, root: Some(2), default: false });
            // Lead Viewer also named by BUS's override of profile 2: Java drops it and repeats
            // the last role kept.
            d.profile_roles.push((5, 3, 1));
        });
        let a = h.auth.dir.profile_authorities(Some("crm"), 2, 10).await.unwrap();
        assert_eq!(a, vec!["Authorities.ROLE_Owner", "Authorities.CRM.PROFILE_Crm_Owner", "Authorities.CRM.PROFILE_Crm_Owner_Override"]);
    }

    #[tokio::test]
    async fn store_errors_in_authorities_fail_the_request() {
        let h = harness();
        h.store.with(|d| d.fail.insert("profile_ids"));
        let e = h.auth.authenticate(&pw("member", "memberpw"), &bus_req("crm"), 0).await.unwrap_err();
        assert_eq!(status(&e), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn context_survives_a_missing_client_row_for_time_zone() {
        let h = harness();
        let token = sign_in(&h, &bus_req("crm"), &pw("member", "memberpw")).await;
        h.store.with(|d| d.fail.insert("client_by_id"));
        // clientId is cached from sign-in, so the context still builds.
        assert!(h.auth.context(&with_bearer(&bus_req("crm"), &token)).await.unwrap().authenticated);
        let fresh = Arc::new(());
        drop(fresh);
    }
}

mod generate_otp_tests {
    use super::*;

    fn gen(name: &str) -> AuthRequest {
        AuthRequest { user_name: Some(name.into()), generate_otp: true, ..Default::default() }
    }

    #[tokio::test]
    async fn generate_otp_not_generate_flag_returns_false() {
        let h = harness();
        assert!(!h.auth.generate_otp(&AuthRequest::default(), &bus_req("crm")).await.unwrap());
        assert_eq!(h.store.called("users_by"), 0);
    }

    #[tokio::test]
    async fn generate_otp_user_not_found_returns_false() {
        let h = harness();
        assert!(!h.auth.generate_otp(&gen("nobody"), &bus_req("crm")).await.unwrap());
    }

    #[tokio::test]
    async fn generate_otp_valid_user_delegates_to_otp_service() {
        let h = harness();
        let mut r = bus_req("crm");
        r.headers.insert("x-debug", HeaderValue::from_static("dbg-1"));
        assert!(h.auth.generate_otp(&gen("member"), &r).await.unwrap());
        let ev = h.events.events.lock().unwrap()[0].clone();
        assert_eq!(ev.event_name, "USER_OTP_GENERATE");
        assert_eq!((ev.client_code.as_deref(), ev.app_code.as_deref(), ev.x_debug.as_deref()), (Some("BUS"), Some("crm"), Some("dbg-1")));
        let otp = ev.data.iter().find(|(k, _)| k == "otp").unwrap().1.as_str().unwrap().to_string();
        assert_eq!(otp.len(), 4);
        let row = h.store.with(|d| d.otps[0].otp.clone());
        assert!(bcrypt::verify(&otp, &row.unique_code).unwrap());
        assert!(row.unique_code.starts_with("$2a$10$"));
        assert_eq!((row.email_id.as_deref(), row.phone_number.as_deref()), (Some("member@example.com"), None));
        assert_eq!((row.expires_at, row.created_at), (dt("2026-10-15 07:35:00"), dt("2026-10-15 07:30:00")));
        assert_eq!(row.ip_address.as_deref(), Some("10.1.2.3"));
        // The code verifies as a sign-in.
        let body = AuthRequest { user_name: Some("member".into()), otp: Some(otp), ..Default::default() };
        assert!(h.auth.authenticate(&body, &bus_req("crm"), 0).await.is_ok());
    }

    #[tokio::test]
    async fn generate_otp_resend_flag_passes_resend_to_request() {
        let h = harness();
        let body = AuthRequest { resend: true, ..gen("member") };
        assert!(h.auth.generate_otp(&body, &bus_req("crm")).await.unwrap());
        assert_eq!(h.store.called("increase_resend_attempts"), 1);
    }

    #[tokio::test]
    async fn generate_otp_resend_same_otp_sends_what_was_stored() {
        let h = harness();
        let mut p = PassType::Otp.default_policy();
        p.otp.as_mut().unwrap().resend_same_otp = true;
        h.store.with(|d| d.policies.push((PassType::Otp, 2, 2, p)));
        assert!(h.auth.generate_otp(&gen("member"), &bus_req("crm")).await.unwrap());
        let stored = h.store.with(|d| d.otps[0].otp.unique_code.clone());
        let body = AuthRequest { resend: true, ..gen("member") };
        assert!(h.auth.generate_otp(&body, &bus_req("crm")).await.unwrap());
        let sent = h.events.events.lock().unwrap()[1].data.iter().find(|(k, _)| k == "otp").unwrap().1.clone();
        assert_eq!(sent.as_str(), Some(stored.as_str()), "Java re-sends the stored hash");
        // Nothing stored yet for another user: nothing to resend.
        let body = AuthRequest { resend: true, ..gen("owner") };
        assert!(!h.auth.generate_otp(&body, &bus_req("crm")).await.unwrap());
    }

    #[tokio::test]
    async fn generate_otp_unknown_app_or_no_email_returns_false() {
        let h = harness();
        assert!(!h.auth.generate_otp(&gen("member"), &bus_req("unknownapp")).await.unwrap());
        assert!(!h.auth.generate_otp(&gen("member"), &req(&[("clientCode", "BUS")])).await.unwrap());
        h.store.with(|d| d.users.iter_mut().find(|u| u.id == 11).unwrap().email_id = Some("NONE".into()));
        assert!(!h.auth.generate_otp(&gen("member"), &bus_req("crm")).await.unwrap());
    }

    #[tokio::test]
    async fn generate_otp_by_phone_and_both() {
        let h = harness();
        h.store.with(|d| d.users.iter_mut().find(|u| u.id == 11).unwrap().phone_number = Some("+919000000000".into()));
        let mut p = PassType::Otp.default_policy();
        p.otp.as_mut().unwrap().target_type = "PHONE".into();
        h.store.with(|d| d.policies.push((PassType::Otp, 2, 2, p.clone())));
        assert!(h.auth.generate_otp(&gen("member"), &bus_req("crm")).await.unwrap());
        assert_eq!(h.sms.sent.lock().unwrap()[0].1, "login");
        assert_eq!(h.store.with(|d| d.otps[0].otp.email_id.clone()), None);
        h.store.with(|d| d.policies[0].3.otp.as_mut().unwrap().target_type = "BOTH".into());
        h.cache.evict_all_everywhere("clientOtpPolicy").await;
        assert!(h.auth.generate_otp(&gen("member"), &bus_req("crm")).await.unwrap());
        assert_eq!(h.events.events.lock().unwrap().len(), 1);
        assert_eq!(h.sms.sent.lock().unwrap().len(), 2);
        let row = h.store.with(|d| d.otps[1].otp.clone());
        assert_eq!((row.email_id.is_some(), row.phone_number.is_some(), row.target_type.as_str()), (true, true, "BOTH"));
        // BOTH with neither: nothing sent.
        h.store.with(|d| {
            let u = d.users.iter_mut().find(|u| u.id == 11).unwrap();
            u.phone_number = Some("NONE".into());
            u.email_id = Some("NONE".into());
        });
        assert!(!h.auth.generate_otp(&gen("member"), &bus_req("crm")).await.unwrap());
        // PHONE without a phone: nothing sent.
        h.store.with(|d| d.policies[0].3.otp.as_mut().unwrap().target_type = "PHONE".into());
        h.cache.evict_all_everywhere("clientOtpPolicy").await;
        assert!(!h.auth.generate_otp(&gen("member"), &bus_req("crm")).await.unwrap());
    }

    #[tokio::test]
    async fn generate_otp_constant_and_blank_codes() {
        let h = harness();
        let mut p = PassType::Otp.default_policy();
        {
            let o = p.otp.as_mut().unwrap();
            o.is_constant = true;
            o.constant_value = Some("  ".into());
        }
        h.store.with(|d| d.policies.push((PassType::Otp, 2, 2, p)));
        assert!(!h.auth.generate_otp(&gen("member"), &bus_req("crm")).await.unwrap(), "a blank code is not sent");
        h.store.with(|d| d.policies[0].3.otp.as_mut().unwrap().constant_value = None);
        h.cache.evict_all_everywhere("clientOtpPolicy").await;
        assert!(!h.auth.generate_otp(&gen("member"), &bus_req("crm")).await.unwrap());
    }

    #[tokio::test]
    async fn generate_otp_app_without_name_is_javas_null_pointer() {
        let h = harness();
        h.store.with(|d| d.apps.iter_mut().find(|a| a.app_code == "crm").unwrap().app_name = None);
        assert!(h.auth.generate_otp(&gen("member"), &bus_req("crm")).await.is_err());
    }

    #[tokio::test]
    async fn generate_otp_check_user_and_client_fails_returns_false() {
        let h = harness();
        // A user found under another client code: SYSTEM sees BUS's users, and passes the check
        // as the SYS client; nothing here fails it, so the flag alone decides.
        assert!(h.auth.generate_otp(&gen("member"), &req(&[("clientCode", "SYSTEM"), ("appCode", "crm")])).await.unwrap());
    }
}

mod make_one_time_token_tests {
    use super::*;
    use security::tokens::OneTimeTokenRequest;

    async fn signed(h: &Harness, remember: bool) -> (security::request::RequestInfo, ContextAuth) {
        let body = AuthRequest { remember_me: remember, ..pw("kirangrandhi", "Pass@1234") };
        let token = sign_in(h, &sys_req("appbuilder"), &body).await;
        let r = with_bearer(&sys_req("appbuilder"), &token);
        let ca = h.auth.context(&r).await.unwrap();
        (r, ca)
    }

    #[tokio::test]
    async fn make_one_time_token_happy_path_returns_token_and_url() {
        let h = harness();
        let (r, ca) = signed(&h, false).await;
        let body = OneTimeTokenRequest { callback_url: Some("https://x{envDotPrefix}.modlix.com/?t={token}&e={env}&s={envDotSuffix}".into()), ..Default::default() };
        let v = h.auth.make_one_time_token(&body, &r, &ca, false).await.unwrap();
        let t = v["token"].as_str().unwrap();
        assert_eq!(v["url"], format!("https://x.local.modlix.com/?t={t}&e=local&s=local."));
        let ott = h.store.with(|d| d.otts[0].row.clone());
        assert_eq!((ott.auth_mode.as_deref(), ott.origin_app_code.as_deref(), ott.target_app_code), (Some("BEARER"), Some("appbuilder"), None));
        assert_eq!(ott.remember_me, Some(false));
    }

    #[tokio::test]
    async fn auth_mode_unset_infers_from_the_call_explicit_beats_it_and_is_normalised() {
        let h = harness();
        let (mut r, ca) = signed(&h, false).await;
        r.headers.insert("cookie", HeaderValue::from_static("Authorization=x"));
        h.auth.make_one_time_token(&OneTimeTokenRequest::default(), &r, &ca, false).await.unwrap();
        let explicit = OneTimeTokenRequest { auth_mode: Some(" bearer ".into()), ..Default::default() };
        h.auth.make_one_time_token(&explicit, &r, &ca, false).await.unwrap();
        let modes: Vec<_> = h.store.with(|d| d.otts.iter().map(|o| o.row.auth_mode.clone().unwrap()).collect());
        assert_eq!(modes, vec!["COOKIE", "BEARER"]);
        let bad = OneTimeTokenRequest { auth_mode: Some("header".into()), ..Default::default() };
        let e = h.auth.make_one_time_token(&bad, &r, &ca, false).await.unwrap_err();
        assert_eq!((status(&e), e.message()), (StatusCode::BAD_REQUEST, "Auth mode must be COOKIE or BEARER".to_string()));
    }

    #[tokio::test]
    async fn make_one_time_token_anonymous_is_unknown_token() {
        let h = harness();
        let e = h.auth.make_one_time_token(&OneTimeTokenRequest::default(), &sys_req("appbuilder"), &ContextAuth::default(), true).await.unwrap_err();
        assert_eq!((status(&e), e.message()), (StatusCode::UNAUTHORIZED, "Unknown token".to_string()));
    }

    #[tokio::test]
    async fn one_time_token_remember_me_rules() {
        let h = harness();
        let (r, ca) = signed(&h, false).await;
        let ask = OneTimeTokenRequest { remember_me: true, ..Default::default() };
        // A short session cannot mint a remember-me fork on the public path...
        h.auth.make_one_time_token(&ask, &r, &ca, false).await.unwrap();
        // ...the internal path honours it...
        h.auth.make_one_time_token(&ask, &r, &ca, true).await.unwrap();
        // ...and a remember-me session keeps it.
        let (r2, ca2) = signed(&h, true).await;
        h.auth.make_one_time_token(&ask, &r2, &ca2, false).await.unwrap();
        let flags: Vec<_> = h.store.with(|d| d.otts.iter().map(|o| o.row.remember_me.unwrap()).collect());
        assert_eq!(flags, vec![false, true, true]);
        assert!(!h.auth.is_remember_me_token(None));
        assert!(!h.auth.is_remember_me_token(Some("Basic abc")));
    }

    #[tokio::test]
    async fn is_remember_me_token_by_lifetime() {
        let mut s = settings();
        s.remember_me_expiry_minutes = 0;
        let h = harness_with(seed(), clock(), s);
        let c = jwt::Claims { user_id: 1, host_name: None, port: None, logged_in_client_id: 1, logged_in_client_code: None, app_code: None, one_time: false };
        let t = jwt::make(KEY, &c, clock().instant().timestamp(), 600).token;
        assert!(!h.auth.is_remember_me_token(Some(&t)), "remember-me disabled");
        let h = harness();
        let almost = jwt::make(KEY, &c, clock().instant().timestamp(), 525_599).token;
        assert!(h.auth.is_remember_me_token(Some(&almost)), "a minute of slack");
        let short = jwt::make(KEY, &c, clock().instant().timestamp(), 525_598).token;
        assert!(!h.auth.is_remember_me_token(Some(&short)));
    }

    #[tokio::test]
    async fn target_apps_need_trust() {
        let h = harness();
        let (r, ca) = signed(&h, false).await;
        for target in ["appbuilder", "authzump", "crm", " "] {
            let b = OneTimeTokenRequest { target_app_code: Some(target.into()), ..Default::default() };
            assert!(h.auth.make_one_time_token(&b, &r, &ca, false).await.is_ok(), "{target}");
        }
        h.store.with(|d| d.apps.push(app(9, 1, "private")));
        let b = OneTimeTokenRequest { target_app_code: Some("private".into()), ..Default::default() };
        let e = h.auth.make_one_time_token(&b, &r, &ca, false).await.unwrap_err();
        assert_eq!((status(&e), e.message()), (StatusCode::FORBIDDEN, "Permission/Role SSO target app is required to use this operation".to_string()));
        let b = OneTimeTokenRequest { target_app_code: Some("ghost".into()), ..Default::default() };
        assert!(h.auth.make_one_time_token(&b, &r, &ca, false).await.is_err());
        let sourceless = ContextAuth { verified_app_code: None, ..ca.clone() };
        let b = OneTimeTokenRequest { target_app_code: Some("crm".into()), ..Default::default() };
        assert!(h.auth.make_one_time_token(&b, &r, &sourceless, false).await.is_err());
        let from_authzump = ContextAuth { verified_app_code: Some("authzump".into()), ..ca };
        assert!(h.auth.make_one_time_token(&b, &r, &from_authzump, false).await.is_ok());
    }
}

mod refresh_token_tests {
    use super::*;

    #[tokio::test]
    async fn refresh_token_not_authenticated_throws_unauthorized() {
        let h = harness();
        let e = h.auth.refresh_token(&sys_req("appbuilder"), &ContextAuth::default()).await.unwrap_err();
        assert_eq!((status(&e), e.message()), (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()));
    }

    #[tokio::test]
    async fn refresh_token_authenticated_token_not_near_expiry_returns_existing_token() {
        let h = harness();
        let token = sign_in(&h, &sys_req("appbuilder"), &pw("kirangrandhi", "Pass@1234")).await;
        let r = with_bearer(&sys_req("appbuilder"), &token);
        let ca = h.auth.context(&r).await.unwrap();
        let m = h.auth.refresh_token(&r, &ca).await.unwrap().unwrap();
        assert_eq!(m.response.access_token.as_deref(), Some(token.as_str()));
        assert_eq!(m.response.verified_app_code, None, "refresh never sets it");
        assert!(m.cookie.is_none());
    }

    #[tokio::test]
    async fn refresh_token_near_expiry_revokes_and_mints_without_app_code() {
        let h = harness();
        let token = sign_in(&h, &sys_req("appbuilder"), &pw("kirangrandhi", "Pass@1234")).await;
        let later = security::clock::Clock::fixed(clock().instant() + chrono::Duration::minutes(55), 19_800);
        let h2 = harness_with(seed(), later, settings());
        h2.store.with(|d| d.tokens = h.store.with(|o| o.tokens.clone()));
        let mut r = with_bearer(&sys_req("appbuilder"), &token);
        r.headers.insert("cookie", HeaderValue::from_static("Authorization="));
        let ca = h2.auth.context(&r).await.unwrap();
        let m = h2.auth.refresh_token(&r, &ca).await.unwrap().unwrap();
        let new = m.response.access_token.clone().unwrap();
        assert_ne!(new, token);
        let c = jwt::parse(KEY, &new, later.millis()).unwrap();
        assert_eq!((c.app_code, c.host_name.as_deref(), c.logged_in_client_code.as_deref()), (None, Some("apps.local"), Some("SYSTEM")));
        let rows = h2.store.with(|d| d.tokens.clone());
        assert_eq!(rows.len(), 1, "the old token is revoked");
        assert_eq!((rows[0].created_by, rows[0].ip.as_deref()), (Some(142), Some("10.1.2.3")));
        // The blank cookie sent is set again (blank), as Java does.
        assert!(m.cookie.unwrap().starts_with("Authorization=; Max-Age=3600; Expires="));
    }

    #[tokio::test]
    async fn refresh_token_for_a_client_that_is_gone_is_empty() {
        let h = harness();
        let ca = ContextAuth { authenticated: true, user: security::model::ContextUser { client_id: Some(99), ..Default::default() }, ..Default::default() };
        assert!(h.auth.refresh_token(&sys_req("appbuilder"), &ca).await.unwrap().is_none());
        let ca = ContextAuth { authenticated: true, user: security::model::ContextUser { client_id: Some(1), ..Default::default() }, ..Default::default() };
        assert!(h.auth.refresh_token(&sys_req("appbuilder"), &ca).await.is_err(), "no expiry to compare");
    }
}

mod authenticate_with_one_time_token_tests {
    use super::*;
    use security::store::NewOneTimeToken;

    fn ott(h: &Harness, token: &str, user: u64, target: Option<&str>, origin: Option<&str>, mode: Option<&str>, remember: bool) {
        h.store.with(|d| {
            d.otts.push(FakeOtt {
                row: NewOneTimeToken {
                    user_id: user,
                    token: token.into(),
                    remember_me: Some(remember),
                    auth_mode: mode.map(str::to_string),
                    origin_app_code: origin.map(str::to_string),
                    target_app_code: target.map(str::to_string),
                    ..Default::default()
                },
                created_at: Utc::now().naive_utc(),
            })
        });
    }

    use chrono::Utc;

    #[tokio::test]
    async fn authenticate_with_one_time_token_valid_token_returns_auth_response() {
        let h = harness();
        ott(&h, "t1", 142, None, Some("appbuilder"), Some("COOKIE"), true);
        let m = h.auth.redeem_one_time_token("t1", &sys_req("crm"), 0).await.unwrap();
        assert_eq!(m.response.verified_app_code.as_deref(), Some("appbuilder"), "the origin app, not the request's");
        assert!(m.cookie.unwrap().contains("Max-Age=31536000"));
        let ca = m.response.to_context_auth();
        assert!(!ca.authenticated);
        assert!(h.store.with(|d| d.otts.is_empty()));
        assert!(h.auth.redeem_one_time_token("t1", &sys_req("crm"), 0).await.is_err(), "single use");
    }

    #[tokio::test]
    async fn authenticate_with_one_time_token_invalid_token_throws_forbidden() {
        let h = harness();
        let e = h.auth.redeem_one_time_token("nope", &sys_req("appbuilder"), 0).await.unwrap_err();
        assert_eq!((status(&e), e.message()), (StatusCode::FORBIDDEN, "User credentials mismatch".to_string()));
    }

    #[tokio::test]
    async fn authenticate_with_one_time_token_locked_user_throws_forbidden() {
        let h = harness();
        ott(&h, "t", 13, None, None, None, false);
        let e = h.auth.redeem_one_time_token("t", &bus_req("crm"), 0).await.unwrap_err();
        assert_eq!(status(&e), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn authenticate_with_one_time_token_user_not_found_throws_forbidden() {
        let h = harness();
        ott(&h, "t", 999, None, None, None, false);
        assert_eq!(status(&h.auth.redeem_one_time_token("t", &bus_req("crm"), 0).await.unwrap_err()), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn target_app_must_match_the_request() {
        let h = harness();
        ott(&h, "t", 142, Some("crm"), None, None, false);
        let e = h.auth.redeem_one_time_token("t", &sys_req("appbuilder"), 0).await.unwrap_err();
        assert_eq!(e.message(), "Permission/Role SSO target app is required to use this operation");
        h.store.with(|d| d.app_access.push((1, 2)));
        ott(&h, "t2", 142, Some("crm"), None, Some("BEARER"), false);
        let m = h.auth.redeem_one_time_token("t2", &req(&[("clientCode", "SYSTEM")]), 0).await.unwrap();
        assert_eq!(m.response.verified_app_code.as_deref(), Some("crm"));
        assert!(m.cookie.is_none());
        ott(&h, "t3", 142, None, None, None, false);
        let m = h.auth.redeem_one_time_token("t3", &sys_req("appbuilder"), 0).await.unwrap();
        assert_eq!(m.response.verified_app_code.as_deref(), Some("appbuilder"), "neither set: the request's app");
    }

    #[tokio::test]
    async fn stale_token_is_deleted_but_does_not_redeem() {
        // OneTimeTokenRedemptionIntegrationTest.staleTokenIsDeletedButDoesNotRedeem
        let h = harness();
        h.store.with(|d| d.db_now = Some(Utc::now().naive_utc() + chrono::Duration::minutes(10)));
        ott(&h, "old", 142, None, None, None, false);
        h.store.with(|d| d.otts[0].created_at = Utc::now().naive_utc());
        assert!(h.auth.redeem_one_time_token("old", &sys_req("appbuilder"), 0).await.is_err());
        assert!(h.store.with(|d| d.otts.is_empty()));
    }

    #[tokio::test]
    async fn user_outside_the_request_client_is_refused() {
        let h = harness();
        ott(&h, "t", 142, None, Some("appbuilder"), None, false);
        // SYSTEM's user is not under BUS.
        assert!(h.auth.redeem_one_time_token("t", &bus_req("appbuilder"), 0).await.is_err());
    }
}

mod get_user_app_access_tests {
    use super::*;
    use security::tokens::AppAccessRequest;

    async fn ctx(h: &Harness, name: &str, password: &str, r: &security::request::RequestInfo) -> ContextAuth {
        let token = sign_in(h, r, &pw(name, password)).await;
        h.auth.context(&with_bearer(r, &token)).await.unwrap()
    }

    #[tokio::test]
    async fn get_user_app_access_user_has_app_profile_returns_access_with_token() {
        let h = harness();
        let r = sys_req("appbuilder");
        let ca = ctx(&h, "kirangrandhi", "Pass@1234", &r).await;
        let body = AppAccessRequest { app_code: Some("appbuilder".into()), callback_url: Some("https://a/{token}".into()) };
        let v = h.auth.user_app_access(&body, &r, &ca).await.unwrap();
        let t = v["appOneTimeToken"].as_str().unwrap();
        assert_eq!((v["app"].clone(), v["owner"].clone(), v["clientAccess"].clone()), (true.into(), false.into(), false.into()));
        assert_eq!(v["appURL"], format!("https://a/{t}"));
    }

    #[tokio::test]
    async fn get_user_app_access_no_profile_but_owner_with_client_access_returns_access() {
        let h = harness();
        let r = bus_req("crm");
        let ca = ctx(&h, "owner", "secret", &r).await;
        h.store.with(|d| d.apps.push(app(9, 2, "busapp")));
        let v = h.auth.user_app_access(&AppAccessRequest { app_code: Some("busapp".into()), callback_url: None }, &r, &ca).await.unwrap();
        assert_eq!((v["app"].clone(), v["owner"].clone(), v["clientAccess"].clone()), (false.into(), true.into(), true.into()));
        assert!(v.get("appOneTimeToken").is_none());
    }

    #[tokio::test]
    async fn get_user_app_access_no_profile_not_owner_returns_no_access() {
        let h = harness();
        let r = bus_req("crm");
        let ca = ctx(&h, "member", "memberpw", &r).await;
        h.store.with(|d| d.apps.push(app(9, 2, "busapp")));
        let v = h.auth.user_app_access(&AppAccessRequest { app_code: Some("busapp".into()), callback_url: None }, &r, &ca).await.unwrap();
        assert_eq!((v["app"].clone(), v["owner"].clone(), v["clientAccess"].clone()), (false.into(), false.into(), false.into()));
    }

    #[tokio::test]
    async fn get_user_app_access_without_app_code_is_an_error() {
        let h = harness();
        let e = h.auth.user_app_access(&AppAccessRequest::default(), &sys_req("appbuilder"), &ContextAuth::default()).await.unwrap_err();
        assert_eq!(status(&e), StatusCode::INTERNAL_SERVER_ERROR);
        let v = h
            .auth
            .user_app_access(&AppAccessRequest { app_code: Some(" ".into()), callback_url: None }, &sys_req("appbuilder"), &ContextAuth::default())
            .await
            .unwrap();
        assert_eq!(v["app"], false);
    }
}

mod verify_token_tests {
    use super::*;

    #[tokio::test]
    async fn verify_token_signed_in_returns_full_response() {
        let h = harness();
        let token = sign_in(&h, &bus_req("crm"), &pw("member", "memberpw")).await;
        let r = with_bearer(&bus_req("crm"), &token);
        let ca = h.auth.context(&r).await.unwrap();
        let v = h.auth.verify_token(&r, &ca).await.unwrap().unwrap();
        assert_eq!((v.client.code(), v.managed_client_code.as_deref(), v.verified_app_code.as_deref()), ("BUS", Some("SYSTEM"), Some("crm")));
        assert_eq!(v.access_token.as_deref(), Some(token.as_str()));
    }

    #[tokio::test]
    async fn verify_token_without_token_is_forbidden_and_with_a_bad_one_unauthorized() {
        let h = harness();
        let e = h.auth.verify_token(&sys_req("appbuilder"), &ContextAuth::default()).await.unwrap_err();
        assert_eq!((status(&e), e.message()), (StatusCode::FORBIDDEN, "Forbidden".to_string()));
        let e = h.auth.verify_token(&req(&[("authorization", "Bearer junk")]), &ContextAuth::default()).await.unwrap_err();
        assert_eq!((status(&e), e.message()), (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()));
    }

    #[tokio::test]
    async fn verify_token_after_revocation_token_deleted_from_db() {
        let h = harness();
        let token = sign_in(&h, &sys_req("appbuilder"), &pw("kirangrandhi", "Pass@1234")).await;
        let r = with_bearer(&sys_req("appbuilder"), &token);
        let ca = h.auth.context(&r).await.unwrap();
        h.auth.revoke(false, &r, &ca).await.unwrap();
        let ca = h.auth.context(&r).await.unwrap();
        assert!(h.auth.verify_token(&r, &ca).await.is_err());
    }

    #[tokio::test]
    async fn verify_token_for_a_client_that_is_gone_is_empty() {
        let h = harness();
        let ca = ContextAuth { authenticated: true, user: security::model::ContextUser { client_id: Some(99), ..Default::default() }, ..Default::default() };
        assert!(h.auth.verify_token(&sys_req("appbuilder"), &ca).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn revoke_one_token_does_not_affect_other() {
        let h = harness();
        let a = sign_in(&h, &sys_req("appbuilder"), &pw("kirangrandhi", "Pass@1234")).await;
        let b = sign_in(&h, &sys_req("appbuilder"), &pw("kirangrandhi", "Pass@1234")).await;
        let ra = with_bearer(&sys_req("appbuilder"), &a);
        h.auth.revoke(false, &ra, &ContextAuth::default()).await.unwrap();
        assert!(!h.auth.context(&ra).await.unwrap().authenticated);
        assert!(h.auth.context(&with_bearer(&sys_req("appbuilder"), &b)).await.unwrap().authenticated);
    }
}

mod cleanup_tests {
    use super::*;

    #[tokio::test]
    async fn cleanup_removes_expired_unused_and_draft_tokens() {
        let h = harness();
        h.store.with(|d| {
            d.draft_tokens_expired = 2;
            for (id, exp, used) in [(1, "2026-10-15 01:00:00", None), (2, "2026-10-15 05:00:00", Some("2026-01-01 00:00:00")), (3, "2026-10-15 05:00:00", Some("2026-10-14 00:00:00"))] {
                d.tokens.push(FakeToken { id, user_id: 142, token: format!("t{id}"), part: format!("t{id}"), expires_at: dt(exp), last_used: used.map(dt), created_by: None, ip: None });
            }
        });
        let v = h.auth.cleanup_tokens(90).await.unwrap();
        assert_eq!(v, serde_json::json!({"expiredTokensRemoved": 1, "unusedTokensRemoved": 1, "expiredDraftTokensRemoved": 2}));
        // Expiry is compared in UTC: the token expiring at 05:00 UTC is kept although the local
        // clock reads 07:30 (Java's local comparison would have deleted it).
        assert_eq!(h.store.with(|d| d.tokens.iter().map(|t| t.id).collect::<Vec<_>>()), vec![3]);
        let v = h.auth.cleanup_tokens(0).await.unwrap();
        assert_eq!(v["unusedTokensRemoved"], 1);
    }

    #[tokio::test]
    async fn fill_values_without_url() {
        let h = harness();
        assert_eq!(h.auth.fill_values(None, "t"), "");
        assert_eq!(h.auth.fill_values(Some(" "), "t"), "");
    }
}
