//! The MySQL store against the local `security` schema, ported from `TokenDAOIntegrationTest`,
//! `OtpDAOIntegrationTest` and `OneTimeTokenRedemptionIntegrationTest` (which run on their own
//! test containers in Java).
//!
//! Gated: runs only with `SECURITY_AUTH_LIVE=1` and `MODLIX__DATABASE__PASSWORD` (source
//! `config/local.toml`). Local stack only. It never creates users and never changes a real user:
//! rows it writes are dummy tokens, OTPs and one-time tokens for user 142, deleted again; the
//! counter, lock and cleanup statements run against a user id that does not exist or a cut-off
//! in the past, so they execute and touch nothing.

use std::sync::Arc;

use chrono::{NaiveDateTime, Utc};
use platform::config::MySqlConfig;
use security::model::{Origin, PassType};
use security::mysql::MySqlStore;
use security::store::{IdentifierType, NewOneTimeToken, NewOtp, NewToken, Store, UserQuery};

const NOBODY: u64 = 9_000_000_001;

async fn store() -> Option<Arc<MySqlStore>> {
    let (Ok(_), Ok(password)) = (std::env::var("SECURITY_AUTH_LIVE"), std::env::var("MODLIX__DATABASE__PASSWORD")) else {
        eprintln!("skipped: SECURITY_AUTH_LIVE / MODLIX__DATABASE__PASSWORD not set");
        return None;
    };
    let cfg = MySqlConfig { database: "security".into(), password, max_connections: 4, ..Default::default() };
    Some(Arc::new(MySqlStore::new(platform::db::mysql_pool(&cfg).await.unwrap())))
}

fn token_value(tag: &str) -> String {
    format!("security-auth-live-test-{tag}-{}-{}", std::process::id(), Utc::now().timestamp_nanos_opt().unwrap_or(0))
}

fn new_token(tag: &str, expires: NaiveDateTime) -> NewToken {
    let token = token_value(tag);
    NewToken {
        user_id: 142,
        part_token: security::context::part_token(&token).to_string(),
        token,
        expires_at: expires,
        origin: Origin { ip_address: Some("127.0.0.1".into()), user_agent: Some("live test".into()), ..Default::default() },
        created_by: Some(0),
    }
}

#[tokio::test]
async fn token_dao_lifecycle() {
    let Some(s) = store().await else { return };
    let t = new_token("a", Utc::now().naive_utc() + chrono::Duration::minutes(5));
    let id = s.insert_token(&t).await.unwrap();
    let rows = s.tokens_by_part(&t.part_token).await.unwrap();
    assert!(rows.iter().any(|r| r.id == id && r.token == t.token && r.user_id == 142));
    // createViaDaoAndVerifyViaGetTokensOfId
    assert!(s.token_strings_of_user(142).await.unwrap().contains(&t.token));
    // updateLastUsedAt_ExistingToken_UpdatesTimestamp / _NonExistent_ReturnsZero
    assert_eq!(s.update_last_used(id, Utc::now().naive_utc()).await.unwrap(), 1);
    assert_eq!(s.update_last_used(u64::MAX, Utc::now().naive_utc()).await.unwrap(), 0);
    // deleteExpiredTokens_NoneExpired_ReturnsZero / deleteUnusedTokens_KeepsRecentlyUsed: a
    // cut-off in the past touches nothing.
    let past = NaiveDateTime::parse_from_str("2000-01-01 00:00:00", "%Y-%m-%d %H:%M:%S").unwrap();
    assert_eq!(s.delete_expired_tokens(past).await.unwrap(), 0);
    assert_eq!(s.delete_unused_tokens(past).await.unwrap(), 0);
    assert_eq!(s.delete_expired_draft_tokens(past).await.unwrap(), 0);
    // tokensGoneAfterDelete
    assert_eq!(s.delete_token(id).await.unwrap(), 1);
    assert_eq!(s.delete_token(id).await.unwrap(), 0);
    assert!(s.tokens_by_part(&t.part_token).await.unwrap().is_empty());
    // noTokensForUser / deleteAllTokensReturnsCount for nobody
    assert!(s.token_strings_of_user(NOBODY).await.unwrap().is_empty());
    assert_eq!(s.delete_tokens_of_user(NOBODY).await.unwrap(), 0);
}

#[tokio::test]
async fn one_time_token_redemption() {
    let Some(s) = store().await else { return };
    // freshTokenRedeemsOnce
    let token = format!("{:0>32}", Utc::now().timestamp_nanos_opt().unwrap_or(0) % 1_000_000_000_000);
    let t = NewOneTimeToken {
        user_id: 142,
        token: token.clone(),
        origin: Origin { ip_address: Some("127.0.0.1".into()), ..Default::default() },
        remember_me: None,
        auth_mode: None,
        origin_app_code: Some("appbuilder".into()),
        target_app_code: None,
    };
    s.insert_one_time_token(&t).await.unwrap();
    let r = s.redeem_one_time_token(&token, 5).await.unwrap().unwrap();
    assert_eq!((r.user_id, r.remember_me, r.auth_mode.as_deref(), r.origin_app_code.as_deref()), (142, false, Some("BEARER"), Some("appbuilder")));
    assert!(s.redeem_one_time_token(&token, 5).await.unwrap().is_none());
    // staleTokenIsDeletedButDoesNotRedeem: a zero-minute window is already past.
    let stale = format!("{}s", &token[..31]);
    s.insert_one_time_token(&NewOneTimeToken { token: stale.clone(), remember_me: Some(true), auth_mode: Some("COOKIE".into()), ..t.clone() }).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    assert!(s.redeem_one_time_token(&stale, 0).await.unwrap().is_none());
    assert!(s.redeem_one_time_token(&stale, 5).await.unwrap().is_none(), "deleted all the same");
    // concurrentRedemptionsGiveOneSession
    let twice = format!("{}c", &token[..31]);
    s.insert_one_time_token(&NewOneTimeToken { token: twice.clone(), ..t }).await.unwrap();
    let (a, b) = tokio::join!(s.redeem_one_time_token(&twice, 5), s.redeem_one_time_token(&twice, 5));
    assert_eq!([a.unwrap().is_some(), b.unwrap().is_some()].iter().filter(|x| **x).count(), 1);
}

#[tokio::test]
async fn otp_dao() {
    let Some(s) = store().await else { return };
    let now = Utc::now().naive_utc();
    let purpose = format!("LIVE_TEST_{}", std::process::id());
    let otp = |code: &str, at: NaiveDateTime| NewOtp {
        app_id: 2,
        user_id: Some(142),
        email_id: Some("live-test@example.com".into()),
        phone_number: None,
        purpose: purpose.clone(),
        target_type: "EMAIL".into(),
        unique_code: code.into(),
        expires_at: at + chrono::Duration::minutes(5),
        ip_address: Some("127.0.0.1".into()),
        created_at: at,
    };
    // multipleOtps_ReturnsLatest
    s.insert_otp(&otp("first", now - chrono::Duration::minutes(1))).await.unwrap();
    s.insert_otp(&otp("second", now)).await.unwrap();
    let latest = s.latest_otp(2, 142, &purpose).await.unwrap().unwrap();
    assert_eq!((latest.unique_code.as_str(), latest.verify_legs_counts), ("second", 0));
    assert_eq!(s.latest_otp_code(2, 142, &purpose).await.unwrap().as_deref(), Some("second"));
    // differentPurpose / differentApp / no user
    assert!(s.latest_otp(2, 142, "NO_SUCH_PURPOSE").await.unwrap().is_none());
    assert!(s.latest_otp(1, 142, &purpose).await.unwrap().is_none());
    assert!(s.latest_otp(2, NOBODY, &purpose).await.unwrap().is_none());
    // multipleIncrements_AccumulateCorrectly
    assert!(s.increase_otp_verify_count(latest.id).await.unwrap());
    assert!(s.increase_otp_verify_count(latest.id).await.unwrap());
    assert_eq!(s.latest_otp(2, 142, &purpose).await.unwrap().unwrap().verify_legs_counts, 2);
    assert!(!s.increase_otp_verify_count(u64::MAX).await.unwrap());
    // Clean up both rows.
    let mut n = 0;
    while let Some(o) = s.latest_otp(2, 142, &purpose).await.unwrap() {
        n += s.delete_otp(o.id).await.unwrap();
    }
    assert_eq!(n, 2);
}

#[tokio::test]
async fn user_reads_and_writes_that_touch_nobody() {
    let Some(s) = store().await else { return };
    let u = s.user_by_id(142).await.unwrap().unwrap();
    assert_eq!((u.id, u.client_id), (142, 1));
    assert!(s.user_by_id(NOBODY).await.unwrap().is_none());
    let q = UserQuery {
        user_name: u.user_name.clone(),
        identifier: IdentifierType::UserName,
        client_code: Some("SYSTEM".into()),
        app_code: Some("appbuilder".into()),
        active_client_only: true,
        limit: 2,
        ..Default::default()
    };
    assert_eq!(s.users_by(&q).await.unwrap().iter().map(|u| u.id).collect::<Vec<_>>(), vec![142]);
    let by_id = UserQuery { user_name: None, user_id: Some(142), app_code: None, active_client_only: false, ..q.clone() };
    assert_eq!(s.users_by(&by_id).await.unwrap().len(), 1);
    for ident in [IdentifierType::EmailId, IdentifierType::PhoneNumber] {
        let q = UserQuery { identifier: ident, user_name: Some("nobody-at-all@example.invalid".into()), ..q.clone() };
        assert!(s.users_by(&q).await.unwrap().is_empty());
    }
    assert!(s.users_by(&UserQuery { client_code: None, ..q.clone() }).await.unwrap().is_empty());
    assert!(s.owner_user_ids(&[]).await.unwrap().is_empty());
    let _ = s.owner_user_ids(&[142, NOBODY]).await.unwrap();
    let _ = s.is_user_owner(142).await.unwrap();
    // The counter, lock and unlock statements, on a user id that does not exist.
    for t in [PassType::Password, PassType::Pin, PassType::Otp] {
        assert_eq!(s.increase_failed_attempt(NOBODY, t).await.unwrap(), None);
        assert!(!s.reset_failed_attempt(NOBODY, t).await.unwrap());
    }
    assert_eq!(s.increase_resend_attempts(NOBODY).await.unwrap(), None);
    assert!(!s.reset_resend_attempts(NOBODY).await.unwrap());
    assert!(!s.lock_user(NOBODY, Utc::now().naive_utc(), "Password").await.unwrap());
    assert!(!s.unlock_user(NOBODY).await.unwrap());
    // A sign-in's own reset, on 142 whose counters are 0 already: rows matched, nothing changes.
    let before = s.user_by_id(142).await.unwrap().unwrap();
    if before.no_failed_attempt == Some(0) {
        s.reset_failed_attempt(142, PassType::Password).await.unwrap();
    }
}

#[tokio::test]
async fn client_app_and_policy_reads() {
    let Some(s) = store().await else { return };
    let c = s.client_by_id(1).await.unwrap().unwrap();
    assert_eq!(c.code.as_deref(), Some("SYSTEM"));
    assert_eq!(s.client_by_code("SYSTEM").await.unwrap().unwrap().id, Some(1));
    assert!(s.client_by_code("NO_SUCH_CLIENT").await.unwrap().is_none());
    assert!(s.client_by_id(NOBODY).await.unwrap().is_none());
    assert_eq!(s.client_type_code_level(1).await.unwrap().unwrap(), ("SYS".to_string(), "SYSTEM".to_string(), "SYSTEM".to_string()));
    assert!(s.client_type_code_level(NOBODY).await.unwrap().is_none());
    let h = s.client_hierarchy(28).await.unwrap().unwrap();
    assert_eq!(h.client_ids().first(), Some(&28));
    assert!(s.client_hierarchy(NOBODY).await.unwrap().is_none());
    assert_eq!(s.count_active_clients(&[1]).await.unwrap(), 1);
    assert_eq!(s.count_active_clients(&[]).await.unwrap(), 0);
    assert!(!s.client_url_patterns().await.unwrap().is_empty());
    let app = s.app_by_code("appbuilder").await.unwrap().unwrap();
    assert_eq!(s.app_by_id(app.id).await.unwrap().unwrap().app_code, "appbuilder");
    assert!(s.app_by_code("no-such-app-code").await.unwrap().is_none());
    assert!(s.app_by_id(NOBODY).await.unwrap().is_none());
    assert!(s.has_read_access("appbuilder", "SYSTEM").await.unwrap());
    assert!(!s.has_read_access("appbuilder", "NO_SUCH_CLIENT").await.unwrap());
    let _ = s.has_dependency_either_direction(132, 148).await.unwrap();
    for t in [PassType::Password, PassType::Pin, PassType::Otp] {
        let _ = s.policy(t, 1, app.id).await.unwrap();
    }
    let otp = s.policy(PassType::Otp, 1, 213).await.unwrap();
    if let Some(p) = otp {
        assert!(p.otp.is_some());
    }
    assert!(s.policy(PassType::Password, NOBODY, 1).await.unwrap().is_none());
    assert!(s.state_by_value("no-such-state").await.unwrap().is_none());
    assert!(!s.consume_state("no-such-state").await.unwrap());
}

#[tokio::test]
async fn authority_reads_for_user_142() {
    let Some(s) = store().await else { return };
    let roles = s.user_roles(142).await.unwrap();
    let ids: Vec<u64> = roles.iter().filter_map(|r| r.id).collect();
    let _ = s.role_permissions(&ids).await.unwrap();
    let profiles = s.profile_ids(Some("appbuilder"), 142).await.unwrap();
    assert!(!profiles.is_empty());
    assert!(!s.profile_ids(None, 142).await.unwrap().is_empty());
    let _ = s.default_profile_ids(Some("appbuilder")).await.unwrap();
    let rows = s.profile_rows(profiles[0], &[1]).await.unwrap();
    let role_rows = s.profile_role_rows(&[profiles[0]]).await.unwrap();
    assert!(!rows.is_empty() && !role_rows.is_empty());
    let role_ids: Vec<u64> = role_rows.iter().filter_map(|r| r.role_id).collect();
    let _ = s.sub_role_rows(&role_ids).await.unwrap();
    assert!(!s.permission_rows(&role_ids).await.unwrap().is_empty() || role_ids.is_empty());
    assert!(s.user_has_any_profile(142, "appbuilder").await.unwrap());
    let app = s.app_by_code("appbuilder").await.unwrap().unwrap();
    assert!(s.has_assigned_profile(142, app.id).await.unwrap());
    assert!(s.user_app_having_profile(142).await.unwrap().is_some());
    assert!(s.user_app_having_profile(NOBODY).await.unwrap().is_none());
}

#[tokio::test]
async fn sox_log_insert() {
    let Some(s) = store().await else { return };
    s.insert_sox_log(NOBODY, "OTHER", "USER", "security-auth live test").await.unwrap();
}

/// `identityExistsInClientFamily` (QA-0445) over the local data: a user's own email is found in
/// their business (the client below SYSTEM their client belongs to), a made-up one is not, and
/// SYSTEM (no business) never matches.
#[tokio::test]
async fn identity_in_a_business_family() {
    let (Ok(_), Ok(password)) = (std::env::var("SECURITY_AUTH_LIVE"), std::env::var("MODLIX__DATABASE__PASSWORD")) else {
        eprintln!("skipped: SECURITY_AUTH_LIVE / MODLIX__DATABASE__PASSWORD not set");
        return;
    };
    let cfg = MySqlConfig { database: "security".into(), password, max_connections: 2, ..Default::default() };
    let pool = platform::db::mysql_pool(&cfg).await.unwrap();
    let db = security::data::Db::new(pool.clone());
    // A user of a business client (directly under SYSTEM) with an email.
    let row: Option<(u64, String)> = sqlx::query_as(
        "SELECT u.CLIENT_ID, u.EMAIL_ID FROM security_user u JOIN security_client_hierarchy h ON h.CLIENT_ID = u.CLIENT_ID \
         WHERE h.MANAGE_CLIENT_LEVEL_0 = 1 AND h.MANAGE_CLIENT_LEVEL_1 IS NULL AND u.STATUS_CODE <> 'DELETED' \
         AND u.EMAIL_ID IS NOT NULL AND u.EMAIL_ID <> '' AND u.EMAIL_ID <> 'NONE' LIMIT 1",
    )
    .fetch_optional(&pool)
    .await
    .unwrap();
    let Some((client, email)) = row else { return };
    assert!(db.identity_exists_in_client_family(Some(client), Some(&email), None).await.unwrap());
    assert!(!db.identity_exists_in_client_family(Some(client), Some("zz-nobody@example.invalid"), Some("+000")).await.unwrap());
    assert!(!db.identity_exists_in_client_family(None, Some(&email), None).await.unwrap(), "no business");
    assert!(!db.identity_exists_in_client_family(Some(client), Some(" "), Some("NONE")).await.unwrap(), "no identity to look for");
}
