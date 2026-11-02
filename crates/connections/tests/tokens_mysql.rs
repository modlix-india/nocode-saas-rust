//! `core_tokens` against a real MySQL: a scratch database this test creates (with the table's
//! DDL from the `core` schema) and drops. Never the real `core` database.
//!
//! `MODLIX_TEST_MYSQL_URL=mysql://root:<password>@127.0.0.1:3306 cargo test -p connections --test tokens_mysql -- --ignored`

use chrono::Duration;
use connections::tokens::{CoreToken, JavaClock, TokenDao, TokenStore, TokenType};
use serde_json::json;
use sqlx::mysql::{MySqlConnectOptions, MySqlPoolOptions};
use sqlx::Executor;

const DDL: &str = "CREATE TABLE `core_tokens` (
  `ID` bigint unsigned NOT NULL AUTO_INCREMENT,
  `USER_ID` bigint unsigned DEFAULT NULL,
  `CLIENT_CODE` char(12) NOT NULL,
  `APP_CODE` char(64) NOT NULL,
  `STATE` char(64) DEFAULT NULL,
  `CONNECTION_NAME` varchar(255) NOT NULL,
  `TOKEN_TYPE` enum('ACCESS','REFRESH') NOT NULL,
  `TOKEN` text,
  `TOKEN_METADATA` json DEFAULT NULL,
  `IS_REVOKED` tinyint(1) NOT NULL DEFAULT '0',
  `EXPIRES_AT` timestamp NULL DEFAULT NULL,
  `IS_LIFETIME_TOKEN` tinyint(1) NOT NULL DEFAULT '0',
  `CREATED_BY` bigint unsigned DEFAULT NULL,
  `UPDATED_BY` bigint unsigned DEFAULT NULL,
  `CREATED_AT` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `UPDATED_AT` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";

#[tokio::test]
#[ignore]
async fn token_dao_on_a_scratch_database() {
    let url = std::env::var("MODLIX_TEST_MYSQL_URL").expect("MODLIX_TEST_MYSQL_URL");
    let db = format!("rust_connections_scratch_{}", uuid::Uuid::new_v4().simple());
    let admin_opts: MySqlConnectOptions = url.parse().unwrap();
    let admin = MySqlPoolOptions::new().max_connections(1).connect_with(admin_opts.clone()).await.unwrap();
    admin.execute(format!("CREATE DATABASE `{db}`").as_str()).await.unwrap();

    // Sessions in UTC, as platform::db::mysql_pool opens them.
    let opts = admin_opts.database(&db).timezone(Some(String::from("+00:00")));
    let pool = MySqlPoolOptions::new().max_connections(2).connect_with(opts).await.unwrap();
    // The checks run in their own task so the database is dropped whether they pass or not.
    let outcome = tokio::spawn(checks(pool.clone())).await;
    pool.close().await;
    admin.execute(format!("DROP DATABASE `{db}`").as_str()).await.unwrap();
    println!("token DAO checked on {db}, dropped");
    if let Err(e) = outcome {
        std::panic::resume_unwind(e.into_panic());
    }
}

async fn checks(pool: sqlx::MySqlPool) {
    pool.execute(DDL).await.unwrap();

    let clock = JavaClock { zone_offset_seconds: 19_800 };
    let dao = TokenDao::new(pool.clone(), clock);
    let base = CoreToken {
        client_code: Some("SYSTEM".into()),
        app_code: Some("app".into()),
        connection_name: Some("conn".into()),
        token_type: Some(TokenType::Access),
        token: Some("t1".into()),
        user_id: Some(142),
        state: Some("st".into()),
        expires_at: Some(clock.now() + Duration::seconds(600)),
        token_metadata: Some(json!({"scope": "a b", "n": 1}).as_object().unwrap().clone()),
        ..Default::default()
    };
    let created = dao.create(&base).await.unwrap();
    assert!(created.id.is_some());
    assert_eq!(created.is_revoked, Some(false), "the column default");
    assert_eq!(created.is_lifetime_token, Some(false));
    assert_eq!(created.token_metadata.as_ref().unwrap()["scope"], "a b");
    assert!(created.created_at.is_some());
    // The wall value written comes back as it is (MySQL rounds it to the second).
    let drift = (created.expires_at.unwrap() - base.expires_at.unwrap()).num_milliseconds().abs();
    assert!(drift <= 1000, "{drift}");

    let tuple = dao.active_access_token_tuple("SYSTEM", "app", "conn").await.unwrap().unwrap();
    assert_eq!(tuple.0.as_deref(), Some("t1"));
    assert_eq!(dao.active_token("SYSTEM", "app", "conn", TokenType::Access).await.unwrap().unwrap().id, created.id);
    assert!(dao.active_token("SYSTEM", "app", "conn", TokenType::Refresh).await.unwrap().is_none());
    assert_eq!(dao.by_state(Some("st")).await.unwrap().unwrap().id, created.id);
    // The consent's first row, scoped to the client, app and connection.
    assert_eq!(dao.consent_row("SYSTEM", "app", "conn", "st").await.unwrap().unwrap().id, created.id);
    assert!(dao.consent_row("OTHER", "app", "conn", "st").await.unwrap().is_none());
    assert!(dao.consent_row("SYSTEM", "app2", "conn", "st").await.unwrap().is_none());
    assert!(dao.by_state(None).await.unwrap().is_none());

    // A lifetime refresh token without an expiry is active; an expired access token is not.
    dao.create(&CoreToken { token_type: Some(TokenType::Refresh), token: Some("r".into()), expires_at: None, is_lifetime_token: Some(true), ..base.clone() })
        .await
        .unwrap();
    assert_eq!(dao.active_token("SYSTEM", "app", "conn", TokenType::Refresh).await.unwrap().unwrap().token.as_deref(), Some("r"));
    dao.create(&CoreToken { connection_name: Some("old".into()), expires_at: Some(clock.now() - Duration::seconds(5)), ..base.clone() })
        .await
        .unwrap();
    assert!(dao.active_token("SYSTEM", "app", "old", TokenType::Access).await.unwrap().is_none());

    // Update writes the entity back (revoked flag included), then reads it.
    let mut changed = created.clone();
    changed.token = Some("t2".into());
    changed.is_revoked = Some(true);
    let updated = dao.update(&changed).await.unwrap().unwrap();
    assert_eq!((updated.token.as_deref(), updated.is_revoked), (Some("t2"), Some(true)));
    assert!(dao.update(&CoreToken::default()).await.unwrap().is_none());

    // Revoke by type, then everything.
    assert!(dao.revoke("SYSTEM", "app", "conn", Some(TokenType::Refresh)).await.unwrap());
    assert!(!dao.revoke("SYSTEM", "app", "conn", Some(TokenType::Refresh)).await.unwrap());
    assert!(dao.revoke("SYSTEM", "app", "old", None).await.unwrap());
    assert!(dao.active_token("SYSTEM", "app", "conn", TokenType::Refresh).await.unwrap().is_none());
}
