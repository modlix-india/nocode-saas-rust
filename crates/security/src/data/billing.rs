//! The billing tables: `AppBillingConfigDAO`, `WalletDAO`, `WalletTransactionDAO` and
//! `MeteringCountDAO`, behind a trait so the wallet rules can be tested without debiting real
//! wallets.

use async_trait::async_trait;
use chrono::NaiveDate;
use sqlx::mysql::MySqlRow;
use sqlx::Row;

use super::Db;
use crate::decimal::Dec;
use crate::errors::{AuthError, AuthResult};

/// `BillingActionKeys`.
pub mod action {
    pub const APP_RENT: &str = "security.app.rent";
    pub const SITE_RENT: &str = "security.site.rent";
    pub const USER: &str = "security.user";
    pub const STORAGE_ROWS: &str = "core.storage.rows";
    pub const DEALS: &str = "entityprocessor.deals";
    pub const FILES_GB: &str = "files.gb";
    pub const AI_LLM_TOKENS: &str = "ai.llm.tokens";
}

/// `AppBillingConfigDAO.rateField`: the rate column of an action, if it has one.
pub fn rate_column(action_key: &str) -> Option<&'static str> {
    Some(match action_key {
        action::APP_RENT => "APP_RENT_PER_MONTH",
        action::SITE_RENT => "SITE_RENT_PER_MONTH",
        action::USER => "USER_TOKENS_PER_MONTH",
        action::STORAGE_ROWS => "STORAGE_ROW_TOKENS_PER_MONTH",
        action::DEALS => "DEAL_TOKENS_PER_MONTH",
        action::FILES_GB => "FILES_TOKENS_PER_MONTH",
        action::AI_LLM_TOKENS => "AI_TOKENS_PER_MILLION",
        _ => return None,
    })
}

/// A `security_app_billing_config` row (the columns the wallet rules read).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct BillingConfig {
    pub id: u64,
    pub client_id: u64,
    pub app_id: u64,
    pub app_rent_per_month: Option<Dec>,
    pub site_rent_per_month: Option<Dec>,
    pub files_tokens_per_month: Option<Dec>,
    pub storage_row_tokens_per_month: Option<Dec>,
    pub deal_tokens_per_month: Option<Dec>,
    pub user_tokens_per_month: Option<Dec>,
    pub ai_tokens_per_million: Option<Dec>,
    pub free_apps: Option<Dec>,
    pub free_sites: Option<Dec>,
    pub free_files_gb: Option<Dec>,
    pub free_storage_rows: Option<Dec>,
    pub free_deals: Option<Dec>,
    pub free_users: Option<Dec>,
    pub free_ai_tokens_per_month: Option<Dec>,
    pub low_balance_threshold: Option<Dec>,
    pub suspend_app_code: Option<String>,
    pub suspend_client_code: Option<String>,
    pub status: String,
}

impl BillingConfig {
    /// `WalletService.rateFor`.
    pub fn rate_for(&self, action_key: &str) -> Option<Dec> {
        match action_key {
            action::APP_RENT => self.app_rent_per_month,
            action::SITE_RENT => self.site_rent_per_month,
            action::USER => self.user_tokens_per_month,
            action::STORAGE_ROWS => self.storage_row_tokens_per_month,
            action::DEALS => self.deal_tokens_per_month,
            action::FILES_GB => self.files_tokens_per_month,
            action::AI_LLM_TOKENS => self.ai_tokens_per_million,
            _ => None,
        }
    }

    /// `WalletService.freeFor`: zero for an unknown action.
    pub fn free_for(&self, action_key: &str) -> Option<Dec> {
        match action_key {
            action::APP_RENT => self.free_apps,
            action::SITE_RENT => self.free_sites,
            action::USER => self.free_users,
            action::STORAGE_ROWS => self.free_storage_rows,
            action::DEALS => self.free_deals,
            action::FILES_GB => self.free_files_gb,
            action::AI_LLM_TOKENS => self.free_ai_tokens_per_month,
            _ => Some(Dec::ZERO),
        }
    }

    pub fn is_active(&self) -> bool {
        self.status == "ACTIVE"
    }
}

/// A `security_wallet` row.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Wallet {
    pub id: u64,
    pub client_id: u64,
    pub app_id: u64,
    pub balance: Dec,
    pub status: String,
    pub alert_threshold: Option<Dec>,
    pub low_balance_notified: Option<i8>,
}

impl Wallet {
    pub fn suspended(&self) -> bool {
        self.status == "SUSPENDED"
    }
}

/// A `security_wallet_transaction` to insert.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Txn {
    pub wallet_id: u64,
    pub kind: &'static str,
    pub tokens: Dec,
    pub balance_after: Dec,
    pub action_key: Option<String>,
    pub app_id: Option<u64>,
    pub quantity: Option<Dec>,
    pub charge_date: Option<NaiveDate>,
    pub window_index: Option<i16>,
    pub idempotency_key: String,
    pub reason: String,
    pub created_by: Option<u64>,
}

/// `MeteringInstruction`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Instruction {
    pub config_client_code: String,
    pub config_client_id: u64,
    pub app_code: String,
    pub app_id: u64,
    pub billed_client_code: String,
    pub billed_client_id: u64,
}

impl Instruction {
    pub fn to_json(&self) -> serde_json::Value {
        crate::jackson::Obj::new()
            .put("configClientCode", self.config_client_code.as_str())
            .put("configClientId", self.config_client_id)
            .put("appCode", self.app_code.as_str())
            .put("appId", self.app_id)
            .put("billedClientCode", self.billed_client_code.as_str())
            .put("billedClientId", self.billed_client_id)
            .build()
    }
}

#[async_trait]
pub trait BillingStore: Send + Sync {
    /// `findByAppAndClient`: the first non-DELETED config.
    async fn config_by_app_client(&self, app_id: u64, client_id: u64) -> AuthResult<Option<BillingConfig>>;
    /// `findByAppCodeAndClientCode`: the ACTIVE config.
    async fn config_by_codes(&self, app_code: &str, client_code: &str) -> AuthResult<Option<BillingConfig>>;
    async fn charge_instructions(&self, action_key: &str) -> AuthResult<Vec<Instruction>>;
    async fn wallet(&self, client_id: u64, app_id: u64) -> AuthResult<Option<Wallet>>;
    /// `createSeeded`: insert if absent (a race loses quietly), then read.
    async fn create_seeded_wallet(&self, client_id: u64, app_id: u64, initial: Dec) -> AuthResult<Option<Wallet>>;
    /// `recordTxn`: false when the idempotency key was already used.
    async fn record_txn(&self, t: &Txn) -> AuthResult<bool>;
    async fn debit(&self, wallet_id: u64, tokens: Dec) -> AuthResult<u64>;
    async fn set_status(&self, wallet_id: u64, status: &str) -> AuthResult<u64>;
    async fn set_low_balance_notified(&self, wallet_id: u64, notified: bool) -> AuthResult<u64>;
    async fn sum_quantity_between(&self, wallet_id: u64, action_key: &str, from: NaiveDate, to: NaiveDate) -> AuthResult<Dec>;
    async fn charged_windows(&self, wallet_id: u64, action_key: &str, date: NaiveDate) -> AuthResult<Vec<i16>>;
    /// `countAppsByType`.
    async fn count_apps(&self, client_id: u64, app_type: &str) -> AuthResult<i64>;
    /// `countUsersWithProfileInApp`.
    async fn count_users_with_profile(&self, client_id: u64, app_id: u64) -> AuthResult<i64>;
}

const CONFIG_COLUMNS: &str = "c.ID, c.CLIENT_ID, c.APP_ID, CAST(c.APP_RENT_PER_MONTH AS CHAR) APP_RENT_PER_MONTH, \
    CAST(c.SITE_RENT_PER_MONTH AS CHAR) SITE_RENT_PER_MONTH, CAST(c.FILES_TOKENS_PER_MONTH AS CHAR) FILES_TOKENS_PER_MONTH, \
    CAST(c.STORAGE_ROW_TOKENS_PER_MONTH AS CHAR) STORAGE_ROW_TOKENS_PER_MONTH, \
    CAST(c.DEAL_TOKENS_PER_MONTH AS CHAR) DEAL_TOKENS_PER_MONTH, CAST(c.USER_TOKENS_PER_MONTH AS CHAR) USER_TOKENS_PER_MONTH, \
    CAST(c.AI_TOKENS_PER_MILLION AS CHAR) AI_TOKENS_PER_MILLION, CAST(c.FREE_APPS AS CHAR) FREE_APPS, \
    CAST(c.FREE_SITES AS CHAR) FREE_SITES, CAST(c.FREE_FILES_GB AS CHAR) FREE_FILES_GB, \
    CAST(c.FREE_STORAGE_ROWS AS CHAR) FREE_STORAGE_ROWS, CAST(c.FREE_DEALS AS CHAR) FREE_DEALS, \
    CAST(c.FREE_USERS AS CHAR) FREE_USERS, CAST(c.FREE_AI_TOKENS_PER_MONTH AS CHAR) FREE_AI_TOKENS_PER_MONTH, \
    CAST(c.LOW_BALANCE_THRESHOLD AS CHAR) LOW_BALANCE_THRESHOLD, c.SUSPEND_APP_CODE, c.SUSPEND_CLIENT_CODE, c.STATUS";

const WALLET_COLUMNS: &str = "ID, CLIENT_ID, APP_ID, CAST(BALANCE AS CHAR) BALANCE, STATUS, \
    CAST(ALERT_THRESHOLD AS CHAR) ALERT_THRESHOLD, LOW_BALANCE_NOTIFIED";

fn dec(row: &MySqlRow, col: &str) -> AuthResult<Option<Dec>> {
    match row.try_get::<Option<String>, _>(col)? {
        None => Ok(None),
        Some(s) => Dec::parse(&s).map(Some).ok_or_else(|| AuthError::internal(format!("{col} is not a number: {s}"))),
    }
}

fn config(row: &MySqlRow) -> AuthResult<BillingConfig> {
    Ok(BillingConfig {
        id: row.try_get("ID")?,
        client_id: row.try_get("CLIENT_ID")?,
        app_id: row.try_get("APP_ID")?,
        app_rent_per_month: dec(row, "APP_RENT_PER_MONTH")?,
        site_rent_per_month: dec(row, "SITE_RENT_PER_MONTH")?,
        files_tokens_per_month: dec(row, "FILES_TOKENS_PER_MONTH")?,
        storage_row_tokens_per_month: dec(row, "STORAGE_ROW_TOKENS_PER_MONTH")?,
        deal_tokens_per_month: dec(row, "DEAL_TOKENS_PER_MONTH")?,
        user_tokens_per_month: dec(row, "USER_TOKENS_PER_MONTH")?,
        ai_tokens_per_million: dec(row, "AI_TOKENS_PER_MILLION")?,
        free_apps: dec(row, "FREE_APPS")?,
        free_sites: dec(row, "FREE_SITES")?,
        free_files_gb: dec(row, "FREE_FILES_GB")?,
        free_storage_rows: dec(row, "FREE_STORAGE_ROWS")?,
        free_deals: dec(row, "FREE_DEALS")?,
        free_users: dec(row, "FREE_USERS")?,
        free_ai_tokens_per_month: dec(row, "FREE_AI_TOKENS_PER_MONTH")?,
        low_balance_threshold: dec(row, "LOW_BALANCE_THRESHOLD")?,
        suspend_app_code: row.try_get("SUSPEND_APP_CODE")?,
        suspend_client_code: row.try_get("SUSPEND_CLIENT_CODE")?,
        status: row.try_get("STATUS")?,
    })
}

fn wallet(row: &MySqlRow) -> AuthResult<Wallet> {
    Ok(Wallet {
        id: row.try_get("ID")?,
        client_id: row.try_get("CLIENT_ID")?,
        app_id: row.try_get("APP_ID")?,
        balance: dec(row, "BALANCE")?.unwrap_or(Dec::ZERO),
        status: row.try_get("STATUS")?,
        alert_threshold: dec(row, "ALERT_THRESHOLD")?,
        low_balance_notified: row.try_get("LOW_BALANCE_NOTIFIED")?,
    })
}

#[async_trait]
impl BillingStore for Db {
    async fn config_by_app_client(&self, app_id: u64, client_id: u64) -> AuthResult<Option<BillingConfig>> {
        let sql = format!(
            "SELECT {CONFIG_COLUMNS} FROM security_app_billing_config c WHERE c.APP_ID = ? AND c.CLIENT_ID = ? AND c.STATUS <> 'DELETED' LIMIT 1"
        );
        let row = sqlx::query(&sql).bind(app_id).bind(client_id).fetch_optional(&self.pool).await?;
        row.as_ref().map(config).transpose()
    }

    async fn config_by_codes(&self, app_code: &str, client_code: &str) -> AuthResult<Option<BillingConfig>> {
        let sql = format!(
            "SELECT {CONFIG_COLUMNS} FROM security_app_billing_config c JOIN security_app ON security_app.ID = c.APP_ID \
             JOIN security_client ON security_client.ID = c.CLIENT_ID WHERE security_app.APP_CODE = ? \
             AND security_client.CODE = ? AND c.STATUS = 'ACTIVE' LIMIT 1"
        );
        let row = sqlx::query(&sql).bind(app_code).bind(client_code).fetch_optional(&self.pool).await?;
        row.as_ref().map(config).transpose()
    }

    async fn charge_instructions(&self, action_key: &str) -> AuthResult<Vec<Instruction>> {
        let Some(rate) = rate_column(action_key) else { return Ok(vec![]) };
        let sql = format!(
            "SELECT cc.CODE, c.CLIENT_ID, security_app.APP_CODE, c.APP_ID, mc.CODE, security_client_hierarchy.CLIENT_ID \
             FROM security_app_billing_config c JOIN security_app ON security_app.ID = c.APP_ID \
             JOIN security_client cc ON cc.ID = c.CLIENT_ID \
             JOIN security_client_hierarchy ON security_client_hierarchy.MANAGE_CLIENT_LEVEL_0 = c.CLIENT_ID \
             JOIN security_client mc ON mc.ID = security_client_hierarchy.CLIENT_ID \
             WHERE c.STATUS = 'ACTIVE' AND c.{rate} > 0"
        );
        let rows = sqlx::query(&sql).fetch_all(&self.pool).await?;
        rows.iter()
            .map(|r| {
                Ok(Instruction {
                    config_client_code: r.try_get(0)?,
                    config_client_id: r.try_get(1)?,
                    app_code: r.try_get(2)?,
                    app_id: r.try_get(3)?,
                    billed_client_code: r.try_get(4)?,
                    billed_client_id: r.try_get(5)?,
                })
            })
            .collect()
    }

    async fn wallet(&self, client_id: u64, app_id: u64) -> AuthResult<Option<Wallet>> {
        sql::wallet(&mut *self.pool.acquire().await?, client_id, app_id).await
    }

    async fn create_seeded_wallet(&self, client_id: u64, app_id: u64, initial: Dec) -> AuthResult<Option<Wallet>> {
        sql::create_seeded_wallet(&mut *self.pool.acquire().await?, client_id, app_id, initial).await
    }

    async fn record_txn(&self, t: &Txn) -> AuthResult<bool> {
        sql::record_txn(&mut *self.pool.acquire().await?, t).await
    }

    async fn debit(&self, wallet_id: u64, tokens: Dec) -> AuthResult<u64> {
        sql::debit(&mut *self.pool.acquire().await?, wallet_id, tokens).await
    }

    async fn set_status(&self, wallet_id: u64, status: &str) -> AuthResult<u64> {
        sql::set_status(&mut *self.pool.acquire().await?, wallet_id, status).await
    }

    async fn set_low_balance_notified(&self, wallet_id: u64, notified: bool) -> AuthResult<u64> {
        sql::set_low_balance_notified(&mut *self.pool.acquire().await?, wallet_id, notified).await
    }

    async fn sum_quantity_between(&self, wallet_id: u64, action_key: &str, from: NaiveDate, to: NaiveDate) -> AuthResult<Dec> {
        sql::sum_quantity_between(&mut *self.pool.acquire().await?, wallet_id, action_key, from, to).await
    }

    async fn charged_windows(&self, wallet_id: u64, action_key: &str, date: NaiveDate) -> AuthResult<Vec<i16>> {
        sql::charged_windows(&mut *self.pool.acquire().await?, wallet_id, action_key, date).await
    }

    async fn count_apps(&self, client_id: u64, app_type: &str) -> AuthResult<i64> {
        Ok(sqlx::query_scalar("SELECT COUNT(*) FROM security_app WHERE CLIENT_ID = ? AND APP_TYPE = ?")
            .bind(client_id)
            .bind(app_type)
            .fetch_one(&self.pool)
            .await?)
    }

    async fn count_users_with_profile(&self, client_id: u64, app_id: u64) -> AuthResult<i64> {
        Ok(sqlx::query_scalar(
            "SELECT COUNT(DISTINCT security_user.ID) FROM security_user \
             JOIN security_profile_user ON security_profile_user.USER_ID = security_user.ID \
             JOIN security_profile ON security_profile.ID = security_profile_user.PROFILE_ID \
             WHERE security_user.CLIENT_ID = ? AND security_profile.APP_ID = ?",
        )
        .bind(client_id)
        .bind(app_id)
        .fetch_one(&self.pool)
        .await?)
    }
}

/// The wallet statements on one connection, so a test can run them inside a transaction it rolls
/// back (they are the only writes security-internal makes).
pub mod sql {
    use chrono::NaiveDate;
    use sqlx::{MySqlConnection, Row};

    use super::{wallet as wallet_row, Txn, Wallet, WALLET_COLUMNS};
    use crate::decimal::Dec;
    use crate::errors::AuthResult;

    /// `WalletDAO.findByClientAndApp`.
    pub async fn wallet(c: &mut MySqlConnection, client_id: u64, app_id: u64) -> AuthResult<Option<Wallet>> {
        let sql = format!("SELECT {WALLET_COLUMNS} FROM security_wallet WHERE CLIENT_ID = ? AND APP_ID = ? LIMIT 1");
        let row = sqlx::query(&sql).bind(client_id).bind(app_id).fetch_optional(&mut *c).await?;
        row.as_ref().map(wallet_row).transpose()
    }

    /// `WalletDAO.createSeeded`: insert if absent (a race loses quietly), then read.
    pub async fn create_seeded_wallet(c: &mut MySqlConnection, client_id: u64, app_id: u64, initial: Dec) -> AuthResult<Option<Wallet>> {
        sqlx::query(
            "INSERT IGNORE INTO security_wallet (CLIENT_ID, APP_ID, BALANCE, STATUS, LOW_BALANCE_NOTIFIED, VERSION) \
             VALUES (?, ?, ?, 'ACTIVE', 0, 0)",
        )
        .bind(client_id)
        .bind(app_id)
        .bind(initial.to_string())
        .execute(&mut *c)
        .await?;
        wallet(c, client_id, app_id).await
    }

    /// `WalletTransactionDAO.recordTxn`: false when the idempotency key was already used.
    pub async fn record_txn(c: &mut MySqlConnection, t: &Txn) -> AuthResult<bool> {
        let r = sqlx::query(
            "INSERT IGNORE INTO security_wallet_transaction (WALLET_ID, TYPE, TOKENS, BALANCE_AFTER, ACTION_KEY, APP_ID, \
             QUANTITY, CHARGE_DATE, WINDOW_INDEX, IDEMPOTENCY_KEY, REFERENCE_TYPE, REFERENCE_ID, REASON, DESCRIPTION, CREATED_BY) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, NULL, ?)",
        )
        .bind(t.wallet_id)
        .bind(t.kind)
        .bind(t.tokens.to_string())
        .bind(t.balance_after.to_string())
        .bind(t.action_key.clone())
        .bind(t.app_id)
        .bind(t.quantity.map(|q| q.to_string()))
        .bind(t.charge_date)
        .bind(t.window_index)
        .bind(t.idempotency_key.clone())
        .bind(t.reason.clone())
        .bind(t.created_by)
        .execute(&mut *c)
        .await?;
        Ok(r.rows_affected() > 0)
    }

    /// `WalletDAO.debit`.
    pub async fn debit(c: &mut MySqlConnection, wallet_id: u64, tokens: Dec) -> AuthResult<u64> {
        let r = sqlx::query("UPDATE security_wallet SET BALANCE = (BALANCE - ?) WHERE ID = ?")
            .bind(tokens.to_string())
            .bind(wallet_id)
            .execute(&mut *c)
            .await?;
        Ok(r.rows_affected())
    }

    /// `WalletDAO.setStatus`.
    pub async fn set_status(c: &mut MySqlConnection, wallet_id: u64, status: &str) -> AuthResult<u64> {
        let r = sqlx::query("UPDATE security_wallet SET STATUS = ? WHERE ID = ?").bind(status).bind(wallet_id).execute(&mut *c).await?;
        Ok(r.rows_affected())
    }

    /// `WalletDAO.setLowBalanceNotified`.
    pub async fn set_low_balance_notified(c: &mut MySqlConnection, wallet_id: u64, notified: bool) -> AuthResult<u64> {
        let r = sqlx::query("UPDATE security_wallet SET LOW_BALANCE_NOTIFIED = ? WHERE ID = ?")
            .bind(i8::from(notified))
            .bind(wallet_id)
            .execute(&mut *c)
            .await?;
        Ok(r.rows_affected())
    }

    /// `WalletTransactionDAO.sumQuantityBetween`.
    pub async fn sum_quantity_between(c: &mut MySqlConnection, wallet_id: u64, action_key: &str, from: NaiveDate, to: NaiveDate) -> AuthResult<Dec> {
        let s: Option<String> = sqlx::query_scalar(
            "SELECT CAST(COALESCE(SUM(QUANTITY), 0) AS CHAR) FROM security_wallet_transaction \
             WHERE WALLET_ID = ? AND ACTION_KEY = ? AND CHARGE_DATE BETWEEN ? AND ?",
        )
        .bind(wallet_id)
        .bind(action_key)
        .bind(from)
        .bind(to)
        .fetch_one(&mut *c)
        .await?;
        Ok(s.as_deref().and_then(Dec::parse).unwrap_or(Dec::ZERO))
    }

    /// `WalletTransactionDAO.chargedWindows`.
    pub async fn charged_windows(c: &mut MySqlConnection, wallet_id: u64, action_key: &str, date: NaiveDate) -> AuthResult<Vec<i16>> {
        let rows = sqlx::query(
            "SELECT WINDOW_INDEX FROM security_wallet_transaction WHERE WALLET_ID = ? AND ACTION_KEY = ? \
             AND CHARGE_DATE = ? AND WINDOW_INDEX IS NOT NULL",
        )
        .bind(wallet_id)
        .bind(action_key)
        .bind(date)
        .fetch_all(&mut *c)
        .await?;
        rows.iter().map(|r| Ok(r.try_get::<i16, _>(0)?)).collect()
    }
}

#[cfg(test)]
mod store_tests {
    use super::*;

    #[test]
    fn free_allowances() {
        let d = |n: i64| Some(Dec::from_i64(n));
        let c = BillingConfig {
            free_storage_rows: d(1),
            free_deals: d(2),
            free_files_gb: d(3),
            free_ai_tokens_per_month: d(4),
            ..Default::default()
        };
        assert_eq!(
            [action::STORAGE_ROWS, action::DEALS, action::FILES_GB, action::AI_LLM_TOKENS, "other"].map(|a| c.free_for(a)),
            [d(1), d(2), d(3), d(4), Some(Dec::ZERO)]
        );
    }

    /// The store's wallet statements through its own connections, on a wallet of the scratch
    /// client `ZZRUL` (removed again by the fixture).
    #[tokio::test]
    async fn wallet_statements_of_the_store() {
        let Some(fx) = crate::admin::users::testkit::fx().await else { return };
        let db: &Db = &fx.s.db;
        let w = db.create_seeded_wallet(fx.c, 2, Dec::ONE).await.unwrap().expect("seeded");
        assert_eq!(db.wallet(fx.c, 2).await.unwrap().map(|x| x.id), Some(w.id));
        let day = NaiveDate::from_ymd_opt(2026, 6, 15).unwrap();
        let txn = Txn {
            wallet_id: w.id,
            kind: "DEBIT",
            tokens: Dec::from_i64(1),
            balance_after: Dec::ZERO,
            action_key: Some(action::USER.into()),
            app_id: Some(2),
            quantity: Some(Dec::from_i64(2)),
            charge_date: Some(day),
            window_index: Some(3),
            idempotency_key: format!("live-test:{}", fx.run),
            reason: "live test".into(),
            created_by: None,
        };
        assert!(db.record_txn(&txn).await.unwrap());
        assert_eq!(db.debit(w.id, Dec::from_i64(1)).await.unwrap(), 1);
        assert_eq!(db.set_status(w.id, "SUSPENDED").await.unwrap(), 1);
        assert_eq!(db.set_low_balance_notified(w.id, true).await.unwrap(), 1);
        assert_eq!(db.sum_quantity_between(w.id, action::USER, day, day).await.unwrap().to_string(), "2.0000");
        assert_eq!(db.charged_windows(w.id, action::USER, day).await.unwrap(), vec![3]);
        fx.finish().await;
    }
}
