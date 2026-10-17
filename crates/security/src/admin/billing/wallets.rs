//! `WalletService` as the admin controllers use it: the owner's wallet views (the whole wallet,
//! the derived display status, the ledger, the plan with its usage), the credits (a paid
//! invoice, an owner's adjustment, an admin grant) and the balance preview.
//!
//! The debits, the metering and the gates are security-internal's (`internal/billing.rs`); a
//! credit here writes the ledger row first (its idempotency key makes a replay harmless), then
//! the balance, then clears the low-balance latch, reactivates a wallet that comes back above
//! zero and evicts the cached status, in Java's order and without a transaction, as in Java.

use rand::RngCore;
use serde_json::Value;

use super::service::{forbidden, Billing};
use crate::data::billing::action;
use crate::data::billing_admin::{Find, Rec, Val, WALLET};
use crate::decimal::Dec;
use crate::errors::{AuthError, AuthResult};
use crate::internal::billing::ChargeResult;
use crate::jackson::Obj;
use crate::model::ContextAuth;
use crate::spring::Pageable;
use crate::web::page_of;

/// `BigDecimal.add(null)`.
pub const NULL_TOKENS: &str = "Cannot read field \"intCompact\" because \"augend\" is null";

/// `WalletStatusResponse`.
pub fn status_response(status: &str, balance: Option<Dec>, threshold: Option<Dec>) -> Value {
    Obj::new()
        .put("status", status)
        .put("balance", balance.map(Dec::to_json).unwrap_or(Value::Null))
        .put("threshold", threshold.map(Dec::to_json).unwrap_or(Value::Null))
        .build()
}

/// `classifyAgainstThreshold`.
pub fn classify(balance: Dec, threshold: Option<Dec>) -> Value {
    match threshold {
        Some(t) if balance.cmp_value(&t) == std::cmp::Ordering::Less => status_response("LOW", Some(balance), Some(t)),
        _ => status_response("ACTIVE", Some(balance), threshold),
    }
}

/// One `PlanDimension`, kept only when it is billed or has a free allowance.
fn dimension(out: &mut Vec<Value>, action_key: &str, label: &str, unit: &str, rate: Option<Dec>, free: Option<Dec>, usage: Option<i64>) {
    let billed = rate.is_some_and(|r| r.signum() > 0);
    let has_free = free.is_some_and(|f| f.signum() > 0);
    if !billed && !has_free {
        return;
    }
    out.push(
        Obj::new()
            .put("actionKey", action_key)
            .put("label", label)
            .put("unit", unit)
            .put("tokensPerUnit", rate.map(Dec::to_json).unwrap_or(Value::Null))
            .put("freeAllowance", free.map(Dec::to_json).unwrap_or(Value::Null))
            .put("currentUsage", usage.map(Value::from).unwrap_or(Value::Null))
            .build(),
    );
}

/// `PlanUsageResponse` for a config and the counts of apps, sites and users with a profile.
pub fn plan_json(config: &Rec, apps: i64, sites: i64, users: i64) -> Value {
    let mut dims = Vec::new();
    let c = |p: &str| config.dec(p);
    dimension(&mut dims, action::APP_RENT, "Apps", "app / month", c("appRentPerMonth"), c("freeApps"), Some(apps));
    dimension(&mut dims, action::SITE_RENT, "Sites", "site / month", c("siteRentPerMonth"), c("freeSites"), Some(sites));
    dimension(&mut dims, action::USER, "Users", "user / month", c("userTokensPerMonth"), c("freeUsers"), Some(users));
    dimension(&mut dims, action::STORAGE_ROWS, "Storage rows", "row / month", c("storageRowTokensPerMonth"), c("freeStorageRows"), None);
    dimension(&mut dims, action::DEALS, "Deals", "deal / month", c("dealTokensPerMonth"), c("freeDeals"), None);
    dimension(&mut dims, action::FILES_GB, "File storage", "GB / month", c("filesTokensPerMonth"), c("freeFilesGb"), None);
    dimension(&mut dims, action::AI_LLM_TOKENS, "AI usage", "1M AI tokens", c("aiTokensPerMillion"), c("freeAiTokensPerMonth"), None);
    Obj::new()
        .put("lowBalanceThreshold", c("lowBalanceThreshold").map(Dec::to_json).unwrap_or(Value::Null))
        .put("dimensions", Value::Array(dims))
        .build()
}

/// `java.util.UUID.randomUUID().toString()`.
pub fn random_uuid() -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..])
}

/// A credit to apply: `applyCredit`'s arguments.
pub struct Credit<'r> {
    pub tokens: Option<Dec>,
    pub kind: &'static str,
    pub reference_type: &'static str,
    pub reference_id: Option<u64>,
    pub idempotency_key: String,
    pub reason: Option<&'r str>,
    pub acting_user: Option<u64>,
}

impl Billing<'_> {
    /// `WalletDAO.findByClientAndApp`.
    pub async fn wallet_of(&self, client: u64, app: u64) -> AuthResult<Option<Rec>> {
        let f = Find { first: true, ..Find::eq(vec![("CLIENT_ID", Val::Id(client)), ("APP_ID", Val::Id(app))]) };
        Ok(self.store.find(&WALLET, &f).await?.into_iter().next())
    }

    /// `getOrCreateWallet`: seeded with one token, ACTIVE.
    pub async fn wallet_or_create(&self, client: u64, app: u64) -> AuthResult<Option<Rec>> {
        if let Some(w) = self.wallet_of(client, app).await? {
            return Ok(Some(w));
        }
        self.store.seed_wallet(client, app, Dec::ONE).await
    }

    /// `applyCredit`.
    pub async fn apply_credit(&self, wallet: &Rec, c: Credit<'_>) -> AuthResult<ChargeResult> {
        let balance = wallet.dec("balance").unwrap_or(Dec::ZERO);
        let tokens = c.tokens.ok_or_else(|| AuthError::internal(NULL_TOKENS))?;
        let after = balance.add(tokens);
        let reactivate = wallet.str("status") == Some("SUSPENDED") && after.signum() > 0;
        let wallet_id = wallet.id().unwrap_or(0);
        let txn = Rec::new(&crate::data::billing_admin::TXN)
            .with("walletId", Val::Id(wallet_id))
            .with("type", Val::Str(c.kind.into()))
            .with("tokens", Val::Dec(tokens))
            .with("balanceAfter", Val::Dec(after))
            .with("appId", wallet.u64("appId").map(Val::Id).unwrap_or(Val::Null))
            .with("idempotencyKey", Val::Str(c.idempotency_key))
            .with("referenceType", Val::Str(c.reference_type.into()))
            .with("referenceId", c.reference_id.map(Val::Id).unwrap_or(Val::Null))
            .with("reason", c.reason.map(|r| Val::Str(r.into())).unwrap_or(Val::Null))
            .with("createdBy", c.acting_user.map(Val::Id).unwrap_or(Val::Null));
        if !self.store.record_txn(&txn).await? {
            return Ok(ChargeResult { charged: false, suspended: false, low_balance_crossed: false, balance_after: balance });
        }
        self.store.credit_balance(wallet_id, tokens).await?;
        self.store.set_low_balance_notified(wallet_id, false).await?;
        if reactivate {
            self.store.set_wallet_status(wallet_id, "ACTIVE").await?;
        }
        if let (Some(client), Some(app)) = (wallet.u64("clientId"), wallet.u64("appId")) {
            self.evict_wallet_status(client, app).await;
        }
        Ok(ChargeResult { charged: true, suspended: false, low_balance_crossed: false, balance_after: after })
    }

    /// `creditFromPayment`: the purchased tokens, once per payment reference.
    pub async fn credit_from_payment(&self, invoice: &Rec) -> AuthResult<Option<ChargeResult>> {
        let (Some(client), Some(app)) = (invoice.u64("clientId"), invoice.u64("appId")) else { return Ok(None) };
        let Some(wallet) = self.wallet_or_create(client, app).await? else { return Ok(None) };
        let reason = format!("Token purchase {}", invoice.str("invoiceNumber").unwrap_or("null"));
        let credit = Credit {
            tokens: invoice.dec("tokensPurchased"),
            kind: "CREDIT",
            reference_type: "INVOICE",
            reference_id: invoice.id(),
            idempotency_key: format!("payment:{}", invoice.str("paymentReference").unwrap_or("null")),
            reason: Some(&reason),
            acting_user: invoice.u64("createdBy"),
        };
        Ok(Some(self.apply_credit(&wallet, credit).await?))
    }

    /// `adjust`: an owner's credit (or debit) of a managed client's wallet, never its own.
    pub async fn adjust(&self, ca: &ContextAuth, wallet_id: u64, tokens: Dec, reason: &str) -> AuthResult<ChargeResult> {
        let wallet = self.read(&WALLET, Some(wallet_id)).await?;
        let client = wallet.u64("clientId").unwrap_or(0);
        if !self.manages(ca, client).await? {
            return Err(forbidden("manage the wallet's client"));
        }
        let own = ca.user.client_id();
        if own == client {
            return Err(forbidden("adjust your own wallet"));
        }
        if !self.write_access(wallet.u64("appId"), Some(own)).await? {
            return Err(forbidden("write access to the application"));
        }
        let credit = Credit {
            tokens: Some(tokens),
            kind: "ADJUST",
            reference_type: "ADJUST",
            reference_id: None,
            idempotency_key: format!("adjust:{}", random_uuid()),
            reason: Some(reason),
            acting_user: ca.user.id,
        };
        self.apply_credit(&wallet, credit).await
    }

    /// `authorizeWalletOp`: SYSTEM, or write access to the app and management of both clients.
    async fn authorize_wallet_op(&self, ca: &ContextAuth, app: u64, url_client: u64, row_client: u64) -> AuthResult<()> {
        if ca.is_system_client() {
            return Ok(());
        }
        if !self.write_access(Some(app), Some(ca.user.client_id())).await? {
            return Err(forbidden("write access to the application"));
        }
        if !self.manages(ca, url_client).await? {
            return Err(forbidden("manage the URL client"));
        }
        if !self.manages(ca, row_client).await? {
            return Err(forbidden("manage the wallet's client"));
        }
        Ok(())
    }

    /// The (app, URL client, wallet client) of `creditTokens` / `lookupWallet`, authorised.
    async fn wallet_op(&self, ca: &ContextAuth, app: Option<&str>, url_client: Option<&str>, client: Option<&str>) -> AuthResult<(u64, u64)> {
        let app = self.app_by_code(app).await?.ok_or_else(|| forbidden("the application"))?;
        let url_client = self.client_by_code(url_client).await?.ok_or_else(|| forbidden("the URL client"))?;
        let row = self.client_by_code(client).await?.ok_or_else(|| forbidden("the wallet's client"))?;
        self.authorize_wallet_op(ca, app.id, url_client.id(), row.id()).await?;
        Ok((app.id, row.id()))
    }

    /// `creditTokens`: an admin grant, creating the wallet when absent.
    pub async fn credit_tokens(
        &self,
        ca: &ContextAuth,
        app: Option<&str>,
        url_client: Option<&str>,
        client: Option<&str>,
        tokens: Option<Dec>,
        reason: Option<&str>,
    ) -> AuthResult<Option<ChargeResult>> {
        let (app, row) = self.wallet_op(ca, app, url_client, client).await?;
        let Some(wallet) = self.wallet_or_create(row, app).await? else { return Ok(None) };
        let credit = Credit {
            tokens,
            kind: "ADJUST",
            reference_type: "ADJUST",
            reference_id: None,
            idempotency_key: format!("adjust:{}", random_uuid()),
            reason,
            acting_user: ca.user.id,
        };
        Ok(Some(self.apply_credit(&wallet, credit).await?))
    }

    /// `lookupWallet`: the balance preview.
    pub async fn lookup_wallet(&self, ca: &ContextAuth, app: Option<&str>, url_client: Option<&str>, client: Option<&str>) -> AuthResult<Option<Rec>> {
        let (app, row) = self.wallet_op(ca, app, url_client, client).await?;
        self.wallet_of(row, app).await
    }

    /// `getWalletByCodes`: the wallet of the headers' app and client, for a client the caller
    /// may see.
    pub async fn wallet_by_codes(&self, ca: &ContextAuth, app_code: Option<&str>, client_code: Option<&str>) -> AuthResult<Option<Rec>> {
        let Some(app) = self.app_by_code(app_code).await? else { return Ok(None) };
        let Some(client) = self.client_by_code(client_code).await? else { return Ok(None) };
        let id = client.id();
        let visible = ca.is_system_client() || id == ca.user.client_id() || self.manages(ca, id).await?;
        if !visible {
            return Err(forbidden("this client's wallet"));
        }
        self.wallet_of(id, app.id).await
    }

    /// `getDisplayStatus`: the caller's own wallet on the app.
    pub async fn display_status(&self, ca: &ContextAuth, app_code: Option<&str>) -> AuthResult<Value> {
        let active = || status_response("ACTIVE", None, None);
        let Some(app) = self.app_by_code(app_code).await? else { return Ok(active()) };
        let client = ca.user.client_id();
        let Some(wallet) = self.wallet_of(client, app.id).await? else { return Ok(active()) };
        let balance = wallet.dec("balance").unwrap_or(Dec::ZERO);
        if wallet.str("status") == Some("SUSPENDED") || balance.signum() < 0 {
            return Ok(status_response("SUSPENDED", Some(balance), None));
        }
        if let Some(t) = wallet.dec("alertThreshold") {
            return Ok(classify(balance, Some(t)));
        }
        Ok(match self.config_for_client(app.id, client).await? {
            Some(config) => classify(balance, config.dec("lowBalanceThreshold")),
            None => status_response("ACTIVE", Some(balance), None),
        })
    }

    /// `getMyTransactions`: a page of the caller's own ledger on the app.
    pub async fn my_transactions(&self, ca: &ContextAuth, app_code: Option<&str>, page: &Pageable) -> AuthResult<Value> {
        let empty = || page_of(vec![], page, 0);
        let Some(app) = self.app_by_code(app_code).await? else { return Ok(empty()) };
        let Some(wallet) = self.wallet_of(ca.user.client_id(), app.id).await? else { return Ok(empty()) };
        let rows = self.store.txn_page(wallet.id().unwrap_or(0), page).await?;
        Ok(page_of(rows.rows.iter().map(Rec::to_json).collect(), page, rows.total.unwrap_or(0)))
    }

    /// `getPlanUsage`: the governing config's rates and allowances with the caller's usage.
    pub async fn plan_usage(&self, ca: &ContextAuth, app_code: Option<&str>) -> AuthResult<Value> {
        let empty = || Obj::new().build();
        let Some(app) = self.app_by_code(app_code).await? else { return Ok(empty()) };
        let client = ca.user.client_id();
        let Some(config) = self.config_for_client(app.id, client).await? else { return Ok(empty()) };
        let apps = self.store.count_apps(client, "APP").await?;
        let sites = self.store.count_apps(client, "SITE").await?;
        let users = self.store.count_users_with_profile(client, app.id).await?;
        Ok(plan_json(&config, apps, sites, users))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::billing_admin::CONFIG;
    use serde_json::json;

    fn d(s: &str) -> Dec {
        Dec::parse(s).unwrap()
    }

    #[test]
    fn statuses() {
        assert_eq!(status_response("ACTIVE", None, None), json!({"status": "ACTIVE"}));
        assert_eq!(crate::jackson::pretty(&classify(d("50.0000"), Some(d("100.0000")))), "{\n  \"status\" : \"LOW\",\n  \"balance\" : 50.0000,\n  \"threshold\" : 100.0000\n}");
        assert_eq!(classify(d("100"), Some(d("100")))["status"], "ACTIVE");
        assert_eq!(classify(d("5"), None), json!({"status": "ACTIVE", "balance": crate::jackson::raw_number("5")}));
    }

    #[test]
    fn plan_dimensions_are_billed_or_free() {
        // The local sitezump config (observed on Java 2026-10-16).
        let c = Rec::new(&CONFIG)
            .with("appRentPerMonth", Val::Dec(d("0.0000")))
            .with("freeApps", Val::Dec(d("0.0000")))
            .with("siteRentPerMonth", Val::Dec(d("1000.0000")))
            .with("freeSites", Val::Dec(d("1.0000")))
            .with("userTokensPerMonth", Val::Dec(d("10.0000")))
            .with("freeUsers", Val::Dec(d("2.0000")))
            .with("storageRowTokensPerMonth", Val::Dec(d("1.0000")))
            .with("freeStorageRows", Val::Dec(d("100.0000")))
            .with("dealTokensPerMonth", Val::Dec(d("0.0000")))
            .with("freeDeals", Val::Dec(d("0.0000")))
            .with("filesTokensPerMonth", Val::Dec(d("100.0000")))
            .with("freeFilesGb", Val::Dec(d("0.0000")))
            .with("aiTokensPerMillion", Val::Dec(d("0.0000")))
            .with("freeAiTokensPerMonth", Val::Dec(d("1000.0000")))
            .with("lowBalanceThreshold", Val::Dec(d("100.0000")));
        let v = plan_json(&c, 3, 242, 56);
        let labels: Vec<&str> = v["dimensions"].as_array().unwrap().iter().map(|x| x["label"].as_str().unwrap()).collect();
        assert_eq!(labels, ["Sites", "Users", "Storage rows", "File storage", "AI usage"]);
        assert_eq!(v["dimensions"][0]["currentUsage"], 242);
        assert!(v["dimensions"][2].get("currentUsage").is_none());
        let s = crate::jackson::pretty(&v);
        assert!(s.starts_with("{\n  \"lowBalanceThreshold\" : 100.0000,\n  \"dimensions\" : [ {\n    \"actionKey\" : \"security.site.rent\""));
        assert_eq!(plan_json(&Rec::new(&CONFIG), 0, 0, 0), json!({}));
    }

    #[test]
    fn uuids_are_version_4() {
        let u = random_uuid();
        assert_eq!(u.len(), 36);
        assert_eq!(&u[14..15], "4");
        assert!(matches!(&u[19..20], "8" | "9" | "a" | "b"));
        assert_ne!(u, random_uuid());
    }
}
