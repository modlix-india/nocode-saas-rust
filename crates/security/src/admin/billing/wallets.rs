//! The owner's wallet views (the whole wallet, the display status, the ledger, the plan with its
//! meters and usage) and the credits (a paid invoice, an owner's adjustment, an admin grant).
//!
//! Every credit goes through security-internal's `credit_wallet`, so it becomes a lot with its
//! expiry (bought and granted credits after the config's validity, plan credits with the period)
//! and pays any debt first; debits and gates stay in `internal/billing.rs`.

use rand::RngCore;
use serde_json::Value;

use super::service::{forbidden, Billing};
use crate::data::billing::{terms, BillingConfig, NewLot, Wallet};
use crate::data::billing_admin::{Find, Rec, Val, WALLET};
use crate::decimal::Dec;
use crate::errors::{AuthError, AuthResult};
use crate::internal::billing::ChargeResult;
use crate::jackson::{opt, Obj};
use crate::model::ContextAuth;
use crate::spring::Pageable;
use crate::web::page_of;

/// `BigDecimal.add(null)`.
pub const NULL_TOKENS: &str = "Cannot read field \"intCompact\" because \"augend\" is null";

/// `WalletStatusResponse`, with the suspension mode and whether an invoice is overdue.
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

/// `java.util.UUID.randomUUID().toString()`.
pub fn random_uuid() -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..])
}

fn wallet_of_rec(r: &Rec) -> Wallet {
    Wallet {
        id: r.id().unwrap_or(0),
        client_id: r.u64("clientId").unwrap_or(0),
        app_id: r.u64("appId").unwrap_or(0),
        balance: r.dec("balance").unwrap_or(Dec::ZERO),
        status: r.str("status").unwrap_or("ACTIVE").to_string(),
        alert_threshold: r.dec("alertThreshold"),
        low_balance_notified: r.int("lowBalanceNotified").map(|n| n as i8),
    }
}

impl Billing<'_> {
    /// `WalletDAO.findByClientAndApp`.
    pub async fn wallet_of(&self, client: u64, app: u64) -> AuthResult<Option<Rec>> {
        let f = Find { first: true, ..Find::eq(vec![("CLIENT_ID", Val::Id(client)), ("APP_ID", Val::Id(app))]) };
        Ok(self.store.find(&WALLET, &f).await?.into_iter().next())
    }

    /// The client's wallet, created when absent (on the governing config's default plan).
    pub async fn wallet_or_create(&self, ca: &ContextAuth, client: u64, app: u64) -> AuthResult<Option<Rec>> {
        if let Some(w) = self.wallet_of(client, app).await? {
            return Ok(Some(w));
        }
        let config = self.internal.governing_config(app, client).await?;
        self.internal.wallet_ready(ca, client, app, config.as_ref()).await?;
        self.wallet_of(client, app).await
    }

    /// The rule row of the config that governs (client, app), or of a given admin row.
    async fn rule_config(&self, config: Option<&Rec>, client: u64, app: u64) -> AuthResult<BillingConfig> {
        let found = match config.and_then(Rec::id) {
            Some(id) => self.internal.billing.config_by_id(id).await?,
            None => self.internal.governing_config(app, client).await?,
        };
        Ok(found.unwrap_or_else(|| BillingConfig { app_id: app, ..Default::default() }))
    }

    /// A credit of the wallet as a lot.
    async fn credit(&self, by: Option<u64>, wallet: &Rec, tokens: Option<Dec>, key: String, reason: &str, lot: NewLot, config: &BillingConfig) -> AuthResult<ChargeResult> {
        let tokens = tokens.ok_or_else(|| AuthError::internal(NULL_TOKENS))?;
        self.internal.credit_wallet_by(by, &wallet_of_rec(wallet), config, tokens, &key, reason, lot).await
    }

    /// `creditFromPayment`: a paid bundle's tokens, once per payment reference, valid for the
    /// config's bought-credit months. A paid monthly invoice credits nothing.
    pub async fn credit_from_payment(&self, ca: &ContextAuth, invoice: &Rec) -> AuthResult<Option<ChargeResult>> {
        if invoice.str("kind") == Some("MONTHLY") {
            return Ok(None);
        }
        let (Some(client), Some(app)) = (invoice.u64("clientId"), invoice.u64("appId")) else { return Ok(None) };
        let Some(wallet) = self.wallet_or_create(ca, client, app).await? else { return Ok(None) };
        let seller = invoice.u64("sellerClientId").unwrap_or(0);
        let admin_config = self.config_of(app, seller).await?;
        let config = self.rule_config(admin_config.as_ref(), client, app).await?;
        let reason = format!("Credit purchase {}", invoice.str("invoiceNumber").unwrap_or("null"));
        let key = format!("payment:{}", invoice.str("paymentReference").unwrap_or("null"));
        let lot = self.internal.bought_credit_lot(&config, invoice.id());
        Ok(Some(self.credit(invoice.u64("createdBy"), &wallet, invoice.dec("tokensPurchased"), key, &reason, lot, &config).await?))
    }

    /// `adjust`: an owner's credit of a managed client's wallet, never its own.
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
        let app = wallet.u64("appId").unwrap_or(0);
        let config = self.rule_config(None, client, app).await?;
        let lot = NewLot { source: "ADJUST", reference_type: Some("ADJUST".into()), reference_id: None, expires_at: self.internal.purchase_expiry(&config, self.now_local()) };
        self.credit(ca.user.id, &wallet, Some(tokens), format!("adjust:{}", random_uuid()), reason, lot, &config).await
    }

    /// SYSTEM, or write access to the app and management of both clients.
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
        let Some(wallet) = self.wallet_or_create(ca, row, app).await? else { return Ok(None) };
        let config = self.rule_config(None, row, app).await?;
        let lot = NewLot { source: "GRANT", reference_type: Some("ADJUST".into()), reference_id: None, expires_at: self.internal.purchase_expiry(&config, self.now_local()) };
        let reason = reason.unwrap_or("Credits granted");
        Ok(Some(self.credit(ca.user.id, &wallet, tokens, format!("adjust:{}", random_uuid()), reason, lot, &config).await?))
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

    /// `getDisplayStatus`: the caller's own wallet on the app (ACTIVE, LOW or SUSPENDED), with
    /// `overdue` (an unpaid monthly invoice past its due date) and the config's `suspendMode`, so
    /// the shell knows which banner to show.
    pub async fn display_status(&self, ca: &ContextAuth, app_code: Option<&str>) -> AuthResult<Value> {
        let active = || status_response("ACTIVE", None, None);
        let Some(app) = self.app_by_code(app_code).await? else { return Ok(active()) };
        let client = ca.user.client_id();
        let config = self.internal.governing_config(app.id, client).await?;
        let overdue = self.internal.billing.has_overdue_invoice(client, app.id).await?;
        let mut v = match self.wallet_of(client, app.id).await? {
            None => active(),
            Some(wallet) => {
                let balance = wallet.dec("balance").unwrap_or(Dec::ZERO);
                if wallet.str("status") == Some("SUSPENDED") || balance.signum() < 0 {
                    status_response("SUSPENDED", Some(balance), None)
                } else if let Some(t) = wallet.dec("alertThreshold") {
                    classify(balance, Some(t))
                } else {
                    match &config {
                        Some(c) => classify(balance, c.low_balance_threshold),
                        None => status_response("ACTIVE", Some(balance), None),
                    }
                }
            }
        };
        if let Value::Object(m) = &mut v {
            m.insert("overdue".into(), Value::Bool(overdue));
            if let Some(c) = &config {
                m.insert("suspendMode".into(), Value::from(c.suspend_mode.clone()));
            }
        }
        Ok(v)
    }

    /// `getMyTransactions`: a page of the caller's own ledger on the app.
    pub async fn my_transactions(&self, ca: &ContextAuth, app_code: Option<&str>, page: &Pageable) -> AuthResult<Value> {
        let empty = || page_of(vec![], page, 0);
        let Some(app) = self.app_by_code(app_code).await? else { return Ok(empty()) };
        let Some(wallet) = self.wallet_of(ca.user.client_id(), app.id).await? else { return Ok(empty()) };
        let rows = self.store.txn_page(wallet.id().unwrap_or(0), page).await?;
        Ok(page_of(rows.rows.iter().map(Rec::to_json).collect(), page, rows.total.unwrap_or(0)))
    }

    /// `getPlanUsage`: the governing config's plans and meters with the caller's plan, usage this
    /// month, credits by expiry. `dimensions` keeps the shape the old pages read.
    pub async fn plan_usage(&self, ca: &ContextAuth, app_code: Option<&str>) -> AuthResult<Value> {
        let empty = || Obj::new().build();
        let Some(app) = self.app_by_code(app_code).await? else { return Ok(empty()) };
        let client = ca.user.client_id();
        let Some(config) = self.internal.governing_config(app.id, client).await? else { return Ok(empty()) };
        let wallet = self.internal.billing.wallet(client, app.id).await?;
        let wp = match &wallet {
            Some(w) => self.internal.billing.wallet_plan(w.id).await?,
            None => None,
        };
        let plans = self.internal.billing.plans_of_config(config.id).await?;
        let current = wp.as_ref().and_then(|wp| plans.iter().find(|p| p.id == wp.plan_id)).cloned();
        let meters = self.internal.billing.meters_of_config(config.id).await?;
        let today = self.today();
        let mut meter_rows = Vec::new();
        let mut dims = Vec::new();
        for m in meters.iter().filter(|m| m.status == "ACTIVE") {
            let t = terms(m, current.as_ref());
            let used = if m.is_gauge() {
                matches!(m.source.as_str(), "USERS" | "APPS" | "SITES").then_some(self.internal.gauge_count(m, client, app.id).await?)
            } else {
                match &wallet {
                    Some(w) => Some(self.internal.month_usage(m, w, client, &app.app_code, today).await?),
                    None => Some(Dec::ZERO),
                }
            };
            let unit = m.unit_label.clone().unwrap_or_else(|| m.label.to_lowercase());
            meter_rows.push(
                Obj::new()
                    .put("meterKey", m.key.as_str())
                    .put("label", m.label.as_str())
                    .put("unit", unit.as_str())
                    .put("kind", m.kind.as_str())
                    .put("chargeMode", m.charge_mode.as_str())
                    .put("rate", t.rate.to_json())
                    .put("rateUnit", m.rate_unit.as_str())
                    .put("free", t.free.to_json())
                    .put("hardCap", t.hard_cap.map(Dec::to_json).unwrap_or(Value::Null))
                    .put("used", used.map(Dec::to_json).unwrap_or(Value::Null))
                    .build(),
            );
            dims.push(
                Obj::new()
                    .put("actionKey", m.action_key(&app.app_code))
                    .put("label", m.label.as_str())
                    .put("unit", unit.as_str())
                    .put("tokensPerUnit", t.rate.to_json())
                    .put("freeAllowance", t.free.to_json())
                    .put("currentUsage", used.map(Dec::to_json).unwrap_or(Value::Null))
                    .build(),
            );
        }
        let plan_rows: Vec<Value> = plans
            .iter()
            .filter(|p| p.status == "ACTIVE")
            .map(|p| {
                let limits: Vec<Value> = meters
                    .iter()
                    .filter(|m| m.status == "ACTIVE")
                    .map(|m| {
                        let t = terms(m, Some(p));
                        Obj::new()
                            .put("meterKey", m.key.as_str())
                            .put("label", m.label.as_str())
                            .put("free", t.free.to_json())
                            .put("rate", t.rate.to_json())
                            .put("hardCap", t.hard_cap.is_some())
                            .build()
                    })
                    .collect();
                Obj::new()
                    .put("id", p.id)
                    .put("code", p.code.as_str())
                    .put("label", p.label.as_str())
                    .put("period", p.period.as_str())
                    .put("paymentMode", p.payment_mode.as_str())
                    .put("priceAmount", p.price_amount.to_json())
                    .put("priceTokens", p.price_tokens.to_json())
                    .put("currency", p.currency.as_str())
                    .put("includedTokens", p.included_tokens.to_json())
                    .put("includedTokensRecurring", p.included_recurring)
                    .put("isDefault", p.is_default)
                    .put("current", current.as_ref().is_some_and(|c| c.id == p.id))
                    .put("limits", Value::Array(limits))
                    .build()
            })
            .collect();
        let credits: Vec<Value> = match &wallet {
            Some(w) => self
                .internal
                .billing
                .open_lots(w.id)
                .await?
                .iter()
                .map(|l| {
                    Obj::new()
                        .put("source", l.source.as_str())
                        .put("left", l.tokens_left.to_json())
                        .put("expiresAt", opt(l.expires_at.map(|t| t.format("%Y-%m-%dT%H:%M:%S").to_string())))
                        .build()
                })
                .collect(),
            None => vec![],
        };
        let plan = match (&current, &wp) {
            (Some(p), Some(wp)) => Obj::new()
                .put("id", p.id)
                .put("code", p.code.as_str())
                .put("label", p.label.as_str())
                .put("paymentMode", p.payment_mode.as_str())
                .put("periodStart", wp.period_start.to_string())
                .put("periodEnd", wp.period_end.to_string())
                .put("autoRenew", wp.auto_renew)
                .put("nextPlanId", opt(wp.next_plan_id))
                .build(),
            _ => Value::Null,
        };
        Ok(Obj::new()
            .put("currency", config.currency.as_str())
            .put("lowBalanceThreshold", config.low_balance_threshold.map(Dec::to_json).unwrap_or(Value::Null))
            .put("suspendMode", config.suspend_mode.as_str())
            .put("purchasedCreditValidityMonths", opt(config.purchased_credit_validity_months))
            .put("balance", wallet.as_ref().map(|w| w.balance.to_json()).unwrap_or(Value::Null))
            .put("walletStatus", opt(wallet.as_ref().map(|w| w.status.clone())))
            .put("plan", plan)
            .put("plans", Value::Array(plan_rows))
            .put("meters", Value::Array(meter_rows))
            .put("credits", Value::Array(credits))
            .put("dimensions", Value::Array(dims))
            .build())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn uuids_are_version_4() {
        let u = random_uuid();
        assert_eq!(u.len(), 36);
        assert_eq!(&u[14..15], "4");
        assert!(matches!(&u[19..20], "8" | "9" | "a" | "b"));
        assert_ne!(u, random_uuid());
    }
}
