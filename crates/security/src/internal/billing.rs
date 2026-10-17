//! `WalletService`, `AppBillingConfigService` and `SecurityMeteringService`, as
//! `InternalBillingController` uses them: metered and AI charges, the serving and hosting
//! gates, and the security-owned metering run.
//!
//! The SQL steps are Java's, in Java's order and without a transaction (as in Java): the
//! transaction row's unique idempotency key is what makes a repeated charge harmless.

use std::sync::Arc;

use chrono::{Datelike, Duration, NaiveDate, Timelike};
use serde_json::Value;

use super::Internal;
use crate::caches;
use crate::data::billing::{action, BillingConfig, Txn, Wallet};
use crate::decimal::Dec;
use crate::errors::{AuthError, AuthResult};
use crate::events::EventMessage;
use crate::jackson::{opt, Obj};
use crate::javamap::hash_map_order_str;
use crate::model::ContextAuth;

pub const WALLET_LOW_BALANCE: &str = "WALLET_LOW_BALANCE";
pub const WALLET_SUSPENDED: &str = "WALLET_SUSPENDED";
const SECURITY_ACTIONS: [&str; 3] = [action::APP_RENT, action::SITE_RENT, action::USER];
const ONE_MILLION: i128 = 1_000_000;

/// `ChargeRequest`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ChargeRequest {
    pub config_client_id: Option<u64>,
    pub billed_client_id: Option<u64>,
    pub app_id: Option<u64>,
    pub action_key: Option<String>,
    pub quantity: Option<Dec>,
    pub date: Option<NaiveDate>,
    pub window_index: Option<i32>,
}

/// `AiChargeRequest`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AiChargeRequest {
    pub client_code: Option<String>,
    pub app_code: Option<String>,
    pub model: Option<String>,
    pub weighted_tokens: Option<Dec>,
    pub request_id: Option<String>,
    pub session_id: Option<String>,
}

/// `ChargeResult`.
#[derive(Debug, Clone, PartialEq)]
pub struct ChargeResult {
    pub charged: bool,
    pub suspended: bool,
    pub low_balance_crossed: bool,
    pub balance_after: Dec,
}

impl ChargeResult {
    pub fn none() -> Self {
        Self { charged: false, suspended: false, low_balance_crossed: false, balance_after: Dec::ZERO }
    }

    pub fn to_json(&self) -> Value {
        Obj::new()
            .put("charged", self.charged)
            .put("suspended", self.suspended)
            .put("lowBalanceCrossed", self.low_balance_crossed)
            .put("balanceAfter", self.balance_after.to_json())
            .build()
    }
}

/// `HostingDecision`.
pub fn hosting_json(suspended: bool, app: Option<&str>, client: Option<&str>) -> Value {
    Obj::new()
        .put("suspended", suspended)
        .put("serveAppCode", opt(app.map(str::to_string)))
        .put("serveClientCode", opt(client.map(str::to_string)))
        .build()
}

/// `WalletStatusView`.
pub fn status_json(status: &str, balance: Option<Dec>, suspended: bool) -> Value {
    Obj::new()
        .put("status", status)
        .put("balance", balance.map(Dec::to_json).unwrap_or(Value::Null))
        .put("suspended", suspended)
        .build()
}

/// The 15-minute charge for a period's quantity: what is above the free allowance, at the
/// monthly rate, over the month's windows, rounded down. `None` when nothing is due.
pub fn metered_tokens(config: &BillingConfig, action_key: &str, quantity: Dec, date: NaiveDate) -> Option<Dec> {
    let rate = config.rate_for(action_key).filter(|r| r.signum() > 0)?;
    let free = config.free_for(action_key).unwrap_or(Dec::ZERO);
    let billable = quantity.sub(free).max(Dec::ZERO);
    let windows = i128::from(days_in_month(date)) * 96;
    let tokens = billable.mul(rate).div_down(windows);
    (tokens.signum() > 0).then_some(tokens)
}

/// The tokens one AI call costs past the monthly grant: only the part of this call that
/// crosses the grant line is priced.
pub fn ai_tokens(month_to_date: Dec, used: Dec, grant: Option<Dec>, rate_per_million: Dec) -> Dec {
    let free = grant.map(|g| g.max(Dec::ZERO)).unwrap_or(Dec::ZERO);
    let after = month_to_date.add(used).sub(free).max(Dec::ZERO);
    let before = month_to_date.sub(free).max(Dec::ZERO);
    after.sub(before).mul(rate_per_million).div_down(ONE_MILLION)
}

pub fn days_in_month(d: NaiveDate) -> u32 {
    let (y, m) = (d.year(), d.month());
    let next = if m == 12 { NaiveDate::from_ymd_opt(y + 1, 1, 1) } else { NaiveDate::from_ymd_opt(y, m + 1, 1) };
    next.map(|n| (n - Duration::days(1)).day()).unwrap_or(30)
}

/// What a debit did, before its side effects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebitOutcome {
    pub low_cross: bool,
    pub now_negative: bool,
    pub newly_suspended: bool,
}

/// `applyDebit`'s decisions: crossing the low-balance threshold (once, until a credit resets
/// it), and going below zero for the first time.
pub fn debit_outcome(wallet: &Wallet, config: Option<&BillingConfig>, before: Dec, after: Dec) -> DebitOutcome {
    let threshold = wallet.alert_threshold.or_else(|| config.and_then(|c| c.low_balance_threshold));
    let low_cross = threshold.is_some_and(|t| {
        before.cmp_value(&t) != std::cmp::Ordering::Less
            && after.cmp_value(&t) == std::cmp::Ordering::Less
            && wallet.low_balance_notified.unwrap_or(0) == 0
    });
    let now_negative = after.signum() < 0;
    DebitOutcome { low_cross, now_negative, newly_suspended: now_negative && !wallet.suspended() }
}

impl Internal {
    /// `AppBillingConfigService.readByAppAndClient` (`cacheEmptyValueOrGet`).
    pub async fn billing_config_by_codes(&self, app_code: &str, client_code: &str) -> AuthResult<Option<BillingConfig>> {
        let store = self.billing.clone();
        let (a, c) = (app_code.to_string(), client_code.to_string());
        let v = self
            .caches()
            .billing_configs
            .get_or_load(caches::BILLING_CONFIG_BY_CODES, format!("{app_code}{client_code}"), || async move {
                Ok::<_, AuthError>(Some(Arc::new(store.config_by_codes(&a, &c).await?)))
            })
            .await?;
        Ok(v.and_then(|v| (*v).clone()))
    }

    /// `getOrCreateWallet`: seeded with one token, ACTIVE, so the first action proceeds.
    async fn wallet_or_create(&self, client_id: u64, app_id: u64) -> AuthResult<Option<Wallet>> {
        if let Some(w) = self.billing.wallet(client_id, app_id).await? {
            return Ok(Some(w));
        }
        self.billing.create_seeded_wallet(client_id, app_id, Dec::ONE).await
    }

    /// `resolveConfigForBilledClient`: the client's own config for the app, else the nearest
    /// manager's.
    async fn config_for_billed_client(&self, app_id: u64, billed_client_id: u64) -> AuthResult<Option<BillingConfig>> {
        for ancestor in self.client_hierarchy_ids(billed_client_id).await? {
            if let Some(c) = self.billing.config_by_app_client(app_id, ancestor).await? {
                return Ok(Some(c));
            }
        }
        Ok(None)
    }

    /// `WalletService.charge`.
    pub async fn charge(&self, ca: &ContextAuth, req: &ChargeRequest) -> AuthResult<ChargeResult> {
        let (Some(app_id), Some(config_client)) = (req.app_id, req.config_client_id) else { return Ok(ChargeResult::none()) };
        let Some(config) = self.billing.config_by_app_client(app_id, config_client).await? else { return Ok(ChargeResult::none()) };
        let action_key = req.action_key.clone().unwrap_or_default();
        if config.rate_for(&action_key).is_none_or(|r| r.signum() <= 0) {
            return Ok(ChargeResult::none());
        }
        let quantity = req.quantity.ok_or_else(|| AuthError::internal("quantity is null"))?;
        let date = req.date.ok_or_else(|| AuthError::internal("date is null"))?;
        let Some(tokens) = metered_tokens(&config, &action_key, quantity, date) else { return Ok(ChargeResult::none()) };
        let window = req.window_index.map(|w| w as i16);
        let window_text = req.window_index.map(|w| w.to_string()).unwrap_or_else(|| "null".into());
        let billed = req.billed_client_id.ok_or_else(|| AuthError::internal("billedClientId is null"))?;
        let Some(wallet) = self.wallet_or_create(billed, app_id).await? else { return Ok(ChargeResult::none()) };
        let txn = Txn {
            wallet_id: wallet.id,
            kind: "DEBIT",
            tokens,
            balance_after: wallet.balance.sub(tokens),
            action_key: Some(action_key.clone()),
            app_id: Some(wallet.app_id),
            quantity: Some(quantity),
            charge_date: Some(date),
            window_index: window,
            idempotency_key: format!("{action_key}:{date}:{window_text}"),
            reason: format!("Metered {action_key} window {window_text}"),
            created_by: None,
        };
        self.apply_debit(ca, &wallet, Some(&config), txn).await
    }

    /// `applyDebit`: the transaction row first (a repeated idempotency key stops here), then the
    /// balance, then the low-balance and suspension side effects.
    async fn apply_debit(&self, ca: &ContextAuth, wallet: &Wallet, config: Option<&BillingConfig>, txn: Txn) -> AuthResult<ChargeResult> {
        let before = wallet.balance;
        let after = txn.balance_after;
        let tokens = txn.tokens;
        let already = wallet.suspended();
        let unchanged = ChargeResult { charged: false, suspended: already, low_balance_crossed: false, balance_after: before };
        if !self.billing.record_txn(&txn).await? || self.billing.debit(wallet.id, tokens).await? == 0 {
            return Ok(unchanged);
        }
        let o = debit_outcome(wallet, config, before, after);
        if o.low_cross {
            self.billing.set_low_balance_notified(wallet.id, true).await?;
            self.raise_wallet_event(ca, WALLET_LOW_BALANCE, wallet, after).await;
        }
        if o.newly_suspended {
            self.billing.set_status(wallet.id, "SUSPENDED").await?;
            self.caches().service.evict_everywhere(caches::WALLET_STATUS, &format!("{}{}", wallet.client_id, wallet.app_id)).await;
            self.raise_wallet_event(ca, WALLET_SUSPENDED, wallet, after).await;
        }
        Ok(ChargeResult { charged: true, suspended: o.now_negative || already, low_balance_crossed: o.low_cross, balance_after: after })
    }

    /// `raiseWalletEvent`: best effort, a failure is logged and the charge stands.
    async fn raise_wallet_event(&self, ca: &ContextAuth, name: &str, wallet: &Wallet, balance: Dec) {
        if let Err(e) = self.try_raise_wallet_event(ca, name, wallet, balance).await {
            tracing::error!(event = name, wallet = wallet.id, error = %e, "wallet event not raised");
        }
    }

    async fn try_raise_wallet_event(&self, ca: &ContextAuth, name: &str, wallet: &Wallet, balance: Dec) -> AuthResult<()> {
        let app = self.dir().app_by_id(wallet.app_id).await?;
        let Some(client) = self.dir().client(wallet.client_id).await? else { return Ok(()) };
        let url_client = match self.dir().managed_client(wallet.client_id).await {
            Ok(m) => m.id.unwrap_or(wallet.client_id),
            Err(_) => wallet.client_id,
        };
        let url_prefix = self.app_url_for(ca, &app, url_client).await.unwrap_or_default();
        let fields: Vec<(&str, Value)> = vec![
            ("walletId", Value::from(wallet.id)),
            ("appCode", Value::from(app.app_code.clone())),
            ("clientCode", Value::from(client.code())),
            ("clientName", Value::from(client.name.clone().unwrap_or_default())),
            // Jackson writes the BigDecimal's digits; a JSON number with the same value here.
            ("balance", serde_json::from_str(&balance.to_string()).unwrap_or(Value::Null)),
            ("urlPrefix", Value::from(url_prefix)),
        ];
        let order = hash_map_order_str(fields.iter().map(|(k, _)| *k));
        let data = order
            .into_iter()
            .filter_map(|k| fields.iter().find(|(f, _)| *f == k).map(|(k, v)| (k.to_string(), v.clone())))
            .collect();
        let event = EventMessage {
            event_name: name.to_string(),
            client_code: Some(client.code().to_string()),
            app_code: Some(app.app_code.clone()),
            x_debug: None,
            draft: false,
            data,
        };
        self.wallet_events.publish(&event).await?;
        Ok(())
    }

    /// `chargeBulk`: each request on its own; a failing one charges nothing.
    pub async fn charge_bulk(&self, ca: &ContextAuth, requests: &[ChargeRequest]) {
        for r in requests {
            if let Err(e) = self.charge(ca, r).await {
                tracing::warn!(error = %e, "charge skipped");
            }
        }
    }

    /// `isAiAllowed`: false only when the governing config bills and the client's wallet is
    /// suspended.
    pub async fn is_ai_allowed(&self, app_code: &str, client_code: &str) -> AuthResult<bool> {
        let Some(app) = self.dir().app_by_code(app_code).await? else { return Ok(true) };
        let Some(client) = self.client_by_code(client_code).await? else { return Ok(true) };
        let Some(config) = self.config_for_billed_client(app.id, client.id()).await? else { return Ok(true) };
        if !config.is_active() {
            return Ok(true);
        }
        Ok(match self.billing.wallet(client.id(), app.id).await? {
            Some(w) => !w.suspended(),
            None => true,
        })
    }

    /// `chargeAi`.
    pub async fn charge_ai(&self, ca: &ContextAuth, req: &AiChargeRequest) -> AuthResult<ChargeResult> {
        let unbilled = || {
            tracing::warn!(app = ?req.app_code, client = ?req.client_code, tokens = ?req.weighted_tokens.map(|t| t.to_string()),
                model = ?req.model, request = ?req.request_id, "AI usage UNBILLED: no billing config resolved");
            ChargeResult::none()
        };
        let Some(app) = (match &req.app_code {
            Some(a) => self.dir().app_by_code(a).await?,
            None => None,
        }) else {
            return Ok(unbilled());
        };
        let Some(client) = (match &req.client_code {
            Some(c) => self.client_by_code(c).await?,
            None => None,
        }) else {
            return Ok(unbilled());
        };
        let Some(config) = self.config_for_billed_client(app.id, client.id()).await? else { return Ok(unbilled()) };
        if !config.is_active() {
            return Ok(ChargeResult::none());
        }
        let Some(rate) = config.ai_tokens_per_million.filter(|r| r.signum() > 0) else { return Ok(ChargeResult::none()) };
        let Some(wallet) = self.wallet_or_create(client.id(), app.id).await? else { return Ok(ChargeResult::none()) };
        self.charge_ai_on_wallet(ca, &wallet, &config, rate, req).await
    }

    async fn charge_ai_on_wallet(&self, ca: &ContextAuth, wallet: &Wallet, config: &BillingConfig, rate: Dec, req: &AiChargeRequest) -> AuthResult<ChargeResult> {
        let today = self.auth.clock.local().date();
        let idem = format!("ai:{}", req.request_id.as_deref().unwrap_or("null"));
        let reason = format!("AI usage {}", req.model.as_deref().unwrap_or("null"));
        let used = req.weighted_tokens.unwrap_or(Dec::ZERO);
        let grant = config.free_ai_tokens_per_month;
        let month_to_date = match grant.filter(|g| g.signum() > 0) {
            Some(_) => {
                let first = today.with_day(1).unwrap_or(today);
                let last = today.with_day(days_in_month(today)).unwrap_or(today);
                self.billing.sum_quantity_between(wallet.id, action::AI_LLM_TOKENS, first, last).await?
            }
            None => Dec::ZERO,
        };
        let tokens = ai_tokens(month_to_date, used, grant, rate);
        let mut txn = Txn {
            wallet_id: wallet.id,
            kind: "DEBIT",
            tokens,
            balance_after: wallet.balance.sub(tokens),
            action_key: Some(action::AI_LLM_TOKENS.to_string()),
            app_id: Some(wallet.app_id),
            quantity: Some(used),
            charge_date: Some(today),
            window_index: None,
            idempotency_key: idem,
            reason,
            created_by: None,
        };
        if tokens.signum() <= 0 {
            // Free (or below one token): recorded with zero tokens so the grant still depletes.
            txn.tokens = Dec::ZERO;
            txn.balance_after = wallet.balance;
            self.billing.record_txn(&txn).await?;
            return Ok(ChargeResult { charged: false, suspended: wallet.suspended(), low_balance_crossed: false, balance_after: wallet.balance });
        }
        self.apply_debit(ca, wallet, Some(config), txn).await
    }

    /// `getServingStatus`: ACTIVE when the URL's app and client have no config; otherwise the
    /// caller's wallet (created if absent).
    pub async fn serving_status(&self, url_app_code: &str, url_client_code: &str, client_id: u64) -> AuthResult<Value> {
        let active = status_json("ACTIVE", None, false);
        let Some(config) = self.billing_config_by_codes(url_app_code, url_client_code).await? else { return Ok(active) };
        Ok(match self.wallet_or_create(client_id, config.app_id).await? {
            Some(w) => status_json(&w.status, Some(w.balance), w.suspended()),
            None => active,
        })
    }

    /// `resolveHosting`: serve the app, or the configured suspend app and client when the
    /// builder wallet (appbuilder for apps; sitezump, else appbuilder, for sites) is suspended.
    pub async fn hosting(&self, url_app_code: &str, url_client_code: &str) -> AuthResult<Value> {
        let pass = || hosting_json(false, Some(url_app_code), Some(url_client_code));
        if url_client_code.trim().is_empty() || url_client_code.eq_ignore_ascii_case("SYSTEM") || url_app_code.trim().is_empty() {
            return Ok(pass());
        }
        let Some(client) = self.client_by_code(url_client_code).await? else { return Ok(pass()) };
        let Some(app) = self.dir().app_by_code(url_app_code).await? else { return Ok(pass()) };
        let builders: &[&str] = if app.app_type.as_deref() == Some("SITE") { &["sitezump", "appbuilder"] } else { &["appbuilder"] };
        let mut found = None;
        for b in builders {
            if let Some(builder) = self.dir().app_by_code(b).await? {
                if let Some(w) = self.billing.wallet(client.id(), builder.id).await? {
                    found = Some((builder, w));
                    break;
                }
            }
        }
        let Some((builder, wallet)) = found else { return Ok(pass()) };
        if !wallet.suspended() {
            return Ok(pass());
        }
        let Some(config) = self.config_for_billed_client(builder.id, client.id()).await? else { return Ok(pass()) };
        Ok(match (config.suspend_app_code.as_deref(), config.suspend_client_code.as_deref()) {
            (Some(a), Some(c)) if !a.trim().is_empty() && !c.trim().is_empty() => hosting_json(true, Some(a), Some(c)),
            _ => pass(),
        })
    }

    /// `SecurityMeteringService.runWindow`.
    pub async fn meter_window(&self, ca: &ContextAuth, date: NaiveDate, window: i32) -> AuthResult<()> {
        for a in SECURITY_ACTIONS {
            for instr in self.billing.charge_instructions(a).await? {
                self.charge_one(ca, a, &instr, date, window).await;
            }
        }
        Ok(())
    }

    /// `SecurityMeteringService.runCurrentWindow`: today's window in the server's zone.
    pub async fn meter_current_window(&self, ca: &ContextAuth) -> AuthResult<()> {
        let now = self.auth.clock.local();
        let window = (now.time().num_seconds_from_midnight() / 900) as i32;
        self.meter_window(ca, now.date(), window).await
    }

    /// `SecurityMeteringService.reconcileDay`: every window of the day not charged yet.
    pub async fn reconcile_day(&self, ca: &ContextAuth, date: NaiveDate) -> AuthResult<()> {
        for a in SECURITY_ACTIONS {
            for instr in self.billing.charge_instructions(a).await? {
                let Some(w) = self.wallet_or_create(instr.billed_client_id, instr.app_id).await? else { continue };
                let done = self.billing.charged_windows(w.id, a, date).await?;
                for window in 0..96 {
                    if !done.contains(&(window as i16)) {
                        self.charge_one(ca, a, &instr, date, window).await;
                    }
                }
            }
        }
        Ok(())
    }

    async fn charge_one(&self, ca: &ContextAuth, action_key: &str, instr: &crate::data::billing::Instruction, date: NaiveDate, window: i32) {
        let count = match action_key {
            action::APP_RENT => self.billing.count_apps(instr.billed_client_id, "APP").await,
            action::SITE_RENT => self.billing.count_apps(instr.billed_client_id, "SITE").await,
            action::USER => self.billing.count_users_with_profile(instr.billed_client_id, instr.app_id).await,
            _ => Ok(0),
        };
        let Ok(count) = count.filter_ok() else { return };
        let req = ChargeRequest {
            config_client_id: Some(instr.config_client_id),
            billed_client_id: Some(instr.billed_client_id),
            app_id: Some(instr.app_id),
            action_key: Some(action_key.to_string()),
            quantity: Some(Dec::from_i64(count)),
            date: Some(date),
            window_index: Some(window),
        };
        if let Err(e) = self.charge(ca, &req).await {
            tracing::warn!(error = %e, action = action_key, "metered charge skipped");
        }
    }
}

trait FilterOk {
    fn filter_ok(self) -> Result<i64, ()>;
}

/// `countFor(...).filter(count -> count > 0)`, errors swallowed by `onErrorResume`.
impl FilterOk for AuthResult<i64> {
    fn filter_ok(self) -> Result<i64, ()> {
        match self {
            Ok(n) if n > 0 => Ok(n),
            _ => Err(()),
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> Dec {
        Dec::parse(s).unwrap()
    }

    fn config() -> BillingConfig {
        BillingConfig {
            app_rent_per_month: Some(d("2880.0000")),
            free_apps: Some(d("1.0000")),
            user_tokens_per_month: Some(d("0.0000")),
            ai_tokens_per_million: Some(d("100.0000")),
            status: "ACTIVE".into(),
            ..Default::default()
        }
    }

    #[test]
    fn metered_charges() {
        let oct = NaiveDate::from_ymd_opt(2026, 10, 16).unwrap();
        // 3 apps, 1 free, 2880 a month, 31 * 96 windows: 2 * 2880 / 2976 = 1.93 -> 1.
        assert_eq!(metered_tokens(&config(), action::APP_RENT, d("3"), oct).unwrap().to_string(), "1");
        assert_eq!(metered_tokens(&config(), action::APP_RENT, d("1"), oct), None);
        assert_eq!(metered_tokens(&config(), action::USER, d("100"), oct), None);
        assert_eq!(metered_tokens(&config(), "nope", d("100"), oct), None);
        assert_eq!(days_in_month(NaiveDate::from_ymd_opt(2024, 2, 3).unwrap()), 29);
        assert_eq!(days_in_month(NaiveDate::from_ymd_opt(2026, 12, 3).unwrap()), 31);
    }

    #[test]
    fn ai_pricing_crosses_the_grant() {
        let r = d("100.0000");
        // Fully inside the grant.
        assert_eq!(ai_tokens(d("0"), d("500000"), Some(d("1000000")), r).to_string(), "0");
        // Straddling: 600k used of a 1M grant, this call 1M: 600k billable -> 60 tokens.
        assert_eq!(ai_tokens(d("600000"), d("1000000"), Some(d("1000000")), r).to_string(), "60");
        // No grant.
        assert_eq!(ai_tokens(d("0"), d("2500000"), None, r).to_string(), "250");
        assert_eq!(ai_tokens(d("0"), d("2500000"), Some(d("-5")), r).to_string(), "250");
    }

    #[test]
    fn debit_side_effects() {
        let w = Wallet { balance: d("10.0000"), status: "ACTIVE".into(), ..Default::default() };
        let c = BillingConfig { low_balance_threshold: Some(d("5.0000")), ..config() };
        assert_eq!(debit_outcome(&w, Some(&c), d("10"), d("4")), DebitOutcome { low_cross: true, now_negative: false, newly_suspended: false });
        assert_eq!(debit_outcome(&w, Some(&c), d("4"), d("-1")), DebitOutcome { low_cross: false, now_negative: true, newly_suspended: true });
        let notified = Wallet { low_balance_notified: Some(1), ..w.clone() };
        assert!(!debit_outcome(&notified, Some(&c), d("10"), d("4")).low_cross);
        let own = Wallet { alert_threshold: Some(d("20")), ..w.clone() };
        assert!(debit_outcome(&own, Some(&c), d("25"), d("15")).low_cross);
        let suspended = Wallet { status: "SUSPENDED".into(), ..w };
        assert!(!debit_outcome(&suspended, None, d("-1"), d("-2")).newly_suspended);
    }

    #[test]
    fn bodies() {
        assert_eq!(crate::jackson::pretty(&ChargeResult::none().to_json()), "{\n  \"charged\" : false,\n  \"suspended\" : false,\n  \"lowBalanceCrossed\" : false,\n  \"balanceAfter\" : 0\n}");
        assert_eq!(status_json("ACTIVE", None, false), serde_json::json!({"status": "ACTIVE", "suspended": false}));
        assert_eq!(crate::jackson::pretty(&status_json("SUSPENDED", Some(d("-3.5000")), true)), "{\n  \"status\" : \"SUSPENDED\",\n  \"balance\" : -3.5000,\n  \"suspended\" : true\n}");
        assert_eq!(hosting_json(false, Some("a"), None), serde_json::json!({"suspended": false, "serveAppCode": "a"}));
        assert_eq!(Ok::<i64, AuthError>(0).filter_ok(), Err(()));
        assert_eq!(Ok::<i64, AuthError>(2).filter_ok(), Ok(2));
    }
}
