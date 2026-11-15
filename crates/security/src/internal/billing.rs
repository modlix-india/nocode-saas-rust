//! The billing rules of security-internal: what a meter charges, the AI price of a call, the
//! gates (may the client use this, is the app served), and the security-owned metering run.
//! The daily run (expiry, plan renewal, monthly invoices, overdue) is `billing_cycle.rs`.
//!
//! **Which config governs a client.** The nearest managing client (the client's own manager
//! first, then its manager, up to four levels) that has a config for the app. A client's own
//! config is what it sells to the clients under it, never what it pays.
//!
//! **TOKENS or INVOICE.** A TOKENS meter debits the client's wallet (a gauge every 15 minutes, pro
//! rata of its monthly rate; a counter when the use happens). An INVOICE meter only records usage
//! (a gauge's highest count of the day, a counter's events), which the monthly invoice bills.
//!
//! **Plans.** A wallet may be on one of the config's plans; a plan overrides a meter's free
//! quantity and rate, and can make the free quantity a hard cap (the action is refused at it,
//! nothing is charged: the Free plan). A new wallet starts on the config's default plan.

use std::sync::Arc;

use chrono::{Datelike, Duration, Months, NaiveDate, NaiveDateTime, Timelike};
use serde_json::{Map, Value};

use super::Internal;
use crate::caches;
use crate::data::billing::{action, platform_meter, terms, AiRate, BillingConfig, Meter, NewLot, Plan, Txn, Usage, Wallet};
use crate::decimal::Dec;
use crate::errors::{AuthError, AuthResult};
use crate::events::EventMessage;
use crate::jackson::{opt, Obj};
use crate::javamap::hash_map_order_str;
use crate::model::ContextAuth;

pub const WALLET_LOW_BALANCE: &str = "WALLET_LOW_BALANCE";
pub const WALLET_SUSPENDED: &str = "WALLET_SUSPENDED";
/// The security-owned gauge sources, as their producer action names.
const SECURITY_ACTIONS: [&str; 3] = [action::APP_RENT, action::SITE_RENT, action::USER];
const ONE_MILLION: i128 = 1_000_000;
/// Decimals the wallet keeps (`DECIMAL(19,6)`, V90).
pub const SCALE: u32 = 6;
/// The platform setting with the USD to INR rate for AI prices.
pub const AI_FX_RATE: &str = "AI_FX_RATE";

/// `ChargeRequest`: a gauge's count for one window, from a producer.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ChargeRequest {
    pub config_client_id: Option<u64>,
    pub billed_client_id: Option<u64>,
    pub app_id: Option<u64>,
    /// The producer's action name (`core.storage.rows`, `files.gb`, ...).
    pub action_key: Option<String>,
    pub quantity: Option<Dec>,
    pub date: Option<NaiveDate>,
    pub window_index: Option<i32>,
    /// The meter, when the producer counts for one (a storage count); else every meter of the source.
    pub meter_id: Option<u64>,
}

/// An AI call's usage, from nocode-ai.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AiChargeRequest {
    pub client_code: Option<String>,
    pub app_code: Option<String>,
    pub model: Option<String>,
    pub input_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
    pub cache_read_tokens: Option<i64>,
    pub cache_write_tokens: Option<i64>,
    /// The old body: tokens already weighted by model, priced at the dearest rate.
    pub weighted_tokens: Option<Dec>,
    pub request_id: Option<String>,
    pub session_id: Option<String>,
}

/// A use an app (or the platform) records against a meter.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RecordRequest {
    pub client_code: Option<String>,
    pub app_code: Option<String>,
    pub meter_key: Option<String>,
    /// Named figures; a bare quantity is `{quantity: n}`.
    pub figures: Map<String, Value>,
    /// The app's id for the use: a retry with the same reference counts once.
    pub reference: Option<String>,
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

/// What a record did.
#[derive(Debug, Clone, PartialEq)]
pub struct RecordResult {
    pub recorded: bool,
    /// The use is past a hard cap: kept by the app, not charged.
    pub over_limit: bool,
    pub charged: Dec,
    pub suspended: bool,
}

impl RecordResult {
    fn nothing() -> Self {
        Self { recorded: false, over_limit: false, charged: Dec::ZERO, suspended: false }
    }

    pub fn to_json(&self) -> Value {
        Obj::new()
            .put("recorded", self.recorded)
            .put("overLimit", self.over_limit)
            .put("charged", self.charged.to_json())
            .put("suspended", self.suspended)
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

/// An allow answer: `{allowed, reason}`.
pub fn allowed_json(allowed: bool, reason: Option<&str>) -> Value {
    Obj::new().put("allowed", allowed).put("reason", opt(reason.map(str::to_string))).build()
}

pub fn days_in_month(d: NaiveDate) -> u32 {
    let (y, m) = (d.year(), d.month());
    let next = if m == 12 { NaiveDate::from_ymd_opt(y + 1, 1, 1) } else { NaiveDate::from_ymd_opt(y, m + 1, 1) };
    next.map(|n| (n - Duration::days(1)).day()).unwrap_or(30)
}

pub fn month_start(d: NaiveDate) -> NaiveDate {
    d.with_day(1).unwrap_or(d)
}

pub fn month_end(d: NaiveDate) -> NaiveDate {
    d.with_day(days_in_month(d)).unwrap_or(d)
}

/// The day a period that starts on `start` ends (exclusive).
pub fn period_end(start: NaiveDate, period: &str) -> NaiveDate {
    let months = if period == "YEAR" { 12 } else { 1 };
    start.checked_add_months(Months::new(months)).unwrap_or(start + Duration::days(30))
}

/// One 15-minute window's share of a monthly rate for what is above the free quantity, at six
/// decimals (so a small rate accrues instead of rounding to nothing). `None` when nothing is due.
pub fn window_tokens(quantity: Dec, free: Dec, rate: Dec, date: NaiveDate) -> Option<Dec> {
    if rate.signum() <= 0 {
        return None;
    }
    let billable = quantity.sub(free).max(Dec::ZERO);
    let windows = i128::from(days_in_month(date)) * 96;
    let tokens = billable.mul(rate).div_down_scaled(windows, SCALE);
    (tokens.signum() > 0).then_some(tokens)
}

/// The part of a counted use past the month's free quantity: what this use adds above the line.
pub fn above_free(month_to_date: Dec, used: Dec, free: Dec) -> Dec {
    let free = free.max(Dec::ZERO);
    let after = month_to_date.add(used).sub(free).max(Dec::ZERO);
    let before = month_to_date.sub(free).max(Dec::ZERO);
    after.sub(before)
}

/// Credits for `units` of a counter at its rate unit.
pub fn counter_tokens(units: Dec, rate: Dec, rate_unit: &str) -> Dec {
    match rate_unit {
        "PER_MILLION" => units.mul(rate).div_down_scaled(ONE_MILLION, SCALE),
        _ => units.mul(rate).round_down(SCALE),
    }
}

/// The rate of a model: the longest pattern its name contains.
pub fn rate_for_model<'r>(rates: &'r [AiRate], model: &str) -> Option<&'r AiRate> {
    let m = model.to_lowercase();
    rates.iter().filter(|r| !r.pattern.is_empty() && m.contains(&r.pattern)).max_by_key(|r| r.pattern.len())
}

/// The dearest rate (by output price): what an unknown model is charged.
pub fn dearest(rates: &[AiRate]) -> Option<&AiRate> {
    rates.iter().max_by(|a, b| a.output.cmp_value(&b.output))
}

/// What an AI call cost us, in the rate's currency.
pub fn ai_cost(rate: &AiRate, req: &AiChargeRequest) -> Dec {
    let part = |n: Option<i64>, per_m: Dec| Dec::from_i64(n.unwrap_or(0).max(0)).mul(per_m);
    let raw = if let Some(w) = req.weighted_tokens.filter(|_| {
        req.input_tokens.is_none() && req.output_tokens.is_none() && req.cache_read_tokens.is_none() && req.cache_write_tokens.is_none()
    }) {
        // The old body carries one weighted number: priced at the output rate, never cheaper.
        w.max(Dec::ZERO).mul(rate.output)
    } else {
        part(req.input_tokens, rate.input)
            .add(part(req.output_tokens, rate.output))
            .add(part(req.cache_read_tokens, rate.cache_read))
            .add(part(req.cache_write_tokens, rate.cache_write))
    };
    raw.div_down_scaled(ONE_MILLION, SCALE)
}

/// What a debit did, before its side effects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebitOutcome {
    pub low_cross: bool,
    pub now_negative: bool,
    pub newly_suspended: bool,
}

/// The decisions of a debit: crossing the low-balance threshold (once, until a credit resets it),
/// and going below zero for the first time.
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
    /// The ACTIVE config of (app code, client code), cached (empty answers too).
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

    /// The config that governs a client on an app: its nearest managing client's (never its own).
    pub async fn governing_config(&self, app_id: u64, client_id: u64) -> AuthResult<Option<BillingConfig>> {
        let ids = match self.client_hierarchy_ids(client_id).await {
            Ok(ids) => ids,
            Err(_) => return Ok(None),
        };
        for ancestor in ids.into_iter().filter(|a| *a != client_id) {
            if let Some(c) = self.billing.config_by_app_client(app_id, ancestor).await? {
                return Ok(Some(c));
            }
        }
        Ok(None)
    }

    /// The client's wallet on the app, created (at zero) when absent. A new wallet goes on the
    /// governing config's default plan, with its credits.
    pub async fn wallet_ready(&self, ca: &ContextAuth, client_id: u64, app_id: u64, config: Option<&BillingConfig>) -> AuthResult<Option<Wallet>> {
        if let Some(w) = self.billing.wallet(client_id, app_id).await? {
            return Ok(Some(w));
        }
        let Some((wallet, created)) = self.billing.create_wallet(client_id, app_id).await? else { return Ok(None) };
        if created {
            if let Some(c) = config {
                if let Some(plan) = self.default_plan(c.id).await? {
                    let today = self.auth.clock.local().date();
                    self.put_on_plan(ca, &wallet, c, &plan, today, false).await?;
                    return self.billing.wallet_by_id(wallet.id).await;
                }
            }
        }
        Ok(Some(wallet))
    }

    /// Starts a plan period for the wallet and gives the plan's credits: every period when they
    /// recur (expiring with the period), once when they do not (`once_only`: already given).
    pub async fn put_on_plan(&self, ca: &ContextAuth, wallet: &Wallet, config: &BillingConfig, plan: &Plan, start: NaiveDate, once_only: bool) -> AuthResult<u64> {
        let end = period_end(start, &plan.period);
        let wp = self.billing.start_wallet_plan(wallet.id, plan.id, start, end).await?;
        let give = plan.included_tokens.signum() > 0 && (plan.included_recurring || !once_only);
        if give {
            let expires = plan.included_recurring.then(|| end.and_hms_opt(0, 0, 0)).flatten();
            let key = if plan.included_recurring { format!("plan:{wp}:{start}") } else { format!("plan-once:{}:{}", wallet.id, plan.id) };
            let reason = format!("{} plan credits", plan.label);
            self.credit_wallet(ca, wallet, config, plan.included_tokens, &key, &reason, NewLot {
                source: "PLAN",
                reference_type: Some("WALLET_PLAN".into()),
                reference_id: Some(wp),
                expires_at: expires,
            })
            .await?;
        }
        Ok(wp)
    }

    /// The config's default plan (where a new client starts), if it has an ACTIVE one.
    pub async fn default_plan(&self, config_id: u64) -> AuthResult<Option<Plan>> {
        Ok(self.billing.plans_of_config(config_id).await?.into_iter().find(|p| p.is_default && p.status == "ACTIVE"))
    }

    /// The wallet's current plan.
    pub async fn plan_of(&self, wallet: &Wallet) -> AuthResult<Option<Plan>> {
        let Some(wp) = self.billing.wallet_plan(wallet.id).await? else { return Ok(None) };
        self.billing.plan_by_id(wp.plan_id).await
    }

    /// A credit: the ledger row, the balance and its lot; then the low-balance latch reset and a
    /// suspended wallet back above zero reactivated.
    pub async fn credit_wallet(&self, ca: &ContextAuth, wallet: &Wallet, config: &BillingConfig, tokens: Dec, key: &str, reason: &str, lot: NewLot) -> AuthResult<ChargeResult> {
        self.credit_wallet_by(ca.user.id, wallet, config, tokens, key, reason, lot).await
    }

    /// [`Self::credit_wallet`] recording who made the credit (a purchase records the buyer who
    /// started it, LZT-2003; a grant or adjustment the acting user).
    pub async fn credit_wallet_by(&self, by: Option<u64>, wallet: &Wallet, _config: &BillingConfig, tokens: Dec, key: &str, reason: &str, lot: NewLot) -> AuthResult<ChargeResult> {
        let fresh = self.billing.wallet_by_id(wallet.id).await?.unwrap_or_else(|| wallet.clone());
        let after = fresh.balance.add(tokens);
        let txn = Txn {
            wallet_id: wallet.id,
            kind: if lot.source == "PURCHASE" { "CREDIT" } else { "ADJUST" },
            tokens,
            balance_after: after,
            app_id: Some(wallet.app_id),
            idempotency_key: key.to_string(),
            reference_type: lot.reference_type.clone(),
            reference_id: lot.reference_id,
            reason: reason.to_string(),
            created_by: by,
            ..Default::default()
        };
        if !self.billing.credit(&txn, &lot).await? {
            return Ok(ChargeResult { charged: false, suspended: fresh.suspended(), low_balance_crossed: false, balance_after: fresh.balance });
        }
        self.billing.set_low_balance_notified(wallet.id, false).await?;
        if fresh.suspended() && after.signum() > 0 {
            self.billing.set_status(wallet.id, "ACTIVE").await?;
        }
        self.evict_wallet_status(wallet).await;
        Ok(ChargeResult { charged: true, suspended: fresh.suspended() && after.signum() <= 0, low_balance_crossed: false, balance_after: after })
    }

    async fn evict_wallet_status(&self, wallet: &Wallet) {
        self.caches().service.evict_everywhere(caches::WALLET_STATUS, &format!("{}{}", wallet.client_id, wallet.app_id)).await;
    }

    /// A debit and its side effects: the low-balance event once, the suspension on going below
    /// zero. A repeated idempotency key changes nothing.
    async fn apply_debit(&self, ca: &ContextAuth, wallet: &Wallet, config: Option<&BillingConfig>, txn: Txn) -> AuthResult<ChargeResult> {
        let before = wallet.balance;
        let after = txn.balance_after;
        let already = wallet.suspended();
        if !self.billing.debit(&txn).await? {
            return Ok(ChargeResult { charged: false, suspended: already, low_balance_crossed: false, balance_after: before });
        }
        let o = debit_outcome(wallet, config, before, after);
        if o.low_cross {
            self.billing.set_low_balance_notified(wallet.id, true).await?;
            self.raise_wallet_event(ca, WALLET_LOW_BALANCE, wallet, after).await;
        }
        if o.newly_suspended {
            self.billing.set_status(wallet.id, "SUSPENDED").await?;
            self.evict_wallet_status(wallet).await;
            self.raise_wallet_event(ca, WALLET_SUSPENDED, wallet, after).await;
        }
        Ok(ChargeResult { charged: true, suspended: o.now_negative || already, low_balance_crossed: o.low_cross, balance_after: after })
    }

    /// A wallet event, best effort: a failure is logged and the charge stands.
    pub async fn raise_wallet_event(&self, ca: &ContextAuth, name: &str, wallet: &Wallet, balance: Dec) {
        let extra = vec![("balance", serde_json::from_str(&balance.to_string()).unwrap_or(Value::Null))];
        if let Err(e) = self.raise_billing_event(ca, name, wallet.client_id, wallet.app_id, Some(wallet.id), extra).await {
            tracing::error!(event = name, wallet = wallet.id, error = %e, "wallet event not raised");
        }
    }

    /// A billing event for (client, app), with the app's URL prefix and the given fields.
    pub async fn raise_billing_event(&self, ca: &ContextAuth, name: &str, client_id: u64, app_id: u64, wallet_id: Option<u64>, extra: Vec<(&str, Value)>) -> AuthResult<()> {
        let app = self.dir().app_by_id(app_id).await?;
        let Some(client) = self.dir().client(client_id).await? else { return Ok(()) };
        let url_client = match self.dir().managed_client(client_id).await {
            Ok(m) => m.id.unwrap_or(client_id),
            Err(_) => client_id,
        };
        let url_prefix = self.app_url_for(ca, &app, url_client).await.unwrap_or_default();
        let mut fields: Vec<(&str, Value)> = vec![
            ("appCode", Value::from(app.app_code.clone())),
            ("clientCode", Value::from(client.code())),
            ("clientName", Value::from(client.name.clone().unwrap_or_default())),
            ("urlPrefix", Value::from(url_prefix)),
        ];
        if let Some(w) = wallet_id {
            fields.push(("walletId", Value::from(w)));
        }
        fields.extend(extra);
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

    /// A gauge's count for one window: each matching meter of the config either debits its
    /// window share (TOKENS) or keeps the day's highest count (INVOICE).
    pub async fn charge(&self, ca: &ContextAuth, req: &ChargeRequest) -> AuthResult<ChargeResult> {
        let (Some(app_id), Some(config_client)) = (req.app_id, req.config_client_id) else { return Ok(ChargeResult::none()) };
        let Some(config) = self.billing.config_by_app_client(app_id, config_client).await? else { return Ok(ChargeResult::none()) };
        if !config.is_active() {
            return Ok(ChargeResult::none());
        }
        let Some(source) = req.action_key.as_deref().and_then(action::source) else { return Ok(ChargeResult::none()) };
        let quantity = req.quantity.ok_or_else(|| AuthError::internal("quantity is null"))?;
        let date = req.date.ok_or_else(|| AuthError::internal("date is null"))?;
        let billed = req.billed_client_id.ok_or_else(|| AuthError::internal("billedClientId is null"))?;
        let meters: Vec<Meter> = self
            .billing
            .meters_of_config(config.id)
            .await?
            .into_iter()
            .filter(|m| m.status == "ACTIVE" && m.source == source && req.meter_id.is_none_or(|id| id == m.id))
            .collect();
        if meters.is_empty() {
            return Ok(ChargeResult::none());
        }
        let app = self.dir().app_by_id(app_id).await?;
        let Some(mut wallet) = self.wallet_ready(ca, billed, app_id, Some(&config)).await? else { return Ok(ChargeResult::none()) };
        let plan = self.plan_of(&wallet).await?;
        let mut last = ChargeResult::none();
        for m in meters {
            let t = terms(&m, plan.as_ref());
            if m.invoiced() {
                let u = Usage { client_id: billed, app_id, meter_id: m.id, date, kind: "SNAPSHOT", quantity, figures: None, reference: None };
                self.billing.record_usage(&u).await?;
                continue;
            }
            if t.hard_cap.is_some() {
                continue;
            }
            let Some(tokens) = window_tokens(quantity, t.free, t.rate, date) else { continue };
            let action_key = m.action_key(&app.app_code);
            let window_text = req.window_index.map(|w| w.to_string()).unwrap_or_else(|| "null".into());
            let txn = Txn {
                wallet_id: wallet.id,
                kind: "DEBIT",
                tokens,
                balance_after: wallet.balance.sub(tokens),
                action_key: Some(action_key.clone()),
                app_id: Some(app_id),
                quantity: Some(quantity),
                charge_date: Some(date),
                window_index: req.window_index.map(|w| w as i16),
                idempotency_key: format!("{action_key}:{date}:{window_text}"),
                reason: format!("{} window {window_text}", m.label),
                ..Default::default()
            };
            last = self.apply_debit(ca, &wallet, Some(&config), txn).await?;
            if last.charged {
                wallet.balance = last.balance_after;
                if last.suspended {
                    wallet.status = "SUSPENDED".into();
                }
            }
        }
        Ok(last)
    }

    /// Each charge on its own; a failing one charges nothing.
    pub async fn charge_bulk(&self, ca: &ContextAuth, requests: &[ChargeRequest]) {
        for r in requests {
            if let Err(e) = self.charge(ca, r).await {
                tracing::warn!(error = %e, "charge skipped");
            }
        }
    }

    /// The (app, client, governing config, meter) of a code pair and a meter key.
    async fn resolve_meter(&self, app_code: &str, client_code: &str, meter_key: &str) -> AuthResult<Option<(Arc<crate::model::App>, u64, BillingConfig, Meter)>> {
        let Some(app) = self.dir().app_by_code(app_code).await? else { return Ok(None) };
        let Some(client) = self.client_by_code(client_code).await? else { return Ok(None) };
        let Some(config) = self.governing_config(app.id, client.id()).await? else { return Ok(None) };
        if !config.is_active() {
            return Ok(None);
        }
        let meter = self.billing.meters_of_config(config.id).await?.into_iter().find(|m| m.key == meter_key && m.status == "ACTIVE");
        Ok(meter.map(|m| (app, client.id(), config, m)))
    }

    /// The figure a meter charges on: its basis, else `quantity`, else one use.
    pub fn units_of(meter: &Meter, figures: &Map<String, Value>) -> Dec {
        let basis = meter.basis.as_deref().filter(|b| !b.trim().is_empty()).unwrap_or("quantity");
        figures.get(basis).and_then(Dec::from_json).unwrap_or(Dec::ONE).max(Dec::ZERO)
    }

    /// A use of a counter meter: an INVOICE meter keeps the event for the monthly invoice, a
    /// TOKENS meter debits what is above the month's free quantity. Past a hard cap nothing is
    /// recorded or charged (`overLimit`).
    pub async fn record(&self, ca: &ContextAuth, req: &RecordRequest) -> AuthResult<RecordResult> {
        let (Some(app_code), Some(client_code), Some(key)) = (req.app_code.as_deref(), req.client_code.as_deref(), req.meter_key.as_deref()) else {
            return Ok(RecordResult::nothing());
        };
        let Some((app, client_id, config, meter)) = self.resolve_meter(app_code, client_code, key).await? else {
            tracing::warn!(app = app_code, client = client_code, meter = key, "usage UNBILLED: no active meter governs it");
            return Ok(RecordResult::nothing());
        };
        if meter.is_gauge() {
            let why = format!("Meter {key} is counted on a schedule; a use cannot be recorded against it.");
            return Err(AuthError::literal(axum::http::StatusCode::BAD_REQUEST, "SEC.BILLING_INVALID", why.clone()).with_param("reason", why));
        }
        let reference = req.reference.clone().filter(|r| !r.trim().is_empty()).unwrap_or_else(crate::admin::billing::wallets::random_uuid);
        let units = Self::units_of(&meter, &req.figures);
        let Some(wallet) = self.wallet_ready(ca, client_id, app.id, Some(&config)).await? else { return Ok(RecordResult::nothing()) };
        let plan = self.plan_of(&wallet).await?;
        let t = terms(&meter, plan.as_ref());
        let today = self.auth.clock.local().date();
        let used = self.month_usage(&meter, &wallet, client_id, &app.app_code, today).await?;
        if let Some(cap) = t.hard_cap {
            if used.add(units).cmp_value(&cap) == std::cmp::Ordering::Greater {
                return Ok(RecordResult { recorded: false, over_limit: true, charged: Dec::ZERO, suspended: wallet.suspended() });
            }
        }
        if meter.invoiced() {
            let u = Usage {
                client_id,
                app_id: app.id,
                meter_id: meter.id,
                date: today,
                kind: "EVENT",
                quantity: units,
                figures: Some(req.figures.clone()),
                reference: Some(reference),
            };
            let recorded = self.billing.record_usage(&u).await?;
            return Ok(RecordResult { recorded, over_limit: false, charged: Dec::ZERO, suspended: false });
        }
        let billable = if t.hard_cap.is_some() { Dec::ZERO } else { above_free(used, units, t.free) };
        let tokens = counter_tokens(billable, t.rate, &meter.rate_unit);
        let action_key = meter.action_key(&app.app_code);
        let txn = Txn {
            wallet_id: wallet.id,
            kind: "DEBIT",
            tokens,
            balance_after: wallet.balance.sub(tokens),
            action_key: Some(action_key),
            app_id: Some(app.id),
            quantity: Some(units),
            charge_date: Some(today),
            idempotency_key: format!("ev:{}:{reference}", meter.key),
            reason: format!("{} {reference}", meter.label),
            description: (!req.figures.is_empty()).then(|| Value::Object(req.figures.clone()).to_string()),
            ..Default::default()
        };
        if tokens.signum() <= 0 {
            // Inside the free quantity: kept with zero tokens so the allowance still depletes.
            let recorded = self.billing.record_txn(&Txn { tokens: Dec::ZERO, balance_after: wallet.balance, ..txn }).await?;
            return Ok(RecordResult { recorded, over_limit: false, charged: Dec::ZERO, suspended: wallet.suspended() });
        }
        let r = self.apply_debit(ca, &wallet, Some(&config), txn).await?;
        Ok(RecordResult { recorded: r.charged, over_limit: false, charged: if r.charged { tokens } else { Dec::ZERO }, suspended: r.suspended })
    }

    /// A counter's use so far this month (events less reversals; ledger quantities for TOKENS).
    pub async fn month_usage(&self, meter: &Meter, wallet: &Wallet, client_id: u64, app_code: &str, today: NaiveDate) -> AuthResult<Dec> {
        let (from, to) = (month_start(today), month_end(today));
        if meter.invoiced() {
            let p = self.billing.period_usage(meter.id, client_id, from, to + Duration::days(1)).await?;
            return Ok(p.events.sub(p.reversals).max(Dec::ZERO));
        }
        self.billing.sum_quantity_between(wallet.id, &meter.action_key(app_code), from, to).await
    }

    /// Undoes a recorded use within the meter's refund window: an INVOICE meter writes a
    /// reversal, a TOKENS meter credits back what the use cost. Outside the window (or with no
    /// refund policy) nothing changes.
    pub async fn reverse(&self, ca: &ContextAuth, req: &RecordRequest) -> AuthResult<Value> {
        let no = |why: &str| Obj::new().put("reversed", false).put("reason", why).build();
        let (Some(app_code), Some(client_code), Some(key), Some(reference)) =
            (req.app_code.as_deref(), req.client_code.as_deref(), req.meter_key.as_deref(), req.reference.as_deref())
        else {
            return Ok(no("appCode, clientCode, meterKey and reference are needed"));
        };
        let Some((app, client_id, config, meter)) = self.resolve_meter(app_code, client_code, key).await? else { return Ok(no("no meter")) };
        if meter.refund_policy != "WITHIN_DAYS" {
            return Ok(no("the meter does not refund"));
        }
        let days = meter.refund_days.unwrap_or(0);
        let now = self.auth.clock.local();
        let in_window = |at: NaiveDateTime| now - at <= Duration::days(days);
        if meter.invoiced() {
            let Some((u, at)) = self.billing.usage_by_reference(meter.id, client_id, reference).await? else { return Ok(no("no such use")) };
            if !in_window(at) {
                return Ok(no("past the refund window"));
            }
            let rev = Usage { kind: "REVERSAL", date: now.date(), figures: None, ..u };
            let done = self.billing.record_usage(&rev).await?;
            return Ok(Obj::new().put("reversed", done).build());
        }
        let Some(wallet) = self.billing.wallet(client_id, app.id).await? else { return Ok(no("no wallet")) };
        let Some((txn, at)) = self.billing.txn_by_key(wallet.id, &format!("ev:{key}:{reference}")).await? else { return Ok(no("no such use")) };
        if !in_window(at) {
            return Ok(no("past the refund window"));
        }
        let expires = self.purchase_expiry(&config, now);
        let r = self
            .credit_wallet(ca, &wallet, &config, txn.tokens, &format!("rev:{key}:{reference}"), &format!("Refund {} {reference}", meter.label), NewLot {
                source: "ADJUST",
                reference_type: Some("REFUND".into()),
                reference_id: None,
                expires_at: expires,
            })
            .await?;
        Ok(Obj::new().put("reversed", r.charged).put("refunded", txn.tokens.to_json()).build())
    }

    /// When a bought credit added now expires under the config.
    pub fn purchase_expiry(&self, config: &BillingConfig, now: NaiveDateTime) -> Option<NaiveDateTime> {
        let months = config.purchased_credit_validity_months.filter(|m| *m > 0)?;
        // EXPIRES_AT is a TIMESTAMP: nothing past 2038-01-19 can be stored.
        let last = NaiveDate::from_ymd_opt(2038, 1, 1).and_then(|d| d.and_hms_opt(0, 0, 0));
        let at = now.checked_add_months(Months::new(months.min(1200) as u32))?;
        Some(match last {
            Some(l) if at > l => l,
            _ => at,
        })
    }

    /// The USD to INR rate for AI prices (`AI_FX_RATE`).
    async fn fx(&self, currency: &str, into: &str) -> AuthResult<Dec> {
        if currency.eq_ignore_ascii_case(into) {
            return Ok(Dec::ONE);
        }
        match self.billing.setting(AI_FX_RATE).await?.as_deref().and_then(Dec::parse) {
            Some(r) if r.signum() > 0 => Ok(r),
            _ => {
                tracing::error!(from = currency, to = into, "AI_FX_RATE is not set: AI prices taken 1:1");
                Ok(Dec::ONE)
            }
        }
    }

    /// May the client use the meter (or AI, when no meter is named) now. False when the governing
    /// config bills and: a TOKENS meter's wallet is suspended; a hard cap is reached; the plan does
    /// not allow the model.
    /// `count` is the app's own current count, for a meter security cannot count itself (a
    /// storage's rows); without it such a cap is not checked.
    pub async fn allowed(&self, app_code: &str, client_code: &str, meter_key: Option<&str>, model: Option<&str>, count: Option<Dec>) -> AuthResult<Value> {
        let yes = || allowed_json(true, None);
        let Some(app) = self.dir().app_by_code(app_code).await? else { return Ok(yes()) };
        let Some(client) = self.client_by_code(client_code).await? else { return Ok(yes()) };
        let Some(config) = self.governing_config(app.id, client.id()).await? else { return Ok(yes()) };
        if !config.is_active() {
            return Ok(yes());
        }
        let key = meter_key.unwrap_or(platform_meter::AI_TOKENS);
        let meters = self.billing.meters_of_config(config.id).await?;
        let meter = meters
            .iter()
            .find(|m| m.status == "ACTIVE" && (m.key == key || (meter_key.is_none() && m.source == "AI_TOKENS")));
        // No wallet yet (the client's first use): judge by the plan it will land on, the config's
        // default plan, so a new Free client cannot use a premium model or pass a cap once.
        let wallet = self.billing.wallet(client.id(), app.id).await?;
        let plan = match wallet.as_ref() {
            Some(w) => self.plan_of(w).await?,
            None => self.default_plan(config.id).await?,
        };
        if let (Some(p), Some(model)) = (plan.as_ref(), model) {
            if !p.allows_model(model) {
                return Ok(allowed_json(false, Some("The plan does not include this AI model")));
            }
        }
        let suspended = wallet.as_ref().is_some_and(Wallet::suspended);
        let Some(meter) = meter else {
            // AI with no AI meter on the config: only a suspended wallet stops it.
            return Ok(if meter_key.is_none() && suspended { allowed_json(false, Some("The wallet is suspended")) } else { yes() });
        };
        if !meter.invoiced() && suspended {
            return Ok(allowed_json(false, Some("The wallet is suspended")));
        }
        let t = terms(meter, plan.as_ref());
        if let Some(cap) = t.hard_cap {
            let used = if meter.is_gauge() {
                match (meter.source.as_str(), count) {
                    ("USERS" | "APPS" | "SITES", _) => self.gauge_count(meter, client.id(), app.id).await?,
                    (_, Some(c)) => c,
                    (_, None) => {
                        tracing::warn!(meter = meter.key, "hard cap not checked: the app sent no count");
                        return Ok(yes());
                    }
                }
            } else {
                match wallet.as_ref() {
                    Some(w) => self.month_usage(meter, w, client.id(), &app.app_code, self.auth.clock.local().date()).await?,
                    // Event meters on the invoice count by client, wallet or not; credit meters need one.
                    None if meter.invoiced() => {
                        let today = self.auth.clock.local().date();
                        let p = self.billing.period_usage(meter.id, client.id(), month_start(today), month_end(today) + Duration::days(1)).await?;
                        p.events.sub(p.reversals).max(Dec::ZERO)
                    }
                    None => Dec::ZERO,
                }
            };
            if used.cmp_value(&cap) != std::cmp::Ordering::Less {
                return Ok(allowed_json(false, Some("The plan's limit is reached")));
            }
        }
        Ok(yes())
    }

    /// `isAiAllowed`, as nocode-ai asks it.
    pub async fn is_ai_allowed(&self, app_code: &str, client_code: &str) -> AuthResult<bool> {
        Ok(self.allowed(app_code, client_code, None, None, None).await?["allowed"] == Value::Bool(true))
    }

    /// The current count of a security gauge (users, apps, sites); 0 for the others.
    pub async fn gauge_count(&self, meter: &Meter, client_id: u64, app_id: u64) -> AuthResult<Dec> {
        let active_only = !meter.source_config.get("countArchived").and_then(Value::as_bool).unwrap_or(false);
        let n = match meter.source.as_str() {
            "USERS" => {
                let profiles: Vec<u64> = meter
                    .source_config
                    .get("profileIds")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))).collect())
                    .unwrap_or_default();
                self.billing.count_users_with_profile(client_id, app_id, &profiles).await?
            }
            "APPS" => self.billing.count_apps(client_id, "APP", active_only).await?,
            "SITES" => self.billing.count_apps(client_id, "SITE", active_only).await?,
            _ => 0,
        };
        Ok(Dec::from_i64(n))
    }

    /// An AI call: what it cost us for its model (input, output, cache read, cache write), in the
    /// config's currency, times the meter's markup. The month's free quantity (credits) goes first.
    pub async fn charge_ai(&self, ca: &ContextAuth, req: &AiChargeRequest) -> AuthResult<ChargeResult> {
        let unbilled = |why: &str| {
            tracing::warn!(app = ?req.app_code, client = ?req.client_code, model = ?req.model, request = ?req.request_id, why, "AI usage UNBILLED");
            ChargeResult::none()
        };
        let (Some(app_code), Some(client_code)) = (req.app_code.as_deref(), req.client_code.as_deref()) else { return Ok(unbilled("no app or client")) };
        let Some(app) = self.dir().app_by_code(app_code).await? else { return Ok(unbilled("no app")) };
        let Some(client) = self.client_by_code(client_code).await? else { return Ok(unbilled("no client")) };
        let Some(config) = self.governing_config(app.id, client.id()).await? else { return Ok(unbilled("no billing config")) };
        if !config.is_active() {
            return Ok(ChargeResult::none());
        }
        let Some(meter) = self.billing.meters_of_config(config.id).await?.into_iter().find(|m| m.status == "ACTIVE" && m.source == "AI_TOKENS") else {
            return Ok(unbilled("no AI meter"));
        };
        let rates = self.billing.ai_rates().await?;
        let model = req.model.clone().unwrap_or_default();
        let rate = match rate_for_model(&rates, &model) {
            Some(r) => r.clone(),
            None => match dearest(&rates) {
                Some(r) => {
                    tracing::error!(model, "AI MODEL UNPRICED: charged at the dearest known rate");
                    r.clone()
                }
                None => return Ok(unbilled("no AI model rates")),
            },
        };
        let cost = ai_cost(&rate, req).mul(self.fx(&rate.currency, &config.currency).await?);
        let Some(wallet) = self.wallet_ready(ca, client.id(), app.id, Some(&config)).await? else { return Ok(ChargeResult::none()) };
        let plan = self.plan_of(&wallet).await?;
        let t = terms(&meter, plan.as_ref());
        // The meter's rate is the markup on cost (MARKUP); PER_MILLION prices raw tokens instead.
        let gross = if meter.rate_unit == "MARKUP" {
            cost.mul(t.rate).round_down(SCALE)
        } else {
            let raw = req.input_tokens.unwrap_or(0) + req.output_tokens.unwrap_or(0) + req.cache_read_tokens.unwrap_or(0) + req.cache_write_tokens.unwrap_or(0);
            counter_tokens(Dec::from_i64(raw.max(0)), t.rate, "PER_MILLION")
        };
        let today = self.auth.clock.local().date();
        let request = req.request_id.as_deref().unwrap_or("null");
        let figures = Obj::new()
            .put("model", model.as_str())
            .put("inputTokens", req.input_tokens.unwrap_or(0))
            .put("outputTokens", req.output_tokens.unwrap_or(0))
            .put("cacheReadTokens", req.cache_read_tokens.unwrap_or(0))
            .put("cacheWriteTokens", req.cache_write_tokens.unwrap_or(0))
            // A JSON number (`Dec::to_json` is a marker only the pretty writer resolves).
            .put("cost", serde_json::from_str::<Value>(&cost.to_string()).unwrap_or(Value::Null))
            .build();
        if meter.invoiced() {
            let u = Usage {
                client_id: client.id(),
                app_id: app.id,
                meter_id: meter.id,
                date: today,
                kind: "EVENT",
                quantity: gross,
                figures: figures.as_object().cloned(),
                reference: Some(format!("ai:{request}")),
            };
            self.billing.record_usage(&u).await?;
            return Ok(ChargeResult { charged: false, suspended: wallet.suspended(), low_balance_crossed: false, balance_after: wallet.balance });
        }
        let action_key = meter.action_key(&app.app_code);
        let used = self.billing.sum_quantity_between(wallet.id, &action_key, month_start(today), month_end(today)).await?;
        let tokens = above_free(used, gross, t.free);
        let txn = Txn {
            wallet_id: wallet.id,
            kind: "DEBIT",
            tokens,
            balance_after: wallet.balance.sub(tokens),
            action_key: Some(action_key),
            app_id: Some(app.id),
            quantity: Some(gross),
            charge_date: Some(today),
            idempotency_key: format!("ai:{request}"),
            reason: format!("AI usage {model}"),
            description: Some(figures.to_string()),
            ..Default::default()
        };
        if tokens.signum() <= 0 {
            self.billing.record_txn(&Txn { tokens: Dec::ZERO, balance_after: wallet.balance, ..txn }).await?;
            return Ok(ChargeResult { charged: false, suspended: wallet.suspended(), low_balance_crossed: false, balance_after: wallet.balance });
        }
        self.apply_debit(ca, &wallet, Some(&config), txn).await
    }

    /// `getServingStatus`: ACTIVE when the URL's app and client have no config; otherwise the
    /// caller's wallet (created if absent).
    pub async fn serving_status(&self, url_app_code: &str, url_client_code: &str, client_id: u64) -> AuthResult<Value> {
        let active = status_json("ACTIVE", None, false);
        let Some(config) = self.billing_config_by_codes(url_app_code, url_client_code).await? else { return Ok(active) };
        let ca = ContextAuth::default();
        Ok(match self.wallet_ready(&ca, client_id, config.app_id, Some(&config)).await? {
            Some(w) => status_json(&w.status, Some(w.balance), w.suspended()),
            None => active,
        })
    }

    /// Whether the app is served for the URL's client, or the configured suspend app and client:
    /// when the builder wallet (appbuilder for apps; sitezump, else appbuilder, for sites) is
    /// suspended, or when the app's own governing config blocks the app and the client's wallet is
    /// suspended or it has an overdue invoice.
    pub async fn hosting(&self, url_app_code: &str, url_client_code: &str) -> AuthResult<Value> {
        let pass = || hosting_json(false, Some(url_app_code), Some(url_client_code));
        if url_client_code.trim().is_empty() || url_client_code.eq_ignore_ascii_case("SYSTEM") || url_app_code.trim().is_empty() {
            return Ok(pass());
        }
        let Some(client) = self.client_by_code(url_client_code).await? else { return Ok(pass()) };
        let Some(app) = self.dir().app_by_code(url_app_code).await? else { return Ok(pass()) };
        let serve = |config: &BillingConfig| match (config.suspend_app_code.as_deref(), config.suspend_client_code.as_deref()) {
            (Some(a), Some(c)) if !a.trim().is_empty() && !c.trim().is_empty() => Some(hosting_json(true, Some(a), Some(c))),
            _ => None,
        };
        // The app's own terms first.
        if let Some(config) = self.governing_config(app.id, client.id()).await? {
            if config.is_active() && config.blocks_app() {
                let suspended = self.billing.wallet(client.id(), app.id).await?.is_some_and(|w| w.suspended());
                if suspended || self.billing.has_overdue_invoice(client.id(), app.id).await? {
                    if let Some(v) = serve(&config) {
                        return Ok(v);
                    }
                }
            }
        }
        let builders: &[&str] = if app.app_type.as_deref() == Some("SITE") { &["sitezump", "appbuilder"] } else { &["appbuilder"] };
        for b in builders {
            let Some(builder) = self.dir().app_by_code(b).await? else { continue };
            let Some(w) = self.billing.wallet(client.id(), builder.id).await? else { continue };
            if !w.suspended() {
                return Ok(pass());
            }
            let Some(config) = self.governing_config(builder.id, client.id()).await? else { return Ok(pass()) };
            return Ok(serve(&config).unwrap_or_else(pass));
        }
        Ok(pass())
    }

    /// Security's gauges for one window.
    pub async fn meter_window(&self, ca: &ContextAuth, date: NaiveDate, window: i32) -> AuthResult<()> {
        for a in SECURITY_ACTIONS {
            let Some(source) = action::source(a) else { continue };
            for instr in self.billing.charge_instructions(source).await? {
                self.charge_one(ca, a, &instr, date, window).await;
            }
        }
        Ok(())
    }

    /// Today's window in the server's zone.
    pub async fn meter_current_window(&self, ca: &ContextAuth) -> AuthResult<()> {
        let now = self.auth.clock.local();
        let window = (now.time().num_seconds_from_midnight() / 900) as i32;
        self.meter_window(ca, now.date(), window).await
    }

    /// Every window of the day not charged yet, for security's gauges.
    pub async fn reconcile_gauges(&self, ca: &ContextAuth, date: NaiveDate) -> AuthResult<()> {
        for a in SECURITY_ACTIONS {
            let Some(source) = action::source(a) else { continue };
            for instr in self.billing.charge_instructions(source).await? {
                let Some(meter) = (match instr.meter_id {
                    Some(id) => self.billing.meter_by_id(id).await?,
                    None => None,
                }) else {
                    continue;
                };
                if meter.invoiced() {
                    self.charge_one(ca, a, &instr, date, 95).await;
                    continue;
                }
                let Some(w) = self.billing.wallet(instr.billed_client_id, instr.app_id).await? else {
                    self.charge_one(ca, a, &instr, date, 0).await;
                    continue;
                };
                let done = self.billing.charged_windows(w.id, &meter.action_key(&instr.app_code), date).await?;
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
        let Some(meter) = (match instr.meter_id {
            Some(id) => self.billing.meter_by_id(id).await.ok().flatten(),
            None => None,
        }) else {
            return;
        };
        let count = match self.gauge_count(&meter, instr.billed_client_id, instr.app_id).await {
            Ok(n) if n.signum() > 0 => n,
            _ => return,
        };
        let req = ChargeRequest {
            config_client_id: Some(instr.config_client_id),
            billed_client_id: Some(instr.billed_client_id),
            app_id: Some(instr.app_id),
            action_key: Some(action_key.to_string()),
            quantity: Some(count),
            date: Some(date),
            window_index: Some(window),
            meter_id: Some(meter.id),
        };
        if let Err(e) = self.charge(ca, &req).await {
            tracing::warn!(error = %e, action = action_key, "metered charge skipped");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> Dec {
        Dec::parse(s).unwrap()
    }

    #[test]
    fn window_shares_accrue_at_six_decimals() {
        let oct = NaiveDate::from_ymd_opt(2026, 10, 16).unwrap();
        // 3 apps, 1 free, 2880 a month over 31 * 96 windows: 2 * 2880 / 2976 = 1.935483.
        assert_eq!(window_tokens(d("3"), d("1"), d("2880"), oct).unwrap().to_string(), "1.935483");
        // A small rate no longer rounds to nothing: 1 a month for one user.
        assert_eq!(window_tokens(d("1"), Dec::ZERO, d("1"), oct).unwrap().to_string(), "0.000336");
        assert_eq!(window_tokens(d("1"), d("1"), d("2880"), oct), None);
        assert_eq!(window_tokens(d("100"), Dec::ZERO, Dec::ZERO, oct), None);
        assert_eq!(days_in_month(NaiveDate::from_ymd_opt(2024, 2, 3).unwrap()), 29);
        assert_eq!(days_in_month(NaiveDate::from_ymd_opt(2026, 12, 3).unwrap()), 31);
    }

    #[test]
    fn counters_price_only_what_crosses_the_free_line() {
        assert_eq!(above_free(d("0"), d("50"), d("100")).to_string(), "0");
        assert_eq!(above_free(d("60"), d("100"), d("100")).to_string(), "60");
        assert_eq!(above_free(d("0"), d("25"), Dec::ZERO).to_string(), "25");
        assert_eq!(above_free(d("0"), d("25"), d("-5")).to_string(), "25");
        assert_eq!(counter_tokens(d("2500000"), d("100"), "PER_MILLION").to_string(), "250.000000");
        assert_eq!(counter_tokens(d("3"), d("1.5"), "EACH").to_string(), "4.500000");
    }

    fn rate(p: &str, i: &str, o: &str, r: &str, w: &str) -> AiRate {
        AiRate { pattern: p.into(), input: d(i), output: d(o), cache_read: d(r), cache_write: d(w), currency: "USD".into() }
    }

    #[test]
    fn ai_calls_cost_what_their_model_costs() {
        let rates = vec![rate("opus", "15", "75", "1.5", "18.75"), rate("deepseek", "0.3", "1.2", "0.03", "0.3"), rate("deepseek-v4-pro", "1", "4", "0.1", "1")];
        assert_eq!(rate_for_model(&rates, "DeepSeek-V4-Pro").unwrap().pattern, "deepseek-v4-pro");
        assert_eq!(rate_for_model(&rates, "deepseek-v4-flash").unwrap().pattern, "deepseek");
        assert!(rate_for_model(&rates, "gpt-9").is_none());
        assert_eq!(dearest(&rates).unwrap().pattern, "opus");
        let call = AiChargeRequest { input_tokens: Some(1_000_000), output_tokens: Some(100_000), cache_read_tokens: Some(10_000_000), ..Default::default() };
        // 15 + 7.5 + 15 = 37.5 on opus; 0.3 + 0.12 + 0.3 = 0.72 on deepseek: the ratio of their prices.
        assert_eq!(ai_cost(&rates[0], &call).to_string(), "37.500000");
        assert_eq!(ai_cost(&rates[1], &call).to_string(), "0.720000");
        // A cache read costs its cache price, not the output price.
        let cached = AiChargeRequest { cache_read_tokens: Some(1_000_000), ..Default::default() };
        assert_eq!(ai_cost(&rates[0], &cached).to_string(), "1.500000");
        // The old body: weighted tokens at the output price.
        let old = AiChargeRequest { weighted_tokens: Some(d("1000000")), ..Default::default() };
        assert_eq!(ai_cost(&rates[1], &old).to_string(), "1.200000");
    }

    #[test]
    fn debit_side_effects() {
        let w = Wallet { balance: d("10.0000"), status: "ACTIVE".into(), ..Default::default() };
        let c = BillingConfig { low_balance_threshold: Some(d("5.0000")), ..Default::default() };
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
    fn periods_and_units() {
        let start = NaiveDate::from_ymd_opt(2026, 1, 31).unwrap();
        assert_eq!(period_end(start, "MONTH"), NaiveDate::from_ymd_opt(2026, 2, 28).unwrap());
        assert_eq!(period_end(start, "YEAR"), NaiveDate::from_ymd_opt(2027, 1, 31).unwrap());
        let m = Meter::default();
        let f = serde_json::json!({"quantity": 3, "bookingValue": 12000000}).as_object().unwrap().clone();
        assert_eq!(Internal::units_of(&m, &f).to_string(), "3");
        assert_eq!(Internal::units_of(&m, &Map::new()).to_string(), "1");
        let by_value = Meter { basis: Some("bookingValue".into()), ..Default::default() };
        assert_eq!(Internal::units_of(&by_value, &f).to_string(), "12000000");
    }

    #[test]
    fn bodies() {
        assert_eq!(crate::jackson::pretty(&ChargeResult::none().to_json()), "{\n  \"charged\" : false,\n  \"suspended\" : false,\n  \"lowBalanceCrossed\" : false,\n  \"balanceAfter\" : 0\n}");
        assert_eq!(status_json("ACTIVE", None, false), serde_json::json!({"status": "ACTIVE", "suspended": false}));
        assert_eq!(hosting_json(false, Some("a"), None), serde_json::json!({"suspended": false, "serveAppCode": "a"}));
        assert_eq!(allowed_json(false, Some("x")), serde_json::json!({"allowed": false, "reason": "x"}));
    }
}
