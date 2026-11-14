//! The billing rules of security-internal (meters, plans, credit lots, the daily cycle), over an
//! in-memory billing store, so no real wallet is ever debited. The ported scenarios of
//! `WalletServiceTest` and `SecurityMeteringServiceTest` now run on meters.
//!
//! The monthly invoice reads its seller fields through `Internal.db` (not the billing store), so
//! raising one needs a schema to read from: those tests are gated like the live ones
//! (`SECURITY_AUTH_LIVE=1` with `eval "$(tools/local-env.py)"`) and only READ the local schema.

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use async_trait::async_trait;
use chrono::{NaiveDate, NaiveDateTime};
use common::{app, dt, harness, Harness, RecordingEvents};
use security::data::billing::{
    action, sql, AiRate, BillingConfig, BillingStore, Instruction, Lot, Meter, MeterOverride, NewLot, PeriodUsage, Plan, Txn, Usage,
    Wallet, WalletPlan,
};
use security::data::billing_admin::{Rec, Val, INVOICE};
use security::data::Db;
use security::decimal::Dec;
use security::errors::{AuthError, AuthResult};
use security::internal::billing::{
    days_in_month, AiChargeRequest, ChargeRequest, RecordRequest, AI_FX_RATE, WALLET_LOW_BALANCE, WALLET_SUSPENDED,
};
use security::internal::billing_cycle::{totals, INVOICE_ISSUED, INVOICE_OVERDUE, WALLET_CREDITS_EXPIRED, WALLET_CREDITS_EXPIRING, WALLET_PLAN_LAPSED};
use security::internal::Internal;
use security::model::ContextAuth;
use serde_json::{json, Map, Value};

// ---------------------------------------------------------------------------------------------
// The in-memory billing store

#[derive(Debug, Clone)]
struct UsageRow {
    u: Usage,
    at: NaiveDateTime,
    invoice: Option<u64>,
}

#[derive(Default)]
struct Books {
    /// The ledger's and the usage's CREATED_AT.
    now: NaiveDateTime,
    configs: Vec<BillingConfig>,
    meters: Vec<Meter>,
    plans: Vec<Plan>,
    wallet_plans: Vec<WalletPlan>,
    wallets: Vec<Wallet>,
    txns: Vec<Txn>,
    txn_at: HashMap<(u64, String), NaiveDateTime>,
    lots: Vec<Lot>,
    usage: Vec<UsageRow>,
    /// (meter source, instruction)
    instructions: Vec<(String, Instruction)>,
    app_counts: Vec<((u64, String), i64)>,
    user_counts: Vec<((u64, u64), i64)>,
    rates: Vec<AiRate>,
    settings: HashMap<String, String>,
    invoices: Vec<Rec>,
    lines: Vec<Rec>,
    debits: Vec<(u64, Dec)>,
    statuses: Vec<(u64, String)>,
    notified: Vec<(u64, bool)>,
    fail_counts: bool,
    next: u64,
}

impl Books {
    fn id(&mut self) -> u64 {
        self.next += 1;
        100 + self.next
    }

    fn wallet_mut(&mut self, id: u64) -> Option<&mut Wallet> {
        self.wallets.iter_mut().find(|w| w.id == id)
    }

    fn used(&self, t: &Txn) -> bool {
        self.txns.iter().any(|x| x.wallet_id == t.wallet_id && x.idempotency_key == t.idempotency_key)
    }

    fn push_txn(&mut self, t: &Txn) {
        self.txns.push(t.clone());
        let now = self.now;
        self.txn_at.insert((t.wallet_id, t.idempotency_key.clone()), now);
    }

    /// `ORDER BY EXPIRES_AT IS NULL, EXPIRES_AT, ID` over the lots with credits left.
    fn open_lots(&self, wallet_id: u64) -> Vec<Lot> {
        let mut v: Vec<Lot> = self.lots.iter().filter(|l| l.wallet_id == wallet_id && l.tokens_left.signum() > 0).cloned().collect();
        v.sort_by_key(|l| (l.expires_at.is_none(), l.expires_at, l.id));
        v
    }
}

#[derive(Default)]
struct FakeBilling {
    b: Mutex<Books>,
}

#[async_trait]
impl BillingStore for FakeBilling {
    async fn config_by_app_client(&self, app_id: u64, client_id: u64) -> AuthResult<Option<BillingConfig>> {
        let b = self.b.lock().unwrap();
        Ok(b.configs.iter().find(|c| c.app_id == app_id && c.client_id == client_id && c.status != "DELETED").cloned())
    }
    async fn config_by_id(&self, id: u64) -> AuthResult<Option<BillingConfig>> {
        Ok(self.b.lock().unwrap().configs.iter().find(|c| c.id == id).cloned())
    }
    async fn config_by_codes(&self, app_code: &str, client_code: &str) -> AuthResult<Option<BillingConfig>> {
        let b = self.b.lock().unwrap();
        let ids = match (app_code, client_code) {
            ("crm", "SYSTEM") => Some((2, 1)),
            ("appbuilder", "SYSTEM") => Some((1, 1)),
            _ => None,
        };
        Ok(ids.and_then(|(a, c)| b.configs.iter().find(|x| x.app_id == a && x.client_id == c && x.status == "ACTIVE").cloned()))
    }
    async fn active_configs(&self) -> AuthResult<Vec<BillingConfig>> {
        Ok(self.b.lock().unwrap().configs.iter().filter(|c| c.status == "ACTIVE").cloned().collect())
    }
    async fn meters_of_config(&self, config_id: u64) -> AuthResult<Vec<Meter>> {
        let mut v: Vec<Meter> =
            self.b.lock().unwrap().meters.iter().filter(|m| m.config_id == config_id && m.status != "DELETED").cloned().collect();
        v.sort_by_key(|m| (m.display_order, m.id));
        Ok(v)
    }
    async fn meter_by_id(&self, id: u64) -> AuthResult<Option<Meter>> {
        Ok(self.b.lock().unwrap().meters.iter().find(|m| m.id == id).cloned())
    }
    async fn charge_instructions(&self, source: &str) -> AuthResult<Vec<Instruction>> {
        let b = self.b.lock().unwrap();
        Ok(b.instructions.iter().filter(|(s, _)| s == source).map(|(_, i)| i.clone()).collect())
    }
    async fn plan_by_id(&self, id: u64) -> AuthResult<Option<Plan>> {
        Ok(self.b.lock().unwrap().plans.iter().find(|p| p.id == id).cloned())
    }
    async fn plans_of_config(&self, config_id: u64) -> AuthResult<Vec<Plan>> {
        Ok(self.b.lock().unwrap().plans.iter().filter(|p| p.config_id == config_id && p.status != "DELETED").cloned().collect())
    }
    async fn wallet_plan(&self, wallet_id: u64) -> AuthResult<Option<WalletPlan>> {
        let b = self.b.lock().unwrap();
        Ok(b.wallet_plans.iter().filter(|w| w.wallet_id == wallet_id && w.status == "ACTIVE").max_by_key(|w| w.id).cloned())
    }
    async fn wallet_plans_due(&self, day: NaiveDate) -> AuthResult<Vec<WalletPlan>> {
        Ok(self.b.lock().unwrap().wallet_plans.iter().filter(|w| w.status == "ACTIVE" && w.period_end <= day).cloned().collect())
    }
    async fn start_wallet_plan(&self, wallet_id: u64, plan_id: u64, start: NaiveDate, end: NaiveDate) -> AuthResult<u64> {
        let mut b = self.b.lock().unwrap();
        for w in b.wallet_plans.iter_mut().filter(|w| w.wallet_id == wallet_id && w.status == "ACTIVE") {
            w.status = "ENDED".into();
        }
        let id = b.id();
        b.wallet_plans.push(WalletPlan { id, wallet_id, plan_id, period_start: start, period_end: end, status: "ACTIVE".into(), auto_renew: true, next_plan_id: None });
        Ok(id)
    }
    async fn set_wallet_plan(&self, wp: &WalletPlan) -> AuthResult<u64> {
        let mut b = self.b.lock().unwrap();
        let Some(x) = b.wallet_plans.iter_mut().find(|w| w.id == wp.id) else { return Ok(0) };
        *x = wp.clone();
        Ok(1)
    }
    async fn wallet(&self, client_id: u64, app_id: u64) -> AuthResult<Option<Wallet>> {
        Ok(self.b.lock().unwrap().wallets.iter().find(|w| w.client_id == client_id && w.app_id == app_id).cloned())
    }
    async fn wallet_by_id(&self, id: u64) -> AuthResult<Option<Wallet>> {
        Ok(self.b.lock().unwrap().wallets.iter().find(|w| w.id == id).cloned())
    }
    async fn create_wallet(&self, client_id: u64, app_id: u64) -> AuthResult<Option<(Wallet, bool)>> {
        let mut b = self.b.lock().unwrap();
        if let Some(w) = b.wallets.iter().find(|w| w.client_id == client_id && w.app_id == app_id) {
            return Ok(Some((w.clone(), false)));
        }
        let id = 900 + b.wallets.len() as u64;
        let w = Wallet { id, client_id, app_id, balance: Dec::ZERO, status: "ACTIVE".into(), alert_threshold: None, low_balance_notified: Some(0) };
        b.wallets.push(w.clone());
        Ok(Some((w, true)))
    }
    async fn debit(&self, t: &Txn) -> AuthResult<bool> {
        let mut b = self.b.lock().unwrap();
        if b.used(t) {
            return Ok(false);
        }
        b.push_txn(t);
        b.debits.push((t.wallet_id, t.tokens));
        if let Some(w) = b.wallet_mut(t.wallet_id) {
            w.balance = w.balance.sub(t.tokens);
        }
        let lots = b.open_lots(t.wallet_id);
        for (id, left) in sql::draw(&lots, t.tokens) {
            if let Some(l) = b.lots.iter_mut().find(|l| l.id == id) {
                l.tokens_left = left;
            }
        }
        Ok(true)
    }
    async fn credit(&self, t: &Txn, lot: &NewLot) -> AuthResult<bool> {
        let mut b = self.b.lock().unwrap();
        if b.used(t) {
            return Ok(false);
        }
        let before = b.wallets.iter().find(|w| w.id == t.wallet_id).map(|w| w.balance).unwrap_or(Dec::ZERO);
        b.push_txn(t);
        if let Some(w) = b.wallet_mut(t.wallet_id) {
            w.balance = w.balance.add(t.tokens);
        }
        let kept = t.tokens.sub(Dec::ZERO.sub(before).max(Dec::ZERO));
        if kept.signum() > 0 {
            let (id, now) = (b.id(), b.now);
            b.lots.push(Lot { id, wallet_id: t.wallet_id, source: lot.source.into(), tokens_added: kept, tokens_left: kept, added_at: now, expires_at: lot.expires_at });
        }
        Ok(true)
    }
    async fn record_txn(&self, t: &Txn) -> AuthResult<bool> {
        let mut b = self.b.lock().unwrap();
        if b.used(t) {
            return Ok(false);
        }
        b.push_txn(t);
        Ok(true)
    }
    async fn expired_lots(&self, now: NaiveDateTime) -> AuthResult<Vec<Lot>> {
        let b = self.b.lock().unwrap();
        Ok(b.lots.iter().filter(|l| l.tokens_left.signum() > 0 && l.expires_at.is_some_and(|e| e <= now)).cloned().collect())
    }
    async fn lots_expiring(&self, from: NaiveDateTime, to: NaiveDateTime) -> AuthResult<Vec<Lot>> {
        let b = self.b.lock().unwrap();
        let mut v: Vec<Lot> = b.lots.iter().filter(|l| l.tokens_left.signum() > 0 && l.expires_at.is_some_and(|e| e > from && e <= to)).cloned().collect();
        v.sort_by_key(|l| (l.wallet_id, l.expires_at));
        Ok(v)
    }
    async fn open_lots(&self, wallet_id: u64) -> AuthResult<Vec<Lot>> {
        Ok(self.b.lock().unwrap().open_lots(wallet_id))
    }
    async fn expire_lot(&self, lot: &Lot, t: &Txn) -> AuthResult<bool> {
        let mut b = self.b.lock().unwrap();
        if b.used(t) {
            return Ok(false);
        }
        b.push_txn(t);
        if let Some(w) = b.wallet_mut(lot.wallet_id) {
            w.balance = w.balance.sub(t.tokens);
        }
        if let Some(l) = b.lots.iter_mut().find(|l| l.id == lot.id) {
            l.tokens_left = Dec::ZERO;
        }
        Ok(true)
    }
    async fn set_status(&self, wallet_id: u64, status: &str) -> AuthResult<u64> {
        let mut b = self.b.lock().unwrap();
        b.statuses.push((wallet_id, status.to_string()));
        Ok(b.wallet_mut(wallet_id).map(|w| w.status = status.into()).is_some() as u64)
    }
    async fn set_low_balance_notified(&self, wallet_id: u64, notified: bool) -> AuthResult<u64> {
        let mut b = self.b.lock().unwrap();
        b.notified.push((wallet_id, notified));
        Ok(b.wallet_mut(wallet_id).map(|w| w.low_balance_notified = Some(i8::from(notified))).is_some() as u64)
    }
    async fn sum_quantity_between(&self, wallet_id: u64, action_key: &str, from: NaiveDate, to: NaiveDate) -> AuthResult<Dec> {
        let b = self.b.lock().unwrap();
        Ok(b.txns
            .iter()
            .filter(|t| t.wallet_id == wallet_id && t.kind == "DEBIT" && t.action_key.as_deref() == Some(action_key))
            .filter(|t| t.charge_date.is_some_and(|d| d >= from && d <= to))
            .fold(Dec::ZERO, |acc, t| acc.add(t.quantity.unwrap_or(Dec::ZERO))))
    }
    async fn sum_tokens_between(&self, wallet_id: u64, action_key: &str, from: NaiveDate, to: NaiveDate) -> AuthResult<Dec> {
        let b = self.b.lock().unwrap();
        Ok(b.txns
            .iter()
            .filter(|t| t.wallet_id == wallet_id && t.kind == "DEBIT" && t.action_key.as_deref() == Some(action_key))
            .filter(|t| t.charge_date.is_some_and(|d| d >= from && d <= to))
            .fold(Dec::ZERO, |acc, t| acc.add(t.tokens)))
    }
    async fn charged_windows(&self, wallet_id: u64, action_key: &str, date: NaiveDate) -> AuthResult<Vec<i16>> {
        let b = self.b.lock().unwrap();
        Ok(b.txns
            .iter()
            .filter(|t| t.wallet_id == wallet_id && t.action_key.as_deref() == Some(action_key) && t.charge_date == Some(date))
            .filter_map(|t| t.window_index)
            .collect())
    }
    async fn txn_by_key(&self, wallet_id: u64, key: &str) -> AuthResult<Option<(Txn, NaiveDateTime)>> {
        let b = self.b.lock().unwrap();
        let t = b.txns.iter().find(|t| t.wallet_id == wallet_id && t.idempotency_key == key).cloned();
        Ok(t.map(|t| {
            let at = b.txn_at.get(&(wallet_id, key.to_string())).copied().unwrap_or(b.now);
            (t, at)
        }))
    }
    async fn record_usage(&self, u: &Usage) -> AuthResult<bool> {
        let mut b = self.b.lock().unwrap();
        let key = u.unique_key();
        if let Some(r) = b.usage.iter_mut().find(|r| r.u.meter_id == u.meter_id && r.u.client_id == u.client_id && r.u.unique_key() == key) {
            if u.kind == "SNAPSHOT" {
                r.u.quantity = r.u.quantity.max(u.quantity);
                return Ok(true);
            }
            return Ok(false);
        }
        let now = b.now;
        b.usage.push(UsageRow { u: u.clone(), at: now, invoice: None });
        Ok(true)
    }
    async fn usage_by_reference(&self, meter_id: u64, client_id: u64, reference: &str) -> AuthResult<Option<(Usage, NaiveDateTime)>> {
        let b = self.b.lock().unwrap();
        let key = format!("ev:{reference}");
        Ok(b.usage.iter().find(|r| r.u.meter_id == meter_id && r.u.client_id == client_id && r.u.unique_key() == key).map(|r| (r.u.clone(), r.at)))
    }
    async fn period_usage(&self, meter_id: u64, client_id: u64, from: NaiveDate, to: NaiveDate) -> AuthResult<PeriodUsage> {
        let b = self.b.lock().unwrap();
        let mut p = PeriodUsage::default();
        for r in b.usage.iter().filter(|r| r.u.meter_id == meter_id && r.u.client_id == client_id && r.u.date >= from && r.u.date < to && r.invoice.is_none()) {
            match r.u.kind {
                "SNAPSHOT" => {
                    p.snapshot_sum = p.snapshot_sum.add(r.u.quantity);
                    p.snapshot_days += 1;
                }
                "EVENT" => p.events = p.events.add(r.u.quantity),
                _ => p.reversals = p.reversals.add(r.u.quantity),
            }
        }
        Ok(p)
    }
    async fn mark_invoiced(&self, client_id: u64, app_id: u64, from: NaiveDate, to: NaiveDate, invoice_id: u64) -> AuthResult<u64> {
        let mut b = self.b.lock().unwrap();
        let mut n = 0;
        for r in b.usage.iter_mut().filter(|r| r.u.client_id == client_id && r.u.app_id == app_id && r.u.date >= from && r.u.date < to && r.invoice.is_none()) {
            r.invoice = Some(invoice_id);
            n += 1;
        }
        Ok(n)
    }
    async fn clients_with_usage(&self, config_id: u64, before: NaiveDate) -> AuthResult<Vec<u64>> {
        let b = self.b.lock().unwrap();
        let meters: Vec<u64> = b.meters.iter().filter(|m| m.config_id == config_id).map(|m| m.id).collect();
        let mut v: Vec<u64> = b.usage.iter().filter(|r| meters.contains(&r.u.meter_id) && r.u.date < before && r.invoice.is_none()).map(|r| r.u.client_id).collect();
        v.sort();
        v.dedup();
        Ok(v)
    }
    async fn count_apps(&self, client_id: u64, app_type: &str, _active_only: bool) -> AuthResult<i64> {
        let b = self.b.lock().unwrap();
        if b.fail_counts {
            return Err(AuthError::internal("count failed"));
        }
        Ok(b.app_counts.iter().find(|(k, _)| k.0 == client_id && k.1 == app_type).map(|(_, n)| *n).unwrap_or(0))
    }
    async fn count_users_with_profile(&self, client_id: u64, app_id: u64, _profile_ids: &[u64]) -> AuthResult<i64> {
        let b = self.b.lock().unwrap();
        if b.fail_counts {
            return Err(AuthError::internal("count failed"));
        }
        Ok(b.user_counts.iter().find(|(k, _)| *k == (client_id, app_id)).map(|(_, n)| *n).unwrap_or(0))
    }
    async fn ai_rates(&self) -> AuthResult<Vec<AiRate>> {
        Ok(self.b.lock().unwrap().rates.clone())
    }
    async fn setting(&self, name: &str) -> AuthResult<Option<String>> {
        Ok(self.b.lock().unwrap().settings.get(name).cloned())
    }
    async fn has_overdue_invoice(&self, client_id: u64, app_id: u64) -> AuthResult<bool> {
        let b = self.b.lock().unwrap();
        Ok(b.invoices.iter().any(|i| i.u64("clientId") == Some(client_id) && i.u64("appId") == Some(app_id) && i.str("status") == Some("OVERDUE")))
    }
    async fn buyer_profile(&self, _client_id: u64, _app_id: u64) -> AuthResult<Option<Rec>> {
        Ok(None)
    }
    async fn insert_monthly_invoice(&self, invoice: &Rec, lines: &[Rec], fin_year: &str) -> AuthResult<Option<Rec>> {
        let mut b = self.b.lock().unwrap();
        let key = invoice.str("periodKey").unwrap_or("").to_string();
        if b.invoices.iter().any(|i| i.str("periodKey") == Some(key.as_str())) {
            return Ok(None);
        }
        let id = 7000 + b.invoices.len() as u64 + 1;
        let seller = invoice.u64("sellerClientId").unwrap_or(0);
        let n = b.invoices.iter().filter(|i| i.u64("sellerClientId") == Some(seller)).count() + 1;
        let saved = invoice.clone().with("id", Val::Id(id)).with("invoiceNumber", Val::Str(format!("INV/{fin_year}/{seller}/{n}")));
        b.invoices.push(saved.clone());
        for l in lines {
            b.lines.push(l.clone().with("invoiceId", Val::Id(id)));
        }
        Ok(Some(saved))
    }
    async fn invoices_past_due(&self, day: NaiveDate) -> AuthResult<Vec<Rec>> {
        let b = self.b.lock().unwrap();
        Ok(b.invoices
            .iter()
            .filter(|i| i.str("status") == Some("PENDING") && i.str("kind") == Some("MONTHLY") && i.date_of("dueDate").is_some_and(|d| d < day))
            .cloned()
            .collect())
    }
    async fn set_invoice_status(&self, invoice_id: u64, status: &str) -> AuthResult<u64> {
        let mut b = self.b.lock().unwrap();
        let Some(i) = b.invoices.iter_mut().find(|i| i.id() == Some(invoice_id)) else { return Ok(0) };
        i.set("status", Val::Str(status.into()));
        Ok(1)
    }
    async fn earliest_unbilled(&self, client_id: u64, app_id: u64) -> AuthResult<Option<NaiveDate>> {
        let b = self.b.lock().unwrap();
        Ok(b.usage.iter().filter(|r| r.u.client_id == client_id && r.u.app_id == app_id && r.invoice.is_none()).map(|r| r.u.date).min())
    }
    async fn gauge_month_units(&self, meter_id: u64, client_id: u64, from: NaiveDate, to: NaiveDate, free: Dec) -> AuthResult<Dec> {
        let b = self.b.lock().unwrap();
        let sum = b
            .usage
            .iter()
            .filter(|r| r.u.meter_id == meter_id && r.u.client_id == client_id && r.u.kind == "SNAPSHOT" && r.u.date >= from && r.u.date < to && r.invoice.is_none())
            .fold(Dec::ZERO, |a, r| a.add(r.u.quantity.sub(free).max(Dec::ZERO).div_down_scaled(i128::from(days_in_month(r.u.date)), 12)));
        Ok(sum.round_down(6))
    }
}

// ---------------------------------------------------------------------------------------------
// The world: SYSTEM (1) manages BUS (2), which manages CUST (3); crm (2) is BUS's app, billed by
// SYSTEM's config (1). The clock reads 2026-10-15 07:30 in the server's zone.

const C_CLIENT: u64 = 1;
const M_CLIENT: u64 = 2;
const APP: u64 = 2;
const CONFIG_ID: u64 = 1;

fn d(s: &str) -> Dec {
    Dec::parse(s).unwrap()
}

fn date(y: i32, m: u32, day: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(y, m, day).unwrap()
}

/// A number as the responses write it (`Dec::to_json` is a raw number only `jackson` prints).
fn num(v: &Value) -> String {
    security::jackson::pretty(v)
}

/// The equal value, whatever the scale.
#[track_caller]
fn same(a: Dec, b: &str) {
    assert!(a.cmp_value(&d(b)).is_eq(), "{a} is not {b}");
}

fn config() -> BillingConfig {
    BillingConfig { id: CONFIG_ID, client_id: C_CLIENT, app_id: APP, ..Default::default() }
}

fn wallet(balance: &str, status: &str, notified: i8) -> Wallet {
    Wallet { id: 7, client_id: M_CLIENT, app_id: APP, balance: d(balance), status: status.into(), alert_threshold: None, low_balance_notified: Some(notified) }
}

/// A TOKENS gauge of the config, priced per month.
fn gauge(id: u64, key: &str, source: &str, rate: &str, free: &str) -> Meter {
    let mut label = key.to_string();
    label[..1].make_ascii_uppercase();
    Meter { id, config_id: CONFIG_ID, key: key.into(), label, source: source.into(), rate: d(rate), free: d(free), ..Default::default() }
}

/// A TOKENS counter of the config, priced per use.
fn counter(id: u64, key: &str, rate: &str, free: &str) -> Meter {
    Meter { kind: "COUNTER".into(), source: "EVENT".into(), rate_unit: "EACH".into(), ..gauge(id, key, "EVENT", rate, free) }
}

fn plan(id: u64, code: &str, label: &str) -> Plan {
    Plan { id, config_id: CONFIG_ID, code: code.into(), label: label.into(), ..Default::default() }
}

fn on_plan(wallet_id: u64, plan_id: u64, start: NaiveDate, end: NaiveDate) -> WalletPlan {
    WalletPlan { id: 1, wallet_id, plan_id, period_start: start, period_end: end, status: "ACTIVE".into(), auto_renew: true, next_plan_id: None }
}

fn lot(id: u64, source: &str, left: &str, expires: Option<&str>) -> Lot {
    Lot {
        id,
        wallet_id: 7,
        source: source.into(),
        tokens_added: d(left),
        tokens_left: d(left),
        added_at: dt("2026-01-01 00:00:00"),
        expires_at: expires.map(dt),
    }
}

struct World {
    h: Harness,
    books: Arc<FakeBilling>,
    events: Arc<RecordingEvents>,
    internal: Internal,
}

impl World {
    fn b(&self) -> MutexGuard<'_, Books> {
        self.books.b.lock().unwrap()
    }

    fn event_names(&self) -> Vec<String> {
        self.events.events.lock().unwrap().iter().map(|e| e.event_name.clone()).collect()
    }

    fn event_data(&self, i: usize) -> HashMap<String, Value> {
        self.events.events.lock().unwrap()[i].data.iter().cloned().collect()
    }
}

fn world_on(db: Db) -> World {
    let h = harness();
    h.store.with(|d| {
        d.apps.push(app(4, 1, "sitezump"));
        d.apps[3].app_type = Some("SITE".into());
        d.apps[1].app_type = Some("APP".into());
        d.apps.push(app(5, 1, "site1"));
        d.apps[4].app_type = Some("SITE".into());
    });
    let books = Arc::new(FakeBilling::default());
    books.b.lock().unwrap().now = h.auth.clock.local();
    let events = Arc::new(RecordingEvents::default());
    let internal = Internal { auth: h.auth.clone(), db, billing: books.clone(), wallet_events: events.clone() };
    World { h, books, events, internal }
}

/// A pool that cannot connect: the app URL of a wallet event is then unresolvable, which the
/// event tolerates.
fn world() -> World {
    let pool = sqlx::mysql::MySqlPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(300))
        .connect_lazy("mysql://nobody:nothing@127.0.0.1:1/security")
        .unwrap();
    world_on(Db::new(pool))
}

fn system() -> ContextAuth {
    ContextAuth { client_type_code: Some("SYS".into()), ..Default::default() }
}

fn today() -> NaiveDate {
    date(2026, 10, 15)
}

/// June 2026: 30 days of 96 windows.
fn june() -> NaiveDate {
    date(2026, 6, 15)
}

fn req(quantity: &str, action_key: &str) -> ChargeRequest {
    ChargeRequest {
        config_client_id: Some(C_CLIENT),
        billed_client_id: Some(M_CLIENT),
        app_id: Some(APP),
        action_key: Some(action_key.into()),
        quantity: Some(d(quantity)),
        date: Some(june()),
        window_index: Some(7),
        meter_id: None,
    }
}

fn use_of(key: &str, quantity: Option<&str>, reference: &str) -> RecordRequest {
    let mut figures = Map::new();
    if let Some(q) = quantity {
        figures.insert("quantity".into(), serde_json::from_str::<Value>(q).unwrap());
    }
    RecordRequest {
        client_code: Some("BUS".into()),
        app_code: Some("crm".into()),
        meter_key: Some(key.into()),
        figures,
        reference: Some(reference.into()),
    }
}

// ---------------------------------------------------------------------------------------------
// Gauges paid from the wallet (`charge`)

#[tokio::test]
async fn a_tokens_gauge_debits_its_window_share_at_six_decimals() {
    let w = world();
    {
        let mut b = w.b();
        b.configs.push(config());
        b.meters.push(gauge(11, "users", "USERS", "2880", "3"));
        b.wallets.push(wallet("100", "ACTIVE", 0));
    }
    // 2 users above the 3 free, 2880 a month over 30 * 96 windows: 2.000000.
    let r = w.internal.charge(&system(), &req("5", action::USER)).await.unwrap();
    assert!(r.charged && !r.suspended);
    assert_eq!(r.balance_after.to_string(), "98.000000");
    {
        let b = w.b();
        assert_eq!(b.debits, vec![(7, d("2.000000"))]);
        let t = &b.txns[0];
        assert_eq!((t.kind, t.idempotency_key.as_str(), t.reason.as_str()), ("DEBIT", "crm.users:2026-06-15:7", "Users window 7"));
        assert_eq!((t.action_key.as_deref(), t.window_index, t.app_id, t.quantity.unwrap().to_string()), (Some("crm.users"), Some(7), Some(APP), "5".to_string()));
        assert_eq!(t.charge_date, Some(june()));
    }
    // A small rate accrues instead of rounding to nothing: 1 a month for one user is 0.000347 a window.
    {
        let mut b = w.b();
        b.meters[0].rate = d("1");
        b.meters[0].free = Dec::ZERO;
    }
    let r = w.internal.charge(&system(), &ChargeRequest { window_index: Some(8), ..req("1", action::USER) }).await.unwrap();
    assert!(r.charged);
    assert_eq!(r.balance_after.to_string(), "97.999653");
    assert_eq!(w.b().txns[1].tokens.to_string(), "0.000347");
}

#[tokio::test]
async fn nothing_is_charged_without_a_matching_priced_meter_or_with_missing_fields() {
    let w = world();
    {
        let mut b = w.b();
        b.configs.push(config());
        b.meters.push(gauge(11, "users", "USERS", "2880", "3"));
    }
    // At the free quantity.
    assert!(!w.internal.charge(&system(), &req("3", action::USER)).await.unwrap().charged);
    // No APPS meter; an unknown producer action; another configurator; no app.
    assert!(!w.internal.charge(&system(), &req("100", action::APP_RENT)).await.unwrap().charged);
    assert!(!w.internal.charge(&system(), &ChargeRequest { quantity: None, ..req("1", "core.nope") }).await.unwrap().charged);
    assert!(!w.internal.charge(&system(), &ChargeRequest { config_client_id: Some(99), ..req("100", action::USER) }).await.unwrap().charged);
    assert!(!w.internal.charge(&system(), &ChargeRequest { app_id: None, ..req("100", action::USER) }).await.unwrap().charged);
    // A request for one meter charges only that meter.
    assert!(!w.internal.charge(&system(), &ChargeRequest { meter_id: Some(12), ..req("100", action::USER) }).await.unwrap().charged);
    // Without its quantity, date or billed client the request fails, and the bulk charge skips it.
    for broken in [
        ChargeRequest { quantity: None, ..req("5", action::USER) },
        ChargeRequest { date: None, ..req("5", action::USER) },
        ChargeRequest { billed_client_id: None, ..req("5", action::USER) },
    ] {
        assert!(w.internal.charge(&system(), &broken).await.is_err());
    }
    w.internal.charge_bulk(&system(), &[ChargeRequest { quantity: None, ..req("5", action::USER) }]).await;
    // A paused config, a paused meter, a meter without a rate.
    w.b().configs[0].status = "INACTIVE".into();
    assert!(!w.internal.charge(&system(), &req("100", action::USER)).await.unwrap().charged);
    w.b().configs[0].status = "ACTIVE".into();
    w.b().meters[0].status = "INACTIVE".into();
    assert!(!w.internal.charge(&system(), &req("100", action::USER)).await.unwrap().charged);
    w.b().meters[0].status = "ACTIVE".into();
    w.b().meters[0].rate = Dec::ZERO;
    assert!(!w.internal.charge(&system(), &req("100", action::USER)).await.unwrap().charged);
    assert!(w.b().debits.is_empty());
}

#[tokio::test]
async fn a_repeated_window_does_not_debit_twice() {
    let w = world();
    {
        let mut b = w.b();
        b.configs.push(config());
        b.meters.push(gauge(11, "users", "USERS", "2880", "0"));
        b.wallets.push(wallet("100", "ACTIVE", 0));
    }
    assert!(w.internal.charge(&system(), &req("5", action::USER)).await.unwrap().charged);
    let again = w.internal.charge(&system(), &req("5", action::USER)).await.unwrap();
    assert!(!again.charged && !again.suspended);
    assert_eq!(again.balance_after.to_string(), "95.000000");
    assert_eq!(w.b().debits.len(), 1);
}

#[tokio::test]
async fn an_invoice_gauge_keeps_the_days_highest_count_and_debits_nothing() {
    let w = world();
    {
        let mut b = w.b();
        b.configs.push(config());
        b.meters.push(Meter { charge_mode: "INVOICE".into(), ..gauge(11, "users", "USERS", "300", "2") });
        b.wallets.push(wallet("100", "ACTIVE", 0));
    }
    for (q, window) in [("5", 1), ("7", 2), ("4", 3)] {
        let r = w.internal.charge(&system(), &ChargeRequest { window_index: Some(window), ..req(q, action::USER) }).await.unwrap();
        assert!(!r.charged);
    }
    let b = w.b();
    assert!(b.txns.is_empty() && b.debits.is_empty());
    assert_eq!(b.usage.len(), 1);
    let u = &b.usage[0].u;
    assert_eq!((u.kind, u.meter_id, u.client_id, u.app_id, u.date), ("SNAPSHOT", 11, M_CLIENT, APP, june()));
    same(u.quantity, "7");
    assert_eq!(b.wallets[0].balance.to_string(), "100");
}

/// A gauge of 30 a window (86400 a month over June's 2880 windows) and a wallet.
fn alerting(w: &World, balance: &str, status: &str, notified: i8, threshold: Option<&str>) {
    let mut b = w.b();
    b.configs.push(BillingConfig { low_balance_threshold: threshold.map(d), ..config() });
    b.meters.push(gauge(11, "users", "USERS", "86400", "0"));
    b.wallets.push(wallet(balance, status, notified));
}

#[tokio::test]
async fn low_balance_fires_once_on_the_downward_crossing() {
    let w = world();
    alerting(&w, "420", "ACTIVE", 0, Some("400"));
    let r = w.internal.charge(&system(), &req("1", action::USER)).await.unwrap();
    assert!(r.low_balance_crossed && !r.suspended);
    assert_eq!(r.balance_after.to_string(), "390.000000");
    let events = w.events.events.lock().unwrap().clone();
    assert_eq!(events.len(), 1);
    let e = &events[0];
    assert_eq!((e.event_name.as_str(), e.client_code.as_deref(), e.app_code.as_deref()), (WALLET_LOW_BALANCE, Some("BUS"), Some("crm")));
    let data = w.event_data(0);
    assert_eq!(data["balance"].as_f64(), Some(390.0));
    assert_eq!(data["clientCode"], "BUS");
    // walletEventStillRaisedWhenAppUrlCannotBeResolved: the URL is empty, not missing.
    assert_eq!(data["urlPrefix"], "");
    assert_eq!(w.b().notified, vec![(7, true)]);
}

#[tokio::test]
async fn no_alert_when_already_notified_or_already_below() {
    let w = world();
    alerting(&w, "420", "ACTIVE", 1, Some("400"));
    assert!(!w.internal.charge(&system(), &req("1", action::USER)).await.unwrap().low_balance_crossed);
    let w = world();
    alerting(&w, "390", "ACTIVE", 0, Some("400"));
    assert!(!w.internal.charge(&system(), &req("1", action::USER)).await.unwrap().low_balance_crossed);
    assert!(w.events.events.lock().unwrap().is_empty());
}

#[tokio::test]
async fn suspends_when_the_balance_crosses_zero() {
    let w = world();
    alerting(&w, "10", "ACTIVE", 0, None);
    let r = w.internal.charge(&system(), &req("1", action::USER)).await.unwrap();
    assert!(r.charged && r.suspended && !r.low_balance_crossed);
    assert_eq!(w.b().statuses, vec![(7, "SUSPENDED".to_string())]);
    assert_eq!(w.event_names(), vec![WALLET_SUSPENDED.to_string()]);
}

#[tokio::test]
async fn an_already_suspended_wallet_is_still_debited_without_a_new_event() {
    let w = world();
    alerting(&w, "-5", "SUSPENDED", 0, None);
    let r = w.internal.charge(&system(), &req("1", action::USER)).await.unwrap();
    assert!(r.charged && r.suspended);
    assert_eq!(r.balance_after.to_string(), "-35.000000");
    assert!(w.b().statuses.is_empty());
    assert!(w.events.events.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_wallet_event_that_cannot_be_sent_does_not_undo_the_charge() {
    let mut w = world();
    alerting(&w, "10", "ACTIVE", 0, None);
    w.internal.wallet_events = Arc::new(RecordingEvents { fail: true, ..Default::default() });
    assert!(w.internal.charge(&system(), &req("1", action::USER)).await.unwrap().suspended);
    // Nor does a client that no longer exists.
    let w2 = world();
    alerting(&w2, "10", "ACTIVE", 0, None);
    w2.h.store.with(|d| d.clients.retain(|c| c.id != Some(M_CLIENT)));
    assert!(w2.internal.charge(&system(), &req("1", action::USER)).await.unwrap().charged);
}

// ---------------------------------------------------------------------------------------------
// Plans and credit lots

#[tokio::test]
async fn a_new_wallet_starts_at_zero_on_the_default_plan_with_its_one_time_credits() {
    let w = world();
    {
        let mut b = w.b();
        b.configs.push(config());
        b.meters.push(gauge(11, "users", "USERS", "2880", "0"));
        b.plans.push(Plan { included_tokens: d("50"), included_recurring: false, ..plan(31, "pro", "Pro") });
        b.plans.push(Plan { is_default: true, included_tokens: d("50"), included_recurring: false, ..plan(30, "free", "Free") });
    }
    let r = w.internal.charge(&system(), &req("1", action::USER)).await.unwrap();
    // 50 plan credits, then the window's 1.
    assert!(r.charged);
    assert_eq!(r.balance_after.to_string(), "49.000000");
    let b = w.b();
    let wallet = &b.wallets[0];
    assert_eq!((wallet.id, wallet.client_id, wallet.app_id), (900, M_CLIENT, APP));
    let wp = &b.wallet_plans[0];
    assert_eq!((wp.plan_id, wp.period_start, wp.period_end, wp.status.as_str()), (30, today(), date(2026, 11, 15), "ACTIVE"));
    let credit = &b.txns[0];
    assert_eq!((credit.kind, credit.idempotency_key.as_str(), credit.reason.as_str()), ("ADJUST", "plan-once:900:30", "Free plan credits"));
    assert_eq!((credit.reference_type.as_deref(), credit.reference_id), (Some("WALLET_PLAN"), Some(wp.id)));
    same(credit.tokens, "50");
    // One-time credits never expire; the debit drew on them.
    assert_eq!(b.lots.len(), 1);
    assert_eq!((b.lots[0].source.as_str(), b.lots[0].expires_at), ("PLAN", None));
    same(b.lots[0].tokens_left, "49");
    assert_eq!(b.notified, vec![(900, false)]);
}

#[tokio::test]
async fn recurring_plan_credits_expire_with_the_period() {
    let w = world();
    {
        let mut b = w.b();
        b.configs.push(config());
        b.plans.push(Plan { is_default: true, included_tokens: d("20"), included_recurring: true, ..plan(30, "free", "Free") });
    }
    // serving-status creates the caller's wallet on the default plan.
    let v = w.internal.serving_status("crm", "SYSTEM", M_CLIENT).await.unwrap();
    assert_eq!((v["status"].as_str(), num(&v["balance"]), v["suspended"].as_bool()), (Some("ACTIVE"), "20".into(), Some(false)));
    let b = w.b();
    let wp = b.wallet_plans[0].id;
    assert_eq!(b.txns[0].idempotency_key, format!("plan:{wp}:2026-10-15"));
    assert_eq!(b.lots[0].expires_at, Some(dt("2026-11-15 00:00:00")));
}

#[tokio::test]
async fn a_debit_draws_the_soonest_expiring_lot_first() {
    let w = world();
    {
        let mut b = w.b();
        b.configs.push(config());
        b.meters.push(counter(21, "leads", "8", "0"));
        b.wallets.push(wallet("115", "ACTIVE", 0));
        b.lots.push(lot(1, "PURCHASE", "10", Some("2027-01-01 00:00:00")));
        b.lots.push(lot(2, "PLAN", "5", Some("2026-11-01 00:00:00")));
        b.lots.push(lot(3, "GRANT", "100", None));
    }
    let r = w.internal.record(&system(), &use_of("leads", None, "L1")).await.unwrap();
    assert!(r.recorded && !r.over_limit && !r.suspended);
    assert_eq!(r.charged.to_string(), "8.000000");
    let b = w.b();
    let left: Vec<String> = b.lots.iter().map(|l| l.tokens_left.to_string()).collect();
    assert_eq!(left, ["7.000000", "0", "100"]);
    assert_eq!(b.wallets[0].balance.to_string(), "107.000000");
    let t = &b.txns[0];
    assert_eq!((t.idempotency_key.as_str(), t.reason.as_str(), t.action_key.as_deref(), t.charge_date), ("ev:leads:L1", "Leads L1", Some("crm.leads"), Some(today())));
}

#[tokio::test]
async fn a_credit_pays_the_debt_first_and_reactivates_the_wallet() {
    let w = world();
    {
        let mut b = w.b();
        b.configs.push(config());
        b.wallets.push(wallet("-30", "SUSPENDED", 1));
    }
    let wallet = w.b().wallets[0].clone();
    let lot = NewLot { source: "PURCHASE", reference_type: Some("INVOICE".into()), reference_id: Some(5), expires_at: None };
    let r = w.internal.credit_wallet(&system(), &wallet, &config(), d("100"), "payment:p1", "Credit purchase", lot.clone()).await.unwrap();
    assert!(r.charged && !r.suspended);
    same(r.balance_after, "70");
    {
        let b = w.b();
        // Only what is left after the debt becomes a lot.
        assert_eq!(b.lots.len(), 1);
        same(b.lots[0].tokens_left, "70");
        assert_eq!((b.txns[0].kind, b.wallets[0].status.as_str(), b.wallets[0].low_balance_notified), ("CREDIT", "ACTIVE", Some(0)));
    }
    // The same key again credits nothing.
    let again = w.internal.credit_wallet(&system(), &wallet, &config(), d("100"), "payment:p1", "Credit purchase", lot).await.unwrap();
    assert!(!again.charged);
    same(again.balance_after, "70");
    // A bought credit lasts the config's validity; none when it has no validity.
    let now = dt("2026-10-15 07:30:00");
    assert_eq!(w.internal.purchase_expiry(&config(), now), Some(dt("2027-10-15 07:30:00")));
    assert_eq!(w.internal.purchase_expiry(&BillingConfig { purchased_credit_validity_months: None, ..config() }, now), None);
    assert_eq!(w.internal.bought_credit_lot(&config(), Some(9)).expires_at, Some(dt("2027-10-15 07:30:00")));
}

#[tokio::test]
async fn expired_lots_are_written_off_and_expiring_ones_warned() {
    let w = world();
    {
        let mut b = w.b();
        b.configs.push(config());
        b.wallets.push(wallet("35", "ACTIVE", 0));
        b.lots.push(lot(1, "PURCHASE", "10", Some("2026-10-01 00:00:00")));
        b.lots.push(lot(2, "PLAN", "20", Some("2026-12-01 00:00:00")));
        b.lots.push(lot(3, "GRANT", "5", Some("2026-10-22 00:00:00")));
    }
    let now = w.internal.auth.clock.local();
    w.internal.expire_lots(&system(), now).await.unwrap();
    {
        let b = w.b();
        let t = &b.txns[0];
        assert_eq!((t.kind, t.idempotency_key.as_str(), t.reference_type.as_deref(), t.reference_id), ("EXPIRE", "expire:1", Some("LOT"), Some(1)));
        assert_eq!((t.reason.as_str(), t.balance_after.to_string()), ("purchase credits expired", "25".to_string()));
        same(t.tokens, "10");
        same(b.wallets[0].balance, "25");
        same(b.lots[0].tokens_left, "0");
        same(b.lots[1].tokens_left, "20");
    }
    assert_eq!(w.event_names(), vec![WALLET_CREDITS_EXPIRED.to_string()]);
    let data = w.event_data(0);
    assert_eq!((data["expiredTokens"].as_str(), data["balance"].as_str()), (Some("10"), Some("25")));
    // A second run has nothing left to write off.
    w.internal.expire_lots(&system(), now).await.unwrap();
    assert_eq!(w.b().txns.len(), 1);
    // Seven days ahead: the grant expiring on the 22nd.
    w.internal.warn_expiring(&system(), now).await.unwrap();
    assert_eq!(w.event_names()[1], WALLET_CREDITS_EXPIRING);
    let data = w.event_data(1);
    assert_eq!((data["expiringTokens"].as_str(), data["expiresOn"].as_str()), (Some("5"), Some("2026-10-22")));
}

#[tokio::test]
async fn a_wallet_plan_renews_from_the_wallet_or_lapses_to_the_default() {
    let setup = |balance: &str, auto_renew: bool| {
        let w = world();
        {
            let mut b = w.b();
            b.configs.push(config());
            b.plans.push(Plan { is_default: true, included_tokens: d("50"), included_recurring: false, ..plan(30, "free", "Free") });
            b.plans.push(Plan { payment_mode: "WALLET".into(), price_tokens: d("100"), ..plan(31, "pro", "Pro") });
            b.wallets.push(wallet(balance, "ACTIVE", 0));
            b.wallet_plans.push(WalletPlan { auto_renew, ..on_plan(7, 31, date(2026, 9, 15), today()) });
        }
        w
    };
    // Paid: the price debited once, the next period started.
    let w = setup("150", true);
    w.internal.renew_plans(&system(), today()).await.unwrap();
    {
        let b = w.b();
        let t = &b.txns[0];
        assert_eq!((t.kind, t.idempotency_key.as_str(), t.action_key.as_deref()), ("DEBIT", "plan-fee:31:7:2026-10-15", Some("crm.plan")));
        assert_eq!((t.reference_type.as_deref(), t.reference_id, t.reason.as_str()), (Some("PLAN"), Some(31), "Pro plan from 2026-10-15"));
        same(b.wallets[0].balance, "50");
        let statuses: Vec<(u64, &str, NaiveDate)> = b.wallet_plans.iter().map(|p| (p.plan_id, p.status.as_str(), p.period_end)).collect();
        assert_eq!(statuses, vec![(31, "ENDED", today()), (31, "ACTIVE", date(2026, 11, 15))]);
    }
    // The same day again: nothing is due.
    w.internal.renew_plans(&system(), today()).await.unwrap();
    assert_eq!(w.b().txns.len(), 1);

    // Not enough credits: LAPSED, the event, and the default plan (its one-time credits were given
    // before, so none now).
    let w = setup("50", true);
    w.internal.renew_plans(&system(), today()).await.unwrap();
    {
        let b = w.b();
        let statuses: Vec<(u64, &str)> = b.wallet_plans.iter().map(|p| (p.plan_id, p.status.as_str())).collect();
        assert_eq!(statuses, vec![(31, "LAPSED"), (30, "ACTIVE")]);
        assert!(b.txns.is_empty());
        same(b.wallets[0].balance, "50");
    }
    assert_eq!(w.event_names(), vec![WALLET_PLAN_LAPSED.to_string()]);
    let data = w.event_data(0);
    assert_eq!((data["planLabel"].as_str(), data["price"].as_str()), (Some("Pro"), Some("100")));

    // Cancelled (no renewal): the default plan, nothing paid.
    let w = setup("500", false);
    w.internal.renew_plans(&system(), today()).await.unwrap();
    let b = w.b();
    let statuses: Vec<(u64, &str)> = b.wallet_plans.iter().map(|p| (p.plan_id, p.status.as_str())).collect();
    assert_eq!(statuses, vec![(31, "ENDED"), (30, "ACTIVE")]);
    assert!(b.debits.is_empty());
}

// ---------------------------------------------------------------------------------------------
// Counters (`record`, `reverse`) and the gates (`allowed`)

#[tokio::test]
async fn a_counter_charges_only_past_the_months_free_quantity() {
    let w = world();
    {
        let mut b = w.b();
        b.configs.push(config());
        b.meters.push(counter(21, "leads", "2", "3"));
        b.wallets.push(wallet("100", "ACTIVE", 0));
        // Last month's use does not count against this month's allowance.
        b.txns.push(Txn {
            wallet_id: 7,
            kind: "DEBIT",
            action_key: Some("crm.leads".into()),
            quantity: Some(d("100")),
            charge_date: Some(date(2026, 9, 20)),
            idempotency_key: "old".into(),
            ..Default::default()
        });
    }
    // 2 of the 3 free: kept with zero tokens so the allowance depletes.
    let r = w.internal.record(&system(), &use_of("leads", Some("2"), "A")).await.unwrap();
    assert!(r.recorded && !r.over_limit);
    same(r.charged, "0");
    // 2 more: 1 is past the line, at 2 each.
    let r = w.internal.record(&system(), &use_of("leads", Some("2"), "B")).await.unwrap();
    assert_eq!((r.recorded, r.charged.to_string()), (true, "2.000000".into()));
    let r = w.internal.record(&system(), &use_of("leads", Some("1"), "C")).await.unwrap();
    assert_eq!(r.charged.to_string(), "2.000000");
    // A retry with the same reference counts once.
    let r = w.internal.record(&system(), &use_of("leads", Some("2"), "B")).await.unwrap();
    assert!(!r.recorded);
    same(r.charged, "0");
    let b = w.b();
    assert_eq!(b.txns.len(), 4);
    let zero = &b.txns[1];
    assert_eq!((zero.kind, zero.idempotency_key.as_str(), zero.tokens.to_string()), ("DEBIT", "ev:leads:A", "0".to_string()));
    same(zero.balance_after, "100");
    same(b.wallets[0].balance, "96");
    let v = r.to_json();
    assert_eq!((v["recorded"].as_bool(), v["overLimit"].as_bool(), num(&v["charged"]), v["suspended"].as_bool()), (Some(false), Some(false), "0".into(), Some(false)));
}

#[tokio::test]
async fn record_needs_an_active_counter() {
    let w = world();
    // No config: unbilled, nothing kept.
    assert!(!w.internal.record(&system(), &use_of("leads", None, "A")).await.unwrap().recorded);
    {
        let mut b = w.b();
        b.configs.push(config());
        b.meters.push(gauge(11, "users", "USERS", "2880", "0"));
        b.meters.push(Meter { status: "INACTIVE".into(), ..counter(21, "leads", "2", "0") });
    }
    // A gauge is counted on a schedule.
    assert!(w.internal.record(&system(), &use_of("users", None, "A")).await.is_err());
    // A paused meter, an unknown one, a missing field.
    assert!(!w.internal.record(&system(), &use_of("leads", None, "A")).await.unwrap().recorded);
    assert!(!w.internal.record(&system(), &use_of("nope", None, "A")).await.unwrap().recorded);
    assert!(!w.internal.record(&system(), &RecordRequest { meter_key: None, ..use_of("leads", None, "A") }).await.unwrap().recorded);
    assert!(w.b().txns.is_empty());
}

#[tokio::test]
async fn a_hard_cap_refuses_the_use_and_charges_nothing() {
    let w = world();
    let caps = |free: &str| MeterOverride { free: Some(d(free)), rate: None, hard_cap: true };
    {
        let mut b = w.b();
        b.configs.push(config());
        b.meters.push(counter(21, "leads", "5", "100"));
        b.meters.push(gauge(11, "users", "USERS", "2880", "0"));
        b.meters.push(Meter { source_config: json!({"storageName": "cxProduct"}).as_object().unwrap().clone(), ..gauge(12, "products", "STORAGE_COUNT", "10", "0") });
        let overrides = HashMap::from([("leads".to_string(), caps("2")), ("users".to_string(), caps("3")), ("products".to_string(), caps("4"))]);
        b.plans.push(Plan { is_default: true, overrides, ..plan(30, "free", "Free") });
        b.wallets.push(wallet("100", "ACTIVE", 0));
        b.wallet_plans.push(on_plan(7, 30, date(2026, 10, 1), date(2026, 11, 1)));
        b.user_counts.push(((M_CLIENT, APP), 2));
    }
    let allowed = |key: &'static str, count: Option<&'static str>| {
        let i = &w.internal;
        async move { i.allowed("crm", "BUS", Some(key), None, count.map(d)).await.unwrap() }
    };
    assert_eq!(allowed("leads", None).await, json!({"allowed": true}));
    for r in ["A", "B"] {
        let used = w.internal.record(&system(), &use_of("leads", None, r)).await.unwrap();
        assert!(used.recorded && !used.over_limit);
        same(used.charged, "0");
    }
    let over = w.internal.record(&system(), &use_of("leads", None, "C")).await.unwrap();
    assert!(over.over_limit && !over.recorded);
    assert_eq!(over.to_json()["overLimit"], true);
    assert_eq!(allowed("leads", None).await, json!({"allowed": false, "reason": "The plan's limit is reached"}));
    // A gauge security counts itself: 2 users of 3, then 3.
    assert_eq!(allowed("users", None).await["allowed"], true);
    w.b().user_counts[0].1 = 3;
    assert_eq!(allowed("users", None).await["allowed"], false);
    // A gauge only the app can count: its count, or not checked without one.
    assert_eq!(allowed("products", Some("5")).await["allowed"], false);
    assert_eq!(allowed("products", Some("3")).await["allowed"], true);
    assert_eq!(allowed("products", None).await["allowed"], true);
    // A capped gauge is never charged per window.
    let r = w.internal.charge(&system(), &req("10", action::USER)).await.unwrap();
    assert!(!r.charged);
    let b = w.b();
    assert!(b.debits.is_empty());
    same(b.wallets[0].balance, "100");
}

#[tokio::test]
async fn the_plans_model_list_refuses_other_models() {
    let w = world();
    {
        let mut b = w.b();
        b.configs.push(config());
        b.plans.push(Plan { ai_models: vec!["deepseek".into()], ..plan(30, "free", "Free") });
        b.wallets.push(wallet("100", "ACTIVE", 0));
        b.wallet_plans.push(on_plan(7, 30, date(2026, 10, 1), date(2026, 11, 1)));
    }
    let v = w.internal.allowed("crm", "BUS", None, Some("claude-opus-5-5"), None).await.unwrap();
    assert_eq!(v, json!({"allowed": false, "reason": "The plan does not include this AI model"}));
    assert_eq!(w.internal.allowed("crm", "BUS", None, Some("DeepSeek-V4-Flash"), None).await.unwrap()["allowed"], true);
    assert!(w.internal.is_ai_allowed("crm", "BUS").await.unwrap());
}

/// Before its first use a client has no wallet; the gate judges by the default plan it will land
/// on (found on dev 2026-11-14: a new Free client was allowed a premium model once).
#[tokio::test]
async fn a_client_without_a_wallet_is_judged_by_the_default_plan() {
    let w = world();
    {
        let mut b = w.b();
        b.configs.push(config());
        b.plans.push(Plan { ai_models: vec!["deepseek".into()], is_default: true, ..plan(30, "free", "Free") });
    }
    let v = w.internal.allowed("crm", "BUS", None, Some("claude-opus-5-5"), None).await.unwrap();
    assert_eq!(v, json!({"allowed": false, "reason": "The plan does not include this AI model"}));
    assert_eq!(w.internal.allowed("crm", "BUS", None, Some("deepseek-chat"), None).await.unwrap()["allowed"], true);
    assert!(w.b().wallets.is_empty(), "the gate never creates a wallet");
}

#[tokio::test]
async fn ai_allowed_only_blocks_an_active_billed_suspended_wallet() {
    let w = world();
    assert!(w.internal.is_ai_allowed("crm", "BUS").await.unwrap(), "no config");
    assert!(w.internal.is_ai_allowed("nope", "BUS").await.unwrap());
    assert!(w.internal.is_ai_allowed("crm", "NOPE").await.unwrap());
    w.b().configs.push(BillingConfig { status: "INACTIVE".into(), ..config() });
    w.b().wallets.push(wallet("-1", "SUSPENDED", 0));
    assert!(w.internal.is_ai_allowed("crm", "BUS").await.unwrap(), "paused config");
    w.b().configs[0].status = "ACTIVE".into();
    assert!(!w.internal.is_ai_allowed("crm", "BUS").await.unwrap(), "suspended wallet, no AI meter");
    // A TOKENS AI meter stops; an invoiced one does not need the wallet.
    w.b().meters.push(Meter { rate_unit: "MARKUP".into(), ..Meter { kind: "COUNTER".into(), ..gauge(41, "ai.tokens", "AI_TOKENS", "2", "0") } });
    assert!(!w.internal.is_ai_allowed("crm", "BUS").await.unwrap());
    w.b().meters[0].charge_mode = "INVOICE".into();
    assert!(w.internal.is_ai_allowed("crm", "BUS").await.unwrap());
    w.b().wallets.clear();
    assert!(w.internal.is_ai_allowed("crm", "BUS").await.unwrap(), "no wallet");
}

#[tokio::test]
async fn a_tokens_use_is_refunded_within_its_window_once() {
    let w = world();
    {
        let mut b = w.b();
        b.configs.push(config());
        b.meters.push(Meter { refund_policy: "WITHIN_DAYS".into(), refund_days: Some(7), ..counter(21, "leads", "8", "0") });
        b.meters.push(counter(22, "calls", "8", "0"));
        b.wallets.push(wallet("100", "ACTIVE", 0));
    }
    w.internal.record(&system(), &use_of("leads", None, "L1")).await.unwrap();
    w.internal.record(&system(), &use_of("calls", None, "C1")).await.unwrap();
    let v = w.internal.reverse(&system(), &use_of("leads", None, "L1")).await.unwrap();
    assert_eq!((v["reversed"].as_bool(), num(&v["refunded"])), (Some(true), "8.000000".into()));
    {
        let b = w.b();
        let t = b.txns.last().unwrap();
        assert_eq!((t.kind, t.idempotency_key.as_str(), t.reason.as_str(), t.reference_type.as_deref()), ("ADJUST", "rev:leads:L1", "Refund Leads L1", Some("REFUND")));
        same(b.wallets[0].balance, "92");
    }
    assert_eq!(w.internal.reverse(&system(), &use_of("leads", None, "L1")).await.unwrap()["reversed"], false);
    let no = |v: Value| v["reason"].as_str().unwrap_or("").to_string();
    assert_eq!(no(w.internal.reverse(&system(), &use_of("calls", None, "C1")).await.unwrap()), "the meter does not refund");
    assert_eq!(no(w.internal.reverse(&system(), &use_of("leads", None, "L9")).await.unwrap()), "no such use");
    assert_eq!(no(w.internal.reverse(&system(), &RecordRequest { reference: None, ..use_of("leads", None, "L1") }).await.unwrap()), "appCode, clientCode, meterKey and reference are needed");
    // A use older than the window stays charged.
    w.internal.record(&system(), &use_of("leads", None, "L2")).await.unwrap();
    w.b().txn_at.insert((7, "ev:leads:L2".into()), dt("2026-10-01 00:00:00"));
    assert_eq!(no(w.internal.reverse(&system(), &use_of("leads", None, "L2")).await.unwrap()), "past the refund window");
}

#[tokio::test]
async fn an_invoice_counter_keeps_events_and_reversals_for_the_invoice() {
    let w = world();
    {
        let mut b = w.b();
        b.configs.push(config());
        b.meters.push(Meter { charge_mode: "INVOICE".into(), refund_policy: "WITHIN_DAYS".into(), refund_days: Some(30), ..counter(21, "leads", "2", "0") });
    }
    for (r, q) in [("L1", "3"), ("L2", "4")] {
        assert!(w.internal.record(&system(), &use_of("leads", Some(q), r)).await.unwrap().recorded);
    }
    assert!(!w.internal.record(&system(), &use_of("leads", Some("3"), "L1")).await.unwrap().recorded, "retried");
    assert_eq!(w.internal.reverse(&system(), &use_of("leads", None, "L1")).await.unwrap()["reversed"], true);
    assert_eq!(w.internal.reverse(&system(), &use_of("leads", None, "L1")).await.unwrap()["reversed"], false);
    let b = w.b();
    let kinds: Vec<(&str, String)> = b.usage.iter().map(|r| (r.u.kind, r.u.quantity.to_string())).collect();
    assert_eq!(kinds.iter().map(|k| k.0).collect::<Vec<_>>(), ["EVENT", "EVENT", "REVERSAL"]);
    same(b.usage[2].u.quantity, "3");
    assert!(b.txns.is_empty(), "nothing touches the wallet");
    let wallet = b.wallets[0].clone();
    let meter = b.meters[0].clone();
    drop(b);
    // Net use this month: 3 + 4 - 3.
    same(w.internal.month_usage(&meter, &wallet, M_CLIENT, "crm", today()).await.unwrap(), "4");
}

// ---------------------------------------------------------------------------------------------
// AI (`charge_ai`)

fn ai_call(model: &str, request: &str) -> AiChargeRequest {
    AiChargeRequest {
        client_code: Some("BUS".into()),
        app_code: Some("crm".into()),
        model: Some(model.into()),
        input_tokens: Some(1_000_000),
        output_tokens: Some(100_000),
        cache_read_tokens: Some(10_000_000),
        cache_write_tokens: None,
        weighted_tokens: None,
        request_id: Some(request.into()),
        session_id: None,
    }
}

fn usd(pattern: &str, i: &str, o: &str, r: &str, w: &str) -> AiRate {
    AiRate { pattern: pattern.into(), input: d(i), output: d(o), cache_read: d(r), cache_write: d(w), currency: "USD".into() }
}

fn ai_world(free: &str, fx: Option<&str>) -> World {
    let w = world();
    {
        let mut b = w.b();
        b.configs.push(config());
        b.meters.push(Meter { kind: "COUNTER".into(), rate_unit: "MARKUP".into(), ..gauge(41, "ai.tokens", "AI_TOKENS", "2", free) });
        b.wallets.push(wallet("100000", "ACTIVE", 0));
        b.rates = vec![usd("opus", "15", "75", "1.5", "18.75"), usd("deepseek", "0.3", "1.2", "0.03", "0.3")];
        if let Some(fx) = fx {
            b.settings.insert(AI_FX_RATE.into(), fx.into());
        }
    }
    w
}

#[tokio::test]
async fn ai_is_priced_per_model_in_the_configs_currency_with_the_markup() {
    let w = ai_world("0", Some("90"));
    // Opus: 15 + 7.5 + 15 = 37.5 USD, at 90 INR, times 2: 6750.
    let opus = w.internal.charge_ai(&system(), &ai_call("claude-opus-5-5", "r1")).await.unwrap();
    assert!(opus.charged);
    assert_eq!(opus.balance_after.to_string(), "93250.000000");
    // DeepSeek: 0.3 + 0.12 + 0.3 = 0.72 USD: 129.6.
    let ds = w.internal.charge_ai(&system(), &ai_call("deepseek-v4-flash", "r2")).await.unwrap();
    assert!(ds.charged);
    // An unknown model is charged at the dearest rate (Opus's).
    w.internal.charge_ai(&system(), &ai_call("gpt-9", "r3")).await.unwrap();
    // The same request again is not charged twice.
    assert!(!w.internal.charge_ai(&system(), &ai_call("gpt-9", "r3")).await.unwrap().charged);
    let b = w.b();
    let tokens: Vec<String> = b.txns.iter().map(|t| t.tokens.to_string()).collect();
    assert_eq!(tokens, ["6750.000000", "129.600000", "6750.000000"]);
    // The charges stand in the ratio of the models' prices: 6750 / 129.6 = 37.5 / 0.72.
    assert!(b.txns[0].tokens.mul(d("0.72")).cmp_value(&b.txns[1].tokens.mul(d("37.5"))).is_eq());
    let t = &b.txns[0];
    assert_eq!((t.idempotency_key.as_str(), t.reason.as_str(), t.action_key.as_deref()), ("ai:r1", "AI usage claude-opus-5-5", Some("crm.ai.tokens")));
    let figures: Value = serde_json::from_str(t.description.as_deref().unwrap()).unwrap();
    assert_eq!((figures["model"].as_str(), figures["inputTokens"].as_i64(), figures["cacheReadTokens"].as_i64()), (Some("claude-opus-5-5"), Some(1_000_000), Some(10_000_000)));
    same(t.quantity.unwrap(), "6750");
}

/// The suspected bug: the call's figures (the ledger row's DESCRIPTION, an invoiced meter's usage
/// FIGURES) are written with serde's `to_string`, but `cost` is put as `Dec::to_json`, a jackson
/// raw-number marker string, so the stored JSON holds `"cost": "\u0001num:3375.000000"`.
#[tokio::test]
async fn ai_figures_keep_the_cost_as_a_number() {
    let w = ai_world("0", Some("90"));
    w.internal.charge_ai(&system(), &ai_call("claude-opus-5-5", "r1")).await.unwrap();
    let description = w.b().txns[0].description.clone().unwrap();
    let figures: Value = serde_json::from_str(&description).unwrap();
    assert_eq!(figures["cost"].as_f64(), Some(3375.0), "{description:?}");
}

#[tokio::test]
async fn ai_free_credits_go_first_and_old_bodies_and_missing_fx_still_price() {
    // 200 free a month: the first 129.6 is inside it, the second call pays the 59.2 past it.
    let w = ai_world("200", Some("90"));
    let first = w.internal.charge_ai(&system(), &ai_call("deepseek", "r1")).await.unwrap();
    assert!(!first.charged);
    same(first.balance_after, "100000");
    let second = w.internal.charge_ai(&system(), &ai_call("deepseek", "r2")).await.unwrap();
    assert!(second.charged);
    {
        let b = w.b();
        assert_eq!((b.txns[0].tokens.to_string(), b.txns[0].idempotency_key.as_str()), ("0".into(), "ai:r1"));
        assert_eq!(b.txns[1].tokens.to_string(), "59.200000");
    }
    // The old body: weighted tokens at the output price, 1.2 USD * 90 * 2.
    let w = ai_world("0", Some("90"));
    let old = AiChargeRequest { input_tokens: None, output_tokens: None, cache_read_tokens: None, weighted_tokens: Some(d("1000000")), ..ai_call("deepseek", "o1") };
    w.internal.charge_ai(&system(), &old).await.unwrap();
    assert_eq!(w.b().txns[0].tokens.to_string(), "216.000000");
    // No FX rate: taken 1:1.
    let w = ai_world("0", None);
    w.internal.charge_ai(&system(), &ai_call("opus", "x")).await.unwrap();
    assert_eq!(w.b().txns[0].tokens.to_string(), "75.000000");
    // An invoiced AI meter keeps the priced call for the invoice.
    let w = ai_world("0", Some("90"));
    w.b().meters[0].charge_mode = "INVOICE".into();
    let r = w.internal.charge_ai(&system(), &ai_call("deepseek", "i1")).await.unwrap();
    assert!(!r.charged);
    let b = w.b();
    assert!(b.txns.is_empty());
    let u = &b.usage[0].u;
    assert_eq!((u.kind, u.reference.as_deref(), u.quantity.to_string()), ("EVENT", Some("ai:i1"), "129.600000".to_string()));
    assert_eq!(u.figures.as_ref().unwrap()["model"], "deepseek");
}

#[tokio::test]
async fn charge_ai_charges_nothing_without_an_active_meter_and_rates() {
    let w = world();
    let call = || ai_call("deepseek", "a");
    // No config at all (and an unknown app or client, or none).
    assert!(!w.internal.charge_ai(&system(), &call()).await.unwrap().charged);
    assert!(!w.internal.charge_ai(&system(), &AiChargeRequest { app_code: Some("nope".into()), ..call() }).await.unwrap().charged);
    assert!(!w.internal.charge_ai(&system(), &AiChargeRequest { client_code: Some("NOPE".into()), ..call() }).await.unwrap().charged);
    assert!(!w.internal.charge_ai(&system(), &AiChargeRequest { client_code: None, app_code: None, ..call() }).await.unwrap().charged);
    // A paused config; an active one with no AI meter; a meter but no model rates.
    w.b().configs.push(BillingConfig { status: "INACTIVE".into(), ..config() });
    assert!(!w.internal.charge_ai(&system(), &call()).await.unwrap().charged);
    w.b().configs[0].status = "ACTIVE".into();
    assert!(!w.internal.charge_ai(&system(), &call()).await.unwrap().charged);
    w.b().meters.push(Meter { kind: "COUNTER".into(), rate_unit: "MARKUP".into(), ..gauge(41, "ai.tokens", "AI_TOKENS", "2", "0") });
    assert!(!w.internal.charge_ai(&system(), &call()).await.unwrap().charged);
    assert!(w.b().txns.is_empty() && w.b().wallets.is_empty());
}

// ---------------------------------------------------------------------------------------------
// Hosting and the serving status

#[tokio::test]
async fn hosting_serves_the_suspend_target_for_a_suspended_builder_wallet() {
    let w = world();
    let pass = |app: &str, client: &str| json!({"suspended": false, "serveAppCode": app, "serveClientCode": client});
    assert_eq!(w.internal.hosting("crm", "SYSTEM").await.unwrap(), pass("crm", "SYSTEM"));
    assert_eq!(w.internal.hosting("", "BUS").await.unwrap(), json!({"suspended": false, "serveClientCode": "BUS"}));
    assert_eq!(w.internal.hosting("crm", "NOPE").await.unwrap(), pass("crm", "NOPE"));
    assert_eq!(w.internal.hosting("nope", "BUS").await.unwrap(), pass("nope", "BUS"));
    // No builder wallet.
    assert_eq!(w.internal.hosting("crm", "BUS").await.unwrap(), pass("crm", "BUS"));
    // An active appbuilder wallet.
    w.b().wallets.push(Wallet { app_id: 1, ..wallet("5", "ACTIVE", 0) });
    assert_eq!(w.internal.hosting("crm", "BUS").await.unwrap(), pass("crm", "BUS"));
    // Suspended, but no config (and then one without a suspend target).
    w.b().wallets[0].status = "SUSPENDED".into();
    assert_eq!(w.internal.hosting("crm", "BUS").await.unwrap(), pass("crm", "BUS"));
    w.b().configs.push(BillingConfig { app_id: 1, ..config() });
    assert_eq!(w.internal.hosting("crm", "BUS").await.unwrap(), pass("crm", "BUS"));
    w.b().configs[0].suspend_app_code = Some("suspended".into());
    w.b().configs[0].suspend_client_code = Some("SYSTEM".into());
    assert_eq!(w.internal.hosting("crm", "BUS").await.unwrap(), json!({"suspended": true, "serveAppCode": "suspended", "serveClientCode": "SYSTEM"}));
    // A site without a sitezump wallet falls back to the appbuilder one.
    assert_eq!(w.internal.hosting("site1", "BUS").await.unwrap()["suspended"], true);
    // With an active sitezump wallet, that one decides.
    w.b().wallets.push(Wallet { id: 8, app_id: 4, ..wallet("5", "ACTIVE", 0) });
    assert_eq!(w.internal.hosting("site1", "BUS").await.unwrap(), pass("site1", "BUS"));
}

#[tokio::test]
async fn block_app_serves_the_suspend_target_on_an_overdue_invoice_or_a_suspended_wallet() {
    let w = world();
    let pass = json!({"suspended": false, "serveAppCode": "crm", "serveClientCode": "BUS"});
    let blocked = json!({"suspended": true, "serveAppCode": "suspended", "serveClientCode": "SYSTEM"});
    {
        let mut b = w.b();
        b.configs.push(BillingConfig {
            suspend_mode: "BLOCK_APP".into(),
            suspend_app_code: Some("suspended".into()),
            suspend_client_code: Some("SYSTEM".into()),
            ..config()
        });
        b.wallets.push(wallet("5", "ACTIVE", 0));
    }
    assert_eq!(w.internal.hosting("crm", "BUS").await.unwrap(), pass);
    w.b().invoices.push(monthly_invoice(1, "OVERDUE", date(2026, 10, 1)));
    assert_eq!(w.internal.hosting("crm", "BUS").await.unwrap(), blocked);
    // Another client's overdue invoice is not BUS's.
    w.b().invoices[0].set("clientId", Val::Id(3));
    assert_eq!(w.internal.hosting("crm", "BUS").await.unwrap(), pass);
    // A suspended wallet blocks too.
    w.b().wallets[0].status = "SUSPENDED".into();
    assert_eq!(w.internal.hosting("crm", "BUS").await.unwrap(), blocked);
    // AI_AND_BANNER never blocks the app.
    w.b().configs[0].suspend_mode = "AI_AND_BANNER".into();
    assert_eq!(w.internal.hosting("crm", "BUS").await.unwrap(), pass);
}

#[tokio::test]
async fn serving_status_is_active_without_a_config_and_the_wallet_otherwise() {
    let w = world();
    w.b().configs.push(config());
    w.b().wallets.push(wallet("-2.5000", "SUSPENDED", 0));
    let v = w.internal.serving_status("crm", "SYSTEM", M_CLIENT).await.unwrap();
    assert_eq!(security::jackson::pretty(&v), "{\n  \"status\" : \"SUSPENDED\",\n  \"balance\" : -2.5000,\n  \"suspended\" : true\n}");
    // Another caller gets a wallet of its own, at zero (no default plan).
    let v = w.internal.serving_status("crm", "SYSTEM", 3).await.unwrap();
    assert_eq!((v["status"].as_str(), num(&v["balance"])), (Some("ACTIVE"), "0".into()));

    let w = world();
    let active = json!({"status": "ACTIVE", "suspended": false});
    assert_eq!(w.internal.serving_status("crm", "SYSTEM", M_CLIENT).await.unwrap(), active);
    // The missing config is cached too (cacheEmptyValueOrGet): a config added later is not seen
    // until an eviction.
    w.b().configs.push(config());
    assert_eq!(w.internal.serving_status("crm", "SYSTEM", M_CLIENT).await.unwrap(), active);
}

// ---------------------------------------------------------------------------------------------
// Security's metering run

fn instruction(meter_id: u64) -> Instruction {
    Instruction {
        config_client_code: "SYSTEM".into(),
        config_client_id: C_CLIENT,
        app_code: "crm".into(),
        app_id: APP,
        billed_client_code: "BUS".into(),
        billed_client_id: M_CLIENT,
        meter_id: Some(meter_id),
        source_config: Some(Map::new()),
    }
}

#[tokio::test]
async fn a_window_charges_each_meter_with_its_count() {
    let w = world();
    {
        let mut b = w.b();
        b.configs.push(config());
        b.meters.push(gauge(11, "apps", "APPS", "2880", "0"));
        b.meters.push(gauge(12, "users", "USERS", "2880", "0"));
        b.meters.push(gauge(13, "sites", "SITES", "2880", "0"));
        b.instructions.push(("APPS".into(), instruction(11)));
        b.instructions.push(("USERS".into(), instruction(12)));
        b.instructions.push(("SITES".into(), instruction(13)));
        b.app_counts.push(((M_CLIENT, "APP".into()), 5));
        b.wallets.push(wallet("100", "ACTIVE", 0));
    }
    w.internal.meter_window(&system(), june(), 7).await.unwrap();
    let b = w.b();
    // Apps: 5 charged; users and sites count 0 and are skipped.
    assert_eq!(b.txns.len(), 1);
    let t = &b.txns[0];
    assert_eq!((t.action_key.as_deref(), t.window_index, t.quantity.unwrap().to_string()), (Some("crm.apps"), Some(7), "5".into()));
    assert_eq!(t.charge_date, Some(june()));
    same(t.tokens, "5");
}

#[tokio::test]
async fn reconcile_back_charges_only_the_missing_windows() {
    let w = world();
    {
        let mut b = w.b();
        b.configs.push(config());
        b.meters.push(gauge(11, "apps", "APPS", "2880", "0"));
        b.meters.push(Meter { charge_mode: "INVOICE".into(), ..gauge(12, "sites", "SITES", "300", "0") });
        b.instructions.push(("APPS".into(), instruction(11)));
        b.instructions.push(("SITES".into(), instruction(12)));
        b.app_counts.push(((M_CLIENT, "APP".into()), 5));
        b.app_counts.push(((M_CLIENT, "SITE".into()), 2));
        b.wallets.push(wallet("1000", "ACTIVE", 0));
        for i in 0..95 {
            b.txns.push(Txn {
                wallet_id: 7,
                kind: "DEBIT",
                action_key: Some("crm.apps".into()),
                charge_date: Some(june()),
                window_index: Some(i),
                idempotency_key: format!("crm.apps:{}:{i}", june()),
                ..Default::default()
            });
        }
    }
    w.internal.reconcile_day(&system(), june()).await.unwrap();
    {
        let b = w.b();
        assert_eq!(b.txns.len(), 96);
        assert_eq!(b.txns[95].window_index, Some(95));
        // The invoiced gauge: the day's snapshot.
        assert_eq!(b.usage.len(), 1);
        assert_eq!((b.usage[0].u.kind, b.usage[0].u.date), ("SNAPSHOT", june()));
        same(b.usage[0].u.quantity, "2");
    }
    // A fully charged day does nothing; a count that fails is skipped.
    w.internal.reconcile_day(&system(), june()).await.unwrap();
    assert_eq!(w.b().txns.len(), 96);
    w.b().fail_counts = true;
    w.internal.meter_window(&system(), date(2026, 6, 16), 1).await.unwrap();
    assert_eq!(w.b().txns.len(), 96);
    // The current window runs in the server's zone; with no instructions left it charges nothing.
    w.b().instructions.clear();
    w.internal.meter_current_window(&system()).await.unwrap();
}

// ---------------------------------------------------------------------------------------------
// Monthly invoices and the overdue pass

fn monthly_invoice(id: u64, status: &str, due: NaiveDate) -> Rec {
    Rec::new(&INVOICE)
        .with("id", Val::Id(id))
        .with("invoiceNumber", Val::Str(format!("INV/M/{id}")))
        .with("kind", Val::Str("MONTHLY".into()))
        .with("status", Val::Str(status.into()))
        .with("dueDate", Val::Date(due))
        .with("sellerClientId", Val::Id(C_CLIENT))
        .with("clientId", Val::Id(M_CLIENT))
        .with("appId", Val::Id(APP))
        .with("totalAmount", Val::Dec(d("118.00")))
}

/// INVOICE meters (users at 300 a month above 2, leads at 2 each above 100, AI priced already)
/// and September's usage: 30 days of 5 users, 150 leads less a 10 reversed, 1234.5678 of AI.
fn invoice_world(w: &World) {
    let mut b = w.b();
    b.configs.push(BillingConfig { gst_percentage: d("18"), ..config() });
    b.meters.push(Meter { charge_mode: "INVOICE".into(), display_order: 1, ..gauge(11, "users", "USERS", "300", "2") });
    b.meters.push(Meter { charge_mode: "INVOICE".into(), display_order: 2, unit_label: Some("leads".into()), ..counter(21, "leads", "2", "100") });
    b.meters.push(Meter {
        charge_mode: "INVOICE".into(),
        display_order: 3,
        kind: "COUNTER".into(),
        rate_unit: "MARKUP".into(),
        label: "AI".into(),
        ..gauge(41, "ai.tokens", "AI_TOKENS", "2", "0")
    });
    let usage = |meter_id: u64, day: u32, kind: &'static str, q: &str, reference: Option<String>| UsageRow {
        u: Usage { client_id: M_CLIENT, app_id: APP, meter_id, date: date(2026, 9, day), kind, quantity: d(q), figures: None, reference },
        at: dt("2026-09-30 00:00:00"),
        invoice: None,
    };
    for day in 1..=30 {
        b.usage.push(usage(11, day, "SNAPSHOT", "5", None));
    }
    for (i, q) in ["50", "50", "50"].iter().enumerate() {
        b.usage.push(usage(21, 10 + i as u32, "EVENT", q, Some(format!("L{i}"))));
    }
    b.usage.push(usage(21, 20, "REVERSAL", "10", Some("L0".into())));
    b.usage.push(usage(41, 25, "EVENT", "1234.5678", Some("ai:r1".into())));
}

#[tokio::test]
async fn monthly_invoice_lines_price_each_invoiced_meter_above_its_free_quantity() {
    let w = world();
    invoice_world(&w);
    let config = w.b().configs[0].clone();
    let lines = w.internal.invoice_lines(&config, M_CLIENT, None, None, date(2026, 10, 1)).await.unwrap();
    let got: Vec<(&str, Option<u64>, String, String, String, i64)> =
        lines.iter().map(|l| (l.kind, l.meter_id, l.quantity.to_string(), l.rate.to_string(), l.amount.to_string(), l.order)).collect();
    assert_eq!(
        got,
        vec![
            // 30 days of 3 above the free 2, over a 30-day month: 3 user-months at 300.
            ("METER", Some(11), "3.000000".into(), "300".into(), "900.00".into(), 2),
            // 150 less 10 reversed, 100 free: 40 at 2.
            ("METER", Some(21), "140".into(), "2".into(), "80.00".into(), 3),
            // AI events are priced already: the rate is one.
            ("METER", Some(41), "1234.5678".into(), "1".into(), "1234.56".into(), 4),
        ]
    );
    assert_eq!(lines[0].description, "Users above 2 free (users months), 01 Sep 2026 to 30 Sep 2026");
    assert_eq!(lines[1].description, "Leads (leads), 01 Sep 2026 to 30 Sep 2026");
    assert_eq!((lines[0].period_start, lines[0].period_end), (date(2026, 9, 1), date(2026, 10, 1)));
    let (base, gst, total) = totals(&lines, config.gst_percentage);
    assert_eq!((base.to_string(), gst.to_string(), total.to_string()), ("2214.56".into(), "398.62".into(), "2613.18".into()));

    // An INVOICE plan adds its fee for the new period first; a hard-capped meter is never billed.
    let mut pro = Plan { price_amount: d("5000"), ..plan(32, "pro", "Pro") };
    pro.overrides.insert("users".into(), MeterOverride { free: Some(d("10")), rate: None, hard_cap: true });
    let lines = w.internal.invoice_lines(&config, M_CLIENT, Some(&pro), Some(date(2026, 10, 1)), date(2026, 10, 1)).await.unwrap();
    let kinds: Vec<(&str, Option<u64>, Option<u64>)> = lines.iter().map(|l| (l.kind, l.meter_id, l.plan_id)).collect();
    assert_eq!(kinds, vec![("PLAN", None, Some(32)), ("METER", Some(21), None), ("METER", Some(41), None)]);
    assert_eq!(lines[0].description, "Pro plan, 01 Oct 2026 to 31 Oct 2026");
    assert_eq!((lines[0].amount.to_string(), lines[0].period_end), ("5000".into(), date(2026, 11, 1)));
    // A free default plan bills no usage: past its caps the actions are refused.
    let free = Plan { is_default: true, ..plan(30, "free", "Free") };
    assert!(w.internal.invoice_lines(&config, M_CLIENT, Some(&free), None, date(2026, 10, 1)).await.unwrap().is_empty());
    // Usage on or after the cut-off day waits for the next invoice.
    assert!(w.internal.invoice_lines(&config, M_CLIENT, None, None, date(2026, 9, 1)).await.unwrap().is_empty());
}

#[tokio::test]
async fn a_monthly_invoice_with_a_zero_total_is_not_raised() {
    let w = world();
    invoice_world(&w);
    let config = w.b().configs[0].clone();
    // A client without usage, and one whose usage stays inside the free quantities.
    assert!(w.internal.raise_monthly_invoice(&system(), &config, 3, None, None, date(2026, 10, 1)).await.unwrap().is_none());
    {
        let mut b = w.b();
        // 100 leads: exactly the free quantity.
        b.usage.retain(|r| r.u.meter_id == 21 && r.u.kind == "EVENT" && r.u.reference.as_deref() != Some("L2"));
    }
    assert!(w.internal.raise_monthly_invoice(&system(), &config, M_CLIENT, None, None, date(2026, 10, 1)).await.unwrap().is_none());
    let b = w.b();
    assert!(b.invoices.is_empty());
    assert!(b.usage.iter().all(|r| r.invoice.is_none()));
}

#[tokio::test]
async fn pending_monthly_invoices_past_due_become_overdue_once() {
    let w = world();
    {
        let mut b = w.b();
        b.invoices.push(monthly_invoice(1, "PENDING", date(2026, 10, 10)));
        b.invoices.push(monthly_invoice(2, "PENDING", date(2026, 10, 20)));
        b.invoices.push(monthly_invoice(3, "PENDING", date(2026, 10, 1)).with("kind", Val::Str("BUNDLE".into())));
        b.invoices.push(monthly_invoice(4, "PAID", date(2026, 10, 1)));
    }
    w.internal.mark_overdue(&system(), today()).await.unwrap();
    let statuses: Vec<String> = w.b().invoices.iter().map(|i| i.str("status").unwrap().to_string()).collect();
    assert_eq!(statuses, ["OVERDUE", "PENDING", "PENDING", "PAID"]);
    assert_eq!(w.event_names(), vec![INVOICE_OVERDUE.to_string()]);
    let e = w.events.events.lock().unwrap()[0].clone();
    assert_eq!((e.client_code.as_deref(), e.app_code.as_deref()), (Some("BUS"), Some("crm")));
    let data = w.event_data(0);
    assert_eq!((data["invoiceId"].as_u64(), data["invoiceNumber"].as_str(), data["dueDate"].as_str()), (Some(1), Some("INV/M/1"), Some("2026-10-10")));
    // The next run finds nothing new.
    w.internal.mark_overdue(&system(), today()).await.unwrap();
    assert_eq!(w.events.events.lock().unwrap().len(), 1);
}

// ---------------------------------------------------------------------------------------------
// Gated: raising a monthly invoice reads the config's seller fields through `Internal.db`.

/// The local `security` pool, read only here; `None` (skipped) without the live environment or
/// without the V90 tables.
async fn local_db() -> Option<Db> {
    let (Ok(_), Ok(password)) = (std::env::var("SECURITY_AUTH_LIVE"), std::env::var("MODLIX__DATABASE__PASSWORD")) else {
        eprintln!("skipped: SECURITY_AUTH_LIVE / MODLIX__DATABASE__PASSWORD not set");
        return None;
    };
    let cfg = platform::config::MySqlConfig { database: "security".into(), password, max_connections: 2, ..Default::default() };
    let pool = platform::db::mysql_pool(&cfg).await.ok()?;
    let v90: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'security' AND table_name = 'security_usage_record'")
        .fetch_one(&pool)
        .await
        .ok()?;
    if v90 == 0 {
        eprintln!("skipped: the local schema has no V90 billing tables");
        return None;
    }
    Some(Db::new(pool))
}

/// A config id no local row has, so the seller fields read as empty.
const UNSEEN_CONFIG: u64 = 4_000_000_001;

#[tokio::test]
async fn a_monthly_invoice_is_raised_once_with_its_lines() {
    let Some(db) = local_db().await else { return };
    let w = world_on(db);
    invoice_world(&w);
    w.b().configs[0].id = UNSEEN_CONFIG;
    for m in w.b().meters.iter_mut() {
        m.config_id = UNSEEN_CONFIG;
    }
    let config = w.b().configs[0].clone();
    let inv = w.internal.raise_monthly_invoice(&system(), &config, M_CLIENT, None, None, date(2026, 10, 1)).await.unwrap().expect("raised");
    let id = inv.id().unwrap();
    assert_eq!((inv.str("kind"), inv.str("status"), inv.str("periodKey")), (Some("MONTHLY"), Some("PENDING"), Some("2:2::2026-10-01")));
    assert_eq!((inv.date_of("periodStart"), inv.date_of("periodEnd"), inv.date_of("dueDate")), (Some(date(2026, 9, 1)), Some(date(2026, 10, 1)), Some(date(2026, 10, 30))));
    let money: Vec<String> = ["baseAmount", "gstAmount", "totalAmount"].iter().map(|p| inv.dec(p).unwrap().to_string()).collect();
    assert_eq!(money, ["2214.56", "398.62", "2613.18"]);
    assert_eq!((inv.u64("sellerClientId"), inv.u64("clientId"), inv.str("buyerLegalName"), inv.str("sellerLegalName")), (Some(C_CLIENT), Some(M_CLIENT), Some("BUS name"), None));
    assert!(inv.str("invoiceNumber").unwrap().starts_with("INV/"));
    {
        let b = w.b();
        let lines: Vec<(Option<&str>, Option<u64>, Option<u64>)> = b.lines.iter().map(|l| (l.str("kind"), l.u64("meterId"), l.u64("invoiceId"))).collect();
        assert_eq!(lines, vec![(Some("METER"), Some(11), Some(id)), (Some("METER"), Some(21), Some(id)), (Some("METER"), Some(41), Some(id))]);
        assert!(b.usage.iter().all(|r| r.invoice == Some(id)), "the usage is marked billed");
    }
    assert_eq!(w.event_names(), vec![INVOICE_ISSUED.to_string()]);
    let data = w.event_data(0);
    assert_eq!((data["invoiceId"].as_u64(), data["totalAmount"].as_str()), (Some(id), Some("2613.18")));
    // The run again: nothing is unbilled any more.
    assert!(w.internal.raise_monthly_invoice(&system(), &config, M_CLIENT, None, None, date(2026, 10, 1)).await.unwrap().is_none());

    // An INVOICE plan's fee for a period: the period key stops a second invoice.
    let pro = Plan { config_id: UNSEEN_CONFIG, price_amount: d("5000"), ..plan(32, "pro", "Pro") };
    let fee = w.internal.raise_monthly_invoice(&system(), &config, M_CLIENT, Some(&pro), Some(date(2026, 10, 1)), date(2026, 10, 1)).await.unwrap().expect("raised");
    assert_eq!((fee.str("periodKey"), fee.str("bundleLabel")), (Some("2:2:2026-10-01:2026-10-01"), Some("Pro plan")));
    assert_eq!(fee.dec("totalAmount").unwrap().to_string(), "5900.00");
    assert!(w.internal.raise_monthly_invoice(&system(), &config, M_CLIENT, Some(&pro), Some(date(2026, 10, 1)), date(2026, 10, 1)).await.unwrap().is_none());
    assert_eq!(w.b().invoices.len(), 2);
}

#[tokio::test]
async fn the_invoice_day_raises_the_usage_of_clients_not_on_an_invoiced_plan() {
    let Some(db) = local_db().await else { return };
    let w = world_on(db);
    invoice_world(&w);
    w.b().configs[0].id = UNSEEN_CONFIG;
    for m in w.b().meters.iter_mut() {
        m.config_id = UNSEEN_CONFIG;
    }
    // Not the invoice day (the 1st): nothing.
    w.internal.invoice_day(&system(), date(2026, 10, 2)).await.unwrap();
    assert!(w.b().invoices.is_empty());
    // On an invoiced plan: invoiced when its period ends, not on the invoice day.
    {
        let mut b = w.b();
        b.plans.push(Plan { config_id: UNSEEN_CONFIG, price_amount: d("5000"), ..plan(32, "pro", "Pro") });
        b.wallets.push(wallet("0", "ACTIVE", 0));
        b.wallet_plans.push(on_plan(7, 32, date(2026, 9, 1), date(2026, 11, 1)));
    }
    w.internal.invoice_day(&system(), date(2026, 10, 1)).await.unwrap();
    assert!(w.b().invoices.is_empty());
    w.b().wallet_plans.clear();
    w.internal.invoice_day(&system(), date(2026, 10, 1)).await.unwrap();
    let b = w.b();
    assert_eq!(b.invoices.len(), 1);
    assert_eq!(b.invoices[0].dec("totalAmount").unwrap().to_string(), "2613.18");
}
