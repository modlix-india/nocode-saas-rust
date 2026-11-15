//! security-admin's billing services, ported from `BundlePurchaseServiceTest`,
//! `RazorpayPaymentServiceTest`, `InvoiceServiceTest`, `WalletServiceTest` (the owner views and the
//! credits), and the service halves of `AppBillingBundleServiceIntegrationTest`,
//! `AppBillingConfigServiceIntegrationTest`, `BundlePurchaseServiceIntegrationTest`,
//! `InvoiceServiceIntegrationTest`, `RazorpayWebhookIntegrationTest` and
//! `WalletServiceBillingIntegrationTest`.
//!
//! The Java unit tests mock the DAOs; an in-memory billing store plays that part here, the
//! clients and apps come from the shared fake schema, and the outside calls (files, Razorpay,
//! the app URL) are answered in process. No payment API is called and no real row is touched.

mod common;
#[path = "common/billing_recs.rs"]
mod billing_recs;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::http::StatusCode;
use chrono::{NaiveDate, NaiveDateTime};
use billing_recs::{cfg_of, lot_of, meter_of, plan_of, txn_rec, wallet_plan_of, wallet_plan_rec, wallet_rule};
use common::{app, client, harness, Harness, RecordingEvents};
use hmac::{Hmac, Mac};
use security::admin::billing::purchase::PurchaseRequest;
use security::admin::billing::service::{Billing, Outside};
use security::condition::{Cond, Op};
use security::data::billing::{
    sql as wallet_sql, AiRate, BillingConfig, BillingStore, Instruction, Lot, Meter, NewLot, PeriodUsage, Plan, Txn, Usage, Wallet, WalletPlan,
};
use security::data::billing_admin::{
    AdminBillingStore, Find, Rec, Schema, Val, AI_RATE, BUNDLE, CONFIG, INVOICE, LOT, METER, PAYMENT, PLAN, PROFILE, TXN, WALLET, WALLET_PLAN,
};
use security::data::clients::Rows;
use security::data::Db;
use security::decimal::Dec;
use security::errors::{AuthError, AuthResult};
use security::internal::Internal;
use security::model::{App, ContextAuth, ContextUser};
use security::spring::{Order, Pageable};
use serde_json::{json, Map, Value};
use sha2::Sha256;

// ---------------------------------------------------------------------------------------------
// The in-memory billing tables

#[derive(Default)]
struct Books {
    rows: HashMap<&'static str, Vec<Rec>>,
    next: u64,
    counters: HashMap<(u64, String), u64>,
    /// (app, client) pairs with write access.
    write: Vec<(u64, u64)>,
    app_counts: HashMap<(u64, &'static str), i64>,
    user_counts: HashMap<(u64, u64), i64>,
    settings: HashMap<String, String>,
    last_invoice_cond: Option<Cond>,
    last_party: Option<Option<u64>>,
    fail_insert: bool,
}

#[derive(Default)]
struct FakeBooks {
    b: Mutex<Books>,
}

fn prop_of(s: &Schema, column: &str) -> &'static str {
    s.cols.iter().find(|c| c.name == column).map(|c| c.prop).unwrap_or("")
}

fn cmp(a: &Val, b: &Val) -> std::cmp::Ordering {
    use std::cmp::Ordering::*;
    match (a, b) {
        (Val::Id(x), Val::Id(y)) => x.cmp(y),
        (Val::Int(x), Val::Int(y)) => x.cmp(y),
        (Val::Dec(x), Val::Dec(y)) => x.cmp_value(y),
        (Val::Str(x), Val::Str(y)) => x.cmp(y),
        (Val::Ts(x), Val::Ts(y)) => x.cmp(y),
        (Val::Null, Val::Null) => Equal,
        (Val::Null, _) => Less,
        (_, Val::Null) => Greater,
        _ => Equal,
    }
}

fn value_matches(v: &Val, j: &Value) -> bool {
    match (v, j) {
        (Val::Id(x), Value::Number(n)) => n.as_u64() == Some(*x),
        (Val::Id(x), Value::String(s)) => s.parse::<u64>().ok() == Some(*x),
        (Val::Str(x), Value::String(s)) => x == s,
        (Val::Dec(x), Value::Number(n)) => Dec::parse(&n.to_string()).is_some_and(|d| d.cmp_value(x).is_eq()),
        _ => false,
    }
}

/// The filters the services build: EQUALS and IN on a property, AND / OR, negation.
fn eval(rec: &Rec, c: &Cond) -> bool {
    match c {
        Cond::Ignored => true,
        Cond::Complex { and, conditions, negate } => {
            let r = if *and { conditions.iter().all(|x| eval(rec, x)) } else { conditions.iter().any(|x| eval(rec, x)) };
            r != *negate
        }
        Cond::Filter(f) => {
            let Some(field) = f.field.as_deref() else { return true };
            if !rec.schema.cols.iter().any(|c| c.prop == field) {
                return !f.negate;
            }
            let v = rec.get(field);
            let r = match f.op {
                Op::Equals => f.value.as_ref().is_none_or(|j| value_matches(v, j)),
                Op::In => {
                    let text = f.value.as_ref().and_then(Value::as_str).unwrap_or("");
                    text.split(',').any(|p| value_matches(v, &Value::String(p.trim().to_string())))
                }
                _ => true,
            };
            r != f.negate
        }
    }
}

fn sorted(mut rows: Vec<Rec>, p: &Pageable) -> Vec<Rec> {
    for o in p.sort.iter().rev() {
        rows.sort_by(|a, b| {
            let c = cmp(a.get(&o.property), b.get(&o.property));
            if o.ascending {
                c
            } else {
                c.reverse()
            }
        });
    }
    rows.into_iter().skip(p.offset() as usize).take(p.size as usize).collect()
}

impl FakeBooks {
    fn put(&self, rec: Rec) -> Rec {
        let mut b = self.b.lock().unwrap();
        let mut rec = rec;
        if rec.id().is_none() {
            b.next += 1;
            let id = 5000 + b.next;
            rec.set("id", Val::Id(id));
        }
        b.rows.entry(rec.schema.table).or_default().push(rec.clone());
        rec
    }

    fn all(&self, s: &Schema) -> Vec<Rec> {
        self.b.lock().unwrap().rows.get(s.table).cloned().unwrap_or_default()
    }

    fn one(&self, s: &Schema, id: u64) -> Option<Rec> {
        self.all(s).into_iter().find(|r| r.id() == Some(id))
    }

    fn grant(&self, app: u64, client: u64) {
        self.b.lock().unwrap().write.push((app, client));
    }
}

#[async_trait]
impl AdminBillingStore for FakeBooks {
    async fn by_id(&self, s: &'static Schema, id: u64) -> AuthResult<Option<Rec>> {
        Ok(self.one(s, id))
    }

    async fn find(&self, s: &'static Schema, q: &Find) -> AuthResult<Vec<Rec>> {
        let mut rows: Vec<Rec> = self
            .all(s)
            .into_iter()
            .filter(|r| q.eq.iter().all(|(c, v)| r.get(prop_of(s, c)) == v))
            .filter(|r| !q.not_deleted || r.str("status") != Some("DELETED"))
            .collect();
        if let Some(o) = q.order_by {
            rows.sort_by(|a, b| cmp(a.get(prop_of(s, o)), b.get(prop_of(s, o))));
        }
        if q.first {
            rows.truncate(1);
        }
        Ok(rows)
    }

    async fn insert(&self, rec: &Rec) -> AuthResult<u64> {
        if self.b.lock().unwrap().fail_insert {
            return Err(AuthError::internal("insert refused"));
        }
        let mut r = rec.clone();
        r.set("id", Val::Null);
        // The NOT NULL defaults the tables declare.
        for (prop, v) in [("status", "ACTIVE"), ("gateway", "RAZORPAY"), ("currency", "INR")] {
            if matches!(r.get(prop), Val::Null) && r.schema.cols.iter().any(|c| c.prop == prop && !c.nullable) {
                r.set(prop, Val::Str(v.into()));
            }
        }
        Ok(self.put(r).id().unwrap_or(0))
    }

    async fn update(&self, rec: &Rec) -> AuthResult<u64> {
        let mut b = self.b.lock().unwrap();
        let Some(rows) = b.rows.get_mut(rec.schema.table) else { return Ok(0) };
        let Some(row) = rows.iter_mut().find(|r| r.id() == rec.id()) else { return Ok(0) };
        for (i, c) in rec.schema.cols.iter().enumerate() {
            if matches!(c.name, "CREATED_BY" | "CREATED_AT" | "UPDATED_AT") || (matches!(rec.vals[i], Val::Null) && !c.nullable) {
                continue;
            }
            row.vals[i] = rec.vals[i].clone();
        }
        Ok(1)
    }

    async fn delete(&self, s: &'static Schema, id: u64) -> AuthResult<u64> {
        let mut b = self.b.lock().unwrap();
        let rows = b.rows.entry(s.table).or_default();
        let before = rows.len();
        rows.retain(|r| r.id() != Some(id));
        Ok((before - rows.len()) as u64)
    }

    async fn invoice_page(&self, cond: Option<&Cond>, party: Option<u64>, page: &Pageable) -> AuthResult<Rows<Rec>> {
        {
            let mut b = self.b.lock().unwrap();
            b.last_invoice_cond = cond.cloned();
            b.last_party = Some(party);
        }
        let rows: Vec<Rec> = self
            .all(&INVOICE)
            .into_iter()
            .filter(|r| cond.is_none_or(|c| eval(r, c)))
            .filter(|r| party.is_none_or(|p| r.u64("sellerClientId") == Some(p) || r.u64("clientId") == Some(p)))
            .collect();
        let total = rows.len() as i64;
        Ok(Rows { rows: sorted(rows, page), total: Some(total) })
    }

    async fn txn_page(&self, wallet_id: u64, page: &Pageable) -> AuthResult<Rows<Rec>> {
        let rows: Vec<Rec> = self.all(&TXN).into_iter().filter(|r| r.u64("walletId") == Some(wallet_id)).collect();
        let total = rows.len() as i64;
        Ok(Rows { rows: sorted(rows, page), total: Some(total) })
    }

    async fn payments_of(&self, invoice_ids: &[u64]) -> AuthResult<Vec<Rec>> {
        Ok(self.all(&PAYMENT).into_iter().filter(|p| p.u64("invoiceId").is_some_and(|i| invoice_ids.contains(&i))).collect())
    }

    async fn next_invoice_number(&self, seller: u64, fin_year: &str) -> AuthResult<String> {
        let mut b = self.b.lock().unwrap();
        let n = b.counters.entry((seller, fin_year.to_string())).or_insert(0);
        *n += 1;
        Ok(format!("INV/{fin_year}/{seller}/{n}"))
    }

    async fn seed_wallet(&self, client: u64, app: u64, initial: Dec) -> AuthResult<Option<Rec>> {
        let w = Rec::new(&WALLET)
            .with("clientId", Val::Id(client))
            .with("appId", Val::Id(app))
            .with("balance", Val::Dec(initial))
            .with("status", Val::Str("ACTIVE".into()))
            .with("lowBalanceNotified", Val::Int(0))
            .with("version", Val::Int(0));
        Ok(Some(self.put(w)))
    }

    async fn credit_balance(&self, wallet: u64, tokens: Dec) -> AuthResult<u64> {
        self.mutate_wallet(wallet, |w| {
            let b = w.dec("balance").unwrap_or(Dec::ZERO).add(tokens);
            w.set("balance", Val::Dec(b));
        })
    }

    async fn set_wallet_status(&self, wallet: u64, status: &str) -> AuthResult<u64> {
        self.mutate_wallet(wallet, |w| {
            w.set("status", Val::Str(status.into()));
        })
    }

    async fn set_low_balance_notified(&self, wallet: u64, notified: bool) -> AuthResult<u64> {
        self.mutate_wallet(wallet, |w| {
            w.set("lowBalanceNotified", Val::Int(i64::from(notified)));
        })
    }

    async fn record_txn(&self, txn: &Rec) -> AuthResult<bool> {
        let dup = self.all(&TXN).iter().any(|t| t.get("walletId") == txn.get("walletId") && t.get("idempotencyKey") == txn.get("idempotencyKey"));
        if dup {
            return Ok(false);
        }
        self.put(txn.clone());
        Ok(true)
    }

    async fn has_write_access(&self, app: u64, client: u64) -> AuthResult<bool> {
        Ok(self.b.lock().unwrap().write.contains(&(app, client)))
    }

    async fn count_apps(&self, client: u64, app_type: &str) -> AuthResult<i64> {
        let b = self.b.lock().unwrap();
        Ok(b.app_counts.iter().find(|((c, t), _)| *c == client && *t == app_type).map(|(_, n)| *n).unwrap_or(0))
    }

    async fn count_users_with_profile(&self, client: u64, app: u64) -> AuthResult<i64> {
        Ok(self.b.lock().unwrap().user_counts.get(&(client, app)).copied().unwrap_or(0))
    }
}

impl FakeBooks {
    fn mutate_wallet(&self, id: u64, f: impl FnOnce(&mut Rec)) -> AuthResult<u64> {
        let mut b = self.b.lock().unwrap();
        let Some(w) = b.rows.get_mut(WALLET.table).and_then(|r| r.iter_mut().find(|w| w.id() == Some(id))) else { return Ok(0) };
        f(w);
        Ok(1)
    }
}

// ---------------------------------------------------------------------------------------------
// The same rows as security-internal's billing store: the engine (wallets, lots, plans) and the
// admin views read and write one set of books.

impl FakeBooks {
    fn txn_used(&self, t: &Txn) -> bool {
        self.all(&TXN).iter().any(|x| x.u64("walletId") == Some(t.wallet_id) && x.str("idempotencyKey") == Some(t.idempotency_key.as_str()))
    }

    fn open_lots_of(&self, wallet_id: u64) -> Vec<Lot> {
        let mut v: Vec<Lot> = self.all(&LOT).iter().map(lot_of).filter(|l| l.wallet_id == wallet_id && l.tokens_left.signum() > 0).collect();
        v.sort_by_key(|l| (l.expires_at.is_none(), l.expires_at, l.id));
        v
    }

    fn set_lot_left(&self, id: u64, left: Dec) {
        let mut b = self.b.lock().unwrap();
        if let Some(l) = b.rows.get_mut(LOT.table).and_then(|r| r.iter_mut().find(|l| l.id() == Some(id))) {
            l.set("tokensLeft", Val::Dec(left));
        }
    }

    fn ledger_sum(&self, prop: &str, wallet_id: u64, action_key: &str, from: NaiveDate, to: NaiveDate) -> Dec {
        self.all(&TXN)
            .iter()
            .filter(|t| t.u64("walletId") == Some(wallet_id) && t.str("type") == Some("DEBIT") && t.str("actionKey") == Some(action_key))
            .filter(|t| t.date_of("chargeDate").is_some_and(|d| d >= from && d <= to))
            .fold(Dec::ZERO, |a, t| a.add(t.dec(prop).unwrap_or(Dec::ZERO)))
    }
}

#[async_trait]
impl BillingStore for FakeBooks {
    async fn config_by_app_client(&self, app_id: u64, client_id: u64) -> AuthResult<Option<BillingConfig>> {
        let rows = self.all(&CONFIG);
        Ok(rows.iter().find(|r| r.u64("appId") == Some(app_id) && r.u64("clientId") == Some(client_id) && r.str("status") != Some("DELETED")).map(cfg_of))
    }
    async fn config_by_id(&self, id: u64) -> AuthResult<Option<BillingConfig>> {
        Ok(self.one(&CONFIG, id).as_ref().map(cfg_of))
    }
    async fn config_by_codes(&self, _app_code: &str, _client_code: &str) -> AuthResult<Option<BillingConfig>> {
        Ok(None)
    }
    async fn active_configs(&self) -> AuthResult<Vec<BillingConfig>> {
        Ok(self.all(&CONFIG).iter().filter(|r| r.str("status") == Some("ACTIVE")).map(cfg_of).collect())
    }
    async fn meters_of_config(&self, config_id: u64) -> AuthResult<Vec<Meter>> {
        let mut v: Vec<Meter> = self.all(&METER).iter().map(meter_of).filter(|m| m.config_id == config_id && m.status != "DELETED").collect();
        v.sort_by_key(|m| (m.display_order, m.id));
        Ok(v)
    }
    async fn meter_by_id(&self, id: u64) -> AuthResult<Option<Meter>> {
        Ok(self.one(&METER, id).as_ref().map(meter_of))
    }
    async fn charge_instructions(&self, _source: &str) -> AuthResult<Vec<Instruction>> {
        Ok(vec![])
    }
    async fn plan_by_id(&self, id: u64) -> AuthResult<Option<Plan>> {
        Ok(self.one(&PLAN, id).as_ref().map(plan_of))
    }
    async fn plans_of_config(&self, config_id: u64) -> AuthResult<Vec<Plan>> {
        Ok(self.all(&PLAN).iter().map(plan_of).filter(|p| p.config_id == config_id && p.status != "DELETED").collect())
    }
    async fn wallet_plan(&self, wallet_id: u64) -> AuthResult<Option<WalletPlan>> {
        Ok(self.all(&WALLET_PLAN).iter().map(wallet_plan_of).filter(|w| w.wallet_id == wallet_id && w.status == "ACTIVE").max_by_key(|w| w.id))
    }
    async fn wallet_plans_due(&self, day: NaiveDate) -> AuthResult<Vec<WalletPlan>> {
        Ok(self.all(&WALLET_PLAN).iter().map(wallet_plan_of).filter(|w| w.status == "ACTIVE" && w.period_end <= day).collect())
    }
    async fn start_wallet_plan(&self, wallet_id: u64, plan_id: u64, start: NaiveDate, end: NaiveDate) -> AuthResult<u64> {
        for wp in self.all(&WALLET_PLAN).iter().map(wallet_plan_of).filter(|w| w.wallet_id == wallet_id && w.status == "ACTIVE") {
            AdminBillingStore::update(self, &wallet_plan_rec(&WalletPlan { status: "ENDED".into(), ..wp })).await?;
        }
        let wp = WalletPlan { id: 0, wallet_id, plan_id, period_start: start, period_end: end, status: "ACTIVE".into(), auto_renew: true, next_plan_id: None };
        Ok(self.put(wallet_plan_rec(&wp).with("id", Val::Null)).id().unwrap_or(0))
    }
    async fn set_wallet_plan(&self, wp: &WalletPlan) -> AuthResult<u64> {
        AdminBillingStore::update(self, &wallet_plan_rec(wp)).await
    }
    async fn wallet(&self, client_id: u64, app_id: u64) -> AuthResult<Option<Wallet>> {
        Ok(self.all(&WALLET).iter().find(|w| w.u64("clientId") == Some(client_id) && w.u64("appId") == Some(app_id)).map(wallet_rule))
    }
    async fn wallet_by_id(&self, id: u64) -> AuthResult<Option<Wallet>> {
        Ok(self.one(&WALLET, id).as_ref().map(wallet_rule))
    }
    async fn create_wallet(&self, client_id: u64, app_id: u64) -> AuthResult<Option<(Wallet, bool)>> {
        if let Some(w) = BillingStore::wallet(self, client_id, app_id).await? {
            return Ok(Some((w, false)));
        }
        let rec = self.seed_wallet(client_id, app_id, Dec::ZERO).await?.unwrap();
        Ok(Some((wallet_rule(&rec), true)))
    }
    async fn debit(&self, t: &Txn) -> AuthResult<bool> {
        if self.txn_used(t) {
            return Ok(false);
        }
        self.put(txn_rec(t));
        self.mutate_wallet(t.wallet_id, |w| {
            let b = w.dec("balance").unwrap_or(Dec::ZERO).sub(t.tokens);
            w.set("balance", Val::Dec(b));
        })?;
        for (id, left) in wallet_sql::draw(&self.open_lots_of(t.wallet_id), t.tokens) {
            self.set_lot_left(id, left);
        }
        Ok(true)
    }
    async fn credit(&self, t: &Txn, lot: &NewLot) -> AuthResult<bool> {
        if self.txn_used(t) {
            return Ok(false);
        }
        let before = self.one(&WALLET, t.wallet_id).and_then(|w| w.dec("balance")).unwrap_or(Dec::ZERO);
        self.put(txn_rec(t));
        self.credit_balance(t.wallet_id, t.tokens).await?;
        let kept = t.tokens.sub(Dec::ZERO.sub(before).max(Dec::ZERO));
        if kept.signum() > 0 {
            self.put(
                Rec::new(&LOT)
                    .with("walletId", Val::Id(t.wallet_id))
                    .with("source", Val::Str(lot.source.into()))
                    .with("referenceType", lot.reference_type.clone().map(Val::Str).unwrap_or(Val::Null))
                    .with("referenceId", lot.reference_id.map(Val::Id).unwrap_or(Val::Null))
                    .with("tokensAdded", Val::Dec(kept))
                    .with("tokensLeft", Val::Dec(kept))
                    .with("addedAt", Val::Ts(NaiveDateTime::default()))
                    .with("expiresAt", lot.expires_at.map(Val::Ts).unwrap_or(Val::Null)),
            );
        }
        Ok(true)
    }
    async fn record_txn(&self, t: &Txn) -> AuthResult<bool> {
        AdminBillingStore::record_txn(self, &txn_rec(t)).await
    }
    async fn expired_lots(&self, now: NaiveDateTime) -> AuthResult<Vec<Lot>> {
        Ok(self.all(&LOT).iter().map(lot_of).filter(|l| l.tokens_left.signum() > 0 && l.expires_at.is_some_and(|e| e <= now)).collect())
    }
    async fn lots_expiring(&self, from: NaiveDateTime, to: NaiveDateTime) -> AuthResult<Vec<Lot>> {
        Ok(self.all(&LOT).iter().map(lot_of).filter(|l| l.tokens_left.signum() > 0 && l.expires_at.is_some_and(|e| e > from && e <= to)).collect())
    }
    async fn open_lots(&self, wallet_id: u64) -> AuthResult<Vec<Lot>> {
        Ok(self.open_lots_of(wallet_id))
    }
    async fn expire_lot(&self, lot: &Lot, t: &Txn) -> AuthResult<bool> {
        if self.txn_used(t) {
            return Ok(false);
        }
        self.put(txn_rec(t));
        self.credit_balance(lot.wallet_id, Dec::ZERO.sub(t.tokens)).await?;
        self.set_lot_left(lot.id, Dec::ZERO);
        Ok(true)
    }
    async fn set_status(&self, wallet_id: u64, status: &str) -> AuthResult<u64> {
        self.set_wallet_status(wallet_id, status).await
    }
    async fn set_low_balance_notified(&self, wallet_id: u64, notified: bool) -> AuthResult<u64> {
        AdminBillingStore::set_low_balance_notified(self, wallet_id, notified).await
    }
    async fn sum_quantity_between(&self, wallet_id: u64, action_key: &str, from: NaiveDate, to: NaiveDate) -> AuthResult<Dec> {
        Ok(self.ledger_sum("quantity", wallet_id, action_key, from, to))
    }
    async fn sum_tokens_between(&self, wallet_id: u64, action_key: &str, from: NaiveDate, to: NaiveDate) -> AuthResult<Dec> {
        Ok(self.ledger_sum("tokens", wallet_id, action_key, from, to))
    }
    async fn charged_windows(&self, wallet_id: u64, action_key: &str, date: NaiveDate) -> AuthResult<Vec<i16>> {
        Ok(self
            .all(&TXN)
            .iter()
            .filter(|t| t.u64("walletId") == Some(wallet_id) && t.str("actionKey") == Some(action_key) && t.date_of("chargeDate") == Some(date))
            .filter_map(|t| t.int("windowIndex").map(|w| w as i16))
            .collect())
    }
    // The admin services never reach the ledger lookups, usage records or AI rates.
    async fn txn_by_key(&self, _wallet_id: u64, _key: &str) -> AuthResult<Option<(Txn, NaiveDateTime)>> {
        Ok(None)
    }
    async fn record_usage(&self, _u: &Usage) -> AuthResult<bool> {
        Ok(false)
    }
    async fn usage_by_reference(&self, _meter_id: u64, _client_id: u64, _reference: &str) -> AuthResult<Option<(Usage, NaiveDateTime)>> {
        Ok(None)
    }
    async fn period_usage(&self, _meter_id: u64, _client_id: u64, _from: NaiveDate, _to: NaiveDate) -> AuthResult<PeriodUsage> {
        Ok(PeriodUsage::default())
    }
    async fn mark_invoiced(&self, _client_id: u64, _app_id: u64, _from: NaiveDate, _to: NaiveDate, _invoice_id: u64) -> AuthResult<u64> {
        Ok(0)
    }
    async fn clients_with_usage(&self, _config_id: u64, _before: NaiveDate) -> AuthResult<Vec<u64>> {
        Ok(vec![])
    }
    async fn count_apps(&self, client_id: u64, app_type: &str, _active_only: bool) -> AuthResult<i64> {
        AdminBillingStore::count_apps(self, client_id, app_type).await
    }
    async fn count_users_with_profile(&self, client_id: u64, app_id: u64, _profile_ids: &[u64]) -> AuthResult<i64> {
        AdminBillingStore::count_users_with_profile(self, client_id, app_id).await
    }
    async fn ai_rates(&self) -> AuthResult<Vec<AiRate>> {
        Ok(vec![])
    }
    async fn setting(&self, name: &str) -> AuthResult<Option<String>> {
        Ok(self.b.lock().unwrap().settings.get(name).cloned())
    }
    async fn has_overdue_invoice(&self, client_id: u64, app_id: u64) -> AuthResult<bool> {
        Ok(self.all(&INVOICE).iter().any(|i| i.u64("clientId") == Some(client_id) && i.u64("appId") == Some(app_id) && i.str("status") == Some("OVERDUE")))
    }
    async fn buyer_profile(&self, client_id: u64, app_id: u64) -> AuthResult<Option<Rec>> {
        Ok(self.all(&PROFILE).into_iter().find(|p| p.u64("clientId") == Some(client_id) && p.u64("appId") == Some(app_id)))
    }
    async fn insert_monthly_invoice(&self, invoice: &Rec, lines: &[Rec], fin_year: &str) -> AuthResult<Option<Rec>> {
        if self.all(&INVOICE).iter().any(|i| i.str("periodKey").is_some() && i.str("periodKey") == invoice.str("periodKey")) {
            return Ok(None);
        }
        let number = self.next_invoice_number(invoice.u64("sellerClientId").unwrap_or(0), fin_year).await?;
        let saved = self.put(invoice.clone().with("invoiceNumber", Val::Str(number)));
        for l in lines {
            self.put(l.clone().with("invoiceId", Val::Id(saved.id().unwrap_or(0))));
        }
        Ok(Some(saved))
    }
    async fn invoices_past_due(&self, day: NaiveDate) -> AuthResult<Vec<Rec>> {
        Ok(self
            .all(&INVOICE)
            .into_iter()
            .filter(|i| i.str("status") == Some("PENDING") && i.str("kind") == Some("MONTHLY") && i.date_of("dueDate").is_some_and(|d| d < day))
            .collect())
    }
    async fn set_invoice_status(&self, invoice_id: u64, status: &str) -> AuthResult<u64> {
        let Some(i) = self.one(&INVOICE, invoice_id) else { return Ok(0) };
        AdminBillingStore::update(self, &i.with("status", Val::Str(status.into()))).await
    }
    async fn earliest_unbilled(&self, _client_id: u64, _app_id: u64) -> AuthResult<Option<NaiveDate>> {
        Ok(None)
    }
    async fn gauge_month_units(&self, _meter_id: u64, _client_id: u64, _from: NaiveDate, _to: NaiveDate, _free: Dec) -> AuthResult<Dec> {
        Ok(Dec::ZERO)
    }
}

// ---------------------------------------------------------------------------------------------
// The outside calls, answered in process

#[derive(Default)]
struct FakeOutside {
    calls: Mutex<Vec<(String, Value)>>,
    keys: Mutex<Vec<String>>,
    urls: Mutex<Vec<u64>>,
    fail_files: bool,
}

#[async_trait]
impl Outside for FakeOutside {
    async fn secured_key(&self, file_path: &str) -> AuthResult<String> {
        if self.fail_files {
            return Err(AuthError::internal("files down"));
        }
        self.keys.lock().unwrap().push(file_path.to_string());
        let key = if file_path.contains("/receipts/") { "RCPTKEY" } else { "INVKEY" };
        Ok(format!("api/files/secured/downloadFileByKey/{key}"))
    }

    async fn razorpay(&self, path: &str, key_id: &str, _key_secret: &str, body: &Value) -> AuthResult<Value> {
        self.calls.lock().unwrap().push((path.to_string(), body.clone()));
        assert_eq!(key_id, "rzp_test_key");
        Ok(match path {
            "/payment_links" => json!({"id": "plink_new", "short_url": "https://rzp.io/i/short"}),
            _ => json!({"id": "order_new", "amount": body["amount"].clone()}),
        })
    }

    async fn app_url(&self, _internal: &Internal, _ca: &ContextAuth, app: &App, client_id: u64) -> AuthResult<String> {
        self.urls.lock().unwrap().push(client_id);
        Ok(format!("https://{}.example", app.app_code))
    }
}

// ---------------------------------------------------------------------------------------------
// The world: SYSTEM (1) manages BUS (2), which manages CUST (3); OTHER (4) is a stranger under
// SYSTEM. The crm app (2) is billed by SYSTEM's config (50).

const C_CLIENT: u64 = 1;
const M_CLIENT: u64 = 2;
const STRANGER: u64 = 4;
const APP: u64 = 2;
const CONFIG_ID: u64 = 50;
const BUNDLE_ID: u64 = 70;
const INVOICE_ID: u64 = 900;
const WALLET_ID: u64 = 500;
const SECRET: &str = "whsec_test_123";

struct World {
    _h: Harness,
    books: Arc<FakeBooks>,
    outside: FakeOutside,
    events: Arc<RecordingEvents>,
    internal: Internal,
}

impl World {
    fn billing(&self) -> Billing<'_> {
        Billing { internal: &self.internal, store: self.books.as_ref(), events: self.events.as_ref(), outside: &self.outside }
    }
}

fn world() -> World {
    let h = harness();
    h.store.with(|d| {
        d.clients.push(client(STRANGER, "OTHER", "BUS", "CLIENT", 30));
        d.hierarchies.push(security::model::ClientHierarchy { client_id: STRANGER, level0: Some(1), ..Default::default() });
        d.apps.push(app(4, 1, "sitezump"));
    });
    let pool = sqlx::mysql::MySqlPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(300))
        .connect_lazy("mysql://nobody:nothing@127.0.0.1:1/security")
        .unwrap();
    let events = Arc::new(RecordingEvents::default());
    // security-internal's billing store is the same in-memory books: a credit or a plan lands in
    // the rows the admin views read.
    let books = Arc::new(FakeBooks::default());
    let internal = Internal { auth: h.auth.clone(), db: Db::new(pool), billing: books.clone(), wallet_events: events.clone() };
    World { _h: h, books, outside: FakeOutside::default(), events, internal }
}

fn d(s: &str) -> Dec {
    Dec::parse(s).unwrap()
}

fn ca(client: u64, type_code: &str, authorities: &[&str]) -> ContextAuth {
    ContextAuth {
        user: ContextUser {
            id: Some(77),
            client_id: Some(client),
            first_name: Some("Kiran".into()),
            last_name: Some("G".into()),
            email_id: Some("k@example.com".into()),
            phone_number: Some("+910000000001".into()),
            string_authorities: Some(authorities.iter().map(|a| a.to_string()).collect()),
            ..Default::default()
        },
        authenticated: true,
        client_type_code: Some(type_code.into()),
        ..Default::default()
    }
}

fn system() -> ContextAuth {
    ca(C_CLIENT, "SYS", &["Authorities.ROLE_Owner"])
}

fn buyer() -> ContextAuth {
    ca(M_CLIENT, "BUS", &["Authorities.ROLE_Owner"])
}

fn stranger() -> ContextAuth {
    ca(STRANGER, "BUS", &["Authorities.ROLE_Owner"])
}

fn config_rec(gst: &str) -> Rec {
    Rec::new(&CONFIG)
        .with("id", Val::Id(CONFIG_ID))
        .with("clientId", Val::Id(C_CLIENT))
        .with("appId", Val::Id(APP))
        .with("gstPercentage", Val::Dec(d(gst)))
        .with("sellerLegalName", Val::Str("Modlix".into()))
        .with("sellerGstin", Val::Str("29ABCDE1234F1Z5".into()))
        .with("status", Val::Str("ACTIVE".into()))
        .with("paymentGatewayConfig", Val::Json(json!({"keyId": "rzp_test_key", "keySecret": "s", "webhookSecret": SECRET, "callbackUrl": "https://x/cb"})))
}

fn bundle_rec(kind: &str) -> Rec {
    Rec::new(&BUNDLE)
        .with("id", Val::Id(BUNDLE_ID))
        .with("billingConfigId", Val::Id(CONFIG_ID))
        .with("bundleType", Val::Str(kind.into()))
        .with("label", Val::Str("Starter".into()))
        .with("currency", Val::Str("INR".into()))
        .with("status", Val::Str("ACTIVE".into()))
        .with("displayOrder", Val::Int(1))
}

fn invoices(w: &World) -> Vec<Rec> {
    w.books.all(&INVOICE)
}

// ---------------------------------------------------------------------------------------------
// BundlePurchaseServiceTest

#[tokio::test]
async fn fixed_bundle_adds_gst_on_top_and_snapshots_the_invoice() {
    let w = world();
    w.books.put(bundle_rec("FIXED").with("tokens", Val::Dec(d("1000"))).with("price", Val::Dec(d("900"))));
    w.books.put(config_rec("18"));
    let r = w.billing().purchase(&buyer(), &PurchaseRequest { bundle_id: Some(BUNDLE_ID), ..Default::default() }).await.unwrap().unwrap();
    assert_eq!(r["paymentUrl"], "https://rzp.io/i/short");
    assert_eq!(security::jackson::pretty(&r["totalAmount"]), "1062.00");
    let inv = invoices(&w).pop().unwrap();
    assert_eq!(r["invoiceId"], json!(inv.id().unwrap()));
    assert_eq!(inv.str("status"), Some("PENDING"));
    // LZT-2003: the purchasing user is kept as the invoice's creator.
    assert_eq!(inv.u64("createdBy"), Some(77));
    assert_eq!((inv.u64("sellerClientId"), inv.u64("clientId")), (Some(C_CLIENT), Some(M_CLIENT)));
    // No saved profile: the client's name.
    assert_eq!(inv.str("buyerLegalName"), Some("BUS name"));
    assert_eq!(inv.dec("tokensPurchased").unwrap().to_string(), "1000");
    assert_eq!(inv.dec("baseAmount").unwrap().to_string(), "900");
    assert_eq!(inv.dec("gstAmount").unwrap().to_string(), "162.00");
    assert_eq!(inv.dec("totalAmount").unwrap().to_string(), "1062.00");
    assert_eq!(inv.str("currency"), Some("INR"));
    assert_eq!(inv.str("sellerLegalName"), Some("Modlix"));
    assert!(inv.str("invoiceNumber").unwrap().starts_with("INV/") && inv.str("invoiceNumber").unwrap().ends_with("/1/1"));
    // The hosted link: amount in paise, the callback, and a PENDING payment keyed by the link.
    let calls = w.outside.calls.lock().unwrap().clone();
    assert_eq!(calls[0].0, "/payment_links");
    assert_eq!(calls[0].1["amount"], 106200);
    assert_eq!(calls[0].1["callback_url"], "https://x/cb");
    assert_eq!(calls[0].1["callback_method"], "get");
    assert_eq!(calls[0].1["reference_id"], format!("INV_{}", inv.id().unwrap()));
    let p = w.books.all(&PAYMENT).pop().unwrap();
    assert_eq!((p.str("gatewayOrderId"), p.str("status")), (Some("plink_new"), Some("PENDING")));
    assert_eq!(p.map("response")["init"]["short_url"], "https://rzp.io/i/short");
}

#[tokio::test]
async fn custom_bundle_prices_at_price_per_token_with_a_saved_profile() {
    let w = world();
    w.books.put(bundle_rec("CUSTOM").with("pricePerToken", Val::Dec(d("0.9"))).with("minTokens", Val::Dec(d("500"))).with("maxTokens", Val::Dec(d("5000"))));
    w.books.put(config_rec("18"));
    w.books.put(
        Rec::new(&PROFILE)
            .with("clientId", Val::Id(M_CLIENT))
            .with("appId", Val::Id(APP))
            .with("legalName", Val::Str("Acme Pvt Ltd".into()))
            .with("gstin", Val::Str("29XYZ".into()))
            .with("city", Val::Str("Bengaluru".into()))
            .with("country", Val::Str("IN".into())),
    );
    let req = PurchaseRequest { bundle_id: Some(BUNDLE_ID), tokens: Some(d("1000")), client_id: Some(M_CLIENT) };
    let r = w.billing().purchase(&buyer(), &req).await.unwrap().unwrap();
    assert_eq!(security::jackson::pretty(&r["totalAmount"]), "1062.00");
    let inv = invoices(&w).pop().unwrap();
    assert_eq!(inv.dec("tokensPurchased").unwrap().to_string(), "1000");
    assert_eq!(inv.dec("baseAmount").unwrap().to_string(), "900.0");
    assert_eq!((inv.str("buyerLegalName"), inv.str("buyerGstin"), inv.str("buyerAddress")), (Some("Acme Pvt Ltd"), Some("29XYZ"), Some("Bengaluru, IN")));
}

#[tokio::test]
async fn custom_bundle_refusals_create_no_invoice() {
    let w = world();
    w.books.put(bundle_rec("CUSTOM").with("pricePerToken", Val::Dec(d("0.9"))).with("minTokens", Val::Dec(d("500"))));
    w.books.put(config_rec("18"));
    let b = w.billing();
    let below = b.purchase(&buyer(), &PurchaseRequest { bundle_id: Some(BUNDLE_ID), tokens: Some(d("100")), ..Default::default() }).await.unwrap_err();
    assert_eq!((below.status(), below.message()), (StatusCode::BAD_REQUEST, "Required params {tokens (below minimum)} for $ not found".into()));
    let none = b.purchase(&buyer(), &PurchaseRequest { bundle_id: Some(BUNDLE_ID), ..Default::default() }).await.unwrap_err();
    assert_eq!(none.message(), "Required params {tokens} for $ not found");
    assert!(invoices(&w).is_empty());
    assert!(w.outside.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn purchases_are_refused_before_anything_is_written() {
    let w = world();
    w.books.put(bundle_rec("FIXED").with("price", Val::Dec(d("900"))));
    w.books.put(config_rec("18"));
    let b = w.billing();
    // A client the caller does not manage.
    let e = b.purchase(&buyer(), &PurchaseRequest { bundle_id: Some(BUNDLE_ID), client_id: Some(STRANGER), ..Default::default() }).await.unwrap_err();
    assert_eq!(e.message(), "Permission/Role buy for this client is required to use this operation");
    // A managed client (SYSTEM buys for BUS), an unknown bundle, a bundle without a config.
    let e = b.purchase_order(&system(), &PurchaseRequest { bundle_id: Some(999), client_id: Some(M_CLIENT), ..Default::default() }).await.unwrap_err();
    assert_eq!((e.status(), e.message()), (StatusCode::NOT_FOUND, "AppBillingBundle with id 999 not found".into()));
    w.books.put(bundle_rec("FIXED").with("id", Val::Id(71)).with("billingConfigId", Val::Id(51)));
    let e = b.quote(&PurchaseRequest { bundle_id: Some(71), ..Default::default() }).await.unwrap_err();
    assert_eq!(e.message(), "AppBillingConfig with id 51 not found");
    let e = b.quote(&PurchaseRequest::default()).await.unwrap_err();
    assert_eq!(e.message(), "AppBillingBundle with id null not found");
    // A config without credentials: the invoice is made, then Java's IllegalStateException.
    w.books.put(config_rec("18").with("id", Val::Id(52)).with("paymentGatewayConfig", Val::Json(json!({"keyId": " "}))));
    w.books.put(bundle_rec("FIXED").with("id", Val::Id(72)).with("billingConfigId", Val::Id(52)).with("price", Val::Dec(d("1"))));
    let e = b.purchase(&buyer(), &PurchaseRequest { bundle_id: Some(72), ..Default::default() }).await.unwrap_err();
    assert_eq!(e.to_string(), "500 Internal Server Error: Razorpay keyId/keySecret missing in billing config");
    assert!(w.outside.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn checkout_orders_carry_what_the_modal_needs() {
    let w = world();
    w.books.put(bundle_rec("FIXED").with("tokens", Val::Dec(d("2000.0000"))).with("price", Val::Dec(d("999.0000"))));
    w.books.put(config_rec("18.00"));
    let r = w.billing().purchase_order(&buyer(), &PurchaseRequest { bundle_id: Some(BUNDLE_ID), ..Default::default() }).await.unwrap().unwrap();
    let inv = invoices(&w).pop().unwrap();
    let keys: Vec<&String> = r.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["orderId", "keyId", "amount", "currency", "invoiceId", "invoiceNumber", "totalAmount", "prefillName", "prefillEmail", "prefillContact"]);
    assert_eq!((r["orderId"].as_str(), r["keyId"].as_str(), r["amount"].as_i64()), (Some("order_new"), Some("rzp_test_key"), Some(117882)));
    assert_eq!((r["prefillName"].as_str(), r["prefillEmail"].as_str()), (Some("Kiran G"), Some("k@example.com")));
    let calls = w.outside.calls.lock().unwrap().clone();
    assert_eq!(calls[0].0, "/orders");
    assert_eq!(calls[0].1["notes"], json!({"invoiceId": inv.id().unwrap().to_string(), "invoiceNumber": inv.str("invoiceNumber").unwrap()}));
    assert_eq!(calls[0].1["receipt"], format!("INV_{}", inv.id().unwrap()));
    // Repay: a fresh order for the same PENDING invoice, no new invoice.
    let again = w.billing().repay(&buyer(), inv.id()).await.unwrap().unwrap();
    assert_eq!(again["invoiceId"], r["invoiceId"]);
    assert_eq!(invoices(&w).len(), 1);
    assert_eq!(w.books.all(&PAYMENT).len(), 2);
}

#[tokio::test]
async fn repay_only_the_callers_pending_or_failed_invoice() {
    let w = world();
    w.books.put(bundle_rec("FIXED").with("price", Val::Dec(d("10"))));
    w.books.put(config_rec("18"));
    let inv = |status: &str, id: u64| {
        Rec::new(&INVOICE)
            .with("id", Val::Id(id))
            .with("clientId", Val::Id(M_CLIENT))
            .with("sellerClientId", Val::Id(C_CLIENT))
            .with("appId", Val::Id(APP))
            .with("bundleId", Val::Id(BUNDLE_ID))
            .with("status", Val::Str(status.into()))
            .with("totalAmount", Val::Dec(d("11.80")))
    };
    w.books.put(inv("PAID", 1));
    w.books.put(inv("FAILED", 2));
    let b = w.billing();
    let e = b.repay(&buyer(), Some(1)).await.unwrap_err();
    assert_eq!((e.status(), e.message()), (StatusCode::BAD_REQUEST, "Required params {invoice (already PAID)} for $ not found".into()));
    let e = b.repay(&stranger(), Some(2)).await.unwrap_err();
    assert_eq!(e.message(), "Permission/Role pay this invoice is required to use this operation");
    let e = b.repay(&buyer(), Some(3)).await.unwrap_err();
    assert_eq!(e.status(), StatusCode::NOT_FOUND);
    assert!(w.outside.calls.lock().unwrap().is_empty());
    // SYSTEM may repay any invoice; the prefill falls back to the buyer's name.
    let mut sys = system();
    sys.user.first_name = None;
    sys.user.last_name = Some(" ".into());
    let r = b.repay(&sys, Some(2)).await.unwrap().unwrap();
    assert_eq!(r["prefillName"], "BUS name");
    assert_eq!(r["amount"], 1180);
    // A monthly invoice (no bundle), OVERDUE: paid through its seller's config.
    w.books.put(inv("OVERDUE", 4).with("bundleId", Val::Null).with("kind", Val::Str("MONTHLY".into())));
    let r = b.repay(&buyer(), Some(4)).await.unwrap().unwrap();
    assert_eq!((r["invoiceId"].as_u64(), r["amount"].as_i64(), r["keyId"].as_str()), (Some(4), Some(1180), Some("rzp_test_key")));
    // One from a seller without a config.
    w.books.put(inv("PENDING", 5).with("bundleId", Val::Null).with("sellerClientId", Val::Id(STRANGER)));
    assert_eq!(b.repay(&buyer(), Some(5)).await.unwrap_err().message(), "Required params {billing config} for $ not found");
}

// ---------------------------------------------------------------------------------------------
// RazorpayPaymentServiceTest + RazorpayWebhookIntegrationTest

const LINK_ID: &str = "plink_1";

fn paid_body() -> String {
    format!("{{\"event\":\"payment_link.paid\",\"payload\":{{\"payment_link\":{{\"entity\":{{\"id\":\"{LINK_ID}\",\"payment_id\":\"pay_xyz\"}}}}}}}}")
}

fn sign(body: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(SECRET.as_bytes()).unwrap();
    mac.update(body.as_bytes());
    mac.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

fn webhook_world(total: Option<&str>) -> World {
    let w = world();
    w.books.put(config_rec("18"));
    w.books.put(
        Rec::new(&PAYMENT)
            .with("invoiceId", Val::Id(INVOICE_ID))
            .with("clientId", Val::Id(M_CLIENT))
            .with("gatewayOrderId", Val::Str(LINK_ID.into()))
            .with("gateway", Val::Str("RAZORPAY".into()))
            .with("status", Val::Str("PENDING".into()))
            .with("amount", Val::Dec(d("1062")))
            .with("response", Val::Json(json!({"init": {"short_url": "https://rzp.io/x"}}))),
    );
    let mut inv = Rec::new(&INVOICE)
        .with("id", Val::Id(INVOICE_ID))
        .with("appId", Val::Id(APP))
        .with("sellerClientId", Val::Id(C_CLIENT))
        .with("clientId", Val::Id(M_CLIENT))
        .with("tokensPurchased", Val::Dec(d("1000")))
        .with("invoiceNumber", Val::Str("INV/1".into()))
        .with("status", Val::Str("PENDING".into()))
        .with("invoiceDate", Val::Ts(NaiveDate::from_ymd_opt(2026, 10, 15).unwrap().and_hms_opt(1, 0, 0).unwrap()));
    if let Some(t) = total {
        inv.set("totalAmount", Val::Dec(d(t)));
    }
    w.books.put(inv);
    w
}

fn wallet_of(w: &World) -> Option<Rec> {
    w.books.all(&WALLET).into_iter().find(|x| x.u64("clientId") == Some(M_CLIENT) && x.u64("appId") == Some(APP))
}

#[tokio::test]
async fn a_verified_paid_webhook_credits_the_wallet_and_emits_the_invoice() {
    let w = webhook_world(None);
    let body = paid_body();
    w.billing().webhook(&ContextAuth::default(), &body, Some(&sign(&body))).await.unwrap();
    let p = w.books.all(&PAYMENT).pop().unwrap();
    assert_eq!((p.str("status"), p.str("gatewayPaymentId")), (Some("PAID"), Some("pay_xyz")));
    let inv = w.books.one(&INVOICE, INVOICE_ID).unwrap();
    assert_eq!((inv.str("status"), inv.str("paymentReference"), inv.str("gateway")), (Some("PAID"), Some("pay_xyz"), Some("RAZORPAY")));
    assert!(inv.ts("paidAt").is_some());
    // A new wallet starts at zero, then the 1000 purchased, as a PURCHASE lot.
    let wallet = wallet_of(&w).unwrap();
    assert_eq!(wallet.dec("balance").unwrap().to_string(), "1000");
    let txn = w.books.all(&TXN).pop().unwrap();
    assert_eq!((txn.str("type"), txn.str("idempotencyKey"), txn.str("referenceType")), (Some("CREDIT"), Some("payment:pay_xyz"), Some("INVOICE")));
    assert_eq!((txn.u64("referenceId"), txn.str("reason")), (Some(INVOICE_ID), Some("Credit purchase INV/1")));
    let lots = w.books.all(&LOT);
    assert_eq!((lots.len(), lots[0].str("source"), lots[0].u64("referenceId")), (1, Some("PURCHASE"), Some(INVOICE_ID)));
    let events = w.events.events.lock().unwrap().clone();
    assert_eq!(events.len(), 1);
    assert_eq!((events[0].event_name.as_str(), events[0].client_code.as_deref(), events[0].app_code.as_deref()), ("INVOICE_GENERATED", Some("BUS"), Some("crm")));
    let data: HashMap<String, Value> = events[0].data.iter().cloned().collect();
    assert_eq!(data["invoiceNumber"], "INV/1");
    assert_eq!(data["invoiceDate"], "2026-10-15");
    assert_eq!(data["urlPrefix"], "https://crm.example");
    assert_eq!(data["paymentReference"], "pay_xyz");
    assert_eq!(data["paymentGateway"], "Razorpay");
    assert_eq!(data["paymentMethod"], "Razorpay");
    assert_eq!(data["tokensPurchased"], json!(1000));
    assert_eq!(data["buyerGstin"], Value::Null);
    // The URL is the buyer's managing client's (SYSTEM).
    assert_eq!(w.outside.urls.lock().unwrap().clone(), vec![C_CLIENT]);
    // A replay is a no-op: the payment is PAID already.
    w.billing().webhook(&ContextAuth::default(), &body, Some(&sign(&body))).await.unwrap();
    assert_eq!(wallet_of(&w).unwrap().dec("balance").unwrap().to_string(), "1000");
    assert_eq!(w.events.events.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn the_payment_entity_is_captured_and_the_init_kept() {
    let w = webhook_world(Some("1062.0000"));
    let body = format!(
        "{{\"event\":\"payment_link.paid\",\"payload\":{{\"payment_link\":{{\"entity\":{{\"id\":\"{LINK_ID}\",\"payment_id\":\"pay_link_fallback\"}}}},\
         \"payment\":{{\"entity\":{{\"id\":\"pay_real\",\"amount\":106200,\"method\":\"upi\",\"fee\":2124,\"tax\":324,\"currency\":\"INR\",\"status\":\"captured\"}}}}}}}}"
    );
    w.billing().webhook(&ContextAuth::default(), &body, Some(&sign(&body))).await.unwrap();
    let p = w.books.all(&PAYMENT).pop().unwrap();
    assert_eq!((p.str("gatewayPaymentId"), p.str("status")), (Some("pay_real"), Some("PAID")));
    let resp = p.map("response");
    assert!(resp.contains_key("init") && resp.contains_key("webhook"));
    assert_eq!(resp["captured"], json!({"amount": 1062.0, "method": "upi", "fee": 21.24, "tax": 3.24, "currency": "INR", "status": "captured"}));
    // Gson's numbers: every one a Double.
    assert_eq!(resp["webhook"]["payload"]["payment"]["entity"]["amount"], json!(106200.0));
    let data: HashMap<String, Value> = w.events.events.lock().unwrap()[0].data.iter().cloned().collect();
    assert_eq!((data["paymentMethod"].as_str(), data["paymentReference"].as_str()), (Some("upi"), Some("pay_real")));
    // The invoice's page shows the method.
    let page = w.billing().my_invoices(&buyer(), &Pageable::of(0, 10, vec![]), None, Some("crm")).await.unwrap().unwrap();
    assert_eq!(page["content"][0]["paymentMethod"], "upi");
}

#[tokio::test]
async fn unverified_unknown_and_unparseable_webhooks_change_nothing() {
    let w = webhook_world(None);
    let b = w.billing();
    let anon = ContextAuth::default();
    let body = paid_body();
    b.webhook(&anon, &body, Some("deadbeef")).await.unwrap();
    b.webhook(&anon, &body, None).await.unwrap();
    b.webhook(&anon, "not-json", Some("sig")).await.unwrap();
    b.webhook(&anon, r#"{"event": "refund.created"}"#, Some("sig")).await.unwrap();
    let other = r#"{"event":"payment_link.paid","payload":{"payment_link":{"entity":{"id":"plink_other"}}}}"#;
    b.webhook(&anon, other, Some(&sign(other))).await.unwrap();
    let blank = r#"{"event":"order.paid","payload":{"order":{"entity":{"id":" "}}}}"#;
    b.webhook(&anon, blank, Some(&sign(blank))).await.unwrap();
    // A verified event that is neither paid nor failed.
    let created = format!("{{\"event\":\"payment_link.created\",\"payload\":{{\"payment_link\":{{\"entity\":{{\"id\":\"{LINK_ID}\"}}}}}}}}");
    b.webhook(&anon, &created, Some(&sign(&created))).await.unwrap();
    assert_eq!(w.books.all(&PAYMENT).pop().unwrap().str("status"), Some("PENDING"));
    assert_eq!(w.books.one(&INVOICE, INVOICE_ID).unwrap().str("status"), Some("PENDING"));
    assert!(wallet_of(&w).is_none());
    assert!(w.events.events.lock().unwrap().is_empty());
    // No webhook secret on the config: never verified.
    let w2 = webhook_world(None);
    w2.books.b.lock().unwrap().rows.get_mut(CONFIG.table).unwrap()[0].set("paymentGatewayConfig", Val::Json(json!({})));
    w2.billing().webhook(&anon, &body, Some(&sign(&body))).await.unwrap();
    assert_eq!(w2.books.one(&INVOICE, INVOICE_ID).unwrap().str("status"), Some("PENDING"));
}

#[tokio::test]
async fn an_amount_mismatch_is_held_for_review() {
    let w = webhook_world(Some("1062"));
    let body = format!(
        "{{\"event\":\"payment_link.paid\",\"payload\":{{\"payment_link\":{{\"entity\":{{\"id\":\"{LINK_ID}\",\"payment_id\":\"pay_link_fallback\"}}}},\
         \"payment\":{{\"entity\":{{\"id\":\"pay_real\",\"amount\":100000,\"method\":\"upi\",\"currency\":\"INR\",\"status\":\"captured\"}}}}}}}}"
    );
    w.billing().webhook(&ContextAuth::default(), &body, Some(&sign(&body))).await.unwrap();
    assert_eq!(w.books.one(&INVOICE, INVOICE_ID).unwrap().str("status"), Some("UNDER_REVIEW"));
    assert_eq!(w.books.all(&PAYMENT).pop().unwrap().str("status"), Some("PAID"));
    assert!(wallet_of(&w).is_none());
    assert!(w.events.events.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_failed_payment_fails_its_invoice_and_says_so() {
    let w = webhook_world(None);
    let body = r#"{"event":"payment.failed","payload":{"payment":{"entity":{"id":"pay_9","order_id":"plink_1"}}}}"#;
    w.billing().webhook(&ContextAuth::default(), body, Some(&sign(body))).await.unwrap();
    assert_eq!(w.books.all(&PAYMENT).pop().unwrap().str("status"), Some("FAILED"));
    assert_eq!(w.books.one(&INVOICE, INVOICE_ID).unwrap().str("status"), Some("FAILED"));
    let events = w.events.events.lock().unwrap().clone();
    assert_eq!(events[0].event_name, "INVOICE_PAYMENT_FAILED");
    let data: HashMap<String, Value> = events[0].data.iter().cloned().collect();
    assert_eq!((data["status"].as_str(), data["paidOn"].as_str()), (Some("FAILED"), Some("")));
    // An order.paid of the Checkout flow settles by the order id.
    let w = webhook_world(None);
    let body = r#"{"event":"order.paid","payload":{"order":{"entity":{"id":"plink_1"}},"payment":{"entity":{"id":"pay_o","amount":0}}}}"#;
    w.billing().webhook(&ContextAuth::default(), body, Some(&sign(body))).await.unwrap();
    assert_eq!(w.books.one(&INVOICE, INVOICE_ID).unwrap().str("paymentReference"), Some("pay_o"));
}

#[tokio::test]
async fn a_webhook_for_a_missing_invoice_or_config() {
    let w = webhook_world(None);
    w.books.b.lock().unwrap().rows.get_mut(INVOICE.table).unwrap().clear();
    let body = paid_body();
    let e = w.billing().webhook(&ContextAuth::default(), &body, Some(&sign(&body))).await.unwrap_err();
    assert_eq!((e.status(), e.message()), (StatusCode::NOT_FOUND, "Invoice with id 900 not found".into()));
    let w = webhook_world(None);
    w.books.b.lock().unwrap().rows.get_mut(CONFIG.table).unwrap().clear();
    w.billing().webhook(&ContextAuth::default(), &body, Some(&sign(&body))).await.unwrap();
    assert_eq!(w.books.one(&INVOICE, INVOICE_ID).unwrap().str("status"), Some("PENDING"));
}

// ---------------------------------------------------------------------------------------------
// InvoiceServiceTest + InvoiceServiceIntegrationTest

fn invoice(id: u64, seller: u64, buyer: u64, app: u64, status: &str) -> Rec {
    Rec::new(&INVOICE)
        .with("id", Val::Id(id))
        .with("sellerClientId", Val::Id(seller))
        .with("clientId", Val::Id(buyer))
        .with("appId", Val::Id(app))
        .with("status", Val::Str(status.into()))
        .with("totalAmount", Val::Dec(d("10.0000")))
}

#[tokio::test]
async fn the_page_ands_seller_app_and_the_callers_filter() {
    let w = world();
    w.books.put(invoice(1, C_CLIENT, M_CLIENT, APP, "PAID"));
    w.books.put(invoice(2, C_CLIENT, M_CLIENT, APP, "PENDING"));
    w.books.put(invoice(3, C_CLIENT, M_CLIENT, 1, "PAID"));
    w.books.put(invoice(4, M_CLIENT, 3, APP, "PAID"));
    let b = w.billing();
    let page = Pageable::of(0, 10, vec![Order::new("id", true)]);
    let paid = Cond::Filter(security::condition::Filter::eq("status", "PAID"));
    let v = b.invoice_page(&system(), &page, Some(paid), Some("crm"), Some("SYSTEM")).await.unwrap().unwrap();
    assert_eq!(v["totalElements"], 1);
    assert_eq!(v["content"][0]["id"], 1);
    let Some(Cond::Complex { and: true, conditions, .. }) = w.books.b.lock().unwrap().last_invoice_cond.clone() else { panic!() };
    assert_eq!(conditions.len(), 3);
    assert_eq!(w.books.b.lock().unwrap().last_party, Some(None));
    let v = b.invoice_page(&system(), &page, None, Some("crm"), Some("SYSTEM")).await.unwrap().unwrap();
    assert_eq!(v["totalElements"], 2);
    let Some(Cond::Complex { conditions, .. }) = w.books.b.lock().unwrap().last_invoice_cond.clone() else { panic!() };
    assert_eq!(conditions.len(), 2);
    // A non-SYSTEM caller only sees invoices it is a party to.
    let v = b.invoice_page(&buyer(), &page, None, Some("crm"), Some("BUS")).await.unwrap().unwrap();
    assert_eq!(v["content"][0]["id"], 4);
    assert_eq!(w.books.b.lock().unwrap().last_party, Some(Some(M_CLIENT)));
    // Unknown app or seller: the empty Mono.
    assert!(b.invoice_page(&system(), &page, None, Some("nope"), Some("SYSTEM")).await.unwrap().is_none());
    assert!(b.invoice_page(&system(), &page, None, Some("crm"), Some("NOPE")).await.unwrap().is_none());
    assert_eq!(b.invoice_page(&system(), &page, None, None, Some("SYSTEM")).await.unwrap_err().to_string(), format!("500 Internal Server Error: {}", security::admin::billing::service::NULL_KEY));
    // The buyer's own purchases.
    let v = b.my_invoices(&buyer(), &page, None, Some("crm")).await.unwrap().unwrap();
    assert_eq!(v["totalElements"], 2);
    assert!(b.my_invoices(&buyer(), &page, None, Some("nope")).await.unwrap().is_none());
}

#[tokio::test]
async fn read_by_id_is_for_the_parties_and_system() {
    let w = world();
    w.books.put(invoice(INVOICE_ID, C_CLIENT, M_CLIENT, APP, "PAID"));
    let b = w.billing();
    assert_eq!(b.invoice_read(&ca(C_CLIENT, "BUS", &[]), INVOICE_ID).await.unwrap()["id"], INVOICE_ID);
    assert_eq!(b.invoice_read(&buyer(), INVOICE_ID).await.unwrap()["id"], INVOICE_ID);
    assert_eq!(b.invoice_read(&system(), INVOICE_ID).await.unwrap()["id"], INVOICE_ID);
    let e = b.invoice_read(&stranger(), INVOICE_ID).await.unwrap_err();
    assert_eq!((e.status(), e.message()), (StatusCode::FORBIDDEN, "Permission/Role the invoice is required to use this operation".into()));
    assert_eq!(b.invoice_read(&system(), 1).await.unwrap_err().status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn document_keys_are_minted_under_the_invoices_own_client() {
    let w = world();
    w.books.put(invoice(INVOICE_ID, C_CLIENT, M_CLIENT, APP, "PAID"));
    let v = w.billing().invoice_documents(&buyer(), INVOICE_ID).await.unwrap().unwrap();
    assert_eq!(v, json!({"invoiceUrl": "api/files/secured/downloadFileByKey/INVKEY", "receiptUrl": "api/files/secured/downloadFileByKey/RCPTKEY"}));
    let mut keys = w.outside.keys.lock().unwrap().clone();
    keys.sort();
    assert_eq!(keys, vec!["BUS/invoices/crm/invoice-900.pdf", "BUS/receipts/crm/receipt-900.pdf"]);
    assert_eq!(w.billing().invoice_documents(&stranger(), INVOICE_ID).await.unwrap_err().status(), StatusCode::FORBIDDEN);
    // An app that is gone: the empty Mono; files down: its error.
    w.books.put(invoice(901, C_CLIENT, M_CLIENT, 99, "PAID"));
    assert!(w.billing().invoice_documents(&system(), 901).await.unwrap().is_none());
    let mut w2 = world();
    w2.outside.fail_files = true;
    w2.books.put(invoice(INVOICE_ID, C_CLIENT, M_CLIENT, APP, "PAID"));
    assert_eq!(w2.billing().invoice_documents(&system(), INVOICE_ID).await.unwrap_err().status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn mark_paid_and_emit_persists_and_raises_invoice_generated() {
    let w = world();
    let inv = invoice(INVOICE_ID, C_CLIENT, M_CLIENT, APP, "PENDING").with("invoiceNumber", Val::Str("INV/2026-27/10/1".into()));
    w.books.put(inv.clone());
    let paid = inv.with("status", Val::Str("PAID".into()));
    let saved = w.billing().mark_paid_and_emit(&system(), &paid).await.unwrap();
    assert_eq!(saved.str("status"), Some("PAID"));
    let e = w.events.events.lock().unwrap()[0].clone();
    assert_eq!((e.event_name.as_str(), e.app_code.as_deref(), e.client_code.as_deref()), ("INVOICE_GENERATED", Some("crm"), Some("BUS")));
    let data: HashMap<String, Value> = e.data.iter().cloned().collect();
    assert_eq!(data["invoiceNumber"], "INV/2026-27/10/1");
    assert_eq!(data.len(), 26);
    // LZT-2003: no paid payment with a webhook yet, so no billing e-mail; no creator, no buyer.
    assert_eq!(data["billingEmail"], "");
    assert_eq!(data["buyerEmail"], "");
    // LZT-2003: the user who started the purchase (CREATED_BY) is named as the buyer, on the
    // generated and the failed event alike; an unknown user leaves it empty.
    for (by, name, want) in [(Some(10), "INVOICE_GENERATED", "owner@example.com"), (Some(15), "INVOICE_PAYMENT_FAILED", ""), (Some(4040), "X", "")] {
        let w3 = world();
        let inv = invoice(INVOICE_ID, C_CLIENT, M_CLIENT, APP, "PAID").with("createdBy", by.map(Val::Id).unwrap_or(Val::Null));
        w3.billing().raise_invoice_event(&system(), &inv, name).await.unwrap();
        let e = w3.events.events.lock().unwrap()[0].clone();
        let data: HashMap<String, Value> = e.data.iter().cloned().collect();
        assert_eq!((e.event_name.as_str(), data["buyerEmail"].as_str()), (name, Some(want)));
    }
    // An events outage fails the call, as in Java.
    let mut w2 = world();
    w2.events = Arc::new(RecordingEvents { fail: true, ..Default::default() });
    w2.books.put(invoice(INVOICE_ID, C_CLIENT, M_CLIENT, APP, "PENDING"));
    assert!(w2.billing().raise_invoice_event(&system(), &invoice(INVOICE_ID, C_CLIENT, M_CLIENT, APP, "PAID"), "X").await.is_err());
    // No app or client: no event.
    w.billing().raise_invoice_event(&system(), &invoice(1, C_CLIENT, M_CLIENT, 99, "PAID"), "X").await.unwrap();
    w.billing().raise_invoice_event(&system(), &invoice(1, C_CLIENT, 99, APP, "PAID"), "X").await.unwrap();
    assert_eq!(w.events.events.lock().unwrap().len(), 1);
}

// ---------------------------------------------------------------------------------------------
// BillingProfileService

#[tokio::test]
async fn the_buyers_own_profile_is_read_and_upserted() {
    let w = world();
    let b = w.billing();
    assert!(b.my_profile(&buyer(), Some("crm")).await.unwrap().is_none());
    assert!(b.my_profile(&buyer(), Some("nope")).await.unwrap().is_none());
    assert!(b.my_profile(&buyer(), None).await.is_err());
    let input = Rec::new(&PROFILE).with("legalName", Val::Str("Acme".into())).with("clientId", Val::Id(STRANGER)).with("city", Val::Str("Pune".into()));
    let created = b.save_my_profile(&buyer(), Some("crm"), &input).await.unwrap().unwrap();
    assert_eq!((created.u64("clientId"), created.u64("appId"), created.str("legalName")), (Some(M_CLIENT), Some(APP), Some("Acme")));
    let update = Rec::new(&PROFILE).with("gstin", Val::Str("29X".into()));
    let saved = b.save_my_profile(&buyer(), Some("crm"), &update).await.unwrap().unwrap();
    assert_eq!((saved.id(), saved.str("legalName"), saved.str("gstin")), (created.id(), None, Some("29X")));
    assert_eq!(w.books.all(&PROFILE).len(), 1);
    assert!(b.save_my_profile(&buyer(), Some("nope"), &update).await.unwrap().is_none());
}

// ---------------------------------------------------------------------------------------------
// AppBillingConfigService / AppBillingBundleService

fn new_config(client: u64) -> Rec {
    Rec::new(&CONFIG).with("clientId", Val::Id(client)).with("appId", Val::Id(APP)).with("status", Val::Str("INACTIVE".into())).with("createdBy", Val::Id(9))
}

#[tokio::test]
async fn configs_are_created_and_changed_by_who_may_manage_them() {
    let w = world();
    w.books.grant(APP, M_CLIENT);
    let b = w.billing();
    // The owner of the app configuring its own client.
    let saved = b.config_create(&buyer(), new_config(M_CLIENT)).await.unwrap().unwrap();
    assert_eq!((saved.u64("clientId"), saved.u64("appId"), saved.u64("createdBy")), (Some(M_CLIENT), Some(APP), None));
    // Without write access to the app, or for a client without it, or one not managed.
    let e = b.config_create(&stranger(), new_config(STRANGER)).await.unwrap_err();
    assert_eq!(e.message(), "Permission/Role write access to the application is required to use this operation");
    let e = b.config_create(&buyer(), new_config(3)).await.unwrap_err();
    assert_eq!(e.message(), "Permission/Role the config's client must have access to the application is required to use this operation");
    w.books.grant(APP, STRANGER);
    let e = b.config_create(&buyer(), new_config(STRANGER)).await.unwrap_err();
    assert_eq!(e.message(), "Permission/Role manage the config's client is required to use this operation");
    let e = b.config_create(&buyer(), Rec::new(&CONFIG)).await.unwrap_err();
    assert_eq!(e.status(), StatusCode::FORBIDDEN);
    // Update copies the editable fields only.
    let id = saved.id().unwrap();
    let put = Rec::new(&CONFIG)
        .with("id", Val::Id(id))
        .with("clientId", Val::Id(1))
        .with("invoiceDay", Val::Int(5))
        .with("suspendMode", Val::Str("AI_ONLY".into()))
        .with("status", Val::Str("INACTIVE".into()));
    let updated = b.config_update(&buyer(), &put).await.unwrap().unwrap();
    assert_eq!((updated.u64("clientId"), updated.int("invoiceDay"), updated.str("suspendMode")), (Some(M_CLIENT), Some(5), Some("AI_ONLY")));
    // The fields must hold together: an invoice day past the 28th, BLOCK_APP without a target.
    let bad = put.clone().with("invoiceDay", Val::Int(29));
    assert_eq!(b.config_update(&buyer(), &bad).await.unwrap_err().status(), StatusCode::BAD_REQUEST);
    let bad = put.clone().with("suspendMode", Val::Str("BLOCK_APP".into()));
    assert_eq!(b.config_update(&buyer(), &bad).await.unwrap_err().status(), StatusCode::BAD_REQUEST);
    assert_eq!(b.config_create(&buyer(), new_config(M_CLIENT).with("invoiceDueDays", Val::Int(-1))).await.unwrap_err().status(), StatusCode::BAD_REQUEST);
    // PATCH: through the declared setters; a stranger cannot even see it.
    let fields: Map<String, Value> = serde_json::from_value(json!({"sellerAddress": "X", "id": 1, "appId": 1})).unwrap();
    let patched = b.config_patch(&buyer(), id, &fields).await.unwrap().unwrap();
    assert_eq!((patched.str("sellerAddress"), patched.u64("appId")), (Some("X"), Some(APP)));
    assert_eq!(patched.map("paymentGatewayConfig").len(), 0);
    assert!(b.config_patch(&stranger(), id, &fields).await.unwrap().is_none());
    let e = b.config_update(&stranger(), &put).await.unwrap_err();
    assert_eq!(e.status(), StatusCode::FORBIDDEN);
    assert_eq!(b.config_update(&buyer(), &Rec::new(&CONFIG).with("id", Val::Id(1234))).await.unwrap_err().status(), StatusCode::NOT_FOUND);
    // Delete.
    assert_eq!(b.config_delete(&stranger(), id).await.unwrap_err().status(), StatusCode::FORBIDDEN);
    assert_eq!(b.config_delete(&buyer(), id).await.unwrap(), 1);
    assert_eq!(b.config_delete(&buyer(), id).await.unwrap_err().status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn config_reads_are_for_own_managed_and_system() {
    let w = world();
    w.books.put(config_rec("18"));
    w.books.put(new_config(M_CLIENT).with("id", Val::Id(60)));
    w.books.put(new_config(STRANGER).with("id", Val::Id(61)).with("status", Val::Str("DELETED".into())));
    let b = w.billing();
    assert!(b.config_read(&system(), CONFIG_ID).await.unwrap().is_some());
    assert!(b.config_read(&buyer(), 60).await.unwrap().is_some());
    // SYSTEM's own config is not the buyer's to see; the parent (an Owner managing BUS) sees BUS's.
    assert!(b.config_read(&buyer(), CONFIG_ID).await.unwrap().is_none());
    assert!(b.config_read(&ca(C_CLIENT, "BUS", &["Authorities.ROLE_Owner"]), 60).await.unwrap().is_some());
    assert!(b.config_read(&stranger(), 60).await.unwrap().is_none());
    assert_eq!(b.config_read(&system(), 999).await.unwrap_err().message(), "AppBillingConfig with id 999 not found");
    let visible: Vec<u64> = b.configs_of_app(&buyer(), APP).await.unwrap().iter().filter_map(Rec::id).collect();
    assert_eq!(visible, vec![60]);
    let all: Vec<u64> = b.configs_of_app(&system(), APP).await.unwrap().iter().filter_map(Rec::id).collect();
    assert_eq!(all, vec![CONFIG_ID, 60]);
    assert_eq!(Billing::config_list_refused().message(), "Permission/Role list billing configs is required to use this operation");
}

#[tokio::test]
async fn bundles_follow_their_configs_managers() {
    let w = world();
    w.books.grant(APP, M_CLIENT);
    w.books.put(new_config(M_CLIENT).with("id", Val::Id(60)));
    let b = w.billing();
    let mk = |order: i64, status: &str| {
        Rec::new(&BUNDLE)
            .with("billingConfigId", Val::Id(60))
            .with("label", Val::Str(format!("B{order}")))
            .with("displayOrder", Val::Int(order))
            .with("status", Val::Str(status.into()))
    };
    let first = b.bundle_create(&buyer(), mk(2, "ACTIVE")).await.unwrap().unwrap();
    b.bundle_create(&buyer(), mk(1, "INACTIVE")).await.unwrap();
    b.bundle_create(&buyer(), mk(3, "DELETED")).await.unwrap();
    assert_eq!(b.bundle_create(&stranger(), mk(4, "ACTIVE")).await.unwrap_err().status(), StatusCode::FORBIDDEN);
    assert_eq!(b.bundle_create(&buyer(), Rec::new(&BUNDLE)).await.unwrap_err().message(), "AppBillingConfig with id null not found");
    let labels: Vec<String> = b.bundles_of_config(60).await.unwrap().iter().map(|r| r.str("label").unwrap().to_string()).collect();
    assert_eq!(labels, ["B1", "B2"]);
    // Serving: the ACTIVE ones of the config governing the URL's client (BUS, or CUST under it).
    for client_code in ["BUS", "CUST"] {
        let s = b.serving_bundles(Some("crm"), Some(client_code)).await.unwrap();
        assert_eq!(s.iter().map(|r| r.str("label").unwrap()).collect::<Vec<_>>(), ["B2"]);
    }
    assert!(b.serving_bundles(Some("crm"), Some("SYSTEM")).await.unwrap().is_empty());
    assert!(b.serving_bundles(Some("nope"), None).await.unwrap().is_empty());
    assert!(b.serving_bundles(Some("crm"), Some("NOPE")).await.unwrap().is_empty());
    assert!(b.serving_bundles(None, Some("BUS")).await.is_err());
    assert!(b.serving_bundles(Some("crm"), None).await.is_err());
    // PUT copies the editable fields; PATCH goes through the setters.
    let id = first.id().unwrap();
    let put = Rec::new(&BUNDLE).with("id", Val::Id(id)).with("label", Val::Str("Renamed".into())).with("billingConfigId", Val::Id(1));
    let updated = b.bundle_update(&buyer(), &put).await.unwrap();
    assert_eq!((updated.str("label"), updated.u64("billingConfigId"), updated.str("status")), (Some("Renamed"), Some(60), Some("ACTIVE")));
    let fields: Map<String, Value> = serde_json::from_value(json!({"price": "12.5", "displayOrder": 9})).unwrap();
    let patched = b.bundle_patch(&buyer(), id, &fields).await.unwrap();
    assert_eq!((patched.dec("price").map(|x| x.to_string()), patched.int("displayOrder")), (Some("12.5".into()), Some(9)));
    let bad: Map<String, Value> = serde_json::from_value(json!({"price": "x"})).unwrap();
    assert_eq!(b.bundle_patch(&buyer(), id, &bad).await.unwrap_err().status(), StatusCode::BAD_REQUEST);
    assert_eq!(b.bundle_update(&stranger(), &put).await.unwrap_err().status(), StatusCode::FORBIDDEN);
    assert_eq!(b.bundle_delete(&stranger(), id).await.unwrap_err().status(), StatusCode::FORBIDDEN);
    assert_eq!(b.bundle_delete(&buyer(), id).await.unwrap(), 1);
    assert_eq!(b.read(&BUNDLE, Some(id)).await.unwrap_err().message(), format!("AppBillingBundle with id {id} not found"));
}

#[tokio::test]
async fn a_row_that_cannot_be_written() {
    let w = world();
    w.books.grant(APP, M_CLIENT);
    w.books.b.lock().unwrap().fail_insert = true;
    assert!(w.billing().config_create(&buyer(), new_config(M_CLIENT)).await.is_err());
}

// ---------------------------------------------------------------------------------------------
// WalletServiceTest (DisplayStatus, Lifecycle) + the owner's credits

fn wallet(balance: &str, status: &str, notified: i64) -> Rec {
    Rec::new(&WALLET)
        .with("id", Val::Id(WALLET_ID))
        .with("clientId", Val::Id(M_CLIENT))
        .with("appId", Val::Id(APP))
        .with("balance", Val::Dec(d(balance)))
        .with("status", Val::Str(status.into()))
        .with("lowBalanceNotified", Val::Int(notified))
        .with("version", Val::Int(0))
}

#[tokio::test]
async fn the_owners_wallet_by_codes() {
    let w = world();
    w.books.put(wallet("250", "ACTIVE", 0));
    let b = w.billing();
    let got = b.wallet_by_codes(&buyer(), Some("crm"), Some("BUS")).await.unwrap().unwrap();
    assert_eq!((got.id(), got.dec("balance").map(|x| x.to_string())), (Some(WALLET_ID), Some("250".into())));
    assert!(b.wallet_by_codes(&system(), Some("crm"), Some("CUST")).await.unwrap().is_none());
    assert!(b.wallet_by_codes(&buyer(), Some("nope"), Some("BUS")).await.unwrap().is_none());
    assert!(b.wallet_by_codes(&buyer(), Some("crm"), Some("NOPE")).await.unwrap().is_none());
    let e = b.wallet_by_codes(&stranger(), Some("crm"), Some("BUS")).await.unwrap_err();
    assert_eq!(e.message(), "Permission/Role this client's wallet is required to use this operation");
}

async fn status_of(w: &World) -> Value {
    w.billing().display_status(&buyer(), Some("crm")).await.unwrap()
}

#[tokio::test]
async fn display_statuses() {
    let w = world();
    assert_eq!(status_of(&w).await, json!({"status": "ACTIVE", "overdue": false}));
    assert_eq!(w.billing().display_status(&buyer(), Some("nope")).await.unwrap(), json!({"status": "ACTIVE"}));
    w.books.put(wallet("50", "SUSPENDED", 0));
    assert_eq!(status_of(&w).await["status"], "SUSPENDED");
    assert!(status_of(&w).await.get("threshold").is_none());
    let w = world();
    w.books.put(wallet("-1", "ACTIVE", 0));
    assert_eq!(status_of(&w).await["status"], "SUSPENDED");
    // The wallet's own threshold wins over the config's.
    let w = world();
    w.books.put(wallet("100", "ACTIVE", 0).with("alertThreshold", Val::Dec(d("500"))));
    w.books.put(config_rec("18").with("lowBalanceThreshold", Val::Dec(d("10"))));
    let s = status_of(&w).await;
    assert_eq!((s["status"].as_str(), security::jackson::pretty(&s["threshold"])), (Some("LOW"), "500".into()));
    // The governing config's suspension mode, for the shell's banner.
    assert_eq!((s["suspendMode"].as_str(), s["overdue"].as_bool()), (Some("AI_AND_BANNER"), Some(false)));
    // The config's threshold, through the hierarchy (BUS's config is SYSTEM's).
    let w = world();
    w.books.put(wallet("100", "ACTIVE", 0));
    w.books.put(config_rec("18").with("lowBalanceThreshold", Val::Dec(d("400"))));
    assert_eq!(status_of(&w).await["status"], "LOW");
    let w = world();
    w.books.put(wallet("1000", "ACTIVE", 0));
    w.books.put(config_rec("18").with("lowBalanceThreshold", Val::Dec(d("400"))));
    assert_eq!(status_of(&w).await["status"], "ACTIVE");
    let w = world();
    w.books.put(wallet("5", "ACTIVE", 0));
    let s = status_of(&w).await;
    assert_eq!((s["status"].as_str(), s.get("threshold")), (Some("ACTIVE"), None));
    assert_eq!(security::jackson::pretty(&s["balance"]), "5");
    // An unpaid monthly invoice past its due date.
    w.books.put(invoice(1, C_CLIENT, M_CLIENT, APP, "OVERDUE"));
    assert_eq!(status_of(&w).await["overdue"], true);
    w.books.put(config_rec("18").with("suspendMode", Val::Str("BLOCK_APP".into())));
    assert_eq!(status_of(&w).await["suspendMode"], "BLOCK_APP");
}

#[tokio::test]
async fn ledger_and_plan_are_the_callers_own() {
    let w = world();
    let b = w.billing();
    let page = Pageable::of(0, 2, vec![Order::new("id", false)]);
    let empty = b.my_transactions(&buyer(), Some("crm"), &page).await.unwrap();
    assert_eq!((empty["totalElements"].as_i64(), empty.get("content")), (Some(0), None));
    assert_eq!(b.plan_usage(&buyer(), Some("crm")).await.unwrap(), json!({}));
    w.books.put(wallet("10", "ACTIVE", 0));
    for i in 1..=3 {
        w.books.put(Rec::new(&TXN).with("id", Val::Id(i)).with("walletId", Val::Id(WALLET_ID)).with("type", Val::Str("DEBIT".into())));
    }
    w.books.put(Rec::new(&TXN).with("id", Val::Id(9)).with("walletId", Val::Id(1)));
    let v = b.my_transactions(&buyer(), Some("crm"), &page).await.unwrap();
    assert_eq!((v["totalElements"].as_i64(), v["content"][0]["id"].as_u64()), (Some(3), Some(3)));
    assert_eq!(b.my_transactions(&buyer(), Some("nope"), &page).await.unwrap()["totalElements"], 0);
    w.books.put(config_rec("18").with("lowBalanceThreshold", Val::Dec(d("100"))));
    w.books.put(meter_rec(CONFIG_ID, "sites", "SITES", "1000", "1").with("displayOrder", Val::Int(1)));
    w.books.put(meter_rec(CONFIG_ID, "leads", "EVENT", "2", "100").with("kind", Val::Str("COUNTER".into())).with("rateUnit", Val::Str("EACH".into())).with("displayOrder", Val::Int(2)));
    w.books.put(meter_rec(CONFIG_ID, "gone", "USERS", "1", "0").with("status", Val::Str("DELETED".into())));
    let starter = plan_rec(CONFIG_ID, "starter", "Starter").with("isDefault", Val::Int(1)).with("meterOverrides", Val::Json(json!({"sites": {"free": 2, "hardCap": true}})));
    let starter = w.books.put(starter);
    w.books.put(plan_rec(CONFIG_ID, "pro", "Pro").with("priceAmount", Val::Dec(d("5000"))));
    w.books.put(wallet_plan_rec(&WalletPlan {
        id: 0,
        wallet_id: WALLET_ID,
        plan_id: starter.id().unwrap(),
        period_start: NaiveDate::from_ymd_opt(2026, 10, 1).unwrap(),
        period_end: NaiveDate::from_ymd_opt(2026, 11, 1).unwrap(),
        status: "ACTIVE".into(),
        auto_renew: true,
        next_plan_id: None,
    })
    .with("id", Val::Null));
    w.books.b.lock().unwrap().app_counts.insert((M_CLIENT, "SITE"), 4);
    let plan = b.plan_usage(&buyer(), Some("crm")).await.unwrap();
    // The old pages' shape: one row a meter, under the plan's terms (numbers as jackson prints them).
    let num = |v: &Value| security::jackson::pretty(v);
    let dim = &plan["dimensions"][0];
    assert_eq!((dim["actionKey"].as_str(), num(&dim["currentUsage"]), num(&dim["freeAllowance"]), num(&dim["tokensPerUnit"])), (Some("crm.sites"), "4".into(), "2".into(), "1000".into()));
    assert_eq!(plan["dimensions"].as_array().unwrap().len(), 2, "a DELETED meter is not shown");
    let m = &plan["meters"];
    assert_eq!((m[0]["meterKey"].as_str(), num(&m[0]["hardCap"]), num(&m[0]["used"])), (Some("sites"), "2".into(), "4".into()));
    assert_eq!((m[1]["meterKey"].as_str(), m[1]["hardCap"].is_null(), num(&m[1]["used"])), (Some("leads"), true, "0".into()));
    assert_eq!((plan["plan"]["code"].as_str(), plan["plan"]["periodEnd"].as_str()), (Some("starter"), Some("2026-11-01")));
    let plans: Vec<(&str, bool)> = plan["plans"].as_array().unwrap().iter().map(|p| (p["code"].as_str().unwrap(), p["current"].as_bool().unwrap())).collect();
    assert_eq!(plans, [("starter", true), ("pro", false)]);
    assert_eq!(plan["plans"][0]["limits"][0]["hardCap"], true);
    // No lots: the empty list is left out, as Jackson's NON_EMPTY does.
    assert_eq!((plan["currency"].as_str(), plan["walletStatus"].as_str(), plan["credits"].as_array().map_or(0, Vec::len)), (Some("INR"), Some("ACTIVE"), 0));
    assert_eq!(b.plan_usage(&buyer(), Some("nope")).await.unwrap(), json!({}));
}

#[tokio::test]
async fn a_new_wallet_starts_at_zero_or_on_the_default_plan() {
    let w = world();
    let made = w.billing().wallet_or_create(&system(), M_CLIENT, APP).await.unwrap().unwrap();
    assert_eq!((made.dec("balance").map(|x| x.to_string()), made.str("status")), (Some("0".into()), Some("ACTIVE")));
    let again = w.billing().wallet_or_create(&system(), M_CLIENT, APP).await.unwrap().unwrap();
    assert_eq!(again.id(), made.id());
    // The governing config's default plan, with its one-time credits.
    let w = world();
    w.books.put(config_rec("18"));
    let free = w.books.put(plan_rec(CONFIG_ID, "free", "Free").with("isDefault", Val::Int(1)).with("includedTokens", Val::Dec(d("25"))).with("includedTokensRecurring", Val::Int(0)));
    let made = w.billing().wallet_or_create(&system(), M_CLIENT, APP).await.unwrap().unwrap();
    assert_eq!(made.dec("balance").map(|x| x.to_string()), Some("25".into()));
    let wp = w.books.all(&WALLET_PLAN).pop().unwrap();
    assert_eq!((wp.u64("walletId"), wp.u64("planId"), wp.str("status")), (made.id(), free.id(), Some("ACTIVE")));
    let lot = w.books.all(&LOT).pop().unwrap();
    assert_eq!((lot.str("source"), lot.ts("expiresAt")), (Some("PLAN"), None));
}

#[tokio::test]
async fn credit_from_payment_reactivates_a_suspended_wallet() {
    let w = world();
    w.books.put(wallet("-5", "SUSPENDED", 1));
    let inv = Rec::new(&INVOICE)
        .with("clientId", Val::Id(M_CLIENT))
        .with("appId", Val::Id(APP))
        .with("tokensPurchased", Val::Dec(d("100")))
        .with("paymentReference", Val::Str("pay_1".into()))
        .with("invoiceNumber", Val::Str("INV/1".into()));
    let r = w.billing().credit_from_payment(&system(), &inv).await.unwrap().unwrap();
    assert!(r.charged);
    assert_eq!(r.balance_after.to_string(), "95");
    // The debt is paid first: only 95 becomes a lot.
    assert_eq!(w.books.all(&LOT).pop().unwrap().dec("tokensLeft").map(|x| x.to_string()), Some("95".into()));
    let after = w.books.one(&WALLET, WALLET_ID).unwrap();
    assert_eq!((after.str("status"), after.int("lowBalanceNotified")), (Some("ACTIVE"), Some(0)));
    // The same payment again: not credited twice.
    let r = w.billing().credit_from_payment(&system(), &inv).await.unwrap().unwrap();
    assert!(!r.charged);
    assert_eq!(r.balance_after.to_string(), "95");
    assert!(w.billing().credit_from_payment(&system(), &Rec::new(&INVOICE)).await.unwrap().is_none());
    // A paid monthly invoice buys no credits.
    let monthly = inv.clone().with("kind", Val::Str("MONTHLY".into())).with("paymentReference", Val::Str("pay_m".into()));
    assert!(w.billing().credit_from_payment(&system(), &monthly).await.unwrap().is_none());
    // Tokens missing: BigDecimal.add(null).
    let none = inv.with("tokensPurchased", Val::Null).with("paymentReference", Val::Str("pay_2".into()));
    assert!(w.billing().credit_from_payment(&system(), &none).await.unwrap_err().to_string().contains("augend"));
}

#[tokio::test]
async fn adjustments_by_a_managing_owner_only() {
    let w = world();
    w.books.put(wallet("10", "SUSPENDED", 0));
    let b = w.billing();
    // BUS's own owner may not adjust BUS's wallet; a stranger does not manage it.
    assert_eq!(b.adjust(&buyer(), WALLET_ID, d("5"), "x").await.unwrap_err().message(), "Permission/Role adjust your own wallet is required to use this operation");
    assert_eq!(b.adjust(&stranger(), WALLET_ID, d("5"), "x").await.unwrap_err().message(), "Permission/Role manage the wallet's client is required to use this operation");
    let parent = ca(C_CLIENT, "BUS", &["Authorities.ROLE_Owner"]);
    assert_eq!(b.adjust(&parent, WALLET_ID, d("5"), "x").await.unwrap_err().message(), "Permission/Role write access to the application is required to use this operation");
    w.books.grant(APP, C_CLIENT);
    let r = b.adjust(&parent, WALLET_ID, d("5"), "goodwill").await.unwrap();
    assert!(r.charged);
    let txn = w.books.all(&TXN).pop().unwrap();
    assert_eq!((txn.str("type"), txn.str("referenceType"), txn.str("reason")), (Some("ADJUST"), Some("ADJUST"), Some("goodwill")));
    assert!(txn.str("idempotencyKey").unwrap().starts_with("adjust:"));
    assert_eq!(w.books.one(&WALLET, WALLET_ID).unwrap().str("status"), Some("ACTIVE"));
    assert_eq!(b.adjust(&parent, 1, d("5"), "x").await.unwrap_err().message(), "Wallet with id 1 not found");
}

#[tokio::test]
async fn admin_credits_and_lookups() {
    let w = world();
    let b = w.billing();
    let one = Some(d("10"));
    // SYSTEM: no checks; the wallet is made when absent.
    assert!(b.lookup_wallet(&system(), Some("crm"), Some("SYSTEM"), Some("BUS")).await.unwrap().is_none());
    let r = b.credit_tokens(&system(), Some("crm"), Some("SYSTEM"), Some("BUS"), one, Some("grant")).await.unwrap().unwrap();
    assert_eq!(r.balance_after.to_string(), "10");
    assert_eq!(b.lookup_wallet(&system(), Some("crm"), Some("SYSTEM"), Some("BUS")).await.unwrap().unwrap().dec("balance").unwrap().to_string(), "10");
    // A grant is a GRANT lot that lasts the default validity (12 months).
    let lot = w.books.all(&LOT).pop().unwrap();
    assert_eq!((lot.str("source"), lot.ts("expiresAt").map(|t| t.date().to_string())), (Some("GRANT"), Some("2027-10-15".into())));
    // Unknown codes, then each of the owner's checks.
    for (app, url, cl, msg) in [
        ("nope", "SYSTEM", "BUS", "the application"),
        ("crm", "NOPE", "BUS", "the URL client"),
        ("crm", "SYSTEM", "NOPE", "the wallet's client"),
    ] {
        let e = b.credit_tokens(&system(), Some(app), Some(url), Some(cl), one, None).await.unwrap_err();
        assert_eq!(e.message(), format!("Permission/Role {msg} is required to use this operation"));
    }
    let owner = buyer();
    let e = b.lookup_wallet(&owner, Some("crm"), Some("BUS"), Some("CUST")).await.unwrap_err();
    assert_eq!(e.message(), "Permission/Role write access to the application is required to use this operation");
    w.books.grant(APP, M_CLIENT);
    let e = b.lookup_wallet(&owner, Some("crm"), Some("SYSTEM"), Some("CUST")).await.unwrap_err();
    assert_eq!(e.message(), "Permission/Role manage the URL client is required to use this operation");
    let e = b.lookup_wallet(&owner, Some("crm"), Some("BUS"), Some("OTHER")).await.unwrap_err();
    assert_eq!(e.message(), "Permission/Role manage the wallet's client is required to use this operation");
    assert!(b.lookup_wallet(&owner, Some("crm"), Some("BUS"), Some("CUST")).await.unwrap().is_none());
    assert!(b.credit_tokens(&owner, None, Some("BUS"), Some("CUST"), one, None).await.is_err());
}

fn meter_rec(config: u64, key: &str, source: &str, rate: &str, free: &str) -> Rec {
    let mut label = key.to_string();
    label[..1].make_ascii_uppercase();
    Rec::new(&METER)
        .with("billingConfigId", Val::Id(config))
        .with("meterKey", Val::Str(key.into()))
        .with("label", Val::Str(label))
        .with("source", Val::Str(source.into()))
        .with("kind", Val::Str("GAUGE".into()))
        .with("rate", Val::Dec(d(rate)))
        .with("rateUnit", Val::Str("MONTH".into()))
        .with("freeQuantity", Val::Dec(d(free)))
        .with("chargeMode", Val::Str("TOKENS".into()))
        .with("refundPolicy", Val::Str("NONE".into()))
        .with("displayOrder", Val::Int(0))
        .with("status", Val::Str("ACTIVE".into()))
}

fn plan_rec(config: u64, code: &str, label: &str) -> Rec {
    Rec::new(&PLAN)
        .with("billingConfigId", Val::Id(config))
        .with("code", Val::Str(code.into()))
        .with("label", Val::Str(label.into()))
        .with("isDefault", Val::Int(0))
        .with("status", Val::Str("ACTIVE".into()))
}

/// The suspected regression: a credit made through `credit_wallet` no longer records who made
/// it. Before the rebuild an owner's adjustment kept the acting user (77) and a paid purchase the
/// purchasing user (the invoice's createdBy) in the ledger's CREATED_BY; `credit_wallet` ignores
/// its `ca` and builds the `Txn` with `created_by: None`.
#[tokio::test]
async fn credits_keep_who_made_them() {
    let w = world();
    w.books.put(wallet("10", "ACTIVE", 0));
    w.books.grant(APP, C_CLIENT);
    let parent = ca(C_CLIENT, "BUS", &["Authorities.ROLE_Owner"]);
    w.billing().adjust(&parent, WALLET_ID, d("5"), "goodwill").await.unwrap();
    assert_eq!(w.books.all(&TXN).pop().unwrap().u64("createdBy"), Some(77));
}

// ---------------------------------------------------------------------------------------------
// Meters, plans, subscribing, AI rates

/// BUS's own config (60) for crm, which BUS may edit.
fn sellers_world() -> World {
    let w = world();
    w.books.grant(APP, M_CLIENT);
    w.books.put(new_config(M_CLIENT).with("id", Val::Id(60)).with("status", Val::Str("ACTIVE".into())));
    w
}

#[tokio::test]
async fn meters_are_managed_by_who_manages_the_config_and_hold_together() {
    let w = sellers_world();
    let b = w.billing();
    let users = meter_rec(60, "users", "USERS", "1000", "5").with("kind", Val::Null).with("chargeMode", Val::Null).with("status", Val::Null);
    let saved = b.meter_create(&buyer(), users).await.unwrap().unwrap();
    // The defaults: the kind follows the source; TOKENS; ACTIVE.
    assert_eq!((saved.str("kind"), saved.str("chargeMode"), saved.str("status")), (Some("GAUGE"), Some("TOKENS"), Some("ACTIVE")));
    let leads = meter_rec(60, "leads.created", "EVENT", "2", "100").with("kind", Val::Null).with("rateUnit", Val::Str("EACH".into()));
    assert_eq!(b.meter_create(&buyer(), leads).await.unwrap().unwrap().str("kind"), Some("COUNTER"));
    // Refused: a stranger; a counted meter not priced by the month; a second AI meter; a second files meter of the client.
    assert_eq!(b.meter_create(&stranger(), meter_rec(60, "x", "USERS", "1", "0")).await.unwrap_err().status(), StatusCode::FORBIDDEN);
    let e = b.meter_create(&buyer(), meter_rec(60, "x", "USERS", "1", "0").with("rateUnit", Val::Str("EACH".into()))).await.unwrap_err();
    assert_eq!((e.status(), e.message()), (StatusCode::BAD_REQUEST, "A counted meter is priced per unit per month (MONTH).".into()));
    let ai = || meter_rec(60, "ai.tokens", "AI_TOKENS", "2", "0").with("kind", Val::Str("COUNTER".into())).with("rateUnit", Val::Str("MARKUP".into()));
    b.meter_create(&buyer(), ai()).await.unwrap();
    assert_eq!(b.meter_create(&buyer(), ai().with("meterKey", Val::Str("ai2".into()))).await.unwrap_err().message(), "A config has one AI meter.");
    w.books.put(new_config(M_CLIENT).with("id", Val::Id(61)).with("appId", Val::Id(1)));
    b.meter_create(&buyer(), meter_rec(60, "files", "FILES_GB", "10", "1")).await.unwrap();
    w.books.grant(1, M_CLIENT);
    let e = b.meter_create(&buyer(), meter_rec(61, "files", "FILES_GB", "10", "1")).await.unwrap_err();
    assert!(e.message().starts_with("Files are counted per client"), "{}", e.message());
    // The list, the update (editable fields only), the soft delete.
    let keys: Vec<String> = b.meters_of(&buyer(), 60).await.unwrap().iter().map(|m| m.str("meterKey").unwrap().to_string()).collect();
    assert_eq!(keys, ["users", "leads.created", "ai.tokens", "files"]);
    assert_eq!(b.meters_of(&stranger(), 60).await.unwrap_err().status(), StatusCode::FORBIDDEN);
    let id = saved.id().unwrap();
    let put = saved.clone().with("rate", Val::Dec(d("1200"))).with("billingConfigId", Val::Id(1));
    let updated = b.meter_update(&buyer(), &put).await.unwrap();
    assert_eq!((updated.dec("rate").map(|x| x.to_string()), updated.u64("billingConfigId")), (Some("1200".into()), Some(60)));
    assert_eq!(b.meter_update(&buyer(), &put.clone().with("kind", Val::Str("COUNTER".into()))).await.unwrap_err().status(), StatusCode::BAD_REQUEST);
    assert_eq!(b.meter_delete(&buyer(), id).await.unwrap(), 1);
    assert_eq!(w.books.one(&METER, id).unwrap().str("status"), Some("DELETED"));
    assert_eq!(b.meters_of(&buyer(), 60).await.unwrap().len(), 3);
}

#[tokio::test]
async fn plans_keep_one_default_per_config() {
    let w = sellers_world();
    let b = w.billing();
    let free = b.plan_create(&buyer(), plan_rec(60, "free", "Free").with("isDefault", Val::Int(1))).await.unwrap().unwrap();
    // The config's currency when none is given.
    assert_eq!(free.str("currency"), Some("INR"));
    let pro = b.plan_create(&buyer(), plan_rec(60, "pro", "Pro").with("isDefault", Val::Int(1))).await.unwrap().unwrap();
    assert_eq!(w.books.one(&PLAN, free.id().unwrap()).unwrap().int("isDefault"), Some(0));
    assert_eq!(w.books.one(&PLAN, pro.id().unwrap()).unwrap().int("isDefault"), Some(1));
    let e = b.plan_create(&buyer(), plan_rec(60, "bad", "Bad").with("meterOverrides", Val::Json(json!({"users": 2})))).await.unwrap_err();
    assert_eq!(e.status(), StatusCode::BAD_REQUEST);
    assert_eq!(b.plan_create(&buyer(), plan_rec(60, " ", "Blank")).await.unwrap_err().status(), StatusCode::BAD_REQUEST);
    assert_eq!(b.plan_create(&stranger(), plan_rec(60, "s", "S")).await.unwrap_err().status(), StatusCode::FORBIDDEN);
    let updated = b.plan_update(&buyer(), &pro.clone().with("priceAmount", Val::Dec(d("4999")))).await.unwrap();
    assert_eq!(updated.dec("priceAmount").map(|x| x.to_string()), Some("4999".into()));
    // Deleting a plan clears its default.
    assert_eq!(b.plan_delete(&buyer(), pro.id().unwrap()).await.unwrap(), 1);
    let gone = w.books.one(&PLAN, pro.id().unwrap()).unwrap();
    assert_eq!((gone.str("status"), gone.int("isDefault")), (Some("DELETED"), Some(0)));
    assert_eq!(b.plans_of(&buyer(), 60).await.unwrap().len(), 1);
}

#[tokio::test]
async fn a_buyer_subscribes_to_a_wallet_plan_it_can_pay_and_cancels_it() {
    let w = world();
    w.books.put(config_rec("18"));
    let pro = w.books.put(plan_rec(CONFIG_ID, "pro", "Pro").with("paymentMode", Val::Str("WALLET".into())).with("priceTokens", Val::Dec(d("100"))));
    let pro_id = pro.id().unwrap();
    let b = w.billing();
    // A new wallet (at zero) cannot pay for it.
    let e = b.subscribe(&buyer(), pro_id).await.unwrap_err();
    assert_eq!((e.status(), e.message()), (StatusCode::BAD_REQUEST, "Not enough credits for this plan: add credits first.".into()));
    assert!(w.books.all(&WALLET_PLAN).is_empty());
    // With credits: paid from the wallet, the period starts today.
    let wallet_id = wallet_of(&w).unwrap().id().unwrap();
    w.books.credit_balance(wallet_id, d("150")).await.unwrap();
    let v = b.subscribe(&buyer(), pro_id).await.unwrap();
    assert_eq!((v["planId"].as_u64(), v["invoice"].is_null()), (Some(pro_id), true));
    let wp = w.books.all(&WALLET_PLAN).pop().unwrap();
    assert_eq!((wp.u64("planId"), wp.date_of("periodStart"), wp.date_of("periodEnd")), (Some(pro_id), NaiveDate::from_ymd_opt(2026, 10, 15), NaiveDate::from_ymd_opt(2026, 11, 15)));
    assert_eq!(wallet_of(&w).unwrap().dec("balance").map(|x| x.to_string()), Some("50".into()));
    let fee = w.books.all(&TXN).pop().unwrap();
    assert_eq!((fee.str("type"), fee.str("idempotencyKey")), (Some("DEBIT"), Some(format!("plan-fee:{pro_id}:{wallet_id}:2026-10-15").as_str())));
    // Again: unchanged, not paid twice.
    assert_eq!(b.subscribe(&buyer(), pro_id).await.unwrap()["unchanged"], true);
    assert_eq!(wallet_of(&w).unwrap().dec("balance").map(|x| x.to_string()), Some("50".into()));
    // Cancelling: no renewal, the period still ends when it ends.
    let v = b.cancel_plan(&buyer(), Some("crm"), None).await.unwrap();
    assert_eq!(v["endsOn"], "2026-11-15");
    assert_eq!(w.books.all(&WALLET_PLAN).pop().unwrap().int("autoRenew"), Some(0));
    // The next plan must be one of the same config's.
    let other = w.books.put(plan_rec(999, "x", "X"));
    assert_eq!(b.cancel_plan(&buyer(), Some("crm"), other.id()).await.unwrap_err().status(), StatusCode::BAD_REQUEST);
    assert_eq!(b.cancel_plan(&stranger(), Some("crm"), None).await.unwrap_err().status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_plan_is_offered_only_to_the_clients_its_config_governs() {
    let w = world();
    w.books.put(config_rec("18"));
    // BUS's own config sells to CUST, not to BUS.
    w.books.put(new_config(M_CLIENT).with("id", Val::Id(60)).with("status", Val::Str("ACTIVE".into())));
    let own = w.books.put(plan_rec(60, "own", "Own").with("paymentMode", Val::Str("WALLET".into())));
    let e = w.billing().subscribe(&buyer(), own.id().unwrap()).await.unwrap_err();
    assert_eq!(e.status(), StatusCode::FORBIDDEN);
    // A plan that is not offered; one that does not exist.
    let off = w.books.put(plan_rec(CONFIG_ID, "off", "Off").with("status", Val::Str("INACTIVE".into())));
    assert_eq!(w.billing().subscribe(&buyer(), off.id().unwrap()).await.unwrap_err().message(), "This plan is not offered.");
    assert_eq!(w.billing().subscribe(&buyer(), 4242).await.unwrap_err().status(), StatusCode::NOT_FOUND);
    // A free WALLET plan of the governing config needs no credits.
    let free = w.books.put(plan_rec(CONFIG_ID, "free", "Free").with("paymentMode", Val::Str("WALLET".into())));
    assert_eq!(w.billing().subscribe(&buyer(), free.id().unwrap()).await.unwrap()["planId"], json!(free.id().unwrap()));
}

#[tokio::test]
async fn ai_rates_and_settings_are_for_system_only() {
    let w = world();
    let b = w.billing();
    let rate = Rec::new(&AI_RATE).with("modelPattern", Val::Str("  DeepSeek ".into())).with("outputPerM", Val::Dec(d("1.2")));
    assert_eq!(b.ai_rate_create(&buyer(), rate.clone()).await.unwrap_err().status(), StatusCode::FORBIDDEN);
    let saved = b.ai_rate_create(&system(), rate).await.unwrap().unwrap();
    assert_eq!(saved.str("modelPattern"), Some("deepseek"));
    assert_eq!(b.ai_rate_create(&system(), Rec::new(&AI_RATE)).await.unwrap_err().status(), StatusCode::BAD_REQUEST);
    let updated = b.ai_rate_update(&system(), &saved.clone().with("modelPattern", Val::Str("DeepSeek-V4".into()))).await.unwrap();
    assert_eq!(updated.str("modelPattern"), Some("deepseek-v4"));
    assert_eq!(b.ai_rates_list(&system()).await.unwrap().len(), 1);
    assert_eq!(b.ai_rates_list(&buyer()).await.unwrap_err().status(), StatusCode::FORBIDDEN);
    assert_eq!(b.ai_rate_delete(&system(), saved.id().unwrap()).await.unwrap(), 1);
    // Settings: read through security-internal's store; an unknown or bad one is refused before any write.
    w.books.b.lock().unwrap().settings.insert("AI_FX_RATE".into(), "90".into());
    assert_eq!(b.settings_read(&system()).await.unwrap(), json!({"AI_FX_RATE": "90"}));
    assert_eq!(b.settings_read(&buyer()).await.unwrap_err().status(), StatusCode::FORBIDDEN);
    assert_eq!(b.setting_write(&system(), "NOPE", "1").await.unwrap_err().message(), "Unknown billing setting.");
    assert_eq!(b.setting_write(&system(), "AI_FX_RATE", "-1").await.unwrap_err().message(), "The value is a positive number.");
}

// ---------------------------------------------------------------------------------------------
// The real outside calls against an in-process stand-in for files and Razorpay

#[tokio::test]
async fn live_calls_against_an_in_process_files_and_razorpay() {
    use axum::extract::Query;
    use axum::http::HeaderMap;
    use axum::routing::{get, post};
    use security::admin::billing::service::Live;

    async fn create_key(Query(q): Query<HashMap<String, String>>) -> (StatusCode, String) {
        match q.get("filePath").map(String::as_str) {
            Some("BAD") => (StatusCode::BAD_REQUEST, "nope".into()),
            Some(p) => (StatusCode::OK, format!("api/files/secured/downloadFileByKey/{}", p.len())),
            None => (StatusCode::BAD_REQUEST, String::new()),
        }
    }
    async fn orders(headers: HeaderMap, body: axum::Json<Value>) -> (StatusCode, axum::Json<Value>) {
        // Basic base64("rzp_test_key:s").
        let auth = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("");
        if auth != "Basic cnpwX3Rlc3Rfa2V5OnM=" {
            return (StatusCode::UNAUTHORIZED, axum::Json(json!({"error": "auth"})));
        }
        (StatusCode::OK, axum::Json(json!({"id": "order_fake", "amount": body.0["amount"].clone()})))
    }
    let app = axum::Router::new()
        .route("/api/files/internal/secured/createKey", get(create_key))
        .route("/orders", post(orders))
        .route("/payment_links", post(|| async { (StatusCode::BAD_GATEWAY, "down") }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let live = Live { files: Some(platform::upstream::Upstream::fixed(&[base.as_str()])), razorpay_base: base.clone() };
    assert_eq!(live.secured_key("A/invoices/x.pdf").await.unwrap(), "api/files/secured/downloadFileByKey/16");
    let e = live.secured_key("BAD").await.unwrap_err();
    assert!(e.to_string().contains("[400 Bad Request] during [GET]"));
    let r = live.razorpay("/orders", "rzp_test_key", "s", &json!({"amount": 100})).await.unwrap();
    assert_eq!(r, json!({"id": "order_fake", "amount": 100}));
    let e = live.razorpay("/orders", "rzp_test_key", "wrong", &json!({})).await.unwrap_err();
    assert_eq!(e.to_string(), format!("500 Internal Server Error: 401 Unauthorized from POST {base}/orders"));
    let e = live.razorpay("/payment_links", "k", "s", &json!({})).await.unwrap_err();
    assert!(e.to_string().contains("502 Bad Gateway from POST"));
    // The app URL goes to the schema (here a pool that cannot connect).
    let w = world();
    let app = security::model::App { id: APP, client_id: M_CLIENT, app_code: "crm".into(), ..Default::default() };
    assert!(live.app_url(&w.internal, &system(), &app, M_CLIENT).await.is_err());
}
