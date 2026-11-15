//! The daily billing run (`internal/billing/reconcile`, 00:45 from the platform schedule), in
//! order, each step on its own (a failing step is logged and the next one runs):
//!
//! 1. security's gauges: every window of the day not charged yet;
//! 2. credit lots past their expiry written off (`WALLET_CREDITS_EXPIRED`), and a warning for
//!    lots expiring in seven days (`WALLET_CREDITS_EXPIRING`);
//! 3. plan periods that ended: renewed (a WALLET plan debits its price, or lapses to the default
//!    plan when the wallet cannot pay: `WALLET_PLAN_LAPSED`), moved to the next plan, or ended;
//!    an INVOICE plan raises its invoice: the new period's fee and the ended period's usage;
//! 4. on a config's invoice day: the usage of clients not on an invoiced plan;
//! 5. PENDING monthly invoices past their due date marked OVERDUE (`INVOICE_OVERDUE`).
//!
//! A monthly invoice is never raised twice: its period key (client, app, period end) is unique.

use chrono::{Duration, NaiveDate, NaiveDateTime};
use serde_json::Value;

use super::billing::{days_in_month, period_end, SCALE};
use super::Internal;
use crate::admin::billing::money::divide_half_up;
use crate::admin::billing::purchase::{fin_year, format_address};
use crate::data::billing::{terms, BillingConfig, Lot, Meter, NewLot, Plan, Txn, Wallet, WalletPlan};
use crate::data::billing_admin::{Rec, Val, INVOICE, INVOICE_LINE};
use crate::decimal::Dec;
use crate::errors::AuthResult;
use crate::model::ContextAuth;

pub const WALLET_CREDITS_EXPIRED: &str = "WALLET_CREDITS_EXPIRED";
pub const WALLET_CREDITS_EXPIRING: &str = "WALLET_CREDITS_EXPIRING";
pub const WALLET_PLAN_LAPSED: &str = "WALLET_PLAN_LAPSED";
pub const INVOICE_ISSUED: &str = "INVOICE_ISSUED";
pub const INVOICE_OVERDUE: &str = "INVOICE_OVERDUE";

/// One line of a monthly invoice before it is saved.
#[derive(Debug, Clone, PartialEq)]
pub struct Line {
    pub kind: &'static str,
    pub meter_id: Option<u64>,
    pub plan_id: Option<u64>,
    pub description: String,
    pub period_start: NaiveDate,
    pub period_end: NaiveDate,
    pub quantity: Dec,
    pub free: Dec,
    pub rate: Dec,
    pub amount: Dec,
    pub order: i64,
}

/// A counter's invoice line amount: what is above the free quantity, at the rate unit. An AI
/// meter on the invoice holds priced amounts already (MARKUP), so its rate is one.
pub fn counter_amount(net_units: Dec, free: Dec, rate: Dec, rate_unit: &str) -> (Dec, Dec) {
    let billable = net_units.sub(free).max(Dec::ZERO);
    match rate_unit {
        "MARKUP" => (Dec::ONE, billable.round_down(2)),
        "PER_MILLION" => (rate, divide_half_up(billable.mul(rate), 1_000_000, 2)),
        _ => (rate, divide_half_up(billable.mul(rate), 1, 2)),
    }
}

/// The base, GST and total of an invoice's lines.
pub fn totals(lines: &[Line], gst_percentage: Dec) -> (Dec, Dec, Dec) {
    let base = lines.iter().fold(Dec::ZERO, |a, l| a.add(l.amount));
    let gst = divide_half_up(base.mul(gst_percentage), 100, 2);
    (base, gst, base.add(gst))
}

fn date_text(d: NaiveDate) -> String {
    d.format("%d %b %Y").to_string()
}

impl Internal {
    /// The daily run for the day just ended (`date`), as of now.
    pub async fn reconcile_day(&self, ca: &ContextAuth, date: NaiveDate) -> AuthResult<()> {
        if let Err(e) = self.reconcile_gauges(ca, date).await {
            tracing::error!(error = %e, "billing: gauge reconcile failed");
        }
        let now = self.auth.clock.local();
        if let Err(e) = self.expire_lots(ca, now).await {
            tracing::error!(error = %e, "billing: credit expiry failed");
        }
        if let Err(e) = self.warn_expiring(ca, now).await {
            tracing::error!(error = %e, "billing: expiry warnings failed");
        }
        if let Err(e) = self.renew_plans(ca, now.date()).await {
            tracing::error!(error = %e, "billing: plan renewal failed");
        }
        if let Err(e) = self.invoice_day(ca, now.date()).await {
            tracing::error!(error = %e, "billing: monthly invoices failed");
        }
        if let Err(e) = self.mark_overdue(ca, now.date()).await {
            tracing::error!(error = %e, "billing: overdue pass failed");
        }
        Ok(())
    }

    /// Writes off what is left of every lot past its expiry.
    pub async fn expire_lots(&self, ca: &ContextAuth, now: NaiveDateTime) -> AuthResult<()> {
        for lot in self.billing.expired_lots(now).await? {
            let Some(wallet) = self.billing.wallet_by_id(lot.wallet_id).await? else { continue };
            let txn = Txn {
                wallet_id: wallet.id,
                kind: "EXPIRE",
                tokens: lot.tokens_left,
                balance_after: wallet.balance.sub(lot.tokens_left),
                app_id: Some(wallet.app_id),
                idempotency_key: format!("expire:{}", lot.id),
                reference_type: Some("LOT".into()),
                reference_id: Some(lot.id),
                reason: format!("{} credits expired", lot.source.to_lowercase()),
                ..Default::default()
            };
            if self.billing.expire_lot(&lot, &txn).await? {
                let extra = vec![
                    ("expiredTokens", Value::from(lot.tokens_left.to_string())),
                    ("balance", Value::from(txn.balance_after.to_string())),
                ];
                if let Err(e) = self.raise_billing_event(ca, WALLET_CREDITS_EXPIRED, wallet.client_id, wallet.app_id, Some(wallet.id), extra).await {
                    tracing::error!(error = %e, wallet = wallet.id, "credits expired event not raised");
                }
            }
        }
        Ok(())
    }

    /// One warning per wallet for its credits expiring in seven days (the run is daily, so each lot
    /// is warned once).
    pub async fn warn_expiring(&self, ca: &ContextAuth, now: NaiveDateTime) -> AuthResult<()> {
        let lots = self.billing.lots_expiring(now + Duration::days(6), now + Duration::days(7)).await?;
        let mut by_wallet: Vec<(u64, Vec<Lot>)> = Vec::new();
        for l in lots {
            match by_wallet.iter_mut().find(|(w, _)| *w == l.wallet_id) {
                Some((_, v)) => v.push(l),
                None => by_wallet.push((l.wallet_id, vec![l])),
            }
        }
        for (wallet_id, lots) in by_wallet {
            let Some(wallet) = self.billing.wallet_by_id(wallet_id).await? else { continue };
            let tokens = lots.iter().fold(Dec::ZERO, |a, l| a.add(l.tokens_left));
            let on = lots.iter().filter_map(|l| l.expires_at).min().map(|t| t.date().to_string()).unwrap_or_default();
            let extra = vec![("expiringTokens", Value::from(tokens.to_string())), ("expiresOn", Value::from(on))];
            if let Err(e) = self.raise_billing_event(ca, WALLET_CREDITS_EXPIRING, wallet.client_id, wallet.app_id, Some(wallet.id), extra).await {
                tracing::error!(error = %e, wallet = wallet.id, "credits expiring event not raised");
            }
        }
        Ok(())
    }

    /// Every plan period that ended by today.
    pub async fn renew_plans(&self, ca: &ContextAuth, today: NaiveDate) -> AuthResult<()> {
        for wp in self.billing.wallet_plans_due(today).await? {
            if let Err(e) = self.renew_one(ca, &wp).await {
                tracing::error!(error = %e, wallet_plan = wp.id, "plan renewal failed");
            }
        }
        Ok(())
    }

    async fn renew_one(&self, ca: &ContextAuth, wp: &WalletPlan) -> AuthResult<()> {
        let Some(wallet) = self.billing.wallet_by_id(wp.wallet_id).await? else { return Ok(()) };
        let Some(current) = self.billing.plan_by_id(wp.plan_id).await? else { return Ok(()) };
        let Some(config) = self.billing.config_by_id(current.config_id).await? else { return Ok(()) };
        let default = self.billing.plans_of_config(config.id).await?.into_iter().find(|p| p.is_default && p.status == "ACTIVE");
        // What comes next: a chosen next plan, the same plan, or (not renewing) the default.
        let next = match wp.next_plan_id {
            Some(id) => self.billing.plan_by_id(id).await?,
            None if wp.auto_renew && current.status == "ACTIVE" => Some(current.clone()),
            None => default.clone(),
        };
        let start = wp.period_end;
        let Some(next) = next.filter(|p| p.status == "ACTIVE") else {
            self.billing.set_wallet_plan(&WalletPlan { status: "ENDED".into(), ..wp.clone() }).await?;
            return Ok(());
        };
        if !next.invoiced() && next.price_tokens.signum() > 0 {
            let paid = self.pay_plan_from_wallet(ca, &wallet, &config, &next, start).await?;
            if !paid {
                self.billing.set_wallet_plan(&WalletPlan { status: "LAPSED".into(), ..wp.clone() }).await?;
                let extra = vec![("planLabel", Value::from(next.label.clone())), ("price", Value::from(next.price_tokens.to_string()))];
                if let Err(e) = self.raise_billing_event(ca, WALLET_PLAN_LAPSED, wallet.client_id, wallet.app_id, Some(wallet.id), extra).await {
                    tracing::error!(error = %e, wallet = wallet.id, "plan lapsed event not raised");
                }
                if let Some(d) = default.filter(|d| d.id != next.id) {
                    self.put_on_plan(ca, &wallet, &config, &d, start, true).await?;
                }
                return Ok(());
            }
        }
        self.put_on_plan(ca, &wallet, &config, &next, start, true).await?;
        if next.invoiced() {
            self.raise_monthly_invoice(ca, &config, wallet.client_id, Some(&next), Some(start), start).await?;
        }
        Ok(())
    }

    /// A WALLET plan's price for the period starting on `start`, debited once; false when the
    /// balance cannot cover it.
    pub async fn pay_plan_from_wallet(&self, ca: &ContextAuth, wallet: &Wallet, config: &BillingConfig, plan: &Plan, start: NaiveDate) -> AuthResult<bool> {
        let fresh = self.billing.wallet_by_id(wallet.id).await?.unwrap_or_else(|| wallet.clone());
        if fresh.balance.cmp_value(&plan.price_tokens) == std::cmp::Ordering::Less {
            return Ok(false);
        }
        let app = self.dir().app_by_id(wallet.app_id).await?;
        let txn = Txn {
            wallet_id: wallet.id,
            kind: "DEBIT",
            tokens: plan.price_tokens,
            balance_after: fresh.balance.sub(plan.price_tokens),
            action_key: Some(format!("{}.plan", app.app_code)),
            app_id: Some(wallet.app_id),
            quantity: Some(Dec::ONE),
            charge_date: Some(start),
            idempotency_key: format!("plan-fee:{}:{}:{start}", plan.id, wallet.id),
            reference_type: Some("PLAN".into()),
            reference_id: Some(plan.id),
            reason: format!("{} plan from {start}", plan.label),
            ..Default::default()
        };
        let _ = config;
        let _ = ca;
        self.billing.debit(&txn).await
    }

    /// On each config's invoice day: the usage of clients that are not on an invoiced plan (those
    /// are invoiced when their period ends).
    pub async fn invoice_day(&self, ca: &ContextAuth, today: NaiveDate) -> AuthResult<()> {
        for config in self.billing.active_configs().await? {
            let day = config.invoice_day.clamp(1, days_in_month(today));
            if chrono::Datelike::day(&today) != day {
                continue;
            }
            for client_id in self.billing.clients_with_usage(config.id, today).await? {
                let on_invoiced_plan = match self.billing.wallet(client_id, config.app_id).await? {
                    Some(w) => self.plan_of(&w).await?.is_some_and(|p| p.invoiced()),
                    None => false,
                };
                if on_invoiced_plan {
                    continue;
                }
                if let Err(e) = self.raise_monthly_invoice(ca, &config, client_id, None, None, today).await {
                    tracing::error!(error = %e, client = client_id, config = config.id, "monthly invoice failed");
                }
            }
        }
        Ok(())
    }

    /// The lines of an invoice for a client: the plan's fee for the period starting on
    /// `plan_start` (when given), and every INVOICE meter's usage not invoiced yet, up to `usage_to`.
    pub async fn invoice_lines(&self, config: &BillingConfig, client_id: u64, plan: Option<&Plan>, plan_start: Option<NaiveDate>, usage_to: NaiveDate) -> AuthResult<Vec<Line>> {
        let mut lines = Vec::new();
        if let (Some(p), Some(start)) = (plan, plan_start) {
            if p.invoiced() && p.price_amount.signum() > 0 {
                let end = period_end(start, &p.period);
                lines.push(Line {
                    kind: "PLAN",
                    meter_id: None,
                    plan_id: Some(p.id),
                    description: format!("{} plan, {} to {}", p.label, date_text(start), date_text(end - Duration::days(1))),
                    period_start: start,
                    period_end: end,
                    quantity: Dec::ONE,
                    free: Dec::ZERO,
                    rate: p.price_amount,
                    amount: p.price_amount,
                    order: 0,
                });
            }
        }
        // A free default plan is never invoiced for usage: past its caps the actions are refused.
        if plan.is_some_and(|p| p.is_default && p.price_amount.signum() == 0 && p.price_tokens.signum() == 0) {
            return Ok(lines);
        }
        let Some(from) = self.billing.earliest_unbilled(client_id, config.app_id).await? else { return Ok(lines) };
        if from >= usage_to {
            return Ok(lines);
        }
        let meters: Vec<Meter> = self.billing.meters_of_config(config.id).await?.into_iter().filter(|m| m.invoiced()).collect();
        for m in meters {
            let t = terms(&m, plan);
            if t.hard_cap.is_some() {
                continue;
            }
            let unit = m.unit_label.clone().unwrap_or_else(|| m.label.to_lowercase());
            let period = format!("{} to {}", date_text(from), date_text(usage_to - Duration::days(1)));
            if m.is_gauge() {
                let month_units = self.billing.gauge_month_units(m.id, client_id, from, usage_to, t.free).await?;
                if month_units.signum() <= 0 || t.rate.signum() <= 0 {
                    continue;
                }
                lines.push(Line {
                    kind: "METER",
                    meter_id: Some(m.id),
                    plan_id: None,
                    description: format!("{} above {} free ({unit} months), {period}", m.label, t.free),
                    period_start: from,
                    period_end: usage_to,
                    quantity: month_units,
                    free: t.free,
                    rate: t.rate,
                    amount: divide_half_up(month_units.mul(t.rate), 1, 2),
                    order: m.display_order + 1,
                });
            } else {
                let u = self.billing.period_usage(m.id, client_id, from, usage_to).await?;
                let net = u.events.sub(u.reversals).max(Dec::ZERO);
                let (rate, amount) = counter_amount(net, t.free, t.rate, &m.rate_unit);
                if amount.signum() <= 0 {
                    continue;
                }
                lines.push(Line {
                    kind: "METER",
                    meter_id: Some(m.id),
                    plan_id: None,
                    description: format!("{} ({unit}), {period}", m.label),
                    period_start: from,
                    period_end: usage_to,
                    quantity: net,
                    free: t.free,
                    rate,
                    amount,
                    order: m.display_order + 1,
                });
            }
        }
        Ok(lines)
    }

    /// Raises (once) the monthly invoice of a client: the lines, GST, seller and buyer snapshots,
    /// the due date; marks the usage invoiced and publishes `INVOICE_ISSUED`. Nothing for a zero
    /// total. The invoice is paid through `billing/repay` (a Checkout order).
    pub async fn raise_monthly_invoice(&self, ca: &ContextAuth, config: &BillingConfig, client_id: u64, plan: Option<&Plan>, plan_start: Option<NaiveDate>, usage_to: NaiveDate) -> AuthResult<Option<Rec>> {
        let lines = self.invoice_lines(config, client_id, plan, plan_start, usage_to).await?;
        let (base, gst, total) = totals(&lines, config.gst_percentage);
        if total.signum() <= 0 {
            return Ok(None);
        }
        let today = self.auth.clock.local().date();
        let from = lines.iter().map(|l| l.period_start).min().unwrap_or(usage_to);
        let to = lines.iter().map(|l| l.period_end).max().unwrap_or(usage_to);
        let buyer = self.dir().client(client_id).await?;
        let profile = self.billing.buyer_profile(client_id, config.app_id).await?;
        let buyer_name = profile
            .as_ref()
            .and_then(|p| p.str("legalName"))
            .filter(|n| !n.trim().is_empty())
            .map(str::to_string)
            .or_else(|| buyer.as_ref().and_then(|b| b.name.clone()));
        let s = |v: Option<String>| v.map(Val::Str).unwrap_or(Val::Null);
        let usage_key = format!("{client_id}:{}:{}:{}", config.app_id, plan_start.map(|d| d.to_string()).unwrap_or_default(), usage_to);
        let invoice = Rec::new(&INVOICE)
            .with("invoiceNumber", Val::Str(String::new()))
            .with("invoiceDate", Val::Ts(self.auth.clock.utc()))
            .with("status", Val::Str("PENDING".into()))
            .with("kind", Val::Str("MONTHLY".into()))
            .with("periodStart", Val::Date(from))
            .with("periodEnd", Val::Date(to))
            .with("dueDate", Val::Date(today + Duration::days(i64::from(config.invoice_due_days))))
            .with("periodKey", Val::Str(usage_key))
            .with("sellerClientId", Val::Id(config.client_id))
            .with("sellerLegalName", s(self.config_text(config, "sellerLegalName").await?))
            .with("sellerGstin", s(self.config_text(config, "sellerGstin").await?))
            .with("sellerAddress", s(self.config_text(config, "sellerAddress").await?))
            .with("clientId", Val::Id(client_id))
            .with("buyerLegalName", s(buyer_name))
            .with("buyerGstin", s(profile.as_ref().and_then(|p| p.str("gstin")).map(str::to_string)))
            .with("buyerAddress", s(profile.as_ref().and_then(format_address)))
            .with("appId", Val::Id(config.app_id))
            .with("bundleLabel", s(plan.map(|p| format!("{} plan", p.label))))
            .with("baseAmount", Val::Dec(base))
            .with("gstPercentage", Val::Dec(config.gst_percentage))
            .with("gstAmount", Val::Dec(gst))
            .with("totalAmount", Val::Dec(total))
            .with("currency", Val::Str(config.currency.clone()))
            .with("gateway", Val::Str("RAZORPAY".into()));
        let recs: Vec<Rec> = lines
            .iter()
            .map(|l| {
                Rec::new(&INVOICE_LINE)
                    .with("kind", Val::Str(l.kind.into()))
                    .with("meterId", l.meter_id.map(Val::Id).unwrap_or(Val::Null))
                    .with("planId", l.plan_id.map(Val::Id).unwrap_or(Val::Null))
                    .with("description", Val::Str(l.description.clone()))
                    .with("periodStart", Val::Date(l.period_start))
                    .with("periodEnd", Val::Date(l.period_end))
                    .with("quantity", Val::Dec(l.quantity.round_down(SCALE)))
                    .with("freeQuantity", Val::Dec(l.free))
                    .with("rate", Val::Dec(l.rate))
                    .with("amount", Val::Dec(l.amount))
                    .with("displayOrder", Val::Int(l.order))
            })
            .collect();
        let Some(saved) = self.billing.insert_monthly_invoice(&invoice, &recs, &fin_year(today)).await? else { return Ok(None) };
        let meter_lines = lines.iter().filter(|l| l.kind == "METER").count();
        if meter_lines > 0 {
            if let Some(id) = saved.id() {
                self.billing.mark_invoiced(client_id, config.app_id, from.min(usage_to), usage_to, id).await?;
            }
        }
        self.raise_invoice_notice(ca, INVOICE_ISSUED, &saved).await;
        Ok(Some(saved))
    }

    /// A seller field of the config (kept on the admin row, not the rule row).
    async fn config_text(&self, config: &BillingConfig, prop: &str) -> AuthResult<Option<String>> {
        use crate::data::billing_admin::AdminBillingStore;
        let row = self.db.by_id(&crate::data::billing_admin::CONFIG, config.id).await?;
        Ok(row.and_then(|r| r.str(prop).map(str::to_string)))
    }

    /// An invoice event (issued, overdue), best effort.
    pub async fn raise_invoice_notice(&self, ca: &ContextAuth, name: &str, inv: &Rec) {
        let (Some(client), Some(app)) = (inv.u64("clientId"), inv.u64("appId")) else { return };
        let num = |p: &str| inv.dec(p).map(|d| Value::from(d.to_string())).unwrap_or(Value::Null);
        let text = |p: &str| inv.str(p).map(Value::from).unwrap_or(Value::Null);
        let date = |p: &str| inv.date_of(p).map(|d| Value::from(d.to_string())).unwrap_or(Value::Null);
        let extra = vec![
            ("invoiceId", inv.id().map(Value::from).unwrap_or(Value::Null)),
            ("invoiceNumber", text("invoiceNumber")),
            ("periodStart", date("periodStart")),
            ("periodEnd", date("periodEnd")),
            ("dueDate", date("dueDate")),
            ("baseAmount", num("baseAmount")),
            ("gstAmount", num("gstAmount")),
            ("totalAmount", num("totalAmount")),
            ("currency", text("currency")),
        ];
        if let Err(e) = self.raise_billing_event(ca, name, client, app, None, extra).await {
            tracing::error!(error = %e, event = name, invoice = ?inv.id(), "invoice event not raised");
        }
    }

    /// PENDING monthly invoices past their due date become OVERDUE.
    pub async fn mark_overdue(&self, ca: &ContextAuth, today: NaiveDate) -> AuthResult<()> {
        for inv in self.billing.invoices_past_due(today).await? {
            let Some(id) = inv.id() else { continue };
            if self.billing.set_invoice_status(id, "OVERDUE").await? > 0 {
                let mut inv = inv;
                inv.set("status", Val::Str("OVERDUE".into()));
                self.raise_invoice_notice(ca, INVOICE_OVERDUE, &inv).await;
            }
        }
        Ok(())
    }

    /// The new lot's expiry for a bought credit (the config's validity from now).
    pub fn bought_credit_lot(&self, config: &BillingConfig, invoice_id: Option<u64>) -> NewLot {
        NewLot {
            source: "PURCHASE",
            reference_type: Some("INVOICE".into()),
            reference_id: invoice_id,
            expires_at: self.purchase_expiry(config, self.auth.clock.local()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> Dec {
        Dec::parse(s).unwrap()
    }

    fn line(amount: &str) -> Line {
        let day = NaiveDate::from_ymd_opt(2026, 11, 1).unwrap();
        Line {
            kind: "METER",
            meter_id: None,
            plan_id: None,
            description: String::new(),
            period_start: day,
            period_end: day,
            quantity: Dec::ONE,
            free: Dec::ZERO,
            rate: Dec::ONE,
            amount: d(amount),
            order: 0,
        }
    }

    #[test]
    fn invoice_totals_add_gst_on_the_lines() {
        let (base, gst, total) = totals(&[line("40000"), line("2500.50")], d("18"));
        assert_eq!((base.to_string(), gst.to_string(), total.to_string()), ("42500.50".into(), "7650.09".into(), "50150.59".into()));
        assert_eq!(totals(&[], d("18")).2.signum(), 0);
    }

    #[test]
    fn counter_lines() {
        // 150 leads, 100 free, 2 each: 100.00.
        assert_eq!(counter_amount(d("150"), d("100"), d("2"), "EACH"), (d("2"), d("100.00")));
        assert_eq!(counter_amount(d("50"), d("100"), d("2"), "EACH").1.signum(), 0);
        // AI on the invoice: the events hold priced amounts already.
        assert_eq!(counter_amount(d("1234.5678"), d("1000"), d("2"), "MARKUP"), (Dec::ONE, d("234.56")));
        assert_eq!(counter_amount(d("3000000"), d("1000000"), d("100"), "PER_MILLION").1, d("200.00"));
    }
}
