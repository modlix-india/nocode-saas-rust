//! What a config charges for and sells: its meters and plans (managed like its bundles, by a
//! caller that manages the config's client), a buyer subscribing to or leaving a plan, and the
//! platform's AI model rates and billing settings (SYSTEM only).

use axum::http::StatusCode;
use serde_json::{Map, Value};

use super::configs::copy;
use super::service::{forbidden, params_not_found, Billing};
use crate::data::billing_admin::{Find, Rec, Val, AI_RATE, CONFIG, METER, PLAN};
use crate::decimal::Dec;
use crate::errors::{AuthError, AuthResult};
use crate::jackson::Obj;
use crate::model::ContextAuth;

/// What a meter update copies from the request.
pub const METER_EDITABLE: [&str; 15] = [
    "meterKey",
    "label",
    "unitLabel",
    "kind",
    "source",
    "sourceConfig",
    "rate",
    "rateUnit",
    "freeQuantity",
    "chargeMode",
    "basis",
    "refundPolicy",
    "refundDays",
    "displayOrder",
    "status",
];

/// What a plan update copies from the request.
pub const PLAN_EDITABLE: [&str; 14] = [
    "code",
    "label",
    "description",
    "period",
    "paymentMode",
    "priceTokens",
    "priceAmount",
    "currency",
    "includedTokens",
    "includedTokensRecurring",
    "meterOverrides",
    "aiModelsAllowed",
    "isDefault",
    "status",
];

/// What an AI rate update copies from the request.
pub const AI_RATE_EDITABLE: [&str; 8] = ["modelPattern", "provider", "inputPerM", "outputPerM", "cacheReadPerM", "cacheWritePerM", "currency", "status"];

/// The platform settings SYSTEM may set.
pub const SETTINGS: [&str; 1] = [crate::internal::billing::AI_FX_RATE];

fn invalid(what: &str) -> AuthError {
    AuthError::literal(StatusCode::BAD_REQUEST, "SEC.BILLING_INVALID", what.to_string()).with_param("reason", what)
}

/// The sources counted on a schedule; the rest are recorded when they happen.
fn gauge_source(source: &str) -> bool {
    matches!(source, "USERS" | "APPS" | "SITES" | "STORAGE_ROWS" | "STORAGE_COUNT" | "FILES_GB")
}

/// A meter's fields hold together (the kind follows the source; value-based charges are not
/// built yet).
pub fn check_meter(m: &Rec) -> AuthResult<()> {
    let key = m.str("meterKey").unwrap_or("").trim();
    if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')) {
        return Err(invalid("A meter key is letters, digits, dot, dash or underscore (for example users, leads.created)."));
    }
    if m.str("label").is_none_or(|l| l.trim().is_empty()) {
        return Err(invalid("A meter needs a label."));
    }
    let source = m.str("source").unwrap_or("");
    let kind = m.str("kind").unwrap_or("");
    if gauge_source(source) != (kind == "GAUGE") {
        return Err(invalid("Users, apps, sites, storage and files are counted on a schedule (GAUGE); AI and app events are recorded when they happen (COUNTER)."));
    }
    let unit = m.str("rateUnit").unwrap_or("MONTH");
    if unit == "PERCENT" || m.dec("minCharge").is_some() || m.dec("maxCharge").is_some() {
        return Err(invalid("Charging a percentage of a value is planned but not built yet."));
    }
    if kind == "GAUGE" && unit != "MONTH" {
        return Err(invalid("A counted meter is priced per unit per month (MONTH)."));
    }
    if source == "AI_TOKENS" && !matches!(unit, "MARKUP" | "PER_MILLION") {
        return Err(invalid("AI is priced as a markup on what the model cost (MARKUP), or per million tokens."));
    }
    if source != "AI_TOKENS" && unit == "MARKUP" {
        return Err(invalid("Only AI is priced as a markup on cost."));
    }
    if source == "STORAGE_COUNT" && m.map("sourceConfig").get("storageName").and_then(Value::as_str).is_none_or(|s| s.trim().is_empty()) {
        return Err(invalid("A storage count needs sourceConfig.storageName (and an optional filter)."));
    }
    if m.dec("rate").is_some_and(|r| r.signum() < 0) || m.dec("freeQuantity").is_some_and(|f| f.signum() < 0) {
        return Err(invalid("Rates and free quantities cannot be negative."));
    }
    if m.str("refundPolicy") == Some("WITHIN_DAYS") && m.int("refundDays").is_none_or(|d| d <= 0) {
        return Err(invalid("A refund window needs refundDays above zero."));
    }
    Ok(())
}

/// A plan's fields hold together.
pub fn check_plan(p: &Rec) -> AuthResult<()> {
    if p.str("code").is_none_or(|c| c.trim().is_empty()) || p.str("label").is_none_or(|l| l.trim().is_empty()) {
        return Err(invalid("A plan needs a code and a label."));
    }
    for k in ["priceTokens", "priceAmount", "includedTokens"] {
        if p.dec(k).is_some_and(|v| v.signum() < 0) {
            return Err(invalid("Plan prices and credits cannot be negative."));
        }
    }
    let overrides = p.map("meterOverrides");
    match overrides.get("limits") {
        Some(Value::Array(list)) => {
            if list.iter().any(|l| l.get("meterKey").and_then(Value::as_str).is_none_or(|k| k.trim().is_empty())) {
                return Err(invalid("Each plan limit names its meter."));
            }
        }
        Some(_) => return Err(invalid("meterOverrides.limits is a list of {meterKey, free, rate, hardCap}.")),
        None => {
            for (k, o) in overrides {
                if !o.is_object() {
                    return Err(invalid(&format!("meterOverrides.{k} is an object like {{\"free\": 5, \"rate\": 1000, \"hardCap\": true}}.")));
                }
            }
        }
    }
    Ok(())
}

/// The config fields hold together.
pub fn check_config(c: &Rec) -> AuthResult<()> {
    if c.int("invoiceDay").is_some_and(|d| !(1..=28).contains(&d)) {
        return Err(invalid("The invoice day is between 1 and 28."));
    }
    if c.int("invoiceDueDays").is_some_and(|d| d < 0) {
        return Err(invalid("Due days cannot be negative."));
    }
    if c.int("purchasedCreditValidityMonths").is_some_and(|m| !(1..=60).contains(&m)) {
        return Err(invalid("Bought credits last 1 to 60 months (leave it empty for never)."));
    }
    let blank = |p: &str| c.str(p).is_none_or(|s| s.trim().is_empty());
    if c.str("suspendMode") == Some("BLOCK_APP") && (blank("suspendAppCode") || blank("suspendClientCode")) {
        return Err(invalid("Blocking the app needs the app and client to show instead (suspend app and client codes)."));
    }
    Ok(())
}

impl Billing<'_> {
    /// A config's meters, by display order.
    pub async fn meters_of(&self, ca: &ContextAuth, config: u64) -> AuthResult<Vec<Rec>> {
        let Some(_) = self.config_read(ca, config).await? else { return Err(forbidden("this billing config")) };
        let f = Find { not_deleted: true, order_by: Some("DISPLAY_ORDER"), ..Find::eq(vec![("BILLING_CONFIG_ID", Val::Id(config))]) };
        self.store.find(&METER, &f).await
    }

    /// One FILES_GB meter per configurator client: a client's files are charged once.
    async fn check_files_once(&self, m: &Rec) -> AuthResult<()> {
        if m.str("source") != Some("FILES_GB") || m.str("status") == Some("DELETED") {
            return Ok(());
        }
        let config = self.read(&CONFIG, m.u64("billingConfigId")).await?;
        let siblings = self.store.find(&CONFIG, &Find { not_deleted: true, ..Find::eq(vec![("CLIENT_ID", Val::Id(config.u64("clientId").unwrap_or(0)))]) }).await?;
        for c in siblings {
            let f = Find::eq(vec![("BILLING_CONFIG_ID", Val::Id(c.id().unwrap_or(0))), ("SOURCE", Val::Str("FILES_GB".into()))]);
            if self.store.find(&METER, &f).await?.iter().any(|x| x.id() != m.id() && x.str("status") != Some("DELETED")) {
                return Err(invalid("Files are counted per client, not per app: only one of this client's billing configs may charge for files."));
            }
        }
        Ok(())
    }

    /// One AI meter per config.
    async fn check_ai_once(&self, m: &Rec) -> AuthResult<()> {
        if m.str("source") != Some("AI_TOKENS") || m.str("status") == Some("DELETED") {
            return Ok(());
        }
        let f = Find::eq(vec![("BILLING_CONFIG_ID", Val::Id(m.u64("billingConfigId").unwrap_or(0))), ("SOURCE", Val::Str("AI_TOKENS".into()))]);
        if self.store.find(&METER, &f).await?.iter().any(|x| x.id() != m.id() && x.str("status") != Some("DELETED")) {
            return Err(invalid("A config has one AI meter."));
        }
        Ok(())
    }

    pub async fn meter_create(&self, ca: &ContextAuth, mut rec: Rec) -> AuthResult<Option<Rec>> {
        self.assert_manageable_config(ca, rec.u64("billingConfigId")).await?;
        for (p, v) in [("rateUnit", "MONTH"), ("chargeMode", "TOKENS"), ("refundPolicy", "NONE"), ("status", "ACTIVE")] {
            if matches!(rec.get(p), Val::Null) {
                rec.set(p, Val::Str(v.into()));
            }
        }
        if matches!(rec.get("kind"), Val::Null) {
            let gauge = gauge_source(rec.str("source").unwrap_or(""));
            rec.set("kind", Val::Str(if gauge { "GAUGE" } else { "COUNTER" }.into()));
        }
        check_meter(&rec)?;
        self.check_files_once(&rec).await?;
        self.check_ai_once(&rec).await?;
        self.create_row(rec).await
    }

    pub async fn meter_update(&self, ca: &ContextAuth, entity: &Rec) -> AuthResult<Rec> {
        let mut target = self.read(&METER, entity.id()).await?;
        self.assert_manageable_config(ca, target.u64("billingConfigId")).await?;
        copy(&mut target, entity, &METER_EDITABLE);
        check_meter(&target)?;
        self.check_files_once(&target).await?;
        self.check_ai_once(&target).await?;
        self.update_row(&target).await
    }

    pub async fn meter_delete(&self, ca: &ContextAuth, id: u64) -> AuthResult<u64> {
        let existing = self.read(&METER, Some(id)).await?;
        self.assert_manageable_config(ca, existing.u64("billingConfigId")).await?;
        // A meter with usage keeps its rows for the invoices: it is marked DELETED, not removed.
        let mut gone = existing;
        gone.set("status", Val::Str("DELETED".into()));
        self.store.update(&gone).await
    }

    /// A config's plans, by display order.
    pub async fn plans_of(&self, ca: &ContextAuth, config: u64) -> AuthResult<Vec<Rec>> {
        let Some(_) = self.config_read(ca, config).await? else { return Err(forbidden("this billing config")) };
        let f = Find { not_deleted: true, order_by: Some("DISPLAY_ORDER"), ..Find::eq(vec![("BILLING_CONFIG_ID", Val::Id(config))]) };
        self.store.find(&PLAN, &f).await
    }

    /// Only one default plan per config: saving one as default clears the others.
    async fn keep_one_default(&self, saved: &Rec) -> AuthResult<()> {
        if saved.int("isDefault") != Some(1) {
            return Ok(());
        }
        let f = Find::eq(vec![("BILLING_CONFIG_ID", Val::Id(saved.u64("billingConfigId").unwrap_or(0))), ("IS_DEFAULT", Val::Int(1))]);
        for mut other in self.store.find(&PLAN, &f).await? {
            if other.id() != saved.id() {
                other.set("isDefault", Val::Int(0));
                self.store.update(&other).await?;
            }
        }
        Ok(())
    }

    pub async fn plan_create(&self, ca: &ContextAuth, mut rec: Rec) -> AuthResult<Option<Rec>> {
        let config = self.assert_manageable_config(ca, rec.u64("billingConfigId")).await?;
        if matches!(rec.get("currency"), Val::Null) {
            rec.set("currency", config.get("currency").clone());
        }
        check_plan(&rec)?;
        let saved = self.create_row(rec).await?;
        if let Some(s) = &saved {
            self.keep_one_default(s).await?;
        }
        Ok(saved)
    }

    pub async fn plan_update(&self, ca: &ContextAuth, entity: &Rec) -> AuthResult<Rec> {
        let mut target = self.read(&PLAN, entity.id()).await?;
        self.assert_manageable_config(ca, target.u64("billingConfigId")).await?;
        copy(&mut target, entity, &PLAN_EDITABLE);
        check_plan(&target)?;
        let saved = self.update_row(&target).await?;
        self.keep_one_default(&saved).await?;
        Ok(saved)
    }

    pub async fn plan_delete(&self, ca: &ContextAuth, id: u64) -> AuthResult<u64> {
        let existing = self.read(&PLAN, Some(id)).await?;
        self.assert_manageable_config(ca, existing.u64("billingConfigId")).await?;
        let mut gone = existing;
        gone.set("status", Val::Str("DELETED".into()));
        gone.set("isDefault", Val::Int(0));
        self.store.update(&gone).await
    }

    /// A buyer moves its own client onto a plan of the config that governs it, from today. A
    /// WALLET plan is paid from the wallet now (400 without enough credits); an INVOICE plan with a
    /// price raises its first invoice now (with any usage not invoiced yet), to pay through
    /// `billing/repay`.
    pub async fn subscribe(&self, ca: &ContextAuth, plan_id: u64) -> AuthResult<Value> {
        let rec = self.read(&PLAN, Some(plan_id)).await?;
        let Some(plan) = self.internal.billing.plan_by_id(plan_id).await? else { return Err(params_not_found("plan")) };
        if plan.status != "ACTIVE" {
            return Err(invalid("This plan is not offered."));
        }
        let Some(config) = self.internal.billing.config_by_id(plan.config_id).await? else { return Err(params_not_found("billing config")) };
        let client = ca.user.client_id();
        let governing = self.internal.governing_config(config.app_id, client).await?;
        if governing.as_ref().map(|g| g.id) != Some(config.id) {
            return Err(forbidden("this plan (it is not offered to your client)"));
        }
        let Some(wallet) = self.internal.wallet_ready(ca, client, config.app_id, Some(&config)).await? else { return Err(params_not_found("wallet")) };
        if let Some(wp) = self.internal.billing.wallet_plan(wallet.id).await? {
            if wp.plan_id == plan.id && wp.auto_renew {
                return Ok(Obj::new().put("planId", plan.id).put("unchanged", true).build());
            }
        }
        let today = self.today();
        if !plan.invoiced() && plan.price_tokens.signum() > 0 && !self.internal.pay_plan_from_wallet(ca, &wallet, &config, &plan, today).await? {
            return Err(invalid("Not enough credits for this plan: add credits first."));
        }
        let wp = self.internal.put_on_plan(ca, &wallet, &config, &plan, today, false).await?;
        let invoice = if plan.invoiced() {
            self.internal.raise_monthly_invoice(ca, &config, client, Some(&plan), Some(today), today).await?
        } else {
            None
        };
        let _ = rec;
        Ok(Obj::new()
            .put("planId", plan.id)
            .put("walletPlanId", wp)
            .put("invoice", invoice.map(|i| i.to_json()).unwrap_or(Value::Null))
            .build())
    }

    /// The buyer's plan does not renew: at the period end the client moves to the default plan
    /// (or, with `nextPlanId`, to that plan of the same config).
    pub async fn cancel_plan(&self, ca: &ContextAuth, app_code: Option<&str>, next_plan: Option<u64>) -> AuthResult<Value> {
        let Some(app) = self.app_by_code(app_code).await? else { return Err(params_not_found("appCode")) };
        let client = ca.user.client_id();
        let Some(wallet) = self.internal.billing.wallet(client, app.id).await? else { return Err(params_not_found("plan")) };
        let Some(mut wp) = self.internal.billing.wallet_plan(wallet.id).await? else { return Err(params_not_found("plan")) };
        if let Some(n) = next_plan {
            let current = self.internal.billing.plan_by_id(wp.plan_id).await?;
            let next = self.internal.billing.plan_by_id(n).await?;
            if next.as_ref().map(|p| p.config_id) != current.as_ref().map(|p| p.config_id) {
                return Err(invalid("The next plan must be one of the same app's plans."));
            }
        }
        wp.auto_renew = false;
        wp.next_plan_id = next_plan;
        self.internal.billing.set_wallet_plan(&wp).await?;
        Ok(Obj::new().put("endsOn", wp.period_end.to_string()).put("nextPlanId", crate::jackson::opt(next_plan)).build())
    }

    /// SYSTEM only.
    fn assert_system(ca: &ContextAuth) -> AuthResult<()> {
        if ca.is_system_client() {
            Ok(())
        } else {
            Err(forbidden("the platform's billing settings (SYSTEM only)"))
        }
    }

    pub async fn ai_rates_list(&self, ca: &ContextAuth) -> AuthResult<Vec<Rec>> {
        Self::assert_system(ca)?;
        self.store.find(&AI_RATE, &Find { not_deleted: true, order_by: Some("MODEL_PATTERN"), ..Default::default() }).await
    }

    pub async fn ai_rate_create(&self, ca: &ContextAuth, mut rec: Rec) -> AuthResult<Option<Rec>> {
        Self::assert_system(ca)?;
        let pattern = rec.str("modelPattern").map(|p| p.trim().to_lowercase()).filter(|p| !p.is_empty()).ok_or_else(|| invalid("A model pattern is needed."))?;
        rec.set("modelPattern", Val::Str(pattern));
        self.create_row(rec).await
    }

    pub async fn ai_rate_update(&self, ca: &ContextAuth, entity: &Rec) -> AuthResult<Rec> {
        Self::assert_system(ca)?;
        let mut target = self.read(&AI_RATE, entity.id()).await?;
        copy(&mut target, entity, &AI_RATE_EDITABLE);
        if let Some(p) = target.str("modelPattern").map(|p| p.trim().to_lowercase()) {
            target.set("modelPattern", Val::Str(p));
        }
        self.update_row(&target).await
    }

    pub async fn ai_rate_delete(&self, ca: &ContextAuth, id: u64) -> AuthResult<u64> {
        Self::assert_system(ca)?;
        self.store.delete(&AI_RATE, id).await
    }

    pub async fn settings_read(&self, ca: &ContextAuth) -> AuthResult<Value> {
        Self::assert_system(ca)?;
        let mut out = Map::new();
        for name in SETTINGS {
            let v = self.internal.billing.setting(name).await?;
            out.insert(name.to_string(), v.map(Value::from).unwrap_or(Value::Null));
        }
        Ok(Value::Object(out))
    }

    pub async fn setting_write(&self, ca: &ContextAuth, name: &str, value: &str) -> AuthResult<Value> {
        Self::assert_system(ca)?;
        if !SETTINGS.contains(&name) {
            return Err(invalid("Unknown billing setting."));
        }
        if Dec::parse(value).is_none_or(|d| d.signum() <= 0) {
            return Err(invalid("The value is a positive number."));
        }
        sqlx::query("INSERT INTO security_billing_setting (NAME, VALUE, UPDATED_BY) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE VALUE = VALUES(VALUE), UPDATED_BY = VALUES(UPDATED_BY)")
            .bind(name)
            .bind(value.trim())
            .bind(ca.user.id)
            .execute(&self.internal.db.pool)
            .await?;
        self.settings_read(ca).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn meter(source: &str, kind: &str, unit: &str) -> Rec {
        Rec::new(&METER)
            .with("meterKey", Val::Str("users".into()))
            .with("label", Val::Str("Users".into()))
            .with("source", Val::Str(source.into()))
            .with("kind", Val::Str(kind.into()))
            .with("rateUnit", Val::Str(unit.into()))
    }

    #[test]
    fn meters_hold_together() {
        assert!(check_meter(&meter("USERS", "GAUGE", "MONTH")).is_ok());
        assert!(check_meter(&meter("EVENT", "COUNTER", "EACH")).is_ok());
        assert!(check_meter(&meter("AI_TOKENS", "COUNTER", "MARKUP")).is_ok());
        assert!(check_meter(&meter("USERS", "COUNTER", "MONTH")).is_err(), "kind follows the source");
        assert!(check_meter(&meter("USERS", "GAUGE", "EACH")).is_err());
        assert!(check_meter(&meter("EVENT", "COUNTER", "PERCENT")).unwrap_err().message().contains("not built yet"));
        assert!(check_meter(&meter("EVENT", "COUNTER", "MARKUP")).is_err());
        assert!(check_meter(&meter("AI_TOKENS", "COUNTER", "EACH")).is_err());
        assert!(check_meter(&meter("STORAGE_COUNT", "GAUGE", "MONTH")).is_err(), "needs a storage");
        let counted = meter("STORAGE_COUNT", "GAUGE", "MONTH").with("sourceConfig", Val::Json(json!({"storageName": "cxProduct"})));
        assert!(check_meter(&counted).is_ok());
        assert!(check_meter(&meter("USERS", "GAUGE", "MONTH").with("meterKey", Val::Str("bad key".into()))).is_err());
        let refund = meter("EVENT", "COUNTER", "EACH").with("refundPolicy", Val::Str("WITHIN_DAYS".into()));
        assert!(check_meter(&refund).is_err());
        assert!(check_meter(&refund.with("refundDays", Val::Int(30))).is_ok());
    }

    #[test]
    fn plans_and_configs_hold_together() {
        let p = Rec::new(&PLAN).with("code", Val::Str("free".into())).with("label", Val::Str("Free".into()));
        assert!(check_plan(&p).is_ok());
        assert!(check_plan(&p.clone().with("meterOverrides", Val::Json(json!({"users": 2})))).is_err());
        assert!(check_plan(&p.with("priceAmount", Val::Dec(Dec::from_i64(-1)))).is_err());
        let c = Rec::new(&CONFIG).with("invoiceDay", Val::Int(29));
        assert!(check_config(&c).is_err());
        let c = Rec::new(&CONFIG).with("suspendMode", Val::Str("BLOCK_APP".into()));
        assert!(check_config(&c).is_err());
        let c = c.with("suspendAppCode", Val::Str("suspended".into())).with("suspendClientCode", Val::Str("SYSTEM".into()));
        assert!(check_config(&c).is_ok());
    }
}
