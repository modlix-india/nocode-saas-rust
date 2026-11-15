//! The billing tables as security-internal uses them: configs, their meters and plans, wallets
//! with their credit lots, the ledger, the usage of monthly-invoiced meters, and the AI model
//! rates, behind [`BillingStore`] so the rules can be tested without debiting real wallets.
//!
//! What a config charges for is its meters (`security_billing_meter`, V90). A meter is either
//! counted on a schedule (GAUGE: users, apps, sites, storage rows, a storage's matching rows,
//! files) or recorded when it happens (COUNTER: AI tokens and app events), and it is paid either
//! from the prepaid wallet (TOKENS) or on the monthly invoice (INVOICE).

use std::collections::HashMap;

use async_trait::async_trait;
use chrono::{NaiveDate, NaiveDateTime};
use serde_json::{Map, Value};
use sqlx::mysql::MySqlRow;
use sqlx::{Acquire, Row};

use super::billing_admin::{sql as admin_sql, Find, Rec, Val, INVOICE, PROFILE};
use super::Db;
use crate::decimal::Dec;
use crate::errors::{AuthError, AuthResult};

/// The source names the metering producers send as the `actionKey` of an instruction or a
/// charge (core and files keep the names they had), and the meter source each one feeds.
pub mod action {
    pub const APP_RENT: &str = "security.app.rent";
    pub const SITE_RENT: &str = "security.site.rent";
    pub const USER: &str = "security.user";
    pub const STORAGE_ROWS: &str = "core.storage.rows";
    pub const STORAGE_COUNT: &str = "core.storage.count";
    pub const FILES_GB: &str = "files.gb";

    /// The meter source of a producer's action name.
    pub fn source(action_key: &str) -> Option<&'static str> {
        Some(match action_key {
            APP_RENT => "APPS",
            SITE_RENT => "SITES",
            USER => "USERS",
            STORAGE_ROWS => "STORAGE_ROWS",
            STORAGE_COUNT => "STORAGE_COUNT",
            FILES_GB => "FILES_GB",
            _ => return None,
        })
    }
}

/// The meter keys the platform itself records (apps never need to), so every config names
/// them the same way.
pub mod platform_meter {
    pub const AI_TOKENS: &str = "ai.tokens";
    pub const WHATSAPP: &str = "messages.whatsapp";
    pub const SMS: &str = "messages.sms";
    pub const CALL_MINUTES: &str = "calls.minutes";
}

/// A `security_app_billing_config` row (the columns the wallet rules read).
#[derive(Debug, Clone, PartialEq)]
pub struct BillingConfig {
    pub id: u64,
    pub client_id: u64,
    pub app_id: u64,
    pub gst_percentage: Dec,
    pub low_balance_threshold: Option<Dec>,
    pub suspend_app_code: Option<String>,
    pub suspend_client_code: Option<String>,
    /// `AI_ONLY`, `AI_AND_BANNER` or `BLOCK_APP`.
    pub suspend_mode: String,
    /// Months a bought credit lasts; `None` never expires.
    pub purchased_credit_validity_months: Option<i64>,
    pub invoice_day: u32,
    pub invoice_due_days: u32,
    pub currency: String,
    pub status: String,
}

impl Default for BillingConfig {
    fn default() -> Self {
        Self {
            id: 0,
            client_id: 0,
            app_id: 0,
            gst_percentage: Dec::ZERO,
            low_balance_threshold: None,
            suspend_app_code: None,
            suspend_client_code: None,
            suspend_mode: "AI_AND_BANNER".into(),
            purchased_credit_validity_months: Some(12),
            invoice_day: 1,
            invoice_due_days: 15,
            currency: "INR".into(),
            status: "ACTIVE".into(),
        }
    }
}

impl BillingConfig {
    pub fn is_active(&self) -> bool {
        self.status == "ACTIVE"
    }

    pub fn blocks_app(&self) -> bool {
        self.suspend_mode == "BLOCK_APP"
    }
}

/// A `security_billing_meter` row.
#[derive(Debug, Clone, PartialEq)]
pub struct Meter {
    pub id: u64,
    pub config_id: u64,
    pub key: String,
    pub label: String,
    pub unit_label: Option<String>,
    /// `GAUGE` or `COUNTER`.
    pub kind: String,
    pub source: String,
    pub source_config: Map<String, Value>,
    pub rate: Dec,
    /// `MONTH`, `EACH`, `PER_MILLION`, `PERCENT` or `MARKUP`.
    pub rate_unit: String,
    pub free: Dec,
    /// `TOKENS` or `INVOICE`.
    pub charge_mode: String,
    pub refund_policy: String,
    pub refund_days: Option<i64>,
    /// The reported figure to charge on (`quantity` when unset).
    pub basis: Option<String>,
    pub display_order: i64,
    pub status: String,
}

impl Default for Meter {
    fn default() -> Self {
        Self {
            id: 0,
            config_id: 0,
            key: String::new(),
            label: String::new(),
            unit_label: None,
            kind: "GAUGE".into(),
            source: "USERS".into(),
            source_config: Map::new(),
            rate: Dec::ZERO,
            rate_unit: "MONTH".into(),
            free: Dec::ZERO,
            charge_mode: "TOKENS".into(),
            refund_policy: "NONE".into(),
            refund_days: None,
            basis: None,
            display_order: 0,
            status: "ACTIVE".into(),
        }
    }
}

impl Meter {
    pub fn invoiced(&self) -> bool {
        self.charge_mode == "INVOICE"
    }

    pub fn is_gauge(&self) -> bool {
        self.kind == "GAUGE"
    }

    /// The ledger's action key of this meter: `{appCode}.{meterKey}`.
    pub fn action_key(&self, app_code: &str) -> String {
        format!("{app_code}.{}", self.key)
    }
}

/// What a plan changes on one meter.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MeterOverride {
    pub free: Option<Dec>,
    pub rate: Option<Dec>,
    /// The free quantity is a hard limit: at it the action is refused, nothing is charged.
    pub hard_cap: bool,
}

/// A `security_billing_plan` row.
#[derive(Debug, Clone, PartialEq)]
pub struct Plan {
    pub id: u64,
    pub config_id: u64,
    pub code: String,
    pub label: String,
    /// `MONTH` or `YEAR`.
    pub period: String,
    /// `WALLET` or `INVOICE`.
    pub payment_mode: String,
    pub price_tokens: Dec,
    pub price_amount: Dec,
    pub currency: String,
    pub included_tokens: Dec,
    pub included_recurring: bool,
    pub overrides: HashMap<String, MeterOverride>,
    /// Model name substrings the plan may use; empty is any.
    pub ai_models: Vec<String>,
    pub is_default: bool,
    pub status: String,
}

impl Default for Plan {
    fn default() -> Self {
        Self {
            id: 0,
            config_id: 0,
            code: String::new(),
            label: String::new(),
            period: "MONTH".into(),
            payment_mode: "INVOICE".into(),
            price_tokens: Dec::ZERO,
            price_amount: Dec::ZERO,
            currency: "INR".into(),
            included_tokens: Dec::ZERO,
            included_recurring: true,
            overrides: HashMap::new(),
            ai_models: vec![],
            is_default: false,
            status: "ACTIVE".into(),
        }
    }
}

impl Plan {
    pub fn invoiced(&self) -> bool {
        self.payment_mode == "INVOICE"
    }

    /// A model is allowed when the plan names none, or its name contains one of them.
    pub fn allows_model(&self, model: &str) -> bool {
        let m = model.to_lowercase();
        self.ai_models.is_empty() || self.ai_models.iter().any(|p| m.contains(&p.to_lowercase()))
    }
}

/// The free quantity, rate and hard cap of a meter under a plan.
#[derive(Debug, Clone, PartialEq)]
pub struct Terms {
    pub free: Dec,
    pub rate: Dec,
    pub hard_cap: Option<Dec>,
}

/// A meter's terms: the plan's override where it has one, else the meter's own.
pub fn terms(meter: &Meter, plan: Option<&Plan>) -> Terms {
    let o = plan.and_then(|p| p.overrides.get(&meter.key));
    let free = o.and_then(|o| o.free).unwrap_or(meter.free);
    Terms {
        free,
        rate: o.and_then(|o| o.rate).unwrap_or(meter.rate),
        hard_cap: o.filter(|o| o.hard_cap).map(|_| free),
    }
}

/// `METER_OVERRIDES` as stored: `{"limits": [{meterKey, free, rate, hardCap}]}` (what the settings
/// tab writes), or keyed `{meterKey: {free, rate, hardCap}}`.
pub fn parse_overrides(v: &Map<String, Value>) -> HashMap<String, MeterOverride> {
    let one = |o: &Map<String, Value>| MeterOverride {
        free: o.get("free").and_then(Dec::from_json),
        rate: o.get("rate").and_then(Dec::from_json),
        hard_cap: o.get("hardCap").and_then(|h| h.as_bool().or_else(|| h.as_str().map(|s| s == "true"))).unwrap_or(false),
    };
    if let Some(list) = v.get("limits").and_then(Value::as_array) {
        return list
            .iter()
            .filter_map(|l| {
                let o = l.as_object()?;
                let key = o.get("meterKey")?.as_str()?.trim();
                (!key.is_empty()).then(|| (key.to_string(), one(o)))
            })
            .collect();
    }
    v.iter().filter_map(|(k, o)| Some((k.clone(), one(o.as_object()?)))).collect()
}

/// `AI_MODELS_ALLOWED` as stored: `{"patterns": [...]}`.
pub fn parse_models(v: &Map<String, Value>) -> Vec<String> {
    v.get("patterns")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).filter(|s| !s.trim().is_empty()).map(|s| s.trim().to_string()).collect())
        .unwrap_or_default()
}

/// A `security_wallet_plan` row.
#[derive(Debug, Clone, PartialEq)]
pub struct WalletPlan {
    pub id: u64,
    pub wallet_id: u64,
    pub plan_id: u64,
    pub period_start: NaiveDate,
    pub period_end: NaiveDate,
    pub status: String,
    pub auto_renew: bool,
    pub next_plan_id: Option<u64>,
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
    pub reference_type: Option<String>,
    pub reference_id: Option<u64>,
    pub reason: String,
    pub description: Option<String>,
    pub created_by: Option<u64>,
}

/// A credit to add as a lot.
#[derive(Debug, Clone, PartialEq)]
pub struct NewLot {
    /// `PLAN`, `PURCHASE`, `GRANT` or `ADJUST`.
    pub source: &'static str,
    pub reference_type: Option<String>,
    pub reference_id: Option<u64>,
    pub expires_at: Option<NaiveDateTime>,
}

/// A `security_wallet_lot` row.
#[derive(Debug, Clone, PartialEq)]
pub struct Lot {
    pub id: u64,
    pub wallet_id: u64,
    pub source: String,
    pub tokens_added: Dec,
    pub tokens_left: Dec,
    pub added_at: NaiveDateTime,
    pub expires_at: Option<NaiveDateTime>,
}

/// `MeteringInstruction`: one (config, app, billed client), and the meter when the producer
/// needs its options (a storage count).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Instruction {
    pub config_client_code: String,
    pub config_client_id: u64,
    pub app_code: String,
    pub app_id: u64,
    pub billed_client_code: String,
    pub billed_client_id: u64,
    pub meter_id: Option<u64>,
    pub source_config: Option<Map<String, Value>>,
}

impl Instruction {
    pub fn to_json(&self) -> Value {
        let mut b = crate::jackson::Obj::new()
            .put("configClientCode", self.config_client_code.as_str())
            .put("configClientId", self.config_client_id)
            .put("appCode", self.app_code.as_str())
            .put("appId", self.app_id)
            .put("billedClientCode", self.billed_client_code.as_str())
            .put("billedClientId", self.billed_client_id);
        if let Some(m) = self.meter_id {
            b = b.put("meterId", m);
        }
        if let Some(c) = &self.source_config {
            b = b.put("sourceConfig", Value::Object(c.clone()));
        }
        b.build()
    }
}

/// A usage record of an INVOICE meter to write.
#[derive(Debug, Clone, PartialEq)]
pub struct Usage {
    pub client_id: u64,
    pub app_id: u64,
    pub meter_id: u64,
    pub date: NaiveDate,
    /// `SNAPSHOT`, `EVENT` or `REVERSAL`.
    pub kind: &'static str,
    pub quantity: Dec,
    pub figures: Option<Map<String, Value>>,
    pub reference: Option<String>,
}

impl Usage {
    /// What makes a retry harmless: one snapshot a day, one event and one reversal a reference.
    pub fn unique_key(&self) -> String {
        match self.kind {
            "SNAPSHOT" => format!("snap:{}", self.date),
            "REVERSAL" => format!("rev:{}", self.reference.as_deref().unwrap_or("")),
            _ => format!("ev:{}", self.reference.as_deref().unwrap_or("")),
        }
    }
}

/// One meter's usage over an invoice period.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PeriodUsage {
    /// Sum of the daily snapshots and the number of days that have one.
    pub snapshot_sum: Dec,
    pub snapshot_days: i64,
    pub events: Dec,
    pub reversals: Dec,
}

/// A `security_ai_model_rate` row: provider prices per million tokens.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AiRate {
    pub pattern: String,
    pub input: Dec,
    pub output: Dec,
    pub cache_read: Dec,
    pub cache_write: Dec,
    pub currency: String,
}

#[async_trait]
pub trait BillingStore: Send + Sync {
    /// The first non-DELETED config of (app, client).
    async fn config_by_app_client(&self, app_id: u64, client_id: u64) -> AuthResult<Option<BillingConfig>>;
    async fn config_by_id(&self, id: u64) -> AuthResult<Option<BillingConfig>>;
    /// The ACTIVE config of (app code, client code).
    async fn config_by_codes(&self, app_code: &str, client_code: &str) -> AuthResult<Option<BillingConfig>>;
    /// Every ACTIVE config (the daily invoice and renewal runs).
    async fn active_configs(&self) -> AuthResult<Vec<BillingConfig>>;
    /// A config's non-DELETED meters, by display order.
    async fn meters_of_config(&self, config_id: u64) -> AuthResult<Vec<Meter>>;
    async fn meter_by_id(&self, id: u64) -> AuthResult<Option<Meter>>;
    /// For every ACTIVE meter of the source on an ACTIVE config: each client it governs (the
    /// client's nearest managing client with a config for the app is the meter's).
    async fn charge_instructions(&self, source: &str) -> AuthResult<Vec<Instruction>>;
    async fn plan_by_id(&self, id: u64) -> AuthResult<Option<Plan>>;
    async fn plans_of_config(&self, config_id: u64) -> AuthResult<Vec<Plan>>;
    /// The wallet's ACTIVE plan.
    async fn wallet_plan(&self, wallet_id: u64) -> AuthResult<Option<WalletPlan>>;
    /// ACTIVE wallet plans whose period ended on or before the day.
    async fn wallet_plans_due(&self, day: NaiveDate) -> AuthResult<Vec<WalletPlan>>;
    /// Puts the wallet on a plan for a period (any ACTIVE one before it is ENDED).
    async fn start_wallet_plan(&self, wallet_id: u64, plan_id: u64, start: NaiveDate, end: NaiveDate) -> AuthResult<u64>;
    async fn set_wallet_plan(&self, wp: &WalletPlan) -> AuthResult<u64>;
    async fn wallet(&self, client_id: u64, app_id: u64) -> AuthResult<Option<Wallet>>;
    async fn wallet_by_id(&self, id: u64) -> AuthResult<Option<Wallet>>;
    /// Inserts the wallet at zero if absent (a race loses quietly), then reads it; `true` when this
    /// call created it.
    async fn create_wallet(&self, client_id: u64, app_id: u64) -> AuthResult<Option<(Wallet, bool)>>;
    /// The ledger row, the balance and the lots it draws on, in one transaction: false (and no
    /// change) when the idempotency key was already used.
    async fn debit(&self, t: &Txn) -> AuthResult<bool>;
    /// The ledger row, the balance and a lot of what is left after any debt is paid, in one
    /// transaction: false when the idempotency key was already used.
    async fn credit(&self, t: &Txn, lot: &NewLot) -> AuthResult<bool>;
    /// A ledger row that moves no balance (an AI call inside the free grant).
    async fn record_txn(&self, t: &Txn) -> AuthResult<bool>;
    /// Lots with credits left whose expiry is on or before the moment.
    async fn expired_lots(&self, now: NaiveDateTime) -> AuthResult<Vec<Lot>>;
    /// Lots with credits left expiring between the moments.
    async fn lots_expiring(&self, from: NaiveDateTime, to: NaiveDateTime) -> AuthResult<Vec<Lot>>;
    /// The wallet's lots with credits left, soonest expiry first.
    async fn open_lots(&self, wallet_id: u64) -> AuthResult<Vec<Lot>>;
    /// Writes off a lot: the EXPIRE ledger row, the balance, the lot to zero; false when done before.
    async fn expire_lot(&self, lot: &Lot, t: &Txn) -> AuthResult<bool>;
    async fn set_status(&self, wallet_id: u64, status: &str) -> AuthResult<u64>;
    async fn set_low_balance_notified(&self, wallet_id: u64, notified: bool) -> AuthResult<u64>;
    async fn sum_quantity_between(&self, wallet_id: u64, action_key: &str, from: NaiveDate, to: NaiveDate) -> AuthResult<Dec>;
    async fn sum_tokens_between(&self, wallet_id: u64, action_key: &str, from: NaiveDate, to: NaiveDate) -> AuthResult<Dec>;
    async fn charged_windows(&self, wallet_id: u64, action_key: &str, date: NaiveDate) -> AuthResult<Vec<i16>>;
    /// A ledger row by its idempotency key (a reversal finds the charge it undoes).
    async fn txn_by_key(&self, wallet_id: u64, key: &str) -> AuthResult<Option<(Txn, NaiveDateTime)>>;
    /// Writes a usage record; a SNAPSHOT keeps the day's highest count. False when an event or
    /// reversal with that reference is there already.
    async fn record_usage(&self, u: &Usage) -> AuthResult<bool>;
    async fn usage_by_reference(&self, meter_id: u64, client_id: u64, reference: &str) -> AuthResult<Option<(Usage, NaiveDateTime)>>;
    /// Not yet invoiced usage of a meter for a client in [from, to).
    async fn period_usage(&self, meter_id: u64, client_id: u64, from: NaiveDate, to: NaiveDate) -> AuthResult<PeriodUsage>;
    /// Marks the not yet invoiced usage of (client, app) in [from, to) as billed by the invoice.
    async fn mark_invoiced(&self, client_id: u64, app_id: u64, from: NaiveDate, to: NaiveDate, invoice_id: u64) -> AuthResult<u64>;
    /// (client, app) pairs with not yet invoiced usage before the day.
    async fn clients_with_usage(&self, config_id: u64, before: NaiveDate) -> AuthResult<Vec<u64>>;
    /// Count of the apps or sites the client owns, ACTIVE only (unless the meter counts archived ones).
    async fn count_apps(&self, client_id: u64, app_type: &str, active_only: bool) -> AuthResult<i64>;
    /// Users of the client with a profile in the app (in the profiles, when given).
    async fn count_users_with_profile(&self, client_id: u64, app_id: u64, profile_ids: &[u64]) -> AuthResult<i64>;
    async fn ai_rates(&self) -> AuthResult<Vec<AiRate>>;
    async fn setting(&self, name: &str) -> AuthResult<Option<String>>;
    /// Whether (client, app) has an OVERDUE invoice.
    async fn has_overdue_invoice(&self, client_id: u64, app_id: u64) -> AuthResult<bool>;
    /// The buyer's billing profile for the app.
    async fn buyer_profile(&self, client_id: u64, app_id: u64) -> AuthResult<Option<Rec>>;
    /// Numbers and inserts a monthly invoice with its lines in one transaction; `None` when the
    /// invoice's period key is taken (the run already raised it).
    async fn insert_monthly_invoice(&self, invoice: &Rec, lines: &[Rec], fin_year: &str) -> AuthResult<Option<Rec>>;
    /// PENDING monthly invoices due before the day.
    async fn invoices_past_due(&self, day: NaiveDate) -> AuthResult<Vec<Rec>>;
    async fn set_invoice_status(&self, invoice_id: u64, status: &str) -> AuthResult<u64>;
    /// The first day of (client, app) usage not invoiced yet.
    async fn earliest_unbilled(&self, client_id: u64, app_id: u64) -> AuthResult<Option<NaiveDate>>;
    /// A gauge's month-units over [from, to): each day's count above the free quantity divided by
    /// that month's days, summed (times the monthly rate is the amount).
    async fn gauge_month_units(&self, meter_id: u64, client_id: u64, from: NaiveDate, to: NaiveDate, free: Dec) -> AuthResult<Dec>;
}

const CONFIG_COLUMNS: &str = "c.ID, c.CLIENT_ID, c.APP_ID, CAST(c.GST_PERCENTAGE AS CHAR) GST_PERCENTAGE, \
    CAST(c.LOW_BALANCE_THRESHOLD AS CHAR) LOW_BALANCE_THRESHOLD, c.SUSPEND_APP_CODE, c.SUSPEND_CLIENT_CODE, c.SUSPEND_MODE, \
    c.PURCHASED_CREDIT_VALIDITY_MONTHS, c.INVOICE_DAY, c.INVOICE_DUE_DAYS, c.CURRENCY, c.STATUS";

const METER_COLUMNS: &str = "m.ID, m.BILLING_CONFIG_ID, m.METER_KEY, m.LABEL, m.UNIT_LABEL, m.KIND, m.SOURCE, \
    CAST(m.SOURCE_CONFIG AS CHAR) SOURCE_CONFIG, CAST(m.RATE AS CHAR) RATE, m.RATE_UNIT, CAST(m.FREE_QUANTITY AS CHAR) FREE_QUANTITY, \
    m.CHARGE_MODE, m.REFUND_POLICY, m.REFUND_DAYS, m.BASIS, m.DISPLAY_ORDER, m.STATUS";

const PLAN_COLUMNS: &str = "p.ID, p.BILLING_CONFIG_ID, p.CODE, p.LABEL, p.PERIOD, p.PAYMENT_MODE, \
    CAST(p.PRICE_TOKENS AS CHAR) PRICE_TOKENS, CAST(p.PRICE_AMOUNT AS CHAR) PRICE_AMOUNT, p.CURRENCY, \
    CAST(p.INCLUDED_TOKENS AS CHAR) INCLUDED_TOKENS, p.INCLUDED_TOKENS_RECURRING, CAST(p.METER_OVERRIDES AS CHAR) METER_OVERRIDES, \
    CAST(p.AI_MODELS_ALLOWED AS CHAR) AI_MODELS_ALLOWED, p.IS_DEFAULT, p.STATUS";

const WALLET_PLAN_COLUMNS: &str = "ID, WALLET_ID, PLAN_ID, PERIOD_START, PERIOD_END, STATUS, AUTO_RENEW, NEXT_PLAN_ID";

const WALLET_COLUMNS: &str = "ID, CLIENT_ID, APP_ID, CAST(BALANCE AS CHAR) BALANCE, STATUS, \
    CAST(ALERT_THRESHOLD AS CHAR) ALERT_THRESHOLD, LOW_BALANCE_NOTIFIED";

const LOT_COLUMNS: &str = "ID, WALLET_ID, SOURCE, CAST(TOKENS_ADDED AS CHAR) TOKENS_ADDED, CAST(TOKENS_LEFT AS CHAR) TOKENS_LEFT, ADDED_AT, EXPIRES_AT";

fn dec(row: &MySqlRow, col: &str) -> AuthResult<Option<Dec>> {
    match row.try_get::<Option<String>, _>(col)? {
        None => Ok(None),
        Some(s) => Dec::parse(&s).map(Some).ok_or_else(|| AuthError::internal(format!("{col} is not a number: {s}"))),
    }
}

fn json_map(row: &MySqlRow, col: &str) -> AuthResult<Map<String, Value>> {
    Ok(match row.try_get::<Option<String>, _>(col)? {
        Some(t) => match serde_json::from_str::<Value>(&t) {
            Ok(Value::Object(m)) => m,
            _ => Map::new(),
        },
        None => Map::new(),
    })
}

fn config(row: &MySqlRow) -> AuthResult<BillingConfig> {
    Ok(BillingConfig {
        id: row.try_get("ID")?,
        client_id: row.try_get("CLIENT_ID")?,
        app_id: row.try_get("APP_ID")?,
        gst_percentage: dec(row, "GST_PERCENTAGE")?.unwrap_or(Dec::ZERO),
        low_balance_threshold: dec(row, "LOW_BALANCE_THRESHOLD")?,
        suspend_app_code: row.try_get("SUSPEND_APP_CODE")?,
        suspend_client_code: row.try_get("SUSPEND_CLIENT_CODE")?,
        suspend_mode: row.try_get("SUSPEND_MODE")?,
        purchased_credit_validity_months: row.try_get::<Option<i32>, _>("PURCHASED_CREDIT_VALIDITY_MONTHS")?.map(i64::from),
        invoice_day: row.try_get::<i32, _>("INVOICE_DAY")?.max(1) as u32,
        invoice_due_days: row.try_get::<i32, _>("INVOICE_DUE_DAYS")?.max(0) as u32,
        currency: row.try_get::<String, _>("CURRENCY")?.trim().to_string(),
        status: row.try_get("STATUS")?,
    })
}

fn meter(row: &MySqlRow) -> AuthResult<Meter> {
    Ok(Meter {
        id: row.try_get("ID")?,
        config_id: row.try_get("BILLING_CONFIG_ID")?,
        key: row.try_get("METER_KEY")?,
        label: row.try_get("LABEL")?,
        unit_label: row.try_get("UNIT_LABEL")?,
        kind: row.try_get("KIND")?,
        source: row.try_get("SOURCE")?,
        source_config: json_map(row, "SOURCE_CONFIG")?,
        rate: dec(row, "RATE")?.unwrap_or(Dec::ZERO),
        rate_unit: row.try_get("RATE_UNIT")?,
        free: dec(row, "FREE_QUANTITY")?.unwrap_or(Dec::ZERO),
        charge_mode: row.try_get("CHARGE_MODE")?,
        refund_policy: row.try_get("REFUND_POLICY")?,
        refund_days: row.try_get::<Option<i32>, _>("REFUND_DAYS")?.map(i64::from),
        basis: row.try_get("BASIS")?,
        display_order: i64::from(row.try_get::<i32, _>("DISPLAY_ORDER")?),
        status: row.try_get("STATUS")?,
    })
}

fn plan(row: &MySqlRow) -> AuthResult<Plan> {
    Ok(Plan {
        id: row.try_get("ID")?,
        config_id: row.try_get("BILLING_CONFIG_ID")?,
        code: row.try_get("CODE")?,
        label: row.try_get("LABEL")?,
        period: row.try_get("PERIOD")?,
        payment_mode: row.try_get("PAYMENT_MODE")?,
        price_tokens: dec(row, "PRICE_TOKENS")?.unwrap_or(Dec::ZERO),
        price_amount: dec(row, "PRICE_AMOUNT")?.unwrap_or(Dec::ZERO),
        currency: row.try_get::<String, _>("CURRENCY")?.trim().to_string(),
        included_tokens: dec(row, "INCLUDED_TOKENS")?.unwrap_or(Dec::ZERO),
        included_recurring: row.try_get::<i8, _>("INCLUDED_TOKENS_RECURRING")? != 0,
        overrides: parse_overrides(&json_map(row, "METER_OVERRIDES")?),
        ai_models: parse_models(&json_map(row, "AI_MODELS_ALLOWED")?),
        is_default: row.try_get::<i8, _>("IS_DEFAULT")? != 0,
        status: row.try_get("STATUS")?,
    })
}

fn wallet_plan(row: &MySqlRow) -> AuthResult<WalletPlan> {
    Ok(WalletPlan {
        id: row.try_get("ID")?,
        wallet_id: row.try_get("WALLET_ID")?,
        plan_id: row.try_get("PLAN_ID")?,
        period_start: row.try_get("PERIOD_START")?,
        period_end: row.try_get("PERIOD_END")?,
        status: row.try_get("STATUS")?,
        auto_renew: row.try_get::<i8, _>("AUTO_RENEW")? != 0,
        next_plan_id: row.try_get("NEXT_PLAN_ID")?,
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

fn lot(row: &MySqlRow) -> AuthResult<Lot> {
    Ok(Lot {
        id: row.try_get("ID")?,
        wallet_id: row.try_get("WALLET_ID")?,
        source: row.try_get("SOURCE")?,
        tokens_added: dec(row, "TOKENS_ADDED")?.unwrap_or(Dec::ZERO),
        tokens_left: dec(row, "TOKENS_LEFT")?.unwrap_or(Dec::ZERO),
        added_at: crate::mysql::ts(row, "ADDED_AT")?.unwrap_or_default(),
        expires_at: crate::mysql::ts(row, "EXPIRES_AT")?,
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

    async fn config_by_id(&self, id: u64) -> AuthResult<Option<BillingConfig>> {
        let sql = format!("SELECT {CONFIG_COLUMNS} FROM security_app_billing_config c WHERE c.ID = ? LIMIT 1");
        let row = sqlx::query(&sql).bind(id).fetch_optional(&self.pool).await?;
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

    async fn active_configs(&self) -> AuthResult<Vec<BillingConfig>> {
        let sql = format!("SELECT {CONFIG_COLUMNS} FROM security_app_billing_config c WHERE c.STATUS = 'ACTIVE' ORDER BY c.ID");
        sqlx::query(&sql).fetch_all(&self.pool).await?.iter().map(config).collect()
    }

    async fn meters_of_config(&self, config_id: u64) -> AuthResult<Vec<Meter>> {
        let sql = format!(
            "SELECT {METER_COLUMNS} FROM security_billing_meter m WHERE m.BILLING_CONFIG_ID = ? AND m.STATUS <> 'DELETED' \
             ORDER BY m.DISPLAY_ORDER, m.ID"
        );
        sqlx::query(&sql).bind(config_id).fetch_all(&self.pool).await?.iter().map(meter).collect()
    }

    async fn meter_by_id(&self, id: u64) -> AuthResult<Option<Meter>> {
        let sql = format!("SELECT {METER_COLUMNS} FROM security_billing_meter m WHERE m.ID = ? LIMIT 1");
        let row = sqlx::query(&sql).bind(id).fetch_optional(&self.pool).await?;
        row.as_ref().map(meter).transpose()
    }

    async fn charge_instructions(&self, source: &str) -> AuthResult<Vec<Instruction>> {
        // A config at hierarchy level k governs the client unless another non-DELETED config of
        // the app sits at a closer level j < k.
        let sql = "SELECT cc.CODE CC, c.CLIENT_ID CID, a.APP_CODE AC, c.APP_ID AID, bc.CODE BC, h.CLIENT_ID BID, m.ID MID, \
             CAST(m.SOURCE_CONFIG AS CHAR) SC \
             FROM security_billing_meter m JOIN security_app_billing_config c ON c.ID = m.BILLING_CONFIG_ID \
             JOIN security_app a ON a.ID = c.APP_ID JOIN security_client cc ON cc.ID = c.CLIENT_ID \
             JOIN security_client_hierarchy h ON c.CLIENT_ID IN (h.MANAGE_CLIENT_LEVEL_0, h.MANAGE_CLIENT_LEVEL_1, \
                  h.MANAGE_CLIENT_LEVEL_2, h.MANAGE_CLIENT_LEVEL_3) \
             JOIN security_client bc ON bc.ID = h.CLIENT_ID \
             WHERE m.SOURCE = ? AND m.STATUS = 'ACTIVE' AND c.STATUS = 'ACTIVE' AND NOT EXISTS ( \
               SELECT 1 FROM security_app_billing_config c2 WHERE c2.APP_ID = c.APP_ID AND c2.STATUS <> 'DELETED' \
               AND c2.CLIENT_ID <> c.CLIENT_ID AND ( \
                 (c2.CLIENT_ID = h.MANAGE_CLIENT_LEVEL_0) \
                 OR (c2.CLIENT_ID = h.MANAGE_CLIENT_LEVEL_1 AND c.CLIENT_ID NOT IN (h.MANAGE_CLIENT_LEVEL_0, h.MANAGE_CLIENT_LEVEL_1)) \
                 OR (c2.CLIENT_ID = h.MANAGE_CLIENT_LEVEL_2 AND c.CLIENT_ID NOT IN (h.MANAGE_CLIENT_LEVEL_0, h.MANAGE_CLIENT_LEVEL_1, h.MANAGE_CLIENT_LEVEL_2)))) \
             ORDER BY m.ID, h.CLIENT_ID";
        let rows = sqlx::query(sql).bind(source).fetch_all(&self.pool).await?;
        rows.iter()
            .map(|r| {
                Ok(Instruction {
                    config_client_code: r.try_get("CC")?,
                    config_client_id: r.try_get("CID")?,
                    app_code: r.try_get("AC")?,
                    app_id: r.try_get("AID")?,
                    billed_client_code: r.try_get("BC")?,
                    billed_client_id: r.try_get("BID")?,
                    meter_id: Some(r.try_get("MID")?),
                    source_config: Some(json_map(r, "SC")?),
                })
            })
            .collect()
    }

    async fn plan_by_id(&self, id: u64) -> AuthResult<Option<Plan>> {
        let sql = format!("SELECT {PLAN_COLUMNS} FROM security_billing_plan p WHERE p.ID = ? LIMIT 1");
        let row = sqlx::query(&sql).bind(id).fetch_optional(&self.pool).await?;
        row.as_ref().map(plan).transpose()
    }

    async fn plans_of_config(&self, config_id: u64) -> AuthResult<Vec<Plan>> {
        let sql = format!(
            "SELECT {PLAN_COLUMNS} FROM security_billing_plan p WHERE p.BILLING_CONFIG_ID = ? AND p.STATUS <> 'DELETED' \
             ORDER BY p.DISPLAY_ORDER, p.ID"
        );
        sqlx::query(&sql).bind(config_id).fetch_all(&self.pool).await?.iter().map(plan).collect()
    }

    async fn wallet_plan(&self, wallet_id: u64) -> AuthResult<Option<WalletPlan>> {
        let sql = format!("SELECT {WALLET_PLAN_COLUMNS} FROM security_wallet_plan WHERE WALLET_ID = ? AND STATUS = 'ACTIVE' ORDER BY ID DESC LIMIT 1");
        let row = sqlx::query(&sql).bind(wallet_id).fetch_optional(&self.pool).await?;
        row.as_ref().map(wallet_plan).transpose()
    }

    async fn wallet_plans_due(&self, day: NaiveDate) -> AuthResult<Vec<WalletPlan>> {
        let sql = format!("SELECT {WALLET_PLAN_COLUMNS} FROM security_wallet_plan WHERE STATUS = 'ACTIVE' AND PERIOD_END <= ? ORDER BY ID");
        sqlx::query(&sql).bind(day).fetch_all(&self.pool).await?.iter().map(wallet_plan).collect()
    }

    async fn start_wallet_plan(&self, wallet_id: u64, plan_id: u64, start: NaiveDate, end: NaiveDate) -> AuthResult<u64> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("UPDATE security_wallet_plan SET STATUS = 'ENDED' WHERE WALLET_ID = ? AND STATUS = 'ACTIVE'")
            .bind(wallet_id)
            .execute(&mut *tx)
            .await?;
        let id = sqlx::query("INSERT INTO security_wallet_plan (WALLET_ID, PLAN_ID, PERIOD_START, PERIOD_END, STATUS, AUTO_RENEW) VALUES (?, ?, ?, ?, 'ACTIVE', 1)")
            .bind(wallet_id)
            .bind(plan_id)
            .bind(start)
            .bind(end)
            .execute(&mut *tx)
            .await?
            .last_insert_id();
        tx.commit().await?;
        Ok(id)
    }

    async fn set_wallet_plan(&self, wp: &WalletPlan) -> AuthResult<u64> {
        let r = sqlx::query(
            "UPDATE security_wallet_plan SET PLAN_ID = ?, PERIOD_START = ?, PERIOD_END = ?, STATUS = ?, AUTO_RENEW = ?, NEXT_PLAN_ID = ? WHERE ID = ?",
        )
        .bind(wp.plan_id)
        .bind(wp.period_start)
        .bind(wp.period_end)
        .bind(&wp.status)
        .bind(i8::from(wp.auto_renew))
        .bind(wp.next_plan_id)
        .bind(wp.id)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected())
    }

    async fn wallet(&self, client_id: u64, app_id: u64) -> AuthResult<Option<Wallet>> {
        sql::wallet(&mut *self.pool.acquire().await?, client_id, app_id).await
    }

    async fn wallet_by_id(&self, id: u64) -> AuthResult<Option<Wallet>> {
        let q = format!("SELECT {WALLET_COLUMNS} FROM security_wallet WHERE ID = ? LIMIT 1");
        let row = sqlx::query(&q).bind(id).fetch_optional(&self.pool).await?;
        row.as_ref().map(wallet).transpose()
    }

    async fn create_wallet(&self, client_id: u64, app_id: u64) -> AuthResult<Option<(Wallet, bool)>> {
        let c = &mut *self.pool.acquire().await?;
        let created = sql::create_seeded_wallet(c, client_id, app_id, Dec::ZERO).await?;
        Ok(sql::wallet(c, client_id, app_id).await?.map(|w| (w, created)))
    }

    async fn debit(&self, t: &Txn) -> AuthResult<bool> {
        let mut conn = self.pool.acquire().await?;
        let mut tx = conn.begin().await?;
        let done = sql::debit_with_lots(&mut tx, t).await?;
        tx.commit().await?;
        Ok(done)
    }

    async fn credit(&self, t: &Txn, lot: &NewLot) -> AuthResult<bool> {
        let mut conn = self.pool.acquire().await?;
        let mut tx = conn.begin().await?;
        let done = sql::credit_with_lot(&mut tx, t, lot).await?;
        tx.commit().await?;
        Ok(done)
    }

    async fn record_txn(&self, t: &Txn) -> AuthResult<bool> {
        sql::record_txn(&mut *self.pool.acquire().await?, t).await
    }

    async fn expired_lots(&self, now: NaiveDateTime) -> AuthResult<Vec<Lot>> {
        let q = format!("SELECT {LOT_COLUMNS} FROM security_wallet_lot WHERE TOKENS_LEFT > 0 AND EXPIRES_AT IS NOT NULL AND EXPIRES_AT <= ? ORDER BY ID");
        sqlx::query(&q).bind(now).fetch_all(&self.pool).await?.iter().map(lot).collect()
    }

    async fn lots_expiring(&self, from: NaiveDateTime, to: NaiveDateTime) -> AuthResult<Vec<Lot>> {
        let q = format!(
            "SELECT {LOT_COLUMNS} FROM security_wallet_lot WHERE TOKENS_LEFT > 0 AND EXPIRES_AT > ? AND EXPIRES_AT <= ? ORDER BY WALLET_ID, EXPIRES_AT"
        );
        sqlx::query(&q).bind(from).bind(to).fetch_all(&self.pool).await?.iter().map(lot).collect()
    }

    async fn open_lots(&self, wallet_id: u64) -> AuthResult<Vec<Lot>> {
        sql::open_lots(&mut *self.pool.acquire().await?, wallet_id).await
    }

    async fn expire_lot(&self, l: &Lot, t: &Txn) -> AuthResult<bool> {
        let mut conn = self.pool.acquire().await?;
        let mut tx = conn.begin().await?;
        if !sql::record_txn(&mut tx, t).await? {
            return Ok(false);
        }
        sqlx::query("UPDATE security_wallet SET BALANCE = (BALANCE - ?) WHERE ID = ?").bind(t.tokens.to_string()).bind(l.wallet_id).execute(&mut *tx).await?;
        sqlx::query("UPDATE security_wallet_lot SET TOKENS_LEFT = 0 WHERE ID = ?").bind(l.id).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(true)
    }

    async fn set_status(&self, wallet_id: u64, status: &str) -> AuthResult<u64> {
        sql::set_status(&mut *self.pool.acquire().await?, wallet_id, status).await
    }

    async fn set_low_balance_notified(&self, wallet_id: u64, notified: bool) -> AuthResult<u64> {
        sql::set_low_balance_notified(&mut *self.pool.acquire().await?, wallet_id, notified).await
    }

    async fn sum_quantity_between(&self, wallet_id: u64, action_key: &str, from: NaiveDate, to: NaiveDate) -> AuthResult<Dec> {
        sql::sum_between(&mut *self.pool.acquire().await?, "QUANTITY", wallet_id, action_key, from, to).await
    }

    async fn sum_tokens_between(&self, wallet_id: u64, action_key: &str, from: NaiveDate, to: NaiveDate) -> AuthResult<Dec> {
        sql::sum_between(&mut *self.pool.acquire().await?, "TOKENS", wallet_id, action_key, from, to).await
    }

    async fn charged_windows(&self, wallet_id: u64, action_key: &str, date: NaiveDate) -> AuthResult<Vec<i16>> {
        sql::charged_windows(&mut *self.pool.acquire().await?, wallet_id, action_key, date).await
    }

    async fn txn_by_key(&self, wallet_id: u64, key: &str) -> AuthResult<Option<(Txn, NaiveDateTime)>> {
        let row = sqlx::query(
            "SELECT TYPE, CAST(TOKENS AS CHAR) TOKENS, CAST(BALANCE_AFTER AS CHAR) BALANCE_AFTER, ACTION_KEY, APP_ID, \
             CAST(QUANTITY AS CHAR) QUANTITY, CHARGE_DATE, IDEMPOTENCY_KEY, REASON, CREATED_AT \
             FROM security_wallet_transaction WHERE WALLET_ID = ? AND IDEMPOTENCY_KEY = ? LIMIT 1",
        )
        .bind(wallet_id)
        .bind(key)
        .fetch_optional(&self.pool)
        .await?;
        let Some(r) = row else { return Ok(None) };
        let kind: String = r.try_get("TYPE")?;
        let t = Txn {
            wallet_id,
            kind: crate::data::billing_admin::TXN_TYPES.iter().find(|k| **k == kind).copied().unwrap_or("DEBIT"),
            tokens: dec(&r, "TOKENS")?.unwrap_or(Dec::ZERO),
            balance_after: dec(&r, "BALANCE_AFTER")?.unwrap_or(Dec::ZERO),
            action_key: r.try_get("ACTION_KEY")?,
            app_id: r.try_get("APP_ID")?,
            quantity: dec(&r, "QUANTITY")?,
            charge_date: r.try_get("CHARGE_DATE")?,
            idempotency_key: r.try_get("IDEMPOTENCY_KEY")?,
            reason: r.try_get("REASON")?,
            ..Default::default()
        };
        Ok(Some((t, crate::mysql::ts(&r, "CREATED_AT")?.unwrap_or_default())))
    }

    async fn record_usage(&self, u: &Usage) -> AuthResult<bool> {
        sql::record_usage(&mut *self.pool.acquire().await?, u).await
    }

    async fn usage_by_reference(&self, meter_id: u64, client_id: u64, reference: &str) -> AuthResult<Option<(Usage, NaiveDateTime)>> {
        let row = sqlx::query(
            "SELECT APP_ID, USAGE_DATE, CAST(QUANTITY AS CHAR) QUANTITY, CREATED_AT FROM security_usage_record \
             WHERE METER_ID = ? AND CLIENT_ID = ? AND UNIQUE_KEY = ? LIMIT 1",
        )
        .bind(meter_id)
        .bind(client_id)
        .bind(format!("ev:{reference}"))
        .fetch_optional(&self.pool)
        .await?;
        let Some(r) = row else { return Ok(None) };
        let u = Usage {
            client_id,
            app_id: r.try_get("APP_ID")?,
            meter_id,
            date: r.try_get("USAGE_DATE")?,
            kind: "EVENT",
            quantity: dec(&r, "QUANTITY")?.unwrap_or(Dec::ZERO),
            figures: None,
            reference: Some(reference.to_string()),
        };
        Ok(Some((u, crate::mysql::ts(&r, "CREATED_AT")?.unwrap_or_default())))
    }

    async fn period_usage(&self, meter_id: u64, client_id: u64, from: NaiveDate, to: NaiveDate) -> AuthResult<PeriodUsage> {
        let rows = sqlx::query(
            "SELECT KIND, CAST(COALESCE(SUM(QUANTITY), 0) AS CHAR) Q, COUNT(*) N FROM security_usage_record \
             WHERE METER_ID = ? AND CLIENT_ID = ? AND USAGE_DATE >= ? AND USAGE_DATE < ? AND INVOICE_ID IS NULL GROUP BY KIND",
        )
        .bind(meter_id)
        .bind(client_id)
        .bind(from)
        .bind(to)
        .fetch_all(&self.pool)
        .await?;
        let mut p = PeriodUsage::default();
        for r in &rows {
            let kind: String = r.try_get("KIND")?;
            let q = dec(r, "Q")?.unwrap_or(Dec::ZERO);
            match kind.as_str() {
                "SNAPSHOT" => {
                    p.snapshot_sum = q;
                    p.snapshot_days = r.try_get("N")?;
                }
                "EVENT" => p.events = q,
                _ => p.reversals = q,
            }
        }
        Ok(p)
    }

    async fn mark_invoiced(&self, client_id: u64, app_id: u64, from: NaiveDate, to: NaiveDate, invoice_id: u64) -> AuthResult<u64> {
        let r = sqlx::query(
            "UPDATE security_usage_record SET INVOICE_ID = ? WHERE CLIENT_ID = ? AND APP_ID = ? AND USAGE_DATE >= ? AND USAGE_DATE < ? AND INVOICE_ID IS NULL",
        )
        .bind(invoice_id)
        .bind(client_id)
        .bind(app_id)
        .bind(from)
        .bind(to)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected())
    }

    async fn clients_with_usage(&self, config_id: u64, before: NaiveDate) -> AuthResult<Vec<u64>> {
        let rows = sqlx::query(
            "SELECT DISTINCT u.CLIENT_ID FROM security_usage_record u JOIN security_billing_meter m ON m.ID = u.METER_ID \
             WHERE m.BILLING_CONFIG_ID = ? AND u.USAGE_DATE < ? AND u.INVOICE_ID IS NULL ORDER BY u.CLIENT_ID",
        )
        .bind(config_id)
        .bind(before)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(|r| Ok(r.try_get::<u64, _>(0)?)).collect()
    }

    async fn count_apps(&self, client_id: u64, app_type: &str, active_only: bool) -> AuthResult<i64> {
        let q = if active_only {
            "SELECT COUNT(*) FROM security_app WHERE CLIENT_ID = ? AND APP_TYPE = ? AND STATUS = 'ACTIVE'"
        } else {
            "SELECT COUNT(*) FROM security_app WHERE CLIENT_ID = ? AND APP_TYPE = ?"
        };
        Ok(sqlx::query_scalar(q).bind(client_id).bind(app_type).fetch_one(&self.pool).await?)
    }

    async fn count_users_with_profile(&self, client_id: u64, app_id: u64, profile_ids: &[u64]) -> AuthResult<i64> {
        let mut qb = sqlx::QueryBuilder::<sqlx::MySql>::new(
            "SELECT COUNT(DISTINCT security_user.ID) FROM security_user \
             JOIN security_profile_user ON security_profile_user.USER_ID = security_user.ID \
             JOIN security_profile ON security_profile.ID = security_profile_user.PROFILE_ID \
             WHERE security_user.CLIENT_ID = ",
        );
        qb.push_bind(client_id).push(" AND security_profile.APP_ID = ").push_bind(app_id);
        qb.push(" AND security_user.STATUS_CODE = 'ACTIVE'");
        if !profile_ids.is_empty() {
            qb.push(" AND (security_profile.ID IN (");
            let mut s = qb.separated(", ");
            for p in profile_ids {
                s.push_bind(*p);
            }
            qb.push(") OR security_profile.ROOT_PROFILE_ID IN (");
            let mut s = qb.separated(", ");
            for p in profile_ids {
                s.push_bind(*p);
            }
            qb.push("))");
        }
        Ok(qb.build_query_scalar().fetch_one(&self.pool).await?)
    }

    async fn ai_rates(&self) -> AuthResult<Vec<AiRate>> {
        let rows = sqlx::query(
            "SELECT MODEL_PATTERN, CAST(INPUT_PER_M AS CHAR) I, CAST(OUTPUT_PER_M AS CHAR) O, CAST(CACHE_READ_PER_M AS CHAR) R, \
             CAST(CACHE_WRITE_PER_M AS CHAR) W, CURRENCY FROM security_ai_model_rate WHERE STATUS = 'ACTIVE'",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok(AiRate {
                    pattern: r.try_get::<String, _>("MODEL_PATTERN")?.to_lowercase(),
                    input: dec(r, "I")?.unwrap_or(Dec::ZERO),
                    output: dec(r, "O")?.unwrap_or(Dec::ZERO),
                    cache_read: dec(r, "R")?.unwrap_or(Dec::ZERO),
                    cache_write: dec(r, "W")?.unwrap_or(Dec::ZERO),
                    currency: r.try_get::<String, _>("CURRENCY")?.trim().to_string(),
                })
            })
            .collect()
    }

    async fn setting(&self, name: &str) -> AuthResult<Option<String>> {
        Ok(sqlx::query_scalar("SELECT VALUE FROM security_billing_setting WHERE NAME = ?").bind(name).fetch_optional(&self.pool).await?)
    }

    async fn has_overdue_invoice(&self, client_id: u64, app_id: u64) -> AuthResult<bool> {
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM security_invoice WHERE CLIENT_ID = ? AND APP_ID = ? AND STATUS = 'OVERDUE'")
            .bind(client_id)
            .bind(app_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(n > 0)
    }

    async fn buyer_profile(&self, client_id: u64, app_id: u64) -> AuthResult<Option<Rec>> {
        let c = &mut *self.pool.acquire().await?;
        let f = Find { first: true, ..Find::eq(vec![("CLIENT_ID", Val::Id(client_id)), ("APP_ID", Val::Id(app_id))]) };
        Ok(admin_sql::find(c, &PROFILE, &f).await?.into_iter().next())
    }

    async fn insert_monthly_invoice(&self, invoice: &Rec, lines: &[Rec], fin_year: &str) -> AuthResult<Option<Rec>> {
        let mut conn = self.pool.acquire().await?;
        let mut tx = conn.begin().await?;
        let taken: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM security_invoice WHERE PERIOD_KEY = ?")
            .bind(invoice.str("periodKey").unwrap_or(""))
            .fetch_one(&mut *tx)
            .await?;
        if taken > 0 {
            return Ok(None);
        }
        let seller = invoice.u64("sellerClientId").unwrap_or(0);
        let number = admin_sql::next_invoice_number(&mut tx, seller, fin_year).await?;
        let mut inv = invoice.clone();
        inv.set("invoiceNumber", Val::Str(number));
        let id = admin_sql::insert(&mut tx, &inv).await?;
        for l in lines {
            let mut l = l.clone();
            l.set("invoiceId", Val::Id(id));
            admin_sql::insert(&mut tx, &l).await?;
        }
        let saved = admin_sql::by_id(&mut tx, &INVOICE, id).await?;
        tx.commit().await?;
        Ok(saved)
    }

    async fn invoices_past_due(&self, day: NaiveDate) -> AuthResult<Vec<Rec>> {
        let c = &mut *self.pool.acquire().await?;
        let all = admin_sql::find(c, &INVOICE, &Find::eq(vec![("STATUS", Val::Str("PENDING".into())), ("KIND", Val::Str("MONTHLY".into()))])).await?;
        Ok(all.into_iter().filter(|i| i.date_of("dueDate").is_some_and(|d| d < day)).collect())
    }

    async fn set_invoice_status(&self, invoice_id: u64, status: &str) -> AuthResult<u64> {
        let r = sqlx::query("UPDATE security_invoice SET STATUS = ? WHERE ID = ?").bind(status).bind(invoice_id).execute(&self.pool).await?;
        Ok(r.rows_affected())
    }

    async fn earliest_unbilled(&self, client_id: u64, app_id: u64) -> AuthResult<Option<NaiveDate>> {
        Ok(sqlx::query_scalar("SELECT MIN(USAGE_DATE) FROM security_usage_record WHERE CLIENT_ID = ? AND APP_ID = ? AND INVOICE_ID IS NULL")
            .bind(client_id)
            .bind(app_id)
            .fetch_one(&self.pool)
            .await?)
    }

    async fn gauge_month_units(&self, meter_id: u64, client_id: u64, from: NaiveDate, to: NaiveDate, free: Dec) -> AuthResult<Dec> {
        let s: Option<String> = sqlx::query_scalar(
            "SELECT CAST(COALESCE(SUM(GREATEST(QUANTITY - CAST(? AS DECIMAL(19,6)), 0) * 1000000 / DAY(LAST_DAY(USAGE_DATE))), 0) / 1000000 AS CHAR) \
             FROM security_usage_record WHERE METER_ID = ? AND CLIENT_ID = ? AND KIND = 'SNAPSHOT' AND USAGE_DATE >= ? AND USAGE_DATE < ? \
             AND INVOICE_ID IS NULL",
        )
        .bind(free.to_string())
        .bind(meter_id)
        .bind(client_id)
        .bind(from)
        .bind(to)
        .fetch_one(&self.pool)
        .await?;
        Ok(s.as_deref().and_then(Dec::parse).unwrap_or(Dec::ZERO).round_down(6))
    }
}

/// The wallet statements on one connection, so a test can run them inside a transaction it rolls
/// back, and a charge can run them inside one transaction.
pub mod sql {
    use chrono::NaiveDate;
    use sqlx::{MySqlConnection, Row};

    use super::{lot as lot_row, wallet as wallet_row, Lot, NewLot, Txn, Usage, Wallet, LOT_COLUMNS, WALLET_COLUMNS};
    use crate::decimal::Dec;
    use crate::errors::AuthResult;

    /// `WalletDAO.findByClientAndApp`.
    pub async fn wallet(c: &mut MySqlConnection, client_id: u64, app_id: u64) -> AuthResult<Option<Wallet>> {
        let sql = format!("SELECT {WALLET_COLUMNS} FROM security_wallet WHERE CLIENT_ID = ? AND APP_ID = ? LIMIT 1");
        let row = sqlx::query(&sql).bind(client_id).bind(app_id).fetch_optional(&mut *c).await?;
        row.as_ref().map(wallet_row).transpose()
    }

    /// Insert if absent (a race loses quietly): true when this call inserted it.
    pub async fn create_seeded_wallet(c: &mut MySqlConnection, client_id: u64, app_id: u64, initial: Dec) -> AuthResult<bool> {
        let r = sqlx::query(
            "INSERT IGNORE INTO security_wallet (CLIENT_ID, APP_ID, BALANCE, STATUS, LOW_BALANCE_NOTIFIED, VERSION) \
             VALUES (?, ?, ?, 'ACTIVE', 0, 0)",
        )
        .bind(client_id)
        .bind(app_id)
        .bind(initial.to_string())
        .execute(&mut *c)
        .await?;
        Ok(r.rows_affected() > 0)
    }

    /// `WalletTransactionDAO.recordTxn`: false when the idempotency key was already used.
    pub async fn record_txn(c: &mut MySqlConnection, t: &Txn) -> AuthResult<bool> {
        let r = sqlx::query(
            "INSERT IGNORE INTO security_wallet_transaction (WALLET_ID, TYPE, TOKENS, BALANCE_AFTER, ACTION_KEY, APP_ID, \
             QUANTITY, CHARGE_DATE, WINDOW_INDEX, IDEMPOTENCY_KEY, REFERENCE_TYPE, REFERENCE_ID, REASON, DESCRIPTION, CREATED_BY) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
        .bind(t.reference_type.clone())
        .bind(t.reference_id)
        .bind(t.reason.clone())
        .bind(t.description.clone())
        .bind(t.created_by)
        .execute(&mut *c)
        .await?;
        Ok(r.rows_affected() > 0)
    }

    /// The wallet's lots with credits left, soonest expiry first (never-expiring last), oldest first.
    pub async fn open_lots(c: &mut MySqlConnection, wallet_id: u64) -> AuthResult<Vec<Lot>> {
        let q = format!(
            "SELECT {LOT_COLUMNS} FROM security_wallet_lot WHERE WALLET_ID = ? AND TOKENS_LEFT > 0 \
             ORDER BY EXPIRES_AT IS NULL, EXPIRES_AT, ID"
        );
        sqlx::query(&q).bind(wallet_id).fetch_all(&mut *c).await?.iter().map(lot_row).collect()
    }

    /// How a debit draws on lots: soonest expiry first, each down to zero before the next.
    pub fn draw(lots: &[Lot], tokens: Dec) -> Vec<(u64, Dec)> {
        let mut left = tokens;
        let mut out = Vec::new();
        for l in lots {
            if left.signum() <= 0 {
                break;
            }
            let take = if l.tokens_left.cmp_value(&left) == std::cmp::Ordering::Less { l.tokens_left } else { left };
            out.push((l.id, l.tokens_left.sub(take)));
            left = left.sub(take);
        }
        out
    }

    /// The ledger row, then the balance, then the lots: nothing when the key was used.
    pub async fn debit_with_lots(c: &mut MySqlConnection, t: &Txn) -> AuthResult<bool> {
        if !record_txn(&mut *c, t).await? {
            return Ok(false);
        }
        sqlx::query("UPDATE security_wallet SET BALANCE = (BALANCE - ?) WHERE ID = ?")
            .bind(t.tokens.to_string())
            .bind(t.wallet_id)
            .execute(&mut *c)
            .await?;
        let lots = open_lots(&mut *c, t.wallet_id).await?;
        for (id, left) in draw(&lots, t.tokens) {
            sqlx::query("UPDATE security_wallet_lot SET TOKENS_LEFT = ? WHERE ID = ?").bind(left.to_string()).bind(id).execute(&mut *c).await?;
        }
        Ok(true)
    }

    /// The ledger row, then the balance, then a lot of what is left after the debt is paid.
    pub async fn credit_with_lot(c: &mut MySqlConnection, t: &Txn, lot: &NewLot) -> AuthResult<bool> {
        let before: Option<String> = sqlx::query_scalar("SELECT CAST(BALANCE AS CHAR) FROM security_wallet WHERE ID = ? FOR UPDATE")
            .bind(t.wallet_id)
            .fetch_optional(&mut *c)
            .await?;
        if !record_txn(&mut *c, t).await? {
            return Ok(false);
        }
        sqlx::query("UPDATE security_wallet SET BALANCE = (BALANCE + ?) WHERE ID = ?")
            .bind(t.tokens.to_string())
            .bind(t.wallet_id)
            .execute(&mut *c)
            .await?;
        let before = before.as_deref().and_then(Dec::parse).unwrap_or(Dec::ZERO);
        let debt = Dec::ZERO.sub(before).max(Dec::ZERO);
        let kept = t.tokens.sub(debt);
        if kept.signum() > 0 {
            sqlx::query(
                "INSERT INTO security_wallet_lot (WALLET_ID, SOURCE, REFERENCE_TYPE, REFERENCE_ID, TOKENS_ADDED, TOKENS_LEFT, EXPIRES_AT) \
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(t.wallet_id)
            .bind(lot.source)
            .bind(lot.reference_type.clone())
            .bind(lot.reference_id)
            .bind(kept.to_string())
            .bind(kept.to_string())
            .bind(lot.expires_at)
            .execute(&mut *c)
            .await?;
        }
        Ok(true)
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

    /// The sum of a ledger column over the action's rows charged between the days.
    pub async fn sum_between(c: &mut MySqlConnection, column: &str, wallet_id: u64, action_key: &str, from: NaiveDate, to: NaiveDate) -> AuthResult<Dec> {
        let column = if column == "TOKENS" { "TOKENS" } else { "QUANTITY" };
        let q = format!(
            "SELECT CAST(COALESCE(SUM({column}), 0) AS CHAR) FROM security_wallet_transaction \
             WHERE WALLET_ID = ? AND ACTION_KEY = ? AND TYPE = 'DEBIT' AND CHARGE_DATE BETWEEN ? AND ?"
        );
        let s: Option<String> = sqlx::query_scalar(&q).bind(wallet_id).bind(action_key).bind(from).bind(to).fetch_one(&mut *c).await?;
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

    /// A usage record; a day's snapshot keeps its highest count.
    pub async fn record_usage(c: &mut MySqlConnection, u: &Usage) -> AuthResult<bool> {
        let figures = u.figures.as_ref().map(|f| serde_json::Value::Object(f.clone()).to_string());
        let snapshot = u.kind == "SNAPSHOT";
        let q = if snapshot {
            "INSERT INTO security_usage_record (CLIENT_ID, APP_ID, METER_ID, USAGE_DATE, KIND, QUANTITY, FIGURES, REFERENCE, UNIQUE_KEY) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE QUANTITY = GREATEST(QUANTITY, VALUES(QUANTITY))"
        } else {
            "INSERT IGNORE INTO security_usage_record (CLIENT_ID, APP_ID, METER_ID, USAGE_DATE, KIND, QUANTITY, FIGURES, REFERENCE, UNIQUE_KEY) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        };
        let r = sqlx::query(q)
            .bind(u.client_id)
            .bind(u.app_id)
            .bind(u.meter_id)
            .bind(u.date)
            .bind(u.kind)
            .bind(u.quantity.to_string())
            .bind(figures)
            .bind(u.reference.clone())
            .bind(u.unique_key())
            .execute(&mut *c)
            .await?;
        Ok(snapshot || r.rows_affected() > 0)
    }
}

#[cfg(test)]
mod store_tests {
    use super::*;
    use serde_json::json;

    fn d(s: &str) -> Dec {
        Dec::parse(s).unwrap()
    }

    fn lot(id: u64, left: &str) -> Lot {
        Lot { id, wallet_id: 1, source: "PLAN".into(), tokens_added: d(left), tokens_left: d(left), added_at: NaiveDateTime::default(), expires_at: None }
    }

    #[test]
    fn a_debit_draws_the_soonest_lots_first() {
        let lots = [lot(1, "3"), lot(2, "10"), lot(3, "5")];
        assert_eq!(sql::draw(&lots, d("5")), vec![(1, d("0")), (2, d("8"))]);
        assert_eq!(sql::draw(&lots, d("3")), vec![(1, d("0"))]);
        // More than the lots hold: all go to zero, the balance goes negative.
        assert_eq!(sql::draw(&lots, d("30")).iter().map(|x| x.1.signum()).collect::<Vec<_>>(), vec![0, 0, 0]);
        assert!(sql::draw(&lots, Dec::ZERO).is_empty());
    }

    #[test]
    fn plan_overrides_and_models() {
        let o = parse_overrides(json!({"users": {"free": 2, "hardCap": true}, "leads": {"rate": "0.5"}, "bad": 1}).as_object().unwrap());
        assert_eq!(o.len(), 2);
        let listed = parse_overrides(json!({"limits": [{"meterKey": "users", "free": 2, "hardCap": true}, {"meterKey": "", "free": 1}, {"free": 3}]}).as_object().unwrap());
        assert_eq!(listed.len(), 1);
        assert_eq!(listed["users"], MeterOverride { free: Some(d("2")), rate: None, hard_cap: true });
        let users = Meter { key: "users".into(), free: d("5"), rate: d("1000"), ..Default::default() };
        let leads = Meter { key: "leads".into(), free: d("100"), rate: d("1"), ..Default::default() };
        let p = Plan { overrides: o, ..Default::default() };
        assert_eq!(terms(&users, Some(&p)), Terms { free: d("2"), rate: d("1000"), hard_cap: Some(d("2")) });
        assert_eq!(terms(&leads, Some(&p)), Terms { free: d("100"), rate: d("0.5"), hard_cap: None });
        assert_eq!(terms(&users, None), Terms { free: d("5"), rate: d("1000"), hard_cap: None });
        let p = Plan { ai_models: parse_models(json!({"patterns": ["deepseek", " haiku ", ""]}).as_object().unwrap()), ..Default::default() };
        assert_eq!(p.ai_models, vec!["deepseek", "haiku"]);
        assert!(p.allows_model("DeepSeek-V4-Flash") && p.allows_model("claude-haiku-5-5") && !p.allows_model("claude-opus-5-5"));
        assert!(Plan::default().allows_model("anything"));
    }

    #[test]
    fn usage_keys_and_sources() {
        let u = Usage {
            client_id: 1,
            app_id: 2,
            meter_id: 3,
            date: NaiveDate::from_ymd_opt(2026, 11, 14).unwrap(),
            kind: "SNAPSHOT",
            quantity: d("4"),
            figures: None,
            reference: None,
        };
        assert_eq!(u.unique_key(), "snap:2026-11-14");
        assert_eq!(Usage { kind: "EVENT", reference: Some("L1".into()), ..u.clone() }.unique_key(), "ev:L1");
        assert_eq!(Usage { kind: "REVERSAL", reference: Some("L1".into()), ..u }.unique_key(), "rev:L1");
        assert_eq!((action::source(action::FILES_GB), action::source("nope")), (Some("FILES_GB"), None));
        assert_eq!(Meter { key: "users".into(), ..Default::default() }.action_key("crm"), "crm.users");
    }
}
