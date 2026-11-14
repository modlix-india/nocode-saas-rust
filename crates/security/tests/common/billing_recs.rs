//! The billing rows as the admin schemas hold them, read as security-internal's rule types (and
//! back), for the in-memory and the rolled-back billing stores of the tests.

#![allow(dead_code)]

use security::data::billing::{parse_models, parse_overrides, BillingConfig, Lot, Meter, Plan, Txn, Wallet, WalletPlan};
use security::data::billing_admin::{Rec, Val, TXN, WALLET_PLAN};
use security::decimal::Dec;

pub fn cfg_of(r: &Rec) -> BillingConfig {
    BillingConfig {
        id: r.id().unwrap_or(0),
        client_id: r.u64("clientId").unwrap_or(0),
        app_id: r.u64("appId").unwrap_or(0),
        gst_percentage: r.dec("gstPercentage").unwrap_or(Dec::ZERO),
        low_balance_threshold: r.dec("lowBalanceThreshold"),
        suspend_app_code: r.str("suspendAppCode").map(str::to_string),
        suspend_client_code: r.str("suspendClientCode").map(str::to_string),
        suspend_mode: r.str("suspendMode").unwrap_or("AI_AND_BANNER").to_string(),
        purchased_credit_validity_months: r.int("purchasedCreditValidityMonths"),
        invoice_day: r.int("invoiceDay").unwrap_or(1) as u32,
        invoice_due_days: r.int("invoiceDueDays").unwrap_or(15) as u32,
        currency: r.str("currency").unwrap_or("INR").to_string(),
        status: r.str("status").unwrap_or("ACTIVE").to_string(),
    }
}

pub fn wallet_rule(r: &Rec) -> Wallet {
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

pub fn meter_of(r: &Rec) -> Meter {
    Meter {
        id: r.id().unwrap_or(0),
        config_id: r.u64("billingConfigId").unwrap_or(0),
        key: r.str("meterKey").unwrap_or("").to_string(),
        label: r.str("label").unwrap_or("").to_string(),
        unit_label: r.str("unitLabel").map(str::to_string),
        kind: r.str("kind").unwrap_or("GAUGE").to_string(),
        source: r.str("source").unwrap_or("").to_string(),
        source_config: r.map("sourceConfig"),
        rate: r.dec("rate").unwrap_or(Dec::ZERO),
        rate_unit: r.str("rateUnit").unwrap_or("MONTH").to_string(),
        free: r.dec("freeQuantity").unwrap_or(Dec::ZERO),
        charge_mode: r.str("chargeMode").unwrap_or("TOKENS").to_string(),
        refund_policy: r.str("refundPolicy").unwrap_or("NONE").to_string(),
        refund_days: r.int("refundDays"),
        basis: r.str("basis").map(str::to_string),
        display_order: r.int("displayOrder").unwrap_or(0),
        status: r.str("status").unwrap_or("ACTIVE").to_string(),
    }
}

pub fn plan_of(r: &Rec) -> Plan {
    Plan {
        id: r.id().unwrap_or(0),
        config_id: r.u64("billingConfigId").unwrap_or(0),
        code: r.str("code").unwrap_or("").to_string(),
        label: r.str("label").unwrap_or("").to_string(),
        period: r.str("period").unwrap_or("MONTH").to_string(),
        payment_mode: r.str("paymentMode").unwrap_or("INVOICE").to_string(),
        price_tokens: r.dec("priceTokens").unwrap_or(Dec::ZERO),
        price_amount: r.dec("priceAmount").unwrap_or(Dec::ZERO),
        currency: r.str("currency").unwrap_or("INR").to_string(),
        included_tokens: r.dec("includedTokens").unwrap_or(Dec::ZERO),
        included_recurring: r.int("includedTokensRecurring") != Some(0),
        overrides: parse_overrides(&r.map("meterOverrides")),
        ai_models: parse_models(&r.map("aiModelsAllowed")),
        is_default: r.int("isDefault") == Some(1),
        status: r.str("status").unwrap_or("ACTIVE").to_string(),
    }
}

pub fn wallet_plan_of(r: &Rec) -> WalletPlan {
    WalletPlan {
        id: r.id().unwrap_or(0),
        wallet_id: r.u64("walletId").unwrap_or(0),
        plan_id: r.u64("planId").unwrap_or(0),
        period_start: r.date_of("periodStart").unwrap_or_default(),
        period_end: r.date_of("periodEnd").unwrap_or_default(),
        status: r.str("status").unwrap_or("ACTIVE").to_string(),
        auto_renew: r.int("autoRenew") != Some(0),
        next_plan_id: r.u64("nextPlanId"),
    }
}

pub fn wallet_plan_rec(wp: &WalletPlan) -> Rec {
    Rec::new(&WALLET_PLAN)
        .with("id", Val::Id(wp.id))
        .with("walletId", Val::Id(wp.wallet_id))
        .with("planId", Val::Id(wp.plan_id))
        .with("periodStart", Val::Date(wp.period_start))
        .with("periodEnd", Val::Date(wp.period_end))
        .with("status", Val::Str(wp.status.clone()))
        .with("autoRenew", Val::Int(i64::from(wp.auto_renew)))
        .with("nextPlanId", wp.next_plan_id.map(Val::Id).unwrap_or(Val::Null))
}

pub fn lot_of(r: &Rec) -> Lot {
    Lot {
        id: r.id().unwrap_or(0),
        wallet_id: r.u64("walletId").unwrap_or(0),
        source: r.str("source").unwrap_or("").to_string(),
        tokens_added: r.dec("tokensAdded").unwrap_or(Dec::ZERO),
        tokens_left: r.dec("tokensLeft").unwrap_or(Dec::ZERO),
        added_at: r.ts("addedAt").unwrap_or_default(),
        expires_at: r.ts("expiresAt"),
    }
}

pub fn txn_rec(t: &Txn) -> Rec {
    let s = |v: &Option<String>| v.clone().map(Val::Str).unwrap_or(Val::Null);
    Rec::new(&TXN)
        .with("walletId", Val::Id(t.wallet_id))
        .with("type", Val::Str(t.kind.into()))
        .with("tokens", Val::Dec(t.tokens))
        .with("balanceAfter", Val::Dec(t.balance_after))
        .with("actionKey", s(&t.action_key))
        .with("appId", t.app_id.map(Val::Id).unwrap_or(Val::Null))
        .with("quantity", t.quantity.map(Val::Dec).unwrap_or(Val::Null))
        .with("chargeDate", t.charge_date.map(Val::Date).unwrap_or(Val::Null))
        .with("windowIndex", t.window_index.map(|w| Val::Int(i64::from(w))).unwrap_or(Val::Null))
        .with("idempotencyKey", Val::Str(t.idempotency_key.clone()))
        .with("referenceType", s(&t.reference_type))
        .with("referenceId", t.reference_id.map(Val::Id).unwrap_or(Val::Null))
        .with("reason", Val::Str(t.reason.clone()))
        .with("description", s(&t.description))
        .with("createdBy", t.created_by.map(Val::Id).unwrap_or(Val::Null))
}
