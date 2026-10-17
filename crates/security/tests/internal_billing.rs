//! The wallet rules of security-internal, ported from `WalletServiceTest` and
//! `SecurityMeteringServiceTest` (which mock the DAOs; an in-memory billing store plays that
//! part here, so no real wallet is ever debited).

mod common;

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::NaiveDate;
use common::{app, harness, Harness, RecordingEvents};
use security::data::billing::{action, BillingConfig, BillingStore, Instruction, Txn, Wallet};
use security::data::Db;
use security::decimal::Dec;
use security::errors::{AuthError, AuthResult};
use security::internal::billing::{AiChargeRequest, ChargeRequest, WALLET_LOW_BALANCE, WALLET_SUSPENDED};
use security::internal::Internal;
use security::model::ContextAuth;

#[derive(Default)]
struct Books {
    configs: Vec<BillingConfig>,
    wallets: Vec<Wallet>,
    txns: Vec<Txn>,
    instructions: Vec<(String, Instruction)>,
    /// (client, type) -> count of apps; (client, app) -> users with a profile.
    app_counts: Vec<((u64, String), i64)>,
    user_counts: Vec<((u64, u64), i64)>,
    debits: Vec<(u64, Dec)>,
    statuses: Vec<(u64, String)>,
    notified: Vec<(u64, bool)>,
    /// `debit` touches no row.
    debit_misses: bool,
    fail_counts: bool,
}

#[derive(Default)]
struct FakeBilling {
    books: Mutex<Books>,
}

#[async_trait]
impl BillingStore for FakeBilling {
    async fn config_by_app_client(&self, app_id: u64, client_id: u64) -> AuthResult<Option<BillingConfig>> {
        let b = self.books.lock().unwrap();
        Ok(b.configs.iter().find(|c| c.app_id == app_id && c.client_id == client_id && c.status != "DELETED").cloned())
    }
    async fn config_by_codes(&self, app_code: &str, client_code: &str) -> AuthResult<Option<BillingConfig>> {
        let b = self.books.lock().unwrap();
        let ids = match (app_code, client_code) {
            ("crm", "SYSTEM") => Some((2, 1)),
            _ => None,
        };
        Ok(ids.and_then(|(a, c)| b.configs.iter().find(|x| x.app_id == a && x.client_id == c && x.status == "ACTIVE").cloned()))
    }
    async fn charge_instructions(&self, action_key: &str) -> AuthResult<Vec<Instruction>> {
        let b = self.books.lock().unwrap();
        Ok(b.instructions.iter().filter(|(a, _)| a == action_key).map(|(_, i)| i.clone()).collect())
    }
    async fn wallet(&self, client_id: u64, app_id: u64) -> AuthResult<Option<Wallet>> {
        Ok(self.books.lock().unwrap().wallets.iter().find(|w| w.client_id == client_id && w.app_id == app_id).cloned())
    }
    async fn create_seeded_wallet(&self, client_id: u64, app_id: u64, initial: Dec) -> AuthResult<Option<Wallet>> {
        let mut b = self.books.lock().unwrap();
        let id = 900 + b.wallets.len() as u64;
        b.wallets.push(Wallet { id, client_id, app_id, balance: initial, status: "ACTIVE".into(), alert_threshold: None, low_balance_notified: Some(0) });
        Ok(b.wallets.last().cloned())
    }
    async fn record_txn(&self, t: &Txn) -> AuthResult<bool> {
        let mut b = self.books.lock().unwrap();
        if b.txns.iter().any(|x| x.wallet_id == t.wallet_id && x.idempotency_key == t.idempotency_key) {
            return Ok(false);
        }
        b.txns.push(t.clone());
        Ok(true)
    }
    async fn debit(&self, wallet_id: u64, tokens: Dec) -> AuthResult<u64> {
        let mut b = self.books.lock().unwrap();
        if b.debit_misses {
            return Ok(0);
        }
        b.debits.push((wallet_id, tokens));
        if let Some(w) = b.wallets.iter_mut().find(|w| w.id == wallet_id) {
            w.balance = w.balance.sub(tokens);
        }
        Ok(1)
    }
    async fn set_status(&self, wallet_id: u64, status: &str) -> AuthResult<u64> {
        let mut b = self.books.lock().unwrap();
        b.statuses.push((wallet_id, status.to_string()));
        Ok(1)
    }
    async fn set_low_balance_notified(&self, wallet_id: u64, notified: bool) -> AuthResult<u64> {
        self.books.lock().unwrap().notified.push((wallet_id, notified));
        Ok(1)
    }
    async fn sum_quantity_between(&self, wallet_id: u64, action_key: &str, from: NaiveDate, to: NaiveDate) -> AuthResult<Dec> {
        let b = self.books.lock().unwrap();
        Ok(b.txns
            .iter()
            .filter(|t| t.wallet_id == wallet_id && t.action_key.as_deref() == Some(action_key))
            .filter(|t| t.charge_date.is_some_and(|d| d >= from && d <= to))
            .fold(Dec::ZERO, |acc, t| acc.add(t.quantity.unwrap_or(Dec::ZERO))))
    }
    async fn charged_windows(&self, wallet_id: u64, action_key: &str, date: NaiveDate) -> AuthResult<Vec<i16>> {
        let b = self.books.lock().unwrap();
        Ok(b.txns
            .iter()
            .filter(|t| t.wallet_id == wallet_id && t.action_key.as_deref() == Some(action_key) && t.charge_date == Some(date))
            .filter_map(|t| t.window_index)
            .collect())
    }
    async fn count_apps(&self, client_id: u64, app_type: &str) -> AuthResult<i64> {
        let b = self.books.lock().unwrap();
        if b.fail_counts {
            return Err(AuthError::internal("count failed"));
        }
        Ok(b.app_counts.iter().find(|(k, _)| k.0 == client_id && k.1 == app_type).map(|(_, n)| *n).unwrap_or(0))
    }
    async fn count_users_with_profile(&self, client_id: u64, app_id: u64) -> AuthResult<i64> {
        let b = self.books.lock().unwrap();
        Ok(b.user_counts.iter().find(|(k, _)| *k == (client_id, app_id)).map(|(_, n)| *n).unwrap_or(0))
    }
}

/// The SYSTEM client, the BUS client (2) it manages, and the crm app (2) BUS owns, billed by
/// SYSTEM's config.
const C_CLIENT: u64 = 1;
const M_CLIENT: u64 = 2;
const APP: u64 = 2;

fn d(s: &str) -> Dec {
    Dec::parse(s).unwrap()
}

fn config() -> BillingConfig {
    BillingConfig { id: 1, client_id: C_CLIENT, app_id: APP, status: "ACTIVE".into(), ..Default::default() }
}

fn wallet(balance: &str, status: &str, notified: i8) -> Wallet {
    Wallet { id: 7, client_id: M_CLIENT, app_id: APP, balance: d(balance), status: status.into(), alert_threshold: None, low_balance_notified: Some(notified) }
}

struct World {
    h: Harness,
    books: Arc<FakeBilling>,
    events: Arc<RecordingEvents>,
    internal: Internal,
}

fn world() -> World {
    let h = harness();
    h.store.with(|d| {
        d.apps.push(app(4, 1, "sitezump"));
        d.apps[3].app_type = Some("SITE".into());
        d.apps[1].app_type = Some("APP".into());
        d.apps.push(app(5, 1, "site1"));
        d.apps[4].app_type = Some("SITE".into());
    });
    let books = Arc::new(FakeBilling::default());
    let events = Arc::new(RecordingEvents::default());
    // A pool that cannot connect: the app URL of a wallet event is then unresolvable, which the
    // event tolerates.
    let pool = sqlx::mysql::MySqlPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(300))
        .connect_lazy("mysql://nobody:nothing@127.0.0.1:1/security")
        .unwrap();
    let internal = Internal { auth: h.auth.clone(), db: Db::new(pool), billing: books.clone(), wallet_events: events.clone() };
    World { h, books, events, internal }
}

fn system() -> ContextAuth {
    ContextAuth { client_type_code: Some("SYS".into()), ..Default::default() }
}

/// June 2026: 30 days of 96 windows.
const WINDOWS_IN_JUNE: i64 = 2880;

fn req(quantity: &str, action_key: &str) -> ChargeRequest {
    ChargeRequest {
        config_client_id: Some(C_CLIENT),
        billed_client_id: Some(M_CLIENT),
        app_id: Some(APP),
        action_key: Some(action_key.into()),
        quantity: Some(d(quantity)),
        date: NaiveDate::from_ymd_opt(2026, 6, 15),
        window_index: Some(7),
    }
}

#[tokio::test]
async fn charges_floored_prorated_tokens_above_free_quota() {
    let w = world();
    {
        let mut b = w.books.books.lock().unwrap();
        b.configs.push(BillingConfig { user_tokens_per_month: Some(Dec::from_i64(WINDOWS_IN_JUNE)), free_users: Some(d("3")), ..config() });
        b.wallets.push(wallet("100", "ACTIVE", 0));
    }
    let r = w.internal.charge(&system(), &req("5", action::USER)).await.unwrap();
    assert!(r.charged && !r.suspended);
    assert_eq!(r.balance_after.to_string(), "98");
    let b = w.books.books.lock().unwrap();
    assert_eq!(b.debits, vec![(7, d("2"))]);
    let t = &b.txns[0];
    assert_eq!((t.kind, t.idempotency_key.as_str(), t.reason.as_str()), ("DEBIT", "security.user:2026-06-15:7", "Metered security.user window 7"));
    assert_eq!((t.window_index, t.app_id, t.quantity.unwrap().to_string()), (Some(7), Some(APP), "5".to_string()));
}

#[tokio::test]
async fn floors_to_zero_no_rate_no_config_and_missing_fields_charge_nothing() {
    let w = world();
    w.books.books.lock().unwrap().configs.push(BillingConfig { user_tokens_per_month: Some(d("100")), ..config() });
    assert!(!w.internal.charge(&system(), &req("1", action::USER)).await.unwrap().charged);
    assert!(!w.internal.charge(&system(), &req("100", action::APP_RENT)).await.unwrap().charged);
    let mut other = req("100", action::USER);
    other.config_client_id = Some(99);
    assert!(!w.internal.charge(&system(), &other).await.unwrap().charged);
    other.app_id = None;
    assert!(!w.internal.charge(&system(), &other).await.unwrap().charged);
    // A request without its quantity, date or billed client fails, and the bulk charge skips it.
    for broken in [
        ChargeRequest { quantity: None, ..req("1", action::USER) },
        ChargeRequest { date: None, ..req("1", action::USER) },
    ] {
        assert!(w.internal.charge(&system(), &broken).await.is_err());
    }
    w.books.books.lock().unwrap().configs[0].user_tokens_per_month = Some(Dec::from_i64(WINDOWS_IN_JUNE));
    assert!(w.internal.charge(&system(), &ChargeRequest { billed_client_id: None, ..req("1", action::USER) }).await.is_err());
    w.internal.charge_bulk(&system(), &[ChargeRequest { quantity: None, ..req("1", action::USER) }]).await;
    assert!(w.books.books.lock().unwrap().debits.is_empty());
}

#[tokio::test]
async fn duplicate_window_does_not_double_debit_and_a_missed_debit_reports_nothing() {
    let w = world();
    {
        let mut b = w.books.books.lock().unwrap();
        b.configs.push(BillingConfig { user_tokens_per_month: Some(Dec::from_i64(WINDOWS_IN_JUNE)), ..config() });
        b.wallets.push(wallet("100", "ACTIVE", 0));
    }
    assert!(w.internal.charge(&system(), &req("5", action::USER)).await.unwrap().charged);
    let again = w.internal.charge(&system(), &req("5", action::USER)).await.unwrap();
    assert!(!again.charged);
    assert_eq!(w.books.books.lock().unwrap().debits.len(), 1);
    // The ledger row went in but the balance update touched nothing.
    w.books.books.lock().unwrap().debit_misses = true;
    let mut next = req("5", action::USER);
    next.window_index = Some(8);
    let r = w.internal.charge(&system(), &next).await.unwrap();
    assert!(!r.charged && !r.suspended);
}

fn alerting(w: &World, balance: &str, status: &str, notified: i8, threshold: Option<&str>) {
    let mut b = w.books.books.lock().unwrap();
    b.configs.push(BillingConfig {
        user_tokens_per_month: Some(Dec::from_i64(WINDOWS_IN_JUNE * 30)),
        low_balance_threshold: threshold.map(d),
        ..config()
    });
    b.wallets.push(wallet(balance, status, notified));
}

#[tokio::test]
async fn low_balance_fires_once_on_the_downward_crossing() {
    let w = world();
    alerting(&w, "420", "ACTIVE", 0, Some("400"));
    let r = w.internal.charge(&system(), &req("1", action::USER)).await.unwrap();
    assert!(r.low_balance_crossed && !r.suspended);
    assert_eq!(r.balance_after.to_string(), "390");
    let events = w.events.events.lock().unwrap();
    assert_eq!(events.len(), 1);
    let e = &events[0];
    assert_eq!((e.event_name.as_str(), e.client_code.as_deref(), e.app_code.as_deref()), (WALLET_LOW_BALANCE, Some("BUS"), Some("crm")));
    let data: std::collections::HashMap<_, _> = e.data.iter().cloned().collect();
    assert_eq!(data["balance"], serde_json::json!(390));
    assert_eq!(data["clientCode"], "BUS");
    // walletEventStillRaisedWhenAppUrlCannotBeResolved: the URL is empty, not missing.
    assert_eq!(data["urlPrefix"], "");
    assert_eq!(w.books.books.lock().unwrap().notified, vec![(7, true)]);
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
    assert_eq!(w.books.books.lock().unwrap().statuses, vec![(7, "SUSPENDED".to_string())]);
    assert_eq!(w.events.events.lock().unwrap()[0].event_name, WALLET_SUSPENDED);
}

#[tokio::test]
async fn an_already_suspended_wallet_is_still_debited_without_a_new_event() {
    let w = world();
    alerting(&w, "-5", "SUSPENDED", 0, None);
    let r = w.internal.charge(&system(), &req("1", action::USER)).await.unwrap();
    assert!(r.charged && r.suspended);
    assert_eq!(r.balance_after.to_string(), "-35");
    assert!(w.books.books.lock().unwrap().statuses.is_empty());
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

#[tokio::test]
async fn get_or_create_seeds_one_token_when_absent() {
    let w = world();
    w.books.books.lock().unwrap().configs.push(BillingConfig { user_tokens_per_month: Some(Dec::from_i64(WINDOWS_IN_JUNE)), ..config() });
    let r = w.internal.charge(&system(), &req("1", action::USER)).await.unwrap();
    // One seeded token, one token charged: zero left.
    assert!(r.charged);
    assert_eq!(r.balance_after.to_string(), "0");
    assert_eq!(w.books.books.lock().unwrap().wallets[0].client_id, M_CLIENT);
}

fn ai(tokens: &str, request: &str) -> AiChargeRequest {
    AiChargeRequest {
        client_code: Some("BUS".into()),
        app_code: Some("crm".into()),
        model: Some("m".into()),
        weighted_tokens: Some(d(tokens)),
        request_id: Some(request.into()),
        session_id: None,
    }
}

#[tokio::test]
async fn charge_ai_prices_per_million_after_the_grant() {
    let w = world();
    {
        let mut b = w.books.books.lock().unwrap();
        b.configs.push(BillingConfig { ai_tokens_per_million: Some(d("100")), free_ai_tokens_per_month: Some(d("1000000")), ..config() });
        b.wallets.push(wallet("1000", "ACTIVE", 0));
    }
    // Inside the grant: recorded with zero tokens, nothing debited.
    let r = w.internal.charge_ai(&system(), &ai("600000", "r1")).await.unwrap();
    assert!(!r.charged);
    assert_eq!(r.balance_after.to_string(), "1000");
    // Straddling the grant: 600k used, this call 1M, 600k billable at 100 per million: 60.
    let r = w.internal.charge_ai(&system(), &ai("1000000", "r2")).await.unwrap();
    assert!(r.charged);
    assert_eq!(r.balance_after.to_string(), "940");
    let b = w.books.books.lock().unwrap();
    assert_eq!(b.txns.len(), 2);
    assert_eq!((b.txns[0].tokens.to_string(), b.txns[0].idempotency_key.as_str()), ("0".into(), "ai:r1"));
    assert_eq!(b.txns[1].reason, "AI usage m");
}

#[tokio::test]
async fn charge_ai_charges_nothing_without_an_active_priced_config() {
    let w = world();
    // No config at all (and an unknown app or client).
    assert!(!w.internal.charge_ai(&system(), &ai("10", "a")).await.unwrap().charged);
    assert!(!w.internal.charge_ai(&system(), &AiChargeRequest { app_code: Some("nope".into()), ..ai("10", "a") }).await.unwrap().charged);
    assert!(!w.internal.charge_ai(&system(), &AiChargeRequest { client_code: Some("NOPE".into()), ..ai("10", "a") }).await.unwrap().charged);
    assert!(!w.internal.charge_ai(&system(), &AiChargeRequest { client_code: None, app_code: None, ..ai("10", "a") }).await.unwrap().charged);
    // Paused config.
    w.books.books.lock().unwrap().configs.push(BillingConfig { ai_tokens_per_million: Some(d("100")), status: "INACTIVE".into(), ..config() });
    assert!(!w.internal.charge_ai(&system(), &ai("10000000", "b")).await.unwrap().charged);
    // Active but no AI rate.
    w.books.books.lock().unwrap().configs[0] = BillingConfig { ai_tokens_per_million: Some(Dec::ZERO), ..config() };
    assert!(!w.internal.charge_ai(&system(), &ai("10000000", "c")).await.unwrap().charged);
    assert!(w.books.books.lock().unwrap().txns.is_empty());
    // Priced, no grant: the whole call is billed against a new wallet.
    w.books.books.lock().unwrap().configs[0] = BillingConfig { ai_tokens_per_million: Some(d("100")), ..config() };
    let r = w.internal.charge_ai(&system(), &ai("2000000", "d")).await.unwrap();
    assert!(r.charged && r.suspended);
    assert_eq!(r.balance_after.to_string(), "-199");
}

#[tokio::test]
async fn ai_allowed_only_blocks_an_active_billed_suspended_wallet() {
    let w = world();
    assert!(w.internal.is_ai_allowed("crm", "BUS").await.unwrap(), "no config");
    assert!(w.internal.is_ai_allowed("nope", "BUS").await.unwrap());
    assert!(w.internal.is_ai_allowed("crm", "NOPE").await.unwrap());
    w.books.books.lock().unwrap().configs.push(BillingConfig { status: "INACTIVE".into(), ..config() });
    w.books.books.lock().unwrap().wallets.push(wallet("-1", "SUSPENDED", 0));
    assert!(w.internal.is_ai_allowed("crm", "BUS").await.unwrap(), "paused config");
    w.books.books.lock().unwrap().configs[0].status = "ACTIVE".into();
    assert!(!w.internal.is_ai_allowed("crm", "BUS").await.unwrap(), "suspended builder wallet");
    w.books.books.lock().unwrap().wallets.clear();
    assert!(w.internal.is_ai_allowed("crm", "BUS").await.unwrap(), "no wallet");
}

#[tokio::test]
async fn hosting_serves_the_suspend_target_for_a_suspended_builder_wallet() {
    let w = world();
    let pass = |app: &str, client: &str| serde_json::json!({"suspended": false, "serveAppCode": app, "serveClientCode": client});
    assert_eq!(w.internal.hosting("crm", "SYSTEM").await.unwrap(), pass("crm", "SYSTEM"));
    assert_eq!(w.internal.hosting("", "BUS").await.unwrap(), serde_json::json!({"suspended": false, "serveClientCode": "BUS"}));
    assert_eq!(w.internal.hosting("crm", "NOPE").await.unwrap(), pass("crm", "NOPE"));
    assert_eq!(w.internal.hosting("nope", "BUS").await.unwrap(), pass("nope", "BUS"));
    // No builder wallet.
    assert_eq!(w.internal.hosting("crm", "BUS").await.unwrap(), pass("crm", "BUS"));
    // An active appbuilder wallet.
    w.books.books.lock().unwrap().wallets.push(Wallet { app_id: 1, ..wallet("5", "ACTIVE", 0) });
    assert_eq!(w.internal.hosting("crm", "BUS").await.unwrap(), pass("crm", "BUS"));
    // Suspended, but no config (and then one without a suspend target).
    w.books.books.lock().unwrap().wallets[0].status = "SUSPENDED".into();
    assert_eq!(w.internal.hosting("crm", "BUS").await.unwrap(), pass("crm", "BUS"));
    w.books.books.lock().unwrap().configs.push(BillingConfig { app_id: 1, ..config() });
    assert_eq!(w.internal.hosting("crm", "BUS").await.unwrap(), pass("crm", "BUS"));
    w.books.books.lock().unwrap().configs[0].suspend_app_code = Some("suspended".into());
    w.books.books.lock().unwrap().configs[0].suspend_client_code = Some("SYSTEM".into());
    assert_eq!(
        w.internal.hosting("crm", "BUS").await.unwrap(),
        serde_json::json!({"suspended": true, "serveAppCode": "suspended", "serveClientCode": "SYSTEM"})
    );
    // A site without a sitezump wallet falls back to the appbuilder one.
    assert_eq!(w.internal.hosting("site1", "BUS").await.unwrap()["suspended"], true);
    // With an active sitezump wallet, that one decides.
    w.books.books.lock().unwrap().wallets.push(Wallet { id: 8, app_id: 4, ..wallet("5", "ACTIVE", 0) });
    assert_eq!(w.internal.hosting("site1", "BUS").await.unwrap(), pass("site1", "BUS"));
}

#[tokio::test]
async fn serving_status_is_active_without_a_config_and_the_wallet_otherwise() {
    let w = world();
    w.books.books.lock().unwrap().configs.push(config());
    w.books.books.lock().unwrap().wallets.push(wallet("-2.5000", "SUSPENDED", 0));
    let v = w.internal.serving_status("crm", "SYSTEM", M_CLIENT).await.unwrap();
    assert_eq!(security::jackson::pretty(&v), "{\n  \"status\" : \"SUSPENDED\",\n  \"balance\" : -2.5000,\n  \"suspended\" : true\n}");
    // Another caller gets a seeded wallet of its own.
    assert_eq!(w.internal.serving_status("crm", "SYSTEM", 3).await.unwrap()["status"], "ACTIVE");

    let w = world();
    let active = serde_json::json!({"status": "ACTIVE", "suspended": false});
    assert_eq!(w.internal.serving_status("crm", "SYSTEM", M_CLIENT).await.unwrap(), active);
    // The missing config is cached too (cacheEmptyValueOrGet): a config added later is not seen
    // until an eviction.
    w.books.books.lock().unwrap().configs.push(config());
    assert_eq!(w.internal.serving_status("crm", "SYSTEM", M_CLIENT).await.unwrap(), active);
}

fn instruction() -> Instruction {
    Instruction {
        config_client_code: "SYSTEM".into(),
        config_client_id: C_CLIENT,
        app_code: "crm".into(),
        app_id: APP,
        billed_client_code: "BUS".into(),
        billed_client_id: M_CLIENT,
    }
}

const DAY: (i32, u32, u32) = (2026, 6, 15);

fn day() -> NaiveDate {
    NaiveDate::from_ymd_opt(DAY.0, DAY.1, DAY.2).unwrap()
}

#[tokio::test]
async fn a_window_charges_each_instruction_with_its_count() {
    let w = world();
    {
        let mut b = w.books.books.lock().unwrap();
        b.instructions.push((action::APP_RENT.into(), instruction()));
        b.instructions.push((action::USER.into(), instruction()));
        b.instructions.push((action::SITE_RENT.into(), instruction()));
        b.app_counts.push(((M_CLIENT, "APP".into()), 5));
        b.configs.push(BillingConfig { app_rent_per_month: Some(Dec::from_i64(WINDOWS_IN_JUNE)), ..config() });
        b.wallets.push(wallet("100", "ACTIVE", 0));
    }
    w.internal.meter_window(&system(), day(), 7).await.unwrap();
    let b = w.books.books.lock().unwrap();
    // Apps: 5 charged; users and sites count 0 and are skipped.
    assert_eq!(b.txns.len(), 1);
    let t = &b.txns[0];
    assert_eq!((t.action_key.as_deref(), t.window_index, t.quantity.unwrap().to_string()), (Some(action::APP_RENT), Some(7), "5".into()));
    assert_eq!(t.charge_date, Some(day()));
}

#[tokio::test]
async fn reconcile_back_charges_only_the_missing_windows() {
    let w = world();
    {
        let mut b = w.books.books.lock().unwrap();
        b.instructions.push((action::APP_RENT.into(), instruction()));
        b.app_counts.push(((M_CLIENT, "APP".into()), 5));
        b.configs.push(BillingConfig { app_rent_per_month: Some(Dec::from_i64(WINDOWS_IN_JUNE)), ..config() });
        b.wallets.push(wallet("1000", "ACTIVE", 0));
        for i in 0..95 {
            b.txns.push(Txn {
                wallet_id: 7,
                action_key: Some(action::APP_RENT.into()),
                charge_date: Some(day()),
                window_index: Some(i),
                idempotency_key: format!("{}:{}:{i}", action::APP_RENT, day()),
                ..Default::default()
            });
        }
    }
    w.internal.reconcile_day(&system(), day()).await.unwrap();
    {
        let b = w.books.books.lock().unwrap();
        assert_eq!(b.txns.len(), 96);
        assert_eq!(b.txns[95].window_index, Some(95));
    }
    // A fully charged day does nothing; a count that fails is skipped.
    w.internal.reconcile_day(&system(), day()).await.unwrap();
    assert_eq!(w.books.books.lock().unwrap().txns.len(), 96);
    w.books.books.lock().unwrap().fail_counts = true;
    w.internal.meter_window(&system(), NaiveDate::from_ymd_opt(2026, 6, 16).unwrap(), 1).await.unwrap();
    assert_eq!(w.books.books.lock().unwrap().txns.len(), 96);
    // The current window runs in the server's zone; with no instructions left it charges nothing.
    w.books.books.lock().unwrap().instructions.clear();
    w.internal.meter_current_window(&system()).await.unwrap();
}
