//! security-admin's billing against the local `security` schema, ported from the DAO integration
//! tests (`AppBillingBundleDAOIntegrationTest`, `AppBillingConfigDAOIntegrationTest`,
//! `InvoiceDAOIntegrationTest`, `PaymentDAOIntegrationTest`, `WalletDAOIntegrationTest`,
//! `WalletTransactionDAOIntegrationTest`) and the end-to-end halves of
//! `BundlePurchaseServiceIntegrationTest`, `RazorpayWebhookIntegrationTest` and
//! `InvoiceServiceIntegrationTest`.
//!
//! Gated: `SECURITY_AUTH_LIVE=1` with `eval "$(tools/local-env.py)"`. Every write runs inside one
//! transaction that is rolled back at the end (the scratch client `ZZPAR11` configures the scratch
//! app `coreedparity`), so no config, bundle, invoice, payment or wallet survives; Razorpay and
//! files are answered in process. The routes are only read through.

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hmac::{Hmac, Mac};
use platform::cache::CacheService;
use platform::config::MySqlConfig;
use security::admin::billing::purchase::PurchaseRequest;
use security::admin::billing::service::{Billing, Outside};
use security::condition::Cond;
use security::config::AuthConfig;
use security::data::billing_admin::{sql, AdminBillingStore, Find, Rec, Schema, Val, BUNDLE, CONFIG, INVOICE, PAYMENT, PROFILE, TXN, WALLET};
use security::data::clients::Rows;
use security::decimal::Dec;
use security::errors::{AuthError, AuthResult};
use security::events::{EventMessage, EventSink};
use security::internal::Internal;
use security::model::{App, ContextAuth, ContextUser};
use security::spring::{Order, Pageable};
use serde_json::{json, Value};
use sha2::Sha256;
use sqlx::{MySql, MySqlPool, Row, Transaction};
use tokio::sync::Mutex;
use tower::ServiceExt;

const P: &str = "/api/security";

struct Live {
    pool: MySqlPool,
    internal: Arc<Internal>,
    admin: security::admin::AdminState,
}

async fn live() -> Option<Live> {
    let (Ok(_), Ok(password), Ok(key)) =
        (std::env::var("SECURITY_AUTH_LIVE"), std::env::var("MODLIX__DATABASE__PASSWORD"), std::env::var("MODLIX__JWT__KEY"))
    else {
        eprintln!("skipped: SECURITY_AUTH_LIVE / MODLIX__DATABASE__PASSWORD / MODLIX__JWT__KEY not set");
        return None;
    };
    let mut cfg = AuthConfig::default();
    cfg.database = MySqlConfig { database: "security".into(), password, max_connections: 4, ..Default::default() };
    cfg.jwt.key = key;
    cfg.security.app_code_suffix = ".local".into();
    cfg.security.subdomain_endings = ".local.modlix.com, .local.sitezump.ai".into();
    cfg.wallet.publish_events = false;
    cfg.events.publish_events = false;
    let pool = platform::db::mysql_pool(&cfg.database).await.unwrap();
    // No Redis: this instance's caches only, so nothing here evicts anything elsewhere.
    let cache = CacheService::new("cmn", "evictionChannel", None).unwrap();
    let admin = security::admin::build(&cfg, pool.clone(), cache, None).unwrap();
    Some(Live { pool, internal: admin.internal.clone(), admin })
}

/// The billing tables inside one transaction that the test rolls back.
struct TxStore {
    tx: Mutex<Option<Transaction<'static, MySql>>>,
}

impl TxStore {
    async fn begin(pool: &MySqlPool) -> Self {
        Self { tx: Mutex::new(Some(pool.begin().await.unwrap())) }
    }

    async fn rollback(&self) {
        if let Some(tx) = self.tx.lock().await.take() {
            tx.rollback().await.unwrap();
        }
    }

    async fn scalar(&self, q: &str) -> i64 {
        let mut g = self.tx.lock().await;
        sqlx::query_scalar(q).fetch_one(&mut **g.as_mut().unwrap()).await.unwrap()
    }

    async fn exec(&self, q: &str) {
        let mut g = self.tx.lock().await;
        sqlx::query(q).execute(&mut **g.as_mut().unwrap()).await.unwrap();
    }
}

macro_rules! on_tx {
    ($self:ident, |$c:ident| $body:expr) => {{
        let mut g = $self.tx.lock().await;
        let $c: &mut sqlx::MySqlConnection = &mut **g.as_mut().ok_or_else(|| AuthError::internal("rolled back"))?;
        $body.await
    }};
}

#[async_trait]
impl AdminBillingStore for TxStore {
    async fn by_id(&self, s: &'static Schema, id: u64) -> AuthResult<Option<Rec>> {
        on_tx!(self, |c| sql::by_id(c, s, id))
    }
    async fn find(&self, s: &'static Schema, q: &Find) -> AuthResult<Vec<Rec>> {
        on_tx!(self, |c| sql::find(c, s, q))
    }
    async fn insert(&self, rec: &Rec) -> AuthResult<u64> {
        on_tx!(self, |c| sql::insert(c, rec))
    }
    async fn update(&self, rec: &Rec) -> AuthResult<u64> {
        on_tx!(self, |c| sql::update(c, rec))
    }
    async fn delete(&self, s: &'static Schema, id: u64) -> AuthResult<u64> {
        on_tx!(self, |c| sql::delete(c, s, id))
    }
    async fn invoice_page(&self, cond: Option<&Cond>, party: Option<u64>, page: &Pageable) -> AuthResult<Rows<Rec>> {
        on_tx!(self, |c| sql::invoice_page(c, cond, party, page))
    }
    async fn txn_page(&self, wallet_id: u64, page: &Pageable) -> AuthResult<Rows<Rec>> {
        on_tx!(self, |c| sql::txn_page(c, wallet_id, page))
    }
    async fn payments_of(&self, invoice_ids: &[u64]) -> AuthResult<Vec<Rec>> {
        on_tx!(self, |c| sql::payments_of(c, invoice_ids))
    }
    async fn next_invoice_number(&self, seller: u64, fin_year: &str) -> AuthResult<String> {
        on_tx!(self, |c| sql::next_invoice_number(c, seller, fin_year))
    }
    async fn seed_wallet(&self, client: u64, app: u64, initial: Dec) -> AuthResult<Option<Rec>> {
        on_tx!(self, |c| sql::seed_wallet(c, client, app, initial))
    }
    async fn credit_balance(&self, wallet: u64, tokens: Dec) -> AuthResult<u64> {
        on_tx!(self, |c| sql::credit_balance(c, wallet, tokens))
    }
    async fn set_wallet_status(&self, wallet: u64, status: &str) -> AuthResult<u64> {
        on_tx!(self, |c| sql::set_wallet_status(c, wallet, status))
    }
    async fn set_low_balance_notified(&self, wallet: u64, notified: bool) -> AuthResult<u64> {
        on_tx!(self, |c| sql::set_low_balance_notified(c, wallet, notified))
    }
    async fn record_txn(&self, txn: &Rec) -> AuthResult<bool> {
        on_tx!(self, |c| sql::record_txn(c, txn))
    }
    async fn has_write_access(&self, app: u64, client: u64) -> AuthResult<bool> {
        on_tx!(self, |c| sql::has_write_access(c, app, client))
    }
    async fn count_apps(&self, client: u64, app_type: &str) -> AuthResult<i64> {
        let mut g = self.tx.lock().await;
        let c: &mut sqlx::MySqlConnection = &mut **g.as_mut().ok_or_else(|| AuthError::internal("rolled back"))?;
        Ok(sqlx::query_scalar("SELECT COUNT(*) FROM security_app WHERE CLIENT_ID = ? AND APP_TYPE = ?").bind(client).bind(app_type).fetch_one(c).await?)
    }
    async fn count_users_with_profile(&self, _client: u64, _app: u64) -> AuthResult<i64> {
        Ok(0)
    }
}

#[derive(Default)]
struct Recorded {
    events: std::sync::Mutex<Vec<EventMessage>>,
    razorpay: std::sync::Mutex<Vec<(String, Value)>>,
}

#[async_trait]
impl EventSink for Recorded {
    async fn publish(&self, event: &EventMessage) -> AuthResult<bool> {
        self.events.lock().unwrap().push(event.clone());
        Ok(true)
    }
}

#[async_trait]
impl Outside for Recorded {
    async fn secured_key(&self, file_path: &str) -> AuthResult<String> {
        Ok(format!("api/files/secured/downloadFileByKey/{}", file_path.len()))
    }
    async fn razorpay(&self, path: &str, _key_id: &str, _key_secret: &str, body: &Value) -> AuthResult<Value> {
        self.razorpay.lock().unwrap().push((path.to_string(), body.clone()));
        // Unique per run: GATEWAY_ORDER_ID is a unique key.
        Ok(json!({"id": format!("order_livetest_{}", security::admin::billing::wallets::random_uuid()), "short_url": "https://rzp.io/i/live"}))
    }
    async fn app_url(&self, _internal: &Internal, _ca: &ContextAuth, app: &App, client_id: u64) -> AuthResult<String> {
        Ok(format!("https://{}.example/{client_id}", app.app_code))
    }
}

fn system() -> ContextAuth {
    ContextAuth {
        user: ContextUser { id: Some(142), client_id: Some(1), string_authorities: Some(vec!["Authorities.ROLE_Owner".into()]), ..Default::default() },
        authenticated: true,
        client_type_code: Some("SYS".into()),
        ..Default::default()
    }
}

fn d(s: &str) -> Dec {
    Dec::parse(s).unwrap()
}

/// The whole purchase, end to end, on scratch rows that are rolled back: config and bundle
/// management, the quote, the purchase (the invoice numbered for the seller), the verified
/// webhook (payment and invoice PAID, the wallet credited once), and the reads after it.
#[tokio::test]
async fn a_purchase_end_to_end_in_a_rolled_back_transaction() {
    let Some(l) = live().await else { return };
    let ids = sqlx::query("SELECT c.ID, a.ID FROM security_client c, security_app a WHERE c.CODE = 'ZZPAR11' AND a.APP_CODE = 'coreedparity' AND a.CLIENT_ID = 1")
        .fetch_optional(&l.pool)
        .await
        .unwrap();
    let Some(ids) = ids else {
        eprintln!("skipped: the scratch client ZZPAR11 or the scratch app coreedparity is missing");
        return;
    };
    let (seller, app): (u64, u64) = (ids.get(0), ids.get(1));
    let store = TxStore::begin(&l.pool).await;
    let rec = Recorded::default();
    let b = Billing { internal: &l.internal, store: &store, events: &rec, outside: &rec };
    let ca = system();
    let run = async {
        // The scratch client may edit the scratch app (inside the transaction only).
        assert!(!b.write_access(Some(app), Some(seller)).await.unwrap());
        store.exec(&format!("INSERT INTO security_app_access (APP_ID, CLIENT_ID, EDIT_ACCESS) VALUES ({app}, {seller}, 1)")).await;
        assert!(b.write_access(Some(app), Some(seller)).await.unwrap());
        assert!(b.write_access(Some(app), Some(1)).await.unwrap());

        // AppBillingConfigServiceIntegrationTest: create, read, update, patch.
        let cfg = Rec::new(&CONFIG)
            .with("clientId", Val::Id(seller))
            .with("appId", Val::Id(app))
            .with("status", Val::Str("INACTIVE".into()))
            .with("gstPercentage", Val::Dec(d("18")))
            .with("sellerLegalName", Val::Str("Live Seller".into()))
            .with("paymentGatewayConfig", Val::Json(json!({"keyId": "rzp_test_live", "keySecret": "x", "webhookSecret": "live-secret"})));
        let config = b.config_create(&ca, cfg).await.unwrap().unwrap();
        let config_id = config.id().unwrap();
        assert_eq!((config.dec("gstPercentage").unwrap().to_string(), config.dec("appRentPerMonth").unwrap().to_string()), ("18.00".into(), "0.0000".into()));
        assert!(config.ts("createdAt").is_some() && config.u64("createdBy").is_none());
        let put = Rec::new(&CONFIG)
            .with("id", Val::Id(config_id))
            .with("status", Val::Str("INACTIVE".into()))
            .with("gstPercentage", Val::Dec(d("18")))
            .with("lowBalanceThreshold", Val::Dec(d("5.5")))
            .with("paymentGatewayConfig", config.get("paymentGatewayConfig").clone());
        let updated = b.config_update(&ca, &put).await.unwrap().unwrap();
        assert_eq!(updated.dec("lowBalanceThreshold").unwrap().to_string(), "5.5000");
        // Not in the PUT: a nullable column goes NULL, a NOT NULL one keeps its value.
        assert!(updated.str("sellerLegalName").is_none());
        assert_eq!(updated.str("paymentGateway"), Some("RAZORPAY"));
        let patch = serde_json::from_value(json!({"sellerLegalName": "Live Seller", "suspendAppCode": ""})).unwrap();
        let patched = b.config_patch(&ca, config_id, &patch).await.unwrap().unwrap();
        assert_eq!(patched.str("sellerLegalName"), Some("Live Seller"));
        assert_eq!(patched.to_json().get("suspendAppCode"), None);
        let visible: Vec<u64> = b.configs_of_app(&ca, app).await.unwrap().iter().filter_map(Rec::id).collect();
        assert!(visible.contains(&config_id));

        // AppBillingBundleDAOIntegrationTest: by display order, DELETED left out.
        let bundle = |label: &str, order: i64, status: &str| {
            Rec::new(&BUNDLE)
                .with("billingConfigId", Val::Id(config_id))
                .with("label", Val::Str(label.into()))
                .with("bundleType", Val::Str("FIXED".into()))
                .with("tokens", Val::Dec(d("1000")))
                .with("price", Val::Dec(d("100")))
                .with("displayOrder", Val::Int(order))
                .with("status", Val::Str(status.into()))
        };
        let fixed = b.bundle_create(&ca, bundle("Starter", 2, "ACTIVE")).await.unwrap().unwrap();
        b.bundle_create(&ca, bundle("Gone", 1, "DELETED")).await.unwrap();
        let custom = b
            .bundle_create(
                &ca,
                bundle("Custom", 3, "ACTIVE").with("bundleType", Val::Str("CUSTOM".into())).with("pricePerToken", Val::Dec(d("0.5"))).with("minTokens", Val::Dec(d("100"))),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!((fixed.str("currency"), fixed.int("displayOrder")), (Some("INR"), Some(2)));
        let labels: Vec<String> = b.bundles_of_config(config_id).await.unwrap().iter().map(|r| r.str("label").unwrap().to_string()).collect();
        assert_eq!(labels, ["Starter", "Custom"]);
        assert_eq!(custom.dec("pricePerToken").unwrap().to_string(), "0.500000");

        // The quote and the CUSTOM pricing (BundlePurchaseServiceIntegrationTest).
        let q = b.quote(&PurchaseRequest { bundle_id: custom.id(), tokens: Some(d("200")), ..Default::default() }).await.unwrap();
        assert_eq!(security::jackson::pretty(&q["totalAmount"]), "118.000000");
        assert!(b.quote(&PurchaseRequest { bundle_id: custom.id(), tokens: Some(d("50")), ..Default::default() }).await.is_err());

        // The purchase: a PENDING invoice snapshotting seller and buyer, the first number of the
        // seller's year, a PENDING payment keyed by the order.
        let r = b.purchase_order(&ca, &PurchaseRequest { bundle_id: fixed.id(), ..Default::default() }).await.unwrap().unwrap();
        let invoice_id = r["invoiceId"].as_u64().unwrap();
        let inv = b.read(&INVOICE, Some(invoice_id)).await.unwrap();
        assert_eq!((inv.str("status"), inv.u64("sellerClientId"), inv.u64("clientId")), (Some("PENDING"), Some(seller), Some(1)));
        assert_eq!((inv.dec("gstAmount").unwrap().to_string(), inv.dec("totalAmount").unwrap().to_string()), ("18.0000".into(), "118.0000".into()));
        assert!(inv.str("invoiceNumber").unwrap().ends_with(&format!("/{seller}/1")));
        assert_eq!(r["amount"], 11800);
        let order = r["orderId"].as_str().unwrap().to_string();
        let pay = b.store.find(&PAYMENT, &Find::eq(vec![("GATEWAY_ORDER_ID", Val::Str(order.clone()))])).await.unwrap();
        assert_eq!(pay.len(), 1);
        assert_eq!((pay[0].str("status"), pay[0].dec("amount").unwrap().to_string()), (Some("PENDING"), "118.0000".into()));
        // InvoiceDAOIntegrationTest: numbers are gapless per seller and year.
        let fy = inv.str("invoiceNumber").unwrap().split('/').nth(1).unwrap().to_string();
        assert!(b.store.next_invoice_number(seller, &fy).await.unwrap().ends_with("/2"));
        assert!(b.store.next_invoice_number(seller, "1999-00").await.unwrap().ends_with("/1"));

        // The webhook, verified with the seller's secret (RazorpayWebhookIntegrationTest).
        let body = json!({"event": "order.paid", "payload": {"order": {"entity": {"id": order}},
            "payment": {"entity": {"id": "pay_livetest", "amount": 11800, "method": "upi", "fee": 236, "tax": 36, "currency": "INR", "status": "captured"}}}})
        .to_string();
        let mut mac = Hmac::<Sha256>::new_from_slice(b"live-secret").unwrap();
        mac.update(body.as_bytes());
        let sig: String = mac.finalize().into_bytes().iter().map(|x| format!("{x:02x}")).collect();
        b.webhook(&ContextAuth::default(), &body, Some("deadbeef")).await.unwrap();
        assert_eq!(b.read(&INVOICE, Some(invoice_id)).await.unwrap().str("status"), Some("PENDING"));
        b.webhook(&ContextAuth::default(), &body, Some(&sig)).await.unwrap();
        let paid = b.read(&INVOICE, Some(invoice_id)).await.unwrap();
        assert_eq!((paid.str("status"), paid.str("paymentReference")), (Some("PAID"), Some("pay_livetest")));
        let pay = b.read(&PAYMENT, pay[0].id()).await.unwrap();
        assert_eq!((pay.str("status"), pay.str("gatewayPaymentId")), (Some("PAID"), Some("pay_livetest")));
        assert_eq!(pay.map("response")["captured"], json!({"amount": 118.0, "currency": "INR", "fee": 2.36, "method": "upi", "status": "captured", "tax": 0.36}));
        assert_eq!(pay.map("response")["webhook"]["payload"]["payment"]["entity"]["amount"], json!(11800.0));
        // The wallet: seeded with one token, then the 1000 purchased; a replay credits nothing.
        let wallet = b.wallet_of(1, app).await.unwrap().unwrap();
        assert_eq!(wallet.dec("balance").unwrap().to_string(), "1001.0000");
        b.webhook(&ContextAuth::default(), &body, Some(&sig)).await.unwrap();
        assert_eq!(b.wallet_of(1, app).await.unwrap().unwrap().dec("balance").unwrap().to_string(), "1001.0000");
        assert_eq!(rec.events.lock().unwrap().iter().filter(|e| e.event_name == "INVOICE_GENERATED").count(), 1);

        // The reads after it.
        let page = Pageable::of(0, 5, vec![Order::new("id", false)]);
        let mine = b.my_invoices(&ca, &page, None, Some("coreedparity")).await.unwrap().unwrap();
        assert_eq!((mine["content"][0]["id"].as_u64(), mine["content"][0]["paymentMethod"].as_str()), (Some(invoice_id), Some("upi")));
        let sold = b.invoice_page(&ca, &page, None, Some("coreedparity"), Some("ZZPAR11")).await.unwrap().unwrap();
        assert_eq!(sold["totalElements"], 1);
        let one = b.invoice_read(&ca, invoice_id).await.unwrap();
        assert_eq!(one["paymentMethod"], "upi");
        let ledger = b.my_transactions(&ca, Some("coreedparity"), &Pageable::of(0, 5, vec![])).await.unwrap();
        assert_eq!(ledger["content"][0]["idempotencyKey"], "payment:pay_livetest");
        assert_eq!(ledger["content"][0]["referenceType"], "INVOICE");
        // The buyer's (SYSTEM's) own hierarchy has no config for the app: no threshold.
        let status = b.display_status(&ca, Some("coreedparity")).await.unwrap();
        assert_eq!((status["status"].as_str(), status.get("threshold")), (Some("ACTIVE"), None));
        assert_eq!(security::jackson::pretty(&status["balance"]), "1001.0000");
        let docs = b.invoice_documents(&ca, invoice_id).await.unwrap().unwrap();
        assert!(docs["invoiceUrl"].as_str().unwrap().starts_with("api/files/secured/downloadFileByKey/"));

        // The billing profile upsert.
        let saved = b.save_my_profile(&ca, Some("coreedparity"), &Rec::new(&PROFILE).with("legalName", Val::Str("Live Buyer".into()))).await.unwrap().unwrap();
        let again = b.save_my_profile(&ca, Some("coreedparity"), &Rec::new(&PROFILE).with("city", Val::Str("Pune".into()))).await.unwrap().unwrap();
        assert_eq!((again.id(), again.str("legalName"), again.str("city")), (saved.id(), None, Some("Pune")));

        // Delete: the bundle, then the config (its bundles go with it).
        assert_eq!(b.bundle_delete(&ca, fixed.id().unwrap()).await.unwrap(), 1);
        assert_eq!(b.config_delete(&ca, config_id).await.unwrap(), 1);
        assert_eq!(store.scalar(&format!("SELECT COUNT(*) FROM security_app_billing_bundle WHERE BILLING_CONFIG_ID = {config_id}")).await, 0);
        AuthResult::Ok(seller)
    };
    let outcome = run.await;
    store.rollback().await;
    outcome.unwrap();
    // Nothing survives the rollback.
    let left: i64 = sqlx::query_scalar(&format!(
        "SELECT (SELECT COUNT(*) FROM security_app_billing_config WHERE CLIENT_ID = {seller}) + \
         (SELECT COUNT(*) FROM security_invoice_counter WHERE SELLER_CLIENT_ID = {seller}) + \
         (SELECT COUNT(*) FROM security_wallet WHERE CLIENT_ID = 1 AND APP_ID = {app}) + \
         (SELECT COUNT(*) FROM security_app_access WHERE CLIENT_ID = {seller} AND APP_ID = {app}) + \
         (SELECT COUNT(*) FROM security_billing_profile WHERE CLIENT_ID = 1 AND APP_ID = {app})"
    ))
    .fetch_one(&l.pool)
    .await
    .unwrap();
    assert_eq!(left, 0);
}

/// The wallet statements (`WalletDAOIntegrationTest`, `WalletTransactionDAOIntegrationTest`) and
/// an owner's adjustment, rolled back.
#[tokio::test]
async fn wallet_credits_in_a_rolled_back_transaction() {
    let Some(l) = live().await else { return };
    let free = sqlx::query(
        "SELECT c.ID, a.ID FROM security_client c JOIN security_app a ON a.CLIENT_ID = 1 AND a.APP_CODE = 'coreedparity' \
         WHERE c.CODE = 'ZZPAR11' AND NOT EXISTS (SELECT 1 FROM security_wallet w WHERE w.CLIENT_ID = c.ID AND w.APP_ID = a.ID)",
    )
    .fetch_optional(&l.pool)
    .await
    .unwrap();
    let Some(free) = free else { return };
    let (client, app): (u64, u64) = (free.get(0), free.get(1));
    let store = TxStore::begin(&l.pool).await;
    let rec = Recorded::default();
    let b = Billing { internal: &l.internal, store: &store, events: &rec, outside: &rec };
    let run = async {
        let w = b.wallet_or_create(client, app).await?.unwrap();
        assert_eq!((w.dec("balance").unwrap().to_string(), w.str("status"), w.int("lowBalanceNotified"), w.int("version")), ("1.0000".into(), Some("ACTIVE"), Some(0), Some(0)));
        assert_eq!(b.wallet_or_create(client, app).await?.unwrap().id(), w.id(), "a second seed finds the first");
        let id = w.id().unwrap();
        store.set_wallet_status(id, "SUSPENDED").await?;
        store.set_low_balance_notified(id, true).await?;
        // An owner of SYSTEM adjusting a managed client's wallet (SYSTEM owns the app).
        let mut parent = system();
        parent.client_type_code = Some("BUS".into());
        let r = b.adjust(&parent, id, d("5"), "live test").await?;
        assert!(r.charged);
        assert_eq!(r.balance_after.to_string(), "6.0000");
        let after = b.wallet_of(client, app).await?.unwrap();
        assert_eq!((after.dec("balance").unwrap().to_string(), after.str("status"), after.int("lowBalanceNotified")), ("6.0000".into(), Some("ACTIVE"), Some(0)));
        // A ledger row's idempotency key is unique per wallet.
        let txn = Rec::new(&TXN)
            .with("walletId", Val::Id(id))
            .with("type", Val::Str("CREDIT".into()))
            .with("tokens", Val::Dec(d("1")))
            .with("balanceAfter", Val::Dec(d("7")))
            .with("idempotencyKey", Val::Str("live:once".into()))
            .with("reason", Val::Str("x".into()))
            .with("chargeDate", Val::Date(chrono::NaiveDate::from_ymd_opt(2026, 6, 15).unwrap()))
            .with("windowIndex", Val::Int(4));
        assert!(store.record_txn(&txn).await?);
        assert!(!store.record_txn(&txn).await?);
        let page = store.txn_page(id, &Pageable::of(0, 10, vec![Order::new("id", true)])).await?;
        assert_eq!(page.total, Some(2));
        let row = page.rows.iter().find(|r| r.str("idempotencyKey") == Some("live:once")).unwrap();
        assert_eq!(row.to_json()["chargeDate"], 1781481600);
        assert_eq!(store.credit_balance(u64::MAX, Dec::ONE).await?, 0);
        assert!(store.find(&WALLET, &Find::eq(vec![("CLIENT_ID", Val::Id(u64::MAX))])).await?.is_empty());
        AuthResult::Ok(())
    };
    let outcome = run.await;
    store.rollback().await;
    outcome.unwrap();
    let left: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM security_wallet WHERE CLIENT_ID = {client} AND APP_ID = {app}"))
        .fetch_one(&l.pool)
        .await
        .unwrap();
    assert_eq!(left, 0);
}

fn basic(user: u64) -> String {
    use base64::Engine;
    format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{user}:Pass@1234")))
}

impl Live {
    async fn get(&self, path: &str, app: &str, client: &str, user: Option<u64>) -> (StatusCode, String) {
        let mut b = Request::builder().method("GET").uri(format!("{P}{path}")).header("host", "localhost:8001").header("appCode", app).header("clientCode", client);
        if let Some(u) = user {
            b = b.header("authorization", basic(u));
        }
        let resp = security::admin::router(self.admin.clone()).oneshot(b.body(Body::empty()).unwrap()).await.unwrap();
        let s = resp.status();
        (s, String::from_utf8_lossy(&to_bytes(resp.into_body(), usize::MAX).await.unwrap()).into_owned())
    }

    async fn post(&self, path: &str, body: &str) -> (StatusCode, String) {
        let req = Request::builder()
            .method("POST")
            .uri(format!("{P}{path}"))
            .header("host", "localhost:8001")
            .header("appCode", "sitezump")
            .header("clientCode", "SYSTEM")
            .header("authorization", basic(142))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let resp = security::admin::router(self.admin.clone()).oneshot(req).await.unwrap();
        let s = resp.status();
        (s, String::from_utf8_lossy(&to_bytes(resp.into_body(), usize::MAX).await.unwrap()).into_owned())
    }
}

/// The read routes over the real tables, checked against the rows themselves.
#[tokio::test]
async fn read_routes_over_the_local_tables() {
    let Some(l) = live().await else { return };
    let config = sqlx::query("SELECT b.ID, a.APP_CODE, a.ID FROM security_app_billing_config b JOIN security_app a ON a.ID = b.APP_ID WHERE b.CLIENT_ID = 1 AND b.STATUS = 'ACTIVE' ORDER BY b.ID LIMIT 1")
        .fetch_optional(&l.pool)
        .await
        .unwrap();
    let Some(config) = config else { return };
    let (cid, app, app_id): (u64, String, u64) = (config.get(0), config.get(1), config.get(2));
    let (s, body) = l.get(&format!("/billing-configs/{cid}"), "appbuilder", "SYSTEM", Some(142)).await;
    assert_eq!(s, StatusCode::OK);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!((v["id"].as_u64(), v["appId"].as_u64()), (Some(cid), Some(app_id)));
    assert!(body.contains("\"gstPercentage\" : "));
    let (s, body) = l.get(&format!("/billing-configs/app/{app_id}"), "appbuilder", "SYSTEM", Some(142)).await;
    assert_eq!(s, StatusCode::OK);
    assert!(serde_json::from_str::<Value>(&body).unwrap().as_array().unwrap().iter().any(|c| c["id"].as_u64() == Some(cid)));
    let bundles: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM security_app_billing_bundle WHERE BILLING_CONFIG_ID = {cid} AND STATUS <> 'DELETED'"))
        .fetch_one(&l.pool)
        .await
        .unwrap();
    let (s, body) = l.get(&format!("/billing-bundles/config/{cid}"), "appbuilder", "SYSTEM", Some(142)).await;
    assert_eq!(s, StatusCode::OK);
    let list: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(list.as_array().unwrap().len() as i64, bundles);
    let (s, _) = l.get("/billing-bundles/serving", &app, "SYSTEM", None).await;
    assert_eq!(s, StatusCode::OK);
    if let Some(first) = list.as_array().unwrap().first() {
        let (s, body) = l.get(&format!("/billing-bundles/{}", first["id"]), "appbuilder", "SYSTEM", Some(142)).await;
        assert_eq!((s, serde_json::from_str::<Value>(&body).unwrap()["id"].clone()), (StatusCode::OK, first["id"].clone()));
        let (s, body) = l.post("/billing/quote", &json!({"bundleId": first["id"]}).to_string()).await;
        assert_eq!(s, StatusCode::OK, "{body}");
    }
    for path in ["/wallets/status", "/wallets/plan", "/wallets/transactions?size=2", "/invoices?size=2&sort=id,desc", "/invoices/my?size=2", "/billing-profile"] {
        let (s, body) = l.get(path, &app, "SYSTEM", Some(142)).await;
        assert_eq!(s, StatusCode::OK, "{path}: {body}");
    }
    let (s, _) = l.get("/wallets", &app, "SYSTEM", Some(142)).await;
    assert!(s == StatusCode::OK || s == StatusCode::NO_CONTENT);
    let (s, _) = l.get("/billing-configs/999999999", "appbuilder", "SYSTEM", Some(142)).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // The invoice reads Java cannot answer (no ULong binder): served here.
    let invoice: Option<u64> = sqlx::query_scalar("SELECT ID FROM security_invoice ORDER BY ID LIMIT 1").fetch_optional(&l.pool).await.unwrap();
    if let Some(i) = invoice {
        let (s, body) = l.get(&format!("/invoices/{i}"), &app, "SYSTEM", Some(142)).await;
        assert_eq!((s, serde_json::from_str::<Value>(&body).unwrap()["id"].as_u64()), (StatusCode::OK, Some(i)));
    }
}

/// The write routes on the real tables: one connection, `BEGIN` before and `ROLLBACK` after, so
/// every statement the routes (and the caller's context) make runs inside that transaction and
/// none survives. The purchase reaches the seller's missing gateway keys and stops there; the
/// documents reach the unconfigured files upstream and stop there: nothing leaves the process.
#[tokio::test]
async fn write_routes_inside_one_rolled_back_session() {
    let (Ok(_), Ok(password), Ok(key)) =
        (std::env::var("SECURITY_AUTH_LIVE"), std::env::var("MODLIX__DATABASE__PASSWORD"), std::env::var("MODLIX__JWT__KEY"))
    else {
        return;
    };
    let mut cfg = AuthConfig::default();
    cfg.database = MySqlConfig { database: "security".into(), password, max_connections: 1, ..Default::default() };
    cfg.jwt.key = key;
    cfg.security.app_code_suffix = ".local".into();
    cfg.wallet.publish_events = false;
    cfg.events.publish_events = false;
    let pool = platform::db::mysql_pool(&cfg.database).await.unwrap();
    let ids = sqlx::query("SELECT c.ID, a.ID FROM security_client c, security_app a WHERE c.CODE = 'ZZPAR11' AND a.APP_CODE = 'coreedparity' AND a.CLIENT_ID = 1")
        .fetch_optional(&pool)
        .await
        .unwrap();
    let Some(ids) = ids else { return };
    let (seller, app): (u64, u64) = (ids.get(0), ids.get(1));
    let admin = security::admin::build(&cfg, pool.clone(), CacheService::new("cmn", "evictionChannel", None).unwrap(), None).unwrap();
    sqlx::raw_sql("BEGIN").execute(&pool).await.unwrap();
    // A bearer token for appbuilder (where 142 is an Owner), minted inside the transaction.
    let signin = Request::builder()
        .method("POST")
        .uri(format!("{P}/authenticate"))
        .header("host", "localhost:8001")
        .header("clientCode", "SYSTEM")
        .header("appCode", "appbuilder")
        .header("X-Real-IP", "127.0.0.1")
        .header("content-type", "application/json")
        .body(Body::from(json!({"userId": 142, "password": "Pass@1234"}).to_string()))
        .unwrap();
    let resp = security::handlers::router(admin.internal.auth.clone()).oneshot(signin).await.unwrap();
    let status = resp.status();
    let token: Value = serde_json::from_slice(&to_bytes(resp.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(status, StatusCode::OK, "{token}");
    let bearer = format!("Bearer {}", token["accessToken"].as_str().unwrap());
    let call = |method: &str, path: String, body: Option<Value>, extra: Vec<(&'static str, String)>| {
        let admin = admin.clone();
        let method = method.to_string();
        let bearer = bearer.clone();
        async move {
            let mut b = Request::builder()
                .method(method.as_str())
                .uri(format!("{P}{path}"))
                .header("host", "localhost:8001")
                .header("clientCode", "SYSTEM")
                .header("appCode", "coreedparity")
                .header("authorization", bearer);
            for (k, v) in extra {
                b = b.header(k, v);
            }
            let req = match body {
                Some(v) => b.header("content-type", "application/json").body(Body::from(v.to_string())).unwrap(),
                None => b.body(Body::empty()).unwrap(),
            };
            let resp = security::admin::router(admin).oneshot(req).await.unwrap();
            let s = resp.status();
            let text = String::from_utf8_lossy(&to_bytes(resp.into_body(), usize::MAX).await.unwrap()).into_owned();
            (s, serde_json::from_str::<Value>(&text).unwrap_or(Value::String(text)))
        }
    };
    let run = async {
        sqlx::query(&format!("INSERT INTO security_app_access (APP_ID, CLIENT_ID, EDIT_ACCESS) VALUES ({app}, {seller}, 1)")).execute(&pool).await.unwrap();
        let (s, c) = call("POST", "/billing-configs".into(), Some(json!({"clientId": seller, "appId": app, "status": "INACTIVE", "gstPercentage": 18,
            "paymentGatewayConfig": {"webhookSecret": "route-secret"}})), vec![]).await;
        assert_eq!(s, StatusCode::OK, "{c}");
        let cid = c["id"].as_u64().unwrap();
        let (s, v) = call("GET", format!("/billing-configs/{cid}"), None, vec![]).await;
        assert_eq!((s, v["clientId"].as_u64()), (StatusCode::OK, Some(seller)));
        let (s, v) = call("PUT", format!("/billing-configs/{cid}"), Some(json!({"status": "INACTIVE", "sellerGstin": "29R", "paymentGatewayConfig": {"webhookSecret": "route-secret"}})), vec![]).await;
        assert_eq!((s, v["sellerGstin"].as_str()), (StatusCode::OK, Some("29R")));
        let (s, v) = call("PATCH", format!("/billing-configs/{cid}"), Some(json!({"sellerLegalName": "Route Seller"})), vec![]).await;
        assert_eq!((s, v["sellerLegalName"].as_str(), v["sellerGstin"].as_str()), (StatusCode::OK, Some("Route Seller"), Some("29R")));
        let (s, b) = call("POST", "/billing-bundles".into(), Some(json!({"billingConfigId": cid, "label": "R", "tokens": 1000, "price": 100})), vec![]).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        let bid = b["id"].as_u64().unwrap();
        let (s, v) = call("PUT", format!("/billing-bundles/{bid}"), Some(json!({"label": "R2", "tokens": 1000, "price": 100})), vec![]).await;
        assert_eq!((s, v["label"].as_str()), (StatusCode::OK, Some("R2")));
        let (s, v) = call("PATCH", format!("/billing-bundles/{bid}"), Some(json!({"displayOrder": 4})), vec![]).await;
        assert_eq!((s, v["displayOrder"].as_i64()), (StatusCode::OK, Some(4)));
        let (s, v) = call("GET", format!("/billing-bundles/config/{cid}"), None, vec![]).await;
        assert_eq!((s, v.as_array().map(Vec::len)), (StatusCode::OK, Some(1)));
        let (s, v) = call("POST", "/billing/quote".into(), Some(json!({"bundleId": bid})), vec![]).await;
        assert_eq!((s, v["totalAmount"].as_f64()), (StatusCode::OK, Some(118.0)));
        // The purchase stops at the seller's missing keys (after its PENDING invoice).
        let (s, v) = call("POST", "/billing/purchase".into(), Some(json!({"bundleId": bid})), vec![]).await;
        assert_eq!((s, v["debugMessage"].as_str()), (StatusCode::INTERNAL_SERVER_ERROR, Some("Razorpay keyId/keySecret missing in billing config")));
        let (s, v) = call("POST", "/billing/purchase/order".into(), Some(json!({"bundleId": bid})), vec![]).await;
        assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR, "{v}");
        let invoice: u64 = sqlx::query_scalar(&format!("SELECT MAX(ID) FROM security_invoice WHERE SELLER_CLIENT_ID = {seller}")).fetch_one(&pool).await.unwrap();
        let (s, v) = call("POST", "/billing/repay".into(), Some(json!({"invoiceId": invoice})), vec![]).await;
        assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR, "{v}");
        // Pay it through the webhook: a PENDING payment for the invoice, the event signed.
        sqlx::query(&format!(
            "INSERT INTO security_payment (INVOICE_ID, CLIENT_ID, GATEWAY_ORDER_ID, AMOUNT, STATUS) VALUES ({invoice}, 1, 'order_route_livetest', 118, 'PENDING')"
        ))
        .execute(&pool)
        .await
        .unwrap();
        let body = json!({"event": "payment.captured", "payload": {"payment": {"entity": {"id": "pay_route", "order_id": "order_route_livetest", "amount": 11800}}}}).to_string();
        let mut mac = Hmac::<Sha256>::new_from_slice(b"route-secret").unwrap();
        mac.update(body.as_bytes());
        let sig: String = mac.finalize().into_bytes().iter().map(|x| format!("{x:02x}")).collect();
        let req = Request::builder()
            .method("POST")
            .uri(format!("{P}/billing/razorpay/webhook"))
            .header("host", "localhost:8001")
            .header("clientCode", "SYSTEM")
            .header("X-Razorpay-Signature", sig)
            .body(Body::from(body))
            .unwrap();
        let resp = security::admin::router(admin.clone()).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let (s, v) = call("GET", format!("/invoices/{invoice}"), None, vec![]).await;
        assert_eq!((s, v["status"].as_str(), v["paymentReference"].as_str()), (StatusCode::OK, Some("PAID"), Some("pay_route")));
        let (s, v) = call("GET", format!("/invoices/{invoice}/documents"), None, vec![]).await;
        assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR, "{v}");
        let (s, v) = call("GET", "/wallets".into(), None, vec![]).await;
        assert_eq!((s, v["balance"].as_f64()), (StatusCode::OK, Some(1001.0)));
        let (s, v) = call("GET", "/wallets/transactions?size=5".into(), None, vec![]).await;
        assert_eq!((s, v["totalElements"].as_i64()), (StatusCode::OK, Some(1)));
        // Credit a scratch client's wallet, look it up, adjust it.
        let (s, v) = call("POST", "/wallets/credit".into(), Some(json!({"appCode": "coreedparity", "urlClientCode": "SYSTEM", "clientCode": "ZZPAR11", "tokens": 10, "reason": "route test"})), vec![]).await;
        assert_eq!((s, v["balanceAfter"].as_f64()), (StatusCode::OK, Some(11.0)));
        let (s, w) = call("GET", "/wallets/lookup?appCode=coreedparity&urlClientCode=SYSTEM&clientCode=ZZPAR11".into(), None, vec![]).await;
        assert_eq!(s, StatusCode::OK);
        // Off by default: Java's "Type mismatch."; served with `[billing] serve_wallet_adjust`.
        let adjust = format!("/wallets/{}/adjust?tokens=-2&reason=route", w["id"]);
        let (s, v) = call("POST", adjust.clone(), None, vec![]).await;
        assert_eq!((s, v["debugMessage"].as_str()), (StatusCode::BAD_REQUEST, Some("400 BAD_REQUEST \"Type mismatch.\"")));
        let on = security::admin::billing::settings::BillingSettings { serve_wallet_adjust: true, ..Default::default() };
        let req = Request::builder()
            .method("POST")
            .uri(format!("{P}{adjust}"))
            .header("host", "localhost:8001")
            .header("clientCode", "SYSTEM")
            .header("appCode", "coreedparity")
            .header("authorization", bearer.clone())
            .body(Body::empty())
            .unwrap();
        let resp = security::admin::billing::router_with(on).with_state(admin.clone()).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v: Value = serde_json::from_slice(&to_bytes(resp.into_body(), usize::MAX).await.unwrap()).unwrap();
        assert_eq!(v["balanceAfter"].as_f64(), Some(9.0));
        // The buyer's profile.
        let (s, v) = call("PUT", "/billing-profile".into(), Some(json!({"legalName": "Route Buyer"})), vec![]).await;
        assert_eq!((s, v["legalName"].as_str()), (StatusCode::OK, Some("Route Buyer")));
        let (s, v) = call("GET", "/billing-profile".into(), None, vec![]).await;
        assert_eq!((s, v["legalName"].as_str()), (StatusCode::OK, Some("Route Buyer")));
        // Deletes.
        let (s, _) = call("DELETE", format!("/billing-bundles/{bid}"), None, vec![]).await;
        assert_eq!(s, StatusCode::NO_CONTENT);
        let (s, _) = call("DELETE", format!("/billing-configs/{cid}"), None, vec![]).await;
        assert_eq!(s, StatusCode::NO_CONTENT);
    };
    run.await;
    sqlx::raw_sql("ROLLBACK").execute(&pool).await.unwrap();
    let left: i64 = sqlx::query_scalar(&format!(
        "SELECT (SELECT COUNT(*) FROM security_app_billing_config WHERE CLIENT_ID = {seller}) + \
         (SELECT COUNT(*) FROM security_invoice WHERE SELLER_CLIENT_ID = {seller}) + \
         (SELECT COUNT(*) FROM security_payment WHERE GATEWAY_ORDER_ID = 'order_route_livetest') + \
         (SELECT COUNT(*) FROM security_wallet WHERE APP_ID = {app}) + \
         (SELECT COUNT(*) FROM security_app_access WHERE CLIENT_ID = {seller} AND APP_ID = {app}) + \
         (SELECT COUNT(*) FROM security_billing_profile WHERE CLIENT_ID = 1 AND APP_ID = {app})"
    ))
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(left, 0);
}
