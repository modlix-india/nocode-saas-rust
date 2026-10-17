//! `BundlePurchaseService` and `RazorpayPaymentService`: pricing a bundle (FIXED tier, or
//! CUSTOM at a price per token, GST on top), the PENDING invoice, the Razorpay payment link or
//! Checkout order, and the webhook that settles a payment.
//!
//! The Razorpay calls go through [`super::service::Outside`]; the webhook is verified with the
//! seller's webhook secret (HMAC-SHA256 of the raw body, hex) before anything changes, and is
//! the only path that credits a wallet.

use hmac::{Hmac, Mac};
use serde_json::{Map, Value};
use sha2::Sha256;

use super::money::{divide_half_up, java_double, long_value, Big};
use super::service::{forbidden, params_not_found, Billing};
use crate::data::billing_admin::{Find, Rec, Val, BUNDLE, CONFIG, INVOICE, PAYMENT};
use crate::decimal::Dec;
use crate::errors::{AuthError, AuthResult};
use crate::jackson::{opt, Obj};
use crate::model::{Client, ContextAuth};

/// `PurchaseRequest`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PurchaseRequest {
    pub bundle_id: Option<u64>,
    pub tokens: Option<Dec>,
    pub client_id: Option<u64>,
}

/// A bundle priced for a buyer: what `buildInvoice` and `priceQuote` compute.
#[derive(Debug, Clone, PartialEq)]
pub struct Price {
    pub tokens: Option<Dec>,
    pub base: Dec,
    pub gst_percentage: Dec,
    pub gst_amount: Dec,
    pub total: Dec,
    pub currency: String,
}

/// The FIXED tier, or tokens x price per token for a CUSTOM bundle within its bounds; GST on
/// top, rounded half up to paise.
pub fn price(bundle: &Rec, config: &Rec, requested: Option<Dec>) -> AuthResult<Price> {
    let (tokens, base) = if bundle.str("bundleType") == Some("CUSTOM") {
        let Some(t) = requested.filter(|t| t.signum() > 0) else { return Err(params_not_found("tokens")) };
        if bundle.dec("minTokens").is_some_and(|m| t.cmp_value(&m) == std::cmp::Ordering::Less) {
            return Err(params_not_found("tokens (below minimum)"));
        }
        if bundle.dec("maxTokens").is_some_and(|m| t.cmp_value(&m) == std::cmp::Ordering::Greater) {
            return Err(params_not_found("tokens (above maximum)"));
        }
        let per_token = bundle
            .dec("pricePerToken")
            .ok_or_else(|| AuthError::internal("Cannot read field \"intCompact\" because \"multiplicand\" is null"))?;
        (Some(t), t.mul(per_token))
    } else {
        let base = bundle.dec("price").ok_or_else(|| {
            AuthError::internal("Cannot invoke \"java.math.BigDecimal.multiply(java.math.BigDecimal)\" because \"base\" is null")
        })?;
        (bundle.dec("tokens"), base)
    };
    let gst_percentage = config.dec("gstPercentage").unwrap_or(Dec::ZERO);
    let gst_amount = divide_half_up(base.mul(gst_percentage), 100, 2);
    Ok(Price {
        tokens,
        base,
        gst_percentage,
        gst_amount,
        total: base.add(gst_amount),
        currency: bundle.str("currency").unwrap_or("INR").to_string(),
    })
}

/// `QuoteResult`.
pub fn quote_json(bundle: &Rec, p: &Price) -> Value {
    Obj::new()
        .put("bundleId", opt(bundle.id()))
        .put("bundleLabel", opt(bundle.str("label").map(str::to_string)))
        .put("tokens", p.tokens.map(Dec::to_json).unwrap_or(Value::Null))
        .put("baseAmount", p.base.to_json())
        .put("gstPercentage", p.gst_percentage.to_json())
        .put("gstAmount", p.gst_amount.to_json())
        .put("totalAmount", p.total.to_json())
        .put("currency", p.currency.as_str())
        .build()
}

/// Indian financial year (April to March) as `YYYY-YY`.
pub fn fin_year(date: chrono::NaiveDate) -> String {
    use chrono::Datelike;
    let start = if date.month() >= 4 { date.year() } else { date.year() - 1 };
    format!("{start}-{:02}", (start + 1) % 100)
}

/// The profile's address parts, trimmed and joined; `None` when there are none.
pub fn format_address(profile: &Rec) -> Option<String> {
    let parts: Vec<&str> = ["addressLine", "city", "state", "postalCode", "country"]
        .iter()
        .filter_map(|p| profile.str(p))
        .filter(|s| !s.trim().is_empty())
        .map(java_trim)
        .collect();
    (!parts.is_empty()).then(|| parts.join(", "))
}

/// `String.trim()`: every char up to U+0020 off both ends.
fn java_trim(s: &str) -> &str {
    s.trim_matches(|c: char| c <= ' ')
}

/// `prefillName`: the user's full name, else the buyer client's name.
pub fn prefill_name(ca: &ContextAuth, buyer: Option<&Client>) -> Option<String> {
    let full = format!("{} {}", ca.user.first_name.as_deref().unwrap_or(""), ca.user.last_name.as_deref().unwrap_or(""));
    let full = java_trim(&full);
    if !full.is_empty() {
        return Some(full.to_string());
    }
    buyer.and_then(|b| b.name.clone())
}

/// `str(map, key)`: the value's `toString()` as Gson / Jackson hold it.
pub fn map_str(m: &Map<String, Value>, key: &str) -> Option<String> {
    m.get(key).and_then(java_to_string)
}

fn java_to_string(v: &Value) -> Option<String> {
    Some(match v {
        Value::Null => return None,
        Value::String(s) => s.clone(),
        Value::Number(n) if n.is_f64() => java_double(n.as_f64().unwrap_or(0.0)),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        // `AbstractMap.toString()` / `AbstractCollection.toString()`.
        Value::Object(m) => {
            let inner: Vec<String> = m.iter().map(|(k, v)| format!("{k}={}", java_to_string(v).unwrap_or_else(|| "null".into()))).collect();
            format!("{{{}}}", inner.join(", "))
        }
        Value::Array(a) => {
            let inner: Vec<String> = a.iter().map(|v| java_to_string(v).unwrap_or_else(|| "null".into())).collect();
            format!("[{}]", inner.join(", "))
        }
    })
}

fn blank(s: &Option<String>) -> bool {
    s.as_deref().is_none_or(|s| s.trim().is_empty())
}

/// `gson.fromJson(body, Map.class)`: an object, every number a `Double`; `None` for anything
/// else (the webhook then does nothing).
pub fn gson_map(raw: &str) -> Option<Map<String, Value>> {
    match serde_json::from_str::<Value>(raw).ok()? {
        Value::Object(m) => match as_gson(Value::Object(m)) {
            Value::Object(m) => Some(m),
            _ => None,
        },
        _ => None,
    }
}

fn as_gson(v: Value) -> Value {
    match v {
        Value::Number(n) => n.as_f64().and_then(serde_json::Number::from_f64).map(Value::Number).unwrap_or(Value::Null),
        Value::Array(a) => Value::Array(a.into_iter().map(as_gson).collect()),
        Value::Object(m) => Value::Object(m.into_iter().map(|(k, v)| (k, as_gson(v))).collect()),
        other => other,
    }
}

/// `payload.<key>.entity` when it is an object.
pub fn entity(payload: &Map<String, Value>, key: &str) -> Option<Map<String, Value>> {
    match payload.get("payload")?.get(key)?.get("entity")? {
        Value::Object(e) => Some(e.clone()),
        _ => None,
    }
}

/// `resolveWebhookKeys`: [the reconciliation key (`Payment.gatewayOrderId`), Razorpay's
/// payment id] for the event family, or `None` for an event that is not handled.
pub fn webhook_keys(event: Option<&str>, payload: &Map<String, Value>) -> Option<(Option<String>, Option<String>)> {
    let event = event?;
    if event.starts_with("payment_link.") {
        let link = entity(payload, "payment_link")?;
        return Some((map_str(&link, "id"), map_str(&link, "payment_id")));
    }
    if event.starts_with("order.") {
        let order = entity(payload, "order");
        let pay = entity(payload, "payment");
        return Some((order.and_then(|o| map_str(&o, "id")), pay.and_then(|p| map_str(&p, "id"))));
    }
    if event.starts_with("payment.") {
        let pay = entity(payload, "payment")?;
        return Some((map_str(&pay, "order_id"), map_str(&pay, "id")));
    }
    None
}

pub fn is_paid_event(e: Option<&str>) -> bool {
    matches!(e, Some("payment_link.paid" | "order.paid" | "payment.captured"))
}

pub fn is_failed_event(e: Option<&str>) -> bool {
    matches!(e, Some("payment_link.expired" | "payment_link.cancelled" | "payment.failed"))
}

/// Razorpay's webhook signature: HMAC-SHA256 of the raw body with the webhook secret, lower
/// case hex, compared exactly.
pub fn verify_signature(body: &str, signature: Option<&str>, secret: &str) -> bool {
    let Some(sig) = signature.filter(|s| !s.trim().is_empty()) else { return false };
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret.as_bytes()) else { return false };
    mac.update(body.as_bytes());
    let hex: String = mac.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect();
    hex == sig
}

/// `rupees(paise)`: the paise value's text as a `BigDecimal`, divided by 100 exactly.
pub fn rupees(v: Option<&Value>) -> Option<Big> {
    let text = java_to_string(v?)?;
    Some(Big::parse(&text)?.divide_exact(100))
}

/// A rupee amount as Jackson writes the `BigDecimal` into the payment's JSON column (MySQL keeps
/// it as a double either way).
fn rupee_json(b: Option<Big>) -> Value {
    b.and_then(|b| serde_json::Number::from_f64(b.to_f64())).map(Value::Number).unwrap_or(Value::Null)
}

impl Billing<'_> {
    /// `resolveBuyer`: the caller's own client, or a client it manages.
    async fn resolve_buyer(&self, ca: &ContextAuth, buyer: Option<u64>) -> AuthResult<Option<std::sync::Arc<Client>>> {
        let own = ca.user.client_id();
        match buyer {
            None => self.client_info(own).await,
            Some(b) if b == own => self.client_info(own).await,
            Some(b) => {
                if !self.manages(ca, b).await? {
                    return Err(forbidden("buy for this client"));
                }
                self.client_info(b).await
            }
        }
    }

    /// The bundle and its config, each the DAO's 404 when missing.
    async fn bundle_and_config(&self, bundle_id: Option<u64>) -> AuthResult<(Rec, Rec)> {
        let bundle = self.read(&BUNDLE, bundle_id).await?;
        let config = self.read(&CONFIG, bundle.u64("billingConfigId")).await?;
        Ok((bundle, config))
    }

    /// `quote`: the price breakup, nothing saved.
    pub async fn quote(&self, req: &PurchaseRequest) -> AuthResult<Value> {
        let (bundle, config) = self.bundle_and_config(req.bundle_id).await?;
        let p = price(&bundle, &config, req.tokens)?;
        Ok(quote_json(&bundle, &p))
    }

    /// `buildInvoice` + `invoiceService.create`: the PENDING invoice, seller and buyer
    /// snapshotted, numbered for the seller's financial year.
    async fn create_invoice(&self, buyer: &Client, bundle: &Rec, config: &Rec, requested: Option<Dec>) -> AuthResult<Option<Rec>> {
        let p = price(bundle, config, requested)?;
        let app = config.u64("appId");
        let profile = match app {
            Some(a) => self.buyer_profile(buyer.id(), a).await?,
            None => None,
        }
        .unwrap_or_else(|| Rec::new(&crate::data::billing_admin::PROFILE));
        let seller = config.u64("clientId").unwrap_or(0);
        let number = self.store.next_invoice_number(seller, &fin_year(self.today())).await?;
        let s = |p: &str| config.str(p).map(|x| Val::Str(x.into())).unwrap_or(Val::Null);
        let buyer_name = profile.str("legalName").filter(|n| !n.trim().is_empty()).map(str::to_string).or_else(|| buyer.name.clone());
        let opt_str = |v: Option<String>| v.map(Val::Str).unwrap_or(Val::Null);
        let invoice = Rec::new(&INVOICE)
            .with("invoiceNumber", Val::Str(number))
            .with("invoiceDate", Val::Ts(self.now_utc()))
            .with("status", Val::Str("PENDING".into()))
            .with("sellerClientId", Val::Id(seller))
            .with("sellerLegalName", s("sellerLegalName"))
            .with("sellerGstin", s("sellerGstin"))
            .with("sellerAddress", s("sellerAddress"))
            .with("clientId", Val::Id(buyer.id()))
            .with("buyerLegalName", opt_str(buyer_name))
            .with("buyerGstin", opt_str(profile.str("gstin").map(str::to_string)))
            .with("buyerAddress", opt_str(format_address(&profile)))
            .with("appId", app.map(Val::Id).unwrap_or(Val::Null))
            .with("bundleId", bundle.id().map(Val::Id).unwrap_or(Val::Null))
            .with("bundleLabel", opt_str(bundle.str("label").map(str::to_string)))
            .with("tokensPurchased", p.tokens.map(Val::Dec).unwrap_or(Val::Null))
            .with("baseAmount", Val::Dec(p.base))
            .with("gstPercentage", Val::Dec(p.gst_percentage))
            .with("gstAmount", Val::Dec(p.gst_amount))
            .with("totalAmount", Val::Dec(p.total))
            .with("currency", Val::Str(p.currency));
        let id = self.store.insert(&invoice).await?;
        self.store.by_id(&INVOICE, id).await
    }

    /// The seller's Razorpay key id and secret (`IllegalStateException` when either is blank).
    fn razorpay_keys(config: &Rec) -> AuthResult<(String, String)> {
        let gw = config.map("paymentGatewayConfig");
        let (id, secret) = (map_str(&gw, "keyId"), map_str(&gw, "keySecret"));
        if blank(&id) || blank(&secret) {
            return Err(AuthError::internal("Razorpay keyId/keySecret missing in billing config"));
        }
        Ok((id.unwrap_or_default(), secret.unwrap_or_default()))
    }

    /// The PENDING payment for a gateway answer (`paymentDAO.create`).
    async fn pending_payment(&self, invoice: &Rec, gateway_id: Option<String>, init: &Value) -> AuthResult<()> {
        let mut response = Map::new();
        response.insert("init".into(), init.clone());
        let payment = Rec::new(&PAYMENT)
            .with("invoiceId", invoice.id().map(Val::Id).unwrap_or(Val::Null))
            .with("clientId", invoice.u64("clientId").map(Val::Id).unwrap_or(Val::Null))
            .with("gateway", Val::Str("RAZORPAY".into()))
            .with("gatewayOrderId", gateway_id.map(Val::Str).unwrap_or(Val::Null))
            .with("amount", invoice.dec("totalAmount").map(Val::Dec).unwrap_or(Val::Null))
            .with("status", Val::Str("PENDING".into()))
            .with("response", Val::Json(Value::Object(response)));
        let id = self.store.insert(&payment).await?;
        self.store.by_id(&PAYMENT, id).await?;
        Ok(())
    }

    /// `(String) r.get(key)`: a ClassCastException for anything but text.
    fn gateway_text(r: &Value, key: &str) -> AuthResult<Option<String>> {
        match r.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) => Ok(Some(s.clone())),
            Some(_) => Err(AuthError::internal("class java.lang.Object cannot be cast to class java.lang.String")),
        }
    }

    fn paise(invoice: &Rec) -> i64 {
        long_value(invoice.dec("totalAmount").unwrap_or(Dec::ZERO).mul(Dec::from_i64(100)))
    }

    /// `RazorpayPaymentService.initialize`: a hosted payment link; its short URL.
    async fn payment_link(&self, invoice: &Rec, config: &Rec) -> AuthResult<Option<String>> {
        let (key_id, key_secret) = Self::razorpay_keys(config)?;
        let gw = config.map("paymentGatewayConfig");
        let mut body = Map::new();
        body.insert("amount".into(), Value::from(Self::paise(invoice)));
        body.insert("currency".into(), Value::from(invoice.str("currency").unwrap_or("INR")));
        body.insert("description".into(), Value::from(format!("Token purchase {}", invoice.str("invoiceNumber").unwrap_or("null"))));
        body.insert("reference_id".into(), Value::from(format!("INV_{}", opt_id(invoice.id()))));
        let callback = map_str(&gw, "callbackUrl");
        if !blank(&callback) {
            body.insert("callback_url".into(), Value::from(callback.unwrap_or_default()));
            body.insert("callback_method".into(), Value::from("get"));
        }
        let r = self.outside.razorpay("/payment_links", &key_id, &key_secret, &Value::Object(body)).await?;
        let id = Self::gateway_text(&r, "id")?;
        let short = Self::gateway_text(&r, "short_url")?;
        self.pending_payment(invoice, id, &r).await?;
        Ok(short)
    }

    /// `RazorpayPaymentService.createOrder`: a Checkout order; what the browser needs to open it.
    async fn checkout_order(&self, ca: &ContextAuth, invoice: &Rec, config: &Rec, buyer: Option<&Client>) -> AuthResult<Value> {
        let (key_id, key_secret) = Self::razorpay_keys(config)?;
        let amount = Self::paise(invoice);
        let currency = invoice.str("currency").unwrap_or("INR").to_string();
        let mut notes = Map::new();
        notes.insert("invoiceId".into(), opt(invoice.id().map(|i| i.to_string())));
        notes.insert("invoiceNumber".into(), opt(invoice.str("invoiceNumber").map(str::to_string)));
        let mut body = Map::new();
        body.insert("amount".into(), Value::from(amount));
        body.insert("currency".into(), Value::from(currency.as_str()));
        body.insert("receipt".into(), Value::from(format!("INV_{}", opt_id(invoice.id()))));
        body.insert("notes".into(), Value::Object(notes));
        let r = self.outside.razorpay("/orders", &key_id, &key_secret, &Value::Object(body)).await?;
        let order_id = Self::gateway_text(&r, "id")?;
        self.pending_payment(invoice, order_id.clone(), &r).await?;
        Ok(Obj::new()
            .put("orderId", opt(order_id))
            .put("keyId", key_id)
            .put("amount", amount)
            .put("currency", currency)
            .put("invoiceId", opt(invoice.id()))
            .put("invoiceNumber", opt(invoice.str("invoiceNumber").map(str::to_string)))
            .put("totalAmount", invoice.dec("totalAmount").map(Dec::to_json).unwrap_or(Value::Null))
            .put("prefillName", opt(prefill_name(ca, buyer)))
            .put("prefillEmail", opt(ca.user.email_id.clone()))
            .put("prefillContact", opt(ca.user.phone_number.clone()))
            .build())
    }

    /// The buyer, the bundle with its config, and the new PENDING invoice of a purchase.
    async fn start_purchase(&self, ca: &ContextAuth, req: &PurchaseRequest) -> AuthResult<Option<(std::sync::Arc<Client>, Rec, Rec)>> {
        let Some(buyer) = self.resolve_buyer(ca, req.client_id).await? else { return Ok(None) };
        let (bundle, config) = self.bundle_and_config(req.bundle_id).await?;
        let Some(invoice) = self.create_invoice(&buyer, &bundle, &config, req.tokens).await? else { return Ok(None) };
        Ok(Some((buyer, config, invoice)))
    }

    /// `purchase`: the invoice and the hosted payment link (`PurchaseResult`).
    pub async fn purchase(&self, ca: &ContextAuth, req: &PurchaseRequest) -> AuthResult<Option<Value>> {
        let Some((_, config, invoice)) = self.start_purchase(ca, req).await? else { return Ok(None) };
        let url = self.payment_link(&invoice, &config).await?;
        Ok(Some(
            Obj::new()
                .put("invoiceId", opt(invoice.id()))
                .put("invoiceNumber", opt(invoice.str("invoiceNumber").map(str::to_string)))
                .put("totalAmount", invoice.dec("totalAmount").map(Dec::to_json).unwrap_or(Value::Null))
                .put("currency", opt(invoice.str("currency").map(str::to_string)))
                .put("paymentUrl", opt(url))
                .build(),
        ))
    }

    /// `purchaseWithOrder`: the invoice and a Checkout order (`CheckoutOrderResult`).
    pub async fn purchase_order(&self, ca: &ContextAuth, req: &PurchaseRequest) -> AuthResult<Option<Value>> {
        let Some((buyer, config, invoice)) = self.start_purchase(ca, req).await? else { return Ok(None) };
        Ok(Some(self.checkout_order(ca, &invoice, &config, Some(&buyer)).await?))
    }

    /// `repay`: a fresh order for the caller's PENDING or FAILED invoice.
    pub async fn repay(&self, ca: &ContextAuth, invoice_id: Option<u64>) -> AuthResult<Option<Value>> {
        let invoice = self.read(&INVOICE, invoice_id).await?;
        if !ca.is_system_client() && Some(ca.user.client_id()) != invoice.u64("clientId") {
            return Err(forbidden("pay this invoice"));
        }
        let status = invoice.str("status").unwrap_or("null");
        if status != "PENDING" && status != "FAILED" {
            return Err(params_not_found(&format!("invoice (already {status})")));
        }
        let (_, config) = self.bundle_and_config(invoice.u64("bundleId")).await?;
        let Some(buyer) = self.client_info(invoice.u64("clientId").unwrap_or(0)).await? else { return Ok(None) };
        Ok(Some(self.checkout_order(ca, &invoice, &config, Some(&buyer)).await?))
    }

    /// `handleWebhook`: the payment behind the event, verified with its seller's webhook secret,
    /// settled; anything unknown, unverified or not terminal changes nothing.
    pub async fn webhook(&self, ca: &ContextAuth, raw: &str, signature: Option<&str>) -> AuthResult<()> {
        let Some(payload) = gson_map(raw) else {
            tracing::warn!("Razorpay webhook: unparseable body");
            return Ok(());
        };
        let event = map_str(&payload, "event");
        let Some((recon, rzp_payment_id)) = webhook_keys(event.as_deref(), &payload) else { return Ok(()) };
        let Some(recon) = recon.filter(|r| !r.trim().is_empty()) else { return Ok(()) };
        let found = self.store.find(&PAYMENT, &Find { first: true, ..Find::eq(vec![("GATEWAY_ORDER_ID", Val::Str(recon.clone()))]) }).await?;
        let Some(payment) = found.into_iter().next() else { return Ok(()) };
        let invoice = self.read(&INVOICE, payment.u64("invoiceId")).await?;
        let (Some(app), Some(seller)) = (invoice.u64("appId"), invoice.u64("sellerClientId")) else { return Ok(()) };
        let Some(config) = self.config_of(app, seller).await? else { return Ok(()) };
        let secret = map_str(&config.map("paymentGatewayConfig"), "webhookSecret");
        if blank(&secret) || !verify_signature(raw, signature, secret.as_deref().unwrap_or("")) {
            tracing::warn!(reconciliation = recon, "Razorpay webhook: signature verification failed");
            return Ok(());
        }
        if !is_paid_event(event.as_deref()) {
            return self.mark_failed_if_needed(ca, event.as_deref(), payment, invoice).await;
        }
        self.apply_paid(ca, payment, invoice, rzp_payment_id, &payload).await
    }

    /// `applyPaid`.
    async fn apply_paid(&self, ca: &ContextAuth, mut payment: Rec, mut invoice: Rec, link_payment_id: Option<String>, payload: &Map<String, Value>) -> AuthResult<()> {
        if payment.str("status") == Some("PAID") {
            return Ok(());
        }
        let now = self.now_local();
        let pay = entity(payload, "payment");
        let payment_id = pay.as_ref().and_then(|e| map_str(e, "id")).filter(|s| !s.trim().is_empty()).or(link_payment_id);
        let captured = pay.as_ref().and_then(|e| rupees(e.get("amount")));
        let total = invoice.dec("totalAmount").map(Big::of);
        let mismatch = matches!((captured, total), (Some(c), Some(t)) if c.cmp_value(&t) != std::cmp::Ordering::Equal);

        let mut response = payment.map("response");
        response.insert("webhook".into(), Value::Object(payload.clone()));
        if let Some(e) = &pay {
            let mut c = Map::new();
            c.insert("amount".into(), rupee_json(captured));
            c.insert("method".into(), e.get("method").cloned().unwrap_or(Value::Null));
            c.insert("fee".into(), rupee_json(rupees(e.get("fee"))));
            c.insert("tax".into(), rupee_json(rupees(e.get("tax"))));
            c.insert("currency".into(), e.get("currency").cloned().unwrap_or(Value::Null));
            c.insert("status".into(), e.get("status").cloned().unwrap_or(Value::Null));
            response.insert("captured".into(), Value::Object(c));
        }
        let reference = payment_id.clone().or_else(|| payment.str("gatewayOrderId").map(str::to_string));
        payment
            .set("status", Val::Str("PAID".into()))
            .set("gatewayPaymentId", payment_id.map(Val::Str).unwrap_or(Val::Null))
            .set("paidAt", Val::Ts(now))
            .set("response", Val::Json(Value::Object(response)));
        invoice
            .set("gateway", Val::Str("RAZORPAY".into()))
            .set("paymentReference", reference.map(Val::Str).unwrap_or(Val::Null))
            .set("paidAt", Val::Ts(now));
        if mismatch {
            tracing::error!(
                invoice = invoice.str("invoiceNumber"),
                "Razorpay amount mismatch: captured differs from the invoice total -> UNDER_REVIEW, not crediting"
            );
            invoice.set("status", Val::Str("UNDER_REVIEW".into()));
            self.update_row(&payment).await?;
            self.update_row(&invoice).await?;
            return Ok(());
        }
        invoice.set("status", Val::Str("PAID".into()));
        self.update_row(&payment).await?;
        self.credit_from_payment(&invoice).await?;
        self.mark_paid_and_emit(ca, &invoice).await?;
        Ok(())
    }

    /// `markFailedIfNeeded`: an expired, cancelled or failed payment fails its invoice.
    async fn mark_failed_if_needed(&self, ca: &ContextAuth, event: Option<&str>, mut payment: Rec, mut invoice: Rec) -> AuthResult<()> {
        if !is_failed_event(event) {
            return Ok(());
        }
        payment.set("status", Val::Str("FAILED".into()));
        invoice.set("status", Val::Str("FAILED".into()));
        self.update_row(&payment).await?;
        self.update_row(&invoice).await?;
        self.raise_invoice_event(ca, &invoice, super::invoices::INVOICE_PAYMENT_FAILED).await
    }
}

fn opt_id(id: Option<u64>) -> String {
    id.map(|i| i.to_string()).unwrap_or_else(|| "null".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::billing_admin::BUNDLE;
    use serde_json::json;

    fn d(s: &str) -> Dec {
        Dec::parse(s).unwrap()
    }

    fn bundle(kind: &str) -> Rec {
        Rec::new(&BUNDLE).with("id", Val::Id(70)).with("bundleType", Val::Str(kind.into())).with("label", Val::Str("Starter".into()))
    }

    fn config(gst: &str) -> Rec {
        Rec::new(&CONFIG).with("gstPercentage", Val::Dec(d(gst)))
    }

    #[test]
    fn fixed_and_custom_prices() {
        // BundlePurchaseServiceTest.fixedBundleAddsGstOnTopAndSnapshotsInvoice.
        let b = bundle("FIXED").with("tokens", Val::Dec(d("1000"))).with("price", Val::Dec(d("900")));
        let p = price(&b, &config("18"), None).unwrap();
        assert_eq!((p.gst_amount.to_string(), p.total.to_string(), p.currency.as_str()), ("162.00".into(), "1062.00".into(), "INR"));
        // customBundlePricesAtPricePerToken: 1000 x 0.9 = 900.0.
        let c = bundle("CUSTOM").with("pricePerToken", Val::Dec(d("0.9"))).with("minTokens", Val::Dec(d("500"))).with("maxTokens", Val::Dec(d("5000")));
        let p = price(&c, &config("18"), Some(d("1000"))).unwrap();
        assert_eq!((p.base.to_string(), p.total.to_string(), p.tokens), ("900.0".into(), "1062.00".into(), Some(d("1000"))));
        // Below the minimum, above the maximum, missing or non-positive.
        assert_eq!(price(&c, &config("18"), Some(d("100"))).unwrap_err().message(), "Required params {tokens (below minimum)} for $ not found");
        assert_eq!(price(&c, &config("18"), Some(d("9000"))).unwrap_err().message(), "Required params {tokens (above maximum)} for $ not found");
        assert_eq!(price(&c, &config("18"), None).unwrap_err().message(), "Required params {tokens} for $ not found");
        assert_eq!(price(&c, &config("18"), Some(d("0"))).unwrap_err().message(), "Required params {tokens} for $ not found");
        // No GST configured, a currency of its own.
        let b2 = b.clone().with("currency", Val::Str("USD".into()));
        let p = price(&b2, &Rec::new(&CONFIG), None).unwrap();
        assert_eq!((p.gst_amount.to_string(), p.total.to_string(), p.currency.as_str()), ("0.00".into(), "900.00".into(), "USD"));
        // Java's NullPointerExceptions.
        assert!(price(&bundle("FIXED"), &config("18"), None).unwrap_err().to_string().contains("\"base\" is null"));
        assert!(price(&bundle("CUSTOM"), &config("18"), Some(d("5"))).unwrap_err().to_string().contains("multiplicand"));
        // The local 2K bundle's quote, as Java answered it.
        let b = bundle("FIXED").with("id", Val::Id(1)).with("label", Val::Str("2K Tokens".into())).with("tokens", Val::Dec(d("2000.0000"))).with("price", Val::Dec(d("999.0000"))).with("currency", Val::Str("INR".into()));
        let q = quote_json(&b, &price(&b, &config("18.00"), None).unwrap());
        assert_eq!(crate::jackson::pretty(&q), "{\n  \"bundleId\" : 1,\n  \"bundleLabel\" : \"2K Tokens\",\n  \"tokens\" : 2000.0000,\n  \"baseAmount\" : 999.0000,\n  \"gstPercentage\" : 18.00,\n  \"gstAmount\" : 179.82,\n  \"totalAmount\" : 1178.8200,\n  \"currency\" : \"INR\"\n}");
    }

    #[test]
    fn invoice_snapshot_helpers() {
        assert_eq!(fin_year(chrono::NaiveDate::from_ymd_opt(2026, 10, 16).unwrap()), "2026-27");
        assert_eq!(fin_year(chrono::NaiveDate::from_ymd_opt(2027, 3, 31).unwrap()), "2026-27");
        assert_eq!(fin_year(chrono::NaiveDate::from_ymd_opt(2099, 4, 1).unwrap()), "2099-00");
        let p = Rec::new(&crate::data::billing_admin::PROFILE)
            .with("addressLine", Val::Str(" main ".into()))
            .with("city", Val::Str("hyd".into()))
            .with("state", Val::Str("  ".into()))
            .with("country", Val::Str("IN".into()));
        assert_eq!(format_address(&p).as_deref(), Some("main, hyd, IN"));
        assert_eq!(format_address(&Rec::new(&crate::data::billing_admin::PROFILE)), None);
        let mut ca = ContextAuth::default();
        let buyer = Client { name: Some("Acme".into()), ..Default::default() };
        assert_eq!(prefill_name(&ca, Some(&buyer)).as_deref(), Some("Acme"));
        assert_eq!(prefill_name(&ca, None), None);
        ca.user.first_name = Some("Kiran".into());
        assert_eq!(prefill_name(&ca, Some(&buyer)).as_deref(), Some("Kiran"));
        ca.user.last_name = Some("G".into());
        assert_eq!(prefill_name(&ca, None).as_deref(), Some("Kiran G"));
    }

    #[test]
    fn webhook_payloads_read_like_gson() {
        let body = r#"{"event":"payment_link.paid","payload":{"payment_link":{"entity":{"id":"plink_1","payment_id":"pay_xyz"}},"payment":{"entity":{"id":"pay_real","amount":106200,"fee":2124,"tax":324,"method":"upi"}}}}"#;
        let m = gson_map(body).unwrap();
        assert_eq!(map_str(&m, "event").as_deref(), Some("payment_link.paid"));
        assert_eq!(webhook_keys(Some("payment_link.paid"), &m), Some((Some("plink_1".into()), Some("pay_xyz".into()))));
        let pay = entity(&m, "payment").unwrap();
        assert_eq!(map_str(&pay, "amount").as_deref(), Some("106200.0"));
        assert_eq!(rupees(pay.get("amount")).unwrap().to_dec().to_string(), "1062.0");
        assert_eq!(rupee_json(rupees(pay.get("fee"))), json!(21.24));
        assert_eq!(rupee_json(None), Value::Null);
        assert_eq!(rupees(Some(&json!("x"))), None);
        assert_eq!(rupees(None), None);
        // order.* and payment.* families.
        let o = gson_map(r#"{"payload":{"order":{"entity":{"id":"order_1"}},"payment":{"entity":{"id":"pay_2","order_id":"order_1"}}}}"#).unwrap();
        assert_eq!(webhook_keys(Some("order.paid"), &o), Some((Some("order_1".into()), Some("pay_2".into()))));
        assert_eq!(webhook_keys(Some("payment.captured"), &o), Some((Some("order_1".into()), Some("pay_2".into()))));
        assert_eq!(webhook_keys(Some("order.paid"), &Map::new()), Some((None, None)));
        assert_eq!(webhook_keys(Some("payment.failed"), &Map::new()), None);
        assert_eq!(webhook_keys(Some("payment_link.paid"), &Map::new()), None);
        assert_eq!(webhook_keys(Some("refund.created"), &o), None);
        assert_eq!(webhook_keys(None, &o), None);
        assert!(gson_map("not-json").is_none() && gson_map("[1]").is_none() && gson_map("null").is_none());
        assert!(is_paid_event(Some("order.paid")) && !is_paid_event(Some("payment.failed")) && !is_paid_event(None));
        assert!(is_failed_event(Some("payment_link.expired")) && !is_failed_event(Some("order.paid")));
        let odd = json!({"a": {"b": [1, null, true]}, "c": null});
        let odd = odd.as_object().unwrap();
        assert_eq!(map_str(odd, "a").as_deref(), Some("{b=[1, null, true]}"));
        assert_eq!(map_str(odd, "c"), None);
    }

    #[test]
    fn signatures() {
        // RazorpayPaymentServiceTest.sign: HMAC-SHA256 of the body with the secret, lower-case hex.
        let body = "{\"event\":\"payment_link.paid\"}";
        let mut mac = Hmac::<Sha256>::new_from_slice(b"whsec_test_123").unwrap();
        mac.update(body.as_bytes());
        let sig: String = mac.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect();
        assert!(verify_signature(body, Some(&sig), "whsec_test_123"));
        assert!(!verify_signature(body, Some(&sig.to_uppercase()), "whsec_test_123"));
        assert!(!verify_signature(body, Some("deadbeef"), "whsec_test_123"));
        assert!(!verify_signature(body, Some(" "), "whsec_test_123"));
        assert!(!verify_signature(body, None, "whsec_test_123"));
        assert!(!verify_signature(&format!("{body} "), Some(&sig), "whsec_test_123"));
    }
}
