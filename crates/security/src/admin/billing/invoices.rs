//! `InvoiceService` and `BillingProfileService`: the token-purchase invoices (party-guarded
//! reads, the seller's and the buyer's pages, the document download keys, the invoice events)
//! and the buyer's own billing profile.

use std::collections::HashMap;

use serde_json::Value;

use super::service::{forbidden, Billing};
use crate::condition::{Cond, Filter};
use crate::data::billing_admin::{Find, Rec, Val, INVOICE, PROFILE};
use crate::errors::AuthResult;
use crate::events::EventMessage;
use crate::jackson::{opt, Obj};
use crate::javamap::hash_map_order_str;
use crate::model::ContextAuth;
use crate::spring::Pageable;
use crate::web::page_of;

pub const INVOICE_GENERATED: &str = "INVOICE_GENERATED";
pub const INVOICE_PAYMENT_FAILED: &str = "INVOICE_PAYMENT_FAILED";

/// What `BillingProfileService.copyFields` takes from the request.
const PROFILE_EDITABLE: [&str; 7] = ["legalName", "gstin", "addressLine", "city", "state", "country", "postalCode"];

/// `capturedMethod`: `response.captured.method` as text.
pub fn captured_method(payment: &Rec) -> Option<String> {
    let response = payment.map("response");
    match response.get("captured")? {
        Value::Object(c) => match c.get("method")? {
            Value::Null => None,
            Value::String(s) => Some(s.clone()),
            other => Some(other.to_string()),
        },
        _ => None,
    }
}

/// `methodByInvoice`: per invoice, the method of its PAID payment, else of the first payment
/// that has one.
pub fn method_by_invoice(payments: &[Rec]) -> HashMap<u64, String> {
    let mut out = HashMap::new();
    for p in payments {
        let (Some(method), Some(invoice)) = (captured_method(p), p.u64("invoiceId")) else { continue };
        if !out.contains_key(&invoice) || p.str("status") == Some("PAID") {
            out.insert(invoice, method);
        }
    }
    out
}

/// `pickPayment`: the PAID payment, else the last one.
pub fn pick_payment(payments: &[Rec]) -> Option<&Rec> {
    payments.iter().find(|p| p.str("status") == Some("PAID")).or(payments.last())
}

/// `gatewayLabel`: `RAZORPAY` -> `Razorpay`.
pub fn gateway_label(gateway: &str) -> String {
    let mut chars = gateway.chars();
    chars.next().map(|f| format!("{f}{}", chars.as_str().to_lowercase())).unwrap_or_default()
}

/// The `Invoice` DTO with its transient `paymentMethod`.
pub fn invoice_json(inv: &Rec, method: Option<&str>) -> Value {
    let Value::Object(mut m) = inv.to_json() else { return Value::Null };
    if let Some(x) = method.filter(|x| !x.is_empty()) {
        m.insert("paymentMethod".into(), Value::from(x));
    }
    Value::Object(m)
}

/// `FilterCondition.of(field, id, EQUALS)`.
fn id_filter(field: &str, id: u64) -> Cond {
    Cond::Filter(Filter::eq(field, id))
}

/// `ComplexCondition.and(a, b[, condition])`.
fn scoped(a: Cond, b: Cond, condition: Option<Cond>) -> Cond {
    let mut all = vec![a, b];
    all.extend(condition);
    Cond::and(all)
}

impl Billing<'_> {
    /// `assertCanSee`: SYSTEM, the seller or the buyer.
    fn assert_can_see_invoice(&self, ca: &ContextAuth, inv: &Rec) -> AuthResult<()> {
        let own = Some(ca.user.client_id());
        if ca.is_system_client() || own == inv.u64("sellerClientId") || own == inv.u64("clientId") {
            return Ok(());
        }
        Err(forbidden("the invoice"))
    }

    /// `InvoiceService.readById` (the authority is checked by the route).
    pub async fn invoice_read(&self, ca: &ContextAuth, id: u64) -> AuthResult<Value> {
        let inv = self.read(&INVOICE, Some(id)).await?;
        self.assert_can_see_invoice(ca, &inv)?;
        let payments = self.store.payments_of(&[id]).await?;
        Ok(invoice_json(&inv, method_by_invoice(&payments).get(&id).map(String::as_str)))
    }

    /// `readDocumentKeys`: download keys for the invoice and receipt PDFs, under the invoice's
    /// own client; `None` when its app or client is gone.
    pub async fn invoice_documents(&self, ca: &ContextAuth, id: u64) -> AuthResult<Option<Value>> {
        let inv = self.read(&INVOICE, Some(id)).await?;
        self.assert_can_see_invoice(ca, &inv)?;
        let Some(app) = (match inv.u64("appId") {
            Some(a) => self.app_by_id(a).await?,
            None => None,
        }) else {
            return Ok(None);
        };
        let Some(client) = (match inv.u64("clientId") {
            Some(c) => self.client_info(c).await?,
            None => None,
        }) else {
            return Ok(None);
        };
        let path = |folder: &str, prefix: &str| format!("{}/{folder}/{}/{prefix}-{id}.pdf", client.code(), app.app_code);
        let (invoice_path, receipt_path) = (path("invoices", "invoice"), path("receipts", "receipt"));
        let (invoice, receipt) = futures::try_join!(self.outside.secured_key(&invoice_path), self.outside.secured_key(&receipt_path))?;
        Ok(Some(Obj::new().put("invoiceUrl", invoice).put("receiptUrl", receipt).build()))
    }

    /// A page of invoices with their payment methods.
    async fn invoice_page_json(&self, ca: &ContextAuth, cond: Cond, page: &Pageable) -> AuthResult<Value> {
        let party = (!ca.is_system_client()).then(|| ca.user.client_id());
        let rows = self.store.invoice_page(Some(&cond), party, page).await?;
        let ids: Vec<u64> = rows.rows.iter().filter_map(Rec::id).collect();
        let methods = if ids.is_empty() { HashMap::new() } else { method_by_invoice(&self.store.payments_of(&ids).await?) };
        let content =
            rows.rows.iter().map(|r| invoice_json(r, r.id().and_then(|i| methods.get(&i)).map(String::as_str))).collect();
        Ok(page_of(content, page, rows.total.unwrap_or(0)))
    }

    /// `InvoiceService.readPageFilter`: the seller's (clientCode header) invoices of the app
    /// (appCode header), with the caller's filters; `None` when either does not resolve.
    pub async fn invoice_page(
        &self,
        ca: &ContextAuth,
        page: &Pageable,
        cond: Option<Cond>,
        app_code: Option<&str>,
        client_code: Option<&str>,
    ) -> AuthResult<Option<Value>> {
        let Some(app) = self.app_by_code(app_code).await? else { return Ok(None) };
        let Some(seller) = self.client_by_code(client_code).await? else { return Ok(None) };
        let c = scoped(id_filter("sellerClientId", seller.id()), id_filter("appId", app.id), cond);
        Ok(Some(self.invoice_page_json(ca, c, page).await?))
    }

    /// `readMyPurchases`: the caller's own purchases of the app.
    pub async fn my_invoices(&self, ca: &ContextAuth, page: &Pageable, cond: Option<Cond>, app_code: Option<&str>) -> AuthResult<Option<Value>> {
        let Some(app) = self.app_by_code(app_code).await? else { return Ok(None) };
        let c = scoped(id_filter("clientId", ca.user.client_id()), id_filter("appId", app.id), cond);
        Ok(Some(self.invoice_page_json(ca, c, page).await?))
    }

    /// `markPaidAndEmit`: the PAID invoice saved, then `INVOICE_GENERATED`.
    pub async fn mark_paid_and_emit(&self, ca: &ContextAuth, inv: &Rec) -> AuthResult<Rec> {
        let saved = self.update_row(inv).await?;
        self.raise_invoice_event(ca, &saved, INVOICE_GENERATED).await?;
        Ok(saved)
    }

    /// `raiseInvoiceEvent`: nothing when the invoice's app or client is gone; the URL comes from
    /// the buyer's managing client (the buyer itself when it has none).
    pub async fn raise_invoice_event(&self, ca: &ContextAuth, inv: &Rec, name: &str) -> AuthResult<()> {
        let (Some(app_id), Some(client_id)) = (inv.u64("appId"), inv.u64("clientId")) else { return Ok(()) };
        let Some(app) = self.app_by_id(app_id).await? else { return Ok(()) };
        let Some(client) = self.client_info(client_id).await? else { return Ok(()) };
        let url_client = match self.dir().managed_client(client_id).await {
            Ok(m) => m.id.unwrap_or(client_id),
            Err(_) => client_id,
        };
        let url = self.outside.app_url(self.internal, ca, &app, url_client).await?;
        let payments = match inv.id() {
            Some(i) => self.store.payments_of(&[i]).await?,
            None => vec![],
        };
        let payment = pick_payment(&payments);
        let num = |p: &str| inv.dec(p).map(|d| d.to_json()).unwrap_or(Value::Null);
        let text = |p: &str| opt(inv.str(p).map(str::to_string));
        let gateway = payment.and_then(|p| p.str("gateway")).map(gateway_label);
        let fields: Vec<(&str, Value)> = vec![
            ("urlPrefix", Value::from(url)),
            ("invoiceId", opt(inv.id())),
            ("invoiceNumber", text("invoiceNumber")),
            ("invoiceDate", Value::from(inv.ts("invoiceDate").map(|t| t.date().to_string()).unwrap_or_default())),
            ("appCode", Value::from(app.app_code.clone())),
            ("clientCode", Value::from(client.code())),
            ("tokensPurchased", num("tokensPurchased")),
            ("baseAmount", num("baseAmount")),
            ("gstPercentage", num("gstPercentage")),
            ("gstAmount", num("gstAmount")),
            ("totalAmount", num("totalAmount")),
            ("currency", text("currency")),
            ("sellerLegalName", text("sellerLegalName")),
            ("sellerGstin", text("sellerGstin")),
            ("sellerAddress", text("sellerAddress")),
            ("buyerLegalName", text("buyerLegalName")),
            ("buyerGstin", text("buyerGstin")),
            ("buyerAddress", text("buyerAddress")),
            ("pdfFileKey", text("pdfFileKey")),
            ("status", text("status")),
            ("paymentReference", Value::from(payment.and_then(|p| p.str("gatewayPaymentId")).unwrap_or("").to_string())),
            ("paymentMethod", Value::from(payment.map(|p| captured_method(p).or_else(|| gateway.clone()).unwrap_or_default()).unwrap_or_default())),
            ("paymentGateway", Value::from(gateway.clone().unwrap_or_default())),
            ("paidOn", Value::from(payment.and_then(|p| p.ts("paidAt")).map(|t| t.date().to_string()).unwrap_or_default())),
        ];
        let data = hash_map_order_str(fields.iter().map(|(k, _)| *k))
            .into_iter()
            .filter_map(|k| fields.iter().find(|(f, _)| *f == k).map(|(k, v)| (k.to_string(), raw_to_plain(v))))
            .collect();
        let event = EventMessage {
            event_name: name.to_string(),
            client_code: Some(client.code().to_string()),
            app_code: Some(app.app_code.clone()),
            x_debug: None,
            draft: false,
            data,
        };
        self.events.publish(&event).await?;
        Ok(())
    }

    /// `BillingProfileDAO.findByClientAndApp`.
    async fn profile_of(&self, client: u64, app: u64) -> AuthResult<Option<Rec>> {
        let f = Find { first: true, ..Find::eq(vec![("CLIENT_ID", Val::Id(client)), ("APP_ID", Val::Id(app))]) };
        Ok(self.store.find(&PROFILE, &f).await?.into_iter().next())
    }

    /// The buyer's saved profile for a client and app (the purchase snapshots it).
    pub async fn buyer_profile(&self, client: u64, app: u64) -> AuthResult<Option<Rec>> {
        self.profile_of(client, app).await
    }

    /// `getMyProfile`: the caller's profile for the app; `None` when there is none.
    pub async fn my_profile(&self, ca: &ContextAuth, app_code: Option<&str>) -> AuthResult<Option<Rec>> {
        let Some(app) = self.app_by_code(app_code).await? else { return Ok(None) };
        self.profile_of(ca.user.client_id(), app.id).await
    }

    /// `saveMyProfile`: the caller's profile updated, or created for the caller's client.
    pub async fn save_my_profile(&self, ca: &ContextAuth, app_code: Option<&str>, input: &Rec) -> AuthResult<Option<Rec>> {
        let Some(app) = self.app_by_code(app_code).await? else { return Ok(None) };
        let client = ca.user.client_id();
        if let Some(mut existing) = self.profile_of(client, app.id).await? {
            for p in PROFILE_EDITABLE {
                existing.set(p, input.get(p).clone());
            }
            return Ok(Some(self.update_row(&existing).await?));
        }
        let mut fresh = Rec::new(&PROFILE).with("clientId", Val::Id(client)).with("appId", Val::Id(app.id));
        for p in PROFILE_EDITABLE {
            fresh.set(p, input.get(p).clone());
        }
        let id = self.store.insert(&fresh).await?;
        self.store.by_id(&PROFILE, id).await
    }
}

/// Event data travels through `crates/connections`' JSON writer: a `BigDecimal` goes as the
/// number it is (see DIFFERENCES.md).
fn raw_to_plain(v: &Value) -> Value {
    match v {
        Value::String(s) if s.starts_with(crate::jackson::RAW_NUMBER) => {
            serde_json::from_str(&s[crate::jackson::RAW_NUMBER.len()..]).unwrap_or(Value::Null)
        }
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::billing_admin::PAYMENT;
    use serde_json::json;

    fn payment(invoice: u64, status: &str, method: Option<&str>) -> Rec {
        let response = match method {
            Some(m) => json!({"init": {}, "captured": {"method": m}}),
            None => json!({"init": {}}),
        };
        Rec::new(&PAYMENT)
            .with("invoiceId", Val::Id(invoice))
            .with("status", Val::Str(status.into()))
            .with("response", Val::Json(response))
            .with("gateway", Val::Str("RAZORPAY".into()))
    }

    #[test]
    fn payment_methods_prefer_the_paid_payment() {
        let ps = vec![payment(1, "FAILED", Some("card")), payment(1, "PAID", Some("upi")), payment(1, "FAILED", Some("netbanking")), payment(2, "PENDING", None)];
        let m = method_by_invoice(&ps);
        assert_eq!(m.get(&1).map(String::as_str), Some("upi"));
        assert!(!m.contains_key(&2));
        assert_eq!(pick_payment(&ps).and_then(|p| p.str("status")), Some("PAID"));
        assert_eq!(pick_payment(&ps[2..]).and_then(|p| p.u64("invoiceId")), Some(2));
        assert!(pick_payment(&[]).is_none());
        let numeric = Rec::new(&PAYMENT).with("response", Val::Json(json!({"captured": {"method": 5}})));
        assert_eq!(captured_method(&numeric).as_deref(), Some("5"));
        let null = Rec::new(&PAYMENT).with("response", Val::Json(json!({"captured": {"method": null}})));
        assert_eq!(captured_method(&null), None);
        let flat = Rec::new(&PAYMENT).with("response", Val::Json(json!({"captured": "x"})));
        assert_eq!(captured_method(&flat), None);
        assert_eq!(gateway_label("RAZORPAY"), "Razorpay");
        assert_eq!(gateway_label(""), "");
    }

    #[test]
    fn invoice_json_appends_the_method() {
        let inv = Rec::new(&INVOICE).with("id", Val::Id(3)).with("status", Val::Str("PAID".into()));
        assert_eq!(invoice_json(&inv, Some("card")), json!({"id": 3, "status": "PAID", "paymentMethod": "card"}));
        assert_eq!(invoice_json(&inv, Some("")), json!({"id": 3, "status": "PAID"}));
        assert_eq!(invoice_json(&inv, None), json!({"id": 3, "status": "PAID"}));
    }

    #[test]
    fn pages_in_the_security_order() {
        let p = Pageable::of(0, 2, vec![]);
        let v = page_of(vec![json!({"id": 1})], &p, 9);
        let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["content", "pageable", "totalPages", "totalElements", "last", "sort", "first", "numberOfElements", "size", "number", "empty"]);
        assert_eq!(v["totalElements"], 1);
        assert_eq!(raw_to_plain(&crate::decimal::Dec::parse("2.50").unwrap().to_json()), json!(2.5));
        assert_eq!(raw_to_plain(&json!("x")), json!("x"));
    }
}
