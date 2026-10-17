//! The routes of `AppBillingBundleController`, `AppBillingConfigController`,
//! `BillingProfileController`, `BundlePurchaseController`, `InvoiceController` and
//! `WalletController`: Spring's argument resolution (path and query conversions, the request
//! body) first, then the service's `@PreAuthorize`, then the service.
//!
//! | Route group | Open to anonymous |
//! |---|---|
//! | `billing-bundles/serving`, `billing/razorpay/webhook` | yes |
//! | everything else | no |

use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use serde_json::Value;

use super::body::{self, decimal, text, ulong};
use super::configs::BUNDLE_LIST_REFUSED;
use super::purchase::PurchaseRequest;
use super::settings::BillingSettings;
use super::service::{pre_authorize, Billing, Live, APPLICATION_CREATE, INVOICE_READ, PAYMENT_CREATE, ROLE_OWNER};
use crate::admin::{Admin, AdminState};
use crate::condition::{from_params, Cond};
use crate::data::billing_admin::{Rec, Val, BUNDLE, CONFIG, PROFILE};
use crate::errors::{AuthError, AuthResult};
use crate::jackson::{empty, json};
use crate::spring::{Pageable, Params};
use crate::web::{bad_request, nothing, query_body, req_str, text as text_response, to_u64, In};

pub fn router(settings: Arc<BillingSettings>) -> Router<AdminState> {
    Router::new()
        // AppBillingBundleController
        .route("/api/security/billing-bundles", get(bundles_list).post(bundle_create))
        .route("/api/security/billing-bundles/query", post(bundles_query))
        .route("/api/security/billing-bundles/serving", get(bundles_serving))
        .route("/api/security/billing-bundles/config/{billingConfigId}", get(bundles_of_config))
        .route("/api/security/billing-bundles/{id}", get(bundle_read).put(bundle_put).patch(bundle_patch).delete(bundle_delete))
        // AppBillingConfigController
        .route("/api/security/billing-configs", get(configs_list).post(config_create))
        .route("/api/security/billing-configs/query", post(configs_query))
        .route("/api/security/billing-configs/app/{appId}", get(configs_of_app))
        .route("/api/security/billing-configs/{id}", get(config_read).put(config_put).patch(config_patch).delete(config_delete))
        // BillingProfileController
        .route("/api/security/billing-profile", get(profile_get).put(profile_put))
        // BundlePurchaseController
        .route("/api/security/billing/purchase", post(purchase))
        .route("/api/security/billing/purchase/order", post(purchase_order))
        .route("/api/security/billing/quote", post(quote))
        .route("/api/security/billing/repay", post(repay))
        .route("/api/security/billing/razorpay/webhook", post(webhook))
        // InvoiceController
        .route("/api/security/invoices", get(invoices_page))
        .route("/api/security/invoices/my", get(invoices_mine))
        .route("/api/security/invoices/query", post(invoices_query))
        .route("/api/security/invoices/{id}", get(invoice_read))
        .route("/api/security/invoices/{id}/documents", get(invoice_documents))
        // WalletController
        .route("/api/security/wallets", get(wallet))
        .route("/api/security/wallets/status", get(wallet_status))
        .route("/api/security/wallets/transactions", get(wallet_transactions))
        .route("/api/security/wallets/plan", get(wallet_plan))
        .route("/api/security/wallets/credit", post(wallet_credit))
        .route("/api/security/wallets/lookup", get(wallet_lookup))
        .route("/api/security/wallets/{walletId}/adjust", post(wallet_adjust))
        .layer(axum::Extension(settings))
}

/// A handler with the caller's context (as [`crate::web_route!`]) and the `[billing]` settings.
macro_rules! bl_route {
    ($name:ident, $path:expr, $protected:expr, |$s:ident, $r:ident, $ca:ident, $cfg:ident| $body:block) => {
        async fn $name(
            axum::extract::State($s): axum::extract::State<AdminState>,
            axum::Extension($cfg): axum::Extension<Arc<BillingSettings>>,
            req: axum::extract::Request,
        ) -> Response {
            crate::handlers::respond(
                concat!("/api/security", $path),
                async {
                    let _ = &$cfg;
                    let $r = crate::web::read(req).await?;
                    #[allow(unused_variables)]
                    let $ca = crate::web::ctx(&$s.auth, &$r, $protected).await?;
                    $body
                }
                .await,
            )
        }
    };
}

/// [`bl_route!`] with one path variable.
macro_rules! bl_route_path {
    ($name:ident, $path:expr, $protected:expr, |$s:ident, $r:ident, $ca:ident, $cfg:ident, $p:ident| $body:block) => {
        async fn $name(
            axum::extract::State($s): axum::extract::State<AdminState>,
            axum::Extension($cfg): axum::Extension<Arc<BillingSettings>>,
            axum::extract::Path($p): axum::extract::Path<String>,
            req: axum::extract::Request,
        ) -> Response {
            crate::handlers::respond(
                concat!("/api/security", $path),
                async {
                    let _ = &$cfg;
                    let $r = crate::web::read(req).await?;
                    #[allow(unused_variables)]
                    let $ca = crate::web::ctx(&$s.auth, &$r, $protected).await?;
                    $body
                }
                .await,
            )
        }
    };
}

/// The services of one request.
fn billing<'a>(s: &'a Admin, outside: &'a Live) -> Billing<'a> {
    Billing { internal: &s.internal, store: &s.internal.db, events: s.events.as_ref(), outside }
}

fn live(s: &Admin, cfg: &BillingSettings) -> Live {
    Live::new(s.files.clone(), &cfg.razorpay_base_url)
}

/// `@ResponseStatus(NO_CONTENT)` on a `Mono<Integer>`: 204, the JSON type, no body.
fn no_content() -> Response {
    let mut resp = empty(StatusCode::NO_CONTENT);
    resp.headers_mut().remove(axum::http::header::CONTENT_LENGTH);
    resp.headers_mut().insert(axum::http::header::CONTENT_TYPE, axum::http::HeaderValue::from_static("application/json"));
    resp
}

/// `ResponseEntity.ok(dto)`, or the empty `Mono` (200, no body).
fn ok_or_nothing(v: Option<Value>) -> Response {
    v.map(|v| json(&v)).unwrap_or_else(nothing)
}

fn list(rows: &[Rec]) -> Response {
    json(&Value::Array(rows.iter().map(Rec::to_json).collect()))
}

/// The page filter of the generic list (`ConditionUtil.parameterMapToMap`), less the names the
/// controller leaves out.
fn param_condition(p: &Params, skip: &[&str]) -> Option<Cond> {
    let kept: Vec<(String, String)> = p.0.iter().filter(|(k, _)| !skip.contains(&k.as_str())).cloned().collect();
    from_params(&kept)
}

/// A `@RequestBody` record: a JSON object (`null` is no body at all).
fn record(bytes: &[u8]) -> AuthResult<serde_json::Map<String, Value>> {
    if bytes.iter().all(u8::is_ascii_whitespace) || serde_json::from_slice::<Value>(bytes).is_ok_and(|v| v.is_null()) {
        return Err(bad_request("400 BAD_REQUEST \"No request body\""));
    }
    body::object(bytes)
}

fn purchase_request(bytes: &[u8]) -> AuthResult<PurchaseRequest> {
    let m = record(bytes)?;
    Ok(PurchaseRequest {
        bundle_id: body::field(&m, "bundleId", ulong)?,
        tokens: body::field(&m, "tokens", decimal)?,
        client_id: body::field(&m, "clientId", ulong)?,
    })
}

/// The body of a `PUT /{id}`, with the path's id.
fn put_entity(r: &In, schema: &'static crate::data::billing_admin::Schema, id: &str) -> AuthResult<Rec> {
    let id = to_u64(id)?;
    let mut rec = body::dto(schema, &r.body)?;
    rec.set("id", Val::Id(id));
    Ok(rec)
}

// ---- AppBillingBundleController ----

bl_route!(bundles_list, "/billing-bundles", true, |s, r, ca, cfg| {
    let _ = (Pageable::from_params(&r.params), param_condition(&r.params, &[]));
    Err::<Response, _>(AuthError::literal(StatusCode::FORBIDDEN, "SEC.BUNDLE_LIST_FORBIDDEN", BUNDLE_LIST_REFUSED))
});

bl_route!(bundles_query, "/billing-bundles/query", true, |s, r, ca, cfg| {
    query_body(&r.body)?;
    Err::<Response, _>(AuthError::literal(StatusCode::FORBIDDEN, "SEC.BUNDLE_LIST_FORBIDDEN", BUNDLE_LIST_REFUSED))
});

bl_route!(bundle_create, "/billing-bundles", true, |s, r, ca, cfg| {
    let rec = body::dto(&BUNDLE, &r.body)?;
    pre_authorize(&ca, &[APPLICATION_CREATE])?;
    let out = live(&s, &cfg);
    Ok(ok_or_nothing(billing(&s, &out).bundle_create(&ca, rec).await?.map(|b| b.to_json())))
});

bl_route!(bundles_serving, "/billing-bundles/serving", false, |s, r, ca, cfg| {
    let out = live(&s, &cfg);
    let app = r.info.header("appCode");
    let client = r.info.header("clientCode");
    Ok(list(&billing(&s, &out).serving_bundles(app.as_deref(), client.as_deref()).await?))
});

bl_route_path!(bundles_of_config, "/billing-bundles/config/{billingConfigId}", true, |s, r, ca, cfg, id| {
    let id = to_u64(&id)?;
    let out = live(&s, &cfg);
    Ok(list(&billing(&s, &out).bundles_of_config(id).await?))
});

bl_route_path!(bundle_read, "/billing-bundles/{id}", true, |s, r, ca, cfg, id| {
    let id = to_u64(&id)?;
    let out = live(&s, &cfg);
    Ok(json(&billing(&s, &out).read(&BUNDLE, Some(id)).await?.to_json()))
});

bl_route_path!(bundle_put, "/billing-bundles/{id}", true, |s, r, ca, cfg, id| {
    let entity = put_entity(&r, &BUNDLE, &id)?;
    pre_authorize(&ca, &[APPLICATION_CREATE])?;
    let out = live(&s, &cfg);
    Ok(json(&billing(&s, &out).bundle_update(&ca, &entity).await?.to_json()))
});

bl_route_path!(bundle_patch, "/billing-bundles/{id}", true, |s, r, ca, cfg, id| {
    let id = to_u64(&id)?;
    let fields = body::object(&r.body)?;
    let out = live(&s, &cfg);
    Ok(json(&billing(&s, &out).bundle_patch(&ca, id, &fields).await?.to_json()))
});

bl_route_path!(bundle_delete, "/billing-bundles/{id}", true, |s, r, ca, cfg, id| {
    let id = to_u64(&id)?;
    pre_authorize(&ca, &[APPLICATION_CREATE])?;
    let out = live(&s, &cfg);
    billing(&s, &out).bundle_delete(&ca, id).await?;
    Ok(no_content())
});

// ---- AppBillingConfigController ----

bl_route!(configs_list, "/billing-configs", true, |s, r, ca, cfg| {
    let _ = (Pageable::from_params(&r.params), param_condition(&r.params, &[]));
    Err::<Response, _>(Billing::config_list_refused())
});

bl_route!(configs_query, "/billing-configs/query", true, |s, r, ca, cfg| {
    query_body(&r.body)?;
    Err::<Response, _>(Billing::config_list_refused())
});

bl_route!(config_create, "/billing-configs", true, |s, r, ca, cfg| {
    let rec = body::dto(&CONFIG, &r.body)?;
    pre_authorize(&ca, &[APPLICATION_CREATE])?;
    let out = live(&s, &cfg);
    Ok(ok_or_nothing(billing(&s, &out).config_create(&ca, rec).await?.map(|c| c.to_json())))
});

bl_route_path!(configs_of_app, "/billing-configs/app/{appId}", true, |s, r, ca, cfg, app| {
    let app = to_u64(&app)?;
    let out = live(&s, &cfg);
    Ok(list(&billing(&s, &out).configs_of_app(&ca, app).await?))
});

bl_route_path!(config_read, "/billing-configs/{id}", true, |s, r, ca, cfg, id| {
    let id = to_u64(&id)?;
    let out = live(&s, &cfg);
    Ok(match billing(&s, &out).config_read(&ca, id).await? {
        Some(c) => json(&c.to_json()),
        None => empty(StatusCode::NOT_FOUND),
    })
});

bl_route_path!(config_put, "/billing-configs/{id}", true, |s, r, ca, cfg, id| {
    let entity = put_entity(&r, &CONFIG, &id)?;
    pre_authorize(&ca, &[APPLICATION_CREATE])?;
    let out = live(&s, &cfg);
    Ok(ok_or_nothing(billing(&s, &out).config_update(&ca, &entity).await?.map(|c| c.to_json())))
});

bl_route_path!(config_patch, "/billing-configs/{id}", true, |s, r, ca, cfg, id| {
    let id = to_u64(&id)?;
    let fields = body::object(&r.body)?;
    let out = live(&s, &cfg);
    Ok(ok_or_nothing(billing(&s, &out).config_patch(&ca, id, &fields).await?.map(|c| c.to_json())))
});

bl_route_path!(config_delete, "/billing-configs/{id}", true, |s, r, ca, cfg, id| {
    let id = to_u64(&id)?;
    pre_authorize(&ca, &[APPLICATION_CREATE])?;
    let out = live(&s, &cfg);
    billing(&s, &out).config_delete(&ca, id).await?;
    Ok(no_content())
});

// ---- BillingProfileController ----

bl_route!(profile_get, "/billing-profile", true, |s, r, ca, cfg| {
    pre_authorize(&ca, &[ROLE_OWNER])?;
    let out = live(&s, &cfg);
    let app = r.info.header("appCode");
    let p = billing(&s, &out).my_profile(&ca, app.as_deref()).await?;
    // A first-time buyer gets an empty profile to fill in, never a 204.
    Ok(json(&p.map(|p| p.to_json()).unwrap_or_else(|| Value::Object(Default::default()))))
});

bl_route!(profile_put, "/billing-profile", true, |s, r, ca, cfg| {
    let input = body::dto(&PROFILE, &r.body)?;
    pre_authorize(&ca, &[ROLE_OWNER])?;
    let out = live(&s, &cfg);
    let app = r.info.header("appCode");
    Ok(ok_or_nothing(billing(&s, &out).save_my_profile(&ca, app.as_deref(), &input).await?.map(|p| p.to_json())))
});

// ---- BundlePurchaseController ----

const BUYERS: [&str; 2] = [ROLE_OWNER, PAYMENT_CREATE];

bl_route!(purchase, "/billing/purchase", true, |s, r, ca, cfg| {
    let req = purchase_request(&r.body)?;
    pre_authorize(&ca, &BUYERS)?;
    let out = live(&s, &cfg);
    Ok(ok_or_nothing(billing(&s, &out).purchase(&ca, &req).await?))
});

bl_route!(purchase_order, "/billing/purchase/order", true, |s, r, ca, cfg| {
    let req = purchase_request(&r.body)?;
    pre_authorize(&ca, &BUYERS)?;
    let out = live(&s, &cfg);
    Ok(ok_or_nothing(billing(&s, &out).purchase_order(&ca, &req).await?))
});

bl_route!(quote, "/billing/quote", true, |s, r, ca, cfg| {
    let req = purchase_request(&r.body)?;
    pre_authorize(&ca, &BUYERS)?;
    let out = live(&s, &cfg);
    Ok(json(&billing(&s, &out).quote(&req).await?))
});

bl_route!(repay, "/billing/repay", true, |s, r, ca, cfg| {
    let m = record(&r.body)?;
    let invoice = body::field(&m, "invoiceId", ulong)?;
    pre_authorize(&ca, &BUYERS)?;
    let out = live(&s, &cfg);
    Ok(ok_or_nothing(billing(&s, &out).repay(&ca, invoice).await?))
});

bl_route!(webhook, "/billing/razorpay/webhook", false, |s, r, ca, cfg| {
    if r.body.is_empty() {
        return Err(bad_request("400 BAD_REQUEST \"No request body\""));
    }
    let raw = String::from_utf8_lossy(&r.body).into_owned();
    let signature = r.info.header("X-Razorpay-Signature");
    let out = live(&s, &cfg);
    billing(&s, &out).webhook(&ca, &raw, signature.as_deref()).await?;
    Ok(text_response("OK"))
});

// ---- InvoiceController ----

const INVOICE_READERS: [&str; 2] = [ROLE_OWNER, INVOICE_READ];
const PAGE_PARAMS: [&str; 5] = ["page", "size", "sort", "appCode", "clientCode"];

bl_route!(invoices_page, "/invoices", true, |s, r, ca, cfg| {
    let page = Pageable::from_params(&r.params);
    let cond = param_condition(&r.params, &PAGE_PARAMS);
    pre_authorize(&ca, &INVOICE_READERS)?;
    let out = live(&s, &cfg);
    let (app, client) = (r.info.header("appCode"), r.info.header("clientCode"));
    Ok(ok_or_nothing(billing(&s, &out).invoice_page(&ca, &page, cond, app.as_deref(), client.as_deref()).await?))
});

bl_route!(invoices_query, "/invoices/query", true, |s, r, ca, cfg| {
    let (page, cond) = query_body(&r.body)?;
    pre_authorize(&ca, &INVOICE_READERS)?;
    let out = live(&s, &cfg);
    let (app, client) = (r.info.header("appCode"), r.info.header("clientCode"));
    Ok(ok_or_nothing(billing(&s, &out).invoice_page(&ca, &page, cond, app.as_deref(), client.as_deref()).await?))
});

bl_route!(invoices_mine, "/invoices/my", true, |s, r, ca, cfg| {
    let page = Pageable::from_params(&r.params);
    let cond = param_condition(&r.params, &PAGE_PARAMS);
    let out = live(&s, &cfg);
    let app = r.info.header("appCode");
    Ok(ok_or_nothing(billing(&s, &out).my_invoices(&ca, &page, cond, app.as_deref()).await?))
});

// Java answers these two with "Type mismatch." for every id: the controller has no `ULong`
// binder. Served here, as reads (DIFFERENCES.md).
bl_route_path!(invoice_read, "/invoices/{id}", true, |s, r, ca, cfg, id| {
    let id = to_u64(&id)?;
    pre_authorize(&ca, &INVOICE_READERS)?;
    let out = live(&s, &cfg);
    Ok(json(&billing(&s, &out).invoice_read(&ca, id).await?))
});

bl_route_path!(invoice_documents, "/invoices/{id}/documents", true, |s, r, ca, cfg, id| {
    let id = to_u64(&id)?;
    pre_authorize(&ca, &INVOICE_READERS)?;
    let out = live(&s, &cfg);
    Ok(ok_or_nothing(billing(&s, &out).invoice_documents(&ca, id).await?))
});

// ---- WalletController ----

/// A wallet, or `ResponseEntity.noContent()`.
fn wallet_or_204(w: Option<Rec>) -> Response {
    w.map(|w| json(&w.to_json())).unwrap_or_else(|| empty(StatusCode::NO_CONTENT))
}

bl_route!(wallet, "/wallets", true, |s, r, ca, cfg| {
    pre_authorize(&ca, &BUYERS)?;
    let out = live(&s, &cfg);
    let (app, client) = (r.info.header("appCode"), r.info.header("clientCode"));
    Ok(wallet_or_204(billing(&s, &out).wallet_by_codes(&ca, app.as_deref(), client.as_deref()).await?))
});

bl_route!(wallet_status, "/wallets/status", true, |s, r, ca, cfg| {
    let out = live(&s, &cfg);
    let app = r.info.header("appCode");
    Ok(json(&billing(&s, &out).display_status(&ca, app.as_deref()).await?))
});

bl_route!(wallet_transactions, "/wallets/transactions", true, |s, r, ca, cfg| {
    let page = Pageable::from_params(&r.params);
    let out = live(&s, &cfg);
    let app = r.info.header("appCode");
    Ok(json(&billing(&s, &out).my_transactions(&ca, app.as_deref(), &page).await?))
});

bl_route!(wallet_plan, "/wallets/plan", true, |s, r, ca, cfg| {
    let out = live(&s, &cfg);
    let app = r.info.header("appCode");
    Ok(json(&billing(&s, &out).plan_usage(&ca, app.as_deref()).await?))
});

// `[billing] serve_wallet_adjust` off (the default): Java's answer, "Type mismatch." for every id
// (the controller has no `ULong` binder), after the caller's 401.
bl_route_path!(wallet_adjust, "/wallets/{walletId}/adjust", true, |s, r, ca, cfg, wallet| {
    if !cfg.serve_wallet_adjust {
        return Err(crate::web::type_mismatch());
    }
    let wallet = to_u64(&wallet)?;
    let tokens = req_str(&r.params, "tokens")?;
    let tokens = crate::decimal::Dec::parse(tokens.trim()).ok_or_else(crate::web::type_mismatch)?;
    let reason = req_str(&r.params, "reason")?.to_string();
    pre_authorize(&ca, &[ROLE_OWNER])?;
    let out = live(&s, &cfg);
    Ok(json(&billing(&s, &out).adjust(&ca, wallet, tokens, &reason).await?.to_json()))
});

bl_route!(wallet_credit, "/wallets/credit", true, |s, r, ca, cfg| {
    let m = record(&r.body)?;
    let app = body::field(&m, "appCode", text)?;
    let url_client = body::field(&m, "urlClientCode", text)?;
    let client = body::field(&m, "clientCode", text)?;
    let tokens = body::field(&m, "tokens", decimal)?;
    let reason = body::field(&m, "reason", text)?;
    pre_authorize(&ca, &BUYERS)?;
    let out = live(&s, &cfg);
    let b = billing(&s, &out);
    let r = b.credit_tokens(&ca, app.as_deref(), url_client.as_deref(), client.as_deref(), tokens, reason.as_deref()).await?;
    Ok(ok_or_nothing(r.map(|c| c.to_json())))
});

bl_route!(wallet_lookup, "/wallets/lookup", true, |s, r, ca, cfg| {
    let app = req_str(&r.params, "appCode")?.to_string();
    let url_client = req_str(&r.params, "urlClientCode")?.to_string();
    let client = req_str(&r.params, "clientCode")?.to_string();
    pre_authorize(&ca, &BUYERS)?;
    let out = live(&s, &cfg);
    Ok(wallet_or_204(billing(&s, &out).lookup_wallet(&ca, Some(&app), Some(&url_client), Some(&client)).await?))
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bodies_and_conditions() {
        assert!(record(b"").is_err() && record(b"  ").is_err() && record(b"null").is_err() && record(b"[1]").is_err());
        assert_eq!(record(br#"{"a": 1}"#).unwrap().len(), 1);
        let p = purchase_request(br#"{"bundleId": "3", "tokens": 12.50, "clientId": null}"#).unwrap();
        assert_eq!((p.bundle_id, p.tokens.map(|t| t.to_string()), p.client_id), (Some(3), Some("12.5".into()), None));
        assert!(purchase_request(br#"{"bundleId": -1}"#).is_err());
        let params = Params::from_query(Some("page=1&status=PAID&sort=id,desc&appCode=x"));
        let c = param_condition(&params, &PAGE_PARAMS).unwrap();
        assert_eq!(c.filters_on("status").len(), 1);
        assert!(c.filters_on("page").is_empty());
        assert!(param_condition(&Params::from_query(Some("size=2")), &PAGE_PARAMS).is_none());
        assert_eq!(no_content().status(), StatusCode::NO_CONTENT);
        assert_eq!(ok_or_nothing(None).status(), StatusCode::OK);
        assert_eq!(wallet_or_204(None).status(), StatusCode::NO_CONTENT);
    }
}
