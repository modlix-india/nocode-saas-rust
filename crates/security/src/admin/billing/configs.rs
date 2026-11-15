//! `AppBillingConfigService` and `AppBillingBundleService`: the per-(client, app) billing terms
//! and the token bundles under them.
//!
//! Mutations need the caller and the config's client to have write access to the app, and the
//! caller to manage the config's client; reads of a config are limited to the caller's own and
//! managed clients; the bundle reads are open (they are what a buyer picks from). The generic
//! lists are refused. `PATCH` reaches `update(entity)` from inside the service, so (as in Java)
//! it skips the `@PreAuthorize` the controller's `PUT` goes through.

use serde_json::{Map, Value};

use super::body;
use super::service::{forbidden, Billing};
use crate::data::billing_admin::{Find, Rec, Val, BUNDLE, CONFIG};
use crate::errors::{AuthError, AuthResult};
use crate::model::ContextAuth;

/// What a config update copies from the request. What it charges for is its meters and plans
/// (`meters.rs`), not columns of the config.
const CONFIG_EDITABLE: [&str; 15] = [
    "gstPercentage",
    "paymentGateway",
    "paymentGatewayConfig",
    "sellerLegalName",
    "sellerGstin",
    "sellerAddress",
    "lowBalanceThreshold",
    "suspendAppCode",
    "suspendClientCode",
    "suspendMode",
    "purchasedCreditValidityMonths",
    "invoiceDay",
    "invoiceDueDays",
    "currency",
    "status",
];

/// What `AppBillingBundleService.updatableEntity` copies from the request.
const BUNDLE_EDITABLE: [&str; 10] =
    ["label", "bundleType", "tokens", "price", "pricePerToken", "minTokens", "maxTokens", "currency", "status", "displayOrder"];

/// The refusal of the generic bundle list.
pub const BUNDLE_LIST_REFUSED: &str = "Listing all billing bundles is not permitted";

/// PLAT-344: the gateway secrets in `paymentGatewayConfig`. They are written, never read back.
pub const GATEWAY_SECRETS: [&str; 2] = ["keySecret", "webhookSecret"];

/// What a read returns in place of a stored secret.
pub const SECRET_MASK: &str = "********";

/// A config as the API returns it: each set gateway secret replaced by [`SECRET_MASK`].
pub fn masked_json(config: &Rec) -> Value {
    let mut v = config.to_json();
    if let Some(Value::Object(gw)) = v.get_mut("paymentGatewayConfig") {
        for k in GATEWAY_SECRETS {
            if let Some(x) = gw.get_mut(k) {
                if x.as_str().is_some_and(|s| !s.is_empty()) {
                    *x = Value::String(SECRET_MASK.to_string());
                }
            }
        }
    }
    v
}

/// On a write, a secret sent back as the mask, empty, null or left out keeps the stored value.
fn keep_stored_secrets(target: &mut Rec, stored: &Map<String, Value>) {
    let Val::Json(Value::Object(gw)) = target.get("paymentGatewayConfig").clone() else { return };
    let mut gw = gw;
    for k in GATEWAY_SECRETS {
        let sent = gw.get(k).and_then(Value::as_str).filter(|s| !s.is_empty() && *s != SECRET_MASK);
        if sent.is_none() {
            match stored.get(k) {
                Some(old) => {
                    gw.insert(k.to_string(), old.clone());
                }
                None => {
                    gw.remove(k);
                }
            }
        }
    }
    target.set("paymentGatewayConfig", Val::Json(Value::Object(gw)));
}

pub(super) fn copy(target: &mut Rec, from: &Rec, props: &[&str]) {
    for p in props {
        target.set(p, from.get(p).clone());
    }
}

impl Billing<'_> {
    /// `canSee`: SYSTEM, the config's own client, or a client the caller manages.
    async fn can_see(&self, ca: &ContextAuth, config: &Rec) -> AuthResult<bool> {
        let client = config.u64("clientId");
        if ca.is_system_client() || client == Some(ca.user.client_id()) {
            return Ok(true);
        }
        match client {
            Some(c) => self.manages(ca, c).await,
            None => Ok(false),
        }
    }

    /// `AppBillingConfigService.read`: the DAO's 404 for no row, `None` for one the caller may
    /// not see.
    pub async fn config_read(&self, ca: &ContextAuth, id: u64) -> AuthResult<Option<Rec>> {
        let config = self.read(&CONFIG, Some(id)).await?;
        Ok(self.can_see(ca, &config).await?.then_some(config))
    }

    /// `findByApp`: the app's non-DELETED configs the caller can see.
    pub async fn configs_of_app(&self, ca: &ContextAuth, app: u64) -> AuthResult<Vec<Rec>> {
        let all = self.store.find(&CONFIG, &Find { not_deleted: true, ..Find::eq(vec![("APP_ID", Val::Id(app))]) }).await?;
        let mut out = Vec::new();
        for c in all {
            if self.can_see(ca, &c).await? {
                out.push(c);
            }
        }
        Ok(out)
    }

    /// `assertCanManage`.
    async fn assert_can_manage(&self, ca: &ContextAuth, app: Option<u64>, client: Option<u64>) -> AuthResult<()> {
        if !self.write_access(app, Some(ca.user.client_id())).await? {
            return Err(forbidden("write access to the application"));
        }
        if !self.write_access(app, client).await? {
            return Err(forbidden("the config's client must have access to the application"));
        }
        let manages = match client {
            Some(c) => self.manages(ca, c).await?,
            None => false,
        };
        if !manages {
            return Err(forbidden("manage the config's client"));
        }
        Ok(())
    }

    /// `assertManageableConfig`: the config (its 404 when missing), managed by the caller.
    pub(super) async fn assert_manageable_config(&self, ca: &ContextAuth, id: Option<u64>) -> AuthResult<Rec> {
        let config = self.read(&CONFIG, id).await?;
        self.assert_can_manage(ca, config.u64("appId"), config.u64("clientId")).await?;
        Ok(config)
    }

    /// `AbstractJOOQDataService.create` (`createdBy` stays null: no logged-in user id is
    /// resolved) and the DAO's insert-then-select; `None` when the row cannot be read back.
    pub(super) async fn create_row(&self, mut rec: Rec) -> AuthResult<Option<Rec>> {
        rec.set("createdBy", Val::Null);
        let id = self.store.insert(&rec).await?;
        self.store.by_id(rec.schema, id).await
    }

    /// `AbstractUpdatableDAO.update(entity)`: the statement, then `readById`.
    pub(super) async fn update_row(&self, rec: &Rec) -> AuthResult<Rec> {
        self.store.update(rec).await?;
        self.read(rec.schema, rec.id()).await
    }

    /// `AppBillingConfigService.create`.
    pub async fn config_create(&self, ca: &ContextAuth, rec: Rec) -> AuthResult<Option<Rec>> {
        self.assert_can_manage(ca, rec.u64("appId"), rec.u64("clientId")).await?;
        super::meters::check_config(&rec)?;
        let Some(saved) = self.create_row(rec).await? else { return Ok(None) };
        self.evict_config(&saved).await?;
        Ok(Some(saved))
    }

    /// `AppBillingConfigService.update(entity)`, for `PUT` and (without the authority) `PATCH`.
    pub async fn config_update(&self, ca: &ContextAuth, entity: &Rec) -> AuthResult<Option<Rec>> {
        let existing = self.read(&CONFIG, entity.id()).await?;
        self.assert_can_manage(ca, existing.u64("appId"), existing.u64("clientId")).await?;
        // `updatableEntity` reads through `this.read`, the caller-visibility one.
        let Some(id) = entity.id() else { return Ok(None) };
        let Some(mut target) = self.config_read(ca, id).await? else { return Ok(None) };
        let stored = target.map("paymentGatewayConfig");
        copy(&mut target, entity, &CONFIG_EDITABLE);
        super::meters::check_config(&target)?;
        keep_stored_secrets(&mut target, &stored);
        let saved = self.update_row(&target).await?;
        self.evict_config(&saved).await?;
        Ok(Some(saved))
    }

    /// `AbstractJOOQUpdatableDataService.update(id, fields)` on a config.
    pub async fn config_patch(&self, ca: &ContextAuth, id: u64, fields: &Map<String, Value>) -> AuthResult<Option<Rec>> {
        let Some(mut retrieved) = self.config_read(ca, id).await? else { return Ok(None) };
        body::patch(&mut retrieved, fields)?;
        self.config_update(ca, &retrieved).await
    }

    /// `AppBillingConfigService.delete`.
    pub async fn config_delete(&self, ca: &ContextAuth, id: u64) -> AuthResult<u64> {
        let existing = self.read(&CONFIG, Some(id)).await?;
        self.assert_can_manage(ca, existing.u64("appId"), existing.u64("clientId")).await?;
        let n = self.store.delete(&CONFIG, id).await?;
        self.evict_config(&existing).await?;
        Ok(n)
    }

    /// The generic config list: always refused.
    pub fn config_list_refused() -> AuthError {
        forbidden("list billing configs")
    }

    /// `AppBillingBundleDAO.findByConfigId`: non-DELETED, by display order.
    pub async fn bundles_of_config(&self, config: u64) -> AuthResult<Vec<Rec>> {
        let f = Find { not_deleted: true, order_by: Some("DISPLAY_ORDER"), ..Find::eq(vec![("BILLING_CONFIG_ID", Val::Id(config))]) };
        self.store.find(&BUNDLE, &f).await
    }

    /// `findServingByCodes`: the ACTIVE bundles of the config governing the URL's app and
    /// client (its own, else the nearest managing client's); empty when nothing resolves.
    pub async fn serving_bundles(&self, app_code: Option<&str>, client_code: Option<&str>) -> AuthResult<Vec<Rec>> {
        let Some(app) = self.app_by_code(app_code).await? else { return Ok(vec![]) };
        let Some(client) = self.client_by_code(client_code).await? else { return Ok(vec![]) };
        let Some(config) = self.config_for_client(app.id, client.id()).await? else { return Ok(vec![]) };
        let Some(id) = config.id() else { return Ok(vec![]) };
        Ok(self.bundles_of_config(id).await?.into_iter().filter(|b| b.str("status") == Some("ACTIVE")).collect())
    }

    /// `AppBillingBundleService.create`.
    pub async fn bundle_create(&self, ca: &ContextAuth, rec: Rec) -> AuthResult<Option<Rec>> {
        self.assert_manageable_config(ca, rec.u64("billingConfigId")).await?;
        self.create_row(rec).await
    }

    /// `AppBillingBundleService.update(entity)`.
    pub async fn bundle_update(&self, ca: &ContextAuth, entity: &Rec) -> AuthResult<Rec> {
        let existing = self.read(&BUNDLE, entity.id()).await?;
        self.assert_manageable_config(ca, existing.u64("billingConfigId")).await?;
        let mut target = self.read(&BUNDLE, entity.id()).await?;
        copy(&mut target, entity, &BUNDLE_EDITABLE);
        self.update_row(&target).await
    }

    /// `update(id, fields)` on a bundle.
    pub async fn bundle_patch(&self, ca: &ContextAuth, id: u64, fields: &Map<String, Value>) -> AuthResult<Rec> {
        let mut retrieved = self.read(&BUNDLE, Some(id)).await?;
        body::patch(&mut retrieved, fields)?;
        self.bundle_update(ca, &retrieved).await
    }

    /// `AppBillingBundleService.delete`.
    pub async fn bundle_delete(&self, ca: &ContextAuth, id: u64) -> AuthResult<u64> {
        let existing = self.read(&BUNDLE, Some(id)).await?;
        self.assert_manageable_config(ca, existing.u64("billingConfigId")).await?;
        self.store.delete(&BUNDLE, id).await
    }
}

#[cfg(test)]
mod secret_tests {
    use serde_json::json;

    use super::*;

    fn config(gw: Value) -> Rec {
        Rec::new(&CONFIG).with("paymentGatewayConfig", Val::Json(gw))
    }

    #[test]
    fn reads_mask_the_gateway_secrets() {
        let c = config(json!({"keyId": "rzp_k", "keySecret": "s1", "webhookSecret": "s2"}));
        let gw = masked_json(&c)["paymentGatewayConfig"].clone();
        assert_eq!(gw, json!({"keyId": "rzp_k", "keySecret": SECRET_MASK, "webhookSecret": SECRET_MASK}));
    }

    #[test]
    fn writes_keep_stored_secrets_unless_a_new_one_is_sent() {
        let stored = json!({"keySecret": "old1", "webhookSecret": "old2"}).as_object().unwrap().clone();
        let mut t = config(json!({"keyId": "k", "keySecret": SECRET_MASK}));
        keep_stored_secrets(&mut t, &stored);
        assert_eq!(t.map("paymentGatewayConfig"), json!({"keyId": "k", "keySecret": "old1", "webhookSecret": "old2"}).as_object().unwrap().clone());
        let mut t = config(json!({"keySecret": "new1", "webhookSecret": ""}));
        keep_stored_secrets(&mut t, &stored);
        assert_eq!(t.map("paymentGatewayConfig"), json!({"keySecret": "new1", "webhookSecret": "old2"}).as_object().unwrap().clone());
    }
}
