//! `CoreBillingMeteringService`: core's slice of the 15-minute token metering loop. For every
//! (config client, app, billed client) security says carries a `core.storage.rows` rate, the
//! billed client's estimated row count in the app's data database goes to security, which
//! prices it and ignores a window it has already charged.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{NaiveDate, Timelike, Utc};
use serde_json::Value;

use crate::editor::storage::DataStores;

pub const ACTION_STORAGE_ROWS: &str = "core.storage.rows";

/// The two security calls (`IFeignSecurityBillingService`).
#[async_trait]
pub trait BillingSecurity: Send + Sync {
    async fn instructions(&self, action: &str) -> anyhow::Result<Value>;
    async fn charge(&self, body: String) -> anyhow::Result<Value>;
}

#[async_trait]
impl BillingSecurity for platform::security::SecurityClient {
    async fn instructions(&self, action: &str) -> anyhow::Result<Value> {
        self.billing_instructions(action).await
    }
    async fn charge(&self, body: String) -> anyhow::Result<Value> {
        self.billing_charge(body).await
    }
}

fn id_of(v: &Value) -> String {
    match v {
        Value::Number(n) => n.to_string(),
        Value::String(s) if !s.is_empty() => s.clone(),
        _ => "null".into(),
    }
}

/// The charge requests of one instruction: the raw count as the quantity, the date as epoch
/// seconds of its start in UTC (`CommonsSerializationModule`).
pub fn charges_json(instr: &Value, count: i64, date: NaiveDate, windows: &[u32]) -> String {
    let date_secs = date.and_hms_opt(0, 0, 0).map(|d| d.and_utc().timestamp()).unwrap_or(0);
    let items: Vec<String> = windows
        .iter()
        .map(|w| {
            format!(
                "{{\"configClientId\":{},\"billedClientId\":{},\"appId\":{},\"actionKey\":\"{ACTION_STORAGE_ROWS}\",\"quantity\":{count},\"date\":{date_secs},\"windowIndex\":{w}}}",
                id_of(&instr["configClientId"]),
                id_of(&instr["billedClientId"]),
                id_of(&instr["appId"]),
            )
        })
        .collect();
    format!("[{}]", items.join(","))
}

pub struct Billing {
    pub security: Arc<dyn BillingSecurity>,
    pub data: Arc<dyn DataStores>,
}

impl Billing {
    async fn run(&self, date: NaiveDate, windows: &[u32]) -> anyhow::Result<bool> {
        let Value::Array(instructions) = self.security.instructions(ACTION_STORAGE_ROWS).await? else { return Ok(true) };
        for instr in instructions {
            let app = instr["appCode"].as_str().unwrap_or("").to_string();
            let client = instr["billedClientCode"].as_str().unwrap_or("").to_string();
            let count = self.data.estimated_row_count(&app, &client).await;
            if count <= 0 {
                continue;
            }
            if let Err(e) = self.security.charge(charges_json(&instr, count, date, windows)).await {
                tracing::error!(app, client, error = %e, "core metering failed");
            }
        }
        Ok(true)
    }

    /// The JVM's local now (the configured Java zone offset).
    fn local_now() -> chrono::NaiveDateTime {
        Utc::now().naive_utc() + chrono::Duration::seconds(overridable::pojo::java_zone_offset_seconds() as i64)
    }

    /// `meterCurrentWindow`: this window of today.
    pub async fn meter(&self) -> anyhow::Result<bool> {
        let now = Self::local_now();
        self.run(now.date(), &[now.num_seconds_from_midnight() / 900]).await
    }

    /// `reconcile(date)`: every window of a day, yesterday by default.
    pub async fn reconcile(&self, date: Option<NaiveDate>) -> anyhow::Result<bool> {
        let day = date.unwrap_or_else(|| Self::local_now().date() - chrono::Duration::days(1));
        let windows: Vec<u32> = (0..96).collect();
        self.run(day, &windows).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    use serde_json::json;

    struct Sec {
        instructions: anyhow::Result<Value>,
        charges: Mutex<Vec<String>>,
        fail_charge: bool,
    }

    #[async_trait]
    impl BillingSecurity for Sec {
        async fn instructions(&self, _action: &str) -> anyhow::Result<Value> {
            match &self.instructions {
                Ok(v) => Ok(v.clone()),
                Err(e) => Err(anyhow::anyhow!("{e}")),
            }
        }
        async fn charge(&self, body: String) -> anyhow::Result<Value> {
            self.charges.lock().push(body);
            if self.fail_charge {
                anyhow::bail!("refused");
            }
            Ok(Value::Bool(true))
        }
    }

    struct Rows;

    #[async_trait]
    impl DataStores for Rows {
        async fn reconcile(&self, _: &str, _: &overridable::JMap, _: &str) {}
        async fn drop_draft_storage(&self, _: &str, _: &str, _: &overridable::JMap) -> Result<bool, String> {
            Ok(true)
        }
        async fn drop_draft_data(&self, _: &str, _: &str) -> Result<bool, String> {
            Ok(true)
        }
        async fn estimated_row_count(&self, _app: &str, client: &str) -> i64 {
            if client == "EMPTY" {
                0
            } else {
                42
            }
        }
    }

    // ── CoreBillingMeteringServiceTest ──

    #[tokio::test]
    async fn every_instruction_with_rows_is_charged_per_window() {
        let sec = Arc::new(Sec {
            instructions: Ok(json!([
                {"configClientId": 1, "appId": 7, "billedClientId": 9, "appCode": "a", "billedClientCode": "CLIA"},
                {"configClientId": 1, "appId": 7, "billedClientId": 10, "appCode": "a", "billedClientCode": "EMPTY"}
            ])),
            charges: Mutex::new(Vec::new()),
            fail_charge: false,
        });
        let b = Billing { security: sec.clone(), data: Arc::new(Rows) };
        assert!(b.reconcile(Some(NaiveDate::from_ymd_opt(2026, 10, 14).unwrap())).await.unwrap());
        let charges = sec.charges.lock().clone();
        assert_eq!(charges.len(), 1, "a client without rows is not charged");
        let v: Value = serde_json::from_str(&charges[0]).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 96);
        assert_eq!(v[0]["quantity"], 42);
        assert_eq!(v[0]["actionKey"], "core.storage.rows");
        assert_eq!(v[95]["windowIndex"], 95);
        assert!(b.meter().await.unwrap());
        assert!(b.reconcile(None).await.unwrap());
    }

    #[tokio::test]
    async fn a_failed_charge_does_not_stop_the_others_but_no_instructions_fails() {
        let sec = Arc::new(Sec { instructions: Ok(json!([{"appCode": "a", "billedClientCode": "X"}])), charges: Mutex::new(Vec::new()), fail_charge: true });
        assert!(Billing { security: sec, data: Arc::new(Rows) }.meter().await.unwrap());
        let down = Arc::new(Sec { instructions: Err(anyhow::anyhow!("down")), charges: Mutex::new(Vec::new()), fail_charge: false });
        assert!(Billing { security: down, data: Arc::new(Rows) }.meter().await.is_err());
        let none = Arc::new(Sec { instructions: Ok(Value::Null), charges: Mutex::new(Vec::new()), fail_charge: false });
        assert!(Billing { security: none, data: Arc::new(Rows) }.meter().await.unwrap());
        let body = charges_json(&json!({"configClientId": "5", "appId": null}), 3, NaiveDate::from_ymd_opt(1970, 1, 2).unwrap(), &[1]);
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!((v[0]["configClientId"].clone(), v[0]["appId"].clone(), v[0]["date"].clone()), (json!(5), Value::Null, json!(86400)));
    }
}
