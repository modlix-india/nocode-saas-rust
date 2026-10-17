//! `FilesBillingMeteringService`: files' slice of the 15-minute token metering loop. For every
//! (config client, app, billed client) security says carries a `files.gb` rate, the billed
//! client's stored bytes (static and secured) go to security as GB; security does the pricing
//! and ignores a window it has already charged.

use anyhow::Result;
use chrono::{Local, NaiveDate, Timelike};
use serde_json::Value;

use crate::state::AppState;

const ACTION_FILES_GB: &str = "files.gb";
const BYTES_PER_GB: u128 = 1024 * 1024 * 1024;

/// `BigDecimal.valueOf(bytes).divide(BYTES_PER_GB, 6, HALF_UP)`, written with its six decimals
/// as Jackson writes that `BigDecimal`.
pub fn gb_quantity(bytes: i64) -> String {
    let millionths = ((bytes.max(0) as u128) * 1_000_000 * 2 + BYTES_PER_GB) / (2 * BYTES_PER_GB);
    format!("{}.{:06}", millionths / 1_000_000, millionths % 1_000_000)
}

/// The window of the day a moment falls in (`toSecondOfDay() / 900`).
pub fn window_of(seconds_of_day: u32) -> u32 {
    seconds_of_day / 900
}

fn id_of(v: &Value) -> Option<String> {
    match v {
        Value::Number(n) => Some(n.to_string()),
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

/// The charge requests of one instruction, as security's `ChargeRequest` reads them: the date
/// as epoch seconds of its start in UTC (`CommonsSerializationModule`).
pub fn charges_json(instr: &Value, quantity: &str, date: NaiveDate, windows: &[u32]) -> String {
    let field = |k: &str| id_of(&instr[k]).unwrap_or_else(|| "null".into());
    let date_secs = date.and_hms_opt(0, 0, 0).map(|d| d.and_utc().timestamp()).unwrap_or(0);
    let items: Vec<String> = windows
        .iter()
        .map(|w| {
            format!(
                "{{\"configClientId\":{},\"billedClientId\":{},\"appId\":{},\"actionKey\":\"{ACTION_FILES_GB}\",\"quantity\":{quantity},\"date\":{date_secs},\"windowIndex\":{w}}}",
                field("configClientId"),
                field("billedClientId"),
                field("appId"),
            )
        })
        .collect();
    format!("[{}]", items.join(","))
}

async fn run(st: &AppState, date: NaiveDate, windows: &[u32]) -> Result<bool> {
    let instructions = st.security().billing_instructions(ACTION_FILES_GB).await?;
    let Value::Array(instructions) = instructions else { return Ok(true) };
    for instr in instructions {
        let client = instr["billedClientCode"].as_str().unwrap_or("").to_string();
        let res: Result<()> = async {
            let bytes = st.dao().sum_bytes_by_client(&client).await?;
            if bytes <= 0 {
                return Ok(());
            }
            let quantity = gb_quantity(bytes);
            if quantity == "0.000000" {
                return Ok(());
            }
            st.security().billing_charge(charges_json(&instr, &quantity, date, windows)).await?;
            Ok(())
        }
        .await;
        if let Err(e) = res {
            tracing::error!(client, error = %e, "files metering failed");
        }
    }
    Ok(true)
}

/// `POST /internal/billing/meter`: the current window, in this process's time zone as Java uses
/// the JVM's.
pub async fn meter(st: &AppState) -> Result<bool> {
    let now = Local::now();
    run(st, now.date_naive(), &[window_of(now.num_seconds_from_midnight())]).await
}

/// `POST /internal/billing/reconcile`: every window of a day, yesterday by default.
pub async fn reconcile(st: &AppState, date: Option<NaiveDate>) -> Result<bool> {
    let day = date.unwrap_or_else(|| Local::now().date_naive() - chrono::Duration::days(1));
    let windows: Vec<u32> = (0..96).collect();
    run(st, day, &windows).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn quantities_round_half_up_to_six_places() {
        assert_eq!(gb_quantity(1024 * 1024 * 1024), "1.000000");
        assert_eq!(gb_quantity(67_829_889), "0.063172");
        assert_eq!(gb_quantity(536), "0.000000");
        assert_eq!(gb_quantity(537), "0.000001");
        assert_eq!(gb_quantity(3 * 1024 * 1024 * 1024 / 2), "1.500000");
    }

    #[test]
    fn windows_and_charges() {
        assert_eq!(window_of(0), 0);
        assert_eq!(window_of(86_399), 95);
        let instr = json!({"configClientId": 1, "billedClientId": 6, "appId": 246, "billedClientCode": "CLIA"});
        let body = charges_json(&instr, "0.063172", NaiveDate::from_ymd_opt(2026, 10, 15).unwrap(), &[3, 4]);
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 2);
        assert_eq!(v[0]["date"], 1_792_022_400);
        assert_eq!(v[1]["windowIndex"], 4);
        assert!(body.contains("\"quantity\":0.063172"));
    }


    #[test]
    fn ids_as_security_sends_them() {
        let instr = json!({"configClientId": "5", "billedClientId": "", "appId": null});
        let v: Value = serde_json::from_str(&charges_json(&instr, "1.000000", NaiveDate::from_ymd_opt(1970, 1, 1).unwrap(), &[0])).unwrap();
        assert_eq!(v[0]["configClientId"], 5);
        assert!(v[0]["billedClientId"].is_null() && v[0]["appId"].is_null());
        assert_eq!(v[0]["date"], 0);
        assert_eq!(gb_quantity(-5), "0.000000");
    }
}
