//! `TimeZoneUtil` (commons): which zone a person is on. The signed-in context carries the user's
//! own zone, or the client's when the user has none, in the canonical form `ZoneId.getId()`
//! gives.

use std::str::FromStr;
use std::sync::OnceLock;

use regex::Regex;

/// `TimeZoneUtil.effective(override, fallback)`: a usable override, else a usable fallback.
pub fn effective(override_zone: Option<&str>, fallback: Option<&str>) -> Option<String> {
    sanitize(override_zone).or_else(|| sanitize(fallback))
}

/// `TimeZoneUtil.sanitize`: the canonical id, or `None` for blank or unreadable names.
pub fn sanitize(zone: Option<&str>) -> Option<String> {
    let zone = zone?.trim();
    if zone.is_empty() {
        return None;
    }
    zone_id(zone)
}

/// `getZoneId(name).getId()`: the `UTC±h[:mm]` shorthand is rewritten first. As in Java, a
/// shorthand without a sign is read as west of UTC.
fn zone_id(name: &str) -> Option<String> {
    static UTC: OnceLock<Regex> = OnceLock::new();
    let re = UTC.get_or_init(|| Regex::new(r"^UTC([+-]?)(\d{1,2}):?(\d{2})?$").expect("static regex"));
    if name.to_uppercase().starts_with("UTC") {
        if let Some(c) = re.captures(name) {
            let sign = if c.get(1).map(|m| m.as_str()) == Some("+") { "+" } else { "-" };
            let hours: u32 = c.get(2)?.as_str().parse().ok()?;
            let minutes: u32 = c.get(3).map(|m| m.as_str().parse().unwrap_or(0)).unwrap_or(0);
            return java_zone_of(&format!("UTC{sign}{hours:02}{minutes:02}"));
        }
    }
    java_zone_of(name)
}

/// `ZoneId.of(id).getId()`.
fn java_zone_of(id: &str) -> Option<String> {
    if id == "Z" {
        return Some("Z".into());
    }
    if id.starts_with('+') || id.starts_with('-') {
        return offset_id(id).map(|o| o.unwrap_or_else(|| "Z".into()));
    }
    if matches!(id, "UTC" | "GMT" | "UT") {
        return Some(id.into());
    }
    for prefix in ["UTC", "GMT", "UT"] {
        if let Some(rest) = id.strip_prefix(prefix) {
            if rest.starts_with('+') || rest.starts_with('-') {
                return offset_id(rest).map(|o| format!("{prefix}{}", o.unwrap_or_default()));
            }
        }
    }
    chrono_tz::Tz::from_str(id).ok().map(|_| id.to_string())
}

/// `ZoneOffset.of(text).getId()`: `Some(None)` for a zero offset.
fn offset_id(text: &str) -> Option<Option<String>> {
    let (sign, digits) = text.split_at(1);
    let negative = sign == "-";
    let compact: String = digits.chars().filter(|c| *c != ':').collect();
    if !compact.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let colon_ok = match digits.len() {
        1 | 2 | 4 | 6 => !digits.contains(':'),
        5 => digits.as_bytes()[2] == b':',
        8 => digits.as_bytes()[2] == b':' && digits.as_bytes()[5] == b':',
        _ => false,
    };
    if !colon_ok {
        return None;
    }
    let part = |from: usize| compact.get(from..from + 2).map(|s| s.parse::<u32>().unwrap_or(0)).unwrap_or(0);
    let hours = if compact.len() == 1 { compact.parse().ok()? } else { part(0) };
    let (minutes, seconds) = if compact.len() <= 2 { (0, 0) } else { (part(2), part(4)) };
    if hours > 18 || minutes > 59 || seconds > 59 || (hours == 18 && (minutes > 0 || seconds > 0)) {
        return None;
    }
    if hours == 0 && minutes == 0 && seconds == 0 {
        return Some(None);
    }
    let s = if negative { '-' } else { '+' };
    Some(Some(if seconds > 0 {
        format!("{s}{hours:02}:{minutes:02}:{seconds:02}")
    } else {
        format!("{s}{hours:02}:{minutes:02}")
    }))
}

#[cfg(test)]
mod tests {
    //! Ported from commons `TimeZoneUtilTest`.
    use super::*;

    #[test]
    fn override_wins() {
        assert_eq!(effective(Some("Asia/Dubai"), Some("Asia/Kolkata")).as_deref(), Some("Asia/Dubai"));
    }

    #[test]
    fn null_override_inherits() {
        for o in [None, Some(""), Some("   ")] {
            assert_eq!(effective(o, Some("Asia/Kolkata")).as_deref(), Some("Asia/Kolkata"));
        }
    }

    #[test]
    fn junk_override_inherits() {
        assert_eq!(effective(Some("Mars/Olympus_Mons"), Some("Asia/Kolkata")).as_deref(), Some("Asia/Kolkata"));
    }

    #[test]
    fn both_unusable_is_null() {
        assert_eq!(effective(None, None), None);
        assert_eq!(effective(Some("nonsense"), Some("also nonsense")), None);
    }

    #[test]
    fn sanitize_is_total() {
        assert_eq!(sanitize(None), None);
        assert_eq!(sanitize(Some("Not/AZone")), None);
        assert_eq!(sanitize(Some("  Europe/London  ")).as_deref(), Some("Europe/London"));
    }

    #[test]
    fn offset_forms_survive() {
        assert_eq!(sanitize(Some("UTC+05:30")).as_deref(), Some("UTC+05:30"));
        assert_eq!(sanitize(Some("UTC+0530")).as_deref(), Some("UTC+05:30"));
        assert_eq!(sanitize(Some("UTC-5")).as_deref(), Some("UTC-05:00"));
        // No sign reads as west, as in Java.
        assert_eq!(sanitize(Some("UTC5")).as_deref(), Some("UTC-05:00"));
        assert_eq!(sanitize(Some("UTC+0")).as_deref(), Some("UTC"));
        assert_eq!(sanitize(Some("UTC")).as_deref(), Some("UTC"));
        assert_eq!(sanitize(Some("GMT+01:00")).as_deref(), Some("GMT+01:00"));
        assert_eq!(sanitize(Some("+05:30")).as_deref(), Some("+05:30"));
        assert_eq!(sanitize(Some("-0800")).as_deref(), Some("-08:00"));
        assert_eq!(sanitize(Some("+00:00")).as_deref(), Some("Z"));
        assert_eq!(sanitize(Some("+5")).as_deref(), Some("+05:00"));
        assert_eq!(sanitize(Some("+05:30:15")).as_deref(), Some("+05:30:15"));
        assert_eq!(sanitize(Some("Z")).as_deref(), Some("Z"));
        assert_eq!(sanitize(Some("+19:00")), None);
        assert_eq!(sanitize(Some("+0a")), None);
        assert_eq!(sanitize(Some("+053")), None);
        assert_eq!(sanitize(Some("UT-02")).as_deref(), Some("UT-02:00"));
    }

    #[test]
    fn aliases_are_left_alone() {
        assert_eq!(sanitize(Some("Asia/Calcutta")).as_deref(), Some("Asia/Calcutta"));
        assert_eq!(sanitize(Some("Asia/Kolkata")).as_deref(), Some("Asia/Kolkata"));
    }
}
