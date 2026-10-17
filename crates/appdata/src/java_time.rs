//! The `java.time` parsers the codecs lean on, with their exact acceptance rules.
//!
//! `LocalDateTime.parse` takes `yyyy-MM-ddTHH:mm[:ss[.f{1,9}]]`, `OffsetDateTime.parse` the
//! same with a `Z` or `+hh:mm` after it, and `Instant.parse` the offset form too. Anything
//! else is refused, which is what decides whether a codec rewrites a value or leaves it.

use chrono::{FixedOffset, NaiveDate, NaiveDateTime, NaiveTime, TimeZone, Timelike};

fn digits(s: &str, n: usize) -> Option<u32> {
    if s.len() != n || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// `LocalDate.parse` (ISO_LOCAL_DATE): four-digit year, two-digit month and day.
pub fn parse_local_date(s: &str) -> Option<NaiveDate> {
    let mut parts = s.splitn(3, '-');
    let y = digits(parts.next()?, 4)? as i32;
    let m = digits(parts.next()?, 2)?;
    let d = digits(parts.next()?, 2)?;
    NaiveDate::from_ymd_opt(y, m, d)
}

/// `LocalTime.parse` (ISO_LOCAL_TIME): `HH:mm[:ss[.fffffffff]]`.
pub fn parse_local_time(s: &str) -> Option<NaiveTime> {
    let mut parts = s.splitn(3, ':');
    let h = digits(parts.next()?, 2)?;
    let mi = digits(parts.next()?, 2)?;
    let (sec, nanos) = match parts.next() {
        None => (0, 0),
        Some(rest) => {
            let (sec, frac) = match rest.find('.') {
                Some(i) => (&rest[..i], Some(&rest[i + 1..])),
                None => (rest, None),
            };
            let sec = digits(sec, 2)?;
            let nanos = match frac {
                None => 0,
                Some(f) => {
                    if f.is_empty() || f.len() > 9 || !f.bytes().all(|b| b.is_ascii_digit()) {
                        return None;
                    }
                    format!("{f:0<9}").parse().ok()?
                }
            };
            (sec, nanos)
        }
    };
    NaiveTime::from_hms_nano_opt(h, mi, sec, nanos)
}

/// `LocalDateTime.parse` (ISO_LOCAL_DATE_TIME).
pub fn parse_local_date_time(s: &str) -> Option<NaiveDateTime> {
    let i = s.find(['T', 't'])?;
    Some(NaiveDateTime::new(parse_local_date(&s[..i])?, parse_local_time(&s[i + 1..])?))
}

/// The offset suffix the ISO formatters read: `Z`, `+hh:mm`, `+hh:mm:ss`, `+hh`.
fn split_offset(s: &str) -> Option<(&str, FixedOffset)> {
    if let Some(body) = s.strip_suffix(['Z', 'z']) {
        return Some((body, FixedOffset::east_opt(0)?));
    }
    let i = s.rfind(['+', '-'])?;
    let (body, off) = (&s[..i], &s[i..]);
    let sign = if off.starts_with('-') { -1 } else { 1 };
    let parts: Vec<&str> = off[1..].split(':').collect();
    let h = digits(parts.first()?, 2)? as i32;
    let m = parts.get(1).map(|p| digits(p, 2)).unwrap_or(Some(0))? as i32;
    let sec = parts.get(2).map(|p| digits(p, 2)).unwrap_or(Some(0))? as i32;
    if h > 18 || m > 59 || sec > 59 {
        return None;
    }
    Some((body, FixedOffset::east_opt(sign * (h * 3600 + m * 60 + sec))?))
}

/// `OffsetDateTime.parse`, returned as the UTC wall time.
pub fn parse_offset_date_time_utc(s: &str) -> Option<NaiveDateTime> {
    let (body, offset) = split_offset(s)?;
    let local = parse_local_date_time(body)?;
    let dt = offset.from_local_datetime(&local).single()?;
    Some(dt.naive_utc())
}

/// `OffsetTime.parse`, returned as the UTC wall time.
pub fn parse_offset_time_utc(s: &str) -> Option<NaiveTime> {
    let (body, offset) = split_offset(s)?;
    let local = parse_local_time(body)?;
    let shifted = local.num_seconds_from_midnight() as i64 - offset.local_minus_utc() as i64;
    let secs = shifted.rem_euclid(86_400) as u32;
    NaiveTime::from_num_seconds_from_midnight_opt(secs, local.nanosecond())
}

/// `Instant.parse(s).toEpochMilli()`.
pub fn parse_instant_millis(s: &str) -> Option<i64> {
    let utc = parse_offset_date_time_utc(s)?;
    Some(utc.and_utc().timestamp_millis())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_forms() {
        assert!(parse_local_date_time("2026-01-15T10:00").is_some());
        assert!(parse_local_date_time("2026-01-15T10:00:00.123456789").is_some());
        assert!(parse_local_date_time("2026-01-15 10:00:00").is_none());
        assert!(parse_local_date_time("2026-1-15T10:00:00").is_none());
        assert!(parse_local_date("2026-02-30").is_none());
    }

    #[test]
    fn offsets_fold_into_utc() {
        let t = parse_offset_date_time_utc("2026-01-15T10:00:00+05:30").unwrap();
        assert_eq!(t.to_string(), "2026-01-15 04:30:00");
        assert_eq!(parse_instant_millis("1970-01-01T00:00:01Z"), Some(1000));
        let t = parse_offset_time_utc("01:00:00+05:30").unwrap();
        assert_eq!(t.to_string(), "19:30:00");
    }
}
