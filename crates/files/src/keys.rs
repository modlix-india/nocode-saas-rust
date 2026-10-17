//! Secured access keys (`createKey`) and the `UniqueUtil` ids the service hands out.

use axum::http::StatusCode;
use chrono::{DateTime, Duration, Months, Utc};
use platform::error::{AppError, AppResult};

use crate::errors::{self, TIME_SPAN_ERROR, TIME_UNIT_ERROR};
use crate::state::AppState;

/// `UniqueUtil.base36UUID`: the first eight characters of a random UUID's text, read as the
/// bytes of a big-endian `long`, in base 36. Eight hex characters are 32 random bits, which is
/// all a key carries (12 or 13 characters, `[0-9a-z]`); kept, because keys already handed out
/// look like this and the column is `CHAR(15)`.
pub fn base36_uuid() -> String {
    let hex = format!("{:08x}", rand::random::<u32>());
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(hex.as_bytes());
    to_base36(i64::from_be_bytes(bytes))
}

fn to_base36(mut n: i64) -> String {
    const DIGITS: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    if n == 0 {
        return "0".into();
    }
    let neg = n < 0;
    let mut out = Vec::new();
    while n != 0 {
        out.push(DIGITS[(n % 36).unsigned_abs() as usize]);
        n /= 36;
    }
    if neg {
        out.push(b'-');
    }
    out.reverse();
    String::from_utf8(out).unwrap_or_default()
}

/// `UniqueUtil.shortUUID`: a random UUID as a signed 128-bit number in base 62, left padded
/// with `0` to 22 characters.
pub fn short_uuid() -> String {
    let mut b: [u8; 16] = rand::random();
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    base62_signed(i128::from_be_bytes(b))
}

fn base62_signed(mut n: i128) -> String {
    const BASE: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut out = Vec::new();
    // `BigInteger.mod` is never negative; `divide` truncates toward zero.
    while n != 0 {
        out.push(BASE[n.rem_euclid(62) as usize]);
        n /= 62;
    }
    out.reverse();
    let s = String::from_utf8(out).unwrap_or_default();
    format!("{s:0>22}")
}

/// `java.time.temporal.ChronoUnit`, by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChronoUnit {
    Nanos,
    Micros,
    Millis,
    Seconds,
    Minutes,
    Hours,
    HalfDays,
    Days,
    Weeks,
    Months,
    Years,
    Decades,
    Centuries,
    Millennia,
    Eras,
    Forever,
}

impl ChronoUnit {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.trim() {
            "NANOS" => Self::Nanos,
            "MICROS" => Self::Micros,
            "MILLIS" => Self::Millis,
            "SECONDS" => Self::Seconds,
            "MINUTES" => Self::Minutes,
            "HOURS" => Self::Hours,
            "HALF_DAYS" => Self::HalfDays,
            "DAYS" => Self::Days,
            "WEEKS" => Self::Weeks,
            "MONTHS" => Self::Months,
            "YEARS" => Self::Years,
            "DECADES" => Self::Decades,
            "CENTURIES" => Self::Centuries,
            "MILLENNIA" => Self::Millennia,
            "ERAS" => Self::Eras,
            "FOREVER" => Self::Forever,
            _ => return None,
        })
    }

    /// `LocalDateTime.plus(amount, unit)`; `None` where Java throws (ERAS beyond the calendar,
    /// FOREVER, overflow).
    pub fn add(self, t: DateTime<Utc>, amount: i64) -> Option<DateTime<Utc>> {
        let months = |m: i64| -> Option<DateTime<Utc>> {
            if m >= 0 {
                t.checked_add_months(Months::new(u32::try_from(m).ok()?))
            } else {
                // `unsigned_abs`, not `-m`: `-i64::MIN` overflows (a panic in a debug build).
                t.checked_sub_months(Months::new(u32::try_from(m.unsigned_abs()).ok()?))
            }
        };
        let dur = |d: Option<Duration>| d.and_then(|d| t.checked_add_signed(d));
        match self {
            Self::Nanos => dur(Some(Duration::nanoseconds(amount))),
            Self::Micros => dur(Some(Duration::microseconds(amount))),
            Self::Millis => dur(Duration::try_milliseconds(amount)),
            Self::Seconds => dur(Duration::try_seconds(amount)),
            Self::Minutes => dur(Duration::try_minutes(amount)),
            Self::Hours => dur(Duration::try_hours(amount)),
            Self::HalfDays => dur(amount.checked_mul(12).and_then(Duration::try_hours)),
            Self::Days => dur(Duration::try_days(amount)),
            Self::Weeks => dur(Duration::try_weeks(amount)),
            Self::Months => months(amount),
            Self::Years => months(amount.checked_mul(12)?),
            Self::Decades => months(amount.checked_mul(120)?),
            Self::Centuries => months(amount.checked_mul(1200)?),
            Self::Millennia => months(amount.checked_mul(12000)?),
            Self::Eras | Self::Forever => None,
        }
    }
}

/// `SecuredFileResourceService.createAccessKey`: a key row for `path` (cut at `?`) lasting
/// `time` `unit`s (the configured default when not given), used at most `limit` times.
pub async fn create_access_key(
    st: &AppState,
    time: Option<i64>,
    unit: Option<ChronoUnit>,
    limit: Option<u64>,
    path: &str,
) -> AppResult<String> {
    if unit.is_none() && time.is_some() {
        return Err(errors::status(StatusCode::BAD_REQUEST, TIME_UNIT_ERROR, &[]));
    }
    if time.is_none() && limit.is_some() {
        return Err(errors::status(StatusCode::BAD_REQUEST, TIME_SPAN_ERROR, &[]));
    }
    let cfg = &st.config().secured_keys;
    let time = time.unwrap_or(cfg.default_time_limit);
    let unit = match unit {
        Some(u) => u,
        None => ChronoUnit::parse(&cfg.default_time_unit).unwrap_or(ChronoUnit::Days),
    };
    let path = path.split('?').next().unwrap_or(path);
    let till = unit
        .add(Utc::now(), time)
        .ok_or_else(|| -> AppError {
            let span = format!("{time} {unit:?}");
            errors::literal("FILES.TIME_SPAN_UNSUPPORTED", StatusCode::BAD_REQUEST, format!("Unsupported time span: {span}")).param("span", span).into()
        })?;

    // The key column is unique and a key has 32 bits: a collision is retried with a new key
    // (Java fails the request).
    for _ in 0..5 {
        let key = base36_uuid();
        let r = sqlx::query(
            "INSERT INTO files_secured_access_keys (PATH, ACCESS_KEY, ACCESS_TILL, ACCESS_LIMIT) VALUES (?, ?, ?, ?)",
        )
        .bind(path)
        .bind(&key)
        .bind(till)
        .bind(limit)
        .execute(st.dao().pool())
        .await;
        match r {
            Ok(_) => return Ok(key),
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => continue,
            Err(e) => return Err(AppError::Internal(e.into())),
        }
    }
    Err(errors::status(StatusCode::INTERNAL_SERVER_ERROR, errors::SECURED_KEY_CREATION_ERROR, &[]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base36_like_java() {
        // Long.toString(ByteBuffer.wrap("1b4e28ba".getBytes()).getLong(), 36)
        let v = i64::from_be_bytes(*b"1b4e28ba");
        assert_eq!(to_base36(v), "r1a2azgu7u5d");
        for _ in 0..200 {
            let k = base36_uuid();
            assert!((12..=13).contains(&k.len()), "{k}");
            assert!(k.chars().all(|c| c.is_ascii_digit() || c.is_ascii_lowercase()));
        }
    }

    #[test]
    fn short_uuid_shape() {
        for _ in 0..200 {
            let s = short_uuid();
            assert_eq!(s.len(), 22, "{s}");
            assert!(s.chars().all(|c| c.is_ascii_alphanumeric()));
        }
        assert_eq!(base62_signed(61), format!("{:0>22}", "Z"));
        assert_eq!(base62_signed(62), format!("{:0>22}", "10"));
    }

    #[test]
    fn chrono_units() {
        let t = DateTime::from_timestamp(1_792_000_000, 0).unwrap();
        assert_eq!(ChronoUnit::Hours.add(t, 2).unwrap().timestamp(), 1_792_007_200);
        assert_eq!(ChronoUnit::parse("Hours"), None);
        assert!(ChronoUnit::Forever.add(t, 1).is_none());
        assert!(ChronoUnit::Years.add(t, 10).is_some());
    }

    #[test]
    fn base36_edges() {
        assert_eq!(to_base36(0), "0");
        // Long.toString(-71, 36)
        assert_eq!(to_base36(-71), "-1z");
        assert_eq!(to_base36(i64::MIN), "-1y2p0ij32e8e8");
    }

    #[test]
    fn every_chrono_unit() {
        let t = DateTime::from_timestamp(1_792_022_400, 0).unwrap();
        let s = |u: &str, n: i64| ChronoUnit::parse(u).unwrap().add(t, n).map(|d| d.timestamp_nanos_opt().unwrap_or(i64::MAX) - t.timestamp_nanos_opt().unwrap());
        assert_eq!(s("NANOS", 5), Some(5));
        assert_eq!(s("MICROS", 5), Some(5_000));
        assert_eq!(s("MILLIS", 5), Some(5_000_000));
        assert_eq!(s("SECONDS", 5), Some(5_000_000_000));
        assert_eq!(s("MINUTES", 1), Some(60_000_000_000));
        assert_eq!(s("HALF_DAYS", 1), Some(43_200_000_000_000));
        assert_eq!(s("DAYS", 1), Some(86_400_000_000_000));
        assert_eq!(s("WEEKS", 1), Some(604_800_000_000_000));
        let months = |u: &str, n: i64| ChronoUnit::parse(u).unwrap().add(t, n).map(|d| d.format("%Y-%m-%d").to_string());
        assert_eq!(t.format("%Y-%m-%d").to_string(), "2026-10-15");
        assert_eq!(months("MONTHS", 1).as_deref(), Some("2026-11-15"));
        assert_eq!(months("MONTHS", -2).as_deref(), Some("2026-08-15"));
        assert_eq!(months("YEARS", 1).as_deref(), Some("2027-10-15"));
        assert_eq!(months("DECADES", 1).as_deref(), Some("2036-10-15"));
        assert_eq!(months("CENTURIES", 1).as_deref(), Some("2126-10-15"));
        assert_eq!(months("MILLENNIA", 1).as_deref(), Some("3026-10-15"));
        assert_eq!(months("MILLENNIA", 1_000_000), None);
        assert_eq!(months("YEARS", i64::MAX), None);
        assert_eq!(months("MONTHS", i64::MIN), None);
        assert_eq!(s("DAYS", i64::MAX), None);
        assert!(ChronoUnit::parse("ERAS").unwrap().add(t, 1).is_none());
        assert_eq!(ChronoUnit::parse(" DAYS "), Some(ChronoUnit::Days));
    }
}
