//! The two clocks the Java service reads, kept apart on purpose.
//!
//! - `LocalDateTime.now(ZoneId.of("UTC"))`: token expiries (`EXPIRES_AT`), social state age,
//!   draft token expiry. [`Clock::utc`].
//! - `LocalDateTime.now()`: the JVM's own zone. Lock times (`LOCKED_UNTIL`), `LAST_USED_AT`, OTP
//!   expiry, the anonymous user's timestamps and a Basic caller's expiry. [`Clock::local`].
//!
//! Both are written into `TIMESTAMP` columns as wall times and compared back as wall times, so
//! a Rust instance has to use the same clock for the same column or a Java lock would read as
//! expired (or the reverse). Tests fix both.

use chrono::{DateTime, FixedOffset, Local, NaiveDateTime, Offset, Utc};

#[derive(Debug, Clone, Copy, Default)]
pub struct Clock {
    fixed: Option<(DateTime<Utc>, FixedOffset)>,
}

impl Clock {
    pub fn system() -> Self {
        Self { fixed: None }
    }

    /// A clock stopped at `at`, in a zone `offset_seconds` east of UTC.
    pub fn fixed(at: DateTime<Utc>, offset_seconds: i32) -> Self {
        let offset = FixedOffset::east_opt(offset_seconds).unwrap_or_else(|| Utc.fix());
        Self { fixed: Some((at, offset)) }
    }

    pub fn instant(&self) -> DateTime<Utc> {
        self.fixed.map(|(t, _)| t).unwrap_or_else(Utc::now)
    }

    pub fn millis(&self) -> i64 {
        self.instant().timestamp_millis()
    }

    /// `LocalDateTime.now(ZoneId.of("UTC"))`.
    pub fn utc(&self) -> NaiveDateTime {
        self.instant().naive_utc()
    }

    /// `LocalDateTime.now()`.
    pub fn local(&self) -> NaiveDateTime {
        match self.fixed {
            Some((t, offset)) => t.with_timezone(&offset).naive_local(),
            None => Local::now().naive_local(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn fixed_clock_has_both_wall_times() {
        let at = Utc.with_ymd_and_hms(2026, 10, 15, 2, 0, 0).unwrap();
        let c = Clock::fixed(at, 19_800);
        assert_eq!(c.utc().to_string(), "2026-10-15 02:00:00");
        assert_eq!(c.local().to_string(), "2026-10-15 07:30:00");
        assert_eq!(c.millis(), at.timestamp_millis());
        let s = Clock::system();
        assert!((s.instant() - Utc::now()).num_seconds().abs() < 5);
        assert!((s.local() - Local::now().naive_local()).num_seconds().abs() < 5);
    }
}
