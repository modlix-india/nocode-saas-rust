//! `VersionRetention`: how much row history a storage keeps, resolved once for both
//! backends. A version row must satisfy BOTH bounds to survive; 0 means unlimited.

use chrono::{Duration, NaiveDateTime, Utc};

use crate::model::Storage;

pub const DEFAULT_DAYS: i32 = 90;
pub const DEFAULT_COUNT: i32 = 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionRetention {
    pub days: i32,
    pub count: i32,
}

impl Default for VersionRetention {
    /// What applies when the installation has configured nothing.
    fn default() -> Self {
        VersionRetention { days: DEFAULT_DAYS, count: DEFAULT_COUNT }
    }
}

impl VersionRetention {
    /// A configured pair, clamped so no caller can build a negative bound.
    pub fn clamped(days: i32, count: i32) -> VersionRetention {
        VersionRetention { days: days.max(0), count: count.max(0) }
    }

    /// The policy for one storage, falling back per field to the installation default.
    pub fn for_storage(storage: &Storage, defaults: VersionRetention) -> VersionRetention {
        VersionRetention {
            days: storage.version_retention_days.map(|d| d.max(0)).unwrap_or(defaults.days),
            count: storage.version_retention_count.map(|c| c.max(0)).unwrap_or(defaults.count),
        }
    }

    pub fn trims_by_age(&self) -> bool {
        self.days > 0
    }

    pub fn trims_by_count(&self) -> bool {
        self.count > 0
    }

    pub fn keeps_everything(&self) -> bool {
        !self.trims_by_age() && !self.trims_by_count()
    }

    /// Version rows older than this go. UTC, as the rows carry it.
    pub fn cutoff(&self) -> NaiveDateTime {
        Utc::now().naive_utc() - Duration::days(self.days as i64)
    }

    pub fn cutoff_epoch_millis(&self) -> i64 {
        self.cutoff().and_utc().timestamp_millis()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_field_fallback() {
        let s = Storage { version_retention_count: Some(5), ..Default::default() };
        let r = VersionRetention::for_storage(&s, VersionRetention::default());
        assert_eq!(r, VersionRetention { days: 90, count: 5 });
        let s = Storage { version_retention_days: Some(-3), version_retention_count: Some(0), ..Default::default() };
        assert!(VersionRetention::for_storage(&s, VersionRetention::default()).keeps_everything());
        assert_eq!(VersionRetention::clamped(-1, -1), VersionRetention { days: 0, count: 0 });
    }
}
