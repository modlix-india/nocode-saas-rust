//! Finishes MySQL storage migrations that a restart, a deploy or a panic interrupted.
//!
//! A storage publish migrates every tenant's table inside the request, journalled step by step
//! in the tenant's own `storage_migration` table. When the request dies part way (the process
//! restarts, the task panics), the tenant's row stays RUNNING and nothing finishes it until the
//! storage is published again. This sweep claims every row nobody has touched for
//! `stale_after_seconds` and finishes it from the plan the row carries.
//!
//! It runs once when core-editor starts and then every `interval_seconds`. Startup matters
//! most: a migration interrupted inside its CONTRACT step leaves a field that cannot be read
//! or written until the rename runs, and a restarted node is the first chance to finish it.
//! Every core-editor instance sweeps; the claim lets only one of them take each row.

use std::sync::Arc;
use std::time::Duration;

use appdata::mysql::migration::RecoveryReport;
use appdata::mysql::MySqlAppDataService;
use serde::{Deserialize, Serialize};

use crate::storage::defs::Catalog;

/// `[appdata.migration_recovery]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RecoverySettings {
    pub enabled: bool,
    /// A RUNNING row whose heartbeat is older than this is taken as abandoned.
    pub stale_after_seconds: i32,
    pub interval_seconds: u64,
}

impl Default for RecoverySettings {
    fn default() -> Self {
        Self {
            enabled: true,
            stale_after_seconds: appdata::mysql::migration::DEFAULT_STALE_AFTER_SECONDS,
            interval_seconds: 300,
        }
    }
}

/// What the sweep runs on.
#[derive(Clone)]
pub struct Recovery {
    pub catalog: Arc<dyn Catalog>,
    pub mysql: Arc<MySqlAppDataService>,
    pub settings: RecoverySettings,
}

impl Recovery {
    /// Sweeps now, then every `interval_seconds`, for the life of the process.
    pub fn spawn(self) {
        if !self.settings.enabled {
            tracing::info!("storage migration recovery is off");
            return;
        }
        tokio::spawn(async move {
            self.sweep("startup").await;
            let mut every = tokio::time::interval(Duration::from_secs(self.settings.interval_seconds.max(30)));
            every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            every.tick().await;
            loop {
                every.tick().await;
                self.sweep("scheduled").await;
            }
        });
    }

    /// One pass over every MySQL app-data connection. Never fails: a connection that cannot be
    /// swept is logged and the pass goes on to the next.
    pub async fn sweep(&self, trigger: &str) -> RecoveryReport {
        let conns = match self.catalog.all_app_data_everywhere("MYSQL").await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(trigger, error = %e.text(), "storage migration recovery could not list the MySQL connections");
                return RecoveryReport::default();
            }
        };
        let mut report = RecoveryReport::default();
        for conn in conns {
            match self.mysql.sweep_interrupted(Some(&conn), self.settings.stale_after_seconds).await {
                Ok(r) => report = merge(report, r),
                Err(e) => tracing::error!(trigger, connection = conn.id, app = conn.app_code.as_deref().unwrap_or(""), error = %e, "storage migration recovery failed on a connection"),
            }
        }
        // Silent when there is nothing to say, so the line that matters is not lost among
        // "nothing happened" every five minutes.
        if !report.is_quiet() {
            if report.unplayable.is_empty() && report.outcomes.values().all(|o| o.is_success()) {
                tracing::warn!(trigger, summary = report.summary(), "storage migration recovery");
            } else {
                tracing::error!(trigger, summary = report.summary(), outcomes = ?report.outcomes, "storage migration recovery");
            }
        }
        report
    }
}

fn merge(a: RecoveryReport, b: RecoveryReport) -> RecoveryReport {
    let mut outcomes = a.outcomes;
    outcomes.extend(b.outcomes);
    RecoveryReport {
        found: a.found + b.found,
        claimed: a.claimed + b.claimed,
        resumed: a.resumed + b.resumed,
        outcomes,
        unplayable: [a.unplayable, b.unplayable].concat(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use appdata::mysql::migration::MigrationOutcome;

    #[test]
    fn reports_add_up() {
        let mut a = RecoveryReport { found: 2, claimed: 1, resumed: 1, ..Default::default() };
        a.outcomes.insert("A_app/orders".into(), MigrationOutcome::applied(2, 0));
        let mut b = RecoveryReport { found: 1, claimed: 1, resumed: 0, unplayable: vec!["B_app/x".into()], ..Default::default() };
        b.outcomes.insert("B_app/orders".into(), MigrationOutcome::failed("boom", 0, 0));
        let m = merge(a, b);
        assert_eq!((m.found, m.claimed, m.resumed), (3, 2, 1));
        assert_eq!(m.outcomes.len(), 2);
        assert_eq!(m.unplayable, vec!["B_app/x".to_string()]);
    }

    #[test]
    fn on_by_default() {
        let s = RecoverySettings::default();
        assert!(s.enabled);
        assert_eq!((s.stale_after_seconds, s.interval_seconds), (60, 300));
    }
}
