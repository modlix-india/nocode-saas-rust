//! Automations: a tenant's "when this happens, do that, wait, check" flow, stored as the
//! overridable `Automation` document ([`crate::docs::AutomationDoc`]). Rust only: Java has no
//! such document (its `Workflow` is storage only and nothing runs it).
//!
//! The document:
//!
//! ```text
//! trigger     { key, filter }            the event that starts a run
//! entry       { oncePerSubject, subjectPath }
//! exitWhen    [ { key, filter } ]        events that stop a waiting run
//! start       the first node's key
//! nodes       { key: { type, title, ... } }
//! transitions [ { from, to, branch } ]
//! ```
//!
//! A node's `type` is one of [`NODE_TYPES`]. An `ACTION` names what it calls in `action` and
//! what it passes in `params`. A `WAIT` holds exactly one of `for` (an ISO-8601 period),
//! `until` (an expression giving a time) or `untilEvent` (`{ key, filter }`, with a `timeout`
//! period beside it). A `CHECK` holds a `condition` and leaves by the `yes` or the
//! `otherwise` branch. A `SPLIT` starts lanes that run side by side and a `JOIN` closes them.

pub mod catalog;
pub mod check;
pub mod engine;
pub mod expr;
pub mod guard;
pub mod routes;
pub mod runtime;
pub mod storage_trigger;

/// The node types.
pub const ACTION: &str = "ACTION";
pub const WAIT: &str = "WAIT";
pub const CHECK: &str = "CHECK";
pub const SPLIT: &str = "SPLIT";
pub const JOIN: &str = "JOIN";
pub const END: &str = "END";
pub const NODE_TYPES: &[&str] = &[ACTION, WAIT, CHECK, SPLIT, JOIN, END];

/// A `CHECK`'s two ways out.
pub const BRANCH_YES: &str = "yes";
pub const BRANCH_OTHERWISE: &str = "otherwise";

/// An ISO-8601 period (`P2D`, `PT90M`, `P1W`, `P1DT12H`) as seconds. Weeks, days, hours,
/// minutes and seconds only: a month or a year has no fixed length, so neither is accepted.
/// `None` for anything else, for an empty period (`P`, `PT`) and for zero.
pub fn period_seconds(text: &str) -> Option<u64> {
    let rest = text.trim().strip_prefix(['P', 'p'])?;
    let (date, time) = match rest.split_once(['T', 't']) {
        Some((d, t)) => (d, Some(t)),
        None => (rest, None),
    };
    if time.is_some_and(str::is_empty) {
        return None;
    }
    let mut total: u64 = 0;
    let mut add = |part: &str, units: &[(char, u64)]| -> Option<()> {
        let mut digits = String::new();
        let mut next_unit = 0usize;
        for c in part.chars() {
            if c.is_ascii_digit() {
                digits.push(c);
                continue;
            }
            // Units come in order (W before D, H before M before S) and once each.
            let at = units[next_unit..].iter().position(|(u, _)| *u == c.to_ascii_uppercase())? + next_unit;
            let n: u64 = digits.parse().ok()?;
            total = total.checked_add(n.checked_mul(units[at].1)?)?;
            digits.clear();
            next_unit = at + 1;
        }
        digits.is_empty().then_some(())
    };
    add(date, &[('W', 604_800), ('D', 86_400)])?;
    if let Some(t) = time {
        add(t, &[('H', 3_600), ('M', 60), ('S', 1)])?;
    }
    (total > 0).then_some(total)
}

#[cfg(test)]
mod tests {
    use super::period_seconds;

    #[test]
    fn periods() {
        assert_eq!(period_seconds("P2D"), Some(172_800));
        assert_eq!(period_seconds("PT90M"), Some(5_400));
        assert_eq!(period_seconds("P1W"), Some(604_800));
        assert_eq!(period_seconds("P1DT12H"), Some(129_600));
        assert_eq!(period_seconds("pt1h30m15s"), Some(5_415));
        assert_eq!(period_seconds(" P1D "), Some(86_400));
        for bad in ["", "P", "PT", "2D", "P2", "P1M", "P1Y", "PT1D", "P1H", "PT0S", "P-1D", "P1.5D", "PT1M1H", "P1D1D", "P1DT"] {
            assert_eq!(period_seconds(bad), None, "{bad}");
        }
    }
}
