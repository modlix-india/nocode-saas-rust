//! The "Show me" shape rules (CXZ-1780): which view types fit a result's shape. This is the one
//! table the runner's BAD_VIEW and the UI's chart type picker both read: the runner checks a spec
//! against it, every Run output carries `fits` (each type's verdict for that result), and
//! `CoreServices.Report.ViewTypes` answers the table itself so the UI can mirror it.
//!
//! A shape is the number of group by entries and the number of value columns (measures plus
//! derived measures; for a FUNCTION source its visible dimension and measure columns). For each
//! group by count (0, 1, 2) a rule allows a range of value counts, or nothing; TABLE and LIST take
//! any shape, more than 2 group by included.
//!
//! Mirrors nocode-ui `components/Reports/shapeRules.ts` (workstream B) rule for rule.

use serde_json::{json, Map, Value};

/// Value columns allowed for one group by count: `(min, max)`, `max` none for no limit.
pub type Values = Option<(u8, Option<u8>)>;

#[derive(Debug, Clone, Copy)]
pub struct ViewRule {
    pub ty: &'static str,
    pub label: &'static str,
    pub family: &'static str,
    /// Index 0, 1, 2: the rule with that many group by entries.
    pub by_groups: [Values; 3],
    /// What the view needs, in plain words, for the reason a shape does not fit.
    pub needs: &'static str,
}

const ANY: Values = Some((0, None));
const ONE_PLUS: Values = Some((1, None));
const TWO_PLUS: Values = Some((2, None));
const ONE: Values = Some((1, Some(1)));
const TWO: Values = Some((2, Some(2)));

const NUMBER: [Values; 3] = [ONE_PLUS, None, None];
const ONE_DIM: [Values; 3] = [None, ONE_PLUS, None];
const TWO_DIMS: [Values; 3] = [None, None, ONE];
const LINES: [Values; 3] = [None, ONE_PLUS, ONE_PLUS];
const TWO_ANY_GROUPS: [Values; 3] = [TWO, TWO, TWO];
const ONE_OR_TWO_DIMS_ONE_VALUE: [Values; 3] = [None, ONE, ONE];
const ONE_DIM_ONE_VALUE: [Values; 3] = [None, ONE, None];

const NUMBER_NEEDS: &str = "no group by (one row) and at least 1 measure";
const ONE_DIM_NEEDS: &str = "exactly 1 group by and at least 1 measure";
const TWO_DIMS_NEEDS: &str = "2 group by and 1 measure";
const LINE_NEEDS: &str = "1 group by (a date is best) or 2 (the second is the series), and at least 1 measure";
const TWO_MEASURES_NEEDS: &str = "exactly 2 measures";

/// Every view type (P1a, then the P1b HEATMAP, TREEMAP and WATERFALL), in the order the picker
/// lists them.
pub const VIEW_RULES: &[ViewRule] = &[
    ViewRule { ty: "KPI", label: "KPI", family: "number", by_groups: NUMBER, needs: NUMBER_NEEDS },
    ViewRule { ty: "GAUGE", label: "Gauge", family: "number", by_groups: NUMBER, needs: NUMBER_NEEDS },
    ViewRule { ty: "BULLET", label: "Bullet", family: "number", by_groups: NUMBER, needs: NUMBER_NEEDS },
    ViewRule { ty: "TABLE", label: "Table", family: "table", by_groups: [ANY, ANY, ANY], needs: "nothing in particular" },
    ViewRule { ty: "LIST", label: "List", family: "table", by_groups: [ANY, ANY, ANY], needs: "nothing in particular" },
    ViewRule { ty: "CROSSTAB", label: "Crosstab", family: "table", by_groups: TWO_DIMS, needs: TWO_DIMS_NEEDS },
    ViewRule { ty: "BAR", label: "Bar", family: "bar", by_groups: ONE_DIM, needs: ONE_DIM_NEEDS },
    ViewRule { ty: "HBAR", label: "Horizontal bar", family: "bar", by_groups: ONE_DIM, needs: ONE_DIM_NEEDS },
    ViewRule {
        ty: "GROUPED_BAR",
        label: "Grouped bar",
        family: "bar",
        by_groups: [None, TWO_PLUS, ONE],
        needs: "1 group by and 2 or more measures, or 2 group by and 1 measure",
    },
    ViewRule { ty: "STACKED_BAR", label: "Stacked bar", family: "bar", by_groups: TWO_DIMS, needs: TWO_DIMS_NEEDS },
    ViewRule { ty: "STACKED_BAR_100", label: "100% stacked bar", family: "bar", by_groups: TWO_DIMS, needs: TWO_DIMS_NEEDS },
    ViewRule { ty: "LOLLIPOP", label: "Lollipop", family: "bar", by_groups: ONE_DIM, needs: ONE_DIM_NEEDS },
    ViewRule { ty: "LINE", label: "Line", family: "line", by_groups: LINES, needs: LINE_NEEDS },
    ViewRule { ty: "SMOOTH_LINE", label: "Smooth line", family: "line", by_groups: LINES, needs: LINE_NEEDS },
    ViewRule { ty: "STEP_LINE", label: "Step line", family: "line", by_groups: LINES, needs: LINE_NEEDS },
    ViewRule { ty: "AREA", label: "Area", family: "line", by_groups: LINES, needs: LINE_NEEDS },
    ViewRule { ty: "STACKED_AREA", label: "Stacked area", family: "line", by_groups: TWO_DIMS, needs: TWO_DIMS_NEEDS },
    ViewRule { ty: "COMBO", label: "Combo (bar and line)", family: "line", by_groups: TWO_ANY_GROUPS, needs: TWO_MEASURES_NEEDS },
    ViewRule { ty: "SCATTER", label: "Scatter", family: "other", by_groups: TWO_ANY_GROUPS, needs: TWO_MEASURES_NEEDS },
    ViewRule { ty: "PIE", label: "Pie", family: "pie", by_groups: ONE_DIM, needs: ONE_DIM_NEEDS },
    ViewRule { ty: "DOUGHNUT", label: "Doughnut", family: "pie", by_groups: ONE_DIM, needs: ONE_DIM_NEEDS },
    ViewRule { ty: "FUNNEL", label: "Funnel", family: "pie", by_groups: ONE_DIM, needs: ONE_DIM_NEEDS },
    // P1b (CONTRACT 8.1).
    ViewRule { ty: "HEATMAP", label: "Heatmap", family: "other", by_groups: TWO_DIMS, needs: TWO_DIMS_NEEDS },
    ViewRule { ty: "TREEMAP", label: "Treemap", family: "other", by_groups: ONE_OR_TWO_DIMS_ONE_VALUE, needs: "1 or 2 group by and 1 measure" },
    ViewRule { ty: "WATERFALL", label: "Waterfall", family: "bar", by_groups: ONE_DIM_ONE_VALUE, needs: "exactly 1 group by and 1 measure" },
];

/// A result's shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shape {
    pub group_by: usize,
    pub values: usize,
}

pub fn rule(ty: &str) -> Option<&'static ViewRule> {
    VIEW_RULES.iter().find(|r| r.ty == ty)
}

/// The views that show one row of numbers; the runner keeps every row for them.
pub fn is_number(ty: &str) -> bool {
    rule(ty).is_some_and(|r| r.family == "number")
}

/// The views that show rows as a table.
pub fn is_table(ty: &str) -> bool {
    rule(ty).is_some_and(|r| r.family == "table")
}

/// Whether `ty` fits `shape`; `Err` holds the plain reason when it does not.
pub fn check(ty: &str, shape: Shape) -> Result<(), String> {
    let Some(r) = rule(ty) else {
        return Err(format!("'{ty}' is not a view type. Pick one of {}.", VIEW_RULES.iter().map(|r| r.ty).collect::<Vec<_>>().join(", ")));
    };
    let any_shape = r.by_groups.iter().all(|v| *v == ANY);
    let fits = any_shape
        || r
        .by_groups
        .get(shape.group_by)
        .copied()
        .flatten()
        .is_some_and(|(min, max)| shape.values >= min as usize && max.is_none_or(|m| shape.values <= m as usize));
    if fits {
        Ok(())
    } else {
        Err(format!(
            "{} needs {}; this report has {} group by and {} measure{}.",
            r.label,
            r.needs,
            shape.group_by,
            shape.values,
            if shape.values == 1 { "" } else { "s" }
        ))
    }
}

/// Every type's verdict for `shape`: `{"KPI": {"ok": true}, "PIE": {"ok": false, "reason": "..."}}`.
pub fn fits(shape: Shape) -> Value {
    let mut m = Map::new();
    for r in VIEW_RULES {
        let v = match check(r.ty, shape) {
            Ok(()) => json!({"ok": true}),
            Err(reason) => json!({"ok": false, "reason": reason}),
        };
        m.insert(r.ty.to_string(), v);
    }
    Value::Object(m)
}

/// The table itself, for the UI to mirror: each type with, per group by count ("0", "1", "2"),
/// `{"min": n, "max": n|null}` or null when that many group by entries never fit.
pub fn rules_json() -> Value {
    let types: Vec<Value> = VIEW_RULES
        .iter()
        .map(|r| {
            let mut groups = Map::new();
            for (i, v) in r.by_groups.iter().enumerate() {
                groups.insert(i.to_string(), v.map(|(min, max)| json!({"min": min, "max": max})).unwrap_or(Value::Null));
            }
            json!({"type": r.ty, "label": r.label, "family": r.family, "groupBy": groups, "needs": r.needs})
        })
        .collect();
    json!({"v": 1, "types": types, "valuesAre": "measures plus derived measures",
           "groupByIs": "spec group by entries; for a FUNCTION source its visible dimension columns (not hidden, not currency)",
           "anyShape": ["TABLE", "LIST"]})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(group_by: usize, values: usize) -> Shape {
        Shape { group_by, values }
    }

    #[test]
    fn the_contract_rules() {
        // KPI / GAUGE / BULLET: one row.
        for t in ["KPI", "GAUGE", "BULLET"] {
            assert!(check(t, s(0, 1)).is_ok());
            assert!(check(t, s(0, 3)).is_ok());
            assert!(check(t, s(1, 1)).unwrap_err().contains("no group by"), "{t}");
            assert!(check(t, s(0, 0)).is_err());
        }
        // Exactly one group by.
        for t in ["PIE", "DOUGHNUT", "FUNNEL", "LOLLIPOP", "BAR", "HBAR"] {
            assert!(check(t, s(1, 1)).is_ok());
            assert!(check(t, s(1, 2)).is_ok());
            assert!(check(t, s(0, 1)).is_err());
            assert!(check(t, s(2, 1)).is_err());
        }
        assert_eq!(check("PIE", s(2, 1)).unwrap_err(), "Pie needs exactly 1 group by and at least 1 measure; this report has 2 group by and 1 measure.");
        // Two group by and one measure.
        for t in ["STACKED_BAR", "STACKED_BAR_100", "STACKED_AREA", "CROSSTAB"] {
            assert!(check(t, s(2, 1)).is_ok());
            assert!(check(t, s(2, 2)).is_err());
            assert!(check(t, s(1, 1)).is_err());
        }
        // Exactly two measures, any group by (as shapeRules.ts).
        for t in ["COMBO", "SCATTER"] {
            assert!(check(t, s(1, 2)).is_ok());
            assert!(check(t, s(0, 2)).is_ok());
            assert!(check(t, s(2, 2)).is_ok());
            assert!(check(t, s(1, 3)).is_err());
            assert!(check(t, s(1, 1)).is_err());
        }
        // The line family: 1 or 2 group by, at least one measure.
        for t in ["LINE", "SMOOTH_LINE", "STEP_LINE", "AREA"] {
            assert!(check(t, s(1, 3)).is_ok());
            assert!(check(t, s(2, 1)).is_ok());
            assert!(check(t, s(2, 2)).is_ok());
            assert!(check(t, s(0, 1)).is_err());
            assert!(check(t, s(1, 0)).is_err());
        }
        // Grouped bar: 1 group by with 2+ measures, or 2 with one.
        assert!(check("GROUPED_BAR", s(1, 2)).is_ok());
        assert!(check("GROUPED_BAR", s(2, 1)).is_ok());
        assert!(check("GROUPED_BAR", s(1, 1)).is_err());
        // TABLE / LIST: anything, records included.
        for t in ["TABLE", "LIST"] {
            for g in 0..5 {
                for v in 0..4 {
                    assert!(check(t, s(g, v)).is_ok());
                }
            }
        }
        assert!(check("DONUT", s(1, 1)).unwrap_err().contains("not a view type"));
        // More than 2 group by (a FUNCTION source's columns): only TABLE and LIST.
        assert!(check("BAR", s(4, 1)).is_err());
    }

    #[test]
    fn the_p1b_rules() {
        // HEATMAP: 2 group by, 1 measure.
        assert!(check("HEATMAP", s(2, 1)).is_ok());
        for bad in [s(2, 2), s(1, 1), s(0, 1), s(2, 0)] {
            assert!(check("HEATMAP", bad).is_err(), "{bad:?}");
        }
        // TREEMAP: 1 or 2 group by, 1 measure.
        assert!(check("TREEMAP", s(1, 1)).is_ok());
        assert!(check("TREEMAP", s(2, 1)).is_ok());
        for bad in [s(1, 2), s(2, 2), s(0, 1), s(3, 1)] {
            assert!(check("TREEMAP", bad).is_err(), "{bad:?}");
        }
        // WATERFALL: 1 group by, 1 measure.
        assert!(check("WATERFALL", s(1, 1)).is_ok());
        for bad in [s(1, 2), s(2, 1), s(0, 1)] {
            assert!(check("WATERFALL", bad).is_err(), "{bad:?}");
        }
        assert_eq!(check("WATERFALL", s(1, 2)).unwrap_err(), "Waterfall needs exactly 1 group by and 1 measure; this report has 1 group by and 2 measures.");
        let j = rules_json();
        let tree = j["types"].as_array().unwrap().iter().find(|t| t["type"] == "TREEMAP").unwrap().clone();
        assert_eq!(tree["groupBy"], json!({"0": null, "1": {"min": 1, "max": 1}, "2": {"min": 1, "max": 1}}));
        assert!(!is_number("HEATMAP") && !is_table("HEATMAP"));
    }

    #[test]
    fn the_table_is_exposed_whole() {
        let j = rules_json();
        assert_eq!(j["types"].as_array().unwrap().len(), 25);
        let pie = j["types"].as_array().unwrap().iter().find(|t| t["type"] == "PIE").unwrap();
        assert_eq!(pie["groupBy"]["0"], Value::Null);
        assert_eq!(pie["groupBy"]["1"], json!({"min": 1, "max": null}));
        let f = fits(s(1, 1));
        assert_eq!(f["BAR"], json!({"ok": true}));
        assert_eq!(f["KPI"]["ok"], json!(false));
        assert!(is_number("GAUGE") && !is_number("BAR") && is_table("CROSSTAB"));
    }
}
