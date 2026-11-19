//! The values and conditions of an automation, read against a run's context.
//!
//! The context is `{ trigger, steps, event, run }`: the trigger event's data, each step's
//! output by step key, the event a wait or an exit is looking at, and the run's own id and test
//! flag. A path is dotted (`trigger.dealId`, `steps.welcome.messageId`, `trigger.items.0.id`).
//!
//! A value is text with `{{path}}` in it. Text that is one `{{path}}` and nothing else gives the
//! value as it is (a number stays a number, an object an object); otherwise each `{{path}}` is
//! replaced by its text, and a missing one by nothing. These are not KIRun expressions: an
//! automation is drawn by people who are not developers, and a path is all the editor offers.
//!
//! A condition is `{ operator: AND | OR, conditions: [...], negate }` of leaves
//! `{ field, operator, value, toValue, negate }`, the grammar CXZump's `cxCondEval` reads.

use serde_json::{Map, Value};

/// The value at `path`, `None` when any part is missing.
pub fn lookup<'a>(ctx: &'a Value, path: &str) -> Option<&'a Value> {
    let mut at = ctx;
    for part in path.trim().split('.').filter(|p| !p.is_empty()) {
        at = match at {
            Value::Object(m) => m.get(part)?,
            Value::Array(a) => a.get(part.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(at)
}

/// A value as text: a string as it is, null as nothing, anything else as JSON.
pub fn text_of(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// The path of text that is exactly one `{{path}}`.
fn whole_path(s: &str) -> Option<&str> {
    let inner = s.trim().strip_prefix("{{")?.strip_suffix("}}")?;
    (!inner.contains("{{") && !inner.contains("}}")).then(|| inner.trim())
}

/// `v` with every `{{path}}` in its texts filled from `ctx`, at any depth.
pub fn render(v: &Value, ctx: &Value) -> Value {
    match v {
        Value::String(s) => {
            if let Some(p) = whole_path(s) {
                return lookup(ctx, p).cloned().unwrap_or(Value::Null);
            }
            if !s.contains("{{") {
                return v.clone();
            }
            let mut out = String::with_capacity(s.len());
            let mut rest = s.as_str();
            while let Some(open) = rest.find("{{") {
                let Some(close) = rest[open..].find("}}") else { break };
                out.push_str(&rest[..open]);
                let path = &rest[open + 2..open + close];
                out.push_str(&lookup(ctx, path.trim()).map(text_of).unwrap_or_default());
                rest = &rest[open + close + 2..];
            }
            out.push_str(rest);
            Value::String(out)
        }
        Value::Array(a) => Value::Array(a.iter().map(|x| render(x, ctx)).collect()),
        Value::Object(m) => Value::Object(m.iter().map(|(k, x)| (k.clone(), render(x, ctx))).collect()),
        other => other.clone(),
    }
}

/// Every value of a params map rendered.
pub fn render_map(params: &Map<String, Value>, ctx: &Value) -> Map<String, Value> {
    params.iter().map(|(k, v)| (k.clone(), render(v, ctx))).collect()
}

fn number(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse::<f64>().ok().filter(|f| f.is_finite()),
        _ => None,
    }
}

fn is_blank(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => true,
        Some(Value::String(s)) => s.trim().is_empty(),
        Some(Value::Array(a)) => a.is_empty(),
        _ => false,
    }
}

fn truth(v: Option<&Value>) -> Option<bool> {
    match v? {
        Value::Bool(b) => Some(*b),
        Value::String(s) if s.eq_ignore_ascii_case("true") => Some(true),
        Value::String(s) if s.eq_ignore_ascii_case("false") => Some(false),
        _ => None,
    }
}

/// Ordering of two values: as numbers when both are, else as texts (ISO dates order as texts).
fn compare(a: &Value, b: &Value) -> std::cmp::Ordering {
    match (number(a), number(b)) {
        (Some(x), Some(y)) => x.partial_cmp(&y).unwrap_or(std::cmp::Ordering::Equal),
        _ => text_of(a).cmp(&text_of(b)),
    }
}

fn equal(a: &Value, b: &Value) -> bool {
    match (number(a), number(b)) {
        (Some(x), Some(y)) => x == y,
        _ => match (truth(Some(a)), truth(Some(b))) {
            (Some(x), Some(y)) => x == y,
            _ => text_of(a) == text_of(b),
        },
    }
}

fn members(v: &Value) -> Vec<Value> {
    match v {
        Value::Array(a) => a.clone(),
        Value::String(s) => s.split(',').map(|p| Value::String(p.trim().to_string())).collect(),
        Value::Null => vec![],
        other => vec![other.clone()],
    }
}

fn leaf(c: &Map<String, Value>, ctx: &Value) -> bool {
    let field = c.get("field").and_then(Value::as_str).unwrap_or("");
    let actual = lookup(ctx, field);
    let value = c.get("value").map(|v| render(v, ctx)).unwrap_or(Value::Null);
    let op = c.get("operator").and_then(Value::as_str).unwrap_or("EQUALS").to_ascii_uppercase();
    let have = || actual.cloned().unwrap_or(Value::Null);
    let r = match op.as_str() {
        "EQUALS" => equal(&have(), &value),
        "NOT_EQUALS" => !equal(&have(), &value),
        "STRING_LOOSE_EQUAL" => text_of(&have()).trim().eq_ignore_ascii_case(text_of(&value).trim()),
        "GREATER_THAN" => !is_blank(actual) && compare(&have(), &value).is_gt(),
        "GREATER_THAN_EQUAL" => !is_blank(actual) && compare(&have(), &value).is_ge(),
        "LESS_THAN" => !is_blank(actual) && compare(&have(), &value).is_lt(),
        "LESS_THAN_EQUAL" => !is_blank(actual) && compare(&have(), &value).is_le(),
        "BETWEEN" => {
            let to = c.get("toValue").map(|v| render(v, ctx)).unwrap_or(Value::Null);
            !is_blank(actual) && compare(&have(), &value).is_ge() && compare(&have(), &to).is_le()
        }
        "IN" => members(&value).iter().any(|m| equal(&have(), m)),
        "LIKE" | "CONTAINS" => text_of(&have()).to_lowercase().contains(&text_of(&value).to_lowercase()),
        "IS_TRUE" => truth(actual) == Some(true),
        "IS_FALSE" => truth(actual) == Some(false),
        "IS_NULL" | "IS_EMPTY" => is_blank(actual),
        "IS_NOT_NULL" | "IS_NOT_EMPTY" => !is_blank(actual),
        _ => false,
    };
    r != c.get("negate").and_then(Value::as_bool).unwrap_or(false)
}

/// Whether `condition` holds. A missing condition, or a group with nothing in it, holds.
pub fn holds(condition: Option<&Value>, ctx: &Value) -> bool {
    let Some(Value::Object(c)) = condition else { return true };
    let negate = c.get("negate").and_then(Value::as_bool).unwrap_or(false);
    let Some(list) = c.get("conditions") else { return leaf(c, ctx) };
    let parts: Vec<&Value> = match list {
        Value::Array(a) => a.iter().collect(),
        _ => vec![],
    };
    let or = c.get("operator").and_then(Value::as_str).is_some_and(|o| o.eq_ignore_ascii_case("OR"));
    let r = if parts.is_empty() {
        true
    } else if or {
        parts.iter().any(|p| holds(Some(p), ctx))
    } else {
        parts.iter().all(|p| holds(Some(p), ctx))
    };
    r != negate
}

/// A point in time as epoch milliseconds: a number (milliseconds, or seconds when it is small
/// enough to be), or an ISO-8601 date-time or date (a date is its midnight in UTC).
pub fn instant(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => {
            let x = n.as_f64()?;
            Some(if x.abs() < 100_000_000_000.0 { (x * 1000.0) as i64 } else { x as i64 })
        }
        Value::String(s) => {
            let s = s.trim();
            if let Ok(t) = chrono::DateTime::parse_from_rfc3339(s) {
                return Some(t.timestamp_millis());
            }
            if let Ok(t) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f") {
                return Some(t.and_utc().timestamp_millis());
            }
            if let Ok(d) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
                return Some(d.and_hms_opt(0, 0, 0)?.and_utc().timestamp_millis());
            }
            s.parse::<f64>().ok().and_then(|x| instant(&serde_json::json!(x)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx() -> Value {
        json!({
            "trigger": {"dealId": 42, "name": "Asha", "stage": "New", "tags": ["hot", "web"], "amount": "1500"},
            "steps": {"welcome": {"messageId": "wamid.1"}, "hold": {"happened": true, "event": {"status": "read"}}},
            "run": {"test": false}
        })
    }

    #[test]
    fn paths_and_texts() {
        let c = ctx();
        assert_eq!(lookup(&c, "trigger.tags.1"), Some(&json!("web")));
        assert_eq!(lookup(&c, "trigger.nothing"), None);
        assert_eq!(render(&json!("{{trigger.dealId}}"), &c), json!(42));
        assert_eq!(render(&json!(" {{ trigger.dealId }} "), &c), json!(42));
        assert_eq!(render(&json!("Hi {{trigger.name}}, deal {{trigger.dealId}}{{trigger.missing}}!"), &c), json!("Hi Asha, deal 42!"));
        assert_eq!(render(&json!({"to": ["{{trigger.name}}"], "n": 3}), &c), json!({"to": ["Asha"], "n": 3}));
        assert_eq!(render(&json!("{{trigger.missing}}"), &c), Value::Null);
        assert_eq!(render(&json!("open {{ never closed"), &c), json!("open {{ never closed"));
    }

    #[test]
    fn conditions() {
        let c = ctx();
        let h = |v: Value| holds(Some(&v), &c);
        assert!(holds(None, &c));
        assert!(h(json!({"operator": "AND", "conditions": []})));
        assert!(h(json!({"field": "steps.hold.event.status", "operator": "EQUALS", "value": "read"})));
        assert!(h(json!({"field": "trigger.amount", "operator": "GREATER_THAN", "value": 999})));
        assert!(!h(json!({"field": "trigger.amount", "operator": "GREATER_THAN", "value": "15000"})));
        assert!(h(json!({"field": "trigger.dealId", "operator": "EQUALS", "value": "42"})));
        assert!(h(json!({"field": "trigger.stage", "operator": "IN", "value": "Won, New"})));
        assert!(h(json!({"field": "trigger.amount", "operator": "BETWEEN", "value": 1000, "toValue": 2000})));
        assert!(h(json!({"field": "trigger.name", "operator": "LIKE", "value": "ASH"})));
        assert!(h(json!({"field": "steps.hold.happened", "operator": "IS_TRUE"})));
        assert!(h(json!({"field": "trigger.missing", "operator": "IS_NULL"})));
        assert!(!h(json!({"field": "trigger.missing", "operator": "LESS_THAN", "value": 5})), "a missing value is never less");
        assert!(h(json!({"field": "trigger.name", "operator": "EQUALS", "value": "{{trigger.name}}"})));
        assert!(h(json!({"operator": "OR", "conditions": [
            {"field": "trigger.stage", "operator": "EQUALS", "value": "Won"},
            {"field": "trigger.stage", "operator": "EQUALS", "value": "Won", "negate": true}
        ]})));
        assert!(!h(json!({"operator": "AND", "negate": true, "conditions": [{"field": "trigger.dealId", "operator": "IS_NOT_NULL"}]})));
        assert!(!h(json!({"field": "trigger.dealId", "operator": "NO_SUCH"})));
    }

    #[test]
    fn instants() {
        assert_eq!(instant(&json!(1_700_000_000)), Some(1_700_000_000_000));
        assert_eq!(instant(&json!(1_700_000_000_123_i64)), Some(1_700_000_000_123));
        assert_eq!(instant(&json!("2026-11-21T10:00:00Z")), Some(1_795_255_200_000));
        assert_eq!(instant(&json!("2026-11-21T15:30:00+05:30")), Some(1_795_255_200_000));
        assert_eq!(instant(&json!("2026-11-21")), Some(1_795_219_200_000));
        assert_eq!(instant(&json!("someday")), None);
        assert_eq!(instant(&Value::Null), None);
    }
}
